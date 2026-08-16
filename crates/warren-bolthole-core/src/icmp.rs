//! The ICMP messages the gateway writes itself, and the rewrite of the packet
//! an ICMP error quotes.
//!
//! An ICMP error carries a copy of the packet that caused it. On the way down
//! that copy is the packet the exit sent, so it names the external address and
//! port: the peer would discard the error (it never sent that packet), and path
//! MTU discovery, connection refusals and traceroute would all go silent. The
//! quote is therefore translated exactly like the outer header, which is also
//! what carries the tunnel's own Packet Too Big back to the peer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use warrenguard_transport_core::{icmpv6_pseudo_sum, internet_checksum};

use crate::error::PacketError;
use crate::ip::{
    ICMPV4_ECHO_REPLY, ICMPV4_ECHO_REQUEST, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST,
    IPV4_MIN_HEADER, IPV6_HEADER, IpHeader, PROTO_ICMPV4, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, Side,
    checksum_update, is_echo, is_icmp_error, parse_ip, parse_ip_quote, read_icmp, read_ports,
};

/// The largest ICMPv6 message that is guaranteed to cross any path (RFC 4443).
const ICMPV6_MAX: usize = 1280;

/// The packet an ICMP error quotes, located inside the error that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorQuote {
    /// Where the quoted packet starts inside the error.
    pub inner_offset: usize,
    /// The quoted packet's own IP header. Its offsets are relative to
    /// [`inner_offset`](Self::inner_offset) and its `total_len` counts the
    /// bytes actually quoted, which is usually less than the packet was.
    pub inner: IpHeader,
    /// The quoted transport ports, when the quote reaches them.
    pub ports: Option<(u16, u16)>,
    /// The quoted echo identifier, when the quoted packet was an echo.
    pub echo_id: Option<u16>,
}

impl ErrorQuote {
    /// The identifier the NAT looks a mapping up by: the quoted port of the
    /// side that names the gateway, or the quoted echo identifier.
    #[must_use]
    pub fn port(&self, side: Side) -> Option<u16> {
        match (self.ports, side) {
            (Some((src, _)), Side::Source) => Some(src),
            (Some((_, dst)), Side::Destination) => Some(dst),
            (None, _) => self.echo_id,
        }
    }
}

fn unicast_v4(addr: Ipv4Addr) -> bool {
    !(addr.is_multicast() || addr.is_broadcast() || addr.is_unspecified() || addr.is_loopback())
}

fn unicast_v6(addr: Ipv6Addr) -> bool {
    !(addr.is_multicast() || addr.is_unspecified() || addr.is_loopback())
}

/// Writes the IPv4 header of a message the gateway builds, and returns the
/// assembled packet.
fn frame_v4(src: Ipv4Addr, dst: Ipv4Addr, body: &[u8]) -> Option<Vec<u8>> {
    let total = IPV4_MIN_HEADER.checked_add(body.len())?;
    let total_u16 = u16::try_from(total).ok()?;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&total_u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_ICMPV4;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ck = internet_checksum(0, &pkt[..IPV4_MIN_HEADER]);
    pkt[10..12].copy_from_slice(&ck.to_be_bytes());
    pkt[IPV4_MIN_HEADER..].copy_from_slice(body);
    let ck = internet_checksum(0, &pkt[IPV4_MIN_HEADER..]);
    pkt[IPV4_MIN_HEADER + 2..IPV4_MIN_HEADER + 4].copy_from_slice(&ck.to_be_bytes());
    Some(pkt)
}

/// Writes the IPv6 header of a message the gateway builds, and returns the
/// assembled packet.
fn frame_v6(src: Ipv6Addr, dst: Ipv6Addr, body: &[u8]) -> Option<Vec<u8>> {
    let payload = u16::try_from(body.len()).ok()?;
    let mut pkt = vec![0u8; IPV6_HEADER + body.len()];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&payload.to_be_bytes());
    pkt[6] = PROTO_ICMPV6;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[IPV6_HEADER..].copy_from_slice(body);
    let seed = icmpv6_pseudo_sum(src, dst, u32::from(payload));
    let ck = internet_checksum(seed, &pkt[IPV6_HEADER..]);
    pkt[IPV6_HEADER + 2..IPV6_HEADER + 4].copy_from_slice(&ck.to_be_bytes());
    Some(pkt)
}

/// Answers an ICMPv4 echo request addressed to the gateway itself.
///
/// `None` when the packet is not an IPv4 echo request the gateway may answer:
/// the local address is the one thing the peer can reach on this side, and a
/// reply to anything else would be an unsolicited packet.
#[must_use]
pub fn build_echo_reply_v4(request: &[u8]) -> Option<Vec<u8>> {
    let hdr = parse_ip(request).ok()?;
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (hdr.src, hdr.dst) else {
        return None;
    };
    if hdr.protocol != PROTO_ICMPV4 || !unicast_v4(src) {
        return None;
    }
    let msg = request.get(hdr.l4_offset..hdr.total_len)?;
    if msg.len() < 8 || msg[0] != ICMPV4_ECHO_REQUEST {
        return None;
    }
    let mut body = msg.to_vec();
    body[0] = ICMPV4_ECHO_REPLY;
    body[2] = 0;
    body[3] = 0;
    frame_v4(dst, src, &body)
}

/// Answers an ICMPv6 echo request addressed to the gateway itself.
///
/// `None` under the same rule as [`build_echo_reply_v4`].
#[must_use]
pub fn build_echo_reply_v6(request: &[u8]) -> Option<Vec<u8>> {
    let hdr = parse_ip(request).ok()?;
    let (IpAddr::V6(src), IpAddr::V6(dst)) = (hdr.src, hdr.dst) else {
        return None;
    };
    if hdr.protocol != PROTO_ICMPV6 || !unicast_v6(src) {
        return None;
    }
    let msg = request.get(hdr.l4_offset..hdr.total_len)?;
    if msg.len() < 8 || msg[0] != ICMPV6_ECHO_REQUEST {
        return None;
    }
    let mut body = msg.to_vec();
    body[0] = ICMPV6_ECHO_REPLY;
    body[2] = 0;
    body[3] = 0;
    frame_v6(dst, src, &body)
}

/// Builds an ICMPv4 destination unreachable, code 1 (host unreachable),
/// sourced from `source` and quoting the packet that provoked it.
///
/// `None` for a non-IPv4 packet, for an ICMP error (RFC 1122 forbids answering
/// one with another) and for a non-unicast sender.
#[must_use]
pub fn build_unreachable_v4(offending: &[u8], source: Ipv4Addr) -> Option<Vec<u8>> {
    let hdr = parse_ip(offending).ok()?;
    let IpAddr::V4(dst) = hdr.src else {
        return None;
    };
    if !unicast_v4(dst) || quotes_an_error(offending, &hdr) {
        return None;
    }
    // RFC 1191: the header plus the first eight transport bytes.
    let quote_len = (hdr.l4_offset + 8).min(hdr.total_len);
    let quote = offending.get(..quote_len)?;
    let mut body = vec![0u8; 8 + quote.len()];
    body[0] = 3;
    body[1] = 1;
    body[8..].copy_from_slice(quote);
    frame_v4(source, dst, &body)
}

/// Builds an ICMPv6 destination unreachable, code 0 (no route to destination),
/// sourced from `source` and quoting as much of the offending packet as fits
/// under the IPv6 minimum MTU.
///
/// `None` under the same rules as [`build_unreachable_v4`].
#[must_use]
pub fn build_unreachable_v6(offending: &[u8], source: Ipv6Addr) -> Option<Vec<u8>> {
    let hdr = parse_ip(offending).ok()?;
    let IpAddr::V6(dst) = hdr.src else {
        return None;
    };
    if !unicast_v6(dst) || quotes_an_error(offending, &hdr) {
        return None;
    }
    let quote_len = hdr.total_len.min(ICMPV6_MAX - IPV6_HEADER - 8);
    let quote = offending.get(..quote_len)?;
    let mut body = vec![0u8; 8 + quote.len()];
    body[0] = 1;
    body[1] = 0;
    body[8..].copy_from_slice(quote);
    frame_v6(source, dst, &body)
}

/// True when the packet is itself an ICMP error, which no further error may
/// answer.
fn quotes_an_error(pkt: &[u8], hdr: &IpHeader) -> bool {
    pkt.get(hdr.l4_offset)
        .is_some_and(|kind| is_icmp_error(hdr.protocol, *kind))
}

/// Locates the packet quoted by an ICMP error.
///
/// # Errors
///
/// [`PacketError::NotAnIcmpError`] when the message is not an error,
/// [`PacketError::Truncated`] when the quote is absent or shorter than an IP
/// header, and the parse errors of [`parse_ip_quote`] for a quote this gateway
/// cannot translate (a fragment, an extension header).
pub fn parse_error_quote(pkt: &[u8], outer: &IpHeader) -> Result<ErrorQuote, PacketError> {
    let head = read_icmp(pkt, outer.l4_offset)?;
    if !is_icmp_error(outer.protocol, head.kind) {
        return Err(PacketError::NotAnIcmpError);
    }
    let inner_offset = outer.l4_offset + 8;
    let quote = pkt
        .get(inner_offset..outer.total_len)
        .ok_or(PacketError::Truncated)?;
    let inner = parse_ip_quote(quote)?;
    let (ports, echo_id) = match inner.protocol {
        PROTO_TCP | PROTO_UDP => (read_ports(quote, inner.l4_offset).ok(), None),
        PROTO_ICMPV4 | PROTO_ICMPV6 => {
            let icmp = read_icmp(quote, inner.l4_offset)?;
            let id = if is_echo(inner.protocol, icmp.kind) {
                icmp.echo_id
            } else {
                None
            };
            (None, id)
        }
        _ => (None, None),
    };
    Ok(ErrorQuote {
        inner_offset,
        inner,
        ports,
        echo_id,
    })
}

/// Rewrites one endpoint of the packet an ICMP error quotes, then recomputes
/// the error's own checksum over the changed payload.
///
/// A transport checksum whose field the quote does not reach is left as it is,
/// which is what a kernel NAT does too: the eight quoted bytes of an IPv4 error
/// stop before the TCP checksum, and the receiving stack matches the error on
/// the addresses and ports alone.
///
/// # Errors
///
/// [`PacketError::FamilyMismatch`] for an address of the wrong family,
/// [`PacketError::Truncated`] when the buffer no longer holds what the headers
/// declare, [`PacketError::UnsupportedProtocol`] for a quoted protocol with no
/// known checksum layout and [`PacketError::NotAnEcho`] when an identifier is
/// offered to a quoted message that carries none.
pub fn rewrite_error_quote(
    pkt: &mut [u8],
    outer: &IpHeader,
    quote: &ErrorQuote,
    side: Side,
    addr: IpAddr,
    port: Option<u16>,
) -> Result<(), PacketError> {
    let inner = &quote.inner;
    if addr.is_ipv6() != inner.is_v6() {
        return Err(PacketError::FamilyMismatch);
    }
    if pkt.len() < outer.total_len {
        return Err(PacketError::Truncated);
    }
    let base = quote.inner_offset;
    let end = base + inner.total_len;
    if end > outer.total_len {
        return Err(PacketError::Truncated);
    }
    let l4 = base + inner.l4_offset;
    let (ck_at, pseudo) = match inner.protocol {
        PROTO_TCP => (16, true),
        PROTO_UDP => (6, true),
        PROTO_ICMPV4 => (2, false),
        PROTO_ICMPV6 => (2, true),
        _ => return Err(PacketError::UnsupportedProtocol),
    };
    let icmp = matches!(inner.protocol, PROTO_ICMPV4 | PROTO_ICMPV6);
    let port_at = if port.is_some() {
        if icmp {
            let kind = pkt.get(l4).copied().ok_or(PacketError::Truncated)?;
            if !is_echo(inner.protocol, kind) {
                return Err(PacketError::NotAnEcho);
            }
            if l4 + 6 > end {
                return Err(PacketError::Truncated);
            }
            Some(l4 + 4)
        } else {
            if l4 + 4 > end {
                return Err(PacketError::Truncated);
            }
            Some(match side {
                Side::Source => l4,
                Side::Destination => l4 + 2,
            })
        }
    } else {
        None
    };
    let addr_at = base
        + match (inner.is_v6(), side) {
            (false, Side::Source) => 12,
            (false, Side::Destination) => 16,
            (true, Side::Source) => 8,
            (true, Side::Destination) => 24,
        };
    let addr_len = if inner.is_v6() { 16 } else { 4 };
    if addr_at + addr_len > end {
        return Err(PacketError::Truncated);
    }
    // The quote may stop before the transport checksum; when it does, the field
    // stays as the exit saw it.
    let ck_reachable = l4 + ck_at + 2 <= end;
    let mut ck = if ck_reachable {
        u16::from_be_bytes([pkt[l4 + ck_at], pkt[l4 + ck_at + 1]])
    } else {
        0
    };
    let keep_unchecksummed =
        inner.protocol == PROTO_UDP && !inner.is_v6() && ck_reachable && ck == 0;
    let patch = ck_reachable && !keep_unchecksummed;

    match addr {
        IpAddr::V4(new) => {
            let old = <[u8; 4]>::try_from(&pkt[addr_at..addr_at + 4])
                .map_err(|_| PacketError::Truncated)?;
            let new = new.octets();
            pkt[addr_at..addr_at + 4].copy_from_slice(&new);
            let header_ck = u16::from_be_bytes([pkt[base + 10], pkt[base + 11]]);
            let header_ck = checksum_update(header_ck, &old, &new);
            pkt[base + 10..base + 12].copy_from_slice(&header_ck.to_be_bytes());
            if patch && pseudo {
                ck = checksum_update(ck, &old, &new);
            }
        }
        IpAddr::V6(new) => {
            let old = <[u8; 16]>::try_from(&pkt[addr_at..addr_at + 16])
                .map_err(|_| PacketError::Truncated)?;
            let new = new.octets();
            pkt[addr_at..addr_at + 16].copy_from_slice(&new);
            if patch && pseudo {
                ck = checksum_update(ck, &old, &new);
            }
        }
    }
    if let (Some(at), Some(new)) = (port_at, port) {
        let old = <[u8; 2]>::try_from(&pkt[at..at + 2]).map_err(|_| PacketError::Truncated)?;
        let new = new.to_be_bytes();
        pkt[at..at + 2].copy_from_slice(&new);
        if patch {
            ck = checksum_update(ck, &old, &new);
        }
    }
    if patch {
        pkt[l4 + ck_at..l4 + ck_at + 2].copy_from_slice(&ck.to_be_bytes());
    }
    recompute_icmp_checksum(pkt, outer)
}

/// Recomputes the ICMP or ICMPv6 checksum of a message whose payload changed.
///
/// # Errors
///
/// [`PacketError::Truncated`] when the buffer is shorter than the header
/// declares, [`PacketError::UnsupportedProtocol`] when the packet carries no
/// ICMP message.
pub fn recompute_icmp_checksum(pkt: &mut [u8], outer: &IpHeader) -> Result<(), PacketError> {
    if pkt.len() < outer.total_len || outer.total_len < outer.l4_offset + 4 {
        return Err(PacketError::Truncated);
    }
    let ck_at = outer.l4_offset + 2;
    // The addresses are read back from the buffer, never from `outer`: a
    // caller that has just rewritten one endpoint holds a header describing
    // the packet as it was, and an ICMPv6 checksum covers the addresses.
    let seed = match outer.protocol {
        PROTO_ICMPV4 if !outer.is_v6() => 0,
        PROTO_ICMPV6 if outer.is_v6() => {
            let src = <[u8; 16]>::try_from(&pkt[8..24]).map_err(|_| PacketError::Truncated)?;
            let dst = <[u8; 16]>::try_from(&pkt[24..40]).map_err(|_| PacketError::Truncated)?;
            let len = u32::try_from(outer.total_len - outer.l4_offset)
                .map_err(|_| PacketError::Truncated)?;
            icmpv6_pseudo_sum(Ipv6Addr::from(src), Ipv6Addr::from(dst), len)
        }
        _ => return Err(PacketError::UnsupportedProtocol),
    };
    pkt[ck_at] = 0;
    pkt[ck_at + 1] = 0;
    let ck = internet_checksum(seed, &pkt[outer.l4_offset..outer.total_len]);
    pkt[ck_at..ck_at + 2].copy_from_slice(&ck.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testpkt;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const GW4: Ipv4Addr = Ipv4Addr::new(10, 67, 0, 1);
    const PEER4: Ipv4Addr = Ipv4Addr::new(10, 67, 0, 2);
    const EXT4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
    const REMOTE4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

    fn v6(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last)
    }

    #[test]
    fn builds_a_v4_echo_reply_with_swapped_endpoints() {
        let request = testpkt::echo(IpAddr::V4(PEER4), IpAddr::V4(GW4), 0x1234, 9, b"payload");
        let reply = build_echo_reply_v4(&request).expect("a reply to an echo request");
        let hdr = crate::ip::parse_ip(&reply).expect("valid reply");
        assert_eq!(hdr.src, IpAddr::V4(GW4));
        assert_eq!(hdr.dst, IpAddr::V4(PEER4));
        let icmp = crate::ip::read_icmp(&reply, hdr.l4_offset).expect("icmp");
        assert_eq!(icmp.kind, crate::ip::ICMPV4_ECHO_REPLY);
        assert_eq!(icmp.echo_id, Some(0x1234));
        assert_eq!(&reply[hdr.l4_offset + 8..], b"payload");
        assert!(testpkt::checksums_valid(&reply));
    }

    #[test]
    fn builds_a_v6_echo_reply_with_swapped_endpoints() {
        let request = testpkt::echo(IpAddr::V6(v6(2)), IpAddr::V6(v6(1)), 0x1234, 9, b"payload");
        let reply = build_echo_reply_v6(&request).expect("a reply to an echo request");
        let hdr = crate::ip::parse_ip(&reply).expect("valid reply");
        assert_eq!(hdr.src, IpAddr::V6(v6(1)));
        assert_eq!(hdr.dst, IpAddr::V6(v6(2)));
        let icmp = crate::ip::read_icmp(&reply, hdr.l4_offset).expect("icmp");
        assert_eq!(icmp.kind, crate::ip::ICMPV6_ECHO_REPLY);
        assert!(testpkt::checksums_valid(&reply));
    }

    #[test]
    fn answers_only_an_echo_request() {
        let reply = testpkt::echo(IpAddr::V4(PEER4), IpAddr::V4(GW4), 1, 1, b"");
        let mut not_a_request = reply.clone();
        not_a_request[20] = crate::ip::ICMPV4_ECHO_REPLY;
        assert!(build_echo_reply_v4(&not_a_request).is_none());
        let udp = testpkt::udp(IpAddr::V4(PEER4), 1, IpAddr::V4(GW4), 2, b"");
        assert!(build_echo_reply_v4(&udp).is_none());
        assert!(
            build_echo_reply_v6(&reply).is_none(),
            "a v4 packet is not v6"
        );
    }

    #[test]
    fn builds_a_v4_host_unreachable_quoting_the_offending_header() {
        let offending = testpkt::udp(IpAddr::V4(PEER4), 5000, IpAddr::V4(REMOTE4), 80, b"body");
        let err = build_unreachable_v4(&offending, GW4).expect("an unreachable");
        let hdr = crate::ip::parse_ip(&err).expect("valid error");
        assert_eq!(hdr.src, IpAddr::V4(GW4));
        assert_eq!(hdr.dst, IpAddr::V4(PEER4));
        let icmp = crate::ip::read_icmp(&err, hdr.l4_offset).expect("icmp");
        assert_eq!(
            (icmp.kind, icmp.code),
            (3, 1),
            "destination host unreachable"
        );
        assert_eq!(
            &err[hdr.l4_offset + 8..],
            &offending[..28],
            "RFC 1191 quote: the header plus eight transport bytes"
        );
        assert!(testpkt::checksums_valid(&err));
    }

    #[test]
    fn builds_a_v6_no_route_bounded_at_the_minimum_mtu() {
        let offending = testpkt::udp(IpAddr::V6(v6(2)), 5000, IpAddr::V6(v6(9)), 80, &[7u8; 2000]);
        let err = build_unreachable_v6(&offending, v6(1)).expect("an unreachable");
        let hdr = crate::ip::parse_ip(&err).expect("valid error");
        assert_eq!(hdr.src, IpAddr::V6(v6(1)));
        assert_eq!(hdr.dst, IpAddr::V6(v6(2)));
        let icmp = crate::ip::read_icmp(&err, hdr.l4_offset).expect("icmp");
        assert_eq!((icmp.kind, icmp.code), (1, 0), "no route to destination");
        assert!(
            err.len() <= 1280,
            "an ICMPv6 error never exceeds 1280 bytes"
        );
        assert!(testpkt::checksums_valid(&err));
    }

    #[test]
    fn never_answers_an_icmp_error_with_another_error() {
        let offending = testpkt::udp(IpAddr::V4(PEER4), 5000, IpAddr::V4(REMOTE4), 80, b"body");
        let err = build_unreachable_v4(&offending, GW4).expect("an unreachable");
        assert!(
            build_unreachable_v4(&err, GW4).is_none(),
            "an ICMP error must not provoke another one"
        );
        let offending6 = testpkt::udp(IpAddr::V6(v6(2)), 5000, IpAddr::V6(v6(9)), 80, b"body");
        let err6 = build_unreachable_v6(&offending6, v6(1)).expect("an unreachable");
        assert!(build_unreachable_v6(&err6, v6(1)).is_none());
    }

    #[test]
    fn never_answers_a_non_unicast_source() {
        let offending = testpkt::udp(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            5000,
            IpAddr::V4(REMOTE4),
            80,
            b"",
        );
        assert!(build_unreachable_v4(&offending, GW4).is_none());
        let multicast = testpkt::udp(
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
            5000,
            IpAddr::V6(v6(9)),
            80,
            b"",
        );
        assert!(build_unreachable_v6(&multicast, v6(1)).is_none());
    }

    #[test]
    fn rewrites_the_embedded_quote_of_a_v4_udp_error_back_to_the_original_bytes() {
        // The peer's own packet, then the one the exit actually saw.
        let original = testpkt::udp(IpAddr::V4(PEER4), 5000, IpAddr::V4(REMOTE4), 80, b"body");
        let mut natted = original.clone();
        let hdr = crate::ip::parse_ip(&natted).expect("valid");
        crate::ip::rewrite_endpoint(
            &mut natted,
            &hdr,
            crate::ip::Side::Source,
            IpAddr::V4(EXT4),
            Some(41000),
        )
        .expect("nat");
        // The error the internet sends back quotes the NATed packet.
        let mut err = build_unreachable_v4(&natted, REMOTE4).expect("an unreachable");
        let outer = crate::ip::parse_ip(&err).expect("valid error");
        let quote = parse_error_quote(&err, &outer).expect("a quote");
        assert_eq!(quote.inner.src, IpAddr::V4(EXT4));
        assert_eq!(quote.ports, Some((41000, 80)));
        // Undo the NAT inside the quote, then the outer destination.
        rewrite_error_quote(
            &mut err,
            &outer,
            &quote,
            crate::ip::Side::Source,
            IpAddr::V4(PEER4),
            Some(5000),
        )
        .expect("quote rewrite");
        assert_eq!(
            &err[quote.inner_offset..],
            &original[..28],
            "the quote must read exactly as the packet the peer sent"
        );
        assert!(testpkt::checksums_valid(&err), "the outer ICMP checksum");
    }

    #[test]
    fn leaves_a_tcp_checksum_the_quote_is_too_short_to_carry() {
        let original = testpkt::tcp(
            IpAddr::V4(PEER4),
            5000,
            IpAddr::V4(REMOTE4),
            80,
            crate::ip::TCP_SYN,
            b"",
        );
        let mut natted = original.clone();
        let hdr = crate::ip::parse_ip(&natted).expect("valid");
        crate::ip::rewrite_endpoint(
            &mut natted,
            &hdr,
            crate::ip::Side::Source,
            IpAddr::V4(EXT4),
            Some(41000),
        )
        .expect("nat");
        let mut err = build_unreachable_v4(&natted, REMOTE4).expect("an unreachable");
        let outer = crate::ip::parse_ip(&err).expect("valid error");
        let quote = parse_error_quote(&err, &outer).expect("a quote");
        rewrite_error_quote(
            &mut err,
            &outer,
            &quote,
            crate::ip::Side::Source,
            IpAddr::V4(PEER4),
            Some(5000),
        )
        .expect("quote rewrite");
        assert_eq!(
            &err[quote.inner_offset..],
            &original[..28],
            "the eight quoted transport bytes stop before the TCP checksum"
        );
        assert!(testpkt::checksums_valid(&err));
    }

    #[test]
    fn rewrites_a_v6_quote_including_the_transport_checksum_it_carries() {
        let original = testpkt::udp(IpAddr::V6(v6(2)), 5000, IpAddr::V6(v6(9)), 80, b"body");
        let mut natted = original.clone();
        let hdr = crate::ip::parse_ip(&natted).expect("valid");
        crate::ip::rewrite_endpoint(
            &mut natted,
            &hdr,
            crate::ip::Side::Source,
            IpAddr::V6(v6(0xbeef)),
            Some(41000),
        )
        .expect("nat");
        let mut err = build_unreachable_v6(&natted, v6(9)).expect("an unreachable");
        let outer = crate::ip::parse_ip(&err).expect("valid error");
        let quote = parse_error_quote(&err, &outer).expect("a quote");
        assert_eq!(quote.inner.src, IpAddr::V6(v6(0xbeef)));
        rewrite_error_quote(
            &mut err,
            &outer,
            &quote,
            crate::ip::Side::Source,
            IpAddr::V6(v6(2)),
            Some(5000),
        )
        .expect("quote rewrite");
        assert_eq!(
            &err[quote.inner_offset..],
            &original[..],
            "a v6 quote carries the whole packet, checksum included"
        );
        assert!(testpkt::checksums_valid(&err));
    }

    #[test]
    fn reads_the_echo_identifier_a_quote_carries() {
        let ping = testpkt::echo(IpAddr::V4(PEER4), IpAddr::V4(REMOTE4), 0x4242, 1, b"x");
        let err = build_unreachable_v4(&ping, REMOTE4).expect("an unreachable");
        let outer = crate::ip::parse_ip(&err).expect("valid error");
        let quote = parse_error_quote(&err, &outer).expect("a quote");
        assert_eq!(quote.echo_id, Some(0x4242));
        assert_eq!(quote.ports, None);
    }

    #[test]
    fn refuses_a_quote_that_is_not_carried_by_an_icmp_error() {
        let pkt = testpkt::echo(IpAddr::V4(PEER4), IpAddr::V4(GW4), 1, 1, b"");
        let outer = crate::ip::parse_ip(&pkt).expect("valid");
        assert_eq!(
            parse_error_quote(&pkt, &outer),
            Err(PacketError::NotAnIcmpError)
        );
    }

    #[test]
    fn never_panics_on_a_truncated_error_packet() {
        let offending = testpkt::udp(IpAddr::V4(PEER4), 5000, IpAddr::V4(REMOTE4), 80, b"body");
        let full = build_unreachable_v4(&offending, GW4).expect("an unreachable");
        let outer = crate::ip::parse_ip(&full).expect("valid error");
        for len in 0..full.len() {
            let mut short = full[..len].to_vec();
            let _ = build_echo_reply_v4(&short);
            let _ = build_unreachable_v4(&short, GW4);
            let _ = build_unreachable_v6(&short, v6(1));
            if let Ok(quote) = parse_error_quote(&short, &outer) {
                let _ = rewrite_error_quote(
                    &mut short,
                    &outer,
                    &quote,
                    crate::ip::Side::Source,
                    IpAddr::V4(PEER4),
                    Some(1),
                );
            }
        }
    }
}
