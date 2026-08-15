//! Bounds-checked, panic-free views and rewrites of the IP and transport
//! headers the gateway translates.
//!
//! Every function validates the whole operation against the length the header
//! itself declares before it writes a byte, so a malformed or truncated
//! datagram from a peer is a refusal and never a panic or a half-rewritten
//! packet. Checksum arithmetic is the engine's ([`internet_checksum`],
//! [`incremental_checksum_update`], [`icmpv6_pseudo_sum`]): the client pump
//! clamps and reflects on the same packets this NAT rewrites, and two homes for
//! that arithmetic would eventually disagree.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use warrenguard_transport_core::incremental_checksum_update;

use crate::error::PacketError;

/// IPv4 protocol number of ICMP.
pub const PROTO_ICMPV4: u8 = 1;
/// IP protocol number of TCP.
pub const PROTO_TCP: u8 = 6;
/// IP protocol number of UDP.
pub const PROTO_UDP: u8 = 17;
/// IPv6 next-header value of ICMPv6.
pub const PROTO_ICMPV6: u8 = 58;

/// Smallest legal IPv4 header, and the offset of the transport header when no
/// option is present.
pub const IPV4_MIN_HEADER: usize = 20;
/// The IPv6 fixed header, which is also the transport offset when no extension
/// header follows.
pub const IPV6_HEADER: usize = 40;

/// TCP FIN flag.
pub const TCP_FIN: u8 = 0x01;
/// TCP SYN flag.
pub const TCP_SYN: u8 = 0x02;
/// TCP RST flag.
pub const TCP_RST: u8 = 0x04;
/// TCP ACK flag.
pub const TCP_ACK: u8 = 0x10;

/// ICMPv4 echo reply.
pub const ICMPV4_ECHO_REPLY: u8 = 0;
/// ICMPv4 destination unreachable.
pub const ICMPV4_DEST_UNREACHABLE: u8 = 3;
/// ICMPv4 echo request.
pub const ICMPV4_ECHO_REQUEST: u8 = 8;
/// ICMPv6 destination unreachable.
pub const ICMPV6_DEST_UNREACHABLE: u8 = 1;
/// ICMPv6 echo request.
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
/// ICMPv6 echo reply.
pub const ICMPV6_ECHO_REPLY: u8 = 129;

/// Which endpoint of a packet a rewrite touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The source address and, when one is given, the source port or echo
    /// identifier.
    Source,
    /// The destination address and, when one is given, the destination port or
    /// echo identifier.
    Destination,
}

/// The fixed IP header of a packet the gateway accepted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IpHeader {
    /// Source address.
    pub src: IpAddr,
    /// Destination address.
    pub dst: IpAddr,
    /// Transport protocol (IPv4) or next header (IPv6).
    pub protocol: u8,
    /// Offset of the transport header inside the packet.
    pub l4_offset: usize,
    /// Length of the packet as the header declares it, never more than the
    /// buffer it was parsed from.
    pub total_len: usize,
}

impl IpHeader {
    /// True for an IPv6 packet.
    #[must_use]
    pub const fn is_v6(&self) -> bool {
        matches!(self.src, IpAddr::V6(_))
    }
}

impl std::fmt::Debug for IpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The addresses identify the peer and the site it talks to, so the
        // shape is rendered and the endpoints are not.
        f.debug_struct("IpHeader")
            .field("v6", &self.is_v6())
            .field("protocol", &self.protocol)
            .field("l4_offset", &self.l4_offset)
            .field("total_len", &self.total_len)
            .finish()
    }
}

/// The first four bytes of an ICMP message, plus the echo identifier when the
/// message carries one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpHeader {
    /// ICMP type.
    pub kind: u8,
    /// ICMP code.
    pub code: u8,
    /// The echo identifier, for an echo request or reply long enough to carry
    /// one. Read by type alone, so the caller pairs it with the family through
    /// [`is_echo`] before treating it as a translatable identifier.
    pub echo_id: Option<u16>,
}

/// True when `kind` is an echo request or reply of that family.
#[must_use]
pub const fn is_echo(protocol: u8, kind: u8) -> bool {
    match protocol {
        PROTO_ICMPV4 => matches!(kind, ICMPV4_ECHO_REQUEST | ICMPV4_ECHO_REPLY),
        PROTO_ICMPV6 => matches!(kind, ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY),
        _ => false,
    }
}

/// True when `kind` is an ICMP error, the class whose payload quotes the packet
/// that caused it (RFC 1122, RFC 4443).
#[must_use]
pub const fn is_icmp_error(protocol: u8, kind: u8) -> bool {
    match protocol {
        PROTO_ICMPV4 => matches!(kind, 3 | 4 | 5 | 11 | 12),
        PROTO_ICMPV6 => kind >= 1 && kind <= 4,
        _ => false,
    }
}

/// True for an IPv6 next-header value that introduces an extension header
/// rather than a transport header.
const fn is_extension_header(next: u8) -> bool {
    matches!(next, 0 | 43 | 44 | 50 | 51 | 59 | 60 | 135 | 139 | 140)
}

/// Reads the fixed IP header.
///
/// # Errors
///
/// [`PacketError::Truncated`] when the buffer is shorter than the header
/// declares, [`PacketError::BadVersion`] for a version nibble that is not 4 or
/// 6, [`PacketError::Fragment`] for an IPv4 fragment and
/// [`PacketError::ExtensionHeader`] for an IPv6 packet whose next header is not
/// a transport header.
pub fn parse_ip(pkt: &[u8]) -> Result<IpHeader, PacketError> {
    let first = *pkt.first().ok_or(PacketError::Truncated)?;
    match first >> 4 {
        4 => {
            if pkt.len() < IPV4_MIN_HEADER {
                return Err(PacketError::Truncated);
            }
            let ihl = usize::from(first & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
            if ihl < IPV4_MIN_HEADER || total_len < ihl || total_len > pkt.len() {
                return Err(PacketError::Truncated);
            }
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
            // More-fragments set, or a non-zero offset: either way the ports
            // are not reliably here.
            if frag & 0x2000 != 0 || frag & 0x1fff != 0 {
                return Err(PacketError::Fragment);
            }
            let src = <[u8; 4]>::try_from(&pkt[12..16]).map_err(|_| PacketError::Truncated)?;
            let dst = <[u8; 4]>::try_from(&pkt[16..20]).map_err(|_| PacketError::Truncated)?;
            Ok(IpHeader {
                src: IpAddr::V4(Ipv4Addr::from(src)),
                dst: IpAddr::V4(Ipv4Addr::from(dst)),
                protocol: pkt[9],
                l4_offset: ihl,
                total_len,
            })
        }
        6 => {
            if pkt.len() < IPV6_HEADER {
                return Err(PacketError::Truncated);
            }
            let total_len = IPV6_HEADER + usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
            if total_len > pkt.len() {
                return Err(PacketError::Truncated);
            }
            if is_extension_header(pkt[6]) {
                return Err(PacketError::ExtensionHeader);
            }
            let src = <[u8; 16]>::try_from(&pkt[8..24]).map_err(|_| PacketError::Truncated)?;
            let dst = <[u8; 16]>::try_from(&pkt[24..40]).map_err(|_| PacketError::Truncated)?;
            Ok(IpHeader {
                src: IpAddr::V6(Ipv6Addr::from(src)),
                dst: IpAddr::V6(Ipv6Addr::from(dst)),
                protocol: pkt[6],
                l4_offset: IPV6_HEADER,
                total_len,
            })
        }
        _ => Err(PacketError::BadVersion),
    }
}

/// Reads the source and destination ports of a TCP or UDP header at `l4_offset`.
///
/// # Errors
///
/// [`PacketError::Truncated`] when the four bytes are not there.
pub fn read_ports(pkt: &[u8], l4_offset: usize) -> Result<(u16, u16), PacketError> {
    let head = pkt
        .get(l4_offset..l4_offset + 4)
        .ok_or(PacketError::Truncated)?;
    Ok((
        u16::from_be_bytes([head[0], head[1]]),
        u16::from_be_bytes([head[2], head[3]]),
    ))
}

/// Reads the TCP flag byte at `l4_offset`.
///
/// # Errors
///
/// [`PacketError::Truncated`] when the TCP header is not there.
pub fn tcp_flags(pkt: &[u8], l4_offset: usize) -> Result<u8, PacketError> {
    pkt.get(l4_offset + 13)
        .copied()
        .ok_or(PacketError::Truncated)
}

/// Reads the head of an ICMP or ICMPv6 message at `l4_offset`.
///
/// # Errors
///
/// [`PacketError::Truncated`] when the four fixed bytes are not there.
pub fn read_icmp(pkt: &[u8], l4_offset: usize) -> Result<IcmpHeader, PacketError> {
    let head = pkt
        .get(l4_offset..l4_offset + 4)
        .ok_or(PacketError::Truncated)?;
    let kind = head[0];
    let echo_id = if matches!(
        kind,
        ICMPV4_ECHO_REPLY | ICMPV4_ECHO_REQUEST | ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY
    ) {
        pkt.get(l4_offset + 4..l4_offset + 6)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
    } else {
        None
    };
    Ok(IcmpHeader {
        kind,
        code: head[1],
        echo_id,
    })
}

/// Folds an RFC 1624 incremental update over a run of 16-bit words: `ck` covers
/// `old`, the result covers `new` in its place.
#[must_use]
pub fn checksum_update<const N: usize>(ck: u16, old: &[u8; N], new: &[u8; N]) -> u16 {
    const { assert!(N % 2 == 0, "an update run must be whole 16-bit words") }
    let mut ck = ck;
    for (o, n) in old.chunks_exact(2).zip(new.chunks_exact(2)) {
        ck = incremental_checksum_update(
            ck,
            u16::from_be_bytes([o[0], o[1]]),
            u16::from_be_bytes([n[0], n[1]]),
        );
    }
    ck
}

/// Where the checksum of a transport header sits, and whether the IP addresses
/// take part in it through a pseudo-header.
fn l4_checksum(protocol: u8) -> Option<(usize, bool, usize)> {
    match protocol {
        // (offset of the checksum, addresses covered, bytes the header needs)
        PROTO_TCP => Some((16, true, 20)),
        PROTO_UDP => Some((6, true, 8)),
        PROTO_ICMPV4 => Some((2, false, 4)),
        PROTO_ICMPV6 => Some((2, true, 4)),
        _ => None,
    }
}

/// Rewrites one endpoint of a packet: its address, and its port or echo
/// identifier when `port` is given, repairing the IPv4 header checksum and the
/// transport checksum incrementally.
///
/// A UDP datagram sent without a checksum (all-zero, legal on IPv4) keeps none,
/// because computing one here would claim an integrity the sender never
/// offered.
///
/// # Errors
///
/// [`PacketError::FamilyMismatch`] when `addr` is not of the packet's family,
/// [`PacketError::Truncated`] when the buffer no longer holds the header the
/// packet declares or the transport header is short,
/// [`PacketError::UnsupportedProtocol`] for a protocol with no known checksum
/// layout, and [`PacketError::NotAnEcho`] when an identifier is offered to an
/// ICMP message that carries none.
pub fn rewrite_endpoint(
    pkt: &mut [u8],
    hdr: &IpHeader,
    side: Side,
    addr: IpAddr,
    port: Option<u16>,
) -> Result<(), PacketError> {
    if addr.is_ipv6() != hdr.is_v6() {
        return Err(PacketError::FamilyMismatch);
    }
    if pkt.len() < hdr.total_len {
        return Err(PacketError::Truncated);
    }
    let (ck_at, pseudo, need) =
        l4_checksum(hdr.protocol).ok_or(PacketError::UnsupportedProtocol)?;
    let l4 = hdr.l4_offset;
    if hdr.total_len < l4 + need {
        return Err(PacketError::Truncated);
    }
    let icmp = matches!(hdr.protocol, PROTO_ICMPV4 | PROTO_ICMPV6);
    // The identifier and the ports live at different offsets, and an ICMP
    // message that is not an echo has no identifier at all.
    let port_at = if port.is_some() {
        if icmp {
            let kind = pkt.get(l4).copied().ok_or(PacketError::Truncated)?;
            if !is_echo(hdr.protocol, kind) {
                return Err(PacketError::NotAnEcho);
            }
            if hdr.total_len < l4 + 8 {
                return Err(PacketError::Truncated);
            }
            Some(l4 + 4)
        } else {
            Some(match side {
                Side::Source => l4,
                Side::Destination => l4 + 2,
            })
        }
    } else {
        None
    };

    let addr_at = match (hdr.is_v6(), side) {
        (false, Side::Source) => 12,
        (false, Side::Destination) => 16,
        (true, Side::Source) => 8,
        (true, Side::Destination) => 24,
    };
    // A UDP datagram whose checksum field is zero carries none; it must stay
    // zero, which is not the same value as the 0xFFFF a computed sum of zero is
    // sent as.
    let mut ck = u16::from_be_bytes([pkt[l4 + ck_at], pkt[l4 + ck_at + 1]]);
    let keep_unchecksummed = hdr.protocol == PROTO_UDP && ck == 0 && !hdr.is_v6();

    match addr {
        IpAddr::V4(new) => {
            let old = <[u8; 4]>::try_from(&pkt[addr_at..addr_at + 4])
                .map_err(|_| PacketError::Truncated)?;
            let new = new.octets();
            pkt[addr_at..addr_at + 4].copy_from_slice(&new);
            let header_ck = u16::from_be_bytes([pkt[10], pkt[11]]);
            let header_ck = checksum_update(header_ck, &old, &new);
            pkt[10..12].copy_from_slice(&header_ck.to_be_bytes());
            if pseudo && !keep_unchecksummed {
                ck = checksum_update(ck, &old, &new);
            }
        }
        IpAddr::V6(new) => {
            let old = <[u8; 16]>::try_from(&pkt[addr_at..addr_at + 16])
                .map_err(|_| PacketError::Truncated)?;
            let new = new.octets();
            pkt[addr_at..addr_at + 16].copy_from_slice(&new);
            if pseudo && !keep_unchecksummed {
                ck = checksum_update(ck, &old, &new);
            }
        }
    }

    if let (Some(at), Some(new)) = (port_at, port) {
        let old = <[u8; 2]>::try_from(&pkt[at..at + 2]).map_err(|_| PacketError::Truncated)?;
        let new = new.to_be_bytes();
        pkt[at..at + 2].copy_from_slice(&new);
        if !keep_unchecksummed {
            ck = checksum_update(ck, &old, &new);
        }
    }
    if !keep_unchecksummed {
        pkt[l4 + ck_at..l4 + ck_at + 2].copy_from_slice(&ck.to_be_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testpkt;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(a: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(a))
    }

    fn v6(last: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last))
    }

    #[test]
    fn oracle_matches_a_known_ipv4_header_checksum() {
        // Textbook IPv4 header whose checksum is 0xb861, computed here by the
        // test's own full recompute so the oracle itself is anchored.
        let mut hdr = [
            0x45u8, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(testpkt::ones_sum(0, &hdr), 0xb861);
        hdr[10] = 0xb8;
        hdr[11] = 0x61;
        assert_eq!(testpkt::ones_sum(0, &hdr), 0);
    }

    #[test]
    fn checksum_update_matches_rfc_1624_equation_three() {
        // RFC 1624 section 4: the case where the naive equation yields the
        // negative zero 0xFFFF and the correct answer is 0x0000.
        assert_eq!(
            checksum_update(0xdd2f, &0x5555u16.to_be_bytes(), &0x3285u16.to_be_bytes()),
            0
        );
    }

    #[test]
    fn parses_a_v4_udp_header() {
        let pkt = testpkt::udp(v4([10, 67, 0, 2]), 1234, v4([1, 1, 1, 1]), 53, b"q");
        let hdr = parse_ip(&pkt).expect("valid packet");
        assert_eq!(hdr.src, v4([10, 67, 0, 2]));
        assert_eq!(hdr.dst, v4([1, 1, 1, 1]));
        assert_eq!(hdr.protocol, PROTO_UDP);
        assert_eq!(hdr.l4_offset, 20);
        assert_eq!(hdr.total_len, pkt.len());
        assert_eq!(read_ports(&pkt, hdr.l4_offset), Ok((1234, 53)));
    }

    #[test]
    fn parses_a_v6_tcp_header() {
        let pkt = testpkt::tcp(v6(2), 40000, v6(1), 443, TCP_SYN, b"");
        let hdr = parse_ip(&pkt).expect("valid packet");
        assert_eq!(hdr.src, v6(2));
        assert_eq!(hdr.dst, v6(1));
        assert_eq!(hdr.protocol, PROTO_TCP);
        assert_eq!(hdr.l4_offset, 40);
        assert_eq!(hdr.total_len, pkt.len());
        assert_eq!(read_ports(&pkt, hdr.l4_offset), Ok((40000, 443)));
        assert_eq!(tcp_flags(&pkt, hdr.l4_offset), Ok(TCP_SYN));
    }

    #[test]
    fn reads_an_icmp_echo_identifier() {
        let pkt = testpkt::echo(v4([10, 67, 0, 2]), v4([1, 1, 1, 1]), 0x4142, 7, b"ping");
        let hdr = parse_ip(&pkt).expect("valid packet");
        let icmp = read_icmp(&pkt, hdr.l4_offset).expect("icmp header");
        assert_eq!(icmp.kind, ICMPV4_ECHO_REQUEST);
        assert_eq!(icmp.echo_id, Some(0x4142));
    }

    #[test]
    fn refuses_a_packet_shorter_than_its_header() {
        let pkt = testpkt::udp(v4([10, 67, 0, 2]), 1, v4([1, 1, 1, 1]), 2, b"");
        for len in 0..pkt.len() {
            assert!(
                parse_ip(&pkt[..len]).is_err(),
                "a {len}-byte prefix must not parse"
            );
        }
        assert_eq!(parse_ip(&[]), Err(PacketError::Truncated));
    }

    #[test]
    fn refuses_a_version_that_is_not_ip() {
        assert_eq!(parse_ip(&[0x00; 40]), Err(PacketError::BadVersion));
    }

    #[test]
    fn refuses_a_v4_fragment() {
        let mut pkt = testpkt::udp(v4([10, 67, 0, 2]), 1, v4([1, 1, 1, 1]), 2, b"payload");
        pkt[6] = 0x20; // more-fragments
        assert_eq!(parse_ip(&pkt), Err(PacketError::Fragment));
        pkt[6] = 0x00;
        pkt[7] = 0x10; // non-zero fragment offset
        assert_eq!(parse_ip(&pkt), Err(PacketError::Fragment));
    }

    #[test]
    fn refuses_a_v6_extension_header() {
        let mut pkt = testpkt::udp(v6(2), 1, v6(1), 2, b"payload");
        for next in [0u8, 43, 44, 50, 51, 60, 135] {
            pkt[6] = next;
            assert_eq!(
                parse_ip(&pkt),
                Err(PacketError::ExtensionHeader),
                "next header {next} must be refused"
            );
        }
    }

    #[test]
    fn rewrites_a_v4_udp_endpoint_against_the_independent_oracle() {
        let mut pkt = testpkt::udp(v4([10, 67, 0, 2]), 1234, v4([1, 1, 1, 1]), 53, b"question");
        let hdr = parse_ip(&pkt).expect("valid packet");
        rewrite_endpoint(
            &mut pkt,
            &hdr,
            Side::Source,
            v4([10, 66, 0, 2]),
            Some(40000),
        )
        .expect("rewrite");
        let after = parse_ip(&pkt).expect("still valid");
        assert_eq!(after.src, v4([10, 66, 0, 2]));
        assert_eq!(read_ports(&pkt, after.l4_offset), Ok((40000, 53)));
        assert!(
            testpkt::checksums_valid(&pkt),
            "checksums after the rewrite"
        );
    }

    #[test]
    fn rewrites_a_v4_tcp_destination_against_the_independent_oracle() {
        let mut pkt = testpkt::tcp(
            v4([1, 1, 1, 1]),
            443,
            v4([10, 66, 0, 2]),
            40000,
            TCP_ACK,
            b"h",
        );
        let hdr = parse_ip(&pkt).expect("valid packet");
        rewrite_endpoint(
            &mut pkt,
            &hdr,
            Side::Destination,
            v4([10, 67, 0, 2]),
            Some(1234),
        )
        .expect("rewrite");
        let after = parse_ip(&pkt).expect("still valid");
        assert_eq!(after.dst, v4([10, 67, 0, 2]));
        assert_eq!(read_ports(&pkt, after.l4_offset), Ok((443, 1234)));
        assert!(
            testpkt::checksums_valid(&pkt),
            "checksums after the rewrite"
        );
    }

    #[test]
    fn rewrites_a_v6_udp_endpoint_against_the_independent_oracle() {
        let mut pkt = testpkt::udp(v6(2), 1234, v6(1), 53, b"question");
        let hdr = parse_ip(&pkt).expect("valid packet");
        rewrite_endpoint(&mut pkt, &hdr, Side::Source, v6(0xbeef), Some(40000)).expect("rewrite");
        let after = parse_ip(&pkt).expect("still valid");
        assert_eq!(after.src, v6(0xbeef));
        assert_eq!(read_ports(&pkt, after.l4_offset), Ok((40000, 53)));
        assert!(
            testpkt::checksums_valid(&pkt),
            "checksums after the rewrite"
        );
    }

    #[test]
    fn rewrites_a_v6_tcp_endpoint_against_the_independent_oracle() {
        let mut pkt = testpkt::tcp(v6(2), 1234, v6(1), 443, TCP_SYN, b"");
        let hdr = parse_ip(&pkt).expect("valid packet");
        rewrite_endpoint(&mut pkt, &hdr, Side::Source, v6(0xbeef), Some(40000)).expect("rewrite");
        assert!(
            testpkt::checksums_valid(&pkt),
            "checksums after the rewrite"
        );
    }

    #[test]
    fn keeps_a_zero_v4_udp_checksum_zero() {
        let mut pkt = testpkt::udp(v4([10, 67, 0, 2]), 1234, v4([1, 1, 1, 1]), 53, b"q");
        pkt[26] = 0;
        pkt[27] = 0;
        let hdr = parse_ip(&pkt).expect("valid packet");
        rewrite_endpoint(
            &mut pkt,
            &hdr,
            Side::Source,
            v4([10, 66, 0, 2]),
            Some(40000),
        )
        .expect("rewrite");
        assert_eq!(
            u16::from_be_bytes([pkt[26], pkt[27]]),
            0,
            "a UDP datagram sent without a checksum keeps none"
        );
        assert!(testpkt::checksums_valid(&pkt), "the IPv4 header checksum");
    }

    #[test]
    fn rewrites_an_icmpv4_echo_identifier_against_the_independent_oracle() {
        let mut pkt = testpkt::echo(v4([10, 67, 0, 2]), v4([1, 1, 1, 1]), 0x4142, 7, b"ping");
        let hdr = parse_ip(&pkt).expect("valid packet");
        rewrite_endpoint(
            &mut pkt,
            &hdr,
            Side::Source,
            v4([10, 66, 0, 2]),
            Some(0x9001),
        )
        .expect("rewrite");
        let after = parse_ip(&pkt).expect("still valid");
        assert_eq!(
            read_icmp(&pkt, after.l4_offset).expect("icmp").echo_id,
            Some(0x9001)
        );
        assert!(
            testpkt::checksums_valid(&pkt),
            "checksums after the rewrite"
        );
    }

    #[test]
    fn rewrites_an_icmpv6_echo_identifier_including_the_pseudo_header() {
        let mut pkt = testpkt::echo(v6(2), v6(1), 0x4142, 7, b"ping");
        let hdr = parse_ip(&pkt).expect("valid packet");
        rewrite_endpoint(&mut pkt, &hdr, Side::Source, v6(0xbeef), Some(0x9001)).expect("rewrite");
        assert!(
            testpkt::checksums_valid(&pkt),
            "an ICMPv6 checksum covers the addresses too"
        );
    }

    #[test]
    fn refuses_an_address_of_the_wrong_family() {
        let mut pkt = testpkt::udp(v4([10, 67, 0, 2]), 1, v4([1, 1, 1, 1]), 2, b"");
        let hdr = parse_ip(&pkt).expect("valid packet");
        assert_eq!(
            rewrite_endpoint(&mut pkt, &hdr, Side::Source, v6(1), Some(3)),
            Err(PacketError::FamilyMismatch)
        );
    }

    #[test]
    fn refuses_to_rewrite_a_protocol_it_does_not_translate() {
        let mut pkt = testpkt::udp(v4([10, 67, 0, 2]), 1, v4([1, 1, 1, 1]), 2, b"");
        pkt[9] = 47; // GRE
        let ck = ones_complement_header(&pkt);
        pkt[10..12].copy_from_slice(&ck.to_be_bytes());
        let hdr = parse_ip(&pkt).expect("valid packet");
        assert_eq!(
            rewrite_endpoint(&mut pkt, &hdr, Side::Source, v4([10, 66, 0, 2]), None),
            Err(PacketError::UnsupportedProtocol)
        );
    }

    #[test]
    fn refuses_an_identifier_rewrite_on_an_icmp_message_that_is_not_an_echo() {
        let mut pkt = testpkt::echo(v4([10, 67, 0, 2]), v4([1, 1, 1, 1]), 1, 1, b"x");
        pkt[20] = ICMPV4_DEST_UNREACHABLE;
        let hdr = parse_ip(&pkt).expect("valid packet");
        assert_eq!(
            rewrite_endpoint(&mut pkt, &hdr, Side::Source, v4([10, 66, 0, 2]), Some(9)),
            Err(PacketError::NotAnEcho)
        );
    }

    #[test]
    fn never_panics_on_a_buffer_shorter_than_the_header_says() {
        let full = testpkt::udp(v4([10, 67, 0, 2]), 1234, v4([1, 1, 1, 1]), 53, b"payload");
        let hdr = parse_ip(&full).expect("valid packet");
        for len in 0..full.len() {
            let mut short = full[..len].to_vec();
            assert!(
                rewrite_endpoint(&mut short, &hdr, Side::Source, v4([10, 66, 0, 2]), Some(1))
                    .is_err(),
                "a {len}-byte buffer must be refused, not indexed"
            );
            let _ = read_ports(&short, hdr.l4_offset);
            let _ = read_icmp(&short, hdr.l4_offset);
            let _ = tcp_flags(&short, hdr.l4_offset);
        }
    }

    /// The IPv4 header checksum computed by the test's own full recompute.
    fn ones_complement_header(pkt: &[u8]) -> u16 {
        let mut hdr = pkt[..20].to_vec();
        hdr[10] = 0;
        hdr[11] = 0;
        testpkt::ones_sum(0, &hdr)
    }
}
