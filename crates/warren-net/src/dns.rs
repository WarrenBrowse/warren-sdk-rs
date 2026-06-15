//! Minimal DNS client codec for resolution over the tunnel (no host resolver,
//! so the lookup cannot leak outside the VPN).
//!
//! Just enough of RFC 1035/3596 to ask for and read `A` (IPv4) and `AAAA` (IPv6)
//! records: a single-question query with recursion desired, and a response parser
//! that skips names (including compression pointers) and collects the answers of
//! the requested type. Hand-rolled to avoid a dependency; the wire layout is
//! pinned by golden-byte tests.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// DNS record type `A` (IPv4 host address).
const TYPE_A: u16 = 1;
/// DNS record type `AAAA` (IPv6 host address, RFC 3596).
const TYPE_AAAA: u16 = 28;
/// DNS class `IN` (Internet).
const CLASS_IN: u16 = 1;

/// The address record type to query for over the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// `A`: an IPv4 address (4-byte RDATA).
    A,
    /// `AAAA`: an IPv6 address (16-byte RDATA).
    Aaaa,
}

impl RecordType {
    /// The QTYPE value on the wire.
    fn qtype(self) -> u16 {
        match self {
            RecordType::A => TYPE_A,
            RecordType::Aaaa => TYPE_AAAA,
        }
    }

    /// The expected RDATA length for this record type.
    fn rdlen(self) -> usize {
        match self {
            RecordType::A => 4,
            RecordType::Aaaa => 16,
        }
    }
}
/// Header flag: recursion desired (byte 2, bit 0).
const FLAG_RD: u16 = 0x0100;
/// Header flag: query/response bit (set in responses).
const FLAG_QR: u16 = 0x8000;
/// Low 4 bits of the response flags carry the RCODE.
const RCODE_MASK: u16 = 0x000F;
/// A name label whose two high bits are set is a compression pointer.
const POINTER_MASK: u8 = 0xC0;
/// The fixed DNS header length in bytes.
const HEADER_LEN: usize = 12;

/// Errors from [`encode_query`] and [`parse_response`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsError {
    /// The name is empty, too long, or has a label over 63 bytes.
    #[error("invalid DNS name")]
    InvalidName,
    /// The response was shorter than required at some field.
    #[error("DNS response truncated")]
    Truncated,
    /// The response id did not match the query id (possible spoof).
    #[error("DNS response id mismatch")]
    IdMismatch,
    /// The response is not a response, or its RCODE is non-zero.
    #[error("DNS server returned an error response")]
    ServerFailure,
    /// The response carried no record of the requested type for the name.
    #[error("no address record in the DNS response")]
    NoAddress,
}

/// Encodes a single-question `IN` query of type `rtype` for `name` with recursion
/// desired.
///
/// `id` is the 16-bit transaction id the caller must match against the response
/// (use an unpredictable value per query to resist off-path spoofing).
///
/// # Errors
///
/// [`DnsError::InvalidName`] if `name` is empty, exceeds 255 bytes on the wire,
/// or has an empty or over-long (>63 byte) label.
pub fn encode_query(name: &str, id: u16, rtype: RecordType) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(name, &mut out)?;
    out.extend_from_slice(&rtype.qtype().to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// Encodes a domain name as length-prefixed labels terminated by a zero byte.
fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        return Err(DnsError::InvalidName);
    }
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(DnsError::InvalidName);
        }
        // A label length never sets the two high bits (those mark a pointer).
        out.push(u8::try_from(bytes.len()).map_err(|_| DnsError::InvalidName)?);
        out.extend_from_slice(bytes);
    }
    if out.len() + 1 > HEADER_LEN + 255 {
        return Err(DnsError::InvalidName);
    }
    out.push(0); // root label terminator
    Ok(())
}

/// Parses a DNS response and returns every address of type `want` it carries.
///
/// Validates the transaction `id` and the RCODE before reading answers, so a
/// spoofed or error reply is rejected rather than mined for addresses.
///
/// # Errors
///
/// [`DnsError::IdMismatch`] on an id mismatch, [`DnsError::ServerFailure`] if
/// the QR bit is unset or the RCODE is non-zero, [`DnsError::Truncated`] on a
/// short buffer, and [`DnsError::NoAddress`] if no record of type `want` is
/// present.
pub fn parse_response(buf: &[u8], id: u16, want: RecordType) -> Result<Vec<IpAddr>, DnsError> {
    parse_response_ttl(buf, id, want).map(|(addrs, _ttl)| addrs)
}

/// Like [`parse_response`] but also returns the smallest TTL (seconds) across the
/// matching answer records, for a caller that caches results. `0` if no matching
/// record carried a TTL (treated as "do not cache" by callers).
///
/// # Errors
///
/// Same as [`parse_response`].
pub fn parse_response_ttl(
    buf: &[u8],
    id: u16,
    want: RecordType,
) -> Result<(Vec<IpAddr>, u32), DnsError> {
    if buf.len() < HEADER_LEN {
        return Err(DnsError::Truncated);
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != id {
        return Err(DnsError::IdMismatch);
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & FLAG_QR == 0 || flags & RCODE_MASK != 0 {
        return Err(DnsError::ServerFailure);
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);

    let mut pos = HEADER_LEN;
    // Skip the echoed question section: each is name + QTYPE(2) + QCLASS(2).
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos = pos.checked_add(4).ok_or(DnsError::Truncated)?;
        if pos > buf.len() {
            return Err(DnsError::Truncated);
        }
    }

    let mut addrs = Vec::new();
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) then RDATA.
        let header_end = pos.checked_add(10).ok_or(DnsError::Truncated)?;
        if header_end > buf.len() {
            return Err(DnsError::Truncated);
        }
        let rec_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlength = usize::from(u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]));
        let rdata = header_end;
        let rdata_end = rdata.checked_add(rdlength).ok_or(DnsError::Truncated)?;
        if rdata_end > buf.len() {
            return Err(DnsError::Truncated);
        }
        if rec_type == want.qtype() && rclass == CLASS_IN && rdlength == want.rdlen() {
            match want {
                RecordType::A => addrs.push(IpAddr::V4(Ipv4Addr::new(
                    buf[rdata],
                    buf[rdata + 1],
                    buf[rdata + 2],
                    buf[rdata + 3],
                ))),
                RecordType::Aaaa => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&buf[rdata..rdata_end]);
                    addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
            }
            min_ttl = min_ttl.min(ttl);
        }
        pos = rdata_end;
    }

    if addrs.is_empty() {
        return Err(DnsError::NoAddress);
    }
    Ok((addrs, if min_ttl == u32::MAX { 0 } else { min_ttl }))
}

/// Returns the offset just past the name at `pos`, following compression
/// pointers only to skip (a pointer ends the in-line name).
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, DnsError> {
    loop {
        let len = *buf.get(pos).ok_or(DnsError::Truncated)?;
        if len & POINTER_MASK == POINTER_MASK {
            // A 2-byte pointer terminates the name in this record.
            return pos.checked_add(2).ok_or(DnsError::Truncated);
        }
        if len == 0 {
            return pos.checked_add(1).ok_or(DnsError::Truncated);
        }
        // A normal label: advance past the length byte and its bytes.
        pos = pos
            .checked_add(1 + usize::from(len))
            .ok_or(DnsError::Truncated)?;
        if pos > buf.len() {
            return Err(DnsError::Truncated);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_for_example_com_is_byte_exact() {
        let q = encode_query("example.com", 0x1234, RecordType::A).expect("encode");
        assert_eq!(
            hex::encode(q),
            "123401000001000000000000076578616d706c6503636f6d0000010001"
        );
    }

    #[test]
    fn aaaa_query_for_example_com_is_byte_exact() {
        // Identical to the A query except QTYPE = 0x001c (28).
        let q = encode_query("example.com", 0x1234, RecordType::Aaaa).expect("encode");
        assert_eq!(
            hex::encode(q),
            "123401000001000000000000076578616d706c6503636f6d00001c0001"
        );
    }

    #[test]
    fn trailing_dot_is_accepted_and_normalised() {
        assert_eq!(
            encode_query("example.com.", 1, RecordType::A).unwrap(),
            encode_query("example.com", 1, RecordType::A).unwrap()
        );
    }

    #[test]
    fn empty_and_overlong_labels_are_rejected() {
        assert_eq!(
            encode_query("", 1, RecordType::A),
            Err(DnsError::InvalidName)
        );
        assert_eq!(
            encode_query("a..b", 1, RecordType::A),
            Err(DnsError::InvalidName)
        );
        let long = "x".repeat(64);
        assert_eq!(
            encode_query(&long, 1, RecordType::A),
            Err(DnsError::InvalidName)
        );
    }

    /// A response for example.com with one A record 93.184.216.34, using a
    /// compression pointer (0xC00C) for the answer name.
    fn example_response() -> Vec<u8> {
        hex::decode(concat!(
            "12348180000100010000000007",
            "6578616d706c6503636f6d00",
            "00010001",             // question QTYPE/QCLASS
            "c00c0001000100000100", // answer: ptr, A, IN, TTL
            "00045db8d822",         // RDLENGTH 4, 93.184.216.34
        ))
        .unwrap()
    }

    #[test]
    fn parses_the_a_record_from_a_pointer_answer() {
        let addrs = parse_response(&example_response(), 0x1234, RecordType::A).expect("parse");
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }

    /// A response for example.com with one AAAA record
    /// 2606:2800:220:1:248:1893:25c8:1946, using a compression pointer (0xC00C)
    /// for the answer name.
    fn example_aaaa_response() -> Vec<u8> {
        hex::decode(concat!(
            "12348180000100010000000007",
            "6578616d706c6503636f6d00",
            "001c0001",                         // question QTYPE=AAAA/QCLASS
            "c00c001c000100000100",             // answer: ptr, AAAA, IN, TTL
            "0010",                             // RDLENGTH 16
            "26062800022000010248189325c81946", // RDATA: the v6 address
        ))
        .unwrap()
    }

    #[test]
    fn parses_the_aaaa_record_from_a_pointer_answer() {
        let addrs =
            parse_response(&example_aaaa_response(), 0x1234, RecordType::Aaaa).expect("parse");
        assert_eq!(
            addrs,
            vec![IpAddr::V6(
                "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
            )]
        );
    }

    #[test]
    fn an_aaaa_query_answered_only_with_a_has_no_address() {
        // The A answer must not satisfy an AAAA request.
        assert_eq!(
            parse_response(&example_response(), 0x1234, RecordType::Aaaa),
            Err(DnsError::NoAddress)
        );
    }

    #[test]
    fn id_mismatch_is_rejected() {
        assert_eq!(
            parse_response(&example_response(), 0x9999, RecordType::A),
            Err(DnsError::IdMismatch)
        );
    }

    #[test]
    fn nonzero_rcode_is_server_failure() {
        let mut r = example_response();
        r[3] |= 0x03; // RCODE = NXDOMAIN
        assert_eq!(
            parse_response(&r, 0x1234, RecordType::A),
            Err(DnsError::ServerFailure)
        );
    }

    #[test]
    fn a_query_echoed_as_response_with_no_answers_has_no_address() {
        // QR set, ANCOUNT 0.
        let bytes = hex::decode(
            "12348180000100000000000007 6578616d706c6503636f6d00 00010001".replace(' ', ""),
        )
        .unwrap();
        assert_eq!(
            parse_response(&bytes, 0x1234, RecordType::A),
            Err(DnsError::NoAddress)
        );
    }

    #[test]
    fn truncated_header_is_truncated() {
        assert_eq!(
            parse_response(&[0x12, 0x34], 0x1234, RecordType::A),
            Err(DnsError::Truncated)
        );
    }
}
