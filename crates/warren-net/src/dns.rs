//! Minimal DNS client codec for resolution over the tunnel (no host resolver,
//! so the lookup cannot leak outside the VPN).
//!
//! Just enough of RFC 1035 to ask for and read `A` records: a single-question
//! query with recursion desired, and a response parser that skips names
//! (including compression pointers) and collects the IPv4 answers. Hand-rolled
//! to avoid a dependency; the wire layout is pinned by golden-byte tests.

use std::net::Ipv4Addr;

/// DNS record type `A` (IPv4 host address).
const TYPE_A: u16 = 1;
/// DNS class `IN` (Internet).
const CLASS_IN: u16 = 1;
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
    /// The response carried no `A` record for the name.
    #[error("no A record in the DNS response")]
    NoAddress,
}

/// Encodes a single-question `A`/`IN` query for `name` with recursion desired.
///
/// `id` is the 16-bit transaction id the caller must match against the response
/// (use an unpredictable value per query to resist off-path spoofing).
///
/// # Errors
///
/// [`DnsError::InvalidName`] if `name` is empty, exceeds 255 bytes on the wire,
/// or has an empty or over-long (>63 byte) label.
pub fn encode_query(name: &str, id: u16) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(name, &mut out)?;
    out.extend_from_slice(&TYPE_A.to_be_bytes());
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

/// Parses a DNS response and returns every `A` record address it carries.
///
/// Validates the transaction `id` and the RCODE before reading answers, so a
/// spoofed or error reply is rejected rather than mined for addresses.
///
/// # Errors
///
/// [`DnsError::IdMismatch`] on an id mismatch, [`DnsError::ServerFailure`] if
/// the QR bit is unset or the RCODE is non-zero, [`DnsError::Truncated`] on a
/// short buffer, and [`DnsError::NoAddress`] if no `A` record is present.
pub fn parse_response(buf: &[u8], id: u16) -> Result<Vec<Ipv4Addr>, DnsError> {
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
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) then RDATA.
        let header_end = pos.checked_add(10).ok_or(DnsError::Truncated)?;
        if header_end > buf.len() {
            return Err(DnsError::Truncated);
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let rdlength = usize::from(u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]));
        let rdata = header_end;
        let rdata_end = rdata.checked_add(rdlength).ok_or(DnsError::Truncated)?;
        if rdata_end > buf.len() {
            return Err(DnsError::Truncated);
        }
        if rtype == TYPE_A && rclass == CLASS_IN && rdlength == 4 {
            addrs.push(Ipv4Addr::new(
                buf[rdata],
                buf[rdata + 1],
                buf[rdata + 2],
                buf[rdata + 3],
            ));
        }
        pos = rdata_end;
    }

    if addrs.is_empty() {
        return Err(DnsError::NoAddress);
    }
    Ok(addrs)
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
        let q = encode_query("example.com", 0x1234).expect("encode");
        assert_eq!(
            hex::encode(q),
            "123401000001000000000000076578616d706c6503636f6d0000010001"
        );
    }

    #[test]
    fn trailing_dot_is_accepted_and_normalised() {
        assert_eq!(
            encode_query("example.com.", 1).unwrap(),
            encode_query("example.com", 1).unwrap()
        );
    }

    #[test]
    fn empty_and_overlong_labels_are_rejected() {
        assert_eq!(encode_query("", 1), Err(DnsError::InvalidName));
        assert_eq!(encode_query("a..b", 1), Err(DnsError::InvalidName));
        let long = "x".repeat(64);
        assert_eq!(encode_query(&long, 1), Err(DnsError::InvalidName));
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
        let addrs = parse_response(&example_response(), 0x1234).expect("parse");
        assert_eq!(addrs, vec![Ipv4Addr::new(93, 184, 216, 34)]);
    }

    #[test]
    fn id_mismatch_is_rejected() {
        assert_eq!(
            parse_response(&example_response(), 0x9999),
            Err(DnsError::IdMismatch)
        );
    }

    #[test]
    fn nonzero_rcode_is_server_failure() {
        let mut r = example_response();
        r[3] |= 0x03; // RCODE = NXDOMAIN
        assert_eq!(parse_response(&r, 0x1234), Err(DnsError::ServerFailure));
    }

    #[test]
    fn a_query_echoed_as_response_with_no_answers_has_no_address() {
        // QR set, ANCOUNT 0.
        let bytes = hex::decode(
            "12348180000100000000000007 6578616d706c6503636f6d00 00010001".replace(' ', ""),
        )
        .unwrap();
        assert_eq!(parse_response(&bytes, 0x1234), Err(DnsError::NoAddress));
    }

    #[test]
    fn truncated_header_is_truncated() {
        assert_eq!(
            parse_response(&[0x12, 0x34], 0x1234),
            Err(DnsError::Truncated)
        );
    }
}
