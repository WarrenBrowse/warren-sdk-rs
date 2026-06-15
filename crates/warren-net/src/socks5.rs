//! SOCKS5 (RFC 1928) wire codec for the non-root proxy datapath.
//!
//! Pure parse/build, no I/O, so it is fully unit-testable. The proxy inbound
//! uses this to terminate application TCP flows, then forwards them over the
//! QUIC tunnel. Domain targets are kept as names and resolved remotely (through
//! the tunnel) to avoid DNS leaks.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// SOCKS protocol version byte.
pub const VERSION: u8 = 0x05;
/// "No authentication required" method.
pub const METHOD_NO_AUTH: u8 = 0x00;
/// Sentinel for "no acceptable methods".
pub const METHOD_NONE: u8 = 0xff;

/// SOCKS5 command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Establish a TCP connection to the target.
    Connect,
    /// Bind (not supported by Warren).
    Bind,
    /// UDP associate.
    UdpAssociate,
}

impl Command {
    /// Whether the Warren proxy supports this command. Only `Connect` is
    /// supported; the server loop must answer `Bind` and `UdpAssociate` with
    /// [`Reply::CommandNotSupported`] rather than attempting them.
    #[must_use]
    pub fn is_supported(self) -> bool {
        matches!(self, Command::Connect)
    }
}

/// Where a SOCKS5 request wants to go. Domain names are preserved so the exit
/// resolves them, never the local resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A resolved socket address.
    Ip(SocketAddr),
    /// A host name and port (resolved remotely).
    Domain(String, u16),
}

/// SOCKS5 reply code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Success.
    Succeeded,
    /// General SOCKS server failure.
    GeneralFailure,
    /// Command not supported.
    CommandNotSupported,
    /// Address type not supported.
    AddressTypeNotSupported,
}

impl Reply {
    fn code(self) -> u8 {
        match self {
            Reply::Succeeded => 0x00,
            Reply::GeneralFailure => 0x01,
            Reply::CommandNotSupported => 0x07,
            Reply::AddressTypeNotSupported => 0x08,
        }
    }
}

/// Errors decoding a SOCKS5 message.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Socks5Error {
    /// Buffer ended before the message was complete.
    #[error("truncated SOCKS5 message")]
    Truncated,
    /// Version byte was not 0x05.
    #[error("unsupported SOCKS version: {0}")]
    BadVersion(u8),
    /// Command byte was not 1/2/3.
    #[error("unsupported SOCKS command: {0}")]
    BadCommand(u8),
    /// Address type byte was not 1/3/4.
    #[error("unsupported address type: {0}")]
    BadAtyp(u8),
    /// Domain name was not valid UTF-8.
    #[error("invalid domain name encoding")]
    BadDomain,
    /// A UDP datagram set a non-zero FRAG byte (fragmentation unsupported).
    #[error("fragmented UDP datagrams are not supported")]
    Fragmented,
}

/// Parses the client greeting (`VER NMETHODS METHODS...`), returning the offered
/// method bytes.
///
/// # Errors
///
/// [`Socks5Error::BadVersion`] or [`Socks5Error::Truncated`].
pub fn parse_greeting(buf: &[u8]) -> Result<Vec<u8>, Socks5Error> {
    if buf.len() < 2 {
        return Err(Socks5Error::Truncated);
    }
    if buf[0] != VERSION {
        return Err(Socks5Error::BadVersion(buf[0]));
    }
    let n = buf[1] as usize;
    if buf.len() < 2 + n {
        return Err(Socks5Error::Truncated);
    }
    Ok(buf[2..2 + n].to_vec())
}

/// Builds the method-selection reply (`VER METHOD`).
#[must_use]
pub fn build_method_reply(method: u8) -> [u8; 2] {
    [VERSION, method]
}

/// Parses a request (`VER CMD RSV ATYP ADDR PORT`).
///
/// # Errors
///
/// [`Socks5Error::Truncated`] on a short buffer, [`Socks5Error::BadVersion`] on a
/// non-`5` version, [`Socks5Error::BadCommand`] on an unknown command,
/// [`Socks5Error::BadAtyp`] on an unknown address type, or
/// [`Socks5Error::BadDomain`] on a non-UTF-8 domain.
pub fn parse_request(buf: &[u8]) -> Result<(Command, Target), Socks5Error> {
    if buf.len() < 4 {
        return Err(Socks5Error::Truncated);
    }
    if buf[0] != VERSION {
        return Err(Socks5Error::BadVersion(buf[0]));
    }
    let command = match buf[1] {
        0x01 => Command::Connect,
        0x02 => Command::Bind,
        0x03 => Command::UdpAssociate,
        other => return Err(Socks5Error::BadCommand(other)),
    };
    // buf[2] is RSV (ignored). buf[3] is ATYP.
    let (target, _consumed) = parse_address(&buf[3..])?;
    Ok((command, target))
}

/// Parses `ATYP ADDR PORT`, returning the target and the number of bytes read.
fn parse_address(buf: &[u8]) -> Result<(Target, usize), Socks5Error> {
    let atyp = *buf.first().ok_or(Socks5Error::Truncated)?;
    match atyp {
        0x01 => {
            if buf.len() < 1 + 4 + 2 {
                return Err(Socks5Error::Truncated);
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((Target::Ip(SocketAddr::from((ip, port))), 7))
        }
        0x04 => {
            if buf.len() < 1 + 16 + 2 {
                return Err(Socks5Error::Truncated);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((Target::Ip(SocketAddr::from((ip, port))), 19))
        }
        0x03 => {
            let len = *buf.get(1).ok_or(Socks5Error::Truncated)? as usize;
            if buf.len() < 2 + len + 2 {
                return Err(Socks5Error::Truncated);
            }
            let host = std::str::from_utf8(&buf[2..2 + len]).map_err(|_| Socks5Error::BadDomain)?;
            let port = u16::from_be_bytes([buf[2 + len], buf[2 + len + 1]]);
            Ok((Target::Domain(host.to_owned(), port), 2 + len + 2))
        }
        other => Err(Socks5Error::BadAtyp(other)),
    }
}

/// Parses a SOCKS5 UDP request datagram (`RSV RSV FRAG ATYP ADDR PORT DATA`),
/// returning the target and the payload slice.
///
/// # Errors
///
/// [`Socks5Error::Fragmented`] if the FRAG byte is non-zero (fragmentation is
/// not supported), [`Socks5Error::Truncated`] on a short buffer, or an
/// address-type/domain error from the embedded address.
pub fn parse_udp_datagram(buf: &[u8]) -> Result<(Target, &[u8]), Socks5Error> {
    // RSV(2) FRAG(1), then the standard ATYP ADDR PORT, then the payload.
    if buf.len() < 3 {
        return Err(Socks5Error::Truncated);
    }
    if buf[2] != 0x00 {
        return Err(Socks5Error::Fragmented);
    }
    let (target, consumed) = parse_address(&buf[3..])?;
    Ok((target, &buf[3 + consumed..]))
}

/// Builds a SOCKS5 UDP reply datagram: header (`RSV RSV FRAG=0 ATYP ADDR PORT`)
/// for `src` (the datagram's origin) followed by `data`.
#[must_use]
pub fn encode_udp_datagram(src: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00, 0x00]; // RSV, RSV, FRAG
    match src {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out.extend_from_slice(data);
    out
}

/// Builds a request reply. `bound` is the server-side bound address echoed back
/// (`0.0.0.0:0` is fine for a CONNECT reply).
#[must_use]
pub fn build_reply(reply: Reply, bound: SocketAddr) -> Vec<u8> {
    let mut out = vec![VERSION, reply.code(), 0x00];
    match bound {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_parses_methods() {
        let methods = parse_greeting(&[0x05, 0x02, 0x00, 0x02]).expect("parse");
        assert_eq!(methods, vec![0x00, 0x02]);
    }

    #[test]
    fn greeting_rejects_bad_version() {
        assert_eq!(
            parse_greeting(&[0x04, 0x00]),
            Err(Socks5Error::BadVersion(4))
        );
    }

    #[test]
    fn greeting_rejects_truncated() {
        assert_eq!(
            parse_greeting(&[0x05, 0x03, 0x00]),
            Err(Socks5Error::Truncated)
        );
    }

    #[test]
    fn request_parses_ipv4_connect() {
        // VER CMD RSV ATYP=1 1.2.3.4 :443
        let buf = [0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xbb];
        let (cmd, target) = parse_request(&buf).expect("parse");
        assert_eq!(cmd, Command::Connect);
        assert_eq!(target, Target::Ip("1.2.3.4:443".parse().unwrap()));
    }

    #[test]
    fn request_parses_domain_connect_and_keeps_name() {
        let host = b"example.com";
        let mut buf = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        buf.extend_from_slice(host);
        buf.extend_from_slice(&443u16.to_be_bytes());
        let (cmd, target) = parse_request(&buf).expect("parse");
        assert_eq!(cmd, Command::Connect);
        assert_eq!(target, Target::Domain("example.com".to_owned(), 443));
    }

    #[test]
    fn request_rejects_non_utf8_domain() {
        // ATYP=domain with non-UTF-8 bytes must be rejected, not lossy-decoded:
        // a malformed client request never becomes a bogus target name.
        let mut buf = vec![0x05, 0x01, 0x00, 0x03, 0x02, 0xff, 0xfe];
        buf.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(parse_request(&buf), Err(Socks5Error::BadDomain));
    }

    #[test]
    fn only_connect_is_supported() {
        // VER CMD=BIND RSV ATYP=1 1.2.3.4 :443
        let bind = [0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xbb];
        let (cmd, _) = parse_request(&bind).expect("parse");
        assert_eq!(cmd, Command::Bind);
        assert!(!cmd.is_supported(), "Bind must be rejected by the server");

        let udp = [0x05, 0x03, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xbb];
        let (cmd, _) = parse_request(&udp).expect("parse");
        assert_eq!(cmd, Command::UdpAssociate);
        assert!(!cmd.is_supported(), "UdpAssociate must be gated");

        assert!(Command::Connect.is_supported());
        // The reply the server loop owes an unsupported command.
        assert_eq!(
            build_reply(Reply::CommandNotSupported, "0.0.0.0:0".parse().unwrap())[1],
            0x07
        );
    }

    #[test]
    fn request_parses_ipv6() {
        let mut buf = vec![0x05, 0x01, 0x00, 0x04];
        buf.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        buf.extend_from_slice(&8443u16.to_be_bytes());
        let (_, target) = parse_request(&buf).expect("parse");
        assert_eq!(
            target,
            Target::Ip(SocketAddr::from((Ipv6Addr::LOCALHOST, 8443)))
        );
    }

    #[test]
    fn request_rejects_bad_command_and_atyp() {
        assert_eq!(
            parse_request(&[0x05, 0x09, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
            Err(Socks5Error::BadCommand(9))
        );
        assert_eq!(
            parse_request(&[0x05, 0x01, 0x00, 0x09]),
            Err(Socks5Error::BadAtyp(9))
        );
    }

    #[test]
    fn udp_datagram_parses_ipv4_target_and_payload() {
        // RSV RSV FRAG ATYP=1 1.2.3.4 :53 "hello"
        let mut buf = vec![0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35];
        buf.extend_from_slice(b"hello");
        let (target, data) = parse_udp_datagram(&buf).expect("parse");
        assert_eq!(target, Target::Ip("1.2.3.4:53".parse().unwrap()));
        assert_eq!(data, b"hello");
    }

    #[test]
    fn udp_datagram_parses_domain_target() {
        let host = b"example.com";
        let mut buf = vec![0x00, 0x00, 0x00, 0x03, host.len() as u8];
        buf.extend_from_slice(host);
        buf.extend_from_slice(&53u16.to_be_bytes());
        buf.extend_from_slice(b"q");
        let (target, data) = parse_udp_datagram(&buf).expect("parse");
        assert_eq!(target, Target::Domain("example.com".to_owned(), 53));
        assert_eq!(data, b"q");
    }

    #[test]
    fn udp_datagram_rejects_fragmentation() {
        let buf = [0x00, 0x00, 0x01, 0x01, 1, 2, 3, 4, 0x00, 0x35];
        assert_eq!(parse_udp_datagram(&buf), Err(Socks5Error::Fragmented));
    }

    #[test]
    fn udp_datagram_rejects_truncated() {
        assert_eq!(
            parse_udp_datagram(&[0x00, 0x00]),
            Err(Socks5Error::Truncated)
        );
    }

    #[test]
    fn udp_datagram_encode_is_byte_exact_and_roundtrips() {
        let src: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let dgram = encode_udp_datagram(src, b"reply");
        assert_eq!(
            dgram,
            vec![
                0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35, b'r', b'e', b'p', b'l', b'y'
            ]
        );
        let (target, data) = parse_udp_datagram(&dgram).expect("parse");
        assert_eq!(target, Target::Ip(src));
        assert_eq!(data, b"reply");
    }

    #[test]
    fn reply_roundtrips_atyp_and_port() {
        let r = build_reply(Reply::Succeeded, "0.0.0.0:0".parse().unwrap());
        assert_eq!(r[0], VERSION);
        assert_eq!(r[1], 0x00);
        assert_eq!(r[3], 0x01);
        assert_eq!(&r[r.len() - 2..], &[0x00, 0x00]);
    }
}
