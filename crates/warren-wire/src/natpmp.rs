//! NAT-PMP wire format (RFC 6886) plus the Warren rate-limit trailer.
//!
//! Pure parse/serialize, no I/O. Byte-compatible with warren-core. Requests are
//! big-endian: version (1B) + opcode (1B) + payload. Map responses may carry a
//! 4-byte Warren trailer after the 16-byte RFC body.

use std::net::Ipv4Addr;

/// NAT-PMP protocol version (must be `0`).
pub const NATPMP_VERSION: u8 = 0;

/// Response indicator bit on the opcode.
pub const RESPONSE_BIT: u8 = 0x80;

/// Mapping transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapProto {
    /// UDP (opcode 1).
    Udp,
    /// TCP (opcode 2).
    Tcp,
}

/// RFC 6886 result codes plus two Warren extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResultCode {
    /// Operation succeeded.
    Success,
    /// Unsupported version.
    UnsupportedVersion,
    /// Refused by the server.
    NotAuthorized,
    /// Network failure.
    NetworkFailure,
    /// No free port or quota exceeded.
    OutOfResources,
    /// Unknown opcode.
    UnsupportedOpcode,
    /// Warren extension: requested specific external port unavailable.
    SuggestedPortUnavailable,
    /// Warren extension: per-source allocation rate limit exceeded.
    RateLimited,
}

impl ResultCode {
    fn from_raw(raw: u16) -> Self {
        match raw {
            0 => ResultCode::Success,
            1 => ResultCode::UnsupportedVersion,
            2 => ResultCode::NotAuthorized,
            3 => ResultCode::NetworkFailure,
            4 => ResultCode::OutOfResources,
            5 => ResultCode::UnsupportedOpcode,
            6 => ResultCode::SuggestedPortUnavailable,
            7 => ResultCode::RateLimited,
            // Any unknown future code maps to NetworkFailure.
            _ => ResultCode::NetworkFailure,
        }
    }
}

/// Optional Warren trailer on a Map response: per-source rate-limit budget.
///
/// Wire layout (4 bytes after the 16-byte RFC body):
/// `attempts_remaining (1B) | reserved (1B) | window_reset_secs (2B BE)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitInfo {
    /// Allocation slots still available to this source after this request.
    pub attempts_remaining: u8,
    /// Seconds until the budget grows by one (retry-after on a rejection).
    pub window_reset_secs: u16,
}

/// A NAT-PMP request (client to gateway).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Get the gateway's public address.
    ExternalAddress,
    /// Create, refresh, or (with `lifetime_secs == 0`) delete a mapping.
    Map {
        /// TCP or UDP.
        proto: MapProto,
        /// Internal client port (tunnel side).
        internal_port: u16,
        /// Suggested external port (`0` = server picks).
        suggested_external_port: u16,
        /// Requested lifetime in seconds (`0` = delete).
        lifetime_secs: u32,
    },
}

/// A NAT-PMP response (gateway to client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    /// Response to [`Request::ExternalAddress`].
    ExternalAddress {
        /// Result code.
        result_code: ResultCode,
        /// Seconds since the daemon epoch.
        epoch_secs: u32,
        /// Public IPv4 of the gateway (`0.0.0.0` on error).
        external_ip: Ipv4Addr,
    },
    /// Response to a [`Request::Map`].
    Map {
        /// TCP or UDP.
        proto: MapProto,
        /// Result code.
        result_code: ResultCode,
        /// Seconds since the daemon epoch.
        epoch_secs: u32,
        /// Internal port (echoed).
        internal_port: u16,
        /// Allocated external port.
        external_port: u16,
        /// Granted lifetime.
        lifetime_secs: u32,
        /// Optional Warren rate-limit trailer.
        rate_limit: Option<RateLimitInfo>,
    },
}

/// Wire parsing errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Frame shorter than the opcode requires.
    #[error("frame too short: got {got}, need at least {need}")]
    TooShort {
        /// Received size.
        got: usize,
        /// Minimum required size.
        need: usize,
    },
    /// Header version is not [`NATPMP_VERSION`].
    #[error("unsupported NAT-PMP version: {0}")]
    UnsupportedVersion(u8),
    /// Unknown opcode.
    #[error("unsupported opcode: {0}")]
    UnsupportedOpcode(u8),
}

/// Serializes a client request to the RFC 6886 wire format.
#[must_use]
pub fn serialize_request(req: &Request) -> Vec<u8> {
    match *req {
        Request::ExternalAddress => vec![NATPMP_VERSION, 0],
        Request::Map {
            proto,
            internal_port,
            suggested_external_port,
            lifetime_secs,
        } => {
            let opcode = match proto {
                MapProto::Udp => 1,
                MapProto::Tcp => 2,
            };
            let mut buf = Vec::with_capacity(12);
            buf.push(NATPMP_VERSION);
            buf.push(opcode);
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&internal_port.to_be_bytes());
            buf.extend_from_slice(&suggested_external_port.to_be_bytes());
            buf.extend_from_slice(&lifetime_secs.to_be_bytes());
            buf
        }
    }
}

/// Parses a gateway response frame.
///
/// # Errors
///
/// [`ParseError`] on a short frame, wrong version, missing response bit, or
/// unknown opcode.
pub fn parse_response(buf: &[u8]) -> Result<Response, ParseError> {
    if buf.len() < 8 {
        return Err(ParseError::TooShort {
            got: buf.len(),
            need: 8,
        });
    }
    if buf[0] != NATPMP_VERSION {
        return Err(ParseError::UnsupportedVersion(buf[0]));
    }
    let opcode_raw = buf[1];
    if opcode_raw & RESPONSE_BIT == 0 {
        return Err(ParseError::UnsupportedOpcode(opcode_raw));
    }
    let opcode = opcode_raw & !RESPONSE_BIT;
    let result_code = ResultCode::from_raw(u16::from_be_bytes([buf[2], buf[3]]));
    let epoch_secs = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

    match opcode {
        0 => {
            if buf.len() < 12 {
                return Err(ParseError::TooShort {
                    got: buf.len(),
                    need: 12,
                });
            }
            Ok(Response::ExternalAddress {
                result_code,
                epoch_secs,
                external_ip: Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]),
            })
        }
        1 | 2 => {
            if buf.len() < 16 {
                return Err(ParseError::TooShort {
                    got: buf.len(),
                    need: 16,
                });
            }
            let proto = if opcode == 1 {
                MapProto::Udp
            } else {
                MapProto::Tcp
            };
            let rate_limit = if buf.len() >= 20 {
                Some(RateLimitInfo {
                    attempts_remaining: buf[16],
                    window_reset_secs: u16::from_be_bytes([buf[18], buf[19]]),
                })
            } else {
                None
            };
            Ok(Response::Map {
                proto,
                result_code,
                epoch_secs,
                internal_port: u16::from_be_bytes([buf[8], buf[9]]),
                external_port: u16::from_be_bytes([buf[10], buf[11]]),
                lifetime_secs: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
                rate_limit,
            })
        }
        other => Err(ParseError::UnsupportedOpcode(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_address_request_is_two_bytes() {
        assert_eq!(
            serialize_request(&Request::ExternalAddress),
            vec![0x00, 0x00]
        );
    }

    #[test]
    fn map_request_wire_layout() {
        let req = Request::Map {
            proto: MapProto::Tcp,
            internal_port: 0x1234,
            suggested_external_port: 0xabcd,
            lifetime_secs: 7200,
        };
        // version 0, opcode 2 (TCP), reserved 0 0, internal 0x1234, suggested
        // 0xabcd, lifetime 7200 = 0x00001c20.
        assert_eq!(
            serialize_request(&req),
            vec![
                0x00, 0x02, 0x00, 0x00, 0x12, 0x34, 0xab, 0xcd, 0x00, 0x00, 0x1c, 0x20
            ]
        );
    }

    #[test]
    fn parse_map_response_with_trailer() {
        // version 0, opcode 1|0x80, result 0, epoch 1, internal 0x1234,
        // external 0xabcd, lifetime 7200, trailer: attempts 3, reserved 0,
        // window 0x0005.
        let buf = [
            0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0xab, 0xcd, 0x00, 0x00,
            0x1c, 0x20, 0x03, 0x00, 0x00, 0x05,
        ];
        let resp = parse_response(&buf).expect("parse");
        match resp {
            Response::Map {
                proto,
                result_code,
                external_port,
                rate_limit,
                ..
            } => {
                assert_eq!(proto, MapProto::Udp);
                assert_eq!(result_code, ResultCode::Success);
                assert_eq!(external_port, 0xabcd);
                assert_eq!(
                    rate_limit,
                    Some(RateLimitInfo {
                        attempts_remaining: 3,
                        window_reset_secs: 5
                    })
                );
            }
            other => panic!("expected Map, got {other:?}"),
        }
    }

    #[test]
    fn parse_map_response_without_trailer_is_none() {
        let buf = [
            0x00, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0xab, 0xcd, 0x00, 0x00,
            0x1c, 0x20,
        ];
        match parse_response(&buf).expect("parse") {
            Response::Map {
                proto, rate_limit, ..
            } => {
                assert_eq!(proto, MapProto::Tcp);
                assert_eq!(rate_limit, None);
            }
            other => panic!("expected Map, got {other:?}"),
        }
    }

    #[test]
    fn parse_external_address_response() {
        // version 0, opcode 0|0x80, result 0, epoch 1, external ip 203.0.113.9.
        let buf = [
            0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 203, 0, 113, 9,
        ];
        match parse_response(&buf).expect("parse") {
            Response::ExternalAddress {
                result_code,
                external_ip,
                ..
            } => {
                assert_eq!(result_code, ResultCode::Success);
                assert_eq!(external_ip, Ipv4Addr::new(203, 0, 113, 9));
            }
            other => panic!("expected ExternalAddress, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_missing_response_bit() {
        let buf = [0x00, 0x01, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            parse_response(&buf).unwrap_err(),
            ParseError::UnsupportedOpcode(0x01)
        ));
    }

    #[test]
    fn parse_rejects_short_frame() {
        assert!(matches!(
            parse_response(&[0x00, 0x81]).unwrap_err(),
            ParseError::TooShort { got: 2, need: 8 }
        ));
    }

    #[test]
    fn parse_rejects_unsupported_version() {
        // Long enough to pass the length guard, but a non-zero version byte: the
        // frame is from an incompatible NAT-PMP dialect and must be rejected.
        let buf = [0x09, 0x81, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            parse_response(&buf).unwrap_err(),
            ParseError::UnsupportedVersion(0x09)
        ));
    }

    #[test]
    fn rate_limited_result_code_maps() {
        let buf = [
            0x00, 0x81, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        match parse_response(&buf).expect("parse") {
            Response::Map { result_code, .. } => {
                assert_eq!(result_code, ResultCode::RateLimited);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn trailer_reserved_byte_is_ignored_on_decode() {
        // The reserved byte (index 17) is forward-compatibility space: a future
        // non-zero value must be ignored, not change the parsed budget.
        let buf = [
            0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0xab, 0xcd, 0x00, 0x00,
            0x1c, 0x20, 0x03, 0xff, 0x00, 0x05,
        ];
        match parse_response(&buf).expect("parse") {
            Response::Map { rate_limit, .. } => assert_eq!(
                rate_limit,
                Some(RateLimitInfo {
                    attempts_remaining: 3,
                    window_reset_secs: 5
                })
            ),
            _ => unreachable!(),
        }
    }

    #[test]
    fn unknown_result_code_maps_to_network_failure() {
        // Pin the deliberately lossy mapping: an unknown/future result code is
        // coerced to NetworkFailure (matches warren-core); changing this is a
        // behavior change a test must catch.
        assert_eq!(ResultCode::from_raw(0), ResultCode::Success);
        assert_eq!(ResultCode::from_raw(99), ResultCode::NetworkFailure);
        assert_eq!(ResultCode::from_raw(u16::MAX), ResultCode::NetworkFailure);
    }
}
