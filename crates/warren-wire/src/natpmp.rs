//! NAT-PMP wire codec (RFC 6886 plus the Warren rate-limit and credential
//! trailers), sourced from the engine's `warrenguard-natpmp-protocol` so a
//! single codec is shared with warren-core. Re-exported to keep the
//! `warren_wire::natpmp::` paths stable; byte-compatibility is pinned by the
//! shared golden vectors and the engine crate's own tests.

pub use warrenguard_natpmp_protocol::{
    MAX_CREDENTIAL_LEN, MapProto, NATPMP_VERSION, ParseError, RESPONSE_BIT, RateLimitInfo, Request,
    Response, ResultCode, TrailerError, append_credential_trailer, credential_trailer,
    parse_response, serialize_request,
};
