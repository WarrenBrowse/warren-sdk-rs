//! Pure Warren wire codecs (Phase P2, not yet implemented).
//!
//! Planned surface, ported wire-compatibly from warren-core:
//! - `Setup` / `SetupAck` handshake frames (postcard, `PROTOCOL_VERSION = 4`,
//!   16-byte `device_id`, feature bitmask MULTIPATH/PORT_FORWARD/IPV6/PAD_TO_MTU).
//! - NAT-PMP request/response (RFC 6886 plus the Warren rate-limit trailer).
//! - The multihop HPKE frame (X25519 + HKDF-SHA256 + ChaCha20Poly1305, frame v1).
//!
//! Every codec will be pinned by golden vectors under `vectors/` extracted from
//! warren-core so all sibling-language SDKs stay byte-compatible.

#[cfg(test)]
mod roadmap {
    #[test]
    #[ignore = "P2: implement Setup/SetupAck + NAT-PMP + multihop codecs with golden vectors"]
    fn placeholder() {}
}
