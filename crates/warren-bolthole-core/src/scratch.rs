//! The decapsulation and encapsulation buffer.
//!
//! boringtun copies a data packet's whole ciphertext into the destination
//! buffer, and panics when that buffer is too small, before it has
//! authenticated anything (`noise/session.rs:236-245`). A datagram carrying a
//! live session index is enough to reach that copy, so the size of this buffer
//! is what stands between an unauthenticated stranger and a dead process.
//! Making it the only shape a buffer can have is what keeps that decision out
//! of every call site.

/// Length of every scratch buffer: the largest datagram a UDP socket can
/// deliver, plus the data-packet overhead an encapsulation adds on top of a
/// full-size inner packet.
pub const SCRATCH_LEN: usize = 65_535 + 32;

/// A buffer boringtun can never overrun.
///
/// One per reader task and one per pump, reused for every datagram; it is far
/// too large to allocate per packet.
pub struct ScratchBuf {
    // Kept as a slice rather than an array so the only way to obtain one is
    // `new`, which is the invariant: no call site chooses a size.
    buf: Box<[u8]>,
}

impl ScratchBuf {
    /// Allocates a buffer of [`SCRATCH_LEN`] bytes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: vec![0u8; SCRATCH_LEN].into_boxed_slice(),
        }
    }
}

impl AsMut<[u8]> for ScratchBuf {
    /// The whole buffer, which is what boringtun must be handed.
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl Default for ScratchBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ScratchBuf {
    // Never renders the bytes: between two datagrams they are the last
    // decrypted packet of some peer.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScratchBuf")
            .field("len", &self.buf.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::noise::{Tunn, TunnResult};
    use boringtun::x25519;
    use rand::rngs::OsRng;

    fn keypair() -> (x25519::StaticSecret, x25519::PublicKey) {
        let secret = x25519::StaticSecret::random_from_rng(OsRng);
        let public = x25519::PublicKey::from(&secret);
        (secret, public)
    }

    #[test]
    fn holds_the_largest_datagram_a_socket_can_deliver_plus_the_data_overhead() {
        let mut scratch = ScratchBuf::new();
        assert_eq!(scratch.as_mut().len(), 65_535 + 32);
    }

    #[test]
    fn survives_an_unauthenticated_oversize_data_datagram_naming_a_live_session() {
        let (gw_secret, gw_public) = keypair();
        let (peer_secret, peer_public) = keypair();
        let mut gateway = Tunn::new(gw_secret, peer_public, None, None, 7, None);
        let mut peer = Tunn::new(peer_secret, gw_public, None, None, 3, None);

        let mut buf = vec![0u8; 2048];
        let init = match peer.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(b) => b.to_vec(),
            other => panic!("expected an initiation, got {other:?}"),
        };
        let mut buf = vec![0u8; 2048];
        let response = match gateway.decapsulate(None, &init, &mut buf) {
            TunnResult::WriteToNetwork(b) => b.to_vec(),
            other => panic!("expected a response, got {other:?}"),
        };
        let mut buf = vec![0u8; 2048];
        let keepalive = match peer.decapsulate(None, &response, &mut buf) {
            TunnResult::WriteToNetwork(b) => b.to_vec(),
            other => panic!("expected a keepalive, got {other:?}"),
        };
        let session_index = u32::from_le_bytes(keepalive[4..8].try_into().unwrap());

        // A datagram nobody authenticated: only its header names the live
        // session, and boringtun copies the whole ciphertext into the
        // destination before it ever checks the tag.
        for len in [8 * 1024_usize, 65_000] {
            let mut forged = vec![0u8; len];
            forged[0] = 4;
            forged[4..8].copy_from_slice(&session_index.to_le_bytes());
            forged[8..16].copy_from_slice(&1000u64.to_le_bytes());
            let mut scratch = ScratchBuf::new();
            match gateway.decapsulate(None, &forged, scratch.as_mut()) {
                TunnResult::Err(_) => {}
                other => panic!("an unauthenticated datagram was accepted: {other:?}"),
            }
        }
    }
}
