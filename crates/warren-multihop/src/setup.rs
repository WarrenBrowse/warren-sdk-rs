//! High-level multihop setup exchange (client side).
//!
//! Wraps the raw [`ClientSession`] seal/open and the
//! [`WarrenControlMessage`](warren_wire::WarrenControlMessage) codec into the
//! single round-trip a client performs before any traffic flows:
//!
//! 1. The client seals a `IpRequest` (asserting its account pubkey + a proof of
//!    possession over this session's `encapsulated_key`) into the first frame
//!    and sends it on a reliable bidi QUIC stream.
//! 2. The exit replies with a sealed `IpAssign` (or `Rejected`/`IpExhausted`).
//!
//! The transport owns the seq/epoch counters (the setup frame is the first
//! forward frame, `epoch = 0`, `seq = 0`; the first data datagram is `seq = 1`),
//! so they are passed in rather than tracked here. This keeps the crypto layer
//! free of transport state, matching warren-core's split.

use ed25519_dalek::SigningKey;
use warren_wire::multihop::{EXIT_ID_LEN, WarrenMultihopFrame};
use warren_wire::{ControlError, WarrenControlMessage, encode_control, try_decode_control};

use crate::pop::sign_pop;
use crate::{ClientSession, SessionError};

/// The exit's authoritative tunnel-IP allocation, decoded from a sealed
/// `IpAssign` reply. `ipv6` is `Some` iff the exit actually granted dual-stack
/// v6 (the capability echo): a client that asked for v6 but got `None` knows the
/// exit could not serve it and surfaces that instead of going v4-only silently.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IpAssignment {
    /// Allocated host IPv4 address.
    pub ipv4: [u8; 4],
    /// IPv4 subnet prefix length (e.g. 24 for a `/24`).
    pub prefix_len: u8,
    /// IPv4 subnet gateway (also the exit-side TUN address).
    pub gateway_ipv4: [u8; 4],
    /// Allocated host IPv6, or `None` when the exit did not grant v6.
    pub ipv6: Option<[u8; 16]>,
    /// IPv6 subnet prefix length. Meaningless when `ipv6` is `None`.
    pub prefix_len_v6: u8,
    /// IPv6 subnet gateway, or `None` when no v6.
    pub gateway_ipv6: Option<[u8; 16]>,
}

/// Failure of the multihop setup exchange.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SetupError {
    /// HPKE seal/open or exit-id/version mismatch on the frame.
    #[error("multihop session error")]
    Session(#[source] SessionError),
    /// Control-message codec error on the request or reply plaintext.
    #[error("multihop control codec error")]
    Control(#[source] ControlError),
    /// The exit refused the setup by policy (pubkey not allowlisted, or the
    /// proof of possession was missing or invalid). The cause is deliberately
    /// opaque on the wire (anti subscription-status oracle).
    #[error("multihop setup rejected by exit policy")]
    Rejected,
    /// The exit's address pool is exhausted.
    #[error("multihop exit ip pool exhausted")]
    IpExhausted,
    /// The reply was not a control message, or was a control message the client
    /// never expects to receive (e.g. an `IpRequest`).
    #[error("unexpected multihop setup reply")]
    UnexpectedReply,
}

impl From<SessionError> for SetupError {
    fn from(e: SessionError) -> Self {
        SetupError::Session(e)
    }
}

impl From<ControlError> for SetupError {
    fn from(e: ControlError) -> Self {
        SetupError::Control(e)
    }
}

impl ClientSession {
    /// Build the `IpRequest` control message for this session.
    ///
    /// When `signing_key` is `Some`, the request asserts its account pubkey and
    /// carries an Ed25519 proof of possession over this session's
    /// `encapsulated_key` (domain-separated and exit-bound), which a strict
    /// exit requires before granting egress. `None` is for permissive/bench
    /// exits only and is rejected by a production exit.
    #[must_use]
    pub fn build_ip_request(
        &self,
        signing_key: Option<&SigningKey>,
        prefer_ipv4: Option<[u8; 4]>,
        wants_ipv6: bool,
    ) -> WarrenControlMessage {
        let exit_id: [u8; EXIT_ID_LEN] = self.exit_id_bytes();
        let encapsulated_key = self.encapsulated_key();
        let (client_pubkey, pop_sig) = match signing_key {
            Some(key) => (
                Some(key.verifying_key().to_bytes()),
                Some(sign_pop(key, &exit_id, &encapsulated_key)),
            ),
            None => (None, None),
        };
        WarrenControlMessage::IpRequest {
            prefer_ipv4,
            client_pubkey,
            wants_ipv6,
            pop_sig,
        }
    }

    /// Seal the setup `IpRequest` into the first forward frame.
    ///
    /// The setup frame is the first forward frame of the session, so the
    /// transport calls this with `epoch = 0`, `seq = 0` and resumes the data
    /// path at `seq = 1`.
    ///
    /// # Errors
    ///
    /// [`SetupError::Control`] if the control message fails to encode,
    /// [`SetupError::Session`] if the HPKE seal fails.
    pub fn seal_setup_request(
        &self,
        signing_key: Option<&SigningKey>,
        prefer_ipv4: Option<[u8; 4]>,
        wants_ipv6: bool,
        epoch: u32,
        seq: u64,
    ) -> Result<WarrenMultihopFrame, SetupError> {
        let msg = self.build_ip_request(signing_key, prefer_ipv4, wants_ipv6);
        let plaintext = encode_control(&msg)?;
        Ok(self.seal(&plaintext, epoch, seq)?)
    }

    /// Open the exit's sealed setup reply and interpret it.
    ///
    /// # Errors
    ///
    /// [`SetupError::Session`] on an HPKE-open / exit-id / version failure,
    /// [`SetupError::Control`] on a malformed control plaintext,
    /// [`SetupError::Rejected`] / [`SetupError::IpExhausted`] on a policy reply,
    /// [`SetupError::UnexpectedReply`] for any other control variant or a
    /// non-control plaintext.
    pub fn open_setup_reply(
        &self,
        frame: &WarrenMultihopFrame,
    ) -> Result<IpAssignment, SetupError> {
        let plaintext = self.open_response(frame)?;
        match try_decode_control(&plaintext)? {
            Some(WarrenControlMessage::IpAssign {
                ipv4,
                prefix_len,
                gateway_ipv4,
                ipv6,
                prefix_len_v6,
                gateway_ipv6,
            }) => Ok(IpAssignment {
                ipv4,
                prefix_len,
                gateway_ipv4,
                ipv6,
                prefix_len_v6,
                gateway_ipv6,
            }),
            Some(WarrenControlMessage::Rejected) => Err(SetupError::Rejected),
            Some(WarrenControlMessage::IpExhausted) => Err(SetupError::IpExhausted),
            // An IpRequest (client->exit), a non-control plaintext, or any
            // future client->exit-only variant on the reply path is a protocol
            // violation by the peer.
            Some(WarrenControlMessage::IpRequest { .. }) | Some(_) | None => {
                Err(SetupError::UnexpectedReply)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WARREN_HPKE_INFO_V1;
    use crate::pop::verify_pop;
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
    use hpke::kdf::HkdfSha256;
    use hpke::kem::X25519HkdfSha256;
    use hpke::{Deserializable, Kem as KemTrait, OpModeR, Serializable, setup_receiver};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    type Aead = HpkeChaCha20Poly1305;
    type Kdf = HkdfSha256;
    type Kem = X25519HkdfSha256;

    const WARREN_HPKE_AAD_V1: &[u8] = b"warren/multihop/v1/aad";

    /// Minimal exit-side mirror: opens the client's forward frame, verifies the
    /// PoP, decodes the IpRequest, and seals a chosen control reply in the
    /// reverse direction. Proves the SDK setup helpers interoperate with the
    /// warren-core scheme byte-for-byte.
    struct FakeExit {
        recipient_priv: <Kem as KemTrait>::PrivateKey,
        exit_id: [u8; EXIT_ID_LEN],
    }

    impl FakeExit {
        fn aad(&self, epoch: u32, seq: u64) -> Vec<u8> {
            let mut a = Vec::new();
            a.extend_from_slice(WARREN_HPKE_AAD_V1);
            a.extend_from_slice(&self.exit_id);
            a.extend_from_slice(&epoch.to_be_bytes());
            a.extend_from_slice(&seq.to_be_bytes());
            a
        }

        fn export_info(epoch: u32, seq: u64, reverse: bool) -> Vec<u8> {
            let mut i = Vec::new();
            i.extend_from_slice(WARREN_HPKE_AAD_V1);
            i.extend_from_slice(&epoch.to_be_bytes());
            i.extend_from_slice(&seq.to_be_bytes());
            if reverse {
                i.push(0x02);
            }
            i
        }

        fn ctx(&self, frame: &WarrenMultihopFrame) -> hpke::aead::AeadCtxR<Aead, Kdf, Kem> {
            let encapped =
                <Kem as KemTrait>::EncappedKey::from_bytes(&frame.encapsulated_key).unwrap();
            setup_receiver::<Aead, Kdf, Kem>(
                &OpModeR::Base,
                &self.recipient_priv,
                &encapped,
                WARREN_HPKE_INFO_V1,
            )
            .unwrap()
        }

        /// Open the client's forward setup frame, returning its inner control
        /// plaintext.
        fn open_request(&self, frame: &WarrenMultihopFrame) -> Vec<u8> {
            let ctx = self.ctx(frame);
            let mut key = [0u8; 32];
            ctx.export(&Self::export_info(frame.epoch, frame.seq, false), &mut key)
                .unwrap();
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let mut buf = frame.ciphertext.clone();
            cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&[0u8; 12]),
                    &self.aad(frame.epoch, frame.seq),
                    &mut buf,
                    chacha20poly1305::Tag::from_slice(&frame.aead_tag),
                )
                .unwrap();
            buf
        }

        /// Seal a control reply for the client in the reverse direction, reusing
        /// the client's frame to recover the HPKE context (same encapsulated
        /// key), as a real exit does.
        fn seal_reply(
            &self,
            request_frame: &WarrenMultihopFrame,
            reply: &WarrenControlMessage,
            epoch: u32,
            seq: u64,
        ) -> WarrenMultihopFrame {
            let ctx = self.ctx(request_frame);
            let mut key = [0u8; 32];
            ctx.export(&Self::export_info(epoch, seq, true), &mut key)
                .unwrap();
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let mut buf = encode_control(reply).unwrap();
            let tag = cipher
                .encrypt_in_place_detached(
                    Nonce::from_slice(&[0u8; 12]),
                    &self.aad(epoch, seq),
                    &mut buf,
                )
                .unwrap();
            let mut aead_tag = [0u8; 16];
            aead_tag.copy_from_slice(tag.as_slice());
            WarrenMultihopFrame {
                version: warren_wire::WARREN_HPKE_VERSION_V1,
                exit_id: self.exit_id,
                epoch,
                seq,
                encapsulated_key: request_frame.encapsulated_key,
                aead_tag,
                ciphertext: buf,
            }
        }
    }

    fn setup() -> (ClientSession, FakeExit, ChaCha20Rng, SigningKey) {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let (recipient_priv, recipient_pub) = Kem::gen_keypair(&mut rng);
        let pub_bytes: [u8; 32] = recipient_pub.to_bytes().into();
        let exit_id = [0x3c; EXIT_ID_LEN];
        let session = ClientSession::new(&pub_bytes, exit_id, &mut rng).unwrap();
        let account = SigningKey::from_bytes(&[0x42; 32]);
        (
            session,
            FakeExit {
                recipient_priv,
                exit_id,
            },
            rng,
            account,
        )
    }

    #[test]
    fn setup_request_carries_a_valid_pop_and_round_trips_to_ip_assign() {
        let (session, exit, _rng, account) = setup();

        let request = session
            .seal_setup_request(Some(&account), None, true, 0, 0)
            .expect("seal setup request");
        assert_eq!(request.seq, 0, "setup frame is the first forward frame");
        assert_eq!(request.epoch, 0);

        // Exit side: open the request, decode it, verify the PoP exactly as a
        // strict exit would before consulting the allowlist.
        let plaintext = exit.open_request(&request);
        let decoded = try_decode_control(&plaintext).unwrap().unwrap();
        let WarrenControlMessage::IpRequest {
            client_pubkey,
            pop_sig,
            wants_ipv6,
            prefer_ipv4,
        } = decoded
        else {
            panic!("expected an IpRequest");
        };
        assert!(wants_ipv6);
        assert_eq!(prefer_ipv4, None);
        let pubkey = client_pubkey.expect("pubkey asserted");
        assert_eq!(pubkey, account.verifying_key().to_bytes());
        assert!(
            verify_pop(
                &pubkey,
                &exit.exit_id,
                &session.encapsulated_key(),
                &pop_sig.expect("pop present"),
            ),
            "the proof of possession must verify against the asserted pubkey"
        );

        // Exit grants a dual-stack assignment; the client decodes it.
        let assign = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 9],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: Some([
                0xfd, 0xcc, 0, 0x0f, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09,
            ]),
            prefix_len_v6: 64,
            gateway_ipv6: Some([
                0xfd, 0xcc, 0, 0x0f, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ]),
        };
        let reply = exit.seal_reply(&request, &assign, 0, 0);
        let got = session.open_setup_reply(&reply).expect("open reply");
        assert_eq!(got.ipv4, [10, 66, 0, 9]);
        assert_eq!(got.prefix_len, 24);
        assert_eq!(got.gateway_ipv4, [10, 66, 0, 1]);
        assert_eq!(got.ipv6.unwrap()[15], 0x09);
        assert_eq!(got.prefix_len_v6, 64);
    }

    #[test]
    fn permissive_request_without_identity_omits_pubkey_and_pop() {
        let (session, exit, _rng, _account) = setup();
        let request = session
            .seal_setup_request(None, Some([10, 66, 0, 5]), false, 0, 0)
            .unwrap();
        let plaintext = exit.open_request(&request);
        let WarrenControlMessage::IpRequest {
            client_pubkey,
            pop_sig,
            prefer_ipv4,
            wants_ipv6,
        } = try_decode_control(&plaintext).unwrap().unwrap()
        else {
            panic!("expected an IpRequest");
        };
        assert_eq!(client_pubkey, None);
        assert_eq!(pop_sig, None);
        assert_eq!(prefer_ipv4, Some([10, 66, 0, 5]));
        assert!(!wants_ipv6);
    }

    #[test]
    fn rejected_reply_maps_to_rejected_error() {
        let (session, exit, _rng, account) = setup();
        let request = session
            .seal_setup_request(Some(&account), None, false, 0, 0)
            .unwrap();
        let reply = exit.seal_reply(&request, &WarrenControlMessage::Rejected, 0, 0);
        assert!(matches!(
            session.open_setup_reply(&reply),
            Err(SetupError::Rejected)
        ));
    }

    #[test]
    fn ip_exhausted_reply_maps_to_ip_exhausted_error() {
        let (session, exit, _rng, account) = setup();
        let request = session
            .seal_setup_request(Some(&account), None, false, 0, 0)
            .unwrap();
        let reply = exit.seal_reply(&request, &WarrenControlMessage::IpExhausted, 0, 0);
        assert!(matches!(
            session.open_setup_reply(&reply),
            Err(SetupError::IpExhausted)
        ));
    }

    #[test]
    fn an_ip_request_on_the_reply_path_is_unexpected() {
        let (session, exit, _rng, account) = setup();
        let request = session
            .seal_setup_request(Some(&account), None, false, 0, 0)
            .unwrap();
        // The exit must never send an IpRequest back; the client rejects it.
        let bogus = WarrenControlMessage::IpRequest {
            prefer_ipv4: None,
            client_pubkey: None,
            wants_ipv6: false,
            pop_sig: None,
        };
        let reply = exit.seal_reply(&request, &bogus, 0, 0);
        assert!(matches!(
            session.open_setup_reply(&reply),
            Err(SetupError::UnexpectedReply)
        ));
    }
}
