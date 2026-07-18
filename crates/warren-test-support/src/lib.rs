//! Test-only helpers shared across the Warren SDK workspace.
//!
//! This crate is `publish = false` and is only ever a dev-dependency. It exists
//! so the in-process fake exit lives in one place instead of being copy-pasted
//! into every crate's integration tests.

use std::collections::VecDeque;
use std::net::SocketAddr;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use ed25519_dalek::SigningKey;
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, Serializable, setup_receiver};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::sync::mpsc;
use warren_transport::{default_crypto_provider, make_server_config};
use warren_wire::multihop::{EXIT_ID_LEN, WarrenMultihopFrame};
use warren_wire::{
    WARREN_HPKE_AAD_V1, WARREN_HPKE_VERSION_V1, WarrenControlMessage, encode_control,
    try_decode_control,
};
// The fake exit accepts the same single-home ALPN the real client offers.
use warrenguard_config::ALPN_H3;

/// TCP port the netstack exit echoes on.
pub const NETSTACK_EXIT_PORT: u16 = 9;
/// The exit-side gateway/listen address of the netstack exit.
pub const NETSTACK_EXIT_IP: [u8; 4] = [10, 66, 0, 1];

/// A channel-backed smoltcp device for the exit-side stack.
struct ExitDevice {
    rx: VecDeque<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
}
struct Rx(Vec<u8>);
struct Tx(mpsc::UnboundedSender<Vec<u8>>);
impl smoltcp::phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl smoltcp::phy::TxToken for Tx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.0.send(buf);
        r
    }
}
impl Device for ExitDevice {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx;
    fn receive(&mut self, _t: SmolInstant) -> Option<(Rx, Tx)> {
        let f = self.rx.pop_front()?;
        Some((Rx(f), Tx(self.tx.clone())))
    }
    fn transmit(&mut self, _t: SmolInstant) -> Option<Tx> {
        Some(Tx(self.tx.clone()))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1280;
        caps.checksum.ipv4 = Checksum::Both;
        caps.checksum.tcp = Checksum::Both;
        caps
    }
}

// ---- Fake multihop exit ----

const WARREN_HPKE_INFO_V1: &[u8] = b"warren/multihop/v1/hpke-info";

type ExitAead = HpkeChaCha20Poly1305;
type ExitKdf = HkdfSha256;
type ExitKem = X25519HkdfSha256;

/// The keys a [`spawn_fake_multihop_exit`] publishes, as a client would read
/// them from a verified multihop directory.
pub struct MultihopExitKeys {
    /// Ed25519 TLS / raw-public-key identity (pinned by the client).
    pub ed25519_pubkey: [u8; 32],
    /// X25519 HPKE recipient key the client seals setup + data frames to.
    pub x25519_pubkey: [u8; 32],
    /// 16-byte cleartext routing tag.
    pub exit_id: [u8; EXIT_ID_LEN],
}

fn exit_aad(exit_id: &[u8; EXIT_ID_LEN], epoch: u32, seq: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(WARREN_HPKE_AAD_V1.len() + EXIT_ID_LEN + 4 + 8);
    a.extend_from_slice(WARREN_HPKE_AAD_V1);
    a.extend_from_slice(exit_id);
    a.extend_from_slice(&epoch.to_be_bytes());
    a.extend_from_slice(&seq.to_be_bytes());
    a
}

fn exit_export_info(epoch: u32, seq: u64, reverse: bool) -> Vec<u8> {
    let mut i = Vec::with_capacity(WARREN_HPKE_AAD_V1.len() + 4 + 8 + 1);
    i.extend_from_slice(WARREN_HPKE_AAD_V1);
    i.extend_from_slice(&epoch.to_be_bytes());
    i.extend_from_slice(&seq.to_be_bytes());
    if reverse {
        i.push(0x02);
    }
    i
}

/// Open one client->exit frame with the established HPKE receiver context.
fn exit_open(
    ctx: &hpke::aead::AeadCtxR<ExitAead, ExitKdf, ExitKem>,
    exit_id: &[u8; EXIT_ID_LEN],
    frame: &WarrenMultihopFrame,
) -> Option<Vec<u8>> {
    let mut key = [0u8; 32];
    ctx.export(&exit_export_info(frame.epoch, frame.seq, false), &mut key)
        .ok()?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut buf = frame.ciphertext.clone();
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&[0u8; 12]),
            &exit_aad(exit_id, frame.epoch, frame.seq),
            &mut buf,
            Tag::from_slice(&frame.aead_tag),
        )
        .ok()?;
    Some(buf)
}

/// Seal one exit->client reply with the reverse-direction key.
fn exit_seal(
    ctx: &hpke::aead::AeadCtxR<ExitAead, ExitKdf, ExitKem>,
    exit_id: &[u8; EXIT_ID_LEN],
    encapsulated_key: [u8; 32],
    plaintext: &[u8],
    epoch: u32,
    seq: u64,
) -> WarrenMultihopFrame {
    let mut key = [0u8; 32];
    ctx.export(&exit_export_info(epoch, seq, true), &mut key)
        .expect("export reverse key");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&[0u8; 12]),
            &exit_aad(exit_id, epoch, seq),
            &mut buf,
        )
        .expect("seal reverse");
    let mut aead_tag = [0u8; 16];
    aead_tag.copy_from_slice(tag.as_slice());
    WarrenMultihopFrame {
        version: WARREN_HPKE_VERSION_V1,
        exit_id: warren_wire::multihop::ExitId::from_bytes(*exit_id),
        epoch,
        seq,
        encapsulated_key,
        aead_tag,
        ciphertext: buf,
    }
}

/// Spawns an in-process QUIC "exit" that speaks the real multihop handshake:
/// it reads the HPKE-sealed setup frame (inner `IpRequest`) off a bidi stream,
/// replies with a sealed `IpAssign` (tunnel IPv4 `10.66.0.2`, gateway
/// `10.66.0.1`), then echoes every sealed data datagram back (opening the
/// client frame and re-sealing the same IP packet in the reverse direction).
///
/// Returns the bound address and the exit's published keys. The exit-side HPKE
/// is re-implemented independently of `warren-multihop`, so a green round-trip
/// proves wire interop, not just internal consistency.
///
/// # Panics
///
/// Panics on any setup failure (test helper).
pub async fn spawn_fake_multihop_exit(exit_key: SigningKey) -> (SocketAddr, MultihopExitKeys) {
    let ed25519_pubkey = exit_key.verifying_key().to_bytes();
    let (recipient_priv, recipient_pub) =
        ExitKem::gen_keypair(&mut rand_core::UnwrapErr(rand_core::OsRng));
    let x25519_pubkey: [u8; 32] = recipient_pub.to_bytes().into();
    let exit_id = [0x11u8; EXIT_ID_LEN];

    let cfg = make_server_config(&exit_key, default_crypto_provider(), &[ALPN_H3])
        .expect("server config");
    let endpoint = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap())
        .expect("server endpoint binds");
    let addr = endpoint.local_addr().expect("local addr");

    tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("conn");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let request_bytes = recv.read_to_end(65536).await.expect("read setup request");
        let request = WarrenMultihopFrame::decode(&request_bytes).expect("decode request frame");
        assert_eq!(
            request.exit_id.as_bytes(),
            &exit_id,
            "setup frame exit_id must match"
        );

        let encapped =
            <ExitKem as KemTrait>::EncappedKey::from_bytes(&request.encapsulated_key).unwrap();
        let ctx = setup_receiver::<ExitAead, ExitKdf, ExitKem>(
            &OpModeR::Base,
            &recipient_priv,
            &encapped,
            WARREN_HPKE_INFO_V1,
        )
        .expect("setup_receiver");

        let plaintext = exit_open(&ctx, &exit_id, &request).expect("open setup request");
        match try_decode_control(&plaintext)
            .expect("decode control")
            .expect("control present")
        {
            WarrenControlMessage::IpRequest { .. } => {}
            other => panic!("expected an IpRequest, got {other:?}"),
        }

        let assign = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 2],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: None,
        };
        let reply_plaintext = encode_control(&assign).expect("encode IpAssign");
        // Reverse seq starts at 0 for the setup reply; data replies use 1, 2, ...
        let reply_frame = exit_seal(
            &ctx,
            &exit_id,
            request.encapsulated_key,
            &reply_plaintext,
            request.epoch,
            0,
        );
        send.write_all(&reply_frame.encode().expect("encode reply"))
            .await
            .expect("write reply");
        send.finish().expect("finish reply");

        let mut reverse_seq: u64 = 1;
        while let Ok(dg) = conn.read_datagram().await {
            let Ok(frame) = WarrenMultihopFrame::decode(&dg) else {
                continue;
            };
            if frame.exit_id.as_bytes() != &exit_id {
                continue;
            }
            let Some(ip_packet) = exit_open(&ctx, &exit_id, &frame) else {
                continue;
            };
            let echo = exit_seal(
                &ctx,
                &exit_id,
                request.encapsulated_key,
                &ip_packet,
                frame.epoch,
                reverse_seq,
            );
            reverse_seq += 1;
            if conn
                .send_datagram(echo.encode().expect("encode echo").into())
                .is_err()
            {
                break;
            }
        }
        drop(endpoint);
    });

    (
        addr,
        MultihopExitKeys {
            ed25519_pubkey,
            x25519_pubkey,
            exit_id,
        },
    )
}

/// Spawns a multihop QUIC "exit" that completes the HPKE-sealed setup exchange
/// and then terminates inner TCP with a real server-side smoltcp stack at
/// `10.66.0.1:9`, echoing the payload. Every data datagram is opened on the way
/// in and re-sealed on the way out, so this exercises the full non-root proxy
/// datapath over the handshake real exits require.
///
/// # Panics
///
/// Panics on any setup failure (test helper).
pub async fn spawn_netstack_multihop_exit(exit_key: SigningKey) -> (SocketAddr, MultihopExitKeys) {
    let ed25519_pubkey = exit_key.verifying_key().to_bytes();
    let (recipient_priv, recipient_pub) =
        ExitKem::gen_keypair(&mut rand_core::UnwrapErr(rand_core::OsRng));
    let x25519_pubkey: [u8; 32] = recipient_pub.to_bytes().into();
    let exit_id = [0x11u8; EXIT_ID_LEN];

    let cfg = make_server_config(&exit_key, default_crypto_provider(), &[ALPN_H3])
        .expect("server config");
    let endpoint = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap())
        .expect("server endpoint binds");
    let addr = endpoint.local_addr().expect("local addr");

    tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("conn");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let request_bytes = recv.read_to_end(65536).await.expect("read setup request");
        let request = WarrenMultihopFrame::decode(&request_bytes).expect("decode request");
        let encapped =
            <ExitKem as KemTrait>::EncappedKey::from_bytes(&request.encapsulated_key).unwrap();
        let ctx = setup_receiver::<ExitAead, ExitKdf, ExitKem>(
            &OpModeR::Base,
            &recipient_priv,
            &encapped,
            WARREN_HPKE_INFO_V1,
        )
        .expect("setup_receiver");
        let _ = exit_open(&ctx, &exit_id, &request).expect("open setup request");

        let assign = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 2],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: None,
        };
        let reply = exit_seal(
            &ctx,
            &exit_id,
            request.encapsulated_key,
            &encode_control(&assign).expect("encode IpAssign"),
            request.epoch,
            0,
        );
        send.write_all(&reply.encode().expect("encode reply"))
            .await
            .expect("write reply");
        send.finish().expect("finish reply");

        // Outbound IP packets from the smoltcp stack are queued here, then sealed
        // and sent in the main loop (single task: keeps the HPKE ctx local).
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut device = ExitDevice {
            rx: VecDeque::new(),
            tx: out_tx,
        };
        let base = tokio::time::Instant::now();
        let now = || {
            SmolInstant::from_micros(i64::try_from(base.elapsed().as_micros()).unwrap_or(i64::MAX))
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x4558_4954_0002;
        let mut iface = Interface::new(config, &mut device, now());
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::v4(10, 66, 0, 1), 16));
        });
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        ));
        sockets
            .get_mut::<tcp::Socket<'_>>(handle)
            .listen(NETSTACK_EXIT_PORT)
            .expect("listen");

        let epoch = request.epoch;
        let mut reverse_seq: u64 = 1;
        loop {
            let _ = iface.poll(now(), &mut device, &mut sockets);
            let sock = sockets.get_mut::<tcp::Socket<'_>>(handle);
            let mut buf = [0u8; 4096];
            while sock.can_recv() && sock.can_send() {
                match sock.recv_slice(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = sock.send_slice(&buf[..n]);
                    }
                }
            }
            // Seal and send everything smoltcp produced this turn.
            while let Ok(ip_packet) = out_rx.try_recv() {
                let frame = exit_seal(
                    &ctx,
                    &exit_id,
                    request.encapsulated_key,
                    &ip_packet,
                    epoch,
                    reverse_seq,
                );
                reverse_seq += 1;
                if conn
                    .send_datagram(frame.encode().expect("encode out frame").into())
                    .is_err()
                {
                    return;
                }
            }
            let delay = iface
                .poll_delay(now(), &sockets)
                .map(|d| std::time::Duration::from_micros(d.total_micros()))
                .unwrap_or_else(|| std::time::Duration::from_millis(5));
            tokio::select! {
                dg = conn.read_datagram() => match dg {
                    Ok(datagram) => {
                        if let Ok(frame) = WarrenMultihopFrame::decode(&datagram)
                            && frame.exit_id.as_bytes() == &exit_id
                            && let Some(ip) = exit_open(&ctx, &exit_id, &frame)
                        {
                            device.rx.push_back(ip);
                        }
                    }
                    Err(_) => break,
                },
                _ = tokio::time::sleep(delay) => {}
            }
        }
        drop(endpoint);
    });

    (
        addr,
        MultihopExitKeys {
            ed25519_pubkey,
            x25519_pubkey,
            exit_id,
        },
    )
}

/// Spawns a multihop exit that, after the sealed setup, REPLAYS each data reply:
/// it seals the echo once and sends it twice with the SAME `(epoch, seq)`. A
/// correct client returns each opened packet exactly once (the duplicate is
/// dropped by the reverse-direction anti-replay window). Used to regression-test
/// the data-plane verify-then-record ordering.
///
/// # Panics
///
/// Panics on any setup failure (test helper).
pub async fn spawn_replaying_multihop_exit(exit_key: SigningKey) -> (SocketAddr, MultihopExitKeys) {
    let ed25519_pubkey = exit_key.verifying_key().to_bytes();
    let (recipient_priv, recipient_pub) =
        ExitKem::gen_keypair(&mut rand_core::UnwrapErr(rand_core::OsRng));
    let x25519_pubkey: [u8; 32] = recipient_pub.to_bytes().into();
    let exit_id = [0x11u8; EXIT_ID_LEN];

    let cfg = make_server_config(&exit_key, default_crypto_provider(), &[ALPN_H3])
        .expect("server config");
    let endpoint = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap())
        .expect("server endpoint binds");
    let addr = endpoint.local_addr().expect("local addr");

    tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("conn");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let request_bytes = recv.read_to_end(65536).await.expect("read setup request");
        let request = WarrenMultihopFrame::decode(&request_bytes).expect("decode request");
        let encapped =
            <ExitKem as KemTrait>::EncappedKey::from_bytes(&request.encapsulated_key).unwrap();
        let ctx = setup_receiver::<ExitAead, ExitKdf, ExitKem>(
            &OpModeR::Base,
            &recipient_priv,
            &encapped,
            WARREN_HPKE_INFO_V1,
        )
        .expect("setup_receiver");
        let _ = exit_open(&ctx, &exit_id, &request).expect("open setup request");

        let assign = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 2],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: None,
        };
        let reply = exit_seal(
            &ctx,
            &exit_id,
            request.encapsulated_key,
            &encode_control(&assign).expect("encode IpAssign"),
            request.epoch,
            0,
        );
        send.write_all(&reply.encode().expect("encode reply"))
            .await
            .expect("write reply");
        send.finish().expect("finish reply");

        let mut reverse_seq: u64 = 1;
        while let Ok(datagram) = conn.read_datagram().await {
            let Ok(frame) = WarrenMultihopFrame::decode(&datagram) else {
                continue;
            };
            if frame.exit_id.as_bytes() != &exit_id {
                continue;
            }
            let Some(ip) = exit_open(&ctx, &exit_id, &frame) else {
                continue;
            };
            let echo = exit_seal(
                &ctx,
                &exit_id,
                request.encapsulated_key,
                &ip,
                frame.epoch,
                reverse_seq,
            );
            reverse_seq += 1;
            let bytes = echo.encode().expect("encode echo");
            // Send the identical sealed frame TWICE (same seq): the client must
            // accept it once and drop the replay.
            if conn.send_datagram(bytes.clone().into()).is_err() {
                break;
            }
            let _ = conn.send_datagram(bytes.into());
        }
        drop(endpoint);
    });

    (
        addr,
        MultihopExitKeys {
            ed25519_pubkey,
            x25519_pubkey,
            exit_id,
        },
    )
}
