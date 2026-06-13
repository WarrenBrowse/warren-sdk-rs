//! Test-only helpers shared across the Warren SDK workspace.
//!
//! This crate is `publish = false` and is only ever a dev-dependency. It exists
//! so the in-process fake exit lives in one place instead of being copy-pasted
//! into every crate's integration tests.

use std::collections::VecDeque;
use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::sync::mpsc;
use warren_transport::{default_crypto_provider, make_server_config};
use warren_wire::{
    MAX_SETUP_FRAME_BYTES, PROTOCOL_VERSION, SetupAck, decode_setup, encode_setup_ack,
};

/// ALPN the fake exit accepts, matching the client.
const ALPN_H3: &[u8] = b"h3";

/// TCP port the netstack exit echoes on.
pub const NETSTACK_EXIT_PORT: u16 = 9;
/// The exit-side gateway/listen address of the netstack exit.
pub const NETSTACK_EXIT_IP: [u8; 4] = [10, 66, 0, 1];

/// Spawns an in-process QUIC "exit" bound to `127.0.0.1:0` that completes the
/// Warren handshake (raw-public-key TLS, Setup/SetupAck) for `exit_key` and then
/// echoes every datagram back until the client disconnects.
///
/// Returns the bound address and the exit's 32-byte public key, which the client
/// pins as the expected identity. The assigned tunnel IPv4 is `10.66.0.2`.
///
/// # Panics
///
/// Panics on any setup failure: it is a test helper, so a broken server is a
/// test bug, not a runtime condition.
pub async fn spawn_fake_exit(exit_key: SigningKey) -> (SocketAddr, [u8; 32]) {
    let exit_pubkey = exit_key.verifying_key().to_bytes();
    let cfg = make_server_config(&exit_key, default_crypto_provider(), &[ALPN_H3])
        .expect("server config");
    let endpoint = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap())
        .expect("server endpoint binds");
    let addr = endpoint.local_addr().expect("local addr");

    tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("incoming connection")
            .await
            .expect("connection established");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let _setup = decode_setup(
            &recv
                .read_to_end(MAX_SETUP_FRAME_BYTES)
                .await
                .expect("read setup"),
        )
        .expect("decode setup");

        let ack = SetupAck {
            protocol_version: PROTOCOL_VERSION,
            tunnel_ipv4: [10, 66, 0, 2],
            tunnel_ipv6: None,
            exit_pubkey,
            max_mtu: 1280,
            multiconn_attached: true,
            daita_spec: None,
        };
        send.write_all(&encode_setup_ack(&ack).expect("encode ack"))
            .await
            .expect("write ack");
        send.finish().expect("finish");

        while let Ok(dg) = conn.read_datagram().await {
            if conn.send_datagram(dg).is_err() {
                break;
            }
        }
        drop(endpoint);
    });

    (addr, exit_pubkey)
}

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

/// Spawns a QUIC "exit" that, after the handshake, terminates inner TCP with a
/// real server-side smoltcp stack at `10.66.0.1:9` and echoes the payload. This
/// lets the full non-root datapath (client netstack over the QUIC tunnel) be
/// exercised in-process, not just the datagram plane.
///
/// # Panics
///
/// Panics on any setup failure (test helper).
pub async fn spawn_netstack_exit(exit_key: SigningKey) -> (SocketAddr, [u8; 32]) {
    let exit_pubkey = exit_key.verifying_key().to_bytes();
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
        let _ = decode_setup(
            &recv
                .read_to_end(MAX_SETUP_FRAME_BYTES)
                .await
                .expect("setup"),
        );
        let ack = SetupAck {
            protocol_version: PROTOCOL_VERSION,
            tunnel_ipv4: [10, 66, 0, 2],
            tunnel_ipv6: None,
            exit_pubkey,
            max_mtu: 1280,
            multiconn_attached: true,
            daita_spec: None,
        };
        send.write_all(&encode_setup_ack(&ack).expect("enc"))
            .await
            .expect("write");
        send.finish().expect("finish");

        // Outbound IP packets from the exit stack -> QUIC datagrams.
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let send_conn = conn.clone();
        tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                if send_conn.send_datagram(frame.into()).is_err() {
                    break;
                }
            }
        });

        let mut device = ExitDevice {
            rx: VecDeque::new(),
            tx: out_tx,
        };
        let base = tokio::time::Instant::now();
        let now = || {
            SmolInstant::from_micros(i64::try_from(base.elapsed().as_micros()).unwrap_or(i64::MAX))
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x4558_4954_0001;
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
            let delay = iface
                .poll_delay(now(), &sockets)
                .map(|d| std::time::Duration::from_micros(d.total_micros()))
                .unwrap_or_else(|| std::time::Duration::from_millis(5));
            tokio::select! {
                dg = conn.read_datagram() => match dg {
                    Ok(frame) => device.rx.push_back(frame.to_vec()),
                    Err(_) => break,
                },
                _ = tokio::time::sleep(delay) => {}
            }
        }
        drop(endpoint);
    });

    (addr, exit_pubkey)
}
