//! Opt-in TLS-over-TCP fallback for the QUIC dial.
//!
//! When outbound UDP/443 is blocked or throttled, a QUIC/UDP-only dial does not
//! connect. This module races the existing UDP handshake against the engine's
//! [`connect_with_fallback`] policy and, only when the deployer opted in AND the
//! selected exit advertises the carrier capability in its signed roster AND it
//! carries a cover domain, retries the SAME QUIC datagrams inside one real TLS
//! 1.3 stream to the exit's cover domain on `:443/tcp` (the
//! [`warrenguard_tcp_fallback`] carrier). The inner QUIC config is byte-for-byte
//! the UDP dial's, so the only thing that changes is the socket underneath.
//!
//! Off by default: with no opt-in, or an exit that does not advertise the
//! capability, the policy is disabled and the TCP path is never even
//! constructed. The disabled path delegates straight to the plain UDP
//! [`dial_quic`](crate::client::dial_quic) with no timeout wrapper, so the
//! default behaviour (and its typed errors) is unchanged.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use warrenguard_tcp_fallback::tls::connect_cover_tls;
use warrenguard_tcp_fallback::{
    FallbackPolicy, TcpCarrierSocket, build_carrier_client_endpoint, connect_with_fallback,
};

// The fallback-carrier arming rule and its cover-domain fingerprint constants
// have a single home in `warrenguard-tcp-fallback`, shared with the privileged
// system-VPN transport so neither the policy nor the on-wire fingerprint can skew
// between datapaths. Re-exported at crate scope for the transport client/multihop
// (which resolve the policy and build the per-dial cover target) and the SDK dial
// glue below (which wraps the engine's UDP-vs-TCP race around the userland dial).
pub(crate) use warrenguard_tcp_fallback::{
    COVER_TCP_ALPN, COVER_TCP_PORT, CoverTls, resolve_fallback_policy,
};

use crate::client::{
    QuicDialError, build_inner_rpk_client_config, build_inner_webpki_client_config, dial_quic,
    dial_quic_webpki,
};
use crate::tls;

/// Dials the exit's QUIC endpoint, falling back to the TLS-over-TCP carrier only
/// when `policy` is enabled and a `cover` target is present. With the policy
/// disabled (the default) this is the plain UDP [`dial_quic`] verbatim: no
/// timeout wrapper, typed errors preserved, and the TCP path never constructed.
///
/// With the policy enabled it races the UDP handshake against
/// [`FallbackPolicy::udp_handshake_timeout`]; on a UDP failure or timeout it
/// builds the carrier (TCP connect, cover-domain TLS, [`TcpCarrierSocket`] over a
/// fresh quinn endpoint) and dials the same exit over it, so the QUIC state
/// machine, RPK identity check and obfuscation are identical to the UDP path.
///
/// # Errors
/// [`QuicDialError`] from the UDP dial (disabled path), or
/// [`QuicDialError::Fallback`] wrapping the engine's typed outcome when the race
/// ends without a connection.
pub(crate) async fn dial_quic_with_fallback(
    exit_pubkey: [u8; 32],
    exit_addr: SocketAddr,
    bind_local_ip: Option<SocketAddr>,
    transport_config: Option<Arc<quinn::TransportConfig>>,
    socket_bypass: Option<warrenguard_socket_bypass::SocketBypass>,
    policy: &FallbackPolicy,
    cover: Option<CoverTls<'_>>,
) -> Result<(quinn::Endpoint, quinn::Connection), QuicDialError> {
    // Opt-out path: byte-for-byte the existing UDP dial. `connect_with_fallback`
    // is deliberately NOT on this path, so the default dial keeps its own quinn
    // handshake timeout (never the fallback's short deadline) and its typed
    // errors. The TCP closure is never even constructed.
    let cover = cover.filter(|_| policy.tcp_fallback_enabled);
    let Some(cover) = cover else {
        return dial_quic(
            exit_pubkey,
            exit_addr,
            bind_local_ip,
            transport_config,
            socket_bypass,
        )
        .await;
    };

    let udp_transport_config = transport_config.clone();
    let udp = async move {
        dial_quic(
            exit_pubkey,
            exit_addr,
            bind_local_ip,
            udp_transport_config,
            socket_bypass,
        )
        .await
        // The UDP error is only surfaced by the engine when the fallback is
        // disabled, which cannot happen on this (enabled) branch, so it is
        // mapped to an opaque io::Error (no address, no-log) purely to satisfy
        // the race's shared Result type.
        .map_err(|_| io::Error::other("udp quic handshake failed"))
    };
    let tcp = || dial_tcp_carrier(exit_pubkey, exit_addr, cover, transport_config);

    connect_with_fallback(policy, udp, tcp)
        .await
        .map_err(QuicDialError::Fallback)
}

/// Builds the TLS-over-TCP carrier to `cover.addr`, wraps it as a quinn abstract
/// socket, and dials the exit's QUIC endpoint over it (same inner RPK config and
/// SNI as the UDP dial). Returns the `(Endpoint, Connection)` the caller drives.
///
/// Errors are mapped to opaque [`io::Error`]s (no address, no-log): the engine's
/// [`connect_with_fallback`] surfaces them as
/// [`FallbackError::TcpFallbackFailed`](warrenguard_tcp_fallback::FallbackError::TcpFallbackFailed).
async fn dial_tcp_carrier(
    exit_pubkey: [u8; 32],
    peer: SocketAddr,
    cover: CoverTls<'_>,
    transport_config: Option<Arc<quinn::TransportConfig>>,
) -> io::Result<(quinn::Endpoint, quinn::Connection)> {
    let tcp = TcpStream::connect(cover.addr).await?;
    let stream = connect_cover_tls(cover.domain, tcp, cover.client_config)
        .await
        .map_err(|_| io::Error::other("cover-domain tls handshake failed"))?;
    // The synthetic quinn peer MUST equal the address passed to `connect`, so
    // quinn routes the carrier's inbound datagrams to this connection's path.
    let socket = TcpCarrierSocket::new(stream, peer);
    let inner_config = build_inner_rpk_client_config(transport_config)
        .map_err(|_| io::Error::other("inner quic client config failed"))?;
    let endpoint = build_carrier_client_endpoint(socket, inner_config)
        .map_err(|_| io::Error::other("carrier quic endpoint build failed"))?;
    let server_name = tls::name::encode(tls::WarrenPubkey::from_bytes(exit_pubkey));
    let conn = endpoint
        .connect(peer, &server_name)
        .map_err(|_| io::Error::other("carrier quic connect setup failed"))?
        .await
        .map_err(|_| io::Error::other("carrier quic handshake failed"))?;
    Ok((endpoint, conn))
}

/// Multihop/WebPKI analogue of [`dial_quic_with_fallback`]: dials the relay's
/// QUIC endpoint in the X.509 cover-domain posture (the production exits run it),
/// falling back to the TLS-over-TCP carrier only when `policy` is enabled and a
/// `cover` target is present. Unlike the RPK variant, both the UDP leg
/// ([`dial_quic_webpki`]) and the carrier-inner QUIC validate the exit's real
/// certificate against Mozilla roots with `server_name` (the cover domain) as the
/// SNI; the relay's Warren identity is proven in-band after the dial, exactly as
/// the plain multihop dial does. With the policy disabled this is the plain
/// [`dial_quic_webpki`] verbatim: no timeout wrapper, typed errors preserved, and
/// the TCP path never constructed.
///
/// # Errors
/// [`QuicDialError`] from the UDP dial (disabled path), or
/// [`QuicDialError::Fallback`] wrapping the engine's typed outcome when the race
/// ends without a connection.
pub(crate) async fn dial_quic_webpki_with_fallback(
    server_name: &str,
    exit_addr: SocketAddr,
    bind_local_ip: Option<SocketAddr>,
    transport_config: Option<Arc<quinn::TransportConfig>>,
    socket_bypass: Option<warrenguard_socket_bypass::SocketBypass>,
    policy: &FallbackPolicy,
    cover: Option<CoverTls<'_>>,
) -> Result<(quinn::Endpoint, quinn::Connection), QuicDialError> {
    let cover = cover.filter(|_| policy.tcp_fallback_enabled);
    let Some(cover) = cover else {
        return dial_quic_webpki(
            server_name,
            exit_addr,
            bind_local_ip,
            transport_config,
            socket_bypass,
        )
        .await;
    };

    let udp_transport_config = transport_config.clone();
    let udp = async move {
        dial_quic_webpki(
            server_name,
            exit_addr,
            bind_local_ip,
            udp_transport_config,
            socket_bypass,
        )
        .await
        .map_err(|_| io::Error::other("udp quic handshake failed"))
    };
    let tcp = || dial_tcp_carrier_webpki(server_name, exit_addr, cover, transport_config);

    connect_with_fallback(policy, udp, tcp)
        .await
        .map_err(QuicDialError::Fallback)
}

/// WebPKI (X.509 cover-domain) analogue of [`dial_tcp_carrier`]: the inner QUIC
/// over the carrier uses the cover posture, with the cover domain as both the
/// outer cover-TLS SNI and the inner QUIC SNI, matching [`dial_quic_webpki`]. The
/// relay's Warren identity is proven in-band by the caller after the dial, not
/// pinned at the TLS layer, so `server_name` (the cover domain) is the only
/// identity input the dial itself needs.
async fn dial_tcp_carrier_webpki(
    server_name: &str,
    peer: SocketAddr,
    cover: CoverTls<'_>,
    transport_config: Option<Arc<quinn::TransportConfig>>,
) -> io::Result<(quinn::Endpoint, quinn::Connection)> {
    let tcp = TcpStream::connect(cover.addr).await?;
    let stream = connect_cover_tls(cover.domain, tcp, cover.client_config)
        .await
        .map_err(|_| io::Error::other("cover-domain tls handshake failed"))?;
    // The synthetic quinn peer MUST equal the address passed to `connect`, so
    // quinn routes the carrier's inbound datagrams to this connection's path.
    let socket = TcpCarrierSocket::new(stream, peer);
    let inner_config = build_inner_webpki_client_config(transport_config)
        .map_err(|_| io::Error::other("inner quic client config failed"))?;
    let endpoint = build_carrier_client_endpoint(socket, inner_config)
        .map_err(|_| io::Error::other("carrier quic endpoint build failed"))?;
    let conn = endpoint
        .connect(peer, server_name)
        .map_err(|_| io::Error::other("carrier quic connect setup failed"))?
        .await
        .map_err(|_| io::Error::other("carrier quic handshake failed"))?;
    Ok((endpoint, conn))
}

#[cfg(test)]
mod tests {
    mod carrier_e2e {
        //! End-to-end: a real cover-domain TLS-over-TCP carrier terminated by the
        //! engine `serve_carrier`, shuttling to a loopback QUIC RPK dispatcher.
        //! Proves the dial actually switches to TCP when UDP is blocked, and
        //! leaves the carrier untouched when UDP succeeds. This is the network
        //! datapath; the anti-censorship behaviour over a real blocked-UDP link
        //! stays operator-validated.

        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        use ed25519_dalek::SigningKey;
        use tokio::io::AsyncWriteExt;
        use warrenguard_tcp_fallback::{FallbackPolicy, TerminatorConfig, serve_carrier};

        use super::super::{COVER_TCP_ALPN, CoverTls, dial_quic_with_fallback};
        use crate::tls;

        /// A loopback QUIC RPK dispatcher plus a cover-domain TLS-over-TCP carrier
        /// terminator in front of it. Returns the exit pubkey, the dispatcher's
        /// UDP address (the direct-UDP dial target), the carrier's TCP address,
        /// the WebPKI client config trusting the cover cert, and a counter of TCP
        /// carrier connections accepted (to assert the carrier stays untouched).
        struct Harness {
            exit_pubkey: [u8; 32],
            dispatcher_addr: std::net::SocketAddr,
            cover_addr: std::net::SocketAddr,
            cover_client_config: Arc<rustls::ClientConfig>,
            carrier_conns: Arc<AtomicUsize>,
        }

        async fn spawn_harness() -> Harness {
            let provider = tls::default_crypto_provider();

            // Loopback QUIC RPK dispatcher: a bare exit endpoint that accepts and
            // holds connections (the terminator shuttles carrier datagrams here).
            let exit_key = SigningKey::from_bytes(&[7u8; 32]);
            let exit_pubkey = exit_key.verifying_key().to_bytes();
            let server_cfg = tls::make_server_config(&exit_key, provider.clone(), &[b"h3"])
                .expect("dispatcher server config");
            let dispatcher = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap())
                .expect("dispatcher binds");
            let dispatcher_addr = dispatcher.local_addr().expect("dispatcher addr");
            tokio::spawn(async move {
                while let Some(incoming) = dispatcher.accept().await {
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            conn.closed().await;
                        }
                    });
                }
            });

            // Cover-domain TLS-over-TCP carrier terminator in front of it.
            let ck = rcgen::generate_simple_self_signed(vec!["cover.test".to_string()])
                .expect("self-signed cover cert");
            let cover_cert = ck.cert.der().clone();
            let cover_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()),
            );
            let cover_server_cfg = warrenguard_tls::build_server_rustls_config_x509(
                vec![cover_cert.clone()],
                cover_key,
                provider.clone(),
                &[b"http/1.1"],
            )
            .expect("cover server config");
            let acceptor =
                warrenguard_tcp_fallback::tls::cover_tls_acceptor(Arc::new(cover_server_cfg));

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("cover listener binds");
            let cover_addr = listener.local_addr().expect("cover addr");
            let term_cfg = TerminatorConfig {
                dispatcher: dispatcher_addr,
                first_frame_timeout: Duration::from_secs(5),
            };
            let carrier_conns = Arc::new(AtomicUsize::new(0));
            let conns = Arc::clone(&carrier_conns);
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        break;
                    };
                    conns.fetch_add(1, Ordering::SeqCst);
                    let acceptor = acceptor.clone();
                    let term_cfg = term_cfg.clone();
                    tokio::spawn(async move {
                        let Ok(tls_stream) = acceptor.accept(tcp).await else {
                            return;
                        };
                        // A non-carrier prober is served a minimal HTTP/1.1 decoy.
                        let _ = serve_carrier(tls_stream, &term_cfg, |mut s, _prefix| async move {
                            let _ = s
                                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                                .await;
                            Ok(())
                        })
                        .await;
                    });
                }
            });

            // Client trusts the self-signed cover cert as a WebPKI root.
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cover_cert).expect("add cover root");
            let cover_client_config = Arc::new(
                warrenguard_tls::build_client_rustls_config_webpki(roots, provider, COVER_TCP_ALPN)
                    .expect("cover client config"),
            );

            Harness {
                exit_pubkey,
                dispatcher_addr,
                cover_addr,
                cover_client_config,
                carrier_conns,
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn blocked_udp_falls_back_to_the_tcp_carrier() {
            let h = spawn_harness().await;

            // The UDP dial targets a loopback port with no listener, so the QUIC
            // handshake never completes; with a short deadline the fallback fires.
            let black_hole: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
            let policy = FallbackPolicy {
                tcp_fallback_enabled: true,
                udp_handshake_timeout: Duration::from_millis(400),
            };
            let cover = CoverTls {
                addr: h.cover_addr,
                domain: "cover.test",
                client_config: Arc::clone(&h.cover_client_config),
            };

            let (_endpoint, conn) = tokio::time::timeout(
                Duration::from_secs(10),
                dial_quic_with_fallback(
                    h.exit_pubkey,
                    black_hole,
                    None,
                    None,
                    None,
                    &policy,
                    Some(cover),
                ),
            )
            .await
            .expect("the fallback dial completes")
            .expect("blocked UDP must fall back to the TCP carrier and connect");

            assert!(
                conn.close_reason().is_none(),
                "the QUIC connection established over the carrier must be live"
            );
            assert_eq!(
                h.carrier_conns.load(Ordering::SeqCst),
                1,
                "exactly one carrier connection must have been used for the fallback"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn working_udp_never_touches_the_tcp_carrier() {
            let h = spawn_harness().await;

            // UDP works (dial the live dispatcher directly); even with the policy
            // armed and a cover target present, the carrier must never be dialled.
            let policy = FallbackPolicy::enabled();
            let cover = CoverTls {
                addr: h.cover_addr,
                domain: "cover.test",
                client_config: Arc::clone(&h.cover_client_config),
            };

            let (_endpoint, conn) = tokio::time::timeout(
                Duration::from_secs(10),
                dial_quic_with_fallback(
                    h.exit_pubkey,
                    h.dispatcher_addr,
                    None,
                    None,
                    None,
                    &policy,
                    Some(cover),
                ),
            )
            .await
            .expect("the UDP dial completes")
            .expect("a reachable exit must connect over UDP");

            assert!(
                conn.close_reason().is_none(),
                "the UDP connection must be live"
            );
            assert_eq!(
                h.carrier_conns.load(Ordering::SeqCst),
                0,
                "a successful UDP handshake must never open the TCP carrier"
            );
        }
    }

    mod real_exit {
        //! Real-exit validation of the WebPKI (X.509 cover-posture) carrier dial
        //! against a LIVE production exit, gated `#[ignore]`. The UDP leg is aimed
        //! at a black-hole port so the QUIC/UDP handshake never completes (a
        //! UDP-blocked censored network), forcing the carrier: the inner QUIC then
        //! rides one real cover-domain TLS stream on the exit's `:443/tcp` and must
        //! validate the exit dispatcher's real X.509 cover certificate against
        //! Mozilla roots. Run with:
        //!   WARREN_CARRIER_EXIT_IP=<ip> WARREN_CARRIER_COVER_DOMAIN=<host> \
        //!     cargo test -p warren-transport --lib \
        //!     real_exit::webpki_carrier_dial_over_blocked_udp -- --ignored --nocapture

        use std::net::SocketAddr;
        use std::time::Duration;

        use warrenguard_tcp_fallback::FallbackPolicy;

        use super::super::{CoverTls, dial_quic_webpki_with_fallback};

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "real-exit: needs WARREN_CARRIER_EXIT_IP + WARREN_CARRIER_COVER_DOMAIN"]
        async fn webpki_carrier_dial_over_blocked_udp() {
            let exit_ip: std::net::IpAddr = std::env::var("WARREN_CARRIER_EXIT_IP")
                .expect("set WARREN_CARRIER_EXIT_IP")
                .parse()
                .expect("WARREN_CARRIER_EXIT_IP must be an IP address");
            let cover_domain = std::env::var("WARREN_CARRIER_COVER_DOMAIN")
                .expect("set WARREN_CARRIER_COVER_DOMAIN");

            // A short UDP deadline so the black-hole leg fails fast and the carrier
            // takes over, exactly as it would on a UDP-hostile network.
            let policy = FallbackPolicy {
                tcp_fallback_enabled: true,
                udp_handshake_timeout: Duration::from_millis(800),
            };
            let cover = CoverTls {
                addr: SocketAddr::new(exit_ip, super::super::COVER_TCP_PORT),
                domain: &cover_domain,
                client_config: crate::client::cover_tls_client_config()
                    .expect("cover-domain WebPKI client config builds"),
            };
            // The UDP/QUIC leg targets the discard port: nothing answers, so the
            // handshake times out and the dial must fall back to the carrier.
            let exit_addr = SocketAddr::new(exit_ip, 9);

            let (_endpoint, conn) = tokio::time::timeout(
                Duration::from_secs(20),
                dial_quic_webpki_with_fallback(
                    &cover_domain,
                    exit_addr,
                    None,
                    None,
                    None,
                    &policy,
                    Some(cover),
                ),
            )
            .await
            .expect("the carrier dial completes within the deadline")
            .expect("blocked UDP must fall back to the real cover-posture carrier and connect");

            assert!(
                conn.close_reason().is_none(),
                "the QUIC connection established over the carrier must be live"
            );
        }
    }
}
