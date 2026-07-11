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

use crate::client::{QuicDialError, build_inner_rpk_client_config, dial_quic};
use crate::tls;

/// The exit's public TCP port for the fallback carrier. The cover-domain TLS
/// handshake mimics ordinary HTTPS, which always lives on `:443`.
pub(crate) const COVER_TCP_PORT: u16 = 443;

/// ALPN offered on the cover-domain TLS handshake of the fallback carrier. Over
/// TCP a real cover host negotiates HTTP (`h2` then `http/1.1`), never `h3`,
/// which is QUIC-only: offering `h3` on a TCP `:443` handshake would be an
/// anomalous, fingerprintable tell that no ordinary browser produces. The
/// carrier payload after the handshake is framed QUIC datagrams regardless of
/// the negotiated protocol, so this list is purely the on-wire fingerprint,
/// matched here to what a browser offers a plain HTTPS server.
pub(crate) const COVER_TCP_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// The cover-domain TLS target of the fallback carrier for one dial: the exit's
/// `:443/tcp` address, the cover-domain SNI to present, and the WebPKI client
/// config that validates the cover certificate.
pub(crate) struct CoverTls<'a> {
    /// The exit's `:443/tcp` endpoint the carrier connects to.
    pub addr: SocketAddr,
    /// The cover-domain hostname: the TLS SNI and the name validated against the
    /// presented certificate. Sourced from the exit's signed roster.
    pub domain: &'a str,
    /// WebPKI client config (roots + [`COVER_TCP_ALPN`]) for the cover handshake.
    pub client_config: Arc<rustls::ClientConfig>,
}

/// Resolves the fallback policy for one dial. Enabled ONLY when all three hold:
/// the deployer opted in (`opt_in`), the selected exit advertises the carrier
/// (`exit_tcp_fallback`, from its signed roster), and it carries a cover domain
/// to present as the TLS SNI. Any missing precondition yields the default OFF
/// policy, so a UDP failure is surfaced and no `:443/tcp` connection is tried:
/// an exit that does not advertise the carrier would only refuse the TCP
/// connection, so attempting it is pointless.
#[must_use]
pub(crate) fn resolve_fallback_policy(
    opt_in: bool,
    exit_tcp_fallback: bool,
    cover_domain: Option<&str>,
) -> FallbackPolicy {
    if opt_in && exit_tcp_fallback && cover_domain.is_some() {
        FallbackPolicy::enabled()
    } else {
        FallbackPolicy::default()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_enabled_only_when_opt_in_and_advertised_and_cover_present() {
        // All three preconditions hold: the fallback is armed.
        assert!(
            resolve_fallback_policy(true, true, Some("cover.example")).tcp_fallback_enabled,
            "opt-in + advertised + cover must enable the fallback"
        );
    }

    #[test]
    fn policy_stays_off_when_the_deployer_did_not_opt_in() {
        assert!(
            !resolve_fallback_policy(false, true, Some("cover.example")).tcp_fallback_enabled,
            "without the deployer opt-in the fallback must stay off"
        );
    }

    #[test]
    fn policy_stays_off_when_the_exit_does_not_advertise_the_carrier() {
        assert!(
            !resolve_fallback_policy(true, false, Some("cover.example")).tcp_fallback_enabled,
            "an exit that does not advertise tcp_fallback must not be dialled over TCP"
        );
    }

    #[test]
    fn policy_stays_off_without_a_cover_domain() {
        assert!(
            !resolve_fallback_policy(true, true, None).tcp_fallback_enabled,
            "no cover domain means no TLS SNI to present, so the fallback stays off"
        );
    }

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
}
