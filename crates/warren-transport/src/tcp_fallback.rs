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
//! [`dial_quic_webpki`](crate::client::dial_quic_webpki) with no timeout wrapper,
//! so the default behaviour (and its typed errors) is unchanged.

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

use crate::client::{QuicDialError, build_inner_webpki_client_config, dial_quic_webpki};

/// Dials the relay's QUIC endpoint in the X.509 cover-domain posture (the
/// production exits run it), falling back to the TLS-over-TCP carrier only when
/// `policy` is enabled and a `cover` target is present. Both the UDP leg
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
                ..FallbackPolicy::default()
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
