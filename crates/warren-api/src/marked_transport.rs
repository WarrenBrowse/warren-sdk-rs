//! Socket-marked control-plane [`HttpTransport`] (feature `marked-transport`).
//!
//! # Why this exists next to [`ReqwestTransport`](crate::ReqwestTransport)
//!
//! A privileged desktop VPN daemon (warrend) locks the host down during a
//! connect with a `policy drop` firewall that permits only its OWN egress. The
//! tightest way to name "its own egress" is the WireGuard fwmark model already
//! used for the QUIC carrier: tag the socket with `SO_MARK =
//! WARREN_TUNNEL_FWMARK` and let a `meta mark <m> accept` firewall rule pass
//! exactly those packets, so no unrelated (even root-owned) process leaks out of
//! the block. The carrier is already tagged in the engine; the CONTROL-PLANE
//! HTTP client (directory/API fetch that runs BEFORE the carrier dials) was not,
//! which forced the guard to fall back to a broad owner-uid match.
//!
//! `reqwest` exposes no seam to set `SO_MARK` on its sockets (its hyper-util
//! `HttpConnector` creates them with no hook, and a `connector_layer` wraps
//! outside socket creation), so the mark can only be set by owning socket
//! creation. This is a small, self-contained HTTPS/1.1 client over
//! hyper + rustls whose TCP sockets are tagged before connect via the engine's
//! [`warrenguard_socket_bypass::apply_pre_connect`], reused verbatim from the
//! carrier path so the client and the carrier can never disagree on the mark.
//!
//! It is OPT-IN and additive: the default [`ReqwestTransport`](crate::ReqwestTransport)
//! is untouched, so every non-daemon app keeps the batteries-included reqwest
//! path. Only warrend builds its control-plane client on this transport.
//!
//! # Scope
//!
//! - **Linux**: `SO_MARK` is applied fail-closed (a socket that cannot be marked
//!   is not connected). `SO_MARK` needs `CAP_NET_ADMIN`; warrend runs as root.
//! - **Other targets**: the mark is a no-op (macOS keeps an owner-uid guard;
//!   there is no `SO_MARK` there). The transport still works as a plain client.
//! - **DNS**: `getaddrinfo` sockets are libc-internal and cannot be marked, so
//!   under a strict mark-only firewall a `getaddrinfo` lookup would be dropped and
//!   brick the fetch. When marking is on (Linux), resolution therefore goes over
//!   a MARKED UDP socket instead ([`marked_dns`]): a minimal A-record query to the
//!   system's upstream nameservers, tagged with the same fwmark, so the whole
//!   fetch (DNS + connect) passes the guard with NO firewall hole. Unmarked mode
//!   and non-Linux keep the system resolver.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpSocket;
use tokio_rustls::TlsConnector;
use warrenguard_socket_bypass::SocketBypass;
use warrenguard_tun_core::WARREN_TUNNEL_FWMARK;

use crate::transport::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError};

/// Connect + total deadlines, mirroring warren-core and [`ReqwestTransport`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);

/// A socket-marked control-plane transport.
///
/// Holds two rustls configs (SNI on / SNI off, matching the reqwest transport's
/// no-SNI anti-censorship fallback) and a flag deciding whether the TCP sockets
/// carry the Warren fwmark. The no-SNI config still verifies the server
/// certificate against the requested host name, so it is no weaker than the
/// default path.
#[derive(Clone)]
pub struct MarkedTransport {
    sni: Arc<rustls::ClientConfig>,
    no_sni: Arc<rustls::ClientConfig>,
    mark_sockets: bool,
}

impl MarkedTransport {
    /// Builds a transport whose TCP sockets carry `SO_MARK = WARREN_TUNNEL_FWMARK`
    /// on Linux (a no-op on other targets). This is the constructor the privileged
    /// daemon uses so its control-plane fetch is permitted by a `meta mark` guard.
    ///
    /// # Errors
    /// [`TransportError::Io`] if the rustls client config cannot be built (a
    /// broken crypto backend; never happens with a working ring build).
    pub fn marked() -> Result<Self, TransportError> {
        Self::build(true)
    }

    /// Builds a transport that does NOT mark its sockets: a plain HTTPS client,
    /// used by tests and available for callers that want this stack without the
    /// privileged fwmark tagging.
    ///
    /// # Errors
    /// Same as [`marked`](Self::marked).
    pub fn unmarked() -> Result<Self, TransportError> {
        Self::build(false)
    }

    fn build(mark_sockets: bool) -> Result<Self, TransportError> {
        let mut sni = client_config()?;
        sni.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut no_sni = sni.clone();
        // The cert is still verified against the requested host name; only the
        // SNI extension is withheld, to defeat SNI-based blocking.
        no_sni.enable_sni = false;
        Ok(Self {
            sni: Arc::new(sni),
            no_sni: Arc::new(no_sni),
            mark_sockets,
        })
    }

    fn tls_config(&self, use_sni: bool) -> Arc<rustls::ClientConfig> {
        if use_sni {
            Arc::clone(&self.sni)
        } else {
            Arc::clone(&self.no_sni)
        }
    }
}

/// Builds the rustls client config: Mozilla WebPKI roots, ring provider, no
/// resumption. TLS 1.3 (the workspace rustls has no `tls12` feature); the Warren
/// API and its fallback hosts are all 1.3-capable.
fn client_config() -> Result<rustls::ClientConfig, TransportError> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| TransportError::Io("tls client config initialization failed".to_owned()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

/// Applies the Warren tunnel fwmark to a fresh, not-yet-connected socket, so a
/// `meta mark <WARREN_TUNNEL_FWMARK> accept` firewall rule lets it egress. Reuses
/// the engine's pre-connect bypass verbatim (the carrier uses the same call), so
/// the control-plane client and the carrier can never disagree on the mark.
///
/// Fail-closed: a socket that cannot be marked is not connected. `SO_MARK` needs
/// `CAP_NET_ADMIN`.
///
/// # Errors
/// The `setsockopt` failure from the engine bypass (`EPERM` without
/// `CAP_NET_ADMIN`).
#[cfg(target_os = "linux")]
fn mark_socket<S: std::os::fd::AsFd>(sock: &S, is_v6: bool) -> io::Result<()> {
    let sref = socket2::SockRef::from(sock);
    warrenguard_socket_bypass::apply_pre_connect(
        &sref,
        is_v6,
        SocketBypass::Fwmark(WARREN_TUNNEL_FWMARK),
    )
}

/// Off Linux there is no `SO_MARK`; the daemon keeps an owner-uid guard there, so
/// marking is a no-op (never a silent failure that would break the connect).
#[cfg(not(target_os = "linux"))]
fn mark_socket<S>(_sock: &S, _is_v6: bool) -> io::Result<()> {
    // Referenced so the constant is not dead on non-Linux targets.
    let _ = (SocketBypass::Fwmark(WARREN_TUNNEL_FWMARK), _is_v6);
    Ok(())
}

/// Dials `addr` on a fresh TCP socket that (optionally) carries the Warren
/// fwmark, set BEFORE connect so the firewall classifies the SYN.
async fn connect_marked(addr: SocketAddr, mark: bool) -> io::Result<tokio::net::TcpStream> {
    let socket = if addr.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    if mark {
        mark_socket(&socket, addr.is_ipv6())?;
    }
    socket.connect(addr).await
}

/// Resolves `host` to one or more socket addresses.
///
/// An IP literal short-circuits (no DNS). When `mark` is on (Linux), resolution
/// goes over a MARKED UDP socket ([`marked_dns::resolve_marked`]) so it passes a
/// strict `meta mark` firewall guard; otherwise (or off Linux) the system
/// resolver is used, matching the reqwest path.
async fn resolve(host: &str, port: u16, mark: bool) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    #[cfg(target_os = "linux")]
    if mark {
        return marked_dns::resolve_marked(host, port).await;
    }
    let _ = mark;
    Ok(tokio::net::lookup_host((host, port)).await?.collect())
}

/// A minimal DNS resolver that queries over a MARKED UDP socket, so name
/// resolution passes the same strict `meta mark` firewall guard as the marked TCP
/// connect (no `getaddrinfo`, whose libc-internal sockets cannot be marked and
/// would be dropped by the guard). Linux only; fail-closed.
///
/// It sends a single A-record query per nameserver and parses the answer. It does
/// NOT follow CNAMEs itself: a recursive resolver returns the target's A records
/// alongside any CNAME, and it extracts those. A spoofed or malformed answer only
/// yields a wrong/empty address, which then fails TLS (the cert is verified
/// against the requested host name), so DNS is not a trust boundary here. IPv4
/// only (the Warren API is dual-stacked with A records).
#[cfg(target_os = "linux")]
mod marked_dns {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    const DNS_TIMEOUT: Duration = Duration::from_secs(3);
    /// systemd-resolved writes the REAL upstream nameservers here; `/etc/resolv.conf`
    /// on such systems is only the `127.0.0.53` stub, whose OWN upstream query is
    /// unmarked and would be dropped by the guard, so the real upstreams are
    /// preferred and loopback stubs are skipped.
    const RESOLV_PATHS: [&str; 2] = ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"];

    /// Resolves `host` to `SocketAddr`s over marked UDP DNS. Fail-closed: an error
    /// if no usable nameserver answers.
    pub(super) async fn resolve_marked(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let servers = read_nameservers();
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no usable (non-loopback) nameserver for marked DNS",
            ));
        }
        // A fixed query id is safe here: the socket is connected to one
        // nameserver and TLS is the trust boundary, but validating it back still
        // rejects a stale datagram.
        let id: u16 = 0x7761;
        let query = encode_a_query(host, id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid host name"))?;
        for ns in servers {
            let Ok(ips) = query_one(ns, &query, id).await else {
                continue;
            };
            if ips.is_empty() {
                continue;
            }
            return Ok(ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect());
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "marked DNS resolution failed",
        ))
    }

    /// Sends `query` to `ns:53` over a marked UDP socket and parses the A records.
    async fn query_one(ns: IpAddr, query: &[u8], id: u16) -> io::Result<Vec<IpAddr>> {
        let domain = if ns.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let sock =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        // Mark BEFORE the first send so the firewall classifies the query.
        super::mark_socket(&sock, ns.is_ipv6())?;
        sock.set_nonblocking(true)?;
        let udp = tokio::net::UdpSocket::from_std(sock.into())?;
        udp.connect(SocketAddr::new(ns, 53)).await?;
        udp.send(query).await?;
        let mut buf = [0u8; 1232];
        let n = tokio::time::timeout(DNS_TIMEOUT, udp.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns query timed out"))??;
        Ok(parse_a_records(&buf[..n], id))
    }

    /// Reads the upstream nameservers, preferring systemd-resolved's real list
    /// over the loopback stub, and dropping loopback addresses (see [`RESOLV_PATHS`]).
    fn read_nameservers() -> Vec<IpAddr> {
        let mut out = Vec::new();
        for path in RESOLV_PATHS {
            if let Ok(text) = std::fs::read_to_string(path) {
                parse_nameservers(&text, &mut out);
                if !out.is_empty() {
                    break;
                }
            }
        }
        out
    }

    /// Collects `nameserver <ip>` lines, skipping loopback stubs and duplicates.
    fn parse_nameservers(text: &str, out: &mut Vec<IpAddr>) {
        for line in text.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("nameserver") else {
                continue;
            };
            let Ok(ip) = rest.trim().parse::<IpAddr>() else {
                continue;
            };
            if !ip.is_loopback() && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }

    /// Encodes a DNS query for the A record of `host` with query id `id`
    /// (RD=1, one question, QTYPE=A, QCLASS=IN). Returns `None` for a malformed
    /// host (empty or over-long label).
    fn encode_a_query(host: &str, id: u16) -> Option<Vec<u8>> {
        let host = host.trim_end_matches('.');
        if host.is_empty() {
            return None;
        }
        let mut q = Vec::with_capacity(host.len() + 18);
        q.extend_from_slice(&id.to_be_bytes());
        // flags 0x0100 = recursion desired; QDCOUNT=1; AN/NS/AR=0.
        q.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in host.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0); // root label
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        Some(q)
    }

    /// Parses the A records out of a DNS response, or an empty vec if the id
    /// mismatches, the RCODE is non-zero, or the message is malformed.
    fn parse_a_records(resp: &[u8], id: u16) -> Vec<IpAddr> {
        if resp.len() < 12 || u16::from_be_bytes([resp[0], resp[1]]) != id {
            return Vec::new();
        }
        if resp[3] & 0x0f != 0 {
            return Vec::new(); // RCODE != NOERROR
        }
        let qd = u16::from_be_bytes([resp[4], resp[5]]);
        let an = u16::from_be_bytes([resp[6], resp[7]]);
        let mut pos = 12;
        for _ in 0..qd {
            pos = match skip_name(resp, pos) {
                Some(p) => p + 4, // QTYPE + QCLASS
                None => return Vec::new(),
            };
            if pos > resp.len() {
                return Vec::new();
            }
        }
        let mut ips = Vec::new();
        for _ in 0..an {
            pos = match skip_name(resp, pos) {
                Some(p) => p,
                None => break,
            };
            if pos + 10 > resp.len() {
                break;
            }
            let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
            let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
            pos += 10;
            if pos + rdlen > resp.len() {
                break;
            }
            if rtype == 1 && rdlen == 4 {
                ips.push(IpAddr::V4(Ipv4Addr::new(
                    resp[pos],
                    resp[pos + 1],
                    resp[pos + 2],
                    resp[pos + 3],
                )));
            }
            pos += rdlen;
        }
        ips
    }

    /// Advances past a DNS name at `pos`, returning the offset just after it.
    /// Handles a compression pointer (top two bits set): the name ends there, so
    /// the two pointer bytes are skipped without following it (we only need to
    /// reach the fixed RR fields, never the pointed-to name).
    fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
        loop {
            let len = *buf.get(pos)?;
            if len & 0xC0 == 0xC0 {
                buf.get(pos + 1)?; // the pointer is two bytes
                return Some(pos + 2);
            }
            if len == 0 {
                return Some(pos + 1);
            }
            pos += 1 + len as usize;
            if pos > buf.len() {
                return None;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn encodes_an_a_query_in_wire_form() {
            let q = encode_a_query("api.warrenbrowse.com", 0x7761).expect("encodes");
            // header: id + RD flag + QDCOUNT=1
            assert_eq!(&q[0..6], &[0x77, 0x61, 0x01, 0x00, 0x00, 0x01]);
            // QNAME labels: 3 "api" 12 "warrenbrowse" 3 "com" 0
            assert_eq!(q[12], 3);
            assert_eq!(&q[13..16], b"api");
            assert_eq!(q[16], 12);
            assert_eq!(&q[17..29], b"warrenbrowse");
            assert_eq!(q[29], 3);
            assert_eq!(&q[30..33], b"com");
            assert_eq!(q[33], 0);
            // QTYPE=A, QCLASS=IN
            assert_eq!(&q[34..38], &[0x00, 0x01, 0x00, 0x01]);
        }

        #[test]
        fn rejects_a_malformed_host() {
            assert!(encode_a_query("", 1).is_none());
            assert!(encode_a_query("a..b", 1).is_none());
            let too_long = "x".repeat(64);
            assert!(encode_a_query(&too_long, 1).is_none());
        }

        /// Builds a response echoing the question then one CNAME and two A
        /// answers, the CNAME using a compression pointer, to exercise the name
        /// skip and the "extract A, ignore CNAME" behaviour.
        fn response_with_cname_and_two_a(id: u16) -> Vec<u8> {
            let mut r = Vec::new();
            r.extend_from_slice(&id.to_be_bytes());
            r.extend_from_slice(&[0x81, 0x80]); // response, RD+RA, RCODE 0
            r.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
            r.extend_from_slice(&[0x00, 0x03]); // ANCOUNT = 3 (CNAME + 2 A)
            r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            // Question: host.test A IN
            let qname_at = r.len();
            r.push(4);
            r.extend_from_slice(b"host");
            r.push(4);
            r.extend_from_slice(b"test");
            r.push(0);
            r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
            // Answer 1: CNAME, name = pointer to the question name
            r.extend_from_slice(&[0xC0, qname_at as u8]);
            r.extend_from_slice(&[0x00, 0x05, 0x00, 0x01]); // TYPE=CNAME, CLASS=IN
            r.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL
            let cname = [3u8, b'c', b'd', b'n', 0];
            r.extend_from_slice(&(cname.len() as u16).to_be_bytes());
            r.extend_from_slice(&cname);
            // Answer 2 + 3: A records, name = pointer, RDATA v4
            for octet in [10u8, 20u8] {
                r.extend_from_slice(&[0xC0, qname_at as u8]);
                r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE=A, CLASS=IN
                r.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
                r.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
                r.extend_from_slice(&[octet, 0, 0, 1]);
            }
            r
        }

        #[test]
        fn parses_a_records_and_ignores_cname_with_compression() {
            let resp = response_with_cname_and_two_a(0x7761);
            let ips = parse_a_records(&resp, 0x7761);
            assert_eq!(
                ips,
                vec![
                    "10.0.0.1".parse::<IpAddr>().unwrap(),
                    "20.0.0.1".parse::<IpAddr>().unwrap()
                ],
                "both A records extracted, the CNAME skipped over its pointer"
            );
        }

        #[test]
        fn rejects_a_response_with_a_mismatched_id_or_rcode() {
            let resp = response_with_cname_and_two_a(0x7761);
            assert!(
                parse_a_records(&resp, 0x1234).is_empty(),
                "a wrong id must yield nothing"
            );
            let mut servfail = resp.clone();
            servfail[3] = 0x82; // RCODE 2 (SERVFAIL)
            assert!(
                parse_a_records(&servfail, 0x7761).is_empty(),
                "a non-zero RCODE must yield nothing"
            );
        }

        #[test]
        fn reads_nameservers_preferring_real_upstreams_over_loopback_stubs() {
            let mut out = Vec::new();
            parse_nameservers(
                "# comment\nnameserver 127.0.0.53\nnameserver 9.9.9.9\nnameserver 9.9.9.9\n",
                &mut out,
            );
            assert_eq!(
                out,
                vec!["9.9.9.9".parse::<IpAddr>().unwrap()],
                "the loopback stub is skipped and duplicates deduped"
            );
        }
    }
}

fn to_http_method(method: Method) -> http::Method {
    match method {
        Method::Get => http::Method::GET,
        Method::Post => http::Method::POST,
        Method::Delete => http::Method::DELETE,
    }
}

/// Maps an io error at the connect stage to a [`TransportError::Connect`] so the
/// [`WarrenApiClient`](crate::WarrenApiClient) host fallback advances, and
/// everything else to a generic [`TransportError::Io`]. No address is included
/// (no-log discipline).
fn connect_error() -> TransportError {
    TransportError::Connect("connection failed".to_owned())
}

impl HttpTransport for MarkedTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let total = TOTAL_TIMEOUT;
        tokio::time::timeout(total, self.send(request))
            .await
            .map_err(|_| TransportError::Io("request timed out".to_owned()))?
    }
}

impl MarkedTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let uri: http::Uri = request
            .url
            .parse()
            .map_err(|_| TransportError::Io("invalid request url".to_owned()))?;
        let host = uri
            .host()
            .ok_or_else(|| TransportError::Io("request url has no host".to_owned()))?
            .to_owned();
        let port = uri.port_u16().unwrap_or(443);

        // Resolve + connect + TLS under the connect deadline. When marking is on
        // (the daemon under a strict `meta mark` guard), resolution ALSO goes over
        // a marked socket, so the whole fetch (DNS + connect) passes the guard with
        // no firewall hole; otherwise the system resolver is used. Each resolved
        // address is tried until one connects.
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, async {
            let addrs = resolve(&host, port, self.mark_sockets)
                .await
                .map_err(|_| connect_error())?;
            let mut last = connect_error();
            for addr in addrs {
                match connect_marked(addr, self.mark_sockets).await {
                    Ok(stream) => return Ok(stream),
                    Err(_) => last = connect_error(),
                }
            }
            Err(last)
        })
        .await
        .map_err(|_| connect_error())??;

        let server_name = ServerName::try_from(host.clone())
            .map_err(|_| TransportError::Io("invalid server name".to_owned()))?;
        let connector = TlsConnector::from(self.tls_config(request.use_sni));
        let tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|_| connect_error())?;

        let (mut sender, conn) = http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| TransportError::Io("http handshake failed".to_owned()))?;
        // The connection future must be driven for the request/response to make
        // progress; it ends when `sender` is dropped after the body is read.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // HTTP/1.1 origin-form: request target is the path, Host carries the
        // authority (default 443 omitted).
        let authority = if port == 443 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let path = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .to_owned();
        let mut builder = http::Request::builder()
            .method(to_http_method(request.method))
            .uri(path)
            .header(http::header::HOST, authority);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let hyper_request = builder
            .body(Full::new(Bytes::from(request.body)))
            .map_err(|_| TransportError::Io("request build failed".to_owned()))?;

        let response = sender
            .send_request(hyper_request)
            .await
            .map_err(|_| TransportError::Io("request failed".to_owned()))?;
        let status = response.status().as_u16();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|_| TransportError::Io("response read failed".to_owned()))?
            .to_bytes()
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_both_marked_and_unmarked_transports() {
        // The rustls configs must build with a working ring provider on either
        // constructor; this also covers the SNI/no-SNI config split.
        let marked = MarkedTransport::marked().expect("marked builds");
        assert!(marked.mark_sockets, "marked() must tag its sockets");
        assert!(marked.sni.enable_sni, "the primary config sends SNI");
        assert!(
            !marked.no_sni.enable_sni,
            "the fallback config withholds SNI"
        );

        let unmarked = MarkedTransport::unmarked().expect("unmarked builds");
        assert!(
            !unmarked.mark_sockets,
            "unmarked() must not tag its sockets"
        );
    }

    #[test]
    fn methods_map_to_their_http_equivalents() {
        assert_eq!(to_http_method(Method::Get), http::Method::GET);
        assert_eq!(to_http_method(Method::Post), http::Method::POST);
        assert_eq!(to_http_method(Method::Delete), http::Method::DELETE);
    }

    // The socket mark is the security-critical unit. `SO_MARK` needs
    // `CAP_NET_ADMIN`: privileged it is set and read back exactly, unprivileged
    // the syscall is REACHED and returns EPERM. Either way it is never a silent
    // no-op, and privileged it carries EXACTLY the Warren tunnel fwmark the guard
    // permits.
    // EPERM without CAP_NET_ADMIN. Matched by name (no libc dep: the workspace
    // forbids unsafe, and socket2 reads the mark back safely).
    #[cfg(target_os = "linux")]
    const EPERM: i32 = 1;

    #[cfg(target_os = "linux")]
    #[test]
    fn marked_socket_carries_the_warren_fwmark_or_reaches_the_syscall() {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .expect("v4 stream socket");

        match mark_socket(&socket, false) {
            Ok(()) => {
                // socket2's safe getsockopt(SO_MARK): the mark must be EXACTLY the
                // Warren tunnel fwmark the firewall guard permits, not merely set.
                let read_back = socket.mark().expect("read SO_MARK back");
                assert_eq!(
                    read_back, WARREN_TUNNEL_FWMARK,
                    "a marked control-plane socket must carry exactly the Warren \
                     tunnel fwmark the firewall guard permits"
                );
            }
            Err(e) => assert_eq!(
                e.raw_os_error(),
                Some(EPERM),
                "the only expected failure is EPERM (missing CAP_NET_ADMIN); got {e:?}"
            ),
        }
    }

    #[tokio::test]
    async fn execute_classifies_a_refused_connection_as_a_connect_error() {
        // Port 1 on loopback refuses immediately: drives the real resolve +
        // connect path and the connect-error classification that triggers host
        // fallback. Unmarked so the test is deterministic without CAP_NET_ADMIN.
        // The error must NOT leak the address (no-log discipline).
        let transport = MarkedTransport::unmarked().expect("unmarked builds");
        let request = HttpRequest {
            method: Method::Get,
            url: "https://127.0.0.1:1/".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
            use_sni: true,
        };
        let err = transport.execute(request).await.unwrap_err();
        match err {
            TransportError::Connect(msg) => {
                assert!(!msg.contains("127.0.0.1"), "must not leak the address");
            }
            other => panic!("expected a Connect error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_uses_the_no_sni_config_when_sni_is_disabled() {
        // The SNI-less fallback path must also reach the connect stage; a refused
        // connection through it still classifies as a connect error.
        let transport = MarkedTransport::unmarked().expect("unmarked builds");
        let request = HttpRequest {
            method: Method::Post,
            url: "https://127.0.0.1:1/".to_owned(),
            headers: vec![("x-test".to_owned(), "1".to_owned())],
            body: b"body".to_vec(),
            use_sni: false,
        };
        let err = transport.execute(request).await.unwrap_err();
        assert!(matches!(err, TransportError::Connect(_)), "got {err:?}");
    }
}
