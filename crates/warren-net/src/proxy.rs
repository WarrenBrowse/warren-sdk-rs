//! Local SOCKS5 proxy server for the non-root datapath.
//!
//! The server terminates application TCP flows locally and hands each one to a
//! [`Connector`], the seam to the outside world. In production the connector
//! drives a userspace netstack over the QUIC tunnel (so the exit, never the
//! local resolver, sees the destination); tests use a direct connector. Keeping
//! the connector abstract is what lets the whole accept/handshake/relay loop be
//! tested in-process without a tunnel.
//!
//! Both servers authenticate every client against the session's
//! [`ProxyCredentials`] before the connector is touched; see
//! [`crate::proxy_auth`] for why a loopback listener needs it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zeroize::Zeroizing;

use crate::error::NetError;
use crate::http_forward;
use crate::proxy_auth::{
    HTTP_PROOF_HEADER, HTTP_PROOF_METHOD, ListenerKind, PROOF_NONCE_LEN, ProxyCredentials,
};
use crate::socks5::{
    Command, METHOD_NONE, METHOD_USERPASS, METHOD_WARREN_PROOF, Reply, Socks5Error, Target,
    USERPASS_VERSION, build_method_reply, build_reply, encode_udp_datagram, parse_greeting,
    parse_request, parse_udp_datagram,
};

/// How long a client has to authenticate and say what it wants. A client that
/// connects and stays silent would otherwise hold a descriptor as long as it
/// likes, and enough of them starve the process of descriptors.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Pause before accepting again after a transient accept failure.
const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// Accepts the next connection. Running out of descriptors, or a connection
/// aborted before it was accepted, is a condition of this moment and not of the
/// listener: it is waited out, because returning it ends the datapath's epoch
/// and redials a healthy tunnel.
async fn accept(listener: &TcpListener) -> Result<TcpStream, NetError> {
    loop {
        match listener.accept().await {
            Ok((client, _peer)) => return Ok(client),
            Err(e) if is_transient_accept_error(&e) => tokio::time::sleep(ACCEPT_BACKOFF).await,
            Err(e) => return Err(NetError::Io(e)),
        }
    }
}

/// Whether an accept failure passes on its own: an aborted or reset pending
/// connection, an interrupted call, or descriptor exhaustion (EMFILE and ENFILE
/// on Unix, WSAEMFILE on Windows).
fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    let exhausted = match e.raw_os_error() {
        Some(code) if cfg!(windows) => code == 10024,
        Some(code) => code == 24 || code == 23,
        None => false,
    };
    exhausted
        || matches!(
            e.kind(),
            ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::Interrupted
        )
}

/// Runs a client's handshake under [`HANDSHAKE_TIMEOUT`]; running out of time
/// refuses the client like a wrong password.
async fn within_handshake<T>(
    handshake: impl std::future::Future<Output = Result<T, NetError>>,
) -> Result<T, NetError> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| NetError::ProxyAuth)?
}

/// Runs one accepted connection of an `..._until` loop until it ends or `run`
/// goes `false` (or its sender is dropped). A relay still open when its loop
/// stops rides a path that is going away, a dead tunnel or a system tunnel that
/// disconnected: dropping it closes both sockets at once, so the client reopens
/// on the new path instead of waiting on a dead connection until it times out.
async fn until_stopped(
    mut run: tokio::sync::watch::Receiver<bool>,
    connection: impl std::future::Future<Output = ()>,
) {
    tokio::select! {
        () = connection => {}
        () = stopped(&mut run) => {}
    }
}

/// Resolves once `run` goes `false` or its sender is dropped.
async fn stopped(run: &mut tokio::sync::watch::Receiver<bool>) {
    while *run.borrow_and_update() {
        if run.changed().await.is_err() {
            return;
        }
    }
}

/// How long a request whose path went away before it was answered waits for
/// the next path. A browser gives a proxy about this long before it shows an
/// error of its own; past it the request is refused as a dead tunnel always was.
pub const HANDOVER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

/// Requests accepted on the stable listeners whose path went away before they
/// were answered, kept for the next path.
///
/// A path (an epoch of the proxy's own tunnel, or the host route while the
/// proxy stands aside) serves the listeners for a while, then is given up. A
/// request it had accepted but not yet answered has sent nothing to its target,
/// so it belongs to no path: dropping it with its path showed the member an
/// error for a request any later path would have carried. That was every page
/// opened in the second the Warren app connected, while the proxy's own tunnel
/// was already walled by the app's kill switch and not yet given up. Every
/// server of the same listeners shares one `Handover` and takes up what it holds,
/// each through its own connector. A request that has started relaying stays
/// bound to its path and closes with it.
#[derive(Clone)]
pub struct Handover {
    inner: Arc<HandoverInner>,
}

struct HandoverInner {
    queue: std::sync::Mutex<std::collections::VecDeque<Pending>>,
    ready: tokio::sync::Notify,
    deadline: std::time::Duration,
}

impl std::fmt::Debug for Handover {
    // Never the targets: a waiting request is a destination.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handover")
            .field("waiting", &self.len())
            .finish()
    }
}

impl Default for Handover {
    fn default() -> Self {
        Self::new()
    }
}

impl Handover {
    /// A handover whose requests wait up to [`HANDOVER_DEADLINE`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_deadline(HANDOVER_DEADLINE)
    }

    /// A handover whose requests wait up to `deadline` from when they were read.
    #[must_use]
    pub fn with_deadline(deadline: std::time::Duration) -> Self {
        Self {
            inner: Arc::new(HandoverInner {
                queue: std::sync::Mutex::new(std::collections::VecDeque::new()),
                ready: tokio::sync::Notify::new(),
                deadline,
            }),
        }
    }

    /// How many requests are waiting for a path.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue().len()
    }

    /// Whether no request is waiting for a path.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn queue(&self) -> std::sync::MutexGuard<'_, std::collections::VecDeque<Pending>> {
        // A poisoned lock only means a holder panicked between two plain
        // queue operations, which leave the queue consistent.
        self.inner
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn expiry_from_now(&self) -> tokio::time::Instant {
        tokio::time::Instant::now() + self.inner.deadline
    }

    /// Keeps `pending` for the next path, or refuses it if its time is up.
    fn hold(&self, pending: Pending) {
        let expires = pending.expires;
        if expires <= tokio::time::Instant::now() {
            tokio::spawn(pending.refuse(NetError::EngineStopped));
            return;
        }
        self.queue().push_back(pending);
        self.inner.ready.notify_one();
        let handover = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep_until(expires).await;
            handover.refuse_expired();
        });
    }

    fn refuse_expired(&self) {
        let now = tokio::time::Instant::now();
        let expired: std::collections::VecDeque<Pending> = {
            let mut queue = self.queue();
            let (expired, kept) = std::mem::take(&mut *queue)
                .into_iter()
                .partition(|p: &Pending| p.expires <= now);
            *queue = kept;
            expired
        };
        for pending in expired {
            tokio::spawn(pending.refuse(NetError::EngineStopped));
        }
    }

    /// The next waiting request still within its deadline.
    async fn take(&self) -> Pending {
        loop {
            let notified = self.inner.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let next = {
                let mut queue = self.queue();
                let next = queue.pop_front();
                if !queue.is_empty() {
                    // Another server of the same listeners may be waiting too.
                    self.inner.ready.notify_one();
                }
                next
            };
            match next {
                Some(p) if p.expires > tokio::time::Instant::now() => return p,
                Some(p) => {
                    tokio::spawn(p.refuse(NetError::EngineStopped));
                }
                None => notified.await,
            }
        }
    }
}

/// What an accepted client asked for, read and authorized, not yet answered.
enum Request {
    Socks(Target),
    Connect {
        target: Target,
        early_data: Zeroizing<Vec<u8>>,
    },
    Forward {
        request: http_forward::ForwardRequest,
        early_data: Zeroizing<Vec<u8>>,
    },
}

impl Request {
    fn target(&self) -> Target {
        match self {
            Self::Socks(target) | Self::Connect { target, .. } => target.clone(),
            Self::Forward { request, .. } => request.target(),
        }
    }
}

/// A client whose request no path has answered yet.
struct Pending {
    client: TcpStream,
    request: Request,
    /// When the member stops being served better by waiting than by an error.
    expires: tokio::time::Instant,
}

impl Pending {
    /// Answers the client the way its protocol reports a CONNECT this proxy
    /// could not carry.
    async fn refuse(mut self, err: NetError) {
        let _ = match self.request {
            Request::Socks(_) => write_reply(&mut self.client, connect_failure_reply(&err)).await,
            Request::Connect { .. } | Request::Forward { .. } => self
                .client
                .write_all(&connect_failure_response(&err))
                .await
                .map_err(NetError::Io),
        };
    }
}

/// The path a request is served on: the signal that gives it up, and where a
/// request it could not answer goes. Neither for a plain `serve` loop.
#[derive(Default)]
struct PathScope {
    stop: Option<tokio::sync::watch::Receiver<bool>>,
    handover: Option<Handover>,
}

impl PathScope {
    fn new(stop: tokio::sync::watch::Receiver<bool>, handover: Option<Handover>) -> Self {
        Self {
            stop: Some(stop),
            handover,
        }
    }

    fn pending(&self, client: TcpStream, request: Request) -> Pending {
        let expires = self
            .handover
            .as_ref()
            .map_or_else(tokio::time::Instant::now, Handover::expiry_from_now);
        Pending {
            client,
            request,
            expires,
        }
    }
}

/// How a dial ended.
enum Dial<S> {
    Up(S),
    /// The path went away, or was given up, before the dial finished: the
    /// target is not to blame, and another path may carry the request.
    PathGone,
    /// The target (or its name) could not be reached over a working path.
    Failed(NetError),
}

async fn dial<C: Connector>(
    connector: &C,
    target: Target,
    stop: Option<&mut tokio::sync::watch::Receiver<bool>>,
) -> Dial<C::Stream> {
    let outcome = |dialed: Result<C::Stream, NetError>| match dialed {
        Ok(stream) => Dial::Up(stream),
        Err(NetError::EngineStopped) => Dial::PathGone,
        Err(e) => Dial::Failed(e),
    };
    let Some(stop) = stop else {
        return outcome(connector.connect(target).await);
    };
    if !*stop.borrow_and_update() {
        return Dial::PathGone;
    }
    tokio::select! {
        biased;
        () = stopped(stop) => Dial::PathGone,
        dialed = connector.connect(target) => outcome(dialed),
    }
}

/// Answers one request over `connector`: dials its target, replies, and relays
/// until either side closes or the path is given up. A request whose path goes
/// away before it is answered is handed over to the next path when the scope
/// has a [`Handover`], and refused otherwise.
async fn answer<C: Connector>(pending: Pending, connector: &C, mut scope: PathScope) {
    let Pending {
        mut client,
        request,
        expires,
    } = pending;
    let upstream = match dial(connector, request.target(), scope.stop.as_mut()).await {
        Dial::Up(upstream) => upstream,
        Dial::PathGone => {
            let pending = Pending {
                client,
                request,
                expires,
            };
            match &scope.handover {
                Some(handover) => handover.hold(pending),
                None => pending.refuse(NetError::EngineStopped).await,
            }
            return;
        }
        Dial::Failed(e) => {
            Pending {
                client,
                request,
                expires,
            }
            .refuse(e)
            .await;
            return;
        }
    };
    let relay = async move {
        let _ = relay(&mut client, upstream, request).await;
    };
    match scope.stop {
        Some(stop) => until_stopped(stop, relay).await,
        None => relay.await,
    }
}

/// Tells the client its request is carried, then relays bytes both ways.
async fn relay<S>(client: &mut TcpStream, mut upstream: S, request: Request) -> Result<(), NetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match request {
        Request::Socks(_) => {
            write_reply(client, Reply::Succeeded).await?;
        }
        Request::Connect { early_data, .. } => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .map_err(NetError::Io)?;
            // A pipelining client may have sent tunnel bytes right after the
            // head; they were read while scanning for the terminator, so
            // forward them before the bidirectional copy takes over.
            if !early_data.is_empty() {
                upstream
                    .write_all(&early_data)
                    .await
                    .map_err(NetError::Io)?;
            }
        }
        Request::Forward {
            request,
            early_data,
        } => return http_forward::forward(client, &early_data, upstream, request).await,
    }
    tokio::io::copy_bidirectional(client, &mut upstream)
        .await
        .map_err(NetError::Io)?;
    Ok(())
}

/// The next request handed over by a path that went away, or never when this
/// server takes none.
async fn handed_over(handover: Option<&Handover>) -> Pending {
    match handover {
        Some(handover) => handover.take().await,
        None => std::future::pending().await,
    }
}

/// The SOCKS5 greeting, authentication and request. `None` when the client
/// only asked for a proof, which it has been given.
async fn socks_handshake(
    client: &mut TcpStream,
    credentials: &ProxyCredentials,
) -> Result<Option<(Command, Target)>, NetError> {
    if negotiate_method(client, credentials).await? == Negotiated::Proved {
        return Ok(None);
    }
    read_request(client).await.map(Some)
}

/// The unspecified bound address echoed in a successful SOCKS5 reply. A CONNECT
/// reply does not need a meaningful bound address.
const REPLY_BOUND: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// Opens a byte stream to a SOCKS5 [`Target`].
///
/// This is the boundary between the proxy front end and the network. The tunnel
/// connector (userspace netstack over the QUIC datagram plane) implements this;
/// [`DirectConnector`] implements it with the local OS stack for tests and a
/// plain non-tunnel mode.
pub trait Connector: Send + Sync + 'static {
    /// The bidirectional stream to the target.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Connects to `target`, returning the stream or a [`NetError`].
    ///
    /// # Errors
    ///
    /// A [`NetError`] when the connection cannot be established (refused, timed
    /// out, name resolution failed, or the tunnel/engine is gone).
    fn connect(
        &self,
        target: Target,
    ) -> impl std::future::Future<Output = Result<Self::Stream, NetError>> + Send;
}

/// A UDP datagram flow to the outside world, backing SOCKS5 UDP associate. The
/// tunnel netstack implements it so datagrams egress at the exit.
pub trait UdpFlow: Send + 'static {
    /// Sends `data` to `dst` through the flow (lossy, like UDP).
    ///
    /// # Errors
    ///
    /// [`NetError::EngineStopped`] if the netstack engine has gone; transient
    /// per-datagram drops are silent (lossy by design), not errors.
    fn send_to(
        &self,
        data: Bytes,
        dst: SocketAddr,
    ) -> impl std::future::Future<Output = Result<(), NetError>> + Send;

    /// Receives the next datagram and its source, or `None` when the flow ends.
    fn recv_from(
        &mut self,
    ) -> impl std::future::Future<Output = Option<(Bytes, SocketAddr)>> + Send;
}

/// A [`Connector`] that can also open UDP flows and resolve names over the same
/// path, so a UDP target given as a name is resolved at the exit (no DNS leak).
pub trait UdpConnector: Connector {
    /// The UDP flow type opened by [`open_udp`](Self::open_udp).
    type Flow: UdpFlow;

    /// Opens a UDP flow (an ephemeral egress port) for a UDP association.
    ///
    /// # Errors
    ///
    /// [`NetError::EngineStopped`] if the netstack engine has stopped.
    fn open_udp(&self) -> impl std::future::Future<Output = Result<Self::Flow, NetError>> + Send;

    /// Resolves `host` to an address through the same path as the data plane.
    ///
    /// # Errors
    ///
    /// A [`NetError`] when resolution fails (no record, timeout, or the engine is
    /// gone).
    fn resolve_host(
        &self,
        host: &str,
    ) -> impl std::future::Future<Output = Result<IpAddr, NetError>> + Send;

    /// Whether IPv6 targets are routable (the engine has a v6 assignment). UDP
    /// associate refuses v6 datagrams when this is false, rather than sending
    /// them into a v6 black hole.
    fn supports_ipv6(&self) -> bool;
}

/// A [`Connector`] that dials the target with the local OS TCP stack.
///
/// Resolves and connects locally, so it does NOT use the tunnel and leaks DNS to
/// the host resolver: it exists for tests and an explicit non-tunnel mode, not
/// for the privacy datapath.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectConnector;

impl Connector for DirectConnector {
    type Stream = TcpStream;

    async fn connect(&self, target: Target) -> Result<Self::Stream, NetError> {
        let stream = match target {
            Target::Ip(addr) => TcpStream::connect(addr).await,
            Target::Domain(host, port) => TcpStream::connect((host.as_str(), port)).await,
        };
        stream.map_err(NetError::Io)
    }
}

/// A SOCKS5 proxy server over a [`Connector`], admitting only clients that
/// authenticate with the session's credentials (RFC 1929).
pub struct Socks5Proxy<C> {
    connector: Arc<C>,
    credentials: Arc<ProxyCredentials>,
    handover: Option<Handover>,
}

impl<C: Connector> Socks5Proxy<C> {
    /// Builds a proxy that opens upstream flows through `connector` for clients
    /// presenting `credentials`.
    pub fn new(connector: C, credentials: ProxyCredentials) -> Self {
        Self {
            connector: Arc::new(connector),
            credentials: Arc::new(credentials),
            handover: None,
        }
    }

    /// Shares `handover` with the other servers of the same listeners: in its
    /// `..._until` loops, a `CONNECT` whose path is given up before it is
    /// answered waits there for the next path instead of failing, and this
    /// server takes up what the others hand over. See [`Handover`].
    #[must_use]
    pub fn with_handover(mut self, handover: Handover) -> Self {
        self.handover = Some(handover);
        self
    }

    /// Accepts connections on `listener` until it errors, handling each on its
    /// own task. Per-connection failures are isolated and never surface raw
    /// addresses to a log (no-log discipline).
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] only if accepting on the listener fails.
    pub async fn serve(&self, listener: TcpListener) -> Result<(), NetError> {
        loop {
            let client = accept(&listener).await?;
            let connector = Arc::clone(&self.connector);
            let credentials = Arc::clone(&self.credentials);
            tokio::spawn(async move {
                handle_connection(
                    client,
                    connector.as_ref(),
                    &credentials,
                    PathScope::default(),
                )
                .await;
            });
        }
    }

    /// Like [`serve`](Self::serve) but accepts on a *borrowed* listener until
    /// `run` goes `false`, for a connector that carries no UDP: `UDP ASSOCIATE`
    /// is refused as unsupported. `run` starting `false` (or its sender dropped)
    /// returns at once.
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] only if accepting on the listener fails.
    pub async fn serve_until(
        &self,
        listener: &TcpListener,
        mut run: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), NetError> {
        loop {
            if !*run.borrow_and_update() {
                return Ok(());
            }
            tokio::select! {
                biased;
                changed = run.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                }
                pending = handed_over(self.handover.as_ref()) => {
                    let connector = Arc::clone(&self.connector);
                    let scope = PathScope::new(run.clone(), self.handover.clone());
                    tokio::spawn(async move { answer(pending, connector.as_ref(), scope).await });
                }
                accepted = accept(listener) => {
                    let client = accepted?;
                    let connector = Arc::clone(&self.connector);
                    let credentials = Arc::clone(&self.credentials);
                    let scope = PathScope::new(run.clone(), self.handover.clone());
                    tokio::spawn(async move {
                        handle_connection(client, connector.as_ref(), &credentials, scope).await;
                    });
                }
            }
        }
    }
}

/// Drives one client through the SOCKS5 handshake, then answers its `CONNECT`.
async fn handle_connection<C: Connector>(
    mut client: TcpStream,
    connector: &C,
    credentials: &ProxyCredentials,
    scope: PathScope,
) {
    let Ok(Some((command, target))) =
        within_handshake(socks_handshake(&mut client, credentials)).await
    else {
        return;
    };
    if !command.is_supported() {
        let _ = write_reply(&mut client, Reply::CommandNotSupported).await;
        return;
    }
    let pending = scope.pending(client, Request::Socks(target));
    answer(pending, connector, scope).await;
}

impl<C: UdpConnector> Socks5Proxy<C> {
    /// Like [`serve`](Self::serve) but also handles `UDP ASSOCIATE`: it binds a
    /// local UDP relay, opens a UDP flow through the connector, and relays
    /// datagrams both ways for the lifetime of the control connection. `CONNECT`
    /// is handled exactly as in [`serve`](Self::serve).
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] only if accepting on the listener fails.
    pub async fn serve_with_udp(&self, listener: TcpListener) -> Result<(), NetError> {
        loop {
            let client = accept(&listener).await?;
            let connector = Arc::clone(&self.connector);
            let credentials = Arc::clone(&self.credentials);
            tokio::spawn(async move {
                handle_with_udp(
                    client,
                    connector.as_ref(),
                    &credentials,
                    PathScope::default(),
                )
                .await;
            });
        }
    }

    /// Like [`serve_with_udp`](Self::serve_with_udp) but accepts on a *borrowed*
    /// listener until `run` goes `false`, then returns. The borrowed listener
    /// lets a supervisor reuse one stable local address across tunnel rebuilds:
    /// each reconnect builds a fresh connector and a new proxy over the same
    /// bound port. `run` starting `false` (or its sender dropped) returns at once.
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] only if accepting on the listener fails.
    pub async fn serve_with_udp_until(
        &self,
        listener: &TcpListener,
        mut run: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), NetError> {
        loop {
            if !*run.borrow_and_update() {
                return Ok(());
            }
            tokio::select! {
                // Prefer the stop signal so a torn-down tunnel halts accepting promptly.
                biased;
                changed = run.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                }
                pending = handed_over(self.handover.as_ref()) => {
                    let connector = Arc::clone(&self.connector);
                    let scope = PathScope::new(run.clone(), self.handover.clone());
                    tokio::spawn(async move { answer(pending, connector.as_ref(), scope).await });
                }
                accepted = accept(listener) => {
                    let client = accepted?;
                    let connector = Arc::clone(&self.connector);
                    let credentials = Arc::clone(&self.credentials);
                    let scope = PathScope::new(run.clone(), self.handover.clone());
                    tokio::spawn(async move {
                        handle_with_udp(client, connector.as_ref(), &credentials, scope).await;
                    });
                }
            }
        }
    }
}

/// SOCKS5 handler that supports `CONNECT` and `UDP ASSOCIATE`. An association
/// lives and dies with its path: its datagrams have no single request to hand
/// over, and the client reopens it on the next one.
async fn handle_with_udp<C: UdpConnector>(
    mut client: TcpStream,
    connector: &C,
    credentials: &ProxyCredentials,
    scope: PathScope,
) {
    let Ok(Some((command, target))) =
        within_handshake(socks_handshake(&mut client, credentials)).await
    else {
        return;
    };
    match command {
        Command::Connect => {
            let pending = scope.pending(client, Request::Socks(target));
            answer(pending, connector, scope).await;
        }
        Command::UdpAssociate => {
            let association = async move {
                let _ = udp_associate(client, connector, &target).await;
            };
            match scope.stop {
                Some(stop) => until_stopped(stop, association).await,
                None => association.await,
            }
        }
        Command::Bind => {
            let _ = write_reply(&mut client, Reply::CommandNotSupported).await;
        }
    }
}

/// Largest UDP datagram (header + payload) the relay buffers.
const MAX_UDP_DATAGRAM: usize = 64 * 1024;

/// Runs one UDP association: bind a loopback relay socket, reply with its
/// address, then relay datagrams between the client and the tunnel flow until
/// the TCP control connection closes (which ends the association, per RFC 1928).
async fn udp_associate<C: UdpConnector>(
    mut client: TcpStream,
    connector: &C,
    declared: &Target,
) -> Result<(), NetError> {
    // The relay port is visible to every local process, and only the TCP
    // control connection is authenticated. A client that declared where it
    // will send from (RFC 1928 section 6) is held to it; one that declared
    // nothing is bound to its first well-formed datagram.
    let declared = match declared {
        Target::Ip(addr) if addr.port() != 0 => Some(*addr),
        _ => None,
    };
    // The client sends its datagrams to this loopback relay socket; the BND
    // address in the reply tells it where.
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(NetError::Io)?;
    let relay_addr = relay.local_addr().map_err(NetError::Io)?;
    client
        .write_all(&build_reply(Reply::Succeeded, relay_addr))
        .await
        .map_err(NetError::Io)?;

    let mut flow = connector.open_udp().await?;

    // A single task owns the flow (recv needs `&mut`, send needs `&`), so no
    // shared state: `client_src` is the address of the most recent client
    // datagram, where replies are sent back.
    let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
    let mut ctrl = [0u8; 256];
    let mut client_src: Option<SocketAddr> = None;
    loop {
        tokio::select! {
            // Client -> tunnel: strip the SOCKS5 UDP header, resolve a name over
            // the tunnel if needed, forward the payload.
            r = relay.recv_from(&mut buf) => {
                // The relay is an unconnected loopback socket, so a recv error is
                // fatal (fd gone), not transient: ending the association is right.
                let (n, src) = r.map_err(NetError::Io)?;
                if declared.is_some_and(|d| !is_declared_source(d, src)) {
                    continue;
                }
                let Ok((target, payload)) = parse_udp_datagram(&buf[..n]) else {
                    continue;
                };
                // Bind the association to the first client source and drop
                // datagrams from any other local source: otherwise a co-resident
                // process could inject traffic and, by setting `client_src`,
                // hijack the reply stream.
                match client_src {
                    None => client_src = Some(src),
                    Some(known) if known != src => continue,
                    Some(_) => {}
                }
                let dst = match target {
                    Target::Ip(addr @ SocketAddr::V4(_)) => Some(addr),
                    // Route v6 only when the engine has a v6 assignment;
                    // otherwise drop rather than black-hole it.
                    Target::Ip(addr @ SocketAddr::V6(_)) => {
                        connector.supports_ipv6().then_some(addr)
                    }
                    Target::Domain(host, port) => connector
                        .resolve_host(&host)
                        .await
                        .ok()
                        .map(|ip| SocketAddr::new(ip, port)),
                };
                if let Some(dst) = dst {
                    let _ = flow.send_to(Bytes::copy_from_slice(payload), dst).await;
                }
            }
            // Tunnel -> client: re-wrap with the SOCKS5 UDP header and deliver to
            // the last-seen client source.
            res = flow.recv_from() => {
                match res {
                    Some((data, src)) => {
                        if let Some(dst) = client_src {
                            let _ = relay.send_to(&encode_udp_datagram(src, &data), dst).await;
                        }
                    }
                    None => return Ok(()), // flow/engine ended
                }
            }
            // The TCP control connection closing tears down the association.
            r = client.read(&mut ctrl) => {
                match r {
                    Ok(0) | Err(_) => return Ok(()),
                    Ok(_) => {} // clients normally send nothing here; ignore
                }
            }
        }
    }
}

/// How a SOCKS5 method negotiation ended without an error.
#[derive(Debug, PartialEq, Eq)]
enum Negotiated {
    /// The client authenticated: its request may be served.
    Authenticated,
    /// The client asked for a proof of possession and got it; the connection
    /// carries nothing else.
    Proved,
}

/// Whether `src` is the address a client declared for its UDP association: the
/// same port, and the same IP unless the client left it unspecified.
fn is_declared_source(declared: SocketAddr, src: SocketAddr) -> bool {
    declared.port() == src.port() && (declared.ip().is_unspecified() || declared.ip() == src.ip())
}

/// Reads the greeting, then either authenticates the client (RFC 1929) or
/// answers a proof request. A client offering neither is told no method is
/// acceptable; a client with the wrong credentials gets a failure status. Both
/// refusals are fixed bytes that say nothing about what was wrong.
async fn negotiate_method(
    client: &mut TcpStream,
    credentials: &ProxyCredentials,
) -> Result<Negotiated, NetError> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await.map_err(NetError::Io)?;
    let mut greeting = head.to_vec();
    greeting.resize(2 + head[1] as usize, 0);
    client
        .read_exact(&mut greeting[2..])
        .await
        .map_err(NetError::Io)?;

    let methods = parse_greeting(&greeting)?;
    if methods.contains(&METHOD_USERPASS) {
        write_all(client, &build_method_reply(METHOD_USERPASS)).await?;
        let accepted = read_userpass(client, credentials).await?;
        let status = if accepted { 0x00 } else { 0x01 };
        write_all(client, &[USERPASS_VERSION, status]).await?;
        return if accepted {
            Ok(Negotiated::Authenticated)
        } else {
            Err(NetError::ProxyAuth)
        };
    }
    if methods.contains(&METHOD_WARREN_PROOF) {
        write_all(client, &build_method_reply(METHOD_WARREN_PROOF)).await?;
        let mut nonce = [0u8; PROOF_NONCE_LEN];
        client.read_exact(&mut nonce).await.map_err(NetError::Io)?;
        write_all(client, &credentials.proof(ListenerKind::Socks5, &nonce)).await?;
        return Ok(Negotiated::Proved);
    }
    write_all(client, &build_method_reply(METHOD_NONE)).await?;
    Err(NetError::ProxyAuth)
}

/// Reads one RFC 1929 sub-negotiation (`VER ULEN UNAME PLEN PASSWD`) and says
/// whether it carries `credentials`. A wrong version byte is a mismatch rather
/// than a protocol error, so it earns the same refusal as a wrong password.
async fn read_userpass(
    client: &mut TcpStream,
    credentials: &ProxyCredentials,
) -> Result<bool, NetError> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await.map_err(NetError::Io)?;
    let mut username = vec![0u8; usize::from(head[1])];
    client
        .read_exact(&mut username)
        .await
        .map_err(NetError::Io)?;
    let mut plen = [0u8; 1];
    client.read_exact(&mut plen).await.map_err(NetError::Io)?;
    let mut password = Zeroizing::new(vec![0u8; usize::from(plen[0])]);
    client
        .read_exact(&mut password)
        .await
        .map_err(NetError::Io)?;
    let matched = credentials.matches(&username, &password);
    Ok(head[0] == USERPASS_VERSION && matched)
}

async fn write_all(client: &mut TcpStream, bytes: &[u8]) -> Result<(), NetError> {
    client.write_all(bytes).await.map_err(NetError::Io)
}

/// Reads exactly one SOCKS5 request, reconstructing the wire buffer for the
/// codec so the address parsing stays in one place ([`parse_request`]).
async fn read_request(client: &mut TcpStream) -> Result<(Command, Target), NetError> {
    let mut head = [0u8; 4]; // VER CMD RSV ATYP
    client.read_exact(&mut head).await.map_err(NetError::Io)?;
    let mut buf = head.to_vec();
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 4 + 2];
            client.read_exact(&mut rest).await.map_err(NetError::Io)?;
            buf.extend_from_slice(&rest);
        }
        0x04 => {
            let mut rest = [0u8; 16 + 2];
            client.read_exact(&mut rest).await.map_err(NetError::Io)?;
            buf.extend_from_slice(&rest);
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await.map_err(NetError::Io)?;
            buf.push(len[0]);
            let mut rest = vec![0u8; len[0] as usize + 2];
            client.read_exact(&mut rest).await.map_err(NetError::Io)?;
            buf.extend_from_slice(&rest);
        }
        other => return Err(NetError::Socks5(Socks5Error::BadAtyp(other))),
    }
    Ok(parse_request(&buf)?)
}

async fn write_reply(client: &mut TcpStream, reply: Reply) -> Result<(), NetError> {
    client
        .write_all(&build_reply(reply, REPLY_BOUND))
        .await
        .map_err(NetError::Io)
}

/// Largest request head (request line plus headers) accepted. A plain-HTTP
/// request carries the page's cookies, so this is sized for a browser's head
/// rather than for a bare CONNECT.
const MAX_HTTP_HEAD: usize = 32 * 1024;

/// Bytes read per call while scanning for the end of a request head.
const HEAD_CHUNK: usize = 256;

/// First capacity of the head buffer, which doubles as the head grows: a
/// connection that has not authenticated yet holds only what it sent.
const HEAD_START: usize = 1024;

/// An HTTP proxy server over a [`Connector`].
///
/// Serves `CONNECT host:port`, the tunneling verb a browser or HTTP client uses
/// for HTTPS, and plain `http://` requests in absolute form, one request per
/// connection, with `Proxy-Authorization` and the other hop-by-hop fields kept
/// off the wire to the origin. Any other request is refused. Like
/// [`Socks5Proxy`] it relays through the connector, so the same tunnel datapath
/// backs it, and it admits only requests carrying the session's credentials in
/// `Proxy-Authorization: Basic`.
pub struct HttpConnectProxy<C> {
    connector: Arc<C>,
    credentials: Arc<ProxyCredentials>,
    handover: Option<Handover>,
}

impl<C: Connector> HttpConnectProxy<C> {
    /// Builds an HTTP proxy that opens upstream flows through `connector` for
    /// requests presenting `credentials`.
    pub fn new(connector: C, credentials: ProxyCredentials) -> Self {
        Self {
            connector: Arc::new(connector),
            credentials: Arc::new(credentials),
            handover: None,
        }
    }

    /// Shares `handover` with the other servers of the same listeners, as
    /// [`Socks5Proxy::with_handover`] does.
    #[must_use]
    pub fn with_handover(mut self, handover: Handover) -> Self {
        self.handover = Some(handover);
        self
    }

    /// Accepts connections on `listener` until it errors, one task each.
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] only if accepting on the listener fails.
    pub async fn serve(&self, listener: TcpListener) -> Result<(), NetError> {
        loop {
            let client = accept(&listener).await?;
            let connector = Arc::clone(&self.connector);
            let credentials = Arc::clone(&self.credentials);
            tokio::spawn(async move {
                handle_connect(
                    client,
                    connector.as_ref(),
                    &credentials,
                    PathScope::default(),
                )
                .await;
            });
        }
    }

    /// Like [`serve`](Self::serve) but accepts on a *borrowed* listener until
    /// `run` goes `false`, so a supervisor can reuse one bound port across tunnel
    /// rebuilds. `run` starting `false` (or its sender dropped) returns at once.
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] only if accepting on the listener fails.
    pub async fn serve_until(
        &self,
        listener: &TcpListener,
        mut run: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), NetError> {
        loop {
            if !*run.borrow_and_update() {
                return Ok(());
            }
            tokio::select! {
                biased;
                changed = run.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                }
                pending = handed_over(self.handover.as_ref()) => {
                    let connector = Arc::clone(&self.connector);
                    let scope = PathScope::new(run.clone(), self.handover.clone());
                    tokio::spawn(async move { answer(pending, connector.as_ref(), scope).await });
                }
                accepted = accept(listener) => {
                    let client = accepted?;
                    let connector = Arc::clone(&self.connector);
                    let credentials = Arc::clone(&self.credentials);
                    let scope = PathScope::new(run.clone(), self.handover.clone());
                    tokio::spawn(async move {
                        handle_connect(client, connector.as_ref(), &credentials, scope).await;
                    });
                }
            }
        }
    }
}

/// Header naming which local condition refused a CONNECT, so a reader does not
/// have to parse prose to branch on it.
const TUNNEL_CAUSE_HEADER: &str = "Warren-Tunnel";

/// The SOCKS5 reply code for a CONNECT this proxy could not carry.
///
/// A reply code is a CLAIM ABOUT THE PATH, and the client acts on it: codes 5
/// and 4 arrive as ECONNREFUSED and EHOSTUNREACH, which HTTP clients treat as
/// terminal and stop retrying on. So only a condition this proxy can actually
/// source earns its own code. `EngineStopped` qualifies: there is no tunnel, and
/// "network unreachable" is precisely that.
///
/// A refused connect and a connect timeout do NOT qualify, whatever their
/// `NetError` is called. `NetError::ConnectionRefused` is raised when the
/// smoltcp socket reaches `Closed` while a connect is pending (`netstack.rs`),
/// which covers SYN exhaustion on a lossy path as much as a peer RST, and
/// `ConnectTimeout` is this proxy's own deadline. Reported as 5 and 4 they told
/// a member on a congested uplink that a firewall was blocking them, and stopped
/// their client from retrying something that would have worked. They stay
/// `GeneralFailure`; the condition still travels in
/// [`connect_failure_cause`] and the log, where it cannot change retry
/// semantics.
fn connect_failure_reply(err: &NetError) -> Reply {
    match err {
        NetError::EngineStopped => Reply::NetworkUnreachable,
        _ => Reply::GeneralFailure,
    }
}

/// Short, fixed tag for a CONNECT that never left this machine.
///
/// The set is deliberately tiny and every arm is a literal: this value reaches a
/// member's terminal and a log, so it may never carry a host, an address, a port
/// or any error text from elsewhere.
fn connect_failure_cause(err: &NetError) -> &'static str {
    match err {
        NetError::EngineStopped => "tunnel-gone",
        NetError::ConnectionRefused => "exit-refused",
        NetError::ConnectTimeout => "connect-timeout",
        _ => "connect-failed",
    }
}

/// The CONNECT response for an upstream this proxy could not reach.
///
/// A bare `502` with no body is what an API client renders as "this is a
/// server-side issue, usually temporary, check the status page", so a member
/// whose own tunnel had just been torn down was sent to diagnose an outage at
/// the other end of the world
/// (`incidents/2026-09-12-bufferbloat-fixed-probe-budget-reconnect-storm.md`
/// section 9.1). The status stays `502`, because a client's retry policy is
/// keyed on it and this failure genuinely is a gateway that could not reach
/// upstream; everything added is the answer to "whose gateway".
pub(crate) fn connect_failure_response(err: &NetError) -> Vec<u8> {
    let cause = connect_failure_cause(err);
    let body = format!(
        "warren: the local proxy has no working tunnel to reach the target ({cause}).\n\
         This is a condition of the VPN on this machine, not an outage at the target service.\n"
    );
    format!(
        "HTTP/1.1 502 Warren Tunnel Unavailable\r\n\
         {TUNNEL_CAUSE_HEADER}: {cause}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )
    .into_bytes()
}

/// The answer to a request without the session's credentials. Identical for a
/// missing and a wrong `Proxy-Authorization`, and the realm names nothing.
const PROXY_AUTH_REQUIRED: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"proxy\"\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\
\r\n";

/// The answer to a proof request for `nonce_hex`, or `None` when the argument
/// is not a nonce (the request is then refused like any other).
fn proof_response(credentials: &ProxyCredentials, nonce_hex: &str) -> Option<Vec<u8>> {
    let nonce: [u8; PROOF_NONCE_LEN] = hex::decode(nonce_hex).ok()?.try_into().ok()?;
    let proof = hex::encode(credentials.proof(ListenerKind::Http, &nonce));
    Some(
        format!(
            "HTTP/1.1 200 OK\r\n{HTTP_PROOF_HEADER}: {proof}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
    )
}

async fn handle_connect<C: Connector>(
    mut client: TcpStream,
    connector: &C,
    credentials: &ProxyCredentials,
    scope: PathScope,
) {
    let Ok(read) = within_handshake(read_request_head(&mut client)).await else {
        return;
    };
    let Some((head, early_data)) = read else {
        let _ = client
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            .await;
        return;
    };
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or("").split_whitespace();
    let method = request_line.next().unwrap_or("");
    let argument = request_line.next().unwrap_or("");

    if method == HTTP_PROOF_METHOD
        && let Some(response) = proof_response(credentials, argument)
    {
        let _ = client.write_all(&response).await;
        return;
    }
    let authorized = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("proxy-authorization"))
        .is_some_and(|(_, value)| credentials.matches_basic(value));
    if !authorized {
        let _ = client.write_all(PROXY_AUTH_REQUIRED).await;
        return;
    }
    let request = if method != "CONNECT" && http_forward::is_absolute_http(argument) {
        match http_forward::rewrite_request(&head) {
            Ok(request) => Request::Forward {
                request,
                early_data,
            },
            Err(_) => {
                let _ = client.write_all(http_forward::BAD_REQUEST).await;
                return;
            }
        }
    } else {
        match (method, parse_authority(argument)) {
            ("CONNECT", Some(target)) => Request::Connect { target, early_data },
            _ => {
                let _ = client
                    .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                    .await;
                return;
            }
        }
    };
    let pending = scope.pending(client, request);
    answer(pending, connector, scope).await;
}

/// Reads a request head and returns it (without its terminating blank line)
/// plus the bytes already received after it (tunnel bytes after a CONNECT, the
/// body after a plain request), or `None` when the client closed first, sent
/// more than [`MAX_HTTP_HEAD`] bytes of head, or sent a head that is not UTF-8.
///
/// Reads in chunks rather than one byte per syscall; any bytes past the head
/// terminator are returned so the caller can replay them to the upstream.
async fn read_request_head(
    client: &mut TcpStream,
) -> Result<Option<(Zeroizing<String>, Zeroizing<Vec<u8>>)>, NetError> {
    // The head carries the client's `Proxy-Authorization`, and so can the bytes
    // after it: every buffer holding them is wiped when it goes, including the
    // ones outgrown on the way.
    let mut head = Zeroizing::new(Vec::with_capacity(HEAD_START));
    let mut chunk = Zeroizing::new([0u8; HEAD_CHUNK]);
    let head_len = loop {
        let n = client.read(&mut *chunk).await.map_err(NetError::Io)?;
        if n == 0 {
            return Ok(None); // connection closed before a full head
        }
        if head.len() + n > head.capacity() {
            let mut grown = Zeroizing::new(Vec::with_capacity(head.capacity() * 2));
            grown.extend_from_slice(&head);
            head = grown;
        }
        head.extend_from_slice(&chunk[..n]);
        // Only the new bytes, and the three before them, can complete the
        // terminator: rescanning the whole head costs quadratic time for a
        // client that sends a byte at a time.
        let from = head.len().saturating_sub(n + 3);
        if let Some(pos) = head[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            break from + pos + 4;
        }
        if head.len() > MAX_HTTP_HEAD {
            return Ok(None);
        }
    };
    let early_data = Zeroizing::new(head.split_off(head_len));
    head.truncate(head_len - 4);
    match String::from_utf8(std::mem::take(&mut *head)) {
        Ok(text) => Ok(Some((Zeroizing::new(text), early_data))),
        Err(not_utf8) => {
            drop(Zeroizing::new(not_utf8.into_bytes()));
            Ok(None)
        }
    }
}

/// Parses an HTTP `CONNECT` authority into a [`Target`], keeping domain names
/// for remote resolution. IPv6 literals use the `[addr]:port` form; a bare
/// (unbracketed) IPv6 literal or a zoned address is malformed in an authority
/// and is rejected rather than coerced into a bogus domain name.
pub(crate) fn parse_authority(authority: &str) -> Option<Target> {
    // Bracketed IPv6 literal: `[addr]:port`. The address must be a real v6
    // literal (a scope/zone id is not meaningful to a remote exit), so parse it
    // strictly; anything else is rejected.
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        let ip: std::net::Ipv6Addr = host.parse().ok()?;
        let port: u16 = port.parse().ok()?;
        return Some(Target::Ip(std::net::SocketAddr::from((ip, port))));
    }
    if let Ok(addr) = authority.parse::<std::net::SocketAddr>() {
        return Some(Target::Ip(addr));
    }
    let (host, port) = authority.rsplit_once(':')?;
    // A remaining colon in the host means an unbracketed IPv6 literal, which is
    // not a valid authority: reject it instead of producing a bogus domain.
    if host.contains(':') {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    Some(Target::Domain(host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_exhaustion_and_aborted_connections_are_waited_out() {
        let exhausted = if cfg!(windows) {
            vec![10024]
        } else {
            vec![24, 23]
        };
        for code in exhausted {
            assert!(is_transient_accept_error(
                &std::io::Error::from_raw_os_error(code)
            ));
        }
        for kind in [
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::Interrupted,
        ] {
            assert!(is_transient_accept_error(&kind.into()), "{kind:?}");
        }
        assert!(
            !is_transient_accept_error(&std::io::ErrorKind::PermissionDenied.into()),
            "a listener that cannot accept at all still ends the epoch"
        );
    }

    #[test]
    fn a_failed_connect_answers_a_response_that_names_this_proxy() {
        // The defect this pins: a bodyless 502 is rendered by an API client as
        // "this is a server-side issue, usually temporary", which sends a member
        // whose own tunnel just died to go read the API provider's status page.
        // The response has to say whose gateway failed.
        let raw = connect_failure_response(&NetError::EngineStopped);
        let text = String::from_utf8(raw).expect("the response is ASCII");
        assert!(
            text.starts_with("HTTP/1.1 502 "),
            "the status stays 502 so a client's retry policy is untouched: {text}"
        );
        assert!(
            text.contains(&format!("{TUNNEL_CAUSE_HEADER}: tunnel-gone")),
            "a machine reader needs the cause on its own header: {text}"
        );
        let body = text.split("\r\n\r\n").nth(1).expect("a body is present");
        assert!(
            !body.is_empty() && body.contains("warren"),
            "the body must name this proxy, got {body:?}"
        );
        assert!(
            text.contains(&format!("Content-Length: {}", body.len())),
            "the length must match the body or the client hangs: {text}"
        );
    }

    #[test]
    fn only_a_sourced_condition_earns_its_own_reply_code() {
        // `EngineStopped` is sourced: there is no tunnel, so the network really
        // is unreachable and RFC 1928's code 3 says exactly that.
        assert_eq!(
            connect_failure_reply(&NetError::EngineStopped),
            Reply::NetworkUnreachable
        );
        // The other two are NOT, and claiming them cost a member a wrong and
        // alarming message. `NetError::ConnectionRefused` is raised whenever the
        // smoltcp socket reaches `Closed` with a connect pending
        // (`netstack.rs`), which on a lossy tunnel is SYN exhaustion, not a peer
        // RST; `ConnectTimeout` is our own deadline, not evidence about the
        // host. Reported as codes 5 and 4 they reach the client as ECONNREFUSED
        // and EHOSTUNREACH, which HTTP clients treat as terminal and stop
        // retrying on, so a congested minute reads as "a firewall is blocking
        // you". The condition still travels, in the cause tag and the log, where
        // it cannot change retry semantics.
        for err in [NetError::ConnectionRefused, NetError::ConnectTimeout] {
            assert_eq!(
                connect_failure_reply(&err),
                Reply::GeneralFailure,
                "{err:?} is not sourced well enough to claim its own RFC 1928 code"
            );
        }
        assert_eq!(
            connect_failure_reply(&NetError::ConnectFailed),
            Reply::GeneralFailure,
            "an unclassified failure must stay the generic code, never a guess"
        );
    }

    #[test]
    fn each_local_failure_carries_its_own_cause_tag() {
        // Low cardinality and fixed strings on purpose: this reaches a log and a
        // user's screen, so it may never carry a host, an address or a port.
        for (err, tag) in [
            (NetError::EngineStopped, "tunnel-gone"),
            (NetError::ConnectionRefused, "exit-refused"),
            (NetError::ConnectTimeout, "connect-timeout"),
            (NetError::ConnectFailed, "connect-failed"),
            (NetError::NoDnsRecord, "connect-failed"),
        ] {
            let text = String::from_utf8(connect_failure_response(&err)).expect("ascii");
            assert!(
                text.contains(&format!("{TUNNEL_CAUSE_HEADER}: {tag}")),
                "{err:?} must report {tag}, got: {text}"
            );
        }
    }

    /// A connector that only ever fails, so the CONNECT path is exercised for
    /// real against a real socket pair.
    struct DeadConnector(NetError);

    impl Connector for DeadConnector {
        type Stream = tokio::net::TcpStream;

        async fn connect(&self, _target: Target) -> Result<Self::Stream, NetError> {
            Err(match self.0 {
                NetError::EngineStopped => NetError::EngineStopped,
                _ => NetError::ConnectFailed,
            })
        }
    }

    #[tokio::test]
    async fn a_connect_over_a_dead_tunnel_reaches_the_client_with_its_cause() {
        // The seam under test is the real `handle_connect`, over a real TCP
        // socket: a pure-function test alone would not catch a response written
        // without its body or with the head and body out of step.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let credentials = ProxyCredentials::generate();
        let server_credentials = credentials.clone();
        let server = tokio::spawn(async move {
            let (client, _) = listener.accept().await.expect("accept");
            handle_connect(
                client,
                &DeadConnector(NetError::EngineStopped),
                &server_credentials,
                PathScope::default(),
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let request = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: {}\r\n\r\n",
            &*credentials.basic_authorization()
        );
        client.write_all(request.as_bytes()).await.expect("write");
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.expect("read");
        server.await.expect("join");

        let text = String::from_utf8(got).expect("ascii");
        assert!(text.starts_with("HTTP/1.1 502 "), "{text}");
        assert!(text.contains("tunnel-gone"), "{text}");
        assert!(
            text.contains("warren"),
            "the member must be able to tell a local tunnel from an API outage: {text}"
        );
        assert!(
            !text.contains("example.com"),
            "the response may never echo the target back: {text}"
        );
    }

    /// A connector whose connect never completes: the dial a walled tunnel
    /// makes, which neither answers nor fails before the path is given up.
    struct HangingConnector;

    impl Connector for HangingConnector {
        type Stream = tokio::net::TcpStream;

        async fn connect(&self, _target: Target) -> Result<Self::Stream, NetError> {
            std::future::pending().await
        }
    }

    /// A local echo server, the upstream a request reaches once a path takes it.
    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    fn connect_request(credentials: &ProxyCredentials, target: SocketAddr) -> String {
        format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {}\r\n\r\n",
            &*credentials.basic_authorization()
        )
    }

    /// Reads an HTTP response head (through its blank line) off `stream`.
    async fn read_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await.expect("read head") == 0 {
                break;
            }
            head.push(byte[0]);
        }
        String::from_utf8(head).expect("ascii head")
    }

    #[tokio::test]
    async fn a_connect_whose_path_ends_before_it_is_answered_is_answered_by_the_next_path() {
        // The defect this pins: at the instant the Warren app connects, the
        // helper's own tunnel is walled by the app's kill switch. A CONNECT the
        // browser sent just then was accepted by that dying path, and when the
        // path was given up the client socket was closed with no answer, which
        // the browser shows as ERR_TUNNEL_CONNECTION_FAILED. Nothing had left
        // for the target yet, so the next path must carry it instead.
        let echo = echo_server().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let credentials = ProxyCredentials::generate();
        let handover = Handover::new();

        let (run_a, rx_a) = tokio::sync::watch::channel(true);
        let dying = HttpConnectProxy::new(HangingConnector, credentials.clone())
            .with_handover(handover.clone());
        let listener = Arc::new(listener);
        let first = {
            let listener = Arc::clone(&listener);
            tokio::spawn(async move { dying.serve_until(&listener, rx_a).await })
        };

        let mut client = TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(connect_request(&credentials, echo).as_bytes())
            .await
            .expect("write");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let _ = run_a.send(false);
        first.await.expect("join").expect("first path served");

        let (_run_b, rx_b) = tokio::sync::watch::channel(true);
        let next = HttpConnectProxy::new(DirectConnector, credentials.clone())
            .with_handover(handover.clone());
        let _second = {
            let listener = Arc::clone(&listener);
            tokio::spawn(async move { next.serve_until(&listener, rx_b).await })
        };

        let head = tokio::time::timeout(std::time::Duration::from_secs(5), read_head(&mut client))
            .await
            .expect("the next path answers the waiting request");
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        client.write_all(b"ping").await.expect("write through");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.expect("read through");
        assert_eq!(&echoed, b"ping");
    }

    #[tokio::test]
    async fn a_socks_connect_whose_path_ends_before_it_is_answered_is_answered_by_the_next_path() {
        let echo = echo_server().await;
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.expect("bind"));
        let addr = listener.local_addr().expect("addr");
        let credentials = ProxyCredentials::generate();
        let handover = Handover::new();

        let (run_a, rx_a) = tokio::sync::watch::channel(true);
        let dying =
            Socks5Proxy::new(HangingConnector, credentials.clone()).with_handover(handover.clone());
        let first = {
            let listener = Arc::clone(&listener);
            tokio::spawn(async move { dying.serve_until(&listener, rx_a).await })
        };
        let client_credentials = credentials.clone();
        let client = tokio::spawn(async move {
            crate::proxy_auth::socks5_connect(addr, &client_credentials, &Target::Ip(echo)).await
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let _ = run_a.send(false);
        first.await.expect("join").expect("first path served");

        let (_run_b, rx_b) = tokio::sync::watch::channel(true);
        let next =
            Socks5Proxy::new(DirectConnector, credentials.clone()).with_handover(handover.clone());
        let _second = {
            let listener = Arc::clone(&listener);
            tokio::spawn(async move { next.serve_until(&listener, rx_b).await })
        };

        let mut stream = tokio::time::timeout(std::time::Duration::from_secs(5), client)
            .await
            .expect("the next path answers the waiting request")
            .expect("join")
            .expect("the SOCKS reply is a success");
        stream.write_all(b"ping").await.expect("write through");
        let mut echoed = [0u8; 4];
        stream.read_exact(&mut echoed).await.expect("read through");
        assert_eq!(&echoed, b"ping");
    }

    #[tokio::test]
    async fn a_request_no_path_takes_up_is_refused_at_its_deadline() {
        // Held, not dropped: a request is kept only as long as a browser would
        // wait for it, then answered the way a dead tunnel always was.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let credentials = ProxyCredentials::generate();
        let handover = Handover::with_deadline(std::time::Duration::from_millis(400));
        let (run, rx) = tokio::sync::watch::channel(true);
        let dying = HttpConnectProxy::new(HangingConnector, credentials.clone())
            .with_handover(handover.clone());
        let server = tokio::spawn(async move { dying.serve_until(&listener, rx).await });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(connect_request(&credentials, "127.0.0.1:9".parse().unwrap()).as_bytes())
            .await
            .expect("write");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = run.send(false);
        server.await.expect("join").expect("served");

        let started = std::time::Instant::now();
        let head = tokio::time::timeout(std::time::Duration::from_secs(5), read_head(&mut client))
            .await
            .expect("the request is answered, not left hanging");
        assert!(head.starts_with("HTTP/1.1 502 "), "{head}");
        assert!(head.contains("tunnel-gone"), "{head}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "refused at its deadline, not at some later timeout"
        );
    }

    #[tokio::test]
    async fn a_target_that_refuses_is_answered_at_once_and_never_handed_over() {
        // Only a path that went away earns a second chance. A target that
        // refuses would refuse on the next path too, and a member waiting for
        // it to fail again would be waiting for nothing.
        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            l.local_addr().expect("addr")
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let credentials = ProxyCredentials::generate();
        let handover = Handover::new();
        let (_run, rx) = tokio::sync::watch::channel(true);
        let proxy = HttpConnectProxy::new(DirectConnector, credentials.clone())
            .with_handover(handover.clone());
        let _server = tokio::spawn(async move { proxy.serve_until(&listener, rx).await });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(connect_request(&credentials, closed).as_bytes())
            .await
            .expect("write");
        let head = tokio::time::timeout(std::time::Duration::from_secs(2), read_head(&mut client))
            .await
            .expect("answered at once");
        assert!(head.starts_with("HTTP/1.1 502 "), "{head}");
        assert_eq!(handover.len(), 0, "nothing waits for another path");
    }

    #[test]
    fn parse_authority_ipv4_literal() {
        assert_eq!(
            parse_authority("1.2.3.4:443"),
            Some(Target::Ip("1.2.3.4:443".parse().unwrap()))
        );
    }

    #[test]
    fn parse_authority_bracketed_ipv6_literal() {
        assert_eq!(
            parse_authority("[2001:db8::1]:8080"),
            Some(Target::Ip("[2001:db8::1]:8080".parse().unwrap()))
        );
    }

    #[test]
    fn parse_authority_domain_keeps_the_name() {
        assert_eq!(
            parse_authority("example.com:443"),
            Some(Target::Domain("example.com".to_owned(), 443))
        );
    }

    #[test]
    fn parse_authority_rejects_malformed_v6_authorities() {
        // Zoned v6 literal: not meaningful to a remote exit.
        assert_eq!(parse_authority("[fe80::1%eth0]:443"), None);
        // Bracketed but no port.
        assert_eq!(parse_authority("[::1]"), None);
        // Unbracketed v6 literal: an invalid authority, must not become a domain.
        assert_eq!(parse_authority("2001:db8::1:443"), None);
        // Missing port / non-numeric port.
        assert_eq!(parse_authority("example.com"), None);
        assert_eq!(parse_authority("example.com:http"), None);
    }
}
