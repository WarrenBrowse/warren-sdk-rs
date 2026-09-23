//! Plain-HTTP forwarding on the local HTTP proxy listener.
//!
//! A client pointed at an HTTP proxy tunnels `https://` through `CONNECT`, but
//! hands a plain `http://` request to the proxy itself, in absolute form
//! (`GET http://host/path HTTP/1.1`). The listener carries exactly one such
//! request per client connection: it rewrites the head to origin form for the
//! target, drops every hop-by-hop field (the client's `Proxy-Authorization`
//! first among them), relays the body by its own framing, relays the final
//! response by its framing with `Connection: close`, and closes.
//!
//! One request per connection is what keeps the session secret on this
//! machine: nothing the client sends after the request it authenticated is
//! forwarded, so a second, pipelined request and its own `Proxy-Authorization`
//! never reach the origin. The proxy closes the client connection once the
//! response is complete, so a client that ignores `Connection: close` cannot
//! reuse it either; it opens a new connection and authenticates again.
//!
//! A message that a lenient reader could split differently from this parser (a
//! bare CR or LF inside a line, a folded line, conflicting body lengths) is
//! refused in both directions: a line this parser saw as one must not become
//! two at the origin, nor at the client.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
    ReadBuf,
};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::error::NetError;
use crate::proxy::{Connector, connect_failure_response, parse_authority};
use crate::socks5::Target;

/// Fields that describe one connection rather than the message (RFC 9110
/// section 7.6.1), dropped in both directions. The proxy's own authentication
/// exchange belongs to the client's hop and is among them.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authentication-info",
    "proxy-authorization",
    "te",
    "upgrade",
];

/// Fields that frame the body this proxy relays unchanged: they travel with it
/// whatever a `Connection` field lists, or the reader would take the body for
/// the next message.
const FRAMING: [&str; 2] = ["content-length", "transfer-encoding"];

/// Longest response head accepted from an origin (it carries its cookies).
const MAX_RESPONSE_HEAD: u64 = 64 * 1024;

/// Longest chunk-size line, and the most trailer bytes, accepted in a chunked
/// body.
const MAX_CHUNK_LINE: u64 = 4 * 1024;

/// Size of the buffer the client's bytes are read through.
const CLIENT_BUFFER: usize = 8 * 1024;

/// How long the client may keep sending after its answer is complete before
/// the connection is dropped. Closing on unread input resets the connection,
/// and a reset can take the answer with it on the client's side.
const LINGER: Duration = Duration::from_secs(2);

/// The answer to a request this proxy refuses to forward.
pub(crate) const BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The answer when the origin said nothing a client can be handed.
const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// A request head this proxy will not forward.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed;

/// How a message body is delimited (RFC 9112 section 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyLength {
    None,
    Exactly(u64),
    Chunked,
    /// A response with neither length nor chunking ends when the origin closes.
    UntilClose,
}

/// A request rewritten for its origin.
#[derive(Debug)]
pub(crate) struct ForwardRequest {
    target: Target,
    /// The origin-form head, terminated, with no hop-by-hop field.
    head: Vec<u8>,
    body: BodyLength,
    /// A `HEAD` request: its response carries no body whatever it declares.
    head_only: bool,
}

/// Whether a request target is an absolute `http` URL, the form a client uses
/// to ask a proxy for a plain-HTTP resource.
pub(crate) fn is_absolute_http(target: &str) -> bool {
    target
        .get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_token(text: &[u8]) -> bool {
    !text.is_empty() && text.iter().copied().all(is_tchar)
}

/// A control character a line may not carry: any but HTAB, and DEL.
fn is_forbidden_control(byte: u8) -> bool {
    byte == 0x7f || (byte < 0x20 && byte != b'\t')
}

/// Whether a lowercased field name is dropped: hop-by-hop, or listed by the
/// message's `Connection` fields (framing fields excepted).
fn is_dropped(name: &str, listed: &[String]) -> bool {
    HOP_BY_HOP.contains(&name)
        || (!FRAMING.contains(&name) && listed.iter().any(|entry| entry == name))
}

/// The lowercased field names the `Connection` and `Proxy-Connection` fields
/// list.
fn connection_listed<'a>(fields: impl Iterator<Item = (&'a str, &'a [u8])>) -> Vec<String> {
    fields
        .filter(|(name, _)| *name == "connection" || *name == "proxy-connection")
        .flat_map(|(_, value)| {
            String::from_utf8_lossy(value)
                .split(',')
                .map(|entry| entry.trim().to_ascii_lowercase())
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Splits `http://authority[/path][?query]` into the authority and the origin
/// form, dropping any fragment. Userinfo is refused (RFC 9110 section 4.2.4).
fn split_absolute(target: &str) -> Result<(&str, String), Malformed> {
    let rest = target.get(7..).ok_or(Malformed)?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.is_empty() || authority.contains('@') {
        return Err(Malformed);
    }
    let tail = tail.split('#').next().unwrap_or_default();
    let origin_form = match tail.as_bytes().first() {
        None => "/".to_owned(),
        Some(b'?') => format!("/{tail}"),
        Some(_) => tail.to_owned(),
    };
    Ok((authority, origin_form))
}

/// The target an authority names, on port 80 when it names none.
fn target_of(authority: &str) -> Result<Target, Malformed> {
    let port = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed.split_once("]:").map(|(_, port)| port),
        None => authority.split_once(':').map(|(_, port)| port),
    };
    let with_port = match port {
        Some(port) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            authority.to_owned()
        }
        Some(_) => return Err(Malformed),
        None => format!("{authority}:80"),
    };
    match parse_authority(&with_port) {
        Some(Target::Domain(host, _)) if host.is_empty() => Err(Malformed),
        Some(target) => Ok(target),
        None => Err(Malformed),
    }
}

/// Rewrites an absolute-form request head (request line and fields, without
/// the blank line that ends it) for its origin.
///
/// # Errors
///
/// [`Malformed`] when the head is not one this proxy can forward unambiguously:
/// a control character or a bare CR or LF inside a line, a request target with
/// anything but visible ASCII, a folded or unnamed field line, a target that is
/// not `http://host[:port]`, a version other than HTTP/1.0 or HTTP/1.1, or a
/// body length that is invalid, repeated with different values, given by both
/// `Content-Length` and `Transfer-Encoding`, or a transfer coding other than
/// `chunked` on an HTTP/1.1 request.
pub(crate) fn rewrite_request(head: &str) -> Result<ForwardRequest, Malformed> {
    let mut lines = head.split("\r\n");
    if lines.clone().flat_map(str::bytes).any(is_forbidden_control) {
        return Err(Malformed);
    }
    let mut request_line = lines.next().ok_or(Malformed)?.split(' ');
    let (Some(method), Some(target), Some(version), None) = (
        request_line.next(),
        request_line.next(),
        request_line.next(),
        request_line.next(),
    ) else {
        return Err(Malformed);
    };
    if !is_token(method.as_bytes())
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || !target.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(Malformed);
    }
    let (authority, origin_form) = split_absolute(target)?;
    let target = target_of(authority)?;

    let mut fields = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(Malformed)?;
        if !is_token(name.as_bytes()) {
            return Err(Malformed);
        }
        fields.push((
            name.to_ascii_lowercase(),
            value.trim_matches([' ', '\t']),
            line,
        ));
    }

    let body = request_body_length(&fields)?;
    if body == BodyLength::Chunked && version == "HTTP/1.0" {
        // RFC 9112 section 6.1: chunked framing on HTTP/1.0 is faulty, so an
        // origin would not end the body where this proxy does.
        return Err(Malformed);
    }
    let listed = connection_listed(
        fields
            .iter()
            .map(|(name, value, _)| (name.as_str(), value.as_bytes())),
    );

    let mut out = format!("{method} {origin_form} {version}\r\nHost: {authority}\r\n");
    let mut length_sent = false;
    for (name, _, line) in &fields {
        // Host is replaced by the target's (RFC 9112 section 3.2.2), and the
        // trailer fields a `Trailer` field announces are not forwarded.
        if is_dropped(name, &listed) || name == "host" || name == "trailer" {
            continue;
        }
        if name == "content-length" {
            if length_sent {
                continue;
            }
            length_sent = true;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    Ok(ForwardRequest {
        target,
        head: out.into_bytes(),
        body,
        head_only: method == "HEAD",
    })
}

/// The body length a request's framing fields declare (RFC 9112 section 6.3).
fn request_body_length(fields: &[(String, &str, &str)]) -> Result<BodyLength, Malformed> {
    let mut length = None;
    let mut codings = 0;
    for (name, value, _) in fields {
        match name.as_str() {
            "content-length" => {
                let parsed = content_length(value.as_bytes()).ok_or(Malformed)?;
                if length.is_some_and(|known| known != parsed) {
                    return Err(Malformed);
                }
                length = Some(parsed);
            }
            "transfer-encoding" => {
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err(Malformed);
                }
                codings += 1;
            }
            _ => {}
        }
    }
    match (length, codings) {
        (None, 0) => Ok(BodyLength::None),
        (Some(n), 0) => Ok(BodyLength::Exactly(n)),
        (None, 1) => Ok(BodyLength::Chunked),
        _ => Err(Malformed),
    }
}

fn content_length(value: &[u8]) -> Option<u64> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

/// The client's side of an exchange, read through a buffer that is wiped when
/// dropped: whatever the client sends past its request can carry another
/// `Proxy-Authorization`, and it must not outlive the exchange in freed memory.
struct WipedReader<R> {
    inner: R,
    buf: Zeroizing<Vec<u8>>,
    start: usize,
    end: usize,
}

impl<R> WipedReader<R> {
    /// A reader that first yields `early`, the bytes already read past the head.
    fn new(inner: R, early: &[u8]) -> Self {
        let mut buf = Zeroizing::new(vec![0u8; CLIENT_BUFFER.max(early.len())]);
        buf[..early.len()].copy_from_slice(early);
        Self {
            inner,
            buf,
            start: 0,
            end: early.len(),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncBufRead for WipedReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.start == this.end {
            let mut read = ReadBuf::new(&mut this.buf[..]);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            this.end = read.filled().len();
            this.start = 0;
        }
        Poll::Ready(Ok(&this.buf[this.start..this.end]))
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        this.start = (this.start + amount).min(this.end);
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for WipedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let available = ready!(self.as_mut().poll_fill_buf(cx))?;
        let n = available.len().min(out.remaining());
        out.put_slice(&available[..n]);
        self.consume(n);
        Poll::Ready(Ok(()))
    }
}

/// Why the upload side of an exchange stopped early.
enum UploadStop {
    /// The client's body broke its framing or its connection failed.
    Client(NetError),
    /// The origin stopped taking the body; its answer, if any, still counts.
    Origin,
}

/// Carries `request` to its origin through `connector` and relays the answer.
/// `early_data` is what the client sent after the head while it was read.
///
/// # Errors
///
/// A [`NetError`] when the origin cannot be reached (the client is told so by
/// this proxy first), when either side fails mid-exchange, or
/// [`NetError::MalformedHttp`] when the client's body or the origin's answer
/// breaks HTTP/1.1 framing (the client is answered `400` or `502` when no
/// byte of an answer had reached it yet).
pub(crate) async fn forward<C: Connector>(
    client: &mut TcpStream,
    early_data: &[u8],
    connector: &C,
    request: ForwardRequest,
) -> Result<(), NetError> {
    let mut upstream = match connector.connect(request.target).await {
        Ok(stream) => stream,
        Err(e) => {
            let _ = client.write_all(&connect_failure_response(&e)).await;
            return Err(e);
        }
    };
    if let Err(e) = upstream.write_all(&request.head).await {
        let _ = client.write_all(BAD_GATEWAY).await;
        return Err(NetError::Io(e));
    }

    let (client_read, mut client_write) = client.split();
    let mut from_client = WipedReader::new(client_read, early_data);
    let (upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let mut from_upstream = BufReader::new(upstream_read);
    let answering = AtomicBool::new(false);

    let (outcome, refusal) = {
        let upload = async {
            match relay_body(&mut from_client, &mut upstream_write, request.body).await {
                Ok(()) => {}
                Err(RelayError::Read(e)) => return UploadStop::Client(e),
                Err(RelayError::Write(_)) => return UploadStop::Origin,
            }
            // The request is delivered. What the client sends next is read and
            // dropped, never forwarded; its close ends nothing, since the
            // answer is what ends the exchange.
            let _ = discard_until_closed(&mut from_client).await;
            std::future::pending().await
        };
        let download = relay_response(
            &mut from_upstream,
            &mut client_write,
            request.head_only,
            &answering,
        );
        tokio::pin!(upload, download);
        let mut uploading = true;
        loop {
            tokio::select! {
                stop = &mut upload, if uploading => match stop {
                    UploadStop::Origin => uploading = false,
                    UploadStop::Client(e) => break (Err(e), BAD_REQUEST),
                },
                answered = &mut download => break (answered, BAD_GATEWAY),
            }
        }
    };
    if outcome.is_err() && !answering.load(Ordering::Relaxed) {
        let _ = client_write.write_all(refusal).await;
    }
    let _ = client_write.shutdown().await;
    let _ = tokio::time::timeout(LINGER, discard_until_closed(&mut from_client)).await;
    outcome
}

/// A relay failure, by the side that caused it.
enum RelayError {
    /// Reading failed, or what was read broke the framing.
    Read(NetError),
    /// Writing to the other side failed.
    Write(std::io::Error),
}

impl From<RelayError> for NetError {
    fn from(e: RelayError) -> Self {
        match e {
            RelayError::Read(e) => e,
            RelayError::Write(e) => NetError::Io(e),
        }
    }
}

async fn relay_body<R, W>(from: &mut R, to: &mut W, body: BodyLength) -> Result<(), RelayError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body {
        BodyLength::None => Ok(()),
        BodyLength::Exactly(length) => copy_exactly(from, to, length).await,
        BodyLength::Chunked => relay_chunked(from, to).await,
        BodyLength::UntilClose => {
            tokio::io::copy_buf(from, to)
                .await
                .map_err(|e| RelayError::Read(NetError::Io(e)))?;
            Ok(())
        }
    }
}

/// Copies exactly `length` bytes, passing them on as they come.
async fn copy_exactly<R, W>(from: &mut R, to: &mut W, length: u64) -> Result<(), RelayError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut left = length;
    while left > 0 {
        let available = from
            .fill_buf()
            .await
            .map_err(|e| RelayError::Read(NetError::Io(e)))?;
        if available.is_empty() {
            return Err(RelayError::Read(NetError::MalformedHttp));
        }
        let n = available
            .len()
            .min(usize::try_from(left).unwrap_or(usize::MAX));
        to.write_all(&available[..n])
            .await
            .map_err(RelayError::Write)?;
        from.consume(n);
        left -= n as u64;
    }
    Ok(())
}

/// Reads one CRLF-terminated line of at most `max` bytes, terminator included.
async fn read_crlf_line<R: AsyncBufRead + Unpin>(
    from: &mut R,
    max: u64,
) -> Result<Vec<u8>, RelayError> {
    let mut line = Vec::new();
    (&mut *from)
        .take(max)
        .read_until(b'\n', &mut line)
        .await
        .map_err(|e| RelayError::Read(NetError::Io(e)))?;
    if line.ends_with(b"\r\n") && !line[..line.len() - 2].contains(&b'\r') {
        Ok(line)
    } else {
        Err(RelayError::Read(NetError::MalformedHttp))
    }
}

/// Relays a chunked body chunk by chunk, as sent, and stops at its last
/// chunk. The trailer fields are dropped: they sit where a peer could slip a
/// field this proxy never inspects.
async fn relay_chunked<R, W>(from: &mut R, to: &mut W) -> Result<(), RelayError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let malformed = || RelayError::Read(NetError::MalformedHttp);
    loop {
        let line = read_crlf_line(from, MAX_CHUNK_LINE).await?;
        let size = chunk_size(&line[..line.len() - 2]).ok_or_else(malformed)?;
        to.write_all(&line).await.map_err(RelayError::Write)?;
        if size == 0 {
            break;
        }
        copy_exactly(from, to, size).await?;
        let mut end = [0u8; 2];
        from.read_exact(&mut end).await.map_err(|_| malformed())?;
        if &end != b"\r\n" {
            return Err(malformed());
        }
        to.write_all(&end).await.map_err(RelayError::Write)?;
    }
    let mut trailers = 0;
    loop {
        let line = read_crlf_line(from, MAX_CHUNK_LINE).await?;
        if line == b"\r\n" {
            break;
        }
        trailers += line.len() as u64;
        if trailers > MAX_CHUNK_LINE {
            return Err(malformed());
        }
    }
    to.write_all(b"\r\n").await.map_err(RelayError::Write)
}

/// The size a chunk-size line declares: hex digits, then optional extensions
/// (RFC 9112 section 7.1.1).
fn chunk_size(line: &[u8]) -> Option<u64> {
    let digits = line
        .iter()
        .position(|b| !b.is_ascii_hexdigit())
        .map_or(line, |end| &line[..end]);
    let rest = &line[digits.len()..];
    let extension = rest.trim_ascii_start().starts_with(b";");
    if digits.is_empty() || digits.len() > 15 || !(rest.is_empty() || extension) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
}

/// Reads and drops whatever the client sends until it closes its sending side.
async fn discard_until_closed<R: AsyncRead + Unpin>(from: &mut R) -> Result<(), NetError> {
    let mut sink = Zeroizing::new([0u8; 1024]);
    loop {
        if from.read(&mut *sink).await.map_err(NetError::Io)? == 0 {
            return Ok(());
        }
    }
}

/// A response head rewritten for the client.
#[derive(Debug, PartialEq, Eq)]
struct ResponseHead {
    bytes: Vec<u8>,
    /// A 1xx: the final response still follows.
    interim: bool,
    body: BodyLength,
}

/// Rewrites a response head (status line and fields, without the blank line)
/// for the client, or `None` when it is not one a client can be handed. The
/// status line is followed by `Connection: close` first, so a client that
/// acts on the first `Connection` it meets acts on this one.
///
/// An origin's `407` becomes a `502`: on this connection a `407` must only ever
/// be this proxy asking for its own credentials, or a client would answer an
/// origin's challenge with them. A `101` is refused: the proxy dropped the
/// request's `Upgrade`, so no protocol switch was asked for.
fn rewrite_response(head: &[u8], head_only: bool) -> Option<ResponseHead> {
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    if lines
        .clone()
        .flat_map(|line| line.iter().copied())
        .any(is_forbidden_control)
    {
        return None;
    }
    let status_line = lines.next()?;
    let version = status_line.get(..8)?;
    let status = status_line.get(9..12)?;
    if !version.starts_with(b"HTTP/1.")
        || status_line.get(8) != Some(&b' ')
        || !status.iter().all(u8::is_ascii_digit)
        || status_line.get(12).is_some_and(|&b| b != b' ')
    {
        return None;
    }
    let code: u16 = std::str::from_utf8(status).ok()?.parse().ok()?;
    if code == 101 {
        return None;
    }

    let mut fields = Vec::new();
    for line in lines {
        let colon = line.iter().position(|&b| b == b':')?;
        if !is_token(&line[..colon]) {
            return None;
        }
        let name = String::from_utf8_lossy(&line[..colon]).to_ascii_lowercase();
        fields.push((name, line[colon + 1..].trim_ascii(), line));
    }
    let listed = connection_listed(
        fields
            .iter()
            .map(|(name, value, _)| (name.as_str(), *value)),
    );
    let interim = (100..200).contains(&code);
    let body = if interim || head_only || code == 204 || code == 304 {
        BodyLength::None
    } else {
        response_body_length(&fields)?
    };

    let mut out = if code == 407 {
        let mut line = version.to_vec();
        line.extend_from_slice(b" 502 Bad Gateway");
        line
    } else {
        status_line.to_vec()
    };
    out.extend_from_slice(b"\r\n");
    if !interim {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    for (name, _, line) in &fields {
        if !is_dropped(name, &listed) {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    Some(ResponseHead {
        bytes: out,
        interim,
        body,
    })
}

/// The body length a final response's framing fields declare (RFC 9112
/// section 6.3), or `None` when they contradict each other.
fn response_body_length(fields: &[(String, &[u8], &[u8])]) -> Option<BodyLength> {
    let mut length = None;
    let mut last_coding: Option<Vec<u8>> = None;
    for (name, value, _) in fields {
        match name.as_str() {
            "content-length" => {
                let parsed = content_length(value)?;
                if length.is_some_and(|known| known != parsed) {
                    return None;
                }
                length = Some(parsed);
            }
            "transfer-encoding" => {
                let coding = value.rsplit(|&b| b == b',').next()?.trim_ascii();
                last_coding = Some(coding.to_ascii_lowercase());
            }
            _ => {}
        }
    }
    match (length, last_coding) {
        (Some(_), Some(_)) => None,
        (Some(n), None) => Some(BodyLength::Exactly(n)),
        (None, Some(coding)) if coding == b"chunked" => Some(BodyLength::Chunked),
        (None, _) => Some(BodyLength::UntilClose),
    }
}

/// Reads a response head up to its blank line, or `None` when the origin
/// closed first or sent more than [`MAX_RESPONSE_HEAD`].
async fn read_response_head<R: AsyncBufRead + Unpin>(from: &mut R) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let budget = MAX_RESPONSE_HEAD.checked_sub(head.len() as u64)?;
        (&mut *from)
            .take(budget)
            .read_until(b'\n', &mut line)
            .await
            .ok()?;
        if !line.ends_with(b"\n") {
            return None;
        }
        if line == b"\r\n" || line == b"\n" {
            head.pop_if(|b| *b == b'\n');
            head.pop_if(|b| *b == b'\r');
            return Some(head);
        }
        head.extend_from_slice(&line);
    }
}

/// Relays the origin's interim responses and its final one, rewritten, then
/// the final body by its framing. `answering` is raised once a byte of an
/// answer has gone to the client, after which a failure can only be a close.
async fn relay_response<R, W>(
    from: &mut R,
    to: &mut W,
    head_only: bool,
    answering: &AtomicBool,
) -> Result<(), NetError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let body = loop {
        let Some(head) = read_response_head(from)
            .await
            .and_then(|head| rewrite_response(&head, head_only))
        else {
            return Err(NetError::MalformedHttp);
        };
        answering.store(true, Ordering::Relaxed);
        to.write_all(&head.bytes).await.map_err(NetError::Io)?;
        if !head.interim {
            break head.body;
        }
    };
    relay_body(from, to, body).await.map_err(NetError::from)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn rewritten(head: &str) -> (Target, String, BodyLength) {
        let request = rewrite_request(head).expect("forwardable");
        (
            request.target,
            String::from_utf8(request.head).unwrap(),
            request.body,
        )
    }

    fn response(head: &[u8]) -> Option<ResponseHead> {
        rewrite_response(head, false)
    }

    /// Bytes already received, so the relays run without a socket.
    fn received(bytes: &[u8]) -> BufReader<Cursor<Vec<u8>>> {
        BufReader::new(Cursor::new(bytes.to_vec()))
    }

    #[test]
    fn an_authority_without_a_port_names_port_80() {
        let (target, head, _) = rewritten("GET http://example.com HTTP/1.1");
        assert_eq!(target, Target::Domain("example.com".to_owned(), 80));
        assert!(
            head.starts_with("GET / HTTP/1.1\r\nHost: example.com\r\n"),
            "{head}"
        );
    }

    #[test]
    fn an_ipv6_literal_keeps_its_brackets_in_host() {
        let (target, head, _) = rewritten("GET http://[2001:db8::1]:8080/a HTTP/1.1");
        assert_eq!(target, Target::Ip("[2001:db8::1]:8080".parse().unwrap()));
        assert!(head.contains("\r\nHost: [2001:db8::1]:8080\r\n"), "{head}");
    }

    #[test]
    fn an_ipv6_literal_without_a_port_names_port_80() {
        let (target, _, _) = rewritten("GET http://[2001:db8::1]/ HTTP/1.1");
        assert_eq!(target, Target::Ip("[2001:db8::1]:80".parse().unwrap()));
    }

    #[test]
    fn a_query_without_a_path_and_a_fragment_are_put_in_origin_form() {
        let (_, head, _) = rewritten("GET http://example.com?q=1#top HTTP/1.1");
        assert!(head.starts_with("GET /?q=1 HTTP/1.1\r\n"), "{head}");
    }

    #[test]
    fn an_http_1_0_request_keeps_its_version() {
        let (_, head, _) = rewritten("GET http://example.com/ HTTP/1.0");
        assert!(head.starts_with("GET / HTTP/1.0\r\n"), "{head}");
    }

    #[test]
    fn a_connection_field_cannot_strip_the_body_framing() {
        let (_, head, body) = rewritten(
            "POST http://example.com/ HTTP/1.1\r\nConnection: content-length, x-a\r\nContent-Length: 3\r\nX-A: 1",
        );
        assert!(head.contains("\r\nContent-Length: 3\r\n"), "{head}");
        assert!(!head.contains("X-A"), "{head}");
        assert_eq!(body, BodyLength::Exactly(3));
    }

    #[test]
    fn heads_that_cannot_be_forwarded_unambiguously_are_refused() {
        for head in [
            "GET http://user:pass@example.com/ HTTP/1.1",
            "GET http://user@example.com/ HTTP/1.1",
            "GET http:/// HTTP/1.1",
            "GET http://:80/ HTTP/1.1",
            "GET http://example.com:/ HTTP/1.1",
            "GET http://example.com:+80/ HTTP/1.1",
            "GET http://2001:db8::1/ HTTP/1.1",
            "GET http://example.com/a\tb HTTP/1.1",
            "GET http://example.com/\u{e9} HTTP/1.1",
            "GET http://example.com/ HTTP/2",
            "GET  http://example.com/ HTTP/1.1",
            "G(T http://example.com/ HTTP/1.1",
            "GET http://example.com/ HTTP/1.1\r\nX-A : 1",
            "GET http://example.com/ HTTP/1.1\r\nX-A: 1\r\n\tfolded",
            "GET http://example.com/ HTTP/1.1\r\nX-A: 1\rX-B: 2",
            "GET http://example.com/ HTTP/1.1\r\nX-A: \u{0}",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: +1",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked",
            "POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: gzip, chunked",
            "POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
            "POST http://example.com/ HTTP/1.0\r\nTransfer-Encoding: chunked",
        ] {
            assert_eq!(rewrite_request(head).unwrap_err(), Malformed, "{head:?}");
        }
    }

    #[test]
    fn a_repeated_identical_length_is_forwarded_once() {
        let (_, head, body) = rewritten(
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4",
        );
        assert_eq!(body, BodyLength::Exactly(4));
        assert_eq!(head.matches("Content-Length").count(), 1, "{head}");
    }

    #[test]
    fn a_head_request_is_marked_so_its_answer_carries_no_body() {
        let head = rewrite_request("HEAD http://example.com/ HTTP/1.1").unwrap();
        let get = rewrite_request("GET http://example.com/ HTTP/1.1").unwrap();
        assert!(head.head_only);
        assert!(!get.head_only);
    }

    #[test]
    fn chunk_sizes_parse_as_hex_with_extensions() {
        assert_eq!(chunk_size(b"1a"), Some(26));
        assert_eq!(chunk_size(b"0"), Some(0));
        assert_eq!(chunk_size(b"5;name=value"), Some(5));
        assert_eq!(chunk_size(b"5 \t;name"), Some(5), "whitespace before ';'");
        assert_eq!(chunk_size(b""), None);
        assert_eq!(chunk_size(b"5 junk"), None);
        assert_eq!(chunk_size(b"5 "), None, "whitespace with no extension");
        assert_eq!(chunk_size(b"-5"), None);
        assert_eq!(chunk_size(b"1000000000000000"), None, "sixteen digits");
    }

    #[test]
    fn a_response_head_a_client_could_read_differently_is_refused() {
        for head in [
            &b"ICY 200 OK"[..],
            b"HTTP/1.1 2000 OK",
            b"HTTP/1.1 20x OK",
            b"HTTP/1.1 101 Switching Protocols",
            b"HTTP/1.1 200 OK\r\nno colon here",
            b"HTTP/1.1 200 OK\r\nX-A: 1\r\n folded",
            b"HTTP/1.1 200 OK\r\nX-A: 1\rConnection: keep-alive",
            b"HTTP/1.1 200 OK\rX-A: 1",
            b"HTTP/1.1 200 OK\r\nX-A: \x00",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked",
        ] {
            assert_eq!(response(head), None, "{head:?}");
        }
    }

    #[test]
    fn connection_close_follows_the_status_line_and_lines_end_in_crlf() {
        let head = response(b"HTTP/1.1 204 No Content\r\nX-A: 1\nX-B: 2").unwrap();
        assert_eq!(
            head.bytes,
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\nX-A: 1\r\nX-B: 2\r\n\r\n"
        );
    }

    #[test]
    fn an_interim_response_is_passed_on_without_a_connection_field() {
        let head = response(b"HTTP/1.1 103 Early Hints\r\nLink: </a>").unwrap();
        assert!(head.interim);
        assert_eq!(
            head.bytes,
            b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
        );
    }

    #[test]
    fn a_final_response_body_is_framed_as_rfc_9112_says() {
        for (head, head_only, body) in [
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 7"[..],
                false,
                BodyLength::Exactly(7),
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 7",
                true,
                BodyLength::None,
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked",
                false,
                BodyLength::Chunked,
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip",
                false,
                BodyLength::UntilClose,
            ),
            (b"HTTP/1.1 200 OK", false, BodyLength::UntilClose),
            (b"HTTP/1.1 204 No Content", false, BodyLength::None),
            (
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 7",
                false,
                BodyLength::None,
            ),
        ] {
            assert_eq!(
                rewrite_response(head, head_only).unwrap().body,
                body,
                "{head:?} head_only={head_only}"
            );
        }
    }

    #[tokio::test]
    async fn a_chunked_body_that_breaks_its_framing_is_malformed_http() {
        for body in [&b"zz\r\n"[..], b"5\r\nhelloXX", b"5\r\nhel"] {
            let mut sink = Vec::new();
            let result = relay_chunked(&mut received(body), &mut sink).await;
            assert!(
                matches!(result, Err(RelayError::Read(NetError::MalformedHttp))),
                "{body:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_body_shorter_than_its_length_is_malformed_http() {
        let mut sink = Vec::new();
        let result = copy_exactly(&mut received(b"0123"), &mut sink, 10).await;
        assert!(matches!(
            result,
            Err(RelayError::Read(NetError::MalformedHttp))
        ));
        assert_eq!(sink, b"0123", "what did arrive went on");
    }

    #[tokio::test]
    async fn the_wiped_reader_yields_the_early_bytes_then_the_stream() {
        let mut from = WipedReader::new(Cursor::new(b" world".to_vec()), b"hello");
        let mut all = Vec::new();
        from.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"hello world");
    }
}
