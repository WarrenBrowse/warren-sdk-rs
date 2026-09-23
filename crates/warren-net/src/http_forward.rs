//! Plain-HTTP forwarding on the local HTTP proxy listener.
//!
//! A client pointed at an HTTP proxy tunnels `https://` through `CONNECT`, but
//! hands a plain `http://` request to the proxy itself, in absolute form
//! (`GET http://host/path HTTP/1.1`). The listener carries exactly one such
//! request per client connection: it rewrites the head to origin form for the
//! target, drops every hop-by-hop field (the client's `Proxy-Authorization`
//! first among them), relays the body by its own framing, and relays the
//! response with its hop-by-hop fields dropped and `Connection: close`.
//!
//! One request per connection is what keeps the session secret on this
//! machine: nothing the client sends after the request it authenticated is
//! forwarded, so a second, pipelined request and its own `Proxy-Authorization`
//! never reach the origin. `Connection: close` tells the client to open a new
//! connection, where it authenticates again.
//!
//! A head that a lenient origin could read differently from this parser (a
//! bare CR or LF inside a line, a folded line, conflicting body lengths) is
//! refused: a header this parser saw as one line must not become two upstream.

use std::io::{Cursor, ErrorKind};

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::TcpStream;

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
/// whatever a `Connection` field lists, or the origin would read the body as
/// the next request.
const FRAMING: [&str; 2] = ["content-length", "transfer-encoding"];

/// Longest response head accepted from an origin (it carries its cookies).
const MAX_RESPONSE_HEAD: u64 = 64 * 1024;

/// Longest chunk-size line, and the most trailer bytes, accepted in a chunked
/// request body.
const MAX_CHUNK_LINE: u64 = 4 * 1024;

/// The answer to a head this proxy refuses to forward.
pub(crate) const BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The answer when the origin said nothing a client can be handed.
const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// A request head this proxy will not forward.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed;

/// How much body follows a request head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyLength {
    None,
    Exactly(u64),
    Chunked,
}

/// A request rewritten for its origin.
#[derive(Debug)]
pub(crate) struct ForwardRequest {
    target: Target,
    /// The origin-form head, terminated, with no hop-by-hop field.
    head: Vec<u8>,
    body: BodyLength,
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

/// The lowercased field names a `Connection` value lists.
fn listed_names(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(',')
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
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
    let has_port = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed.contains("]:"),
        None => authority.contains(':'),
    };
    let with_port = if has_port {
        authority.to_owned()
    } else {
        format!("{authority}:80")
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
/// a control character or a bare CR or LF inside a line, a folded or unnamed
/// field line, a target that is not `http://host[:port]`, a version other
/// than HTTP/1.0 or HTTP/1.1, or a body length that is invalid, repeated with
/// different values, or given by both `Content-Length` and
/// `Transfer-Encoding`, or a transfer coding other than `chunked`.
pub(crate) fn rewrite_request(head: &str) -> Result<ForwardRequest, Malformed> {
    let mut lines = head.split("\r\n");
    let all_lines = lines.clone();
    if all_lines
        .flat_map(str::bytes)
        .any(|b| b == 0x7f || (b < 0x20 && b != b'\t'))
    {
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
    if !is_token(method.as_bytes()) || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
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

    let body = body_length(&fields)?;
    let mut dropped: Vec<String> = fields
        .iter()
        .filter(|(name, _, _)| name == "connection" || name == "proxy-connection")
        .flat_map(|(_, value, _)| listed_names(value))
        .filter(|name| !FRAMING.contains(&name.as_str()))
        .collect();
    dropped.extend(HOP_BY_HOP.iter().map(|name| (*name).to_owned()));
    // Host is replaced by the target's (RFC 9112 section 3.2.2), and the
    // trailer fields a `Trailer` field announces are not forwarded.
    dropped.extend(["host".to_owned(), "trailer".to_owned()]);

    let mut out = format!("{method} {origin_form} {version}\r\nHost: {authority}\r\n");
    for (name, _, line) in &fields {
        if !dropped.contains(name) {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out.push_str("Connection: close\r\n\r\n");
    Ok(ForwardRequest {
        target,
        head: out.into_bytes(),
        body,
    })
}

/// The request body length its framing fields declare (RFC 9112 section 6.3).
fn body_length(fields: &[(String, &str, &str)]) -> Result<BodyLength, Malformed> {
    let mut length = None;
    let mut codings = 0;
    for (name, value, _) in fields {
        match name.as_str() {
            "content-length" => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Malformed);
                }
                let parsed: u64 = value.parse().map_err(|_| Malformed)?;
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

/// Carries `request` to its origin through `connector` and relays the answer.
/// `early_data` is what the client sent after the head while it was read.
///
/// # Errors
///
/// A [`NetError`] when the origin cannot be reached (the client is told so by
/// this proxy first), or either side fails mid-exchange.
pub(crate) async fn forward<C: Connector>(
    client: &mut TcpStream,
    early_data: Vec<u8>,
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
    upstream
        .write_all(&request.head)
        .await
        .map_err(NetError::Io)?;

    let (client_read, mut client_write) = client.split();
    let mut from_client = BufReader::new(Cursor::new(early_data).chain(client_read));
    let (upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let mut from_upstream = BufReader::new(upstream_read);

    let upload = async {
        relay_body(&mut from_client, &mut upstream_write, request.body).await?;
        discard_until_closed(&mut from_client).await?;
        // The client half-closed after its request: pass that on, and wait for
        // the answer, which is what ends the exchange.
        upstream_write.shutdown().await.map_err(NetError::Io)?;
        std::future::pending::<Result<(), NetError>>().await
    };
    let download = relay_response(&mut from_upstream, &mut client_write);
    tokio::select! {
        result = upload => result,
        result = download => result,
    }
}

async fn relay_body<R, W>(from: &mut R, to: &mut W, body: BodyLength) -> Result<(), NetError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body {
        BodyLength::None => Ok(()),
        BodyLength::Exactly(length) => copy_exactly(from, to, length).await,
        BodyLength::Chunked => relay_chunked(from, to).await,
    }
}

fn invalid() -> NetError {
    NetError::Io(ErrorKind::InvalidData.into())
}

async fn copy_exactly<R, W>(from: &mut R, to: &mut W, length: u64) -> Result<(), NetError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy_buf(&mut from.take(length), to)
        .await
        .map_err(NetError::Io)?;
    if copied == length {
        Ok(())
    } else {
        Err(NetError::Io(ErrorKind::UnexpectedEof.into()))
    }
}

/// Reads one CRLF-terminated line of at most `max` bytes, terminator included.
async fn read_crlf_line<R: AsyncBufRead + Unpin>(
    from: &mut R,
    max: u64,
) -> Result<Vec<u8>, NetError> {
    let mut line = Vec::new();
    (&mut *from)
        .take(max)
        .read_until(b'\n', &mut line)
        .await
        .map_err(NetError::Io)?;
    if line.ends_with(b"\r\n") && !line[..line.len() - 2].contains(&b'\r') {
        Ok(line)
    } else {
        Err(invalid())
    }
}

/// Relays a chunked body chunk by chunk, as sent, and stops at its last
/// chunk. The trailer fields are dropped: they sit where a client could slip a
/// field this proxy never inspects.
async fn relay_chunked<R, W>(from: &mut R, to: &mut W) -> Result<(), NetError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let line = read_crlf_line(from, MAX_CHUNK_LINE).await?;
        let size = chunk_size(&line[..line.len() - 2]).ok_or_else(invalid)?;
        to.write_all(&line).await.map_err(NetError::Io)?;
        if size == 0 {
            break;
        }
        copy_exactly(from, to, size).await?;
        let mut end = [0u8; 2];
        from.read_exact(&mut end).await.map_err(NetError::Io)?;
        if &end != b"\r\n" {
            return Err(invalid());
        }
        to.write_all(&end).await.map_err(NetError::Io)?;
    }
    let mut trailers = 0;
    loop {
        let line = read_crlf_line(from, MAX_CHUNK_LINE).await?;
        if line == b"\r\n" {
            break;
        }
        trailers += line.len() as u64;
        if trailers > MAX_CHUNK_LINE {
            return Err(invalid());
        }
    }
    to.write_all(b"\r\n").await.map_err(NetError::Io)
}

/// The size a chunk-size line declares: hex digits, then optional extensions.
fn chunk_size(line: &[u8]) -> Option<u64> {
    let digits = line
        .iter()
        .position(|b| !b.is_ascii_hexdigit())
        .map_or(line, |end| &line[..end]);
    let rest = &line[digits.len()..];
    if digits.is_empty() || digits.len() > 15 || !(rest.is_empty() || rest.starts_with(b";")) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
}

/// Reads and drops whatever the client sends after its request, so none of it
/// is forwarded, until the client closes its sending side.
async fn discard_until_closed<R: AsyncRead + Unpin>(from: &mut R) -> Result<(), NetError> {
    let mut sink = [0u8; 1024];
    loop {
        if from.read(&mut sink).await.map_err(NetError::Io)? == 0 {
            return Ok(());
        }
    }
}

/// A response head rewritten for the client.
#[derive(Debug, PartialEq, Eq)]
struct ResponseHead {
    bytes: Vec<u8>,
    /// A 1xx other than 101: the final response still follows.
    interim: bool,
}

/// Rewrites a response head (status line and fields, without the blank line)
/// for the client, or `None` when it is not one a client can be handed.
///
/// An origin's `407` becomes a `502`: on this connection a `407` must only ever
/// be this proxy asking for its own credentials, or a client would answer an
/// origin's challenge with them.
fn rewrite_response(head: &[u8]) -> Option<ResponseHead> {
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
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

    let mut fields = Vec::new();
    for line in lines {
        let colon = line.iter().position(|&b| b == b':')?;
        if !is_token(&line[..colon]) {
            return None;
        }
        let name = String::from_utf8_lossy(&line[..colon]).to_ascii_lowercase();
        fields.push((name, &line[colon + 1..], line));
    }
    let mut dropped: Vec<String> = fields
        .iter()
        .filter(|(name, _, _)| name == "connection" || name == "proxy-connection")
        .flat_map(|(_, value, _)| listed_names(&String::from_utf8_lossy(value)).collect::<Vec<_>>())
        .filter(|name| !FRAMING.contains(&name.as_str()))
        .collect();
    dropped.extend(HOP_BY_HOP.iter().map(|name| (*name).to_owned()));

    let mut out = if code == 407 {
        let mut line = version.to_vec();
        line.extend_from_slice(b" 502 Bad Gateway");
        line
    } else {
        status_line.to_vec()
    };
    out.extend_from_slice(b"\r\n");
    for (name, _, line) in &fields {
        if !dropped.contains(name) {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
    let interim = (100..200).contains(&code) && code != 101;
    if !interim {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Some(ResponseHead {
        bytes: out,
        interim,
    })
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
/// the body as it comes until the origin closes.
async fn relay_response<R, W>(from: &mut R, to: &mut W) -> Result<(), NetError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let Some(head) = read_response_head(from)
            .await
            .as_deref()
            .and_then(rewrite_response)
        else {
            let _ = to.write_all(BAD_GATEWAY).await;
            return Err(invalid());
        };
        to.write_all(&head.bytes).await.map_err(NetError::Io)?;
        if !head.interim {
            break;
        }
    }
    tokio::io::copy_buf(from, to).await.map_err(NetError::Io)?;
    to.shutdown().await.map_err(NetError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewritten(head: &str) -> (Target, String, BodyLength) {
        let request = rewrite_request(head).expect("forwardable");
        (
            request.target,
            String::from_utf8(request.head).unwrap(),
            request.body,
        )
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
            "GET http://2001:db8::1/ HTTP/1.1",
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
        ] {
            assert_eq!(rewrite_request(head).unwrap_err(), Malformed, "{head:?}");
        }
    }

    #[test]
    fn a_repeated_identical_length_is_one_length() {
        let (_, _, body) = rewritten(
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4",
        );
        assert_eq!(body, BodyLength::Exactly(4));
    }

    #[test]
    fn chunk_sizes_parse_as_hex_with_extensions() {
        assert_eq!(chunk_size(b"1a"), Some(26));
        assert_eq!(chunk_size(b"0"), Some(0));
        assert_eq!(chunk_size(b"5;name=value"), Some(5));
        assert_eq!(chunk_size(b""), None);
        assert_eq!(chunk_size(b"5 junk"), None);
        assert_eq!(chunk_size(b"-5"), None);
        assert_eq!(chunk_size(b"1000000000000000"), None, "sixteen digits");
    }

    #[test]
    fn a_response_head_that_is_not_http_1_is_refused() {
        for head in [
            &b"ICY 200 OK"[..],
            b"HTTP/1.1 2000 OK",
            b"HTTP/1.1 20x OK",
            b"HTTP/1.1 200 OK\r\nno colon here",
            b"HTTP/1.1 200 OK\r\nX-A: 1\r\n folded",
        ] {
            assert_eq!(rewrite_response(head), None, "{head:?}");
        }
    }

    #[test]
    fn response_lines_end_in_crlf_whichever_ending_the_origin_used() {
        let head = rewrite_response(b"HTTP/1.1 204 No Content\r\nX-A: 1\nX-B: 2").unwrap();
        assert_eq!(
            head.bytes,
            b"HTTP/1.1 204 No Content\r\nX-A: 1\r\nX-B: 2\r\nConnection: close\r\n\r\n"
        );
        assert!(!head.interim);
    }

    #[test]
    fn switching_protocols_is_a_final_response() {
        let head = rewrite_response(b"HTTP/1.1 101 Switching Protocols").unwrap();
        assert!(!head.interim);
    }
}
