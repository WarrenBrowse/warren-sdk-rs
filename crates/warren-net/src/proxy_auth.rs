//! Access control for the local SOCKS5 and HTTP CONNECT listeners.
//!
//! A loopback listener is reachable by every account and every process on the
//! host: another user, a container sharing the host network, a web page that
//! reached `127.0.0.1` through DNS rebinding. Left open, it is a proxy carrying
//! the member's Warren identity for whoever finds it. So every connection
//! presents a per-session secret before anything is forwarded (RFC 1929
//! username/password on SOCKS5, `Proxy-Authorization: Basic` on HTTP CONNECT),
//! and no server in this crate has an unauthenticated mode.
//!
//! The password authenticates the client to the listener, and nothing in it
//! authenticates the listener to the client: a process that took over a
//! released port accepts any password. A consumer that learns a listener
//! address from elsewhere (a state file, an environment variable) therefore
//! asks the listener to prove it holds the secret before handing it the
//! password ([`prove_socks5_listener`], [`prove_http_listener`]). The proof is
//! an HMAC-SHA256 of a fresh client nonce keyed by the password and bound to
//! the listener's protocol, so a squatter can neither replay one nor relay the
//! nonce to the session's other, still-live listener and pass its answer off.
//!
//! Every exchange is in clear: on a non-loopback bind the password crosses the
//! network as RFC 1929 and Basic carry it, and anyone who can reach the port
//! can ask for proofs. A password an operator chooses must be long and random.

use std::net::SocketAddr;

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::socks5::{
    self, METHOD_USERPASS, METHOD_WARREN_PROOF, Target, USERPASS_VERSION, VERSION,
};

/// The username [`ProxyCredentials::generate`] uses. The password carries the
/// entropy; a fixed username keeps every generated credential the same shape.
pub const DEFAULT_USERNAME: &str = "warren";

/// Entropy of a generated password, in bytes (256 bits).
const SECRET_BYTES: usize = 32;

/// Longest username or password RFC 1929 can carry (one length byte).
const MAX_FIELD_LEN: usize = 255;

/// Domain separation for the listener proof, so the HMAC can never be confused
/// with any other use of the same key.
const PROOF_LABEL: &[u8] = b"warren-local-proxy-proof/v1";

/// Length of the nonce a client sends to ask for a proof.
pub const PROOF_NONCE_LEN: usize = 32;

/// Length of the proof a listener answers with (HMAC-SHA256).
pub const PROOF_LEN: usize = 32;

/// The HTTP method a client uses to ask the HTTP CONNECT listener for a proof.
/// An extension method token, so no ordinary client ever sends it.
pub const HTTP_PROOF_METHOD: &str = "WARREN-PROOF";

/// The response header carrying the proof, lowercase hex.
pub const HTTP_PROOF_HEADER: &str = "Warren-Proof";

/// Which listener a proof speaks for. The two listeners share one password, so
/// the proof names its protocol: a squatter on one port cannot answer by
/// relaying the challenge to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerKind {
    /// The SOCKS5 listener (private method `0x80`).
    Socks5,
    /// The HTTP CONNECT listener (method [`HTTP_PROOF_METHOD`]).
    Http,
}

impl ListenerKind {
    fn tag(self) -> &'static [u8] {
        match self {
            ListenerKind::Socks5 => b"socks5",
            ListenerKind::Http => b"http",
        }
    }
}

/// A rejected credential. The variants name the field and never its value.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialsError {
    /// Empty, longer than 255 bytes, carrying a control character, or carrying
    /// a colon (HTTP Basic cannot represent one in the username).
    #[error("invalid proxy username")]
    Username,
    /// Empty, longer than 255 bytes, or carrying a control character.
    #[error("invalid proxy password")]
    Password,
}

/// The username and password a client presents to the local listeners.
///
/// The password is zeroized on drop and never rendered by `Debug`.
#[derive(Clone)]
pub struct ProxyCredentials {
    username: String,
    password: Zeroizing<String>,
}

impl std::fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

fn valid_field(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_FIELD_LEN && !value.chars().any(char::is_control)
}

impl ProxyCredentials {
    /// Fresh credentials for one session: [`DEFAULT_USERNAME`] and a password of
    /// 256 bits from the operating system's CSPRNG, hex-encoded so it needs no
    /// escaping in a proxy URL.
    #[must_use]
    pub fn generate() -> Self {
        let mut secret = Zeroizing::new([0u8; SECRET_BYTES]);
        rand::rngs::OsRng.fill_bytes(secret.as_mut());
        Self {
            username: DEFAULT_USERNAME.to_owned(),
            password: Zeroizing::new(hex::encode(&secret[..])),
        }
    }

    /// Operator-chosen credentials (a daemon whose clients are configured by
    /// hand).
    ///
    /// # Errors
    ///
    /// [`CredentialsError::Username`] or [`CredentialsError::Password`] when a
    /// field cannot be carried by both RFC 1929 and HTTP Basic.
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, CredentialsError> {
        let username = username.into();
        let password = Zeroizing::new(password.into());
        if !valid_field(&username) || username.contains(':') {
            return Err(CredentialsError::Username);
        }
        if !valid_field(&password) {
            return Err(CredentialsError::Password);
        }
        Ok(Self { username, password })
    }

    /// The username.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The password. Hand it only to a client of this session's listeners.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    /// A proxy URL carrying these credentials, `scheme://user:password@addr`,
    /// with the userinfo percent-encoded. It holds the secret: keep it out of
    /// argv, logs and anything another account can read.
    #[must_use]
    pub fn proxy_url(&self, scheme: &str, addr: SocketAddr) -> Zeroizing<String> {
        let password = Zeroizing::new(percent_encode_userinfo(&self.password));
        Zeroizing::new(format!(
            "{scheme}://{}:{}@{addr}",
            percent_encode_userinfo(&self.username),
            &*password,
        ))
    }

    /// The `Proxy-Authorization` value a client sends, `Basic <base64>`.
    #[must_use]
    pub fn basic_authorization(&self) -> Zeroizing<String> {
        let pair = Zeroizing::new(format!("{}:{}", self.username, &*self.password));
        let encoded = Zeroizing::new(data_encoding::BASE64.encode(pair.as_bytes()));
        Zeroizing::new(format!("Basic {}", &*encoded))
    }

    /// Whether a presented username and password are these. Both fields are
    /// compared through their SHA-256 digests in constant time, so the answer's
    /// timing says nothing about which field, which prefix or which length was
    /// wrong.
    #[must_use]
    pub fn matches(&self, username: &[u8], password: &[u8]) -> bool {
        let digest = |bytes: &[u8]| Zeroizing::new(<[u8; 32]>::from(Sha256::digest(bytes)));
        let user_ok = digest(username).ct_eq(&*digest(self.username.as_bytes()));
        let pass_ok = digest(password).ct_eq(&*digest(self.password.as_bytes()));
        (user_ok & pass_ok).into()
    }

    /// Whether a `Proxy-Authorization` header value carries these credentials.
    /// Anything that is not well-formed `Basic` is a mismatch.
    #[must_use]
    pub fn matches_basic(&self, header_value: &str) -> bool {
        let Some((scheme, encoded)) = header_value.trim().split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Ok(decoded) = data_encoding::BASE64.decode(encoded.trim().as_bytes()) else {
            return false;
        };
        let decoded = Zeroizing::new(decoded);
        let Some(colon) = decoded.iter().position(|&b| b == b':') else {
            return false;
        };
        self.matches(&decoded[..colon], &decoded[colon + 1..])
    }

    /// The proof of possession the `kind` listener answers to `nonce`.
    #[must_use]
    pub fn proof(&self, kind: ListenerKind, nonce: &[u8; PROOF_NONCE_LEN]) -> [u8; PROOF_LEN] {
        self.proof_mac(kind, nonce).finalize().into_bytes().into()
    }

    /// Whether `proof` is the `kind` listener's answer to `nonce` under these
    /// credentials, compared in constant time.
    #[must_use]
    pub fn verify_proof(
        &self,
        kind: ListenerKind,
        nonce: &[u8; PROOF_NONCE_LEN],
        proof: &[u8],
    ) -> bool {
        self.proof_mac(kind, nonce).verify_slice(proof).is_ok()
    }

    fn proof_mac(&self, kind: ListenerKind, nonce: &[u8; PROOF_NONCE_LEN]) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.password.as_bytes())
            .expect("HMAC accepts a key of any length");
        mac.update(PROOF_LABEL);
        mac.update(kind.tag());
        mac.update(&[0]);
        mac.update(nonce);
        mac
    }
}

/// Percent-encodes everything outside RFC 3986's unreserved set, which is what
/// userinfo needs for a password with arbitrary characters to survive a URL.
fn percent_encode_userinfo(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A failed SOCKS5 client exchange. `Display` carries protocol detail only.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Socks5ClientError {
    /// The proxy could not be reached or the stream failed.
    #[error("socks5 proxy unreachable")]
    Io(#[source] std::io::Error),
    /// The proxy did not select username/password authentication.
    #[error("socks5 proxy refused username/password authentication")]
    MethodRefused,
    /// The proxy rejected the credentials.
    #[error("socks5 proxy rejected the credentials")]
    AuthRefused,
    /// The proxy answered the CONNECT with a failure reply code.
    #[error("SOCKS5 CONNECT rejected (rep={0})")]
    ConnectRejected(u8),
    /// The proxy answered something that is not SOCKS5.
    #[error("malformed socks5 reply")]
    Malformed,
}

/// Opens an authenticated SOCKS5 `CONNECT` to `target` through `proxy`,
/// returning the stream once the proxy reports success.
///
/// # Errors
///
/// [`Socks5ClientError::Io`] when the proxy cannot be reached,
/// [`Socks5ClientError::MethodRefused`] or [`Socks5ClientError::AuthRefused`]
/// when it does not accept these credentials,
/// [`Socks5ClientError::ConnectRejected`] with the RFC 1928 reply code when the
/// connect fails, [`Socks5ClientError::Malformed`] on a non-SOCKS5 answer.
pub async fn socks5_connect(
    proxy: SocketAddr,
    credentials: &ProxyCredentials,
    target: &Target,
) -> Result<TcpStream, Socks5ClientError> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(Socks5ClientError::Io)?;
    socks5_authenticate(&mut stream, credentials).await?;
    stream
        .write_all(&socks5::build_request(socks5::Command::Connect, target))
        .await
        .map_err(Socks5ClientError::Io)?;
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(Socks5ClientError::Io)?;
    if head[0] != VERSION {
        return Err(Socks5ClientError::Malformed);
    }
    if head[1] != 0x00 {
        return Err(Socks5ClientError::ConnectRejected(head[1]));
    }
    // Drain BND.ADDR and BND.PORT so the stream starts at the relayed bytes.
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(Socks5ClientError::Io)?;
            usize::from(len[0])
        }
        _ => return Err(Socks5ClientError::Malformed),
    };
    let mut bound = vec![0u8; addr_len + 2];
    stream
        .read_exact(&mut bound)
        .await
        .map_err(Socks5ClientError::Io)?;
    Ok(stream)
}

async fn socks5_authenticate(
    stream: &mut TcpStream,
    credentials: &ProxyCredentials,
) -> Result<(), Socks5ClientError> {
    stream
        .write_all(&[VERSION, 0x01, METHOD_USERPASS])
        .await
        .map_err(Socks5ClientError::Io)?;
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(Socks5ClientError::Io)?;
    if method != [VERSION, METHOD_USERPASS] {
        return Err(Socks5ClientError::MethodRefused);
    }
    let request = Zeroizing::new(socks5::build_userpass_request(
        credentials.username.as_bytes(),
        credentials.password.as_bytes(),
    ));
    stream
        .write_all(&request)
        .await
        .map_err(Socks5ClientError::Io)?;
    let mut status = [0u8; 2];
    stream
        .read_exact(&mut status)
        .await
        .map_err(Socks5ClientError::Io)?;
    if status != [USERPASS_VERSION, 0x00] {
        return Err(Socks5ClientError::AuthRefused);
    }
    Ok(())
}

/// Why a listener was not accepted as the holder of a session's credentials.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ListenerProofError {
    /// Nothing answered, or the stream failed before a proof arrived.
    #[error("the proxy listener is unreachable")]
    Io(#[source] std::io::Error),
    /// Something answered without the right proof: the listener at this address
    /// is not the one these credentials belong to.
    #[error("the proxy listener did not prove it holds this session's credentials")]
    NotOurs,
}

fn fresh_nonce() -> [u8; PROOF_NONCE_LEN] {
    let mut nonce = [0u8; PROOF_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Asks the SOCKS5 listener at `proxy` to prove it holds `credentials`, without
/// sending them. Wrap it in a timeout: a squatter can accept and stay silent.
///
/// # Errors
///
/// [`ListenerProofError::Io`] when nothing usable answered,
/// [`ListenerProofError::NotOurs`] when the answer is not the proof.
pub async fn prove_socks5_listener(
    proxy: SocketAddr,
    credentials: &ProxyCredentials,
) -> Result<(), ListenerProofError> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(ListenerProofError::Io)?;
    stream
        .write_all(&[VERSION, 0x01, METHOD_WARREN_PROOF])
        .await
        .map_err(ListenerProofError::Io)?;
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(ListenerProofError::Io)?;
    if method != [VERSION, METHOD_WARREN_PROOF] {
        return Err(ListenerProofError::NotOurs);
    }
    let nonce = fresh_nonce();
    stream
        .write_all(&nonce)
        .await
        .map_err(ListenerProofError::Io)?;
    let mut proof = [0u8; PROOF_LEN];
    match stream.read_exact(&mut proof).await {
        Ok(_) => {}
        // A listener that hung up instead of answering is not ours either.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ListenerProofError::NotOurs);
        }
        Err(e) => return Err(ListenerProofError::Io(e)),
    }
    if credentials.verify_proof(ListenerKind::Socks5, &nonce, &proof) {
        Ok(())
    } else {
        Err(ListenerProofError::NotOurs)
    }
}

/// Longest proof response head accepted from an HTTP listener.
const MAX_PROOF_RESPONSE: usize = 4 * 1024;

/// Asks the HTTP CONNECT listener at `proxy` to prove it holds `credentials`,
/// without sending them. Wrap it in a timeout: a squatter can accept and stay
/// silent.
///
/// # Errors
///
/// [`ListenerProofError::Io`] when nothing answered,
/// [`ListenerProofError::NotOurs`] when the answer is not the proof.
pub async fn prove_http_listener(
    proxy: SocketAddr,
    credentials: &ProxyCredentials,
) -> Result<(), ListenerProofError> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(ListenerProofError::Io)?;
    let nonce = fresh_nonce();
    let request = format!(
        "{HTTP_PROOF_METHOD} {} HTTP/1.1\r\n\r\n",
        hex::encode(nonce)
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(ListenerProofError::Io)?;
    let mut response = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    while !response.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(ListenerProofError::Io)?;
        if n == 0 || response.len() > MAX_PROOF_RESPONSE {
            return Err(ListenerProofError::NotOurs);
        }
        response.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&response);
    let mut lines = text.split("\r\n");
    if !lines.next().is_some_and(|l| l.starts_with("HTTP/1.1 200 ")) {
        return Err(ListenerProofError::NotOurs);
    }
    let proof = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case(HTTP_PROOF_HEADER))
        .and_then(|(_, value)| hex::decode(value.trim()).ok());
    match proof {
        Some(proof) if credentials.verify_proof(ListenerKind::Http, &nonce, &proof) => Ok(()),
        _ => Err(ListenerProofError::NotOurs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed() -> ProxyCredentials {
        ProxyCredentials::new("warren", "correct horse battery staple").unwrap()
    }

    #[test]
    fn generated_credentials_carry_256_bits_and_differ_every_time() {
        let a = ProxyCredentials::generate();
        let b = ProxyCredentials::generate();
        assert_eq!(a.username(), DEFAULT_USERNAME);
        assert_eq!(a.password().len(), 2 * SECRET_BYTES, "hex of 32 bytes");
        assert!(a.password().bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a.password(), b.password(), "a fresh secret per session");
    }

    #[test]
    fn debug_never_renders_the_password() {
        let creds = ProxyCredentials::generate();
        let rendered = format!("{creds:?}");
        assert!(!rendered.contains(creds.password()), "{rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn matches_needs_both_fields_exactly() {
        let creds = fixed();
        assert!(creds.matches(b"warren", b"correct horse battery staple"));
        assert!(!creds.matches(b"warren", b"correct horse battery stapl"));
        assert!(!creds.matches(b"warren", b"correct horse battery staplf"));
        assert!(!creds.matches(b"warreN", b"correct horse battery staple"));
        assert!(!creds.matches(b"", b""));
    }

    #[test]
    fn matches_basic_accepts_only_well_formed_basic_with_these_credentials() {
        let creds = ProxyCredentials::new("warren", "s3cret").unwrap();
        // base64("warren:s3cret"), computed independently.
        assert!(creds.matches_basic("Basic d2FycmVuOnMzY3JldA=="));
        assert!(creds.matches_basic("basic d2FycmVuOnMzY3JldA=="));
        assert!(creds.matches_basic("  BASIC   d2FycmVuOnMzY3JldA==  "));
        assert!(!creds.matches_basic("Bearer d2FycmVuOnMzY3JldA=="));
        assert!(!creds.matches_basic("Basic not-base64!"));
        assert!(!creds.matches_basic("Basic d2FycmVu"), "no colon");
        assert!(!creds.matches_basic("Basic"));
        assert!(!creds.matches_basic(""));
        assert!(creds.matches_basic(&creds.basic_authorization()));
    }

    #[test]
    fn a_password_may_contain_a_colon_but_a_username_may_not() {
        let creds = ProxyCredentials::new("u", "a:b").unwrap();
        assert!(creds.matches_basic(&creds.basic_authorization()));
        assert_eq!(
            ProxyCredentials::new("a:b", "p").unwrap_err(),
            CredentialsError::Username
        );
    }

    #[test]
    fn new_refuses_fields_rfc_1929_or_basic_cannot_carry() {
        assert_eq!(
            ProxyCredentials::new("", "p").unwrap_err(),
            CredentialsError::Username
        );
        assert_eq!(
            ProxyCredentials::new("u\n", "p").unwrap_err(),
            CredentialsError::Username
        );
        assert_eq!(
            ProxyCredentials::new("u", "").unwrap_err(),
            CredentialsError::Password
        );
        assert_eq!(
            ProxyCredentials::new("u", "x".repeat(256)).unwrap_err(),
            CredentialsError::Password
        );
        assert_eq!(
            ProxyCredentials::new("u", "p\u{7}").unwrap_err(),
            CredentialsError::Password
        );
        assert!(ProxyCredentials::new("u".repeat(255), "p".repeat(255)).is_ok());
    }

    #[test]
    fn the_error_never_names_the_rejected_value() {
        let err = ProxyCredentials::new("u", "hunter2\n").unwrap_err();
        assert!(!err.to_string().contains("hunter2"));
    }

    #[test]
    fn proxy_url_percent_encodes_the_userinfo() {
        let creds = ProxyCredentials::new("us er", "p@ss:w/rd%").unwrap();
        let url = creds.proxy_url("http", "127.0.0.1:8080".parse().unwrap());
        assert_eq!(&*url, "http://us%20er:p%40ss%3Aw%2Frd%25@127.0.0.1:8080");
        let generated = ProxyCredentials::generate();
        let url = generated.proxy_url("socks5", "127.0.0.1:1080".parse().unwrap());
        assert_eq!(
            &*url,
            &format!("socks5://warren:{}@127.0.0.1:1080", generated.password())
        );
    }

    #[test]
    fn the_proof_is_the_pinned_hmac_of_the_label_the_protocol_and_the_nonce() {
        // Computed with an independent HMAC-SHA256 implementation (Python's
        // hmac module, over label || tag || 0x00 || nonce): the local proof
        // protocol between a launcher and this listener must not drift.
        let nonce: [u8; PROOF_NONCE_LEN] = std::array::from_fn(|i| i as u8);
        assert_eq!(
            hex::encode(fixed().proof(ListenerKind::Socks5, &nonce)),
            "e3e2bf25be42633e6ed2df74aefc97b0695c493795e8ea70928ab38fec2a0db1"
        );
        assert_eq!(
            hex::encode(fixed().proof(ListenerKind::Http, &nonce)),
            "899170bd64a5486a0931dc26bc26aec717146e48fdeb2c10a8f9e2ccf7cbd2b2"
        );
    }

    #[test]
    fn verify_proof_refuses_another_key_nonce_or_protocol() {
        let creds = fixed();
        let nonce = [7u8; PROOF_NONCE_LEN];
        let proof = creds.proof(ListenerKind::Socks5, &nonce);
        assert!(creds.verify_proof(ListenerKind::Socks5, &nonce, &proof));
        assert!(!creds.verify_proof(ListenerKind::Socks5, &[8u8; PROOF_NONCE_LEN], &proof));
        assert!(!ProxyCredentials::generate().verify_proof(ListenerKind::Socks5, &nonce, &proof));
        assert!(!creds.verify_proof(ListenerKind::Socks5, &nonce, &proof[..31]));
        assert!(
            !creds.verify_proof(ListenerKind::Http, &nonce, &proof),
            "a SOCKS5 proof relayed to an HTTP challenge must not pass"
        );
    }

    #[test]
    fn matches_refuses_a_prefix_or_an_extension_of_either_field() {
        let creds = fixed();
        assert!(!creds.matches(b"warren", b"correct horse battery staple!"));
        assert!(!creds.matches(b"warre", b"correct horse battery staple"));
    }
}
