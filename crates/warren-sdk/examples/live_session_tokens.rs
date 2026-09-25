//! Real-exit proof that the SDK's sessions are admitted on anonymous v7 tokens,
//! that two concurrent sessions of one wallet both come up, and that a dial
//! walks past a token whose serial a live session holds elsewhere.
//!
//! Run (beta): `WARREN_API_URL=https://api.beta.warrenbrowse.com
//! WARREN_MNEMONIC="word1 ... word12" cargo run -p warren-sdk --example
//! live_session_tokens`
//!
//! Needs a subscribed wallet and two exits. It opens at most four dials and
//! makes a handful of API calls, then tears everything down. Nothing it prints
//! names a token, a serial or the wallet beyond its public address.
//!
//! `WARREN_TOKENS_ONLY=1` dials under [`SessionAdmission::TokensOnly`], so a
//! session can only come up on a token. Without it the default policy runs,
//! and a wallet the issuer serves no token (its epoch taken by another batch)
//! shows the wallet-signed fallback instead, with step 2 skipped.
//!
//! 1. Session A: `connect_multihop` to exit X.
//! 2. Session C: a raw tunnel to exit Y whose stack leads with A's token, the
//!    way another device of the wallet would when it starts where A did. Exit
//!    Y must refuse it (the serial is leased to A on X) and admit the next one.
//! 3. Session B: `start_proxy` to exit Y, a second session of A's client,
//!    concurrent with A. It must come up on a token too, and an HTTPS IP echo
//!    fetched through it (by `curl`, over the session's SOCKS5 listener) must
//!    answer with an address that is not this host's.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use warren_sdk::api::{BlindingKey, ReqwestTransport, TokenManager, WarrenApiClient};
use warren_sdk::identity::{WarrenIdentity, seed_from_mnemonic};
use warren_sdk::net::ProxyConfig;
use warren_sdk::transport::{MultihopClientTunnel, SessionToken, SessionTokenSource, TokenHold};
use warren_sdk::{Circuit, SessionAdmission, WarrenClient};

/// HTTPS IP echo, answering with the caller's address as the whole body.
const ECHO_URL: &str = "https://api.ipify.org";

/// A fixed stack that counts the tokens a dial claims, standing in for a
/// second device of the wallet: it shares nothing with the client's leases.
struct ForcedStack {
    stack: Vec<SessionToken>,
    claims: AtomicUsize,
}

impl SessionTokenSource for ForcedStack {
    fn stack(&self) -> Vec<SessionToken> {
        self.stack.clone()
    }

    fn claim(&self, _token: &SessionToken) -> Option<TokenHold> {
        self.claims.fetch_add(1, Ordering::SeqCst);
        Some(TokenHold::new(()))
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's words")?;
    let api_base = std::env::var(warren_sdk::product::API_URL_ENV)
        .unwrap_or_else(|_| warren_sdk::product::API_URL.to_owned());
    let identity = WarrenIdentity::from_mnemonic(phrase.trim())?;
    let address = identity.address();
    println!("wallet {}.. against {api_base}", &address[..8]);

    let client = WarrenClient::builder()
        .identity(identity)
        .api_base(api_base.clone())
        .server_pubkey_pin(warren_sdk::product::SERVER_PUBKEY_HEX)
        .session_admission(admission())
        .build()?;
    let selector = client.fetch_exits().await?;
    let exits: Vec<_> = client
        .fetch_multihop_directory()
        .await?
        .into_iter()
        .filter(|e| {
            selector
                .relays()
                .iter()
                .any(|r| r.endpoint_id() == e.exit_ed25519_pubkey)
        })
        .collect();
    let [exit_x, exit_y, ..] = exits.as_slice() else {
        return Err(format!("need two cross-checked exits, found {}", exits.len()).into());
    };
    println!("exit X: {} / {}", exit_x.country, exit_x.city);
    println!("exit Y: {} / {}", exit_y.country, exit_y.city);

    // (1) Session A.
    let a = client.connect_multihop(exit_x).await?;
    println!(
        "session A on X: anonymous={}",
        a.session().metrics_snapshot().anonymous
    );
    match a.session().admission().token().copied() {
        // C proves the walk and ends before B dials the same exit.
        Some(a_token) => drop(walk_past(&phrase, &api_base, a_token, exit_y).await?),
        None => println!("no token admitted session A: the walk (step 2) is skipped"),
    }

    // (3) Session B through the proxy datapath, concurrent with A.
    let direct_ip = echo(None).await?;
    let cfg = ProxyConfig {
        socks5: "127.0.0.1:0".parse()?,
        http: None,
        ..ProxyConfig::default()
    };
    let b = client
        .start_proxy(&Circuit::SingleHop(exit_y.clone()), &cfg)
        .await?;
    let b_anonymous = b.metrics().is_some_and(|m| m.anonymous);
    println!("session B on Y (proxy): anonymous={b_anonymous}");
    let proxy = b.credentials().proxy_url("socks5h", b.local_addr());
    let mut tunnel_ip = None;
    for _ in 0..4 {
        if let Ok(ip) = echo(Some(proxy.as_str())).await {
            tunnel_ip = Some(ip);
            break;
        }
    }
    let tunnel_ip = tunnel_ip.ok_or("the IP echo never answered through session B")?;
    // This host's own address stays off the output.
    println!("egress through B: {tunnel_ip} (differs from this host's address)");
    if tunnel_ip == direct_ip {
        return Err("session B did not route through the exit".into());
    }

    let a_anonymous = a.session().admission().is_anonymous();
    b.shutdown();
    drop(a);
    println!(
        "DONE: A anonymous={a_anonymous}, B anonymous={b_anonymous}, walk {}",
        if a_anonymous { "proven" } else { "not run" }
    );
    Ok(())
}

fn admission() -> SessionAdmission {
    match std::env::var("WARREN_TOKENS_ONLY").as_deref() {
        Ok("1") => SessionAdmission::TokensOnly,
        _ => SessionAdmission::default(),
    }
}

/// Session C, standing in for another device of the wallet: its own manager
/// derives the same batch (the issuer serves it again) and its stack leads
/// with `a_token`, which session A holds on another exit. The exit must refuse
/// it and admit the next token.
async fn walk_past(
    phrase: &str,
    api_base: &str,
    a_token: SessionToken,
    exit_y: &warren_sdk::discovery::VerifiedExit,
) -> Result<warren_sdk::transport::MultihopSession, Box<dyn std::error::Error>> {
    let seed = seed_from_mnemonic(phrase.trim())?;
    let other_device = TokenManager::new(
        Arc::new(WarrenApiClient::new(
            api_base.to_owned(),
            WarrenIdentity::from_seed(&seed),
            ReqwestTransport::try_new()?,
        )),
        BlindingKey::session(&seed),
    )
    .with_mint_horizon(0);
    other_device.refresh(now_unix_secs()).await?;
    let batch: Vec<SessionToken> = other_device
        .session_stack(now_unix_secs())
        .into_iter()
        .map(SessionToken)
        .collect();
    println!("the other device holds {} token(s) this epoch", batch.len());
    let mut stack = vec![a_token];
    stack.extend(batch.iter().copied().filter(|t| *t != a_token));
    if stack.len() < 2 {
        return Err("the batch has no second token to walk to".into());
    }
    let forced = Arc::new(ForcedStack {
        stack,
        claims: AtomicUsize::new(0),
    });
    let c = MultihopClientTunnel::new(WarrenIdentity::from_seed(&seed).signing_key())
        .with_session_tokens(forced.clone())
        .with_session_admission(SessionAdmission::TokensOnly)
        .connect(
            exit_y.exit_ed25519_pubkey,
            exit_y.exit_x25519_multihop_pubkey,
            exit_y.exit_id,
            exit_y.endpoint,
        )
        .await?;
    let c_token = *c
        .admission()
        .token()
        .ok_or("session C was not admitted on a token")?;
    println!(
        "session C on Y: dials={} admitted_on_a_token={} admitted_on_A_token={}",
        forced.claims.load(Ordering::SeqCst),
        c.admission().is_anonymous(),
        c_token == a_token,
    );
    if c_token == a_token || forced.claims.load(Ordering::SeqCst) < 2 {
        return Err("exit Y admitted the serial session A holds on X".into());
    }

    Ok(c)
}

/// The address the echo sees, through `proxy` when one is given. The proxy
/// URL carries the listener's credentials, so it goes to `curl` as an argument
/// and is never printed.
async fn echo(proxy: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
    let mut curl = tokio::process::Command::new("curl");
    curl.args(["--silent", "--show-error", "--max-time", "15"]);
    if let Some(proxy) = proxy {
        curl.args(["--proxy", proxy]);
    }
    let out = curl.arg(ECHO_URL).output().await?;
    let body = String::from_utf8(out.stdout)?.trim().to_owned();
    if !out.status.success() || body.is_empty() {
        return Err("the IP echo returned nothing".into());
    }
    Ok(body)
}
