//! Real-exit proof that an exit releases a v7 token's lease the moment the
//! session holding it ends, so the same serial is admitted on another exit at
//! once instead of being refused `serial_in_use` until the lease lapses.
//!
//! Run (beta): `WARREN_API_URL=https://api.beta.warrenbrowse.com
//! WARREN_MNEMONIC="word1 ... word12" LEASE_HOLDER=SG LEASE_OTHER=DE
//! cargo run -p warren-sdk --example live_lease_release`
//!
//! `LEASE_HOLDER` / `LEASE_OTHER` are the country codes of the two exits.
//! `LEASE_TOKEN_INDEX` picks which token of the wallet's current batch is
//! used (default 0), so a run can avoid a serial a previous run left leased.
//! `LEASE_POLL_SECS` (default 5) and `LEASE_MAX_SECS` (default 30) bound the
//! wait for the other exit to admit the serial.
//!
//! 1. Session A on the holder, admitted on that one token only.
//! 2. The other exit is dialed with the same single token while A is up: it
//!    must refuse it (the serial is leased to the holder).
//! 3. A is closed, then the other exit is dialed again with the same token
//!    every poll interval until it admits it or the budget runs out.
//!
//! Every line carries a unix timestamp so it can be matched against the API's
//! access log. Nothing printed names a token, a serial or the wallet.

use std::sync::Arc;
use std::time::{Duration, Instant};

use warren_sdk::api::{BlindingKey, ReqwestTransport, TokenManager, WarrenApiClient};
use warren_sdk::discovery::VerifiedExit;
use warren_sdk::identity::{WarrenIdentity, seed_from_mnemonic};
use warren_sdk::transport::{
    MultihopClientTunnel, MultihopSession, SessionToken, SessionTokenSource, TokenHold,
};
use warren_sdk::{SessionAdmission, WarrenClient};

/// A stack of exactly one token, so a dial either comes up on it or fails.
struct OneToken(SessionToken);

impl SessionTokenSource for OneToken {
    fn stack(&self) -> Vec<SessionToken> {
        vec![self.0]
    }

    fn claim(&self, _token: &SessionToken) -> Option<TokenHold> {
        Some(TokenHold::new(()))
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's words")?;
    let api_base = std::env::var(warren_sdk::product::API_URL_ENV)
        .unwrap_or_else(|_| warren_sdk::product::API_URL.to_owned());
    let holder_cc = std::env::var("LEASE_HOLDER").map_err(|_| "set LEASE_HOLDER")?;
    let other_cc = std::env::var("LEASE_OTHER").map_err(|_| "set LEASE_OTHER")?;
    let index = usize::try_from(env_u64("LEASE_TOKEN_INDEX", 0))?;
    let poll = Duration::from_secs(env_u64("LEASE_POLL_SECS", 5));
    let budget = Duration::from_secs(env_u64("LEASE_MAX_SECS", 30));

    let identity = WarrenIdentity::from_mnemonic(phrase.trim())?;
    let client = WarrenClient::builder()
        .identity(identity)
        .api_base(api_base.clone())
        .server_pubkey_pin(warren_sdk::product::SERVER_PUBKEY_HEX)
        .session_admission(SessionAdmission::TokensOnly)
        .build()?;
    let exits = client.fetch_multihop_directory().await?;
    let pick = |cc: &str| {
        exits
            .iter()
            .find(|e| e.country.eq_ignore_ascii_case(cc))
            .cloned()
            .ok_or_else(|| format!("no exit in {cc}"))
    };
    let holder = pick(&holder_cc)?;
    let other = pick(&other_cc)?;

    let seed = seed_from_mnemonic(phrase.trim())?;
    let manager = TokenManager::new(
        Arc::new(WarrenApiClient::new(
            api_base.clone(),
            WarrenIdentity::from_seed(&seed),
            ReqwestTransport::try_new()?,
        )),
        BlindingKey::session(&seed),
    )
    .with_mint_horizon(0);
    manager.refresh(now_unix_secs()).await?;
    let batch = manager.session_stack(now_unix_secs());
    let token = SessionToken(
        *batch
            .get(index)
            .ok_or_else(|| format!("the batch holds {} token(s)", batch.len()))?,
    );
    println!(
        "{} batch of {}, using token #{index}; holder {} / {}, other {} / {}",
        now_unix_secs(),
        batch.len(),
        holder.country,
        holder.city,
        other.country,
        other.city
    );

    let a = dial(&seed, &holder, token)
        .await
        .map_err(|e| format!("session A on the holder was not admitted: {e}"))?;
    println!("{} session A up on the holder", now_unix_secs());

    match dial(&seed, &other, token).await {
        Ok(_) => return Err("the other exit admitted a serial the holder leases".into()),
        Err(e) => println!(
            "{} other exit refused the serial while A is up ({e})",
            now_unix_secs()
        ),
    }

    a.connection().close(0u32.into(), b"");
    drop(a);
    let closed = Instant::now();
    println!("{} session A closed", now_unix_secs());

    loop {
        tokio::time::sleep(poll).await;
        match dial(&seed, &other, token).await {
            Ok(c) => {
                println!(
                    "{} ADMITTED on the other exit {:.1} s after A closed",
                    now_unix_secs(),
                    closed.elapsed().as_secs_f64()
                );
                c.connection().close(0u32.into(), b"");
                return Ok(());
            }
            Err(e) => println!(
                "{} refused {:.1} s after A closed ({e})",
                now_unix_secs(),
                closed.elapsed().as_secs_f64()
            ),
        }
        if closed.elapsed() >= budget {
            return Err("the serial was not admitted on the other exit within the budget".into());
        }
    }
}

/// One tunnel admitted on `token` alone, dialed the way the SDK's own dials
/// take a verified exit.
async fn dial(
    seed: &[u8; 32],
    exit: &VerifiedExit,
    token: SessionToken,
) -> Result<MultihopSession, Box<dyn std::error::Error>> {
    let session = MultihopClientTunnel::new(WarrenIdentity::from_seed(seed).signing_key())
        .with_cover_domain(exit.cover_domain.clone())
        .with_tcp_fallback(exit.tcp_fallback)
        .with_alt_endpoint(exit.endpoint_v6)
        .with_exit_mlkem768(exit.exit_mlkem768_pubkey.clone())
        .with_session_tokens(Arc::new(OneToken(token)))
        .with_session_admission(SessionAdmission::TokensOnly)
        .connect(
            exit.exit_ed25519_pubkey,
            exit.exit_x25519_multihop_pubkey,
            exit.exit_id,
            exit.endpoint,
        )
        .await?;
    Ok(session)
}
