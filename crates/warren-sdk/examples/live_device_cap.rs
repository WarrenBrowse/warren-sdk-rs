//! Live proof of the per-subscription device cap on anonymous session tokens:
//! how many tokens the issuer serves a wallet per epoch, that a batch minted
//! under a smaller quota grows to the current one instead of being refused
//! `already_issued`, and that the fleet admits exactly that many concurrent
//! sessions on the wallet's tokens.
//!
//! Run (beta): `WARREN_API_URL=https://api.beta.warrenbrowse.com
//! WARREN_MNEMONIC="word1 ... word12" DEVICE_CAP_STEP=<mint|admit>
//! cargo run -p warren-sdk --example live_device_cap`
//!
//! `mint`: mints the session class (or `DEVICE_CAP_CLASS=browser-proxy`) for
//! the current epoch and the `DEVICE_CAP_AHEAD` (default 3) epochs after it,
//! and prints, per epoch, the directory quota, the count served and a digest
//! of each credential. Run once before the quota grows and once after: the
//! second run is served the full new quota, and its leading digests equal the
//! first run's (the same credentials, extended rather than replaced).
//!
//! `admit`: mints the current epoch, then holds one session per token, each
//! on its own exit and admitted on that token alone (tokens-only admission,
//! so no session can fall back to the wallet-signed login), and finally
//! dials one more exit with the whole batch, which every exit must refuse
//! since each serial is leased elsewhere. Needs one more exit in the
//! directory than the quota. Each session is held only for the handshake and
//! the next dial, then closed.
//!
//! `wallet`: holds `DEVICE_CAP_WALLET_SESSIONS` (default 6) wallet-signed
//! sessions of the wallet at once, round-robin over the exits of the
//! directory (or all on exit `DEVICE_CAP_EXIT`, an index into the directory),
//! each presenting no token, so each is the v6 login with a session-fresh
//! placement hint. With the fleet capping wallet sessions at five per
//! account, the sixth is refused with the device limit, wherever it lands.
//! Then it closes every held session and dials one more, which is admitted
//! once the releases reached the API.
//!
//! Every line carries a unix timestamp. Nothing printed names a token, a
//! serial or the wallet: the digests only let two runs be compared.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use warren_sdk::api::{
    BlindingKey, CredentialClass, ReqwestTransport, TokenClientError, WarrenApiClient, mint_tokens,
};
use warren_sdk::discovery::VerifiedExit;
use warren_sdk::identity::{WarrenIdentity, seed_from_mnemonic};
use warren_sdk::transport::{
    MultihopClientTunnel, MultihopSession, SessionToken, SessionTokenSource, TokenHold,
};
use warren_sdk::{SessionAdmission, WarrenClient};

/// A fixed stack of tokens, walked in order by the dial.
struct Stack(Vec<SessionToken>);

impl SessionTokenSource for Stack {
    fn stack(&self) -> Vec<SessionToken> {
        self.0.clone()
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

/// A digest to compare two runs by, not a commitment: the fixed-key SipHash
/// of `std`, the same in every process.
fn digest(bytes: &[u8]) -> u16 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    (hasher.finish() & 0xffff) as u16
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's words")?;
    let api_base = std::env::var(warren_sdk::product::API_URL_ENV)
        .unwrap_or_else(|_| warren_sdk::product::API_URL.to_owned());
    let step = std::env::var("DEVICE_CAP_STEP").map_err(|_| "set DEVICE_CAP_STEP")?;
    let seed = seed_from_mnemonic(phrase.trim())?;
    let client = WarrenApiClient::new(
        api_base.clone(),
        WarrenIdentity::from_seed(&seed),
        ReqwestTransport::try_new()?,
    );
    match step.as_str() {
        "mint" => mint(&client, &seed).await,
        "admit" => admit(&client, &seed, &api_base, phrase.trim()).await,
        "wallet" => wallet_sessions(&seed, &api_base, phrase.trim()).await,
        other => Err(format!("unknown DEVICE_CAP_STEP {other}").into()),
    }
}

async fn mint(
    client: &WarrenApiClient<ReqwestTransport>,
    seed: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let (class, key) = match std::env::var("DEVICE_CAP_CLASS").as_deref() {
        Ok("browser-proxy") => (
            CredentialClass::BrowserProxy,
            BlindingKey::browser_proxy(seed),
        ),
        _ => (CredentialClass::Session, BlindingKey::session(seed)),
    };
    let ahead: u64 = std::env::var("DEVICE_CAP_AHEAD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let directory = client.token_keys_for(class).await?;
    let current = now_unix_secs() / directory.epoch_secs;
    println!(
        "{} {class:?} directory quota_per_epoch {}",
        now_unix_secs(),
        directory.quota_per_epoch
    );
    for epoch in current..=current + ahead {
        match mint_tokens(client, &directory, &[epoch], &key).await {
            Ok(batches) => {
                let batch = batches.first().ok_or("no batch in the answer")?;
                let slots: Vec<String> = batch
                    .tokens
                    .iter()
                    .map(|t| format!("{:04x}", digest(&t.serialize())))
                    .collect();
                println!(
                    "{} epoch {epoch}: served {} [{}]",
                    now_unix_secs(),
                    batch.tokens.len(),
                    slots.join(" ")
                );
            }
            Err(TokenClientError::EpochRefused { reason, .. }) => println!(
                "{} epoch {epoch}: refused ({})",
                now_unix_secs(),
                reason.as_deref().unwrap_or("no reason")
            ),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

async fn admit(
    client: &WarrenApiClient<ReqwestTransport>,
    seed: &[u8; 32],
    api_base: &str,
    phrase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = client.token_keys().await?;
    let epoch = now_unix_secs() / directory.epoch_secs;
    let batches = mint_tokens(client, &directory, &[epoch], &BlindingKey::session(seed)).await?;
    let tokens: Vec<SessionToken> = batches
        .first()
        .ok_or("no batch in the answer")?
        .tokens
        .iter()
        .map(|t| SessionToken(t.serialize()))
        .collect();

    let wallet = WarrenClient::builder()
        .identity(WarrenIdentity::from_mnemonic(phrase)?)
        .api_base(api_base.to_owned())
        .server_pubkey_pin(warren_sdk::product::SERVER_PUBKEY_HEX)
        .session_admission(SessionAdmission::TokensOnly)
        .build()?;
    let exits = wallet.fetch_multihop_directory().await?;
    println!(
        "{} epoch {epoch}: {} token(s), {} exit(s) in the directory",
        now_unix_secs(),
        tokens.len(),
        exits.len()
    );
    if exits.len() <= tokens.len() {
        return Err("the directory needs one more exit than the batch has tokens".into());
    }

    let mut held = Vec::new();
    for (i, (token, exit)) in tokens.iter().zip(&exits).enumerate() {
        match dial(seed, exit, vec![*token]).await {
            Ok(session) => {
                println!(
                    "{} session {} ADMITTED on {} / {} with token #{i}",
                    now_unix_secs(),
                    i + 1,
                    exit.country,
                    exit.city
                );
                held.push(session);
            }
            Err(e) => println!(
                "{} session {} REFUSED on {} / {} with token #{i} ({e})",
                now_unix_secs(),
                i + 1,
                exit.country,
                exit.city
            ),
        }
    }

    let extra = &exits[tokens.len()];
    match dial(seed, extra, tokens.clone()).await {
        Ok(session) => {
            session.connection().close(0u32.into(), b"");
            println!(
                "{} session {} ADMITTED on {} / {} with the whole batch: the cap did not hold",
                now_unix_secs(),
                tokens.len() + 1,
                extra.country,
                extra.city
            );
        }
        Err(e) => println!(
            "{} session {} REFUSED on {} / {} with the whole batch ({e})",
            now_unix_secs(),
            tokens.len() + 1,
            extra.country,
            extra.city
        ),
    }

    for session in held {
        session.connection().close(0u32.into(), b"");
    }
    println!("{} every held session closed", now_unix_secs());

    // Control: the same dial once the serials are free, so the refusal above
    // reads as the cap and not as an exit that admits nobody.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    match dial(seed, extra, tokens).await {
        Ok(session) => {
            session.connection().close(0u32.into(), b"");
            println!(
                "{} control: ADMITTED on {} / {} once the others closed",
                now_unix_secs(),
                extra.country,
                extra.city
            );
        }
        Err(e) => println!(
            "{} control: refused on {} / {} ({e})",
            now_unix_secs(),
            extra.country,
            extra.city
        ),
    }
    Ok(())
}

/// One tunnel admitted on `stack` only, dialed the way the SDK's own dials
/// take a verified exit.
async fn wallet_sessions(
    seed: &[u8; 32],
    api_base: &str,
    phrase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let count: usize = std::env::var("DEVICE_CAP_WALLET_SESSIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);
    let wallet = WarrenClient::builder()
        .identity(WarrenIdentity::from_mnemonic(phrase)?)
        .api_base(api_base.to_owned())
        .server_pubkey_pin(warren_sdk::product::SERVER_PUBKEY_HEX)
        .build()?;
    let mut exits = wallet.fetch_multihop_directory().await?;
    if let Some(i) = std::env::var("DEVICE_CAP_EXIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        let one = exits
            .get(i)
            .cloned()
            .ok_or("DEVICE_CAP_EXIT is out of range")?;
        exits = vec![one];
    }
    if exits.is_empty() {
        return Err("the directory lists no exit".into());
    }
    println!(
        "{} {count} wallet-signed session(s) over {} exit(s)",
        now_unix_secs(),
        exits.len()
    );

    let mut held = Vec::new();
    for i in 0..count {
        let exit = &exits[i % exits.len()];
        match dial_wallet(seed, exit).await {
            Ok(session) => {
                println!(
                    "{} wallet session {} ADMITTED on {} / {}",
                    now_unix_secs(),
                    i + 1,
                    exit.country,
                    exit.city
                );
                held.push(session);
            }
            Err(e) => println!(
                "{} wallet session {} REFUSED on {} / {} ({e})",
                now_unix_secs(),
                i + 1,
                exit.country,
                exit.city
            ),
        }
    }

    for session in held {
        session.connection().close(0u32.into(), b"");
    }
    println!("{} every held session closed", now_unix_secs());
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let exit = &exits[count % exits.len()];
    match dial_wallet(seed, exit).await {
        Ok(session) => {
            session.connection().close(0u32.into(), b"");
            println!(
                "{} control: ADMITTED on {} / {} once the others closed",
                now_unix_secs(),
                exit.country,
                exit.city
            );
        }
        Err(e) => println!(
            "{} control: refused on {} / {} ({e})",
            now_unix_secs(),
            exit.country,
            exit.city
        ),
    }
    Ok(())
}

/// One wallet-signed session: no token to present, so the default admission
/// sends the v6 login, with the session-fresh placement hint every dial sends.
async fn dial_wallet(
    seed: &[u8; 32],
    exit: &VerifiedExit,
) -> Result<MultihopSession, Box<dyn std::error::Error>> {
    let session = MultihopClientTunnel::new(WarrenIdentity::from_seed(seed).signing_key())
        .with_cover_domain(exit.cover_domain.clone())
        .with_tcp_fallback(exit.tcp_fallback)
        .with_alt_endpoint(exit.endpoint_v6)
        .with_exit_mlkem768(exit.exit_mlkem768_pubkey.clone())
        .with_session_tokens(Arc::new(Stack(Vec::new())))
        .with_session_admission(SessionAdmission::TokensOrWallet)
        .connect(
            exit.exit_ed25519_pubkey,
            exit.exit_x25519_multihop_pubkey,
            exit.exit_id,
            exit.endpoint,
        )
        .await?;
    Ok(session)
}

async fn dial(
    seed: &[u8; 32],
    exit: &VerifiedExit,
    stack: Vec<SessionToken>,
) -> Result<MultihopSession, Box<dyn std::error::Error>> {
    let session = MultihopClientTunnel::new(WarrenIdentity::from_seed(seed).signing_key())
        .with_cover_domain(exit.cover_domain.clone())
        .with_tcp_fallback(exit.tcp_fallback)
        .with_alt_endpoint(exit.endpoint_v6)
        .with_exit_mlkem768(exit.exit_mlkem768_pubkey.clone())
        .with_session_tokens(Arc::new(Stack(stack)))
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
