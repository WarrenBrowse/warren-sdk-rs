//! Live proof of the device registry (warren-core doc 115) against a real API
//! and a real exit: an older client that blinds its batch at random holds the
//! wallet's epochs, an up-to-date device of the same wallet still gets its
//! tokens and a tunnel, the account lists both, and a device renamed then
//! revoked from another one learns it at its next refresh.
//!
//! Run (staging): `WARREN_API_URL=https://api.staging.warrenbrowse.com
//! WARREN_MNEMONIC="word1 ... word12" PIN_EXIT=FI ECHO_URL=https://1.1.1.1/cdn-cgi/trace
//! cargo run -p warren-sdk --example live_device_registry`
//!
//! Use a wallet no other client holds: the older client this probe plays
//! reserves the wallet's next epochs with a batch nobody can reproduce.
//!
//! Every step prints a verdict, and the run fails at the first one that does
//! not hold. Nothing printed names a token, a device id or the wallet.

use std::sync::Arc;

use warren_sdk::api::{
    BlindingKey, DeviceIdentity, DevicePlatform, ReqwestTransport, TokenManager, WarrenApiClient,
};
use warren_sdk::identity::{WarrenIdentity, seed_from_mnemonic};
use warren_sdk::net::ProxyConfig;
use warren_sdk::{Circuit, SessionAdmission, WarrenClient};

const ECHO_URL: &str = "https://api.ipify.org";
/// `ECHO_URL` overrides it, e.g. with an IP literal to tell DNS from egress.
fn echo_url() -> String {
    std::env::var("ECHO_URL").unwrap_or_else(|_| ECHO_URL.to_owned())
}
const VERSION: &str = "live-device-registry";
/// Enough epochs to cover the current one and the next, which is all a
/// session needs, without reserving the whole published window.
const HORIZON: u64 = 2;

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn check(step: &str, holds: bool) -> Result<(), String> {
    println!("[{}] {step}", if holds { "ok" } else { "FAIL" });
    if holds {
        Ok(())
    } else {
        Err(format!("step failed: {step}"))
    }
}

fn echo_through(proxy: &str) -> Option<String> {
    let out = std::process::Command::new("curl")
        .args(["-sS", "--max-time", "15", "--proxy", proxy, &echo_url()])
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!(
            "echo failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Brings a tokens-only tunnel up for a device registered through the client
/// builder, and checks it carries traffic. `TUNNEL_ONLY=1` runs this step
/// alone, on a wallet an earlier run already left with identified epochs.
async fn tunnel_device(
    seed: &[u8; 32],
    api_base: &str,
    country: &str,
    now: u64,
) -> Result<WarrenClient<ReqwestTransport>, Box<dyn std::error::Error>> {
    let state = std::env::temp_dir().join(format!("live-device-registry-{now}"));
    std::fs::create_dir_all(&state)?;
    let builder = WarrenClient::builder()
        .identity(WarrenIdentity::from_seed(seed))
        .api_base(api_base.to_owned())
        .server_pubkey_pin(warren_sdk::product::SERVER_PUBKEY_HEX)
        .session_admission(SessionAdmission::TokensOnly);
    // `NO_DEVICE=1` is the control: the same tunnel from a client that does
    // not register, to tell a registry fault from an environment one.
    let builder = if std::env::var("NO_DEVICE").as_deref() == Ok("1") {
        builder
    } else {
        builder.device(&state, DevicePlatform::Linux, VERSION)
    };
    let client_c = builder.build()?;
    let exit = client_c
        .fetch_multihop_directory()
        .await?
        .into_iter()
        .find(|e| e.country.eq_ignore_ascii_case(country))
        .ok_or_else(|| format!("no exit in {country}"))?;
    let cfg = ProxyConfig {
        socks5: "127.0.0.1:0".parse()?,
        http: None,
        ..ProxyConfig::default()
    };
    let handle = client_c
        .start_proxy(&Circuit::SingleHop(exit), &cfg)
        .await?;
    let proxy = handle
        .credentials()
        .proxy_url("socks5h", handle.local_addr());
    let mut echoed = echo_through(proxy.as_str());
    if echoed.is_none() {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        echoed = echo_through(proxy.as_str());
    }
    check(
        "a tokens-only tunnel comes up and carries traffic",
        echoed.is_some(),
    )?;
    handle.shutdown();

    let _ = std::fs::remove_dir_all(&state);
    Ok(client_c)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's words")?;
    let api_base = std::env::var(warren_sdk::product::API_URL_ENV)
        .unwrap_or_else(|_| warren_sdk::product::API_URL.to_owned());
    let country = std::env::var("PIN_EXIT").unwrap_or_else(|_| "FI".to_owned());
    let seed = seed_from_mnemonic(phrase.trim())?;
    let api = || {
        Ok::<_, Box<dyn std::error::Error>>(Arc::new(WarrenApiClient::new(
            api_base.clone(),
            WarrenIdentity::from_seed(&seed),
            ReqwestTransport::try_new()?,
        )))
    };
    let now = now_unix_secs();
    if std::env::var("TUNNEL_ONLY").as_deref() == Ok("1") {
        tunnel_device(&seed, &api_base, &country, now).await?;
        return Ok(());
    }

    // 1. The older client: a batch blinded from a seed nobody else holds, no
    // device. It takes the epochs first, as the 1.1.30 daemon did.
    let mut random_seed = [0u8; 32];
    random_seed[..16].copy_from_slice(DeviceIdentity::generate().device_id.as_bytes());
    random_seed[16..].copy_from_slice(DeviceIdentity::generate().device_id.as_bytes());
    let older =
        TokenManager::new(api()?, BlindingKey::session(&random_seed)).with_mint_horizon(HORIZON);
    older.refresh(now).await?;
    check(
        "an older client holds the wallet's epochs",
        !older.session_stack(now).is_empty(),
    )?;

    // 2. An up-to-date client that does not register (1.1.36 to 1.1.54) is
    // still refused, which is the incident of forum topic 241.
    let unregistered =
        TokenManager::new(api()?, BlindingKey::session(&seed)).with_mint_horizon(HORIZON);
    let _ = unregistered.refresh(now).await;
    check(
        "a client that does not register gets no token while the older one holds the epoch",
        unregistered.session_stack(now).is_empty(),
    )?;

    // 3. A registered device supersedes the older client.
    let a = DeviceIdentity::generate();
    let device_a = TokenManager::new(api()?, BlindingKey::session(&seed))
        .with_mint_horizon(HORIZON)
        .with_device(a.registration(DevicePlatform::Android, VERSION));
    device_a.refresh(now).await?;
    check(
        "a registered device gets its tokens despite the older client",
        !device_a.session_stack(now).is_empty(),
    )?;

    // 4. The list, seen from a second device.
    let b = DeviceIdentity::generate();
    let client_b = api()?;
    client_b
        .register_device(&b.registration(DevicePlatform::Macos, VERSION))
        .await?;
    let list = client_b.list_devices(Some(b.device_id)).await?;
    let seen_a = list.devices.iter().any(|d| d.device_id == a.device_id);
    let b_is_this = list
        .devices
        .iter()
        .any(|d| d.device_id == b.device_id && d.this_device);
    check("the list shows the first device", seen_a)?;
    check("the list marks the asking device as this one", b_is_this)?;
    check(
        "the list reports the superseded older client",
        list.older_client_seen_on.is_some(),
    )?;

    // 5. A real tunnel for a third device of the wallet, registered through
    // the client builder, on the same supersede.
    let client_c = tunnel_device(&seed, &api_base, &country, now).await?;

    // 6. Renamed from B, A takes the name at its next refresh.
    let renamed = "renamed by another device";
    client_b.rename_device(a.device_id, renamed).await?;
    device_a.refresh(now_unix_secs()).await?;
    check(
        "a rename made elsewhere reaches the device at its next refresh",
        device_a.device_name().as_deref() == Some(renamed),
    )?;

    // 7. Revoked from B, A stops at its next refresh and holds nothing.
    client_b.revoke_device(a.device_id).await?;
    let _ = device_a.refresh(now_unix_secs()).await;
    check(
        "a device revoked elsewhere learns it at its next refresh",
        device_a.device_revoked(),
    )?;
    check(
        "a revoked device holds no token",
        device_a.session_stack(now_unix_secs()).is_empty(),
    )?;
    let after = client_b.list_devices(Some(b.device_id)).await?;
    check(
        "the revoked device leaves the list",
        !after.devices.iter().any(|d| d.device_id == a.device_id),
    )?;

    // Leave the wallet as clean as the registry allows.
    client_b.revoke_device(b.device_id).await?;
    if let Some(c) = client_c.device_id() {
        client_b.revoke_device(c).await?;
    }
    println!("all steps hold");
    Ok(())
}
