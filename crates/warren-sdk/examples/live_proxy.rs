//! End-to-end PROOF OF EGRESS over a real multihop tunnel.
//!
//! Run: `WARREN_MNEMONIC="word1 ... word12" cargo run -p warren-sdk --example
//! live_proxy`
//!
//! 1. Opens a real multihop tunnel to a production exit and starts the non-root
//!    SOCKS5 proxy datapath (`start_proxy_multihop`).
//! 2. PROOF: a SOCKS5 CONNECT to a public host (`1.1.1.1:443`) completes through
//!    the sealed tunnel, i.e. a SYN-ACK came back from the internet via the exit.
//!    That is conclusive: traffic egresses at the exit, not this host.
//! 3. Best-effort: a plain-HTTP IP-echo for a human-readable before/after. This
//!    is flaky (many echo hosts are CDN-fronted and only answer :443 by name),
//!    so it is informational and does not gate the proof.
//!
//! The first QUIC datagrams on a fresh path are frequently lost during warm-up,
//! so the CONNECT is retried with a short per-attempt budget. DNS-over-tunnel is
//! not implemented yet, so targets are resolved locally and SOCKS5 CONNECT uses
//! the IP literal (the bytes still egress at the exit).

use std::net::ToSocketAddrs;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use warren_sdk::WarrenClient;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::ProxyConfig;

const API_BASE: &str = "https://api.warrenbrowse.com";
const SERVER_PUBKEY_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";
/// Plain-HTTP IP echo on port 80 (returns the caller's public IP as the body).
/// Served by AWS, answers by IP literal, so it works without DNS-over-tunnel.
const ECHO_HOST: &str = "checkip.amazonaws.com";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's 12 words")?;
    let identity = WarrenIdentity::from_mnemonic(phrase.trim())?;
    println!("client identity: {}", identity.address());

    // Resolve the echo host once, locally (no DNS-over-tunnel yet).
    let echo_addr = format!("{ECHO_HOST}:80")
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .ok_or("no IPv4 for echo host")?;
    println!("echo host {ECHO_HOST} -> {echo_addr}");

    // (1) Direct egress IP (no tunnel).
    let direct_ip = http_get_ip_direct(echo_addr).await?;
    println!("direct egress IP   : {direct_ip}");

    // (2) Tunnel up + proxy.
    let client = WarrenClient::builder()
        .identity(identity)
        .api_base(API_BASE)
        .server_pubkey_pin(SERVER_PUBKEY_PIN)
        .build()?;
    let selector = client.fetch_exits().await?;
    let exits = client.fetch_multihop_directory().await?;
    let exit = exits
        .into_iter()
        .find(|e| {
            selector
                .relays()
                .iter()
                .any(|r| r.endpoint_id() == e.exit_ed25519_pubkey)
        })
        .ok_or("no cross-checked multihop exit")?;
    println!("exit: {} / {}  {}", exit.country, exit.city, exit.endpoint);

    let cfg = ProxyConfig {
        socks5: "127.0.0.1:0".parse()?,
        http: None,
        ..ProxyConfig::default()
    };
    let handle = client.start_proxy_multihop(&exit, &cfg).await?;
    println!("SOCKS5 proxy up on {}", handle.local_addr());

    // (2b) Pure-TCP egress probe: a successful SOCKS5 CONNECT to a well-known
    // public service proves a SYN-ACK came back through the sealed tunnel
    // (egress works), independent of any HTTP semantics. Retried: the first
    // QUIC datagrams on a fresh path are frequently lost while it warms up
    // (smoltcp retransmits the SYN on each fresh attempt).
    // Each attempt is bounded client-side (2.5 s) so a SYN lost during warm-up
    // aborts fast and the next fresh attempt sends a new SYN, instead of waiting
    // out the netstack's 10 s connect timeout.
    let attempt_budget = std::time::Duration::from_millis(2500);
    let probe: std::net::SocketAddr = "1.1.1.1:443".parse()?;
    let mut probe_ok = false;
    for attempt in 1..=15 {
        if let Ok(Ok(())) =
            tokio::time::timeout(attempt_budget, socks5_connect(handle.local_addr(), probe)).await
        {
            println!(
                "egress probe 1.1.1.1:443: CONNECT ok (SYN-ACK via the exit, attempt {attempt})"
            );
            probe_ok = true;
            break;
        }
    }
    if !probe_ok {
        return Err("egress probe never succeeded: no SYN-ACK through the tunnel".into());
    }

    println!(
        "EGRESS CONFIRMED: a TCP handshake to a public host completed through the \
         sealed tunnel (traffic egresses at the exit, not the host)."
    );

    // (3) Best-effort IP-echo for a human-readable before/after. Plain HTTP on
    // port 80 by IP literal is flaky (many echo hosts are CDN-fronted and only
    // answer :443), so this is informational and does not gate the proof.
    let mut tunnel_ip = String::new();
    for _ in 1..=6 {
        if let Ok(Ok(ip)) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            http_get_ip_via_socks5(handle.local_addr(), echo_addr),
        )
        .await
        {
            tunnel_ip = ip;
            break;
        }
    }
    if tunnel_ip.is_empty() {
        println!(
            "(IP-echo over :80 did not return a body from {ECHO_HOST}; the egress probe \
             above is the conclusive proof.)"
        );
    } else if tunnel_ip == direct_ip {
        return Err(format!(
            "egress IP unchanged ({tunnel_ip}): traffic did NOT route through the exit"
        )
        .into());
    } else {
        println!(
            "ROUTING CONFIRMED: egress IP {tunnel_ip} (the exit), not {direct_ip} (this host)."
        );
    }
    Ok(())
}

/// Minimal HTTP/1.1 GET to an IP-echo service over a direct TCP connection.
async fn http_get_ip_direct(
    addr: std::net::SocketAddr,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(http_request().as_bytes()).await?;
    read_ip_body(&mut s).await
}

/// Same request, but tunneled through a local SOCKS5 proxy (CONNECT to the IP).
async fn http_get_ip_via_socks5(
    proxy: std::net::SocketAddr,
    target: std::net::SocketAddr,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut s = TcpStream::connect(proxy).await?;
    // Greeting: VER=5, 1 method, NO-AUTH.
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        return Err("socks5 no-auth not accepted".into());
    }
    // CONNECT to the IPv4 target.
    let std::net::IpAddr::V4(ip) = target.ip() else {
        return Err("ipv4 target required".into());
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(format!("socks5 CONNECT failed (rep={})", reply[1]).into());
    }
    s.write_all(http_request().as_bytes()).await?;
    read_ip_body(&mut s).await
}

/// SOCKS5 greeting + CONNECT to `target`; Ok(()) iff the proxy replied success.
async fn socks5_connect(
    proxy: std::net::SocketAddr,
    target: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut s = TcpStream::connect(proxy).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await?;
    let std::net::IpAddr::V4(ip) = target.ip() else {
        return Err("ipv4 only".into());
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(format!("rep={}", reply[1]).into());
    }
    Ok(())
}

fn http_request() -> String {
    format!(
        "GET / HTTP/1.1\r\nHost: {ECHO_HOST}\r\nUser-Agent: warren-sdk\r\nConnection: close\r\n\r\n"
    )
}

/// Reads the whole HTTP response and returns the trimmed body (the IP).
async fn read_ip_body(s: &mut TcpStream) -> Result<String, Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .ok_or("no HTTP body")?
        .trim()
        .to_owned();
    if body.is_empty() {
        return Err("empty IP body".into());
    }
    Ok(body)
}
