//! `warren-proxy`: headless Warren proxy daemon. See the crate docs
//! ([`warren_proxy`]) and `README.md` for the env contract.

use std::process::ExitCode;

/// `warren-proxy healthcheck`: probe the running daemon's `/healthz` and
/// exit 0/1, so a container HEALTHCHECK needs no shell and no wget.
fn healthcheck() -> ExitCode {
    let addr = std::env::var("WARREN_HEALTH_LISTEN")
        .ok()
        .filter(|v| !v.is_empty() && v != "off")
        .unwrap_or_else(|| "127.0.0.1:9999".to_owned());
    let Ok(addr) = addr.parse() else {
        eprintln!("warren-proxy: WARREN_HEALTH_LISTEN is not an ip:port");
        return ExitCode::from(1);
    };
    match warren_proxy::health::probe_healthz(addr) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("warren-proxy: unhealthy");
            ExitCode::from(1)
        }
        Err(err) => {
            eprintln!("warren-proxy: health endpoint unreachable: {err}");
            ExitCode::from(1)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck();
    }
    let config =
        match warren_proxy::config::load(|k| std::env::var(k).ok(), |p| std::fs::read_to_string(p))
        {
            Ok(config) => config,
            Err(err) => {
                eprintln!("warren-proxy: {err}");
                return ExitCode::from(1);
            }
        };
    match warren_proxy::run::run(config).await {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(err) => {
            eprintln!("warren-proxy: {err:#}");
            ExitCode::from(1)
        }
    }
}
