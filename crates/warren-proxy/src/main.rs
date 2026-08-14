//! `warren-proxy`: headless Warren proxy daemon. See the crate docs
//! ([`warren_proxy`]) and `README.md` for the env contract.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
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
