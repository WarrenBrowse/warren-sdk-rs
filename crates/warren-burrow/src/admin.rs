//! The two write operations an operator needs on a running daemon: apply the
//! configuration file again, and rebuild one peer's protocol session.
//!
//! They ride the health listener, behind a bearer token the daemon writes next
//! to its configuration (`admin.token`, 0600, regenerated at every start), and
//! they are served only when that listener is on a loopback address: a write
//! surface reachable from the network is not what a local gateway is for.
//! `SIGHUP` remains the unix shortcut for the reload, and is the only one on a
//! host where the listener is off.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use warren_burrow_core::{PeerLabel, PeerPlan, PresharedKey, ReloadReport};
use warren_headless::health::{Request, RouteReply};
use zeroize::Zeroizing;

use crate::config::GatewayEnv;
use crate::device::GatewayDevice;
use crate::provision::{self, ProvisionError};

/// The file the daemon writes its token to, inside the state directory.
pub const TOKEN_FILE: &str = "admin.token";

/// Where the token lives for this environment.
#[must_use]
pub fn token_path(env: &GatewayEnv) -> PathBuf {
    env.state_dir.join(TOKEN_FILE)
}

/// Generates a token and writes it 0600, replacing any previous one.
///
/// A fresh token at every start is what makes a token read out of a stale
/// backup useless.
///
/// # Errors
///
/// [`ProvisionError::Io`] when the file cannot be written.
pub fn write_token(env: &GatewayEnv) -> Result<Zeroizing<String>, ProvisionError> {
    // 32 random bytes from the same generator the peers' keys come from.
    let token = PresharedKey::generate().to_base64_zeroizing();
    provision::write_secret_file(&token_path(env), token.as_bytes())?;
    Ok(token)
}

/// Reads the token a running daemon wrote.
///
/// # Errors
///
/// [`ProvisionError::NoDaemonToken`] when no daemon has written one.
pub fn read_token(env: &GatewayEnv) -> Result<Zeroizing<String>, ProvisionError> {
    std::fs::read_to_string(token_path(env))
        .map(|token| Zeroizing::new(token.trim().to_owned()))
        .map_err(|_| ProvisionError::NoDaemonToken)
}

/// Forgets the token, for a daemon that serves no admin surface at all.
pub fn forget_token(env: &GatewayEnv) {
    // A token file left behind would have the subcommands present a credential
    // that opens nothing.
    let _ = std::fs::remove_file(token_path(env));
}

/// The admin routes of one running daemon.
pub struct Admin {
    device: GatewayDevice,
    conf_path: PathBuf,
    plan: PeerPlan,
    token: Zeroizing<String>,
}

impl std::fmt::Debug for Admin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The token is a credential: it is never rendered, here or anywhere.
        f.debug_struct("Admin").finish_non_exhaustive()
    }
}

impl Admin {
    /// Wires the routes to the device they act on.
    #[must_use]
    pub fn new(
        device: GatewayDevice,
        conf_path: PathBuf,
        plan: PeerPlan,
        token: Zeroizing<String>,
    ) -> Self {
        Self {
            device,
            conf_path,
            plan,
            token,
        }
    }

    /// Renders an admin request, or `None` when the path is not an admin one.
    #[must_use]
    pub fn render(&self, request: &Request<'_>) -> Option<RouteReply> {
        let rest = request.path.strip_prefix("/admin/")?;
        if !self.authorized(request.authorization) {
            return Some(RouteReply::text(401, "unauthorized\n".to_owned()));
        }
        if request.method != "POST" {
            // Both routes change the gateway's state, and a GET that does is
            // what a browser prefetch or a link click fires by accident.
            return Some(RouteReply::text(405, "admin routes take POST\n".to_owned()));
        }
        match rest {
            "reload" => Some(self.reload()),
            path => match path.strip_prefix("reset-peer/") {
                Some(label) => Some(self.reset_peer(label)),
                None => Some(RouteReply::text(404, "no such admin route\n".to_owned())),
            },
        }
    }

    /// Whether the request carries this daemon's token.
    fn authorized(&self, authorization: Option<&str>) -> bool {
        let Some(offered) = authorization.and_then(|value| value.strip_prefix("Bearer ")) else {
            return false;
        };
        constant_time_eq(offered.trim().as_bytes(), self.token.as_bytes())
    }

    fn reload(&self) -> RouteReply {
        match reload(&self.device, &self.conf_path, &self.plan) {
            Ok(report) => RouteReply::json(200, render_report(&report)),
            // The typed errors of the configuration name the rule that
            // refused, never the value that broke it, so they are safe to
            // answer with.
            Err(err) => RouteReply::text(400, format!("{err}\n")),
        }
    }

    fn reset_peer(&self, label: &str) -> RouteReply {
        let Ok(label) = PeerLabel::new(label) else {
            return RouteReply::text(404, "no peer carries that label\n".to_owned());
        };
        match self.device.reset_peer(&label) {
            Ok(()) => RouteReply::text(200, format!("{} reset\n", label.as_str())),
            Err(_) => RouteReply::text(404, "no peer carries that label\n".to_owned()),
        }
    }
}

/// Applies the configuration file as it now stands.
///
/// # Errors
///
/// [`ProvisionError`] when the file cannot be read or does not hold together,
/// in which case nothing changed.
pub fn reload(
    device: &GatewayDevice,
    conf_path: &Path,
    plan: &PeerPlan,
) -> Result<ReloadReport, ProvisionError> {
    let conf = provision::load_conf_from(conf_path, plan)?;
    device.reload(&conf).map_err(|err| match err {
        crate::device::GatewayError::Conf(err) => ProvisionError::Conf(err),
        // Neither of the other two can come out of a reload: it installs a
        // configuration, it pins nothing and it names no peer.
        other => ProvisionError::Io {
            path: conf_path.display().to_string(),
            source: std::io::Error::other(other.to_string()),
        },
    })
}

/// What a reload changed, as `/admin/reload` renders it.
fn render_report(report: &ReloadReport) -> String {
    let names = |labels: &[PeerLabel]| {
        labels
            .iter()
            .map(|l| format!("\"{}\"", l.as_str()))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "{{\"added\": [{}], \"removed\": [{}], \"rebuilt\": [{}], \"unchanged\": {}}}\n",
        names(&report.added),
        names(&report.removed),
        names(&report.rebuilt),
        report.unchanged
    )
}

/// An answer from a running daemon's admin surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminReply {
    /// The HTTP status it answered with.
    pub status: u16,
    /// The body, for the operator to read.
    pub body: String,
}

/// Posts one admin request to a running daemon.
///
/// # Errors
///
/// I/O errors reaching the endpoint, which is what a daemon that is not
/// running looks like.
pub fn post(addr: SocketAddr, path: &str, token: &str) -> std::io::Result<AdminReply> {
    use std::io::{Read as _, Write as _};
    let timeout = std::time::Duration::from_secs(8);
    let mut stream = std::net::TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(
        format!(
            "POST {path} HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {token}\r\n\
             content-length: 0\r\nconnection: close\r\n\r\n"
        )
        .as_bytes(),
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = response
        .split_once("\r\n\r\n")
        .map_or(String::new(), |(_, body)| body.to_owned());
    Ok(AdminReply { status, body })
}

/// Compares two secrets without letting the time it takes say how far they
/// matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use crate::device::{GatewayDevice, GatewayOptions};
    use crate::provision::InitOptions;

    fn env_for(dir: &Path) -> GatewayEnv {
        let map: HashMap<String, String> = [(
            "WARREN_BURROW_STATE_DIR".to_owned(),
            dir.display().to_string(),
        )]
        .into_iter()
        .collect();
        crate::config::load(
            move |k| map.get(k).cloned(),
            |_| Err(std::io::Error::other("no file")),
            |_| None,
            false,
        )
        .expect("a valid test environment")
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "warren-burrow-admin-{}-{name}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    async fn admin_for(env: &GatewayEnv, token: &str) -> Admin {
        let conf = provision::init(env, &InitOptions::default()).expect("a provisioned gateway");
        let sockets = crate::socket::bind_all(&["127.0.0.1:0".parse().unwrap()])
            .await
            .expect("loopback binds");
        let device = GatewayDevice::new(&conf.conf, env.plan, &GatewayOptions::default(), sockets)
            .expect("a device");
        Admin::new(
            device,
            env.conf_path.clone(),
            env.plan,
            Zeroizing::new(token.to_owned()),
        )
    }

    fn request<'a>(method: &'a str, path: &'a str, bearer: Option<&'a str>) -> Request<'a> {
        Request {
            method,
            path,
            authorization: bearer,
        }
    }

    /// The routes change the gateway's state, so an unauthenticated caller and
    /// a caller with the wrong token get the same answer, and a read method
    /// never triggers a write.
    #[tokio::test]
    async fn only_a_post_carrying_the_token_reaches_a_route() {
        let dir = temp_dir("token");
        let env = env_for(&dir);
        let admin = admin_for(&env, "sesame").await;

        for authorization in [None, Some("Bearer nope"), Some("sesame")] {
            let reply = admin
                .render(&request("POST", "/admin/reload", authorization))
                .expect("an admin path is always answered");
            assert_eq!(reply.status, 401, "{authorization:?}");
        }
        let reply = admin
            .render(&request("GET", "/admin/reload", Some("Bearer sesame")))
            .expect("an admin path is always answered");
        assert_eq!(reply.status, 405);

        let reply = admin
            .render(&request("POST", "/admin/reload", Some("Bearer sesame")))
            .expect("the route runs");
        assert_eq!(reply.status, 200, "{}", reply.body);
        assert!(reply.body.contains("\"unchanged\": 1"), "{}", reply.body);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The revocation path for a lost device: the peer disappears from the
    /// file, and a reload is what takes its session away from it.
    #[tokio::test]
    async fn a_reload_applies_what_the_file_now_says() {
        let dir = temp_dir("reload");
        let env = env_for(&dir);
        let admin = admin_for(&env, "sesame").await;
        provision::add_peer(&env, "phone", &crate::provision::PeerOptions::default())
            .expect("a second peer");

        let reply = admin
            .render(&request("POST", "/admin/reload", Some("Bearer sesame")))
            .expect("the route runs");

        assert_eq!(reply.status, 200);
        assert!(
            reply.body.contains("\"added\": [\"phone\"]"),
            "{}",
            reply.body
        );
        assert_eq!(admin.device.snapshot().peers.len(), 2);

        provision::remove_peer(&env, "phone").expect("the peer is revoked");
        let reply = admin
            .render(&request("POST", "/admin/reload", Some("Bearer sesame")))
            .expect("the route runs");
        assert!(
            reply.body.contains("\"removed\": [\"phone\"]"),
            "{}",
            reply.body
        );
        assert_eq!(admin.device.snapshot().peers.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The escape for a peer whose clock jumped: its session is rebuilt, and a
    /// label nobody carries is not a way to learn who does.
    #[tokio::test]
    async fn reset_peer_names_only_whether_that_label_exists() {
        let dir = temp_dir("reset");
        let env = env_for(&dir);
        let admin = admin_for(&env, "sesame").await;

        let reply = admin
            .render(&request(
                "POST",
                "/admin/reset-peer/peer2",
                Some("Bearer sesame"),
            ))
            .expect("the route runs");
        assert_eq!(reply.status, 200);
        assert!(reply.body.contains("peer2 reset"), "{}", reply.body);

        for path in ["/admin/reset-peer/nobody", "/admin/reset-peer/not a label"] {
            let reply = admin
                .render(&request("POST", path, Some("Bearer sesame")))
                .expect("the route runs");
            assert_eq!(reply.status, 404, "{path}");
        }
        let reply = admin
            .render(&request("POST", "/admin/nothing", Some("Bearer sesame")))
            .expect("an admin path is always answered");
        assert_eq!(reply.status, 404);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A path this module does not own falls through to the routes that do.
    #[tokio::test]
    async fn a_path_outside_admin_is_left_to_the_other_routes() {
        let dir = temp_dir("fallthrough");
        let env = env_for(&dir);
        let admin = admin_for(&env, "sesame").await;

        assert!(admin.render(&request("GET", "/status", None)).is_none());
        assert!(admin.render(&request("GET", "/healthz", None)).is_none());
        assert!(admin.render(&request("GET", "/adminx", None)).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The token is a credential to the gateway's write surface: it is written
    /// as privately as the keys, and a fresh one at every start makes a copy
    /// taken from a backup useless.
    #[test]
    fn the_token_is_written_privately_and_regenerated() {
        let dir = temp_dir("write-token");
        let env = env_for(&dir);
        std::fs::create_dir_all(&dir).expect("the state directory");

        let first = write_token(&env).expect("a token is written");
        assert_eq!(read_token(&env).expect("it reads back").as_str(), &*first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let mode = std::fs::metadata(token_path(&env))
                .expect("the file")
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let second = write_token(&env).expect("a second start writes another");
        assert_ne!(*first, *second);

        forget_token(&env);
        assert!(
            matches!(read_token(&env), Err(ProvisionError::NoDaemonToken)),
            "with no daemon running there is no token to present"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_token_comparison_answers_on_the_whole_value() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
    }
}
