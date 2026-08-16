//! First run, and the subcommands that write the credentials.
//!
//! Everything a peer needs is generated here and written once: the gateway's
//! own configuration, one stock client configuration per peer, the gluetun
//! environment snippet, and a README that says plainly what those files are.
//! Peer private keys are kept nowhere else, which is why the client files are
//! the credentials and why they are created 0600 under a 0700 directory, with
//! no window in between.

use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use ip_network::IpNetwork;
use warren_burrow_core::{
    ClientConf, ConfError, GatewayConf, GatewayKey, LabelError, PeerConf, PeerLabel, PlanError,
    PresharedKey, parse_gateway_conf, render_client_conf, render_gateway_conf, render_gluetun_env,
};
use zeroize::Zeroizing;

use crate::config::GatewayEnv;

/// How often a peer reminds the gateway it is there. It is what holds open the
/// NAT between a peer and this gateway, which is the path inbound traffic
/// takes.
const KEEPALIVE_SECS: u16 = 25;

/// Why provisioning refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProvisionError {
    /// The state directory holds something else, and is never clobbered.
    #[error(
        "the state directory is not empty and holds no gateway configuration: refusing to write \
         into it. Point WARREN_BURROW_STATE_DIR somewhere else, or empty it"
    )]
    StateDirNotEmpty,
    /// A configuration is already there.
    #[error("a gateway configuration already exists: pass --force to replace it")]
    AlreadyProvisioned,
    /// Nothing to show or remove under that label.
    #[error("no peer carries that label")]
    UnknownPeer,
    /// The label is already taken.
    #[error("a peer already carries that label")]
    DuplicateLabel,
    /// The label is not usable.
    #[error(transparent)]
    Label(#[from] LabelError),
    /// The peer plan cannot number that many peers.
    #[error(transparent)]
    Plan(#[from] PlanError),
    /// The configuration file could not be parsed or does not hold together.
    #[error(transparent)]
    Conf(#[from] ConfError),
    /// No endpoint could be written into the client configurations.
    #[error(
        "could not detect an address peers can reach this gateway at: set WARREN_BURROW_ENDPOINT"
    )]
    EndpointUnknown,
    /// A LAN gateway was about to hand out an endpoint nobody can reach.
    #[error(
        "the detected endpoint is a loopback address while WARREN_BURROW_LAN=1: set \
         WARREN_BURROW_ENDPOINT to the address peers reach this host at"
    )]
    LoopbackEndpoint,
    /// No daemon has written an admin token, so there is nothing to talk to.
    #[error(
        "no running daemon left an admin token in the state directory: start the gateway, or \
         apply the change at its next start"
    )]
    NoDaemonToken,
    /// A file could not be written.
    #[error("writing {path}")]
    Io {
        /// The file at fault.
        path: String,
        /// What the filesystem said.
        #[source]
        source: std::io::Error,
    },
}

/// What a provisioning run produced.
#[derive(Debug)]
pub struct Provisioned {
    /// The gateway configuration now on disk.
    pub conf: GatewayConf,
    /// The peers whose client files were written by this run.
    pub written: Vec<PeerLabel>,
    /// Where they were written.
    pub clients_dir: PathBuf,
}

/// How a peer's client files are shaped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerOptions {
    /// Prefixes the peer keeps reaching directly, outside the tunnel.
    pub lan_exclude: Vec<IpNetwork>,
    /// Write v4-only lines, for a host whose kernel has IPv6 disabled
    /// entirely (wg-quick fails on `ip -6 address add` there).
    pub no_v6: bool,
}

/// How a first run or an explicit `init` is shaped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitOptions {
    /// How many peers to generate; the environment's own count when unset.
    pub peers: Option<u32>,
    /// Operator labels, in order; missing ones are named `peerN`.
    pub labels: Vec<String>,
    /// Shared shape of every client file this run writes.
    pub peer: PeerOptions,
    /// Move an existing configuration aside instead of refusing.
    pub force: bool,
}

/// Reads the gateway configuration.
///
/// # Errors
///
/// [`ProvisionError::Io`] when it cannot be read, [`ProvisionError::Conf`]
/// when it does not parse or breaks a rule.
pub fn load_conf(env: &GatewayEnv) -> Result<GatewayConf, ProvisionError> {
    load_conf_from(&env.conf_path, &env.plan)
}

/// Reads a gateway configuration and checks it against a peer plan.
///
/// # Errors
///
/// [`ProvisionError::Io`] when it cannot be read, [`ProvisionError::Conf`]
/// when it does not parse or breaks a rule.
pub fn load_conf_from(
    path: &Path,
    plan: &warren_burrow_core::PeerPlan,
) -> Result<GatewayConf, ProvisionError> {
    let text =
        Zeroizing::new(
            std::fs::read_to_string(path).map_err(|source| ProvisionError::Io {
                path: path.display().to_string(),
                source,
            })?,
        );
    let conf = parse_gateway_conf(&text)?;
    conf.check_against(plan)?;
    Ok(conf)
}

/// Writes a file only its owner can read, replacing whatever was there.
///
/// The same discipline as the client credentials: the mode is set at creation
/// and the file appears whole or not at all.
///
/// # Errors
///
/// [`ProvisionError::Io`] when it cannot be written.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), ProvisionError> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    write_private(path, bytes)
}

/// Whether a gateway configuration already exists.
#[must_use]
pub fn is_provisioned(env: &GatewayEnv) -> bool {
    env.conf_path.exists()
}

/// Generates a gateway and `env.peers` peers, and writes every file.
///
/// # Errors
///
/// See [`ProvisionError`]. A state directory that holds something other than a
/// gateway configuration is refused rather than written into.
pub fn init(env: &GatewayEnv, options: &InitOptions) -> Result<Provisioned, ProvisionError> {
    if is_provisioned(env) {
        if !options.force {
            return Err(ProvisionError::AlreadyProvisioned);
        }
        move_aside(env)?;
    } else if state_dir_has_other_files(env)? {
        return Err(ProvisionError::StateDirNotEmpty);
    }

    let endpoint = resolve_endpoint(env)?;
    let key = GatewayKey::generate();
    let gateway_public = key.public();
    let mut conf = GatewayConf {
        key,
        peers: Vec::new(),
    };
    let mut written = Vec::new();
    let count = options.peers.unwrap_or(env.peers);
    for number in 0..count {
        let index = number + 2;
        let label = match options.labels.get(number as usize) {
            Some(name) => PeerLabel::new(name)?,
            None => PeerLabel::new(&format!("peer{index}"))?,
        };
        let peer = build_peer(env, &label, index, gateway_public, endpoint, &options.peer)?;
        write_client_files(env, &peer.client)?;
        conf.peers.push(peer.conf);
        written.push(label);
    }
    write_gateway_conf(env, &conf)?;
    write_readme(env, &written)?;
    Ok(Provisioned {
        conf,
        written,
        clients_dir: env.clients_dir(),
    })
}

/// Adds one peer to an existing configuration and writes its client files.
///
/// # Errors
///
/// See [`ProvisionError`].
pub fn add_peer(
    env: &GatewayEnv,
    label: &str,
    options: &PeerOptions,
) -> Result<Provisioned, ProvisionError> {
    let label = PeerLabel::new(label)?;
    let mut conf = load_conf(env)?;
    if conf.peers.iter().any(|p| p.label == label) {
        return Err(ProvisionError::DuplicateLabel);
    }
    let endpoint = resolve_endpoint(env)?;
    let index = next_free_index(env, &conf)?;
    let peer = build_peer(env, &label, index, conf.key.public(), endpoint, options)?;
    write_client_files(env, &peer.client)?;
    conf.peers.push(peer.conf);
    write_gateway_conf(env, &conf)?;
    Ok(Provisioned {
        conf,
        written: vec![label],
        clients_dir: env.clients_dir(),
    })
}

/// Removes one peer and deletes its client files.
///
/// This is the revocation path for a lost device: the gateway drops its
/// session, its endpoint and its NAT mappings the moment it reloads.
///
/// # Errors
///
/// [`ProvisionError::UnknownPeer`] when no peer carries that label.
pub fn remove_peer(env: &GatewayEnv, label: &str) -> Result<GatewayConf, ProvisionError> {
    let label = PeerLabel::new(label)?;
    let mut conf = load_conf(env)?;
    let before = conf.peers.len();
    conf.peers.retain(|p| p.label != label);
    if conf.peers.len() == before {
        return Err(ProvisionError::UnknownPeer);
    }
    write_gateway_conf(env, &conf)?;
    for name in client_file_names(&label) {
        let path = env.clients_dir().join(name);
        // A file an operator already deleted is not an error; the credential
        // is revoked by the configuration, not by the file.
        let _ = std::fs::remove_file(path);
    }
    Ok(conf)
}

/// The client configuration of one peer, as it was written.
///
/// # Errors
///
/// [`ProvisionError::UnknownPeer`] when no file carries that label.
pub fn show(env: &GatewayEnv, label: &str) -> Result<Zeroizing<String>, ProvisionError> {
    let label = PeerLabel::new(label)?;
    let path = env.clients_dir().join(format!("{}.conf", label.as_str()));
    std::fs::read_to_string(&path)
        .map(Zeroizing::new)
        .map_err(|_| ProvisionError::UnknownPeer)
}

/// The same configuration as a terminal QR code, for a phone or a TV.
///
/// # Errors
///
/// [`ProvisionError::UnknownPeer`] when no file carries that label.
#[cfg(feature = "qr")]
pub fn show_qr(env: &GatewayEnv, label: &str) -> Result<Zeroizing<String>, ProvisionError> {
    let conf = show(env, label)?;
    let code = qrcode::QrCode::new(conf.as_bytes()).map_err(|_| ProvisionError::UnknownPeer)?;
    Ok(Zeroizing::new(
        code.render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(true)
            .build(),
    ))
}

/// The endpoint written into client configurations.
///
/// # Errors
///
/// [`ProvisionError::EndpointUnknown`] when a LAN gateway has no explicit
/// endpoint and none could be detected, [`ProvisionError::LoopbackEndpoint`]
/// when detection returned an address no other device can reach.
pub fn resolve_endpoint(env: &GatewayEnv) -> Result<SocketAddr, ProvisionError> {
    resolve_endpoint_with(env, detect_local_address)
}

/// The same, with the detection injected so both refusals are testable without
/// a network.
///
/// # Errors
///
/// See [`resolve_endpoint`].
pub fn resolve_endpoint_with(
    env: &GatewayEnv,
    detect: impl FnOnce() -> Option<IpAddr>,
) -> Result<SocketAddr, ProvisionError> {
    if let Some(endpoint) = env.endpoint {
        return Ok(endpoint);
    }
    let port = env.listen.first().map_or(51820, SocketAddr::port);
    if !env.lan {
        // A loopback gateway is reachable from this host alone, which is what
        // the default asks for.
        return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    let detected = detect().ok_or(ProvisionError::EndpointUnknown)?;
    if detected.is_loopback() {
        return Err(ProvisionError::LoopbackEndpoint);
    }
    Ok(SocketAddr::new(detected, port))
}

/// This host's address on the interface its default route uses.
///
/// A connected UDP socket sends nothing: the kernel picks the source address
/// the route would use, which is exactly the address a peer on that network
/// reaches this host at.
#[must_use]
pub fn detect_local_address() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:53").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// One generated peer: what goes in the gateway file, and what goes to the
/// operator.
struct GeneratedPeer {
    conf: PeerConf,
    client: ClientConf,
}

fn build_peer(
    env: &GatewayEnv,
    label: &PeerLabel,
    index: u32,
    gateway_public: warren_burrow_core::PeerPublicKey,
    endpoint: SocketAddr,
    options: &PeerOptions,
) -> Result<GeneratedPeer, ProvisionError> {
    let (v4, v6) = env.plan.address_for(index)?;
    let key = GatewayKey::generate();
    let psk = PresharedKey::generate();
    let mut allowed = vec![IpNetwork::new(IpAddr::V4(v4), 32).expect("a host prefix")];
    if !options.no_v6 {
        allowed.push(IpNetwork::new(IpAddr::V6(v6), 128).expect("a host prefix"));
    }
    let public = key.public();
    Ok(GeneratedPeer {
        conf: PeerConf {
            label: label.clone(),
            public,
            psk: Some(psk.clone()),
            allowed,
        },
        client: ClientConf {
            label: label.clone(),
            private_key: key.to_base64_zeroizing(),
            address_v4: v4,
            address_v6: (!options.no_v6).then_some(v6),
            gateway_public,
            psk,
            endpoint,
            dns: env.dns_server,
            mtu: env.client_mtu,
            keepalive: KEEPALIVE_SECS,
            lan_exclude: options.lan_exclude.clone(),
        },
    })
}

/// The lowest peer number no existing peer holds.
fn next_free_index(env: &GatewayEnv, conf: &GatewayConf) -> Result<u32, ProvisionError> {
    let base = u32::from(env.plan.subnet_v4().network_address());
    let taken: Vec<u32> = conf
        .peers
        .iter()
        .flat_map(|p| p.allowed.iter())
        .filter_map(|n| match n.network_address() {
            IpAddr::V4(v4) => Some(u32::from(v4).wrapping_sub(base)),
            IpAddr::V6(_) => None,
        })
        .collect();
    (2..)
        .find(|index| !taken.contains(index))
        .filter(|index| env.plan.address_for(*index).is_ok())
        .ok_or(ProvisionError::Plan(PlanError::IndexOutOfRange))
}

fn client_file_names(label: &PeerLabel) -> [String; 2] {
    [
        format!("{}.conf", label.as_str()),
        format!("{}.gluetun.env", label.as_str()),
    ]
}

fn write_client_files(env: &GatewayEnv, client: &ClientConf) -> Result<(), ProvisionError> {
    let dir = env.clients_dir();
    create_private_dir(&dir)?;
    let [conf_name, env_name] = client_file_names(&client.label);
    write_private(&dir.join(conf_name), render_client_conf(client).as_bytes())?;
    write_private(&dir.join(env_name), render_gluetun_env(client).as_bytes())
}

fn write_gateway_conf(env: &GatewayEnv, conf: &GatewayConf) -> Result<(), ProvisionError> {
    create_private_dir(&env.state_dir)?;
    write_private(&env.conf_path, render_gateway_conf(conf).as_bytes())
}

fn write_readme(env: &GatewayEnv, written: &[PeerLabel]) -> Result<(), ProvisionError> {
    let first = written
        .first()
        .map_or_else(|| "peer2".to_owned(), |l| l.as_str().to_owned());
    let body = format!(
        "This directory holds the credentials of a Warren local gateway.\n\
         \n\
         The files under clients/ ARE the credentials. Each one carries a peer's private key and \n\
         its preshared key, and they are kept nowhere else: whoever holds one can join this \n\
         gateway. Retrieve one with:\n\
         \n\
             warren-burrow show {first}\n\
         \n\
         In a container:\n\
         \n\
             docker exec <container> warren-burrow show {first}\n\
         \n\
         Three things to know about what this gateway is.\n\
         \n\
         1. One Warren session, shared. Every peer of this gateway rides one authenticated \n\
         session: one address assigned at the exit, one abuse identity, one device slot on the \n\
         account, one port-forwarding quota, one failover (a peer that congests the uplink can \n\
         get the tunnel rebuilt, and every peer's public address changes with it), shared NAT \n\
         state and bandwidth, and no per-peer accounting. Peer isolation keeps peers from \n\
         reaching each other; it does not isolate their share of the session.\n\
         \n\
         2. Warren's QUIC transport and its obfuscation begin AT this gateway. The hop between a \n\
         stock client and this gateway is ordinary WireGuard, recognisable to anyone inspecting \n\
         the traffic. On a home network or a NAS that hop is local, which is the point; a gateway \n\
         reachable across the internet gives up Warren's censorship resistance for that leg. Do \n\
         not publish the gateway's UDP port to the internet.\n\
         \n\
         3. The kill switch is the peer's own setting. This gateway never routes a peer's packet \n\
         anywhere but into the tunnel, so it fails closed by construction. What it cannot do is \n\
         stop a peer's operating system from routing around an interface that was torn down. Use \n\
         the client's own setting where it has one: \"block untunneled traffic\" on Windows, \n\
         \"block connections without VPN\" on Android, gluetun's own firewall, your router's \n\
         equivalent.\n\
         \n\
         A peer with a full-tunnel configuration loses access to its own LAN (printer, NAS, \n\
         casting) unless it was generated with an excluded prefix, and an excluded LAN is not \n\
         protected.\n\
         \n\
         \"WireGuard\" is a registered trademark of Jason A. Donenfeld.\n"
    );
    write_private(&env.state_dir.join("README.txt"), body.as_bytes())
}

/// Moves an existing configuration and its client files aside, so `--force`
/// never destroys a credential an operator still has a device on.
fn move_aside(env: &GatewayEnv) -> Result<(), ProvisionError> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let backup = env
        .conf_path
        .with_extension(format!("conf.bak-{stamp}"))
        .to_owned();
    std::fs::rename(&env.conf_path, &backup).map_err(|source| ProvisionError::Io {
        path: env.conf_path.display().to_string(),
        source,
    })?;
    let clients = env.clients_dir();
    if clients.exists() {
        let backup = clients.with_file_name(format!("clients.bak-{stamp}"));
        std::fs::rename(&clients, &backup).map_err(|source| ProvisionError::Io {
            path: clients.display().to_string(),
            source,
        })?;
    }
    Ok(())
}

/// Whether the state directory holds anything but what this gateway writes.
///
/// The configuration's own name comes from the environment, so the file this
/// gateway is about to write is never what makes its directory look occupied.
fn state_dir_has_other_files(env: &GatewayEnv) -> Result<bool, ProvisionError> {
    let dir = &env.state_dir;
    if !dir.exists() {
        return Ok(false);
    }
    let conf_name = env.conf_path.file_name().map_or_else(
        || "burrow.conf".to_owned(),
        |n| n.to_string_lossy().into_owned(),
    );
    let entries = std::fs::read_dir(dir).map_err(|source| ProvisionError::Io {
        path: dir.display().to_string(),
        source,
    })?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let ours = name == "clients"
            || name == "README.txt"
            || name == crate::admin::TOKEN_FILE
            || name.starts_with(conf_name.as_str());
        if !ours {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Creates a directory only this user can enter, if it is not there yet.
fn create_private_dir(path: &Path) -> Result<(), ProvisionError> {
    if path.exists() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|source| ProvisionError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Writes a file only its owner can read, atomically.
///
/// Created with the mode already set rather than chmod-ed afterwards (no
/// window where the umask decides who can read a private key), through a
/// temporary name and a rename (no partial file ever carries a key).
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ProvisionError> {
    let tmp = path.with_extension("tmp");
    let io = |source| ProvisionError::Io {
        path: path.display().to_string(),
        source,
    };
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_for(dir: &Path, pairs: &[(&str, &str)]) -> GatewayEnv {
        let mut all: Vec<(String, String)> = vec![
            ("WARREN_MNEMONIC".to_owned(), "m".to_owned()),
            (
                "WARREN_BURROW_STATE_DIR".to_owned(),
                dir.display().to_string(),
            ),
        ];
        all.extend(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        );
        let map: HashMap<String, String> = all.into_iter().collect();
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
            "warren-burrow-{}-{name}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(path).expect("the file exists").mode() & 0o777
    }

    /// What a container start on an empty volume produces: everything a peer
    /// needs, and nothing readable by anyone else.
    #[test]
    fn a_first_run_writes_every_file_private_and_atomically() {
        let dir = temp_dir("first-run");
        let env = env_for(&dir, &[("WARREN_BURROW_PEERS", "2")]);

        let out = init(&env, &InitOptions::default()).expect("an empty state dir provisions");

        assert_eq!(out.conf.peers.len(), 2);
        assert_eq!(
            out.written
                .iter()
                .map(PeerLabel::as_str)
                .collect::<Vec<_>>(),
            vec!["peer2", "peer3"]
        );
        for label in &out.written {
            for name in client_file_names(label) {
                let path = out.clients_dir.join(&name);
                assert!(path.exists(), "{name} must be written");
                #[cfg(unix)]
                assert_eq!(mode_of(&path), 0o600, "{name} carries a private key");
                assert!(
                    !path.with_extension("tmp").exists(),
                    "no partial file may be left behind"
                );
            }
        }
        assert!(env.conf_path.exists());
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&env.conf_path), 0o600);
            assert_eq!(mode_of(&dir), 0o700, "the state directory is private too");
        }
        let readme = std::fs::read_to_string(dir.join("README.txt")).expect("a README");
        assert!(readme.contains("warren-burrow show peer2"), "{readme}");
        assert!(readme.contains("ARE the credentials"), "{readme}");
        assert!(
            readme.contains("obfuscation begin AT this gateway"),
            "{readme}"
        );
        assert!(
            readme.contains("kill switch is the peer's own setting"),
            "{readme}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_state_directory_that_holds_something_else_is_never_clobbered() {
        let dir = temp_dir("not-empty");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("important.db"), b"someone else's").unwrap();
        let env = env_for(&dir, &[]);

        let err = init(&env, &InitOptions::default()).expect_err("a busy directory must refuse");

        assert!(matches!(err, ProvisionError::StateDirNotEmpty));
        assert!(!env.conf_path.exists(), "nothing was written");
        assert_eq!(
            std::fs::read(dir.join("important.db")).unwrap(),
            b"someone else's"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_init_refuses_and_force_moves_the_previous_files_aside() {
        let dir = temp_dir("force");
        let env = env_for(&dir, &[]);
        let first = init(&env, &InitOptions::default()).expect("the first run");
        let first_key = first.conf.key.public();

        let err = init(&env, &InitOptions::default()).expect_err("a second run must refuse");
        assert!(matches!(err, ProvisionError::AlreadyProvisioned));

        let second = init(
            &env,
            &InitOptions {
                force: true,
                ..InitOptions::default()
            },
        )
        .expect("force replaces it");
        assert_ne!(
            second.conf.key.public().to_base64(),
            first_key.to_base64(),
            "a forced run generates a fresh gateway key"
        );
        let backups: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".bak-"))
            .collect();
        assert!(
            backups.iter().any(|n| n.starts_with("burrow.")),
            "the previous configuration must be kept, not destroyed: {backups:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_peer_is_added_on_the_next_free_address_and_removed_with_its_files() {
        let dir = temp_dir("add-remove");
        let env = env_for(&dir, &[]);
        init(&env, &InitOptions::default()).expect("the first run");

        let added = add_peer(&env, "livingroom-tv", &PeerOptions::default()).expect("a new peer");
        assert_eq!(added.conf.peers.len(), 2);
        let client = show(&env, "livingroom-tv")
            .expect("its configuration")
            .to_string();
        assert!(
            client.contains("Address = 10.67.0.3/32"),
            "the second peer takes the next address: {client}"
        );

        assert!(matches!(
            add_peer(&env, "livingroom-tv", &PeerOptions::default()),
            Err(ProvisionError::DuplicateLabel)
        ));

        let conf = remove_peer(&env, "livingroom-tv").expect("the peer is revoked");
        assert_eq!(conf.peers.len(), 1);
        assert!(
            show(&env, "livingroom-tv").is_err(),
            "a revoked peer's credential must be gone"
        );
        assert!(matches!(
            remove_peer(&env, "nobody"),
            Err(ProvisionError::UnknownPeer)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A peer that routed only IPv4 would keep its native IPv6 default route
    /// and send every AAAA-resolved connection outside the tunnel, under its
    /// own address.
    #[test]
    fn a_client_configuration_routes_both_families_into_the_tunnel() {
        let dir = temp_dir("both-families");
        let env = env_for(&dir, &[]);
        init(&env, &InitOptions::default()).expect("the first run");

        let client = show(&env, "peer2").expect("its configuration").to_string();

        assert!(client.contains("AllowedIPs = 0.0.0.0/0, ::/0"), "{client}");
        assert!(
            client.contains("Address = 10.67.0.2/32, fd77:6172:7265::2/128"),
            "{client}"
        );
        assert!(client.contains("DNS = 10.66.0.1"), "{client}");
        assert!(client.contains("MTU = 1280"), "{client}");
        assert!(client.contains("PersistentKeepalive = 25"), "{client}");
        assert!(client.contains("Endpoint = 127.0.0.1:51820"), "{client}");

        let gluetun = std::fs::read_to_string(env.clients_dir().join("peer2.gluetun.env"))
            .expect("the gluetun snippet");
        assert!(gluetun.contains("WIREGUARD_MTU=1280"), "{gluetun}");
        assert!(
            gluetun.contains("WIREGUARD_PERSISTENT_KEEPALIVE_INTERVAL=25s"),
            "gluetun ignores the .conf's keepalive, so the env must carry it: {gluetun}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_excluded_lan_and_a_v4_only_host_shape_the_client_lines() {
        let dir = temp_dir("shaped");
        let env = env_for(&dir, &[("WARREN_BURROW_PEERS", "1")]);
        init(
            &env,
            &InitOptions {
                peers: None,
                labels: vec!["phone".to_owned()],
                peer: PeerOptions {
                    lan_exclude: vec!["192.168.1.0/24".parse().unwrap()],
                    no_v6: true,
                },
                force: false,
            },
        )
        .expect("the first run");

        let client = show(&env, "phone").expect("its configuration").to_string();
        assert!(
            !client.contains("::/0"),
            "an excluded LAN is a split route: {client}"
        );
        assert!(
            !client.contains("fd77:"),
            "a v4-only host writes no v6 line: {client}"
        );
        assert!(
            !client.contains("192.168.1.0/24"),
            "the excluded prefix is what is absent from the routes: {client}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The client files are the only copy of a peer's private key, so a
    /// gateway file that carried one would double the blast radius of a leak.
    #[test]
    fn the_gateway_file_holds_no_peer_private_key() {
        let dir = temp_dir("no-peer-secret");
        let env = env_for(&dir, &[]);
        init(&env, &InitOptions::default()).expect("the first run");

        let client = show(&env, "peer2").expect("its configuration").to_string();
        let private = client
            .lines()
            .find_map(|l| l.strip_prefix("PrivateKey = "))
            .expect("a private key")
            .to_owned();
        let gateway = std::fs::read_to_string(&env.conf_path).expect("the gateway file");

        assert!(
            !gateway.contains(&private),
            "a peer's private key must live in its own file alone"
        );
        assert!(gateway.contains("[Peer]"), "{gateway}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_loopback_gateway_writes_a_loopback_endpoint_and_an_explicit_one_is_kept() {
        let dir = temp_dir("endpoint");
        let env = env_for(&dir, &[]);
        assert_eq!(
            resolve_endpoint(&env).unwrap(),
            "127.0.0.1:51820".parse().unwrap()
        );

        let explicit = env_for(&dir, &[("WARREN_BURROW_ENDPOINT", "192.168.1.10:51820")]);
        assert_eq!(
            resolve_endpoint(&explicit).unwrap(),
            "192.168.1.10:51820".parse().unwrap(),
            "an explicit endpoint is never second-guessed"
        );
    }

    /// A LAN gateway hands its endpoint to devices that are not this host, so
    /// a detection that finds nothing, or finds only loopback, refuses rather
    /// than writing configurations that are dead on arrival.
    #[test]
    fn a_lan_gateway_refuses_an_endpoint_no_peer_could_reach() {
        let dir = temp_dir("lan-endpoint");
        let env = env_for(
            &dir,
            &[
                ("WARREN_BURROW_LAN", "1"),
                ("WARREN_BURROW_LISTEN", "0.0.0.0:51820"),
            ],
        );

        assert!(matches!(
            resolve_endpoint_with(&env, || None),
            Err(ProvisionError::EndpointUnknown)
        ));
        assert!(matches!(
            resolve_endpoint_with(&env, || Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))),
            Err(ProvisionError::LoopbackEndpoint)
        ));
        assert_eq!(
            resolve_endpoint_with(&env, || Some("192.168.1.10".parse().unwrap()))
                .expect("a routable address is what peers reach this host at"),
            "192.168.1.10:51820".parse().unwrap()
        );
    }

    /// A state directory that holds only what this gateway writes is not
    /// occupied by someone else, whatever the configuration file is called.
    #[test]
    fn the_files_this_gateway_writes_never_make_its_own_directory_look_busy() {
        let dir = temp_dir("own-files");
        std::fs::create_dir_all(&dir).unwrap();
        let env = env_for(
            &dir,
            &[(
                "WARREN_BURROW_CONF",
                &dir.join("gateway.conf").display().to_string(),
            )],
        );
        std::fs::write(dir.join("admin.token"), b"a token from a previous run").unwrap();
        std::fs::write(dir.join("README.txt"), b"the README").unwrap();

        init(&env, &InitOptions::default()).expect("its own files do not occupy the directory");

        std::fs::write(dir.join("someone-elses.db"), b"data").unwrap();
        let env = env_for(&temp_dir("own-files-2"), &[]);
        let _ = std::fs::create_dir_all(&env.state_dir);
        std::fs::write(env.state_dir.join("someone-elses.db"), b"data").unwrap();
        assert!(matches!(
            init(&env, &InitOptions::default()),
            Err(ProvisionError::StateDirNotEmpty)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&env.state_dir);
    }

    #[test]
    fn a_written_configuration_parses_back_into_the_same_peers() {
        let dir = temp_dir("round-trip");
        let env = env_for(&dir, &[("WARREN_BURROW_PEERS", "3")]);
        let written = init(&env, &InitOptions::default()).expect("the first run");

        let read = load_conf(&env).expect("the file parses");

        assert_eq!(
            read.key.public().to_base64(),
            written.conf.key.public().to_base64()
        );
        assert_eq!(read.peers.len(), 3);
        for (a, b) in read.peers.iter().zip(written.conf.peers.iter()) {
            assert_eq!(a.label, b.label);
            assert_eq!(a.public.to_base64(), b.public.to_base64());
            assert_eq!(a.allowed, b.allowed);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
