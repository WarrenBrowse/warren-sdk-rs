//! Userland-purity invariant.
//!
//! The default build of `warren-sdk` (no-root, userland proxy datapath) must
//! pull **zero privileged code**: no TUN device open, no OS killswitch, no
//! `pfctl`/`wintun`. Privileged datapaths live in separate crates behind the
//! `experimental-tun` feature, which is OFF by default. This is a **crate**
//! boundary, not just a feature flag, so it survives Cargo's workspace-wide
//! feature unification (the footgun: a sibling member enabling a feature must
//! not be able to drag privileged code into a userland build).
//!
//! ## Why this is `#[ignore]` today
//!
//! `warren-net` currently depends on `warren-tun` **unconditionally**
//! (`warren-net/Cargo.toml`), so `warren-tun`, which carries the privileged
//! device-open code, is already in `warren-sdk`'s default dependency closure.
//! The fix is to split `warren-tun` into a safe core crate (traits, types and
//! parsers: zero unsafe, always on) and a privileged device crate (the only
//! unsafe+root crate, gated behind `experimental-tun`), then re-point the
//! TUN-to-sink bridge at the safe core. Once that unconditional edge is gone the
//! default closure is privileged-free and this test flips GREEN (drop the
//! `#[ignore]`).
//!
//! `libc` and `smoltcp` in the default closure are **OK**: they are userland
//! FFI / a userspace netstack, not privileged operations. The invariant keys
//! on privileged *crate names*, never on `libc`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::process::Command;

use serde_json::Value;

/// Crate names that must never appear in the userland (default-feature) closure
/// of `warren-sdk`. The post-split engine names are listed alongside the current
/// monolithic `warren-tun` so the assertion is correct both before and after the
/// device-crate split.
const PRIVILEGED_CRATES: &[&str] = &[
    // Current monolith carrying the privileged device-open (pre-split).
    "warren-tun",
    // Post-split engine crates carrying the privileged device-open / OS killswitch.
    "warrenguard-tun-device",
    "warrenguard-killswitch-os",
    // Platform privileged shims that must only ever appear feature-gated.
    "pfctl",
    "wintun",
];

/// Walk `warren-sdk`'s default-feature dependency closure over non-dev edges and
/// return the set of reachable crate names.
fn default_closure_crate_names() -> HashSet<String> {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            // Resolve the workspace's default features. Dev-dependencies are
            // filtered below by inspecting each edge's `dep_kinds`.
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let meta: Value = serde_json::from_slice(&output.stdout).expect("metadata is valid JSON");

    // id -> crate name, for every package in the graph.
    let mut name_by_id: HashMap<String, String> = HashMap::new();
    for pkg in meta["packages"].as_array().expect("packages array") {
        let id = pkg["id"].as_str().expect("package id").to_owned();
        let name = pkg["name"].as_str().expect("package name").to_owned();
        name_by_id.insert(id, name);
    }

    // id -> resolved node (carries the feature-activated dependency edges).
    let resolve = &meta["resolve"];
    let mut node_by_id: HashMap<&str, &Value> = HashMap::new();
    for node in resolve["nodes"].as_array().expect("resolve nodes") {
        node_by_id.insert(node["id"].as_str().expect("node id"), node);
    }

    let sdk_id = name_by_id
        .iter()
        .find(|(_, name)| name.as_str() == "warren-sdk")
        .map(|(id, _)| id.clone())
        .expect("warren-sdk package is present");

    // BFS over non-dev edges (normal + build, matching `cargo tree -e no-dev`).
    let mut reached: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(sdk_id);
    while let Some(id) = queue.pop_front() {
        let Some(node) = node_by_id.get(id.as_str()) else {
            continue;
        };
        for dep in node["deps"].as_array().into_iter().flatten() {
            let is_dev_only = dep["dep_kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .all(|k| k["kind"].as_str() == Some("dev"));
            if is_dev_only {
                continue;
            }
            let Some(dep_id) = dep["pkg"].as_str() else {
                continue;
            };
            if let Some(name) = name_by_id.get(dep_id)
                && reached.insert(name.clone())
            {
                queue.push_back(dep_id.to_owned());
            }
        }
    }
    reached
}

#[test]
#[ignore = "RED until warren-tun is split into a safe core and a privileged device crate (the unconditional warren-net to warren-tun edge keeps privileged code in the default closure)"]
fn default_build_pulls_no_privileged_crate() {
    let reached = default_closure_crate_names();
    let violations: Vec<&str> = PRIVILEGED_CRATES
        .iter()
        .copied()
        .filter(|c| reached.contains(*c))
        .collect();
    assert!(
        violations.is_empty(),
        "userland (default-feature) closure of warren-sdk must contain no privileged crate, \
         found: {violations:?}. Privileged datapaths belong behind `experimental-tun` in \
         separate crates."
    );
}
