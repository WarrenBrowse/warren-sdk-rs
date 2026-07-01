//! Clean-room invariant: the SDK never depends on the private backend.
//!
//! `warren-core` is read-only reference material; the dependency direction is
//! backend -> contract/engine -> SDK, never SDK -> backend. Nothing in the
//! build system enforces that by construction (a stray `path = "../warren-core/..."`
//! or a backend git-dep would compile fine), so this test walks the full
//! resolved graph of the workspace, dev- and build-dependencies included, and
//! fails on any package that is `warren-core` or is sourced from a warren-core
//! git repository or checkout.

use std::process::Command;

use serde_json::Value;

/// A package belongs to the private backend when it is the `warren-core`
/// crate itself, or when its source (git URL) or manifest path points into a
/// warren-core repository. The `/warren-core` needle keeps the sibling
/// `../warren-contract` checkout from matching while still catching any
/// `warren-core`-rooted path or repo.
fn is_backend_package(pkg: &Value) -> bool {
    if pkg["name"].as_str() == Some("warren-core") {
        return true;
    }
    if let Some(source) = pkg["source"].as_str()
        && source.contains("/warren-core")
    {
        return true;
    }
    pkg["manifest_path"]
        .as_str()
        .is_some_and(|p| p.contains("/warren-core/"))
}

#[test]
fn workspace_graph_contains_no_warren_core() {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let meta: Value = serde_json::from_slice(&output.stdout).expect("metadata is valid JSON");

    let violations: Vec<String> = meta["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .filter(|pkg| is_backend_package(pkg))
        .map(|pkg| {
            format!(
                "{} ({})",
                pkg["name"].as_str().unwrap_or("?"),
                pkg["source"]
                    .as_str()
                    .or(pkg["manifest_path"].as_str())
                    .unwrap_or("?")
            )
        })
        .collect();
    assert!(
        violations.is_empty(),
        "the SDK dependency graph must never contain the private backend \
         (clean-room rule: backend depends on contract/engine, never the \
         reverse), found: {violations:?}"
    );
}
