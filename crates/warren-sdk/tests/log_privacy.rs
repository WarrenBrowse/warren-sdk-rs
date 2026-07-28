//! No-log privacy invariants for the SDK facade (source-level scan).
//!
//! The SDK emits tracing events at its migration decision points (escape
//! refused, rebind failed, epoch ended) and nowhere may a trace carry a user
//! address, the physical gateway, the exit IP, a full pubkey, or identity
//! material. The only values it may render are non-correlating diagnostics
//! (an errno Display, a boolean, an engine-authored static reason). This test
//! anchors that at the source level so a future `tracing::*` site cannot
//! silently reintroduce a leak.
//!
//! Same log-call-scoped (paren-balanced, `%` and `?` aware) approach as the
//! engine's `warrenguard-pump/tests/log_privacy.rs`.

use std::path::Path;

/// Forbidden anywhere: interpolation syntaxes that only appear when something
/// sensitive is being formatted into a log / format string.
const FORBIDDEN_GLOBAL_SUBSTRINGS: &[&str] = &[
    "{remote_addr}",
    "{client_addr}",
    "{peer_addr}",
    "{remote_address",
    // The physical gateway and the exit IP locate the user's network.
    "{gateway",
    "%gateway",
    "{exit_ip",
    "%exit_ip",
    "{carrier_host_route",
    // A packet's destination is the user's browsing activity.
    "{dst_addr",
    "{dest_addr",
    "{dst_ip",
    // Raw Display of a full pubkey / identity material.
    "{pubkey",
    "{verifying_key",
    "{node_id",
    "{mnemonic",
    "{nonce",
    "{payload",
    "{datagram",
];

/// Forbidden only *inside* a tracing macro's argument list. These identifiers
/// have legitimate non-logging uses elsewhere (installing the escape route,
/// picking a bind address), so a global ban would false-positive; inside a log
/// they leak the user's network or identity regardless of the `%`/`?` sigil or
/// whether the value sits in the field or the value position.
const FORBIDDEN_IN_LOG_ARGS: &[&str] = &[
    "remote_address",
    "peer_addr",
    "peer_address",
    "local_addr",
    "dest_addr",
    "dst_addr",
    "dest_ip",
    "dst_ip",
    "gateway",
    "exit_ip",
    "carrier_host_route",
    "to_hex(",
];

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn log_call_args(body: &str) -> Vec<String> {
    const MACROS: &[&str] = &["trace!", "debug!", "info!", "warn!", "error!"];
    let chars: Vec<char> = body.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let mut advanced = false;
        for m in MACROS {
            let mlen = m.chars().count();
            if i + mlen > n || chars[i..i + mlen].iter().collect::<String>() != *m {
                continue;
            }
            if i > 0 && is_ident_char(chars[i - 1]) {
                continue;
            }
            let mut j = i + mlen;
            while j < n && chars[j].is_whitespace() {
                j += 1;
            }
            if j >= n || chars[j] != '(' {
                continue;
            }
            let start = j + 1;
            let mut depth = 0usize;
            let mut k = j;
            let mut in_str = false;
            let mut escaped = false;
            while k < n {
                let c = chars[k];
                if in_str {
                    if escaped {
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        in_str = false;
                    }
                } else if c == '"' {
                    in_str = true;
                } else if c == '(' {
                    depth += 1;
                } else if c == ')' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                k += 1;
            }
            out.push(chars[start..k].iter().collect());
            i = k + 1;
            advanced = true;
            break;
        }
        if !advanced {
            i += 1;
        }
    }
    out
}

fn strip_line_comments(body: &str) -> String {
    body.lines()
        .map(|l| match l.find("//") {
            Some(idx) => &l[..idx],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn violations_in(rel: &str, body: &str) -> Vec<String> {
    let code = strip_line_comments(body);
    let mut out = Vec::new();

    for substr in FORBIDDEN_GLOBAL_SUBSTRINGS {
        if code.contains(substr) {
            out.push(format!(
                "{rel}: forbidden log-leakage substring {substr:?} \
                 (user address / gateway / exit IP / identity material)"
            ));
        }
    }

    for args in log_call_args(&code) {
        for token in FORBIDDEN_IN_LOG_ARGS {
            if args.contains(token) {
                out.push(format!(
                    "{rel}: tracing macro interpolates {token:?} (leaks the user's network \
                     or identity).\n      {}",
                    args.trim()
                ));
            }
        }
    }
    out
}

fn collect_rs(dir: &Path, prefix: &str, acc: &mut Vec<(String, std::path::PathBuf)>) {
    for entry in std::fs::read_dir(dir).expect("read_dir src/") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if path.is_dir() {
            collect_rs(&path, &rel, acc);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            acc.push((rel, path));
        }
    }
}

/// Walks every `.rs` file under `src/` and fails if any leaks a user address,
/// the gateway, the exit IP, or identity material through a `tracing`
/// interpolation.
#[test]
fn no_sdk_module_logs_an_address_or_identity_material() {
    let mut files = Vec::new();
    collect_rs(Path::new("src"), "", &mut files);
    assert!(
        !files.is_empty(),
        "walkdir must find at least one .rs file under src/"
    );

    let mut violations = Vec::new();
    for (rel, path) in files {
        let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        violations.extend(violations_in(&rel, &body));
    }

    assert!(
        violations.is_empty(),
        "warren-sdk no-log violations: the SDK must never log a user address, the gateway, \
         the exit IP, or identity material in cleartext:\n{}",
        violations.join("\n")
    );
}

// --- scanner self-tests: prove the guard is neither blind nor trigger-happy.

#[test]
fn scanner_flags_display_interpolation_of_the_gateway() {
    let leaky = r#"tracing::info!(via = %gateway, "escape installed");"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_flags_exit_ip_format_capture() {
    let leaky = r#"tracing::info!("escape to {exit_ip} failed");"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_flags_local_addr_inside_a_log() {
    let leaky = r#"tracing::debug!(bound = ?session.local_addr(), "rebound");"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_ignores_errno_display_and_booleans() {
    // The exact shapes this crate uses must NOT be flagged.
    let benign = "tracing::info!(%error, \"endpoint rebind failed; the session stays on its \
                  socket\");\n\
                  tracing::debug!(had_session, \"watchdog verdict applied\");";
    assert!(
        violations_in("t.rs", benign).is_empty(),
        "an errno Display and a boolean must not be flagged"
    );
}

#[test]
fn scanner_ignores_route_install_code_outside_a_log() {
    // The same identifiers are legitimate in non-logging code.
    let benign = "let ok = add_carrier_host_route_macos(exit_ip, &gateway).is_ok();";
    assert!(
        violations_in("t.rs", benign).is_empty(),
        "using the gateway to install the route must not be flagged"
    );
}
