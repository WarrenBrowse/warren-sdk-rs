#!/usr/bin/env bash
#
# Codemagic `windows-ci` workflow: the Windows leg of ci.yml's clippy and test
# gates, in one build so the two share one clone, one toolchain and one
# compiled tree. Same commands as the Linux and macOS legs.
#
#   scripts/ci/codemagic/windows-ci.sh <prepare|clippy|test>
#
# One Codemagic step per phase, so the GitHub job shows which one is running;
# CARGO_TARGET_DIR comes from codemagic.yaml, outside the clone, where the
# workflow's cache keeps it.
set -euo pipefail
source scripts/ci/codemagic/windows-env.sh

case "${1:?usage: windows-ci.sh <prepare|clippy|test>}" in
    prepare)
        check_commit
        # The test binaries read the golden vectors at runtime.
        git submodule update --init --recursive
        timed install_rustup
        timed install_nextest
        checkout_sibling warrenguard .warrenguard-version
        checkout_sibling warren-contract .warren-contract-version
        ;;
    clippy)
        install_rustup
        timed cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
        ;;
    test)
        install_rustup
        # --retries 2 re-runs a test that ran and failed: the in-process quinn
        # loopback tunnel tests can hit a quinn Drop/UDP-bind race on slower
        # machines.
        timed cargo nextest run --locked --workspace --all-targets --all-features --retries 2
        trim_target "$CARGO_TARGET_DIR" 7
        ;;
    *) echo "unknown phase: $1" >&2; exit 2 ;;
esac
