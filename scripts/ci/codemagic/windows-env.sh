# shellcheck shell=bash
#
# Build environment for a Codemagic windows_x2 machine (Git Bash), sourced by
# the scripts/ci/codemagic/*.sh entry points. Every build starts on a fresh VM
# (Windows Server 2022, x64, VS 2022 17.14, Git, Python 3.9) with no Rust, so
# rustup is installed here and the toolchain comes from rust-toolchain.toml.
#
# codemagic.yaml caches rustup's toolchains, ~/.cargo/bin and cargo's registry
# and git sources for every workflow, and the compiled tree for the CI
# workflow only: a release lane always compiles from a clean target/. A
# restored toolchain is reused only when it is the pinned one (any other is
# uninstalled), so a pin bump needs no cache action;
# `scripts/codemagic-cache.sh clear warren-sdk-rs` in the workspace empties it.

set -euo pipefail

# The step's PowerShell hands bash a stdin pipe it never closes; a child that
# reads it (Windows PowerShell 5.1 does, before running -Command) waits forever.
exec < /dev/null


# Codemagic's PowerShell profile (posh-sshell, Start-SshAgent, the build's
# variables) makes every Windows PowerShell that loads it hold its caller's
# output open: `x="$(powershell.exe -Command 'Write-Output ok')"` never
# returned, the same call with -NoProfile did in 2 s (self-test of
# 2026-09-26). The build starts PowerShell without -NoProfile in places it
# does not own (msbuild's NMake steps, tool scripts), and whatever waits for
# that output then hangs with no CPU. Nothing in these builds needs the
# profile, so it is moved aside for the rest of the VM's life.
neutralize_powershell_profile() {
    local profile
    profile="$(powershell.exe -NoProfile -NonInteractive -Command 'Write-Output $PROFILE.CurrentUserCurrentHost' | tr -d '\r')"
    if [ -n "$profile" ] && [ -f "$(cygpath -u "$profile")" ]; then
        mv -f "$(cygpath -u "$profile")" "$(cygpath -u "$profile").off"
        echo "PowerShell profile moved aside: $profile"
    fi
}
neutralize_powershell_profile

CM_TOOLS="${CM_TOOLS:-$HOME/cm-tools}"
mkdir -p "$CM_TOOLS"

fetch() { # fetch <url> <dest>
    curl -fsSL --retry 5 --retry-all-errors --connect-timeout 30 -o "$2" "$1"
}

# Run one setup phase and say how long it took, so the effect of the cache
# can be read off any build log.
timed() { # timed <function> [args...]
    local start=$SECONDS
    "$@"
    echo "[timing] $1: $((SECONDS - start))s"
}

check_commit() {
    local head
    head="$(git rev-parse HEAD)"
    if [ "$head" != "$WARREN_SHA" ]; then
        echo "::error::checked out $head but the build was asked for $WARREN_SHA" >&2
        return 1
    fi
}

install_rustup() {
    export PATH="$HOME/.cargo/bin:$PATH"
    if ! command -v rustup > /dev/null 2>&1; then
        fetch https://win.rustup.rs/x86_64 "$CM_TOOLS/rustup-init.exe"
        "$CM_TOOLS/rustup-init.exe" -y --default-toolchain none --profile minimal --no-modify-path
        rm -f "$CM_TOOLS/rustup-init.exe"
    fi
    # The toolchain rust-toolchain.toml names (a no-op when the cache restored
    # it), then no other one, so the cache never carries a stale toolchain.
    rustup toolchain install
    local active other
    active="$(rustup show active-toolchain | cut -d' ' -f1)"
    for other in $(rustup toolchain list | cut -d' ' -f1); do
        [ "$other" = "$active" ] || rustup toolchain uninstall "$other"
    done
    echo "rust: $active"
}

install_nextest() {
    if ! cargo nextest --version > /dev/null 2>&1; then
        fetch https://get.nexte.st/latest/windows "$CM_TOOLS/nextest.zip"
        7z x -y -o"$(cygpath -w "$HOME/.cargo/bin")" "$(cygpath -w "$CM_TOOLS/nextest.zip")" > /dev/null
        rm -f "$CM_TOOLS/nextest.zip"
    fi
    cargo nextest --version
}

# Keep a cached compiled tree under the cache's size limit (10 GB per
# workflow): past the threshold it is dropped, and the next build compiles
# from scratch and caches a fresh one.
trim_target() { # trim_target <dir> <max GB>
    local kb
    [ -d "$1" ] || return 0
    kb="$(du -sk "$1" | cut -f1)"
    echo "compiled tree: $((kb / 1024 / 1024)) GB"
    if [ "$kb" -gt $(($2 * 1024 * 1024)) ]; then
        echo "over $2 GB: not caching it"
        rm -rf "$1"
    fi
}

# Clone a public WarrenBrowse sibling next to this checkout, at its pin.
checkout_sibling() { # checkout_sibling <repo> <pin file>
    local repo="$1" sha
    sha="$(tr -d '[:space:]' < "$2")"
    if ! printf '%s' "$sha" | grep -Eq '^[0-9a-f]{40}$'; then
        echo "::error::$2 must hold one full commit SHA, got '$sha'" >&2
        return 1
    fi
    rm -rf "../$repo"
    git clone --quiet --filter=blob:none "https://github.com/WarrenBrowse/$repo.git" "../$repo"
    git -C "../$repo" checkout --quiet --detach "$sha"
    echo "$repo @ $(git -C "../$repo" rev-parse HEAD)"
}

# Write outputs flat into cm-out/ with the checksum list the GitHub proxy
# (warren-app .github/actions/codemagic-build) verifies before publishing.
export_outputs() { # export_outputs <file>...
    rm -rf cm-out
    mkdir -p cm-out
    cp -- "$@" cm-out/
    (cd cm-out && sha256sum -- * > codemagic.sha256)
    cat cm-out/codemagic.sha256
}
