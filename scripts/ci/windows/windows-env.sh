# shellcheck shell=bash
#
# Build environment for a GitHub-hosted windows-2025 runner (Git Bash), sourced
# by the scripts/ci/windows/*.sh entry points. The runner image carries rustup,
# Visual Studio 2022 and 7-Zip; the toolchain comes from rust-toolchain.toml.
# The CI job caches its compiled tree with Swatinem/rust-cache; a release lane
# always compiles from a clean target/.

set -euo pipefail

# A caller can hand bash a stdin pipe it never closes (Codemagic's PowerShell
# steps did); a child that reads it (Windows PowerShell 5.1 does, before
# running -Command) waits forever.
exec < /dev/null

# A PowerShell profile can make every Windows PowerShell that loads it hold
# its caller's output open: on the Codemagic machines this repo used to build
# on, `x="$(powershell.exe -Command 'Write-Output ok')"` never returned, the
# same call with -NoProfile did in 2 s (self-test of 2026-09-26). The build
# starts PowerShell without -NoProfile in places it does not own (msbuild's
# NMake steps, tool scripts), and whatever waits for that output then hangs
# with no CPU. Nothing in these builds needs the
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

CI_TOOLS="${CI_TOOLS:-$HOME/ci-tools}"
mkdir -p "$CI_TOOLS"

fetch() { # fetch <url> <dest>
    curl -fsSL --retry 5 --retry-all-errors --connect-timeout 30 -o "$2" "$1"
}

# Run one phase and say how long it took, so the effect of the cache can be
# read off any build log.
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
        fetch https://win.rustup.rs/x86_64 "$CI_TOOLS/rustup-init.exe"
        "$CI_TOOLS/rustup-init.exe" -y --default-toolchain none --profile minimal --no-modify-path
        rm -f "$CI_TOOLS/rustup-init.exe"
    fi
    # The toolchain rust-toolchain.toml names. A rustup older than 1.28 has no
    # argument-less `toolchain install`, and installs it on `rustup show`.
    rustup toolchain install || rustup show
    echo "rust: $(rustup show active-toolchain | cut -d' ' -f1)"
}

install_nextest() {
    if ! cargo nextest --version > /dev/null 2>&1; then
        fetch https://get.nexte.st/latest/windows "$CI_TOOLS/nextest.zip"
        7z x -y -o"$(cygpath -w "$HOME/.cargo/bin")" "$(cygpath -w "$CI_TOOLS/nextest.zip")" > /dev/null
        rm -f "$CI_TOOLS/nextest.zip"
    fi
    cargo nextest --version
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

# Write outputs flat into ci-out/ with the checksum list the workflow verifies
# (`sha256sum -c`) before it uploads them for publication.
export_outputs() { # export_outputs <file>...
    rm -rf ci-out
    mkdir -p ci-out
    cp -- "$@" ci-out/
    (cd ci-out && sha256sum -- * > SHA256SUMS)
    cat ci-out/SHA256SUMS
}
