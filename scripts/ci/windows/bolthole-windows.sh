#!/usr/bin/env bash
#
# The Windows x86_64 lane of release-bolthole.yml (job `build-windows`).
# Builds, tests and packages warren-bolthole as
# warren-bolthole<env_tag>-<version>-windows-x86_64.zip.
#
#   scripts/ci/windows/bolthole-windows.sh <prepare|build|package>
set -euo pipefail
source scripts/ci/windows/windows-env.sh

export WARREN_PRODUCT_ENV="$WARREN_CHANNEL"
target=x86_64-pc-windows-msvc
bin="target/$target/release/warren-bolthole.exe"

case "${1:?usage: bolthole-windows.sh <prepare|build|package>}" in
    prepare)
        check_commit
        timed install_rustup
        checkout_sibling warrenguard .warrenguard-version
        checkout_sibling warren-contract .warren-contract-version
        ;;
    build)
        install_rustup
        timed cargo build --locked --release -p warren-bolthole --target "$target"
        # A tag can be cut on any commit, so nothing else in the pipeline
        # guarantees the packaged code passed its tests. Same profile and
        # target as the build.
        timed cargo test --locked --release -p warren-bolthole -p warren-bolthole-core --target "$target"
        ;;
    package)
        test -f "$bin" || { echo "::error::cargo reported success but produced no $bin" >&2; exit 1; }
        "$bin" --help > /dev/null
        name="warren-bolthole${WARREN_ENV_TAG}-${WARREN_VERSION}-windows-x86_64"
        rm -rf staging && mkdir -p staging
        cp "$bin" staging/warren-bolthole.exe
        (cd staging && 7z a -tzip "../$name.zip" warren-bolthole.exe > /dev/null)
        export_outputs "$name.zip"
        ;;
    *) echo "unknown phase: $1" >&2; exit 2 ;;
esac
