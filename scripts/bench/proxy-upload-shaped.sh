#!/usr/bin/env bash
#
# proxy-upload-shaped.sh - measure the userland proxy datapath uploading through
# a REAL exit over a narrow, shaped uplink, the shape of one Claude Code turn on
# a member's 1 Mbit/s line (workspace incidents 2026-09-12 and 2026-09-13).
#
# The client under test runs inside a privileged Linux container on the local
# VM, so the shaping (netem, cake) applies to the container's own uplink and
# never touches the host's network. The exit is the production one the members
# use; the upload target is Cloudflare's speed-test sink, which accepts a POST
# of any size over HTTPS, so the whole path is TLS over TCP over the tunnel,
# exactly what an API turn is.
#
# Usage:
#   scripts/bench/proxy-upload-shaped.sh build <arm> [git-ref]
#       Build the `bench_proxy` example into bench/proxy-arms/<arm>. With a
#       git-ref, the SDK tree is exported from that commit (`git archive`), so
#       an arm can be a committed baseline while the working tree carries the
#       change under test; without one the working tree is rsync'd as it stands.
#       The engine siblings are always taken as they stand, so a run compares
#       SDK revisions over one engine.
#   scripts/bench/proxy-upload-shaped.sh run <arm> <profile> [reps] [size-mb]
#       Upload size-mb (default 3) through the arm's proxy, reps times (default
#       2), on one of the uplink profiles below. Reads the team mnemonic from
#       ../wclaude/secrets/warren-mnemonic (never printed) unless
#       WARREN_MNEMONIC is already set.
#
# Profiles (applied to the container's eth0, egress only):
#   bloat   1 Mbit/s, 25 ms, a deep packet queue: the member's line before the
#           shaper, the bufferbloat the 2026-09-12 report measured.
#   cake    25 ms, then cake at 860 kbit/s: the member's line after the shaper.
#   clean   no shaping, the control.
#
# Each measurement prints one RESULT line: the curl outcome (status, seconds,
# upload rate) and the datapath's final counters, offered against wire.
set -euo pipefail

mode="${1:?usage: proxy-upload-shaped.sh build|run ...}"
shift

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sdk="$(cd "$here/../.." && pwd)"
ws="$(cd "$sdk/.." && pwd)"
arms="$sdk/bench/proxy-arms"

command -v docker >/dev/null || { echo "docker is required (colima start)" >&2; exit 1; }

build_arm() {
    local arm="${1:?usage: build <arm> [git-ref]}"
    local ref="${2:-}"
    local scratch="$arms/.src-$arm"
    local target="$arms/.target-$arm"
    local out="$arms/$arm"

    command -v rsync >/dev/null || { echo "rsync is required" >&2; exit 1; }
    rm -rf "$scratch"
    mkdir -p "$scratch/warren-sdk-rs" "$target" "$out"

    if [ -n "$ref" ]; then
        git -C "$sdk" archive "$ref" | tar -x -C "$scratch/warren-sdk-rs"
        # The bench client itself may postdate the baseline commit.
        mkdir -p "$scratch/warren-sdk-rs/crates/warren-sdk/examples"
        cp "$sdk/crates/warren-sdk/examples/bench_proxy.rs" \
            "$scratch/warren-sdk-rs/crates/warren-sdk/examples/"
        printf '      %-16s %s (git archive)\n' warren-sdk-rs "$(git -C "$sdk" rev-parse --short "$ref")"
    else
        rsync -a --exclude target --exclude .git --exclude bench "$sdk/" "$scratch/warren-sdk-rs/"
        printf '      %-16s %s (working tree)\n' warren-sdk-rs \
            "$(git -C "$sdk" describe --tags --always --dirty 2>/dev/null)"
    fi
    for repo in warrenguard warren-contract; do
        rsync -a --exclude target --exclude .git "$ws/$repo/" "$scratch/$repo/"
        printf '      %-16s %s\n' "$repo" \
            "$(git -C "$ws/$repo" describe --tags --always --dirty 2>/dev/null)"
    done

    # cargo decides what to rebuild from mtimes, and rsync preserves them, so a
    # source older than the previous build's artefacts would be skipped and the
    # arm would carry the previous build's code. Key the target dir on content.
    local src_hash
    src_hash="$(cd "$scratch" && find . -type f \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) \
        | LC_ALL=C sort | xargs shasum | shasum | cut -d' ' -f1)"
    if [ "$(cat "$target/.src-hash" 2>/dev/null)" != "$src_hash" ]; then
        echo "==> sources changed since the last '$arm' build, discarding its target dir"
        rm -rf "$target"
        mkdir -p "$target"
    fi
    printf '%s\n' "$src_hash" > "$target/.src-hash"

    local toolchain
    toolchain="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$scratch/warren-sdk-rs/rust-toolchain.toml")"
    echo "==> building arm '$arm' with rust:${toolchain}-bookworm"
    docker run --rm \
        -v "$scratch:/ws" \
        -v "$target:/target" \
        -e CARGO_TARGET_DIR=/target \
        -w /ws/warren-sdk-rs \
        "rust:${toolchain}-bookworm" \
        bash -eu -c '
            apt-get update -qq
            apt-get install -y -qq pkg-config libssl-dev >/dev/null
            cargo build --release -p warren-sdk --example bench_proxy
        '
    cp "$target/release/examples/bench_proxy" "$out/bench_proxy"
    {
        echo "sdk $(if [ -n "$ref" ]; then git -C "$sdk" rev-parse "$ref"; else git -C "$sdk" describe --always --dirty; fi)"
        echo "warrenguard $(git -C "$ws/warrenguard" describe --always --dirty)"
        echo "warren-contract $(git -C "$ws/warren-contract" describe --always --dirty)"
        echo "src-hash $src_hash"
    } > "$out/ARM-REVISION"
    echo "==> arm '$arm' built into $out"
    cat "$out/ARM-REVISION"
}

run_arm() {
    local arm="${1:?usage: run <arm> <profile> [reps] [size-mb]}"
    local profile="${2:?usage: run <arm> <profile> [reps] [size-mb]}"
    local reps="${3:-2}"
    local size_mb="${4:-3}"
    local out="$arms/$arm"
    [ -x "$out/bench_proxy" ] || { echo "arm '$arm' not built" >&2; exit 1; }

    case "$profile" in
        bloat|cake|clean) ;;
        *) echo "unknown profile '$profile' (bloat|cake|clean)" >&2; exit 1 ;;
    esac

    local mnemonic="${WARREN_MNEMONIC:-}"
    if [ -z "$mnemonic" ]; then
        local secret="$ws/wclaude/secrets/warren-mnemonic"
        [ -r "$secret" ] || { echo "no WARREN_MNEMONIC and $secret unreadable" >&2; exit 1; }
        mnemonic="$(tr -d '\n' < "$secret")"
    fi

    local platform
    platform="linux/$(docker info -f '{{.Architecture}}' 2>/dev/null | sed 's/aarch64/arm64/;s/x86_64/amd64/')"
    local name="bench-proxy-$$"
    # The container's lifetime is bounded from outside as well: a wedged upload
    # or a hung tunnel must not keep a shaped client dialing the exit forever.
    ( sleep 3000; docker kill "$name" >/dev/null 2>&1 || true ) &
    local watchdog=$!
    trap 'kill $watchdog 2>/dev/null || true; docker kill "$name" >/dev/null 2>&1 || true' EXIT

    echo "==> arm '$arm' ($(head -1 "$out/ARM-REVISION")), profile $profile, $reps x ${size_mb} MB"
    docker run --rm --name "$name" --privileged --cap-add=NET_ADMIN \
        --platform "$platform" \
        -v "$out:/arm:ro" \
        -e WARREN_MNEMONIC="$mnemonic" \
        -e WARREN_EXIT_COUNTRY="${WARREN_EXIT_COUNTRY:-NL}" \
        -e BENCH_ARM="$arm" -e BENCH_PROFILE="$profile" -e BENCH_REPS="$reps" -e BENCH_SIZE_MB="$size_mb" \
        debian:bookworm-slim \
        bash -eu -c '
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq >/dev/null
            apt-get install -y -qq curl iproute2 ca-certificates procps >/dev/null
            dd if=/dev/urandom of=/tmp/payload bs=1M count="$BENCH_SIZE_MB" status=none

            shape_on() {
                case "$BENCH_PROFILE" in
                    bloat) tc qdisc add dev eth0 root netem delay 25ms rate 1mbit limit 1500 ;;
                    cake)  tc qdisc add dev eth0 root handle 1: netem delay 25ms
                           tc qdisc add dev eth0 parent 1: handle 10: cake bandwidth 860kbit ;;
                    clean) ;;
                esac
            }
            shape_off() { tc qdisc del dev eth0 root 2>/dev/null || true; }

            for rep in $(seq 1 "$BENCH_REPS"); do
                shape_off
                rm -f /tmp/ctl; mkfifo /tmp/ctl
                /arm/bench_proxy < /tmp/ctl > /tmp/metrics.log 2> /tmp/bench.err &
                client=$!
                exec 3> /tmp/ctl
                proxy=""
                for _ in $(seq 1 120); do
                    proxy="$(sed -n "s/^PROXY //p" /tmp/metrics.log | head -1)"
                    [ -n "$proxy" ] && break
                    kill -0 "$client" 2>/dev/null || break
                    sleep 0.5
                done
                if [ -z "$proxy" ]; then
                    echo "RESULT arm=$BENCH_ARM profile=$BENCH_PROFILE rep=$rep error=no-proxy $(tail -1 /tmp/bench.err)"
                    exec 3>&-; wait "$client" 2>/dev/null || true
                    continue
                fi
                # Let the fresh path settle (PMTU search, first probes) before
                # the line narrows, as a member sits idle before a turn.
                sleep 5
                shape_on
                curl_out="$(curl -sS -o /dev/null \
                    -w "code=%{http_code} secs=%{time_total} up_bps=%{speed_upload}" \
                    --socks5-hostname "$proxy" --max-time 1200 \
                    -X POST --data-binary @/tmp/payload https://speed.cloudflare.com/__up 2>&1 \
                    || true)"
                sleep 2
                final="$(grep "^METRICS" /tmp/metrics.log | tail -1 | sed "s/^METRICS //")"
                echo "RESULT arm=$BENCH_ARM profile=$BENCH_PROFILE rep=$rep size_mb=$BENCH_SIZE_MB $curl_out $final"
                exec 3>&-
                wait "$client" 2>/dev/null || true
                shape_off
                sleep 3
            done
        '
}

case "$mode" in
    build) build_arm "$@" ;;
    run) run_arm "$@" ;;
    *) echo "usage: proxy-upload-shaped.sh build|run ..." >&2; exit 1 ;;
esac
