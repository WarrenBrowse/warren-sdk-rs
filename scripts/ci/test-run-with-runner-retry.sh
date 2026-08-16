#!/usr/bin/env bash
# Tests for the failure classifier in scripts/ci/run-with-runner-retry.sh.
#
#   bash scripts/ci/test-run-with-runner-retry.sh
#
# Both directions of a misclassification are expensive, which is why they are
# pinned here rather than reviewed by eye:
#
#   too narrow  every push pays a manual rerun for a transient nobody can fix,
#               and a red main stops being read;
#   too broad   a genuine regression is retried until it reads as intermittent,
#               which is how a real bug gets filed as "flaky CI" and shipped.
#
# The log excerpts are real, taken from the runs named in the comments.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WARREN_RETRY_LIB=1
export WARREN_RETRY_LIB
# shellcheck source=./run-with-runner-retry.sh
. "$SCRIPT_DIR/run-with-runner-retry.sh"

failures=0
checks=0

expect() { # expect <description> <expected class> <log text> [exit code]
	checks=$((checks + 1))
	local log actual
	log="$(mktemp)"
	printf '%s\n' "$3" > "$log"
	actual="$(warren_flake_class "$log" "${4:-1}")"
	rm -f "$log"
	if [ "$actual" = "$2" ]; then
		printf '  ok   %s\n' "$1"
	else
		printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' \
			"$1" "${2:-<no retry>}" "${actual:-<no retry>}"
		failures=$((failures + 1))
	fi
}

echo "runner transients (must retry)"
# Run 31923309620, job "cargo test (windows)": cargo could not spawn rustc for
# the uniffi dependency. The crate it names never had a chance to be wrong.
expect "cargo could not spawn rustc on windows" plain \
	"  could not execute process \`C:\\Users\\vagrant\\.rustup\\toolchains\\1.89.0-aarch64-pc-windows-msvc\\bin\\rustc.exe --crate-name uniffi --edition=2021 --cap-lints allow -D warnings\` (never executed)

Caused by:
  The directory name is invalid. (os error 267)"
# Run 31954612737, job "cargo test (macos)": the same failure, and the macOS
# errno makes it look like a missing file rather than a runner fault.
expect "the same spawn failure on macos, where the errno reads as a missing file" plain \
	"  could not execute process \`/Users/axiom/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin/rustc --crate-name uniffi --edition=2021 --cap-lints allow -D warnings\` (never executed)

Caused by:
  No such file or directory (os error 2)"
# Run 31957766776, job "cargo test (macos)": the persistent target directory
# of a self-hosted runner lost the .d dep-info files of what it holds, which
# only a clean recovers.
expect "a target directory whose dep-info is gone gets a clean" clean \
	"error: could not parse/generate dep info at: /Users/axiom/actions-runner-2/_work/warren-sdk-rs/warren-sdk-rs/target/debug/deps/warren_burrow-0d4e.d

Caused by:
  No such file or directory (os error 2)"
# The release lanes link windows-rs; the import lib is briefly unopenable
# under a concurrent runner, and a clean lands on a fresh state.
expect "the transient linker failure gets a clean first" clean \
	"error: linking with \`link.exe\` failed: exit code: 1181
  = note: LINK : fatal error LNK1181: cannot open input file 'windows.0.52.0.lib'"
# Same run, first attempt: the shared cargo bin directory was being rewritten
# by another job, so the tool cargo was asked to spawn was half a file.
expect "a tool that was being rewritten while cargo spawned it" plain \
	"error: could not execute process \`/Users/axiom/.cargo/bin/cargo-nextest nextest run --locked\` (never executed)

Caused by:
  Malformed Mach-o file (os error 88)"
# The release workflow's x86_64 lane builds under Rosetta, where a rustc dies
# mid-compile on a random crate. The crash is in the log.
expect "a rustc crash under emulation is a signature, not an exit code" plain \
	"error: rustc interrupted by SIGSEGV, printing backtrace"
# Run 31958663710, job "cargo test (macos)": `cargo` itself was gone between
# one attempt and the next, because another job on the same runner was
# reinstalling the toolchain into the shared CARGO_HOME. The shell's own 127
# comes with it.
expect "the toolchain binary vanished between two attempts" plain \
	"scripts/ci/run-with-runner-retry.sh: line 85: cargo: command not found" 127
expect "the same, with only the exit code to go on" plain "" 127
# A wedged cargo (a zombie rustc holding its jobserver token) prints nothing
# at all, so the exit code of the watchdog or the timeout wrapper is the only
# evidence there is.
expect "a build killed from outside leaves no signature to grep" plain "" 137
expect "a build the timeout wrapper fired on" plain "" 124
expect "a wedge that did manage to print something still retries" plain \
	"   Compiling warren-burrow-core v0.0.1" 137

echo "real failures (must NOT retry)"
expect "a compile error is the code's own" "" \
	"error[E0308]: mismatched types
  --> crates/warren-burrow/src/run.rs:42:5"
# Run 31922805535, job "cargo clippy (windows)": a real lint failure that came
# in the same burst of runs as the spawn flakes.
expect "a lint failure is the code's own" "" \
	"error: unused import: \`super::*\`
  --> crates\\warren-headless\\src\\hardening.rs:57:9
error: could not compile \`warren-headless\` (lib test) due to 1 previous error"
expect "a failing test is not a flake" "" \
	"        FAIL [   0.031s] warren-burrow-core conf::tests::refuses_overlapping_subnet
Summary [   4.512s] 812 tests run: 811 passed, 1 failed"
# The macOS spawn failure carries this errno, so the errno alone must not be
# the anchor: a file a test genuinely needs and cannot find reports it too, and
# retrying that hides a real regression behind three identical failures.
expect "the macos errno without the spawn marker is a real failure" "" \
	"thread 'provision::tests::writes_client_files' panicked at crates/warren-burrow/src/provision.rs:120:
  No such file or directory (os error 2)"
expect "an empty log retries nothing" "" ""

# A log carrying both takes the clean path: a clean also fixes the spawn case,
# while a plain retry does not fix the linker one.
echo "precedence"
expect "a log carrying both takes the clean path" clean \
	"error: could not execute process \`rustc.exe\` (never executed)
LINK : fatal error LNK1181: cannot open input file 'windows.0.52.0.lib'"

printf '\n%d checks, %d failure(s)\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
