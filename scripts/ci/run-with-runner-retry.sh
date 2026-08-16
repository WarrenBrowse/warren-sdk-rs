#!/usr/bin/env bash
# Run a CI command, retrying only the failures that are the runner rather than
# the code.
#
#   scripts/ci/run-with-runner-retry.sh <command> [args...]
#
# The failure this exists for: cargo cannot SPAWN rustc for a dependency and
# reports `could not execute process ... (never executed)`, with
# `The directory name is invalid. (os error 267)` on the Windows runner and
# `No such file or directory (os error 2)` on the macOS one. The crate cargo
# names never ran, so nothing on disk is poisoned and nothing in this repo can
# fix it; only a rerun clears it, and it was costing one on nearly every push.
#
# Three classes:
#
#   plain    a spawn failure, a compiler killed mid-compile (a crash signature
#            in the log), or a wedge (no output at all, only the exit code of
#            whatever killed it). Retry the same command.
#   clean    a corrupt persistent target directory (dep-info gone), or LNK1181,
#            the windows-rs import lib briefly unopenable at link time. Both
#            need a `cargo clean` for the retry to land on a fresh state.
#   nothing  everything else, which fails on the first attempt: a real compile
#            error, lint or test failure must not cost three builds before it
#            is reported, and must never be able to read as intermittent.
#
# The anchor for the spawn class is the `(never executed)` marker, never the
# errno on its own: `No such file or directory (os error 2)` is also what a
# test reports when a file it genuinely needs is missing.
#
# The classifier is exercised by scripts/ci/test-run-with-runner-retry.sh.
set -uo pipefail

ATTEMPTS="${WARREN_RETRY_ATTEMPTS:-3}"

# Prints the retry strategy a failure calls for: "clean", "plain", or nothing
# at all when the failure is the code's own.
warren_flake_class() { # warren_flake_class <logfile> [exit-code]
	if grep -q "LNK1181" "$1"; then
		echo clean
		return
	fi
	# The self-hosted runners keep target/ across jobs, so a job killed
	# mid-write (a cancelled superseded run) or a cache restore that pruned the
	# .d files leaves a tree cargo can no longer describe. Retrying in place
	# hits the same missing file; only a clean recovers it. ci.yml's rust-cache
	# step carries the same signature in its comment.
	if grep -q "could not parse/generate dep info" "$1"; then
		echo clean
		return
	fi
	if grep -q "(never executed)" "$1"; then
		echo plain
		return
	fi
	# A compiler killed mid-compile, which the emulated x86_64 lane of the
	# release workflow produces on a random crate.
	if grep -qE "SIGSEGV|signal: 11|signal: 4|signal: 6|Illegal instruction|internal compiler error: Segmentation" "$1"; then
		echo plain
		return
	fi
	# The only evidence a wedge leaves. A crashed rustc that became a zombie
	# never returns its GNU jobserver token, so cargo waits at 0 % CPU printing
	# nothing; there is no signature to grep, only the exit code of the
	# `timeout` wrapper (124) or of whatever SIGKILLed the subtree (137).
	case "${2:-}" in
		124 | 137) echo plain ;;
	esac
}

# Sourced by the test, which wants the classifier and not a build.
if [ "${WARREN_RETRY_LIB:-0}" = "1" ]; then
	return 0 2> /dev/null || exit 0
fi

[ "$#" -ge 1 ] || {
	echo "usage: scripts/ci/run-with-runner-retry.sh <command> [args...]" >&2
	exit 2
}

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

attempt=1
while :; do
	"$@" 2>&1 | tee "$log"
	# PIPESTATUS, never $?: `$?` after a pipeline reads `tee`, and after an
	# `if` whose condition failed and which has no else it reads 0, which would
	# report every real compile error as a success.
	rc=${PIPESTATUS[0]}
	[ "$rc" = 0 ] && exit 0

	class="$(warren_flake_class "$log" "$rc")"
	if [ -z "$class" ]; then
		echo "::error title=warren-sdk-rs CI::the failure carries no known runner signature; failing on attempt $attempt"
		exit "$rc"
	fi
	if [ "$attempt" -ge "$ATTEMPTS" ]; then
		echo "::error title=warren-sdk-rs CI::still failing on the '$class' runner signature after $attempt attempts"
		exit "$rc"
	fi

	echo "::warning title=warren-sdk-rs CI::runner flake ('$class' class) on attempt $attempt/$ATTEMPTS; retrying"
	if [ "$class" = clean ]; then
		cargo clean || true
	fi
	attempt=$((attempt + 1))
done
