#!/usr/bin/env bash
#
# matrix-rust-toolchain.test.sh — unit tests for scripts/matrix/lib/rust-toolchain.sh,
# the OS test matrix's Rust (os-test-matrix.md §4.1): the suites that build the
# Rust workspace run the CI pin (scripts/ci/pins.env RUST_VERSION) by name,
# never the caller's `rustup default`. The v0.2.0-beta.8 tag's install job ran
# host/kernel under the CI runner's clean HOME, whose rustup had no default:
# "rustup could not choose a version of cargo to run".
#
# Stub rustup / cargo on PATH; no network, no real toolchain.
#
# Run:  bash scripts/test/matrix-rust-toolchain.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
LIB="$REPO/scripts/matrix/lib/rust-toolchain.sh"
PASS=0; FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
PIN="$(sed -n 's/^RUST_VERSION=//p' "$REPO/scripts/ci/pins.env")"
[[ "$PIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && pass "pins.env has RUST_VERSION ($PIN)" || fail "RUST_VERSION='$PIN'"

# stubs <dir> <installed toolchains> <install mode>: a rustup that lists the
# installed toolchains and logs every call, and a cargo that reports the
# toolchain it was asked for. Install modes: ok; fail (nothing installed,
# exit 1); late-fail (installed, then exit 1: the real rustup under a HOME
# whose CARGO_HOME holds no rustup, when its self-update check runs).
stubs() {
  mkdir -p "$1"
  cat > "$1/rustup" <<STUB
#!/bin/bash
echo "\$*" >> "$1/rustup.log"
case "\$1 \$2" in
  "toolchain list") for t in $2 \$(cat "$1/installed" 2>/dev/null); do echo "\$t-x86_64-unknown-linux-gnu"; done ;;
  "toolchain install")
    case "$3" in
      ok) echo "\$3" >> "$1/installed" ;;
      late-fail) echo "\$3" >> "$1/installed"; exit 1 ;;
      *) exit 1 ;;
    esac ;;
esac
STUB
  printf '#!/bin/sh\necho "cargo for ${RUSTUP_TOOLCHAIN:-<default>}"\n' > "$1/cargo"
  chmod +x "$1/rustup" "$1/cargo"
}
# use <bin dir>: run matrix_use_pinned_rust under a PATH holding only the stubs
# and the shell's tools; prints RUSTUP_TOOLCHAIN after it, then rc.
use() {
  # No RUSTUP_TOOLCHAIN from the caller: the matrix's own `all` suite runs this
  # test with the pin already exported (ubuntu-2604, 2026-10-23).
  env -u RUSTUP_TOOLCHAIN PATH="$1:/usr/bin:/bin" bash -c '
    source "$1"; matrix_use_pinned_rust "$2"; rc=$?
    echo "toolchain=${RUSTUP_TOOLCHAIN:-} rc=$rc"' _ "$LIB" "$REPO" 2>"$1/stderr"
}

# 1. Installed (the CI guest, a dev host): exported, nothing installed.
stubs "$WORK/a" "$PIN stable" ok
out="$(use "$WORK/a")"
[[ "$out" == "toolchain=$PIN rc=0" ]] && pass "installed pin: RUSTUP_TOOLCHAIN=$PIN exported" || fail "installed: $out"
grep -q 'toolchain install' "$WORK/a/rustup.log" && fail "installed pin was installed again" || pass "installed pin: no rustup install"
grep -q "cargo for $PIN" "$WORK/a/stderr" && pass "the note names cargo run under the pin" || fail "note: $(cat "$WORK/a/stderr")"

# 2. The CI runner's clean HOME: rustup with no toolchain and no default.
stubs "$WORK/b" "" ok
out="$(use "$WORK/b")"
[[ "$out" == "toolchain=$PIN rc=0" ]] && pass "no toolchain at all: RUSTUP_TOOLCHAIN=$PIN exported" || fail "clean: $out"
grep -qx "toolchain install $PIN --profile minimal --no-self-update" "$WORK/b/rustup.log" \
  && pass "no toolchain at all: the pin is installed, minimal profile" || fail "install call: $(cat "$WORK/b/rustup.log")"
grep -q '^default' "$WORK/b/rustup.log" && fail "rustup default was run" || pass "never runs \`rustup default\`"

# 3. Another toolchain only (a newer stable as the default): the pin still wins.
stubs "$WORK/c" "1.99.0" ok
out="$(use "$WORK/c")"
[[ "$out" == "toolchain=$PIN rc=0" ]] && grep -q "toolchain install $PIN" "$WORK/c/rustup.log" \
  && pass "only another toolchain: the pin is installed and used" || fail "other: $out $(cat "$WORK/c/rustup.log")"

# 4. The install fails (no network): an error, not a run on something else.
stubs "$WORK/d" "" fail
out="$(use "$WORK/d")"
[[ "$out" == *"rc=1" ]] && grep -q "could not install $PIN" "$WORK/d/stderr" \
  && pass "failed install: exit 1, named" || fail "failed install: $out $(cat "$WORK/d/stderr")"

# 4b. Installed, but rustup exits 1 afterwards (its self-update check under the
#     runner's HOME): the toolchain is there, so the pin is used.
stubs "$WORK/f" "" late-fail
out="$(use "$WORK/f")"
[[ "$out" == "toolchain=$PIN rc=0" ]] && pass "installed then a non-zero exit: judged by the toolchain being there" || fail "late-fail: $out $(cat "$WORK/f/stderr")"

# 5. No rustup (a distro cargo): used as it is, with a note.
mkdir -p "$WORK/e"; printf '#!/bin/sh\necho "cargo 1.80.0 (distro)"\n' > "$WORK/e/cargo"; chmod +x "$WORK/e/cargo"
out="$(use "$WORK/e")"
[[ "$out" == "toolchain= rc=0" ]] && grep -q "no rustup on PATH; using cargo 1.80.0 (distro), not the pin $PIN" "$WORK/e/stderr" \
  && pass "no rustup: the distro cargo is used, with a note" || fail "no rustup: $out $(cat "$WORK/e/stderr")"

# 6. The suites that build Rust source it before their first cargo.
for s in kernel all; do
  f="$REPO/scripts/matrix/suites/$s.sh"
  src="$(grep -n '^source scripts/matrix/lib/rust-toolchain.sh' "$f" | cut -d: -f1)"
  use_l="$(grep -n '^matrix_use_pinned_rust' "$f" | cut -d: -f1)"
  cargo_l="$(grep -nE 'cargo |test-all\.sh|kernel-tests\.sh' "$f" | grep -v '^[0-9]*:#' | head -n1 | cut -d: -f1)"
  [[ -n "$src" && -n "$use_l" && -n "$cargo_l" && "$src" -lt "$use_l" && "$use_l" -lt "$cargo_l" ]] \
    && pass "suites/$s.sh pins Rust before its first build" || fail "suites/$s.sh: source=$src use=$use_l build=$cargo_l"
done

# 7. The kernel suite also declares node, so a guest has node and python3 for
#    net-supervisor's a_holders_runtimes_run_under_the_memfd_trap (the
#    v0.2.0-beta.8 tag's ubuntu-2604/kernel, provisioned for cargo alone).
deps="$(source "$REPO/scripts/matrix/lib/common.sh"; parse_deps "$REPO/scripts/matrix/suites/kernel.sh")"
[[ " $deps " == *" cargo "* && " $deps " == *" node "* ]] && pass "suites/kernel.sh declares cargo and node ($deps)" || fail "kernel deps: '$deps'"

echo; echo "matrix-rust-toolchain: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
