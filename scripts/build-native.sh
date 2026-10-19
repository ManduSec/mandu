#!/usr/bin/env bash
# build-native.sh — build the launcher's native bins the way the launcher
# resolves them (interceptors/target/release first, then debug):
#   mandu-exec-box, mandu-landlock-apply   (exec-supervisor)
#   mandu-net-guard                          (net-supervisor)
#
# Why a script: these bins carry `required-features = ["kernel"]`, so a plain
# `cargo build` / `cargo build --release` SKIPS them without a word and the
# launcher keeps running the previous build. The launcher warns when a
# resolved bin is older than a source it was compiled from
# (launcher/src/services/native-bins.ts); the drill runner refuses to start on
# one (drill-run.ts). Both name this script.
#
#   scripts/build-native.sh            # release (the profile the launcher prefers)
#   scripts/build-native.sh --debug    # debug; NOTE a stale release bin still wins resolution
#   scripts/build-native.sh --target aarch64-unknown-linux-gnu
#                                      # cross-build for the linux-arm64 bundle
#                                      #   (packaging.md §11.3) → target/<triple>/release/;
#                                      #   the launcher never resolves these in a checkout
#
# A cross build needs the rust target (`rustup target add <triple>`) and a C
# linker for it: for aarch64 on another host, `aarch64-linux-gnu-gcc`
# (Debian/Ubuntu gcc-aarch64-linux-gnu), used automatically unless
# CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER names another.
#
# Prints each bin's path and build time afterwards. No root; the `kernel`
# feature only compiles the attachment code, it does not run it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT/interceptors"

usage() { echo "usage: scripts/build-native.sh [--debug] [--target <triple>]" >&2; exit 2; }
profile=release
triple=""
while [ $# -gt 0 ]; do
  case "$1" in
    --debug) profile=debug; shift ;;
    --target) [ $# -ge 2 ] || usage; triple="$2"; shift 2 ;;
    *) usage ;;
  esac
done

args=(build -p exec-supervisor -p net-supervisor --features kernel --bins)
[ "$profile" = release ] && args+=(--release)
tdir="${CARGO_TARGET_DIR:-target}"
outdir="$tdir/$profile"
if [ -n "$triple" ]; then
  case "$triple" in
    x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
    *) echo "build-native: no bundle ships $triple (known: x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu; launcher/scripts/native-targets.mjs)" >&2; exit 2 ;;
  esac
  if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -qx "$triple"; then
    echo "build-native: the rust target $triple is not installed: rustup target add $triple" >&2; exit 1
  fi
  host_arch="$(uname -m)"
  if [ "$triple" = aarch64-unknown-linux-gnu ] && [ "$host_arch" != aarch64 ] \
     && [ -z "${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-}" ]; then
    if ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
      echo "build-native: cross-linking for $triple needs aarch64-linux-gnu-gcc (Debian/Ubuntu: gcc-aarch64-linux-gnu)" >&2
      echo "              or CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER naming another linker" >&2
      exit 1
    fi
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
  fi
  args+=(--target "$triple")
  outdir="$tdir/$triple/$profile"
fi
echo "+ cargo ${args[*]}"
cargo "${args[@]}"

echo
for bin in mandu-exec-box mandu-landlock-apply mandu-net-guard; do
  p="$outdir/$bin"
  if [ -x "$p" ]; then
    printf '  %-24s %s  (built %s)\n' "$bin" "$p" "$(date -r "$p" '+%Y-%m-%dT%H:%M:%S')"
  else
    echo "  $bin MISSING at $p" >&2; exit 1
  fi
done
# What each host bin was built from (packaging.md §5.2): a git worktree of
# this checkout with no bins of its own uses these only when its native
# sources are byte-identical to the ones recorded here. Never fails the build.
if [ -z "$triple" ]; then
  if command -v node >/dev/null 2>&1; then
    node "$REPO_ROOT/scripts/native-provenance.mjs" record "$REPO_ROOT/interceptors" "$outdir" \
      mandu-exec-box mandu-landlock-apply mandu-net-guard || echo "  (no provenance recorded: other checkouts will not use these bins)" >&2
  else
    echo "  (node not found: no provenance recorded, other checkouts will not use these bins)" >&2
  fi
fi
if [ -z "$triple" ] && [ "$profile" = debug ] && ls target/release/mandu-exec-box >/dev/null 2>&1; then
  echo
  echo "NOTE: target/release/ bins exist and the launcher resolves release BEFORE debug;" >&2
  echo "      rebuild without --debug (or remove target/release/mandu-*) for this build to take effect." >&2
fi
