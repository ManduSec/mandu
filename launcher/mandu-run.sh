#!/usr/bin/env bash
#
# mandu-run.sh — thin compatibility shim over the single TS launcher (`mandu`).
#
# RETIRED 2026-07-14 (portable-wrapper.md §7 step 3-4): the 1441-line bash
# launcher is gone. The TS launcher (launcher/src/run.ts, built as
# launcher/bin/mandu.mjs → dist/mandu.mjs) is now the ONE launcher, with the
# chokepoint hardening ON by default — exec-box, landlock-net, net-proxy,
# exec-wrap, fs-sync, reply-filter (each `--no-<flag>` / env `=0` opts out;
# `--no-kernel` / `--portable` drops all kernel-tier rungs at once). This shim
# keeps the historical `launcher/mandu-run.sh -- <agent>` invocation working —
# it now transparently gains the default-on hardening — so existing callers (the
# dashboard/eval harnesses, docs, muscle memory) need no change.
#
# The four opt-in flags the bash launcher alone implemented — `--fs-preload`,
# `--unshare`, `--unshare-net`, slirp — were retired outright (2026-07-14):
# requesting one is a parse-time error naming the default-on rungs that cover
# the job (fs-sync + the kernel-tier FS rungs; the bwrap rungs exec-box /
# secret-twins; landlock-net + net-guard). Everything else is at full parity.
#
# Resolution (packaging.md §5.1):
#   - a DEV checkout (src/ + the launcher's local tsx) runs its own prebuilt
#     bundle, launcher/dist, through bin/mandu.mjs WHEN THAT BUNDLE IS FRESH: its
#     build record (scripts/bundle-stamp.mjs) lists every file it was built from,
#     and none has changed. A stale bundle is rebuilt first (--if-stale, under
#     the build's lock: about half a second); if it cannot be rebuilt, the
#     launcher runs from source through tsx. The source stays authoritative: a
#     stale bundle never runs. The services follow the launcher's form
#     (services/layout.ts), so a bundled launch runs every per-session service
#     from the same build;
#   - MANDU_FROM_SOURCE=1 forces the source path (tsx, no build);
#   - an INSTALLED package (no src/tsx) runs the built bundle through
#     bin/mandu.mjs.
# Mirrors scripts/bootstrap.sh, whose `mandu` shim execs this file.
#
# ONE node (2026-10-16): in a checkout this shim starts no node of its own.
# It execs `node bin/mandu.mjs` with MANDU_SHIM_CHECKOUT=<repo root>, and that
# node runs the checkout prelude (scripts/checkout-launch.mjs) before the
# launcher: it loads the secrets file into its own environment (what sourcing
# scripts/mandu-env.sh did: the same variables, never one already set, quiet
# unless verbose, best effort), checks the bundle's build record, and on a
# stale bundle rebuilds it or replaces itself with tsx over the source, as
# this shim used to. The two node starts that saves were about 0.4 s of every
# launch on a host whose node starts slowly.
#
# NOT -e: the best-effort secrets source below must never abort the launch.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

# The checkout hand-off to bin/mandu.mjs is this shim's alone: an inherited
# one names no checkout of ours.
unset MANDU_SHIM_CHECKOUT

# Parity with the retired bash launcher (which auto-sourced this): load the
# secrets file so callers that relied on `mandu-run.sh` populating
# ANTHROPIC_API_KEY / OPENAI_API_KEY / MANDU_ULLM_* keep working. Never
# overrides an already-set var; no-ops without the file / node (continuous-integration.md §13).
# Its informational lines print only for a verbose launch (packaging.md §5).
# A checkout's bundled launch does the same in the launcher's own node
# instead (scripts/checkout-launch.mjs, the same verbose rule); the source
# path and an installed package call this.
_mandu_source_secrets() {
  [[ -f "$REPO_ROOT/scripts/mandu-env.sh" ]] || return 0
  local _mandu_quiet=1 _a
  case "${MANDU_VERBOSE:-}" in ""|0|false|FALSE|False) ;; *) _mandu_quiet=0 ;; esac
  for _a in "$@"; do [[ "$_a" == "--verbose" ]] && _mandu_quiet=0; [[ "$_a" == "--" ]] && break; done
  # shellcheck source=/dev/null
  MANDU_SECRETS_QUIET=$_mandu_quiet source "$REPO_ROOT/scripts/mandu-env.sh" || true
}

TSX="$HERE/node_modules/.bin/tsx"
RUN="$HERE/src/run.ts"
BIN="$HERE/bin/mandu.mjs"
DIST="$HERE/dist"
BUNDLE="$DIST/mandu.mjs"

# Dev checkout: the bundle only while it matches the source, else the source.
# One node: bin/mandu.mjs's checkout prelude loads the secrets, checks the
# build record, rebuilds a stale bundle (--if-stale --no-native --quiet) and,
# when it cannot, replaces itself with "$TSX" "$RUN" and says so.
if [[ -x "$TSX" && -f "$RUN" ]]; then
  case "${MANDU_FROM_SOURCE:-}" in
    1|true|TRUE|True|yes|on) _mandu_source_secrets "$@"; exec "$TSX" "$RUN" "$@" ;;
  esac
  MANDU_SHIM_CHECKOUT="$REPO_ROOT" exec node "$BIN" "$@"
fi
_mandu_source_secrets "$@"
# Installed package: the bundle is all there is.
if [[ -f "$BUNDLE" && -f "$BIN" ]]; then
  exec node "$BIN" "$@"
fi

echo "mandu-run.sh: TS launcher not found. In a dev checkout run 'cd launcher && npm install'; for an installed package run 'cd launcher && npm run build:bundle'." >&2
exit 1
