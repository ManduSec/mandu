# shellcheck shell=bash
# GENERATED FILE: do not edit. Source: scripts/paths/mandu-paths.mjs
# (docs/design/architecture/on-disk-layout.md §5). Regenerate with
# `node scripts/paths/mandu-paths.mjs generate`; scripts/test/mandu-paths.test.mjs fails
# when this copy differs from the table.
#
# Source it, then `mandu_path <name> [home]` / `mandu_base <name> [home]`
# print the path (home defaults to $HOME). Pure: reads no file. Paths are
# joined like node's `path.posix.join`, so every copy agrees byte for byte.

# node's path.posix.normalize.
_mandu_normalize() {
  local p="$1" abs="" trail="" seg s IFS=/
  if [ -z "$p" ]; then printf '.\n'; return; fi
  [ "${p:0:1}" = / ] && abs=1
  [ "${p: -1}" = / ] && trail=1
  local -a parts=() out=()
  read -r -a parts <<< "$p"
  for seg in "${parts[@]}"; do
    case "$seg" in
      "" | .) ;;
      ..)
        if [ "${#out[@]}" -gt 0 ] && [ "${out[${#out[@]}-1]}" != .. ]; then
          unset "out[${#out[@]}-1]"
          out=("${out[@]}")
        elif [ -z "$abs" ]; then
          out+=(..)
        fi ;;
      *) out+=("$seg") ;;
    esac
  done
  s="${out[*]}"
  if [ -z "$s" ]; then
    if [ -n "$abs" ]; then printf '/\n'; elif [ -n "$trail" ]; then printf './\n'; else printf '.\n'; fi
    return
  fi
  [ -n "$trail" ] && s="$s/"
  [ -n "$abs" ] && s="/$s"
  printf '%s\n' "$s"
}

# node's path.posix.join(a, b).
_mandu_join() {
  if [ -z "$1" ] && [ -z "$2" ]; then printf '.\n'
  elif [ -z "$2" ]; then _mandu_normalize "$1"
  elif [ -z "$1" ]; then _mandu_normalize "$2"
  else _mandu_normalize "$1/$2"
  fi
}

mandu_base() {
  local h="${2-$HOME}"
  case "$1" in
    home) _mandu_join "$h" "" ;;
    mandu) if [ -n "${MANDU_HOME:-}" ]; then printf '%s\n' "$MANDU_HOME"; else _mandu_join "$h" ".mandu"; fi ;;
    runtime) if [ -n "${XDG_RUNTIME_DIR:-}" ]; then printf '%s\n' "$XDG_RUNTIME_DIR"; elif [ -n "${TMPDIR:-}" ]; then printf '%s\n' "$TMPDIR"; else printf '%s\n' "/tmp"; fi ;;
    install) _mandu_join "$h" ".local/share" ;;
    *) printf 'mandu_base: unknown base %s\n' "$1" >&2; return 2 ;;
  esac
}

mandu_path() {
  local h="${2-$HOME}" parent
  case "$1" in
    mandu-home) parent="$(mandu_base mandu "$h")" && _mandu_join "$parent" "" ;;
    config-root) parent="$(mandu_path mandu-home "$h")" && _mandu_join "$parent" "" ;;
    config-toml) parent="$(mandu_path config-root "$h")" && _mandu_join "$parent" "config.toml" ;;
    policy) parent="$(mandu_path config-root "$h")" && _mandu_join "$parent" "policy.yaml" ;;
    packs) parent="$(mandu_path config-root "$h")" && _mandu_join "$parent" "packs" ;;
    pack-keys) parent="$(mandu_path config-root "$h")" && _mandu_join "$parent" "pack-keys" ;;
    prompt-filters) parent="$(mandu_path config-root "$h")" && _mandu_join "$parent" "prompt-filters" ;;
    secrets-json) parent="$(mandu_path config-root "$h")" && _mandu_join "$parent" "secrets.json" ;;
    dashboard-env) parent="$(mandu_path config-root "$h")" && _mandu_join "$parent" "dashboard.env" ;;
    state-root) parent="$(mandu_path mandu-home "$h")" && _mandu_join "$parent" "state" ;;
    symbol-db) parent="$(mandu_path state-root "$h")" && _mandu_join "$parent" "mandu.db" ;;
    symbol-db-test) parent="$(mandu_path state-root "$h")" && _mandu_join "$parent" "mandu-test.db" ;;
    view-state) parent="$(mandu_path state-root "$h")" && _mandu_join "$parent" "" ;;
    workspaces) parent="$(mandu_path view-state "$h")" && _mandu_join "$parent" "workspaces" ;;
    object-walks) parent="$(mandu_path state-root "$h")" && _mandu_join "$parent" "object-walks" ;;
    paired-approvals) parent="$(mandu_path state-root "$h")" && _mandu_join "$parent" "paired-approvals" ;;
    browser-profile) parent="$(mandu_path state-root "$h")" && _mandu_join "$parent" "browser" ;;
    launch-logs) parent="$(mandu_path state-root "$h")" && _mandu_join "$parent" "launch-logs" ;;
    dashboard-account) parent="$(mandu_path state-root "$h")" && _mandu_join "$parent" "dashboard-account.json" ;;
    last-scan) parent="$(mandu_path state-root "$h")" && _mandu_join "$parent" "last-scan.json" ;;
    events) parent="$(mandu_path mandu-home "$h")" && _mandu_join "$parent" "events" ;;
    events-test) parent="$(mandu_path events "$h")" && _mandu_join "$parent" "test" ;;
    runs-root) parent="$(mandu_path mandu-home "$h")" && _mandu_join "$parent" "runs" ;;
    test-runs) parent="$(mandu_path runs-root "$h")" && _mandu_join "$parent" "test-runs.json" ;;
    test-run-results) parent="$(mandu_path runs-root "$h")" && _mandu_join "$parent" "test-runs" ;;
    live-drill-runs) parent="$(mandu_path runs-root "$h")" && _mandu_join "$parent" "drills/live" ;;
    ci-runs) parent="$(mandu_path runs-root "$h")" && _mandu_join "$parent" "ci" ;;
    matrix-results) parent="$(mandu_path runs-root "$h")" && _mandu_join "$parent" "matrix" ;;
    eval-runs) parent="$(mandu_path runs-root "$h")" && _mandu_join "$parent" "eval" ;;
    replay-drill-runs) parent="$(mandu_path runs-root "$h")" && _mandu_join "$parent" "drills/replay" ;;
    drill-baselines) parent="$(mandu_path runs-root "$h")" && _mandu_join "$parent" "drills/baselines" ;;
    dev-root) parent="$(mandu_path mandu-home "$h")" && _mandu_join "$parent" "dev" ;;
    docker-e2e-home) parent="$(mandu_path dev-root "$h")" && _mandu_join "$parent" "docker-e2e-home" ;;
    cache-root) parent="$(mandu_path mandu-home "$h")" && _mandu_join "$parent" "cache" ;;
    object-twins) parent="$(mandu_path cache-root "$h")" && _mandu_join "$parent" "object-twins" ;;
    ci-cache) parent="$(mandu_path cache-root "$h")" && _mandu_join "$parent" "ci" ;;
    ci-host-out) parent="$(mandu_path ci-cache "$h")" && _mandu_join "$parent" "host-out" ;;
    dashboard-cache) parent="$(mandu_path cache-root "$h")" && _mandu_join "$parent" "dashboard" ;;
    update-check) parent="$(mandu_path cache-root "$h")" && _mandu_join "$parent" "update-check.json" ;;
    runtime-dir) if [ -n "${MANDU_RUNTIME_DIR:-}" ]; then printf '%s\n' "$MANDU_RUNTIME_DIR"; else parent="$(mandu_base runtime "$h")" && _mandu_join "$parent" "mandu"; fi ;;
    install-prefix) if [ -n "${MANDU_PREFIX:-}" ]; then printf '%s\n' "$MANDU_PREFIX"; else parent="$(mandu_base install "$h")" && _mandu_join "$parent" "mandu"; fi ;;
    exec-box-cache) parent="$(mandu_path install-prefix "$h")" && _mandu_join "$parent" "exec-box" ;;
    bin-dir) if [ -n "${MANDU_BIN_DIR:-}" ]; then printf '%s\n' "$MANDU_BIN_DIR"; else parent="$(mandu_base home "$h")" && _mandu_join "$parent" ".local/bin"; fi ;;
    *) printf 'mandu_path: unknown path %s\n' "$1" >&2; return 2 ;;
  esac
}

# Every entry name, for callers that list them.
MANDU_PATH_NAMES=(mandu-home config-root config-toml policy packs pack-keys prompt-filters secrets-json dashboard-env state-root symbol-db symbol-db-test view-state workspaces object-walks paired-approvals browser-profile launch-logs dashboard-account last-scan events events-test runs-root test-runs test-run-results live-drill-runs ci-runs matrix-results eval-runs replay-drill-runs drill-baselines dev-root docker-e2e-home cache-root object-twins ci-cache ci-host-out dashboard-cache update-check runtime-dir install-prefix exec-box-cache bin-dir)
