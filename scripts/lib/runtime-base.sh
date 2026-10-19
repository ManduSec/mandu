# shellcheck shell=bash
# runtime-base.sh — the launcher's runtime-base rule for shell callers
# (launcher/src/runtime-base.ts; runtime-instances.md §3b). Sourced, not run.
#
#   mandu_runtime_base     print the base: MANDU_RUNTIME_DIR, else
#                          $XDG_RUNTIME_DIR/mandu (the path table's
#                          `runtime-dir`), else the per-user
#                          ($TMPDIR or /tmp)/mandu-<uid>, else, when an
#                          instance socket (63 bytes of suffix) would not fit
#                          sun_path's 108, the /tmp/mandu-<uid> fallback
#   mandu_runtime_base_owned <dir>
#                          true when <dir> is a real directory (not a link)
#                          of this uid with no group/other write bit: what a
#                          reader checks before trusting a `current` link
#
# Linux only (the callers are the VM harnesses and the SIEM exporter); the
# macOS 104-byte sun_path is the launcher's concern.
#
# PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code, a shell mirror of
# the TS rule; scripts/test/guest-registry.test.sh pins it.

# shellcheck source=scripts/paths/mandu-paths.sh
. "$(dirname "${BASH_SOURCE[0]}")/../paths/mandu-paths.sh"

mandu_runtime_base() {
  local base
  base="$(mandu_path runtime-dir)"
  [[ ${#base} -gt 1 ]] && base="${base%/}"   # one trailing slash, as the TS rule strips
  if [[ -z "${MANDU_RUNTIME_DIR:-}" && -z "${XDG_RUNTIME_DIR:-}" ]]; then
    base="$base-$(id -u)"
    (( ${#base} + 63 < 108 )) || base="/tmp/mandu-$(id -u)"
  fi
  printf '%s\n' "$base"
}

mandu_runtime_base_owned() {
  local mode
  [[ -d "$1" && ! -L "$1" && -O "$1" ]] || return 1
  mode="$(stat -c %a "$1" 2>/dev/null)" || return 1
  [[ "$mode" =~ ^[0-7]+$ ]] || return 1
  (( (8#$mode & 8#022) == 0 ))
}
