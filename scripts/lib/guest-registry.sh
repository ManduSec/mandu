# shellcheck shell=bash
# guest-registry.sh — register the qemu guests a test harness starts, so
# `mandu reap` collects one a killed run leaked (os-test-matrix.md §10.5,
# runtime-instances.md §10). Sourced, not run.
#
# The VM harnesses (scripts/ci/vm-run.sh, scripts/ci/vm-image.sh, the matrix
# qemu executor scripts/matrix/lib/qemu.sh, scripts/kernel-vm.sh) start qemu
# with `-pidfile`, in the background, then:
#
#   guest_register <launcher pid> <pidfile> <harness> <work dir> <keep 0|1> [also-remove...]
#   wait <launcher pid>
#   guest_release
#
# and call guest_release again from their EXIT trap. An entry is one flat JSON
# file, `<runtime dir>/vm-guests/<harness>-<pid>.json`, beside the arbiter
# `instances/` and the `dashboards/` entries:
#
#   pid, pidStart        qemu's pid and its start time (/proc/<pid>/stat field
#                        22): a reused pid never matches, so reap never signals it
#   bootId               /proc/sys/kernel/random/boot_id: an entry from an
#                        earlier boot names no live process at all
#   ownerPid, ownerStart the harness process ($$) whose death makes the guest
#                        garbage (the same owner rule as dev-arbiter.sh's
#                        MANDU_OWNER_PID, with the start time so a reused
#                        owner pid does not keep a leaked guest alive)
#   workDir, keep        the run's scratch dir (overlay, seed, disks); reap
#                        removes it unless the run was started with --keep
#   alsoRemove           removed even under --keep: a host-side credential
#                        copy never outlives its guest
#
# Registration is best-effort housekeeping, never on a security path: a guest
# that writes no pidfile within 60 s is simply not registered (a warning).
#
# PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code; the entry layout is read
# by launcher/src/reap.ts (GuestEntryLite).

# shellcheck source=scripts/paths/mandu-paths.sh
. "$(dirname "${BASH_SOURCE[0]}")/../paths/mandu-paths.sh"

GUEST_REG_ENTRY="" GUEST_REG_PID="" GUEST_REG_START=""

# shellcheck source=scripts/lib/runtime-base.sh
. "$(dirname "${BASH_SOURCE[0]}")/runtime-base.sh"

# guest_registry_dir — <runtime dir>/vm-guests, where `mandu reap` looks: the
# launcher's runtime-base rule (mandu_runtime_base; per-user without
# MANDU_RUNTIME_DIR and XDG_RUNTIME_DIR since 2026-10-09).
guest_registry_dir() { printf '%s/vm-guests\n' "$(mandu_runtime_base)"; }

# _greg_start <pid> — the process's start time in clock ticks since boot
# (field 22 of /proc/<pid>/stat; the fields after the `)` closing comm). Fails
# for a missing pid and for a zombie (state Z/X: it has exited already).
_greg_start() {
  local s
  s="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
  s="${s##*) }"
  # shellcheck disable=SC2086
  set -- $s
  [[ "${1:-}" == [ZX] ]] && return 1
  [[ "${20:-}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${20}"
}

_greg_boot_id() { cat /proc/sys/kernel/random/boot_id 2>/dev/null || true; }

_greg_mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null; }

# _greg_own_dir <dir> — true when <dir> is a real directory (not a link)
# owned by this uid with no group/other write bit.
_greg_own_dir() {
  local mode
  [[ -d "$1" && ! -L "$1" && -O "$1" ]] || return 1
  mode="$(_greg_mode "$1")" || return 1
  [[ "$mode" =~ ^[0-7]+$ ]] || return 1
  (( (8#$mode & 8#022) == 0 ))
}

# _greg_trusted_registry <registry dir> — the launcher's rule for a runtime
# base (runtime-instances.md §3b): a base directly in a shared sticky dir
# (/tmp: world-writable + sticky, where `$TMPDIR/mandu-<uid>` lands without
# XDG_RUNTIME_DIR) must be this uid's and writable by no one else; any base
# is otherwise the user's own choice. The registry dir itself, made 0700
# here, must be ours and not a link either way.
_greg_trusted_registry() {
  local base="${1%/*}" pmode
  pmode="$(_greg_mode "${base%/*}" 2>/dev/null)" || pmode=0
  [[ "$pmode" =~ ^[0-7]+$ ]] || pmode=0
  if (( (8#$pmode & 8#1002) == 8#1002 )); then _greg_own_dir "$base" || return 1; fi
  _greg_own_dir "$1"
}

# _greg_same <pid> <start> — true while <pid> is still the process that
# started at <start> (not a reused pid).
_greg_same() {
  local now
  now="$(_greg_start "$1")" || return 1
  [[ "$now" == "$2" ]]
}

# _greg_json <string> — a JSON string literal.
_greg_json() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
  printf '"%s"' "$s"
}

guest_register() {
  local lp="$1" pf="$2" harness="$3" wd="$4" keep="${5:-0}"
  shift 5 2>/dev/null || shift $#
  local pid="" i
  GUEST_REG_ENTRY="" GUEST_REG_PID="" GUEST_REG_START=""
  for ((i = 0; i < 600; i++)); do
    if [[ -s "$pf" ]]; then
      pid="$(tr -dc '0-9' < "$pf")"
      [[ -n "$pid" ]] && break
    fi
    kill -0 "$lp" 2>/dev/null || return 0   # the guest already stopped
    sleep 0.1
  done
  if [[ -z "$pid" ]]; then
    echo "guest-registry: no pidfile from the $harness guest after 60s; not registered (mandu reap will not see it)" >&2
    return 0
  fi
  local start owner_start dir entry also="" p
  start="$(_greg_start "$pid")" || return 0     # gone before we looked
  owner_start="$(_greg_start $$)" || return 0
  for p in "$@"; do [[ -n "$p" ]] && also+="${also:+,}$(_greg_json "$p")"; done
  dir="$(guest_registry_dir)"
  (umask 077; mkdir -p "$dir") 2>/dev/null || { echo "guest-registry: cannot create $dir; the $harness guest is not registered" >&2; return 0; }
  # `mkdir -p` adopts a runtime dir that is already there: a `/tmp/mandu`
  # another account made first (a host with no XDG_RUNTIME_DIR), or a
  # `vm-guests` link planted in it, would receive the entry, which names the
  # run's work dir and the credential copies reap removes
  # (_greg_trusted_registry: the launcher's ownedDirProblem rule).
  if ! _greg_trusted_registry "$dir"; then
    echo "guest-registry: $dir (or the runtime dir it is in) is not a directory of yours that only you can write; the $harness guest is not registered" >&2
    return 0
  fi
  entry="$dir/$harness-$pid.json"
  (
    umask 077
    printf '{"schema":1,"kind":"qemu-guest","harness":%s,"pid":%s,"pidStart":%s,"bootId":%s,"ownerPid":%s,"ownerStart":%s,"workDir":%s,"keep":%s,"alsoRemove":[%s],"startedAt":%s}\n' \
      "$(_greg_json "$harness")" "$pid" "$start" "$(_greg_json "$(_greg_boot_id)")" "$$" "$owner_start" \
      "$(_greg_json "$wd")" "$([[ "$keep" == 1 ]] && echo true || echo false)" "$also" \
      "$(_greg_json "$(date -u +%Y-%m-%dT%H:%M:%SZ)")" > "$entry.tmp" && mv -f "$entry.tmp" "$entry"
  ) || { rm -f "$entry.tmp"; return 0; }
  GUEST_REG_ENTRY="$entry" GUEST_REG_PID="$pid" GUEST_REG_START="$start"
}

# guest_release — the harness is done with its guest (it stopped, or the
# harness is exiting): stop the guest if it still runs (SIGTERM, then SIGKILL
# after 10 s; only the process that was registered, never a reused pid), then
# drop the entry. A guest that survives SIGKILL keeps its entry, so a later
# `mandu reap` still sees it. Idempotent.
guest_release() {
  [[ -n "${GUEST_REG_ENTRY:-}" ]] || return 0
  local pid="$GUEST_REG_PID" start="$GUEST_REG_START" i
  if _greg_same "$pid" "$start"; then
    kill -TERM "$pid" 2>/dev/null
    for ((i = 0; i < 100; i++)); do _greg_same "$pid" "$start" || break; sleep 0.1; done
    if _greg_same "$pid" "$start"; then
      kill -KILL "$pid" 2>/dev/null
      for ((i = 0; i < 20; i++)); do _greg_same "$pid" "$start" || break; sleep 0.1; done
    fi
  fi
  if _greg_same "$pid" "$start"; then
    echo "guest-registry: guest pid $pid survived SIGKILL; its entry stays for mandu reap" >&2
    return 0
  fi
  rm -f "$GUEST_REG_ENTRY"
  GUEST_REG_ENTRY="" GUEST_REG_PID="" GUEST_REG_START=""
}
