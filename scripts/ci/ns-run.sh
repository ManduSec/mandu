#!/usr/bin/env bash
# ns-run.sh — run ONE command in a throwaway namespace sandbox
# (docs/design/testing/continuous-integration.md §5). The CI runner wraps every
# non-kernel suite in it, so two suites running side by side cannot collide on
# a port, a socket, a $HOME file, a process or a file in the checkout.
#
#   ns-run.sh [--chdir DIR] [--setenv K V]... [--bind-rw DIR]... [--root DIR]
#             [--bwrap PATH] [--tree overlay|copy|auto] -- cmd [arg...]
#   ns-run.sh [--bwrap PATH] --check     runs nothing; prints the bwrap it
#             would use, `overlay: yes|no` and `nested-bwrap: yes|no`
#
# The sandbox (bubblewrap):
#   - new user, PID, IPC, UTS and network namespaces: loopback only;
#   - the host's / read-only;
#   - the checkout (--root, default the repo this script is in) as a PRIVATE
#     copy: writes into it are the command's own and vanish with it;
#   - a fresh, empty tmpfs over $HOME (HOME stays its path), over /tmp, over
#     /dev/shm and over the host's runtime dir; XDG_RUNTIME_DIR is a fresh
#     directory. The toolchain directories that live under $HOME (the PATH
#     entries there, ~/.cargo, ~/.rustup) come back read-only (copy mode) or
#     as a private overlay (overlay mode) so node and cargo still resolve;
#   - --clearenv, then an allow-list: PATH, LANG, TERM, HOME, USER, LOGNAME,
#     TMPDIR, XDG_RUNTIME_DIR, MANDU_AXES_STRICT and MANDU_POLICY_FILE when set,
#     RUSTUP_HOME/CARGO_HOME when set, the names in $MANDU_CI_PASSENV, and the
#     --setenv pairs (last wins);
#   - a fixed git identity (GIT_CONFIG_GLOBAL, a file in the sandbox's /tmp),
#     because git refuses to commit without one and the real ~/.gitconfig is
#     hidden;
#   - --die-with-parent --new-session;
#   - nothing of the host writable, except each --bind-rw DIR (below).
#
# The end of the box: ns-run returns only once the whole sandbox is gone.
# bwrap itself returns as soon as the command exits (its init, pid 1 of the
# box, reports the status at once), but that init lives on, in a session of
# its own, until everything left in the box is killed and reaped and the box's
# namespaces and mounts are released. Under load that takes seconds, and the
# runner's subreaper (run-suites.mjs) then found the init still ending, orphaned
# and with no command line: "left 1 process running outside its process group
# (killed): <pid> (?)" on a suite whose tests all passed. So ns-run stays the
# parent of bwrap, reads the init's pid from `--info-fd` ("child-pid") and
# waits for it to end (at most NS_RUN_END_S seconds, default 30) before it
# exits with the command's status.
#
# --bind-rw DIR (repeatable) binds DIR read-write at its own path: the ONLY
# host paths a command can write, for results it leaves behind (a replay
# drill's records, continuous-integration.md §6). DIR must be an absolute,
# canonical path (no symlink in it), an existing EMPTY directory owned by this
# user (the box gets a fresh place to write, never a view of host files), and
# neither /, the checkout, $HOME, the account's home, the runtime dir nor an
# ancestor of any of them; two --bind-rw may not nest. It is mounted last, over
# the tmpfs and the overlays. What the command leaves there is untrusted: the
# reader (pipeline.sh, then collect-results.mjs) treats it so. A refusal is
# exit 125, before anything runs.
#
# The private checkout (--tree, or $MANDU_CI_TREE):
#   overlay  (default) --overlay-src ROOT --tmp-overlay ROOT. Needs bubblewrap
#            >= 0.10; Ubuntu 24.04 ships 0.9.0, so the CI image builds its own
#            (/usr/local/lib/mandu-ci/bwrap, scripts/ci/pins.env). With a
#            bwrap that lacks it, ns-run FAILS; it never falls back to binding
#            the checkout read-write.
#   copy     a per-run copy of the checkout without node_modules/ and .git/
#            (target/ included), bound read-write; every node_modules/ is
#            bound back read-only. For a host whose only usable bwrap is 0.9
#            (Ubuntu 24.04 with Mandu's granted copy). A suite that writes into
#            a node_modules/ fails with EROFS instead of reaching the host.
#   auto     overlay when the bwrap supports it, else copy (with a note on
#            stderr). scripts/ci/pipeline.sh --host uses it.
#
# Which bwrap: --bwrap, else $MANDU_CI_BWRAP, else the first candidate that can
# create a user namespace here AND lets a bwrap started inside its sandbox
# create one too (a sandbox nests), else the first that can create one at all.
# The candidates: `bwrap` on PATH, then /usr/lib/mandu/bin/bwrap (Mandu's own
# copy with its AppArmor profile, installed by `mandu setup`);
# $MANDU_CI_BWRAP_CANDIDATES (colon-separated) replaces the list. Probed, not
# guessed: an explicit choice that cannot create a namespace is an error.
#
# Nesting (continuous-integration.md §5.6). Mandu's git sandbox (hardened-git.ts
# probeGitSandbox) and every other sandbox a suite starts run INSIDE this one.
# Where Ubuntu's AppArmor `bwrap-userns-restrict` is loaded (26.04's default),
# what /usr/bin/bwrap runs may not create a user namespace, so inside the box
# the git sandbox is off and the tests of its paths SKIP; ns-run says so on
# stderr at the start of every such run. The CI guest disables that profile
# (scripts/ci/guest/provision.sh), so the paths run there; on a host, Mandu's
# own bubblewrap nests (its profile lets bwrap start bwrap), and ns-run picks it
# when it is installed.
#
# Exit status: the command's, or 125 when the sandbox cannot be set up.
set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SELF_DIR/../.." && pwd)"
CHDIR=""
BWRAP="${MANDU_CI_BWRAP:-}"
TREE="${MANDU_CI_TREE:-overlay}"
SETENV=()
BIND_RW=()

die() { echo "ns-run: $*" >&2; exit 125; }
usage() { die "usage: ns-run.sh [--chdir DIR] [--setenv K V]... [--bind-rw DIR]... [--root DIR] [--bwrap PATH] [--tree overlay|copy|auto] -- cmd... | ns-run.sh [--bwrap PATH] --check"; }
CHECK=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --chdir)  [[ $# -ge 2 ]] || usage; CHDIR="$2"; shift 2 ;;
    --setenv) [[ $# -ge 3 ]] || usage
              [[ "$2" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "bad variable name: $2"
              SETENV+=("$2" "$3"); shift 3 ;;
    --root)   [[ $# -ge 2 ]] || usage; ROOT="$2"; shift 2 ;;
    --bind-rw) [[ $# -ge 2 ]] || usage; BIND_RW+=("$2"); shift 2 ;;
    --bwrap)  [[ $# -ge 2 ]] || usage; BWRAP="$2"; shift 2 ;;
    --tree)   [[ $# -ge 2 ]] || usage; TREE="$2"; shift 2 ;;
    --check)  CHECK=1; shift ;;
    --)       shift; break ;;
    *)        usage ;;
  esac
done
[[ $# -ge 1 || $CHECK -eq 1 ]] || usage
case "$TREE" in overlay|copy|auto) ;; *) die "--tree must be overlay, copy or auto (got '$TREE')" ;; esac
[[ -d "$ROOT" ]] || die "--root is not a directory: $ROOT"
ROOT="$(cd "$ROOT" && pwd -P)"
[[ "$ROOT" != / ]] || die "--root cannot be /"
if [[ -n "$CHDIR" ]]; then
  [[ "$CHDIR" == /* ]] || die "--chdir must be absolute: $CHDIR"
else
  CHDIR="$ROOT"
fi

# ── which bwrap ────────────────────────────────────────────────────────────
bwrap_works() { [[ -x "$1" ]] && "$1" --unshare-user --ro-bind / / -- /bin/true >/dev/null 2>&1; }
# Can a bwrap started inside $1's sandbox create a user namespace? The inner
# candidates are the git sandbox's (hardened-git.ts): Mandu's own copy, then
# `bwrap` on PATH.
# shellcheck disable=SC2016
NEST_PROBE='for b in /usr/lib/mandu/bin/bwrap "$(command -v bwrap)"; do [ -x "$b" ] && "$b" --unshare-user --ro-bind / / -- /bin/true 2>/dev/null && exit 0; done; exit 1'
bwrap_nests() { "$1" --unshare-user --unshare-pid --ro-bind / / --dev /dev --proc /proc -- /bin/sh -c "$NEST_PROBE" >/dev/null 2>&1; }
# grep reads to the end (no -q): with pipefail, `grep -q` exiting at the first
# match can SIGPIPE bwrap's second write of its ~4.9 KB help, and the probe then
# says "no overlay" under load (continuous-integration.md §11, local-faster-v32).
bwrap_has_overlay() { "$1" --help 2>&1 | grep -- '--tmp-overlay' >/dev/null; }
resolve() { command -v "$1" 2>/dev/null || true; }
NESTS=0
if [[ -n "$BWRAP" ]]; then
  b="$(resolve "$BWRAP")"
  [[ -n "$b" ]] || die "bwrap not found: $BWRAP"
  bwrap_works "$b" || die "$b cannot create a user namespace here ($("$b" --unshare-user --ro-bind / / -- /bin/true 2>&1 | head -1))"
  BWRAP="$b"
  bwrap_nests "$BWRAP" && NESTS=1
else
  if [[ -n "${MANDU_CI_BWRAP_CANDIDATES:-}" ]]; then IFS=: read -r -a cands <<<"$MANDU_CI_BWRAP_CANDIDATES"
  else cands=("$(resolve bwrap)" /usr/lib/mandu/bin/bwrap); fi
  first=""
  for cand in "${cands[@]}"; do
    { [[ -n "$cand" ]] && bwrap_works "$cand"; } || continue
    [[ -n "$first" ]] || first="$cand"
    # A bwrap a sandbox nests in wins, unless it lacks the overlay asked for.
    [[ "$TREE" == overlay ]] && ! bwrap_has_overlay "$cand" && continue
    if bwrap_nests "$cand"; then BWRAP="$cand"; NESTS=1; break; fi
  done
  [[ -n "$BWRAP" ]] || BWRAP="$first"
  [[ -n "$BWRAP" ]] || die "no bubblewrap here can create a user namespace (tried: ${cands[*]}). On Ubuntu 24.04 run \`mandu setup\` for the granted copy, or set MANDU_CI_BWRAP."
fi
has_overlay() { bwrap_has_overlay "$BWRAP"; }
if [[ $CHECK -eq 1 ]]; then
  echo "bwrap: $BWRAP ($("$BWRAP" --version 2>/dev/null))"
  echo "overlay: $(has_overlay && echo yes || echo no)"
  echo "nested-bwrap: $([[ $NESTS -eq 1 ]] && echo yes || echo no)"
  exit 0
fi
if [[ $NESTS -eq 0 ]]; then
  echo "ns-run: note: a bubblewrap inside this sandbox cannot create a user namespace here (on Ubuntu: AppArmor's bwrap-userns-restrict), so Mandu's git sandbox is off inside and the tests of the git-sandbox paths SKIP; they run in the CI guest (scripts/ci/vm-run.sh), or here with Mandu's own bubblewrap (\`mandu setup\`)" >&2
fi
if [[ "$TREE" == auto ]]; then
  if has_overlay; then TREE=overlay
  else TREE=copy; echo "ns-run: note: $BWRAP ($("$BWRAP" --version 2>/dev/null)) has no overlay support; the checkout is a private copy (--tree copy)" >&2; fi
elif [[ "$TREE" == overlay ]] && ! has_overlay; then
  die "$BWRAP ($("$BWRAP" --version 2>/dev/null)) has no --overlay-src/--tmp-overlay (bubblewrap >= 0.10 has them). Refusing to bind the checkout read-write. Use a newer bwrap (MANDU_CI_BWRAP), or --tree copy for a private copy of the checkout."
fi

# ── the sandbox ────────────────────────────────────────────────────────────
uid="$(id -u)"
user="$(id -un 2>/dev/null || echo ci)"
args=(--unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-net
      --die-with-parent --new-session
      --ro-bind / /
      --dev /dev --proc /proc
      --tmpfs /tmp --tmpfs /dev/shm)

# The host's runtime dir (sockets of a live stack, the session bus): hidden.
if [[ -d "/run/user/$uid" ]]; then args+=(--tmpfs "/run/user/$uid"); fi
# A container daemon's socket is root-equivalent for its group: hidden too.
for s in $(for s in /run/docker.sock /var/run/docker.sock /run/podman/podman.sock; do
             [[ -S "$s" ]] && readlink -f "$s"; done | sort -u); do
  args+=(--ro-bind /dev/null "$s")
done

# $HOME: a fresh tmpfs at the same path; toolchains under it come back. The
# account's own home (passwd) is hidden too when $HOME points elsewhere.
canon() { [[ -n "$1" && -d "$1" ]] && (cd "$1" && pwd -P); }
home="$(canon "${HOME:-}")"
pw_home="$(canon "$(getent passwd "$uid" 2>/dev/null | cut -d: -f6)")"
hide=()
for h in "$home" "$pw_home"; do
  [[ -n "$h" && "$h" != / && "$h" != "$ROOT" && "$h" != "$ROOT"/* ]] || continue
  hide+=("$h")
done
mapfile -t hide < <(printf '%s\n' "${hide[@]+"${hide[@]}"}" | awk 'NF' | LC_ALL=C sort -u)
if [[ -z "$home" || "$home" == / || "$home" == "$ROOT" ]]; then
  home=/tmp/home; args+=(--dir /tmp/home)
fi
under_hidden() { local h; for h in "${hide[@]+"${hide[@]}"}"; do [[ "$1" == "$h"/* ]] && return 0; done; return 1; }

# --bind-rw: every check before anything runs (the header says why each).
# is_at_or_above A B: A is B or one of its ancestors.
is_at_or_above() { [[ "$1" == "$2" || "$1" == / || "$2" == "$1"/* ]]; }
rw=()
for d in "${BIND_RW[@]+"${BIND_RW[@]}"}"; do
  [[ "$d" == /* ]] || die "--bind-rw must be an absolute path: $d"
  [[ "$d" =~ ^/+$ ]] && die "--bind-rw cannot be /"
  d="${d%/}"
  [[ -d "$d" && ! -L "$d" ]] || die "--bind-rw is not a directory: $d"
  c="$(cd "$d" 2>/dev/null && pwd -P)" || die "--bind-rw cannot be entered: $d"
  [[ "$c" == "$d" ]] || die "--bind-rw must be a canonical path (no symlink, no . or ..): $d is $c"
  case "$c" in /proc|/proc/*|/sys|/sys/*|/dev|/dev/*) die "--bind-rw cannot be under /proc, /sys or /dev: $c" ;; esac
  for s in "$ROOT" "$home" "$pw_home" "/run/user/$uid" "${XDG_RUNTIME_DIR:-}"; do
    [[ -n "$s" ]] || continue
    if is_at_or_above "$c" "$s"; then die "--bind-rw $c is or holds $s: it would make that writable"; fi
  done
  for e in "${rw[@]+"${rw[@]}"}"; do
    if is_at_or_above "$c" "$e" || is_at_or_above "$e" "$c"; then die "--bind-rw $c and $e nest"; fi
  done
  rw+=("$c")
done
for c in "${rw[@]+"${rw[@]}"}"; do
  [[ -O "$c" ]] || die "--bind-rw must be owned by this user: $c"
  first="$(find "$c" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" || die "--bind-rw cannot be listed: $c"
  [[ -z "$first" ]] || die "--bind-rw must be an empty directory: $c"
done
keep=()
for h in "${hide[@]+"${hide[@]}"}"; do args+=(--tmpfs "$h"); done
IFS=: read -r -a path_dirs <<<"${PATH:-}"
for d in "${path_dirs[@]+"${path_dirs[@]}"}"; do
  d="$(canon "$d")"; [[ -n "$d" ]] || continue
  under_hidden "$d" || continue
  # ~/.nvm/versions/node/vX/bin → the whole version dir (its lib/ holds npm);
  # ~/.local/bin and ~/bin stay themselves (~/.local/share holds logins).
  p="$(dirname "$d")"
  if [[ "$(basename "$d")" == bin && "$(basename "$p")" != .local ]] && ! printf '%s\n' "${hide[@]}" | grep -xF "$p" >/dev/null; then
    d="$p"
  fi
  keep+=("$d")
done
for h in "${hide[@]+"${hide[@]}"}"; do
  for d in "${RUSTUP_HOME:-$h/.rustup}" "${CARGO_HOME:-$h/.cargo}"; do
    d="$(canon "$d")"; [[ -n "$d" ]] && under_hidden "$d" && keep+=("$d")
  done
done
# de-duplicate, drop a dir nested in another kept one, drop the checkout.
mapfile -t keep < <(printf '%s\n' "${keep[@]+"${keep[@]}"}" | awk 'NF' | LC_ALL=C sort -u)
kept=()
for d in "${keep[@]+"${keep[@]}"}"; do
  nested=0
  for e in "${kept[@]+"${kept[@]}"}"; do [[ "$d" == "$e"/* ]] && nested=1; done
  [[ "$d" == "$ROOT" || "$d" == "$ROOT"/* || "$ROOT" == "$d"/* ]] && nested=1
  [[ $nested -eq 0 ]] && kept+=("$d")
done
for d in "${kept[@]+"${kept[@]}"}"; do
  if [[ "$TREE" == overlay ]]; then args+=(--overlay-src "$d" --tmp-overlay "$d")
  else args+=(--ro-bind "$d" "$d"); fi
done

# The checkout, private.
copy_dir=""
cleanup() { [[ -n "$copy_dir" ]] && rm -rf "$copy_dir"; }
if [[ "$TREE" == overlay ]]; then
  args+=(--overlay-src "$ROOT" --tmp-overlay "$ROOT")
else
  copy_dir="$(mktemp -d "${TMPDIR:-/tmp}/mandu-ns-run.XXXXXX")" || die "mktemp failed"
  trap cleanup EXIT
  trap 'exit 143' TERM INT HUP
  tar -C "$ROOT" --exclude=./.git --exclude=node_modules -cf - . | tar -C "$copy_dir" -xf - \
    || die "copying the checkout failed"
  args+=(--bind "$copy_dir" "$ROOT")
  while IFS= read -r -d '' nm; do
    args+=(--ro-bind "$nm" "$nm")
  done < <(find "$ROOT" \( -path "$ROOT/.git" -o -path "$ROOT/interceptors/target" \) -prune \
             -o -name node_modules -type d -print0 -prune 2>/dev/null)
fi

# The policy file a suite is pointed at, when it lives under a hidden dir.
if [[ -n "${MANDU_POLICY_FILE:-}" && -f "$MANDU_POLICY_FILE" ]]; then
  args+=(--ro-bind "$MANDU_POLICY_FILE" "$MANDU_POLICY_FILE")
fi

# The writable binds, last: over the tmpfs and the overlays above.
for d in "${rw[@]+"${rw[@]}"}"; do args+=(--bind "$d" "$d"); done

# The environment.
runtime=/tmp/.xdg-runtime
args+=(--perms 0700 --dir "$runtime")
gitcfg=/tmp/.mandu-ci-gitconfig
exec 3<<'GITCFG'
[user]
	name = Mandu CI
	email = ci@mandu.invalid
[init]
	defaultBranch = main
GITCFG
args+=(--file 3 "$gitcfg")
args+=(--clearenv
       --setenv PATH "${PATH:-/usr/local/bin:/usr/bin:/bin}"
       --setenv LANG "${LANG:-C.UTF-8}"
       --setenv HOME "$home"
       --setenv USER "$user" --setenv LOGNAME "$user"
       --setenv TMPDIR /tmp
       --setenv XDG_RUNTIME_DIR "$runtime"
       --setenv GIT_CONFIG_GLOBAL "$gitcfg")
[[ -n "${TERM:-}" ]] && args+=(--setenv TERM "$TERM")
for v in MANDU_AXES_STRICT MANDU_POLICY_FILE RUSTUP_HOME CARGO_HOME ${MANDU_CI_PASSENV:-}; do
  [[ "$v" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "bad name in MANDU_CI_PASSENV: $v"
  if [[ -n "${!v+x}" ]]; then args+=(--setenv "$v" "${!v}"); fi
done
for ((i = 0; i < ${#SETENV[@]}; i += 2)); do
  args+=(--setenv "${SETENV[i]}" "${SETENV[i+1]}")
done
args+=(--chdir "$CHDIR")

# The box's init: bwrap writes its pid ("child-pid", this namespace's) to the
# info fd; fd 4 writes it, fd 5 reads it back, the file is unlinked at once
# (nothing is left in TMPDIR). bwrap closes the info fd in the box.
info="$(mktemp "${TMPDIR:-/tmp}/ns-run-info.XXXXXX")" || die "mktemp failed"
exec 4>"$info" 5<"$info"
rm -f "$info"
args+=(--info-fd 4)

# box_init_alive PID: the box's init is still there (neither gone nor a zombie,
# which its reaper reaps; and started after this script, so not a recycled pid).
own_start="$(read -r s < "/proc/$$/stat" && s="${s##*) }" && set -- $s && echo "${20}")"
box_init_alive() {
  local s
  { read -r s < "/proc/$1/stat"; } 2>/dev/null || return 1
  s="${s##*) }"
  # shellcheck disable=SC2086
  set -- $s
  [[ "$1" != Z && ( -z "$own_start" || "${20}" -ge "$own_start" ) ]]
}

# copy mode needs the parent for the copy's removal, both modes for the wait.
"$BWRAP" "${args[@]}" -- "$@" 5<&-
rc=$?
exec 4>&-
init_pid="$(sed -n 's/^ *"child-pid": *\([0-9][0-9]*\).*/\1/p' <&5 | head -1)"
exec 5<&-
if [[ -n "$init_pid" ]]; then
  end_s="${NS_RUN_END_S:-30}"
  [[ "$end_s" =~ ^[0-9]+$ ]] || end_s=30
  deadline=$((SECONDS + end_s))
  while box_init_alive "$init_pid"; do
    if ((SECONDS >= deadline)); then
      echo "ns-run: the sandbox's init (pid $init_pid) had not ended ${end_s}s after its command exited" >&2
      break
    fi
    sleep 0.05
  done
fi
exit "$rc"
