#!/usr/bin/env bash
#
# ci-ns-run.test.sh — scripts/ci/ns-run.sh, the per-suite sandbox of the CI
# guest (docs/design/testing/continuous-integration.md §5), for real: a command inside it
# sees an empty $HOME, only the loopback interface, none of the host's
# processes, sockets or /tmp, a cleared environment, and a PRIVATE checkout
# (its writes never reach the host's tree). Both tree modes: `overlay` where
# the chosen bwrap supports it (>= 0.10: the CI image's), and `copy`
# everywhere; plus the refusals (overlay asked of a bwrap without it, a bwrap
# that cannot create a namespace).
#
# Needs a bubblewrap that can create a user namespace here (the guest: any;
# Ubuntu 24.04 host: Mandu's granted /usr/lib/mandu/bin/bwrap). Without one it
# SKIPs. Tier: kernel (it creates namespaces; never run it inside ns-run).
#
# Run:  bash scripts/test/ci-ns-run.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NSRUN="$(cd "$HERE/../ci" && pwd)/ns-run.sh"
PASS=0 FAIL=0 SKIP=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP: $1"; SKIP=$((SKIP + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

# Which bwrap ns-run will use (the same probe order).
works() { [[ -x "$1" ]] && "$1" --unshare-user --ro-bind / / -- /bin/true >/dev/null 2>&1; }
BW=""
for c in "${MANDU_CI_BWRAP:-}" "$(command -v bwrap 2>/dev/null)" /usr/lib/mandu/bin/bwrap; do
  if [[ -n "$c" ]] && works "$c"; then BW="$c"; break; fi
done
if [[ -z "$BW" ]]; then
  skip "no bubblewrap here can create a user namespace (Ubuntu 24.04: \`mandu setup\` installs the granted one)"
  echo; echo "ci-ns-run: $PASS passed, $FAIL failed, $SKIP skipped"; exit 0
fi
export MANDU_CI_BWRAP="$BW"
# grep reads to the end, as ns-run.sh's own probe does: `grep -q` under
# pipefail SIGPIPEs bwrap's --help and, under load, says "no overlay", and the
# refusal checks below then expect a refusal ns-run rightly does not give.
HAS_OVERLAY=0; "$BW" --help 2>&1 | grep -- '--tmp-overlay' >/dev/null && HAS_OVERLAY=1
echo "bwrap: $BW ($("$BW" --version)); overlay: $HAS_OVERLAY"

T="$(mktemp -d "${TMPDIR:-/tmp}/ci-ns-run.XXXXXX")"
SLEEPER=""; LISTENER=""
cleanup() { [[ -n "$SLEEPER" ]] && kill "$SLEEPER" 2>/dev/null; [[ -n "$LISTENER" ]] && kill "$LISTENER" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

# A fake checkout, a fake home with a secret, a host /tmp file, a host process,
# a host loopback listener, a host environment secret.
ROOT="$T/checkout"; mkdir -p "$ROOT/pkg/node_modules/dep" "$ROOT/sub"
echo "original" > "$ROOT/file.txt"; echo "dep" > "$ROOT/pkg/node_modules/dep/index.js"
FHOME="$T/home"; mkdir -p "$FHOME/.ssh"; echo "PRIVATE" > "$FHOME/.ssh/id_ed25519"; echo "tok" > "$FHOME/.claude.json"
HOSTTMP="$(mktemp /tmp/ci-ns-run-host.XXXXXX)"; echo "host" > "$HOSTTMP"
trap 'cleanup; rm -f "$HOSTTMP"' EXIT
sleep 300 & SLEEPER=$!
PORT=""
if command -v python3 >/dev/null 2>&1; then
  python3 - "$T/port" <<'PY' & LISTENER=$!
import socket, sys, time
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(5)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept(); c.close()
PY
  for _ in $(seq 1 50); do [[ -s "$T/port" ]] && break; sleep 0.1; done
  PORT="$(cat "$T/port" 2>/dev/null)"
fi

# in <tree-mode> <script> : run a bash script in the sandbox (HOME = the fake home).
# A private TMPDIR holds ns-run's copy of the checkout, so the "copy removed"
# check sees only this test's copies, never those of the suites the CI runs
# beside the kernel lane (continuous-integration.md §5).
BOXTMP="$T/tmp"; mkdir -p "$BOXTMP"
in_box() {
  local mode="$1"; shift
  TMPDIR="$BOXTMP" HOME="$FHOME" HOST_SECRET_ENV=leak MANDU_AXES_STRICT=1 \
    "$NSRUN" --root "$ROOT" --tree "$mode" --setenv SUITE_VAR fromsuite --chdir "$ROOT/sub" -- bash -c "$1"
}

modes=(copy)
[[ $HAS_OVERLAY -eq 1 ]] && modes=(overlay copy)
for m in "${modes[@]}"; do
  out="$(in_box "$m" '
    echo "HOME=$HOME"; echo "HOMELS=[$(ls -A "$HOME" | tr "\n" " ")]"
    echo "SSH=$(cat '"$FHOME"'/.ssh/id_ed25519 2>&1 | head -1)"
    echo "IFACES=[$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d " " | tr "\n" " ")]"
    echo "NPROC=$(ls -d /proc/[0-9]* | wc -l)"
    echo "SLEEPER=$(kill -0 '"$SLEEPER"' 2>/dev/null && echo visible || echo invisible)"
    echo "HOSTTMP=$(cat '"$HOSTTMP"' 2>/dev/null || echo absent)"
    echo "TMPLS=[$(ls -A /tmp | tr "\n" " ")]"
    echo "PWD=$PWD"
    echo "ENV_SECRET=${HOST_SECRET_ENV:-unset} SUITE_VAR=${SUITE_VAR:-unset} AXES=${MANDU_AXES_STRICT:-unset}"
    echo "ENVKEYS=[$(env | cut -d= -f1 | sort | tr "\n" " ")]"
    echo "GITNAME=$(git config user.name 2>/dev/null)"
    echo "HOSTPORT=$( [[ -n "'"$PORT"'" ]] && { (exec 3<>/dev/tcp/127.0.0.1/'"${PORT:-1}"') 2>/dev/null && echo open || echo refused; } || echo n/a)"
    echo changed > '"$ROOT"'/file.txt; echo new > '"$ROOT"'/new.txt; rm -f '"$ROOT"'/sub/.keep
    echo "INSIDE_FILE=$(cat '"$ROOT"'/file.txt)"
    echo "NM_WRITE=$( (echo x > '"$ROOT"'/pkg/node_modules/dep/index.js) 2>/dev/null && echo written || echo refused)"
    exit 7')"
  rc=$?
  val() { sed -n "s/^$1=//p" <<<"$out" | head -1; }
  check "[$m] the command's exit status comes back (7)" "[[ $rc -eq 7 ]]"
  check "[$m] HOME is the fake home's path, and empty" "[[ \"\$(val HOME)\" == '$FHOME' && \"\$(val HOMELS)\" == '[]' ]]"
  check "[$m] the home's secret is not readable" "[[ \"\$(val SSH)\" != PRIVATE ]]"
  check "[$m] only the loopback interface" "[[ \"\$(val IFACES)\" == '[lo ]' ]]"
  check "[$m] host processes are invisible (a fresh PID namespace)" "[[ \"\$(val SLEEPER)\" == invisible && \"\$(val NPROC)\" -lt 10 ]]"
  check "[$m] the host's /tmp is invisible; /tmp is fresh" "[[ \"\$(val HOSTTMP)\" == absent ]] && ! grep -q ci-ns-run-host <<<\"\$(val TMPLS)\""
  check "[$m] --chdir is honoured" "[[ \"\$(val PWD)\" == '$ROOT/sub' ]]"
  check "[$m] env cleared: a host variable is gone, --setenv and MANDU_AXES_STRICT pass" "[[ \"\$(val ENV_SECRET)\" == 'unset SUITE_VAR=fromsuite AXES=1' ]]"
  keys="$(val ENVKEYS)"
  extra="$(tr -d '[]' <<<"$keys" | tr ' ' '\n' | grep -vxE 'PATH|LANG|TERM|HOME|USER|LOGNAME|TMPDIR|XDG_RUNTIME_DIR|GIT_CONFIG_GLOBAL|SUITE_VAR|MANDU_AXES_STRICT|MANDU_POLICY_FILE|RUSTUP_HOME|CARGO_HOME|PWD|SHLVL|_|OLDPWD|'"$(tr ' ' '|' <<<"${MANDU_CI_PASSENV:-NONE}")" | grep . || true)"
  check "[$m] no variable outside the allow-list (${extra:-none})" "[[ -z \"\$extra\" ]]"
  check "[$m] a git identity exists without the real ~/.gitconfig" "[[ \"\$(val GITNAME)\" == 'Mandu CI' ]]"
  if [[ -n "$PORT" ]]; then
    check "[$m] a host loopback port is unreachable" "[[ \"\$(val HOSTPORT)\" == refused ]]"
  else skip "[$m] host loopback port (no python3 for a listener)"; fi
  check "[$m] the write is visible inside" "[[ \"\$(val INSIDE_FILE)\" == changed ]]"
  check "[$m] ... and never reaches the host's tree" "[[ \"\$(cat '$ROOT/file.txt')\" == original && ! -e '$ROOT/new.txt' ]]"
  if [[ "$m" == copy ]]; then
    check "[copy] node_modules is read-only inside (EROFS, not the host's file)" "[[ \"\$(val NM_WRITE)\" == refused && \"\$(cat '$ROOT/pkg/node_modules/dep/index.js')\" == dep ]]"
    check "[copy] the private copy is removed afterwards" "! ls -d '$BOXTMP'/mandu-ns-run.* >/dev/null 2>&1"
  else
    check "[overlay] node_modules writes stay in the overlay" "[[ \"\$(cat '$ROOT/pkg/node_modules/dep/index.js')\" == dep ]]"
  fi
done

# --bind-rw DIR: the one writable host path (a replay drill's records,
# continuous-integration.md §6). A write into it reaches the host; a write beside
# it, into its parent, into the checkout or the home does not; a hard link
# from outside cannot be made into it (another mount: EXDEV), so the box
# cannot hand the host a file it only had read access to.
for m in "${modes[@]}"; do
  OUTD="$T/out-$m"; DIR="$OUTD/drills/replay/entry.one"; mkdir -p "$DIR"
  HDIR="$FHOME/.mandu/ci-host-out/run-$m/drills/replay/e"; mkdir -p "$HDIR"
  out="$(TMPDIR="$BOXTMP" HOME="$FHOME" "$NSRUN" --root "$ROOT" --tree "$m" --bind-rw "$DIR" --bind-rw "$HDIR" -- bash -c '
    echo "rec" > '"$DIR"'/run.json && mkdir -p '"$DIR"'/sessions && echo s > '"$DIR"'/sessions/k.json && echo "W_DIR=ok"
    echo x > '"$OUTD"'/escape 2>/dev/null; mkdir '"$OUTD"'/drills/replay/sibling 2>/dev/null
    echo changed > '"$ROOT"'/file.txt
    echo "HL=$(ln '"$ROOT"'/file.txt '"$DIR"'/hl 2>/dev/null && echo made || echo refused)"
    echo h > '"$HDIR"'/rec && echo "W_HDIR=ok"
    echo "HOMELS=[$(ls -A "$HOME" | tr "\n" " ")]"
    echo "SSH=$(cat '"$FHOME"'/.ssh/id_ed25519 2>&1 | head -1)"' 2>&1)"; rc=$?
  val() { sed -n "s/^$1=//p" <<<"$out" | head -1; }
  check "[$m] --bind-rw: the box runs ($rc) and its write into DIR reaches the host" "[[ $rc -eq 0 && \"\$(val W_DIR)\" == ok && \"\$(cat '$DIR/run.json')\" == rec && \"\$(cat '$DIR/sessions/k.json')\" == s ]]"
  check "[$m] --bind-rw: a write beside DIR (its parent, a sibling) never reaches the host" "[[ ! -e '$OUTD/escape' && ! -e '$OUTD/drills/replay/sibling' ]]"
  check "[$m] --bind-rw: the checkout stays private" "[[ \"\$(cat '$ROOT/file.txt')\" == original ]]"
  check "[$m] --bind-rw: no hard link into DIR from outside it (another mount)" "[[ \"\$(val HL)\" == refused && ! -e '$DIR/hl' ]]"
  check "[$m] --bind-rw under the hidden home: only that dir comes back, writable; the rest of the home stays empty" "[[ \"\$(val W_HDIR)\" == ok && \"\$(cat '$HDIR/rec')\" == h && \"\$(val HOMELS)\" == '[.mandu ]' && \"\$(val SSH)\" != PRIVATE ]]"
  rm -rf "$FHOME/.mandu"
done
# The refusals: exit 125 before anything runs (the command would leave a mark).
mkdir -p "$T/rw/full" "$T/rw/real" "$T/rw/a/b"; echo x > "$T/rw/full/old"; ln -s "$T/rw/real" "$T/rw/link"
mark="$T/rw-ran"
refuse() {  # refuse <label> <message-regex> <ns-run args...>
  local label="$1" re="$2"; shift 2
  local e; e="$(HOME="$FHOME" "$NSRUN" --root "$ROOT" --tree copy "$@" -- touch "$mark" 2>&1)"; local r=$?
  check "--bind-rw refused: $label (exit 125, says why, ran nothing)" "[[ $r -eq 125 && ! -e '$mark' ]] && grep -qE '$re' <<<\"\$e\""
  rm -f "$mark"
}
refuse "a relative path" "absolute" --bind-rw rw/real
refuse "a missing directory" "not a directory" --bind-rw "$T/rw/missing"
refuse "a symlink" "not a directory" --bind-rw "$T/rw/link"
refuse "a path through a symlink" "canonical" --bind-rw "$T/rw/link/../real"
refuse "a non-empty directory (a view of host files)" "empty" --bind-rw "$T/rw/full"
refuse "the checkout" "is or holds" --bind-rw "$ROOT"
refuse "an ancestor of the checkout" "is or holds" --bind-rw "$T"
refuse "the home" "is or holds|empty" --bind-rw "$FHOME"
refuse "/" "cannot be /" --bind-rw /
refuse "a directory another user owns" "owned by this user|empty" --bind-rw /usr
refuse "two that nest" "nest" --bind-rw "$T/rw/a" --bind-rw "$T/rw/a/b"

# Two sandboxes side by side: the same port, no collision.
if command -v python3 >/dev/null 2>&1; then
  bind='python3 -c "import socket,time; s=socket.socket(); s.bind((\"127.0.0.1\", 45678)); s.listen(1); time.sleep(1.5); print(\"bound\")"'
  a="$(HOME="$FHOME" "$NSRUN" --root "$ROOT" --tree copy -- bash -c "$bind" 2>&1)" & pa=$!
  b="$(HOME="$FHOME" "$NSRUN" --root "$ROOT" --tree copy -- bash -c "$bind" 2>&1)"
  wait $pa; ra=$?
  check "two sandboxes bind the same loopback port at once" "[[ $ra -eq 0 ]] && grep -qx bound <<<\"\$b\""
fi

# The end of the box (ns-run.sh's header): bwrap returns as soon as the
# command exits, while the box's init (pid 1 inside, a session of its own
# outside) still kills and reaps what the command left and releases the box.
# Under load that took seconds, and the runner's subreaper found the init
# still ending, nameless: "left 1 process running outside its process group
# (killed): <pid> (?)" on suites whose tests all passed (2026-10-17, six
# entries in four CI runs). ns-run returns only once that init is gone.
# The box leaves a 256 MiB process behind, so the box takes a while to end;
# the control (bare bwrap, the same flags) shows the init outliving bwrap.
if command -v python3 >/dev/null 2>&1; then
  # kids_of PID: the pids whose parent is PID (field 4 of /proc/<pid>/stat).
  kids_of() {
    local f s p
    for f in /proc/[0-9]*/stat; do
      { read -r s < "$f"; } 2>/dev/null || continue
      p="${s##*) }"; p="${p#* }"; p="${p%% *}"
      if [[ "$p" == "$1" ]]; then s="${f#/proc/}"; echo "${s%/stat}"; fi
    done
  }
  init_alive() {  # the pid is there and not a zombie
    local s; { read -r s < "/proc/$1/stat"; } 2>/dev/null || return 1
    s="${s##*) }"; [[ "${s:0:1}" != Z ]]
  }
  ENDD="$T/end"; mkdir -p "$ENDD"
  leftover='python3 -c "import time; b=bytearray(256*1024*1024); [b.__setitem__(i,1) for i in range(0,len(b),4096)]; open(\"'"$ENDD"'/ready\",\"w\"); time.sleep(600)" & while [ ! -e '"$ENDD"'/go ]; do sleep 0.05; done; exit 0'
  # box_end <label> <cmd...>: run cmd in the background; once the leftover is
  # up, find the box's init (the child of the outer bwrap), let the command
  # exit, and print whether the init was still there when cmd returned.
  box_end() {
    rm -f "$ENDD/ready" "$ENDD/go"
    "$@" >/dev/null 2>&1 & local top=$! outer="" init="" i
    for i in $(seq 1 300); do [[ -e "$ENDD/ready" ]] && break; sleep 0.1; done
    # the outer bwrap: the command itself once it is bwrap (bare, or an
    # ns-run that exec'd it), else its child (an ns-run that stays the parent)
    if [[ "$(cat "/proc/$top/comm" 2>/dev/null)" == bwrap ]]; then outer=$top; else outer="$(kids_of "$top" | head -1)"; fi
    [[ -n "$outer" ]] && init="$(kids_of "$outer" | head -1)"
    touch "$ENDD/go"
    wait "$top"; local rc=$?
    if [[ -z "$init" ]]; then echo "noinit rc=$rc"; elif init_alive "$init"; then echo "alive rc=$rc"; else echo "gone rc=$rc"; fi
  }
  ctl="$(box_end "$BW" --unshare-user --unshare-pid --die-with-parent --new-session --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --bind "$ENDD" "$ENDD" -- sh -c "$leftover")"
  check "control: bare bwrap returns while the box's init is still ending ($ctl)" "[[ \"\$ctl\" == 'alive rc=0' ]]"
  for m in "${modes[@]}"; do
    got="$(TMPDIR="$BOXTMP" HOME="$FHOME" box_end "$NSRUN" --root "$ROOT" --tree "$m" --bind-rw "$ENDD" -- sh -c "$leftover")"
    check "[$m] ns-run returns only once the box's init is gone ($got)" "[[ \"\$got\" == 'gone rc=0' ]]"
    check "[$m] ... and leaves nothing in its TMPDIR (the info file is unlinked)" "! ls '$BOXTMP'/ns-run-info.* >/dev/null 2>&1"
    rm -f "$ENDD/ready" "$ENDD/go"
  done
else skip "the end of the box (no python3 for the leftover process)"; fi

# Refusals.
# overlay asked of a bwrap without it: the real one if it lacks overlay, else
# the same bwrap behind a wrapper whose --help does not offer it (0.9's).
NOOV="$BW"
if [[ $HAS_OVERLAY -eq 1 ]]; then
  NOOV="$T/bwrap-0.9-like"
  printf '#!/bin/sh\nif [ "$1" = --help ]; then "%s" --help 2>&1 | grep -v overlay; exit 0; fi\nexec "%s" "$@"\n' "$BW" "$BW" > "$NOOV"
  chmod +x "$NOOV"
fi
# The overlay probe must not depend on how bwrap's --help is written: a help
# that names --tmp-overlay first and goes on for 300 KB made the old
# `--help | grep -q` probe SIGPIPE the writer and, under pipefail, say "no
# overlay" (it did so under load in the guest, local-faster-v32).
if [[ $HAS_OVERLAY -eq 1 ]]; then
  LOUD="$T/bwrap-loud-help"
  printf '#!/bin/sh\nif [ "$1" = --help ]; then echo "  --tmp-overlay DEST"; head -c 300000 /dev/zero | tr "\\0" x; echo; exit 0; fi\nexec "%s" "$@"\n' "$BW" > "$LOUD"
  chmod +x "$LOUD"
  out="$(HOME="$FHOME" MANDU_CI_BWRAP="$LOUD" "$NSRUN" --root "$ROOT" --tree overlay -- cat "$ROOT/file.txt" 2>&1)"; rc=$?
  check "the overlay probe reads a long --help to the end (no SIGPIPE false 'no overlay')" "[[ $rc -eq 0 ]] && grep -q original <<<\"\$out\""
else skip "overlay probe on a long --help (this bwrap has no overlay)"; fi

err="$(HOME="$FHOME" MANDU_CI_BWRAP="$NOOV" "$NSRUN" --root "$ROOT" --tree overlay -- sh -c "echo bad > '$ROOT/file.txt'" 2>&1)"; rc=$?
check "overlay asked of a bwrap without it: exit 125, says so, never binds rw" "[[ $rc -eq 125 ]] && grep -q 'overlay' <<<\"\$err\" && grep -q 'Refusing' <<<\"\$err\" && [[ \"\$(cat '$ROOT/file.txt')\" == original ]]"
out="$(HOME="$FHOME" MANDU_CI_BWRAP="$NOOV" MANDU_CI_TREE=auto "$NSRUN" --root "$ROOT" -- cat "$ROOT/file.txt" 2>&1)"
check "--tree auto on a bwrap without overlay falls back to the copy, with a note" "grep -q original <<<\"\$out\" && grep -q 'private copy' <<<\"\$out\""
err="$(MANDU_CI_BWRAP=/bin/false "$NSRUN" --root "$ROOT" -- true 2>&1)"; rc=$?
check "a MANDU_CI_BWRAP that cannot create a namespace: exit 125" "[[ $rc -eq 125 ]] && grep -q 'cannot create a user namespace' <<<\"\$err\""
"$NSRUN" --root "$ROOT" --tree bogus -- true 2>/dev/null; check "--tree must be overlay|copy|auto" "[[ $? -eq 125 ]]"

# Nesting (continuous-integration.md §5.6): can a bwrap started inside the box
# create a user namespace (Mandu's git sandbox needs it)? --check says, the
# box agrees, a run that cannot nest says so on stderr, and the auto-pick
# prefers a bwrap that nests. The independent answer: a real bwrap inside a
# real ns-run box.
inner='for b in /usr/lib/mandu/bin/bwrap "$(command -v bwrap)"; do [ -x "$b" ] && "$b" --unshare-user --ro-bind / / -- /bin/true 2>/dev/null && { echo yes; exit 0; }; done; echo no'
real_nest="$(HOME="$FHOME" "$NSRUN" --root "$ROOT" --tree copy -- sh -c "$inner" 2>/dev/null)"
chk="$(HOME="$FHOME" "$NSRUN" --check)"; rc=$?
check "--check runs nothing and names the bwrap, overlay and nesting" "[[ $rc -eq 0 ]] && grep -qx 'bwrap: $BW (.*)' <<<\"\$chk\" && grep -qxE 'overlay: (yes|no)' <<<\"\$chk\""
check "--check's nested-bwrap ($(sed -n 's/^nested-bwrap: //p' <<<"$chk")) is what a bwrap inside the box finds ($real_nest)" "[[ \"\$(sed -n 's/^nested-bwrap: //p' <<<\"\$chk\")\" == '$real_nest' ]]"
err="$(HOME="$FHOME" "$NSRUN" --root "$ROOT" --tree copy -- true 2>&1 >/dev/null)"
if [[ "$real_nest" == no ]]; then
  check "a box a bwrap cannot nest in says so on stderr: the git sandbox is off, its tests SKIP, the guest runs them" "grep -q \"git sandbox is off inside\" <<<\"\$err\" && grep -q 'scripts/ci/vm-run.sh' <<<\"\$err\""
else
  check "a box a bwrap nests in says nothing about nesting" "! grep -q 'git sandbox' <<<\"\$err\""
fi
# A bwrap whose sandbox never nests: the same bwrap with --disable-userns.
if "$BW" --help 2>&1 | grep -- '--disable-userns' >/dev/null; then
  NONEST="$T/bwrap-no-nest"
  printf '#!/bin/sh\ncase "$1" in --help|--version) exec "%s" "$@" ;; esac\nexec "%s" --disable-userns "$@"\n' "$BW" "$BW" > "$NONEST"
  chmod +x "$NONEST"
  chk="$(env -u MANDU_CI_BWRAP HOME="$FHOME" MANDU_CI_BWRAP="$NONEST" "$NSRUN" --tree copy --check)"
  check "an explicit bwrap that cannot nest: --check says nested-bwrap: no" "grep -qx 'nested-bwrap: no' <<<\"\$chk\""
  err="$(HOME="$FHOME" MANDU_CI_BWRAP="$NONEST" "$NSRUN" --root "$ROOT" --tree copy -- true 2>&1 >/dev/null)"
  check "... and a run in it says the git sandbox is off inside" "grep -q 'git sandbox is off inside' <<<\"\$err\""
  chk="$(env -u MANDU_CI_BWRAP HOME="$FHOME" MANDU_CI_BWRAP_CANDIDATES="$NONEST:$BW" "$NSRUN" --tree copy --check)"
  if [[ "$real_nest" == yes ]]; then
    check "the auto-pick passes over a first candidate that cannot nest for one that can" "grep -qx 'bwrap: $BW (.*)' <<<\"\$chk\" && grep -qx 'nested-bwrap: yes' <<<\"\$chk\""
  else
    check "the auto-pick keeps the first candidate when none nests" "grep -qx 'bwrap: $NONEST (.*)' <<<\"\$chk\" && grep -qx 'nested-bwrap: no' <<<\"\$chk\""
  fi
else skip "nesting preference (this bwrap has no --disable-userns to build a non-nesting one)"; fi
"$NSRUN" --root / -- true 2>/dev/null; check "--root / is refused" "[[ $? -eq 125 ]]"
out="$(HOME="$FHOME" MANDU_CI_TREE=auto "$NSRUN" --root "$ROOT" -- cat "$ROOT/file.txt" 2>&1)"
check "--tree auto picks what the bwrap supports and runs" "grep -q original <<<\"\$out\""

echo
echo "ci-ns-run: $PASS passed, $FAIL failed, $SKIP skipped"
[[ $FAIL -eq 0 ]]
