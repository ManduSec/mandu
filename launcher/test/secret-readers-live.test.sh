#!/usr/bin/env bash
# secret-readers-live.test.sh — plan 10 §4.1 live: the interposer's reader half
# (confidentiality-plan-10-flow-taint.md). A real arbiter in mode `secrets` with
# a policy.yaml naming GNU `sha256sum` as the reader of ~/.pgpass (a system
# program that reads the file it is named and prints none of its bytes: a
# raw read shows as the real file's hash; on a uutils host every coreutils
# program is a printer by path, so it is GNU's `gnusha256sum` there). Until
# 2026-10-03 the reader was `cat`, then `curl file://…`: both are printers
# and admit nothing since plan 13 D8 and its !437 leftover (1), asserted in
# (6c) and (6d). The steps that need the raw bytes on a pipe (the shells
# holding .env, plan 13 D2) read through `mdu-holder`, a reader the test
# builds (tests/lib/holder-reader.c) and pins by path and hash. The real mandu-net-guard
# with the launcher's secret policy file, real bwrap twin binds (the launcher's
# wrap order: guard OUTSIDE, bind inside), real processes:
#   (1) the listed reader gets the REAL bytes through the bind (ADDFD of the real file)
#   (2) a program not on the list gets EACCES (a reader list is exhaustive)
#   (3) a file with no reader list is the structured twin for everyone, and sources
#   (4) WITHOUT any bind (the `gated` shape), the guard alone serves the twin (§11.7),
#       and a path rewritten mid-open never reads the real file (§4.1a)
#   (5) the arbiter recorded the reader's taint before the descriptor was injected
#   (7)-(10) the shells hold the workspace secrets through the reader's pipe
#       (plan 13 D2): since plan 13 §8 decision (b) (2026-10-02) a shell is no
#       reader, and (6b) asserts it: `. .env` with sh, dash and bash listed
#       gets no byte; (6c): `cat .env` with cat listed gets none either
#       (printers admit nothing, plan 13 D8, 2026-10-03); (6e): a copy of
#       bash renamed and pinned by path and hash gets none (its hash is an
#       installed shell's, 2026-10-03); (6f): a python no installed
#       program's hash matches, renamed and pinned, gets none (the guard
#       knows it by its content, 2026-10-03); (6g): the same for each of
#       ksh93, mksh, lksh, yash, posh, fish and LuaJIT the host has, the
#       refusal naming its family (the families !506 left out, 2026-10-04;
#       the CI image has mksh, lksh, yash and luajit); (6h): a GNU cat no hash knows,
#       renamed and vouched for (`prints: nothing`), gets none (the guard
#       knows its package by content, P0 item 14, 2026-10-07); (6i): nor
#       does a disguised .NET muxer (the holder carrying its front end)
#   (12)-(16) Plan 13 D8, a reader's identity: a human verdict, a first-use pin,
#       a `from:` parent and a secret socket's reader are the BINARY (path,
#       hash, out of the agent's reach, a clean loader environment), never a
#       name a workspace copy can take
#   (17) a `from:` parent is a process of the session: the guard started by a
#       python3 subreaper (an IDE's terminal, a CI harness) leaves that
#       python3 no parent of any reader (2026-10-17)
#   (4c) the ssh-agent socket's readers: ssh-add (started by python3) reaches
#       it; a printer or a relay listed there (nc, socat, ncat; plan 13 D8,
#       leftover (3b) of !437, 2026-10-03) reaches it from no parent, nor
#       does a versioned perl (perl5.X.Y: the guard knows it by its content
#       and asks the arbiter what it is, 2026-10-03; since 2026-10-04 its
#       name, without the version, is perl's too)
# SKIPs where bwrap / user namespaces / nc / the built guard are unavailable;
# the socket legs (4c) and (16) where ssh-add (openssh-client) is.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { echo "  ok — $1"; PASS=$((PASS+1)); }
bad() { echo "  NOT OK — $1"; FAIL=$((FAIL+1)); }
skip() { echo "secret-readers-live.test.sh: SKIP ($1)"; echo "1 skipped, 0 failed"; exit 0; }
# A broken run, not a missing prerequisite (the dev arbiter did not come up,
# or refused the setup calls): FAIL with why and, given a log, its last
# lines; never SKIP, or a suite that went quiet shows green
# (scripts/lib/ready-deadline.sh).
# shellcheck source=scripts/lib/ready-deadline.sh
. "$REPO/scripts/lib/ready-deadline.sh"
abort() { echo "  NOT OK — $1"; if [[ -n "${2:-}" ]]; then mdu_log_tail "$2"; fi; echo "secret-readers-live.test.sh: $PASS passed, $((FAIL + 1)) failed"; exit 1; }
# await_grep <grep args...>: grep until it matches, for up to 30 s. The arbiter
# logs and emits asynchronously; a fixed 0.3-0.5 s sleep missed it under CI
# load (continuous-integration.md §11, 2026-09-29). Returns grep's last status.
await_grep() { local i; for i in $(seq 1 300); do grep "$@" && return 0; sleep 0.1; done; grep "$@"; }
command -v bwrap >/dev/null 2>&1 || skip "bwrap not installed"
command -v nc >/dev/null 2>&1 || skip "nc not installed"
command -v curl >/dev/null 2>&1 || skip "curl not installed (a printer the test lists)"
# The reader of the identity steps (the header): GNU sha256sum, never the
# uutils multi-call binary (a printer by path).
SUM_APP=""; SUM_BIN=""
for c in gnusha256sum sha256sum; do
  p="$(command -v "$c" 2>/dev/null)" || continue
  r="$(readlink -f "$p")"
  case "$r" in /usr/lib/cargo/*|*/busybox|*/toybox|*/coreutils) continue ;; esac
  SUM_APP="$c"; SUM_BIN="$r"; break
done
[[ -n "$SUM_APP" ]] || skip "no GNU sha256sum (the reader)"
SUM_BASE="$(basename "$SUM_BIN")"
command -v cc >/dev/null 2>&1 || skip "no C compiler (cc) to build the pinned holder"
unshare --user --map-root-user --mount -- true >/dev/null 2>&1 || skip "unprivileged user namespaces unavailable"
GUARD="$REPO/interceptors/target/release/mandu-net-guard"
[[ -x "$GUARD" ]] || GUARD="$REPO/interceptors/target/debug/mandu-net-guard"
[[ -x "$GUARD" ]] || skip "mandu-net-guard is not built (cargo build --release -p net-supervisor --features kernel)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-readers.XXXXXX")"
cleanup() { for p in ${SRV:-} ${SRV2:-}; do kill "$p" 2>/dev/null; done; "$REPO/scripts/dev-arbiter.sh" stop "$WORK/arb" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
# The runtime base (the instance registry, the human-plane socket): the
# suite's own, never the caller's $XDG_RUNTIME_DIR/mandu, also when the suite
# is killed; the lifeline (lib/lifeline.sh) ends the dev arbiter then, since
# `mandu reap` cannot see a registry here (test-organization.md §8.5).
export MANDU_RUNTIME_DIR="$WORK/rt"
source "$(dirname "${BASH_SOURCE[0]}")/lib/lifeline.sh"
mdu_lifeline_init "$WORK"

HOME_DIR="$WORK/home"; mkdir -p "$HOME_DIR"
PGPASS="$HOME_DIR/.pgpass"; PG_CANARY="PGPASS_LIVE_CANARY_$RANDOM"
printf 'db:5432:prod:app:%s\n' "$PG_CANARY" > "$PGPASS"
ENVF="$HOME_DIR/.env"; ENV_CANARY="DOTENV_LIVE_CANARY_$RANDOM"
printf 'PORT=3000\nAPI_KEY=%s\n' "$ENV_CANARY" > "$ENVF"
KEYF="$HOME_DIR/deploy_key"; KEY_CANARY="LINEAGE_LIVE_CANARY_$RANDOM"
printf -- '-----BEGIN KEY-----\n%s\n' "$KEY_CANARY" > "$KEYF"
WS2="$HOME_DIR/ws"; mkdir -p "$WS2"
WSENV="$WS2/.env"; WS_CANARY="WSENV_LIVE_CANARY_$RANDOM"
printf 'API_KEY=%s\n' "$WS_CANARY" > "$WSENV"
WSAWS="$WS2/aws.env"; AWS_CANARY="WSAWS_LIVE_CANARY_$RANDOM"
printf 'AWS_SECRET_ACCESS_KEY=%s\n' "$AWS_CANARY" > "$WSAWS"
TOFUF="$HOME_DIR/tofu.env"; TOFU_CANARY="TOFU_LIVE_CANARY_$RANDOM"
printf 'TOKEN=%s\n' "$TOFU_CANARY" > "$TOFUF"
# A raw read by the reader shows as the real file's hash (a twin's differs).
sha_of() { sha256sum "$1" | cut -d' ' -f1; }
PG_SHA="$(sha_of "$PGPASS")"; KEY_SHA="$(sha_of "$KEYF")"; TOFU_SHA="$(sha_of "$TOFUF")"
# The holder of the D2 steps, built and pinned by path and hash.
mkdir -p "$WORK/bin"
cc -O2 -o "$WORK/bin/mdu-holder" "$REPO/tests/lib/holder-reader.c" || skip "could not build the pinned holder"
HOLDER="$(readlink -f "$WORK/bin/mdu-holder")"; HSHA="$(sha_of "$HOLDER")"
# (6e) the host's bash copied under another name and pinned by path and hash
# (2026-10-03): byte for byte an installed shell, so it admits nothing.
SHREAL="$(readlink -f /bin/bash)"
cp "$SHREAL" "$WORK/bin/mdu-shcopy"; chmod 755 "$WORK/bin/mdu-shcopy"
SHCOPY="$(readlink -f "$WORK/bin/mdu-shcopy")"; SHSHA="$(sha_of "$SHCOPY")"
# (6f) a python build no installed program's hash matches (a pyenv or
# self-built python; here the host's with a byte appended, which still
# runs), renamed and pinned by path and hash: the guard knows it by its
# content (2026-10-03). Absent python3: a placeholder pin, the leg skipped.
PYCOPY="$WORK/bin/mdu-pycopy"; PYSHA="$(printf 'no python3' | sha256sum | cut -d' ' -f1)"
if PYREAL="$(readlink -f "$(command -v python3 2>/dev/null)")" && [[ -f "$PYREAL" ]]; then
  cp "$PYREAL" "$PYCOPY"; printf '\0' >> "$PYCOPY"; chmod 755 "$PYCOPY"
  PYCOPY="$(readlink -f "$PYCOPY")"; PYSHA="$(sha_of "$PYCOPY")"
fi
# (6g) the same for an interpreter of the families !506 left out (2026-10-04):
# EVERY one of these the host has (one per binary: `ksh` is often ksh93), a
# byte appended, renamed mdu-rtcopy-N and pinned by path and hash, with inline
# code that opens the file in the interpreter's own process. The CI image
# carries mksh (with lksh) and yash on both guests, and luajit
# (continuous-integration.md §4): the pdksh line, whose own marker must win
# over the ash family's shared `set -o` header; a shell no other marker
# names; an interpreter whose front end links its runtime. Absent every one:
# no pin, the leg skipped (and said so).
RT_NAMES=(); RT_LABELS=(); RT_FAMS=(); RT_COPIES=(); RT_READERS=""
rt_code() { # <cand>: the inline code that opens .env, into RTCODE
  case "$1" in
    ksh93|ksh|mksh|lksh|yash|posh) RTCODE=(-c 'IFS= read -r l < "$1"; printf "%s\n" "$l"' mdu "$WSENV") ;;
    fish) RTCODE=(-c 'read -l l < $argv[1]; echo $l' "$WSENV") ;;
    luajit) RTCODE=(-e "io.write(io.open('$WSENV'):read('*a'))") ;;
  esac
}
RT_SEEN=" "
for cand in ksh93 ksh mksh lksh yash posh fish luajit; do
  RTREAL="$(readlink -f "$(command -v "$cand" 2>/dev/null)" 2>/dev/null)" && [[ -f "$RTREAL" ]] || continue
  [[ "$(head -c4 "$RTREAL" | od -An -c | tr -d ' ')" == '177ELF' ]] || continue   # a wrapper script: not this leg's
  [[ "$RT_SEEN" == *" $RTREAL "* ]] && continue
  RT_SEEN+="$RTREAL "
  # the family the guard must name, by the binary's own name
  case "$(basename "$RTREAL")" in
    ksh93*|ksh2020*|ksh) fam=ksh ;; mksh*|lksh*) fam=mksh ;; *) fam="$cand" ;;
  esac
  i=$(( ${#RT_NAMES[@]} + 1 ))
  c="$WORK/bin/mdu-rtcopy-$i"
  cp "$RTREAL" "$c"; printf '\0' >> "$c"; chmod 755 "$c"; c="$(readlink -f "$c")"
  RT_NAMES+=("$cand"); RT_FAMS+=("$fam"); RT_COPIES+=("$c")
  [[ "$(basename "$RTREAL")" == "$cand" ]] && RT_LABELS+=("$cand") || RT_LABELS+=("$cand ($(basename "$RTREAL"))")
  RT_READERS+="{ app: mdu-rtcopy-$i, path: $c, sha256: $(sha_of "$c") }, "
done
# (6h) P0 item 14 (2026-10-07): a GNU printer no installed program's hash
# matches (another version or a static build: here the host's GNU cat with
# a byte appended), renamed and pinned with the human's `prints: nothing`:
# the guard knows it by its package's own text (`pkg:coreutils`). Absent a
# GNU cat (uutils' is a printer by its path): a placeholder pin, the leg
# skipped.
CATCOPY="$WORK/bin/mdu-catbuild"; CATSHA="$(printf 'no GNU cat' | sha256sum | cut -d' ' -f1)"
for c in gnucat cat; do
  CATREAL="$(readlink -f "$(command -v "$c" 2>/dev/null)" 2>/dev/null)" && [[ -f "$CATREAL" ]] || continue
  case "$CATREAL" in /usr/lib/cargo/*|*/busybox|*/toybox) continue ;; esac
  grep -qaF 'GNU coreutils' "$CATREAL" || continue
  cp "$CATREAL" "$CATCOPY"; printf '\0' >> "$CATCOPY"; chmod 755 "$CATCOPY"
  CATCOPY="$(readlink -f "$CATCOPY")"; CATSHA="$(sha_of "$CATCOPY")"
  break
done
# (6i) P0 item 14: a disguised interpreter of a family known by name only
# until then: the pinned holder with the .NET muxer's usage line appended
# (an ELF runs with data after it), renamed and pinned with `prints:
# nothing`. The guard finds the muxer's front end (`runs:dotnet`); the same
# holder without it is the listed reader the steps above use.
MUXCOPY="$WORK/bin/mdu-muxer"
cp "$HOLDER" "$MUXCOPY"; printf '\0Usage: dotnet [path-to-application]\0' >> "$MUXCOPY"; chmod 755 "$MUXCOPY"
MUXCOPY="$(readlink -f "$MUXCOPY")"; MUXSHA="$(sha_of "$MUXCOPY")"
# (4c) a byte-identical, versioned perl the distribution installs (Debian's
# /usr/bin/perl5.X.Y, a hard link of perl): its name was on no list, so the
# socket's list, judged by name, let it connect (until 2026-10-04 the name
# rule took no version off). Absent: the leg is skipped.
PERLV=""
for p in /usr/bin/perl5.*; do
  [[ "$(basename "$p")" =~ ^perl5\.[0-9]+\.[0-9]+$ && -x "$p" ]] || continue
  [[ -x /usr/bin/perl && "$(sha_of "$p")" == "$(sha_of /usr/bin/perl)" ]] && { PERLV="$p"; break; }
done
PERLV_NAME="$(basename "${PERLV:-/mdu-no-versioned-perl}")"
cat > "$WORK/policy.yaml" <<YAML
version: 1
paths:
  - path: $PGPASS
    level: no-model
    readers: [{ app: $SUM_BASE, prints: nothing }]
  - path: $WSENV
    level: no-model
    readers: [curl, cat, sh, dash, bash, { app: mdu-shcopy, path: $SHCOPY, sha256: $SHSHA }, { app: mdu-pycopy, path: $PYCOPY, sha256: $PYSHA }, $RT_READERS{ app: mdu-catbuild, path: $CATCOPY, sha256: $CATSHA, prints: nothing }, { app: mdu-muxer, path: $MUXCOPY, sha256: $MUXSHA, prints: nothing }, { app: mdu-holder, path: $HOLDER, sha256: $HSHA, prints: nothing }]   # curl and cat (printers, plan 13 D8), the shells (plan 13 §8 decision (b)), a renamed copy of bash, interpreters no hash knows and a GNU printer by its package admit nothing: (6b)-(6i)
    bindings: ["127.0.0.2", "unix:$WORK/sock-bound"]
  - path: $WSAWS
    level: no-model
    readers: [{ app: mdu-holder, path: $HOLDER, sha256: $HSHA, prints: nothing }]
    bindings: ["127.0.0.3"]
  - path: $KEYF
    level: no-model
    readers:
      - app: $SUM_BASE
        from: python3
        prints: nothing
    others: deny
  - path: $TOFUF
    level: no-model
    readers: [{ app: $SUM_BASE, prints: nothing }]
YAML

mkdir -p "$WORK/arb"
# dev-arbiter.sh waits for both sockets on the shared readiness budget; a
# start that does not come up makes it say why, with its log's last lines,
# and exit non-zero: that FAILS this suite, never SKIPs it.
arb_env="$(MANDU_MODE=secrets MANDU_TENANT=test MANDU_POLICY_FILE="$WORK/policy.yaml" MANDU_LIFELINE_FIFO="$MANDU_LIFELINE_FIFO" "$REPO/scripts/dev-arbiter.sh" "$WORK/arb")" \
  || abort "the dev arbiter did not come up (dev-arbiter.sh exited $?; why and its log's last lines are above)"
eval "$(printf '%s\n' "$arb_env" | grep '^export ')"
SOCK="$MANDU_ARBITER_SOCK"
[[ -S "$SOCK" ]] || abort "dev-arbiter.sh reported up but $SOCK is no socket" "$WORK/arb/arbiter.log"
call() { printf '%s\n' "$1" | timeout 10 nc -U -q1 "$SOCK" 2>/dev/null | head -1; }
json_field() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);const v=(j.result||{})[process.argv[1]];process.stdout.write(v==null?"":String(v))})' "$1"; }
# The arbiter's human-plane socket, from `hello`: the model proxy asks
# callTaint there, the only channel a call is bound from (plan 13 D9; the
# guard finds it the same way and reports there).
HSOCK="$(call '{"id":0,"op":"hello"}' | json_field humanSock)"
[[ -S "$HSOCK" ]] || abort "the dev arbiter serves no human-plane socket" "$WORK/arb/arbiter.log"
hcall() { printf '%s\n' "$1" | timeout 10 nc -U -q1 "$HSOCK" 2>/dev/null | head -1; }

mkdir -p "$WORK/twins"
register() { # path twinfile
  local reg; reg="$(call "{\"id\":1,\"op\":\"registerSecret\",\"path\":\"$1\"}")"
  local twin; twin="$(printf '%s' "$reg" | json_field twin)"
  local sym; sym="$(printf '%s' "$reg" | json_field symbol)"
  [[ -n "$sym" ]] || { echo "$reg"; abort "the arbiter refused registerSecret" "$WORK/arb/arbiter.log"; }
  if [[ -n "$twin" ]]; then printf '%s' "$twin" > "$2"; else printf '%s\n' "$sym" > "$2"; fi
}
register "$PGPASS" "$WORK/twins/pgpass"
register "$ENVF" "$WORK/twins/env"
register "$WSENV" "$WORK/twins/wsenv"
register "$KEYF" "$WORK/twins/key"
register "$WSAWS" "$WORK/twins/wsaws"
register "$TOFUF" "$WORK/twins/tofu"
cat > "$WORK/secret-policy.json" <<JSON
{"agentExe":"","ask":"never","session":"readers-live","unixDeny":["$WORK/rt/human"],"secrets":[
  {"path":"$PGPASS","twin":"$WORK/twins/pgpass","level":"no-model"},
  {"path":"$ENVF","twin":"$WORK/twins/env","level":"no-model"},
  {"path":"$WSENV","twin":"$WORK/twins/wsenv","level":"no-model"},
  {"path":"$KEYF","twin":"$WORK/twins/key","level":"no-model"},
  {"path":"$WSAWS","twin":"$WORK/twins/wsaws","level":"no-model"},
  {"path":"$TOFUF","twin":"$WORK/twins/tofu","level":"no-model"}],
 "sockets":[{"path":"$WORK/agent.sock","label":"ssh-agent","readers":[{"app":"ssh-add","from":"python3"},"nc",{"app":"socat","from":"python3"},{"app":"ncat","from":"python3"},"$PERLV_NAME"]}],
 "protect":["$HOME_DIR/Documents"]}
JSON

mkdir -p "$HOME_DIR/Documents" "$HOME_DIR/scratch"
echo keep > "$HOME_DIR/Documents/tax.pdf"; echo drop > "$HOME_DIR/scratch/tmp.txt"
export MANDU_NET_GUARD_PROTECT=1
G=(mdu_without_lifeline "$GUARD" --allow "127.0.0.0/8:*" --)  # never holds the lifeline (lib/lifeline.sh)
BW=(bwrap --dev-bind / / --die-with-parent --cap-drop ALL --unshare-ipc --unshare-uts --bind "$WORK/twins/pgpass" "$PGPASS" --bind "$WORK/twins/env" "$ENVF" --)
export MANDU_ARBITER_SOCK="$SOCK" MANDU_NET_GUARD_SECRETS="$WORK/secret-policy.json"
# The reader's read of a file: its hash. Plan 13 D8: cat, the reader until
# 2026-10-03, and curl, the next one, are printers and admit nothing.
rd() { printf "%s '%s'" "$SUM_APP" "$1"; }

# (1) the listed reader gets the REAL bytes, through the bind
OUT="$("${G[@]}" "${BW[@]}" /bin/sh -c "$(rd "$PGPASS")" 2>&1)"
[[ "$OUT" == *"$PG_SHA"* ]] && ok "listed reader ($SUM_BASE) reads the REAL .pgpass through the twin bind (ADDFD of the real file)" || bad "$SUM_BASE got: $OUT"

# (2) a program not on the list: EACCES
OUT="$("${G[@]}" "${BW[@]}" /bin/sh -c "head -c 200 '$PGPASS'" 2>&1)"
[[ "$OUT" == *"ermission denied"* && "$OUT" != *"$PG_CANARY"* ]] && ok "a non-reader (head) gets EACCES: the list is exhaustive" || bad "head got: $OUT"

# (3) no reader list: the structured twin for everyone, and it sources
OUT="$("${G[@]}" "${BW[@]}" /bin/sh -c "cat '$ENVF'; cd '$HOME_DIR' && . ./.env && echo \"port=\$PORT key=\$API_KEY\"" 2>&1)"
[[ "$OUT" == *"API_KEY='\$MDU:nomodel_Read["* && "$OUT" == *"port=3000 key=\$MDU:nomodel_Read["* && "$OUT" != *"$ENV_CANARY"* ]] \
  && ok "no reader list: cat and a sourcing shell both see the structured twin" || bad "env got: $OUT"

# (4) the gated shape: NO bind at all, the guard alone serves the twin / raw / deny
OUT="$("${G[@]}" /bin/sh -c "cat '$ENVF'" 2>&1)"
[[ "$OUT" == *"API_KEY='\$MDU:nomodel_Read["* && "$OUT" != *"$ENV_CANARY"* ]] && ok "without any bind the guard injects the TWIN descriptor (§11.7: gated hosts get confined)" || bad "unbound cat .env got: $OUT"
OUT="$("${G[@]}" /bin/sh -c "$(rd "$PGPASS")" 2>&1)"
[[ "$OUT" == *"$PG_SHA"* ]] && ok "without a bind the listed reader still gets raw" || bad "unbound $SUM_BASE .pgpass got: $OUT"
OUT="$("${G[@]}" /bin/sh -c "head -c 200 '$PGPASS'" 2>&1)"
[[ "$OUT" == *"ermission denied"* ]] && ok "without a bind a non-reader is still denied" || bad "unbound head got: $OUT"

# (4e) another name for a registered file: a hard link, or a different-case
#      spelling on a filesystem that folds case (WSL drvfs over a Windows
#      profile; a hard link stands in here: one inode, another spelling). The
#      path map and the twin bind (a mount on one dentry) miss both; the guard
#      knows the file by its inode.
ln "$ENVF" "$HOME_DIR/.ENV"; ln "$PGPASS" "$HOME_DIR/innocent"
OUT="$("${G[@]}" "${BW[@]}" /bin/sh -c "cat '$HOME_DIR/.ENV'" 2>&1)"
[[ "$OUT" == *"API_KEY='\$MDU:nomodel_Read["* && "$OUT" != *"$ENV_CANARY"* ]] && ok "a different-case spelling of a twinned file still gets the twin (the guard matches the inode)" || bad ".ENV got: $OUT"
OUT="$("${G[@]}" /bin/sh -c "head -c 200 '$HOME_DIR/innocent'" 2>&1)"
[[ "$OUT" == *"ermission denied"* && "$OUT" != *"$PG_CANARY"* ]] && ok "a hard link under another name is the same secret: a non-reader is denied" || bad "head of the hard link got: $OUT"
OUT="$("${G[@]}" /bin/sh -c "$(rd "$HOME_DIR/innocent")" 2>&1)"
[[ "$OUT" == *"$PG_SHA"* ]] && ok "and its listed reader still reads it" || bad "$SUM_BASE of the hard link got: $OUT"
rm -f "$HOME_DIR/.ENV" "$HOME_DIR/innocent"

# (4f) the CONTINUE race (plan 10 §4.1a): another thread rewrites the path
#      buffer between the guard's read and the kernel's, from a decoy to the
#      secret. The guard performs the open itself, once, so the real bytes
#      never come back; the twin does (the race reached the secret's path).
if command -v python3 >/dev/null 2>&1; then
  printf 'DECOY=1\n' > "$HOME_DIR/.enx"
  cat > "$WORK/race.py" <<'PY'
import ctypes, os, sys, threading
libc = ctypes.CDLL(None, use_errno=True)
a, b = sys.argv[1].encode(), sys.argv[2].encode()
assert len(a) == len(b)
buf = ctypes.create_string_buffer(a, len(a) + 1)
stop = [False]
def flip():
    while not stop[0]:
        ctypes.memmove(buf, b, len(b)); ctypes.memmove(buf, a, len(a))
threading.Thread(target=flip, daemon=True).start()
out = ctypes.create_string_buffer(256)
counts = {"real": 0, "twin": 0, "decoy": 0, "other": 0}
for _ in range(3000):
    fd = libc.open(buf, os.O_RDONLY)
    if fd < 0:
        counts["other"] += 1
        continue
    n = libc.read(fd, out, 255); libc.close(fd)
    s = out.raw[:max(n, 0)]
    k = "real" if sys.argv[3].encode() in s else "twin" if b"$MDU:" in s else "decoy" if b"DECOY" in s else "other"
    counts[k] += 1
stop[0] = True
print("RACE real=%(real)d twin=%(twin)d decoy=%(decoy)d other=%(other)d" % counts)
PY
  OUT="$("${G[@]}" python3 "$WORK/race.py" "$HOME_DIR/.enx" "$ENVF" "$ENV_CANARY" 2>&1 | grep '^RACE')"
  echo "    $OUT"
  [[ "$OUT" == "RACE real=0 twin="* && "$OUT" != *"twin=0 "* ]] \
    && ok "a path rewritten mid-open by another thread never reads the real file (the guard opens once; twins served)" \
    || bad "the rewritten-path race: $OUT"
  rm -f "$HOME_DIR/.enx"
fi

# (4g) every descriptor of a labelled file names ONE path, and under the bind
#      that path is the file's own, never Mandu's twin file
#      (differential-interactive.md §20). Bun, Claude Code's runtime, resolves
#      a path with an O_PATH open + readlink of /proc/self/fd/N (the permission
#      dialog offered "allow access to <scope>/secret-twins" while the guard
#      opened the twin by its own path), and Claude's Read tool refuses a file
#      whose read descriptor names another path than the one it checked.
#      Without a bind (the guard alone) both name the twin. Reads are the twin.
if command -v python3 >/dev/null 2>&1; then
  cat > "$WORK/opath.py" <<'PY'
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_PATH)
print("NAMED " + os.readlink("/proc/self/fd/%d" % fd))
r = os.open("/proc/self/fd/%d" % fd, os.O_RDONLY)
print("REOPEN " + os.read(r, 256).decode(errors="replace").replace("\n", " "))
f = os.open(sys.argv[1], os.O_RDONLY)
print("READNAMED " + os.readlink("/proc/self/fd/%d" % f))
print("READ " + os.read(f, 256).decode(errors="replace").replace("\n", " "))
PY
  for shape in bind guard-only; do
    if [[ "$shape" == bind ]]; then OUT="$("${G[@]}" "${BW[@]}" python3 "$WORK/opath.py" "$ENVF" 2>&1)"; else OUT="$("${G[@]}" python3 "$WORK/opath.py" "$ENVF" 2>&1)"; fi
    NAMED="$(printf '%s\n' "$OUT" | sed -n 's/^NAMED //p')"; READNAMED="$(printf '%s\n' "$OUT" | sed -n 's/^READNAMED //p')"
    [[ -n "$NAMED" && "$NAMED" == "$READNAMED" ]] \
      && ok "$shape: the O_PATH and the read descriptor of the labelled file name one path ($NAMED)" || bad "$shape naming differs: $OUT"
    if [[ "$shape" == bind ]]; then
      [[ "$NAMED" == "$ENVF" && "$OUT" != *"$WORK/twins"* ]] \
        && ok "bind: that path is the file's own, never the twin dir" || bad "bind naming: $OUT"
    fi
    [[ "$(printf '%s\n' "$OUT" | grep '^REOPEN ')" == *"API_KEY='\$MDU:nomodel_Read["* \
       && "$(printf '%s\n' "$OUT" | grep '^READ ')" == *"API_KEY='\$MDU:nomodel_Read["* && "$OUT" != *"$ENV_CANARY"* ]] \
      && ok "$shape: a read, and a re-open of the O_PATH descriptor, get the twin" || bad "$shape reads: $OUT"
  done
fi

# (4b) a lineage-conditional reader (learn-from-nono §3.5: readers [{app:
#      sha256sum, from: python3}]): the guard reports the opener's ancestry,
#      so the reader started by python3 reads raw and the same reader started
#      by sh is refused.
if command -v python3 >/dev/null 2>&1; then
  OUT="$("${G[@]}" python3 -c "import subprocess,sys; sys.stdout.write(subprocess.run(['$SUM_APP','$KEYF'],capture_output=True,text=True).stdout)" 2>&1)"
  [[ "$OUT" == *"$KEY_SHA"* ]] && ok "from: python3, $SUM_BASE started by python3 reads the key raw" || bad "python3's $SUM_BASE got: $OUT"
  OUT="$("${G[@]}" /bin/sh -c "$(rd "$KEYF"); echo rc=\$?" 2>&1)"
  [[ "$OUT" != *"rc=0"* && "$OUT" != *"$KEY_SHA"* ]] && ok "from: python3, the same $SUM_BASE started by sh is refused (others: deny)" || bad "sh's $SUM_BASE got: $OUT"
fi

# (4c) a secret SOCKET (the ssh-agent, learn-from-nono §3.5): only its
#      readers connect; here ssh-add started by python3, and ssh-add started
#      by sh is refused. Plan 13 D8, printers admit nothing (leftover (3b) of
#      !437, 2026-10-03): nc listed bare, socat and ncat listed under
#      python3 relay the agent to whatever drives them, so none connects,
#      from any parent (before, the listed nc and socat did). The stub agent
#      logs each connection it accepts (the oracle: no accept, no use) and
#      answers SSH_AGENT_IDENTITIES_ANSWER with no keys.
# agent_stub <socket> <log>: a stub ssh-agent in the background ($!). Like a
# real agent it reads the whole request (length-prefixed) before it answers.
# Until 2026-10-04 it answered after ONE recv and closed: ssh-add writes the
# 4-byte length and the body separately, so when the first recv returned
# the length alone (on a loaded host), ssh-add's second write met a closed
# connection and ssh-add died of SIGPIPE with no output, which read as a
# refusal (an intermittent NOT OK in steps (4c) and (16)). The alarm only
# reaps a stub the test failed to kill.
agent_stub() {
  python3 -c "import socket,os,sys
s=socket.socket(socket.AF_UNIX); p='$1'
s.bind(p); s.listen(8)
import signal; signal.alarm(300)
def readn(c, n):
  b = b''
  while len(b) < n:
    d = c.recv(n - len(b))
    if not d: break
    b += d
  return b
while True:
  c,_=s.accept()
  with open('$2','a') as f: f.write('accept\\n')
  c.settimeout(60)
  try:
    h = readn(c, 4)
    if len(h) == 4: readn(c, int.from_bytes(h, 'big'))
    c.sendall(b'\\x00\\x00\\x00\\x05\\x0c\\x00\\x00\\x00\\x00')
  except Exception: pass
  c.close()" &
}
accepts() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }
# py_run <argv as a python list>: run it from python3 under the guard, with
# SSH_AUTH_SOCK at the stub; prints its output, and the signal that killed
# the program if one did (an empty output would read as a refusal). The
# program's deadline is generous: a loaded host is slow, not wrong.
py_run() { "${G[@]}" python3 -c "import subprocess,sys,os; r=subprocess.run($1,input='',capture_output=True,text=True,timeout=30,env=dict(os.environ,SSH_AUTH_SOCK='$2')); sys.stdout.write(r.stdout+r.stderr+(' [killed by signal %d]' % -r.returncode if r.returncode < 0 else ''))" 2>&1; }
if command -v python3 >/dev/null 2>&1 && command -v ssh-add >/dev/null 2>&1; then
  ALOG="$WORK/agent.log"
  agent_stub "$WORK/agent.sock" "$ALOG"
  SRV=$!
  for _ in $(seq 1 50); do [[ -S "$WORK/agent.sock" ]] && break; sleep 0.1; done
  OUT="$(py_run "['ssh-add','-l']" "$WORK/agent.sock")"
  [[ "$OUT" == *"no identities"* && "$(accepts "$ALOG")" == 1 ]] && ok "secret socket: ssh-add started by python3 (its reader) reaches the agent" || bad "python3's ssh-add got ($(accepts "$ALOG") accepts): $OUT"
  OUT="$("${G[@]}" /bin/sh -c "SSH_AUTH_SOCK='$WORK/agent.sock' timeout 5 ssh-add -l </dev/null; true" 2>&1)"
  [[ "$OUT" != *"no identities"* && "$(accepts "$ALOG")" == 1 ]] && ok "secret socket: the same ssh-add started by sh is refused" || bad "sh's ssh-add got ($(accepts "$ALOG") accepts): $OUT"
  OUT="$(py_run "['nc','-U','-q1','$WORK/agent.sock']" "$WORK/agent.sock")"
  [[ "$(accepts "$ALOG")" == 1 ]] && ok "secret socket: nc listed bare, started by python3, is refused (a relay admits nothing)" || bad "the listed nc reached the agent: $OUT"
  OUT="$("${G[@]}" /bin/sh -c "timeout 5 nc -U -q1 '$WORK/agent.sock' </dev/null; true" 2>&1)"
  [[ "$(accepts "$ALOG")" == 1 ]] && ok "secret socket: the listed nc started by sh is refused" || bad "sh's nc reached the agent: $OUT"
  if command -v socat >/dev/null 2>&1; then
    OUT="$(py_run "['socat','-','UNIX-CONNECT:$WORK/agent.sock']" "$WORK/agent.sock")"
    [[ "$(accepts "$ALOG")" == 1 ]] && ok "secret socket: socat listed under python3, started by python3, is refused (a printer admits nothing)" || bad "the listed socat reached the agent: $OUT"
  else
    echo "  skip — (4c) no socat on this host (the CI image has it)"
  fi
  if command -v ncat >/dev/null 2>&1; then
    OUT="$(py_run "['ncat','-U','$WORK/agent.sock']" "$WORK/agent.sock")"
    [[ "$(accepts "$ALOG")" == 1 ]] && ok "secret socket: ncat listed under python3 is refused (it runs code: --sh-exec)" || bad "the listed ncat reached the agent: $OUT"
  else
    echo "  skip — (4c) no ncat on this host"
  fi
  # 2026-10-03: the socket's list was judged by name only, so perl5.X.Y
  # (byte for byte perl, a name on no list) listed there connected and ran
  # the agent's code with the human's keys. Now the guard knows it by its
  # content (`runs:perl`) and asks the arbiter what the binary is (by the
  # host's program hashes): refused.
  if [[ -n "$PERLV" ]]; then
    printf '%s\n' 'use IO::Socket::UNIX; my $s = IO::Socket::UNIX->new(Peer => $ARGV[0]) or exit 3; print $s "\0\0\0\1\13"; sleep 1; exit 0;' > "$WORK/conn.pl"
    OUT="$(py_run "['$PERLV','$WORK/conn.pl','$WORK/agent.sock']" "$WORK/agent.sock")"
    [[ "$(accepts "$ALOG")" == 1 ]] && ok "secret socket: $PERLV_NAME (byte for byte perl, a name on no list) listed there is refused" || bad "the listed $PERLV_NAME reached the agent ($(accepts "$ALOG") accepts): $OUT"
  else
    echo "  skip — (4c) no versioned perl (perl5.X.Y) on this host"
  fi
  kill "$SRV" 2>/dev/null; SRV=
else
  echo "  skip — (4c) the secret socket legs need python3 and ssh-add (openssh-client)"
fi

# (4d) protect: (learn-from-nono §4 item 8): a delete or rename of a
#      protected path, or of its ancestor, is refused; elsewhere deletes work.
OUT="$("${G[@]}" /bin/sh -c "rm -f '$HOME_DIR/Documents/tax.pdf'; mv '$HOME_DIR/Documents' '$HOME_DIR/Docs2'; rm -f '$HOME_DIR/scratch/tmp.txt'; true" 2>&1)"
[[ -f "$HOME_DIR/Documents/tax.pdf" ]] && ok "protect: rm of a file in a protected folder is refused (the file is still there)" || bad "protected file removed: $OUT"
[[ -d "$HOME_DIR/Documents" && ! -e "$HOME_DIR/Docs2" ]] && ok "protect: renaming the protected folder away is refused" || bad "protected folder renamed: $OUT"
[[ ! -e "$HOME_DIR/scratch/tmp.txt" ]] && ok "protect: a delete outside the protected paths still works" || bad "unprotected delete failed: $OUT"
# another spelling of the protected folder (a case-folding filesystem, WSL
# drvfs; a bind in the program's own mount namespace stands in: one folder,
# another path) is refused by identity, which the path compare misses
if unshare --user --map-root-user --mount -- true >/dev/null 2>&1; then
  mkdir -p "$HOME_DIR/alias"
  OUT="$("${G[@]}" unshare --user --map-root-user --mount -- /bin/sh -c "mount --bind '$HOME_DIR/Documents' '$HOME_DIR/alias' && rm -f '$HOME_DIR/alias/tax.pdf'; true" 2>&1)"
  [[ -f "$HOME_DIR/Documents/tax.pdf" ]] && ok "protect: a delete through another spelling of the protected folder is refused (by identity)" || bad "protected file removed through the alias: $OUT"
fi

# (4h) an in-place edit, a move onto, or a delete of a registered file, the
#      guard alone (no bind; write-protection.md, the name family,
#      2026-10-02): `sed -i` reads the twin and renames its temp file OVER the
#      real path; that rename, an `mv` onto it and an `rm` of it are refused
#      (EACCES), so the real credential is never replaced by its placeholder
#      or lost. An ordinary file still takes the same commands (`plain.txt`:
#      a `*.env` name is a catalog file the guard gates at the open since
#      2026-10-17, confidentiality.md §6).
printf 'PORT=1\n' > "$HOME_DIR/scratch/plain.txt"
OUT="$("${G[@]}" /bin/sh -c "sed -i 's/PORT/PORTX/' '$ENVF'; echo sed=\$?; printf 'X\n' > '$HOME_DIR/scratch/new'; mv -f '$HOME_DIR/scratch/new' '$ENVF'; echo mv=\$?; rm -f '$ENVF'; echo rm=\$?; sed -i 's/PORT/PORTX/' '$HOME_DIR/scratch/plain.txt'; echo plain=\$?" 2>&1)"
[[ "$OUT" == *"sed="[1-9]* && "$OUT" == *"mv="[1-9]* && "$OUT" == *"rm="[1-9]* ]] \
  && ok "guard-only: sed -i, mv onto and rm of a registered file are refused" || bad "in-place edit / move / delete of .env: $OUT"
grep -q "$ENV_CANARY" "$ENVF" && ! grep -q PORTX "$ENVF" \
  && ok "guard-only: the real .env still holds its secret (not replaced by the placeholder)" || bad "the real .env changed: $(head -c 200 "$ENVF" | sed 's/[A-Z_]*CANARY_[0-9]*/<canary>/g')"
[[ "$OUT" == *"plain=0"* ]] && grep -q PORTX "$HOME_DIR/scratch/plain.txt" \
  && ok "guard-only: sed -i of an ordinary file still works" || bad "sed -i of an ordinary file: $OUT"
rm -f "$HOME_DIR"/sed* "$HOME_DIR/scratch/new" "$HOME_DIR/scratch/plain.txt"

# the real files are intact
grep -q "$PG_CANARY" "$PGPASS" && grep -q "$ENV_CANARY" "$ENVF" && ok "the real files are intact" || bad "a real file changed"

# (5) the arbiter recorded the reader's taint before answering
if await_grep -q "decideSecretOpen: $PGPASS by .*/$SUM_BASE .* → raw" "$WORK/arb/arbiter.log"; then ok "the arbiter decided raw for $SUM_BASE and recorded its taint (log)"; else bad "no raw decision in the arbiter log: $(grep decideSecretOpen "$WORK/arb/arbiter.log" | tail -3)"; fi
await_grep -q "decideSecretOpen: $PGPASS by .*/head .* → deny" "$WORK/arb/arbiter.log" && ok "the arbiter decided deny for head" || bad "no deny decision logged"

# (6) the guard reported the execs: a tool call is matched to its tree by command signature
#     (asked as the model proxy asks, on the human socket)
CT="$(hcall "{\"id\":9,\"op\":\"callTaint\",\"callId\":\"toolu_live_sum\",\"command\":\"$SUM_APP '$PGPASS'\",\"session\":\"readers-live\"}")"
[[ "$CT" == *'"level":"no-model"'* && "$CT" == *"\"apps\":[\"$SUM_BASE\"]"* ]] \
  && ok "callTaint by command signature finds the reader's taint (level no-model, app $SUM_BASE)" \
  || bad "callTaint for $SUM_BASE: $CT"
CT2="$(hcall "{\"id\":10,\"op\":\"callTaint\",\"callId\":\"toolu_live_head\",\"command\":\"head -c 200 '$PGPASS'\",\"session\":\"readers-live\"}")"
# Plan 13 D7: this run names no agent (agentExe ""), so the call-root recorder
# binds no call; the session holds the reader's raw read, so the denied head's call is
# masked at the session's level (fail-closed) and its denial still rides along.
[[ "$CT2" == *'"level":"no-model"'* && "$CT2" == *'"evidence":"session"'* && "$CT2" == *'"app":"head"'* ]] \
  && ok "callTaint for the denied head: no agent named, so no tree is bound; masked at the session's level, the denial shown" \
  || bad "callTaint for head: $CT2"

# (6b) plan 13 §8 decision (b): a shell listed as a reader admits nothing; its
#      inline code (`. .env`, the pattern these steps used before) gets no byte
for SH in /bin/sh /bin/bash; do
  # (in a subshell: dash leaves on a `.` it cannot read)
  OUT="$("${G[@]}" "$SH" -c "( . '$WSENV'; echo \"key=\${API_KEY:-none}\" ) 2>&1; echo done" 2>&1)"
  [[ "$OUT" != *"$WS_CANARY"* && "$OUT" == *"done"* ]] \
    && ok "decision (b): $SH sourcing .env, with sh, dash and bash listed as its readers, gets no byte" \
    || bad "decision (b): $SH read the listed .env: $(printf '%s' "$OUT" | sed "s/$WS_CANARY/<KEY>/g" | tail -3)"
done
await_grep -q "decideSecretOpen: $WSENV by .*bash.* → deny (.*pinned script" "$WORK/arb/arbiter.log" \
  && ok "decision (b): the arbiter refused the shell, naming the script pin" || bad "decision (b): no refusal for the shell: $(grep -F "decideSecretOpen: $WSENV" "$WORK/arb/arbiter.log" | tail -3)"
# (6c) plan 13 D8, printers admit nothing (2026-10-03): cat is listed for
#      .env too, and gets no byte (refused: the list is exhaustive)
OUT="$("${G[@]}" /bin/sh -c "cat '$WSENV'; echo rc=\$?" 2>&1)"
[[ "$OUT" != *"$WS_CANARY"* && "$OUT" != *"rc=0"* ]] \
  && ok "printers admit nothing: cat, listed for .env, gets no byte" \
  || bad "printers admit nothing: a listed cat read .env: $(printf '%s' "$OUT" | sed "s/$WS_CANARY/<KEY>/g" | tail -3)"
await_grep -q "decideSecretOpen: $WSENV by .*cat.* → deny (.*prints or copies" "$WORK/arb/arbiter.log" \
  && ok "printers admit nothing: the arbiter refused cat, saying why" || bad "printers admit nothing: no refusal for cat: $(grep -F "decideSecretOpen: $WSENV" "$WORK/arb/arbiter.log" | tail -3)"
# (6d) the !437 leftover (1): curl, listed for .env too, prints any file it
#      is pointed at (`curl file://…`): a printer, it gets no byte
OUT="$("${G[@]}" /bin/sh -c "curl -q -s file://'$WSENV'; echo rc=\$?" 2>&1)"
[[ "$OUT" != *"$WS_CANARY"* && "$OUT" != *"rc=0"* ]] \
  && ok "printers admit nothing: curl, listed for .env, gets no byte through file://" \
  || bad "printers admit nothing: a listed curl read .env: $(printf '%s' "$OUT" | sed "s/$WS_CANARY/<KEY>/g" | tail -3)"
await_grep -q "decideSecretOpen: $WSENV by .*curl.* → deny (.*prints or copies" "$WORK/arb/arbiter.log" \
  && ok "printers admit nothing: the arbiter refused curl, saying why" || bad "printers admit nothing: no refusal for curl: $(grep -F "decideSecretOpen: $WSENV" "$WORK/arb/arbiter.log" | tail -3)"
# (6e) 2026-10-03: a renamed copy of the host's bash, listed for .env by
#      path and hash, is bash (its hash is an installed shell's): sourcing
#      .env gets no byte, and the arbiter says what the copy is
OUT="$("${G[@]}" "$SHCOPY" -c "( . '$WSENV'; echo \"key=\${API_KEY:-none}\" ) 2>&1; echo done" 2>&1)"
[[ "$OUT" != *"$WS_CANARY"* && "$OUT" == *"done"* ]] \
  && ok "a renamed copy of bash, pinned by path and hash for .env, gets no byte" \
  || bad "a pinned copy of bash read the listed .env: $(printf '%s' "$OUT" | sed "s/$WS_CANARY/<KEY>/g" | tail -3)"
await_grep -q "decideSecretOpen: $WSENV by $SHCOPY .* → deny (mdu-shcopy is a copy of " "$WORK/arb/arbiter.log" \
  && ok "the arbiter refused the copy, naming the shell it is a copy of" || bad "no copy refusal: $(grep -F "decideSecretOpen: $WSENV" "$WORK/arb/arbiter.log" | tail -3)"
# (6f) 2026-10-03: a python no installed program's hash matches (the host's
#      with a byte appended: a pyenv or self-built python stands for it),
#      renamed and pinned by path and hash for .env: before, neither its name
#      nor its hash said it runs code, and `mdu-pycopy -c` read the file raw.
#      The guard finds CPython's front end in its content (`runs:python`).
if [[ -x "$PYCOPY" ]]; then
  OUT="$("${G[@]}" "$PYCOPY" -c "import sys; sys.stdout.write(open('$WSENV').read())" 2>&1)"
  [[ "$OUT" != *"$WS_CANARY"* ]] \
    && ok "a python build no hash knows, renamed and pinned by path and hash for .env, gets no byte" \
    || bad "a pinned python build read the listed .env: $(printf '%s' "$OUT" | sed "s/$WS_CANARY/<KEY>/g" | tail -3)"
  await_grep -q "decideSecretOpen: $WSENV by $PYCOPY .* → deny (mdu-pycopy is not the program a human could name: its executable is, by its content, a python interpreter" "$WORK/arb/arbiter.log" \
    && ok "the arbiter refused it on the guard's content finding" || bad "no content refusal: $(grep -F "decideSecretOpen: $WSENV" "$WORK/arb/arbiter.log" | tail -3)"
else
  echo "  skip — (6f) needs python3"
fi
# (6g) 2026-10-04: the same for an interpreter of the families !506 left out
#      (ksh93, mksh, lksh, yash, posh, fish or LuaJIT, every one the host
#      has): before, the guard's table knew none of them by content. The
#      refusal must name the binary's own family, not just some interpreter.
for i in "${!RT_COPIES[@]}"; do
  RTNAME="${RT_LABELS[$i]}"; RTCOPY="${RT_COPIES[$i]}"; RTBASE="$(basename "$RTCOPY")"
  rt_code "${RT_NAMES[$i]}"
  OUT="$("${G[@]}" "$RTCOPY" "${RTCODE[@]}" 2>&1)"
  [[ "$OUT" != *"$WS_CANARY"* ]] \
    && ok "a $RTNAME build no hash knows, renamed and pinned by path and hash for .env, gets no byte" \
    || bad "a pinned $RTNAME build read the listed .env: $(printf '%s' "$OUT" | sed "s/$WS_CANARY/<KEY>/g" | tail -3)"
  await_grep -q "decideSecretOpen: $WSENV by $RTCOPY .* → deny ($RTBASE is not the program a human could name: its executable is, by its content, a ${RT_FAMS[$i]} interpreter" "$WORK/arb/arbiter.log" \
    && ok "the arbiter refused the $RTNAME copy on the guard's content finding (runs:${RT_FAMS[$i]})" || bad "no content refusal for $RTNAME naming ${RT_FAMS[$i]}: $(grep -F "decideSecretOpen: $WSENV by $RTCOPY" "$WORK/arb/arbiter.log" | tail -3)"
done
(( ${#RT_COPIES[@]} > 0 )) || echo "  skip — (6g) needs one of ksh93, mksh, lksh, yash, posh, fish, luajit"
# (6h) P0 item 14 (2026-10-07): a GNU cat no hash knows, renamed and pinned
#      with `prints: nothing`: before, it read .env raw and printed it. The
#      guard finds GNU coreutils' own text in it (`pkg:coreutils`).
if [[ "$CATSHA" != "$(printf 'no GNU cat' | sha256sum | cut -d' ' -f1)" ]]; then
  OUT="$("${G[@]}" "$CATCOPY" "$WSENV" 2>&1)"
  [[ "$OUT" != *"$WS_CANARY"* ]] \
    && ok "a GNU cat build no hash knows, renamed and vouched for, gets no byte of .env" \
    || bad "a pinned GNU cat build printed the listed .env: $(printf '%s' "$OUT" | sed "s/$WS_CANARY/<KEY>/g" | tail -3)"
  await_grep -q "decideSecretOpen: $WSENV by $CATCOPY .* → deny (mdu-catbuild is, by its content, a program of GNU coreutils" "$WORK/arb/arbiter.log" \
    && ok "the arbiter refused it on the guard's package finding" || bad "no package refusal: $(grep -F "decideSecretOpen: $WSENV" "$WORK/arb/arbiter.log" | tail -3)"
else
  echo "  skip — (6h) needs GNU cat"
fi
# (6i) P0 item 14: the pinned holder carrying the .NET muxer's front end,
#      renamed and vouched for: a disguised interpreter of a family the
#      guard knew by name only. Refused on the content finding
#      (`runs:dotnet`); the holder itself reads the same file raw (above).
OUT="$("${G[@]}" "$MUXCOPY" "$WSENV" 2>&1)"
[[ "$OUT" != *"$WS_CANARY"* ]] \
  && ok "a disguised dotnet muxer, renamed and vouched for, gets no byte of .env" \
  || bad "a pinned disguised interpreter read the listed .env: $(printf '%s' "$OUT" | sed "s/$WS_CANARY/<KEY>/g" | tail -3)"
await_grep -q "decideSecretOpen: $WSENV by $MUXCOPY .* → deny (mdu-muxer is not the program a human could name: its executable is, by its content, a dotnet interpreter" "$WORK/arb/arbiter.log" \
  && ok "the arbiter refused it on the guard's content finding (runs:dotnet)" || bad "no dotnet content refusal: $(grep -F "decideSecretOpen: $WSENV" "$WORK/arb/arbiter.log" | tail -3)"
# The holder these steps use instead: the shell sources the file through
# mdu-holder, its pinned reader, and holds it by the pipe (plan 13 D2).
SRC_WSENV="eval \"\$('$HOLDER' '$WSENV')\""
SRC_WSAWS="eval \"\$('$HOLDER' '$WSAWS')\""
OUT="$("${G[@]}" /bin/sh -c "$SRC_WSENV; echo \"key=\$API_KEY\"" 2>&1)"
[[ "$OUT" == *"key=$WS_CANARY"* ]] && ok "a shell sourcing .env through mdu-holder (its pinned reader) holds the real value" || bad "the holder-fed shell got: $(printf '%s' "$OUT" | tail -2)"

# (7) the NETWORK exit (§4.3): a shell that sourced the secret may connect only to the bindings
lst() { python3 -c 'import socket,sys,time
s=socket.socket(); s.bind((sys.argv[1],0)); s.listen(8); print(s.getsockname()[1], flush=True)
time.sleep(120)' "$1"; }
lst 127.0.0.2 > "$WORK/p2" & L2=$!; lst 127.0.0.3 > "$WORK/p3" & L3=$!
for _ in $(seq 1 50); do [[ -s "$WORK/p2" && -s "$WORK/p3" ]] && break; sleep 0.1; done
P2="$(cat "$WORK/p2")"; P3="$(cat "$WORK/p3")"
conn() { "${G[@]}" /bin/sh -c "$1; nc -z -w 3 $2 $3 >/dev/null 2>&1; echo rc=\$?" 2>/dev/null | tail -1; }
[[ "$(conn "true" 127.0.0.3 "$P3")" == "rc=0" ]] && ok "an UNTAINTED shell reaches 127.0.0.3 (the static policy allows loopback)" || bad "untainted connect to 127.0.0.3 failed"
[[ "$(conn "$SRC_WSENV" 127.0.0.2 "$P2")" == "rc=0" ]] && ok "a shell that sourced the secret reaches its BOUND host 127.0.0.2" || bad "tainted connect to the bound host failed"
[[ "$(conn "$SRC_WSENV" 127.0.0.3 "$P3")" != "rc=0" ]] && ok "the same tainted shell is REFUSED at the unbound 127.0.0.3 (the network exit)" || bad "tainted connect to an unbound host was allowed"
# a child of the tainted shell inherits the restriction
[[ "$("${G[@]}" /bin/sh -c "$SRC_WSENV; sh -c 'nc -z -w 3 127.0.0.3 $P3' >/dev/null 2>&1; echo rc=\$?" 2>/dev/null | tail -1)" != "rc=0" ]] \
  && ok "a CHILD of the tainted shell is refused at the unbound host too" || bad "the child escaped the taint"
# (7b) confidentiality plan 13 D1: a holder of TWO secrets reaches only where
#      BOTH are bound. .env is bound to 127.0.0.2, aws.env to 127.0.0.3: each
#      alone reaches its own host; a shell that sourced both reaches neither
#      (the union answered before let it send either key to either host).
[[ "$(conn "$SRC_WSAWS" 127.0.0.3 "$P3")" == "rc=0" ]] && ok "a shell that sourced only aws.env reaches ITS bound host 127.0.0.3" || bad "tainted connect to aws.env's bound host failed"
[[ "$(conn "$SRC_WSENV; $SRC_WSAWS" 127.0.0.2 "$P2")" != "rc=0" ]] && ok "D1: holding .env and aws.env, the shell is REFUSED at .env's host (aws.env is not bound there)" || bad "D1: a holder of both secrets reached 127.0.0.2"
[[ "$(conn "$SRC_WSAWS; $SRC_WSENV" 127.0.0.3 "$P3")" != "rc=0" ]] && ok "D1: holding both, the shell is REFUSED at aws.env's host (.env is not bound there)" || bad "D1: a holder of both secrets reached 127.0.0.3"
kill $L2 $L3 2>/dev/null
# the refusal is an EVENT, named like the net-proxy's proxied leg (plan 10 §8 phase 3, the owed one)
await_grep -rq "egress:tainted-process-unbound" "$WORK/arb/events" \
  && ok "the guard's refusal emitted its event (rule egress:tainted-process-unbound, the files and the bindings named)" \
  || bad "no taint-refusal event under $WORK/arb/events: $(grep -rh "REFUSED\|DENIED" "$WORK/arb/events" | tail -2)"

# (8) the FILESYSTEM exit: a file the tainted shell writes is labeled at the taint's level
"${G[@]}" /bin/sh -c "$SRC_WSENV; echo hello > '$WS2/notes.txt'" 2>/dev/null
await_grep -q "labelWrittenPathTainted: $WS2/notes.txt .* → no-model" "$WORK/arb/arbiter.log" \
  && ok "the file a tainted shell wrote got a derived label (no-model)" \
  || bad "no derived label for notes.txt; the arbiter's lines about $WS2: $(grep -F "$WS2" "$WORK/arb/arbiter.log" | tail -8)"
"${G[@]}" /bin/sh -c "echo plain > '$WS2/plain.txt'" 2>/dev/null
sleep 0.3
grep -q "labelWrittenPathTainted: $WS2/plain.txt" "$WORK/arb/arbiter.log" && bad "an untainted write was labeled" || ok "an untainted shell's write is not labeled"

# (9) AF_UNIX: a tainted shell reaches only its `unix:` bindings (and the arbiter socket)
ulst() { python3 -c 'import socket,sys,time,os
p=sys.argv[1]
try: os.unlink(p)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX); s.bind(p); s.listen(8); print("ok", flush=True); time.sleep(120)' "$1"; }
mkdir -p "$WORK/sock-bound"; ulst "$WORK/sock-bound/s.sock" > "$WORK/u1" & U1=$!; ulst "$WORK/other.sock" > "$WORK/u2" & U2=$!
for _ in $(seq 1 50); do [[ -s "$WORK/u1" && -s "$WORK/u2" ]] && break; sleep 0.1; done
uconn() { "${G[@]}" /bin/sh -c "$1; nc -U -z -w 3 '$2' >/dev/null 2>&1; echo rc=\$?" 2>/dev/null | tail -1; }
[[ "$(uconn "true" "$WORK/other.sock")" == "rc=0" ]] && ok "an untainted shell reaches any unix socket" || bad "untainted unix connect failed"
[[ "$(uconn "$SRC_WSENV" "$WORK/sock-bound/s.sock")" == "rc=0" ]] && ok "a tainted shell reaches a unix socket under its unix: binding" || bad "tainted connect to the bound unix socket failed"
[[ "$(uconn "$SRC_WSENV" "$WORK/other.sock")" != "rc=0" ]] && ok "the tainted shell is refused at an unbound unix socket" || bad "tainted unix connect to an unbound socket was allowed"
kill $U1 $U2 2>/dev/null

# (10) introspection: an untainted process cannot read a tainted process's environment
# (the tainted process is a reader: mdu-holder, reading .env and then its
# standard input, which stays open for 4 s (cat until 2026-10-03, then curl,
# printers since plan 13 D8); it was a shell that sourced .env before
# plan 13 §8 decision (b)). The looker is DETACHED before the read (its
# subshell exits at once, the guard adopts it): since 2026-10-03 the shell
# that starts a holder is one itself (it learns the holder's exit status,
# plan 13 §4.9), and so is every child of that shell; the looker stands for
# a process of another call. The target writes its own pid (before it reads:
# a file the holding shell wrote would take the label, and the looker would
# read its twin), and the looker reports through a file.
# intro <a pipeline the guarded shell runs in the background; its target writes its pid to $WORK/intro.pid>
intro() {
  local pf="$WORK/intro.pid" res="$WORK/intro.res"; rm -f "$pf" "$res"
  "${G[@]}" /bin/sh -c "( ( i=0; while [ ! -s '$pf' ] && [ \$i -lt 150 ]; do sleep 0.05; i=\$((i+1)); done; sleep 1; P=\$(cat '$pf'); case \$P in ''|*[!0-9]*) echo bad-pid;; *) if cat /proc/\$P/environ >/dev/null 2>&1; then echo readable; else echo denied; fi;; esac > '$res' ) & ); sleep 0.3; $1 & wait; i=0; while [ ! -s '$res' ] && [ \$i -lt 100 ]; do sleep 0.1; i=\$((i+1)); done" >/dev/null 2>&1
  cat "$res" 2>/dev/null || echo never
}
INTRO="$(intro "sleep 4 | sh -c 'echo \$\$ > $WORK/intro.pid; exec $HOLDER $WSENV /dev/stdin >/dev/null'")"
[[ "$INTRO" == "denied" ]] && ok "an untainted process cannot open /proc/<tainted pid>/environ (EACCES)" || bad "introspection of a tainted process: $INTRO"
# the same for a shell holding .env by the reader's pipe (plan 13 D2). The looker
# looks a second after the shell started. It was informational for a day (2026-10-02, a run read the environment):
# when the outer shell started within a clock tick of cat's taint, the orphan
# backstop judged it cat's orphan, so the sibling was "tainted" too, and the
# guard exempted every tainted opener (confidentiality-plan-10 §4.1,
# "Built"). Since 2026-10-03 the backstop never takes a holder's own
# ancestor for its orphan (lineage::orphan_of); a root older than the
# holder was not enough, as the shell and cat often start in one tick
# (master pipeline 8239).
HOLDER_INTRO="$(intro "sh -c 'echo \$\$ > $WORK/intro.pid; eval \"\$($HOLDER $WSENV)\"; sleep 4'")"
[[ "$HOLDER_INTRO" == "denied" ]] && ok "an untainted process cannot open /proc/<pid>/environ of a shell holding .env by a pipe (D2)" || bad "introspection of a pipe holder (D2): $HOLDER_INTRO"
SELF="$("${G[@]}" /bin/sh -c "$SRC_WSENV; if cat /proc/\$\$/environ >/dev/null 2>&1; then echo readable; else echo denied; fi" 2>/dev/null | tail -1)"
[[ "$SELF" == "readable" ]] && ok "a tainted process still reads its own /proc entries" || bad "self-introspection broke: $SELF"

# (11) the HOLD (§11.1): with prompting on, a non-reader's open waits for the human; an allow makes it raw and pins the reader
mkdir -p "$HOME_DIR/held"; HELD="$HOME_DIR/held/.env"; HELD_CANARY="HELD_LIVE_CANARY_$RANDOM"
printf 'TOKEN=%s\n' "$HELD_CANARY" > "$HELD"; HELD_SHA="$(sha_of "$HELD")"
register "$HELD" "$WORK/twins/held"
cat > "$WORK/secret-policy-ask.json" <<JSON
{"agentExe":"","ask":"always","askTimeoutMs":20000,"session":"readers-live","unixDeny":["$WORK/rt/human"],"secrets":[
  {"path":"$HELD","twin":"$WORK/twins/held","level":"no-model"}]}
JSON
ADMIN="$MANDU_ADMIN_SOCK"
acall() { printf '%s\n' "$1" | timeout 10 nc -U -q1 "$ADMIN" 2>/dev/null | head -1; }
( MANDU_NET_GUARD_SECRETS="$WORK/secret-policy-ask.json" "${G[@]}" /bin/sh -c "$(rd "$HELD")" > "$WORK/held.out" 2>/dev/null; echo "rc=$?" >> "$WORK/held.out" ) &
HOLD_PID=$!
sleep 2
[[ ! -s "$WORK/held.out" ]] && ok "the open is HELD: $SUM_BASE has produced nothing after 2 s" || bad "$SUM_BASE was not held: $(cat "$WORK/held.out")"
ROW="$(acall '{"id":20,"op":"egressApprovals","status":"pending"}')"
AID="$(printf '%s' "$ROW" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);const a=(j.result||{}).approvals||[];const r=a.find(x=>x.symbol.startsWith("trust:/")&&x.symbol.split("#")[0].endsWith("/"+process.argv[1])&&/#[0-9a-f]{64}$/.test(x.symbol));process.stdout.write(r?r.id:"")})' "$SUM_BASE")"
[[ -n "$AID" ]] && ok "an Inbox row 'trust:<$SUM_BASE's path>#<its sha256>' → held/.env is pending ($AID): the verdict names the binary, not the name (Plan 13 D8), and it is the warning question ($SUM_BASE is no vetted reader, D8 (12))" || bad "no pending row for the held open: ${ROW:0:200}"
if [[ -n "$AID" ]]; then
  RES="$(acall "{\"id\":21,\"op\":\"resolveEgressApproval\",\"approvalId\":\"$AID\",\"approve\":true,\"scope\":\"always\"}")"
  wait $HOLD_PID 2>/dev/null
  [[ "$(cat "$WORK/held.out")" == *"$HELD_SHA"* && "$(cat "$WORK/held.out")" == *"rc=0"* ]] && ok "after the human's allow the held $SUM_BASE completed with the RAW bytes" || bad "held $SUM_BASE after allow: $(cat "$WORK/held.out")"
  grep -q "app: $SUM_BASE" "$WORK/policy.yaml" && grep -q "held/.env" "$WORK/policy.yaml" && ok "the standing allow pinned $SUM_BASE as a reader of held/.env in policy.yaml" || bad "no pin written: $(grep -B2 -A4 "app: $SUM_BASE" "$WORK/policy.yaml")"
fi

# (12) Plan 13 D8: a human verdict names the BINARY (path + hash), not the
#      program's name. The human allows the system's reader ONCE for once/.env (its
#      hold is abandoned before the answer, so the once is unspent); then a
#      copy of the reader in the workspace, named like it, opens the file: it is not the
#      binary the human allowed, so it is held and, unanswered, refused. Until
#      2026-10-02 the verdict was keyed `open:cat` and the copy spent the once
#      on the raw bytes.
mkdir -p "$HOME_DIR/once" "$WS2/bin"; ONCE="$HOME_DIR/once/.env"; ONCE_CANARY="ONCE_LIVE_CANARY_$RANDOM"
printf 'TOKEN=%s\n' "$ONCE_CANARY" > "$ONCE"; ONCE_SHA="$(sha_of "$ONCE")"
register "$ONCE" "$WORK/twins/once"
cat > "$WORK/secret-policy-once.json" <<JSON
{"agentExe":"","ask":"always","askTimeoutMs":3000,"session":"readers-live","unixDeny":["$WORK/rt/human"],"secrets":[
  {"path":"$ONCE","twin":"$WORK/twins/once","level":"no-model"}]}
JSON
RD_BIN="$SUM_BIN"
cp "$RD_BIN" "$WS2/bin/$SUM_BASE"
( MANDU_NET_GUARD_SECRETS="$WORK/secret-policy-once.json" "${G[@]}" /bin/sh -c "exec '$RD_BIN' '$ONCE'" > "$WORK/once-real.out" 2>/dev/null ) &
REAL_PID=$!
ONCE_AID=""
for _ in $(seq 1 50); do
  ONCE_AID="$(acall '{"id":22,"op":"egressApprovals","status":"pending"}' | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);const a=(j.result||{}).approvals||[];const r=a.find(x=>x.destination===process.argv[1]&&/^trust:\//.test(x.symbol));process.stdout.write(r?r.id+" "+r.symbol:"")})' "$ONCE")"
  [[ -n "$ONCE_AID" ]] && break; sleep 0.1
done
pkill -KILL -P "$REAL_PID" 2>/dev/null; kill -KILL "$REAL_PID" 2>/dev/null; wait "$REAL_PID" 2>/dev/null
if [[ -n "$ONCE_AID" ]]; then
  [[ "${ONCE_AID#* }" == "trust:$RD_BIN#"* ]] && ok "the held row names $RD_BIN and its hash" || bad "the held row: $ONCE_AID"
  acall "{\"id\":23,\"op\":\"resolveEgressApproval\",\"approvalId\":\"${ONCE_AID%% *}\",\"approve\":true,\"scope\":\"once\"}" >/dev/null
  OUT="$(MANDU_NET_GUARD_SECRETS="$WORK/secret-policy-once.json" "${G[@]}" /bin/sh -c "'$WS2/bin/$SUM_BASE' '$ONCE'" 2>&1)"
  [[ "$OUT" != *"$ONCE_SHA"* ]] && ok "a copy of the reader in the workspace is not the binary the human allowed once: no raw byte" || bad "the workspace copy of the reader spent the human's once on the raw file: $OUT"
  OUT="$(MANDU_NET_GUARD_SECRETS="$WORK/secret-policy-once.json" "${G[@]}" /bin/sh -c "'$RD_BIN' '$ONCE'" 2>&1)"
  [[ "$OUT" == *"$ONCE_SHA"* ]] && ok "the allowed binary still has its once: $RD_BIN reads the real file" || bad "the allowed reader after the copy: $OUT"
else
  bad "no pending row for the held open of once/.env"
fi

# (13) Plan 13 D8, trust on first use: tofu.env names the reader by name only, and
#      no such program has opened it yet. A copy of the reader in the workspace opens it FIRST:
#      the agent could have written that file, so it is not pinned and gets no
#      raw byte (ask: never, a listed file: refused). The system's reader then
#      reads it and is the one pinned. Until 2026-10-02 the first opener of the
#      name became the pin, the copy included.
OUT="$("${G[@]}" /bin/sh -c "'$WS2/bin/$SUM_BASE' '$TOFUF'" 2>&1)"
[[ "$OUT" != *"$TOFU_SHA"* ]] && ok "a workspace copy named like it, first to open a bare-name file, gets no raw byte" || bad "the workspace copy read the real file: $OUT"
grep -q "$WS2/bin/$SUM_BASE" "$WORK/policy.yaml" && bad "the workspace copy was pinned as the reader: $(grep -n "$WS2/bin/$SUM_BASE" "$WORK/policy.yaml")" || ok "and it was not pinned"
OUT="$("${G[@]}" /bin/sh -c "'$RD_BIN' '$TOFUF'" 2>&1)"
[[ "$OUT" == *"$TOFU_SHA"* ]] && ok "the system's reader still reads it raw" || bad "the system reader on tofu.env: $OUT"
PINNED=0
for _ in $(seq 1 100); do grep -A6 "path: $TOFUF" "$WORK/policy.yaml" | grep -q "path: $RD_BIN" && { PINNED=1; break; }; sleep 0.1; done
[[ $PINNED -eq 1 ]] && ok "and is the binary pinned for tofu.env" || bad "no pin for $RD_BIN under tofu.env: $(grep -A6 "path: $TOFUF" "$WORK/policy.yaml")"

# (14) Plan 13 D8, the loader environment: the pinned reader of .pgpass, run with
#      LD_PRELOAD (a harmless library here; the agent's own in an attack),
#      is not the pinned program: refused, no raw byte. A python3 parent run
#      with PYTHONPATH the launch did not give is no `from: python3` parent.
PRELOAD_LIB="$(ldd "$RD_BIN" 2>/dev/null | awk '/libc\.so/ {print $3; exit}')"
if [[ -n "$PRELOAD_LIB" && -f "$PRELOAD_LIB" ]]; then
  OUT="$("${G[@]}" /bin/sh -c "LD_PRELOAD='$PRELOAD_LIB' '$RD_BIN' '$PGPASS'; echo rc=\$?" 2>&1)"
  [[ "$OUT" != *"$PG_SHA"* && "$OUT" != *"rc=0"* ]] && ok "the pinned reader run with LD_PRELOAD is refused raw" || bad "the reader with LD_PRELOAD got: $OUT"
  await_grep -q "decideSecretOpen: $PGPASS by $RD_BIN .* → deny (.*LD_PRELOAD" "$WORK/arb/arbiter.log" && ok "the arbiter names LD_PRELOAD as the reason" || bad "no LD_PRELOAD denial logged: $(grep "decideSecretOpen: $PGPASS" "$WORK/arb/arbiter.log" | tail -2)"
  OUT="$("${G[@]}" /bin/sh -c "$(rd "$PGPASS")" 2>&1)"
  [[ "$OUT" == *"$PG_SHA"* ]] && ok "the same reader without it still reads raw" || bad "clean reader after the preload: $OUT"
fi
if command -v python3 >/dev/null 2>&1; then
  OUT="$("${G[@]}" /bin/sh -c "PYTHONPATH='$WS2' python3 -c \"import subprocess,sys; sys.stdout.write(subprocess.run(['$SUM_APP','$KEYF'],capture_output=True,text=True).stdout)\"" 2>&1)"
  [[ "$OUT" != *"$KEY_SHA"* ]] && ok "from: python3 — a python3 run with PYTHONPATH from the workspace is no trusted parent" || bad "python3 with PYTHONPATH let its reader read the key: $OUT"

  # (15) Plan 13 D8, `from:` by path: a copy of sh in the workspace NAMED
  #      python3 starts the reader; a basename is the program's choice.
  cp "$(readlink -f /bin/sh)" "$WS2/bin/python3"
  OUT="$("${G[@]}" "$WS2/bin/python3" -c "$(rd "$KEYF"); true" 2>&1)"
  [[ "$OUT" != *"$KEY_SHA"* ]] && ok "from: python3 — a shell renamed python3 in the workspace is not python3: no raw key" || bad "a renamed sh passed as python3: $OUT"

  # (16) the secret socket by the same rules: a workspace copy of ssh-add,
  #      started by python3, is not the reader ssh-add.
  if command -v ssh-add >/dev/null 2>&1; then
    cp "$(readlink -f "$(command -v ssh-add)")" "$WS2/bin/ssh-add"
    ALOG2="$WORK/agent2.log"
    agent_stub "$WORK/agent2.sock" "$ALOG2"
    SRV2=$!
    for _ in $(seq 1 50); do [[ -S "$WORK/agent2.sock" ]] && break; sleep 0.1; done
    sed "s#$WORK/agent.sock#$WORK/agent2.sock#" "$WORK/secret-policy.json" > "$WORK/secret-policy-sock2.json"
    OUT="$(MANDU_NET_GUARD_SECRETS="$WORK/secret-policy-sock2.json" py_run "['$WS2/bin/ssh-add','-l']" "$WORK/agent2.sock")"
    [[ "$OUT" != *"no identities"* && "$(accepts "$ALOG2")" == 0 ]] && ok "secret socket: a workspace copy named ssh-add, started by python3, is refused" || bad "the workspace ssh-add reached the agent socket: $OUT"
    OUT="$(MANDU_NET_GUARD_SECRETS="$WORK/secret-policy-sock2.json" py_run "['ssh-add','-l']" "$WORK/agent2.sock")"
    [[ "$OUT" == *"no identities"* ]] && ok "and the system's ssh-add still reaches it" || bad "the system ssh-add after the copy: $OUT"
    kill "$SRV2" 2>/dev/null; SRV2=
  fi
fi

# (17) Plan 13 D8, `from:` ends at the session (2026-10-17): the guard
#      started by a python3 that made itself a subreaper (an IDE's or a
#      notebook's terminal, a CI harness) has that python3 ABOVE the
#      session. Until the fix the guard's ancestor walk went on past itself
#      to pid 1, so that python3 (out of reach, the launch's own clean
#      environment) was a trusted `from: python3` parent of every opener:
#      sh's reader, a shell renamed python3 and sh's ssh-add all passed. A
#      python3 INSIDE the session still is one.
if command -v python3 >/dev/null 2>&1; then
  UP=(python3 -c "import ctypes,subprocess,sys; ctypes.CDLL(None).prctl(36,1,0,0,0); sys.exit(subprocess.call(sys.argv[1:]))")
  GU=(mdu_without_lifeline "${UP[@]}" "$GUARD" --allow "127.0.0.0/8:*" --)
  OUT="$("${GU[@]}" /bin/sh -c "$(rd "$KEYF"); echo rc=\$?" 2>&1)"
  [[ "$OUT" != *"rc=0"* && "$OUT" != *"$KEY_SHA"* ]] && ok "from: python3 — a python3 above the launch is no parent: sh's $SUM_BASE is refused" || bad "the python3 above the guard let sh's $SUM_BASE read the key: $OUT"
  OUT="$("${GU[@]}" python3 -c "import subprocess,sys; sys.stdout.write(subprocess.run(['$SUM_APP','$KEYF'],capture_output=True,text=True).stdout)" 2>&1)"
  [[ "$OUT" == *"$KEY_SHA"* ]] && ok "from: python3 — under it, a python3 inside the session still is the reader's parent" || bad "python3's $SUM_BASE under an outside python3 got: $OUT"
  [[ -x "$WS2/bin/python3" ]] || cp "$(readlink -f /bin/sh)" "$WS2/bin/python3"
  OUT="$("${GU[@]}" "$WS2/bin/python3" -c "$(rd "$KEYF"); true" 2>&1)"
  [[ "$OUT" != *"$KEY_SHA"* ]] && ok "from: python3 — under it, a shell renamed python3 still is not python3" || bad "a renamed sh under an outside python3 read the key: $OUT"
  if command -v ssh-add >/dev/null 2>&1; then
    ALOG3="$WORK/agent3.log"
    agent_stub "$WORK/agent3.sock" "$ALOG3"
    SRV2=$!
    for _ in $(seq 1 50); do [[ -S "$WORK/agent3.sock" ]] && break; sleep 0.1; done
    sed "s#$WORK/agent.sock#$WORK/agent3.sock#" "$WORK/secret-policy.json" > "$WORK/secret-policy-sock3.json"
    OUT="$(MANDU_NET_GUARD_SECRETS="$WORK/secret-policy-sock3.json" "${GU[@]}" /bin/sh -c "SSH_AUTH_SOCK='$WORK/agent3.sock' timeout 5 ssh-add -l </dev/null; true" 2>&1)"
    [[ "$OUT" != *"no identities"* && "$(accepts "$ALOG3")" == 0 ]] && ok "secret socket: under it, ssh-add started by sh is refused" || bad "sh's ssh-add under an outside python3 reached the agent ($(accepts "$ALOG3") accepts): $OUT"
    OUT="$(MANDU_NET_GUARD_SECRETS="$WORK/secret-policy-sock3.json" "${GU[@]}" python3 -c "import subprocess,sys,os; r=subprocess.run(['ssh-add','-l'],input='',capture_output=True,text=True,timeout=30,env=dict(os.environ,SSH_AUTH_SOCK='$WORK/agent3.sock')); sys.stdout.write(r.stdout+r.stderr)" 2>&1)"
    [[ "$OUT" == *"no identities"* && "$(accepts "$ALOG3")" == 1 ]] && ok "secret socket: under it, ssh-add started by a python3 inside the session reaches the agent" || bad "python3's ssh-add under an outside python3 got ($(accepts "$ALOG3") accepts): $OUT"
    kill "$SRV2" 2>/dev/null; SRV2=
  fi
fi

echo "secret-readers-live.test.sh: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
