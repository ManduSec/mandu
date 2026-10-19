#!/usr/bin/env bash
# agent-leg.sh <agent> <mode> — one scripted-model run of a REAL agent through
# the INSTALLED mandu (docs/design/testing/os-test-matrix.md §10.14). Runs as the
# test user, with `mandu` and the agent on PATH. Prints PASS/FAIL/NOTE lines
# the suite forwards into its step log; exit 0 iff no FAIL.
#
#   agent: claude | codex | opencode | openclaw
#   mode:  a protection mode name, or "default" (no --mode flag: the shipped
#          default, `secrets`)
#   LEG_AGENT_ARGS: extra args (codex: spliced after `exec`; claude: mandu's
#          own options, before the agent); LEG_CLAUDE_TOOL=Bash: Claude reads
#          with a shell `cat` through the exec box; LEG_NAME
#          names the output dir (default <agent>-<mode>)
#
# The model is fake-model.mjs on loopback (MANDU_UPSTREAM), which tells the
# agent to read $TARGET_FILE with the agent's own read tool (codex: a shell
# `cat`) and records every request body it gets. The oracles read that capture,
# i.e. exactly what the privileged model was given:
#   1. the agent ran the tool: a request carrying the tool result arrived
#      (fail-closed: no tool result = the run proved nothing = FAIL);
#   2. the planted canary appears in NO request body;
#   3. the tool result carried a $MDU: symbol in the canary's place;
#   4. the read REALLY happened (fail-closed, since a failed command's error
#      text also comes back masked, which once made 1-3 pass vacuously for
#      Codex in the VM): with a secret target the arbiter must have decided
#      an open of it during the run; for Codex and Claude Code, the agent's
#      own local session log (read here, never by a model) must show the
#      tool's raw output.
set -uo pipefail
AGENT="${1:?agent}"; MODE="${2:?mode}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET_FILE="${TARGET_FILE:-$HOME/.aws/credentials}"
CANARY_RE="${CANARY_RE:-FRESHINSTALLCANARY}"
OUT="${LEG_OUT:-$HOME/agent-legs}/${LEG_NAME:-$AGENT-$MODE}"
read -r -a XARGS <<< "${LEG_AGENT_ARGS:-}"
TIMEOUT="${LEG_TIMEOUT:-240}"
PROJ="${LEG_PROJ:-$HOME/proj}"
mkdir -p "$OUT"; rm -f "$OUT"/*
FAILS=0
pass() { echo "PASS [$AGENT/$MODE] $1"; }
fail() { echo "FAIL [$AGENT/$MODE] $1"; FAILS=$((FAILS+1)); }
note() { echo "NOTE [$AGENT/$MODE] $1"; }

# LEG_CLAUDE_TOOL=Bash: Claude Code reads with a shell `cat` (through Mandu's
# exec box) instead of its Read tool.
CLAUDE_TOOL="${LEG_CLAUDE_TOOL:-Read}"
node "$HERE/fake-model.mjs" --agent "$AGENT" --file "$TARGET_FILE" --capture "$OUT/capture.ndjson" --port-file "$OUT/port" --claude-tool "$CLAUDE_TOOL" &
FAKE=$!
trap 'kill $FAKE 2>/dev/null; wait $FAKE 2>/dev/null' EXIT
for _ in $(seq 50); do [[ -s "$OUT/port" ]] && break; sleep 0.1; done
[[ -s "$OUT/port" ]] || { fail "fake model did not start"; exit 1; }
export MANDU_UPSTREAM="http://127.0.0.1:$(cat "$OUT/port")"

MODEFLAG=(); [[ "$MODE" != default ]] && MODEFLAG=(--mode "$MODE")
ALOG="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/mandu/logs/arbiter.log"
TS="$(date -u +%Y-%m-%dT%H:%M:%S)"
PROMPT="Read the file $TARGET_FILE with your file-reading tool and tell me which section names it has. Do not print any values."
cd "$PROJ" || { fail "no project dir $PROJ"; exit 1; }

# --no-reply-filter: stdout is what the MODEL wrote, not the human-side
# rendering. The keys below are dummies: the fake model accepts anything, and a
# real credential must never reach a stand-in upstream.
case "$AGENT" in
  claude)
    ANTHROPIC_API_KEY=sk-ant-fake-mandu-vm timeout "$TIMEOUT" \
      mandu "${MODEFLAG[@]}" "${XARGS[@]}" --no-reply-filter claude -p "$PROMPT" --allowedTools "$CLAUDE_TOOL" </dev/null ;;
  codex)
    OPENAI_API_KEY=sk-fake-mandu-vm timeout "$TIMEOUT" \
      mandu "${MODEFLAG[@]}" --no-reply-filter codex exec "${XARGS[@]}" --skip-git-repo-check "$PROMPT" </dev/null ;;
  opencode)
    ANTHROPIC_API_KEY=sk-ant-fake-mandu-vm OPENCODE_PERMISSION='{"*":"allow"}' \
    OPENCODE_DISABLE_MODELS_FETCH=1 OPENCODE_DISABLE_AUTOUPDATE=1 timeout "$TIMEOUT" \
      mandu "${MODEFLAG[@]}" --no-reply-filter opencode run -m anthropic/claude-sonnet-4-5 "$PROMPT" </dev/null ;;
  openclaw)
    ANTHROPIC_API_KEY=sk-ant-fake-mandu-vm timeout "$TIMEOUT" \
      mandu "${MODEFLAG[@]}" --no-reply-filter openclaw agent --local --agent main \
        --session-id "vm-$MODE-$$" -m "$PROMPT" --json --timeout "$((TIMEOUT - 30))" </dev/null ;;
  *) fail "unknown agent $AGENT"; exit 1 ;;
esac > "$OUT/stdout" 2> "$OUT/stderr"
RC=$?
kill $FAKE 2>/dev/null; wait $FAKE 2>/dev/null; trap - EXIT

CAP="$OUT/capture.ndjson"
nreq=$(wc -l < "$CAP" 2>/dev/null || echo 0)
ncall=$(grep -c '"kind":"tool-call"' "$CAP" 2>/dev/null); ncall=${ncall:-0}
nres=$(grep -c '"kind":"tool-result"' "$CAP" 2>/dev/null); nres=${nres:-0}
[[ $RC -eq 0 ]] && pass "launch exit 0" || fail "launch exit $RC"
[[ "$nreq" -gt 0 ]] && pass "the agent's model traffic reached the model endpoint through mandu ($nreq requests)" \
  || fail "no request reached the model endpoint: the agent never talked to the model through mandu"
[[ "$ncall" -gt 0 ]] && pass "the model asked for the read" || fail "the agent never advertised its read tool (no tool call issued)"
if [[ "$nres" -gt 0 ]]; then pass "the agent ran the tool and sent its result back"
else fail "no tool result came back: the canary checks below would be vacuous"; fi
if grep -Eq "$CANARY_RE" "$CAP" 2>/dev/null; then
  fail "the CANARY reached the model (invariant violated)"
  grep -Eo ".{60}$CANARY_RE.{20}" "$CAP" | head -3 | sed 's/^/        ! /'
else pass "the canary appears in no request the model received"; fi
if [[ "$nres" -gt 0 ]]; then
  # The tool result ITSELF (fake-model.mjs extracts it), not the whole body:
  # the handling prompt carries example $MDU: tokens of its own.
  node -e 'for (const l of require("fs").readFileSync(process.argv[1], "utf8").split("\n")) { if (!l) continue; const r = JSON.parse(l); if (r.kind === "tool-result") console.log(JSON.stringify(r.toolResult)); }' "$CAP" > "$OUT/tool-results.txt"
  if grep -q '\$MDU:' "$OUT/tool-results.txt"; then pass "the tool result itself carried a \$MDU: symbol: $(grep -o '\$MDU:[A-Za-z_]*\[[0-9a-f]*\][A-Za-z0-9_.]*' "$OUT/tool-results.txt" | head -1)"
  else fail "the tool result carried no \$MDU: symbol"; head -c 400 "$OUT/tool-results.txt" | sed 's/^/        | /'; fi
fi
# 4. read evidence
if [[ "$TARGET_FILE" == */.aws/credentials ]]; then
  if awk -v ts="$TS" '$1 >= ts' "$ALOG" 2>/dev/null | grep -qF "decideSecretOpen: $TARGET_FILE"; then
    pass "the agent really opened the file (arbiter: $(awk -v ts="$TS" '$1 >= ts' "$ALOG" | grep -F "decideSecretOpen: $TARGET_FILE" | head -1 | sed 's/.* by //' | cut -c1-60))"
  else fail "no arbiter decision for $TARGET_FILE during the run: the read never happened, so 2-3 are vacuous"; fi
fi
if [[ "$AGENT" == codex ]]; then
  ROLL="$(ls -t "$HOME"/.codex/sessions/*/*/*/rollout-*.jsonl 2>/dev/null | head -1)"
  node -e '
    const out = [];
    for (const l of require("fs").readFileSync(process.argv[1], "utf8").split("\n")) {
      if (!l) continue; const p = JSON.parse(l).payload || {};
      if (p.type === "custom_tool_call_output" || p.type === "function_call_output")
        out.push(Array.isArray(p.output) ? p.output.map((x) => x.text || "").join("") : String(p.output));
    }
    process.stdout.write(out.join("\n"));' "$ROLL" > "$OUT/codex-raw-output.txt" 2>/dev/null
  first="$(head -1 "$TARGET_FILE")"
  # What a real read shows: the file's first line, or (a twin or an AgentView
  # file) the $MDU: symbol that stands in for it. A sandbox failure shows
  # neither ("bwrap: loopback: Failed RTM_NEWADDR" on a host without a
  # usable bubblewrap, os-test-matrix.md §10.14.1).
  if grep -qF -- "$first" "$OUT/codex-raw-output.txt" || grep -q '\$MDU:' "$OUT/codex-raw-output.txt"; then
    pass "codex's command really read the file (its local log: $(tail -c 90 "$OUT/codex-raw-output.txt" | tr '\n' ' '))"
  else fail "codex's command did not read the file; its raw output was: $(tail -c 200 "$OUT/codex-raw-output.txt" | tr '\n' ' ')"; fi
fi
if [[ "$AGENT" == claude ]]; then
  # Claude Code's own transcript holds the tool result as the tool produced
  # it, before the proxy masks it. A failed command shows its error here and
  # nothing else (§14.1 item 6: under 26.04's bwrap profile every boxed
  # `cat` died "No permissions to create a new namespace", while the masked
  # wire copy and the arbiter's decision, which Claude Code's own open of the
  # named file satisfies, both looked like a read).
  TRANS="$(ls -t "$HOME"/.claude/projects/*/*.jsonl 2>/dev/null | head -1)"
  node -e '
    const out = [];
    for (const l of require("fs").readFileSync(process.argv[1], "utf8").split("\n")) {
      if (!l) continue; const c = JSON.parse(l).message?.content;
      if (Array.isArray(c)) for (const b of c) if (b?.type === "tool_result")
        out.push(typeof b.content === "string" ? b.content : (b.content || []).map((x) => x.text || "").join(""));
    }
    process.stdout.write(out.join("\n"));' "$TRANS" > "$OUT/claude-raw-output.txt" 2>/dev/null
  first="$(head -1 "$TARGET_FILE")"
  if grep -qF -- "$first" "$OUT/claude-raw-output.txt" || grep -q '\$MDU:' "$OUT/claude-raw-output.txt"; then
    pass "claude's $CLAUDE_TOOL really read the file (its local transcript: $(tail -c 90 "$OUT/claude-raw-output.txt" | tr '\n' ' '))"
  else fail "claude's $CLAUDE_TOOL did not read the file; its raw result was: $(tail -c 200 "$OUT/claude-raw-output.txt" | tr '\n' ' ')"; fi
  # A Mandu before 0.2.0-beta.6 started Claude Code in permission mode `auto`
  # (no feature flags with CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC;
  # os-test-matrix.md §10.14.1 item 9), which asks its classifier, through
  # the same proxy, before a Bash command; a later one passes
  # `--permission-mode default` (supported-agents.md §2), so the note should
  # read `default` and no classifier request. The fake still answers one; a
  # classifier denial here means the fake no longer recognizes its request.
  ncls=$(grep -c '"kind":"classifier"' "$CAP" 2>/dev/null); ncls=${ncls:-0}
  pmode="$(grep -o '"permissionMode":"[A-Za-z]*"' "$TRANS" 2>/dev/null | head -1 | cut -d'"' -f4)"
  note "permission mode ${pmode:-unknown}; auto-mode classifier requests: $ncls"
  if grep -q 'auto mode classifier\|require the classifier' "$OUT/claude-raw-output.txt" 2>/dev/null; then
    fail "Claude Code's auto-mode classifier refused or gave no verdict: fake-model.mjs did not answer its request as a verdict"
  fi
fi
grep -q 'MANDU_FAKE_DONE' "$OUT/stdout" && pass "the agent printed the model's closing reply" \
  || note "the closing reply is not on stdout (agent output format)"
if [[ $FAILS -gt 0 ]]; then
  echo "        --- stderr (tail)"; tail -15 "$OUT/stderr" | sed 's/^/        | /'
  echo "        --- stdout (tail)"; tail -8 "$OUT/stdout" | sed 's/^/        | /'
fi
exit $(( FAILS > 0 ))
