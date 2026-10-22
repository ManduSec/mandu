#!/usr/bin/env bash
# timing-leg.sh <agent> <bare|mandu> <proj> <label> — one TIMED scripted-model
# run of a real agent, with or without the installed mandu
# (docs/design/testing/os-test-matrix.md §10.18). Runs as the test user.
#
# The model is fake-model.mjs on loopback (the fresh-agents one): it answers
# at once, so the wall time is the agent's own start plus Mandu's, with no
# network or model latency in it. `bare` points the agent straight at the
# fake (ANTHROPIC_BASE_URL; a Codex provider override), `mandu` puts the
# installed mandu's context proxy in between (MANDU_UPSTREAM).
#
# Prints one line the suite collects:
#   TIMING <label> agent=<a> via=<bare|mandu> wall_ms=<n> first_req_ms=<n> reqs=<n> rc=<n>
# (first_req_ms: launch to the first request the model got, -1 when none)
# and PASS/FAIL/NOTE lines on the canary: under mandu it must reach no
# request; bare, it must reach one (the positive control: the capture can
# see a leak, so the mandu legs' "none" means something).
set -uo pipefail
AGENT="${1:?agent}"; VIA="${2:?bare|mandu}"; PROJ="${3:?proj}"; LABEL="${4:?label}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET_FILE="${TARGET_FILE:-$HOME/.aws/credentials}"
CANARY_RE="${CANARY_RE:-FRESHINSTALLCANARY}"
OUT="${LEG_OUT:-$HOME/timing-legs}/$LABEL"
TIMEOUT="${LEG_TIMEOUT:-240}"
mkdir -p "$OUT"; rm -f "$OUT"/*

node "$HERE/fake-model.mjs" --agent "$AGENT" --file "$TARGET_FILE" --capture "$OUT/capture.ndjson" --port-file "$OUT/port" &
FAKE=$!
trap 'kill $FAKE 2>/dev/null; wait $FAKE 2>/dev/null' EXIT
for _ in $(seq 50); do [[ -s "$OUT/port" ]] && break; sleep 0.1; done
[[ -s "$OUT/port" ]] || { echo "FAIL [$LABEL] fake model did not start"; exit 1; }
URL="http://127.0.0.1:$(cat "$OUT/port")"
PROMPT="Read the file $TARGET_FILE with your file-reading tool and tell me which section names it has. Do not print any values."
cd "$PROJ" || { echo "FAIL [$LABEL] no project dir $PROJ"; exit 1; }

T0=$(date +%s%3N)
case "$AGENT/$VIA" in
  claude/bare)
    ANTHROPIC_BASE_URL="$URL" ANTHROPIC_API_KEY=sk-ant-fake-mandu-vm timeout "$TIMEOUT" \
      claude -p "$PROMPT" --allowedTools Read </dev/null ;;
  claude/mandu)
    MANDU_UPSTREAM="$URL" ANTHROPIC_API_KEY=sk-ant-fake-mandu-vm timeout "$TIMEOUT" \
      mandu --no-reply-filter claude -p "$PROMPT" --allowedTools Read </dev/null ;;
  codex/bare)
    OPENAI_API_KEY=sk-fake-mandu-vm timeout "$TIMEOUT" \
      codex -c model_provider=fake \
        -c "model_providers.fake={name=\"fake\",base_url=\"$URL/v1\",wire_api=\"responses\",env_key=\"OPENAI_API_KEY\"}" \
        exec --skip-git-repo-check "$PROMPT" </dev/null ;;
  codex/mandu)
    MANDU_UPSTREAM="$URL" OPENAI_API_KEY=sk-fake-mandu-vm timeout "$TIMEOUT" \
      mandu --no-reply-filter codex exec --skip-git-repo-check "$PROMPT" </dev/null ;;
  *) echo "FAIL [$LABEL] unknown leg $AGENT/$VIA"; exit 1 ;;
esac > "$OUT/stdout" 2> "$OUT/stderr"
RC=$?
T1=$(date +%s%3N)
kill $FAKE 2>/dev/null; wait $FAKE 2>/dev/null; trap - EXIT

CAP="$OUT/capture.ndjson"
reqs=$(wc -l < "$CAP" 2>/dev/null || echo 0)
first=-1
[[ -s "$CAP" ]] && first=$(( $(head -1 "$CAP" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).t))') - T0 ))
echo "TIMING $LABEL agent=$AGENT via=$VIA wall_ms=$((T1 - T0)) first_req_ms=$first reqs=$reqs rc=$RC"
[[ $RC -eq 0 ]] || { echo "FAIL [$LABEL] $AGENT ($VIA) exit $RC"; tail -5 "$OUT/stderr" | sed 's/^/        ! /'; }
nres=$(grep -c '"kind":"tool-result"' "$CAP" 2>/dev/null); nres=${nres:-0}
if [[ "$nres" -eq 0 ]]; then
  echo "NOTE [$LABEL] no tool result came back (the canary check below proves nothing for this leg)"
elif [[ "$VIA" == mandu ]]; then
  if grep -Eq "$CANARY_RE" "$CAP"; then echo "FAIL [$LABEL] CONFIDENTIALITY: the canary reached the model through mandu"
  else echo "PASS [$LABEL] the canary reached no request through mandu"; fi
else
  if grep -Eq "$CANARY_RE" "$CAP"; then echo "PASS [$LABEL] positive control: without mandu the canary reaches the model"
  else echo "NOTE [$LABEL] without mandu the canary did not reach the model (the agent's own sandbox stopped the read?)"; fi
fi
[[ $RC -eq 0 ]]
