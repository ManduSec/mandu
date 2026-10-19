#!/usr/bin/env bash
# nightly.sh — a nightly lane's run (docs/design/testing/continuous-integration.md §9,
# §9.8): what the scheduled GitLab jobs `nightly-subscription` and
# `nightly-api-key` run, and what a developer runs to rehearse them. The
# api-key lane's job runs `--weekly` (2026-10-15): one agent of the weekly
# rotation a night, on the Anthropic API key a human placed on the runner
# host (credential.mjs path api); by hand it runs the whole lane.
#
#   scripts/ci/nightly.sh --lane subscription|api-key [--weekly] [--canary-credential] [vm-run.sh options…]
#
# It is scripts/ci/vm-run.sh with the nightly's selection and options:
#
#   --kind live-drill,env,eval            the nightly kinds, `secrets` mode only
#                                         (the manifest keeps the frozen lane out)
#   --include-flaky                       plus every `flaky` entry of every kind
#   --include-internet                    plus the nightly kinds' `internet` entries
#   --lane L                              of those, only the entries of lane L
#                                         (each entry's `credential`, §9.8;
#                                         one that needs no login holds none
#                                         and runs in the subscription lane)
#   --network                             the guest's internet (no host loopback)
#   --ollama                              subscription only: the host's Ollama on
#                                         one port (no API-lane entry uses one)
#   --credential claude[,codex]           subscription: the scoped agent credential a human
#                                         placed on this host (credential.mjs path claude),
#                                         plus the CI account's Codex sign-in when this
#                                         host holds one (credential.mjs path codex):
#                                         refreshed here first (credential.mjs refresh
#                                         codex), the guest gets a reduced copy
#   --credential api                      api: the vendor API keys a human placed
#                                         on this host (credential.mjs path api)
#
# One lane's credential kinds per run: the subscription lane's guest never
# holds an API key and the API lane's never holds a subscription sign-in, so
# no suite can quietly pass on the other (§9.8). A subscription host without a
# Codex sign-in, or with one that cannot be refreshed and no longer covers the
# run, runs the lane without it (one line says so; the ChatGPT-sign-in suites
# skip). MANDU_CI_TIMEOUT defaults to 8 h for the
# subscription lane (the drill entries alone may take hours) and 3 h for the
# API lane. Later options win over these (vm-run takes the last --kind), and
# `--only <id>` selects exactly those entries of the lane, so a rehearsal of
# one suite is
#
#   scripts/ci/nightly.sh --lane subscription --canary-credential --worktree --only integration.ollama-doctor
#
# --weekly   api-key lane only: tonight's agent of the weekly rotation
#     (continuous-integration.md §9.8; the agents whose live runs ride the
#     key): Monday OpenCode (1 and 2), Wednesday
#     OpenClaw, Friday Goose, by the UTC weekday (MANDU_CI_WEEKDAY, 1-7,
#     overrides it). Only that agent's live-drill entries of the lane run
#     (`--only`, from `suites.mjs list --agents`); another night runs nothing
#     and exits 0.
#
# --canary-credential   a local rehearsal without any real login: the guest
#     gets synthetic credentials of the lane's kinds (sk-ant-oat01-CANARY… and
#     a Codex sign-in of JWT-shaped CANARY tokens, or sk-ant-api03-CANARY… and
#     sk-proj-CANARY…; they authenticate nothing, and nothing is refreshed),
#     so the whole credential path runs (the host file's checks, the unlinked
#     credential disk, the guest's placement, the canary scan of the console,
#     the results disk and what is published) and nothing spends anything. A
#     real-model or drill entry then fails its login; the rehearsal is for the
#     plumbing and the local-model env suites.
#
# Exit: vm-run's (0 pass, 1 fail, 2 error). The GitLab jobs are allow_failure:
# a red nightly never blocks anything; it is read on the dashboard and in the
# pipeline list (§9).
set -uo pipefail

CI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANARY=0 LANE="" WEEKLY=0
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --canary-credential) CANARY=1; shift ;;
    --weekly) WEEKLY=1; shift ;;
    --lane) [[ $# -ge 2 ]] || { echo "nightly: --lane needs subscription or api-key" >&2; exit 2; }; LANE="$2"; shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
case "$LANE" in
  subscription) CRED=claude; OLLAMA=(--ollama); export MANDU_CI_TIMEOUT="${MANDU_CI_TIMEOUT:-28800}" ;;
  api-key) CRED=api; OLLAMA=(); export MANDU_CI_TIMEOUT="${MANDU_CI_TIMEOUT:-10800}" ;;
  *) echo "nightly: --lane subscription|api-key is required (continuous-integration.md §9.8)" >&2; exit 2 ;;
esac
# The weekly rotation (--weekly): one API-key agent a night, so a night spends
# one agent's runs of the key.
if [[ $WEEKLY -eq 1 ]]; then
  [[ $LANE == api-key ]] || { echo "nightly: --weekly is the api-key lane's rotation" >&2; exit 2; }
  day="${MANDU_CI_WEEKDAY:-$(date -u +%u)}"
  case "$day" in
    1) agent=opencode ;;
    3) agent=openclaw ;;
    5) agent=goose ;;
    [2467]) echo "nightly: the weekly API-key rotation runs no agent tonight (weekday $day; Monday OpenCode, Wednesday OpenClaw, Friday Goose)"; exit 0 ;;
    *) echo "nightly: MANDU_CI_WEEKDAY must be 1-7 (got '$day')" >&2; exit 2 ;;
  esac
  ids="$(node "$CI/../suites.mjs" list --kind live-drill --lane api-key --agents "$agent" --include-internet --ids)" || exit 2
  if [[ -z "$ids" ]]; then echo "nightly: the weekly rotation's $agent has no live-drill entry in the api-key lane"; exit 0; fi
  echo "nightly: weekly API-key rotation, weekday $day: $agent ($(tr ',' '\n' <<<"$ids" | grep -c .) entries)"
  args+=(--only "$ids")
fi

# A synthetic secret: the prefix, then random base64url characters, the shape
# of a real one and the bytes of none. node, not base64(1): a runner host's
# PATH can put a different base64 first (continuous-integration.md §7).
synthetic() { node -e 'process.stdout.write(process.argv[1] + require("crypto").randomBytes(72).toString("base64url").slice(0, 90))' "$1"; }
# A synthetic Codex sign-in: JWT-shaped CANARY tokens valid for 10 days, and a
# refresh token of the same kind of bytes.
synthetic_codex() {
  node -e '
    const r = (n) => require("crypto").randomBytes(n).toString("base64url");
    const b = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const exp = Math.floor(Date.now() / 1000) + 10 * 86400;
    const jwt = () => `${b({ alg: "RS256", typ: "JWT" })}.${b({ exp, sub: "CANARY", "https://api.openai.com/auth": { chatgpt_account_id: "CANARY" } })}.CANARY${r(96)}`;
    process.stdout.write(JSON.stringify({ OPENAI_API_KEY: null, tokens: { id_token: jwt(), access_token: jwt(), refresh_token: "rt_CANARY" + r(48), account_id: "CANARY" }, last_refresh: new Date().toISOString() }));'
}

if [[ $CANARY -eq 1 ]]; then
  d="$(mktemp -d "${TMPDIR:-/tmp}/mandu-ci-canary.XXXXXX")" || exit 2
  trap 'rm -rf "$d"' EXIT
  if [[ $CRED == claude ]]; then
    synthetic sk-ant-oat01-CANARY | node "$CI/credential.mjs" install claude --dest "$d/claude-credential.json" --valid-days 2 --subscription max || exit 2
    export MANDU_CI_CLAUDE_CREDENTIAL="$d/claude-credential.json"
    synthetic_codex > "$d/codex-src.json" && chmod 600 "$d/codex-src.json" \
      && node "$CI/credential.mjs" install codex --from "$d/codex-src.json" --dest "$d/codex-auth.json" 2>/dev/null || exit 2
    export MANDU_CI_CODEX_CREDENTIAL="$d/codex-auth.json"
    echo "nightly: --canary-credential: a synthetic token and Codex sign-in, not logins ($MANDU_CI_CLAUDE_CREDENTIAL, $MANDU_CI_CODEX_CREDENTIAL)" >&2
  else
    synthetic sk-ant-api03-CANARY | node "$CI/credential.mjs" install api --provider anthropic --dest "$d/api-keys.json" || exit 2
    synthetic sk-proj-CANARY | node "$CI/credential.mjs" install api --provider openai --dest "$d/api-keys.json" || exit 2
    export MANDU_CI_API_CREDENTIAL="$d/api-keys.json"
    echo "nightly: --canary-credential: synthetic keys, not accounts ($MANDU_CI_API_CREDENTIAL)" >&2
  fi
fi

# The subscription lane's Codex sign-in (§9.8 "The Codex sign-in"): refreshed
# on this host when it no longer covers the run plus two days, or is a week
# old (a canary rehearsal never refreshes: its tokens authenticate nothing).
if [[ $LANE == subscription ]]; then
  need=$((MANDU_CI_TIMEOUT + 300))
  cf="$(node "$CI/credential.mjs" path codex)" || exit 2
  if [[ ! -e "$cf" ]]; then
    echo "nightly: no Codex sign-in on this host ($cf): the ChatGPT-sign-in suites will skip (setup: continuous-integration.md §9.8)" >&2
  else
    if [[ $CANARY -eq 0 ]] && ! node "$CI/credential.mjs" refresh codex --min-seconds $((need + 2 * 86400)); then
      echo "nightly: WARNING: the Codex sign-in was not refreshed (above)" >&2
    fi
    if cmsg="$(node "$CI/credential.mjs" check codex --min-seconds "$need" 2>&1)"; then CRED=claude,codex
    else echo "nightly: WARNING: the Codex sign-in is not usable for this run ($(head -1 <<<"$cmsg" | sed 's/^credential: //')); the lane runs without it and the ChatGPT-sign-in suites will skip" >&2; fi
  fi
fi

"$CI/vm-run.sh" --kind live-drill,env,eval --include-flaky --include-internet \
  --network "${OLLAMA[@]}" --credential "$CRED" --lane "$LANE" "${args[@]}"
