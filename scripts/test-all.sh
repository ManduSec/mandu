#!/usr/bin/env bash
#
# test-all.sh — the developer's "run the Mandu test suites" entrypoint: a thin
# wrapper over the suite manifest (tests/suites.mjs) and its runner
# (scripts/run-suites.mjs). docs/design/testing/test-organization.md §5.
#
# It installs any missing node_modules (npm ci where a lockfile exists), then
# runs the manifest's entries of the chosen kinds on THIS host, unsandboxed,
# and prints the per-suite PASS / FAIL / SKIP rows and a summary. It is the
# quick loop, not the proof: CI runs the same manifest in a VM, each entry in
# its own sandbox (docs/design/testing/continuous-integration.md §5, §8).
#
# Default kinds: unit,component,stack,sandbox — everything that needs no agent
# CLI, model or VM (test-reorganization.md §3). The sandbox entries self-SKIP
# where this host refuses unprivileged user namespaces; a SKIP row says so.
#
# When a selected entry runs the launcher's native bins (the replay-drill and
# sandbox kinds, or an entry that needs `native-bins`: `node scripts/suites.mjs
# list --native-bins`), it first runs scripts/build-native.sh, so no entry
# meets a release bin older than its sources (test-organization.md §3). A
# failed build stops the run (exit 4). A unit/component/stack run builds nothing.
#
# Usage:
#   scripts/test-all.sh [--kind <k>[,<k>]] [--only <id>[,<id>]] [--jobs N]
#                       [--lane subscription|api-key] [--agents <a>[,<a>]] [--drills <id>[,<id>]]
#                       [--integrity] [--fail-fast] [--strict-skips] [--tmp-leftovers fail|warn]
#                       [--include-flaky] [--include-internet] [--out DIR] [--run-id ID] [--dry-run]
#                       [--no-build-native] [--no-lane-stack] [--replay-store DIR] [--watch-store DIR]
#                       [--failures-only] [--fail-tail N]
#   scripts/test-all.sh --scope shipping     # = --kind unit,component,stack
#   scripts/test-all.sh --scope all          # = --kind unit,component,stack,sandbox (the default)
#
#   --kind         kinds to run: unit, component, stack, replay-drill, sandbox,
#                  live-drill, env, eval, install (`node scripts/suites.mjs list`;
#                  test-reorganization.md §3)
#   --only         exactly these manifest entries ('*' allowed), whatever their kind
#   --lane L       one nightly lane on THIS host (continuous-integration.md §9.8):
#                  subscription or api-key, the entries whose `credential` it is
#                  (subscription also runs the entries that need no login).
#                  Without --kind it runs what the nightly job of that lane runs:
#                  the kinds live-drill,env,eval plus every flaky entry of the
#                  lane (the internet entries only
#                  with --include-internet). It holds ONE lane's credentials, as
#                  CI's guest does: `subscription` removes the API-key variables
#                  from the environment (ANTHROPIC_API_KEY,
#                  MANDU_E2E_ANTHROPIC_API_KEY, OPENAI_API_KEY, CODEX_API_KEY,
#                  MANDU_ULLM_API_KEY; one line names what it removed) and uses
#                  your logins; its ChatGPT-sign-in Codex suites run only with
#                  MANDU_CI_CODEX_AUTH set (e.g. ~/.codex/auth.json: each run
#                  holds a reduced copy, so it cannot sign you out). `api-key` loads
#                  the keys from the secrets file (scripts/mandu-env.sh) when they
#                  are not set, and drops CLAUDE_CODE_OAUTH_TOKEN and
#                  MANDU_CI_CODEX_AUTH. Unlike CI's guest, this host still has its
#                  ~/.claude login, which the U-LLM of an API-lane scenario may use.
#                  It stands up the nightly's stack first, as CI's pipeline does
#                  (scripts/ci/nightly-stack.sh, continuous-integration.md §9.4): a
#                  `secrets`-mode arbiter of the test tenant with the drill policy
#                  (drill-policy.yaml), started through
#                  scripts/dev-arbiter.sh as this run's (`mandu reap` collects one
#                  a killed run left), its sockets under a short directory, and
#                  MANDU_ARBITER_SOCK, MANDU_ADMIN_SOCK, MANDU_TENANT=test,
#                  MANDU_BIN=launcher/mandu-run.sh and MANDU_TEST_DASHBOARD=1 for
#                  the suites; stopped when the run ends, ^C included. Without it
#                  the claude-e2e cut and codex-e2e skip to green. An arbiter that
#                  does not come up stops the run (exit 5).
#   --no-lane-stack  a --lane run without that stack (MANDU_TEST_LANE_STACK=0 too)
#   --agents A,B   only the entries whose agents are all in the list: claude,
#                  codex, openclaw, opencode, goose (an entry's `agent` and
#                  `ullm`, opencode2 counted as opencode; else its agent CLI or
#                  login needs; an entry driving no agent stays)
#   --drills I,J   narrow the drill entries to these drills (docs/testing/drills.md;
#                  e.g. util-web-answers,conf-callback-unbound); a drill
#                  entry with none of them is left out, an unknown id is an
#                  error. Without --kind or --lane it runs the drill catalog's
#                  entries (the drill.* live-drills).
#   --integrity    also the FROZEN integrity lane's offline part: every package's
#                  test:integrity and the conformance corpus
#                  (docs/design/architecture/protection-modes.md §10). MANDU_TEST_INTEGRITY=1 too.
#   --jobs N       run the parallel-safe entries N at a time (default 1)
#   --fail-fast|-f stop starting entries after the first failure
#   --out DIR      keep summary.json, junit.xml and logs/ there (MANDU_TEST_LOG_DIR
#                  too); otherwise a mandu-suites-* directory in $TMPDIR the
#                  summary names, of which run-suites keeps this user's newest
#                  5 and every one changed in the last 6 h
#                  (MANDU_TEST_KEEP_RESULTS=N|all, MANDU_TEST_KEEP_RESULTS_HOURS=H;
#                  never a live run's; test-organization.md §5)
#   --run-id ID    the run's id in summary.json (run-suites.mjs's; default
#                  local-<time>-<sha>). The dashboard's Tests tab passes its own
#                  run id with --out <results>/<id>, so its Coverage view can
#                  tell which suites the run ran (dashboard.md §4.29)
#   --no-build-native  skip scripts/build-native.sh when the bins are known
#                  fresh (MANDU_TEST_BUILD_NATIVE=0 too); --dry-run only says
#                  whether it would run
#   --failures-only  print only what needs acting on (MANDU_TEST_FAILURES_ONLY=1
#                  too): no row for a suite that passed or skipped; each FAIL
#                  row with the last --fail-tail lines of its log; then the
#                  failed rows again, one counts line (`FAILURES PRESENT: 1
#                  failed, 40 passed, 3 skipped of 44 entries`) and the results
#                  directory. summary.json, junit.xml, logs/ and the exit code
#                  are unchanged: the full output stays on disk. For an agent
#                  session, whose context pays for every PASS row
#                  (test-organization.md §5)
#   --fail-tail N  the lines of a failed suite's log printed under its row
#                  (MANDU_TEST_FAIL_TAIL too; default 40 with --failures-only,
#                  25 without; 0 prints only the log's path)
#   --strict-skips, --include-flaky, --include-internet, --dry-run: run-suites.mjs's
#   --tmp-leftovers fail|warn: run-suites.mjs's. Each entry runs with a fresh
#                  TMPDIR of its own and FAILS when it leaves anything there
#                  or a process running outside its process group (killed)
#                  (the default); `warn` only reports it
#                  (MANDU_TEST_TMP_LEFTOVERS too; test-organization.md §8.5)
#   --replay-store DIR: run-suites.mjs's; the replay-drill entries write their
#                  replay records there (the dashboard reads ~/.mandu/runs/drills/replay;
#                  test-reorganization.md §7.3). Without it they record nothing
#   --watch-store DIR: where the drill entries (drill.*, drill-run.ts) put their
#                  run records (run-suites.mjs's). Default: YOUR watch store,
#                  the path table's `live-drill-runs` (~/.mandu/runs/drills/live, or
#                  $MANDU_HOME/runs/drills/live), resolved before the MANDU_HOME pin
#                  below, so the dashboard's Live drills section lists the run.
#                  A relative DIR (here and for --replay-store) is the caller's.
#
# Environment: MANDU_TEST_SCOPE (all|shipping), MANDU_TEST_INTEGRITY=1,
# MANDU_TEST_LOG_DIR, MANDU_CI_REQUIRE_USERNS=1 (fail when unprivileged userns
# is unavailable instead of letting the kernel entries skip),
# MANDU_TEST_BUILD_NATIVE=0 (= --no-build-native), MANDU_TEST_LANE_STACK=0
# (= --no-lane-stack), MANDU_TEST_FAILURES_ONLY=1 (= --failures-only),
# MANDU_TEST_FAIL_TAIL=N (= --fail-tail N). The last two are this run's
# printing only: they are removed from the suites' environment, so a suite
# that runs test-all.sh or run-suites.mjs itself never inherits them.
#
# Exit: run-suites.mjs's, or 2 (usage), 3 (the userns gate), 4 (the native
# build failed), 5 (the lane's arbiter did not start), 130 / 143 / 129
# (interrupted: SIGINT / SIGTERM / SIGHUP).
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# A relative store path is the caller's, not the repository root's.
CALLER_PWD="$PWD"
caller_abs() { if [[ -z "$1" || "$1" == /* ]]; then printf '%s\n' "$1"; else printf '%s/%s\n' "$CALLER_PWD" "$1"; fi; }
cd "$REPO_ROOT"

KINDS=""
ONLY=""
LANE=""
AGENTS=""
DRILLS=""
INTEGRITY="${MANDU_TEST_INTEGRITY:-0}"
SCOPE="${MANDU_TEST_SCOPE:-}"
OUT="${MANDU_TEST_LOG_DIR:-}"
BUILD_NATIVE="${MANDU_TEST_BUILD_NATIVE:-1}"
LANE_STACK="${MANDU_TEST_LANE_STACK:-1}"
FAILURES_ONLY="${MANDU_TEST_FAILURES_ONLY:-0}"
FAIL_TAIL="${MANDU_TEST_FAIL_TAIL:-}"
# The printing knobs are the caller's, not the suites' (see Environment).
unset MANDU_TEST_FAILURES_ONLY MANDU_TEST_FAIL_TAIL
DRY_RUN=0
WATCH_STORE=""
LIST_FLAGS=()
PASS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--fail-fast) PASS+=(--fail-fast); shift ;;
    --integrity) INTEGRITY=1; shift ;;
    --scope) SCOPE="${2:-}"; shift 2 ;;
    --scope=*) SCOPE="${1#*=}"; shift ;;
    --kind) KINDS="${2:-}"; shift 2 ;;
    --kind=*) KINDS="${1#*=}"; shift ;;
    --only) ONLY="${2:-}"; shift 2 ;;
    --only=*) ONLY="${1#*=}"; shift ;;
    --lane) LANE="${2:-}"; shift 2 ;;
    --lane=*) LANE="${1#*=}"; shift ;;
    --agents) AGENTS="${2:-}"; shift 2 ;;
    --agents=*) AGENTS="${1#*=}"; shift ;;
    --drills) DRILLS="${2:-}"; shift 2 ;;
    --drills=*) DRILLS="${1#*=}"; shift ;;
    --jobs) PASS+=(--jobs "${2:-}"); shift 2 ;;
    --jobs=*) PASS+=(--jobs "${1#*=}"); shift ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --out=*) OUT="${1#*=}"; shift ;;
    --run-id) PASS+=(--run-id "${2:-}"); shift 2 ;;
    --run-id=*) PASS+=(--run-id "${1#*=}"); shift ;;
    --no-build-native) BUILD_NATIVE=0; shift ;;
    --no-lane-stack) LANE_STACK=0; shift ;;
    --dry-run) DRY_RUN=1; PASS+=("$1"); shift ;;
    --include-flaky|--include-internet) LIST_FLAGS+=("$1"); PASS+=("$1"); shift ;;
    --strict-skips) PASS+=("$1"); shift ;;
    --failures-only) FAILURES_ONLY=1; shift ;;
    --fail-tail) FAIL_TAIL="${2:-}"; [[ -n "$FAIL_TAIL" ]] || { echo "test-all: --fail-tail needs a number of lines" >&2; exit 2; }; shift 2 ;;
    --fail-tail=*) FAIL_TAIL="${1#*=}"; [[ -n "$FAIL_TAIL" ]] || { echo "test-all: --fail-tail needs a number of lines" >&2; exit 2; }; shift ;;
    --tmp-leftovers) PASS+=(--tmp-leftovers "${2:-}"); shift 2 ;;
    --tmp-leftovers=*) PASS+=(--tmp-leftovers "${1#*=}"); shift ;;
    --replay-store) PASS+=(--replay-store "$(caller_abs "${2:-}")"); shift 2 ;;
    --replay-store=*) PASS+=(--replay-store "$(caller_abs "${1#*=}")"); shift ;;
    --watch-store) WATCH_STORE="${2:-}"; [[ -n "$WATCH_STORE" ]] || { echo "test-all: --watch-store needs a directory" >&2; exit 2; }; shift 2 ;;
    --watch-store=*) WATCH_STORE="${1#*=}"; [[ -n "$WATCH_STORE" ]] || { echo "test-all: --watch-store needs a directory" >&2; exit 2; }; shift ;;
    -h|--help)
      sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "test-all: unknown option '$1'" >&2; exit 2 ;;
  esac
done

if [[ -n "$SCOPE" && -z "$KINDS" ]]; then
  case "$SCOPE" in
    all) KINDS="unit,component,stack,sandbox" ;;
    shipping) KINDS="unit,component,stack" ;;
    *) echo "test-all: unknown --scope '$SCOPE' (want: all | shipping)" >&2; exit 2 ;;
  esac
fi
[[ "$FAILURES_ONLY" == "1" ]] && PASS+=(--failures-only)
if [[ -n "$FAIL_TAIL" ]]; then
  [[ "$FAIL_TAIL" =~ ^[0-9]+$ ]] || { echo "test-all: --fail-tail (MANDU_TEST_FAIL_TAIL) must be a number of lines, not '$FAIL_TAIL'" >&2; exit 2; }
  PASS+=(--fail-tail "$FAIL_TAIL")
fi
case "$LANE" in
  ""|subscription|api-key) ;;
  *) echo "test-all: unknown --lane '$LANE' (want: subscription | api-key)" >&2; exit 2 ;;
esac
# A lane without --kind is the nightly job of that lane (scripts/ci/nightly.sh:
# the nightly kinds, and every flaky entry, which never fails the run);
# --drills alone is the live-drill kind.
if [[ -z "$KINDS" && -z "$ONLY" && -n "$LANE" ]]; then
  KINDS="live-drill,env,eval"
  LIST_FLAGS+=(--include-flaky)
  PASS+=(--include-flaky --flaky-kinds unit,component,stack,replay-drill,sandbox,live-drill,env,eval)
fi
# --drills alone selects the drill catalog's entries (no --kind: run-suites and
# suites.mjs list read --drills without a kind that way).
DRILLS_ALONE=0
[[ -z "$KINDS" && -z "$ONLY" && -n "$DRILLS" ]] && DRILLS_ALONE=1
[[ $DRILLS_ALONE -eq 1 ]] || KINDS="${KINDS:-unit,component,stack,sandbox}"

command -v node >/dev/null 2>&1 || { echo "test-all: node is not on PATH" >&2; exit 2; }

# ── one lane's credentials (continuous-integration.md §9.8) ────────────────────────
# CI's guest holds one lane's credentials only, so no suite passes on the
# wrong one; a host run of a lane does the same with its
# environment. Names only are printed, never a value.
SUB_STRIP=(ANTHROPIC_API_KEY MANDU_E2E_ANTHROPIC_API_KEY OPENAI_API_KEY CODEX_API_KEY MANDU_ULLM_API_KEY)
API_STRIP=(CLAUDE_CODE_OAUTH_TOKEN MANDU_CI_CODEX_AUTH)
# Unset each named variable (in this shell); STRIPPED lists the ones that were set.
strip_env() {
  STRIPPED=()
  local v
  for v in "$@"; do
    [[ -n "${!v:-}" ]] && STRIPPED+=("$v")
    unset "$v"
  done
}
if [[ "$LANE" == subscription ]]; then
  strip_env "${SUB_STRIP[@]}"
  [[ ${#STRIPPED[@]} -gt 0 ]] && echo "test-all: lane subscription: removed ${STRIPPED[*]} from the environment (the API lane's credentials)"
  if [[ -z "${MANDU_CI_CODEX_AUTH:-}" && ( -z "$AGENTS" || ",$AGENTS," == *,codex,* ) ]]; then
    echo "test-all: lane subscription: MANDU_CI_CODEX_AUTH is not set, so the ChatGPT-sign-in Codex suites skip; MANDU_CI_CODEX_AUTH=~/.codex/auth.json runs them (each run holds a reduced copy of it, so it cannot sign you out)"
  fi
elif [[ "$LANE" == api-key ]]; then
  strip_env "${API_STRIP[@]}"
  [[ ${#STRIPPED[@]} -gt 0 ]] && echo "test-all: lane api-key: removed ${STRIPPED[*]} from the environment (the subscription lane's credentials)"
  if [[ -z "${ANTHROPIC_API_KEY:-}" || -z "${OPENAI_API_KEY:-}" ]]; then
    # It never overrides a variable already set, and prints nothing here.
    # shellcheck source=/dev/null
    source "$REPO_ROOT/scripts/mandu-env.sh" >/dev/null 2>&1
    have=()
    [[ -n "${ANTHROPIC_API_KEY:-}" ]] && have+=(ANTHROPIC_API_KEY)
    [[ -n "${OPENAI_API_KEY:-}" ]] && have+=(OPENAI_API_KEY)
    echo "test-all: lane api-key: a key was not set, so the secrets file was loaded (scripts/mandu-env.sh); keys now set: ${have[*]:-none} (an entry whose key is missing skips)"
    strip_env "${API_STRIP[@]}"
  fi
fi

# ── CI hard gate: require unprivileged userns when asked ──────────────────────
# MANDU_CI_REQUIRE_USERNS=1 turns a host lacking unprivileged userns into a
# FAILURE here instead of letting the kernel entries SKIP into a false green.
if [[ "${MANDU_CI_REQUIRE_USERNS:-0}" == "1" ]]; then
  echo "▶ CI gate: require unprivileged userns"
  if ! "$REPO_ROOT/scripts/require-userns.sh"; then
    echo "test-all: MANDU_CI_REQUIRE_USERNS=1 but unprivileged userns is unavailable — aborting." >&2
    exit 3
  fi
fi

# ── install what is missing ───────────────────────────────────────────────────
# `npm ci` (lockfile-exact, atomic) wherever a package-lock.json exists — a
# resolve-at-test-time `npm install` is nondeterministic and broke the
# 2026-07-04 nightly with an incomplete tree. Deliberately NO --prefer-offline:
# a corrupt npm cache once made even `npm ci` emit an esbuild-less tree with
# exit 0 — installs here revalidate against the registry. A failed install is
# reported; the package's entries then fail on their own.
INSTALL_LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mandu-test-all-install.XXXXXX")"
# The lane's stack (below) is stopped whichever way the run ends.
STACK_LOG_COPY=""
cleanup() {
  if declare -F nightly_stack_stop >/dev/null; then nightly_stack_stop ${STACK_LOG_COPY:+"$STACK_LOG_COPY"}; fi
  rm -rf "$INSTALL_LOG_DIR"
}
trap cleanup EXIT
trap 'cleanup; trap - EXIT; exit 130' INT
trap 'cleanup; trap - EXIT; exit 143' TERM
trap 'cleanup; trap - EXIT; exit 129' HUP
while IFS= read -r dir; do
  [[ -n "$dir" && ! -d "$dir/node_modules" ]] || continue
  inst=(npm install)
  [[ -f "$dir/package-lock.json" ]] && inst=(npm ci --no-audit --no-fund)
  log="$INSTALL_LOG_DIR/$(echo "$dir" | tr '/' '_').log"
  echo "⚠ deps not installed in $dir — running '${inst[*]}'"
  if ! ( cd "$dir" && "${inst[@]}" >"$log" 2>&1 ); then
    echo "✗ '${inst[*]}' failed in $dir:" >&2
    tail -n 20 "$log" | sed 's/^/  /' >&2
  fi
done < <(node scripts/suites.mjs packages)

# ── the frozen integrity lane (docs/design/architecture/protection-modes.md §10) ──────────────
# --integrity adds the frozen entries that need nothing beyond an offline run
# (each package's test:integrity, the conformance corpus). The frozen lane's
# agent / model / drill entries run only by an explicit run-suites `--frozen`.
SELECT=()
[[ -n "$KINDS" ]] && SELECT=(--kind "$KINDS")
if [[ "$INTEGRITY" == "1" && -z "$ONLY" && $DRILLS_ALONE -eq 0 ]]; then
  platform="$(node -p process.platform)"
  base_ids="$(node scripts/suites.mjs list --kind "$KINDS" --platform "$platform" --ids)" || exit 2
  frozen_ids="$(node scripts/suites.mjs list --frozen --platform "$platform" --needs-within offline --ids)" || exit 2
  ONLY="$(printf '%s,%s' "$base_ids" "$frozen_ids" | sed 's/^,//; s/,$//')"
  SELECT=(--kind "$KINDS" --frozen)
fi
[[ -n "$ONLY" ]] && SELECT+=(--only "$ONLY")
[[ -n "$LANE" ]] && SELECT+=(--lane "$LANE")
[[ -n "$AGENTS" ]] && SELECT+=(--agents "$AGENTS")
[[ -n "$DRILLS" ]] && SELECT+=(--drills "$DRILLS")
[[ -n "$OUT" ]] && PASS+=(--out "$OUT")

# ── the native bins (test-organization.md §3) ───────────────────────────────
# The sandbox kind's `cargo test --features kernel` relinks the debug bins
# mid-run; a release bin from before a source change once won a newest-by-mtime
# pick and faked a setxattr leak (2026-09-29). The guard tests now refuse a
# stale build (tests/lib/native-guard.ts); building first keeps
# the run from going red on it at all. CI's pipeline builds them in its own
# build stage (scripts/ci/pipeline.sh) and calls run-suites.mjs directly.
if [[ "$BUILD_NATIVE" != "0" ]]; then
  native_ids="$(node scripts/suites.mjs list "${SELECT[@]}" --platform "$(node -p process.platform)" \
    --native-bins --ids ${LIST_FLAGS[@]+"${LIST_FLAGS[@]}"})" || exit 2
  if [[ -n "$native_ids" ]]; then
    n_native="$(tr ',' '\n' <<<"$native_ids" | wc -l | tr -d ' ')"
    # `⚙`, not `▶`: the dashboard's test-all parser reads `▶ <label> (<cmd>)`
    # as a suite header (the developer view's test-output-parse.ts).
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "⚙ would run scripts/build-native.sh first ($n_native selected entries run the native bins)"
    else
      echo "⚙ scripts/build-native.sh ($n_native selected entries run the native bins; --no-build-native skips it)"
      native_log="$INSTALL_LOG_DIR/build-native.log"
      if ! "$REPO_ROOT/scripts/build-native.sh" >"$native_log" 2>&1; then
        echo "✗ scripts/build-native.sh failed; the entries that run the native bins would meet a stale or missing build:" >&2
        tail -n 20 "$native_log" | sed 's/^/  /' >&2
        echo "test-all: fix the build, or pass --no-build-native (MANDU_TEST_BUILD_NATIVE=0) when the bins are known fresh." >&2
        exit 4
      fi
      [[ "$FAILURES_ONLY" == "1" ]] || grep -E '^  mandu-' "$native_log" || true
    fi
  fi
fi

# The caller's paths, resolved before the pin below hides the caller's home
# (test-reorganization.md §6.3, §7.3, §8.1): the replay records' baselines go
# to the CALLER's cache, and every drill entry's run record to the CALLER's
# watch store (run-suites.mjs --watch-store; under the pin it would resolve
# to /dev/null/mandu-test-home/runs/drills/live and record nowhere).
# shellcheck source=scripts/paths/mandu-paths.sh
. "$REPO_ROOT/scripts/paths/mandu-paths.sh"
if [[ " ${PASS[*]+"${PASS[*]}"} " == *" --replay-store "* ]]; then
  PASS+=(--replay-baselines "$(mandu_path drill-baselines)")
fi
PASS+=(--watch-store "$(caller_abs "${WATCH_STORE:-$(mandu_path live-drill-runs)}")")

# ── the lane's stack (continuous-integration.md §9.4) ─────────────────────────────
# What CI's pipeline starts for a nightly lane, through the same helper
# (scripts/ci/nightly-stack.sh): the test tenant's `secrets` arbiter with the
# drill policy, MANDU_BIN and MANDU_TEST_DASHBOARD=1. Without it the
# claude-e2e cut and codex-e2e skip to green on a host. Started before the
# MANDU_HOME pin below (dev-arbiter.sh gives the arbiter a home of its own and
# keeps the real runtime dir, so `mandu status` lists it and `mandu reap`
# collects it should this shell die past its traps); owned by this shell,
# which then waits for the runner instead of exec'ing it, so the traps above
# stop the stack.
STACK_UP=0
if [[ -n "$LANE" && "$LANE_STACK" != "0" ]]; then
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "⚙ would start the nightly stack (a secrets arbiter of the test tenant with the drill policy, MANDU_BIN, MANDU_TEST_DASHBOARD=1; --no-lane-stack skips it)"
  else
    echo "⚙ the nightly stack (scripts/ci/nightly-stack.sh; --no-lane-stack skips it)"
    # shellcheck source=scripts/ci/nightly-stack.sh
    . "$REPO_ROOT/scripts/ci/nightly-stack.sh" || exit 5
    if [[ -n "$OUT" ]] && mkdir -p "$OUT/logs" 2>/dev/null; then STACK_LOG_COPY="$OUT/logs/nightly-arbiter.log"; fi
    STACK_UP=1
    nightly_stack_start "$REPO_ROOT" "$$" > "$INSTALL_LOG_DIR/nightly-stack.log" 2>&1
    stack_rc=$?
    sed 's/^/  /' "$INSTALL_LOG_DIR/nightly-stack.log"
    if [[ $stack_rc -ne 0 ]]; then
      echo "test-all: the lane's arbiter did not start, so its suites would skip to green; fix it, or pass --no-lane-stack (MANDU_TEST_LANE_STACK=0)." >&2
      exit 5
    fi
  fi
fi

# No suite inherits a real Mandu home (on-disk-layout.md §9): run-suites.mjs
# pins this for every entry (FIXED_ENV); the runner itself gets it too.
export MANDU_HOME=/dev/null/mandu-test-home
# An exec skips the EXIT trap: remove the install logs first (they were
# printed where they mattered), or every run leaves one behind in $TMPDIR.
if [[ $STACK_UP -eq 0 ]]; then
  rm -rf "$INSTALL_LOG_DIR"
  exec node scripts/run-suites.mjs "${SELECT[@]}" ${PASS[@]+"${PASS[@]}"}
fi
node scripts/run-suites.mjs "${SELECT[@]}" ${PASS[@]+"${PASS[@]}"}
exit $?
