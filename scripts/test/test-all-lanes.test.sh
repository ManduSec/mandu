#!/usr/bin/env bash
#
# test-all-lanes.test.sh — scripts/test-all.sh runs one nightly lane on the host
# (docs/design/testing/test-organization.md §5, continuous-integration.md §9.8):
#   --lane L without --kind is the nightly job of that lane (the nightly kinds
#   and every flaky entry), forwarded as run-suites' --lane; --agents and
#   --drills are forwarded; --drills alone passes no --kind (the drill catalog alone).
#   One lane's credentials per run: `subscription` removes the API-key
#   variables (naming them, never printing a value) and hints at
#   MANDU_CI_CODEX_AUTH when it is unset; `api-key` removes the subscription's
#   token and Codex sign-in path, and loads the secrets file only when a key
#   is unset. Every run hands the runner --watch-store: the caller's watch
#   store, resolved before the MANDU_HOME pin (or the --watch-store given).
#   A lane run stands up the nightly stack (scripts/ci/nightly-stack.sh,
#   continuous-integration.md §9.4) with exactly the environment CI's pipeline.sh
#   --network gives the suites (both run here against the same stubs, their
#   records compared), its sockets under a short directory even when TMPDIR
#   is long, owned by the test-all shell, and torn down when the run ends,
#   on ^C too; an arbiter that does not come up stops the run (exit 5);
#   --no-lane-stack and --dry-run start nothing, nor does a run without a lane.
#   --failures-only / --fail-tail N (MANDU_TEST_FAILURES_ONLY=1,
#   MANDU_TEST_FAIL_TAIL) are forwarded and never reach the suites' environment.
#
# Runs test-all.sh in a throwaway tree with the real scripts/suites.mjs, a small
# manifest, a runner stub that records its argv, which credential variables it
# inherited and the stack's environment, a stub scripts/mandu-env.sh and a stub
# scripts/dev-arbiter.sh (a setsid'd `sleep` stands in for the arbiter: no real
# arbiter, model or credential is used). Needs bash and node.
#
# Run:  bash scripts/test/test-all-lanes.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PASS=0 FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); [ -f "$T/out" ] && sed 's/^/  | /' "$T/out"; [ -f "$T/calls" ] && sed 's/^/  calls: /' "$T/calls"; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

T="$(mktemp -d "${TMPDIR:-/tmp}/test-all-lanes.XXXXXX")"
# Every stand-in arbiter is killed at the end whatever a case left.
trap 'while read -r p; do kill -KILL "$p" 2>/dev/null; done < "$T/all-arbiter-pids" 2>/dev/null; rm -rf "$T"' EXIT
R="$T/repo"
mkdir -p "$R/scripts" "$R/tests"
cp "$REPO/scripts/test-all.sh" "$REPO/scripts/suites.mjs" "$R/scripts/"
# suites.mjs imports the agent registry
mkdir -p "$R/scripts/agents"; cp "$REPO/scripts/agents/agent-registry.mjs" "$R/scripts/agents/"
mkdir -p "$R/scripts/paths"; cp "$REPO/scripts/paths/mandu-paths.sh" "$REPO/scripts/paths/mandu-paths.mjs" "$R/scripts/paths/"
# The nightly stack's helper and, for the comparison, CI's pipeline itself.
mkdir -p "$R/scripts/ci"
cp "$REPO/scripts/ci/"{nightly-stack.sh,pipeline.sh,summary.mjs,collect-results.mjs,replay-retention.mjs,live-events.mjs,ns-run.sh} "$R/scripts/ci/"
cp "$REPO/scripts/drill-tree.mjs" "$R/scripts/"
# The drills are not in the public tree: there the drill-tree resolver finds
# none, the stack's arbiter runs with no policy file (nightly-stack.sh), and
# the checks below expect that. Where this tree has them, the stand-in repo
# gets a drill tree of its own (declared as the source repository declares
# its own) holding a copy of the drill policy.
DRILL_TREE="$(node "$REPO/scripts/drill-tree.mjs" "$REPO" 2>/dev/null)" || DRILL_TREE=""
if [ -n "$DRILL_TREE" ] && [ -f "$DRILL_TREE/live/drill-policy.yaml" ]; then
  mkdir -p "$R/tests/drill-tree/live"
  printf '{ "mandu": { "drillTree": "drill-tree" } }\n' > "$R/tests/package.json"
  cp "$DRILL_TREE/live/drill-policy.yaml" "$R/tests/drill-tree/live/"
  WANT_POLICY="policy drill"
else
  WANT_POLICY="policy OTHER:/dev/null/mandu-test-no-policy.yaml"
fi

cat > "$R/tests/suites.mjs" <<'EOF'
const base = { axis: "secrets", cwd: ".", cmd: ["true"], env: {}, needs: [], timeout: 10, parallel: true,
  gate: null, select: null, flaky: null, internet: false, platforms: ["linux", "darwin"], doc: "x" };
export const entries = [
  { ...base, id: "off", kind: "unit" },
  { ...base, id: "sub", kind: "live-drill", credential: "subscription", needs: ["claude", "claude-login"] },
  { ...base, id: "key", kind: "live-drill", credential: "api-key", needs: ["codex", "openai-api-key"] },
];
EOF
# The runner stub: its argv, then the credential variables it inherited (names
# and whether set; a value only for the one the stub secrets file writes).
cat > "$R/scripts/run-suites.mjs" <<EOF
import { appendFileSync } from "node:fs";
const names = ["ANTHROPIC_API_KEY", "MANDU_E2E_ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CODEX_API_KEY", "MANDU_ULLM_API_KEY",
  "MANDU_TEST_FAILURES_ONLY", "MANDU_TEST_FAIL_TAIL",
  "CLAUDE_CODE_OAUTH_TOKEN", "MANDU_CI_CODEX_AUTH"];
appendFileSync("$T/calls", "argv " + process.argv.slice(2).join(" ") + "\n");
appendFileSync("$T/calls", "env " + names.filter((n) => process.env[n]).join(",") + "\n");
if (process.env.OPENAI_API_KEY === "sk-FROM-SECRETS-FILE") appendFileSync("$T/calls", "openai-from-file\n");
// The stack's environment: the repository root taken off MANDU_BIN (the two
// callers' trees differ), the sockets reduced to their place in the stack.
import { dirname, basename } from "node:path";
import { readFileSync, writeFileSync } from "node:fs";
const root = dirname(dirname(process.argv[1]));
const sock = process.env.MANDU_ARBITER_SOCK ?? "";
const shape = (p) => !p ? "unset" : dirname(p) === dirname(sock) ? "<work>/" + basename(p) : "OTHER:" + p;
appendFileSync("$T/calls", "stack " + [
  "MANDU_ARBITER_SOCK=" + shape(sock),
  "MANDU_ADMIN_SOCK=" + shape(process.env.MANDU_ADMIN_SOCK ?? ""),
  "MANDU_TENANT=" + (process.env.MANDU_TENANT ?? "unset"),
  "MANDU_BIN=" + (process.env.MANDU_BIN ?? "unset").replace(root + "/", "<root>/"),
  "MANDU_TEST_DASHBOARD=" + (process.env.MANDU_TEST_DASHBOARD ?? "unset"),
].join(" ") + "\n");
if (sock) {
  appendFileSync("$T/calls", "sock " + sock + "\n");
  appendFileSync("$T/calls", "socklen " + Buffer.byteLength(sock) + "\n");
  const pid = Number(readFileSync(dirname(sock) + "/pid", "utf8"));
  let alive = true; try { process.kill(pid, 0); } catch { alive = false; }
  appendFileSync("$T/calls", "arbiter-alive " + alive + "\n");
}
appendFileSync("$T/calls", "ppid " + process.ppid + "\n");
// The ^C case: say so, then wait to be interrupted.
if (process.env.STUB_RUNNER_BLOCK) { writeFileSync("$T/runner-started", ""); setInterval(() => {}, 1000); }
EOF
# The dev-arbiter stub: records how it was asked (mode, policy, owner), then
# starts a setsid'd `sleep` as the arbiter (a process group of its own, as the
# real one's setsid'd node daemon), its pid in <work>/pid, and prints the
# real script's export lines. STUB_ARBITER_FAIL=1: it does not come up.
cat > "$R/scripts/dev-arbiter.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# `stop <work>`: recorded, and nothing stopped, so the helper's own group
# kill after it is what the teardown checks below prove.
if [ "${1:-}" = stop ]; then echo "${2:-}" >> "$STUB_T/arbiter-stops"; exit 0; fi
WORK="$1"; mkdir -p "$WORK/home"
{
  echo "mode ${MANDU_MODE:-unset}"
  echo "owner ${MANDU_OWNER_PID:-unset}"
  if cmp -s "${MANDU_POLICY_FILE:-/nonexistent}" "$STUB_DRILL_POLICY"; then echo "policy drill"; else echo "policy OTHER:${MANDU_POLICY_FILE:-unset}"; fi
} >> "$STUB_T/arbiter-calls"
setsid sleep 300 > /dev/null 2>&1 < /dev/null &
echo $! > "$WORK/pid"
echo $! >> "$STUB_T/arbiter-pids"
echo $! >> "$STUB_T/all-arbiter-pids"
echo "arbiter stub log" > "$WORK/arbiter.log"
if [ "${STUB_ARBITER_FAIL:-0}" = 1 ]; then echo "dev-arbiter: did not come up" >&2; exit 1; fi
: > "$WORK/arbiter.sock"
echo "export MANDU_ARBITER_SOCK=\"$WORK/arbiter.sock\""
echo "export MANDU_ADMIN_SOCK=\"$WORK/admin.sock\""
echo "export MANDU_TENANT=test"
echo "export MANDU_DEV_ARBITER_WORK=\"$WORK\""
EOF
chmod +x "$R/scripts/dev-arbiter.sh"
export STUB_T="$T" STUB_DRILL_POLICY="${DRILL_TREE:-/nonexistent}/live/drill-policy.yaml"
# The secrets loader stub: like the real one, it never overrides a set variable.
cat > "$R/scripts/mandu-env.sh" <<'EOF'
[ -n "${OPENAI_API_KEY:-}" ] || export OPENAI_API_KEY=sk-FROM-SECRETS-FILE
echo "[mandu-secrets] loaded OPENAI_API_KEY=sk-FRO…" >&2
EOF
chmod +x "$R/scripts/test-all.sh"

CLEAN=(-u MANDU_TEST_BUILD_NATIVE -u MANDU_CI_REQUIRE_USERNS -u MANDU_TEST_INTEGRITY -u MANDU_TEST_SCOPE -u MANDU_TEST_LOG_DIR
  -u ANTHROPIC_API_KEY -u MANDU_E2E_ANTHROPIC_API_KEY -u OPENAI_API_KEY -u CODEX_API_KEY -u MANDU_ULLM_API_KEY
  -u CLAUDE_CODE_OAUTH_TOKEN -u MANDU_CI_CODEX_AUTH
  -u MANDU_TEST_LANE_STACK -u MANDU_ARBITER_SOCK -u MANDU_ADMIN_SOCK -u MANDU_TENANT -u MANDU_BIN -u MANDU_TEST_DASHBOARD
  -u MANDU_DEV_ARBITER_WORK -u STUB_RUNNER_BLOCK -u STUB_ARBITER_FAIL -u MANDU_CI_GUEST -u MANDU_CI_OFFLINE
  -u MANDU_TEST_FAILURES_ONLY -u MANDU_TEST_FAIL_TAIL)
run() { rm -f "$T/calls" "$T/arbiter-calls" "$T/arbiter-pids"; ( cd "$R" && env "${CLEAN[@]}" MANDU_TEST_BUILD_NATIVE=0 "$@" ) > "$T/out" 2>&1; echo $? > "$T/rc"; }
rc() { cat "$T/rc"; }
argv() { sed -n 's/^argv //p' "$T/calls" 2>/dev/null; }
envs() { sed -n 's/^env //p' "$T/calls" 2>/dev/null; }
says() { grep -qE -- "$1" "$T/out"; }

run env ANTHROPIC_API_KEY=sk-ant-api03-SECRETVALUE OPENAI_API_KEY=sk-SECRETVALUE CODEX_API_KEY=cx-SECRETVALUE \
  CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-TOKENVALUE scripts/test-all.sh --lane subscription
check "subscription: the nightly kinds, every flaky entry, the lane forwarded" \
  '[ "$(rc)" = 0 ] && argv | grep -q -- "--kind live-drill,env,eval --lane subscription" && argv | grep -q -- "--include-flaky --flaky-kinds unit,component,stack,replay-drill,sandbox,live-drill,env,eval"'
check "subscription: the API-key variables are gone, the subscription token stays" '[ "$(envs)" = "CLAUDE_CODE_OAUTH_TOKEN" ]'
check "subscription: one line names what it removed, never a value" \
  'says "lane subscription: removed ANTHROPIC_API_KEY OPENAI_API_KEY CODEX_API_KEY from the environment" && ! grep -q "SECRETVALUE" "$T/out"'
check "subscription: no MANDU_CI_CODEX_AUTH → the hint, not a silent ~/.codex/auth.json" \
  'says "MANDU_CI_CODEX_AUTH is not set" && says "MANDU_CI_CODEX_AUTH=~/.codex/auth.json runs them" && ! envs | grep -q MANDU_CI_CODEX_AUTH'

run env MANDU_CI_CODEX_AUTH=/x/auth.json scripts/test-all.sh --lane subscription
check "subscription: a MANDU_CI_CODEX_AUTH given is kept, no hint, nothing removed" \
  '[ "$(envs)" = "MANDU_CI_CODEX_AUTH" ] && ! says "is not set" && ! says removed'

run scripts/test-all.sh --lane subscription --agents claude
check "subscription --agents claude: no Codex hint; --agents forwarded" '! says MANDU_CI_CODEX_AUTH && argv | grep -q -- "--agents claude"'

run env CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-TOKENVALUE MANDU_CI_CODEX_AUTH=/x/auth.json OPENAI_API_KEY=sk-SET ANTHROPIC_API_KEY=sk-ant-api03-SET \
  scripts/test-all.sh --lane api-key
check "api-key: the lane forwarded; the subscription's token and sign-in path removed, named; the keys kept; no secrets file read" \
  '[ "$(rc)" = 0 ] && argv | grep -q -- "--lane api-key" && [ "$(envs)" = "ANTHROPIC_API_KEY,OPENAI_API_KEY" ] && says "lane api-key: removed CLAUDE_CODE_OAUTH_TOKEN MANDU_CI_CODEX_AUTH" && ! says "secrets file" && ! grep -q TOKENVALUE "$T/out"'

run scripts/test-all.sh --lane api-key
check "api-key: a key unset → the secrets file is loaded, the line names the keys now set" \
  'grep -q openai-from-file "$T/calls" && says "the secrets file was loaded .*keys now set: OPENAI_API_KEY" && ! says "sk-FRO"'

run scripts/test-all.sh --lane nightly
check "an unknown lane is a usage error before anything runs" '[ "$(rc)" = 2 ] && [ ! -f "$T/calls" ] && says "unknown --lane"'

# The retired lane name: never a silent run without the credential handling.
run scripts/test-all.sh --lane api
check "the retired lane name api is a usage error" '[ "$(rc)" = 2 ] && [ ! -f "$T/calls" ] && says "unknown --lane"'

run scripts/test-all.sh --drills util-web-answers,conf-callback-unbound
check "--drills alone: no kind, the ids forwarded (the drill catalog alone)" 'argv | grep -q -- "--drills util-web-answers,conf-callback-unbound" && ! argv | grep -q -- "--kind"'

run scripts/test-all.sh --kind live-drill --lane api-key
check "--kind given with --lane: the kind wins, no implied flaky set" \
  'argv | grep -q -- "--kind live-drill --lane api-key" && ! argv | grep -q -- "--flaky-kinds"'

run scripts/test-all.sh --scope shipping
check "--scope shipping: unit, component and stack" 'argv | grep -q -- "^--kind unit,component,stack --watch-store "'

# --scope is documented (development.md, running-tests.md; test-reorganization.md §11.4).
run scripts/test-all.sh --scope=all
check "--scope=all: the default kinds" 'argv | grep -qx -- "--kind unit,component,stack,sandbox --watch-store .*"'
run env MANDU_TEST_SCOPE=shipping scripts/test-all.sh
check "MANDU_TEST_SCOPE=shipping: unit, component and stack" 'argv | grep -qx -- "--kind unit,component,stack --watch-store .*"'
run env MANDU_TEST_SCOPE=shipping scripts/test-all.sh --kind stack
check "--kind wins over --scope" 'argv | grep -qx -- "--kind stack --watch-store .*"'
run scripts/test-all.sh --scope offline
check "an unknown --scope is a usage error before anything runs" '[ "$(rc)" = 2 ] && [ ! -f "$T/calls" ] && says "unknown --scope"'

run scripts/test-all.sh
check "no lane: the default kinds, no credential handling" 'argv | grep -q -- "^--kind unit,component,stack,sandbox --watch-store " && ! says "lane "'

run scripts/test-all.sh --tier offline
check "the retired --tier is a usage error before anything runs" '[ "$(rc)" = 2 ] && [ ! -f "$T/calls" ]'

# --failures-only (test-organization.md §5): forwarded to the runner, which
# prints the rows (scripts/test/run-suites.test.mjs proves its output); the
# environment knobs are this run's printing only, never the suites'.
run scripts/test-all.sh --failures-only
check "--failures-only: forwarded, no --fail-tail of its own" \
  '[ "$(rc)" = 0 ] && argv | grep -q -- " --failures-only" && ! argv | grep -q -- "--fail-tail"'
run scripts/test-all.sh --fail-tail=12
check "--fail-tail N: forwarded alone, without --failures-only" 'argv | grep -q -- " --fail-tail 12" && ! argv | grep -q -- "--failures-only"'
run env MANDU_TEST_FAILURES_ONLY=1 MANDU_TEST_FAIL_TAIL=10 scripts/test-all.sh
check "MANDU_TEST_FAILURES_ONLY=1 MANDU_TEST_FAIL_TAIL=10: the flags; the suites inherit neither variable" \
  'argv | grep -q -- " --failures-only --fail-tail 10" && ! envs | grep -q MANDU_TEST_FAIL'
run env MANDU_TEST_FAILURES_ONLY=0 scripts/test-all.sh
check "MANDU_TEST_FAILURES_ONLY=0: the default output" '! argv | grep -q -- "--failures-only"'
run scripts/test-all.sh --failures-only --fail-tail lots
check "a --fail-tail that is no number is a usage error before anything runs" '[ "$(rc)" = 2 ] && [ ! -f "$T/calls" ] && says "must be a number of lines"'

# --replay-store (test-reorganization.md §7.3): forwarded, with the CALLER's
# baseline cache resolved before test-all pins MANDU_HOME to /dev/null.
run env HOME=/home/u MANDU_HOME=/srv/caller scripts/test-all.sh --kind replay-drill --replay-store /x/replay
check "--replay-store: forwarded, the baselines the caller's (not the pinned home's)" \
  'argv | grep -q -- "--replay-store /x/replay --replay-baselines /srv/caller/runs/drills/baselines"'
run scripts/test-all.sh --kind replay-drill
check "no --replay-store: no replay flags" '! argv | grep -q -- "--replay"'

# The drill entries' watch store (test-reorganization.md §8.1): the CALLER's
# `live-drill-runs`, resolved before test-all pins MANDU_HOME to /dev/null, so a
# drill run through test-all records where the dashboard looks.
run env HOME=/home/u MANDU_HOME=/srv/caller scripts/test-all.sh --drills util-web-answers
check "--watch-store: the caller's MANDU_HOME's runs/drills/live, never the pinned home's" \
  'argv | grep -q -- "--watch-store /srv/caller/runs/drills/live" && ! argv | grep -q -- "--watch-store /dev/null"'
run env -u MANDU_HOME HOME=/home/u scripts/test-all.sh --kind live-drill
check "--watch-store: no MANDU_HOME → the caller's ~/.mandu/runs/drills/live" 'argv | grep -q -- "--watch-store /home/u/.mandu/runs/drills/live"'
run env HOME=/home/u MANDU_HOME=/srv/caller scripts/test-all.sh --kind live-drill --watch-store /x/watch
check "--watch-store DIR: given, it wins, once" \
  'argv | grep -q -- "--watch-store /x/watch" && [ "$(argv | grep -o -- "--watch-store" | wc -l)" = 1 ]'
rm -f "$T/calls"; mkdir -p "$T/caller"
( cd "$T/caller" && env "${CLEAN[@]}" MANDU_TEST_BUILD_NATIVE=0 "$R/scripts/test-all.sh" --kind live-drill --watch-store w --replay-store r ) > "$T/out" 2>&1
check "a relative --watch-store / --replay-store is the caller's directory, not the repository root" \
  'argv | grep -q -- "--watch-store $T/caller/w" && argv | grep -q -- "--replay-store $T/caller/r"'
run scripts/test-all.sh --kind live-drill --watch-store
check "--watch-store with no directory is a usage error" '[ "$(rc)" = 2 ] && [ ! -f "$T/calls" ]'

# The same through the REAL runner's dry run: the drill entry's argv carries
# --store <the caller's watch store>, never a path under /dev/null.
R2="$T/repo2"
mkdir -p "$R2/scripts/paths" "$R2/scripts/lib" "$R2/tests"
cp "$REPO/scripts/test-all.sh" "$REPO/scripts/suites.mjs" "$REPO/scripts/run-suites.mjs" "$REPO/scripts/tmp-gc.mjs" "$R2/scripts/"
cp "$REPO/scripts/paths/mandu-paths.sh" "$REPO/scripts/paths/mandu-paths.mjs" "$R2/scripts/paths/"
cp "$REPO/scripts/lib/timeout-report.mjs" "$R2/scripts/lib/"
mkdir -p "$R2/scripts/agents"; cp "$REPO/scripts/agents/agent-registry.mjs" "$R2/scripts/agents/"
cat > "$R2/tests/suites.mjs" <<'EOF'
const base = { axis: "secrets", cwd: ".", env: {}, needs: [], timeout: 10, parallel: true,
  gate: null, select: null, flaky: null, internet: false, platforms: ["linux", "darwin"], doc: "x" };
export const entries = [
  { ...base, id: "drill.secrets.util", kind: "live-drill", credential: "subscription", cmd: ["npx", "tsx", "drill-run.ts", "--ids", "util-web-answers"] },
];
EOF
( cd "$R2" && env "${CLEAN[@]}" MANDU_TEST_BUILD_NATIVE=0 HOME=/home/u MANDU_HOME=/srv/caller-home scripts/test-all.sh --only drill.secrets.util --dry-run ) > "$T/out" 2>&1
check "dry run through test-all + run-suites: the drill gets --store <the caller's runs/drills/live>, nothing under /dev/null, no warning" \
  'grep -q "drill\.secrets\.util .*\"--store\",\"/srv/caller-home/runs/drills/live\"" "$T/out" && ! grep -q "\"--store\",\"/dev/null" "$T/out" && ! grep -q "records would go nowhere" "$T/out"'
# run-suites called under the pin with no --watch-store says so on stderr.
( cd "$R2" && env "${CLEAN[@]}" HOME=/home/u MANDU_HOME=/dev/null/mandu-test-home node scripts/run-suites.mjs --only drill.secrets.util --dry-run ) > "$T/out" 2>&1
check "run-suites under the pinned home without --watch-store: the warning" 'grep -q "records would go nowhere" "$T/out"'

# ── the nightly stack (continuous-integration.md §9.4, test-organization.md §5) ──
# A process is alive when /proc has it and it is not a zombie.
alive() { local st; st="$(cut -d' ' -f3 "/proc/$1/stat" 2>/dev/null)"; [ -n "$st" ] && [ "$st" != Z ]; }
stack_line() { sed -n 's/^stack //p' "$T/calls" 2>/dev/null; }
sock_of() { sed -n 's/^sock //p' "$T/calls" 2>/dev/null; }
# Torn down: every stand-in arbiter of the run gone (TERM reaches it within
# the stop's 5 s), and the stack's directory removed.
stack_gone() {
  local p s
  [ -s "$T/arbiter-pids" ] || return 1
  for _ in $(seq 1 30); do
    s=0; while read -r p; do alive "$p" && s=1; done < "$T/arbiter-pids"
    [ $s -eq 0 ] && break; sleep 0.1
  done
  [ $s -eq 0 ] || return 1
  if [ -n "${1:-}" ]; then [ ! -e "$1" ]; fi
}
asked_like_ci() {  # the arbiter request: secrets, the drill policy (none in the public tree), owned by the runner's parent shell
  [ "$(sed -n 's/^mode //p' "$T/arbiter-calls")" = secrets ] && grep -qx "$WANT_POLICY" "$T/arbiter-calls" &&
    [ "$(sed -n 's/^owner //p' "$T/arbiter-calls")" = "$(sed -n 's/^ppid //p' "$T/calls")" ]
}
WANT_STACK="MANDU_ARBITER_SOCK=<work>/arbiter.sock MANDU_ADMIN_SOCK=<work>/admin.sock MANDU_TENANT=test MANDU_BIN=<root>/launcher/mandu-run.sh MANDU_TEST_DASHBOARD=1"

run scripts/test-all.sh --lane subscription
LANE_STACK="$(stack_line)"; work="$(dirname "$(dirname "$(sock_of)")")"
check "lane: the suites get the stack's environment (arbiter and admin sockets, tenant test, MANDU_BIN, MANDU_TEST_DASHBOARD=1)" \
  '[ "$(rc)" = 0 ] && [ "$LANE_STACK" = "$WANT_STACK" ]'
check "lane: the arbiter is asked for as CI asks: secrets, the drill policy, owned by the test-all shell (reapable)" 'asked_like_ci'
check "lane: the arbiter was up while the suites ran" 'grep -qx "arbiter-alive true" "$T/calls"'
check "lane: torn down when the run ends (the arbiter's group gone, its directory removed)" '[ -n "$work" ] && stack_gone "$work"'
check "lane: the teardown asks dev-arbiter.sh to stop its work dir first" '[ -n "$work" ] && grep -qxF "$work/arbiter" "$T/arbiter-stops"'
check "lane: one line says the stack starts, and how to skip it" 'says "the nightly stack .*--no-lane-stack skips it"'

# CI's pipeline (--network: the nightly) against the same stubs: the suites
# must see the same environment, so a host lane run is the nightly's.
rm -f "$T/calls" "$T/arbiter-calls" "$T/arbiter-pids"
( cd "$R" && env "${CLEAN[@]}" HOME="$T/phome" MANDU_HOME="$T/pmandu" bash scripts/ci/pipeline.sh --host --no-build --network \
    --commit 0123456789abcdef0123456789abcdef01234567 --ref test --run-id host-stack --out "$T/pout" ) > "$T/out" 2>&1
PIPE_STACK="$(stack_line)"; work="$(dirname "$(dirname "$(sock_of)")")"
check "pipeline.sh --network gives its suites the same stack environment as test-all.sh --lane" \
  '[ "$PIPE_STACK" = "$WANT_STACK" ] && [ "$PIPE_STACK" = "$LANE_STACK" ]'
check "pipeline.sh: the same arbiter request (secrets, the drill policy, owned by the pipeline's shell)" 'asked_like_ci'
check "pipeline.sh: torn down too, the arbiter's log kept as logs/nightly-arbiter.log" \
  '[ -n "$work" ] && stack_gone "$work" && grep -q "arbiter stub log" "$T/pout/logs/nightly-arbiter.log"'
check "pipeline.sh: its teardown asks dev-arbiter.sh to stop too" '[ -n "$work" ] && grep -qxF "$work/arbiter" "$T/arbiter-stops"'

# A TMPDIR too long for sun_path (a scratch path was, 2026-10-01): the
# sockets go under /tmp instead, within 107 bytes.
LONG="$T/$(printf 'd%.0s' $(seq 1 90))"; mkdir -p "$LONG"
run env TMPDIR="$LONG" scripts/test-all.sh --lane subscription
check "a long TMPDIR: the stack's sockets go under /tmp/mandu-stack.*, within sun_path's 107 bytes" \
  '[ "$(rc)" = 0 ] && sock_of | grep -q "^/tmp/mandu-stack\.[^/]*/arbiter/arbiter\.sock$" && [ "$(sed -n "s/^socklen //p" "$T/calls")" -le 107 ]'
check "a long TMPDIR: still torn down" 'stack_gone "$(dirname "$(dirname "$(sock_of)")")"'

# ^C while the suites run: the whole foreground group gets SIGINT, as a
# terminal sends it; the arbiter (its own session) is stopped by the trap.
rm -f "$T/calls" "$T/arbiter-calls" "$T/arbiter-pids" "$T/runner-started"
cat > "$T/interrupt.mjs" <<'EOF'
import { spawn } from "node:child_process";
import { existsSync, openSync } from "node:fs";
const [cwd, started, out, ...argv] = process.argv.slice(2);
const fd = openSync(out, "w");
const c = spawn("env", argv, { cwd, detached: true, stdio: ["ignore", fd, fd] });
const t0 = Date.now();
const iv = setInterval(() => {
  if (existsSync(started)) { clearInterval(iv); process.kill(-c.pid, "SIGINT"); }
  else if (Date.now() - t0 > 60000) { clearInterval(iv); process.kill(-c.pid, "SIGKILL"); }
}, 50);
c.on("exit", (code, sig) => console.log(code ?? sig));
EOF
node "$T/interrupt.mjs" "$R" "$T/runner-started" "$T/out" "${CLEAN[@]}" MANDU_TEST_BUILD_NATIVE=0 STUB_RUNNER_BLOCK=1 \
  scripts/test-all.sh --lane subscription > "$T/rc" 2>&1
work="$(dirname "$(dirname "$(sock_of)")")"
check "^C during the suites: test-all exits 130 and the stack is torn down" \
  '[ -f "$T/runner-started" ] && [ "$(rc)" = 130 ] && [ -n "$work" ] && stack_gone "$work"'

run env STUB_ARBITER_FAIL=1 scripts/test-all.sh --lane subscription
check "an arbiter that does not come up stops the run (exit 5) before any suite, and what it started is stopped" \
  '[ "$(rc)" = 5 ] && [ ! -f "$T/calls" ] && says "arbiter: did not start" && says "--no-lane-stack" && stack_gone'

run scripts/test-all.sh --lane subscription --no-lane-stack
check "--no-lane-stack: no stack" '[ "$(rc)" = 0 ] && [ ! -f "$T/arbiter-calls" ] && stack_line | grep -q "^MANDU_ARBITER_SOCK=unset .*MANDU_TEST_DASHBOARD=unset$"'
run env MANDU_TEST_LANE_STACK=0 scripts/test-all.sh --lane subscription
check "MANDU_TEST_LANE_STACK=0: no stack" '[ "$(rc)" = 0 ] && [ ! -f "$T/arbiter-calls" ]'
run scripts/test-all.sh --lane api-key --dry-run
check "--dry-run: says it would start the stack, starts nothing" '[ ! -f "$T/arbiter-calls" ] && says "would start the nightly stack"'
run scripts/test-all.sh --kind unit
check "no lane: no stack" '[ ! -f "$T/arbiter-calls" ] && stack_line | grep -q "^MANDU_ARBITER_SOCK=unset"'

echo "test-all-lanes: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
