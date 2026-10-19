#!/usr/bin/env bash
#
# ci-pipeline.test.sh — scripts/ci/pipeline.sh's own summaries (docs/design/
# continuous-integration.md §5, §6): --selftest writes a valid summary without a
# build; --exec runs one command and brings release/ back as
# artifacts/release/ (regular files only); a build failure is a `fail` run
# whose one entry is the build log; an npm ci that cannot run offline is an
# `error` run, "image stale". Every summary goes through the collector (so it
# lands in the runs directory) and must pass its validator and, when the
# dashboard's node_modules are installed, the dashboard's.
#
# Runs pipeline.sh --host in a throwaway copy of scripts/ci (never the real
# checkout: --exec clears release/). Needs node, bash, tar; no network.
#
# Run:  bash scripts/test/ci-pipeline.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PASS=0 FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

T="$(mktemp -d "${TMPDIR:-/tmp}/ci-pipeline.XXXXXX")"; trap 'rm -rf "$T"' EXIT
F="$T/repo"; mkdir -p "$F/scripts/ci" "$F/scripts/test" "$F/scripts/paths"
cp "$REPO/scripts/ci/"{pipeline.sh,nightly-stack.sh,summary.mjs,collect-results.mjs,replay-retention.mjs,live-events.mjs,ns-run.sh,lib.sh} "$F/scripts/ci/"
cp "$REPO/scripts/paths/"{mandu-paths.sh,mandu-paths.mjs} "$F/scripts/paths/"
export HOME="$T/home" MANDU_HOME="$T/mandu"
# The collector's destination: the path table's `ci-runs` under MANDU_HOME.
RUNS="$T/mandu/runs/ci"
mkdir -p "$HOME"
unset MANDU_CI_GUEST MANDU_CI_OFFLINE
SHA=0123456789abcdef0123456789abcdef01234567
P() { bash "$F/scripts/ci/pipeline.sh" --commit "$SHA" --ref test "$@"; }

# validate <run>: the collector's validator and (where this checkout has the
# developer view, scripts/dev-view.mjs, and the dashboard is installed) its CI reader's.
validate() {
  local s="$RUNS/$1/summary.json"
  node --input-type=module -e "
    import { validateSummary } from '$F/scripts/ci/collect-results.mjs';
    import fs from 'node:fs';
    const e = validateSummary(JSON.parse(fs.readFileSync('$s','utf8')), { dirName: '$1' });
    if (e.length) { console.error(e.join('; ')); process.exit(1); }" || return 1
  local tsx="$REPO/dashboard/node_modules/.bin/tsx" dev
  dev="$(node "$REPO/scripts/dev-view.mjs" "$REPO" 2>/dev/null)" || dev=""
  if [[ -x "$tsx" && -n "$dev" ]]; then
    cat > "$T/dash.ts" <<EOF
import { validateSummary } from "$dev/src/ci-runs.ts";
import { readFileSync } from "node:fs";
const v = validateSummary(JSON.parse(readFileSync("$s", "utf8")), "$1");
if (!v.ok) { console.error(v.reason); process.exit(1); }
EOF
    (cd "$REPO/dashboard" && "$tsx" "$T/dash.ts") || return 1
  fi
}
jq_() { node -e "const s=JSON.parse(require('fs').readFileSync('$RUNS/$1/summary.json','utf8')); console.log($2)"; }

# 1. not on a host by accident
bash "$F/scripts/ci/pipeline.sh" --selftest >/dev/null 2>&1
check "without --host (and outside the guest) it refuses (exit 2)" "[[ $? -eq 2 ]]"

# 2. --selftest
P --host --selftest --run-id host-st --out "$T/out-st" > "$T/st.log" 2>&1; rc=$?
check "--selftest exits 0" "[[ $rc -eq 0 ]]"
check "--selftest: a valid summary in the runs dir (collector + dashboard rules)" "validate host-st"
check "--selftest: build skipped, vm skipped (a host run), one probe entry with its log" \
  "[[ \"\$(jq_ host-st 's.stages.build.result+\" \"+s.stages.vm.result+\" \"+s.entries.map(e=>e.id+\":\"+e.result).join(\",\")')\" == 'skip skip selftest.probe:pass' ]] && [[ -s '$RUNS/host-st/logs/selftest.probe.log' ]]"
check "--selftest: the probe records ns-run's bwrap and whether a bwrap nests in it (or why there is none)" \
  "grep -qE '^ns-run: +(bwrap: .*nested-bwrap: (yes|no)|ns-run: no bubblewrap)' '$RUNS/host-st/logs/selftest.probe.log'"
check "--selftest: commit, ref, source and image recorded" "[[ \"\$(jq_ host-st 's.commit+\" \"+s.ref+\" \"+s.source+\" \"+s.image')\" == '$SHA test local host' ]]"

# 3. --exec: a failing command, its release/ comes back (files only)
P --host --no-build --run-id host-ex --out "$T/out-ex" \
  --exec 'mkdir -p release/sub && echo hi > release/a.txt && echo b > release/sub/b.txt && ln -s /etc/passwd release/link && mkfifo release/fifo; echo out; exit 3' \
  > "$T/ex.log" 2>&1; rc=$?
check "--exec with a failing command exits 1" "[[ $rc -eq 1 ]]"
check "--exec: a valid summary" "validate host-ex"
check "the pipeline's own entries carry their label as kind, never tier (selftest, exec)" \
  "[[ \"\$(jq_ host-st 's.entries.map(e=>e.kind+\":\"+(\"tier\" in e)).join()')\" == 'selftest:false' && \"\$(jq_ host-ex 's.entries.map(e=>e.kind+\":\"+(\"tier\" in e)).join()')\" == 'exec:false' ]]"
check "--exec: one entry 'exec', result fail, its log holds the output and the exit status" \
  "[[ \"\$(jq_ host-ex 's.entries.map(e=>e.id+\":\"+e.result+\":\"+e.fail).join()')\" == 'exec:fail:1' ]] && grep -q '^out' '$RUNS/host-ex/logs/exec.log' && grep -q 'exit status 3' '$RUNS/host-ex/logs/exec.log'"
check "--exec: release/ is under artifacts/release/ in the runs dir and --out" \
  "[[ \"\$(cat '$RUNS/host-ex/artifacts/release/a.txt')\" == hi && -f '$RUNS/host-ex/artifacts/release/sub/b.txt' && -f '$T/out-ex/artifacts/release/a.txt' ]]"
check "--exec: a symlink or fifo in release/ is not carried" \
  "[[ ! -e '$RUNS/host-ex/artifacts/release/link' && ! -L '$RUNS/host-ex/artifacts/release/link' && ! -e '$RUNS/host-ex/artifacts/release/fifo' ]]"
P --host --no-build --run-id host-ok --exec 'true' > /dev/null 2>&1
check "--exec with a passing command exits 0" "[[ $? -eq 0 ]] && validate host-ok"
# Without --out a host run writes under the path table's `ci-host-out`:
# $MANDU_HOME/cache/ci/host-out/<run> (on-disk-layout.md §7).
check "no --out: the run's output is under \$MANDU_HOME/cache/ci/host-out/<run>" \
  "[[ -d '$T/mandu/cache/ci/host-out/host-ok/logs' ]]"
MANDU_CI_CACHE="$T/ci-cache" MANDU_CI_RUNS_DIR="$T/ci-runs" P --host --no-build --run-id host-cc --exec 'true' > /dev/null 2>&1
check "the retired MANDU_CI_CACHE / MANDU_CI_RUNS_DIR move nothing" \
  "[[ -d '$T/mandu/cache/ci/host-out/host-cc/logs' && -f '$RUNS/host-cc/summary.json' && ! -e '$T/ci-cache' && ! -e '$T/ci-runs' ]]"
# The runner's MANDU_HOME places the results, but the command never inherits it.
P --host --no-build --run-id host-mh --exec 'echo "home=$MANDU_HOME"' > /dev/null 2>&1
check "--exec runs under the pinned /dev/null test home, not the runner's" \
  "grep -qx 'home=/dev/null/mandu-test-home' '$RUNS/host-mh/logs/exec.log'"

# 4. a build failure: fail, one entry 'build' with the build log
P --host --run-id host-bf > "$T/bf.log" 2>&1; rc=$?
check "a build failure exits 1" "[[ $rc -eq 1 ]]"
check "a build failure: result fail, build stage fail, one entry 'build' with logs/build.log" \
  "validate host-bf && [[ \"\$(jq_ host-bf 's.result+\" \"+s.stages.build.result+\" \"+s.entries.map(e=>e.id+\":\"+e.log).join()')\" == 'fail fail build:logs/build.log' ]]"

# 5. an npm ci that cannot run offline: error, image stale
mkdir -p "$F/pkg"
cat > "$F/pkg/package.json" <<'EOF'
{ "name": "pkg", "version": "1.0.0", "dependencies": { "mandu-ci-no-such-package": "1.0.0" } }
EOF
cat > "$F/pkg/package-lock.json" <<'EOF'
{ "name": "pkg", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": { "": { "name": "pkg", "version": "1.0.0", "dependencies": { "mandu-ci-no-such-package": "1.0.0" } },
    "node_modules/mandu-ci-no-such-package": { "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/mandu-ci-no-such-package/-/mandu-ci-no-such-package-1.0.0.tgz",
      "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" } } }
EOF
MANDU_CI_OFFLINE=1 P --host --run-id host-stale > "$T/stale.log" 2>&1; rc=$?
check "npm ci that cannot run offline exits 2" "[[ $rc -eq 2 ]]"
check "... as an error run whose reason says 'image stale'" \
  "validate host-stale && [[ \"\$(jq_ host-stale 's.result+\" \"+s.stages.build.result')\" == 'error error' ]] && jq_ host-stale 's.reason' | grep -q '^image stale: pkg'"

# 6. the nightly's flags (continuous-integration.md §9): refused shapes; the
# networked run itself is proven in a guest (scripts/ci/nightly.sh --canary-credential)
P --host --no-build --include-internet --exec true > /dev/null 2>&1
check "--include-internet without --network is refused (exit 2)" "[[ $? -eq 2 ]]"
P --host --no-build --network --ollama not-an-addr --exec true > /dev/null 2>&1
check "--ollama takes <ipv4>:<port> (exit 2 otherwise)" "[[ $? -eq 2 ]]"
PL="$F/scripts/ci/pipeline.sh"; pl_use=0
grep -qF 'if [[ $NIGHTLY -eq 0 ]]; then' "$PL" && grep -qF 'args+=(--replay-baseline-mode use --replay-blocking)' "$PL" && grep -qF -- '--replay-baselines-seed "$ROOT/.mandu-ci/baselines"' "$PL" && pl_use=1
check "a per-push run uses master's promoted baselines and blocks on the replay verdict, the nightly records every plain run again and does not (step 5 decision 8, test-reorganization.md §6.9)" "[[ $pl_use -eq 1 ]]"
# The stack's arbiter, MANDU_BIN and MANDU_TEST_DASHBOARD come from the helper
# test-all.sh --lane shares (one copy, so a host lane run is the nightly's;
# scripts/test/test-all-lanes.test.sh runs both against stubs and compares).
check "the nightly stack's arbiter is the shared helper's (nightly-stack.sh), not a dev-arbiter.sh call of the pipeline's own" \
  "grep -q '^\. \"\$CI/nightly-stack.sh\"' '$PL' && grep -q 'nightly_stack_start \"\$ROOT\" \"\$\$\"' '$PL' && grep -q 'nightly_stack_stop \"\$OUT/logs/nightly-arbiter.log\"' '$PL' && ! grep -v '^ *#' '$PL' | grep -q 'dev-arbiter.sh'"
check "a networked run drops ns-run's sandbox and starts the nightly stack; every flaky entry via --flaky-kinds" \
  "grep -q '^\[\[ \$NIGHTLY -eq 1 \]\] || args+=(--sandbox' '$F/scripts/ci/pipeline.sh' && grep -q '^\[\[ \$NIGHTLY -eq 1 \]\] && nightly_stack' '$F/scripts/ci/pipeline.sh' && grep -q -- '--include-flaky --flaky-kinds unit,component,stack,replay-drill,sandbox,live-drill,env,eval' '$F/scripts/ci/pipeline.sh'"

# 6b. the guest's deadline and the heartbeat (continuous-integration.md §3):
# --deadline <epoch s> and the heartbeat go to the runner; a malformed one is
# a usage error before anything runs.
P --host --no-build --deadline soon > "$T/dl.log" 2>&1; rc=$?
check "--deadline that is not epoch seconds: exit 2" "[[ $rc -eq 2 ]] && grep -q -- '--deadline takes seconds since the epoch' '$T/dl.log'"
MANDU_CI_HEARTBEAT=often P --host --no-build > "$T/hb.log" 2>&1; rc=$?
check "MANDU_CI_HEARTBEAT that is not seconds: exit 2" "[[ $rc -eq 2 ]] && grep -q 'MANDU_CI_HEARTBEAT must be seconds' '$T/hb.log'"
check "pipeline.sh hands --deadline and the heartbeat (default 120 s) to run-suites" \
  "grep -qF -- '[[ -n \"\$DEADLINE\" ]] && args+=(--deadline \"\$DEADLINE\")' '$F/scripts/ci/pipeline.sh' && grep -qF -- '[[ \"\$HEARTBEAT\" != 0 ]] && args+=(--heartbeat \"\$HEARTBEAT\")' '$F/scripts/ci/pipeline.sh' && grep -qF 'HEARTBEAT=\"\${MANDU_CI_HEARTBEAT:-120}\"' '$F/scripts/ci/pipeline.sh'"

# 7. the replay records (continuous-integration.md §6): a sandboxed replay-drill
# entry writes its record into its own --bind-rw dir under $OUT/drills/;
# pipeline.sh tidies what it left (a symlink, a fifo, a bad name, a hard link)
# so the archive is not refused; the collector merges the record into the
# host's runs/drills/replay/<run>/ with the run's id, and promotes no baseline
# from a local run. Needs a bubblewrap that can make ns-run's sandbox here
# (inside ns-run, one that nests): else SKIP.
mkdir -p "$F/scripts/lib" "$F/tests"
cp "$REPO/scripts/"{run-suites.mjs,suites.mjs,tmp-gc.mjs} "$F/scripts/"
cp "$REPO/scripts/lib/timeout-report.mjs" "$F/scripts/lib/"
# suites.mjs and run-suites.mjs import the agent registry
mkdir -p "$F/scripts/agents"; cp "$REPO/scripts/agents/agent-registry.mjs" "$F/scripts/agents/"
cat > "$F/tests/suites.mjs" <<'EOF'
const E = (id, kind, script) => ({ id, kind, axis: "off", cwd: ".", cmd: ["bash", "-c", script], needs: [], timeout: 60,
  parallel: true, flaky: null, internet: false, platforms: ["linux"], env: {} });
const record = [
  'echo "baseline mode=${MANDU_REPLAY_BASELINE:-unset} seed=${MANDU_REPLAY_BASELINES_SEED:-unset}"',
  'echo "replay blocking=${MANDU_REPLAY_BLOCKING:-unset}"',
  'R="$MANDU_REPLAY_STORE/$MANDU_REPLAY_RUN_ID"; mkdir -p "$R/sessions" "$R/casts"',
  `echo '{"schema":1,"kind":"mandu-replay-run","runId":"guest-id","commit":"abc1234"}' > "$R/run.json"`,
  `echo '{"schema":1,"kind":"mandu-replay-session","key":"k-claude-80x24","sessionId":"guest-id/k-claude-80x24"}' > "$R/sessions/k-claude-80x24.json"`,
  'echo cast > "$R/casts/k-claude-80x24.mandu.cast"; ln "$R/casts/k-claude-80x24.mandu.cast" "$R/casts/k-claude-80x24.plain.cast"',
  'ln -s /etc/passwd "$R/link"; mkfifo "$R/fifo"; echo x > "$R/bad name.txt"',
  'mkdir -p "$MANDU_REPLAY_BASELINES/bk-1"; echo "{}" > "$MANDU_REPLAY_BASELINES/bk-1/baseline.json"',
  'echo "# pass 1"',
].join("\n");
export const entries = [
  E("rd.one", "replay-drill", record),
  E("u.one", "unit", 'echo "store=${MANDU_REPLAY_STORE:-unset}"; echo "# pass 1"'),
];
export default entries;
EOF
# Inside ns-run (this entry's own sandbox in CI) an overlay over an overlay may
# not mount: the private copy then.
TREE_MODE=""
for m in auto copy; do
  if HOME="$T/home" "$F/scripts/ci/ns-run.sh" --root "$F" --tree "$m" -- true >/dev/null 2>&1; then TREE_MODE="$m"; break; fi
done
if [[ -n "$TREE_MODE" ]]; then
  MANDU_CI_TREE="$TREE_MODE" P --host --no-build --kind replay-drill,unit --run-id host-rp --out "$T/out-rp" > "$T/rp.log" 2>&1; rc=$?
  RP="$T/mandu/runs/drills/replay/host-rp"
  check "replay records: the run passes (exit $rc)" "[[ $rc -eq 0 ]] && validate host-rp"
  check "replay records: the host's store has the run, runId forced to the run's, the session namespaced by it" \
    "grep -q '\"runId\": \"host-rp\"' '$RP/run.json' && grep -q '\"sessionId\": \"host-rp/k-claude-80x24\"' '$RP/sessions/k-claude-80x24.json' && [[ -f '$RP/casts/k-claude-80x24.mandu.cast' && -f '$RP/casts/k-claude-80x24.plain.cast' ]]"
  check "replay records: what the box left that an archive cannot carry was removed (symlink, fifo, name), the hard link copied" \
    "grep -q 'removed (not a file or directory): replay/rd.one/host-rp/link' '$T/out-rp/logs/drills.log' && grep -q 'removed (not a file or directory): replay/rd.one/host-rp/fifo' '$T/out-rp/logs/drills.log' && grep -q 'removed (name): replay/rd.one/host-rp/bad name.txt' '$T/out-rp/logs/drills.log' && grep -q 'unlinked (hard link)' '$T/out-rp/logs/drills.log' && [[ ! -e '$RP/link' && ! -L '$RP/link' ]]"
  check "replay records: runs/ci/<run> holds no drills/; --out (the GitLab artifact) does" \
    "[[ ! -e '$RUNS/host-rp/drills' && -f '$T/out-rp/drills/replay/rd.one/host-rp/run.json' && -f '$T/out-rp/drills/baselines/rd.one/bk-1/baseline.json' ]]"
  check "replay records: a local run promotes no baseline" "[[ ! -e '$T/mandu/runs/drills/baselines' ]] && grep -q 'baselines not promoted: not a default-branch GitLab run' '$T/rp.log'"
  check "replay records: a unit entry gets no store" "grep -qx 'store=unset' '$RUNS/host-rp/logs/u.one.log'"
  rp_use=0; grep -qE '^baseline mode=use seed=(unset|.*/\.mandu-ci/baselines)$' "$RUNS/host-rp/logs/rd.one.log" && rp_use=1
  check "replay records: a per-push run's replay-drill entry uses the promoted baselines (mode use; the tree's .mandu-ci/baselines when vm-run brought them)" "[[ $rp_use -eq 1 ]]"
  check "replay records: a per-push run's replay-drill entry blocks on its replay verdict (MANDU_REPLAY_BLOCKING=1, test-reorganization.md §6.9)" \
    "grep -qx 'replay blocking=1' '$RUNS/host-rp/logs/rd.one.log'"
  check "replay records: drills.log says how full drills/ came, against its caps" \
    "grep -qE '^drills/: [0-9]+ members, [0-9]+ bytes \(caps 3000 members, 268435456 bytes\)$' '$T/out-rp/logs/drills.log' && grep -qE 'collect-results: drills/: [0-9]+ members' '$T/rp.log' && ! grep -q WARNING '$T/rp.log'"
  # Over the cap (lowered for the test): drills/ is dropped, the run still
  # passes, and the drop is said in the pipeline log, the summary (stage
  # `drills: skip`) and the collector's report (the GitLab job log).
  MANDU_CI_TREE="$TREE_MODE" MANDU_CI_DRILLS_MAX_FILES=3 P --host --no-build --kind replay-drill,unit --run-id host-cap --out "$T/out-cap" > "$T/cap.log" 2>&1; rc=$?
  check "over the drills/ cap: the run still passes (exit $rc), its summary valid" "[[ $rc -eq 0 ]] && validate host-cap"
  check "over the drills/ cap: drills/ is dropped whole, no replay record kept, drills.log says how much it held" \
    "[[ ! -e '$T/out-cap/drills' && ! -e '$T/mandu/runs/drills/replay/host-cap' ]] && grep -qE '^dropped drills/: [0-9]+ members, [0-9]+ bytes \(caps 3 members' '$T/out-cap/logs/drills.log'"
  check "over the drills/ cap: the summary records the stage drills: skip, the run's result unchanged" \
    "[[ \"\$(jq_ host-cap 's.stages.drills.result+\" \"+s.result')\" == 'skip pass' ]]"
  check "over the drills/ cap: a WARNING in the pipeline log and in the collector's report" \
    "grep -q 'WARNING: drills/ DROPPED, over its cap' '$T/cap.log' && grep -q 'collect-results: WARNING: the guest DROPPED drills/' '$T/cap.log'"
else
  echo "SKIP: replay records through the sandbox (ns-run.sh cannot make its sandbox here)"
fi

# 8. the nightly's live-drill records (test-reorganization.md §8.1): a drill
# entry of a networked run (unsandboxed, as the nightly's are) records into
# the pipeline's scratch store (its --store, run-suites --watch-store);
# collect_live carries only the record files to drills/live/<drill run>/,
# never the workspace, the arbiter's work dir, a CODEX_HOME, the model
# captures, a symlink or a fifo; the collector puts the run in the host's
# runs/drills/live/<run>.<drill run>/ under that name, a `running` meta marked
# aborted. The networked run's stack fails to start here (no arbiter in this
# copy; logged, as on a guest whose arbiter breaks) and the suites run anyway.
# The drill entry also says what MANDU_KERNEL_TESTS_LOG_DIR it was given.
cat > "$F/tests/suites.mjs" <<'EOF'
const E = (id, kind, script) => ({ id, kind, axis: "secrets", cwd: ".", cmd: ["bash", "-c", script], needs: [], timeout: 60,
  parallel: false, flaky: null, internet: false, platforms: ["linux"], env: {} });
// bash -c SCRIPT --store DIR: $0 is --store, $1 the store.
const drill = [
  'echo "kdir=${MANDU_KERNEL_TESTS_LOG_DIR:-unset}"',
  'S="$1"; R="$S/watch-20261002T000001"; mkdir -p "$R/ws-util-x" "$R/arbiter/events" "$R/codex-home" "$S/watch-nometa" "$S/bad name"',
  `echo '{"runId":"watch-20261002T000001","startedAt":"2026-10-02T00:00:01Z","status":"running","pid":4242,"ids":["util-x"],"settings":["secrets"],"attach":{},"sessions":{"util-x":"watch-20261002T000001-util-x"},"casts":{}}' > "$R/meta.json"`,
  `echo '[{"id":"util-x","title":"x","setting":"secrets","scopeId":"watch-20261002T000001-util-x","cast":"terminal-util-x.cast","t":0,"verdict":"PASS","turns":[]}]' > "$R/chapters.json"`,
  'echo "[]" > "$R/report.json"; echo "# report" > "$R/report.md"; echo log > "$R/run.log"; echo "{}" > "$R/seed-utilx.json"',
  'head -c 4000 /dev/zero | tr "\\0" c > "$R/terminal-util-x.cast"; head -c 3000 /dev/zero | tr "\\0" p > "$R/utilx-1.pane.txt"',
  'echo SECRET-WS > "$R/ws-util-x/.env"; echo SECRET-DB > "$R/arbiter/symbols.db"; echo SECRET-AUTH > "$R/codex-home/auth.json"; echo cap > "$R/model-util-x.ndjson"',
  'ln -s /etc/passwd "$R/terminal-evil.cast"; mkfifo "$R/utilx-2.pane.txt"; echo x > "$S/watch-nometa/run.log"; echo x > "$S/loose-file"',
  // the run's own arbiter's event dir: the named session's log, another's, its log and policy
  `echo '{"seq":1,"kind":"tllm_call","note":"EVENT-LANE"}' > "$R/arbiter/events/watch-20261002T000001-util-x.ndjson"`,
  'echo OTHER-LANE > "$R/arbiter/events/watch-20261002T000001-other.ndjson"; echo ARBITER-LOG > "$R/arbiter/arbiter.log"',
  'echo "# pass 1"',
].join("\n");
export const entries = [E("drill.secrets.fake", "live-drill", drill)];
export default entries;
EOF
LV="$T/mandu/runs/drills/live/host-lv.watch-20261002T000001"
P --host --no-build --network --kind live-drill --run-id host-lv --out "$T/out-lv" > "$T/lv.log" 2>&1; rc=$?
check "live records: the networked run passes (exit $rc), its summary valid" "[[ $rc -eq 0 ]] && validate host-lv"
check "live records: the drill entry recorded into the pipeline's scratch store (its --store), not the guest's home" \
  "grep -q '\"--store\",\"[^\"]*/mandu-ci-pipeline\.[^\"]*/live\"' '$RUNS/host-lv/logs/drill.secrets.fake.log' && [[ ! -e '$HOME/.mandu' ]]"
check "live records: the record files are in --out's drills/live/<drill run>/, nothing else" \
  "[[ \"\$(cd '$T/out-lv/drills/live' && find . -type f | LC_ALL=C sort | tr '\n' ' ')\" == './watch-20261002T000001/chapters.json ./watch-20261002T000001/events-watch-20261002T000001-util-x.ndjson ./watch-20261002T000001/meta.json ./watch-20261002T000001/report.json ./watch-20261002T000001/report.md ./watch-20261002T000001/run.log ./watch-20261002T000001/seed-utilx.json ./watch-20261002T000001/terminal-util-x.cast ./watch-20261002T000001/utilx-1.pane.txt ' ]]"
check "live records: no workspace, arbiter work dir, CODEX_HOME or model capture leaves the run (no SECRET-* under drills/ or the host's drill stores; the entry's log holds its own command)" \
  "! grep -rq 'SECRET-' '$T/out-lv/drills' '$T/mandu/runs/drills' && [[ ! -e '$T/out-lv/drills/live/watch-20261002T000001/ws-util-x' && ! -e '$LV/arbiter' && ! -e '$LV/codex-home' && ! -e '$LV/model-util-x.ndjson' ]]"
check "live records: a symlink, a fifo, a run without meta.json, a bad name and a loose file are left behind, each said in drills.log" \
  "grep -q 'live: watch-20261002T000001/terminal-evil.cast left behind (not a record file)' '$T/out-lv/logs/drills.log' && grep -q 'live: watch-20261002T000001/utilx-2.pane.txt left behind' '$T/out-lv/logs/drills.log' && grep -q 'live: left behind (no meta.json): watch-nometa' '$T/out-lv/logs/drills.log' && grep -q 'live: left behind (not a run directory): bad name' '$T/out-lv/logs/drills.log' && grep -q 'live: left behind (not a run directory): loose-file' '$T/out-lv/logs/drills.log' && [[ ! -e '$LV/terminal-evil.cast' ]]"
check "live records: the host's live store has the run as <CI run>.<drill run>, its meta's runId that name, running → aborted, pid 0" \
  "node -e 'const m=JSON.parse(require(\"fs\").readFileSync(\"$LV/meta.json\",\"utf8\"));process.exit(m.runId===\"host-lv.watch-20261002T000001\"&&m.status===\"aborted\"&&m.pid===0&&m.startedAt===\"2026-10-02T00:00:01Z\"?0:1)' && [[ -f '$LV/chapters.json' && -f '$LV/terminal-util-x.cast' ]]"
check "live records: the run carries ci-run.json naming the CI run; runs/ci/<run> holds no drills/" \
  "grep -q '\"ciRun\": \"host-lv\"' '$LV/ci-run.json' && [[ ! -e '$RUNS/host-lv/drills' ]]"
check "live records: drills.log and the collector say how full drills/live came" \
  "grep -qE '^drills/live: [0-9]+ members, [0-9]+ bytes \(caps 10000 members, 805306368 bytes\); 0 recordings trimmed$' '$T/out-lv/logs/drills.log' && grep -qE 'collect-results: drills/live: [0-9]+ members' '$T/lv.log' && grep -q 'collect-results: live-drill records (1 runs: host-lv.watch-20261002T000001)' '$T/lv.log' && ! grep -q WARNING '$T/lv.log'"
check "the kernel lane's log dir is the run's logs/kernel-tests/, handed to every unsandboxed entry" \
  "grep -qx 'kdir=$T/out-lv/logs/kernel-tests' '$RUNS/host-lv/logs/drill.secrets.fake.log'"
# The event lanes: the own arbiter's log of each session the run names, nothing else of its work dir.
EV="$T/out-lv/drills/live/watch-20261002T000001/events-watch-20261002T000001-util-x.ndjson"
HEV="$LV/events-host-lv.watch-20261002T000001-util-x.ndjson"
check "event lanes: the named session's log is carried (drills.log says so) and lands in the host store under the host's session id; meta and chapters name it" \
  "grep -q EVENT-LANE '$EV' && grep -q EVENT-LANE '$HEV' && grep -qE '^live: event logs: 1 copied, [0-9]+ bytes \(cap 100663296 bytes\)$' '$T/out-lv/logs/drills.log' && grep -q '\"util-x\": \"host-lv.watch-20261002T000001-util-x\"' '$LV/meta.json' && grep -q '\"scopeId\": \"host-lv.watch-20261002T000001-util-x\"' '$LV/chapters.json'"
check "event lanes: another session's log, the arbiter's log and its symbol DB never leave the guest" \
  "! grep -rqE 'OTHER-LANE|ARBITER-LOG|SECRET-DB' '$T/out-lv/drills' '$T/mandu/runs/drills'"
check "event lanes: drills/live is owner-only in the results and in the host store (0700 directories, 0600 files)" \
  "[[ \"\$(stat -c %a '$T/out-lv/drills/live' '$T/out-lv/drills/live/watch-20261002T000001' '$EV' '$T/mandu/runs/drills/live' '$LV' '$HEV' '$LV/meta.json' | tr '\n' ' ')\" == '700 700 600 700 700 600 600 ' ]] && [[ -z \"\$(find '$T/out-lv/drills/live' '$LV' -type f ! -perm 600)\" ]]"
# Over the events budget: the logs are left behind (largest first), the rest of the record kept.
MANDU_CI_LIVE_EVENTS_MAX_BYTES=10 P --host --no-build --network --kind live-drill --run-id host-le --out "$T/out-le" > "$T/le.log" 2>&1; rc=$?
LE="$T/mandu/runs/drills/live/host-le.watch-20261002T000001"
check "over the events budget: the run passes (exit $rc), the log left behind and said (drills.log, a WARNING), the record and the cast kept" \
  "[[ $rc -eq 0 && -f '$LE/meta.json' && -f '$LE/terminal-util-x.cast' ]] && ! ls '$LE' | grep -q '^events-' && grep -q 'the event log of watch-20261002T000001-util-x left behind (over the events cap' '$T/out-le/logs/drills.log' && grep -q 'WARNING: drills/live: 1 event logs left behind, over the events cap of 10 bytes' '$T/le.log'"
# Over the bytes cap: the recordings go first, largest first; the verdicts stay.
MANDU_CI_LIVE_MAX_BYTES=2000 P --host --no-build --network --kind live-drill --run-id host-lt --out "$T/out-lt" > "$T/lt.log" 2>&1; rc=$?
LT="$T/mandu/runs/drills/live/host-lt.watch-20261002T000001"
check "over the drills/live cap: the run passes (exit $rc), the cast and pane trimmed, the record JSON kept" \
  "[[ $rc -eq 0 && ! -e '$LT/terminal-util-x.cast' && ! -e '$LT/utilx-1.pane.txt' && -f '$LT/meta.json' && -f '$LT/chapters.json' ]] && grep -q 'live: trimmed (over the cap): watch-20261002T000001/terminal-util-x.cast (4000 bytes)' '$T/out-lt/logs/drills.log'"
check "over the drills/live cap: a WARNING in the pipeline log, no stage (the run's records are kept)" \
  "grep -q 'WARNING: drills/live over its cap: 2 recordings trimmed' '$T/lt.log' && [[ \"\$(jq_ host-lt 'String(s.stages[\"drills-live\"])')\" == undefined ]]"
# The record files alone over the members cap: dropped whole, said three times.
MANDU_CI_LIVE_MAX_FILES=3 P --host --no-build --network --kind live-drill --run-id host-ld --out "$T/out-ld" > "$T/ld.log" 2>&1; rc=$?
check "record files over the drills/live cap: the run passes (exit $rc), drills/live dropped, no live record kept" \
  "[[ $rc -eq 0 && ! -e '$T/out-ld/drills/live' && ! -e '$T/mandu/runs/drills/live/host-ld.watch-20261002T000001' ]] && grep -qE '^dropped drills/live: [0-9]+ members' '$T/out-ld/logs/drills.log'"
check "record files over the drills/live cap: the stage drills-live: skip, a WARNING in the pipeline log and the collector's report" \
  "[[ \"\$(jq_ host-ld 's.stages[\"drills-live\"].result+\" \"+s.result')\" == 'skip pass' ]] && grep -q 'WARNING: drills/live DROPPED' '$T/ld.log' && grep -q 'collect-results: WARNING: the guest DROPPED drills/live' '$T/ld.log'"

echo
echo "ci-pipeline: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
