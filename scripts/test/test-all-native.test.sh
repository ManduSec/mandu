#!/usr/bin/env bash
#
# test-all-native.test.sh — scripts/test-all.sh builds the native bins first
# (docs/design/testing/test-organization.md §3): scripts/build-native.sh runs before
# the runner exactly when a selected entry runs the bins (a replay-drill or
# sandbox entry outside the frozen lane, or `needs: native-bins`), never for a
# unit/component/stack-only run; an
# --only selection counts by what it names; --no-build-native and
# MANDU_TEST_BUILD_NATIVE=0 skip it; --dry-run only says so; a failed build
# stops the run with exit 4 before any entry starts. --out and --run-id reach
# the runner (the dashboard's Tests tab names its results by them).
#
# Runs test-all.sh and the real scripts/suites.mjs in a throwaway tree with a
# small manifest, a recording build-native.sh stub and a recording runner
# stub. Needs bash and node; builds nothing.
#
# Run:  bash scripts/test/test-all-native.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PASS=0 FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); [ -f "$T/out" ] && sed 's/^/  | /' "$T/out"; [ -f "$T/calls" ] && sed 's/^/  calls: /' "$T/calls"; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

T="$(mktemp -d "${TMPDIR:-/tmp}/test-all-native.XXXXXX")"; trap 'rm -rf "$T"' EXIT
R="$T/repo"
mkdir -p "$R/scripts" "$R/tests"
cp "$REPO/scripts/test-all.sh" "$REPO/scripts/suites.mjs" "$R/scripts/"
# suites.mjs imports the agent registry
mkdir -p "$R/scripts/agents"; cp "$REPO/scripts/agents/agent-registry.mjs" "$R/scripts/agents/"

# The manifest: one entry per case. No cwd has a package.json, so test-all
# installs nothing.
cat > "$R/tests/suites.mjs" <<'EOF'
const base = { axis: "off", cwd: ".", cmd: ["true"], env: {}, needs: [], timeout: 10, parallel: true,
  gate: null, select: null, flaky: null, internet: false, platforms: ["linux", "darwin"], doc: "x" };
export const entries = [
  { ...base, id: "off", kind: "unit" },
  { ...base, id: "kern", kind: "sandbox", needs: ["kernel"] },
  { ...base, id: "fake", kind: "replay-drill" },
  { ...base, id: "drill", kind: "live-drill", needs: ["native-bins"] },
  { ...base, id: "model", kind: "env" },
  { ...base, id: "flakyk", kind: "sandbox", needs: ["kernel"], flaky: { reason: "x", since: "2026-09-30" } },
  { ...base, id: "frozenfake", kind: "replay-drill", frozen: true },
];
EOF
# The stubs record their calls, in order, in $T/calls.
cat > "$R/scripts/build-native.sh" <<EOF
#!/usr/bin/env bash
echo build-native >> "$T/calls"
echo "  mandu-net-guard          target/release/mandu-net-guard  (built now)"
[ "\${FAKE_BUILD_FAIL:-0}" = 1 ] && { echo "error[E0425]: cannot find value"; exit 101; }
exit 0
EOF
cat > "$R/scripts/run-suites.mjs" <<EOF
import { appendFileSync } from "node:fs";
appendFileSync("$T/calls", "run-suites " + process.argv.slice(2).join(" ") + "\n");
EOF
chmod +x "$R/scripts/build-native.sh" "$R/scripts/test-all.sh"

run() { rm -f "$T/calls"; ( cd "$R" && env -u MANDU_TEST_BUILD_NATIVE -u MANDU_CI_REQUIRE_USERNS -u MANDU_TEST_INTEGRITY -u MANDU_TEST_SCOPE -u MANDU_TEST_LOG_DIR "$@" ) > "$T/out" 2>&1; echo $? > "$T/rc"; }
ta() { run scripts/test-all.sh "$@"; }
rc() { cat "$T/rc"; }
calls() { cat "$T/calls" 2>/dev/null | cut -d' ' -f1 | tr '\n' ' ' | sed 's/ $//'; }
says() { grep -qE -- "$1" "$T/out"; }

ta --kind unit
check "unit only: no build, the runner runs" '[ "$(rc)" = 0 ] && [ "$(calls)" = "run-suites" ] && ! says build-native'

ta
check "the default kinds (unit,component,stack,sandbox): the build runs first, then the runner" \
  '[ "$(rc)" = 0 ] && [ "$(calls)" = "build-native run-suites" ] && says "scripts/build-native.sh \(1 selected entries" && says "mandu-net-guard"'
check "no build line looks like a suite header to the dashboard's test-all parser (^▶ )" '! grep -q "^▶ " "$T/out"'

ta --kind replay-drill
check "the replay-drill kind builds" '[ "$(calls)" = "build-native run-suites" ]'

ta --kind env
check "a kind that runs no bins builds nothing" '[ "$(calls)" = "run-suites" ]'

ta --only off
check "--only a unit entry: no build" '[ "$(calls)" = "run-suites" ]'

ta --kind unit --only kern
check "--only a sandbox entry builds, whatever --kind says" '[ "$(calls)" = "build-native run-suites" ]'

ta --only drill
check "--only an entry that needs native-bins builds" '[ "$(calls)" = "build-native run-suites" ]'

ta --only frozenfake
check "--only a frozen replay-drill (no native-bins need): no build" '[ "$(calls)" = "run-suites" ]'

ta --kind unit,sandbox --include-flaky
check "--include-flaky counts the flaky sandbox entry too" '[ "$(calls)" = "build-native run-suites" ] && says "\(2 selected entries"'

ta --no-build-native
check "--no-build-native skips the build" '[ "$(rc)" = 0 ] && [ "$(calls)" = "run-suites" ]'

run env MANDU_TEST_BUILD_NATIVE=0 scripts/test-all.sh
check "MANDU_TEST_BUILD_NATIVE=0 skips the build" '[ "$(calls)" = "run-suites" ]'

ta --dry-run
check "--dry-run says it would build and builds nothing" \
  '[ "$(calls)" = "run-suites" ] && says "would run scripts/build-native.sh first" && grep -q -- "--dry-run" "$T/calls"'

run env FAKE_BUILD_FAIL=1 scripts/test-all.sh
check "a failed build stops the run: exit 4, no entry starts, the fix named" \
  '[ "$(rc)" = 4 ] && [ "$(calls)" = "build-native" ] && says "build-native.sh failed" && says "E0425" && says "--no-build-native"'

run env FAKE_BUILD_FAIL=1 scripts/test-all.sh --kind unit
check "a broken build does not touch a unit-only run" '[ "$(rc)" = 0 ] && [ "$(calls)" = "run-suites" ]'

ta --kind unit --out /tmp/x/r1 --run-id 20261002-1010-ab12
check "--out and --run-id reach the runner (the dashboard's Tests tab attributes its runs by them)" \
  'grep -q -- "--out /tmp/x/r1" "$T/calls" && grep -q -- "--run-id 20261002-1010-ab12" "$T/calls"'

ta --only nope
check "an unknown --only id is a usage error before any build" '[ "$(rc)" = 2 ] && [ -z "$(calls)" ]'

# The real manifest: a unit/component/stack run stays free of the build.
check "the real manifest: no unit, component or stack entry runs the native bins" \
  '[ -z "$(cd "$REPO" && node scripts/suites.mjs list --kind unit,component,stack --native-bins --ids)" ]'
check "the real manifest: every kernel-lane entry does" \
  '[ "$(cd "$REPO" && node scripts/suites.mjs list --kind sandbox,replay-drill --need kernel --native-bins --ids)" = "$(cd "$REPO" && node scripts/suites.mjs list --kind sandbox,replay-drill --need kernel --ids)" ]'

echo "test-all-native: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
