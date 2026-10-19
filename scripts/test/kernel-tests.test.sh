#!/usr/bin/env bash
#
# kernel-tests.test.sh — tests for scripts/kernel-tests.sh's failure report:
# `--print-panics <log>` prints each panic of a cargo test log with its message,
# which a FAIL row shows before the log's tail. Under --nocapture a panic prints
# mid-log and the closing `failures:` list names only the test, so the tail
# alone lost the cause of the 2026-10-01 routing-test flake (exec-routing.md §6).
# Needs no userns: the mode reads a saved log and exits.
#
# Run:  bash scripts/test/kernel-tests.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../kernel-tests.sh"

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/kernel-tests-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# A --nocapture log shaped like the failing one: the panic mid-log, other
# tests' output after it, then a tail that names only the test.
cat >"$TMP/fail.log" <<'EOF'
running 27 tests
exec-box AgentShell exit: 126
thread 'exec_box_bin_boxes_agentshell_and_passes_humanshell' panicked at exec-supervisor/tests/kernel_integration.rs:457:5:
assertion `left == right` failed: a boxed command's connect() MUST fail (net-off) — the bin propagates the probe's 7
  left: 126
 right: 7
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test exec_box_bin_boxes_agentshell_and_passes_humanshell ... FAILED
UNRELATED-OUTPUT-AFTER-THE-NOTE
thread 'second_test' panicked at x.rs:1:1:
second message
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
failures:
    exec_box_bin_boxes_agentshell_and_passes_humanshell
    second_test
test result: FAILED. 25 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.79s
EOF

OUT="$(bash "$SCRIPT" --print-panics "$TMP/fail.log" 2>&1)"; RC=$?
[[ $RC -eq 0 ]] && pass "--print-panics exits 0" || fail "--print-panics exits 0 (rc=$RC)"
if grep -q "exec_box_bin_boxes_agentshell_and_passes_humanshell' panicked at" <<<"$OUT" \
  && grep -q "left: 126" <<<"$OUT" && grep -q "right: 7" <<<"$OUT"; then
  pass "the panic is printed with the test's name and the assertion's values"
else
  fail "the panic is printed with the test's name and the assertion's values (out=$OUT)"
fi
grep -q "second message" <<<"$OUT" && pass "every panic is printed" || fail "every panic is printed (out=$OUT)"
if grep -q "UNRELATED-OUTPUT-AFTER-THE-NOTE" <<<"$OUT"; then
  fail "a panic's block stops at its note: line (out=$OUT)"
else
  pass "a panic's block stops at its note: line"
fi
if grep -q "Mandu — privileged" <<<"$OUT"; then
  fail "--print-panics runs no tests (out=$OUT)"
else
  pass "--print-panics runs no tests"
fi

# A passing log: nothing printed.
printf 'test result: ok. 3 passed; 0 failed\n' >"$TMP/ok.log"
OUT="$(bash "$SCRIPT" --print-panics "$TMP/ok.log" 2>&1)"; RC=$?
[[ $RC -eq 0 && -z "$OUT" ]] && pass "a log without panics prints nothing" \
  || fail "a log without panics prints nothing (rc=$RC out=$OUT)"

# A missing log is a usage error, not a silent pass.
OUT="$(bash "$SCRIPT" --print-panics "$TMP/none.log" 2>&1)"; RC=$?
[[ $RC -eq 2 ]] && pass "a missing log exits 2" || fail "a missing log exits 2 (rc=$RC out=$OUT)"

# The FAIL path calls it before the tail.
if grep -A12 'record "$label" FAIL' "$SCRIPT" | grep -q 'print_panics "$log"'; then
  pass "a FAIL row prints the panics before the tail"
else
  fail "a FAIL row prints the panics before the tail"
fi

# --log-dir / MANDU_KERNEL_TESTS_LOG_DIR: each crate's full log is kept there
# (the CI pipeline points it at the run's logs/kernel-tests/, which the results
# archive carries; the working copies die with the guest). Run against stubs:
# an `unshare` that runs its command, an `id` that says root, a `cargo` whose
# net-supervisor run fails with a panic and whose fs-supervisor run writes more
# than the 5 MiB a kept log holds.
STUB="$TMP/stub"; mkdir -p "$STUB"
cat >"$STUB/unshare" <<'EOF'
#!/usr/bin/env bash
while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done
shift
exec "$@"
EOF
cat >"$STUB/id" <<'EOF'
#!/usr/bin/env bash
echo 0
EOF
cat >"$STUB/cargo" <<'EOF'
#!/usr/bin/env bash
crate=""; while [[ $# -gt 0 ]]; do [[ "$1" == -p ]] && crate="$2"; shift; done
case "$crate" in
  exec-supervisor) echo "EXEC-FIRST-LINE"; echo "test result: ok. 4 passed; 0 failed; 0 ignored" ;;
  net-supervisor) echo "NET-FIRST-LINE"
    echo "thread 'guard_refuses' panicked at net-supervisor/tests/guard.rs:9:5:"
    echo "the guard let it through"
    echo "note: run with \`RUST_BACKTRACE=1\` environment variable to display a backtrace"
    echo "test result: FAILED. 2 passed; 1 failed; 0 ignored"; exit 101 ;;
  fs-supervisor) echo "FS-FIRST-LINE"; head -c $((6 * 1024 * 1024)) /dev/zero | tr '\0' 'x'; echo
    echo "test result: ok. 3 passed; 0 failed; 0 ignored" ;;
esac
EOF
chmod +x "$STUB/unshare" "$STUB/id" "$STUB/cargo"
KEPT="$TMP/kept"
OUT="$(PATH="$STUB:$PATH" MANDU_KERNEL_TESTS_LOG_DIR="$KEPT" bash "$SCRIPT" 2>&1)"; RC=$?
[[ $RC -eq 1 ]] && pass "stubbed run: a failing crate fails the run (exit 1)" || fail "stubbed run: a failing crate fails the run (rc=$RC out=$(tail -5 <<<"$OUT"))"
if [[ -f "$KEPT/exec.log" && -f "$KEPT/net.log" && -f "$KEPT/fs.log" ]] \
  && grep -q EXEC-FIRST-LINE "$KEPT/exec.log" && grep -q NET-FIRST-LINE "$KEPT/net.log"; then
  pass "MANDU_KERNEL_TESTS_LOG_DIR keeps every crate's whole log (exec, net, fs)"
else
  fail "MANDU_KERNEL_TESTS_LOG_DIR keeps every crate's whole log (ls=$(ls "$KEPT" 2>&1))"
fi
grep -q "the guard let it through" "$KEPT/net.log" && pass "the kept log of the failing crate holds its panic" \
  || fail "the kept log of the failing crate holds its panic"
grep -q "kernel test FAILED — see $KEPT/net.log" <<<"$OUT" && pass "the FAIL row names the kept log" \
  || fail "the FAIL row names the kept log (out=$(grep FAIL <<<"$OUT"))"
SZ="$(stat -c %s "$KEPT/fs.log" 2>/dev/null || echo 0)"
if [[ "$SZ" -eq $((5 * 1024 * 1024)) ]] && tail -n 1 "$KEPT/fs.log" | grep -q '^test result: ok'; then
  pass "a kept log is capped at its last 5 MiB (the result line kept)"
else
  fail "a kept log is capped at its last 5 MiB (size=$SZ)"
fi
KEPT2="$TMP/kept2"
PATH="$STUB:$PATH" MANDU_KERNEL_TESTS_LOG_DIR="$TMP/not-this" bash "$SCRIPT" --log-dir "$KEPT2" >/dev/null 2>&1
[[ -f "$KEPT2/exec.log" && ! -e "$TMP/not-this" ]] && pass "--log-dir wins over MANDU_KERNEL_TESTS_LOG_DIR" \
  || fail "--log-dir wins over MANDU_KERNEL_TESTS_LOG_DIR"
OUT="$(env -u MANDU_KERNEL_TESTS_LOG_DIR PATH="$STUB:$PATH" TMPDIR="$TMP" bash "$SCRIPT" 2>&1)"
if grep -q "kernel test FAILED — see $TMP/mandu-kernel-tests\..*/net.log" <<<"$OUT" && ! ls -d "$TMP"/mandu-kernel-tests.* >/dev/null 2>&1; then
  pass "without a log dir the logs stay in the temp dir, removed at the end"
else
  fail "without a log dir the logs stay in the temp dir, removed at the end"
fi
bash "$SCRIPT" --log-dir >/dev/null 2>&1
[[ $? -eq 2 ]] && pass "--log-dir without a directory exits 2" || fail "--log-dir without a directory exits 2"

# A crate whose tests print raw bytes (net-supervisor's git legs print a pack,
# NULs and all) before its `test result:` lines: the outer runner sums those
# lines from this script's stdout, so they must come through as text, never as
# grep's "binary file matches" (nightly 11551: rust.kernel counted 256 of 1016
# and failed its ci.minPass with every test green).
cat >"$STUB/cargo" <<'EOF'
#!/usr/bin/env bash
crate=""; while [[ $# -gt 0 ]]; do [[ "$1" == -p ]] && crate="$2"; shift; done
case "$crate" in
  exec-supervisor) echo "test result: ok. 4 passed; 0 failed; 0 ignored" ;;
  net-supervisor) printf 'tcat [0]: PACK\0\0\0\2\0\0\0\6\n'
    echo "SKIP: no go toolchain; the Go leg did not run"
    echo "test result: ok. 700 passed; 0 failed; 0 ignored"
    echo "test result: ok. 60 passed; 0 failed; 0 ignored" ;;
  fs-supervisor) echo "test result: ok. 3 passed; 0 failed; 0 ignored" ;;
esac
EOF
chmod +x "$STUB/cargo"
OUT="$(PATH="$STUB:$PATH" bash "$SCRIPT" 2>&1)"; RC=$?
[[ $RC -eq 0 ]] && pass "a log with raw bytes: the run passes" || fail "a log with raw bytes: the run passes (rc=$RC out=$(tail -5 <<<"$OUT"))"
SUM="$(awk '/^test result:/ { for (i=1;i<=NF;i++) if ($(i+1)=="passed;") p+=$i } END{print p+0}' <<<"$OUT")"
[[ "$SUM" -eq 767 ]] && pass "a log with raw bytes: every crate's test result: line reaches stdout (767)" \
  || fail "a log with raw bytes: every crate's test result: line reaches stdout (sum=$SUM out=$OUT)"
grep -qi "binary file matches" <<<"$OUT" && fail "a log with raw bytes: no grep 'binary file matches' (out=$OUT)" \
  || pass "a log with raw bytes: no grep 'binary file matches'"
grep -q "^SKIP: no go toolchain" <<<"$OUT" && grep -q "759 passed; 1 kernel-version SKIP (no go toolchain)" <<<"$OUT" \
  && pass "a log with raw bytes: its SKIP: line is counted and named" \
  || fail "a log with raw bytes: its SKIP: line is counted and named (out=$OUT)"

# A crate that hangs (rust.kernel in pipelines 10978, 11050 and 11099, killed
# with the guest and nothing kept): stopped by a SIGTERM to its process group
# (run-suites' timeout, the CI deadline), the kept log already holds what the
# crate printed, and the script says which crate it stopped, the tests libtest
# reported as running long, and the log's tail.
cat >"$STUB/cargo" <<EOF
#!/usr/bin/env bash
crate=""; while [[ \$# -gt 0 ]]; do [[ "\$1" == -p ]] && crate="\$2"; shift; done
case "\$crate" in
  exec-supervisor) echo "test result: ok. 4 passed; 0 failed; 0 ignored" ;;
  net-supervisor) echo "running 3 tests"; echo "test quick_one ... ok"
    echo "test a_rename_racing_a_swapped_parent has been running for over 60 seconds"
    : > "$TMP/hanging"; sleep 300 ;;
  *) echo "test result: ok. 1 passed; 0 failed; 0 ignored" ;;
esac
EOF
chmod +x "$STUB/cargo"
KEPT3="$TMP/kept3"
PATH="$STUB:$PATH" setsid bash "$SCRIPT" --log-dir "$KEPT3" >"$TMP/hang.out" 2>&1 &
HPID=$!
for _ in $(seq 1 100); do [[ -e "$TMP/hanging" ]] && break; sleep 0.1; done
kill -TERM -- "-$HPID" 2>/dev/null
wait "$HPID"; RC=$?
OUT="$(cat "$TMP/hang.out")"
[[ $RC -eq 143 ]] && pass "a crate stopped by SIGTERM: the script exits 143" || fail "a crate stopped by SIGTERM: the script exits 143 (rc=$RC out=$OUT)"
grep -q "^kernel-tests: SIGTERM while net-supervisor ran; its log: $KEPT3/net.log$" <<<"$OUT" \
  && pass "it names the crate it stopped and its kept log" || fail "it names the crate it stopped and its kept log (out=$OUT)"
grep -q "^  test a_rename_racing_a_swapped_parent has been running for over 60 seconds$" <<<"$OUT" \
  && pass "it lists the tests libtest reported as running long" || fail "it lists the tests libtest reported as running long (out=$OUT)"
grep -q "^  test quick_one ... ok$" <<<"$OUT" && pass "it prints the log's tail" || fail "it prints the log's tail (out=$OUT)"
grep -q "has been running for over" "$KEPT3/net.log" 2>/dev/null \
  && pass "the kept log of the stopped crate holds what it printed (written as it ran)" \
  || fail "the kept log of the stopped crate holds what it printed (ls=$(ls "$KEPT3" 2>&1))"
[[ ! -e "$KEPT3/fs.log" ]] && pass "no crate runs after the stopped one" || fail "no crate runs after the stopped one"
# The CI pipeline points it at the run's logs/ (kept in the results archive).
grep -q '^export MANDU_KERNEL_TESTS_LOG_DIR="\$OUT/logs/kernel-tests"$' "$HERE/../ci/pipeline.sh" \
  && pass "pipeline.sh keeps the kernel logs in the run's logs/kernel-tests/" \
  || fail "pipeline.sh keeps the kernel logs in the run's logs/kernel-tests/"

echo
echo "kernel-tests.test.sh: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
