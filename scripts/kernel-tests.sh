#!/usr/bin/env bash
#
# kernel-tests.sh — run Mandu's PRIVILEGED Track B kernel-attachment tests via
# the UNPRIVILEGED-USER-NAMESPACE path (no host root, no host pollution, no sudo).
#
# The three OS interceptors (fs-supervisor, net-supervisor, exec-supervisor) carry their
# real kernel-attachment loops behind each crate's `kernel` cargo feature, exercised
# by `#[ignore]`d integration tests. Those tests need privilege the host does NOT
# normally grant the invoking user — seccomp-unotify (CAP_SYS_ADMIN), nftables/TPROXY
# (CAP_NET_ADMIN), namespace+bind-mount setup. This runner obtains all of that WITHOUT
# host root by wrapping each crate's test binary in an UNPRIVILEGED user namespace
# (`unshare --user --map-root-user ...`): the test process becomes root-in-namespace
# with caps scoped to that namespace and to nothing on the host. See
# `docs/design/architecture/privilege-model.md` §2 Tier 1 for why this is the recommended path.
#
# Mapping (which namespaces each crate's loop needs):
#   exec-supervisor  user + mount + NET + pid   (AgentShell net-dead + bind-mount AgentView)
#   net-supervisor        user + mount + NET + pid   (TPROXY redirect inside the agent's own netns)
#   fs-supervisor    user + mount +     pid     (seccomp-unotify; no netns needed)
#
# Behavior (mirrors scripts/test-all.sh's PASS/FAIL summary style, plus SKIP):
#   - PASS : the crate's kernel test(s) ran and passed.
#   - SKIP : a documented, non-failing skip — either unprivileged userns is OFF on
#            this host (the whole runner SKIPs, exit 0), or a kernel-version gate
#            (fs-supervisor's ADDFD `openat` REDIRECT needs kernel ≥ 5.9; on older
#            kernels the test self-SKIPs and prints "SKIP:" — that is NOT a failure).
#   - FAIL : a kernel test actually failed → this runner exits non-zero.
#
# Exit code: 0 unless a REAL failure occurred. Kernel-version / missing-prereq SKIPs
# never fail the run, so this script is safe to invoke on ANY host (including ones
# where unprivileged userns is disabled — it detects that and SKIPs cleanly).
#
# Each crate's cargo `test result:` lines and the tests' own `SKIP:` lines are
# echoed after its row, so a caller (scripts/run-suites.mjs) can count what ran.
#
# Usage:
#   scripts/kernel-tests.sh                    # the #[ignore]d kernel tests via userns
#   scripts/kernel-tests.sh --include-ignored  # the kernel feature IN FULL: also the
#                                              # non-ignored tests, including the ones
#                                              # that compile only under `kernel`
#                                              # (test-organization.md §6.3; the
#                                              # manifest's rust.kernel entry)
#   scripts/kernel-tests.sh --fail-fast | -f
#   scripts/kernel-tests.sh --print-panics <log>  # only print the panics of a saved
#                                              # cargo test log (what a FAIL row shows)
#   scripts/kernel-tests.sh --log-dir DIR      # also keep each crate's full cargo log
#                                              # as DIR/<exec|net|fs>.log (the last 5 MiB)
#
# MANDU_KERNEL_TESTS_LOG_DIR=DIR is --log-dir DIR (the flag wins): the CI
# pipeline sets it to the run's logs/kernel-tests/, so a kernel FAIL in CI has
# its whole log in the run's artifacts, not only the tail and the panics the
# row prints (the working copies live in a temp dir that dies with the guest).
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAIL_FAST=0
PANICS_OF=""
KEEP_LOGS="${MANDU_KERNEL_TESTS_LOG_DIR:-}"
# `--ignored` runs only the #[ignore]d attachment tests; `--include-ignored` runs
# every test of the crate with the `kernel` feature on, inside the namespaces.
TEST_FILTER="--ignored"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--fail-fast) FAIL_FAST=1 ;;
    --include-ignored) TEST_FILTER="--include-ignored" ;;
    --print-panics) PANICS_OF="${2:-}"; shift ;;
    --log-dir) [[ -n "${2:-}" ]] || { echo "kernel-tests: --log-dir needs a directory" >&2; exit 2; }; KEEP_LOGS="$2"; shift ;;
    -h|--help)
      sed -n '2,52p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    * ) echo "kernel-tests: unknown option '$1'" >&2; exit 2 ;;
  esac
  shift
done

# Colors (only if stdout is a TTY).
if [[ -t 1 ]]; then
  C_GRN=$'\033[32m'; C_RED=$'\033[31m'; C_YLW=$'\033[33m'; C_DIM=$'\033[2m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_GRN=""; C_RED=""; C_YLW=""; C_DIM=""; C_BLD=""; C_RST=""
fi

# print_panics <log> — each `thread '<test>' panicked at …` with the lines after
# it (the assertion, left/right) up to the `note:` line, at most 12 lines and 20
# panics. The test name is in the first line.
print_panics() {
  grep -aq "^thread '.*' panicked at " "$1" || return 0
  echo "  ${C_DIM}--- panics in $1 ---${C_RST}"
  awk '
    /^thread .* panicked at / { if (n >= 20) exit; n++; on = 1; k = 0 }
    on { print "  " $0; k++; if ($0 ~ /^note: / || k >= 12) on = 0 }
  ' "$1"
}

if [[ -n "$PANICS_OF" ]]; then
  [[ -r "$PANICS_OF" ]] || { echo "kernel-tests: cannot read '$PANICS_OF'" >&2; exit 2; }
  print_panics "$PANICS_OF"
  exit 0
fi

LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mandu-kernel-tests.XXXXXX")"
trap 'rm -rf "$LOG_DIR"' EXIT
# --log-dir: where each crate's log is kept (absolute: the runner cds below).
if [[ -n "$KEEP_LOGS" ]]; then
  mkdir -p "$KEEP_LOGS" && KEEP_LOGS="$(cd "$KEEP_LOGS" && pwd)" \
    || { echo "kernel-tests: cannot use --log-dir '$KEEP_LOGS'" >&2; exit 2; }
fi
LOG_KEEP_CAP=$((5 * 1024 * 1024))

# keep_log <log>: a copy of the crate's log (its last LOG_KEEP_CAP bytes) in
# --log-dir, named as the working copy; echoes the copy's path, or the working
# copy's when no --log-dir was given.
keep_log() {
  local log="$1" kept
  [[ -n "$KEEP_LOGS" ]] || { echo "$log"; return 0; }
  kept="$KEEP_LOGS/$(basename "$log")"
  if tail -c "$LOG_KEEP_CAP" "$log" > "$kept" 2>/dev/null; then echo "$kept"; else echo "$log"; fi
}

INTERCEPTORS="$REPO_ROOT/interceptors"

# The crate running now (run_kernel_crate) and its log. A SIGTERM or SIGINT
# (run-suites' timeout or the CI deadline, after its timeout report) says
# which crate it stopped, the tests libtest reported as running long, and the
# tail of that crate's log, before the exit: the crate's own output never
# reaches this script's stdout otherwise (continuous-integration.md §3).
CURRENT_LABEL="" CURRENT_LOG=""
on_stop() {
  if [[ -n "$CURRENT_LABEL" && -f "$CURRENT_LOG" ]]; then
    echo "kernel-tests: $1 while $CURRENT_LABEL ran; its log: $CURRENT_LOG"
    local slow
    slow="$(grep -aE '^test .* has been running for over [0-9]+ seconds' "$CURRENT_LOG" | tail -n 10)"
    [[ -n "$slow" ]] && { echo "kernel-tests: running long when stopped:"; sed 's/^/  /' <<<"$slow"; }
    echo "  --- the last 40 lines of $CURRENT_LOG ---"
    tail -n 40 "$CURRENT_LOG" | sed 's/^/  /'
  else
    echo "kernel-tests: $1"
  fi
  [[ "$1" == SIGINT ]] && exit 130
  exit 143
}
trap 'on_stop SIGTERM' TERM
trap 'on_stop SIGINT' INT

# Parallel arrays of results.
declare -a NAMES=()
declare -a STATUS=()   # PASS | FAIL | SKIP
declare -a SUMMARY=()

OVERALL_RC=0

# ── prerequisite detection ─────────────────────────────────────────────────────

have() { command -v "$1" >/dev/null 2>&1; }

# Is an unprivileged user namespace actually usable here? Probe directly — a bare
# sysctl read can lie (seccomp/AppArmor/container policy may still block the call),
# so we attempt the exact unshare we use and check it lands us as root-in-namespace.
userns_ok() {
  unshare --user --map-root-user --mount --net --pid --fork --mount-proc -- \
    bash -c '[[ "$(id -u)" == "0" ]]' >/dev/null 2>&1
}

# ── the runner ─────────────────────────────────────────────────────────────────

# record <label> <status PASS|FAIL|SKIP> <summary>
record() {
  local label="$1" st="$2" sum="$3"
  NAMES+=("$label"); STATUS+=("$st"); SUMMARY+=("$sum")
  case "$st" in
    PASS) printf "  %s✓ PASS%s  %s%s%s\n" "$C_GRN" "$C_RST" "$C_DIM" "$sum" "$C_RST" ;;
    SKIP) printf "  %s∅ SKIP%s  %s%s%s\n" "$C_YLW" "$C_RST" "$C_DIM" "$sum" "$C_RST" ;;
    FAIL) printf "  %s✗ FAIL%s  %s%s%s\n" "$C_RED" "$C_RST" "$C_DIM" "$sum" "$C_RST"; OVERALL_RC=1 ;;
  esac
}

# echo_counts <log> — the crate's cargo `test result:` lines and its tests' own
# `SKIP:` lines, unindented, so an outer runner can sum what actually ran.
# Every grep of a crate's log reads it as text (-a): a test may print raw
# bytes (net-supervisor's git legs print a pack), and grep then calls the log
# binary and prints "binary file matches" instead of the lines. Where that
# byte fell inside grep's first buffer no `test result:` line reached the
# runner and rust.kernel failed its ci.minPass with every test green
# (nightly 11551's kernel-linux-7 job, 256 of 1016 counted).
echo_counts() {
  grep -aE '^(test result:|SKIP:)' "$1" || true
}

# run_kernel_crate <label> <crate> <log-basename> -- <unshare-args...>
# Runs `cargo test -p <crate> --features kernel -- $TEST_FILTER --nocapture` inside the
# given unshare namespaces, then classifies the result into PASS/FAIL/SKIP.
run_kernel_crate() {
  local label="$1"; shift
  local crate="$1"; shift
  local logbase="$1"; shift
  [[ "$1" == "--" ]] && shift
  local unshare_args=("$@")
  local log="$LOG_DIR/$logbase.log"
  # With --log-dir the crate writes its log there AS IT RUNS, so a run stopped
  # mid-crate (a hung test, a CI deadline) keeps it; the working copy below is
  # taken when the crate ends.
  local live="$log"
  [[ -n "$KEEP_LOGS" ]] && live="$KEEP_LOGS/$logbase.log"

  printf "%s▶ %s%s %s(unshare %s -- cargo test -p %s --features kernel -- %s)%s\n" \
    "$C_BLD" "$label" "$C_RST" "$C_DIM" "${unshare_args[*]}" "$crate" "$TEST_FILTER" "$C_RST"

  # The unshare(1) wrapper drops us into root-in-namespace; cargo then runs the
  # crate's #[ignore]d kernel tests. --nocapture so we see the test's own SKIP/PASS
  # diagnostics (e.g. fs-supervisor's "SKIP: ... kernel ≥ 5.9" message).
  CURRENT_LABEL="$label" CURRENT_LOG="$live"
  if unshare "${unshare_args[@]}" -- \
       bash -c "cd '$INTERCEPTORS' && cargo test -p '$crate' --features kernel -- $TEST_FILTER --nocapture" \
       >"$live" 2>&1; then
    local rc=0
  else
    local rc=$?
  fi
  CURRENT_LABEL="" CURRENT_LOG=""
  [[ "$live" == "$log" ]] || cp "$live" "$log"

  # The full log outlives the run where the caller asked for it (--log-dir).
  local kept
  kept="$(keep_log "$log")"

  # Aggregate the cargo "test result:" lines across all targets of this crate.
  # (The integration target carries the kernel tests; lib/doc targets report 0.)
  local passed failed
  passed="$(awk '/^test result:/ { for (i=1;i<=NF;i++) if ($(i+1)=="passed;") p+=$i } END{print p+0}' "$log")"
  failed="$(awk '/^test result:/ { for (i=1;i<=NF;i++) if ($(i+1)=="failed;") f+=$i } END{print f+0}' "$log")"

  # Count the kernel-version / capability SKIPs the test itself prints. The tests
  # emit a line beginning "SKIP:" (then `return`, which the harness scores as ok),
  # so a printed SKIP corresponds to a "passed" that is really a documented skip.
  # (grep -c exits 1 on zero matches; force a clean integer either way.)
  local self_skips
  self_skips="$(grep -ac '^SKIP:' "$log")" || self_skips=0
  self_skips="${self_skips//[^0-9]/}"; self_skips="${self_skips:-0}"

  if [[ $rc -ne 0 || "$failed" -gt 0 ]]; then
    echo_counts "$log"
    record "$label" FAIL "$passed passed; $failed failed (kernel test FAILED — see $kept)"
    # Under --nocapture a panic prints where it happens, mid-log, and the closing
    # `failures:` list names only the test, so the tail alone can miss the cause
    # (the 2026-10-01 routing-test flake: "1 failed" and no message). Print every
    # panic with its message first; the whole log is the --log-dir copy (in CI,
    # the run's logs/kernel-tests/).
    print_panics "$log"
    echo "  ${C_DIM}--- tail of $log ---${C_RST}"
    tail -n 30 "$log" | sed 's/^/  /'
    if [[ $FAIL_FAST -eq 1 ]]; then
      echo "${C_RED}kernel-tests: --fail-fast set; stopping at first failure.${C_RST}" >&2
      print_summary
      exit 1
    fi
    return
  fi

  # rc == 0 and no failures. Distinguish a real-PASS from a version-SKIP.
  echo_counts "$log"
  local real_pass=$(( passed - self_skips ))
  if [[ "$self_skips" -gt 0 ]]; then
    # Surface the first SKIP reason (its leading clause, up to the first ';')
    # so the row is self-explanatory without dumping the whole message.
    local reason
    reason="$(grep -a -m1 '^SKIP:' "$log" | sed 's/^SKIP: *//')"
    record "$label" PASS \
      "$real_pass passed; $self_skips kernel-version SKIP (${reason%%;*})"
  else
    record "$label" PASS "$passed passed; 0 failed"
  fi
}

print_summary() {
  echo
  echo "${C_BLD}════════════════════ kernel-tests (Track B) summary ════════════════════${C_RST}"
  local i
  for i in "${!NAMES[@]}"; do
    case "${STATUS[$i]}" in
      PASS) printf "  %s✓%s  %-22s %s%s%s\n" "$C_GRN" "$C_RST" "${NAMES[$i]}" "$C_DIM" "${SUMMARY[$i]}" "$C_RST" ;;
      SKIP) printf "  %s∅%s  %-22s %s%s%s\n" "$C_YLW" "$C_RST" "${NAMES[$i]}" "$C_DIM" "${SUMMARY[$i]}" "$C_RST" ;;
      FAIL) printf "  %s✗%s  %-22s %s%s%s\n" "$C_RED" "$C_RST" "${NAMES[$i]}" "$C_DIM" "${SUMMARY[$i]}" "$C_RST" ;;
    esac
  done
  echo "${C_BLD}─────────────────────────────────────────────────────────────────────────${C_RST}"
  if [[ $OVERALL_RC -eq 0 ]]; then
    echo "  ${C_GRN}${C_BLD}TRACK B GREEN${C_RST} (kernel-version SKIPs are not failures; fs ADDFD redirect → scripts/kernel-vm.sh)"
  else
    echo "  ${C_RED}${C_BLD}KERNEL TEST FAILURES PRESENT${C_RST} — see the ✗ rows above"
  fi

  # Machine-readable footer (matches scripts/test-all.sh's " passed, N failed"
  # summary regex) so this runner can be folded into test-all as a sub-suite.
  local i np nf ns
  np=0; nf=0; ns=0
  for i in "${!STATUS[@]}"; do
    case "${STATUS[$i]}" in
      PASS) np=$((np + 1)) ;;
      FAIL) nf=$((nf + 1)) ;;
      SKIP) ns=$((ns + 1)) ;;
    esac
  done
  [[ "$ns" -gt 0 ]] && echo "kernel-tests.sh: $ns suite(s) SKIPPED (userns/prereq unavailable — counts green)"
  echo "kernel-tests.sh: $np passed, $nf failed"
}

# ── preflight ──────────────────────────────────────────────────────────────────

echo "${C_BLD}Mandu — privileged Track B kernel tests (via unprivileged userns)${C_RST}"
echo "${C_DIM}host kernel $(uname -r); $(nproc) cpus${C_RST}"
echo

if ! have cargo; then
  record "interceptors (kernel)" SKIP "cargo not on PATH — cannot build the kernel-feature tests"
  print_summary
  exit 0
fi

if ! have unshare; then
  record "interceptors (kernel)" SKIP "unshare(1) not available — cannot enter an unprivileged userns"
  print_summary
  exit 0
fi

if ! userns_ok; then
  echo "${C_YLW}unprivileged user namespaces are unavailable on this host${C_RST}" \
       "${C_DIM}(kernel.unprivileged_userns_clone=0, or seccomp/AppArmor/container policy blocks it).${C_RST}"
  echo "${C_DIM}Track B's privileged tests are SKIPPED cleanly — run them on a host with" \
       "unprivileged userns enabled, or as root. See docs/design/architecture/privilege-model.md §2.${C_RST}"
  echo "${C_DIM}On Ubuntu's AppArmor restriction, a development box can add the developer-only" \
       "unshare grant: sudo scripts/apparmor/install.sh --dev-unshare (scripts/apparmor/README.md).${C_RST}"
  echo
  record "exec-supervisor" SKIP "no unprivileged userns (Tier 1 unavailable)"
  record "net-supervisor"       SKIP "no unprivileged userns (Tier 1 unavailable)"
  record "fs-supervisor"   SKIP "no unprivileged userns (Tier 1 unavailable)"
  print_summary
  exit 0   # a host without userns is not a FAILURE — it is a documented SKIP.
fi

# ── run the three crates' kernel tests, each in its required namespaces ─────────

# exec-supervisor + net-supervisor both exercise the NETWORK boundary → need --net.
# (exec: AgentShell must observe a dead net; net-supervisor: TPROXY lives in the netns.)
# --mount-proc: with `--pid` but the OUTER /proc still mounted, /proc/<pid>
# reads resolve in-namespace pids against OUTER-namespace processes — on this
# host that accidentally hits boot kthreads ("4-312" proc keys), on leaner
# guests the pid does not exist at all and proc_key_for_pid(self) hard-fails
# (found by the OS test matrix on ubuntu-2604). A namespace-local /proc makes
# std::process::id()-keyed reads coherent.
run_kernel_crate "exec-supervisor" exec-supervisor exec -- \
  --user --map-root-user --mount --net --pid --fork --mount-proc
# net-supervisor carries TWO kernel legs behind --features kernel: the (root-only,
# host-global) TPROXY redirect AND the UNPRIVILEGED connect-guard (guard_integration:
# seccomp-unotify connect(2) trap + supervisor-connect — the IP/domain-aware egress
# teeth that close the port-only gap). Both ride this same --net/--pid/--mount-proc
# invocation (the guard needs the netns for lo + a pidns-coherent /proc).
run_kernel_crate "net-supervisor" net-supervisor net -- \
  --user --map-root-user --mount --net --pid --fork --mount-proc
# fs-supervisor traps openat via seccomp-unotify; it needs the mount/pid ns but NOT
# a netns. The ADDFD REDIRECT half self-SKIPs below kernel 5.9 (→ scripts/kernel-vm.sh).
run_kernel_crate "fs-supervisor" fs-supervisor fs -- \
  --user --map-root-user --mount --pid --fork --mount-proc

print_summary
exit $OVERALL_RC
