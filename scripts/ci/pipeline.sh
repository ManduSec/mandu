#!/usr/bin/env bash
# pipeline.sh — the ONE entry point of a CI run (docs/design/testing/continuous-integration.md
# §5, §8): in the CI guest (mandu-ci.service's boot.sh runs it as user `ci`)
# and, with --host, on a developer's machine without KVM.
#
#   scripts/ci/pipeline.sh (--host | in the guest) [--kind k[,k]] [--need n] [--only id[,id]]
#       [--jobs N] [--kernel-jobs N] [--run-id ID] [--source local|gitlab] [--commit SHA]
#       [--ref REF] [--image NAME] [--out DIR] [--no-build]
#       [--selftest | --exec 'COMMAND']
#       [--network] [--ollama ADDR] [--include-flaky] [--include-internet]
#       [--deadline EPOCH_S]
#
# Stages:
#   1. build (logs/build.log): `npm ci` in every package whose node_modules is
#      missing or was installed from another package-lock.json (the stamp
#      node_modules/.mandu-ci-lock holds the lockfile's sha256); `cargo build
#      --tests` at default features and with `--features kernel`;
#      scripts/build-native.sh. In the guest (MANDU_CI_OFFLINE=1) npm and cargo
#      run --offline from the image's warm caches: an npm ci that cannot is the
#      run's `error` with reason "image stale", never a reach for the network.
#      Any other build failure ends the run as `fail`, with the build log as
#      its one entry (id `build`).
#   2. the suites: scripts/run-suites.mjs with --sandbox scripts/ci/ns-run.sh,
#      the build stage passed in (--stages-json), and --strict-skips in the
#      guest. The kernel lane runs beside the parallel stage, its `parallel:
#      true` entries --kernel-jobs at a time (default 3,
#      continuous-integration.md §5.2); scripts/kernel-tests.sh keeps its full
#      per-crate cargo logs in logs/kernel-tests/ (MANDU_KERNEL_TESTS_LOG_DIR).
#      --deadline EPOCH_S (the guest's, boot.sh) goes to the runner: what still
#      runs then is stopped as a timeout and the summary written (§3); every
#      MANDU_CI_HEARTBEAT seconds (default 120, 0 none) the runner names the
#      entries still running.
#      Every live-drill entry records into a scratch store (run-suites
#      --watch-store), whose record files alone, and the event log of each
#      session a run names (from the run's own arbiter), collect_live copies to
#      drills/live/<drill run>/ for the collector (the nightly's drill runs on
#      the dashboard, continuous-integration.md §6). In --host mode there is no --strict-skips: the kernel lane is not
#      equivalent on a host that restricts user namespaces, and the summary
#      records the stage `vm` as `skip` to say the run was not in the VM.
#   --selftest skips 1 and 2 and writes a summary of its own (the VM plumbing
#      check): an entry `selftest.probe` with the guest's facts and, in the
#      guest, `selftest.ns-run` (scripts/test/ci-ns-run.test.sh, the sandbox's
#      isolation proof on the guest's own bwrap).
#   --exec runs COMMAND (bash -c, cwd the checkout, as this user, unsandboxed,
#      with MANDU_CI_COMMIT and MANDU_CI_REF set: the guest's checkout has no
#      .git) after the build instead of the suites: one entry `exec`; whatever
#      it leaves under release/ is copied to <out>/artifacts/release/.
#
# The nightly (vm-run.sh --network, continuous-integration.md §9):
#   --network (or --ollama)   the guest has a network: the suites run UNSANDBOXED (ns-run's
#      loopback-only namespace and empty $HOME would take away the network and
#      the credential they exist to use; the guest is their boundary, as it is
#      the kernel entries'), and a nightly stack is started first (logs/
#      nightly-stack.log): a `secrets`-mode arbiter of the test tenant
#      (scripts/dev-arbiter.sh, with the drill labels of drill-runner.md §2
#      as its policy; scripts/ci/nightly-stack.sh, which a host
#      `test-all.sh --lane` shares) exported as MANDU_ARBITER_SOCK / MANDU_ADMIN_SOCK (the
#      drill entries start their own instead: drill-run.ts --own-arbiter), the
#      launcher as MANDU_BIN, MANDU_TEST_DASHBOARD=1, and a claude config that
#      skips the first-run screens. Stopped when the run ends.
#   --ollama ADDR   the host's Ollama as the guest sees it (10.0.2.100:11434):
#      relayed to 127.0.0.1:11434 in the guest, where every local-model suite
#      looks by default (scripts/ci/port-bridge.mjs relay)
#   --include-flaky     every `flaky` entry of every kind runs too, never
#      failing the run (run-suites --flaky-kinds)
#   --include-internet  the selected kinds' `internet` entries run too
#   --lane subscription|api-key   the nightly lane (§9.8): only the selected
#      entries holding that credential (run-suites --lane). The API lane's keys, which the
#      guest's boot.sh placed, are exported as ANTHROPIC_API_KEY /
#      OPENAI_API_KEY for the suites (never printed); the subscription lane's
#      reduced Codex sign-in is named by MANDU_CI_CODEX_AUTH
#
# In --host mode the results then go through scripts/ci/collect-results.mjs,
# like a VM run's, so they land in the same runs directory (source local).
#
# Exit: 0 pass, 1 fail, 2 error (--host: the collector's status).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CI="$ROOT/scripts/ci"
# shellcheck source=scripts/paths/mandu-paths.sh
. "$ROOT/scripts/paths/mandu-paths.sh"
# nightly_stack_start / nightly_stack_stop: the arbiter, MANDU_BIN and
# MANDU_TEST_DASHBOARD, shared with scripts/test-all.sh --lane.
# shellcheck source=scripts/ci/nightly-stack.sh
. "$CI/nightly-stack.sh"

HOST=0 SELFTEST=0 NOBUILD=0 EXEC=""
KINDS="unit,component,stack,replay-drill,sandbox" NEED="" ONLY="" JOBS="" KJOBS="${MANDU_CI_KERNEL_JOBS:-3}" RUN_ID="" SOURCE="local"
COMMIT="" REF="" IMAGE="" OUT="" NETWORK=0 OLLAMA="" INC_FLAKY=0 INC_INTERNET=0 LANE="" DEADLINE=""
# Every this many seconds the runner names the entries still running (§3: an
# entry's line comes only when it ends, so a hung one is otherwise silent).
HEARTBEAT="${MANDU_CI_HEARTBEAT:-120}"

usage() { sed -n '6,11p' "$0" >&2; exit 2; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST=1; shift ;;
    --selftest) SELFTEST=1; shift ;;
    --no-build) NOBUILD=1; shift ;;
    --exec) [[ $# -ge 2 ]] || usage; EXEC="$2"; shift 2 ;;
    --kind) [[ $# -ge 2 ]] || usage; KINDS="$2"; shift 2 ;;
    --need) [[ $# -ge 2 ]] || usage; NEED="$2"; shift 2 ;;
    --only) [[ $# -ge 2 ]] || usage; ONLY="$2"; shift 2 ;;
    --jobs) [[ $# -ge 2 ]] || usage; JOBS="$2"; shift 2 ;;
    --kernel-jobs) [[ $# -ge 2 ]] || usage; KJOBS="$2"; shift 2 ;;
    --run-id) [[ $# -ge 2 ]] || usage; RUN_ID="$2"; shift 2 ;;
    --source) [[ $# -ge 2 ]] || usage; SOURCE="$2"; shift 2 ;;
    --commit) [[ $# -ge 2 ]] || usage; COMMIT="$2"; shift 2 ;;
    --ref) [[ $# -ge 2 ]] || usage; REF="$2"; shift 2 ;;
    --image) [[ $# -ge 2 ]] || usage; IMAGE="$2"; shift 2 ;;
    --out) [[ $# -ge 2 ]] || usage; OUT="$2"; shift 2 ;;
    --network) NETWORK=1; shift ;;
    --ollama) [[ $# -ge 2 ]] || usage; OLLAMA="$2"; shift 2 ;;
    --include-flaky) INC_FLAKY=1; shift ;;
    --include-internet) INC_INTERNET=1; shift ;;
    --lane) [[ $# -ge 2 ]] || usage; LANE="$2"; shift 2 ;;
    --deadline) [[ $# -ge 2 ]] || usage; DEADLINE="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "pipeline: unknown option $1" >&2; usage ;;
  esac
done

GUEST="${MANDU_CI_GUEST:-0}"
if [[ $HOST -eq 0 && "$GUEST" != 1 ]]; then
  echo "pipeline: this runs in the CI guest (scripts/ci/vm-run.sh). On this machine, say --host." >&2
  exit 2
fi
[[ $SELFTEST -eq 1 && -n "$EXEC" ]] && { echo "pipeline: --selftest and --exec exclude each other" >&2; exit 2; }
# The guest runs as the unprivileged user `ci`, whose login PATH has no sbin
# directories; the sandbox suites' netns tests call `nft` and `ip` from there
# (they need no privilege beyond their own user and network namespace).
if [[ "$GUEST" == 1 ]]; then
  for d in /usr/local/sbin /usr/sbin /sbin; do [[ ":$PATH:" == *":$d:"* ]] || PATH="$PATH:$d"; done
  export PATH
fi
case "$SOURCE" in local|gitlab) ;; *) echo "pipeline: --source local|gitlab" >&2; exit 2 ;; esac
[[ -z "$OLLAMA" || "$OLLAMA" =~ ^[0-9.]+:[0-9]{1,5}$ ]] || { echo "pipeline: --ollama takes <ipv4>:<port>" >&2; exit 2; }
[[ -z "$DEADLINE" || "$DEADLINE" =~ ^[0-9]{1,12}$ ]] || { echo "pipeline: --deadline takes seconds since the epoch" >&2; exit 2; }
[[ "$HEARTBEAT" =~ ^[0-9]{1,6}$ ]] || { echo "pipeline: MANDU_CI_HEARTBEAT must be seconds (0: none)" >&2; exit 2; }
[[ $INC_INTERNET -eq 1 && $NETWORK -eq 0 ]] && { echo "pipeline: --include-internet needs --network" >&2; exit 2; }
[[ -z "$LANE" || "$LANE" == subscription || "$LANE" == api-key ]] || { echo "pipeline: --lane subscription|api-key" >&2; exit 2; }

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
STARTED="$(now_iso)"
[[ -n "$RUN_ID" ]] || RUN_ID="host-$(date -u +%Y%m%d-%H%M%S)-$$"
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$ ]] || { echo "pipeline: bad --run-id: $RUN_ID" >&2; exit 2; }
if [[ -z "$COMMIT" ]]; then
  COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
  if [[ -n "$COMMIT" && -n "$(git -C "$ROOT" status --porcelain 2>/dev/null | head -1)" ]]; then COMMIT="$COMMIT+dirty"; fi
fi
[[ "$COMMIT" =~ ^[0-9a-f]{7,64}(\+dirty)?$ ]] || { echo "pipeline: no commit id (--commit SHA)" >&2; exit 2; }
[[ -n "$REF" ]] || REF="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
[[ -n "$IMAGE" ]] || { [[ $HOST -eq 1 ]] && IMAGE="host"; }
if [[ -z "$OUT" ]]; then
  if [[ $HOST -eq 1 ]]; then OUT="$(mandu_path ci-host-out)/$RUN_ID"
  else echo "pipeline: --out is required in the guest" >&2; exit 2; fi
fi
if [[ -z "$JOBS" ]]; then JOBS=$(( $(nproc) / 2 )); (( JOBS < 1 )) && JOBS=1; fi
rm -rf "$OUT"; mkdir -p "$OUT/logs" || exit 2
OUT="$(cd "$OUT" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/mandu-ci-pipeline.XXXXXX")"
STACK_PIDS=()
on_exit() {
  local p
  # The nightly stack's processes: the Ollama relay, then the arbiter (its
  # log kept as logs/nightly-arbiter.log).
  for p in "${STACK_PIDS[@]}"; do kill -TERM -- "-$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null; done
  nightly_stack_stop "$OUT/logs/nightly-arbiter.log"
  rm -rf "$TMP"
}
trap on_exit EXIT
OFFLINE="${MANDU_CI_OFFLINE:-0}"

meta=(--run-id "$RUN_ID" --source "$SOURCE" --commit "$COMMIT" --ref "$REF" --started "$STARTED")
[[ -n "$IMAGE" ]] && meta+=(--image "$IMAGE")

say() { printf '[pipeline %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# finish <rc>: in --host mode hand the results to the collector.
finish() {
  local rc="$1"
  if [[ $HOST -eq 1 ]]; then
    local tar="$TMP/results.tar"
    tar -C "$OUT" -cf "$tar" --owner=0 --group=0 --numeric-owner . || exit 2
    node "$CI/collect-results.mjs" --archive "$tar" --run-id "$RUN_ID" --source "$SOURCE" \
      --commit "$COMMIT" --ref "$REF" --started "$STARTED" ${IMAGE:+--image "$IMAGE"} ${ONLY:+--only "$ONLY"}
    exit $?
  fi
  exit "$rc"
}

# write_summary <entries.json|""> [--result R] [--reason TEXT]
write_summary() {
  local entries="$1"; shift
  node "$CI/summary.mjs" write --out "$OUT" "${meta[@]}" --stages-json "$TMP/stages.json" \
    ${entries:+--entries-json "$entries"} "$@"
}

cap_log() {  # keep the last 5 MiB of a log (the runner's cap)
  local f="$1" max=$((5 * 1024 * 1024))
  if [[ -f "$f" && $(stat -c %s "$f") -gt $max ]]; then
    tail -c "$max" "$f" > "$f.tail" && mv "$f.tail" "$f"
  fi
}

echo '{}' > "$TMP/stages.json"
stage_json() {  # stage_json <name> <result> <seconds>
  node -e 'const fs=require("fs");const f=process.argv[1];const s=JSON.parse(fs.readFileSync(f,"utf8"));s[process.argv[2]]={result:process.argv[3],duration_s:Number(process.argv[4])};fs.writeFileSync(f,JSON.stringify(s))' \
    "$TMP/stages.json" "$1" "$2" "$3"
}
# A host run says so: the stage `vm` is `skip` (the summary has no free-text
# field for it; continuous-integration.md §8).
[[ $HOST -eq 1 ]] && stage_json vm skip 0

# ── selftest ───────────────────────────────────────────────────────────────
if [[ $SELFTEST -eq 1 ]]; then
  say "selftest (no build, no suites)"
  stage_json build skip 0
  entries="[]"
  t0=$SECONDS
  {
    echo "PASS: pipeline.sh started as $(id -un) (uid $(id -u)) in $ROOT"
    echo "kernel:  $(uname -r)"
    echo "cpus:    $(nproc)   mem: $(free -m 2>/dev/null | awk '/^Mem:/ {print $2 " MiB"}')"
    echo "userns restricted by AppArmor: $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo n/a)"
    echo "node:    $(node --version 2>&1)   cargo: $(cargo --version 2>&1)"
    echo "bwrap:   $(bwrap --version 2>&1)   MANDU_CI_BWRAP=${MANDU_CI_BWRAP:-} $([[ -n "${MANDU_CI_BWRAP:-}" ]] && "$MANDU_CI_BWRAP" --version 2>&1)"
    echo "ns-run:  $("$CI/ns-run.sh" --check 2>&1 | tr '\n' ' ')"
    echo "network: $(ls /sys/class/net 2>/dev/null | tr '\n' ' ')"
    echo "tree:    $(find "$ROOT" -maxdepth 1 | wc -l) top-level entries; node_modules dirs: $(find "$ROOT" -maxdepth 3 -name node_modules -type d 2>/dev/null | wc -l)"
    echo "PASS: probe complete"
  } > "$OUT/logs/selftest.probe.log" 2>&1
  entries="$(node -e 'console.log(JSON.stringify([{id:"selftest.probe",kind:"selftest",result:"pass",pass:2,fail:0,skip:0,duration_s:Number(process.argv[1]),log:"logs/selftest.probe.log"}]))' "$((SECONDS - t0))")"
  if [[ "$GUEST" == 1 ]]; then
    say "selftest: the sandbox's isolation test (scripts/test/ci-ns-run.test.sh)"
    t0=$SECONDS
    bash "$ROOT/scripts/test/ci-ns-run.test.sh" > "$OUT/logs/selftest.ns-run.log" 2>&1
    rc=$?
    read -r p f s < <(node "$CI/summary.mjs" counts "$OUT/logs/selftest.ns-run.log")
    if [[ $rc -ne 0 || $f -gt 0 ]]; then r=fail
    elif [[ $p -eq 0 && $s -gt 0 ]]; then r=skip
    else r=pass; fi
    entries="$(node -e 'const e=JSON.parse(process.argv[1]);e.push({id:"selftest.ns-run",kind:"selftest",result:process.argv[2],pass:+process.argv[3],fail:+process.argv[4],skip:+process.argv[5],duration_s:+process.argv[6],log:"logs/selftest.ns-run.log"});console.log(JSON.stringify(e))' \
      "$entries" "$r" "$p" "$f" "$s" "$((SECONDS - t0))")"
    say "selftest.ns-run: $r ($p passed, $f failed, $s skipped)"
  fi
  echo "$entries" > "$TMP/entries.json"
  write_summary "$TMP/entries.json" || exit 2
  finish "$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).result==="pass"?"0":"1")' "$OUT/summary.json")"
fi

# ── 1. build ───────────────────────────────────────────────────────────────
BUILD_LOG="$OUT/logs/build.log"
build_fail() {  # build_fail <result fail|error> <reason>
  local result="$1" reason="$2" secs="$3"
  cap_log "$BUILD_LOG"
  stage_json build "$result" "$secs"
  node -e 'console.log(JSON.stringify([{id:"build",kind:"build",result:process.argv[1],pass:0,fail:1,skip:0,duration_s:+process.argv[2],log:"logs/build.log"}]))' \
    "$result" "$secs" > "$TMP/entries.json"
  write_summary "$TMP/entries.json" --result "$result" ${reason:+--reason "$reason"} >/dev/null || exit 2
  say "build: $result${reason:+ ($reason)}; log $BUILD_LOG"
  finish $([[ "$result" == error ]] && echo 2 || echo 1)
}

lock_dirs() {  # every package dir with a package-lock.json (not under node_modules/target/.git;
  # private/ packages count when the checkout has them: the source repo runs its private rows too)
  find "$ROOT" \( -name node_modules -o -name target -o -name .git \) -prune \
    -o -name package-lock.json -type f -printf '%h\n' | LC_ALL=C sort
}

if [[ $NOBUILD -eq 0 ]]; then
  say "build (log: $BUILD_LOG)"
  t0=$SECONDS
  (
    echo "== npm (offline=$OFFLINE)"
    while IFS= read -r d; do
      want="$(sha256sum "$d/package-lock.json" | cut -d' ' -f1)"
      have="$(cat "$d/node_modules/.mandu-ci-lock" 2>/dev/null || true)"
      rel="${d#"$ROOT"/}"
      if [[ -d "$d/node_modules" && "$have" == "$want" ]]; then echo "   $rel: node_modules current"; continue; fi
      echo "   $rel: npm ci (node_modules ${have:+from another lockfile}${have:-missing or unstamped})"
      if [[ "$OFFLINE" == 1 ]]; then
        (cd "$d" && npm ci --offline --no-audit --no-fund) || { echo "NPM_STALE $rel"; exit 3; }
      else
        (cd "$d" && npm ci --no-audit --no-fund) || exit 1
      fi
      echo "$want" > "$d/node_modules/.mandu-ci-lock"
    done < <(lock_dirs)
    off=(); [[ "$OFFLINE" == 1 ]] && off=(--offline)
    echo "== cargo build --tests (default features)"
    (cd "$ROOT/interceptors" && cargo build "${off[@]}" --tests --workspace) || exit 1
    echo "== cargo build --tests --features kernel"
    (cd "$ROOT/interceptors" && cargo build "${off[@]}" --tests --workspace --features kernel) || exit 1
    echo "== scripts/build-native.sh"
    CARGO_NET_OFFLINE=$([[ "$OFFLINE" == 1 ]] && echo true || echo false) bash "$ROOT/scripts/build-native.sh" || exit 1
  ) > "$BUILD_LOG" 2>&1
  brc=$?
  secs=$((SECONDS - t0))
  case $brc in
    0) stage_json build pass "$secs"; say "build: pass (${secs}s)" ;;
    3) build_fail error "image stale: $(grep -m1 '^NPM_STALE' "$BUILD_LOG" | cut -d' ' -f2) needs packages the image's npm cache lacks (rebuild the image: scripts/ci/vm-image.sh)" "$secs" ;;
    *) build_fail fail "" "$secs" ;;
  esac
  cap_log "$BUILD_LOG"
else
  stage_json build skip 0
fi

# ── --exec ─────────────────────────────────────────────────────────────────
if [[ -n "$EXEC" ]]; then
  say "exec: $EXEC"
  t0=$SECONDS
  rm -rf "$ROOT/release"
  # The checkout has no .git in the guest: the command learns the commit and
  # ref from MANDU_CI_COMMIT / MANDU_CI_REF. Like every suite (run-suites.mjs
  # FIXED_ENV), it never inherits a --host runner's real Mandu home.
  (cd "$ROOT" && MANDU_CI_COMMIT="$COMMIT" MANDU_CI_REF="$REF" MANDU_HOME=/dev/null/mandu-test-home bash -c "$EXEC") > "$OUT/logs/exec.log" 2>&1
  rc=$?
  secs=$((SECONDS - t0))
  cap_log "$OUT/logs/exec.log"
  if [[ -d "$ROOT/release" ]]; then
    # Regular files and directories only, names the collector accepts.
    (cd "$ROOT/release" && find . -mindepth 1 \( -type d -o -type f \) -print0) | while IFS= read -r -d '' p; do
      p="${p#./}"
      if ! [[ "$p" =~ ^[A-Za-z0-9._@+=,:/-]+$ ]] || [[ "/$p/" == */../* ]]; then echo "exec: skipped release/$p (name)" >> "$OUT/logs/exec.log"; continue; fi
      if [[ -d "$ROOT/release/$p" ]]; then mkdir -p "$OUT/artifacts/release/$p"
      else mkdir -p "$(dirname "$OUT/artifacts/release/$p")" && cp --no-preserve=all "$ROOT/release/$p" "$OUT/artifacts/release/$p"; fi
    done
    say "exec: release/ copied to artifacts/release/ ($(find "$OUT/artifacts/release" -type f | wc -l) files)"
  fi
  r=pass; [[ $rc -eq 0 ]] || r=fail
  node -e 'console.log(JSON.stringify([{id:"exec",kind:"exec",result:process.argv[1],pass:process.argv[1]==="pass"?1:0,fail:process.argv[1]==="pass"?0:1,skip:0,duration_s:+process.argv[2],log:"logs/exec.log"}]))' \
    "$r" "$secs" > "$TMP/entries.json"
  echo "exec: exit status $rc" >> "$OUT/logs/exec.log"
  write_summary "$TMP/entries.json" || exit 2
  say "exec: $r (exit $rc, ${secs}s)"
  finish $([[ $r == pass ]] && echo 0 || echo 1)
fi

# ── 2. the nightly stack (--network) ───────────────────────────────────────
# What the nightly kinds need beside the suites themselves
# (continuous-integration.md §9). Each step logs to logs/nightly-stack.log; a step
# that fails is logged and the suites run anyway (each reports its own red or
# skip), so one missing piece does not hide the others' results.
nightly_stack() {
  local log="$OUT/logs/nightly-stack.log" t0=$SECONDS
  {
    echo "== nightly stack ($(now_iso))"
    echo "network: $(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2, $4}' | tr '\n' ' ')"
    echo "default route: $(ip -4 route show default 2>/dev/null | head -1)"
    if [[ -n "$OLLAMA" ]]; then
      node "$CI/port-bridge.mjs" relay 127.0.0.1:11434 "$OLLAMA" >> "$TMP/ollama-relay.log" 2>&1 &
      STACK_PIDS+=($!)
      local ok=0
      for _ in $(seq 1 50); do
        if curl -fsS -m 5 http://127.0.0.1:11434/api/version > "$TMP/ollama.version" 2>/dev/null; then ok=1; break; fi
        sleep 0.2
      done
      if [[ $ok -eq 1 ]]; then echo "ollama: 127.0.0.1:11434 -> $OLLAMA, $(cat "$TMP/ollama.version")"
        echo "ollama models: $(curl -fsS -m 10 http://127.0.0.1:11434/api/tags 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).models.map(m=>m.name).join(" "))}catch{console.log("?")}})')"
      else echo "ollama: NOT reachable through $OLLAMA (the host's Ollama is down, or the bridge failed)"; fi
    fi
    # The arbiter of the test tenant, MANDU_BIN and MANDU_TEST_DASHBOARD
    # (scripts/ci/nightly-stack.sh, which a host `test-all.sh --lane` starts
    # too). A failed arbiter is logged; the suites run anyway.
    nightly_stack_start "$ROOT" "$$" || true
    # A fresh claude config shows first-run screens the drill runner does not
    # answer (onboarding, the skip-permissions confirmation).
    mkdir -p "$HOME/.claude"
    [[ -e "$HOME/.claude.json" ]] || echo '{"hasCompletedOnboarding":true}' > "$HOME/.claude.json"
    [[ -e "$HOME/.claude/settings.json" ]] || echo '{"skipDangerousModePermissionPrompt":true}' > "$HOME/.claude/settings.json"
    if [[ -f "$HOME/.claude/.credentials.json" ]]; then echo "claude credential: present (placed by the guest's boot from the read-only credential disk)"
    else echo "claude credential: none (the real-model suites that need a login will skip or fail)"; fi
    # The subscription lane's Codex sign-in (§9.8): a reduced copy, no refresh
    # token. The ChatGPT-sign-in suites read its PATH (they give Codex a
    # CODEX_HOME of their own holding a copy); its contents are never logged.
    if [[ -f "$HOME/.config/mandu-ci/codex-auth.json" ]]; then
      export MANDU_CI_CODEX_AUTH="$HOME/.config/mandu-ci/codex-auth.json"
      echo "codex sign-in: present, MANDU_CI_CODEX_AUTH=$MANDU_CI_CODEX_AUTH (placed by the guest's boot; no refresh token)"
    elif [[ "$LANE" == subscription ]]; then echo "codex sign-in: none (the ChatGPT-sign-in suites will skip)"; fi
    # Tool credentials (§9.8 "Tool credentials"): the demo lane's baselines
    # read each file by its PATH (never an exported token: the agent under
    # test inherits this environment).
    if [[ -f "$HOME/.config/mandu-ci/docker-auth.json" ]]; then
      export MANDU_CI_DOCKER_AUTH="$HOME/.config/mandu-ci/docker-auth.json"
      echo "docker sign-in: present, MANDU_CI_DOCKER_AUTH=$MANDU_CI_DOCKER_AUTH (placed by the guest's boot)"
    fi
    if [[ -f "$HOME/.config/mandu-ci/gitguardian-key.json" ]]; then
      export MANDU_CI_GITGUARDIAN_AUTH="$HOME/.config/mandu-ci/gitguardian-key.json"
      echo "gitguardian token: present, MANDU_CI_GITGUARDIAN_AUTH=$MANDU_CI_GITGUARDIAN_AUTH (placed by the guest's boot)"
    fi
    # The API lane (§9.8): the keys go to the suites as the environment the
    # CLIs and harnesses read. Only the names are logged.
    local api="$HOME/.config/mandu-ci/api-keys.json" k
    if [[ -f "$api" ]]; then
      k="$(jq -r '.anthropic // empty' "$api" 2>/dev/null)"; [[ -n "$k" ]] && export ANTHROPIC_API_KEY="$k"
      k="$(jq -r '.openai // empty' "$api" 2>/dev/null)"; [[ -n "$k" ]] && export OPENAI_API_KEY="$k"
      k=""
      echo "api keys: $(jq -r 'keys | join(", ")' "$api" 2>/dev/null) (placed by the guest's boot; exported as ${ANTHROPIC_API_KEY:+ANTHROPIC_API_KEY }${OPENAI_API_KEY:+OPENAI_API_KEY})"
    elif [[ "$LANE" == api-key ]]; then echo "api keys: none (the api-key lane's suites will skip)"; fi
  } >> "$log" 2>&1
  stage_json nightly-stack pass "$((SECONDS - t0))"
  say "nightly stack up ($((SECONDS - t0))s; logs/nightly-stack.log)"
}

# tidy_drills: what the replay-drill entries left under $OUT/drills/ is the
# commit's own output, so it is made to fit the results archive before the
# archive is written (the collector refuses a whole archive with one bad
# member, and every other result would go with it): anything but a regular
# file or a directory, and any name outside the collector's characters, is
# removed; a hard-linked file becomes a copy of its own; empty directories go;
# and past DRILLS_MAX_FILES members or DRILLS_MAX_BYTES the whole of drills/
# but drills/live (which collect_live sized to its own caps) is dropped. A
# drop is never silent: logs/drills.log says how much it held,
# the pipeline log says WARNING, and the summary gets the stage `drills: skip`,
# which the collector turns into a WARNING in the job log (its drillsReport).
# The caps are the collector's DRILLS_MAX_MEMBERS / DRILLS_MAX_BYTES (a test
# checks they agree; continuous-integration.md §6 has the margin); the
# MANDU_CI_DRILLS_MAX_* overrides exist for scripts/test/ci-pipeline.test.sh.
# The collector checks it all again.
DRILLS_MAX_FILES="${MANDU_CI_DRILLS_MAX_FILES:-3000}" DRILLS_MAX_BYTES="${MANDU_CI_DRILLS_MAX_BYTES:-$((256 * 1024 * 1024))}"
# members and bytes (of the files) under a directory, the directory itself
# counted, as the collector counts the archive's members; a second argument
# names a subdirectory left out.
tree_size() {
  local d="$1" skip="${2:-}"
  if [[ -n "$skip" ]]; then
    find "$d" -path "$d/$skip" -prune -o -printf '%y %s\n'
  else
    find "$d" -printf '%y %s\n'
  fi | awk '{ n++; if ($1 == "f") b += $2 } END { print n + 0, b + 0 }'
}
tidy_drills() {
  local d="$OUT/drills" log="$OUT/logs/drills.log" n bytes f dropped=""
  [[ -d "$d" && ! -L "$d" ]] || { rm -f "$d"; return 0; }
  {
    LC_ALL=C find "$d" -mindepth 1 ! -type f ! -type d -printf 'removed (not a file or directory): %P\n' -delete
    LC_ALL=C find "$d" -mindepth 1 -name '*[!A-Za-z0-9._@+=,:-]*' -printf 'removed (name): %P\n' -prune -exec rm -rf {} +
    while IFS= read -r -d '' f; do
      cp --no-preserve=all "$f" "$f.tidy-copy" && mv -f "$f.tidy-copy" "$f" && echo "unlinked (hard link): ${f#"$d"/}"
    done < <(find "$d" -type f -links +1 -print0)
    find "$d" -mindepth 1 -depth -type d -empty -delete
    read -r n bytes < <(tree_size "$d" live)
    if (( n > DRILLS_MAX_FILES || bytes > DRILLS_MAX_BYTES )); then
      find "$d" -mindepth 1 -maxdepth 1 ! -name live -exec rm -rf {} +
      dropped="$n members, $bytes bytes (caps $DRILLS_MAX_FILES members, $DRILLS_MAX_BYTES bytes)"
      echo "dropped drills/: $dropped"
    else
      echo "drills/: $n members, $bytes bytes (caps $DRILLS_MAX_FILES members, $DRILLS_MAX_BYTES bytes)"
    fi
    [[ -d "$d" ]] && find "$d" -maxdepth 0 -empty -delete
  } >> "$log" 2>&1
  if [[ -n "$dropped" ]]; then
    say "WARNING: drills/ DROPPED, over its cap: $dropped; this run keeps no replay record or baseline (logs/drills.log; continuous-integration.md §6)"
    stage_json drills skip 0
    [[ -f "$OUT/summary.json" ]] && { node "$CI/summary.mjs" add-stage --out "$OUT" --stage drills=skip || say "WARNING: could not record the stage drills: skip in summary.json"; }
  fi
  return 0
}

# collect_live: the live-drill entries (drill-run.ts) recorded into a scratch
# store, LIVE_STORE (run-suites --watch-store), whose run directories also
# hold what must never leave the guest: the drill workspaces, the owned
# arbiter's work dir (its symbol DB), a private CODEX_HOME, the model
# captures. Only the record files the dashboard reads are copied to
# $OUT/drills/live/<drill run>/ (the collector's LIVE_RUN_ID_RE and its
# record files: meta, chapters, report and matrix JSON, the file route's
# RUN_FILE_RE, and the collector's LIVE_DATA_FILE_RE: a baseline's wire.ndjson
# and the demo battery's compare.md, §9.9), each a regular file of at most 32 MiB (the collector's
# MAX_RECORD_FILE_BYTES); a run directory without a meta.json is left behind.
# Then scripts/ci/live-events.mjs adds the EVENT LANES: the event log of
# each session the run names, from the run's own arbiter's event dir (never
# the rest of its work dir), as <drill run>/events-<session>.ndjson, each at
# most 32 MiB and all of them together at most LIVE_EVENTS_MAX_BYTES (the
# largest left behind first). drills/live is owner-only (0700 directories,
# 0600 files): an event log holds originals (DualRepr.original), synthetic
# drill data, kept as ~/.mandu keeps every event log.
# Past LIVE_MAX_FILES members or LIVE_MAX_BYTES the recordings go first, the
# casts then the pane captures, then the event logs, then the wire logs, largest first, so the
# verdicts stay; if the record files alone are over, drills/live is dropped
# whole with the stage `drills-live: skip`. All of it is said in
# logs/drills.log, a trim, a drop or an event log over its budget as a
# WARNING in the pipeline log. The caps are the collector's LIVE_MAX_* and
# live-events.mjs's EVENTS_MAX_BYTES (a test checks they agree);
# MANDU_CI_LIVE_* are for ci-pipeline.test.sh.
LIVE_MAX_FILES="${MANDU_CI_LIVE_MAX_FILES:-10000}" LIVE_MAX_BYTES="${MANDU_CI_LIVE_MAX_BYTES:-$((768 * 1024 * 1024))}"
LIVE_EVENTS_MAX_BYTES="${MANDU_CI_LIVE_EVENTS_MAX_BYTES:-$((96 * 1024 * 1024))}"
LIVE_FILE_MAX=$((32 * 1024 * 1024))
LIVE_RUN_RE='^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$'
LIVE_FILE_RE='^((meta|chapters|report|matrix)\.json|terminal-[a-z0-9-]+\.cast|browser-[a-z0-9-]+\.mp4|run\.log|report\.md|[A-Za-z0-9]+-[0-9]+\.pane\.txt|seed-[a-z0-9]+\.json|wire\.ndjson|compare\.md)$'
LIVE_STORE="$TMP/live"
collect_live() {
  local d="$OUT/drills/live" log="$OUT/logs/drills.log" r run f name n bytes sz p trimmed=0 dropped="" evlog="$TMP/live-events.log"
  [[ -d "$LIVE_STORE" ]] || return 0
  : > "$evlog"
  {
    for r in "$LIVE_STORE"/*; do
      [[ -e "$r" || -L "$r" ]] || continue
      run="${r##*/}"
      if [[ -L "$r" || ! -d "$r" || ! "$run" =~ $LIVE_RUN_RE ]]; then echo "live: left behind (not a run directory): $run"; continue; fi
      if [[ -L "$r/meta.json" || ! -f "$r/meta.json" ]]; then echo "live: left behind (no meta.json): $run"; continue; fi
      for f in "$r"/*; do
        name="${f##*/}"
        if [[ -L "$f" || ! -f "$f" || ! "$name" =~ $LIVE_FILE_RE ]]; then echo "live: $run/$name left behind (not a record file)"; continue; fi
        if (( $(stat -c %s "$f") > LIVE_FILE_MAX )); then echo "live: $run/$name left behind (over $LIVE_FILE_MAX bytes)"; continue; fi
        mkdir -p "$d/$run" && cp --no-preserve=all "$f" "$d/$run/$name"
      done
    done
    [[ -d "$d" ]] || return 0
    node "$CI/live-events.mjs" --store "$LIVE_STORE" --dest "$d" --max-file-bytes "$LIVE_FILE_MAX" --max-bytes "$LIVE_EVENTS_MAX_BYTES" > "$evlog" 2>&1 ||
      echo "live: the event logs were not copied (live-events.mjs failed)"
    cat "$evlog"
    find "$d" -type d -exec chmod 700 {} +; find "$d" -type f -exec chmod 600 {} +
    read -r n bytes < <(tree_size "$d")
    if (( n > LIVE_MAX_FILES || bytes > LIVE_MAX_BYTES )); then
      while read -r sz p; do
        (( n > LIVE_MAX_FILES || bytes > LIVE_MAX_BYTES )) || break
        rm -f "$p"; n=$((n - 1)); bytes=$((bytes - sz)); trimmed=$((trimmed + 1))
        echo "live: trimmed (over the cap): ${p#"$d"/} ($sz bytes)"
      done < <(find "$d" -type f -name '*.cast' -printf '%s %p\n' | sort -rn; find "$d" -type f -name '*.pane.txt' -printf '%s %p\n' | sort -rn
               find "$d" -type f -name 'events-*.ndjson' -printf '%s %p\n' | sort -rn
               find "$d" -type f -name 'wire.ndjson' -printf '%s %p\n' | sort -rn)
    fi
    if (( n > LIVE_MAX_FILES || bytes > LIVE_MAX_BYTES )); then
      rm -rf "$d"
      dropped="$n members, $bytes bytes (caps $LIVE_MAX_FILES members, $LIVE_MAX_BYTES bytes)"
      echo "dropped drills/live: $dropped"
    else
      echo "drills/live: $n members, $bytes bytes (caps $LIVE_MAX_FILES members, $LIVE_MAX_BYTES bytes); $trimmed recordings trimmed"
    fi
  } >> "$log" 2>&1
  (( trimmed > 0 )) && say "WARNING: drills/live over its cap: $trimmed recordings trimmed, largest first; the verdicts are kept (logs/drills.log; continuous-integration.md §6)"
  n="$(grep -c 'left behind (over the events cap' "$evlog" 2>/dev/null)"
  (( ${n:-0} > 0 )) && say "WARNING: drills/live: $n event logs left behind, over the events cap of $LIVE_EVENTS_MAX_BYTES bytes, largest first; those sessions have no event lanes (logs/drills.log; continuous-integration.md §6)"
  if [[ -n "$dropped" ]]; then
    say "WARNING: drills/live DROPPED, its record files alone over its cap: $dropped; this run keeps no live-drill record (logs/drills.log; continuous-integration.md §6)"
    stage_json drills-live skip 0
    [[ -f "$OUT/summary.json" ]] && { node "$CI/summary.mjs" add-stage --out "$OUT" --stage drills-live=skip || say "WARNING: could not record the stage drills-live: skip in summary.json"; }
  fi
  return 0
}

# ── 3. the suites ──────────────────────────────────────────────────────────
args=(--kind "$KINDS" --jobs "$JOBS" --kernel-jobs "$KJOBS" --out "$OUT"
      --run-id "$RUN_ID" --source "$SOURCE" --commit "$COMMIT" --ref "$REF"
      --stages-json "$TMP/stages.json")
# The per-push run sandboxes every non-kernel entry (§5); a networked run's
# suites run in the guest itself (above).
NIGHTLY=0; [[ $NETWORK -eq 1 || -n "$OLLAMA" ]] && NIGHTLY=1
[[ $NIGHTLY -eq 1 ]] || args+=(--sandbox "$CI/ns-run.sh")
# Said once here as well as in each sandboxed suite's log (§5.6).
if [[ $NIGHTLY -eq 0 && "$("$CI/ns-run.sh" --check 2>/dev/null | sed -n 's/^nested-bwrap: //p')" == no ]]; then
  say "note: a bubblewrap cannot nest inside ns-run's sandbox here, so Mandu's git sandbox is off in the sandboxed suites and its tests SKIP (the CI guest runs them; continuous-integration.md §5.6)"
fi
[[ -n "$ONLY" ]] && args+=(--only "$ONLY")
[[ -n "$IMAGE" ]] && args+=(--image "$IMAGE")
[[ -n "$NEED" ]] && args+=(--need "$NEED")
[[ $INC_FLAKY -eq 1 ]] && args+=(--include-flaky --flaky-kinds unit,component,stack,replay-drill,sandbox,live-drill,env,eval)
[[ $INC_INTERNET -eq 1 ]] && args+=(--include-internet)
[[ -n "$LANE" ]] && args+=(--lane "$LANE")
# The guest's deadline (boot.sh, from vm-run.sh's MANDU_CI_BUDGET, §3): the
# runner stops what still runs then as timeouts, with their reports, and
# writes the summary, so a hung entry comes back named instead of the guest
# being killed with nothing. The heartbeat names the running entries meanwhile.
[[ -n "$DEADLINE" ]] && args+=(--deadline "$DEADLINE")
[[ "$HEARTBEAT" != 0 ]] && args+=(--heartbeat "$HEARTBEAT")
# The replay records (test-reorganization.md §7.3, continuous-integration.md §6):
# every replay-drill entry writes its record and its plain-run baselines under
# $OUT/drills/, which the results archive carries; sandboxed, each entry gets
# its own <dir>/<entry id>, bound read-write into its box (ns-run --bind-rw).
args+=(--replay-store "$OUT/drills/replay" --replay-baselines "$OUT/drills/baselines")
# The live-drill records (test-reorganization.md §8.1): every drill entry
# records into LIVE_STORE, never the guest's ~/.mandu (discarded with it);
# collect_live carries the record files to drills/live. The full per-crate
# logs of the kernel lane's scripts/kernel-tests.sh go to logs/kernel-tests/
# (a kernel entry runs unsandboxed, in this environment).
args+=(--watch-store "$LIVE_STORE")
export MANDU_KERNEL_TESTS_LOG_DIR="$OUT/logs/kernel-tests"
# A per-push run USES the plain-run baselines master promoted (step 5 decision
# 8, test-reorganization.md §6.9): vm-run.sh brings them in the tree under
# .mandu-ci/baselines, read-only; a key with none records its plain run here
# (slow, not red), into drills/baselines as before. The nightly records every
# plain run again (the drift check). A per-push run also BLOCKS on the replay
# verdict (MANDU_REPLAY_BLOCKING=1, test-reorganization.md §6.9: the budget
# held for the week to 2026-10-11): a FAIL or TIMEOUT verdict fails its test.
if [[ $NIGHTLY -eq 0 ]]; then
  args+=(--replay-baseline-mode use --replay-blocking)
  [[ -d "$ROOT/.mandu-ci/baselines" ]] && args+=(--replay-baselines-seed "$ROOT/.mandu-ci/baselines")
fi
[[ $NIGHTLY -eq 1 ]] && nightly_stack
# The entries' measured costs (§5.4): vm-run.sh brings each entry's median
# duration over its host's last green full runs, which order the queue over
# the checked-in tables (an entry they do not name keeps its table cost).
if [[ -f "$ROOT/.mandu-ci/suite-costs.json" ]]; then
  args+=(--costs "$ROOT/.mandu-ci/suite-costs.json")
  say "costs: the host's measured medians ($ROOT/.mandu-ci/suite-costs.json) over the checked-in tables"
fi
if [[ $HOST -eq 1 ]]; then
  # A host's bwrap may be 0.9 (no overlay): a private copy of the checkout then.
  export MANDU_CI_TREE="${MANDU_CI_TREE:-auto}"
else
  args+=(--strict-skips)
fi
say "suites: node scripts/run-suites.mjs ${args[*]}"
node "$ROOT/scripts/run-suites.mjs" "${args[@]}"
rc=$?
collect_live
tidy_drills
if [[ ! -f "$OUT/summary.json" ]]; then
  echo "run-suites exited $rc without a summary" > "$OUT/logs/run-suites.log"
  node -e 'console.log(JSON.stringify([]))' > "$TMP/entries.json"
  write_summary "$TMP/entries.json" --result error --reason "run-suites exited $rc without writing summary.json" >/dev/null || exit 2
  rc=2
fi
finish "$rc"
