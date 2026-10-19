#!/usr/bin/env bash
# vm-run.sh — run what CI runs, in a fresh KVM guest (docs/design/testing/continuous-integration.md §3, §8).
#
#   scripts/ci/vm-run.sh [--kind k[,k]] [--need n] [--only id[,id]] [--commit REV | --worktree]
#                        [--guest ubuntu-2404|ubuntu-2604]
#                        [--jobs N] [--vcpus N] [--mem MiB] [--shell] [--keep]
#                        [--out DIR] [--dry-run] [--run-id ID] [--source local|gitlab]
#                        [--ref REF] [--selftest | --exec 'COMMAND']
#                        [--network] [--ollama] [--credential K[,K]] [--lane L]
#                        [--include-flaky] [--include-internet] [--timeout S]
#                        [--demo-ids L] [--demo-sides L] [--demo-models L]
#                        [--demo-repeat N] [--demo-jobs N] [--demo-agents L]
#
#   --kind       the kinds (default unit,component,stack,replay-drill,sandbox, the per-push run)
#   --need       only the selected entries with this need (`--need kernel`:
#                the kernel lane, the kernel-linux-7 job)
#   --only       only these manifest entries (node scripts/suites.mjs list)
#   --commit     the commit under test (default HEAD); --worktree: the work tree
#                instead, uncommitted changes and untracked files included,
#                never ignored files (commit id <HEAD>+dirty when it differs)
#   --guest      the guest image (default ubuntu-2404, every per-push run's);
#                ubuntu-2604 is Ubuntu 26.04 on Linux 7.0, for the kernel lane
#                on the newer kernel (the `kernel-linux-7` job, §4.1). Its own
#                image, built from its own base pins by the same provision.sh
#   --jobs       the runner's concurrency (default: half the guest's vCPUs)
#   --vcpus/--mem  the guest's size (MANDU_CI_VCPUS=32, MANDU_CI_MEM=65536,
#                capped to the host's CPUs). Every guest on the host shares one
#                CPU budget, the host's physical cores (MANDU_CI_HOST_VCPUS; 0:
#                none): a guest waits for room before it boots, at most
#                MANDU_CI_SLOT_WAIT seconds (1800; continuous-integration.md §5.7)
#   --shell      boot the same image with the same checkout and give the
#                serial console a shell as `ci` in /work/mandu; nothing runs;
#                the guest powers off when the shell exits
#   --keep       keep the overlay and the raw disks (and the console log)
#   --out DIR    also copy the results there (CI: the job's artifacts)
#   --dry-run    print the job file and the qemu command; run nothing
#   --run-id     the run's id (default local-<time>-<sha>); --source local|gitlab
#   --ref        the ref to record (default $CI_COMMIT_REF_NAME, else the branch)
#   --selftest   the VM plumbing check: no build, no suites (pipeline.sh --selftest)
#   --exec CMD   after the build, run CMD as `ci` in /work/mandu instead of the
#                suites; what it leaves in release/ comes back under
#                <results>/artifacts/release/ (the release jobs)
#
# The nightly's options (continuous-integration.md §9); without them nothing below
# changes:
#   --network    user-mode network to the internet: qemu runs in its own user
#                + network namespace joined to slirp4netns
#                --disable-host-loopback, so the guest never reaches a port on
#                the host's loopback. The suites then run unsandboxed in the
#                guest (they need its network and its HOME's credential)
#   --ollama     the host's Ollama (MANDU_CI_OLLAMA_HOST, default
#                127.0.0.1:11434) at 10.0.2.100:11434 in the guest, and nothing
#                else of the host: a guestfwd whose per-connection command
#                reaches the host only through a unix socket in a private
#                (0700) directory (scripts/ci/port-bridge.mjs)
#   --credential K[,K]  (claude, codex, docker, gitguardian; or api, alone or
#                with docker)
#                claude: the scoped agent credential a human placed on this host
#                (`node scripts/ci/credential.mjs path claude`; mode 0600,
#                access token only); codex: the reduced copy (no refresh
#                token) of the CI account's Codex sign-in kept on this
#                host (`credential.mjs path codex`); api: the API lane's
#                vendor keys (`credential.mjs path api`, §9.8); docker,
#                gitguardian: tool tokens for the demo lane's baselines
#                (Docker Sandboxes' sign-in, ggshield's API token; §9.8
#                "Tool credentials"). The subscription and tool kinds
#                combine; api stands alone or with docker (the API lane's
#                Docker Sandboxes side, never a subscription kind). All of them on
#                one fourth, read-only disk (virtio serial mandu-cred). The disk is an unlinked file qemu holds open, so
#                it is gone with the guest whatever happens. Missing or
#                unusable: the run is an `error` with the reason and the setup
#                steps, before any image build or boot. After the run a canary
#                (credential.mjs scan) looks for every token of the host files
#                (the codex refresh token too) in the console and the results
#                disk; a hit withholds both and makes the run an
#                `error`. Needs --network; refused with --shell and --exec
#   --lane subscription|api-key
#                the nightly lane (§9.8): of the selected entries, only those
#                whose `credential` is this one (run-suites.mjs --lane). The lane
#                and the credential file agree: api-key takes --credential api
#                (or api,docker), and subscription never takes api
#   --include-flaky     also every `flaky` entry of every kind (they report
#                their own result and never fail the run)
#   --include-internet  also the `internet` entries of the selected kinds
#                (needs --network)
#   --timeout S  the guest's timeout in seconds (MANDU_CI_TIMEOUT; the flag wins)
#   --demo-ids L, --demo-sides L, --demo-models L, --demo-repeat N, --demo-jobs N,
#   --demo-agents L
#                the demo lane's MANDU_DEMO_IDS, _SIDES, _MODELS, _REPEAT, _JOBS and
#                _AGENTS (below) as flags, each winning over its variable: a
#                command that starts with this script carries the whole battery
#
# The demo lane (continuous-integration.md §9.9): MANDU_DEMO_IDS,
# MANDU_DEMO_SIDES, MANDU_DEMO_MODELS, MANDU_DEMO_REPEAT, MANDU_DEMO_JOBS and MANDU_DEMO_AGENTS in this script's
# environment go into job.env (the job.env character set) and reach the
# demo battery (`--only live.demo-battery`, or its stand-in rehearsal
# `live.demo-battery.rehearsal`), which runs with --network: e.g.
#   MANDU_DEMO_IDS=demo-scam-email,demo-api-401-debug \
#     scripts/ci/vm-run.sh --worktree --network --only live.demo-battery.rehearsal
# or the same with a flag:
#   scripts/ci/vm-run.sh --worktree --network --only live.demo-battery.rehearsal \
#     --demo-ids demo-scam-email,demo-api-401-debug
#
# Without --network/--ollama/--credential, the guest gets exactly three disks
# and no network (-nic none), no shared filesystem: its system disk (a
# throwaway qcow2 overlay over the image), the input disk (a raw tar: src/ + job.env, read-only, virtio serial mandu-in)
# and the output disk (a sparse 2 GiB raw file, virtio serial mandu-out) the
# guest writes its results tar onto. After it powers off (or after
# MANDU_CI_TIMEOUT seconds, default 2700, when it is killed and the run is an
# `error`), scripts/ci/collect-results.mjs reads that disk as an UNTRUSTED
# archive into the runs directory. The guest gets a budget below that timeout
# (job.env MANDU_CI_BUDGET, ci_guest_budget: the timeout less a tenth, at most
# 150 s): its runner stops what still runs before it (the timeouts reported,
# the summary written) and its watchdog stops the pipeline at it, so a hung
# suite comes back named and the kill is a backstop (§3). Exit: 0 pass,
# 1 fail, 2 error.
set -uo pipefail

CI_REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null)" \
  || { echo "vm-run: not in a git checkout" >&2; exit 2; }
CI="$CI_REPO_ROOT/scripts/ci"
# shellcheck source=scripts/ci/lib.sh
. "$CI/lib.sh"

KINDS="unit,component,stack,replay-drill,sandbox" NEED="" ONLY="" REV=HEAD WORKTREE=0 JOBS="" GUEST="$CI_DEFAULT_GUEST"
VCPUS="${MANDU_CI_VCPUS:-32}" MEM="${MANDU_CI_MEM:-65536}" SHELL_MODE=0 KEEP=0 OUT="" DRY=0
RUN_ID="" SOURCE=local REF="${CI_COMMIT_REF_NAME:-}" MODE=run EXEC=""
TIMEOUT="${MANDU_CI_TIMEOUT:-2700}"
NETWORK=0 OLLAMA=0 CRED="" LANE="" INC_FLAKY=0 INC_INTERNET=0
OLLAMA_HOST_ADDR="${MANDU_CI_OLLAMA_HOST:-127.0.0.1:11434}"
OLLAMA_GUEST_ADDR="10.0.2.100:11434"

usage() { sed -n '4,12p' "$0" >&2; exit 2; }
need() { [[ $# -ge 2 && -n "$2" ]] || { echo "vm-run: $1 needs a value" >&2; exit 2; }; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kind) need "$@"; KINDS="$2"; shift 2 ;;
    --need) need "$@"; NEED="$2"; shift 2 ;;
    --only) need "$@"; ONLY="$2"; shift 2 ;;
    --commit) need "$@"; REV="$2"; shift 2 ;;
    --worktree) WORKTREE=1; shift ;;
    --guest) need "$@"; GUEST="$2"; shift 2 ;;
    --jobs) need "$@"; JOBS="$2"; shift 2 ;;
    --vcpus) need "$@"; VCPUS="$2"; shift 2 ;;
    --mem) need "$@"; MEM="$2"; shift 2 ;;
    --shell) SHELL_MODE=1; MODE=shell; shift ;;
    --keep) KEEP=1; shift ;;
    --out) need "$@"; OUT="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --run-id) need "$@"; RUN_ID="$2"; shift 2 ;;
    --source) need "$@"; SOURCE="$2"; shift 2 ;;
    --ref) need "$@"; REF="$2"; shift 2 ;;
    --selftest) MODE=selftest; shift ;;
    --exec) need "$@"; MODE=exec; EXEC="$2"; shift 2 ;;
    --network) NETWORK=1; shift ;;
    --ollama) OLLAMA=1; shift ;;
    --credential) need "$@"; CRED="$2"; shift 2 ;;
    --lane) need "$@"; LANE="$2"; shift 2 ;;
    --include-flaky) INC_FLAKY=1; shift ;;
    --include-internet) INC_INTERNET=1; shift ;;
    --timeout) need "$@"; TIMEOUT="$2"; shift 2 ;;
    # the demo lane's variables as flags; ci_render_job_env reads them
    --demo-ids) need "$@"; export MANDU_DEMO_IDS="$2"; shift 2 ;;
    --demo-sides) need "$@"; export MANDU_DEMO_SIDES="$2"; shift 2 ;;
    --demo-models) need "$@"; export MANDU_DEMO_MODELS="$2"; shift 2 ;;
    --demo-repeat) need "$@"; export MANDU_DEMO_REPEAT="$2"; shift 2 ;;
    --demo-jobs) need "$@"; export MANDU_DEMO_JOBS="$2"; shift 2 ;;
    --demo-agents) need "$@"; export MANDU_DEMO_AGENTS="$2"; shift 2 ;;
    -h|--help) sed -n '2,/^[^#]/{/^#/p}' "$0"; exit 0 ;;
    *) echo "vm-run: unknown option $1" >&2; usage ;;
  esac
done
[[ $SHELL_MODE -eq 1 && ( -n "$EXEC" ) ]] && { echo "vm-run: --shell and --exec exclude each other" >&2; exit 2; }
[[ $SHELL_MODE -eq 1 ]] && MODE=shell
case "$SOURCE" in local|gitlab) ;; *) echo "vm-run: --source local|gitlab" >&2; exit 2 ;; esac
ci_check_guest "$GUEST" || exit 2
[[ "$VCPUS" =~ ^[0-9]+$ && "$MEM" =~ ^[0-9]+$ ]] || { echo "vm-run: --vcpus/--mem must be numbers" >&2; exit 2; }
[[ -z "$JOBS" || "$JOBS" =~ ^[0-9]+$ ]] || { echo "vm-run: --jobs must be a number" >&2; exit 2; }
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { echo "vm-run: --timeout / MANDU_CI_TIMEOUT must be seconds" >&2; exit 2; }
if [[ -n "$CRED" ]]; then
  # The subscription kinds and the tool kinds combine (a kind named twice is
  # refused by credential.mjs check, before anything slow); api stands alone
  # or with docker (credential.mjs API_TOOL_KINDS), never with a subscription kind.
  [[ "$CRED" == api || "$CRED" == api,docker || "$CRED" == docker,api || "$CRED" =~ ^(claude|codex|docker|gitguardian)(,(claude|codex|docker|gitguardian))*$ ]] \
    || { echo "vm-run: --credential: api or api,docker, or any of claude, codex, docker, gitguardian joined by commas (api never combines with a subscription kind or gitguardian)" >&2; exit 2; }
  [[ $NETWORK -eq 1 ]] || { echo "vm-run: --credential needs --network (a model call is a network call)" >&2; exit 2; }
  [[ "$MODE" == shell || "$MODE" == exec ]] && { echo "vm-run: --credential is for the suites: refused with --shell and --exec" >&2; exit 2; }
fi
[[ $INC_INTERNET -eq 1 && $NETWORK -eq 0 ]] && { echo "vm-run: --include-internet needs --network" >&2; exit 2; }
[[ -z "$LANE" || "$LANE" == subscription || "$LANE" == api-key ]] || { echo "vm-run: --lane: subscription or api-key" >&2; exit 2; }
CRED_HAS_API=0; [[ ",$CRED," == *,api,* ]] && CRED_HAS_API=1
if [[ -n "$CRED" && -n "$LANE" ]] && { [[ "$LANE" == api-key && $CRED_HAS_API -eq 0 ]] || [[ "$LANE" != api-key && $CRED_HAS_API -eq 1 ]]; }; then
  echo "vm-run: --lane $LANE with --credential $CRED: the api-key lane holds the api credential file (and at most the docker tool token), the subscription lane only subscription and tool kinds (§9.8)" >&2; exit 2
fi
[[ "$OLLAMA_HOST_ADDR" =~ ^(127\.0\.0\.1|localhost):[0-9]{1,5}$ ]] \
  || { echo "vm-run: MANDU_CI_OLLAMA_HOST must be 127.0.0.1:<port> or localhost:<port> (the bridge reaches this host only)" >&2; exit 2; }
host_cpus="$(nproc)"; (( VCPUS > host_cpus )) && VCPUS=$host_cpus

log() { echo "vm-run: $*" >&2; }

# ── what is under test ─────────────────────────────────────────────────────
if [[ $WORKTREE -eq 1 ]]; then
  SRC=--worktree
  COMMIT="$(git -C "$CI_REPO_ROOT" rev-parse HEAD)" || exit 2
  [[ -n "$(git -C "$CI_REPO_ROOT" status --porcelain | head -1)" ]] && COMMIT="$COMMIT+dirty"
else
  COMMIT="$(git -C "$CI_REPO_ROOT" rev-parse --verify --quiet "$REV^{commit}")" \
    || { echo "vm-run: not a commit: $REV" >&2; exit 2; }
  SRC="$COMMIT"
fi
if [[ -z "$REF" ]]; then
  if [[ $WORKTREE -eq 1 || "$REV" == HEAD ]]; then REF="$(git -C "$CI_REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  elif git -C "$CI_REPO_ROOT" show-ref --verify --quiet "refs/heads/$REV"; then REF="$REV"; fi
fi
[[ "$REF" == HEAD ]] && REF=""
[[ -n "$RUN_ID" ]] || RUN_ID="local-$(date -u +%Y%m%d-%H%M%S)-${COMMIT:0:8}"
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]{0,119}$ ]] \
  || { echo "vm-run: --run-id must match [A-Za-z0-9][A-Za-z0-9.:-]* (≤ 120): $RUN_ID" >&2; exit 2; }

KEY="$(ci_image_key "$SRC" "$GUEST")" || exit 2
CACHE="$(ci_cache_dir)"
IMAGE_NAME="$(ci_image_name "$GUEST" "$KEY")"
IMAGE="$CACHE/$IMAGE_NAME.qcow2"

# ── the job file ───────────────────────────────────────────────────────────
# node, not base64(1): a runner host's PATH can put a different base64 first
# (continuous-integration.md §7).
EXEC_B64=""; [[ -n "$EXEC" ]] && { EXEC_B64="$(node -e 'process.stdout.write(Buffer.from(process.argv[1]).toString("base64"))' "$EXEC")" || exit 2; }
BUDGET=""; [[ "$MODE" != shell ]] && BUDGET="$(ci_guest_budget "$TIMEOUT")"
JOBENV_TEXT="$(MANDU_CI_BUDGET="$BUDGET" MANDU_CI_MODE="$MODE" MANDU_CI_KINDS="$KINDS" MANDU_CI_NEED="$NEED" MANDU_CI_ONLY="$ONLY" MANDU_CI_JOBS="$JOBS" \
  MANDU_CI_RUN_ID="$RUN_ID" MANDU_CI_SOURCE="$SOURCE" MANDU_CI_COMMIT="$COMMIT" MANDU_CI_REF="$REF" \
  MANDU_CI_IMAGE="$IMAGE_NAME" MANDU_CI_EXEC_B64="$EXEC_B64" \
  MANDU_CI_NETWORK="$([[ $NETWORK -eq 1 ]] && echo 1)" MANDU_CI_OLLAMA="$([[ $OLLAMA -eq 1 ]] && echo "$OLLAMA_GUEST_ADDR")" \
  MANDU_CI_CREDENTIAL="$CRED" MANDU_CI_INCLUDE_FLAKY="$([[ $INC_FLAKY -eq 1 ]] && echo 1)" \
  MANDU_CI_INCLUDE_INTERNET="$([[ $INC_INTERNET -eq 1 ]] && echo 1)" MANDU_CI_LANE="$LANE" ci_render_job_env)" || exit 2

# ── the qemu command ───────────────────────────────────────────────────────
WORK_BASE="${MANDU_CI_WORK:-$CACHE/runs}"
if [[ $DRY -eq 1 ]]; then WORK="$WORK_BASE/$RUN_ID.XXXXXX"
else mkdir -p "$WORK_BASE" && WORK="$(mktemp -d "$WORK_BASE/$RUN_ID.XXXXXX")" || exit 2; fi
OVERLAY="$WORK/system.qcow2" INPUT="$WORK/input.tar" OUTPUT="$WORK/output.raw" CONSOLE="$WORK/console.log"
CRED_FD=7 SOCK_DIR=""
# The bridge's socket: a private (0700) directory of its own with a short
# path (a unix socket path has ~108 bytes, a run id up to 120).
if [[ $OLLAMA -eq 1 ]]; then
  if [[ $DRY -eq 1 ]]; then SOCK_DIR="${TMPDIR:-/tmp}/mandu-ci-ollama.XXXXXX"
  else SOCK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mandu-ci-ollama.XXXXXX")" || exit 2; fi
fi
OLLAMA_SOCK="$SOCK_DIR/s"
NODE_BIN="$(command -v node || echo node)"
read -r -a accel <<<"$(ci_accel)"
# -pidfile: the guest is registered for `mandu reap` while it runs (below).
qemu=(qemu-system-x86_64 "${accel[@]}" -smp "$VCPUS" -m "$MEM" -nographic -no-reboot -pidfile "$WORK/qemu.pid")
# The network (§9): none, unless --network (an uplink through slirp4netns in
# qemu's own namespace) or --ollama (one guestfwd to the host's Ollama through
# port-bridge.mjs's unix socket; without --network that is all the guest
# reaches: restrict=on). qemu's option parser needs `,` doubled in a value.
if [[ $NETWORK -eq 1 || $OLLAMA -eq 1 ]]; then
  netdev="user,id=n0"
  [[ $NETWORK -eq 0 ]] && netdev+=",restrict=on"
  if [[ $OLLAMA -eq 1 ]]; then
    netdev+=",guestfwd=tcp:${OLLAMA_GUEST_ADDR}-cmd:${NODE_BIN//,/,,} ${CI//,/,,}/port-bridge.mjs connect ${OLLAMA_SOCK//,/,,}"
  fi
  qemu+=(-netdev "$netdev" -device virtio-net-pci,netdev=n0)
else
  qemu+=(-nic none)
fi
if [[ $SHELL_MODE -eq 1 ]]; then qemu+=(-serial mon:stdio)
else qemu+=(-serial "file:$CONSOLE" -monitor none); fi
# The system disk is thrown away after the run, so the guest's flushes are
# not passed to the host (cache=unsafe): on a spinning disk every fsync was a
# seek and the run ~50x slower (continuous-integration.md §3).
qemu+=(-drive "file=$OVERLAY,if=none,id=sys,format=qcow2,discard=unmap,cache=unsafe"
       -device virtio-blk-pci,drive=sys,bootindex=0
       -drive "file=$INPUT,if=none,id=in,format=raw,readonly=on"
       -device virtio-blk-pci,drive=in,serial=mandu-in
       -drive "file=$OUTPUT,if=none,id=out,format=raw"
       -device virtio-blk-pci,drive=out,serial=mandu-out)
# The credential disk: fd CRED_FD is the unlinked tar credential.mjs wrote
# (below); qemu takes it as an fd set, so no path to it exists while it runs.
[[ -n "$CRED" ]] && qemu+=(-add-fd "fd=$CRED_FD,set=$CRED_FD"
       -drive "file=/dev/fdset/$CRED_FD,if=none,id=cred,format=raw,readonly=on"
       -device virtio-blk-pci,drive=cred,serial=mandu-cred)

if [[ $DRY -eq 1 ]]; then
  echo "# guest: $GUEST"
  echo "# image: $IMAGE$([[ -s "$IMAGE" ]] || echo "  (missing: vm-image.sh would build it)")"
  echo "# commit: $COMMIT  ref: ${REF:-(none)}  run: $RUN_ID  mode: $MODE"
  echo "# timeout: ${TIMEOUT}s; the guest's budget: ${BUDGET:-none}${BUDGET:+s of uptime}"
  if [[ $NETWORK -eq 1 || $OLLAMA -eq 1 ]]; then
    echo "# network: qemu in its own user+network namespace ($(ci_netns_bwrap || echo 'NO usable bwrap')), $([[ $NETWORK -eq 1 ]] && echo 'uplink slirp4netns --disable-host-loopback' || echo 'no uplink')"
    [[ $OLLAMA -eq 1 ]] && echo "# ollama: guest $OLLAMA_GUEST_ADDR -> port-bridge.mjs listen $OLLAMA_SOCK $OLLAMA_HOST_ADDR"
  fi
  if [[ -n "$CRED" ]]; then
    for k in ${CRED//,/ }; do
      cf="$(node "$CI/credential.mjs" path "$k")"
      if cmsg="$(node "$CI/credential.mjs" check "$k" --src "$cf" --min-seconds "$((TIMEOUT + 300))" 2>&1)"; then
        echo "# credential: $k from $cf (usable)"
      else
        echo "# credential: $k from $cf: NOT USABLE ($(head -1 <<<"$cmsg" | sed 's/^credential: not usable: //'))"
      fi
    done
  fi
  echo "# job.env:"
  printf '%s\n' "$JOBENV_TEXT" | sed 's/^/#   /'
  printf '%q ' "${qemu[@]}"; echo
  exit 0
fi

PIDS=()
cleanup() {
  local p
  # A guest still up (this run was signalled) stops with it and leaves the
  # registry, before its disks go.
  guest_release
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  # The credential tar is unlinked as soon as it is open on fd 7 (below);
  # this is only for a run that stopped in between. Never kept, even --keep.
  rm -f "$WORK/cred.tar"
  [[ -n "$SOCK_DIR" ]] && rm -rf "$SOCK_DIR"
  if [[ $KEEP -eq 1 ]]; then log "kept: $WORK"
  else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# record_error <reason>: a run that broke before its guest ran still shows up
# (the runs directory, --out), as an `error` with the reason (§6). Exits 2.
record_error() {
  node "$CI/collect-results.mjs" --run-id "$RUN_ID" --source "$SOURCE" --commit "$COMMIT" --ref "$REF" \
    --image "$IMAGE_NAME" --started "$(date -u +%Y-%m-%dT%H:%M:%SZ)" ${OUT:+--out "$OUT"} --error "$1"
  exit 2
}

# ── the credential and the network (before anything slow) ─────────────────
# A missing or unusable credential fails the run in seconds, with the reason
# and the human's setup steps, before any image build or boot.
if [[ -n "$CRED" ]]; then
  # Every kind from its own host file (credential.mjs path K); the run needs
  # each token for its whole timeout, plus a margin.
  if ! cmsg="$(node "$CI/credential.mjs" check "$CRED" --min-seconds "$((TIMEOUT + 300))" 2>&1)"; then
    printf '%s\n' "$cmsg" | sed 's/^/vm-run: /' >&2
    record_error "credential: $(head -1 <<<"$cmsg" | sed 's/^credential: //') (setup: continuous-integration.md §9)"
  fi
fi
if [[ $NETWORK -eq 1 || $OLLAMA -eq 1 ]]; then
  BWRAP_NET="$(ci_netns_bwrap)" \
    || record_error "network: no bwrap here can create a user+network namespace (on Ubuntu 24.04: mandu setup); without one the guest could reach the host's loopback"
  if [[ $NETWORK -eq 1 ]] && ! command -v slirp4netns >/dev/null; then
    record_error "network: slirp4netns is not installed"
  fi
fi

# ── the image ──────────────────────────────────────────────────────────────
if [[ ! -s "$IMAGE" ]]; then
  log "image $IMAGE_NAME is not built yet: building it (scripts/ci/vm-image.sh; network, one boot)"
  if [[ $WORKTREE -eq 1 ]]; then "$CI/vm-image.sh" --guest "$GUEST" --worktree >/dev/null || exit 2
  else "$CI/vm-image.sh" --guest "$GUEST" --commit "$COMMIT" >/dev/null || exit 2; fi
fi
touch "$IMAGE"
exec 8<"$IMAGE"; flock -s 8   # vm-image.sh never prunes an image in use

# ── the host's CPU (lib.sh ci_take_cpu_slots, continuous-integration.md §5.7) ──
CPU_BUDGET="$(ci_cpu_budget)"
if [[ -n "$CPU_BUDGET" ]]; then
  W0=$SECONDS
  SLOT_WAIT="${MANDU_CI_SLOT_WAIT:-1800}"; [[ "$SLOT_WAIT" =~ ^[0-9]+$ ]] || SLOT_WAIT=1800
  if ci_take_cpu_slots "$CACHE/cpu-slots" "$VCPUS" "$CPU_BUDGET" "$SLOT_WAIT"; then
    (( SECONDS - W0 > 0 )) && log "waited $(( SECONDS - W0 ))s for host CPU (guests at once within ${CPU_BUDGET} vCPUs; this one ${VCPUS})"
  else
    log "WARNING: host CPU still taken after ${SLOT_WAIT}s (MANDU_CI_SLOT_WAIT): booting anyway, over the ${CPU_BUDGET}-vCPU budget"
  fi
fi

# ── the disks ──────────────────────────────────────────────────────────────
T0=$SECONDS
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
qemu-img create -q -f qcow2 -F qcow2 -b "$IMAGE" "$OVERLAY" || exit 2
ci_source_tar "$SRC" "$INPUT" || { log "could not archive the tree"; exit 2; }
# The per-push run's plain-run baselines (test-reorganization.md §6.9, step 5
# decision 8): what passing master runs promoted to this host's store rides in
# the input disk, read-only data for the guest, so its replays run the Mandu
# side alone. Not for the nightly (it reruns every plain run), --exec, --shell or --selftest.
if [[ $NETWORK -eq 0 && $OLLAMA -eq 0 && "$MODE" == run && "${MANDU_CI_NO_BASELINES:-0}" != 1 ]]; then
  BSTORE="$(mandu_path drill-baselines)"
  NB="$(ci_append_baselines "$BSTORE" "$INPUT")" || { log "could not add the replay baselines"; exit 2; }
  log "replay baselines: $NB promoted entr$([[ "$NB" == 1 ]] && echo y || echo ies) from $BSTORE (the per-push replays use them)"
fi
# The entries' measured costs (continuous-integration.md §5.4): each entry's
# median duration over this host's last green full runs orders the guest's
# queue, so a new or slower entry starts in time without anyone regenerating
# the checked-in tables. Only orders the queue: on any failure, or with no
# such run here (a fresh runner), the guest orders by the tables.
if [[ $NETWORK -eq 0 && $OLLAMA -eq 0 && "$MODE" == run && "${MANDU_CI_NO_MEASURED_COSTS:-0}" != 1 ]]; then
  CRUNS="$(mandu_path ci-runs)"
  if NCOST="$(ci_append_costs "$CRUNS" "$INPUT")"; then
    log "entry costs: $NCOST measured in $CRUNS (the guest's queue order; else the checked-in tables)"
  else
    log "entry costs: could not measure them from $CRUNS; the guest orders by the checked-in tables"
  fi
fi
printf '%s\n' "$JOBENV_TEXT" > "$WORK/job.env"
tar -rf "$INPUT" -C "$WORK" --owner=0 --group=0 --numeric-owner job.env || exit 2
truncate -s 2G "$OUTPUT" || exit 2
if [[ -n "$CRED" ]]; then
  # Written 0600, opened read-only on fd 7 (CRED_FD), unlinked at once: from
  # here the only reference is that fd, which qemu inherits. The token is never
  # in a variable, an argument or a log of this script.
  ( umask 077 && node "$CI/credential.mjs" prepare "$CRED" --out "$WORK/cred.tar" \
      --min-seconds "$((TIMEOUT + 300))" ) || record_error "credential: could not prepare the credential disk"
  exec 7<"$WORK/cred.tar"
  rm -f "$WORK/cred.tar"
fi
log "run $RUN_ID: $MODE, commit $COMMIT, guest $GUEST, image $IMAGE_NAME, ${VCPUS} vCPUs, ${MEM} MiB, timeout ${TIMEOUT}s"
log "input $(du -h "$INPUT" | cut -f1); console $CONSOLE"
if [[ $NETWORK -eq 1 || $OLLAMA -eq 1 ]]; then
  log "network: $([[ $NETWORK -eq 1 ]] && echo 'internet (slirp4netns, no host loopback)' || echo 'no uplink')$([[ $OLLAMA -eq 1 ]] && echo "; ollama $OLLAMA_GUEST_ADDR -> $OLLAMA_HOST_ADDR")"
fi
[[ -n "$CRED" ]] && log "credential: $CRED (read-only disk mandu-cred, gone with the guest)"

# ── the guest ──────────────────────────────────────────────────────────────
if [[ $OLLAMA -eq 1 ]]; then
  node "$CI/port-bridge.mjs" listen "$OLLAMA_SOCK" "$OLLAMA_HOST_ADDR" 2>>"$WORK/port-bridge.log" &
  PIDS+=($!)
  for _ in $(seq 1 50); do [[ -S "$OLLAMA_SOCK" ]] && break; sleep 0.1; done
  [[ -S "$OLLAMA_SOCK" ]] || record_error "ollama: the port bridge did not start"
fi

# guest [TIMEOUT]: run qemu; with a network, in its own user + network
# namespace (vm-image.sh's provisioning boot does the same), joined to
# slirp4netns --disable-host-loopback when the guest has an uplink. Either way
# qemu runs in the background so its -pidfile can be registered for `mandu
# reap` (scripts/lib/guest-registry.sh): a run killed hard leaves a guest that
# runs up to its whole timeout, and --shell's none at all. This script is the
# owner; the work dir goes with a leaked guest unless --keep.
guest() {
  local tmo=() qpid rc
  [[ -n "${1:-}" ]] && tmo=(timeout --kill-after=30 "$1")
  rm -f "$WORK/qemu.pid"
  if [[ -z "${BWRAP_NET:-}" ]]; then
    # 0<&0: a background job's stdin would be /dev/null; --shell's console needs the terminal.
    "${tmo[@]}" "${qemu[@]}" 0<&0 &
    qpid=$!
    guest_register "$qpid" "$WORK/qemu.pid" vm-run "$WORK" "$KEEP" ${SOCK_DIR:+"$SOCK_DIR"}
    wait "$qpid"; rc=$?
    guest_release
    return $rc
  fi
  local pidf="$WORK/ns.pid" go="$WORK/ns.go" rcf
  printf 'nameserver 10.0.2.3\n' > "$WORK/resolv.conf"
  rcf="$(readlink -f /etc/resolv.conf)"
  "${tmo[@]}" "$BWRAP_NET" --unshare-user --unshare-net --die-with-parent --dev-bind / / \
      --ro-bind "$WORK/resolv.conf" "$rcf" -- \
      bash -c 'echo $$ > "$1"; while [[ ! -e "$2" ]]; do sleep 0.1; done; shift 2; exec "$@"' \
      _ "$pidf" "$go" "${qemu[@]}" &
  qpid=$!
  for _ in $(seq 1 100); do [[ -s "$pidf" ]] && break; sleep 0.1; done
  if [[ ! -s "$pidf" ]]; then log "the guest's network namespace did not come up"; kill "$qpid" 2>/dev/null; wait "$qpid"; return 2; fi
  if [[ $NETWORK -eq 1 ]]; then
    slirp4netns --configure --mtu=65520 --disable-host-loopback "$(cat "$pidf")" tap0 > "$WORK/slirp4netns.log" 2>&1 &
    PIDS+=($!)
    sleep 1
  fi
  touch "$go"
  guest_register "$qpid" "$WORK/qemu.pid" vm-run "$WORK" "$KEEP" ${SOCK_DIR:+"$SOCK_DIR"}
  wait "$qpid"; rc=$?
  guest_release
  return $rc
}

if [[ $SHELL_MODE -eq 1 ]]; then
  log "shell: the serial console is this terminal (Ctrl-a x kills the guest)"
  guest
  exit 0
fi
guest "$TIMEOUT" </dev/null
qrc=$?
[[ -n "$CRED" ]] && exec 7<&-
T1=$SECONDS
log "guest exited ($qrc) after $((T1 - T0))s"

# The canary (§9): a token, or any 19 characters of it, anywhere in
# what came back (the console, the results disk) withholds both: the run is
# recorded as an `error` without them, and nothing of the guest's is printed.
LEAK=0
if [[ -n "$CRED" ]]; then
  node "$CI/credential.mjs" scan "$CRED" "$CONSOLE" "$OUTPUT"
  crc=$?
  if [[ $crc -ne 0 ]]; then
    LEAK=1
    log "CREDENTIAL CANARY: $([[ $crc -eq 1 ]] && echo 'the credential is in what the guest returned' || echo 'the scan failed'); the console and the results are withheld"
    : > "$CONSOLE"; truncate -s 0 "$OUTPUT"
  fi
fi
[[ $LEAK -eq 0 && -f "$CONSOLE" ]] && grep -a 'mandu-ci:' "$CONSOLE" | tr -d '\r' | sed 's/^/  guest| /' | tail -n 30 >&2
# A guest that did not power off by itself: the console's last lines too (the
# runner's heartbeat names what was still running), into the job log.
if [[ $LEAK -eq 0 && $qrc -ne 0 && -f "$CONSOLE" ]]; then
  log "the guest did not end by itself; the console's last 40 lines (all of it in the run's console.log):"
  tail -n 40 "$CONSOLE" | tr -d '\r' | sed 's/^/  console| /' >&2
fi

err=()
if [[ $LEAK -eq 1 ]]; then err=(--error "credential canary: the credential appeared in the guest's console or results; both withheld")
elif [[ $qrc -eq 124 || $qrc -eq 137 ]]; then err=(--error "timeout: the guest ran longer than ${TIMEOUT}s (MANDU_CI_TIMEOUT)")
elif [[ $qrc -ne 0 ]]; then err=(--error "qemu exited $qrc")
fi
# --only: the host's own selection; the collector pins a published job's
# records (the demo battery's) so no prune removes them (§6, pins).
node "$CI/collect-results.mjs" --archive "$OUTPUT" --run-id "$RUN_ID" --source "$SOURCE" \
  --commit "$COMMIT" --ref "$REF" --image "$IMAGE_NAME" --started "$STARTED" \
  --console "$CONSOLE" ${OUT:+--out "$OUT"} ${ONLY:+--only "$ONLY"} "${err[@]}" > "$WORK/collect.log" 2>&1
rc=$?
if [[ -n "$CRED" ]]; then
  # Belt and braces: what was published (the run dir, --out, and the
  # collector's report, which goes to the job log) is scanned again.
  RUN_DIR="$(mandu_path ci-runs)/$RUN_ID"
  if ! node "$CI/credential.mjs" scan "$CRED" "$WORK/collect.log" "$RUN_DIR" ${OUT:+"$OUT"}; then
    rm -rf "$RUN_DIR" ${OUT:+"$OUT"}
    : > "$WORK/collect.log"
    log "CREDENTIAL CANARY: the published results held the credential; removed"
    record_error "credential canary: the published results held the credential; removed"
  fi
fi
cat "$WORK/collect.log"
log "total $((SECONDS - T0))s"
exit $rc
