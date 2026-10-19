#!/usr/bin/env bash
#
# docker-run.sh — run ANY Mandu test kind inside the CI container.
#
# This is the ONLY supported way to start a container from packaging/docker/Dockerfile.ci,
# and it is the same command CI and a developer run — a red pipeline reproduces
# locally by copy-pasting the job's line. See docs/design/testing/docker-e2e.md §1.
#
#   scripts/ci/docker-run.sh core   -- npm run typecheck
#   scripts/ci/docker-run.sh userns -- scripts/test-all.sh
#   scripts/ci/docker-run.sh vm     -- scripts/kernel-vm.sh
#
# ── PROFILES: the privilege each job actually needs, and no more ──────────────
# Measured on the dev host (docs/design/testing/docker-e2e.md §1 "what Docker can and cannot host"):
#
#   core    no extra privilege. Everything that is pure userspace: typecheck,
#           unit, e2e, conformance, eval, cargo decision-logic, live-*.
#   userns  + seccomp=unconfined + apparmor=unconfined. Docker's DEFAULT seccomp
#           profile blocks clone(CLONE_NEWUSER), and AppArmor separately blocks
#           the mount namespace — so the launcher's namespace suites (the LIVE
#           e2e: net-proxy, MITM, exec-wrap, reply-filter, fs-preload) cannot run
#           without both. It does NOT need --privileged and NOT any added
#           capability: verified `unshare --user --map-root-user --mount --net
#           --pid --fork` → uid 0, plus `nft add chain … prerouting priority -150`
#           (net-supervisor's real TPROXY hook) inside the container.
#   vm      + /dev/kvm. Only scripts/kernel-vm.sh + the vm-matrix: the seccomp
#           ADDFD openat() REDIRECT needs kernel >= 5.9 and the host is 5.4, so a
#           guest kernel is the only way to assert it (a container shares the host
#           kernel — QEMU is not replaceable by Docker here).
#
# ── --kernel-tests: OFF by default (the sandbox kind's kernel tests) ──────────
# (Called --kernel-tier until 2026-10-02, when the manifest's tiers had become
# kinds, test-reorganization.md §4; the old flag is still accepted as an alias.)
# scripts/kernel-tests.sh (the Track B seccomp-unotify / nft-TPROXY attachment
# tests) additionally needs `unshare --mount-proc`, and that is blocked in a
# container for a non-obvious reason: Docker masks parts of /proc (/proc/kcore &c)
# with bind mounts, those count as LOCKED mounts, and the kernel then refuses to
# mount a fresh procfs over /proc inside a nested userns+mountns. The unlock is a
# THIRD security-opt, `systempaths=unconfined` (verified: with it --mount-proc
# works and all 16 Track B tests run; without it they SKIP).
#
# It is deliberately NOT in the `userns` profile. This Docker path does not run
# the kernel tests (CI runs the sandbox kind in a KVM guest, continuous-integration.md),
# and granting a /proc-masking relaxation for tests we do not run is privilege we
# have not earned. Pass --kernel-tests to opt in (locally).
#
# BEWARE the shape of the bug this hid: without --kernel-tests, kernel-tests.sh
# SKIPs and still counts GREEN, and its skip message blames "unprivileged userns
# unavailable" — which is FALSE in the container (userns works fine; only
# --mount-proc is blocked). Caught 2026-07-12 by diffing a container run (0 kernel
# tests) against the host (16). If you ever expect kernel tests in CI, assert the
# COUNT, not the colour. See docs/design/testing/docker-e2e.md §1.
#
# ── SECRETS / CREDENTIALS: opt-in, so the container IS the boundary ───────────
# Nothing model-facing is forwarded unless a flag says so. GitLab injects project
# variables into EVERY job's environment, so without this an "offline" job would
# still be holding a key and could silently go live and pass for the wrong reason.
# Here the offline containers provably have neither key nor credential.
#
#   --with-claude-auth  bind-mount the host's REAL ~/.claude (rw) as the
#                       container's credential store. The `claude` CLI inside is
#                       first-party Claude Code, so the Pro/Max SUBSCRIPTION
#                       authenticates it — CI needs NO Anthropic API key.
#                       It is a MOUNT, not a copy, on purpose: OAuth refresh
#                       tokens ROTATE, so a copied credential dies the moment
#                       the host refreshes —
#                       observed 2026-07-12, "OAuth session expired and could not
#                       be refreshed". One shared store has one token lineage and
#                       cannot go stale. (docs/design/agents/agent-sign-in.md §1 F1/F3.)
#   --with-codex-auth   same, for ~/.codex (codex's own ChatGPT login).
#   --publish-events    give the container a Mandu home at the host home's path
#                       whose events/ is the HOST's event dir (bind-mounted), so
#                       the run's sessions land in the dashboard you actually look
#                       at instead of dying with the container. Required for the
#                       sidebar's CI badge to have anything to badge.
#   --with-secrets      materialize API keys from the central secrets source
#                       (scripts/secrets-to-env.mjs) into a mode-600 env-file.
#                       Only needed by third-party-SDK clients that CANNOT use the
#                       subscription: eval --mode real-api, eval/agentdojo real
#                       (agent-sign-in.md §1 F4/F6/F7).
#   --with-npm-token    forward $NPM_TOKEN into the container. ONLY the manual
#                       release-publish job (packaging.md §11.3); every other job
#                       provably has no publish credential.
#   --out <dir>         bind-mount a HOST dir (created if absent) at /repo/release,
#                       read-write. The image bakes the source in — nothing a job
#                       writes survives the container — so this is how release-pack
#                       hands its tarball to GitLab as a job artifact, and how
#                       release-publish reads it back. Nothing else is mounted.
#
# --dry-run prints the docker argv it WOULD run (one arg per line) and exits 0;
# scripts/test/docker-run.test.sh asserts the profile→flags and secret-isolation
# contracts against it.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/paths/mandu-paths.sh
. "$REPO_ROOT/scripts/paths/mandu-paths.sh"

IMAGE="${MANDU_CI_IMAGE:-mandu-ci:latest}"
PROFILE=""
WITH_CLAUDE_AUTH=0
WITH_CODEX_AUTH=0
WITH_SECRETS=0
KERNEL_TESTS=0
PUBLISH_EVENTS=0
WITH_NPM_TOKEN=0
OUT_DIR=""
DO_BUILD=1
DRY_RUN=0

usage() { sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; }

case "${1:-}" in
  core|userns|vm) PROFILE="$1"; shift ;;
  -h|--help) usage; exit 0 ;;
  "") echo "docker-run: missing profile (core|userns|vm)" >&2; usage >&2; exit 2 ;;
  *) echo "docker-run: unknown profile '$1' (want core|userns|vm)" >&2; exit 2 ;;
esac

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-claude-auth) WITH_CLAUDE_AUTH=1; shift ;;
    --with-codex-auth)  WITH_CODEX_AUTH=1;  shift ;;
    --with-secrets)     WITH_SECRETS=1;     shift ;;
    # --kernel-tier: the flag's name until 2026-10-02 (tiers became kinds)
    --kernel-tests|--kernel-tier) KERNEL_TESTS=1; shift ;;
    --publish-events)   PUBLISH_EVENTS=1;   shift ;;
    --with-npm-token)   WITH_NPM_TOKEN=1;   shift ;;
    --out)              OUT_DIR="$2";       shift 2 ;;
    --no-build)         DO_BUILD=0;         shift ;;
    --dry-run)          DRY_RUN=1; DO_BUILD=0; shift ;;
    --image)            IMAGE="$2";         shift 2 ;;
    --) shift; break ;;
    *) echo "docker-run: unknown option '$1'" >&2; exit 2 ;;
  esac
done

if [[ $# -eq 0 ]]; then
  echo "docker-run: no command given (expected: … -- <cmd> [args…])" >&2
  exit 2
fi

# Keep the image in step with the working tree. In CI this is a cache hit on
# every layer but the source COPY; locally it is what makes `docker-run.sh` run
# YOUR edits rather than a stale build. --no-build/--dry-run skip it.
if [[ $DO_BUILD -eq 1 ]]; then
  MANDU_CI_IMAGE="$IMAGE" "$REPO_ROOT/scripts/ci/build-image.sh" >&2
fi

ARGS=(docker run --rm --init)

# Run as the invoking uid so a bind-mounted, mode-600 host credential is readable
# (and so anything written to a mounted cache is not root-owned).
ARGS+=(--user "$(id -u):$(id -g)")
ARGS+=(--workdir /repo)

# Everything this script starts IS a container, so the e2e harness's runtime tag is
# `docker` by construction — assert it here rather than hoping a caller exports it.
# (A caller may still override: the allowlist pass below runs after this and a later
# -e wins in docker.) This is what makes a CI batch badge 🐳 docker as well as CI —
# they are orthogonal: WHERE it ran vs WHO ran it.
ARGS+=(-e MANDU_E2E_RUNTIME=docker)

# Per-profile privilege. Nothing here is granted to `core`.
case "$PROFILE" in
  core) ;;
  userns)
    ARGS+=(--security-opt seccomp=unconfined --security-opt apparmor=unconfined)
    ;;
  vm)
    ARGS+=(--security-opt seccomp=unconfined --security-opt apparmor=unconfined)
    ARGS+=(--device /dev/kvm)
    ARGS+=(-v mandu-ci-vm-cache:/home/agent/.cache/mandu-vm)
    ARGS+=(-e MANDU_VM_CACHE=/home/agent/.cache/mandu-vm)
    ;;
esac

# Opt-in: unmask /proc so `unshare --mount-proc` works, which is what
# scripts/kernel-tests.sh needs. OFF by default — this Docker path does not run
# those tests (see header).
if [[ $KERNEL_TESTS -eq 1 ]]; then
  if [[ "$PROFILE" == "core" ]]; then
    echo "docker-run: --kernel-tests needs the userns (or vm) profile — core grants no namespaces" >&2
    exit 2
  fi
  ARGS+=(--security-opt systempaths=unconfined)
fi

# Cargo registry: SHARED, and safe to share. It is a download-only, content-addressed
# cache; cargo locks it while fetching, and with a warm registry there is no fetch at
# all. The image ships the dir agent-owned, so Docker seeds the fresh named volume
# with the right ownership (a root-owned volume would break the unprivileged build).
ARGS+=(-v mandu-ci-cargo-registry:/usr/local/cargo/registry)

# The build TARGET dir is deliberately NOT a shared volume — it stays inside the
# container's own writable layer and dies with it. Sharing it would couple every
# concurrent container together, which is the one thing this host must not do:
# The dev host is also the dev box, so a CI job and a developer's local run (and two CI
# jobs, once the runner's concurrency is raised) are expected to overlap. A shared
# target dir means (a) cargo's target lock makes one build BLOCK on the other, and
# (b) two different source trees thrash each other's fingerprints into rebuilds.
# The saving did not justify it: cold 14s vs warm 1.8s — ~12s, about what the lock
# contention would cost anyway. Isolation is worth 12s.

# Resolve a credential store on the HOST.
#
# $HOME is not enough: the GitLab runner deliberately runs under a clean CI HOME
# ($HOME/mandu-ci/cihome of the runner user — docs/design/testing/docker-e2e.md §1) that has no ~/.claude, so a
# naive "$HOME/.claude" would break --with-claude-auth in exactly the place it is
# meant to work. Fall back to the invoking user's REAL home from passwd, which is
# where `claude /login` actually wrote the credential. Explicitly overridable.
#   $MANDU_CLAUDE_HOME / $MANDU_CODEX_HOME  →  $HOME/.<name>  →  <passwd home>/.<name>
resolve_store() {
  local name="$1" override="$2"
  if [[ -n "$override" ]]; then printf '%s' "$override"; return; fi
  if [[ -d "$HOME/.$name" ]]; then printf '%s' "$HOME/.$name"; return; fi
  local pw_home
  pw_home="$(getent passwd "$(id -u)" | cut -d: -f6)"
  if [[ -n "$pw_home" && -d "$pw_home/.$name" ]]; then printf '%s' "$pw_home/.$name"; return; fi
  printf '%s' "$HOME/.$name"   # nonexistent: the caller reports it
}

# Credential stores — one shared store, never a copy (see header).
if [[ $WITH_CLAUDE_AUTH -eq 1 ]]; then
  CLAUDE_STORE="$(resolve_store claude "${MANDU_CLAUDE_HOME:-}")"
  if [[ ! -d "$CLAUDE_STORE" ]]; then
    echo "docker-run: --with-claude-auth but no credential store at $CLAUDE_STORE — run 'claude /login' on this host (or set \$MANDU_CLAUDE_HOME)" >&2
    exit 1
  fi
  ARGS+=(-v "$CLAUDE_STORE:/home/agent/.claude")
fi
if [[ $WITH_CODEX_AUTH -eq 1 ]]; then
  CODEX_STORE="$(resolve_store codex "${MANDU_CODEX_HOME:-}")"
  if [[ ! -d "$CODEX_STORE" ]]; then
    echo "docker-run: --with-codex-auth but no credential store at $CODEX_STORE — run 'codex login' on this host (or set \$MANDU_CODEX_HOME)" >&2
    exit 1
  fi
  ARGS+=(-v "$CODEX_STORE:/home/agent/.codex")
fi

# Publish the run's sessions to the HOST dashboard.
#
# Without this a CI e2e run is invisible: the container boots its own arbiter, the
# sessions land in the container's event dir, and they die with it — so the CI
# badge on the sidebar's group row would have nothing to badge. The container
# gets a Mandu home AT THE HOST HOME'S PATH (MANDU_HOME=<host home>) whose
# `events/` is the host's event dir, bind-mounted at the same path; the rest of
# that home is a container-private tmpfs owned by the container's uid (its
# state/ — the container arbiter's symbol DB — dies with the container). The
# container's arbiter, and the dashboard's test tenant (`events/test`), resolve
# into the mount by the path table alone, so a pipeline's batch shows up in the
# dashboard next to the ones you ran by hand — distinguishable precisely by that
# badge. Only MANDU_HOME moves the event dir (on-disk-layout.md §5, §9.1).
#
# The host side is the path table's `mandu-home` / `events` entries
# (scripts/paths/mandu-paths.sh; runtime-instances.md §12):
# ${MANDU_HOME:-<home>/.mandu}/events — ON DISK since 2026-09-05 (the old
# ${XDG_RUNTIME_DIR}/events default was a per-boot tmpfs; three reboots on
# 2026-09-04 erased every CI run from the dashboard).
#
# <home> is the invoking uid's PASSWD home, not $HOME: the GitLab runner runs
# jobs with HOME overridden to its clean CI home (docker-e2e.md §1 — that is the point of
# it), while "publish to the host dashboard" means the dashboard of the USER
# running the runner. Under a $HOME rule the CI sessions would silently land in
# <cihome>/.mandu and never reach the dashboard. A runner that sets MANDU_HOME
# (its systemd unit) publishes there.
#
# A test suite inside the container still isolates with its own MANDU_HOME
# (scripts/test-all.sh exports /dev/null/mandu-test-home), so only a Mandu
# session the command itself runs publishes here.
if [[ $PUBLISH_EVENTS -eq 1 ]]; then
  _home="$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6)"
  _home="${_home:-$HOME}"
  HOST_MANDU_HOME="$(mandu_path mandu-home "$_home")"
  EVENT_DIR="$(mandu_path events "$_home")"
  # Not under --dry-run: a dry run prints the argv and must not create the
  # passwd home's state dirs (the event-dir parity test dry-runs this).
  [[ $DRY_RUN -eq 1 ]] || mkdir -p "$EVENT_DIR"
  ARGS+=(--tmpfs "$HOST_MANDU_HOME:uid=$(id -u),gid=$(id -g),mode=0700")
  ARGS+=(-v "$EVENT_DIR:$EVENT_DIR")
  ARGS+=(-e "MANDU_HOME=$HOST_MANDU_HOME")
fi

# API keys, from the ONE central source (secrets file or already-set env — the
# loader lets env win, so a masked GitLab variable overrides the file).
ENV_FILE=""
if [[ $WITH_SECRETS -eq 1 ]]; then
  ENV_FILE="$(mktemp "${TMPDIR:-/tmp}/mandu-ci-env.XXXXXX")"
  chmod 600 "$ENV_FILE"
  trap 'rm -f "$ENV_FILE"' EXIT
  node "$REPO_ROOT/scripts/secrets-to-env.mjs" --format=env-file >"$ENV_FILE"
  if [[ ! -s "$ENV_FILE" ]]; then
    echo "docker-run: --with-secrets but no keys resolved (no secrets file, no env) — continuing keyless" >&2
  fi
  ARGS+=(--env-file "$ENV_FILE")
fi

# Test-behavior env passthrough. Deliberately an ALLOWLIST of non-secret knobs:
# never `-e` a bare name, or a GitLab-injected key would ride along into a job
# that must not have one.
#
# The AXIS/POSTURE knobs (MANDU_CONFIDENTIALITY / MANDU_INTEGRITY — read by
# the arbiter the container's entrypoint boots — and the MANDU_E2E_EXPECT_* /
# MANDU_E2E_CONF_INT posture-guard/fold selectors) MUST be on this list: a
# job variable that never reaches the container leaves the arbiter at its
# defaults while the pipeline claims a different fold — the exact silent-green
# "posture nobody runs" failure the suite's posture guard exists to catch (and
# with the guard set, the run then FAILS loudly instead of lying).
for v in MANDU_CI_REQUIRE_USERNS MANDU_TEST_DASHBOARD MANDU_E2E_ONLY \
         MANDU_E2E_DRIVER MANDU_E2E_CONCURRENCY MANDU_E2E_INTERACTIVE_CONCURRENCY \
         MANDU_E2E_MODELS MANDU_E2E_ORIGIN MANDU_E2E_RUNTIME \
         MANDU_CONFIDENTIALITY MANDU_INTEGRITY \
         MANDU_E2E_EXPECT_CONF MANDU_E2E_EXPECT_INT MANDU_E2E_CONF_INT \
         MANDU_DIFF_ONLY MANDU_DIFF_AGENT MANDU_DIFF_KEEP MANDU_DIFF_SIZES \
         MANDU_E2E_STRICT_INTERACTIVE \
         MANDU_BATCH_ID CI CI_COMMIT_SHA CI_JOB_ID CI_PIPELINE_ID TZ; do
  if [[ -n "${!v:-}" ]]; then ARGS+=(-e "$v=${!v}"); fi
done

# The publish credential: opt-in, one job (release-publish). Refuse to run
# with the flag and no token rather than let `npm publish` fail later.
if [[ $WITH_NPM_TOKEN -eq 1 ]]; then
  if [[ -z "${NPM_TOKEN:-}" ]]; then
    echo "docker-run: --with-npm-token but NPM_TOKEN is empty (a masked, protected project variable)" >&2
    exit 1
  fi
  ARGS+=(-e "NPM_TOKEN=$NPM_TOKEN")
fi

# The release output dir (see header): the one host path a job may write.
if [[ -n "$OUT_DIR" ]]; then
  [[ $DRY_RUN -eq 1 ]] || mkdir -p "$OUT_DIR"
  OUT_ABS="$(cd "$OUT_DIR" 2>/dev/null && pwd || printf '%s' "$OUT_DIR")"
  ARGS+=(-v "$OUT_ABS:/repo/release")
fi

ARGS+=("$IMAGE" "$@")

if [[ $DRY_RUN -eq 1 ]]; then
  printf '%s\n' "${ARGS[@]}"
  exit 0
fi

exec "${ARGS[@]}"
