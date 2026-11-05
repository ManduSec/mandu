#!/usr/bin/env bash
# macos-run.sh — the macOS check: the manifest's darwin entries (the kinds
# unit, component, stack and sandbox; what `scripts/test-all.sh` selects on a
# Mac) on a Mac, with summary.json, junit.xml and logs/ in --out.
# docs/design/testing/continuous-integration.md §12.6.
#
#   scripts/ci/macos-run.sh [--out DIR] [--dry-run]
#
# Where it runs: the GitLab `macos` job on the self-hosted Mac runner (the
# macOS schedule), the GitHub `macos` job (a release check or a manual run, on
# GitHub's arm64 and Intel images), and by hand on any Mac.
#
# Not in a VM and not in a sandbox: macOS cannot nest Seatbelt, so the
# Seatbelt suites must run outside any profile. On the Mac runner the boundary
# is the runner's own account (not an admin, no logins or keys) and a scratch
# HOME; the job holds no credential but GitLab's own per-job token.
#
# The toolchain: MANDU_CI_NODE_DIR (a node install whose bin/ goes first on
# PATH) and MANDU_CI_OPENSSL_PREFIX (an OpenSSL 3, e.g. Homebrew's openssl@3)
# when set (the Mac runner's config.toml sets both); else node from PATH and
# Homebrew's openssl@3 where it is installed. LibreSSL (/usr/bin/openssl)
# alone is not enough for the TLS suites.
#
# Exit: 0 green; 1 a suite failed, or a Seatbelt entry did not pass or
# skipped a test it must run (a skip there means the run was inside another
# sandbox or the profile could not start, so it proved nothing); 2 this host
# cannot run the check (not macOS, no node 22.15+, no usable sandbox-exec, an
# install failed). Never green by absence.
#
# bash 3.2 (macOS /bin/bash): no mapfile, no associative arrays.
set -euo pipefail

OUT=ci-out
DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) [ -n "${2:-}" ] || { echo "macos-run.sh: --out needs a directory" >&2; exit 2; }; OUT="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
    *) echo "macos-run.sh: unknown option $1" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"

# The suites and the installs never need a CI secret: keep GitLab's job token
# and the publish tokens out of their environment.
unset NPM_TOKEN NODE_AUTH_TOKEN CI_JOB_TOKEN CI_REGISTRY_PASSWORD CI_DEPENDENCY_PROXY_PASSWORD CI_DEPLOY_PASSWORD CI_REPOSITORY_URL GITHUB_TOKEN ACTIONS_RUNTIME_TOKEN 2>/dev/null || true

fail_host() { echo "macos-run.sh: $*" >&2; exit 2; }

[ "$(uname -s)" = Darwin ] || fail_host "not macOS ($(uname -s))"
if [ -n "${MANDU_CI_NODE_DIR:-}" ]; then PATH="$MANDU_CI_NODE_DIR/bin:$PATH"; fi
SSL="${MANDU_CI_OPENSSL_PREFIX:-}"
if [ -z "$SSL" ]; then
  for p in /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3; do
    if [ -x "$p/bin/openssl" ]; then SSL="$p"; break; fi
  done
fi
[ -n "$SSL" ] && [ -x "$SSL/bin/openssl" ] || fail_host "no OpenSSL 3 (set MANDU_CI_OPENSSL_PREFIX, or brew install openssl@3)"
export PATH="$SSL/bin:$PATH"
for c in git node npm openssl script; do
  command -v "$c" >/dev/null || fail_host "$c not found on PATH"
done
node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 15) ? 0 : 1)' \
  || fail_host "node $(node --version) is older than 22.15 (launcher/package.json engines)"
# The Seatbelt suites need an unnested sandbox-exec: a run started inside
# another profile (an agent session's own sandbox) would skip them all.
/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny file-read* (literal "/nonexistent-mandu-ci"))' /usr/bin/true \
  || fail_host "sandbox-exec cannot apply a profile here (is this run itself inside a sandbox?)"
echo "macOS $(sw_vers -productVersion) $(uname -m); node $(node --version); $(openssl version); $(git --version)"

IMAGE="darwin-$(sw_vers -productVersion)-$(uname -m)"
if [ "${GITLAB_CI:-}" = true ]; then
  SOURCE=gitlab
  RUN_ID="gl-${CI_PIPELINE_ID}-${CI_JOB_ID}"
  COMMIT="$CI_COMMIT_SHA"
  REF="${CI_COMMIT_REF_NAME:-master}"
else
  # A GitHub run and a run by hand are both "local" to the summary's schema
  # (collect-results.mjs: gitlab or local); the run id says which.
  SOURCE=local
  COMMIT="$(git rev-parse HEAD)"
  REF="${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD)}"
  if [ -n "${GITHUB_RUN_ID:-}" ]; then
    RUN_ID="gh-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT:-1}-$(uname -m)"
  else
    RUN_ID="local-$(date -u +%Y%m%dT%H%M%SZ)-$(printf '%s' "$COMMIT" | cut -c1-12)"
    [ -z "$(git status --porcelain --untracked-files=normal)" ] || COMMIT="$COMMIT+dirty"
  fi
fi
KINDS="unit,component,stack,sandbox"
if [ "$DRY" = 1 ]; then
  echo "would run: node scripts/run-suites.mjs --kind $KINDS --run-id $RUN_ID --source $SOURCE --commit $COMMIT --ref $REF --image $IMAGE --out $OUT"
  exit 0
fi

# Every TS package, as the Linux guest installs them (provision.sh): npm ci.
while IFS= read -r d; do
  [ -n "$d" ] && [ -f "$d/package-lock.json" ] || continue
  echo "npm ci: $d"
  (cd "$d" && npm ci --no-audit --no-fund --loglevel=error) || fail_host "npm ci failed in $d"
done < <(node scripts/suites.mjs packages)

# A scratch HOME (short: a macOS socket path must fit in 104 bytes) with a
# git identity for the suites' own commits; never the account's own home.
SUITE_HOME="$(mktemp -d /tmp/mdu-h.XXXXXX)"
trap 'rm -rf "$SUITE_HOME"' EXIT
printf '[user]\n\tname = Mandu CI\n\temail = ci@mandu.invalid\n[init]\n\tdefaultBranch = main\n' > "$SUITE_HOME/.gitconfig"

rm -rf "$OUT"
rc=0
env -u XDG_RUNTIME_DIR HOME="$SUITE_HOME" \
  node scripts/run-suites.mjs --kind "$KINDS" \
  --run-id "$RUN_ID" --source "$SOURCE" --commit "$COMMIT" --ref "$REF" --image "$IMAGE" --out "$OUT" || rc=$?

# Never green by absence: both Seatbelt entries ran and passed, and skipped
# nothing but git-sandbox's xcrun-cache test (every other test in the two
# files is gated on the sandbox probe; an entry with one pass and the rest
# skipped would still read "pass").
OUT="$OUT" node -e '
  const s = JSON.parse(require("fs").readFileSync(process.env.OUT + "/summary.json", "utf8"));
  const maxSkip = { "launcher.darwin-seatbelt": 0, "launcher.darwin-git-sandbox": 1 };
  const bad = Object.keys(maxSkip).filter((id) => {
    const e = (s.entries || []).find((x) => x.id === id);
    return !e || e.result !== "pass" || !(e.skip <= maxSkip[id]);
  });
  if (bad.length) { console.error("macos-run.sh: Seatbelt entries did not pass, or skipped tests: " + bad.join(", ")); process.exit(1); }
' || exit 1
echo "macos-run.sh: run-suites exit $rc"
exit "$rc"
