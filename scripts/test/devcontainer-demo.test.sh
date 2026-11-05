#!/usr/bin/env bash
#
# devcontainer-demo.test.sh — the "Try Mandu" container (.devcontainer/, what
# the README's "Open in GitHub Codespaces" starts) builds, and `mandu demo`
# passes in it under Docker's defaults: the default seccomp profile, no added
# capability, not privileged, the image's non-root user
# (docs/design/distribution/packaging.md §3.1).
#
# It builds the image from .devcontainer/Dockerfile (which installs the
# published @mandusec/mandu from the npm registry, so it needs the internet),
# then in fresh containers of it: the user is not root and Node meets Mandu's
# floor; `mandu doctor` runs (it always exits 0) and its output is kept in
# the log; `mandu demo` exits 0 with its closing line. A container shares the
# host's kernel, so what the demo's guard can attach is the host's: the log
# keeps the demo's `--verbose` lines (the guard, or why there is none).
#
# Needs a Docker engine the caller can reach; without one it SKIPs (exit 0,
# "1 skipped, 0 failed"). MANDU_DEVCONTAINER_VERSION=<version> builds with
# that package version instead of `latest`. MANDU_DEVCONTAINER_TARBALL=<tgz>
# installs that package tarball (e.g. `npm pack` of a tree with its native
# bins built) over the published one in an image built on top, to test a
# change before it is released.
#
# Run:  bash scripts/test/devcontainer-demo.test.sh
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIR="$ROOT/.devcontainer"
PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP: $1"; echo "1 skipped, 0 failed"; exit 0; }

command -v docker >/dev/null 2>&1 || skip "no docker on PATH"
docker info >/dev/null 2>&1 || skip "no Docker engine this user can reach (docker info failed)"
[[ -f "$DIR/Dockerfile" && -f "$DIR/devcontainer.json" ]] || { fail ".devcontainer/Dockerfile and devcontainer.json exist"; echo "0 passed, 1 failed"; exit 1; }

IMG="mandu-try-it-test:$$"
BASE_IMG="$IMG"
STAGE=""
cleanup() {
  docker image rm -f "$IMG" "$BASE_IMG" >/dev/null 2>&1 || true
  [[ -n "$STAGE" ]] && rm -rf "$STAGE"
}
trap cleanup EXIT

# The build context is .devcontainer/ (devcontainer.json's build has no
# `context`, so it is the file's own directory).
build_args=()
[[ -n "${MANDU_DEVCONTAINER_VERSION:-}" ]] && build_args=(--build-arg "MANDU_VERSION=$MANDU_DEVCONTAINER_VERSION")
echo "== docker build $DIR ${build_args[*]}"
if docker build "${build_args[@]}" -t "$IMG" "$DIR"; then
  pass "the devcontainer image builds"
else
  fail "the devcontainer image builds"
  echo "$PASS passed, $FAIL failed"
  exit 1
fi

if [[ -n "${MANDU_DEVCONTAINER_TARBALL:-}" ]]; then
  [[ -f "$MANDU_DEVCONTAINER_TARBALL" ]] || { fail "MANDU_DEVCONTAINER_TARBALL is a file"; echo "$PASS passed, $FAIL failed"; exit 1; }
  STAGE="$(mktemp -d)"
  cp "$MANDU_DEVCONTAINER_TARBALL" "$STAGE/mandu.tgz"
  printf 'FROM %s\nUSER root\nCOPY mandu.tgz /tmp/mandu.tgz\nRUN npm install -g /tmp/mandu.tgz && rm /tmp/mandu.tgz\nUSER node\n' "$BASE_IMG" > "$STAGE/Dockerfile"
  IMG="$BASE_IMG-tarball"
  echo "== docker build (the tarball $MANDU_DEVCONTAINER_TARBALL over the published package)"
  if docker build -t "$IMG" "$STAGE"; then
    pass "the tarball installs over the published package"
  else
    fail "the tarball installs over the published package"
    echo "$PASS passed, $FAIL failed"
    exit 1
  fi
fi

# Every run is `docker run --rm` with no security option, capability or
# device: Docker's defaults, as a devcontainer host starts it.
run() { docker run --rm "$IMG" "$@"; }

uid="$(run id -u 2>&1)"
if [[ "$uid" =~ ^[0-9]+$ && "$uid" != 0 ]]; then pass "the container runs as a non-root user (uid $uid)"; else fail "the container runs as a non-root user (got: $uid)"; fi

floor="$(sed -n 's/^NODE_FLOOR="\([0-9.]*\)"$/\1/p' "$ROOT/scripts/install.sh")"
if run node -e '
  const p = (v) => v.replace(/^v/, "").split(".").map(Number);
  const [v, f] = [p(process.version), p(process.argv[1])];
  for (let i = 0; i < 3; i++) { if (v[i] !== f[i]) process.exit(v[i] > f[i] ? 0 : 1); }
' "$floor"; then
  pass "the container's Node ($(run node --version)) meets Mandu's floor $floor"
else
  fail "the container's Node meets Mandu's floor $floor"
fi

echo "== mandu --version"
run mandu --version || true

echo "== mandu doctor"
doc_out="$(run timeout -s KILL 120 mandu doctor 2>&1)"; doc_rc=$?
printf '%s\n' "$doc_out"
if [[ $doc_rc -eq 0 && "$doc_out" == *Node* ]]; then pass "mandu doctor runs (exit 0)"; else fail "mandu doctor runs (exit $doc_rc)"; fi

echo "== mandu demo --verbose"
demo_out="$(run timeout -s KILL 240 mandu demo --verbose 2>&1)"; demo_rc=$?
printf '%s\n' "$demo_out"
why="exit $demo_rc"; [[ $demo_rc -eq 137 ]] && why+=": killed after 240 s"
if [[ $demo_rc -eq 0 ]]; then pass "mandu demo exits 0"; else fail "mandu demo exits 0 ($why)"; fi
if grep -q "The AI never got the key" <<<"$demo_out"; then pass "mandu demo ends with its result line"; else fail "mandu demo ends with its result line"; fi
if grep -q "could not run" <<<"$demo_out"; then fail "mandu demo did not stop with 'could not run'"; else pass "mandu demo did not stop with 'could not run'"; fi

echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
