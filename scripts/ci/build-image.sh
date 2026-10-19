#!/usr/bin/env bash
#
# build-image.sh — build the ONE CI image (packaging/docker/Dockerfile.ci) from the current
# working tree. Called automatically by scripts/ci/docker-run.sh; run it directly
# only to pre-warm the cache. See docs/design/testing/docker-e2e.md §1.
#
# Cost model (why calling this before every job is fine), measured on the dev host:
#   - source-only change  → only the final COPY layer rebuilds        ~10-30 s
#   - lockfile change     → the npm-ci dep layer rebuilds correctly   ~1-2 min
#   - cold / no cache     → apt + rustup + npm ci x13                 ~3 min
#
# The image is built with the CALLER's uid/gid so a bind-mounted mode-600 host
# credential (docker-run.sh --with-claude-auth) is readable inside the container.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

IMAGE="${MANDU_CI_IMAGE:-mandu-ci:latest}"

TAGS=(-t "$IMAGE")
# In CI also pin an immutable per-commit tag, so a job can never silently run an
# image some later pipeline rebuilt underneath it.
if [[ -n "${CI_COMMIT_SHA:-}" ]]; then
  TAGS+=(-t "mandu-ci:${CI_COMMIT_SHA}")
fi

echo "[build-image] building $IMAGE (uid=$(id -u) gid=$(id -g))"
DOCKER_BUILDKIT=1 docker build \
  -f packaging/docker/Dockerfile.ci \
  --build-arg "UID=$(id -u)" \
  --build-arg "GID=$(id -g)" \
  "${TAGS[@]}" \
  .

echo "[build-image] ok: $IMAGE"
