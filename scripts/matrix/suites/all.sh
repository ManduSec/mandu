#!/usr/bin/env bash
# deps: cargo node
# run-as: matrix
# all — the canonical full stack: every package's unit + e2e suites
# (docs/design/testing/os-test-matrix.md §4). scripts/test-all.sh npm-installs missing
# node_modules itself, so a fresh target only needs node + cargo on PATH.
# In a qemu guest it runs as the unprivileged user `matrix` (§4.2), as CI's
# guest runs the same suites as `ci`: several of them refuse root or assert
# what an ordinary user may not touch.
set -uo pipefail
# fs-sync's AgentView worktree seeding runs `git commit`, which needs an
# identity; a pristine target (fresh VM guest, bare CI user) has none, and the
# launcher then degrades out of fs-preload (found on ubuntu-2604: "unable to
# auto-detect email address"). A qemu guest gets one as CI's guest does, in
# the system config (lib/qemu.sh, a run-as suite). Elsewhere, only when the
# caller has none, an env-scoped one keeps a non-disposable target (the future
# macOS laptop) unpolluted, no --global config writes. Never GIT_AUTHOR_* /
# GIT_COMMITTER_* over an identity that exists: they override the author of
# every commit made, a cherry-pick's included, and private.import-public-pr
# asserts a contributor's (ubuntu-2604, 2026-10-23).
if [[ -z "$(git config user.email 2>/dev/null)" ]]; then
  export GIT_AUTHOR_NAME="mandu-matrix" GIT_AUTHOR_EMAIL="matrix@mandu.invalid"
  export GIT_COMMITTER_NAME="mandu-matrix" GIT_COMMITTER_EMAIL="matrix@mandu.invalid"
fi
# Keep every suite's full log where the executor collects it (MATRIX_OUT: the
# qemu guest's /mnt/out share, or the part of it the run-as user can write);
# test-all.sh's summary tails name no failing test.
out="${MATRIX_OUT:-/mnt/out}"
if [[ -d "$out" && -w "$out" ]]; then export MANDU_TEST_LOG_DIR="$out/test-all-logs"; fi
# The CI pin's toolchain, never the caller's `rustup default` (lib/rust-toolchain.sh).
# shellcheck source=../lib/rust-toolchain.sh
source scripts/matrix/lib/rust-toolchain.sh
matrix_use_pinned_rust . || exit 1
# Half the CPUs at a time, as CI's pipeline runs them (scripts/ci/pipeline.sh), at most 8.
jobs=$(( $(nproc) / 2 )); (( jobs < 1 )) && jobs=1; (( jobs > 8 )) && jobs=8
exec scripts/test-all.sh --jobs "$jobs"
