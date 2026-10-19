#!/usr/bin/env bash
# deps: cargo node
# all — the canonical full stack: every package's unit + e2e suites
# (docs/design/testing/os-test-matrix.md §4). scripts/test-all.sh npm-installs missing
# node_modules itself, so a fresh target only needs node + cargo on PATH.
set -uo pipefail
# fs-sync's AgentView worktree seeding runs `git commit`, which needs an
# identity; a pristine target (fresh VM guest, bare CI user) has none, and the
# launcher then degrades out of fs-preload (found on ubuntu-2604: "unable to
# auto-detect email address"). Env-scoped identity keeps non-disposable
# targets (the future macOS laptop) unpolluted — no --global config writes.
export GIT_AUTHOR_NAME="mandu-matrix" GIT_AUTHOR_EMAIL="matrix@mandu.invalid"
export GIT_COMMITTER_NAME="mandu-matrix" GIT_COMMITTER_EMAIL="matrix@mandu.invalid"
# Keep every suite's full log where the executor collects it (the qemu guest's
# /mnt/out share); test-all.sh's summary tails name no failing test.
if [[ -d /mnt/out && -w /mnt/out ]]; then export MANDU_TEST_LOG_DIR=/mnt/out/test-all-logs; fi
exec scripts/test-all.sh
