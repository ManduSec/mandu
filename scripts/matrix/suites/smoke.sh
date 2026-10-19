#!/usr/bin/env bash
# deps:
# smoke — validates matrix plumbing end-to-end (docs/design/testing/os-test-matrix.md §4):
# the executor delivered the env contract and every matrix script parses.
# Runs with cwd = repo copy. Cheap enough for the per-push CI gate.
set -euo pipefail

[[ -n "${MATRIX_TARGET:-}" ]] || { echo "smoke: MATRIX_TARGET not set"; exit 1; }
[[ -d "${MATRIX_WORK:-/nonexistent}" ]] || { echo "smoke: MATRIX_WORK not a dir"; exit 1; }
[[ -f "scripts/matrix/run.sh" ]] || { echo "smoke: cwd is not a repo copy (no scripts/matrix/run.sh)"; exit 1; }

for f in scripts/matrix/run.sh scripts/matrix/run-matrix.sh \
         scripts/matrix/lib/*.sh scripts/matrix/suites/*.sh; do
  bash -n "$f" || { echo "smoke: syntax error in $f"; exit 1; }
done

echo "smoke ok: target=$MATRIX_TARGET labels=${MATRIX_LABELS:-—}"
