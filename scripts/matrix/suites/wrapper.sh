#!/usr/bin/env bash
# deps: node
# wrapper — the portable-wrapper parity e2e (docs/design/testing/os-test-matrix.md §4,
# docs/design/distribution/portable-wrapper.md §6). Runs the launcher package's own suite,
# which spawns a fake agent and asserts the composed context + the fail-closed
# arbiter-refuse — the OS-independence claim as a tested fact on each target.
set -uo pipefail
[[ -d launcher ]] || { echo "wrapper: no launcher/ package"; exit 1; }
# The launcher suite is not self-contained: its bundle e2e builds from the
# sibling packages (arbiter imports js-yaml, …) and its golden path spawns the
# arbiter's tsx. Installing only launcher/ failed 14 tests on a fresh 26.04
# guest (2026-09-25: "Could not resolve js-yaml", "spawn arbiter/node_modules/
# .bin/tsx ENOENT"). Install every package the launcher reaches, lockfile-exact.
for pkg in arbiter dashboard fs-sync interceptors/*/ launcher; do
  pkg="${pkg%/}"
  [[ -f "$pkg/package.json" && ! -d "$pkg/node_modules" ]] || continue
  echo "wrapper: installing $pkg"
  if [[ -f "$pkg/package-lock.json" ]]; then
    ( cd "$pkg" && npm ci --no-audit --no-fund ) || { echo "wrapper: npm ci failed in $pkg"; exit 1; }
  else
    ( cd "$pkg" && npm install --no-audit --no-fund ) || { echo "wrapper: npm install failed in $pkg"; exit 1; }
  fi
done
cd launcher
exec npm test --silent
