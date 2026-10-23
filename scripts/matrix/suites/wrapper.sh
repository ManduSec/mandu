#!/usr/bin/env bash
# deps: node
# run-as: matrix
# wrapper — the portable-wrapper parity e2e (docs/design/testing/os-test-matrix.md §4,
# docs/design/distribution/portable-wrapper.md §6). Runs the launcher package's own suite,
# which spawns a fake agent and asserts the composed context + the fail-closed
# arbiter-refuse — the OS-independence claim as a tested fact on each target.
# In a qemu guest it runs as the unprivileged user `matrix` (§4.2): the
# launcher's install.sh, safe-remove and secret-confinement tests refuse root
# or assert what an ordinary user may not touch (ubuntu-2604, 2026-10-23).
set -uo pipefail
[[ -d launcher ]] || { echo "wrapper: no launcher/ package"; exit 1; }
# The launcher suite is not self-contained: its bundle e2e builds from the
# sibling packages (arbiter imports js-yaml, …) and its golden path spawns the
# arbiter's tsx. Installing only launcher/ failed 14 tests on a fresh 26.04
# guest (2026-09-25: "Could not resolve js-yaml", "spawn arbiter/node_modules/
# .bin/tsx ENOENT"); a hand-kept list of those packages then missed the
# developer view the bundle builds when its source is in the tree (v0.2.0-beta.8's
# matrix, 2026-10-23). Install every package the bundle build reads, the list
# derived from launcher/bundle-manifest.json (scripts/suites.mjs packages
# --bundle), lockfile-exact.
node scripts/install-deps.mjs --bundle || { echo "wrapper: installing the bundle's packages failed"; exit 1; }
cd launcher
exec npm test --silent
