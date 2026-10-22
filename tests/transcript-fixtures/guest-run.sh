#!/usr/bin/env bash
# guest-run.sh — make the past-sessions scan's real-store fixtures in the CI
# guest (tests/transcript-fixtures/generate.ts;
# docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md §6).
#
#   scripts/ci/vm-run.sh --worktree --network --vcpus 4 --mem 8192 \
#     --exec 'bash tests/transcript-fixtures/guest-run.sh'
#
# The guest image has the pinned OpenCode 1.x and 2.x, Goose and OpenClaw
# (scripts/ci/pins.env); OpenClaw 9.x (its SQLite store) is installed here
# into a temporary prefix, on the guest's own agent node, from npm
# (MANDU_FIXTURE_OPENCLAW9_VERSION, default 2026.9.9; that is what needs
# --network). The fixtures and their manifest land in release/transcripts,
# which vm-run.sh copies back under the run's artifacts/release/; copy them
# into arbiter/test/fixtures/transcripts/real/ and run the reader tests.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/release/transcripts"
mkdir -p "$OUT"

oc9="${MANDU_FIXTURE_OPENCLAW9_VERSION:-2026.9.9}"
node_bin=/opt/agent-node/bin
if [[ -x "$node_bin/npm" ]]; then
  prefix="$(mktemp -d)"
  trap 'rm -rf "$prefix"' EXIT
  if PATH="$node_bin:$PATH" "$node_bin/npm" install -g --no-audit --no-fund --prefix "$prefix" "openclaw@$oc9" >"$OUT/openclaw9-install.log" 2>&1; then
    printf '#!/bin/sh\nexec %s/node %s/lib/node_modules/openclaw/openclaw.mjs "$@"\n' "$node_bin" "$prefix" > "$prefix/openclaw9"
    chmod +x "$prefix/openclaw9"
    export MANDU_FIXTURE_OPENCLAW9_BIN="$prefix/openclaw9"
  else
    echo "guest-run: openclaw@$oc9 did not install (see openclaw9-install.log)" >&2
  fi
fi

cd "$ROOT/tests"
npx tsx transcript-fixtures/generate.ts --out "$OUT" "$@"
ls -la "$OUT"
cat "$OUT/manifest.json"
