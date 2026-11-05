#!/usr/bin/env bash
# fresh-openclaw-plugin host prep (docs/design/testing/os-test-matrix.md §10.20):
# the scripted model, the OpenClaw version the guest installs and the Node
# major it needs, and the commit under test. Nothing is packed: the guest
# installs Mandu from its copy of the checkout (docs/development.md §1), since
# the OpenClaw plugin ships only in a checkout today.
set -euo pipefail
: "${ARTIFACT_DIR:?}" "${REPO_ROOT:?}"
HERE="$(cd "$(dirname "$0")" && pwd)"

{ git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown; git -C "$REPO_ROOT" diff --quiet 2>/dev/null || echo "+dirty"; } \
  | tr -d '\n' > "$ARTIFACT_DIR/COMMIT"

cp "$HERE/fresh-agents/fake-model.mjs" "$ARTIFACT_DIR/"

# Which OpenClaw the guest installs. `tested` (default): the launcher's tested
# max (launcher/src/agent-versions.ts), the version a release vouches for.
# `latest`: whatever npm serves today. Any other value is taken as a version.
want="${FRESH_OPENCLAW_VERSION:-tested}"
if [[ "$want" == tested ]]; then
  want="$(node -e '
    const s = require("fs").readFileSync(process.argv[1], "utf8");
    const m = /openclaw:\s*\{[^}]*?max:\s*"([^"]+)"/.exec(s);
    if (!m) { console.error("no tested max for openclaw"); process.exit(1); }
    console.log(m[1]);' "$REPO_ROOT/launcher/src/agent-versions.ts")"
fi
echo "$want" > "$ARTIFACT_DIR/OPENCLAW_VERSION"

# The Node major: the lowest of 22, 24, 26 whose current release satisfies the
# chosen OpenClaw's own `engines` (2026.9.3 and later need >= 24.16), decided
# here where npm and the network are at hand (fresh-agents.host.sh, the same
# parser: lib/node-major.mjs).
range="$(npm view "openclaw@$want" engines.node 2>/dev/null || true)"
curl -fsS https://nodejs.org/dist/index.json -o "$ARTIFACT_DIR/.node-index.json" 2>/dev/null || true
node "$HERE/../lib/node-major.mjs" "$range" "$ARTIFACT_DIR/.node-index.json" > "$ARTIFACT_DIR/NODE_MAJOR"
rm -f "$ARTIFACT_DIR/.node-index.json"
echo "fresh-openclaw-plugin: openclaw@$want${range:+ wants node $range}; the guest installs node $(cat "$ARTIFACT_DIR/NODE_MAJOR")" >&2
