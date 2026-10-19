#!/usr/bin/env bash
# fresh-agents host prep (docs/design/testing/os-test-matrix.md §10.14): everything
# fresh-install's prep packs (the bundle, the stub, the optional reduced Claude
# credential), plus the scripted model and the per-agent runner, the agent
# versions to install, and (FRESH_AGENTS_LIVE=1) the OpenAI key for the live
# Codex leg. The key goes ONLY into ephemeral/, which the executor deletes the
# moment the guest powers off, --keep or not.
set -euo pipefail
: "${ARTIFACT_DIR:?}" "${REPO_ROOT:?}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[[ "${FRESH_AGENTS_LIVE:-0}" == "1" ]] && export FRESH_INSTALL_LIVE=1
bash "$HERE/fresh-install.host.sh"

cp "$HERE/fresh-agents/fake-model.mjs" "$HERE/fresh-agents/agent-leg.sh" "$HERE/fresh-agents/env-twin-check.mjs" "$ARTIFACT_DIR/"

# Which agents the guest installs: the agent registry's agents whose CLI
# installs from npm (scripts/agents/agent-registry.mjs NPM_AGENTS; Goose ships
# as a release binary, so it has no leg here), in the registry's order.
AGENTS="$(node --input-type=module -e '
  const { pathToFileURL } = await import("node:url");
  const { NPM_AGENTS } = await import(pathToFileURL(process.argv[1]).href);
  console.log(NPM_AGENTS.join(" "));' "$REPO_ROOT/scripts/agents/agent-registry.mjs")" || true
[[ -n "$AGENTS" ]] || { echo "fresh-agents: cannot read the agents from scripts/agents/agent-registry.mjs" >&2; exit 1; }

# Which agent versions the guest installs. `tested` (default): each agent's
# tested MAX from the launcher's table (launcher/src/agent-versions.ts), the
# versions a release vouches for. `latest`: whatever npm serves today, the
# version a new user actually gets.
VERS="${FRESH_AGENTS_VERSIONS:-tested}"
if [[ "$VERS" == latest ]]; then
  for a in $AGENTS; do echo "$a=latest"; done > "$ARTIFACT_DIR/AGENT_VERSIONS"
else
  node -e '
    const s = require("fs").readFileSync(process.argv[1], "utf8");
    for (const a of process.argv[2].split(" ")) {
      const m = new RegExp(a + ":\\s*\\{[^}]*?max:\\s*\"([^\"]+)\"").exec(s);
      if (!m) { console.error("no tested max for " + a); process.exit(1); }
      console.log(a + "=" + m[1]);
    }' "$REPO_ROOT/launcher/src/agent-versions.ts" "$AGENTS" > "$ARTIFACT_DIR/AGENT_VERSIONS"
fi

# Which Node major the guest installs: the README's 22 unless the chosen
# OpenClaw's own `engines` rules it out (2026.9.3 and later need >= 24.16), then
# the lowest of 24, 26 whose current release satisfies it. Decided here, where
# npm and the network are at hand, so the guest's step 1 stays one nvm line.
# The range is compared by Mandu's own small parser (lib/node-major.mjs), not
# by npm's semver, which Debian's npm keeps outside npm's global root.
oc="$(sed -n 's/^openclaw=//p' "$ARTIFACT_DIR/AGENT_VERSIONS")"
range=""; [[ -n "$oc" ]] && range="$(npm view "openclaw@$oc" engines.node 2>/dev/null || true)"
curl -fsS https://nodejs.org/dist/index.json -o "$ARTIFACT_DIR/.node-index.json" 2>/dev/null || true
node "$HERE/../lib/node-major.mjs" "$range" "$ARTIFACT_DIR/.node-index.json" > "$ARTIFACT_DIR/NODE_MAJOR"
rm -f "$ARTIFACT_DIR/.node-index.json"
[[ -n "$range" ]] && echo "fresh-agents: openclaw@$oc wants node $range; the guest installs node $(cat "$ARTIFACT_DIR/NODE_MAJOR")" >&2

# The `full` legs (step 5) are an integrity form, frozen with the axis
# (protection-modes.md §10.5): they run only when asked, and then opt in.
rm -f "$ARTIFACT_DIR/INTEGRITY"
[[ "${FRESH_AGENTS_INTEGRITY:-0}" == "1" ]] && : > "$ARTIFACT_DIR/INTEGRITY"

if [[ "${FRESH_AGENTS_LIVE:-0}" == "1" ]]; then
  key="$(node -e 'try { process.stdout.write(require(process.argv[1]).openai_api_key || "") } catch {}' "$REPO_ROOT/secrets.local.json")"
  if [[ -n "$key" ]]; then
    mkdir -m 0700 -p "$ARTIFACT_DIR/ephemeral"
    ( umask 077; printf '%s' "$key" > "$ARTIFACT_DIR/ephemeral/openai.key" )
  else
    echo "fresh-agents: live Codex leg will SKIP (no openai_api_key in secrets.local.json)" >&2
  fi
fi
