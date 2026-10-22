#!/usr/bin/env bash
# npm-release host prep (docs/design/testing/os-test-matrix.md §10.18): decide
# WHICH @mandusec/mandu the guest installs and put everything the guest needs
# beside it in $ARTIFACT_DIR. Unlike fresh-install, nothing is packed from the
# checkout: the guest installs a published version from the npm registry, or
# the release's candidate tarball before it is published.
#
#   NPM_RELEASE_PACKAGE=<spec>|<path.tgz>  default @mandusec/mandu@latest
#       a registry spec: the guest runs `npm install -g @mandusec/mandu@<v>`,
#       <v> resolved here (so both targets test one version);
#       a .tgz: the candidate tarball (npm releases runbook step 2), copied in.
#   NPM_RELEASE_UPGRADE_FROM=auto|none|<version>  default auto: the published
#       version before the one under test (for a candidate tarball: `latest`)
#   NPM_RELEASE_AGENTS="claude codex"   the agents to install from npm
#   NPM_RELEASE_AGENT_VERSIONS=latest|tested  default latest (what a new user
#       gets); tested = the launcher's tested max (launcher/src/agent-versions.ts)
#   NPM_RELEASE_BIG_REPO=<git url>  the "dirty, complex repo" the guest clones
#       and dirties; default the public Mandu repository
#   NPM_RELEASE_NODE_MAJOR=22       the README's Node
#   NPM_RELEASE_LIVE=1              the real-model legs (credentials below go
#       ONLY into ephemeral/, which the executor deletes when the guest stops):
#     Claude: NPM_RELEASE_CLAUDE_AUTH=api-key (default; anthropic_api_key from
#       the Mandu secrets file) | subscription (the access-token-only copy of
#       the host's Claude login, reduce-credential.mjs);
#       NPM_RELEASE_CLAUDE_MODEL=haiku (default)
#     Codex: openai_api_key from the Mandu secrets file, else the
#       access-token-only copy of the host's `codex login` (reduce-codex-auth.mjs)
set -euo pipefail
: "${ARTIFACT_DIR:?}" "${REPO_ROOT:?}"
HERE="$(cd "$(dirname "$0")" && pwd)"
NAME=@mandusec/mandu
ART="$ARTIFACT_DIR"

pkg="${NPM_RELEASE_PACKAGE:-$NAME@latest}"
if [[ "$pkg" == *.tgz ]]; then
  [[ -f "$pkg" ]] || { echo "npm-release: no tarball at $pkg" >&2; exit 1; }
  cp "$pkg" "$ART/"
  ver="$(tar -xzOf "$pkg" package/package.json | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).version))')"
  printf 'file %s\n' "$(basename "$pkg")" > "$ART/PACKAGE"
  sha1sum "$pkg" | cut -d' ' -f1 > "$ART/EXPECT_SHASUM"
  printf 'tgz:%s' "$ver" > "$ART/COMMIT"
else
  # `npm view <range> version` prints one line per match; the last is the highest.
  ver="$(npm view "$pkg" version 2>/dev/null | tail -1 | sed -E "s/^.*'([^']+)'.*$/\1/; s/^[^ ]+ //")"
  [[ -n "$ver" ]] || { echo "npm-release: npm resolves no version for $pkg" >&2; exit 1; }
  printf 'registry %s@%s\n' "$NAME" "$ver" > "$ART/PACKAGE"
  npm view "$NAME@$ver" dist.shasum > "$ART/EXPECT_SHASUM"
  printf 'npm:%s' "$ver" > "$ART/COMMIT"
fi
echo "$ver" > "$ART/EXPECT_VERSION"
echo "npm-release: the guest installs $(cat "$ART/PACKAGE") (version $ver)" >&2

# The version an existing user upgrades from: the published one before $ver
# (npm lists versions in semver order), or `latest` when $ver is not
# published yet. Stage builds (0.0.0-*) never count.
from="${NPM_RELEASE_UPGRADE_FROM:-auto}"
if [[ "$from" == auto ]]; then
  from="$(npm view "$NAME" versions --json 2>/dev/null | node -e '
    let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
      let v = []; try { v = [].concat(JSON.parse(s)); } catch {}
      v = v.filter((x) => !/^0\.0\.0-/.test(x));
      const i = v.indexOf(process.argv[1]);
      const before = i >= 0 ? v.slice(0, i) : v;
      console.log(before.length ? before[before.length - 1] : "none");
    });' "$ver")"
fi
[[ "$from" == "$ver" ]] && from=none
echo "${from:-none}" > "$ART/UPGRADE_FROM"

# The agents, at the versions a new user gets (or the tested max).
agents="${NPM_RELEASE_AGENTS:-claude codex}"
if [[ "${NPM_RELEASE_AGENT_VERSIONS:-latest}" == tested ]]; then
  node -e '
    const s = require("fs").readFileSync(process.argv[1], "utf8");
    for (const a of process.argv[2].split(" ").filter(Boolean)) {
      const m = new RegExp(a + ":\\s*\\{[^}]*?max:\\s*\"([^\"]+)\"").exec(s);
      if (!m) { console.error("no tested max for " + a); process.exit(1); }
      console.log(a + "=" + m[1]);
    }' "$REPO_ROOT/launcher/src/agent-versions.ts" "$agents" > "$ART/AGENT_VERSIONS"
else
  for a in $agents; do echo "$a=latest"; done > "$ART/AGENT_VERSIONS"
fi

echo "${NPM_RELEASE_BIG_REPO:-https://github.com/ManduSec/mandu.git}" > "$ART/BIG_REPO"
echo "${NPM_RELEASE_NODE_MAJOR:-22}" > "$ART/NODE_MAJOR"
echo "${NPM_RELEASE_CLAUDE_MODEL:-haiku}" > "$ART/CLAUDE_MODEL"
cp "$HERE/fresh-agents/fake-model.mjs" "$HERE/fresh-agents/agent-leg.sh" "$HERE/fresh-agents/env-twin-check.mjs" \
  "$HERE/npm-release/timing-leg.sh" "$ART/"

if [[ "${NPM_RELEASE_LIVE:-0}" == 1 ]]; then
  mkdir -m 0700 -p "$ART/ephemeral"
  secrets="${MANDU_HOME:-$HOME/.mandu}/secrets.json"
  field() { node -e 'try { process.stdout.write(require(process.argv[1])[process.argv[2]] || "") } catch {}' "$1" "$2"; }
  case "${NPM_RELEASE_CLAUDE_AUTH:-api-key}" in
    api-key)
      key="$(field "$secrets" anthropic_api_key)"
      if [[ -n "$key" ]]; then ( umask 077; printf '%s' "$key" > "$ART/ephemeral/anthropic.key" )
      else echo "npm-release: live Claude legs will SKIP (no anthropic_api_key in $secrets)" >&2; fi ;;
    subscription)
      node "$REPO_ROOT/scripts/matrix/lib/reduce-credential.mjs" \
        "${MANDU_CLAUDE_HOME:-$HOME/.claude}/.credentials.json" "$ART/ephemeral" 3600 \
        || echo "npm-release: live Claude legs will SKIP (no usable credential)" >&2 ;;
    *) echo "NPM_RELEASE_CLAUDE_AUTH must be api-key or subscription" >&2; exit 1 ;;
  esac
  key="$(field "$secrets" openai_api_key)"
  [[ -z "$key" && -f "$REPO_ROOT/secrets.local.json" ]] && key="$(field "$REPO_ROOT/secrets.local.json" openai_api_key)"
  if [[ -n "$key" ]]; then ( umask 077; printf '%s' "$key" > "$ART/ephemeral/openai.key" )
  else
    node "$REPO_ROOT/scripts/matrix/lib/reduce-codex-auth.mjs" "${CODEX_HOME:-$HOME/.codex}/auth.json" "$ART/ephemeral" 3600 \
      || echo "npm-release: live Codex legs will SKIP (no OpenAI key and no usable codex login)" >&2
  fi
fi
