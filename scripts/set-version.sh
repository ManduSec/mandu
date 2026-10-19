#!/usr/bin/env bash
#
# set-version.sh — stamp ONE release version across every manifest.
#
#   scripts/set-version.sh 0.1.0
#
# Mandu has no root package.json/workspace (docs/development.md): 15 standalone npm
# packages plus one Cargo workspace. They release together, as one product,
# so they carry one version; launcher/test/unit/version-parity.test.ts refuses
# a tree where any manifest disagrees. This script is the only sanctioned way
# to bump: it rewrites `"version"` in every package.json (and package-lock.json
# where present), `[workspace.package] version` in interceptors/Cargo.toml,
# and prints what changed. It never commits or tags (docs/design/distribution/packaging.md §11).
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-}"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "usage: scripts/set-version.sh <major.minor.patch[-prerelease]>  (got: '${VERSION}')" >&2
  exit 2
fi

cd "$REPO_ROOT"

# Every package.json outside node_modules / vendored trees, one level deep or
# under interceptors/ or tests/ — the same set license-manifest.test.ts and
# version-parity.test.ts enumerate.
mapfile -t PKGS < <(ls -d ./*/package.json ./interceptors/*/package.json ./tests/*/package.json 2>/dev/null | sort)

node - "$VERSION" "${PKGS[@]}" <<'EOF'
const fs = require("node:fs");
const [version, ...paths] = process.argv.slice(2);
for (const p of paths) {
  for (const file of [p, p.replace(/package\.json$/, "package-lock.json")]) {
    if (!fs.existsSync(file)) continue;
    const text = fs.readFileSync(file, "utf8");
    const json = JSON.parse(text);
    const before = json.version;
    json.version = version;
    // package-lock's root entry mirrors package.json's version.
    if (json.packages && json.packages[""] && json.packages[""].version !== undefined) {
      json.packages[""].version = version;
    }
    const indent = /^\{\n(\s+)/.exec(text)?.[1] ?? "  ";
    fs.writeFileSync(file, JSON.stringify(json, null, indent) + "\n");
    console.log(`${file}: ${before} -> ${version}`);
  }
}
EOF

CARGO="interceptors/Cargo.toml"
before="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$CARGO" | head -1)"
# Only the [workspace.package] line: it is the first `version = "…"` in the file.
sed -i "0,/^version = \".*\"$/s//version = \"$VERSION\"/" "$CARGO"
echo "$CARGO: $before -> $VERSION"
# Cargo.lock carries each crate's version; refresh it without a network fetch.
if command -v cargo >/dev/null 2>&1; then
  (cd interceptors && cargo update --workspace --offline -q 2>/dev/null) || \
    echo "note: cargo update --workspace --offline failed; run \`cd interceptors && cargo update --workspace\` yourself" >&2
fi

# The MCP servers (inspect-mcp, policy-mcp) announce their version in
# `initialize`; the bundle cannot read a package.json, so the constant is
# rewritten here.
for MCP in interceptors/inspect-mcp/src/mcp-server.ts interceptors/policy-mcp/src/mcp-server.ts; do
  sed -i "s/^const SERVER_VERSION = \"[^\"]*\";/const SERVER_VERSION = \"$VERSION\";/" "$MCP"
  echo "$MCP: SERVER_VERSION -> $VERSION"
done

# The Homebrew formula names the release tarball by version
# (packaging/homebrew/mandu.rb; its sha256 is set when the tarball exists).
BREW="packaging/homebrew/mandu.rb"
sed -i "s/mandusec-mandu-[0-9][^\"]*\.tgz/mandusec-mandu-$VERSION.tgz/" "$BREW"
echo "$BREW: url -> mandusec-mandu-$VERSION.tgz"

echo "done: version $VERSION everywhere. Now: update CHANGELOG.md, commit, then \`git tag v$VERSION\`."
