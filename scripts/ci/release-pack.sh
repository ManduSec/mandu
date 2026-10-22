#!/usr/bin/env bash
#
# release-pack.sh — build the release artifact for a tag from the PUBLIC tree
# (docs/design/distribution/packaging.md §11.3). Run by the `pack` job of
# .github/workflows/release.yml on the snapshot a `v*` tag names; writes
# release/, which that job hands to the publish job:
#
#   bash scripts/ci/release-pack.sh v0.2.0
#
# What it proves, in order (any failure is the job's red):
#   0. the tree is the public one: its launcher is not `private: true` (npm
#      would refuse the tarball, EPRIVATE) and the build can name the public
#      commit it came from (the snapshot's Mandu-Snapshot trailer, or
#      MANDU_BUILD_PUBLIC_COMMIT for a tree with no git);
#   1. the tag names the version every manifest carries (version-parity);
#   2. the launcher's native bins build (`kernel` feature, unprivileged) for
#      EVERY shipped tag — linux-x64 natively, linux-arm64 cross-built
#      (launcher/scripts/native-targets.mjs) — and ride into the one bundle;
#      the sudo-free `confined` posture on a stock Ubuntu 24.04 depends on
#      them (packaging.md §5, plan 10 §11.7). The arm64 bins are started
#      under qemu-user when the host has it: that proves they link and run
#      on an arm64 userland, not that they confine on arm64 hardware. Build
#      paths are remapped (--remap-path-prefix), so no bin names this host;
#   3. `npm pack` yields the self-contained artifact the npm-pack e2e
#      oracle accepts, and the license manifest is complete;
#   4. the tarball holds what a public package must and nothing it must not:
#      every native bin, NOTICE and LICENSE, a build-info naming both commits,
#      no `private` flag, no developer view, no source maps;
#   5. the tarball + its sha256 land in release/.
#
# It never publishes: the workflow's publish job does, after a maintainer
# approves the `release` environment.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAG="${1:?usage: release-pack.sh <tag, e.g. v0.1.0>}"
OUT="$REPO_ROOT/release"

cd "$REPO_ROOT"
VERSION="$(node -p "require('./launcher/package.json').version")"
if [[ "$TAG" != "v$VERSION" ]]; then
  echo "release-pack: tag '$TAG' does not match the manifests' version '$VERSION' — run scripts/set-version.sh ${TAG#v} and retag" >&2
  exit 1
fi
echo "release-pack: $TAG == launcher/package.json $VERSION"

# 0. the public tree, and the commit it is. A tree whose launcher is private
#    packs a tarball npm refuses and whose bundle may carry what the public
#    tree leaves out: refuse it here, with the reason, not at publish time.
if node -e 'process.exit(require("./launcher/package.json").private ? 0 : 1)'; then
  echo "release-pack: launcher/package.json is \`private: true\`: this is not the public tree. Pack the public repository's snapshot (packaging.md §11.3)." >&2
  exit 1
fi
PUBLIC_COMMIT="$(node --input-type=module -e 'import { resolveBuildInfo } from "./launcher/scripts/build-info.mjs"; console.log(resolveBuildInfo({ repoRoot: process.cwd() }).publicCommit ?? "")')"
if [[ -z "$PUBLIC_COMMIT" ]]; then
  echo "release-pack: no public commit to record: build from a checkout of a public snapshot (its Mandu-Snapshot trailer), or set MANDU_BUILD_PUBLIC_COMMIT" >&2
  exit 1
fi
echo "release-pack: public commit $PUBLIC_COMMIT"

# 1. one version everywhere, licenses complete (the two repo-hygiene suites).
( cd launcher && npx tsx --test test/unit/version-parity.test.ts test/unit/license-manifest.test.ts test/unit/node-floor.test.ts )

# 2. the native bins the bundle ships (a plain `cargo build` skips them), for
#    every tag: the host's (linux-x64) and the cross-built linux-arm64.
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/interceptors/target}"
ARM64_TRIPLE=aarch64-unknown-linux-gnu
# No bin may carry this host's paths (a home directory, a scratch dir): the
# same remap gives two builds of one commit the same bytes on any host.
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$REPO_ROOT=/mandu"
scripts/build-native.sh
scripts/build-native.sh --target "$ARM64_TRIPLE"
export MANDU_NATIVE_BIN_DIRS="linux-x64=$TARGET_DIR/release,linux-arm64=$TARGET_DIR/$ARM64_TRIPLE/release"
for dir in "$TARGET_DIR/release" "$TARGET_DIR/$ARM64_TRIPLE/release"; do
  for bin in mandu-exec-box mandu-landlock-apply mandu-net-guard; do
    if strings -a "$dir/$bin" | grep -qF -e "$REPO_ROOT" -e "$CARGO_HOME_DIR"; then
      echo "release-pack: $dir/$bin names a build path of this host (the remap did not apply)" >&2
      exit 1
    fi
  done
done
# An arm64 bin that cannot even start (wrong loader, missing symbol) would
# ship silently: start each once under qemu-user, where the image has it.
# Every bin answers an unknown flag with a line naming itself.
if command -v qemu-aarch64 >/dev/null 2>&1 && [ -d /usr/aarch64-linux-gnu ]; then
  for bin in mandu-exec-box mandu-landlock-apply mandu-net-guard; do
    out="$(qemu-aarch64 -L /usr/aarch64-linux-gnu "$TARGET_DIR/$ARM64_TRIPLE/release/$bin" --release-pack-smoke 2>&1 || true)"
    case "$out" in
      "$bin:"*) echo "release-pack: linux-arm64 $bin starts under qemu-aarch64" ;;
      *) echo "release-pack: linux-arm64 $bin did not start under qemu-aarch64: $out" >&2; exit 1 ;;
    esac
  done
else
  echo "release-pack: NOTE no qemu-aarch64 + /usr/aarch64-linux-gnu: the linux-arm64 bins are built but not started"
fi

# 3. the self-contained artifact, and the oracle that says it is one.
( cd launcher && npx tsx --test test/component/npm-pack.test.ts )
rm -rf "$OUT"; mkdir -p "$OUT"
( cd launcher && npm pack --silent --pack-destination "$OUT" >/dev/null )
TARBALL="$(ls "$OUT"/mandusec-mandu-*.tgz)"
( cd "$OUT" && sha256sum "$(basename "$TARBALL")" > SHA256SUMS )
echo "$PUBLIC_COMMIT" > "$OUT/COMMIT"

# 4/5. what the artifact is — printed so the job log is the manifest.
echo "release-pack: $(basename "$TARBALL") ($(du -h "$TARBALL" | cut -f1))"
cat "$OUT/SHA256SUMS"
tar -tzf "$TARBALL" | grep -E 'dist/native/' || true
# Every shipped tag carries every bin: a tag with a hole would leave that CPU
# `gated` with no word at pack time.
for tag in linux-x64 linux-arm64; do
  for bin in mandu-exec-box mandu-landlock-apply mandu-net-guard; do
    # No -q: an early exit would SIGPIPE tar, and pipefail would call the bin missing.
    tar -tzf "$TARBALL" | grep -x "package/dist/native/$tag/$bin" >/dev/null \
      || { echo "release-pack: $(basename "$TARBALL") is missing dist/native/$tag/$bin" >&2; exit 1; }
  done
done
echo "release-pack: native bins present for linux-x64 and linux-arm64"
# The commit the package says it is (`mandu version`, packaging.md §11.7): a
# release that cannot say which source it came from is not one.
INFO="$(tar -xzOf "$TARBALL" package/dist/build-info.json)"
echo "release-pack: dist/build-info.json: $(echo "$INFO" | tr -d '\n ')"
node -e 'if (!JSON.parse(process.argv[1]).sourceCommit) process.exit(1)' "$INFO" \
  || { echo "release-pack: dist/build-info.json names no source commit" >&2; exit 1; }
node -e 'const i = JSON.parse(process.argv[1]); if (i.publicCommit !== process.argv[2]) process.exit(1)' "$INFO" "$PUBLIC_COMMIT" \
  || { echo "release-pack: dist/build-info.json does not name the public commit $PUBLIC_COMMIT" >&2; exit 1; }
# What a public package must carry, and what it must not.
LIST="$(tar -tzf "$TARBALL")"
for f in package/NOTICE package/LICENSE; do
  grep -qx "$f" <<<"$LIST" || { echo "release-pack: $(basename "$TARBALL") lacks $f" >&2; exit 1; }
done
if grep -E 'dashboard-dev|dist/dashboard/dev/|bundle-stamp|\.map$' <<<"$LIST"; then
  echo "release-pack: $(basename "$TARBALL") carries the developer view, the build stamp or a source map (above)" >&2
  exit 1
fi
if tar -xzOf "$TARBALL" package/package.json | node -e 'process.exit(JSON.parse(require("fs").readFileSync(0, "utf8")).private ? 0 : 1)'; then
  echo "release-pack: the packed package.json is private: npm would refuse it" >&2
  exit 1
fi
echo "release-pack: public package checks passed (NOTICE, LICENSE, no developer view, not private)"
