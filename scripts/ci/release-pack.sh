#!/usr/bin/env bash
#
# release-pack.sh — build the release artifact for a tag, inside the CI
# guest (docs/design/distribution/packaging.md §11.3; writes release/, which vm-run.sh --exec
# returns as artifacts/release/). Run by the `release-pack` job:
#
#   scripts/ci/vm-run.sh --exec "bash scripts/ci/release-pack.sh v0.1.0" --out ci-out   # what CI runs (continuous-integration.md §7)
#
# What it proves, in order (any failure is the job's red):
#   1. the tag names the version every manifest carries (version-parity);
#   2. the launcher's native bins build (`kernel` feature, unprivileged) for
#      EVERY shipped tag — linux-x64 natively, linux-arm64 cross-built
#      (launcher/scripts/native-targets.mjs) — and ride into the one bundle;
#      the sudo-free `confined` posture on a stock Ubuntu 24.04 depends on
#      them (packaging.md §5, plan 10 §11.7). The arm64 bins are started
#      under qemu-user when the image has it: that proves they link and run
#      on an arm64 userland, not that they confine on arm64 hardware;
#   3. `npm pack` yields the self-contained artifact the npm-pack e2e
#      oracle accepts, and the license manifest is complete;
#   4. the tarball + its sha256 land in release/ as the job artifact.
#
# It never publishes: `release-publish` is a separate MANUAL job. Run in
# Mandu Security's source repository, it packs a launcher that is
# `private: true`, so npm refuses the tarball; in the public tree (the
# export, with no `private`) the same steps make the publishable one
# (packaging.md §11.4).
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

# 1. one version everywhere, licenses complete (the two repo-hygiene suites).
( cd launcher && npx tsx --test test/unit/version-parity.test.ts test/unit/license-manifest.test.ts test/unit/node-floor.test.ts )

# 2. the native bins the bundle ships (a plain `cargo build` skips them), for
#    every tag: the host's (linux-x64) and the cross-built linux-arm64.
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/interceptors/target}"
ARM64_TRIPLE=aarch64-unknown-linux-gnu
scripts/build-native.sh
scripts/build-native.sh --target "$ARM64_TRIPLE"
export MANDU_NATIVE_BIN_DIRS="linux-x64=$TARGET_DIR/release,linux-arm64=$TARGET_DIR/$ARM64_TRIPLE/release"
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
git rev-parse HEAD > "$OUT/COMMIT"

# 4. what the artifact is — printed so the job log is the manifest.
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
