#!/usr/bin/env bash
# fresh-install host prep (docs/design/testing/os-test-matrix.md §10.3.2): build
# and pack the @mandusec/mandu bundle ON THE HOST and place the tarball, plus the
# stub agent, in $ARTIFACT_DIR. The guest installs ONLY that tarball; it never
# sees the checkout. Run by the qemu executor before boot.
set -euo pipefail
: "${ARTIFACT_DIR:?}" "${REPO_ROOT:?}"

# FRESH_INSTALL_REF=<git ref> packs a CLEAN export of that commit instead of
# the working tree: what a release test wants, and the way to get a run while
# another session has the tree half-edited. Each package's node_modules is
# symlinked in from the checkout (build tooling only; the bundle is what ships).
SRC="$REPO_ROOT"
# Every package the bundle build reads gets its node_modules first, the
# developer view's among them when its source is here (a clean CI checkout has
# none: v0.2.0-beta.8's matrix failed "Could not resolve js-yaml" in it). The
# list comes from launcher/bundle-manifest.json (scripts/suites.mjs packages
# --bundle); each install is lockfile-exact and per-package locked, so two
# targets' preps at once install a package once. A FRESH_INSTALL_REF export
# links these node_modules in below.
node "$REPO_ROOT/scripts/install-deps.mjs" --bundle >&2
if [[ -n "${FRESH_INSTALL_REF:-}" ]]; then
  SRC="$(mktemp -d "${TMPDIR:-/tmp}/mandu-pack-src.XXXXXX")"
  trap 'rm -rf "$SRC"' EXIT
  git -C "$REPO_ROOT" archive "$FRESH_INSTALL_REF" | tar -x -C "$SRC"
  ( cd "$REPO_ROOT" && find . -maxdepth 4 -name node_modules -type d -prune -not -path './.git/*' 2>/dev/null || true ) |
    while read -r nm; do [[ -d "$SRC/$(dirname "$nm")" ]] && ln -s "$REPO_ROOT/$nm" "$SRC/$nm"; done || true
  git -C "$REPO_ROOT" rev-parse --short "$FRESH_INSTALL_REF" > "$ARTIFACT_DIR/COMMIT"
else
  { git -C "$REPO_ROOT" rev-parse --short HEAD; git -C "$REPO_ROOT" diff --quiet || echo "+dirty"; } \
    | tr -d '\n' > "$ARTIFACT_DIR/COMMIT" 2>/dev/null || echo unknown > "$ARTIFACT_DIR/COMMIT"
fi
cd "$SRC/launcher"
# Two targets packing the same working tree at once race on launcher/dist/
# (`npm pack` rebuilds it in prepack): one tarball then ships without its
# bundle ("mandu: bundle missing"; seen 2026-09-29 running 24.04 and 26.04
# side by side). Serialize on the directory itself, so no lock file is left.
exec {pack_lock}<"$SRC/launcher"
flock "$pack_lock"
# The prebuilt native bins ride from the CHECKOUT's release tree (a `git
# archive` has no target/): with them the guest is `confined` with no sudo
# (plan 10 §11.7). Absent bins are a note in the pack log, and the guest's
# `fresh-posture=` label decides whether that is a failure. A clean checkout
# (the CI runner's: v0.2.0-beta.8's install job) has no target/, so the prep
# builds them first with the CI pin's Rust (lib/rust-toolchain.sh), as the
# release pack does; scripts/build-native.sh is incremental, so a checkout
# whose bins are fresh pays a cargo no-op. MANDU_NATIVE_BIN_DIR set by the
# caller is used as it is, unbuilt.
if [[ -z "${MANDU_NATIVE_BIN_DIR:-}" ]]; then
  if command -v cargo >/dev/null 2>&1; then
    # shellcheck source=../lib/rust-toolchain.sh
    source "$REPO_ROOT/scripts/matrix/lib/rust-toolchain.sh"
    matrix_use_pinned_rust "$REPO_ROOT"
    "$REPO_ROOT/scripts/build-native.sh" >&2
  else
    echo "fresh-install: no cargo on PATH; packing with whatever native bins $REPO_ROOT/interceptors/target/release holds" >&2
  fi
fi
export MANDU_NATIVE_BIN_DIR="${MANDU_NATIVE_BIN_DIR:-$REPO_ROOT/interceptors/target/release}"
# --loglevel=error, not --silent: a failed prepack build (the bundle) prints
# its output on stderr, where --silent left only "host prep failed".
npm pack --loglevel=error --pack-destination "$ARTIFACT_DIR" >/dev/null
ls "$ARTIFACT_DIR"/mandusec-mandu-*.tgz >/dev/null
cp "$REPO_ROOT/scripts/matrix/suites/fresh-install/stub-claude.sh" "$ARTIFACT_DIR/claude"
chmod 0755 "$ARTIFACT_DIR/claude"

# Live leg (os-test-matrix.md §10.3.5): an ACCESS-TOKEN-ONLY copy of the
# host's Claude login. `ephemeral/` is deleted by the executor as soon as the
# guest powers off, --keep or not. No credential → the guest self-SKIPs the leg.
if [[ "${FRESH_INSTALL_LIVE:-0}" == "1" ]]; then
  mkdir -m 0700 -p "$ARTIFACT_DIR/ephemeral"
  node "$REPO_ROOT/scripts/matrix/lib/reduce-credential.mjs" \
    "${MANDU_CLAUDE_HOME:-$HOME/.claude}/.credentials.json" "$ARTIFACT_DIR/ephemeral" \
    "${FRESH_INSTALL_MIN_TOKEN_SECONDS:-3600}" \
    || echo "fresh-install: live leg will SKIP (no usable credential)" >&2
fi
