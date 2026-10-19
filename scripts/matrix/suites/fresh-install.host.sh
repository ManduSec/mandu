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
[[ -d node_modules ]] || npm ci --no-audit --no-fund
# The prebuilt native bins ride from the CHECKOUT's release tree (a `git
# archive` has no target/): with them the guest is `confined` with no sudo
# (plan 10 §11.7). Absent bins are a note in the pack log, and the guest's
# `fresh-posture=` label decides whether that is a failure.
export MANDU_NATIVE_BIN_DIR="${MANDU_NATIVE_BIN_DIR:-$REPO_ROOT/interceptors/target/release}"
npm pack --silent --pack-destination "$ARTIFACT_DIR" >/dev/null
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
