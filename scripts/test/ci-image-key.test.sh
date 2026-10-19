#!/usr/bin/env bash
#
# ci-image-key.test.sh — the CI image key (scripts/ci/lib.sh ci_image_key, as
# `scripts/ci/vm-image.sh --key` prints it; docs/design/testing/continuous-integration.md
# §4): deterministic, and sensitive to exactly pins.env, vm-image.sh,
# scripts/ci/guest/**, every package-lock.json outside node_modules/ (private/
# ones included), and interceptors/Cargo.lock; per guest (§4.1: ubuntu-2604 has
# its own key, name and pruning). Runs in a throwaway git repo, so it
# needs only git and bash (no network, no KVM).
#
# Run:  bash scripts/test/ci-image-key.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PASS=0 FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d "${TMPDIR:-/tmp}/ci-image-key.XXXXXX")"; trap 'rm -rf "$T"' EXIT
F="$T/repo"
mkdir -p "$F/scripts/ci/guest" "$F/scripts/paths" "$F/scripts/lib" "$F/arbiter" "$F/interceptors" "$F/launcher/node_modules/dep" "$F/private/pkg" "$F/docs"
cp "$REPO/scripts/ci/lib.sh" "$REPO/scripts/ci/vm-image.sh" "$REPO/scripts/ci/pins.env" "$F/scripts/ci/"
cp "$REPO/scripts/paths/mandu-paths.sh" "$F/scripts/paths/"
cp "$REPO/scripts/lib/guest-registry.sh" "$REPO/scripts/lib/runtime-base.sh" "$F/scripts/lib/"
echo "boot" > "$F/scripts/ci/guest/boot.sh"
echo '{"lockfileVersion":3}' > "$F/arbiter/package-lock.json"
echo '{"lockfileVersion":3}' > "$F/launcher/package-lock.json"
echo '{"nested":1}' > "$F/launcher/node_modules/dep/package-lock.json"
echo '{"private":1}' > "$F/private/pkg/package-lock.json"
echo 'version = 3' > "$F/interceptors/Cargo.lock"
echo "# doc" > "$F/docs/README.md"
printf 'node_modules/\n' > "$F/.gitignore"
g() { git -C "$F" -c user.name=t -c user.email=t@t.invalid -c commit.gpgsign=false "$@"; }
g init -q -b main && g add -A && g add -f launcher/node_modules/dep/package-lock.json && g commit -qm base
key() { "$F/scripts/ci/vm-image.sh" --key "$@"; }
commit_all() { g add -A && g commit -qm "$1" --allow-empty; }

K0="$(key)"
[[ "$K0" =~ ^[0-9a-f]{16}$ ]] && pass "the key is 16 hex characters ($K0)" || fail "the key is 16 hex characters (got '$K0')"
[[ "$(key)" == "$K0" ]] && pass "deterministic: the same tree gives the same key" || fail "deterministic"
[[ "$(key --commit HEAD)" == "$K0" && "$(key --worktree)" == "$K0" ]] \
  && pass "a clean work tree has its commit's key" || fail "a clean work tree has its commit's key"
[[ "$(key --commit "$(g rev-parse HEAD)")" == "$K0" ]] && pass "--commit <sha> == --commit HEAD" || fail "--commit <sha>"

# Not in the key: sources, docs, nested lockfiles.
echo "# changed" >> "$F/docs/README.md"; echo "x" > "$F/arbiter/index.ts"
[[ "$(key --worktree)" == "$K0" ]] && pass "a source/doc change (work tree) keeps the key" || fail "a source/doc change keeps the key"
commit_all src
[[ "$(key)" == "$K0" ]] && pass "a source/doc change (commit) keeps the key" || fail "a source/doc change (commit) keeps the key"
echo '{"nested":2}' > "$F/launcher/node_modules/dep/package-lock.json"; g add -f launcher/node_modules/dep/package-lock.json
commit_all nested
[[ "$(key)" == "$K0" ]] && pass "lockfiles under node_modules/ are not in the key" || fail "lockfiles under node_modules/ are not in the key"

# In the key: a private/ package's lockfile (the source repo warms and runs its
# private rows; the public export has no private/, so its key is unaffected).
echo '{"private":2}' > "$F/private/pkg/package-lock.json"; commit_all private
KP="$(key)"
[[ "$KP" != "$K0" ]] && pass "a private/ lockfile is in the key" || fail "a private/ lockfile is in the key"
K0="$KP"

# In the key: each of these changes it, and changing it back restores it.
BASE="$(g rev-parse HEAD)"
for f in scripts/ci/pins.env scripts/ci/vm-image.sh scripts/ci/guest/boot.sh arbiter/package-lock.json interceptors/Cargo.lock; do
  cp "$F/$f" "$T/saved"
  echo "# touched" >> "$F/$f"
  kw="$(key --worktree)"
  commit_all "touch $f"
  kc="$(key)"
  if [[ "$kw" != "$K0" && "$kc" == "$kw" ]]; then pass "$f changes the key (work tree and commit agree)"
  else fail "$f changes the key (K0=$K0 worktree=$kw commit=$kc)"; fi
  cp "$T/saved" "$F/$f"; commit_all "restore $f"
  [[ "$(key)" == "$K0" ]] && pass "$f restored → the old key" || fail "$f restored → the old key"
done
echo "new" > "$F/scripts/ci/guest/new-unit.service"
[[ "$(key --worktree)" != "$K0" ]] && pass "a NEW untracked file under scripts/ci/guest/ changes the work-tree key" || fail "a new guest file changes the key"
rm "$F/scripts/ci/guest/new-unit.service"
mkdir -p "$F/newpkg" && echo '{}' > "$F/newpkg/package-lock.json"
[[ "$(key --worktree)" != "$K0" ]] && pass "a new package's lockfile changes the key" || fail "a new package's lockfile changes the key"
rm -rf "$F/newpkg"
[[ "$(key --commit "$BASE")" == "$K0" ]] && pass "an older commit keeps its own key" || fail "an older commit keeps its own key"
key --commit no-such-rev >/dev/null 2>&1 && fail "an unknown revision is refused" || pass "an unknown revision is refused"

# vm-image.sh --path names the image by the key, under the path table's
# `ci-cache`: MANDU_HOME's cache/ci (on-disk-layout.md §3); XDG_CACHE_HOME and
# the retired MANDU_CI_CACHE move nothing.
p="$(MANDU_HOME="$T/mh" XDG_CACHE_HOME="$T/xdg-cache" MANDU_CI_CACHE="$T/cache" "$F/scripts/ci/vm-image.sh" --path)"
[[ "$p" == "$T/mh/cache/ci/mandu-ci-$K0.qcow2" ]] && pass "--path is <home>/cache/ci/mandu-ci-<key>.qcow2" || fail "--path under MANDU_HOME (got $p)"
p="$(unset MANDU_HOME; HOME="$T/h" XDG_CACHE_HOME="$T/xdg-cache" "$F/scripts/ci/vm-image.sh" --path)"
[[ "$p" == "$T/h/.mandu/cache/ci/mandu-ci-$K0.qcow2" ]] && pass "--path defaults to ~/.mandu/cache/ci" || fail "--path default (got $p)"

# The guests (continuous-integration.md §4.1): the default's key and name are what
# they were before there were two; ubuntu-2604 has a key of its own (its name
# is hashed), a name that says the guest, and its own pruning.
[[ "$(key --guest ubuntu-2404)" == "$K0" ]] && pass "--guest ubuntu-2404 is the default (same key)" || fail "--guest ubuntu-2404 is the default"
K26="$(key --guest ubuntu-2604)"
[[ "$K26" =~ ^[0-9a-f]{16}$ && "$K26" != "$K0" ]] && pass "--guest ubuntu-2604 has a key of its own ($K26)" || fail "ubuntu-2604's key (got '$K26', default $K0)"
[[ "$(key --guest ubuntu-2604 --worktree)" == "$K26" && "$(key --commit HEAD --guest ubuntu-2604)" == "$K26" ]] \
  && pass "ubuntu-2604's key is deterministic, work tree and commit alike" || fail "ubuntu-2604's key is deterministic"
cp "$F/scripts/ci/pins.env" "$T/saved"; echo "# touched" >> "$F/scripts/ci/pins.env"
[[ "$(key --guest ubuntu-2604 --worktree)" != "$K26" ]] && pass "pins.env changes ubuntu-2604's key too" || fail "pins.env changes ubuntu-2604's key"
cp "$T/saved" "$F/scripts/ci/pins.env"
key --guest ubuntu-2204 >/dev/null 2>&1 && fail "an unknown guest is refused" || pass "an unknown guest is refused"
key --guest >/dev/null 2>&1 && fail "--guest without a value is refused" || pass "--guest without a value is refused"
p="$(MANDU_HOME="$T/mh" "$F/scripts/ci/vm-image.sh" --path --guest ubuntu-2604)"
[[ "$p" == "$T/mh/cache/ci/mandu-ci-ubuntu-2604-$K26.qcow2" ]] && pass "--path --guest ubuntu-2604 is mandu-ci-ubuntu-2604-<key>.qcow2" || fail "ubuntu-2604's path (got $p)"
( . "$F/scripts/ci/lib.sh"
  [[ "$(ci_pins_prefix ubuntu-2404)" == UBUNTU_ && "$(ci_pins_prefix ubuntu-2604)" == UBUNTU_2604_ ]] && ! ci_pins_prefix x 2>/dev/null ) \
  && pass "ci_pins_prefix: UBUNTU_ for 24.04, UBUNTU_2604_ for 26.04, nothing for an unknown guest" || fail "ci_pins_prefix"
# Pruning keeps the newest three of the guest it builds for and never counts
# the other guest's images: an existing image is "ensured" (touched), then
# pruned among its own kind. Fake images, so no build runs.
C="$T/mh/cache/ci"; mkdir -p "$C"
for i in 1 2 3 4 5; do
  echo x > "$C/mandu-ci-000000000000000$i.qcow2"; touch -d "@$((1000000000 + i))" "$C/mandu-ci-000000000000000$i.qcow2"
  echo x > "$C/mandu-ci-ubuntu-2604-000000000000000$i.qcow2"; touch -d "@$((1000000000 + i))" "$C/mandu-ci-ubuntu-2604-000000000000000$i.qcow2"
done
echo x > "$C/mandu-ci-ubuntu-2604-$K26.qcow2"
MANDU_HOME="$T/mh" "$F/scripts/ci/vm-image.sh" --guest ubuntu-2604 >/dev/null 2>&1
left26="$(cd "$C" && ls mandu-ci-ubuntu-2604-*.qcow2 | LC_ALL=C sort | tr '\n' ' ')"
left24="$(cd "$C" && ls mandu-ci-[0-9a-f]*.qcow2 | wc -l)"
[[ "$left26" == "mandu-ci-ubuntu-2604-0000000000000004.qcow2 mandu-ci-ubuntu-2604-0000000000000005.qcow2 mandu-ci-ubuntu-2604-$K26.qcow2 " && $left24 -eq 5 ]] \
  && pass "ubuntu-2604's build prunes to its newest three and leaves every 24.04 image" || fail "per-guest pruning (2604 left: $left26; 24.04 left: $left24)"
rm -f "$C"/mandu-ci-*.qcow2

# The source tar carries src/.git: a one-commit repository at the commit under
# test, clean for a commit, dirty for a --worktree run with an edit.
src_tar() { ( source "$F/scripts/ci/lib.sh"; CI_REPO_ROOT="$F"; ci_source_tar "$@" ); }
HEAD_SHA="$(g rev-parse HEAD)"
mkdir -p "$T/x"; src_tar HEAD "$T/c.tar" && tar -xf "$T/c.tar" -C "$T/x"
[[ "$(git -C "$T/x/src" rev-parse HEAD 2>/dev/null)" == "$HEAD_SHA" ]] \
  && pass "the source tar's src/.git has HEAD = the commit" || fail "src/.git HEAD (got $(git -C "$T/x/src" rev-parse HEAD 2>&1))"
[[ -z "$(git -C "$T/x/src" status --porcelain 2>&1)" ]] \
  && pass "a commit's checkout is a clean tree" || fail "a commit's checkout is clean (status: $(git -C "$T/x/src" status --porcelain 2>&1 | head -3))"
[[ "$(git -C "$T/x/src" rev-list --count HEAD 2>/dev/null)" == 1 && ! -e "$T/x/src/.git/hooks" ]] \
  && pass "src/.git holds one commit and no hooks" || fail "src/.git holds one commit and no hooks"
echo "edited" >> "$F/docs/README.md"
mkdir -p "$T/w"; src_tar --worktree "$T/w.tar" && tar -xf "$T/w.tar" -C "$T/w"
[[ "$(git -C "$T/w/src" status --porcelain 2>/dev/null)" == " M docs/README.md" ]] \
  && pass "a --worktree checkout shows its edit as a dirty tree" || fail "--worktree dirty (status: $(git -C "$T/w/src" status --porcelain 2>&1))"
git -C "$F" checkout -q -- docs/README.md

echo
echo "ci-image-key: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
