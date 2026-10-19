#!/usr/bin/env bash
# vm-image.sh — build (or find) the CI guest image (docs/design/testing/continuous-integration.md §4).
#
#   scripts/ci/vm-image.sh [--commit REV | --worktree]   # ensure it; print its path
#   scripts/ci/vm-image.sh --key  [--commit REV | --worktree]  # print the image key
#   scripts/ci/vm-image.sh --path [--commit REV | --worktree]  # print where it is/would be
#       [--guest ubuntu-2404|ubuntu-2604] [--force] [--vcpus N] [--mem MiB] [--keep-build]
#
# The image is chosen by the guest (default ubuntu-2404; ubuntu-2604 is the
# Linux 7.0 kernel-tier guest, continuous-integration.md §4.1) and the key of the
# tree under test (default HEAD): a hash of scripts/ci/pins.env, this file,
# scripts/ci/guest/**, every package-lock.json outside node_modules/ (private/
# ones included when the checkout has them), and interceptors/Cargo.lock, plus
# the guest's name for a guest other than the default (scripts/ci/lib.sh
# ci_image_key). It lives at the path table's `ci-cache`
# (${MANDU_HOME:-~/.mandu}/cache/ci)/mandu-ci-<key>.qcow2 (another guest:
# mandu-ci-<guest>-<key>.qcow2); the newest three of each guest (by last use)
# are kept, older ones pruned.
#
# Building one:
#   1. the base: the dated Ubuntu cloud image pins.env names for the guest
#      (UBUNTU_CLOUD_* for 24.04, UBUNTU_2604_CLOUD_* for 26.04), cached
#      under <cache>/base/, verified against that release's SHA256SUMS;
#   2. a standalone qcow2 copy of it, grown to MANDU_CI_IMAGE_SIZE (64G,
#      sparse), a cloud-init seed (genisoimage or xorriso) whose runcmd
#      unpacks the input disk and runs scripts/ci/guest/provision.sh, and the
#      input disk: a tar of the tree (virtio serial mandu-in, read-only);
#   3. one boot WITH user-mode network, the only boot that has one. The code
#      it runs (provision.sh, npm lifecycle scripts) comes from the tree under
#      test, so qemu runs in its own network namespace (Mandu's granted
#      bwrap or a bwrap that can create one) joined to slirp4netns
#      --disable-host-loopback: the guest reaches the internet, never a port
#      on the host's loopback (where a live stack listens).
#      MANDU_CI_PROVISION_NET=plain opts out (plain qemu SLIRP, whose 10.0.2.2
#      IS the host's loopback) where that is impossible;
#   4. success is `MANDU-CI-PROVISION: OK <key>` on the serial console; the
#      console log is kept at <cache>/logs/<image name>.provision.log.
#
# Needs qemu-system-x86_64, qemu-img, genisoimage or xorriso, curl, and
# /dev/kvm (the kvm group) for a build that takes minutes, not hours.
set -uo pipefail

CI_REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null)" \
  || { echo "vm-image: not in a git checkout" >&2; exit 2; }
# shellcheck source=scripts/ci/lib.sh
. "$CI_REPO_ROOT/scripts/ci/lib.sh"

SRC=HEAD ACTION=ensure FORCE=0 KEEP_BUILD=0 GUEST="$CI_DEFAULT_GUEST"
VCPUS="${MANDU_CI_IMAGE_VCPUS:-16}" MEM="${MANDU_CI_IMAGE_MEM:-16384}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --commit) SRC="$2"; shift 2 ;;
    --worktree) SRC=--worktree; shift ;;
    --guest) [[ $# -ge 2 ]] || { echo "vm-image: --guest needs a value" >&2; exit 2; }; GUEST="$2"; shift 2 ;;
    --key) ACTION=key; shift ;;
    --path) ACTION=path; shift ;;
    --force) FORCE=1; shift ;;
    --keep-build) KEEP_BUILD=1; shift ;;
    --vcpus) VCPUS="$2"; shift 2 ;;
    --mem) MEM="$2"; shift 2 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "vm-image: unknown option $1" >&2; exit 2 ;;
  esac
done

ci_check_guest "$GUEST" || exit 2
KEY="$(ci_image_key "$SRC" "$GUEST")" || exit 2
CACHE="$(ci_cache_dir)"
IMAGE_NAME="$(ci_image_name "$GUEST" "$KEY")"
IMAGE="$CACHE/$IMAGE_NAME.qcow2"
case "$ACTION" in
  key) echo "$KEY"; exit 0 ;;
  path) echo "$IMAGE"; exit 0 ;;
esac

log() { echo "vm-image: $*" >&2; }

# prune_images: keep the newest three of this guest by mtime (vm-run.sh
# touches an image it boots); skip one in use (vm-run.sh holds a shared lock on
# it). Another guest's images are not counted: the nightly's 26.04 images never
# push a per-push 24.04 image out, nor the other way round.
prune_images() {
  local n=0 img
  while IFS= read -r img; do
    n=$((n + 1))
    (( n <= 3 )) && continue
    [[ "$img" == "$IMAGE" ]] && continue
    if flock -n -x "$img" true 2>/dev/null; then rm -f "$img" && log "pruned $(basename "$img")"
    else log "kept $(basename "$img") (in use)"; fi
  done < <(ls -1t "$CACHE"/$(ci_image_glob "$GUEST") 2>/dev/null)
}

mkdir -p "$CACHE/base" "$CACHE/logs"
exec 9>"$CACHE/.build.lock"
flock 9
if [[ -s "$IMAGE" && $FORCE -eq 0 ]]; then
  touch "$IMAGE"; prune_images; echo "$IMAGE"; exit 0
fi

have() { command -v "$1" >/dev/null 2>&1; }
for t in qemu-system-x86_64 qemu-img curl sha256sum; do have "$t" || { log "$t not found"; exit 2; }; done
have genisoimage || have xorriso || { log "need genisoimage or xorriso (cloud-init seed)"; exit 2; }
ci_have_kvm || log "WARNING: no read-write /dev/kvm: the build runs under TCG and takes hours"

BUILD="$(mktemp -d "$CACHE/build-$KEY.XXXXXX")"
cleanup() { guest_release; [[ $KEEP_BUILD -eq 1 ]] || rm -rf "$BUILD"; [[ -n "${TAILPID:-}" ]] && kill "$TAILPID" 2>/dev/null; [[ -n "${SLIRPPID:-}" ]] && kill "$SLIRPPID" 2>/dev/null; }
trap cleanup EXIT
T0=$SECONDS

# ── the tree and its pins ──────────────────────────────────────────────────
log "image $IMAGE_NAME (guest $GUEST, tree: ${SRC})"
ci_source_tar "$SRC" "$BUILD/input.tar" || { log "could not make the source tar"; exit 1; }
tar -xOf "$BUILD/input.tar" src/scripts/ci/pins.env > "$BUILD/pins.env" || { log "the tree has no scripts/ci/pins.env"; exit 1; }
ci_read_pins "$BUILD/pins.env" || exit 1
# The guest's base-image pins (§4.1): UBUNTU_CLOUD_* or UBUNTU_2604_CLOUD_*.
PFX="$(ci_pins_prefix "$GUEST")" || exit 2
v="${PFX}CLOUD_BASE"; CLOUD_BASE="${!v:-}"
v="${PFX}CLOUD_RELEASE"; CLOUD_RELEASE="${!v:-}"
v="${PFX}CLOUD_IMAGE"; CLOUD_IMAGE="${!v:-}"
[[ -n "$CLOUD_BASE" && -n "$CLOUD_RELEASE" && -n "$CLOUD_IMAGE" ]] \
  || { log "pins.env has no ${PFX}CLOUD_BASE/_RELEASE/_IMAGE for the guest $GUEST"; exit 1; }

# ── 1. the base image ──────────────────────────────────────────────────────
# The SHA256SUMS file is named by the image too: two guests' releases can
# share a date (noble's and resolute's release-2026MMDD are different files).
base="$CACHE/base/${CLOUD_IMAGE%.img}.$CLOUD_RELEASE.img"
sums="$CACHE/base/SHA256SUMS.${CLOUD_IMAGE%.img}.$CLOUD_RELEASE"
url="$CLOUD_BASE/$CLOUD_RELEASE"
if [[ ! -s "$sums" ]]; then
  curl -fsSL --retry 3 -o "$sums.part" "$url/SHA256SUMS" && mv "$sums.part" "$sums" \
    || { log "cannot fetch $url/SHA256SUMS (a dated release is removed after some months: bump ${PFX}CLOUD_RELEASE in pins.env)"; exit 1; }
fi
want="$(awk -v f="$CLOUD_IMAGE" '$2 == f || $2 == "*" f { print $1 }' "$sums")"
[[ "$want" =~ ^[0-9a-f]{64}$ ]] || { log "$CLOUD_IMAGE is not in $sums"; exit 1; }
if [[ ! -s "$base" ]] || [[ "$(sha256sum "$base" | cut -d' ' -f1)" != "$want" ]]; then
  log "downloading $url/$CLOUD_IMAGE"
  curl -fSL --retry 3 -o "$base.part" "$url/$CLOUD_IMAGE" || { log "download failed"; exit 1; }
  [[ "$(sha256sum "$base.part" | cut -d' ' -f1)" == "$want" ]] || { log "sha256 mismatch for the base image"; rm -f "$base.part"; exit 1; }
  mv "$base.part" "$base"
fi
log "base $(basename "$base") (sha256 verified)"

# ── 2. disks and seed ──────────────────────────────────────────────────────
qemu-img convert -O qcow2 "$base" "$BUILD/image.qcow2" || exit 1
qemu-img resize -q "$BUILD/image.qcow2" "${MANDU_CI_IMAGE_SIZE:-64G}" || exit 1
mkdir -p "$BUILD/seed"
printf 'instance-id: %s\nlocal-hostname: mandu-ci\n' "$IMAGE_NAME" > "$BUILD/seed/meta-data"
cat > "$BUILD/seed/user-data" <<EOF
#cloud-config
# mandu CI image $IMAGE_NAME: one provisioning boot (scripts/ci/vm-image.sh).
users: []
disable_root: true
ssh_pwauth: false
package_update: false
package_upgrade: false
runcmd:
  - [ bash, -c, "mkdir -p /var/lib/mandu-ci/in && tar -x -f /dev/disk/by-id/virtio-mandu-in -C /var/lib/mandu-ci/in --no-same-owner && bash /var/lib/mandu-ci/in/src/scripts/ci/guest/provision.sh /var/lib/mandu-ci/in/src $KEY; systemctl poweroff" ]
EOF
if have genisoimage; then
  genisoimage -quiet -output "$BUILD/seed.iso" -volid cidata -joliet -rock "$BUILD/seed/user-data" "$BUILD/seed/meta-data"
else
  xorriso -as mkisofs -quiet -o "$BUILD/seed.iso" -V cidata -J -r "$BUILD/seed/user-data" "$BUILD/seed/meta-data"
fi || { log "seed ISO failed"; exit 1; }

# ── 3. the provisioning boot ───────────────────────────────────────────────
CONSOLE="$BUILD/console.log"
: > "$CONSOLE"
read -r -a accel <<<"$(ci_accel)"
# cache=unsafe: the guest's flushes stay in the host's page cache (dpkg and
# npm fsync per file; on a spinning disk that made the build ~50x slower). The
# image is flushed once, after a good boot and before it is published (below).
qemu=(qemu-system-x86_64 "${accel[@]}" -smp "$VCPUS" -m "$MEM"
      -display none -serial "file:$CONSOLE" -monitor none -no-reboot -pidfile "$BUILD/qemu.pid"
      -drive "file=$BUILD/image.qcow2,if=none,id=sys,format=qcow2,discard=unmap,cache=unsafe"
      -device virtio-blk-pci,drive=sys,bootindex=0
      -drive "file=$BUILD/seed.iso,if=virtio,format=raw,readonly=on"
      -drive "file=$BUILD/input.tar,if=none,id=in,format=raw,readonly=on"
      -device "virtio-blk-pci,drive=in,serial=mandu-in"
      -netdev user,id=n0 -device virtio-net-pci,netdev=n0)
TIMEOUT="${MANDU_CI_IMAGE_TIMEOUT:-5400}"

follow() {  # echo the provisioning steps from the console as they appear
  local n=0 m
  while sleep 5; do
    m="$(grep -acE '=== provision|MANDU-CI-PROVISION' "$CONSOLE")"
    if (( m > n )); then
      grep -aE '=== provision|MANDU-CI-PROVISION' "$CONSOLE" | sed -n "$((n + 1)),${m}p" | tr -d '\r' >&2
      n=$m
    fi
  done
}
follow &
TAILPID=$!

NET="${MANDU_CI_PROVISION_NET:-isolated}"
if [[ "$NET" == isolated ]]; then
  bw=""
  for c in "${MANDU_CI_BWRAP:-}" "$(command -v bwrap 2>/dev/null)" /usr/lib/mandu/bin/bwrap; do
    [[ -n "$c" && -x "$c" ]] && "$c" --unshare-user --unshare-net --ro-bind / / -- /bin/true 2>/dev/null && { bw="$c"; break; }
  done
  if [[ -z "$bw" ]] || ! have slirp4netns; then
    log "cannot isolate the provisioning boot from the host's loopback: need a bwrap that can create a user+network namespace (on Ubuntu 24.04: \`mandu setup\`) and slirp4netns. MANDU_CI_PROVISION_NET=plain builds without that isolation."
    exit 2
  fi
  log "provisioning boot (network: own netns + slirp4netns --disable-host-loopback; ${VCPUS} vCPUs, ${MEM} MiB; timeout ${TIMEOUT}s; console $CONSOLE)"
  printf 'nameserver 10.0.2.3\n' > "$BUILD/resolv.conf"
  rc_target="$(readlink -f /etc/resolv.conf)"
  pidf="$BUILD/ns.pid" go="$BUILD/ns.go"
  "$bw" --unshare-user --unshare-net --die-with-parent --dev-bind / / \
        --ro-bind "$BUILD/resolv.conf" "$rc_target" -- \
        bash -c 'echo $$ > "$1"; while [[ ! -e "$2" ]]; do sleep 0.1; done; shift 2; exec timeout "$@"' \
        _ "$pidf" "$go" "$TIMEOUT" "${qemu[@]}" &
  QPID=$!
  for _ in $(seq 1 100); do [[ -s "$pidf" ]] && break; sleep 0.1; done
  [[ -s "$pidf" ]] || { log "the network namespace did not come up"; exit 1; }
  slirp4netns --configure --mtu=65520 --disable-host-loopback "$(cat "$pidf")" tap0 > "$BUILD/slirp4netns.log" 2>&1 &
  SLIRPPID=$!
  sleep 1
  touch "$go"
  # Registered for `mandu reap` (scripts/lib/guest-registry.sh): a leaked
  # provisioning guest keeps the build lock (fd 9) open, so every later build
  # waits on it, and leaves a build dir of up to 64 GiB.
  guest_register "$QPID" "$BUILD/qemu.pid" vm-image "$BUILD" "$KEEP_BUILD"
  wait "$QPID"; qrc=$?
  guest_release
elif [[ "$NET" == plain ]]; then
  log "WARNING: MANDU_CI_PROVISION_NET=plain: the provisioning guest can reach the host's loopback (10.0.2.2)"
  log "provisioning boot (${VCPUS} vCPUs, ${MEM} MiB; timeout ${TIMEOUT}s; console $CONSOLE)"
  timeout "$TIMEOUT" "${qemu[@]}" </dev/null &
  QPID=$!
  guest_register "$QPID" "$BUILD/qemu.pid" vm-image "$BUILD" "$KEEP_BUILD"
  wait "$QPID"; qrc=$?
  guest_release
else
  log "MANDU_CI_PROVISION_NET must be isolated or plain"; exit 2
fi
cp "$CONSOLE" "$CACHE/logs/$IMAGE_NAME.provision.log" 2>/dev/null

if [[ $qrc -eq 124 ]]; then log "the provisioning boot timed out after ${TIMEOUT}s (console: $CACHE/logs/$IMAGE_NAME.provision.log)"; exit 1; fi
if ! grep -aq "MANDU-CI-PROVISION: OK $KEY" "$CONSOLE"; then
  log "provisioning failed (qemu exit $qrc); the console log: $CACHE/logs/$IMAGE_NAME.provision.log"
  grep -a -B2 -A2 'MANDU-CI-PROVISION' "$CONSOLE" | tail -n 20 >&2
  exit 1
fi
# -d: fdatasync this one file; uutils' plain `sync FILE` waits on every dirty
# page of the filesystem (tens of minutes on a busy shared host).
sync -d "$BUILD/image.qcow2" || { log "could not flush the image to disk"; exit 1; }
mv "$BUILD/image.qcow2" "$IMAGE.part" && mv "$IMAGE.part" "$IMAGE" || exit 1
log "built $(basename "$IMAGE") in $((SECONDS - T0))s ($(du -h "$IMAGE" | cut -f1) on disk)"
prune_images
echo "$IMAGE"
