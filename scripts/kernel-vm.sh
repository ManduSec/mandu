#!/usr/bin/env bash
#
# kernel-vm.sh — boot a kernel ≥ 5.9 VM and run Track B against a DIFFERENT kernel
# than the host's. Historical origin: the then-5.4 dev host could not run
# fs-supervisor's seccomp-unotify ADDFD `openat()` REDIRECT
# (`SECCOMP_IOCTL_NOTIF_ADDFD`, kernel ≥ 5.9 — see docs/design/architecture/privilege-model.md
# §3.2), so this VM was the only place that one assertion ran. The host is now 6.8
# (ADDFD + Landlock live in scripts/kernel-tests.sh), so this script is no longer a
# necessity — it survives as the os-test-matrix's alternate-kernel vehicle (pin the
# guest image to whatever posture needs proving, e.g. a pre-5.9 or pre-5.13 kernel).
# It provisions a guest and runs
#
#     cargo test -p fs-supervisor --features kernel -- --ignored --nocapture
#
# inside it (where `seccomp_unotify_redirect_returns_agentview_fd` actually enacts the
# redirect and asserts the tracee's openat returns the AgentView/symbolized content,
# NOT the raw HumanView bytes). Everything inside the VM still uses the SAME
# root-in-unprivileged-userns path as the host runner — the VM only supplies the newer
# kernel, not extra host privilege.
#
# ── Mechanism ───────────────────────────────────────────────────────────────────
#   • Base image : Ubuntu 22.04 LTS cloud image (jammy, kernel 5.15 ≥ 5.9), amd64.
#   • Overlay    : a qcow2 backed by the (read-only) base, so the base is never
#                  mutated and re-runs are cheap.
#   • Repo into  : the host `interceptors/` Cargo workspace is shared into the guest
#     guest        read-only over virtio-9p (no copy, no large image bloat).
#   • Provision  : cloud-init (user-data via a genisoimage seed ISO) installs rustup +
#                  build-essential, copies the 9p share to a writable guest dir,
#                  builds + runs the one test, and writes a RESULT line + the test
#                  log to the OUTPUT 9p share the host reads after shutdown.
#   • Accel      : KVM if /dev/kvm is usable; user-mode (SLIRP) networking so no root
#                  / bridge is needed to fetch the toolchain.
#
# ── Usage ───────────────────────────────────────────────────────────────────────
#   scripts/kernel-vm.sh            # provision + boot + run + report (default)
#   scripts/kernel-vm.sh --check    # only print the feasibility preflight, do nothing
#   scripts/kernel-vm.sh --keep     # don't delete the overlay/seed/output on exit
#   MANDU_VM_BASE_URL=<url>        # override the cloud image URL
#   MANDU_VM_CACHE=<dir>           # where to cache the (large) base image
#   MANDU_VM_TIMEOUT=<secs>        # hard cap on the guest run (default 1800)
#
# This is the NICE-TO-HAVE for a single 5.9-gated assertion; scripts/kernel-tests.sh
# (userns) is the must-have and runs the rest of Track B live on the host.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INTERCEPTORS="$REPO_ROOT/interceptors"

# ── tunables ────────────────────────────────────────────────────────────────────
BASE_URL="${MANDU_VM_BASE_URL:-https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img}"
CACHE_DIR="${MANDU_VM_CACHE:-${TMPDIR:-/tmp}/mandu-kernel-vm-cache}"
VM_TIMEOUT="${MANDU_VM_TIMEOUT:-1800}"
VM_MEM="${MANDU_VM_MEM:-4096}"
VM_CPUS="${MANDU_VM_CPUS:-4}"

MODE="run"
KEEP=0
for arg in "$@"; do
  case "$arg" in
    --check) MODE="check" ;;
    --keep)  KEEP=1 ;;
    -h|--help) sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "kernel-vm: unknown option '$arg'" >&2; exit 2 ;;
  esac
done

if [[ -t 1 ]]; then
  C_GRN=$'\033[32m'; C_RED=$'\033[31m'; C_YLW=$'\033[33m'; C_DIM=$'\033[2m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_GRN=""; C_RED=""; C_YLW=""; C_DIM=""; C_BLD=""; C_RST=""
fi
say()  { printf "%s%s%s\n" "$C_BLD" "$*" "$C_RST"; }
info() { printf "  %s%s%s\n" "$C_DIM" "$*" "$C_RST"; }
ok()   { printf "  %s✓%s %s\n" "$C_GRN" "$C_RST" "$*"; }
warn() { printf "  %s⚠%s %s\n" "$C_YLW" "$C_RST" "$*"; }
err()  { printf "  %s✗%s %s\n" "$C_RED" "$C_RST" "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ── working dir (overlay, seed iso, output share) ────────────────────────────────
WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-kernel-vm.XXXXXX")"
# The guest is registered for `mandu reap` while it runs (os-test-matrix.md §10.5).
# shellcheck source=scripts/lib/guest-registry.sh
. "$REPO_ROOT/scripts/lib/guest-registry.sh"
cleanup() {
  guest_release
  if [[ $KEEP -eq 1 ]]; then
    info "--keep set; leaving VM work dir at $WORK (base image cache at $CACHE_DIR stays regardless)"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

# ── preflight: is end-to-end VM provisioning feasible on THIS host? ──────────────
# We check every prerequisite and report a precise reason if any is missing, so an
# abort is a clear "scaffolded, needs X" rather than a silent failure.
preflight() {
  local ready=1
  say "kernel-vm preflight (fs-supervisor ADDFD redirect needs guest kernel ≥ 5.9)"

  if have qemu-system-x86_64; then ok "qemu-system-x86_64: $(qemu-system-x86_64 --version | head -1)"
  else err "qemu-system-x86_64 not found"; ready=0; fi

  if have qemu-img; then ok "qemu-img present (overlay creation)"
  else err "qemu-img not found"; ready=0; fi

  if have genisoimage || have mkisofs || have xorriso; then ok "ISO authoring tool present (cloud-init seed)"
  else err "no genisoimage/mkisofs/xorriso (cannot build cloud-init seed ISO)"; ready=0; fi

  if [[ -r /dev/kvm && -w /dev/kvm ]]; then ok "/dev/kvm read-write (KVM acceleration available)"
  else warn "/dev/kvm not r/w — would fall back to TCG (very slow; may exceed timeout)"; fi

  # virtio-9p is how we mount the host repo + collect the result without a big copy.
  if qemu-system-x86_64 -device help 2>/dev/null | grep -q virtio-9p; then ok "qemu supports virtio-9p (host↔guest share)"
  else err "qemu lacks virtio-9p; would need image-copy provisioning instead"; ready=0; fi

  # The guest needs egress to fetch rustup + crates; user-mode SLIRP needs no root.
  if curl -sSI --max-time 15 "$BASE_URL" 2>/dev/null | grep -qi '^HTTP/.* 200'; then
    ok "base image reachable: $BASE_URL"
  else
    warn "base image URL not reachable (no network egress?) — provisioning would need a pre-staged image at \$MANDU_VM_CACHE"
    ready=0
  fi

  # Disk headroom for the ~700MB base + overlay growth.
  local avail_gb
  avail_gb="$(df -BG --output=avail "${CACHE_DIR%/*}" 2>/dev/null | tail -1 | tr -dc '0-9')"
  if [[ -n "$avail_gb" && "$avail_gb" -ge 5 ]]; then ok "disk headroom: ${avail_gb}G free"
  else warn "low disk headroom for the base image + overlay (need ~5G)"; fi

  return $((ready == 1 ? 0 : 1))
}

if ! preflight; then
  echo
  err "Preflight failed — NOT booting a VM."
  cat <<EOF

  ${C_BLD}This is a documented SCAFFOLD, not a failure.${C_RST}
  The exact provisioning this script performs when the prerequisites above are met:

    1. Fetch the Ubuntu 22.04 cloud image (kernel 5.15 ≥ 5.9) to \$MANDU_VM_CACHE.
    2. qemu-img create an -F qcow2 overlay backed by that base (base stays read-only).
    3. genisoimage a cloud-init seed ISO (user-data below) that, on first boot:
         - apt-get install build-essential + curl,
         - rustup-installs a stable toolchain,
         - mounts the host '${INTERCEPTORS}' over virtio-9p (tag 'reposrc', read-only),
         - copies it to a writable guest dir,
         - runs:  unshare --user --map-root-user --mount --pid --fork -- \\
                    cargo test -p fs-supervisor --features kernel -- --ignored --nocapture
         - writes RESULT=<pass|fail> + the full log to a second 9p share ('out'),
         - powers off.
    4. Boot headless, KVM-accelerated, user-mode (SLIRP) net, serial console captured.
    5. After shutdown, read RESULT from the 'out' share and report the REDIRECT result.

  Missing piece on THIS host: see the ✗ / ⚠ lines above (most commonly no network
  egress for the image download, or no ISO tool). Provide it (or pre-stage the image
  at \$MANDU_VM_CACHE) and re-run. The host-side rest of Track B already runs live
  via scripts/kernel-tests.sh (userns) — this VM only adds the one 5.9-gated assertion.
EOF
  exit 3
fi

[[ "$MODE" == "check" ]] && { echo; ok "preflight OK — re-run without --check to provision + boot."; exit 0; }

# ── 1) fetch + cache the base image ──────────────────────────────────────────────
mkdir -p "$CACHE_DIR"
BASE_IMG="$CACHE_DIR/$(basename "$BASE_URL")"
if [[ -s "$BASE_IMG" ]]; then
  ok "base image cached: $BASE_IMG ($(du -h "$BASE_IMG" | cut -f1))"
else
  say "Downloading base image (~700MB, one-time) → $BASE_IMG"
  if ! curl -fSL --retry 3 -o "$BASE_IMG.part" "$BASE_URL"; then
    err "download failed"; rm -f "$BASE_IMG.part"; exit 4
  fi
  mv "$BASE_IMG.part" "$BASE_IMG"
  ok "downloaded $(du -h "$BASE_IMG" | cut -f1)"
fi

# ── 2) overlay (base stays read-only) ────────────────────────────────────────────
OVERLAY="$WORK/overlay.qcow2"
qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMG" "$OVERLAY" 20G >/dev/null
# Resize the guest rootfs so cloud-init's growpart has room for the toolchain.
ok "overlay: $OVERLAY (backed by base, 20G virtual)"

# ── 3) output share the guest writes its result into ─────────────────────────────
OUT_DIR="$WORK/out"; mkdir -p "$OUT_DIR"

# ── 4) cloud-init seed ISO (user-data) ───────────────────────────────────────────
SEED_DIR="$WORK/seed"; mkdir -p "$SEED_DIR"
cat > "$SEED_DIR/meta-data" <<'EOF'
instance-id: mandu-kernel-vm
local-hostname: mandu-kernel-vm
EOF

# The guest script: mount the repo (9p tag 'reposrc') read-only, copy it writable,
# build + run the ONE fs-supervisor kernel test inside an unprivileged userns (the
# SAME path the host runner uses), and write RESULT + log to the 'out' 9p share.
cat > "$SEED_DIR/user-data" <<'EOF'
#cloud-config
package_update: true
packages:
  - build-essential
  - curl
  - pkg-config
write_files:
  - path: /usr/local/bin/mandu-run-fs-kernel-test.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -uo pipefail
      exec > >(tee -a /var/log/mandu-fs-kernel.log) 2>&1
      echo "=== Mandu fs-supervisor ADDFD redirect — guest kernel $(uname -r) ==="

      # Mount the host interceptors workspace (read-only) and the output share.
      mkdir -p /mnt/reposrc /mnt/out
      mount -t 9p -o trans=virtio,version=9p2000.L,ro reposrc /mnt/reposrc || { echo "9p reposrc mount failed"; }
      mount -t 9p -o trans=virtio,version=9p2000.L     out     /mnt/out     || { echo "9p out mount failed"; }

      RESULT_FILE=/mnt/out/RESULT
      LOG_FILE=/mnt/out/test.log
      echo "PENDING" > "$RESULT_FILE" 2>/dev/null || true

      # Copy the workspace somewhere writable (cargo needs to write target/).
      # EXCLUDE the host's target/ — its artifacts + .cargo-build-lock carry host
      # ownership/permissions that collide inside the guest (Permission denied) and
      # must be rebuilt for the guest's kernel anyway. Copy source only, then make
      # the tree unambiguously owned by guest root so cargo can write target/.
      mkdir -p /root/work
      if command -v rsync >/dev/null 2>&1; then
        rsync -a --exclude='target/' --exclude='**/target/' /mnt/reposrc/ /root/work/
      else
        ( cd /mnt/reposrc && find . -path ./target -prune -o -print0 | cpio -0 -pdm /root/work/ ) 2>/dev/null \
          || cp -a /mnt/reposrc/. /root/work/
        rm -rf /root/work/target
      fi
      chown -R root:root /root/work 2>/dev/null || true
      cd /root/work || { echo "FAIL: no workspace" | tee "$RESULT_FILE"; poweroff; }

      # Install rust (stable) for the runner.
      export RUSTUP_HOME=/root/.rustup CARGO_HOME=/root/.cargo
      curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
      export PATH="$CARGO_HOME/bin:$PATH"
      rustc --version || { echo "FAIL: rustc not installed" | tee "$RESULT_FILE"; poweroff; }

      echo "=== building + running fs-supervisor kernel test (in unprivileged userns) ==="
      # Same invocation as scripts/kernel-tests.sh — userns root, no host privilege.
      set -o pipefail
      unshare --user --map-root-user --mount --pid --fork -- \
        bash -c 'cargo test -p fs-supervisor --features kernel -- --ignored --nocapture' \
        2>&1 | tee "$LOG_FILE"
      RC=${PIPESTATUS[0]}

      # Classify: the redirect test prints "REDIRECT PASS (kernel ≥ 5.9)" on success.
      if [[ $RC -eq 0 ]] && grep -q 'REDIRECT PASS' "$LOG_FILE"; then
        echo "PASS" > "$RESULT_FILE"
        echo "=== RESULT: REDIRECT PASS on $(uname -r) ==="
      elif [[ $RC -eq 0 ]] && grep -q '^SKIP:' "$LOG_FILE"; then
        echo "SKIP" > "$RESULT_FILE"
        echo "=== RESULT: redirect SKIPPED (guest kernel < 5.9?) ==="
      else
        echo "FAIL (rc=$RC)" > "$RESULT_FILE"
        echo "=== RESULT: FAIL (rc=$RC) ==="
      fi
      sync
      poweroff
runcmd:
  - [ bash, -lc, "/usr/local/bin/mandu-run-fs-kernel-test.sh" ]
EOF

SEED_ISO="$WORK/seed.iso"
if have genisoimage; then
  genisoimage -quiet -output "$SEED_ISO" -volid cidata -joliet -rock "$SEED_DIR/user-data" "$SEED_DIR/meta-data"
elif have mkisofs; then
  mkisofs -quiet -output "$SEED_ISO" -volid cidata -joliet -rock "$SEED_DIR/user-data" "$SEED_DIR/meta-data"
else
  xorriso -as mkisofs -quiet -o "$SEED_ISO" -V cidata -J -r "$SEED_DIR/user-data" "$SEED_DIR/meta-data"
fi
ok "cloud-init seed ISO: $SEED_ISO"

# ── 5) boot ──────────────────────────────────────────────────────────────────────
SERIAL_LOG="$WORK/serial.log"
ACCEL=()
if [[ -r /dev/kvm && -w /dev/kvm ]]; then ACCEL=(-enable-kvm -cpu host); else ACCEL=(-cpu max); fi

say "Booting guest (kernel ≥ 5.9), running the fs-supervisor ADDFD redirect test…"
info "serial console → $SERIAL_LOG ; hard timeout ${VM_TIMEOUT}s"

# virtio-9p shares: 'reposrc' = the host interceptors workspace (RO via mount opt),
# 'out' = the result drop. user-mode net gives the guest egress for rustup/cargo.
timeout "$VM_TIMEOUT" qemu-system-x86_64 \
  "${ACCEL[@]}" \
  -m "$VM_MEM" -smp "$VM_CPUS" \
  -nographic -serial "file:$SERIAL_LOG" \
  -drive "file=$OVERLAY,if=virtio,format=qcow2" \
  -drive "file=$SEED_ISO,if=virtio,format=raw,readonly=on" \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
  -fsdev local,id=fsrepo,path="$INTERCEPTORS",security_model=none \
  -device virtio-9p-pci,fsdev=fsrepo,mount_tag=reposrc \
  -fsdev local,id=fsout,path="$OUT_DIR",security_model=none \
  -device virtio-9p-pci,fsdev=fsout,mount_tag=out \
  -pidfile "$WORK/qemu.pid" -no-reboot </dev/null &
QPID=$!
guest_register "$QPID" "$WORK/qemu.pid" kernel-vm "$WORK" "$KEEP"
wait "$QPID"; QEMU_RC=$?
guest_release

# ── 6) collect + report ──────────────────────────────────────────────────────────
echo
say "════════════════════ kernel-vm result (fs-supervisor ADDFD redirect) ════════════════════"
RESULT="$(cat "$OUT_DIR/RESULT" 2>/dev/null || echo "")"
if [[ -s "$OUT_DIR/test.log" ]]; then
  info "--- guest test.log (tail) ---"
  tail -n 25 "$OUT_DIR/test.log" | sed 's/^/  /'
fi

case "$RESULT" in
  PASS)
    ok "REDIRECT PASS on a kernel ≥ 5.9 guest — the seccomp-unotify ADDFD openat() redirect"
    ok "delivered AgentView (symbolized) content; the raw HumanView bytes never reached the tracee."
    exit 0 ;;
  SKIP)
    warn "guest reported SKIP (its kernel was < 5.9?). RESULT=$RESULT"
    exit 0 ;;
  FAIL*)
    err "guest reported $RESULT — the REDIRECT assertion FAILED in the VM. See $SERIAL_LOG."
    exit 1 ;;
  *)
    if [[ $QEMU_RC -eq 124 ]]; then
      err "VM run TIMED OUT after ${VM_TIMEOUT}s (toolchain install / boot too slow). serial: $SERIAL_LOG"
    else
      err "no RESULT produced by the guest (qemu rc=$QEMU_RC). serial: $SERIAL_LOG"
    fi
    warn "Scaffold completed but the run did not yield a result on this host — see serial log."
    exit 2 ;;
esac
