#!/usr/bin/env bash
# qemu.sh — qemu executor for the OS test matrix (docs/design/testing/os-test-matrix.md §2).
# Provenance: extracted + parameterized from scripts/kernel-vm.sh (image cache,
# qcow2 overlay, cloud-init seed ISO, virtio-9p shares, serial log, RESULT
# protocol); purpose: boot ANY declared cloud-image target and run ANY suite,
# where kernel-vm.sh hardcodes Ubuntu 22.04 × the fs-supervisor ADDFD test.
#
# Contract: executor_check → 0 ready / 3 unavailable (reasons printed);
#           executor_run <suite> → 0 pass / 1 fail / 3 skip. A suite that
#           exits 75 in the guest is booted again on the same disk, up to its
#           `# boots:` header (os-test-matrix.md §2.1).
#           executor_interactive [suite] → boots the guest with an ssh
#           port-forward and waits (os-test-matrix.md §10.5 item 3).
# Disks: base image ← cached provisioned layer (packages only, keyed by the
# image digest and the package list; MANDU_VM_SNAPSHOT=0 skips it) ← per-run
# overlay, thrown away at exit (os-test-matrix.md §10.5 item 2).
# Consumes conf vars: IMAGE_URL IMAGE_SHA256 CPUS MEM TIMEOUT LABELS SYSCTLS,
# and driver vars: MATRIX_DIR REPO_ROOT TARGET_NAME RUN_WORK.

CACHE_DIR="${MANDU_VM_CACHE:-${TMPDIR:-/tmp}/mandu-vm-cache}"

# Every guest is registered for `mandu reap` (os-test-matrix.md §10.5):
# qemu writes -pidfile, guest_register records it with this harness as owner,
# guest_release (after each boot, and from run.sh's EXIT trap) stops it.
# shellcheck source=scripts/lib/guest-registry.sh
. "$(dirname "${BASH_SOURCE[0]}")/../../lib/guest-registry.sh"

qemu_base_img() { echo "$CACHE_DIR/$(basename "$IMAGE_URL")"; }

executor_check() {
  local ready=1
  say "qemu preflight for target '$TARGET_NAME'"
  if have qemu-system-x86_64; then ok "qemu-system-x86_64: $(qemu-system-x86_64 --version | head -1)"
  else err "qemu-system-x86_64 not found"; ready=0; fi
  if have qemu-img; then ok "qemu-img present (overlay creation)"
  else err "qemu-img not found"; ready=0; fi
  if have genisoimage || have mkisofs || have xorriso; then ok "ISO authoring tool present (cloud-init seed)"
  else err "no genisoimage/mkisofs/xorriso"; ready=0; fi
  if qemu-system-x86_64 -device help 2>/dev/null | grep -q virtio-9p; then ok "qemu supports virtio-9p"
  else err "qemu lacks virtio-9p"; ready=0; fi
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then ok "/dev/kvm read-write (KVM acceleration)"
  else warn "/dev/kvm not r/w — TCG fallback (very slow; may exceed TIMEOUT=$TIMEOUT)"; fi
  # NOTE: -sSIL (follow redirects) — the 26.04 release URL 302s to the codename path.
  if [[ -s "$(qemu_base_img)" ]]; then
    ok "base image cached: $(qemu_base_img)"
  elif curl -sSIL --max-time 15 "$IMAGE_URL" 2>/dev/null | grep -qi '^HTTP/.* 200'; then
    ok "base image reachable: $IMAGE_URL"
  else
    err "base image neither cached nor reachable: $IMAGE_URL"; ready=0
  fi
  local avail_gb
  avail_gb="$(df -BG --output=avail "${CACHE_DIR%/*}" 2>/dev/null | tail -1 | tr -dc '0-9')"
  if [[ -n "$avail_gb" && "$avail_gb" -ge 5 ]]; then ok "disk headroom: ${avail_gb}G free"
  else warn "low disk headroom (need ~5G for base + overlay)"; fi
  if [[ $ready -eq 1 ]]; then return 0; fi
  echo "skip: qemu preflight failed for target '$TARGET_NAME' (see ✗ above)"
  return 3
}

# qemu_pkg_list <deps> — the apt packages a run with these deps needs. One flat
# list feeds cloud-init's packages:, the guest's provisioning gate (@PKGS@)
# and the provisioned layer's cache key, so the three cannot drift. (git:
# fs-sync/e2e suites need the git BINARY even though the repo's .git is
# excluded; they create their own repos in tmp.)
qemu_pkg_list() {
  local pkg_list="curl rsync git"
  case " $1 " in *" cargo "*) pkg_list="$pkg_list build-essential pkg-config libssl-dev nftables" ;; esac
  case " $1 " in *" node "*)  pkg_list="$pkg_list python3 make g++" ;; esac
  echo "$pkg_list"
}

# ── The provisioned snapshot layer (os-test-matrix.md §10.5 item 2) ──────
# Every run used to pay cloud-init's apt update + package installs. A cached
# middle qcow2 holds exactly that: base image, then the packages the run's deps
# declare, nothing of Mandu's. It is built by one boot of the same guest runner
# with SUITE=__provision__ and NO share but its own out dir (no repo, no
# artifacts, so no credential can ever land in it). "Fresh" means no mandu
# state, not an un-updated apt cache: every run still does its apt update.
QEMU_LAYER_VERSION=1   # bump when the provisioning boot changes what it leaves on disk
QEMU_LAYER_MAX_AGE_DAYS="${MANDU_VM_LAYER_MAX_AGE_DAYS:-7}"

# qemu_layer_key <image digest> <pkg list> — 16 hex chars; changes with the
# image, the package list or QEMU_LAYER_VERSION.
qemu_layer_key() {
  printf 'image=%s\npkgs=%s\nversion=%s\n' "$1" "$2" "$QEMU_LAYER_VERSION" | sha256sum | cut -c1-16
}
qemu_image_digest() {
  if [[ -n "$IMAGE_SHA256" ]]; then echo "$IMAGE_SHA256"; else sha256sum < "$(qemu_base_img)" | cut -d' ' -f1; fi
}
qemu_layer_path() { echo "$CACHE_DIR/provisioned-$TARGET_NAME-$1.qcow2"; }

qemu_accel() {
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then QEMU_ACCEL=(-enable-kvm -cpu host); else QEMU_ACCEL=(-cpu max); fi
}

# qemu_build_layer <layer path> <deps> — one provisioning boot into
# <layer>.part, renamed into place only when the guest reported
# RESULT=provisioned. 0 on success.
qemu_build_layer() {
  local layer="$1" deps="$2" d="$RUN_WORK/provision" rc
  mkdir -p "$d/seed" "$d/out"
  # A different instance-id from the run's: cloud-init then treats the run's
  # boot as a new instance and runs write_files/runcmd (the real suite) again.
  printf 'instance-id: mandu-matrix-provision-%s\nlocal-hostname: mandu-matrix\n' "$(basename "$layer" .qcow2)" > "$d/seed/meta-data"
  RUN_WORK="$d" qemu_userdata __provision__ "$deps" "$d/seed/user-data"
  qemu_make_seed "$d/seed" "$d/seed.iso" || return 1
  qemu-img create -q -f qcow2 -F qcow2 -b "$(qemu_base_img)" "$layer.part" 20G >/dev/null || return 1
  qemu_accel
  timeout "${MANDU_VM_LAYER_TIMEOUT:-1800}" qemu-system-x86_64 \
    "${QEMU_ACCEL[@]}" -m "$MEM" -smp "$CPUS" \
    -nographic -serial "file:$d/serial.log" \
    -drive "file=$layer.part,if=virtio,format=qcow2" \
    -drive "file=$d/seed.iso,if=virtio,format=raw,readonly=on" \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -fsdev local,id=fsout,path="$d/out",security_model=none \
    -device virtio-9p-pci,fsdev=fsout,mount_tag=out \
    -pidfile "$d/qemu.pid" -no-reboot </dev/null &
  local qpid=$!
  # Registered for `mandu reap` (guest-registry.sh): a leaked provisioning
  # guest holds the layer lock (every later run of this target waits on it)
  # and leaves <layer>.part.
  guest_register "$qpid" "$d/qemu.pid" matrix-provision "$RUN_WORK" "${KEEP:-0}" "$layer.part"
  wait "$qpid"; rc=$?
  guest_release
  if [[ "$(cat "$d/out/RESULT" 2>/dev/null)" == provisioned ]]; then
    mv -f "$layer.part" "$layer"; return 0
  fi
  warn "provisioning boot did not finish (qemu rc=$rc, RESULT=$(cat "$d/out/RESULT" 2>/dev/null || echo none); serial: $d/serial.log)"
  rm -f "$layer.part"; return 1
}

# qemu_prepare_backing <deps> — sets QEMU_BACKING, the disk the per-run
# overlay sits on: the provisioned layer (cached, or built now), else the base
# image. A layer that fails to build is a warning, never a failed run: the
# run then provisions itself as before (the guest's provisioning gate).
qemu_prepare_backing() {
  QEMU_BACKING="$(qemu_base_img)"
  if [[ "${MANDU_VM_SNAPSHOT:-1}" == 0 ]]; then info "snapshot layer off (MANDU_VM_SNAPSHOT=0)"; return 0; fi
  local pkgs key layer lfd
  pkgs="$(qemu_pkg_list "$1")"
  key="$(qemu_layer_key "$(qemu_image_digest)" "$pkgs")"
  layer="$(qemu_layer_path "$key")"
  # Two runs of one target may want the same layer: one builds, the other waits.
  exec {lfd}>"$layer.lock"
  flock "$lfd"
  if [[ -s "$layer" && -n "$(find "$layer" -mmin "-$(( QEMU_LAYER_MAX_AGE_DAYS * 1440 ))" 2>/dev/null)" ]]; then
    ok "provisioned layer cached: $layer"
    QEMU_BACKING="$layer"
  else
    say "Building the provisioned layer ($pkgs) → $layer"
    if qemu_build_layer "$layer" "$1"; then ok "provisioned layer built: $layer"; QEMU_BACKING="$layer"
    else warn "no provisioned layer; this run provisions itself from the base image"; fi
  fi
  exec {lfd}>&-
  return 0
}

qemu_fetch_image() {
  mkdir -p "$CACHE_DIR"
  local base_img; base_img="$(qemu_base_img)"
  if [[ -s "$base_img" ]]; then
    ok "base image cached: $base_img ($(du -h "$base_img" | cut -f1))"
  else
    say "Downloading base image (one-time) → $base_img"
    if ! curl -fSL --retry 3 -o "$base_img.part" "$IMAGE_URL"; then
      err "download failed"; rm -f "$base_img.part"; return 1
    fi
    mv "$base_img.part" "$base_img"
    ok "downloaded $(du -h "$base_img" | cut -f1)"
  fi
  if [[ -n "$IMAGE_SHA256" ]]; then
    echo "$IMAGE_SHA256  $base_img" | sha256sum -c - >/dev/null \
      || { err "IMAGE_SHA256 mismatch for $base_img"; return 1; }
    ok "sha256 verified"
  fi
  return 0
}

# qemu_userdata <suite> <deps> <outfile> — generate the cloud-init user-data.
# The guest runner is a quoted-heredoc template with @TOKEN@ substitution (no
# shell expansion inside), then indented 6 spaces into the YAML block scalar —
# the kernel-vm.sh pattern. Deps drive provisioning: cargo → rustup;
# node → NodeSource 22.x (Ubuntu apt node is too old for the TS stack).
qemu_userdata() {
  local suite="$1" deps="$2" out="$3" pubkey="${4:-}"
  local guest_sh="$RUN_WORK/guest-runner.sh"

  cat > "$guest_sh" <<'GUEST'
#!/usr/bin/env bash
set -uo pipefail
exec > >(tee -a /var/log/mandu-matrix.log) 2>&1
SUITE="@SUITE@"; DEPS="@DEPS@"; SYSCTLS="@SYSCTLS@"
# cloud-init's runcmd gives this script no HOME (nor USER). Suites that read
# it failed as something else on 2026-09-25: docker-run.test.sh died on "HOME:
# unbound variable", and a launcher e2e passed HOME=undefined, found no
# secrets to confine and so never reached the refusal it asserts.
export HOME="${HOME:-/root}" USER="${USER:-root}"
echo "=== Mandu matrix guest: suite=$SUITE target=@TARGET@ ==="
echo "guest: kernel=$(uname -r) apparmor_userns=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo n/a) userns_clone=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo n/a)"

mkdir -p /mnt/reposrc /mnt/out /mnt/artifacts
mount -t 9p -o trans=virtio,version=9p2000.L,ro reposrc /mnt/reposrc || echo "9p reposrc mount failed"
mount -t 9p -o trans=virtio,version=9p2000.L     out     /mnt/out     || echo "9p out mount failed"
# Host-built artifacts (a suite's <suite>.host.sh fills it; empty otherwise).
mount -t 9p -o trans=virtio,version=9p2000.L,ro artifacts /mnt/artifacts || echo "9p artifacts mount failed"
RESULT_FILE=/mnt/out/RESULT; LOG_FILE=/mnt/out/suite.log
echo "pending" > "$RESULT_FILE" 2>/dev/null || true
finish() { echo "$1" > "$RESULT_FILE"; sync; poweroff; }

# Reboots (a distro upgrade, os-test-matrix.md §2.1). A suite that needs the
# guest rebooted saves its own state and exits 75: the runner marks the next
# boot a RESUME, enables the mandu-matrix-resume unit and powers off with
# RESULT=reboot, and the executor boots the same disk again. On the resume
# boot that unit runs this script again: the shares are mounted and the suite
# runs again with MATRIX_RESUME=1 (it reads its own state to know where it
# left off). Provisioning, the repo copy and the toolchains are already on
# the disk and are not redone.
RESUME_FLAG=/var/lib/mandu-matrix/resume; RESUME=0
if [[ -f $RESUME_FLAG ]]; then
  RESUME=1; rm -f "$RESUME_FLAG"
  systemctl disable mandu-matrix-resume.service 2>/dev/null || true
  echo "=== resume boot: $(. /etc/os-release; echo "$PRETTY_NAME") kernel=$(uname -r) ==="
fi

for kv in $SYSCTLS; do sysctl -w "$kv" || echo "sysctl $kv failed"; done

if [[ $RESUME -eq 0 ]]; then
# Provisioning gate. cloud-init's package module only WARNS when the mirror is
# unreachable and then runs this script anyway; a suite on a half-provisioned
# guest fails as something else ("linker `cc` not found", 0 passed / 0
# failed; found 2026-09-25 on ubuntu-2604 with a slow archive.ubuntu.com).
# Verify one probe command per package, retry apt with backoff, and give up
# as a PROVISIONING failure that names what is missing.
APT_OPTS=(-o Acquire::Retries=5 -o Acquire::http::Timeout=60 -o DPkg::Lock::Timeout=600)
apt_retry() {  # apt_retry <pkg>... : update + install, up to 4 tries
  local try
  for try in 1 2 3 4; do
    apt-get "${APT_OPTS[@]}" update -q && \
      DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTS[@]}" install -y -q "$@" && return 0
    echo "provisioning: apt attempt $try failed; retrying in $((try * 30))s"
    sleep $((try * 30))
  done
  return 1
}
missing_pkgs() {  # the declared packages whose probe command is absent
  local pkg probe out=""
  for pkg in @PKGS@; do
    case "$pkg" in
      build-essential) probe=cc ;;  libssl-dev) probe=/usr/include/openssl/ssl.h ;;
      nftables) probe=nft ;;        g++) probe=g++ ;;  *) probe="$pkg" ;;
    esac
    if [[ "$probe" == /* ]]; then [[ -e "$probe" ]] || out="$out $pkg"
    else command -v "$probe" >/dev/null 2>&1 || out="$out $pkg"; fi
  done
  echo "$out"
}
miss="$(missing_pkgs)"
if [[ -n "$miss" ]]; then
  echo "provisioning: cloud-init left these uninstalled:$miss; retrying apt"
  # shellcheck disable=SC2086
  apt_retry $miss
  miss="$(missing_pkgs)"
  [[ -z "$miss" ]] || finish "fail: provisioning: packages missing after retries:$miss (package mirror unreachable?)"
fi
echo "provisioning: all declared packages present"

# Building the cached provisioned layer (executor qemu_build_layer): packages
# only. Leave no identity that every run on the layer would share.
if [[ "$SUITE" == __provision__ ]]; then
  apt-get clean
  truncate -s 0 /etc/machine-id; rm -f /var/lib/dbus/machine-id
  finish "provisioned"
  exit 0
fi

# Writable repo copy; EXCLUDE host build state (host-owned artifacts collide in
# the guest and must be rebuilt for the guest anyway) and .git (suites must not
# depend on the repo's own git state).
mkdir -p /root/work /root/matrix-work
if command -v rsync >/dev/null 2>&1; then
  rsync -a --exclude='.git/' --exclude='target/' --exclude='**/target/' \
        --exclude='node_modules/' --exclude='**/node_modules/' /mnt/reposrc/ /root/work/
else
  cp -a /mnt/reposrc/. /root/work/
  rm -rf /root/work/.git /root/work/interceptors/target
  find /root/work -maxdepth 3 -name node_modules -type d -exec rm -rf {} + 2>/dev/null
fi
chown -R root:root /root/work 2>/dev/null || true
cd /root/work || finish "fail: no workspace"

case " $DEPS " in *" cargo "*)
  export RUSTUP_HOME=/root/.rustup CARGO_HOME=/root/.cargo
  curl -sSf --retry 5 --retry-delay 10 https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    || finish "fail: rustup install"
  export PATH="$CARGO_HOME/bin:$PATH"
  rustc --version || finish "fail: rustc missing after install"
  ;;
esac
case " $DEPS " in *" node "*)
  curl -fsSL --retry 5 --retry-delay 10 https://deb.nodesource.com/setup_22.x | bash - \
    && apt_retry nodejs || finish "fail: provisioning: node install"
  node --version || finish "fail: node missing after install"
  ;;
esac
fi  # RESUME -eq 0
cd /root/work || finish "fail: no workspace"
if [[ -x /root/.cargo/bin/cargo ]]; then
  export RUSTUP_HOME=/root/.rustup CARGO_HOME=/root/.cargo PATH="/root/.cargo/bin:$PATH"
fi

# The manual lane (run.sh --interactive): shares mounted, packages and the repo
# copy in place, the artifact share filled by the suite's host prep; the
# guest stays up for ssh and never runs the suite.
if [[ "$SUITE" == __interactive__ ]]; then
  echo "interactive" > "$RESULT_FILE"; sync
  echo "=== interactive guest ready: artifacts in /mnt/artifacts, repo copy in /root/work ==="
  exit 0
fi

echo "=== running suite $SUITE ==="
TEE_OPT=(); [[ $RESUME -eq 1 ]] && TEE_OPT=(-a)
MATRIX_TARGET="@TARGET@" MATRIX_LABELS="@LABELS@" MATRIX_WORK=/root/matrix-work MATRIX_RESUME=$RESUME \
  bash "scripts/matrix/suites/$SUITE.sh" 2>&1 | tee "${TEE_OPT[@]}" "$LOG_FILE"
RC=${PIPESTATUS[0]}
case $RC in
  75)
    mkdir -p "${RESUME_FLAG%/*}" && touch "$RESUME_FLAG" \
      && systemctl enable mandu-matrix-resume.service \
      || finish "fail: could not arm the resume boot"
    finish "reboot" ;;
  0)  finish "pass" ;;
  77) finish "skip: suite exit 77" ;;
  *)  finish "fail: rc=$RC" ;;
esac
GUEST

  # Dep-driven package list (qemu_pkg_list): cloud-init's packages: and the
  # guest's provisioning gate (@PKGS@) read the same one.
  local pkg_list; pkg_list="$(qemu_pkg_list "$deps")"
  local pkgs p
  pkgs="$(for p in $pkg_list; do echo "  - $p"; done)"

  sed -i \
    -e "s|@SUITE@|$suite|g" \
    -e "s|@DEPS@|$deps|g" \
    -e "s|@TARGET@|$TARGET_NAME|g" \
    -e "s|@LABELS@|$LABELS|g" \
    -e "s|@SYSCTLS@|$SYSCTLS|g" \
    -e "s|@PKGS@|$pkg_list|g" \
    "$guest_sh"

  {
    echo "#cloud-config"
    if [[ -n "$pubkey" ]]; then
      # The manual lane: key-only ssh for the image's default user.
      echo "ssh_pwauth: false"
      echo "ssh_authorized_keys:"
      echo "  - $(cat "$pubkey")"
    fi
    echo "package_update: true"
    echo "packages:"
    echo "$pkgs"
    echo "write_files:"
    echo "  - path: /usr/local/bin/mandu-matrix-guest.sh"
    echo "    permissions: '0755'"
    echo "    content: |"
    sed 's/^/      /' "$guest_sh"
    echo "  - path: /etc/systemd/system/mandu-matrix-resume.service"
    echo "    permissions: '0644'"
    echo "    content: |"
    sed 's/^/      /' <<'UNIT'
[Unit]
Description=Mandu matrix: run the suite again after a reboot it asked for
Wants=network-online.target
After=network-online.target
ConditionPathExists=/var/lib/mandu-matrix/resume

[Service]
Type=oneshot
ExecStart=/usr/local/bin/mandu-matrix-guest.sh
TimeoutStartSec=infinity

[Install]
WantedBy=multi-user.target
UNIT
    echo "runcmd:"
    echo "  - [ bash, -lc, \"/usr/local/bin/mandu-matrix-guest.sh\" ]"
  } > "$out"
}

qemu_make_seed() {  # $1 = seed dir with user-data+meta-data, $2 = output iso
  if have genisoimage; then
    genisoimage -quiet -output "$2" -volid cidata -joliet -rock "$1/user-data" "$1/meta-data"
  elif have mkisofs; then
    mkisofs -quiet -output "$2" -volid cidata -joliet -rock "$1/user-data" "$1/meta-data"
  else
    xorriso -as mkisofs -quiet -o "$2" -V cidata -J -r "$1/user-data" "$1/meta-data"
  fi
}

executor_run() {
  local suite="$1" suite_sh="$MATRIX_DIR/suites/$1.sh"
  local deps; deps="$(parse_deps "$suite_sh")"
  # A suite's own bounds (common.sh parse_header): how many boots it may
  # ask for, and a floor under the target's TIMEOUT for a long suite.
  local MAX_BOOTS min_timeout
  MAX_BOOTS="$(parse_header "$suite_sh" boots)"; MAX_BOOTS="${MAX_BOOTS:-1}"
  min_timeout="$(parse_header "$suite_sh" min-timeout)"
  if [[ -n "$min_timeout" ]] && (( min_timeout > TIMEOUT )); then TIMEOUT=$min_timeout; fi

  executor_check || return 3
  qemu_fetch_image || return 1

  qemu_prepare_backing "$deps"
  local overlay="$RUN_WORK/overlay.qcow2"
  qemu-img create -q -f qcow2 -F qcow2 -b "$QEMU_BACKING" "$overlay" 20G >/dev/null || {
    err "overlay creation failed"; return 1; }
  ok "overlay: $overlay (backed by $(basename "$QEMU_BACKING"), 20G virtual)"

  local out_dir="$RUN_WORK/out"; mkdir -p "$out_dir"

  # Host prep (os-test-matrix.md §10.3.2): an optional <suite>.host.sh runs
  # ON THE HOST before boot and fills $ARTIFACT_DIR, shared read-only into the
  # guest at /mnt/artifacts. This is how a suite tests a host-BUILT artifact
  # (the packed tarball) instead of the checkout.
  local artifact_dir="$RUN_WORK/artifacts"; mkdir -p "$artifact_dir"
  local host_prep="$MATRIX_DIR/suites/$suite.host.sh"
  if [[ -f "$host_prep" ]]; then
    say "Host prep: $(basename "$host_prep")"
    ARTIFACT_DIR="$artifact_dir" REPO_ROOT="$REPO_ROOT" bash "$host_prep" \
      || { err "host prep failed"; return 1; }
    ok "artifacts: $(ls "$artifact_dir" | tr '\n' ' ')"
  fi
  local seed_dir="$RUN_WORK/seed"; mkdir -p "$seed_dir"
  printf 'instance-id: mandu-matrix-%s\nlocal-hostname: mandu-matrix\n' "$TARGET_NAME" \
    > "$seed_dir/meta-data"
  qemu_userdata "$suite" "$deps" "$seed_dir/user-data"
  local seed_iso="$RUN_WORK/seed.iso"
  qemu_make_seed "$seed_dir" "$seed_iso" || { err "seed ISO creation failed"; return 1; }
  ok "cloud-init seed ISO: $seed_iso"

  local serial_log="$RUN_WORK/serial.log"
  qemu_accel

  # One boot, or several when the suite asks for a reboot (RESULT=reboot,
  # §2.1): every boot runs on the same overlay, the whole run stays inside
  # TIMEOUT, and MAX_BOOTS bounds a suite that keeps asking.
  local boot=1 max_boots="${MAX_BOOTS:-1}" t_start=$SECONDS left qemu_rc boot_log
  say "Booting $TARGET_NAME (suite '$suite', deps '${deps:-none}')…"
  info "serial console → $serial_log ; hard timeout ${TIMEOUT}s; up to $max_boots boot(s)"
  while :; do
    left=$(( TIMEOUT - (SECONDS - t_start) ))
    if (( left <= 0 )); then qemu_rc=124; break; fi
    boot_log="$serial_log"; (( boot > 1 )) && boot_log="$RUN_WORK/serial.boot$boot.log"
    # A boot that dies before its guest writes anything must not be read as
    # the previous boot's "reboot".
    rm -f "$out_dir/RESULT" "$RUN_WORK/qemu.pid"
    timeout "$left" qemu-system-x86_64 \
      "${QEMU_ACCEL[@]}" \
      -m "$MEM" -smp "$CPUS" \
      -nographic -serial "file:$boot_log" \
      -drive "file=$overlay,if=virtio,format=qcow2" \
      -drive "file=$seed_iso,if=virtio,format=raw,readonly=on" \
      -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
      -fsdev local,id=fsrepo,path="$REPO_ROOT",security_model=none \
      -device virtio-9p-pci,fsdev=fsrepo,mount_tag=reposrc \
      -fsdev local,id=fsout,path="$out_dir",security_model=none \
      -device virtio-9p-pci,fsdev=fsout,mount_tag=out \
      -fsdev local,id=fsart,path="$artifact_dir",security_model=none,readonly=on \
      -device virtio-9p-pci,fsdev=fsart,mount_tag=artifacts \
      -pidfile "$RUN_WORK/qemu.pid" -no-reboot </dev/null &
    local qpid=$!
    # Registered for `mandu reap` (guest-registry.sh); the host-prep
    # credential copy goes with a leaked guest even under --keep.
    guest_register "$qpid" "$RUN_WORK/qemu.pid" matrix "$RUN_WORK" "${KEEP:-0}" "$artifact_dir/ephemeral"
    wait "$qpid"; qemu_rc=$?
    guest_release
    if (( boot > 1 )); then
      { echo; echo "===== boot $boot ====="; cat "$boot_log"; } >> "$serial_log" 2>/dev/null; rm -f "$boot_log"
    fi
    [[ "$(cat "$out_dir/RESULT" 2>/dev/null)" == reboot ]] || break
    if (( boot >= max_boots )); then
      echo "fail: the suite asked for boot $((boot + 1)); MAX_BOOTS=$max_boots" > "$out_dir/RESULT"; break
    fi
    boot=$((boot + 1))
    info "the suite asked for a reboot: boot $boot of at most $max_boots ($(( TIMEOUT - (SECONDS - t_start) ))s left)"
  done
  # Host-prep secrets never outlive the guest, even under --keep.
  rm -rf "$artifact_dir/ephemeral"

  echo
  if [[ -s "$out_dir/suite.log" ]]; then
    info "--- guest suite.log (tail) ---"
    tail -n 25 "$out_dir/suite.log" | sed 's/^/  /'
  fi
  local result; result="$(cat "$out_dir/RESULT" 2>/dev/null || echo "")"
  case "$result" in
    pass)  return 0 ;;
    skip*) echo "skip: guest reported '$result'"; return 3 ;;
    fail*) err "guest reported '$result' (serial: $serial_log — use --keep to retain)"; return 1 ;;
    *)
      if [[ $qemu_rc -eq 124 ]]; then err "VM TIMED OUT after ${TIMEOUT}s (serial: $serial_log)"
      else err "no RESULT from guest (qemu rc=$qemu_rc; serial: $serial_log)"; fi
      return 1 ;;
  esac
}

# ── The manual lane: run.sh --interactive (os-test-matrix.md §10.5 item 3) ─
# Boot the same guest a suite gets (same image, provisioned layer, shares, and
# the suite's host prep when one is named, so a fresh-install guest has the
# packed tarball and the stub agent in /mnt/artifacts), with ssh forwarded
# from a LOOPBACK port and a key generated for this run, and keep it up until
# the user powers it off (in the guest) or presses Ctrl-C here. The suite
# itself never runs. The per-run overlay is thrown away at exit unless --keep.

# qemu_free_port — a free loopback TCP port (small race; qemu fails loudly if lost).
qemu_free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])' 2>/dev/null \
    || echo $(( 20000 + RANDOM % 20000 ))
}

executor_interactive() {
  local suite="${1:-}" deps="" suite_sh=""
  if [[ -n "$suite" ]]; then
    suite_sh="$MATRIX_DIR/suites/$suite.sh"
    deps="$(parse_deps "$suite_sh")"
  fi
  executor_check || return 3
  qemu_fetch_image || return 1
  qemu_prepare_backing "$deps"
  local overlay="$RUN_WORK/overlay.qcow2"
  qemu-img create -q -f qcow2 -F qcow2 -b "$QEMU_BACKING" "$overlay" 20G >/dev/null || {
    err "overlay creation failed"; return 1; }
  local out_dir="$RUN_WORK/out" artifact_dir="$RUN_WORK/artifacts"; mkdir -p "$out_dir" "$artifact_dir"
  if [[ -n "$suite" && -f "$MATRIX_DIR/suites/$suite.host.sh" ]]; then
    say "Host prep: $suite.host.sh"
    ARTIFACT_DIR="$artifact_dir" REPO_ROOT="$REPO_ROOT" bash "$MATRIX_DIR/suites/$suite.host.sh" \
      || { err "host prep failed"; return 1; }
    ok "artifacts: $(ls "$artifact_dir" | tr '\n' ' ')"
  fi
  local key="$RUN_WORK/ssh/id_ed25519"
  mkdir -p -m 0700 "$RUN_WORK/ssh"
  ssh-keygen -q -t ed25519 -N '' -C "mandu-matrix-interactive-$TARGET_NAME" -f "$key" || { err "ssh-keygen failed"; return 1; }
  local seed_dir="$RUN_WORK/seed"; mkdir -p "$seed_dir"
  printf 'instance-id: mandu-matrix-%s\nlocal-hostname: mandu-matrix\n' "$TARGET_NAME" > "$seed_dir/meta-data"
  qemu_userdata __interactive__ "$deps" "$seed_dir/user-data" "$key.pub"
  qemu_make_seed "$seed_dir" "$RUN_WORK/seed.iso" || { err "seed ISO creation failed"; return 1; }
  local port; port="$(qemu_free_port)"
  qemu_accel
  qemu-system-x86_64 \
    "${QEMU_ACCEL[@]}" -m "$MEM" -smp "$CPUS" \
    -display none -monitor none -serial "file:$RUN_WORK/serial.log" \
    -drive "file=$overlay,if=virtio,format=qcow2" \
    -drive "file=$RUN_WORK/seed.iso,if=virtio,format=raw,readonly=on" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=net0 \
    -fsdev local,id=fsrepo,path="$REPO_ROOT",security_model=none \
    -device virtio-9p-pci,fsdev=fsrepo,mount_tag=reposrc \
    -fsdev local,id=fsout,path="$out_dir",security_model=none \
    -device virtio-9p-pci,fsdev=fsout,mount_tag=out \
    -fsdev local,id=fsart,path="$artifact_dir",security_model=none,readonly=on \
    -device virtio-9p-pci,fsdev=fsart,mount_tag=artifacts \
    -pidfile "$RUN_WORK/qemu.pid" -no-reboot </dev/null &
  local qpid=$!
  # shellcheck disable=SC2064
  trap "kill $qpid 2>/dev/null" INT TERM
  # This guest has no timeout at all: a harness killed hard would leave it up
  # for good. Registered, `mandu reap` stops it once this harness is gone.
  guest_register "$qpid" "$RUN_WORK/qemu.pid" matrix-interactive "$RUN_WORK" "${KEEP:-0}" "$artifact_dir/ephemeral"
  say "Booting $TARGET_NAME for ssh (suite prep: ${suite:-none}); serial → $RUN_WORK/serial.log"
  local waited=0
  while kill -0 "$qpid" 2>/dev/null && [[ "$(cat "$out_dir/RESULT" 2>/dev/null)" != interactive ]]; do
    sleep 2; waited=$((waited + 2))
    (( waited % 60 == 0 )) && info "still provisioning (${waited}s)…"
  done
  if [[ "$(cat "$out_dir/RESULT" 2>/dev/null)" == interactive ]]; then
    ok "guest ready"
    echo
    echo "  ssh -i $key -p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@127.0.0.1"
    echo
    info "the default user 'ubuntu' has passwordless sudo; artifacts in /mnt/artifacts, the repo read-only in /mnt/reposrc"
    info "stays up until you run 'sudo poweroff' in the guest or press Ctrl-C here"
  else
    err "the guest stopped before it was ready (serial: $RUN_WORK/serial.log)"
  fi
  wait "$qpid" 2>/dev/null
  trap - INT TERM
  guest_release
  rm -rf "$artifact_dir/ephemeral"
  return 0
}
