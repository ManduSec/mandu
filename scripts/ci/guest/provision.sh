#!/usr/bin/env bash
# provision.sh — turn a stock Ubuntu cloud image into the CI image
# (docs/design/testing/continuous-integration.md §4): 24.04, or 26.04 for the Linux 7.0
# guest (vm-image.sh --guest ubuntu-2604, §4.1), the same steps for both. Runs ONCE, as root, on the image's
# provisioning boot (cloud-init runcmd, user-mode network), started by the
# bootstrap scripts/ci/vm-image.sh puts in the cloud-init seed:
#
#   provision.sh <src-dir> <image-key>
#
# <src-dir> is the tree the image is built from (a `git archive` of the
# commit, or the work tree with vm-image.sh --worktree), read from the
# provisioning input disk. Everything is pinned by <src-dir>/scripts/ci/pins.env.
#
#   1. apt packages (build-essential, git, bubblewrap, tmux, util-linux
#      script(1), openssl, python3, netcat-openbsd, curl, bzip2, uidmap,
#      slirp4netns, pkg-config, the aarch64 cross toolchain + qemu-user for the arm64
#      native bins, meson/ninja/libcap-dev for bubblewrap, cmake for the
#      build-tool-reader sandbox test, socat and ripgrep for Claude Code's
#      own sandbox: the cc-* baselines, continuous-integration.md §9.9, and
#      the secret-readers-live socat leg; mksh, yash and luajit, the
#      interpreter families that test's step (6g) needs; golang-go, the Go
#      leg of the sibling refusal's tests, §4);
#   2. node at NODE_VERSION (nodejs.org tarball, checked against its
#      SHASUMS256.txt) into /usr/local;
#   3. bubblewrap BWRAP_VERSION from source (sha256-pinned) into
#      /usr/local/lib/mandu-ci/bwrap, OFF the PATH: ns-run.sh's overlay needs
#      >= 0.10, the product under test keeps the distro's /usr/bin/bwrap;
#   4. the agent CLIs, globally, at their pins: the npm ones (claude, codex,
#      opencode, openclaw) and the release binaries (goose), each checked
#      to run, and cargo-audit (the dependency audit) the same way; then the
#      comparison baselines (continuous-integration.md §9.10) under
#      /opt/mandu-baselines: fencepost and gitleaks, ggshield, (python 3.12
#      only) PrivAiTe in a venv with its model, OpenShell's CLI, gateway and
#      MicroVM driver, and nono, each by sha256;
#   5. the user `ci`, its rust (RUST_VERSION + the aarch64 target + clippy), a git
#      identity; the sandbox baselines' per-user state: `ci` in the kvm group
#      (OpenShell's MicroVM driver), the driver's image cache prepared from the
#      pinned images (openshell-cache.sh), nono's Claude Code pack pulled;
#   6. the warm dependencies: the tree in /work/mandu, every source file
#      stamped with one fixed mtime (and its sha256 recorded, so a run can give
#      unchanged files that mtime back and cargo rebuilds only what changed),
#      `npm ci` in every package, `cargo fetch`, `cargo build --tests` at
#      default features and `--features kernel` (and `cargo clippy` at both),
#      scripts/build-native.sh; then
#      every source file is deleted, keeping **/node_modules and
#      interceptors/target (and ~/.cargo, ~/.npm, ~/.rustup);
#   7. the guest unit (mandu-ci.service + boot.sh), the sysctls (no AppArmor
#      userns restriction; unprivileged ports from 80, for a live drill run's
#      sink, §9.9) and (26.04) the
#      bwrap-userns-restrict profile disabled, a quiet boot
#      (no getty on the serial console, no network wait, no timers, no
#      snapd, cloud-init disabled), the ready marker last.
#
# Success prints `MANDU-CI-PROVISION: OK <key>` on the serial console, which is
# what vm-image.sh waits for; failure prints `MANDU-CI-PROVISION: FAIL …`.
set -uo pipefail

SRC="${1:?usage: provision.sh <src-dir> <image-key>}"
KEY="${2:?usage: provision.sh <src-dir> <image-key>}"
CI_USER=ci
WORK=/work
TREE=$WORK/mandu
LIB=/usr/local/lib/mandu-ci
BASELINES=/opt/mandu-baselines   # lib/baseline-tools.ts BASELINE_TOOLS_DEFAULT
FIXED_MTIME=946684800   # 2000-01-01; boot.sh restores it on unchanged files

stamp() { echo "=== provision [$(date -u +%H:%M:%S)] $*"; }

read_pins() {
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9._:/+-]*)$ ]] || { echo "bad pins line: $line"; return 1; }
    printf -v "${BASH_REMATCH[1]}" '%s' "${BASH_REMATCH[2]}"
  done < "$1"
}

apt_retry() {
  local try
  for try in 1 2 3 4; do
    apt-get -o Acquire::Retries=5 -o DPkg::Lock::Timeout=600 update -q \
      && apt-get -o Acquire::Retries=5 -o DPkg::Lock::Timeout=600 install -y -q --no-install-recommends "$@" \
      && return 0
    echo "apt attempt $try failed; retrying in $((try * 20))s"; sleep $((try * 20))
  done
  return 1
}

# use_apt_mirror <url> — point the image's apt sources (both the archive and
# the security pocket) at the pinned mirror. Fails when no source took it, so a
# changed sources layout cannot silently fall back to the slow archive.
use_apt_mirror() {
  local m="$1" f n=0
  for f in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list; do
    [[ -f "$f" ]] || continue
    sed -i -E "s#https?://(archive|security)\.ubuntu\.com/ubuntu/?#$m/#g" "$f"
    grep -qF "$m/" "$f" && n=$((n + 1))
  done
  (( n > 0 )) || { echo "no apt source took the mirror $m"; return 1; }
  echo "apt mirror: $m"
}

# install_release_bin <cmd> <url> <sha256> [member] — an agent CLI (or a CI
# tool) shipped as one binary in a release tarball (.tar.bz2 or .tar.gz
# holding ./<cmd>, or <member> when the binary sits in a directory), checked
# against its pinned sha256, into /usr/local/bin. The next release-binary agent
# adds its <AGENT>_VERSION/_SHA256 pins and one call below.
install_release_bin() {
  local cmd="$1" url="$2" sha="$3" member="${4:-$1}" t
  t="$(mktemp -d)"
  curl -fsSL --retry 5 -o "$t/pkg" "$url"
  echo "$sha  $t/pkg" | sha256sum -c -
  case "$url" in *.tar.bz2) tar -xjf "$t/pkg" -C "$t" ;; *) tar -xzf "$t/pkg" -C "$t" ;; esac
  install -m 0755 "$t/$member" "/usr/local/bin/$cmd"
  rm -rf "$t"
}

as_ci() { runuser -u "$CI_USER" -- env -i HOME=/home/$CI_USER USER=$CI_USER LOGNAME=$CI_USER \
  PATH=/home/$CI_USER/.cargo/bin:/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 "$@"; }

provision() {
  set -euo pipefail
  export DEBIAN_FRONTEND=noninteractive
  read_pins "$SRC/scripts/ci/pins.env"
  stamp "image $KEY: node $NODE_VERSION, rust $RUST_VERSION, bwrap $BWRAP_VERSION"

  # 1. packages. snapd and unattended-upgrades go: they only slow each boot.
  stamp "apt"
  systemctl stop unattended-upgrades.service 2>/dev/null || true
  use_apt_mirror "$UBUNTU_APT_MIRROR"
  apt_retry build-essential git bubblewrap tmux util-linux bsdutils openssl python3 \
    netcat-openbsd curl bzip2 ca-certificates uidmap slirp4netns pkg-config xz-utils jq \
    iproute2 nftables iptables procps file \
    gcc-aarch64-linux-gnu libc6-dev-arm64-cross qemu-user \
    meson ninja-build libcap-dev cmake \
    socat ripgrep python3-venv unzip \
    golang-go \
    mksh yash luajit
  apt-get purge -y -q snapd unattended-upgrades 2>/dev/null || true
  apt-get autoremove -y -q || true

  # 2. node.
  stamp "node $NODE_VERSION"
  local d; d="$(mktemp -d)"
  local tarball="node-v$NODE_VERSION-linux-x64.tar.xz"
  curl -fsSL --retry 5 -o "$d/$tarball" "https://nodejs.org/dist/v$NODE_VERSION/$tarball"
  curl -fsSL --retry 5 -o "$d/SHASUMS256.txt" "https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt"
  (cd "$d" && grep " $tarball\$" SHASUMS256.txt | sha256sum -c -)
  tar -xJf "$d/$tarball" -C /usr/local --strip-components=1 --no-same-owner \
    --exclude='*/CHANGELOG.md' --exclude='*/README.md' --exclude='*/LICENSE'
  [[ "$(/usr/local/bin/node --version)" == "v$NODE_VERSION" ]]

  # 3. bubblewrap for ns-run.sh.
  stamp "bubblewrap $BWRAP_VERSION (source)"
  curl -fsSL --retry 5 -o "$d/bwrap.tar.xz" \
    "https://github.com/containers/bubblewrap/releases/download/v$BWRAP_VERSION/bubblewrap-$BWRAP_VERSION.tar.xz"
  echo "$BWRAP_SHA256  $d/bwrap.tar.xz" | sha256sum -c -
  tar -xJf "$d/bwrap.tar.xz" -C "$d"
  (cd "$d/bubblewrap-$BWRAP_VERSION" \
     && meson setup _build -Dman=disabled -Dtests=false -Dselinux=disabled \
          -Dbash_completion=disabled -Dzsh_completion=disabled >/dev/null \
     && ninja -C _build >/dev/null)
  install -d "$LIB"
  install -m 0755 "$d/bubblewrap-$BWRAP_VERSION/_build/bwrap" "$LIB/bwrap"
  "$LIB/bwrap" --version
  rm -rf "$d"

  # 4. the agent CLIs. openclaw's engine floor is above Mandu's node, so it
  #    gets its own node (AGENT_NODE_VERSION, verified the same way) under
  #    /opt/agent-node and a wrapper on PATH; the others run on Mandu's node.
  stamp "agent CLIs"
  npm install -g --no-audit --no-fund \
    "@anthropic-ai/claude-code@$CLAUDE_CODE_VERSION" "@openai/codex@$CODEX_VERSION" \
    "opencode-ai@$OPENCODE_VERSION"
  # OpenCode 2 installs `opencode` too: its own prefix, and only `opencode2`
  # linked onto PATH, so `opencode` stays the 1.x pin.
  stamp "opencode2 $OPENCODE2_VERSION"
  npm install -g --no-audit --no-fund --prefix /opt/opencode2 "@opencode/cli@$OPENCODE2_VERSION"
  ln -sf /opt/opencode2/bin/opencode2 /usr/local/bin/opencode2
  [[ "$(HOME="$(mktemp -d)" opencode2 --version)" == "opencode v$OPENCODE2_VERSION" ]]
  [[ "$(opencode --version)" == "$OPENCODE_VERSION" ]]
  stamp "agent node $AGENT_NODE_VERSION + openclaw $OPENCLAW_VERSION"
  d="$(mktemp -d)"
  tarball="node-v$AGENT_NODE_VERSION-linux-x64.tar.xz"
  curl -fsSL --retry 5 -o "$d/$tarball" "https://nodejs.org/dist/v$AGENT_NODE_VERSION/$tarball"
  curl -fsSL --retry 5 -o "$d/SHASUMS256.txt" "https://nodejs.org/dist/v$AGENT_NODE_VERSION/SHASUMS256.txt"
  (cd "$d" && grep " $tarball\$" SHASUMS256.txt | sha256sum -c -)
  install -d /opt/agent-node
  tar -xJf "$d/$tarball" -C /opt/agent-node --strip-components=1 --no-same-owner \
    --exclude='*/CHANGELOG.md' --exclude='*/README.md' --exclude='*/LICENSE'
  rm -rf "$d"
  [[ "$(/opt/agent-node/bin/node --version)" == "v$AGENT_NODE_VERSION" ]]
  PATH=/opt/agent-node/bin:$PATH /opt/agent-node/bin/npm install -g --no-audit --no-fund \
    --prefix /opt/agent-node "openclaw@$OPENCLAW_VERSION"
  printf '#!/bin/sh\nexec /opt/agent-node/bin/node /opt/agent-node/lib/node_modules/openclaw/openclaw.mjs "$@"\n' \
    > /usr/local/bin/openclaw
  chmod 0755 /usr/local/bin/openclaw
  stamp "release-binary agents: goose $GOOSE_VERSION"
  install_release_bin goose \
    "https://github.com/aaif-goose/goose/releases/download/v$GOOSE_VERSION/goose-x86_64-unknown-linux-gnu.tar.bz2" \
    "$GOOSE_SHA256"
  [[ "$(goose --version | tr -d ' ')" == "$GOOSE_VERSION" ]]
  # The dependency audit's cargo-audit (continuous-integration.md §14.2): the
  # static musl build of the RustSec release, not `cargo install` (the
  # current releases need a newer rustc than the workspace's pinned one).
  stamp "cargo-audit $CARGO_AUDIT_VERSION"
  install_release_bin cargo-audit \
    "https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv$CARGO_AUDIT_VERSION/cargo-audit-x86_64-unknown-linux-musl-v$CARGO_AUDIT_VERSION.tgz" \
    "$CARGO_AUDIT_SHA256" "cargo-audit-x86_64-unknown-linux-musl-v$CARGO_AUDIT_VERSION/cargo-audit"
  [[ "$(cargo-audit --version)" == "cargo-audit $CARGO_AUDIT_VERSION" ]]
  # The comparison baselines (continuous-integration.md §9.10): third-party
  # protections the maintainers measure Mandu against, offline once here.
  stamp "baselines: gitleaks $GITLEAKS_VERSION, fencepost $FENCEPOST_VERSION"
  install_release_bin gitleaks \
    "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    "$GITLEAKS_SHA256"
  [[ "$(gitleaks version)" == "$GITLEAKS_VERSION" ]]
  install -d -m 0755 "$BASELINES"
  d="$(mktemp -d)"
  curl -fsSL --retry 5 -o "$d/fencepost.zip" \
    "https://github.com/ch4nn0n/fencepost/releases/download/v$FENCEPOST_VERSION/fencepost-v$FENCEPOST_VERSION.zip"
  echo "$FENCEPOST_SHA256  $d/fencepost.zip" | sha256sum -c -
  unzip -q "$d/fencepost.zip" -d "$d"
  rm -rf "$BASELINES/fencepost"
  mv "$d/fencepost-v$FENCEPOST_VERSION" "$BASELINES/fencepost"
  rm -rf "$d"
  [[ "$(jq -r .version "$BASELINES/fencepost/.claude-plugin/plugin.json")" == "$FENCEPOST_VERSION" ]]
  # GitGuardian's ggshield, the standalone release (its own python inside):
  # the ggshield baseline's Claude Code hooks (lib/baseline-ggshield.ts).
  stamp "baselines: ggshield $GGSHIELD_VERSION"
  d="$(mktemp -d)"
  curl -fsSL --retry 5 -o "$d/ggshield.tar.gz" \
    "https://github.com/GitGuardian/ggshield/releases/download/v$GGSHIELD_VERSION/ggshield-$GGSHIELD_VERSION-x86_64-unknown-linux-gnu.tar.gz"
  echo "$GGSHIELD_SHA256  $d/ggshield.tar.gz" | sha256sum -c -
  tar -xzf "$d/ggshield.tar.gz" -C "$d"
  rm -rf "$BASELINES/ggshield"
  mv "$d/ggshield-$GGSHIELD_VERSION-x86_64-unknown-linux-gnu" "$BASELINES/ggshield"
  rm -rf "$d"
  [[ "$("$BASELINES/ggshield/ggshield" --version)" == "ggshield, version $GGSHIELD_VERSION" ]]
  # Docker Sandboxes (sbx): Docker's 24.04 package, the Docker Sandboxes
  # baseline (lib/baseline-docker-sbx.ts); microVMs on the guest's nested KVM
  # (`ci` joins the kvm group below). The 26.04 guest goes without it.
  if [[ "$(. /etc/os-release && echo "$VERSION_ID")" == 24.04 ]]; then
    stamp "baselines: docker sbx $SBX_VERSION"
    d="$(mktemp -d)"
    curl -fsSL --retry 5 -o "$d/docker-sbx.deb" \
      "https://github.com/docker/sbx-releases/releases/download/v$SBX_VERSION/DockerSandboxes-linux-amd64-ubuntu2404.deb"
    echo "$SBX_SHA256  $d/docker-sbx.deb" | sha256sum -c -
    apt_retry "$d/docker-sbx.deb"
    rm -rf "$d"
    [[ "$(sbx version | head -1)" == "sbx version v$SBX_VERSION "* ]]
  else
    echo "baselines: not Ubuntu 24.04: no Docker Sandboxes on this guest"
  fi
  # PrivAiTe's wheels are CPython 3.12's (privaite-requirements.txt): the
  # 24.04 guest. Another guest's python goes without it, and a privaite
  # baseline there is refused (lib/baseline-tools.ts), never run bare.
  if python3 -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)'; then
    stamp "baselines: privaite $PRIVAITE_VERSION + openai/privacy-filter@$PRIVACY_FILTER_REVISION"
    python3 -m venv "$BASELINES/privaite"
    "$BASELINES/privaite/bin/pip" install -q --no-cache-dir --require-hashes --no-deps --only-binary :all: \
      -r "$SRC/scripts/ci/guest/privaite-requirements.txt"
    grep -q "^privaite==$PRIVAITE_VERSION " "$SRC/scripts/ci/guest/privaite-requirements.txt"
    local snap="$BASELINES/hf/hub/models--openai--privacy-filter/snapshots/$PRIVACY_FILTER_REVISION" f
    install -d "$snap/onnx"
    while read -r _ f; do
      curl -fsSL --retry 5 -o "$snap/$f" "https://huggingface.co/openai/privacy-filter/resolve/$PRIVACY_FILTER_REVISION/$f"
    done < "$SRC/scripts/ci/guest/privaite-model.sha256"
    (cd "$snap" && sha256sum -c --quiet "$SRC/scripts/ci/guest/privaite-model.sha256")
    # it loads offline: spaCy's model, the ONNX model from the cache, no hub call
    HF_HOME="$BASELINES/hf" HF_HUB_OFFLINE=1 LITELLM_LOCAL_MODEL_COST_MAP=True "$BASELINES/privaite/bin/python" -I -c \
      "import importlib.metadata as m, spacy; assert m.version('privaite') == '$PRIVAITE_VERSION'; spacy.load('en_core_web_lg'); print('privaite', m.version('privaite'), 'spacy', spacy.__version__)"
  else
    echo "baselines: python3 is $(python3 --version 2>&1), not 3.12: no PrivAiTe on this guest"
  fi
  # OpenShell: the CLI, the gateway and its MicroVM driver (the driver's
  # image cache is prepared as the CI user below, once the user exists).
  stamp "baselines: openshell $OPENSHELL_VERSION, nono $NONO_VERSION"
  local osb="$BASELINES/openshell/bin" pair asset
  install -d -m 0755 "$osb"
  d="$(mktemp -d)"
  for pair in "openshell-x86_64-unknown-linux-musl.tar.gz:$OPENSHELL_CLI_SHA256" \
              "openshell-gateway-x86_64-unknown-linux-gnu.tar.gz:$OPENSHELL_GATEWAY_SHA256" \
              "openshell-driver-vm-x86_64-unknown-linux-gnu.tar.gz:$OPENSHELL_DRIVER_VM_SHA256"; do
    asset="${pair%%:*}"
    curl -fsSL --retry 5 -o "$d/$asset" "https://github.com/NVIDIA/OpenShell/releases/download/v$OPENSHELL_VERSION/$asset"
    echo "${pair#*:}  $d/$asset" | sha256sum -c -
    tar -xzf "$d/$asset" -C "$osb" --no-same-owner
  done
  rm -rf "$d"
  for c in openshell openshell-gateway openshell-driver-vm; do
    [[ "$("$osb/$c" --version)" == "$c $OPENSHELL_VERSION" ]]
  done
  # nono: one static-enough binary (glibc), by sha256
  install_release_bin nono \
    "https://github.com/nolabs-ai/nono/releases/download/v$NONO_VERSION/nono-v$NONO_VERSION-x86_64-unknown-linux-gnu.tar.gz" \
    "$NONO_SHA256"
  [[ "$(nono --version)" == "nono $NONO_VERSION" ]]
  chmod -R a+rX "$BASELINES"
  # Every CLI must RUN, not just be on PATH: a CLI that installs but refuses
  # to start would make its suite skip to green in every run.
  for c in claude codex opencode opencode2 openclaw goose; do command -v "$c"; "$c" --version; done
  # Claude Code's own sandbox (the cc-* baselines, §9.9) needs these on PATH;
  # without one it refuses to start under failIfUnavailable.
  for c in bwrap socat rg; do command -v "$c"; done
  # secret-readers-live's (6g) skips the leg without them (§4): each must run.
  mksh -c 'echo mksh ok'; lksh -c 'echo lksh ok'; yash -c 'echo yash ok'; luajit -e 'print("luajit ok")'
  # The sibling refusal's Go leg (clone_filter_integration, wrap-clone-filter)
  # builds its probe with the distro's go; without it the leg skips.
  go version

  # 5. the user, its rust, a git identity (fs-sync commits; git refuses to
  #    without one).
  stamp "user $CI_USER + rust $RUST_VERSION"
  id "$CI_USER" >/dev/null 2>&1 || useradd -m -U -s /bin/bash "$CI_USER"
  # Docker Sandboxes' local microVMs need /dev/kvm (the baseline, §9.10)
  getent group kvm >/dev/null && usermod -aG kvm "$CI_USER"
  passwd -l "$CI_USER" >/dev/null
  git config --system user.name "Mandu CI"
  git config --system user.email "ci@mandu.invalid"
  git config --system init.defaultBranch main
  as_ci bash -c "curl --proto '=https' --tlsv1.2 -sSf --retry 5 https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain '$RUST_VERSION' --target aarch64-unknown-linux-gnu --component clippy"
  as_ci rustc --version
  as_ci cargo clippy --version
  # The sandbox baselines' per-user state (continuous-integration.md §9.10).
  # OpenShell's MicroVM driver opens /dev/kvm (the guest runs under KVM with
  # the host CPU, so it has a nested one): the user joins the kvm group, and
  # the driver's image cache is prepared once from the pinned images.
  stamp "baselines: openshell image cache, nono's Claude Code and Codex packs"
  usermod -aG kvm "$CI_USER"
  install -d -o "$CI_USER" -g "$CI_USER" -m 0755 "$BASELINES/openshell/vm"
  as_ci bash "$SRC/scripts/ci/guest/openshell-cache.sh" "$BASELINES/openshell/bin" "$BASELINES/openshell/vm" \
    "$OPENSHELL_SANDBOX_IMAGE@$OPENSHELL_SANDBOX_IMAGE_DIGEST" "$OPENSHELL_BOOTSTRAP_IMAGE@$OPENSHELL_BOOTSTRAP_IMAGE_DIGEST"
  # nono's Claude Code pack (the claude-code profile and its plugin), signed,
  # into the user's ~/.config/nono; the profile checked by sha256. Pulling it
  # enables its plugin in the user's ~/.claude/settings.json for every Claude
  # Code session: that line is taken out again, and the baseline-nono session
  # enables it for itself (baseline-tools.ts in the drill suite)
  as_ci nono pull "nolabs-ai/claude@$NONO_CLAUDE_PACK_VERSION"
  echo "$NONO_CLAUDE_PACK_PROFILE_SHA256  /home/$CI_USER/.config/nono/packages/nolabs-ai/claude/profiles/claude.json" | sha256sum -c -
  local ccs="/home/$CI_USER/.claude/settings.json"
  if [[ -f "$ccs" ]]; then
    jq 'del(.enabledPlugins["nono@nolabs-ai"]) | if .enabledPlugins == {} then del(.enabledPlugins) else . end' "$ccs" > "$ccs.tmp"
    chown "$CI_USER:$CI_USER" "$ccs.tmp" && mv "$ccs.tmp" "$ccs"
    ! grep -q 'nono@nolabs-ai' "$ccs"
  fi
  # nono's Codex pack (the codex profile), the same way. Pulling it merges a
  # block (the pack's skill and developer instructions) into the user's
  # ~/.codex/config.toml for every Codex session: the file is put back as it
  # was (or removed, when there was none); a drill's Codex runs on a private
  # CODEX_HOME anyway
  local cxc="/home/$CI_USER/.codex/config.toml" had_cxc=0
  [[ -f "$cxc" ]] && { had_cxc=1; cp -p "$cxc" "$cxc.pre-nono"; }
  as_ci nono pull "nolabs-ai/codex@$NONO_CODEX_PACK_VERSION"
  echo "$NONO_CODEX_PACK_PROFILE_SHA256  /home/$CI_USER/.config/nono/packages/nolabs-ai/codex/profiles/codex.json" | sha256sum -c -
  if [[ $had_cxc == 1 ]]; then mv "$cxc.pre-nono" "$cxc"; else rm -f "$cxc"; fi

  # 6. the warm dependencies.
  stamp "warm dependencies in $TREE"
  install -d -o "$CI_USER" -g "$CI_USER" "$WORK" "$TREE"
  tar -C "$SRC" -cf - . | as_ci tar -C "$TREE" -xf -
  as_ci find "$TREE" \( -type f -o -type l \) -exec touch -h -d "@$FIXED_MTIME" {} +
  install -d /var/lib/mandu-ci
  (cd "$TREE" && find . -type f -printf '%P\0' | LC_ALL=C sort -z | xargs -0 sha256sum) > /var/lib/mandu-ci/src.sha256
  local lockdirs
  lockdirs="$(find "$TREE" \( -name node_modules -o -name target -o -name .git \) -prune \
                -o -name package-lock.json -type f -printf '%h\n' | LC_ALL=C sort)"
  local p
  for p in $lockdirs; do
    stamp "npm ci: ${p#"$TREE"/}"
    as_ci bash -c "cd '$p' && npm ci --no-audit --no-fund"
    sha256sum "$p/package-lock.json" | cut -d' ' -f1 | as_ci tee "$p/node_modules/.mandu-ci-lock" >/dev/null
  done
  stamp "cargo fetch + build"
  as_ci bash -c "cd '$TREE/interceptors' && cargo fetch && cargo build --tests --workspace \
    && cargo build --tests --workspace --features kernel \
    && cargo clippy --workspace --all-targets --quiet && cargo clippy --workspace --all-targets --features kernel --quiet"
  as_ci bash "$TREE/scripts/build-native.sh"
  stamp "drop the sources, keep the dependencies"
  (cd "$TREE" && find . -mindepth 1 \( -name node_modules -o -path ./interceptors/target \) -prune \
      -o \( -type f -o -type l \) -print0 | xargs -0 -r rm -f)
  local i
  for i in $(seq 1 30); do
    (cd "$TREE" && find . -mindepth 1 \( -name node_modules -o -path ./interceptors/target \) -prune \
        -o -type d -empty -print0 | xargs -0 -r rmdir) || true
  done
  du -sh "$TREE" /home/$CI_USER/.cargo /home/$CI_USER/.rustup /home/$CI_USER/.npm 2>/dev/null || true

  # 7. the guest unit and a quiet boot.
  stamp "guest unit"
  install -m 0755 "$SRC/scripts/ci/guest/boot.sh" "$LIB/boot.sh"
  install -m 0644 "$SRC/scripts/ci/guest/mandu-ci.service" /etc/systemd/system/mandu-ci.service
  printf '%s\n' "kernel.apparmor_restrict_unprivileged_userns = 0" "net.ipv4.ip_unprivileged_port_start = 80" > /etc/sysctl.d/60-mandu-ci.conf
  # The sysctl is not the whole restriction on 26.04 (§4.1): its
  # bwrap-userns-restrict profile, attached to /usr/bin/bwrap whatever the
  # sysctl says, moves what a bwrap sandbox runs into `unpriv_bwrap`, which may
  # not create a user namespace, so a bwrap inside a bwrap (the whole-agent
  # wrap around the exec box, the guard's pid-namespace tests) fails with "No
  # permissions to create a new namespace". The kernel tier runs as on an
  # unrestricted host (§3), so the image disables it the documented way (a
  # link in /etc/apparmor.d/disable, honoured at every boot). The restricted
  # posture a stock 26.04 user has is the install matrix's subject.
  if [[ -f /etc/apparmor.d/bwrap-userns-restrict ]]; then
    install -d /etc/apparmor.d/disable   # 26.04 ships none
    ln -sf /etc/apparmor.d/bwrap-userns-restrict /etc/apparmor.d/disable/bwrap-userns-restrict
    apparmor_parser -R /etc/apparmor.d/bwrap-userns-restrict 2>/dev/null || true
    echo "apparmor: bwrap-userns-restrict disabled"
  fi
  systemctl enable mandu-ci.service
  systemctl mask serial-getty@ttyS0.service systemd-networkd-wait-online.service \
    apt-daily.timer apt-daily-upgrade.timer motd-news.timer man-db.timer fwupd-refresh.timer \
    e2scrub_all.timer fstrim.timer ssh.service ssh.socket multipathd.service multipathd.socket \
    2>/dev/null || true
  touch /etc/cloud/cloud-init.disabled
  cat > /etc/default/grub.d/60-mandu-ci.cfg <<'GRUB'
# mandu CI: no menu wait; the serial console last, so it is /dev/console.
GRUB_TIMEOUT=0
GRUB_TIMEOUT_STYLE=hidden
GRUB_RECORDFAIL_TIMEOUT=0
GRUB_CMDLINE_LINUX_DEFAULT="console=tty1 console=ttyS0"
GRUB
  update-grub 2>/dev/null || true
  install -d /etc/mandu-ci
  {
    echo "MANDU_CI_IMAGE_KEY=$KEY"
    echo "MANDU_CI_IMAGE_BUILT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    grep -E '^[A-Z]' "$SRC/scripts/ci/pins.env"
  } > /etc/mandu-ci/image.env

  stamp "clean up"
  apt-get clean
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
  case "$SRC" in /var/lib/mandu-ci/in/*) rm -rf /var/lib/mandu-ci/in ;; esac
  fstrim -av || true
  touch /etc/mandu-ci/ready
  sync
}

( provision )
rc=$?
if [[ $rc -eq 0 ]]; then
  echo "MANDU-CI-PROVISION: OK $KEY"
  echo "MANDU-CI-PROVISION: OK $KEY" > /dev/ttyS0 2>/dev/null || true
else
  echo "MANDU-CI-PROVISION: FAIL (exit $rc)"
  echo "MANDU-CI-PROVISION: FAIL (exit $rc)" > /dev/ttyS0 2>/dev/null || true
fi
exit $rc
