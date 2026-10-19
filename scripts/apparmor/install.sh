#!/usr/bin/env bash
# Install Mandu's own bubblewrap from a git checkout: a copy of the system bwrap
# at the root-owned /usr/lib/mandu/bin/bwrap plus /etc/apparmor.d/mandu-bwrap,
# which attaches to that copy only (what `mandu setup` installs; see
# scripts/apparmor/README.md and docs/design/confidentiality/rootless-confinement-ubuntu-2404.md
# §12.3). One-time host admin step; nothing at Mandu runtime needs root.
#
#   sudo scripts/apparmor/install.sh                 Mandu's bubblewrap
#   sudo scripts/apparmor/install.sh --dev-unshare   also the developer-only
#                                                    unshare grant that
#                                                    scripts/kernel-tests.sh needs
#
# Older Mandu grants (/etc/apparmor.d/bwrap, unshare with a `# Mandu:` first
# line) are removed by `mandu setup`, which knows not to unload a profile name
# Ubuntu's own file also defines; this script only points at them.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEV_UNSHARE=0
for a in "$@"; do
  case "$a" in
    --dev-unshare) DEV_UNSHARE=1 ;;
    *) echo "scripts/apparmor/install.sh: unknown option '$a'" >&2; exit 2 ;;
  esac
done
if [ "$(id -u)" -ne 0 ]; then
  echo "scripts/apparmor/install.sh: must run as root (sudo $0)" >&2
  exit 1
fi
if ! command -v apparmor_parser >/dev/null 2>&1; then
  echo "scripts/apparmor/install.sh: apparmor_parser not found (is the apparmor package installed?)" >&2
  exit 1
fi
if [ ! -x /usr/bin/bwrap ]; then
  echo "scripts/apparmor/install.sh: /usr/bin/bwrap not found (sudo apt install bubblewrap)" >&2
  exit 1
fi

install -d -m 0755 -o root -g root /usr/lib/mandu /usr/lib/mandu/bin
install -m 0755 -o root -g root /usr/bin/bwrap /usr/lib/mandu/bin/bwrap
install -m 0644 -o root -g root "$HERE/mandu-bwrap" /etc/apparmor.d/mandu-bwrap
apparmor_parser -r /etc/apparmor.d/mandu-bwrap
echo "installed /usr/lib/mandu/bin/bwrap + loaded /etc/apparmor.d/mandu-bwrap"
if [ "$DEV_UNSHARE" -eq 1 ]; then
  install -m 0644 -o root -g root "$HERE/mandu-dev-unshare" /etc/apparmor.d/mandu-dev-unshare
  apparmor_parser -r /etc/apparmor.d/mandu-dev-unshare
  echo "installed + loaded /etc/apparmor.d/mandu-dev-unshare (developer-only; see the file's header)"
fi
for old in bwrap unshare; do
  if head -1 "/etc/apparmor.d/$old" 2>/dev/null | grep -q '^# Mandu:'; then
    echo "NOTE: an older Mandu grant is still installed: /etc/apparmor.d/$old; run \`mandu setup\` to remove it safely" >&2
  fi
done

echo
echo "sysctl kernel.apparmor_restrict_unprivileged_userns = $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo '(absent)')"
# Probe as the invoking (unprivileged) user when run via sudo, else as root.
probe_as() {
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    runuser -u "$SUDO_USER" -- "$@"
  else
    "$@"
  fi
}
probes=("/usr/lib/mandu/bin/bwrap --unshare-user --ro-bind / / true"
        "/usr/lib/mandu/bin/bwrap --unshare-user --dev-bind / / -- /usr/bin/bwrap --unshare-user --ro-bind / / true")
[ "$DEV_UNSHARE" -eq 1 ] && probes+=("unshare --user --map-root-user --mount -- true")
for probe in "${probes[@]}"; do
  # shellcheck disable=SC2086
  if probe_as $probe >/dev/null 2>&1; then
    echo "probe OK  : $probe"
  else
    echo "probe FAIL: $probe" >&2
  fi
done
