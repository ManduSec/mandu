#!/usr/bin/env bash
#
# require-userns.sh — CI HARD GATE: exit 0 iff an unprivileged user namespace is
# usable on this host, non-zero (with an actionable message) otherwise.
#
# Why this exists: scripts/test-all.sh and scripts/kernel-tests.sh *self-SKIP* the
# offline-userns enforcement tests (fs/net/exec supervisors via seccomp-unotify, nftables/
# TPROXY, namespaces) when unprivileged userns is unavailable. That self-skip is
# correct for portability and local dev, but in CI it is a FALSE GREEN: the
# enforcement that guards the one invariant would not run, yet the job passes.
# The every-push `test` job sets MANDU_CI_REQUIRE_USERNS=1, which makes
# test-all.sh call this gate first so a userns-less runner FAILS instead of
# skipping. See docs/design/testing/docker-e2e.md §1 ("the userns hard gate").
#
# The probe is injectable via $MANDU_USERNS_PROBE (a command string) so the gate
# is unit-testable without toggling real kernel state; unset, it runs the same
# real unshare(1) probe scripts/kernel-tests.sh uses.
#
set -uo pipefail

userns_ok() {
  if [[ -n "${MANDU_USERNS_PROBE:-}" ]]; then
    eval "$MANDU_USERNS_PROBE"
    return
  fi
  unshare --user --map-root-user --mount --net --pid --fork -- \
    bash -c '[[ "$(id -u)" == "0" ]]' >/dev/null 2>&1
}

if userns_ok; then
  echo "userns: available — offline-userns enforcement tests will run live"
  exit 0
fi

echo "userns: UNAVAILABLE — unprivileged user namespaces are off on this host" >&2
echo "  (kernel.unprivileged_userns_clone=0, or seccomp/AppArmor/container policy blocks it)." >&2
echo "  Refusing: with MANDU_CI_REQUIRE_USERNS the offline-userns enforcement tests must run, not SKIP." >&2
echo "  Run on a host with unprivileged userns enabled. See docs/design/architecture/privilege-model.md §2." >&2
exit 1
