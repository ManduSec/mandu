#!/usr/bin/env bash
# release-upgrade host prep (os-test-matrix.md §10.15): the same bundle and
# stub agent fresh-install packs, plus the scenario knobs the guest reads.
#   RELEASE_UPGRADE_FROM=current (default) | legacy
#     current: the host ran today's `mandu setup` (Mandu's own bubblewrap)
#     legacy:  the host ran a pre-2026-09-27 `mandu setup` (the grant named
#              `bwrap` for /usr/bin/bwrap, and one for unshare)
#   RELEASE_UPGRADE_PATH=auto (default) | regular | development | proposed
#     which do-release-upgrade path to take; auto takes the regular LTS path
#     when Ubuntu offers it and the development one (-d) otherwise
set -euo pipefail
: "${ARTIFACT_DIR:?}" "${REPO_ROOT:?}"
HERE="$(cd "$(dirname "$0")" && pwd)"
bash "$HERE/fresh-install.host.sh"
from="${RELEASE_UPGRADE_FROM:-current}"; path="${RELEASE_UPGRADE_PATH:-auto}"
case "$from" in current|legacy) ;; *) echo "RELEASE_UPGRADE_FROM must be current or legacy" >&2; exit 1 ;; esac
case "$path" in auto|regular|development|proposed) ;; *) echo "RELEASE_UPGRADE_PATH must be auto, regular, development or proposed" >&2; exit 1 ;; esac
printf 'from=%s\npath=%s\n' "$from" "$path" > "$ARTIFACT_DIR/UPGRADE"
