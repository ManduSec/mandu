#!/usr/bin/env bash
# stub `claude` for the fresh-install suite (os-test-matrix.md §10.3.5).
# Deterministic and credential-free: records the context the wrapper composed
# and what a read of the planted secret returned, as KEY=value lines in
# $STUB_REPORT (default ~/stub-report). The secret read is the behavioral
# oracle: under `confined` it must NOT be the canary.
set -uo pipefail
out="${STUB_REPORT:-$HOME/stub-report}"
{
  echo "ran=1"
  echo "base_url=${ANTHROPIC_BASE_URL:-}"
  echo "arbiter_sock=${MANDU_ARBITER_SOCK:-}"
  echo "scope=${MANDU_SCOPE_ID:-}"
  echo "argv=$*"
  if secret="$(cat "$HOME/.aws/credentials" 2>/dev/null)"; then
    case "$secret" in
      *FRESHINSTALLCANARY*) echo "secret_read=canary" ;;
      *)                    echo "secret_read=other" ;;
    esac
  else
    echo "secret_read=denied"
  fi
  # Can the agent start a sandbox of its own here (what Codex's does)? The
  # release-upgrade suite reads it; fresh-install only records it.
  if ! command -v bwrap >/dev/null 2>&1; then echo "nest=no-bwrap"
  elif bwrap --unshare-user --unshare-pid --unshare-net --ro-bind / / --proc /proc --dev /dev -- true 2>/dev/null; then echo "nest=ok"
  else echo "nest=refused"; fi
  echo "bwrap_path=$(command -v bwrap 2>/dev/null)"
} > "$out"
echo "stub-claude: ok"
