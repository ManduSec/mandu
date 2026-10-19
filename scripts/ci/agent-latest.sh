#!/usr/bin/env bash
#
# agent-latest.sh — run a command with an agent's NEWEST release first on PATH
# (the version-drift check, test-organization.md §5): install the agent's
# current release into a temporary prefix of its own, put its bin directory
# ahead of PATH, say the version beside the pin, and run the command. The
# maintainers' `drill.core-latest.<agent>` entries run the core drills through
# it; a red there reports a release Mandu does not handle yet and gates
# nothing (the nightly kinds are reported, continuous-integration.md §9).
#
#   scripts/ci/agent-latest.sh <agent> -- <command> [args…]
#
# <agent>: claude, codex, openclaw, opencode, opencode2 (npm), goose (the
# GitHub release binary). The prefix is a fresh directory under $TMPDIR
# (MANDU_AGENT_LATEST_PREFIX_ROOT overrides the parent), removed when the
# command ends, never the user's or the image's own install (the same rule
# as claude-latest-lane.sh). It needs the network. MANDU_AGENT_LATEST_DRY=1
# prints the install it would do and runs nothing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
usage() { echo "usage: scripts/ci/agent-latest.sh <claude|codex|openclaw|opencode|opencode2|goose> -- <command> [args…]" >&2; exit 2; }
[[ $# -ge 3 && "$2" == "--" ]] || usage
agent="$1"; shift 2

# the npm package of each npm-installed agent, and the pin's key in pins.env
case "$agent" in
  claude) pkg="@anthropic-ai/claude-code"; pinkey=CLAUDE_CODE_VERSION; bin=claude ;;
  codex) pkg="@openai/codex"; pinkey=CODEX_VERSION; bin=codex ;;
  openclaw) pkg="openclaw"; pinkey=OPENCLAW_VERSION; bin=openclaw ;;
  opencode) pkg="opencode-ai"; pinkey=OPENCODE_VERSION; bin=opencode ;;
  opencode2) pkg="@opencode/cli"; pinkey=OPENCODE2_VERSION; bin=opencode2 ;;
  goose) pkg=""; pinkey=GOOSE_VERSION; bin=goose ;;
  *) usage ;;
esac
pin="$(sed -n "s/^$pinkey=//p" "$ROOT/scripts/ci/pins.env")"

if [[ "${MANDU_AGENT_LATEST_DRY:-}" == 1 ]]; then
  if [[ -n "$pkg" ]]; then echo "agent-latest: npm install -g --prefix <temp> $pkg@latest (pinned $pin)"
  else echo "agent-latest: the newest goose release binary from GitHub into <temp>/bin (pinned $pin)"; fi
  echo "agent-latest: then: $*"
  exit 0
fi

parent="${MANDU_AGENT_LATEST_PREFIX_ROOT:-${TMPDIR:-/tmp}}"
prefix="$(mktemp -d "$parent/mandu-agent-latest.XXXXXX")"
trap 'rm -rf "$prefix"' EXIT
# Never the user's or the image's own install, whatever the parent.
real="$(cd "$prefix" && pwd -P)"
for own in "$HOME/.local" "$(npm config get prefix 2>/dev/null || true)"; do
  [[ -n "$own" && -d "$own" ]] || continue
  own="$(cd "$own" && pwd -P)"
  case "$real/" in "$own"/*)
    echo "agent-latest: the temporary prefix $real is inside $own (an install of its own); set MANDU_AGENT_LATEST_PREFIX_ROOT elsewhere" >&2
    exit 2 ;;
  esac
done

if [[ -n "$pkg" ]]; then
  npm install -g --no-audit --no-fund --prefix "$prefix" "$pkg@latest" >/dev/null
  # OpenCode 2 installs `opencode` too: only `opencode2` may lead PATH, so the
  # 1.x pin keeps its name
  if [[ "$agent" == opencode2 ]]; then
    find "$prefix/bin" -mindepth 1 -maxdepth 1 ! -name opencode2 -exec rm -f {} +
  fi
else
  # The latest release's asset by GitHub's redirect, not its REST API: the
  # CI guest maps the API host to a live drill run's sink
  # (continuous-integration.md §9.9).
  mkdir -p "$prefix/bin" "$prefix/dl"
  curl -fsSL --retry 5 -o "$prefix/dl/goose.tar.bz2" \
    https://github.com/aaif-goose/goose/releases/latest/download/goose-x86_64-unknown-linux-gnu.tar.bz2
  tar -xjf "$prefix/dl/goose.tar.bz2" -C "$prefix/dl"
  install -m 0755 "$prefix/dl/goose" "$prefix/bin/goose"
fi
export PATH="$prefix/bin:$PATH"
latest="$("$bin" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)*([-+][0-9A-Za-z.]+)?' | head -1 || true)"
if [[ "$latest" == "$pin" ]]; then
  echo "agent-latest: $agent $latest from $(command -v "$bin") is the pinned version (no drift)"
else
  echo "agent-latest: $agent $latest from $(command -v "$bin") (pinned $pin: DRIFT)"
fi
"$@"
