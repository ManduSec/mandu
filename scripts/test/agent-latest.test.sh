#!/usr/bin/env bash
#
# agent-latest.test.sh — scripts/ci/agent-latest.sh (the version-drift check,
# docs/design/testing/test-organization.md §5): it installs the agent's newest
# release into a temporary npm prefix of its own, never ~/.local or npm's
# global prefix, runs the command with that release first on PATH, says the
# version beside the pin (DRIFT when they differ), passes the command's exit
# status through, and removes the prefix when the command ends, failed or not.
#
# Runs the script in a throwaway tree with a stub `npm` on PATH: nothing is
# installed, no network, no model. Needs bash and coreutils.
#
# Run:  bash scripts/test/agent-latest.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PASS=0 FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); [ -f "$T/out" ] && sed 's/^/  | /' "$T/out"; [ -f "$T/calls" ] && sed 's/^/  calls: /' "$T/calls"; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

T="$(mktemp -d "${TMPDIR:-/tmp}/agent-latest.XXXXXX")"; trap 'rm -rf "$T"' EXIT
R="$T/repo"; mkdir -p "$R/scripts/ci" "$T/bin" "$T/tmp" "$T/npm-global" "$T/home"
cp "$REPO/scripts/ci/agent-latest.sh" "$R/scripts/ci/"
printf 'CLAUDE_CODE_VERSION=2.1.295\nCODEX_VERSION=0.162.0\nOPENCODE2_VERSION=2.0.23\nGOOSE_VERSION=1.53.0\n' > "$R/scripts/ci/pins.env"
# A stub npm: `config get prefix` names a global prefix of its own; `install -g
# --prefix P <pkg>@latest` records the call and puts a CLI printing VERSION in
# P/bin (OpenCode 2's package installs `opencode` too, as the real one does).
cat > "$T/bin/npm" <<'EOF'
#!/bin/sh
echo "npm $*" >> "$CALLS"
if [ "$1" = config ]; then echo "$NPM_GLOBAL"; exit 0; fi
prefix=""; pkg=""
while [ $# -gt 0 ]; do case "$1" in --prefix) prefix="$2"; shift 2 ;; -*) shift ;; *) pkg="$1"; shift ;; esac; done
[ -n "$FAIL_INSTALL" ] && exit 1
mkdir -p "$prefix/bin"
case "$pkg" in
  @anthropic-ai/claude-code@latest) n=claude ;;
  @openai/codex@latest) n=codex ;;
  @opencode/cli@latest) n=opencode2; printf '#!/bin/sh\necho 1.0.0\n' > "$prefix/bin/opencode"; chmod +x "$prefix/bin/opencode" ;;
  *) exit 1 ;;
esac
printf '#!/bin/sh\necho "%s"\n' "$VERSION" > "$prefix/bin/$n"; chmod +x "$prefix/bin/$n"
EOF
chmod +x "$T/bin/npm"
export CALLS="$T/calls" NPM_GLOBAL="$T/npm-global" HOME="$T/home" TMPDIR="$T/tmp" PATH="$T/bin:$PATH" FAIL_INSTALL=""
run() { : > "$T/calls"; ( cd "$R" && bash scripts/ci/agent-latest.sh "$@" ) > "$T/out" 2>&1; echo $? > "$T/rc"; }

# the newest release ahead of PATH, the version and DRIFT said, the command run, the prefix gone
VERSION="2.1.300 (Claude Code)" run claude -- sh -c 'command -v claude; claude --version; echo "args:$*"' x one two
check "claude: npm installs @anthropic-ai/claude-code@latest into a temporary prefix under TMPDIR" \
  "grep -q 'npm install -g --no-audit --no-fund --prefix $T/tmp/mandu-agent-latest\\.[A-Za-z0-9]* @anthropic-ai/claude-code@latest' '$T/calls'"
check "claude: the command ran with that prefix's claude first on PATH, and its arguments" \
  "grep -q '^$T/tmp/mandu-agent-latest\\.[A-Za-z0-9]*/bin/claude$' '$T/out' && grep -q '^2.1.300 (Claude Code)$' '$T/out' && grep -q '^args:one two$' '$T/out'"
check "claude: the version beside the pin, DRIFT when they differ" "grep -q 'agent-latest: claude 2.1.300 from .* (pinned 2.1.295: DRIFT)' '$T/out'"
check "claude: exit 0, and the prefix is removed" "[[ \$(cat '$T/rc') -eq 0 ]] && [[ -z \"\$(ls -A '$T/tmp')\" ]]"

VERSION="codex-cli 0.162.0" run codex -- true
check "codex: the pinned version is no drift" "grep -q 'agent-latest: codex 0.162.0 from .* is the pinned version (no drift)' '$T/out'"

# the command's red is the script's, and the prefix still goes
VERSION="2.1.300" run claude -- sh -c 'exit 7'
check "a failing command: its exit status passes through, the prefix removed" "[[ \$(cat '$T/rc') -eq 7 ]] && [[ -z \"\$(ls -A '$T/tmp')\" ]]"

# OpenCode 2: only `opencode2` leads PATH, so the 1.x pin keeps its name
VERSION="2.0.30" run opencode2 -- sh -c 'command -v opencode || echo no-opencode; opencode2 --version'
check "opencode2: @opencode/cli@latest, and its own opencode left out of the prefix" \
  "grep -q '@opencode/cli@latest' '$T/calls' && grep -q '^2.0.30$' '$T/out' && ! grep -q 'mandu-agent-latest.*/bin/opencode$' '$T/out' && grep -q 'pinned 2.0.23: DRIFT' '$T/out'"

# a failed install stops before the command
FAIL_INSTALL=1 VERSION=x run claude -- sh -c 'echo RAN'
check "a failed install: nonzero, the command never ran, the prefix removed" \
  "[[ \$(cat '$T/rc') -ne 0 ]] && ! grep -q RAN '$T/out' && [[ -z \"\$(ls -A '$T/tmp')\" ]]"

# never inside the user's or npm's own prefix
NPM_GLOBAL="$T/tmp" VERSION=x run claude -- true
check "a temporary prefix inside npm's global prefix is refused (exit 2)" \
  "[[ \$(cat '$T/rc') -eq 2 ]] && grep -q 'is inside' '$T/out'"

# usage, and the dry run
run nope -- true
check "an unknown agent is a usage error" "[[ \$(cat '$T/rc') -eq 2 ]] && grep -q '^usage:' '$T/out'"
run claude true
check "a command without -- is a usage error" "[[ \$(cat '$T/rc') -eq 2 ]]"
MANDU_AGENT_LATEST_DRY=1 run goose -- echo hi
check "the dry run names the install (goose: the GitHub release) and runs nothing" \
  "[[ \$(cat '$T/rc') -eq 0 ]] && grep -q 'the newest goose release binary from GitHub' '$T/out' && grep -q 'pinned 1.53.0' '$T/out' && ! grep -q '^hi$' '$T/out' && [[ ! -s '$T/calls' ]]"

echo "agent-latest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
