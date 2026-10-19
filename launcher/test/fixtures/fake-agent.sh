#!/usr/bin/env bash
# fake-agent — a stand-in for claude/codex. Prints the wrapper-composed context
# as JSON so the e2e can assert the env/CWD/argv the agent actually received.
set -euo pipefail
printf '{"base_url":"%s","headers":"%s","scope":"%s","arbiter":"%s","cwd":"%s","path0":"%s","nonessential":"%s","argv":"%s"}\n' \
  "${ANTHROPIC_BASE_URL:-}" "${ANTHROPIC_CUSTOM_HEADERS:-}" "${MANDU_SCOPE_ID:-}" \
  "${MANDU_ARBITER_SOCK:-}" "$(pwd)" "${PATH%%:*}" "${CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:-}" "$*"
