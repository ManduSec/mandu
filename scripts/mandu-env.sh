#!/usr/bin/env bash
# mandu-env.sh — load the Mandu secrets file into the environment.
#
#   source scripts/mandu-env.sh      # load keys into THIS shell (then run
#                                       # launcher / npx tsx eval / etc. normally)
#
# Central key setup: it reads the gitignored secrets JSON (see docs/design/
# continuous-integration.md §13) and exports ANTHROPIC_API_KEY / OPENAI_API_KEY / MANDU_ULLM_* —
# the env vars the launcher, proxies, inspect-mcp, and eval backends already read.
#
# Safe to source repeatedly. Never overrides an env var you already set. A missing
# file / bad JSON is non-fatal (nothing loaded). Needs `node` on PATH (this is a
# Node repo); if node is absent it warns and no-ops.
#
# The launcher (launcher/mandu-run.sh) and eval/agentdojo/run.sh auto-load
# this, so you only need to source it yourself for direct `npx tsx` eval runs.
# A checkout's bundled `mandu` launch does not source it: the launcher's own
# node applies the same exports in process (secrets-to-env.mjs
# applySecretsEnv, launcher/scripts/checkout-launch.mjs; packaging.md §5.1).
_mandu_env_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
if command -v node >/dev/null 2>&1; then
  eval "$(node "${_mandu_env_dir}/secrets-to-env.mjs")"
else
  echo "[mandu-secrets] node not on PATH — cannot load secrets file" >&2
fi
unset _mandu_env_dir
