#!/usr/bin/env bash
# run.sh — entrypoint for the Mandu × AgentDojo eval (docs/design/testing/evaluation.md §2).
#
#   ./run.sh smoke              offline invariant proof (no key, no network). Boots
#                               the real arbiter + anthropic-proxy against a mock
#                               upstream and asserts an AgentDojo injection reaches
#                               the model only as a $MDU:* symbol. Default.
#   ./run.sh audit              offline trust-gap audit (no key): assert every
#                               injection-carrying tool classifies UNTRUSTED. The
#                               static half of the adaptive-attack arm; exits
#                               non-zero on a by-construction hole.
#   ./run.sh real [args...]     real-model ASR / utility / overhead over the
#                               benchmark. Needs a Console ANTHROPIC_API_KEY; SKIPS
#                               cleanly (exit 0) without one. args pass through to
#                               runner.py (e.g. --suites slack --defense both).
#
# Provisions a local venv (prefers uv, falls back to python3 -m venv) with
# agentdojo pinned. SKIPs cleanly (exit 0) if a Python >=3.10 or the Node stack is
# unavailable, so it never breaks a portable suite.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# Central API-key setup: load the gitignored secrets file (if present) so the
# `real` tier picks up ANTHROPIC_API_KEY from one place (docs/design/testing/continuous-integration.md §13).
if [ -f "$HERE/../../scripts/mandu-env.sh" ]; then
  # shellcheck source=/dev/null
  source "$HERE/../../scripts/mandu-env.sh"
fi

MODE="${1:-smoke}"; shift || true

# ── provision a Python >=3.10 venv (agentdojo needs 3.10+) ───────────────────
# Prefer uv: it can FETCH a managed 3.12 even when none is on PATH (this host's
# system python is 3.8). Fall back to a system python3 >=3.10 via venv.
VENV="$HERE/.venv"
PYBIN="$VENV/bin/python"
if [ ! -x "$PYBIN" ]; then
  echo "[agentdojo-eval] provisioning venv at $VENV …"
  if command -v uv >/dev/null 2>&1; then
    uv venv --python 3.12 "$VENV" >/dev/null || { echo "SKIP: uv could not provision Python 3.12"; exit 0; }
    uv pip install --python "$PYBIN" -r requirements.txt >/dev/null
  else
    PY=""
    for cand in python3.12 python3.11 python3.10 python3; do
      if command -v "$cand" >/dev/null 2>&1 \
         && "$cand" -c 'import sys; sys.exit(0 if sys.version_info[:2]>=(3,10) else 1)' 2>/dev/null; then
        PY="$cand"; break
      fi
    done
    if [ -z "$PY" ]; then
      echo "SKIP: no Python >=3.10 found and uv is unavailable (agentdojo requires 3.10+)"; exit 0
    fi
    "$PY" -m venv "$VENV"
    "$PYBIN" -m pip install --quiet --upgrade pip >/dev/null
    "$PYBIN" -m pip install --quiet -r requirements.txt >/dev/null
  fi
fi

case "$MODE" in
  smoke)
    exec "$PYBIN" invariant_smoke.py
    ;;
  audit)
    # Offline (no-key) trust-gap audit: assert every AgentDojo injection-carrying
    # tool classifies UNTRUSTED under arbiter/policy/agentdojo-inbound.ts. Exits
    # non-zero on a by-construction hole. The static half of the adaptive arm.
    exec "$PYBIN" trust_gap_audit.py
    ;;
  real)
    exec "$PYBIN" runner.py "$@"
    ;;
  *)
    echo "usage: run.sh [smoke|audit|real] [runner args…]"; exit 2
    ;;
esac
