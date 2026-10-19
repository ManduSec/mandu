#!/usr/bin/env bash
# scripts/bootstrap.sh — M1 interim install channel (packaging.md §8).
#
#   git clone … && cd mandu && scripts/bootstrap.sh
#
# One command: install every TS package's deps, typecheck them, build the
# launcher bundle, and drop an `mandu` shim on PATH — so a fresh clone becomes a
# runnable `mandu claude` without the clone-and-a-dozen-npm-installs prelude
# (packaging.md §1). This is the COLLABORATOR / onboarding channel until the
# public npm package (M5); it is NOT the shipped artifact. The shim runs
# launcher/mandu-run.sh, which runs the checkout's own prebuilt bundle while it
# matches the source and rebuilds it (or falls back to tsx) when it does not
# (packaging.md §5.1); building it here keeps the first launch from paying for
# that build.
#
# The node:sqlite migration (§4) means the repo has zero native addons, so every
# `npm install` below is pure-JS — install cannot fail on compilation.
#
# Options:
#   --no-typecheck        skip the per-package typecheck pass (faster)
#   --bin-dir=DIR         where to write the `mandu` shim (default:
#                         $MANDU_BIN_DIR or ~/.local/bin)
#   --no-shim             install deps only; don't write the shim
#   -h | --help           this help
#
# Idempotent: safe to re-run (npm install is incremental; the shim is rewritten).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/paths/mandu-paths.sh
. "$REPO_ROOT/scripts/paths/mandu-paths.sh"

# ── options ──────────────────────────────────────────────────────────────────
BIN_DIR="$(mandu_path bin-dir)"
DO_TYPECHECK=1
DO_SHIM=1
for arg in "$@"; do
  case "$arg" in
    --no-typecheck) DO_TYPECHECK=0 ;;
    --no-shim)      DO_SHIM=0 ;;
    --bin-dir=*)    BIN_DIR="${arg#*=}" ;;
    -h|--help)      sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "bootstrap: unknown option '$arg' (try --help)" >&2; exit 2 ;;
  esac
done

# Minor colour helpers (no-op when not a tty).
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; Z=$'\033[0m'; else B=; G=; Y=; R=; Z=; fi
info() { printf '%s\n' "$*"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$Z" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$Z" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$R" "$Z" "$*"; }

# ── preflight: Node ≥ 22.13.0 (node:sqlite floor), git (required), claude (optional) ─
# NODE_FLOOR is pinned to launcher/src/node-floor.ts by launcher/test/unit/node-floor.test.ts.
NODE_FLOOR="22.13.0"
info "${B}Mandu bootstrap${Z} — repo: $REPO_ROOT"
info ""
info "${B}Prerequisites${Z}"

if ! command -v node >/dev/null 2>&1; then
  bad "node not found — install Node ≥ $NODE_FLOOR (nvm install 22)"; exit 1
fi
NODE_VER="$(node -p 'process.versions.node' 2>/dev/null || echo 0.0.0)"
# Compare major.minor.patch numerically (a major-only check admitted 22.0–22.12,
# where node:sqlite is still behind a flag and the arbiter dies at import).
node_meets_floor() {
  local IFS=.; local -a v=($1) f=($2); local i
  for i in 0 1 2; do
    [ "${v[$i]:-0}" -gt "${f[$i]:-0}" ] 2>/dev/null && return 0
    [ "${v[$i]:-0}" -lt "${f[$i]:-0}" ] 2>/dev/null && return 1
  done
  return 0
}
if ! node_meets_floor "$NODE_VER" "$NODE_FLOOR"; then
  bad "node $NODE_VER is too old — Mandu needs Node ≥ $NODE_FLOOR (node:sqlite is unflagged from 22.13). Try: nvm install 22"
  exit 1
fi
ok "node $NODE_VER (≥ $NODE_FLOOR)"

if ! command -v npm >/dev/null 2>&1; then bad "npm not found (ships with Node)"; exit 1; fi
ok "npm $(npm --version)"

if command -v git >/dev/null 2>&1; then ok "git $(git --version | awk '{print $3}')"; else
  warn "git not found — the fs-view dual-view worktrees need it; mandu will degrade loudly to raw CWD without it"
fi

if command -v claude >/dev/null 2>&1; then ok "claude present ($(command -v claude))"; else
  warn "claude not on PATH — install it (npm i -g @anthropic-ai/claude-code) to run 'mandu claude'"
fi

# ── install + typecheck every TS package ─────────────────────────────────────
# Authoritative list mirrors scripts/test-all.sh (the npm_suite rows) + launcher.
PKGS=(
  arbiter
  interceptors/anthropic-proxy
  interceptors/openai-proxy
  interceptors/net-proxy
  interceptors/cdp-relay
  interceptors/inspect-mcp
  interceptors/policy-mcp
  interceptors/exec-wrap
  interceptors/reply-filter
  fs-sync
  dashboard
  tests
  tests/conformance
  launcher
)

info ""
info "${B}Installing dependencies${Z} (${#PKGS[@]} packages, pure-JS — no native build)"
INSTALL_FAIL=()
for pkg in "${PKGS[@]}"; do
  dir="$REPO_ROOT/$pkg"
  if [ ! -f "$dir/package.json" ]; then warn "$pkg — no package.json, skipping"; continue; fi
  if ( cd "$dir" && npm install --no-audit --no-fund >/dev/null 2>&1 ); then
    ok "$pkg"
  else
    bad "$pkg — npm install failed"; INSTALL_FAIL+=("$pkg")
  fi
done

TYPECHECK_FAIL=()
if [ "$DO_TYPECHECK" -eq 1 ]; then
  info ""
  info "${B}Typechecking${Z}"
  for pkg in "${PKGS[@]}"; do
    dir="$REPO_ROOT/$pkg"
    [ -f "$dir/package.json" ] || continue
    # Only packages that declare a typecheck script (all TS packages do today).
    if ! node -e "process.exit(require('$dir/package.json').scripts?.typecheck?0:1)" 2>/dev/null; then
      warn "$pkg — no typecheck script, skipping"; continue
    fi
    if ( cd "$dir" && npm run typecheck >/dev/null 2>&1 ); then
      ok "$pkg"
    else
      bad "$pkg — typecheck failed (run: cd $pkg && npm run typecheck)"; TYPECHECK_FAIL+=("$pkg")
    fi
  done
fi

# ── the launcher bundle (packaging.md §5.1) ─────────────────────────────────
# Best effort: without it the first launch builds it (or runs from source).
if [[ " ${INSTALL_FAIL[*]-} " != *" launcher "* ]]; then  # `-`: bash 3.2 (macOS) calls an empty array unbound under set -u
  info ""
  info "${B}Building the launcher bundle${Z}"
  if ( cd "$REPO_ROOT/launcher" && node scripts/build-bundle.mjs --if-stale --no-native --quiet ); then
    ok "launcher/dist"
  else
    warn "launcher bundle build failed — mandu runs from source until it builds (cd launcher && npm run build:bundle)"
  fi
fi

# ── the `mandu` shim ───────────────────────────────────────────────────────
# Hands off to launcher/mandu-run.sh, which loads secrets.local.json into the
# environment (scripts/secrets-to-env.mjs, in the launcher's own node for a
# bundled launch: OPENAI_API_KEY for `mandu codex`, MANDU_ULLM_* for the
# quarantine; packaging.md §5.1) and then runs the checkout's fresh bundle,
# or the TS launcher from source with the launcher's LOCAL tsx, so no global
# tsx is required. Until 2026-09-24
# the shim ran tsx directly and skipped that step: `mandu codex` started
# with no OPENAI_API_KEY unless the shell had exported one by hand.
SHIM="$BIN_DIR/mandu"
if [ "$DO_SHIM" -eq 1 ]; then
  info ""
  info "${B}Installing the mandu shim${Z}"
  mkdir -p "$BIN_DIR"
  cat > "$SHIM" <<EOF
#!/usr/bin/env bash
# Mandu launcher shim (generated by scripts/bootstrap.sh — M1 interim channel).
# Runs the checkout's launcher through launcher/mandu-run.sh (loads
# secrets.local.json, then the fresh prebuilt bundle or the local tsx).
set -euo pipefail
REPO_ROOT="$REPO_ROOT"
RUNSH="\$REPO_ROOT/launcher/mandu-run.sh"
TSX="\$REPO_ROOT/launcher/node_modules/.bin/tsx"
if [ ! -x "\$TSX" ]; then
  echo "mandu: launcher tsx missing (\$TSX) — re-run scripts/bootstrap.sh" >&2
  exit 1
fi
exec bash "\$RUNSH" "\$@"
EOF
  chmod +x "$SHIM"
  ok "wrote $SHIM"
fi

# ── doctor-style summary ─────────────────────────────────────────────────────
info ""
info "${B}Summary${Z}"
if [ "${#INSTALL_FAIL[@]}" -gt 0 ]; then bad "install failed: ${INSTALL_FAIL[*]}"; fi
if [ "${#TYPECHECK_FAIL[@]}" -gt 0 ]; then bad "typecheck failed: ${TYPECHECK_FAIL[*]}"; fi

if [ "$DO_SHIM" -eq 1 ]; then
  case ":$PATH:" in
    *":$BIN_DIR:"*) ok "$BIN_DIR is on PATH — run: mandu claude" ;;
    *) warn "$BIN_DIR is NOT on PATH. Add it, e.g.:"
       info "      echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
       info "    Then: mandu claude" ;;
  esac
else
  info "  (shim skipped) run directly: launcher/node_modules/.bin/tsx launcher/src/run.ts claude"
fi

info ""
info "Next: ${B}mandu claude${Z}  (everything auto-starts — arbiter, proxies, fs-view, reply-filter)."
info "Note: this is the interim from-source channel; the bundled npm package (@mandusec/mandu) is M2/M5."

# Fail the script if anything hard-failed, so CI / callers can gate on it.
if [ "${#INSTALL_FAIL[@]}" -gt 0 ] || [ "${#TYPECHECK_FAIL[@]}" -gt 0 ]; then exit 1; fi
