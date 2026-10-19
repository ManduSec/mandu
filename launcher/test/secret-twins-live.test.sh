#!/usr/bin/env bash
# secret-twins-live.test.sh — THE money test for confidentiality plan 4′.
#
# Proves the §7.2 invariant on real infrastructure (a real arbiter, a real
# bwrap sandbox, a real credential file):
#
#   RAW SECRET BYTES NEVER EXIST INSIDE THE AGENT'S WORLD.
#
#   1. Inside the sandbox, reading the secret path yields the SYMBOL.
#   2. The raw bytes are absent from the sandbox's view (grep finds nothing) —
#      including through the exfil idiom `cat <secret> | …`, which sends a token.
#   3. Outside the sandbox the real file is INTACT. We masked a VIEW, not the
#      disk; a destructive bug here would eat the user's credentials, so this is
#      asserted explicitly.
#   4. The arbiter still holds the original (the defense is reversible at a
#      trusted boundary — the egress gate substitutes it at a bound destination).
#
# Skips cleanly (exit 0) where bwrap / unprivileged userns are unavailable.
#
# Run: bash launcher/test/secret-twins-live.test.sh
set -uo pipefail
# This suite STATES its axes (docs/design/architecture/protection-modes.md §4): the arbiter it
# spawns and the launcher it runs both read these, so a change of the built-in
# default can never quietly change what the suite proves. STRICT makes an
# unstated axis a startup error in the arbiter. `secrets`, the product default
# (test-organization.md §7.3): every check here is the confidentiality axis's;
# it pinned `full` incidentally until 2026-09-29.
export MANDU_AXES_STRICT=1 MANDU_INTEGRITY=0 MANDU_CONFIDENTIALITY=1
# No host policy file (the runner sets the same; a hand run must not read one).
export MANDU_POLICY_FILE="${MANDU_POLICY_FILE:-/dev/null/mandu-test-no-policy.yaml}"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()   { echo "  ok — $1"; PASS=$((PASS+1)); }
bad()  { echo "  NOT OK — $1"; FAIL=$((FAIL+1)); }
skip() { echo "secret-twins-live.test.sh: SKIP ($1)"; echo "1 skipped, 0 failed"; exit 0; }

command -v bwrap >/dev/null 2>&1 || skip "bwrap not installed"
unshare --user --map-root-user --mount -- true >/dev/null 2>&1 \
  || skip "unprivileged user namespaces unavailable"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-twins-live.XXXXXX")"
# The Mandu home: a temp one under $WORK with no config.toml, so no host
# ~/.mandu/config.toml is read (the 7cdfc2c e2e rule) and nothing lands in the
# real home; the arbiter and every launch below inherit it.
export MANDU_HOME="$WORK/mandu-home"
# The runtime base (the instance registry, the human-plane socket): the
# suite's own, never the caller's $XDG_RUNTIME_DIR/mandu, also when the suite
# is killed (test-organization.md §8.5).
export MANDU_RUNTIME_DIR="$WORK/rt"
cleanup() {
  # Its own process group (setsid, below), stopped AND waited for: a plain
  # kill reached only npx, and the arbiter went on shutting down past the
  # suite with $WORK removed under it (test-organization.md §8.5).
  [[ -n "${ARB_PID:-}" ]] && mdu_stop_group "$ARB_PID"
  rm -rf "$WORK"
}
trap cleanup EXIT
# Lifeline backstop (lib/lifeline.sh): the trap is the graceful teardown; the
# lifeline reaps the arbiter when this shell dies WITHOUT it (SIGKILL/abandoned
# hang — the way this exact suite orphaned two 16h arbiters on 2026-07-14).
source "$(dirname "${BASH_SOURCE[0]}")/lib/lifeline.sh"
mdu_lifeline_init "$WORK"

# ── a fake HOME with a real-looking credential ───────────────────────────────
HOME_DIR="$WORK/home"; mkdir -p "$HOME_DIR/.aws"
SECRET_PATH="$HOME_DIR/.aws/credentials"
RAW='aws_secret_access_key=SUPERSECRET_LIVE_CANARY_42'
printf '[default]\n%s\n' "$RAW" > "$SECRET_PATH"
CANARY="SUPERSECRET_LIVE_CANARY_42"

# ── a real arbiter with the confidentiality axis ON ──────────────────────────
SOCK="$WORK/arbiter.sock"
cd "$REPO/arbiter"
setsid env MANDU_ARBITER_SOCK="$SOCK" \
  MANDU_HOME="$MANDU_HOME" \
  MANDU_CONFIDENTIALITY=1 \
  MANDU_LIFELINE=stdin \
  npx tsx ipc/server-main.ts "$SOCK" <"$MANDU_LIFELINE_FIFO" 9>&- >"$WORK/arbiter.log" 2>&1 &
ARB_PID=$!
for _ in $(seq 1 50); do [[ -S "$SOCK" ]] && break; sleep 0.2; done
[[ -S "$SOCK" ]] || { cat "$WORK/arbiter.log"; skip "arbiter did not start"; }

# ── register the secret (the ARBITER reads it — this script never passes bytes)
call() { printf '%s\n' "$1" | timeout 10 nc -U -q1 "$SOCK" 2>/dev/null | head -1; }
# The ops that return originals answer only on the arbiter's human plane
# (docs/design/architecture/arbiter-human-plane.md); its path comes from `hello`, as the
# launcher learns it. The data socket refuses them.
HELLO="$(call '{"id":0,"op":"hello"}')"
HUMAN_SOCK="$(printf '%s' "$HELLO" | sed -n 's/.*"humanSock":"\([^"]*\)".*/\1/p')"
hcall() { printf '%s\n' "$1" | timeout 10 nc -U -q1 "$HUMAN_SOCK" 2>/dev/null | head -1; }
REG="$(call "{\"id\":1,\"op\":\"registerSecret\",\"path\":\"$SECRET_PATH\"}")"
SYMBOL="$(printf '%s' "$REG" | sed -n 's/.*"symbol":"\([^"]*\)".*/\1/p')"

if [[ -z "$SYMBOL" ]]; then
  echo "registerSecret returned: $REG"
  skip "could not register the secret (nc -U unavailable?)"
fi
echo "secret-twins-live: registered $SECRET_PATH → $SYMBOL"
# The confidentiality axis is what minted it: a no-model symbol, not a
# placeholder some other path produced (a quiet axis must fail here).
[[ "$SYMBOL" == '$MDU:nomodel_'* ]] \
  && ok "the registered credential's symbol carries the no-model level ($SYMBOL)" \
  || bad "expected a \$MDU:nomodel_ symbol from registerSecret, got: $SYMBOL"

# ── build the twin exactly as the launcher does ──────────────────────────────
TWIN="$WORK/twin"; printf '%s\n' "$SYMBOL" > "$TWIN"

# The same hardening flags the launcher's planSecretTwins now emits, so this
# live proof exercises the real production wrap (see secret-twins.ts).
HARDEN=(--cap-drop ALL --unshare-ipc --unshare-uts)

# ── (1) inside the sandbox: the read yields the SYMBOL ───────────────────────
INSIDE="$(bwrap --dev-bind / / --die-with-parent "${HARDEN[@]}" --bind "$TWIN" "$SECRET_PATH" -- \
  /bin/sh -c "cat '$SECRET_PATH'" 2>/dev/null)"
[[ "$INSIDE" == "$SYMBOL" ]] \
  && ok "inside the sandbox the secret path reads as the SYMBOL ($SYMBOL)" \
  || bad "expected the symbol inside the sandbox, got: $INSIDE"

# ── (2) the raw bytes are ABSENT from the agent's world ──────────────────────
if bwrap --dev-bind / / --die-with-parent "${HARDEN[@]}" --bind "$TWIN" "$SECRET_PATH" -- \
     /bin/sh -c "grep -q '$CANARY' '$SECRET_PATH'" 2>/dev/null; then
  bad "RAW SECRET BYTES VISIBLE INSIDE THE SANDBOX — the invariant is broken"
else
  ok "raw secret bytes are absent from the sandbox's view (the §7.2 invariant)"
fi

# the canonical exfil idiom now pipes a TOKEN, not a key
EXFIL="$(bwrap --dev-bind / / --die-with-parent "${HARDEN[@]}" --bind "$TWIN" "$SECRET_PATH" -- \
  /bin/sh -c "cat '$SECRET_PATH' | tr -d '\n'" 2>/dev/null)"
[[ "$EXFIL" != *"$CANARY"* ]] \
  && ok "\`cat <secret> | …\` (the exfil idiom) carries a token, not the key" \
  || bad "the exfil idiom leaked the raw key"

# ── (3) OUTSIDE the sandbox the real file is INTACT (we masked a view, not the disk)
grep -q "$CANARY" "$SECRET_PATH" \
  && ok "outside the sandbox the real credential file is INTACT (non-destructive)" \
  || bad "THE REAL SECRET FILE WAS DESTROYED — catastrophic"

# ── (4) the arbiter still holds the original (reversible at a trusted boundary)
HUMAN="$(hcall "{\"id\":2,\"op\":\"desymbolize\",\"text\":\"key: $SYMBOL\"}")"
[[ "$HUMAN" == *"$CANARY"* ]] \
  && ok "the arbiter still holds the original (HumanView desymbolize reveals it)" \
  || bad "the arbiter lost the original bytes"
# ...and only over the human plane: the data socket the agent's tools reach refuses it.
DATA_DESYM="$(call "{\"id\":6,\"op\":\"desymbolize\",\"text\":\"key: $SYMBOL\"}")"
[[ "$DATA_DESYM" != *"$CANARY"* && "$DATA_DESYM" == *'"ok":false'* ]] \
  && ok "desymbolize on the DATA socket is refused (arbiter-human-plane.md)" \
  || bad "the data socket answered desymbolize: $DATA_DESYM"

# ...but the U-LLM path must NOT get it (plan 2: the quarantine is an egress)
ULLM="$(call "{\"id\":3,\"op\":\"resolve\",\"symbol\":\"$SYMBOL\",\"deep\":true}")"
[[ "$ULLM" == *'"value":null'* ]] \
  && ok "the quarantined U-LLM resolve REFUSES the secret (plan 2 composition)" \
  || bad "the U-LLM deep resolve returned the secret: $ULLM"

# ── (5) the STRUCTURED twin (plan 10 §2.4): keys stay, values are field symbols
json_field() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);const v=(j.result||{})[process.argv[1]];process.stdout.write(v==null?"":String(v))})' "$1"; }
STWIN_TEXT="$(printf '%s' "$REG" | json_field twin)"
if [[ -z "$STWIN_TEXT" ]]; then
  bad "registerSecret returned no structured twin for an INI credentials file: $REG"
else
  STWIN="$WORK/stwin"; printf '%s' "$STWIN_TEXT" > "$STWIN"
  S_INSIDE="$(bwrap --dev-bind / / --die-with-parent "${HARDEN[@]}" --bind "$STWIN" "$SECRET_PATH" -- \
    /bin/sh -c "cat '$SECRET_PATH'" 2>/dev/null)"
  [[ "$S_INSIDE" == *"[default]"* && "$S_INSIDE" == *"aws_secret_access_key=\$MDU:nomodel_Read["*".default.aws_secret_access_key"* && "$S_INSIDE" != *"$CANARY"* ]] \
    && ok "the structured twin keeps the INI structure and masks only the value (no canary inside)" \
    || bad "structured twin inside the sandbox reads wrong: $S_INSIDE"
fi

# ── (6) a dotenv the agent SOURCES: benign values raw, secrets as tokens ──────
WS="$HOME_DIR/ws"; mkdir -p "$WS"
DOTENV="$WS/.env"; CANARY2="DOTENV_LIVE_CANARY_7731"
printf 'PORT=3000\nAPI_KEY=%s\nDATABASE_URL=postgres://app:pw_%s@db:5432/prod\n' "$CANARY2" "$CANARY2" > "$DOTENV"
REG2="$(call "{\"id\":4,\"op\":\"registerSecret\",\"path\":\"$DOTENV\"}")"
DTWIN_TEXT="$(printf '%s' "$REG2" | json_field twin)"
if [[ -z "$DTWIN_TEXT" ]]; then
  bad "registerSecret returned no structured twin for a dotenv: $REG2"
else
  DTWIN="$WORK/dtwin"; printf '%s' "$DTWIN_TEXT" > "$DTWIN"
  SOURCED="$(bwrap --dev-bind / / --die-with-parent "${HARDEN[@]}" --bind "$DTWIN" "$DOTENV" -- \
    /bin/sh -c "cd '$WS' && . ./.env && echo \"port=\$PORT key=\$API_KEY url=\$DATABASE_URL\"" 2>&1)"
  [[ "$SOURCED" == *"port=3000"* && "$SOURCED" == *"key=\$MDU:nomodel_Read["*".API_KEY"* && "$SOURCED" == *"url=postgres://app:\$MDU:nomodel_Read["*".DATABASE_URL.password@db:5432/prod"* && "$SOURCED" != *"$CANARY2"* ]] \
    && ok "\`. ./.env\` works inside the sandbox: PORT raw, API_KEY a token, only the URL password masked" \
    || bad "sourcing the dotenv twin gave: $SOURCED"
  # the field token resolves to exactly its value for the human, never the whole file
  FIELD="$(printf '%s' "$DTWIN_TEXT" | sed -n "s/^API_KEY='\(.*\)'$/\1/p")"
  HUMAN2="$(hcall "{\"id\":5,\"op\":\"desymbolize\",\"text\":\"k: $FIELD\"}")"
  [[ "$HUMAN2" == *"k: $CANARY2"* && "$HUMAN2" != *"PORT=3000"* ]] \
    && ok "a field token desymbolizes to its own value only" \
    || bad "field token desymbolize: $HUMAN2"
fi

echo "secret-twins-live.test.sh: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] || exit 1
