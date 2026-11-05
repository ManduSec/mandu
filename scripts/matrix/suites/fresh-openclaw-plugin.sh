#!/usr/bin/env bash
# deps:
# min-timeout: 3600
# fresh-openclaw-plugin — a fresh guest, a fresh OpenClaw run the way its own
# docs say (nvm Node, `npm install -g openclaw`, non-interactive onboarding,
# the Gateway as a systemd user service), then Mandu from a copy of the
# checkout (docs/development.md §1: scripts/bootstrap.sh, never a packed
# tarball: the plugin ships only in a checkout) attached to that Gateway the
# way docs/usage.md says for "OpenClaw running as a service": `mandu serve
# install`, `mandu openclaw install`, `openclaw gateway restart`, `mandu
# doctor` (docs/design/testing/os-test-matrix.md §10.20;
# docs/design/agents/openclaw-plugin.md). Runs as root in the guest (the matrix
# contract); every product step runs as the ordinary user `alice`, under her
# REAL systemd user manager (linger on), via runuser.
#
# The model is fresh-agents/fake-model.mjs `--script attach` on loopback,
# behind Mandu's service proxy (the proxy's upstream, set by a drop-in on
# mandu.service; OpenClaw's own Anthropic provider is left as onboarding wrote
# it, with no address of its own, so the install records Anthropic's built-in
# address and the service's drop-in decides it: openclaw-plugin.md §8.1). One
# Gateway turn: the read of a planted
# credential file, a tool call naming ~/.mandu, a reply quoting the read's
# placeholder. No key, no live model, nothing on the host.
#
# Until `mandu serve` runs the proxy pool (openclaw-plugin.md §3.2; `mandu
# serve status` then has an `attached:` line), the leg stops where `mandu
# openclaw install` must refuse for lack of a service proxy, asserts that it
# wrote nothing, skips the Gateway turn with a PENDING note, and still checks
# scan, uninstall and the service's removal.
set -uo pipefail
# shellcheck source=scripts/paths/mandu-paths.sh
. "$(dirname "${BASH_SOURCE[0]}")/../../paths/mandu-paths.sh"

ART=/mnt/artifacts
STEPLOG=/mnt/out/steps.log
FAILS=0
: > "$STEPLOG" 2>/dev/null || STEPLOG=/tmp/steps.log
CANARY=FRESHOCPLUGINCANARY0123456789abcdef

step() { echo; echo "──── step $1: $2"; CUR="$1"; }
pass() { echo "  PASS  $1"; echo "PASS step=$CUR $1" >> "$STEPLOG"; }
fail() { echo "  FAIL  $1"; echo "FAIL step=$CUR $1" >> "$STEPLOG"; FAILS=$((FAILS+1)); }
note() { echo "  note  $1"; echo "NOTE step=$CUR $1" >> "$STEPLOG"; }
show() { sed 's/^/        | /' "$1" | head -"${2:-40}"; }
# npm_global <out file> <spec>: npm install -g as alice, tried again (at most
# 3 times) only when the registry connection broke (2026-11-04: an ECONNRESET
# reading openclaw from npm failed a run); any other failure stands. Sets rc.
npm_global() {
  local try
  for try in 1 2 3; do
    as_alice "npm install -g --no-audit --no-fund '$2'" > "$1" 2>&1; rc=$?
    [[ $rc -ne 0 ]] && grep -Eq 'npm error code (ECONNRESET|ETIMEDOUT|EAI_AGAIN|ECONNREFUSED|EPIPE)' "$1" && (( try < 3 )) || return 0
    note "npm install -g $2: the registry connection broke (try $try of 3): $(grep -Eo 'npm error code [A-Z_]+' "$1" | head -1)"
    sleep 10
  done
}
expect_out() {
  if grep -Eq -- "$2" "$3"; then pass "$1"; else fail "$1 (wanted /$2/)"; show "$3"; fi
}
expect_no() {
  if grep -Eq -- "$2" "$3"; then fail "$1 (found /$2/)"; show "$3"; else pass "$1"; fi
}
expect_rc() {  # expect_rc <label> <wanted rc> <got rc> <output file>
  if [[ "$3" == "$2" ]]; then pass "$1 (rc=$3)"; else fail "$1 (rc=$3, wanted $2)"; show "$4" 30; fi
}

# The guest runner's copy of the checkout (cwd; qemu.sh copies the share and
# the commit's one-commit .git). alice gets a copy of her own, as a user who
# cloned it; root's stays out of her reach.
SRC="$PWD"
umount /mnt/reposrc 2>/dev/null || true
chmod 0700 /root

useradd -m -s /bin/bash alice
UIDA="$(id -u alice)"
RUNA="/run/user/$UIDA"
install -o alice -g alice -m 0755 -d /home/alice/legs
install -o alice -g alice -m 0644 "$ART/fake-model.mjs" /home/alice/legs/
# alice's event dir: the path table's `events` for her home (her login sets no
# MANDU_HOME, so root drops its own before resolving).
ALICE_EVENTS="$(unset MANDU_HOME; mandu_path events /home/alice)"
# A login shell with her nvm Node, ~/.local/bin (bootstrap's shim) and her user
# manager's bus (runuser opens no logind session, so the two variables are set
# here, as a desktop login would have them).
as_alice() {
  runuser -l alice -c "export XDG_RUNTIME_DIR=$RUNA DBUS_SESSION_BUS_ADDRESS=unix:path=$RUNA/bus; \
export PATH=\$HOME/.local/bin:\$PATH NVM_DIR=\$HOME/.nvm; [ -s \$NVM_DIR/nvm.sh ] && . \$NVM_DIR/nvm.sh; cd \$HOME; $*"
}
OC_CONFIG=/home/alice/.openclaw/openclaw.json
# The config as onboarding left it: root's copy, which alice can read (canon
# runs her node) and not change.
PRE=/var/lib/mandu-vm/openclaw.pre-install.json
install -d -m 0755 /var/lib/mandu-vm
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
# canon <file>: the JSON with sorted keys, one per line (for a diff).
canon() {
  as_alice "node -e '
    const s = (v) => Array.isArray(v) ? v.map(s) : v && typeof v === \"object\" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, s(v[k])])) : v;
    process.stdout.write(JSON.stringify(s(JSON.parse(require(\"fs\").readFileSync(process.argv[1], \"utf8\"))), null, 2) + \"\\n\");' $1"
}

# ── step 0: baseline facts ───────────────────────────────────────────────────
step 0 "baseline facts"
OC_VERSION="$(cat "$ART/OPENCLAW_VERSION" 2>/dev/null || echo latest)"
NODE_MAJOR="$(cat "$ART/NODE_MAJOR" 2>/dev/null || echo 24)"
echo "  commit under test: $(cat "$ART/COMMIT" 2>/dev/null)"
echo "  os: $(. /etc/os-release; echo "$PRETTY_NAME")  kernel: $(uname -r)  systemd: $(systemctl --version | head -1)"
echo "  openclaw: $OC_VERSION  node: $NODE_MAJOR"
pass "recorded"

# ── step 1: node + OpenClaw, onboarded the way its docs say ──────────────────
step 1 "node $NODE_MAJOR via nvm, npm install -g openclaw@$OC_VERSION, non-interactive onboarding"
as_alice "curl -fsSo- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash >/dev/null 2>&1; . \$HOME/.nvm/nvm.sh; nvm install $NODE_MAJOR >/dev/null 2>&1; node --version" > /tmp/node.out 2>&1
expect_out "node $NODE_MAJOR installed under alice's HOME" "^v$NODE_MAJOR\\." /tmp/node.out
t0=$(date +%s)
npm_global /tmp/install-openclaw.out "openclaw@$OC_VERSION"
as_alice 'openclaw --version' > /tmp/version-openclaw.out 2>&1
if [[ $rc -eq 0 ]] && grep -Eq '[0-9]{4}\.[0-9]+\.[0-9]+' /tmp/version-openclaw.out; then
  pass "openclaw@$OC_VERSION installed: $(grep -Eo '[0-9]{4}\.[0-9]+\.[0-9]+' /tmp/version-openclaw.out | head -1) ($(( $(date +%s) - t0 ))s)"
else
  fail "openclaw@$OC_VERSION did not install (rc=$rc)"; tail -15 /tmp/install-openclaw.out | sed 's/^/        | /'
fi
# OpenClaw's scripted setup (docs/start/wizard-cli-automation.md, its Anthropic
# API key example): a local Gateway on loopback, the key a dummy, the daemon
# left for step 4 (`openclaw gateway install`), no model call.
as_alice 'openclaw onboard --non-interactive --accept-risk --mode local --auth-choice apiKey \
  --anthropic-api-key sk-ant-dummy-mandu-vm --secret-input-mode plaintext --gateway-bind loopback \
  --skip-daemon --skip-health --skip-skills </dev/null' > /tmp/onboard.out 2>&1; rc=$?
expect_rc "openclaw onboard --non-interactive" 0 "$rc" /tmp/onboard.out
if [[ -s "$OC_CONFIG" ]]; then
  pass "onboarding wrote $OC_CONFIG"
  install -m 0644 "$OC_CONFIG" "$PRE"
  # What onboarding chose: the primary model and whether Anthropic calls
  # already have an endpoint of their own (they must not, for the install).
  as_alice "node -e '
    const c = JSON.parse(require(\"fs\").readFileSync(process.argv[1], \"utf8\"));
    const m = c.agents?.defaults?.model; const p = typeof m === \"string\" ? m : m?.primary;
    console.log(\"primary=\" + p);
    console.log(\"fallbacks=\" + JSON.stringify(typeof m === \"object\" ? m?.fallbacks ?? [] : []));
    console.log(\"anthropicBaseUrl=\" + (c.models?.providers?.anthropic?.baseUrl ?? \"none\"));
    console.log(\"toolsProfile=\" + (c.tools?.profile ?? \"none\"));
    console.log(\"keys=\" + Object.keys(c).join(\",\"));' $OC_CONFIG" > /tmp/onboard-facts.out 2>&1
  show /tmp/onboard-facts.out
  expect_out "onboarding chose an Anthropic model" '^primary=anthropic/' /tmp/onboard-facts.out
  expect_out "Anthropic calls have no endpoint of their own yet" '^anthropicBaseUrl=none$' /tmp/onboard-facts.out
else
  fail "no $OC_CONFIG after onboarding"; show /tmp/onboard.out
fi

# ── step 2: the user's secret ────────────────────────────────────────────────
step 2 "a credential file in alice's HOME"
as_alice "mkdir -p ~/.aws && printf '[default]\naws_access_key_id = AKIAFRESHOCPLUGIN\naws_secret_access_key = $CANARY\n' > ~/.aws/credentials && chmod 600 ~/.aws/credentials"
[[ -s /home/alice/.aws/credentials ]] && pass "planted ~/.aws/credentials (canary $CANARY)" || fail "could not plant ~/.aws/credentials"

# ── step 3: Mandu from the checkout, and its service ─────────────────────────
step 3 "Mandu from a copy of the checkout (scripts/bootstrap.sh), then mandu serve install under alice's systemd user manager"
rsync -a "$SRC/" /home/alice/mandu/ && chown -R alice:alice /home/alice/mandu \
  && pass "copied the checkout to ~/mandu ($(git -C /home/alice/mandu rev-parse --short HEAD 2>/dev/null || echo 'no .git'))" \
  || fail "could not copy the checkout"
t0=$(date +%s)
as_alice 'cd ~/mandu && scripts/bootstrap.sh </dev/null' > /tmp/bootstrap.out 2>&1; rc=$?
expect_rc "scripts/bootstrap.sh ($(( $(date +%s) - t0 ))s)" 0 "$rc" /tmp/bootstrap.out
grep -E '✗|!' /tmp/bootstrap.out | sed 's/^/        | /' | head -10
as_alice 'mandu --version' > /tmp/version.out 2>&1 && pass "mandu --version: $(head -1 /tmp/version.out)" || { fail "mandu --version"; show /tmp/version.out; }

loginctl enable-linger alice
for _ in $(seq 60); do [[ -S "$RUNA/bus" ]] && break; sleep 1; done
[[ -S "$RUNA/bus" ]] && pass "linger on: alice's user manager runs ($RUNA/bus)" || fail "no user manager bus at $RUNA/bus after enable-linger"

# The scripted model, where api.anthropic.com would be for Mandu's service
# proxy. Started detached so it outlives each runuser.
as_alice "setsid nohup node ~/legs/fake-model.mjs --agent openclaw --script attach --file \$HOME/.aws/credentials \
  --capture ~/legs/capture.ndjson --port-file ~/legs/port > ~/legs/fake-model.log 2>&1 < /dev/null &"
for _ in $(seq 50); do [[ -s /home/alice/legs/port ]] && break; sleep 0.2; done
FAKE_PORT="$(cat /home/alice/legs/port 2>/dev/null)"
[[ -n "$FAKE_PORT" ]] && pass "scripted model on 127.0.0.1:$FAKE_PORT" || fail "the scripted model did not start"
# The service proxy's upstream: a drop-in on the unit `mandu serve install`
# writes (the stand-in for api.anthropic.com; a user changes nothing here).
as_alice "mkdir -p ~/.config/systemd/user/mandu.service.d && printf '[Service]\nEnvironment=MANDU_UPSTREAM=http://127.0.0.1:$FAKE_PORT\n' > ~/.config/systemd/user/mandu.service.d/upstream.conf"

as_alice 'mandu serve install </dev/null' > /tmp/serve-install.out 2>&1; rc=$?
echo "  mandu serve install:"; show /tmp/serve-install.out 20
expect_rc "mandu serve install" 0 "$rc" /tmp/serve-install.out
as_alice 'systemctl --user is-active mandu.service' > /tmp/serve-active.out 2>&1
expect_out "mandu.service is active in alice's user manager" '^active$' /tmp/serve-active.out
as_alice 'mandu serve status </dev/null' > /tmp/serve-status.out 2>&1; rc=$?
echo "  mandu serve status:"; show /tmp/serve-status.out 30
expect_rc "mandu serve status" 0 "$rc" /tmp/serve-status.out
expect_out "the service reports running" '^Mandu service \(mandu serve\): running' /tmp/serve-status.out

# ── step 4: mandu openclaw install, the Gateway as a service, doctor ─────────
POOL=0; grep -q '^  attached:' /tmp/serve-status.out && POOL=1
step 4 "mandu openclaw install; openclaw gateway install/start/restart; mandu doctor"
sha_before="$(sha "$OC_CONFIG")"
as_alice 'mandu openclaw install </dev/null' > /tmp/oc-install.out 2>&1; rc=$?
echo "  mandu openclaw install:"; show /tmp/oc-install.out 20
backups() { ls /home/alice/.openclaw/openclaw.json.mandu-backup-* 2>/dev/null; }
if [[ $POOL -eq 0 ]]; then
  note "PENDING: mandu serve has no proxy pool yet (no 'attached:' line in its status; openclaw-plugin.md §3.2): the install must refuse, and the Gateway turn waits for the pool"
  expect_rc "mandu openclaw install refuses without a service proxy" 1 "$rc" /tmp/oc-install.out
  expect_out "the refusal names the missing service proxy and the fix" "service proxy for openclaw:main is not running.*mandu serve start" /tmp/oc-install.out
  expect_out "the refusal says nothing was written" "Nothing was written" /tmp/oc-install.out
  [[ "$(sha "$OC_CONFIG")" == "$sha_before" ]] && pass "openclaw.json is byte for byte as onboarding left it" || fail "openclaw.json changed although the install refused"
  [[ -z "$(backups)" ]] && pass "no backup file was made" || fail "a refused install left a backup: $(backups)"
else
  expect_rc "mandu openclaw install" 0 "$rc" /tmp/oc-install.out
  b="$(backups | head -1)"
  if [[ -n "$b" ]] && cmp -s "$b" "$PRE"; then pass "the backup ($b) is the config as onboarding left it"
  else fail "no backup, or the backup differs from the pre-install config ($b)"; fi
  as_alice "node -e '
    const c = JSON.parse(require(\"fs\").readFileSync(process.argv[1], \"utf8\"));
    const e = c.plugins?.entries?.[\"mandu-inspect\"];
    console.log(\"plugin=\" + (e?.enabled === true) + \" attachment=\" + (e?.config?.attachment === true) + \" scope=\" + e?.config?.scopeId);
    console.log(\"loadPaths=\" + JSON.stringify(c.plugins?.load?.paths ?? []));
    console.log(\"baseUrl=\" + c.models?.providers?.anthropic?.baseUrl);' $OC_CONFIG" > /tmp/oc-installed.out 2>&1
  show /tmp/oc-installed.out
  expect_out "the plugin is enabled in attachment mode for openclaw:main" '^plugin=true attachment=true scope=openclaw:main' /tmp/oc-installed.out
  expect_out "Anthropic calls go to a loopback service proxy" '^baseUrl=http://127\.0\.0\.1:[0-9]+' /tmp/oc-installed.out
  # The install declared the session; the pool serves it (status after it).
  as_alice 'mandu serve status </dev/null' > /tmp/serve-status2.out 2>&1
  echo "  mandu serve status (after the install):"; show /tmp/serve-status2.out 30
  expect_out "the status lists the session's proxy, answering and registered" \
    'openclaw:main: proxy on 127\.0\.0\.1:[0-9]+, answering, registered' /tmp/serve-status2.out
  expect_out "the status names the posture and its gap" 'posture: +gated, gap openclaw-plugin' /tmp/serve-status2.out
  expect_out "the status warns that confined launches lose their attestation" 'warning: .*attestation' /tmp/serve-status2.out
  # The route's port is the one the proxy answers on.
  sport="$(grep -Eo 'openclaw:main: proxy on 127\.0\.0\.1:[0-9]+' /tmp/serve-status2.out | grep -Eo '[0-9]+$')"
  grep -q "^baseUrl=http://127.0.0.1:${sport:-none}\$" /tmp/oc-installed.out \
    && pass "the Gateway's route is the pool's proxy (port $sport)" || fail "the route's port is not the pool's proxy (${sport:-none})"
fi

# The Gateway as its own systemd user service (docs/cli/gateway/service.md),
# restarted after the install so it reads the config.
as_alice 'openclaw gateway install </dev/null' > /tmp/gw-install.out 2>&1; rc=$?
expect_rc "openclaw gateway install" 0 "$rc" /tmp/gw-install.out
# gw_healthy <out>: poll `openclaw gateway health` for up to 90 s.
gw_healthy() {
  local _
  for _ in $(seq 45); do
    as_alice 'openclaw gateway health </dev/null' > "$1" 2>&1 && return 0
    sleep 2
  done
  return 1
}
as_alice 'openclaw gateway start </dev/null' > /tmp/gw-start.out 2>&1; rc=$?
expect_rc "openclaw gateway start" 0 "$rc" /tmp/gw-start.out
# A restart before the started Gateway serves is refused by 2026.9.9
# ("GATEWAY_RESTART_PREPARATION_REFUSED: Cannot verify a live serving Gateway
# owner"; the stand-in run of §10.20), so wait for it first, as a user would.
gw_healthy /tmp/gw-health0.out && pass "the started Gateway answers" || { fail "the started Gateway never answered"; show /tmp/gw-health0.out 20; }
as_alice 'openclaw gateway restart </dev/null' > /tmp/gw-restart.out 2>&1; rc=$?
expect_rc "openclaw gateway restart" 0 "$rc" /tmp/gw-restart.out
gw_healthy /tmp/gw-health.out && pass "the restarted Gateway answers (openclaw gateway health)" || { fail "the restarted Gateway never answered"; show /tmp/gw-health.out 20; }
as_alice 'openclaw gateway status </dev/null' > /tmp/gw-status.out 2>&1
echo "  openclaw gateway status:"; show /tmp/gw-status.out 20
as_alice 'systemctl --user list-units --type=service --no-legend' > /tmp/user-units.out 2>&1
echo "  alice's user services:"; show /tmp/user-units.out 10

as_alice 'mandu doctor </dev/null' > /tmp/doctor.out 2>&1
echo "  mandu doctor (the OpenClaw section and the posture lines):"
sed -n '/^OpenClaw service Gateway/,/^$/p' /tmp/doctor.out | sed 's/^/        | /'
grep -Ei 'posture|gated|openclaw-plugin|attestation|attach' /tmp/doctor.out | grep -v '^OpenClaw service Gateway' | sed 's/^/        | /' | head -20
if [[ $POOL -eq 1 ]]; then
  expect_out "doctor: the plugin is enabled" "the Mandu plugin is enabled in .*openclaw\\.json \\(session openclaw:main\\)" /tmp/doctor.out
  # Route 1 (a80b8be44) names every routed provider: "Anthropic, openai calls go ...".
  expect_out "doctor: the route goes through the service proxy" "Anthropic(, [^ ]+)* calls go to Mandu's service proxy" /tmp/doctor.out
  expect_no "doctor: no ✗ in the OpenClaw section" "✗" <(sed -n '/^OpenClaw service Gateway/,/^$/p' /tmp/doctor.out)
  expect_out "doctor: the posture is gated" "gated" /tmp/doctor.out
  expect_out "doctor: the gap is the OpenClaw plugin" "openclaw-plugin|in this OpenClaw Gateway" /tmp/doctor.out
  expect_out "doctor: warns that confined launches lose their attestation" "attestation" /tmp/doctor.out
else
  expect_no "doctor shows no OpenClaw attachment while nothing is installed" "^OpenClaw service Gateway" /tmp/doctor.out
fi

# ── step 5: one turn through the running Gateway ─────────────────────────────
step 5 "one turn through the Gateway: the read, a call naming ~/.mandu, the reply"
CAP=/home/alice/legs/capture.ndjson
if [[ $POOL -eq 0 ]]; then
  note "PENDING: skipped, the Gateway has no Mandu route until the proxy pool lands"
else
  as_alice "timeout 300 openclaw agent --agent main --session-id vm-plugin-$$ --json --timeout 240 \
    -m 'Read the file ~/.aws/credentials with your read tool, then tell me what is in it.' </dev/null" > /tmp/turn.out 2> /tmp/turn.err; rc=$?
  expect_rc "openclaw agent (through the Gateway) finished the turn" 0 "$rc" /tmp/turn.err
  # The capture holds what the model was given, request by request.
  as_alice "node -e '
    const recs = require(\"fs\").readFileSync(process.argv[1], \"utf8\").trim().split(\"\\n\").filter(Boolean).map((l) => JSON.parse(l));
    const by = (k) => recs.find((r) => r.kind === k);
    console.log(\"kinds=\" + recs.map((r) => r.kind ?? \"-\").join(\",\"));
    console.log(\"readResult=\" + JSON.stringify(by(\"tamper-call\")?.toolResults?.[0] ?? null));
    console.log(\"tamperResult=\" + JSON.stringify(by(\"final\")?.toolResults?.[1] ?? null));' $CAP" > /tmp/capture-facts.out 2>&1
  show /tmp/capture-facts.out 12
  expect_out "the model asked for the read, then for ~/.mandu, then answered" '^kinds=.*tool-call.*tamper-call.*final' /tmp/capture-facts.out
  expect_no "the canary is in NO request the model got" "$CANARY" "$CAP"
  # Without the wrapper's file guard the proxy masks the whole file: the
  # model gets one placeholder (`$MDU:nomodel_read[…]`), not the keys.
  expect_out "the read's result reached the model as a \$MDU: placeholder" '^readResult="?\$MDU:' /tmp/capture-facts.out
  # The read really happened (else a masked error text would pass the two
  # checks above): OpenClaw's own local record of the turn, which no model
  # reads, holds the file's raw text.
  grep -rlF "$CANARY" /home/alice/.openclaw/agents > /tmp/oc-transcript-canary.out 2>/dev/null
  [[ -s /tmp/oc-transcript-canary.out ]] && pass "the read really happened: OpenClaw's own record holds the raw file ($(head -1 /tmp/oc-transcript-canary.out))" \
    || fail "no raw read in OpenClaw's own record under ~/.openclaw/agents: the agent never read the file, so the checks above are vacuous"
  expect_out "the plugin refused the tool call naming ~/.mandu" '^tamperResult=.*Mandu refused this' /tmp/capture-facts.out
  grep -rl 'openclaw:tamper:mandu-state' "$ALICE_EVENTS" > /tmp/tamper-events.out 2>/dev/null
  [[ -s /tmp/tamper-events.out ]] && pass "the refusal left the plugin's event (openclaw:tamper:mandu-state)" \
    || fail "no openclaw:tamper:mandu-state event under $ALICE_EVENTS"
  ph="$(grep -o '\$MDU:[^ "\\]*' /tmp/capture-facts.out | head -1 | sed 's/[.:]*$//')"
  echo "  the reply the user got:"; show /tmp/turn.out 12
  expect_out "the reply reached the user" 'MANDU_FAKE_DONE' /tmp/turn.out
  if [[ -n "$ph" ]] && grep -qF -- "$ph" /tmp/turn.out; then pass "the delivered reply keeps the placeholder ($ph)"
  else fail "the delivered reply does not carry the read's placeholder (${ph:-none found})"; fi
  expect_no "the delivered reply carries no canary" "$CANARY" /tmp/turn.out
  if grep -rq '"emitter":"openclaw-plugin"' "$ALICE_EVENTS" 2>/dev/null && grep -rq 'egress_decision' "$ALICE_EVENTS" 2>/dev/null; then
    note "the plugin's reply check ran (an egress_decision from openclaw-plugin)"
  else
    note "no reply-check event: a CLI turn without --deliver goes to no channel, so message_sending does not run"
  fi
fi

# ── step 6: mandu scan reads the OpenClaw history ────────────────────────────
step 6 "mandu scan"
as_alice 'mandu scan </dev/null' > /tmp/scan.out 2>&1; rc=$?
echo "  mandu scan:"; show /tmp/scan.out 30
expect_rc "mandu scan ran" 0 "$rc" /tmp/scan.out
note "scan's classification of the Gateway's session (not checked until scan knows plugin sessions): $(grep -Ei 'openclaw' /tmp/scan.out | head -3 | tr '\n' ' ' | cut -c1-200)"

# ── step 7: uninstall restores the config; the service goes; nothing remains ─
step 7 "mandu openclaw uninstall, mandu serve uninstall, no Mandu process left"
as_alice 'mandu openclaw uninstall </dev/null' > /tmp/oc-uninstall.out 2>&1; rc=$?
echo "  mandu openclaw uninstall:"; show /tmp/oc-uninstall.out 10
expect_rc "mandu openclaw uninstall" 0 "$rc" /tmp/oc-uninstall.out
if [[ $POOL -eq 0 ]]; then
  expect_out "uninstall finds nothing to remove" "not installed .*nothing written" /tmp/oc-uninstall.out
fi
canon "$PRE" > /tmp/oc-pre.canon; canon "$OC_CONFIG" > /tmp/oc-post.canon
if diff -u /tmp/oc-pre.canon /tmp/oc-post.canon > /tmp/oc-restore.diff; then
  pass "openclaw.json after uninstall equals the pre-install config"
else
  fail "openclaw.json after uninstall differs from the pre-install config"; show /tmp/oc-restore.diff 40
fi
as_alice 'openclaw gateway restart </dev/null' > /tmp/gw-restart2.out 2>&1
gw_healthy /tmp/gw-health2.out && pass "the Gateway restarts on the restored config" || { fail "the Gateway does not come back on the restored config"; show /tmp/gw-health2.out 20; }
as_alice 'openclaw gateway uninstall </dev/null' > /tmp/gw-uninstall.out 2>&1 || true

pkill -u alice -f 'legs/fake-model.mjs' 2>/dev/null || true
as_alice 'mandu serve uninstall </dev/null' > /tmp/serve-uninstall.out 2>&1; rc=$?
echo "  mandu serve uninstall:"; show /tmp/serve-uninstall.out 10
expect_rc "mandu serve uninstall" 0 "$rc" /tmp/serve-uninstall.out
[[ ! -e /home/alice/.config/systemd/user/mandu.service ]] && pass "the unit file is gone" || fail "mandu.service is still in ~/.config/systemd/user"
as_alice 'systemctl --user is-active mandu.service' > /tmp/serve-active2.out 2>&1
expect_no "mandu.service is no longer active" '^active$' /tmp/serve-active2.out
left=""
for _ in $(seq 20); do
  left="$(pgrep -u alice -af '/home/alice/mandu/' || true)"
  [[ -z "$left" ]] && break; sleep 0.5
done
[[ -z "$left" ]] && pass "no Mandu process remains" || { fail "Mandu processes remain:"; echo "$left" | sed 's/^/        | /'; }

# Evidence for post-mortems (the keys are dummies, the canary a canary).
mkdir -p /mnt/out/evidence
cp /tmp/*.out /tmp/*.err /tmp/*.diff /tmp/*.canon /mnt/out/evidence/ 2>/dev/null || true
cp "$CAP" /home/alice/legs/fake-model.log /mnt/out/evidence/ 2>/dev/null || true
cp "$PRE" /mnt/out/evidence/openclaw.pre-install.json 2>/dev/null || true
cp /home/alice/.openclaw/openclaw.json* /mnt/out/evidence/ 2>/dev/null || true
cp -r "$RUNA/mandu/logs" /mnt/out/evidence/alice-logs 2>/dev/null || true
cp -r "$ALICE_EVENTS" /mnt/out/evidence/alice-events 2>/dev/null || true
journalctl --user -M alice@ --no-pager > /mnt/out/evidence/alice-journal.txt 2>/dev/null \
  || journalctl _UID="$UIDA" --no-pager > /mnt/out/evidence/alice-journal.txt 2>/dev/null || true

echo
echo "fresh-openclaw-plugin: $FAILS failing check(s)$([[ $POOL -eq 0 ]] && echo "; the Gateway turn is PENDING the proxy pool")"
[[ $FAILS -eq 0 ]]
