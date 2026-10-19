#!/usr/bin/env bash
#
# docker-run.test.sh — unit tests for scripts/ci/docker-run.sh, the single
# entrypoint every CI job (and every local repro) uses to enter the container.
#
# Two contracts are asserted, both security-relevant (docs/design/testing/docker-e2e.md §1):
#
#  1. PROFILE → PRIVILEGE. Each profile gets exactly the privilege it needs and no
#     more: `core` runs with NO extra privilege; `userns` adds ONLY the two
#     security-opts that Docker's default seccomp/AppArmor policy would otherwise
#     use to block clone(CLONE_NEWUSER) and the mount namespace; `vm` adds
#     /dev/kvm. Nothing ever gets --privileged or an added capability. A profile
#     silently gaining privilege is the regression this test exists to catch.
#
#  2. THE CONTAINER IS THE SECRET BOUNDARY. GitLab injects project variables into
#     EVERY job's environment, so an "offline" job could otherwise be holding a
#     real key and go live without anyone noticing — passing for the wrong reason.
#     docker-run.sh forwards keys/credentials ONLY under an explicit flag, so an
#     offline container provably has neither. This test proves it by exporting
#     decoy keys and asserting they do NOT reach the container's argv.
#
# All assertions run against `--dry-run` (prints the docker argv it WOULD run),
# so the suite needs no docker daemon, no image, and no network.
#
# Run:  bash scripts/test/docker-run.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../ci/docker-run.sh"

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

# argv <args…> -> ARGV holds the printed docker argv (newline-separated), RC the exit code
argv() {
  ARGV="$(bash "$SCRIPT" "$@" 2>/dev/null)"
  RC=$?
}

# ── 1. profile → privilege ────────────────────────────────────────────────────

argv core --dry-run -- true
if [[ $RC -eq 0 ]] && ! grep -qE 'seccomp|apparmor|privileged|cap-add|/dev/kvm' <<<"$ARGV"; then
  pass "core: no extra privilege (no seccomp/apparmor/kvm/cap-add/privileged)"
else
  fail "core: expected zero extra privilege, got: $(tr '\n' ' ' <<<"$ARGV")"
fi

argv userns --dry-run -- true
if grep -q 'seccomp=unconfined' <<<"$ARGV" && grep -q 'apparmor=unconfined' <<<"$ARGV"; then
  pass "userns: grants seccomp=unconfined + apparmor=unconfined"
else
  fail "userns: missing the two security-opts the enforcement suites need"
fi
if ! grep -qE 'privileged|cap-add|/dev/kvm' <<<"$ARGV"; then
  pass "userns: does NOT escalate to --privileged / --cap-add / kvm"
else
  fail "userns: escalated beyond the two security-opts"
fi
# /proc unmasking is for the kernel tests (scripts/kernel-tests.sh), which this
# Docker path does not run. It must stay OFF by default: privilege we do not need
# is privilege we do not take.
if ! grep -q 'systempaths=unconfined' <<<"$ARGV"; then
  pass "userns: does NOT unmask /proc by default (the kernel tests are opt-in)"
else
  fail "userns: unmasks /proc without --kernel-tests"
fi

# ...and --kernel-tests is the ONLY way to get it (Docker's masked /proc paths are
# locked mounts that block `unshare --mount-proc`). --kernel-tier, its name until
# the manifest's tiers became kinds (2026-10-02), stays an alias with the same effect.
for flag in --kernel-tests --kernel-tier; do
  argv userns "$flag" --dry-run -- true
  if [[ $RC -eq 0 ]] && grep -q 'systempaths=unconfined' <<<"$ARGV"; then
    pass "$flag unmasks /proc (unblocks unshare --mount-proc)"
  else
    fail "$flag did not add systempaths=unconfined"
  fi

  # It is meaningless on `core`, which grants no namespaces at all — reject it loudly
  # rather than hand back a container that cannot do what the caller asked.
  argv core "$flag" --dry-run -- true
  [[ $RC -ne 0 ]] && pass "$flag on core is an error" || fail "$flag on core should exit non-zero"
done

# The script's own words follow the kinds: no "tier" left outside the alias's note.
if ! grep -i 'tier' "$SCRIPT" | grep -qv 'kernel-tier'; then
  pass "docker-run.sh names no tier (only the --kernel-tier alias and its note)"
else
  fail "docker-run.sh still says tier: $(grep -ni 'tier' "$SCRIPT" | grep -v 'kernel-tier' | tr '\n' ' ')"
fi

argv vm --dry-run -- true
if grep -q '/dev/kvm' <<<"$ARGV" && ! grep -q 'privileged' <<<"$ARGV"; then
  pass "vm: adds /dev/kvm without --privileged"
else
  fail "vm: expected /dev/kvm and no --privileged"
fi

# No profile may EVER reach for --privileged.
for p in core userns vm; do
  argv "$p" --dry-run -- true
  if grep -q -- '--privileged' <<<"$ARGV"; then
    fail "$p: uses --privileged (never acceptable — the profiles are proven not to need it)"
  fi
done
pass "no profile uses --privileged"

# ── 2. the container is the secret boundary ───────────────────────────────────
# Decoy keys in the environment, exactly as GitLab would inject them into a job.

DECOY_ANTHROPIC="sk-ant-DECOY-must-not-leak"
DECOY_OPENAI="sk-DECOY-must-not-leak"

leaks() { grep -qE 'DECOY-must-not-leak' <<<"$1"; }

ARGV="$(ANTHROPIC_API_KEY="$DECOY_ANTHROPIC" OPENAI_API_KEY="$DECOY_OPENAI" \
        bash "$SCRIPT" core --dry-run -- true 2>/dev/null)"
if leaks "$ARGV"; then
  fail "SECURITY: an offline (core) container received an API key from the ambient env"
else
  pass "offline container carries NO API key even when one is in the ambient env"
fi

# ...and the same for the userns profile, which is the one that runs live agents.
ARGV="$(ANTHROPIC_API_KEY="$DECOY_ANTHROPIC" OPENAI_API_KEY="$DECOY_OPENAI" \
        bash "$SCRIPT" userns --dry-run -- true 2>/dev/null)"
if leaks "$ARGV"; then
  fail "SECURITY: a userns container received an API key from the ambient env"
else
  pass "userns container carries NO API key without --with-secrets"
fi

# Opting IN must actually deliver the key — via an --env-file, never as a bare
# `-e KEY=value` (which would print the secret into `docker inspect` / ps output).
ARGV="$(ANTHROPIC_API_KEY="$DECOY_ANTHROPIC" \
        bash "$SCRIPT" core --with-secrets --dry-run -- true 2>/dev/null)"
if grep -q -- '--env-file' <<<"$ARGV"; then
  pass "--with-secrets delivers keys via --env-file"
else
  fail "--with-secrets did not add an --env-file"
fi
if leaks "$ARGV"; then
  fail "SECURITY: --with-secrets put the key in the argv (visible to docker inspect/ps) instead of the env-file"
else
  pass "--with-secrets keeps the key OUT of the argv (env-file only)"
fi

# Credential stores are opt-in too, and are MOUNTS (shared store), not copies.
argv core --dry-run -- true
if grep -q "\.claude" <<<"$ARGV"; then
  fail "credential store mounted without --with-claude-auth"
else
  pass "no credential store without --with-claude-auth"
fi

if [[ -d "$HOME/.claude" ]]; then
  argv core --with-claude-auth --dry-run -- true
  if grep -q "$HOME/.claude:/home/agent/.claude" <<<"$ARGV"; then
    pass "--with-claude-auth bind-mounts the host's real ~/.claude (one shared store, not a copy)"
  else
    fail "--with-claude-auth did not bind-mount ~/.claude"
  fi
else
  echo "SKIP: --with-claude-auth mount check (no \$HOME/.claude on this host)"
fi

# ── 3. --publish-events: the run's sessions reach the HOST dashboard ──────────
# Without it a CI e2e run is invisible (its arbiter writes into the container's own
# event dir and dies with it), so the sidebar's CI badge would have nothing to badge.

argv core --dry-run -- true
if grep -q 'MANDU_HOME=\|/events:' <<<"$ARGV"; then
  fail "the host event dir is mounted without --publish-events"
else
  pass "no host event dir without --publish-events (a plain job writes nothing to it)"
fi

# publish_ok <host mandu home>: the container gets MANDU_HOME=<that home> (the
# same path), a private uid-owned tmpfs there, and the host's <home>/events
# bind-mounted at the same path — the container's arbiter and its test tenant
# (`events/test`) resolve into the mount by the path table alone. No retired
# per-path variable crosses.
publish_ok() {
  local h="$1"
  grep -qx -- "MANDU_HOME=$h" <<<"$ARGV" \
    && grep -qx -- "$h/events:$h/events" <<<"$ARGV" \
    && grep -qx -- "$h:uid=$(id -u),gid=$(id -g),mode=0700" <<<"$ARGV" \
    && ! grep -q 'MANDU_EVENT_DIR\|MANDU_SYMBOL_DB' <<<"$ARGV"
}

argv core --publish-events --dry-run -- true
# The host dashboard's home (runtime-instances.md §12): on disk, keyed by the
# invoking uid's passwd home — NOT $HOME, which the CI runner overrides.
_pw_home="$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6)"
EXPECT_HOME="${MANDU_HOME:-${_pw_home:-$HOME}/.mandu}"
if publish_ok "$EXPECT_HOME"; then
  pass "--publish-events gives the container the host home's path, with the host event dir mounted at its events/"
else
  fail "--publish-events did not wire the host event dir ($EXPECT_HOME/events; argv: $ARGV)"
fi

# The GitLab runner overrides HOME to its clean CI home; the published dir must
# still be the USER's dashboard dir (passwd home), or CI sessions vanish from
# the dashboard silently. Also: an explicit MANDU_HOME wins over both.
_saved_home="$HOME"
_saved_mh="${MANDU_HOME-}"; _had_mh="${MANDU_HOME+set}"
unset MANDU_HOME
_pw_expect="${_pw_home:-$HOME}/.mandu"
export HOME="/nonexistent/ci-home"
argv core --publish-events --dry-run -- true
if publish_ok "$_pw_expect"; then
  pass "--publish-events ignores an overridden HOME (the runner's CI home) and keeps the user's dashboard dir"
else
  fail "--publish-events followed the overridden HOME instead of the passwd home (argv: $ARGV)"
fi
_mh_probe="$(mktemp -d)"
export MANDU_HOME="$_mh_probe"
argv core --publish-events --dry-run -- true
if publish_ok "$_mh_probe"; then
  pass "--publish-events honors an explicit MANDU_HOME (a runner unit's)"
else
  fail "--publish-events ignored MANDU_HOME (argv: $ARGV)"
fi
rm -rf "$_mh_probe"
unset MANDU_HOME
ARGV="$(MANDU_EVENT_DIR=/srv/ev bash "$SCRIPT" core --publish-events --dry-run -- true 2>/dev/null)"
if publish_ok "$_pw_expect" && ! grep -q '/srv/ev' <<<"$ARGV"; then
  pass "--publish-events: the retired MANDU_EVENT_DIR moves nothing"
else
  fail "--publish-events followed the retired MANDU_EVENT_DIR (argv: $ARGV)"
fi
export HOME="$_saved_home"
if [[ -n "$_had_mh" ]]; then export MANDU_HOME="$_saved_mh"; fi

# ── 3b. axis/posture knobs reach the container ────────────────────────────────
# The int×conf fold a live job runs is decided by env the CONTAINER's arbiter
# boots with. A job variable that silently never crossed the docker boundary
# leaves the arbiter at its defaults while the pipeline claims a different
# fold — the "posture nobody runs" class. These knobs must be on the
# passthrough allowlist (and ONLY as non-secret -e pairs).

ARGV="$(MANDU_CONFIDENTIALITY=1 MANDU_INTEGRITY=0 \
        MANDU_E2E_EXPECT_CONF=1 MANDU_E2E_EXPECT_INT=1 MANDU_E2E_CONF_INT=0 \
        bash "$SCRIPT" core --dry-run -- true 2>/dev/null)"
POSTURE_OK=1
for pair in MANDU_CONFIDENTIALITY=1 MANDU_INTEGRITY=0 \
            MANDU_E2E_EXPECT_CONF=1 MANDU_E2E_EXPECT_INT=1 MANDU_E2E_CONF_INT=0; do
  grep -q -- "^$pair$" <<<"$ARGV" || { POSTURE_OK=0; fail "posture knob $pair did not reach the container argv"; }
done
[[ $POSTURE_OK -eq 1 ]] && pass "axis/posture knobs (MANDU_CONFIDENTIALITY/INTEGRITY + EXPECT_*/CONF_INT) reach the container"

# ── 3c. the differential-battery selectors reach the container ───────────────
# agent-mock-diff-agents runs the lanes serially via MANDU_DIFF_AGENT; a
# selector that never crossed the boundary would run the whole battery
# concurrently — the very contention the serial job exists to remove.
ARGV="$(MANDU_DIFF_AGENT=opencode MANDU_DIFF_ONLY=fidelity-two-turn-prose MANDU_DIFF_KEEP=1 \
        bash "$SCRIPT" core --dry-run -- true 2>/dev/null)"
DIFF_OK=1
for pair in MANDU_DIFF_AGENT=opencode MANDU_DIFF_ONLY=fidelity-two-turn-prose MANDU_DIFF_KEEP=1; do
  grep -q -- "^$pair$" <<<"$ARGV" || { DIFF_OK=0; fail "differential selector $pair did not reach the container argv"; }
done
[[ $DIFF_OK -eq 1 ]] && pass "differential selectors (MANDU_DIFF_ONLY/AGENT/KEEP) reach the container"

# ...and an unset knob adds nothing (no bare -e names that would leak ambient env).
argv core --dry-run -- true
if ! grep -qE 'MANDU_CONFIDENTIALITY|MANDU_INTEGRITY|MANDU_E2E_EXPECT|MANDU_E2E_CONF_INT' <<<"$ARGV"; then
  pass "unset posture knobs add no -e pairs (allowlist forwards values, never bare names)"
else
  fail "an unset posture knob still appeared in the container argv"
fi

# ── 4. usage errors ───────────────────────────────────────────────────────────

argv --dry-run -- true
[[ $RC -ne 0 ]] && pass "missing profile is an error" || fail "missing profile should exit non-zero"

argv bogus --dry-run -- true
[[ $RC -ne 0 ]] && pass "unknown profile is an error" || fail "unknown profile should exit non-zero"

argv core --dry-run
[[ $RC -ne 0 ]] && pass "missing command is an error" || fail "missing command should exit non-zero"

# ── 3. the release flags (packaging.md §11.3): a publish credential is opt-in, one
#      host path is writable, and neither exists unless asked for ──────────────

DECOY_NPM="npm_decoy_0000000000000000000000000000000000"
ARGV="$(NPM_TOKEN="$DECOY_NPM" bash "$SCRIPT" core --dry-run -- true 2>/dev/null)"
if ! grep -q "$DECOY_NPM" <<<"$ARGV" && ! grep -q 'NPM_TOKEN' <<<"$ARGV"; then
  pass "core container carries NO npm token without --with-npm-token"
else
  fail "SECURITY: NPM_TOKEN reached the container argv without --with-npm-token"
fi
if ! grep -q '/repo/release' <<<"$ARGV"; then
  pass "no host path is mounted at /repo/release without --out"
else
  fail "a release mount appeared without --out"
fi

ARGV="$(NPM_TOKEN="$DECOY_NPM" bash "$SCRIPT" core --with-npm-token --dry-run -- true 2>/dev/null)"
if grep -q -- "-e" <<<"$ARGV" && grep -q "NPM_TOKEN=$DECOY_NPM" <<<"$ARGV"; then
  pass "--with-npm-token forwards NPM_TOKEN"
else
  fail "--with-npm-token did not forward NPM_TOKEN"
fi

ARGV="$(NPM_TOKEN="" bash "$SCRIPT" core --with-npm-token --dry-run -- true 2>/dev/null)"; RC=$?
[[ $RC -ne 0 ]] && pass "--with-npm-token with an empty NPM_TOKEN is an error (never a silent unauthenticated publish)" \
  || fail "--with-npm-token with an empty token should exit non-zero"

ARGV="$(bash "$SCRIPT" core --out /tmp/mandu-rel-test-out --dry-run -- true 2>/dev/null)"
if grep -q -- '-v' <<<"$ARGV" && grep -qE '/tmp/mandu-rel-test-out:/repo/release' <<<"$ARGV"; then
  pass "--out mounts the host dir at /repo/release"
else
  fail "--out did not mount the host dir at /repo/release: $(tr '\n' ' ' <<<"$ARGV")"
fi
if ! grep -qE 'seccomp|apparmor|privileged|cap-add|/dev/kvm' <<<"$ARGV"; then
  pass "--out grants no privilege"
else
  fail "--out changed the profile's privilege"
fi

echo
echo "docker-run.test.sh: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
