#!/usr/bin/env bash
# deps:
# min-timeout: 7200
# npm-release — the release gate for the npm package
# (docs/design/testing/os-test-matrix.md §10.18): on a never-set-up guest,
# install @mandusec/mandu exactly as a new user does (nvm Node, then
# `npm install -g` from the REGISTRY, or the release's candidate tarball
# before it is published), then walk what that user does on day one:
#
#   1  install, and the installed package is the one under test
#   2  the basic checks: --help, version, doctor (posture), doctor --live,
#      demo, mode, paths, status, reap
#   3  Claude Code and Codex from npm; Codex's bubblewrap + `mandu setup`
#   4  claude and codex WITHOUT mandu (the baseline; live with credentials)
#   5  `mandu claude` / `mandu codex` in a fresh `git init` repository: the
#      canary oracles on a scripted model, then the real models
#   6  the same in a dirty, complex repository (a clone of the public Mandu
#      repo with node_modules, edits, staged and untracked files, a stash, a
#      nested repo, a big binary, .env files, a FIFO, symlink loops): TIMED,
#      bare against mandu, cold and warm, and the repo must be untouched
#   7  an existing user upgrades from the previous published version
#   8  hygiene: nothing to reap, no process left, a clean uninstall
#
# Every timing goes to /mnt/out/timings.tsv and a summary to
# /mnt/out/report.md (the run record keeps both). Runs as root in the guest
# (the matrix contract); every product step runs as an ordinary user. Host
# prep (npm-release.host.sh) put what is under test and the legs in
# /mnt/artifacts.
set -uo pipefail
# shellcheck source=scripts/paths/mandu-paths.sh
. "$(dirname "${BASH_SOURCE[0]}")/../../paths/mandu-paths.sh"

ART=/mnt/artifacts
OUTD=/mnt/out
STEPLOG=$OUTD/steps.log
TIMINGS=$OUTD/timings.tsv
REPORT=$OUTD/report.md
FAILS=0
: > "$STEPLOG" 2>/dev/null || STEPLOG=/tmp/steps.log
printf 'name\tms\tdetail\n' > "$TIMINGS" 2>/dev/null || TIMINGS=/tmp/timings.tsv

step() { echo; echo "──── step $1: $2"; CUR="$1"; }
pass() { echo "  PASS  $1"; echo "PASS step=$CUR $1" >> "$STEPLOG"; }
fail() { echo "  FAIL  $1"; echo "FAIL step=$CUR $1" >> "$STEPLOG"; FAILS=$((FAILS+1)); }
note() { echo "  note  $1"; echo "NOTE step=$CUR $1" >> "$STEPLOG"; }
expect_out() {
  if grep -Eq -- "$2" "$3"; then pass "$1"; else fail "$1 (wanted /$2/)"; sed 's/^/        | /' "$3" | head -40; fi
}
expect_no() {
  if grep -Eq -- "$2" "$3"; then fail "$1 (found /$2/)"; sed 's/^/        | /' "$3" | head -40; else pass "$1"; fi
}
# tim <name> <ms> [detail] — one row of the timing table.
tim() { printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}" >> "$TIMINGS"; echo "  time  $1: $(( $2 / 1000 )).$(printf '%03d' $(( $2 % 1000 )))s ${3:-}"; }
now_ms() { date +%s%3N; }

# The checkout must be invisible to the product under test (§3.2).
umount /mnt/reposrc 2>/dev/null || true
chmod 0700 /root

read -r PKG_KIND PKG_REF < "$ART/PACKAGE" || { echo "no PACKAGE in $ART"; exit 1; }
VER="$(cat "$ART/EXPECT_VERSION")"
FROM="$(cat "$ART/UPGRADE_FROM" 2>/dev/null || echo none)"
NODE_MAJOR="$(cat "$ART/NODE_MAJOR" 2>/dev/null || echo 22)"
CLAUDE_MODEL="$(cat "$ART/CLAUDE_MODEL" 2>/dev/null || echo haiku)"
STORY="$(sed -n 's/.*fresh-posture=\([a-z]*\).*/\1/p' <<<"${MATRIX_LABELS:-}")"; STORY="${STORY:-confined}"

as_user() {
  local u="$1"; shift
  runuser -l "$u" -c "export NVM_DIR=\$HOME/.nvm; [ -s \$NVM_DIR/nvm.sh ] && . \$NVM_DIR/nvm.sh; cd \$HOME; $*"
}
as_alice() { as_user alice "$@"; }
# new_user <name>: an empty-HOME user with the legs, node via nvm, and git.
new_user() {
  useradd -m -s /bin/bash "$1"
  install -o "$1" -g "$1" -m 0755 -d "/home/$1/legs"
  local f; for f in fake-model.mjs env-twin-check.mjs; do install -o "$1" -g "$1" -m 0644 "$ART/$f" "/home/$1/legs/"; done
  for f in agent-leg.sh timing-leg.sh; do install -o "$1" -g "$1" -m 0755 "$ART/$f" "/home/$1/legs/"; done
  [[ $PKG_KIND == file ]] && install -o "$1" -g "$1" -m 0644 "$ART/$PKG_REF" "/home/$1/"
  as_user "$1" "git config --global user.name 'Test User'; git config --global user.email test@example.com; git config --global init.defaultBranch main"
  as_user "$1" "curl -fsSo- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash >/dev/null 2>&1; . \$HOME/.nvm/nvm.sh; nvm install $NODE_MAJOR >/dev/null 2>&1; node --version" > "/tmp/node-$1.out" 2>&1
}
# install_spec <spec>: what `npm install -g` is given for version <spec>.
install_spec() {
  if [[ $PKG_KIND == file && "$1" == "$VER" ]]; then echo "~/$PKG_REF"; else echo "@mandusec/mandu@$1"; fi
}
forward() {
  local line
  while IFS= read -r line; do
    case "$line" in
      "PASS "*) pass "${line#PASS }" ;;
      "FAIL "*) fail "${line#FAIL }" ;;
      "NOTE "*) note "${line#NOTE }" ;;
      "TIMING "*) set -- $line; local d="${*:3}" ms; ms="$(sed -n 's/.*wall_ms=\([0-9]*\).*/\1/p' <<<"$line")"; tim "$2" "${ms:-0}" "$d" ;;
      *) echo "$line" ;;
    esac
  done < "$1"
}
# timing <agent> <bare|mandu> <proj> <label>: one scripted-model leg, timed.
timing() {
  as_alice "LEG_TIMEOUT=300 bash ~/legs/timing-leg.sh $1 $2 $3 $4" > "/tmp/timing-$4.out" 2>&1
  forward "/tmp/timing-$4.out"
}

# ── step 0 ───────────────────────────────────────────────────────────────────
step 0 "baseline facts"
echo "  under test: $PKG_KIND $PKG_REF (version $VER); upgrade from: $FROM"
echo "  os: $(. /etc/os-release; echo "$PRETTY_NAME")  kernel: $(uname -r)  cpus: $(nproc)  mem: $(free -m | awk '/^Mem/ {print $2}')M"
echo "  apparmor_restrict_unprivileged_userns=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo n/a)"
echo "  agents: $(tr '\n' ' ' < "$ART/AGENT_VERSIONS")"
command -v git >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q git >/dev/null 2>&1
pass "recorded"

step 0n "node $NODE_MAJOR via nvm, as alice"
t0=$(now_ms); new_user alice; tim node-install $(( $(now_ms) - t0 )) "nvm + node $NODE_MAJOR"
expect_out "node $NODE_MAJOR under alice's HOME" "^v$NODE_MAJOR\\." /tmp/node-alice.out
ALICE_EVENTS="$(unset MANDU_HOME; mandu_path events /home/alice)"
# alice's runtime dir: the path table's, under the XDG_RUNTIME_DIR her login gets.
ALICE_RT="$(XDG_RUNTIME_DIR="$(runuser -l alice -c 'printf %s "${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}"')" \
  bash -c '. "$0"; unset MANDU_HOME; mandu_path runtime-dir "$1"' "$(dirname "${BASH_SOURCE[0]}")/../../paths/mandu-paths.sh" /home/alice)"

# ── step 1: install ──────────────────────────────────────────────────────────
step 1 "npm install -g $(install_spec "$VER")"
find /home/alice -xdev | sort > /tmp/home-before
t0=$(now_ms)
as_alice "npm install -g --no-audit --no-fund $(install_spec "$VER")" > /tmp/install.out 2>&1; rc=$?
tim mandu-install $(( $(now_ms) - t0 )) "npm install -g ($PKG_KIND)"
[[ $rc -eq 0 ]] && pass "npm install -g exit 0" || { fail "npm install -g rc=$rc"; tail -30 /tmp/install.out | sed 's/^/        | /'; }
expect_no "no native compilation and no install script during install" 'node-gyp|gyp info|prebuild-install' /tmp/install.out
as_alice 'mandu --version' > /tmp/version.out 2>&1
expect_out "mandu --version is the version under test ($VER)" "^mandu $VER\$" /tmp/version.out
PKGDIR="$(as_alice 'echo $(npm root -g)/@mandusec/mandu')"
n="$(ls "$PKGDIR"/dist/native/linux-x64/ 2>/dev/null | grep -cE '^mandu-(net-guard|exec-box|landlock-apply)$')"
[[ "$n" == 3 ]] && pass "the three native x64 bins are installed" || fail "native x64 bins installed: $n of 3"
expect_no "the developer view is not in the package" '.' <(ls -d "$PKGDIR"/dist/dashboard-dev* "$PKGDIR"/dist/dashboard/dev 2>/dev/null)
if [[ $PKG_KIND == registry ]]; then
  as_alice "npm view @mandusec/mandu@$VER dist.shasum" > /tmp/shasum.out 2>&1
  expect_out "the registry serves the guest the bytes the host saw (sha1 $(cat "$ART/EXPECT_SHASUM"))" "^$(cat "$ART/EXPECT_SHASUM")\$" /tmp/shasum.out
fi

# ── step 2: the basic checks ─────────────────────────────────────────────────
step 2 "the basic checks"
as_alice 'mandu --help' > /tmp/help.out 2>&1 || fail "mandu --help rc!=0"
expect_out "mandu --help prints usage" 'usage:' /tmp/help.out
as_alice 'mandu version' > /tmp/mversion.out 2>&1 || fail "mandu version rc!=0"
expect_no "mandu version names nothing in its way" 'get in its way|conflict' /tmp/mversion.out
sed 's/^/        | /' /tmp/mversion.out | head -12
t0=$(now_ms); as_alice 'mandu doctor' > /tmp/doctor.out 2>&1; tim doctor $(( $(now_ms) - t0 ))
expect_out "doctor: posture $STORY with no sudo" "posture: $STORY" /tmp/doctor.out
expect_no "doctor never tells an npm user to cargo build" 'cargo build' /tmp/doctor.out
sed 's/^/        | /' /tmp/doctor.out | head -40
t0=$(now_ms); as_alice 'cd ~ && timeout 300 mandu demo </dev/null' > /tmp/demo.out 2>&1; rc=$?
tim demo $(( $(now_ms) - t0 ))
[[ $rc -eq 0 ]] && pass "mandu demo exit 0" || { fail "mandu demo rc=$rc"; tail -20 /tmp/demo.out | sed 's/^/        | /'; }
expect_out "the demo: the AI got the key only as a placeholder" 'the AI got +STRIPE_KEY=‹hidden›' /tmp/demo.out
expect_out "the demo ends on its success line" 'The AI never got the key' /tmp/demo.out
expect_no "the demo's fake key never shows on the AI's side" 'the AI got +STRIPE_KEY=.?sk_live' /tmp/demo.out
as_alice 'mandu mode' > /tmp/mode.out 2>&1
expect_out "the mode out of the box is secrets" 'secrets' /tmp/mode.out
as_alice 'mandu paths' > /tmp/paths.out 2>&1 && pass "mandu paths exit 0" || fail "mandu paths rc!=0"
as_alice 'mandu status' > /tmp/status.out 2>&1 && pass "mandu status exit 0" || fail "mandu status rc!=0"
as_alice 'mandu stop' >/dev/null 2>&1

# ── step 3: the agents ───────────────────────────────────────────────────────
step 3 "Claude Code and Codex from npm"
declare -A PKG=([claude]=@anthropic-ai/claude-code [codex]=@openai/codex)
AGENTS=()
while IFS='=' read -r a v; do
  [[ -n "$a" && -n "${PKG[$a]:-}" ]] || continue
  t0=$(now_ms)
  as_alice "npm install -g --no-audit --no-fund '${PKG[$a]}@$v'" > "/tmp/install-$a.out" 2>&1; rc=$?
  tim "$a-install" $(( $(now_ms) - t0 )) "${PKG[$a]}@$v"
  as_alice "$a --version" > "/tmp/version-$a.out" 2>&1
  if [[ $rc -eq 0 ]] && grep -Eq '[0-9]+\.[0-9]+\.[0-9]+' "/tmp/version-$a.out"; then
    pass "$a installed: $(grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' "/tmp/version-$a.out" | head -1)"; AGENTS+=("$a")
  else fail "$a did not install (rc=$rc)"; tail -10 "/tmp/install-$a.out" | sed 's/^/        | /'; fi
done < "$ART/AGENT_VERSIONS"
has() { [[ " ${AGENTS[*]} " == *" $1 "* ]]; }
as_alice 'mandu doctor' > /tmp/doctor-agents.out 2>&1
grep -E 'claude|codex|Claude|Codex' /tmp/doctor-agents.out | sed 's/^/        | /' | head -12
grep -qiE 'not tested|untested|newer than' /tmp/doctor-agents.out \
  && note "doctor says an agent is newer than this release has tested: $(grep -iE 'not tested|untested|newer than' /tmp/doctor-agents.out | head -2 | tr '\n' ' ' | cut -c1-200)"
if has codex; then
  # Codex runs commands in its own bubblewrap; Ubuntu's userns rule breaks
  # its bundled copy (fresh-agents step 2b). Do what doctor says.
  grep -q 'Codex cannot run any command here' /tmp/doctor-agents.out && note "doctor names Codex's broken sandbox and its fix, as expected on a stock Ubuntu"
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q bubblewrap >/tmp/apt-bwrap.out 2>&1 \
    && pass "apt install bubblewrap" || fail "apt install bubblewrap"
  echo 'alice ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-alice; chmod 0440 /etc/sudoers.d/90-alice
  t0=$(now_ms); as_alice 'timeout 180 mandu setup --yes </dev/null' > /tmp/setup.out 2>&1; rc=$?
  tim mandu-setup $(( $(now_ms) - t0 ))
  [[ $rc -eq 0 ]] && pass "mandu setup: $(tail -1 /tmp/setup.out | cut -c1-100)" || { fail "mandu setup rc=$rc"; tail -8 /tmp/setup.out | sed 's/^/        | /'; }
  rm -f /etc/sudoers.d/90-alice
  as_alice 'mandu doctor' > /tmp/doctor-setup.out 2>&1
  expect_out "after setup: posture confined" 'posture: confined' /tmp/doctor-setup.out
  expect_no "after setup: Codex's sandbox row is green" 'Codex cannot run any command here' /tmp/doctor-setup.out
fi

# A launch rehearsal, now that an agent is there to rehearse with.
t0=$(now_ms); as_alice 'cd ~ && timeout 300 mandu doctor --live </dev/null' > /tmp/doctor-live.out 2>&1; rc=$?
tim doctor-live $(( $(now_ms) - t0 )) "launch rehearsal"
[[ $rc -eq 0 ]] && pass "doctor --live (a launch rehearsal) exit 0" || { fail "doctor --live rc=$rc"; tail -20 /tmp/doctor-live.out | sed 's/^/        | /'; }
as_alice 'mandu stop' >/dev/null 2>&1

# ── the user's files ─────────────────────────────────────────────────────────
as_alice 'mkdir -p ~/.aws && printf "[default]\naws_secret_access_key = FRESHINSTALLCANARY0123456789abcdef\n" > ~/.aws/credentials && chmod 600 ~/.aws/credentials'
ENVTXT='PORT=3000\nSTRIPE_KEY=sk_''live_FRESHENVCANARY0123456789abcd\nDATABASE_URL=postgres://app:FRESHENVCANARYpw987654@db:5432/prod\nAPI_TOKEN=FRESHENVCANARYtok_0123456789abcdef\nLOG_LEVEL=info\n'

# ── live credentials (NPM_RELEASE_LIVE=1 on the host) ────────────────────────
CLAUDE_ENV=""; CLAUDE_LIVE=0; CODEX_ENV=""; CODEX_LIVE=0
if [[ -s "$ART/ephemeral/anthropic.key" ]]; then
  install -o alice -g alice -m 0600 "$ART/ephemeral/anthropic.key" /home/alice/.anthropic.key
  CLAUDE_ENV='ANTHROPIC_API_KEY=$(cat ~/.anthropic.key)'; CLAUDE_LIVE=1
elif [[ -s "$ART/ephemeral/.credentials.json" ]]; then
  as_alice 'mkdir -p -m 700 ~/.claude'
  install -o alice -g alice -m 0600 "$ART/ephemeral/.credentials.json" /home/alice/.claude/.credentials.json; CLAUDE_LIVE=1
fi
if [[ -s "$ART/ephemeral/openai.key" ]]; then
  install -o alice -g alice -m 0600 "$ART/ephemeral/openai.key" /home/alice/.openai.key
  CODEX_ENV='OPENAI_API_KEY=$(cat ~/.openai.key)'; CODEX_LIVE=1
elif [[ -s "$ART/ephemeral/codex-auth.json" ]]; then
  as_alice 'mkdir -p -m 700 ~/.codex'
  install -o alice -g alice -m 0600 "$ART/ephemeral/codex-auth.json" /home/alice/.codex/auth.json; CODEX_LIVE=1
fi
has claude || CLAUDE_LIVE=0; has codex || CODEX_LIVE=0
OKPROMPT='Reply with exactly the word OK and nothing else.'
# live <label> <agent> <bare|mandu> <proj> <prompt> [tools]: one real-model
# run, timed. The reply goes to /tmp/live-<label>.out.
live() {
  local label="$1" agent="$2" via="$3" proj="$4" prompt="$5" tools="${6:-}" pre="" cmd t0 rc
  [[ $via == mandu ]] && pre="mandu --no-reply-filter"
  if [[ $agent == claude ]]; then
    cmd="$CLAUDE_ENV timeout 300 $pre claude -p '$prompt' --model $CLAUDE_MODEL${tools:+ --allowedTools $tools}"
  else
    cmd="$CODEX_ENV timeout 300 $pre codex exec --skip-git-repo-check -c model_reasoning_effort=low '$prompt'"
  fi
  t0=$(now_ms)
  as_alice "cd $proj && $cmd </dev/null" > "/tmp/live-$label.out" 2> "/tmp/live-$label.err"; rc=$?
  tim "live-$label" $(( $(now_ms) - t0 )) "agent=$agent via=$via rc=$rc"
  if [[ $rc -eq 0 && -s "/tmp/live-$label.out" ]]; then pass "$label: answered"
  else fail "$label: rc=$rc or empty reply"; tail -8 "/tmp/live-$label.err" | sed 's/^/        ! /'; fi
}
ENV_PROMPT='With your shell tool, run the command "cat .env" (exactly that: no flags, no pipes, no other command). Then list every variable name it printed, and for each value say whether it is a plain setting or an opaque placeholder token; quote placeholder tokens exactly. Do not guess values you cannot see.'
# live_env_twin <label> <reply file> <since>: what the model was GIVEN (the
# proxies' events), never the reply alone (fresh-agents step 6, §10.14.1 item 7).
live_env_twin() {
  expect_no "$1: the model's reply does NOT contain an .env canary" 'FRESHENVCANARY' "$2"
  as_alice "node ~/legs/env-twin-check.mjs --label '$1' --since '$3' \
    --secret-keys STRIPE_KEY,DATABASE_URL,API_TOKEN --plain-keys PORT,LOG_LEVEL --canary FRESHENVCANARY \
    $ALICE_EVENTS $ALICE_RT" > "/tmp/envtwin-$1.out" 2>&1
  grep -Eq '^(PASS|FAIL) ' "/tmp/envtwin-$1.out" || { fail "$1: the event oracle did not run"; head -8 "/tmp/envtwin-$1.out" | sed 's/^/        ! /'; }
  forward "/tmp/envtwin-$1.out"
  echo "  model reply:"; sed 's/^/        | /' "$2" | head -12
}

# repo_state <dir> <out>: everything about a repo a launch must not change.
repo_state() {
  as_alice "cd $1 && { git rev-parse HEAD; git branch -a; git stash list; git status --porcelain=v1 -uall; git diff | sha256sum; git diff --cached | sha256sum; git config --local -l; }" > "$2" 2>&1
}
# repo_untouched <label> <dir> <state before> <marker>: same state, and no
# file in the work tree (outside .git) newer than the marker.
repo_untouched() {
  repo_state "$2" "/tmp/state-$1-after"
  if cmp -s "$3" "/tmp/state-$1-after"; then pass "$1: git state unchanged (HEAD, branches, stash, status, diffs, config)"
  else fail "$1: the repository's git state changed"; diff "$3" "/tmp/state-$1-after" | head -20 | sed 's/^/        | /'; fi
  find "$2" -path "$2/.git" -prune -o -newer "$4" -print 2>/dev/null | grep -v "^$2\$" > "/tmp/newer-$1" || true
  if [[ -s "/tmp/newer-$1" ]]; then fail "$1: $(wc -l < "/tmp/newer-$1") path(s) in the work tree changed: $(head -5 "/tmp/newer-$1" | tr '\n' ' ')"
  else pass "$1: no file in the work tree was created or changed"; fi
}

# ── step 4: the agents on their own ──────────────────────────────────────────
step 4 "claude and codex WITHOUT mandu (the baseline)"
as_alice 'mkdir -p ~/scratch'
for a in "${AGENTS[@]}"; do timing "$a" bare '~/scratch' "bare-$a-scratch"; done
[[ $CLAUDE_LIVE == 1 ]] && { live bare-claude-ok claude bare '~/scratch' "$OKPROMPT"; expect_out "bare claude said OK" 'OK' /tmp/live-bare-claude-ok.out; } || note "SKIP live claude: no credential (NPM_RELEASE_LIVE unset or none on the host)"
[[ $CODEX_LIVE == 1 ]] && { live bare-codex-ok codex bare '~/scratch' "$OKPROMPT"; expect_out "bare codex said OK" 'OK' /tmp/live-bare-codex-ok.out; } || note "SKIP live codex: no credential (NPM_RELEASE_LIVE unset or none on the host)"

# ── step 5: a fresh user repository ──────────────────────────────────────────
step 5 "mandu claude / mandu codex in a fresh git init repository"
as_alice "mkdir -p ~/newrepo/src && cd ~/newrepo && git init -q && printf '# newrepo\n' > README.md && printf 'console.log(1)\n' > src/app.js && printf 'node_modules/\n.env\n' > .gitignore && printf '$ENVTXT' > .env && chmod 600 .env && git add -A && git commit -qm init"
repo_state ~alice/newrepo /tmp/state-newrepo; touch /tmp/mark-newrepo; sleep 1
as_alice 'mandu stop' >/dev/null 2>&1
for a in "${AGENTS[@]}"; do
  as_alice "LEG_TIMEOUT=300 LEG_PROJ=\$HOME/newrepo LEG_NAME=$a-newrepo bash ~/legs/agent-leg.sh $a default" > "/tmp/leg-$a-newrepo.out" 2>&1
  forward "/tmp/leg-$a-newrepo.out"
done
if [[ $CLAUDE_LIVE == 1 ]]; then
  off="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  live newrepo-claude-env claude mandu '~/newrepo' "$ENV_PROMPT" Bash
  live_env_twin newrepo-claude /tmp/live-newrepo-claude-env.out "$off"
fi
if [[ $CODEX_LIVE == 1 ]]; then
  off="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  live newrepo-codex-env codex mandu '~/newrepo' "$ENV_PROMPT"
  live_env_twin newrepo-codex /tmp/live-newrepo-codex-env.out "$off"
fi
repo_untouched newrepo ~alice/newrepo /tmp/state-newrepo /tmp/mark-newrepo

# ── step 6: a dirty, complex repository, timed ───────────────────────────────
step 6 "a dirty, complex repository: build it"
BIG="$(cat "$ART/BIG_REPO")"
t0=$(now_ms); as_alice "mkdir -p ~/work && git clone -q '$BIG' ~/work/big" > /tmp/clone.out 2>&1; rc=$?
tim big-clone $(( $(now_ms) - t0 )) "$BIG"
if [[ $rc -ne 0 ]]; then
  fail "git clone $BIG rc=$rc"; sed 's/^/        | /' /tmp/clone.out | tail -5
else
  # node_modules where the repo has lockfiles (the first three), no scripts.
  t0=$(now_ms)
  as_alice 'cd ~/work/big && for d in $(git ls-files "*package-lock.json" | sed -n "1,3p" | xargs -rn1 dirname); do (cd "$d" && npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1) || echo "npm ci failed in $d"; done' > /tmp/big-npm.out 2>&1
  tim big-npm-ci $(( $(now_ms) - t0 )) "node_modules in up to 3 packages"
  [[ -s /tmp/big-npm.out ]] && note "$(tr '\n' ' ' < /tmp/big-npm.out)"
  # History: a published snapshot has one commit, and what reads the history
  # (policy suggest, a launch's history scan) needs some. 400 small commits,
  # one of which added a key that a later one deleted.
  t0=$(now_ms)
  as_alice 'cd ~/work/big && set -e
    files=$(git ls-files | grep -E "\.(ts|md)$" | sed -n "1,200p")
    i=0; for f in $files $files; do i=$((i+1))
      printf "\n// change %s\n" $i >> "$f"; git commit -qam "change $i"
      if [ $i -eq 120 ]; then mkdir -p config; printf "AWS_SECRET_ACCESS_KEY=DIRTYCANARYhist0123456789abcdefABCDEF0123\n" > config/old.env; git add -f config/old.env; git commit -qm "add old config"; fi
      if [ $i -eq 180 ]; then git rm -q config/old.env; git commit -qm "drop old config"; fi
    done' > /tmp/big-history.out 2>&1 && pass "400 commits of history, a deleted key among them" || { fail "could not build the history"; tail -5 /tmp/big-history.out | sed 's/^/        | /'; }
  tim big-history $(( $(now_ms) - t0 )) "400 commits"
  as_alice 'cd ~/work/big && set -e
    files=$(git ls-files | grep -E "\.(ts|js|md|sh)$" | head -400)
    i=0; for f in $files; do i=$((i+1))
      case $((i % 8)) in
        0) printf "\n// local edit %s\n" $i >> "$f" ;;
        1) printf "\n// staged edit %s\n" $i >> "$f"; git add "$f"; printf "\n// and edited again %s\n" $i >> "$f" ;;
      esac
    done
    git ls-files | grep -E "\.md$" | sed -n "20,24p" | xargs -r git rm -qf
    git ls-files | grep -E "\.md$" | sed -n "30,32p" | while read -r f; do git mv "$f" "$f.moved"; done
    printf "stashed\n" >> README.md && git stash push -q -m "wip before lunch" README.md
    mkdir -p scratch/notes scratch/config scratch/deep scratch/private
    for n in $(seq 1 600); do d=scratch/notes/n$((n % 30)); mkdir -p $d; printf "note %s\n" $n > $d/note-$n.txt; done
    d=scratch/deep; for n in $(seq 1 40); do d=$d/l$n; done; mkdir -p $d && printf deep > $d/leaf.txt
    head -c 200000000 /dev/urandom > scratch/big.bin
    git init -q scratch/vendor-lib && (cd scratch/vendor-lib && printf x > x && git add x && git commit -qm v)
    printf "OPENAI_API_KEY=sk-proj-DIRTYCANARY0123456789abcdefghij\nDEBUG=1\n" > .env
    printf "DATABASE_URL=postgres://u:DIRTYCANARYpw55555@db/x\n" > scratch/config/.env.production
    ln -s .. scratch/loop; ln -s loop2 scratch/loop1; ln -s loop1 scratch/loop2
    mkfifo scratch/pipe
    printf secret > scratch/private/key && chmod 000 scratch/private
  ' > /tmp/dirty.out 2>&1 && pass "dirtied" || { fail "could not dirty the repo"; tail -10 /tmp/dirty.out | sed 's/^/        | /'; }
  as_alice 'cd ~/work/big && echo "tracked=$(git ls-files | wc -l) commits=$(git rev-list --count HEAD) files=$(find . -xdev 2>/dev/null | wc -l) node_modules_files=$(find . -path "*/node_modules/*" 2>/dev/null | wc -l) size=$(du -sh --exclude=.git . 2>/dev/null | cut -f1) git=$(du -sh .git 2>/dev/null | cut -f1) status_lines=$(git status --porcelain -uall 2>/dev/null | wc -l) stash=$(git stash list | wc -l)"' 2>/dev/null > /tmp/big-stats.out
  BIGSTATS="$(cat /tmp/big-stats.out)"; note "the repo: $BIGSTATS"
  t0=$(now_ms); as_alice 'cd ~/work/big && git status >/dev/null'; tim big-git-status $(( $(now_ms) - t0 )) "one git status, for scale"
  repo_state ~alice/work/big /tmp/state-big; touch /tmp/mark-big; sleep 1

  step 6t "timings: bare against mandu, fresh repo against the dirty one"
  for a in "${AGENTS[@]}"; do
    for r in 1 2 3; do timing "$a" bare '~/work/big' "bare-$a-big-$r"; done
    as_alice 'mandu stop' >/dev/null 2>&1
    timing "$a" mandu '~/work/big' "mandu-$a-big-cold"
    for r in 1 2 3; do timing "$a" mandu '~/work/big' "mandu-$a-big-warm-$r"; done
    as_alice 'mandu stop' >/dev/null 2>&1
    timing "$a" mandu '~/newrepo' "mandu-$a-newrepo-cold"
    for r in 1 2; do timing "$a" mandu '~/newrepo' "mandu-$a-newrepo-warm-$r"; done
    for r in 1 2; do timing "$a" bare '~/newrepo' "bare-$a-newrepo-$r"; done
  done
  # Mandu's own launch steps, from the last launch's log.
  as_alice 'mandu log' > /tmp/mandu-log.out 2>&1 || true
  t0=$(now_ms); as_alice 'cd ~/work/big && timeout 300 mandu doctor --secrets </dev/null' > /tmp/big-doctor-secrets.out 2>&1; rc=$?
  tim big-doctor-secrets $(( $(now_ms) - t0 )) "rc=$rc"
  expect_out "doctor --secrets finds the dirty repo's .env" '\.env' /tmp/big-doctor-secrets.out
  t0=$(now_ms); as_alice 'cd ~/work/big && timeout 600 mandu policy suggest --dry-run </dev/null' > /tmp/big-suggest.out 2>&1; rc=$?
  tim big-policy-suggest $(( $(now_ms) - t0 )) "rc=$rc (git history + files)"
  [[ $rc -eq 124 ]] && fail "mandu policy suggest did not finish in 600s on the dirty repo"
  if grep -Eq 'old\.env|AWS_SECRET_ACCESS_KEY' /tmp/big-suggest.out; then pass "policy suggest names the key that only the history still holds"
  else note "policy suggest did not name the key deleted from the history: $(head -5 /tmp/big-suggest.out | tr '\n' ' ' | cut -c1-200)"; fi
  if [[ $CLAUDE_LIVE == 1 ]]; then
    live big-bare-claude claude bare '~/work/big' "$OKPROMPT"
    live big-mandu-claude claude mandu '~/work/big' "$OKPROMPT"
    expect_out "mandu claude in the dirty repo said OK" 'OK' /tmp/live-big-mandu-claude.out
  fi
  if [[ $CODEX_LIVE == 1 ]]; then
    live big-bare-codex codex bare '~/work/big' "$OKPROMPT"
    live big-mandu-codex codex mandu '~/work/big' "$OKPROMPT"
    expect_out "mandu codex in the dirty repo said OK" 'OK' /tmp/live-big-mandu-codex.out
  fi
  repo_untouched big ~alice/work/big /tmp/state-big /tmp/mark-big
fi

# ── step 7: an existing user upgrades ────────────────────────────────────────
step 7 "upgrade from $FROM"
if [[ "$FROM" == none ]]; then
  note "SKIP: no earlier published version"
else
  new_user bob
  as_user bob 'mkdir -p ~/.aws ~/proj && printf "[default]\naws_secret_access_key = FRESHINSTALLCANARY0123456789abcdef\n" > ~/.aws/credentials && chmod 600 ~/.aws/credentials'
  cv="$(sed -n 's/^claude=//p' "$ART/AGENT_VERSIONS")"
  as_user bob "npm install -g --no-audit --no-fund @mandusec/mandu@$FROM '${PKG[claude]}@${cv:-latest}'" > /tmp/up-old.out 2>&1 \
    && pass "bob: installed mandu $FROM" || { fail "bob: npm install -g @mandusec/mandu@$FROM"; tail -8 /tmp/up-old.out | sed 's/^/        | /'; }
  as_user bob 'LEG_TIMEOUT=300 LEG_NAME=claude-old bash ~/legs/agent-leg.sh claude default' > /tmp/up-leg-old.out 2>&1
  grep -q '^FAIL' /tmp/up-leg-old.out && note "bob: the old version's own leg had failures: $(grep '^FAIL' /tmp/up-leg-old.out | head -2 | tr '\n' ' ')"
  # The old services stay up, as they would for a user who upgrades mid-day.
  t0=$(now_ms); as_user bob "npm install -g --no-audit --no-fund $(install_spec "$VER")" > /tmp/up-new.out 2>&1; rc=$?
  tim upgrade-install $(( $(now_ms) - t0 )) "$FROM -> $VER"
  [[ $rc -eq 0 ]] && pass "bob: upgraded to $VER" || { fail "bob: upgrade rc=$rc"; tail -8 /tmp/up-new.out | sed 's/^/        | /'; }
  as_user bob 'mandu --version' > /tmp/up-version.out 2>&1
  expect_out "bob: mandu --version is $VER" "^mandu $VER\$" /tmp/up-version.out
  as_user bob 'mandu version' > /tmp/up-mversion.out 2>&1
  sed 's/^/        | /' /tmp/up-mversion.out | head -10
  as_user bob 'LEG_TIMEOUT=300 LEG_NAME=claude-new bash ~/legs/agent-leg.sh claude default' > /tmp/up-leg-new.out 2>&1
  forward /tmp/up-leg-new.out
  as_user bob 'mandu doctor' > /tmp/up-doctor.out 2>&1
  expect_out "bob: doctor after the upgrade: posture $STORY" "posture: $STORY" /tmp/up-doctor.out
  as_user bob 'mandu stop --all' >/dev/null 2>&1
fi

# ── step 7b: the README's other route, for a user with no Node ───────────────
# `curl … install.sh | sh` from the public repository (a pinned Node for
# Mandu alone, then npm's latest), and the GitHub release's own install.sh,
# whose PACKAGE_DEFAULT names the release tarball and its SHA-256. One
# version, one artifact across channels (packaging.md §11): both must
# install <v>, and the release tarball must be npm's bytes.
step 7b "no Node: the curl | sh installers"
if [[ $PKG_KIND != registry ]]; then
  note "SKIP: a candidate tarball is not on npm or GitHub yet (the registry run after publish covers this)"
else
  as_alice "cd /tmp && rm -f mandusec-mandu-$VER.tgz && npm pack -q @mandusec/mandu@$VER >/dev/null 2>&1 && sha256sum mandusec-mandu-$VER.tgz | cut -d' ' -f1" > /tmp/npm-sha256.out 2>&1
  NPM_SHA256="$(tail -1 /tmp/npm-sha256.out)"
  for u in carol dave; do useradd -m -s /bin/bash "$u"; done
  t0=$(now_ms)
  as_user carol 'curl -fsSL https://raw.githubusercontent.com/mandusec/mandu/main/scripts/install.sh | sh' > /tmp/curl-main.out 2>&1; rc=$?
  tim curl-install-main $(( $(now_ms) - t0 )) "raw main install.sh, rc=$rc"
  [[ $rc -eq 0 ]] && pass "carol (no Node): the README's curl | sh exit 0" || { fail "carol: curl | sh rc=$rc"; tail -10 /tmp/curl-main.out | sed 's/^/        | /'; }
  as_user carol '~/.local/bin/mandu --version' > /tmp/curl-main-version.out 2>&1
  expect_out "carol: the README's installer gives mandu $VER" "^mandu $VER\$" /tmp/curl-main-version.out
  as_user carol 'curl -fsSLO https://github.com/ManduSec/mandu/releases/latest/download/install.sh && grep "^PACKAGE_DEFAULT" install.sh' > /tmp/rel-install.out 2>&1
  expect_out "the latest GitHub release's installer names the $VER tarball" "^PACKAGE_DEFAULT=.*mandusec-mandu-$VER\\.tgz" /tmp/rel-install.out
  if [[ -n "$NPM_SHA256" ]] && grep -q "^PACKAGE_DEFAULT_SHA256=\"$NPM_SHA256\"" /tmp/rel-install.out; then
    pass "GitHub's release tarball is npm's bytes (sha256 ${NPM_SHA256:0:12}…)"
  else fail "GitHub's release tarball SHA-256 is not npm's (npm: ${NPM_SHA256:-unknown}; $(grep '^PACKAGE_DEFAULT_SHA256' /tmp/rel-install.out))"; fi
  t0=$(now_ms)
  as_user dave 'curl -fsSL https://github.com/ManduSec/mandu/releases/latest/download/install.sh | sh' > /tmp/curl-rel.out 2>&1; rc=$?
  tim curl-install-release $(( $(now_ms) - t0 )) "GitHub latest release install.sh, rc=$rc"
  as_user dave '~/.local/bin/mandu --version' > /tmp/curl-rel-version.out 2>&1
  expect_out "dave: the GitHub release's installer gives mandu $VER" "^mandu $VER\$" /tmp/curl-rel-version.out
  as_user dave '~/.local/bin/mandu doctor' > /tmp/curl-rel-doctor.out 2>&1
  expect_out "dave: doctor after the curl install: posture $STORY" "posture: $STORY" /tmp/curl-rel-doctor.out
fi

# ── step 8: hygiene ──────────────────────────────────────────────────────────
step 8 "hygiene: reap, processes, uninstall"
as_alice 'mandu stop' >/dev/null 2>&1
as_alice 'mandu reap --dry-run' > /tmp/reap.out 2>&1
# A session that ended non-zero keeps its scope dir for diagnosis, and the
# `current` link to it (launcher scope-dir-cleanup.ts): reap's to collect, a
# NOTE. Anything else reap would collect (an orphan arbiter, a dead instance
# record) is a FAIL. After `mandu reap`, nothing is left.
if grep -q '^nothing to reap' /tmp/reap.out; then pass "mandu reap --dry-run: nothing to reap"
else
  n="$(grep -c '^  would rm-stale-scope-dir' /tmp/reap.out)"
  [[ $n -gt 0 ]] && note "reap would collect $n scope dir(s) of sessions that ended non-zero (kept by design)"
  grep -q '^  would rm-dangling-current' /tmp/reap.out && note "reap would remove the dangling current link (the arbiter removed its instance dir at mandu stop)"
  if grep '^  would ' /tmp/reap.out | grep -Evq '^  would (rm-stale-scope-dir|rm-dangling-current)'; then
    fail "reap would collect more than failed sessions' scope dirs: $(grep '^  would ' /tmp/reap.out | grep -Ev 'rm-stale-scope-dir|rm-dangling-current' | tr '\n' ';')"
  fi
  as_alice 'mandu reap' > /tmp/reap-do.out 2>&1
  as_alice 'mandu reap --dry-run' > /tmp/reap-after.out 2>&1
  expect_out "after mandu reap, nothing is left to reap" '^nothing to reap' /tmp/reap-after.out
fi
sleep 2
ps -u alice -o pid=,args= 2>/dev/null | grep -Ev '(systemd --user|\(sd-pam\))$' > /tmp/procs.out || true
expect_no "no alice process outlives mandu stop" 'mandu|arbiter|proxy|node' /tmp/procs.out
as_alice 'npm uninstall -g @mandusec/mandu' > /tmp/uninstall.out 2>&1 && pass "npm uninstall -g exit 0" || fail "npm uninstall -g"
as_alice 'command -v mandu || echo gone' > /tmp/gone.out 2>&1
expect_out "mandu is gone from PATH" '^gone$' /tmp/gone.out
find /home/alice -xdev | sort > /tmp/home-after
note "what stays in alice's HOME after uninstall (Mandu's state, by design): $(comm -13 /tmp/home-before /tmp/home-after | grep -E '/\.(mandu|config/mandu|local/state/mandu|cache/mandu)$' | tr '\n' ' ')"

# ── the report ───────────────────────────────────────────────────────────────
for f in /home/alice/.anthropic.key /home/alice/.openai.key /home/alice/.claude/.credentials.json /home/alice/.codex/auth.json; do
  [[ -e $f ]] && { shred -u "$f" 2>/dev/null || rm -f "$f"; }
done
med() { grep -P "^$1\t" "$TIMINGS" | cut -f2 | sort -n | awk '{a[NR]=$1} END {if (NR) print a[int((NR+1)/2)]; else print ""}'; }
secs() { [[ -n "$1" ]] && awk -v m="$1" 'BEGIN {printf "%.1fs", m/1000}' || echo "—"; }
{
  echo "# npm-release: $PKG_KIND $PKG_REF on $(. /etc/os-release; echo "$PRETTY_NAME")"
  echo
  echo "Version $VER, kernel $(uname -r), $(nproc) CPUs. $(grep -c '^PASS' "$STEPLOG") checks passed, $FAILS failed, $(grep -c '^NOTE' "$STEPLOG") notes."
  echo
  echo "Dirty repo: ${BIGSTATS:-not built}"
  echo
  echo "| scripted-model launch (median) | bare | mandu cold | mandu warm | overhead (warm − bare) |"
  echo "|---|---|---|---|---|"
  for a in "${AGENTS[@]}"; do
    for r in big newrepo; do
      b="$(med "bare-$a-$r-[0-9]")"; c="$(med "mandu-$a-$r-cold")"; w="$(med "mandu-$a-$r-warm-[0-9]")"
      o="—"; [[ -n "$b" && -n "$w" ]] && o="$(secs $(( w - b )))"
      echo "| $a, $( [[ $r == big ]] && echo dirty repo || echo fresh repo ) | $(secs "$b") | $(secs "$c") | $(secs "$w") | $o |"
    done
  done
  echo
  echo "| step | time |"; echo "|---|---|"
  grep -vP '^(name|bare-|mandu-)' "$TIMINGS" | while IFS=$'\t' read -r n ms d; do echo "| $n${d:+ ($d)} | $(secs "$ms") |"; done
  echo
  if [[ $FAILS -gt 0 ]]; then echo "## Failures"; grep '^FAIL' "$STEPLOG" | sed 's/^FAIL /- /'; echo; fi
  echo "## Notes"; grep '^NOTE' "$STEPLOG" | sed 's/^NOTE /- /'
} > "$REPORT" 2>/dev/null
echo; cat "$REPORT"

# Evidence for post-mortems (never the credentials).
mkdir -p "$OUTD/legs" && cp -r /home/alice/agent-legs/. /home/alice/timing-legs/. "$OUTD/legs/" 2>/dev/null || true
cp -r "$ALICE_RT/logs" "$OUTD/alice-logs" 2>/dev/null || true
cp /tmp/*.out /tmp/*.err "$OUTD/" 2>/dev/null || true

echo
echo "npm-release: $FAILS failing check(s)"
[[ $FAILS -eq 0 ]]
