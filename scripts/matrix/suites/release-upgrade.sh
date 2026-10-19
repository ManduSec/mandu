#!/usr/bin/env bash
# deps:
# boots: 4
# min-timeout: 10800
# release-upgrade — a REAL `do-release-upgrade` 24.04 → 26.04 under an installed
# Mandu (os-test-matrix.md §10.15; rootless-confinement-ubuntu-2404.md
# §12.3 had only a file-copy reproduction). Runs as root in an ubuntu-2404
# guest across three boots (os-test-matrix.md §2.1; the suite exits 75 to ask
# for a reboot and reads its phase back from disk):
#   boot 1  apt full-upgrade (do-release-upgrade refuses a host with pending
#           updates or a pending reboot)
#   boot 2  install the packed bundle as alice the way fresh-install does, set
#           it up (today's `mandu setup`, or a pre-2026-09-27 host's old grants
#           when RELEASE_UPGRADE_FROM=legacy), prove it confined, then run
#           do-release-upgrade non-interactively
#   boot 3  on 26.04: what the upgraded host looks like before the user does
#           anything (doctor, a confined launch, Ubuntu's own rules), then
#           `mandu setup` and the same checks again
# Host prep (release-upgrade.host.sh) put the tarball, the stub agent and the
# UPGRADE knobs in /mnt/artifacts.
set -uo pipefail

ART=/mnt/artifacts
STATE=/var/lib/mandu-matrix/release-upgrade
STEPLOG=/mnt/out/steps.log
mkdir -p "$STATE"
PHASE="$(cat "$STATE/phase" 2>/dev/null || echo prepare)"
[[ "${MATRIX_RESUME:-0}" == 1 ]] || { [[ $PHASE == prepare ]] && : > "$STEPLOG"; }

step() { echo; echo "──── step $1: $2"; CUR="$1"; }
pass() { echo "  PASS  $1"; echo "PASS step=$CUR $1" >> "$STEPLOG"; }
fail() { echo "  FAIL  $1"; echo "FAIL step=$CUR $1" >> "$STEPLOG"; }
note() { echo "  note  $1"; echo "NOTE step=$CUR $1" >> "$STEPLOG"; }
expect_out() {
  if grep -Eq -- "$2" "$3"; then pass "$1"; else fail "$1 (wanted /$2/)"; sed 's/^/        | /' "$3" | head -40; fi
}
expect_no() {
  if grep -Eq -- "$2" "$3"; then fail "$1 (found /$2/)"; sed 's/^/        | /' "$3" | head -40; else pass "$1"; fi
}
next_boot() { echo "$1" > "$STATE/phase"; sync; echo "release-upgrade: phase $1 on the next boot"; exit 75; }
finish_suite() {
  cp /tmp/*.out /mnt/out/ 2>/dev/null || true
  cp -r /run/user/"$(id -u alice 2>/dev/null)"/mandu/logs /mnt/out/alice-logs 2>/dev/null || true
  local n; n="$(grep -c '^FAIL' "$STEPLOG" 2>/dev/null)"; n="${n:-0}"
  echo; echo "release-upgrade: $n failing check(s) over every boot"
  [[ $n -eq 0 ]]
  exit $?
}
knob() { sed -n "s/^$1=//p" "$ART/UPGRADE" 2>/dev/null | head -1; }
FROM="$(knob from)"; FROM="${FROM:-current}"
UPATH="$(knob path)"; UPATH="${UPATH:-auto}"

umount /mnt/reposrc 2>/dev/null || true
chmod 0700 /root
as_alice() {
  runuser -l alice -c "export NVM_DIR=\$HOME/.nvm; [ -s \$NVM_DIR/nvm.sh ] && . \$NVM_DIR/nvm.sh; export PATH=\$HOME/bin:\$PATH; cd \$HOME; $*"
}
APT=(apt-get -o DPkg::Lock::Timeout=900 -o Acquire::Retries=5)
export DEBIAN_FRONTEND=noninteractive
facts() {  # the release-level facts every phase records
  note "os: $(. /etc/os-release; echo "$PRETTY_NAME")  kernel: $(uname -r)  apparmor_restrict_unprivileged_userns=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo n/a)"
  note "system bwrap: $(/usr/bin/bwrap --version 2>/dev/null || echo absent)  Mandu's copy: $(/usr/lib/mandu/bin/bwrap --version 2>/dev/null || echo absent)  apparmor: $(dpkg-query -W -f='${Version}' apparmor 2>/dev/null)"
  note "profiles loaded: $(aa-status 2>/dev/null | grep -Eo '^\s+(bwrap|unpriv_bwrap|unshare|mandu_bwrap|mandu_child)$' | tr -d ' ' | sort -u | tr '\n' ' ')"
  note "/etc/apparmor.d bwrap files: $(ls /etc/apparmor.d 2>/dev/null | grep -E '^(bwrap|unshare|mandu-bwrap|bwrap-userns-restrict)$' | tr '\n' ' ')"
}
# launch <tag>: a confined launch of the stub agent; leaves /tmp/launch-<tag>.out
# and the stub report in /tmp/report-<tag>.out, asserts the confidentiality
# oracle fail-closed.
launch() {
  as_alice "cd ~/proj && rm -f ~/stub-report && timeout 180 mandu --confidentiality --require-confinement claude -p hello </dev/null" > "/tmp/launch-$1.out" 2>&1; local rc=$?
  cp /home/alice/stub-report "/tmp/report-$1.out" 2>/dev/null || : > "/tmp/report-$1.out"
  [[ $rc -eq 0 ]] && pass "confined launch (--require-confinement) exit 0" || { fail "confined launch rc=$rc"; sed 's/^/        | /' "/tmp/launch-$1.out" | head -30; }
  local got; got="$(sed -n 's/^secret_read=//p' "/tmp/report-$1.out")"
  case "$got" in
    other|denied) pass "the agent did NOT read the canary (secret_read=$got)" ;;
    canary)       fail "CONFIDENTIALITY: the agent read the raw canary" ;;
    *)            fail "no parsable stub report (fail-closed)" ;;
  esac
  note "inside the agent: $(grep -E '^(nest|bwrap_path)=' "/tmp/report-$1.out" | tr '\n' ' ')"
  sed 's/^/        | /' "/tmp/launch-$1.out" | grep -iv '^\s*|\s*$' | head -12
}
# Ubuntu's own rules, as the unprivileged user (they are the host's, not Mandu's).
host_rules() {
  as_alice 'unshare -Ur true' >/dev/null 2>&1 \
    && fail "any program gets a user namespace through unshare (Ubuntu's restriction is off)" \
    || pass "unshare -Ur is refused for an ordinary program (Ubuntu's restriction holds)"
  if [[ -f /etc/apparmor.d/bwrap-userns-restrict ]]; then
    as_alice '/usr/bin/bwrap --dev-bind / / -- /usr/bin/bwrap --unshare-user --ro-bind / / -- true' >/dev/null 2>&1 \
      && fail "a bwrap starts inside the system bwrap (Ubuntu's no-nesting rule is off)" \
      || pass "Ubuntu's no-nesting rule is in force (no bwrap inside the system bwrap)"
  fi
}

case "$PHASE" in
# ── boot 1: bring 24.04 up to date ───────────────────────────────────────────
prepare)
  step 0 "baseline: an up-to-date 24.04 (scenario from=$FROM path=$UPATH)"
  [[ "$(. /etc/os-release; echo "$VERSION_ID")" == 24.04 ]] || { fail "this suite starts on Ubuntu 24.04 (target ubuntu-2404)"; finish_suite; }
  [[ -f "$ART/UPGRADE" ]] && ls "$ART"/mandusec-mandu-*.tgz >/dev/null 2>&1 || { fail "no tarball / UPGRADE knobs in $ART"; finish_suite; }
  echo "  commit under test: $(cat "$ART/COMMIT" 2>/dev/null)"
  "${APT[@]}" update -q > /tmp/apt-update.out 2>&1
  "${APT[@]}" -y -q full-upgrade > /tmp/full-upgrade.out 2>&1 && pass "apt full-upgrade" || { fail "apt full-upgrade"; tail -20 /tmp/full-upgrade.out; finish_suite; }
  "${APT[@]}" -y -q install bubblewrap ubuntu-release-upgrader-core > /tmp/apt-bwrap.out 2>&1 \
    && pass "bubblewrap and the release upgrader installed" || { fail "apt install bubblewrap ubuntu-release-upgrader-core"; finish_suite; }
  facts
  next_boot install
  ;;

# ── boot 2: Mandu on 24.04, then the upgrade ─────────────────────────────────
install)
  step 1 "install Mandu as alice"
  TARBALL="$(ls "$ART"/mandusec-mandu-*.tgz | head -1)"
  useradd -m -s /bin/bash alice
  echo 'alice ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-alice; chmod 0440 /etc/sudoers.d/90-alice
  install -o alice -g alice -m 0644 "$TARBALL" /home/alice/
  install -o alice -g alice -m 0755 -d /home/alice/bin
  install -o alice -g alice -m 0755 "$ART/claude" /home/alice/bin/claude
  as_alice 'curl -fsSo- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash >/dev/null 2>&1; . $HOME/.nvm/nvm.sh; nvm install 22 >/dev/null 2>&1; node --version' > /tmp/node.out 2>&1
  expect_out "node 22 under alice's HOME" '^v22\.' /tmp/node.out
  as_alice "npm install -g --no-audit --no-fund ~/$(basename "$TARBALL")" > /tmp/install.out 2>&1 \
    && pass "npm install -g" || { fail "npm install -g"; tail -20 /tmp/install.out; finish_suite; }
  as_alice 'mkdir -p ~/.aws ~/proj && printf "[default]\naws_secret_access_key = FRESHINSTALLCANARY0123456789abcdef\n" > ~/.aws/credentials && chmod 600 ~/.aws/credentials'
  facts

  if [[ $FROM == current ]]; then
    step 2 "today's mandu setup"
    as_alice 'mandu setup --yes </dev/null' > /tmp/setup-pre.out 2>&1 && pass "setup --yes exit 0" || { fail "setup --yes"; tail -20 /tmp/setup-pre.out; }
    [[ -f /etc/apparmor.d/mandu-bwrap && -f /usr/lib/mandu/bin/bwrap ]] && pass "Mandu's own bubblewrap and profile installed" || fail "setup left no copy/profile"
  else
    step 2 "a pre-2026-09-27 host: the old grants, as the old mandu setup left them"
    # Byte-for-byte what `mandu setup` wrote until 2026-09-27 (fresh-install step 10).
    printf '# Mandu: grant bubblewrap the right to create an unprivileged user namespace\nabi <abi/4.0>,\ninclude <tunables/global>\n\nprofile bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n\n  include if exists <local/bwrap>\n}\n' > /etc/apparmor.d/bwrap
    printf '# Mandu: the same grant for util-linux unshare\nabi <abi/4.0>,\ninclude <tunables/global>\n\nprofile unshare /usr/bin/unshare flags=(unconfined) {\n  userns,\n\n  include if exists <local/unshare>\n}\n' > /etc/apparmor.d/unshare
    apparmor_parser -r /etc/apparmor.d/bwrap /etc/apparmor.d/unshare && pass "old grants loaded" || fail "old grants failed to load"
  fi
  step 3 "on 24.04: doctor + a confined launch"
  as_alice 'mandu doctor' > /tmp/doctor-pre.out 2>&1
  expect_out "posture: confined" 'posture: confined' /tmp/doctor-pre.out
  [[ $FROM == current ]] && expect_out "doctor names Mandu's own bubblewrap" "Mandu's own bubblewrap: installed" /tmp/doctor-pre.out
  [[ $FROM == legacy ]] && expect_out "doctor flags the old grant" 'older Mandu grant is still installed' /tmp/doctor-pre.out
  launch pre
  as_alice 'command -v mandu; mandu --version' > /tmp/mandu-pre.out 2>&1

  step U "do-release-upgrade 24.04 → 26.04"
  grep -E '^Prompt=' /etc/update-manager/release-upgrades > /tmp/prompt.out 2>&1; note "$(cat /tmp/prompt.out)"
  do-release-upgrade -c > /tmp/dru-check.out 2>&1; note "regular LTS path (do-release-upgrade -c): $(grep -Eim1 "new release|no new|no development|not available" /tmp/dru-check.out || tail -1 /tmp/dru-check.out)"
  flag=()
  case "$UPATH" in
    regular)     ;;
    development) flag=(-d) ;;
    proposed)    flag=(-p) ;;
    auto)        grep -qi "New release '26\.04" /tmp/dru-check.out || flag=(-d) ;;
  esac
  echo "path=${flag[*]:-regular}" > "$STATE/path"
  note "upgrade path taken: do-release-upgrade ${flag[*]:-(regular)}"
  t0=$(date +%s)
  do-release-upgrade -f DistUpgradeViewNonInteractive "${flag[@]}" > /mnt/out/do-release-upgrade.log 2>&1; rc=$?
  note "do-release-upgrade rc=$rc in $(( $(date +%s) - t0 ))s"
  cp /var/log/dist-upgrade/main.log /mnt/out/dist-upgrade-main.log 2>/dev/null || true
  if [[ "$(grep -h '^VERSION_ID=' /etc/os-release | cut -d'"' -f2)" == 26.04 ]]; then
    pass "the disk now carries 26.04 (reboot pending)"
  else
    fail "do-release-upgrade did not bring the host to 26.04"; tail -30 /mnt/out/do-release-upgrade.log | sed 's/^/        | /'; finish_suite
  fi
  next_boot after
  ;;

# ── boot 3: 26.04, as the upgrade left it, then after mandu setup ────────────
after)
  step 4 "the upgraded host (path: $(cat "$STATE/path" 2>/dev/null))"
  [[ "$(. /etc/os-release; echo "$VERSION_ID")" == 26.04 ]] && pass "booted 26.04 ($(uname -r))" || { fail "not 26.04 after the reboot"; finish_suite; }
  facts
  as_alice 'mandu --version' > /tmp/mandu-post.out 2>&1 && pass "the installed mandu still runs (nvm node in alice's HOME)" || { fail "mandu no longer runs"; cat /tmp/mandu-post.out; finish_suite; }
  stale=0; cmp -s /usr/lib/mandu/bin/bwrap /usr/bin/bwrap 2>/dev/null || { [[ -f /usr/lib/mandu/bin/bwrap ]] && stale=1; }
  if [[ -f /usr/lib/mandu/bin/bwrap ]]; then
    as_alice '/usr/lib/mandu/bin/bwrap --unshare-user --unshare-net --ro-bind / / -- true' >/dev/null 2>&1 \
      && note "Mandu's 24.04 copy still starts a sandbox on 26.04 (its profile still loads)" \
      || note "Mandu's 24.04 copy no longer starts a sandbox on 26.04"
  fi

  step 5 "before the user does anything: doctor"
  as_alice 'mandu doctor' > /tmp/doctor-post.out 2>&1
  expect_out "posture: confined (the guard at least)" 'posture: confined' /tmp/doctor-post.out
  if [[ $FROM == current && $stale -eq 1 ]]; then
    expect_out "doctor says the copy is older and names mandu setup" 'older than /usr/bin/bwrap.*mandu setup' /tmp/doctor-post.out
  fi
  if [[ $FROM == legacy ]]; then
    expect_out "doctor flags the old grant" 'older Mandu grant is still installed' /tmp/doctor-post.out
    expect_out "doctor names the host-wide override (26.04 ships Ubuntu's own bwrap profile)" "shares the name of Ubuntu's own .bwrap. profile" /tmp/doctor-post.out
    # The real upgrade loads Ubuntu's `bwrap` over Mandu's but keeps Mandu's
    # `unshare` grant: that one is the live hole, so it must be named.
    [[ -f /etc/apparmor.d/unshare ]] && expect_out "doctor names the unshare grant's own hazard" 'unshare one lets every program on this machine create a user namespace through unshare' /tmp/doctor-post.out
  fi
  sed 's/^/        | /' /tmp/doctor-post.out | grep -Ei 'posture|bubblewrap|grant|mount layer|guard|fix|setup' | head -20

  step 6 "before the user does anything: a launch"
  launch post
  if [[ $FROM == current && $stale -eq 1 ]]; then
    expect_out "the launch WARNS that the copy is not the system's, naming both versions and mandu setup" "WARNING .*Mandu's own bubblewrap \(/usr/lib/mandu/bin/bwrap, bubblewrap [0-9.]+\) is not the system's \(/usr/bin/bwrap, bubblewrap [0-9.]+\).*fix: mandu setup" /tmp/launch-post.out
  fi
  if [[ $FROM == legacy ]]; then
    expect_out "the launch WARNS about the old grant" 'WARNING .*older Mandu grant' /tmp/launch-post.out
    [[ -f /etc/apparmor.d/unshare ]] && expect_out "the launch names the unshare grant's own hazard" 'WARNING .*through unshare; fix: mandu setup' /tmp/launch-post.out
  fi

  step 7 "Ubuntu's own rules on the upgraded host, before mandu setup"
  if [[ $FROM == legacy ]]; then
    # The old grant shares its profile NAME with Ubuntu's; which one is loaded
    # after the upgrade is what §12.3 asked about. Recorded, then fixed by setup.
    as_alice 'unshare -Ur true' >/dev/null 2>&1 && note "the old unshare grant is in force: unshare -Ur works for any program" || note "unshare -Ur refused"
    as_alice '/usr/bin/bwrap --dev-bind / / -- /usr/bin/bwrap --unshare-user --ro-bind / / -- true' >/dev/null 2>&1 \
      && note "OLD GRANT WON: a bwrap starts inside the system bwrap (Ubuntu's no-nesting rule is off)" \
      || note "Ubuntu's no-nesting rule is in force"
  else
    host_rules
  fi

  step 8 "mandu setup on 26.04"
  as_alice 'mandu setup --yes </dev/null' > /tmp/setup-post.out 2>&1 && pass "setup --yes exit 0" || { fail "setup --yes"; sed 's/^/        | /' /tmp/setup-post.out | tail -20; }
  cmp -s /usr/lib/mandu/bin/bwrap /usr/bin/bwrap && pass "Mandu's copy is the 26.04 bwrap now" || fail "Mandu's copy was not refreshed"
  aa-status 2>/dev/null | grep -Eq '^\s+mandu_bwrap$' && aa-status 2>/dev/null | grep -Eq '^\s+mandu_child$' \
    && pass "mandu_bwrap and mandu_child loaded" || fail "Mandu's profiles not loaded"
  [[ ! -e /etc/apparmor.d/bwrap && ! -e /etc/apparmor.d/unshare ]] && pass "no old grant file left" || fail "an old grant file remains"
  aa-status 2>/dev/null | grep -Eq '^\s+unpriv_bwrap$' && pass "Ubuntu's own bwrap profiles are loaded" || fail "Ubuntu's bwrap profiles are not loaded"
  host_rules
  b=/usr/lib/mandu/bin/bwrap
  as_alice "$b --dev-bind / / -- /usr/bin/bwrap --unshare-user --unshare-pid --unshare-net --ro-bind / / -- true" >/tmp/nest.out 2>&1 \
    && pass "a sandbox starts inside Mandu's bubblewrap" || { fail "nesting inside Mandu's bubblewrap"; sed 's/^/        | /' /tmp/nest.out; }
  as_alice "$b --dev-bind / / -- unshare -Ur true" >/dev/null 2>&1 \
    && fail "TRAMPOLINE: a program inside Mandu's bubblewrap got a user namespace" || pass "no trampoline through Mandu's bubblewrap"
  facts

  step 9 "after setup: doctor + launch"
  as_alice 'mandu doctor' > /tmp/doctor-final.out 2>&1
  expect_out "posture: confined" 'posture: confined' /tmp/doctor-final.out
  expect_no  "both layers (not the guard alone)" 'by the guard alone' /tmp/doctor-final.out
  expect_out "doctor names Mandu's own bubblewrap" "Mandu's own bubblewrap: installed" /tmp/doctor-final.out
  expect_no  "no stale-copy row" 'older than /usr/bin/bwrap' /tmp/doctor-final.out
  expect_no  "no old-grant row" 'older Mandu grant' /tmp/doctor-final.out
  launch final
  expect_no  "no bubblewrap WARNING on the launch" "WARNING .*(bubblewrap|grant)" /tmp/launch-final.out
  grep -q '^nest=ok' /tmp/report-final.out && pass "the agent can start a sandbox of its own (nest=ok)" || fail "the agent cannot nest a sandbox after setup ($(grep '^nest=' /tmp/report-final.out))"
  finish_suite
  ;;
*) fail "unknown phase '$PHASE'"; finish_suite ;;
esac
