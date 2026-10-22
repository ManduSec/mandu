#!/usr/bin/env bash
# boot.sh — the CI guest's one job (docs/design/testing/continuous-integration.md §3).
# Installed by provision.sh as /usr/local/lib/mandu-ci/boot.sh and run as root
# by mandu-ci.service at every boot of the CI image:
#
#   1. find the input and output disks by their virtio serials
#      (/dev/disk/by-id/virtio-mandu-in, virtio-mandu-out); mount nothing of
#      the host (there is nothing of the host to mount);
#   2. kernel.apparmor_restrict_unprivileged_userns=0 (the sandbox suites' plain
#      `unshare --user` and bwrap work as on an unrestricted host), and
#      net.ipv4.ip_unprivileged_port_start=80 (a live drill run's sink listens
#      on :80 and :443 as `ci`, continuous-integration.md §9.9);
#   3. read job.env from the input tar AS DATA (KEY=value, a fixed key list, a
#      narrow character set), unpack src/ over /work/mandu (where the image
#      keeps its warm node_modules and interceptors/target) as user `ci`;
#      then map the demo drills' named hosts to the sink's loopback address in
#      /etc/hosts: the drill tree's catalog/guest-hosts (found with
#      scripts/drill-tree.mjs, read as `ci`, AS DATA: `<slot> <host>` a
#      line), `192.0.2.<slot> <host>` each (map_guest_hosts; a checkout
#      without a drill tree maps nothing; a slot per demo drill), each such
#      TEST-NET address's :80 and :443 redirected to 127.0.0.<slot>
#      (redirect_sink, nftables);
#   4. delegate a cgroup to `ci` (delegate_cgroup: the shape a desktop
#      session gives a user), then run scripts/ci/pipeline.sh as `ci` in
#      it (MANDU_CI_MODE run, selftest or
#      exec), then write /work/out as a tar straight onto the output disk
#      (`tar -c -f /dev/disk/by-id/virtio-mandu-out`) and power off.
#
# The nightly (vm-run.sh --network / --ollama / --credential, continuous-integration.md
# §9): MANDU_CI_NETWORK or MANDU_CI_OLLAMA → wait for the NIC's address and
# pass --network / --ollama on; MANDU_CI_CREDENTIAL lists the kinds on the
# read-only disk virtio-mandu-cred (`claude`, `codex`, `claude,codex` or
# `api`), each placed in the CI user's home (0600, owner ci, the files
# below): claude, refusing one that carries a refresh token; codex, refusing
# one that holds a refresh token (pipeline.sh exports its path as
# MANDU_CI_CODEX_AUTH for the ChatGPT-sign-in suites, §9.8); api, refusing
# anything but the anthropic / openai keys (pipeline.sh exports them for the
# API lane, §9.8); the tool kinds (§9.8 "Tool credentials"), docker and
# gitguardian, nothing but their fields (pipeline.sh exports their PATHS,
# MANDU_CI_DOCKER_AUTH and MANDU_CI_GITGUARDIAN_AUTH, for the demo lane's
# baselines). Each is deleted again before the results are written. Their
# bytes are never printed. MANDU_CI_LANE → pipeline.sh --lane. The demo
# battery's choices (MANDU_DEMO_IDS, MANDU_DEMO_SIDES, MANDU_DEMO_MODELS,
# MANDU_DEMO_REPEAT, MANDU_DEMO_JOBS, MANDU_DEMO_AGENTS, §9.9) reach the pipeline's environment when set.
#
# Not running: the kernel command line `mandu.ci=off`, or MANDU_CI_MODE=shell,
# which unpacks the checkout and gives the serial console a login shell as
# `ci` in /work/mandu instead (vm-run.sh --shell); the guest powers off when
# that shell exits.
set -uo pipefail

IN=/dev/disk/by-id/virtio-mandu-in
OUT=/dev/disk/by-id/virtio-mandu-out
WORK=/work
TREE=$WORK/mandu
RESULTS=$WORK/out
JOB=/run/mandu-ci
CI_USER=ci
BWRAP_CI=/usr/local/lib/mandu-ci/bwrap
MTIME_MANIFEST=/var/lib/mandu-ci/src.sha256
FIXED_MTIME=946684800   # 2000-01-01: provision.sh stamps every source file with it

say() { echo "mandu-ci: $*"; }
uptime_s() { cut -d' ' -f1 /proc/uptime; }
off() { sync; say "powering off (uptime $(uptime_s)s)"; systemctl poweroff --no-block; exit 0; }

# budget_plan <budget> <uptime> <now>: the guest's two deadlines from
# vm-run.sh's MANDU_CI_BUDGET (seconds of uptime by which the pipeline must
# be over, its timeout less a margin: continuous-integration.md §3), as
# "<the suites' deadline, epoch seconds> <the watchdog's delay, seconds>". The
# watchdog fires at the budget; the suites' deadline comes a tenth of the
# budget (at most 150 s) before it, for the runner to stop what still runs,
# write its summary and the pipeline to end. Returns 1 when the budget is
# spent already.
budget_plan() {
  local budget="$1" up="${2%.*}" now="$3" left tail
  left=$((budget - up))
  ((left > 0)) || return 1
  tail=$((budget / 10)); ((tail > 150)) && tail=150
  echo "$((now + left - tail)) $left"
}
# watchdog <delay>: the backstop behind the runner's deadline (a build that
# hangs, a runner that does not stop): after <delay> seconds every process of
# CI_USER gets SIGTERM, then SIGKILL, and the pipeline's end below writes what
# there is to the output disk before the host's timeout would kill the guest
# with nothing (pipelines 10978, 11050 and 11099).
watchdog() {
  sleep "$1"
  : > "$JOB/watchdog"
  say "watchdog: the pipeline still runs at the budget (${J[MANDU_CI_BUDGET]}s of uptime): stopping every process of $CI_USER"
  pkill -TERM -u "$CI_USER"
  for _ in $(seq 1 20); do pgrep -u "$CI_USER" >/dev/null || break; sleep 1; done
  pkill -KILL -u "$CI_USER"
}

say "service start at uptime $(uptime_s)s; kernel $(uname -r)"
if grep -qw 'mandu.ci=off' /proc/cmdline; then say "mandu.ci=off on the kernel command line: not running"; exit 0; fi

for _ in $(seq 1 60); do [[ -b $IN ]] && break; udevadm settle -t 1 2>/dev/null; sleep 0.5; done
if [[ ! -b $IN ]]; then say "no input disk ($IN): nothing to run"; exit 0; fi

sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0 2>/dev/null || true
sysctl -q -w net.ipv4.ip_unprivileged_port_start=80 2>/dev/null || true

# ── job.env, as data ───────────────────────────────────────────────────────
mkdir -p "$JOB"
if ! tar -x -f "$IN" -C "$JOB" --no-same-owner --no-same-permissions job.env; then
  say "the input disk holds no job.env"; off
fi
declare -A J=()
KEYS=" MANDU_CI_MODE MANDU_CI_KINDS MANDU_CI_NEED MANDU_CI_ONLY MANDU_CI_JOBS MANDU_CI_RUN_ID MANDU_CI_SOURCE MANDU_CI_COMMIT MANDU_CI_REF MANDU_CI_IMAGE MANDU_CI_EXEC_B64 MANDU_CI_NETWORK MANDU_CI_OLLAMA MANDU_CI_CREDENTIAL MANDU_CI_INCLUDE_FLAKY MANDU_CI_INCLUDE_INTERNET MANDU_CI_LANE MANDU_CI_BUDGET MANDU_DEMO_IDS MANDU_DEMO_SIDES MANDU_DEMO_MODELS MANDU_DEMO_REPEAT MANDU_DEMO_JOBS MANDU_DEMO_AGENTS "
DEMO_KEYS="MANDU_DEMO_IDS MANDU_DEMO_SIDES MANDU_DEMO_MODELS MANDU_DEMO_REPEAT MANDU_DEMO_JOBS MANDU_DEMO_AGENTS"
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
  if [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)=([A-Za-z0-9_.,:/@+=-]*)$ ]] && [[ "$KEYS" == *" ${BASH_REMATCH[1]} "* ]]; then
    J[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
  else
    say "job.env: refused line: ${line:0:120}"; off
  fi
done < "$JOB/job.env"
MODE="${J[MANDU_CI_MODE]:-run}"
say "job: mode=$MODE run=${J[MANDU_CI_RUN_ID]:-} kinds=${J[MANDU_CI_KINDS]:-}${J[MANDU_CI_NEED]:+ need=${J[MANDU_CI_NEED]}} only=${J[MANDU_CI_ONLY]:-} commit=${J[MANDU_CI_COMMIT]:-}"

# ── the checkout ───────────────────────────────────────────────────────────
t0=$(uptime_s)
install -d -o "$CI_USER" -g "$CI_USER" "$WORK" "$TREE"
# -m: every file gets the extraction time as its mtime; restore-mtimes then
# gives each file whose content the image already built from the image's
# fixed mtime back, so cargo rebuilds exactly what changed (its fingerprints
# of the workspace's own crates are mtime-based).
if ! cat "$IN" | runuser -u "$CI_USER" -- tar -x -f - -C "$TREE" -m --strip-components=1 src/; then
  say "unpacking the checkout failed"; off
fi
if [[ -f "$MTIME_MANIFEST" ]]; then
  runuser -u "$CI_USER" -- python3 - "$TREE" "$MTIME_MANIFEST" "$FIXED_MTIME" <<'PY'
import hashlib, os, sys
tree, manifest, fixed = sys.argv[1], sys.argv[2], int(sys.argv[3])
old = {}
with open(manifest, encoding="utf-8", errors="surrogateescape") as f:
    for line in f:
        h, _, p = line.rstrip("\n").partition("  ")
        old[p] = h
same = changed = 0
for p, h in old.items():
    fp = os.path.join(tree, p)
    try:
        if os.path.islink(fp) or not os.path.isfile(fp):
            continue
        with open(fp, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() == h:
                os.utime(fp, (fixed, fixed)); same += 1
            else:
                changed += 1
    except OSError:
        pass
print(f"mandu-ci: mtimes: {same} files as built into the image, {changed} changed")
PY
fi
say "checkout unpacked in $(awk -v a="$t0" -v b="$(uptime_s)" 'BEGIN{printf "%.1f", b-a}')s"

# ── the demo drills' named hosts (continuous-integration.md §9.9) ──────────
# A baseline-cc-mask session dials the drill's named hosts itself (Claude
# Code's sandbox proxy re-originates the TLS it terminates), so it runs only
# where /etc/hosts sends each to the run's sink (drill-runner.md §3.7). That
# proxy refuses an address that is loopback or one of this machine's own
# ("resolved to a loopback address"), so the hosts map into SINK_NET, a
# TEST-NET-1 /24 (RFC 5737: never a real host): a demo drill's hosts to
# SINK_NET.<its slot>, which an nftables rule redirects (:80 and :443,
# locally made connections only) to LISTEN_NET.<the slot>, where that
# drill's sink listens. A slot per drill, so cc-mask sides of two drills run
# at once (the demo battery's MANDU_DEMO_JOBS, drill-runner.md §3.9);
# MANDU_DRILL_SINK_NAT tells the runner every slot's pair, and the runner
# probes its redirect before a session. The list is the drill tree's
# catalog/guest-hosts, a generated file of the commit under test, read as
# `ci` and taken AS DATA: comments, blank lines, one host a line, `<slot>
# <host>` or a bare `<host>` (slot SLOT_MIN), the slot a number from
# SLOT_MIN to SLOT_MAX with no leading zero, the host a lower-case DNS name
# on one line only, at most MAX_HOSTS; a line outside that grammar maps
# nothing. The drill tree's lib/guest-hosts.ts holds the same grammar and
# addresses (a test keeps the two equal).
SINK_NET=192.0.2
LISTEN_NET=127.0.0
SLOT_MIN=2
SLOT_MAX=254
SLOT_RE='^[1-9][0-9]{0,2}$'
MAX_HOSTS=200
HOST_RE='^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
# the slots map_guest_hosts mapped, for redirect_sink
SLOTS=()
# map_guest_hosts <list> <hosts file>: the block `# mandu-ci guest-hosts
# begin` … `end` in <hosts file>, one `SINK_NET.<slot> host` line per host
# of <list>, replacing an earlier block; SLOTS the slots it used. Returns 1
# (and maps nothing) on a refused list.
map_guest_hosts() {
  local list="$1" etc="$2" line slot h i tmp hosts=() slots=() seen=" "
  SLOTS=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ "$line" == *" "* ]]; then slot="${line%% *}"; h="${line#* }"; else slot="$SLOT_MIN"; h="$line"; fi
    if [[ "$slot" =~ $SLOT_RE ]] && (( slot >= SLOT_MIN && slot <= SLOT_MAX )) && [[ ${#h} -le 253 && "$h" =~ $HOST_RE && "$seen" != *" $h "* ]]; then
      hosts+=("$h"); slots+=("$slot"); seen+="$h "
    else say "hosts: a line of the drill tree's guest-hosts is not <slot> <host> (or a host named twice); nothing mapped"; return 1; fi
  done < "$list"
  (( ${#hosts[@]} <= MAX_HOSTS )) || { say "hosts: ${#hosts[@]} hosts, over $MAX_HOSTS; nothing mapped"; return 1; }
  (( ${#hosts[@]} > 0 )) || { say "hosts: the drill tree's guest-hosts names no host"; return 0; }
  tmp="$(mktemp)" || return 1
  sed '/^# mandu-ci guest-hosts begin$/,/^# mandu-ci guest-hosts end$/d' "$etc" > "$tmp" || { rm -f "$tmp"; return 1; }
  {
    echo "# mandu-ci guest-hosts begin"
    for i in "${!hosts[@]}"; do echo "$SINK_NET.${slots[$i]} ${hosts[$i]}"; done
    echo "# mandu-ci guest-hosts end"
  } >> "$tmp"
  cat "$tmp" > "$etc"
  rm -f "$tmp"
  mapfile -t SLOTS < <(printf '%s\n' "${slots[@]}" | sort -nu)
  say "hosts: ${#hosts[@]} demo host(s) mapped into $SINK_NET.{${SLOTS[*]}}: ${hosts[*]}"
}
# redirect_sink: each SLOTS address's :80 and :443 to its LISTEN_NET one,
# for connections this machine makes (nat output; a route through lo, so the
# address needs no network), as the table mandu_ci_sink. Returns 1 when it
# could not.
redirect_sink() {
  local s rules=""
  for s in "${SLOTS[@]}"; do
    ip route replace "$SINK_NET.$s/32" dev lo || return 1
    rules+="    ip daddr $SINK_NET.$s tcp dport { 80, 443 } dnat to $LISTEN_NET.$s"$'\n'
  done
  nft -f - <<NFT || return 1
table ip mandu_ci_sink
delete table ip mandu_ci_sink
table ip mandu_ci_sink {
  chain output {
    type nat hook output priority dstnat; policy accept;
$rules  }
}
NFT
  say "hosts: $SINK_NET.{${SLOTS[*]}}:80,443 redirected to $LISTEN_NET.{${SLOTS[*]}}, where a live run's sink listens"
}
SINK_NAT=""
drill_tree="$(runuser -u "$CI_USER" -- node "$TREE/scripts/drill-tree.mjs" "$TREE" 2>/dev/null)" || drill_tree=""
if [[ -n "$drill_tree" ]] && runuser -u "$CI_USER" -- head -c 65536 -- "$drill_tree/catalog/guest-hosts" > "$JOB/guest-hosts" 2>/dev/null; then
  if map_guest_hosts "$JOB/guest-hosts" /etc/hosts; then
    if (( ${#SLOTS[@]} == 0 )); then :
    elif redirect_sink; then SINK_NAT="$(for s in "${SLOTS[@]}"; do printf '%s>%s,' "$SINK_NET.$s" "$LISTEN_NET.$s"; done)"; SINK_NAT="${SINK_NAT%,}"
    else say "hosts: the redirect of $SINK_NET.{${SLOTS[*]}} could not be set up: a cc-mask session is refused"; fi
  fi
else
  say "hosts: no drill tree with a catalog/guest-hosts in this checkout: no host mapped"
fi

# ── a cgroup delegated to ci (continuous-integration.md §3) ────────────────
# The shape a desktop terminal or tmux gives a user (user@UID.service's
# delegated subtree): the suites run in a cgroup `ci` owns, beside a sibling
# it owns, under a parent it owns, so the guard's cgroup rule
# (rootless-confinement-ubuntu-2404.md §12.2, "The cgroup") is exercised
# rather than skipped. mandu-ci.service has Delegate=memory pids, so systemd leaves
# its subtree alone:
#   <unit>/boot      boot.sh itself (a cgroup with children holds no process
#                    once controllers are on: the no-internal-process rule)
#   <unit>/ci        delegated as the kernel documents it (cgroup-v2.rst
#                    "Delegation"): the directory, cgroup.procs,
#                    cgroup.threads and cgroup.subtree_control are ci's
#   <unit>/ci/run    made by ci: the suites (in_ci_cgroup moves each command)
#   <unit>/ci/spare  made by ci, empty: the sibling
# memory and pids are switched on down to run/ where the kernel offers them
# (no limit is set), never cpu (and the unit delegates only memory and pids,
# so systemd keeps cpu off above it): a cgroup with cpu on is a task group of
# its own, and the kernel applies autogroups (one fair share per session)
# only in the root task group. With cpu on, every suite's processes shared
# one per-task pool, a single-threaded TUI drill's agent got a slice beside
# the cargo builds, and the first OpenClaw replay drill went from 43 s to
# 120-220 s, past its 90 s composer wait (continuous-integration.md §3).
# A step that fails leaves the run as before (the root-owned unit cgroup)
# and says so; rust.kernel's strict skips then fail.
CI_CGROUP=""
# delegate_cgroup <unit cgroup dir> <user>: the layout above; CI_CGROUP the
# run/ directory. Returns 1 (CI_CGROUP empty) when a step failed.
delegate_cgroup() {
  local unit="$1" user="$2" d c on=""
  d="$unit/ci"
  mkdir -p "$unit/boot" && echo $$ > "$unit/boot/cgroup.procs" || return 1
  for c in memory pids; do
    grep -qw "$c" "$unit/cgroup.controllers" 2>/dev/null && echo "+$c" > "$unit/cgroup.subtree_control" 2>/dev/null && on+=" +$c"
  done
  mkdir -p "$d" && chown "$user:$user" "$d" "$d/cgroup.procs" "$d/cgroup.threads" "$d/cgroup.subtree_control" || return 1
  runuser -u "$user" -- mkdir -p "$d/run" "$d/spare" || return 1
  [[ -z "$on" ]] || runuser -u "$user" -- sh -c 'echo "$1" > "$2"' _ "${on# }" "$d/cgroup.subtree_control" \
    || say "cgroup: switching on${on} under $d failed; the suites run there without them"
  CI_CGROUP="$d/run"
}
# in_ci_cgroup <command…>: run it in CI_CGROUP (a root write: the move's
# common ancestor is the unit's cgroup), or where boot.sh is when there is none.
in_ci_cgroup() {
  if [[ -n "$CI_CGROUP" ]]; then
    bash -c 'echo 0 > "$1/cgroup.procs" && shift && exec "$@"' _ "$CI_CGROUP" "$@"
  else
    "$@"
  fi
}
# cpu_group_of <cgroup dir>: the cgroup whose cpu task group holds that
# one's processes (the nearest at or above it with cpu on: a cpu.weight
# file), or nothing in the root task group, where autogroups apply.
cpu_group_of() {
  local d="$1"
  while [[ "$d" == /sys/fs/cgroup/?* ]]; do
    [[ -e "$d/cpu.weight" ]] && { echo "$d"; return; }
    d="${d%/*}"
  done
}
unit_cg="/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup)"
if [[ "$unit_cg" == /sys/fs/cgroup/?* ]] && delegate_cgroup "$unit_cg" "$CI_USER"; then
  say "cgroup: the suites run in $CI_CGROUP, delegated to $CI_USER ($(cat "$unit_cg/ci/cgroup.subtree_control" 2>/dev/null))"
else
  CI_CGROUP=""
  say "cgroup: could not delegate a cgroup to $CI_USER under '$unit_cg'; the suites run in the unit's root-owned cgroup"
fi
cg_cpu="$(cpu_group_of "${CI_CGROUP:-$unit_cg}")"
if [[ -z "$cg_cpu" ]]; then
  say "cpu: the suites are in the root cpu task group: each session gets its fair share (autogroup $(cat /proc/sys/kernel/sched_autogroup_enabled 2>/dev/null))"
else
  say "cpu: WARNING: the suites share the cpu task group of $cg_cpu, where no autogroup applies: a single-threaded suite gets a per-task slice beside the builds (continuous-integration.md §3)"
fi

# ── shell mode ─────────────────────────────────────────────────────────────
if [[ "$MODE" == shell ]]; then
  say "shell mode: a login shell as $CI_USER in $TREE on the serial console; exit it to power off"
  in_ci_cgroup setsid --ctty --wait runuser -l "$CI_USER" -c "cd $TREE && MANDU_CI_GUEST=1 MANDU_CI_OFFLINE=1 MANDU_CI_BWRAP=$BWRAP_CI exec bash -l" \
    </dev/ttyS0 >/dev/ttyS0 2>&1
  off
fi

# ── the pipeline ───────────────────────────────────────────────────────────
args=(--out "$RESULTS")
case "$MODE" in
  run) ;;
  selftest) args+=(--selftest) ;;
  exec)
    cmd="$(printf '%s' "${J[MANDU_CI_EXEC_B64]:-}" | base64 -d 2>/dev/null)"
    [[ -n "$cmd" ]] || { say "exec mode without a command"; off; }
    args+=(--exec "$cmd") ;;
  *) say "unknown mode: $MODE"; off ;;
esac
for kv in kind:MANDU_CI_KINDS need:MANDU_CI_NEED only:MANDU_CI_ONLY jobs:MANDU_CI_JOBS run-id:MANDU_CI_RUN_ID \
          source:MANDU_CI_SOURCE commit:MANDU_CI_COMMIT ref:MANDU_CI_REF image:MANDU_CI_IMAGE \
          ollama:MANDU_CI_OLLAMA lane:MANDU_CI_LANE; do
  v="${J[${kv#*:}]:-}"
  [[ -n "$v" ]] && args+=("--${kv%%:*}" "$v")
done
[[ "${J[MANDU_CI_NETWORK]:-}" == 1 ]] && args+=(--network)
[[ "${J[MANDU_CI_INCLUDE_FLAKY]:-}" == 1 ]] && args+=(--include-flaky)
[[ "${J[MANDU_CI_INCLUDE_INTERNET]:-}" == 1 ]] && args+=(--include-internet)

# ── the network (nightly) ──────────────────────────────────────────────────
# The image keeps the provisioning boot's DHCP config and no network wait; a
# networked run waits here for the NIC's address (the build stage would hide
# a slow lease, a suite would not).
if [[ "${J[MANDU_CI_NETWORK]:-}" == 1 || -n "${J[MANDU_CI_OLLAMA]:-}" ]]; then
  for _ in $(seq 1 120); do
    ip -4 route show default 2>/dev/null | grep -q . && break
    sleep 0.5
  done
  say "network: $(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2, $4}' | tr '\n' ' ')default $(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')"
fi

# ── the credential (nightly) ───────────────────────────────────────────────
CRED_DISK=/dev/disk/by-id/virtio-mandu-cred
CRED_FILE=/home/$CI_USER/.claude/.credentials.json
API_FILE=/home/$CI_USER/.config/mandu-ci/api-keys.json
CODEX_FILE=/home/$CI_USER/.config/mandu-ci/codex-auth.json
DOCKER_FILE=/home/$CI_USER/.config/mandu-ci/docker-auth.json
GG_FILE=/home/$CI_USER/.config/mandu-ci/gitguardian-key.json
# place <what> <tar member> <dest> <jq test>: one credential off the disk, or
# nothing (a partial file is removed).
place() {
  local what="$1" member="$2" dest="$3" test="$4"
  if [[ -b $CRED_DISK ]] && ( umask 077 && tar -x -O -f "$CRED_DISK" "$member" > "$dest" ) \
       && jq -e "$test" "$dest" >/dev/null 2>&1; then
    chown "$CI_USER:$CI_USER" "$dest"; chmod 600 "$dest"
    return 0
  fi
  rm -f "$dest"
  say "credential: $what requested but the credential disk is missing or unusable; the suites run without it"
  return 1
}
if [[ -n "${J[MANDU_CI_CREDENTIAL]:-}" ]]; then
  for _ in $(seq 1 20); do [[ -b $CRED_DISK ]] && break; udevadm settle -t 1 2>/dev/null; sleep 0.5; done
  install -d -m 700 -o "$CI_USER" -g "$CI_USER" "/home/$CI_USER/.config" "/home/$CI_USER/.config/mandu-ci"
fi
for kind in ${J[MANDU_CI_CREDENTIAL]//,/ }; do
  case "$kind" in
    api)
      place api api/keys.json "$API_FILE" \
        'type == "object" and length > 0 and (keys - ["anthropic", "openai"] | length == 0) and all(.[]; type == "string")' \
        && say "credential: api keys placed for $CI_USER ($(jq -r 'keys | join(", ")' "$API_FILE"))" ;;
    claude)
      install -d -m 700 -o "$CI_USER" -g "$CI_USER" "/home/$CI_USER/.claude"
      place claude claude/.credentials.json "$CRED_FILE" \
        '(.claudeAiOauth.accessToken | type == "string") and (.claudeAiOauth | has("refreshToken") | not)' \
        && say "credential: claude placed for $CI_USER ($(stat -c %s "$CRED_FILE") bytes, access token only)" ;;
    codex)
      place codex codex/auth.json "$CODEX_FILE" \
        '(.tokens.access_token | type == "string") and (.tokens.id_token | type == "string") and .tokens.refresh_token == "" and (.OPENAI_API_KEY == null)' \
        && say "credential: codex placed for $CI_USER ($(stat -c %s "$CODEX_FILE") bytes, no refresh token)" ;;
    docker)
      place docker docker/auth.json "$DOCKER_FILE" \
        'type == "object" and (keys == ["token", "username"]) and (.token | type == "string" and startswith("dckr_pat_")) and (.username | type == "string")' \
        && say "credential: docker placed for $CI_USER (user $(jq -r .username "$DOCKER_FILE"), the token not shown)" ;;
    gitguardian)
      place gitguardian gitguardian/key.json "$GG_FILE" \
        'type == "object" and (keys == ["token"]) and (.token | type == "string")' \
        && say "credential: gitguardian placed for $CI_USER ($(stat -c %s "$GG_FILE") bytes)" ;;
    *) say "credential: unknown kind '$kind' refused" ;;
  esac
done
install -d -o "$CI_USER" -g "$CI_USER" "$RESULTS"
# ── the budget (continuous-integration.md §3) ─────────────────────────────
# The runner's deadline and the watchdog, from MANDU_CI_BUDGET, so the guest
# ends its own run, results written, before vm-run.sh's timeout kills it.
WATCHDOG=""
BUDGET="${J[MANDU_CI_BUDGET]:-}"
if [[ -n "$BUDGET" ]]; then
  if [[ "$BUDGET" =~ ^[0-9]{1,7}$ ]] && plan="$(budget_plan "$BUDGET" "$(uptime_s)" "$(date +%s)")"; then
    read -r deadline wd_in <<<"$plan"
    args+=(--deadline "$deadline")
    say "budget: ${BUDGET}s of uptime: the suites stop at $(date -u -d "@$deadline" +%H:%M:%SZ) (--deadline), the watchdog fires in ${wd_in}s"
    watchdog "$wd_in" &
    WATCHDOG=$!
  else
    say "budget: ${BUDGET}s of uptime is spent already (uptime $(uptime_s)s): no deadline, no watchdog"
  fi
fi
say "pipeline start at uptime $(uptime_s)s"
PASSENV="CARGO_NET_OFFLINE DISABLE_AUTOUPDATER OPENCODE_DISABLE_AUTOUPDATE OPENCODE_DISABLE_MODELS_FETCH"
# The demo battery's choices (§9.9): in the pipeline's environment, and passed
# into a sandboxed entry's box too. The sink's redirect for the live runner
# (MANDU_DRILL_SINK_NAT) only into the pipeline's: a box has its own network
# namespace, which the redirect is not in.
demo_env=()
for k in $DEMO_KEYS; do
  v="${J[$k]:-}"
  [[ -n "$v" ]] && { demo_env+=("$k=$v"); PASSENV+=" $k"; }
done
[[ ${#demo_env[@]} -gt 0 ]] && say "demo battery: ${demo_env[*]}"
[[ -n "$SINK_NAT" ]] && demo_env+=("MANDU_DRILL_SINK_NAT=$SINK_NAT")
in_ci_cgroup runuser -u "$CI_USER" -- env -i \
  HOME=/home/$CI_USER USER=$CI_USER LOGNAME=$CI_USER SHELL=/bin/bash \
  PATH=/home/$CI_USER/.cargo/bin:/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 TERM=dumb \
  MANDU_CI_GUEST=1 MANDU_CI_OFFLINE=1 CARGO_NET_OFFLINE=true MANDU_CI_BWRAP=$BWRAP_CI \
  MANDU_CI_PASSENV="$PASSENV" \
  DISABLE_AUTOUPDATER=1 OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1 \
  "${demo_env[@]}" \
  bash "$TREE/scripts/ci/pipeline.sh" "${args[@]}" 2>&1 | tee "$JOB/pipeline.log"
rc=${PIPESTATUS[0]}
say "pipeline exit $rc at uptime $(uptime_s)s"
[[ -n "$WATCHDOG" ]] && kill "$WATCHDOG" 2>/dev/null
rm -f "$CRED_FILE" "$API_FILE" "$CODEX_FILE" "$DOCKER_FILE" "$GG_FILE"
# The watchdog fired: the run says so. A summary the runner still wrote gets
# the stage `watchdog: error`; with none, an `error` summary of its own, so
# the collector keeps the logs written so far instead of refusing the archive.
if [[ -f "$JOB/watchdog" ]]; then
  if [[ -f "$RESULTS/summary.json" ]]; then
    runuser -u "$CI_USER" -- node "$TREE/scripts/ci/summary.mjs" add-stage --out "$RESULTS" --stage watchdog=error \
      || say "watchdog: could not record the stage in summary.json"
  else
    meta=(--run-id "${J[MANDU_CI_RUN_ID]:-}" --commit "${J[MANDU_CI_COMMIT]:-}" --source "${J[MANDU_CI_SOURCE]:-local}")
    [[ -n "${J[MANDU_CI_REF]:-}" ]] && meta+=(--ref "${J[MANDU_CI_REF]}")
    [[ -n "${J[MANDU_CI_IMAGE]:-}" ]] && meta+=(--image "${J[MANDU_CI_IMAGE]}")
    runuser -u "$CI_USER" -- node "$TREE/scripts/ci/summary.mjs" write --out "$RESULTS" "${meta[@]}" --result error \
      --reason "watchdog: the pipeline still ran at the guest's budget (${BUDGET}s of uptime) and was stopped; logs/pipeline.log says what ran, logs/ holds each entry's log so far" \
      >/dev/null || say "watchdog: could not write a summary"
  fi
fi

# ── the results ────────────────────────────────────────────────────────────
mkdir -p "$RESULTS/logs"
cp "$JOB/pipeline.log" "$RESULTS/logs/pipeline.log" 2>/dev/null
tail -c $((5 * 1024 * 1024)) "$RESULTS/logs/pipeline.log" > "$JOB/p.tail" 2>/dev/null && mv "$JOB/p.tail" "$RESULTS/logs/pipeline.log"
# The collector refuses an archive with anything but files and directories.
find "$RESULTS" -mindepth 1 ! -type f ! -type d -print -delete | sed 's/^/mandu-ci: dropped non-regular: /'
if [[ -b $OUT ]]; then
  if tar -c -f "$OUT" -C "$RESULTS" --format=gnu --owner=0 --group=0 --numeric-owner .; then
    say "results written to the output disk ($(du -sh "$RESULTS" | cut -f1))"
  else
    say "writing the results to the output disk failed"
  fi
else
  say "no output disk ($OUT): results stay in the guest"
fi
off
