#!/usr/bin/env bash
#
# ci-vm-run.test.sh — scripts/ci/vm-run.sh --dry-run (docs/design/
# continuous-integration.md §3, §8): the guest it WOULD start gets no network
# device but `-nic none`, no shared filesystem, a read-only input disk and the
# two virtio serials the guest looks for; the job file it renders carries the
# options, as data the guest's boot.sh accepts. Plus the pieces vm-run uses:
# ci_render_job_env's refusals, the source tar's contents. In a throwaway git
# repo; needs git, tar, bash (no KVM, no qemu, no network).
#
# Run:  bash scripts/test/ci-vm-run.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PASS=0 FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

T="$(mktemp -d "${TMPDIR:-/tmp}/ci-vm-run.XXXXXX")"; trap 'rm -rf "$T"' EXIT
F="$T/repo"
mkdir -p "$F/scripts/ci/guest" "$F/scripts/paths" "$F/scripts/lib" "$F/arbiter/node_modules/x"
cp "$REPO/scripts/lib/guest-registry.sh" "$REPO/scripts/lib/runtime-base.sh" "$F/scripts/lib/"
cp "$REPO/scripts/ci/lib.sh" "$REPO/scripts/ci/vm-run.sh" "$REPO/scripts/ci/vm-image.sh" "$REPO/scripts/ci/pins.env" "$F/scripts/ci/"
cp "$REPO/scripts/paths/"mandu-paths.* "$F/scripts/paths/"
cp "$REPO/scripts/ci/credential.mjs" "$REPO/scripts/ci/port-bridge.mjs" "$REPO/scripts/ci/nightly.sh" \
   "$REPO/scripts/ci/collect-results.mjs" "$REPO/scripts/ci/replay-retention.mjs" "$REPO/scripts/ci/live-events.mjs" "$F/scripts/ci/"
cp "$REPO/scripts/ci/guest/"* "$F/scripts/ci/guest/"
cp "$REPO/scripts/suites.mjs" "$F/scripts/"
# suites.mjs imports the agent registry
mkdir -p "$F/scripts/agents"; cp "$REPO/scripts/agents/agent-registry.mjs" "$F/scripts/agents/"
echo '{}' > "$F/arbiter/package-lock.json"; echo "src" > "$F/arbiter/index.ts"; echo "dep" > "$F/arbiter/node_modules/x/i.js"
echo "secret" > "$F/secrets.local.json"
printf 'node_modules/\nsecrets.local.json\n' > "$F/.gitignore"
g() { git -C "$F" -c user.name=t -c user.email=t@t.invalid -c commit.gpgsign=false "$@"; }
g init -q -b feat/ci_x && g add -A && g commit -qm base
SHA="$(g rev-parse HEAD)"
# The image cache and the runs dir are the path table's `ci-cache` and
# `ci-runs` under MANDU_HOME (the runner's unit sets MANDU_HOME).
export MANDU_HOME="$T/mh"
CACHE="$T/mh/cache/ci" RUNS="$T/mh/runs/ci"
unset CI_COMMIT_REF_NAME MANDU_CI_VCPUS MANDU_CI_MEM MANDU_CI_TIMEOUT MANDU_CI_OLLAMA_HOST
# Never the host's real credential files: every credential below is
# synthetic, and a Codex refresh never leaves this machine.
export MANDU_CI_CLAUDE_CREDENTIAL="$T/no-credential.json"
export MANDU_CI_API_CREDENTIAL="$T/no-api-default.json"
export MANDU_CI_CODEX_CREDENTIAL="$T/no-codex.json"
export MANDU_CI_DOCKER_CREDENTIAL="$T/no-docker.json" MANDU_CI_GITGUARDIAN_CREDENTIAL="$T/no-gg.json"
unset MANDU_CI_DOCKER_USER
export MANDU_CI_CODEX_REFRESH_URL="http://127.0.0.1:1/oauth/token"

dry() { "$F/scripts/ci/vm-run.sh" --dry-run "$@" 2>&1; }
OUT="$(dry --kind unit,sandbox --only arbiter,launcher.net-guard-live --jobs 7 --run-id gl-1-2 --source gitlab)"
rc=$?
check "--dry-run exits 0" "[[ $rc -eq 0 ]]"
CMD="$(grep -v '^#' <<<"$OUT" | sed 's/\\,/,/g')"
JOB="$(grep '^#   ' <<<"$OUT" | sed 's/^#   //')"
read -r -a ARGV <<<"$CMD"

check "qemu is the command" "[[ \"\${ARGV[0]}\" == qemu-system-x86_64 ]]"
nics="$(printf '%s\n' "${ARGV[@]}" | grep -c -- '^-nic$')"
check "exactly one -nic, and it is 'none'" "[[ $nics -eq 1 ]] && grep -q -- '-nic none' <<<\"\$CMD\""
check "no -netdev, -net or network device" "! grep -qE -- '(^| )-(netdev|net) |virtio-net|e1000|rtl8139|user,|hostfwd|guestfwd' <<<\"\$CMD\""
# The shared-filesystem forms as qemu spells them (an option, or a device or
# backend name after `-device`/`-chardev`), not as substrings of the line: the
# line holds this run's random temp dir, and a name like ci-vm-run.ab9PxY once
# matched a bare /9p/i (2026-09-29).
NOSHARE='(^| )-(virtfs|fsdev)( |$)|(^| )-(device|chardev|object) [^ ]*(virtio-9p|vhost-user|virtiofs|memory-backend-memfd)'
noshare() { ! grep -qE -- "$NOSHARE" <<<"$1"; }
check "the shared-filesystem pattern sees each form, and not a path that merely contains 9p" \
  "! noshare '-virtfs local,path=/x' && ! noshare '-fsdev local,id=f' && ! noshare '-device virtio-9p-pci,fsdev=f' && ! noshare '-chardev socket,id=c -device vhost-user-fs-pci,chardev=c' && noshare '-drive file=/tmp/ci-vm-run.ab9PxY/system.qcow2 -nic none'"
check "no shared filesystem (9p, virtfs, virtiofs, fsdev)" "noshare \"\$CMD\""
check "the input disk is read-only" "grep -qE -- '-drive file=[^ ]*/input\.tar,if=none,id=in,format=raw,readonly=on' <<<\"\$CMD\""
check "the input disk has virtio serial mandu-in" "grep -q -- 'virtio-blk-pci,drive=in,serial=mandu-in' <<<\"\$CMD\""
check "the output disk has virtio serial mandu-out and is raw" "grep -q -- 'virtio-blk-pci,drive=out,serial=mandu-out' <<<\"\$CMD\" && grep -qE -- 'output\.raw,if=none,id=out,format=raw( |\$)' <<<\"\$CMD\""
check "the output disk is not read-only, the system disk is an overlay" "! grep -qE -- 'id=out[^ ]*readonly' <<<\"\$CMD\" && grep -q -- 'system.qcow2,if=none,id=sys,format=qcow2' <<<\"\$CMD\""
check "the system disk boots first" "grep -q -- 'drive=sys,bootindex=0' <<<\"\$CMD\""
check "only the throwaway system disk ignores flushes (cache=unsafe)" "grep -qE -- 'system\.qcow2,if=none,id=sys,[^ ]*cache=unsafe' <<<\"\$CMD\" && [[ \$(grep -o -- 'cache=unsafe' <<<\"\$CMD\" | wc -l) -eq 1 ]]"
check "the image build ignores flushes, then flushes the image file (sync -d) before publishing it" "grep -qE -- 'image\.qcow2,if=none,id=sys,[^\"]*cache=unsafe' '$F/scripts/ci/vm-image.sh' && awk '/^sync -d \"\\\$BUILD\/image\.qcow2\"/{s=NR} /^mv \"\\\$BUILD\/image\.qcow2\" /{m=NR} END{exit !(s && m && s < m)}' '$F/scripts/ci/vm-image.sh'"
check "-nographic, -no-reboot, serial to a console log" "grep -q -- '-nographic' <<<\"\$CMD\" && grep -q -- '-no-reboot' <<<\"\$CMD\" && grep -qE -- '-serial file:[^ ]*/console\.log' <<<\"\$CMD\""
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  check "KVM: -enable-kvm -cpu host" "grep -q -- '-enable-kvm -cpu host' <<<\"\$CMD\""
fi
check "32 vCPUs (capped to the host) and 64 GiB by default" "grep -qE -- '-smp ($(nproc)|32) -m 65536' <<<\"\$CMD\""
check "the default timeout is 2700 s" "grep -q '^# timeout: 2700s' <<<\"\$OUT\""
check "the image is named by the key" "grep -q \"^# image: $CACHE/mandu-ci-\$($F/scripts/ci/vm-image.sh --key).qcow2\" <<<\"\$OUT\""

# job.env
jv() { sed -n "s/^$1=//p" <<<"$JOB"; }
check "job.env: mode run, kinds, no need, only, jobs" "[[ \$(jv MANDU_CI_MODE) == run && \$(jv MANDU_CI_KINDS) == unit,sandbox && -z \$(jv MANDU_CI_NEED) && \$(jv MANDU_CI_ONLY) == arbiter,launcher.net-guard-live && \$(jv MANDU_CI_JOBS) == 7 ]]"
check "job.env: run id, source, commit, ref (the branch), image" "[[ \$(jv MANDU_CI_RUN_ID) == gl-1-2 && \$(jv MANDU_CI_SOURCE) == gitlab && \$(jv MANDU_CI_COMMIT) == $SHA && \$(jv MANDU_CI_REF) == feat/ci_x && \$(jv MANDU_CI_IMAGE) =~ ^mandu-ci-[0-9a-f]{16}\$ ]]"
boot_keys="$(sed -n 's/^KEYS=" \(.*\) "$/\1/p' "$REPO/scripts/ci/guest/boot.sh")"
bad=0
while IFS= read -r l; do
  [[ "$l" =~ ^\# ]] && continue
  [[ "$l" =~ ^([A-Z_][A-Z0-9_]*)=([A-Za-z0-9_.,:/@+=-]*)$ ]] || { bad=1; echo "  line outside boot.sh's grammar: $l"; continue; }
  [[ " $boot_keys " == *" ${BASH_REMATCH[1]} "* ]] || { bad=1; echo "  key boot.sh does not read: $l"; }
done <<<"$JOB"
check "every job.env line is KEY=value in boot.sh's grammar, with a key boot.sh reads" "[[ -n \"\$boot_keys\" && $bad -eq 0 ]]"

# modes
E="$(dry --exec 'bash scripts/ci/release-pack.sh v0.1.0 && echo "a b"')"
b64="$(grep '^#   MANDU_CI_EXEC_B64=' <<<"$E" | cut -d= -f2-)"
b64d() { node -e 'process.stdout.write(Buffer.from(process.argv[1], "base64").toString())' "$1"; }
check "--exec: mode exec, the command base64 in job.env, decoded intact" "grep -q '^#   MANDU_CI_MODE=exec' <<<\"\$E\" && [[ \"\$(b64d \"\$b64\")\" == 'bash scripts/ci/release-pack.sh v0.1.0 && echo \"a b\"' ]]"
# A runner host whose PATH puts a foreign base64 first (the 128-core lab
# host's /usr/local/bin/base64 is a Python codec tool that crashes): vm-run
# and nightly.sh must not depend on it.
mkdir -p "$T/badbin"; printf '#!/bin/sh\necho "broken base64" >&2\nexit 1\n' > "$T/badbin/base64"; chmod +x "$T/badbin/base64"
EB="$(PATH="$T/badbin:$PATH" dry --exec 'echo "a b"')"
b64="$(grep '^#   MANDU_CI_EXEC_B64=' <<<"$EB" | cut -d= -f2-)"
check "--exec does not use base64(1) from PATH" "[[ \"\$(b64d \"\$b64\")\" == 'echo \"a b\"' ]] && ! grep -q 'broken base64' <<<\"\$EB\""
S="$(dry --selftest)"
check "--selftest: mode selftest" "grep -q '^#   MANDU_CI_MODE=selftest' <<<\"\$S\""
SH="$(dry --shell)"
check "--shell: mode shell, the serial console on stdio, still no network" "grep -q '^#   MANDU_CI_MODE=shell' <<<\"\$SH\" && grep -q -- '-serial mon:stdio' <<<\"\$SH\" && grep -q -- '-nic none' <<<\"\$SH\" && ! grep -q -- 'netdev' <<<\"\$SH\""
V="$(MANDU_CI_VCPUS=2 MANDU_CI_MEM=4096 MANDU_CI_TIMEOUT=60 dry)"
check "MANDU_CI_VCPUS / MANDU_CI_MEM / MANDU_CI_TIMEOUT" "grep -q -- '-smp 2 -m 4096' <<<\"\$V\" && grep -q '^# timeout: 60s' <<<\"\$V\""
V="$(dry --vcpus 100000 --mem 2048)"
check "--vcpus is capped to the host's CPUs" "grep -q -- \"-smp $(nproc) -m 2048\" <<<\"\$V\""

# The guest's budget (continuous-integration.md §3): the guest ends its own run
# before the host's timeout kills it, so a hung suite comes back named
# (pipelines 10978, 11050 and 11099 were killed with nothing but the console).
check "job.env: the guest's budget is the timeout less 150 s by default (2550 s of 2700)" \
  "[[ \$(jv MANDU_CI_BUDGET) == 2550 ]] && grep -q '^# timeout: 2700s; the guest.s budget: 2550s of uptime\$' <<<\"\$OUT\""
B1="$(MANDU_CI_TIMEOUT=600 dry | sed -n 's/^#   MANDU_CI_BUDGET=//p')"
B2="$(MANDU_CI_TIMEOUT=59 dry | grep -c '^#   MANDU_CI_BUDGET=$')"
B3="$(dry --shell | grep -c '^#   MANDU_CI_BUDGET=$')"
check "the budget's margin is a tenth of a shorter timeout (540 of 600); none under 60 s, none for --shell" \
  "[[ '$B1' == 540 && '$B2' == 1 && '$B3' == 1 ]]"
# shellcheck source=scripts/ci/lib.sh
check "ci_guest_budget: 14400 -> 14250, 60 -> 54, 59 and junk -> nothing" \
  "( CI_REPO_ROOT='$F'; . '$F/scripts/ci/lib.sh'; [[ \$(ci_guest_budget 14400) == 14250 && \$(ci_guest_budget 60) == 54 && -z \$(ci_guest_budget 59) && -z \$(ci_guest_budget x) ]] )"
# The host's CPU slots (lib.sh ci_take_cpu_slots, continuous-integration.md §5.7):
# a 16-vCPU budget is two 8-vCPU slots; a holder of one leaves one.
SL="$T/slots"
check "ci_cpu_budget: MANDU_CI_HOST_VCPUS overrides, 0 or junk is no budget, else the host's physical cores" \
  "( . '$F/scripts/ci/lib.sh'; [[ \$(MANDU_CI_HOST_VCPUS=48 ci_cpu_budget) == 48 && -z \$(MANDU_CI_HOST_VCPUS=0 ci_cpu_budget) && -z \$(MANDU_CI_HOST_VCPUS=x ci_cpu_budget) && \$(ci_cpu_budget) -ge 1 ]] )"
( . "$F/scripts/ci/lib.sh"; ci_take_cpu_slots "$SL" 8 16 5 && echo held > "$T/slot-held" && sleep 6 ) & HOLDER=$!
for _ in $(seq 50); do [[ -s "$T/slot-held" ]] && break; sleep 0.1; done
check "ci_take_cpu_slots: a second 8-vCPU guest takes the other slot at once" \
  "( . '$F/scripts/ci/lib.sh'; ci_take_cpu_slots '$SL' 8 16 1 && [[ \${#CI_SLOT_FDS[@]} -eq 1 ]] )"
check "ci_take_cpu_slots: a 16-vCPU guest waits while one slot is held, and gives up after its wait holding nothing" \
  "( . '$F/scripts/ci/lib.sh'; ! ci_take_cpu_slots '$SL' 16 16 2 && [[ \${#CI_SLOT_FDS[@]} -eq 0 ]] )"
check "ci_take_cpu_slots: and gets both once the holder is gone (a guest bigger than the budget takes it all)" \
  "( . '$F/scripts/ci/lib.sh'; ci_take_cpu_slots '$SL' 32 16 20 && [[ \${#CI_SLOT_FDS[@]} -eq 2 ]] )"
wait "$HOLDER" 2>/dev/null
check "vm-run.sh takes the slots before the disks, with its own vCPUs" \
  "grep -q 'ci_take_cpu_slots \"\$CACHE/cpu-slots\" \"\$VCPUS\" \"\$CPU_BUDGET\" \"\$SLOT_WAIT\"' '$REPO/scripts/ci/vm-run.sh'"
# boot.sh's half, its functions run here: budget_plan's two deadlines, and
# the watchdog against stub pkill/pgrep.
BOOT="$REPO/scripts/ci/guest/boot.sh"
fn() { sed -n "/^$1() {\$/,/^}\$/p" "$BOOT"; }
eval "$(fn budget_plan)"
check "budget_plan: the suites' deadline 150 s before the budget, the watchdog at it (2550 s, uptime 7.05 s)" \
  "[[ \"\$(budget_plan 2550 7.05 1000000)\" == '1002393 2543' ]]"
check "budget_plan: a shorter budget keeps a tenth for the end (300 s at uptime 10: deadline in 260 s)" \
  "[[ \"\$(budget_plan 300 10 1000)\" == '1260 290' ]]"
check "budget_plan: a budget already spent gives no plan" "! budget_plan 100 150 1000 >/dev/null"
mkdir -p "$T/wd/bin" "$T/wd/job"
printf '#!/bin/sh\necho "pkill $*" >> "%s"\n' "$T/wd/calls" > "$T/wd/bin/pkill"
printf '#!/bin/sh\necho "pgrep $*" >> "%s"\nexit 1\n' "$T/wd/calls" > "$T/wd/bin/pgrep"
chmod +x "$T/wd/bin/pkill" "$T/wd/bin/pgrep"
WD_OUT="$(PATH="$T/wd/bin:$PATH" bash -c "$(grep '^say() ' "$BOOT")
$(fn watchdog)
JOB='$T/wd/job' CI_USER=ci; declare -A J=([MANDU_CI_BUDGET]=2550); watchdog 0")"
check "watchdog: marks the run, says so, SIGTERMs every process of ci, then SIGKILLs them" \
  "[[ -f '$T/wd/job/watchdog' ]] && grep -q '^mandu-ci: watchdog: the pipeline still runs at the budget (2550s of uptime)' <<<\"\$WD_OUT\" && [[ \"\$(head -1 '$T/wd/calls')\" == 'pkill -TERM -u ci' && \"\$(tail -1 '$T/wd/calls')\" == 'pkill -KILL -u ci' ]]"
check "boot.sh: --deadline to the pipeline and the watchdog only from a budget; the watchdog stopped after the pipeline" \
  "grep -qF 'args+=(--deadline \"\$deadline\")' '$BOOT' && grep -qF 'watchdog \"\$wd_in\" &' '$BOOT' && grep -qF '[[ -n \"\$WATCHDOG\" ]] && kill \"\$WATCHDOG\"' '$BOOT'"
# delegate_cgroup and in_ci_cgroup on a fake cgroup tree (plain files; the
# kernel's own files made by the stub mkdir, runuser a stub running as this user).
mkdir -p "$T/cg/bin" "$T/cg/unit"
printf '#!/bin/sh\nfor d in "$@"; do case "$d" in -*) ;; *) /bin/mkdir -p "$d" && for f in cgroup.procs cgroup.threads cgroup.subtree_control; do : > "$d/$f"; done ;; esac; done\n' > "$T/cg/bin/mkdir"
printf '#!/bin/sh\nshift 3; exec "$@"\n' > "$T/cg/bin/runuser"
chmod +x "$T/cg/bin/mkdir" "$T/cg/bin/runuser"
echo "cpu io memory pids" > "$T/cg/unit/cgroup.controllers"; : > "$T/cg/unit/cgroup.subtree_control"
ME="$(id -un)"
CG_OUT="$(PATH="$T/cg/bin:$PATH" bash -c "$(grep '^say() ' "$BOOT")
$(fn delegate_cgroup)
$(fn in_ci_cgroup)
delegate_cgroup '$T/cg/unit' '$ME' && echo \"run=\$CI_CGROUP\" && in_ci_cgroup sh -c 'echo moved=\$(cat \"\$1/cgroup.procs\")' _ \"\$CI_CGROUP\"")"
check "delegate_cgroup: boot.sh into <unit>/boot, memory and pids on (cpu and io not asked), ci/run and ci/spare under ci/, the suites in run/" \
  "[[ -s '$T/cg/unit/boot/cgroup.procs' && \"\$(cat '$T/cg/unit/cgroup.subtree_control')\" == '+pids' && -d '$T/cg/unit/ci/run' && -d '$T/cg/unit/ci/spare' ]] && grep -qx 'run=$T/cg/unit/ci/run' <<<\"\$CG_OUT\" && grep -qx 'moved=0' <<<\"\$CG_OUT\""
check "delegate_cgroup: the controllers switched on below ci/ for run/ and spare/, cpu never (a cpu task group has no autogroups)" \
  "[[ \"\$(cat '$T/cg/unit/ci/cgroup.subtree_control')\" == '+memory +pids' ]]"
# cpu_group_of on a fake tree (its /sys/fs/cgroup prefix moved under $T):
# nothing in the root task group, else the nearest cgroup at or above with
# cpu on (a cpu.weight file).
CGF="$T/cg/sys/fs/cgroup"
mkdir -p "$CGF/a/b/c"
{ fn cpu_group_of | sed "s#/sys/fs/cgroup#$CGF#g"
  echo "[[ -z \"\$(cpu_group_of '$CGF/a/b/c')\" ]] || exit 1"
  echo ": > '$CGF/a/cpu.weight'"
  echo "[[ \"\$(cpu_group_of '$CGF/a/b/c')\" == '$CGF/a' ]]"; } > "$T/cg/cpu-of.sh"
check "cpu_group_of: none in the root task group (autogroups apply), else the nearest cgroup with cpu on" \
  "grep -q '^cpu_group_of() {\$' '$BOOT' && bash '$T/cg/cpu-of.sh'"
check "boot.sh: says on the console whether the suites are in the root cpu task group" \
  "grep -qF 'cg_cpu=\"\$(cpu_group_of \"\${CI_CGROUP:-\$unit_cg}\")\"' '$BOOT' && grep -qF 'say \"cpu: WARNING: the suites share the cpu task group of' '$BOOT'"
check "delegate_cgroup: ci owns ci/ and its three delegation files (cgroup-v2.rst), and makes run/ and spare/ itself" \
  "grep -qF 'chown \"\$user:\$user\" \"\$d\" \"\$d/cgroup.procs\" \"\$d/cgroup.threads\" \"\$d/cgroup.subtree_control\"' '$BOOT' && grep -qF 'runuser -u \"\$user\" -- mkdir -p \"\$d/run\" \"\$d/spare\"' '$BOOT'"
check "delegate_cgroup: fails on a unit cgroup it cannot write (boot.sh then runs the suites where they ran before)" \
  "PATH='$T/cg/bin':\$PATH bash -c \"\$(grep '^say() ' '$BOOT'); \$(fn delegate_cgroup); CI_CGROUP=x; ! delegate_cgroup /proc/nonexistent/unit '$ME' 2>/dev/null\""
check "boot.sh: the pipeline and the shell-mode login run through in_ci_cgroup; mandu-ci.service delegates memory and pids, not cpu" \
  "grep -qF 'in_ci_cgroup runuser -u \"\$CI_USER\" -- env -i' '$BOOT' && grep -qF 'in_ci_cgroup setsid --ctty --wait runuser -l' '$BOOT' && grep -qx 'Delegate=memory pids' '$REPO/scripts/ci/guest/mandu-ci.service'"
check "boot.sh: after the watchdog, the stage watchdog: error in the runner's summary, else an error summary of its own" \
  "grep -qF 'add-stage --out \"\$RESULTS\" --stage watchdog=error' '$BOOT' && grep -qF 'summary.mjs\" write --out \"\$RESULTS\" \"\${meta[@]}\" --result error' '$BOOT'"

# --guest (§4.1): the default is ubuntu-2404; ubuntu-2604 boots its own image,
# named for it, and changes nothing else of the guest's boundary.
check "the default guest is ubuntu-2404" "grep -q '^# guest: ubuntu-2404\$' <<<\"\$OUT\""
G="$(dry --guest ubuntu-2604 --kind sandbox,replay-drill --need kernel --run-id gl-3-4 --source gitlab)"
rc=$?
K26="$("$F/scripts/ci/vm-image.sh" --key --guest ubuntu-2604)"
GJOB="$(grep '^#   ' <<<"$G" | sed 's/^#   //')"
gjv() { sed -n "s/^$1=//p" <<<"$GJOB"; }
check "--guest ubuntu-2604: exits 0, says the guest, boots mandu-ci-ubuntu-2604-<its key>.qcow2" \
  "[[ $rc -eq 0 ]] && grep -q '^# guest: ubuntu-2604\$' <<<\"\$G\" && grep -q \"^# image: $CACHE/mandu-ci-ubuntu-2604-$K26.qcow2\" <<<\"\$G\""
check "--guest ubuntu-2604 --need kernel: job.env names that image, the kinds and the kernel need" "[[ \$(gjv MANDU_CI_IMAGE) == mandu-ci-ubuntu-2604-$K26 && \$(gjv MANDU_CI_KINDS) == sandbox,replay-drill && \$(gjv MANDU_CI_NEED) == kernel ]]"
# The guest hands the need to the pipeline, and the pipeline to the runner: the
# kernel-linux-7 job is --kind sandbox,replay-drill --need kernel end to end.
check "boot.sh passes MANDU_CI_KINDS and MANDU_CI_NEED as --kind and --need" \
  "grep -qE '^for kv in kind:MANDU_CI_KINDS need:MANDU_CI_NEED ' '$REPO/scripts/ci/guest/boot.sh' && grep -q ' MANDU_CI_KINDS MANDU_CI_NEED ' <<<\" \$boot_keys \""
check "pipeline.sh takes --kind and --need and forwards --need to run-suites" \
  "grep -qF -- '--need) [[ \$# -ge 2 ]] || usage; NEED=' '$REPO/scripts/ci/pipeline.sh' && grep -qF -- '[[ -n \"\$NEED\" ]] && args+=(--need \"\$NEED\")' '$REPO/scripts/ci/pipeline.sh'"
# The GitLab pipeline lives only in the source repository (the public snapshot
# runs GitHub CI), so this check runs where the file is.
if [[ -f "$REPO/.gitlab-ci.yml" ]]; then
  check "the kernel-linux-7 job selects the kernel lane by kind and need" \
    "grep -qE '^      --kind sandbox,replay-drill\$' '$REPO/.gitlab-ci.yml' && grep -qE '^      --need kernel\$' '$REPO/.gitlab-ci.yml'"
fi
dry --tier kernel >/dev/null; check "the retired --tier is refused" "[[ $? -eq 2 ]]"
GQ="$(grep -v '^#' <<<"$G")"
check "--guest ubuntu-2604: still no network, no shared filesystem, the same three disks" \
  "grep -q -- '-nic none' <<<\"\$GQ\" && ! grep -qE -- 'netdev|virtio-net' <<<\"\$GQ\" && noshare \"\$GQ\" && [[ \$(grep -o -- 'serial=mandu-[a-z]*' <<<\"\$GQ\" | tr '\n' ' ') == 'serial=mandu-in serial=mandu-out ' ]]"
dry --guest ubuntu-2204 >/dev/null; check "an unknown --guest is refused" "[[ $? -eq 2 ]]"
dry --guest >/dev/null; check "--guest without a value is refused" "[[ $? -eq 2 ]]"

# refusals
dry --ref 'has space' >/dev/null; check "a ref outside the job.env charset is refused" "[[ $? -eq 2 ]]"
dry --run-id '../evil' >/dev/null; check "a run id outside [A-Za-z0-9.:-] is refused" "[[ $? -eq 2 ]]"
dry --run-id 'has_underscore' >/dev/null; check "a run id with _ is refused (the dashboard's id rule)" "[[ $? -eq 2 ]]"
dry --commit no-such-rev >/dev/null; check "an unknown commit is refused" "[[ $? -eq 2 ]]"
dry --source github >/dev/null; check "--source other than local|gitlab is refused" "[[ $? -eq 2 ]]"
dry --shell --exec true >/dev/null; check "--shell with --exec is refused" "[[ $? -eq 2 ]]"

# the work tree: +dirty, untracked-not-ignored in, ignored out
echo "change" >> "$F/arbiter/index.ts"; echo "new" > "$F/arbiter/new.ts"
# a relative link to a directory, as the inspector's fixtures links are
mkdir -p "$F/sub/deeper"; ln -s ../../arbiter "$F/sub/deeper/linked"
W="$(dry --worktree)"
check "--worktree with changes: commit <sha>+dirty" "grep -q \"^#   MANDU_CI_COMMIT=$SHA+dirty\" <<<\"\$W\""
( CI_REPO_ROOT="$F"; . "$F/scripts/ci/lib.sh"; ci_source_tar --worktree "$T/wt.tar"; ci_source_tar HEAD "$T/head.tar" )
wt="$(tar -tf "$T/wt.tar")"; hd="$(tar -tf "$T/head.tar")"
check "the work-tree tar has the untracked file and the change, under src/" "grep -qx 'src/arbiter/new.ts' <<<\"\$wt\" && tar -xOf '$T/wt.tar' src/arbiter/index.ts | grep -q change"
check "the work-tree tar has no ignored file (node_modules, secrets.local.json)" "! grep -qE 'node_modules|secrets\.local\.json' <<<\"\$wt\""
# GNU tar's --transform also rewrites link targets unless told not to (`S`):
# the link once arrived as `-> src/../../arbiter`, dangling in the guest.
mkdir -p "$T/wt-x"; tar -xf "$T/wt.tar" -C "$T/wt-x" src/sub/deeper/linked src/arbiter/new.ts 2>/dev/null
check "the work-tree tar keeps a relative symlink's target as written, so it resolves after unpacking" \
  "[[ \"\$(readlink '$T/wt-x/src/sub/deeper/linked')\" == ../../arbiter && -f '$T/wt-x/src/sub/deeper/linked/new.ts' ]]"
# the promoted replay baselines (step 5 decision 8): newest first under the cap,
# only <key>/baseline.json regular files of a key-named directory
B="$T/bstore"; mkdir -p "$B/k-old" "$B/k-new" "$B/k-big" "$B/bad name" "$B/k-link" "$B/k-other"
echo '{"a":1}' > "$B/k-old/baseline.json"; touch -d '2026-01-01' "$B/k-old/baseline.json"
echo '{"b":2}' > "$B/k-new/baseline.json"
head -c 4096 /dev/zero > "$B/k-big/baseline.json"; touch -d '2025-01-01' "$B/k-big/baseline.json"
echo '{}' > "$B/bad name/baseline.json"; ln -s "$B/k-new/baseline.json" "$B/k-link/baseline.json"; echo x > "$B/k-other/notes.txt"
cp "$T/head.tar" "$T/with-b.tar"
NBL="$( CI_REPO_ROOT="$F"; . "$F/scripts/ci/lib.sh"; ci_append_baselines "$B" "$T/with-b.tar" 1000 )"
wb="$(tar -tf "$T/with-b.tar" | grep '^src/.mandu-ci/' | sort | tr '\n' ' ')"
check "ci_append_baselines: the key dirs' baseline.json under src/.mandu-ci/baselines, the oversized, the misnamed and the symlink left out" \
  "[[ '$NBL' == 2 && '$wb' == 'src/.mandu-ci/baselines/k-new/baseline.json src/.mandu-ci/baselines/k-old/baseline.json ' ]]"
kb="$(tar -xOf "$T/with-b.tar" src/.mandu-ci/baselines/k-new/baseline.json)"
# the listing first: under pipefail, `tar | grep -q` fails when grep exits before tar finishes writing
wbl="$(tar -tf "$T/with-b.tar")"
kb_ok=0; grep -qx 'src/arbiter/index.ts' <<<"$wbl" && [[ "$kb" == '{"b":2}' ]] && kb_ok=1
check "ci_append_baselines: the tree is still there, and the entries' bytes are the store's" "[[ $kb_ok -eq 1 ]]"
nb0="$( CI_REPO_ROOT="$F"; . "$F/scripts/ci/lib.sh"; ci_append_baselines "$T/no-store" "$T/head.tar" )"
check "ci_append_baselines: an absent store adds nothing" "[[ '$nb0' == 0 ]]"
VR="$F/scripts/ci/vm-run.sh"; vm_gate=0
grep -qF 'if [[ $NETWORK -eq 0 && $OLLAMA -eq 0 && "$MODE" == run' "$VR" && grep -qF 'ci_append_baselines "$BSTORE" "$INPUT"' "$VR" && vm_gate=1
check "vm-run.sh brings the baselines for a per-push run only (not the nightly, --exec, --shell or --selftest)" "[[ $vm_gate -eq 1 ]]"
# the measured entry costs (§5.4): each entry's median over the host's last
# green full runs, as src/.mandu-ci/suite-costs.json; none, nothing appended
CR="$T/cruns"
crun() {  # crun <dir> <started> <result> <id:seconds>...
  local d="$CR/$1" started="$2" result="$3" e list=""; shift 3
  for e in "$@"; do list+="${list:+,}{\"id\":\"${e%%:*}\",\"result\":\"pass\",\"duration_s\":${e##*:}}"; done
  mkdir -p "$d"; printf '{"kind":"mandu-ci-run","started":"%s","result":"%s","entries":[%s]}\n' "$started" "$result" "$list" > "$d/summary.json"
}
crun gl-1-1 2026-10-01T00:00:00Z pass a:10 b:100 c:1
crun gl-2-2 2026-10-02T00:00:00Z pass a:20 b:300 c:1
crun gl-3-3 2026-10-03T00:00:00Z pass a:30 b:200 c:1
crun gl-4-4 2026-10-04T00:00:00Z fail a:999 b:999 c:1
crun gl-5-5 2026-10-05T00:00:00Z pass a:1
cp "$T/head.tar" "$T/with-c.tar"
NCO="$( CI_REPO_ROOT="$F"; . "$F/scripts/ci/lib.sh"; ci_append_costs "$CR" "$T/with-c.tar" )"
wcl="$(tar -tf "$T/with-c.tar")"
cj="$(tar -xOf "$T/with-c.tar" src/.mandu-ci/suite-costs.json | tr -d ' \n')"
check "ci_append_costs: the medians of the green full runs as src/.mandu-ci/suite-costs.json (the red run and the one-entry run left out)" \
  "[[ '$NCO' == 3 && '$cj' == '{\"a\":20,\"b\":200,\"c\":1}' ]] && grep -qx 'src/arbiter/index.ts' <<<\"\$wcl\""
cp "$T/head.tar" "$T/with-c1.tar"
NCL="$( CI_REPO_ROOT="$F"; . "$F/scripts/ci/lib.sh"; ci_append_costs "$CR" "$T/with-c1.tar" 1 )"
cj1="$(tar -xOf "$T/with-c1.tar" src/.mandu-ci/suite-costs.json | tr -d ' \n')"
check "ci_append_costs: [last] takes that many recent runs" "[[ '$NCL' == 3 && '$cj1' == '{\"a\":30,\"b\":200,\"c\":1}' ]]"
cp "$T/head.tar" "$T/no-c.tar"
nc0="$( CI_REPO_ROOT="$F"; . "$F/scripts/ci/lib.sh"; ci_append_costs "$T/no-runs" "$T/no-c.tar" )"
mkdir -p "$T/empty-runs"
nce="$( CI_REPO_ROOT="$F"; . "$F/scripts/ci/lib.sh"; ci_append_costs "$T/empty-runs" "$T/no-c.tar" )"
check "ci_append_costs: no runs dir, or no green run in it, adds nothing (the guest orders by the checked-in tables)" \
  "[[ '$nc0' == 0 && '$nce' == 0 ]] && cmp -s '$T/head.tar' '$T/no-c.tar'"
cost_gate=0
grep -qF 'ci_append_costs "$CRUNS" "$INPUT"' "$VR" && grep -qF 'MANDU_CI_NO_MEASURED_COSTS' "$VR" \
  && [[ "$(grep -cF 'if [[ $NETWORK -eq 0 && $OLLAMA -eq 0 && "$MODE" == run' "$VR")" -ge 2 ]] && cost_gate=1
check "vm-run.sh brings the measured costs for a per-push run only (not the nightly, --exec, --shell or --selftest)" "[[ $cost_gate -eq 1 ]]"
cost_pl=0
grep -qF 'args+=(--costs "$ROOT/.mandu-ci/suite-costs.json")' "$REPO/scripts/ci/pipeline.sh" && cost_pl=1
check "pipeline.sh passes the brought costs to run-suites --costs" "[[ $cost_pl -eq 1 ]]"
check "the commit tar is the commit (no untracked file, no change)" "grep -qx 'src/arbiter/index.ts' <<<\"\$hd\" && ! grep -q 'new.ts' <<<\"\$hd\" && ! tar -xOf '$T/head.tar' src/arbiter/index.ts | grep -q change"

# ── the nightly's options (continuous-integration.md §9) ────────────────────────
qline() { grep -v '^#' <<<"$1" | sed 's/\\,/,/g; s/\\ / /g'; }
jline() { grep "^#   $1=" <<<"$2" | cut -d= -f2-; }
CANARY_TOK="sk-ant-oat01-CANARYvmrun$(node -e 'process.stdout.write(require("crypto").randomBytes(60).toString("base64url"))')"
printf '%s\n' "$CANARY_TOK" | node "$F/scripts/ci/credential.mjs" install claude --dest "$T/cred/claude-credential.json" --subscription max 2>/dev/null
# The API lane's keys (§9.8), synthetic too.
AF="$T/cred/api-keys.json"
CANARY_ANT="sk-ant-api03-CANARYvmrun$(node -e 'process.stdout.write(require("crypto").randomBytes(60).toString("base64url"))')"
CANARY_OAI="sk-proj-CANARYvmrun$(node -e 'process.stdout.write(require("crypto").randomBytes(60).toString("base64url"))')"
printf '%s\n' "$CANARY_ANT" | node "$F/scripts/ci/credential.mjs" install api --provider anthropic --dest "$AF" 2>/dev/null
printf '%s\n' "$CANARY_OAI" | node "$F/scripts/ci/credential.mjs" install api --provider openai --dest "$AF" 2>/dev/null
API_NEEDLES="$(CRED_MJS="$F/scripts/ci/credential.mjs" A="$CANARY_ANT" O="$CANARY_OAI" node -e 'import(process.env.CRED_MJS).then(m=>{for(const t of [process.env.A,process.env.O])for(const b of m.needles(t))console.log(b.toString())})')"
# The subscription lane's Codex sign-in (§9.8), synthetic: JWT-shaped tokens
# valid for <days>, and a refresh token.
codex_signin() {  # codex_signin <out> <days>
  node -e '
    const r = (n) => require("crypto").randomBytes(n).toString("base64url");
    const b = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const exp = Math.floor(Date.now() / 1000) + Math.round(Number(process.argv[2]) * 86400);
    const jwt = () => `${b({ alg: "RS256", typ: "JWT" })}.${b({ exp })}.CANARYvmrun${r(96)}`;
    require("fs").writeFileSync(process.argv[1], JSON.stringify({ OPENAI_API_KEY: null, tokens: { id_token: jwt(), access_token: jwt(), refresh_token: "rt_CANARYvmrun" + r(48), account_id: "acct-ci" }, last_refresh: new Date().toISOString() }), { mode: 0o600 });' "$1" "$2"
}
XF="$T/cred/codex-auth.json"
codex_signin "$T/codex-src.json" 10
node "$F/scripts/ci/credential.mjs" install codex --from "$T/codex-src.json" --dest "$XF" 2>/dev/null
rm -f "$T/codex-src.json"
cfield() { node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).tokens[process.argv[2]])' "$XF" "$1"; }
CODEX_AT="$(cfield access_token)" CODEX_RT="$(cfield refresh_token)"
CODEX_NEEDLES="$(CRED_MJS="$F/scripts/ci/credential.mjs" A="$CODEX_AT" I="$(cfield id_token)" R="$CODEX_RT" node -e 'import(process.env.CRED_MJS).then(m=>{for(const t of [process.env.A,process.env.I,process.env.R])for(const b of m.needles(t))console.log(b.toString())})')"
# The tool credentials (§9.8 "Tool credentials"), synthetic: a Docker token
# (its username written beside it by install) and a GitGuardian token.
DF="$T/cred/docker-token" GF="$T/cred/gitguardian-token"
CANARY_DCK="dckr_pat_CANARYvmrun$(node -e 'process.stdout.write(require("crypto").randomBytes(24).toString("base64url"))')"
CANARY_GG="CANARYvmrun$(node -e 'process.stdout.write(require("crypto").randomBytes(40).toString("hex"))')"
printf '%s\nci-docker-user\n' "$CANARY_DCK" | env -u MANDU_CI_DOCKER_USER node "$F/scripts/ci/credential.mjs" install docker --dest "$DF" 2>/dev/null
printf '%s' "$CANARY_GG" | node "$F/scripts/ci/credential.mjs" install api --provider gitguardian --dest "$GF" 2>/dev/null
TOOL_NEEDLES="$(CRED_MJS="$F/scripts/ci/credential.mjs" A="$CANARY_DCK" G="$CANARY_GG" node -e 'import(process.env.CRED_MJS).then(m=>{for(const t of [process.env.A,process.env.G])for(const b of m.needles(t))console.log(b.toString())})')"
NETNS_OK=0; ( CI_REPO_ROOT="$F"; . "$F/scripts/ci/lib.sh"; ci_netns_bwrap >/dev/null ) && NETNS_OK=1

N="$(dry --network --kind live-drill)"
NQ="$(qline "$N")"
check "--network: one user-mode netdev and a virtio NIC, no -nic none" "grep -q -- '-netdev user,id=n0 ' <<<\"\$NQ\" && grep -q -- '-device virtio-net-pci,netdev=n0' <<<\"\$NQ\" && ! grep -q -- '-nic none' <<<\"\$NQ\""
check "--network: no port forward of any kind, not restricted (it has an uplink)" "! grep -qE -- 'hostfwd|guestfwd|restrict=on' <<<\"\$NQ\""
check "--network: still no shared filesystem" "noshare \"\$NQ\""
if [[ $NETNS_OK -eq 1 ]]; then
  check "--network: qemu runs in its own netns behind slirp4netns --disable-host-loopback" "grep -q '^# network: qemu in its own user+network namespace (.*), uplink slirp4netns --disable-host-loopback' <<<\"\$N\""
fi
check "--network: job.env says so" "[[ \$(jline MANDU_CI_NETWORK \"\$N\") == 1 && -z \$(jline MANDU_CI_OLLAMA \"\$N\") && -z \$(jline MANDU_CI_CREDENTIAL \"\$N\") ]]"
O="$(dry --ollama)"
OQ="$(qline "$O")"
check "--ollama alone: restrict=on and exactly one guestfwd, to 10.0.2.100:11434, through port-bridge.mjs connect <private socket>" \
  "grep -q -- 'restrict=on' <<<\"\$OQ\" && [[ \$(grep -o 'guestfwd=' <<<\"\$OQ\" | wc -l) -eq 1 ]] && grep -qE -- 'guestfwd=tcp:10\.0\.2\.100:11434-cmd:[^ ]*node [^ ]*/scripts/ci/port-bridge\.mjs connect [^ ]*/mandu-ci-ollama\.[^ /]*/s( |,|\$)' <<<\"\$OQ\" && ! grep -q hostfwd <<<\"\$OQ\""
check "--ollama: the bridge targets the host's 127.0.0.1:11434; job.env gives the guest 10.0.2.100:11434" "grep -q '^# ollama: guest 10.0.2.100:11434 -> port-bridge.mjs listen .* 127.0.0.1:11434' <<<\"\$O\" && [[ \$(jline MANDU_CI_OLLAMA \"\$O\") == 10.0.2.100:11434 ]]"
C="$(MANDU_CI_CLAUDE_CREDENTIAL="$T/cred/claude-credential.json" dry --network --credential claude)"
CQ="$(qline "$C")"
check "--credential claude: a fourth disk, read-only, from an fd set (no path), virtio serial mandu-cred" \
  "grep -q -- '-add-fd fd=7,set=7' <<<\"\$CQ\" && grep -q -- '-drive file=/dev/fdset/7,if=none,id=cred,format=raw,readonly=on' <<<\"\$CQ\" && grep -q -- 'virtio-blk-pci,drive=cred,serial=mandu-cred' <<<\"\$CQ\""
check "--credential claude: job.env names the kind, never the token; the dry run says the file is usable" "[[ \$(jline MANDU_CI_CREDENTIAL \"\$C\") == claude ]] && grep -q '^# credential: claude from .*claude-credential.json (usable)' <<<\"\$C\""
# (the module path goes by env: as process.argv[1] it would run credential.mjs's CLI)
NEEDLES="$(CRED_MJS="$F/scripts/ci/credential.mjs" TOK="$CANARY_TOK" node -e 'import(process.env.CRED_MJS).then(m=>{for(const b of m.needles(process.env.TOK))console.log(b.toString())})')"
leak=0; while IFS= read -r n; do grep -qF -- "$n" <<<"$C" && leak=1; done <<<"$NEEDLES"
check "--credential claude: no piece of the token in the dry run's output (checked against $(wc -l <<<"$NEEDLES") pieces)" "[[ $leak -eq 0 && \$(wc -l <<<\"\$NEEDLES\") -ge 5 ]]"
M="$(dry --network --credential claude)"
check "--credential with no file: the dry run says NOT USABLE" "grep -q '^# credential: claude from .*no-credential.json: NOT USABLE (no credential file' <<<\"\$M\""
A="$(MANDU_CI_API_CREDENTIAL="$AF" dry --network --credential api --lane api-key)"
AQ="$(qline "$A")"
check "--credential api: the same read-only fd-set disk, virtio serial mandu-cred" \
  "grep -q -- '-drive file=/dev/fdset/7,if=none,id=cred,format=raw,readonly=on' <<<\"\$AQ\" && grep -q -- 'virtio-blk-pci,drive=cred,serial=mandu-cred' <<<\"\$AQ\""
check "--credential api --lane api-key: job.env names the credential file kind and the lane; the dry run says the keys are usable" \
  "[[ \$(jline MANDU_CI_CREDENTIAL \"\$A\") == api && \$(jline MANDU_CI_LANE \"\$A\") == api-key ]] && grep -q '^# credential: api from .*api-keys.json (usable)' <<<\"\$A\""
leak=0; while IFS= read -r n; do grep -qF -- "$n" <<<"$A" && leak=1; done <<<"$API_NEEDLES"
check "--credential api: no piece of either key in the dry run's output" "[[ $leak -eq 0 ]]"
MA="$(MANDU_CI_API_CREDENTIAL="$T/no-api.json" dry --network --credential api)"
check "--credential api with no file: NOT USABLE" "grep -q '^# credential: api from .*no-api.json: NOT USABLE (no credential file' <<<\"\$MA\""
X="$(MANDU_CI_CLAUDE_CREDENTIAL="$T/cred/claude-credential.json" MANDU_CI_CODEX_CREDENTIAL="$XF" dry --network --credential claude,codex --lane subscription)"
XQ="$(qline "$X")"
check "--credential claude,codex: ONE read-only fd-set disk for both kinds" \
  "[[ \$(grep -o -- 'serial=mandu-cred' <<<\"\$XQ\" | wc -l) -eq 1 ]] && grep -q -- '-drive file=/dev/fdset/7,if=none,id=cred,format=raw,readonly=on' <<<\"\$XQ\""
check "--credential claude,codex --lane subscription: job.env names both kinds and the lane; each file is usable" \
  "[[ \$(jline MANDU_CI_CREDENTIAL \"\$X\") == claude,codex && \$(jline MANDU_CI_LANE \"\$X\") == subscription ]] && grep -q '^# credential: claude from .*claude-credential.json (usable)' <<<\"\$X\" && grep -q '^# credential: codex from .*codex-auth.json (usable)' <<<\"\$X\""
leak=0; while IFS= read -r n; do grep -qF -- "$n" <<<"$X" && leak=1; done <<<"$CODEX_NEEDLES"
check "--credential claude,codex: no piece of a Codex token (access, id, refresh) in the dry run's output" "[[ $leak -eq 0 && \$(wc -l <<<\"\$CODEX_NEEDLES\") -ge 15 ]]"
TL="$(MANDU_CI_CLAUDE_CREDENTIAL="$T/cred/claude-credential.json" MANDU_CI_DOCKER_CREDENTIAL="$DF" MANDU_CI_GITGUARDIAN_CREDENTIAL="$GF" dry --network --credential claude,docker,gitguardian --lane subscription)"
TLQ="$(qline "$TL")"
check "--credential claude,docker,gitguardian: ONE read-only fd-set disk for the three kinds" \
  "[[ \$(grep -o -- 'serial=mandu-cred' <<<\"\$TLQ\" | wc -l) -eq 1 ]] && grep -q -- '-drive file=/dev/fdset/7,if=none,id=cred,format=raw,readonly=on' <<<\"\$TLQ\""
check "--credential claude,docker,gitguardian --lane subscription: job.env names the kinds; each file is usable" \
  "[[ \$(jline MANDU_CI_CREDENTIAL \"\$TL\") == claude,docker,gitguardian ]] && grep -q '^# credential: docker from .*docker-token (usable)' <<<\"\$TL\" && grep -q '^# credential: gitguardian from .*gitguardian-token (usable)' <<<\"\$TL\""
leak=0; while IFS= read -r n; do grep -qF -- "$n" <<<"$TL" && leak=1; done <<<"$TOOL_NEEDLES"
check "--credential docker,gitguardian: no piece of either tool token in the dry run's output" "[[ $leak -eq 0 && \$(wc -l <<<\"\$TOOL_NEEDLES\") -ge 10 ]]"
AD="$(MANDU_CI_API_CREDENTIAL="$AF" MANDU_CI_DOCKER_CREDENTIAL="$DF" dry --network --credential api,docker --lane api-key)"
ADQ="$(qline "$AD")"
check "--credential api,docker --lane api-key (the API lane's Docker Sandboxes side): ONE read-only disk; job.env names both kinds and the lane; each file is usable" \
  "[[ \$(grep -o -- 'serial=mandu-cred' <<<\"\$ADQ\" | wc -l) -eq 1 && \$(jline MANDU_CI_CREDENTIAL \"\$AD\") == api,docker && \$(jline MANDU_CI_LANE \"\$AD\") == api-key ]] && grep -q '^# credential: api from .*api-keys.json (usable)' <<<\"\$AD\" && grep -q '^# credential: docker from .*docker-token (usable)' <<<\"\$AD\""
leak=0; while IFS= read -r n; do grep -qF -- "$n" <<<"$AD" && leak=1; done < <(printf '%s\n' "$API_NEEDLES" "$TOOL_NEEDLES")
check "--credential api,docker: no piece of a key or the Docker token in the dry run's output" "[[ $leak -eq 0 ]]"
TM="$(MANDU_CI_DOCKER_CREDENTIAL="$T/no-docker-token" dry --network --credential claude,docker)"
check "--credential docker with no token file: NOT USABLE" "grep -q '^# credential: docker from .*no-docker-token: NOT USABLE (no credential file' <<<\"\$TM\""
F2="$(dry --network --ollama --include-flaky --include-internet)"
check "--include-flaky / --include-internet reach job.env" "[[ \$(jline MANDU_CI_INCLUDE_FLAKY \"\$F2\") == 1 && \$(jline MANDU_CI_INCLUDE_INTERNET \"\$F2\") == 1 ]]"
D="$(MANDU_DEMO_IDS=demo-a,demo-b MANDU_DEMO_SIDES=mandu,baseline-none MANDU_DEMO_MODELS=sonnet,opus MANDU_DEMO_REPEAT=2 MANDU_DEMO_JOBS=6 dry --network --only live.demo-battery)"
check "the demo lane's choices (MANDU_DEMO_*) reach job.env from vm-run's environment (§9.9)" \
  "[[ \$(jline MANDU_DEMO_IDS \"\$D\") == demo-a,demo-b && \$(jline MANDU_DEMO_SIDES \"\$D\") == mandu,baseline-none && \$(jline MANDU_DEMO_MODELS \"\$D\") == sonnet,opus && \$(jline MANDU_DEMO_REPEAT \"\$D\") == 2 && \$(jline MANDU_DEMO_JOBS \"\$D\") == 6 ]] && [[ -z \$(jline MANDU_DEMO_IDS \"\$N\") ]]"
MANDU_DEMO_IDS='a b' dry --network >/dev/null; check "a MANDU_DEMO_* value outside the job.env charset is refused" "[[ $? -eq 2 ]]"
DEMOF="$(MANDU_DEMO_SIDES=mandu MANDU_DEMO_AGENTS=claude dry --network --only live.demo-battery --demo-ids demo-a,demo-b --demo-sides baseline-none,baseline-nono --demo-models sonnet --demo-repeat 3 --demo-jobs 4 --demo-agents claude,codex)"
check "--demo-ids/-sides/-models/-repeat/-jobs/-agents reach job.env, each flag winning over its MANDU_DEMO_* variable" \
  "[[ \$(jline MANDU_DEMO_IDS \"\$DEMOF\") == demo-a,demo-b && \$(jline MANDU_DEMO_SIDES \"\$DEMOF\") == baseline-none,baseline-nono && \$(jline MANDU_DEMO_MODELS \"\$DEMOF\") == sonnet && \$(jline MANDU_DEMO_REPEAT \"\$DEMOF\") == 3 && \$(jline MANDU_DEMO_JOBS \"\$DEMOF\") == 4 && \$(jline MANDU_DEMO_AGENTS \"\$DEMOF\") == claude,codex ]]"
dry --network --demo-ids 'a b' >/dev/null; check "a --demo-* value outside the job.env charset is refused" "[[ $? -eq 2 ]]"
dry --demo-sides >/dev/null; check "--demo-sides without a value is refused" "[[ $? -eq 2 ]]"
TF="$(MANDU_CI_TIMEOUT=60 dry --timeout 7200)"
check "--timeout sets the guest's timeout, winning over MANDU_CI_TIMEOUT" "grep -q '^# timeout: 7200s' <<<\"\$TF\""
dry --timeout soon >/dev/null; check "--timeout that is not seconds is refused" "[[ $? -eq 2 ]]"
check "--help prints the whole header, through its exit codes" "\"$F/scripts/ci/vm-run.sh\" --help | tail -1 | grep -q '1 fail, 2 error'"
check "boot.sh hands the demo lane's keys to the pipeline (and a sandboxed entry's box)" \
  "grep -q '^DEMO_KEYS=\"MANDU_DEMO_IDS MANDU_DEMO_SIDES MANDU_DEMO_MODELS MANDU_DEMO_REPEAT MANDU_DEMO_JOBS MANDU_DEMO_AGENTS\"\$' '$REPO/scripts/ci/guest/boot.sh' && grep -q '\"\${demo_env\[@\]}\"' '$REPO/scripts/ci/guest/boot.sh'"
bad=0
for out in "$N" "$O" "$C" "$A" "$X" "$TL" "$AD" "$F2" "$D"; do
  while IFS= read -r l; do
    [[ "$l" =~ ^\# ]] && continue
    [[ "$l" =~ ^([A-Z_][A-Z0-9_]*)=([A-Za-z0-9_.,:/@+=-]*)$ ]] && [[ " $boot_keys " == *" ${BASH_REMATCH[1]} "* ]] || { bad=1; echo "  refused by boot.sh: $l"; }
  done < <(grep '^#   ' <<<"$out" | sed 's/^#   //')
done
check "the nightly's job.env lines are all in boot.sh's grammar and key list" "[[ $bad -eq 0 ]]"

dry --credential claude >/dev/null; check "--credential without --network is refused" "[[ $? -eq 2 ]]"
dry --network --credential gemini >/dev/null; check "an unknown --credential kind is refused" "[[ $? -eq 2 ]]"
dry --network --credential claude,api >/dev/null; check "--credential mixing a subscription kind with api is refused" "[[ $? -eq 2 ]]"
dry --network --credential codex,api >/dev/null; check "--credential codex,api is refused" "[[ $? -eq 2 ]]"
dry --network --credential gitguardian,api >/dev/null; check "--credential gitguardian,api is refused (only docker rides with api)" "[[ $? -eq 2 ]]"
dry --network --credential api,docker,gitguardian --lane api-key >/dev/null; check "--credential api,docker,gitguardian is refused" "[[ $? -eq 2 ]]"
dry --network --credential docker --lane api-key >/dev/null; check "--lane api-key with only a tool credential is refused" "[[ $? -eq 2 ]]"
dry --network --credential api,docker --lane subscription >/dev/null; check "--lane subscription with api,docker is refused" "[[ $? -eq 2 ]]"
dry --network --credential claude,docker --lane api-key >/dev/null; check "--lane api-key with a tool credential is refused" "[[ $? -eq 2 ]]"
dry --network --credential claude,codex --lane api-key >/dev/null; check "--lane api-key with subscription credentials is refused" "[[ $? -eq 2 ]]"
dry --network --credential api --lane subscription >/dev/null; check "--lane subscription with the api credential is refused" "[[ $? -eq 2 ]]"
dry --network --lane nightly >/dev/null; check "--lane other than subscription or api-key is refused" "[[ $? -eq 2 ]]"
dry --network --credential api --lane api >/dev/null; check "the retired lane name api is refused" "[[ $? -eq 2 ]]"
dry --network --credential claude --shell >/dev/null; check "--credential with --shell is refused" "[[ $? -eq 2 ]]"
dry --network --credential claude --exec true >/dev/null; check "--credential with --exec is refused" "[[ $? -eq 2 ]]"
dry --include-internet >/dev/null; check "--include-internet without --network is refused" "[[ $? -eq 2 ]]"
MANDU_CI_OLLAMA_HOST=10.1.2.3:11434 dry --ollama >/dev/null; check "an Ollama bridge target off this host's loopback is refused" "[[ $? -eq 2 ]]"

# A real (not dry) run with no credential file fails in seconds, before any
# image build or boot, and still records an `error` run with the reason.
R="$("$F/scripts/ci/vm-run.sh" --network --credential claude --run-id nocred-1 --out "$T/nocred-out" 2>&1)"; rc=$?
check "no credential file: exit 2, the reason and the human's setup steps, no image built" \
  "[[ $rc -eq 2 ]] && grep -q 'no credential file at' <<<\"\$R\" && grep -q 'claude setup-token' <<<\"\$R\" && grep -q 'credential.mjs install claude' <<<\"\$R\" && ! grep -q 'building it' <<<\"\$R\" && [[ ! -e '$CACHE/mandu-ci-'*.qcow2 ]]"
check "no credential file: the run is recorded as an error with the reason (runs dir and --out)" \
  "grep -q '\"result\": \"error\"' '$RUNS/nocred-1/summary.json' && grep -q 'credential: not usable: no credential file' '$T/nocred-out/summary.json'"
chmod 644 "$T/cred/claude-credential.json"
R="$(MANDU_CI_CLAUDE_CREDENTIAL="$T/cred/claude-credential.json" "$F/scripts/ci/vm-run.sh" --network --credential claude --run-id opencred-1 2>&1)"; rc=$?
check "a credential file others can read is refused the same way" "[[ $rc -eq 2 ]] && grep -q 'chmod 600' <<<\"\$R\""
chmod 600 "$T/cred/claude-credential.json"

# nightly.sh --weekly: the api-key lane's rotation, one agent a night (§9.8),
# over a manifest of this fixture's own (suites.mjs list --agents).
mkdir -p "$F/tests"
cat > "$F/tests/suites.mjs" <<'EOF'
const e = (id, agent) => ({ id, kind: "live-drill", axis: "secrets", cwd: ".", cmd: ["true"], needs: [agent, "anthropic-api-key"],
  timeout: 5, parallel: false, gate: null, select: null, flaky: null, internet: false, platforms: ["linux"], env: {}, credential: "api-key", agent });
export const entries = [e("drill.conf.opencode", "opencode"), e("drill.conf.opencode2", "opencode2"), e("drill.conf.openclaw", "openclaw"), e("drill.conf.goose", "goose")];
export default entries;
EOF
APIF="$T/cred/api-keys.json"
WK() { MANDU_CI_API_CREDENTIAL="$APIF" MANDU_CI_WEEKDAY="$1" "$F/scripts/ci/nightly.sh" --lane api-key --weekly --dry-run 2>&1; }
W1="$(WK 1)"; w1=$?
check "nightly.sh --weekly on a Monday: OpenCode, both generations, and nothing else" \
  "[[ $w1 -eq 0 ]] && grep -q 'weekly API-key rotation, weekday 1: opencode (2 entries)' <<<\"\$W1\" && grep -q 'drill.conf.opencode,drill.conf.opencode2' <<<\"\$W1\" && ! grep -q 'openclaw\|goose' <<<\"\$(grep -v rotation <<<\"\$W1\")\""
W3="$(WK 3)"; W5="$(WK 5)"
check "nightly.sh --weekly: Wednesday OpenClaw, Friday Goose" \
  "grep -q 'weekday 3: openclaw (1 entries)' <<<\"\$W3\" && grep -q 'drill.conf.openclaw' <<<\"\$W3\" && grep -q 'weekday 5: goose (1 entries)' <<<\"\$W5\""
W2="$(WK 2)"; w2=$?
check "nightly.sh --weekly on another night: runs nothing and exits 0" \
  "[[ $w2 -eq 0 ]] && grep -q 'runs no agent tonight (weekday 2' <<<\"\$W2\" && ! grep -q qemu <<<\"\$W2\""
WS="$(MANDU_CI_CLAUDE_CREDENTIAL="$T/cred/claude-credential.json" "$F/scripts/ci/nightly.sh" --lane subscription --weekly --dry-run 2>&1)"; ws=$?
check "nightly.sh --weekly outside the api-key lane is refused" "[[ $ws -eq 2 ]] && grep -q 'the api-key lane' <<<\"\$WS\""
WB="$(WK 9)"; wb=$?
check "nightly.sh --weekly with a weekday outside 1-7 is refused" "[[ $wb -eq 2 ]]"
rm -f "$F/tests/suites.mjs"

# nightly.sh: the scheduled jobs' command lines, one per lane (§9.8)
NL="$(MANDU_CI_CLAUDE_CREDENTIAL="$T/cred/claude-credential.json" "$F/scripts/ci/nightly.sh" --lane subscription --dry-run --run-id gl-9-9 --source gitlab 2>&1)"
check "nightly.sh --lane subscription, no Codex sign-in on the host: says so in one line; the claude credential only" \
  "grep -q '^nightly: no Codex sign-in on this host (.*no-codex.json): the ChatGPT-sign-in suites will skip' <<<\"\$NL\""
check "nightly.sh --lane subscription: the nightly kinds, every flaky entry, internet entries, network, Ollama, the claude credential, the lane" \
  "[[ \$(jline MANDU_CI_KINDS \"\$NL\") == live-drill,env,eval && -z \$(jline MANDU_CI_NEED \"\$NL\") && \$(jline MANDU_CI_INCLUDE_FLAKY \"\$NL\") == 1 && \$(jline MANDU_CI_INCLUDE_INTERNET \"\$NL\") == 1 && \$(jline MANDU_CI_NETWORK \"\$NL\") == 1 && \$(jline MANDU_CI_OLLAMA \"\$NL\") == 10.0.2.100:11434 && \$(jline MANDU_CI_CREDENTIAL \"\$NL\") == claude && \$(jline MANDU_CI_LANE \"\$NL\") == subscription ]]"
NX="$(MANDU_CI_CLAUDE_CREDENTIAL="$T/cred/claude-credential.json" MANDU_CI_CODEX_CREDENTIAL="$XF" "$F/scripts/ci/nightly.sh" --lane subscription --dry-run 2>&1)"
check "nightly.sh --lane subscription with a fresh Codex sign-in: no refresh, both kinds on the disk" \
  "grep -q 'codex: fresh enough, not refreshed' <<<\"\$NX\" && [[ \$(jline MANDU_CI_CREDENTIAL \"\$NX\") == claude,codex ]] && grep -q '^# credential: codex from .*codex-auth.json (usable)' <<<\"\$NX\""
leak=0; while IFS= read -r n; do grep -qF -- "$n" <<<"$NX" && leak=1; done <<<"$CODEX_NEEDLES"
check "nightly.sh with the Codex sign-in: no piece of a Codex token in its output" "[[ $leak -eq 0 ]]"
XS="$T/cred/codex-1d.json"; codex_signin "$T/c1.json" 1; node "$F/scripts/ci/credential.mjs" install codex --from "$T/c1.json" --dest "$XS" 2>/dev/null
NX1="$(MANDU_CI_CLAUDE_CREDENTIAL="$T/cred/claude-credential.json" MANDU_CI_CODEX_CREDENTIAL="$XS" "$F/scripts/ci/nightly.sh" --lane subscription --dry-run 2>&1)"
check "nightly.sh: a Codex sign-in with a day left is refreshed first; a failed refresh warns, and the lane keeps it while it covers the run" \
  "grep -q 'codex: not refreshed: the refresh request failed' <<<\"\$NX1\" && grep -q 'WARNING: the Codex sign-in was not refreshed' <<<\"\$NX1\" && [[ \$(jline MANDU_CI_CREDENTIAL \"\$NX1\") == claude,codex ]]"
XE="$T/cred/codex-1h.json"; codex_signin "$T/c2.json" 0.04; node "$F/scripts/ci/credential.mjs" install codex --from "$T/c2.json" --dest "$XE" 2>/dev/null
NX2="$(MANDU_CI_CLAUDE_CREDENTIAL="$T/cred/claude-credential.json" MANDU_CI_CODEX_CREDENTIAL="$XE" "$F/scripts/ci/nightly.sh" --lane subscription --dry-run 2>&1)"
check "nightly.sh: a Codex sign-in that cannot be refreshed and does not cover the run: the lane runs without it, and says so" \
  "grep -q 'WARNING: the Codex sign-in is not usable for this run' <<<\"\$NX2\" && [[ \$(jline MANDU_CI_CREDENTIAL \"\$NX2\") == claude ]]"
NA="$(MANDU_CI_API_CREDENTIAL="$AF" MANDU_CI_CODEX_CREDENTIAL="$XF" "$F/scripts/ci/nightly.sh" --lane api-key --dry-run --run-id gl-9-10 --source gitlab 2>&1)"
check "nightly.sh --lane api-key: the same selection, the api credential file kind, the lane, no Ollama, a 3 h timeout" \
  "[[ \$(jline MANDU_CI_KINDS \"\$NA\") == live-drill,env,eval && \$(jline MANDU_CI_INCLUDE_FLAKY \"\$NA\") == 1 && \$(jline MANDU_CI_NETWORK \"\$NA\") == 1 && -z \$(jline MANDU_CI_OLLAMA \"\$NA\") && \$(jline MANDU_CI_CREDENTIAL \"\$NA\") == api && \$(jline MANDU_CI_LANE \"\$NA\") == api-key ]] && grep -q '^# timeout: 10800s' <<<\"\$NA\""
"$F/scripts/ci/nightly.sh" --dry-run >/dev/null 2>&1; check "nightly.sh without --lane is refused" "[[ $? -eq 2 ]]"
"$F/scripts/ci/nightly.sh" --lane api --dry-run >/dev/null 2>&1; check "nightly.sh --lane api (the retired name) is refused" "[[ $? -eq 2 ]]"
NT="$(MANDU_CI_TIMEOUT=60 "$F/scripts/ci/nightly.sh" --lane subscription --canary-credential --dry-run 2>&1)"
check "nightly.sh: an 8 h timeout unless MANDU_CI_TIMEOUT says otherwise" "grep -q '^# timeout: 28800s' <<<\"\$NL\" && grep -q '^# timeout: 60s' <<<\"\$NT\""
NC="$("$F/scripts/ci/nightly.sh" --lane subscription --canary-credential --dry-run --only integration.ollama-doctor 2>&1)"
check "nightly.sh --canary-credential: a synthetic token and Codex sign-in, usable, never refreshed, removed afterwards; --only passes through" \
  "grep -q 'a synthetic token and Codex sign-in, not logins' <<<\"\$NC\" && grep -q '^# credential: claude from .*mandu-ci-canary\..*(usable)' <<<\"\$NC\" && grep -q '^# credential: codex from .*mandu-ci-canary\..*(usable)' <<<\"\$NC\" && [[ \$(jline MANDU_CI_CREDENTIAL \"\$NC\") == claude,codex ]] && ! grep -q 'refresh' <<<\"\$NC\" && [[ \$(jline MANDU_CI_ONLY \"\$NC\") == integration.ollama-doctor ]] && cdir=\$(sed -n 's|^nightly: .*(\(.*\)/claude-credential.json, .*)\$|\1|p' <<<\"\$NC\") && [[ -n \"\$cdir\" && ! -e \"\$cdir\" ]]"
NCA="$("$F/scripts/ci/nightly.sh" --lane api-key --canary-credential --dry-run 2>&1)"
check "nightly.sh --lane api-key --canary-credential: synthetic keys, usable, removed afterwards" \
  "grep -q 'synthetic keys, not accounts' <<<\"\$NCA\" && grep -q '^# credential: api from .*mandu-ci-canary\..*(usable)' <<<\"\$NCA\" && cdir=\$(sed -n 's|^nightly: .*(\(.*\)/api-keys.json)\$|\1|p' <<<\"\$NCA\") && [[ -n \"\$cdir\" && ! -e \"\$cdir\" ]]"
NB="$(PATH="$T/badbin:$PATH" "$F/scripts/ci/nightly.sh" --lane subscription --canary-credential --dry-run 2>&1)"
check "nightly.sh --canary-credential does not use base64(1) from PATH" \
  "grep -q '^# credential: claude from .*mandu-ci-canary\..*(usable)' <<<\"\$NB\" && ! grep -q 'broken base64' <<<\"\$NB\""

# ── the credential canary, end to end, with a stand-in guest ───────────────
# A fake qemu-system-x86_64 plays the guest: it reads the credential the way
# the real guest does (the tar on fd 7, the fd set qemu is given), says
# whether the tar still had a path while it ran, writes a valid results tar
# onto the output disk, and on request LEAKS the token into its console or a
# results log. vm-run must then withhold both, record an `error`, and print
# no piece of the token. Needs a bwrap that can make a user+net namespace
# (the networked guest runs in one); SKIPs otherwise.
if [[ $NETNS_OK -eq 1 ]]; then
  FB="$T/fakebin"; mkdir -p "$FB"
  cat > "$FB/qemu-img" <<'EOF'
#!/usr/bin/env bash
for last; do :; done; : > "$last"
EOF
  cat > "$FB/qemu-system-x86_64" <<'EOF'
#!/usr/bin/env bash
# A stand-in guest for ci-vm-run.test.sh (never a real qemu).
console="" out="" in="" pf="" prev=""
for a in "$@"; do
  case "$a" in
    file:*) console="${a#file:}" ;;
    file=*output.raw,*) out="${a#file=}"; out="${out%%,*}" ;;
    file=*input.tar,*) in="${a#file=}"; in="${in%%,*}" ;;
  esac
  [[ "$prev" == -pidfile ]] && pf="$a"
  prev="$a"
done
work="$(dirname "$out")"
# As qemu's -pidfile does; then wait until vm-run registered this guest for
# `mandu reap` (scripts/lib/guest-registry.sh).
reg=""
if [[ -n "$pf" ]]; then
  echo $$ > "$pf"
  for _ in $(seq 50); do [[ -f "$MANDU_RUNTIME_DIR/vm-guests/vm-run-$$.json" ]] && { reg=1; break; }; sleep 0.1; done
fi
tok="$(tar -xOf /proc/self/fd/7 claude/.credentials.json 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(JSON.parse(s).claudeAiOauth.accessToken)}catch{}})')"
# The API lane's disk (credential.mjs TAR_PATH.api): leak its SECOND key, so
# the canary is shown to look for every key, not only the first.
[[ -n "$tok" ]] || tok="$(tar -xOf /proc/self/fd/7 api/keys.json 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(JSON.parse(s).openai)}catch{}})')"
# The subscription lane's Codex sign-in (TAR_PATH.codex): its access token,
# when its refresh token is empty (the reduced copy).
# The tool kinds (TAR_PATH.docker, TAR_PATH.gitguardian).
dtok="$(tar -xOf /proc/self/fd/7 docker/auth.json 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const o=JSON.parse(s);if(o.username)process.stdout.write(o.token)}catch{}})')"
gtok="$(tar -xOf /proc/self/fd/7 gitguardian/key.json 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(JSON.parse(s).token)}catch{}})')"
ctok="$(tar -xOf /proc/self/fd/7 codex/auth.json 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const t=JSON.parse(s).tokens;if(t.refresh_token==="")process.stdout.write(t.access_token)}catch{}})')"
{
  echo "mandu-ci: fake guest up"
  [[ -n "$reg" ]] && echo "mandu-ci: FAKE: registered for mandu reap"
  [[ -e "$work/cred.tar" ]] && echo "mandu-ci: FAKE: the credential tar still has a path"
  [[ "$tok" == sk-ant-oat01-* ]] && echo "mandu-ci: FAKE: credential read from fd 7"
  [[ "$tok" == sk-proj-* ]] && echo "mandu-ci: FAKE: api keys read from fd 7"
  [[ -n "$ctok" ]] && echo "mandu-ci: FAKE: codex sign-in read from fd 7, no refresh token"
  [[ -n "$dtok" && -n "$gtok" ]] && echo "mandu-ci: FAKE: docker and gitguardian tokens read from fd 7"
  [[ "${FAKE_LEAK:-}" == docker ]] && echo "mandu-ci: oops ${dtok: -20}"
  [[ "${FAKE_LEAK:-}" == console ]] && echo "mandu-ci: oops $tok"
  # A refresh token the guest never had (FAKE_RT: a path this test cannot
  # otherwise make); the canary looks for it all the same.
  [[ "${FAKE_LEAK:-}" == refresh ]] && echo "mandu-ci: oops ${FAKE_RT:-}"
} > "$console"
r="$(mktemp -d)"; mkdir -p "$r/logs"
eval "$(tar -xOf "$in" job.env | grep -E '^MANDU_CI_(RUN_ID|COMMIT|REF|IMAGE|SOURCE)=')"
echo "fake suite ok" > "$r/logs/fake.log"
[[ "${FAKE_LEAK:-}" == results ]] && echo "debug: Authorization: Bearer ${tok:10:30}" >> "$r/logs/fake.log"
[[ "${FAKE_LEAK:-}" == codex ]] && echo "debug: Authorization: Bearer ${ctok: -40}" >> "$r/logs/fake.log"
[[ "${FAKE_LEAK:-}" == gitguardian ]] && echo "debug: Authorization: Token ${gtok:5:25}" >> "$r/logs/fake.log"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
node -e 'const [run,commit,ref,image,source,now,out]=process.argv.slice(1);require("fs").writeFileSync(out,JSON.stringify({schema:1,kind:"mandu-ci-run",run,source,commit,ref,image,started:now,finished:now,result:"pass",entries:[{id:"fake",kind:"unit",result:"pass",pass:1,fail:0,skip:0,duration_s:1,log:"logs/fake.log"}]}))' \
  "$MANDU_CI_RUN_ID" "$MANDU_CI_COMMIT" "$MANDU_CI_REF" "$MANDU_CI_IMAGE" "$MANDU_CI_SOURCE" "$now" "$r/summary.json"
tar -cf "$out" -C "$r" --format=gnu . && rm -rf "$r"
EOF
  chmod +x "$FB/qemu-img" "$FB/qemu-system-x86_64"
  KEY="$("$F/scripts/ci/vm-image.sh" --key)"
  mkdir -p "$CACHE"; echo fake-image > "$CACHE/mandu-ci-$KEY.qcow2"
  CF="$T/cred/claude-credential.json"
  fake() { PATH="$FB:$PATH" MANDU_RUNTIME_DIR="$T/rt" MANDU_CI_CLAUDE_CREDENTIAL="$CF" MANDU_CI_TIMEOUT=120 "$F/scripts/ci/vm-run.sh" --network --credential claude --vcpus 1 --mem 256 "$@" 2>&1; }
  noleak() {  # noleak <text> <path...>: no piece of the canary token in the text or under the paths
    local n
    while IFS= read -r n; do
      grep -qF -- "$n" <<<"$1" && { echo "  a piece of the token is in the job log"; return 1; }
      [[ $# -gt 1 ]] && grep -rqF -- "$n" "${@:2}" 2>/dev/null && { echo "  a piece of the token is under ${*:2}"; return 1; }
    done <<<"$NEEDLES"
    return 0
  }
  G="$(fake --run-id canary-clean --out "$T/co-clean")"; rc=$?
  check "fake guest, no leak: the run passes and its results are collected" "[[ $rc -eq 0 ]] && grep -qE '\"result\": *\"pass\"' '$RUNS/canary-clean/summary.json'"
  check "fake guest: it read the credential from fd 7, and the tar had no path while it ran" "grep -q 'FAKE: credential read from fd 7' <<<\"\$G\" && ! grep -q 'still has a path' <<<\"\$G\""
  check "fake guest: the canary scanned the console and the results disk, then what was published" "[[ \$(grep -c 'canary: clean' <<<\"\$G\") -eq 2 ]]"
  check "fake guest: no piece of the token in the job log, the runs dir or --out" "noleak \"\$G\" '$RUNS/canary-clean' '$T/co-clean'"
  check "fake guest: the work dir (disks, the unlinked credential) is gone" "! ls -d '$CACHE/runs/canary-clean.'* 2>/dev/null | grep -q ."
  check "fake guest: registered for mandu reap while it ran (qemu -pidfile), and out of the registry after" \
    "grep -q 'FAKE: registered for mandu reap' <<<\"\$G\" && [[ -z \"\$(ls -A '$T/rt/vm-guests' 2>/dev/null)\" ]]"
  for where in console results; do
    G="$(FAKE_LEAK=$where fake --run-id "canary-$where" --out "$T/co-$where")"; rc=$?
    check "fake guest leaks the token into its $where: exit 2, an error run naming the canary" \
      "[[ $rc -eq 2 ]] && grep -q 'CREDENTIAL CANARY' <<<\"\$G\" && grep -q '\"reason\": \"credential canary' '$RUNS/canary-$where/summary.json' && grep -q '\"result\": \"error\"' '$T/co-$where/summary.json'"
    check "fake guest leaks into its $where: no piece of the token in the job log, the runs dir or --out; no console kept" \
      "noleak \"\$G\" '$RUNS/canary-$where' '$T/co-$where' && [[ ! -s '$RUNS/canary-$where/console.log' && ! -e '$RUNS/canary-$where/logs' ]]"
  done
  # The API lane (§9.8): the same disk, canary and withholding for its keys.
  fake_api() { PATH="$FB:$PATH" MANDU_RUNTIME_DIR="$T/rt" MANDU_CI_API_CREDENTIAL="$AF" MANDU_CI_TIMEOUT=120 "$F/scripts/ci/vm-run.sh" --network --credential api --lane api-key --vcpus 1 --mem 256 "$@" 2>&1; }
  G="$(fake_api --run-id canary-api-clean --out "$T/co-api-clean")"; rc=$?
  check "fake guest, api lane, no leak: passes; it read the keys from fd 7; two clean canary scans" \
    "[[ $rc -eq 0 ]] && grep -q 'FAKE: api keys read from fd 7' <<<\"\$G\" && ! grep -q 'still has a path' <<<\"\$G\" && [[ \$(grep -c 'canary: clean' <<<\"\$G\") -eq 2 ]]"
  G="$(FAKE_LEAK=results fake_api --run-id canary-api-results --out "$T/co-api-results")"; rc=$?
  check "fake guest, api lane, leaks its OpenAI key into its results: exit 2, an error run, nothing of it published" \
    "[[ $rc -eq 2 ]] && grep -q 'CREDENTIAL CANARY' <<<\"\$G\" && grep -q '\"reason\": \"credential canary' '$RUNS/canary-api-results/summary.json' && NEEDLES=\"\$API_NEEDLES\" noleak \"\$G\" '$RUNS/canary-api-results' '$T/co-api-results'"
  # The subscription lane with the Codex sign-in (§9.8): both kinds on one
  # disk; the canary covers the access token AND the host's refresh token.
  fake_sub() { PATH="$FB:$PATH" MANDU_RUNTIME_DIR="$T/rt" MANDU_CI_CLAUDE_CREDENTIAL="$CF" MANDU_CI_CODEX_CREDENTIAL="$XF" MANDU_CI_TIMEOUT=120 "$F/scripts/ci/vm-run.sh" --network --credential claude,codex --lane subscription --vcpus 1 --mem 256 "$@" 2>&1; }
  G="$(fake_sub --run-id canary-sub-clean --out "$T/co-sub-clean")"; rc=$?
  check "fake guest, subscription lane with Codex, no leak: passes; it read both kinds from fd 7, the Codex copy without a refresh token" \
    "[[ $rc -eq 0 ]] && grep -q 'FAKE: credential read from fd 7' <<<\"\$G\" && grep -q 'FAKE: codex sign-in read from fd 7, no refresh token' <<<\"\$G\" && [[ \$(grep -c 'canary: clean' <<<\"\$G\") -eq 2 ]]"
  for where in codex refresh; do
    G="$(FAKE_LEAK=$where FAKE_RT="$CODEX_RT" fake_sub --run-id "canary-sub-$where" --out "$T/co-sub-$where")"; rc=$?
    check "fake guest leaks the Codex $([[ $where == codex ]] && echo 'access token into its results' || echo 'refresh token into its console'): exit 2, an error run, nothing of it published" \
      "[[ $rc -eq 2 ]] && grep -q 'CREDENTIAL CANARY' <<<\"\$G\" && grep -q '\"reason\": \"credential canary' '$RUNS/canary-sub-$where/summary.json' && NEEDLES=\"\$CODEX_NEEDLES\" noleak \"\$G\" '$RUNS/canary-sub-$where' '$T/co-sub-$where'"
  done
  # The tool credentials (§9.8 "Tool credentials"): beside claude on the
  # subscription lane; the canary covers both tokens.
  fake_tool() { PATH="$FB:$PATH" MANDU_RUNTIME_DIR="$T/rt" MANDU_CI_CLAUDE_CREDENTIAL="$CF" MANDU_CI_DOCKER_CREDENTIAL="$DF" MANDU_CI_GITGUARDIAN_CREDENTIAL="$GF" MANDU_CI_TIMEOUT=120 "$F/scripts/ci/vm-run.sh" --network --credential claude,docker,gitguardian --lane subscription --vcpus 1 --mem 256 "$@" 2>&1; }
  G="$(fake_tool --run-id canary-tool-clean --out "$T/co-tool-clean")"; rc=$?
  check "fake guest, claude,docker,gitguardian, no leak: passes; it read all three from fd 7; two clean canary scans" \
    "[[ $rc -eq 0 ]] && grep -q 'FAKE: credential read from fd 7' <<<\"\$G\" && grep -q 'FAKE: docker and gitguardian tokens read from fd 7' <<<\"\$G\" && [[ \$(grep -c 'canary: clean' <<<\"\$G\") -eq 2 ]]"
  for where in docker gitguardian; do
    G="$(FAKE_LEAK=$where fake_tool --run-id "canary-tool-$where" --out "$T/co-tool-$where")"; rc=$?
    check "fake guest leaks the $where token into its $([[ $where == docker ]] && echo console || echo results): exit 2, an error run, nothing of it published" \
      "[[ $rc -eq 2 ]] && grep -q 'CREDENTIAL CANARY' <<<\"\$G\" && grep -q '\"reason\": \"credential canary' '$RUNS/canary-tool-$where/summary.json' && NEEDLES=\"\$TOOL_NEEDLES\" noleak \"\$G\" '$RUNS/canary-tool-$where' '$T/co-tool-$where'"
  done
else
  echo "SKIP: the credential canary with a stand-in guest (no bwrap here can create a user+network namespace)"
fi

# port-bridge.mjs: the one host port, and the guest's loopback relay
PB="$F/scripts/ci/port-bridge.mjs"
node -e 'const s=require("net").createServer(c=>c.on("data",d=>c.write("echo:"+d))).listen(0,"127.0.0.1",()=>{require("fs").writeFileSync(process.argv[1],String(s.address().port))})' "$T/echo.port" &
EPID=$!
for _ in $(seq 1 50); do [[ -s "$T/echo.port" ]] && break; sleep 0.1; done
EPORT="$(cat "$T/echo.port")"
node "$PB" listen "$T/pb.sock" "127.0.0.1:$EPORT" 2>/dev/null &
LPID=$!
for _ in $(seq 1 50); do [[ -S "$T/pb.sock" ]] && break; sleep 0.1; done
got="$(printf 'hi' | node "$PB" connect "$T/pb.sock")"   # stdin ends at once: a half-close through the guestfwd path
check "port-bridge: connect <sock> ↔ listen <sock> 127.0.0.1:<port> carries a connection both ways" "[[ \"\$got\" == echo:hi ]]"
check "port-bridge: the socket is 0600" "[[ \$(stat -c %a '$T/pb.sock') == 600 ]]"
node "$PB" listen "$T/pb2.sock" 10.0.2.2:11434 2>/dev/null; check "port-bridge listen: a target off loopback is refused" "[[ $? -eq 2 && ! -e '$T/pb2.sock' ]]"
# The relay binds port 0 and says which port it got (no pick-then-bind race),
# and ONE exchange must be exact: a client that sends and then half-closes
# (the shape that came back empty before the bridge was half-close safe;
# scripts/test/ci-port-bridge.test.mjs holds it under load). No retry on an
# empty reply: a retry is what hid that bug.
node "$PB" relay "127.0.0.1:0" "127.0.0.1:$EPORT" 2>"$T/relay.err" &
RPID=$!
RPORT=""; for _ in $(seq 1 100); do RPORT="$(sed -n 's/^port-bridge: 127\.0\.0\.1:\([0-9]*\) -> .*/\1/p' "$T/relay.err")"; [[ -n "$RPORT" ]] && break; sleep 0.1; done
got="$(node -e 'const c=require("net").connect({port:+process.argv[1],host:"127.0.0.1",allowHalfOpen:true},()=>c.end("yo"));let s="";c.on("data",d=>s+=d).on("close",()=>process.stdout.write(s)).on("error",e=>process.stdout.write("ERR "+e.code))' "$RPORT")"
check "port-bridge relay: 127.0.0.1:0 binds a free port, and a half-closing client gets its reply (one try)" "[[ -n \"$RPORT\" && \"\$got\" == echo:yo ]]"
node "$PB" relay "0.0.0.0:0" "127.0.0.1:$EPORT" 2>/dev/null; check "port-bridge relay: listens on 127.0.0.1 only" "[[ $? -eq 2 ]]"
kill "$EPID" "$LPID" "$RPID" 2>/dev/null; wait 2>/dev/null

echo
echo "ci-vm-run: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
