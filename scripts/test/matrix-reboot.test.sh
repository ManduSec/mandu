#!/usr/bin/env bash
#
# matrix-reboot.test.sh — unit tests for the qemu executor's REBOOT support
# (os-test-matrix.md §2.1). A suite that must reboot the guest (the
# release-upgrade suite: do-release-upgrade, then boot the new release)
# exits 75; the guest runner arms a resume unit and powers off with
# RESULT=reboot, and the executor boots the same disk again, bounded by the
# suite's `# boots:` header and the run's TIMEOUT.
#
# Renders the real user-data and cuts the runner's resume pieces out of it;
# drives the real executor_run against a stub qemu that plays a scripted
# sequence of boots. No VM, no network.
#
# Run:  bash scripts/test/matrix-reboot.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MATRIX="$HERE/../matrix"
PASS=0; FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ── 1. the rendered user-data ──────────────────────────────────────────────────
R="$WORK/render"; mkdir -p "$R"
( source "$MATRIX/lib/common.sh"; source "$MATRIX/lib/qemu.sh"
  RUN_WORK="$R" TARGET_NAME=t LABELS=l SYSCTLS=""
  qemu_userdata s "" "$R/user-data" ) >/dev/null 2>&1
if python3 - "$R/user-data" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
files = {f["path"]: f for f in d["write_files"]}
unit = files["/etc/systemd/system/mandu-matrix-resume.service"]["content"]
assert "ExecStart=/usr/local/bin/mandu-matrix-guest.sh" in unit, unit
assert "ConditionPathExists=/var/lib/mandu-matrix/resume" in unit, unit
assert "WantedBy=multi-user.target" in unit, unit
assert "/usr/local/bin/mandu-matrix-guest.sh" in files
PY
then pass "user-data is valid YAML and carries the resume unit (runs the runner, only when armed)"
else fail "user-data YAML / resume unit"; fi
bash -n "$R/guest-runner.sh" && pass "rendered guest runner parses" || fail "guest runner syntax"

# The resume detection, run on a disk that was armed and one that was not.
{ echo 'systemctl() { echo "systemctl $*" >> "$LOG"; }'
  sed -n '/^RESUME_FLAG=/,/^fi$/p' "$R/guest-runner.sh" | sed "s|/var/lib/mandu-matrix/resume|\$FLAGDIR/resume|"
  echo 'echo "RESUME=$RESUME"'
} > "$WORK/resume.sh"
mkdir -p "$WORK/armed" "$WORK/fresh"; touch "$WORK/armed/resume"
out="$(FLAGDIR="$WORK/armed" LOG="$WORK/armed.log" bash "$WORK/resume.sh" 2>&1)"
[[ "$out" == *"RESUME=1"* && ! -e "$WORK/armed/resume" ]] && grep -q 'disable mandu-matrix-resume.service' "$WORK/armed.log" \
  && pass "an armed disk resumes, and disarms (flag gone, unit disabled) so a later boot is not a resume" \
  || fail "armed: $out / $(cat "$WORK/armed.log" 2>/dev/null)"
out="$(FLAGDIR="$WORK/fresh" LOG="$WORK/fresh.log" bash "$WORK/resume.sh" 2>&1)"
[[ "$out" == *"RESUME=0"* && ! -e "$WORK/fresh.log" ]] && pass "a first boot is not a resume" || fail "fresh: $out"

# Provisioning and the repo copy are skipped on a resume; the suite always runs.
p_line="$(grep -n '^if \[\[ \$RESUME -eq 0 \]\]; then' "$R/guest-runner.sh" | cut -d: -f1)"
g_line="$(grep -n '^# Provisioning gate' "$R/guest-runner.sh" | cut -d: -f1)"
f_line="$(grep -n '^fi  # RESUME -eq 0' "$R/guest-runner.sh" | cut -d: -f1)"
rs_line="$(grep -n 'rsync -a' "$R/guest-runner.sh" | head -1 | cut -d: -f1)"
s_line="$(grep -n '=== running suite' "$R/guest-runner.sh" | cut -d: -f1)"
[[ -n "$p_line" && "$p_line" -lt "$g_line" && "$g_line" -lt "$rs_line" && "$rs_line" -lt "$f_line" && "$f_line" -lt "$s_line" ]] \
  && pass "provisioning + repo copy are inside the first-boot block, the suite after it" \
  || fail "block order: if=$p_line gate=$g_line rsync=$rs_line fi=$f_line suite=$s_line"
grep -q 'MATRIX_RESUME=\$RESUME' "$R/guest-runner.sh" && pass "the suite is told it is resuming (MATRIX_RESUME)" || fail "no MATRIX_RESUME"

# The runner's exit-code table: 75 arms the resume and reports "reboot".
{ echo 'finish() { echo "FINISH $1"; exit 0; }'
  echo 'systemctl() { echo "systemctl $*" >> "$LOG"; }'
  echo "RESUME_FLAG=\"\$FLAGDIR/resume\""
  sed -n '/^case \$RC in$/,/^esac$/p' "$R/guest-runner.sh"
} > "$WORK/rc.sh"
out="$(RC=75 FLAGDIR="$WORK/rc75/x" LOG="$WORK/rc75.log" bash -c 'RC=75; . '"$WORK/rc.sh" 2>&1)"
[[ "$out" == "FINISH reboot" && -e "$WORK/rc75/x/resume" ]] && grep -q 'enable mandu-matrix-resume.service' "$WORK/rc75.log" \
  && pass "suite exit 75 → resume armed + unit enabled + RESULT reboot" || fail "rc 75: $out"
out="$(FLAGDIR="$WORK/rc0" LOG="$WORK/rc0.log" bash -c 'RC=0; . '"$WORK/rc.sh" 2>&1)"
[[ "$out" == "FINISH pass" && ! -e "$WORK/rc0/resume" ]] && pass "suite exit 0 → pass, nothing armed" || fail "rc 0: $out"

# ── 2. parse_header ────────────────────────────────────────────────────────────
printf '#!/bin/bash\n# deps: node\n# boots: 4\n# min-timeout: 9000\n' > "$WORK/h.sh"
( source "$MATRIX/lib/common.sh"
  [[ "$(parse_header "$WORK/h.sh" boots)" == 4 && "$(parse_header "$WORK/h.sh" min-timeout)" == 9000 && -z "$(parse_header "$WORK/h.sh" nope)" ]] ) \
  && pass "parse_header reads boots / min-timeout, empty for an absent key" || fail "parse_header"

# ── 3. the executor's boot loop, on a stub qemu ────────────────────────────────
STUB="$WORK/stub"; mkdir -p "$STUB"
cat > "$STUB/qemu-system-x86_64" <<'Q'
#!/bin/bash
# Stub qemu: one "boot" per call. Writes the next scripted RESULT into the out
# share and a line to the serial file. QSTUB_RESULTS="reboot pass"; a result
# of "hang" sleeps past any timeout and writes nothing; "die" exits at once
# and writes nothing (a guest that crashed before its runner started).
[[ "$1" == -device && "$2" == help ]] && { echo 'name "virtio-9p-pci"'; exit 0; }
[[ "$1" == --version ]] && { echo "QEMU emulator version 0 (stub)"; exit 0; }
out=""; serial=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -fsdev) [[ "$2" == *id=fsout,* ]] && out="$(sed 's/.*path=\([^,]*\).*/\1/' <<<"$2")"; shift ;;
    -serial) serial="${2#file:}"; shift ;;
  esac; shift
done
n=$(( $(cat "$QSTUB_DIR/count" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$QSTUB_DIR/count"
r="$(awk -v n="$n" '{print $n}' <<<"$QSTUB_RESULTS")"
echo "stub boot $n" > "$serial"
if [[ "$r" == hang ]]; then sleep 30; exit 0; fi
[[ "$r" == die ]] && exit 1
[[ -n "$r" ]] && echo "$r" > "$out/RESULT"
exit 0
Q
printf '#!/bin/bash\n[[ "$1" == create ]] && touch "${@: -2:1}"\nexit 0\n' > "$STUB/qemu-img"
printf '#!/bin/bash\nwhile [[ $# -gt 0 ]]; do [[ "$1" == -output ]] && touch "$2"; shift; done\n' > "$STUB/genisoimage"
chmod +x "$STUB"/*

run_loop() {  # run_loop <name> <suite headers> <results> <timeout> ; sets RC, BOOTS, OUTDIR, SERIAL, LOGTXT
  local d="$WORK/loop-$1"; mkdir -p "$d/matrix/suites" "$d/cache" "$d/run" "$d/q"
  printf '#!/bin/bash\n# deps:\n%b' "$2" > "$d/matrix/suites/s.sh"
  echo img > "$d/cache/base.img"
  LOGTXT="$(
    PATH="$STUB:$PATH" QSTUB_RESULTS="$3" QSTUB_DIR="$d/q" MANDU_VM_CACHE="$d/cache" MANDU_VM_SNAPSHOT=0 bash -c '
      source "'"$MATRIX"'/lib/common.sh"; source "'"$MATRIX"'/lib/qemu.sh"
      MATRIX_DIR="'"$d"'/matrix" REPO_ROOT="'"$d"'" TARGET_NAME=t RUN_WORK="'"$d"'/run"
      IMAGE_URL=http://x/base.img IMAGE_SHA256="" CPUS=1 MEM=64 TIMEOUT='"$4"' LABELS=l SYSCTLS=""
      executor_run s' 2>&1
  )"; RC=$?
  BOOTS="$(cat "$d/q/count" 2>/dev/null || echo 0)"; OUTDIR="$d/run/out"; SERIAL="$d/run/serial.log"
}

run_loop three '# boots: 3\n' "reboot reboot pass" 60
[[ $RC -eq 0 && $BOOTS -eq 3 ]] && pass "reboot, reboot, pass with boots: 3 → PASS after 3 boots" || fail "three: rc=$RC boots=$BOOTS; $LOGTXT"
grep -q '===== boot 3 =====' "$SERIAL" && grep -q 'stub boot 1' "$SERIAL" && grep -q 'stub boot 3' "$SERIAL" \
  && pass "serial.log keeps every boot's console" || fail "serial.log: $(cat "$SERIAL")"

run_loop capped '# boots: 2\n' "reboot reboot reboot" 60
[[ $RC -eq 1 && $BOOTS -eq 2 ]] && grep -q 'asked for boot 3; MAX_BOOTS=2' "$OUTDIR/RESULT" \
  && pass "a suite that asks past its # boots: fails, naming the cap" || fail "capped: rc=$RC boots=$BOOTS result=$(cat "$OUTDIR/RESULT" 2>/dev/null)"

run_loop nohdr '' "reboot pass" 60
[[ $RC -eq 1 && $BOOTS -eq 1 ]] && pass "no # boots: header → one boot; a reboot request fails the run" || fail "nohdr: rc=$RC boots=$BOOTS"

run_loop hang '# boots: 3\n' "reboot hang" 3
[[ $RC -eq 1 && $BOOTS -eq 2 && "$LOGTXT" == *"TIMED OUT"* ]] \
  && pass "a second boot that never reports runs into the SAME timeout and fails (not read as the first boot's reboot)" \
  || fail "hang: rc=$RC boots=$BOOTS; $(tail -3 <<<"$LOGTXT")"

run_loop die '# boots: 3\n' "reboot die pass" 60
[[ $RC -eq 1 && $BOOTS -eq 2 && "$LOGTXT" == *"no RESULT from guest"* ]] \
  && pass "a boot that dies without a word fails the run; the previous boot's reboot is not read again" \
  || fail "die: rc=$RC boots=$BOOTS; $(tail -3 <<<"$LOGTXT")"

run_loop floor '# boots: 1\n# min-timeout: 60\n' "pass" 1
[[ "$LOGTXT" == *"hard timeout 60s"* ]] && pass "# min-timeout: raises a shorter target TIMEOUT" || fail "floor: $(grep -m1 'hard timeout' <<<"$LOGTXT")"

echo; echo "matrix-reboot: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
