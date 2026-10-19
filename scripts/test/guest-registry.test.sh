#!/usr/bin/env bash
#
# guest-registry.test.sh — scripts/lib/guest-registry.sh, the registration the
# VM harnesses make for every qemu guest they start (os-test-matrix.md §10
# §5, runtime-instances.md §10). A stand-in guest (a process whose argv[0] is
# qemu-system-x86_64 and which writes its own pidfile, as qemu's -pidfile
# does) stands in for a VM: no qemu, no KVM. The registry is scoped to a
# throwaway MANDU_RUNTIME_DIR.
#
#   - the entry: the guest's pid and start time, the boot id, the owner (this
#     harness) and its start time, the work dir, keep, alsoRemove; valid JSON
#     even for a path with a quote in it; mode 0600;
#   - a guest that never writes its pidfile and exits is not registered;
#   - guest_release stops a still-running guest (only that process) and
#     drops the entry; idempotent; a guest that is gone is not signalled;
#   - runtime-instances.md §3b: no entry goes into a runtime dir in a shared
#     sticky dir that others can write (a squatted /tmp/mandu), nor through
#     a planted `vm-guests` link.
#
# Run:  bash scripts/test/guest-registry.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PASS=0 FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

T="$(mktemp -d "${TMPDIR:-/tmp}/guest-registry.XXXXXX")"
KIDS=()
trap '{ for k in "${KIDS[@]}"; do kill -9 "$k"; done; wait; } 2>/dev/null; rm -rf "$T"' EXIT
export MANDU_RUNTIME_DIR="$T/rt"
# shellcheck source=scripts/lib/guest-registry.sh
. "$REPO/scripts/lib/guest-registry.sh"

REG="$T/rt/vm-guests"
check "the registry lives under the runtime dir" "[[ \"\$(guest_registry_dir)\" == '$REG' ]]"
# The launcher's rule (runtime-instances.md §3b): XDG_RUNTIME_DIR/mandu, else
# the per-user ($TMPDIR or /tmp)/mandu-<uid>, else the /tmp/mandu-<uid> fallback.
U="$(id -u)"
check "rule 2: XDG_RUNTIME_DIR/mandu" "[[ \"\$(unset MANDU_RUNTIME_DIR; XDG_RUNTIME_DIR=/run/user/7 mandu_runtime_base)\" == /run/user/7/mandu ]]"
check "rule 3: per-user under TMPDIR, never the shared /tmp/mandu" "[[ \"\$(unset MANDU_RUNTIME_DIR XDG_RUNTIME_DIR; TMPDIR=/var/tmp mandu_runtime_base)\" == /var/tmp/mandu-$U && \"\$(unset MANDU_RUNTIME_DIR XDG_RUNTIME_DIR TMPDIR; mandu_runtime_base)\" == /tmp/mandu-$U ]]"
check "rule 4: a TMPDIR too long for a socket gives /tmp/mandu-<uid>" "[[ \"\$(unset MANDU_RUNTIME_DIR XDG_RUNTIME_DIR; TMPDIR=/$(printf 't%.0s' {1..50}) mandu_runtime_base)\" == /tmp/mandu-$U ]]"

# fake_guest <pidfile> — a long-running stand-in qemu that writes its pidfile.
fake_guest() {
  bash -c 'echo $$ > "$1"; exec -a qemu-system-x86_64 sleep 600' _ "$1" &
  FG=$!
  KIDS+=("$FG")
}

W="$T/work \"q\""; mkdir -p "$W/artifacts/ephemeral"
fake_guest "$W/qemu.pid"
guest_register "$FG" "$W/qemu.pid" test-harness "$W" 1 "$W/artifacts/ephemeral"
E="$REG/test-harness-$FG.json"
check "the guest is registered as <harness>-<pid>.json" "[[ -f '$REG/test-harness-$FG.json' && \"\$GUEST_REG_ENTRY\" == '$REG/test-harness-$FG.json' ]]"
check "the entry is mode 0600 in a 0700 dir" "[[ \$(stat -c %a '$E') == 600 && \$(stat -c %a '$REG') == 700 ]]"
J="$(node -e '
  const e = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
  const st = (p) => require("fs").readFileSync(`/proc/${p}/stat`, "utf8").split(") ")[1].split(" ")[19];
  const boot = require("fs").readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  const ok = e.kind === "qemu-guest" && e.harness === "test-harness" && e.pid === +process.argv[2]
    && String(e.pidStart) === st(e.pid) && e.bootId === boot
    && e.ownerPid === +process.argv[3] && String(e.ownerStart) === st(e.ownerPid)
    && e.workDir === process.argv[4] && e.keep === true
    && JSON.stringify(e.alsoRemove) === JSON.stringify([process.argv[4] + "/artifacts/ephemeral"]);
  console.log(ok ? "ok" : "bad " + JSON.stringify(e));
' "$E" "$FG" "$$" "$W" 2>&1)"
check "the entry: pid + start time, boot id, owner (this harness) + start time, work dir with a quote, keep, alsoRemove ($J)" "[[ '$J' == ok ]]"

guest_release
check "guest_release stops the still-running guest" "! kill -0 $FG 2>/dev/null || [[ \$(cut -d' ' -f3 /proc/$FG/stat 2>/dev/null) == Z ]]"
check "…and drops its entry" "[[ ! -e '$E' && -z \"\$GUEST_REG_ENTRY\" ]]"
check "…and leaves the work dir to the harness" "[[ -d '$W' ]]"
guest_release; check "guest_release is idempotent" "[[ \$? -eq 0 ]]"

# A guest that exits without a pidfile: nothing registered, no wait past its exit.
W2="$T/w2"; mkdir -p "$W2"
bash -c 'sleep 0.3' & NP=$!
t0=$SECONDS
guest_register "$NP" "$W2/qemu.pid" nopid "$W2" 0
check "a guest that exits without writing its pidfile is not registered (and not waited for)" \
  "[[ -z \"\$GUEST_REG_ENTRY\" && -z \"\$(ls '$REG' 2>/dev/null | grep nopid)\" && \$((SECONDS - t0)) -lt 5 ]]"

# A guest that already stopped: release drops the entry and signals nothing.
W3="$T/w3"; mkdir -p "$W3"
fake_guest "$W3/qemu.pid"
guest_register "$FG" "$W3/qemu.pid" gone "$W3" 0
E3="$GUEST_REG_ENTRY"
kill -9 "$FG"; wait "$FG" 2>/dev/null
guest_release
check "a guest that already stopped: its entry is dropped" "[[ -n '$E3' && ! -e '$E3' ]]"

# A reused pid: the entry's start time no longer matches, so release never
# signals whatever holds that pid now.
sleep 600 & BYSTANDER=$!; KIDS+=("$BYSTANDER")
GUEST_REG_ENTRY="$REG/fake.json" GUEST_REG_PID="$BYSTANDER" GUEST_REG_START=1
: > "$GUEST_REG_ENTRY"
guest_release
check "a reused pid (start time differs) is never signalled" "kill -0 $BYSTANDER 2>/dev/null && [[ ! -e '$REG/fake.json' ]]"

# runtime-instances.md §3b: a runtime dir directly in a shared sticky dir
# (`$T/sticky` stands in for /tmp, where `/tmp/mandu` lands without
# XDG_RUNTIME_DIR) that others can write — a /tmp/mandu another account made
# first is the same case, not this uid's — gets no entry, and a `vm-guests`
# link planted in it is not followed.
W4="$T/w4"; mkdir -p "$W4" "$T/elsewhere"
mkdir -p "$T/sticky/mandu"; chmod 1777 "$T/sticky"; chmod 0777 "$T/sticky/mandu"
ln -s "$T/elsewhere" "$T/sticky/mandu/vm-guests"
fake_guest "$W4/qemu.pid"
MANDU_RUNTIME_DIR="$T/sticky/mandu" guest_register "$FG" "$W4/qemu.pid" shared "$W4" 0 2>"$T/shared.err"
check "a runtime dir in /tmp that others can write gets no entry (nor its planted vm-guests link)" \
  "[[ -z \"\$GUEST_REG_ENTRY\" && -z \"\$(ls '$T/elsewhere')\" ]] && grep -q 'not registered' '$T/shared.err'"
chmod 0700 "$T/sticky/mandu"
MANDU_RUNTIME_DIR="$T/sticky/mandu" guest_register "$FG" "$W4/qemu.pid" shared "$W4" 0 2>"$T/shared.err"
check "…and a vm-guests link in a private runtime dir is not followed either" \
  "[[ -z \"\$GUEST_REG_ENTRY\" && -z \"\$(ls '$T/elsewhere')\" ]]"
# A group-writable runtime dir that is NOT in a shared sticky dir (the
# umask-002 /run/user/<uid>/mandu of a dev host) is the user's own: registered.
mkdir -p "$T/own/mandu"; chmod 0775 "$T/own/mandu"
MANDU_RUNTIME_DIR="$T/own/mandu" guest_register "$FG" "$W4/qemu.pid" own "$W4" 0
check "a group-writable runtime dir outside a shared sticky dir is still the user's (registered)" \
  "[[ -f '$T/own/mandu/vm-guests/own-$FG.json' ]]"
MANDU_RUNTIME_DIR="$T/own/mandu" guest_release
kill -9 "$FG" 2>/dev/null; wait "$FG" 2>/dev/null

echo; echo "guest-registry: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
