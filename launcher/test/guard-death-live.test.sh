#!/usr/bin/env bash
# guard-death-live.test.sh — what happens when the whole-agent guard dies
# mid-session, and that the agent cannot kill it (rootless-confinement-ubuntu-
# 2404.md §12.2). The real mandu-net-guard with a secret policy (plan 10 §4.1)
# wraps a python3 "agent"; the agent reads its twinned secret (the twin), then:
#   (1) the guard is killed from outside (SIGKILL by pid): the agent's top
#       process dies with it (the guard's child carries PR_SET_PDEATHSIG), and
#       a tool process the agent started, reparented, finds every trapped
#       syscall failing ENOSYS (seccomp_unotify(2)): opening the secret and an
#       ordinary file, a TCP and an AF_UNIX connect, an execve. The real bytes
#       never come back. The launcher's status file stays at `supervising`.
#   (2) the agent tries every way to signal its guard (same uid, the guard is
#       its parent): kill by pid, by group, kill(-1), tgkill, tkill of a guard
#       thread, kill / rt_sigqueueinfo of a guard WORKER thread's id with
#       SIGKILL or signal 32 (the kernel signals the whole process), prlimit,
#       pidfd_open, pidfd_send_signal on a /proc/<guard> directory (also under
#       a dup2 race), F_SETSIG to SIGKILL, joining the guard's group, reading
#       the guard's /proc environ, and starving it (setpriority by thread,
#       group and user, SCHED_IDLE, affinity, idle I/O priority). Each is
#       refused, the guard keeps serving, and the tree's own signals and
#       scheduling calls still work (a SIGKILL by pidfd, performed by the
#       guard, reaches the child it names).
#   (3) with the bind inside (the launcher's order: guard OUTSIDE, the twin
#       wrap's bwrap inside, --die-with-parent and its own pid namespace): the
#       guard's death kills the whole agent tree, also where AppArmor changes
#       the sandboxed program's profile at its exec (Ubuntu 26.04).
#   (4) a guard whose tree exits normally records `exited <code>`.
#   (5) a link the tree plants at the record's names is replaced, never
#       written through (runtime-instances.md §2, 2026-10-17).
# SKIPs where python3 or the built guard are unavailable; (3) also needs bwrap.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { echo "  ok — $1"; PASS=$((PASS+1)); }
bad() { echo "  NOT OK — $1"; FAIL=$((FAIL+1)); }
skip() { echo "guard-death-live.test.sh: SKIP ($1)"; echo "1 skipped, 0 failed"; exit 0; }
command -v python3 >/dev/null 2>&1 || skip "python3 not installed"
GUARD="$REPO/interceptors/target/release/mandu-net-guard"
[[ -x "$GUARD" ]] || GUARD="$REPO/interceptors/target/debug/mandu-net-guard"
[[ -x "$GUARD" ]] || skip "mandu-net-guard is not built (scripts/build-native.sh)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-guard-death.XXXXXX")"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT

SECRET="$WORK/home/.env"; CANARY="GUARD_DEATH_CANARY_$RANDOM$RANDOM"
mkdir -p "$WORK/home" "$WORK/twins"
printf 'API_KEY=%s\n' "$CANARY" > "$SECRET"
printf "API_KEY='\$MDU:nomodel_Read[dead].API_KEY'\n" > "$WORK/twins/env"
echo plain > "$WORK/home/plain.txt"
cat > "$WORK/secret-policy.json" <<JSON
{"agentExe":"","ask":"never","session":"guard-death-live","secrets":[
  {"path":"$SECRET","twin":"$WORK/twins/env","level":"no-model"}]}
JSON

# The "agent". Everything it needs after the guard is gone is imported up
# front: an import opens files, and every open fails once the guard is dead.
cat > "$WORK/agent.py" <<'PY'
import ctypes, errno, fcntl, json, os, platform, resource, signal, socket, subprocess, sys, threading, time
secret, plain, unix_path, mode = sys.argv[1:5]
def en(e):
    return errno.errorcode.get(e.errno, str(e.errno))
def try_open(p):
    try:
        with open(p) as f:
            s = f.read()
        return "real" if "GUARD_DEATH_CANARY" in s else "twin" if "$MDU:" in s else "read-ok"
    except OSError as e:
        return en(e)
def try_connect(fam, addr):
    s = socket.socket(fam, socket.SOCK_STREAM)
    try:
        s.connect(addr); return "connected"
    except OSError as e:
        return en(e)
    finally:
        s.close()
def try_exec():
    try:
        return "rc=%d" % subprocess.run(["/bin/true"]).returncode
    except OSError as e:
        return en(e)
def probe():
    return {"secret": try_open(secret), "plain": try_open(plain),
            "tcp": try_connect(socket.AF_INET, ("127.0.0.1", 9)),
            "unix": try_connect(socket.AF_UNIX, unix_path), "exec": try_exec()}
def attempt(f):
    try:
        f(); return "ok"
    except OSError as e:
        return en(e)
libc = ctypes.CDLL(None, use_errno=True)
def sysc(nr, *a):
    if libc.syscall(nr, *[ctypes.c_long(x) for x in a]) < 0:
        e = ctypes.get_errno(); raise OSError(e, os.strerror(e))
X86 = platform.machine() == "x86_64"  # raw syscall numbers below are x86_64's
guard = os.getppid()
out = {"pid": os.getpid(), "guard": guard, "before": probe()}
if mode == "attacks":
    # The guard's other threads (its reaper, its workers), listed by the
    # harness OUTSIDE the tree and handed over in a file: in (2a) an open of
    # /proc/<guard>/task here would name the agent's own entry, and guessing
    # thread ids just above the guard's pid failed under a loaded CI guest,
    # where other suites took those pids first (2026-10-02, pipeline 8108).
    print("WANT_TIDS %d" % guard, flush=True)
    tids_file = sys.argv[5]
    for _ in range(400):  # up to 20 s
        if os.path.exists(tids_file):
            break
        time.sleep(0.05)
    try:
        tids = [int(t) for t in open(tids_file).read().split() if int(t) != guard]
    except (OSError, ValueError):
        tids = []
    a = {}
    a["kill"] = attempt(lambda: os.kill(guard, 0))
    a["killpg"] = attempt(lambda: os.kill(-guard, 0))
    a["kill_all"] = attempt(lambda: os.kill(-1, 0))
    a["prlimit"] = attempt(lambda: resource.prlimit(guard, resource.RLIMIT_NOFILE))
    a["pidfd_open"] = attempt(lambda: os.pidfd_open(guard))
    # Which process an open of /proc/<guard> names: the guard's own entry, or
    # (where the guard performs the tree's opens) the opener's own instead.
    d = os.open("/proc/%d" % guard, os.O_RDONLY | os.O_DIRECTORY)
    named = int(os.read(os.open("stat", os.O_RDONLY, dir_fd=d), 64).split()[0])
    a["proc_names"] = "guard" if named == guard else "self" if named == os.getpid() else str(named)
    a["pidfd_procdir"] = attempt(lambda: signal.pidfd_send_signal(d, 0))
    a["setsig_kill"] = attempt(lambda: fcntl.fcntl(d, 10, signal.SIGKILL))  # F_SETSIG
    a["environ"] = try_open("/proc/%d/environ" % guard)
    if X86:
        a["tgkill"] = attempt(lambda: sysc(234, guard, guard, 0))
        a["tkill_worker"] = attempt(lambda: sysc(200, tids[0], 0)) if tids else "no-thread"
        a["own_tkill"] = attempt(lambda: sysc(200, threading.get_native_id(), 0))
    a["own_group"] = attempt(lambda: os.kill(0, 0))
    child = subprocess.Popen(["sleep", "5"])
    a["child_pidfd"] = attempt(lambda: signal.pidfd_send_signal(os.pidfd_open(child.pid), signal.SIGTERM))
    child.wait()
    a["guard_own_group"] = os.getpgid(guard) == guard and os.getpgid(0) != guard
    a["join_guard_group"] = attempt(lambda: os.setpgid(0, guard))
    # The signals the guard neither ignores nor handles: SIGKILL and SIGSTOP,
    # and the defaults that do nothing (CHLD, CONT, URG, WINCH).
    # (Read only where an open of /proc/<guard> reaches the guard's entry.)
    if a["proc_names"] == "guard":
        mask = 0
        for l in open("/proc/%d/status" % guard).read().splitlines():
            if l.startswith(("SigIgn:", "SigCgt:")):
                mask |= int(l.split()[1], 16)
        a["uncovered"] = [s for s in range(1, 65) if not mask >> (s - 1) & 1]
    # A guard worker thread's id (the harness's list, above): kill(tid)
    # signals the whole process, and the scheduling calls take thread ids.
    # Each would hurt (a refusal that failed kills or starves the guard, and
    # the report never comes).
    w = tids[0] if tids else None
    if w:
        a["kill_worker_sigkill"] = attempt(lambda: os.kill(w, signal.SIGKILL))
        a["kill_worker_32"] = attempt(lambda: os.kill(w, 32))
        a["prlimit_worker"] = attempt(lambda: resource.prlimit(w, resource.RLIMIT_CPU, (1, 1)))
        a["nice_worker"] = attempt(lambda: os.setpriority(os.PRIO_PROCESS, w, 19))
        a["nice_group"] = attempt(lambda: os.setpriority(os.PRIO_PGRP, guard, 19))
        a["nice_user"] = attempt(lambda: os.setpriority(os.PRIO_USER, 0, 19))
        a["sched_idle_worker"] = attempt(lambda: os.sched_setscheduler(w, os.SCHED_IDLE, os.sched_param(0)))
        a["affinity_worker"] = attempt(lambda: os.sched_setaffinity(w, {min(os.sched_getaffinity(0))}))
        if X86:
            a["ioprio_worker"] = attempt(lambda: sysc(251, 1, w, 3 << 13))  # IOPRIO_CLASS_IDLE
            info = ctypes.create_string_buffer(128)
            ctypes.memmove(info, (ctypes.c_int * 3)(signal.SIGKILL, 0, -1), 12)  # si_code SI_QUEUE
            a["sigqueue_worker"] = attempt(lambda: sysc(129, w, signal.SIGKILL, ctypes.addressof(info)))
    else:
        a["kill_worker_sigkill"] = "no-thread"
    # The tree's own calls still work: its own thread by id, a child killed
    # by pid and by pidfd (performed by the guard), with a siginfo too.
    a["own_nice_by_id"] = attempt(lambda: os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), os.getpriority(os.PRIO_PROCESS, 0)))
    a["own_affinity_by_id"] = attempt(lambda: os.sched_setaffinity(threading.get_native_id(), os.sched_getaffinity(0)))
    c1 = subprocess.Popen(["sleep", "5"]); a["child_kill"] = attempt(lambda: os.kill(c1.pid, signal.SIGKILL)); c1.wait()
    c2 = subprocess.Popen(["sleep", "5"])
    a["child_pidfd_kill"] = attempt(lambda: signal.pidfd_send_signal(os.pidfd_open(c2.pid), signal.SIGKILL))
    a["child_pidfd_kill_died"] = c2.wait() == -signal.SIGKILL
    if X86:
        c3 = subprocess.Popen(["sleep", "5"])
        info = ctypes.create_string_buffer(128)
        ctypes.memmove(info, (ctypes.c_int * 3)(signal.SIGKILL, 0, -1), 12)
        a["child_pidfd_siginfo"] = attempt(lambda: sysc(424, os.pidfd_open(c3.pid), signal.SIGKILL, ctypes.addressof(info), 0))
        c3.wait()
    if a["proc_names"] == "guard":
        a["pidfd_procdir_sigkill"] = attempt(lambda: signal.pidfd_send_signal(d, signal.SIGKILL))
        if X86:
            # The dup2 race: one thread swaps descriptor N between the guard's
            # /proc entry and a dead child's pidfd while another sends SIGKILL
            # through N. A check-then-continue loses it; a performed send
            # signals only the descriptor it judged.
            c4 = subprocess.Popen(["true"]); dead = os.pidfd_open(c4.pid); c4.wait()
            N = 200; stop = time.time() + 1.5; seen = set()
            libc.dup2.argtypes = [ctypes.c_int, ctypes.c_int]
            def swap():
                while time.time() < stop:
                    libc.dup2(d, N); libc.dup2(dead, N)
            t = threading.Thread(target=swap); t.start()
            while time.time() < stop:
                r = libc.syscall(ctypes.c_long(424), ctypes.c_long(N), ctypes.c_long(signal.SIGKILL), ctypes.c_long(0), ctypes.c_long(0))
                seen.add("ok" if r == 0 else errno.errorcode.get(ctypes.get_errno(), "?"))
            t.join()
            a["race"] = sorted(seen)
    out["attacks"] = a
    out["alive"] = os.getppid() == guard
    out["after"] = probe()
    print("ATTACKS " + json.dumps(out), flush=True)
    sys.exit(0)
# "outside": a tool process outlives the agent's top process.
tool = os.fork()
if tool == 0:
    top = os.getppid()
    for _ in range(200):  # wait up to 10 s for the top process to be gone
        if os.getppid() != top:
            break
        time.sleep(0.05)
    res = {"reparented": os.getppid() != top, "after": probe()}
    os.write(1, ("AFTER " + json.dumps(res) + "\n").encode())
    os._exit(0)
out["tool"] = tool
print("READY " + json.dumps(out), flush=True)
time.sleep(30)
PY

export MANDU_NET_GUARD_SECRETS="$WORK/secret-policy.json" MANDU_NET_GUARD_EVENTS=0
unset MANDU_ARBITER_SOCK
jq_() { python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(eval("d"+sys.argv[2]))' "$1" "$2" 2>/dev/null; }
wait_line() { # file prefix [seconds, default 10]
  for _ in $(seq 1 "$(( ${3:-10} * 10 ))"); do grep -q "^$2 " "$1" 2>/dev/null && break; sleep 0.1; done
  grep "^$2 " "$1" 2>/dev/null | head -1 | cut -d' ' -f2-
}
check_after() { # label json
  local a="$2"
  [[ "$(jq_ "$a" "['reparented']")" == True ]] && ok "$1: the tool process outlived the agent's top process (reparented)" || bad "$1: the tool was not reparented: $a"
  local k
  for k in secret plain tcp unix exec; do
    [[ "$(jq_ "$a" "['after']['$k']")" == ENOSYS ]] && ok "$1: after the guard died, $k fails ENOSYS" || bad "$1: after the guard died, $k gave $(jq_ "$a" "['after']['$k']")"
  done
}
check_before() { # label json
  local b="$1"
  [[ "$(jq_ "$2" "['before']['secret']")" == twin ]] && ok "$b: before, the secret opens as its twin (the guard is serving)" || bad "$b: before, secret gave $(jq_ "$2" "['before']['secret']")"
  [[ "$(jq_ "$2" "['before']['plain']")" == read-ok && "$(jq_ "$2" "['before']['tcp']")" == ECONNREFUSED ]] \
    && ok "$b: before, an ordinary open and an allowed connect behave normally" || bad "$b: before: $2"
}

# (1) killed from outside
MANDU_NET_GUARD_STATUS="$WORK/status1" "$GUARD" --allow "127.0.0.0/8:*" -- python3 "$WORK/agent.py" "$SECRET" "$WORK/home/plain.txt" "$WORK/nosock" outside > "$WORK/out1" 2>"$WORK/err1" &
G1=$!; disown "$G1"; PIDS+=("$G1")
B="$(wait_line "$WORK/out1" READY)"
[[ -n "$B" ]] || { cat "$WORK/err1"; bad "(1) the agent never got ready"; }
if [[ -n "$B" ]]; then
  AP="$(jq_ "$B" "['pid']")"; PIDS+=("$AP" "$(jq_ "$B" "['tool']")")
  [[ "$(jq_ "$B" "['guard']")" == "$G1" ]] && ok "(1) the guard is the agent's parent (pid $G1)" || bad "(1) guard pid $G1, agent's parent $(jq_ "$B" "['guard']")"
  check_before "(1)" "$B"
  [[ "$(cat "$WORK/status1" 2>/dev/null)" == "supervising $G1 $AP" ]] && ok "(1) the status file says the guard is supervising" || bad "(1) status file: $(cat "$WORK/status1" 2>&1)"
  kill -9 "$G1"
  for _ in $(seq 1 50); do kill -0 "$AP" 2>/dev/null || break; sleep 0.1; done
  kill -0 "$AP" 2>/dev/null && bad "(1) the agent's top process outlived the guard" || ok "(1) the agent's top process died with the guard (PR_SET_PDEATHSIG)"
  # The tool polls up to 10 s for its reparenting before it probes: wait
  # past that, not alongside it.
  A="$(wait_line "$WORK/out1" AFTER 20)"
  check_after "(1)" "$A"
  [[ "$(cat "$WORK/status1" 2>/dev/null)" == supervising* ]] && ok "(1) the status file still says supervising: the launcher can tell the guard died first" || bad "(1) status file after the kill: $(cat "$WORK/status1" 2>&1)"
fi
grep -q "$CANARY" "$WORK/out1" && bad "(1) the canary reached the agent" || ok "(1) the real secret bytes never reached the agent"

# (2) the agent tries to stop its guard: (2a) under a secret policy, where
# the guard performs the tree's opens and never hands over its own procfs
# entry (an open of /proc/<guard> names the opener's own); (2b) a connect-only
# guard, where the kernel opens /proc/<guard> and the checks meet it.
attacks() { # label out-file [env…]
  local L="$1" OUT="$2"; shift 2
  env "$@" "$GUARD" --allow "127.0.0.0/8:*" -- python3 "$WORK/agent.py" "$SECRET" "$WORK/home/plain.txt" "$WORK/nosock" attacks "$OUT.tids" > "$OUT" 2>"$OUT.err" &
  local G=$!; disown "$G"; PIDS+=("$G")
  # The guard's threads but its own (it starts its reaper before the agent
  # runs, its workers right after), listed here, outside the tree.
  # Waited as long as the agent waits for the list (20 s).
  if [[ -n "$(wait_line "$OUT" WANT_TIDS 20)" ]]; then
    local t tids=""
    for _ in $(seq 1 100); do
      tids=""
      for t in /proc/"$G"/task/*; do [[ "${t##*/}" != "$G" && -e "$t" ]] && tids+="${t##*/} "; done
      [[ -n "$tids" ]] && break; sleep 0.05
    done
    printf '%s\n' "$tids" > "$OUT.tids.tmp" && mv "$OUT.tids.tmp" "$OUT.tids"
  fi
  # The agent waits up to 20 s for the thread list before its attempts
  # (which take seconds more: the 1.5 s dup2 race, the child sleeps): a
  # shorter wait here gave up on an agent that was still on its way.
  local R; R="$(wait_line "$OUT" ATTACKS 40)"
  if [[ -z "$R" ]]; then cat "$OUT.err"; bad "$L the agent never reported"; return; fi
  PIDS+=("$(jq_ "$R" "['pid']")")
  local k v
  for k in kill killpg kill_all prlimit pidfd_open setsig_kill join_guard_group kill_worker_sigkill kill_worker_32 prlimit_worker \
           nice_worker nice_group nice_user sched_idle_worker affinity_worker; do
    [[ "$(jq_ "$R" "['attacks']['$k']")" == EPERM ]] && ok "$L the agent's $k aimed at its guard is refused (EPERM)" || bad "$L $k gave $(jq_ "$R" "['attacks']['$k']")"
  done
  if [[ "$(uname -m)" == x86_64 ]]; then
    for k in tgkill tkill_worker ioprio_worker sigqueue_worker; do
      [[ "$(jq_ "$R" "['attacks']['$k']")" == EPERM ]] && ok "$L the agent's $k aimed at its guard is refused (EPERM)" || bad "$L $k gave $(jq_ "$R" "['attacks']['$k']")"
    done
    [[ "$(jq_ "$R" "['attacks']['own_tkill']")" == ok ]] && ok "$L a tkill of the agent's own thread still works" || bad "$L own tkill gave $(jq_ "$R" "['attacks']['own_tkill']")"
    [[ "$(jq_ "$R" "['attacks']['child_pidfd_siginfo']")" == ok ]] && ok "$L a SIGKILL by pidfd with a siginfo, performed by the guard, still reaches the agent's child" || bad "$L child pidfd with siginfo gave $(jq_ "$R" "['attacks']['child_pidfd_siginfo']")"
  fi
  for k in own_nice_by_id own_affinity_by_id child_kill child_pidfd_kill; do
    [[ "$(jq_ "$R" "['attacks']['$k']")" == ok ]] && ok "$L the tree's own $k still works" || bad "$L own $k gave $(jq_ "$R" "['attacks']['$k']")"
  done
  [[ "$(jq_ "$R" "['attacks']['child_pidfd_kill_died']")" == True ]] && ok "$L the performed pidfd SIGKILL killed the child it named" || bad "$L the child named by pidfd survived its SIGKILL"
  v="$(jq_ "$R" "['attacks']['proc_names']")"
  if [[ "$v" == guard ]]; then
    [[ "$(jq_ "$R" "['attacks']['pidfd_procdir']")" == EPERM ]] && ok "$L pidfd_send_signal on a /proc/<guard> directory is refused (EPERM)" || bad "$L pidfd_procdir gave $(jq_ "$R" "['attacks']['pidfd_procdir']")"
    [[ "$(jq_ "$R" "['attacks']['uncovered']")" == "[9, 17, 18, 19, 23, 28]" ]] \
      && ok "$L the guard ignores or handles every signal but SIGKILL, SIGSTOP and the harmless defaults (32 included)" || bad "$L signals left at their default: $(jq_ "$R" "['attacks']['uncovered']")"
    [[ "$(jq_ "$R" "['attacks']['pidfd_procdir_sigkill']")" == EPERM ]] && ok "$L a SIGKILL through a /proc/<guard> directory is refused (EPERM)" || bad "$L pidfd_procdir SIGKILL gave $(jq_ "$R" "['attacks']['pidfd_procdir_sigkill']")"
    if [[ "$(uname -m)" == x86_64 ]]; then
      [[ "$(jq_ "$R" "['attacks']['race']")" =~ ^\[(\'EBADF\',\ )?\'EPERM\',\ \'ESRCH\'\]$ ]] && ok "$L 1.5 s of dup2 swaps under pidfd SIGKILLs: the guard judged and signalled only what it copied (EPERM / ESRCH, EBADF before the first swap)" || bad "$L the dup2 race gave $(jq_ "$R" "['attacks']['race']")"
    fi
    [[ "$(jq_ "$R" "['attacks']['environ']")" == EACCES ]] && ok "$L the guard is not dumpable: its /proc environ is closed to the agent" || bad "$L the guard's environ gave $(jq_ "$R" "['attacks']['environ']")"
  elif [[ "$v" == self ]]; then
    ok "$L an open of /proc/<guard> names the agent's own entry: the guard's procfs is never handed over"
  else
    bad "$L /proc/<guard> named $v"
  fi
  [[ "$(jq_ "$R" "['attacks']['own_group']")" == ok && "$(jq_ "$R" "['attacks']['child_pidfd']")" == ok ]] \
    && ok "$L the tree's own signals still work (its own group, a child by pidfd)" || bad "$L own signals: $(jq_ "$R" "['attacks']")"
  [[ "$(jq_ "$R" "['attacks']['guard_own_group']")" == True ]] && ok "$L the guard runs in a process group of its own" || bad "$L the guard shares the agent's process group"
  [[ "$(jq_ "$R" "['alive']")" == True && "$(jq_ "$R" "['after']['plain']")" == read-ok ]] \
    && ok "$L the guard survived every attempt and still serves" || bad "$L after the attempts: $R"
  grep -q "$CANARY" "$OUT" && bad "$L the canary reached the agent" || ok "$L the real secret bytes never reached the agent"
}
attacks "(2a)" "$WORK/out2a"
[[ "$(jq_ "$(wait_line "$WORK/out2a" ATTACKS)" "['after']['secret']")" == twin ]] && ok "(2a) after the attempts, the secret still opens as its twin" || bad "(2a) the secret no longer opens as its twin"
attacks "(2b)" "$WORK/out2b" MANDU_NET_GUARD_SECRETS=

# (3) the launcher's order, guard OUTSIDE and the bind inside: the tree dies.
# The wrap's flags are the launcher's (secret-twins.ts TWIN_WRAP_HARDENING),
# its pid namespace included: that, not --die-with-parent, is what ends the
# tree where AppArmor moves the sandboxed program to another profile at its
# exec (Ubuntu 26.04's bwrap-userns-restrict, `unpriv_bwrap`), since a
# profile change at exec clears the death signal bwrap set just before it.
# The namespace's first process is bwrap itself, which never execs: it keeps
# its death signal, and the namespace dies with it. Without --unshare-pid the
# agent outlived the guard on such a host, every time (a stock 26.04 host;
# the CI guests lift the userns restriction, so they never showed it).
TREE3="$WORK/agent.py $SECRET $WORK/home/plain.txt $WORK/nosock outside tree3"
tree3() { # "<host pid>:<comm>" of every process under the guard whose argv carries (3)'s agent command
  local p c
  for p in /proc/[0-9]*; do
    [[ "${p##*/}" == "${G3:-}" ]] && continue
    c="$(cat "$p/comm" 2>/dev/null)"
    [[ "$c" == bwrap || "$c" == python3 ]] || continue
    tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -qF -- "$TREE3" && echo "${p##*/}:$c"
  done
}
TW="$(sed -n '/^export const TWIN_WRAP_HARDENING/,/^];/p' "$REPO/launcher/src/secret-twins.ts")"
missing=""
for f in --die-with-parent --cap-drop --unshare-ipc --unshare-uts --unshare-pid --proc; do grep -qF "\"$f\"" <<<"$TW" || missing+=" $f"; done
[[ -z "$missing" ]] && ok "(3) runs the launcher's twin-wrap flags (TWIN_WRAP_HARDENING)" || bad "(3) the launcher's twin wrap no longer has$missing: (3) tests a wrap the launcher does not run"
if command -v bwrap >/dev/null 2>&1 && bwrap --dev-bind / / --die-with-parent -- true >/dev/null 2>&1; then
  "$GUARD" --allow "127.0.0.0/8:*" -- bwrap --dev-bind / / --die-with-parent --cap-drop ALL --unshare-ipc --unshare-uts \
    --unshare-pid --proc /proc \
    --bind "$WORK/twins/env" "$SECRET" -- python3 $TREE3 > "$WORK/out3" 2>"$WORK/err3" &
  G3=$!; disown "$G3"; PIDS+=("$G3")
  B="$(wait_line "$WORK/out3" READY)"
  if [[ -n "$B" ]]; then
    # The agent's pid in READY is its number inside the namespace: find the
    # tree by its argv instead.
    T3="$(tree3)"; for p in $T3; do PIDS+=("${p%%:*}"); done
    [[ "$(grep -c ':bwrap$' <<<"$T3")" -ge 1 && "$(grep -c ':python3$' <<<"$T3")" -ge 2 ]] \
      && ok "(3) the agent tree runs under the bind (bwrap, the agent and its tool)" || bad "(3) the agent tree: [$(echo $T3)]"
    kill -9 "$G3"
    # Polled by pid (cheap), not by a rescan: the agent's top process ends
    # by itself 30 s on, and a slow scan would reach that.
    alive3() { local q; for q in $T3; do kill -0 "${q%%:*}" 2>/dev/null && echo "$q"; done; }
    for _ in $(seq 1 50); do [[ -z "$(alive3)" ]] && break; sleep 0.1; done
    [[ -n "$(alive3)" ]] && bad "(3) the agent tree under the bind outlived the guard: $(echo $(alive3))" || ok "(3) with the bind inside (bwrap --die-with-parent, its own pid namespace), the guard's death kills the whole agent tree"
  else
    cat "$WORK/err3"; bad "(3) the agent never got ready"
  fi
else
  echo "  skip — (3) bwrap unusable here"
fi

# (4) a normal end is recorded
MANDU_NET_GUARD_STATUS="$WORK/status4" "$GUARD" --allow "127.0.0.0/8:*" -- true >/dev/null 2>&1
[[ "$(cat "$WORK/status4" 2>/dev/null)" == "exited 0" ]] && ok "(4) a tree that exits normally leaves the status file at 'exited 0'" || bad "(4) status file: $(cat "$WORK/status4" 2>&1)"

# (5) the status file lives in the scope dir, which the agent may write while
#     it runs (runtime-instances.md §2, "planted paths", 2026-10-17): the tree
#     plants a link at the record's temp name and at its name, each to a file
#     of the user's; the guard's `exited` record replaces the links and never
#     writes through them (before, `std::fs::write("<status>.tmp")` followed
#     the link and truncated the victim to `exited 0`).
echo "keep me" > "$WORK/victim5.rc"
mkdir -p "$WORK/scope5"
MANDU_NET_GUARD_STATUS="$WORK/scope5/net-guard.status" "$GUARD" --allow "127.0.0.0/8:*" -- \
  /bin/sh -c "ln -sf '$WORK/victim5.rc' '$WORK/scope5/net-guard.status.tmp'; ln -sf '$WORK/victim5.rc' '$WORK/scope5/net-guard.status'" >/dev/null 2>&1
[[ "$(cat "$WORK/victim5.rc")" == "keep me" ]] && ok "(5) links planted at the status record's names: the linked file is untouched" || bad "(5) the guard wrote through a planted link: $(cat "$WORK/victim5.rc")"
[[ ! -L "$WORK/scope5/net-guard.status" && "$(cat "$WORK/scope5/net-guard.status" 2>/dev/null)" == "exited 0" ]] && ok "(5) and the record replaced the link at its name" || bad "(5) status: $(ls -l "$WORK/scope5" 2>&1)"

echo "guard-death-live.test.sh: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
