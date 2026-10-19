//! exec_record_integration — an exec under the guard, as the arbiter learns
//! it (plan 10 §4.2, plan 13 D7), after the exec path's cost was cut
//! (runtime-instances.md §14.8, 2026-10-18): the reads run on the worker that
//! received the exec, the process's key and its ancestors come from one
//! `/proc` walk (`secret_open::exec_lineage_of`), and only an exec that waits
//! for the arbiter before it goes is held on a thread of its own.
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! or the kernel lane of `scripts/ci/vm-run.sh`. A host where the seccomp
//! listener cannot be installed SKIPs.
//!
//!   (1) the record of every exec names the same process, parent and live
//!       chain as before: an exec two subshells deep (neither of which ever
//!       execs) names both; an exec from a worker THREAD names its process
//!       (the thread group's key, `own_key_of`); the tree's top process names
//!       the guard's process as its parent and no chain; each was held on the
//!       worker that received it (`EXECS_HELD_HERE`), none on a thread;
//!   (2) a call root in a session (the agent's child's exec, with a secret
//!       policy) still waits for the arbiter's `sessionExecRoot` BEFORE the
//!       exec goes: while the arbiter answers, the process still runs its old
//!       image; the holder it is made is recorded before the exec proceeds;
//!       it was held on a thread of its own (`EXECS_HELD_ON_THREAD`).

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, readable_within, reap_within, run_tag, socketpair, wait_limit};

use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use net_supervisor::guard::{parse_rules, GuardPolicy, NoResolver};
use net_supervisor::guard_kernel::{
    hand_listener, install_guard_filter_self, receive_listener, run_guard_supervisor, FilterTraps, GuardConfig, EXECS_HELD_HERE, EXECS_HELD_ON_THREAD,
};

const EXIT_NO_SECCOMP: i32 = 91;

fn reap(pid: i32) -> Option<i32> {
    if in_test_process() {
        return reap_within(pid, wait_limit(), "waiting for a child the test forked").code();
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    }
}

fn close_all_but(keep: &[RawFd]) {
    let mut k: Vec<RawFd> = keep.iter().copied().filter(|f| *f >= 3).collect();
    k.sort_unstable();
    let mut from: u32 = 3;
    for f in k {
        if (f as u32) > from {
            unsafe { libc::syscall(libc::SYS_close_range, from, f as u32 - 1, 0u32) };
        }
        from = f as u32 + 1;
    }
    unsafe { libc::syscall(libc::SYS_close_range, from, u32::MAX, 0u32) };
}

fn guarded(traps: FilterTraps, cfg: GuardConfig, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    let (sup, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        close_all_but(&[child_sock]);
        let listener = match install_guard_filter_self(traps) {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if !hand_listener(child_sock, listener, true) {
            unsafe { libc::_exit(92) };
        }
        unsafe { libc::close(listener) };
        let code = body();
        unsafe { libc::_exit(code) };
    }
    unsafe { libc::close(child_sock) };
    readable_within(sup, child, wait_limit(), "waiting for the tracee to hand over its seccomp listener");
    let listener = match receive_listener(sup) {
        Ok((fd, _)) => fd,
        Err(_) => {
            assert_eq!(reap(child), Some(EXIT_NO_SECCOMP), "the tracee could not hand over its listener");
            eprintln!("SKIP: seccomp NEW_LISTENER denied here");
            return None;
        }
    };
    let server = std::thread::spawn(move || {
        let _ = run_guard_supervisor(listener, cfg);
        unsafe { libc::close(listener) };
    });
    let code = reap(child);
    let _ = join_within(server, wait_limit(), "the guard supervisor (run_guard_supervisor), after its tracee exited");
    unsafe { libc::close(sup) };
    Some(code)
}

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn this_exe() -> String {
    std::fs::read_link("/proc/self/exe").unwrap().to_str().unwrap().to_string()
}

fn work_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("mandu-exec-record-{tag}-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn wait_for(p: &Path) -> Option<String> {
    for _ in 0..500 {
        if let Ok(s) = std::fs::read_to_string(p) {
            if s.ends_with('\n') {
                return Some(s.trim().to_string());
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

fn fork_run(f: impl FnOnce() -> i32) -> i32 {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let code = f();
        unsafe { libc::_exit(code) };
    }
    pid
}

/// The scenario's facts, written by the processes of the tree.
#[derive(Clone)]
struct Run {
    dir: PathBuf,
}

impl Run {
    fn put(&self, name: &str, v: &str) {
        std::fs::write(self.dir.join(format!("{name}.tmp")), format!("{v}\n")).unwrap();
        std::fs::rename(self.dir.join(format!("{name}.tmp")), self.dir.join(name)).unwrap();
    }
    fn get(&self, name: &str) -> Option<String> {
        wait_for(&self.dir.join(name))
    }
}

fn key_of(pid: i32) -> String {
    mandu_arbiter::proc::proc_key_for_pid(pid).unwrap_or_default()
}

fn exec_true() -> i32 {
    let p = std::ffi::CString::new("/bin/true").unwrap();
    unsafe { libc::execl(p.as_ptr(), p.as_ptr(), std::ptr::null::<libc::c_char>()) };
    7
}

/// One record the arbiter was told.
#[derive(Debug, Clone, Default)]
struct Told {
    op: String,
    proc_key: String,
    parent_key: String,
    ancestors: Option<Vec<String>>,
    call_root: bool,
    /// For `sessionExecRoot`: the image the process ran while it was asked.
    exe_then: String,
}

type Log = Arc<Mutex<Vec<Told>>>;

fn recording_arbiter() -> (&'static mandu_arbiter::mock::MockArbiter, Log) {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let l = log.clone();
    let m = mandu_arbiter::mock::MockArbiter::start(mandu_arbiter::mock::op_handler(move |op, req| {
        let s = |k: &str| req.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let mut t = Told { op: op.to_string(), proc_key: s("procKey"), parent_key: s("parentKey"), ..Default::default() };
        t.ancestors = req.get("ancestors").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect());
        t.call_root = req.get("callRoot").and_then(|v| v.as_bool()).unwrap_or(false);
        match op {
            "sessionExecRoot" => {
                // The exec is held while this is asked: the process still runs
                // the image it had before the exec.
                let pid = t.proc_key.split('-').next().unwrap_or("").to_string();
                std::thread::sleep(Duration::from_millis(150));
                t.exe_then = std::fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
                l.lock().unwrap().push(t);
                Ok(serde_json::json!({ "holder": true, "level": "no-model", "reason": "the session read a secret" }))
            }
            "recordExecRoot" => {
                l.lock().unwrap().push(t);
                Ok(serde_json::json!({ "ok": true }))
            }
            _ => Ok(serde_json::Value::Null),
        }
    }))
    .leak();
    (m, log)
}

/// A secret policy (so the filter traps exec) with the arbiter `arbiter`;
/// `agent`: the launch names this test binary as the agent.
fn secret_cfg(dir: &Path, arbiter: &mandu_arbiter::mock::MockArbiter, agent: bool) -> GuardConfig {
    let secret = dir.join("secret.env");
    let twin = dir.join("twin.env");
    std::fs::write(&secret, "API_KEY=EXEC-RECORD-CANARY\n").unwrap();
    std::fs::write(&twin, "API_KEY=$MDU:twin\n").unwrap();
    let policy = dir.join("policy.json");
    let agent_exe = if agent { this_exe() } else { String::new() };
    std::fs::write(
        &policy,
        format!(r#"{{"agentExe":"{agent_exe}","ask":"never","session":"exec-record","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, secret.display(), twin.display()),
    )
    .unwrap();
    let mut c = GuardConfig::new(Arc::new(GuardPolicy::new(parse_rules(&["tcp:192.0.2.1:9".to_string()]).unwrap())), Arc::new(NoResolver));
    c.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(&policy).unwrap()));
    c.emitter = Some(Arc::new(Mutex::new(mandu_arbiter::ArbiterClient::new(&arbiter.socket_path))));
    c
}

fn traps() -> FilterTraps {
    FilterTraps { open: true, secrets: true, ..Default::default() }
}

fn exec_of<'a>(log: &'a [Told], key: &str) -> Option<&'a Told> {
    log.iter().find(|t| t.op == "recordExecRoot" && t.proc_key == key)
}

/// Wait (bounded) until the arbiter was told of an exec by each of `keys`:
/// the records are sent after the CONTINUE, off the tracee's path.
fn told_of(log: &Log, keys: &[&str]) -> Vec<Told> {
    for _ in 0..300 {
        let now = log.lock().unwrap().clone();
        if keys.iter().all(|k| exec_of(&now, k).is_some()) {
            return now;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    log.lock().unwrap().clone()
}

#[test]
#[ignore]
fn every_exec_record_names_its_process_parent_and_live_chain_and_is_held_on_the_worker() {
    let _g = serial();
    let dir = work_dir("chain");
    let (arb, log) = recording_arbiter();
    let cfg = secret_cfg(&dir, arb, false);
    let (here0, thread0) = (EXECS_HELD_HERE.load(Ordering::SeqCst), EXECS_HELD_ON_THREAD.load(Ordering::SeqCst));
    let r = Run { dir: dir.clone() };
    let rb = r.clone();
    let code = guarded(traps(), cfg, move || {
        rb.put("b", &key_of(unsafe { libc::getpid() }));
        // Two subshells that never exec, then an exec two levels below.
        let r1 = rb.clone();
        let s1 = fork_run(move || {
            r1.put("s1", &key_of(unsafe { libc::getpid() }));
            let r2 = r1.clone();
            let s2 = fork_run(move || {
                r2.put("s2", &key_of(unsafe { libc::getpid() }));
                exec_true()
            });
            if reap(s2) == Some(0) {
                0
            } else {
                3
            }
        });
        if reap(s1) != Some(0) {
            return 4;
        }
        // An exec from a worker thread: the process's key, not the thread's.
        let r3 = rb.clone();
        let s3 = fork_run(move || {
            r3.put("s3", &key_of(unsafe { libc::getpid() }));
            let _ = std::thread::spawn(exec_true);
            std::thread::sleep(Duration::from_secs(10));
            5
        });
        if reap(s3) != Some(0) {
            return 6;
        }
        // The top process's own exec: its parent is the guard's process.
        exec_true()
    });
    let Some(code) = code else { return };
    assert_eq!(code, Some(0), "every exec ran: the tree's checks passed");
    let (b, s1, s2, s3) = (r.get("b").unwrap(), r.get("s1").unwrap(), r.get("s2").unwrap(), r.get("s3").unwrap());
    let told = told_of(&log, &[&b, &s2, &s3]);
    let _ = std::fs::remove_dir_all(&dir);

    let e2 = exec_of(&told, &s2).unwrap_or_else(|| panic!("the deep exec is recorded: {told:?}"));
    assert_eq!(e2.parent_key, s1, "its parent is the subshell above it");
    assert_eq!(e2.ancestors.as_deref(), Some(&[s1.clone(), b.clone()][..]), "both subshells, nearest first, stopped below the guard");
    let e3 = exec_of(&told, &s3).unwrap_or_else(|| panic!("the thread's exec is recorded under its process: {told:?}"));
    assert_eq!(e3.parent_key, b);
    assert_eq!(e3.ancestors.as_deref(), Some(&[b.clone()][..]));
    let eb = exec_of(&told, &b).unwrap_or_else(|| panic!("the top process's exec is recorded: {told:?}"));
    assert_eq!(eb.parent_key, key_of(unsafe { libc::getpid() }), "the top process's parent is the guard's process");
    assert_eq!(eb.ancestors, None, "and no chain: the walk stops below the guard");
    assert!(told.iter().all(|t| !t.call_root && t.op != "sessionExecRoot"), "no agent named: no call root, no ask: {told:?}");

    let (here, thread) = (EXECS_HELD_HERE.load(Ordering::SeqCst) - here0, EXECS_HELD_ON_THREAD.load(Ordering::SeqCst) - thread0);
    assert!(here >= 3, "every exec was held on the worker that received it: {here}");
    assert_eq!(thread, 0, "none on a thread of its own");
}

#[test]
#[ignore]
fn a_call_root_in_a_session_is_made_a_holder_before_its_exec_goes() {
    let _g = serial();
    let dir = work_dir("call-root");
    let (arb, log) = recording_arbiter();
    let cfg = secret_cfg(&dir, arb, true);
    let tainted = cfg.tainted.clone();
    let thread0 = EXECS_HELD_ON_THREAD.load(Ordering::SeqCst);
    let r = Run { dir: dir.clone() };
    let rb = r.clone();
    // The body is the agent (this test binary, the tree's first process of
    // it); its child's exec is the shell of a tool call.
    let code = guarded(traps(), cfg, move || {
        let rc = rb.clone();
        let shell = fork_run(move || {
            rc.put("shell", &key_of(unsafe { libc::getpid() }));
            exec_true()
        });
        if reap(shell) == Some(0) {
            0
        } else {
            3
        }
    });
    let Some(code) = code else { return };
    assert_eq!(code, Some(0));
    let shell = r.get("shell").unwrap();
    let told = told_of(&log, &[&shell]);
    let _ = std::fs::remove_dir_all(&dir);

    let ask = told.iter().find(|t| t.op == "sessionExecRoot" && t.proc_key == shell).unwrap_or_else(|| panic!("the call root is asked: {told:?}"));
    assert_eq!(ask.exe_then, this_exe(), "the exec was held while the arbiter answered: the process still ran its old image");
    assert!(tainted.contains(&shell), "the call root was made a holder");
    let rec = exec_of(&told, &shell).unwrap_or_else(|| panic!("the call root's exec is recorded: {told:?}"));
    assert!(rec.call_root, "recorded as a call root: {rec:?}");
    assert!(EXECS_HELD_ON_THREAD.load(Ordering::SeqCst) - thread0 >= 1, "the asking exec was held on a thread of its own");
}
