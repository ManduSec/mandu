//! fifo_signal_integration — a named pipe whose reader the guard does not
//! watch, a named pipe joined after a holder's write, and a signal that
//! carries data (confidentiality-plan-13 §4.5.1 "Not covered", §4.9;
//! exec-routing.md §7.5 "Still uncovered").
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`.
//! Leak oracles, each red on master before this change:
//!
//!   1. a holder's write-open of a FIFO whose only reader is OUTSIDE the
//!      guard's tree (here: a thread of the test process, which the guard
//!      does not supervise) is refused, and the outside reader receives no
//!      byte; control: an in-tree reader is made a holder and the write
//!      goes on;
//!   2. a FIFO reader that opens it AFTER a holder's write, reads and closes
//!      it before any other trapped call is a holder at its open, so its
//!      later send to an unbound host is refused;
//!   2b. a reader whose BLOCKING read-open completes at the same moment as
//!      the holder's write-open (both released by the FIFO) and that closes
//!      it before its next trapped call: a holder, every round (on master
//!      every round leaked);
//!   2c. a reader the agent runs itself (a file tool's child, Grep's `rg`)
//!      reading a holder's FIFO: recorded as an agent flow on the FIFO;
//!   3. a holder's `sigqueue` (a signal with an 8-byte payload) to a process
//!      that holds no secret is refused (EPERM); control: an untainted
//!      process's `sigqueue`, and the holder's to itself, go through.
//!
//! P0 1a (2026-10-07), each red on master: a holder's `O_RDWR` write-open
//! of a FIFO whose only reader is outside the tree (a process of the same
//! user that is no descendant of the guard's tree), or that has no reader
//! at all, is refused, and an in-tree reader admits it; a FIFO read both
//! inside and outside the tree refuses a holder's `O_WRONLY` write-open.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, read_to_end_within, readable_within, readable_within_tree, reap_within, run_tag, socketpair, wait_limit};

use std::io::{Read, Write};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mandu_arbiter::mock::{op_handler, MockArbiter};
use net_supervisor::guard::{parse_rules, GuardPolicy, NoResolver};
use net_supervisor::guard_kernel::{
    hand_listener, install_guard_filter_self, receive_listener, run_guard_supervisor, FilterTraps,
    GuardConfig,
};

const EXIT_NO_SECCOMP: i32 = 91;
const CANARY: &str = "OBJECT-CANARY-5519";
const DEST: [u8; 4] = [127, 0, 0, 3];

// ── plumbing (as pipe_taint_integration.rs) ─────────────────────────────────

fn lo_up() {
    let _ = std::process::Command::new("ip").args(["link", "set", "lo", "up"]).stderr(std::process::Stdio::null()).status();
}

fn read_file(p: &Path) -> Result<String, i32> {
    std::fs::read_to_string(p).map_err(|e| e.raw_os_error().unwrap_or(-1))
}

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

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

struct Secret {
    dir: PathBuf,
    path: PathBuf,
    policy: PathBuf,
}

impl Secret {
    fn new(tag: &str) -> Secret {
        let dir = std::env::temp_dir().join(format!("mandu-obj-{tag}-{}", run_tag()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let path = dir.join("x.txt");
        let twin = dir.join("twin.txt");
        std::fs::write(&path, format!("API_KEY={CANARY}\n")).unwrap();
        std::fs::write(&twin, "API_KEY=$MDU:twin\n").unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(
            &policy,
            format!(r#"{{"agentExe":"","ask":"never","session":"obj","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, path.display(), twin.display()),
        )
        .unwrap();
        Secret { dir, path, policy }
    }
    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
    /// The same secret, with this test binary as the launch's agent: the
    /// guarded body (its first-started process in the tree) is the agent,
    /// and a process it forks is the agent's child, as a file tool's `rg`.
    fn with_agent(self) -> Secret {
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let twin = self.dir.join("twin.txt");
        std::fs::write(
            &self.policy,
            format!(r#"{{"agentExe":"{}","ask":"never","session":"obj","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, exe.display(), self.path.display(), twin.display()),
        )
        .unwrap();
        self
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `(op, procKey, detail)`: the flows and labels the guard reported.
type Told = Arc<Mutex<Vec<(String, String, Vec<String>)>>>;

/// Every opener is a reader (raw); every holder is bound nowhere; labels
/// and flows are recorded. Leaked on purpose (send_integration.rs).
fn recording_arbiter() -> (&'static MockArbiter, Told) {
    let told: Told = Arc::new(Mutex::new(Vec::new()));
    let t = told.clone();
    let m = MockArbiter::start(op_handler(move |op, req| {
        let key = req.get("procKey").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let flows = |r: &serde_json::Value| -> Vec<String> { r.get("flowsFrom").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default() };
        match op {
            "decideSecretOpen" => Ok(serde_json::json!({ "verdict": "raw", "app": "test", "level": "no-model", "reason": "mock reader" })),
            "taintedProcessBindings" => Ok(serde_json::json!({ "tainted": true, "level": "no-model", "files": ["x.txt"], "bindings": [] })),
            "recordProcessFlow" => {
                t.lock().unwrap().push((op.to_string(), key, flows(req)));
                Ok(serde_json::json!({ "ok": true }))
            }
            "recordAgentFlow" => {
                // (op, channel, [flowsFrom…, "closed"?])
                let channel = req.get("channel").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let mut f = flows(req);
                if req.get("closed").and_then(|v| v.as_bool()) == Some(true) {
                    f.push("closed".into());
                }
                t.lock().unwrap().push((op.to_string(), channel, f));
                Ok(serde_json::json!({ "ok": true }))
            }
            "labelWrittenPathTainted" => {
                let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
                t.lock().unwrap().push((op.to_string(), key, vec![path]));
                Ok(serde_json::json!({ "labeled": true, "level": "no-model", "reason": "mock" }))
            }
            _ => Ok(serde_json::Value::Null),
        }
    })).leak();
    (m, told)
}

fn secret_cfg(secret: &Secret, arbiter: &MockArbiter) -> GuardConfig {
    let specs: Vec<String> = ["any:127.0.0.0/8:*"].iter().map(|s| s.to_string()).collect();
    let mut cfg = GuardConfig::new(Arc::new(GuardPolicy::new(parse_rules(&specs).unwrap())), Arc::new(NoResolver));
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(&secret.policy).unwrap()));
    cfg.emitter = Some(Arc::new(Mutex::new(mandu_arbiter::ArbiterClient::new(&arbiter.socket_path))));
    cfg.proxy_ports = vec![1];
    cfg
}

fn secret_traps() -> FilterTraps {
    FilterTraps { open: true, secrets: true, ..Default::default() }
}

/// Run `body` in a forked child under the guard's filter, served by the real
/// supervisor loop with `cfg`; the child's exit code (None: killed), or None
/// to SKIP.
fn guarded(cfg: GuardConfig, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    lo_up();
    let (sup, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        close_all_but(&[child_sock]);
        // Its own process group, for the watchdog below.
        unsafe { libc::setpgid(0, 0) };
        let listener = match install_guard_filter_self(secret_traps()) {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if !hand_listener(child_sock, listener, true) {
            unsafe {
                libc::close(listener);
                libc::_exit(92)
            };
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
    // A watchdog: a tree that hangs (a FIFO open nobody completes) is
    // killed after 60 s, so one stuck shape fails its own test instead of
    // hanging the whole run.
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let d2 = done.clone();
    let dog = std::thread::spawn(move || {
        for _ in 0..600 {
            std::thread::sleep(Duration::from_millis(100));
            if d2.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
        }
        eprintln!("WATCHDOG: the guarded tree hung; killed");
        unsafe { libc::kill(-child, libc::SIGKILL) };
    });
    let code = reap(child);
    let _ = join_within(server, wait_limit(), "the guard supervisor (run_guard_supervisor), after its tracee exited");
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = join_within(dog, wait_limit(), "the watchdog thread, after its done flag");
    unsafe { libc::close(sup) };
    Some(code)
}

/// The tests share the test process's tree: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn tcp_listener(ip: [u8; 4]) -> (u16, Arc<Mutex<Vec<u8>>>) {
    let l = std::net::TcpListener::bind((std::net::Ipv4Addr::from(ip), 0)).expect("bind tcp listener");
    let port = l.local_addr().unwrap().port();
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { break };
            let g = g.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = c.read_to_end(&mut buf);
                g.lock().unwrap().extend_from_slice(&buf);
            });
        }
    });
    (port, got)
}

fn tcp_connect(ip: [u8; 4], port: u16) -> Result<RawFd, i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let a = libc::sockaddr_in { sin_family: libc::AF_INET as u16, sin_port: port.to_be(), sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(ip) }, sin_zero: [0; 8] };
    if unsafe { libc::connect(fd, &a as *const _ as *const libc::sockaddr, 16) } == 0 {
        Ok(fd)
    } else {
        let e = errno();
        unsafe { libc::close(fd) };
        Err(e)
    }
}

/// Send `data` to `ip:port`: "sent", or "e<errno>".
fn send_to(ip: [u8; 4], port: u16, data: &[u8]) -> String {
    match tcp_connect(ip, port) {
        Ok(fd) => {
            unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
            unsafe { libc::close(fd) };
            "sent".into()
        }
        Err(e) => format!("e{e}"),
    }
}

fn fork_run(f: impl FnOnce() -> i32) -> i32 {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let c = f();
        unsafe { libc::_exit(c) };
    }
    pid
}

fn canary_in(buf: &Arc<Mutex<Vec<u8>>>) -> bool {
    String::from_utf8_lossy(&buf.lock().unwrap()).contains(CANARY)
}

fn report(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|_| "<no report>".into())
}

fn eacces() -> String {
    format!("e{}", libc::EACCES)
}

fn mkfifo(p: &Path) {
    let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
}

/// A pipe one process signals readiness on (`signal_ready`, `await_ready`):
/// a blocking read of the other end returns once the byte is written, or
/// at EOF once every write end is closed (the signaller died before it got
/// ready). The FIFO tests' synchronization: no sleep stands in for "the
/// reader has opened it", and no marker file is polled for and read back
/// (`std::fs::write` creates the file before it writes it, so the poll
/// could read it empty: the 2026-10-07 flake of
/// `a_holders_rdwr_fifo_needs_a_reader_in_the_tree_and_none_outside`).
fn ready_pipe() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0, "pipe2");
    (fds[0], fds[1])
}

/// Write `b` to the readiness pipe `w` (when there is one, `w >= 0`) and
/// close it.
fn signal_ready(w: RawFd, b: u8) {
    if w >= 0 {
        unsafe {
            libc::write(w, &b as *const u8 as *const libc::c_void, 1);
            libc::close(w);
        }
    }
}

/// Block until `n` bytes were written to `r`, or every write end closed
/// first; close it. The bytes read. In the test process under a deadline
/// (its writer there is the outside reader, no child of this process).
fn await_ready(r: RawFd, n: usize) -> Vec<u8> {
    let t0 = std::time::Instant::now();
    let mut out = Vec::new();
    while out.len() < n {
        if in_test_process() {
            readable_within_tree(r, wait_limit().saturating_sub(t0.elapsed()), "waiting on a readiness pipe (the outside reader's open)");
        }
        let mut buf = [0u8; 64];
        let want = (n - out.len()).min(buf.len());
        let got = unsafe { libc::read(r, buf.as_mut_ptr() as *mut libc::c_void, want) };
        if got > 0 {
            out.extend_from_slice(&buf[..got as usize]);
        } else if got < 0 && errno() == libc::EINTR {
            continue;
        } else {
            break;
        }
    }
    unsafe { libc::close(r) };
    out
}

/// Open `p` for reading without blocking, signal the readiness pipe `ready`
/// (`o`, or `f` when the open failed), and read until `done` exists (and a
/// last read after it), or 30 s.
fn drain_fifo_until_ready(p: &Path, done: &Path, ready: RawFd) -> Vec<u8> {
    let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    signal_ready(ready, if fd >= 0 { b'o' } else { b'f' });
    if fd < 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let end = std::time::Instant::now() + Duration::from_secs(30);
    let mut last = false;
    loop {
        let mut buf = [0u8; 512];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            out.extend_from_slice(&buf[..n as usize]);
            continue;
        }
        if last || std::time::Instant::now() >= end {
            break;
        }
        last = done.exists();
        std::thread::sleep(Duration::from_millis(10));
    }
    unsafe { libc::close(fd) };
    out
}

fn drain_fifo(p: &Path, for_ms: u64) -> Vec<u8> {
    let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    if fd < 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let end = std::time::Instant::now() + Duration::from_millis(for_ms);
    while std::time::Instant::now() < end {
        let mut buf = [0u8; 512];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            out.extend_from_slice(&buf[..n as usize]);
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    unsafe { libc::close(fd) };
    out
}

// ── 1b. P0 1a: O_RDWR, and a FIFO read inside and outside the tree ─────────

/// A reader of a FIFO OUTSIDE the guard's tree (`outside_reader`): `got`
/// stops it and takes what it read.
struct OutsideReader {
    stop: PathBuf,
    /// The read end of the pipe the reader writes what it read to, then
    /// `OUTSIDE_DONE`, before it exits.
    result: RawFd,
}

/// What the outside reader writes after what it read: its absence (the
/// reader died) fails the test, so a reader that is gone never passes the
/// leak oracle as one that received nothing.
const OUTSIDE_DONE: &[u8] = b"\0outside-reader-done";

/// A reader of `fifo` OUTSIDE the guard's tree that is not the guard's own
/// process: forked twice, the middle exiting, so it is no descendant of the
/// test process (the guard's tree is everything below it) and runs on its
/// own. It holds the FIFO open for reading (non-blocking) and drains it
/// until `stop` exists (or 60 s), then writes what it read to its result
/// pipe. Returns once its open is done (a readiness pipe: `ready_pipe`).
fn outside_reader(fifo: &Path, stop: &Path) -> OutsideReader {
    let (fifo, stop) = (fifo.to_path_buf(), stop.to_path_buf());
    let (ready_r, ready_w) = ready_pipe();
    let (result_r, result_w) = ready_pipe();
    let mid = unsafe { libc::fork() };
    assert!(mid >= 0);
    if mid == 0 {
        let reader = unsafe { libc::fork() };
        if reader == 0 {
            unsafe {
                libc::close(ready_r);
                libc::close(result_r);
                libc::setsid();
            }
            let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) };
            // `o` (or `f`) and its pid.
            let mut hello = vec![if fd >= 0 { b'o' } else { b'f' }];
            hello.extend_from_slice(&unsafe { libc::getpid() }.to_ne_bytes());
            unsafe {
                libc::write(ready_w, hello.as_ptr() as *const libc::c_void, hello.len());
                libc::close(ready_w);
            }
            let mut out = Vec::new();
            let end = std::time::Instant::now() + Duration::from_secs(60);
            let mut last = false;
            // Reads until the stop file is seen and one more read is empty
            // (or the deadline); nothing when the open failed.
            if fd >= 0 {
                loop {
                    let mut buf = [0u8; 512];
                    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                    if n > 0 {
                        out.extend_from_slice(&buf[..n as usize]);
                        continue;
                    }
                    if last || std::time::Instant::now() >= end {
                        break;
                    }
                    last = stop.exists();
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            out.extend_from_slice(OUTSIDE_DONE);
            let mut off = 0;
            while off < out.len() {
                let n = unsafe { libc::write(result_w, out[off..].as_ptr() as *const libc::c_void, out.len() - off) };
                if n <= 0 {
                    break;
                }
                off += n as usize;
            }
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::_exit(0) };
    }
    // Only the reader keeps the write ends now: EOF on either means it is
    // done with it, or gone.
    unsafe {
        libc::close(ready_w);
        libc::close(result_w);
    }
    reap(mid);
    let hello = await_ready(ready_r, 5);
    assert_eq!(hello.first(), Some(&b'o'), "the outside reader opened the FIFO");
    // Orphaned when the middle exited, it is reparented to the namespace's
    // init or a subreaper: when that is this test process (the binary run
    // as pid 1 of its pid namespace, not under a shell as kernel-tests.sh
    // runs it), the reader is in the guard's tree after all (everything
    // below the guard's process) and the test proves nothing.
    let pid = i32::from_ne_bytes(hello[1..5].try_into().unwrap());
    let ppid = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| s.rsplit_once(") ").and_then(|(_, r)| r.split_whitespace().nth(1).and_then(|p| p.parse::<i32>().ok())));
    assert_ne!(ppid, Some(std::process::id() as i32), "the outside reader is a child of the test process (pid 1 of its namespace, or a subreaper): it is inside the guard's tree; run the test under a shell (scripts/kernel-tests.sh)");
    OutsideReader { stop, result: result_r }
}

impl OutsideReader {
    /// Stop the reader; what it read. Panics when it did not report to the
    /// end (it died: its silence is no proof that it received nothing).
    fn got(self) -> Vec<u8> {
        let _ = std::fs::write(&self.stop, "");
        let mut all = read_to_end_within(self.result, wait_limit(), "reading the outside reader's report to its end, after its stop file");
        unsafe { libc::close(self.result) };
        assert!(all.ends_with(OUTSIDE_DONE), "the outside reader reported what it read, to the end");
        all.truncate(all.len() - OUTSIDE_DONE.len());
        all
    }
}

/// The holder's write-open of `p` (`rdwr`: `O_RDWR`, else `O_WRONLY`) and
/// write of `k`: "wrote" or "e<errno>".
fn holder_write(p: &Path, k: &str, rdwr: bool) -> String {
    match std::fs::OpenOptions::new().read(rdwr).write(true).open(p) {
        Ok(mut f) => {
            let _ = f.write_all(k.as_bytes());
            "wrote".to_string()
        }
        Err(e) => format!("e{}", e.raw_os_error().unwrap_or(-1)),
    }
}

#[test]
#[ignore]
fn a_holders_rdwr_fifo_needs_a_reader_in_the_tree_and_none_outside() {
    // P0 1a (2026-10-07): an O_RDWR open completes with no reader, so the
    // guard's wait for an in-tree reader was skipped and a reader outside
    // the tree (a daemon, the user's own `cat`) received the holder's bytes.
    // Now: one outside refuses the open at once; none anywhere refuses it
    // after the wait (a later outside reader would go unseen); an in-tree
    // reader alone (the control) admits it.
    let _one = serial();
    let secret = Secret::new("fifo-rdwr");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (out_fifo, none_fifo, in_fifo) = (secret.file("out.fifo"), secret.file("none.fifo"), secret.file("in.fifo"));
    mkfifo(&out_fifo);
    mkfifo(&none_fifo);
    mkfifo(&in_fifo);
    let outside = outside_reader(&out_fifo, &secret.file("o.stop"));
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        // The in-tree reader has in.fifo open before the holder starts.
        let (ready_r, ready_w) = ready_pipe();
        let r = fork_run(|| {
            unsafe { libc::close(ready_r) };
            let data = drain_fifo_until_ready(&in_fifo, &d.join("h.done"), ready_w);
            let _ = std::fs::write(d.join("r.got"), &data);
            0
        });
        unsafe { libc::close(ready_w) };
        if await_ready(ready_r, 1) != b"o" {
            let _ = std::fs::write(d.join("report"), "the in-tree reader did not open in.fifo");
            return 0;
        }
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            let inn = holder_write(&in_fifo, &k, true);
            let _ = std::fs::write(d.join("h.done"), "");
            let out = holder_write(&out_fifo, &k, true);
            let none = holder_write(&none_fifo, &k, true);
            let _ = std::fs::write(d.join("h.out"), format!("in={inn} out={out} none={none}"));
            0
        });
        let rs = (reap(h), reap(r));
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        let _ = outside.got();
        return;
    };
    let seen = outside.got();
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let h = report(&secret.file("h.out"));
    eprintln!("O_RDWR holder: {h}");
    assert!(!String::from_utf8_lossy(&seen).contains(CANARY), "THE LEAK: a reader outside the guard's tree received the holder's O_RDWR write");
    assert_eq!(h, format!("in=wrote out={} none={}", eacces(), eacces()), "O_RDWR: an outside reader, or no reader in the tree, refuses the open; an in-tree reader admits it");
    assert!(String::from_utf8_lossy(&std::fs::read(secret.file("r.got")).unwrap_or_default()).contains(CANARY), "control: the in-tree reader got the write");
    eprintln!("FIFO O_RDWR PASS");
}

#[test]
#[ignore]
fn a_holders_fifo_read_inside_and_outside_the_tree_is_refused() {
    // P0 1a (2026-10-07): one in-tree reader ended the guard's look, so a
    // reader outside the tree beside it received the holder's bytes.
    let _one = serial();
    let secret = Secret::new("fifo-both");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (both_fifo, in_fifo) = (secret.file("both.fifo"), secret.file("in.fifo"));
    mkfifo(&both_fifo);
    mkfifo(&in_fifo);
    let outside = outside_reader(&both_fifo, &secret.file("o.stop"));
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        // In-tree readers of both FIFOs, held open until the holder is done,
        // and open (two readiness bytes) before the holder starts.
        let (b2, i2, d2) = (both_fifo.clone(), in_fifo.clone(), d.clone());
        let (ready_r, ready_w) = ready_pipe();
        let r = fork_run(move || {
            unsafe { libc::close(ready_r) };
            let w2 = unsafe { libc::dup(ready_w) };
            let t = std::thread::spawn({
                let (i2, d2) = (i2.clone(), d2.clone());
                move || drain_fifo_until_ready(&i2, &d2.join("h.done"), w2)
            });
            let both = drain_fifo_until_ready(&b2, &d2.join("h.done"), ready_w);
            let inn = t.join().unwrap_or_default();
            let _ = std::fs::write(d2.join("r.both"), &both);
            let _ = std::fs::write(d2.join("r.in"), &inn);
            0
        });
        unsafe { libc::close(ready_w) };
        if await_ready(ready_r, 2) != b"oo" {
            let _ = std::fs::write(d.join("report"), "the in-tree reader did not open both FIFOs");
            return 0;
        }
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            let inn = holder_write(&in_fifo, &k, false);
            let both = holder_write(&both_fifo, &k, false);
            let _ = std::fs::write(d.join("h.done"), "");
            let _ = std::fs::write(d.join("h.out"), format!("in={inn} both={both}"));
            0
        });
        let rs = (reap(h), reap(r));
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        let _ = outside.got();
        return;
    };
    let seen = outside.got();
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let h = report(&secret.file("h.out"));
    eprintln!("inside-and-outside holder: {h}");
    assert!(!String::from_utf8_lossy(&seen).contains(CANARY), "THE LEAK: a reader outside the guard's tree, beside one inside, received the secret");
    assert_eq!(h, format!("in=wrote both={}", eacces()), "a FIFO read outside the tree as well refuses the write-open; the control (in-tree only) goes on");
    assert!(String::from_utf8_lossy(&std::fs::read(secret.file("r.in")).unwrap_or_default()).contains(CANARY), "control: the in-tree reader got the write");
    eprintln!("FIFO INSIDE AND OUTSIDE PASS");
}

// ── 1. a FIFO whose only reader is outside the guard's tree ─────────────────

#[test]
#[ignore]
fn a_holders_fifo_whose_only_reader_is_outside_the_tree_is_refused() {
    let _one = serial();
    let secret = Secret::new("fifo-out");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let (out_fifo, in_fifo) = (secret.file("out.fifo"), secret.file("in.fifo"));
    mkfifo(&out_fifo);
    mkfifo(&in_fifo);
    // The reader the guard does not watch: a thread of this test process
    // (the guard's tree is the process the test forks).
    // It holds the FIFO open until the guarded run is over (a reader that
    // went away would leave the holder's write-open blocked for good).
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let outside = {
        let (p, stop) = (out_fifo.clone(), stop.clone());
        std::thread::spawn(move || {
            let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
            let mut out = Vec::new();
            if fd < 0 {
                return out;
            }
            let end = std::time::Instant::now() + Duration::from_secs(60);
            while !stop.load(std::sync::atomic::Ordering::SeqCst) && std::time::Instant::now() < end {
                let mut buf = [0u8; 512];
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n > 0 {
                    out.extend_from_slice(&buf[..n as usize]);
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            unsafe { libc::close(fd) };
            out
        })
    };
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        // The control's reader, in the tree, open before the holder starts.
        let (ready_r, ready_w) = ready_pipe();
        let r = fork_run(|| {
            unsafe { libc::close(ready_r) };
            // Held open until the holder says it wrote (h.in), however long its
            // raw open took: a reader gone first would leave its write-open
            // blocked for good.
            let data = drain_fifo_until_ready(&in_fifo, &d.join("h.in"), ready_w);
            let _ = std::fs::write(d.join("r.out"), send_to(DEST, port, &data));
            0
        });
        unsafe { libc::close(ready_w) };
        if await_ready(ready_r, 1) != b"o" {
            let _ = std::fs::write(d.join("report"), "the in-tree reader did not open in.fifo");
            return 0;
        }
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            let try_write = |p: &Path| match std::fs::OpenOptions::new().write(true).open(p) {
                Ok(mut f) => {
                    let _ = f.write_all(k.as_bytes());
                    "wrote".to_string()
                }
                Err(e) => format!("e{}", e.raw_os_error().unwrap_or(-1)),
            };
            // The in-tree reader first (it reads for 1.5 s); the refusal of the
            // outside one waits for an in-tree reader that never comes.
            let t0 = std::time::Instant::now();
            let inn = try_write(&in_fifo);
            let _ = std::fs::write(d.join("h.in"), format!("{inn} after {:?}", t0.elapsed()));
            let out = try_write(&out_fifo);
            let _ = std::fs::write(d.join("h.out"), format!("out={out} in={inn}"));
            0
        });
        let rs = (reap(h), reap(r));
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        return;
    };
    eprintln!("outside test progress: in={} h={} r={}", report(&secret.file("h.in")), report(&secret.file("h.out")), report(&secret.file("r.out")));
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let seen = join_within(outside, wait_limit(), "the outside reader thread, after its stop flag").unwrap();
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let h = report(&secret.file("h.out"));
    eprintln!("holder: {h}; in-tree reader: {}", report(&secret.file("r.out")));
    assert!(!String::from_utf8_lossy(&seen).contains(CANARY), "THE LEAK: a reader outside the guard's tree received the secret");
    assert_eq!(h, format!("out={} in=wrote", eacces()), "the write-open toward an outside reader is refused; the in-tree one goes on");
    assert_eq!(report(&secret.file("r.out")), eacces(), "control: the in-tree reader is a holder (plan 13 D2)");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    eprintln!("FIFO OUTSIDE PASS");
}

// ── 2. a FIFO joined after the holder's write ───────────────────────────────

#[test]
#[ignore]
fn a_fifo_reader_that_joins_after_the_write_and_closes_first_is_a_holder() {
    let _one = serial();
    let secret = Secret::new("fifo-late");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let fifo = secret.file("pipe.fifo");
    mkfifo(&fifo);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        // The first reader keeps the FIFO open, so the holder's write-open
        // completes and its bytes wait in the pipe.
        let first = fork_run(|| {
            let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
            if fd < 0 {
                return 3;
            }
            let _ = std::fs::write(d.join("first"), "f");
            std::thread::sleep(Duration::from_millis(1500));
            unsafe { libc::close(fd) };
            0
        });
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            for _ in 0..200 {
                if d.join("first").exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            match std::fs::OpenOptions::new().write(true).open(&fifo) {
                Ok(mut f) => {
                    let _ = f.write_all(k.as_bytes());
                    let _ = std::fs::write(d.join("written"), "w");
                    // Hold the write end until the late reader read.
                    std::thread::sleep(Duration::from_millis(1000));
                }
                Err(e) => {
                    let _ = std::fs::write(d.join("written"), format!("e{}", e.raw_os_error().unwrap_or(-1)));
                }
            }
            0
        });
        // The late reader: opens after the write, reads, closes, sends.
        let late = fork_run(|| {
            for _ in 0..300 {
                if d.join("written").exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let data = drain_fifo(&fifo, 300);
            let _ = std::fs::write(d.join("late.out"), format!("read={} send={}", String::from_utf8_lossy(&data).contains(CANARY), send_to(DEST, port, &data)));
            0
        });
        let rs = (reap(late), reap(h), reap(first));
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0), Some(0))");
    let late = report(&secret.file("late.out"));
    eprintln!("late reader: {late}");
    assert!(late == format!("read=true send={}", eacces()) || late.starts_with("read=false"), "a reader joining after the write must be a holder at its open: {late}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    eprintln!("FIFO LATE PASS");
}

/// A reader's BLOCKING read-open of a FIFO that completes at the same moment
/// as a holder's write-open: the reader reads, closes the FIFO and sends,
/// with no other trapped call in between. Repeated, both opens released
/// together each time: the reader must be a holder every time (it is
/// listed in flight, or its descriptor is in its table, when the holder's
/// write-open looks; or it sees the mark at its own open).
#[test]
#[ignore]
fn a_fifo_reader_whose_open_completes_with_the_holders_is_a_holder() {
    let _one = serial();
    let secret = Secret::new("fifo-race");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    const ROUNDS: usize = 12;
    for i in 0..ROUNDS {
        mkfifo(&secret.file(&format!("race{i}.fifo")));
    }
    let Some(code) = guarded(cfg, move || {
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            for i in 0..ROUNDS {
                // Released with the reader by the FIFO itself: its blocking
                // open waits for this one.
                match std::fs::OpenOptions::new().write(true).open(d.join(format!("race{i}.fifo"))) {
                    Ok(mut f) => {
                        let _ = f.write_all(k.as_bytes());
                    }
                    Err(e) => {
                        let _ = std::fs::write(d.join(format!("h{i}.out")), format!("e{}", e.raw_os_error().unwrap_or(-1)));
                    }
                }
            }
            0
        });
        let mut rs = Vec::new();
        for i in 0..ROUNDS {
            let r = fork_run(|| {
                let p = d.join(format!("race{i}.fifo"));
                let data = match std::fs::File::open(&p) {
                    Ok(mut f) => {
                        let mut v = Vec::new();
                        let _ = f.read_to_end(&mut v);
                        v
                    }
                    Err(_) => Vec::new(),
                };
                // Closed already; the next trapped call is the connect.
                let _ = std::fs::write(d.join(format!("r{i}.out")), format!("read={} send={}", String::from_utf8_lossy(&data).contains(CANARY), send_to(DEST, port, &data)));
                0
            });
            rs.push(reap(r));
        }
        let hc = reap(h);
        let _ = std::fs::write(d.join("report"), format!("{hc:?} {}", rs.iter().all(|r| *r == Some(0))));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "Some(0) true");
    let outs: Vec<String> = (0..ROUNDS).map(|i| report(&secret.file(&format!("r{i}.out")))).collect();
    eprintln!("racing readers: {outs:?}");
    for o in &outs {
        assert!(o == &format!("read=true send={}", eacces()) || o.starts_with("read=false"), "a racing reader must be a holder: {outs:?}");
    }
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    eprintln!("FIFO RACE PASS");
}

/// A reader the AGENT runs itself (a file tool's child, Claude Code's
/// Grep running `rg`) reads a FIFO a holder writes. The child is made a
/// holder (D2), and since its output is the agent's own file tool result,
/// which no call tree folds, the receipt is recorded as an agent flow on a
/// file channel (the FIFO's path): the model exit masks that tool's result.
#[test]
#[ignore]
fn an_agent_tools_child_reading_a_holders_fifo_is_recorded_as_an_agent_flow() {
    let _one = serial();
    let secret = Secret::new("fifo-rg").with_agent();
    let (arbiter, told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let fifo = secret.file("tool.fifo");
    mkfifo(&fifo);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let f2 = fifo.clone();
    let Some(code) = guarded(cfg, move || {
        // The agent (this body) runs its tool's child: it reads the FIFO.
        let rg = fork_run(|| {
            let data = match std::fs::File::open(&f2) {
                Ok(mut f) => {
                    let mut v = Vec::new();
                    let _ = f.read_to_end(&mut v);
                    v
                }
                Err(e) => format!("e{}", e.raw_os_error().unwrap_or(-1)).into_bytes(),
            };
            let _ = std::fs::write(d.join("rg.out"), format!("read={}", String::from_utf8_lossy(&data).contains(CANARY)));
            0
        });
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            match std::fs::OpenOptions::new().write(true).open(&f2) {
                Ok(mut f) => {
                    let _ = f.write_all(k.as_bytes());
                }
                Err(e) => {
                    let _ = std::fs::write(d.join("h.out"), format!("e{}", e.raw_os_error().unwrap_or(-1)));
                }
            }
            0
        });
        let rs = (reap(h), reap(rg));
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    eprintln!("rg: {}; told: {:?}", report(&secret.file("rg.out")), told.lock().unwrap());
    let want = fifo.to_string_lossy().to_string();
    assert!(
        told.lock().unwrap().iter().any(|(op, ch, f)| op == "recordAgentFlow" && *ch == want && !f.iter().any(|x| x == "closed")),
        "the agent tool's child's read of the holder's FIFO must be recorded as an agent flow on the FIFO: {:?}",
        told.lock().unwrap()
    );
    eprintln!("AGENT CHILD FIFO PASS");
}

// ── 3. a signal with a payload ──────────────────────────────────────────────

/// Wait up to 2 s for SIGRTMIN (blocked beforehand): its payload, or None.
fn take_rt_payload() -> Option<i64> {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGRTMIN());
    }
    let ts = libc::timespec { tv_sec: 2, tv_nsec: 0 };
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::sigtimedwait(&set, &mut info, &ts) };
    if r < 0 {
        return None;
    }
    // si_value sits after si_pid and si_uid in the _rt member.
    let raw = &info as *const libc::siginfo_t as *const u8;
    let v = unsafe { std::ptr::read_unaligned(raw.add(24) as *const i64) };
    Some(v)
}

fn block_rt() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGRTMIN());
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
}

fn sigqueue_to(pid: i32, v: i64) -> i32 {
    let val = libc::sigval { sival_ptr: v as usize as *mut libc::c_void };
    if unsafe { libc::sigqueue(pid, libc::SIGRTMIN(), val) } == 0 {
        0
    } else {
        errno()
    }
}

#[test]
#[ignore]
fn a_holders_signal_with_a_payload_to_an_untainted_process_is_refused() {
    let _one = serial();
    let secret = Secret::new("sigq");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    // The receiver: no secret; reports the payloads it gets. Started by the
    // test process, OUTSIDE the guard's tree: since 2026-10-03 the holder's
    // parent (the tree's root below) becomes a holder at the holder's taint
    // (plan 13 §4.9, the exit status), and so does every child of it, so a
    // receiver the root started would hold the secret's taint too. It stands
    // for a process of another call (or none of the agent's).
    let rd = d.clone();
    let r = fork_run(move || {
        block_rt();
        let _ = std::fs::write(rd.join("r.ready"), "r");
        let a = take_rt_payload();
        let b = take_rt_payload();
        let _ = std::fs::write(rd.join("r.out"), format!("{a:?} {b:?}"));
        0
    });
    for _ in 0..200 {
        if d.join("r.ready").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let Some(code) = guarded(cfg, move || {
        block_rt();
        // Control: an untainted sender.
        let u = fork_run(|| {
            let _ = std::fs::write(d.join("u.out"), format!("{}", sigqueue_to(r, 7)));
            0
        });
        let uc = reap(u);
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            block_rt();
            // Eight bytes of the secret in the payload.
            let mut word = [0u8; 8];
            word.copy_from_slice(&k.as_bytes()[8..16]);
            let other = sigqueue_to(r, i64::from_ne_bytes(word));
            // To itself (a holder): goes through.
            let me = sigqueue_to(unsafe { libc::getpid() }, 9);
            let own = take_rt_payload();
            let _ = std::fs::write(d.join("h.out"), format!("other={other} self={me} got={own:?}"));
            0
        });
        let hc = reap(h);
        let _ = std::fs::write(d.join("report"), format!("{:?}", (uc, hc)));
        0
    }) else {
        unsafe { libc::kill(r, libc::SIGKILL) };
        let _ = reap(r);
        return;
    };
    let rc = reap(r);
    assert_eq!(rc, Some(0), "the receiver ran to its end");
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let (h, r) = (report(&secret.file("h.out")), report(&secret.file("r.out")));
    eprintln!("holder: {h}; receiver: {r}");
    assert_eq!(report(&secret.file("u.out")), "0", "control: an untainted sigqueue goes through");
    assert_eq!(h, format!("other={} self=0 got=Some(9)", libc::EPERM), "the holder's payload to an untainted process is refused; to itself it goes");
    assert_eq!(r, "Some(7) None", "the receiver got the control's payload and nothing of the holder's");
    eprintln!("SIGQUEUE PASS");
}

