//! wait_status_integration — plan 13 §4.9 and §9 R4, decided by the
//! maintainer 2026-10-03: a holder's EXIT STATUS reaches whoever reaps it,
//! so the reaper becomes a holder (`wait_flow`, `guard_wait`).
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! (an unprivileged user + network + pid namespace; `lo` is brought up
//! here). A host where the seccomp listener cannot be installed SKIPs; a
//! missing `python3`, `node` or `make` SKIPs its leg.
//!
//! The tree's root plays the call's shell: it forks a reader that reads the
//! secret raw and exits with a byte of it (`cat .env | prog`), then learns
//! that status and tries to take it out (`curl "…?b=$?"`, a file). Before
//! 2026-10-03 every leak below passed: the shell was no holder.
//!
//!   - by `waitpid`, then a connect to an unbound host: refused (EACCES);
//!     then a file it opens: labelled as its write;
//!   - by `SIGCHLD`'s `siginfo` (`sigwaitinfo`), with no wait at all;
//!   - by a blocking `waitpid` already in progress when the child read;
//!   - a holder the guard learned of WITHOUT a sweep (planted in the set by
//!     the test, as the later-event look or the orphan backstop records
//!     one): its reaper becomes a holder at the wait itself (`wait4` with and
//!     without `WNOHANG`, `waitid` by pid and by pidfd);
//!   - a reaper already holding an unbound connection: the child's raw open
//!     is refused (the taint-time sweep), and a wait for a planted holder
//!     answers ECHILD (the status never arrives);
//!   - `ioctl(PIDFD_GET_INFO)` answers ENOTTY under a secret policy;
//!   - the controls: shells, `make`, Python's `subprocess` and Node's
//!     `child_process` still reap their children and see their real status,
//!     with and without a holder in the tree.
//!
//! The arbiter is a mock that answers every secret open `raw`, binds every
//! holder nowhere and records the labels the guard asks for.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, pipe, readable_within, reap_within, run_tag, socketpair, wait_limit};

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
const CANARY: &str = "WAIT-CANARY-5521";
/// The byte of the secret the reader exits with: `API_KEY=W…`, index 8.
const SECRET_BYTE: i32 = b'W' as i32;

// ── plumbing (as pipe_taint_integration.rs) ─────────────────────────────────

fn lo_up() {
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .stderr(std::process::Stdio::null())
        .status();
}

fn write_all(fd: RawFd, data: &[u8]) -> isize {
    unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) }
}

fn read_byte(fd: RawFd) -> bool {
    let mut b = [0u8; 1];
    unsafe { libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, 1) == 1 }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Wait for `pid`: its exit code, or a negative errno, or -1000 for a death
/// by signal.
fn wait_code(pid: i32, flags: i32) -> i32 {
    let mut status = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, flags) };
        if r == pid {
            return if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1000 };
        }
        if r == 0 {
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }
        let e = errno();
        if e == libc::EINTR {
            continue;
        }
        return -e;
    }
}

fn reap(pid: i32) -> Option<i32> {
    if in_test_process() {
        return reap_within(pid, wait_limit(), "waiting for a child the test forked").code();
    }
    match wait_code(pid, 0) {
        c if c >= 0 => Some(c),
        _ => None,
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

fn fork_run(f: impl FnOnce() -> i32) -> i32 {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let c = f();
        unsafe { libc::_exit(c) };
    }
    pid
}

struct Secret {
    dir: PathBuf,
    path: PathBuf,
    policy: PathBuf,
}

impl Secret {
    fn new(tag: &str) -> Secret {
        let dir = std::env::temp_dir().join(format!("mandu-wait-{tag}-{}", run_tag()));
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
            format!(
                r#"{{"agentExe":"","ask":"never","session":"wait","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#,
                path.display(),
                twin.display()
            ),
        )
        .unwrap();
        Secret { dir, path, policy }
    }
    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What the mock arbiter was asked to label: `(path, procKey)`.
type Labels = Arc<Mutex<Vec<(String, String)>>>;

fn recording_arbiter() -> (&'static MockArbiter, Labels) {
    let labels: Labels = Arc::new(Mutex::new(Vec::new()));
    let l = labels.clone();
    let m = MockArbiter::start(op_handler(move |op, req| match op {
        "decideSecretOpen" => Ok(serde_json::json!({ "verdict": "raw", "app": "test", "level": "no-model", "reason": "mock reader" })),
        "taintedProcessBindings" => Ok(serde_json::json!({ "tainted": true, "level": "no-model", "files": ["x.txt"], "bindings": [] })),
        "labelWrittenPathTainted" => {
            let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let key = req.get("procKey").and_then(|v| v.as_str()).unwrap_or("").to_string();
            l.lock().unwrap().push((path, key));
            Ok(serde_json::json!({ "labeled": true, "level": "no-model", "reason": "mock" }))
        }
        _ => Ok(serde_json::Value::Null),
    })).leak();
    (m, labels)
}

fn secret_cfg(secret: &Secret, arbiter: &MockArbiter) -> GuardConfig {
    let specs: Vec<String> = ["any:127.0.0.0/8:*"].iter().map(|s| s.to_string()).collect();
    let mut cfg = GuardConfig::new(Arc::new(GuardPolicy::new(parse_rules(&specs).unwrap())), Arc::new(NoResolver));
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(&secret.policy).unwrap()));
    cfg.emitter = Some(Arc::new(Mutex::new(mandu_arbiter::ArbiterClient::new(&arbiter.socket_path))));
    cfg.proxy_ports = vec![1];
    cfg
}

fn guarded_keep(cfg: GuardConfig, keep: &[RawFd], body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    lo_up();
    let (sup, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let mut k = keep.to_vec();
        k.push(child_sock);
        close_all_but(&k);
        let listener = match install_guard_filter_self(FilterTraps { open: true, secrets: true, ..Default::default() }) {
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
    let code = reap(child);
    let _ = join_within(server, wait_limit(), "the guard supervisor (run_guard_supervisor), after its tracee exited");
    unsafe { libc::close(sup) };
    Some(code)
}

fn guarded(cfg: GuardConfig, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    guarded_keep(cfg, &[], body)
}

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// A TCP listener on `ip` whose connections are read into a shared buffer.
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
                use std::io::Read;
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
            write_all(fd, data);
            unsafe { libc::close(fd) };
            "sent".into()
        }
        Err(e) => format!("e{e}"),
    }
}

/// The unbound host (no binding of the mock's holders names it).
const DEST: [u8; 4] = [127, 0, 0, 3];

/// The reader: reads the secret raw and exits with one byte of it (the
/// program whose status the shell reads); 4 when the raw open is refused.
fn reader(path: &Path) -> i32 {
    match std::fs::read_to_string(path) {
        Ok(k) if k.contains(CANARY) => k.as_bytes()[8] as i32,
        Ok(_) => 5,
        Err(_) => 4,
    }
}

fn report(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn seen(got: &Arc<Mutex<Vec<u8>>>) -> String {
    std::thread::sleep(Duration::from_millis(200));
    String::from_utf8_lossy(&got.lock().unwrap()).to_string()
}

fn status_msg(code: i32) -> String {
    format!("STATUS={code};")
}

// ── the leak: `cat .env | prog; curl "…?b=$?"` ──────────────────────────────

/// The shell reaps the reader with `waitpid`, then connects to an unbound
/// host with the status, then writes it to a file it opens.
#[test]
#[ignore]
fn the_reaper_of_a_holder_is_confined_like_one() {
    let _one = serial();
    let secret = Secret::new("reap");
    let (arbiter, labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let (path, rp, sp) = (secret.path.clone(), secret.file("report.txt"), secret.file("status.txt"));
    let Some(code) = guarded(cfg, move || {
        let child = fork_run(|| reader(&path));
        let status = wait_code(child, 0);
        let sent = send_to(DEST, port, status_msg(status).as_bytes());
        let _ = std::fs::write(&sp, status_msg(status));
        let _ = std::fs::write(&rp, format!("status={status} sent={sent}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = report(&secret.file("report.txt"));
    assert!(r.starts_with(&format!("status={SECRET_BYTE} ")), "the shell still reaps its child and sees its status: {r}");
    assert!(r.ends_with(&format!("sent=e{}", libc::EACCES)), "the reaper's connect to an unbound host must be refused: {r}");
    let s = seen(&got);
    assert!(!s.contains(&status_msg(SECRET_BYTE)), "the holder's exit status reached the unbound host: {s}");
    let status_file = secret.file("status.txt").to_string_lossy().to_string();
    let l = labels.lock().unwrap().clone();
    assert!(l.iter().any(|(p, _)| *p == status_file), "the file the reaper wrote the status to must take the label: {l:?}");
    eprintln!("WAIT REAP PASS");
}

/// `SIGCHLD`'s `siginfo` carries the status at the exit itself, before any
/// wait: the parent was made a holder at the child's taint.
#[test]
#[ignore]
fn a_sigchld_siginfo_reaches_no_untainted_parent() {
    let _one = serial();
    let secret = Secret::new("siginfo");
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let Some(code) = guarded(cfg, move || {
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGCHLD);
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        }
        let child = fork_run(|| reader(&path));
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let sig = unsafe { libc::sigwaitinfo(&set, &mut info) };
        let status = if sig == libc::SIGCHLD { unsafe { info.si_status() } } else { -1 };
        let sent = send_to(DEST, port, status_msg(status).as_bytes());
        // Reaped only now, after the send (no wait before it).
        let _ = wait_code(child, 0);
        let _ = std::fs::write(&rp, format!("status={status} sent={sent}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = report(&secret.file("report.txt"));
    assert!(r.starts_with(&format!("status={SECRET_BYTE} ")), "siginfo carries the status: {r}");
    assert!(r.ends_with(&format!("sent=e{}", libc::EACCES)), "the parent learned the status from siginfo and must be confined: {r}");
    assert!(!seen(&got).contains(&status_msg(SECRET_BYTE)), "the status reached the unbound host");
    eprintln!("WAIT SIGINFO PASS");
}

/// The shell is already blocked in `waitpid` (judged, nobody held yet) when
/// its child reads: the child's taint makes it a holder before the read.
#[test]
#[ignore]
fn a_wait_already_blocking_when_the_child_reads_is_covered() {
    let _one = serial();
    let secret = Secret::new("blocking");
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let Some(code) = guarded(cfg, move || {
        let child = fork_run(|| {
            std::thread::sleep(Duration::from_millis(400));
            reader(&path)
        });
        let status = wait_code(child, 0);
        let sent = send_to(DEST, port, status_msg(status).as_bytes());
        let _ = std::fs::write(&rp, format!("status={status} sent={sent}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = report(&secret.file("report.txt"));
    assert!(r.starts_with(&format!("status={SECRET_BYTE} ")), "{r}");
    assert!(r.ends_with(&format!("sent=e{}", libc::EACCES)), "a wait in progress at the child's read must not leave the shell untainted: {r}");
    assert!(!seen(&got).contains(&status_msg(SECRET_BYTE)));
    eprintln!("WAIT BLOCKING PASS");
}

// ── the wait trap itself: a holder the guard learned of without a sweep ─────

/// How the shell waits for the planted holder (each variant names the syscall).
#[derive(Clone, Copy, Debug)]
#[allow(clippy::enum_variant_names)]
enum Wait {
    Wait4,
    Wait4NoHang,
    WaitidPid,
    WaitidPidfd,
}

/// Wait for `pid` in the given shape: its exit code, or a negative errno.
fn wait_as(how: Wait, pid: i32) -> i32 {
    match how {
        Wait::Wait4 => wait_code(pid, 0),
        Wait::Wait4NoHang => wait_code(pid, libc::WNOHANG),
        Wait::WaitidPid | Wait::WaitidPidfd => {
            let (idtype, id) = match how {
                Wait::WaitidPid => (libc::P_PID, pid as libc::id_t),
                _ => {
                    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
                    if fd < 0 {
                        return -errno();
                    }
                    (3 as libc::idtype_t, fd as libc::id_t) // P_PIDFD
                }
            };
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            loop {
                let r = unsafe { libc::waitid(idtype, id, &mut info, libc::WEXITED) };
                if r == 0 {
                    return unsafe { info.si_status() };
                }
                if errno() != libc::EINTR {
                    return -errno();
                }
            }
        }
    }
}

/// The child is planted in the guard's set as a holder (as the later-event
/// look, `guard_flow::holder`, or the orphan backstop records one: no sweep
/// made its parent a holder). Its reaper must become one at the wait.
fn planted_holder_case(how: Wait, connect_first: bool) -> Option<(String, String)> {
    let secret = Secret::new(&format!("plant-{how:?}-{connect_first}").to_lowercase());
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let tainted = cfg.tainted.clone();
    let (port, got) = tcp_listener(DEST);
    let rp = secret.file("report.txt");
    // body → test: the child's pid; test → body: planted.
    let (pid_r, pid_w) = pipe();
    let (ok_r, ok_w) = pipe();
    let planter = std::thread::spawn(move || {
        let mut b = [0u8; 4];
        let n = unsafe { libc::read(pid_r, b.as_mut_ptr() as *mut libc::c_void, 4) };
        if n == 4 {
            let pid = i32::from_ne_bytes(b);
            tainted.insert(&net_supervisor::secret_open::own_key_of(pid));
        }
        write_all(ok_w, b"k");
        unsafe {
            libc::close(pid_r);
            libc::close(ok_w);
        }
    });
    let got_code = guarded_keep(cfg, &[pid_w, ok_r], move || {
        // A connection the shell holds BEFORE it reaps (allowed: no holder yet).
        let early = if connect_first { tcp_connect(DEST, port).ok() } else { None };
        let (go_r, go_w) = pipe();
        let child = fork_run(|| {
            if let Some(fd) = early {
                unsafe { libc::close(fd) };
            }
            read_byte(go_r);
            42
        });
        write_all(pid_w, &child.to_ne_bytes());
        if !read_byte(ok_r) {
            return 3;
        }
        write_all(go_w, b"g");
        // Let the child exit before a WNOHANG wait.
        std::thread::sleep(Duration::from_millis(100));
        let status = wait_as(how, child);
        let sent = match early {
            Some(fd) => {
                let w = write_all(fd, status_msg(status).as_bytes());
                unsafe { libc::close(fd) };
                if w > 0 { "sent".to_string() } else { format!("e{}", errno()) }
            }
            None => send_to(DEST, port, status_msg(status).as_bytes()),
        };
        let _ = std::fs::write(&rp, format!("status={status} sent={sent}"));
        0
    });
    // The tree is gone: the planter's read ends even when the body never
    // wrote (a SKIP, an early failure), so its join cannot wait for good.
    unsafe { libc::close(pid_w) };
    let _ = join_within(planter, wait_limit(), "the planter thread (it waits for the body's child pid)");
    let code = got_code?;
    Some((format!("code={code:?} {}", report(&secret.file("report.txt"))), seen(&got)))
}

#[test]
#[ignore]
fn the_reaper_of_a_holder_learned_without_a_sweep_becomes_one_at_the_wait() {
    let _one = serial();
    for how in [Wait::Wait4, Wait::Wait4NoHang, Wait::WaitidPid, Wait::WaitidPidfd] {
        let Some((r, s)) = planted_holder_case(how, false) else { return };
        assert_eq!(r, format!("code=Some(0) status=42 sent=e{}", libc::EACCES), "{how:?}: the waiter must be a holder once it reaped a holder");
        assert!(!s.contains("STATUS=42"), "{how:?}: the planted holder's status reached the unbound host: {s}");
    }
    eprintln!("WAIT TRAP PASS");
}

/// A waiter that already holds a connection to an unbound host: it is
/// killed at its wait for a holder, and the status never reaches it (nor,
/// through it, the host).
#[test]
#[ignore]
fn a_reaper_holding_an_unbound_connection_never_gets_the_status() {
    let _one = serial();
    let Some((r, s)) = planted_holder_case(Wait::Wait4, true) else { return };
    assert_eq!(r, "code=None ", "the waiter must be killed at the wait (no exit code, no report)");
    assert!(!s.contains("STATUS="), "the waiter sent a status to the unbound host: {s}");
    eprintln!("WAIT KILLED PASS");
}

/// `exec 3<>/dev/udp/…; K=$(cat .env)`: the reader inherits its shell's
/// unbound socket, so its raw open is refused, as before; the reader then
/// holds nothing, so the shell that reaps it goes on (no holder, no kill).
#[test]
#[ignore]
fn a_reader_refused_its_raw_open_leaves_its_shell_alone() {
    let _one = serial();
    let secret = Secret::new("refused-reader");
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let Some(code) = guarded(cfg, move || {
        let Ok(fd) = tcp_connect(DEST, port) else { return 3 };
        // The reader keeps the socket (as `$(cat …)` inherits fd 3).
        let child = fork_run(|| reader(&path));
        let status = wait_code(child, 0);
        write_all(fd, status_msg(status).as_bytes());
        unsafe { libc::close(fd) };
        let later = send_to(DEST, port, b"LATER");
        let _ = std::fs::write(&rp, format!("status={status} later={later}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0), "the shell was not killed");
    assert_eq!(report(&secret.file("report.txt")), "status=4 later=sent", "the read refused, the shell untouched");
    let s = seen(&got);
    assert!(!s.contains(CANARY) && !s.contains(&status_msg(SECRET_BYTE)), "{s}");
    eprintln!("WAIT REFUSED READER PASS");
}

/// The same shell holding an unbound connection when a REAL child reads:
/// the child's raw open is refused (the sweep finds its parent's socket).
#[test]
#[ignore]
fn a_raw_read_is_refused_when_its_reaper_holds_an_unbound_connection() {
    let _one = serial();
    let secret = Secret::new("reaper-sock");
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let Some(code) = guarded(cfg, move || {
        let Ok(fd) = tcp_connect(DEST, port) else { return 3 };
        // The reader holds no socket of its own: only its parent does.
        let child = fork_run(|| {
            unsafe { libc::close(fd) };
            reader(&path)
        });
        let status = wait_code(child, 0);
        write_all(fd, status_msg(status).as_bytes());
        unsafe { libc::close(fd) };
        let _ = std::fs::write(&rp, format!("status={status}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report.txt")), "status=4", "the reader's raw open must be refused (its reaper holds an unbound connection)");
    let s = seen(&got);
    assert!(!s.contains(CANARY) && !s.contains(&status_msg(SECRET_BYTE)), "{s}");
    eprintln!("WAIT RAW REFUSED PASS");
}

/// `PIDFD_GET_INFO` hands a pidfd's holder the exit status (6.15): ENOTTY,
/// as a kernel without it answers.
#[test]
#[ignore]
fn pidfd_get_info_is_refused_under_a_secret_policy() {
    let _one = serial();
    let secret = Secret::new("pidfd-info");
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let rp = secret.file("report.txt");
    let Some(code) = guarded(cfg, move || {
        let child = fork_run(|| 7);
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) };
        let _ = wait_code(child, 0);
        let mut info = [0u64; 32];
        // _IOWR(0xFF, 11, struct pidfd_info) at 64 bytes.
        let req: libc::c_ulong = (3 << 30) | (64 << 16) | (0xFF << 8) | 11;
        let r = if fd >= 0 { unsafe { libc::ioctl(fd as i32, req, info.as_mut_ptr()) } } else { -2 };
        let _ = std::fs::write(&rp, format!("r={r} errno={}", if r < 0 { errno() } else { 0 }));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report.txt")), format!("r=-1 errno={}", libc::ENOTTY));
    eprintln!("PIDFD INFO PASS");
}

// ── controls: ordinary programs still reap their children ───────────────────

fn have(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `$1`: the secret's path, or empty (no holder in the tree); `$2..$4`:
/// python3, node and make present (1/0).
const SH: &str = r#"
x="$1"
if [ -n "$x" ]; then
  n=$(cat "$x" | wc -l); echo "lines=$n rc=$?"
fi
false; echo "false=$?"
(exit 7); echo "sub=$?"
sh -c 'exit 9'; echo "sh=$?"
sleep 0.2 & bg=$!; wait $bg; echo "bg=$?"
v=$(echo hi); echo "subst=$v"
if [ "$2" = 1 ]; then python3 -c '
import subprocess, os
r = subprocess.run(["sh", "-c", "exit 5"]).returncode
o = subprocess.check_output(["echo", "out"]).decode().strip()
p = subprocess.Popen(["sleep", "0.1"]); p.wait()
print("py", r, o, p.returncode)
' || echo "py-failed"; fi
if [ "$3" = 1 ]; then node -e '
const cp = require("child_process");
let r; try { cp.execSync("exit 6"); } catch (e) { r = e.status; }
const o = cp.execFileSync("echo", ["out"]).toString().trim();
cp.exec("exit 3", (e) => { console.log("node", r, o, e.code); });
' || echo "node-failed"; fi
if [ "$4" = 1 ]; then printf 'all:\n\t@sh -c "exit 0"; echo made\nbad:\n\t@exit 4\n' > "$5/Makefile"; make -s -C "$5" all; echo "make=$?"; make -s -C "$5" bad 2>/dev/null; echo "makebad=$?"; fi
exit 0
"#;

fn run_ordinary(with_holder: bool) {
    let py = have("python3");
    let node = have("node");
    let make = have("make");
    for (ok, name) in [(py, "python3"), (node, "node"), (make, "make")] {
        if !ok {
            eprintln!("SKIP: {name} is not installed (its leg)");
        }
    }
    let secret = Secret::new(if with_holder { "ordinary-held" } else { "ordinary" });
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let out = secret.file("out.txt");
    let sh = std::ffi::CString::new("/bin/sh").unwrap();
    let flag = |b: bool| if b { "1" } else { "0" };
    let x = if with_holder { secret.path.to_string_lossy().to_string() } else { String::new() };
    let d = secret.dir.to_string_lossy().to_string();
    let args: Vec<std::ffi::CString> = ["sh", "-c", SH, "sh", &x, flag(py), flag(node), flag(make), &d]
        .iter()
        .map(|a| std::ffi::CString::new(*a).unwrap())
        .collect();
    let out_c = std::ffi::CString::new(out.to_str().unwrap()).unwrap();
    let path = std::ffi::CString::new(format!("PATH={}", std::env::var("PATH").unwrap_or_default())).unwrap();
    let got = guarded(cfg, move || {
        let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
        argv.push(std::ptr::null());
        let envp = [path.as_ptr(), std::ptr::null()];
        let fd = unsafe { libc::open(out_c.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o600) };
        if fd < 0 {
            return 2;
        }
        unsafe {
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            libc::execve(sh.as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
        3
    });
    let r = std::fs::read_to_string(&out).unwrap_or_default();
    let Some(code) = got else { return };
    assert_eq!(code, Some(0), "{r}");
    if with_holder {
        assert!(r.contains("lines=1 rc=0"), "a pipeline with a holder: {r}");
    }
    for want in ["false=1", "sub=7", "sh=9", "bg=0", "subst=hi"] {
        assert!(r.contains(want), "{want} missing (holder {with_holder}):\n{r}");
    }
    if py {
        assert!(r.contains("py 5 out 0"), "Python's subprocess (holder {with_holder}):\n{r}");
    }
    if node {
        assert!(r.contains("node 6 out 3"), "Node's child_process (holder {with_holder}):\n{r}");
    }
    if make {
        assert!(r.contains("made") && r.contains("make=0") && r.contains("makebad=2"), "make (holder {with_holder}):\n{r}");
    }
}

#[test]
#[ignore]
fn shells_make_python_and_node_still_reap_their_children() {
    let _one = serial();
    run_ordinary(false);
    run_ordinary(true);
    eprintln!("WAIT ORDINARY PASS");
}
