//! object_flow_integration — a taint follows a FILE OBJECT two processes
//! share (confidentiality-plan-13 §9 R1, the file shapes; `object_flow`).
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! (an unprivileged user + network + pid namespace; `lo` is brought up
//! here). A host where the seccomp listener cannot be installed SKIPs.
//!
//! Each test is a leak oracle: a process that never read the secret itself
//! receives it through a shared object and then sends what it holds to an
//! unbound listener (127.0.0.3). The listener must never see the canary,
//! and the receiver's send is refused (EACCES) because it became a holder
//! (or the holder's write is refused, when the receiver already held an
//! unbound connection). Every shape was red on master before this change,
//! except the reopen through `/proc/<pid>/fd/N`, which the guard already
//! refused (`EXDEV`: it resolves an open in the tracee's view without
//! crossing a magic link) and which is kept here so it stays closed:
//!
//!   1. `tail -f log | curl … &`: a reader that already holds a file open
//!      when a holder appends to it; and the sink-first order (the reader
//!      already connected out refuses the holder's write-open);
//!   2. a `/dev/shm` file mapped shared (POSIX `shm_open`); a SysV segment
//!      attached after the taint, and one a holder wrote and left;
//!   3. a memfd shared with the holder's own parent (the taint-time sweep);
//!      an unlinked file a holder reopens through `/proc/<pid>/fd/N`; an
//!      `O_TMPFILE` a holder writes and links into place; a memfd passed to
//!      a holder over `SCM_RIGHTS` that it writes into; (P0 1b, 2026-10-07)
//!      a memfd a holder creates after its taint, read by a process sharing
//!      its descriptor table, and a holder's runtimes under the memfd trap;
//!      (P0 2c, pinned) an `O_TMPFILE` a non-holder holds when a holder
//!      writes it;
//!   and, item 2's company, a SysV and a POSIX message queue: a holder's
//!   send is refused.
//!
//! Controls: an untainted writer and reader sharing a file are untouched.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, readable_within, reap_within, run_tag, socketpair, wait_limit};

use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
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
    /// The guarded root plays the AGENT (`agentExe` = this test binary; the
    /// first-started process of it in the tree is the root): each process it
    /// forks stands for a tool call's shell of its own. Since 2026-10-03 the
    /// parent of a holder becomes one (plan 13 §4.9, the exit status), never
    /// the agent; with no agent named the root would carry every holder's
    /// taint below it, and every later child of it with it.
    fn root_is_the_agent(&self) {
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let p = std::fs::read_to_string(&self.policy).unwrap();
        assert!(p.contains(r#""agentExe":"""#), "{p}");
        std::fs::write(&self.policy, p.replacen(r#""agentExe":"""#, &format!(r#""agentExe":"{}""#, exe.display()), 1)).unwrap();
    }
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
    recording_arbiter_labelling(true)
}

/// `label`: whether `labelWrittenPathTainted` answers labelled (false: the
/// guard has no derived label to gate the copy with, as for an object with
/// no path, and only the object flow stands).
fn recording_arbiter_labelling(label: bool) -> (&'static MockArbiter, Told) {
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
            "labelWrittenPathTainted" => {
                let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
                t.lock().unwrap().push((op.to_string(), key, vec![path]));
                Ok(serde_json::json!({ "labeled": label, "level": "no-model", "reason": "mock" }))
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
    let code = reap(child);
    let _ = join_within(server, wait_limit(), "the guard supervisor (run_guard_supervisor), after its tracee exited");
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

fn wait_for(p: &Path) -> bool {
    for _ in 0..500 {
        if p.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn canary_in(buf: &Arc<Mutex<Vec<u8>>>) -> bool {
    String::from_utf8_lossy(&buf.lock().unwrap()).contains(CANARY)
}

fn report(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|_| "<no report>".into())
}

/// `len` bytes of the memory at `p`, as text.
fn mem_text(p: *const libc::c_void, len: usize) -> String {
    let s = unsafe { std::slice::from_raw_parts(p as *const u8, len) };
    String::from_utf8_lossy(s).trim_end_matches('\0').to_string()
}

fn eacces() -> String {
    format!("e{}", libc::EACCES)
}

// ── 1. a reader that already holds the file a holder writes ─────────────────

/// `tail -f log | curl … &`, started BEFORE any secret is read: it holds
/// `log` open for reading; a holder then appends the secret to `log`. The
/// reader reads it and sends it on. Control: an untainted writer's bytes
/// reach the same kind of reader, which sends freely.
#[test]
#[ignore]
fn a_reader_already_holding_a_file_a_holder_writes_becomes_a_holder() {
    let _one = serial();
    let secret = Secret::new("tail");
    let (arbiter, told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let (path, log, ctl_log) = (secret.path.clone(), secret.file("app.log"), secret.file("ctl.log"));
    std::fs::write(&log, "start\n").unwrap();
    std::fs::write(&ctl_log, "start\n").unwrap();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        // The long-lived reader, left running by an earlier tool call.
        let tail = |log: PathBuf, opened: PathBuf, written: PathBuf, out: PathBuf| {
            fork_run(move || {
                let Ok(mut f) = std::fs::File::open(&log) else { return 3 };
                let _ = std::fs::write(&opened, "o");
                if !wait_for(&written) {
                    return 5;
                }
                let mut data = String::new();
                let _ = f.read_to_string(&mut data);
                let _ = std::fs::write(&out, send_to(DEST, port, data.as_bytes()));
                0
            })
        };
        let t = tail(log.clone(), d.join("opened"), d.join("written"), d.join("tail.out"));
        let c = tail(ctl_log.clone(), d.join("ctl.opened"), d.join("ctl.written"), d.join("ctl.out"));
        if !wait_for(&d.join("opened")) || !wait_for(&d.join("ctl.opened")) {
            return 6;
        }
        let holder = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&log) else { return 100 + (errno() & 0x3f) };
            let _ = f.write_all(k.as_bytes());
            drop(f);
            let _ = std::fs::write(d.join("written"), "w");
            0
        });
        let writer = fork_run(|| {
            let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&ctl_log) else { return 3 };
            let _ = f.write_all(b"LIVE-CONTROL\n");
            drop(f);
            let _ = std::fs::write(d.join("ctl.written"), "w");
            0
        });
        let rs = (reap(holder), reap(writer), reap(t), reap(c));
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0), Some(0), Some(0))");
    assert_eq!(report(&secret.file("tail.out")), eacces(), "the reader that held the file must be a holder at its connect (plan 13 §9 R1)");
    assert_eq!(report(&secret.file("ctl.out")), "sent", "control: an untainted writer taints nobody");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    assert!(String::from_utf8_lossy(&got.lock().unwrap()).contains("LIVE-CONTROL"), "control bytes arrive");
    assert!(told.lock().unwrap().iter().any(|(op, _, _)| op == "recordProcessFlow"), "the flow is recorded at the arbiter: {:?}", told.lock().unwrap());
    eprintln!("R1 FILE TAIL PASS");
}

/// The sink first: the reader holds `log` AND a connection to the unbound
/// host before the holder writes. The holder's write-open is refused, so no
/// byte reaches the file.
#[test]
#[ignore]
fn a_reader_already_connected_out_refuses_the_holders_write_open() {
    let _one = serial();
    let secret = Secret::new("tailnc");
    secret.root_is_the_agent();
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let (path, log) = (secret.path.clone(), secret.file("app.log"));
    std::fs::write(&log, "start\n").unwrap();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        let t = fork_run(|| {
            let Ok(sock) = tcp_connect(DEST, port) else { return 3 };
            let Ok(mut f) = std::fs::File::open(&log) else { return 3 };
            let _ = std::fs::write(d.join("opened"), "o");
            if !wait_for(&d.join("written")) {
                return 5;
            }
            let mut data = String::new();
            let _ = f.read_to_string(&mut data);
            unsafe { libc::write(sock, data.as_ptr() as *const libc::c_void, data.len()) };
            unsafe { libc::close(sock) };
            0
        });
        if !wait_for(&d.join("opened")) {
            return 6;
        }
        let holder = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            let r = match std::fs::OpenOptions::new().append(true).open(&log) {
                Ok(mut f) => {
                    let _ = f.write_all(k.as_bytes());
                    "opened".to_string()
                }
                Err(e) => format!("e{}", e.raw_os_error().unwrap_or(-1)),
            };
            let _ = std::fs::write(d.join("holder.out"), r);
            let _ = std::fs::write(d.join("written"), "w");
            0
        });
        let rs = (reap(holder), reap(t));
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    assert_eq!(report(&secret.file("holder.out")), eacces(), "the holder's write-open must be refused: a reader of the file holds an unbound connection");
    assert!(!read_file(&secret.file("app.log")).unwrap().contains(CANARY), "no byte of the secret reached the file");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    eprintln!("R1 FILE SINK-FIRST PASS");
}

/// A file the holder created a moment ago (born less than `FRESH` ago, so
/// the guard looks only at the processes listed as having opened it) that
/// another process opened in between: no label gates it (this arbiter
/// labels nothing), so only the object flow stands. The reader opened it
/// after its birth, so it is listed, and the holder's next write-open finds
/// it.
#[test]
#[ignore]
fn a_reader_of_a_file_a_holder_just_created_is_a_holder() {
    let _one = serial();
    let secret = Secret::new("fresh");
    let (arbiter, _told) = recording_arbiter_labelling(false);
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let (path, fresh) = (secret.path.clone(), secret.file("fresh.txt"));
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            // Created empty, by the holder.
            let Ok(f) = std::fs::OpenOptions::new().create_new(true).write(true).open(&fresh) else { return 3 };
            drop(f);
            if !wait_for(&d.join("opened")) {
                return 5;
            }
            let out = match std::fs::OpenOptions::new().append(true).open(&fresh) {
                Ok(mut f) => {
                    let _ = f.write_all(k.as_bytes());
                    "wrote".to_string()
                }
                Err(e) => format!("e{}", e.raw_os_error().unwrap_or(-1)),
            };
            let _ = std::fs::write(d.join("h.out"), out);
            let _ = std::fs::write(d.join("written"), "w");
            0
        });
        let r = fork_run(|| {
            let f = loop {
                if let Ok(f) = std::fs::File::open(&fresh) {
                    break f;
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            let _ = std::fs::write(d.join("opened"), "o");
            if !wait_for(&d.join("written")) {
                return 5;
            }
            let mut data = String::new();
            let _ = (&f).read_to_string(&mut data);
            let _ = std::fs::write(d.join("r.out"), send_to(DEST, port, data.as_bytes()));
            0
        });
        let rs = (reap(h), reap(r));
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let (h, r) = (report(&secret.file("h.out")), report(&secret.file("r.out")));
    eprintln!("holder: {h}; reader: {r}");
    assert_eq!(h, "wrote");
    assert_eq!(r, eacces(), "the reader of the holder's fresh file must be a holder");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    eprintln!("R1 FRESH FILE PASS");
}

// ── 2. shared memory ────────────────────────────────────────────────────────

/// POSIX shared memory: the reader maps a `/dev/shm` object shared and
/// closes its descriptor (the mapping alone remains); a holder opens the
/// same object and writes the secret into its own mapping.
#[test]
#[ignore]
fn a_dev_shm_mapping_shared_with_a_reader_carries_the_taint() {
    let _one = serial();
    let secret = Secret::new("shm");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let name = std::ffi::CString::new(format!("/mandu-obj-shm-{}", run_tag())).unwrap();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        let r = fork_run(|| {
            let fd = unsafe { libc::shm_open(name.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600) };
            if fd < 0 {
                return 77;
            }
            unsafe { libc::ftruncate(fd, 4096) };
            let p = unsafe { libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ, libc::MAP_SHARED, fd, 0) };
            unsafe { libc::close(fd) };
            if p == libc::MAP_FAILED {
                return 3;
            }
            let _ = std::fs::write(d.join("ready"), "r");
            if !wait_for(&d.join("written")) {
                return 5;
            }
            let data = mem_text(p, 4096);
            let _ = std::fs::write(d.join("r.out"), send_to(DEST, port, data.as_bytes()));
            0
        });
        if !wait_for(&d.join("ready")) {
            return reap(r).unwrap_or(6);
        }
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            let fd = unsafe { libc::shm_open(name.as_ptr(), libc::O_RDWR, 0) };
            if fd < 0 {
                let _ = std::fs::write(d.join("h.out"), format!("e{}", errno()));
                let _ = std::fs::write(d.join("written"), "w");
                return 0;
            }
            let p = unsafe { libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0) };
            unsafe { libc::close(fd) };
            if p == libc::MAP_FAILED {
                return 3;
            }
            unsafe { std::ptr::copy_nonoverlapping(k.as_ptr(), p as *mut u8, k.len()) };
            let _ = std::fs::write(d.join("h.out"), "wrote");
            let _ = std::fs::write(d.join("written"), "w");
            0
        });
        let rs = (reap(h), reap(r));
        unsafe { libc::shm_unlink(name.as_ptr()) };
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        return;
    };
    if report(&secret.file("report")).contains("Some(77)") || code == Some(77) {
        eprintln!("SKIP: no /dev/shm here");
        return;
    }
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let (h, r) = (report(&secret.file("h.out")), report(&secret.file("r.out")));
    eprintln!("holder: {h}; reader: {r}");
    assert!(r == eacces() || h == eacces(), "the reader must be a holder (or the holder's open refused): h={h} r={r}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    eprintln!("R1 DEV-SHM PASS");
}

/// A SysV segment the reader attached before the holder attaches it AFTER
/// its taint and writes into it.
#[test]
#[ignore]
fn a_sysv_segment_attached_after_the_taint_carries_the_taint() {
    let _one = serial();
    let secret = Secret::new("sysv");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        let id = unsafe { libc::shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | 0o600) };
        if id < 0 {
            return 77;
        }
        let r = fork_run(|| {
            let p = unsafe { libc::shmat(id, std::ptr::null(), libc::SHM_RDONLY) };
            if p as isize == -1 {
                return 3;
            }
            let _ = std::fs::write(d.join("ready"), "r");
            if !wait_for(&d.join("written")) {
                return 5;
            }
            let data = mem_text(p, 4096);
            let _ = std::fs::write(d.join("r.out"), send_to(DEST, port, data.as_bytes()));
            0
        });
        if !wait_for(&d.join("ready")) {
            return reap(r).unwrap_or(6);
        }
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            let p = unsafe { libc::shmat(id, std::ptr::null(), 0) };
            let out = if p as isize == -1 {
                format!("e{}", errno())
            } else {
                unsafe { std::ptr::copy_nonoverlapping(k.as_ptr(), p as *mut u8, k.len()) };
                "wrote".into()
            };
            let _ = std::fs::write(d.join("h.out"), out);
            let _ = std::fs::write(d.join("written"), "w");
            0
        });
        let rs = (reap(h), reap(r));
        unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        return;
    };
    if code == Some(77) {
        eprintln!("SKIP: no SysV shared memory here");
        return;
    }
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let (h, r) = (report(&secret.file("h.out")), report(&secret.file("r.out")));
    eprintln!("holder: {h}; reader: {r}");
    assert!(r == eacces() || h == eacces(), "the reader must be a holder (or the holder's attach refused): h={h} r={r}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    eprintln!("R1 SYSV LATER PASS");
}

/// A holder writes a SysV segment and leaves (detached, exited); a process
/// attaching it afterwards reads what it left.
#[test]
#[ignore]
fn a_sysv_segment_a_holder_left_taints_a_later_attach() {
    let _one = serial();
    let secret = Secret::new("sysvleft");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        let id = unsafe { libc::shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | 0o600) };
        if id < 0 {
            return 77;
        }
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            let p = unsafe { libc::shmat(id, std::ptr::null(), 0) };
            if p as isize == -1 {
                let _ = std::fs::write(d.join("h.out"), format!("e{}", errno()));
                return 0;
            }
            unsafe { std::ptr::copy_nonoverlapping(k.as_ptr(), p as *mut u8, k.len()) };
            unsafe { libc::shmdt(p) };
            let _ = std::fs::write(d.join("h.out"), "wrote");
            0
        });
        let hc = reap(h);
        // The holder is gone; a later process attaches, reads, detaches.
        let r = fork_run(|| {
            let p = unsafe { libc::shmat(id, std::ptr::null(), libc::SHM_RDONLY) };
            if p as isize == -1 {
                let _ = std::fs::write(d.join("r.out"), format!("attach e{}", errno()));
                return 0;
            }
            let data = mem_text(p, 4096);
            unsafe { libc::shmdt(p) };
            let _ = std::fs::write(d.join("r.out"), send_to(DEST, port, data.as_bytes()));
            0
        });
        let rc = reap(r);
        unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
        let _ = std::fs::write(d.join("report"), format!("{:?}", (hc, rc)));
        0
    }) else {
        return;
    };
    if code == Some(77) {
        eprintln!("SKIP: no SysV shared memory here");
        return;
    }
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let r = report(&secret.file("r.out"));
    assert!(r == eacces() || r.starts_with("attach e"), "the later attach must make the reader a holder (or be refused): {r} (holder: {})", report(&secret.file("h.out")));
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    eprintln!("R1 SYSV LEFT PASS");
}

// ── 3. objects with no path ─────────────────────────────────────────────────

/// A memfd the parent made and kept: its child reads the secret raw and
/// writes it into the memfd; the parent (no descendant of the holder) reads
/// it back. Found by the taint-time sweep.
#[test]
#[ignore]
fn a_memfd_shared_with_the_holders_parent_carries_the_taint() {
    let _one = serial();
    let secret = Secret::new("memfd");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        let p = fork_run(|| {
            let name = std::ffi::CString::new("mandu-drop").unwrap();
            let m = unsafe { libc::memfd_create(name.as_ptr(), 0) };
            if m < 0 {
                return 3;
            }
            let h = fork_run(|| {
                let Ok(k) = read_file(&path) else { return 4 };
                unsafe { libc::pwrite(m, k.as_ptr() as *const libc::c_void, k.len(), 0) };
                0
            });
            if reap(h) != Some(0) {
                return 4;
            }
            let mut buf = [0u8; 256];
            let n = unsafe { libc::pread(m, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            let data = &buf[..n.max(0) as usize];
            let _ = std::fs::write(d.join("p.out"), send_to(DEST, port, data));
            0
        });
        reap(p).unwrap_or(9)
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("p.out")), eacces(), "the holder's parent reads the memfd it wrote: a holder at its connect");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    eprintln!("R1 MEMFD PASS");
}

/// A child that SHARES the caller's descriptor table (`clone(CLONE_FILES)`,
/// no exec): whatever either opens, the other holds.
fn clone_files(f: impl FnOnce() -> i32) -> i32 {
    // SAFETY: a raw clone with no new stack is a fork whose child shares the
    // descriptor table; the child only runs `f` and exits.
    let pid = unsafe { libc::syscall(libc::SYS_clone, (libc::CLONE_FILES | libc::SIGCHLD) as libc::c_ulong, 0usize, 0usize, 0usize, 0usize) } as i32;
    assert!(pid >= 0, "clone(CLONE_FILES): errno {}", errno());
    if pid == 0 {
        let c = f();
        unsafe { libc::_exit(c) };
    }
    pid
}

/// P0 triage 1b: a memfd a holder creates AFTER its taint. `memfd_create`
/// is trapped under a secret policy and performed by the guard for a
/// holder, which marks the new object's key before the descriptor is
/// handed over (as a holder's write-open marks a file). A process that
/// shares the holder's descriptor table but is neither its parent (a
/// holder's parent receives its exit status, so it is made a holder at the
/// taint) nor its descendant: two children of the agent made with
/// `clone(CLONE_FILES)`, so the memfd lands in the other's table too. It
/// reads the memfd and sends what it holds on: by the mark it is a holder at
/// its connect. No file passes between the two (a file a holder writes is
/// labelled, and its reader a holder by that); the memfd's descriptor
/// number appearing in the shared table is the signal. Red before the trap:
/// no event named the memfd, so its reader was nobody's holder. Control: an
/// untainted process's memfd taints nobody. The holder's memfd also works
/// as one: its flags (`MFD_CLOEXEC`, `MFD_ALLOW_SEALING`) and its name hold.
#[test]
#[ignore]
fn a_memfd_a_holder_creates_after_its_taint_carries_the_taint() {
    let _one = serial();
    let secret = Secret::new("memfdlate");
    secret.root_is_the_agent();
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        // The agent keeps no channel the two children would share but the
        // memfd (the guard's socket would join them as a link a holder holds).
        close_all_but(&[]);
        // Standard input may be a socket or a pipe the harness reads from:
        // the null device instead.
        let null = std::ffi::CString::new("/dev/null").unwrap();
        let n = unsafe { libc::open(null.as_ptr(), libc::O_RDONLY) };
        unsafe { libc::dup2(n, 0) };
        unsafe { libc::close(n) };
        let fd_open = |fd: RawFd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
        let wait_fd = |fd: RawFd| {
            for _ in 0..1000 {
                if fd_open(fd) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            false
        };
        let round = |taint: bool, at: RawFd, out: &str| {
            let p = clone_files(|| {
                let k = if taint {
                    let Ok(k) = read_file(&path) else { return 4 };
                    k
                } else {
                    "LIVE-CONTROL\n".to_string()
                };
                let name = std::ffi::CString::new("mandu-late").unwrap();
                let m = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
                if m < 0 {
                    let _ = std::fs::write(d.join(format!("{out}.facts")), format!("memfd_create e{}", errno()));
                    return 3;
                }
                let wrote = unsafe { libc::pwrite(m, k.as_ptr() as *const libc::c_void, k.len(), 0) };
                let cloexec = unsafe { libc::fcntl(m, libc::F_GETFD) } & libc::FD_CLOEXEC != 0;
                let sealed = unsafe { libc::fcntl(m, libc::F_ADD_SEALS, libc::F_SEAL_GROW) } == 0;
                let link = std::fs::read_link(format!("/proc/self/fd/{m}")).map(|p| p.display().to_string()).unwrap_or_default();
                let _ = std::fs::write(d.join(format!("{out}.facts")), format!("wrote={} cloexec={cloexec} sealed={sealed} link={link}", wrote == k.len() as isize));
                unsafe { libc::dup3(m, at, libc::O_CLOEXEC) };
                unsafe { libc::close(m) };
                // Alive until the reader is done (it leaves `at + 1`).
                if wait_fd(at + 1) {
                    0
                } else {
                    5
                }
            });
            let q = clone_files(|| {
                let result = if wait_fd(at) {
                    let mut buf = [0u8; 256];
                    let n = unsafe { libc::pread(at, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
                    send_to(DEST, port, &buf[..n.max(0) as usize])
                } else {
                    "no memfd".to_string()
                };
                let _ = std::fs::write(d.join(out), result);
                unsafe { libc::dup3(at, at + 1, libc::O_CLOEXEC) };
                0
            });
            let qc = reap(q);
            if qc != Some(0) {
                // P must not wait forever on a reader that died.
                unsafe { libc::dup3(at, at + 1, libc::O_CLOEXEC) };
            }
            (reap(p), qc)
        };
        let c = round(false, 100, "ctl.out");
        // The control's memfd leaves the table: a writable object the
        // holder holds at its taint would make every sharer of the table a
        // holder at once (the taint-time sweep), memfd or not.
        unsafe { libc::close(100) };
        unsafe { libc::close(101) };
        let r = round(true, 110, "q.out");
        let _ = std::fs::write(d.join("report"), format!("{c:?} {r:?}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0)) (Some(0), Some(0))");
    for out in ["ctl.out", "q.out"] {
        let facts = report(&secret.file(&format!("{out}.facts")));
        assert!(facts.starts_with("wrote=true cloexec=true sealed=true link=/memfd:mandu-late"), "{out}: the memfd is the one asked for: {facts}");
    }
    assert_eq!(report(&secret.file("ctl.out")), "sent", "control: an untainted process's memfd taints nobody");
    assert_eq!(report(&secret.file("q.out")), eacces(), "the sharer of the holder's descriptor table reads the memfd it wrote: a holder at its connect");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    assert!(String::from_utf8_lossy(&got.lock().unwrap()).contains("LIVE-CONTROL"), "control bytes arrive");
    eprintln!("1b LATE MEMFD PASS");
}

/// P0 triage 1b: the memfd trap does not break a holder's runtimes. A
/// holder runs node (V8, whose JIT may use memfds) and python3, which
/// creates a memfd through the guard's performed call and reads back what it
/// wrote.
#[test]
#[ignore]
fn a_holders_runtimes_run_under_the_memfd_trap() {
    let _one = serial();
    let secret = Secret::new("memfdrt");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let find = |name: &str| std::env::var("PATH").unwrap_or_default().split(':').map(|p| Path::new(p).join(name)).find(|p| p.is_file());
    let (Some(node), Some(python)) = (find("node"), find("python3")) else {
        panic!("node and python3 are on every kernel lane's PATH");
    };
    let Some(code) = guarded(cfg, move || {
        let h = fork_run(|| {
            let Ok(_k) = read_file(&path) else { return 4 };
            let run = |prog: &Path, args: &[&str]| -> String {
                match std::process::Command::new(prog).args(args).stdin(std::process::Stdio::null()).output() {
                    Ok(o) => format!("{} {}", o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).trim()),
                    Err(e) => format!("spawn {e}"),
                }
            };
            let n = run(&node, &["-e", "const a = []; for (let i = 0; i < 200000; i++) a.push(i * 2); process.stdout.write(String(a.length))"]);
            let p = run(&python, &["-c", "import os; f = os.memfd_create('jit', os.MFD_CLOEXEC); os.write(f, b'ok'); os.lseek(f, 0, 0); print(os.read(f, 2).decode())"]);
            let _ = std::fs::write(d.join("h.out"), format!("node={n} python={p}"));
            0
        });
        reap(h).unwrap_or(9)
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("h.out")), "node=0 200000 python=0 ok", "a holder's node and python3 run, python's memfd through the guard");
    eprintln!("1b RUNTIMES PASS");
}

/// P0 triage 2c (pinned): an `O_TMPFILE` a non-holder already holds when a
/// holder writes it. The non-holder opens it read-write and forks; its child
/// reads the secret raw (the taint sweep lists the object as one the child
/// can write) and writes the secret into it; the parent reads it and sends
/// it on: a holder at its connect. Control: no taint, the send goes.
#[test]
#[ignore]
fn an_o_tmpfile_a_non_holder_holds_when_a_holder_writes_it_carries_the_taint() {
    let _one = serial();
    let secret = Secret::new("tmpheld");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        let run = |taint: bool, out: &'static str| {
            let (path, d) = (path.clone(), d.clone());
            fork_run(move || {
                let dir = std::ffi::CString::new(d.to_str().unwrap()).unwrap();
                let t = unsafe { libc::open(dir.as_ptr(), libc::O_TMPFILE | libc::O_RDWR, 0o600) };
                if t < 0 {
                    let _ = std::fs::write(d.join(out), format!("tmpfile e{}", errno()));
                    return 0;
                }
                let h = fork_run(|| {
                    let k = if taint {
                        let Ok(k) = read_file(&path) else { return 4 };
                        k
                    } else {
                        "LIVE-CONTROL\n".to_string()
                    };
                    unsafe { libc::pwrite(t, k.as_ptr() as *const libc::c_void, k.len(), 0) };
                    0
                });
                if reap(h) != Some(0) {
                    return 4;
                }
                let mut buf = [0u8; 256];
                let n = unsafe { libc::pread(t, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
                let _ = std::fs::write(d.join(out), send_to(DEST, port, &buf[..n.max(0) as usize]));
                0
            })
        };
        let c = run(false, "ctl.out");
        let cc = reap(c);
        let r = run(true, "r.out");
        let rc = reap(r);
        let _ = std::fs::write(d.join("report"), format!("{:?}", (cc, rc)));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = report(&secret.file("r.out"));
    if r.starts_with("tmpfile e") {
        eprintln!("SKIP: no O_TMPFILE on this filesystem ({r})");
        return;
    }
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    assert_eq!(report(&secret.file("ctl.out")), "sent", "control: an untainted writer taints nobody");
    assert_eq!(r, eacces(), "the O_TMPFILE's other holder reads what the holder wrote: a holder at its connect");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    assert!(String::from_utf8_lossy(&got.lock().unwrap()).contains("LIVE-CONTROL"), "control bytes arrive");
    eprintln!("2c O_TMPFILE HELD PASS");
}

/// An unlinked file an untainted process keeps open; a holder reopens it
/// through `/proc/<pid>/fd/N` and writes the secret into it.
#[test]
#[ignore]
fn an_unlinked_file_a_holder_reopens_through_proc_carries_the_taint() {
    let _one = serial();
    let secret = Secret::new("unlinked");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        let r = fork_run(|| {
            let scratch = d.join("scratch");
            let Ok(f) = std::fs::OpenOptions::new().create(true).read(true).write(true).truncate(true).open(&scratch) else { return 3 };
            let _ = std::fs::remove_file(&scratch);
            // Written whole, then renamed into place: `wait_for` sees the
            // name only once its content is there (a plain write creates the
            // file first, and the holder could read it empty).
            let _ = std::fs::write(d.join("ready.tmp"), format!("{} {}", unsafe { libc::getpid() }, f.as_raw_fd()));
            let _ = std::fs::rename(d.join("ready.tmp"), d.join("ready"));
            if !wait_for(&d.join("written")) {
                return 5;
            }
            let mut buf = [0u8; 256];
            let n = unsafe { libc::pread(f.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            let _ = std::fs::write(d.join("r.out"), send_to(DEST, port, &buf[..n.max(0) as usize]));
            0
        });
        if !wait_for(&d.join("ready")) {
            return reap(r).unwrap_or(6);
        }
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            let ready = report(&d.join("ready"));
            let (pid, fd) = ready.split_once(' ').unwrap();
            let out = match std::fs::OpenOptions::new().write(true).open(format!("/proc/{pid}/fd/{fd}")) {
                Ok(mut f) => {
                    let _ = f.write_all(k.as_bytes());
                    "wrote".to_string()
                }
                Err(e) => format!("e{}", e.raw_os_error().unwrap_or(-1)),
            };
            let _ = std::fs::write(d.join("h.out"), out);
            let _ = std::fs::write(d.join("written"), "w");
            0
        });
        let rs = (reap(h), reap(r));
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let (h, r) = (report(&secret.file("h.out")), report(&secret.file("r.out")));
    eprintln!("holder: {h}; reader: {r}");
    assert!(r == eacces() || h.starts_with('e'), "the unlinked file's reader must be a holder (or the reopen refused): h={h} r={r}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    eprintln!("R1 UNLINKED PASS");
}

/// An `O_TMPFILE` a holder writes and then links into place: a process that
/// opens the new name afterwards (a sibling, not the holder's descendant)
/// reads it and sends it on.
#[test]
#[ignore]
fn an_o_tmpfile_a_holder_links_into_place_taints_its_opener() {
    let _one = serial();
    let secret = Secret::new("tmpfile");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let named = secret.file("published.txt");
    let Some(code) = guarded(cfg, move || {
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            let dir = std::ffi::CString::new(d.to_str().unwrap()).unwrap();
            let fd = unsafe { libc::open(dir.as_ptr(), libc::O_TMPFILE | libc::O_RDWR, 0o600) };
            if fd < 0 {
                let _ = std::fs::write(d.join("h.out"), format!("tmpfile e{}", errno()));
                return 0;
            }
            unsafe { libc::write(fd, k.as_ptr() as *const libc::c_void, k.len()) };
            let from = std::ffi::CString::new(format!("/proc/self/fd/{fd}")).unwrap();
            let to = std::ffi::CString::new(named.to_str().unwrap()).unwrap();
            let rc = unsafe { libc::linkat(libc::AT_FDCWD, from.as_ptr(), libc::AT_FDCWD, to.as_ptr(), libc::AT_SYMLINK_FOLLOW) };
            let _ = std::fs::write(d.join("h.out"), if rc == 0 { "linked".to_string() } else { format!("link e{}", errno()) });
            0
        });
        let hc = reap(h);
        let r = fork_run(|| {
            let out = match read_file(&named) {
                Ok(data) => send_to(DEST, port, data.as_bytes()),
                Err(e) => format!("open e{e}"),
            };
            let _ = std::fs::write(d.join("r.out"), out);
            0
        });
        let rc = reap(r);
        let _ = std::fs::write(d.join("report"), format!("{:?}", (hc, rc)));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let h = report(&secret.file("h.out"));
    if h.starts_with("tmpfile e") {
        eprintln!("SKIP: no O_TMPFILE on this filesystem ({h})");
        return;
    }
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let r = report(&secret.file("r.out"));
    assert!(r == eacces() || r.starts_with("open e") || h.starts_with("link e"), "the opener of the linked copy must be a holder (or refused): h={h} r={r}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    eprintln!("R1 O_TMPFILE PASS");
}

// ── a file passed over SCM_RIGHTS ───────────────────────────────────────────

/// `sendmsg` of `fd` over the unconnected Unix socket `via` to the path `to`.
fn pass_fd_to(via: RawFd, to: &Path, fd: RawFd) -> i32 {
    use std::os::unix::ffi::OsStrExt;
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as u16;
    let bytes = to.as_os_str().as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        sa.sun_path[i] = *b as libc::c_char;
    }
    let mut cbuf = [0u64; 4];
    let mut iov = libc::iovec { iov_base: b"F".as_ptr() as *mut libc::c_void, iov_len: 1 };
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_name = &mut sa as *mut _ as *mut libc::c_void;
    m.msg_namelen = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as u32;
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    m.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    m.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&m);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::copy_nonoverlapping(&fd as *const i32 as *const u8, libc::CMSG_DATA(c), 4);
    }
    if unsafe { libc::sendmsg(via, &m, 0) } < 0 {
        errno()
    } else {
        0
    }
}

/// `recvmsg` of one descriptor over `via` (bounded); -1 none.
fn recv_fd(via: RawFd) -> RawFd {
    let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
    unsafe { libc::setsockopt(via, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of_val(&tv) as u32) };
    let mut buf = [0u8; 8];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: 8 };
    let mut cbuf = [0u64; 8];
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    m.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    m.msg_controllen = std::mem::size_of_val(&cbuf) as _;
    if unsafe { libc::recvmsg(via, &mut m, 0) } <= 0 {
        return -1;
    }
    let mut fd = -1;
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&m);
        if !c.is_null() && (*c).cmsg_type == libc::SCM_RIGHTS {
            std::ptr::copy_nonoverlapping(libc::CMSG_DATA(c), &mut fd as *mut i32 as *mut u8, 4);
        }
    }
    fd
}

/// An untainted process hands a holder a memfd it keeps (over a one-way
/// datagram the holder bound after its taint, so no channel taints the
/// sender by itself); the holder writes the secret into it; the sender
/// reads it back.
#[test]
#[ignore]
fn a_writable_file_passed_to_a_holder_carries_its_writes_back() {
    let _one = serial();
    let secret = Secret::new("passfile");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let sock = secret.file("h.sock");
    let Some(code) = guarded(cfg, move || {
        let h = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            let l = match std::os::unix::net::UnixDatagram::bind(&sock) {
                Ok(l) => l,
                Err(_) => return 3,
            };
            let _ = std::fs::write(d.join("ready"), "r");
            let fd = recv_fd(l.as_raw_fd());
            let out = if fd < 0 {
                "none".to_string()
            } else {
                unsafe { libc::pwrite(fd, k.as_ptr() as *const libc::c_void, k.len(), 0) };
                "wrote".into()
            };
            let _ = std::fs::write(d.join("h.out"), out);
            let _ = std::fs::write(d.join("written"), "w");
            0
        });
        if !wait_for(&d.join("ready")) {
            return reap(h).unwrap_or(6);
        }
        let s = fork_run(|| {
            let name = std::ffi::CString::new("mandu-pass").unwrap();
            let m = unsafe { libc::memfd_create(name.as_ptr(), 0) };
            let via = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            let sent = pass_fd_to(via, &sock, m);
            if sent != 0 {
                let _ = std::fs::write(d.join("s.out"), format!("pass e{sent}"));
                return 0;
            }
            if !wait_for(&d.join("written")) {
                return 5;
            }
            let mut buf = [0u8; 256];
            let n = unsafe { libc::pread(m, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            let _ = std::fs::write(d.join("s.out"), send_to(DEST, port, &buf[..n.max(0) as usize]));
            0
        });
        let rs = (reap(h), reap(s));
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let (h, s) = (report(&secret.file("h.out")), report(&secret.file("s.out")));
    assert!(s == eacces() || s.starts_with("pass e"), "the sender that keeps the passed file must be a holder (or the pass refused): h={h} s={s}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!canary_in(&got), "THE LEAK: the unbound listener received the secret");
    eprintln!("R1 FILE PASS PASS");
}

// ── message queues ──────────────────────────────────────────────────────────

/// A holder's send on a SysV and on a POSIX message queue is refused; an
/// untainted process's goes through (control).
#[test]
#[ignore]
fn a_holders_message_queue_send_is_refused() {
    let _one = serial();
    let secret = Secret::new("mq");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let qname = std::ffi::CString::new(format!("/mandu-obj-mq-{}", run_tag())).unwrap();
    let Some(code) = guarded(cfg, move || {
        #[repr(C)]
        struct Msg {
            mtype: libc::c_long,
            text: [u8; 64],
        }
        let try_send = |tag: &str| -> String {
            let id = unsafe { libc::msgget(libc::IPC_PRIVATE, libc::IPC_CREAT | 0o600) };
            let sysv = if id < 0 {
                "none".to_string()
            } else {
                let mut m = Msg { mtype: 1, text: [0; 64] };
                m.text[..CANARY.len()].copy_from_slice(CANARY.as_bytes());
                let rc = unsafe { libc::msgsnd(id, &m as *const Msg as *const libc::c_void, 64, libc::IPC_NOWAIT) };
                let r = if rc == 0 { "sent".to_string() } else { format!("e{}", errno()) };
                unsafe { libc::msgctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
                r
            };
            let q = unsafe { libc::mq_open(qname.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600 as libc::mode_t, std::ptr::null::<libc::mq_attr>()) };
            let posix = if q < 0 {
                "none".to_string()
            } else {
                let rc = unsafe { libc::mq_send(q, CANARY.as_ptr() as *const libc::c_char, CANARY.len(), 0) };
                let r = if rc == 0 { "sent".to_string() } else { format!("e{}", errno()) };
                unsafe { libc::mq_close(q) };
                unsafe { libc::mq_unlink(qname.as_ptr()) };
                r
            };
            format!("{tag}: sysv={sysv} posix={posix}")
        };
        let ctl = fork_run(|| {
            let _ = std::fs::write(d.join("ctl.out"), try_send("control"));
            0
        });
        let cc = reap(ctl);
        let h = fork_run(|| {
            let Ok(_k) = read_file(&path) else { return 4 };
            let _ = std::fs::write(d.join("h.out"), try_send("holder"));
            0
        });
        let hc = reap(h);
        let _ = std::fs::write(d.join("report"), format!("{:?}", (cc, hc)));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let ctl = report(&secret.file("ctl.out"));
    let h = report(&secret.file("h.out"));
    eprintln!("{ctl} / {h}");
    if ctl.contains("sysv=sent") {
        assert!(h.contains(&format!("sysv=e{}", libc::EACCES)), "a holder's msgsnd must be refused: {h}");
    }
    if ctl.contains("posix=sent") {
        assert!(h.contains(&format!("posix=e{}", libc::EACCES)), "a holder's mq_send must be refused: {h}");
    }
    assert!(ctl.contains("sent"), "control: at least one queue works here: {ctl}");
    eprintln!("MESSAGE QUEUES PASS");
}

#[repr(C)]
struct QMsg {
    mtype: libc::c_long,
    text: [u8; 64],
}

/// The first field of a thread's `/proc/self/task/<tid>/syscall` (the
/// syscall number it is inside, `running`, or `-1`), from a descriptor of
/// that file opened beforehand (a `pread` at 0 renders it again): no open,
/// so nothing the guard traps while it judges another thread's open.
fn task_syscall_fd(fd: RawFd) -> Option<String> {
    let mut buf = [0u8; 256];
    let n = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n <= 0 {
        return None;
    }
    String::from_utf8_lossy(&buf[..n as usize]).split_whitespace().next().map(String::from)
}

/// P0 1c (2026-10-07), deterministic: a queue send the guard lets go
/// (CONTINUE) is copied by the kernel after the answer, so a taint of its
/// process must wait until the sending thread is out of the call. Thread S
/// blocks inside `msgsnd` on a full queue (its own message type, 2); once
/// the guard holds S's send (`QueueSends::holds`, read by a thread of this
/// test process, which runs the guard, and told to the tree as `s.held`),
/// the main thread reads the secret raw. Before: the raw open returned at
/// once, S still inside its send (a buffer it had not copied yet could take
/// the secret). Now: the open returns only after S's send is done, which
/// the main thread checks in the queue itself as the open returns: S's
/// message is there. A drainer frees one slot once the main thread is
/// inside that open (its `openat`) and a margin after (so a guard that does
/// not wait returns first, and the check is red: so it was, 8 of 8, on the
/// guard before the fix). No sleep orders S's send before the open, and no
/// clock is compared across threads: the first version slept 300 ms for
/// "S is inside its send" and compared S's own clock, read after its
/// `msgsnd` returned, with the open's, which a preempted S reads after the
/// open returned (red 8 of 8 with S held 50 ms there; the guard was right).
#[test]
#[ignore]
#[allow(clippy::nonminimal_bool)] // the drain's wait reads "until past, or opening at openat"
fn a_raw_open_waits_for_a_queue_send_another_thread_has_in_flight() {
    let _one = serial();
    let secret = Secret::new("mq-race");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    // The guard's side: once S's tid is known (`s.tid`), `s.held` when the
    // guard holds its send; `s.done` ends the look.
    let held_watch = {
        let (sends, d) = (cfg.queue_sends.clone(), d.clone());
        std::thread::spawn(move || {
            let end = std::time::Instant::now() + Duration::from_secs(60);
            while std::time::Instant::now() < end && !d.join("s.done").exists() {
                let tid = std::fs::read_to_string(d.join("s.tid")).ok().and_then(|s| s.trim().parse::<i32>().ok());
                if tid.is_some_and(|t| sends.holds(t)) {
                    let _ = std::fs::write(d.join("s.held"), "");
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    };
    let Some(code) = guarded(cfg, move || {
        let p = fork_run(|| {
            use std::sync::atomic::{AtomicBool, AtomicI32, Ordering::SeqCst};
            let id = unsafe { libc::msgget(libc::IPC_PRIVATE, libc::IPC_CREAT | 0o600) };
            if id < 0 {
                let _ = std::fs::write(d.join("p.out"), "skip=no SysV queue");
                return 0;
            }
            // Fill the queue (IPC_NOWAIT until EAGAIN).
            let m = QMsg { mtype: 1, text: [b'x'; 64] };
            let mut n = 0;
            while unsafe { libc::msgsnd(id, &m as *const QMsg as *const libc::c_void, 64, libc::IPC_NOWAIT) } == 0 {
                n += 1;
                if n > 100_000 {
                    break;
                }
            }
            let t0 = std::time::Instant::now();
            // S: a blocking send of type 2, inside msgsnd until the drainer
            // frees room.
            let (tx, rx) = std::sync::mpsc::channel();
            let s = std::thread::spawn(move || {
                let _ = tx.send(unsafe { libc::gettid() });
                let m = QMsg { mtype: 2, text: [b'y'; 64] };
                let rc = unsafe { libc::msgsnd(id, &m as *const QMsg as *const libc::c_void, 64, 0) };
                (rc, t0.elapsed())
            });
            let s_tid: i32 = rx.recv().unwrap();
            // Written whole, then renamed into place (never read half-written).
            let _ = std::fs::write(d.join("s.tid.tmp"), s_tid.to_string());
            let _ = std::fs::rename(d.join("s.tid.tmp"), d.join("s.tid"));
            let end = std::time::Instant::now() + Duration::from_secs(20);
            while !d.join("s.held").exists() && std::time::Instant::now() < end {
                std::thread::sleep(Duration::from_millis(1));
            }
            let blocked = d.join("s.held").exists();
            // The drainer: one slot freed once the main thread is inside the
            // raw open below (or is past it), and 300 ms after.
            let main_tid = unsafe { libc::gettid() };
            let main_syscall = std::fs::File::open(format!("/proc/self/task/{main_tid}/syscall")).map(std::os::unix::io::IntoRawFd::into_raw_fd).unwrap_or(-1);
            let opening = Arc::new(AtomicBool::new(false));
            let past = Arc::new(AtomicBool::new(false));
            let freed_at = Arc::new(AtomicI32::new(-1));
            let drain = {
                let (opening, past, freed_at) = (opening.clone(), past.clone(), freed_at.clone());
                std::thread::spawn(move || {
                    let open_nr = libc::SYS_openat.to_string();
                    while !past.load(SeqCst) && !(opening.load(SeqCst) && task_syscall_fd(main_syscall) == Some(open_nr.clone())) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    if !past.load(SeqCst) {
                        std::thread::sleep(Duration::from_millis(300));
                    }
                    let mut r = QMsg { mtype: 0, text: [0; 64] };
                    let rc = unsafe { libc::msgrcv(id, &mut r as *mut QMsg as *mut libc::c_void, 64, 1, libc::IPC_NOWAIT) };
                    freed_at.store(t0.elapsed().as_millis() as i32, SeqCst);
                    rc
                })
            };
            opening.store(true, SeqCst);
            let read = if blocked { read_file(&path).map(|k| k.contains(CANARY)) } else { Err(-1) };
            // As the open returns: is S's message (type 2) in the queue, i.e.
            // has the kernel copied S's buffer?
            let mut r = QMsg { mtype: 0, text: [0; 64] };
            let copied = unsafe { libc::msgrcv(id, &mut r as *mut QMsg as *mut libc::c_void, 64, 2, libc::IPC_NOWAIT) } == 64 && r.text[0] == b'y';
            let opened = t0.elapsed();
            past.store(true, SeqCst);
            let (rc, sent) = s.join().unwrap();
            let _ = drain.join();
            unsafe {
                libc::close(main_syscall);
                libc::msgctl(id, libc::IPC_RMID, std::ptr::null_mut());
            }
            let _ = std::fs::write(d.join("p.out"), format!("filled={n} blocked={blocked} send_rc={rc} copied={copied} sent_ms={} read={read:?} opened_ms={} freed_ms={}", sent.as_millis(), opened.as_millis(), freed_at.load(SeqCst)));
            0
        });
        let pc = reap(p);
        let _ = std::fs::write(d.join("report"), format!("{pc:?}"));
        0
    }) else {
        let _ = std::fs::write(secret.file("s.done"), "");
        let _ = join_within(held_watch, wait_limit(), "the guard-side watcher of the held send, after s.done");
        return;
    };
    let _ = std::fs::write(secret.file("s.done"), "");
    let _ = join_within(held_watch, wait_limit(), "the guard-side watcher of the held send, after s.done");
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("report")), "Some(0)");
    let out = report(&secret.file("p.out"));
    eprintln!("queue send in flight: {out}");
    if out.starts_with("skip=") {
        eprintln!("SKIP: {out}");
        return;
    }
    let field = |k: &str| out.split_whitespace().find_map(|f| f.strip_prefix(&format!("{k}="))).unwrap_or("").to_string();
    assert_eq!(field("blocked"), "true", "the guard held S's send (let go, its gate kept) before the raw open: {out}");
    assert_eq!(field("send_rc"), "0", "S's send completed once room was made: {out}");
    assert_eq!(field("copied"), "true", "the raw open must come back only after the other thread's queue send is done (its message is in the queue as the open returns: the kernel had copied its buffer): {out}");
    assert_eq!(field("read"), "Ok(true)", "the open then reads the secret (the wait is well inside the taint's bound): {out}");
    eprintln!("QUEUE SEND IN FLIGHT PASS");
}

/// P0 1c, the leak oracle (probabilistic): a process whose thread S sends a
/// buffer on a SysV queue in a loop while its main thread reads the secret
/// raw and writes it into that buffer; another process of the tree drains
/// the queue. No message it receives may carry the secret: every send the
/// guard let go before the taint is copied before the open returns, and
/// every send after it is refused.
#[test]
#[ignore]
fn no_queue_message_carries_a_secret_another_thread_read_during_the_send() {
    let _one = serial();
    let secret = Secret::new("mq-leak");
    let (arbiter, _told) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let path = secret.path.clone();
    let d = secret.dir.clone();
    let Some(code) = guarded(cfg, move || {
        let id = unsafe { libc::msgget(libc::IPC_PRIVATE, libc::IPC_CREAT | 0o600) };
        if id < 0 {
            let _ = std::fs::write(d.join("p.out"), "skip=no SysV queue");
            return 0;
        }
        // The receiver: drains for 6 s, writes what it got.
        let d2 = d.clone();
        let q = fork_run(move || {
            let mut got: Vec<u8> = Vec::new();
            let end = std::time::Instant::now() + Duration::from_secs(6);
            while std::time::Instant::now() < end {
                let mut r = QMsg { mtype: 0, text: [0; 64] };
                let n = unsafe { libc::msgrcv(id, &mut r as *mut QMsg as *mut libc::c_void, 64, 0, libc::IPC_NOWAIT) };
                if n > 0 {
                    got.extend_from_slice(&r.text[..n as usize]);
                } else {
                    std::thread::sleep(Duration::from_micros(200));
                }
            }
            let _ = std::fs::write(d2.join("q.got"), &got);
            0
        });
        let d3 = d.clone();
        let p = fork_run(move || {
            static BUF: std::sync::atomic::AtomicPtr<QMsg> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
            let buf = Box::into_raw(Box::new(QMsg { mtype: 1, text: [b'.'; 64] }));
            BUF.store(buf, std::sync::atomic::Ordering::SeqCst);
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let st = stop.clone();
            let s = std::thread::spawn(move || {
                let (mut sent, mut refused) = (0u64, 0u64);
                while !st.load(std::sync::atomic::Ordering::SeqCst) {
                    let b = BUF.load(std::sync::atomic::Ordering::SeqCst);
                    if unsafe { libc::msgsnd(id, b as *const libc::c_void, 64, libc::IPC_NOWAIT) } == 0 {
                        sent += 1;
                    } else if errno() == libc::EACCES {
                        refused += 1;
                    }
                }
                (sent, refused)
            });
            std::thread::sleep(Duration::from_millis(200));
            let read = read_file(&path);
            if let Ok(k) = &read {
                // Into the buffer S keeps sending, over and over.
                let bytes = k.as_bytes();
                for _ in 0..20_000 {
                    // SAFETY: the buffer outlives both threads (leaked); a
                    // racy byte copy is the point of the test.
                    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), (*buf).text.as_mut_ptr(), bytes.len().min(64)) };
                    std::hint::spin_loop();
                }
            }
            std::thread::sleep(Duration::from_millis(300));
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let (sent, refused) = s.join().unwrap();
            let _ = std::fs::write(d3.join("p.out"), format!("read={} sent={sent} refused={refused}", match &read { Ok(_) => "raw".to_string(), Err(e) => format!("e{e}") }));
            0
        });
        let rs = (reap(p), reap(q));
        unsafe { libc::msgctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
        let _ = std::fs::write(d.join("report"), format!("{rs:?}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let out = report(&secret.file("p.out"));
    eprintln!("queue race: {out}");
    if out.starts_with("skip=") {
        eprintln!("SKIP: {out}");
        return;
    }
    assert_eq!(report(&secret.file("report")), "(Some(0), Some(0))");
    let got = std::fs::read(secret.file("q.got")).unwrap_or_default();
    assert!(!String::from_utf8_lossy(&got).contains(CANARY), "THE LEAK: a queue message carried the secret another thread read during the send ({out})");
    assert!(!out.contains("sent=0 "), "control: S sent before the taint: {out}");
    eprintln!("QUEUE RACE PASS ({} bytes received)", got.len());
}
