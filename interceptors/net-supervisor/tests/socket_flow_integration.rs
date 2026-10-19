//! socket_flow_integration — confidentiality plan 13 §9 R1 at the guard: a
//! channel joined AFTER a holder's taint carries the taint to the process at
//! its other end.
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! (an unprivileged user + network + pid namespace; `lo` is brought up
//! here), or the kernel lane of `scripts/ci/vm-run.sh`. A host where the
//! seccomp listener cannot be installed SKIPs.
//!
//! Before: plan 13 D2's pipe-flow taint and the taint-time sweep covered a
//! pipe, a FIFO and a socket pair that existed at the taint; the holder's
//! accept admitted a connection from this machine. So a process that
//! connected to a holder's listener after its taint, or got a socket pair
//! end from (or gave one to) a holder after it, received the secret and
//! sent it anywhere the static list allowed. Asserted here, each with the
//! leak oracle (a TCP sink on 127.0.0.3, bound nowhere, never receives the
//! canary) and its control (127.0.0.2, the binding, does receive it, so the
//! receiver really held the bytes):
//!
//!   (A) a client of a holder's TCP or Unix listener, connected after the
//!       taint, is a holder (its connect to the sink refused, its file
//!       labelled, the flow reported to the arbiter); a client already
//!       connected to the sink is refused at the holder's accept
//!       (ECONNABORTED) and gets nothing; a client of an untainted server
//!       is untouched;
//!   (C) a socket pair end passed after the taint, either way (the holder
//!       passes one end of a pair it made; an untainted process passes one
//!       end of its own pair to the holder and keeps the other), makes the
//!       untainted side a holder; one already connected to the sink has
//!       the pass refused (EACCES);
//!   (B) where the accept is not judged (sends and accepts untrapped, the
//!       old-kernel degrade), the client is caught at its own later
//!       connect.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, readable_within, reap_within, run_tag, socketpair, wait_limit};

use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
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
const CANARY: &str = "R1-CANARY-6083";

// ── plumbing (as taint_gaps_integration.rs) ─────────────────────────────────

fn lo_up() {
    let _ = std::process::Command::new("ip").args(["link", "set", "lo", "up"]).stderr(std::process::Stdio::null()).status();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A TCP listener in the TEST process (outside the guard's tree) whose
/// accepted connections are read into a shared buffer.
fn tcp_sink(ip: [u8; 4]) -> (u16, Arc<Mutex<Vec<u8>>>) {
    let l = std::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::from(ip), 0)).expect("bind tcp sink");
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

fn sin(ip: [u8; 4], port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in { sin_family: libc::AF_INET as u16, sin_port: port.to_be(), sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(ip) }, sin_zero: [0; 8] }
}

fn tcp_connect(ip: [u8; 4], port: u16) -> Result<RawFd, i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let a = sin(ip, port);
    if unsafe { libc::connect(fd, &a as *const _ as *const libc::sockaddr, 16) } == 0 {
        Ok(fd)
    } else {
        let e = errno();
        unsafe { libc::close(fd) };
        Err(e)
    }
}

/// Connect to `ip:port` and send `data`: "sent", or the connect's errno.
fn send_to(ip: [u8; 4], port: u16, data: &[u8]) -> String {
    match tcp_connect(ip, port) {
        Ok(fd) => {
            let n = write_all(fd, data);
            unsafe { libc::close(fd) };
            if n > 0 { "sent".into() } else { format!("w{}", errno()) }
        }
        Err(e) => format!("{e}"),
    }
}

fn write_all(fd: RawFd, data: &[u8]) -> isize {
    unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) }
}

/// Read until EOF (bounded by SO_RCVTIMEO 3 s).
fn read_all(fd: RawFd) -> String {
    let tv = libc::timeval { tv_sec: 3, tv_usec: 0 };
    unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of_val(&tv) as u32) };
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
        if out.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()) {
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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

fn fork_run(f: impl FnOnce() -> i32) -> i32 {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let code = f();
        unsafe { libc::_exit(code) };
    }
    pid
}

/// Wait (stat only: the stat family is not trapped here) until `p` exists.
fn wait_for(p: &Path) -> bool {
    for _ in 0..500 {
        if p.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// A Unix datagram socket bound at `p`.
fn dgram_bound(p: &Path) -> RawFd {
    let s = std::os::unix::net::UnixDatagram::bind(p).expect("bind dgram");
    s.into_raw_fd()
}

/// `sendmsg` of `fd` over the Unix socket `via` to the path `to` (one byte).
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

/// `recvmsg` of one descriptor over `via` (bounded by SO_RCVTIMEO 3 s); -1 none.
fn recv_fd(via: RawFd) -> RawFd {
    let tv = libc::timeval { tv_sec: 3, tv_usec: 0 };
    unsafe { libc::setsockopt(via, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of_val(&tv) as u32) };
    recv_fd_waiting(via)
}

/// `recvmsg` of one descriptor over `via`, bounded by its own SO_RCVTIMEO.
fn recv_fd_waiting(via: RawFd) -> RawFd {
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
        let dir = std::env::temp_dir().join(format!("mandu-r1-{tag}-{}", run_tag()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let path = dir.join("secret.env");
        let twin = dir.join("twin.env");
        std::fs::write(&path, format!("API_KEY={CANARY}\n")).unwrap();
        std::fs::write(&twin, "API_KEY=$MDU:twin\n").unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(&policy, format!(r#"{{"agentExe":"","ask":"never","session":"r1","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, path.display(), twin.display())).unwrap();
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

/// What the mock arbiter was told: `(op, procKey, flowsFrom or [path])`.
type Told = Arc<Mutex<Vec<(String, String, Vec<String>)>>>;

/// Every opener is a reader (raw); a holder's bindings are `bindings`; the
/// flows (`recordProcessFlow`) and labels (`labelWrittenPathTainted`, not
/// granted, so no file the tests sync through is gated) are recorded.
fn recording_arbiter(bindings: Vec<String>) -> (&'static MockArbiter, Told) {
    let told: Told = Arc::new(Mutex::new(Vec::new()));
    let t = told.clone();
    let m = MockArbiter::start(op_handler(move |op, req| {
        let key = req.get("procKey").and_then(|v| v.as_str()).unwrap_or("").to_string();
        match op {
            "decideSecretOpen" => Ok(serde_json::json!({ "verdict": "raw", "app": "test", "level": "no-model", "reason": "mock reader" })),
            "taintedProcessBindings" => Ok(serde_json::json!({ "tainted": true, "level": "no-model", "files": ["secret.env"], "bindings": bindings })),
            "recordProcessFlow" => {
                let flows: Vec<String> = req.get("flowsFrom").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                t.lock().unwrap().push((op.to_string(), key, flows));
                Ok(serde_json::json!({ "ok": true }))
            }
            "labelWrittenPathTainted" => {
                let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
                t.lock().unwrap().push((op.to_string(), key, vec![path]));
                Ok(serde_json::Value::Null)
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
fn guarded(traps: FilterTraps, cfg: GuardConfig, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    lo_up();
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

fn report(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Did the guard tell the arbiter that process `pid` flows from `from`?
fn flow_reported(told: &Told, pid: i32, from: i32) -> bool {
    told.lock().unwrap().iter().any(|(op, k, f)| op == "recordProcessFlow" && k.starts_with(&format!("{pid}-")) && f.iter().any(|x| x.starts_with(&format!("{from}-"))))
}

fn labelled_by(told: &Told, path: &Path, pid: i32) -> bool {
    let want = path.to_string_lossy().to_string();
    told.lock().unwrap().iter().any(|(op, k, f)| op == "labelWrittenPathTainted" && k.starts_with(&format!("{pid}-")) && f.iter().any(|x| *x == want))
}

fn canary_in(buf: &Arc<Mutex<Vec<u8>>>) -> bool {
    String::from_utf8_lossy(&buf.lock().unwrap()).contains(CANARY)
}

// ── (A) a connection to a holder's listener after the taint ─────────────────

/// The server: reads the secret (a holder from here on) when `read_secret`,
/// marks `ready`, then answers `n` accepts with the secret, recording each
/// accept's result into `rp`.
fn serve(listener: RawFd, path: &Path, read_secret: bool, ready: &Path, n: usize, rp: &Path) -> i32 {
    let answer = if read_secret {
        match read_file(path) {
            Ok(k) if k.contains(CANARY) => k,
            _ => return 4,
        }
    } else {
        "LIVE-SERVER".to_string()
    };
    let _ = std::fs::write(ready, "r");
    let mut results = Vec::new();
    while results.len() < n {
        let c = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
        if c < 0 {
            results.push(format!("e{}", errno()));
            continue;
        }
        write_all(c, answer.as_bytes());
        unsafe { libc::close(c) };
        results.push("ok".into());
    }
    let _ = std::fs::write(rp, results.join(","));
    0
}

/// A client of the server at `connect`: reads what the server sends, then
/// sends it to the bound host and to the sink, and writes it to `out`
/// (opened after); "<got canary> bound=<…> sink=<…>".
fn client(connect: impl FnOnce() -> Result<RawFd, i32>, bound: u16, sink: u16, out: &Path) -> String {
    let got = match connect() {
        Ok(fd) => {
            let s = read_all(fd);
            unsafe { libc::close(fd) };
            s
        }
        Err(e) => return format!("connect={e}"),
    };
    let has = got.contains(CANARY);
    let bound_r = send_to([127, 0, 0, 2], bound, got.as_bytes());
    let sink_r = send_to([127, 0, 0, 3], sink, got.as_bytes());
    let _ = std::fs::write(out, &got);
    format!("got={has} bound={bound_r} sink={sink_r}")
}

fn run_accept_case(unix: bool) {
    let _g = serial();
    lo_up();
    let (bound, bound_got) = tcp_sink([127, 0, 0, 2]);
    let (sink, sink_got) = tcp_sink([127, 0, 0, 3]);
    let secret = Secret::new(if unix { "accept-unix" } else { "accept-tcp" });
    secret.root_is_the_agent();
    let (arbiter, told) = recording_arbiter(vec!["127.0.0.2".into()]);
    let cfg = secret_cfg(&secret, arbiter);
    let (path, ready, hrp, rp) = (secret.path.clone(), secret.file("ready"), secret.file("h.txt"), secret.file("report.txt"));
    let (out_u, out_u2, sock) = (secret.file("u-out.txt"), secret.file("u2-out.txt"), secret.file("srv.sock"));
    let (out_c, sock_live, ready_live, lrp) = (secret.file("c-out.txt"), secret.file("live.sock"), secret.file("ready-live"), secret.file("live.txt"));
    let Some(code) = guarded(secret_traps(), cfg, move || {
        // The listeners exist before anyone holds a secret; the server
        // (H) inherits its own; the clients are its siblings.
        let (lfd, port, live_fd, live_port) = if unix {
            let l = std::os::unix::net::UnixListener::bind(&sock).unwrap().into_raw_fd();
            let v = std::os::unix::net::UnixListener::bind(&sock_live).unwrap().into_raw_fd();
            (l, 0u16, v, 0u16)
        } else {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            let v = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let vp = v.local_addr().unwrap().port();
            (l.into_raw_fd(), p, v.into_raw_fd(), vp)
        };
        let dial = |live: bool| -> Result<RawFd, i32> {
            if unix {
                std::os::unix::net::UnixStream::connect(if live { &sock_live } else { &sock }).map(|s| s.into_raw_fd()).map_err(|e| e.raw_os_error().unwrap_or(-1))
            } else {
                tcp_connect([127, 0, 0, 1], if live { live_port } else { port })
            }
        };
        let h = fork_run(|| {
            unsafe { libc::close(live_fd) };
            serve(lfd, &path, true, &ready, 2, &hrp)
        });
        // The control: an untainted server's client is untouched.
        let s = fork_run(|| {
            unsafe { libc::close(lfd) };
            serve(live_fd, &path, false, &ready_live, 1, &lrp)
        });
        unsafe {
            libc::close(lfd);
            libc::close(live_fd);
        }
        if !wait_for(&ready) || !wait_for(&ready_live) {
            return 5;
        }
        // U: connects after the taint, then sends what it got.
        let u = fork_run(|| {
            let r = client(|| dial(false), bound, sink, &out_u);
            let _ = std::fs::write(out_u.with_extension("r"), r);
            0
        });
        reap(u);
        // U2: already connected to the sink, then connects to the holder.
        let u2 = fork_run(|| {
            let pre = tcp_connect([127, 0, 0, 3], sink);
            let got = match dial(false) {
                Ok(fd) => read_all(fd),
                Err(e) => format!("connect={e}"),
            };
            if let Ok(fd) = pre {
                write_all(fd, got.as_bytes());
                unsafe { libc::close(fd) };
            }
            let _ = std::fs::write(&out_u2, format!("got={}", got.contains(CANARY)));
            0
        });
        reap(u2);
        // C: a client of the untainted server.
        let c = fork_run(|| {
            let r = client(|| dial(true), bound, sink, &out_c);
            let _ = std::fs::write(out_c.with_extension("r"), r);
            0
        });
        reap(c);
        reap(h);
        reap(s);
        let _ = std::fs::write(&rp, format!("h={h} u={u} u2={u2}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    std::thread::sleep(Duration::from_millis(300));
    let pids: Vec<i32> = report(&secret.file("report.txt")).split_whitespace().filter_map(|kv| kv.split_once('=')).filter_map(|(_, v)| v.parse().ok()).collect();
    let (h, u) = (pids[0], pids[1]);
    let ur = report(&secret.file("u-out.r"));
    let u2r = report(&secret.file("u2-out.txt"));
    let cr = report(&secret.file("c-out.r"));
    let hr = report(&secret.file("h.txt"));
    eprintln!("unix={unix} server={hr} U: {ur} | U2: {u2r} | control: {cr}");
    assert!(ur.starts_with("got=true "), "U received the secret from the holder: {ur}");
    assert!(ur.contains("bound=sent"), "U, now a holder, still reaches the binding: {ur}");
    assert!(ur.ends_with(&format!("sink={}", libc::EACCES)), "U is a holder: its connect to the unbound sink is refused: {ur}");
    assert!(flow_reported(&told, u, h), "the guard told the arbiter U flows from the server (the model exit's fold)");
    assert!(labelled_by(&told, &secret.file("u-out.txt"), u), "U's file takes the label");
    assert_eq!(hr, format!("ok,e{}", libc::ECONNABORTED), "U2, already connected to the sink, is refused at the holder's accept");
    assert_eq!(u2r, "got=false", "U2 received nothing");
    assert_eq!(cr, "got=false bound=sent sink=sent", "control: a client of an untainted server is untouched");
    assert!(!canary_in(&sink_got), "THE LEAK: the unbound sink received the secret");
    assert!(canary_in(&bound_got), "control: U really held the secret (the binding got it)");
    eprintln!("R1 ACCEPT ({}) PASS", if unix { "unix" } else { "tcp" });
}

#[test]
#[ignore]
fn a_client_of_a_holders_tcp_listener_connected_after_the_taint_is_a_holder() {
    run_accept_case(false);
}

#[test]
#[ignore]
fn a_client_of_a_holders_unix_listener_connected_after_the_taint_is_a_holder() {
    run_accept_case(true);
}

// ── (C) a socket pair end passed after the taint ────────────────────────────

#[test]
#[ignore]
fn a_socket_pair_end_passed_after_the_taint_makes_the_other_side_a_holder() {
    let _g = serial();
    lo_up();
    let (bound, bound_got) = tcp_sink([127, 0, 0, 2]);
    let (sink, sink_got) = tcp_sink([127, 0, 0, 3]);
    let secret = Secret::new("pass");
    secret.root_is_the_agent();
    let u_sock = secret.file("u.sock");
    // The holder's datagram to U's socket is a send to a Unix path: bound.
    let (arbiter, told) = recording_arbiter(vec!["127.0.0.2".into(), format!("unix:{}", u_sock.display())]);
    let cfg = secret_cfg(&secret, arbiter);
    let (ready, u_ready, h_sock, rp) = (secret.file("ready"), secret.file("u-ready"), secret.file("h.sock"), secret.file("report.txt"));
    let spath = secret.path.clone();
    let (u_out, v_out, w_out, hrp) = (secret.file("u.r"), secret.file("v.r"), secret.file("w.r"), secret.file("h.r"));
    let Some(code) = guarded(secret_traps(), cfg, move || {
        // U: its datagram socket exists before the taint (H sends to it);
        // it receives H's end, reads, sends on. Neither the parent nor any
        // sibling holds U's socket, so U alone receives the pass.
        let u = fork_run(|| {
            let u_dgram = dgram_bound(&u_sock);
            let _ = std::fs::write(&u_ready, "r");
            let tv = libc::timeval { tv_sec: 10, tv_usec: 0 };
            unsafe { libc::setsockopt(u_dgram, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of_val(&tv) as u32) };
            let fd = recv_fd_waiting(u_dgram);
            let got = if fd >= 0 { read_all(fd) } else { "none".into() };
            let r = format!("got={} bound={} sink={}", got.contains(CANARY), send_to([127, 0, 0, 2], bound, got.as_bytes()), send_to([127, 0, 0, 3], sink, got.as_bytes()));
            let _ = std::fs::write(&u_out, r);
            0
        });
        if !wait_for(&u_ready) {
            return 6;
        }
        let h = fork_run(|| {
            let k = match read_file(&spath) {
                Ok(k) if k.contains(CANARY) => k,
                _ => return 4,
            };
            let h_dgram = dgram_bound(&h_sock);
            let _ = std::fs::write(&ready, "r");
            // (1) H → U: a pair made after the taint, one end passed to U.
            let (a, b) = socketpair(libc::SOCK_STREAM);
            let sender = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            let pass1 = pass_fd_to(sender, &u_sock, a);
            unsafe { libc::close(a) };
            write_all(b, k.as_bytes());
            // (2) V → H: V's pair end arrives; the secret goes into it.
            let tv = libc::timeval { tv_sec: 10, tv_usec: 0 };
            unsafe { libc::setsockopt(h_dgram, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of_val(&tv) as u32) };
            let fd = recv_fd_waiting(h_dgram);
            let got2 = if fd >= 0 { write_all(fd, k.as_bytes()) > 0 } else { false };
            // (3) W → H: refused at W's send, so nothing arrives.
            let fd3 = recv_fd(h_dgram);
            let got3 = fd3 >= 0;
            let _ = std::fs::write(&hrp, format!("pass1={pass1} got2={got2} got3={got3}"));
            unsafe { libc::close(b) };
            std::thread::sleep(Duration::from_millis(300));
            0
        });
        if !wait_for(&ready) {
            return 5;
        }
        reap(u);
        // V: passes one end of its own pair to H, keeps the other.
        let v = fork_run(|| {
            let (a, b) = socketpair(libc::SOCK_STREAM);
            let sender = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            let pass = pass_fd_to(sender, &h_sock, b);
            unsafe { libc::close(b) };
            let got = read_all(a);
            let r = format!("pass={pass} got={} bound={} sink={}", got.contains(CANARY), send_to([127, 0, 0, 2], bound, got.as_bytes()), send_to([127, 0, 0, 3], sink, got.as_bytes()));
            let _ = std::fs::write(&v_out, r);
            0
        });
        reap(v);
        // W: already connected to the sink; its pass is refused.
        let w = fork_run(|| {
            let pre = tcp_connect([127, 0, 0, 3], sink);
            let (a, b) = socketpair(libc::SOCK_STREAM);
            let sender = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            let pass = pass_fd_to(sender, &h_sock, b);
            unsafe { libc::close(b) };
            let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
            unsafe { libc::setsockopt(a, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of_val(&tv) as u32) };
            let got = read_all(a);
            if let Ok(fd) = pre {
                write_all(fd, got.as_bytes());
                unsafe { libc::close(fd) };
            }
            let _ = std::fs::write(&w_out, format!("pass={pass} got={}", got.contains(CANARY)));
            0
        });
        reap(w);
        reap(h);
        let _ = std::fs::write(&rp, format!("h={h} u={u} v={v}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    std::thread::sleep(Duration::from_millis(300));
    let pids: Vec<i32> = report(&secret.file("report.txt")).split_whitespace().filter_map(|kv| kv.split_once('=')).filter_map(|(_, v)| v.parse().ok()).collect();
    let (h, u, v) = (pids[0], pids[1], pids[2]);
    let (ur, vr, wr, hr) = (report(&secret.file("u.r")), report(&secret.file("v.r")), report(&secret.file("w.r")), report(&secret.file("h.r")));
    eprintln!("H: {hr} | U: {ur} | V: {vr} | W: {wr}");
    assert!(hr.starts_with("pass1=0 got2=true got3=false"), "{hr}");
    assert_eq!(ur, format!("got=true bound=sent sink={}", libc::EACCES), "U got H's pair end after the taint: a holder");
    assert_eq!(vr, format!("pass=0 got=true bound=sent sink={}", libc::EACCES), "V gave H one end of its own pair: a holder");
    assert_eq!(wr, format!("pass={} got=false", libc::EACCES), "W, already connected to the sink, has its pass refused");
    assert!(flow_reported(&told, u, h) && flow_reported(&told, v, h), "both flows reported to the arbiter");
    assert!(!canary_in(&sink_got), "THE LEAK: the unbound sink received the secret");
    assert!(canary_in(&bound_got), "control: the receivers really held the secret");
    eprintln!("R1 PASS PASS");
}

// ── (B) the later event, where the accept is not judged ─────────────────────

#[test]
#[ignore]
fn where_the_accept_is_not_judged_the_client_is_caught_at_its_connect() {
    let _g = serial();
    lo_up();
    let (sink, sink_got) = tcp_sink([127, 0, 0, 3]);
    let secret = Secret::new("later");
    secret.root_is_the_agent();
    let (arbiter, told) = recording_arbiter(vec![]);
    let cfg = secret_cfg(&secret, arbiter);
    let (spath, ready, sock, u_out, rp) = (secret.path.clone(), secret.file("ready"), secret.file("srv.sock"), secret.file("u.r"), secret.file("report.txt"));
    // Sends and accepts untrapped: the old-kernel degrade (no pidfd_getfd).
    let traps = FilterTraps { no_sends: true, ..secret_traps() };
    let Some(code) = guarded(traps, cfg, move || {
        let h = fork_run(|| {
            let k = match read_file(&spath) {
                Ok(k) if k.contains(CANARY) => k,
                _ => return 4,
            };
            // Bound after the taint: no sweep saw it.
            let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            let _ = std::fs::write(&ready, "r");
            if let Ok((c, _)) = l.accept() {
                write_all(c.as_raw_fd(), k.as_bytes());
                std::thread::sleep(Duration::from_millis(500));
            }
            0
        });
        if !wait_for(&ready) {
            return 5;
        }
        let u = fork_run(|| {
            let conn = std::os::unix::net::UnixStream::connect(&sock).ok();
            let got = match &conn {
                Some(s) => read_all(s.as_raw_fd()),
                None => "none".into(),
            };
            // Still holding the connection to the holder (one closed before
            // any trapped call is the stated residual of this degrade).
            let r = format!("got={} sink={}", got.contains(CANARY), send_to([127, 0, 0, 3], sink, got.as_bytes()));
            drop(conn);
            let _ = std::fs::write(&u_out, r);
            0
        });
        reap(u);
        reap(h);
        let _ = std::fs::write(&rp, format!("h={h} u={u}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    std::thread::sleep(Duration::from_millis(300));
    let pids: Vec<i32> = report(&secret.file("report.txt")).split_whitespace().filter_map(|kv| kv.split_once('=')).filter_map(|(_, v)| v.parse().ok()).collect();
    let ur = report(&secret.file("u.r"));
    eprintln!("U: {ur}");
    assert_eq!(ur, format!("got=true sink={}", libc::EACCES), "the client holding a connection to the holder is a holder at its connect");
    assert!(flow_reported(&told, pids[1], pids[0]));
    assert!(!canary_in(&sink_got), "THE LEAK: the unbound sink received the secret");
    eprintln!("R1 LATER EVENT PASS");
}
