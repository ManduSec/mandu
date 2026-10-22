//! agent_flow_integration — confidentiality plan 13 §4.5.1, the decision of
//! 2026-10-02 (mask, do not refuse), at the guard: the AGENT process itself
//! connected to a secret holder.
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! or the kernel lane of `scripts/ci/vm-run.sh` (an unprivileged user +
//! network + pid namespace; `lo` is brought up here). A host where the
//! seccomp listener cannot be installed SKIPs.
//!
//! The agent is never made a holder (D2's exemption): it holds the read end
//! of every tool call's output, and tainting it would refuse its own
//! connections. Before this change its own connection to a holder (an HTTP
//! MCP server that read `.env`, a dev server it fetched) was recorded
//! nowhere, so the reply reached the model raw; and a keep-alive the agent
//! held when the server then read its secret refused that raw open (the
//! sweep judged the agent's end as an exit). Asserted here, the agent being
//! the guarded body (the first-started process of `agentExe`, this test
//! binary):
//!
//!   (1) the agent connects to a holder's TCP or Unix listener AFTER the
//!       taint: the guard records an agent flow at the arbiter
//!       (`recordAgentFlow`, the agent's socket, the holder's key) before
//!       the holder gets the connection; the agent receives the reply and is
//!       NOT made a holder (its own connection to an unbound host still
//!       goes); once it drops the connection the guard reports it closed;
//!   (2) a server the agent is ALREADY connected to (keep-alive) reads its
//!       secret: the raw open is admitted (it was refused on master) and the
//!       agent flow recorded at the taint-time sweep;
//!   (3) fail-closed: an arbiter that cannot record the flow resets the
//!       connection at the holder's accept (ECONNABORTED): the agent gets
//!       nothing.
//!
//! Plan 13 §4.5.1's three leftovers (2026-10-02, each red on master):
//!
//!   (4) the session's net-proxy re-originates a request of the agent or of
//!       a tool process to a holder on this machine (an address `NO_PROXY`
//!       does not name): the guard sees the proxy, outside its tree, as the
//!       holder's client, and the reply went back raw to whoever asked. The
//!       holder's accept of a connection the proxy holds is reset now, and a
//!       holder that reads its secret with one already accepted is refused
//!       the raw open (even when its bindings admit this machine);
//!   (5) where the accept is not judged (the old-kernel degrade, no
//!       `pidfd_getfd`: accept and sendmsg untrapped), the agent's connect to
//!       a holder's listener made after the taint is recorded at the connect,
//!       and one already waiting in the listener's backlog when the server
//!       reads its secret at the taint-time sweep;
//!   (6) a FIFO a holder writes and the agent ITSELF reads (its file tool on
//!       a named pipe): recorded as an agent flow (the FIFO's path) at the
//!       later of the two opens, or at the sweep when the writer held it
//!       before its taint; a record that fails refuses the open;
//!   (7) a regular file the agent already holds open for reading (through a
//!       hard link) when a holder writes it: recorded as an agent flow (the
//!       agent's link) at the holder's write-open, or at the sweep of a
//!       writer that held it open before its taint; a record that fails
//!       refuses the write.
//!
//! The model-exit half (the masked tool_result) is the arbiter's
//! test/unit/agent-flow-record.test.ts and, under this real guard,
//! tests/sandbox/guard/agent-flow.test.ts.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, readable_within, reap_within, run_tag, socketpair, wait_limit};

use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::{IntoRawFd, RawFd};
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
const CANARY: &str = "AGENT-FLOW-CANARY-4551";

fn lo_up() {
    let _ = std::process::Command::new("ip").args(["link", "set", "lo", "up"]).stderr(std::process::Stdio::null()).status();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A TCP listener in the TEST process (outside the guard's tree).
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

/// Whether the sink received `needle` within `within`. The sink appends on
/// its own reader thread after the sender's close, so a check made the
/// moment the sender returns can run before the bytes land: CI pipeline
/// 8591 failed the agent's own `AGENT-LIVE` this way, with the send
/// reported `sent` (docs/design/testing/continuous-integration.md §11).
fn sink_received(got: &Arc<Mutex<Vec<u8>>>, needle: &str, within: Duration) -> bool {
    let end = std::time::Instant::now() + within;
    loop {
        if String::from_utf8_lossy(&got.lock().unwrap()).contains(needle) {
            return true;
        }
        if std::time::Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
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

/// Read until EOF or the canary, each read bounded by the run's wait limit
/// (SO_RCVTIMEO, `wait_limit`). Every peer here answers and closes, or has
/// its connection reset by the guard, so a read returns when it does. It
/// was 3 s until 2026-10-21: a server whose secret read took longer under
/// load (CI job 18285) answered an agent that had already given up and
/// closed, and the sweep then rightly refused the server's raw open (its
/// connection's agent end gone: an exit).
fn read_some(fd: RawFd) -> String {
    let tv = libc::timeval { tv_sec: wait_limit().as_secs() as libc::time_t, tv_usec: 0 };
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

fn reap(pid: i32) -> Option<i32> {
    if in_test_process() {
        return reap_within(pid, wait_limit(), "waiting for a child the test forked").code();
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) { Some(libc::WEXITSTATUS(status)) } else { None }
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

/// Whether `p` appears within the run's wait limit (`wait_limit`). A fixed
/// 5 s here failed tests whose peer was only slow: under load a holder's
/// first secret read took over 7 s (docs/design/testing/
/// continuous-integration.md §11, CI job 18268).
fn wait_for(p: &Path) -> bool {
    wait_for_within(p, wait_limit())
}

fn wait_for_within(p: &Path, limit: Duration) -> bool {
    let end = std::time::Instant::now() + limit;
    loop {
        if p.exists() {
            return true;
        }
        if std::time::Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
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

struct Secret {
    dir: PathBuf,
    path: PathBuf,
    policy: PathBuf,
}

impl Secret {
    /// A no-model secret, with THIS test binary as the launch's agent.
    fn new(tag: &str) -> Secret {
        let dir = std::env::temp_dir().join(format!("mandu-agent-flow-{tag}-{}", run_tag()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let path = dir.join("secret.env");
        let twin = dir.join("twin.env");
        std::fs::write(&path, format!("API_KEY={CANARY}\n")).unwrap();
        std::fs::write(&twin, "API_KEY=$MDU:twin\n").unwrap();
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(
            &policy,
            format!(r#"{{"agentExe":"{}","ask":"never","session":"af","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, exe.display(), path.display(), twin.display()),
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

/// The file a test's mock arbiter creates when it is told a channel closed
/// (`recordAgentFlow` with `closed`, [`recording_arbiter_marking`]): the
/// agent waits for it before it exits ([`wait_close_reported`]). Each mock
/// has its own: a guard's thread that reports a close after its test ended
/// (its last 200 ms look) reaches only its own test's mock, so it can never
/// stand for the next test's report (a marker shared by the file did, in
/// the kernel lane: four tests in a row each saw the one before's).
fn close_mark(secret: &Secret) -> PathBuf {
    secret.file("closed-reported")
}

/// In the agent, after it dropped a channel it read the holder's bytes from
/// (so an agent flow was recorded open): wait until the guard's look (every
/// 200 ms) has reported the close, so the agent is still alive when it does.
/// A fixed 800 ms sleep missed it under load; the test asserts
/// the report after the run, so a close never reported still fails there
/// (this wait gives up at half the run's wait limit, before the harness's).
fn wait_close_reported(mark: &Path) {
    let _ = wait_for_within(mark, wait_limit() / 2);
}

/// What the mock arbiter was told: `(op, channel or procKey, flowsFrom, closed)`.
type Told = Arc<Mutex<Vec<(String, String, Vec<String>, bool)>>>;

/// Every opener a reader (raw); a holder bound to 127.0.0.2; the agent
/// flows recorded (or refused, `record_fails`).
fn recording_arbiter(record_fails: bool) -> (&'static MockArbiter, Told) {
    recording_arbiter_with(record_fails, &["127.0.0.2"], None)
}

/// As `recording_arbiter`, and it creates `mark` when it is told a channel
/// closed ([`close_mark`]).
fn recording_arbiter_marking(record_fails: bool, mark: &Path) -> (&'static MockArbiter, Told) {
    recording_arbiter_with(record_fails, &["127.0.0.2"], Some(mark.to_path_buf()))
}

/// As `recording_arbiter`, the holder bound to `bindings`.
fn recording_arbiter_bound(record_fails: bool, bindings: &[&str]) -> (&'static MockArbiter, Told) {
    recording_arbiter_with(record_fails, bindings, None)
}

fn recording_arbiter_with(record_fails: bool, bindings: &[&str], mark: Option<PathBuf>) -> (&'static MockArbiter, Told) {
    let bindings: Vec<String> = bindings.iter().map(|b| b.to_string()).collect();
    let told: Told = Arc::new(Mutex::new(Vec::new()));
    let t = told.clone();
    let m = MockArbiter::start(op_handler(move |op, req| {
        let strs = |k: &str| -> Vec<String> { req.get(k).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default() };
        match op {
            "decideSecretOpen" => Ok(serde_json::json!({ "verdict": "raw", "app": "test", "level": "no-model", "reason": "mock reader" })),
            "taintedProcessBindings" => Ok(serde_json::json!({ "tainted": true, "level": "no-model", "files": ["secret.env"], "bindings": bindings.clone() })),
            "recordAgentFlow" => {
                let ch = req.get("channel").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let closed = req.get("closed").and_then(|v| v.as_bool()).unwrap_or(false);
                t.lock().unwrap_or_else(|e| e.into_inner()).push((op.to_string(), ch, strs("flowsFrom"), closed));
                if let (true, Some(m)) = (closed, mark.as_ref()) {
                    let _ = std::fs::write(m, "c");
                }
                if record_fails && !closed {
                    return Err("mock: the arbiter cannot record it".into());
                }
                Ok(serde_json::json!({ "recorded": true }))
            }
            "recordProcessFlow" => {
                let key = req.get("procKey").and_then(|v| v.as_str()).unwrap_or("").to_string();
                t.lock().unwrap_or_else(|e| e.into_inner()).push((op.to_string(), key, strs("flowsFrom"), false));
                Ok(serde_json::json!({ "ok": true }))
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

fn guarded(cfg: GuardConfig, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    guarded_with(FilterTraps { open: true, secrets: true, ..Default::default() }, cfg, body)
}

/// `guarded` with these traps (`no_sends`: the old-kernel degrade, where
/// accept and sendmsg are not trapped).
fn guarded_with(traps: FilterTraps, cfg: GuardConfig, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
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

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn report(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn agent_flow_opened(told: &Told, from: i32) -> Option<String> {
    told.lock().unwrap().iter().find(|(op, _, f, closed)| op == "recordAgentFlow" && !closed && f.iter().any(|x| x.starts_with(&format!("{from}-")))).map(|(_, ch, _, _)| ch.clone())
}

fn agent_flow_closed(told: &Told, channel: &str) -> bool {
    told.lock().unwrap().iter().any(|(op, ch, _, closed)| op == "recordAgentFlow" && *closed && ch == channel)
}

fn flow_reported_for(told: &Told, pid: i32) -> bool {
    told.lock().unwrap().iter().any(|(op, k, _, _)| op == "recordProcessFlow" && k.starts_with(&format!("{pid}-")))
}

// ── (1) the agent connects to a holder after its taint ──────────────────────

fn run_after_taint(unix: bool) {
    run_after_taint_with(unix, FilterTraps { open: true, secrets: true, ..Default::default() });
}

fn run_after_taint_with(unix: bool, traps: FilterTraps) {
    let _g = serial();
    let (sink, sink_got) = tcp_sink([127, 0, 0, 3]);
    let secret = Secret::new(if unix { "after-unix" } else if traps.no_sends { "after-tcp-untrapped" } else { "after-tcp" });
    let mark = close_mark(&secret);
    let (arbiter, told) = recording_arbiter_marking(false, &mark);
    let mut cfg = secret_cfg(&secret, arbiter);
    cfg.accepts_untrapped = traps.no_sends;
    let (path, ready, hrp, rp, sock) = (secret.path.clone(), secret.file("ready"), secret.file("h.txt"), secret.file("report.txt"), secret.file("srv.sock"));
    let Some(code) = guarded_with(traps, cfg, move || {
        let (lfd, port) = if unix {
            (std::os::unix::net::UnixListener::bind(&sock).unwrap().into_raw_fd(), 0u16)
        } else {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            (l.into_raw_fd(), p)
        };
        // H: a holder (reads the secret), then answers one connection.
        let h = fork_run(|| {
            let k = match std::fs::read_to_string(&path) {
                Ok(k) if k.contains(CANARY) => k,
                _ => return 4,
            };
            let _ = std::fs::write(&ready, "r");
            let c = unsafe { libc::accept(lfd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if c < 0 {
                let _ = std::fs::write(&hrp, format!("e{}", errno()));
                return 0;
            }
            write_all(c, k.as_bytes());
            unsafe { libc::close(c) };
            let _ = std::fs::write(&hrp, "ok");
            0
        });
        unsafe { libc::close(lfd) };
        if !std::path::Path::new(&ready).exists() && !wait_for(&ready) {
            return 5;
        }
        // The agent itself connects, as WebFetch or an HTTP MCP client does.
        let fd = if unix {
            std::os::unix::net::UnixStream::connect(&sock).map(|s| s.into_raw_fd()).map_err(|e| e.raw_os_error().unwrap_or(-1))
        } else {
            tcp_connect([127, 0, 0, 1], port)
        };
        let got = match fd {
            Ok(fd) => {
                let s = read_some(fd);
                unsafe { libc::close(fd) };
                s
            }
            Err(e) => format!("connect={e}"),
        };
        // The guard's look reports the dropped channel (every 200 ms).
        if got.contains(CANARY) {
            wait_close_reported(&mark);
        }
        // Never a holder: its own connection to an unbound host still goes.
        let out = send_to([127, 0, 0, 3], sink, b"AGENT-LIVE");
        reap(h);
        let me = unsafe { libc::getpid() };
        let _ = std::fs::write(&rp, format!("got={} sink={out} agent={me} h={h}", got.contains(CANARY)));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = report(&secret.file("report.txt"));
    eprintln!("unix={unix} holder={} agent: {r}", report(&secret.file("h.txt")));
    let pid = |k: &str| -> i32 { r.split_whitespace().find_map(|kv| kv.strip_prefix(&format!("{k}="))).and_then(|v| v.parse().ok()).unwrap_or(-1) };
    let (agent, h) = (pid("agent"), pid("h"));
    assert!(r.starts_with("got=true "), "the agent received the holder's reply (so the model exit must mask it): {r}");
    assert!(r.contains("sink=sent"), "the agent is never made a holder: its own connection still goes: {r}");
    let channel = agent_flow_opened(&told, h).unwrap_or_else(|| panic!("the guard recorded no agent flow from the holder {h}: {:?}", told.lock().unwrap()));
    assert!(channel.starts_with("socket:["), "{channel}");
    assert!(!flow_reported_for(&told, agent), "the agent is not recorded as a receiving holder");
    assert!(agent_flow_closed(&told, &channel), "the dropped channel was reported closed: {:?}", told.lock().unwrap());
    assert!(sink_received(&sink_got, "AGENT-LIVE", Duration::from_secs(5)), "the agent's own bytes reached the unbound sink: {r}");
    eprintln!("AGENT FLOW AFTER TAINT ({}) PASS", if unix { "unix" } else { "tcp" });
}

#[test]
#[ignore]
fn the_agent_connecting_to_a_holders_tcp_listener_is_an_agent_flow_not_a_holder() {
    run_after_taint(false);
}

#[test]
#[ignore]
fn the_agent_connecting_to_a_holders_unix_listener_is_an_agent_flow_not_a_holder() {
    run_after_taint(true);
}

// ── (2) a keep-alive the agent holds when the server reads its secret ───────

#[test]
#[ignore]
fn a_server_the_agent_is_connected_to_reads_its_secret_raw_and_the_flow_is_recorded() {
    let _g = serial();
    let secret = Secret::new("keepalive");
    let (arbiter, told) = recording_arbiter(false);
    let cfg = secret_cfg(&secret, arbiter);
    let (path, ready, srp, rp) = (secret.path.clone(), secret.file("ready"), secret.file("s.txt"), secret.file("report.txt"));
    let Some(code) = guarded(cfg, move || {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let lfd = l.into_raw_fd();
        // S: untainted when it accepts; reads the secret only on "LOAD".
        let s = fork_run(|| {
            let _ = std::fs::write(&ready, "r");
            let c = unsafe { libc::accept(lfd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if c < 0 {
                return 6;
            }
            let mut b = [0u8; 4];
            let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
            unsafe { libc::setsockopt(c, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of_val(&tv) as u32) };
            if unsafe { libc::read(c, b.as_mut_ptr() as *mut libc::c_void, 4) } != 4 {
                return 7;
            }
            match std::fs::read_to_string(&path) {
                Ok(k) => {
                    write_all(c, k.as_bytes());
                    let _ = std::fs::write(&srp, "ok");
                }
                Err(e) => {
                    write_all(c, b"DENIED");
                    let _ = std::fs::write(&srp, format!("e{}", e.raw_os_error().unwrap_or(-1)));
                }
            }
            unsafe { libc::close(c) };
            0
        });
        unsafe { libc::close(lfd) };
        if !wait_for(&ready) {
            return 5;
        }
        // The agent's keep-alive, opened before the server holds anything.
        let got = match tcp_connect([127, 0, 0, 1], port) {
            Ok(fd) => {
                write_all(fd, b"LOAD");
                let g = read_some(fd);
                unsafe { libc::close(fd) };
                g
            }
            Err(e) => format!("connect={e}"),
        };
        let sc = reap(s);
        let _ = std::fs::write(&rp, format!("got={} s={s} sc={sc:?}", got.contains(CANARY)));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = report(&secret.file("report.txt"));
    let sr = report(&secret.file("s.txt"));
    eprintln!("keep-alive: server={sr} agent: {r}");
    assert_eq!(sr, "ok", "the server's raw open is admitted while the agent holds a connection to it (refused before: the agent's end was judged as an exit)");
    assert!(r.starts_with("got=true "), "{r}");
    let s: i32 = r.split_whitespace().find_map(|kv| kv.strip_prefix("s=")).and_then(|v| v.parse().ok()).unwrap_or(-1);
    assert!(agent_flow_opened(&told, s).is_some(), "the sweep recorded the agent's keep-alive as an agent flow: {:?}", told.lock().unwrap());
    eprintln!("AGENT FLOW KEEP-ALIVE PASS");
}

// ── (3) fail-closed: the record cannot be made ──────────────────────────────

#[test]
#[ignore]
fn an_agent_flow_the_arbiter_cannot_record_resets_the_connection() {
    let _g = serial();
    let secret = Secret::new("fail");
    let (arbiter, told) = recording_arbiter(true);
    let cfg = secret_cfg(&secret, arbiter);
    let (path, ready, hrp, rp) = (secret.path.clone(), secret.file("ready"), secret.file("h.txt"), secret.file("report.txt"));
    let Some(code) = guarded(cfg, move || {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let lfd = l.into_raw_fd();
        let h = fork_run(|| {
            let k = match std::fs::read_to_string(&path) {
                Ok(k) if k.contains(CANARY) => k,
                _ => return 4,
            };
            let _ = std::fs::write(&ready, "r");
            let c = unsafe { libc::accept(lfd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if c < 0 {
                let _ = std::fs::write(&hrp, format!("e{}", errno()));
                return 0;
            }
            write_all(c, k.as_bytes());
            unsafe { libc::close(c) };
            let _ = std::fs::write(&hrp, "ok");
            0
        });
        unsafe { libc::close(lfd) };
        if !wait_for(&ready) {
            return 5;
        }
        let got = match tcp_connect([127, 0, 0, 1], port) {
            Ok(fd) => {
                let s = read_some(fd);
                unsafe { libc::close(fd) };
                s
            }
            Err(e) => format!("connect={e}"),
        };
        reap(h);
        let _ = std::fs::write(&rp, format!("got={}", got.contains(CANARY)));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(report(&secret.file("h.txt")), format!("e{}", libc::ECONNABORTED), "the holder's accept is refused when the flow cannot be recorded");
    assert_eq!(report(&secret.file("report.txt")), "got=false", "the agent received nothing");
    assert!(told.lock().unwrap().iter().any(|(op, _, _, _)| op == "recordAgentFlow"), "the guard tried to record it");
    eprintln!("AGENT FLOW FAIL-CLOSED PASS");
}

// ── (4) the session's net-proxy relays a request to a holder ────────────────

/// A stand-in for the session's net-proxy, in the TEST process (outside the
/// guard's tree, as the launcher's net-proxy is): a client sends
/// `TO <port>\n`; the proxy dials 127.0.0.1:<port>, sends `GET\n`, and relays
/// what that server answers until it closes. Its port is the launch's proxy
/// port (`proxy_ports`).
fn relay_proxy() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the proxy");
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { break };
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                let mut line = Vec::new();
                let mut b = [0u8; 1];
                while c.read(&mut b).map(|n| n == 1).unwrap_or(false) && b[0] != b'\n' {
                    line.push(b[0]);
                }
                let to: u16 = String::from_utf8_lossy(&line).trim().strip_prefix("TO ").and_then(|p| p.parse().ok()).unwrap_or(0);
                if let Ok(mut up) = std::net::TcpStream::connect(("127.0.0.1", to)) {
                    let _ = up.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = up.write_all(b"GET\n");
                    let mut buf = Vec::new();
                    let _ = up.read_to_end(&mut buf);
                    let _ = c.write_all(&buf);
                }
            });
        }
    });
    port
}

/// What the server at `to` answers, asked through the proxy at `proxy`.
fn via_proxy(proxy: u16, to: u16) -> String {
    match tcp_connect([127, 0, 0, 1], proxy) {
        Ok(fd) => {
            write_all(fd, format!("TO {to}\n").as_bytes());
            let s = read_some(fd);
            unsafe { libc::close(fd) };
            s
        }
        Err(e) => format!("connect={e}"),
    }
}

fn any_agent_flow(told: &Told) -> bool {
    told.lock().unwrap().iter().any(|(op, _, _, closed)| op == "recordAgentFlow" && !closed)
}

fn run_proxied(agent_asks: bool) {
    let _g = serial();
    let proxy = relay_proxy();
    let secret = Secret::new(if agent_asks { "proxy-agent" } else { "proxy-tool" });
    let (arbiter, told) = recording_arbiter(false);
    let mut cfg = secret_cfg(&secret, arbiter);
    cfg.proxy_ports = vec![proxy];
    let (path, ready, hrp, rp, qp) = (secret.path.clone(), secret.file("ready"), secret.file("h.txt"), secret.file("report.txt"), secret.file("q.txt"));
    let Some(code) = guarded(cfg, move || {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let lfd = l.into_raw_fd();
        // H: a holder (reads the secret), then answers one connection with it.
        let h = fork_run(|| {
            let k = match std::fs::read_to_string(&path) {
                Ok(k) if k.contains(CANARY) => k,
                _ => return 4,
            };
            let _ = std::fs::write(&ready, "r");
            let c = unsafe { libc::accept(lfd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if c < 0 {
                let _ = std::fs::write(&hrp, format!("e{}", errno()));
                return 0;
            }
            write_all(c, k.as_bytes());
            unsafe { libc::close(c) };
            let _ = std::fs::write(&hrp, "ok");
            0
        });
        unsafe { libc::close(lfd) };
        if !wait_for(&ready) {
            return 5;
        }
        // The agent's fetch (WebFetch through HTTPS_PROXY), or a tool call's
        // `curl` through it: the proxy, not the asker, is the holder's client.
        let got = if agent_asks {
            via_proxy(proxy, port)
        } else {
            let q = fork_run(|| {
                let g = via_proxy(proxy, port);
                let _ = std::fs::write(&qp, g);
                0
            });
            reap(q);
            std::fs::read_to_string(&qp).unwrap_or_default()
        };
        reap(h);
        let _ = std::fs::write(&rp, format!("got={}", got.contains(CANARY)));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let (hr, r) = (report(&secret.file("h.txt")), report(&secret.file("report.txt")));
    let who = if agent_asks { "the agent" } else { "a tool process" };
    eprintln!("proxied ({who}): holder={hr} asker: {r}");
    assert_eq!(r, "got=false", "CONFIDENTIALITY VIOLATION: {who} received a holder's bytes through the session's net-proxy (re-originated outside the guard's tree, never attributed): holder={hr}");
    assert_eq!(hr, format!("e{}", libc::ECONNABORTED), "the holder's accept of a connection the proxy holds is reset");
    assert!(!any_agent_flow(&told), "no flow is recorded: the proxy's asker cannot be told: {:?}", told.lock().unwrap());
    eprintln!("PROXIED ({who}) REFUSED PASS");
}

#[test]
#[ignore]
fn the_agents_request_relayed_by_the_session_net_proxy_to_a_holder_is_refused_at_the_holders_accept() {
    run_proxied(true);
}

#[test]
#[ignore]
fn a_tool_processs_request_relayed_by_the_session_net_proxy_to_a_holder_is_refused_at_the_holders_accept() {
    run_proxied(false);
}

#[test]
#[ignore]
fn a_server_holding_a_proxied_connection_is_refused_its_raw_open_even_where_its_bindings_admit_this_machine() {
    let _g = serial();
    let proxy = relay_proxy();
    let secret = Secret::new("proxy-sweep");
    // The secret is bound to this machine: the sweep's exit check alone
    // admits the proxy's end of the connection (127.0.0.1, any port).
    let (arbiter, told) = recording_arbiter_bound(false, &["127.0.0.1"]);
    let mut cfg = secret_cfg(&secret, arbiter);
    cfg.proxy_ports = vec![proxy];
    let (path, ready, srp, rp) = (secret.path.clone(), secret.file("ready"), secret.file("s.txt"), secret.file("report.txt"));
    let Some(code) = guarded(cfg, move || {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let lfd = l.into_raw_fd();
        // S: takes the proxy's connection while it holds nothing, then reads
        // its secret and answers with it.
        let s = fork_run(|| {
            let _ = std::fs::write(&ready, "r");
            let c = unsafe { libc::accept(lfd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if c < 0 {
                return 6;
            }
            let mut b = [0u8; 4];
            let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
            unsafe { libc::setsockopt(c, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of_val(&tv) as u32) };
            if unsafe { libc::read(c, b.as_mut_ptr() as *mut libc::c_void, 4) } != 4 {
                return 7;
            }
            match std::fs::read_to_string(&path) {
                Ok(k) => {
                    write_all(c, k.as_bytes());
                    let _ = std::fs::write(&srp, "ok");
                }
                Err(e) => {
                    write_all(c, b"DENIED");
                    let _ = std::fs::write(&srp, format!("e{}", e.raw_os_error().unwrap_or(-1)));
                }
            }
            unsafe { libc::close(c) };
            0
        });
        unsafe { libc::close(lfd) };
        if !wait_for(&ready) {
            return 5;
        }
        let got = via_proxy(proxy, port);
        reap(s);
        let _ = std::fs::write(&rp, format!("got={}", got.contains(CANARY)));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let (sr, r) = (report(&secret.file("s.txt")), report(&secret.file("report.txt")));
    eprintln!("proxied sweep: server={sr} agent: {r}");
    assert_eq!(r, "got=false", "CONFIDENTIALITY VIOLATION: a server holding a connection the net-proxy relays read its secret and the proxy relayed it: server={sr}");
    assert_eq!(sr, format!("e{}", libc::EACCES), "the raw open is refused while the server holds a connection the proxy relays");
    assert!(!any_agent_flow(&told));
    eprintln!("PROXIED SWEEP REFUSED PASS");
}

// ── (5) where the accept is not judged (the old-kernel degrade) ─────────────

fn untrapped() -> FilterTraps {
    FilterTraps { open: true, secrets: true, no_sends: true, ..Default::default() }
}

#[test]
#[ignore]
fn where_the_accept_is_not_judged_the_agents_connect_to_a_holder_is_recorded_at_the_connect() {
    run_after_taint_with(false, untrapped());
}

#[test]
#[ignore]
fn where_the_accept_is_not_judged_the_agents_connection_in_a_holders_backlog_is_recorded_at_the_taint() {
    let _g = serial();
    let secret = Secret::new("backlog");
    let (arbiter, told) = recording_arbiter(false);
    let mut cfg = secret_cfg(&secret, arbiter);
    cfg.accepts_untrapped = true;
    let (path, ready, conn, srp, rp) = (secret.path.clone(), secret.file("ready"), secret.file("conn"), secret.file("s.txt"), secret.file("report.txt"));
    let Some(code) = guarded_with(untrapped(), cfg, move || {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let lfd = l.into_raw_fd();
        // S: holds nothing while the agent's connection waits in its
        // backlog; reads its secret (the taint), then accepts and answers.
        let s = fork_run(|| {
            let _ = std::fs::write(&ready, "r");
            if !wait_for(&conn) {
                return 6;
            }
            let k = match std::fs::read_to_string(&path) {
                Ok(k) => k,
                Err(e) => {
                    let _ = std::fs::write(&srp, format!("e{}", e.raw_os_error().unwrap_or(-1)));
                    return 0;
                }
            };
            let c = unsafe { libc::accept(lfd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if c < 0 {
                let _ = std::fs::write(&srp, format!("a{}", errno()));
                return 0;
            }
            write_all(c, k.as_bytes());
            unsafe { libc::close(c) };
            let _ = std::fs::write(&srp, "ok");
            0
        });
        unsafe { libc::close(lfd) };
        if !wait_for(&ready) {
            return 5;
        }
        let got = match tcp_connect([127, 0, 0, 1], port) {
            Ok(fd) => {
                let _ = std::fs::write(&conn, "c");
                let g = read_some(fd);
                unsafe { libc::close(fd) };
                g
            }
            Err(e) => format!("connect={e}"),
        };
        reap(s);
        let _ = std::fs::write(&rp, format!("got={} s={s}", got.contains(CANARY)));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let (sr, r) = (report(&secret.file("s.txt")), report(&secret.file("report.txt")));
    eprintln!("backlog: server={sr} agent: {r}");
    assert_eq!(sr, "ok", "the server's raw open is admitted");
    assert!(r.starts_with("got=true "), "precondition: the agent received the reply: {r}");
    let s: i32 = r.split_whitespace().find_map(|kv| kv.strip_prefix("s=")).and_then(|v| v.parse().ok()).unwrap_or(-1);
    assert!(agent_flow_opened(&told, s).is_some(), "the taint-time sweep recorded the agent's connection waiting in the holder's backlog: {:?}", told.lock().unwrap());
    eprintln!("AGENT FLOW BACKLOG PASS");
}

// ── (6) a FIFO a holder writes and the agent itself reads ───────────────────

fn mkfifo(p: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
}

fn open_path(p: &Path, flags: i32) -> Result<RawFd, i32> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd >= 0 { Ok(fd) } else { Err(errno()) }
}

/// Read until EOF after some data, or the canary, or until `writer_done()`
/// held before a read that found nothing (the writer is finished: whatever
/// it wrote was in the pipe by then), within the run's wait limit. A
/// non-blocking FIFO with no writer yet answers EOF at once: waited through.
///
/// The reader keeps its end open until the writer is done. With a fixed
/// 5 s instead (until 2026-10-21), a holder slower than that under load
/// (CI job 18268: its secret read alone took over 7 s) made its blocking
/// `O_WRONLY` open after the agent had closed the FIFO's only read end; the
/// open then waits for a reader forever, as it does with no guard (the
/// guard performs it in a worker, `wait_for_partner`), and the test hung
/// until the 240 s limit killed it.
fn drain(fd: RawFd, writer_done: impl Fn() -> bool) -> String {
    let deadline = std::time::Instant::now() + wait_limit();
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let done = writer_done();
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            out.extend_from_slice(&buf[..n as usize]);
            if out.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()) {
                break;
            }
            continue;
        }
        if (n == 0 && !out.is_empty()) || done || std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// How the agent and the holder meet at the FIFO.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FifoOrder {
    /// The holder (already a holder) opens to write first and blocks; the
    /// agent's blocking read-open completes both.
    HolderFirst,
    /// The agent opens to read first (non-blocking); the holder then opens to
    /// write.
    AgentFirst,
    /// Both hold the FIFO when the writer reads its secret (the sweep).
    AtTheTaint,
}

fn run_fifo(order: FifoOrder, record_fails: bool) {
    let _g = serial();
    let secret = Secret::new(&format!("fifo-{order:?}-{record_fails}").to_lowercase());
    let mark = close_mark(&secret);
    let (arbiter, told) = recording_arbiter_marking(record_fails, &mark);
    let cfg = secret_cfg(&secret, arbiter);
    let fifo = secret.file("pipe.fifo");
    mkfifo(&fifo);
    let (path, ready, opened, hrp, rp, ff) = (secret.path.clone(), secret.file("ready"), secret.file("opened"), secret.file("h.txt"), secret.file("report.txt"), fifo.clone());
    let Some(code) = guarded(cfg, move || {
        // The holder is done (it wrote its report): the agent stops reading.
        let h_done = { let hrp = hrp.clone(); move || hrp.exists() };
        let agent_fd = if order == FifoOrder::HolderFirst { None } else { Some(open_path(&ff, libc::O_RDONLY | libc::O_NONBLOCK)) };
        let inherited = agent_fd.as_ref().and_then(|r| r.as_ref().ok().copied());
        let f2 = ff.clone();
        let ready2 = ready.clone();
        // H: reads the secret (before or, at the taint, after its own FIFO
        // write-open), then writes it into the FIFO. It drops the copy of
        // the agent's read end the fork gave it (a writer does not read).
        let h = fork_run(move || {
            if let Some(fd) = inherited {
                unsafe { libc::close(fd) };
            }
            let read_secret = || std::fs::read_to_string(&path).ok().filter(|k| k.contains(CANARY));
            let (k, w) = if order == FifoOrder::AtTheTaint {
                let w = open_path(&f2, libc::O_WRONLY);
                let _ = std::fs::write(&opened, "o");
                (read_secret(), w)
            } else {
                let k = read_secret();
                let _ = std::fs::write(&ready2, "r");
                (k, open_path(&f2, libc::O_WRONLY))
            };
            let Some(k) = k else {
                let _ = std::fs::write(&hrp, "nosecret");
                return 0;
            };
            match w {
                Ok(w) => {
                    write_all(w, k.as_bytes());
                    unsafe { libc::close(w) };
                    let _ = std::fs::write(&hrp, "ok");
                }
                Err(e) => {
                    let _ = std::fs::write(&hrp, format!("e{e}"));
                }
            }
            0
        });
        let got = match agent_fd {
            None => {
                if !wait_for(&ready) {
                    return 5;
                }
                match open_path(&ff, libc::O_RDONLY) {
                    Ok(fd) => {
                        let g = drain(fd, &h_done);
                        unsafe { libc::close(fd) };
                        g
                    }
                    Err(e) => format!("open={e}"),
                }
            }
            Some(Ok(fd)) => {
                let g = drain(fd, &h_done);
                unsafe { libc::close(fd) };
                g
            }
            Some(Err(e)) => format!("open={e}"),
        };
        // The guard's look reports the dropped channel (every 200 ms).
        if got.contains(CANARY) {
            wait_close_reported(&mark);
        }
        reap(h);
        let _ = std::fs::write(&rp, format!("got={} h={h} out={got}", got.contains(CANARY)));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let (hr, r) = (report(&secret.file("h.txt")), report(&secret.file("report.txt")));
    eprintln!("fifo {order:?} record_fails={record_fails}: holder={hr} agent: {r}");
    let h: i32 = r.split_whitespace().find_map(|kv| kv.strip_prefix("h=")).and_then(|v| v.parse().ok()).unwrap_or(-1);
    if record_fails {
        assert!(r.starts_with("got=false "), "fail-closed: a FIFO flow that cannot be recorded reaches the agent no byte: {r} holder={hr}");
        assert!(told.lock().unwrap().iter().any(|(op, _, _, _)| op == "recordAgentFlow"), "the guard tried to record it");
        eprintln!("AGENT FIFO ({order:?}) FAIL-CLOSED PASS");
        return;
    }
    assert!(r.starts_with("got=true "), "precondition: the agent read the holder's bytes from the FIFO (so the model exit must mask them): {r} holder={hr}");
    let channel = agent_flow_opened(&told, h).unwrap_or_else(|| panic!("CONFIDENTIALITY GAP: the agent read a FIFO the holder {h} writes and no agent flow was recorded: {:?}", told.lock().unwrap()));
    assert_eq!(channel, fifo.to_str().unwrap(), "the channel is the FIFO the agent holds");
    assert!(agent_flow_closed(&told, &channel), "the dropped FIFO was reported closed: {:?}", told.lock().unwrap());
    eprintln!("AGENT FIFO ({order:?}) PASS");
}

#[test]
#[ignore]
fn the_agent_reading_a_fifo_a_holder_opened_to_write_is_an_agent_flow() {
    run_fifo(FifoOrder::HolderFirst, false);
}

#[test]
#[ignore]
fn a_holder_opening_a_fifo_the_agent_already_reads_records_an_agent_flow() {
    run_fifo(FifoOrder::AgentFirst, false);
}

#[test]
#[ignore]
fn a_writer_of_a_fifo_the_agent_reads_that_then_reads_its_secret_records_an_agent_flow_at_the_sweep() {
    run_fifo(FifoOrder::AtTheTaint, false);
}

#[test]
#[ignore]
fn an_agent_fifo_flow_the_arbiter_cannot_record_reaches_the_agent_no_byte() {
    run_fifo(FifoOrder::HolderFirst, true);
    run_fifo(FifoOrder::AgentFirst, true);
}

#[test]
#[ignore]
fn where_the_accept_is_not_judged_an_agent_flow_the_arbiter_cannot_record_refuses_the_agents_connect() {
    let _g = serial();
    let secret = Secret::new("untrapped-fail");
    let (arbiter, told) = recording_arbiter(true);
    let mut cfg = secret_cfg(&secret, arbiter);
    cfg.accepts_untrapped = true;
    let (path, ready, hrp, rp) = (secret.path.clone(), secret.file("ready"), secret.file("h.txt"), secret.file("report.txt"));
    let Some(code) = guarded_with(untrapped(), cfg, move || {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let lfd = l.into_raw_fd();
        let h = fork_run(|| {
            let k = match std::fs::read_to_string(&path) {
                Ok(k) if k.contains(CANARY) => k,
                _ => return 4,
            };
            // Wait 2 s at most for a connection (none should come).
            let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
            unsafe { libc::setsockopt(lfd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of_val(&tv) as u32) };
            let _ = std::fs::write(&ready, "r");
            let c = unsafe { libc::accept(lfd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if c < 0 {
                let _ = std::fs::write(&hrp, format!("e{}", errno()));
                return 0;
            }
            write_all(c, k.as_bytes());
            unsafe { libc::close(c) };
            let _ = std::fs::write(&hrp, "ok");
            0
        });
        unsafe { libc::close(lfd) };
        if !wait_for(&ready) {
            return 5;
        }
        let got = match tcp_connect([127, 0, 0, 1], port) {
            Ok(fd) => {
                let s = read_some(fd);
                unsafe { libc::close(fd) };
                s
            }
            Err(e) => format!("connect={e}"),
        };
        reap(h);
        let _ = std::fs::write(&rp, format!("got={} {got}", got.contains(CANARY)));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = report(&secret.file("report.txt"));
    eprintln!("untrapped fail-closed: holder={} agent: {r}", report(&secret.file("h.txt")));
    assert!(r.starts_with("got=false "), "the agent received nothing: {r}");
    assert!(r.contains(&format!("connect={}", libc::EACCES)), "the agent's connect is refused when its flow cannot be recorded: {r}");
    assert!(told.lock().unwrap().iter().any(|(op, _, _, _)| op == "recordAgentFlow"), "the guard tried to record it");
    eprintln!("AGENT FLOW UNTRAPPED FAIL-CLOSED PASS");
}

// ── (7) a file the agent itself holds open while a holder writes it ─────────

/// The agent opened `f` to read (its file tool, a `tail`-like read in
/// progress) before a holder writes it: at the holder's write-open after its
/// taint (`at_taint` false), or at the taint of a writer that held it open
/// for writing before (`at_taint` true). Read through a hard link, so the
/// path the label takes is not the agent's.
fn run_held_file(at_taint: bool, record_fails: bool) {
    let _g = serial();
    let secret = Secret::new(&format!("held-file-{at_taint}-{record_fails}"));
    let mark = close_mark(&secret);
    let (arbiter, told) = recording_arbiter_marking(record_fails, &mark);
    let cfg = secret_cfg(&secret, arbiter);
    let file = secret.file("app.log");
    std::fs::write(&file, "start\n").unwrap();
    let link = secret.file("view.log");
    std::fs::hard_link(&file, &link).unwrap();
    let (path, opened, hrp, rp, f2, l2) = (secret.path.clone(), secret.file("opened"), secret.file("h.txt"), secret.file("report.txt"), file.clone(), link.clone());
    let Some(code) = guarded(cfg, move || {
        // The agent's read descriptor, by the other link, before anything.
        let afd = match open_path(&l2, libc::O_RDONLY) {
            Ok(fd) => fd,
            Err(e) => return 10 + e.min(80),
        };
        let h = fork_run(move || {
            unsafe { libc::close(afd) };
            let read_secret = || std::fs::read_to_string(&path).ok().filter(|k| k.contains(CANARY));
            let (k, w) = if at_taint {
                let w = open_path(&f2, libc::O_WRONLY | libc::O_APPEND);
                let _ = std::fs::write(&opened, "o");
                (read_secret(), w)
            } else {
                let k = read_secret();
                (k, open_path(&f2, libc::O_WRONLY | libc::O_APPEND))
            };
            let Some(k) = k else {
                let _ = std::fs::write(&hrp, "nosecret");
                return 0;
            };
            match w {
                Ok(w) => {
                    write_all(w, k.as_bytes());
                    unsafe { libc::close(w) };
                    let _ = std::fs::write(&hrp, "ok");
                }
                Err(e) => {
                    let _ = std::fs::write(&hrp, format!("e{e}"));
                }
            }
            0
        });
        reap(h);
        // The holder was reaped: what it wrote is in the file.
        let got = drain(afd, || true);
        // The guard's look reports the dropped channel (every 200 ms).
        unsafe { libc::close(afd) };
        if got.contains(CANARY) {
            wait_close_reported(&mark);
        }
        let _ = std::fs::write(&rp, format!("got={} h={h}", got.contains(CANARY)));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let (hr, r) = (report(&secret.file("h.txt")), report(&secret.file("report.txt")));
    eprintln!("held file at_taint={at_taint} record_fails={record_fails}: holder={hr} agent: {r}");
    let h: i32 = r.split_whitespace().find_map(|kv| kv.strip_prefix("h=")).and_then(|v| v.parse().ok()).unwrap_or(-1);
    if record_fails {
        assert!(r.starts_with("got=false "), "fail-closed: a flow that cannot be recorded reaches the agent no byte: {r} holder={hr}");
        assert!(told.lock().unwrap().iter().any(|(op, _, _, _)| op == "recordAgentFlow"), "the guard tried to record it");
        eprintln!("AGENT HELD FILE (at_taint={at_taint}) FAIL-CLOSED PASS");
        return;
    }
    assert!(r.starts_with("got=true "), "precondition: the agent read the holder's bytes through its own descriptor: {r} holder={hr}");
    let channel = agent_flow_opened(&told, h).unwrap_or_else(|| panic!("CONFIDENTIALITY GAP: the agent read a file the holder {h} wrote through a descriptor it held, and no agent flow was recorded: {:?}", told.lock().unwrap()));
    assert_eq!(channel, link.to_str().unwrap(), "the channel is the agent's own link to the file");
    assert!(agent_flow_closed(&told, &channel), "the dropped file was reported closed: {:?}", told.lock().unwrap());
    eprintln!("AGENT HELD FILE (at_taint={at_taint}) PASS");
}

#[test]
#[ignore]
fn a_holder_writing_a_file_the_agent_already_reads_records_an_agent_flow() {
    run_held_file(false, false);
}

#[test]
#[ignore]
fn a_writer_of_a_file_the_agent_reads_that_then_reads_its_secret_records_an_agent_flow_at_the_sweep() {
    run_held_file(true, false);
}

#[test]
#[ignore]
fn an_agent_file_flow_the_arbiter_cannot_record_refuses_the_write() {
    run_held_file(false, true);
}
