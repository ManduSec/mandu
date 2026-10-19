//! taint_gaps_integration — the taint leg's open gaps of exec-routing.md
//! §7.5 ("What remains uncovered", 2026-10-01), closed 2026-10-02, each with
//! its control.
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! (an unprivileged user + network + pid namespace; `lo` is brought up
//! here). A host where the seccomp listener cannot be installed SKIPs.
//!
//!   (a) a holder's ACCEPT: a connection from another machine (here, a
//!       second address on `lo` that is not the connection's own) is reset
//!       and the call answers ECONNABORTED; one from this machine, or from a
//!       bound host, is taken; an accept already waiting when the process
//!       becomes a holder is judged too; an untainted server is unchanged
//!       (flags, the peer's address);
//!   (b) a socket PASSED to a holder over SCM_RIGHTS: refused at its sender
//!       when its peer is unbound (EACCES), passed when bound or harmless; one
//!       queued before the taint refuses the raw open;
//!   (c) a UNIX socket connected before the taint to a named peer refuses
//!       the raw open, unless the peer is a `unix:` binding;
//!   (d) a FORK after the taint: a child that outlives its holder stays a
//!       holder (the orphan backstop), whether the holder exited or was
//!       killed, also under a subreaper the tree made. (The fork family is
//!       not trapped — that would destabilize the bubblewrap wrap; a
//!       `CLONE_PARENT`/`clone3` sibling is refused in the filter instead,
//!       clone_filter_integration.rs, §7.5 gap (d).)
//!   (e) a UNIX CONNECT in a posture without the allow-list: a thread that
//!       swaps an INET socket under the descriptor reaches no unjudged
//!       destination.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, pipe, read_to_end_within, readable_within, reap_within, run_tag, socketpair, wait_limit};

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mandu_arbiter::mock::{op_handler, MockArbiter};
use net_supervisor::guard::{parse_rules, GuardPolicy, NoResolver};
use net_supervisor::guard_kernel::{
    hand_listener, install_guard_filter_self, receive_listener, run_guard_supervisor, FilterTraps,
    GuardConfig,
};

const EXIT_NO_SECCOMP: i32 = 91;
const CANARY: &str = "GAPS-CANARY-5521";

// ── plumbing (as send_integration.rs) ───────────────────────────────────────

fn lo_up() {
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .stderr(std::process::Stdio::null())
        .status();
}

/// A second address on `lo` that is no connection's own: a stand-in for
/// another machine (a connection from it to the first is not from "this
/// machine" by the accept rule). False where it cannot be added.
fn lo_addr(ip: &str) -> bool {
    let _ = std::process::Command::new("ip")
        .args(["addr", "add", &format!("{ip}/32"), "dev", "lo"])
        .stderr(std::process::Stdio::null())
        .status();
    std::net::TcpListener::bind(format!("{ip}:0")).is_ok()
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn udp_listener(ip: [u8; 4], port: u16) -> UdpSocket {
    let s =
        UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::from(ip), port)).expect("bind udp listener");
    s.set_nonblocking(true).unwrap();
    s
}

fn drain(s: &UdpSocket) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    let end = Instant::now() + Duration::from_millis(200);
    while Instant::now() < end {
        match s.recv(&mut buf) {
            Ok(n) => out.push(buf[..n].to_vec()),
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    out
}

/// A TCP listener whose accepted connections are read into a shared buffer.
fn tcp_listener(ip: [u8; 4]) -> (u16, Arc<Mutex<Vec<u8>>>) {
    let l = std::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::from(ip), 0))
        .expect("bind tcp listener");
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
    libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip),
        },
        sin_zero: [0; 8],
    }
}

fn sendto(fd: RawFd, data: &[u8], ip: [u8; 4], port: u16) -> isize {
    let a = sin(ip, port);
    // SAFETY: sendto with a stack sockaddr.
    let n = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            &a as *const _ as *const libc::sockaddr,
            16,
        )
    };
    if n < 0 {
        -(errno() as isize)
    } else {
        n
    }
}

fn udp_socket() -> RawFd {
    unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) }
}

fn connect(fd: RawFd, ip: [u8; 4], port: u16) -> i32 {
    let a = sin(ip, port);
    if unsafe { libc::connect(fd, &a as *const _ as *const libc::sockaddr, 16) } == 0 {
        0
    } else {
        errno()
    }
}

fn tcp_connect(ip: [u8; 4], port: u16) -> Result<RawFd, i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    match connect(fd, ip, port) {
        0 => Ok(fd),
        e => {
            unsafe { libc::close(fd) };
            Err(e)
        }
    }
}

fn write_all(fd: RawFd, data: &[u8]) -> isize {
    unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) }
}

fn read_file(p: &Path) -> Result<String, i32> {
    std::fs::read_to_string(p).map_err(|e| e.raw_os_error().unwrap_or(-1))
}

/// `fd` read to its end. In the test process under a deadline (its writers
/// are the guarded tree and the orphans it leaves, adopted here).
fn read_string(fd: RawFd) -> String {
    if in_test_process() {
        return String::from_utf8_lossy(&read_to_end_within(fd, wait_limit(), "reading a report pipe to its end (its writers: the guarded tree and the orphans it left)")).into_owned();
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    String::from_utf8_lossy(&out).into_owned()
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

struct Secret {
    dir: PathBuf,
    path: PathBuf,
    policy: PathBuf,
}

impl Secret {
    fn new(tag: &str) -> Secret {
        let dir = std::env::temp_dir().join(format!("mandu-gaps-{tag}-{}", run_tag()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.env");
        let twin = dir.join("twin.env");
        std::fs::write(&path, format!("API_KEY={CANARY}\n")).unwrap();
        std::fs::write(&twin, "API_KEY=$MDU:twin\n").unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(&policy, format!(r#"{{"agentExe":"","ask":"never","session":"gaps","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, path.display(), twin.display())).unwrap();
        Secret { dir, path, policy }
    }
    fn report(&self) -> PathBuf {
        self.dir.join("report.txt")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Every opener is a reader (raw); a holder's bindings are `bindings`.
/// Leaked on purpose (send_integration.rs `reader_arbiter`).
fn reader_arbiter(bindings: Vec<String>) -> &'static MockArbiter {
    MockArbiter::start(op_handler(
        move |op, _req| match op {
            "decideSecretOpen" => Ok(
                serde_json::json!({ "verdict": "raw", "app": "test", "level": "no-model", "reason": "mock reader" }),
            ),
            "taintedProcessBindings" => Ok(
                serde_json::json!({ "tainted": true, "level": "no-model", "files": ["secret.env"], "bindings": bindings }),
            ),
            _ => Ok(serde_json::Value::Null),
        },
    )).leak()
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

/// The tests share the test process, and so its tree: one at a time
/// (2026-10-10). The guard here is this process, the subreaper of every
/// test's processes, so another test's children are children of the reaper
/// it sees, orphan roots by its rule: one born while a holder lived is
/// adopted as that holder's orphan at its death (fail-closed), and a later
/// orphan root born while the adopted process lived is judged its orphan.
/// Round (a) of the orphan window failed so in 15 of 132 CI runs (8 of 200
/// in a loaded VM, each time a process of another test, born in the tick
/// of the holder's death stamp, adopted).
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Run `body` in a forked child under the guard's filter, served by the
/// real supervisor loop with `cfg`, the child keeping `keep` open; the
/// child's exit code (None: killed), or None to SKIP.
fn guarded_keep(
    traps: FilterTraps,
    cfg: GuardConfig,
    keep: &[RawFd],
    body: impl FnOnce() -> i32,
) -> Option<Option<i32>> {
    lo_up();
    let (sup, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let mut k = keep.to_vec();
        k.push(child_sock);
        close_all_but(&k);
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
            assert_eq!(
                reap(child),
                Some(EXIT_NO_SECCOMP),
                "the tracee could not hand over its listener"
            );
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

fn guarded(
    traps: FilterTraps,
    cfg: GuardConfig,
    body: impl FnOnce() -> i32,
) -> Option<Option<i32>> {
    guarded_keep(traps, cfg, &[], body)
}

fn static_cfg(rules: &[&str]) -> GuardConfig {
    let specs: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
    GuardConfig::new(
        Arc::new(GuardPolicy::new(parse_rules(&specs).unwrap())),
        Arc::new(NoResolver),
    )
}

/// Secrets mode: the secret registered, the mock arbiter wired, every
/// address the tests use allowed by the static list (the taint leg is what
/// is under test).
fn secret_cfg(secret: &Secret, arbiter: &MockArbiter) -> GuardConfig {
    let mut cfg = static_cfg(&["any:127.0.0.0/8:*", "any:10.77.1.0/24:*"]);
    cfg.secrets = Some(Arc::new(
        net_supervisor::secret_open::SecretIndex::load(&secret.policy).unwrap(),
    ));
    cfg.emitter = Some(Arc::new(Mutex::new(mandu_arbiter::ArbiterClient::new(
        &arbiter.socket_path,
    ))));
    cfg.proxy_ports = vec![1];
    cfg
}

fn secret_traps() -> FilterTraps {
    FilterTraps {
        open: true,
        secrets: true,
        ..Default::default()
    }
}

fn report_of(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// A TCP connection to `dst:port` from `src` (bound first); what it reads
/// until the server closes it, or the errno.
fn fetch_from(src: [u8; 4], dst: [u8; 4], port: u16) -> Result<String, String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let s = sin(src, 0);
    if unsafe { libc::bind(fd, &s as *const _ as *const libc::sockaddr, 16) } != 0 {
        return Err(format!("bind {}", errno()));
    }
    let tv = libc::timeval {
        tv_sec: 3,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of_val(&tv) as u32,
        )
    };
    let e = connect(fd, dst, port);
    if e != 0 {
        unsafe { libc::close(fd) };
        return Err(format!("connect {e}"));
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    let r = loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            break Err(format!("read {}", errno()));
        }
        if n == 0 {
            break Ok(String::from_utf8_lossy(&out).into_owned());
        }
        out.extend_from_slice(&buf[..n as usize]);
    };
    unsafe { libc::close(fd) };
    r
}

// ── (a) a holder's accept ───────────────────────────────────────────────────

/// A server in the guarded tree: listens on 0.0.0.0, reports its port on
/// `port_wr`, reads the secret when `read_secret` (then reports "r"), and
/// answers each of `n` accepts with the secret (or LIVE), recording each
/// accept's result.
fn serve_n(path: PathBuf, read_secret: bool, n: usize, port_wr: RawFd, rp: PathBuf) -> i32 {
    let l = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            l,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            4,
        )
    };
    let a = sin([0, 0, 0, 0], 0);
    if unsafe { libc::bind(l, &a as *const _ as *const libc::sockaddr, 16) } != 0
        || unsafe { libc::listen(l, 16) } != 0
    {
        return 3;
    }
    let mut got: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = 16u32;
    unsafe { libc::getsockname(l, &mut got as *mut _ as *mut libc::sockaddr, &mut len) };
    let port = u16::from_be(got.sin_port);
    let answer = if read_secret {
        match read_file(&path) {
            Ok(k) if k.contains(CANARY) => k,
            _ => return 4,
        }
    } else {
        "LIVE-SERVER".to_string()
    };
    write_all(port_wr, &port.to_ne_bytes());
    let mut results = Vec::new();
    while results.len() < n {
        let c = unsafe { libc::accept(l, std::ptr::null_mut(), std::ptr::null_mut()) };
        if c < 0 {
            results.push(format!("e{}", errno()));
            continue;
        }
        write_all(c, answer.as_bytes());
        unsafe { libc::close(c) };
        results.push("ok".into());
    }
    let _ = std::fs::write(&rp, results.join(","));
    0
}

#[test]
#[ignore]
fn a_holders_accept_takes_this_machine_and_its_bindings_only() {
    let _serial = serial();
    lo_up();
    if !(lo_addr("10.77.1.1") && lo_addr("10.77.1.2")) {
        eprintln!("SKIP: no second address on lo here");
        return;
    }
    let (here, other) = ([10, 77, 1, 1], [10, 77, 1, 2]);
    // Unbound: the other machine is refused, this machine is served.
    for (bindings, remote_ok) in [(vec![], false), (vec!["10.77.1.2".to_string()], true)] {
        let secret = Secret::new(if remote_ok { "accept-bound" } else { "accept" });
        let arbiter = reader_arbiter(bindings);
        let cfg = secret_cfg(&secret, arbiter);
        let (pr, pw) = pipe();
        let (path, rp) = (secret.path.clone(), secret.report());
        let fetches = std::thread::spawn(move || {
            let mut p = [0u8; 2];
            unsafe { libc::read(pr, p.as_mut_ptr() as *mut libc::c_void, 2) };
            let port = u16::from_ne_bytes(p);
            let remote = fetch_from(other, here, port);
            let local = fetch_from([127, 0, 0, 1], [127, 0, 0, 1], port);
            (remote, local)
        });
        let Some(code) = guarded_keep(secret_traps(), cfg, &[pw], move || {
            serve_n(path, true, 2, pw, rp)
        }) else {
            return;
        };
        let (remote, local) = join_within(fetches, wait_limit(), "the fetching thread (it waits for the guarded server's port)").unwrap();
        let seen = report_of(&secret.report());
        eprintln!("bindings? {remote_ok}: accepts={seen} remote={remote:?} local={local:?}");
        assert_eq!(code, Some(0), "{seen}");
        if remote_ok {
            assert!(
                remote.as_deref().unwrap_or("").contains(CANARY),
                "a bound host is served: {remote:?}"
            );
            assert_eq!(seen, "ok,ok");
        } else {
            assert!(
                !remote.as_deref().unwrap_or("").contains(CANARY),
                "THE LEAK: another machine got the secret: {remote:?}"
            );
            assert_eq!(
                seen,
                format!("e{},ok", libc::ECONNABORTED),
                "the refused accept answers ECONNABORTED, then the next is served"
            );
        }
        assert!(
            local.as_deref().unwrap_or("").contains(CANARY),
            "this machine (the browser, the agent's curl) is served: {local:?}"
        );
    }
    // Control: an untainted server answers the other machine.
    let secret = Secret::new("accept-live");
    let arbiter = reader_arbiter(vec![]);
    let cfg = secret_cfg(&secret, arbiter);
    let (pr, pw) = pipe();
    let rp = secret.report();
    let path = secret.path.clone();
    let fetch = std::thread::spawn(move || {
        let mut p = [0u8; 2];
        unsafe { libc::read(pr, p.as_mut_ptr() as *mut libc::c_void, 2) };
        fetch_from(other, here, u16::from_ne_bytes(p))
    });
    let Some(code) = guarded_keep(secret_traps(), cfg, &[pw], move || {
        serve_n(path, false, 1, pw, rp)
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(
        join_within(fetch, wait_limit(), "the fetching thread (it waits for the guarded server's port)").unwrap().as_deref(),
        Ok("LIVE-SERVER"),
        "control: an untainted server is reached"
    );
    eprintln!("HOLDER ACCEPT PASS");
}

#[test]
#[ignore]
fn an_accept_waiting_when_the_taint_lands_is_judged() {
    let _serial = serial();
    // A thread blocks in accept while the process holds nothing; another
    // thread then reads the secret. The connection that comes afterwards
    // reaches a holder: refused.
    lo_up();
    if !(lo_addr("10.77.1.1") && lo_addr("10.77.1.2")) {
        eprintln!("SKIP: no second address on lo here");
        return;
    }
    let secret = Secret::new("accept-race");
    let arbiter = reader_arbiter(vec![]);
    let cfg = secret_cfg(&secret, arbiter);
    let (pr, pw) = pipe();
    let (path, rp) = (secret.path.clone(), secret.report());
    let fetch = std::thread::spawn(move || {
        let mut p = [0u8; 2];
        unsafe { libc::read(pr, p.as_mut_ptr() as *mut libc::c_void, 2) };
        fetch_from([10, 77, 1, 2], [10, 77, 1, 1], u16::from_ne_bytes(p))
    });
    let Some(code) = guarded_keep(secret_traps(), cfg, &[pw], move || {
        let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = l.local_addr().unwrap().port();
        use std::os::unix::io::AsRawFd;
        let lfd = l.as_raw_fd();
        let acceptor = std::thread::spawn(move || {
            let c = unsafe { libc::accept(lfd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if c < 0 {
                return format!("e{}", errno());
            }
            // A holder by now: what it would send.
            write_all(c, CANARY.as_bytes());
            "ok".to_string()
        });
        std::thread::sleep(Duration::from_millis(300));
        let k = read_file(&path).unwrap_or_default();
        if !k.contains(CANARY) {
            return 4;
        }
        write_all(pw, &port.to_ne_bytes());
        let r = acceptor.join().unwrap();
        let _ = std::fs::write(&rp, r);
        drop(l);
        0
    }) else {
        return;
    };
    let remote = join_within(fetch, wait_limit(), "the fetching thread (it waits for the guarded server's port)").unwrap();
    let seen = report_of(&secret.report());
    eprintln!("accept={seen} remote={remote:?}");
    assert_eq!(code, Some(0));
    assert_eq!(
        seen,
        format!("e{}", libc::ECONNABORTED),
        "the accept that waited is judged as a holder's"
    );
    assert!(
        !remote.as_deref().unwrap_or("").contains(CANARY),
        "THE LEAK: {remote:?}"
    );
    eprintln!("ACCEPT RACE PASS");
}

#[test]
#[ignore]
fn an_untainted_accept_is_unchanged_flags_and_address_included() {
    let _serial = serial();
    lo_up();
    let cfg = static_cfg(&["any:127.0.0.0/8:*"]);
    let mut cfg = cfg;
    // A secret policy (the accept trap is on), nothing read.
    let secret = Secret::new("accept-flags");
    cfg.secrets = Some(Arc::new(
        net_supervisor::secret_open::SecretIndex::load(&secret.policy).unwrap(),
    ));
    let rp = secret.report();
    let Some(code) = guarded(secret_traps(), cfg, move || {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let port = l.local_addr().unwrap().port();
        use std::os::unix::io::AsRawFd;
        let lfd = l.as_raw_fd();
        let mut out = String::new();
        // Nothing pending on a non-blocking listener: EAGAIN at once.
        let r = unsafe {
            libc::accept4(
                lfd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_NONBLOCK,
            )
        };
        out += &format!("empty={} ", if r < 0 { errno() } else { 0 });
        // Unknown flags: EINVAL, as the kernel's.
        let r = unsafe { libc::accept4(lfd, std::ptr::null_mut(), std::ptr::null_mut(), 0x40) };
        out += &format!("badflags={} ", if r < 0 { errno() } else { 0 });
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mine = client.local_addr().unwrap().port();
        std::thread::sleep(Duration::from_millis(100));
        let mut peer: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len: u32 = 4; // shorter than the address: truncated, full length back
        let c = unsafe {
            libc::accept4(
                lfd,
                &mut peer as *mut _ as *mut libc::sockaddr,
                &mut len,
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        let fl = unsafe { libc::fcntl(c, libc::F_GETFL) };
        let fd_fl = unsafe { libc::fcntl(c, libc::F_GETFD) };
        out += &format!(
            "accepted={} nonblock={} cloexec={} len={} family={} ",
            c >= 0,
            fl & libc::O_NONBLOCK != 0,
            fd_fl & libc::FD_CLOEXEC != 0,
            len,
            peer.sin_family
        );
        // A full buffer: the peer's own address.
        let client2 = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mine2 = client2.local_addr().unwrap().port();
        std::thread::sleep(Duration::from_millis(100));
        let mut peer2: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len2: u32 = 16;
        let c2 =
            unsafe { libc::accept(lfd, &mut peer2 as *mut _ as *mut libc::sockaddr, &mut len2) };
        let fd_fl2 = unsafe { libc::fcntl(c2, libc::F_GETFD) };
        out += &format!(
            "peer_port_ok={} cloexec2={} ",
            u16::from_be(peer2.sin_port) == mine2,
            fd_fl2 & libc::FD_CLOEXEC != 0
        );
        let _ = mine;
        // A blocking accept on a listener with SO_RCVTIMEO: EAGAIN after it.
        let lb = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 300_000,
        };
        unsafe {
            libc::setsockopt(
                lb.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of_val(&tv) as u32,
            )
        };
        let t = Instant::now();
        let r = unsafe { libc::accept(lb.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut()) };
        out += &format!(
            "timeo={} waited={} ",
            if r < 0 { errno() } else { 0 },
            t.elapsed() >= Duration::from_millis(250)
        );
        let _ = std::fs::write(&rp, out);
        drop((client, client2));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let seen = report_of(&secret.report());
    eprintln!("{seen}");
    for want in [
        format!("empty={} ", libc::EAGAIN),
        format!("badflags={} ", libc::EINVAL),
        "accepted=true nonblock=true cloexec=true len=16 family=2 ".to_string(),
        "peer_port_ok=true cloexec2=false ".to_string(),
        format!("timeo={} waited=true ", libc::EAGAIN),
    ] {
        assert!(seen.contains(&want), "{want} missing: {seen}");
    }
    eprintln!("UNTAINTED ACCEPT PASS");
}

// ── (b) a socket passed to a holder ─────────────────────────────────────────

/// `sendmsg` of `fd` over the Unix socket `via` (one byte of data).
fn pass_fd(via: RawFd, fd: RawFd) -> i32 {
    let mut cbuf = [0u64; 4];
    let mut iov = libc::iovec {
        iov_base: b"F".as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
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

/// `sendmsg` of `fd` over the unconnected Unix socket `via` to the path `to`
/// (one byte of data): a one-way channel, no peer.
fn pass_fd_to(via: RawFd, to: &Path, fd: RawFd) -> i32 {
    use std::os::unix::ffi::OsStrExt;
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as u16;
    let bytes = to.as_os_str().as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        sa.sun_path[i] = *b as libc::c_char;
    }
    let mut cbuf = [0u64; 4];
    let mut iov = libc::iovec {
        iov_base: b"F".as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
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

/// `recvmsg` of one descriptor over `via` (bounded by SO_RCVTIMEO); -1 none.
fn recv_fd(via: RawFd) -> RawFd {
    let tv = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            via,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of_val(&tv) as u32,
        )
    };
    let mut buf = [0u8; 8];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: 8,
    };
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

#[test]
#[ignore]
fn a_socket_passed_to_a_holder_is_judged_at_its_sender() {
    let _serial = serial();
    lo_up();
    let off = udp_listener([127, 0, 0, 3], 0);
    let port = off.local_addr().unwrap().port();
    // Bindings are TCP (`binding_to_spec`): the bound peer is a TCP server.
    let (bound_port, bound_got) = tcp_listener([127, 0, 0, 2]);
    let secret = Secret::new("pass");
    let arbiter = reader_arbiter(vec!["127.0.0.2".into()]);
    let cfg = secret_cfg(&secret, arbiter);
    let (path, rp) = (secret.path.clone(), secret.report());
    // The channel to the holder is one way and made AFTER its taint (a Unix
    // datagram socket it binds then, which the sender addresses by path): a
    // pipe or a socket pair it held at the taint would make the sender a
    // holder too (plan 13 D2), and so, since plan 13 §9 R1, would a
    // connection to a listener the holder accepts or any other socket whose
    // peer the holder holds; the sender's own connect to the unbound peer
    // would then be refused before any pass. The sender learns the holder is
    // ready from the socket's path appearing, never from a file the holder
    // wrote: since plan 13 §9 R1's file shapes, reading what a holder wrote
    // (here unlabelled, the mock labels nothing) makes the reader a holder.
    let (sock, child_rp) = (secret.dir.join("pass.sock"), secret.dir.join("child.txt"));
    let Some(code) = guarded(secret_traps(), cfg, move || {
        // The holder is DETACHED (a middle process forks it and exits; the
        // namespace's init adopts it before it reads): since 2026-10-03 the
        // parent of a holder becomes one (plan 13 §4.9, the exit status), and
        // this process, the sender, must stay untainted until it reads the
        // holder's report.
        let mid = unsafe { libc::fork() };
        if mid == 0 {
            if unsafe { libc::fork() } != 0 {
                unsafe { libc::_exit(0) };
            }
            let parent = unsafe { libc::getppid() };
            for _ in 0..2000 {
                if unsafe { libc::getppid() } != parent {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let k = read_file(&path).unwrap_or_default();
            let Ok(c) = std::os::unix::net::UnixDatagram::bind(&sock) else { unsafe { libc::_exit(3) } };
            let read = if k.contains(CANARY) { "r" } else { "n" };
            use std::os::unix::io::AsRawFd;
            let s1 = c.as_raw_fd();
            // Whatever arrives, the secret goes into it.
            let mut got = Vec::new();
            for _ in 0..3 {
                let fd = recv_fd(s1);
                if fd >= 0 {
                    got.push(format!("{}", write_all(fd, k.as_bytes()) > 0));
                } else {
                    got.push("none".into());
                }
            }
            let _ = std::fs::write(&child_rp, format!("{read}|{}", got.join(",")));
            unsafe { libc::_exit(0) };
        }
        for _ in 0..500 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let s0 = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        // An unbound peer: refused at the sender.
        let u = udp_socket();
        connect(u, [127, 0, 0, 3], port);
        let unbound = pass_fd_to(s0, &sock, u);
        // A bound peer, and a listening socket: passed.
        let v = tcp_connect([127, 0, 0, 2], bound_port).unwrap_or(-1);
        let bound_pass = pass_fd_to(s0, &sock, v);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        use std::os::unix::io::AsRawFd;
        let listening = pass_fd_to(s0, &sock, l.as_raw_fd());
        unsafe { libc::close(s0) };
        reap(mid);
        // Not this process's child: its report is the sign it finished.
        for _ in 0..1000 {
            if child_rp.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // The holder's report is a file it wrote: reading it makes this
        // process a holder too (plan 13 §9 R1, the file shapes), which an
        // unbound connection it still held would refuse.
        unsafe {
            libc::close(u);
            libc::close(v);
        }
        drop(l);
        // The whole report, not the file alone: `fs::write` creates the file
        // before it writes, and on one CPU this process read it empty in
        // between (2 runs in 75 in a 1-vCPU VM, 2026-10-09).
        let mut child = String::new();
        for _ in 0..500 {
            child = std::fs::read_to_string(&child_rp).unwrap_or_default();
            if child.contains('|') {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let (read, got) = child.split_once('|').unwrap_or(("?", ""));
        let _ = std::fs::write(&rp, format!("read={read} unbound={unbound} bound={bound_pass} listening={listening} child_got={got}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let seen = report_of(&secret.report());
    eprintln!("{seen}");
    assert!(
        seen.starts_with(&format!(
            "read=r unbound={} bound=0 listening=0 child_got=",
            libc::EACCES
        )),
        "{seen}"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        drain(&off).is_empty(),
        "THE LEAK: the unbound peer got the secret"
    );
    assert!(
        String::from_utf8_lossy(&bound_got.lock().unwrap()).contains(CANARY),
        "control: a socket to a binding is passed and used"
    );

    // Queued before the taint: the raw open is refused.
    let secret = Secret::new("pass-queued");
    let arbiter = reader_arbiter(vec!["127.0.0.2".into()]);
    let cfg = secret_cfg(&secret, arbiter);
    let (path, rp) = (secret.path.clone(), secret.report());
    let Some(code) = guarded(secret_traps(), cfg, move || {
        let (s0, s1) = socketpair(libc::SOCK_STREAM);
        let u = udp_socket();
        connect(u, [127, 0, 0, 3], port);
        let queued = pass_fd(s0, u);
        // Only the queued copy is left (the sweep would refuse `u` itself).
        unsafe { libc::close(u) };
        let opened = match read_file(&path) {
            Ok(_) => "ok".to_string(),
            Err(e) => format!("{e}"),
        };
        let _ = (
            s1,
            std::fs::write(&rp, format!("queued={queued} open={opened}")),
        );
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(
        report_of(&secret.report()),
        format!("queued=0 open={}", libc::EACCES),
        "a descriptor queued to the reader refuses its raw open"
    );
    eprintln!("PASSED DESCRIPTOR PASS");
}

// ── (c) a Unix socket connected before the taint ────────────────────────────

#[test]
#[ignore]
fn a_unix_socket_connected_before_the_taint_refuses_the_raw_open() {
    let _serial = serial();
    let secret = Secret::new("unix-pre");
    let sock = secret.dir.join("relay.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    {
        let got = got.clone();
        std::thread::spawn(move || {
            for c in listener.incoming() {
                let Ok(mut c) = c else { break };
                let got = got.clone();
                std::thread::spawn(move || {
                    use std::io::Read;
                    let mut buf = Vec::new();
                    let _ = c.read_to_end(&mut buf);
                    got.lock().unwrap().extend_from_slice(&buf);
                });
            }
        });
    }
    let abs_name = format!("mandu-gaps-relay-{}", run_tag());
    let abs = {
        // An abstract listener too (the test's network namespace).
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        a.sun_family = libc::AF_UNIX as u16;
        for (i, b) in abs_name.bytes().enumerate() {
            a.sun_path[i + 1] = b as libc::c_char;
        }
        let len = (2 + 1 + abs_name.len()) as u32;
        assert_eq!(
            unsafe { libc::bind(fd, &a as *const _ as *const libc::sockaddr, len) },
            0
        );
        assert_eq!(unsafe { libc::listen(fd, 8) }, 0);
        fd
    };
    let run = |bindings: Vec<String>, how: &'static str| -> String {
        let arbiter = reader_arbiter(bindings);
        let cfg = secret_cfg(&secret, arbiter);
        let (path, rp, sp, an) = (
            secret.path.clone(),
            secret.report(),
            sock.clone(),
            abs_name.clone(),
        );
        let Some(code) = guarded(secret_traps(), cfg, move || {
            let held = match how {
                "path" => std::os::unix::net::UnixStream::connect(&sp).map(|s| {
                    use std::os::unix::io::IntoRawFd;
                    s.into_raw_fd()
                }),
                "abstract" => {
                    let fd = unsafe {
                        libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
                    };
                    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
                    a.sun_family = libc::AF_UNIX as u16;
                    for (i, b) in an.bytes().enumerate() {
                        a.sun_path[i + 1] = b as libc::c_char;
                    }
                    let len = (2 + 1 + an.len()) as u32;
                    if unsafe { libc::connect(fd, &a as *const _ as *const libc::sockaddr, len) }
                        == 0
                    {
                        Ok(fd)
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                }
                _ => Ok(socketpair(libc::SOCK_STREAM).0),
            };
            let Ok(fd) = held else {
                let _ = std::fs::write(&rp, "connect=failed");
                return 0;
            };
            let out = match read_file(&path) {
                Ok(k) => format!("open=ok sent={}", write_all(fd, k.as_bytes()) > 0),
                Err(e) => format!("open={e}"),
            };
            let _ = std::fs::write(&rp, out);
            0
        }) else {
            return "SKIP".into();
        };
        assert_eq!(code, Some(0));
        report_of(&secret.report())
    };
    let r = run(vec![], "path");
    if r == "SKIP" {
        return;
    }
    assert_eq!(
        r,
        format!("open={}", libc::EACCES),
        "a named Unix peer that is no binding"
    );
    assert_eq!(
        run(vec![], "abstract"),
        format!("open={}", libc::EACCES),
        "an abstract one"
    );
    assert_eq!(
        run(vec![], "pair"),
        "open=ok sent=true",
        "control: an unnamed socketpair is a pipe"
    );
    let bound = format!("unix:{}", secret.dir.display());
    assert_eq!(
        run(vec![bound], "path"),
        "open=ok sent=true",
        "control: a `unix:` binding"
    );
    std::thread::sleep(Duration::from_millis(200));
    // Only the bound run's bytes arrived.
    assert_eq!(
        String::from_utf8_lossy(&got.lock().unwrap())
            .matches(CANARY)
            .count(),
        1
    );
    unsafe { libc::close(abs) };
    eprintln!("UNIX PRE-TAINT PASS");
}

// ── (d) a fork after the taint ──────────────────────────────────────────────

/// A config whose taint set knows THIS process as a reaper (it is made a
/// subreaper, as the guard is): an orphan of the guarded tree comes here.
fn reaper_cfg(secret: &Secret, arbiter: &MockArbiter) -> GuardConfig {
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let cfg = secret_cfg(secret, arbiter);
    cfg.tainted
        .add_reaper(&mandu_arbiter::proc::proc_key_for_pid(std::process::id() as i32).unwrap());
    cfg
}

/// The child's part: wait to be orphaned, then try both exits; report on `wr`.
fn orphan_tries(k: &str, parent: i32, port: u16, tcp: u16, wr: RawFd) -> ! {
    let end = Instant::now() + Duration::from_secs(5);
    while unsafe { libc::getppid() } == parent && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    let reparented = unsafe { libc::getppid() } != parent;
    let s = sendto(udp_socket(), k.as_bytes(), [127, 0, 0, 3], port);
    let t = tcp_connect([127, 0, 0, 3], tcp).map(|f| {
        write_all(f, k.as_bytes());
        0
    });
    let msg = format!(
        "reparented={reparented} send={s} tcp={}",
        t.err().unwrap_or(0)
    );
    write_all(wr, msg.as_bytes());
    unsafe { libc::_exit(0) }
}

#[test]
#[ignore]
fn a_child_that_outlives_its_holder_stays_a_holder() {
    let _serial = serial();
    lo_up();
    let off = udp_listener([127, 0, 0, 3], 0);
    let port = off.local_addr().unwrap().port();
    let (tcp, tcp_got) = tcp_listener([127, 0, 0, 3]);
    for how in ["exit", "killed"] {
        let secret = Secret::new(&format!("orphan-{how}"));
        let arbiter = reader_arbiter(vec!["127.0.0.2".into()]);
        let cfg = reaper_cfg(&secret, arbiter);
        let path = secret.path.clone();
        let (rd, wr) = pipe();
        let Some(_) = guarded_keep(secret_traps(), cfg, &[wr], move || {
            let k = read_file(&path).unwrap_or_default();
            let me = unsafe { libc::getpid() };
            // The child makes no trapped call while its holder lives.
            if unsafe { libc::fork() } == 0 {
                orphan_tries(&k, me, port, tcp, wr);
            }
            if how == "killed" {
                // No exit the guard sees: a signal ends the holder.
                unsafe { libc::kill(me, libc::SIGKILL) };
            }
            0
        }) else {
            return;
        };
        unsafe { libc::close(wr) };
        let seen = read_string(rd);
        unsafe { libc::close(rd) };
        // Reap the adopted orphan.
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
        eprintln!("{how}: {seen}");
        assert_eq!(
            seen,
            format!("reparented=true send=-{e} tcp={e}", e = libc::EACCES),
            "{how}: the orphan of a holder stays one"
        );
    }
    std::thread::sleep(Duration::from_millis(200));
    assert!(drain(&off).is_empty(), "THE LEAK (udp)");
    assert!(
        !String::from_utf8_lossy(&tcp_got.lock().unwrap()).contains(CANARY),
        "THE LEAK (tcp)"
    );

    // Under a subreaper the tree made itself (the trapped prctl names it).
    let secret = Secret::new("orphan-subreaper");
    let arbiter = reader_arbiter(vec!["127.0.0.2".into()]);
    let cfg = secret_cfg(&secret, arbiter);
    let path = secret.path.clone();
    let (rd, wr) = pipe();
    let Some(_) = guarded_keep(secret_traps(), cfg, &[wr], move || {
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        let holder = unsafe { libc::fork() };
        if holder == 0 {
            let k = read_file(&path).unwrap_or_default();
            let me = unsafe { libc::getpid() };
            if unsafe { libc::fork() } == 0 {
                orphan_tries(&k, me, port, tcp, wr);
            }
            unsafe { libc::kill(me, libc::SIGKILL) };
        }
        reap(holder);
        // Wait for the adopted orphan.
        std::thread::sleep(Duration::from_millis(100));
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) } > 0 {}
        0
    }) else {
        return;
    };
    unsafe { libc::close(wr) };
    let seen = read_string(rd);
    eprintln!("subreaper: {seen}");
    assert_eq!(
        seen,
        format!("reparented=true send=-{e} tcp={e}", e = libc::EACCES)
    );
    assert!(drain(&off).is_empty());

    // Control: the same orphan of a process that read nothing goes out.
    let secret = Secret::new("orphan-live");
    let arbiter = reader_arbiter(vec![]);
    let cfg = reaper_cfg(&secret, arbiter);
    let (rd, wr) = pipe();
    let Some(_) = guarded_keep(secret_traps(), cfg, &[wr], move || {
        let me = unsafe { libc::getpid() };
        if unsafe { libc::fork() } == 0 {
            orphan_tries("LIVE-ORPHAN", me, port, tcp, wr);
        }
        0
    }) else {
        return;
    };
    unsafe { libc::close(wr) };
    let seen = read_string(rd);
    while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
    assert_eq!(
        seen, "reparented=true send=11 tcp=0",
        "control: an untainted orphan's sends go out"
    );
    assert_eq!(drain(&off), vec![b"LIVE-ORPHAN".to_vec()]);
    eprintln!("ORPHAN PASS");
}

// ── (d') the orphan window ends at the holder's death (2026-10-09) ──────────

/// Try both exits now; the report line.
fn exits_now(k: &str, port: u16, tcp: u16) -> String {
    let s = sendto(udp_socket(), k.as_bytes(), [127, 0, 0, 3], port);
    let t = tcp_connect([127, 0, 0, 3], tcp).map(|f| {
        write_all(f, k.as_bytes());
        0
    });
    format!("send={s} tcp={}", t.err().unwrap_or(0))
}

/// Wait (at most 5 s) until `pid` is a zombie or gone: its death happened.
fn until_dead(pid: i32) {
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(st) => {
                let state = st.rsplit_once(')').and_then(|(_, r)| r.trim_start().chars().next());
                if matches!(state, Some('Z') | Some('X')) {
                    return;
                }
            }
            Err(_) => return,
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Fork `holder` with no parent left in the tree (its parent exits at once,
/// so it is this test's orphan, reaped outside the tree): its pid.
fn spawn_orphaned(holder: impl FnOnce() -> i32) -> i32 {
    let (rd, wr) = pipe();
    let mid = unsafe { libc::fork() };
    if mid == 0 {
        let h = unsafe { libc::fork() };
        if h == 0 {
            unsafe { libc::close(rd) };
            unsafe { libc::close(wr) };
            let code = holder();
            unsafe { libc::_exit(code) };
        }
        let b = h.to_ne_bytes();
        unsafe { libc::write(wr, b.as_ptr() as *const libc::c_void, 4) };
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(wr) };
    let mut b = [0u8; 4];
    unsafe { libc::read(rd, b.as_mut_ptr() as *mut libc::c_void, 4) };
    unsafe { libc::close(rd) };
    reap(mid);
    i32::from_ne_bytes(b)
}

/// Wait (at most 5 s) until the clock is past this process's own start
/// tick, so a process it forks now starts in a later tick than it did.
fn until_past_own_start_tick() {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let Some(me) = net_supervisor::lineage::parse_stat(&stat) else { return };
    let end = Instant::now() + Duration::from_secs(5);
    while net_supervisor::secret_open::now_ticks() <= me.start && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// In a new pid namespace (this process must be able to `unshare` it: root
/// in the test's user namespace), the namespace's init forks `child` and
/// waits for it: `child` is the init's child, an orphan root to the guard.
fn in_new_pidns(child: impl FnOnce() -> i32) -> bool {
    if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
        return false;
    }
    let init = unsafe { libc::fork() };
    if init == 0 {
        let c = unsafe { libc::fork() };
        if c == 0 {
            let code = child();
            unsafe { libc::_exit(code) };
        }
        reap(c);
        unsafe { libc::_exit(0) };
    }
    reap(init);
    true
}

/// confidentiality-plan-13 §4.5.1 and exec-routing.md §7.5 (2026-10-09,
/// `death_watch`): the orphan backstop's window ends at the holder's death,
/// stamped when it happens.
///   (a) a pid namespace init's child born AFTER a holder died, and after a
///       trapped call the tree made once the death had happened (Codex
///       `execve`s the next sandbox's bwrap after reaping the last), is no
///       orphan of it: its sends go out (before, a death stamped up to 200 ms
///       late took it in: the Codex sandbox flake). The guard stamps a death
///       before it answers any later call (`stamp_ready_deaths`), so this
///       holds however late the watcher's own thread runs: 15 ms after that
///       call, more than one clock tick, is enough (until 2026-10-09 the
///       round waited 40 ms on the watcher's thread alone and failed once
///       under load, CI pipeline 10012). It runs alone (`serial`): with
///       the other tests of this process beside it, it failed in 15 of 132
///       CI runs (2026-10-09/10), each time when a child of another test
///       was adopted as the holder's orphan. And the tree's root starts the
///       holder in a later clock tick than its own (exec-routing.md §7.5
///       (d), "One process's tree");
///   (b) one born WHILE the holder lived, in a pid namespace the holder made,
///       orphaned when it dies, still inherits, however late it acts;
///   (c) an orphan the death left running (adopted at the death) that forks
///       and dies before any trapped call: its child, born after the holder
///       died, inherits through it.
#[test]
#[ignore]
fn the_orphan_window_ends_at_the_holders_death() {
    let _serial = serial();
    lo_up();
    let off = udp_listener([127, 0, 0, 3], 0);
    let port = off.local_addr().unwrap().port();
    let (tcp, tcp_got) = tcp_listener([127, 0, 0, 3]);
    let refused = format!("send=-{e} tcp={e}", e = libc::EACCES);

    // (a) born after the death, three times (a 200 ms poll stamp would take
    // most of them in; with the tick of margin after the stamp that the
    // window had until 2026-10-09, a birth 15 ms later would be taken in
    // about half the time).
    for round in 0..3 {
        let secret = Secret::new(&format!("window-after-{round}"));
        let arbiter = reader_arbiter(vec!["127.0.0.2".into()]);
        let cfg = reaper_cfg(&secret, arbiter);
        let path = secret.path.clone();
        let (rd, wr) = pipe();
        let tainted = cfg.tainted.clone();
        let Some(_) = guarded_keep(secret_traps(), cfg, &[wr], move || {
            // This tree's root is no orphan of the holder: the holder is
            // started in a later clock tick than the root. Its parent exits
            // at once (`spawn_orphaned`), mostly before its read, and then
            // the guard records no lineage for it: a root born in its tick
            // would be taken
            // for a child it left running (fail-closed; secret_open's
            // a_root_in_the_tick_of_a_holder_whose_lineage_is_lost_is_its_orphan).
            until_past_own_start_tick();
            let me = net_supervisor::secret_open::own_key_of(unsafe { libc::getpid() });
            write_all(wr, format!("root={me} ").as_bytes());
            let h = spawn_orphaned(move || {
                let _ = read_file(&path);
                0
            });
            until_dead(h);
            // the tree's next trapped call (the next sandbox's exec, in
            // Codex): the death is stamped before it is answered
            drop(std::fs::File::open("/dev/null"));
            std::thread::sleep(Duration::from_millis(15));
            let ok = in_new_pidns(move || {
                let line = exits_now(&format!("AFTER-{round}"), port, tcp);
                write_all(wr, line.as_bytes());
                0
            });
            if !ok {
                write_all(wr, b"SKIP: no unshare(CLONE_NEWPID) here");
            }
            0
        }) else {
            return;
        };
        unsafe { libc::close(wr) };
        let seen = read_string(rd);
        unsafe { libc::close(rd) };
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
        if seen.contains("SKIP") {
            eprintln!("{seen}");
            return;
        }
        let (root, line) = seen.strip_prefix("root=").and_then(|r| r.split_once(' ')).unwrap_or(("", seen.as_str()));
        assert_eq!(
            line,
            format!("send={} tcp=0", format!("AFTER-{round}").len()),
            "(a) round {round}: a sandbox born after the holder died is no orphan of it (the tree's root {root} holds from {:?})",
            tainted.taint_sources(root)
        );
    }

    // (b) born while the holder lived, in a pid namespace it made; acts
    // 300 ms after the death.
    let secret = Secret::new("window-during");
    let arbiter = reader_arbiter(vec!["127.0.0.2".into()]);
    let cfg = reaper_cfg(&secret, arbiter);
    let path = secret.path.clone();
    let (rd, wr) = pipe();
    let Some(_) = guarded_keep(secret_traps(), cfg, &[wr], move || {
        let _ = spawn_orphaned(move || {
            let k = read_file(&path).unwrap_or_default();
            let holder = unsafe { libc::getpid() };
            if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
                write_all(wr, b"SKIP: no unshare(CLONE_NEWPID) here");
                return 0;
            }
            if unsafe { libc::fork() } == 0 {
                // the namespace's init: its child is the one under test
                if unsafe { libc::fork() } == 0 {
                    until_dead(holder);
                    std::thread::sleep(Duration::from_millis(300));
                    let line = exits_now(&k, port, tcp);
                    write_all(wr, line.as_bytes());
                    unsafe { libc::_exit(0) };
                }
                while unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) } > 0 {}
                unsafe { libc::_exit(0) };
            }
            std::thread::sleep(Duration::from_millis(50));
            0
        });
        0
    }) else {
        return;
    };
    unsafe { libc::close(wr) };
    let seen = read_string(rd);
    unsafe { libc::close(rd) };
    while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
    if seen.starts_with("SKIP") {
        eprintln!("{seen}");
        return;
    }
    assert_eq!(seen, refused, "(b) a pid namespace child born while the holder lived still inherits");

    // (c) the orphan the death left running forks and dies; its child acts
    // 300 ms later.
    let secret = Secret::new("window-adopted");
    let arbiter = reader_arbiter(vec!["127.0.0.2".into()]);
    let cfg = reaper_cfg(&secret, arbiter);
    let path = secret.path.clone();
    let (rd, wr) = pipe();
    let Some(_) = guarded_keep(secret_traps(), cfg, &[wr], move || {
        let _ = spawn_orphaned(move || {
            let k = read_file(&path).unwrap_or_default();
            // Made after the read (the taint's sweep never saw it): its
            // read end returns at the holder's death. No trapped call below
            // until the last child's sends: nothing but the death adoption
            // can record the middle process.
            let (dead_rd, dead_wr) = pipe();
            if unsafe { libc::fork() } == 0 {
                unsafe { libc::close(dead_wr) };
                let mut b = [0u8; 1];
                unsafe { libc::read(dead_rd, b.as_mut_ptr() as *mut libc::c_void, 1) };
                std::thread::sleep(Duration::from_millis(100));
                let (gone_rd, gone_wr) = pipe();
                if unsafe { libc::fork() } == 0 {
                    unsafe { libc::close(gone_wr) };
                    unsafe { libc::read(gone_rd, b.as_mut_ptr() as *mut libc::c_void, 1) };
                    std::thread::sleep(Duration::from_millis(300));
                    let line = exits_now(&k, port, tcp);
                    write_all(wr, line.as_bytes());
                    unsafe { libc::_exit(0) };
                }
                unsafe { libc::_exit(0) };
            }
            unsafe { libc::close(dead_rd) };
            0
        });
        0
    }) else {
        return;
    };
    unsafe { libc::close(wr) };
    let seen = read_string(rd);
    unsafe { libc::close(rd) };
    while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
    assert_eq!(seen, refused, "(c) the child of an orphan the holder's death left running inherits through it");

    std::thread::sleep(Duration::from_millis(200));
    assert!(drain(&off).iter().all(|b| b.starts_with(b"AFTER-")), "THE LEAK (udp)");
    assert!(!String::from_utf8_lossy(&tcp_got.lock().unwrap()).contains(CANARY), "THE LEAK (tcp)");
    eprintln!("ORPHAN WINDOW PASS");
}

// ── (e) a Unix connect without the allow-list ───────────────────────────────

#[test]
#[ignore]
fn a_unix_connect_cannot_be_swapped_for_an_unjudged_inet_one() {
    let _serial = serial();
    lo_up();
    let refused = udp_listener([127, 0, 0, 3], 0);
    let port = refused.local_addr().unwrap().port();
    let allowed = udp_listener([127, 0, 0, 4], port);
    let dir = std::env::temp_dir().join(format!("mandu-gaps-swap-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let upath = dir.join("d.sock");
    let _ul = std::os::unix::net::UnixDatagram::bind(&upath).unwrap();
    // A secret policy WITHOUT a Unix allow-list (MANDU_UNIX_POLICY=0, the
    // posture gap (e) names): every Unix connect is supervised, so a thread
    // cannot swap an INET socket under the descriptor. The static list admits
    // 127.0.0.4 only. The process never reads the secret (it stays untainted);
    // the static list, not a taint, is what the swap tries to defeat.
    let secret = Secret::new("swap");
    let arbiter = reader_arbiter(vec![]);
    let mut cfg = static_cfg(&["udp:127.0.0.4/32:*"]);
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(&secret.policy).unwrap()));
    cfg.emitter = Some(Arc::new(Mutex::new(mandu_arbiter::ArbiterClient::new(&arbiter.socket_path))));
    let report = dir.join("report.txt");
    let rp = report.clone();
    let Some(code) = guarded(secret_traps(), cfg, move || {
        // One buffer the size of a sockaddr_un; the flipper writes either a
        // Unix path or 127.0.0.3 into it, and puts either socket under fd F.
        let un = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        let inet = udp_socket();
        let f = unsafe { libc::dup(un) };
        let mut unix_addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        unix_addr.sun_family = libc::AF_UNIX as u16;
        for (i, b) in upath.as_os_str().as_encoded_bytes().iter().enumerate() {
            unix_addr.sun_path[i] = *b as libc::c_char;
        }
        let inet_addr = sin([127, 0, 0, 3], port);
        // Control, before any race: a Unix connect to the path goes through
        // (supervised by the guard), the errno reported.
        let probe = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        let baseline = if unsafe { libc::connect(probe, &unix_addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_un>() as u32) } == 0 { 0 } else { errno() };
        let buf: &'static mut libc::sockaddr_un = Box::leak(Box::new(unix_addr));
        let p = buf as *mut libc::sockaddr_un as usize;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let st = stop.clone();
        let flipper = std::thread::spawn(move || {
            let b = p as *mut u8;
            while !st.load(std::sync::atomic::Ordering::Relaxed) {
                unsafe {
                    libc::dup2(inet, f);
                    std::ptr::copy_nonoverlapping(&inet_addr as *const _ as *const u8, b, 16);
                    libc::dup2(un, f);
                    std::ptr::copy_nonoverlapping(
                        &unix_addr as *const _ as *const u8,
                        b,
                        std::mem::size_of::<libc::sockaddr_un>(),
                    );
                }
            }
        });
        let mut unix_ok = 0;
        for _ in 0..3000 {
            if unsafe {
                libc::connect(
                    f,
                    p as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_un>() as u32,
                )
            } == 0
            {
                unix_ok += 1;
            }
            // Whatever F is now and wherever it is connected: send.
            unsafe { libc::send(f, b"SWAP".as_ptr() as *const libc::c_void, 4, 0) };
            unsafe { libc::send(inet, b"SWAP".as_ptr() as *const libc::c_void, 4, 0) };
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = flipper.join();
        let direct = sendto(udp_socket(), b"ALLOWED", [127, 0, 0, 4], port);
        let _ = std::fs::write(&rp, format!("baseline={baseline} unix_connects={unix_ok} direct={direct}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let seen = report_of(&report);
    eprintln!("{seen}");
    let leaked = drain(&refused);
    assert!(
        leaked.is_empty(),
        "THE SWAP: {} datagrams reached the unjudged 127.0.0.3",
        leaked.len()
    );
    // The control: the allowed destination IS reachable (the guard is not
    // simply blocking everything). The Unix connects themselves race the swap
    // and mostly fail by design (the guard connects whatever socket is under
    // F to the Unix inode it checked; an INET socket swapped in fails there),
    // so their count is not asserted — the leak oracle above is the point.
    assert!(
        seen.contains("direct=7"),
        "control: the allowed address is reachable: {seen}"
    );
    assert!(drain(&allowed).iter().any(|d| d == b"ALLOWED"));
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("UNIX SWAP PASS");
}
