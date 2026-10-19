//! send_integration — the guard judges SENDS like connects, and judges the
//! sockets a process already holds when it becomes tainted (exec-routing.md
//! §7.5, "Sends are judged like connects", 2026-10-01).
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! (an unprivileged user + network namespace; `lo` is brought up here). Only
//! `no_new_privs` and kernel ≥ 5.6 are needed; a host where the seccomp
//! listener cannot be installed SKIPs.
//!
//! What it proves, each with its control:
//!   - finding path 1: `sendto`/`sendmsg`/`sendmmsg` with an address to a
//!     destination the static list refuses get EACCES and reach nobody; an
//!     allowed one is delivered (and `sendmmsg` writes each `msg_len`); an
//!     `AF_UNSPEC` address and IPv4-over-IPv6 are judged as the kernel reads
//!     them;
//!   - a thread rewriting the address (or turning an `AF_UNSPEC` connect into
//!     an `AF_INET` one) never reaches an unjudged destination;
//!   - a TAINTED process sends only to its bindings and the session's proxy
//!     port (finding path 3: 127.0.0.1 on another port is refused);
//!   - finding path 2: a socket connected before the taint, by the reader or
//!     a descendant, refuses the raw open; one to a binding or the proxy
//!     does not;
//!   - the taint is the process's, whichever thread opened or sends; a
//!     descendant judged once stays a holder after its parent exits;
//!   - a holder's command line (`/proc/<pid>/cmdline`, which a shell fills
//!     with the secret it expands into a child's argv) is refused to an
//!     untainted reader, `ps` included (plan 10 §11.13.1);
//!   - a Unix datagram to a path is judged like a Unix connect; descriptors
//!     passed over `SCM_RIGHTS` still arrive; `pidfd_getfd` is refused; a
//!     routing header is refused; a blocking stream send is sent whole.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, readable_within, readable_within_tree, reap_within, run_tag, socketpair, wait_limit};

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mandu_arbiter::mock::{op_handler, MockArbiter};
use net_supervisor::guard::{parse_rules, GuardPolicy, NoResolver};
use net_supervisor::guard_kernel::{hand_listener, install_guard_filter_self, receive_listener, run_guard_supervisor, FilterTraps, GuardConfig};

const EXIT_NO_SECCOMP: i32 = 91;
const CANARY: &str = "SEND-CANARY-7731";

// ── plumbing ──────────────────────────────────────────────────────────────────

fn lo_up() {
    let _ = std::process::Command::new("ip").args(["link", "set", "lo", "up"]).stderr(std::process::Stdio::null()).status();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A UDP listener on `ip`, port `port` (0: any), nonblocking.
fn udp_listener(ip: [u8; 4], port: u16) -> UdpSocket {
    let s = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::from(ip), port)).expect("bind udp listener");
    s.set_nonblocking(true).unwrap();
    s
}

/// Everything a UDP listener has received so far.
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
    let l = std::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::from(ip), 0)).expect("bind tcp listener");
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

fn sin(ip: [u8; 4], port: u16, family: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: family,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(ip) },
        sin_zero: [0; 8],
    }
}

/// `sendto` of `data` to `ip:port`: the count or the errno (negative).
fn sendto(fd: RawFd, data: &[u8], ip: [u8; 4], port: u16) -> isize {
    let a = sin(ip, port, libc::AF_INET as u16);
    // SAFETY: sendto with a stack sockaddr.
    let n = unsafe { libc::sendto(fd, data.as_ptr() as *const libc::c_void, data.len(), 0, &a as *const _ as *const libc::sockaddr, std::mem::size_of_val(&a) as u32) };
    if n < 0 { -(errno() as isize) } else { n }
}

/// `sendmsg` of `data` to `ip:port`.
fn sendmsg(fd: RawFd, data: &[u8], ip: [u8; 4], port: u16) -> isize {
    let mut a = sin(ip, port, libc::AF_INET as u16);
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
    // SAFETY: a msghdr over stack buffers.
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_name = &mut a as *mut _ as *mut libc::c_void;
    m.msg_namelen = std::mem::size_of_val(&a) as u32;
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    let n = unsafe { libc::sendmsg(fd, &m, 0) };
    if n < 0 { -(errno() as isize) } else { n }
}

fn udp_socket() -> RawFd {
    // SAFETY: a fresh datagram socket.
    unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) }
}

/// `connect` of `fd` to `ip:port`: 0 or the errno.
fn connect(fd: RawFd, ip: [u8; 4], port: u16) -> i32 {
    let a = sin(ip, port, libc::AF_INET as u16);
    // SAFETY: connect with a stack sockaddr.
    if unsafe { libc::connect(fd, &a as *const _ as *const libc::sockaddr, std::mem::size_of_val(&a) as u32) } == 0 { 0 } else { errno() }
}

fn tcp_connect(ip: [u8; 4], port: u16) -> Result<RawFd, i32> {
    // SAFETY: a fresh stream socket.
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
    // SAFETY: write from a slice.
    unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) }
}

/// Read a file the tracee may get raw: its bytes, or the errno.
fn read_file(p: &Path) -> Result<String, i32> {
    std::fs::read_to_string(p).map_err(|e| e.raw_os_error().unwrap_or(-1))
}

fn reap(pid: i32) -> Option<i32> {
    if in_test_process() {
        return reap_within(pid, wait_limit(), "waiting for a child the test forked").code();
    }
    let mut status = 0;
    // SAFETY: waitpid on our own child.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) { Some(libc::WEXITSTATUS(status)) } else { None }
}

/// A secret the guard serves raw to whoever the mock arbiter says is a
/// reader, its twin, and the guard's policy file naming them.
struct Secret {
    dir: PathBuf,
    path: PathBuf,
    policy: PathBuf,
}

impl Secret {
    fn new(tag: &str) -> Secret {
        let dir = std::env::temp_dir().join(format!("mandu-send-{tag}-{}", run_tag()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.env");
        let twin = dir.join("twin.env");
        std::fs::write(&path, format!("API_KEY={CANARY}\n")).unwrap();
        std::fs::write(&twin, "API_KEY=$MDU:twin\n").unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(&policy, format!(r#"{{"agentExe":"","ask":"never","session":"send","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, path.display(), twin.display())).unwrap();
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

/// The mock arbiter: every opener of the secret is a reader (raw); a
/// holder's bindings are `bindings`. Leaked on purpose: the supervisor's
/// idle workers may still sit in NOTIF_RECV holding the guard's arbiter
/// connection after the tree is gone (the guard process exits in
/// production; a test process lives on), and dropping the mock joins that
/// connection's thread, which would wait forever.
fn reader_arbiter(bindings: &'static [&'static str]) -> &'static MockArbiter {
    MockArbiter::start(op_handler(move |op, _req| match op {
        "decideSecretOpen" => Ok(serde_json::json!({ "verdict": "raw", "app": "test", "level": "no-model", "reason": "mock reader" })),
        "taintedProcessBindings" => Ok(serde_json::json!({ "tainted": true, "level": "no-model", "files": ["secret.env"], "bindings": bindings })),
        _ => Ok(serde_json::Value::Null),
    })).leak()
}

/// Close every descriptor from 3 up but `keep` (a forked child of this
/// multithreaded test process holds the sockets other tests have open, and
/// a reader's sockets are what the taint-time sweep judges). Only system
/// calls: safe between fork and exec.
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

/// Run `body` in a forked child under the guard's filter, served by the real
/// supervisor loop with `cfg`; the child's exit code, None to SKIP.
fn guarded(traps: FilterTraps, cfg: GuardConfig, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    guarded_keep(traps, cfg, &[], body)
}

/// `guarded`, the child keeping `keep` open (every other inherited
/// descriptor is closed first).
fn guarded_keep(traps: FilterTraps, cfg: GuardConfig, keep: &[RawFd], body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    lo_up();
    let (sup, child_sock) = socketpair(libc::SOCK_STREAM);
    // SAFETY: fork; the child makes system calls and runs `body`.
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
            // Its own listener closed first: a trapped exit_group would wait
            // for a supervisor that never came.
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

fn static_cfg(rules: &[&str]) -> GuardConfig {
    let specs: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
    GuardConfig::new(Arc::new(GuardPolicy::new(parse_rules(&specs).unwrap())), Arc::new(NoResolver))
}

/// A secrets-mode config: the secret registered, the mock arbiter wired,
/// every loopback destination allowed by the static list (the taint leg is
/// what is under test), `proxy` the session's proxy port.
fn secret_cfg(secret: &Secret, arbiter: &MockArbiter, proxy: u16) -> GuardConfig {
    let mut cfg = static_cfg(&["any:127.0.0.0/8:*"]);
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(&secret.policy).unwrap()));
    cfg.emitter = Some(Arc::new(Mutex::new(mandu_arbiter::ArbiterClient::new(&arbiter.socket_path))));
    cfg.proxy_ports = vec![proxy];
    cfg
}

fn secret_traps() -> FilterTraps {
    FilterTraps { open: true, secrets: true, ..Default::default() }
}

fn report_of(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

// ── finding path 1: a datagram with an address ───────────────────────────────

#[test]
#[ignore]
fn an_unconnected_datagram_is_judged_like_a_connect() {
    lo_up();
    let refused = udp_listener([127, 0, 0, 3], 0);
    let port = refused.local_addr().unwrap().port();
    let allowed = udp_listener([127, 0, 0, 4], port);
    let cfg = static_cfg(&["udp:127.0.0.4/32:*"]);
    let report = std::env::temp_dir().join(format!("mandu-send-static-{}.txt", run_tag()));
    let rp = report.clone();
    let Some(code) = guarded(FilterTraps::default(), cfg, move || {
        let fd = udp_socket();
        let mut out = String::new();
        out += &format!("sendto3={} ", sendto(fd, b"LEAK-sendto", [127, 0, 0, 3], port));
        out += &format!("sendmsg3={} ", sendmsg(fd, b"LEAK-sendmsg", [127, 0, 0, 3], port));
        // AF_UNSPEC: UDP reads it as an AF_INET address.
        let a = sin([127, 0, 0, 3], port, libc::AF_UNSPEC as u16);
        let n = unsafe { libc::sendto(fd, b"LEAK-unspec".as_ptr() as *const libc::c_void, 11, 0, &a as *const _ as *const libc::sockaddr, 16) };
        out += &format!("unspec3={} ", if n < 0 { -(errno() as isize) } else { n });
        // IPv4 over an IPv6 socket.
        let fd6 = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
        if fd6 >= 0 {
            // AF_UNSPEC on an IPv6 socket is no address: the kernel's own
            // EDESTADDRREQ on an unconnected socket, nothing sent.
            let n = unsafe { libc::sendto(fd6, b"LEAK-v4v6".as_ptr() as *const libc::c_void, 9, 0, &a as *const _ as *const libc::sockaddr, 16) };
            let n = if n < 0 { -(errno() as isize) } else { n };
            let a4 = sin([127, 0, 0, 3], port, libc::AF_INET as u16);
            let n2 = unsafe { libc::sendto(fd6, b"LEAK-v4v6".as_ptr() as *const libc::c_void, 9, 0, &a4 as *const _ as *const libc::sockaddr, 16) };
            let n2 = if n2 < 0 { -(errno() as isize) } else { n2 };
            out += &format!("v6unspec={n} v4overv6={n2} ");
        }
        out += &format!("sendto4={} ", sendto(fd, b"OK-sendto", [127, 0, 0, 4], port));
        // sendmmsg: two to the allowed host (msg_len written back), then two
        // to the refused one.
        let mut a4 = sin([127, 0, 0, 4], port, libc::AF_INET as u16);
        let mut a3 = sin([127, 0, 0, 3], port, libc::AF_INET as u16);
        let bufs: [&[u8]; 2] = [b"OK-mmsg-1", b"OK-mmsg-22"];
        let mut iovs = [
            libc::iovec { iov_base: bufs[0].as_ptr() as *mut libc::c_void, iov_len: bufs[0].len() },
            libc::iovec { iov_base: bufs[1].as_ptr() as *mut libc::c_void, iov_len: bufs[1].len() },
        ];
        let mut mm: [libc::mmsghdr; 2] = unsafe { std::mem::zeroed() };
        for i in 0..2 {
            mm[i].msg_hdr.msg_name = &mut a4 as *mut _ as *mut libc::c_void;
            mm[i].msg_hdr.msg_namelen = 16;
            mm[i].msg_hdr.msg_iov = &mut iovs[i];
            mm[i].msg_hdr.msg_iovlen = 1;
        }
        let n = unsafe { libc::sendmmsg(fd, mm.as_mut_ptr(), 2, 0) };
        out += &format!("mmsg4={n} lens={},{} ", mm[0].msg_len, mm[1].msg_len);
        for m in mm.iter_mut() {
            m.msg_hdr.msg_name = &mut a3 as *mut _ as *mut libc::c_void;
        }
        let n = unsafe { libc::sendmmsg(fd, mm.as_mut_ptr(), 2, 0) };
        out += &format!("mmsg3={} ", if n < 0 { -(errno() as isize) } else { n as isize });
        // A mixed batch: the allowed one goes, the batch ends at the refused.
        mm[0].msg_hdr.msg_name = &mut a4 as *mut _ as *mut libc::c_void;
        let n = unsafe { libc::sendmmsg(fd, mm.as_mut_ptr(), 2, 0) };
        out += &format!("mmsgmixed={n} ");
        let _ = std::fs::write(&rp, out);
        0
    }) else { return };
    assert_eq!(code, Some(0));
    let seen = report_of(&report);
    eprintln!("{seen}");
    for want in ["sendto3=-13", "sendmsg3=-13", "unspec3=-13", "sendto4=9", "mmsg4=2 lens=9,10", "mmsg3=-13", "mmsgmixed=1"] {
        assert!(seen.contains(want), "{want} missing: {seen}");
    }
    if seen.contains("v4overv6=") {
        assert!(seen.contains("v4overv6=-13"), "IPv4 over IPv6 must be judged as IPv4: {seen}");
        assert!(seen.contains(&format!("v6unspec=-{}", libc::EDESTADDRREQ)), "AF_UNSPEC on IPv6 is no address: {seen}");
    }
    let leaked = drain(&refused);
    assert!(leaked.is_empty(), "the refused listener got {leaked:?}");
    let got = drain(&allowed);
    assert_eq!(got.len(), 4, "the allowed listener: {got:?}");
    let _ = std::fs::remove_file(&report);
    eprintln!("SEND STATIC PASS");
}

#[test]
#[ignore]
fn a_rewritten_address_never_reaches_an_unjudged_destination() {
    lo_up();
    let refused = udp_listener([127, 0, 0, 3], 0);
    let port = refused.local_addr().unwrap().port();
    let allowed = udp_listener([127, 0, 0, 4], port);
    let cfg = static_cfg(&["udp:127.0.0.4/32:*"]);
    let Some(code) = guarded(FilterTraps::default(), cfg, move || {
        // One sockaddr, its address flipped between .4 and .3 by a thread
        // while the main thread sends to it (sendmsg), then connects with it
        // flipping between AF_UNSPEC and AF_INET .3 and sends on the result.
        let addr = Box::leak(Box::new(sin([127, 0, 0, 4], port, libc::AF_INET as u16)));
        let p = addr as *mut libc::sockaddr_in as usize;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let st = stop.clone();
        let flipper = std::thread::spawn(move || {
            let a = p as *mut libc::sockaddr_in;
            while !st.load(std::sync::atomic::Ordering::Relaxed) {
                unsafe {
                    std::ptr::write_volatile(&mut (*a).sin_addr.s_addr, u32::from_ne_bytes([127, 0, 0, 3]));
                    std::ptr::write_volatile(&mut (*a).sin_addr.s_addr, u32::from_ne_bytes([127, 0, 0, 4]));
                }
            }
        });
        let fd = udp_socket();
        for _ in 0..2000 {
            let mut iov = libc::iovec { iov_base: b"RACE".as_ptr() as *mut libc::c_void, iov_len: 4 };
            let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
            m.msg_name = p as *mut libc::c_void;
            m.msg_namelen = 16;
            m.msg_iov = &mut iov;
            m.msg_iovlen = 1;
            unsafe { libc::sendmsg(fd, &m, 0) };
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = flipper.join();
        // The connect form: AF_UNSPEC (a disconnect) ⇄ AF_INET .3.
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let st = stop.clone();
        unsafe { (*(p as *mut libc::sockaddr_in)).sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 3]) };
        let flipper = std::thread::spawn(move || {
            let a = p as *mut libc::sockaddr_in;
            while !st.load(std::sync::atomic::Ordering::Relaxed) {
                unsafe {
                    std::ptr::write_volatile(&mut (*a).sin_family, libc::AF_UNSPEC as u16);
                    std::ptr::write_volatile(&mut (*a).sin_family, libc::AF_INET as u16);
                }
            }
        });
        for _ in 0..2000 {
            if unsafe { libc::connect(fd, p as *const libc::sockaddr, 16) } == 0 {
                unsafe { libc::send(fd, b"RACE-CONNECT".as_ptr() as *const libc::c_void, 12, 0) };
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = flipper.join();
        0
    }) else { return };
    assert_eq!(code, Some(0));
    let leaked = drain(&refused);
    assert!(leaked.is_empty(), "a rewritten address reached the refused listener {} times: {:?}", leaked.len(), leaked.first());
    let got = drain(&allowed);
    assert!(!got.is_empty(), "control: the allowed address was never sent to");
    eprintln!("SEND RACE PASS: {} datagrams to the allowed address, none to the other", got.len());
}

#[test]
#[ignore]
fn a_send_without_an_address_runs_at_full_speed_and_costs_are_measured() {
    // The trap's cost, for exec-routing.md §7.5: send() (sendto with no
    // address) is not trapped; sendto with an address and sendmsg are, and
    // the guard sends for the tracee.
    lo_up();
    let sink = udp_listener([127, 0, 0, 4], 0);
    let port = sink.local_addr().unwrap().port();
    let cfg = static_cfg(&["udp:127.0.0.4/32:*"]);
    let report = std::env::temp_dir().join(format!("mandu-send-cost-{}.txt", run_tag()));
    let rp = report.clone();
    let time = |f: &dyn Fn()| {
        let t = Instant::now();
        for _ in 0..2000 {
            f();
        }
        t.elapsed().as_nanos() as f64 / 2000.0 / 1000.0
    };
    let bare = {
        let fd = udp_socket();
        assert_eq!(connect(fd, [127, 0, 0, 4], port), 0);
        let a = time(&|| {
            unsafe { libc::send(fd, b"x".as_ptr() as *const libc::c_void, 1, 0) };
        });
        let b = time(&|| {
            sendto(fd, b"x", [127, 0, 0, 4], port);
        });
        unsafe { libc::close(fd) };
        (a, b)
    };
    let Some(code) = guarded(FilterTraps::default(), cfg, move || {
        let fd = udp_socket();
        let c = connect(fd, [127, 0, 0, 4], port);
        let send = time(&|| {
            unsafe { libc::send(fd, b"x".as_ptr() as *const libc::c_void, 1, 0) };
        });
        let to = time(&|| {
            sendto(fd, b"x", [127, 0, 0, 4], port);
        });
        let msg = time(&|| {
            sendmsg(fd, b"x", [127, 0, 0, 4], port);
        });
        let _ = std::fs::write(&rp, format!("connect={c} send_us={send:.2} sendto_us={to:.2} sendmsg_us={msg:.2}"));
        0
    }) else { return };
    assert_eq!(code, Some(0));
    let seen = report_of(&report);
    eprintln!("SEND COST (2000 each, µs/call): bare send={:.2} bare sendto={:.2} | guarded {seen}", bare.0, bare.1);
    assert!(seen.starts_with("connect=0 "), "{seen}");
    let _ = drain(&sink);
    let _ = std::fs::remove_file(&report);
}

// ── the taint leg: sends of a holder, finding path 3 ────────────────────────

#[test]
#[ignore]
fn a_tainted_process_sends_only_to_its_bindings_and_the_session_proxy() {
    lo_up();
    let secret = Secret::new("bindings");
    let arbiter = reader_arbiter(&["127.0.0.2"]);
    let off = udp_listener([127, 0, 0, 3], 0);
    let port = off.local_addr().unwrap().port();
    let lo_udp = udp_listener([127, 0, 0, 1], port);
    let (lo_tcp, lo_tcp_got) = tcp_listener([127, 0, 0, 1]);
    let (proxy, proxy_got) = tcp_listener([127, 0, 0, 1]);
    let (bound, bound_got) = tcp_listener([127, 0, 0, 2]);
    let cfg = secret_cfg(&secret, arbiter, proxy);
    let (path, rp) = (secret.path.clone(), secret.report());
    let Some(code) = guarded(secret_traps(), cfg, move || {
        let mut out = String::new();
        let k = match read_file(&path) {
            Ok(k) => k,
            Err(e) => {
                let _ = std::fs::write(&rp, format!("open failed {e}"));
                return 1;
            }
        };
        out += &format!("raw={} ", k.contains(CANARY));
        let fd = udp_socket();
        out += &format!("sendto3={} ", sendto(fd, k.as_bytes(), [127, 0, 0, 3], port));
        out += &format!("sendmsg3={} ", sendmsg(fd, k.as_bytes(), [127, 0, 0, 3], port));
        // Finding path 3: 127.0.0.1 off the proxy port, UDP and TCP.
        out += &format!("udp_lo={} ", sendto(fd, k.as_bytes(), [127, 0, 0, 1], port));
        let u2 = udp_socket();
        out += &format!("udp_lo_connect={} ", connect(u2, [127, 0, 0, 1], port));
        out += &format!("tcp_lo={} ", tcp_connect([127, 0, 0, 1], lo_tcp).map(|f| { write_all(f, k.as_bytes()); 0 }).unwrap_or_else(|e| e));
        // UDP to the proxy's port number is not the proxy.
        out += &format!("udp_proxyport={} ", sendto(fd, k.as_bytes(), [127, 0, 0, 1], proxy));
        // The session's proxy, and a binding.
        out += &format!("tcp_proxy={} ", tcp_connect([127, 0, 0, 1], proxy).map(|f| { write_all(f, b"PROXY-OK"); unsafe { libc::close(f) }; 0 }).unwrap_or_else(|e| e));
        out += &format!("tcp_bound={} ", tcp_connect([127, 0, 0, 2], bound).map(|f| { write_all(f, k.as_bytes()); unsafe { libc::close(f) }; 0 }).unwrap_or_else(|e| e));
        let _ = std::fs::write(&rp, out);
        0
    }) else { return };
    assert_eq!(code, Some(0), "{}", report_of(&secret.report()));
    let seen = report_of(&secret.report());
    eprintln!("{seen}");
    for want in ["raw=true", "sendto3=-13", "sendmsg3=-13", "udp_lo=-13", "udp_lo_connect=13", "tcp_lo=13", "udp_proxyport=-13", "tcp_proxy=0", "tcp_bound=0"] {
        assert!(seen.contains(want), "{want} missing: {seen}");
    }
    std::thread::sleep(Duration::from_millis(200));
    assert!(drain(&off).is_empty() && drain(&lo_udp).is_empty(), "a refused datagram arrived");
    assert!(!String::from_utf8_lossy(&lo_tcp_got.lock().unwrap()).contains(CANARY));
    assert_eq!(&proxy_got.lock().unwrap()[..], b"PROXY-OK");
    assert!(String::from_utf8_lossy(&bound_got.lock().unwrap()).contains(CANARY), "the binding must be reachable");

    // Control: the same sends from a process that read nothing arrive.
    let cfg = secret_cfg(&secret, arbiter, proxy);
    let Some(code) = guarded(secret_traps(), cfg, move || {
        let fd = udp_socket();
        (sendto(fd, b"LIVE-sendto", [127, 0, 0, 3], port) != 11) as i32 | (((sendto(fd, b"LIVE-lo", [127, 0, 0, 1], port)) != 7) as i32) << 1
    }) else { return };
    assert_eq!(code, Some(0), "control: an untainted process's sends must go through");
    assert_eq!(drain(&off), vec![b"LIVE-sendto".to_vec()]);
    assert_eq!(drain(&lo_udp), vec![b"LIVE-lo".to_vec()]);
    eprintln!("TAINTED SENDS PASS");
}

// ── finding path 2: sockets held before the taint ───────────────────────────

/// Run `before` (it opens sockets), then try the raw open: the report says
/// whether the open succeeded, and what a send of the bytes did.
fn open_after(tag: &str, bindings: &'static [&'static str], proxy: u16, before: impl FnOnce() -> Vec<RawFd>) -> Option<String> {
    let secret = Secret::new(tag);
    let arbiter = reader_arbiter(bindings);
    let cfg = secret_cfg(&secret, arbiter, proxy);
    let (path, rp) = (secret.path.clone(), secret.report());
    let code = guarded(secret_traps(), cfg, move || {
        let fds = before();
        let out = match read_file(&path) {
            Ok(k) => {
                let sent: Vec<isize> = fds.iter().map(|f| write_all(*f, k.as_bytes())).collect();
                format!("open=ok sent={sent:?}")
            }
            Err(e) => format!("open={e}"),
        };
        let _ = std::fs::write(&rp, out);
        0
    })?;
    assert_eq!(code, Some(0));
    Some(report_of(&secret.report()))
}

#[test]
#[ignore]
fn a_socket_held_before_the_taint_refuses_the_raw_open() {
    lo_up();
    let off = udp_listener([127, 0, 0, 3], 0);
    let port = off.local_addr().unwrap().port();
    let (off_tcp, off_tcp_got) = tcp_listener([127, 0, 0, 3]);
    let (proxy, _) = tcp_listener([127, 0, 0, 1]);
    let (bound, _) = tcp_listener([127, 0, 0, 2]);

    // Connected UDP and TCP to an unbound peer: refused.
    let Some(r) = open_after("pre-udp", &["127.0.0.2"], proxy, move || {
        let u = udp_socket();
        connect(u, [127, 0, 0, 3], port);
        vec![u]
    }) else { return };
    assert_eq!(r, "open=13", "a connected UDP socket to an unbound peer");
    let r = open_after("pre-tcp", &["127.0.0.2"], proxy, move || vec![tcp_connect([127, 0, 0, 3], off_tcp).unwrap()]).unwrap();
    assert_eq!(r, "open=13", "a connected TCP socket to an unbound peer");
    // 127.0.0.1 off the proxy port (finding path 3 through the sweep).
    let r = open_after("pre-lo", &["127.0.0.2"], proxy, move || {
        let u = udp_socket();
        connect(u, [127, 0, 0, 1], port);
        vec![u]
    })
    .unwrap();
    assert_eq!(r, "open=13", "UDP to 127.0.0.1 off the proxy port");
    // Held by a descendant that lives on: refused.
    let r = open_after("pre-child", &["127.0.0.2"], proxy, move || {
        let (rd, wr) = {
            let mut p = [0; 2];
            unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) };
            (p[0], p[1])
        };
        if unsafe { libc::fork() } == 0 {
            let u = udp_socket();
            connect(u, [127, 0, 0, 3], port);
            write_all(wr, b"r");
            std::thread::sleep(Duration::from_secs(3));
            unsafe { libc::_exit(0) };
        }
        let mut b = [0u8; 1];
        unsafe { libc::read(rd, b.as_mut_ptr() as *mut libc::c_void, 1) };
        vec![]
    })
    .unwrap();
    assert_eq!(r, "open=13", "a descendant's connected socket");
    // Controls: the proxy, a binding, an unconnected socket.
    let r = open_after("pre-proxy", &["127.0.0.2"], proxy, move || vec![tcp_connect([127, 0, 0, 1], proxy).unwrap()]).unwrap();
    assert!(r.starts_with("open=ok"), "a socket to the session's proxy: {r}");
    let r = open_after("pre-bound", &["127.0.0.2"], proxy, move || vec![tcp_connect([127, 0, 0, 2], bound).unwrap()]).unwrap();
    assert!(r.starts_with("open=ok"), "a socket to a binding: {r}");
    let r = open_after("pre-unconnected", &["127.0.0.2"], proxy, move || {
        udp_socket();
        // An unconnected TCP socket is in no /proc/net table: its state says.
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        vec![]
    })
    .unwrap();
    assert!(r.starts_with("open=ok"), "unconnected UDP and TCP sockets: {r}");
    // A connect in flight (nonblocking) to an unbound peer.
    let r = open_after("pre-inflight", &["127.0.0.2"], proxy, move || {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
        connect(fd, [127, 0, 0, 3], off_tcp);
        vec![fd]
    })
    .unwrap();
    assert_eq!(r, "open=13", "a connect in flight to an unbound peer");
    std::thread::sleep(Duration::from_millis(200));
    assert!(drain(&off).is_empty());
    assert!(!String::from_utf8_lossy(&off_tcp_got.lock().unwrap()).contains(CANARY));
    eprintln!("PRE-TAINT SWEEP PASS");
}

// ── whose taint: threads, and a descendant that outlives its parent ─────────

#[test]
#[ignore]
fn the_taint_is_the_processes_whichever_thread_opened_or_sends() {
    lo_up();
    let off = udp_listener([127, 0, 0, 3], 0);
    let port = off.local_addr().unwrap().port();
    let (off_tcp, _) = tcp_listener([127, 0, 0, 3]);
    let secret = Secret::new("threads");
    let arbiter = reader_arbiter(&["127.0.0.2"]);
    let cfg = secret_cfg(&secret, arbiter, 1);
    let (path, rp) = (secret.path.clone(), secret.report());
    let Some(code) = guarded(secret_traps(), cfg, move || {
        // A worker thread opens; the main thread sends.
        let p2 = path.clone();
        let k = std::thread::spawn(move || read_file(&p2)).join().unwrap().unwrap_or_default();
        let fd = udp_socket();
        let mut out = format!("raw={} main_sendto={} main_tcp={} ", k.contains(CANARY), sendto(fd, k.as_bytes(), [127, 0, 0, 3], port), tcp_connect([127, 0, 0, 3], off_tcp).err().unwrap_or(0));
        // And a worker thread sends.
        let w = std::thread::spawn(move || (sendto(udp_socket(), CANARY.as_bytes(), [127, 0, 0, 3], port), tcp_connect([127, 0, 0, 3], off_tcp).err().unwrap_or(0))).join().unwrap();
        out += &format!("worker_sendto={} worker_tcp={}", w.0, w.1);
        let _ = std::fs::write(&rp, out);
        0
    }) else { return };
    assert_eq!(code, Some(0));
    let seen = report_of(&secret.report());
    assert_eq!(seen, "raw=true main_sendto=-13 main_tcp=13 worker_sendto=-13 worker_tcp=13", "{seen}");
    assert!(drain(&off).is_empty());
    eprintln!("THREAD TAINT PASS");
}

#[test]
#[ignore]
fn a_descendant_judged_once_stays_tainted_after_its_parent_exits() {
    lo_up();
    let off = udp_listener([127, 0, 0, 3], 0);
    let port = off.local_addr().unwrap().port();
    let secret = Secret::new("orphan");
    let arbiter = reader_arbiter(&["127.0.0.2"]);
    let cfg = secret_cfg(&secret, arbiter, 1);
    let path = secret.path.clone();
    // The grandchild reports on a pipe (write(2) is not trapped; once it is
    // reparented away from this test process, the guard of this harness is
    // no longer its ancestor, where the launcher's guard is the subreaper).
    let mut p = [0; 2];
    assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let (rd, wr) = (p[0], p[1]);
    let Some(code) = guarded_keep(secret_traps(), cfg, &[wr], move || {
        let k = read_file(&path).unwrap_or_default();
        let parent = unsafe { libc::getpid() };
        if unsafe { libc::fork() } == 0 {
            // Judged once while the parent lives (refused: it holds the key).
            let first = sendto(udp_socket(), k.as_bytes(), [127, 0, 0, 3], port);
            // Then orphaned: wait until reparented, and send again.
            let end = Instant::now() + Duration::from_secs(5);
            while unsafe { libc::getppid() } == parent && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(10));
            }
            let reparented = unsafe { libc::getppid() } != parent;
            let second = sendto(udp_socket(), k.as_bytes(), [127, 0, 0, 3], port);
            let msg = format!("first={first} reparented={reparented} second={second}");
            write_all(wr, msg.as_bytes());
            unsafe { libc::_exit(0) };
        }
        // Exit once the child was judged (its first send went through the guard).
        std::thread::sleep(Duration::from_millis(300));
        0
    }) else { return };
    assert_eq!(code, Some(0));
    unsafe { libc::close(wr) };
    // Its writer is an orphan now, no child of this process to name.
    readable_within_tree(rd, wait_limit(), "waiting for the orphaned grandchild's report");
    let mut buf = vec![0u8; 256];
    let n = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    unsafe { libc::close(rd) };
    let seen = String::from_utf8_lossy(&buf[..n.max(0) as usize]).to_string();
    assert_eq!(seen, "first=-13 reparented=true second=-13", "{seen}");
    assert!(drain(&off).is_empty());
    eprintln!("ORPHAN TAINT PASS");
}

// ── §4.1: a holder's argv (plan 10 §11.13.1, "found on the way") ────────────

/// `/proc/<pid>/<what>` read by THIS process: its bytes, or the errno.
fn read_proc(pid: i32, what: &str) -> Result<Vec<u8>, i32> {
    std::fs::read(format!("/proc/{pid}/{what}")).map_err(|e| e.raw_os_error().unwrap_or(-1))
}

fn exec_sh_with_arg(arg: &str) -> ! {
    // `sleep; :` (two commands): a shell that execs its last command would
    // replace this argv with sleep's. 60 s, and the test kills both shells
    // AND their sleeps (each runs in a process group of its own; a sleep left
    // behind would keep the guard's filter, and the test, alive for its 60
    // s) when it has read them: with 5 s the control had already exited (a
    // zombie, its cmdline empty) when a loaded CI guest got to the reads
    // (2026-10-17, `control_cmdline=ok`).
    let argv: Vec<std::ffi::CString> = ["sh", "-c", "sleep 60; :", arg].iter().map(|s| std::ffi::CString::new(*s).unwrap()).collect();
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let sh = std::ffi::CString::new("/bin/sh").unwrap();
    unsafe {
        libc::setpgid(0, 0);
        libc::execv(sh.as_ptr(), ptrs.as_ptr());
        libc::_exit(127)
    }
}

#[test]
#[ignore]
fn a_holders_argv_is_refused_to_an_untainted_reader() {
    // A listed reader that expands its secret into a command line
    // (`curl -H "Authorization: Bearer $KEY"`) put it in `/proc/<pid>/cmdline`,
    // which the introspection list did not name: `ps -ef` in another tool
    // call printed it to the model, and an untainted process could poll it.
    let secret = Secret::new("cmdline");
    let arbiter = reader_arbiter(&[]);
    let cfg = secret_cfg(&secret, arbiter, 1);
    let (path, rp) = (secret.path.clone(), secret.report());
    // The holder signals by a file, not a pipe: a pipe from the holder makes
    // its reader (and every process that inherited the read end) a holder
    // too (plan 13 D2), and this process must stay untainted.
    let mark = secret.dir.join("read.mark");
    let Some(code) = guarded(secret_traps(), cfg, move || {
        // The control: an untainted process with an argument of its own.
        let u = unsafe { libc::fork() };
        if u == 0 {
            exec_sh_with_arg("LIVE-ARGV-0042");
        }
        // The holder: reads the secret raw, then runs with it in its argv.
        // DETACHED (a middle process forks it and exits; the namespace's
        // init adopts it before it reads): since 2026-10-03 the parent of a
        // holder becomes one (plan 13 §4.9, the exit status), and this
        // process must stay untainted. Its pid comes back over a pipe the
        // middle process writes (no holder writes it).
        let (pr, pw) = {
            let mut p = [0; 2];
            assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            (p[0], p[1])
        };
        let mid = unsafe { libc::fork() };
        if mid == 0 {
            let h = unsafe { libc::fork() };
            if h == 0 {
                unsafe {
                    libc::close(pr);
                    libc::close(pw);
                }
                let parent = unsafe { libc::getppid() };
                for _ in 0..2000 {
                    if unsafe { libc::getppid() } != parent {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                let k = read_file(&path).unwrap_or_default();
                if !k.contains(CANARY) {
                    unsafe { libc::_exit(3) };
                }
                let _ = std::fs::write(&mark, "r");
                exec_sh_with_arg(k.trim_end());
            }
            unsafe { libc::write(pw, &h as *const i32 as *const libc::c_void, 4) };
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::close(pw) };
        let mut hb = [0u8; 4];
        let n = unsafe { libc::read(pr, hb.as_mut_ptr() as *mut libc::c_void, 4) };
        unsafe { libc::close(pr) };
        reap(mid);
        if n != 4 {
            return 9;
        }
        let h = i32::from_ne_bytes(hb);
        for _ in 0..500 {
            if mark.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Both execs done: each process's name is the shell's (its `stat`,
        // which stays readable), not a fixed pause that a loaded runner
        // outlasts (the control's argv then still the test binary's).
        let execd = |p: i32| read_proc(p, "stat").map(|s| String::from_utf8_lossy(&s).contains("(sh)")).unwrap_or(false);
        let end = Instant::now() + Duration::from_secs(20);
        while !(execd(u) && execd(h)) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        let show = |r: Result<Vec<u8>, i32>| match r {
            Ok(v) if String::from_utf8_lossy(&v).contains(CANARY) => "CANARY".to_string(),
            Ok(v) if String::from_utf8_lossy(&v).contains("LIVE-ARGV-0042") => "live".to_string(),
            Ok(_) => "ok".to_string(),
            Err(e) => format!("{e}"),
        };
        // This process never read the secret: it is not tainted.
        let mut out = String::new();
        out += &format!("cmdline={} ", show(read_proc(h, "cmdline")));
        out += &format!("task_cmdline={} ", show(read_proc(h, &format!("task/{h}/cmdline"))));
        out += &format!("environ={} ", show(read_proc(h, "environ")));
        out += &format!("stat={} ", show(read_proc(h, "stat")));
        out += &format!("status={} ", show(read_proc(h, "status")));
        out += &format!("control_cmdline={} ", show(read_proc(u, "cmdline")));
        // `ps` as the agent runs it, when the image has it.
        match std::process::Command::new("ps").args(["-o", "pid=,args=", "-p", &format!("{h},{u}")]).output() {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout).to_string();
                out += &format!("ps_canary={} ps_live={} ps_lists_holder={} ", s.contains(CANARY), s.contains("LIVE-ARGV-0042"), s.lines().any(|l| l.trim_start().starts_with(&h.to_string())));
                // What the holder's row looks like (the doc quotes it).
                let row = s.lines().find(|l| l.trim_start().starts_with(&h.to_string())).unwrap_or("").replace(CANARY, "<canary>");
                out += &format!("ps_row=[{}] ", row.trim());
            }
            Err(_) => out += "ps=absent ",
        }
        let _ = std::fs::write(&rp, out);
        unsafe {
            libc::kill(-h, libc::SIGKILL);
            libc::kill(-u, libc::SIGKILL);
        }
        reap(u);
        0
    }) else { return };
    assert_eq!(code, Some(0));
    let seen = report_of(&secret.report());
    eprintln!("{seen}");
    for want in ["cmdline=13 ", "task_cmdline=13 ", "environ=13 ", "stat=ok ", "status=ok ", "control_cmdline=live "] {
        assert!(seen.contains(want), "{want} missing: {seen}");
    }
    if !seen.contains("ps=absent") {
        assert!(seen.contains("ps_canary=false"), "ps printed the holder's argv: {seen}");
        assert!(seen.contains("ps_live=true"), "control: ps shows an untainted process's argv: {seen}");
        assert!(seen.contains("ps_lists_holder=true"), "ps still lists the holder (without its argv): {seen}");
        // procps shows a process whose command line it cannot read by its
        // name in brackets (guarantees.md quotes this).
        assert!(seen.contains("[sh]"), "the holder's row: {seen}");
    }
    eprintln!("HOLDER ARGV PASS");
}

// ── Unix datagrams, SCM_RIGHTS, pidfd_getfd, routes, blocking sends ─────────

#[test]
#[ignore]
fn a_unix_datagram_to_a_path_is_judged_like_a_connect() {
    let secret = Secret::new("unixdgram");
    let arbiter = reader_arbiter(&["127.0.0.2"]);
    let sock_path = secret.dir.join("dgram.sock");
    let listener = std::os::unix::net::UnixDatagram::bind(&sock_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let send_to_path = |p: &Path, data: &[u8]| -> isize {
        let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
        let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        a.sun_family = libc::AF_UNIX as u16;
        for (i, b) in p.as_os_str().as_encoded_bytes().iter().enumerate() {
            a.sun_path[i] = *b as libc::c_char;
        }
        let n = unsafe { libc::sendto(s, data.as_ptr() as *const libc::c_void, data.len(), 0, &a as *const _ as *const libc::sockaddr, std::mem::size_of_val(&a) as u32) };
        if n < 0 { -(errno() as isize) } else { n }
    };
    // A holder: refused (not a `unix:` binding).
    let cfg = secret_cfg(&secret, arbiter, 1);
    let (path, sp, rp) = (secret.path.clone(), sock_path.clone(), secret.report());
    let Some(code) = guarded(secret_traps(), cfg, move || {
        let k = read_file(&path).unwrap_or_default();
        let _ = std::fs::write(&rp, format!("tainted={}", send_to_path(&sp, k.as_bytes())));
        0
    }) else { return };
    assert_eq!(code, Some(0));
    assert_eq!(report_of(&secret.report()), "tainted=-13");
    let mut buf = [0u8; 256];
    assert!(listener.recv(&mut buf).is_err(), "a holder's datagram arrived");
    // Untainted: delivered, and a descriptor passed over SCM_RIGHTS works.
    let cfg = secret_cfg(&secret, arbiter, 1);
    let (sp, rp) = (sock_path.clone(), secret.report());
    let Some(code) = guarded(secret_traps(), cfg, move || {
        let sent = send_to_path(&sp, b"LIVE-unix");
        let (a, b) = socketpair(libc::SOCK_DGRAM);
        let mut p = [0; 2];
        unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) };
        let mut cbuf = [0u64; 4];
        let mut iov = libc::iovec { iov_base: b"fd".as_ptr() as *mut libc::c_void, iov_len: 2 };
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
            std::ptr::copy_nonoverlapping(&p[1] as *const i32 as *const u8, libc::CMSG_DATA(c), 4);
        }
        let n = unsafe { libc::sendmsg(a, &m, 0) };
        // Receive the descriptor, write through it, read the pipe.
        let mut rbuf = [0u8; 8];
        let mut riov = libc::iovec { iov_base: rbuf.as_mut_ptr() as *mut libc::c_void, iov_len: 8 };
        let mut rc = [0u64; 4];
        let mut rm: libc::msghdr = unsafe { std::mem::zeroed() };
        rm.msg_iov = &mut riov;
        rm.msg_iovlen = 1;
        rm.msg_control = rc.as_mut_ptr() as *mut libc::c_void;
        rm.msg_controllen = std::mem::size_of_val(&rc) as _;
        unsafe { libc::recvmsg(b, &mut rm, 0) };
        let mut passed = -1;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&rm);
            if !c.is_null() {
                std::ptr::copy_nonoverlapping(libc::CMSG_DATA(c), &mut passed as *mut i32 as *mut u8, 4);
            }
        }
        write_all(passed, b"through");
        let mut got = [0u8; 16];
        let r = unsafe { libc::read(p[0], got.as_mut_ptr() as *mut libc::c_void, 16) };
        let _ = std::fs::write(&rp, format!("sent={sent} rights={n} piped={}", String::from_utf8_lossy(&got[..r.max(0) as usize])));
        0
    }) else { return };
    assert_eq!(code, Some(0));
    assert_eq!(report_of(&secret.report()), "sent=9 rights=2 piped=through");
    let n = listener.recv(&mut buf).expect("control: the untainted datagram arrives");
    assert_eq!(&buf[..n], b"LIVE-unix");
    eprintln!("UNIX DGRAM PASS");
}

#[test]
#[ignore]
fn pidfd_getfd_and_routes_are_refused() {
    let secret = Secret::new("pidfd");
    let arbiter = reader_arbiter(&[]);
    let cfg = secret_cfg(&secret, arbiter, 1);
    let rp = secret.report();
    let Some(code) = guarded(secret_traps(), cfg, move || {
        let pfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
        let r = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pfd, 0, 0) };
        let getfd = if r < 0 { errno() } else { 0 };
        let opt = |fam: i32, level: i32, name: i32, val: &[u8]| -> i32 {
            let s = unsafe { libc::socket(fam, libc::SOCK_DGRAM, 0) };
            if unsafe { libc::setsockopt(s, level, name, val.as_ptr() as *const libc::c_void, val.len() as u32) } == 0 { 0 } else { errno() }
        };
        let mut rh = vec![0u8, 2, 2, 1, 0, 0, 0, 0];
        rh.extend_from_slice(&[0u8; 15]);
        rh.push(1);
        let rthdr = opt(libc::AF_INET6, libc::IPPROTO_IPV6, 57, &rh);
        let ipopt = opt(libc::AF_INET, libc::IPPROTO_IP, libc::IP_OPTIONS, &[1, 0x83, 7, 4, 127, 0, 0, 3]);
        let tos = opt(libc::AF_INET, libc::IPPROTO_IP, libc::IP_TOS, &16i32.to_ne_bytes());
        let _ = std::fs::write(&rp, format!("getfd={getfd} rthdr={rthdr} ipopt={ipopt} tos={tos}"));
        0
    }) else { return };
    assert_eq!(code, Some(0));
    assert_eq!(report_of(&secret.report()), "getfd=1 rthdr=1 ipopt=1 tos=0");
    eprintln!("PIDFD + ROUTES PASS");
}

#[test]
#[ignore]
fn a_blocking_stream_send_is_sent_whole_and_holds_no_worker() {
    lo_up();
    let sink = udp_listener([127, 0, 0, 4], 0);
    let port = sink.local_addr().unwrap().port();
    let cfg = static_cfg(&["udp:127.0.0.4/32:*"]);
    let report = std::env::temp_dir().join(format!("mandu-send-block-{}.txt", run_tag()));
    let rp = report.clone();
    let Some(code) = guarded(FilterTraps::default(), cfg, move || {
        let (a, b) = socketpair(libc::SOCK_STREAM);
        let small = 4096i32;
        unsafe { libc::setsockopt(a, libc::SOL_SOCKET, libc::SO_SNDBUF, &small as *const i32 as *const libc::c_void, 4) };
        let data: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();
        // A reader that starts late: the send must wait, then finish whole.
        let reader = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let mut got = Vec::new();
            let mut buf = vec![0u8; 65536];
            while got.len() < 1_048_576 {
                let n = unsafe { libc::read(b, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n <= 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n as usize]);
            }
            got
        });
        // Meanwhile another thread's trapped sends are answered.
        let side = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            sendto(udp_socket(), b"SIDE", [127, 0, 0, 4], port)
        });
        let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
        let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
        m.msg_iov = &mut iov;
        m.msg_iovlen = 1;
        let n = unsafe { libc::sendmsg(a, &m, 0) };
        let got = reader.join().unwrap();
        let side = side.join().unwrap();
        let _ = std::fs::write(&rp, format!("sent={n} whole={} side={side}", got == data));
        0
    }) else { return };
    assert_eq!(code, Some(0));
    assert_eq!(report_of(&report), "sent=1048576 whole=true side=4");
    let _ = std::fs::remove_file(&report);
    eprintln!("BLOCKING STREAM PASS");
}

#[test]
#[ignore]
fn an_icmp_echo_is_not_a_udp_datagram() {
    // Best effort: an unprivileged ICMP echo socket needs the caller's group
    // in ping_group_range (per network namespace; a fresh one allows none).
    lo_up();
    let _ = std::fs::write("/proc/sys/net/ipv4/ping_group_range", "0 2147483647");
    let probe = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if probe < 0 {
        eprintln!("note: no unprivileged ICMP socket here; the decision is unit-tested (send_guard::an_icmp_socket_is_not_covered_by_a_udp_rule)");
        return;
    }
    unsafe { libc::close(probe) };
    let cfg = static_cfg(&["udp:*:53"]);
    let Some(code) = guarded(FilterTraps::default(), cfg, move || {
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
        let echo = [8u8, 0, 0, 0, 0, 1, 0, 1, b'x'];
        let r = sendto(s, &echo, [127, 0, 0, 3], 53);
        (r != -(libc::EACCES as isize)) as i32
    }) else { return };
    assert_eq!(code, Some(0), "an ICMP echo to 'port' 53 must not pass a udp:*:53 rule");
}

#[allow(dead_code)]
fn _unused(_: &dyn AsRawFd) {}
