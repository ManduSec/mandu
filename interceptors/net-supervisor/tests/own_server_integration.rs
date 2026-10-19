//! own_server_integration — the agent's PRIVATE server under the guard
//! (supported-agents.md §2.3.1; `own_server`): OpenCode 2's `--standalone`
//! client spawns its server as a child of the same executable, which binds an
//! ephemeral loopback port, and only the CLIENT may connect to it.
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! or the kernel lane of `scripts/ci/vm-run.sh` (an unprivileged user +
//! network + pid namespace; `lo` is brought up here). A host where the
//! seccomp listener cannot be installed SKIPs.
//!
//! The guarded body is the CLIENT (the first-started process of the named
//! executable, this test binary); it forks its SERVER (same executable),
//! which binds 127.0.0.1:0 and serves; the server forks a COMMAND (same
//! executable, the shape of a nested `opencode run`, or of any agent's
//! command). With no allow rule for loopback:
//!
//!   (1) the client connects to its server and gets the reply;
//!   (2) the command's connect to the server is refused (EACCES), and so is
//!       a second, later child of the client running another program's
//!       shape (it forks from the client but is not the server: it holds no
//!       listener, and connecting is the client's right only);
//!   (3) the client's connect to a listener OUTSIDE the tree (the user's
//!       background service) is refused;
//!   (4) a listener the command opens on its own ephemeral port is not the
//!       server's: the client's connect to it is refused;
//!   (5) the allowance off (no `OWN_SERVER_ENV`): the client's connect to
//!       its server is refused, as before;
//!   (6) the command cannot copy a descriptor out of the client
//!       (pidfd_getfd: EPERM for the whole tree);
//!   (7) a Landlock layer the server nested itself still decides its bind:
//!       a layer that grants no bind port refuses the ephemeral bind even
//!       though the guard performs it (on a mirror of that layer).

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{empty_own_cmdline, in_test_process, join_within, pipe, readable_within, reap_within, run_tag, socketpair, wait_limit};

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use net_supervisor::guard::{parse_rules, GuardPolicy, NoResolver};
use net_supervisor::guard_kernel::{hand_listener, install_guard_filter_self, receive_listener, run_guard_supervisor, FilterTraps, GuardConfig};

const EXIT_NO_SECCOMP: i32 = 91;

fn lo_up() {
    let _ = std::process::Command::new("ip").args(["link", "set", "lo", "up"]).stderr(std::process::Stdio::null()).status();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn reap(pid: i32) -> Option<i32> {
    if in_test_process() {
        return reap_within(pid, wait_limit(), "waiting for a child the test forked").code();
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) { Some(libc::WEXITSTATUS(status)) } else { None }
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

/// No loopback rule at all: only the allowance can admit a connect.
fn cfg(own_server: bool) -> GuardConfig {
    let mut c = GuardConfig::new(Arc::new(GuardPolicy::new(parse_rules(&["tcp:192.0.2.1:9".to_string()]).unwrap())), Arc::new(NoResolver));
    if own_server {
        c.own_server = Some(this_exe());
    }
    c
}

fn traps() -> FilterTraps {
    FilterTraps { own_server: true, ..Default::default() }
}

fn work_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("mandu-own-server-{tag}-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A raw connect to 127.0.0.1:`port`: Ok(the reply) or Err(errno).
fn try_connect(port: u16) -> Result<String, i32> {
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if s < 0 {
        return Err(errno());
    }
    let sa = libc::sockaddr_in { sin_family: libc::AF_INET as u16, sin_port: port.to_be(), sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) }, sin_zero: [0; 8] };
    let rc = unsafe { libc::connect(s, &sa as *const _ as *const libc::sockaddr, std::mem::size_of_val(&sa) as libc::socklen_t) };
    if rc != 0 {
        let e = errno();
        unsafe { libc::close(s) };
        return Err(e);
    }
    let mut t = unsafe { TcpStream::from_raw_fd(s) };
    let _ = t.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = String::new();
    let _ = t.read_to_string(&mut buf);
    Ok(buf)
}

/// A raw ephemeral loopback bind + listen: Ok(fd, port) or Err(errno).
fn ephemeral_listener() -> Result<(RawFd, u16), i32> {
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if s < 0 {
        return Err(errno());
    }
    let sa = libc::sockaddr_in { sin_family: libc::AF_INET as u16, sin_port: 0, sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) }, sin_zero: [0; 8] };
    if unsafe { libc::bind(s, &sa as *const _ as *const libc::sockaddr, std::mem::size_of_val(&sa) as libc::socklen_t) } != 0 {
        let e = errno();
        unsafe { libc::close(s) };
        return Err(e);
    }
    if unsafe { libc::listen(s, 16) } != 0 {
        return Err(errno());
    }
    let mut got: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&got) as libc::socklen_t;
    unsafe { libc::getsockname(s, &mut got as *mut _ as *mut libc::sockaddr, &mut len) };
    Ok((s, u16::from_be(got.sin_port)))
}

/// Serve `reply` on `fd` to every connection until `stop` exists.
fn serve(fd: RawFd, reply: &'static str, stop: PathBuf) {
    let l = unsafe { TcpListener::from_raw_fd(fd) };
    l.set_nonblocking(true).unwrap();
    while !stop.exists() {
        match l.accept() {
            Ok((mut c, _)) => {
                let _ = c.write_all(reply.as_bytes());
            }
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
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

fn verdict(r: Result<String, i32>) -> String {
    match r {
        Ok(s) => format!("ok:{s}"),
        Err(e) => format!("errno:{e}"),
    }
}

/// The tree: client (body) → server (binds, serves "server") → command
/// (connects to the server; opens its own listener). Then the client
/// connects to its server, to an outside listener, and to the command's.
fn scenario(own_server: bool, tag: &str) -> Option<Run> {
    let run = Run { dir: work_dir(tag) };
    let outside = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    let outside_port = outside.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut c in outside.incoming().flatten() {
            let _ = c.write_all(b"outside");
        }
    });
    let dir = run.dir.clone();
    let code = guarded(traps(), cfg(own_server), move || {
        let r = Run { dir };
        let stop = r.dir.join("stop");
        // The server: the client's own child on the same executable.
        let rs = Run { dir: r.dir.clone() };
        let stop_s = stop.clone();
        let server = fork_run(move || {
            match ephemeral_listener() {
                Ok((fd, port)) => {
                    rs.put("server-port", &port.to_string());
                    // The command: the server's child (an agent's command).
                    let rc = Run { dir: rs.dir.clone() };
                    let stop_c = stop_s.clone();
                    let _cmd = fork_run(move || {
                        // A command does not keep its server's listener (OpenCode's
                        // sockets are close-on-exec); a holder that is not the
                        // server makes the listener no longer the server's alone,
                        // and the client's connect is refused (the pure test).
                        unsafe { libc::close(fd) };
                        rc.put("command-connect", &verdict(try_connect(port)));
                        // Copying a descriptor out of another process (the
                        // client's connection to its server) is refused.
                        let server_pid = unsafe { libc::getppid() };
                        let client_pid = std::fs::read_to_string(format!("/proc/{server_pid}/stat")).ok()
                            .and_then(|s| s.rsplit(')').next().map(str::to_string))
                            .and_then(|s| s.split_whitespace().nth(1).and_then(|p| p.parse::<i32>().ok()))
                            .unwrap_or(0);
                        let pfd = unsafe { libc::syscall(libc::SYS_pidfd_open, client_pid, 0) } as i32;
                        let got = if pfd < 0 { -1 } else { unsafe { libc::syscall(libc::SYS_pidfd_getfd, pfd, 0, 0) as i32 } };
                        rc.put("command-getfd", &if got < 0 { format!("errno:{}", errno()) } else { "copied".into() });
                        match ephemeral_listener() {
                            Ok((cfd, cport)) => {
                                rc.put("command-port", &cport.to_string());
                                serve(cfd, "command", stop_c);
                            }
                            Err(e) => rc.put("command-port", &format!("errno:{e}")),
                        }
                        0
                    });
                    serve(fd, "server", stop_s);
                }
                Err(e) => rs.put("server-port", &format!("errno:{e}")),
            }
            0
        });
        let Some(port) = r.get("server-port") else { return 10 };
        let Ok(port) = port.parse::<u16>() else {
            r.put("client-own", &format!("server bind: {port}"));
            let _ = std::fs::write(&stop, "");
            reap(server);
            return 0;
        };
        let _ = r.get("command-connect");
        r.put("client-own", &verdict(try_connect(port)));
        r.put("client-outside", &verdict(try_connect(outside_port)));
        if let Some(cp) = r.get("command-port").and_then(|p| p.parse::<u16>().ok()) {
            r.put("client-command", &verdict(try_connect(cp)));
        }
        // A later child of the client that is not the server.
        let ro = Run { dir: r.dir.clone() };
        let other = fork_run(move || {
            ro.put("other-child", &verdict(try_connect(port)));
            0
        });
        reap(other);
        let _ = std::fs::write(&stop, "");
        reap(server);
        0
    })?;
    assert_eq!(code, Some(0), "the guarded tree exited cleanly");
    Some(run)
}

const EACCES: &str = "errno:13";

#[test]
#[ignore]
fn only_the_client_reaches_its_own_server() {
    let _g = serial();
    let Some(run) = scenario(true, "on") else { return };
    // The server's ephemeral loopback bind (performed by the guard).
    assert!(run.get("server-port").unwrap().parse::<u16>().is_ok(), "the server bound: {:?}", run.get("server-port"));
    // (1) the client gets its server's reply.
    assert_eq!(run.get("client-own").as_deref(), Some("ok:server"));
    // (2) the server's command, and another child of the client: refused.
    assert_eq!(run.get("command-connect").as_deref(), Some(EACCES));
    assert_eq!(run.get("other-child").as_deref(), Some(EACCES));
    // ...nor can it copy the client's descriptors (pidfd_getfd: EPERM).
    assert_eq!(run.get("command-getfd").as_deref(), Some("errno:1"));
    // (3) a listener outside the tree (the user's background service): refused.
    assert_eq!(run.get("client-outside").as_deref(), Some(EACCES));
    // (4) the command's own listener is not the client's server: refused.
    assert_eq!(run.get("client-command").as_deref(), Some(EACCES));
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
#[ignore]
fn without_the_allowance_the_client_is_refused_like_everyone() {
    let _g = serial();
    let Some(run) = scenario(false, "off") else { return };
    assert_eq!(run.get("client-own").as_deref(), Some(EACCES));
    assert_eq!(run.get("command-connect").as_deref(), Some(EACCES));
    assert_eq!(run.get("client-outside").as_deref(), Some(EACCES));
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
#[ignore]
fn a_landlock_layer_the_server_nested_still_decides_its_bind() {
    use fs_supervisor::landlock::{landlock_abi_version, landlock_net_supported, plan_net_confine, restrict_self_to_plan};
    let _g = serial();
    if !landlock_net_supported() {
        eprintln!("SKIP: Landlock has no TCP rules on this kernel");
        return;
    }
    let dir = work_dir("nested");
    let d2 = dir.clone();
    let Some(code) = guarded(traps(), cfg(true), move || {
        let r = Run { dir: d2 };
        let rs = Run { dir: r.dir.clone() };
        let server = fork_run(move || {
            // No bind port and no connect port: the server's own sandbox.
            let plan = plan_net_confine(&[], &[], landlock_abi_version() as u32);
            if restrict_self_to_plan(&plan).is_err() {
                rs.put("bind", "no-landlock");
                return 0;
            }
            rs.put("bind", &match ephemeral_listener() {
                Ok((_, port)) => format!("bound:{port}"),
                Err(e) => format!("errno:{e}"),
            });
            0
        });
        reap(server);
        0
    }) else { return };
    assert_eq!(code, Some(0));
    let got = Run { dir: dir.clone() }.get("bind");
    if got.as_deref() == Some("no-landlock") {
        eprintln!("SKIP: the server could not apply a Landlock layer");
    } else {
        assert_eq!(got.as_deref(), Some(EACCES), "the server's own layer refuses the bind the guard performs");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── a fork of the server before its exec (exec-routing.md §7.5) ──────────────
//
// (10) The server forks (a command it spawns) as the client connects; until
// its exec the fork holds a copy of the close-on-exec listener. The guard
// waits for that exec (FORK_EXEC_WAIT) and admits the client's connect. (11)
// A fork that holds it past the wait (it never execs) still refuses it.

/// The server forks a child holding its close-on-exec listener; the child
/// execs `/bin/sleep` after `exec_after_ms`, or never (it sleeps 4 s, past the
/// guard's 2 s wait). The client connects while the fork holds the listener.
fn fork_window_scenario(exec_after_ms: Option<u64>, tag: &str) -> Option<Run> {
    let run = Run { dir: work_dir(tag) };
    let dir = run.dir.clone();
    let code = guarded(traps(), cfg(true), move || {
        let r = Run { dir };
        let stop = r.dir.join("stop");
        let rs = Run { dir: r.dir.clone() };
        let stop_s = stop.clone();
        let server = fork_run(move || {
            let Ok((fd, port)) = ephemeral_listener() else {
                rs.put("server-port", "errno");
                return 0;
            };
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            let rf = Run { dir: rs.dir.clone() };
            let _fork = fork_run(move || {
                rf.put("fork-up", "1");
                match exec_after_ms {
                    Some(ms) => {
                        std::thread::sleep(Duration::from_millis(ms));
                        let prog = std::ffi::CString::new("/bin/sleep").unwrap();
                        let arg = std::ffi::CString::new("1").unwrap();
                        let argv = [prog.as_ptr(), arg.as_ptr(), std::ptr::null()];
                        unsafe { libc::execv(prog.as_ptr(), argv.as_ptr()) };
                        1
                    }
                    None => {
                        std::thread::sleep(Duration::from_secs(4));
                        0
                    }
                }
            });
            rs.put("server-port", &port.to_string());
            serve(fd, "server", stop_s);
            0
        });
        let port = r.get("server-port").and_then(|p| p.parse::<u16>().ok());
        let _ = r.get("fork-up");
        r.put("client-own", &match port {
            Some(p) => verdict(try_connect(p)),
            None => "no server".to_string(),
        });
        let _ = std::fs::write(&stop, "");
        reap(server);
        0
    })?;
    assert_eq!(code, Some(0), "the guarded tree exited cleanly");
    Some(run)
}

#[test]
#[ignore]
fn the_client_reaches_its_server_while_a_fork_of_it_is_on_its_way_to_an_exec() {
    let _g = serial();
    let Some(run) = fork_window_scenario(Some(400), "fork-exec") else { return };
    assert_eq!(run.get("client-own").as_deref(), Some("ok:server"), "(10) the guard waited for the fork's exec");
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
#[ignore]
fn a_fork_that_keeps_the_listener_past_the_wait_still_refuses_the_client() {
    let _g = serial();
    let Some(run) = fork_window_scenario(None, "fork-keeps") else { return };
    assert_eq!(run.get("client-own").as_deref(), Some(EACCES), "(11) a holder that is not the server, past the wait");
    let _ = std::fs::remove_dir_all(&run.dir);
}

// ── a first look inside the fork's exec (exec-routing.md §7.5) ───────────────
//
// (12) The server forks and execs at once, in a tight loop, while the client
// connects again and again: a connect whose first look at the fork lands
// INSIDE its exec (the image switched, the close-on-exec listener not closed
// yet) is held until that exec ends and admitted (`own_server::first_look`,
// `guard_flow::wait_exec_done`). The server carries a large populated heap,
// so each exec's teardown of the old image (`exec_mmap`'s `mmput`, in that
// window) takes milliseconds and the looks land there often. Before the fix
// such a connect was refused (by a guard that reads the table there: root in
// the tree's user namespace, as in these tests). (13) A fork that looks
// inside an exec forever (an emptied command line, `PR_SET_MM_MAP`) is
// refused at the same bound; and so is one whose table cannot be read as
// well (non-dumpable, as every process is inside its exec to a guard that is
// not root in its user namespace), which was read as holding nothing and
// admitted the connect at once.

/// The server's heap: populated, small pages (no THP), so the fork copies
/// and the exec tears down this many page-table entries.
const BALLAST_MB: usize = 256;

/// A populated anonymous mapping of `mb` MiB in small pages (leaked).
fn ballast(mb: usize) {
    let len = mb << 20;
    // SAFETY: a fresh private anonymous mapping, written only through `p`.
    let p = unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
    if p == libc::MAP_FAILED {
        return;
    }
    unsafe { libc::madvise(p, len, libc::MADV_NOHUGEPAGE) };
    for off in (0..len).step_by(4096) {
        unsafe { *(p as *mut u8).add(off) = 1 };
    }
}

/// The client's connects while its server forks and execs `/bin/true` in a
/// loop: (admitted, refused, other verdicts, forks the server made).
fn exec_loop_scenario(connects: usize, tag: &str) -> Option<(usize, usize, Vec<String>, u64)> {
    let run = Run { dir: work_dir(tag) };
    let dir = run.dir.clone();
    let code = guarded(traps(), cfg(true), move || {
        let r = Run { dir };
        let stop = r.dir.join("stop");
        let rs = Run { dir: r.dir.clone() };
        let stop_s = stop.clone();
        let server = fork_run(move || {
            let Ok((fd, port)) = ephemeral_listener() else {
                rs.put("server-port", "errno");
                return 0;
            };
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            ballast(BALLAST_MB);
            let l = unsafe { TcpListener::from_raw_fd(fd) };
            l.set_nonblocking(true).unwrap();
            let prog = std::ffi::CString::new("/bin/true").unwrap();
            let argv = [prog.as_ptr(), std::ptr::null()];
            rs.put("server-port", &port.to_string());
            let mut forks: u64 = 0;
            while !stop.exists() {
                while let Ok((mut c, _)) = l.accept() {
                    let _ = c.write_all(b"server");
                }
                // Fork and exec at once: the child's exec is the first thing it does.
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    unsafe { libc::execv(prog.as_ptr(), argv.as_ptr()) };
                    unsafe { libc::_exit(127) };
                }
                if pid > 0 {
                    forks += 1;
                    let mut st = 0;
                    unsafe { libc::waitpid(pid, &mut st, 0) };
                }
            }
            rs.put("forks", &forks.to_string());
            0
        });
        let Some(port) = r.get("server-port").and_then(|p| p.parse::<u16>().ok()) else {
            let _ = std::fs::write(&stop_s, "");
            reap(server);
            return 10;
        };
        let mut verdicts = Vec::with_capacity(connects);
        for _ in 0..connects {
            verdicts.push(verdict(try_connect(port)));
        }
        r.put("verdicts", &verdicts.join(","));
        let _ = std::fs::write(&stop_s, "");
        reap(server);
        0
    })?;
    assert_eq!(code, Some(0), "the guarded tree exited cleanly");
    let verdicts = run.get("verdicts").unwrap_or_default();
    let forks = run.get("forks").and_then(|f| f.parse().ok()).unwrap_or(0);
    let all: Vec<String> = verdicts.split(',').map(str::to_string).collect();
    let ok = all.iter().filter(|v| *v == "ok:server").count();
    let refused = all.iter().filter(|v| *v == EACCES).count();
    let other = all.into_iter().filter(|v| v != "ok:server" && v != EACCES).collect();
    let _ = std::fs::remove_dir_all(&run.dir);
    Some((ok, refused, other, forks))
}

#[test]
#[ignore]
fn the_client_reaches_its_server_while_the_server_forks_and_execs_in_a_tight_loop() {
    let _g = serial();
    const CONNECTS: usize = 300;
    let Some((ok, refused, other, forks)) = exec_loop_scenario(CONNECTS, "exec-loop") else { return };
    eprintln!("exec loop: {ok} admitted, {refused} refused, {} other, of {CONNECTS} connects; {forks} fork-and-execs", other.len());
    assert!(forks > 0, "the server forked and exec'd while the client connected");
    assert_eq!(refused, 0, "(12) a connect whose first look landed inside the fork's exec was refused ({refused} of {CONNECTS})");
    assert!(other.is_empty(), "(12) other verdicts: {other:?}");
    assert_eq!(ok, CONNECTS);
}

/// The server forks a child that empties its own command line (so it looks
/// inside an exec for as long as it lives) and holds the listener 4 s, past
/// the guard's 2 s bound; `hidden`: it also makes itself non-dumpable and
/// holds a copy of the listener WITHOUT the close-on-exec flag, so a guard
/// that is not root in its user namespace cannot read its table, as inside
/// a real exec. The client connects once. (verdict, milliseconds), or None
/// when this kernel refuses `PR_SET_MM_MAP` (SKIP).
fn never_settles_scenario(hidden: bool, tag: &str) -> Option<(String, u64)> {
    let run = Run { dir: work_dir(tag) };
    let dir = run.dir.clone();
    let code = guarded(traps(), cfg(true), move || {
        let r = Run { dir };
        let stop = r.dir.join("stop");
        let rs = Run { dir: r.dir.clone() };
        let stop_s = stop.clone();
        let server = fork_run(move || {
            let Ok((fd, port)) = ephemeral_listener() else {
                rs.put("server-port", "errno");
                return 0;
            };
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            let rf = Run { dir: rs.dir.clone() };
            let _fork = fork_run(move || {
                let kept = if hidden { unsafe { libc::dup(fd) } } else { fd };
                let faked = empty_own_cmdline().is_some() && (!hidden || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0);
                rf.put("faked", if faked { "1" } else { "0" });
                // Holds the listener past the guard's 2 s bound.
                std::thread::sleep(Duration::from_secs(4));
                unsafe { libc::close(kept) };
                0
            });
            rs.put("server-port", &port.to_string());
            serve(fd, "server", stop_s);
            0
        });
        let port = r.get("server-port").and_then(|p| p.parse::<u16>().ok());
        // Connect once the fork has emptied its command line (or failed to).
        let _ = r.get("faked");
        let t0 = std::time::Instant::now();
        let v = match port {
            Some(p) => verdict(try_connect(p)),
            None => "no server".to_string(),
        };
        r.put("client-own", &v);
        r.put("elapsed-ms", &t0.elapsed().as_millis().to_string());
        let _ = std::fs::write(&stop, "");
        reap(server);
        0
    })?;
    assert_eq!(code, Some(0), "the guarded tree exited cleanly");
    let faked = run.get("faked");
    let out = (run.get("client-own").unwrap_or_default(), run.get("elapsed-ms").and_then(|m| m.parse().ok()).unwrap_or(0));
    let _ = std::fs::remove_dir_all(&run.dir);
    if faked.as_deref() != Some("1") {
        eprintln!("SKIP: PR_SET_MM_MAP could not empty a command line here");
        return None;
    }
    Some(out)
}

#[test]
#[ignore]
fn a_fork_that_looks_inside_an_exec_forever_still_refuses_the_client_at_the_bound() {
    let _g = serial();
    let Some((v, ms)) = never_settles_scenario(false, "never-settles") else { return };
    assert_eq!(v, EACCES, "(13) a holder that never settles is refused");
    assert!(ms >= 1900, "(13) refused at the bound (FORK_EXEC_WAIT, 2 s), not before: {ms} ms");
    assert!(ms < 3900, "(13) refused at the bound, not when the holder went: {ms} ms");
}

#[test]
#[ignore]
fn a_holder_inside_an_exec_whose_table_cannot_be_read_is_not_taken_for_none() {
    let _g = serial();
    let Some((v, ms)) = never_settles_scenario(true, "never-settles-hidden") else { return };
    // Before 2026-10-17 a guard that is not root in the tree's user namespace
    // read the hidden table as empty and admitted the connect at once.
    assert_eq!(v, EACCES, "(13) a hidden holder inside an exec is waited for, then refused ({ms} ms)");
    assert!(ms >= 1900, "(13) refused at the bound (FORK_EXEC_WAIT, 2 s), not before: {ms} ms");
    assert!(ms < 3900, "(13) refused at the bound, not when the holder went: {ms} ms");
}

// ── the agent is the server (supported-agents.md §2.3.1) ─────────────────────
//
// With a secret policy whose agent is this test binary, and the allowance on
// for the same executable, the client's own server is the agent of plan 13
// D2 / D7 too: (8) a process its child execs is a CALL ROOT (the shell of a
// tool call the server runs); a grandchild's exec is not; and (9) a server
// that reads a holder's output through a pipe is not made a holder (no
// `recordProcessFlow` for it). The allowance off: the server is an ordinary
// process (its child's exec is no call root, and the pipe makes it a holder).

/// What the recording arbiter was told: `(op, procKey, parentKey, callRoot)`.
type Told = Arc<Mutex<Vec<(String, String, String, bool)>>>;

fn recording_arbiter() -> (&'static mandu_arbiter::mock::MockArbiter, Told) {
    let told: Told = Arc::new(Mutex::new(Vec::new()));
    let t = told.clone();
    let m = mandu_arbiter::mock::MockArbiter::start(mandu_arbiter::mock::op_handler(move |op, req| {
        let s = |k: &str| req.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        match op {
            "decideSecretOpen" => Ok(serde_json::json!({ "verdict": "raw", "app": "test", "level": "no-model", "reason": "mock reader" })),
            "taintedProcessBindings" => Ok(serde_json::json!({ "tainted": true, "level": "no-model", "files": ["secret.env"], "bindings": [] })),
            "recordExecRoot" | "recordProcessFlow" => {
                let root = req.get("callRoot").and_then(|v| v.as_bool()).unwrap_or(false);
                t.lock().unwrap().push((op.to_string(), s("procKey"), s("parentKey"), root));
                Ok(serde_json::json!({ "ok": true }))
            }
            _ => Ok(serde_json::Value::Null),
        }
    }))
    .leak();
    (m, told)
}

fn secret_cfg(dir: &Path, arbiter: &mandu_arbiter::mock::MockArbiter, own_server: bool) -> (GuardConfig, PathBuf) {
    let secret = dir.join("secret.env");
    let twin = dir.join("twin.env");
    std::fs::write(&secret, "API_KEY=OWN-SERVER-CANARY\n").unwrap();
    std::fs::write(&twin, "API_KEY=$MDU:twin\n").unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(r#"{{"agentExe":"{}","ask":"never","session":"os","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, this_exe(), secret.display(), twin.display()),
    )
    .unwrap();
    let mut c = cfg(own_server);
    c.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(&policy).unwrap()));
    c.emitter = Some(Arc::new(Mutex::new(mandu_arbiter::ArbiterClient::new(&arbiter.socket_path))));
    (c, secret)
}

fn key_of(pid: i32) -> String {
    mandu_arbiter::proc::proc_key_for_pid(pid).unwrap_or_default()
}

/// client → server (fork) → { reader child: opens the secret raw, writes it
/// to a pipe the server reads; shell child: execs /bin/true, after its own
/// child execs /bin/true too }. Returns what the arbiter was told, the
/// server's key and the shell's.
fn identity_scenario(own_server: bool, tag: &str) -> Option<(Told, String, String)> {
    let dir = work_dir(tag);
    let (arb, told) = recording_arbiter();
    let (c, secret) = secret_cfg(&dir, arb, own_server);
    let d2 = dir.clone();
    let code = guarded(FilterTraps { open: true, secrets: true, own_server, ..Default::default() }, c, move || {
        let r = Run { dir: d2 };
        let rs = Run { dir: r.dir.clone() };
        let server = fork_run(move || {
            rs.put("server", &key_of(unsafe { libc::getpid() }));
            // The pipe a tool's output comes back on.
            let fds = {
                let (out_r, out_w) = pipe();
                [out_r, out_w]
            };
            let secret = secret.clone();
            let reader = fork_run(move || {
                unsafe { libc::close(fds[0]) };
                let got = std::fs::read(&secret).unwrap_or_default();
                unsafe { libc::write(fds[1], got.as_ptr() as *const libc::c_void, got.len()) };
                0
            });
            unsafe { libc::close(fds[1]) };
            let mut buf = [0u8; 256];
            while unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut libc::c_void, buf.len()) } > 0 {}
            reap(reader);
            // A tool call's shell: the server's child execs, and so does its own child.
            let rsh = Run { dir: rs.dir.clone() };
            let shell = fork_run(move || {
                rsh.put("shell", &key_of(unsafe { libc::getpid() }));
                let inner = fork_run(|| {
                    let p = std::ffi::CString::new("/bin/true").unwrap();
                    unsafe { libc::execl(p.as_ptr(), p.as_ptr(), std::ptr::null::<libc::c_char>()) };
                    7
                });
                reap(inner);
                let p = std::ffi::CString::new("/bin/true").unwrap();
                unsafe { libc::execl(p.as_ptr(), p.as_ptr(), std::ptr::null::<libc::c_char>()) };
                7
            });
            reap(shell);
            0
        });
        reap(server);
        0
    })?;
    assert_eq!(code, Some(0));
    let r = Run { dir: dir.clone() };
    let (server, shell) = (r.get("server").unwrap(), r.get("shell").unwrap());
    // The reports are best-effort and asynchronous: give them a moment.
    std::thread::sleep(Duration::from_millis(300));
    let _ = std::fs::remove_dir_all(&dir);
    Some((told, server, shell))
}

#[test]
#[ignore]
fn the_server_is_the_agent_its_childs_exec_is_a_call_root_and_a_pipe_does_not_make_it_a_holder() {
    let _g = serial();
    let Some((told, server, shell)) = identity_scenario(true, "agent-on") else { return };
    let told = told.lock().unwrap().clone();
    assert!(
        told.iter().any(|(op, k, p, root)| op == "recordExecRoot" && *root && *k == shell && *p == server),
        "the server's child's exec is a call root: {told:?}"
    );
    assert!(!told.iter().any(|(op, _, p, root)| op == "recordExecRoot" && *root && *p == shell), "a grandchild's exec is not: {told:?}");
    assert!(!told.iter().any(|(op, k, _, _)| op == "recordProcessFlow" && *k == server), "the server is never made a holder by a pipe: {told:?}");
}

#[test]
#[ignore]
fn without_the_allowance_the_server_is_an_ordinary_process() {
    let _g = serial();
    let Some((told, server, shell)) = identity_scenario(false, "agent-off") else { return };
    let told = told.lock().unwrap().clone();
    assert!(!told.iter().any(|(op, k, _, root)| op == "recordExecRoot" && *root && *k == shell), "no call root under the server: {told:?}");
    assert!(told.iter().any(|(op, k, _, _)| op == "recordProcessFlow" && *k == server), "the pipe made the server a holder: {told:?}");
}
