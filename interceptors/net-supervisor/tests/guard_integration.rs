//! Privileged integration test for the seccomp-unotify connect(2) guard.
//!
//! `#[ignore]`d so the default (unprivileged) `cargo test` skips it. Run with the
//! kernel feature, as root OR — the recommended, no-host-state path — as
//! root-in-an-unprivileged-user-namespace:
//!
//!   cargo build -p net-supervisor --features kernel
//!   unshare --user --map-root-user --mount --net --pid --fork -- \
//!     bash -c 'cd interceptors && cargo test -p net-supervisor --features kernel \
//!                -- --ignored --nocapture'
//!
//! Requirements: only `no_new_privs` for seccomp NEW_LISTENER (NOT CAP_SYS_ADMIN
//! or a userns — the ALLOW/DENY/PASSTHROUGH/NONBLOCKING legs pass as a plain uid),
//! kernel ≥ 5.0 for USER_NOTIF and ≥ 5.6 for the supervisor-connect enactment
//! (pidfd_getfd). The netns-discriminator leg additionally needs a userns to
//! CREATE a fresh netns (CLONE_NEWNET) and self-SKIPs where that is unavailable —
//! which is why the recommended runner still uses `unshare --user`. Where
//! NEW_LISTENER is denied the seccomp tests self-SKIP (print "SKIP:", exit 0).
//!
//! ── What this proves ─────────────────────────────────────────────────────────
//!  • ALLOW: a tracee's `connect` to an allow-listed loopback destination is
//!    supervisor-connected and returns success — the tracee reaches the peer.
//!  • DENY: a `connect` to an unlisted destination returns `-EACCES` — the
//!    IP/port-precise deny the port-only Landlock layer cannot express.
//!  • AF_UNIX PASSTHROUGH: a `connect` to a unix socket is NOT blocked — the
//!    arbiter's own IPC keeps working under the guard.
//!  • NONBLOCKING: a nonblocking `connect` is replicated (EINPROGRESS handed back;
//!    the tracee completes on its own fd).
//!  • DIFFERENT-NETNS discriminator: a child in a fresh netns is recognized as
//!    NOT sharing our netns (→ the guard CONTINUEs, deferring to its own boundary).
//!  • WSL INTEROP: with the WSL config pinned, a connect to the interop socket
//!    (or a symlink to it) and any AF_VSOCK connect are refused with EACCES;
//!    without it both pass through (the differential). Pathname Unix connects
//!    are supervised there: the guard checks the inode it opened in the
//!    tracee's view and connects exactly that inode, so a hardlink, a
//!    /proc/self/fd/N spelling and a symlink swapped mid-check (a tight race
//!    loop) all miss the door, while benign sockets still connect.
//!
//! The PURE decision + sockaddr decode are covered by `src/guard.rs` unit tests on
//! the unprivileged host; this file proves the kernel glue where privileges exist.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, pipe, reap_within, readable_within, run_tag, socketpair, wait_limit, StopOnDrop};

use std::net::TcpListener;
use std::os::unix::io::RawFd;
use std::sync::Arc;

use net_supervisor::guard::{parse_rule, GuardPolicy, NoResolver, WslGuard};
use net_supervisor::guard_kernel::{
    handle_connect_notif, install_connect_filter_self, recv_notif, tracee_shares_our_netns,
    GuardConfig, GuardOutcome,
};
use net_supervisor::HostResolver;

// Child exit codes distinguishing what the tracee observed from its own connect().
const EXIT_CONNECTED: i32 = 0; // connect() returned 0
const EXIT_NO_SECCOMP: i32 = 91; // NEW_LISTENER denied → parent SKIPs
const EXIT_SETUP_FAIL: i32 = 92;
const EXIT_UNEXPECTED: i32 = 93;

fn no_resolver() -> Arc<dyn HostResolver + Send + Sync> {
    Arc::new(NoResolver)
}

fn cfg(rule: &str) -> GuardConfig {
    GuardConfig::new(Arc::new(GuardPolicy::new(vec![parse_rule(rule).unwrap()])), no_resolver())
}

/// Bind a loopback TCP listener on an ephemeral port; return (listener, port).
/// A fresh network namespace (the recommended `unshare --net` runner) starts with
/// `lo` DOWN, so bring it up first or the loopback connect has no route.
fn loopback_listener() -> (TcpListener, u16) {
    ensure_loopback_up();
    let l = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// Bring `lo` up (best-effort). Idempotent; harmless where it is already up.
fn ensure_loopback_up() {
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status();
}

/// A routing errno that means "this env has no working loopback" (rather than a
/// guard bug) — used to SKIP the connect legs cleanly on such a host.
fn is_no_route(errno: i32) -> bool {
    errno == libc::ENETUNREACH || errno == libc::EHOSTUNREACH || errno == libc::EADDRNOTAVAIL
}

/// Make `/proc` reflect THIS pid namespace so `/proc/<pid>/ns/net` resolves the
/// tracee (the `--pid --fork` runner leaves the host `/proc` mounted otherwise).
/// Best-effort; needs CAP_SYS_ADMIN-in-userns (held under the recommended runner).
fn ensure_proc_matches_pidns() {
    let src = b"proc\0";
    let target = b"/proc\0";
    let fstype = b"proc\0";
    let _ = unsafe {
        libc::mount(
            src.as_ptr() as *const libc::c_char,
            target.as_ptr() as *const libc::c_char,
            fstype.as_ptr() as *const libc::c_char,
            0,
            std::ptr::null(),
        )
    };
}

#[test]
#[ignore]
fn guard_allows_connect_to_allowed_loopback() {
    let (listener, port) = loopback_listener();
    // Allow exactly the loopback range on this port.
    let cfg = cfg(&format!("tcp:127.0.0.0/8:{port}"));

    let outcome = drive_one_connect(ConnectRecipe::Tcp { port, nonblocking: false }, &cfg);
    let Some((outcome, child_exit)) = outcome else { return /* SKIP */ };

    match outcome {
        GuardOutcome::AllowedSupervised { port: p, answered, .. } => {
            assert_eq!(p, port);
            if is_no_route(answered) {
                eprintln!("SKIP: no working loopback in this env (answered errno {answered})");
                return;
            }
            assert_eq!(answered, 0, "loopback connect should succeed immediately");
        }
        other => panic!("expected AllowedSupervised, got {other:?}"),
    }
    assert_eq!(child_exit, Some(EXIT_CONNECTED), "tracee's connect() returned 0");
    // The supervisor-connect actually reached the listener.
    listener.set_nonblocking(true).unwrap();
    assert!(listener.accept().is_ok(), "the guarded connect reached the listener");
    eprintln!("ALLOW PASS: guarded connect to 127.0.0.1:{port} supervisor-connected + accepted");
}

#[test]
#[ignore]
fn guard_supervises_an_allowed_connect_from_a_worker_thread() {
    // pidfd_open takes only a thread-group leader (before Linux 6.9); the
    // notification names the calling thread. Since the socket copy is
    // mandatory (finding 8), a copy through the thread's pid failed and every
    // worker-thread connect was refused: Claude Code's DNS never resolved.
    let (listener, port) = loopback_listener();
    let cfg = cfg(&format!("tcp:127.0.0.0/8:{port}"));
    let Some((outcome, child_exit)) = drive_one_connect(ConnectRecipe::TcpFromThread { port }, &cfg) else { return };
    match outcome {
        GuardOutcome::AllowedSupervised { answered, .. } => {
            if is_no_route(answered) {
                eprintln!("SKIP: no working loopback in this env");
                return;
            }
            assert_eq!(answered, 0, "the worker thread's connect is supervisor-connected");
        }
        other => panic!("expected AllowedSupervised, got {other:?}"),
    }
    assert_eq!(child_exit, Some(EXIT_CONNECTED));
    listener.set_nonblocking(true).unwrap();
    assert!(listener.accept().is_ok(), "the guarded connect reached the listener");
}

#[test]
#[ignore]
fn guard_denies_connect_to_unlisted_destination() {
    let (_listener, port) = loopback_listener();
    // Allow a DIFFERENT port only → the tracee's connect to `port` is denied.
    let cfg = cfg(&format!("tcp:127.0.0.0/8:{}", port.wrapping_add(1).max(1)));

    let outcome = drive_one_connect(ConnectRecipe::Tcp { port, nonblocking: false }, &cfg);
    let Some((outcome, child_exit)) = outcome else { return /* SKIP */ };

    match outcome {
        GuardOutcome::Denied { port: p, .. } => assert_eq!(p, port),
        other => panic!("expected Denied, got {other:?}"),
    }
    assert_eq!(
        child_exit,
        Some(libc::EACCES),
        "tracee's connect() returned -EACCES (the IP/port-precise deny)"
    );
    eprintln!("DENY PASS: unlisted connect to 127.0.0.1:{port} → EACCES in the tracee");
}

#[test]
#[ignore]
fn guard_denies_metadata_endpoint_despite_an_any_host_rule() {
    // `tcp:*:80` would admit every host on :80; the always-denied check runs
    // first, so the cloud metadata endpoint is still refused in the tracee.
    let cfg = cfg("tcp:*:80");
    let recipe = ConnectRecipe::TcpTo { ip: std::net::Ipv4Addr::new(169, 254, 169, 254), port: 80 };
    let Some((outcome, child_exit)) = drive_one_connect(recipe, &cfg) else { return /* SKIP */ };
    match outcome {
        GuardOutcome::Denied { ip, port } => {
            assert_eq!(ip.to_string(), "169.254.169.254");
            assert_eq!(port, 80);
        }
        other => panic!("expected Denied, got {other:?}"),
    }
    assert_eq!(child_exit, Some(libc::EACCES), "the metadata connect returned -EACCES");
    eprintln!("METADATA PASS: 169.254.169.254:80 denied under tcp:*:80");
}

#[test]
#[ignore]
fn guard_passes_through_unix_socket() {
    // The critical invariant: an AF_UNIX connect (the arbiter's IPC family) is NOT
    // blocked by the guard even under a default-DENY INET policy.
    use std::os::unix::net::UnixListener;
    let sock_path = format!("{}/mandu-net-guard-it-{}.sock", std::env::temp_dir().display(), run_tag());
    let _ = std::fs::remove_file(&sock_path);
    let ul = UnixListener::bind(&sock_path).expect("bind unix socket");

    // A policy that allows NOTHING on INET — proving the passthrough is by family,
    // not by an allow rule.
    let cfg = GuardConfig::new(Arc::new(GuardPolicy::default()), no_resolver());

    let outcome = drive_one_connect(ConnectRecipe::Unix { path: sock_path.clone() }, &cfg);
    let cleanup = || {
        let _ = std::fs::remove_file(&sock_path);
    };
    let Some((outcome, child_exit)) = outcome else {
        cleanup();
        return; // SKIP
    };

    assert!(
        matches!(outcome, GuardOutcome::PassedThrough { .. }),
        "AF_UNIX connect must pass through, got {outcome:?}"
    );
    assert_eq!(child_exit, Some(EXIT_CONNECTED), "the unix connect succeeded");
    ul.set_nonblocking(true).unwrap();
    assert!(ul.accept().is_ok(), "the passed-through unix connect reached the listener");
    cleanup();
    eprintln!("PASSTHROUGH PASS: AF_UNIX connect survived a default-DENY INET policy");
}

#[test]
#[ignore]
fn guard_nonblocking_connect_replicated() {
    let (listener, port) = loopback_listener();
    let cfg = cfg(&format!("tcp:127.0.0.0/8:{port}"));

    let outcome = drive_one_connect(ConnectRecipe::Tcp { port, nonblocking: true }, &cfg);
    let Some((outcome, child_exit)) = outcome else { return /* SKIP */ };

    match outcome {
        GuardOutcome::AllowedSupervised { answered, .. } => {
            if is_no_route(answered) {
                eprintln!("SKIP: no working loopback in this env (answered errno {answered})");
                return;
            }
            // Loopback may connect immediately (0) or report EINPROGRESS; both are
            // valid replications of a nonblocking connect the tracee then completes.
            assert!(
                answered == 0 || answered == libc::EINPROGRESS,
                "nonblocking connect answered {answered}, want 0 or EINPROGRESS"
            );
        }
        other => panic!("expected AllowedSupervised, got {other:?}"),
    }
    assert_eq!(child_exit, Some(EXIT_CONNECTED), "the tracee completed the nonblocking connect");
    listener.set_nonblocking(true).unwrap();
    assert!(listener.accept().is_ok());
    eprintln!("NONBLOCKING PASS: nonblocking connect replicated + completed by the tracee");
}

#[test]
#[ignore]
fn guard_different_netns_discriminator() {
    // No seccomp needed — just prove the netns discriminator the guard relies on:
    // a child that unshares CLONE_NEWNET is seen as NOT sharing our netns (so the
    // guard CONTINUEs, deferring to the box's own boundary). Requires userns.
    // Make /proc reflect our pidns so /proc/<child>/ns/net resolves the child.
    ensure_proc_matches_pidns();
    let (rd, wr) = pipe();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", last_err());
    if pid == 0 {
        unsafe { libc::close(rd) };
        // Try to enter a new network namespace.
        let rc = unsafe { libc::unshare(libc::CLONE_NEWNET) };
        // Signal readiness (byte value = whether unshare succeeded), then block so
        // /proc/<pid>/ns/net is stable while the parent stats it.
        let ok: u8 = if rc == 0 { 1 } else { 0 };
        unsafe { libc::write(wr, &ok as *const u8 as *const libc::c_void, 1) };
        // Park until the parent kills us.
        loop {
            unsafe { libc::pause() };
        }
    }
    unsafe { libc::close(wr) };
    let mut ready: u8 = 0;
    let n = unsafe { libc::read(rd, &mut ready as *mut u8 as *mut libc::c_void, 1) };
    unsafe { libc::close(rd) };
    if n != 1 || ready == 0 {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        eprintln!("SKIP: CLONE_NEWNET unavailable (need an unprivileged userns)");
        return;
    }
    // Precondition: /proc must resolve the child (a bogus /proc/<pid> would make
    // the discriminator default to "same" and mask the real check). SKIP if not.
    let proc_ok = std::path::Path::new(&format!("/proc/{pid}/ns/net")).exists();
    let shares = tracee_shares_our_netns(pid);
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    if !proc_ok {
        eprintln!("SKIP: /proc/<pid>/ns/net not resolvable (could not remount /proc for this pidns)");
        return;
    }
    assert!(!shares, "a CLONE_NEWNET child must NOT share our netns (guard → CONTINUE)");
    // Sanity: we share our OWN netns.
    assert!(tracee_shares_our_netns(unsafe { libc::getpid() }));
    eprintln!("NETNS PASS: fresh-netns child discriminated; self shares self");
}

#[test]
#[ignore]
fn guard_judges_the_socket_netns_not_the_process() {
    // The guard keys "a nested sandbox, its own boundary" on the SOCKET's
    // network namespace (exec-routing.md §4.2: the command box's supervisor
    // connects box sockets on the box's behalf from the agent's namespace).
    let (listener, port) = loopback_listener();
    listener.set_nonblocking(true).unwrap();
    // Nothing allows 127.0.0.1:port: an enforced connect there is DENIED.
    let cfg = cfg("tcp:10.9.9.9/32:9");

    // A process that moved to a fresh netns but holds a socket of OURS is
    // judged like anyone else (the process-netns check CONTINUEd it, and it
    // reached the listener).
    // drive_one_connect SKIPs (None) where the tracee cannot split its
    // namespaces: its unshare(CLONE_NEWNET) needs an unprivileged userns.
    let Some((outcome, exit)) = drive_one_connect(ConnectRecipe::TcpSplitNetns { port, socket_elsewhere: false }, &cfg) else { return };
    assert_eq!(outcome, GuardOutcome::Denied { ip: "127.0.0.1".parse().unwrap(), port }, "a socket of our namespace is judged");
    assert_eq!(exit, Some(libc::EACCES));
    assert!(listener.accept().is_err(), "nothing reached the listener");

    // A process in OUR netns holding a socket of another namespace: that
    // namespace is the boundary, and the guard connects its own copy of the
    // socket there (fresh netns, loopback down: ENETUNREACH), never ours.
    let Some((outcome, exit)) = drive_one_connect(ConnectRecipe::TcpSplitNetns { port, socket_elsewhere: true }, &cfg) else { return };
    assert_eq!(outcome, GuardOutcome::DifferentNetns);
    assert_eq!(exit, Some(libc::ENETUNREACH), "connected in the socket's own namespace");
    assert!(listener.accept().is_err(), "nothing reached the listener");
    eprintln!("SOCKET-NETNS PASS: judged by the socket's namespace, both ways");
}

/// exec-routing.md §4.2: the kernel allows one seccomp listener per filter
/// chain, so under the whole-agent guard the command box cannot have its own,
/// and the guard serves the box's socket allow-list. A boxed process (in its
/// own network namespace, below the box binary; here, below this test binary)
/// reaches the Unix sockets it bound itself, by path and abstract, and is
/// refused a host socket, which never sees the connection. The control (the
/// guard not serving boxes) reaches the host socket.
#[test]
#[ignore]
fn guard_serves_the_command_box_socket_allowlist() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = std::env::temp_dir().join(format!("mandu-guard-box-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let host = dir.join("host.sock");
    let reached = Arc::new(AtomicUsize::new(0));
    {
        let l = std::os::unix::net::UnixListener::bind(&host).unwrap();
        let n = reached.clone();
        std::thread::spawn(move || {
            for c in l.incoming() {
                if c.is_err() {
                    return;
                }
                n.fetch_add(1, Ordering::SeqCst);
            }
        });
    }
    let me = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned();

    // Child exit bits: 1 own path connected, 2 host refused ECONNREFUSED,
    // 4 host connected, 8 own abstract connected; 64 = no netns here (SKIP).
    let leg = |served: bool, tag: &str| -> Option<i32> {
        let own = dir.join(format!("own-{tag}.sock"));
        let (sup_sock, child_sock) = socketpair(libc::SOCK_STREAM);
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::close(sup_sock) };
            // Not std::env::set_var: a forked child of a multithreaded test
            // process may inherit its environment lock held.
            let traps = net_supervisor::guard_kernel::FilterTraps { box_sockets: true, ..Default::default() };
            let listener = match net_supervisor::guard_kernel::install_guard_filter_self(traps) {
                Ok(fd) => fd,
                Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
            };
            if send_fd(child_sock, listener).is_err() {
                unsafe {
                    libc::close(listener);
                    libc::_exit(EXIT_SETUP_FAIL)
                };
            }
            unsafe { libc::close(listener) };
            // Look like a box: a network namespace of its own.
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                unsafe { libc::_exit(64) };
            }
            let mut bits = 0;
            let srv = std::os::unix::net::UnixListener::bind(&own).expect("bind own");
            if std::os::unix::net::UnixStream::connect(&own).is_ok() {
                bits |= 1;
            }
            match std::os::unix::net::UnixStream::connect(&host) {
                Ok(_) => bits |= 4,
                Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => bits |= 2,
                Err(_) => {}
            }
            let name = format!("mandu-guard-box-{}-{}", run_tag(), unsafe { libc::getpid() });
            let abs = child_abstract_roundtrip(&name);
            if abs {
                bits |= 8;
            }
            drop(srv);
            unsafe { libc::_exit(bits) };
        }
        unsafe { libc::close(child_sock) };
        let listener = match recv_fd_from(sup_sock, child) {
            Ok(fd) => fd,
            Err(_) => {
                let code = reap(child);
                assert_eq!(code, Some(EXIT_NO_SECCOMP), "tracee failed to send its listener");
                return None;
            }
        };
        let mut cfg = cfg("tcp:10.9.9.9/32:9");
        cfg.box_ancestor = me.clone();
        if served {
            cfg.box_sockets = Some(Arc::new(fs_supervisor::box_sockets::BoxSockets::new()));
        }
        let server = std::thread::spawn(move || {
            let _ = net_supervisor::guard_kernel::run_guard_supervisor(listener, cfg);
            unsafe { libc::close(listener) };
        });
        let code = reap(child);
        let _ = join_within(server, wait_limit(), "the guard supervisor (run_guard_supervisor), after its tracee exited");
        unsafe { libc::close(sup_sock) };
        code
    };

    let Some(served) = leg(true, "served") else {
        eprintln!("SKIP: seccomp NEW_LISTENER denied here");
        return;
    };
    if served == 64 {
        eprintln!("SKIP: no unprivileged network namespace here");
        return;
    }
    let reached_served = reached.swap(0, Ordering::SeqCst);
    let control = leg(false, "control").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    let reached_control = reached.load(Ordering::SeqCst);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(served, 1 | 2 | 8, "served: own path + abstract connect, the host socket refused (bits {served:#b})");
    assert_eq!(reached_served, 0, "the host socket saw nothing from the box");
    assert_eq!(control, 1 | 4 | 8, "control: the host socket is reachable (bits {control:#b})");
    assert!(reached_control > 0);
    eprintln!("BOX SOCKETS PASS: the guard serves the box's allow-list; control reaches the host");
}

/// Child: bind + listen on an abstract name and connect to it.
fn child_abstract_roundtrip(name: &str) -> bool {
    unsafe {
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, b) in name.bytes().enumerate() {
            addr.sun_path[i + 1] = b as libc::c_char;
        }
        let len = (2 + 1 + name.len()) as libc::socklen_t;
        let srv = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if libc::bind(srv, &addr as *const _ as *const libc::sockaddr, len) != 0 || libc::listen(srv, 4) != 0 {
            return false;
        }
        let c = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let ok = libc::connect(c, &addr as *const _ as *const libc::sockaddr, len) == 0;
        libc::close(c);
        libc::close(srv);
        ok
    }
}

// ── plan 10 §4.1a: the guard performs every open that can read ───────────────

/// A temporary tree with a registered secret, its twin and a decoy of the
/// same name length, plus the guard's secret policy file naming them.
struct OpenTree {
    dir: std::path::PathBuf,
    secret: std::path::PathBuf,
    decoy: std::path::PathBuf,
    policy: std::path::PathBuf,
}

impl OpenTree {
    fn new(tag: &str) -> OpenTree {
        let dir = std::env::temp_dir().join(format!("mandu-open-{tag}-{}", run_tag()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("secret.txt");
        let decoy = dir.join("decoy0.txt");
        let twin = dir.join("twin.txt");
        std::fs::write(&secret, "REAL-SECRET-BYTES\n").unwrap();
        std::fs::write(&decoy, "DECOY-BYTES\n").unwrap();
        std::fs::write(&twin, "TWIN-PLACEHOLDER\n").unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(
            &policy,
            format!(r#"{{"agentExe":"","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, secret.display(), twin.display()),
        )
        .unwrap();
        OpenTree { dir, secret, decoy, policy }
    }
}

impl Drop for OpenTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Fork a child that installs the guard's filter with the secret policy
/// (every open family trapped) and runs `body`; serve it with the real
/// supervisor loop until the tree is gone. `Some(the child's exit code, None
/// if it died by a signal)`, or None to SKIP (no seccomp listener here).
fn run_guarded(tree: &OpenTree, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    run_guarded_cfg(tree, |_| {}, body)
}

/// `run_guarded` with the guard's config adjusted by `tweak` first.
fn run_guarded_cfg(tree: &OpenTree, tweak: impl FnOnce(&mut GuardConfig), body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    run_guarded_setup(tree, tweak, || None, body)
}

/// `run_guarded_cfg` with `setup` run in the child BEFORE the filter goes
/// on (a namespace, a mount); `Some(code)` from it exits the child with that
/// code instead.
fn run_guarded_setup(tree: &OpenTree, tweak: impl FnOnce(&mut GuardConfig), setup: impl FnOnce() -> Option<i32>, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    let traps = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, ..Default::default() };
    run_guarded_traps(tree, traps, tweak, setup, body)
}

/// `run_guarded_setup` with the filter's traps given.
fn run_guarded_traps(
    tree: &OpenTree,
    traps: net_supervisor::guard_kernel::FilterTraps,
    tweak: impl FnOnce(&mut GuardConfig),
    setup: impl FnOnce() -> Option<i32>,
    body: impl FnOnce() -> i32,
) -> Option<Option<i32>> {
    let (sup_sock, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        close_inherited(&[child_sock]);
        if let Some(code) = setup() {
            unsafe { libc::_exit(code) };
        }
        // Not std::env::set_var: a forked child of a multithreaded test
        // process may inherit its environment lock held.
        let listener = match net_supervisor::guard_kernel::install_guard_filter_self(traps) {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if send_fd(child_sock, listener).is_err() {
            unsafe {
                libc::close(listener);
                libc::_exit(EXIT_SETUP_FAIL)
            };
        }
        unsafe { libc::close(listener) };
        let code = body();
        unsafe { libc::_exit(code) };
    }
    unsafe { libc::close(child_sock) };
    let listener = match recv_fd_from(sup_sock, child) {
        Ok(fd) => fd,
        Err(_) => {
            assert_eq!(reap(child), Some(EXIT_NO_SECCOMP), "tracee failed to send its listener");
            return None;
        }
    };
    let mut cfg = cfg("tcp:10.9.9.9/32:9");
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(&tree.policy).unwrap()));
    tweak(&mut cfg);
    let server = std::thread::spawn(move || {
        let _ = net_supervisor::guard_kernel::run_guard_supervisor(listener, cfg);
        unsafe { libc::close(listener) };
    });
    let reaped = reap_within(child, wait_limit(), "waiting for the guarded tracee (run_guarded_traps)");
    let t0 = std::time::Instant::now();
    let _ = join_within(server, wait_limit(), "the guard supervisor (run_guard_supervisor), after its tracee exited");
    if reaped.waited >= std::time::Duration::from_secs(10) {
        let test = std::thread::current().name().unwrap_or("?").to_string();
        eprintln!("SLOW GUARDED RUN ({test}): tracee {}; supervisor ended {:.1}s after", reaped.timing(), t0.elapsed().as_secs_f64());
    }
    unsafe { libc::close(sup_sock) };
    Some(reaped.code())
}

/// Child: read up to 64 bytes of what `path` (a NUL-terminated buffer the
/// caller may be rewriting) opens.
fn child_read_at(buf: *const u8) -> Result<String, i32> {
    unsafe {
        let fd = libc::open(buf as *const libc::c_char, libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        let mut b = [0u8; 64];
        let n = libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, b.len());
        libc::close(fd);
        Ok(String::from_utf8_lossy(&b[..n.max(0) as usize]).into_owned())
    }
}

/// Child: tally what 3000 opens returned; exit 1 if any read the real bytes,
/// 2 if none reached the secret's path (the race did not happen), 3 if none
/// reached the decoy.
fn tally_opens(open_one: impl Fn() -> Result<String, i32>, report: &std::path::Path) -> i32 {
    let (mut real, mut twin, mut decoy, mut other) = (0, 0, 0, 0);
    for _ in 0..3000 {
        match open_one() {
            Ok(s) if s.contains("REAL-SECRET") => real += 1,
            Ok(s) if s.contains("TWIN-PLACEHOLDER") => twin += 1,
            Ok(s) if s.contains("DECOY") => decoy += 1,
            _ => other += 1,
        }
    }
    let _ = std::fs::write(report, format!("real={real} twin={twin} decoy={decoy} other={other}"));
    if real > 0 {
        1
    } else if twin == 0 {
        2
    } else if decoy == 0 {
        3
    } else {
        0
    }
}

#[test]
#[ignore]
fn a_path_rewritten_mid_open_never_reads_the_secret() {
    // The CONTINUE race by memory: the kernel would re-read the path buffer
    // after the guard read it, and another thread rewrites it from the decoy
    // to the secret. The guard opens the path it read, once.
    let tree = OpenTree::new("memrace");
    let report = tree.dir.join("report.txt");
    let (secret, decoy) = (tree.secret.clone(), tree.decoy.clone());
    let code = run_guarded(&tree, || {
        static mut BUF: [u8; 512] = [0; 512];
        let a = decoy.as_os_str().as_encoded_bytes().to_vec();
        let b = secret.as_os_str().as_encoded_bytes().to_vec();
        assert_eq!(a.len(), b.len());
        let buf = unsafe { std::ptr::addr_of_mut!(BUF) as *mut u8 };
        unsafe { std::ptr::copy_nonoverlapping(a.as_ptr(), buf, a.len()) };
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flipper = {
            let stop = stop.clone();
            let addr = buf as usize;
            std::thread::spawn(move || {
                let p = addr as *mut u8;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    for src in [&a, &b] {
                        for (i, c) in src.iter().enumerate() {
                            unsafe { std::ptr::write_volatile(p.add(i), *c) };
                        }
                    }
                }
            })
        };
        let code = tally_opens(|| child_read_at(buf), &report);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = flipper.join();
        code
    });
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("MEMORY RACE: {seen}");
    assert_eq!(code, Some(0), "exit {code:?}: {seen}");
    eprintln!("MEMORY RACE PASS: 3000 opens of a rewritten path, the real bytes never read");
}

#[test]
#[ignore]
fn a_symlink_swapped_mid_open_never_reads_the_secret() {
    // The CONTINUE race by the filesystem: a link flipped between the decoy
    // and the secret. The guard opens once and judges the file it opened.
    let tree = OpenTree::new("linkrace");
    let report = tree.dir.join("report.txt");
    let (secret, decoy, dir) = (tree.secret.clone(), tree.decoy.clone(), tree.dir.clone());
    let code = run_guarded(&tree, || {
        let link = dir.join("link");
        let tmp = dir.join("link.new");
        std::os::unix::fs::symlink(&decoy, &link).unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flipper = {
            let stop = stop.clone();
            let (link, tmp) = (link.clone(), tmp.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    for target in [&secret, &decoy] {
                        let _ = std::fs::remove_file(&tmp);
                        if std::os::unix::fs::symlink(target, &tmp).is_ok() {
                            let _ = std::fs::rename(&tmp, &link);
                        }
                    }
                }
            })
        };
        let c = std::ffi::CString::new(link.as_os_str().as_encoded_bytes()).unwrap();
        let code = tally_opens(|| child_read_at(c.as_ptr() as *const u8), &report);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = flipper.join();
        code
    });
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("SYMLINK RACE: {seen}");
    assert_eq!(code, Some(0), "exit {code:?}: {seen}");
    eprintln!("SYMLINK RACE PASS: 3000 opens through a flipping link, the real bytes never read");
}

#[test]
#[ignore]
fn an_open_the_guard_performs_behaves_like_the_tracees_own() {
    use std::io::{Read, Write};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let tree = OpenTree::new("semantics");
    let report = tree.dir.join("report.txt");
    let (secret, decoy, dir) = (tree.secret.clone(), tree.decoy.clone(), tree.dir.clone());
    std::fs::hard_link(&secret, dir.join("hard")).unwrap();
    let code = run_guarded(&tree, || {
        let mut log = String::new();
        let mut failed = 0;
        let mut check = |name: &str, ok: bool, detail: String| {
            log.push_str(&format!("{} {name}: {detail}\n", if ok { "ok" } else { "FAIL" }));
            if !ok {
                failed += 1;
            }
        };
        let read = |p: &std::path::Path| std::fs::read_to_string(p).map_err(|e| e.raw_os_error().unwrap_or(0));
        let me = unsafe { libc::getpid() };
        // procfs: the tracee's own entries, never the guard's.
        let status = read(std::path::Path::new("/proc/self/status")).unwrap_or_default();
        check("/proc/self/status is mine", status.contains(&format!("\nPid:\t{me}\n")), status.lines().find(|l| l.starts_with("Pid:")).unwrap_or("").into());
        let stat = read(std::path::Path::new("/proc/self/stat")).unwrap_or_default();
        check("/proc/self/stat is mine", stat.starts_with(&format!("{me} ")), stat.chars().take(20).collect());
        check("/proc/mounts", read(std::path::Path::new("/proc/mounts")).map(|m| !m.is_empty()).unwrap_or(false), String::new());
        if std::fs::read_link("/etc/mtab").map(|t| t.to_string_lossy().contains("self")).unwrap_or(false) {
            check("/etc/mtab through its link into self", read(std::path::Path::new("/etc/mtab")).map(|m| !m.is_empty()).unwrap_or(false), String::new());
        }
        // A symlink into /proc/self: resolved as the TRACEE's `self` (a
        // walk from the guard would name the guard, here the test process).
        let statlink = dir.join("statlink");
        std::os::unix::fs::symlink("/proc/self/stat", &statlink).unwrap();
        let via = read(&statlink).unwrap_or_default();
        check("a symlink to /proc/self/stat is mine", via.starts_with(&format!("{me} ")), via.chars().take(20).collect());
        let envlink = dir.join("envlink");
        std::os::unix::fs::symlink("/proc/self/environ", &envlink).unwrap();
        check("a symlink to /proc/self/environ opens", std::fs::read(&envlink).is_ok(), String::new());
        // Descriptors through procfs, and stdin.
        let mut fds = [0i32; 2];
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        unsafe { libc::write(fds[1], b"PIPE-DATA".as_ptr() as *const libc::c_void, 9) };
        unsafe { libc::close(fds[1]) };
        let via = read(std::path::Path::new(&format!("/proc/self/fd/{}", fds[0])));
        check("/proc/self/fd/N of a pipe", via == Ok("PIPE-DATA".into()), format!("{via:?}"));
        let mut p2 = [0i32; 2];
        unsafe { libc::pipe2(p2.as_mut_ptr(), libc::O_CLOEXEC) };
        unsafe { libc::write(p2[1], b"STDIN-DATA".as_ptr() as *const libc::c_void, 10) };
        unsafe { libc::close(p2[1]) };
        unsafe { libc::dup2(p2[0], 0) };
        let via = read(std::path::Path::new("/dev/stdin"));
        check("/dev/stdin", via == Ok("STDIN-DATA".into()), format!("{via:?}"));
        // Creation, as the tracee's umask says.
        unsafe { libc::umask(0o027) };
        let made = dir.join("made.txt");
        let f = std::fs::OpenOptions::new().read(true).write(true).create(true).mode(0o666).open(&made);
        let mode = std::fs::metadata(&made).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
        check("O_RDWR|O_CREAT under umask 027", f.is_ok() && mode == 0o640, format!("mode {mode:o}"));
        unsafe { libc::umask(0o022) };
        if let Ok(mut f) = f {
            let _ = f.write_all(b"RW");
            let mut back = String::new();
            let _ = std::fs::File::open(&made).and_then(|mut g| g.read_to_string(&mut back));
            check("O_RDWR writes", back == "RW", back);
        }
        let cdir = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
        let tmpfile = unsafe { libc::open(cdir.as_ptr(), libc::O_TMPFILE | libc::O_RDWR, 0o600) };
        check("O_TMPFILE", tmpfile >= 0, format!("fd {tmpfile}"));
        // Errors as the kernel would give them.
        let link = dir.join("to-decoy");
        std::os::unix::fs::symlink(&decoy, &link).unwrap();
        let e = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&link).map_err(|e| e.raw_os_error());
        check("O_NOFOLLOW on a link", e.as_ref().err() == Some(&Some(libc::ELOOP)), format!("{:?}", e.map(|_| ())));
        let e = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(&decoy).map_err(|e| e.raw_os_error());
        check("O_DIRECTORY on a file", e.as_ref().err() == Some(&Some(libc::ENOTDIR)), format!("{:?}", e.map(|_| ())));
        let e = read(&dir.join("missing"));
        check("ENOENT", e == Err(libc::ENOENT), format!("{e:?}"));
        // Relative walks: `..` from the cwd, a dirfd, openat2 BENEATH.
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::env::set_current_dir(dir.join("sub")).unwrap();
        check("`..` from the cwd", read(std::path::Path::new("../decoy0.txt")) == Ok("DECOY-BYTES\n".into()), String::new());
        let dfd = unsafe { libc::open(cdir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        let at = unsafe { libc::openat(dfd, b"decoy0.txt\0".as_ptr() as *const libc::c_char, libc::O_RDONLY) };
        check("openat(dirfd)", at >= 0, format!("fd {at}"));
        #[repr(C)]
        struct How { flags: u64, mode: u64, resolve: u64 }
        let how = How { flags: libc::O_RDONLY as u64, mode: 0, resolve: libc::RESOLVE_BENEATH };
        let ok2 = unsafe { libc::syscall(libc::SYS_openat2, dfd, b"decoy0.txt\0".as_ptr(), &how as *const How, std::mem::size_of::<How>()) };
        let esc = unsafe { libc::syscall(libc::SYS_openat2, dfd, b"../x\0".as_ptr(), &how as *const How, std::mem::size_of::<How>()) };
        let esc_e = std::io::Error::last_os_error().raw_os_error();
        check("openat2 BENEATH", ok2 >= 0 && esc < 0 && esc_e == Some(libc::EXDEV), format!("{ok2} {esc} {esc_e:?}"));
        // GNU tar 1.35's parent open, `openat2(…, O_PATH|O_DIRECTORY|
        // O_NOFOLLOW|O_CLOEXEC)`, then a stat and an open beneath it
        // (2026-10-03: EINVAL from the performer's O_NOCTTY, then EBADF from
        // ADDFD, which cannot install an O_PATH file): the directory is
        // answered read-only, and the secret beneath it is still its twin.
        let mut parent = dir.as_os_str().as_encoded_bytes().to_vec();
        parent.extend_from_slice(b"/\0");
        let tar_how = How { flags: (libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_PATH | libc::O_DIRECTORY) as u64, mode: 0, resolve: 0 };
        let pfd = unsafe { libc::syscall(libc::SYS_openat2, libc::AT_FDCWD, parent.as_ptr(), &tar_how as *const How, std::mem::size_of::<How>()) } as i32;
        let pfd_e = std::io::Error::last_os_error().raw_os_error();
        check("openat2 O_PATH of a directory (tar)", pfd >= 0, format!("{pfd} {pfd_e:?}"));
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let srel = std::ffi::CString::new(secret.file_name().unwrap().as_encoded_bytes()).unwrap();
        let lst = unsafe { libc::fstatat(pfd, b"decoy0.txt\0".as_ptr() as *const libc::c_char, &mut st, libc::AT_SYMLINK_NOFOLLOW) };
        check("lstat beneath it", lst == 0 && st.st_mode & libc::S_IFMT == libc::S_IFREG, format!("{lst}"));
        let readat = |name: &std::ffi::CStr| -> String {
            let fd = unsafe { libc::openat(pfd, name.as_ptr(), libc::O_RDONLY | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            if fd < 0 {
                return format!("errno {:?}", std::io::Error::last_os_error().raw_os_error());
            }
            let mut f = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
            let mut s = String::new();
            let _ = f.read_to_string(&mut s);
            s
        };
        let drel = std::ffi::CString::new("decoy0.txt").unwrap();
        check("a file beneath it reads", readat(&drel) == "DECOY-BYTES\n", readat(&drel));
        check("the secret beneath it is its twin", readat(&srel) == "TWIN-PLACEHOLDER\n", readat(&srel));
        let fl = unsafe { libc::fcntl(pfd, libc::F_GETFL) };
        check("the stand-in is a read-only directory", fl >= 0 && fl & libc::O_ACCMODE == libc::O_RDONLY, format!("{fl:#o}"));
        let cl = unsafe { libc::fcntl(pfd, libc::F_GETFD) } & libc::FD_CLOEXEC;
        check("the stand-in is close-on-exec as asked", cl == libc::FD_CLOEXEC, format!("{cl}"));
        // An O_PATH openat2 the kernel refuses is refused the same way.
        let bad = How { flags: (libc::O_PATH | libc::O_RDWR) as u64, mode: 0, resolve: 0 };
        let r = unsafe { libc::syscall(libc::SYS_openat2, libc::AT_FDCWD, parent.as_ptr(), &bad as *const How, std::mem::size_of::<How>()) };
        let r_e = std::io::Error::last_os_error().raw_os_error();
        check("openat2 O_PATH|O_RDWR: the kernel's EINVAL", r < 0 && r_e == Some(libc::EINVAL), format!("{r} {r_e:?}"));
        // O_CLOEXEC as asked.
        let cl = unsafe { libc::fcntl(at, libc::F_GETFD) } & libc::FD_CLOEXEC;
        let with = unsafe { libc::openat(dfd, b"decoy0.txt\0".as_ptr() as *const libc::c_char, libc::O_RDONLY | libc::O_CLOEXEC) };
        let cl2 = unsafe { libc::fcntl(with, libc::F_GETFD) } & libc::FD_CLOEXEC;
        check("O_CLOEXEC as asked", cl == 0 && cl2 == libc::FD_CLOEXEC, format!("{cl} {cl2}"));
        // The secret, by name, by hard link, by symlink: the twin.
        check("the secret is its twin", read(&secret) == Ok("TWIN-PLACEHOLDER\n".into()), format!("{:?}", read(&secret)));
        // (Made before the guard: since 2026-10-04 the link family is
        // trapped under every secret policy, and a registered secret's real
        // file is never hard-linked from the tree, write-protection.md.)
        let hard = dir.join("hard");
        let relink = std::fs::hard_link(&secret, dir.join("hard2")).map_err(|e| e.raw_os_error().unwrap_or(0));
        check("a new hard link of the secret is refused", relink == Err(libc::EACCES), format!("{relink:?}"));
        check("a hard link is the secret", read(&hard) == Ok("TWIN-PLACEHOLDER\n".into()), format!("{:?}", read(&hard)));
        let soft = dir.join("soft");
        std::os::unix::fs::symlink(&secret, &soft).unwrap();
        check("a symlink is the secret", read(&soft) == Ok("TWIN-PLACEHOLDER\n".into()), format!("{:?}", read(&soft)));
        // A FIFO opened without O_NONBLOCK waits for its peer, which comes.
        let fifo = dir.join("fifo");
        let cf = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        unsafe { libc::mkfifo(cf.as_ptr(), 0o600) };
        let writer = unsafe { libc::fork() };
        if writer == 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if let Ok(mut w) = std::fs::OpenOptions::new().write(true).open(&fifo) {
                let _ = w.write_all(b"FIFO-DATA");
            }
            unsafe { libc::_exit(0) };
        }
        let via = read(&fifo);
        unsafe { libc::waitpid(writer, std::ptr::null_mut(), 0) };
        check("a blocking FIFO open", via == Ok("FIFO-DATA".into()), format!("{via:?}"));
        // Bytes that are not UTF-8.
        let odd = dir.join(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(b"\xffodd.bin"));
        std::fs::write(&odd, "ODD").unwrap();
        check("a non-UTF-8 name", read(&odd) == Ok("ODD".into()), format!("{:?}", read(&odd)));
        // A directory listing.
        let n = std::fs::read_dir(&dir).map(|d| d.count()).unwrap_or(0);
        check("a directory listing", n >= 5, format!("{n} entries"));
        // Bun's (Claude Code's) open of a directory: O_DIRECTORY with the
        // 0666 it passes on every open, issued raw so the mode register is
        // set. The kernel ignores that mode; the guard's one-step openat2
        // carried it (libc's O_TMPFILE holds the O_DIRECTORY bit, so the
        // open was taken for a create) and answered EINVAL (2026-10-16:
        // "Error processing settings: EINVAL … open '/tmp/claude-<uid>'").
        let bun = libc::O_RDONLY | libc::O_LARGEFILE | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY;
        let dfd2 = unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, cdir.as_ptr(), bun, 0o666) } as i32;
        let dfd2_e = std::io::Error::last_os_error().raw_os_error();
        check("an O_DIRECTORY open with a stray 0666 (Bun)", dfd2 >= 0, format!("{dfd2} {dfd2_e:?}"));
        // Relative to a descriptor (the cwd-based plan).
        let sub = unsafe { libc::syscall(libc::SYS_openat, dfd, b"sub\0".as_ptr(), bun, 0o666) } as i32;
        let sub_e = std::io::Error::last_os_error().raw_os_error();
        check("…relative to a dirfd", sub >= 0, format!("{sub} {sub_e:?}"));
        // The tracee's own openat2 with such a mode: the kernel's EINVAL.
        let moded = How { flags: (libc::O_RDONLY | libc::O_DIRECTORY) as u64, mode: 0o666, resolve: 0 };
        let r = unsafe { libc::syscall(libc::SYS_openat2, libc::AT_FDCWD, cdir.as_ptr(), &moded as *const How, std::mem::size_of::<How>()) };
        let r_e = std::io::Error::last_os_error().raw_os_error();
        check("openat2 with a mode on an open that creates nothing: the kernel's EINVAL", r < 0 && r_e == Some(libc::EINVAL), format!("{r} {r_e:?}"));
        let _ = std::fs::write(&report, &log);
        failed
    });
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("{seen}");
    assert_eq!(code, Some(0), "{seen}");
    eprintln!("SEMANTICS PASS: the performed opens behave like the tracee's own");
}

/// 2026-10-16 (a CI replay of `git filter-branch`): "index file open
/// failed: Resource temporarily unavailable" on `.git-rewrite/t/../index`.
/// The guard performs a tracee's open with a scoped `openat2`, which fails
/// EAGAIN when a rename or a mount anywhere on the machine lands during its
/// `..` walk; eight back-to-back attempts could all land in one burst. Here
/// this process renames in bursts (2 ms in every 6, the shape of a sandbox
/// starting up or git renaming its locks) while the guarded child opens
/// paths that walk `..`, as git's does and longer: none may answer EAGAIN.
#[test]
#[ignore]
fn an_open_walking_dotdot_through_rename_bursts_is_never_eagain() {
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Arc;
    let tree = OpenTree::new("dotdot");
    let report = tree.dir.join("report.txt");
    std::fs::create_dir_all(tree.dir.join("t/a")).unwrap();
    // How long a walk must be for a storm to fail three raw attempts in four
    // on this machine (a short walk races rarely; the length stands in for
    // a busier machine).
    let phase = Arc::new(AtomicU8::new(0)); // 0 storm, 1 bursts, 2 stop
    let epoch = std::time::Instant::now();
    let renamers: Vec<_> = (0..std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(2, 8))
        .map(|i| {
            let (phase, dir) = (phase.clone(), tree.dir.clone());
            std::thread::spawn(move || {
                let (a, b) = (dir.join(format!("ra{i}")), dir.join(format!("rb{i}")));
                let _ = std::fs::write(&a, b"");
                loop {
                    match phase.load(Ordering::Relaxed) {
                        2 => break,
                        1 if epoch.elapsed().as_micros() % 6_000 >= 2_000 => std::thread::yield_now(),
                        _ => {
                            let _ = std::fs::rename(&a, &b);
                            let _ = std::fs::rename(&b, &a);
                        }
                    }
                }
            })
        })
        .collect();
    #[repr(C)]
    struct How { flags: u64, mode: u64, resolve: u64 }
    let cdir = std::ffi::CString::new(tree.dir.as_os_str().as_encoded_bytes()).unwrap();
    let dfd = unsafe { libc::open(cdir.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    let rate = |k: usize| {
        let rel = std::ffi::CString::new(format!("t/{}../decoy0.txt", "a/../".repeat(k))).unwrap();
        let how = How { flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64, mode: 0, resolve: libc::RESOLVE_BENEATH };
        (0..200)
            .filter(|_| {
                let fd = unsafe { libc::syscall(libc::SYS_openat2, dfd, rel.as_ptr(), &how as *const How, std::mem::size_of::<How>()) } as i32;
                if fd >= 0 {
                    unsafe { libc::close(fd) };
                }
                fd < 0
            })
            .count() as f64
            / 200.0
    };
    // Small steps, stopping at three in four: a longer walk (a storm failing
    // every attempt) leaves no quiet long enough on a machine busy with the
    // other kernel tests as well.
    let mut k = 0usize;
    let mut r = rate(k);
    while r < 0.75 && k < 700 {
        k = (k + k / 12 + 1).min(700);
        r = rate(k);
    }
    unsafe { libc::close(dfd) };
    phase.store(1, Ordering::Relaxed);
    eprintln!("a walk of {k} more `a/..` pairs fails {:.0}% of raw attempts in a storm", r * 100.0);
    // git's own shape, `t/../decoy0.txt`, and the long one.
    let short = tree.dir.join("t/../decoy0.txt");
    let long = tree.dir.join(format!("t/{}../decoy0.txt", "a/../".repeat(k)));
    let code = run_guarded(&tree, || {
        let (mut eagain, mut other, mut wrong) = (0, 0, 0);
        for i in 0..400 {
            match std::fs::read_to_string(if i % 4 == 0 { &short } else { &long }) {
                Ok(s) if s == "DECOY-BYTES\n" => {}
                Ok(_) => wrong += 1,
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => eagain += 1,
                Err(_) => other += 1,
            }
        }
        let _ = std::fs::write(&report, format!("eagain={eagain} other={other} wrong={wrong}\n"));
        eagain + other + wrong
    });
    phase.store(2, Ordering::Relaxed);
    for h in renamers {
        let _ = join_within(h, wait_limit(), "a renamer thread, after its phase ended");
    }
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("{seen}");
    assert_eq!(code, Some(0), "400 guarded opens walking `..` through rename bursts: {seen}");
    eprintln!("DOTDOT PASS: no performed open answered EAGAIN through rename bursts");
}

#[test]
#[ignore]
fn a_pseudo_file_is_opened_with_the_tracees_namespaces_and_rights() {
    // procfs and its kin judge the OPENER (plan 10 §4.1a, context_helper):
    // `/proc/sys/kernel/hostname` shows the opener's UTS namespace, and a
    // child's `uid_map` may only be opened by a process in the child's
    // parent user namespace. The guard hands such opens to a helper that
    // joins the tracee's namespaces.
    let tree = OpenTree::new("pseudo");
    let report = tree.dir.join("report.txt");
    let have_bwrap = std::process::Command::new("bwrap").arg("--version").output().map(|o| o.status.success()).unwrap_or(false);
    let bwrap_disable = have_bwrap
        && std::process::Command::new("bwrap").arg("--help").output().map(|o| String::from_utf8_lossy(&o.stdout).contains("--disable-userns")).unwrap_or(false);
    let code = run_guarded(&tree, || {
        let mut log = String::new();
        let mut failed = 0;
        // Its own UTS namespace, its own hostname.
        let set = unsafe { libc::unshare(libc::CLONE_NEWUTS) == 0 && libc::sethostname(b"mandu-helper-test".as_ptr() as *const libc::c_char, 17) == 0 };
        if set {
            let seen = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
            let ok = seen.trim() == "mandu-helper-test";
            log.push_str(&format!("{} hostname through procfs: {:?}\n", if ok { "ok" } else { "FAIL" }, seen.trim()));
            failed += (!ok) as i32;
        } else {
            log.push_str("skip hostname: cannot unshare UTS here\n");
        }
        // bwrap writes its own child's uid_map (O_RDWR) from inside the new
        // user namespace; with --disable-userns that namespace is nested
        // inside another that owns the rest.
        if have_bwrap {
            let mut args = vec!["--unshare-user", "--unshare-net", "--unshare-uts", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev"];
            if bwrap_disable {
                args.insert(1, "--disable-userns");
            }
            let out = std::process::Command::new("bwrap").args(&args).args(["cat", "/proc/self/uid_map"]).output();
            let (ok, detail) = match out {
                Ok(o) => (o.status.success(), format!("{:?} {}", o.status.code(), String::from_utf8_lossy(&o.stderr).trim())),
                Err(e) => (false, e.to_string()),
            };
            log.push_str(&format!("{} bwrap{} sets up its user namespace: {detail}\n", if ok { "ok" } else { "FAIL" }, if bwrap_disable { " --disable-userns" } else { "" }));
            failed += (!ok) as i32;
        }
        let _ = std::fs::write(&report, &log);
        failed
    });
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("{seen}");
    assert_eq!(code, Some(0), "{seen}");
    eprintln!("PSEUDO-FS PASS: procfs opens are judged as the tracee's");
}

#[test]
#[ignore]
fn a_tracee_in_its_own_pid_namespace_reads_its_own_procfs() {
    // The whole-agent wrap with `--unshare-pid --proc /proc` (sandbox review
    // finding 3): the guard stays OUTSIDE that pid namespace, and procfs
    // resolves `self` for the opener, so every `self` the guard's own walk
    // met there named nobody (ENOENT): `bwrap: Can't open
    // /proc/self/mountinfo`, `ps` empty. The guard now names the tracee's
    // entry by the number that procfs shows for it.
    let tree = OpenTree::new("pidns");
    let report = tree.dir.join("report.txt");
    let have_bwrap = std::process::Command::new("bwrap").arg("--version").output().map(|o| o.status.success()).unwrap_or(false);
    if !have_bwrap {
        eprintln!("SKIP: no bwrap");
        return;
    }
    let script = r#"
fail=0
p=$$
say() { echo "$1"; }
read -r a rest < /proc/self/stat; [ "$a" = "$p" ] && say "ok /proc/self/stat is mine ($a)" || { say "FAIL /proc/self/stat: $a != $p"; fail=1; }
cd /proc && { read -r b rest < self/stat; [ "$b" = "$p" ] && say "ok self/stat relative to /proc" || { say "FAIL self/stat relative: $b"; fail=1; }; }
cd /
head -c1 /proc/self/mountinfo >/dev/null && say "ok /proc/self/mountinfo" || { say "FAIL /proc/self/mountinfo"; fail=1; }
head -c1 /proc/mounts >/dev/null && say "ok /proc/mounts (link into self)" || { say "FAIL /proc/mounts"; fail=1; }
head -c1 /proc/net/dev >/dev/null && say "ok /proc/net/dev (link into self)" || { say "FAIL /proc/net/dev"; fail=1; }
case "$(readlink /etc/mtab 2>/dev/null)" in *self*) head -c1 /etc/mtab >/dev/null && say "ok /etc/mtab" || { say "FAIL /etc/mtab"; fail=1; } ;; esac
bwrap --dev-bind / / --unshare-pid --proc /proc -- true && say "ok a nested bwrap starts" || { say "FAIL nested bwrap"; fail=1; }
bwrap --dev-bind / / --unshare-pid -- sh -c 'read -r c rest < /proc/self/stat; [ "$c" -gt 1 ]' && say "ok nested pid ns without its own /proc sees the outer numbers" || { say "FAIL nested pid ns without /proc"; fail=1; }
exit $fail
"#;
    let code = run_guarded(&tree, || {
        let out = std::process::Command::new("bwrap").args(["--dev-bind", "/", "/", "--unshare-pid", "--proc", "/proc", "--", "sh", "-c", script]).output();
        let (code, log) = match out {
            Ok(o) => (o.status.code().unwrap_or(99), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))),
            Err(e) => (98, e.to_string()),
        };
        let _ = std::fs::write(&report, &log);
        code
    });
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("{seen}");
    if seen.contains("No permissions to create") || seen.contains("setting up uid map") {
        eprintln!("SKIP: bwrap cannot create a user namespace here");
        return;
    }
    assert_eq!(code, Some(0), "{seen}");
    eprintln!("PIDNS PASS: the tracee's own procfs across a pid namespace");
}

#[test]
#[ignore]
fn a_tainted_process_in_its_own_pid_namespace_stays_uninspectable() {
    // §4.1 under the wrap's `--unshare-pid`: a procfs path names a process by
    // ITS namespace's number, and the taint set is keyed by host pids. An
    // untainted sibling reading `/proc/<n>/environ` of a tainted process must
    // be refused though `n` is not the host pid.
    pidns_introspection_case("pidns-taint", false);
}

#[test]
#[ignore]
fn a_holder_of_another_secret_cannot_read_a_holder() {
    // §4.1 (exec-routing.md §7.5, 2026-10-02): the opener's own taint is no
    // pass. The shell holds one secret, the sleep another; the shell's child
    // carries the shell's taint, not the sleep's, and is refused the sleep's
    // environment. It still reads the shell's (it carries all of that one).
    // Before, every tainted opener was exempt: `READ environ of 4`.
    pidns_introspection_case("pidns-taint-other", true);
}

/// The two §4.1 pid-namespace cases: a `sleep` in a pid namespace of its
/// own is tainted by its host pid, and the script's `head` (the shell's
/// child) reads `/proc/<its number>/environ`. `taint_shell`: the shell is a
/// holder too (of another secret), and must still read its own entry. The
/// `sleep` is detached (its subshell exits at once; the namespace's init
/// adopts it): since 2026-10-03 a process that may reap a holder becomes one
/// at its next wait (plan 13 §4.9, the exit status), and the shell waits
/// for every `sleep 0.05` of its loop; as the holder's parent it would carry
/// the holder's taint, and so would its `head`.
fn pidns_introspection_case(name: &str, taint_shell: bool) {
    let tree = OpenTree::new(name);
    let have_bwrap = std::process::Command::new("bwrap").arg("--version").output().map(|o| o.status.success()).unwrap_or(false);
    if !have_bwrap {
        eprintln!("SKIP: no bwrap");
        return;
    }
    let dir = tree.dir.clone();
    let tainted = Arc::new(net_supervisor::secret_open::TaintedSet::default());
    let marker = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // The side thread: find the in-namespace `sleep` (and the shell) by host
    // pid, taint it, then let the script look. The match names THIS test's
    // pid namespace (its `ns/pid` link, which the script records first): a
    // number in the namespace alone is ambiguous, since every test and suite
    // running beside this one that starts a `sleep` early in a pid namespace
    // of its own gives it the same small number.
    let side = {
        let (dir, tainted, marker) = (dir.clone(), tainted.clone(), marker.clone());
        std::thread::spawn(move || {
            let find = |ns: i32, ns_id: &str, comm: &str| -> Option<i32> {
                for e in std::fs::read_dir("/proc").ok()?.flatten() {
                    let Some(h) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
                    let st = std::fs::read_to_string(format!("/proc/{h}/status")).unwrap_or_default();
                    let nspid = st.lines().find_map(|l| l.strip_prefix("NSpid:")).unwrap_or("");
                    let levels: Vec<i32> = nspid.split_whitespace().filter_map(|v| v.parse().ok()).collect();
                    let same_ns = || std::fs::read_link(format!("/proc/{h}/ns/pid")).map(|l| l.to_string_lossy() == ns_id).unwrap_or(false);
                    if levels.len() >= 2 && levels.last() == Some(&ns) && st.starts_with(&format!("Name:\t{comm}\n")) && same_ns() {
                        return Some(h);
                    }
                }
                None
            };
            let num = |f: &str| std::fs::read_to_string(dir.join(f)).ok().and_then(|s| s.trim().parse::<i32>().ok());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while std::time::Instant::now() < deadline {
                if let (Some(ns), Some(sh), Ok(ns_id)) = (num("ns_pid"), num("sh_pid"), std::fs::read_to_string(dir.join("ns_id"))) {
                    let ns_id = ns_id.trim().to_string();
                    let sleep = find(ns, &ns_id, "sleep");
                    let shell = if taint_shell { find(sh, &ns_id, "sh") } else { Some(0) };
                    if let (Some(h), Some(s)) = (sleep, shell) {
                        tainted.insert(&mandu_arbiter::proc::proc_key_for_pid(h).unwrap());
                        if taint_shell {
                            tainted.insert(&mandu_arbiter::proc::proc_key_for_pid(s).unwrap());
                        }
                        marker.store(true, std::sync::atomic::Ordering::SeqCst);
                        let _ = std::fs::write(dir.join("go"), "");
                        return;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
    };
    let own = if taint_shell {
        r#"head -c1 /proc/$$/environ >/dev/null 2>&1 && echo "ok the shell's child reads the shell it carries" || { echo "FAIL the shell's own entry refused to its child"; r=1; }"#
    } else {
        ""
    };
    let script = format!(
        r#"
cd {dir}
readlink /proc/self/ns/pid > ns_id
echo $$ > sh_pid
( sleep 30 & echo $! > ns_pid )
i=0; while [ ! -e go ] && [ $i -lt 300 ]; do sleep 0.05; i=$((i+1)); done
n=$(cat ns_pid)
if head -c1 /proc/$n/environ >/dev/null 2>&1; then echo "READ environ of $n"; r=1; else echo "REFUSED environ of $n"; r=0; fi
head -c1 /proc/$n/stat >/dev/null 2>&1 && echo "ok stat stays readable" || {{ echo "FAIL stat refused"; r=1; }}
{own}
kill $n 2>/dev/null
exit $r
"#,
        dir = dir.display()
    );
    let report = dir.join("report.txt");
    let t2 = tainted.clone();
    let code = run_guarded_cfg(&tree, move |c| c.tainted = t2, || {
        // The descriptors this child inherited from the test process (every
        // test's socket pairs and pipes, made without CLOEXEC, open in the
        // parallel tests at the fork) never reach the script: the shell and
        // the sleep held the same pipe and socket-pair ends, so plan 13 D2
        // made the shell a holder flowing from the sleep, its child `head`
        // carried that taint, and read the sleep (2026-10-02, the flaky
        // `READ environ of 4` in parallel kernel lanes). Marked CLOEXEC
        // here, closed by the exec.
        // SAFETY: a plain syscall on this process's own descriptor table.
        unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC) };
        let out = std::process::Command::new("bwrap").args(["--dev-bind", "/", "/", "--unshare-pid", "--proc", "/proc", "--", "sh", "-c", &script]).output();
        let (code, log) = match out {
            Ok(o) => (o.status.code().unwrap_or(99), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))),
            Err(e) => (98, e.to_string()),
        };
        let _ = std::fs::write(&report, &log);
        code
    });
    let _ = join_within(side, wait_limit(), "the test's side thread");
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("{seen}");
    assert!(marker.load(std::sync::atomic::Ordering::SeqCst), "the side thread never found the sleep: {seen}");
    assert_eq!(code, Some(0), "{seen}");
    eprintln!("PIDNS TAINT PASS ({name})");
}

#[test]
#[ignore]
fn a_double_forked_orphan_stays_in_its_sandbox() {
    // The gap the pid-namespace record closes (landlock_mirror): a sandboxed
    // process double-forks, the middle one exits, and the orphan is
    // re-parented to its namespace's init, which is NOT sandboxed (bwrap's
    // init in the command box). Its lineage no longer shows the sandbox; its
    // pid namespace still does.
    if landlock_abi() < 1 {
        eprintln!("SKIP: no Landlock on this kernel");
        return;
    }
    let tree = OpenTree::new("orphan");
    let report = tree.dir.join("report.txt");
    let dir = tree.dir.clone();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    std::fs::create_dir_all(&allowed).unwrap();
    std::fs::create_dir_all(&denied).unwrap();
    std::fs::write(allowed.join("a.txt"), "ALLOWED").unwrap();
    std::fs::write(denied.join("d.txt"), "DENIED-BYTES").unwrap();
    let code = run_guarded(&tree, || unsafe {
        if libc::unshare(libc::CLONE_NEWPID) != 0 {
            return 64;
        }
        let init = libc::fork();
        if init != 0 {
            let mut st = 0;
            libc::waitpid(init, &mut st, 0);
            return if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 70 };
        }
        // pid 1 of the new namespace: unrestricted, reaps everything.
        let a = libc::fork();
        if a == 0 {
            if !child_landlock_read_only(&allowed) {
                libc::_exit(65);
            }
            let m = libc::fork();
            if m == 0 {
                let g = libc::fork();
                if g == 0 {
                    // Wait to be re-parented to the namespace's init.
                    for _ in 0..200 {
                        if libc::getppid() == 1 {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    let read = |p: &std::path::Path| std::fs::read_to_string(p).map_err(|e| e.raw_os_error().unwrap_or(0));
                    let a = read(&allowed.join("a.txt"));
                    let d = read(&denied.join("d.txt"));
                    let _ = std::fs::write(&report, format!("ppid={} allowed={a:?} denied={d:?}", libc::getppid()));
                    libc::_exit(if a == Ok("ALLOWED".into()) && d == Err(libc::EACCES) { 0 } else { 1 });
                }
                libc::_exit(0);
            }
            let mut st = 0;
            libc::waitpid(m, &mut st, 0);
            libc::_exit(0);
        }
        // Init: reap every child (the orphan included); the orphan's verdict
        // is the one that counts.
        let mut verdict = 66;
        loop {
            let mut st = 0;
            let pid = libc::waitpid(-1, &mut st, 0);
            if pid < 0 {
                break;
            }
            if pid != a && libc::WIFEXITED(st) {
                verdict = libc::WEXITSTATUS(st);
            }
        }
        libc::_exit(verdict);
    });
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("ORPHAN: {seen}");
    match code {
        Some(64) => {
            eprintln!("SKIP: no pid namespace here");
            return;
        }
        Some(65) => {
            eprintln!("SKIP: could not restrict with Landlock here");
            return;
        }
        _ => {}
    }
    assert_eq!(code, Some(0), "{seen}");
    assert!(seen.starts_with("ppid=1 "), "the orphan was re-parented to the namespace's init: {seen}");
    eprintln!("ORPHAN PASS: a double-forked orphan stays in its sandbox");
}

/// Landlock syscalls (the same numbers on x86_64 and aarch64).
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;

fn landlock_abi() -> i64 {
    unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, std::ptr::null::<u8>(), 0usize, 1u32) }
}

/// Child: restrict itself to reading files under `allowed` only.
fn child_landlock_read_only(allowed: &std::path::Path) -> bool {
    #[repr(C)]
    struct Attr { handled_access_fs: u64 }
    #[repr(C, packed)]
    struct Beneath { allowed_access: u64, parent_fd: i32 }
    unsafe {
        let attr = Attr { handled_access_fs: LANDLOCK_ACCESS_FS_READ_FILE };
        let rs = libc::syscall(SYS_LANDLOCK_CREATE_RULESET, &attr as *const Attr, std::mem::size_of::<Attr>(), 0u32);
        if rs < 0 {
            return false;
        }
        let c = std::ffi::CString::new(allowed.as_os_str().as_encoded_bytes()).unwrap();
        let pfd = libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
        let rule = Beneath { allowed_access: LANDLOCK_ACCESS_FS_READ_FILE, parent_fd: pfd };
        if libc::syscall(SYS_LANDLOCK_ADD_RULE, rs, 1u32, &rule as *const Beneath, 0u32) != 0 {
            return false;
        }
        libc::close(pfd);
        let ok = libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, rs, 0u32) == 0;
        libc::close(rs as i32);
        ok
    }
}

#[test]
#[ignore]
fn a_sandboxed_tracees_opens_stay_in_its_sandbox() {
    // The guard performs the open; without the mirror it would read what the
    // tracee's own Landlock domain forbids.
    if landlock_abi() < 1 {
        eprintln!("SKIP: no Landlock on this kernel");
        return;
    }
    let tree = OpenTree::new("landlock");
    let report = tree.dir.join("report.txt");
    let (dir, secret) = (tree.dir.clone(), tree.secret.clone());
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    std::fs::create_dir_all(&allowed).unwrap();
    std::fs::create_dir_all(&denied).unwrap();
    std::fs::write(allowed.join("a.txt"), "ALLOWED").unwrap();
    std::fs::write(denied.join("d.txt"), "DENIED-BYTES").unwrap();
    let code = run_guarded(&tree, || {
        let read = |p: &std::path::Path| std::fs::read_to_string(p).map_err(|e| e.raw_os_error().unwrap_or(0));
        let before = read(&denied.join("d.txt"));
        if !child_landlock_read_only(&allowed) {
            return 64;
        }
        let a = read(&allowed.join("a.txt"));
        let d = read(&denied.join("d.txt"));
        let s = read(&secret);
        // A child forked after the restriction inherits it.
        let grand = unsafe { libc::fork() };
        if grand == 0 {
            let d2 = read(&denied.join("d.txt"));
            unsafe { libc::_exit(if d2 == Err(libc::EACCES) { 0 } else { 1 }) };
        }
        let mut st = 0;
        unsafe { libc::waitpid(grand, &mut st, 0) };
        let gok = libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0;
        let _ = std::fs::write(&report, format!("before={before:?} allowed={a:?} denied={d:?} secret={s:?} grandchild_denied={gok}"));
        let ok = before == Ok("DENIED-BYTES".into()) && a == Ok("ALLOWED".into()) && d == Err(libc::EACCES) && gok
            // The secret sits outside the sandbox's allowed dir: refused too.
            && s == Err(libc::EACCES);
        if ok { 0 } else { 1 }
    });
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("LANDLOCK: {seen}");
    if code == Some(64) {
        eprintln!("SKIP: could not restrict with Landlock here");
        return;
    }
    assert_eq!(code, Some(0), "{seen}");
    eprintln!("LANDLOCK MIRROR PASS: a sandboxed tracee's performed opens stay inside its sandbox");
}

#[test]
#[ignore]
fn a_tracee_that_confines_its_own_tcp_stays_confined_under_the_guard() {
    // confidentiality-plan-11 §8 item 5: the guard performs every allowed
    // connect on its copy of the socket, so without the connect mirror a
    // tracee's own Landlock TCP rules were widened to the guard's allow set
    // (the launcher's inspect-mcp confine was a no-op under the default-on
    // guard). Traps WITHOUT a secret policy: the restrict is trapped anyway.
    use fs_supervisor::landlock::{landlock_abi_version, landlock_net_supported, plan_net_confine, restrict_self_to_plan};
    if !landlock_net_supported() {
        eprintln!("SKIP: no Landlock TCP rules on this kernel (needs >= 6.7)");
        return;
    }
    ensure_loopback_up();
    let (_la, allowed) = loopback_listener();
    let (_lb, other) = loopback_listener();
    let (sup_sock, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe { libc::close(sup_sock) };
        let traps = net_supervisor::guard_kernel::FilterTraps::default();
        let listener = match net_supervisor::guard_kernel::install_guard_filter_self(traps) {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if send_fd(child_sock, listener).is_err() {
            unsafe {
                libc::close(listener);
                libc::_exit(EXIT_SETUP_FAIL)
            };
        }
        unsafe { libc::close(listener) };
        let lo = std::net::Ipv4Addr::new(127, 0, 0, 1);
        // Before the restriction both ports connect (the guard allows both).
        if child_tcp_connect(lo, other, false) != EXIT_CONNECTED {
            unsafe { libc::_exit(10) };
        }
        let plan = plan_net_confine(&[allowed], &[], landlock_abi_version() as u32);
        if restrict_self_to_plan(&plan).is_err() {
            unsafe { libc::_exit(64) };
        }
        let a = child_tcp_connect(lo, allowed, false);
        let a_nb = child_tcp_connect(lo, allowed, true);
        let o = child_tcp_connect(lo, other, false);
        let o_nb = child_tcp_connect(lo, other, true);
        // A child forked after the restriction inherits it.
        let grand = unsafe { libc::fork() };
        if grand == 0 {
            let g = child_tcp_connect(lo, other, false);
            unsafe { libc::_exit(if g == libc::EACCES { 0 } else { 1 }) };
        }
        let mut st = 0;
        unsafe { libc::waitpid(grand, &mut st, 0) };
        let gok = libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0;
        let code = if a != EXIT_CONNECTED {
            20
        } else if a_nb != EXIT_CONNECTED {
            21
        } else if o != libc::EACCES {
            30
        } else if o_nb != libc::EACCES {
            31
        } else if !gok {
            40
        } else {
            0
        };
        unsafe { libc::_exit(code) };
    }
    unsafe { libc::close(child_sock) };
    let listener = match recv_fd_from(sup_sock, child) {
        Ok(fd) => fd,
        Err(_) => {
            assert_eq!(reap(child), Some(EXIT_NO_SECCOMP), "tracee failed to send its listener");
            eprintln!("SKIP: seccomp NEW_LISTENER denied here");
            return;
        }
    };
    let rules = vec![
        parse_rule(&format!("tcp:127.0.0.1:{allowed}")).unwrap(),
        parse_rule(&format!("tcp:127.0.0.1:{other}")).unwrap(),
    ];
    let cfg = GuardConfig::new(Arc::new(GuardPolicy::new(rules)), no_resolver());
    let server = std::thread::spawn(move || {
        let _ = net_supervisor::guard_kernel::run_guard_supervisor(listener, cfg);
        unsafe { libc::close(listener) };
    });
    let code = reap(child);
    let _ = join_within(server, wait_limit(), "the guard supervisor (run_guard_supervisor), after its tracee exited");
    unsafe { libc::close(sup_sock) };
    if code == Some(64) {
        eprintln!("SKIP: could not restrict with Landlock here");
        return;
    }
    assert_eq!(
        code,
        Some(0),
        "10 = the unrestricted connect failed, 2x = the allowed port was refused, \
         3x = the port outside the tracee's own rules connected through the guard, 40 = a child escaped it"
    );
    eprintln!("LANDLOCK CONNECT MIRROR PASS: a tracee's own TCP rules hold for the connects the guard performs");
}

// ── the single-connect driver (mirrors fs-supervisor's drive_one_open) ───────

enum ConnectRecipe {
    Tcp { port: u16, nonblocking: bool },
    /// A blocking loopback TCP connect issued by a WORKER thread (glibc's and
    /// Bun's DNS do this): the notification names a thread, not a leader.
    TcpFromThread { port: u16 },
    /// A blocking TCP connect to a non-loopback v4 address.
    TcpTo { ip: std::net::Ipv4Addr, port: u16 },
    Unix { path: String },
    /// An AF_UNIX connect after `chdir(dir)` (a relative `path` resolves
    /// against it), optionally nonblocking.
    UnixFrom { dir: String, path: String, nonblocking: bool },
    /// Open `target` O_PATH, then connect to `/proc/self/fd/<that fd>`.
    UnixViaFd { target: String },
    /// An AF_VSOCK connect to (cid, port): WSL2's channel to the Windows host.
    Vsock { cid: u32, port: u32 },
    /// A TCP connect to 127.0.0.1:port where the socket and the process sit in
    /// different network namespaces: `socket_elsewhere` makes the socket in a
    /// fresh netns and returns the process to ours; otherwise the socket is
    /// ours and the process moves to a fresh netns before connecting.
    TcpSplitNetns { port: u16, socket_elsewhere: bool },
}

/// The tracee could not split its namespaces (no userns here): SKIP.
const EXIT_NO_NETNS: i32 = 94;

/// Fork a tracee that installs the connect listener, hands it to us, and issues
/// exactly ONE connect (suspended on the trap). We (the supervisor) RECV the
/// notification and run `handle_connect_notif`, then reap the child. Returns
/// `(outcome, child_exit)`, or `None` to SKIP when seccomp NEW_LISTENER is denied
/// or a split-netns tracee cannot make a fresh network namespace.
fn drive_one_connect(recipe: ConnectRecipe, cfg: &GuardConfig) -> Option<(GuardOutcome, Option<i32>)> {
    let (sup_sock, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork: {}", last_err());

    if child == 0 {
        // ── TRACEE ──────────────────────────────────────────────────────────
        unsafe { libc::close(sup_sock) };
        let listener = match install_connect_filter_self() {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if send_fd(child_sock, listener).is_err() {
            unsafe {
                libc::close(listener);
                libc::_exit(EXIT_SETUP_FAIL)
            };
        }
        // Issue the one connect that trips the trap; exit with what we observed.
        let code = match recipe {
            ConnectRecipe::Tcp { port, nonblocking } => {
                child_tcp_connect(std::net::Ipv4Addr::new(127, 0, 0, 1), port, nonblocking)
            }
            ConnectRecipe::TcpTo { ip, port } => child_tcp_connect(ip, port, false),
            ConnectRecipe::TcpFromThread { port } => {
                // A raw clone-thread would do; std's thread is one (CLONE_THREAD
                // | CLONE_FILES), which is the shape that matters.
                std::thread::spawn(move || child_tcp_connect(std::net::Ipv4Addr::new(127, 0, 0, 1), port, false)).join().unwrap_or(EXIT_SETUP_FAIL)
            }
            ConnectRecipe::Unix { path } => child_unix_connect(&path),
            ConnectRecipe::UnixFrom { dir, path, nonblocking } => {
                let d = std::ffi::CString::new(dir).unwrap();
                if unsafe { libc::chdir(d.as_ptr()) } != 0 {
                    unsafe { libc::_exit(EXIT_SETUP_FAIL) };
                }
                child_unix_connect_opts(&path, nonblocking)
            }
            ConnectRecipe::UnixViaFd { target } => {
                let t = std::ffi::CString::new(target).unwrap();
                let fd = unsafe { libc::open(t.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                if fd < 0 {
                    unsafe { libc::_exit(EXIT_SETUP_FAIL) };
                }
                child_unix_connect(&format!("/proc/self/fd/{fd}"))
            }
            ConnectRecipe::Vsock { cid, port } => child_vsock_connect(cid, port),
            ConnectRecipe::TcpSplitNetns { port, socket_elsewhere } => child_split_netns_connect(port, socket_elsewhere),
        };
        unsafe { libc::_exit(code) };
    }

    // ── SUPERVISOR (parent) ───────────────────────────────────────────────────
    unsafe { libc::close(child_sock) };
    let listener = match recv_fd_from(sup_sock, child) {
        Ok(fd) => fd,
        Err(_) => {
            let code = reap(child);
            unsafe { libc::close(sup_sock) };
            if code == Some(EXIT_NO_SECCOMP) {
                eprintln!(
                    "SKIP: seccomp NEW_LISTENER denied (need CAP_SYS_ADMIN-in-userns + \
                     no_new_privs). Re-run under: unshare --user --map-root-user ..."
                );
                return None;
            }
            panic!("tracee failed to send listener fd (exit {code:?})");
        }
    };

    let notif = match recv_notif(listener) {
        Ok(n) => n,
        Err(e) => {
            // The tracee exited without issuing its connect: the filter has no
            // task left, so NOTIF_RECV answers ENOENT. A split-netns recipe
            // does that when its unshare/setns probe fails (no userns to make
            // a fresh network namespace): SKIP. Anything else is a failure.
            let code = reap(child);
            unsafe {
                libc::close(listener);
                libc::close(sup_sock);
            }
            if code == Some(EXIT_NO_NETNS) {
                eprintln!("SKIP: cannot split network namespaces here (CLONE_NEWNET needs an unprivileged userns)");
                return None;
            }
            panic!("NOTIF_RECV: {e} (tracee exit {code:?})");
        }
    };
    let outcome = handle_connect_notif(listener, cfg, &notif).expect("handle_connect_notif");
    let child_exit = reap(child);
    unsafe {
        libc::close(listener);
        libc::close(sup_sock);
    }
    Some((outcome, child_exit))
}

/// Child: TCP connect to ip:port. Returns EXIT_CONNECTED (0) on success,
/// the raw errno on failure. For nonblocking, complete via poll + SO_ERROR.
fn child_tcp_connect(ip: std::net::Ipv4Addr, port: u16, nonblocking: bool) -> i32 {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return EXIT_UNEXPECTED;
        }
        if nonblocking {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr { s_addr: u32::from(ip).to_be() },
            sin_zero: [0; 8],
        };
        let rc = libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if rc == 0 {
            libc::close(fd);
            return EXIT_CONNECTED;
        }
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
        if nonblocking && e == libc::EINPROGRESS {
            // Complete the nonblocking connect on our own fd (the shared socket the
            // supervisor connected). poll for writable, then read SO_ERROR.
            let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
            let _ = libc::poll(&mut pfd, 1, 2000);
            let mut soerr: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, &mut soerr as *mut _ as *mut libc::c_void, &mut len);
            libc::close(fd);
            return if soerr == 0 { EXIT_CONNECTED } else { soerr };
        }
        libc::close(fd);
        e
    }
}

/// Child: `ConnectRecipe::TcpSplitNetns`. EXIT_CONNECTED, the connect's
/// errno, or EXIT_NO_NETNS when the namespaces cannot be split.
fn child_split_netns_connect(port: u16, socket_elsewhere: bool) -> i32 {
    unsafe {
        let ours = libc::open(b"/proc/self/ns/net\0".as_ptr() as *const libc::c_char, libc::O_RDONLY | libc::O_CLOEXEC);
        if ours < 0 {
            return EXIT_NO_NETNS;
        }
        let fd = if socket_elsewhere {
            if libc::unshare(libc::CLONE_NEWNET) != 0 {
                return EXIT_NO_NETNS;
            }
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if libc::setns(ours, libc::CLONE_NEWNET) != 0 {
                return EXIT_NO_NETNS;
            }
            fd
        } else {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if libc::unshare(libc::CLONE_NEWNET) != 0 {
                return EXIT_NO_NETNS;
            }
            fd
        };
        if fd < 0 {
            return EXIT_UNEXPECTED;
        }
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr { s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be() },
            sin_zero: [0; 8],
        };
        let rc = libc::connect(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t);
        let code = if rc == 0 { EXIT_CONNECTED } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) };
        libc::close(fd);
        code
    }
}

/// Child: AF_UNIX connect to `path`. EXIT_CONNECTED on success, errno on failure.
fn child_unix_connect(path: &str) -> i32 {
    child_unix_connect_opts(path, false)
}

/// `child_unix_connect`, optionally on a nonblocking socket (a Unix stream
/// connect to a listening socket completes at once: 0, or EAGAIN when the
/// backlog is full).
fn child_unix_connect_opts(path: &str, nonblocking: bool) -> i32 {
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | if nonblocking { libc::SOCK_NONBLOCK } else { 0 }, 0);
        if fd < 0 {
            return EXIT_UNEXPECTED;
        }
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_bytes();
        if bytes.len() >= addr.sun_path.len() {
            return EXIT_UNEXPECTED;
        }
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        let rc = libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        );
        let code = if rc == 0 {
            EXIT_CONNECTED
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
        };
        libc::close(fd);
        code
    }
}

/// Child: AF_VSOCK connect. EXIT_VSOCK_UNAVAILABLE when the host cannot open
/// a vsock socket at all (no module: nothing to trap), else the connect's errno
/// (0 on success).
fn child_vsock_connect(cid: u32, port: u32) -> i32 {
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return EXIT_VSOCK_UNAVAILABLE;
        }
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = cid;
        addr.svm_port = port;
        let rc = libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        );
        let code = if rc == 0 {
            EXIT_CONNECTED
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
        };
        libc::close(fd);
        code
    }
}

const EXIT_VSOCK_UNAVAILABLE: i32 = 94;

/// WSL2's Windows interop door, whole-agent leg (`guard::WslGuard`), on a
/// plain Linux kernel by pinning the guard's WSL config: a Unix socket named
/// as `$WSL_INTEROP` stands in for `/run/WSL/<pid>_interop`. Differential:
/// the same socket passes through with no WSL config (the door is real), is
/// refused with EACCES under it, and a SYMLINK to it is refused too (the path
/// is canonicalized before the check).
#[test]
#[ignore]
fn guard_refuses_the_wsl_interop_socket() {
    use std::os::unix::net::UnixListener;
    let dir = std::env::temp_dir().join(format!("mandu-net-guard-wsl-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("1_interop").to_string_lossy().to_string();
    let link = dir.join("innocent.sock").to_string_lossy().to_string();
    let ul = UnixListener::bind(&sock).expect("bind the stand-in interop socket");
    std::os::unix::fs::symlink(&sock, &link).unwrap();
    let cleanup = || {
        let _ = std::fs::remove_dir_all(&dir);
    };

    // Control: no WSL config → the connect passes through and lands.
    let plain = GuardConfig::new(Arc::new(GuardPolicy::default()), no_resolver());
    let Some((outcome, child_exit)) = drive_one_connect(ConnectRecipe::Unix { path: sock.clone() }, &plain) else {
        cleanup();
        return; // SKIP
    };
    assert!(matches!(outcome, GuardOutcome::PassedThrough { .. }), "control: {outcome:?}");
    assert_eq!(child_exit, Some(EXIT_CONNECTED), "control: the socket is reachable");
    ul.set_nonblocking(true).unwrap();
    assert!(ul.accept().is_ok());

    // WSL: the named socket, directly and through a symlink.
    let mut wsl = GuardConfig::new(Arc::new(GuardPolicy::default()), no_resolver());
    wsl.wsl = Some(WslGuard { interop_env: Some(sock.clone()), interop_id: None });
    for target in [&sock, &link] {
        let (outcome, child_exit) = drive_one_connect(ConnectRecipe::Unix { path: target.clone() }, &wsl).expect("seccomp worked above");
        assert!(matches!(outcome, GuardOutcome::Refused { .. }), "{target}: {outcome:?}");
        assert_eq!(child_exit, Some(libc::EACCES), "{target}: the tracee's connect must fail EACCES");
    }
    assert!(ul.accept().is_err(), "no refused connect may reach the listener");
    cleanup();
    eprintln!("WSL INTEROP PASS: the interop socket (and a symlink to it) refused; reachable without the WSL config");
}

/// `(st_dev, st_ino)` of a path.
fn identity(p: &str) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(p).unwrap();
    (m.dev(), m.ino())
}

/// A listener that accepts on a background thread and counts what it got.
struct CountingListener {
    count: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    th: Option<std::thread::JoinHandle<()>>,
}

impl CountingListener {
    fn bind(path: &str) -> Self {
        use std::sync::atomic::Ordering;
        let ul = std::os::unix::net::UnixListener::bind(path).expect("bind");
        ul.set_nonblocking(true).unwrap();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (c, st) = (count.clone(), stop.clone());
        let th = std::thread::spawn(move || {
            while !st.load(Ordering::Relaxed) {
                match ul.accept() {
                    Ok(_) => {
                        c.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_micros(200)),
                }
            }
            // Drain anything still queued.
            while ul.accept().is_ok() {
                c.fetch_add(1, Ordering::SeqCst);
            }
        });
        CountingListener { count, stop, th: Some(th) }
    }

    fn finish(mut self) -> usize {
        std::thread::sleep(std::time::Duration::from_millis(20));
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        join_within(self.th.take().unwrap(), wait_limit(), "the counting listener's thread, after its stop flag").unwrap();
        self.count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The supervised Unix connect under the WSL config (exec-routing.md §4.1):
/// the guard opens the target in the tracee's view, checks that inode, and
/// connects the tracee's socket to it. A benign socket connects (blocking,
/// nonblocking, relative to the tracee's cwd, through /proc/self/fd/N); the
/// stand-in interop socket is refused through a HARDLINK (same inode, other
/// name) and through /proc/self/fd/N; a missing path gets ENOENT, as from the
/// kernel.
#[test]
#[ignore]
fn guard_supervises_unix_connects_on_wsl() {
    let dir = std::env::temp_dir().join(format!("mandu-net-guard-wslsup-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.to_string_lossy().to_string();
    let interop = format!("{d}/1_interop");
    let benign = format!("{d}/benign.sock");
    let hard = format!("{d}/hard.sock");
    let li = CountingListener::bind(&interop);
    let lb = CountingListener::bind(&benign);
    std::fs::hard_link(&interop, &hard).expect("hardlink the stand-in");
    let cleanup = || {
        let _ = std::fs::remove_dir_all(&dir);
    };

    let mut wsl = GuardConfig::new(Arc::new(GuardPolicy::default()), no_resolver());
    wsl.wsl = Some(WslGuard { interop_env: Some(interop.clone()), interop_id: None }.with_interop_identity(Some(identity(&interop))));

    let Some((outcome, child_exit)) = drive_one_connect(ConnectRecipe::Unix { path: benign.clone() }, &wsl) else {
        cleanup();
        return; // SKIP
    };
    assert_eq!(outcome, GuardOutcome::UnixSupervised { answered: 0 }, "benign, blocking");
    assert_eq!(child_exit, Some(EXIT_CONNECTED));

    let cases: Vec<(ConnectRecipe, GuardOutcome, i32)> = vec![
        (ConnectRecipe::UnixFrom { dir: d.clone(), path: "benign.sock".into(), nonblocking: true }, GuardOutcome::UnixSupervised { answered: 0 }, EXIT_CONNECTED),
        (ConnectRecipe::UnixViaFd { target: benign.clone() }, GuardOutcome::UnixSupervised { answered: 0 }, EXIT_CONNECTED),
        (ConnectRecipe::UnixFrom { dir: d.clone(), path: "missing.sock".into(), nonblocking: false }, GuardOutcome::UnixSupervised { answered: libc::ENOENT }, libc::ENOENT),
    ];
    for (recipe, want, exit) in cases {
        let (outcome, child_exit) = drive_one_connect(recipe, &wsl).expect("seccomp worked above");
        assert_eq!(outcome, want);
        assert_eq!(child_exit, Some(exit));
    }
    for recipe in [
        ConnectRecipe::Unix { path: hard.clone() },
        ConnectRecipe::UnixFrom { dir: d.clone(), path: "hard.sock".into(), nonblocking: false },
        ConnectRecipe::UnixViaFd { target: interop.clone() },
    ] {
        let (outcome, child_exit) = drive_one_connect(recipe, &wsl).expect("seccomp worked above");
        assert!(matches!(outcome, GuardOutcome::Refused { .. }), "{outcome:?}");
        assert_eq!(child_exit, Some(libc::EACCES));
    }
    assert_eq!(li.finish(), 0, "no refused connect may reach the interop stand-in");
    assert_eq!(lb.finish(), 3, "every benign connect landed");
    cleanup();
    eprintln!("WSL SUPERVISED PASS: benign connects land; hardlink and fd spellings of the door refused");
}

/// The race the supervised connect closes: another thread swaps a symlink
/// between a benign socket and the stand-in interop socket as fast as it can
/// while the tracee connects through the link over and over. Under the old
/// check-then-CONTINUE the kernel re-resolved the link after the check, so a
/// swap in between reached the door. Now the guard connects the inode it
/// checked: the stand-in must see ZERO connections, whatever the timing.
///
/// Deterministic in what it proves, whatever the scheduler does: the swapper
/// is live (both targets installed) before the first connect, every next
/// connect waits for at least one more swap, and the tracee keeps connecting
/// (at least `MIN`, at most `MAX`) until BOTH targets have been hit, then the
/// supervisor answers its next connect with `STOP`. A fixed 400 connects with
/// a free-running swapper failed in CI when the loaded host never scheduled
/// the swapper during the run (0 refused / 400 benign / 0 at the door, MR !37;
/// reproduced by looping the whole binary under load): a starved adversary,
/// never a connect at the door.
#[test]
#[ignore]
fn guard_wsl_check_survives_a_symlink_swap_race() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    const MIN: usize = 400;
    const MAX: usize = 50_000;
    // The supervisor's "you are done" answer to the tracee's next connect.
    const STOP: i32 = libc::ECANCELED;
    let dir = std::env::temp_dir().join(format!("mandu-net-guard-wslrace-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.to_string_lossy().to_string();
    let interop = format!("{d}/1_interop");
    let benign = format!("{d}/benign.sock");
    let link = format!("{d}/link.sock");
    let li = CountingListener::bind(&interop);
    let lb = CountingListener::bind(&benign);
    std::os::unix::fs::symlink(&benign, &link).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let swaps = Arc::new(AtomicUsize::new(0));
    let swapper = {
        let (stop, swaps, benign, interop, link, d) = (stop.clone(), swaps.clone(), benign.clone(), interop.clone(), link.clone(), d.clone());
        std::thread::spawn(move || {
            let tmp = format!("{d}/link.tmp");
            let mut flip = true;
            while !stop.load(Ordering::Relaxed) {
                let _ = std::fs::remove_file(&tmp);
                let _ = std::os::unix::fs::symlink(if flip { &interop } else { &benign }, &tmp);
                if std::fs::rename(&tmp, &link).is_ok() {
                    swaps.fetch_add(1, Ordering::SeqCst);
                }
                flip = !flip;
            }
        })
    };
    // Wait for the swapper to go live (the link has pointed at both targets)
    // until a deadline: past it the test fails, never passes vacuously.
    let wait_for_swaps = |past: usize| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while swaps.load(Ordering::SeqCst) <= past {
            assert!(std::time::Instant::now() < deadline, "the swapper thread made no progress for 30 s");
            std::thread::yield_now();
        }
        swaps.load(Ordering::SeqCst)
    };
    wait_for_swaps(1);

    let mut wsl = GuardConfig::new(Arc::new(GuardPolicy::default()), no_resolver());
    wsl.wsl = Some(WslGuard { interop_env: Some(interop.clone()), interop_id: None }.with_interop_identity(Some(identity(&interop))));

    // One tracee connecting until told to stop, each connect trapped and
    // handled here in turn.
    let (sup_sock, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe { libc::close(sup_sock) };
        let listener = match install_connect_filter_self() {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if send_fd(child_sock, listener).is_err() {
            unsafe {
                libc::close(listener);
                libc::_exit(EXIT_SETUP_FAIL)
            };
        }
        for _ in 0..=MAX {
            match child_unix_connect(&link) {
                STOP => unsafe { libc::_exit(0) },
                // The supervisor is gone (it panicked): no listener answers.
                libc::ENOSYS => break,
                _ => {}
            }
        }
        unsafe { libc::_exit(EXIT_UNEXPECTED) };
    }
    unsafe { libc::close(child_sock) };
    let Ok(listener) = recv_fd_from(sup_sock, child) else {
        stop.store(true, Ordering::Relaxed);
        join_within(swapper, wait_limit(), "the symlink swapper thread, after its stop flag").unwrap();
        let code = reap(child);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(code, Some(EXIT_NO_SECCOMP), "tracee failed to send its listener");
        eprintln!("SKIP: seccomp NEW_LISTENER denied");
        return;
    };
    let (mut refused, mut landed, mut other) = (0usize, 0usize, 0usize);
    let mut seen_swaps = swaps.load(Ordering::SeqCst);
    let mut n = 0usize;
    loop {
        let notif = recv_notif(listener).expect("NOTIF_RECV");
        if (n >= MIN && refused > 0 && landed > 0) || n >= MAX {
            fs_supervisor::kernel::respond_errno(listener, notif.id, STOP).expect("answer STOP");
            break;
        }
        match handle_connect_notif(listener, &wsl, &notif).expect("handle") {
            GuardOutcome::Refused { .. } => refused += 1,
            GuardOutcome::UnixSupervised { answered: 0 } => landed += 1,
            _ => other += 1,
        }
        n += 1;
        // The adversary moves before the next connect: a swapper the
        // scheduler starves cannot pin the link on one target.
        seen_swaps = wait_for_swaps(seen_swaps);
    }
    let code = reap(child);
    stop.store(true, Ordering::Relaxed);
    join_within(swapper, wait_limit(), "the symlink swapper thread, after its stop flag").unwrap();
    unsafe {
        libc::close(listener);
        libc::close(sup_sock);
    }
    let (at_door, at_benign) = (li.finish(), lb.finish());
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, Some(0));
    assert_eq!(at_door, 0, "a connect reached the interop stand-in ({refused} refused, {landed} landed, {other} other)");
    assert_eq!(at_benign, landed, "every supervised success is a benign connection");
    assert!(refused > 0 && landed > 0, "the swap must hit both targets for the race to be exercised ({refused}/{landed}/{other} in {n} connects)");
    eprintln!("WSL RACE PASS: {n} connects under a swapping link ({} swaps): {refused} refused, {landed} benign, {other} lookup errors, 0 at the door", swaps.load(Ordering::SeqCst));
}

/// A socket that is itself a secret (policy.yaml `ssh_agent`, learn-from-nono
/// §3.5) under the supervised connect: only a listed reader may connect, and
/// the check follows the INODE, so a HARDLINK to the socket (another name the
/// path-string check never matched) and a symlink are both refused for a
/// program that is not a reader, while an unrelated socket still connects.
/// No WSL config: the socket index alone turns supervision on.
#[test]
#[ignore]
fn guard_refuses_a_secret_socket_by_inode() {
    let dir = std::env::temp_dir().join(format!("mandu-net-guard-secsock-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.to_string_lossy().to_string();
    let agent = format!("{d}/agent.sock");
    let other = format!("{d}/other.sock");
    let (hard, link) = (format!("{d}/hard.sock"), format!("{d}/link.sock"));
    let la = CountingListener::bind(&agent);
    let lo = CountingListener::bind(&other);
    std::fs::hard_link(&agent, &hard).unwrap();
    std::os::unix::fs::symlink(&agent, &link).unwrap();

    let file: net_supervisor::secret_open::SecretPolicyFile =
        serde_json::from_str(&format!(r#"{{"sockets":[{{"path":"{agent}","label":"ssh-agent","readers":["ssh"]}}]}}"#)).unwrap();
    let mut cfg = GuardConfig::new(Arc::new(GuardPolicy::default()), no_resolver());
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::from_file(file)));

    let Some((outcome, child_exit)) = drive_one_connect(ConnectRecipe::Unix { path: other.clone() }, &cfg) else {
        let _ = std::fs::remove_dir_all(&dir);
        return; // SKIP
    };
    assert_eq!(outcome, GuardOutcome::UnixSupervised { answered: 0 }, "an unrelated socket connects");
    assert_eq!(child_exit, Some(EXIT_CONNECTED));
    for target in [&agent, &hard, &link] {
        let (outcome, child_exit) = drive_one_connect(ConnectRecipe::Unix { path: target.clone() }, &cfg).expect("seccomp worked above");
        assert!(matches!(outcome, GuardOutcome::PassedThrough { why } if why.starts_with("secret socket")), "{target}: {outcome:?}");
        assert_eq!(child_exit, Some(libc::EACCES), "{target}");
    }
    assert_eq!(la.finish(), 0, "no non-reader reached the secret socket");
    assert_eq!(lo.finish(), 1);
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("SECRET SOCKET PASS: the socket, a hardlink and a symlink refused to a non-reader; others connect");
}

/// The same leg for AF_VSOCK: refused under the WSL config before the kernel
/// sees it, passed through (the kernel answers) without it. SKIPs where the
/// host cannot open a vsock socket at all.
#[test]
#[ignore]
fn guard_refuses_vsock_on_wsl() {
    // CID 2 = the host; an arbitrary port nobody listens on.
    let recipe = || ConnectRecipe::Vsock { cid: 2, port: 50_123 };
    let plain = GuardConfig::new(Arc::new(GuardPolicy::default()), no_resolver());
    let Some((outcome, child_exit)) = drive_one_connect(recipe(), &plain) else { return /* SKIP */ };
    if child_exit == Some(EXIT_VSOCK_UNAVAILABLE) {
        eprintln!("SKIP: this host cannot open an AF_VSOCK socket (no vsock transport)");
        return;
    }
    // Off WSL the guard connects its own copy of the socket to the address
    // it read (exec-routing.md §7.5, 2026-10-01: never CONTINUE, which let a
    // thread rewrite the address); the kernel's answer is what comes back.
    assert!(matches!(outcome, GuardOutcome::OtherPerformed { answered } if answered != libc::EACCES), "control: {outcome:?}");
    assert_ne!(child_exit, Some(libc::EACCES), "control: the kernel, not the guard, answers");

    let mut wsl = GuardConfig::new(Arc::new(GuardPolicy::default()), no_resolver());
    wsl.wsl = Some(WslGuard::default());
    let (outcome, child_exit) = drive_one_connect(recipe(), &wsl).expect("seccomp worked above");
    assert!(matches!(outcome, GuardOutcome::Refused { .. }), "WSL: {outcome:?}");
    assert_eq!(child_exit, Some(libc::EACCES), "WSL: the vsock connect must fail EACCES");
    eprintln!("WSL VSOCK PASS: AF_VSOCK refused under the WSL config, left to the kernel without it");
}

// ── fd / process plumbing (mirrors fs-supervisor's kernel_integration harness) ──

fn last_err() -> String {
    std::io::Error::last_os_error().to_string()
}

/// In a tracee just forked from this multithreaded test process: close every
/// descriptor but stdio and `keep`. Without it the tracee holds whatever the
/// other tests' threads had open at the fork (their fixtures, their guards'
/// pins), and a tracee that becomes a holder has the guard narrow those files
/// as files it holds open for writing (plan 13 §9 R4 (b)): a protected file
/// of a concurrent test once went 0644 → 0600 that way. A launched agent
/// inherits nothing of the guard's.
fn close_inherited(keep: &[RawFd]) {
    let mut k: Vec<RawFd> = keep.iter().copied().filter(|f| *f >= 3).collect();
    k.sort_unstable();
    let mut from: u32 = 3;
    for f in k {
        if (f as u32) > from {
            // SAFETY: close_range on our own table; async-signal-safe after fork.
            unsafe { libc::syscall(libc::SYS_close_range, from, f as u32 - 1, 0u32) };
        }
        from = f as u32 + 1;
    }
    // SAFETY: as above.
    unsafe { libc::syscall(libc::SYS_close_range, from, u32::MAX, 0u32) };
}

/// The child's exit code (None: a signal ended it). In the test process the
/// wait has a deadline (support::reap_within: past it the test fails with
/// the child tree's state, killed); in a forked child it waits as long as
/// it takes, the test process's own deadline covering it.
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

/// Hand the listener to the supervisor by NUMBER (`write`): the guard's
/// filter traps `sendmsg`, and its supervisor is the one waiting for this
/// (guard_kernel::hand_listener).
fn send_fd(sock: RawFd, fd: RawFd) -> std::io::Result<()> {
    if net_supervisor::guard_kernel::hand_listener(sock, fd, true) {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The supervisor side: the listener, copied out of the child.
fn recv_fd(sock: RawFd) -> std::io::Result<RawFd> {
    net_supervisor::guard_kernel::receive_listener(sock).map(|(fd, _)| fd)
}

/// The harness's own deadlines (support/mod.rs): a wait that runs out fails
/// by name with the stuck tree's /proc state, and the child is killed and
/// reaped, never left; a joined thread past its limit fails the same way.
#[test]
fn a_wait_past_its_deadline_fails_by_name_kills_the_child_and_reports_its_state() {
    let msg = |e: Box<dyn std::any::Any + Send>| e.downcast_ref::<String>().cloned().unwrap_or_default();
    let mut child = std::process::Command::new("sleep").arg("30").spawn().expect("sleep");
    let pid = child.id() as i32;
    let t0 = std::time::Instant::now();
    let got = std::panic::catch_unwind(|| reap_within(pid, std::time::Duration::from_millis(300), "a sleep that outlives its wait"));
    let text = msg(got.err().expect("the wait ran out"));
    assert!(t0.elapsed() < std::time::Duration::from_secs(10), "it gave up near its limit");
    assert!(text.starts_with("STUCK: a sleep that outlives its wait: pid "), "{text}");
    assert!(text.contains(&format!("pid {pid} task {pid} sleep S wchan=")), "the stuck task's comm, state and wait channel: {text}");
    assert!(text.contains("syscall="), "{text}");
    // Reaped by the helper: no zombie, nothing left running.
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "the child is gone");
    let _ = child.try_wait();

    // A pipe nobody writes, while a child that should write it sleeps.
    let mut child = std::process::Command::new("sleep").arg("30").spawn().expect("sleep");
    let pid = child.id() as i32;
    let (r, w) = pipe();
    let got = std::panic::catch_unwind(|| readable_within(r, pid, std::time::Duration::from_millis(300), "a hand-over that never comes"));
    assert!(msg(got.expect_err("ran out")).starts_with("STUCK: a hand-over that never comes"));
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    let _ = child.try_wait();
    unsafe {
        libc::close(r);
        libc::close(w);
    }

    // A thread: named in the failure, left running (a thread cannot be killed).
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::Builder::new().name("slow-helper".into()).spawn(move || while !s2.load(std::sync::atomic::Ordering::Relaxed) { std::thread::sleep(std::time::Duration::from_millis(5)) }).unwrap();
    let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| join_within(h, std::time::Duration::from_millis(100), "a helper thread")));
    let text = msg(got.expect_err("ran out"));
    assert!(text.starts_with("STUCK: a helper thread: thread Some(\"slow-helper\")"), "{text}");
    assert!(text.contains("slow-helper"), "this process's threads listed: {text}");
    // StopOnDrop ends a loop on the flag however the scope ends.
    drop(StopOnDrop(stop.clone()));
    assert!(stop.load(std::sync::atomic::Ordering::Relaxed));
    // Within its limit the join returns what the thread did.
    assert_eq!(join_within(std::thread::spawn(|| 7), wait_limit(), "a quick thread").unwrap(), 7);
}

/// The deadlines with no one child to blame (support/mod.rs): a silent pipe,
/// a condition that never holds, each fails by name with this process's
/// tree; within the limit a pipe is read to its end. Nothing is killed.
#[test]
fn a_tree_wait_past_its_deadline_fails_by_name_and_reads_to_the_end_within_it() {
    let msg = |e: Box<dyn std::any::Any + Send>| e.downcast_ref::<String>().cloned().unwrap_or_default();
    let ms = std::time::Duration::from_millis;
    let (r, w) = pipe();
    let got = std::panic::catch_unwind(|| support::readable_within_tree(r, ms(300), "a report nobody writes"));
    let text = msg(got.expect_err("ran out"));
    assert!(text.starts_with(&format!("STUCK: a report nobody writes: descriptor {r} still not readable after")), "{text}");
    assert!(text.contains("  this process ("), "this process's threads listed: {text}");
    // Some bytes and no end: past its deadline (what it read goes with it);
    // then the rest and the end, read whole.
    unsafe { libc::write(w, b"part-one ".as_ptr() as *const libc::c_void, 9) };
    let got = std::panic::catch_unwind(|| support::read_to_end_within(r, ms(300), "a report cut off before its end"));
    assert!(msg(got.expect_err("no end yet")).starts_with("STUCK: a report cut off before its end"));
    unsafe {
        libc::write(w, b"part-two".as_ptr() as *const libc::c_void, 8);
        libc::close(w);
    }
    assert_eq!(support::read_to_end_within(r, wait_limit(), "a report"), b"part-two");
    unsafe { libc::close(r) };
    // A child's descriptor: read to its end as it exits.
    let mut child = std::process::Command::new("sh").args(["-c", "printf from-the-child"]).stdout(std::process::Stdio::piped()).spawn().expect("sh");
    use std::os::unix::io::AsRawFd;
    let out = child.stdout.take().unwrap();
    assert_eq!(support::read_to_end_from(out.as_raw_fd(), child.id() as i32, wait_limit(), "the child's output"), b"from-the-child");
    let _ = child.wait();
    // A polled condition.
    let got = std::panic::catch_unwind(|| support::until_within(ms(200), ms(10), "a file that never appears", || false));
    assert!(msg(got.expect_err("ran out")).starts_with("STUCK: a file that never appears: still not so after"));
    let mut n = 0;
    support::until_within(wait_limit(), ms(1), "a count reached", || {
        n += 1;
        n >= 3
    });
    assert_eq!(n, 3);
}

/// A [`support::Watchdog`] past its limit kills the descendants of its
/// process, so a wait inside code the test does not own returns, and the
/// guard fails the test by name. Run in a fresh process (this binary,
/// re-executed for `watchdog_child`): the kill takes every descendant of
/// its process, and the other tests of this file run beside it in this one.
#[test]
fn a_watchdog_past_its_limit_kills_the_tree_and_fails_by_name() {
    let t0 = std::time::Instant::now();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "watchdog_child", "--ignored", "--nocapture", "--test-threads=1"])
        .env("MANDU_TEST_WATCHDOG_CHILD", "1")
        .output()
        .expect("re-exec the test binary");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(t0.elapsed() < std::time::Duration::from_secs(60), "the watchdog fired near its limit: {text}");
    assert!(!out.status.success(), "the stuck call failed its test: {text}");
    assert!(text.contains("STUCK: a sleep that outlives its watchdog: still running after"), "{text}");
    assert!(text.contains(" sleep S wchan="), "the stuck child's comm, state and wait channel: {text}");
    assert!(text.contains("STUCK: a sleep that outlives its watchdog: ran past"), "the guard's drop failed the test: {text}");
    assert!(text.contains("the sleep ended by signal 9"), "the kill ended the wait: {text}");
}

/// The child of [`a_watchdog_past_its_limit_kills_the_tree_and_fails_by_name`]:
/// a no-op unless `MANDU_TEST_WATCHDOG_CHILD` is set.
#[test]
#[ignore]
fn watchdog_child() {
    if std::env::var_os("MANDU_TEST_WATCHDOG_CHILD").is_none() {
        return;
    }
    let _w = support::Watchdog::start(std::time::Duration::from_millis(300), "a sleep that outlives its watchdog");
    let mut sleep = std::process::Command::new("sleep").arg("30").spawn().expect("sleep");
    // A blocking wait, as a supervisor's own: only the kill ends it.
    let st = sleep.wait().expect("wait");
    use std::os::unix::process::ExitStatusExt;
    eprintln!("the sleep ended by signal {}", st.signal().unwrap_or(0));
}

/// `recv_fd` of the listener `child` hands over, waited for at most
/// `wait_limit()` (a child stuck before it sends fails the test by name).
fn recv_fd_from(sock: RawFd, child: i32) -> std::io::Result<RawFd> {
    readable_within(sock, child, wait_limit(), "waiting for the tracee to hand over its seccomp listener");
    recv_fd(sock)
}

// ── git object-store twins (launcher git-object-twins.ts) ────────────────────

/// Child: what `path` opens, as a report field: the first bytes, or `E<errno>`.
fn child_probe(path: &std::path::Path) -> String {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    match child_read_at(c.as_ptr() as *const u8) {
        Ok(s) => s.trim().to_string(),
        Err(e) => format!("E{e}"),
    }
}

#[test]
#[ignore]
fn object_store_twins_serve_sanitized_packs_deny_exposers_and_hide_shadow_repos() {
    // The guard-only posture (no bind): a pack registered `object` opens as
    // its sanitized twin with no arbiter at all, a loose copy registered
    // `deny` is EACCES, anything under a deny prefix is EACCES, and a file
    // beside them reads as it is. The sanitized twin sits in the Mandu home's
    // cache, under a deny prefix (on-disk-layout.md §4): served through the
    // pack's own path, refused by its own.
    let tree = OpenTree::new("gitobj");
    let objects = tree.dir.join("repo/dotgit/objects");
    std::fs::create_dir_all(objects.join("pack")).unwrap();
    std::fs::create_dir_all(objects.join("ab")).unwrap();
    let pack = objects.join("pack/pack-1.pack");
    let mhome = tree.dir.join("home/.mandu");
    std::fs::create_dir_all(mhome.join("cache/object-twins")).unwrap();
    let sanitized = mhome.join("cache/object-twins/p.pack");
    let loose = objects.join("ab/cdef");
    let shadow = tree.dir.join("view-state/workspaces");
    std::fs::create_dir_all(shadow.join("ws-1/repo")).unwrap();
    let shadow_file = shadow.join("ws-1/repo/HEAD");
    let beside = tree.dir.join("repo/README");
    std::fs::write(&pack, "REAL-PACK-WITH-SECRET\n").unwrap();
    std::fs::write(&sanitized, "SANITIZED-PACK\n").unwrap();
    std::fs::write(&loose, "REAL-LOOSE-SECRET\n").unwrap();
    std::fs::write(&shadow_file, "REAL-SHADOW\n").unwrap();
    std::fs::write(&beside, "README-BYTES\n").unwrap();
    let deny = tree.dir.join("denied");
    std::fs::write(&deny, "").unwrap();
    std::fs::write(
        &tree.policy,
        format!(
            r#"{{"agentExe":"","secrets":[
              {{"path":"{}","twin":"{}","level":"no-model","kind":"object"}},
              {{"path":"{}","twin":"{}","level":"no-model","kind":"deny"}}],
              "denyPrefixes":["{}","{}"]}}"#,
            pack.display(), sanitized.display(), loose.display(), deny.display(), shadow.display(), mhome.display(),
        ),
    )
    .unwrap();
    let report = tree.dir.join("report.txt");
    let (p, l, s, sd, b, tw) = (pack.clone(), loose.clone(), shadow_file.clone(), shadow.clone(), beside.clone(), sanitized.clone());
    let rep = report.clone();
    let code = run_guarded(&tree, move || {
        let line = format!("{}|{}|{}|{}|{}|{}", child_probe(&p), child_probe(&l), child_probe(&s), child_probe(&sd), child_probe(&b), child_probe(&tw));
        let _ = std::fs::write(&rep, line);
        0
    });
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    assert_eq!(code, Some(0));
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    let parts: Vec<&str> = seen.split('|').collect();
    assert_eq!(parts.len(), 6, "report: {seen}");
    assert_eq!(parts[0], "SANITIZED-PACK", "the pack opens as its sanitized twin, cached under a deny prefix: {seen}");
    assert_eq!(parts[1], format!("E{}", libc::EACCES), "the loose copy is refused: {seen}");
    assert_eq!(parts[2], format!("E{}", libc::EACCES), "a file under the shadow repositories is refused: {seen}");
    assert_eq!(parts[3], format!("E{}", libc::EACCES), "the shadow directory itself does not open: {seen}");
    assert_eq!(parts[4], "README-BYTES", "a file beside them reads as it is: {seen}");
    assert_eq!(parts[5], format!("E{}", libc::EACCES), "the twin cache by its own path is refused: {seen}");
    assert!(!seen.contains("REAL-"), "no real byte of the pack, the loose copy or the shadow repo: {seen}");
    eprintln!("GIT OBJECT TWINS PASS: {seen}");
}

#[test]
#[ignore]
fn own_stores_of_originals_are_refused_by_file_and_by_dir() {
    // docs/design/architecture/on-disk-layout.md phase 1: the launcher names Mandu's own
    // stores of originals as deny prefixes (launcher ownStoresHidden): the
    // symbol DB and its companions as FILE paths, the event log as a
    // directory, the egress CA key as a file. A prefix matches whole path
    // components, so the certificate beside the key and a `mandu.dbx` beside
    // the DB still read; any spelling (a symlink) of a denied file is refused.
    let tree = OpenTree::new("ownstores");
    let home = tree.dir.join("home/.mandu");
    let events = tree.dir.join("state/mandu/events");
    let ca = tree.dir.join("scope/egress-mitm-ca");
    for d in [&home, &events, &ca] {
        std::fs::create_dir_all(d).unwrap();
    }
    let db = home.join("mandu.db");
    let wal = home.join("mandu.db-wal");
    let beside_db = home.join("mandu.dbx");
    let record = events.join("s1.ndjson");
    let key = ca.join("mandu-egress-ca.key");
    let cert = ca.join("mandu-egress-ca.pem");
    let link = tree.dir.join("db-link");
    std::fs::write(&db, "REAL-SYMBOL-TABLE\n").unwrap();
    std::fs::write(&wal, "REAL-WAL-PAGE\n").unwrap();
    std::fs::write(&beside_db, "BESIDE-DB\n").unwrap();
    std::fs::write(&record, "REAL-EVENT-ORIGINAL\n").unwrap();
    std::fs::write(&key, "REAL-CA-KEY\n").unwrap();
    std::fs::write(&cert, "CA-CERT\n").unwrap();
    std::os::unix::fs::symlink(&db, &link).unwrap();
    std::fs::write(
        &tree.policy,
        format!(
            r#"{{"agentExe":"","secrets":[],"denyPrefixes":["{}","{}","{}","{}"]}}"#,
            db.display(), wal.display(), events.display(), key.display(),
        ),
    )
    .unwrap();
    let report = tree.dir.join("report.txt");
    let probes = [db.clone(), wal.clone(), link.clone(), record.clone(), events.clone(), key.clone(), cert.clone(), beside_db.clone()];
    let rep = report.clone();
    let code = run_guarded(&tree, move || {
        let line: Vec<String> = probes.iter().map(|p| child_probe(p)).collect();
        let _ = std::fs::write(&rep, line.join("|"));
        0
    });
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    assert_eq!(code, Some(0));
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    let parts: Vec<&str> = seen.split('|').collect();
    assert_eq!(parts.len(), 8, "report: {seen}");
    let denied = format!("E{}", libc::EACCES);
    for (i, what) in ["the symbol DB", "its WAL", "a symlink to the DB", "an event record", "the event dir", "the CA key"].iter().enumerate() {
        assert_eq!(parts[i], denied, "{what} is refused: {seen}");
    }
    assert_eq!(parts[6], "CA-CERT", "the certificate beside the key reads: {seen}");
    assert_eq!(parts[7], "BESIDE-DB", "a prefix matches whole components, not `mandu.db*`: {seen}");
    assert!(!seen.contains("REAL-"), "no original from Mandu's own stores: {seen}");
    eprintln!("OWN STORES PASS: {seen}");
}

#[test]
#[ignore]
fn the_whole_home_is_hidden_and_unwritable_but_its_carve_out_is_the_agents() {
    // on-disk-layout.md §4: the launcher names the whole Mandu home as ONE
    // deny prefix and ONE write-protect entry, with the integrity modes'
    // AgentView carved out of both (launcher ownStoresHidden / ownFiles). The
    // agent can neither read a stray file at the top of the home (the
    // pre-one-home `mandu.db`), nor create a new file there or under
    // `state/`, nor read the object-twin cache by its own path; inside the
    // carve-out it reads, creates and writes as in any directory.
    let dir = std::env::temp_dir().join(format!("mandu-onehome-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = dir.join("home/.mandu");
    let state = home.join("state");
    let av = state.join("workspaces/ws-1/agentview");
    let twins = home.join("cache/object-twins/k");
    for d in [&av, &twins] {
        std::fs::create_dir_all(d).unwrap();
    }
    let stray = home.join("mandu.db");
    let pack = twins.join("pack-1.pack");
    let in_av = av.join("main.rs");
    std::fs::write(&stray, "REAL-OLD-SYMBOL-TABLE\n").unwrap();
    std::fs::write(&pack, "REAL-TWIN-CACHE\n").unwrap();
    std::fs::write(&in_av, "AGENTVIEW-BYTES\n").unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"agentExe":"","secrets":[],"denyPrefixes":["{h}"],"denyExcept":["{a}"],
              "writeProtect":[{{"path":"{h}","answer":"deny","label":"Mandu's own files","except":["{a}"]}}]}}"#,
            h = home.display(),
            a = av.display(),
        ),
    )
    .unwrap();
    let (stray_c, pack_c, in_av_c) = (cstr(&stray), cstr(&pack), cstr(&in_av));
    let (top_new, state_new, av_new) = (home.join("new-top"), state.join("new-state"), av.join("new.rs"));
    let (top_c, state_c, av_new_c) = (cstr(&top_new), cstr(&state_new), cstr(&av_new));
    let got = run_guarded_protect(&policy, || unsafe {
        let checks: Vec<(i32, i32)> = vec![
            (errno_of_fd(libc::open(stray_c.as_ptr(), libc::O_RDONLY)), libc::EACCES),
            (errno_of_fd(libc::open(pack_c.as_ptr(), libc::O_RDONLY)), libc::EACCES),
            (errno_of_fd(libc::open(top_c.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644)), libc::EACCES),
            (errno_of_fd(libc::open(state_c.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644)), libc::EACCES),
            (errno_of_fd(libc::open(in_av_c.as_ptr(), libc::O_RDONLY)), 0),
            (errno_of_fd(libc::open(in_av_c.as_ptr(), libc::O_WRONLY | libc::O_APPEND)), 0),
            (errno_of_fd(libc::open(av_new_c.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644)), 0),
        ];
        match checks.iter().position(|(got, want)| got != want) {
            None => 0,
            Some(i) => 10 + i as i32,
        }
    });
    let Some(code) = got else {
        eprintln!("SKIP: seccomp NEW_LISTENER unavailable");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let created_in_home = top_new.exists() || state_new.exists();
    let created_in_av = av_new.exists();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, Some(0), "check #{} (10 + index) got an unexpected answer", code.unwrap_or(-1) - 10);
    assert!(!created_in_home, "a name was created in the home outside the carve-out");
    assert!(created_in_av, "the carve-out is the agent's to write");
    eprintln!("ONE HOME PASS");
}

/// `io_uring_setup(1, &params)` in this process: 0 = a ring was created
/// (closed again), else the errno.
fn io_uring_setup_errno() -> i32 {
    let mut params = [0u8; 120]; // struct io_uring_params
    let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
    if fd >= 0 {
        unsafe { libc::close(fd as i32) };
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

/// sandbox-security-review-2026-09-28 finding 5: under the plain connect guard
/// (no secret policy, the `injection` mode's posture) io_uring is refused, so
/// its CONNECT op cannot go around the connect trap. Needs no supervisor: the
/// filter refuses the call itself.
#[test]
#[ignore]
fn guard_refuses_io_uring_without_a_secret_policy() {
    if io_uring_setup_errno() != 0 {
        eprintln!("SKIP: io_uring is unavailable here before the guard (disabled by sysctl or kernel)");
        return;
    }
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let traps = net_supervisor::guard_kernel::FilterTraps::default();
        let listener = match net_supervisor::guard_kernel::install_guard_filter_self(traps) {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        unsafe { libc::close(listener) };
        let e = io_uring_setup_errno();
        unsafe { libc::_exit(if e == libc::EPERM { 0 } else if e == 0 { 10 } else { 11 }) };
    }
    let st = reap_within(child, wait_limit(), "waiting for the io_uring probe child").status;
    assert!(libc::WIFEXITED(st), "child did not exit normally");
    let code = libc::WEXITSTATUS(st);
    if code == EXIT_NO_SECCOMP {
        eprintln!("SKIP: seccomp NEW_LISTENER unavailable");
        return;
    }
    assert_eq!(code, 0, "io_uring under the guard: 10 = a ring was created, 11 = another errno");
}

// ── sandbox-security-review-2026-09-28 findings 2 and 6: write protection ────

/// `run_guarded`, with the delete / write family trapped too and the policy
/// file at `policy`.
fn run_guarded_protect(policy: &std::path::Path, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    run_guarded_protect_setup(policy, || None, body)
}

/// `run_guarded_protect` with `setup` run in the child BEFORE the filter
/// goes on (a user namespace of its own); `Some(code)` from it exits the
/// child with that code instead.
fn run_guarded_protect_setup(policy: &std::path::Path, setup: impl FnOnce() -> Option<i32>, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    let (sup_sock, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        close_inherited(&[child_sock]);
        if let Some(code) = setup() {
            unsafe { libc::_exit(code) };
        }
        let traps = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, protect: true, ..Default::default() };
        let listener = match net_supervisor::guard_kernel::install_guard_filter_self(traps) {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if send_fd(child_sock, listener).is_err() {
            unsafe {
                libc::close(listener);
                libc::_exit(EXIT_SETUP_FAIL)
            };
        }
        unsafe { libc::close(listener) };
        let code = body();
        unsafe { libc::_exit(code) };
    }
    unsafe { libc::close(child_sock) };
    let listener = match recv_fd_from(sup_sock, child) {
        Ok(fd) => fd,
        Err(_) => {
            // No listener: seccomp is unavailable (SKIP), or `setup` exited
            // the child with its own code (the caller reads it).
            let code = reap(child);
            unsafe { libc::close(sup_sock) };
            return if code == Some(EXIT_NO_SECCOMP) { None } else { Some(code) };
        }
    };
    let mut cfg = cfg("tcp:10.9.9.9/32:9");
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(policy).unwrap()));
    let server = std::thread::spawn(move || {
        let _ = net_supervisor::guard_kernel::run_guard_supervisor(listener, cfg);
        unsafe { libc::close(listener) };
    });
    let code = reap(child);
    let _ = join_within(server, wait_limit(), "the guard supervisor (run_guard_supervisor), after its tracee exited");
    unsafe { libc::close(sup_sock) };
    Some(code)
}

/// The write-open race (sandbox review, finding 6's residual): a write open
/// was judged by path and then continued, so a symlink swapped in between
/// led the kernel's own resolution to a protected file. Now the guard
/// performs the open and judges the file it resolved, pinned, before any
/// O_TRUNC. A thread swaps `sw` between a free file and a protected one
/// (atomic renames) while the main thread opens `sw` O_WRONLY|O_TRUNC and
/// writes, many times: the protected file never changes.
#[test]
#[ignore]
fn a_symlink_swapped_during_a_write_open_never_reaches_a_protected_file() {
    let dir = std::env::temp_dir().join(format!("mandu-wrace-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let own = dir.join("mandu");
    std::fs::create_dir_all(&own).unwrap();
    let law = own.join("policy.yaml");
    std::fs::write(&law, "law: strict\n").unwrap();
    let free = dir.join("free.txt");
    std::fs::write(&free, "").unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(&policy, format!(r#"{{"agentExe":"","writeProtect":[{{"path":"{}","answer":"deny","label":"Mandu's own files"}}]}}"#, own.display())).unwrap();
    let (sw, a, b) = (dir.join("sw"), dir.join("to-free"), dir.join("to-law"));
    let (law2, free2, sw2, a2, b2) = (law.clone(), free.clone(), sw.clone(), a.clone(), b.clone());
    let got = run_guarded_protect(&policy, move || {
        std::os::unix::fs::symlink(&free2, &sw2).unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flipper = {
            let stop = stop.clone();
            let (sw, a, b, free, law) = (sw2.clone(), a2.clone(), b2.clone(), free2.clone(), law2.clone());
            std::thread::spawn(move || {
                let mut n = 0u32;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let (tmp, to) = if n % 2 == 0 { (&b, &law) } else { (&a, &free) };
                    let _ = std::fs::remove_file(tmp);
                    let _ = std::os::unix::fs::symlink(to, tmp);
                    let _ = std::fs::rename(tmp, &sw);
                    n += 1;
                }
            })
        };
        let c = cstr(&sw2);
        let mut opened = 0;
        for _ in 0..400 {
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_TRUNC) };
            if fd >= 0 {
                opened += 1;
                unsafe { libc::write(fd, b"PWNED\n".as_ptr() as *const libc::c_void, 6) };
                unsafe { libc::close(fd) };
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = flipper.join();
        // Some opens must have landed on the free file (the test raced at all).
        if opened == 0 { 20 } else { 0 }
    });
    let law_after = std::fs::read_to_string(&law).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else {
        eprintln!("SKIP: seccomp NEW_LISTENER unavailable");
        return;
    };
    assert_eq!(law_after, "law: strict\n", "a swapped symlink led a write open to the protected file");
    assert_eq!(code, Some(0), "no write open landed at all (the race did not run)");
}

/// A write open of a registered secret is judged before O_TRUNC takes
/// effect: with no bind layer (the guard alone serves the twins),
/// `O_RDWR|O_TRUNC` of the real path used to truncate the real file in the
/// guard's own open, before the lookup that then served the twin.
#[test]
#[ignore]
fn a_truncating_open_of_a_secret_never_truncates_the_real_file() {
    let tree = OpenTree::new("trunc");
    let (secret, report) = (tree.secret.clone(), tree.dir.join("report.txt"));
    let code = run_guarded(&tree, || {
        let c = cstr(&secret);
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_TRUNC) };
        let _ = std::fs::write(&report, format!("fd={fd}\n"));
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        0
    });
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    assert_eq!(code, Some(0));
    assert_eq!(std::fs::read_to_string(&tree.secret).unwrap(), "REAL-SECRET-BYTES\n", "the real secret was truncated ({})", std::fs::read_to_string(&report).unwrap_or_default());
}

/// The same with a READ-ONLY truncating open (`O_RDONLY|O_TRUNC`, which
/// Linux truncates when the opener may write): the guard's own open of the
/// real path, served the twin afterwards, used to keep the `O_TRUNC` (only a
/// writable access mode held it back) and empty the real file.
#[test]
#[ignore]
fn a_read_only_truncating_open_of_a_secret_never_truncates_the_real_file() {
    let tree = OpenTree::new("rotrunc");
    let (secret, decoy, report) = (tree.secret.clone(), tree.decoy.clone(), tree.dir.join("report.txt"));
    let code = run_guarded(&tree, || {
        let fd = unsafe { libc::open(cstr(&secret).as_ptr(), libc::O_RDONLY | libc::O_TRUNC) };
        // The control: a file that is no secret is truncated as the kernel would.
        let dfd = unsafe { libc::open(cstr(&decoy).as_ptr(), libc::O_RDONLY | libc::O_TRUNC) };
        let _ = std::fs::write(&report, format!("fd={fd} decoy={dfd}\n"));
        for f in [fd, dfd] {
            if f >= 0 {
                unsafe { libc::close(f) };
            }
        }
        0
    });
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    assert_eq!(code, Some(0));
    let got = std::fs::read_to_string(&report).unwrap_or_default();
    assert_eq!(std::fs::read_to_string(&tree.secret).unwrap(), "REAL-SECRET-BYTES\n", "the real secret was truncated by a read-only open ({got})");
    assert_eq!(std::fs::read_to_string(&tree.decoy).unwrap(), "", "a file that is no secret is truncated as the kernel would ({got})");
}

/// Child: what the descriptors of `secret` NAME and what they read — an
/// `O_PATH` open (Bun's `realpathSync`: `O_PATH` + `readlink
/// /proc/self/fd/N`), a re-open of it through `/proc/self/fd`, and a plain
/// read open, as Claude Code's Read tool compares them.
fn probe_names(secret: &std::path::Path, report: &std::path::Path) -> i32 {
    let c = cstr(secret);
    let name_of = |fd: i32| std::fs::read_link(format!("/proc/self/fd/{fd}")).map(|p| p.display().to_string()).unwrap_or_default();
    let read_all = |fd: i32| -> String {
        let mut b = [0u8; 64];
        let n = unsafe { libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, b.len()) };
        String::from_utf8_lossy(&b[..n.max(0) as usize]).trim_end().to_string()
    };
    let mut lines = Vec::new();
    let pfd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_PATH) };
    if pfd < 0 {
        let _ = std::fs::write(report, format!("O_PATH open failed: {}", std::io::Error::last_os_error()));
        return 1;
    }
    lines.push(format!("opath_named={}", name_of(pfd)));
    let again = cstr(std::path::Path::new(&format!("/proc/self/fd/{pfd}")));
    let rfd = unsafe { libc::open(again.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    lines.push(format!("reopen={}", if rfd >= 0 { read_all(rfd) } else { format!("errno {}", std::io::Error::last_os_error()) }));
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd >= 0 {
        lines.push(format!("read_named={}", name_of(fd)));
        lines.push(format!("read={}", read_all(fd)));
    } else {
        lines.push("read=failed".into());
    }
    let _ = std::fs::write(report, lines.join("\n") + "\n");
    0
}

/// Differential-interactive.md §20, the guard alone (no bind): every
/// descriptor of the secret names the SAME path (the twin's: nothing else
/// can be named without a mount), so a program that checks a path and then
/// the descriptor it opened (Claude Code's Read tool) sees one file; every
/// read, a re-open of the `O_PATH` descriptor included, is the twin.
#[test]
#[ignore]
fn every_descriptor_of_a_secret_names_one_path_and_reads_the_twin() {
    let tree = OpenTree::new("names");
    let (secret, report) = (tree.secret.clone(), tree.dir.join("report.txt"));
    let code = run_guarded(&tree, || probe_names(&secret, &report));
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let got = std::fs::read_to_string(&report).unwrap_or_default();
    assert_eq!(code, Some(0), "{got}");
    assert!(!got.contains("REAL-SECRET"), "a descriptor of the secret led to the real bytes: {got}");
    let twin = tree.dir.join("twin.txt");
    assert!(
        got.contains(&format!("opath_named={}\n", twin.display())) && got.contains(&format!("read_named={}\n", twin.display())),
        "O_PATH and read descriptors must name one path: {got}"
    );
    assert!(got.contains("reopen=TWIN-PLACEHOLDER\n") && got.contains("read=TWIN-PLACEHOLDER\n"), "reads must get the twin: {got}");
}

/// mandu.md §2.x, a WEDGED arbiter (connected, never answering) behind the
/// guard's reports: an open of a registered secret is asked about, the
/// question gives up at the client's deadline, and the open gets the twin,
/// the guard's "unreachable" answer, in bounded time. Before 2026-10-17 the
/// client had no deadline: the tracee stayed suspended in its open for good.
///
/// The SECOND open is the one timed. A binary's first open of a secret also
/// pays the guard's one reading of that binary (its sha256 and the content
/// scan, once per inode: `reader_identity::IdentityCtx`), which has nothing
/// to do with the arbiter and, for this 60+ MB test binary read by every
/// guard of the parallel kernel lane at once, took 3.0 to 4.4 s in CI
/// (2026-10-17, six runs, each with ONE `decideSecretOpen` asked). The
/// second open finds that reading cached, so its time is the question's:
/// at least the deadline (it was asked, and waited), well under ten of them.
#[test]
#[ignore]
fn a_wedged_arbiter_gives_an_open_of_a_secret_its_twin_at_the_deadline() {
    let tree = OpenTree::new("wedged");
    let (secret, report) = (tree.secret.clone(), tree.dir.join("report.txt"));
    let arbiter = mandu_arbiter::mock::StallingArbiter::wedged().leak();
    let limit = std::time::Duration::from_millis(300);
    let sock = arbiter.socket_path.clone();
    let code = run_guarded_cfg(
        &tree,
        move |cfg| {
            let c = mandu_arbiter::ArbiterClient::new(&sock).with_io_timeout(Some(limit));
            cfg.emitter = Some(Arc::new(std::sync::Mutex::new(c)));
        },
        || {
            let c = cstr(&secret);
            let mut lines = String::new();
            for name in ["first", "second"] {
                let t0 = std::time::Instant::now();
                let got = child_read_at(c.as_ptr() as *const u8);
                let ms = t0.elapsed().as_millis();
                lines.push_str(&format!("{name}={got:?} ms={ms}\n"));
            }
            let _ = std::fs::write(&report, lines);
            0
        },
    );
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let got = std::fs::read_to_string(&report).unwrap_or_default();
    assert_eq!(code, Some(0), "{got}");
    assert!(!got.contains("REAL-SECRET"), "a wedged arbiter let the real bytes through: {got}");
    assert_eq!(got.matches("TWIN-PLACEHOLDER").count(), 2, "each open must get the twin: {got}");
    // The mock reads a request on a thread of its own, which a loaded guest
    // may run after the client gave up (one CI run, 2026-10-17, found none
    // recorded right after the child was reaped): wait for both, bounded.
    support::until_within(std::time::Duration::from_secs(30), std::time::Duration::from_millis(20), "the mock reading both asks", || arbiter.asked("decideSecretOpen") >= 2);
    let asks: Vec<u64> = arbiter.requests().into_iter().filter(|(_, op)| op == "decideSecretOpen").map(|(conn, _)| conn).collect();
    assert_eq!(asks.len(), 2, "one ask per open: {:?}", arbiter.requests());
    assert_ne!(asks[0], asks[1], "the connection a question expired on is dropped, never reused: {:?}", arbiter.requests());
    let second = got.lines().find(|l| l.starts_with("second=")).unwrap_or_default();
    let ms: u128 = second.rsplit("ms=").next().and_then(|m| m.trim().parse().ok()).unwrap_or(u128::MAX);
    assert!(ms >= limit.as_millis(), "the second open was answered before the deadline, so not by the wedged question: {got}");
    // One wedged question costs one deadline; a handful at most.
    assert!(ms < limit.as_millis() * 10, "the second open waited {ms} ms: {got} ({:?})", arbiter.requests());
}

/// Differential-interactive.md §20, the bind posture (the twin mounted over
/// the secret in the agent's own mount namespace, as the launcher's wrap
/// does): the path a program resolves a labelled file to, and the name of
/// the descriptor it reads, are the file's OWN path, never Mandu's twin
/// file. Bun resolves a path with an `O_PATH` open and `readlink`, and while
/// the guard answered with the twin opened by its own path Claude Code's
/// permission dialog offered "allow access to `<scope>/secret-twins`". The
/// confinement is unchanged: every read is the twin, never the bytes.
#[test]
#[ignore]
fn under_the_bind_a_secret_is_named_by_its_own_path_and_reads_the_twin() {
    let tree = OpenTree::new("bindnames");
    let (secret, report) = (tree.secret.clone(), tree.dir.join("report.txt"));
    let twin = tree.dir.join("twin.txt");
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let (s2, t2) = (secret.clone(), twin.clone());
    // The agent's namespace: a user + mount namespace with the twin bound
    // over the secret (bwrap's `--bind <twin> <secret>`), made before the
    // filter goes on. Where user namespaces are barred the child exits as
    // if seccomp were missing: the test SKIPs.
    let setup = move || -> Option<i32> {
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            return Some(EXIT_NO_SECCOMP);
        }
        let maps = std::fs::write("/proc/self/setgroups", "deny").is_ok()
            && std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).is_ok()
            && std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).is_ok();
        let root = cstr(std::path::Path::new("/"));
        let (src, dst) = (cstr(&t2), cstr(&s2));
        // SAFETY: NUL-terminated paths; mounts in the child's own namespace.
        let mounted = maps
            && unsafe {
                libc::mount(std::ptr::null(), root.as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) == 0
                    && libc::mount(src.as_ptr(), dst.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) == 0
            };
        if mounted { None } else { Some(EXIT_NO_SECCOMP) }
    };
    let code = run_guarded_setup(&tree, |_| {}, setup, || probe_names(&secret, &report));
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER or an unprivileged mount namespace unavailable here"); return };
    let got = std::fs::read_to_string(&report).unwrap_or_default();
    assert_eq!(code, Some(0), "{got}");
    assert!(!got.contains("REAL-SECRET"), "a descriptor of the secret led to the real bytes: {got}");
    assert!(got.contains(&format!("opath_named={}\n", tree.secret.display())), "the O_PATH descriptor must name the secret's own path: {got}");
    assert!(got.contains(&format!("read_named={}\n", tree.secret.display())), "the read descriptor must name the secret's own path: {got}");
    assert!(!got.contains("twin.txt"), "an agent-visible path names Mandu's twin file: {got}");
    assert!(got.contains("reopen=TWIN-PLACEHOLDER\n") && got.contains("read=TWIN-PLACEHOLDER\n"), "reads must get the twin: {got}");
}

// ── O_PATH opens: the kernel's own answer, and nothing of a secret ──────────

/// Drop every capability from this process's sets (root in a user namespace,
/// the kernel runner's posture, would otherwise read a search-only
/// directory through `CAP_DAC_READ_SEARCH`); a no-op for a plain uid.
fn drop_all_caps() {
    #[repr(C)]
    struct Hdr {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let hdr = Hdr { version: 0x2008_0522, pid: 0 };
    let data = [Data { effective: 0, permitted: 0, inheritable: 0 }, Data { effective: 0, permitted: 0, inheritable: 0 }];
    // SAFETY: capset with a v3 header and two data words, our own process.
    unsafe { libc::syscall(libc::SYS_capset, &hdr as *const Hdr, data.as_ptr()) };
}

/// The targets of `probe_o_path`: a plain file, a file with no read bit, a
/// FIFO, a Unix socket, a symlink (opened `O_NOFOLLOW`: the link itself), a
/// search-only directory and a file beneath it, `/dev/null` and procfs
/// paths. Made by the test process; the listener keeps the socket bound.
struct OPathTargets {
    dir: std::path::PathBuf,
    _sock: std::os::unix::net::UnixListener,
}

impl OPathTargets {
    fn new(dir: &std::path::Path) -> OPathTargets {
        use std::os::unix::fs::PermissionsExt;
        let d = dir.join("opath");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("plain.txt"), "PLAIN-BYTES\n").unwrap();
        std::fs::write(d.join("noread.txt"), "NOREAD-BYTES\n").unwrap();
        std::fs::set_permissions(d.join("noread.txt"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let fifo = cstr(&d.join("fifo"));
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let sock = std::os::unix::net::UnixListener::bind(d.join("sock")).unwrap();
        std::os::unix::fs::symlink("plain.txt", d.join("link")).unwrap();
        std::fs::create_dir_all(d.join("xonly")).unwrap();
        std::fs::write(d.join("xonly/inner.txt"), "INNER-BYTES\n").unwrap();
        std::fs::set_permissions(d.join("xonly"), std::fs::Permissions::from_mode(0o311)).unwrap();
        OPathTargets { dir: d, _sock: sock }
    }
}

impl Drop for OPathTargets {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(self.dir.join("xonly"), std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Child: every `O_PATH` open of `OPathTargets` by `open`, `openat` (from a
/// directory descriptor for a relative name) and `openat2`, one line each:
/// the errno, or that it opened, whether the descriptor is `O_PATH`, the
/// file type it names, its name (the directory and this pid spelled
/// generically, so two processes' reports compare), what `read` on it
/// answers, and a `*at` use of it (`fstatat(fd, "")`, and for a directory a
/// name beneath it). The kernel's own answers, without a guard, are the
/// oracle the guarded run is compared with.
fn probe_o_path(dir: &std::path::Path, report: &std::path::Path) -> i32 {
    drop_all_caps();
    #[repr(C)]
    struct How {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let me = unsafe { libc::getpid() };
    let generic = |s: String| s.replace(&dir.display().to_string(), "<dir>").replace(&format!("/proc/{me}"), "/proc/<me>");
    let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
    let describe = |fd: i32| -> String {
        if fd < 0 {
            return format!("errno {}", errno());
        }
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let empty = unsafe { libc::fstatat(fd, b"\0".as_ptr() as *const libc::c_char, &mut st, libc::AT_EMPTY_PATH) };
        let kind = match st.st_mode & libc::S_IFMT {
            libc::S_IFREG => "file",
            libc::S_IFDIR => "dir",
            libc::S_IFIFO => "fifo",
            libc::S_IFCHR => "chr",
            libc::S_IFSOCK => "sock",
            libc::S_IFLNK => "link",
            _ => "other",
        };
        let name = std::fs::read_link(format!("/proc/self/fd/{fd}")).map(|p| generic(p.display().to_string())).unwrap_or_default();
        let mut b = [0u8; 1];
        let n = unsafe { libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, 1) };
        let read = if n < 0 { format!("errno {}", errno()) } else { "bytes".into() };
        let beneath = if kind == "dir" {
            let r = unsafe { libc::fstatat(fd, b"inner.txt\0".as_ptr() as *const libc::c_char, &mut st, libc::AT_SYMLINK_NOFOLLOW) };
            format!(" inner={}", if r == 0 { "0".into() } else { format!("errno {}", errno()) })
        } else {
            String::new()
        };
        let cloexec = unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC != 0;
        unsafe { libc::close(fd) };
        format!("opened o_path={} type={kind} name={name} read={read} fstat_empty={empty} cloexec={cloexec}{beneath}", fl >= 0 && fl & libc::O_PATH != 0)
    };
    let dfd = unsafe { libc::open(cstr(dir).as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if dfd < 0 {
        let _ = std::fs::write(report, format!("the directory: errno {}", errno()));
        return 1;
    }
    let targets: [(&str, i32); 11] = [
        ("plain.txt", 0),
        ("noread.txt", 0),
        ("fifo", 0),
        ("sock", 0),
        ("link", libc::O_NOFOLLOW),
        ("xonly", 0),
        ("xonly", libc::O_DIRECTORY),
        ("xonly/inner.txt", 0),
        ("/dev/null", 0),
        ("/proc/self/status", 0),
        ("/proc/self", libc::O_DIRECTORY),
    ];
    let mut lines = Vec::new();
    for (name, extra) in targets {
        let flags = libc::O_PATH | libc::O_CLOEXEC | extra;
        let (abs, at) = if name.starts_with('/') { (name.to_string(), libc::AT_FDCWD) } else { (format!("{}/{name}", dir.display()), dfd) };
        let c_abs = std::ffi::CString::new(abs.clone()).unwrap();
        let c_rel = std::ffi::CString::new(if at == dfd { name.to_string() } else { abs.clone() }).unwrap();
        let fd = unsafe { libc::open(c_abs.as_ptr(), flags) };
        lines.push(format!("open {name} {extra:#o}: {}", describe(fd)));
        let fd = unsafe { libc::openat(at, c_rel.as_ptr(), flags) };
        lines.push(format!("openat {name} {extra:#o}: {}", describe(fd)));
        let how = How { flags: flags as u64, mode: 0, resolve: 0 };
        let fd = unsafe { libc::syscall(libc::SYS_openat2, at, c_rel.as_ptr(), &how as *const How, std::mem::size_of::<How>()) } as i32;
        lines.push(format!("openat2 {name} {extra:#o}: {}", describe(fd)));
        // Without O_CLOEXEC: the descriptor is inherited as asked.
        let how = How { flags: (flags & !libc::O_CLOEXEC) as u64, mode: 0, resolve: 0 };
        let fd = unsafe { libc::syscall(libc::SYS_openat2, at, c_rel.as_ptr(), &how as *const How, std::mem::size_of::<How>()) } as i32;
        lines.push(format!("openat2-inherit {name} {extra:#o}: {}", describe(fd)));
    }
    unsafe { libc::close(dfd) };
    let _ = std::fs::write(report, lines.join("\n") + "\n");
    0
}

/// Run `probe_o_path` in a plain forked child (no filter): the kernel's own
/// answers.
fn o_path_oracle(dir: &std::path::Path, report: &std::path::Path) -> String {
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        close_inherited(&[]);
        let code = probe_o_path(dir, report);
        unsafe { libc::_exit(code) };
    }
    assert_eq!(reap(child), Some(0), "the unguarded probe: {}", std::fs::read_to_string(report).unwrap_or_default());
    std::fs::read_to_string(report).unwrap()
}

/// The ledger's guard-only `O_PATH` item (!404): an `O_PATH` open of a file
/// that is no secret (a plain file, one with no read bit, a FIFO, a socket,
/// a symlink itself, `/dev/null`, procfs) and of a search-only directory.
///
/// By `open` and `openat` (flags in a register: the guard runs it as
/// issued) it is exactly the kernel's own: an `O_PATH` descriptor naming
/// that object, with nothing opened (no FIFO peer, no device, no read
/// permission needed). By `openat2` (the guard performs every one: its
/// flags are memory another thread could rewrite after a CONTINUE) the
/// kernel's answer cannot be given, since ADDFD refuses an `O_PATH` file:
/// a directory the tracee may list is its read-only stand-in (GNU tar's
/// parent open), anything else `ENOSYS`, a kernel without `openat2`, so a
/// caller takes its `openat` path. Before 2026-10-17 those were `EBADF`
/// and, for the search-only directory, `EACCES`.
#[test]
#[ignore]
fn an_o_path_open_of_what_is_no_secret_is_the_kernels_own() {
    let tree = OpenTree::new("opath");
    let targets = OPathTargets::new(&tree.dir);
    let (native_report, guarded_report) = (tree.dir.join("native.txt"), tree.dir.join("guarded.txt"));
    let native = o_path_oracle(&targets.dir, &native_report);
    let d = targets.dir.clone();
    let gr = guarded_report.clone();
    let code = run_guarded(&tree, || probe_o_path(&d, &gr));
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let guarded = std::fs::read_to_string(&guarded_report).unwrap_or_default();
    assert_eq!(code, Some(0), "{guarded}");
    // The oracle itself: every target opens O_PATH, the search-only
    // directory and the unreadable file included (not as a user whose
    // capabilities read anything: the probe drops them).
    for l in native.lines() {
        assert!(l.contains(": opened o_path=true "), "the kernel's own O_PATH open: {l}");
    }
    // What the guard answers: the kernel's own line for `open`/`openat`;
    // for `openat2`, a directory the guard's stand-in can list (as the
    // tracee: here the same process rights, the probe's dropped caps aside)
    // is that stand-in (read-only, so `read` is EISDIR), else ENOSYS.
    let lists = |name: &str| {
        let p = if name.starts_with('/') { std::path::PathBuf::from(name) } else { targets.dir.join(name) };
        let fd = unsafe { libc::open(cstr(&p).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        errno_of_fd(fd) == 0
    };
    let expected = |n: &str| -> String {
        if !n.starts_with("openat2") {
            return n.to_string();
        }
        let (head, _) = n.split_once(": ").unwrap();
        let name = head.split(' ').nth(1).unwrap();
        if n.contains(" type=dir ") && lists(name) {
            n.replace(" o_path=true ", " o_path=false ").replace(" read=errno 9 ", &format!(" read=errno {} ", libc::EISDIR))
        } else {
            format!("{head}: errno {}", libc::ENOSYS)
        }
    };
    assert_eq!(native.lines().count(), guarded.lines().count(), "native:\n{native}\nguarded:\n{guarded}");
    let differ: Vec<String> = native
        .lines()
        .zip(guarded.lines())
        .filter(|(n, g)| expected(n) != *g)
        .map(|(n, g)| format!("  native:   {n}\n  expected: {}\n  guarded:  {g}", expected(n)))
        .collect();
    assert!(differ.is_empty(), "{} O_PATH open(s) differ from what the guard must answer:\n{}", differ.len(), differ.join("\n"));
    let exact = native.lines().filter(|l| !l.starts_with("openat2")).count();
    eprintln!("O_PATH PASS: {exact} open/openat answers are the kernel's own; openat2: stand-in or ENOSYS");
}

/// Child: open the registered secret `O_PATH` every way (its path, a
/// symlink, a hard link, `openat2`, `openat2` with `RESOLVE_BENEATH`; and
/// `pre`, the REAL file's `O_PATH` descriptor the kernel gave before the
/// guard was on, which is what an `open`/`openat` `O_PATH` the guard runs
/// as issued yields when another thread swaps its path to the secret after
/// the check), then try to turn each descriptor into content: `read` on it,
/// a reopen of `/proc/self/fd/N`, `openat(fd, "", O_RDONLY|AT_EMPTY_PATH)`
/// (to `openat` that bit is `O_DSYNC`, and an empty name is ENOENT),
/// `openat2(fd, "")`, and a hard link of the descriptor
/// (`linkat(AT_EMPTY_PATH)`) opened by its new name. One line per attempt:
/// the bytes it read, or the errno.
fn probe_secret_o_path(dir: &std::path::Path, secret: &std::path::Path, pre: RawFd, report: &std::path::Path) -> i32 {
    #[repr(C)]
    struct How {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
    let read_fd = |fd: i32| -> String {
        if fd < 0 {
            return format!("errno {}", errno());
        }
        let mut b = [0u8; 64];
        let n = unsafe { libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, b.len()) };
        if n < 0 { format!("read errno {}", errno()) } else { String::from_utf8_lossy(&b[..n as usize]).trim_end().to_string() }
    };
    let read_close = |fd: i32| -> String {
        let s = read_fd(fd);
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        s
    };
    let soft = dir.join("soft-opath");
    std::os::unix::fs::symlink(secret, &soft).unwrap();
    let hard = dir.join("hard");
    let dfd = unsafe { libc::open(cstr(dir).as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    let name = std::ffi::CString::new(secret.file_name().unwrap().as_encoded_bytes()).unwrap();
    let opath = libc::O_PATH | libc::O_CLOEXEC;
    let openat2 = |at: i32, p: &std::ffi::CStr, flags: i32, resolve: u64| -> i32 {
        let how = How { flags: flags as u64, mode: 0, resolve };
        unsafe { libc::syscall(libc::SYS_openat2, at, p.as_ptr(), &how as *const How, std::mem::size_of::<How>()) as i32 }
    };
    let openers: Vec<(&str, i32)> = vec![
        ("real O_PATH from before the guard", pre),
        ("open path", unsafe { libc::open(cstr(secret).as_ptr(), opath) }),
        ("open symlink", unsafe { libc::open(cstr(&soft).as_ptr(), opath) }),
        ("open hard link", unsafe { libc::open(cstr(&hard).as_ptr(), opath) }),
        ("openat dirfd", unsafe { libc::openat(dfd, name.as_ptr(), opath) }),
        ("openat2 path", openat2(libc::AT_FDCWD, &cstr(secret), opath, 0)),
        ("openat2 symlink", openat2(libc::AT_FDCWD, &cstr(&soft), opath, 0)),
        ("openat2 beneath", openat2(dfd, &name, opath, libc::RESOLVE_BENEATH)),
    ];
    let mut lines = Vec::new();
    for (i, (how, fd)) in openers.into_iter().enumerate() {
        if fd < 0 {
            lines.push(format!("{how}: errno {}", errno()));
            continue;
        }
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        lines.push(format!("{how}: o_path={}", fl & libc::O_PATH != 0));
        lines.push(format!("{how} read: {}", read_fd(fd)));
        unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
        let again = cstr(std::path::Path::new(&format!("/proc/self/fd/{fd}")));
        lines.push(format!("{how} /proc/self/fd reopen: {}", read_close(unsafe { libc::open(again.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) })));
        lines.push(format!("{how} openat empty: {}", read_close(unsafe { libc::openat(fd, b"\0".as_ptr() as *const libc::c_char, libc::O_RDONLY | libc::AT_EMPTY_PATH) })));
        lines.push(format!("{how} openat2 empty: {}", read_close(openat2(fd, std::ffi::CStr::from_bytes_with_nul(b"\0").unwrap(), libc::O_RDONLY, 0))));
        let stolen = dir.join(format!("stolen{i}"));
        let linked = unsafe { libc::linkat(fd, b"\0".as_ptr() as *const libc::c_char, libc::AT_FDCWD, cstr(&stolen).as_ptr(), libc::AT_EMPTY_PATH) };
        let via = if linked == 0 { read_close(unsafe { libc::open(cstr(&stolen).as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) }) } else { format!("link errno {}", errno()) };
        lines.push(format!("{how} linkat empty: {via}"));
        unsafe { libc::close(fd) };
    }
    let _ = std::fs::write(report, lines.join("\n") + "\n");
    0
}

/// The other half of the `O_PATH` item: an `O_PATH` descriptor of a
/// protected file must never become its bytes. Every `O_PATH` open of it
/// the guard answers (its path, a symlink, a hard link, `openat2`) is its
/// twin, never the real file; and even the real file's own `O_PATH`
/// descriptor (which the kernel hands out when a path is swapped after the
/// guard's check of an `open`/`openat` it runs as issued) reads nothing,
/// and every way of turning it into an open file (a `/proc/self/fd/N`
/// reopen, an empty-name `openat`/`openat2`, a hard link of it) is an open
/// the guard performs and judges by the inode reached: the twin, or an
/// error, never the real bytes.
#[test]
#[ignore]
fn an_o_path_descriptor_of_a_secret_never_becomes_its_bytes() {
    let tree = OpenTree::new("opathsecret");
    let report = tree.dir.join("report.txt");
    // Made before the guard (the link family is trapped under a secret policy).
    std::fs::hard_link(&tree.secret, tree.dir.join("hard")).unwrap();
    let (dir, secret) = (tree.dir.clone(), tree.secret.clone());
    // The real file's O_PATH descriptor, opened before the filter goes on,
    // at a number the probe knows.
    const PRE: RawFd = 250;
    let s2 = secret.clone();
    let setup = move || -> Option<i32> {
        let fd = unsafe { libc::open(cstr(&s2).as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 || unsafe { libc::dup3(fd, PRE, libc::O_CLOEXEC) } != PRE {
            return Some(EXIT_SETUP_FAIL);
        }
        unsafe { libc::close(fd) };
        None
    };
    let code = run_guarded_setup(&tree, |_| {}, setup, || probe_secret_o_path(&dir, &secret, PRE, &report));
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    let got = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("SECRET O_PATH:\n{got}");
    assert_eq!(code, Some(0), "{got}");
    assert!(!got.contains("REAL-SECRET"), "an O_PATH descriptor of the secret became its bytes:\n{got}");
    // The guard's own answers to an O_PATH open of the secret are its twin
    // (opened readable: ADDFD carries no O_PATH file), never the real file.
    for l in got.lines().filter(|l| l.ends_with(": o_path=true") || l.ends_with(": o_path=false")) {
        assert_eq!(l.ends_with(": o_path=true"), l.starts_with("real O_PATH"), "only the descriptor from before the guard is the real O_PATH one: {l}");
    }
    assert!(got.contains(&format!("real O_PATH from before the guard read: read errno {}\n", libc::EBADF)), "an O_PATH descriptor reads nothing:\n{got}");
    for how in ["real O_PATH from before the guard", "open path", "open symlink", "open hard link", "openat dirfd", "openat2 path", "openat2 symlink", "openat2 beneath"] {
        let reopen = got.lines().find(|l| l.starts_with(&format!("{how} /proc/self/fd reopen: "))).unwrap_or("");
        assert!(reopen.ends_with(": TWIN-PLACEHOLDER"), "the descriptor's reopen must read the twin ({how}):\n{got}");
    }
}

fn cstr(p: &std::path::Path) -> std::ffi::CString {
    std::ffi::CString::new(p.as_os_str().to_str().unwrap()).unwrap()
}

/// errno of a -1 return, 0 on success (closing a returned descriptor).
fn errno_of_fd(rc: i32) -> i32 {
    if rc >= 0 {
        unsafe { libc::close(rc) };
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

fn errno_of_rc(rc: i32) -> i32 {
    if rc == 0 { 0 } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) }
}

/// Every way of changing a file by name is refused under a `deny` entry and
/// under an `ask` entry the guard cannot ask about (no arbiter: fail-closed);
/// reads and writes elsewhere go on.
#[test]
#[ignore]
fn guard_refuses_changes_under_write_protected_paths() {
    let dir = std::env::temp_dir().join(format!("mandu-wp-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let own = dir.join("mandu");
    std::fs::create_dir_all(&own).unwrap();
    let law = own.join("policy.yaml");
    std::fs::write(&law, "law: strict\n").unwrap();
    let rc = dir.join("rc");
    std::fs::write(&rc, "# startup\n").unwrap();
    let evil = dir.join("evil");
    std::fs::write(&evil, "law: open\n").unwrap();
    let sl = dir.join("sl");
    std::os::unix::fs::symlink(&rc, &sl).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"agentExe":"","askTimeoutMs":1000,"writeProtect":[{{"path":"{}","answer":"deny","label":"Mandu's own files"}},{{"path":"{}","answer":"ask","label":"a shell startup file"}}]}}"#,
            own.display(),
            rc.display()
        ),
    )
    .unwrap();
    let (law_c, rc_c, evil_c, sl_c) = (cstr(&law), cstr(&rc), cstr(&evil), cstr(&sl));
    let new_c = cstr(&own.join("new"));
    let link_c = cstr(&own.join("l"));
    let alias_c = cstr(&dir.join("alias"));
    let free_c = cstr(&dir.join("free.txt"));
    let fake_sock = own.join("arbiter.sock");
    let got = run_guarded_protect(&policy, || unsafe {
        // Finding 3: a socket bound under a protected path is a new file too.
        let bound = {
            let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            let (addr, len) = unix_addr(Some(&fake_sock), None);
            let rc = libc::bind(s, &addr as *const libc::sockaddr_un as *const libc::sockaddr, len);
            let e = errno_of_rc(rc);
            libc::close(s);
            e
        };
        let checks: Vec<(i32, i32)> = vec![
            (errno_of_fd(libc::open(law_c.as_ptr(), libc::O_WRONLY | libc::O_TRUNC)), libc::EACCES),
            (errno_of_fd(libc::open(new_c.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644)), libc::EACCES),
            (errno_of_rc(libc::rename(evil_c.as_ptr(), law_c.as_ptr())), libc::EACCES),
            (errno_of_rc(libc::symlink(evil_c.as_ptr(), link_c.as_ptr())), libc::EACCES),
            (errno_of_rc(libc::link(law_c.as_ptr(), alias_c.as_ptr())), libc::EACCES),
            (errno_of_rc(libc::truncate(law_c.as_ptr(), 0)), libc::EACCES),
            (errno_of_rc(libc::unlink(law_c.as_ptr())), libc::EACCES),
            // `ask` with nobody to ask: refused.
            (errno_of_fd(libc::open(rc_c.as_ptr(), libc::O_WRONLY | libc::O_APPEND)), libc::EACCES),
            // A symlink elsewhere that leads to the protected file.
            (errno_of_fd(libc::open(sl_c.as_ptr(), libc::O_WRONLY | libc::O_TRUNC)), libc::EACCES),
            // Reads of a protected file, and writes elsewhere, go on.
            (errno_of_fd(libc::open(law_c.as_ptr(), libc::O_RDONLY)), 0),
            (errno_of_fd(libc::open(free_c.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644)), 0),
            (bound, libc::EACCES),
        ];
        #[cfg(target_arch = "x86_64")]
        let checks = {
            let mut c = checks;
            c.push((errno_of_fd(libc::syscall(libc::SYS_creat, new_c.as_ptr(), 0o644) as i32), libc::EACCES));
            c
        };
        match checks.iter().position(|(got, want)| got != want) {
            None => 0,
            Some(i) => 10 + i as i32,
        }
    });
    let Some(code) = got else {
        eprintln!("SKIP: seccomp NEW_LISTENER unavailable");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let law_after = std::fs::read_to_string(&law).unwrap_or_default();
    let rc_after = std::fs::read_to_string(&rc).unwrap_or_default();
    let created = own.join("new").exists() || own.join("l").exists() || dir.join("alias").exists() || own.join("arbiter.sock").exists();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, Some(0), "check #{} (10 + index) got an unexpected answer", code.unwrap_or(-1) - 10);
    assert_eq!(law_after, "law: strict\n", "the protected file changed");
    assert_eq!(rc_after, "# startup\n", "the held file changed");
    assert!(!created, "a name was created under a protected path");
}

/// P0 (D), 2026-10-07 (write-protection.md §2): a name changed at a strict
/// ancestor of a write-protected path replaces it with no write under it.
/// Red before: `mv ~/.ssh ~/.ssh.old` went through (then a planted
/// directory renamed to `~/.ssh` brought its own `config`), and so did
/// renaming or symlinking a planted directory into the place of an entry's
/// missing parent (`~/.orbstack` for `~/.orbstack/ssh/config`).
#[test]
#[ignore]
fn guard_refuses_replacing_an_ancestor_of_a_write_protected_path() {
    let dir = std::env::temp_dir().join(format!("mandu-wp-anc-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let ssh = dir.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("config"), "Host *\n").unwrap();
    let planted = dir.join("planted");
    std::fs::create_dir_all(planted.join("ssh")).unwrap();
    std::fs::write(planted.join("config"), "Include /x/id_ed25519\n").unwrap();
    std::fs::write(planted.join("ssh").join("config"), "Include /x/id_ed25519\n").unwrap();
    let free = dir.join("free");
    std::fs::create_dir_all(&free).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"agentExe":"","askTimeoutMs":1000,"writeProtect":[{{"path":"{}","answer":"ask","label":"an ssh setting"}},{{"path":"{}","answer":"ask","label":"an ssh setting"}}]}}"#,
            ssh.join("config").display(),
            dir.join(".orbstack").join("ssh").join("config").display()
        ),
    )
    .unwrap();
    let (ssh_c, old_c, planted_c, orb_c) = (cstr(&ssh), cstr(&dir.join(".ssh.old")), cstr(&planted), cstr(&dir.join(".orbstack")));
    let (free_c, free2_c) = (cstr(&free), cstr(&dir.join("free2")));
    let got = run_guarded_protect(&policy, || unsafe {
        let checks: Vec<(i32, i32)> = vec![
            // The protected file's directory moved aside, or replaced.
            (errno_of_rc(libc::rename(ssh_c.as_ptr(), old_c.as_ptr())), libc::EACCES),
            (errno_of_rc(libc::rename(planted_c.as_ptr(), ssh_c.as_ptr())), libc::EACCES),
            // A planted directory, or a symlink to one, put where an entry's
            // missing parent would be.
            (errno_of_rc(libc::rename(planted_c.as_ptr(), orb_c.as_ptr())), libc::EACCES),
            (errno_of_rc(libc::symlink(planted_c.as_ptr(), orb_c.as_ptr())), libc::EACCES),
            // An unrelated directory is renamed freely.
            (errno_of_rc(libc::rename(free_c.as_ptr(), free2_c.as_ptr())), 0),
        ];
        match checks.iter().position(|(got, want)| got != want) {
            None => 0,
            Some(i) => 10 + i as i32,
        }
    });
    let Some(code) = got else {
        eprintln!("SKIP: seccomp NEW_LISTENER unavailable");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let config_after = std::fs::read_to_string(ssh.join("config")).unwrap_or_default();
    let orb = dir.join(".orbstack").symlink_metadata().is_ok();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, Some(0), "check #{} (10 + index) got an unexpected answer", code.unwrap_or(-1) - 10);
    assert_eq!(config_after, "Host *\n", "the protected file was replaced through its directory");
    assert!(!orb, "a planted directory took the place of a protected path's parent");
}

// ── sandbox-security-review-2026-09-28 finding 1: the Unix socket allow-list ──

/// `run_guarded_protect` with the tree root set to the child (the listener
/// probe's notion of "in the agent's tree"). `record`: the guard keeps the
/// bind record (`GuardConfig::unix_binds`, the production launch's
/// posture: the filter traps `bind` under every secret policy), so an
/// unlisted listener of this network namespace is judged by it; false =
/// by the probe connection alone (the posture without the record).
fn run_guarded_unix(policy: &std::path::Path, record: bool, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    run_guarded_unix_pre(policy, record, || (), |()| body())
}

/// `run_guarded_unix`, with `pre` run in the child BEFORE the filter goes
/// up (what the filter refuses, `clone3` under a secret policy, can still be
/// done there), its result handed to `body`.
fn run_guarded_unix_pre<T>(policy: &std::path::Path, record: bool, pre: impl FnOnce() -> T, body: impl FnOnce(T) -> i32) -> Option<Option<i32>> {
    run_guarded_unix_keep(policy, record, &[], pre, body)
}

/// `run_guarded_unix_pre`, the tracee keeping `keep` of this process's
/// descriptors (what a launcher leaks into the agent).
fn run_guarded_unix_keep<T>(policy: &std::path::Path, record: bool, keep: &[RawFd], pre: impl FnOnce() -> T, body: impl FnOnce(T) -> i32) -> Option<Option<i32>> {
    let (sup_sock, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        close_inherited(&[&[child_sock][..], keep].concat());
        let before = pre();
        let traps = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, ..Default::default() };
        let listener = match net_supervisor::guard_kernel::install_guard_filter_self(traps) {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if send_fd(child_sock, listener).is_err() {
            unsafe {
                libc::close(listener);
                libc::_exit(EXIT_SETUP_FAIL)
            };
        }
        unsafe { libc::close(listener) };
        let code = body(before);
        unsafe { libc::_exit(code) };
    }
    unsafe { libc::close(child_sock) };
    let listener = match recv_fd_from(sup_sock, child) {
        Ok(fd) => fd,
        Err(_) => {
            assert_eq!(reap(child), Some(EXIT_NO_SECCOMP), "tracee failed to send its listener");
            return None;
        }
    };
    let mut cfg = cfg("tcp:10.9.9.9/32:9");
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(policy).unwrap()));
    cfg.tree_roots = vec![child];
    if record {
        cfg.unix_binds = Some(Arc::new(net_supervisor::unix_owner::BindRecord::new(net_supervisor::unix_owner::BindRecord::DEFAULT_CAP)));
    }
    let server = std::thread::spawn(move || {
        let _ = net_supervisor::guard_kernel::run_guard_supervisor(listener, cfg);
        unsafe { libc::close(listener) };
    });
    let code = reap(child);
    let _ = join_within(server, wait_limit(), "the guard supervisor (run_guard_supervisor), after its tracee exited");
    unsafe { libc::close(sup_sock) };
    Some(code)
}

/// A listening Unix socket (`abstract_name` = an abstract address).
fn unix_listen(path: Option<&std::path::Path>, abstract_name: Option<&str>, ty: i32) -> i32 {
    unsafe {
        let s = libc::socket(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0);
        assert!(s >= 0);
        let (addr, len) = unix_addr(path, abstract_name);
        assert_eq!(libc::bind(s, &addr as *const libc::sockaddr_un as *const libc::sockaddr, len), 0, "bind");
        if ty == libc::SOCK_STREAM {
            assert_eq!(libc::listen(s, 8), 0);
        }
        s
    }
}

fn unix_addr(path: Option<&std::path::Path>, abstract_name: Option<&str>) -> (libc::sockaddr_un, libc::socklen_t) {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes: Vec<u8> = match (path, abstract_name) {
        (Some(p), _) => p.as_os_str().to_str().unwrap().as_bytes().to_vec(),
        (None, Some(n)) => std::iter::once(0u8).chain(n.bytes()).collect(),
        _ => panic!("an address"),
    };
    for (i, b) in bytes.iter().enumerate() {
        addr.sun_path[i] = *b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + usize::from(path.is_some())) as libc::socklen_t;
    (addr, len)
}

/// errno of a Unix connect from this process (0 = connected).
fn unix_connect(path: Option<&std::path::Path>, abstract_name: Option<&str>, ty: i32) -> i32 {
    unsafe {
        let s = libc::socket(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return -1;
        }
        let (addr, len) = unix_addr(path, abstract_name);
        let rc = libc::connect(s, &addr as *const libc::sockaddr_un as *const libc::sockaddr, len);
        let e = if rc == 0 { 0 } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) };
        libc::close(s);
        e
    }
}

#[test]
#[ignore]
fn guard_allow_lists_unix_sockets_by_list_and_by_the_tree() {
    // By the bind record (the production posture), and by the probe alone
    // (where the record cannot decide): the same answers.
    allow_list_round(true);
    allow_list_round(false);
}

fn allow_list_round(record: bool) {
    let dir = std::env::temp_dir().join(format!("mandu-unix-{}-{}", run_tag(), if record { "rec" } else { "probe" }));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Abstract names are per round: the first round's listeners of this
    // process are still bound.
    let tag = format!("{}-{}", run_tag(), if record { "rec" } else { "probe" });
    let host = dir.join("host.sock");
    let listed = dir.join("listed.sock");
    let own = dir.join("own.sock");
    let dgram = dir.join("dgram.sock");
    // A socket file nobody listens on any more (Claude Code's stale
    // `cc-socks/<pid>.sock`): the kernel's ECONNREFUSED, not a refusal.
    // Made by a short-lived child, NOT by listen-then-close here: libtest runs
    // this file's tests on threads of one process, and a fork by another test
    // between our listen() and close() copies the listener into a child that
    // lives on, so the socket stays LISTENING, held outside the tree, and the
    // guard rightly refuses it (EACCES; the local-full-3 run's failure,
    // check #7). The child's descriptor table is its own: nobody can copy it.
    let stale = dir.join("stale.sock");
    let maker = unsafe { libc::fork() };
    assert!(maker >= 0);
    if maker == 0 {
        // Raw calls only in this forked copy of a multithreaded process.
        let (addr, len) = unix_addr(Some(&stale), None);
        let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        let ok = s >= 0
            && unsafe { libc::bind(s, &addr as *const libc::sockaddr_un as *const libc::sockaddr, len) } == 0
            && unsafe { libc::listen(s, 8) } == 0;
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    assert_eq!(reap(maker), Some(0), "the stale socket's maker");
    // That failure's situation, on purpose: a listener its creator closed but
    // another process OUTSIDE the tree still holds is live and not the tree's:
    // refused, never taken for a stale file.
    let held = dir.join("held.sock");
    let held_fd = unix_listen(Some(&held), None, libc::SOCK_STREAM);
    let holder = unsafe { libc::fork() };
    assert!(holder >= 0);
    if holder == 0 {
        loop { unsafe { libc::pause() }; }
    }
    unsafe { libc::close(held_fd) };
    let nobody_abs = format!("mandu-nobody-{tag}");
    let host_abs = format!("mandu-host-{tag}");
    let ok_abs = format!("mandu-ok-{tag}");
    let own_abs = format!("mandu-own-{tag}");
    // The "host services": listeners of this test process, outside the tree.
    let _h = unix_listen(Some(&host), None, libc::SOCK_STREAM);
    let _l = unix_listen(Some(&listed), None, libc::SOCK_STREAM);
    let _d = unix_listen(Some(&dgram), None, libc::SOCK_DGRAM);
    let _ha = unix_listen(None, Some(&host_abs), libc::SOCK_STREAM);
    let _oa = unix_listen(None, Some(&ok_abs), libc::SOCK_STREAM);
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(r#"{{"agentExe":"","unixPolicy":{{"allow":[{{"path":"{}","label":"listed"}}],"abstractAllow":["mandu-ok-*"]}}}}"#, listed.display()),
    )
    .unwrap();
    let (own2, own_abs2, host2, listed2, dgram2, host_abs2, ok_abs2) = (own.clone(), own_abs.clone(), host.clone(), listed.clone(), dgram.clone(), host_abs.clone(), ok_abs.clone());
    let (stale2, nobody_abs2, held2) = (stale.clone(), nobody_abs.clone(), held.clone());
    let unlistened = dir.join("own-unlistened.sock");
    let unlistened2 = unlistened.clone();
    let got = run_guarded_unix(&policy, record, move || {
        // The tree's own server: a grandchild listening on a path and an
        // abstract name, then waiting to be killed.
        let (r, w) = pipe();
        let srv = unsafe { libc::fork() };
        if srv == 0 {
            let _a = unix_listen(Some(&own2), None, libc::SOCK_STREAM);
            let _b = unix_listen(None, Some(&own_abs2), libc::SOCK_STREAM);
            // Bound, never listening: a server between its bind() and its
            // listen(). The kernel's answer is ECONNREFUSED, and so is the
            // guard's (the probe meets it too): the socket file existing is
            // not the server being up (the unix-allow-list e2e waits on a
            // mark the server writes after listen() for this reason).
            let _c = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            let (ua, ul) = unix_addr(Some(&unlistened2), None);
            unsafe { libc::bind(_c, &ua as *const libc::sockaddr_un as *const libc::sockaddr, ul) };
            unsafe { libc::write(w, b"k".as_ptr() as *const libc::c_void, 1) };
            loop { unsafe { libc::pause() }; }
        }
        let mut b = 0u8;
        unsafe { libc::read(r, &mut b as *mut u8 as *mut libc::c_void, 1) };
        let checks = [
            (unix_connect(Some(&host2), None, libc::SOCK_STREAM), libc::EACCES),
            (unix_connect(Some(&listed2), None, libc::SOCK_STREAM), 0),
            (unix_connect(Some(&own2), None, libc::SOCK_STREAM), 0),
            (unix_connect(Some(&dgram2), None, libc::SOCK_DGRAM), libc::EACCES),
            (unix_connect(None, Some(&host_abs2), libc::SOCK_STREAM), libc::EACCES),
            (unix_connect(None, Some(&ok_abs2), libc::SOCK_STREAM), 0),
            (unix_connect(None, Some(&own_abs2), libc::SOCK_STREAM), 0),
            (unix_connect(Some(&stale2), None, libc::SOCK_STREAM), libc::ECONNREFUSED),
            (unix_connect(None, Some(&nobody_abs2), libc::SOCK_STREAM), libc::ECONNREFUSED),
            (unix_connect(Some(&held2), None, libc::SOCK_STREAM), libc::EACCES),
            (unix_connect(Some(&unlistened2), None, libc::SOCK_STREAM), libc::ECONNREFUSED),
        ];
        unsafe { libc::kill(srv, libc::SIGKILL) };
        let mut st = 0;
        unsafe { libc::waitpid(srv, &mut st, 0) };
        match checks.iter().position(|(got, want)| got != want) {
            None => 0,
            Some(i) => {
                // The forked child's eprintln! goes to a capture buffer that
                // dies with it: write the whole table to fd 2 itself.
                let msg = format!("unix allow-list checks (got, want): {checks:?}; first mismatch #{i}\n");
                unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()) };
                10 + i as i32
            }
        }
    });
    unsafe { libc::kill(holder, libc::SIGKILL) };
    reap(holder);
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else {
        eprintln!("SKIP: seccomp NEW_LISTENER unavailable");
        return;
    };
    assert_eq!(code, Some(0), "check #{} (10 + index) got an unexpected answer (record: {record})", code.unwrap_or(-1) - 10);
}

/// A child made with `clone3` at pid `want` (`set_tid`: needs CAP_SYS_ADMIN
/// over the pid namespace, root-in-namespace under `scripts/kernel-tests.sh`),
/// pausing until killed. None where the kernel or the privilege refuses.
/// Called before the guard's filter goes up: under a secret policy the
/// filter refuses `clone3` (ENOSYS, exec-routing.md §7.5 gap (d)).
fn fork_at_pid(want: i32) -> Option<i32> {
    #[repr(C)]
    #[derive(Default)]
    struct CloneArgs { flags: u64, pidfd: u64, child_tid: u64, parent_tid: u64, exit_signal: u64, stack: u64, stack_size: u64, tls: u64, set_tid: u64, set_tid_size: u64, cgroup: u64 }
    let tid = [want as libc::pid_t];
    let args = CloneArgs { exit_signal: libc::SIGCHLD as u64, set_tid: tid.as_ptr() as u64, set_tid_size: 1, ..Default::default() };
    // SAFETY: clone3 (435 on x86_64 and aarch64) without a stack: a fork.
    let r = unsafe { libc::syscall(435, &args as *const CloneArgs, std::mem::size_of::<CloneArgs>()) };
    if r == 0 {
        loop { unsafe { libc::pause() }; }
    }
    (r > 0).then_some(r as i32)
}

/// The TODO's fail-open (2026-09-28): the allow list judged "the tree's own
/// listener" by the `SO_PEERCRED` pid, which the kernel keeps reporting after
/// the `listen()` caller exits. A HOST listener whose creator died, reached
/// from a tree that took the dead creator's pid, was judged the tree's. Now it
/// is judged by its live creator or its holder (`unix_owner`): refused. The
/// fail-closed side of the same flaw: a tree server whose listener its parent
/// made before exiting (ssh-agent's shape) is reached.
#[test]
#[ignore]
fn guard_judges_a_unix_listener_by_its_holder_not_a_reused_pid() {
    // The probe's creator and holder rules (the record off), and the same
    // shapes under the bind record: the daemon's parent bound the socket,
    // and the host's reused number names nothing the tree bound.
    reused_pid_round(false);
    reused_pid_round(true);
}

fn reused_pid_round(record: bool) {
    let dir = std::env::temp_dir().join(format!("mandu-unix-reuse-{}-{}", run_tag(), if record { "rec" } else { "probe" }));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let reused = dir.join("host-reused.sock");
    let daemon = dir.join("tree-daemon.sock");
    // The host service: its creator listens, leaves a holder outside the
    // tree, and exits; its number is free for the taking.
    let (r, w) = pipe();
    let creator = unsafe { libc::fork() };
    assert!(creator >= 0);
    if creator == 0 {
        // Raw calls only in this forked copy of a multithreaded process.
        let (addr, len) = unix_addr(Some(&reused), None);
        let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        let ok = s >= 0
            && unsafe { libc::bind(s, &addr as *const libc::sockaddr_un as *const libc::sockaddr, len) } == 0
            && unsafe { libc::listen(s, 8) } == 0;
        if !ok {
            unsafe { libc::_exit(1) };
        }
        let holder = unsafe { libc::fork() };
        if holder == 0 {
            loop { unsafe { libc::pause() }; }
        }
        let b = holder.to_ne_bytes();
        unsafe { libc::write(w, b.as_ptr() as *const libc::c_void, 4) };
        unsafe { libc::_exit(0) };
    }
    assert_eq!(reap(creator), Some(0), "the host service's creator");
    let mut hb = [0u8; 4];
    unsafe { libc::read(r, hb.as_mut_ptr() as *mut libc::c_void, 4) };
    let host_holder = i32::from_ne_bytes(hb);
    let policy = dir.join("policy.json");
    std::fs::write(&policy, r#"{"agentExe":"","unixPolicy":{"allow":[],"abstractAllow":[]}}"#).unwrap();
    let (reused2, daemon2) = (reused.clone(), daemon.clone());
    // The attack: a tree process at the host creator's old number, made by
    // the tree's root before the filter goes up (it refuses clone3).
    let got = run_guarded_unix_pre(&policy, record, move || fork_at_pid(creator), move |squatter| {
        // The guard is its tree's subreaper; this root stands in for it.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        // The tree's daemon: its parent listens, forks the server, exits.
        let (r, w) = pipe();
        let parent = unsafe { libc::fork() };
        if parent == 0 {
            let _l = unix_listen(Some(&daemon2), None, libc::SOCK_STREAM);
            let server = unsafe { libc::fork() };
            if server == 0 {
                loop { unsafe { libc::pause() }; }
            }
            let b = server.to_ne_bytes();
            unsafe { libc::write(w, b.as_ptr() as *const libc::c_void, 4) };
            unsafe { libc::_exit(0) };
        }
        let mut st = 0;
        unsafe { libc::waitpid(parent, &mut st, 0) };
        let mut sb = [0u8; 4];
        unsafe { libc::read(r, sb.as_mut_ptr() as *mut libc::c_void, 4) };
        let server = i32::from_ne_bytes(sb);
        let checks = [
            (unix_connect(Some(&daemon2), None, libc::SOCK_STREAM), 0),
            (unix_connect(Some(&reused2), None, libc::SOCK_STREAM), libc::EACCES),
        ];
        if let Some(p) = squatter {
            unsafe { libc::kill(p, libc::SIGKILL) };
        } else {
            let msg = format!("NOTE: pid {creator} could not be taken (clone3 set_tid); the reuse ran without a squatter\n");
            unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()) };
        }
        // The daemon's server, now this subreaper's child.
        unsafe { libc::kill(server, libc::SIGKILL) };
        while unsafe { libc::waitpid(-1, &mut st, 0) } > 0 {}
        match checks.iter().position(|(got, want)| got != want) {
            None => 0,
            Some(i) => {
                let msg = format!("unix listener ownership checks (got, want): {checks:?}; first mismatch #{i}\n");
                unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()) };
                10 + i as i32
            }
        }
    });
    unsafe { libc::kill(host_holder, libc::SIGKILL) };
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else {
        eprintln!("SKIP: seccomp NEW_LISTENER unavailable");
        return;
    };
    assert_eq!(code, Some(0), "check #{} (10 + index) got an unexpected answer", code.unwrap_or(-1) - 10);
}

// ── exec-routing.md §4.3 (2026-10-18): the bind record, no probe connection ──

/// A connected Unix stream socket's exchange, from the client's side: send
/// one byte, wait (5 s at most) for one back. The byte, or the errno.
fn unix_exchange(path: Option<&std::path::Path>, abstract_name: Option<&str>) -> Result<u8, i32> {
    unsafe {
        let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return Err(-1);
        }
        let (addr, len) = unix_addr(path, abstract_name);
        let out = (|| {
            if libc::connect(s, &addr as *const libc::sockaddr_un as *const libc::sockaddr, len) != 0 {
                return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
            }
            let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
            libc::setsockopt(s, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const libc::timeval as *const libc::c_void, std::mem::size_of::<libc::timeval>() as libc::socklen_t);
            if libc::send(s, b"x".as_ptr() as *const libc::c_void, 1, libc::MSG_NOSIGNAL) != 1 {
                return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
            }
            let mut b = 0u8;
            match libc::recv(s, &mut b as *mut u8 as *mut libc::c_void, 1, 0) {
                1 => Ok(b),
                0 => Err(0),
                _ => Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)),
            }
        })();
        libc::close(s);
        out
    }
}

/// In a forked tree process: ssh-agent's shape with a server that takes
/// exactly ONE connection. This process binds and listens, forks the
/// server and returns (its caller exits); the server accepts once, reads
/// a byte and answers `k` (`MSG_NOSIGNAL`: a dead connection is an error,
/// not a signal), then exits: 0 served, 1 its one connection was empty
/// (the guard's probe), 2 its answer failed. `ready` gets one byte once
/// it listens.
fn one_accept_server(path: Option<&std::path::Path>, abstract_name: Option<&str>, ready: RawFd) -> i32 {
    let l = unix_listen(path, abstract_name, libc::SOCK_STREAM);
    let server = unsafe { libc::fork() };
    if server == 0 {
        let c = unsafe { libc::accept(l, std::ptr::null_mut(), std::ptr::null_mut()) };
        let mut b = 0u8;
        let got = unsafe { libc::recv(c, &mut b as *mut u8 as *mut libc::c_void, 1, 0) };
        if got != 1 {
            unsafe { libc::_exit(1) };
        }
        let sent = unsafe { libc::send(c, b"k".as_ptr() as *const libc::c_void, 1, libc::MSG_NOSIGNAL) };
        unsafe { libc::_exit(if sent == 1 { 0 } else { 2 }) };
    }
    unsafe { libc::write(ready, b"r".as_ptr() as *const libc::c_void, 1) };
    server
}

/// The bug the record fixes (found 2026-10-17): the probe connection landed
/// in the listener's queue ahead of the client's, so a server that accepts
/// exactly once took the guard's dead probe (its answer failed with EPIPE)
/// and the real client waited on a connection nobody accepted. Under the
/// bind record the listener is judged by name, without a connection: the
/// one-accept server serves its real client, by a socket file and by an
/// abstract name, its listener made by a parent that then exited
/// (ssh-agent's shape). Red on the probe alone (`one_accept_round(false)`
/// fails both legs).
#[test]
#[ignore]
fn guard_serves_a_one_accept_tree_server_its_real_client() {
    one_accept_round(true);
}

fn one_accept_round(record: bool) {
    let dir = std::env::temp_dir().join(format!("mandu-unix-once-{}-{}", run_tag(), if record { "rec" } else { "probe" }));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("once.sock");
    let name = format!("mandu-once-{}-{record}", run_tag());
    let policy = dir.join("policy.json");
    std::fs::write(&policy, r#"{"agentExe":"","unixPolicy":{"allow":[],"abstractAllow":[]}}"#).unwrap();
    let (path2, name2) = (path.clone(), name.clone());
    let got = run_guarded_unix(&policy, record, move || {
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        let mut results = Vec::new();
        for (p, n) in [(Some(path2.as_path()), None), (None, Some(name2.as_str()))] {
            let (r, w) = pipe();
            let parent = unsafe { libc::fork() };
            if parent == 0 {
                one_accept_server(p, n, w);
                unsafe { libc::_exit(0) };
            }
            let mut st = 0;
            unsafe { libc::waitpid(parent, &mut st, 0) };
            let mut b = 0u8;
            unsafe { libc::read(r, &mut b as *mut u8 as *mut libc::c_void, 1) };
            let answer = unix_exchange(p, n);
            // The server, now this subreaper's child: its own verdict.
            let mut server_st = 0;
            let server = unsafe { libc::waitpid(-1, &mut server_st, 0) };
            let served = if server > 0 && libc::WIFEXITED(server_st) { libc::WEXITSTATUS(server_st) } else { -1 };
            results.push((answer, served));
            unsafe {
                libc::close(r);
                libc::close(w);
            }
        }
        let want = [(Ok(b'k'), 0), (Ok(b'k'), 0)];
        if results == want {
            0
        } else {
            let msg = format!("one-accept server (client answer, server status), path then abstract: {results:?}; want {want:?}\n");
            unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()) };
            10
        }
    });
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else {
        eprintln!("SKIP: seccomp NEW_LISTENER unavailable");
        return;
    };
    assert_eq!(code, Some(0), "a one-accept server in the tree did not serve its real client (record: {record})");
}

/// What the record must never do: take a listener the tree inherited for
/// the tree's. A host service (this test process: alive, outside the tree)
/// listens on a socket file and an abstract name; the tree gets both
/// listeners (a launcher's leak), fails to name them again (a bound socket
/// cannot be bound: never recorded), and calls `listen()` on them, which
/// makes it their `listen()` caller (the kernel updates `SO_PEERCRED` on a
/// listen of a listening socket; the probe's creator rule would then take
/// them for the tree's). Both stay refused, and the host's server sees no
/// connection.
#[test]
#[ignore]
fn guard_refuses_an_inherited_host_listener_the_tree_listens_on_again() {
    let dir = std::env::temp_dir().join(format!("mandu-unix-inherit-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("host.sock");
    let other = dir.join("renamed.sock");
    let name = format!("mandu-inherit-{}", run_tag());
    let hp = unix_listen(Some(&path), None, libc::SOCK_STREAM);
    let ha = unix_listen(None, Some(&name), libc::SOCK_STREAM);
    let policy = dir.join("policy.json");
    std::fs::write(&policy, r#"{"agentExe":"","unixPolicy":{"allow":[],"abstractAllow":[]}}"#).unwrap();
    let (path2, other2, name2) = (path.clone(), other.clone(), name.clone());
    let got = run_guarded_unix_keep(&policy, true, &[hp, ha], || (), move |()| {
        let (oa, ol) = unix_addr(Some(&other2), None);
        let rebinds = [hp, ha].map(|fd| {
            let rc = unsafe { libc::bind(fd, &oa as *const libc::sockaddr_un as *const libc::sockaddr, ol) };
            if rc == 0 { 0 } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) }
        });
        let relistens = [hp, ha].map(|fd| unsafe { libc::listen(fd, 16) });
        let checks = [
            (rebinds[0], libc::EINVAL),
            (rebinds[1], libc::EINVAL),
            (relistens[0], 0),
            (relistens[1], 0),
            (unix_connect(Some(&path2), None, libc::SOCK_STREAM), libc::EACCES),
            (unix_connect(None, Some(&name2), libc::SOCK_STREAM), libc::EACCES),
        ];
        match checks.iter().position(|(got, want)| got != want) {
            None => 0,
            Some(i) => {
                let msg = format!("inherited host listener checks (got, want): {checks:?}; first mismatch #{i}\n");
                unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()) };
                10 + i as i32
            }
        }
    });
    // Nothing reached the host's servers: no connection is queued.
    let queued = |fd: RawFd| unsafe {
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        let c = libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut());
        if c >= 0 {
            libc::close(c);
        }
        c >= 0
    };
    let (qp, qa) = (queued(hp), queued(ha));
    unsafe {
        libc::close(hp);
        libc::close(ha);
    }
    let renamed = other.exists();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else {
        eprintln!("SKIP: seccomp NEW_LISTENER unavailable");
        return;
    };
    assert_eq!(code, Some(0), "check #{} (10 + index) got an unexpected answer", code.unwrap_or(-1) - 10);
    assert!(!qp && !qa, "a connection reached the host's listener (path: {qp}, abstract: {qa})");
    assert!(!renamed, "a bind of the inherited listener made a socket file");
}

/// The record's fallback: a tree server listening in ANOTHER network
/// namespace (its own user and network namespaces, unprivileged) is not
/// seen by `sock_diag` in the guard's, so its socket file is judged by the
/// probe connection, as before the record: its live creator is in the tree,
/// so the client is connected. The server serves every connection and
/// counts them: 2 (the probe, then the client) shows the probe judged.
/// SKIPs where unprivileged user namespaces are not allowed.
#[test]
#[ignore]
fn guard_falls_back_to_the_probe_for_a_listener_in_another_netns() {
    let dir = std::env::temp_dir().join(format!("mandu-unix-netns-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("nested.sock");
    let policy = dir.join("policy.json");
    std::fs::write(&policy, r#"{"agentExe":"","unixPolicy":{"allow":[],"abstractAllow":[]}}"#).unwrap();
    let path2 = path.clone();
    const SKIP_NO_USERNS: i32 = 77;
    let got = run_guarded_unix(&policy, true, move || {
        let (r, w) = pipe();
        let (cr, cw) = pipe();
        let server = unsafe { libc::fork() };
        if server == 0 {
            if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
                unsafe { libc::write(w, b"s".as_ptr() as *const libc::c_void, 1) };
                unsafe { libc::_exit(0) };
            }
            let l = unix_listen(Some(&path2), None, libc::SOCK_STREAM);
            unsafe { libc::write(w, b"r".as_ptr() as *const libc::c_void, 1) };
            let mut n = 0u8;
            loop {
                let c = unsafe { libc::accept(l, std::ptr::null_mut(), std::ptr::null_mut()) };
                if c < 0 {
                    unsafe { libc::_exit(3) };
                }
                n += 1;
                let mut b = 0u8;
                if unsafe { libc::recv(c, &mut b as *mut u8 as *mut libc::c_void, 1, 0) } == 1 {
                    unsafe { libc::send(c, b"k".as_ptr() as *const libc::c_void, 1, libc::MSG_NOSIGNAL) };
                    unsafe { libc::write(cw, &n as *const u8 as *const libc::c_void, 1) };
                }
                unsafe { libc::close(c) };
            }
        }
        let mut b = 0u8;
        unsafe { libc::read(r, &mut b as *mut u8 as *mut libc::c_void, 1) };
        if b == b's' {
            let mut st = 0;
            unsafe { libc::waitpid(server, &mut st, 0) };
            return SKIP_NO_USERNS;
        }
        let answer = unix_exchange(Some(&path2), None);
        let mut accepts = 0u8;
        if answer.is_ok() {
            unsafe { libc::read(cr, &mut accepts as *mut u8 as *mut libc::c_void, 1) };
        }
        unsafe { libc::kill(server, libc::SIGKILL) };
        let mut st = 0;
        unsafe { libc::waitpid(server, &mut st, 0) };
        if answer == Ok(b'k') && accepts == 2 {
            0
        } else {
            let msg = format!("another netns: client answer {answer:?}, the server's accept count at the client's byte {accepts} (want Ok(107), 2)\n");
            unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()) };
            10
        }
    });
    let _ = std::fs::remove_dir_all(&dir);
    match got {
        None => eprintln!("SKIP: seccomp NEW_LISTENER unavailable"),
        Some(Some(SKIP_NO_USERNS)) => eprintln!("SKIP: no unprivileged user + network namespace here"),
        Some(code) => assert_eq!(code, Some(0), "a tree server in another network namespace was not judged by the probe"),
    }
}

/// sandbox-security-review-2026-09-28 finding 9: under the guard's filter,
/// TIOCSTI on a terminal is refused by the filter (EPERM), whatever the
/// kernel's own `legacy_tiocsti` says (it answers EIO, or lets it through).
#[test]
#[ignore]
fn guard_refuses_tiocsti() {
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe {
            let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            if m < 0 || libc::grantpt(m) != 0 || libc::unlockpt(m) != 0 {
                libc::_exit(EXIT_SETUP_FAIL);
            }
            let traps = net_supervisor::guard_kernel::FilterTraps::default();
            let listener = match net_supervisor::guard_kernel::install_guard_filter_self(traps) {
                Ok(fd) => fd,
                Err(_) => libc::_exit(EXIT_NO_SECCOMP),
            };
            libc::close(listener);
            let c: libc::c_char = b'x' as libc::c_char;
            let rc = libc::ioctl(m, libc::TIOCSTI, &c as *const libc::c_char);
            let e = if rc == 0 { 0 } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) };
            libc::_exit(if e == libc::EPERM { 0 } else { 10 });
        }
    }
    let st = reap_within(child, wait_limit(), "waiting for the TIOCSTI probe child").status;
    let code = libc::WEXITSTATUS(st);
    if code == EXIT_NO_SECCOMP || code == EXIT_SETUP_FAIL {
        eprintln!("SKIP: no seccomp listener or no pty here ({code})");
        return;
    }
    assert_eq!(code, 0, "TIOCSTI under the guard was not refused by the filter");
}

// ── path-change TOCTOU (sandbox-security-review-2026-09-28 findings 6/7) ──────
//
// The name family (rename, unlink, link, symlink, truncate, bind) used to be
// judged BY NAME and then CONTINUEd, so the kernel re-resolved the path and a
// racing thread could swap a symlinked parent between the check and the
// resolve. The guard now PERFORMS each on the tracee's behalf, relative to a
// pinned parent descriptor, and never CONTINUEs. Each race test below fails on
// the old CONTINUE handler (a swapped parent lands the change in the protected
// directory); the swap is driven by a tight flipper thread, exactly as the
// write-open race template (`a_symlink_swapped_during_a_write_open…`) does.

/// A flipper: swap the symlink `sw` between pointing at `dest_free` (a scratch
/// dir) and `dest_prot` (the protected dir), atomically, until `stop`.
fn spawn_parent_flipper(
    sw: std::path::PathBuf,
    dest_free: std::path::PathBuf,
    dest_prot: std::path::PathBuf,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    use std::sync::atomic::Ordering;
    let ta = sw.with_extension("flip_a");
    let tb = sw.with_extension("flip_b");
    std::thread::spawn(move || {
        let mut n = 0u32;
        while !stop.load(Ordering::Relaxed) {
            let (tmp, to) = if n % 2 == 0 { (&ta, &dest_free) } else { (&tb, &dest_prot) };
            let _ = std::fs::remove_file(tmp);
            let _ = std::os::unix::fs::symlink(to, tmp);
            let _ = std::fs::rename(tmp, &sw);
            n += 1;
        }
    })
}

/// A scratch directory with a protected sub-directory `own` (write-protect
/// `deny`) and a scratch `free`, plus the guard policy file. `own`, `free` and
/// the policy path are returned.
fn protect_tree(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("mandu-{tag}-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let own = dir.join("own");
    let free = dir.join("free");
    std::fs::create_dir_all(&own).unwrap();
    std::fs::create_dir_all(&free).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(r#"{{"agentExe":"","writeProtect":[{{"path":"{}","answer":"deny","label":"Mandu's own files"}}]}}"#, own.display()),
    )
    .unwrap();
    (dir, own, free, policy)
}

/// `run_guarded_protect`, but the flipper swapping `sw` between `free` and
/// `prot` runs in the PARENT (supervisor) process — which is NOT under the
/// seccomp filter, so the swap runs at full kernel speed. The child's own
/// syscalls are all trapped and therefore slow, so a flipper running inside it
/// (a filtered thread) rarely coincides with the old CONTINUE handler's
/// check→resolve window; a parent-side flipper hits it reliably. `body` is the
/// child's op loop.
fn run_guarded_protect_race(
    policy: &std::path::Path,
    sw: std::path::PathBuf,
    free: std::path::PathBuf,
    prot: std::path::PathBuf,
    body: impl FnOnce() -> i32,
) -> Option<Option<i32>> {
    use std::sync::atomic::AtomicBool;
    let (sup_sock, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        close_inherited(&[child_sock]);
        let traps = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, protect: true, ..Default::default() };
        let listener = match net_supervisor::guard_kernel::install_guard_filter_self(traps) {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if send_fd(child_sock, listener).is_err() {
            unsafe {
                libc::close(listener);
                libc::_exit(EXIT_SETUP_FAIL)
            };
        }
        unsafe { libc::close(listener) };
        let code = body();
        unsafe { libc::_exit(code) };
    }
    unsafe { libc::close(child_sock) };
    let listener = match recv_fd_from(sup_sock, child) {
        Ok(fd) => fd,
        Err(_) => {
            assert_eq!(reap(child), Some(EXIT_NO_SECCOMP), "tracee failed to send its listener");
            return None;
        }
    };
    let mut cfg = cfg("tcp:10.9.9.9/32:9");
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(policy).unwrap()));
    let server = std::thread::spawn(move || {
        let _ = net_supervisor::guard_kernel::run_guard_supervisor(listener, cfg);
        unsafe { libc::close(listener) };
    });
    let stop = Arc::new(AtomicBool::new(false));
    // The flipper stops however this ends, a failed wait's panic included.
    let stopper = StopOnDrop(stop.clone());
    let flip = spawn_parent_flipper(sw, free, prot, stop.clone());
    let test = std::thread::current().name().unwrap_or("race").to_string();
    let reaped = reap_within(child, wait_limit(), "waiting for the race's tracee (its op loop under the guard, the parent-side flipper running)");
    drop(stopper);
    let t0 = std::time::Instant::now();
    let _ = join_within(flip, wait_limit(), "the parent-side flipper, after its stop flag was set");
    let _ = join_within(server, wait_limit(), "the guard supervisor (run_guard_supervisor), after its tracee exited");
    // Where a slow run's time went (CI 2026-10-16: past 60 s in about one
    // run in nine): the tracee's wall time, its CPU and context switches,
    // and how long the flipper and the supervisor took to end after it.
    eprintln!("RACE TIMING ({test}): tracee {}; flipper and supervisor ended {:.1}s after", reaped.timing(), t0.elapsed().as_secs_f64());
    unsafe { libc::close(sup_sock) };
    Some(reaped.code())
}

const RACE_ITERS: usize = 4000;

#[test]
#[ignore]
fn a_rename_racing_a_swapped_parent_never_replaces_a_protected_file() {
    let (dir, own, free, policy) = protect_tree("rename-race");
    std::fs::write(own.join("canary"), "PROTECTED\n").unwrap();
    let sw = dir.join("sw");
    std::os::unix::fs::symlink(&free, &sw).unwrap();
    let evil = dir.join("evil");
    let (sw2, evil2) = (sw.clone(), evil.clone());
    let got = run_guarded_protect_race(&policy, sw.clone(), free.clone(), own.clone(), move || {
        let dst = sw2.join("canary");
        let (dc, ec) = (cstr(&dst), cstr(&evil2));
        let mut moved = 0;
        for _ in 0..RACE_ITERS {
            let _ = std::fs::write(&evil2, "PWNED\n");
            // rename(evil, sw/canary): sw flips between free and the protected dir.
            if unsafe { libc::rename(ec.as_ptr(), dc.as_ptr()) } == 0 {
                moved += 1;
            }
        }
        if moved == 0 { 20 } else { 0 }
    });
    let canary = std::fs::read_to_string(own.join("canary")).unwrap_or_default();
    let stray: Vec<String> = std::fs::read_dir(&own).map(|rd| rd.flatten().filter_map(|e| e.file_name().into_string().ok()).filter(|n| n != "canary").collect()).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0), "no rename ever landed (the race did not run)");
    assert_eq!(canary, "PROTECTED\n", "a swapped parent let a rename replace the protected file");
    assert!(stray.is_empty(), "a swapped parent let a rename create {stray:?} under the protected dir");
}

#[test]
#[ignore]
fn an_unlink_racing_a_swapped_parent_never_removes_a_protected_file() {
    let (dir, own, free, policy) = protect_tree("unlink-race");
    std::fs::write(own.join("canary"), "PROTECTED\n").unwrap();
    // A free/canary so the unlink has something to remove on the allowed side.
    std::fs::write(free.join("canary"), "").unwrap();
    let sw = dir.join("sw");
    std::os::unix::fs::symlink(&free, &sw).unwrap();
    let (free2, sw2) = (free.clone(), sw.clone());
    let got = run_guarded_protect_race(&policy, sw.clone(), free.clone(), own.clone(), move || {
        let target = sw2.join("canary");
        let tc = cstr(&target);
        for _ in 0..RACE_ITERS {
            // free/canary may be removed then recreated; the protected one must never go.
            unsafe { libc::unlink(tc.as_ptr()) };
            let _ = std::fs::write(free2.join("canary"), "");
        }
        0
    });
    let survived = own.join("canary").exists() && std::fs::read_to_string(own.join("canary")).unwrap_or_default() == "PROTECTED\n";
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0));
    assert!(survived, "a swapped parent let an unlink remove the protected file");
}

#[test]
#[ignore]
fn a_hard_link_racing_a_swapped_parent_never_links_a_protected_file() {
    use std::os::unix::fs::MetadataExt;
    let dir = std::env::temp_dir().join(format!("mandu-link-race-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let own = dir.join("own");
    let free = dir.join("free");
    std::fs::create_dir_all(&own).unwrap();
    std::fs::create_dir_all(&free).unwrap();
    std::fs::write(own.join("canary"), "PROTECTED\n").unwrap();
    std::fs::write(free.join("canary"), "FREE\n").unwrap();
    // A registered secret: a hard link to it (no race) is refused too.
    let secret = dir.join("secret.txt");
    let twin = dir.join("twin.txt");
    std::fs::write(&secret, "REAL-SECRET-BYTES\n").unwrap();
    std::fs::write(&twin, "TWIN\n").unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"agentExe":"","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}],"writeProtect":[{{"path":"{}","answer":"deny","label":"Mandu's own files"}}]}}"#,
            secret.display(), twin.display(), own.display(),
        ),
    )
    .unwrap();
    let prot_ino = std::fs::metadata(own.join("canary")).unwrap().ino();
    let sw = dir.join("sw");
    std::os::unix::fs::symlink(&free, &sw).unwrap();
    let alias = dir.join("alias");
    let alias2 = dir.join("alias-secret");
    let (sw2, alias_c, alias2_c, secret_c) = (sw.clone(), alias.clone(), alias2.clone(), secret.clone());
    let got = run_guarded_protect_race(&policy, sw.clone(), free.clone(), own.clone(), move || {
        // A hard link to the registered secret: refused (EACCES), never created.
        let sc = cstr(&secret_c);
        let a2 = cstr(&alias2_c);
        let secret_link = unsafe { libc::link(sc.as_ptr(), a2.as_ptr()) };
        if secret_link == 0 {
            return 30; // the secret was hard-linked to a new name
        }
        let src = sw2.join("canary");
        let (srcc, ac) = (cstr(&src), cstr(&alias_c));
        for _ in 0..RACE_ITERS {
            // link(sw/canary, alias): sw flips; a hit on the protected dir would
            // hard-link the protected file under a writable name.
            if unsafe { libc::link(srcc.as_ptr(), ac.as_ptr()) } == 0 {
                unsafe { libc::unlink(ac.as_ptr()) };
            }
        }
        0
    });
    let secret_after = std::fs::read_to_string(&secret).unwrap_or_default();
    let alias_ino = std::fs::metadata(&alias).ok().map(|m| m.ino());
    let alias2_exists = alias2.exists();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0), "30 = the registered secret was hard-linked to a new name");
    assert_eq!(secret_after, "REAL-SECRET-BYTES\n");
    assert!(!alias2_exists, "a hard link to the registered secret was created");
    assert_ne!(alias_ino, Some(prot_ino), "a swapped parent let a hard link reach the protected file's inode");
}

#[test]
#[ignore]
fn a_truncate_by_name_never_empties_a_secrets_real_file() {
    // The truncate/delete/write family is trapped only with `protect` on (as
    // the launcher always sets it in secrets mode); the secret refusal then
    // holds with no write-protect list at all.
    let dir = std::env::temp_dir().join(format!("mandu-trunc-name-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let secret = dir.join("secret.txt");
    let twin = dir.join("twin.txt");
    std::fs::write(&secret, "REAL-SECRET-BYTES\n").unwrap();
    std::fs::write(&twin, "TWIN\n").unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(&policy, format!(r#"{{"agentExe":"","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, secret.display(), twin.display())).unwrap();
    // A symlink to the secret: truncate follows it, so it would reach the real file.
    let sl = dir.join("sl");
    std::os::unix::fs::symlink(&secret, &sl).unwrap();
    let (secret2, sl2) = (secret.clone(), sl.clone());
    let code = run_guarded_protect(&policy, move || {
        let sc = cstr(&secret2);
        let slc = cstr(&sl2);
        // truncate the real path and a symlink to it: both must be EACCES.
        let e_direct = errno_of_rc(unsafe { libc::truncate(sc.as_ptr(), 0) });
        let e_link = errno_of_rc(unsafe { libc::truncate(slc.as_ptr(), 0) });
        if e_direct != libc::EACCES {
            10
        } else if e_link != libc::EACCES {
            11
        } else {
            0
        }
    });
    let after = std::fs::read_to_string(&secret).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    assert_eq!(code, Some(0), "10 = direct truncate not refused, 11 = truncate through a symlink not refused");
    assert_eq!(after, "REAL-SECRET-BYTES\n", "truncate emptied the secret's real file");
}

#[test]
#[ignore]
fn a_rename_onto_or_unlink_of_a_secrets_real_file_is_refused() {
    // The guard-only posture (no twin bind): an in-place writer (`sed -i`,
    // `perl -pi`, an editor's save) writes the placeholder text it read to a
    // temp file and renames it OVER the real path; `rm` removes it. Both
    // would destroy the real credential (write-protection.md, the name
    // family: a rename destination and a removed name that are a registered
    // secret's file are refused, 2026-10-02). Under the bind the same calls
    // meet the mount point (EBUSY). An object-store entry (git's, `kind:
    // object`) stays git's to replace or remove, and a symlink TO the secret
    // is only a name: replacing or removing it leaves the file alone.
    let dir = std::env::temp_dir().join(format!("mandu-rename-onto-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let secret = dir.join("credentials");
    let twin = dir.join("twin.txt");
    let pack = dir.join("pack-1.pack");
    let pack_twin = dir.join("pack-1.twin");
    std::fs::write(&secret, "REAL-SECRET-BYTES\n").unwrap();
    std::fs::write(&twin, "TWIN\n").unwrap();
    std::fs::write(&pack, "PACK\n").unwrap();
    std::fs::write(&pack_twin, "SANITIZED\n").unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"agentExe":"","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}},{{"path":"{}","twin":"{}","level":"no-model","kind":"object"}}]}}"#,
            secret.display(),
            twin.display(),
            pack.display(),
            pack_twin.display()
        ),
    )
    .unwrap();
    let sl = dir.join("sl");
    std::os::unix::fs::symlink(&secret, &sl).unwrap();
    let report = dir.join("report.txt");
    let (secret2, sl2, pack2, dir2, report2) = (secret.clone(), sl.clone(), pack.clone(), dir.clone(), report.clone());
    let code = run_guarded_protect(&policy, move || {
        let p = |n: &str| dir2.join(n);
        let rename = |a: &std::path::Path, b: &std::path::Path| errno_of_rc(unsafe { libc::rename(cstr(a).as_ptr(), cstr(b).as_ptr()) });
        // (1) the in-place writer's last step: a temp file renamed over the secret.
        std::fs::write(p("sedXYZ"), "PLACEHOLDER\n").unwrap();
        let e_onto = rename(&p("sedXYZ"), &secret2);
        // (2) renameat2 onto it (flags 0), relative to a directory fd.
        let dfd = unsafe { libc::open(cstr(&dir2).as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        let e_onto_at = errno_of_rc(unsafe {
            libc::syscall(libc::SYS_renameat2, dfd, cstr(std::path::Path::new("sedXYZ")).as_ptr(), dfd, cstr(std::path::Path::new("credentials")).as_ptr(), 0) as i32
        });
        // (3) unlink and unlinkat of the secret.
        let e_unlink = errno_of_rc(unsafe { libc::unlink(cstr(&secret2).as_ptr()) });
        let e_unlinkat = errno_of_rc(unsafe { libc::unlinkat(dfd, cstr(std::path::Path::new("credentials")).as_ptr(), 0) });
        unsafe { libc::close(dfd) };
        // (4) a symlink to the secret is a name of its own: replaced, then removed.
        std::fs::write(p("other"), "OTHER\n").unwrap();
        let e_onto_link = rename(&p("other"), &sl2);
        let link_replaced = std::fs::read_to_string(&sl2).unwrap_or_default() == "OTHER\n";
        let e_unlink_link = errno_of_rc(unsafe { libc::unlink(cstr(&sl2).as_ptr()) });
        // (5) an ordinary file: a rename over it and an unlink still work.
        std::fs::write(p("plain"), "OLD\n").unwrap();
        std::fs::write(p("plain.new"), "NEW\n").unwrap();
        let e_plain = rename(&p("plain.new"), &p("plain"));
        let plain_ok = std::fs::read_to_string(p("plain")).unwrap_or_default() == "NEW\n";
        let e_plain_rm = errno_of_rc(unsafe { libc::unlink(cstr(&p("plain")).as_ptr()) });
        // (6) git's object store (`kind: object`): replaced and removed as git does.
        std::fs::write(p("pack.tmp"), "PACK2\n").unwrap();
        let e_pack = rename(&p("pack.tmp"), &pack2);
        let e_pack_rm = errno_of_rc(unsafe { libc::unlink(cstr(&pack2).as_ptr()) });
        let _ = std::fs::write(
            &report2,
            format!("onto={e_onto} onto_at={e_onto_at} unlink={e_unlink} unlinkat={e_unlinkat} onto_link={e_onto_link}/{link_replaced} unlink_link={e_unlink_link} plain={e_plain}/{plain_ok} plain_rm={e_plain_rm} pack={e_pack} pack_rm={e_pack_rm}"),
        );
        if e_onto != libc::EACCES || e_onto_at != libc::EACCES {
            10
        } else if e_unlink != libc::EACCES || e_unlinkat != libc::EACCES {
            11
        } else if e_onto_link != 0 || !link_replaced || e_unlink_link != 0 {
            12
        } else if e_plain != 0 || !plain_ok || e_plain_rm != 0 {
            13
        } else if e_pack != 0 || e_pack_rm != 0 {
            14
        } else {
            0
        }
    });
    let after = std::fs::read_to_string(&secret).unwrap_or_default();
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    assert_eq!(after, "REAL-SECRET-BYTES\n", "the secret's real file was replaced or removed ({seen})");
    assert_eq!(code, Some(0), "10 = a rename onto the secret not refused, 11 = an unlink of it not refused, 12 = a symlink to it not handled as a name, 13 = an ordinary rename/unlink broken, 14 = git's object store refused: {seen}");
}

#[test]
#[ignore]
fn an_unprotected_rename_unlink_link_symlink_truncate_is_performed_on_behalf() {
    use std::os::unix::fs::MetadataExt;
    // A write-protect entry that no operation touches, only to enable the
    // perform path; every op below runs in a scratch dir with the CORRECT
    // effect and errno (the guard now performs them, never CONTINUEs).
    let dir = std::env::temp_dir().join(format!("mandu-perform-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let work = dir.join("work");
    let guarded = dir.join("guarded");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&guarded).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(&policy, format!(r#"{{"agentExe":"","writeProtect":[{{"path":"{}","answer":"deny","label":"Mandu's own files"}}]}}"#, guarded.display())).unwrap();
    let report = dir.join("report.txt");
    let (work2, report2) = (work.clone(), report.clone());
    let got = run_guarded_protect(&policy, move || {
        let p = |n: &str| work2.join(n);
        // rename
        std::fs::write(p("a"), "A").unwrap();
        let r_rename = errno_of_rc(unsafe { libc::rename(cstr(&p("a")).as_ptr(), cstr(&p("b")).as_ptr()) });
        let rename_ok = !p("a").exists() && std::fs::read_to_string(p("b")).unwrap_or_default() == "A";
        // unlink
        std::fs::write(p("c"), "C").unwrap();
        let r_unlink = errno_of_rc(unsafe { libc::unlink(cstr(&p("c")).as_ptr()) });
        let unlink_ok = !p("c").exists();
        // hard link: same inode
        std::fs::write(p("d"), "D").unwrap();
        let r_link = errno_of_rc(unsafe { libc::link(cstr(&p("d")).as_ptr(), cstr(&p("d2")).as_ptr()) });
        let link_ok = std::fs::metadata(p("d")).map(|m| m.ino()).ok() == std::fs::metadata(p("d2")).map(|m| m.ino()).ok();
        // symlink: created, target verbatim
        let r_symlink = errno_of_rc(unsafe { libc::symlink(cstr(std::path::Path::new("target-text")).as_ptr(), cstr(&p("sl")).as_ptr()) });
        let symlink_ok = std::fs::read_link(p("sl")).map(|t| t == std::path::Path::new("target-text")).unwrap_or(false);
        // truncate to a length
        std::fs::write(p("t"), "0123456789").unwrap();
        let r_trunc = errno_of_rc(unsafe { libc::truncate(cstr(&p("t")).as_ptr(), 4) });
        let trunc_ok = std::fs::metadata(p("t")).map(|m| m.len()).unwrap_or(0) == 4;
        // renameat2 RENAME_NOREPLACE onto an existing name → EEXIST
        std::fs::write(p("e"), "E").unwrap();
        std::fs::write(p("f"), "F").unwrap();
        let noreplace = unsafe {
            libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, cstr(&p("e")).as_ptr(), libc::AT_FDCWD, cstr(&p("f")).as_ptr(), libc::RENAME_NOREPLACE)
        };
        let noreplace_e = errno_of_rc(noreplace as i32);
        let noreplace_ok = std::fs::read_to_string(p("f")).unwrap_or_default() == "F";
        // renameat2 RENAME_EXCHANGE swaps two files
        std::fs::write(p("g"), "G").unwrap();
        std::fs::write(p("h"), "H").unwrap();
        let exch = unsafe {
            libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, cstr(&p("g")).as_ptr(), libc::AT_FDCWD, cstr(&p("h")).as_ptr(), libc::RENAME_EXCHANGE)
        };
        let exch_e = errno_of_rc(exch as i32);
        let exch_ok = std::fs::read_to_string(p("g")).unwrap_or_default() == "H" && std::fs::read_to_string(p("h")).unwrap_or_default() == "G";
        let _ = std::fs::write(&report2, format!(
            "rename={r_rename}/{rename_ok} unlink={r_unlink}/{unlink_ok} link={r_link}/{link_ok} symlink={r_symlink}/{symlink_ok} trunc={r_trunc}/{trunc_ok} noreplace={noreplace_e}/{noreplace_ok} exchange={exch_e}/{exch_ok}"));
        let all = rename_ok && r_rename == 0
            && unlink_ok && r_unlink == 0
            && link_ok && r_link == 0
            && symlink_ok && r_symlink == 0
            && trunc_ok && r_trunc == 0
            && noreplace_ok && noreplace_e == libc::EEXIST
            && exch_ok && exch_e == 0;
        if all { 0 } else { 1 }
    });
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0), "an unprotected name change was not performed correctly: {seen}");
    eprintln!("PERFORM-ON-BEHALF PASS: {seen}");
}

#[test]
#[ignore]
fn a_bind_racing_a_swapped_parent_never_binds_under_the_arbiter_socket_dir() {
    let (dir, own, free, policy) = protect_tree("bind-race");
    let sw = dir.join("sw");
    std::os::unix::fs::symlink(&free, &sw).unwrap();
    let (free2, sw2) = (free.clone(), sw.clone());
    let got = run_guarded_protect_race(&policy, sw.clone(), free.clone(), own.clone(), move || {
        let target = sw2.join("arbiter.sock");
        let mut bound_free = 0;
        for _ in 0..RACE_ITERS {
            unsafe {
                let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
                if s < 0 {
                    continue;
                }
                let (addr, len) = unix_addr(Some(&target), None);
                if libc::bind(s, &addr as *const libc::sockaddr_un as *const libc::sockaddr, len) == 0 {
                    bound_free += 1;
                    // Clean up the free-side socket so the next bind can reuse the name.
                    let _ = std::fs::remove_file(free2.join("arbiter.sock"));
                }
                libc::close(s);
            }
        }
        // At least one bind must have hit the free side (the race actually ran).
        if bound_free == 0 { 20 } else { 0 }
    });
    let leaked = own.join("arbiter.sock").exists();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0), "no bind hit the free side (the race did not run)");
    assert!(!leaked, "a swapped parent let a bind create a socket under the protected dir");
}

const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;

/// Child: restrict itself with a ruleset that handles a filesystem right (file
/// removal) and grants nothing. Because REFER is NOT handled, Landlock then
/// forbids every rename that changes a file's parent directory — the tracee's
/// own cross-directory rename is denied by its own ruleset. ABI 1.
fn child_landlock_no_cross_dir_rename() -> bool {
    #[repr(C)]
    struct Attr { handled_access_fs: u64 }
    unsafe {
        let attr = Attr { handled_access_fs: LANDLOCK_ACCESS_FS_REMOVE_FILE };
        let rs = libc::syscall(SYS_LANDLOCK_CREATE_RULESET, &attr as *const Attr, std::mem::size_of::<Attr>(), 0u32);
        if rs < 0 {
            return false;
        }
        let ok = libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, rs, 0u32) == 0;
        libc::close(rs as i32);
        ok
    }
}

#[test]
#[ignore]
fn a_rename_a_tracees_own_landlock_ruleset_forbids_stays_forbidden() {
    // The guard performs the rename under a mirror of the tracee's Landlock
    // domain, so a rename the tracee's own ruleset forbids is refused, not
    // widened by the guard performing it.
    if landlock_abi() < 1 {
        eprintln!("SKIP: no Landlock on this kernel");
        return;
    }
    let dir = std::env::temp_dir().join(format!("mandu-ll-refer-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let a = dir.join("a");
    let b = dir.join("b");
    let guarded = dir.join("guarded");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::create_dir_all(&guarded).unwrap();
    std::fs::write(a.join("x"), "X").unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(&policy, format!(r#"{{"agentExe":"","writeProtect":[{{"path":"{}","answer":"deny","label":"Mandu's own files"}}]}}"#, guarded.display())).unwrap();
    let (a2, b2) = (a.clone(), b.clone());
    let got = run_guarded_protect(&policy, move || {
        if !child_landlock_no_cross_dir_rename() {
            return 64;
        }
        // A cross-directory rename the ruleset forbids.
        let e = errno_of_rc(unsafe { libc::rename(cstr(&a2.join("x")).as_ptr(), cstr(&b2.join("x")).as_ptr()) });
        if e == libc::EACCES { 0 } else { 10 }
    });
    let src_kept = a.join("x").exists();
    let dst_absent = !b.join("x").exists();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    if code == Some(64) {
        eprintln!("SKIP: could not restrict with Landlock here");
        return;
    }
    assert_eq!(code, Some(0), "10 = the rename the tracee's own ruleset forbids was NOT refused (the guard widened it)");
    assert!(src_kept && dst_absent, "the forbidden rename still moved the file");
}

#[test]
#[ignore]
fn guard_refuses_changes_under_write_protected_paths_through_a_symlinked_parent() {
    // The deterministic half of the parent-swap close: a rename, unlink, create
    // and truncate reached through a SYMLINKED parent directory that leads to
    // the protected dir is refused, because the guard resolves and pins the
    // parent in the tracee's view before it acts.
    let (dir, own, _free, policy) = protect_tree("wp-symlink");
    std::fs::write(own.join("canary"), "PROTECTED\n").unwrap();
    // `sldir` is a symlink to the protected directory.
    let sldir = dir.join("sldir");
    std::os::unix::fs::symlink(&own, &sldir).unwrap();
    let evil = dir.join("evil");
    std::fs::write(&evil, "PWNED\n").unwrap();
    let (sldir2, evil2) = (sldir.clone(), evil.clone());
    let got = run_guarded_protect(&policy, move || {
        let through = |n: &str| sldir2.join(n);
        let checks: Vec<(i32, i32)> = vec![
            (errno_of_rc(unsafe { libc::rename(cstr(&evil2).as_ptr(), cstr(&through("canary")).as_ptr()) }), libc::EACCES),
            (errno_of_rc(unsafe { libc::unlink(cstr(&through("canary")).as_ptr()) }), libc::EACCES),
            (errno_of_fd(unsafe { libc::open(cstr(&through("new")).as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644) }), libc::EACCES),
            (errno_of_rc(unsafe { libc::truncate(cstr(&through("canary")).as_ptr(), 0) }), libc::EACCES),
            (errno_of_rc(unsafe { libc::symlink(cstr(&evil2).as_ptr(), cstr(&through("link")).as_ptr()) }), libc::EACCES),
        ];
        match checks.iter().position(|(got, want)| got != want) {
            None => 0,
            Some(i) => 10 + i as i32,
        }
    });
    let canary = std::fs::read_to_string(own.join("canary")).unwrap_or_default();
    let created = own.join("new").exists() || own.join("link").exists();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0), "check #{} (10 + index) got an unexpected answer through the symlinked parent", code.unwrap_or(-1) - 10);
    assert_eq!(canary, "PROTECTED\n", "a change reached the protected file through a symlinked parent");
    assert!(!created, "a name was created under the protected dir through a symlinked parent");
}

// ── write-protection.md §4 closed (2026-09-29): mknod and the chmod family ────

/// `fchmodat2(dirfd, path, mode, flags)`: 452 on every arch (Linux 6.6).
const SYS_FCHMODAT2: libc::c_long = 452;

fn mode_of(p: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(p).map(|m| m.permissions().mode() & 0o7777).unwrap_or(0)
}

/// Every way of changing a protected file's mode, and of making a node under
/// a protected name, is refused; a registered secret's mode is not changed;
/// a mode change that changes nothing still runs.
#[test]
#[ignore]
fn guard_refuses_a_chmod_or_mknod_of_a_protected_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("mandu-wp-mode-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let own = dir.join("own");
    std::fs::create_dir_all(&own).unwrap();
    // A hook-like script, not executable: `chmod +x` would arm it.
    let hook = own.join("pre-commit");
    std::fs::write(&hook, "#!/bin/sh\necho armed\n").unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o644)).unwrap();
    // A symlink elsewhere that leads to it.
    let sl = dir.join("sl");
    std::os::unix::fs::symlink(&hook, &sl).unwrap();
    // A registered secret, owner-only.
    let secret = dir.join("secret.key");
    let twin = dir.join("twin.key");
    std::fs::write(&secret, "REAL-SECRET-BYTES\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&twin, "TWIN\n").unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"agentExe":"","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}],"writeProtect":[{{"path":"{}","answer":"deny","label":"Mandu's own files"}}]}}"#,
            secret.display(),
            twin.display(),
            own.display()
        ),
    )
    .unwrap();
    let (hook_c, sl_c, secret_c) = (cstr(&hook), cstr(&sl), cstr(&secret));
    let (fifo_c, reg_c, sock_c) = (cstr(&own.join("fifo")), cstr(&own.join("reg")), cstr(&own.join("sock")));
    let got = run_guarded_protect(&policy, || unsafe {
        let ro = libc::open(hook_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        let mut checks: Vec<(i32, i32)> = vec![
            (errno_of_rc(libc::chmod(hook_c.as_ptr(), 0o755)), libc::EACCES),
            (errno_of_rc(libc::syscall(libc::SYS_fchmodat, libc::AT_FDCWD, hook_c.as_ptr(), 0o755) as i32), libc::EACCES),
            // A read-only descriptor is enough for fchmod: judged by the file.
            (if ro < 0 { -1 } else { errno_of_rc(libc::fchmod(ro, 0o755)) }, libc::EACCES),
            // Through a symlink elsewhere.
            (errno_of_rc(libc::chmod(sl_c.as_ptr(), 0o755)), libc::EACCES),
            // A registered secret opened to others.
            (errno_of_rc(libc::chmod(secret_c.as_ptr(), 0o644)), libc::EACCES),
            // The protected file's own mode again: nothing changes, it runs.
            (errno_of_rc(libc::chmod(hook_c.as_ptr(), 0o644)), 0),
            // Nodes under the protected directory.
            (errno_of_rc(libc::mknodat(libc::AT_FDCWD, fifo_c.as_ptr(), libc::S_IFIFO | 0o644, 0)), libc::EACCES),
            (errno_of_rc(libc::mknodat(libc::AT_FDCWD, reg_c.as_ptr(), libc::S_IFREG | 0o644, 0)), libc::EACCES),
            (errno_of_rc(libc::mknodat(libc::AT_FDCWD, sock_c.as_ptr(), libc::S_IFSOCK | 0o644, 0)), libc::EACCES),
        ];
        // fchmodat2 (Linux 6.6): with AT_SYMLINK_NOFOLLOW, and AT_EMPTY_PATH on
        // the read-only descriptor. ENOSYS on an older kernel (nothing to trap).
        let f2 = libc::syscall(SYS_FCHMODAT2, libc::AT_FDCWD, hook_c.as_ptr(), 0o755, libc::AT_SYMLINK_NOFOLLOW) as i32;
        let f2e = errno_of_rc(f2);
        if f2e != libc::ENOSYS {
            checks.push((f2e, libc::EACCES));
            checks.push((errno_of_rc(libc::syscall(SYS_FCHMODAT2, ro, b"\0".as_ptr(), 0o755, libc::AT_EMPTY_PATH) as i32), libc::EACCES));
        }
        #[cfg(target_arch = "x86_64")]
        checks.push((errno_of_rc(libc::syscall(libc::SYS_mknod, fifo_c.as_ptr(), libc::S_IFIFO | 0o644, 0) as i32), libc::EACCES));
        match checks.iter().position(|(got, want)| got != want) {
            None => 0,
            Some(i) => 10 + i as i32,
        }
    });
    let hook_mode = mode_of(&hook);
    let secret_mode = mode_of(&secret);
    let created: Vec<String> = std::fs::read_dir(&own).map(|rd| rd.flatten().filter_map(|e| e.file_name().into_string().ok()).filter(|n| n != "pre-commit").collect()).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0), "check #{} (10 + index) got an unexpected answer", code.unwrap_or(-1) - 10);
    assert_eq!(hook_mode, 0o644, "the protected script's mode changed");
    assert_eq!(secret_mode, 0o600, "the registered secret's mode changed");
    assert!(created.is_empty(), "a node was made under the protected dir: {created:?}");
}

/// The positive: an unprotected chmod / fchmod / fchmodat2 / mknod and a bind
/// the guard performs behave like the tracee's own call — the effect, the
/// errno, the tracee's umask on what is created, and a bind whose leaf only
/// fits `sun_path` relative to its directory (write-protection.md §4's old
/// `/proc/self/fd/<pin>/<leaf>` overflow).
#[test]
#[ignore]
fn an_unprotected_chmod_mknod_and_bind_are_performed_like_the_tracees_own() {
    use std::os::unix::fs::FileTypeExt;
    let dir = std::env::temp_dir().join(format!("mandu-perform-mode-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let work = dir.join("work");
    let guarded = dir.join("guarded");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&guarded).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(&policy, format!(r#"{{"agentExe":"","writeProtect":[{{"path":"{}","answer":"deny","label":"Mandu's own files"}}]}}"#, guarded.display())).unwrap();
    // The kernel's own answer for fchmodat2(AT_SYMLINK_NOFOLLOW) on a symlink,
    // taken outside the guard, to compare the performed one against.
    let ref_link = dir.join("ref-link");
    std::os::unix::fs::symlink("nowhere", &ref_link).unwrap();
    let ref_nofollow = errno_of_rc(unsafe { libc::syscall(SYS_FCHMODAT2, libc::AT_FDCWD, cstr(&ref_link).as_ptr(), 0o700, libc::AT_SYMLINK_NOFOLLOW) as i32 });
    let report = dir.join("report.txt");
    let (work2, report2) = (work.clone(), report.clone());
    let got = run_guarded_protect(&policy, move || {
        let p = |n: &str| work2.join(n);
        let c = |n: &str| cstr(&p(n));
        let mut r: Vec<(&str, i32, i32, bool)> = Vec::new(); // (name, got errno, want errno, effect ok)
        unsafe { libc::umask(0o027) };
        // chmod by name
        std::fs::write(p("s"), "x").unwrap();
        r.push(("chmod", errno_of_rc(unsafe { libc::chmod(c("s").as_ptr(), 0o755) }), 0, mode_of(&p("s")) == 0o755));
        // fchmod on a read-only descriptor
        std::fs::write(p("f"), "x").unwrap();
        let ro = unsafe { libc::open(c("f").as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        r.push(("fchmod", errno_of_rc(unsafe { libc::fchmod(ro, 0o711) }), 0, mode_of(&p("f")) == 0o711));
        // fchmod on an O_PATH descriptor: the kernel's EBADF
        let op = unsafe { libc::open(c("f").as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        r.push(("fchmod-opath", errno_of_rc(unsafe { libc::fchmod(op, 0o700) }), libc::EBADF, mode_of(&p("f")) == 0o711));
        r.push(("fchmod-badfd", errno_of_rc(unsafe { libc::fchmod(987, 0o700) }), libc::EBADF, true));
        r.push(("chmod-missing", errno_of_rc(unsafe { libc::chmod(c("missing").as_ptr(), 0o700) }), libc::ENOENT, true));
        // glibc's AT_SYMLINK_NOFOLLOW fallback: an O_PATH descriptor, then
        // chmod of /proc/self/fd/N (the tracee's own descriptor, not the guard's).
        let via = cstr(std::path::Path::new(&format!("/proc/self/fd/{op}")));
        r.push(("chmod-proc-self-fd", errno_of_rc(unsafe { libc::chmod(via.as_ptr(), 0o640) }), 0, mode_of(&p("f")) == 0o640));
        // fchmodat2, when the kernel has it
        std::fs::write(p("g"), "x").unwrap();
        let f2 = errno_of_rc(unsafe { libc::syscall(SYS_FCHMODAT2, libc::AT_FDCWD, c("g").as_ptr(), 0o700, libc::AT_SYMLINK_NOFOLLOW) as i32 });
        if f2 != libc::ENOSYS {
            r.push(("fchmodat2-nofollow", f2, 0, mode_of(&p("g")) == 0o700));
            let gfd = unsafe { libc::open(c("g").as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            r.push(("fchmodat2-empty-path", errno_of_rc(unsafe { libc::syscall(SYS_FCHMODAT2, gfd, b"\0".as_ptr(), 0o604, libc::AT_EMPTY_PATH) as i32 }), 0, mode_of(&p("g")) == 0o604));
            r.push(("fchmodat2-bad-flags", errno_of_rc(unsafe { libc::syscall(SYS_FCHMODAT2, libc::AT_FDCWD, c("g").as_ptr(), 0o700, libc::AT_REMOVEDIR) as i32 }), libc::EINVAL, mode_of(&p("g")) == 0o604));
            std::os::unix::fs::symlink("nowhere", p("link")).unwrap();
            r.push(("fchmodat2-symlink", errno_of_rc(unsafe { libc::syscall(SYS_FCHMODAT2, libc::AT_FDCWD, c("link").as_ptr(), 0o700, libc::AT_SYMLINK_NOFOLLOW) as i32 }), ref_nofollow, true));
        }
        // mknod: a FIFO and a regular file, under the tracee's umask 027
        let fifo = errno_of_rc(unsafe { libc::mknodat(libc::AT_FDCWD, c("fifo").as_ptr(), libc::S_IFIFO | 0o666, 0) });
        let fifo_ok = std::fs::symlink_metadata(p("fifo")).map(|m| m.file_type().is_fifo()).unwrap_or(false) && mode_of(&p("fifo")) == 0o640;
        r.push(("mknod-fifo", fifo, 0, fifo_ok));
        let reg = errno_of_rc(unsafe { libc::mknodat(libc::AT_FDCWD, c("reg").as_ptr(), libc::S_IFREG | 0o666, 0) });
        r.push(("mknod-reg", reg, 0, std::fs::symlink_metadata(p("reg")).map(|m| m.is_file()).unwrap_or(false) && mode_of(&p("reg")) == 0o640));
        r.push(("mknod-exists", errno_of_rc(unsafe { libc::mknodat(libc::AT_FDCWD, c("reg").as_ptr(), libc::S_IFIFO | 0o666, 0) }), libc::EEXIST, true));
        // bind: the socket file carries the tracee's umask (0777 & ~027)
        let bind_to = |path: &std::path::Path| -> i32 {
            unsafe {
                let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
                let (addr, len) = unix_addr(Some(path), None);
                let e = errno_of_rc(libc::bind(s, &addr as *const libc::sockaddr_un as *const libc::sockaddr, len));
                libc::close(s);
                e
            }
        };
        r.push(("bind-umask", bind_to(&p("sock")), 0, mode_of(&p("sock")) == 0o750));
        // bind by a long leaf, relative to the cwd: fits the tracee's
        // sun_path, but "/proc/self/fd/<pin>/" + leaf would not.
        let leaf = "L".repeat(100);
        unsafe { libc::chdir(cstr(&work2).as_ptr()) };
        r.push(("bind-long-leaf", bind_to(std::path::Path::new(&leaf)), 0, std::fs::symlink_metadata(p(&leaf)).map(|m| m.file_type().is_socket()).unwrap_or(false)));
        let text: Vec<String> = r.iter().map(|(n, g, w, ok)| format!("{n}={g}/{w}/{ok}")).collect();
        let _ = std::fs::write(&report2, text.join(" "));
        if r.iter().all(|(_, g, w, ok)| g == w && *ok) { 0 } else { 1 }
    });
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0), "a chmod / mknod / bind was not performed like the tracee's own (name=got/want/effect): {seen}");
    eprintln!("MODE-NODE-BIND PASS: {seen}");
}

/// The chmod race: `sw` flips between a scratch dir and the protected one
/// while the tracee chmods `sw/canary`. Judged by name and CONTINUEd, a swap
/// between the check and the kernel's own resolve would arm the protected
/// file; pinned and performed, it never changes.
#[test]
#[ignore]
fn a_chmod_racing_a_swapped_parent_never_changes_a_protected_file() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, own, free, policy) = protect_tree("chmod-race");
    std::fs::write(own.join("canary"), "PROTECTED\n").unwrap();
    std::fs::set_permissions(own.join("canary"), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(free.join("canary"), "FREE\n").unwrap();
    let sw = dir.join("sw");
    std::os::unix::fs::symlink(&free, &sw).unwrap();
    let sw2 = sw.clone();
    let got = run_guarded_protect_race(&policy, sw.clone(), free.clone(), own.clone(), move || {
        let tc = cstr(&sw2.join("canary"));
        let mut changed = 0;
        for i in 0..RACE_ITERS {
            // Alternate so every call on the free side is a real change.
            let m = if i % 2 == 0 { 0o755 } else { 0o711 };
            if unsafe { libc::chmod(tc.as_ptr(), m) } == 0 {
                changed += 1;
            }
        }
        if changed == 0 { 20 } else { 0 }
    });
    let mode = mode_of(&own.join("canary"));
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0), "no chmod ever landed (the race did not run)");
    assert_eq!(mode, 0o644, "a swapped parent let a chmod change the protected file's mode");
}

/// The mknod race: as the chmod race, a FIFO made at `sw/fifo`.
#[test]
#[ignore]
fn a_mknod_racing_a_swapped_parent_never_makes_a_node_in_a_protected_dir() {
    let (dir, own, free, policy) = protect_tree("mknod-race");
    let sw = dir.join("sw");
    std::os::unix::fs::symlink(&free, &sw).unwrap();
    let (sw2, free2) = (sw.clone(), free.clone());
    let got = run_guarded_protect_race(&policy, sw.clone(), free.clone(), own.clone(), move || {
        let tc = cstr(&sw2.join("fifo"));
        let mut made = 0;
        for _ in 0..RACE_ITERS {
            if unsafe { libc::mknodat(libc::AT_FDCWD, tc.as_ptr(), libc::S_IFIFO | 0o644, 0) } == 0 {
                made += 1;
                let _ = std::fs::remove_file(free2.join("fifo"));
            }
        }
        if made == 0 { 20 } else { 0 }
    });
    let leaked = std::fs::symlink_metadata(own.join("fifo")).is_ok();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0), "no mknod ever landed (the race did not run)");
    assert!(!leaked, "a swapped parent let a mknod make a node under the protected dir");
}

// ── write-protection.md §4 (closed 2026-09-29): extended attributes ─────────

use net_supervisor::xattr_change::{acl_value, ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_USER, ACL_USER_OBJ};

/// `ACL_UNDEFINED_ID`: the id of an owner, group-owner, mask or other entry.
const NO_ID: u32 = u32::MAX;
const ACL_ACCESS: &str = "system.posix_acl_access";
const ACL_DEFAULT: &str = "system.posix_acl_default";

/// A MINIMAL access ACL: exactly a mode (`setfacl -m u::rwx` on a file with
/// no ACL writes this).
fn minimal_acl(mode: u32) -> Vec<u8> {
    acl_value(&[(ACL_USER_OBJ, ((mode >> 6) & 7) as u16, NO_ID), (ACL_GROUP_OBJ, ((mode >> 3) & 7) as u16, NO_ID), (ACL_OTHER, (mode & 7) as u16, NO_ID)])
}

/// An ACL that opens the file to a named user and group (`setfacl -m
/// u:<uid>:r,g:<gid>:r`).
fn named_acl(uid: u32, gid: u32) -> Vec<u8> {
    acl_value(&[(ACL_USER_OBJ, 6, NO_ID), (ACL_USER, 4, uid), (ACL_GROUP_OBJ, 4, NO_ID), (ACL_GROUP, 4, gid), (ACL_MASK, 4, NO_ID), (ACL_OTHER, 0, NO_ID)])
}

fn cname(n: &str) -> std::ffi::CString {
    std::ffi::CString::new(n).unwrap()
}

fn setx(p: &std::path::Path, name: &str, v: &[u8], flags: i32) -> i32 {
    errno_of_rc(unsafe { libc::setxattr(cstr(p).as_ptr(), cname(name).as_ptr(), v.as_ptr() as *const libc::c_void, v.len(), flags) })
}

fn getx(p: &std::path::Path, name: &str) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; 65536];
    let n = unsafe { libc::lgetxattr(cstr(p).as_ptr(), cname(name).as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// Why this filesystem cannot run the attribute tests (user attributes or
/// POSIX ACLs unsupported: tmpfs before 6.6, a mount without `acl`), probed
/// outside any guard. `None` = both work.
fn xattr_unsupported(dir: &std::path::Path) -> Option<String> {
    let probe = dir.join("xattr-probe");
    std::fs::write(&probe, "x").unwrap();
    let user = setx(&probe, "user.probe", b"1", 0);
    let acl = setx(&probe, ACL_ACCESS, &minimal_acl(0o640), 0);
    let _ = std::fs::remove_file(&probe);
    match (user, acl) {
        (0, 0) => None,
        (u, a) => Some(format!("user attributes errno {u}, POSIX ACLs errno {a} on {}", dir.display())),
    }
}

/// `setfacl`-style changes of a protected hook and of a registered secret are
/// refused: the owner entry that arms the hook (`u::rwx`), a named user or
/// group, a default ACL on the protected directory, a `user.*` attribute, and
/// a removal, by path, by `lsetxattr`, through a symlink elsewhere and by a
/// read-only descriptor (`fsetxattr` needs no write access). A change that
/// changes nothing (the file's own minimal ACL, its own value, a removal of
/// an absent name) still runs. Fails on a guard that does not trap the
/// family.
#[test]
#[ignore]
fn guard_refuses_an_acl_or_xattr_change_of_a_protected_or_secret_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("mandu-wp-xattr-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let own = dir.join("own");
    std::fs::create_dir_all(&own).unwrap();
    if let Some(why) = xattr_unsupported(&dir) {
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("SKIP: {why}");
        return;
    }
    let hook = own.join("pre-commit");
    std::fs::write(&hook, "#!/bin/sh\necho armed\n").unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(setx(&hook, "user.kept", b"orig", 0), 0);
    let sl = dir.join("sl");
    std::os::unix::fs::symlink(&hook, &sl).unwrap();
    let secret = dir.join("secret.key");
    let twin = dir.join("twin.key");
    std::fs::write(&secret, "REAL-SECRET-BYTES\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&twin, "TWIN\n").unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"agentExe":"","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}],"writeProtect":[{{"path":"{}","answer":"deny","label":"Mandu's own files"}}]}}"#,
            secret.display(),
            twin.display(),
            own.display()
        ),
    )
    .unwrap();
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let (hook2, sl2, secret2, own2) = (hook.clone(), sl.clone(), secret.clone(), own.clone());
    let got = run_guarded_protect(&policy, move || unsafe {
        let arm = minimal_acl(0o755);
        let named = named_acl(uid, gid);
        let hook_c = cstr(&hook2);
        let ro = libc::open(hook_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        let fset = |fd: i32, name: &str, v: &[u8]| errno_of_rc(libc::fsetxattr(fd, cname(name).as_ptr(), v.as_ptr() as *const libc::c_void, v.len(), 0));
        let lset = |p: &std::path::Path, name: &str, v: &[u8]| errno_of_rc(libc::lsetxattr(cstr(p).as_ptr(), cname(name).as_ptr(), v.as_ptr() as *const libc::c_void, v.len(), 0));
        let mut checks: Vec<(i32, i32)> = vec![
            // setfacl -m u::rwx: the hook armed.
            (setx(&hook2, ACL_ACCESS, &arm, 0), libc::EACCES),
            (lset(&hook2, ACL_ACCESS, &arm), libc::EACCES),
            (if ro < 0 { -1 } else { fset(ro, ACL_ACCESS, &arm) }, libc::EACCES),
            (setx(&sl2, ACL_ACCESS, &arm, 0), libc::EACCES),
            // A named user and group opened to it.
            (setx(&hook2, ACL_ACCESS, &named, 0), libc::EACCES),
            // A default ACL on the protected directory itself.
            (setx(&own2, ACL_DEFAULT, &named, 0), libc::EACCES),
            // Any other name: a user attribute set, changed and removed.
            (setx(&hook2, "user.new", b"v", 0), libc::EACCES),
            (setx(&hook2, "user.kept", b"changed", 0), libc::EACCES),
            (errno_of_rc(libc::removexattr(hook_c.as_ptr(), cname("user.kept").as_ptr())), libc::EACCES),
            (if ro < 0 { -1 } else { errno_of_rc(libc::fremovexattr(ro, cname("user.kept").as_ptr())) }, libc::EACCES),
            // A registered secret opened to another local user, or tagged.
            (setx(&secret2, ACL_ACCESS, &named, 0), libc::EACCES),
            (setx(&secret2, ACL_ACCESS, &minimal_acl(0o644), 0), libc::EACCES),
            (setx(&secret2, "user.new", b"v", 0), libc::EACCES),
            // Changes that change nothing run: the hook's own mode as an
            // ACL (an editor re-applying it), its own attribute value, and
            // a removal of a name it does not have (the kernel's ENODATA).
            (setx(&hook2, ACL_ACCESS, &minimal_acl(0o644), 0), 0),
            (setx(&hook2, "user.kept", b"orig", 0), 0),
            (errno_of_rc(libc::removexattr(hook_c.as_ptr(), cname("user.absent").as_ptr())), libc::ENODATA),
        ];
        // setxattrat / removexattrat (Linux 6.13), when the kernel has them.
        let args: [u64; 2] = [arm.as_ptr() as u64, arm.len() as u64];
        let at = errno_of_rc(libc::syscall(463, libc::AT_FDCWD, hook_c.as_ptr(), 0, cname(ACL_ACCESS).as_ptr(), args.as_ptr(), 16usize) as i32);
        if at != libc::ENOSYS {
            checks.push((at, libc::EACCES));
            checks.push((errno_of_rc(libc::syscall(466, libc::AT_FDCWD, hook_c.as_ptr(), 0, cname("user.kept").as_ptr()) as i32), libc::EACCES));
        }
        match checks.iter().position(|(got, want)| got != want) {
            None => 0,
            Some(i) => 10 + i as i32,
        }
    });
    let hook_mode = mode_of(&hook);
    let hook_acl = getx(&hook, ACL_ACCESS);
    let hook_user = (getx(&hook, "user.kept"), getx(&hook, "user.new"));
    let own_default = getx(&own, ACL_DEFAULT);
    let secret_mode = mode_of(&secret);
    let secret_attrs = (getx(&secret, ACL_ACCESS), getx(&secret, "user.new"));
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0), "check #{} (10 + index) got an unexpected answer", code.unwrap_or(-1) - 10);
    assert_eq!(hook_mode, 0o644, "the protected hook's mode changed (armed through its ACL)");
    assert_eq!(hook_acl, Err(libc::ENODATA), "the protected hook carries an access ACL");
    assert_eq!(hook_user, (Ok(b"orig".to_vec()), Err(libc::ENODATA)), "the protected hook's user attributes changed");
    assert_eq!(own_default, Err(libc::ENODATA), "the protected directory carries a default ACL");
    assert_eq!(secret_mode, 0o600, "the registered secret's mode changed");
    assert_eq!(secret_attrs, (Err(libc::ENODATA), Err(libc::ENODATA)), "the registered secret's attributes changed");
}

/// Every attribute call in `dir`, and what it left: `name=errno` for each
/// call, then each file's mode and attributes. Run once outside the guard
/// and once under it, the two reports must be equal: the guard performs an
/// unprotected change exactly as the kernel would (effect and errno, in the
/// kernel's order of checks).
fn xattr_battery(dir: &std::path::Path) -> String {
    let p = |n: &str| dir.join(n);
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let mut r: Vec<String> = Vec::new();
    let mut note = |n: &str, e: i32| r.push(format!("{n}={e}"));
    std::fs::write(p("f"), "x").unwrap();
    std::fs::create_dir_all(p("d")).unwrap();
    let _ = std::os::unix::fs::symlink("f", p("link"));
    let fc = cstr(&p("f"));
    let lc = cstr(&p("link"));
    unsafe {
        note("set", setx(&p("f"), "user.a", b"one", 0));
        note("set-create-exists", setx(&p("f"), "user.a", b"two", 1));
        note("set-replace-absent", setx(&p("f"), "user.b", b"two", 2));
        note("set-bad-flags", setx(&p("f"), "user.a", b"two", 4));
        note("set-empty-name", setx(&p("f"), "", b"two", 0));
        note("set-long-name", setx(&p("f"), &format!("user.{}", "n".repeat(260)), b"two", 0));
        let big = vec![0u8; 65537];
        note("set-too-big", setx(&p("f"), "user.a", &big, 0));
        note("set-null-value", errno_of_rc(libc::setxattr(fc.as_ptr(), cname("user.a").as_ptr(), std::ptr::null(), 5, 0)));
        note("set-empty-value", setx(&p("f"), "user.empty", b"", 0));
        note("set-bogus-namespace", setx(&p("f"), "bogus.a", b"v", 0));
        note("set-trusted", setx(&p("f"), "trusted.a", b"v", 0));
        note("set-missing", setx(&p("missing"), "user.a", b"v", 0));
        note("set-follows-link", setx(&p("link"), "user.via", b"link", 0));
        note("lset-on-symlink", errno_of_rc(libc::lsetxattr(lc.as_ptr(), cname("user.a").as_ptr(), b"v".as_ptr() as *const libc::c_void, 1, 0)));
        note("set-dir", setx(&p("d"), "user.d", b"dir", 0));
        let ro = libc::open(fc.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        note("fset-read-only-fd", errno_of_rc(libc::fsetxattr(ro, cname("user.fd").as_ptr(), b"fd".as_ptr() as *const libc::c_void, 2, 0)));
        let op = libc::open(fc.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
        note("fset-opath", errno_of_rc(libc::fsetxattr(op, cname("user.op").as_ptr(), b"op".as_ptr() as *const libc::c_void, 2, 0)));
        note("fset-bad-fd", errno_of_rc(libc::fsetxattr(987, cname("user.op").as_ptr(), b"op".as_ptr() as *const libc::c_void, 2, 0)));
        // POSIX ACLs: a mode change by another name, a named user and group,
        // a default ACL, a malformed value, a symlink's.
        note("acl-minimal", setx(&p("f"), ACL_ACCESS, &minimal_acl(0o751), 0));
        std::fs::write(p("g"), "x").unwrap();
        note("acl-named", setx(&p("g"), ACL_ACCESS, &named_acl(uid, gid), 0));
        note("acl-default", setx(&p("d"), ACL_DEFAULT, &named_acl(uid, gid), 0));
        note("acl-malformed", setx(&p("g"), ACL_ACCESS, b"\x02\0\0\0\x01", 0));
        let m = minimal_acl(0o700);
        note("acl-on-symlink", errno_of_rc(libc::lsetxattr(lc.as_ptr(), cname(ACL_ACCESS).as_ptr(), m.as_ptr() as *const libc::c_void, m.len(), 0)));
        // Removals.
        note("remove", errno_of_rc(libc::removexattr(fc.as_ptr(), cname("user.a").as_ptr())));
        note("remove-absent", errno_of_rc(libc::removexattr(fc.as_ptr(), cname("user.a").as_ptr())));
        note("fremove", errno_of_rc(libc::fremovexattr(ro, cname("user.fd").as_ptr())));
        note("fremove-opath", errno_of_rc(libc::fremovexattr(op, cname("user.via").as_ptr())));
        note("lremove-on-symlink", errno_of_rc(libc::lremovexattr(lc.as_ptr(), cname("user.via").as_ptr())));
        // setxattrat / removexattrat (Linux 6.13; ENOSYS before it).
        let v = b"at";
        let args: [u64; 2] = [v.as_ptr() as u64, 2];
        note("setxattrat", errno_of_rc(libc::syscall(463, libc::AT_FDCWD, fc.as_ptr(), 0, cname("user.at").as_ptr(), args.as_ptr(), 16usize) as i32));
        note("setxattrat-short-args", errno_of_rc(libc::syscall(463, libc::AT_FDCWD, fc.as_ptr(), 0, cname("user.at").as_ptr(), args.as_ptr(), 8usize) as i32));
        note("setxattrat-bad-at-flags", errno_of_rc(libc::syscall(463, libc::AT_FDCWD, fc.as_ptr(), libc::AT_REMOVEDIR, cname("user.at").as_ptr(), args.as_ptr(), 16usize) as i32));
        note("setxattrat-empty-path", errno_of_rc(libc::syscall(463, ro, b"\0".as_ptr(), libc::AT_EMPTY_PATH, cname("user.at2").as_ptr(), args.as_ptr(), 16usize) as i32));
        note("removexattrat", errno_of_rc(libc::syscall(466, libc::AT_FDCWD, fc.as_ptr(), 0, cname("user.at").as_ptr()) as i32));
        libc::close(ro);
        libc::close(op);
    }
    // What the calls left.
    for f in ["f", "g", "d", "link"] {
        let mut names: Vec<String> = Vec::new();
        let mut buf = vec![0u8; 4096];
        let n = unsafe { libc::llistxattr(cstr(&p(f)).as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if n > 0 {
            names = buf[..n as usize].split(|b| *b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect();
            names.sort();
        }
        let attrs: Vec<String> = names.iter().map(|n| format!("{n}:{:?}", getx(&p(f), n).unwrap_or_default())).collect();
        r.push(format!("{f}:mode={:o}:[{}]", mode_of(&p(f)), attrs.join(",")));
    }
    r.join(" ")
}

/// The positive: an attribute change of an ordinary file is performed like
/// the tracee's own call, compared call by call with the same battery run
/// outside the guard (`xattr_battery`).
#[test]
#[ignore]
fn an_unprotected_xattr_change_is_performed_like_the_tracees_own() {
    let dir = std::env::temp_dir().join(format!("mandu-perform-xattr-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let (reference, work, guarded) = (dir.join("reference"), dir.join("work"), dir.join("guarded"));
    for d in [&reference, &work, &guarded] {
        std::fs::create_dir_all(d).unwrap();
    }
    if let Some(why) = xattr_unsupported(&dir) {
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("SKIP: {why}");
        return;
    }
    let policy = dir.join("policy.json");
    std::fs::write(&policy, format!(r#"{{"agentExe":"","writeProtect":[{{"path":"{}","answer":"deny","label":"Mandu's own files"}}]}}"#, guarded.display())).unwrap();
    let want = xattr_battery(&reference);
    let report = dir.join("report.txt");
    let (work2, report2) = (work.clone(), report.clone());
    let got = run_guarded_protect(&policy, move || {
        let _ = std::fs::write(&report2, xattr_battery(&work2));
        0
    });
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0));
    let diff: Vec<String> = want.split(' ').zip(seen.split(' ')).filter(|(a, b)| a != b).map(|(a, b)| format!("kernel {a} / guard {b}")).collect();
    assert_eq!(seen, want, "an attribute call was not performed like the tracee's own: {diff:?}");
    eprintln!("XATTR PERFORM PASS: {seen}");
}

/// The path-swap race: `sw` flips between a scratch directory and the
/// protected one while the tracee sets an ACL and an attribute on
/// `sw/canary`. Judged by name and CONTINUEd, a swap between the check and
/// the kernel's own resolve would arm the protected file; pinned and
/// performed, it never changes.
#[test]
#[ignore]
fn an_acl_racing_a_swapped_parent_never_changes_a_protected_file() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, own, free, policy) = protect_tree("xattr-race");
    if let Some(why) = xattr_unsupported(&dir) {
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("SKIP: {why}");
        return;
    }
    std::fs::write(own.join("canary"), "PROTECTED\n").unwrap();
    std::fs::set_permissions(own.join("canary"), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(free.join("canary"), "FREE\n").unwrap();
    let sw = dir.join("sw");
    std::os::unix::fs::symlink(&free, &sw).unwrap();
    let sw2 = sw.clone();
    let got = run_guarded_protect_race(&policy, sw.clone(), free.clone(), own.clone(), move || {
        let t = sw2.join("canary");
        let (a, b) = (minimal_acl(0o755), minimal_acl(0o711));
        let mut changed = 0;
        for i in 0..RACE_ITERS {
            // Alternate so every call on the free side is a real change.
            if setx(&t, ACL_ACCESS, if i % 2 == 0 { &a } else { &b }, 0) == 0 {
                changed += 1;
            }
            let _ = setx(&t, "user.raced", if i % 2 == 0 { b"x" } else { b"y" }, 0);
        }
        if changed == 0 { 20 } else { 0 }
    });
    let mode = mode_of(&own.join("canary"));
    let tagged = getx(&own.join("canary"), "user.raced");
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0), "no ACL change ever landed (the race did not run)");
    assert_eq!(mode, 0o644, "a swapped parent let an ACL change the protected file's mode");
    assert_eq!(tagged, Err(libc::ENODATA), "a swapped parent let an attribute reach the protected file");
}

/// The symlink race: the final component `swf` is itself a symlink flipped
/// between a scratch file and the protected one while the tracee sets an
/// ACL through it (setxattr follows it). The call is performed on the file
/// the one resolution reached, so the protected file never changes.
#[test]
#[ignore]
fn an_acl_racing_a_swapped_symlink_never_changes_a_protected_file() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, own, free, policy) = protect_tree("xattr-link-race");
    if let Some(why) = xattr_unsupported(&dir) {
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("SKIP: {why}");
        return;
    }
    let (prot, scratch) = (own.join("hook"), free.join("hook"));
    std::fs::write(&prot, "PROTECTED\n").unwrap();
    std::fs::set_permissions(&prot, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&scratch, "FREE\n").unwrap();
    let sw = dir.join("swf");
    std::os::unix::fs::symlink(&scratch, &sw).unwrap();
    let sw2 = sw.clone();
    let got = run_guarded_protect_race(&policy, sw.clone(), scratch.clone(), prot.clone(), move || {
        let (a, b) = (minimal_acl(0o755), minimal_acl(0o711));
        let mut changed = 0;
        for i in 0..RACE_ITERS {
            if setx(&sw2, ACL_ACCESS, if i % 2 == 0 { &a } else { &b }, 0) == 0 {
                changed += 1;
            }
        }
        if changed == 0 { 20 } else { 0 }
    });
    let mode = mode_of(&prot);
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    assert_eq!(code, Some(0), "no ACL change ever landed (the race did not run)");
    assert_eq!(mode, 0o644, "a swapped symlink let an ACL change the protected file's mode");
}

const EXIT_NO_USERNS: i32 = 95;

/// A tracee in a user namespace of its own (the whole-agent wrap's) names a
/// user in an ACL by ITS namespace's id; the guard, which makes the call,
/// stores the user that id means (the kernel reads the ids in the caller's
/// namespace). The child maps its uid 5 to our uid and sets `u:5:r,g:5:r`
/// on a file: the ACL must name our uid and gid, not 5.
#[test]
#[ignore]
fn an_acl_from_a_tracee_in_its_own_user_namespace_names_the_same_user() {
    let dir = std::env::temp_dir().join(format!("mandu-xattr-userns-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let (work, guarded) = (dir.join("work"), dir.join("guarded"));
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&guarded).unwrap();
    if let Some(why) = xattr_unsupported(&dir) {
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("SKIP: {why}");
        return;
    }
    let policy = dir.join("policy.json");
    std::fs::write(&policy, format!(r#"{{"agentExe":"","writeProtect":[{{"path":"{}","answer":"deny","label":"Mandu's own files"}}]}}"#, guarded.display())).unwrap();
    let f = work.join("shared.txt");
    std::fs::write(&f, "x").unwrap();
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let f2 = f.clone();
    let got = run_guarded_protect_setup(
        &policy,
        move || unsafe {
            if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                return Some(EXIT_NO_USERNS);
            }
            let write = |p: &str, s: String| std::fs::write(p, s).is_ok();
            if !write("/proc/self/setgroups", "deny".into()) || !write("/proc/self/uid_map", format!("5 {uid} 1")) || !write("/proc/self/gid_map", format!("5 {gid} 1")) {
                return Some(EXIT_NO_USERNS);
            }
            None
        },
        move || {
            if unsafe { libc::getuid() } != 5 {
                return 30;
            }
            match setx(&f2, ACL_ACCESS, &named_acl(5, 5), 0) {
                0 => 0,
                e => 40 + e.min(50),
            }
        },
    );
    let stored = getx(&f, ACL_ACCESS);
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { eprintln!("SKIP: seccomp NEW_LISTENER unavailable"); return };
    if code == Some(EXIT_NO_USERNS) {
        eprintln!("SKIP: no nested user namespace here");
        return;
    }
    assert_eq!(code, Some(0), "30 = the map did not apply; 40 + errno = the ACL was not set");
    assert_eq!(stored, Ok(named_acl(uid, gid)), "the ACL names another user than the tracee meant");
}

// ── confidentiality.md §7.2a: a stat by path of a guard-only twin ─────────────

fn errno_now() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Child: `path`'s metadata by every stat form, as `form=size` fields (or
/// `form=E<errno>`), plus `same_ino` (stat vs fstat of what opens) and
/// `read` (the first bytes the open reads).
fn child_stat_forms(path: &std::path::Path) -> String {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let mut out: Vec<String> = Vec::new();
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        let mut put = |name: &str, rc: i64, st: &libc::stat| {
            out.push(if rc == 0 { format!("{name}={}", st.st_size) } else { format!("{name}=E{}", errno_now()) });
        };
        let rc = libc::stat(c.as_ptr(), &mut st) as i64;
        put("stat", rc, &st);
        let ino = if rc == 0 { st.st_ino } else { 0 };
        let rc = libc::lstat(c.as_ptr(), &mut st) as i64;
        put("lstat", rc, &st);
        let rc = libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, c.as_ptr(), &mut st as *mut libc::stat, 0);
        put("newfstatat", rc, &st);
        #[cfg(target_arch = "x86_64")]
        {
            let rc = libc::syscall(libc::SYS_stat, c.as_ptr(), &mut st as *mut libc::stat);
            put("sys_stat", rc, &st);
        }
        let mut sx: libc::statx = std::mem::zeroed();
        let rc = libc::statx(libc::AT_FDCWD, c.as_ptr(), 0, libc::STATX_SIZE | libc::STATX_INO, &mut sx);
        out.push(if rc == 0 { format!("statx={}", sx.stx_size) } else { format!("statx=E{}", errno_now()) });
        let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd >= 0 {
            let rc = libc::fstat(fd, &mut st) as i64;
            out.push(if rc == 0 { format!("fstat={}", st.st_size) } else { format!("fstat=E{}", errno_now()) });
            out.push(format!("same_ino={}", ino != 0 && ino == st.st_ino));
            let mut b = [0u8; 32];
            let n = libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, b.len());
            out.push(format!("read={}", String::from_utf8_lossy(&b[..n.max(0) as usize]).trim()));
            libc::close(fd);
        } else {
            out.push(format!("open=E{}", errno_now()));
        }
    }
    out.join(",")
}

/// A stat of `path` (size, `link:<size>` for a symlink, or `E<errno>`),
/// following the final symlink or not.
fn child_stat_one(path: &std::path::Path, follow: bool) -> String {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        let rc = if follow { libc::stat(c.as_ptr(), &mut st) } else { libc::lstat(c.as_ptr(), &mut st) };
        if rc != 0 {
            return format!("E{}", errno_now());
        }
        let kind = if st.st_mode & libc::S_IFMT == libc::S_IFLNK { "link:" } else { "" };
        format!("{kind}{}", st.st_size)
    }
}

struct StatTree {
    tree: OpenTree,
    pack: std::path::PathBuf,
    cred: std::path::PathBuf,
    loose: std::path::PathBuf,
    beside: std::path::PathBuf,
    same_name: std::path::PathBuf,
    other_name: std::path::PathBuf,
}

/// A pack, a protected file and a loose copy registered as the launcher
/// writes them in the guard-only posture, each twin a different size.
fn stat_tree(tag: &str) -> StatTree {
    let tree = OpenTree::new(tag);
    let objects = tree.dir.join("repo/dotgit/objects");
    std::fs::create_dir_all(objects.join("pack")).unwrap();
    std::fs::create_dir_all(objects.join("ab")).unwrap();
    std::fs::create_dir_all(tree.dir.join("cache")).unwrap();
    std::fs::create_dir_all(tree.dir.join("elsewhere")).unwrap();
    let pack = objects.join("pack/pack-1.pack");
    let sanitized = tree.dir.join("cache/p.pack");
    let cred = tree.dir.join("credentials");
    let cred_twin = tree.dir.join("cache/credentials.twin");
    let loose = objects.join("ab/cdef");
    let denied = tree.dir.join("cache/denied");
    let beside = tree.dir.join("repo/README");
    std::fs::write(&pack, format!("REAL-PACK-{}\n", "x".repeat(100))).unwrap();
    std::fs::write(&sanitized, "SANITIZED\n").unwrap();
    std::fs::write(&cred, format!("REAL-CRED-{}\n", "k".repeat(40))).unwrap();
    std::fs::write(&cred_twin, "TWIN-CRED\n").unwrap();
    std::fs::write(&loose, "REAL-LOOSE-SECRET\n").unwrap();
    std::fs::write(&denied, "").unwrap();
    std::fs::write(&beside, "README-BYTES\n").unwrap();
    let same_name = tree.dir.join("elsewhere/pack-1.pack");
    let other_name = tree.dir.join("elsewhere/other-name");
    std::os::unix::fs::symlink(&pack, &same_name).unwrap();
    std::os::unix::fs::symlink(&pack, &other_name).unwrap();
    std::fs::write(
        &tree.policy,
        format!(
            r#"{{"agentExe":"","secrets":[
              {{"path":"{}","twin":"{}","level":"no-model","kind":"object"}},
              {{"path":"{}","twin":"{}","level":"no-model"}},
              {{"path":"{}","twin":"{}","level":"no-model","kind":"deny"}}]}}"#,
            pack.display(), sanitized.display(), cred.display(), cred_twin.display(), loose.display(), denied.display(),
        ),
    )
    .unwrap();
    StatTree { tree, pack, cred, loose, beside, same_name, other_name }
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let key = format!("{name}=");
    line.split(',').find_map(|f| f.strip_prefix(key.as_str())).unwrap_or("?")
}

#[test]
#[ignore]
fn a_stat_by_path_of_a_guard_only_twin_answers_the_twins_metadata() {
    // confidentiality.md §7.2a: with no bind, git stats the real .pack by
    // path and fstats the twin the guard hands out; the sizes must agree.
    // Every stat by path that follows links answers the twin's metadata
    // (stat, newfstatat, statx, x86_64's stat syscall, relative to the cwd
    // or a directory descriptor, through a symlink of the same name or of
    // another name (P0 4c), with AT_EMPTY_PATH on the cwd: P0 4b); lstat is
    // the kernel's here (this filter traps none).
    let t = stat_tree("stattwin");
    let report = t.tree.dir.join("report.txt");
    let (pack, cred, loose, beside, same, other) = (t.pack.clone(), t.cred.clone(), t.loose.clone(), t.beside.clone(), t.same_name.clone(), t.other_name.clone());
    let pack_dir = t.pack.parent().unwrap().to_path_buf();
    let rep = report.clone();
    let traps = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, stat: true, ..Default::default() };
    let code = run_guarded_traps(&t.tree, traps, |_| {}, || None, move || {
        let mut lines = vec![
            format!("pack:{}", child_stat_forms(&pack)),
            format!("cred:{}", child_stat_forms(&cred)),
            format!("loose:{}", child_stat_one(&loose, true)),
            format!("beside:{}", child_stat_one(&beside, true)),
            format!("same:{}", child_stat_one(&same, true)),
            format!("same_l:{}", child_stat_one(&same, false)),
            format!("other:{}", child_stat_one(&other, true)),
            format!("gone:{}", child_stat_one(&pack_dir.join("nope/pack-1.pack"), true)),
        ];
        unsafe {
            // Relative to the cwd and to a directory descriptor.
            let dir = std::ffi::CString::new(pack_dir.as_os_str().as_encoded_bytes()).unwrap();
            let name = std::ffi::CString::new("pack-1.pack").unwrap();
            let mut st: libc::stat = std::mem::zeroed();
            libc::chdir(dir.as_ptr());
            let rc = libc::stat(name.as_ptr(), &mut st);
            lines.push(format!("rel:{}", if rc == 0 { st.st_size.to_string() } else { format!("E{}", errno_now()) }));
            let dfd = libc::open(dir.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC);
            let rc = libc::fstatat(dfd, name.as_ptr(), &mut st, 0);
            lines.push(format!("at:{}", if rc == 0 { st.st_size.to_string() } else { format!("E{}", errno_now()) }));
            // A buffer the kernel could not write either: EFAULT, as its own.
            let rc = libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, name.as_ptr(), 8usize as *mut libc::stat, 0);
            lines.push(format!("efault:{}", if rc == 0 { "0".to_string() } else { format!("E{}", errno_now()) }));
            // P0 4b (2026-10-07): AT_EMPTY_PATH with a path on the cwd is
            // that path's stat (it ran free and said the real size): the
            // twin's, in newfstatat and statx; with AT_SYMLINK_NOFOLLOW, it
            // is that lstat (free here: this filter traps no lstat).
            let rc = libc::fstatat(libc::AT_FDCWD, name.as_ptr(), &mut st, libc::AT_EMPTY_PATH);
            lines.push(format!("emptypath:{}", if rc == 0 { st.st_size.to_string() } else { format!("E{}", errno_now()) }));
            let mut sx: libc::statx = std::mem::zeroed();
            let rc = libc::statx(libc::AT_FDCWD, name.as_ptr(), libc::AT_EMPTY_PATH, libc::STATX_SIZE, &mut sx);
            lines.push(format!("emptypath_statx:{}", if rc == 0 { sx.stx_size.to_string() } else { format!("E{}", errno_now()) }));
            let rc = libc::fstatat(libc::AT_FDCWD, name.as_ptr(), &mut st, libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW);
            lines.push(format!("emptypath_l:{}", if rc == 0 { st.st_size.to_string() } else { format!("E{}", errno_now()) }));
            // An empty path on the cwd is the cwd's own stat: a directory.
            let empty = std::ffi::CString::new("").unwrap();
            let rc = libc::fstatat(libc::AT_FDCWD, empty.as_ptr(), &mut st, libc::AT_EMPTY_PATH);
            lines.push(format!("emptypath_cwd:{}", if rc == 0 { (st.st_mode & libc::S_IFMT == libc::S_IFDIR).to_string() } else { format!("E{}", errno_now()) }));
        }
        let _ = std::fs::write(&rep, lines.join("\n"));
        0
    });
    let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    assert_eq!(code, Some(0));
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("STAT TWINS:\n{seen}");
    let line = |k: &str| {
        let key = format!("{k}:");
        seen.lines().find_map(|l| l.strip_prefix(key.as_str())).unwrap_or("").to_string()
    };
    let twin = "10"; // "SANITIZED\n"
    let pack = line("pack");
    let mut forms = vec!["stat", "newfstatat", "statx", "fstat"];
    if cfg!(target_arch = "x86_64") {
        forms.push("sys_stat");
    }
    for form in forms {
        assert_eq!(field(&pack, form), twin, "{form} of the pack by path is the twin's size: {pack}");
    }
    // Residual (§7.2a): lstat is not trapped (the tree walkers' call).
    assert_eq!(field(&pack, "lstat"), "111", "lstat runs free and sees the real file: {pack}");
    assert_eq!(field(&pack, "same_ino"), "true", "stat and fstat name the same file: {pack}");
    assert_eq!(field(&pack, "read"), "SANITIZED", "{pack}");
    let cred = line("cred");
    for form in ["stat", "newfstatat", "statx", "fstat"] {
        assert_eq!(field(&cred, form), "10", "{form} of a protected file is its twin's: {cred}");
    }
    assert_eq!(field(&cred, "read"), "TWIN-CRED", "{cred}");
    assert_eq!(line("loose"), "0", "a deny entry stats as its empty stand-in, as under the bind");
    assert_eq!(line("beside"), "13", "an unregistered file keeps its own metadata");
    assert_eq!(line("same"), twin, "a symlink of the same name leads to the twin's metadata");
    assert!(line("same_l").starts_with("link:"), "lstat of a symlink is the link: {}", line("same_l"));
    assert_eq!(line("other"), twin, "a symlink of ANOTHER name leads to the twin's metadata too (P0 4c)");
    assert_eq!(line("gone"), format!("E{}", libc::ENOENT));
    assert_eq!(line("rel"), twin, "relative to the cwd");
    assert_eq!(line("at"), twin, "relative to a directory descriptor");
    assert_eq!(line("efault"), format!("E{}", libc::EFAULT));
    assert_eq!(line("emptypath"), twin, "AT_EMPTY_PATH with a path on the cwd is the path's stat (P0 4b)");
    assert_eq!(line("emptypath_statx"), twin, "statx(AT_FDCWD, path, AT_EMPTY_PATH) too (P0 4b)");
    assert_eq!(line("emptypath_l"), "111", "with AT_SYMLINK_NOFOLLOW it is that lstat, free without the lstat trap");
    assert_eq!(line("emptypath_cwd"), "true", "an empty path on the cwd stats the cwd");
    assert!(!seen.contains("REAL-"), "no real byte read: {seen}");

    // The differential: without the trap the stat by path is the real file's.
    let t2 = stat_tree("stattwin-off");
    let report2 = t2.tree.dir.join("report.txt");
    let (pack2, rep2) = (t2.pack.clone(), report2.clone());
    let traps = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, ..Default::default() };
    let code = run_guarded_traps(&t2.tree, traps, |_| {}, || None, move || {
        let _ = std::fs::write(&rep2, child_stat_forms(&pack2));
        0
    });
    assert_eq!(code, Some(Some(0)));
    let off = std::fs::read_to_string(&report2).unwrap_or_default();
    assert_eq!(field(&off, "stat"), "111", "without the trap stat is the real pack's: {off}");
    assert_eq!(field(&off, "fstat"), twin, "while the descriptor is the twin: {off}");
    eprintln!("STAT TWINS PASS");
}

// ── P0 4c (2026-10-09): the twin's metadata under ANOTHER name ────────────────

/// A `struct stat` as `size/ino/nlink/mtime/ctime.nsec` (`link:` first for
/// a symlink): every number 4c is about.
fn meta_of(st: &libc::stat) -> String {
    let kind = if st.st_mode & libc::S_IFMT == libc::S_IFLNK { "link:" } else { "" };
    format!("{kind}{}/{}/{}/{}/{}.{}", st.st_size, st.st_ino, st.st_nlink, st.st_mtime, st.st_ctime, st.st_ctime_nsec)
}

/// `meta_of` for a `struct statx`.
fn meta_of_x(sx: &libc::statx) -> String {
    let kind = if sx.stx_mode as u32 & libc::S_IFMT == libc::S_IFLNK { "link:" } else { "" };
    format!("{kind}{}/{}/{}/{}/{}.{}", sx.stx_size, sx.stx_ino, sx.stx_nlink, sx.stx_mtime.tv_sec, sx.stx_ctime.tv_sec, sx.stx_ctime.tv_nsec)
}

/// `meta_of` of a stat call's result, or `E<errno>`.
fn meta_or_errno(rc: i64, st: &libc::stat) -> String {
    if rc == 0 { meta_of(st) } else { format!("E{}", errno_now()) }
}

/// The parent's own (unguarded) `lstat` of `path`, as `meta_of`.
fn host_meta(path: &std::path::Path) -> String {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::lstat(c.as_ptr(), &mut st) }, 0, "{}", path.display());
    meta_of(&st)
}

/// Child: `path`'s metadata by every stat form that names a path, following
/// its final symlink or not, as `form=meta` fields.
fn child_meta_forms(path: &std::path::Path) -> String {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let parent = std::ffi::CString::new(path.parent().unwrap().as_os_str().as_encoded_bytes()).unwrap();
    let leaf = std::ffi::CString::new(path.file_name().unwrap().as_encoded_bytes()).unwrap();
    let mut out: Vec<String> = Vec::new();
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        let rc = libc::stat(c.as_ptr(), &mut st) as i64;
        out.push(format!("stat={}", meta_or_errno(rc, &st)));
        let rc = libc::lstat(c.as_ptr(), &mut st) as i64;
        out.push(format!("lstat={}", meta_or_errno(rc, &st)));
        let rc = libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, c.as_ptr(), &mut st as *mut libc::stat, 0);
        out.push(format!("at={}", meta_or_errno(rc, &st)));
        let rc = libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, c.as_ptr(), &mut st as *mut libc::stat, libc::AT_SYMLINK_NOFOLLOW);
        out.push(format!("at_l={}", meta_or_errno(rc, &st)));
        #[cfg(target_arch = "x86_64")]
        {
            let rc = libc::syscall(libc::SYS_stat, c.as_ptr(), &mut st as *mut libc::stat);
            out.push(format!("sys_stat={}", meta_or_errno(rc, &st)));
            let rc = libc::syscall(libc::SYS_lstat, c.as_ptr(), &mut st as *mut libc::stat);
            out.push(format!("sys_lstat={}", meta_or_errno(rc, &st)));
        }
        for (name, flags) in [("statx", 0), ("statx_l", libc::AT_SYMLINK_NOFOLLOW)] {
            let mut sx: libc::statx = std::mem::zeroed();
            let rc = libc::statx(libc::AT_FDCWD, c.as_ptr(), flags, libc::STATX_BASIC_STATS, &mut sx);
            out.push(format!("{name}={}", if rc == 0 { meta_of_x(&sx) } else { format!("E{}", errno_now()) }));
        }
        // Relative to a directory descriptor: a following stat, and the
        // fts walkers' lstat (`find`, `du`), which runs free under
        // `LstatTrap::Cwd` (P0 4a, disclosed).
        let dfd = libc::open(parent.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC);
        let rc = libc::fstatat(dfd, leaf.as_ptr(), &mut st, 0) as i64;
        out.push(format!("dirfd={}", meta_or_errno(rc, &st)));
        let rc = libc::fstatat(dfd, leaf.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) as i64;
        out.push(format!("dirfd_l={}", meta_or_errno(rc, &st)));
        libc::close(dfd);
    }
    out.join(",")
}

struct AliasTree {
    tree: OpenTree,
    env: std::path::PathBuf,
    twin: std::path::PathBuf,
    /// `links/x` → the registered file (absolute), and `links/y` → `x`.
    sym: std::path::PathBuf,
    chain: std::path::PathBuf,
    /// `links/innocent`, a hard link made before the guard starts.
    hard: Option<std::path::PathBuf>,
    beside: std::path::PathBuf,
}

/// A credential file registered as the launcher writes it in the guard-only
/// posture, with symlinks of other names to it and, with `hard`, a hard link
/// of another name made before the launch. The real file and its twin differ
/// in every number `meta_of` shows: size, inode, link count (with `hard`),
/// mtime (the real one is 2001's) and ctime (the twin is written later).
fn alias_tree(tag: &str, hard: bool) -> AliasTree {
    let tree = OpenTree::new(tag);
    for d in ["home", "links", "cache"] {
        std::fs::create_dir_all(tree.dir.join(d)).unwrap();
    }
    let env = tree.dir.join("home/.env");
    std::fs::write(&env, format!("TOKEN={}\n", "k".repeat(40))).unwrap();
    std::fs::File::options().write(true).open(&env).unwrap().set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000)).unwrap();
    let hard = hard.then(|| {
        let h = tree.dir.join("links/innocent");
        std::fs::hard_link(&env, &h).unwrap();
        h
    });
    let sym = tree.dir.join("links/x");
    let chain = tree.dir.join("links/y");
    std::os::unix::fs::symlink(&env, &sym).unwrap();
    std::os::unix::fs::symlink("x", &chain).unwrap();
    let beside = tree.dir.join("links/plain");
    std::fs::write(&beside, "PLAIN\n").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let twin = tree.dir.join("cache/env.twin");
    std::fs::write(&twin, "TOKEN=<placeholder>\n").unwrap();
    std::fs::write(&tree.policy, format!(r#"{{"agentExe":"","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, env.display(), twin.display())).unwrap();
    AliasTree { tree, env, twin, sym, chain, hard, beside }
}

/// The report of `child_meta_forms` for each name, under the guard-only
/// posture's traps (`stat`, `LstatTrap::Cwd`). None: SKIP.
fn alias_report(t: &AliasTree) -> Option<Vec<(String, String)>> {
    alias_report_with(t, stat_traps(), || None)
}

/// The filter of a launch with the stat trap on (`MANDU_NET_GUARD_STAT_TWINS=1`,
/// the lstat trap at its default, `Cwd`).
fn stat_traps() -> net_supervisor::guard_kernel::FilterTraps {
    net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, stat: true, lstat: net_supervisor::guard_filter::LstatTrap::Cwd, ..Default::default() }
}

/// `alias_report` under `traps`, with the child's `setup` run before its
/// filter goes on (a bind's namespace).
fn alias_report_with(t: &AliasTree, traps: net_supervisor::guard_kernel::FilterTraps, setup: impl FnOnce() -> Option<i32>) -> Option<Vec<(String, String)>> {
    let report = t.tree.dir.join("report.txt");
    let _ = std::fs::remove_file(&report);
    let mut names = vec![("env", t.env.clone()), ("sym", t.sym.clone()), ("chain", t.chain.clone()), ("beside", t.beside.clone())];
    if let Some(h) = &t.hard {
        names.push(("hard", h.clone()));
    }
    let rep = report.clone();
    let named = names.clone();
    let code = run_guarded_traps(&t.tree, traps, |_| {}, setup, move || {
        let lines: Vec<String> = named.iter().map(|(n, p)| format!("{n}:{}", child_meta_forms(p))).collect();
        let _ = std::fs::write(&rep, lines.join("\n"));
        0
    })?;
    assert_eq!(code, Some(0));
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    Some(names.iter().map(|(n, _)| (n.to_string(), seen.lines().find_map(|l| l.strip_prefix(&format!("{n}:"))).unwrap_or("").to_string())).collect())
}

#[test]
#[ignore]
fn a_stat_of_another_name_for_a_guard_only_twin_answers_the_twins_metadata() {
    // P0 4c (confidentiality.md §7.2a "Another name for a twinned file"):
    // in the guard-only posture a symlink of another name (`ln -s ~/.env
    // /tmp/x; stat -L /tmp/x`) or a hard link of another name made before
    // the launch reached the REAL file's metadata: its size (a one-token
    // file's token length), times, inode and link count. Every name that
    // resolves to the registered inode now answers the twin's, by every
    // stat form the trap sees. Pinned residual: an lstat relative to a
    // directory descriptor (P0 4a, `LstatTrap::Cwd`).
    let follow = ["stat", "at", "statx", "dirfd"].iter().chain(if cfg!(target_arch = "x86_64") { &["sys_stat"][..] } else { &[][..] }).copied().collect::<Vec<_>>();
    let nofollow = ["lstat", "at_l", "statx_l"].iter().chain(if cfg!(target_arch = "x86_64") { &["sys_lstat"][..] } else { &[][..] }).copied().collect::<Vec<_>>();
    for hard in [true, false] {
        let t = alias_tree(if hard { "alias-hard" } else { "alias-sym" }, hard);
        let (real, twin, beside) = (host_meta(&t.env), host_meta(&t.twin), host_meta(&t.beside));
        assert_ne!(real.split('/').next(), twin.split('/').next(), "the sizes differ");
        let Some(rows) = alias_report(&t) else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
        eprintln!("ALIAS STAT (hard link: {hard}) real={real} twin={twin}");
        for (n, r) in &rows {
            eprintln!("  {n}: {r}");
        }
        let row = |n: &str| rows.iter().find(|(k, _)| k == n).map(|(_, r)| r.clone()).unwrap();
        for name in ["env", "sym", "chain"].into_iter().chain(hard.then_some("hard")) {
            let r = row(name);
            for f in &follow {
                assert_eq!(field(&r, f), twin, "{name}: {f} reaches the twin's metadata: {r}");
            }
            for f in &nofollow {
                if name == "sym" || name == "chain" {
                    assert!(field(&r, f).starts_with("link:"), "{name}: {f} of a symlink is the link's own: {r}");
                } else {
                    assert_eq!(field(&r, f), twin, "{name}: {f} of the registered inode is the twin's: {r}");
                }
            }
            let dl = field(&r, "dirfd_l");
            if name == "sym" || name == "chain" {
                assert!(dl.starts_with("link:"), "{name}: {r}");
            } else {
                assert_eq!(dl, real, "{name}: residual P0 4a, a directory descriptor's lstat runs free: {r}");
            }
            for (f, v) in r.split(',').filter_map(|kv| kv.split_once('=')) {
                assert!(f == "dirfd_l" || v != real, "{name}: {f} said the real file's metadata: {r}");
            }
        }
        let b = row("beside");
        for f in follow.iter().chain(&nofollow) {
            assert_eq!(field(&b, f), beside, "an unregistered file keeps its own metadata ({f}): {b}");
        }
    }
    eprintln!("ALIAS STAT PASS");
}

/// The bind posture's namespace for the child: a user + mount namespace with
/// `twin` bound over `secret` (bwrap's `--bind <twin> <secret>`), the guard
/// outside it. `Some(EXIT_NO_SECCOMP)` (the test SKIPs) where an
/// unprivileged mount namespace is barred.
fn bind_twin_setup(twin: std::path::PathBuf, secret: std::path::PathBuf) -> impl FnOnce() -> Option<i32> {
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    move || {
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            return Some(EXIT_NO_SECCOMP);
        }
        let maps = std::fs::write("/proc/self/setgroups", "deny").is_ok()
            && std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).is_ok()
            && std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).is_ok();
        let root = cstr(std::path::Path::new("/"));
        let (src, dst) = (cstr(&twin), cstr(&secret));
        // SAFETY: NUL-terminated paths; mounts in the child's own namespace.
        let mounted = maps
            && unsafe {
                libc::mount(std::ptr::null(), root.as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) == 0
                    && libc::mount(src.as_ptr(), dst.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) == 0
            };
        if mounted { None } else { Some(EXIT_NO_SECCOMP) }
    }
}

#[test]
#[ignore]
fn under_the_bind_a_hard_link_of_another_name_answers_the_twins_metadata() {
    // P0 4c, the bind posture (confidentiality.md §7.2a "Another name for a
    // twinned file"): the twin is bound over the registered name only, so a
    // hard link of another name made before the launch showed the REAL
    // file's size, times, inode and link count, the stat trap being off under
    // the bind. The launcher now turns the trap on when a protected file has
    // st_nlink > 1 (secret-setup.ts `linkedSecretFiles`): the guard, outside
    // the bind, matches that name by (st_dev, st_ino) and answers the twin's
    // metadata by every stat form. First the posture without the trap (the
    // launch before the fix: the hard link leaks the real metadata), then
    // with it. Pinned residual: an lstat relative to a directory descriptor
    // (P0 4a).
    let follow = ["stat", "at", "statx", "dirfd"].iter().chain(if cfg!(target_arch = "x86_64") { &["sys_stat"][..] } else { &[][..] }).copied().collect::<Vec<_>>();
    let nofollow = ["lstat", "at_l", "statx_l"].iter().chain(if cfg!(target_arch = "x86_64") { &["sys_lstat"][..] } else { &[][..] }).copied().collect::<Vec<_>>();
    let all: Vec<&str> = follow.iter().chain(&nofollow).copied().chain(["dirfd_l"]).collect();
    let t = alias_tree("bind-hard", true);
    let (real, twin, beside) = (host_meta(&t.env), host_meta(&t.twin), host_meta(&t.beside));
    let row = |rows: &[(String, String)], n: &str| rows.iter().find(|(k, _)| k == n).map(|(_, r)| r.clone()).unwrap();
    let bind = || bind_twin_setup(t.twin.clone(), t.env.clone());

    // The bind posture as launched before the fix: no stat trap.
    let open_only = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, ..Default::default() };
    let Some(before) = alias_report_with(&t, open_only, bind()) else { eprintln!("SKIP: seccomp NEW_LISTENER or an unprivileged mount namespace unavailable here"); return };
    eprintln!("BIND ALIAS STAT (no stat trap) real={real} twin={twin}");
    for (n, r) in &before {
        eprintln!("  {n}: {r}");
    }
    let env = row(&before, "env");
    for f in &all {
        assert_eq!(field(&env, f), twin, "the bind shows the twin under the registered name ({f}): {env}");
    }
    let hard = row(&before, "hard");
    for f in &all {
        assert_eq!(field(&hard, f), real, "the residual this fixes: the hard link shows the real file without the trap ({f}): {hard}");
    }

    // With the trap the launcher now turns on.
    let after = alias_report_with(&t, stat_traps(), bind()).expect("the first run did not SKIP");
    eprintln!("BIND ALIAS STAT (stat trap) real={real} twin={twin}");
    for (n, r) in &after {
        eprintln!("  {n}: {r}");
    }
    for name in ["env", "hard", "sym", "chain"] {
        let r = row(&after, name);
        for f in &follow {
            assert_eq!(field(&r, f), twin, "{name}: {f} is the twin's: {r}");
        }
        for f in nofollow.iter().chain(&["dirfd_l"]) {
            match name {
                "sym" | "chain" => assert!(field(&r, f).starts_with("link:"), "{name}: {f} of a symlink is the link's own: {r}"),
                "hard" if *f == "dirfd_l" => assert_eq!(field(&r, f), real, "hard: residual P0 4a, a directory descriptor's lstat runs free: {r}"),
                _ => assert_eq!(field(&r, f), twin, "{name}: {f} is the twin's: {r}"),
            }
        }
        for (f, v) in r.split(',').filter_map(|kv| kv.split_once('=')) {
            assert!((name == "hard" && f == "dirfd_l") || v != real, "{name}: {f} said the real file's metadata: {r}");
        }
    }
    let b = row(&after, "beside");
    for f in follow.iter().chain(&nofollow) {
        assert_eq!(field(&b, f), beside, "an unregistered file keeps its own metadata ({f}): {b}");
    }
    eprintln!("BIND ALIAS STAT PASS");
}

fn git_ok() -> bool {
    std::process::Command::new("git").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

fn git_at(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> String {
    use std::io::Write;
    let mut cmd = std::process::Command::new("git");
    cmd.current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@x")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@x")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "git {args:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// A repository whose one pack holds a protected blob, the sanitized pack
/// (every object but that blob) as the launcher builds it, and the guard's
/// policy registering the real `.pack`/`.idx`/`.rev` as `object` entries.
/// Returns (tree, repo, public blob, protected blob, sanitized pack size).
fn git_pack_tree(tag: &str) -> (OpenTree, std::path::PathBuf, String, String, u64) {
    let tree = OpenTree::new(tag);
    let repo = tree.dir.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git_at(&repo, &["init", "-q"], None);
    std::fs::write(repo.join("a.txt"), "PUBLIC-A\n").unwrap();
    std::fs::write(repo.join("secret.txt"), "REAL-SECRET-BLOB\n").unwrap();
    git_at(&repo, &["add", "."], None);
    git_at(&repo, &["commit", "-qm", "both"], None);
    git_at(&repo, &["rm", "-q", "secret.txt"], None);
    git_at(&repo, &["commit", "-qm", "drop it"], None);
    git_at(&repo, &["repack", "-adq"], None);
    let public = git_at(&repo, &["rev-parse", "HEAD:a.txt"], None);
    let protected = git_at(&repo, &["rev-parse", "HEAD~1:secret.txt"], None);
    let all = git_at(&repo, &["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"], None);
    let keep: Vec<&str> = all.lines().filter(|l| *l != protected).collect();
    let cache = tree.dir.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    let hash = git_at(&repo, &["pack-objects", "-q", &cache.join("pack").display().to_string()], Some(&format!("{}\n", keep.join("\n"))));
    let pack_dir = repo.join(".git/objects/pack");
    let real = std::fs::read_dir(&pack_dir).unwrap().flatten().map(|e| e.path()).find(|p| p.extension().is_some_and(|x| x == "pack")).unwrap();
    let base = real.with_extension("");
    let mut entries = Vec::new();
    for ext in ["pack", "idx", "rev"] {
        let (r, s) = (base.with_extension(ext), cache.join(format!("pack-{hash}.{ext}")));
        assert_eq!(r.exists(), s.exists(), "{ext}: the real and the sanitized pack carry the same files");
        if r.exists() {
            entries.push(format!(r#"{{"path":"{}","twin":"{}","level":"no-model","kind":"object"}}"#, r.display(), s.display()));
        }
    }
    std::fs::write(&tree.policy, format!(r#"{{"agentExe":"","secrets":[{}]}}"#, entries.join(","))).unwrap();
    let sanitized = std::fs::metadata(cache.join(format!("pack-{hash}.pack"))).unwrap().len();
    assert_ne!(sanitized, std::fs::metadata(&real).unwrap().len(), "the sanitized pack differs in size (the bug's precondition)");
    (tree, repo, public, protected, sanitized)
}

/// Run `script` with /bin/sh in the guarded tree.
fn run_git_script(tree: &OpenTree, stat: bool, script: String) -> Option<Option<i32>> {
    let sh = std::ffi::CString::new("/bin/sh").unwrap();
    let args = [std::ffi::CString::new("sh").unwrap(), std::ffi::CString::new("-c").unwrap(), std::ffi::CString::new(script).unwrap()];
    let traps = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, stat, ..Default::default() };
    run_guarded_traps(tree, traps, |_| {}, || None, move || {
        let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
        argv.push(std::ptr::null());
        unsafe { libc::execv(sh.as_ptr(), argv.as_ptr()) };
        99
    })
}

#[test]
#[ignore]
fn git_reads_every_other_object_of_a_guard_only_sanitized_pack() {
    // The bug (confidentiality.md §7.2a, found by plan 14's C17 oracle): in
    // the guard-only posture git dropped the whole sanitized pack ("packfile
    // … size changed"), so every other object became unreadable too.
    if !git_ok() {
        eprintln!("SKIP: git is not installed");
        return;
    }
    for stat in [true, false] {
        let (tree, repo, public, protected, sanitized) = git_pack_tree(if stat { "statgit" } else { "statgit-off" });
        let out = tree.dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let o = out.display();
        let pack = std::fs::read_dir(repo.join(".git/objects/pack")).unwrap().flatten().map(|e| e.path()).find(|p| p.extension().is_some_and(|x| x == "pack")).unwrap();
        let script = format!(
            "export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_PAGER=cat HOME={home}\n\
             cd '{repo}'\n\
             git cat-file -p {public} > {o}/pub 2>&1; echo $? > {o}/pub.status\n\
             git log --oneline > {o}/log 2>&1; echo $? > {o}/log.status\n\
             git show HEAD:a.txt > {o}/show 2>&1; echo $? > {o}/show.status\n\
             git cat-file -p {protected} > {o}/sec 2>&1; echo $? > {o}/sec.status\n\
             stat -L -c %s '{pack}' > {o}/size 2>&1\n",
            home = tree.dir.display(),
            repo = repo.display(),
            pack = pack.display(),
        );
        let Some(code) = run_git_script(&tree, stat, script) else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
        assert_eq!(code, Some(0));
        let read = |n: &str| std::fs::read_to_string(out.join(n)).unwrap_or_default();
        let all = ["pub", "log", "show", "sec", "size"].iter().map(|n| format!("{n}: {}", read(n))).collect::<Vec<_>>().join("\n");
        eprintln!("GIT (stat trap {stat}):\n{all}");
        assert!(!all.contains("REAL-SECRET-BLOB"), "the protected blob's bytes never appear: {all}");
        assert_ne!(read("sec.status").trim(), "0", "the protected blob is not in the sanitized pack: {all}");
        if stat {
            assert_eq!(read("pub"), "PUBLIC-A\n", "another object of the same pack reads: {all}");
            assert_eq!(read("show"), "PUBLIC-A\n", "{all}");
            assert_eq!(read("log.status").trim(), "0", "{all}");
            assert!(read("log").contains("drop it") && read("log").contains("both"), "{all}");
            assert_eq!(read("size").trim(), sanitized.to_string(), "stat -L (following, as a reader does) of the real pack says the twin's size: {all}");
        } else {
            // The differential: the bug, as found.
            assert_ne!(read("pub.status").trim(), "0", "without the trap git drops the whole pack: {all}");
            assert!(read("pub").contains("size changed"), "{all}");
        }
    }
    eprintln!("GIT GUARD-ONLY PACK PASS");
}

#[test]
#[ignore]
fn stat_trap_cost_is_measured() {
    // confidentiality.md §7.2a "Cost": the price of the stat trap, against
    // the same guard without it, for a stat of another name (resolved since
    // P0 4c: a symlink there may reach a registered file), an lstat of
    // another name (let go by the prefilter while no registered file has
    // another link; resolved while one has), and a stat the guard answers (a
    // twinned name). Prints the numbers; asserts only that a prefiltered
    // lstat stays well below a resolved stat, and a resolved stat within a
    // loose bound of an open the guard performs.
    const N: u32 = 20_000;
    let mut rows = Vec::new();
    // (stat trap, a registered file hard-linked under another name)
    for (stat, linked) in [(false, false), (true, false), (true, true)] {
        let t = stat_tree(match (stat, linked) {
            (false, _) => "statcost-off",
            (true, false) => "statcost",
            (true, true) => "statcost-linked",
        });
        if linked {
            std::fs::hard_link(&t.cred, t.tree.dir.join("elsewhere/cred-link")).unwrap();
        }
        let report = t.tree.dir.join("report.txt");
        let (pack, beside, rep) = (t.pack.clone(), t.beside.clone(), report.clone());
        let lstat = if stat { net_supervisor::guard_filter::LstatTrap::Cwd } else { net_supervisor::guard_filter::LstatTrap::Off };
        let traps = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, stat, lstat, ..Default::default() };
        let code = run_guarded_traps(&t.tree, traps, |_| {}, || None, move || {
            let time = |p: &std::path::Path, n: u32, f: &dyn Fn(&std::ffi::CStr)| {
                let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
                let t0 = std::time::Instant::now();
                for _ in 0..n {
                    f(&c);
                }
                t0.elapsed().as_nanos() as f64 / n as f64 / 1000.0
            };
            let do_stat = |c: &std::ffi::CStr| unsafe {
                let mut st: libc::stat = std::mem::zeroed();
                libc::stat(c.as_ptr(), &mut st);
            };
            let do_fstat = |c: &std::ffi::CStr| unsafe {
                let mut st: libc::stat = std::mem::zeroed();
                let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                libc::fstat(fd, &mut st);
                libc::close(fd);
            };
            let do_lstat = |c: &std::ffi::CStr| unsafe {
                let mut st: libc::stat = std::mem::zeroed();
                libc::lstat(c.as_ptr(), &mut st);
            };
            // Interleaved rounds, the best of each (the CI guest is shared).
            let mut best = [f64::MAX; 4];
            for _ in 0..3 {
                let v = [time(&beside, N / 3, &do_stat), time(&beside, N / 3, &do_lstat), time(&pack, N / 30, &do_stat), time(&beside, N / 30, &do_fstat)];
                for (b, x) in best.iter_mut().zip(v) {
                    *b = b.min(x);
                }
            }
            let _ = std::fs::write(&rep, best.iter().map(|x| format!("{x:.2}")).collect::<Vec<_>>().join(" "));
            0
        });
        let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
        assert_eq!(code, Some(0));
        let r = std::fs::read_to_string(&report).unwrap_or_default();
        let v: Vec<f64> = r.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        assert_eq!(v.len(), 4, "{r}");
        rows.push((stat, linked, v));
    }
    for (stat, linked, v) in &rows {
        eprintln!(
            "STAT COST (trap {stat}, a registered file linked {linked}): stat of another name {:.2} us, lstat of another name {:.2} us, stat of a twinned name {:.2} us, open+fstat+close {:.2} us",
            v[0], v[1], v[2], v[3]
        );
    }
    let (on, linked) = (&rows[1].2, &rows[2].2);
    // Loose bounds only (a shared guest): which stat is resolved is
    // `stat_twin::stat_probe`'s, unit-tested.
    assert!(on[0] < on[3] * 5.0, "a resolved stat costs no more than a few performed opens: {on:?}");
    assert!(linked[1] < linked[3] * 5.0, "a resolved lstat (a registered file linked) as a resolved stat: {linked:?}");
}

// ── confidentiality.md §7.2a "The size a reader sees": a reader that sizes
// its read by a stat (2026-10-04) ──────────────────────────────────────────────

/// A short credential whose twin is LONGER (`.env`: a placeholder is longer
/// than the value) and a long key whose twin is SHORTER, by more than a
/// page (`big.key`: `mmap` of the key's size past the twin's end is
/// SIGBUS), registered as the launcher writes them in the guard-only
/// posture.
struct SizeTree {
    tree: OpenTree,
    env: std::path::PathBuf,
    key: std::path::PathBuf,
    env_twin: Vec<u8>,
    key_twin: Vec<u8>,
}

const ENV_RAW: &str = "API_TOKEN=REAL-x9\n";
const ENV_TWIN: &str = "API_TOKEN=$MDU:secret:0123456789abcdef\n";
const KEY_TWIN: &str = "KEY=$MDU:secret:fedcba9876543210\n";

fn size_tree(tag: &str) -> SizeTree {
    let tree = OpenTree::new(tag);
    std::fs::create_dir_all(tree.dir.join("home")).unwrap();
    std::fs::create_dir_all(tree.dir.join("cache")).unwrap();
    let env = tree.dir.join("home/.env");
    let key = tree.dir.join("home/big.key");
    let (env_twin_p, key_twin_p) = (tree.dir.join("cache/env.twin"), tree.dir.join("cache/key.twin"));
    std::fs::write(&env, ENV_RAW).unwrap();
    std::fs::write(&env_twin_p, ENV_TWIN).unwrap();
    std::fs::write(&key, format!("KEY=REAL-{}\n", "k".repeat(9000))).unwrap();
    std::fs::write(&key_twin_p, KEY_TWIN).unwrap();
    std::fs::write(
        &tree.policy,
        format!(
            r#"{{"agentExe":"","secrets":[
              {{"path":"{}","twin":"{}","level":"no-model"}},
              {{"path":"{}","twin":"{}","level":"no-model"}}]}}"#,
            env.display(),
            env_twin_p.display(),
            key.display(),
            key_twin_p.display(),
        ),
    )
    .unwrap();
    SizeTree { tree, env, key, env_twin: ENV_TWIN.as_bytes().to_vec(), key_twin: KEY_TWIN.as_bytes().to_vec() }
}

/// How a size-checked reader learns the size it reads.
#[derive(Clone, Copy)]
enum SizeBy {
    /// `fstat` of the descriptor it opened (Python's `read()`, `cat`, most).
    Fstat,
    /// `stat` of the path, then open (follows).
    Stat,
    /// `lstat` of the path, then open (`git diff --no-index`, `git grep`).
    Lstat,
    /// `statx(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW)` (Rust's and libuv's lstat).
    StatxNofollow,
    /// `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)` relative to a directory
    /// descriptor (the fts walkers).
    DirfdLstat,
    /// `statx(AT_FDCWD, path, AT_EMPTY_PATH)`: a path with the flag a
    /// descriptor's own stat carries (P0 4b).
    StatxEmptyPath,
}

/// Child: learn the size `by`, open, then read exactly that many bytes
/// (`read` in a loop to EOF, or `mmap` of that length): what a reader that
/// sizes its read by a stat sees. `Ok((bytes, the size it expected))` or
/// `Err(why)`.
fn sized_read(path: &std::path::Path, by: SizeBy, mmap: bool) -> Result<(Vec<u8>, usize), String> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        let pre = match by {
            SizeBy::Fstat => None,
            _ => {
                let rc = match by {
                    SizeBy::Stat => libc::stat(c.as_ptr(), &mut st),
                    SizeBy::Lstat => libc::lstat(c.as_ptr(), &mut st),
                    SizeBy::StatxNofollow | SizeBy::StatxEmptyPath => {
                        let flags = if matches!(by, SizeBy::StatxNofollow) { libc::AT_SYMLINK_NOFOLLOW } else { libc::AT_EMPTY_PATH };
                        let mut sx: libc::statx = std::mem::zeroed();
                        let rc = libc::statx(libc::AT_FDCWD, c.as_ptr(), flags, libc::STATX_SIZE, &mut sx);
                        st.st_size = sx.stx_size as i64;
                        rc
                    }
                    _ => {
                        let dir = std::ffi::CString::new(path.parent().unwrap().as_os_str().as_encoded_bytes()).unwrap();
                        let name = std::ffi::CString::new(path.file_name().unwrap().as_encoded_bytes()).unwrap();
                        let dfd = libc::open(dir.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC);
                        let rc = libc::fstatat(dfd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW);
                        libc::close(dfd);
                        rc
                    }
                };
                if rc != 0 {
                    return Err(format!("stat E{}", errno_now()));
                }
                Some(st.st_size)
            }
        };
        let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(format!("open E{}", errno_now()));
        }
        let size = match pre {
            Some(s) => s,
            None => {
                if libc::fstat(fd, &mut st) != 0 {
                    libc::close(fd);
                    return Err(format!("fstat E{}", errno_now()));
                }
                st.st_size
            }
        } as usize;
        let mut out = vec![0u8; size];
        if mmap {
            let p = libc::mmap(std::ptr::null_mut(), size, libc::PROT_READ, libc::MAP_PRIVATE, fd, 0);
            libc::close(fd);
            if p == libc::MAP_FAILED {
                return Err(format!("mmap E{}", errno_now()));
            }
            // Past the file's last page this is SIGBUS: the child dies.
            std::ptr::copy_nonoverlapping(p as *const u8, out.as_mut_ptr(), size);
            libc::munmap(p, size);
            return Ok((out, size));
        }
        let mut got = 0usize;
        while got < size {
            let n = libc::read(fd, out[got..].as_mut_ptr() as *mut libc::c_void, size - got);
            if n <= 0 {
                break;
            }
            got += n as usize;
        }
        libc::close(fd);
        out.truncate(got);
        Ok((out, size))
    }
}

/// What a sized read returned, against the twin: `whole`, `cut:<n>` (fewer
/// bytes than the twin), `long:<n>` (more: the twin, then NULs), `short:<n>`
/// (the whole twin, but the reader expected `n` bytes: git grep's "short
/// read"), `REAL` (a byte of the real file), or the error.
fn verdict(got: &Result<(Vec<u8>, usize), String>, twin: &[u8]) -> String {
    match got {
        Err(e) => e.clone(),
        Ok((b, _)) if b.windows(5).any(|w| w == b"REAL-") => "REAL".into(),
        Ok((b, size)) if b.as_slice() == twin && *size != b.len() => format!("short:{size}"),
        Ok((b, _)) if b.as_slice() == twin => "whole".into(),
        Ok((b, _)) if b.len() < twin.len() => format!("cut:{}", b.len()),
        Ok((b, _)) => format!("long:{}", b.len()),
    }
}

/// Run every sized reader over both files with `lstat` as the filter's
/// lstat trap. `None`: SKIP; `Some(None)`: the child died (its partial
/// report is in the tree); else the report, `<file>.<reader>=<verdict>`.
fn sized_reads_under(t: &SizeTree, lstat: net_supervisor::guard_filter::LstatTrap, with_mmap: bool) -> Option<Option<String>> {
    let report = t.tree.dir.join(format!("sized-{lstat:?}.txt"));
    let (env, key, rep) = (t.env.clone(), t.key.clone(), report.clone());
    let (env_twin, key_twin) = (t.env_twin.clone(), t.key_twin.clone());
    let traps = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, stat: true, lstat, ..Default::default() };
    let code = run_guarded_traps(&t.tree, traps, |_| {}, || None, move || {
        let mut lines = Vec::new();
        for (name, path, twin) in [("env", &env, &env_twin), ("key", &key, &key_twin)] {
            for (r, by) in [("fstat", SizeBy::Fstat), ("stat", SizeBy::Stat), ("lstat", SizeBy::Lstat), ("statx_nofollow", SizeBy::StatxNofollow), ("dirfd_lstat", SizeBy::DirfdLstat), ("statx_empty", SizeBy::StatxEmptyPath)] {
                lines.push(format!("{name}.{r}={}", verdict(&sized_read(path, by, false), twin)));
                // Written as it goes: a SIGBUS below leaves what came before.
                let _ = std::fs::write(&rep, lines.join("\n"));
            }
            if with_mmap {
                for (r, by) in [("fstat_mmap", SizeBy::Fstat), ("lstat_mmap", SizeBy::Lstat)] {
                    lines.push(format!("{name}.{r}={}", verdict(&sized_read(path, by, true), twin)));
                    let _ = std::fs::write(&rep, lines.join("\n"));
                }
            }
        }
        0
    })?;
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    Some(code.map(|_| seen))
}

fn report_field(seen: &str, k: &str) -> String {
    let key = format!("{k}=");
    seen.lines().find_map(|l| l.strip_prefix(key.as_str())).unwrap_or("?").to_string()
}

#[test]
#[ignore]
fn a_reader_that_sizes_its_read_by_a_stat_reads_a_guard_only_twin_whole() {
    // confidentiality.md §7.2a "The size a reader sees" (2026-10-04, found by
    // MR !540's printer-downstream: `git diff --no-index /dev/null .env`
    // printed the twin cut mid-symbol). With no bind the guard serves the
    // twin's descriptor, whose fstat is the twin's; an lstat of the path was
    // the REAL file's, so a reader that lstats, opens and reads exactly
    // st_size bytes read the twin cut short (a twin longer than the value)
    // or past its end (a twin shorter: NULs, a short read, or SIGBUS under
    // mmap). Every form a reader sizes by now says the twin's size.
    use net_supervisor::guard_filter::LstatTrap;
    let t = size_tree("sized");
    let Some(seen) = sized_reads_under(&t, LstatTrap::Cwd, true) else {
        eprintln!("SKIP: seccomp NEW_LISTENER denied here");
        return;
    };
    let Some(seen) = seen else {
        panic!("the child died (SIGBUS of an mmap past the twin's end?): {}", std::fs::read_to_string(t.tree.dir.join("sized-Cwd.txt")).unwrap_or_default())
    };
    eprintln!("SIZED READS (lstat trap Cwd):\n{seen}");
    assert!(!seen.contains("REAL"), "no byte of a real file: {seen}");
    for f in ["env", "key"] {
        for r in ["fstat", "stat", "lstat", "statx_nofollow", "statx_empty", "fstat_mmap", "lstat_mmap"] {
            assert_eq!(report_field(&seen, &format!("{f}.{r}")), "whole", "{f} sized by {r}: {seen}");
        }
        // Residual (§7.2a): an lstat relative to a directory descriptor (the
        // fts walkers) runs free under Cwd, so it reads by the real size.
        assert_ne!(report_field(&seen, &format!("{f}.dirfd_lstat")), "whole", "{f}: the dirfd-relative lstat is the residual under Cwd: {seen}");
    }

    // `All`: the directory-relative lstat too.
    let t2 = size_tree("sized-all");
    let seen2 = sized_reads_under(&t2, LstatTrap::All, true).unwrap().expect("the child lived");
    eprintln!("SIZED READS (lstat trap All):\n{seen2}");
    assert!(!seen2.contains("REAL"), "{seen2}");
    assert!(seen2.lines().all(|l| l.ends_with("=whole")), "every reader, the fts form too: {seen2}");

    // The differential: lstat free (the guard-only posture before
    // 2026-10-04) is the bug.
    let t3 = size_tree("sized-off");
    let seen3 = sized_reads_under(&t3, LstatTrap::Off, false).unwrap().expect("the child lived (no mmap)");
    eprintln!("SIZED READS (lstat trap Off):\n{seen3}");
    assert!(!seen3.contains("REAL"), "a stat moves no byte: {seen3}");
    assert_eq!(report_field(&seen3, "env.fstat"), "whole", "the descriptor was always the twin's: {seen3}");
    assert_eq!(report_field(&seen3, "env.stat"), "whole", "{seen3}");
    assert_eq!(report_field(&seen3, "env.lstat"), format!("cut:{}", ENV_RAW.len()), "the bug: the twin cut at the real file's size: {seen3}");
    let key_len = std::fs::metadata(&t3.key).unwrap().len();
    assert_eq!(report_field(&seen3, "key.lstat"), format!("short:{key_len}"), "the bug: a twin shorter than the key, read as the key's size: {seen3}");
    eprintln!("SIZED READS PASS");
}

/// The calling thread's capability sets (v3: two 32-bit words each).
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
const CAP_V3: u32 = 0x2008_0522;

/// Run `f` with CAP_SYS_PTRACE out of this thread's effective set (threads
/// it spawns, and a child it forks, start without it in theirs), then put
/// it back.
/// As root of the lane's user namespace the guard may read a non-dumpable
/// tracee's memory; the guard of a launch, outside the tree's namespace
/// that holds no capability there, may not (P0 4d). A thread that never
/// had it changes nothing.
fn without_cap_sys_ptrace<T>(f: impl FnOnce() -> T) -> T {
    // CAP_SYS_PTRACE (linux/capability.h; libc does not export it).
    let bit = 19u32;
    let mut hdr = CapHeader { version: CAP_V3, pid: 0 };
    let mut data = [CapData::default(); 2];
    let got = unsafe { libc::syscall(libc::SYS_capget, &mut hdr as *mut CapHeader, data.as_mut_ptr()) } == 0;
    let had = got && data[0].effective & (1 << bit) != 0;
    if had {
        let mut less = data;
        less[0].effective &= !(1 << bit);
        let mut h = CapHeader { version: CAP_V3, pid: 0 };
        assert_eq!(unsafe { libc::syscall(libc::SYS_capset, &mut h as *mut CapHeader, less.as_ptr()) }, 0, "drop CAP_SYS_PTRACE");
    }
    let out = f();
    if had {
        let mut h = CapHeader { version: CAP_V3, pid: 0 };
        unsafe { libc::syscall(libc::SYS_capset, &mut h as *mut CapHeader, data.as_ptr()) };
    }
    out
}

#[test]
#[ignore]
fn a_non_dumpable_callers_stat_of_a_guard_only_twin_never_says_the_real_size() {
    // P0 4d (2026-10-07): when the guard cannot read the caller's path (a
    // process that made itself non-dumpable, `prctl(PR_SET_DUMPABLE, 0)`),
    // the stat handler CONTINUED to the kernel: the real file's metadata,
    // so its size. Now it fails closed, as the open path does on the same
    // error. The control: the same process, dumpable, gets the twin's size.
    use net_supervisor::guard_filter::LstatTrap;
    let t = size_tree("nodump");
    let report = t.tree.dir.join("nodump.txt");
    let (env, rep) = (t.env.clone(), report.clone());
    let traps = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, stat: true, lstat: LstatTrap::Cwd, ..Default::default() };
    let code = without_cap_sys_ptrace(|| {
        // The tracee holds no capability (the guard's /proc reads of it
        // need its permitted set within the guard's effective one).
        let no_caps = || {
            let mut h = CapHeader { version: CAP_V3, pid: 0 };
            let none = [CapData::default(); 2];
            (unsafe { libc::syscall(libc::SYS_capset, &mut h as *mut CapHeader, none.as_ptr()) } != 0).then_some(5)
        };
        run_guarded_traps(&t.tree, traps, |_| {}, no_caps, move || {
            let c = std::ffi::CString::new(env.as_os_str().as_encoded_bytes()).unwrap();
            let stat_of = || unsafe {
                let mut st: libc::stat = std::mem::zeroed();
                let rc = libc::stat(c.as_ptr(), &mut st);
                let s = if rc == 0 { st.st_size.to_string() } else { format!("E{}", errno_now()) };
                let mut sx: libc::statx = std::mem::zeroed();
                let rc = libc::statx(libc::AT_FDCWD, c.as_ptr(), libc::AT_SYMLINK_NOFOLLOW, libc::STATX_SIZE, &mut sx);
                let x = if rc == 0 { sx.stx_size.to_string() } else { format!("E{}", errno_now()) };
                (s, x)
            };
            let (s1, x1) = stat_of();
            // Opened while dumpable: the guard performs every open, and
            // fails closed on a caller whose path it cannot read.
            let Ok(mut out) = std::fs::File::create(&rep) else { return 4 };
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
            let (s2, x2) = stat_of();
            let _ = std::io::Write::write_all(&mut out, format!("dumpable.stat={s1}\ndumpable.statx={x1}\nnodump.stat={s2}\nnodump.statx={x2}\n").as_bytes());
            0
        })
    });
    let Some(code) = code else {
        eprintln!("SKIP: seccomp NEW_LISTENER denied here");
        return;
    };
    assert_eq!(code, Some(0));
    let seen = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("NON-DUMPABLE STATS:\n{seen}");
    let twin = ENV_TWIN.len().to_string();
    let real = ENV_RAW.len().to_string();
    assert_eq!(report_field(&seen, "dumpable.stat"), twin, "control: {seen}");
    assert_eq!(report_field(&seen, "dumpable.statx"), twin, "control: {seen}");
    for k in ["nodump.stat", "nodump.statx"] {
        let v = report_field(&seen, k);
        assert_ne!(v, real, "THE LEAK: a non-dumpable caller's {k} says the real file's size: {seen}");
        assert!(v == twin || v.starts_with('E'), "{k}: the twin's size or a refusal: {seen}");
    }
    eprintln!("NON-DUMPABLE STATS PASS");
}

#[test]
#[ignore]
fn git_diff_and_grep_no_index_print_a_guard_only_twin_whole() {
    // The bug as found (MR !540): `git diff --no-index /dev/null .env` lstats
    // the path, opens it and mmaps st_size bytes; `git grep --no-index` reads
    // exactly st_size and checks it. With the lstat trap both print the
    // twin's line whole; without it the twin is cut at the real size.
    use net_supervisor::guard_filter::LstatTrap;
    if !git_ok() {
        eprintln!("SKIP: git is not installed");
        return;
    }
    for lstat in [LstatTrap::Cwd, LstatTrap::Off] {
        let t = size_tree(&format!("sized-git-{lstat:?}"));
        let out = t.tree.dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let script = format!(
            "export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_PAGER=cat HOME='{home}'\n\
             cd '{home}'\n\
             git diff --no-index /dev/null .env > '{o}/diff' 2>&1\n\
             git grep --no-index -h . .env > '{o}/grep' 2>&1\n\
             git diff --no-index /dev/null big.key > '{o}/kdiff' 2>&1\n\
             exit 0\n",
            home = t.env.parent().unwrap().display(),
            o = out.display(),
        );
        let sh = std::ffi::CString::new("/bin/sh").unwrap();
        let args = [std::ffi::CString::new("sh").unwrap(), std::ffi::CString::new("-c").unwrap(), std::ffi::CString::new(script).unwrap()];
        let traps = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, stat: true, lstat, ..Default::default() };
        let code = run_guarded_traps(&t.tree, traps, |_| {}, || None, move || {
            let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
            argv.push(std::ptr::null());
            unsafe { libc::execv(sh.as_ptr(), argv.as_ptr()) };
            99
        });
        let Some(code) = code else {
            eprintln!("SKIP: seccomp NEW_LISTENER denied here");
            return;
        };
        assert_eq!(code, Some(0));
        let read = |n: &str| std::fs::read_to_string(out.join(n)).unwrap_or_default();
        let all = ["diff", "grep", "kdiff"].iter().map(|n| format!("{n}: {}", read(n))).collect::<Vec<_>>().join("\n");
        eprintln!("GIT SIZED (lstat trap {lstat:?}):\n{all}");
        assert!(!all.contains("REAL-"), "no byte of a real file: {all}");
        let line = ENV_TWIN.trim_end();
        if lstat == LstatTrap::Cwd {
            assert!(read("diff").contains(&format!("+{line}\n")), "git diff prints the twin's line whole: {all}");
            assert!(!read("diff").contains("No newline at end of file"), "{all}");
            assert_eq!(read("grep"), format!("{line}\n"), "git grep prints the twin's line whole: {all}");
            assert!(read("kdiff").contains(&format!("+{}\n", KEY_TWIN.trim_end())), "a twin shorter than its file prints whole, not as binary: {all}");
        } else {
            // The differential: the bug as found, the twin cut at the real size.
            let cut = &ENV_TWIN[..ENV_RAW.len()];
            assert!(read("diff").contains(&format!("+{cut}\n\\ No newline at end of file")), "without the trap the twin is cut: {all}");
        }
    }
    eprintln!("GIT SIZED PASS");
}

#[test]
#[ignore]
fn lstat_trap_cost_is_measured() {
    // confidentiality.md §7.2a "Cost": what trapping lstat costs the tree
    // walkers, in a repository of 3,000 tracked files with two twinned
    // files: `git status` (an lstat of every tracked file relative to the
    // cwd), `find -size` (fts: lstat relative to a directory descriptor) and
    // `ls -lR` (statx relative to the cwd) under every `LstatTrap`: the best
    // of 3 rounds of 3 runs each, the modes interleaved so the noise of the
    // tests that run beside it spreads over all three. Prints the numbers;
    // asserts only that `Cwd` leaves the fts walker near `Off` (it does not
    // trap its calls).
    use net_supervisor::guard_filter::LstatTrap;
    if !git_ok() {
        eprintln!("SKIP: git is not installed");
        return;
    }
    let t = size_tree("lstatcost");
    let repo = t.env.parent().unwrap().to_path_buf();
    for d in 0..30 {
        let dir = repo.join(format!("d{d:02}"));
        std::fs::create_dir_all(&dir).unwrap();
        for f in 0..100 {
            std::fs::write(dir.join(format!("f{f:03}.txt")), format!("{d} {f}\n")).unwrap();
        }
    }
    std::fs::write(repo.join(".gitignore"), ".env\nbig.key\n").unwrap();
    git_at(&repo, &["init", "-q"], None);
    git_at(&repo, &["add", "."], None);
    git_at(&repo, &["commit", "-qm", "files"], None);
    // (label, the stat trap, its lstat part, a registered file hard-linked).
    // "none": no stat trap (the bind posture as launched with one link);
    // "Cwd+linked": what the guard does in the bind posture whose protected
    // file has another link (P0 4c: the launcher turns the trap on there),
    // and in the guard-only posture with one.
    let modes = [("none", false, LstatTrap::Off, false), ("Off", true, LstatTrap::Off, false), ("Cwd", true, LstatTrap::Cwd, false), ("All", true, LstatTrap::All, false), ("Cwd+linked", true, LstatTrap::Cwd, true)];
    let mut rows: Vec<(&str, Vec<f64>)> = modes.iter().map(|m| (m.0, vec![f64::MAX; 3])).collect();
    let link = t.tree.dir.join("env-link");
    for (round, (label, stat, lstat, linked)) in (0..3).flat_map(|r| modes.iter().map(move |m| (r, *m))) {
        let _ = std::fs::remove_file(&link);
        if linked {
            std::fs::hard_link(&t.env, &link).unwrap();
        }
        let out = t.tree.dir.join(format!("cost-{label}-{round}"));
        let script = format!(
            "export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null HOME='{home}'\n\
             cd '{home}'\n\
             best() {{ b=999999999999; for i in 1 2 3; do s=$(date +%s%N); \"$@\" >/dev/null 2>&1; e=$(date +%s%N); d=$(( (e-s)/1000 )); [ $d -lt $b ] && b=$d; done; echo $b; }}\n\
             echo \"$(best git status --porcelain) $(best find . -size +0) $(best ls -lR .)\" > '{out}'\n",
            home = repo.display(),
            out = out.display(),
        );
        let sh = std::ffi::CString::new("/bin/sh").unwrap();
        let args = [std::ffi::CString::new("sh").unwrap(), std::ffi::CString::new("-c").unwrap(), std::ffi::CString::new(script).unwrap()];
        let traps = net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, stat, lstat, ..Default::default() };
        let code = run_guarded_traps(&t.tree, traps, |_| {}, || None, move || {
            let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
            argv.push(std::ptr::null());
            unsafe { libc::execv(sh.as_ptr(), argv.as_ptr()) };
            99
        });
        let Some(code) = code else {
            eprintln!("SKIP: seccomp NEW_LISTENER denied here");
            return;
        };
        assert_eq!(code, Some(0));
        let v: Vec<f64> = std::fs::read_to_string(&out).unwrap_or_default().split_whitespace().filter_map(|x| x.parse().ok()).collect();
        assert_eq!(v.len(), 3, "{v:?}");
        let row = &mut rows.iter_mut().find(|(m, _)| *m == label).unwrap().1;
        for (best, x) in row.iter_mut().zip(v) {
            *best = best.min(x);
        }
    }
    let _ = std::fs::remove_file(&link);
    for (label, v) in &rows {
        eprintln!("LSTAT COST (stat trap {label}): git status {:.1} ms, find -size {:.1} ms, ls -lR {:.1} ms", v[0] / 1000.0, v[1] / 1000.0, v[2] / 1000.0);
    }
    let (off, cwd) = (&rows[1].1, &rows[2].1);
    assert!(cwd[1] < off[1] * 2.0 + 20_000.0, "Cwd leaves the fts walker's lstats free: {rows:?}");
}

// ── plan 14 §11.1 R4: the guard's backstop for locked objects ────────────────

/// Two repositories and a fork, as the kernel oracle has them: `a` holds a
/// deleted key in its pack and a second locked blob stored loose, `fork` is
/// a clone of `a` with its own pack, `clean` holds nothing locked. The
/// policy file locks both blobs (`gitLocks`), with no sanitized copy of any.
struct LockTree {
    tree: OpenTree,
    a: std::path::PathBuf,
    fork: std::path::PathBuf,
    clean: std::path::PathBuf,
    loose: std::path::PathBuf,
    notice: std::path::PathBuf,
    ids: Vec<String>,
}

const LOCKED_KEY: &str = "R4-LOCKED-KEY-BYTES-7731";
const LOOSE_KEY: &str = "R4-LOOSE-KEY-BYTES-7731";

fn lock_tree(tag: &str) -> LockTree {
    let tree = OpenTree::new(tag);
    let a = tree.dir.join("a");
    std::fs::create_dir_all(&a).unwrap();
    git_at(&a, &["init", "-q"], None);
    std::fs::write(a.join("README.md"), "readme of a\n").unwrap();
    std::fs::write(a.join("id_rsa"), format!("{LOCKED_KEY}\n")).unwrap();
    git_at(&a, &["add", "."], None);
    git_at(&a, &["commit", "-qm", "with the key"], None);
    let blob = git_at(&a, &["rev-parse", "HEAD:id_rsa"], None);
    git_at(&a, &["rm", "-q", "id_rsa"], None);
    git_at(&a, &["commit", "-qm", "oops, remove it"], None);
    git_at(&a, &["repack", "-adq"], None);
    // A second locked blob, stored loose (never packed).
    let loose_id = git_at(&a, &["hash-object", "-w", "--stdin"], Some(&format!("{LOOSE_KEY}\n")));
    let loose = a.join(".git/objects").join(&loose_id[..2]).join(&loose_id[2..]);
    assert!(loose.exists());
    let fork = tree.dir.join("fork");
    git_at(&tree.dir, &["clone", "-q", "--no-local", &a.display().to_string(), &fork.display().to_string()], None);
    let clean = tree.dir.join("clean");
    std::fs::create_dir_all(&clean).unwrap();
    git_at(&clean, &["init", "-q"], None);
    std::fs::write(clean.join("pub.txt"), "public words\n").unwrap();
    git_at(&clean, &["add", "."], None);
    git_at(&clean, &["commit", "-qm", "clean"], None);
    git_at(&clean, &["repack", "-adq"], None);
    let notice = tree.dir.join("notice");
    let ids = vec![format!("sha1:{blob}"), format!("sha1:{loose_id}")];
    LockTree { tree, a, fork, clean, loose, notice, ids }
}

fn write_lock_policy(t: &LockTree, ids: &[String]) {
    let ids = ids.iter().map(|i| format!("\"{i}\"")).collect::<Vec<_>>().join(",");
    std::fs::write(&t.tree.policy, format!(r#"{{"agentExe":"","secrets":[],"gitLocks":{{"ids":[{ids}],"noticeFile":"{}"}}}}"#, t.notice.display())).unwrap();
}

fn pack_of(repo: &std::path::Path, ext: &str) -> std::path::PathBuf {
    std::fs::read_dir(repo.join(".git/objects/pack")).unwrap().flatten().map(|e| e.path()).find(|p| p.extension().is_some_and(|x| x == ext)).unwrap()
}

/// Run `script` with /bin/sh under the guard with these traps.
fn run_sh_traps(tree: &OpenTree, traps: net_supervisor::guard_kernel::FilterTraps, script: String) -> Option<Option<i32>> {
    let sh = std::ffi::CString::new("/bin/sh").unwrap();
    let args = [std::ffi::CString::new("sh").unwrap(), std::ffi::CString::new("-c").unwrap(), std::ffi::CString::new(script).unwrap()];
    run_guarded_traps(tree, traps, |_| {}, || None, move || {
        let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
        argv.push(std::ptr::null());
        unsafe { libc::execv(sh.as_ptr(), argv.as_ptr()) };
        99
    })
}

/// The open family AND the rename / link / unlink / truncate family trapped
/// (the launcher sets MANDU_NET_GUARD_PROTECT whenever a lock is in force).
fn lock_traps() -> net_supervisor::guard_kernel::FilterTraps {
    net_supervisor::guard_kernel::FilterTraps { open: true, secrets: true, protect: true, ..Default::default() }
}

#[test]
#[ignore]
fn a_locked_object_in_an_unprepared_repository_is_refused_and_a_clean_one_reads() {
    if !git_ok() {
        eprintln!("SKIP: git is not installed");
        return;
    }
    for locked in [false, true] {
        let t = lock_tree(if locked { "r4" } else { "r4-off" });
        // Off: the same guard with no lock (the differential: the key is there to find).
        write_lock_policy(&t, if locked { &t.ids } else { &[] });
        let out = t.tree.dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let (apack, aidx, fpack, cpack) = (pack_of(&t.a, "pack"), pack_of(&t.a, "idx"), pack_of(&t.fork, "pack"), pack_of(&t.clean, "pack"));
        let script = format!(
            "export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_PAGER=cat HOME={home}\n\
             r() {{ n=$1; shift; \"$@\" > {o}/$n 2>&1; echo $? > {o}/$n.status; }}\n\
             r alog git -C '{a}' log -p\n\
             r ashow git -C '{a}' show HEAD:README.md\n\
             r acat cat '{apack}'\n\
             r aidx cat '{aidx}'\n\
             r loose cat '{loose}'\n\
             r looseshow git -C '{a}' cat-file -p {loose_id}\n\
             r flog git -C '{fork}' log -p\n\
             r fcat cat '{fpack}'\n\
             r clog git -C '{clean}' log -p\n\
             r ccat head -c 4 '{cpack}'\n\
             r mvidx mv '{aidx}' '{dir}/moved.idx'\n\
             r rmidx rm -f '{aidx}'\n\
             r lnpack ln '{apack}' '{dir}/hard.pack'\n\
             r mvpack mv '{apack}' '{dir}/moved.pack'\n\
             r mvloose mv '{loose}' '{dir}/moved-loose'\n\
             r trunc truncate -s 0 '{aidx}'\n\
             r mvdir mv '{a}/.git/objects/pack' '{dir}/packdir'\n\
             r catmoved sh -c 'cat {dir}/packdir/*.pack'\n",
            home = t.tree.dir.display(),
            o = out.display(),
            a = t.a.display(),
            fork = t.fork.display(),
            clean = t.clean.display(),
            dir = t.tree.dir.display(),
            apack = apack.display(),
            aidx = aidx.display(),
            fpack = fpack.display(),
            cpack = cpack.display(),
            loose = t.loose.display(),
            loose_id = t.ids[1].trim_start_matches("sha1:"),
        );
        let Some(code) = run_sh_traps(&t.tree, lock_traps(), script) else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
        assert_eq!(code, Some(0));
        let read = |n: &str| std::fs::read_to_string(out.join(n)).unwrap_or_default();
        let st = |n: &str| read(&format!("{n}.status")).trim().to_string();
        let names = ["alog", "ashow", "acat", "aidx", "loose", "looseshow", "flog", "fcat", "clog", "ccat", "mvidx", "rmidx", "lnpack", "mvpack", "mvloose", "trunc", "mvdir", "catmoved"];
        let all = names.iter().map(|n| format!("{n} [{}]: {}", st(n), read(n).chars().take(300).collect::<String>())).collect::<Vec<_>>().join("\n");
        eprintln!("R4 (locked {locked}):\n{all}");
        // The clean repository is untouched either way.
        assert_eq!(st("clog"), "0", "{all}");
        assert!(read("clog").contains("public words"), "{all}");
        assert_eq!(read("ccat"), "PACK", "{all}");
        if !locked {
            assert!(read("alog").contains(LOCKED_KEY), "the differential: with no lock the history reads: {all}");
            assert!(read("flog").contains(LOCKED_KEY), "{all}");
            assert!(read("looseshow").contains(LOOSE_KEY), "{all}");
            continue;
        }
        for n in names {
            assert!(!read(n).contains(LOCKED_KEY) && !read(n).contains(LOOSE_KEY), "{n}: no locked byte reaches the tree: {all}");
        }
        for n in ["alog", "ashow", "acat", "aidx", "loose", "looseshow", "flog", "fcat"] {
            assert_ne!(st(n), "0", "{n}: refused: {all}");
        }
        assert!(read("acat").contains("Permission denied") && read("fcat").contains("Permission denied"), "EACCES: {all}");
        // The locked pack keeps its checked name, and its index its place.
        for n in ["mvidx", "rmidx", "lnpack", "mvpack", "mvloose", "trunc"] {
            assert_ne!(st(n), "0", "{n}: refused: {all}");
        }
        assert!(t.loose.exists(), "{all}");
        // A moved pack directory is still one (the pack and its index moved together).
        assert_eq!(st("mvdir"), "0", "a directory rename runs: {all}");
        assert_ne!(st("catmoved"), "0", "and the pack in it is still refused: {all}");
        let moved = t.tree.dir.join("packdir");
        assert!(moved.join(aidx.file_name().unwrap()).exists() && moved.join(apack.file_name().unwrap()).exists(), "{all}");
        assert!(std::fs::metadata(moved.join(aidx.file_name().unwrap())).unwrap().len() > 1000, "the index is not truncated: {all}");
        // The person is told once per repository: a and its fork, not clean.
        let notice = std::fs::read_to_string(&t.notice).unwrap_or_default();
        eprintln!("NOTICE:\n{notice}");
        let repos: Vec<&str> = notice.lines().map(|l| l.split('\t').next().unwrap_or("")).collect();
        let (a, fork) = (t.a.display().to_string(), t.fork.display().to_string());
        assert!(repos.contains(&a.as_str()), "{notice}");
        assert!(repos.contains(&fork.as_str()), "{notice}");
        assert!(!notice.contains(&t.clean.display().to_string()), "{notice}");
        assert_eq!(repos.iter().filter(|r| **r == a).count(), 1, "once per repository: {notice}");
        assert!(!notice.contains(LOCKED_KEY), "{notice}");
    }
    eprintln!("R4 BACKSTOP PASS");
}

#[test]
#[ignore]
fn a_temporary_pack_another_writer_left_is_refused_and_the_sessions_own_git_writes_work() {
    // Plan 14 §11.1, the in-progress residual (2026-10-17): git writes a new
    // pack as `objects/pack/tmp_pack_*` (a loose object as `tmp_obj_*`)
    // before it has an index, so the backstop could not judge it and let it
    // through. A `git gc` the person runs outside the session writes every
    // object of the repository there, the locked one included; the agent
    // reading that file mid-write read the key. Planted here before the
    // session (what such a writer leaves, as the agent sees it): refused at
    // every read, rename and link. The session's OWN git still writes and
    // reads its temporary files (a clone through index-pack and through
    // unpack-objects, a repack, a loose write), under the lock.
    if !git_ok() {
        eprintln!("SKIP: git is not installed");
        return;
    }
    for locked in [false, true] {
        let t = lock_tree(if locked { "r4tmp" } else { "r4tmp-off" });
        write_lock_policy(&t, if locked { &t.ids } else { &[] });
        let pd = t.a.join(".git/objects/pack");
        let tmp_pack = pd.join("tmp_pack_Ab12Cd");
        std::fs::copy(pack_of(&t.a, "pack"), &tmp_pack).unwrap();
        let tmp_obj = t.loose.parent().unwrap().join("tmp_obj_Zz99Yy");
        std::fs::copy(&t.loose, &tmp_obj).unwrap();
        // What was planted (with no lock the script's `mv` moves them away).
        let (pack_bytes, obj_bytes) = (std::fs::read(&tmp_pack).unwrap(), std::fs::read(&tmp_obj).unwrap());
        let out = t.tree.dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let script = format!(
            "export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_PAGER=cat HOME={home}\n\
             r() {{ n=$1; shift; \"$@\" > {o}/$n 2>&1; echo $? > {o}/$n.status; }}\n\
             r tcat cat '{tp}'\n\
             r ocat cat '{to}'\n\
             r tmv mv '{tp}' '{dir}/moved-tmp'\n\
             r tln ln '{tp}' '{dir}/linked-tmp'\n\
             r omv mv '{to}' '{dir}/moved-obj'\n\
             r clone1 git -c pack.threads=4 -c transfer.unpackLimit=1 clone -q --no-local '{clean}' '{dir}/c1'\n\
             r log1 git -C '{dir}/c1' log -p\n\
             r init2 git init -q '{dir}/c2'\n\
             r fetch2 git -C '{dir}/c2' -c fetch.unpackLimit=100000 -c transfer.unpackLimit=100000 fetch -q '{clean}' HEAD\n\
             r log2 git -C '{dir}/c2' log -p FETCH_HEAD\n\
             r repack git -C '{dir}/c1' -c pack.threads=4 repack -adq\n\
             r log3 git -C '{dir}/c1' log -p\n\
             r hash sh -c 'echo session-own-object | git -C {dir}/c2 hash-object -w --stdin'\n\
             r catobj sh -c 'git -C {dir}/c2 cat-file -p $(cat {o}/hash)'\n",
            home = t.tree.dir.display(),
            o = out.display(),
            dir = t.tree.dir.display(),
            tp = tmp_pack.display(),
            to = tmp_obj.display(),
            clean = t.clean.display(),
        );
        let Some(code) = run_sh_traps(&t.tree, lock_traps(), script) else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
        assert_eq!(code, Some(0));
        let read = |n: &str| std::fs::read_to_string(out.join(n)).unwrap_or_default();
        let st = |n: &str| read(&format!("{n}.status")).trim().to_string();
        let bytes = |n: &str| std::fs::read(out.join(n)).unwrap_or_default();
        let names = ["tcat", "ocat", "tmv", "tln", "omv", "clone1", "log1", "init2", "fetch2", "log2", "repack", "log3", "hash", "catobj"];
        let all = names.iter().map(|n| format!("{n} [{}]: {}", st(n), String::from_utf8_lossy(&bytes(n)).chars().take(300).collect::<String>())).collect::<Vec<_>>().join("\n");
        eprintln!("R4 TMP (locked {locked}):\n{all}");
        // The session's own git writes its temporary files and reads them back.
        for n in ["clone1", "log1", "init2", "fetch2", "log2", "repack", "log3", "hash", "catobj"] {
            assert_eq!(st(n), "0", "{n}: the session's own git works under the lock: {all}");
        }
        for n in ["log1", "log2", "log3"] {
            assert!(read(n).contains("public words"), "{n}: {all}");
        }
        assert!(read("catobj").contains("session-own-object"), "{all}");
        if !locked {
            // The differential: with no lock the planted files read whole
            // (A's pack, which holds the key, and the locked loose object).
            assert_eq!(bytes("tcat"), pack_bytes, "{all}");
            assert_eq!(bytes("ocat"), obj_bytes, "{all}");
            continue;
        }
        // Nothing of either planted file reached the tree: the reads printed
        // only their refusal (the object's zlib header and the pack's
        // signature are absent), and no output names a locked key.
        let obj_head = obj_bytes[..16].to_vec();
        for n in names {
            let b = bytes(n);
            assert!(!String::from_utf8_lossy(&b).contains(LOCKED_KEY) && !String::from_utf8_lossy(&b).contains(LOOSE_KEY), "{n}: {all}");
            assert!(!b.windows(obj_head.len()).any(|w| w == obj_head.as_slice()), "{n}: none of the planted object's bytes: {all}");
        }
        assert!(!bytes("tcat").starts_with(b"PACK") && bytes("tcat").len() < 1024, "{all}");
        for n in ["tcat", "ocat", "tmv", "tln", "omv"] {
            assert_ne!(st(n), "0", "{n}: refused: {all}");
        }
        assert!(read("tcat").contains("Permission denied"), "EACCES: {all}");
        assert!(tmp_pack.exists() && tmp_obj.exists(), "they keep their names: {all}");
        let notice = std::fs::read_to_string(&t.notice).unwrap_or_default();
        assert!(notice.contains(&t.a.display().to_string()), "{notice}");
        assert!(notice.contains("outside this session"), "{notice}");
    }
    eprintln!("R4 TMP PASS");
}

#[test]
#[ignore]
fn a_sanitized_copy_the_launch_prepared_is_served_before_the_backstop() {
    // The launch prepared a twin of the pack (an `object` entry): the guard
    // serves it, git reads every other object, and the locked blob is a bad
    // object; the backstop never refuses what already has a twin.
    if !git_ok() {
        eprintln!("SKIP: git is not installed");
        return;
    }
    let (tree, repo, public, protected, _) = git_pack_tree("r4twin");
    let policy = std::fs::read_to_string(&tree.policy).unwrap();
    let with_locks = format!("{}{}", policy.trim_end().trim_end_matches('}'), format_args!(r#","gitLocks":{{"ids":["sha1:{protected}"]}}}}"#));
    std::fs::write(&tree.policy, with_locks).unwrap();
    let out = tree.dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let script = format!(
        "export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_PAGER=cat HOME={home}\n\
         cd '{repo}'\n\
         git cat-file -p {public} > {o}/pub 2>&1; echo $? > {o}/pub.status\n\
         git cat-file -p {protected} > {o}/sec 2>&1; echo $? > {o}/sec.status\n",
        home = tree.dir.display(),
        repo = repo.display(),
        o = out.display(),
    );
    let traps = net_supervisor::guard_kernel::FilterTraps { stat: true, ..lock_traps() };
    let Some(code) = run_sh_traps(&tree, traps, script) else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
    assert_eq!(code, Some(0));
    let read = |n: &str| std::fs::read_to_string(out.join(n)).unwrap_or_default();
    assert_eq!(read("pub"), "PUBLIC-A\n", "the sanitized copy serves every other object: {}", read("pub"));
    assert_ne!(read("sec.status").trim(), "0");
    assert!(!read("sec").contains("REAL-SECRET-BLOB"));
    eprintln!("R4 TWIN FIRST PASS");
}

#[test]
#[ignore]
fn git_lock_cost_is_measured() {
    // plan 14 §11.1 R4 "Cost": the price of the backstop for an ordinary
    // open (the prefilter), for an open of a clean pack (a cached verdict),
    // against the same guard with no lock; and a cold lookup of the locked
    // set in the real packs of this checkout (no seccomp: the verdict code
    // alone).
    const N: u32 = 20_000;
    if !git_ok() {
        eprintln!("SKIP: git is not installed");
        return;
    }
    let mut rows = Vec::new();
    for locked in [false, true] {
        let t = lock_tree(if locked { "r4cost" } else { "r4cost-off" });
        write_lock_policy(&t, if locked { &t.ids } else { &[] });
        let report = t.tree.dir.join("report.txt");
        let (plain, cpack, apack, rep) = (t.tree.decoy.clone(), pack_of(&t.clean, "pack"), pack_of(&t.a, "pack"), report.clone());
        let code = run_guarded_traps(&t.tree, lock_traps(), |_| {}, || None, move || {
            let time = |p: &std::path::Path, n: u32| {
                let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
                let t0 = std::time::Instant::now();
                for _ in 0..n {
                    unsafe {
                        let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                        if fd >= 0 {
                            libc::close(fd);
                        }
                    }
                }
                t0.elapsed().as_nanos() as f64 / n as f64 / 1000.0
            };
            let plain_us = time(&plain, N);
            let pack_us = time(&cpack, N / 4);
            let refused_us = time(&apack, N / 4);
            let _ = std::fs::write(&rep, format!("{plain_us:.2} {pack_us:.2} {refused_us:.2}"));
            0
        });
        let Some(code) = code else { eprintln!("SKIP: seccomp NEW_LISTENER denied here"); return };
        assert_eq!(code, Some(0));
        let r = std::fs::read_to_string(&report).unwrap_or_default();
        let v: Vec<f64> = r.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        assert_eq!(v.len(), 3, "{r}");
        rows.push((locked, v));
    }
    for (locked, v) in &rows {
        eprintln!("GIT LOCK COST (lock {locked}): open+close of an ordinary file {:.2} us, of a clean pack {:.2} us, of a locked pack {:.2} us", v[0], v[1], v[2]);
    }
    // A lookup (no cache) in the real packs of this checkout, and in a
    // synthetic index of 4 M objects (a large monorepo's), 1 and 200 locked
    // ids; the page cache is warm.
    let mut idxs: Vec<std::path::PathBuf> = Vec::new();
    let common = std::process::Command::new("git").args(["rev-parse", "--git-common-dir"]).current_dir(env!("CARGO_MANIFEST_DIR")).output().ok().filter(|o| o.status.success());
    if let Some(o) = common {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(String::from_utf8_lossy(&o.stdout).trim()).join("objects/pack");
        idxs = std::fs::read_dir(&dir).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "idx")).collect()).unwrap_or_default();
    }
    let big = std::env::temp_dir().join(format!("mandu-r4-big-{}.idx", run_tag()));
    {
        const COUNT: u128 = 4_000_000;
        let step = u128::MAX / COUNT;
        let name = |i: u128| -> [u8; 20] {
            let mut n = [0u8; 20];
            n[..16].copy_from_slice(&(i * step).to_be_bytes());
            n
        };
        let mut b: Vec<u8> = Vec::with_capacity(1032 + COUNT as usize * 28 + 40);
        b.extend_from_slice(&net_supervisor::git_lock::IDX_MAGIC);
        b.extend_from_slice(&2u32.to_be_bytes());
        let mut fan = [0u32; 256];
        for i in 0..COUNT {
            fan[name(i)[0] as usize] += 1;
        }
        let mut acc = 0u32;
        for f in fan {
            acc += f;
            b.extend_from_slice(&acc.to_be_bytes());
        }
        for i in 0..COUNT {
            b.extend_from_slice(&name(i));
        }
        b.resize(b.len() + COUNT as usize * 8 + 40, 0);
        std::fs::write(&big, &b).unwrap();
    }
    for (label, set_idxs) in [("this checkout", idxs.clone()), ("synthetic", vec![big.clone()])] {
        for k in [1usize, 200] {
            let ids: Vec<String> = (0..k).map(|i| format!("sha1:{:040x}", (i as u128 + 1) * 0x0123_4567_89ab_cdef_u128)).collect();
            let (set, _) = net_supervisor::git_lock::LockedSet::from_ids(ids.iter().map(String::as_str));
            let files: Vec<(std::fs::File, u64)> = set_idxs.iter().map(|p| { let f = std::fs::File::open(p).unwrap(); let n = f.metadata().unwrap().len(); (f, n) }).collect();
            let bytes: u64 = files.iter().map(|(_, n)| *n).sum();
            let objects: u64 = files.iter().map(|(f, n)| {
                use std::os::fd::AsRawFd;
                let mut head = vec![0u8; 1032];
                let got = unsafe { libc::pread(f.as_raw_fd(), head.as_mut_ptr() as *mut libc::c_void, 1032, 0) };
                head.truncate(got.max(0) as usize);
                net_supervisor::git_lock::idx_layout(&head, *n).map(|l| l.count as u64).unwrap_or(0)
            }).sum();
            let t0 = std::time::Instant::now();
            for (f, size) in &files {
                use std::os::fd::AsRawFd;
                assert!(net_supervisor::git_lock::idx_file_holds_any(f.as_raw_fd(), *size, &set).is_ok());
            }
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            eprintln!("GIT LOCK LOOKUP ({label}): {} index(es), {objects} objects, {:.1} MiB, {k} locked id(s): {ms:.3} ms", files.len(), bytes as f64 / 1_048_576.0);
        }
    }
    let _ = std::fs::remove_file(&big);
    let (off, on) = (&rows[0].1, &rows[1].1);
    // One sample per guard, taken minutes apart on a shared runner: load
    // alone moved an ordinary open from 34 to 68 us between two of them
    // (CI, 2026-09-30). So this bound catches only a gross regression (the
    // prefilter doing a lookup on every open); the numbers above are the
    // measurement.
    assert!(on[0] < off[0] * 3.0 + 20.0, "the prefilter adds little to an ordinary open: off {off:?}, on {on:?}");
}

// ── plan 10 §4.1a, "The descriptor handed over" (2026-10-18) ─────────────────

/// The tracee: open `path` for writing (trapped), write a script into it,
/// close it and exec it at once. Exits 7 when the script ran, 95 when the
/// exec met ETXTBSY, 96 when it failed otherwise, 97 when the open did.
fn child_write_then_exec(path: &std::ffi::CString, argv: &[*const libc::c_char; 2]) -> i32 {
    const BODY: &[u8] = b"#!/bin/sh\nexit 7\n";
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC, 0o755);
        if fd < 0 {
            return 97;
        }
        let _ = libc::write(fd, BODY.as_ptr() as *const libc::c_void, BODY.len());
        libc::close(fd);
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ETXTBSY) { 95 } else { 96 }
    }
}

/// Answer the tracee's first open by handing over the guard's own writable
/// descriptor of the file, `ordered` (`guard_kernel::hand_over`) or as the
/// guard did before (ADDFD with SEND, the guard's descriptor still open
/// while the tracee runs on), then CONTINUE every other trapped call until
/// the tracee exits. The tracee's exit code, or None to SKIP.
///
/// The guard's side runs in a process of its own, forked before anything is
/// opened: in the test binary every other test's thread forks too, and a
/// child forked while the guard side holds its descriptor keeps a copy of it
/// (`O_CLOEXEC` closes only at an exec), which made the exec ETXTBSY whatever
/// the order (master pipeline 11893, the binary's 81 tests side by side). A
/// single-threaded process forks nothing it is not asked to.
fn write_then_exec_under(ordered: bool, tag: &str) -> Option<Option<i32>> {
    let dir = std::env::temp_dir().join(format!("mandu-handover-{tag}-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let prog = dir.join("prog.sh");
    let path = std::ffi::CString::new(prog.to_str().unwrap()).unwrap();
    let argv: [*const libc::c_char; 2] = [path.as_ptr(), std::ptr::null()];
    // SAFETY: the child makes plain syscalls on what was built above.
    let guard_side = unsafe { libc::fork() };
    assert!(guard_side >= 0);
    if guard_side == 0 {
        let code = guard_side_write_then_exec(ordered, &path, &argv);
        unsafe { libc::_exit(code) };
    }
    let code = reap(guard_side);
    let _ = std::fs::remove_dir_all(&dir);
    match code {
        Some(EXIT_NO_SECCOMP) => None,
        Some(c) if (80..=84).contains(&c) => panic!("the guard side failed at step {c} (80 socketpair or fork, 81 no listener, 82 its open, 83 the handover, 84 the tracee died by a signal)"),
        c => Some(c),
    }
}

/// `write_then_exec_under`'s guard side, in its own single-threaded process:
/// fork the tracee, serve it, and exit with the tracee's code
/// (EXIT_NO_SECCOMP when it had no listener), or 80-84 for a step of its own
/// that failed.
fn guard_side_write_then_exec(ordered: bool, path: &std::ffi::CString, argv: &[*const libc::c_char; 2]) -> i32 {
    let mut pair = [0 as RawFd; 2];
    // SAFETY: socketpair into an owned array.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, pair.as_mut_ptr()) } != 0 {
        return 80;
    }
    let (sup_sock, child_sock) = (pair[0], pair[1]);
    let child = unsafe { libc::fork() };
    if child < 0 {
        return 80;
    }
    if child == 0 {
        close_inherited(&[child_sock]);
        let traps = net_supervisor::guard_kernel::FilterTraps { open: true, ..Default::default() };
        let listener = match net_supervisor::guard_kernel::install_guard_filter_self(traps) {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if send_fd(child_sock, listener).is_err() {
            unsafe { libc::_exit(EXIT_SETUP_FAIL) };
        }
        unsafe { libc::close(listener) };
        let code = child_write_then_exec(path, argv);
        unsafe { libc::_exit(code) };
    }
    unsafe { libc::close(child_sock) };
    let wait_child = || {
        let mut status = 0;
        // SAFETY: reap our own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 84 }
    };
    let Ok(listener) = recv_fd(sup_sock) else {
        let code = wait_child();
        return if code == EXIT_NO_SECCOMP { code } else { 81 };
    };
    let mut held: Option<RawFd> = None;
    let mut first = true;
    let mut failed = 0;
    loop {
        let mut pfd = libc::pollfd { fd: listener, events: libc::POLLIN, revents: 0 };
        let n = unsafe { libc::poll(&mut pfd, 1, 100) };
        if n < 0 || pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            break;
        }
        if n == 0 {
            continue;
        }
        let Ok(notif) = recv_notif(listener) else { continue };
        if first && notif.data.nr as i64 == libc::SYS_openat as i64 {
            first = false;
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC, 0o755) };
            if fd < 0 {
                failed = 82;
                let _ = fs_supervisor::kernel::respond_errno(listener, notif.id, libc::EIO);
                continue;
            }
            if ordered {
                if net_supervisor::guard_kernel::hand_over(listener, &notif, fd, libc::O_CLOEXEC).is_err() {
                    failed = 83;
                }
            } else {
                let addfd = libc::seccomp_notif_addfd { id: notif.id, flags: libc::SECCOMP_ADDFD_FLAG_SEND as u32, srcfd: fd as u32, newfd: 0, newfd_flags: libc::O_CLOEXEC as u32 };
                // SAFETY: ADDFD reads a seccomp_notif_addfd by pointer.
                let rc = unsafe { libc::ioctl(listener, fs_supervisor::kernel::SECCOMP_IOCTL_NOTIF_ADDFD as _, &addfd as *const libc::seccomp_notif_addfd) };
                if rc < 0 {
                    failed = 83;
                }
                held = Some(fd);
            }
            continue;
        }
        let _ = fs_supervisor::kernel::respond_continue(listener, notif.id);
    }
    let code = wait_child();
    if let Some(fd) = held {
        unsafe { libc::close(fd) };
    }
    unsafe {
        libc::close(listener);
        libc::close(sup_sock);
    }
    if failed != 0 { failed } else { code }
}

#[test]
#[ignore]
fn a_program_written_through_the_guard_runs_at_once() {
    // CI pipelines 11765 and 11856: the guard performs a write-capable open
    // and hands the tracee its own open file description; the kernel refuses
    // to exec a file any description holds for writing. Deterministic here:
    // the control keeps the guard's descriptor open for as long as the
    // tracee runs (what a descheduled guard thread did for a moment), and the
    // tracee's exec meets ETXTBSY; `hand_over` closes it before the tracee
    // resumes, and the script it wrote runs.
    let Some(control) = write_then_exec_under(false, "send") else {
        eprintln!("SKIP: seccomp NEW_LISTENER denied here");
        return;
    };
    assert_eq!(control, Some(95), "the control: the guard's descriptor still open makes the exec ETXTBSY (the test discriminates)");
    for round in 0..10 {
        let ordered = write_then_exec_under(true, &format!("ordered{round}")).expect("the listener came up once already");
        assert_eq!(ordered, Some(7), "round {round}: a program the tracee wrote through the guard runs at once (95 = ETXTBSY)");
    }
    eprintln!("HANDOVER PASS: the guard's write descriptor is closed before the tracee resumes");
}
