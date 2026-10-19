//! Privileged integration test for the execve interception + per-shell sandbox.
//!
//! `#[ignore]`d so the default `cargo test` skips them. Run as root OR inside an
//! unprivileged user namespace, with the kernel feature:
//!
//!   # real root:
//!   sudo cargo test -p exec-supervisor --features kernel -- --ignored --nocapture
//!
//!   # unprivileged user namespace (NO host changes — preferred on a shared host):
//!   unshare --user --map-root-user --mount --net --pid --fork -- \
//!     bash -c 'cargo test -p exec-supervisor --features kernel -- --ignored --nocapture'
//!
//! Requirements: CAP_SYS_ADMIN in the current user namespace (so the supervisor
//! can `unshare(CLONE_NEWNET)`/bind-mount for the AgentShell child) and `bash`
//! on PATH (used as the network probe). The view-selection + argv-resolution
//! policy is covered by the pure unit tests in `src/orchestrate.rs`; THIS test
//! proves the real enforcement: the fork + namespace sandbox the supervisor
//! applies actually isolates the AgentShell child's network.
//!
//! What it asserts, end to end:
//!   1. AgentShell route (default): the supervised child is placed in a fresh
//!      network namespace (egress OFF). A connect() from inside FAILS even though
//!      the parent can reach the same loopback listener — the netns is dead.
//!   2. HumanShell route (net-needing): the supervised child keeps the inherited
//!      network and CONNECTS to that same listener successfully.
//!   3. HumanShell with a withheld approval (symbol-as-command): the exec is
//!      REFUSED before any child is spawned (fail-closed).
//!
//! ── ATTACH FRONT-END (seccomp-unotify execve trap) ──────────────────────────
//! The above three prove the FORK MODEL (`supervise_exec`). The front-end tests
//! below prove the ATTACH path (`run_supervisor`/`handle_exec_notif`) — trapping
//! an UNCOOPERATIVE process's `execve` and ENFORCING the gate via a seccomp
//! user-notification response:
//!   4. DENY (needs only kernel ≥ 5.0): a tracee installs the execve listener on itself, hands
//!      the fd to the supervisor, then `execve`s a SYMBOL-AS-COMMAND argv. The
//!      supervisor decodes the argv (asserted: it read the right program + args),
//!      `plan_exec` says approval-required, and the supervisor answers EPERM → the
//!      tracee's `execve` returns EPERM and the program NEVER runs.
//!   5. CONTINUE-allow (kernel ≥ 5.5; self-SKIPs below that — runs live on this
//!      6.8 host): a benign exec the
//!      arbiter classifies HumanShell-no-approval is answered with CONTINUE so the
//!      real execve proceeds. A seccomp response cannot inject namespaces, so this
//!      allow path is only meaningful where CONTINUE exists (≥ 5.5).
//!
//! The (1) vs (2) differential is fully self-contained: the test FIRST moves
//! itself into a PRIVATE network namespace and brings `lo` UP there, then binds
//! its TCP listener on 127.0.0.1. So:
//!   - the HumanShell child inherits this netns (lo up) → connect SUCCEEDS;
//!   - the AgentShell child `unshare`s AGAIN into a brand-new netns (lo down) →
//!     connect FAILS.
//! Entering our own netns first means we NEVER touch the host's real loopback,
//! whether run as real root or inside a userns — no external connectivity and no
//! host services are needed, and nothing on the host is changed.

#![cfg(feature = "kernel")]

use std::ffi::CString;
use std::io::Write;
use std::net::TcpListener;
use std::os::unix::io::RawFd;

use mandu_arbiter::mock::{op_handler, MockArbiter};
use mandu_arbiter::ArbiterClient;
use exec_supervisor::kernel::{
    self, continue_supported, handle_exec_notif, install_execve_filter_self, notif_recv,
    FrontEndAction,
};
use exec_supervisor::kernel::{ExecOutcome, SandboxBackend, SupervisorConfig, ViewConfig};
use exec_supervisor::orchestrate::ExecRequest;

// The deadline helpers net-supervisor's integration tests share
// (docs/design/testing/test-organization.md §8.5): a wait for a child or a
// thread fails by name with the /proc state of what it waited for, and kills
// that tree, instead of hanging the kernel lane.
#[path = "../../net-supervisor/tests/support/mod.rs"]
mod support;
use support::{in_test_process, join_within, reap_within, readable_within, wait_limit, BoundedCommand};

/// `kernel::supervise_exec` with the caller's deadline (exec-routing.md
/// §4.4) at `wait_limit()`, unless the test set one: past it the crate kills
/// the box's tree and answers `TimedOut`, and the test fails by name with
/// this process's tree. The supervisor's internal waits (the socket
/// hand-over, the clean attempt's drain) carry bounds of their own.
fn supervise_exec(client: &mut ArbiterClient, cfg: &SupervisorConfig, req: &ExecRequest) -> std::io::Result<ExecOutcome> {
    let mut bounded = cfg.clone();
    bounded.deadline = cfg.deadline.or(Some(wait_limit()));
    let got = exec_supervisor::kernel::supervise_exec(client, &bounded, req);
    if let Err(e) = &got {
        if e.kind() == std::io::ErrorKind::TimedOut && cfg.deadline.is_none() {
            panic!("STUCK: supervise_exec of {:?} ran past wait_limit(): {e}. This process's tree:\n{}", req.argv, support::tree_report());
        }
    }
    got
}

// Every script a test EXECUTES is written through this (never std::fs::write):
// see the module header for the ETXTBSY fork race it closes.
#[path = "support/exec_script.rs"]
mod exec_script;
use exec_script::write_exec_script;

/// Skip (pass with a printed note) if the host can't create the namespaces this
/// test needs — e.g. running unprivileged with userns disabled. We probe by
/// trying to `unshare(CLONE_NEWNET)` in a throwaway forked child.
fn netns_available() -> bool {
    // SAFETY: fork + unshare + _exit in the child only.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        let rc = unsafe { libc::unshare(libc::CLONE_NEWNET) };
        unsafe { libc::_exit(if rc == 0 { 0 } else { 1 }) };
    }
    reap_within(pid, wait_limit(), "waiting for the netns probe child").code() == Some(0)
}

/// Move the CURRENT process into a fresh private network namespace and bring its
/// loopback interface UP. Returns false if either step fails (then the test
/// SKIPs). Done on the test thread itself so the listener + every child inherits
/// this netns; the AgentShell child later unshares AGAIN into its own (lo-down)
/// netns. Because this is our own private netns, bringing `lo` up never touches
/// the host's real loopback.
fn enter_private_netns_with_loopback() -> bool {
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        return false;
    }
    bring_loopback_up()
}

/// Bring the `lo` interface UP in the current netns via SIOCSIFFLAGS on an
/// AF_INET datagram socket (the classic ifreq ioctl; no `ip`/`iproute2` needed).
fn bring_loopback_up() -> bool {
    // SAFETY: standard SIOCGIFFLAGS/SIOCSIFFLAGS ioctl dance on a throwaway socket.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return false;
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        // ifr_name = "lo\0"
        let name = b"lo\0";
        for (i, &b) in name.iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }
        // Read current flags.
        if libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr) != 0 {
            libc::close(fd);
            return false;
        }
        // Set IFF_UP | IFF_RUNNING.
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        let rc = libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifr);
        libc::close(fd);
        rc == 0
    }
}

/// Find `bash` on PATH (the network probe interpreter). Returns the program name
/// to hand to execvp (which searches PATH itself).
fn have_bash() -> bool {
    std::process::Command::new("bash")
        .arg("-c")
        .arg("exit 0")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A mock arbiter that classifies `argv[0]` deterministically: `netcmd` →
/// HumanShell (needs network), `shcmd` → HumanShell but withholds the
/// symbol-as-command, anything else → AgentShell (the safe default).
fn routing_arbiter() -> MockArbiter {
    MockArbiter::start(op_handler(|op, req| match op {
        "classifyExec" => {
            let argv0 = req
                .get("argv")
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let needs_net = req
                .get("needsNetwork")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if needs_net {
                Ok(serde_json::json!({
                    "shell": "HumanShell", "identifier": argv0, "reason": "needs network"
                }))
            } else {
                Ok(serde_json::json!({
                    "shell": "AgentShell", "identifier": argv0, "reason": "default AgentShell"
                }))
            }
        }
        "resolveExecArgv" => {
            // Echo argv through; withhold any token in command position.
            let argv: Vec<String> = req
                .get("argv")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let has_sym = argv.iter().any(|s| s.contains("$MDU:"));
            if has_sym {
                let syms: Vec<&String> =
                    argv.iter().filter(|s| s.contains("$MDU:")).collect();
                Ok(serde_json::json!({
                    "argv": argv,
                    "approvals": [{
                        "kind": "symbol_as_command",
                        "symbols": syms,
                        "reason": "symbol used as command — withheld"
                    }],
                    "reason": "withheld symbol-as-command"
                }))
            } else {
                Ok(serde_json::json!({
                    "argv": argv, "approvals": [], "reason": "no symbols → run as-is"
                }))
            }
        }
        _ => Err(format!("unexpected op {op}")),
    }))
}

/// Write a bash network-probe script to a temp file and return its path. The
/// script connects to 127.0.0.1:<port>; exits 0 on success, non-zero on failure.
fn write_probe(port: u16) -> std::path::PathBuf {
    // Unique per call: the tests of this binary run as threads of ONE process,
    // each in its own network namespace, so two of them can hold the same port
    // number and would otherwise share (and rewrite) one probe file.
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "mandu-exec-probe-{}-{}-{}.sh",
        std::process::id(),
        seq,
        port
    ));
    let script = format!(
        "#!/bin/bash\nif exec 3<>/dev/tcp/127.0.0.1/{port}; then exit 0; else exit 7; fi\n"
    );
    // Executable (0755) so execvp runs it directly, and written with no write
    // descriptor in this process: a sibling test's fork must not inherit one,
    // or the exec of this probe fails ETXTBSY (exit 126, not the probe's 0/7).
    write_exec_script(&path, script.as_bytes()).expect("write probe");
    path
}

#[test]
#[ignore = "requires root or an unprivileged userns (CLONE_NEWNET) + bash; run with --features kernel -- --ignored"]
fn execve_routes_to_agentshell_by_default_and_humanshell_when_needed() {
    if !netns_available() {
        eprintln!(
            "SKIP: cannot create a network namespace here (need root or an \
             unprivileged userns with CLONE_NEWNET). Re-run under: \
             unshare --user --map-root-user --net --mount --pid --fork -- ..."
        );
        return;
    }
    if !have_bash() {
        eprintln!("SKIP: bash not found on PATH (the network probe needs it).");
        return;
    }

    // Move THIS process into a private netns with `lo` UP. The listener and the
    // HumanShell child run here; the AgentShell child unshares again (lo down).
    // This never touches the host's real loopback.
    if !enter_private_netns_with_loopback() {
        eprintln!(
            "SKIP: could not enter a private netns + bring lo up (need \
             CAP_NET_ADMIN in the netns; run under unshare --user --map-root-user \
             --net ...)."
        );
        return;
    }

    // Stand up a TCP listener in THIS (private) netns. The HumanShell child shares
    // this netns and must reach it; the AgentShell child is moved to a fresh netns
    // (lo down) and must NOT.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
    let port = listener.local_addr().unwrap().port();
    // Accept+drop connections in a background thread so each probe's connect()
    // completes. Driven by a stop flag (non-blocking accept + poll) so a varying
    // number of connections never makes `join()` hang.
    listener
        .set_nonblocking(true)
        .expect("listener nonblocking");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thr = stop.clone();
    let acceptor = std::thread::spawn(move || {
        while !stop_thr.load(std::sync::atomic::Ordering::Relaxed) {
            match listener.accept() {
                Ok((_s, _a)) => { /* drop → close */ }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let probe = write_probe(port);
    let probe_str = probe.to_string_lossy().to_string();

    let arbiter = routing_arbiter();
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let cfg = SupervisorConfig {
        view: ViewConfig::default(), // FS bind-mount not exercised here (no tracked root)
        // Pin the LEGACY in-process backend: this test proves the netns isolation
        // via `unshare(CLONE_NEWNET)` directly and must not require `bwrap` (the
        // now-default Bubblewrap backend) — bwrap availability isn't probed here.
        backend: SandboxBackend::InProcess,
        landlock_apply: None,
        ..Default::default()
    };

    // ── 1) AgentShell (default route): network MUST be dead. ────────────────
    let agent = supervise_exec(
        &mut client,
        &cfg,
        &ExecRequest {
            argv: vec![probe_str.clone()],
            needs_network: false, // → AgentShell (safe default)
            ..Default::default()
        },
    )
    .expect("supervise AgentShell exec");
    eprintln!("AgentShell outcome: {agent:?}");
    assert_eq!(
        agent.shell,
        mandu_arbiter::protocol::ExecShell::AgentShell,
        "default route must be AgentShell"
    );
    assert!(agent.net_isolated, "AgentShell must isolate the network");
    assert!(
        !agent.refused_pending_approval,
        "AgentShell with no symbols should run"
    );
    assert_eq!(
        agent.child_status,
        Some(7),
        "AgentShell child's connect() MUST fail in the dead netns (probe exits 7)"
    );

    // ── 2) HumanShell (needs network): connect MUST succeed. ────────────────
    let human = supervise_exec(
        &mut client,
        &cfg,
        &ExecRequest {
            argv: vec![probe_str.clone()],
            needs_network: true, // → HumanShell (keeps inherited netns)
            ..Default::default()
        },
    )
    .expect("supervise HumanShell exec");
    eprintln!("HumanShell outcome: {human:?}");
    assert_eq!(
        human.shell,
        mandu_arbiter::protocol::ExecShell::HumanShell,
        "net-needing route must be HumanShell"
    );
    assert!(
        !human.net_isolated,
        "HumanShell keeps the inherited network"
    );
    assert_eq!(
        human.child_status,
        Some(0),
        "HumanShell child's connect() MUST succeed (probe exits 0) — same netns as the listener"
    );

    // ── 3) HumanShell with a symbol in command position: REFUSED. ───────────
    let refused = supervise_exec(
        &mut client,
        &cfg,
        &ExecRequest {
            // A symbol as the command itself → resolveExecArgv withholds it →
            // approval required → the supervisor must refuse before forking.
            argv: vec![
                "bash".into(),
                "-c".into(),
                "$MDU:Read[ab12].body".into(),
            ],
            needs_network: true,
            ..Default::default()
        },
    )
    .expect("supervise refused exec");
    eprintln!("Refused outcome: {refused:?}");
    assert_eq!(refused.shell, mandu_arbiter::protocol::ExecShell::HumanShell);
    assert!(
        refused.refused_pending_approval,
        "a symbol-as-command MUST be refused pending approval (fail-closed)"
    );
    // WHY rides on the outcome, so the box bin's message names the real kind.
    assert!(!refused.gate_unreachable);
    assert_eq!(
        refused.withheld_approvals.iter().map(|a| a.kind.as_str()).collect::<Vec<_>>(),
        vec!["symbol_as_command"]
    );
    assert_eq!(
        refused.child_status, None,
        "no child should be spawned for a refused exec"
    );

    // Cleanup: stop the acceptor (it polls the flag, so join() returns promptly),
    // remove the probe file. Drop the CLIENT first so its still-open arbiter
    // connection closes — otherwise the mock's per-connection read loop blocks and
    // the arbiter's drop()/join() would hang the process. Then drop the arbiter.
    // Leaves NO host state behind — the private netns + its lo-up live only for
    // this process and vanish on exit.
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = join_within(acceptor, wait_limit(), "the probe listener's acceptor thread, after its stop flag");
    let _ = std::fs::remove_file(&probe);
    drop(client); // close the arbiter connection → unblocks the mock's read loop
    drop(arbiter); // now the mock's accept/read thread can join cleanly
}

/// The PRODUCTION entry point: drive the `mandu-exec-box` BINARY (not
/// supervise_exec directly) end to end, proving the launcher's shim path actually
/// boxes an AgentShell command and passes a HumanShell one through. Same
/// netns-differential harness as the routing test, but the routing decision +
/// enforcement flow through the real bin (env + argv + exit code), which is all a
/// launcher shim gets to work with. Pins the InProcess backend (no bwrap needed)
/// via MANDU_EXEC_BOX_BACKEND so it runs in the plain unshare harness.
#[test]
#[ignore = "requires an unprivileged userns (CLONE_NEWNET) + bash; run with --features kernel -- --ignored"]
fn exec_box_bin_boxes_agentshell_and_passes_humanshell() {
    if !netns_available() || !have_bash() {
        eprintln!("SKIP: need an unprivileged userns + bash for the exec-box bin test");
        return;
    }
    if !enter_private_netns_with_loopback() {
        eprintln!("SKIP: could not enter a private netns + bring lo up");
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thr = stop.clone();
    let acceptor = std::thread::spawn(move || {
        while !stop_thr.load(std::sync::atomic::Ordering::Relaxed) {
            match listener.accept() {
                Ok((_s, _a)) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let probe = write_probe(port);
    let probe_str = probe.to_string_lossy().to_string();
    let arbiter = routing_arbiter();
    let bin = env!("CARGO_BIN_EXE_mandu-exec-box");

    // Helper: run the bin with the given routing flag, return its exit code.
    let run = |flag: &str| -> i32 {
        std::process::Command::new(bin)
            .env("MANDU_ARBITER_SOCK", &arbiter.socket_path)
            .env("MANDU_EXEC_BOX_BACKEND", "inprocess")
            .args([flag, "--", &probe_str])
            .status_bounded("mandu-exec-box (a routed probe)")
            .expect("spawn mandu-exec-box")
            .code()
            .expect("bin exited via a normal exit code")
    };

    // ── 1) Boxed (AgentShell): the bin puts the probe in a dead netns → connect
    //       fails → the probe's exit 7 propagates through the bin. ──────────────
    let boxed = run("--no-needs-network");
    eprintln!("exec-box AgentShell exit: {boxed}");
    assert_eq!(
        boxed, 7,
        "a boxed command's connect() MUST fail (net-off) — the bin propagates the probe's 7"
    );

    // ── 2) Passthrough (HumanShell): the bin keeps the inherited netns → connect
    //       succeeds → exit 0. ────────────────────────────────────────────────
    let passed = run("--needs-network");
    eprintln!("exec-box HumanShell exit: {passed}");
    assert_eq!(
        passed, 0,
        "a passthrough command keeps the network → the probe's connect() succeeds"
    );

    // ── 3) Safe-degrade inference: a net-needing PROGRAM name (no flag) must be
    //       inferred as needs_network → HumanShell → net alive. We prove the
    //       inference path (not an explicit flag) routes a real net tool through.
    // The detector keys on argv0's BASENAME, so the file must be named exactly
    // `git` — put it in a private temp dir to avoid collisions.
    let gitdir = unique_dir(&std::env::temp_dir(), "mandu-box-git").expect("a private temp dir");
    let gitish = gitdir.join("git");
    // Not std::fs::copy: that holds a write descriptor a sibling's fork can inherit.
    write_exec_script(&gitish, &std::fs::read(&probe).unwrap()).unwrap();
    let inferred = std::process::Command::new(bin)
        .env("MANDU_ARBITER_SOCK", &arbiter.socket_path)
        .env("MANDU_EXEC_BOX_BACKEND", "inprocess")
        // No routing flag → the bin infers from argv0 basename `git` → needs_network.
        .args(["--", gitish.to_string_lossy().as_ref()])
        .status_bounded("mandu-exec-box (the route inferred from argv0)")
        .expect("spawn mandu-exec-box (inferred)")
        .code()
        .expect("exit code");
    eprintln!("exec-box inferred-git exit: {inferred}");
    assert_eq!(
        inferred, 0,
        "argv0 `git` must be INFERRED net-needing → HumanShell → net alive (exit 0)"
    );

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = join_within(acceptor, wait_limit(), "the probe listener's acceptor thread, after its stop flag");
    let _ = std::fs::remove_file(&probe);
    let _ = std::fs::remove_dir_all(&gitdir);
    drop(arbiter);
}

/// mandu.md §2.x, a WEDGED arbiter (connected, never answering) through the
/// PRODUCTION entry point at its default deadline: a command routed to
/// HumanShell by a live arbiter (`--needs-network`, exit 0 in the test above)
/// is boxed instead, net off (the probe's connect fails: 7), because
/// `classifyExec` gave up at 5 s and took plan_exec's unreachable branch
/// (fail-closed AgentShell). Bounded: the classify and the lineage edge each
/// cost one deadline. Before 2026-10-17 the bin waited for good.
#[test]
#[ignore = "requires an unprivileged userns (CLONE_NEWNET) + bash; run with --features kernel -- --ignored"]
fn exec_box_bin_boxes_a_humanshell_command_when_the_arbiter_hangs() {
    if !netns_available() || !have_bash() {
        eprintln!("SKIP: need an unprivileged userns + bash for the exec-box bin test");
        return;
    }
    if !enter_private_netns_with_loopback() {
        eprintln!("SKIP: could not enter a private netns + bring lo up");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thr = stop.clone();
    let acceptor = std::thread::spawn(move || {
        while !stop_thr.load(std::sync::atomic::Ordering::Relaxed) {
            match listener.accept() {
                Ok((_s, _a)) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    let probe = write_probe(port);
    let probe_str = probe.to_string_lossy().to_string();
    let arbiter = mandu_arbiter::mock::StallingArbiter::wedged();
    let bin = env!("CARGO_BIN_EXE_mandu-exec-box");
    let t0 = std::time::Instant::now();
    let code = std::process::Command::new(bin)
        .env("MANDU_ARBITER_SOCK", &arbiter.socket_path)
        .env("MANDU_EXEC_BOX_BACKEND", "inprocess")
        .args(["--needs-network", "--", &probe_str])
        .status_bounded("mandu-exec-box (a wedged arbiter)")
        .expect("spawn mandu-exec-box")
        .code()
        .expect("bin exited via a normal exit code");
    let took = t0.elapsed();
    eprintln!("exec-box on a wedged arbiter: exit {code} after {took:?}; asked {:?}", arbiter.requests());
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = join_within(acceptor, wait_limit(), "the probe listener's acceptor thread, after its stop flag");
    let _ = std::fs::remove_file(&probe);
    assert_eq!(code, 7, "a command the arbiter could not classify MUST run boxed, net off (fail-closed)");
    assert_eq!(arbiter.asked_after("classifyExec", 1), 1, "{:?}", arbiter.requests());
    assert!(took >= mandu_arbiter::client::DEFAULT_IO_TIMEOUT, "the classify gave up early: {took:?}");
    assert!(took < mandu_arbiter::client::DEFAULT_IO_TIMEOUT * 4, "the exec waited {took:?}");
}

/// FS side of the AgentShell sandbox: when a tracked AgentView root is
/// configured, the supervisor bind-mounts the AgentView worktree OVER the
/// workspace for AgentShell execs, so the child reads the SYMBOLIZED copy. We
/// prove it by giving the workspace and the AgentView differing contents of the
/// same filename and asserting the child `cat`s the AgentView (symbolized) one.
#[test]
#[ignore = "requires root or an unprivileged userns (CLONE_NEWNS + bind mount); run with --features kernel -- --ignored"]
fn agentshell_bind_mounts_agentview_over_workspace() {
    if !netns_available() {
        eprintln!("SKIP: cannot create namespaces here (need root or an unprivileged userns).");
        return;
    }
    if !have_bash() {
        eprintln!("SKIP: bash not found on PATH.");
        return;
    }

    // Two dirs with the SAME filename but different contents.
    let base = unique_dir(&std::env::temp_dir(), "mandu-exec-fs").expect("a private temp dir");
    let workspace = base.join("workspace"); // HumanView (raw)
    let agent_view = base.join("agentview"); // AgentView (symbolized)
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&agent_view).unwrap();
    std::fs::write(workspace.join("note.txt"), b"RAW-SECRET\n").unwrap();
    std::fs::write(
        agent_view.join("note.txt"),
        b"$MDU:Read[ab12].body\n",
    )
    .unwrap();

    // A probe that prints the workspace file's contents to a result file (so the
    // parent can read what the child saw). The probe runs inside the child's mount
    // ns; if the bind-mount worked it reads the AgentView copy.
    let result_path = base.join("seen.txt");
    let probe = base.join("probe.sh");
    let script = format!(
        "#!/bin/bash\ncat {}/note.txt > {} 2>&1\n",
        workspace.display(),
        result_path.display()
    );
    write_exec_script(&probe, script.as_bytes()).unwrap();

    // Arbiter: classify → AgentShell (no net needed).
    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"bash","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let cfg = SupervisorConfig {
        view: ViewConfig {
            agent_view_root: Some(agent_view.to_string_lossy().to_string()),
            workspace: Some(workspace.to_string_lossy().to_string()),
            workspace_writable: false,
        },
        // Pin the LEGACY in-process backend: this test proves the private-mount-ns
        // bind of the AgentView over the workspace via `unshare(CLONE_NEWNS)`+mount
        // directly, and must not require `bwrap` (the now-default backend).
        backend: SandboxBackend::InProcess,
        landlock_apply: None,
        ..Default::default()
    };

    let outcome = supervise_exec(
        &mut client,
        &cfg,
        &ExecRequest {
            argv: vec![probe.to_string_lossy().to_string()],
            needs_network: false,
            ..Default::default()
        },
    )
    .expect("supervise AgentShell fs exec");
    eprintln!("AgentShell FS outcome: {outcome:?}");
    assert_eq!(outcome.shell, mandu_arbiter::protocol::ExecShell::AgentShell);
    assert!(
        outcome.fs_bind_mounted,
        "with a tracked root, AgentShell must bind-mount the AgentView"
    );
    assert_eq!(outcome.child_status, Some(0), "the probe should have run");

    // The child (in its private mount ns) read the AgentView copy; the host
    // workspace file is UNCHANGED (the bind-mount never escaped the child's ns).
    let seen = std::fs::read_to_string(&result_path).unwrap_or_default();
    eprintln!("child saw: {seen:?}");
    assert!(
        seen.contains("$MDU:"),
        "AgentShell child must read the SYMBOLIZED AgentView copy, got: {seen:?}"
    );
    let host_after = std::fs::read_to_string(workspace.join("note.txt")).unwrap();
    assert_eq!(
        host_after, "RAW-SECRET\n",
        "the host workspace must be untouched — bind-mount stayed in the child's mount ns"
    );

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// Is `bubblewrap` runnable here? The Bubblewrap backend execs it, so a host
/// without bwrap (or without unprivileged userns for it) skips the test.
fn bwrap_available() -> bool {
    std::process::Command::new(exec_supervisor::sandbox::BWRAP)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Bubblewrap backend — the Phase-1 asymmetric overlay (exec-routing.md §4).
/// Proves the make-or-break claim end to end: an AgentShell command runs verbatim
/// in a world where the AgentView is writable at the workspace path, the REST of
/// the filesystem is READ-ONLY (a write outside the AgentView fails), and the
/// network is dead. The seccomp deny-filter is ALSO installed (default) for this
/// backend; the probe's ordinary reads/writes/execs completing to exit 0 proves
/// the filter does NOT break normal execution. SKIPPED unless bwrap + a userns are
/// available.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces (see file header)"]
fn bubblewrap_backend_enforces_the_asymmetric_overlay() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }

    // The base MUST live outside /tmp: AgentShell mounts a fresh tmpfs over /tmp
    // (scratch), which would mask a test tree placed there — and, more to the
    // point, the "write outside the AgentView must fail" assertion needs its
    // escape target on the READ-ONLY root, not on the writable /tmp scratch.
    let Some(base) = outside_tmp_dir("bwrap") else { return };
    let workspace = base.join("workspace"); // HumanView (raw)
    let agent_view = base.join("agentview"); // AgentView (symbolized), bound RW over ws
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&agent_view).unwrap();
    std::fs::write(workspace.join("note.txt"), b"RAW-SECRET\n").unwrap();
    std::fs::write(agent_view.join("note.txt"), b"$MDU:Read[ab12].body\n").unwrap();

    // The probe writes its findings INTO the workspace (the ONLY writable place —
    // the AgentView bind), so the parent reads them from the AgentView side. It:
    //   (a) reads workspace/note.txt   → should see the AgentView SYMBOL copy (RW bind);
    //   (b) writes inside the workspace → succeeds (RW AgentView);
    //   (c) writes OUTSIDE (base/)      → must FAIL (RO root) → records ESCAPE-BLOCKED.
    let escape = base.join("escape.txt");
    let probe = base.join("probe.sh");
    let script = format!(
        "#!/bin/bash\n\
         cat {ws}/note.txt > {ws}/seen.txt 2>&1\n\
         echo INSIDE-OK >> {ws}/seen.txt\n\
         if echo ESCAPED > {esc} 2>/dev/null; then echo ESCAPE-SUCCEEDED >> {ws}/seen.txt; \
         else echo ESCAPE-BLOCKED >> {ws}/seen.txt; fi\n",
        ws = workspace.display(),
        esc = escape.display(),
    );
    write_exec_script(&probe, script.as_bytes()).unwrap();

    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"bash","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let cfg = SupervisorConfig {
        view: ViewConfig {
            agent_view_root: Some(agent_view.to_string_lossy().to_string()),
            workspace: Some(workspace.to_string_lossy().to_string()),
            workspace_writable: false,
        },
        backend: SandboxBackend::Bubblewrap,
        landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
        ..Default::default()
    };

    let outcome = supervise_exec(
        &mut client,
        &cfg,
        &ExecRequest {
            argv: vec![probe.to_string_lossy().to_string()],
            needs_network: false,
            ..Default::default()
        },
    )
    .expect("supervise AgentShell exec via bubblewrap");
    eprintln!("Bubblewrap outcome: {outcome:?}");
    assert_eq!(outcome.shell, mandu_arbiter::protocol::ExecShell::AgentShell);
    assert!(outcome.net_isolated, "AgentShell egress must be off");
    assert!(outcome.ro_enforced, "the bubblewrap backend must enforce the RO overlay");
    assert_eq!(outcome.child_status, Some(0), "the probe should have run to completion");

    // The parent reads the probe's findings from the AgentView side of the bind.
    let seen = std::fs::read_to_string(agent_view.join("seen.txt")).unwrap_or_default();
    eprintln!("probe saw: {seen:?}");
    assert!(
        seen.contains("$MDU:"),
        "the command must read the SYMBOLIZED AgentView copy at the workspace path, got: {seen:?}"
    );
    assert!(seen.contains("INSIDE-OK"), "a write inside the AgentView must succeed");
    assert!(
        seen.contains("ESCAPE-BLOCKED"),
        "a write OUTSIDE the AgentView must be denied by the RO overlay, got: {seen:?}"
    );
    // The out-of-AgentView write never landed on the host.
    assert!(!escape.exists(), "the escape write must not have reached the host filesystem");

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// Writable-AgentView boxing — the SECOND RW bind (the AgentView at its OWN
/// path). The launcher's fs-view rewrites the live agent's cwd INTO the
/// AgentView worktree (cwd = the AgentView REAL path, not the workspace path),
/// and a boxed command inherits that cwd — before the identity bind it chdir'd
/// into the RO base layer and every relative write at its own cwd (`sed -i`,
/// `sort -o`, `> out.txt`) failed EROFS. Proves end to end: a relative write at
/// an AgentView cwd succeeds and lands in the REAL AgentView dir on the host,
/// the same write at a cwd OUTSIDE both binds is denied by the RO overlay, and
/// the workspace REAL dir stays untouched (the overlay bind is in-box only).
/// SKIPPED unless bwrap + a userns are available.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces (see file header)"]
fn bubblewrap_backend_writable_agentview_at_own_path() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    let (base, workspace, agent_view) = match bwrap_view_tree("avcwd") {
        Some(t) => t,
        None => return,
    };
    // A marker only the REAL AgentView tree has: the probe reads it RELATIVE to
    // its cwd, proving the cwd really is the AgentView before the write leg.
    std::fs::write(agent_view.join("marker.txt"), b"AV-MARKER\n").unwrap();

    // sh/echo are not net-needing, so the request routes AgentShell (boxed).
    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"sh","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let cfg = SupervisorConfig {
        view: ViewConfig {
            agent_view_root: Some(agent_view.to_string_lossy().to_string()),
            workspace: Some(workspace.to_string_lossy().to_string()),
            workspace_writable: false,
        },
        backend: SandboxBackend::Bubblewrap,
        landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
        ..Default::default()
    };

    // ── (a)+(b) cwd = the AgentView REAL path; a RELATIVE write must land. ──
    let outcome = supervise_exec(
        &mut client,
        &cfg,
        &ExecRequest {
            argv: vec![
                "sh".into(),
                "-c".into(),
                "test -f marker.txt && echo boxed > out.txt".into(),
            ],
            needs_network: false,
            cwd: Some(agent_view.to_string_lossy().to_string()),
            ..Default::default()
        },
    )
    .expect("supervise AgentShell exec at an AgentView cwd");
    eprintln!("AgentView-cwd outcome: {outcome:?}");
    assert_eq!(outcome.shell, mandu_arbiter::protocol::ExecShell::AgentShell);
    assert!(outcome.net_isolated, "AgentShell egress must be off");
    assert!(outcome.ro_enforced, "the bubblewrap backend must enforce the RO overlay");
    assert_eq!(
        outcome.child_status,
        Some(0),
        "a relative write at the AgentView cwd must succeed (the identity bind)"
    );
    let written = std::fs::read_to_string(agent_view.join("out.txt")).unwrap_or_default();
    assert_eq!(
        written, "boxed\n",
        "the write must land in the REAL AgentView dir on the host"
    );

    // ── (c) the same write at a cwd OUTSIDE both binds must fail (RO base). ──
    let outside = base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let denied = supervise_exec(
        &mut client,
        &cfg,
        &ExecRequest {
            argv: vec!["sh".into(), "-c".into(), "echo boxed > out.txt".into()],
            needs_network: false,
            cwd: Some(outside.to_string_lossy().to_string()),
            ..Default::default()
        },
    )
    .expect("supervise AgentShell exec at an outside cwd");
    eprintln!("outside-cwd outcome: {denied:?}");
    assert_ne!(
        denied.child_status,
        Some(0),
        "a write at a cwd outside both binds must be denied by the RO overlay"
    );
    assert!(
        !outside.join("out.txt").exists(),
        "the outside write must not have reached the host filesystem"
    );

    // ── (d) the workspace REAL dir on the host is untouched. ──
    assert!(
        !workspace.join("out.txt").exists(),
        "the workspace real dir must be untouched — the AgentView-cwd write went to the AgentView"
    );

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// The workspace without an AgentView (exec-routing.md §7.2): integrity OFF
/// (`secrets`), the launcher bakes `MANDU_EXEC_BOX_WORKSPACE_RW=1`, and the
/// box binds the workspace WRITABLE at its own path. The 2026-10-01 replay
/// smoke finding: without it a boxed `sed -i` failed `couldn't open temporary
/// file …: Read-only file system`. Proves: (a) without the flag the in-place
/// writers fail and leave the file as it was (the bug, reproduced); (b) with
/// it `sed -i` and `sort -o` succeed and edit the REAL file; (c) a write at a
/// cwd outside the workspace is still denied by the RO base; (d) the box is
/// still net-off. SKIPPED unless bwrap + a userns are available.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces (see file header)"]
fn bubblewrap_backend_writable_workspace_without_agentview() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    let (base, workspace, _agent_view) = match bwrap_view_tree("wsrw") {
        Some(t) => t,
        None => return,
    };
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(workspace.join("src/x.js"), b"const a = 1;\n").unwrap();
    std::fs::write(workspace.join("list.txt"), b"b\na\n").unwrap();
    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"sh","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let ws = workspace.to_string_lossy().to_string();
    let cfg = |writable: bool| SupervisorConfig {
        view: ViewConfig { agent_view_root: None, workspace: Some(ws.clone()), workspace_writable: writable },
        backend: SandboxBackend::Bubblewrap,
        landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
        ..Default::default()
    };
    let run = |client: &mut ArbiterClient, cfg: &SupervisorConfig, script: &str, cwd: &std::path::Path| {
        supervise_exec(
            client,
            cfg,
            &ExecRequest {
                argv: vec!["sh".into(), "-c".into(), script.into()],
                needs_network: false,
                cwd: Some(cwd.to_string_lossy().to_string()),
                ..Default::default()
            },
        )
        .expect("supervise AgentShell exec")
    };
    let in_place = "sed -i 's/a/b/' src/x.js && sort -o list.txt list.txt";

    // (a) the bug: no flag → the RO root refuses the in-place writers.
    let ro = run(&mut client, &cfg(false), in_place, &workspace);
    eprintln!("read-only workspace outcome: {ro:?}");
    assert_eq!(ro.shell, mandu_arbiter::protocol::ExecShell::AgentShell);
    assert_ne!(ro.child_status, Some(0), "without the flag the workspace is read-only in the box");
    assert_eq!(std::fs::read_to_string(workspace.join("src/x.js")).unwrap(), "const a = 1;\n");

    // (b) the flag: both in-place writers succeed and edit the REAL files.
    let rw = run(&mut client, &cfg(true), in_place, &workspace);
    eprintln!("writable workspace outcome: {rw:?}");
    assert!(rw.net_isolated, "the box stays net-off");
    assert!(rw.ro_enforced, "the RO overlay still holds outside the workspace");
    assert_eq!(rw.child_status, Some(0), "sed -i and sort -o must succeed in a writable workspace");
    assert_eq!(std::fs::read_to_string(workspace.join("src/x.js")).unwrap(), "const b = 1;\n");
    assert_eq!(std::fs::read_to_string(workspace.join("list.txt")).unwrap(), "a\nb\n");

    // (c) outside the workspace the RO base still refuses the write.
    let outside = base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let denied = run(&mut client, &cfg(true), "echo boxed > out.txt", &outside);
    assert_ne!(denied.child_status, Some(0), "a write outside the workspace stays denied");
    assert!(!outside.join("out.txt").exists());

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// A project under /tmp (open-source-release checklist a7). The box mounts a
/// fresh tmpfs over /tmp, so a no-AgentView launch from `/tmp/x/proj` died on
/// EVERY boxed command with `bwrap: Can't chdir to /tmp/x/proj`. The plan now
/// re-binds the workspace READ-ONLY at its own path after the tmpfs. Proves,
/// through the real bwrap + Landlock applier:
///   (a) the ordinary box chdirs into the /tmp project and reads its file;
///   (b) a sibling of the project elsewhere in the real /tmp stays INVISIBLE;
///   (c) the project is read-only (a write at the cwd fails, nothing lands);
///   (d) the scratch /tmp is still writable and private (nothing reaches the host);
///   (e) the CLEAN box never sees the project: its attempt falls back to the
///       ordinary box, no clean verdict is reported.
/// The probe proves each point by its exit status: a bwrap setup failure (the
/// old chdir error) exits nonzero, so exit 0 means the box ran AND every
/// condition held. SKIPPED unless bwrap + a userns are available and /tmp is
/// usable.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces (see file header)"]
fn bubblewrap_backend_runs_a_project_under_tmp() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    let _g = STDIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !stdin_to_devnull() {
        eprintln!("SKIP: cannot point stdin at /dev/null");
        return;
    }
    // pid + nanos: under kernel-tests.sh the test runs in a fresh pid ns, where
    // the pid alone is the same small number on every run.
    let tag = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    );
    let base = std::path::PathBuf::from(format!("/tmp/mandu-exec-tmpproj-{tag}"));
    let proj = base.join("proj");
    if std::fs::create_dir_all(&proj).is_err() {
        eprintln!("SKIP: /tmp is not writable here");
        return;
    }
    // Removed however the test ends, a failed assertion (a panic) included.
    let _base_guard = RemoveOnDrop(base.clone());
    std::fs::write(proj.join("README.md"), b"HELLO-TMP").unwrap();
    std::fs::write(base.join("sibling-secret.txt"), b"AKIA-SIBLING").unwrap();
    let scratch = format!("/tmp/mandu-exec-tmpproj-scratch-{tag}");
    // Only there if the box's /tmp was not private (an assertion below fails).
    let _scratch_guard = RemoveOnDrop(std::path::PathBuf::from(&scratch));    let proj_s = proj.to_string_lossy().to_string();

    let (arbiter, reports) = clean_arbiter("toolu_tmp_project");
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let mut cfg = SupervisorConfig {
        view: ViewConfig { agent_view_root: None, workspace: Some(proj_s.clone()), workspace_writable: false },
        backend: SandboxBackend::Bubblewrap,
        landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
        clean_box: false,
        clean_via: None,
        clean_only: false,
        ..Default::default()
    };
    let probe = format!(
        "test \"$(cat README.md)\" = HELLO-TMP \
         && test \"$(pwd -P)\" = {proj} \
         && ! test -e {base}/sibling-secret.txt \
         && ! ( echo x > w.txt ) 2>/dev/null \
         && echo s > {scratch} && test -f {scratch}",
        proj = proj_s,
        base = base.display(),
        scratch = scratch,
    );
    let req = ExecRequest {
        argv: vec!["sh".into(), "-c".into(), probe],
        cwd: Some(proj_s.clone()),
        needs_network: false,
        ..Default::default()
    };

    // ── (a)–(d) the ordinary box ──
    let outcome = supervise_exec(&mut client, &cfg, &req).expect("supervise a /tmp-project exec");
    eprintln!("tmp-project outcome: {outcome:?}");
    assert_eq!(outcome.shell, mandu_arbiter::protocol::ExecShell::AgentShell);
    assert_eq!(
        outcome.child_status,
        Some(0),
        "the boxed command must chdir into the /tmp project, read it, not see its /tmp sibling, \
         fail to write the project, and write the private scratch"
    );
    assert!(!proj.join("w.txt").exists(), "the project stays read-only");
    assert!(!std::path::Path::new(&scratch).exists(), "the scratch /tmp is private to the box");

    // ── (e) the clean box: never sees the project, falls back, no verdict ──
    cfg.clean_box = true;
    let read = ExecRequest {
        argv: vec!["cat".into(), "README.md".into()],
        cwd: Some(proj_s.clone()),
        needs_network: false,
        ..Default::default()
    };
    let fb = supervise_exec(&mut client, &cfg, &read).expect("clean attempt + fallback");
    eprintln!("tmp-project clean outcome: {fb:?}");
    assert_eq!(fb.child_status, Some(0), "the ordinary-box fallback reads the project");
    assert!(fb.clean.is_none(), "a /tmp project's bytes can never yield a clean outcome");
    assert!(reports.lock().unwrap().is_empty(), "no clean verdict for the failed attempt");

    drop(client);
    drop(arbiter);
    // `_base_guard` and `_scratch_guard` remove the tree and the scratch file.
}

/// The agent's own /tmp (exec-routing.md §7.2, 2026-10-19). demo-c14: the
/// agent ran `curl -o /tmp/reset1042.out …` (unboxed), then a boxed `cat
/// /tmp/reset1042.out` read the box's fresh tmpfs and printed "No such file or
/// directory". In the integrity-OFF posture (`workspace_writable`, no
/// AgentView) the box now binds the REAL /tmp. Proves, through the real bwrap
/// + Landlock applier and the production socket scan:
///   (a) a file the host wrote to /tmp before the box ran is read in-box;
///   (b) a file the box writes to /tmp lands in the real /tmp;
///   (c) a Unix socket directly in /tmp is masked in-box (`/dev/null`, a
///       character device, not a socket), and an ssh-agent's directory
///       (`ssh-…`, like tmux's and X11's) is hidden whole;
///   (d) the box stays net-off and RO outside the workspace and /tmp;
///   (e) the integrity-ON posture (no flag) still sees a fresh, empty /tmp.
/// SKIPPED unless bwrap + a userns are available and /tmp is usable.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces (see file header)"]
fn bubblewrap_backend_shares_the_real_tmp_in_the_integrity_off_box() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    let (base, workspace, _agent_view) = match bwrap_view_tree("realtmp") {
        Some(t) => t,
        None => return,
    };
    let _base_guard = RemoveOnDrop(base.clone());
    let tag = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    );
    let dir = std::path::PathBuf::from(format!("/tmp/mandu-exec-realtmp-{tag}"));
    if std::fs::create_dir_all(&dir).is_err() {
        eprintln!("SKIP: /tmp is not writable here");
        return;
    }
    let _dir_guard = RemoveOnDrop(dir.clone());
    std::fs::write(dir.join("reset.out"), b"{\"status\":\"processing\"}").unwrap();
    // A socket directly in /tmp (a database's, say: masked) and an ssh-agent's
    // directory (hidden whole), as `host_sockets::scan_host` reads the real /tmp.
    let sock = std::path::PathBuf::from(format!("/tmp/mandu-exec-realtmp-{tag}.sock"));
    let _sock_guard = RemoveOnDrop(sock.clone());
    let _listener = std::os::unix::net::UnixListener::bind(&sock).expect("a socket in /tmp");
    let agent_dir = std::path::PathBuf::from(format!("/tmp/ssh-manduexec{}", tag.replace('-', "")));
    std::fs::create_dir_all(&agent_dir).unwrap();
    let _agent_guard = RemoveOnDrop(agent_dir.clone());
    let _agent = std::os::unix::net::UnixListener::bind(agent_dir.join("agent.1")).expect("an ssh-agent-like socket");
    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"sh","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let ws = workspace.to_string_lossy().to_string();
    let cfg = |writable: bool| SupervisorConfig {
        view: ViewConfig { agent_view_root: None, workspace: Some(ws.clone()), workspace_writable: writable },
        backend: SandboxBackend::Bubblewrap,
        landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
        ..Default::default()
    };
    let run = |client: &mut ArbiterClient, cfg: &SupervisorConfig, script: String| {
        supervise_exec(
            client,
            cfg,
            &ExecRequest {
                argv: vec!["sh".into(), "-c".into(), script],
                needs_network: false,
                cwd: Some(ws.clone()),
                ..Default::default()
            },
        )
        .expect("supervise AgentShell exec")
    };
    let d = dir.display();
    let outside = base.join("outside.txt");

    // (a)–(d) integrity OFF: the agent's own /tmp
    let probe = format!(
        "grep -q processing {d}/reset.out \
         && echo boxed > {d}/from-box.txt \
         && ! test -S {s} && test -c {s} \
         && ! test -e {a}/agent.1 \
         && ! ( echo x > {out} ) 2>/dev/null",
        s = sock.display(),
        a = agent_dir.display(),
        out = outside.display(),
    );
    let shared = run(&mut client, &cfg(true), probe);
    eprintln!("real-/tmp outcome: {shared:?}");
    assert!(shared.net_isolated, "the box stays net-off");
    assert!(shared.ro_enforced, "the RO overlay still holds outside the workspace and /tmp");
    assert_eq!(
        shared.child_status,
        Some(0),
        "the box must read the host's /tmp file, write to the real /tmp, see the /tmp socket masked, \
         and still fail a write outside the workspace and /tmp"
    );
    assert_eq!(std::fs::read_to_string(dir.join("from-box.txt")).unwrap(), "boxed\n", "the box's write landed in the real /tmp");
    assert!(!outside.exists());

    // (e) integrity ON (no flag): a fresh, private /tmp
    let fresh = run(&mut client, &cfg(false), format!("! test -e {d}/reset.out && ! test -e {d} && echo s > /tmp/fresh-{tag}"));
    eprintln!("fresh-/tmp outcome: {fresh:?}");
    assert_eq!(fresh.child_status, Some(0), "the integrity-ON box sees none of the real /tmp");
    assert!(!std::path::Path::new(&format!("/tmp/fresh-{tag}")).exists(), "its scratch stays private");

    drop(client);
    drop(arbiter);
}

/// A test's file or tree, removed when the guard drops: at the end of the
/// test and also when an assertion fails, since a panic unwinds through it
/// (test-organization.md §8.5). A path outside `$TMPDIR` (here, the real
/// `/tmp`, which a box test needs) is not swept by the suite runner, so the
/// test removes it itself.
struct RemoveOnDrop(std::path::PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        match std::fs::symlink_metadata(&self.0) {
            Ok(m) if m.is_dir() => {
                let _ = std::fs::remove_dir_all(&self.0);
            }
            Ok(_) => {
                let _ = std::fs::remove_file(&self.0);
            }
            Err(_) => {}
        }
    }
}

/// Locate `strace` (the ptrace-deny differential needs it). `None` → SKIP.
fn strace_path() -> Option<String> {
    for p in ["/usr/bin/strace", "/bin/strace"] {
        if std::path::Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

/// A fresh, uniquely named directory OUTSIDE /tmp for a box test: the box
/// mounts a fresh tmpfs over /tmp, so a tree there would be masked inside AND
/// sit on the writable side of the RO assertions. Under `/var/tmp` (on the
/// box's read-only root, like the rest of the host), never under the real
/// `$HOME` (test-organization.md §8.4). The name is unique by construction: a
/// random suffix and an atomic `create_dir` that refuses an existing name, not
/// the pid, which is the same in every run inside the harness's pid namespace
/// (two parallel runs shared one tree, and a killed run's stale socket failed
/// the next AddrInUse). Mode 0700, like mkdtemp. `None` (→ SKIP) when
/// `/var/tmp` is unusable.
fn outside_tmp_dir(tag: &str) -> Option<std::path::PathBuf> {
    let dir = unique_dir(std::path::Path::new("/var/tmp"), &format!("mandu-exec-{tag}"));
    if dir.is_none() {
        eprintln!("SKIP: cannot make a test dir under /var/tmp (the tree must live outside /tmp)");
    }
    dir
}

/// mkdtemp: a new directory `<root>/<prefix>-<16 random hex>`, mode 0700,
/// made by an atomic `create_dir` that refuses an existing name (so two
/// concurrent runs, whose pids are equal inside their pid namespaces, never
/// share one). `None` when `root` is unusable.
fn unique_dir(root: &std::path::Path, prefix: &str) -> Option<std::path::PathBuf> {
    use std::io::Read;
    use std::os::unix::fs::DirBuilderExt;
    for _ in 0..16 {
        let mut rnd = [0u8; 8];
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut rnd)).ok()?;
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let dir = root.join(format!("{prefix}-{suffix}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Some(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
    }
    None
}

/// Set up a workspace/AgentView pair outside /tmp (`outside_tmp_dir`) for a
/// bwrap-backend test that needs an outside-visible writable path. Returns
/// `None` (→ SKIP) when no such dir can be made.
fn bwrap_view_tree(tag: &str) -> Option<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> {
    let base = outside_tmp_dir(tag)?;
    let workspace = base.join("workspace");
    let agent_view = base.join("agentview");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&agent_view).unwrap();
    Some((base, workspace, agent_view))
}

/// Bubblewrap backend, seccomp deny-filter — proves a DANGEROUS syscall is blocked
/// inside the AgentShell. `strace` needs `ptrace(2)` to trace its child: WITHOUT
/// the filter, `strace /bin/true` traces true and exits 0; WITH the default
/// deny-filter, the ptrace syscall returns EPERM and strace fails (non-zero).
///
/// The probe must PROVE the sandbox actually RAN before the denial is asserted:
/// a bwrap argv/setup error exits 1 without running the command — by exit code
/// alone that is indistinguishable from "strace was blocked inside the box"
/// (this test false-passed exactly that way when bwrap 0.6 rejected
/// --disable-userns). So the child first drops a sentinel into the ONLY
/// outside-visible writable place (the AgentView RW bind over the workspace —
/// /tmp is a fresh tmpfs INSIDE the box, invisible outside), then execs strace;
/// the test asserts sentinel AND non-zero exit. SKIPPED unless bwrap + a userns
/// + bash + strace are all available.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces + strace (see file header)"]
fn bubblewrap_backend_seccomp_denies_ptrace() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    if !have_bash() {
        eprintln!("SKIP: bash not found on PATH (the sentinel probe needs it).");
        return;
    }
    let strace = match strace_path() {
        Some(s) => s,
        None => {
            eprintln!("SKIP: strace not found — the ptrace-deny differential needs it.");
            return;
        }
    };
    let truebin = if std::path::Path::new("/bin/true").exists() {
        "/bin/true"
    } else {
        "/usr/bin/true"
    };
    let (base, workspace, agent_view) = match bwrap_view_tree("seccomp") {
        Some(t) => t,
        None => return,
    };

    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"strace","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    // The DEFAULT backend is now Bubblewrap; we name it explicitly for clarity.
    let cfg = SupervisorConfig {
        view: ViewConfig {
            agent_view_root: Some(agent_view.to_string_lossy().to_string()),
            workspace: Some(workspace.to_string_lossy().to_string()),
            workspace_writable: false,
        },
        backend: SandboxBackend::Bubblewrap,
        landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
        ..Default::default()
    };

    // Sentinel first (proves the box ran), then exec strace (the denial probe).
    // `&&` so a failed sentinel write cannot mask itself behind strace's exit.
    let cmd = format!(
        "echo SANDBOX-RAN > {ws}/sentinel.txt && exec {strace} -f {truebin}",
        ws = workspace.display(),
    );
    let outcome = supervise_exec(
        &mut client,
        &cfg,
        &ExecRequest {
            argv: vec!["bash".into(), "-c".into(), cmd],
            needs_network: false,
            ..Default::default()
        },
    )
    .expect("supervise strace under the seccomp deny-filter");
    eprintln!("seccomp/ptrace outcome: {outcome:?}");
    assert_eq!(outcome.shell, mandu_arbiter::protocol::ExecShell::AgentShell);
    assert!(outcome.ro_enforced, "the bubblewrap backend must be in force");
    // Gate 1: the sandbox RAN (the sentinel landed in the AgentView side of the
    // bind). A bwrap argv/setup error never writes it → loud failure here, not
    // a false-pass below.
    let sentinel = std::fs::read_to_string(agent_view.join("sentinel.txt")).unwrap_or_default();
    assert!(
        sentinel.contains("SANDBOX-RAN"),
        "the sandboxed probe never ran (bwrap argv/setup failure?) — exit {:?} proves nothing about seccomp",
        outcome.child_status
    );
    // Gate 2: strace could NOT trace (ptrace → EPERM) → non-zero exit. A
    // successful trace of /bin/true would exit 0, so Some(0) is a FAILURE here.
    match outcome.child_status {
        Some(0) => panic!("ptrace was NOT blocked — strace traced /bin/true and exited 0"),
        Some(code) => eprintln!(
            "SECCOMP PASS: sandbox ran (sentinel present) and strace exited {code} (non-zero) — \
             ptrace blocked by the deny-filter"
        ),
        None => panic!("the strace child was signalled, not cleanly exited: {outcome:?}"),
    }

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// Userns-NESTING denial, both postures. `--disable-userns` (bwrap ≥ 0.8) or the
/// probe-selected seccomp fallback (bwrap < 0.8: unshare/clone with CLONE_NEWUSER
/// → EPERM) must BOTH make `unshare --user` fail inside the AgentShell — the box
/// must never mint a fresh user namespace to regain the capabilities we dropped.
/// Same sentinel-first shape as the ptrace test so a bwrap setup error fails
/// loudly instead of masquerading as the denial.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces + util-linux unshare (see file header)"]
fn bubblewrap_backend_denies_nested_userns() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    if !have_bash() {
        eprintln!("SKIP: bash not found on PATH (the probe needs it).");
        return;
    }
    let (base, workspace, agent_view) = match bwrap_view_tree("userns") {
        Some(t) => t,
        None => return,
    };

    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"bash","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let cfg = SupervisorConfig {
        view: ViewConfig {
            agent_view_root: Some(agent_view.to_string_lossy().to_string()),
            workspace: Some(workspace.to_string_lossy().to_string()),
            workspace_writable: false,
        },
        backend: SandboxBackend::Bubblewrap,
        landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
        ..Default::default()
    };

    // Sentinel first, then the nesting attempt; record the verdict either way so
    // the probe itself always exits 0 (a non-zero exit means SETUP failed).
    let cmd = format!(
        "echo SANDBOX-RAN > {ws}/seen.txt && \
         if unshare --user true 2>>{ws}/seen.txt; then echo NESTED-USERNS-OK >> {ws}/seen.txt; \
         else echo NESTED-USERNS-BLOCKED >> {ws}/seen.txt; fi",
        ws = workspace.display(),
    );
    let outcome = supervise_exec(
        &mut client,
        &cfg,
        &ExecRequest {
            argv: vec!["bash".into(), "-c".into(), cmd],
            needs_network: false,
            ..Default::default()
        },
    )
    .expect("supervise the nested-userns probe");
    eprintln!("nested-userns outcome: {outcome:?}");
    assert_eq!(outcome.shell, mandu_arbiter::protocol::ExecShell::AgentShell);
    assert_eq!(outcome.child_status, Some(0), "the probe itself must run to completion");
    let seen = std::fs::read_to_string(agent_view.join("seen.txt")).unwrap_or_default();
    eprintln!("probe saw: {seen:?}");
    assert!(
        seen.contains("SANDBOX-RAN"),
        "the sandboxed probe never ran (bwrap argv/setup failure?)"
    );
    if seen.contains("unshare: not found") || seen.contains("command not found") {
        eprintln!("SKIP: util-linux unshare unavailable inside the box — cannot drive the nesting attempt.");
    } else {
        assert!(
            seen.contains("NESTED-USERNS-BLOCKED"),
            "minting a nested user namespace inside the AgentShell must fail \
             (--disable-userns on bwrap ≥ 0.8, seccomp CLONE_NEWUSER denial below), got: {seen:?}"
        );
    }

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// Bubblewrap backend, the LANDLOCK leg — proves the interposed
/// `mandu-landlock-apply` actually restricted the box at the LSM layer, not
/// merely that the mounts held. The distinguisher is CREATING a file under the
/// fresh `/dev`: the mounts ALLOW it (a tmpfs /dev, and we are ns-root), but the
/// Landlock plan grants /dev WRITE_FILE only (no MAKE_REG) — so a denied create
/// can ONLY come from Landlock. The carve-outs must still hold: `> /dev/null`
/// (WRITE_FILE on an existing node) and a /tmp scratch write both succeed.
/// SKIPPED unless bwrap + userns + bash + a ≥ 5.13 Landlock kernel.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces + Landlock ≥ 5.13 (see file header)"]
fn bubblewrap_backend_landlock_denies_dev_create() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    if !have_bash() {
        eprintln!("SKIP: bash not found on PATH (the probe needs it).");
        return;
    }
    if !fs_supervisor::landlock::landlock_supported() {
        eprintln!("SKIP: Landlock unavailable on this kernel (< 5.13 or disabled at boot)");
        return;
    }
    let (base, workspace, agent_view) = match bwrap_view_tree("landlock") {
        Some(t) => t,
        None => return,
    };

    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"bash","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let cfg = SupervisorConfig {
        view: ViewConfig {
            agent_view_root: Some(agent_view.to_string_lossy().to_string()),
            workspace: Some(workspace.to_string_lossy().to_string()),
            workspace_writable: false,
        },
        backend: SandboxBackend::Bubblewrap,
        landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
        ..Default::default()
    };

    // Sentinel first (proves the applier chain EXEC'd the probe — a broken
    // interposition exits before running anything), then the three verdicts.
    let cmd = format!(
        "echo SANDBOX-RAN > {ws}/seen.txt && \
         if echo x > /dev/null 2>>{ws}/seen.txt; then echo DEVNULL-OK >> {ws}/seen.txt; fi && \
         if echo x > /tmp/scratch 2>/dev/null; then echo TMP-OK >> {ws}/seen.txt; fi && \
         if touch /dev/mandu-landlock-probe 2>/dev/null; then echo DEV-CREATE-OK >> {ws}/seen.txt; \
         else echo DEV-CREATE-DENIED >> {ws}/seen.txt; fi",
        ws = workspace.display(),
    );
    let outcome = supervise_exec(
        &mut client,
        &cfg,
        &ExecRequest {
            argv: vec!["bash".into(), "-c".into(), cmd],
            needs_network: false,
            ..Default::default()
        },
    )
    .expect("supervise AgentShell exec via bubblewrap + landlock applier");
    eprintln!("Landlock outcome: {outcome:?}");
    assert!(
        outcome.landlock_engaged,
        "the parent probe + pinned applier must engage the LSM leg"
    );
    assert_eq!(outcome.child_status, Some(0), "the probe should have run to completion");

    let seen = std::fs::read_to_string(agent_view.join("seen.txt")).unwrap_or_default();
    eprintln!("probe saw: {seen:?}");
    assert!(seen.contains("SANDBOX-RAN"), "the applier chain must have exec'd the probe");
    assert!(seen.contains("DEVNULL-OK"), "the /dev WRITE_FILE carve-out must keep > /dev/null working");
    assert!(seen.contains("TMP-OK"), "the /tmp scratch must stay writable under Landlock");
    assert!(
        seen.contains("DEV-CREATE-DENIED"),
        "creating a file under /dev is mount-ALLOWED but must be Landlock-DENIED (no MAKE_REG): {seen:?}"
    );

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// InProcess backend, the LANDLOCK leg — the legacy backend historically had NO
/// RO-outside-AgentView enforcement (net-off + bind only); the pre-execve
/// Landlock restrict is what closes that. Proves, on a Landlock kernel: the
/// bind still substitutes the AgentView at the workspace path, a write inside
/// it succeeds, a write OUTSIDE it (the test tree under /var/tmp) is DENIED, and
/// `> /dev/null` still works. SKIPPED without userns or Landlock.
#[test]
#[ignore = "privileged: needs user namespaces + Landlock ≥ 5.13 (see file header)"]
fn inprocess_backend_landlock_enforces_ro_outside_agentview() {
    if !netns_available() {
        eprintln!("SKIP: cannot create namespaces on this host (unprivileged userns off?)");
        return;
    }
    if !have_bash() {
        eprintln!("SKIP: bash not found on PATH (the probe needs it).");
        return;
    }
    if !fs_supervisor::landlock::landlock_supported() {
        eprintln!("SKIP: Landlock unavailable on this kernel (< 5.13 or disabled at boot)");
        return;
    }
    let (base, workspace, agent_view) = match bwrap_view_tree("inproc-ll") {
        Some(t) => t,
        None => return,
    };
    std::fs::write(agent_view.join("note.txt"), b"$MDU:Read[ab12].body\n").unwrap();
    std::fs::write(workspace.join("note.txt"), b"RAW-SECRET\n").unwrap();

    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"bash","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let cfg = SupervisorConfig {
        view: ViewConfig {
            agent_view_root: Some(agent_view.to_string_lossy().to_string()),
            workspace: Some(workspace.to_string_lossy().to_string()),
            workspace_writable: false,
        },
        backend: SandboxBackend::InProcess,
        landlock_apply: None, // in-process restrict — no applier binary involved
        ..Default::default()
    };

    // The escape target lives on the REAL tree next to the workspace — writable
    // today without Landlock (InProcess has no RO overlay), so a denial can only
    // come from the new pre-execve restrict.
    let escape = base.join("escape.txt");
    let cmd = format!(
        "cat {ws}/note.txt > {ws}/seen.txt 2>&1 && \
         echo INSIDE-OK >> {ws}/seen.txt && \
         if echo x > /dev/null 2>/dev/null; then echo DEVNULL-OK >> {ws}/seen.txt; fi && \
         if echo ESCAPED > {esc} 2>/dev/null; then echo ESCAPE-SUCCEEDED >> {ws}/seen.txt; \
         else echo ESCAPE-BLOCKED >> {ws}/seen.txt; fi",
        ws = workspace.display(),
        esc = escape.display(),
    );
    let outcome = supervise_exec(
        &mut client,
        &cfg,
        &ExecRequest {
            argv: vec!["bash".into(), "-c".into(), cmd],
            needs_network: false,
            ..Default::default()
        },
    )
    .expect("supervise AgentShell exec via InProcess + landlock");
    eprintln!("InProcess landlock outcome: {outcome:?}");
    assert!(outcome.landlock_engaged, "the InProcess backend must engage Landlock on this kernel");
    assert!(
        outcome.ro_enforced,
        "with Landlock engaged the InProcess backend now enforces the RO overlay"
    );
    assert_eq!(outcome.child_status, Some(0), "the probe should have run to completion");

    let seen = std::fs::read_to_string(agent_view.join("seen.txt")).unwrap_or_default();
    eprintln!("probe saw: {seen:?}");
    assert!(
        seen.contains("$MDU:"),
        "the command must read the SYMBOLIZED AgentView copy at the workspace path: {seen:?}"
    );
    assert!(seen.contains("INSIDE-OK"), "a write inside the AgentView bind must succeed");
    assert!(seen.contains("DEVNULL-OK"), "the /dev WRITE_FILE carve-out must keep > /dev/null working");
    assert!(
        seen.contains("ESCAPE-BLOCKED"),
        "a write outside the AgentView must now be DENIED by Landlock (the legacy backend's only RO enforcement): {seen:?}"
    );
    assert!(!escape.exists(), "the escape write must not have reached the host filesystem");

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// The WHOLE-AGENT net-confine wrap: drive `mandu-landlock-apply --net-only`
/// end to end. It restricts the process (and its descendants) to CONNECT only the
/// allowed port(s), leaving the filesystem untouched. Proves, live on an ABI-4
/// kernel: a connect to the ALLOWED port succeeds, a connect to a DIFFERENT port
/// (that has a live listener, so the only reason to fail is Landlock, not
/// connection-refused) is denied, and — as a control — the same other-port
/// connect succeeds when NOT wrapped. Landlock is unprivileged, but we enter a
/// private netns with lo up so the loopback listeners are reachable in the
/// unshare harness too. SKIPs below ABI v4.
#[test]
#[ignore = "privileged-ish: needs a loopback (userns) + bash + Landlock net ABI >= 4"]
fn landlock_net_confine_wrap_allows_only_named_ports() {
    if !netns_available() || !have_bash() {
        eprintln!("SKIP: need a userns + bash for the net-confine wrap test");
        return;
    }
    if !fs_supervisor::landlock::landlock_net_supported() {
        eprintln!("SKIP: Landlock TCP-net unavailable (needs kernel >= 6.7 / ABI >= 4)");
        return;
    }
    if !enter_private_netns_with_loopback() {
        eprintln!("SKIP: could not enter a private netns + bring lo up");
        return;
    }

    // Two live listeners: one we ALLOW, one we don't. Both accept, so a failure to
    // reach the disallowed one is a Landlock denial, never connection-refused.
    let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
    let denied = TcpListener::bind("127.0.0.1:0").unwrap();
    let allowed_port = allowed.local_addr().unwrap().port();
    let denied_port = denied.local_addr().unwrap().port();
    allowed.set_nonblocking(true).unwrap();
    denied.set_nonblocking(true).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut acceptors = Vec::new();
    for l in [allowed, denied] {
        let stop_thr = stop.clone();
        acceptors.push(std::thread::spawn(move || {
            while !stop_thr.load(std::sync::atomic::Ordering::Relaxed) {
                match l.accept() {
                    Ok((_s, _a)) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        }));
    }

    let probe_allowed = write_probe(allowed_port);
    let probe_denied = write_probe(denied_port);
    let apply = env!("CARGO_BIN_EXE_mandu-landlock-apply");

    // The probes run as `bash <script>`, not exec'd directly: another test
    // thread's fork() can briefly hold a just-written script open for writing,
    // and exec'ing it then fails with ETXTBSY (bash only reads it).
    // Control: unwrapped, the disallowed port IS reachable (exit 0).
    let control = std::process::Command::new("bash").arg(&probe_denied)
        .status_bounded("the unwrapped control probe").unwrap().code().unwrap();
    assert_eq!(control, 0, "control: the other port must be reachable when unwrapped");

    // Wrapped, allowing ONLY `allowed_port`: the allowed connect succeeds…
    let ok = std::process::Command::new(apply)
        .args(["--net-only", "--allow-tcp-port", &allowed_port.to_string(), "--skip-unsupported", "--", "bash"])
        .arg(&probe_allowed)
        .status_bounded("mandu-landlock-apply --net-only (the allowed port)").unwrap().code().unwrap();
    assert_eq!(ok, 0, "the ALLOWED port must stay reachable under the net-confine");

    // …and the other port's connect is DENIED by Landlock (non-zero probe exit).
    let blocked = std::process::Command::new(apply)
        .args(["--net-only", "--allow-tcp-port", &allowed_port.to_string(), "--skip-unsupported", "--", "bash"])
        .arg(&probe_denied)
        .status_bounded("mandu-landlock-apply --net-only (the denied port)").unwrap().code().unwrap();
    assert_ne!(blocked, 0, "a non-allowed port MUST be denied in-kernel (Landlock), got exit 0");

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for a in acceptors { let _ = join_within(a, wait_limit(), "a probe listener's acceptor thread, after its stop flag"); }
    let _ = std::fs::remove_file(&probe_allowed);
    let _ = std::fs::remove_file(&probe_denied);
}

/// Write a python3 BIND probe: listens on 127.0.0.1:<port> for an instant; exits
/// 0 when bind(2) succeeds, 9 on EACCES/any failure. bash has no bind primitive,
/// hence python (SKIP when absent).
fn write_bind_probe(port: u16) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("mandu-exec-bindprobe-{}-{}.py", std::process::id(), port));
    let script = format!(
        "import socket, sys\ns = socket.socket()\ns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
         try:\n    s.bind(('127.0.0.1', {port}))\n    s.listen(1)\nexcept OSError as e:\n    sys.exit(9)\nsys.exit(0)\n"
    );
    let mut f = std::fs::File::create(&path).expect("create bind probe");
    f.write_all(script.as_bytes()).expect("write bind probe");
    path
}

fn have_python3() -> bool {
    std::process::Command::new("python3").arg("-c").arg("import socket")
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}

/// The BIND allowance of the net-confine wrap (exec-routing.md §7.1; the
/// differential-interactive.md §13.6 defect): a handled Landlock net domain
/// denies bind(2) by default, so a wrapped agent whose TUI is a local server
/// died at `bind = EACCES` under `--net-only`. `--allow-tcp-bind-port <p>` grants
/// BIND|CONNECT on `p`. Proves live on an ABI-4 kernel: (control) an unwrapped
/// bind works; a connect-only wrap DENIES the bind; the bind allowance lets it
/// through; and a bind to a DIFFERENT port stays denied under that allowance.
#[test]
#[ignore = "privileged-ish: needs a loopback (userns) + python3 + Landlock net ABI >= 4"]
fn landlock_net_confine_bind_allowance_permits_only_named_bind_ports() {
    if !netns_available() || !have_python3() {
        eprintln!("SKIP: need a userns + python3 for the bind-allowance test");
        return;
    }
    if !fs_supervisor::landlock::landlock_net_supported() {
        eprintln!("SKIP: Landlock TCP-net unavailable (needs kernel >= 6.7 / ABI >= 4)");
        return;
    }
    if !enter_private_netns_with_loopback() {
        eprintln!("SKIP: could not enter a private netns + bring lo up");
        return;
    }

    // Two free ports on the private loopback (bound then released). Both
    // listeners are held until both ports are known: picked one after the
    // other, the kernel could hand out the same port twice, and the "other"
    // port was then the allowed one (MR !428's pipeline, 2026-10-03).
    let (bind_port, other_port) = {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let b = TcpListener::bind("127.0.0.1:0").unwrap();
        (a.local_addr().unwrap().port(), b.local_addr().unwrap().port())
    };
    let probe_bind = write_bind_probe(bind_port);
    let probe_other = write_bind_probe(other_port);
    let apply = env!("CARGO_BIN_EXE_mandu-landlock-apply");
    let run = |args: &[&str], probe: &std::path::Path| -> i32 {
        std::process::Command::new(apply)
            .args(args)
            .args(["--skip-unsupported", "--", "python3"])
            .arg(probe)
            .status_bounded("mandu-landlock-apply (a bind probe)").unwrap().code().unwrap()
    };

    // Control: unwrapped, the bind succeeds.
    let control = std::process::Command::new("python3").arg(&probe_bind)
        .status_bounded("the unwrapped bind probe").unwrap().code().unwrap();
    assert_eq!(control, 0, "control: bind must succeed unwrapped");

    // Connect-only wrap on that very port: bind is DENIED (the §13.6 defect, pinned).
    let bp = bind_port.to_string();
    let denied = run(&["--net-only", "--allow-tcp-port", &bp], &probe_bind);
    assert_ne!(denied, 0, "a CONNECT-only allowance must NOT permit bind(2)");

    // The bind allowance: the same bind now succeeds…
    let allowed = run(&["--net-only", "--allow-tcp-bind-port", &bp], &probe_bind);
    assert_eq!(allowed, 0, "--allow-tcp-bind-port must permit the bind on that port");

    // …and a bind to a different port is still denied under it.
    let other = run(&["--net-only", "--allow-tcp-bind-port", &bp], &probe_other);
    assert_ne!(other, 0, "a bind allowance is per-port: another port stays denied");

    let _ = std::fs::remove_file(&probe_bind);
    let _ = std::fs::remove_file(&probe_other);
}

// ════════════════════════════════════════════════════════════════════════════
// ATTACH FRONT-END tests (seccomp-unotify execve trap).
//
// These drive a REAL tracee: it installs the execve listener on itself, sends the
// listener fd to the supervisor (this process) over SCM_RIGHTS, then attempts an
// `execve`. The supervisor RECVs the notification, decodes the argv/cwd, decides
// via `plan_exec`, and answers EPERM (deny) or CONTINUE (allow). The tracee, after
// a denied execve, observes the EPERM and ships it back so we can assert the
// program never ran.
// ════════════════════════════════════════════════════════════════════════════

/// A mock arbiter for the front-end: classify an argv carrying a `$MDU:` token
/// as HumanShell that WITHHOLDS the symbol-as-command (→ approval required → the
/// front-end DENIES). A clean argv → HumanShell with no approvals (→ the front-end
/// ALLOWs via CONTINUE where the kernel supports it). We force HumanShell (not the
/// AgentShell default) by always returning HumanShell from classifyExec, so the
/// ALLOW-vs-DENY decision turns on resolveExecArgv's approvals — the exact gate the
/// front-end enforces.
fn frontend_arbiter() -> MockArbiter {
    MockArbiter::start(op_handler(|op, req| match op {
        "classifyExec" => {
            let argv0 = req
                .get("argv")
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // Always HumanShell here: the front-end's ALLOW path requires a non-
            // AgentShell plan (AgentShell needs the sandbox the front-end can't
            // inject → it would DENY). This isolates the symbol-as-command gate.
            Ok(serde_json::json!({
                "shell": "HumanShell", "identifier": argv0, "reason": "front-end test: HumanShell"
            }))
        }
        "resolveExecArgv" => {
            let argv: Vec<String> = req
                .get("argv")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let syms: Vec<&String> = argv.iter().filter(|s| s.contains("$MDU:")).collect();
            if syms.is_empty() {
                Ok(serde_json::json!({
                    "argv": argv, "approvals": [], "reason": "no symbols → run as-is"
                }))
            } else {
                Ok(serde_json::json!({
                    "argv": argv,
                    "approvals": [{
                        "kind": "symbol_as_command",
                        "symbols": syms,
                        "reason": "symbol used as command — withheld"
                    }],
                    "reason": "withheld symbol-as-command"
                }))
            }
        }
        _ => Err(format!("unexpected op {op}")),
    }))
}

/// Distinct tracee exit codes so the supervisor can tell setup-failure from the
/// outcome it wants to observe.
const FE_EXIT_NO_SECCOMP: i32 = 91;
const FE_EXIT_SETUP_FAIL: i32 = 92;

/// Outcome the supervisor observed for one trapped execve plus what the tracee
/// reported about its `execve` result.
struct FrontEndOutcome {
    /// The argv the supervisor decoded from the SUSPENDED tracee (asserted so the
    /// test proves the process_vm_readv argv-array decode, not a coincidence).
    decoded_argv: Vec<String>,
    /// What `handle_exec_notif` decided + enacted.
    action: FrontEndAction,
    /// The errno the tracee's `execve` returned (it only returns on FAILURE; a
    /// successful exec replaces the image and never reports here). `Some(EPERM)` is
    /// the DENY proof. `None` means the tracee's execve did not fail (e.g. CONTINUE
    /// let it through, or it never reached the report).
    tracee_execve_errno: Option<i32>,
    /// The tracee's exit code (its own, after a failed execve), or None if signalled
    /// / replaced by a successful exec.
    tracee_exit: Option<i32>,
}

/// Drive ONE trapped execve through the front-end. The tracee execs `program` with
/// `argv` (a real, existing `program` path so a CONTINUE would actually succeed).
/// `cwd` is chdir'd to before installing the filter (so the chdir isn't trapped and
/// `/proc/<pid>/cwd` is stable for the decode). Returns `None` to SKIP when seccomp
/// NEW_LISTENER is denied (no CAP_SYS_ADMIN-in-userns).
fn drive_one_execve(
    client: &mut ArbiterClient,
    program: &str,
    argv: &[String],
    cwd: Option<&str>,
) -> Option<FrontEndOutcome> {
    let (sup_sock, child_sock) = socketpair();
    // Pipe to ship the tracee's execve errno (4 bytes, little-endian) back up.
    let (rd, wr) = pipe();

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed: {}", last_err());

    if child == 0 {
        // ── TRACEE ──────────────────────────────────────────────────────────
        unsafe {
            libc::close(sup_sock);
            libc::close(rd);
        }
        // PRE-FILTER chdir so the cwd read by the supervisor is stable + the chdir
        // itself isn't trapped.
        if let Some(d) = cwd {
            let dc = CString::new(d).unwrap();
            if unsafe { libc::chdir(dc.as_ptr()) } != 0 {
                unsafe { libc::_exit(FE_EXIT_SETUP_FAIL) };
            }
        }
        // Install no_new_privs + the execve listener on ourselves, hand it up.
        let listener = match install_execve_filter_self() {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(FE_EXIT_NO_SECCOMP) },
        };
        if send_fd(child_sock, listener).is_err() {
            unsafe { libc::_exit(FE_EXIT_SETUP_FAIL) };
        }

        // Build the argv (NULL-terminated) + a minimal envp.
        let prog_c = CString::new(program).unwrap();
        let argv_c: Vec<CString> = argv.iter().map(|a| CString::new(a.as_str()).unwrap()).collect();
        let mut argv_p: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
        argv_p.push(std::ptr::null());
        let envp_p: [*const libc::c_char; 1] = [std::ptr::null()];

        // THE TRAPPED EXECVE. If the supervisor denies it (EPERM), execve returns -1
        // and we fall through to report errno; if it CONTINUEs, the image is replaced
        // (this code never runs again). We exec a real program so a CONTINUE genuinely
        // succeeds (proving the allow path on ≥ 5.5).
        let rc = unsafe { libc::execve(prog_c.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr()) };
        // Only reached on FAILURE (denied). Ship the errno up the pipe, then exit.
        let _ = rc;
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let bytes = errno.to_le_bytes();
        unsafe {
            libc::write(wr, bytes.as_ptr() as *const libc::c_void, bytes.len());
            libc::close(wr);
            libc::_exit(0);
        }
    }

    // ── SUPERVISOR (parent) ───────────────────────────────────────────────────
    unsafe {
        libc::close(child_sock);
        libc::close(wr);
    }
    readable_within(sup_sock, child, wait_limit(), "waiting for the tracee to hand over its execve listener");
    let listener = match recv_fd(sup_sock) {
        Ok(fd) => fd,
        Err(_) => {
            let code = reap(child);
            unsafe {
                libc::close(sup_sock);
                libc::close(rd);
            }
            if code == Some(FE_EXIT_NO_SECCOMP) {
                eprintln!(
                    "SKIP: seccomp NEW_LISTENER install was denied (need CAP_SYS_ADMIN-in-userns + \
                     no_new_privs). Re-run under: unshare --user --map-root-user ..."
                );
                return None;
            }
            panic!("tracee failed to send listener fd (exit {code:?})");
        }
    };

    // RECV the trapped execve. Decode the argv the SAME way handle_exec_notif does,
    // BEFORE answering, so the test can assert what the supervisor read.
    readable_within(listener, child, wait_limit(), "waiting for the tracee's trapped execve (its seccomp notification)");
    let notif = notif_recv(listener).expect("NOTIF_RECV failed");
    let decoded_argv = kernel::decode_argv_for_test(&notif);

    // Decide + enact (EPERM deny / CONTINUE allow) via the real front-end handler.
    let action = handle_exec_notif(listener, client, &notif).expect("handle_exec_notif");

    // Read the tracee's reported execve errno (if it failed). A successful CONTINUE
    // replaces the image, so the pipe write end held by the tracee is closed by the
    // exec → read returns 0 (EOF) → None.
    let mut buf = [0u8; 4];
    let tracee_execve_errno = {
        readable_within(rd, child, wait_limit(), "waiting for the tracee's execve result (its errno, or EOF at the exec)");
        let n = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n == 4 {
            Some(i32::from_le_bytes(buf))
        } else {
            None
        }
    };
    unsafe {
        libc::close(rd);
        libc::close(listener);
        libc::close(sup_sock);
    }
    let tracee_exit = reap(child);

    Some(FrontEndOutcome {
        decoded_argv,
        action,
        tracee_execve_errno,
        tracee_exit,
    })
}

/// DENY (kernel ≥ 5.0): a tracee `execve`s a SYMBOL-AS-COMMAND argv; the front-end
/// decodes it, `plan_exec` (HumanShell, symbol withheld) requires approval, and the
/// supervisor answers EPERM → the tracee's execve returns EPERM and the program
/// NEVER ran. This is the core front-end guarantee and needs only kernel ≥ 5.0.
#[test]
#[ignore = "requires CAP_SYS_ADMIN-in-userns + SECCOMP_USER_NOTIF; --features kernel -- --ignored"]
fn frontend_denies_symbol_as_command_execve() {
    ensure_proc_matches_pidns();
    if !have_bash() {
        eprintln!("SKIP: /bin/sh not found — the DENY test execs a real program path.");
        return;
    }
    let arbiter = frontend_arbiter();
    let mut client = ArbiterClient::new(&arbiter.socket_path);

    // Exec a REAL program (/bin/sh) but with a symbol IN COMMAND POSITION in the
    // argv. The arbiter withholds it (symbol-as-command) → the front-end DENIES, so
    // /bin/sh must NEVER run. argv[0] is the real program; argv[2] is the symbol.
    let program = "/bin/sh";
    let argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "$MDU:Read[ab12].body".to_string(),
    ];
    let outcome = match drive_one_execve(&mut client, program, &argv, None) {
        Some(o) => o,
        None => {
            drop(client);
            drop(arbiter);
            return; // SKIP (seccomp denied; message already printed)
        }
    };

    // The supervisor DECODED the right program + args out of the suspended tracee.
    eprintln!("front-end decoded argv: {:?}", outcome.decoded_argv);
    assert_eq!(
        outcome.decoded_argv, argv,
        "front-end must decode the exact argv the tracee passed (program + args) via process_vm_readv"
    );

    // The DECISION + enactment was DENY (EPERM).
    match &outcome.action {
        FrontEndAction::Denied { reason } => {
            eprintln!("front-end DENIED (as required): {reason}");
        }
        other => panic!("a symbol-as-command execve MUST be denied; got {other:?}"),
    }

    // The decisive proof: the tracee's execve returned EPERM and the program never
    // ran (the tracee continued its own code and reported the errno + exited 0).
    assert_eq!(
        outcome.tracee_execve_errno,
        Some(libc::EPERM),
        "the denied execve must return EPERM to the tracee (program did NOT run)"
    );
    assert_eq!(
        outcome.tracee_exit,
        Some(0),
        "the tracee survived the failed execve and exited normally — /bin/sh never replaced it"
    );
    eprintln!("DENY PASS (kernel ≥ 5.0): trapped execve(/bin/sh -c $SYM), decoded argv, EPERM → program blocked.");

    drop(client);
    drop(arbiter);
}

/// ALLOW via CONTINUE (kernel ≥ 5.5; self-SKIPs below that — runs live on this
/// 6.8 host): a benign exec the
/// arbiter classifies HumanShell-with-no-approval is answered with CONTINUE so the
/// REAL execve proceeds. On < 5.5 there is no CONTINUE, so a seccomp front-end
/// cannot cleanly allow an execve through — the front-end fails closed (EPERM) and
/// we SKIP the allow assertion (verified live wherever CONTINUE exists).
#[test]
#[ignore = "requires kernel ≥ 5.5 (CONTINUE) + CAP_SYS_ADMIN-in-userns; --features kernel -- --ignored"]
fn frontend_allows_benign_execve_via_continue() {
    ensure_proc_matches_pidns();
    if !continue_supported() {
        let (maj, min) = kernel::kernel_version();
        eprintln!(
            "SKIP: the ALLOW-through path needs SECCOMP_USER_NOTIF_FLAG_CONTINUE (kernel ≥ 5.5); \
             this host is {maj}.{min}. A seccomp front-end cannot inject namespaces and cannot \
             allow-through an execve without CONTINUE, so the allow path is deferred to a ≥ 5.5 VM. \
             The DENY guarantee is proven on this host by frontend_denies_symbol_as_command_execve."
        );
        return;
    }
    if !have_bash() {
        eprintln!("SKIP: /bin/true / /bin/sh not found for the benign exec.");
        return;
    }
    let arbiter = frontend_arbiter();
    let mut client = ArbiterClient::new(&arbiter.socket_path);

    // A benign exec: a real program, NO symbols → HumanShell with no approvals →
    // the front-end ALLOWs via CONTINUE → the real execve proceeds. We exec
    // `/bin/true` which exits 0 immediately, so a successful CONTINUE replaces the
    // tracee image and the tracee exits 0 WITHOUT reporting an execve errno.
    let program = if std::path::Path::new("/bin/true").exists() {
        "/bin/true"
    } else {
        "/usr/bin/true"
    };
    let argv = vec![program.to_string()];
    let outcome = match drive_one_execve(&mut client, program, &argv, None) {
        Some(o) => o,
        None => {
            drop(client);
            drop(arbiter);
            return; // SKIP
        }
    };

    eprintln!("front-end decoded argv: {:?}", outcome.decoded_argv);
    assert_eq!(outcome.decoded_argv, argv, "front-end must decode the benign argv");

    match &outcome.action {
        FrontEndAction::Continued => {
            // The execve was allowed through: no errno was reported (the image was
            // replaced by `true`, which exited 0).
            assert_eq!(
                outcome.tracee_execve_errno, None,
                "an allowed execve must proceed — the tracee should NOT report an execve errno"
            );
            assert_eq!(
                outcome.tracee_exit,
                Some(0),
                "the allowed-through program (/bin/true) ran and exited 0"
            );
            eprintln!("ALLOW PASS (kernel ≥ 5.5): trapped execve answered CONTINUE → real program ran.");
        }
        other => panic!("a benign HumanShell exec must be allowed via CONTINUE on ≥ 5.5; got {other:?}"),
    }

    drop(client);
    drop(arbiter);
}

// ── Task 3: REAL spawn-lineage edge from the fork loop ──────────────────────

/// Assert that `supervise_exec` records a `processLineage` edge with REAL,
/// shared-format (`${pid}-${starttime}`) keys: one for the child and one for the
/// supervisor itself (the parent). Requires a user namespace (for fork+exec) and
/// a mock arbiter that handles `processLineage`. The rest of the arbiter ops drive
/// a no-approval HumanShell plan so the exec actually runs (we exec `true`).
#[test]
#[ignore = "requires root or an unprivileged userns (fork+exec) + a arbiter; --features kernel -- --ignored"]
fn supervise_exec_records_real_lineage_edge() {
    use std::sync::{Arc, Mutex};

    // Record the lineage keys the supervisor emits.
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();

    let arbiter = MockArbiter::start(op_handler(move |op, req| match op {
        // classifyExec: return HumanShell so `true` actually runs.
        "classifyExec" => Ok(serde_json::json!({
            "shell": "HumanShell",
            "identifier": "true",
            "reason": "test — needs-network drives HumanShell"
        })),
        // resolveExecArgv: no symbols → pass argv through with empty approvals.
        "resolveExecArgv" => {
            let argv: Vec<serde_json::Value> = req
                .get("argv")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();
            Ok(serde_json::json!({
                "argv": argv,
                "approvals": [],
                "reason": "no symbols"
            }))
        }
        "processLineage" => {
            let c = req
                .get("childKey")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let p = req
                .get("parentKey")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            seen2.lock().unwrap().push((c, p));
            Ok(serde_json::json!({ "ok": true }))
        }
        other => Err(format!("unexpected op {other}")),
    }));

    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let cfg = SupervisorConfig {
        view: ViewConfig::default(),
        ..Default::default()
    };
    let req = ExecRequest {
        argv: vec!["true".into()],
        needs_network: true, // → HumanShell so `true` runs
        ..Default::default()
    };

    let out = supervise_exec(&mut client, &cfg, &req).expect("supervise_exec for `true`");
    assert_eq!(out.child_status, Some(0), "`true` must exit 0");

    let edges = seen.lock().unwrap();
    assert_eq!(edges.len(), 1, "exactly one processLineage edge must be emitted");
    let (child, parent) = &edges[0];
    assert!(
        regex_lite_is_pid_dash(child),
        "child key must be `${{pid}}-${{starttime}}`: got {child:?}"
    );
    assert!(
        regex_lite_is_pid_dash(parent),
        "parent key must be `${{pid}}-${{starttime}}`: got {parent:?}"
    );
    assert!(
        parent.starts_with(&format!("{}-", std::process::id())),
        "parent key must start with the supervisor's own pid ({}); got {parent:?}",
        std::process::id()
    );

    drop(client);
    drop(arbiter);
}

// tiny inline check (no regex dep): `\d+-\d+`
#[cfg(feature = "kernel")]
fn regex_lite_is_pid_dash(s: &str) -> bool {
    match s.split_once('-') {
        Some((a, b)) => {
            !a.is_empty()
                && !b.is_empty()
                && a.bytes().all(|c| c.is_ascii_digit())
                && b.bytes().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

// ── front-end test helpers (test-local; mirror fs-supervisor's pattern) ─────

fn last_err() -> String {
    std::io::Error::last_os_error().to_string()
}

/// Make `/proc/<pid>` agree with the pid namespace `seccomp_notif.pid` is reported
/// in. The run recipe uses `unshare --pid --fork`, putting us in a NEW pid ns while
/// the HOST `/proc` stays mounted — so a namespace-local `notif.pid` would index the
/// wrong host process and the supervisor's `/proc/<pid>/cwd` read would be bogus.
/// Remounting `/proc` (we hold CAP_SYS_ADMIN in the new mount+user ns) makes procfs
/// reflect the new pid ns. Best-effort; harmless if not needed.
fn ensure_proc_matches_pidns() {
    let src = b"proc\0";
    let target = b"/proc\0";
    let fstype = b"proc\0";
    // SAFETY: mount(2) of a fresh procfs over /proc; CAP_SYS_ADMIN held in the userns.
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

fn socketpair() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair: {}", last_err());
    (fds[0], fds[1])
}

fn pipe() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe: {}", last_err());
    (fds[0], fds[1])
}

/// Reap a child; return its exit code (None if signalled).
fn reap(pid: i32) -> Option<i32> {
    if in_test_process() {
        return reap_within(pid, wait_limit(), "waiting for the tracee").code();
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    }
}

/// Send a single fd over a unix socket via SCM_RIGHTS.
fn send_fd(sock: RawFd, fd: RawFd) -> std::io::Result<()> {
    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; 32];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
        msg.msg_controllen = (*cmsg).cmsg_len as _;
        let n = libc::sendmsg(sock, &msg, 0);
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receive a single fd over a unix socket via SCM_RIGHTS.
fn recv_fd(sock: RawFd) -> std::io::Result<RawFd> {
    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; 32];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    unsafe {
        let n = libc::recvmsg(sock, &mut msg, 0);
        if n <= 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("recvmsg returned {n}: {}", last_err()),
            ));
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no SCM_RIGHTS control message",
            ));
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut RawFd as *mut u8,
            std::mem::size_of::<RawFd>(),
        );
        Ok(fd)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CLEAN BOX (exec-routing.md §8.4 rung 2) — the enforce-clean attempt +
// verdict reporter, live. All four tests serialize on STDIN_LOCK because the
// stdin gate reads the PROCESS-global fd 0 (tests in this binary share it).
// ════════════════════════════════════════════════════════════════════════════

static STDIN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Point the process's fd 0 at /dev/null (the stdin shape the clean gate
/// accepts). Returns false (→ SKIP) if /dev/null can't be opened.
fn stdin_to_devnull() -> bool {
    let dn = CString::new("/dev/null").unwrap();
    let fd = unsafe { libc::open(dn.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return false;
    }
    let ok = unsafe { libc::dup2(fd, 0) } == 0;
    unsafe { libc::close(fd) };
    ok
}

/// A mock arbiter for the clean tests: AgentShell classify, a recorded exec
/// decision carrying `call_id`, and a clean-verdict sink that echoes the §5
/// resolution; every received report is captured for assertions.
fn clean_arbiter(
    call_id: &'static str,
) -> (MockArbiter, std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>) {
    let reports = std::sync::Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
    let sink = reports.clone();
    let arbiter = MockArbiter::start(op_handler(move |op, req| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":null,"reason":"default AgentShell"
        })),
        "processLineage" => Ok(serde_json::json!({ "ok": true })),
        "execDecisionFor" => Ok(serde_json::json!({
            "decision": {
                "block": false, "shell": "AgentShell", "evasion": [],
                "reason": "recorded", "callId": call_id, "seq": 1
            },
            "signature": "test"
        })),
        "reportExecCleanVerdict" => {
            let report = req.get("report").cloned().unwrap_or(serde_json::Value::Null);
            sink.lock().unwrap().push(report.clone());
            // Echo a CLEAN resolution (the real store's gate chain is covered
            // by the arbiter's own unit tests; here we prove the reporter leg).
            Ok(serde_json::json!({ "verdict": {
                "callId": report.get("callId"),
                "clean": true,
                "reason": "clean (boxed AgentShell, lineage untainted)",
                "outputSha256": report.get("outputSha256"),
                "seq": 1
            }}))
        }
        other => Err(format!("unexpected op {other}")),
    }));
    (arbiter, reports)
}

/// A throwaway workspace/AgentView pair outside /tmp (the box tmpfs-masks /tmp).
fn clean_view_tree(tag: &str) -> Option<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> {
    let base = outside_tmp_dir(&format!("clean-{tag}"))?;
    let ws = base.join("workspace");
    let av = base.join("agentview");
    std::fs::create_dir_all(&ws).ok()?;
    std::fs::create_dir_all(&av).ok()?;
    Some((base, ws, av))
}

fn clean_cfg(ws: &std::path::Path, av: &std::path::Path) -> SupervisorConfig {
    SupervisorConfig {
        view: ViewConfig {
            agent_view_root: Some(av.to_string_lossy().to_string()),
            workspace: Some(ws.to_string_lossy().to_string()),
            workspace_writable: false,
        },
        backend: SandboxBackend::Bubblewrap,
        landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
        clean_box: true,
        clean_via: None,
        clean_only: false,
        ..Default::default()
    }
}

/// The E47 leaf shape, end to end: an influence-free command (`sha256sum` over
/// a /dev/null stdin — reads nothing but system paths) COMPLETES in the clean
/// box; the supervisor forwards the exact stdout, correlates the callId off the
/// recorded decision, and reports a verdict whose hash is sha256 of those
/// bytes. This is the producer leg E47's live green rides on.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces + Landlock ≥ 5.13 (see file header)"]
fn clean_box_completes_and_reports_the_hash_bound_verdict() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    let _g = STDIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !stdin_to_devnull() {
        eprintln!("SKIP: cannot point stdin at /dev/null");
        return;
    }
    let Some((base, ws, av)) = clean_view_tree("ok") else {
        eprintln!("SKIP: no test dir outside /tmp");
        return;
    };

    let (arbiter, reports) = clean_arbiter("toolu_clean_e2e");
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let outcome = supervise_exec(
        &mut client,
        &clean_cfg(&ws, &av),
        &ExecRequest { argv: vec!["sha256sum".into()], ..Default::default() },
    )
    .expect("clean-box supervise");
    eprintln!("clean outcome: {outcome:?}");

    assert_eq!(outcome.child_status, Some(0));
    let clean = outcome.clean.expect("the influence-free command must complete IN the clean box");
    // sha256sum over empty stdin prints the canonical empty-input digest line;
    // the verdict hash must be sha256 of EXACTLY those forwarded bytes.
    let expected_stdout = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -\n";
    assert_eq!(clean.output_sha256, exec_supervisor::clean::sha256_hex(expected_stdout));
    assert_eq!(clean.call_id.as_deref(), Some("toolu_clean_e2e"));
    assert!(clean.verdict_clean, "the mock resolved the report clean");

    // The report the arbiter received: every §5 gate input present.
    let got = reports.lock().unwrap();
    assert_eq!(got.len(), 1, "exactly one verdict report");
    let r = &got[0];
    assert_eq!(r.get("callId").and_then(|v| v.as_str()), Some("toolu_clean_e2e"));
    assert_eq!(r.get("clean").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(r.get("boxed").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(r.get("shell").and_then(|v| v.as_str()), Some("AgentShell"));
    assert!(
        r.get("procKey").and_then(|v| v.as_str()).is_some(),
        "the invocation's proc key rides the report for the arbiter's taint re-check"
    );
    assert_eq!(
        r.get("outputSha256").and_then(|v| v.as_str()),
        Some(clean.output_sha256.as_str())
    );

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// The clean verdict survives other threads' spawns (pipeline #11899,
/// 2026-10-18): the clean attempt's capture pipes are close-on-exec, so a
/// process another thread of the supervisor spawns while the pipes exist
/// does not keep their write ends past its exec. Before, it kept them for as
/// long as it ran: the drain then saw the pipes open `DRAIN_GRACE` past the
/// box's exit, voided the attempt and fell back (exec-routing.md §4.4). Here
/// two threads keep spawning a `sleep` that outlives the grace while the
/// influence-free command runs, several rounds over; every round must still
/// complete IN the clean box and report its hash-bound verdict.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces + Landlock ≥ 5.13 (see file header)"]
fn clean_box_verdict_survives_concurrent_spawns() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    let _g = STDIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !stdin_to_devnull() {
        eprintln!("SKIP: cannot point stdin at /dev/null");
        return;
    }
    let Some((base, ws, av)) = clean_view_tree("spawns") else {
        eprintln!("SKIP: no test dir outside /tmp");
        return;
    };
    let expected_stdout = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -\n";
    let (arbiter, reports) = clean_arbiter("toolu_clean_spawns");
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    const ROUNDS: usize = 6;
    let mut voided = 0usize;
    for round in 0..ROUNDS {
        let stop = Arc::new(AtomicBool::new(false));
        let storm: Vec<_> = (0..2)
            .map(|_| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut kids = Vec::new();
                    // Bounded: at most 400 children a thread a round.
                    while !stop.load(Ordering::Relaxed) && kids.len() < 400 {
                        // Outlives DRAIN_GRACE (2 s) by a margin.
                        if let Ok(c) = std::process::Command::new("sleep")
                            .arg("4")
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .spawn()
                        {
                            kids.push(c);
                        }
                        std::thread::sleep(std::time::Duration::from_micros(200));
                    }
                    kids
                })
            })
            .collect();
        let outcome = supervise_exec(
            &mut client,
            &clean_cfg(&ws, &av),
            &ExecRequest { argv: vec!["sha256sum".into()], ..Default::default() },
        );
        stop.store(true, Ordering::Relaxed);
        let mut spawned = 0usize;
        for t in storm {
            for mut k in t.join().unwrap() {
                spawned += 1;
                let _ = k.kill();
                let _ = k.wait();
            }
        }
        let outcome = outcome.expect("clean-box supervise");
        eprintln!("round {round}: {spawned} concurrent spawns; clean = {:?}", outcome.clean);
        assert_eq!(outcome.child_status, Some(0));
        match outcome.clean {
            Some(clean) => {
                assert_eq!(clean.output_sha256, exec_supervisor::clean::sha256_hex(expected_stdout));
                assert_eq!(clean.call_id.as_deref(), Some("toolu_clean_spawns"));
                assert!(clean.verdict_clean, "the mock resolved the report clean");
            }
            None => voided += 1,
        }
    }
    assert_eq!(
        voided, 0,
        "{voided} of {ROUNDS} influence-free runs fell back out of the clean box while \
         other threads spawned: a spawned process kept the capture pipes open"
    );
    assert_eq!(reports.lock().unwrap().len(), ROUNDS, "one verdict report a round");

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// The utility cliff + graceful fallback: a command that READS an unverified
/// workspace file fails inside the clean box (AgentView is write-only there)
/// and is rerun in the ordinary box — same command, same view, output
/// UNTRUSTED (no verdict), today's behavior. The caller sees ONE clean result.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces + Landlock ≥ 5.13 (see file header)"]
fn clean_box_denies_workspace_read_and_falls_back_to_the_ordinary_box() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    let _g = STDIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !stdin_to_devnull() {
        eprintln!("SKIP: cannot point stdin at /dev/null");
        return;
    }
    let Some((base, ws, av)) = clean_view_tree("fb") else {
        eprintln!("SKIP: no test dir outside /tmp");
        return;
    };
    std::fs::write(ws.join("note.txt"), b"RAW\n").unwrap();
    std::fs::write(av.join("note.txt"), b"$MDU:Read[ab12].body\n").unwrap();

    let (arbiter, reports) = clean_arbiter("toolu_clean_fb");
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let note = ws.join("note.txt").to_string_lossy().to_string();
    let outcome = supervise_exec(
        &mut client,
        &clean_cfg(&ws, &av),
        &ExecRequest { argv: vec!["cat".into(), note], ..Default::default() },
    )
    .expect("fallback supervise");
    eprintln!("fallback outcome: {outcome:?}");

    // The ordinary rerun succeeded (cat read the AgentView bind) — but the run
    // did NOT qualify as clean and nothing was reported.
    assert_eq!(outcome.child_status, Some(0), "the ordinary-box fallback must succeed");
    assert!(outcome.clean.is_none(), "a workspace read can never yield a clean outcome");
    assert!(reports.lock().unwrap().is_empty(), "no verdict report for a failed attempt");

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// Trusted-read grants (the §3 TOCTOU closure, live): a file OUTSIDE the
/// system roots becomes readable in the clean box iff its CURRENT bytes hash
/// to the granted value. Same command, two grants: matching hash → clean
/// completion + verdict; mismatched hash → the read is denied in-box and the
/// run falls back (no verdict).
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces + Landlock ≥ 5.13 (see file header)"]
fn clean_box_trusted_read_grant_admits_only_hash_matching_content() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    let _g = STDIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !stdin_to_devnull() {
        eprintln!("SKIP: cannot point stdin at /dev/null");
        return;
    }
    let Some((base, ws, av)) = clean_view_tree("grant") else {
        eprintln!("SKIP: no test dir outside /tmp");
        return;
    };
    // The granted file lives OUTSIDE the view pair and outside /tmp, so its
    // in-box bytes are the host bytes (the RO root), matching what
    // verify_trusted_reads hashes parent-side.
    let data = base.join("data.txt");
    std::fs::write(&data, b"granted bytes\n").unwrap();
    let data_s = data.to_string_lossy().to_string();

    for (tag, grant_hash, expect_clean) in [
        ("match", exec_supervisor::clean::sha256_hex(b"granted bytes\n"), true),
        ("mismatch", exec_supervisor::clean::sha256_hex(b"different bytes\n"), false),
    ] {
        let (arbiter, reports) = clean_arbiter("toolu_clean_grant");
        let mut client = ArbiterClient::new(&arbiter.socket_path);
        let mut cfg = clean_cfg(&ws, &av);
        cfg.trusted_reads = vec![exec_supervisor::clean::TrustedRead {
            path: data_s.clone(),
            sha256: grant_hash,
        }];
        let outcome = supervise_exec(
            &mut client,
            &cfg,
            &ExecRequest { argv: vec!["sha256sum".into(), data_s.clone()], ..Default::default() },
        )
        .expect("grant supervise");
        eprintln!("grant[{tag}] outcome: {outcome:?}");
        assert_eq!(outcome.child_status, Some(0), "[{tag}] the run (or its fallback) succeeds");
        assert_eq!(
            outcome.clean.is_some(),
            expect_clean,
            "[{tag}] clean iff the grant's hash matches the on-disk bytes"
        );
        assert_eq!(reports.lock().unwrap().len(), usize::from(expect_clean), "[{tag}] report count");
        drop(client);
        drop(arbiter);
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// The stdin gate: a PIPE stdin can carry bytes from an upstream process the
/// box never vetted (`cat evil.md | tool`), so the clean attempt must be
/// SKIPPED entirely — even for a command that would complete cleanly — and the
/// ordinary box runs. No correlation lookup, no report.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces + Landlock ≥ 5.13 (see file header)"]
fn clean_box_is_skipped_when_stdin_is_a_pipe() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    let _g = STDIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Point fd 0 at the READ end of a pipe whose write end we hold open.
    let mut fds = [0 as RawFd; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { libc::dup2(fds[0], 0) }, 0);
    unsafe { libc::close(fds[0]) };
    let Some((base, ws, av)) = clean_view_tree("stdin") else {
        eprintln!("SKIP: no test dir outside /tmp");
        return;
    };

    let (arbiter, reports) = clean_arbiter("toolu_clean_stdin");
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    // `echo` ignores stdin, so it WOULD complete cleanly — only the gate keeps
    // it out of the clean box.
    let outcome = supervise_exec(
        &mut client,
        &clean_cfg(&ws, &av),
        &ExecRequest { argv: vec!["echo".into(), "hi".into()], ..Default::default() },
    )
    .expect("pipe-stdin supervise");
    eprintln!("pipe-stdin outcome: {outcome:?}");
    assert_eq!(outcome.child_status, Some(0));
    assert!(outcome.clean.is_none(), "a piped stdin must disqualify the clean attempt");
    assert!(reports.lock().unwrap().is_empty(), "no lookup/report when the gate skips");

    // Restore a benign stdin for any later test and release the pipe.
    unsafe { libc::close(fds[1]) };
    let _ = stdin_to_devnull();
    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// WSL2's Windows interop door (mandu_arbiter::wsl, exec-routing.md §4.1),
/// proved on a plain Linux kernel by PINNING the WSL signals: a Unix socket
/// named by `$WSL_INTEROP` stands in for `/run/WSL/<pid>_interop`, the thing
/// the `/init` interop client must reach to start a Windows program outside
/// every Linux box. A differential, so the proof is not vacuous:
///   - the SAME box with the signals pinned OFF reaches the socket (a Unix
///     socket on the read-only base IS connectable: the door is real);
///   - with WSL pinned ON the socket is masked (`/dev/null` bound over it),
///     `WSL_INTEROP` is unset inside, and the connect fails;
///   - in both, `socket(AF_VSOCK)` fails with EAFNOSUPPORT (the seccomp arg
///     check), checked against the host where vsock opens (else noted, not
///     asserted: a host without the vsock module cannot tell the two apart).
/// SKIPPED unless bwrap + a userns + python3 are available.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces + python3 (see file header)"]
fn bubblewrap_backend_hides_the_wsl_interop_door() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    if !have_python3() {
        eprintln!("SKIP: python3 not found on PATH (the socket probe needs it).");
        return;
    }
    let (base, workspace, agent_view) = match bwrap_view_tree("wsl") {
        Some(t) => t,
        None => return,
    };
    // The stand-in interop socket, OUTSIDE /tmp (the box's /tmp is a fresh
    // tmpfs, which would hide it for the wrong reason).
    let sock_dir = base.join("run-wsl");
    std::fs::create_dir_all(&sock_dir).unwrap();
    let sock = sock_dir.join("1_interop");
    let listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind the stand-in interop socket");
    listener.set_nonblocking(true).unwrap();
    let sock_s = sock.to_string_lossy().to_string();

    let probe = base.join("probe.py");
    std::fs::write(
        &probe,
        r#"import os, socket, sys
out = open(sys.argv[1], "w")
out.write("RAN\n")
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sys.argv[2])
    out.write("INTEROP-REACHED\n")
except OSError as e:
    out.write("INTEROP-BLOCKED %d\n" % e.errno)
out.write("ENV=%s\n" % os.environ.get("WSL_INTEROP", "<unset>"))
try:
    socket.socket(40, socket.SOCK_STREAM)
    out.write("VSOCK-OPENED\n")
except OSError as e:
    out.write("VSOCK-BLOCKED %d\n" % e.errno)
"#,
    )
    .unwrap();

    // The parent's env carries a pointer, as a WSL session's does, so the box
    // must unset it. Its value names a path that never exists: the process
    // env is shared with concurrently running tests, whose boxes probe it and
    // would otherwise mask this stand-in socket, then fail at the mount once
    // this test deletes it. (The WSL legs get the stand-in through the pinned
    // signals below.) Restored below.
    std::env::set_var("WSL_INTEROP", "/nonexistent-mandu-wsl-test/1_interop");

    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"python3","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let run = |client: &mut ArbiterClient, wsl: mandu_arbiter::wsl::WslSignals, tag: &str| -> String {
        let cfg = SupervisorConfig {
            view: ViewConfig {
                agent_view_root: Some(agent_view.to_string_lossy().to_string()),
                workspace: Some(workspace.to_string_lossy().to_string()),
                workspace_writable: false,
            },
            backend: SandboxBackend::Bubblewrap,
            landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
            wsl: Some(wsl),
            // The control shows the door on the RO base: without the socket
            // allow-list too, which alone would refuse it (§4.2).
            socket_allowlist: (tag == "off").then_some(false),
            ..Default::default()
        };
        let seen = workspace.join(format!("{tag}.txt"));
        let outcome = supervise_exec(
            client,
            &cfg,
            &ExecRequest {
                argv: vec![
                    "python3".into(),
                    probe.to_string_lossy().to_string(),
                    seen.to_string_lossy().to_string(),
                    sock_s.clone(),
                ],
                needs_network: false,
                ..Default::default()
            },
        )
        .expect("supervise the interop probe");
        assert_eq!(outcome.shell, mandu_arbiter::protocol::ExecShell::AgentShell);
        assert_eq!(outcome.child_status, Some(0), "[{tag}] the probe must run to completion: {outcome:?}");
        std::fs::read_to_string(agent_view.join(format!("{tag}.txt"))).unwrap_or_default()
    };

    // Control: not WSL. The door is open (so the WSL leg below is not vacuous).
    let off = run(&mut client, mandu_arbiter::wsl::WslSignals::default(), "off");
    eprintln!("not-WSL probe saw: {off:?}");
    // WSL: the socket named by $WSL_INTEROP, plus a WSL2 kernel release.
    let on = run(
        &mut client,
        mandu_arbiter::wsl::WslSignals {
            osrelease: Some("6.6.36.6-microsoft-standard-WSL2".into()),
            interop_env: Some(sock_s.clone()),
            binfmt_interop: true,
        },
        "on",
    );
    eprintln!("WSL probe saw: {on:?}");
    std::env::remove_var("WSL_INTEROP");

    assert!(off.contains("RAN") && on.contains("RAN"), "the probe never ran (bwrap setup?)");
    assert!(off.contains("INTEROP-REACHED"), "control: a socket on the RO base must be reachable, got {off:?}");
    assert!(on.contains("INTEROP-BLOCKED"), "WSL: the interop socket must be unreachable in the box, got {on:?}");
    for (tag, seen) in [("off", &off), ("on", &on)] {
        assert!(seen.contains("ENV=<unset>"), "[{tag}] WSL_INTEROP must be unset inside the box, got {seen:?}");
        assert!(seen.contains("VSOCK-BLOCKED 97"), "[{tag}] socket(AF_VSOCK) must fail EAFNOSUPPORT, got {seen:?}");
    }
    let host_vsock = std::process::Command::new("python3")
        .args(["-c", "import socket; socket.socket(40, socket.SOCK_STREAM)"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if host_vsock {
        eprintln!("vsock differential: the host opens AF_VSOCK, the box does not");
    } else {
        eprintln!("NOTE: this host cannot open AF_VSOCK either; the vsock leg is not differential here");
    }

    drop(listener);
    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// exec-routing.md §4.2: the box hides the host's Unix sockets. The RO base
/// shows the whole host and read-only does not stop `connect(2)`; the netns
/// does not cover pathname sockets. Real bwrap + `supervise_exec`, with a
/// stand-in `/run` under `/var/tmp` (the box's `/tmp` is a fresh tmpfs, which
/// would hide stand-ins there for the wrong reason):
///   - control (no hiding): every stand-in socket is reachable in the box, so
///     the hidden legs below are not vacuous;
///   - the stand-in `/run` is an empty tmpfs: its sockets are gone (ENOENT),
///     its top-level symlink, its `wrappers/` dir and a file an environment
///     variable names are put back readable, and a socket inside `wrappers/`
///     is masked (ECONNREFUSED);
///   - a scanned root's socket and the `$SSH_AUTH_SOCK` socket are masked
///     (the environment the hiding reads is pinned in the config, so the
///     stand-in never reaches a concurrent test's box);
///   - production (`/run` itself, default roots): when THIS host has a
///     connectable `/run/docker.sock` (a docker-group user), the box cannot
///     reach it, and `$XDG_RUNTIME_DIR` still exists as a directory.
/// SKIPPED without bwrap/userns/python3.
#[test]
fn bubblewrap_backend_masks_host_unix_sockets() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    if !have_python3() {
        eprintln!("SKIP: python3 not found on PATH (the socket probe needs it).");
        return;
    }
    let (base, workspace, agent_view) = match bwrap_view_tree("hostsock") {
        Some(t) => t,
        None => return,
    };
    let s = |p: &std::path::Path| p.to_string_lossy().to_string();
    let bind = |p: &std::path::Path| std::os::unix::net::UnixListener::bind(p).unwrap();
    // The stand-in /run.
    let run = base.join("fake-run");
    std::fs::create_dir_all(run.join("user/1000")).unwrap();
    std::fs::create_dir_all(run.join("wrappers")).unwrap();
    std::fs::create_dir_all(run.join("locked")).unwrap();
    let daemon = run.join("daemon.sock");
    let bus = run.join("user/1000/bus");
    let wrapped = run.join("wrappers/inner.sock");
    let locked = run.join("locked/hidden.sock");
    let _l = [bind(&daemon), bind(&bus), bind(&wrapped), bind(&locked)];
    std::fs::write(run.join("wrappers/tool"), "wrapper\n").unwrap();
    std::fs::write(run.join("ca.pem"), "ca\n").unwrap();
    std::fs::write(run.join("not-kept"), "x\n").unwrap();
    std::fs::write(base.join("link-target"), "linked\n").unwrap();
    std::os::unix::fs::symlink(base.join("link-target"), run.join("link")).unwrap();
    // A scanned root outside /run, and a socket only an env var names.
    let varlib = base.join("var-lib");
    std::fs::create_dir_all(varlib.join("lxd")).unwrap();
    let lxd = varlib.join("lxd/unix.socket");
    let elsewhere = base.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let agent = elsewhere.join("agent.sock");
    let _m = [bind(&lxd), bind(&agent)];

    let probe = base.join("probe.py");
    std::fs::write(
        &probe,
        r#"import os, socket, sys
out = open(sys.argv[1], "w")
out.write("RAN\n")
for p in sys.argv[2:]:
    if p.startswith("read:"):
        try:
            open(p[5:]).read()
            out.write("READ-OK %s\n" % p[5:])
        except OSError as e:
            out.write("READ-FAIL %d %s\n" % (e.errno, p[5:]))
        continue
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(p)
        out.write("REACHED %s\n" % p)
    except OSError as e:
        out.write("BLOCKED %d %s\n" % (e.errno, p))
rt = os.environ.get("XDG_RUNTIME_DIR")
out.write("RUNTIME_DIR=%s\n" % ("dir" if rt and os.path.isdir(rt) else "missing"))
"#,
    )
    .unwrap();
    let docker = std::path::Path::new("/run/docker.sock");
    let host_reaches_docker = std::os::unix::net::UnixStream::connect(docker).is_ok();
    let mut targets: Vec<String> = [&daemon, &bus, &wrapped, &locked, &lxd, &agent].iter().map(|p| s(p)).collect();
    for f in [run.join("wrappers/tool"), run.join("ca.pem"), run.join("link"), run.join("not-kept")] {
        targets.push(format!("read:{}", s(&f)));
    }
    if host_reaches_docker {
        targets.push("/run/docker.sock".into());
    }

    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"python3","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let go = |client: &mut ArbiterClient,
              run_dir: Option<String>,
              roots: Option<Vec<exec_supervisor::host_sockets::ScanRoot>>,
              host_env: Option<Vec<(String, String)>>,
              tag: &str|
     -> String {
        let cfg = SupervisorConfig {
            view: ViewConfig { agent_view_root: Some(s(&agent_view)), workspace: Some(s(&workspace)), workspace_writable: false },
            backend: SandboxBackend::Bubblewrap,
            landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
            socket_roots: roots,
            run_dir,
            host_env,
            // The control leg runs without the socket allow-list as well: it
            // alone refuses every host socket (§4.2, proved below).
            socket_allowlist: (tag == "off").then_some(false),
            ..Default::default()
        };
        let seen = workspace.join(format!("{tag}.txt"));
        let mut argv = vec!["python3".to_string(), s(&probe), s(&seen)];
        argv.extend(targets.iter().cloned());
        let t0 = std::time::Instant::now();
        let outcome = supervise_exec(client, &cfg, &ExecRequest { argv, needs_network: false, ..Default::default() })
            .expect("supervise the socket probe");
        eprintln!("[{tag}] supervise_exec took {:?}", t0.elapsed());
        assert_eq!(outcome.child_status, Some(0), "[{tag}] the probe must run to completion: {outcome:?}");
        std::fs::read_to_string(agent_view.join(format!("{tag}.txt"))).unwrap_or_default()
    };

    let off = go(&mut client, Some(String::new()), Some(vec![]), Some(vec![]), "off");
    eprintln!("control saw: {off:?}");
    let pinned_env = vec![
        ("SSH_AUTH_SOCK".to_string(), s(&agent)),
        ("MANDU_TEST_HOSTSOCK_CA".to_string(), s(&run.join("ca.pem"))),
    ];
    let on = go(
        &mut client,
        Some(s(&run)),
        Some(vec![exec_supervisor::host_sockets::ScanRoot::new(s(&varlib), 2)]),
        Some(pinned_env),
        "on",
    );
    eprintln!("stand-in saw: {on:?}");
    let prod = go(&mut client, None, None, None, "prod");
    eprintln!("production saw: {prod:?}");

    for (tag, seen) in [("off", &off), ("on", &on), ("prod", &prod)] {
        assert!(seen.contains("RAN"), "[{tag}] the probe never ran (bwrap setup?): {seen:?}");
    }
    for t in [&daemon, &bus, &wrapped, &locked, &lxd, &agent] {
        assert!(off.contains(&format!("REACHED {}", s(t))), "control: {} must be reachable on the RO base, got {off:?}", s(t));
    }
    for gone in [&daemon, &bus, &locked] {
        assert!(on.contains(&format!("BLOCKED 2 {}", s(gone))), "the hidden run dir's socket is gone: {on:?}");
    }
    for masked in [&wrapped, &lxd, &agent] {
        assert!(on.contains(&format!("BLOCKED 111 {}", s(masked))), "{} is masked: {on:?}", s(masked));
    }
    for kept in ["wrappers/tool", "ca.pem", "link"] {
        assert!(on.contains(&format!("READ-OK {}", s(&run.join(kept)))), "{kept} is put back: {on:?}");
    }
    assert!(on.contains(&format!("READ-FAIL 2 {}", s(&run.join("not-kept")))), "anything else in the run dir is gone: {on:?}");
    if host_reaches_docker {
        assert!(off.contains("REACHED /run/docker.sock"), "control: docker.sock is reachable without the hiding: {off:?}");
        assert!(prod.contains("BLOCKED 2 /run/docker.sock"), "the host's docker.sock must be gone in the box: {prod:?}");
    } else {
        eprintln!("NOTE: this host has no connectable /run/docker.sock; the production leg is not differential here");
    }
    if std::env::var("XDG_RUNTIME_DIR").map(|r| r.starts_with("/run/")).unwrap_or(false) {
        assert!(prod.contains("RUNTIME_DIR=dir"), "$XDG_RUNTIME_DIR still exists (empty) in the box: {prod:?}");
    }

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// The box's Unix-socket allow-list (exec-routing.md §4.2): a boxed command
/// connects only to sockets the box itself bound. Real bwrap + `supervise_exec`
/// with the scan and the `/run` hiding OFF (no roots, no run dir, an empty
/// environment), so the allow-list alone is what the "on" leg proves. A host
/// socket outside every scan root, and one a host process bound inside the
/// workspace, are refused ECONNREFUSED and never see a connection; the box's
/// own sockets (on its /tmp, in the workspace by a relative path, seqpacket,
/// abstract) connect; a Unix datagram socket cannot be created;
/// and a symlink flipped between the box's socket and the host's never lets a
/// connect reach the host. The control leg (allow-list off) reaches the host
/// socket, the race included, so neither leg is vacuous.
///
/// The race must hit both targets in BOTH legs, or a leg proves nothing: the
/// control must reach the host through the link (`RACE OK:HOST`), and the
/// allow-list leg must have connected through the link while it named the
/// host (`RACE ERR:111`, refused) as well as the box's socket (`RACE OK:OWN`).
/// The race used to be a fixed 400 connects against a flipper THREAD, and in
/// about 1 CI run in 40 the control saw `RACE OK:OWN 400`: the link never
/// named the host while a connect ran. The 400 connects take only 15-40 ms,
/// and the flipper advances only when it holds both the GIL and a CPU; on a
/// contended CPU (a busy CI guest) the link changed state just 3-5 times per
/// race, so now and then it sat on one side for all of it (reproduced: 1 in
/// 100 races on a CPU shared with two busy loops). Two changes: the flipper
/// is a separate process, forked before any thread exists, so it no longer
/// waits on the connector's GIL; and, because a process on a shared CPU is
/// still scheduled in slices of milliseconds, the connect loop no longer
/// stops at a fixed count: it runs at least 400 attempts and then until the
/// link was caught naming each side 20 times, bounded by a 30 s deadline
/// (thousands of scheduler slices, so a miss now means the flipper is broken,
/// which the assertion should report). Only the liveness controls gain from
/// the extra attempts; the security assertions (no `OK:HOST` in the box, the
/// host listeners saw nothing) hold over every attempt, so more attempts only
/// make them stronger.
#[test]
#[ignore = "privileged: needs bwrap + an unprivileged userns + python3"]
fn bubblewrap_backend_connects_only_to_sockets_the_box_bound() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    if !have_python3() {
        eprintln!("SKIP: python3 not found on PATH (the socket probe needs it).");
        return;
    }
    let (base, workspace, agent_view) = match bwrap_view_tree("sockallow") {
        Some(t) => t,
        None => return,
    };
    let s = |p: &std::path::Path| p.to_string_lossy().to_string();
    let outside = base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    // Two host listeners that count what reaches them and answer "HOST".
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let host_listener = |path: &std::path::Path| {
        let l = std::os::unix::net::UnixListener::bind(path).unwrap();
        let n = accepted.clone();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { return };
                n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = std::io::Write::write_all(&mut c, b"HOST");
            }
        });
    };
    let host = outside.join("host.sock");
    host_listener(&host);
    // In the AgentView, i.e. inside the box's workspace, bound by the host.
    host_listener(&agent_view.join("host-ws.sock"));

    let probe = base.join("probe.py");
    std::fs::write(
        &probe,
        r#"import os, signal, socket, sys, threading, time
out = open(sys.argv[1], "w", buffering=1)
host, host_ws, ws = sys.argv[2], sys.argv[3], sys.argv[4]
# The race's symlink flipper: a separate process (a thread flipper waits on
# the connector's GIL; see the Rust doc comment), forked before any thread
# exists and held on a pipe until the race starts. It exits when the probe
# dies (EOF on the pipe, or reparented).
link = "/tmp/race-link"
parent = os.getpid()
go_r, go_w = os.pipe()
flipper = os.fork()
if flipper == 0:
    os.close(go_w)
    if os.read(go_r, 1):
        while os.getppid() == parent:
            for target in ("/tmp/race-own.sock", host):
                try:
                    os.symlink(target, link + ".new")
                    os.rename(link + ".new", link)
                except OSError:
                    # A stale link.new (EEXIST) would stall every flip.
                    try:
                        os.unlink(link + ".new")
                    except OSError:
                        pass
    os._exit(0)
os.close(go_r)
def conn(path, typ=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_UNIX, typ)
    try:
        s.settimeout(2)
        s.connect(path)
        return "OK:" + s.recv(16).decode(errors="replace")
    except OSError as e:
        return "ERR:%s" % e.errno
    finally:
        s.close()
def serve(addr, typ=socket.SOCK_STREAM, fam=socket.AF_UNIX):
    srv = socket.socket(fam, typ)
    if isinstance(addr, str) and not addr.startswith("\0") and os.path.lexists(addr):
        os.unlink(addr)
    srv.bind(addr)
    srv.listen(128)
    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                c.sendall(b"OWN")
            except OSError:
                pass
            c.close()
    threading.Thread(target=loop, daemon=True).start()
    return srv
out.write("HOST-OUTSIDE %s\n" % conn(host))
out.write("HOST-WS %s\n" % conn(host_ws))
serve("/tmp/own.sock")
out.write("OWN-TMP %s\n" % conn("/tmp/own.sock"))
os.chdir(ws)
serve("own-ws.sock")
out.write("OWN-WS-REL %s\n" % conn("own-ws.sock"))
out.write("OWN-WS-ABS %s\n" % conn(os.path.join(ws, "own-ws.sock")))
serve("/tmp/own-seq.sock", socket.SOCK_SEQPACKET)
out.write("OWN-SEQ %s\n" % conn("/tmp/own-seq.sock", socket.SOCK_SEQPACKET))
abstract = "\0mandu-abstract-%d" % os.getpid()
serve(abstract)
out.write("ABSTRACT %s\n" % conn(abstract))
for name, typ in (("DGRAM", socket.SOCK_DGRAM), ("RAW", socket.SOCK_RAW)):
    try:
        socket.socket(socket.AF_UNIX, typ).close()
        out.write("UNIX-%s created\n" % name)
    except OSError as e:
        out.write("UNIX-%s ERR:%s\n" % (name, e.errno))
try:
    socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    out.write("PAIR-DGRAM created\n")
except OSError as e:
    out.write("PAIR-DGRAM ERR:%s\n" % e.errno)
a, b = socket.socketpair()
a.sendall(b"x")
out.write("PAIR-STREAM %s\n" % b.recv(1).decode())
serve("/tmp/race-own.sock")
os.symlink(host, link)
os.write(go_w, b"x")
# At least 400 connects, then on until the link was caught naming each side 20
# times (the box's socket: OK:OWN; the host's: OK:HOST without the allow-list,
# ERR:111 with it), within a 30 s bound. Every attempt counts.
counts = {}
attempts = 0
deadline = time.monotonic() + 30
while True:
    r = conn(link)
    counts[r] = counts.get(r, 0) + 1
    attempts += 1
    own = counts.get("OK:OWN", 0)
    other = counts.get("OK:HOST", 0) + counts.get("ERR:111", 0)
    if (attempts >= 400 and own >= 20 and other >= 20) or time.monotonic() > deadline:
        break
os.kill(flipper, signal.SIGKILL)
os.waitpid(flipper, 0)
for k, v in sorted(counts.items()):
    out.write("RACE %s %d\n" % (k, v))
out.write("RACE-ATTEMPTS %d\n" % attempts)
out.write("DONE\n")
out.close()
os._exit(0)
"#,
    )
    .unwrap();

    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"python3","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let go = |client: &mut ArbiterClient, allowlist: bool, tag: &str| -> (String, exec_supervisor::socket_supervision::BoxSocketMode) {
        let cfg = SupervisorConfig {
            view: ViewConfig { agent_view_root: Some(s(&agent_view)), workspace: Some(s(&workspace)), workspace_writable: false },
            backend: SandboxBackend::Bubblewrap,
            landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
            // The scan and the /run hiding off: the allow-list stands alone.
            socket_roots: Some(vec![]),
            run_dir: Some(String::new()),
            host_env: Some(vec![]),
            socket_allowlist: (!allowlist).then_some(false),
            ..Default::default()
        };
        let seen = workspace.join(format!("{tag}.txt"));
        let argv = vec![
            "python3".to_string(),
            s(&probe),
            s(&seen),
            s(&host),
            s(&workspace.join("host-ws.sock")),
            s(&workspace),
        ];
        let t0 = std::time::Instant::now();
        let outcome = supervise_exec(client, &cfg, &ExecRequest { argv, cwd: Some(s(&workspace)), needs_network: false, ..Default::default() })
            .expect("supervise the socket probe");
        eprintln!("[{tag}] supervise_exec took {:?}", t0.elapsed());
        assert_eq!(outcome.child_status, Some(0), "[{tag}] the probe must run to completion: {outcome:?}");
        (std::fs::read_to_string(agent_view.join(format!("{tag}.txt"))).unwrap_or_default(), outcome.box_sockets)
    };

    let (off, off_mode) = go(&mut client, false, "off");
    eprintln!("control saw:\n{off}");
    let reached_in_control = accepted.swap(0, std::sync::atomic::Ordering::SeqCst);
    let (on, on_mode) = go(&mut client, true, "on");
    eprintln!("allow-list saw:\n{on}");
    let reached_with_allowlist = accepted.load(std::sync::atomic::Ordering::SeqCst);

    use exec_supervisor::socket_supervision::BoxSocketMode;
    assert!(off.contains("DONE") && on.contains("DONE"), "the probe never finished");
    assert_eq!(off_mode, BoxSocketMode::NotBoxed);
    assert_eq!(on_mode, BoxSocketMode::Own, "no guard here: the box serves its own listener");
    // Control: the host sockets are reachable (the legs are not vacuous).
    assert!(off.contains("HOST-OUTSIDE OK:HOST") && off.contains("HOST-WS OK:HOST"), "control reaches the host: {off}");
    // The race's liveness controls (see the doc comment): the control leg's
    // link reached both the host and the box's socket.
    assert!(off.contains("RACE OK:HOST"), "control: the race reaches the host socket: {off}");
    assert!(off.contains("RACE OK:OWN"), "control: the race reaches the box's socket: {off}");
    assert!(reached_in_control > 0);
    // The allow-list: host sockets refused, and nothing ever reached them.
    assert!(on.contains("HOST-OUTSIDE ERR:111"), "{on}");
    assert!(on.contains("HOST-WS ERR:111"), "a socket a host process bound in the workspace: {on}");
    assert!(!on.contains("OK:HOST"), "nothing in the box reached a host socket: {on}");
    assert_eq!(reached_with_allowlist, 0, "the host listeners saw no connection");
    // The box's own sockets work.
    // (Loopback TCP is the box's Landlock leg's to refuse on an ABI-4 kernel.)
    for own in ["OWN-TMP", "OWN-WS-REL", "OWN-WS-ABS", "OWN-SEQ", "ABSTRACT"] {
        assert!(on.contains(&format!("{own} OK:OWN")), "{own} must connect: {on}");
    }
    assert!(on.contains("RACE OK:OWN"), "the link reaches the box's own socket: {on}");
    // Liveness: the link was also caught naming the host, and was refused.
    assert!(on.contains("RACE ERR:111"), "the race connected while the link named the host: {on}");
    // No Unix datagram socket in the box, either way (the deny-filter).
    for seen in [&off, &on] {
        for d in ["UNIX-DGRAM ERR:1", "UNIX-RAW ERR:1", "PAIR-DGRAM ERR:1", "PAIR-STREAM x"] {
            assert!(seen.contains(d), "{d}: {seen}");
        }
    }

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// What the socket allow-list costs a box (exec-routing.md §4.2): the same
/// trivial command boxed with the allow-list on and off, alternating, the
/// medians printed. A measurement, not a pass/fail on time (timing asserts
/// flake under load); it asserts only that every run succeeded.
#[test]
#[ignore = "privileged: needs bwrap + an unprivileged userns"]
fn box_socket_allowlist_setup_cost() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    let (base, workspace, agent_view) = match bwrap_view_tree("sockcost") {
        Some(t) => t,
        None => return,
    };
    let s = |p: &std::path::Path| p.to_string_lossy().to_string();
    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({ "shell":"AgentShell","identifier":"true","reason":"default" })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let mut times: [Vec<std::time::Duration>; 2] = [Vec::new(), Vec::new()];
    for i in 0..30 {
        let on = i % 2 == 0;
        let cfg = SupervisorConfig {
            view: ViewConfig { agent_view_root: Some(s(&agent_view)), workspace: Some(s(&workspace)), workspace_writable: false },
            backend: SandboxBackend::Bubblewrap,
            landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
            socket_roots: Some(vec![]),
            run_dir: Some(String::new()),
            host_env: Some(vec![]),
            socket_allowlist: (!on).then_some(false),
            ..Default::default()
        };
        let t0 = std::time::Instant::now();
        let o = supervise_exec(&mut client, &cfg, &ExecRequest { argv: vec!["true".into()], ..Default::default() }).unwrap();
        times[on as usize].push(t0.elapsed());
        assert_eq!(o.child_status, Some(0), "{o:?}");
    }
    for t in times.iter_mut() {
        t.sort();
    }
    eprintln!(
        "COST: boxed `true`, median of 15: allow-list off {:?}, on {:?}",
        times[0][times[0].len() / 2],
        times[1][times[1].len() / 2]
    );
    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// Who serves the allow-list when the box cannot have its own listener
/// (exec-routing.md §4.2): the kernel allows one per filter chain, so under
/// an ancestor's listener the box's is EBUSY. Without a guard that serves
/// boxes, every connect in the box is refused (fail-closed); with one
/// (`MANDU_NET_GUARD_BOX_SOCKETS=1`) the box leaves its connects to it. Each
/// leg runs in a forked child that first installs a listener of its own (an
/// allow-everything filter), standing in for the whole-agent guard; each
/// leg is a fresh process (`box_under_listener_child`).
#[test]
#[ignore = "privileged: needs bwrap + an unprivileged userns + python3"]
fn a_box_under_another_listener_fails_closed_unless_the_guard_serves_it() {
    if !netns_available() || !bwrap_available() || !have_python3() {
        eprintln!("SKIP: bubblewrap, user namespaces or python3 unavailable on this host");
        return;
    }
    let (base, workspace, agent_view) = match bwrap_view_tree("sockdeny") {
        Some(t) => t,
        None => return,
    };
    let s = |p: &std::path::Path| p.to_string_lossy().to_string();
    let probe = base.join("probe.py");
    std::fs::write(
        &probe,
        r#"import socket, sys
out = open(sys.argv[1], "w")
srv = socket.socket(socket.AF_UNIX)
srv.bind("/tmp/own.sock")
srv.listen(1)
c = socket.socket(socket.AF_UNIX)
try:
    c.connect("/tmp/own.sock")
    out.write("OWN OK\n")
except OSError as e:
    out.write("OWN ERR:%s\n" % e.errno)
"#,
    )
    .unwrap();
    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"python3","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let sock = arbiter.socket_path.clone();
    let leg = |guard: bool, tag: &str| -> (i32, String) {
        let seen = workspace.join(format!("{tag}.txt"));
        let cfg = SupervisorConfig {
            view: ViewConfig { agent_view_root: Some(s(&agent_view)), workspace: Some(s(&workspace)), workspace_writable: false },
            backend: SandboxBackend::Bubblewrap,
            landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
            socket_roots: Some(vec![]),
            run_dir: Some(String::new()),
            host_env: Some(vec![]),
            ..Default::default()
        };
        let _ = &cfg;
        // A FRESH process (this test binary, re-executed for
        // `box_under_listener_child`), not a fork of this multithreaded
        // harness: a forked child can inherit a lock another test thread held
        // (the environment's, taken by every getenv) and hang on it.
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "box_under_listener_child", "--ignored", "--nocapture", "--test-threads=1"])
            .env(BOX_CHILD_ENV, format!("{}\n{}\n{}\n{}\n{}", s(&agent_view), s(&workspace), s(&probe), s(&seen), sock.display()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if guard {
            cmd.env(exec_supervisor::socket_supervision::GUARD_BOX_SOCKETS_ENV, "1");
        } else {
            cmd.env_remove(exec_supervisor::socket_supervision::GUARD_BOX_SOCKETS_ENV);
        }
        let code = cmd.status_bounded("the re-executed box_under_listener_child").ok().and_then(|st| st.code()).unwrap_or(-1);
        (code, std::fs::read_to_string(agent_view.join(format!("{tag}.txt"))).unwrap_or_default())
    };

    let (code, seen) = leg(false, "denied");
    if code == 90 {
        eprintln!("SKIP: could not install a stand-in listener here");
        return;
    }
    eprintln!("no guard: code {code}, saw {seen:?}");
    assert_eq!(code, 10, "no guard serves the box: connect denied");
    assert!(seen.contains("OWN ERR:13"), "every connect in the box is refused EACCES, its own sockets too: {seen}");
    let (code, seen) = leg(true, "guard");
    eprintln!("guard serves: code {code}, saw {seen:?}");
    assert_eq!(code, 11, "the guard serves the box");
    assert!(seen.contains("OWN OK"), "the stand-in guard lets it through: {seen}");

    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// The child of `a_box_under_another_listener_fails_closed_unless_the_guard_serves_it`,
/// run as a fresh process of this binary (`BOX_CHILD_ENV` carries its
/// parameters): install a listener of its own (an allow-everything filter),
/// then box the probe and exit with the socket mode the box reported.
const BOX_CHILD_ENV: &str = "MANDU_TEST_BOX_UNDER_LISTENER";

#[test]
#[ignore = "a child entry of a_box_under_another_listener_fails_closed_unless_the_guard_serves_it; does nothing on its own"]
fn box_under_listener_child() {
    let Ok(spec) = std::env::var(BOX_CHILD_ENV) else { return };
    let parts: Vec<&str> = spec.split('\n').collect();
    let [agent_view, workspace, probe, seen, sock] = parts[..] else { std::process::exit(21) };
    let cfg = SupervisorConfig {
        view: ViewConfig { agent_view_root: Some(agent_view.into()), workspace: Some(workspace.into()), workspace_writable: false },
        backend: SandboxBackend::Bubblewrap,
        landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
        socket_roots: Some(vec![]),
        run_dir: Some(String::new()),
        host_env: Some(vec![]),
        ..Default::default()
    };
    let allow: [libc::sock_filter; 1] = [libc::sock_filter { code: (libc::BPF_RET | libc::BPF_K) as u16, jt: 0, jf: 0, k: libc::SECCOMP_RET_ALLOW }];
    let fprog = libc::sock_fprog { len: 1, filter: allow.as_ptr() as *mut libc::sock_filter };
    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    let l = unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, libc::SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog) };
    if l < 0 {
        std::process::exit(90);
    }
    let mut client = ArbiterClient::new(std::path::Path::new(sock));
    let argv = vec!["python3".to_string(), probe.to_string(), seen.to_string()];
    let code = match supervise_exec(&mut client, &cfg, &ExecRequest { argv, needs_network: false, ..Default::default() }) {
        Ok(o) if o.child_status == Some(0) => match o.box_sockets {
            exec_supervisor::socket_supervision::BoxSocketMode::ConnectDenied => 10,
            exec_supervisor::socket_supervision::BoxSocketMode::Guard => 11,
            exec_supervisor::socket_supervision::BoxSocketMode::Own => 12,
            _ => 13,
        },
        _ => 20,
    };
    std::process::exit(code);
}

/// The mount race (exec-routing.md §4.2): a socket the scan found vanishes
/// before bwrap mounts `/dev/null` over it, so the box's setup fails before
/// the command runs. The supervisor sees no "box is up" byte from the applier
/// and a mount point gone, rescans and builds the box once more: the command
/// runs exactly once and succeeds. A command that fails on its own inside a
/// box that came up is never rerun.
static RACE_SOCKET: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);
static RACE_HOOK_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn race_hook_delete_socket(hide: &exec_supervisor::sandbox::HostHide) {
    RACE_HOOK_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if let Some(p) = RACE_SOCKET.lock().unwrap().take() {
        assert!(hide.files.iter().any(|f| std::path::Path::new(f) == p), "the scan must have found the socket first: {hide:?}");
        std::fs::remove_file(&p).unwrap();
    }
}

#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces + Landlock (see file header)"]
fn bubblewrap_backend_rebuilds_a_box_whose_masked_socket_vanished() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    if !fs_supervisor::landlock::landlock_supported() {
        eprintln!("SKIP: no Landlock: the applier (the box's ready signal) is not interposed");
        return;
    }
    let (base, workspace, agent_view) = match bwrap_view_tree("mountrace") {
        Some(t) => t,
        None => return,
    };
    let s = |p: &std::path::Path| p.to_string_lossy().to_string();
    let root = base.join("sockets");
    std::fs::create_dir_all(&root).unwrap();
    let sock = root.join("control.sock");
    let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();

    let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
        "classifyExec" => Ok(serde_json::json!({
            "shell":"AgentShell","identifier":"sh","reason":"default"
        })),
        _ => Err(format!("unexpected op {op}")),
    }));
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let cfg = SupervisorConfig {
        view: ViewConfig { agent_view_root: Some(s(&agent_view)), workspace: Some(s(&workspace)), workspace_writable: false },
        backend: SandboxBackend::Bubblewrap,
        landlock_apply: Some(env!("CARGO_BIN_EXE_mandu-landlock-apply").to_string()),
        socket_roots: Some(vec![exec_supervisor::host_sockets::ScanRoot::new(s(&root), 1)]),
        run_dir: Some(String::new()),
        host_env: Some(vec![]),
        after_host_hide: Some(race_hook_delete_socket),
        ..Default::default()
    };
    let runs = workspace.join("runs.txt");
    let run = |client: &mut ArbiterClient, script: &str| {
        supervise_exec(
            client,
            &cfg,
            &ExecRequest { argv: vec!["/bin/sh".into(), "-c".into(), script.into()], needs_network: false, ..Default::default() },
        )
        .expect("supervise")
    };

    // 1) The socket vanishes after the scan: the first box never comes up.
    *RACE_SOCKET.lock().unwrap() = Some(sock.clone());
    let out = run(&mut client, &format!("echo ran >> {}", s(&runs)));
    let seen = std::fs::read_to_string(agent_view.join("runs.txt")).unwrap_or_default();
    assert_eq!(out.child_status, Some(0), "the rebuilt box runs the command: {out:?}");
    assert_eq!(seen.lines().count(), 1, "exactly once: {seen:?}");
    assert_eq!(RACE_HOOK_CALLS.load(std::sync::atomic::Ordering::SeqCst), 2, "one failed box, one rebuilt");

    // 2) A box that came up and whose command failed is never rerun, even
    //    with a masked socket present.
    let _l2 = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    RACE_HOOK_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
    let out = run(&mut client, &format!("echo ran >> {}; exit 3", s(&runs)));
    let seen = std::fs::read_to_string(agent_view.join("runs.txt")).unwrap_or_default();
    assert_eq!(out.child_status, Some(3), "{out:?}");
    assert_eq!(seen.lines().count(), 2, "the failing command ran once: {seen:?}");
    assert_eq!(RACE_HOOK_CALLS.load(std::sync::atomic::Ordering::SeqCst), 1, "no rebuild");

    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

// ── Which bubblewrap the command box runs, end to end ───────────────────────
// (docs/design/confidentiality/rootless-confinement-ubuntu-2404.md §0.7)

/// The bubblewrap this test's own PATH resolves outside `base` (the
/// production resolver), when it can start a box here; `None` → SKIP.
fn box_capable_system_bwrap(base: &std::path::Path) -> Option<String> {
    let b = exec_supervisor::sandbox::resolve_bwrap(&[base.to_str()?])?;
    std::process::Command::new(&b)
        .args(["--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status_bounded("a bubblewrap capability probe")
        .ok()?
        .success()
        .then_some(b)
}

/// The PRODUCTION path (the `mandu-exec-box` bin a launcher shim execs, its
/// Bubblewrap backend, the box's own PATH) runs only the distribution's
/// bubblewrap, by its absolute real path:
///   (a) a boxed command runs inside the first `bwrap` on PATH outside the
///       workspace, the command's cwd and the box's own cwd, exec'd by its
///       absolute path, and the command is boxed (the root is read-only);
///   (b) a `bwrap` planted in the cwd (`.` on PATH), in the workspace (its
///       `bin/`, absolute or relative on PATH), behind a link from outside
///       into the workspace, on a relative entry that points OUTSIDE the
///       workspace, or in the AgentView worktree is never executed: each
///       planted one appends to a marker file, which stays empty;
///   (c) with no usable bubblewrap the bin exits 126 with the message and
///       runs nothing, in the ordinary box and with the clean box first;
///   (d) the administrator's `bwrap_path`: the launcher puts its directory on
///       the agent's PATH ahead of the system one (run.ts `bwrapDir`), and the
///       box runs that one, not the system one behind it.
/// SKIPPED unless a bubblewrap outside the test tree can start a box here.
#[test]
#[ignore = "privileged: needs bubblewrap + user namespaces (see file header)"]
fn exec_box_bin_runs_only_the_resolved_system_bwrap() {
    use std::os::unix::fs::symlink;
    let Some(base) = outside_tmp_dir("bwrap-resolve") else { return };
    let base = std::fs::canonicalize(&base).unwrap();
    let Some(sys_bwrap) = box_capable_system_bwrap(&base) else {
        eprintln!("SKIP: no bubblewrap outside the test tree can start a box on this host");
        let _ = std::fs::remove_dir_all(&base);
        return;
    };
    let s = |p: &std::path::Path| p.to_string_lossy().to_string();
    let sys_dir = s(std::path::Path::new(&sys_bwrap).parent().unwrap());

    let ws = base.join("ws");
    let av = base.join("av");
    let elsewhere = base.join("elsewhere");
    let rel = base.join("rel");
    let link = base.join("link");
    let sys_wrap = base.join("sys");
    let admin = base.join("admin");
    for d in [ws.join("bin"), av.join("bin"), elsewhere.clone(), rel.clone(), link.clone(), sys_wrap.clone(), admin.clone()] {
        std::fs::create_dir_all(&d).unwrap();
    }
    // Planted: each would run on the HOST, outside any box, and records it.
    let planted_log = base.join("planted.log");
    let planted = format!("#!/bin/sh\necho \"$0\" >> {}\nexit 0\n", s(&planted_log));
    for p in [ws.join("bwrap"), ws.join("bin").join("bwrap"), rel.join("bwrap"), av.join("bin").join("bwrap")] {
        write_exec_script(&p, planted.as_bytes()).unwrap();
    }
    symlink(ws.join("bin").join("bwrap"), link.join("bwrap")).unwrap();
    // Legitimate ones outside every excluded root: record the path they were
    // exec'd by, then run the system bubblewrap.
    let sys_log = base.join("sys.log");
    let admin_log = base.join("admin.log");
    for (dir, log) in [(&sys_wrap, &sys_log), (&admin, &admin_log)] {
        let body = format!("#!/bin/sh\necho \"$0\" >> {}\nexec {} \"$@\"\n", s(log), sys_bwrap);
        write_exec_script(&dir.join("bwrap"), body.as_bytes()).unwrap();
    }
    // The boxed command: records that it ran and whether the root is
    // read-only (a write outside the workspace must fail inside the box).
    let probe = base.join("probe.sh");
    let script = format!(
        "#!/bin/sh\necho RAN >> {ws}/ran.txt\n\
         if echo x > {esc} 2>/dev/null; then echo ESCAPED >> {ws}/ran.txt; else echo RO >> {ws}/ran.txt; fi\n",
        ws = s(&ws),
        esc = s(&base.join("escape.txt")),
    );
    write_exec_script(&probe, script.as_bytes()).unwrap();

    let arbiter = routing_arbiter();
    let bin = env!("CARGO_BIN_EXE_mandu-exec-box");
    let applier = env!("CARGO_BIN_EXE_mandu-landlock-apply");
    // One boxed exec through the bin, as a shim runs it (`--cwd "$PWD"`), with
    // nothing ambient: the PATH and the shim's baked variables only.
    let run = |path: &str, cwd: &std::path::Path, env: &[(&str, String)]| -> (i32, String) {
        let out = std::process::Command::new(bin)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", path)
            .env("MANDU_ARBITER_SOCK", &arbiter.socket_path)
            .env("MANDU_LANDLOCK_APPLY", applier)
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .args(["--cwd", &s(cwd), "--no-needs-network", "--", &s(&probe)])
            .output_bounded("mandu-exec-box (a boxed probe, as a shim runs it)")
            .expect("spawn mandu-exec-box");
        (out.status.code().expect("exit code"), String::from_utf8_lossy(&out.stderr).to_string())
    };
    let read = |p: &std::path::Path| std::fs::read_to_string(p).unwrap_or_default();
    let reset = || {
        for p in [ws.join("ran.txt"), av.join("ran.txt"), sys_log.clone(), admin_log.clone()] {
            let _ = std::fs::remove_file(p);
        }
    };
    // The launcher's no-view shims (integrity off, `secrets`): the project is
    // MANDU_WORKSPACE, bound writable at its own path.
    let no_view = [("MANDU_WORKSPACE", s(&ws)), ("MANDU_EXEC_BOX_WORKSPACE_RW", "1".to_string())];
    let planted_path = format!(".:../rel:bin:{ws}/bin:{link}", ws = s(&ws), link = s(&link));
    let sys_wrap_real = s(&std::fs::canonicalize(sys_wrap.join("bwrap")).unwrap());
    let admin_real = s(&std::fs::canonicalize(admin.join("bwrap")).unwrap());

    // (a) + (b): every planted one first on PATH, then a bubblewrap outside.
    reset();
    let (code, err) = run(&format!("{planted_path}:{}", s(&sys_wrap)), &ws, &no_view);
    eprintln!("(a) exit {code}, stderr {err:?}, ran by {:?}", read(&sys_log));
    assert_eq!(code, 0, "the boxed command runs: {err}");
    assert_eq!(read(&ws.join("ran.txt")), "RAN\nRO\n", "it ran once, inside the box (read-only root)");
    let ran_by = read(&sys_log);
    assert!(!ran_by.is_empty(), "the bubblewrap outside the workspace ran");
    assert!(ran_by.lines().all(|l| l == sys_wrap_real), "always by its absolute real path, never `bwrap`: {ran_by:?}");
    assert_eq!(read(&planted_log), "", "no planted bubblewrap ran");
    assert!(!base.join("escape.txt").exists());

    // (a) the distribution's own bubblewrap, by its absolute path, behind
    // the planted ones (no stand-in).
    reset();
    let (code, err) = run(&format!("{planted_path}:{sys_dir}"), &ws, &no_view);
    eprintln!("(a) system {sys_bwrap}: exit {code}, stderr {err:?}");
    assert_eq!(code, 0, "the boxed command runs under {sys_bwrap}: {err}");
    assert_eq!(read(&ws.join("ran.txt")), "RAN\nRO\n");
    assert_eq!(read(&planted_log), "", "no planted bubblewrap ran");

    // (b) the AgentView worktree is the agent's too: a `bwrap` in it is
    // skipped even when neither the cwd nor the workspace contains it.
    reset();
    let view = [("MANDU_AGENTVIEW_ROOT", s(&av)), ("MANDU_WORKSPACE", s(&ws))];
    let (code, err) = run(&format!("{}/bin:{}", s(&av), s(&sys_wrap)), &elsewhere, &view);
    eprintln!("(b) AgentView: exit {code}, stderr {err:?}");
    assert_eq!(read(&planted_log), "", "the AgentView's planted bubblewrap never ran");
    assert_eq!(code, 0, "the boxed command runs: {err}");
    assert_eq!(read(&av.join("ran.txt")), "RAN\nRO\n", "boxed: its workspace writes land in the AgentView");

    // (d) the administrator's directory ahead of the system one.
    reset();
    let (code, err) = run(&format!("{}:{planted_path}:{}", s(&admin), s(&sys_wrap)), &ws, &no_view);
    eprintln!("(d) exit {code}, stderr {err:?}, ran by {:?}", read(&admin_log));
    assert_eq!(code, 0, "the boxed command runs: {err}");
    assert_eq!(read(&ws.join("ran.txt")), "RAN\nRO\n");
    let ran_by = read(&admin_log);
    assert!(!ran_by.is_empty() && ran_by.lines().all(|l| l == admin_real), "the administrator's ran, by its path: {ran_by:?}");
    assert_eq!(read(&sys_log), "", "not the system one behind it");
    assert_eq!(read(&planted_log), "", "no planted bubblewrap ran");

    // (c) none outside: 126 with the message, nothing runs, planted or boxed
    // or unboxed; the same with the clean box tried first.
    for clean in ["0", "1"] {
        reset();
        let mut env = no_view.to_vec();
        env.push(("MANDU_EXEC_CLEAN_BOX", clean.to_string()));
        let (code, err) = run(&planted_path, &ws, &env);
        eprintln!("(c) clean box {clean}: exit {code}, stderr {err:?}");
        assert_eq!(code, 126, "no bubblewrap: the documented 126");
        assert!(err.contains(exec_supervisor::sandbox::NO_BWRAP_MESSAGE.trim_end()), "with the message: {err:?}");
        assert!(!ws.join("ran.txt").exists(), "the command never ran, boxed or not");
        assert_eq!(read(&planted_log), "", "no planted bubblewrap ran");
    }

    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

// ── The supervisor's bounded waits (exec-routing.md §4.4) ─────────────────────

/// Is a process whose command line is exactly `argv` alive (not a zombie)?
/// The marker a deadline test looks for after the kill.
fn running_with_cmdline(argv: &[&str]) -> bool {
    let want: Vec<u8> = argv.iter().flat_map(|a| a.bytes().chain(std::iter::once(0))).collect();
    std::fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten().any(|e| {
                let p = e.path();
                let zombie = std::fs::read_to_string(p.join("stat")).ok().and_then(|s| s.rsplit_once(") ").map(|(_, r)| r.starts_with('Z'))).unwrap_or(true);
                !zombie && std::fs::read(p.join("cmdline")).ok().as_deref() == Some(&want[..])
            })
        })
        .unwrap_or(false)
}

/// Until `argv`'s process is gone, at most 10 s: true when it went.
fn gone_soon(argv: &[&str]) -> bool {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < end {
        if !running_with_cmdline(argv) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

/// The caller's deadline (`SupervisorConfig::deadline`) on a command that
/// runs past it: the box's whole tree is killed and the exec refused with
/// `TimedOut`, never left running unsupervised. HumanShell (InProcess, no
/// sandbox): the shell's child `sleep` is a grandchild of the supervisor, so
/// the kill must reach the tree, not the child alone.
#[test]
#[ignore = "requires root or an unprivileged userns (fork+exec) + a arbiter; --features kernel -- --ignored"]
fn a_deadline_kills_the_whole_tree_of_a_command_that_runs_past_it() {
    let arbiter = routing_arbiter();
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let marker = ["sleep", "41.25"];
    let cfg = SupervisorConfig {
        backend: SandboxBackend::InProcess,
        deadline: Some(std::time::Duration::from_millis(1500)),
        ..Default::default()
    };
    // `; :` keeps sh from exec'ing sleep in place: it forks it.
    let req = ExecRequest { argv: vec!["sh".into(), "-c".into(), "sleep 41.25; :".into()], needs_network: true, ..Default::default() };
    let t0 = std::time::Instant::now();
    let got = exec_supervisor::kernel::supervise_exec(&mut client, &cfg, &req);
    let took = t0.elapsed();
    let err = got.expect_err("past its deadline the exec is refused, never an outcome");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(err.to_string().contains("killed"), "the error says the box was killed: {err}");
    assert!(took < std::time::Duration::from_secs(20), "it gave up near its deadline: {took:?}");
    assert!(gone_soon(&marker), "the shell's child was killed with it");
    // Control: within its deadline the same shape completes.
    let req = ExecRequest { argv: vec!["sh".into(), "-c".into(), "exit 3".into()], needs_network: true, ..Default::default() };
    let out = exec_supervisor::kernel::supervise_exec(&mut client, &cfg, &req).expect("within its deadline");
    assert_eq!(out.child_status, Some(3));
    drop(client);
    drop(arbiter);
}

/// The same deadline on a bubblewrap AgentShell box: the box (and the
/// command in its pid namespace) dies with it.
#[test]
#[ignore = "privileged: needs bwrap + an unprivileged userns"]
fn a_deadline_kills_a_bubblewrap_box_that_runs_past_it() {
    if !netns_available() || !bwrap_available() {
        eprintln!("SKIP: bubblewrap and/or user namespaces unavailable on this host");
        return;
    }
    let Some((base, workspace, agent_view)) = bwrap_view_tree("deadline") else { return };
    let s = |p: &std::path::Path| p.to_string_lossy().to_string();
    let arbiter = routing_arbiter();
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let cfg = SupervisorConfig {
        view: ViewConfig { agent_view_root: Some(s(&agent_view)), workspace: Some(s(&workspace)), workspace_writable: false },
        backend: SandboxBackend::Bubblewrap,
        socket_roots: Some(vec![]),
        run_dir: Some(String::new()),
        host_env: Some(vec![]),
        deadline: Some(std::time::Duration::from_secs(3)),
        ..Default::default()
    };
    let marker = ["sleep", "41.5"];
    let req = ExecRequest { argv: vec!["sh".into(), "-c".into(), "sleep 41.5; :".into()], ..Default::default() };
    let t0 = std::time::Instant::now();
    let err = exec_supervisor::kernel::supervise_exec(&mut client, &cfg, &req).expect_err("refused past its deadline");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(t0.elapsed() < std::time::Duration::from_secs(30), "{:?}", t0.elapsed());
    assert!(gone_soon(&marker), "the boxed command died with its box");
    drop(client);
    drop(arbiter);
    let _ = std::fs::remove_dir_all(&base);
}

/// Stands in for a box child stuck before its socket hand-over (a lock its
/// fork inherited, a wedged call): it never reports.
/// Named `mdu-no-report` (its comm) so the test can tell it is gone.
fn never_report() {
    // SAFETY: renaming this thread (the forked child's only one).
    unsafe { libc::prctl(libc::PR_SET_NAME, b"mdu-no-report\0".as_ptr() as libc::c_ulong, 0, 0, 0) };
    loop {
        // SAFETY: pause until a signal; the parent's SIGKILL ends it.
        unsafe { libc::pause() };
    }
}

/// The box's socket hand-over (exec-routing.md §4.2) is the supervisor's own
/// wait: with NO caller deadline, a child that never reports is killed at the
/// hand-over's bound and the exec refused, never waited for for good.
#[test]
#[ignore = "requires root or an unprivileged userns (fork) + a arbiter; --features kernel -- --ignored"]
fn a_box_whose_socket_hand_over_never_comes_is_killed_and_refused() {
    let arbiter = routing_arbiter();
    let mut client = ArbiterClient::new(&arbiter.socket_path);
    let cfg = SupervisorConfig {
        backend: SandboxBackend::Bubblewrap,
        socket_roots: Some(vec![]),
        run_dir: Some(String::new()),
        host_env: Some(vec![]),
        handoff_limit: Some(std::time::Duration::from_secs(1)),
        before_handoff: Some(never_report),
        ..Default::default()
    };
    let req = ExecRequest { argv: vec!["true".into()], ..Default::default() };
    let t0 = std::time::Instant::now();
    let got = exec_supervisor::kernel::supervise_exec(&mut client, &cfg, &req);
    let took = t0.elapsed();
    let err = got.expect_err("a hand-over that never came refuses the exec");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(err.to_string().contains("hand-over"), "the error names the hand-over: {err}");
    assert!(took < std::time::Duration::from_secs(20), "it gave up near its bound: {took:?}");
    // The stuck child was killed and reaped (not even a zombie is left).
    let left = std::fs::read_dir("/proc").unwrap().flatten().any(|e| std::fs::read_to_string(e.path().join("comm")).unwrap_or_default().trim() == "mdu-no-report");
    assert!(!left, "the stuck child is gone");
    drop(client);
    drop(arbiter);
}

/// The attach front-end's loop (`run_supervisor`) ends once no tracee uses
/// its filter, whether the last one was gone before the loop started or
/// exits while the loop waits in it (exec-routing.md §4.4).
#[test]
#[ignore = "requires SECCOMP_USER_NOTIF (no_new_privs); --features kernel -- --ignored"]
fn the_notification_loop_ends_when_its_tracee_is_gone() {
    for live in [false, true] {
        let (sup_sock, child_sock) = socketpair();
        // live: the tracee waits for a byte on `go` while the loop runs.
        let (go_r, go_w) = pipe();
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed: {}", last_err());
        if child == 0 {
            unsafe {
                libc::close(sup_sock);
                libc::close(go_w);
            }
            let Ok(listener) = install_execve_filter_self() else { unsafe { libc::_exit(FE_EXIT_NO_SECCOMP) } };
            if send_fd(child_sock, listener).is_err() {
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::close(listener) };
            if live {
                let mut b = [0u8; 1];
                unsafe { libc::read(go_r, b.as_mut_ptr().cast(), 1) };
            }
            unsafe { libc::_exit(0) };
        }
        unsafe {
            libc::close(child_sock);
            libc::close(go_r);
        }
        readable_within(sup_sock, child, wait_limit(), "waiting for the tracee to hand over its execve listener");
        let listener = recv_fd(sup_sock);
        unsafe { libc::close(sup_sock) };
        let Ok(listener) = listener else {
            unsafe { libc::close(go_w) };
            assert_eq!(reap(child), Some(FE_EXIT_NO_SECCOMP), "the tracee failed to send its listener");
            eprintln!("SKIP: seccomp NEW_LISTENER denied here");
            return;
        };
        if !live {
            unsafe { libc::close(go_w) };
            assert_eq!(reap(child), Some(0));
        }
        let arbiter = routing_arbiter();
        let sock = arbiter.socket_path.clone();
        let lp = std::thread::spawn(move || {
            let mut client = ArbiterClient::new(&sock);
            exec_supervisor::kernel::run_supervisor(listener, &mut client)
        });
        if live {
            // The loop is waiting in it by now; the tracee exits.
            std::thread::sleep(std::time::Duration::from_millis(300));
            // A byte, not the close alone: another test's fork may hold a copy.
            unsafe {
                libc::write(go_w, b"g".as_ptr().cast(), 1);
                libc::close(go_w);
            }
            assert_eq!(reap(child), Some(0));
        }
        let what = format!("run_supervisor, after its only tracee exited (live={live})");
        let got = join_within(lp, std::time::Duration::from_secs(30), &what).expect("the loop did not panic");
        assert!(got.is_ok(), "{got:?}");
        unsafe { libc::close(listener) };
        drop(arbiter);
    }
}
