//! Unprivileged integration tests for the Landlock FS + net backend.
//!
//! `#[ignore]`d so the default `cargo test` skips them. Landlock needs NO root and
//! NO capability — only `no_new_privs` (which `restrict_self_to_plan` sets) — so
//! these run as an ORDINARY user, with no `unshare`. The FS test needs kernel
//! ≥ 5.13 (Landlock ABI v1); the net tests need kernel ≥ 6.7 (ABI v4). On an older
//! kernel each SELF-SKIPs with a clear message.
//!
//!   cargo test -p fs-supervisor --features kernel -- --ignored --nocapture landlock
//!
//! ── What the FS test proves (on a ≥ 5.13 kernel) ─────────────────────────────
//! A forked child restricts itself to the asymmetric overlay (whole FS READ-ONLY,
//! one temp dir READ-WRITE) and then:
//!   • a WRITE inside the RW dir SUCCEEDS, and
//!   • a WRITE to a control dir that is NOT in the RW set FAILS with EACCES/EPERM,
//! even though DAC would permit both (the control dir is the user's own temp dir).
//! Landlock is therefore the sole cause of the denial — the LSM-enforced boundary.
//!
//! ── What the NET tests prove (on a ≥ 6.7 kernel) ─────────────────────────────
//! A forked child restricts itself to the deny-all-TCP plan and then, against a
//! LIVE 127.0.0.1 listener the parent bound BEFORE the restrict (so a denial is
//! attributable to Landlock, not a dead port):
//!   • connect() to the listener FAILS with EACCES,
//!   • bind() of a fresh TCP socket FAILS with EACCES, and
//!   • a UDP socket still binds + connects — Landlock net governs TCP ONLY (the
//!     honest boundary; the AgentShell netns is what removes UDP).
//! A second child gets a CONNECT-only allow rule for the listener's port and its
//! connect() SUCCEEDS while bind() stays denied — the port-rule plumbing works.
//! Every restrict runs in a FORKED child: it is irreversible and must never poison
//! the test runner.

// The whole file is kernel-feature + Linux. The default build compiles an empty
// crate so it never breaks `cargo test` (mirrors kernel_integration.rs).
#![cfg(all(feature = "kernel", target_os = "linux"))]

// The deadline helpers net-supervisor's integration tests share
// (docs/design/testing/test-organization.md §8.5): a reap fails by name with
// the child's /proc state, and kills it, instead of hanging.
#[path = "../../net-supervisor/tests/support/mod.rs"]
mod support;
use support::{reap_within, wait_limit};

use std::ffi::CString;

use fs_supervisor::landlock::{
    landlock_abi_version, landlock_supported, plan_landlock, plan_landlock_deny_tcp,
    LANDLOCK_ACCESS_NET_CONNECT_TCP, RO_ROOT,
};

// Child exit codes — the parent decodes these to assert the Landlock behavior.
// (Codes >= 100 encode an UNEXPECTED errno as 100 + (errno & 0x7f).)
const EXIT_OK: i32 = 0; // RW write succeeded AND RO-control write was denied
const EXIT_RESTRICT_FAIL: i32 = 80; // restrict_self_to_plan returned Err
const EXIT_RW_DENIED: i32 = 81; // a write inside the RW dir was (wrongly) denied
const EXIT_RO_WRITABLE: i32 = 82; // a write to the RO-control dir (wrongly) succeeded

// Net-test child exit codes (same EXIT_OK / EXIT_RESTRICT_FAIL / errno channel).
const EXIT_TCP_CONNECT_ALLOWED: i32 = 83; // deny-all: connect (wrongly) succeeded
const EXIT_TCP_BIND_ALLOWED: i32 = 84; // deny-all: bind (wrongly) succeeded
const EXIT_UDP_DENIED: i32 = 85; // UDP was (wrongly) affected — TCP-only scope broken
const EXIT_ALLOWED_CONNECT_DENIED: i32 = 86; // allow-port: connect (wrongly) denied

/// LANDLOCK ENFORCEMENT (self-SKIPs on kernel < 5.13). Restrict a forked child to
/// an RW temp dir over an RO root and assert writes land only where the plan allows.
#[test]
#[ignore = "unprivileged but needs kernel >= 5.13 (Landlock ABI v1); --features kernel -- --ignored"]
fn landlock_restricts_writes_to_the_agentview_overlay() {
    if !landlock_supported() {
        eprintln!(
            "SKIP: Landlock unavailable (needs kernel >= 5.13; this host may be older). \
             abi_probe={}",
            landlock_abi_version()
        );
        return;
    }
    eprintln!("Landlock available: ABI v{}", landlock_abi_version());

    let tmp = TempDir::new("fs-supervisor-landlock-it");
    // Two sibling dirs the user can normally write to (DAC allows both). Only `rw`
    // goes into the Landlock plan; `ro_ctrl` is covered only by the RO `/` rule, so
    // a write to it must be DENIED — isolating Landlock as the cause.
    let rw_dir = format!("{}/rw", tmp.path);
    let ro_ctrl_dir = format!("{}/ro", tmp.path);
    std::fs::create_dir_all(&rw_dir).unwrap();
    std::fs::create_dir_all(&ro_ctrl_dir).unwrap();

    // Build the plan at the LIVE ABI so no bit is masked away unexpectedly.
    let abi = landlock_abi_version().max(1) as u32;
    let plan = plan_landlock(RO_ROOT, &[rw_dir.clone()], abi);

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed: {}", last_err());

    if child == 0 {
        // ── CHILD: restrict self, then probe both dirs ────────────────────────
        if fs_supervisor::landlock::restrict_self_to_plan(&plan).is_err() {
            unsafe { libc::_exit(EXIT_RESTRICT_FAIL) };
        }
        // A write INSIDE the RW dir must SUCCEED (union of the RO `/` rule + this RW
        // rule ⇒ writable).
        if create_write(&format!("{rw_dir}/probe.txt")).is_err() {
            unsafe { libc::_exit(EXIT_RW_DENIED) };
        }
        // A write to the RO-control dir must FAIL (only the RO `/` rule covers it).
        match create_write(&format!("{ro_ctrl_dir}/probe.txt")) {
            Ok(()) => unsafe { libc::_exit(EXIT_RO_WRITABLE) }, // invariant violation
            Err(errno) => {
                // Landlock denies with EACCES (open) or EPERM; anything else is a
                // surprise we surface via the errno-as-exit-code (>= 100).
                if errno == libc::EACCES || errno == libc::EPERM {
                    unsafe { libc::_exit(EXIT_OK) };
                }
                unsafe { libc::_exit(100 + (errno & 0x7f)) };
            }
        }
    }

    // ── PARENT: reap + assert the child observed the overlay ──────────────────
    let code = reap(child);
    match code {
        Some(EXIT_OK) => eprintln!(
            "LANDLOCK PASS: write inside {rw_dir} succeeded; write to {ro_ctrl_dir} \
             denied (EACCES/EPERM) — the RW subtree is the only writable place."
        ),
        Some(EXIT_RESTRICT_FAIL) => {
            panic!("restrict_self_to_plan failed on a Landlock-capable kernel")
        }
        Some(EXIT_RW_DENIED) => panic!("write inside the RW dir was denied — plan under-grants"),
        Some(EXIT_RO_WRITABLE) => panic!(
            "write to the RO-control dir SUCCEEDED — Landlock did not restrict writes \
             (invariant violation)"
        ),
        other => panic!("child exited unexpectedly: {other:?}"),
    }
}

/// LANDLOCK NET ENFORCEMENT (self-SKIPs below ABI v4 / kernel 6.7). Restrict a
/// forked child to the deny-all-TCP plan and assert: connect to a LIVE listener →
/// EACCES, bind of a fresh TCP socket → EACCES, UDP untouched (TCP-only scope).
#[test]
#[ignore = "unprivileged but needs kernel >= 6.7 (Landlock ABI v4); --features kernel -- --ignored"]
fn landlock_denies_tcp_for_the_net_off_agentshell_world() {
    let abi = landlock_abi_version();
    if abi < 4 {
        eprintln!("SKIP: Landlock net rights need ABI v4 (kernel >= 6.7). abi_probe={abi}");
        return;
    }
    eprintln!("Landlock net available: ABI v{abi}");

    // A LIVE listener, bound BEFORE the restrict: the child's connect failure is
    // then attributable to Landlock, not to a dead port. The parent never accepts —
    // a successful connect would complete via the backlog alone.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // Deny-all TCP over a read-only FS world (no RW paths — the child only probes
    // sockets). net_rules is EMPTY: handled-but-never-granted = denied everywhere.
    let plan = plan_landlock_deny_tcp(RO_ROOT, &[], abi as u32);

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed: {}", last_err());

    if child == 0 {
        // ── CHILD: restrict self, then probe TCP connect / TCP bind / UDP ─────
        if fs_supervisor::landlock::restrict_self_to_plan(&plan).is_err() {
            unsafe { libc::_exit(EXIT_RESTRICT_FAIL) };
        }
        // connect() to the live listener must be refused by the LSM with EACCES.
        match tcp_connect(port) {
            Ok(()) => unsafe { libc::_exit(EXIT_TCP_CONNECT_ALLOWED) },
            Err(errno) if errno == libc::EACCES => {}
            Err(errno) => unsafe { libc::_exit(100 + (errno & 0x7f)) },
        }
        // bind() of a fresh TCP socket must be refused likewise. A FIXED port is
        // flake-free: security_socket_bind runs BEFORE the address-in-use check,
        // so EACCES precedes any EADDRINUSE.
        match tcp_bind(50505) {
            Ok(()) => unsafe { libc::_exit(EXIT_TCP_BIND_ALLOWED) },
            Err(errno) if errno == libc::EACCES => {}
            Err(errno) => unsafe { libc::_exit(100 + (errno & 0x7f)) },
        }
        // The HONEST BOUNDARY: Landlock net governs TCP only. UDP must still bind
        // and connect (the AgentShell netns, not the LSM, is what removes UDP).
        if udp_bind_and_connect(port).is_err() {
            unsafe { libc::_exit(EXIT_UDP_DENIED) };
        }
        unsafe { libc::_exit(EXIT_OK) };
    }

    // ── PARENT: reap + assert the child observed the net-off world ────────────
    match reap(child) {
        Some(EXIT_OK) => eprintln!(
            "LANDLOCK NET PASS: TCP connect to 127.0.0.1:{port} and TCP bind both \
             denied (EACCES); UDP unaffected — deny-all TCP holds, TCP-only scope."
        ),
        Some(EXIT_RESTRICT_FAIL) => {
            panic!("restrict_self_to_plan failed on an ABI-v4 kernel")
        }
        Some(EXIT_TCP_CONNECT_ALLOWED) => panic!(
            "TCP connect SUCCEEDED under a deny-all-TCP plan (invariant violation)"
        ),
        Some(EXIT_TCP_BIND_ALLOWED) => {
            panic!("TCP bind SUCCEEDED under a deny-all-TCP plan (invariant violation)")
        }
        Some(EXIT_UDP_DENIED) => panic!(
            "UDP was denied — Landlock net must govern TCP only (scope regression)"
        ),
        other => panic!("child exited unexpectedly: {other:?} (>=100 encodes an errno)"),
    }
}

/// LANDLOCK NET PORT-RULE (self-SKIPs below ABI v4). With a CONNECT-only allow rule
/// for the listener's port, connect() SUCCEEDS while bind() stays denied — proves
/// the LANDLOCK_RULE_NET_PORT plumbing a future launcher wrap will use to allow
/// only the model-proxy port.
#[test]
#[ignore = "unprivileged but needs kernel >= 6.7 (Landlock ABI v4); --features kernel -- --ignored"]
fn landlock_net_port_allow_rule_permits_connect_to_that_port_only() {
    let abi = landlock_abi_version();
    if abi < 4 {
        eprintln!("SKIP: Landlock net rights need ABI v4 (kernel >= 6.7). abi_probe={abi}");
        return;
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // Deny-all TCP + one CONNECT-only hole for the listener's port.
    let plan = plan_landlock_deny_tcp(RO_ROOT, &[], abi as u32)
        .allow_tcp_port(port, LANDLOCK_ACCESS_NET_CONNECT_TCP);

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed: {}", last_err());

    if child == 0 {
        // ── CHILD: restrict self, then probe the allowed + still-denied paths ─
        if fs_supervisor::landlock::restrict_self_to_plan(&plan).is_err() {
            unsafe { libc::_exit(EXIT_RESTRICT_FAIL) };
        }
        // connect() to the ALLOWED port must succeed.
        if tcp_connect(port).is_err() {
            unsafe { libc::_exit(EXIT_ALLOWED_CONNECT_DENIED) };
        }
        // bind() stays denied: the rule granted CONNECT only (and only that port).
        match tcp_bind(50506) {
            Ok(()) => unsafe { libc::_exit(EXIT_TCP_BIND_ALLOWED) },
            Err(errno) if errno == libc::EACCES => unsafe { libc::_exit(EXIT_OK) },
            Err(errno) => unsafe { libc::_exit(100 + (errno & 0x7f)) },
        }
    }

    // ── PARENT: reap + assert the allow-rule shape ─────────────────────────────
    match reap(child) {
        Some(EXIT_OK) => eprintln!(
            "LANDLOCK NET PASS: CONNECT allow-rule for 127.0.0.1:{port} admitted the \
             connect; TCP bind stayed denied — port-rule plumbing works."
        ),
        Some(EXIT_RESTRICT_FAIL) => {
            panic!("restrict_self_to_plan failed on an ABI-v4 kernel (with a net rule)")
        }
        Some(EXIT_ALLOWED_CONNECT_DENIED) => panic!(
            "connect to the ALLOWED port was denied — the NET_PORT rule was not applied"
        ),
        Some(EXIT_TCP_BIND_ALLOWED) => panic!(
            "TCP bind SUCCEEDED despite a CONNECT-only allow rule (over-grant)"
        ),
        other => panic!("child exited unexpectedly: {other:?} (>=100 encodes an errno)"),
    }
}

// ── tiny libc helpers (test-local; the crate core stays clean) ───────────────

fn last_err() -> String {
    std::io::Error::last_os_error().to_string()
}

/// `open(path, O_WRONLY|O_CREAT, 0644)` + a 1-byte write. Returns `Ok(())` on
/// success or `Err(errno)` on the FIRST failing syscall (Landlock denials surface
/// as EACCES on the open). Keeps the probe to raw libc so a restricted child never
/// pulls in std machinery that might itself touch a denied path.
fn create_write(path: &str) -> Result<(), i32> {
    let c = CString::new(path).map_err(|_| libc::EINVAL)?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
    }
    let buf = b"x";
    let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, 1) };
    let werr = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
    unsafe { libc::close(fd) };
    if n < 0 {
        return Err(werr);
    }
    Ok(())
}

/// `sockaddr_in` for 127.0.0.1:`port`. `sin_port`/`sin_addr` are NETWORK byte
/// order (unlike `landlock_net_port_attr.port`, which is host order).
fn sockaddr_localhost(port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
        },
        sin_zero: [0; 8],
    }
}

/// socket(AF_INET, `ty`) + connect/bind (per `probe`) against 127.0.0.1:`port`.
/// Returns `Ok(())` on success or `Err(errno)` — Landlock denials surface as
/// EACCES on the connect/bind itself (socket creation is never restricted). Raw
/// libc so the forked, restricted child stays on plain syscalls.
enum SockProbe {
    Connect,
    Bind,
}
fn sock_probe(ty: libc::c_int, probe: SockProbe, port: u16) -> Result<(), i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, ty, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
    }
    let addr = sockaddr_localhost(port);
    let addr_ptr = &addr as *const libc::sockaddr_in as *const libc::sockaddr;
    let addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        match probe {
            SockProbe::Connect => libc::connect(fd, addr_ptr, addr_len),
            SockProbe::Bind => libc::bind(fd, addr_ptr, addr_len),
        }
    };
    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
    unsafe { libc::close(fd) };
    if rc == 0 {
        Ok(())
    } else {
        Err(err)
    }
}

/// TCP connect to a live 127.0.0.1 listener.
fn tcp_connect(port: u16) -> Result<(), i32> {
    sock_probe(libc::SOCK_STREAM, SockProbe::Connect, port)
}

/// TCP bind of a fresh socket to 127.0.0.1:`port`.
fn tcp_bind(port: u16) -> Result<(), i32> {
    sock_probe(libc::SOCK_STREAM, SockProbe::Bind, port)
}

/// UDP control probe: bind an ephemeral port, then connect() (which for UDP just
/// sets the default peer). Both must succeed under any Landlock net plan — the LSM
/// governs TCP only.
fn udp_bind_and_connect(peer_port: u16) -> Result<(), i32> {
    sock_probe(libc::SOCK_DGRAM, SockProbe::Bind, 0)?;
    sock_probe(libc::SOCK_DGRAM, SockProbe::Connect, peer_port)
}

/// Reap a child; return its exit code (None if signalled).
fn reap(pid: i32) -> Option<i32> {
    reap_within(pid, wait_limit(), "waiting for the Landlock-restricted child").code()
}

/// Minimal self-cleaning temp dir (avoids a dev-dep on `tempfile`; mirrors the
/// helper in kernel_integration.rs).
struct TempDir {
    path: String,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let uniq = format!(
            "{base}/{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::fs::create_dir_all(&uniq).unwrap();
        TempDir { path: uniq }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
