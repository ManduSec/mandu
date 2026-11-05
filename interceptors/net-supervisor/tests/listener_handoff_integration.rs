//! Kernel integration test: the guard fails closed, and promptly, when it
//! cannot take over its tracee's seccomp listener (packaging.md §3.1,
//! 2026-10-24).
//!
//! Docker's default seccomp profile refuses `pidfd_getfd` to a process
//! without CAP_SYS_PTRACE, and the guard copies the child's listener out with
//! `pidfd_getfd` (guard_kernel.rs `receive_listener`). The child then waits
//! for the guard's one-byte ack; the guard reaped it with the socket still
//! open, so both waited forever: `mandu demo` and every wrapped launch hung
//! in a default Docker container. This test runs the real bin under a filter
//! that answers `pidfd_getfd` with EPERM, as that profile does, and asserts
//! the guard exits 71 (fail-closed setup) within the time limit, names
//! `pidfd_getfd`, and never runs its target, with and without
//! `--skip-unsupported` (the target is not run unguarded: the copy failed
//! after the trap was installed, which is no "kernel without the feature").
//!
//! `#[ignore]`d, kernel feature only, like the crate's other kernel tests:
//!   scripts/kernel-tests.sh   (or: cargo test -p net-supervisor --features kernel -- --ignored)
//! Needs only `no_new_privs` (no root, no userns). Self-SKIPs where seccomp
//! user notification is unavailable (the guard then exits 71 for that reason
//! before any copy, which this test cannot tell apart from the fix).

#![cfg(all(feature = "kernel", target_os = "linux"))]

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SYS_PIDFD_GETFD: u32 = 438; // the same number on x86_64 and aarch64
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

/// Install, in the calling process, a filter that answers `pidfd_getfd`
/// with EPERM and allows everything else. Runs between fork and exec.
fn refuse_pidfd_getfd() -> std::io::Result<()> {
    let filter = [
        // A = seccomp_data.nr
        libc::sock_filter { code: 0x20, jt: 0, jf: 0, k: 0 },
        // if A == pidfd_getfd: fall through to EPERM, else skip to ALLOW
        libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: SYS_PIDFD_GETFD },
        libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: SECCOMP_RET_ERRNO | libc::EPERM as u32 },
        libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW },
    ];
    let prog = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_ptr() as *mut libc::sock_filter };
    // SAFETY: prctl with integer arguments, then a filter over a stack array
    // that outlives the call.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog as *const libc::sock_fprog) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Does the guard supervise at all here (no extra filter)? Its own exit 0
/// around `true` says so; anything else is a host without user notification.
fn guard_works(bin: &str) -> bool {
    Command::new(bin).args(["--", "true"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}

fn run_refused(bin: &str, skip_unsupported: bool, marker: &std::path::Path) -> (Option<i32>, String) {
    let mut cmd = Command::new(bin);
    if skip_unsupported {
        cmd.arg("--skip-unsupported");
    }
    cmd.args(["--", "sh", "-c", &format!("touch '{}'", marker.display())]);
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    // SAFETY: the closure only makes system calls (prctl) between fork and exec.
    unsafe { cmd.pre_exec(refuse_pidfd_getfd) };
    let mut child = cmd.spawn().expect("spawn mandu-net-guard");
    let start = Instant::now();
    let limit = Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().expect("wait") {
            let mut err = String::new();
            use std::io::Read;
            child.stderr.take().unwrap().read_to_string(&mut err).ok();
            return (status.code(), err);
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("mandu-net-guard hung for {limit:?} when pidfd_getfd was refused (the listener hand-off deadlock)");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore]
fn guard_fails_closed_without_hanging_when_pidfd_getfd_is_refused() {
    let bin = env!("CARGO_BIN_EXE_mandu-net-guard");
    if !guard_works(bin) {
        println!("SKIP: the guard cannot supervise on this host (no seccomp user notification)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("mandu-handoff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for skip in [false, true] {
        let marker = dir.join(format!("ran-{skip}"));
        let (code, err) = run_refused(bin, skip, &marker);
        assert_eq!(code, Some(71), "fail-closed setup exit (skip_unsupported={skip}); stderr: {err}");
        assert!(err.contains("pidfd_getfd"), "names what the container refused (skip_unsupported={skip}): {err}");
        assert!(err.contains("fail-closed"), "says it failed closed: {err}");
        assert!(!marker.exists(), "the target never ran (skip_unsupported={skip})");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
