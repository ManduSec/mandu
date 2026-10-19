//! Regression test for the ETXTBSY fork race that made the kernel routing test
//! flaky (`execve_routes_to_agentshell_by_default_and_humanshell_when_needed`,
//! about 1 CI run in 22; see `tests/support/exec_script.rs`). Default features,
//! no privilege: it needs only fork and exec.
//!
//!   1. The mechanism, deterministically: a child forked while this process
//!      holds a write descriptor to a script keeps the file busy, and exec of it
//!      fails ETXTBSY until that child exits.
//!   2. Under a fork storm (threads forking children that linger, as the
//!      supervisor's sandbox children do), scripts written with std::fs hit
//!      ETXTBSY (the control: the storm reproduces the race), and scripts
//!      written with `write_exec_script` never do.

#[path = "support/exec_script.rs"]
mod exec_script;
use exec_script::write_exec_script;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The two tests fork; one at a time, so neither's children hold the other's
/// descriptors.
static SERIAL: Mutex<()> = Mutex::new(());

const SCRIPT: &[u8] = b"#!/bin/sh\nexit 42\n";

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("mandu-exec-script-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Exec `path` and return its exit code, or the exec's errno.
fn run(path: &Path) -> Result<i32, i32> {
    match std::process::Command::new(path).status() {
        Ok(s) => Ok(s.code().expect("script exits normally")),
        Err(e) => Err(e.raw_os_error().unwrap_or(-1)),
    }
}

/// The way the tests wrote scripts before: a write descriptor open in THIS process.
fn naive_write(path: &Path) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(SCRIPT).unwrap();
    f.set_permissions(std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn a_forked_child_holding_the_write_descriptor_makes_exec_fail_etxtbsy() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch("held");
    let p = dir.join("probe.sh");

    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(SCRIPT).unwrap();
    f.set_permissions(std::fs::Permissions::from_mode(0o755)).unwrap();
    // A child forked now inherits the write descriptor (O_CLOEXEC drops it only
    // at exec). It lingers until we close the pipe, as a sandbox child lingers in
    // its namespace setup.
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let holder = unsafe { libc::fork() };
    assert!(holder >= 0);
    if holder == 0 {
        let mut b = 0u8;
        unsafe {
            libc::close(fds[1]);
            libc::read(fds[0], (&mut b as *mut u8).cast(), 1);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(fds[0]) };
    drop(f); // this process no longer writes the file; the child still does

    assert_eq!(run(&p), Err(libc::ETXTBSY), "a writer anywhere makes exec ETXTBSY");

    unsafe { libc::close(fds[1]) };
    let mut st = 0;
    assert_eq!(unsafe { libc::waitpid(holder, &mut st, 0) }, holder);
    assert_eq!(run(&p), Ok(42), "the writer gone, the same file runs");

    // The helper leaves no writer behind, so a child forked right after it
    // (or at any time) cannot make the file busy.
    write_exec_script(&p, SCRIPT).unwrap();
    let after = unsafe { libc::fork() };
    assert!(after >= 0);
    if after == 0 {
        unsafe {
            libc::usleep(200_000);
            libc::_exit(0);
        }
    }
    assert_eq!(run(&p), Ok(42));
    assert_eq!(unsafe { libc::waitpid(after, &mut st, 0) }, after);
    assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o755);

    // Errors come back as the failing step's errno.
    let missing = dir.join("no-such-dir").join("x.sh");
    assert_eq!(
        write_exec_script(&missing, SCRIPT).unwrap_err().raw_os_error(),
        Some(libc::ENOENT)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_exec_script_never_loses_to_a_fork_storm() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch("storm");

    // Forkers: each child keeps a copy of every descriptor for 5 ms, the way the
    // supervisor's sandbox child keeps one through unshare + mounts.
    let stop = Arc::new(AtomicBool::new(false));
    let forkers: Vec<_> = (0..8)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let pid = unsafe { libc::fork() };
                    if pid == 0 {
                        unsafe {
                            libc::usleep(5_000);
                            libc::_exit(0);
                        }
                    }
                    if pid > 0 {
                        let mut st = 0;
                        unsafe { libc::waitpid(pid, &mut st, 0) };
                    }
                }
            })
        })
        .collect();

    // Control: the storm reproduces the race with the old way of writing.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut naive_runs = 0;
    let mut busy = 0;
    while busy < 5 && Instant::now() < deadline {
        let p = dir.join(format!("naive-{naive_runs}.sh"));
        naive_write(&p);
        naive_runs += 1;
        match run(&p) {
            Ok(42) => {}
            Err(e) if e == libc::ETXTBSY => busy += 1,
            other => panic!("naive script: unexpected {other:?}"),
        }
    }

    // The helper, twice as many runs as the control needed for 5 hits, so a
    // helper no better than std::fs would expect about 10 failures here.
    let helper_runs = (2 * naive_runs).max(300);
    let mut helper_fail = Vec::new();
    for i in 0..helper_runs {
        let p = dir.join(format!("helper-{i}.sh"));
        write_exec_script(&p, SCRIPT).unwrap();
        let r = run(&p);
        if r != Ok(42) {
            helper_fail.push((i, r));
        }
    }

    stop.store(true, Ordering::Relaxed);
    for t in forkers {
        t.join().unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("fork storm: naive {busy} ETXTBSY in {naive_runs} runs; helper {helper_runs} runs, {} failed", helper_fail.len());
    assert!(
        busy >= 5,
        "control: the fork storm must reproduce ETXTBSY with std::fs writes (saw {busy} in {naive_runs} runs)"
    );
    assert!(helper_fail.is_empty(), "write_exec_script lost the race: {helper_fail:?}");
}
