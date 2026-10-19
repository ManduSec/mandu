//! clone_filter_integration — exec-routing.md §7.5 gap (d), closed
//! 2026-10-03: under a secret policy no process in the agent's tree can make
//! a SIBLING of itself, so every process a holder starts is its child and
//! the lineage walk and the orphan backstop see it.
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! (an unprivileged user + pid namespace). A host where the seccomp listener
//! cannot be installed SKIPs; a missing `python3` or `node` SKIPs its leg.
//!
//!   (a) `clone(CLONE_PARENT)` answers EPERM, in the tree's root and in a
//!       process deeper in the tree; the same call outside the filter makes
//!       a sibling (the control: the test process reaps it);
//!   (b) `clone3` answers ENOSYS whatever its arguments, and what falls back
//!       from it still works: a plain `clone` and `fork`, a shell's
//!       subshells, pipelines, background jobs and command substitutions,
//!       Python's `subprocess` (vfork and fork paths), `os.posix_spawn` and
//!       threads (glibc 2.34+ tries `clone3` first for both), Node's
//!       `child_process` (sync and async), a worker thread and the libuv
//!       thread pool;
//!   (c) Go (`tests/fixtures/clone-probe.go`, built here with `go build`,
//!       static and, where cgo builds, with its threads made through
//!       glibc's pthread_create): the runtime's raw thread clones, os/exec
//!       in each shape (the clone(CLONE_VFORK|CLONE_VM|CLONE_PIDFD) path,
//!       with a pidfd held exactly when one is held outside the filter),
//!       loopback TCP, HTTP and a unix socket all work; a raw
//!       clone(CLONE_PARENT), clone3(CLONE_PARENT) and Go's own
//!       `Cloneflags: CLONE_PARENT` spawn are refused, and Go's one clone3
//!       path (`SysProcAttr.UseCgroupFD`) fails with ENOSYS, since Go has no
//!       fallback there (the cost, exec-routing.md §7.5 gap (d)). A host
//!       without `go` SKIPs it.
//!
//! The filter is the guard's real program (`install_guard_filter_self`),
//! served by the real supervisor loop.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, pipe, readable_within, reap_within, run_tag, socketpair, wait_limit};

use std::sync::Arc;

use net_supervisor::guard::{parse_rules, GuardPolicy, NoResolver};
use net_supervisor::guard_filter::{CLONE_PARENT, SYS_CLONE3};
use net_supervisor::guard_kernel::{
    hand_listener, install_guard_filter_self, receive_listener, run_guard_supervisor, FilterTraps,
    GuardConfig,
};

const EXIT_NO_SECCOMP: i32 = 91;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn reap(pid: i32) -> Option<i32> {
    if in_test_process() {
        return reap_within(pid, wait_limit(), "waiting for a child the test forked").code();
    }
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
        return None;
    }
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    }
}

/// The guard's traps under a secret policy (the only posture with holders).
fn secret_traps() -> FilterTraps {
    FilterTraps { open: true, secrets: true, ..Default::default() }
}

/// A secret policy with no secrets: the guard serves the tree's opens and
/// execs, nothing is a holder (the refusal does not depend on one).
fn secret_cfg(dir: &std::path::Path) -> GuardConfig {
    secret_cfg_allowing(dir, &[])
}

/// `secret_cfg` with these connects allowed (the Go leg's loopback).
fn secret_cfg_allowing(dir: &std::path::Path, allow: &[&str]) -> GuardConfig {
    let policy = dir.join("policy.json");
    std::fs::write(&policy, r#"{"agentExe":""}"#).unwrap();
    let rules: Vec<String> = allow.iter().map(|s| s.to_string()).collect();
    let mut cfg = GuardConfig::new(Arc::new(GuardPolicy::new(parse_rules(&rules).unwrap())), Arc::new(NoResolver));
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(&policy).unwrap()));
    cfg
}

/// Run `body` in a forked child under the guard's filter (secret traps),
/// served by the real supervisor; the child's exit code (None: killed), or
/// None to SKIP.
fn guarded(cfg: GuardConfig, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    let (sup, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe { libc::close(sup) };
        let listener = match install_guard_filter_self(secret_traps()) {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if !hand_listener(child_sock, listener, true) {
            unsafe {
                libc::close(listener);
                libc::_exit(92)
            };
        }
        unsafe {
            libc::close(listener);
            libc::close(child_sock);
        }
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

/// `clone(flags)` with no new stack (a fork: the child continues on a copy
/// of this stack). The child `_exit`s at once with `child_code`. The
/// parent's return: the child's pid, or `-errno`.
fn raw_clone(flags: u64, child_code: i32) -> i64 {
    // SAFETY: clone without CLONE_VM and without a stack is a fork; the
    // child only calls _exit.
    let r = unsafe { libc::syscall(libc::SYS_clone, flags, 0u64, 0u64, 0u64, 0u64) };
    if r == 0 {
        unsafe { libc::_exit(child_code) };
    }
    if r < 0 {
        -(errno() as i64)
    } else {
        r
    }
}

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
}

/// `clone3` with these flags (no stack: a fork); the child `_exit`s at once.
/// The parent's return: the child's pid, or `-errno`.
fn raw_clone3(flags: u64) -> i64 {
    let args = CloneArgs { flags, exit_signal: libc::SIGCHLD as u64, ..Default::default() };
    // SAFETY: clone3 without a stack is a fork; the child only calls _exit.
    let r = unsafe { libc::syscall(SYS_CLONE3 as libc::c_long, &args as *const CloneArgs, std::mem::size_of::<CloneArgs>()) };
    if r == 0 {
        unsafe { libc::_exit(0) };
    }
    if r < 0 {
        -(errno() as i64)
    } else {
        r
    }
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("mandu-clone-{tag}-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// (a): a sibling is refused in the tree, and made outside it.
#[test]
#[ignore]
fn a_clone_parent_sibling_is_refused_in_the_agent_tree() {
    let sigchld = libc::SIGCHLD as u64;
    let parent = CLONE_PARENT as u64;
    // The control, outside the filter: a process's CLONE_PARENT child is
    // this test process's child (its sibling), which this process reaps.
    let (r, w) = pipe();
    let p = unsafe { libc::fork() };
    assert!(p >= 0);
    if p == 0 {
        let sib = raw_clone(parent | sigchld, 5);
        let b = (sib as i32).to_ne_bytes();
        unsafe { libc::write(w, b.as_ptr() as *const libc::c_void, 4) };
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(w) };
    let mut b = [0u8; 4];
    readable_within(r, p, wait_limit(), "waiting for the control child to report its sibling's pid");
    assert_eq!(unsafe { libc::read(r, b.as_mut_ptr() as *mut libc::c_void, 4) }, 4);
    unsafe { libc::close(r) };
    assert_eq!(reap(p), Some(0));
    let sib = i32::from_ne_bytes(b);
    assert!(sib > 0, "the control's CLONE_PARENT clone failed outside the filter (errno {})", -sib);
    assert_eq!(reap(sib), Some(5), "outside the filter a CLONE_PARENT child is its creator's sibling");

    let dir = scratch("sibling");
    let got = guarded(secret_cfg(&dir), move || {
        // The tree's root: refused, in each shape.
        if raw_clone(parent | sigchld, 0) != -(libc::EPERM as i64) {
            return 10;
        }
        if raw_clone(parent, 0) != -(libc::EPERM as i64) {
            return 11;
        }
        // Junk in the high word does not hide the flag.
        if raw_clone((0xdead_beef_u64 << 32) | parent | sigchld, 0) != -(libc::EPERM as i64) {
            return 12;
        }
        // clone3: ENOSYS whatever it asks for, CLONE_PARENT or not.
        if raw_clone3(parent) != -(libc::ENOSYS as i64) {
            return 13;
        }
        if raw_clone3(0) != -(libc::ENOSYS as i64) {
            return 14;
        }
        // SAFETY: a null clone3 argument; the filter answers before the kernel reads it.
        if unsafe { libc::syscall(SYS_CLONE3 as libc::c_long, 0usize, 0usize) } != -1 || errno() != libc::ENOSYS {
            return 15;
        }
        // A plain clone and fork still make children.
        let c = raw_clone(sigchld, 7);
        if c <= 0 || reap(c as i32) != Some(7) {
            return 16;
        }
        let f = unsafe { libc::fork() };
        if f == 0 {
            unsafe { libc::_exit(8) };
        }
        if f <= 0 || reap(f) != Some(8) {
            return 17;
        }
        // Deeper in the tree (the filter is inherited): refused too.
        let g = unsafe { libc::fork() };
        if g == 0 {
            let ok = raw_clone(parent | sigchld, 0) == -(libc::EPERM as i64) && raw_clone3(parent) == -(libc::ENOSYS as i64);
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        if g <= 0 || reap(g) != Some(0) {
            return 18;
        }
        0
    });
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { return };
    assert_eq!(code, Some(0), "check {} (10 + index) failed under the guard's filter", code.unwrap_or(-1));
}

/// Python: a sibling refused, clone3 ENOSYS, and every way Python starts a
/// process or a thread still works. Prints `py-ok`.
const PY: &str = r#"
import ctypes, errno, os, platform, subprocess, sys, threading
from concurrent.futures import ThreadPoolExecutor
libc = ctypes.CDLL(None, use_errno=True)
L = ctypes.c_long
SYS_clone = {"x86_64": 56, "aarch64": 220}[platform.machine()]
r = libc.syscall(L(SYS_clone), L(0x8000 | 17), L(0), L(0), L(0), L(0))
if r == 0:
    os._exit(0)
assert r == -1 and ctypes.get_errno() == errno.EPERM, ("clone(CLONE_PARENT)", r, ctypes.get_errno())
r = libc.syscall(L(435), L(0), L(0))
assert r == -1 and ctypes.get_errno() == errno.ENOSYS, ("clone3", r, ctypes.get_errno())
assert subprocess.run(["true"]).returncode == 0
assert subprocess.run(["sh", "-c", "exit 3"], close_fds=False).returncode == 3
assert subprocess.run(["true"], preexec_fn=lambda: None).returncode == 0
assert subprocess.check_output(["echo", "piped"]).strip() == b"piped"
pid = os.posix_spawn("/bin/sh", ["sh", "-c", "exit 4"], os.environ)
assert os.waitpid(pid, 0)[1] >> 8 == 4
pid = os.fork()
if pid == 0:
    os._exit(6)
assert os.waitpid(pid, 0)[1] >> 8 == 6
seen = []
ts = [threading.Thread(target=lambda i=i: seen.append(i)) for i in range(8)]
[t.start() for t in ts]
[t.join() for t in ts]
assert sorted(seen) == list(range(8))
with ThreadPoolExecutor(4) as ex:
    assert list(ex.map(lambda x: x * x, range(6))) == [0, 1, 4, 9, 16, 25]
print("py-ok", platform.libc_ver())
"#;

/// Node: child_process (sync, async, a shell), a worker thread, the libuv
/// thread pool (fs). Prints `node-ok`.
const NODE: &str = r#"
const cp = require("child_process");
const { Worker } = require("worker_threads");
const fail = (n, why) => { console.error("node check", n, why); process.exit(n); };
if (cp.execFileSync("sh", ["-c", "echo n"]).toString().trim() !== "n") fail(2, "execFileSync");
if (cp.spawnSync("true").status !== 0) fail(3, "spawnSync");
const w = new Worker("require('worker_threads').parentPort.postMessage(42)", { eval: true });
w.on("error", (e) => fail(4, e));
w.on("message", (m) => {
  if (m !== 42) fail(5, m);
  cp.exec("echo async", (e, out) => {
    if (e || out.trim() !== "async") fail(6, e);
    const c = cp.spawn("sh", ["-c", "exit 7"]);
    c.on("error", (e) => fail(7, e));
    c.on("exit", (code) => {
      if (code !== 7) fail(8, code);
      require("fs").readFile("/proc/self/status", (e) => {
        if (e) fail(9, e);
        require("crypto").pbkdf2("k", "s", 1000, 32, "sha256", (e) => {
          if (e) fail(10, e);
          w.terminate().then(() => console.log("node-ok"));
        });
      });
    });
  });
});
"#;

/// The shell's own forks, then the Python and Node legs. Exit 0 = all ran;
/// 11.. a shell form, 21 Python, 31 Node.
const SH: &str = r#"
( exit 0 ) || exit 11
echo hi | cat > /dev/null || exit 12
sleep 0 & wait $! || exit 13
x=$(echo sub); [ "$x" = sub ] || exit 14
{ ( true ) & } ; wait || exit 15
if [ "$1" = 1 ]; then python3 -c "$3" || exit 21; fi
if [ "$2" = 1 ]; then node -e "$4" || exit 31; fi
exit 0
"#;

fn have(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// (b): what falls back from clone3 still works, in a shell, Python and Node.
#[test]
#[ignore]
fn ordinary_forks_spawns_and_threads_work_under_the_sibling_refusal() {
    let py = have("python3");
    let node = have("node");
    if !py {
        eprintln!("SKIP: python3 is not installed (the Python leg)");
    }
    if !node {
        eprintln!("SKIP: node is not installed (the Node leg)");
    }
    let dir = scratch("spawn");
    let out = dir.join("out.txt");
    let sh = std::ffi::CString::new("/bin/sh").unwrap();
    let args: Vec<std::ffi::CString> = [
        "sh",
        "-c",
        SH,
        "sh",
        if py { "1" } else { "0" },
        if node { "1" } else { "0" },
        PY,
        NODE,
    ]
    .iter()
    .map(|a| std::ffi::CString::new(*a).unwrap())
    .collect();
    let out_c = std::ffi::CString::new(out.to_str().unwrap()).unwrap();
    // PATH for python3 / node / true / sleep; nothing else of the test's env.
    let path = std::ffi::CString::new(format!("PATH={}", std::env::var("PATH").unwrap_or_default())).unwrap();
    let got = guarded(secret_cfg(&dir), move || {
        let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
        argv.push(std::ptr::null());
        let envp = [path.as_ptr(), std::ptr::null()];
        // stdout and stderr to the report file (opened before the exec: the
        // guard performs the open).
        let fd = unsafe { libc::open(out_c.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o600) };
        if fd < 0 {
            return 2;
        }
        unsafe {
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            libc::execve(sh.as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
        3
    });
    let report = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let Some(code) = got else { return };
    assert_eq!(code, Some(0), "a fork, spawn or thread failed under the guard's filter:\n{report}");
    if py {
        assert!(report.contains("py-ok"), "{report}");
    }
    if node {
        assert!(report.contains("node-ok"), "{report}");
    }
}

/// `go` runs here (`go version`; `go` has no `--version`).
fn have_go() -> bool {
    std::process::Command::new("go")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Build `tests/fixtures/clone-probe.go` into `out` (`cgo`: "0" or "1").
/// No module and no dependency, so nothing is downloaded; GOTOOLCHAIN=local
/// keeps `go` from fetching a toolchain.
fn build_go_probe(dir: &std::path::Path, out: &std::path::Path, cgo: &str) {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/clone-probe.go");
    let mut cmd = std::process::Command::new("go");
    cmd.arg("build").arg("-o").arg(out).arg(&src);
    cmd.env("GOTOOLCHAIN", "local").env("CGO_ENABLED", cgo).env("GOFLAGS", "");
    if std::env::var_os("GOCACHE").is_none() && std::env::var_os("HOME").is_none() {
        cmd.env("GOCACHE", dir.join("gocache"));
    }
    let o = cmd.output().expect("go build");
    assert!(
        o.status.success(),
        "go build (CGO_ENABLED={cgo}) of the probe failed:\n{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
}

/// The probe's `pidfd=` line (whether Go holds a pidfd for a child).
fn pidfd_line(report: &str) -> Option<&str> {
    report.lines().find(|l| l.starts_with("pidfd="))
}

/// (c): a Go program under the sibling refusal, beside the same binary
/// outside it.
#[test]
#[ignore]
fn go_threads_spawns_and_sockets_work_under_the_sibling_refusal() {
    if !have_go() {
        eprintln!("SKIP: go is not installed (the Go leg)");
        return;
    }
    let dir = scratch("go");
    let cgo_default = std::process::Command::new("go")
        .args(["env", "CGO_ENABLED"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "1")
        .unwrap_or(false);
    let mut variants = vec![("static", "0")];
    if cgo_default {
        variants.push(("cgo", "1"));
    } else {
        eprintln!("SKIP: cgo cannot build here (no C compiler): the static Go leg only");
    }
    for (name, cgo) in variants {
        let bin = dir.join(format!("clone-probe-{name}"));
        build_go_probe(&dir, &bin, cgo);
        // The control: the same binary outside the filter.
        let control = std::process::Command::new(&bin).arg("open").env("TMPDIR", &dir).output().expect("run the Go probe");
        let control_out = String::from_utf8_lossy(&control.stdout).into_owned();
        assert!(
            control.status.success() && control_out.contains("go-ok"),
            "the Go probe ({name}) fails outside the filter:\n{control_out}{}",
            String::from_utf8_lossy(&control.stderr)
        );

        let out = dir.join(format!("out-{name}.txt"));
        let bin_c = std::ffi::CString::new(bin.to_str().unwrap()).unwrap();
        let args = [bin_c.clone(), std::ffi::CString::new("refused").unwrap()];
        let out_c = std::ffi::CString::new(out.to_str().unwrap()).unwrap();
        let path = std::ffi::CString::new(format!("PATH={}", std::env::var("PATH").unwrap_or_default())).unwrap();
        let tmp = std::ffi::CString::new(format!("TMPDIR={}", dir.display())).unwrap();
        // Loopback only: the probe's TCP and HTTP legs; nothing else connects.
        let cfg = secret_cfg_allowing(&dir, &["127.0.0.0/8:*"]);
        let got = guarded(cfg, move || {
            let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
            argv.push(std::ptr::null());
            let envp = [path.as_ptr(), tmp.as_ptr(), std::ptr::null()];
            let fd = unsafe { libc::open(out_c.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o600) };
            if fd < 0 {
                return 2;
            }
            unsafe {
                libc::dup2(fd, 1);
                libc::dup2(fd, 2);
                libc::execve(bin_c.as_ptr(), argv.as_ptr(), envp.as_ptr());
            }
            3
        });
        let report = std::fs::read_to_string(&out).unwrap_or_default();
        let Some(code) = got else {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        };
        assert_eq!(code, Some(0), "the Go probe ({name}) failed under the guard's filter:\n{report}");
        assert!(report.contains("go-ok"), "{report}");
        for want in ["clone_parent=EPERM", "clone3_parent=ENOSYS", "exec_clone_parent=EPERM"] {
            assert!(report.contains(want), "the Go probe ({name}) under the filter: no `{want}`\n{report}");
        }
        // The filter does not push Go off its pidfd path: Go holds a pidfd
        // for its child under the filter exactly when it does outside.
        assert_eq!(
            pidfd_line(&report),
            pidfd_line(&control_out),
            "Go's pidfd use differs under the filter ({name}):\n{report}\n--- outside:\n{control_out}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
