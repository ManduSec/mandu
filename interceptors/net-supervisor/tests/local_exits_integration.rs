//! local_exits_integration — confidentiality plan 13 §9 R4 (b) at the guard:
//! the exits a holder's write reaches as a path (`local_exits`).
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! (an unprivileged user namespace), or the kernel lane of
//! `scripts/ci/vm-run.sh`. A host where the seccomp listener cannot be
//! installed SKIPs.
//!
//! Before: a process holding a secret could write it onto a network or FUSE
//! mount (a send at the VFS, no `connect()`), into a file other local users
//! read (the umask's 0644), into a device (a serial port, `/dev/fuse`), and a
//! later `chmod` or ACL opened a derived copy to everyone. Each assertion
//! below failed on the code before. The guarded root plays the agent; each
//! process it forks stands for a tool call. Asserted, each with its control:
//!
//!   (M) a holder's create on a mount that leaves the machine, and its
//!       append to a file there, are refused before anything lands (no file,
//!       no canary); a process already writing there when it reads the
//!       secret has the raw open refused; bound to `mount:<fstype>:<source>`,
//!       the holder writes. A non-holder writes there freely. No FUSE server
//!       is at hand, so the test counts `/dev/shm` as remote by its device
//!       (`GuardConfig::extra_remote_devs`); the file-system table itself is
//!       unit-tested (`local_exits`);
//!   (P) a holder's new file has no group or other bits, an existing one it
//!       appends to and one it held open before its taint are narrowed to
//!       0600; a `chmod` that opens the derived file to others, and a POSIX
//!       ACL on it, are refused, by the holder and by a later process alike;
//!       a non-holder's file keeps the umask's 0644 and its chmod runs;
//!       (2026-10-04) a descriptor number the process swaps between a file
//!       it writes and a file it only reads while it reads the secret never
//!       gets the read-only file narrowed (the sweep judges a copy);
//!   (D) a holder writes to `/dev/null` but not to `/dev/fuse`, and a process
//!       holding `/dev/fuse` open has its raw open refused; a non-holder
//!       opens `/dev/fuse`;
//!   (X) the display server's socket (a pathname `X11-unix` socket and an
//!       abstract one, both on the launch's Unix allow-list as the launcher
//!       lists the displays) is refused to a holder unless bound, and open to
//!       a non-holder.
//!
//! The leftovers closed 2026-10-04 (plan 13 §9 R4 (b)):
//!
//!   (O) an overlay whose upper layer is on a mount that leaves the machine
//!       is that mount: a holder's create and mkdir through it are refused,
//!       an overlay whose upper is local takes the holder's write, one whose
//!       upper cannot be found any more is refused (named by the overlay),
//!       and bound to the upper's mount the holder writes through it. A
//!       non-holder writes through each. The overlays are mounted in the
//!       guard's own namespace (the test process's, root in the user
//!       namespace `scripts/kernel-tests.sh` makes) and seen from a user +
//!       mount namespace of the tracee's own, as the launcher's wrap makes;
//!       (2026-10-09, P0 5d) the unfound upper is refused though the tree
//!       laid a local directory at its path in its own view. SKIPs where no
//!       overlay can be mounted.
//!   (O2) P0 5d (2026-10-09): an overlay the tree mounts in a user namespace
//!       of its own is remote whatever its `upperdir=` names: one whose
//!       remote upper a tmpfs of the tree's shadows, one whose remote upper
//!       was unmounted from under it (both paths resolve to a local
//!       directory in the guard's view and the tracee's: the control's write
//!       lands on the remote mount), and one over a local upper (the
//!       fail-closed cost) refuse a holder's create and mkdir, even bound to
//!       the upper's real mount; bound to the overlay itself
//!       (`mount:overlay:<source>`) the holder writes through each. Red on
//!       the code before: the shadowed and detached writes landed remote.
//!   (N) a holder's names and attributes on such a mount: mkdir, symlink,
//!       hard link, rename, mknod, unlink, truncate, chmod and setxattr are
//!       refused and nothing changes there; the same calls on a local disk
//!       run; bound, its mkdir runs; a non-holder's run;
//!   (R) a writable descriptor passed over `SCM_RIGHTS`: the agent's (it holds
//!       nothing; a socket pair makes any other sender a holder, D2) pass of a
//!       file on such a mount, or of `/dev/fuse`, to a holder is
//!       refused at the send (the holder never calls open); a local file
//!       passes; a process that received such a descriptor (or has one
//!       queued) before it reads a secret has the raw open refused; in a
//!       network namespace of its own the pass is refused outright.
//!
//! P0 (2026-10-07):
//!
//!   (B) a holder's socket file (a pathname Unix `bind`) on such a mount is
//!       refused with no write-protect list (`bind` was trapped only with
//!       one); on a local disk it binds; a non-holder binds on the mount.
//!   (T) a holder's timestamps and owner on such a mount (`utimensat`,
//!       `futimens`, the `chown` family, x86_64's `utime`, `utimes`,
//!       `futimesat`; by path, by a read-only descriptor, and without
//!       following) are refused and leave the stamp in place; on a local
//!       disk they run; bound, they run there; a non-holder's run.
//!
//! Lookups and read offsets, closed 2026-10-07 (plan 13 §4.9, "refuse raw if
//! visible"):
//!
//!   (V) a reader's raw open is answered with the twin (and an event) while
//!       a mount that sees lookups is visible in its mount namespace,
//!       neither trusted for lookups (policy.yaml `remote_mounts.
//!       trust_lookups`, the policy file's `trustLookups`) nor bound; the
//!       arbiter unable to say the bindings, likewise; bound or trusted, or
//!       with no such mount, the reader gets the real file (trusted, its
//!       writes there are still refused); a mount made in the reader's
//!       namespace after the guard first looked is seen at the next raw
//!       open, and its removal too. The other cases trust `/dev/shm`'s own
//!       mount (`shm_trust`), so their raw opens still test the write gate.
//!
//! The real file itself (2026-10-10):
//!
//!   (W) a reader's truncating write-open of the real file truncates it, as
//!       the kernel's would, after the open's refusals: a shorter rewrite
//!       (`aws configure`) leaves no stale tail (the guard dropped the
//!       `O_TRUNC` before).

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, readable_within, reap_within, run_tag, socketpair, wait_limit};

use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mandu_arbiter::mock::{op_handler, MockArbiter};
use net_supervisor::guard::{parse_rules, GuardPolicy, NoResolver};
use net_supervisor::guard_kernel::{
    hand_listener, install_guard_filter_self, receive_listener, run_guard_supervisor, FilterTraps,
    GuardConfig,
};

const EXIT_NO_SECCOMP: i32 = 91;
const CANARY: &str = "R4B-CANARY-5521";

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

fn fork_run(f: impl FnOnce() -> i32) -> i32 {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let code = f();
        unsafe { libc::_exit(code) };
    }
    pid
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

fn errno_of<T>(r: std::io::Result<T>) -> i32 {
    match r {
        Ok(_) => 0,
        Err(e) => e.raw_os_error().unwrap_or(-1),
    }
}

/// The secret, its twin, and the guard's policy file; the guarded root is
/// the agent (`agentExe` = this test binary).
struct Fixture {
    dir: PathBuf,
    secret: PathBuf,
    policy: PathBuf,
}

/// The mounts of `/dev/shm`'s file system as `trustLookups` entries: the
/// cases that count it remote by its device test the write gate, so its
/// being visible must not withhold their raw opens (plan 13 §4.9; the (V)
/// cases below test that). Empty where there is no such mount.
fn shm_trust() -> Vec<(String, String)> {
    let Ok(dev) = std::fs::metadata("/dev/shm").map(|m| m.dev()) else { return Vec::new() };
    let mi = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    net_supervisor::visible_mounts::parse_rows(&mi).into_iter().filter(|r| r.dev == dev).map(|r| (r.row.mount_point, r.row.fstype)).collect()
}

impl Fixture {
    fn new(tag: &str, unix_policy: Option<String>) -> Fixture {
        Fixture::build(tag, unix_policy, shm_trust())
    }

    /// The fixture with exactly these `trustLookups` (mount point, type).
    fn build(tag: &str, unix_policy: Option<String>, trust: Vec<(String, String)>) -> Fixture {
        let dir = std::env::temp_dir().join(format!("mandu-r4b-{tag}-{}", run_tag()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let secret = dir.join("secret.env");
        let twin = dir.join("twin.env");
        std::fs::write(&secret, format!("API_KEY={CANARY}\n")).unwrap();
        std::fs::write(&twin, "API_KEY=$MDU:twin\n").unwrap();
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let unix = unix_policy.map(|u| format!(r#","unixPolicy":{u}"#)).unwrap_or_default();
        let trust = serde_json::to_string(&trust.iter().map(|(m, t)| serde_json::json!({ "mount": m, "type": t })).collect::<Vec<_>>()).unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(
            &policy,
            format!(r#"{{"agentExe":"{}","ask":"never","session":"r4b","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]{unix},"trustLookups":{trust}}}"#, exe.display(), secret.display(), twin.display()),
        )
        .unwrap();
        Fixture { dir, secret, policy }
    }
    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Every opener is a reader (raw); a holder's bindings are `bindings`; a
/// holder's write is labelled, and listed by `derivedLabelsSince` as the
/// arbiter lists its derived rows (so the guard's derived index has it).
fn arbiter(bindings: Vec<String>) -> &'static MockArbiter {
    let labelled: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    MockArbiter::start(op_handler(move |op, req| match op {
        "decideSecretOpen" => Ok(serde_json::json!({ "verdict": "raw", "app": "test", "level": "no-model", "reason": "mock reader" })),
        "taintedProcessBindings" => Ok(serde_json::json!({ "tainted": true, "level": "no-model", "files": ["secret.env"], "bindings": bindings })),
        "labelWrittenPathTainted" => {
            if let Some(p) = req.get("path").and_then(|v| v.as_str()) {
                labelled.lock().unwrap().push(p.to_string());
            }
            Ok(serde_json::json!({ "labeled": true, "level": "no-model", "reason": "written by a reader" }))
        }
        "derivedLabelsSince" => {
            let rows: Vec<serde_json::Value> = labelled.lock().unwrap().iter().map(|p| serde_json::json!({ "path": p, "level": "no-model" })).collect();
            let gen = rows.len();
            Ok(serde_json::json!({ "epoch": "r4b", "gen": gen, "labels": rows }))
        }
        _ => Ok(serde_json::Value::Null),
    }))
    .leak()
}

fn cfg(fx: &Fixture, arb: &MockArbiter) -> GuardConfig {
    let specs = vec!["any:127.0.0.0/8:*".to_string()];
    let mut cfg = GuardConfig::new(Arc::new(GuardPolicy::new(parse_rules(&specs).unwrap())), Arc::new(NoResolver));
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(&fx.policy).unwrap()));
    cfg.emitter = Some(Arc::new(Mutex::new(mandu_arbiter::ArbiterClient::new(&arb.socket_path))));
    cfg.proxy_ports = vec![1];
    cfg
}

/// Run `body` in a forked child under the guard's filter (a secret policy,
/// no write-protect list: the mode and attribute calls are trapped all the
/// same), served by the real supervisor loop; its exit code, or None to SKIP.
fn guarded(cfg: GuardConfig, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    guarded_setup(cfg, || None, body)
}

/// `guarded`, with `setup` run in the child before the filter goes on (its
/// own namespaces, its mounts); `Some(code)` from it ends the child with that
/// code (`EXIT_NO_SECCOMP`: SKIP).
fn guarded_setup(cfg: GuardConfig, setup: impl FnOnce() -> Option<i32>, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    let (sup, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        close_all_but(&[child_sock]);
        unsafe { libc::umask(0o022) };
        if let Some(code) = setup() {
            unsafe { libc::_exit(code) };
        }
        let traps = FilterTraps { open: true, secrets: true, ..Default::default() };
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

fn report(p: &Path, lines: &[String]) {
    let _ = std::fs::write(p, lines.join("\n"));
}

fn read_report(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Read the secret (a holder from here on): true when the canary came back.
fn take_secret(secret: &Path) -> bool {
    std::fs::read_to_string(secret).map(|k| k.contains(CANARY)).unwrap_or(false)
}

fn mode_of(p: &Path) -> u32 {
    std::fs::metadata(p).map(|m| m.mode() & 0o7777).unwrap_or(0)
}

// ── (M) a network or FUSE mount ─────────────────────────────────────────────

/// A directory on a file system other than the fixture's (`/dev/shm`), and
/// its device, or None (SKIP) when there is none.
fn remote_dir(fx: &Fixture, tag: &str) -> Option<(PathBuf, u64)> {
    let d = PathBuf::from(format!("/dev/shm/mandu-r4b-{tag}-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok()?;
    let dev = std::fs::metadata(&d).ok()?.dev();
    if dev == std::fs::metadata(&fx.dir).ok()?.dev() {
        let _ = std::fs::remove_dir_all(&d);
        return None;
    }
    Some((d, dev))
}

/// The holder's attempts on the "remote" mount, reported.
fn run_mount_case(fx: &Fixture, remote: &Path, dev: u64, bindings: Vec<String>, out: &Path) -> Option<i32> {
    let arb = arbiter(bindings);
    let mut c = cfg(fx, arb);
    c.extra_remote_devs = vec![dev];
    let (secret, remote, out) = (fx.secret.clone(), remote.to_path_buf(), out.to_path_buf());
    guarded(c, move || {
        // The control: a process holding nothing writes there.
        let ctl = fork_run(|| errno_of(std::fs::write(remote.join("ctl.txt"), "CONTROL\n")));
        let ctl = reap(ctl).unwrap_or(-1);
        // A holder: a new file, and an append to the control's file.
        let h_out = out.with_extension("h");
        let (r2, s_out) = (remote.clone(), out.with_extension("s"));
        let sec = secret.clone();
        let h = fork_run(move || {
            if !take_secret(&sec) {
                return 3;
            }
            let create = std::fs::OpenOptions::new().write(true).create(true).open(r2.join("h.txt")).and_then(|mut f| f.write_all(CANARY.as_bytes()));
            let append = std::fs::OpenOptions::new().append(true).open(r2.join("ctl.txt")).and_then(|mut f| f.write_all(CANARY.as_bytes()));
            report(&h_out, &[format!("create={}", errno_of(create)), format!("append={}", errno_of(append))]);
            0
        });
        let h = reap(h).unwrap_or(-1);
        // A process already writing there when it reads the secret.
        let r3 = remote.clone();
        let s = fork_run(move || {
            let Ok(mut held) = std::fs::OpenOptions::new().write(true).create(true).open(r3.join("held.txt")) else { return 4 };
            let read = std::fs::read_to_string(&secret);
            if let Ok(k) = &read {
                let _ = held.write_all(k.as_bytes());
            }
            report(&s_out, &[format!("read={}", errno_of(read))]);
            0
        });
        let s = reap(s).unwrap_or(-1);
        report(&out, &[format!("ctl={ctl}"), format!("h={h}"), format!("s={s}")]);
        0
    })
    .map(|c| c.unwrap_or(-1))
}

#[test]
#[ignore]
fn a_holders_write_onto_a_mount_that_leaves_the_machine_is_refused_unless_bound() {
    let _g = serial();
    let fx = Fixture::new("mount", None);
    let Some((remote, dev)) = remote_dir(&fx, "m") else {
        eprintln!("SKIP: no second file system at /dev/shm");
        return;
    };
    // The destination the guard names this mount by, as it reads it.
    let dir = std::fs::File::open(&remote).unwrap();
    let facts = net_supervisor::local_exits::fd_fs_facts(dir.as_raw_fd(), None);
    let net_supervisor::local_exits::MountVerdict::Remote(dest) = net_supervisor::local_exits::mount_verdict(&facts, &[dev]) else { panic!("{facts:?}") };
    assert!(dest.starts_with("mount:tmpfs:"), "{dest}");

    let out = fx.file("m.txt");
    let Some(code) = run_mount_case(&fx, &remote, dev, vec!["127.0.0.2".into()], &out) else { return };
    assert_eq!(code, 0);
    let (r, h, s) = (read_report(&out), read_report(&out.with_extension("h")), read_report(&out.with_extension("s")));
    eprintln!("unbound: {r} | holder: {h} | sweep: {s}");
    assert!(r.contains("ctl=0") && r.contains("h=0") && r.contains("s=0"), "{r}");
    assert!(h.contains(&format!("create={}", libc::EACCES)), "a holder's create on the mount is refused: {h}");
    assert!(h.contains(&format!("append={}", libc::EACCES)), "a holder's append on the mount is refused: {h}");
    assert!(!remote.join("h.txt").exists(), "refused before the create: no file (no name) lands on the mount");
    assert_eq!(std::fs::read_to_string(remote.join("ctl.txt")).unwrap(), "CONTROL\n", "THE LEAK: the canary reached the mount");
    assert!(s.contains(&format!("read={}", libc::EACCES)), "a process writing onto the mount has its raw open refused: {s}");
    assert!(!std::fs::read_to_string(remote.join("held.txt")).unwrap_or_default().contains(CANARY), "THE LEAK: the held file got the canary");

    // Bound to the mount: the holder writes.
    let _ = std::fs::remove_file(remote.join("held.txt"));
    let Some(code) = run_mount_case(&fx, &remote, dev, vec![dest.clone()], &out) else { return };
    assert_eq!(code, 0);
    let h = read_report(&out.with_extension("h"));
    eprintln!("bound to {dest}: holder: {h}");
    assert!(h.contains("create=0"), "bound: the holder's create runs: {h}");
    assert!(std::fs::read_to_string(remote.join("h.txt")).unwrap_or_default().contains(CANARY), "bound: the holder really wrote the secret there");
    let _ = std::fs::remove_dir_all(&remote);
    eprintln!("R4b MOUNT PASS");
}

// ── (P) another local user ──────────────────────────────────────────────────

#[test]
#[ignore]
fn a_holders_files_are_closed_to_other_local_users() {
    use net_supervisor::xattr_change::{acl_value, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_USER, ACL_USER_OBJ};
    let _g = serial();
    let fx = Fixture::new("perm", None);
    let (outp, wide, pre, ctl, rp) = (fx.file("out.txt"), fx.file("wide.txt"), fx.file("pre.txt"), fx.file("ctl.txt"), fx.file("p.txt"));
    for f in [&wide, &pre] {
        std::fs::write(f, "BEFORE\n").unwrap();
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let uid = unsafe { libc::getuid() };
    let acl = acl_value(&[(ACL_USER_OBJ, 6, u32::MAX), (ACL_USER, 4, uid), (ACL_GROUP_OBJ, 0, u32::MAX), (ACL_MASK, 4, u32::MAX), (ACL_OTHER, 0, u32::MAX)]);
    let arb = arbiter(vec![]);
    let secret = fx.secret.clone();
    let Some(code) = guarded(cfg(&fx, arb), move || {
        let c2 = ctl.clone();
        let c = fork_run(move || errno_of(std::fs::write(&c2, "CONTROL\n")));
        let c = reap(c).unwrap_or(-1);
        let (sec, o, w, c3, a, hp) = (secret.clone(), outp.clone(), wide.clone(), ctl.clone(), acl.clone(), rp.with_extension("h"));
        let h = fork_run(move || {
            if !take_secret(&sec) {
                return 3;
            }
            let made = errno_of(std::fs::OpenOptions::new().write(true).create(true).mode(0o644).open(&o).and_then(|mut f| f.write_all(b"copy\n")));
            let appended = errno_of(std::fs::OpenOptions::new().append(true).open(&w).and_then(|mut f| f.write_all(b"more\n")));
            let widen = errno_of(std::fs::set_permissions(&o, std::fs::Permissions::from_mode(0o644)));
            let keep = errno_of(std::fs::set_permissions(&o, std::fs::Permissions::from_mode(0o600)));
            let other = errno_of(std::fs::set_permissions(&c3, std::fs::Permissions::from_mode(0o640)));
            let name = std::ffi::CString::new("system.posix_acl_access").unwrap();
            let path = std::ffi::CString::new(o.to_str().unwrap()).unwrap();
            let rc = unsafe { libc::setxattr(path.as_ptr(), name.as_ptr(), a.as_ptr() as *const libc::c_void, a.len(), 0) };
            let acl = if rc == 0 { 0 } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) };
            report(&hp, &[format!("made={made}"), format!("appended={appended}"), format!("widen={widen}"), format!("keep={keep}"), format!("other={other}"), format!("acl={acl}")]);
            0
        });
        let h = reap(h).unwrap_or(-1);
        // Held open for writing before the taint (`reader > pre.txt`).
        let (sec, p2, sp) = (secret.clone(), pre.clone(), rp.with_extension("s"));
        let s = fork_run(move || {
            let Ok(_held) = std::fs::OpenOptions::new().append(true).open(&p2) else { return 4 };
            let read = std::fs::read_to_string(&sec);
            report(&sp, &[format!("read={}", errno_of(read))]);
            0
        });
        let s = reap(s).unwrap_or(-1);
        // A later tool call, holding nothing, tries to open the copy up.
        let (o2, lp) = (outp.clone(), rp.with_extension("l"));
        let l = fork_run(move || {
            report(&lp, &[format!("later={}", errno_of(std::fs::set_permissions(&o2, std::fs::Permissions::from_mode(0o604))))]);
            0
        });
        let l = reap(l).unwrap_or(-1);
        report(&rp, &[format!("c={c}"), format!("h={h}"), format!("s={s}"), format!("l={l}")]);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let (r, h, s, l) = (read_report(&fx.file("p.txt")), read_report(&fx.file("p.h")), read_report(&fx.file("p.s")), read_report(&fx.file("p.l")));
    eprintln!("{r} | holder: {h} | sweep: {s} | later: {l}");
    assert!(r.contains("c=0") && r.contains("h=0") && r.contains("s=0") && r.contains("l=0"), "{r}");
    assert!(h.contains("made=0") && h.contains("appended=0"), "the holder's writes run: {h}");
    assert_eq!(mode_of(&fx.file("out.txt")) & 0o077, 0, "a holder's new file is closed to other users (asked 0644)");
    assert_eq!(mode_of(&fx.file("wide.txt")), 0o600, "a file a holder appends to is narrowed before it gets the descriptor");
    assert!(s.contains("read=0"), "the sweep's reader still reads: {s}");
    assert_eq!(mode_of(&fx.file("pre.txt")), 0o600, "a file held open for writing before the taint is narrowed at the taint");
    assert!(h.contains(&format!("widen={}", libc::EACCES)), "a chmod that opens the derived copy to others is refused: {h}");
    assert!(h.contains("keep=0"), "a chmod that keeps it closed runs: {h}");
    assert!(h.contains(&format!("acl={}", libc::EACCES)), "a POSIX ACL naming another user on the derived copy is refused: {h}");
    assert!(l.contains(&format!("later={}", libc::EACCES)), "a later process holding nothing cannot open it up either: {l}");
    assert_eq!(mode_of(&fx.file("out.txt")) & 0o077, 0, "the copy stayed closed");
    // The control: a non-holder's file keeps the umask's mode, and its chmod runs.
    assert!(h.contains("other=0"), "a chmod of a file no holder wrote runs: {h}");
    assert_eq!(mode_of(&fx.file("ctl.txt")), 0o640, "the control file took its chmod");
    eprintln!("R4b PERMISSIONS PASS");
}

/// (P), the sweep's own race (2026-10-04): a process swaps one descriptor
/// number between a file it writes and a file it only reads while it reads
/// the secret again and again. The sweep found the number writable by its
/// `fdinfo`, then narrowed whatever `/proc/<pid>/fd/<n>` named a moment
/// later: the read-only file (in the kernel tests, a concurrent test's
/// protected file went 0600 that way). Judged on a copy of the descriptor,
/// only the written file is narrowed.
#[test]
#[ignore]
fn the_sweep_narrows_the_file_a_descriptor_writes_never_one_it_swapped_in() {
    let _g = serial();
    let fx = Fixture::new("swap", None);
    let (w, f, rp) = (fx.file("w.txt"), fx.file("f.txt"), fx.file("swap.txt"));
    for p in [&w, &f] {
        std::fs::write(p, "X\n").unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let arb = arbiter(vec![]);
    let secret = fx.secret.clone();
    let (w2, f2) = (w.clone(), f.clone());
    let Some(code) = guarded(cfg(&fx, arb), move || {
        let s = fork_run(move || {
            let (Ok(wf), Ok(ff)) = (std::fs::OpenOptions::new().append(true).open(&w2), std::fs::File::open(&f2)) else { return 4 };
            let (wfd, ffd) = (wf.as_raw_fd(), ff.as_raw_fd());
            const N: RawFd = 200;
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let st = stop.clone();
            let swapper = std::thread::spawn(move || {
                while !st.load(std::sync::atomic::Ordering::Relaxed) {
                    unsafe {
                        libc::dup2(wfd, N);
                        libc::dup2(ffd, N);
                    }
                }
            });
            let mut reads = 0;
            for _ in 0..200 {
                if std::fs::read_to_string(&secret).is_ok() {
                    reads += 1;
                }
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = swapper.join();
            report(&rp, &[format!("reads={reads}")]);
            0
        });
        reap(s).unwrap_or(-1)
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = read_report(&fx.file("swap.txt"));
    eprintln!("{r}: w.txt {:o}, f.txt {:o}", mode_of(&w), mode_of(&f));
    assert!(r.contains("reads=") && !r.contains("reads=0"), "the secret was read: {r}");
    assert_eq!(mode_of(&w), 0o600, "the file the reader writes is narrowed");
    assert_eq!(mode_of(&f), 0o644, "THE BUG: a file the reader only reads was narrowed through a reused descriptor number");
    eprintln!("R4b SWEEP COPY PASS");
}

// ── (D) device nodes ────────────────────────────────────────────────────────

#[test]
#[ignore]
fn a_holder_writes_to_no_device_but_the_terminal_and_the_sinks_that_keep_nothing() {
    let _g = serial();
    if std::fs::OpenOptions::new().read(true).write(true).open("/dev/fuse").is_err() {
        eprintln!("SKIP: /dev/fuse cannot be opened here");
        return;
    }
    let fx = Fixture::new("dev", None);
    let rp = fx.file("d.txt");
    let arb = arbiter(vec![]);
    let secret = fx.secret.clone();
    let Some(code) = guarded(cfg(&fx, arb), move || {
        let fuse = || std::fs::OpenOptions::new().read(true).write(true).open("/dev/fuse");
        let c = fork_run(move || errno_of(fuse()));
        let c = reap(c).unwrap_or(-1);
        let (sec, hp) = (secret.clone(), rp.with_extension("h"));
        let h = fork_run(move || {
            if !take_secret(&sec) {
                return 3;
            }
            let null = errno_of(std::fs::OpenOptions::new().write(true).open("/dev/null").and_then(|mut f| f.write_all(CANARY.as_bytes())));
            let dev = errno_of(fuse());
            report(&hp, &[format!("null={null}"), format!("fuse={dev}")]);
            0
        });
        let h = reap(h).unwrap_or(-1);
        let (sec, sp) = (secret.clone(), rp.with_extension("s"));
        let s = fork_run(move || {
            let Ok(_held) = fuse() else { return 4 };
            report(&sp, &[format!("read={}", errno_of(std::fs::read_to_string(&sec)))]);
            0
        });
        let s = reap(s).unwrap_or(-1);
        report(&rp, &[format!("c={c}"), format!("h={h}"), format!("s={s}")]);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let (r, h, s) = (read_report(&fx.file("d.txt")), read_report(&fx.file("d.h")), read_report(&fx.file("d.s")));
    eprintln!("{r} | holder: {h} | sweep: {s}");
    assert!(r.contains("c=0"), "control: a process holding nothing opens /dev/fuse: {r}");
    assert!(r.contains("h=0") && r.contains("s=0"), "{r}");
    assert!(h.contains("null=0"), "a holder writes to /dev/null: {h}");
    assert!(h.contains(&format!("fuse={}", libc::EACCES)), "a holder's open of /dev/fuse is refused: {h}");
    assert!(s.contains(&format!("read={}", libc::EACCES)), "a process holding /dev/fuse has its raw open refused: {s}");
    eprintln!("R4b DEVICES PASS");
}

// ── (X) the display server ──────────────────────────────────────────────────

fn unix_connect_errno(addr: &[u8]) -> i32 {
    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if s < 0 {
        return -1;
    }
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, b) in addr.iter().enumerate() {
        sa.sun_path[i] = *b as libc::c_char;
    }
    let abstract_ = addr.first() == Some(&0);
    let len = (std::mem::size_of::<libc::sa_family_t>() + addr.len() + usize::from(!abstract_)) as libc::socklen_t;
    let rc = unsafe { libc::connect(s, &sa as *const libc::sockaddr_un as *const libc::sockaddr, len) };
    let e = if rc == 0 { 0 } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) };
    unsafe { libc::close(s) };
    e
}

fn run_display_case(bound: bool) {
    let _g = serial();
    let tag = run_tag();
    let x11 = std::env::temp_dir().join(format!("mandu-r4b-x11-{tag}-{bound}"));
    let _ = std::fs::remove_dir_all(&x11);
    std::fs::create_dir_all(&x11).unwrap();
    let x11 = std::fs::canonicalize(&x11).unwrap();
    let path = x11.join("X7");
    let abs = format!("/tmp/.X11-unix/X7-r4b-{tag}-{bound}");
    // The display server: listeners of this test process, outside the tree,
    // on the allow-list the launcher writes for the displays.
    let _p = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let abs_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let abs_addr: Vec<u8> = std::iter::once(0u8).chain(abs.bytes()).collect();
    {
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, b) in abs_addr.iter().enumerate() {
            sa.sun_path[i] = *b as libc::c_char;
        }
        let len = (std::mem::size_of::<libc::sa_family_t>() + abs_addr.len()) as libc::socklen_t;
        assert_eq!(unsafe { libc::bind(abs_fd, &sa as *const libc::sockaddr_un as *const libc::sockaddr, len) }, 0);
        assert_eq!(unsafe { libc::listen(abs_fd, 8) }, 0);
    }
    let unix_policy = format!(r#"{{"allow":[{{"path":"{}","label":"display"}}],"abstractAllow":["/tmp/.X11-unix/X7-r4b-*"]}}"#, x11.display());
    let fx = Fixture::new(&format!("x11-{bound}"), Some(unix_policy));
    let bindings = if bound { vec![format!("unix:{}", path.display()), format!("unix:@{abs}")] } else { vec!["127.0.0.2".to_string()] };
    let arb = arbiter(bindings);
    let mut c = cfg(&fx, arb);
    c.tree_roots = Vec::new();
    let (secret, rp) = (fx.secret.clone(), fx.file("x.txt"));
    let pbytes: Vec<u8> = path.to_str().unwrap().as_bytes().to_vec();
    let Some(code) = guarded(c, move || {
        let (pb, ab) = (pbytes.clone(), abs_addr.clone());
        let cp = rp.with_extension("c");
        let ctl = fork_run(move || {
            report(&cp, &[format!("path={}", unix_connect_errno(&pb)), format!("abs={}", unix_connect_errno(&ab))]);
            0
        });
        let ctl = reap(ctl).unwrap_or(-1);
        let (pb, ab, hp, sec) = (pbytes.clone(), abs_addr.clone(), rp.with_extension("h"), secret.clone());
        let h = fork_run(move || {
            if !take_secret(&sec) {
                return 3;
            }
            report(&hp, &[format!("path={}", unix_connect_errno(&pb)), format!("abs={}", unix_connect_errno(&ab))]);
            0
        });
        let h = reap(h).unwrap_or(-1);
        report(&rp, &[format!("ctl={ctl}"), format!("h={h}")]);
        0
    }) else {
        unsafe { libc::close(abs_fd) };
        return;
    };
    unsafe { libc::close(abs_fd) };
    assert_eq!(code, Some(0));
    let (r, ctl, h) = (read_report(&fx.file("x.txt")), read_report(&fx.file("x.c")), read_report(&fx.file("x.h")));
    eprintln!("bound={bound}: {r} | control: {ctl} | holder: {h}");
    let _ = std::fs::remove_dir_all(&x11);
    assert!(r.contains("ctl=0") && r.contains("h=0"), "{r}");
    assert!(ctl.contains("path=0") && ctl.contains("abs=0"), "control: a process holding nothing reaches the display: {ctl}");
    if bound {
        assert!(h.contains("path=0") && h.contains("abs=0"), "bound: the holder reaches the display: {h}");
    } else {
        assert!(h.contains(&format!("path={}", libc::EACCES)) && h.contains(&format!("abs={}", libc::EACCES)), "THE LEAK: a holder reached the display server (the clipboard): {h}");
    }
    eprintln!("R4b DISPLAY (bound={bound}) PASS");
}

#[test]
#[ignore]
fn the_display_socket_is_refused_to_a_holder() {
    run_display_case(false);
}

#[test]
#[ignore]
fn the_display_socket_is_reached_by_a_holder_bound_to_it() {
    run_display_case(true);
}

// ── (O) a stacking file system: an overlay judged by its upper layer ────────

fn cpath(p: &Path) -> std::ffi::CString {
    std::ffi::CString::new(p.as_os_str().to_str().unwrap()).unwrap()
}

/// The overlay source every test overlay is mounted with: the destination
/// a stack is named by is `mount:overlay:mandu-ovl`.
const OVL_SOURCE: &str = "mandu-ovl";
const OVL_DEST: &str = "mount:overlay:mandu-ovl";

/// Mount an overlay (`lowerdir`, `upperdir`, `workdir`) at `merged` in the
/// caller's mount namespace (with `userxattr` first, as a user namespace
/// needs, then without). False when the kernel refuses.
fn mount_overlay(merged: &Path, lower: &Path, upper: &Path, work: &Path) -> bool {
    let (src, ty) = (std::ffi::CString::new(OVL_SOURCE).unwrap(), std::ffi::CString::new("overlay").unwrap());
    let base = format!("lowerdir={},upperdir={},workdir={}", lower.display(), upper.display(), work.display());
    [format!("{base},userxattr"), base].iter().any(|o| {
        let data = std::ffi::CString::new(o.as_str()).unwrap();
        // SAFETY: NUL-terminated strings; an overlay mount in the caller's
        // own namespace.
        unsafe { libc::mount(src.as_ptr(), cpath(merged).as_ptr(), ty.as_ptr(), 0, data.as_ptr() as *const libc::c_void) == 0 }
    })
}

/// A bind mount (`from` at `to`) or, `from` None, a fresh tmpfs at `to`, in
/// the caller's mount namespace.
fn mount_at(from: Option<&Path>, to: &Path) -> bool {
    let tmpfs = std::ffi::CString::new("tmpfs").unwrap();
    let (ty, src, flags) = match from {
        Some(f) => (std::ptr::null(), cpath(f), libc::MS_BIND),
        None => (tmpfs.as_ptr(), std::ffi::CString::new("mandu-shadow").unwrap(), 0),
    };
    // SAFETY: NUL-terminated paths; a mount in the caller's own namespace.
    unsafe { libc::mount(src.as_ptr(), cpath(to).as_ptr(), ty, flags, std::ptr::null()) == 0 }
}

/// In the tracee, before its filter: a user + mount namespace of its own (as
/// the launcher's wrap makes, so every mount the guard sees there is a copy),
/// then `then` (the tree's own mounts); false from `then` ends the child
/// with 94.
fn own_namespace_setup(then: impl FnOnce() -> bool) -> impl FnOnce() -> Option<i32> {
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    move || {
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            return Some(EXIT_NO_SECCOMP);
        }
        let maps = std::fs::write("/proc/self/setgroups", "deny").is_ok()
            && std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).is_ok()
            && std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).is_ok();
        let root = cpath(Path::new("/"));
        // SAFETY: NUL-terminated paths; mounts in the child's own namespace.
        if !maps || unsafe { libc::mount(std::ptr::null(), root.as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) } != 0 {
            return Some(EXIT_NO_SECCOMP);
        }
        if then() { None } else { Some(94) }
    }
}

/// Overlays mounted in the guard's own mount namespace (the test process's:
/// what the launcher's namespace holds, which the tree cannot mount in);
/// unmounted on drop. None when the kernel refuses (no root in a user
/// namespace here: SKIP).
struct GuardOverlays(Vec<PathBuf>);

impl GuardOverlays {
    fn mount(mounts: &[(PathBuf, PathBuf, PathBuf, PathBuf)]) -> Option<GuardOverlays> {
        let mut up = GuardOverlays(Vec::new());
        for (merged, lower, upper, work) in mounts {
            if !mount_overlay(merged, lower, upper, work) {
                return None;
            }
            up.0.push(merged.clone());
        }
        Some(up)
    }
}

impl Drop for GuardOverlays {
    fn drop(&mut self) {
        for m in self.0.iter().rev() {
            // SAFETY: a NUL-terminated path; our own mount.
            unsafe { libc::umount2(cpath(m).as_ptr(), libc::MNT_DETACH) };
        }
    }
}

/// Make `dirs`, each under `base`.
fn mkdirs(base: &Path, dirs: &[&str]) -> Vec<PathBuf> {
    dirs.iter()
        .map(|d| {
            let p = base.join(d);
            std::fs::create_dir_all(&p).unwrap();
            p
        })
        .collect()
}

/// The guarded run of the overlay cases: a control (a process holding
/// nothing) writes `ctl.txt` through `ctl_through`, then a holder creates
/// `h.txt` through each of `merged` (and `mkdir`s `hd` through the first),
/// each errno reported under its tag.
fn run_overlay_writes(c: GuardConfig, setup: impl FnOnce() -> Option<i32>, fx: &Fixture, ctl_through: PathBuf, merged: Vec<(&'static str, PathBuf)>, out: &Path) -> Option<i32> {
    let (secret, out) = (fx.secret.clone(), out.to_path_buf());
    let code = guarded_setup(c, setup, move || {
        let ctl = fork_run(move || errno_of(std::fs::write(ctl_through.join("ctl.txt"), "CONTROL\n")));
        let ctl = reap(ctl).unwrap_or(-1);
        let (sec, hp) = (secret.clone(), out.with_extension("h"));
        let h = fork_run(move || {
            if !take_secret(&sec) {
                return 3;
            }
            let w = |p: PathBuf| errno_of(std::fs::OpenOptions::new().write(true).create(true).open(p).and_then(|mut f| f.write_all(CANARY.as_bytes())));
            let mut lines: Vec<String> = merged.iter().map(|(tag, m)| format!("{tag}={}", w(m.join("h.txt")))).collect();
            lines.push(format!("mkdir={}", errno_of(std::fs::create_dir(merged[0].1.join("hd")))));
            report(&hp, &lines);
            0
        });
        let h = reap(h).unwrap_or(-1);
        report(&out, &[format!("ctl={ctl}"), format!("h={h}")]);
        0
    });
    match code {
        None => None,
        Some(Some(94)) => {
            eprintln!("SKIP: the tree's own mounts could not be made");
            None
        }
        Some(c) => Some(c.unwrap_or(-1)),
    }
}

/// (O): overlays the guard's own namespace mounts (r: upper on the "remote"
/// mount; l: upper on the fixture's disk; g: an upper whose directory is
/// renamed away once the overlay is up, and that the tree then lays a local
/// directory at in its own view), written through from a tracee in a user +
/// mount namespace of its own.
fn run_overlay_case(fx: &Fixture, remote: &Path, dev: u64, bindings: Vec<String>, out: &Path) -> Option<i32> {
    let local = mkdirs(&fx.dir, &["lower", "merged_r", "merged_l", "merged_g", "up_l", "wk_l"]);
    let rem = mkdirs(remote, &["up_r", "wk_r", "gone/up", "gone/wk"]);
    let (lower, merged_r, merged_l, merged_g) = (local[0].clone(), local[1].clone(), local[2].clone(), local[3].clone());
    let mounts = vec![
        (merged_r.clone(), lower.clone(), rem[0].clone(), rem[1].clone()),
        (merged_l.clone(), lower.clone(), local[4].clone(), local[5].clone()),
        (merged_g.clone(), lower.clone(), rem[2].clone(), rem[3].clone()),
    ];
    let Some(ovl) = GuardOverlays::mount(&mounts) else {
        eprintln!("SKIP: no overlay can be mounted in the test's own namespace (run through scripts/kernel-tests.sh)");
        return None;
    };
    let gone = remote.join("gone");
    if std::fs::rename(&gone, remote.join("gone2")).is_err() {
        eprintln!("SKIP: the upper directory could not be renamed away");
        return None;
    }
    // The tree lays a local directory (a tmpfs of its own) where the renamed
    // upper was, in its view only: the guard's own view finds nothing there.
    let setup = own_namespace_setup(move || std::fs::create_dir(&gone).is_ok() && mount_at(None, &gone) && std::fs::create_dir(gone.join("up")).is_ok());
    let arb = arbiter(bindings);
    let mut c = cfg(fx, arb);
    c.extra_remote_devs = vec![dev];
    let code = run_overlay_writes(c, setup, fx, merged_r.clone(), vec![("remote", merged_r), ("local", merged_l), ("gone", merged_g)], out);
    let _ = std::fs::remove_dir(remote.join("gone"));
    drop(ovl);
    code
}

#[test]
#[ignore]
fn an_overlay_is_judged_by_the_mount_its_upper_layer_is_on() {
    let _g = serial();
    let fx = Fixture::new("ovl", None);
    let Some((remote, dev)) = remote_dir(&fx, "o") else {
        eprintln!("SKIP: no second file system at /dev/shm");
        return;
    };
    let dir = std::fs::File::open(&remote).unwrap();
    let facts = net_supervisor::local_exits::fd_fs_facts(dir.as_raw_fd(), None);
    let net_supervisor::local_exits::MountVerdict::Remote(dest) = net_supervisor::local_exits::mount_verdict(&facts, &[dev]) else { panic!("{facts:?}") };

    let out = fx.file("o.txt");
    let Some(code) = run_overlay_case(&fx, &remote, dev, vec!["127.0.0.2".into()], &out) else {
        let _ = std::fs::remove_dir_all(&remote);
        eprintln!("SKIP: seccomp NEW_LISTENER, an unprivileged user namespace or an overlay unavailable here");
        return;
    };
    assert_eq!(code, 0);
    let (r, h) = (read_report(&out), read_report(&out.with_extension("h")));
    eprintln!("overlay, unbound: {r} | holder: {h}");
    assert!(r.contains("ctl=0") && r.contains("h=0"), "{r}");
    assert_eq!(std::fs::read_to_string(remote.join("up_r/ctl.txt")).unwrap_or_default(), "CONTROL\n", "control: a non-holder writes through the overlay (its upper gets the file)");
    assert!(h.contains(&format!("remote={}", libc::EACCES)), "a holder's create through an overlay whose upper leaves the machine is refused: {h}");
    assert!(h.contains(&format!("mkdir={}", libc::EACCES)), "and its mkdir: {h}");
    assert!(!remote.join("up_r/h.txt").exists() && !remote.join("up_r/hd").exists(), "THE LEAK: a name or the canary reached the upper layer");
    assert!(h.contains("local=0"), "an overlay whose upper is local takes the holder's write: {h}");
    assert!(std::fs::read_to_string(fx.file("up_l/h.txt")).unwrap_or_default().contains(CANARY), "the local upper really got it");
    assert!(
        h.contains(&format!("gone={}", libc::EACCES)),
        "an overlay whose upper the guard's own view cannot find is refused, though the tree laid a local directory at its path in its own view (P0 5d): {h}"
    );
    assert!(!remote.join("gone2/up/h.txt").exists(), "THE LEAK: the unfound upper got the file");

    // Bound to the upper's mount: the holder writes through the overlay.
    let _ = std::fs::remove_dir_all(&remote);
    std::fs::create_dir_all(&remote).unwrap();
    for d in ["merged_r", "merged_l", "merged_g", "up_l", "wk_l"] {
        let _ = std::fs::remove_dir_all(fx.file(d));
    }
    let Some(code) = run_overlay_case(&fx, &remote, dev, vec![dest.clone()], &out) else { return };
    assert_eq!(code, 0);
    let h = read_report(&out.with_extension("h"));
    eprintln!("overlay, bound to {dest}: holder: {h}");
    assert!(h.contains("remote=0"), "bound to the upper's mount: the holder writes through the overlay: {h}");
    assert!(std::fs::read_to_string(remote.join("up_r/h.txt")).unwrap_or_default().contains(CANARY), "bound: the upper really got it");
    let _ = std::fs::remove_dir_all(&remote);
    eprintln!("R4b OVERLAY PASS");
}

// ── (O2) an overlay the tree mounted in a user namespace of its own ─────────

/// (O2), P0 5d: the tree's own overlays, each over an upper it then hides
/// (s: the upper reached through a bind of the "remote" directory, the bind
/// detached and a tmpfs of its own laid over that path; d: the bind
/// detached, so the path falls through to a local directory; t: an honest
/// local upper). Every
/// path the overlays name resolves to a local directory in the guard's view
/// and in the tracee's.
fn run_tree_overlay_case(fx: &Fixture, remote: &Path, dev: u64, bindings: Vec<String>, out: &Path) -> Option<i32> {
    let l = mkdirs(&fx.dir, &["lower2", "merged_s", "merged_d", "merged_t", "sh/up", "sh/wk", "dt/up", "dt/wk", "up_t", "wk_t"]);
    mkdirs(remote, &["s/up", "s/wk", "d/up", "d/wk"]);
    let (lower, merged_s, merged_d, merged_t) = (l[0].clone(), l[1].clone(), l[2].clone(), l[3].clone());
    let (sh, dt, up_t, wk_t) = (fx.file("sh"), fx.file("dt"), l[8].clone(), l[9].clone());
    let (rs, rd) = (remote.join("s"), remote.join("d"));
    let (ms, md, mt, lw) = (merged_s.clone(), merged_d.clone(), merged_t.clone(), lower.clone());
    let setup = own_namespace_setup(move || {
        // s: the upper is the remote directory, reached through a bind at
        // `sh`; the bind detached and a tmpfs laid over `sh`, with a local
        // `up` in it. (Detached, not covered: a covered bind of the remote
        // mount would still be listed and withhold the raw open, plan 13
        // §4.9; this case tests the write gate.)
        // SAFETY: a NUL-terminated path; our own mount.
        let s = mount_at(Some(&rs), &sh)
            && mount_overlay(&ms, &lw, &sh.join("up"), &sh.join("wk"))
            && unsafe { libc::umount2(cpath(&sh).as_ptr(), libc::MNT_DETACH) } == 0
            && mount_at(None, &sh)
            && std::fs::create_dir(sh.join("up")).is_ok();
        // d: the same through `dt`, and the bind detached (the overlay keeps
        // its own reference to the remote upper).
        // SAFETY: a NUL-terminated path; our own mount.
        let d = mount_at(Some(&rd), &dt) && mount_overlay(&md, &lw, &dt.join("up"), &dt.join("wk")) && unsafe { libc::umount2(cpath(&dt).as_ptr(), libc::MNT_DETACH) } == 0;
        let t = mount_overlay(&mt, &lw, &up_t, &wk_t);
        s && d && t
    });
    let arb = arbiter(bindings);
    let mut c = cfg(fx, arb);
    c.extra_remote_devs = vec![dev];
    run_overlay_writes(c, setup, fx, merged_s.clone(), vec![("shadowed", merged_s), ("detached", merged_d), ("local", merged_t)], out)
}

#[test]
#[ignore]
fn an_overlay_the_tree_mounted_is_remote_whatever_its_upper_names() {
    let _g = serial();
    let fx = Fixture::new("ovl2", None);
    let Some((remote, dev)) = remote_dir(&fx, "o2") else {
        eprintln!("SKIP: no second file system at /dev/shm");
        return;
    };
    let dir = std::fs::File::open(&remote).unwrap();
    let facts = net_supervisor::local_exits::fd_fs_facts(dir.as_raw_fd(), None);
    let net_supervisor::local_exits::MountVerdict::Remote(upper_dest) = net_supervisor::local_exits::mount_verdict(&facts, &[dev]) else { panic!("{facts:?}") };

    // Unbound, and bound to the mount the upper is really on: the guard
    // cannot tell that mount from what the tree's overlay names.
    let out = fx.file("o2.txt");
    let Some(code) = run_tree_overlay_case(&fx, &remote, dev, vec!["127.0.0.2".into(), upper_dest.clone()], &out) else {
        let _ = std::fs::remove_dir_all(&remote);
        eprintln!("SKIP: seccomp NEW_LISTENER, an unprivileged user namespace or an unprivileged overlay unavailable here");
        return;
    };
    assert_eq!(code, 0);
    let (r, h) = (read_report(&out), read_report(&out.with_extension("h")));
    eprintln!("the tree's overlays, unbound: {r} | holder: {h}");
    assert!(r.contains("ctl=0") && r.contains("h=0"), "{r}");
    // The control proves the shadow: a write through the overlay lands on
    // the "remote" mount, though its upperdir= resolves locally everywhere.
    assert_eq!(std::fs::read_to_string(remote.join("s/up/ctl.txt")).unwrap_or_default(), "CONTROL\n", "control: the shadowed overlay's writes land on the remote mount");
    assert!(!fx.file("sh/up/ctl.txt").exists(), "control: nothing landed in the local directory its upperdir= names");
    assert!(h.contains(&format!("shadowed={}", libc::EACCES)), "THE LEAK (P0 5d): a holder wrote through the tree's overlay whose remote upper a local directory shadows: {h}");
    assert!(h.contains(&format!("detached={}", libc::EACCES)), "THE LEAK (P0 5d): a holder wrote through the tree's overlay whose remote upper was unmounted from under it: {h}");
    assert!(h.contains(&format!("mkdir={}", libc::EACCES)), "and its mkdir: {h}");
    assert!(h.contains(&format!("local={}", libc::EACCES)), "fail-closed: the tree's overlay is remote even over a local upper (the guard cannot tell): {h}");
    for p in ["s/up/h.txt", "s/up/hd", "d/up/h.txt"] {
        assert!(!remote.join(p).exists(), "THE LEAK: {p} reached the remote upper");
    }

    // Bound to the overlay itself: the holder writes through it.
    let _ = std::fs::remove_dir_all(&remote);
    std::fs::create_dir_all(&remote).unwrap();
    for d in ["lower2", "merged_s", "merged_d", "merged_t", "sh", "dt", "up_t", "wk_t"] {
        let _ = std::fs::remove_dir_all(fx.file(d));
    }
    let Some(code) = run_tree_overlay_case(&fx, &remote, dev, vec![OVL_DEST.into()], &out) else { return };
    assert_eq!(code, 0);
    let h = read_report(&out.with_extension("h"));
    eprintln!("the tree's overlays, bound to {OVL_DEST}: holder: {h}");
    assert!(h.contains("shadowed=0") && h.contains("detached=0") && h.contains("local=0"), "bound to the overlay: the holder writes through it: {h}");
    assert!(std::fs::read_to_string(remote.join("s/up/h.txt")).unwrap_or_default().contains(CANARY), "bound: the remote upper really got it");
    let _ = std::fs::remove_dir_all(&remote);
    eprintln!("R4b TREE OVERLAY PASS");
}

// ── (N) names and attributes on a mount that leaves the machine ─────────────

/// Every name-family and attribute call on `dir`, each errno: `existing.txt`,
/// `victim.txt` exist there beforehand; `tag` prefixes the new names.
fn name_calls(dir: &Path, tag: &str) -> Vec<String> {
    let c = |p: PathBuf| cpath(&p);
    let ex = dir.join("existing.txt");
    let last = || std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
    let rc = |r: libc::c_int| if r == 0 { 0 } else { last() };
    let name = std::ffi::CString::new("user.mandu").unwrap();
    // SAFETY: NUL-terminated paths and names.
    unsafe {
        vec![
            format!("mkdir={}", errno_of(std::fs::create_dir(dir.join(format!("{tag}dir"))))),
            format!("symlink={}", errno_of(std::os::unix::fs::symlink(CANARY, dir.join(format!("{tag}sym"))))),
            format!("link={}", errno_of(std::fs::hard_link(&ex, dir.join(format!("{tag}link"))))),
            format!("rename={}", errno_of(std::fs::rename(dir.join(format!("{tag}victim.txt")), dir.join(format!("{tag}{CANARY}"))))),
            format!("mknod={}", rc(libc::mknod(c(dir.join(format!("{tag}fifo"))).as_ptr(), libc::S_IFIFO | 0o600, 0))),
            format!("unlink={}", errno_of(std::fs::remove_file(dir.join(format!("{tag}gone.txt"))))),
            format!("truncate={}", rc(libc::truncate(c(ex.clone()).as_ptr(), 4242))),
            format!("chmod={}", errno_of(std::fs::set_permissions(&ex, std::fs::Permissions::from_mode(0o640)))),
            format!("setxattr={}", rc(libc::setxattr(c(ex.clone()).as_ptr(), name.as_ptr(), CANARY.as_ptr() as *const libc::c_void, CANARY.len(), 0))),
        ]
    }
}

const NAME_CALLS: [&str; 9] = ["mkdir", "symlink", "link", "rename", "mknod", "unlink", "truncate", "chmod", "setxattr"];

fn seed_names(dir: &Path, tag: &str) {
    std::fs::write(dir.join("existing.txt"), "EXISTING\n").unwrap();
    std::fs::set_permissions(dir.join("existing.txt"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(dir.join(format!("{tag}victim.txt")), "V\n").unwrap();
    std::fs::write(dir.join(format!("{tag}gone.txt")), "G\n").unwrap();
}

#[test]
#[ignore]
fn a_holders_names_and_attributes_on_a_mount_that_leaves_the_machine_are_refused() {
    let _g = serial();
    let fx = Fixture::new("names", None);
    let Some((remote, dev)) = remote_dir(&fx, "n") else {
        eprintln!("SKIP: no second file system at /dev/shm");
        return;
    };
    let local = fx.file("localdir");
    std::fs::create_dir_all(&local).unwrap();
    for (d, t) in [(&remote, "c_"), (&remote, "h_"), (&local, "l_")] {
        seed_names(d, t);
    }
    let dir = std::fs::File::open(&remote).unwrap();
    let facts = net_supervisor::local_exits::fd_fs_facts(dir.as_raw_fd(), None);
    let net_supervisor::local_exits::MountVerdict::Remote(dest) = net_supervisor::local_exits::mount_verdict(&facts, &[dev]) else { panic!("{facts:?}") };
    let run = |bindings: Vec<String>, tag: &'static str, out: PathBuf| {
        let arb = arbiter(bindings);
        let mut c = cfg(&fx, arb);
        c.extra_remote_devs = vec![dev];
        let (secret, remote, local) = (fx.secret.clone(), remote.clone(), local.clone());
        guarded(c, move || {
            // The control: a process holding nothing, on the mount.
            let (r2, cp) = (remote.clone(), out.with_extension("c"));
            let ctl = fork_run(move || {
                report(&cp, &name_calls(&r2, "c_"));
                0
            });
            let ctl = reap(ctl).unwrap_or(-1);
            let (sec, hp) = (secret.clone(), out.with_extension("h"));
            let h = fork_run(move || {
                if !take_secret(&sec) {
                    return 3;
                }
                let mut lines = name_calls(&remote, tag);
                // The same holder on a local disk.
                lines.extend(name_calls(&local, "l_").into_iter().map(|l| format!("local_{l}")));
                report(&hp, &lines);
                0
            });
            let h = reap(h).unwrap_or(-1);
            report(&out, &[format!("ctl={ctl}"), format!("h={h}")]);
            0
        })
    };
    let out = fx.file("n.txt");
    let Some(code) = run(vec!["127.0.0.2".into()], "h_", out.clone()) else { return };
    assert_eq!(code, Some(0));
    let (r, ctl, h) = (read_report(&out), read_report(&out.with_extension("c")), read_report(&out.with_extension("h")));
    eprintln!("{r} | control: {ctl} | holder: {h}");
    assert!(r.contains("ctl=0") && r.contains("h=0"), "{r}");
    for call in NAME_CALLS {
        // setxattr: a tmpfs before Linux 6.6 has no user attributes.
        if call != "setxattr" {
            assert!(ctl.contains(&format!("\n{call}=0")) || ctl.starts_with(&format!("{call}=0")), "control: a non-holder's {call} on the mount runs: {ctl}");
            assert!(h.contains(&format!("local_{call}=0")), "a holder's {call} on a local disk runs: {h}");
        }
        assert!(h.contains(&format!("\n{call}={}", libc::EACCES)) || h.starts_with(&format!("{call}={}", libc::EACCES)), "a holder's {call} on the mount is refused: {h}");
    }
    for n in ["h_dir", "h_sym", "h_link", "h_fifo"] {
        assert!(std::fs::symlink_metadata(remote.join(n)).is_err(), "THE LEAK: the holder's name {n} reached the mount");
    }
    assert!(remote.join("h_victim.txt").exists() && !remote.join(format!("h_{CANARY}")).exists(), "THE LEAK: the holder renamed a file to the canary on the mount");
    assert!(remote.join("h_gone.txt").exists(), "the holder removed a name on the mount");
    let md = std::fs::metadata(remote.join("existing.txt")).unwrap();
    // The control's truncate and chmod ran first (4242, 0640); the holder's
    // changed nothing after them.
    assert_eq!((md.len(), md.mode() & 0o777), (4242, 0o640), "the holder changed the file's length or mode");

    // Bound to the mount: the holder's mkdir runs.
    let Some(code) = run(vec![dest.clone()], "b_", fx.file("nb.txt")) else { return };
    assert_eq!(code, Some(0));
    let h = read_report(&fx.file("nb.h"));
    eprintln!("bound to {dest}: {h}");
    assert!(h.starts_with("mkdir=0") && remote.join("b_dir").is_dir(), "bound: the holder's mkdir on the mount runs: {h}");
    let _ = std::fs::remove_dir_all(&remote);
    eprintln!("R4b NAMES PASS");
}

// ── (R) a writable descriptor passed over SCM_RIGHTS ────────────────────────

/// Send `fd` over the Unix socket `sock` (one byte, `SCM_RIGHTS`): errno.
fn send_fd(sock: RawFd, fd: RawFd) -> i32 {
    let mut byte = [b'F'];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut libc::c_void, iov_len: 1 };
    let mut cbuf = [0u64; 8];
    // SAFETY: a msghdr over our buffers with one SCM_RIGHTS message.
    unsafe {
        let mut m: libc::msghdr = std::mem::zeroed();
        m.msg_iov = &mut iov;
        m.msg_iovlen = 1;
        m.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        m.msg_controllen = libc::CMSG_SPACE(4) as _;
        let c = libc::CMSG_FIRSTHDR(&m);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::copy_nonoverlapping(&fd as *const RawFd as *const u8, libc::CMSG_DATA(c), 4);
        if libc::sendmsg(sock, &m, 0) < 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        }
    }
    0
}

/// Receive one descriptor, without waiting: None when nothing is queued.
fn recv_fd(sock: RawFd) -> Option<RawFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut libc::c_void, iov_len: 1 };
    let mut cbuf = [0u64; 8];
    // SAFETY: recvmsg into our buffers.
    unsafe {
        let mut m: libc::msghdr = std::mem::zeroed();
        m.msg_iov = &mut iov;
        m.msg_iovlen = 1;
        m.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        m.msg_controllen = std::mem::size_of_val(&cbuf) as _;
        if libc::recvmsg(sock, &mut m, libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC) <= 0 {
            return None;
        }
        let c = libc::CMSG_FIRSTHDR(&m);
        if c.is_null() || (*c).cmsg_type != libc::SCM_RIGHTS {
            return None;
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(c), &mut fd as *mut RawFd as *mut u8, 4);
        Some(fd)
    }
}

fn wait_for(p: &Path) -> bool {
    for _ in 0..400 {
        if p.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    false
}

fn open_w(p: &Path) -> RawFd {
    std::fs::OpenOptions::new().write(true).create(true).append(true).open(p).map(std::os::unix::io::IntoRawFd::into_raw_fd).unwrap_or(-1)
}

#[test]
#[ignore]
fn a_writable_descriptor_passed_to_a_holder_is_judged_as_the_exit_it_is() {
    let _g = serial();
    let fx = Fixture::new("rights", None);
    let Some((remote, dev)) = remote_dir(&fx, "r") else {
        eprintln!("SKIP: no second file system at /dev/shm");
        return;
    };
    let fuse_ok = std::fs::OpenOptions::new().read(true).write(true).open("/dev/fuse").is_ok();
    let arb = arbiter(vec!["127.0.0.2".into()]);
    let mut c = cfg(&fx, arb);
    c.extra_remote_devs = vec![dev];
    let (secret, dir, rem, rp) = (fx.secret.clone(), fx.dir.clone(), remote.clone(), fx.file("r.txt"));
    let Some(code) = guarded(c, move || {
        // A holder H, and the agent (this root, holding nothing) passing to it.
        let (a, b) = socketpair(libc::SOCK_STREAM);
        let (ready, sent) = (dir.join("ready"), dir.join("sent"));
        let (sec, hp, rd, st) = (secret.clone(), rp.with_extension("h"), ready.clone(), sent.clone());
        let h = fork_run(move || {
            unsafe { libc::close(a) };
            if !take_secret(&sec) {
                return 3;
            }
            let _ = std::fs::write(&rd, "");
            if !wait_for(&st) {
                return 4;
            }
            // Whatever arrived, written to: the canary must reach no remote file.
            let mut got = Vec::new();
            while let Some(fd) = recv_fd(b) {
                let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).map(|l| l.display().to_string()).unwrap_or_default();
                // SAFETY: a descriptor we received.
                let _ = unsafe { libc::write(fd, CANARY.as_ptr() as *const libc::c_void, CANARY.len()) };
                got.push(link);
            }
            report(&hp, &[format!("got={}", got.join(";"))]);
            0
        });
        // The sender is the guarded root, the agent: a socket pair joins any
        // other process to a holder as a holder itself (plan 13 D2), which
        // may then open nothing there for writing; the agent is not made one
        // (its connection to a holder is masked at the model exit, §4.5.1).
        unsafe { libc::close(b) };
        let s = if wait_for(&ready) {
            let local = open_w(&dir.join("pass-local.txt"));
            let remote = open_w(&rem.join("pass-remote.txt"));
            let mut lines = vec![format!("opened={}", local >= 0 && remote >= 0), format!("local={}", send_fd(a, local)), format!("remote={}", send_fd(a, remote))];
            if fuse_ok {
                let dev = std::fs::OpenOptions::new().read(true).write(true).open("/dev/fuse").map(std::os::unix::io::IntoRawFd::into_raw_fd).unwrap_or(-1);
                lines.push(format!("fuse={}", send_fd(a, dev)));
            }
            report(&rp.with_extension("s"), &lines);
            0
        } else {
            4
        };
        let _ = std::fs::write(&sent, "");
        unsafe { libc::close(a) };
        let h = reap(h).unwrap_or(-1);
        // The other order: a process that already received such a descriptor
        // (T), or has one queued (Q), reads the secret: the raw open refused.
        let (sec, r3, tp) = (secret.clone(), rem.clone(), rp.with_extension("t"));
        let t = fork_run(move || {
            let (a, b) = socketpair(libc::SOCK_STREAM);
            // Its own descriptor closed: it holds only the one it received.
            let fd = open_w(&r3.join("pass-before.txt"));
            let sent = send_fd(a, fd);
            unsafe { libc::close(fd) };
            let held = recv_fd(b).is_some();
            let read_held = errno_of(std::fs::read_to_string(&sec));
            report(&tp, &[format!("sent={sent}"), format!("held={held}"), format!("read={read_held}")]);
            0
        });
        let t = reap(t).unwrap_or(-1);
        let (sec, r4, qp) = (secret.clone(), rem.clone(), rp.with_extension("q"));
        let q = fork_run(move || {
            let (a, b) = socketpair(libc::SOCK_STREAM);
            let fd = open_w(&r4.join("pass-queued.txt"));
            let sent = send_fd(a, fd);
            unsafe { libc::close(fd) };
            let read_queued = errno_of(std::fs::read_to_string(&sec));
            let _ = b;
            report(&qp, &[format!("sent={sent}"), format!("read={read_queued}")]);
            0
        });
        let q = reap(q).unwrap_or(-1);
        // A network namespace of its own: the guard cannot see who receives.
        let (r5, np) = (rem.clone(), rp.with_extension("n"));
        let n = fork_run(move || {
            let fd = open_w(&r5.join("pass-netns.txt"));
            if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
                report(&np, &["skip=1".to_string()]);
                return 0;
            }
            let (a, _b) = socketpair(libc::SOCK_STREAM);
            report(&np, &[format!("netns={}", send_fd(a, fd))]);
            0
        });
        let n = reap(n).unwrap_or(-1);
        report(&rp, &[format!("s={s}"), format!("h={h}"), format!("t={t}"), format!("q={q}"), format!("n={n}")]);
        0
    }) else {
        let _ = std::fs::remove_dir_all(&remote);
        return;
    };
    assert_eq!(code, Some(0));
    let (r, s, h, t, q, n) = (read_report(&fx.file("r.txt")), read_report(&fx.file("r.s")), read_report(&fx.file("r.h")), read_report(&fx.file("r.t")), read_report(&fx.file("r.q")), read_report(&fx.file("r.n")));
    eprintln!("{r} | sender: {s} | holder: {h} | before: {t} | queued: {q} | netns: {n}");
    assert!(["s=0", "h=0", "t=0", "q=0", "n=0"].iter().all(|x| r.contains(x)), "{r}");
    assert!(s.contains("opened=true") && s.contains("local=0"), "control: a local file's descriptor passes to the holder: {s}");
    assert!(h.contains("pass-local.txt"), "control: the holder received the local file: {h}");
    assert!(s.contains(&format!("remote={}", libc::EACCES)), "a writable descriptor of a file on the mount, passed to a holder, is refused at the send: {s}");
    assert!(!h.contains("pass-remote.txt"), "the holder received the mount's file: {h}");
    assert!(!std::fs::read_to_string(remote.join("pass-remote.txt")).unwrap_or_default().contains(CANARY), "THE LEAK: the canary reached the mount through a passed descriptor");
    if fuse_ok {
        assert!(s.contains(&format!("fuse={}", libc::EACCES)), "a writable /dev/fuse passed to a holder is refused: {s}");
        assert!(!h.contains("/dev/fuse"), "the holder received /dev/fuse: {h}");
    }
    assert!(t.contains("sent=0") && t.contains("held=true"), "a process holding nothing passes and takes the mount's descriptor: {t}");
    assert!(t.contains(&format!("read={}", libc::EACCES)), "holding a received writable descriptor on the mount, the raw open is refused: {t}");
    assert!(q.contains("sent=0") && q.contains(&format!("read={}", libc::EACCES)), "with one queued for it, the raw open is refused: {q}");
    if !n.contains("skip=1") {
        assert!(n.contains(&format!("netns={}", libc::EACCES)), "in a network namespace of its own the pass is refused: {n}");
    }
    let _ = std::fs::remove_dir_all(&remote);
    eprintln!("R4b SCM_RIGHTS PASS");
}

// ── (B) a holder's socket name, with no write-protect list ──────────────────

/// Bind a new pathname Unix socket at `p`: errno.
fn unix_bind_errno(p: &Path) -> i32 {
    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if s < 0 {
        return -1;
    }
    let bytes = p.as_os_str().to_str().unwrap().as_bytes();
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, b) in bytes.iter().enumerate() {
        sa.sun_path[i] = *b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    let rc = unsafe { libc::bind(s, &sa as *const libc::sockaddr_un as *const libc::sockaddr, len) };
    let e = if rc == 0 { 0 } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) };
    unsafe { libc::close(s) };
    e
}

/// P0 5e (2026-10-07): a socket file is a name; a holder's `bind` on a mount
/// that leaves the machine carries that name to the server. `bind` was
/// trapped only with a write-protect list (or the command box, or the
/// agent's own server), so under a secret policy with the list turned off
/// the holder's bind ran free. Now trapped under every secret policy: the
/// harness's filter has no write-protect list (`protect: false`).
#[test]
#[ignore]
fn a_holders_socket_name_on_a_mount_that_leaves_the_machine_is_refused_without_a_protect_list() {
    let _g = serial();
    let fx = Fixture::new("bind", None);
    let Some((remote, dev)) = remote_dir(&fx, "b") else {
        eprintln!("SKIP: no second file system at /dev/shm");
        return;
    };
    let arb = arbiter(vec!["127.0.0.2".into()]);
    let mut c = cfg(&fx, arb);
    c.extra_remote_devs = vec![dev];
    let (secret, rem, local, rp) = (fx.secret.clone(), remote.clone(), fx.dir.clone(), fx.file("b.txt"));
    let Some(code) = guarded(c, move || {
        let (r2, cp) = (rem.clone(), rp.with_extension("c"));
        let ctl = fork_run(move || {
            report(&cp, &[format!("remote={}", unix_bind_errno(&r2.join("c.sock")))]);
            0
        });
        let ctl = reap(ctl).unwrap_or(-1);
        let (hp, sec) = (rp.with_extension("h"), secret.clone());
        let h = fork_run(move || {
            if !take_secret(&sec) {
                return 3;
            }
            report(&hp, &[format!("remote={}", unix_bind_errno(&rem.join(format!("h_{CANARY}.sock")))), format!("local={}", unix_bind_errno(&local.join("h.sock")))]);
            0
        });
        let h = reap(h).unwrap_or(-1);
        report(&rp, &[format!("ctl={ctl}"), format!("h={h}")]);
        0
    }) else {
        let _ = std::fs::remove_dir_all(&remote);
        return;
    };
    assert_eq!(code, Some(0));
    let (r, ctl, h) = (read_report(&fx.file("b.txt")), read_report(&fx.file("b.c")), read_report(&fx.file("b.h")));
    eprintln!("{r} | control: {ctl} | holder: {h}");
    assert!(r.contains("ctl=0") && r.contains("h=0"), "{r}");
    assert!(ctl.contains("remote=0") && remote.join("c.sock").exists(), "control: a process holding nothing binds a socket on the mount: {ctl}");
    assert!(h.contains("local=0") && fx.file("h.sock").exists(), "a holder binds a socket on a local disk: {h}");
    assert!(h.contains(&format!("remote={}", libc::EACCES)), "a holder's bind on the mount is refused: {h}");
    assert!(std::fs::symlink_metadata(remote.join(format!("h_{CANARY}.sock"))).is_err(), "THE LEAK: the holder's socket name reached the mount");
    let _ = std::fs::remove_dir_all(&remote);
    eprintln!("R4b BIND PASS");
}

// ── (T) times and owner ─────────────────────────────────────────────────────

/// The holder's time stamp: 4242 seconds, a value no file here has.
const T_HOLDER: i64 = 4242;

/// Every owner and timestamp form on `dir/victim.txt` (and `dir/link`, a
/// symlink to it, for the no-follow forms), each errno. The owner calls set
/// the caller's own group (a no-op the server sees all the same).
fn time_owner_calls(dir: &Path, secs: i64) -> Vec<String> {
    let victim = cpath(&dir.join("victim.txt"));
    let link = cpath(&dir.join("link"));
    let last = || std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
    let rc = |r: libc::c_int| if r == 0 { 0 } else { last() };
    let rcl = |r: libc::c_long| if r == 0 { 0 } else { last() };
    let ts = [libc::timespec { tv_sec: secs as _, tv_nsec: 0 }, libc::timespec { tv_sec: secs as _, tv_nsec: 0 }];
    // SAFETY: NUL-terminated paths, our own buffers, a descriptor we opened.
    unsafe {
        let gid = libc::getgid();
        let ro = libc::open(victim.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        let mut v = vec![
            format!("ro_open={}", if ro >= 0 { 0 } else { last() }),
            format!("utimensat={}", rc(libc::utimensat(libc::AT_FDCWD, victim.as_ptr(), ts.as_ptr(), 0))),
            format!("utimensat_l={}", rc(libc::utimensat(libc::AT_FDCWD, link.as_ptr(), ts.as_ptr(), libc::AT_SYMLINK_NOFOLLOW))),
            format!("futimens={}", rc(libc::futimens(ro, ts.as_ptr()))),
            format!("fchownat={}", rc(libc::fchownat(libc::AT_FDCWD, victim.as_ptr(), u32::MAX, gid, 0))),
            format!("fchownat_l={}", rc(libc::fchownat(libc::AT_FDCWD, link.as_ptr(), u32::MAX, gid, libc::AT_SYMLINK_NOFOLLOW))),
            format!("fchown={}", rc(libc::fchown(ro, u32::MAX, gid))),
        ];
        #[cfg(target_arch = "x86_64")]
        {
            let ub = [secs, secs];
            let tv = [libc::timeval { tv_sec: secs as _, tv_usec: 0 }, libc::timeval { tv_sec: secs as _, tv_usec: 0 }];
            v.push(format!("utime={}", rcl(libc::syscall(libc::SYS_utime, victim.as_ptr(), ub.as_ptr()))));
            v.push(format!("utimes={}", rcl(libc::syscall(libc::SYS_utimes, victim.as_ptr(), tv.as_ptr()))));
            v.push(format!("futimesat={}", rcl(libc::syscall(libc::SYS_futimesat, libc::AT_FDCWD, victim.as_ptr(), tv.as_ptr()))));
            v.push(format!("chown={}", rcl(libc::syscall(libc::SYS_chown, victim.as_ptr(), u32::MAX, gid))));
            v.push(format!("lchown={}", rcl(libc::syscall(libc::SYS_lchown, link.as_ptr(), u32::MAX, gid))));
        }
        let _ = rcl;
        if ro >= 0 {
            libc::close(ro);
        }
        v
    }
}

fn time_owner_names() -> Vec<&'static str> {
    let mut v = vec!["utimensat", "utimensat_l", "futimens", "fchownat", "fchownat_l", "fchown"];
    if cfg!(target_arch = "x86_64") {
        v.extend(["utime", "utimes", "futimesat", "chown", "lchown"]);
    }
    v
}

fn seed_times(dir: &Path) {
    std::fs::write(dir.join("victim.txt"), "V\n").unwrap();
    let _ = std::fs::remove_file(dir.join("link"));
    std::os::unix::fs::symlink(dir.join("victim.txt"), dir.join("link")).unwrap();
}

/// P0 5c (2026-10-07): a holder's timestamps (about 128 bits per call) and
/// owner on a mount that leaves the machine ran free (`utimensat`, the
/// `chown` family: not in any trapped list). Now judged like its other
/// attribute changes there, by path, by descriptor and without following.
#[test]
#[ignore]
fn a_holders_times_and_owner_on_a_mount_that_leaves_the_machine_are_refused() {
    let _g = serial();
    let fx = Fixture::new("times", None);
    let Some((remote, dev)) = remote_dir(&fx, "t") else {
        eprintln!("SKIP: no second file system at /dev/shm");
        return;
    };
    let local = fx.file("localdir");
    std::fs::create_dir_all(&local).unwrap();
    seed_times(&remote);
    seed_times(&local);
    let dir = std::fs::File::open(&remote).unwrap();
    let facts = net_supervisor::local_exits::fd_fs_facts(dir.as_raw_fd(), None);
    let net_supervisor::local_exits::MountVerdict::Remote(dest) = net_supervisor::local_exits::mount_verdict(&facts, &[dev]) else { panic!("{facts:?}") };
    let run = |bindings: Vec<String>, out: PathBuf| {
        let arb = arbiter(bindings);
        let mut c = cfg(&fx, arb);
        c.extra_remote_devs = vec![dev];
        let (secret, remote, local) = (fx.secret.clone(), remote.clone(), local.clone());
        guarded(c, move || {
            // The control: a process holding nothing, on the mount (it sets
            // 1111, the stamp the holder's calls must leave in place).
            let (r2, cp) = (remote.clone(), out.with_extension("c"));
            let ctl = fork_run(move || {
                report(&cp, &time_owner_calls(&r2, 1111));
                0
            });
            let ctl = reap(ctl).unwrap_or(-1);
            let (sec, hp) = (secret.clone(), out.with_extension("h"));
            let h = fork_run(move || {
                if !take_secret(&sec) {
                    return 3;
                }
                let mut lines = time_owner_calls(&remote, T_HOLDER);
                lines.extend(time_owner_calls(&local, T_HOLDER).into_iter().map(|l| format!("local_{l}")));
                report(&hp, &lines);
                0
            });
            let h = reap(h).unwrap_or(-1);
            report(&out, &[format!("ctl={ctl}"), format!("h={h}")]);
            0
        })
    };
    let out = fx.file("t.txt");
    let Some(code) = run(vec!["127.0.0.2".into()], out.clone()) else {
        let _ = std::fs::remove_dir_all(&remote);
        return;
    };
    assert_eq!(code, Some(0));
    let (r, ctl, h) = (read_report(&out), read_report(&out.with_extension("c")), read_report(&out.with_extension("h")));
    eprintln!("{r} | control: {ctl} | holder: {h}");
    assert!(r.contains("ctl=0") && r.contains("h=0"), "{r}");
    let has = |text: &str, line: String| text.lines().any(|l| l == line);
    assert!(has(&h, "ro_open=0".into()), "a holder opens the mount's file read-only (not gated): {h}");
    for call in time_owner_names() {
        assert!(has(&ctl, format!("{call}=0")), "control: a non-holder's {call} on the mount runs: {ctl}");
        assert!(has(&h, format!("local_{call}=0")), "a holder's {call} on a local disk runs: {h}");
        assert!(has(&h, format!("{call}={}", libc::EACCES)), "a holder's {call} on the mount is refused: {h}");
    }
    let mtime = |p: &Path| std::fs::symlink_metadata(p).map(|m| m.mtime()).unwrap_or(-1);
    assert_eq!(mtime(&remote.join("victim.txt")), 1111, "THE LEAK: the holder's time stamp reached the mount");
    assert_eq!(mtime(&remote.join("link")), 1111, "THE LEAK: the holder's time stamp reached the mount's symlink");
    assert_eq!(mtime(&local.join("victim.txt")), T_HOLDER, "the holder's stamp on a local disk is set");
    assert_eq!(mtime(&local.join("link")), T_HOLDER, "the no-follow form stamps the local symlink itself");

    // Bound to the mount: the holder's calls run there.
    seed_times(&remote);
    let Some(code) = run(vec![dest.clone()], fx.file("tb.txt")) else { return };
    assert_eq!(code, Some(0));
    let h = read_report(&fx.file("tb.h"));
    eprintln!("bound to {dest}: {h}");
    for call in time_owner_names() {
        assert!(has(&h, format!("{call}=0")), "bound: the holder's {call} on the mount runs: {h}");
    }
    assert_eq!(mtime(&remote.join("victim.txt")), T_HOLDER, "bound: the holder's stamp is set");
    let _ = std::fs::remove_dir_all(&remote);
    eprintln!("R4b TIMES PASS");
}

// ── (V) a network or FUSE mount visible to a reader (plan 13 §4.9) ──────────

/// What a read of the secret got: the real file, the twin, or the errno.
fn what_was_read(secret: &Path) -> String {
    match std::fs::read_to_string(secret) {
        Ok(t) if t.contains(CANARY) => "raw".into(),
        Ok(t) if t.contains("$MDU:twin") => "twin".into(),
        Ok(t) => format!("other:{}", t.len()),
        Err(e) => format!("errno:{}", e.raw_os_error().unwrap_or(-1)),
    }
}

/// Every reader is granted raw; a holder's bindings are `bindings` (`None`:
/// the arbiter cannot say them); the events' reasons are kept in `emitted`.
fn arbiter_v(bindings: Option<Vec<String>>, emitted: Arc<Mutex<Vec<String>>>) -> &'static MockArbiter {
    MockArbiter::start(op_handler(move |op, req| match op {
        "decideSecretOpen" => Ok(serde_json::json!({ "verdict": "raw", "app": "test", "level": "no-model", "reason": "mock reader" })),
        "taintedProcessBindings" => match &bindings {
            Some(b) => Ok(serde_json::json!({ "tainted": true, "level": "no-model", "files": ["secret.env"], "bindings": b })),
            None => Err("the arbiter cannot say".into()),
        },
        "emit" => {
            if let Some(r) = req.pointer("/event/policy/reason").and_then(|v| v.as_str()) {
                emitted.lock().unwrap().push(r.to_string());
            }
            Ok(serde_json::json!({ "ok": true }))
        }
        _ => Ok(serde_json::Value::Null),
    }))
    .leak()
}

/// The destinations (`mount:<fstype>:<source>`) of the mounts of device `dev`.
fn dests_of(dev: u64) -> Vec<String> {
    let mi = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    net_supervisor::visible_mounts::parse_rows(&mi).into_iter().filter(|r| r.dev == dev).map(|r| net_supervisor::local_exits::mount_destination(&r.row.fstype, &r.row.source)).collect()
}

/// One reader under the guard: what it read, and whether, holding what it
/// read, it could then create a file on the "remote" mount (a reader served
/// the twin holds nothing, so it may). `None`: SKIP.
fn read_case(fx: &Fixture, devs: Vec<u64>, bindings: Option<Vec<String>>, remote: &Path) -> Option<(String, String, Vec<String>)> {
    let emitted = Arc::new(Mutex::new(Vec::new()));
    let arb = arbiter_v(bindings, emitted.clone());
    let mut c = cfg(fx, arb);
    c.extra_remote_devs = devs;
    let out = fx.file("v.txt");
    let _ = std::fs::remove_file(&out);
    let (secret, o, r) = (fx.secret.clone(), out.clone(), remote.to_path_buf());
    let code = guarded(c, move || {
        let p = fork_run(move || {
            let got = what_was_read(&secret);
            let wrote = errno_of(std::fs::write(r.join(format!("w-{}.txt", std::process::id())), "AFTER\n"));
            report(&o, &[got, format!("write={wrote}")]);
            0
        });
        reap(p).unwrap_or(-1)
    })?;
    assert_eq!(code, Some(0));
    let text = read_report(&out);
    let mut lines = text.lines();
    let got = lines.next().unwrap_or("").to_string();
    let wrote = lines.next().unwrap_or("").to_string();
    let ev = emitted.lock().unwrap().clone();
    Some((got, wrote, ev))
}

#[test]
#[ignore]
fn a_raw_open_is_withheld_while_an_unbound_network_mount_is_visible() {
    let _g = serial();
    let fx = Fixture::build("visible", None, Vec::new());
    let Some((remote, dev)) = remote_dir(&fx, "v") else {
        eprintln!("SKIP: no second file system at /dev/shm");
        return;
    };
    let dests = dests_of(dev);
    assert!(!dests.is_empty(), "the test file system is a mount of its own");

    // (V1) visible, untrusted, unbound: the twin, the event names it, and the
    // reader holds nothing (it writes on the mount).
    let Some((got, wrote, ev)) = read_case(&fx, vec![dev], Some(vec!["127.0.0.2".into()]), &remote) else { return };
    eprintln!("visible: {got} {wrote} {ev:?}");
    assert_eq!(got, "twin", "THE LEAK: a reader got the real file while a network mount it can look names up on is visible");
    assert_eq!(wrote, "write=0", "a reader served the twin holds nothing");
    assert!(ev.iter().any(|r| r.contains("REAL FILE WITHHELD") && r.contains("remote-mount-visible") && r.contains(&dests[0])), "{ev:?}");

    // (V2) the arbiter cannot say the bindings: withheld (fail-closed).
    let Some((got, _, _)) = read_case(&fx, vec![dev], None, &remote) else { return };
    assert_eq!(got, "twin", "THE LEAK: raw with the bindings unknown");

    // (V3) bound to the mount (every row of it): raw.
    let Some((got, _, _)) = read_case(&fx, vec![dev], Some(dests.clone()), &remote) else { return };
    assert_eq!(got, "raw", "bound to the mount: the reader gets the real file");

    // (V4) trusted for lookups in policy.yaml: raw; it is a holder, and the
    // trust admits no write there.
    let trusted = Fixture::build("visible-t", None, shm_trust());
    let Some((got, wrote, ev)) = read_case(&trusted, vec![dev], Some(vec!["127.0.0.2".into()]), &remote) else { return };
    eprintln!("trusted: {got} {wrote} {ev:?}");
    assert_eq!(got, "raw", "trusted for lookups: the reader gets the real file");
    assert_eq!(wrote, format!("write={}", libc::EACCES), "the trust is for lookups: a holder's write there is still refused");
    assert!(!ev.iter().any(|r| r.contains("REAL FILE WITHHELD")), "{ev:?}");

    // (V5) no such mount visible: raw (where the host itself shows none).
    let real = net_supervisor::visible_mounts::MountViews::new().visible_for(std::process::id() as i32, &[]).unwrap();
    if real.is_empty() {
        let Some((got, _, _)) = read_case(&fx, Vec::new(), Some(vec!["127.0.0.2".into()]), &remote) else { return };
        assert_eq!(got, "raw", "no network mount visible: the reader gets the real file");
    } else {
        eprintln!("SKIP (V5): this host shows network or FUSE mounts of its own: {real:?}");
    }
    let _ = std::fs::remove_dir_all(&remote);
    eprintln!("R4b VISIBLE MOUNT PASS");
}

#[test]
#[ignore]
fn a_mount_made_after_the_first_look_is_seen_at_the_next_raw_open() {
    let _g = serial();
    let fx = Fixture::new("visible-later", None);
    let Some((remote, dev)) = remote_dir(&fx, "vl") else {
        eprintln!("SKIP: no second file system at /dev/shm");
        return;
    };
    let at = fx.file("m");
    std::fs::create_dir_all(&at).unwrap();
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // A user + mount namespace of the tracee's own, as the launcher's wrap
    // makes, so it can mount after its filter is on.
    let setup = move || {
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            return Some(EXIT_NO_SECCOMP);
        }
        let maps = std::fs::write("/proc/self/setgroups", "deny").is_ok()
            && std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).is_ok()
            && std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).is_ok();
        let root = cpath(Path::new("/"));
        // SAFETY: a NUL-terminated path; our own namespace.
        if !maps || unsafe { libc::mount(std::ptr::null(), root.as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) } != 0 {
            return Some(EXIT_NO_SECCOMP);
        }
        None
    };
    let emitted = Arc::new(Mutex::new(Vec::new()));
    let arb = arbiter_v(Some(vec!["127.0.0.2".into()]), emitted.clone());
    let mut c = cfg(&fx, arb);
    c.extra_remote_devs = vec![dev];
    let (secret, out, src) = (fx.secret.clone(), fx.file("vl.txt"), remote.clone());
    let reader = |secret: PathBuf| reap(fork_run(move || if what_was_read(&secret) == "raw" { 10 } else { 11 })).unwrap_or(-1);
    let Some(code) = guarded_setup(c, setup, move || {
        // Only /dev/shm's own mount (trusted) is visible: raw.
        let first = reader(secret.clone());
        // A bind of the "remote" file system at a point nobody trusts.
        let (s, t) = (cpath(&src), cpath(&at));
        // SAFETY: a bind mount in the tracee's own namespace.
        let bound = unsafe { libc::mount(s.as_ptr(), t.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) } == 0;
        let second = reader(secret.clone());
        // SAFETY: the mount made above.
        let gone = bound && unsafe { libc::umount2(t.as_ptr(), libc::MNT_DETACH) } == 0;
        let third = reader(secret.clone());
        report(&out, &[format!("first={first}"), format!("bound={bound}"), format!("second={second}"), format!("gone={gone}"), format!("third={third}")]);
        0
    }) else {
        let _ = std::fs::remove_dir_all(&remote);
        return;
    };
    let r = read_report(&fx.file("vl.txt"));
    eprintln!("{code:?}: {r} {:?}", emitted.lock().unwrap());
    if code == Some(EXIT_NO_SECCOMP) {
        eprintln!("SKIP: no user namespace with mount rights here");
        let _ = std::fs::remove_dir_all(&remote);
        return;
    }
    assert_eq!(code, Some(0));
    assert!(r.contains("first=10"), "only a trusted mount visible: raw: {r}");
    assert!(r.contains("bound=true"), "{r}");
    assert!(r.contains("second=11"), "THE LEAK: a mount made after the guard first looked was not seen: {r}");
    assert!(r.contains("gone=true") && r.contains("third=10"), "unmounted again: raw again: {r}");
    let _ = std::fs::remove_dir_all(&remote);
    eprintln!("R4b VISIBLE MOUNT LATER PASS");
}

// ── (W) the real file, rewritten by its reader ──────────────────────────────

/// An allow-listed reader (the arbiter answers `raw`) that rewrites its own
/// credentials file shorter (`aws configure`: `open(O_WRONLY|O_CREAT|
/// O_TRUNC)`, then a write) gets the file truncated, as without Mandu. The
/// guard opens the real file on the reader's behalf and used to drop the
/// tracee's `O_TRUNC` (`secret_open::supervisor_open_flags`), so the shorter
/// write left the longer value's tail behind it (2026-10-10, red on the code
/// before). Also `O_RDWR|O_TRUNC`; an append keeps what is there; a
/// reader's `O_RDONLY|O_TRUNC` truncates, as Linux's own open does for an
/// opener that may write (the twin case, where the real file must never
/// change, is guard_integration's
/// `a_read_only_truncating_open_of_a_secret_never_truncates_the_real_file`).
#[test]
#[ignore]
fn a_readers_shorter_rewrite_of_the_real_file_leaves_no_stale_tail() {
    let _g = serial();
    let fx = Fixture::new("rewrite", None);
    let arb = arbiter(Vec::new());
    const LONG: &str = "aws_secret_access_key=LONG-OLD-VALUE-0123456789-0123456789\n";
    const SHORT: &str = "aws_secret_access_key=new\n";
    const RDWR: &str = "k=rw\n";
    let (secret, out) = (fx.secret.clone(), fx.file("w.txt"));
    let code = guarded(cfg(&fx, arb), move || {
        let p = fork_run(move || {
            let text = |p: &Path| std::fs::read_to_string(p).unwrap_or_else(|e| format!("errno {}", e.raw_os_error().unwrap_or(-1)));
            let first = text(&secret);
            let long = errno_of(std::fs::write(&secret, LONG));
            let short = errno_of(std::fs::write(&secret, SHORT));
            let after_short = text(&secret);
            let c = cpath(&secret);
            // SAFETY: a NUL-terminated path; our own descriptor.
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_TRUNC) };
            if fd >= 0 {
                unsafe { libc::write(fd, RDWR.as_ptr() as *const libc::c_void, RDWR.len()) };
                unsafe { libc::close(fd) };
            }
            let after_rdwr = text(&secret);
            let appended = std::fs::OpenOptions::new().append(true).open(&secret).and_then(|mut f| f.write_all(b"+\n")).is_ok();
            let after_append = text(&secret);
            // SAFETY: as above.
            let ro = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_TRUNC) };
            if ro >= 0 {
                unsafe { libc::close(ro) };
            }
            let after_ro = text(&secret);
            report(&out, &[
                format!("first={first:?}"),
                format!("long={long} short={short}"),
                format!("after_short={after_short:?}"),
                format!("rdwr_fd={} after_rdwr={after_rdwr:?}", fd >= 0),
                format!("appended={appended} after_append={after_append:?}"),
                format!("ro_fd={} after_ro={after_ro:?}", ro >= 0),
            ]);
            0
        });
        reap(p).unwrap_or(-1)
    });
    let Some(code) = code else { return };
    assert_eq!(code, Some(0));
    let r = read_report(&fx.file("w.txt"));
    eprintln!("rewrite: {r}");
    assert!(r.contains(&format!("first={:?}", format!("API_KEY={CANARY}\n"))), "the reader was not handed the real file: {r}");
    assert!(r.contains("long=0 short=0"), "the reader's writes failed: {r}");
    assert!(r.contains(&format!("after_short={SHORT:?}")), "THE STALE TAIL: a reader's shorter rewrite kept the longer value's tail: {r}");
    assert!(r.contains(&format!("rdwr_fd=true after_rdwr={RDWR:?}")), "an O_RDWR|O_TRUNC rewrite kept a stale tail: {r}");
    assert!(r.contains(&format!("appended=true after_append={:?}", format!("{RDWR}+\n"))), "an append keeps what is there: {r}");
    assert!(r.contains("ro_fd=true after_ro=\"\""), "a reader's O_RDONLY|O_TRUNC truncates as the kernel's would: {r}");
    eprintln!("R4b READER REWRITE PASS");
}
