//! derived_label_integration — confidentiality plan 13 D4 at the guard: a
//! DERIVED file (a copy a process holding a secret wrote) is gated at the
//! open like a labelled file with no reader list, during the session, and
//! its label follows `rename` and `link`.
//!
//! Before the fix the guard loaded its secret index once at start and
//! nothing added a derived path to it, so every program opened such a copy
//! raw (`curl --data @copy.txt`); each test below failed that way.
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! (an unprivileged user namespace). A host where the seccomp listener cannot
//! be installed SKIPs. The arbiter is a mock that lists the derived paths
//! (`derivedLabelsSince`), answers the twin at the gate (`decideSecretOpen`),
//! mints the twin text (`registerSecret`) and records `followDerivedLabel`.
//!
//!   (a) a derived copy known at the guard's start is served its twin, never
//!       its bytes; an ordinary file still reads raw (the control);
//!   (b) a copy labelled AFTER the guard's first look (the list changes) is
//!       gated too: the guard asks again for a file changed since;
//!   (c) the label follows a rename and a hard link the guard performs (the
//!       arbiter is told before the change runs) and a rename it did not
//!       see (the same inode under another name);
//!   (d) with the arbiter unreachable, a file changed in this session is
//!       refused (it may be a copy) and an older one opens as before;
//!   (e) with an arbiter older than the guard, the guard's own labels gate;
//!   (f) the label of a holder's write lands before the writer holds its
//!       descriptor, so a copy read back at once is never raw.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, pipe, readable_within, reap_within, run_tag, socketpair, wait_limit};

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
const CANARY: &str = "D4-DERIVED-CANARY-7731";
const TWIN: &str = "API_KEY=$MDU:nomodel_Read[d4d4]\n";

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

/// Run `body` in a forked child under the guard's filter, served by the real
/// supervisor loop with `cfg`; `parent` runs beside it in the test process
/// (the other side of the pipes the child keeps), given the child's pid for
/// its waits' deadlines. The child's exit code, or
/// None to SKIP.
fn guarded(
    cfg: GuardConfig,
    keep: &[RawFd],
    body: impl FnOnce() -> i32,
    parent: impl FnOnce(i32),
) -> Option<Option<i32>> {
    let (sup, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let mut k = keep.to_vec();
        k.push(child_sock);
        close_all_but(&k);
        let traps = FilterTraps { open: true, secrets: true, protect: true, ..Default::default() };
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
    parent(child);
    let code = reap(child);
    let _ = join_within(server, wait_limit(), "the guard supervisor (run_guard_supervisor), after its tracee exited");
    unsafe { libc::close(sup) };
    Some(code)
}

struct Fixture {
    dir: PathBuf,
    policy: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("mandu-d4-{tag}-{}", run_tag()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // One registered secret, so the index is a real launch's shape.
        let secret = dir.join("secret.env");
        let twin = dir.join("twin.env");
        std::fs::write(&secret, format!("API_KEY={CANARY}\n")).unwrap();
        std::fs::write(&twin, "API_KEY=$MDU:twin\n").unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(&policy, format!(r#"{{"agentExe":"","ask":"never","session":"d4","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, secret.display(), twin.display())).unwrap();
        Fixture { dir, policy }
    }
    fn file(&self, name: &str, content: &str) -> PathBuf {
        let p = self.dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }
    fn cfg(&self, sock: &Path) -> GuardConfig {
        let specs = vec!["any:127.0.0.0/8:*".to_string()];
        let mut cfg = GuardConfig::new(Arc::new(GuardPolicy::new(parse_rules(&specs).unwrap())), Arc::new(NoResolver));
        cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(&self.policy).unwrap()));
        cfg.emitter = Some(Arc::new(Mutex::new(mandu_arbiter::ArbiterClient::new(sock))));
        cfg
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What the mock arbiter saw and serves.
#[derive(Default)]
struct Book {
    /// (path, level) listed by `derivedLabelsSince`, and from which call on.
    labels: Vec<(String, String, usize)>,
    since_calls: usize,
    follows: Vec<(String, String, String)>,
    decided: Vec<String>,
}

/// A mock arbiter over `book`. Leaked on purpose (the supervisor's client
/// outlives the test body in some paths).
fn arbiter(book: Arc<Mutex<Book>>) -> &'static MockArbiter {
    MockArbiter::start(op_handler(move |op, req| {
        let mut b = book.lock().unwrap();
        match op {
            "derivedLabelsSince" => {
                b.since_calls += 1;
                let n = b.since_calls;
                let labels: Vec<serde_json::Value> = b
                    .labels
                    .iter()
                    .filter(|(_, _, from)| n >= *from)
                    .map(|(p, l, _)| serde_json::json!({ "path": p, "level": l }))
                    .collect();
                // a new epoch every time: the guard takes every row each answer
                Ok(serde_json::json!({ "epoch": format!("e{n}"), "gen": n, "labels": labels }))
            }
            "decideSecretOpen" => {
                b.decided.push(req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string());
                Ok(serde_json::json!({ "verdict": "twin", "app": "test", "level": "no-model", "reason": "no reader list on a derived file" }))
            }
            "registerSecret" => Ok(serde_json::json!({ "symbol": "$MDU:nomodel_Read[d4d4]", "reason": "registered", "twin": TWIN })),
            "followDerivedLabel" => {
                let s = |k: &str| req.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                b.follows.push((s("from"), s("to"), s("how")));
                Ok(serde_json::json!({ "labeled": true, "level": "no-model", "reason": "follows" }))
            }
            _ => Ok(serde_json::Value::Null),
        }
    })).leak()
}

fn read(p: &Path) -> Result<String, i32> {
    std::fs::read_to_string(p).map_err(|e| e.raw_os_error().unwrap_or(-1))
}

/// The child's report: one line per probe, written to `out`.
fn report(out: &Path, lines: &[String]) {
    let _ = std::fs::write(out, lines.join("\n"));
}

// ── (a) a derived copy at the guard's start ─────────────────────────────────

#[test]
#[ignore]
fn a_derived_copy_is_served_its_twin_never_its_bytes() {
    let fx = Fixture::new("a");
    let copy = fx.file("copy.txt", &format!("API_KEY={CANARY}\n"));
    let plain = fx.file("plain.txt", "PLAIN-CONTROL\n");
    let book = Arc::new(Mutex::new(Book::default()));
    book.lock().unwrap().labels.push((copy.to_str().unwrap().into(), "no-model".into(), 1));
    let arb = arbiter(book.clone());
    let out = fx.dir.join("report.txt");
    let (c, p, o) = (copy.clone(), plain.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), &[], move || {
        let lines = vec![format!("copy={:?}", read(&c)), format!("plain={:?}", read(&p))];
        report(&o, &lines);
        0
    }, |_| {}) else { return };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(!r.contains(CANARY), "the derived copy was read raw: {r}");
    assert!(r.contains("$MDU:nomodel_Read[d4d4]"), "the twin was not served: {r}");
    assert!(r.contains("PLAIN-CONTROL"), "an ordinary file must still read raw: {r}");
    assert!(book.lock().unwrap().decided.iter().any(|d| d == copy.to_str().unwrap()), "the arbiter decided the copy's open");
}

// ── (b) a copy labelled after the guard's first look ────────────────────────

#[test]
#[ignore]
fn a_copy_labelled_after_the_first_look_is_gated_too() {
    let fx = Fixture::new("b");
    let plain = fx.file("plain.txt", "PLAIN-CONTROL\n");
    let late = fx.dir.join("late.txt");
    let book = Arc::new(Mutex::new(Book::default()));
    // listed from the SECOND read of the list on: the first open (plain.txt)
    // reads it before the copy exists
    book.lock().unwrap().labels.push((late.to_str().unwrap().into(), "no-model".into(), 2));
    let arb = arbiter(book.clone());
    let out = fx.dir.join("report.txt");
    let (p, l, o) = (plain.clone(), late.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), &[], move || {
        let first = read(&p);
        // a writer makes the copy (write-only: not gated)
        let wrote = std::fs::write(&l, format!("API_KEY={CANARY}\n")).is_ok();
        let lines = vec![format!("first={first:?}"), format!("wrote={wrote}"), format!("late={:?}", read(&l))];
        report(&o, &lines);
        0
    }, |_| {}) else { return };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("wrote=true"), "{r}");
    assert!(!r.contains(CANARY), "a copy labelled after the guard's first look was read raw: {r}");
    assert!(r.contains("$MDU:nomodel_Read[d4d4]"), "{r}");
    assert!(book.lock().unwrap().since_calls >= 2, "the guard asked again for a file changed since its first look");
}

// ── (c) the label follows the file ──────────────────────────────────────────

#[test]
#[ignore]
fn the_label_follows_rename_and_link_and_an_unseen_rename() {
    let fx = Fixture::new("c");
    let copy = fx.file("copy.txt", &format!("API_KEY={CANARY}\n"));
    let other = fx.file("other.txt", &format!("API_KEY={CANARY}\n"));
    let plain = fx.file("plain.txt", "PLAIN-CONTROL\n");
    let book = Arc::new(Mutex::new(Book::default()));
    {
        let mut b = book.lock().unwrap();
        b.labels.push((copy.to_str().unwrap().into(), "no-model".into(), 1));
        b.labels.push((other.to_str().unwrap().into(), "no-model".into(), 1));
    }
    let arb = arbiter(book.clone());
    let out = fx.dir.join("report.txt");
    let moved = fx.dir.join("moved.txt");
    let linked = fx.dir.join("linked.txt");
    let away = fx.dir.join("away.txt");
    // child → parent: "renamed other.txt yet?"; parent → child: "done"
    let (ask_r, ask_w) = pipe();
    let (done_r, done_w) = pipe();
    let (c, m, l, a, p, o, ot) = (copy.clone(), moved.clone(), linked.clone(), away.clone(), plain.clone(), out.clone(), other.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), &[ask_w, done_r], move || {
        let mut lines = vec![format!("plain={:?}", read(&p))];
        lines.push(format!("rename={:?}", std::fs::rename(&c, &m).map_err(|e| e.raw_os_error())));
        lines.push(format!("moved={:?}", read(&m)));
        lines.push(format!("link={:?}", std::fs::hard_link(&m, &l).map_err(|e| e.raw_os_error())));
        lines.push(format!("linked={:?}", read(&l)));
        // the parent renames other.txt (a rename the guard does not see)
        unsafe { libc::write(ask_w, b"r".as_ptr() as *const libc::c_void, 1) };
        let mut b = [0u8; 1];
        unsafe { libc::read(done_r, b.as_mut_ptr() as *mut libc::c_void, 1) };
        lines.push(format!("away={:?}", read(&a)));
        let _ = ot;
        report(&o, &lines);
        0
    }, |child| {
        let mut b = [0u8; 1];
        readable_within(ask_r, child, wait_limit(), "waiting for the tracee to ask for the rename");
        unsafe { libc::read(ask_r, b.as_mut_ptr() as *mut libc::c_void, 1) };
        std::fs::rename(&other, &away).unwrap();
        // the rename's ctime must be past the guard's last look
        std::thread::sleep(Duration::from_millis(10));
        unsafe { libc::write(done_w, b"d".as_ptr() as *const libc::c_void, 1) };
    }) else { return };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("PLAIN-CONTROL"), "{r}");
    assert!(r.contains("rename=Ok(())") && r.contains("link=Ok(())"), "rename and link of a derived file still work: {r}");
    assert!(!r.contains(CANARY), "a moved, linked or renamed-elsewhere copy was read raw: {r}");
    assert_eq!(r.matches("$MDU:nomodel_Read[d4d4]").count(), 3, "moved, linked and away all get the twin: {r}");
    let follows = book.lock().unwrap().follows.clone();
    let has = |from: &Path, to: &Path, how: &str| follows.iter().any(|(f, t, h)| f == from.to_str().unwrap() && t == to.to_str().unwrap() && h == how);
    assert!(has(&copy, &moved, "rename"), "the arbiter was told of the rename: {follows:?}");
    assert!(has(&moved, &linked, "link"), "the arbiter was told of the link: {follows:?}");
    assert!(has(&other, &away, "identity"), "a rename the guard did not see is caught by the file's identity: {follows:?}");
    for fd in [ask_r, ask_w, done_r, done_w] {
        unsafe { libc::close(fd) };
    }
}

// ── (e) an arbiter older than the guard ─────────────────────────────────────

/// An arbiter that cannot list derived labels (it answers null, as an older
/// one's `unknown op` is read): fresh files open as before (no refusal storm),
/// and the copy the guard labels itself, from its own write exit, is gated.
#[test]
#[ignore]
fn with_an_older_arbiter_the_guards_own_labels_still_gate() {
    let fx = Fixture::new("e");
    let secret = fx.dir.join("secret.env");
    let copy = fx.dir.join("copy.txt");
    let fresh = fx.dir.join("fresh.txt");
    let arb: &'static MockArbiter = MockArbiter::start(op_handler(move |op, req| {
        let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        match op {
            // the reader: raw for the registered secret, the twin for anything else
            "decideSecretOpen" if path.ends_with("secret.env") => Ok(serde_json::json!({ "verdict": "raw", "app": "test", "level": "no-model", "reason": "mock reader" })),
            "decideSecretOpen" => Ok(serde_json::json!({ "verdict": "twin", "app": "test", "level": "no-model", "reason": "no reader list" })),
            "labelWrittenPathTainted" => Ok(serde_json::json!({ "labeled": true, "level": "no-model", "reason": "written by a reader" })),
            "registerSecret" => Ok(serde_json::json!({ "symbol": "$MDU:nomodel_Read[d4d4]", "reason": "registered", "twin": TWIN })),
            "taintedProcessBindings" => Ok(serde_json::json!({ "tainted": true, "level": "no-model", "files": [path], "bindings": [] })),
            _ => Ok(serde_json::Value::Null),
        }
    })).leak();
    let out = fx.dir.join("report.txt");
    let (s, c, f, o) = (secret.clone(), copy.clone(), fresh.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), &[], move || {
        let wrote_fresh = std::fs::write(&f, "FRESH-CONTROL\n").is_ok();
        let fresh = read(&f);
        // the reader copies the secret: the guard labels the copy itself
        let raw = read(&s);
        let copied = raw.as_ref().map(|k| std::fs::write(&c, k).is_ok()).unwrap_or(false);
        let lines = vec![
            format!("wrote_fresh={wrote_fresh}"),
            format!("fresh={fresh:?}"),
            format!("raw_has_key={}", raw.map(|k| k.contains(CANARY)).unwrap_or(false)),
            format!("copied={copied}"),
            format!("copy={:?}", read(&c)),
        ];
        report(&o, &lines);
        0
    }, |_| {}) else { return };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("FRESH-CONTROL"), "a fresh file opens as before with an arbiter that cannot list labels: {r}");
    assert!(r.contains("raw_has_key=true") && r.contains("copied=true"), "the reader read the key and wrote the copy: {r}");
    assert!(r.contains("copy=Ok(\"API_KEY=$MDU:nomodel_Read[d4d4]"), "the copy the guard labelled is served its twin: {r}");
    assert!(std::fs::read_to_string(&copy).unwrap().contains(CANARY), "the real copy holds the key (the flow the label must follow)");
}

// ── (f) the label lands before the writer holds its descriptor ─────────────

/// The writer's label is in the guard's index before its write-open returns
/// (2026-10-02). Labelled after the answer, as built until then, a reader
/// that wrote its copy and read it back at once (`cp .env c; cat c`) could
/// win the race to the arbiter and read the copy raw: (e) above failed so on
/// master under load (pipelines 8097 and 8099), and the live
/// derived-label-live printed the key (8105). Deterministic: the mock
/// arbiter marks the label's arrival and answers it only 300 ms later, so a
/// guard that answers the open first hands the writer its descriptor before
/// the mark exists.
#[test]
#[ignore]
fn the_label_lands_before_the_writer_gets_its_descriptor() {
    let fx = Fixture::new("f");
    let secret = fx.dir.join("secret.env");
    let copy = fx.dir.join("copy.txt");
    let mark = fx.dir.join("label-arrived");
    let m = mark.clone();
    let arb: &'static MockArbiter = MockArbiter::start(op_handler(move |op, req| {
        let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        match op {
            "decideSecretOpen" if path.ends_with("secret.env") => Ok(serde_json::json!({ "verdict": "raw", "app": "test", "level": "no-model", "reason": "mock reader" })),
            "decideSecretOpen" => Ok(serde_json::json!({ "verdict": "twin", "app": "test", "level": "no-model", "reason": "no reader list" })),
            "labelWrittenPathTainted" => {
                std::thread::sleep(Duration::from_millis(300));
                let _ = std::fs::write(&m, "");
                Ok(serde_json::json!({ "labeled": true, "level": "no-model", "reason": "written by a reader" }))
            }
            "registerSecret" => Ok(serde_json::json!({ "symbol": "$MDU:nomodel_Read[d4d4]", "reason": "registered", "twin": TWIN })),
            "taintedProcessBindings" => Ok(serde_json::json!({ "tainted": true, "level": "no-model", "files": [path], "bindings": [] })),
            // a current arbiter's list, empty: only the guard's own label gates
            "derivedLabelsSince" => Ok(serde_json::json!({ "epoch": "e1", "gen": 0, "labels": [] })),
            _ => Ok(serde_json::Value::Null),
        }
    })).leak();
    let out = fx.dir.join("report.txt");
    let (s, c, mk, o) = (secret.clone(), copy.clone(), mark.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), &[], move || {
        use std::io::Write;
        let raw = read(&s);
        let mut lines = vec![format!("raw_has_key={}", raw.as_ref().map(|k| k.contains(CANARY)).unwrap_or(false))];
        match std::fs::File::create(&c) {
            Ok(mut f) => {
                // the descriptor is the writer's now: was the label in first?
                lines.push(format!("labelled_before_fd={}", mk.exists()));
                lines.push(format!("wrote={}", f.write_all(raw.unwrap_or_default().as_bytes()).is_ok()));
            }
            Err(e) => lines.push(format!("create={e}")),
        }
        lines.push(format!("copy={:?}", read(&c)));
        report(&o, &lines);
        0
    }, |_| {}) else { return };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("raw_has_key=true") && r.contains("wrote=true"), "the reader read the key and wrote the copy: {r}");
    assert!(r.contains("labelled_before_fd=true"), "the writer held its descriptor before the copy's label reached the arbiter: {r}");
    assert!(r.contains("copy=Ok(\"API_KEY=$MDU:nomodel_Read[d4d4]"), "the copy read back at once is served its twin: {r}");
    assert!(!r.contains(CANARY), "the copy was read raw: {r}");
}

// ── (d) the arbiter unreachable ─────────────────────────────────────────────

#[test]
#[ignore]
fn an_unreachable_arbiter_refuses_a_file_changed_in_the_session_only() {
    let fx = Fixture::new("d");
    let old = fx.file("old.txt", "OLD-CONTROL\n");
    // older than the guard by more than the slack
    std::thread::sleep(Duration::from_millis(2_300));
    let dead = fx.dir.join("no-arbiter.sock");
    let cfg = fx.cfg(&dead);
    let out = fx.dir.join("report.txt");
    let fresh = fx.dir.join("fresh.txt");
    let (od, f, o) = (old.clone(), fresh.clone(), out.clone());
    let Some(code) = guarded(cfg, &[], move || {
        let wrote = std::fs::write(&f, format!("API_KEY={CANARY}\n")).is_ok();
        let lines = vec![format!("wrote={wrote}"), format!("fresh={:?}", read(&f)), format!("old={:?}", read(&od))];
        report(&o, &lines);
        0
    }, |_| {}) else { return };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("wrote=true"), "{r}");
    assert!(r.contains(&format!("fresh=Err({})", libc::EACCES)), "a file changed in this session is refused while its label cannot be checked: {r}");
    assert!(r.contains("OLD-CONTROL"), "a file older than the guard opens as before: {r}");
}

// ── (g) a derived twin's descriptor reports its file's identity ─────────────

/// `(dev, ino)` of a `struct stat`.
/// The empty path of a descriptor stat.
const EMPTY: &[u8] = b"\0";

fn ident(st: &libc::stat) -> (u64, u64) {
    (st.st_dev as u64, st.st_ino as u64)
}

/// Plan 13 D4 (2026-10-04): Claude Code 2.1.288 reads a Bash call's output
/// back from its task file the way this child does: `lstat` the path, open
/// it `O_NOFOLLOW`, `fstat` the descriptor and refuse it unless `st_dev` and
/// `st_ino` agree ("output file identity changed"). A holder wrote that file,
/// so the agent is served its twin, by descriptor, on another inode: before
/// the fix every such check failed and the call's output was lost. Now the
/// twin's descriptor sits at `TWIN_FD_BASE` or above and every descriptor
/// stat of it (`fstat`, `newfstatat` and `statx` with `AT_EMPTY_PATH`)
/// reports the derived file's identity with the twin's own size, what a read
/// returns; the bytes stay the twin's. A plain file's descriptor is the
/// ordinary lowest number (the control).
#[test]
#[ignore]
fn a_derived_twins_descriptor_reports_the_identity_of_its_file() {
    use std::os::unix::ffi::OsStrExt;
    let fx = Fixture::new("g");
    let copy = fx.file("task.output", &format!("API_KEY={CANARY}\n"));
    let plain = fx.file("plain.txt", "PLAIN-CONTROL\n");
    let book = Arc::new(Mutex::new(Book::default()));
    book.lock().unwrap().labels.push((copy.to_str().unwrap().into(), "no-model".into(), 1));
    let arb = arbiter(book.clone());
    let out = fx.dir.join("report.txt");
    let (c, p, o) = (copy.clone(), plain.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), &[], move || {
        // The soft limit up to the hard one, as Bun (Claude Code) sets it.
        let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
        rl.rlim_cur = rl.rlim_max;
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) };
        let mut lines = Vec::new();
        for (name, path) in [("copy", &c), ("plain", &p)] {
            let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            let mut l: libc::stat = unsafe { std::mem::zeroed() };
            unsafe { libc::lstat(cpath.as_ptr(), &mut l) };
            let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
            if fd < 0 {
                lines.push(format!("{name}_open_errno={}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)));
                continue;
            }
            let mut f: libc::stat = unsafe { std::mem::zeroed() };
            let frc = unsafe { libc::fstat(fd, &mut f) };
            let mut n: libc::stat = unsafe { std::mem::zeroed() };
            let nrc = unsafe { libc::fstatat(fd, EMPTY.as_ptr() as *const libc::c_char, &mut n, libc::AT_EMPTY_PATH) };
            let mut x: libc::statx = unsafe { std::mem::zeroed() };
            let xrc = unsafe { libc::statx(fd, EMPTY.as_ptr() as *const libc::c_char, libc::AT_EMPTY_PATH, libc::STATX_BASIC_STATS, &mut x) };
            let xdev = libc::makedev(x.stx_dev_major, x.stx_dev_minor) as u64;
            let mut buf = vec![0u8; 4096];
            let got = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            let text = String::from_utf8_lossy(&buf[..got.max(0) as usize]).to_string();
            lines.push(format!("{name}_fd={fd}"));
            lines.push(format!("{name}_rc={frc},{nrc},{xrc}"));
            lines.push(format!("{name}_same_fstat={}", ident(&f) == ident(&l)));
            lines.push(format!("{name}_same_fstatat={}", ident(&n) == ident(&l)));
            lines.push(format!("{name}_same_statx={}", (xdev, x.stx_ino) == ident(&l)));
            lines.push(format!("{name}_size_is_read={}", f.st_size as isize == got && x.stx_size as isize == got && n.st_size as isize == got));
            lines.push(format!("{name}_text={text:?}"));
            unsafe { libc::close(fd) };
        }
        report(&o, &lines);
        0
    }, |_| {}) else { return };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(!r.contains(CANARY), "the derived file was read raw: {r}");
    assert!(r.contains("copy_text=\"API_KEY=$MDU:nomodel_Read[d4d4]"), "the twin was not served: {r}");
    let fd_of = |name: &str| -> i64 { r.lines().find_map(|l| l.strip_prefix(&format!("{name}_fd="))).and_then(|v| v.parse().ok()).unwrap_or(-1) };
    let base = net_supervisor::stat_twin::TWIN_FD_BASE as i64;
    assert!(fd_of("copy") >= base, "the twin's descriptor sits at the twin base: {r}");
    assert!(fd_of("plain") >= 0 && fd_of("plain") < base, "an ordinary open keeps the lowest number: {r}");
    assert!(r.contains("copy_rc=0,0,0"), "{r}");
    for form in ["fstat", "fstatat", "statx"] {
        assert!(r.contains(&format!("copy_same_{form}=true")), "{form} of the twin's descriptor must report the derived file's identity (Claude Code: \"output file identity changed\"): {r}");
        assert!(r.contains(&format!("plain_same_{form}=true")), "{r}");
    }
    assert!(r.contains("copy_size_is_read=true"), "the size is the twin's, what a read returns: {r}");
    assert!(r.contains("plain_text=\"PLAIN-CONTROL"), "{r}");
}

// ── (h) a twin the arbiter renders with no symbol ───────────────────────────

/// Plan 13 D4 (2026-10-04): the arbiter answers `registerSecret` for a
/// derived file holding only the name of an existing directory (Claude
/// Code's cwd file) with its own text as the twin and NO symbol. The guard
/// serves that twin; with neither a twin nor a symbol it still refuses
/// (fail-closed, the answer for anything it cannot render).
#[test]
#[ignore]
fn a_twin_rendered_without_a_symbol_is_served_and_nothing_at_all_refuses() {
    let fx = Fixture::new("h");
    let cwd_file = fx.file("claude-ab12-cwd", "/tmp/sub\n");
    let other = fx.file("other.txt", &format!("API_KEY={CANARY}\n"));
    let (cf, ot) = (cwd_file.to_str().unwrap().to_string(), other.to_str().unwrap().to_string());
    let (cf2, ot2) = (cf.clone(), ot.clone());
    let arb: &'static MockArbiter = MockArbiter::start(op_handler(move |op, req| {
        let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        match op {
            "derivedLabelsSince" => Ok(serde_json::json!({ "epoch": "e1", "gen": 1, "labels": [{ "path": cf2, "level": "no-model" }, { "path": ot2, "level": "no-model" }] })),
            "decideSecretOpen" => Ok(serde_json::json!({ "verdict": "twin", "app": "test", "level": "no-model", "reason": "no reader list" })),
            "registerSecret" if path == cf2 => Ok(serde_json::json!({ "symbol": null, "reason": "a directory name", "twin": "/tmp/sub\n" })),
            "registerSecret" => Ok(serde_json::json!({ "symbol": null, "reason": "unreadable" })),
            _ => Ok(serde_json::Value::Null),
        }
    })).leak();
    let out = fx.dir.join("report.txt");
    let (c, o2, o) = (cwd_file.clone(), other.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), &[], move || {
        report(&o, &[format!("cwd={:?}", read(&c)), format!("other={:?}", read(&o2))]);
        0
    }, |_| {}) else { return };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("cwd=Ok(\"/tmp/sub\\n\")"), "the arbiter's twin is served: {r}");
    assert!(r.contains(&format!("other=Err({})", libc::EACCES)), "no twin and no symbol: refused: {r}");
    assert!(!r.contains(CANARY), "{r}");
}
