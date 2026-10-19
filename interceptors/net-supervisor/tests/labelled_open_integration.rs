//! labelled_open_integration — a file a HUMAN label covers that the launch
//! did not register is gated at the open (2026-10-17, confidentiality.md §6
//! "Read by a program the launch did not see").
//!
//! Before the fix the guard consulted only the launch's registered list and
//! the derived labels, so a labelled file created after the launch (or under
//! a label set mid-session, or past the discovery walk's limits) opened RAW
//! for every program, and a recursive read (`grep -r`, `tar`, `os.walk`)
//! printed it to the model in clear. Each test below that expects the twin
//! failed that way.
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! (an unprivileged user namespace). A host where the seccomp listener cannot
//! be installed SKIPs. The arbiter is a mock that lists the label roots
//! (`labelRootsSince`), classifies a file under one (`labelledLevel`),
//! answers the twin at the gate (`decideSecretOpen`), mints the twin text
//! (`registerSecret`) and records `followDerivedLabel`.
//!
//!   (a) a file created under a labelled folder after the guard started, and
//!       every file a recursive walk reads there, is served its twin; a
//!       nested `public` file, a file in a directory the discovery walk never
//!       enters (`node_modules`) and a file outside every root read raw, and
//!       the last two cost no classification;
//!   (b) a pattern root's shape spares the files it cannot match;
//!   (c) a file under a root the arbiter cannot classify is refused;
//!   (d) with an arbiter older than the guard (no roots) files open as before;
//!   (e) a label set after the guard's first look gates within the refresh;
//!   (f) the label follows a performed rename out from under its folder;
//!   (g) a program's write through the gate (in place, an append, a
//!       truncating write, through a hard link outside the label) lands in a
//!       twin the guard records for the session-end notice, never in the
//!       real file; a file the write creates holds its bytes (red before
//!       2026-10-17's write gate: the append and the truncating write
//!       reached the real file, and no twin was recorded);
//!   (h) a rename onto a labelled file is refused (`sed -i`'s placeholder
//!       text never replaces the real file), onto an unlabelled one it runs;
//!   (i) a holder's write-only open of a labelled file runs on the real file
//!       (no twin its later readers would be served its bytes from);
//!   (j) on a file system on a block device, where the guard no longer asks
//!       `fstatfs` (runtime-instances.md §14.9), every name of a labelled
//!       or registered file is still gated: a label set mid-session over a
//!       file read raw before it, a symlink and a hard link outside the
//!       root, a rename inside it and one out of it, and the registered
//!       secret by a symlink and a hard link; a procfs file is still the
//!       tracee's own.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, readable_within, reap_within, run_tag, socketpair, wait_limit};

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
const CANARY: &str = "LABELLED-OPEN-CANARY-5a1e";
const TWIN: &str = "$MDU:nomodel_Read[1a6e]\n";

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
/// supervisor loop with `cfg`. The child's exit code, or None to SKIP.
fn guarded(cfg: GuardConfig, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    let (sup, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        close_all_but(&[child_sock]);
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
        Fixture::new_in(&std::env::temp_dir(), tag)
    }
    fn new_in(base: &Path, tag: &str) -> Fixture {
        let dir = base.join(format!("mandu-labelled-{tag}-{}", run_tag()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("vault").join("open")).unwrap();
        std::fs::create_dir_all(dir.join("vault").join("a").join("b")).unwrap();
        std::fs::create_dir_all(dir.join("notes")).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        // One registered secret, so the index is a real launch's shape.
        let secret = dir.join("secret.env");
        let twin = dir.join("twin.env");
        std::fs::write(&secret, "API_KEY=registered\n").unwrap();
        std::fs::write(&twin, "API_KEY=$MDU:twin\n").unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(&policy, format!(r#"{{"agentExe":"","ask":"never","session":"lab","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, secret.display(), twin.display())).unwrap();
        Fixture { dir, policy }
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }
    fn s(&self, rel: &str) -> String {
        self.p(rel).to_str().unwrap().to_string()
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

/// What the mock arbiter serves and saw.
#[derive(Default)]
struct Book {
    /// The roots listed: `(path, shape)`, from which `labelRootsSince` call on.
    roots: Vec<(String, Option<serde_json::Value>, usize)>,
    roots_calls: usize,
    /// No `labelRootsSince` at all (an older arbiter).
    older: bool,
    /// `labelledLevel` fails (the arbiter cannot classify).
    level_fails: bool,
    /// The registered secret gets its twin too (else it reads raw, its
    /// reader's verdict, so a test can make a holder).
    registered_twin: bool,
    /// The paths `labelledLevel` was asked about.
    classified: Vec<String>,
    decided: Vec<String>,
    follows: Vec<(String, String, String)>,
}

/// The mock's law: under `vault/` every file is no-model but `vault/open/`;
/// under `notes/` only `*.md`.
fn level_of(path: &str) -> &'static str {
    if path.contains("/vault/open/") {
        "public"
    } else if path.contains("/vault/") || (path.contains("/notes/") && path.ends_with(".md")) {
        "no-model"
    } else {
        "public"
    }
}

fn arbiter(book: Arc<Mutex<Book>>) -> &'static MockArbiter {
    MockArbiter::start(op_handler(move |op, req| {
        let mut b = book.lock().unwrap();
        let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        match op {
            "labelRootsSince" if b.older => Ok(serde_json::Value::Null),
            "labelRootsSince" => {
                b.roots_calls += 1;
                let n = b.roots_calls;
                let roots: Vec<serde_json::Value> = b
                    .roots
                    .iter()
                    .filter(|(_, _, from)| n >= *from)
                    .map(|(p, s, _)| match s {
                        Some(s) => serde_json::json!({ "path": p, "shape": s }),
                        None => serde_json::json!({ "path": p }),
                    })
                    .collect();
                let key = format!("k{}", roots.len());
                if req.get("key").and_then(|v| v.as_str()) == Some(key.as_str()) {
                    return Ok(serde_json::json!({ "key": key, "unchanged": true, "roots": [] }));
                }
                Ok(serde_json::json!({ "key": key, "unchanged": false, "roots": roots, "skipDirs": ["node_modules", ".git", "target"] }))
            }
            "labelledLevel" => {
                b.classified.push(path.clone());
                if b.level_fails {
                    return Err("the arbiter cannot classify now".into());
                }
                Ok(serde_json::json!({ "level": level_of(&path), "key": format!("k{}", b.roots.len()) }))
            }
            "decideSecretOpen" => {
                // The registered secret reads raw (its reader), so a test
                // can make a holder; every labelled file gets its twin.
                let verdict = if path.ends_with("/secret.env") && !b.registered_twin { "raw" } else { "twin" };
                b.decided.push(path);
                Ok(serde_json::json!({ "verdict": verdict, "app": "test", "level": "no-model", "reason": "no reader list" }))
            }
            "registerSecret" => Ok(serde_json::json!({ "symbol": TWIN.trim_end(), "reason": "registered", "terminator": "\n" })),
            "followDerivedLabel" => {
                let s = |k: &str| req.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                b.follows.push((s("from"), s("to"), s("how")));
                Ok(serde_json::json!({ "labeled": true, "level": "no-model", "reason": "follows" }))
            }
            _ => Ok(serde_json::Value::Null),
        }
    }))
    .leak()
}

fn read(p: &Path) -> Result<String, i32> {
    std::fs::read_to_string(p).map_err(|e| e.raw_os_error().unwrap_or(-1))
}

/// A recursive read of `dir`, as `grep -r` or `os.walk` does it: every
/// regular file's text, by path.
fn walk(dir: &Path, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            walk(&p, out);
        } else if ft.is_file() {
            out.push(format!("{}={:?}", p.display(), read(&p)));
        }
    }
}

fn report(out: &Path, lines: &[String]) {
    let _ = std::fs::write(out, lines.join("\n"));
}

// ── (a) a file created under a labelled folder, and a recursive walk ────────

#[test]
#[ignore]
fn a_labelled_file_the_launch_did_not_register_is_served_its_twin_and_so_is_every_file_a_walk_reads() {
    let fx = Fixture::new("a");
    std::fs::write(fx.p("vault/plan.md"), format!("password: {CANARY}\n")).unwrap();
    std::fs::write(fx.p("vault/a/b/deep.md"), format!("password: {CANARY}-deep\n")).unwrap();
    std::fs::write(fx.p("vault/open/readme.md"), "OPEN-CONTROL\n").unwrap();
    std::fs::create_dir_all(fx.p("vault/node_modules/dep")).unwrap();
    std::fs::write(fx.p("vault/node_modules/dep/index.js"), "DEP-CONTROL\n").unwrap();
    std::fs::write(fx.p("plain.txt"), "PLAIN-CONTROL\n").unwrap();
    let book = Arc::new(Mutex::new(Book::default()));
    book.lock().unwrap().roots.push((fx.s("vault"), None, 1));
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (dir, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        // created after the guard started: written (not gated), then read
        let wrote = std::fs::write(dir.join("vault").join("new.md"), format!("password: {CANARY}-new\n")).is_ok();
        let mut lines = vec![format!("wrote={wrote}"), format!("new={:?}", read(&dir.join("vault").join("new.md")))];
        walk(&dir, &mut lines);
        report(&o, &lines);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("wrote=true"), "{r}");
    assert!(!r.contains(CANARY), "a labelled file the launch did not register was read raw: {r}");
    assert!(r.matches(TWIN.trim_end()).count() >= 4, "new.md (twice: by name and by the walk), plan.md and deep.md get the twin: {r}");
    assert!(r.contains("OPEN-CONTROL"), "a nested public file reads raw: {r}");
    assert!(r.contains("PLAIN-CONTROL"), "a file outside every label reads raw: {r}");
    assert!(r.contains("DEP-CONTROL"), "a toolchain's file in a directory the walk never enters reads raw: {r}");
    let b = book.lock().unwrap();
    assert!(!b.classified.iter().any(|p| p.ends_with("/plain.txt")), "a file under no root costs no classification: {:?}", b.classified);
    assert!(!b.classified.iter().any(|p| p.contains("/node_modules/")), "nor does one in a skipped directory: {:?}", b.classified);
    assert!(b.decided.iter().any(|p| p.ends_with("/vault/new.md")), "the arbiter decided the open: {:?}", b.decided);
}

// ── (b) a pattern root's shape ──────────────────────────────────────────────

#[test]
#[ignore]
fn a_pattern_roots_shape_spares_the_files_it_cannot_match() {
    let fx = Fixture::new("b");
    std::fs::write(fx.p("notes/plan.md"), format!("password: {CANARY}\n")).unwrap();
    std::fs::write(fx.p("notes/readme.txt"), "TXT-CONTROL\n").unwrap();
    let book = Arc::new(Mutex::new(Book::default()));
    book.lock().unwrap().roots.push((fx.s("notes"), Some(serde_json::json!({ "head": "", "tail": ".md", "exact": false })), 1));
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        let lines = vec![format!("md={:?}", read(&d.join("notes/plan.md"))), format!("txt={:?}", read(&d.join("notes/readme.txt")))];
        report(&o, &lines);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(!r.contains(CANARY) && r.contains(TWIN.trim_end()), "{r}");
    assert!(r.contains("TXT-CONTROL"), "{r}");
    let b = book.lock().unwrap();
    assert!(!b.classified.iter().any(|p| p.ends_with("readme.txt")), "the shape spares readme.txt the round trip: {:?}", b.classified);
}

// ── (c) fail-closed ─────────────────────────────────────────────────────────

#[test]
#[ignore]
fn a_file_under_a_root_the_arbiter_cannot_classify_is_refused() {
    let fx = Fixture::new("c");
    std::fs::write(fx.p("vault/plan.md"), format!("password: {CANARY}\n")).unwrap();
    std::fs::write(fx.p("plain.txt"), "PLAIN-CONTROL\n").unwrap();
    let book = Arc::new(Mutex::new(Book { level_fails: true, ..Default::default() }));
    book.lock().unwrap().roots.push((fx.s("vault"), None, 1));
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        let lines = vec![format!("plan={:?}", read(&d.join("vault/plan.md"))), format!("plain={:?}", read(&d.join("plain.txt")))];
        report(&o, &lines);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(!r.contains(CANARY), "{r}");
    assert!(r.contains(&format!("plan=Err({})", libc::EACCES)), "refused, never the real file: {r}");
    assert!(r.contains("PLAIN-CONTROL"), "{r}");
}

// ── (d) an arbiter older than the guard ─────────────────────────────────────

#[test]
#[ignore]
fn with_an_arbiter_that_lists_no_roots_files_open_as_before() {
    let fx = Fixture::new("d");
    std::fs::write(fx.p("vault/plan.md"), "OLDER-ARBITER-CONTROL\n").unwrap();
    let book = Arc::new(Mutex::new(Book { older: true, ..Default::default() }));
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        report(&o, &[format!("plan={:?}", read(&d.join("vault/plan.md")))]);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("OLDER-ARBITER-CONTROL"), "no refusal storm with an older arbiter: {r}");
    assert!(book.lock().unwrap().classified.is_empty());
}

// ── (e) a label set after the guard's first look ───────────────────────────

#[test]
#[ignore]
fn a_label_set_after_the_first_look_gates_within_the_refresh() {
    let fx = Fixture::new("e");
    std::fs::write(fx.p("vault/plan.md"), format!("password: {CANARY}\n")).unwrap();
    std::fs::write(fx.p("plain.txt"), "PLAIN-CONTROL\n").unwrap();
    let book = Arc::new(Mutex::new(Book::default()));
    // listed from the SECOND read of the list on
    book.lock().unwrap().roots.push((fx.s("vault"), None, 2));
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        let first = read(&d.join("plain.txt"));
        std::thread::sleep(Duration::from_millis(1_200));
        let lines = vec![format!("first={first:?}"), format!("plan={:?}", read(&d.join("vault/plan.md")))];
        report(&o, &lines);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("PLAIN-CONTROL"), "{r}");
    assert!(!r.contains(CANARY) && r.contains(TWIN.trim_end()), "the label set later gates the file: {r}");
    assert!(book.lock().unwrap().roots_calls >= 2, "the list was read again");
}

// ── (f) the label follows a rename ──────────────────────────────────────────

#[test]
#[ignore]
fn the_label_follows_a_rename_out_from_under_its_folder() {
    let fx = Fixture::new("f");
    std::fs::write(fx.p("vault/plan.md"), format!("password: {CANARY}\n")).unwrap();
    let book = Arc::new(Mutex::new(Book::default()));
    book.lock().unwrap().roots.push((fx.s("vault"), None, 1));
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        let mv = std::fs::rename(d.join("vault/plan.md"), d.join("moved.md")).map_err(|e| e.raw_os_error());
        report(&o, &[format!("rename={mv:?}")]);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("rename=Ok(())"), "a labelled file may still be renamed: {r}");
    let follows = book.lock().unwrap().follows.clone();
    assert!(
        follows.iter().any(|(f, t, h)| f == &fx.s("vault/plan.md") && t == &fx.s("moved.md") && h == "rename"),
        "the arbiter was told before the rename ran: {follows:?}"
    );
}

// ── (g) a program's writes through the gate: in the recorded twin ──────────

/// The guard's twin records (`label_index::TWIN_RECORDS`), by target path:
/// whether the twin each record names still holds what the guard wrote.
fn twin_records(fx: &Fixture) -> Vec<(String, bool)> {
    use sha2::{Digest, Sha256};
    let text = std::fs::read_to_string(fx.p("derived-twins").join(net_supervisor::label_index::TWIN_RECORDS)).unwrap_or_default();
    text.lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            let twin = v["twinPath"].as_str().unwrap();
            let now = std::fs::read(twin).map(|b| Sha256::digest(&b).iter().map(|x| format!("{x:02x}")).collect::<String>()).unwrap_or_default();
            (v["targetPath"].as_str().unwrap().to_string(), now == v["sha256"].as_str().unwrap())
        })
        .collect()
}

#[test]
#[ignore]
fn a_programs_write_through_the_gate_lands_in_a_recorded_twin_and_never_in_the_real_file() {
    use std::io::{Seek, SeekFrom, Write};
    let fx = Fixture::new("g");
    for f in ["rdwr", "append", "trunc", "linked", "untouched"] {
        std::fs::write(fx.p(&format!("vault/{f}.md")), format!("password: {CANARY}-{f}\n")).unwrap();
    }
    let book = Arc::new(Mutex::new(Book::default()));
    book.lock().unwrap().roots.push((fx.s("vault"), None, 1));
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        let v = d.join("vault");
        let mut lines = Vec::new();
        // In place (`O_RDWR`, as `dd conv=notrunc`, sqlite, python "r+").
        let r = std::fs::OpenOptions::new().read(true).write(true).open(v.join("rdwr.md")).and_then(|mut f| {
            f.seek(SeekFrom::Start(0))?;
            f.write_all(b"EDITED")
        });
        lines.push(format!("rdwr={r:?}"));
        // `echo x >> f` (`O_WRONLY|O_APPEND`) and `echo x > f` (`O_TRUNC`).
        let r = std::fs::OpenOptions::new().append(true).open(v.join("append.md")).and_then(|mut f| f.write_all(b"APPENDED\n"));
        lines.push(format!("append={r:?}"));
        let r = std::fs::write(v.join("trunc.md"), b"REPLACED\n");
        lines.push(format!("trunc={r:?}"));
        // A file the write creates under the label: the real file.
        let r = std::fs::write(v.join("created.md"), b"CREATED-BY-THE-PROGRAM\n");
        lines.push(format!("created={r:?}"));
        // Another name outside the label (a hard link made in the session).
        let r = std::fs::hard_link(v.join("linked.md"), d.join("alias.txt"))
            .and_then(|()| std::fs::OpenOptions::new().append(true).open(d.join("alias.txt")))
            .and_then(|mut f| f.write_all(b"VIA-ALIAS\n"));
        lines.push(format!("alias={r:?}"));
        lines.push(format!("alias-read={:?}", read(&d.join("alias.txt"))));
        lines.push(format!("untouched={:?}", read(&v.join("untouched.md"))));
        report(&o, &lines);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    for k in ["rdwr", "append", "trunc", "created", "alias"] {
        assert!(r.contains(&format!("{k}=Ok(())")), "the program's write succeeds ({k}): {r}");
    }
    assert!(!r.contains(CANARY), "no real text read through either name: {r}");
    // The real files hold what they held: no placeholder text, no edit.
    for f in ["rdwr", "append", "trunc", "linked"] {
        assert_eq!(std::fs::read_to_string(fx.p(&format!("vault/{f}.md"))).unwrap(), format!("password: {CANARY}-{f}\n"), "{f}.md");
    }
    assert_eq!(std::fs::read_to_string(fx.p("vault/created.md")).unwrap(), "CREATED-BY-THE-PROGRAM\n", "a file the write created holds its bytes");
    // Each written twin is recorded and no longer what the guard wrote.
    let recs = twin_records(&fx);
    for (target, f) in [(fx.s("vault/rdwr.md"), "rdwr"), (fx.s("vault/append.md"), "append"), (fx.s("vault/trunc.md"), "trunc"), (fx.s("alias.txt"), "alias")] {
        assert!(recs.iter().any(|(t, same)| t == &target && !same), "the twin {f} wrote is recorded, changed: {recs:?}");
    }
    assert!(recs.iter().any(|(t, same)| t == &fx.s("vault/untouched.md") && *same), "a twin only read stays as made: {recs:?}");
    assert!(!recs.iter().any(|(t, _)| t.ends_with("/created.md")), "the created file got no twin: {recs:?}");
}

// ── (h) a rename onto a labelled file ──────────────────────────────────────

#[test]
#[ignore]
fn a_rename_onto_a_labelled_file_is_refused_so_placeholder_text_never_replaces_it() {
    let fx = Fixture::new("h");
    std::fs::write(fx.p("vault/plan.md"), format!("password: {CANARY}\n")).unwrap();
    std::fs::write(fx.p("plain.txt"), "PLAIN\n").unwrap();
    let book = Arc::new(Mutex::new(Book::default()));
    book.lock().unwrap().roots.push((fx.s("vault"), None, 1));
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        // `sed -i`: read the file, write the edit beside it, rename over it.
        let text = read(&d.join("vault/plan.md")).unwrap_or_default();
        let _ = std::fs::write(d.join("edited.tmp"), text.replace("password", "secret"));
        let over = std::fs::rename(d.join("edited.tmp"), d.join("vault/plan.md")).map_err(|e| e.raw_os_error());
        let _ = std::fs::write(d.join("other.tmp"), "OTHER\n");
        let plain = std::fs::rename(d.join("other.tmp"), d.join("plain.txt")).map_err(|e| e.raw_os_error());
        report(&o, &[format!("over={over:?}"), format!("plain={plain:?}")]);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains(&format!("over=Err(Some({}))", libc::EACCES)), "{r}");
    assert!(r.contains("plain=Ok(())"), "a rename onto an unlabelled file runs: {r}");
    assert_eq!(std::fs::read_to_string(fx.p("vault/plan.md")).unwrap(), format!("password: {CANARY}\n"), "the real file is not replaced by placeholder text");
}

// ── (i) a holder's write-only open runs on the real file ───────────────────

#[test]
#[ignore]
fn a_holders_write_to_a_labelled_file_runs_on_the_real_file_never_into_a_twin_others_read() {
    use std::io::Write;
    let fx = Fixture::new("i");
    std::fs::write(fx.p("vault/log.md"), format!("password: {CANARY}\n")).unwrap();
    let book = Arc::new(Mutex::new(Book::default()));
    book.lock().unwrap().roots.push((fx.s("vault"), None, 1));
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        // Read the registered secret raw: this process holds it now.
        let held = read(&d.join("secret.env"));
        let r = std::fs::OpenOptions::new().append(true).open(d.join("vault/log.md")).and_then(|mut f| f.write_all(b"HOLDER-APPENDED\n"));
        report(&o, &[format!("held={held:?}"), format!("append={r:?}")]);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("API_KEY=registered"), "the holder read the secret raw: {r}");
    assert!(r.contains("append=Ok(())"), "{r}");
    // Its bytes went to the real file (labelled by its write, plan 13 D5),
    // not into a twin whose later readers would be served them as written.
    assert_eq!(std::fs::read_to_string(fx.p("vault/log.md")).unwrap(), format!("password: {CANARY}\nHOLDER-APPENDED\n"));
    assert!(twin_records(&fx).is_empty(), "no twin was made for the holder's write");
}

// ── (j) the same gates where the guard skips `fstatfs` ─────────────────────

/// A directory for fixtures on a file system on a block device (its device
/// has a non-zero major), where the guard's open takes the stat shortcut
/// (runtime-instances.md §14.9); None when this host has none to write.
fn block_device_base() -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let candidates = [Some(PathBuf::from(env!("CARGO_TARGET_TMPDIR"))), Some(PathBuf::from("/var/tmp")), home, Some(std::env::temp_dir())];
    candidates.into_iter().flatten().find(|d| {
        let probe = d.join(format!(".mandu-blockdev-probe-{}", std::process::id()));
        let ok = std::fs::write(&probe, b"x").is_ok() && std::fs::metadata(&probe).is_ok_and(|m| !fs_supervisor::tracee::may_be_pseudo_fs(m.dev()));
        let _ = std::fs::remove_file(&probe);
        ok
    })
}

#[test]
#[ignore]
fn on_a_block_device_every_name_of_a_labelled_file_is_still_gated() {
    let Some(base) = block_device_base() else {
        eprintln!("SKIP: no writable directory on a block device's file system here");
        return;
    };
    let fx = Fixture::new_in(&base, "j");
    std::fs::create_dir_all(fx.p("vault/sub")).unwrap();
    std::fs::write(fx.p("vault/early.md"), "password: EARLY-READ-RAW\n").unwrap();
    std::fs::write(fx.p("vault/plan.md"), format!("password: {CANARY}\n")).unwrap();
    std::fs::write(fx.p("plain.txt"), "PLAIN-CONTROL\n").unwrap();
    std::os::unix::fs::symlink(fx.p("vault/plan.md"), fx.p("link.md")).unwrap();
    std::fs::hard_link(fx.p("vault/plan.md"), fx.p("hard.md")).unwrap();
    std::os::unix::fs::symlink(fx.p("secret.env"), fx.p("secret-link")).unwrap();
    std::fs::hard_link(fx.p("secret.env"), fx.p("secret-hard")).unwrap();
    let book = Arc::new(Mutex::new(Book { registered_twin: true, ..Default::default() }));
    // Listed from the SECOND read of the list on: set mid-session.
    book.lock().unwrap().roots.push((fx.s("vault"), None, 2));
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        let mut lines = vec![format!("plain={:?}", read(&d.join("plain.txt"))), format!("early={:?}", read(&d.join("vault/early.md")))];
        std::thread::sleep(Duration::from_millis(1_200));
        lines.push(format!("early-after={:?}", read(&d.join("vault/early.md"))));
        lines.push(format!("plan={:?}", read(&d.join("vault/plan.md"))));
        lines.push(format!("symlink={:?}", read(&d.join("link.md"))));
        lines.push(format!("hardlink={:?}", read(&d.join("hard.md"))));
        let mv = std::fs::rename(d.join("vault/plan.md"), d.join("vault/sub/renamed.md")).map_err(|e| e.raw_os_error());
        lines.push(format!("rename-in={mv:?} {:?}", read(&d.join("vault/sub/renamed.md"))));
        let mv = std::fs::rename(d.join("vault/sub/renamed.md"), d.join("moved.md")).map_err(|e| e.raw_os_error());
        lines.push(format!("rename-out={mv:?} {:?}", read(&d.join("moved.md"))));
        lines.push(format!("secret-symlink={:?}", read(&d.join("secret-link"))));
        lines.push(format!("secret-hardlink={:?}", read(&d.join("secret-hard"))));
        // SAFETY: getpid has no failure mode.
        let me = unsafe { libc::getpid() }.to_string();
        let own = read(Path::new("/proc/self/status")).unwrap_or_default().lines().any(|l| l.split_whitespace().collect::<Vec<_>>() == ["Pid:", me.as_str()]);
        lines.push(format!("proc-own={own}"));
        report(&o, &lines);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    let line = |k: &str| r.lines().find(|l| l.starts_with(&format!("{k}="))).unwrap_or_else(|| panic!("no {k} line: {r}")).to_string();
    assert!(line("plain").contains("PLAIN-CONTROL"), "{r}");
    assert!(line("early").contains("EARLY-READ-RAW"), "before the label is listed the file reads raw (the refresh, label_index::REFRESH_NS): {r}");
    assert!(!r.contains(CANARY), "a labelled file was read raw by some name: {r}");
    for k in ["early-after", "plan", "symlink", "hardlink", "rename-in", "rename-out"] {
        assert!(line(k).contains(TWIN.trim_end()), "{k} is served the twin: {r}");
    }
    assert!(line("rename-in").contains("Ok(())") && line("rename-out").contains("Ok(())"), "{r}");
    assert!(!r.contains("API_KEY=registered"), "the registered secret was read raw by another name: {r}");
    for k in ["secret-symlink", "secret-hardlink"] {
        assert!(line(k).contains("API_KEY=$MDU:twin"), "{k}: {r}");
    }
    assert!(line("proc-own").ends_with("true"), "a procfs file is still reopened as the tracee's own: {r}");
}
