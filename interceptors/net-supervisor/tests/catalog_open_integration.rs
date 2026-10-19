//! catalog_open_integration — a file the secret CATALOG names (a `.env`, a
//! key under `~/.ssh`) that the launch did not register is gated at the open
//! (2026-10-17, confidentiality.md §6 "Read by a program the launch did not
//! see").
//!
//! Before the fix the guard gated the registered files, the derived ones and
//! (since the same day) the human-labelled ones, so a `.env` created after
//! the launch, deeper than the discovery walk, past its cap or outside HOME
//! opened RAW for every program, and a recursive read (`grep -r`, `tar`,
//! `os.walk`) printed it to the model in clear. Each test below that expects
//! the twin failed that way.
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! (an unprivileged user namespace). A host where the seccomp listener cannot
//! be installed SKIPs. The arbiter is a mock that lists the catalog
//! (`labelRootsSince`: a prefix root and the name prefilter), classifies a
//! candidate (`labelledLevel`), answers the twin at the gate
//! (`decideSecretOpen`) and mints the twin text (`registerSecret`).
//!
//!   (a) a `.env` created after the guard started, deeper than the walk, and
//!       every catalog file a recursive walk reads, is served its twin; a
//!       template (`.env.example`, public by the catalog's rule) reads raw; a
//!       `.env` in `node_modules`, a file no anchor admits and the launch's
//!       own twin read raw and cost no classification, and so does a source
//!       file named like a credential (`Credentials.ts`, an extension the
//!       anchor's `notSuffixes` names);
//!   (b) a new file under a catalog prefix (`~/.ssh`) is served its twin;
//!   (c) a candidate the arbiter cannot classify is refused, a file no
//!       anchor admits still reads;
//!   (d) with an arbiter that ships no catalog, files open as before;
//!   (e) its writes are a labelled file's (2026-10-17): a rename onto it
//!       (`sed -i`) is refused and a truncating write lands in its copy, the
//!       real file keeping its bytes.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, readable_within, reap_within, run_tag, socketpair, wait_limit};

use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mandu_arbiter::mock::{op_handler, MockArbiter};
use net_supervisor::guard::{parse_rules, GuardPolicy, NoResolver};
use net_supervisor::guard_kernel::{
    hand_listener, install_guard_filter_self, receive_listener, run_guard_supervisor, FilterTraps,
    GuardConfig,
};

const EXIT_NO_SECCOMP: i32 = 91;
const CANARY: &str = "CATALOG-OPEN-CANARY-7d2b";
const TWIN: &str = "$MDU:nomodel_Read[c47a]\n";

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
        let dir = std::env::temp_dir().join(format!("mandu-catalog-{tag}-{}", run_tag()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["home/.ssh", "home/proj/a/b/c/d/e/f", "home/proj/node_modules/pkg", "twins"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        let dir = std::fs::canonicalize(&dir).unwrap();
        // One registered secret, its twin in the launch's twin directory and
        // named as the launch names twins (its file's name kept): a catalog
        // shape the guard must never gate as a file of its own.
        let secret = dir.join("home/proj/.env");
        let twin = dir.join("twins/0a1b2c3d-.env");
        std::fs::write(&secret, "API_KEY=registered\n").unwrap();
        std::fs::write(&twin, "API_KEY=$MDU:twin\n").unwrap();
        let policy = dir.join("twins/policy.json");
        std::fs::write(&policy, format!(r#"{{"agentExe":"","ask":"never","session":"cat","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#, secret.display(), twin.display())).unwrap();
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
    home: String,
    /// The answer ships no catalog (an arbiter older than the catalog gate).
    no_catalog: bool,
    /// `labelledLevel` fails (the arbiter cannot classify).
    level_fails: bool,
    /// The sessions `labelRootsSince` was asked for.
    sessions: Vec<String>,
    /// The paths `labelledLevel` was asked about.
    classified: Vec<String>,
    decided: Vec<String>,
}

/// The mock's catalog rule: a template is public, every other candidate is
/// no-model (the arbiter's `gateVerdict` is unit-tested on its own).
fn level_of(path: &str) -> &'static str {
    if path.ends_with(".example") {
        "public"
    } else {
        "no-model"
    }
}

fn arbiter(book: Arc<Mutex<Book>>) -> &'static MockArbiter {
    MockArbiter::start(op_handler(move |op, req| {
        let mut b = book.lock().unwrap();
        let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        match op {
            "labelRootsSince" => {
                let session = req.get("session").and_then(|v| v.as_str()).unwrap_or("").to_string();
                b.sessions.push(session);
                if req.get("key").and_then(|v| v.as_str()) == Some("c1") {
                    return Ok(serde_json::json!({ "key": "c1", "unchanged": true, "roots": [] }));
                }
                let roots = serde_json::json!([{ "path": format!("{}/.ssh", b.home) }]);
                let mut answer = serde_json::json!({ "key": "c1", "unchanged": false, "roots": roots, "skipDirs": ["node_modules", ".git", "target"] });
                if !b.no_catalog {
                    answer["catalog"] = serde_json::json!({
                        "names": [{ "exact": ".env" }, { "prefix": ".env." }, { "suffix": ".env" }, { "contains": "credentials", "notSuffixes": [".md", ".ts", ".py"], "ci": true }],
                        "homes": [b.home],
                        "skipDirs": ["site-packages"],
                    });
                }
                Ok(answer)
            }
            "labelledLevel" => {
                b.classified.push(path.clone());
                if b.level_fails {
                    return Err("the arbiter cannot classify now".into());
                }
                Ok(serde_json::json!({ "level": level_of(&path), "key": "c1" }))
            }
            "decideSecretOpen" => {
                b.decided.push(path);
                Ok(serde_json::json!({ "verdict": "twin", "app": "test", "level": "no-model", "reason": "no reader list" }))
            }
            "registerSecret" => Ok(serde_json::json!({ "symbol": TWIN.trim_end(), "reason": "registered", "terminator": "\n" })),
            _ => Ok(serde_json::Value::Null),
        }
    }))
    .leak()
}

fn read(p: &Path) -> Result<String, i32> {
    std::fs::read_to_string(p).map_err(|e| e.raw_os_error().unwrap_or(-1))
}

/// A recursive read of `dir`, as `grep -r` or `os.walk` does it.
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

fn book_for(fx: &Fixture) -> Arc<Mutex<Book>> {
    Arc::new(Mutex::new(Book { home: fx.s("home"), ..Default::default() }))
}

// ── (a) a .env created mid-session, deeper than the walk, and a walk ────────

#[test]
#[ignore]
fn a_catalog_file_the_launch_did_not_register_is_served_its_twin_and_so_is_every_one_a_walk_reads() {
    let fx = Fixture::new("a");
    std::fs::write(fx.p("home/proj/aws_credentials.ini"), format!("secret={CANARY}-cred\n")).unwrap();
    std::fs::write(fx.p("home/proj/.env.example"), "TEMPLATE-CONTROL\n").unwrap();
    std::fs::write(fx.p("home/proj/node_modules/pkg/.env"), "DEP-CONTROL\n").unwrap();
    std::fs::write(fx.p("home/proj/main.rs"), "PLAIN-CONTROL\n").unwrap();
    // A source file named like a credential, deeper than the walk: its
    // extension is one of the anchor's `notSuffixes` (2026-10-17).
    std::fs::write(fx.p("home/proj/a/b/c/d/e/f/Credentials.ts"), "SOURCE-CONTROL\n").unwrap();
    let book = book_for(&fx);
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (dir, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        // created after the guard started, deeper than the walk: written (not gated), then read
        let deep = dir.join("home/proj/a/b/c/d/e/f/.env");
        let wrote = std::fs::write(&deep, format!("DB_PASSWORD={CANARY}-deep\n")).is_ok();
        let mut lines = vec![format!("wrote={wrote}"), format!("deep={:?}", read(&deep))];
        walk(&dir, &mut lines);
        report(&o, &lines);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("wrote=true"), "{r}");
    assert!(!r.contains(CANARY), "a catalog file the launch did not register was read raw: {r}");
    assert!(r.matches(TWIN.trim_end()).count() >= 3, "the deep .env (by name and by the walk) and the credentials file get the twin: {r}");
    assert!(r.contains("TEMPLATE-CONTROL"), "a template the catalog calls public reads raw: {r}");
    assert!(r.contains("DEP-CONTROL"), "a .env in node_modules reads raw: {r}");
    assert!(r.contains("PLAIN-CONTROL"), "a file no anchor admits reads raw: {r}");
    assert!(r.contains("SOURCE-CONTROL"), "a source file named like a credential reads raw (the anchor's notSuffixes): {r}");
    assert!(r.contains("API_KEY=$MDU:twin"), "the launch's own twin reads as itself: {r}");
    let b = book.lock().unwrap();
    assert!(b.sessions.iter().all(|s| s == "cat"), "the guard names its session: {:?}", b.sessions);
    assert!(!b.classified.iter().any(|p| p.ends_with("/main.rs")), "a name no anchor admits costs no classification: {:?}", b.classified);
    assert!(!b.classified.iter().any(|p| p.ends_with("/Credentials.ts")), "nor a name only a not-suffix spares: {:?}", b.classified);
    assert!(b.classified.iter().any(|p| p.ends_with("/aws_credentials.ini")), "the data file the same anchor admits is classified: {:?}", b.classified);
    assert!(!b.classified.iter().any(|p| p.contains("/node_modules/")), "nor does one in a skipped directory: {:?}", b.classified);
    assert!(!b.classified.iter().any(|p| p.contains("/twins/")), "nor the launch's own twin: {:?}", b.classified);
    assert!(b.decided.iter().any(|p| p.ends_with("/a/b/c/d/e/f/.env")), "the arbiter decided the open: {:?}", b.decided);
}

// ── (b) a catalog prefix ────────────────────────────────────────────────────

#[test]
#[ignore]
fn a_new_file_under_a_catalog_prefix_is_served_its_twin() {
    let fx = Fixture::new("b");
    let book = book_for(&fx);
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        let key = d.join("home/.ssh/deploy_key_new");
        let _ = std::fs::write(&key, format!("key material {CANARY}\n")).is_ok();
        report(&o, &[format!("key={:?}", read(&key))]);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(!r.contains(CANARY) && r.contains(TWIN.trim_end()), "{r}");
}

// ── (c) fail-closed ─────────────────────────────────────────────────────────

#[test]
#[ignore]
fn a_candidate_the_arbiter_cannot_classify_is_refused() {
    let fx = Fixture::new("c");
    std::fs::write(fx.p("home/proj/a/.env"), format!("K={CANARY}\n")).unwrap();
    std::fs::write(fx.p("home/proj/main.rs"), "PLAIN-CONTROL\n").unwrap();
    let book = Arc::new(Mutex::new(Book { home: fx.s("home"), level_fails: true, ..Default::default() }));
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        let lines = vec![format!("env={:?}", read(&d.join("home/proj/a/.env"))), format!("plain={:?}", read(&d.join("home/proj/main.rs")))];
        report(&o, &lines);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(!r.contains(CANARY), "{r}");
    assert!(r.contains(&format!("env=Err({})", libc::EACCES)), "refused, never the real file: {r}");
    assert!(r.contains("PLAIN-CONTROL"), "{r}");
}

// ── (e) its writes: as a labelled file's (!1791) ────────────────────────────

#[test]
#[ignore]
fn a_rename_onto_a_catalog_file_is_refused_and_a_write_lands_in_its_copy() {
    let fx = Fixture::new("e");
    let env = fx.p("home/proj/a/.env");
    std::fs::write(&env, format!("K={CANARY}\n")).unwrap();
    let book = book_for(&fx);
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        // what `sed -i` does: a new file renamed over the real one
        let tmp = d.join("home/proj/a/sedXYZ");
        let _ = std::fs::write(&tmp, "K=$MDU:placeholder\n");
        let mv = std::fs::rename(&tmp, d.join("home/proj/a/.env")).map_err(|e| e.raw_os_error());
        // a truncating write-only open of the non-empty file
        let wrote = std::fs::write(d.join("home/proj/a/.env"), "K=overwritten\n").map_err(|e| e.raw_os_error());
        report(&o, &[format!("rename={mv:?}"), format!("write={wrote:?}")]);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains(&format!("rename=Err(Some({}))", libc::EACCES)), "a rename onto the catalog file is refused: {r}");
    assert_eq!(std::fs::read_to_string(&env).unwrap(), format!("K={CANARY}\n"), "the real file keeps its bytes: {r}");
}

// ── (d) an arbiter that ships no catalog ────────────────────────────────────

#[test]
#[ignore]
fn with_an_arbiter_that_ships_no_catalog_files_open_as_before() {
    let fx = Fixture::new("d");
    std::fs::write(fx.p("home/proj/a/.env"), "OLDER-ARBITER-CONTROL\n").unwrap();
    let book = Arc::new(Mutex::new(Book { home: fx.s("home"), no_catalog: true, ..Default::default() }));
    let arb = arbiter(book.clone());
    let out = fx.p("report.txt");
    let (d, o) = (fx.dir.clone(), out.clone());
    let Some(code) = guarded(fx.cfg(&arb.socket_path), move || {
        report(&o, &[format!("env={:?}", read(&d.join("home/proj/a/.env")))]);
        0
    }) else {
        return;
    };
    assert_eq!(code, Some(0));
    let r = std::fs::read_to_string(&out).unwrap();
    assert!(r.contains("OLDER-ARBITER-CONTROL"), "no gate without a catalog: {r}");
    assert!(book.lock().unwrap().classified.is_empty());
}
