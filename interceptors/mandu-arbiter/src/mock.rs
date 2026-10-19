//! mock — an in-process mock arbiter for unit tests.
//!
//! Stands up a real `UnixListener` on a temp socket path in a background thread.
//! For each accepted connection it reads NDJSON request lines and replies with a
//! canned response derived from a user-supplied handler closure. This lets the
//! interceptor crates exercise the REAL `ArbiterClient` wire path (framing,
//! id-correlation, error handling) without a running arbiter daemon.
//!
//! Gated behind `cfg(any(test, feature = "mock"))` so it ships only for tests and
//! callers who opt in; it is not part of the production surface.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::Value;

/// A handler maps a parsed request object → the `result` value (or an error
/// string). It receives the full request (`{id, op, ...}`) and returns either
/// `Ok(result_value)` (the arbiter replies `{id, ok:true, result}`) or
/// `Err(message)` (replies `{id, ok:false, error}`).
pub type Handler = Arc<dyn Fn(&Value) -> std::result::Result<Value, String> + Send + Sync>;

/// A running mock arbiter. Drop it (or call `shutdown`) to stop the listener.
pub struct MockArbiter {
    pub socket_path: PathBuf,
    requests: Arc<AtomicU64>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockArbiter {
    /// Start a mock arbiter on a fresh temp socket path with the given handler.
    pub fn start(handler: Handler) -> Self {
        let (socket_path, listener) = bind_fresh_socket();
        Self::serve(socket_path, listener, handler)
    }

    /// Start a mock arbiter on `path` (which must not exist), e.g. in a
    /// private directory of the test's own (a human-plane socket in its
    /// walled directory, arbiter-human-plane.md §5.2).
    pub fn start_at(path: impl Into<PathBuf>, handler: Handler) -> Self {
        let socket_path = path.into();
        let listener = UnixListener::bind(&socket_path).unwrap_or_else(|e| panic!("bind mock arbiter socket {}: {e}", socket_path.display()));
        Self::serve(socket_path, listener, handler)
    }

    fn serve(socket_path: PathBuf, listener: UnixListener, handler: Handler) -> Self {
        listener
            .set_nonblocking(false)
            .expect("blocking listener");

        let requests = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let req_count = requests.clone();
        let stop_flag = stop.clone();
        let sock_for_thread = socket_path.clone();

        let handle = thread::spawn(move || {
            // Accept connections until told to stop. We use a short accept timeout
            // by polling the stop flag between blocking accepts via a self-connect
            // on shutdown.
            for conn in listener.incoming() {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                let stream = match conn {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut writer = stream.try_clone().expect("clone stream");
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                loop {
                    line.clear();
                    let n = match reader.read_line(&mut line) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if n == 0 {
                        break; // client closed
                    }
                    let trimmed = line.trim_end();
                    if trimmed.is_empty() {
                        continue;
                    }
                    req_count.fetch_add(1, Ordering::Relaxed);
                    let req: Value = match serde_json::from_str(trimmed) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let id = req.get("id").cloned().unwrap_or(Value::Null);
                    let reply = match handler(&req) {
                        Ok(result) => serde_json::json!({ "id": id, "ok": true, "result": result }),
                        Err(err) => serde_json::json!({ "id": id, "ok": false, "error": err }),
                    };
                    let mut out = serde_json::to_string(&reply).unwrap();
                    out.push('\n');
                    if writer.write_all(out.as_bytes()).is_err() {
                        break;
                    }
                    let _ = writer.flush();
                }
            }
            let _ = std::fs::remove_file(&sock_for_thread);
        });

        MockArbiter {
            socket_path,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    /// Keep this mock for the life of the test process (a `&'static` that a
    /// supervisor's threads, or a forked child, can hold), and still remove its
    /// socket when the process exits: a `Box::leak` never drops, so every such
    /// test left a `mandu-mock-arbiter-*.sock` in TMPDIR (hundreds a run, docs/
    /// design/test-organization.md §8.5). The removal runs from `atexit` in the
    /// process that called this only, never in a forked child that exits.
    pub fn leak(self) -> &'static MockArbiter {
        remove_at_exit(self.socket_path.clone());
        Box::leak(Box::new(self))
    }

    /// Number of request lines the mock has processed so far.
    pub fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// Stop the listener thread.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Nudge the blocking `accept` by connecting once.
        let _ = std::os::unix::net::UnixStream::connect(&self.socket_path);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for MockArbiter {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The sockets of leaked mocks (`MockArbiter::leak`), each with the pid of the
/// process that leaked it.
static LEAKED: std::sync::Mutex<Vec<(u32, PathBuf)>> = std::sync::Mutex::new(Vec::new());

extern "C" {
    fn atexit(cb: extern "C" fn()) -> i32;
}

extern "C" fn remove_leaked_sockets() {
    let me = std::process::id();
    // try_lock: a thread that held the lock at exit must not hang the exit.
    if let Ok(list) = LEAKED.try_lock() {
        for (owner, path) in list.iter() {
            if *owner == me {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn remove_at_exit(path: PathBuf) {
    static HOOK: std::sync::Once = std::sync::Once::new();
    // SAFETY: registers a plain `extern "C" fn()` with the C runtime's exit
    // handlers; it touches only the mutex-guarded list above.
    HOOK.call_once(|| unsafe {
        atexit(remove_leaked_sockets);
    });
    if let Ok(mut list) = LEAKED.lock() {
        list.push((std::process::id(), path));
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Bind a listener on a NEW socket path under the system temp dir:
/// `mandu-mock-arbiter-<pid>-<n>-<random>.sock`. The pid and counter alone are
/// not unique: inside a pid namespace (scripts/kernel-tests.sh) every run has
/// the same small pid, and an earlier version that unlinked "its" path before
/// binding stole the socket of a concurrent run, whose tests then hung
/// (test-organization.md §8.4). So the name carries 64 random bits and an
/// existing path is never removed: `bind` refuses it (AddrInUse) and the next
/// name is tried.
fn bind_fresh_socket() -> (PathBuf, UnixListener) {
    let pid = std::process::id();
    for _ in 0..16 {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut socket_path = std::env::temp_dir();
        socket_path.push(format!("mandu-mock-arbiter-{pid}-{n}-{:016x}.sock", random_u64()));
        match UnixListener::bind(&socket_path) {
            Ok(l) => return (socket_path, l),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(e) => panic!("bind mock arbiter socket {}: {e}", socket_path.display()),
        }
    }
    panic!("bind mock arbiter socket: no free name after 16 tries");
}

/// 64 bits from /dev/urandom, or (where it cannot be read) the clock's nanos
/// mixed with the stack address: unique enough for a test socket name.
fn random_u64() -> u64 {
    use std::io::Read;
    let mut b = [0u8; 8];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_ok() {
        return u64::from_le_bytes(b);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ (&b as *const _ as u64)
}

/// Convenience: build a `Handler` that dispatches on the request `op` string.
/// `f` receives `(op, &request)` and returns the same `Result<Value, String>`.
pub fn op_handler<F>(f: F) -> Handler
where
    F: Fn(&str, &Value) -> std::result::Result<Value, String> + Send + Sync + 'static,
{
    Arc::new(move |req: &Value| {
        let op = req.get("op").and_then(|v| v.as_str()).unwrap_or("");
        f(op, req)
    })
}

// ── a WEDGED arbiter (mandu.md §2.x) ─────────────────────────────────────────

/// What a [`StallingArbiter`] does with one request.
pub enum Stall {
    /// Answer at once, as [`MockArbiter`] does.
    Answer(std::result::Result<Value, String>),
    /// Answer after a wait (a late answer: the client gave up first).
    AnswerAfter(Duration, std::result::Result<Value, String>),
    /// Never answer, nor anything after it on this connection: the arbiter
    /// is wedged there, its socket open.
    Never,
}

/// Maps a request (`{id, op, ...}`) to what the [`StallingArbiter`] does.
pub type StallHandler = Arc<dyn Fn(&Value) -> Stall + Send + Sync>;

/// [`op_handler`] for a [`StallingArbiter`].
pub fn op_stall<F>(f: F) -> StallHandler
where
    F: Fn(&str, &Value) -> Stall + Send + Sync + 'static,
{
    Arc::new(move |req: &Value| {
        let op = req.get("op").and_then(|v| v.as_str()).unwrap_or("");
        f(op, req)
    })
}

/// A mock arbiter that accepts every connection, each served on a thread of
/// its own, and may leave a request unanswered while its socket stays open:
/// the arbiter that is alive but wedged (SIGSTOPped, blocked on disk I/O, a
/// poison row), which errors on nothing. Records each request with the
/// connection it came on, so a test tells a fresh connection from a reused one.
pub struct StallingArbiter {
    pub socket_path: PathBuf,
    connections: Arc<AtomicU64>,
    seen: Arc<std::sync::Mutex<Vec<(u64, String)>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl StallingArbiter {
    /// An arbiter that never answers anything.
    pub fn wedged() -> Self {
        StallingArbiter::start(Arc::new(|_| Stall::Never))
    }

    /// Start one on a fresh temp socket with `handler`.
    pub fn start(handler: StallHandler) -> Self {
        let (socket_path, listener) = bind_fresh_socket();
        let connections = Arc::new(AtomicU64::new(0));
        let seen: Arc<std::sync::Mutex<Vec<(u64, String)>>> = Arc::default();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (conns, seen_t, stop_t, sock_t) = (connections.clone(), seen.clone(), stop.clone(), socket_path.clone());
        let handle = thread::spawn(move || {
            for conn in listener.incoming() {
                if stop_t.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(stream) = conn else { break };
                let n = conns.fetch_add(1, Ordering::Relaxed) + 1;
                let (handler, seen) = (handler.clone(), seen_t.clone());
                thread::spawn(move || serve_stalling(stream, n, handler, seen));
            }
            let _ = std::fs::remove_file(&sock_t);
        });
        StallingArbiter { socket_path, connections, seen, stop, handle: Some(handle) }
    }

    /// See [`MockArbiter::leak`].
    pub fn leak(self) -> &'static StallingArbiter {
        remove_at_exit(self.socket_path.clone());
        Box::leak(Box::new(self))
    }

    /// Connections accepted so far.
    pub fn connection_count(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Every request read so far: (the connection's number from 1, its op).
    pub fn requests(&self) -> Vec<(u64, String)> {
        self.seen.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// How many requests of `op` were read.
    pub fn asked(&self, op: &str) -> usize {
        self.requests().iter().filter(|(_, o)| o == op).count()
    }

    /// [`StallingArbiter::requests`] once at least `n` were read, or at
    /// [`SETTLE_LIMIT`]. A request the client gave up on is read by its
    /// connection's thread when that thread runs, which on a loaded machine
    /// can be after the client's deadline and the next request: a test that
    /// counts what reached the arbiter waits for it here (a CI run read
    /// `[(1, desymbolizationDecision), (3, classify)]`, the second
    /// connection's `isProcessTainted` not yet).
    pub fn requests_after(&self, n: usize) -> Vec<(u64, String)> {
        self.settle(|seen| seen.len() >= n)
    }

    /// [`StallingArbiter::asked`] once it reached `n`, or at [`SETTLE_LIMIT`]
    /// (see [`StallingArbiter::requests_after`]).
    pub fn asked_after(&self, op: &str, n: usize) -> usize {
        self.settle(|seen| seen.iter().filter(|(_, o)| o == op).count() >= n).iter().filter(|(_, o)| o == op).count()
    }

    fn settle(&self, done: impl Fn(&[(u64, String)]) -> bool) -> Vec<(u64, String)> {
        let until = std::time::Instant::now() + SETTLE_LIMIT;
        loop {
            let seen = self.requests();
            if done(&seen) || std::time::Instant::now() >= until {
                return seen;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

/// The longest [`StallingArbiter::requests_after`] and
/// [`StallingArbiter::asked_after`] wait.
pub const SETTLE_LIMIT: Duration = Duration::from_secs(10);

impl Drop for StallingArbiter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // A connection that never comes back (nothing accepts it) is fine:
        // the accept loop sees the flag on this one.
        let _ = std::os::unix::net::UnixStream::connect(&self.socket_path);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// One connection of a [`StallingArbiter`]: read each line; once a request
/// went unanswered, read the rest (recorded) without answering, until EOF.
fn serve_stalling(stream: std::os::unix::net::UnixStream, n: u64, handler: StallHandler, seen: Arc<std::sync::Mutex<Vec<(u64, String)>>>) {
    let Ok(mut writer) = stream.try_clone() else { return };
    let mut reader = BufReader::new(stream);
    let mut wedged = false;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let Ok(req) = serde_json::from_str::<Value>(line.trim_end()) else { continue };
        let op = req.get("op").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if let Ok(mut s) = seen.lock() {
            s.push((n, op));
        }
        if wedged {
            continue;
        }
        let (wait, answer) = match handler(&req) {
            Stall::Never => {
                wedged = true;
                continue;
            }
            Stall::Answer(a) => (None, a),
            Stall::AnswerAfter(d, a) => (Some(d), a),
        };
        if let Some(d) = wait {
            thread::sleep(d);
        }
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let reply = match answer {
            Ok(result) => serde_json::json!({ "id": id, "ok": true, "result": result }),
            Err(err) => serde_json::json!({ "id": id, "ok": false, "error": err }),
        };
        let mut out = serde_json::to_string(&reply).unwrap();
        out.push('\n');
        if writer.write_all(out.as_bytes()).and_then(|_| writer.flush()).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// The name is not a function of (pid, counter) alone: the random part
    /// keeps two runs with equal pids (pid namespaces) apart.
    #[test]
    fn socket_names_carry_a_random_part() {
        let a = MockArbiter::start(op_handler(|_, _| Ok(Value::Null)));
        let b = MockArbiter::start(op_handler(|_, _| Ok(Value::Null)));
        for m in [&a, &b] {
            let name = m.socket_path.file_name().unwrap().to_string_lossy().to_string();
            let suffix = name.trim_end_matches(".sock").rsplit('-').next().unwrap().to_string();
            assert_eq!(suffix.len(), 16, "a 64-bit hex suffix: {name}");
            assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()), "{name}");
        }
        assert_ne!(a.socket_path, b.socket_path);
    }

    /// A path that already exists is never unlinked and taken over: the next
    /// name is tried, and the existing socket keeps answering its owner.
    #[test]
    fn an_existing_socket_is_left_alone() {
        let a = MockArbiter::start(op_handler(|_, _| Ok(Value::Null)));
        let before = std::fs::metadata(&a.socket_path).unwrap().ino();
        let b = MockArbiter::start(op_handler(|_, _| Ok(Value::Null)));
        assert_eq!(before, std::fs::metadata(&a.socket_path).unwrap().ino(), "the first mock's socket was not replaced");
        assert!(std::os::unix::net::UnixStream::connect(&a.socket_path).is_ok());
        assert!(std::os::unix::net::UnixStream::connect(&b.socket_path).is_ok());
    }

    /// A leaked mock (`leak`) answers for the life of the process and its
    /// socket is gone once the process exits (test-organization.md §8.5). Run
    /// in a child copy of this test binary, so the exit is a real one.
    #[test]
    fn a_leaked_mock_removes_its_socket_when_the_process_exits() {
        const CHILD: &str = "MANDU_MOCK_LEAK_CHILD_OUT";
        if let Ok(out) = std::env::var(CHILD) {
            let m = MockArbiter::start(op_handler(|_, _| Ok(Value::Null))).leak();
            assert!(std::os::unix::net::UnixStream::connect(&m.socket_path).is_ok(), "the leaked mock answers");
            std::fs::write(out, m.socket_path.to_string_lossy().as_bytes()).unwrap();
            return;
        }
        let out = std::env::temp_dir().join(format!("mandu-mock-leak-{}-{:016x}.txt", std::process::id(), random_u64()));
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "mock::tests::a_leaked_mock_removes_its_socket_when_the_process_exits", "--test-threads=1", "--quiet"])
            .env(CHILD, &out)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        let sock = std::fs::read_to_string(&out).unwrap_or_default();
        let _ = std::fs::remove_file(&out);
        assert!(status.success(), "the child run passed");
        assert!(sock.contains("mandu-mock-arbiter-"), "the child named its socket: {sock:?}");
        assert!(!std::path::Path::new(&sock).exists(), "the leaked mock's socket outlived its process: {sock}");
    }
}
