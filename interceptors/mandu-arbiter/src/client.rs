//! client — the NDJSON-over-Unix-socket arbiter client.
//!
//! Reimplements `arbiter/ipc/client.ts` natively in Rust. Synchronous and
//! blocking by design: each interceptor's hot path is a single request/response
//! round-trip per intercepted action, and the supervisors are themselves
//! event-loop drivers, so a blocking call against a local Unix socket is the
//! simplest correct model. (A connection is one outstanding request at a time —
//! we write one line, then read exactly one reply line.)
//!
//! Wire framing: write `{ "id": N, "op": "...", ...args }\n`; read one line back
//! `{ "id": N, "ok": true, "result": {...} }` or `{ "id": N, "ok": false,
//! "error": "..." }`. The arbiter preserves order on a connection, so the `id`
//! correlation is belt-and-suspenders.
//!
//! FAIL-CLOSED: every call returns a `Result`; callers MUST treat an `Err` as a
//! deny/redirect-to-AgentView, never a fall-through to raw. The high-level
//! interceptor crates encode that policy in their pure decision functions.
//!
//! BOUNDED (2026-10-17, mandu.md §2.x): a caller that never returns never
//! reaches its fail-closed branch, and a WEDGED arbiter (alive, its socket
//! open, never answering) errors on nothing. Every request therefore runs
//! under one deadline spanning connect + write + reply, as
//! `arbiter/ipc/client.ts` `DEFAULT_REQUEST_TIMEOUT_MS` does:
//! [`DEFAULT_IO_TIMEOUT`] (5 s) for every op, [`REPORT_IO_TIMEOUT`] (2 s) for
//! the reports nothing waits on (`emit`, the twin and clean-verdict reports).
//! Expiry is [`ArbiterError::Timeout`]: the caller's "arbiter unreachable"
//! branch takes it like any other error. The connection it expired on is
//! dropped, never reused: a late answer would otherwise be read as the next
//! request's. No op of this client is a long poll or a stream, so none is
//! exempt; a caller that must wait longer says so with
//! [`ArbiterClient::with_io_timeout`].

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::protocol::*;

/// Errors a arbiter call can produce. Any of these means "arbiter unreachable or
/// refused" → the caller fails closed.
#[derive(Debug)]
pub enum ArbiterError {
    /// Could not connect / read / write the socket.
    Io(io::Error),
    /// The arbiter replied `{ ok:false, error }`.
    Arbiter(String),
    /// The reply could not be parsed, or was missing/mismatched.
    Protocol(String),
    /// The arbiter did not answer `op` within its deadline (connect, write
    /// and reply together): a wedged arbiter, connected but silent, or one
    /// whose listen queue is full. The connection was dropped; the next call
    /// dials afresh.
    Timeout { op: String, after: Duration },
}

impl ArbiterError {
    /// The call ran out of its deadline ([`ArbiterError::Timeout`]).
    pub fn is_timeout(&self) -> bool {
        matches!(self, ArbiterError::Timeout { .. })
    }

    /// Nothing listens at the path dialled (`ENOENT`, `ECONNREFUSED`,
    /// `ENOTSOCK`): the arbiter is down there, not refusing.
    pub fn is_dead_endpoint(&self) -> bool {
        matches!(self, ArbiterError::Io(e) if is_dead_endpoint(e))
    }
}

impl std::fmt::Display for ArbiterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArbiterError::Io(e) => write!(f, "arbiter io error: {e}"),
            ArbiterError::Arbiter(e) => write!(f, "arbiter error: {e}"),
            ArbiterError::Protocol(e) => write!(f, "arbiter protocol error: {e}"),
            ArbiterError::Timeout { op, after } => write!(
                f,
                "arbiter {op} timed out after {} ms (connected but not answering) — fail closed",
                after.as_millis()
            ),
        }
    }
}

impl std::error::Error for ArbiterError {}

impl From<io::Error> for ArbiterError {
    fn from(e: io::Error) -> Self {
        ArbiterError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ArbiterError>;

/// The deadline of every request of a new client: connect + write + reply.
/// Matches `arbiter/ipc/client.ts` `DEFAULT_REQUEST_TIMEOUT_MS`; the
/// decisions on the agent's path (an exec's shell, an open's verdict, a
/// connect's bindings) wait at most this long, then fail closed.
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// The deadline of a report nothing waits on and whose loss costs no
/// protection (`emit`, `reportExecTwins`, `reportExecCleanVerdict`,
/// `execCleanVerdictFor`), capped by the client's own.
pub const REPORT_IO_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a call may wait for its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallKind {
    /// The client's deadline ([`DEFAULT_IO_TIMEOUT`] unless set).
    Decision,
    /// [`REPORT_IO_TIMEOUT`], capped by the client's deadline.
    Report,
}

/// A read, write or connect that gave up at its deadline. A socket timeout
/// surfaces as `EAGAIN` (`WouldBlock`) on Linux and macOS.
fn is_timeout_io(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// What is left of `deadline`, or a timeout when nothing is (a zero socket
/// timeout would mean "none", so one is never set).
fn left(deadline: Instant) -> io::Result<Duration> {
    let d = deadline.saturating_duration_since(Instant::now());
    if d.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "the request's deadline passed"));
    }
    Ok(d)
}

/// Connect to `path`, waiting at most until `deadline` (`None`: as long as
/// the kernel waits). A Unix listener whose queue is full holds a blocking
/// `connect` until it accepts, which a wedged arbiter never does, and each
/// timed-out request leaves one more unaccepted connection in that queue;
/// `SO_SNDTIMEO` set before the `connect` bounds that wait (Linux
/// `unix_stream_connect` sleeps for the send timeout, then `EAGAIN`).
fn connect_before(path: &Path, deadline: Option<Instant>) -> io::Result<UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{FromRawFd, OwnedFd};
    let Some(deadline) = deadline else { return UnixStream::connect(path) };
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: a zeroed sockaddr_un is a valid value of the type.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a socket path must be non-empty, without NUL, and shorter than sun_path",
        ));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (d, b) in addr.sun_path.iter_mut().zip(bytes) {
        *d = *b as libc::c_char;
    }
    let path_off = addr.sun_path.as_ptr() as usize - (&addr as *const libc::sockaddr_un as usize);
    let len = path_off + bytes.len() + 1;
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
    {
        addr.sun_len = len as u8;
    }
    // SAFETY: plain socket(2); the descriptor is owned right below.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor nothing else owns.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: fcntl on our own descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let t = left(deadline)?;
    let usec = t.subsec_micros() as libc::suseconds_t;
    let tv = libc::timeval {
        tv_sec: t.as_secs().min(i32::MAX as u64) as libc::time_t,
        // Never {0, 0}: that is "no timeout".
        tv_usec: if t.as_secs() == 0 && usec == 0 { 1 } else { usec },
    };
    // SAFETY: setsockopt on our descriptor with a timeval of the size given.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: connect with the address built above and its length.
    let rc = unsafe { libc::connect(fd, &addr as *const libc::sockaddr_un as *const libc::sockaddr, len as libc::socklen_t) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(UnixStream::from(owned))
}

/// Write all of `bytes`, each write bounded by what is left of `deadline`.
fn write_all_before(s: &mut UnixStream, bytes: &[u8], deadline: Option<Instant>) -> io::Result<()> {
    let mut off = 0;
    while off < bytes.len() {
        s.set_write_timeout(deadline.map(left).transpose()?)?;
        match s.write(&bytes[off..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "the arbiter socket took no bytes")),
            Ok(n) => off += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    s.flush()
}

/// Read one `\n`-terminated line, all of it before `deadline` (a per-read
/// socket timeout alone would let an answer trickled a byte at a time run
/// for ever). `Ok(None)`: the peer closed first.
fn read_line_before(r: &mut BufReader<UnixStream>, deadline: Option<Instant>) -> io::Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        if r.buffer().is_empty() {
            r.get_ref().set_read_timeout(deadline.map(left).transpose()?)?;
        }
        let buf = match r.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf.is_empty() {
            return Ok(None);
        }
        match buf.iter().position(|&b| b == b'\n') {
            Some(i) => {
                line.extend_from_slice(&buf[..=i]);
                r.consume(i + 1);
                break;
            }
            None => {
                let n = buf.len();
                line.extend_from_slice(buf);
                r.consume(n);
            }
        }
    }
    String::from_utf8(line).map(Some).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// The env var naming the arbiter's HUMAN-PLANE socket (arbiter/ipc/instance.ts
/// `HUMAN_SOCK_ENV`; docs/design/architecture/arbiter-human-plane.md). Set only for the
/// human-facing consumers, never in the agent's own environment.
pub const HUMAN_SOCK_ENV: &str = "MANDU_ARBITER_HUMAN_SOCK";

/// The human-plane socket path from a raw env value: `Some(non-empty)` → the
/// path; unset or empty → an error. PURE (the caller reads the env), so the
/// no-fallback rule is unit-testable without mutating the process env.
pub fn human_sock_from(value: Option<String>) -> Result<PathBuf> {
    match value {
        Some(v) if !v.is_empty() => Ok(PathBuf::from(v)),
        _ => Err(ArbiterError::Protocol(format!(
            "{HUMAN_SOCK_ENV} not set — the human plane is unavailable (never falls back to the data socket)"
        ))),
    }
}

// ── following an arbiter restart (arbiter-human-plane.md §5.1) ─────────────────
//
// The human socket's name carries the arbiter's instance id, so an arbiter
// restarted under a live session listens on a NEW human socket while the data
// socket keeps its spelling. A human-plane client built with
// [`ArbiterClient::human_plane`] re-learns the path when a dial of its own
// finds no listener, the way the launcher learned it: `hello` on the data
// socket, and the answer adopted only after [`acceptable_human_sock`] and the
// candidate's own `hello` (channel `human`, the same instance id). A
// human-plane op is never sent to the data socket. A request already written
// into a dying connection is never retried (some ops spend a verdict); the
// NEXT request dials, and re-learns. Mirrors `arbiter/ipc/client.ts`
// `humanPlaneRediscovery`.

/// The first wait between two rediscoveries of one human socket, and the longest.
pub const REDISCOVER_MIN: Duration = Duration::from_millis(250);
pub const REDISCOVER_MAX: Duration = Duration::from_secs(30);
/// The deadline of each discovery `hello` (a wedged arbiter must not hang the caller).
pub const REDISCOVER_HELLO_TIMEOUT: Duration = Duration::from_secs(3);
/// `sun_path` (Linux 108, macOS 104): a longer path would dial a shortened name.
const SUN_PATH_MAX: usize = if cfg!(target_os = "linux") { 108 } else { 104 };

/// What a rediscovery found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rediscovery {
    /// The path to dial instead.
    Found(PathBuf),
    /// Nothing answers where it asked (the arbiter is down): asked again on
    /// the next dial, the backoff untouched.
    Unreachable,
    /// The arbiter answered and named nothing usable: the backoff grows.
    Nothing,
}

/// Where a client looks for its endpoint's new path, given the stale path.
pub type RediscoverFn = dyn Fn(&Path) -> Rediscovery + Send + Sync;

/// Per original human-socket path, process-wide: the path last re-learned for
/// it (so a client built later, e.g. one per proxied connection, starts there)
/// and the backoff (so a down arbiter is not asked on every dial).
struct Learned {
    path: Option<PathBuf>,
    next_at: Option<Instant>,
    delay: Duration,
}

fn learned() -> &'static Mutex<HashMap<PathBuf, Learned>> {
    static LEARNED: OnceLock<Mutex<HashMap<PathBuf, Learned>>> = OnceLock::new();
    LEARNED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn with_learned<T>(origin: &Path, f: impl FnOnce(&mut Learned) -> T) -> T {
    let mut map = learned().lock().unwrap_or_else(|p| p.into_inner());
    let e = map.entry(origin.to_path_buf()).or_insert(Learned { path: None, next_at: None, delay: REDISCOVER_MIN });
    f(e)
}

/// A dial error that means "nothing listens at this path any more".
fn is_dead_endpoint(e: &io::Error) -> bool {
    const ENOTSOCK: i32 = if cfg!(target_os = "linux") { 88 } else { 38 };
    matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused) || e.raw_os_error() == Some(ENOTSOCK)
}

/// `p` with `.` dropped and `..` applied, lexically (no filesystem access).
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The checks a re-learned human socket must pass before a client dials it:
/// an absolute `.sock` path, in the SAME directory as the stale one (the
/// walled `human/` directory), not the data socket, and short enough to dial
/// as written. PURE.
pub fn acceptable_human_sock(cand: &str, stale: &Path, data: &Path) -> bool {
    let c = Path::new(cand);
    if cand.is_empty() || !c.is_absolute() || !cand.ends_with(".sock") || cand.len() >= SUN_PATH_MAX {
        return false;
    }
    if !stale.is_absolute() {
        return false;
    }
    let (c, s) = (lexical(c), lexical(stale));
    if c.parent() != s.parent() {
        return false;
    }
    c != lexical(data)
}

/// Re-learn a human socket (arbiter-human-plane.md §5.1): the data socket's
/// `hello` names `humanSock`; adopt it only when [`acceptable_human_sock`]
/// passes and the candidate's own `hello` answers `channel: human` with the
/// instance id the data socket reported. `hello` is injected (unit tests).
pub fn rediscover_human(data: &Path, stale: &Path, hello: impl Fn(&Path) -> Option<HelloResult>) -> Option<PathBuf> {
    let h = hello(data)?;
    let cand = h.human_sock.filter(|s| !s.is_empty())?;
    if !acceptable_human_sock(&cand, stale, data) {
        return None;
    }
    let c = hello(Path::new(&cand))?;
    if c.channel.as_deref() != Some("human") {
        return None;
    }
    if let Some(id) = h.instance_id.as_deref() {
        if c.instance_id.as_deref() != Some(id) {
            return None;
        }
    }
    Some(PathBuf::from(cand))
}

/// One `hello` on `path`, bounded by [`REDISCOVER_HELLO_TIMEOUT`].
fn probe_hello(path: &Path) -> Option<HelloResult> {
    probe_hello_at(path).ok()
}

/// As [`probe_hello`], keeping the error (a dead endpoint is told apart).
fn probe_hello_at(path: &Path) -> Result<HelloResult> {
    ArbiterClient::new(path).with_io_timeout(Some(REDISCOVER_HELLO_TIMEOUT)).hello()
}

/// The human-plane rediscovery over real sockets: the data socket's `hello`
/// first (nothing there → [`Rediscovery::Unreachable`]), then
/// [`rediscover_human`]'s checks.
fn rediscover_over_sockets(data: &Path, stale: &Path) -> Rediscovery {
    let first = match probe_hello_at(data) {
        Ok(h) => h,
        Err(ArbiterError::Io(e)) if is_dead_endpoint(&e) => return Rediscovery::Unreachable,
        Err(_) => return Rediscovery::Nothing,
    };
    let found = rediscover_human(data, stale, |p| if p == data { Some(first.clone()) } else { probe_hello(p) });
    match found {
        Some(p) => Rediscovery::Found(p),
        None => Rediscovery::Nothing,
    }
}

/// The process listening at the other end of a connected Unix stream, as the
/// kernel recorded it when that process called `listen` ([`ArbiterClient::peer_cred`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub pid: i32,
    pub uid: u32,
}

#[cfg(target_os = "linux")]
fn peer_cred_of(s: &UnixStream) -> Option<PeerCred> {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt into a local ucred of the length given.
    let rc = unsafe {
        libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut libc::ucred as *mut libc::c_void, &mut len)
    };
    if rc != 0 || len as usize != std::mem::size_of::<libc::ucred>() {
        return None;
    }
    Some(PeerCred { pid: cred.pid, uid: cred.uid })
}

#[cfg(not(target_os = "linux"))]
fn peer_cred_of(_s: &UnixStream) -> Option<PeerCred> {
    None
}

/// A blocking NDJSON arbiter client over a Unix-domain socket.
pub struct ArbiterClient {
    socket_path: PathBuf,
    stream: Option<BufReader<UnixStream>>,
    next_id: u64,
    /// The path this client was built for (the key of its re-learned path).
    origin: PathBuf,
    rediscover: Option<Arc<RediscoverFn>>,
    rediscoveries: u64,
    io_timeout: Option<Duration>,
    /// Whether `emit` sends (observability only; every other op always does).
    events: bool,
}

impl ArbiterClient {
    /// Construct a client for a socket path (does not connect yet).
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        let p = socket_path.as_ref().to_path_buf();
        ArbiterClient {
            origin: p.clone(),
            socket_path: p,
            stream: None,
            next_id: 1,
            rediscover: None,
            rediscoveries: 0,
            io_timeout: Some(DEFAULT_IO_TIMEOUT),
            events: true,
        }
    }

    /// The same client with each request's deadline set to `t` (connect +
    /// write + reply; reports wait at most [`REPORT_IO_TIMEOUT`] within it).
    /// `None` removes the bound: a request then waits for as long as the
    /// arbiter takes, which no caller on the agent's path may do.
    pub fn with_io_timeout(mut self, t: Option<Duration>) -> Self {
        self.set_io_timeout(t);
        self
    }

    /// Set each request's deadline (see [`ArbiterClient::with_io_timeout`]).
    /// Takes effect on the next request. A zero duration is taken as 1 ms.
    pub fn set_io_timeout(&mut self, t: Option<Duration>) {
        self.io_timeout = t.map(|d| d.max(Duration::from_millis(1)));
    }

    /// The same client with its observability events on or off. Off, `emit`
    /// sends nothing and answers `seq: -1` (as a suppressed event does); no
    /// other op is touched, so a caller that turns its events off keeps every
    /// report and decision (arbiter-human-plane.md §5.3: the guard's
    /// `MANDU_NET_GUARD_EVENTS=0`).
    pub fn with_events(mut self, on: bool) -> Self {
        self.events = on;
        self
    }

    /// Whether `emit` sends ([`ArbiterClient::with_events`]).
    pub fn events_enabled(&self) -> bool {
        self.events
    }

    /// Each request's deadline (`None`: unbounded).
    pub fn io_timeout(&self) -> Option<Duration> {
        self.io_timeout
    }

    /// The deadline of one call of `kind`.
    fn timeout_for(&self, kind: CallKind) -> Option<Duration> {
        match kind {
            CallKind::Decision => self.io_timeout,
            CallKind::Report => self.io_timeout.map(|t| t.min(REPORT_IO_TIMEOUT)),
        }
    }

    /// A client that, when a dial of its path finds no listener, asks
    /// `rediscover` for the path to dial instead (with the process-wide
    /// backoff), and starts at the path last re-learned for `socket_path`.
    pub fn with_rediscovery(socket_path: impl AsRef<Path>, rediscover: Arc<RediscoverFn>) -> Self {
        let mut c = ArbiterClient::new(socket_path);
        if let Some(p) = with_learned(&c.origin, |l| l.path.clone()) {
            c.socket_path = p;
        }
        c.rediscover = Some(rediscover);
        c
    }

    /// A HUMAN-PLANE client (arbiter-human-plane.md §5.1) that follows the
    /// arbiter across a restart: with `data` (the launcher's
    /// `MANDU_ARBITER_SOCK`) it re-learns the human socket there when its own
    /// stops answering ([`rediscover_human`]); without it, a plain client. A
    /// human-plane op is never sent to the data socket.
    pub fn human_plane(human: impl AsRef<Path>, data: Option<&Path>) -> Self {
        match data.filter(|d| !d.as_os_str().is_empty()) {
            Some(d) => {
                let d = d.to_path_buf();
                ArbiterClient::with_rediscovery(human, Arc::new(move |stale: &Path| rediscover_over_sockets(&d, stale)))
            }
            None => ArbiterClient::new(human),
        }
    }

    /// The path this client dials now.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// How many times this client moved to a re-learned path.
    pub fn rediscoveries(&self) -> u64 {
        self.rediscoveries
    }

    /// Who listens at the other end of this client's CURRENT connection, as
    /// the kernel recorded it (Linux `SO_PEERCRED`: the pid and uid of the
    /// process that called `listen`, which no answer of the peer can change).
    /// `None` when not connected (call it right after a request, on the same
    /// connection the answer came on), or off Linux. A peer in another pid
    /// namespace reads as pid 0. arbiter-human-plane.md §5.2: the guard's
    /// check that a human socket it moves to is served by the arbiter that
    /// answers the data socket.
    pub fn peer_cred(&self) -> Option<PeerCred> {
        let s = self.stream.as_ref()?.get_ref();
        peer_cred_of(s)
    }

    /// Construct from the `MANDU_ARBITER_SOCK` environment variable — the DATA
    /// socket. The original-returning ops (`desymbolize`, a shallow `resolve`)
    /// are refused there; use [`ArbiterClient::human_from_env`] for them.
    pub fn from_env() -> Result<Self> {
        let path = std::env::var("MANDU_ARBITER_SOCK").map_err(|_| {
            ArbiterError::Protocol("MANDU_ARBITER_SOCK not set".into())
        })?;
        Ok(ArbiterClient::new(path))
    }

    /// Construct from `MANDU_ARBITER_HUMAN_SOCK` — the arbiter's HUMAN-PLANE
    /// socket (docs/design/architecture/arbiter-human-plane.md), the only socket that
    /// answers `desymbolize` and a shallow `resolve`. Unset → `Err`: there is
    /// deliberately NO fallback to `MANDU_ARBITER_SOCK`, and the caller fails
    /// closed (withholds) exactly as for an unreachable arbiter.
    pub fn human_from_env() -> Result<Self> {
        Ok(ArbiterClient::new(human_sock_from(std::env::var(HUMAN_SOCK_ENV).ok())?))
    }

    fn ensure_connected(&mut self, deadline: Option<Instant>) -> io::Result<&mut BufReader<UnixStream>> {
        if self.stream.is_none() {
            let s = self.dial(deadline)?;
            self.stream = Some(BufReader::new(s));
        }
        Ok(self.stream.as_mut().unwrap())
    }

    /// Dial the current path; when nothing listens there and a rediscovery is
    /// set (and the backoff allows), dial the path it names instead. Each
    /// connect waits at most until `deadline`.
    fn dial(&mut self, deadline: Option<Instant>) -> io::Result<UnixStream> {
        let err = match connect_before(&self.socket_path, deadline) {
            Ok(s) => {
                if self.rediscover.is_some() {
                    with_learned(&self.origin, |l| {
                        l.next_at = None;
                        l.delay = REDISCOVER_MIN;
                    });
                }
                return Ok(s);
            }
            Err(e) => e,
        };
        let Some(rediscover) = self.rediscover.clone() else { return Err(err) };
        if !is_dead_endpoint(&err) {
            return Err(err);
        }
        let now = Instant::now();
        if with_learned(&self.origin, |l| l.next_at.is_some_and(|t| now < t)) {
            return Err(err);
        }
        // The backoff advances only when the arbiter answered and named
        // nothing usable: while it is down (its data socket does not answer
        // either) a rediscovery costs one failed connect, like the dial
        // itself, and the first dial after it is back must not wait out a
        // window grown during the downtime.
        let next = match rediscover(&self.socket_path) {
            Rediscovery::Found(p) if p != self.socket_path => p,
            Rediscovery::Unreachable => return Err(err),
            _ => {
                with_learned(&self.origin, |l| {
                    l.next_at = Some(now + l.delay);
                    l.delay = (l.delay * 2).min(REDISCOVER_MAX);
                });
                return Err(err);
            }
        };
        let s = connect_before(&next, deadline)?;
        with_learned(&self.origin, |l| {
            l.path = Some(next.clone());
            l.next_at = None;
            l.delay = REDISCOVER_MIN;
        });
        self.socket_path = next;
        self.rediscoveries += 1;
        Ok(s)
    }

    /// Drop a dead connection so the next call reconnects.
    fn reset(&mut self) {
        self.stream = None;
    }

    /// Connect if needed and write one request line before `deadline`; on
    /// any error the connection is dropped (the next call reconnects).
    fn write_line(&mut self, line: &str, deadline: Option<Instant>) -> io::Result<()> {
        let res = self.ensure_connected(deadline).and_then(|r| write_all_before(r.get_mut(), line.as_bytes(), deadline));
        if res.is_err() {
            self.reset();
        }
        res
    }

    /// Low-level request: build `{id, op, ...args}`, write one line, read one
    /// reply line, return the `result` deserialized into `T`. Under the
    /// client's deadline ([`CallKind::Decision`]).
    fn request<T: DeserializeOwned>(&mut self, op: &str, args: Value) -> Result<T> {
        self.request_as(CallKind::Decision, op, args)
    }

    /// [`ArbiterClient::request`] under the deadline of `kind`: connect,
    /// write and the whole reply line together. Any failure that can leave
    /// the connection's framing in doubt (an I/O error, a timeout, a torn or
    /// unparsable line, a reply to another request) drops the connection, so
    /// a late answer is never read as the next request's.
    fn request_as<T: DeserializeOwned>(&mut self, kind: CallKind, op: &str, args: Value) -> Result<T> {
        let timeout = self.timeout_for(kind);
        let deadline = timeout.map(|t| Instant::now() + t);
        let failed = |e: io::Error| match timeout {
            Some(after) if is_timeout_io(&e) => ArbiterError::Timeout { op: op.to_string(), after },
            _ => ArbiterError::Io(e),
        };
        let id = self.next_id;
        self.next_id += 1;

        // Compose the envelope: { id, op, ...args }.
        let mut obj: Map<String, Value> = match args {
            Value::Object(m) => m,
            Value::Null => Map::new(),
            other => {
                return Err(ArbiterError::Protocol(format!(
                    "request args must be a JSON object, got {other:?}"
                )))
            }
        };
        obj.insert("id".into(), Value::from(id));
        obj.insert("op".into(), Value::from(op));
        let mut line = serde_json::to_string(&Value::Object(obj))
            .map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        line.push('\n');

        // Write, then read exactly one reply line. On any IO error, reset so a
        // retry reconnects (but we propagate the error — callers fail closed).
        //
        // One exception, for a client that follows a restart (§5.1): a write
        // on a REUSED connection whose peer is already gone fails with EPIPE
        // before a byte is delivered (a Unix stream does not buffer for a
        // closed peer), so nothing reached any arbiter and the request is sent
        // once more on a fresh dial (which may re-learn the path). A request
        // that WAS written is never retried: the read below just fails.
        let reused = self.stream.is_some();
        let mut sent = self.write_line(&line, deadline);
        if let Err(e) = &sent {
            if reused && self.rediscover.is_some() && e.kind() == io::ErrorKind::BrokenPipe {
                sent = self.write_line(&line, deadline);
            }
        }
        sent.map_err(failed)?;
        let reader = self.stream.as_mut().expect("connected by write_line");

        let resp_line = match read_line_before(reader, deadline) {
            Ok(Some(l)) => l,
            Ok(None) => {
                self.reset();
                return Err(ArbiterError::Protocol("arbiter closed connection".into()));
            }
            Err(e) => {
                // Timed out, or torn: what is left of this reply (or a late
                // one) must never be read as the next request's.
                self.reset();
                return Err(if e.kind() == io::ErrorKind::InvalidData {
                    ArbiterError::Protocol(format!("bad reply line: {e}"))
                } else {
                    failed(e)
                });
            }
        };

        let resp: Value = match serde_json::from_str(resp_line.trim_end()) {
            Ok(v) => v,
            Err(e) => {
                self.reset();
                return Err(ArbiterError::Protocol(format!("bad reply json: {e}")));
            }
        };

        // Correlate id (best-effort; ordering is preserved per connection).
        // A reply to another request means the framing is off: drop it.
        if let Some(rid) = resp.get("id").and_then(|v| v.as_u64()) {
            if rid != id {
                self.reset();
                return Err(ArbiterError::Protocol(format!(
                    "reply id {rid} != request id {id}"
                )));
            }
        }

        let ok = resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        if !ok {
            let err = resp
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown arbiter error")
                .to_string();
            return Err(ArbiterError::Arbiter(err));
        }

        let result = resp.get("result").cloned().unwrap_or(Value::Null);
        serde_json::from_value(result)
            .map_err(|e| ArbiterError::Protocol(format!("bad result shape: {e}")))
    }

    // ── typed ops ──────────────────────────────────────────────────────────────

    /// `classify` — data-trust-policy classification (ingress).
    pub fn classify(&mut self, req: &ClassifyRequest) -> Result<ClassifyResult> {
        self.request("classify", serde_json::json!({ "request": req }))
    }

    /// `symbolize` — allocate (or reuse) a symbol for an untrusted value.
    pub fn symbolize(&mut self, args: &SymbolizeArgs) -> Result<SymbolizeResult> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("symbolize", v)
    }

    /// `desymbolize` — replace every known symbol in `text` with its raw value.
    /// HUMAN PLANE ONLY: call it on a [`ArbiterClient::human_from_env`] client;
    /// the data socket refuses it.
    pub fn desymbolize(&mut self, text: &str) -> Result<DesymbolizeResult> {
        self.request("desymbolize", serde_json::json!({ "text": text }))
    }

    /// `resolve` — resolve one symbol name to its raw value (None if unknown).
    /// This is the SHALLOW resolve: HUMAN PLANE ONLY (a
    /// [`ArbiterClient::human_from_env`] client); the data socket refuses it.
    pub fn resolve(&mut self, symbol: &str) -> Result<ResolveResult> {
        self.request("resolve", serde_json::json!({ "symbol": symbol }))
    }

    /// `desymbolizationDecision` — the egress gate.
    pub fn desymbolization_decision(
        &mut self,
        req: &DesymbolizationRequest,
    ) -> Result<DesymbolizationDecision> {
        self.request(
            "desymbolizationDecision",
            serde_json::json!({ "request": req }),
        )
    }

    /// `classifyExec` — select AgentShell vs HumanShell.
    pub fn classify_exec(&mut self, args: &ClassifyExecArgs) -> Result<ExecClassifyDecision> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("classifyExec", v)
    }

    /// `resolveExecArgv` — desymbolize argv for a shell after the data-usage check.
    pub fn resolve_exec_argv(
        &mut self,
        args: &ResolveExecArgvArgs,
    ) -> Result<ResolveExecArgvResult> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("resolveExecArgv", v)
    }

    /// `execDecisionFor` — the proxy's recorded execGate decision for a command,
    /// by signature (exec-routing.md §4 step 1). A miss returns `decision: None`.
    pub fn exec_decision_for(
        &mut self,
        args: &ExecDecisionForArgs,
    ) -> Result<ExecDecisionForResult> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("execDecisionFor", v)
    }

    /// `escalateExec` — may an AgentShell command that needs a restricted resource
    /// escalate to HumanShell? (exec-routing.md §5). Approved → HumanShell;
    /// otherwise stay AgentShell (a pending approval is queued).
    pub fn escalate_exec(&mut self, args: &EscalateExecArgs) -> Result<EscalateExecResult> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("escalateExec", v)
    }

    /// `reportExecCleanVerdict` — report one finished boxed invocation's clean
    /// verdict (exec-routing.md §8.5). The report rides NESTED under a
    /// `report` field (matching the TS op shape — unlike most flattened ops).
    /// Returns what the arbiter's fail-closed gate chain RESOLVED it to; the
    /// caller treats the resolution as informational (the classify-time upgrade
    /// consumes the store, not this return value). Best-effort by usage: a
    /// reporting failure only costs the upgrade, never the exec.
    pub fn report_exec_clean_verdict(
        &mut self,
        report: &ExecCleanVerdictReport,
    ) -> Result<ExecCleanVerdict> {
        let r: ReportExecCleanVerdictResult = self.request_as(
            CallKind::Report,
            "reportExecCleanVerdict",
            serde_json::json!({ "report": report }),
        )?;
        Ok(r.verdict)
    }

    /// The same report from the session's guard, carrying the reporter token
    /// it claimed (exec-routing.md §8.5.3). Only such a report can resolve
    /// CLEAN, and the verdict is recorded for the token's session.
    pub fn report_exec_clean_verdict_as_reporter(
        &mut self,
        report: &ExecCleanVerdictReport,
        reporter_token: &str,
    ) -> Result<ExecCleanVerdict> {
        let r: ReportExecCleanVerdictResult = self.request_as(
            CallKind::Report,
            "reportExecCleanVerdict",
            serde_json::json!({ "report": report, "reporterToken": reporter_token }),
        )?;
        Ok(r.verdict)
    }

    /// `claimCleanReporter` — the session guard's one claim of its reporter
    /// token, before its agent starts (exec-routing.md §8.5.3). `Err` when
    /// the launcher did not offer a reporter, or on a second claim (which
    /// revokes the reporter for good).
    pub fn claim_clean_reporter(&mut self, session_key: &str) -> Result<String> {
        let r: ClaimCleanReporterResult = self.request(
            "claimCleanReporter",
            serde_json::json!({ "sessionKey": session_key }),
        )?;
        Ok(r.token)
    }

    /// `execCleanVerdictFor` — the resolved clean verdict for a callId, or None
    /// on a miss (observability / tests / the supervisor double-checking).
    pub fn exec_clean_verdict_for(&mut self, call_id: &str) -> Result<Option<ExecCleanVerdict>> {
        let r: ExecCleanVerdictForResult = self.request_as(
            CallKind::Report,
            "execCleanVerdictFor",
            serde_json::json!({ "callId": call_id }),
        )?;
        Ok(r.verdict)
    }

    /// `reportExecTwins` — the exec box's symbol-twin hint for one AgentShell
    /// leaf it is about to run (symbol-twin-shell-blindness.md §4.1 v2): the
    /// paths the leaf named whose AgentView twin is solely symbol tokens. Rides
    /// NESTED under `report` (like the clean verdict). UTILITY-ONLY and
    /// best-effort by usage: a failure only costs the proxy's `[mandu:twin]`
    /// note for a pipeline / post-`cd` leaf, never the exec.
    pub fn report_exec_twins(&mut self, report: &ExecTwinReport) -> Result<ReportExecTwinsResult> {
        self.request_as(CallKind::Report, "reportExecTwins", serde_json::json!({ "report": report }))
    }

    /// `emit` — append one observability event (fire-and-forget). Returns the
    /// arbiter-assigned seq. Callers MUST NOT gate any decision on this.
    pub fn emit(&mut self, event: &crate::event::ManduEvent) -> Result<EmitResult> {
        if !self.events {
            return Ok(EmitResult { seq: -1 });
        }
        // Tenancy (policy-surface.md §2.7): stamp the emitter's tenant
        // (MANDU_TENANT) on the wire form so a live arbiter refuses a test
        // emitter's events and vice versa — the same stamp the TS emitters carry.
        let mut ev = serde_json::to_value(event).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        crate::event::stamp_tenant(&mut ev, crate::event::tenant_from_env().as_deref());
        self.request_as(CallKind::Report, "emit", serde_json::json!({ "event": ev }))
    }

    /// `ping` — liveness check.
    pub fn ping(&mut self) -> Result<PingResult> {
        self.request("ping", Value::Null)
    }

    /// `hello` — the human-plane socket's path and the channel this socket
    /// is (confidentiality plan 13 §3 D9).
    pub fn hello(&mut self) -> Result<HelloResult> {
        self.request("hello", Value::Null)
    }

    /// `taintProcess` — mark a process tainted (touched an untrusted host). Ack.
    pub fn taint_process(&mut self, args: &TaintProcessArgs) -> Result<()> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        let _: serde_json::Value = self.request("taintProcess", v)?;
        Ok(())
    }

    /// `decideSecretOpen` — plan 10 §4.1: what an open of a registered secret
    /// by this process becomes (raw | twin | deny | ask); the arbiter records
    /// the taint on `raw` before answering.
    pub fn decide_secret_open(&mut self, args: &DecideSecretOpenArgs) -> Result<SecretOpenVerdict> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("decideSecretOpen", v)
    }

    /// `decideProtectedWrite` — a change under an `ask` write-protect entry:
    /// allow | deny | ask (sandbox-security-review-2026-09-28 finding 6).
    pub fn decide_protected_write(&mut self, args: &DecideProtectedWriteArgs) -> Result<ProtectedWriteVerdict> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("decideProtectedWrite", v)
    }

    /// `readerProgram` — Plan 13 D8 (2026-10-03): what the arbiter knows a
    /// binary to be (a printer, a program that runs code, a renamed copy of
    /// an installed one), by name and by the host's program hashes.
    pub fn reader_program(&mut self, args: &ReaderProgramArgs) -> Result<ReaderProgramResult> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("readerProgram", v)
    }

    /// `registerRepository` — confidentiality-plan-14 §11.1 R1: add the work
    /// tree `root` lies in to the arbiter's known-repository registry, so the
    /// next launch resolves its locks (the guard's backstop refused it: a
    /// locked object with no sanitized copy). Data plane, add-only; the
    /// arbiter refuses what is not a work tree, Mandu's own home, a full
    /// registry.
    pub fn register_repository(&mut self, root: &str) -> Result<RegisterRepositoryResult> {
        let v = serde_json::to_value(RegisterRepositoryArgs { root: root.to_string() }).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("registerRepository", v)
    }

    /// `recordExecRoot` — plan 10 §4.2: an exec in the agent tree (lineage +
    /// signature). Best-effort: the caller has already let the exec proceed.
    pub fn record_exec_root(&mut self, args: &RecordExecRootArgs) -> Result<()> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        let _: serde_json::Value = self.request("recordExecRoot", v)?;
        Ok(())
    }

    /// `sessionExecRoot` — confidentiality.md §4: is this call root a HIGH
    /// session's command (then it holds what the session read)? Asked before
    /// the guard lets the exec go.
    pub fn session_exec_root(&mut self, args: &SessionExecRootArgs) -> Result<SessionExecRootResult> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("sessionExecRoot", v)
    }
    /// `guardAttach` — confidentiality.md §4: this session's processes are
    /// held by this guard (a HIGH session's command card says so).
    pub fn guard_attach(&mut self, args: &GuardAttachArgs) -> Result<GuardAttachResult> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("guardAttach", v)
    }
    /// `taintedProcessBindings` — plan 10 §4.3: the hosts a tainted process may
    /// still reach (empty with `tainted` ⇒ loopback only).
    pub fn tainted_process_bindings(&mut self, args: &TaintedProcessBindingsArgs) -> Result<TaintedProcessBindings> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("taintedProcessBindings", v)
    }

    /// `labelWrittenPathTainted` — plan 10 filesystem exit: whether the file
    /// now carries a derived label (confidentiality plan 13 D4: the guard
    /// adds a labelled path to its live index).
    pub fn label_written_path_tainted(&mut self, args: &LabelWrittenPathTaintedArgs) -> Result<LabelWrittenPathTaintedResult> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("labelWrittenPathTainted", v)
    }

    /// `recordProcessFlow` — confidentiality plan 13 §9 R1: `procKey` holds
    /// what `flowsFrom` hold, through a descriptor. Ack. An older arbiter
    /// answers `unknown op` (the caller ignores it: the guard's own
    /// confinement of the receiver stands).
    pub fn record_process_flow(&mut self, args: &RecordProcessFlowArgs) -> Result<()> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        let _: serde_json::Value = self.request("recordProcessFlow", v)?;
        Ok(())
    }

    /// `recordAgentFlow` — confidentiality plan 13 §4.5.1: the agent process
    /// itself holds a channel a holder writes into (or no longer holds it,
    /// `closed`). Unlike `record_process_flow` an error is the caller's to
    /// act on (an older arbiter's `unknown op` included): the guard refuses
    /// the connection, or the raw open, it could not record (fail-closed).
    pub fn record_agent_flow(&mut self, args: &RecordAgentFlowArgs) -> Result<()> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        let _: serde_json::Value = self.request("recordAgentFlow", v)?;
        Ok(())
    }

    /// `derivedLabelsSince` — confidentiality plan 13 D4: the derived labels
    /// changed after `since` in `epoch` (every row on another epoch). `None`:
    /// an arbiter that does not know the op (an older one, a test mock that
    /// answers null, or `unknown op`).
    pub fn derived_labels_since(&mut self, args: &DerivedLabelsSinceArgs) -> Result<Option<DerivedLabelsSince>> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        match self.request::<Option<DerivedLabelsSince>>("derivedLabelsSince", v) {
            Err(ArbiterError::Arbiter(e)) if e.starts_with("unknown op") => Ok(None),
            other => other,
        }
    }

    /// `labelRootsSince` — where the human labels above `public` lie
    /// (confidentiality.md §6, 2026-10-17), unless they are what `key`
    /// names. `None`: an arbiter that does not know the op.
    pub fn label_roots_since(&mut self, args: &LabelRootsSinceArgs) -> Result<Option<LabelRootsSince>> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        match self.request::<Option<LabelRootsSince>>("labelRootsSince", v) {
            Err(ArbiterError::Arbiter(e)) if e.starts_with("unknown op") => Ok(None),
            other => other,
        }
    }

    /// `labelledLevel` — the level a path under a label root classifies at
    /// now. `None`: an arbiter that does not know the op.
    pub fn labelled_level(&mut self, args: &LabelledLevelArgs) -> Result<Option<LabelledLevel>> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        match self.request::<Option<LabelledLevel>>("labelledLevel", v) {
            Err(ArbiterError::Arbiter(e)) if e.starts_with("unknown op") => Ok(None),
            other => other,
        }
    }

    /// `followDerivedLabel` — confidentiality plan 13 D4: the derived label of
    /// `from` follows its file to `to`. Raise-only.
    pub fn follow_derived_label(&mut self, args: &FollowDerivedLabelArgs) -> Result<FollowDerivedLabelResult> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("followDerivedLabel", v)
    }

    /// `registerSecret` — the arbiter reads a labelled file and mints its
    /// symbol and twin text (the guard's twin of a derived file, plan 13 D4).
    pub fn register_secret(&mut self, path: &str) -> Result<RegisterSecretResult> {
        let v = serde_json::to_value(RegisterSecretArgs { path: path.to_string() }).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("registerSecret", v)
    }

    /// `processLineage` — record a parent→child spawn edge. Ack.
    pub fn process_lineage(&mut self, args: &ProcessLineageArgs) -> Result<()> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        let _: serde_json::Value = self.request("processLineage", v)?;
        Ok(())
    }

    /// `isProcessTainted` — tainted iff this process OR a transitive ancestor is.
    pub fn is_process_tainted(&mut self, proc_key: &str) -> Result<IsProcessTaintedResult> {
        self.request(
            "isProcessTainted",
            serde_json::json!({ "procKey": proc_key }),
        )
    }

    /// `taintFile` — mark a file's content untrusted-by-origin. Ack.
    pub fn taint_file(&mut self, args: &TaintFileArgs) -> Result<()> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        let _: serde_json::Value = self.request("taintFile", v)?;
        Ok(())
    }

    /// `fileTrust` — untrusted if EITHER the content-hash OR the path is on record.
    pub fn file_trust(&mut self, args: &FileTrustArgs) -> Result<FileTrustResult> {
        let v = serde_json::to_value(args).map_err(|e| ArbiterError::Protocol(e.to_string()))?;
        self.request("fileTrust", v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The human plane has no fallback (docs/design/architecture/arbiter-human-plane.md):
    /// unset or empty → an error, whatever the data socket says.
    #[test]
    fn human_sock_from_requires_the_human_socket() {
        assert_eq!(
            human_sock_from(Some("/run/mandu/human/x.sock".into())).unwrap(),
            PathBuf::from("/run/mandu/human/x.sock")
        );
        assert!(human_sock_from(None).is_err());
        assert!(human_sock_from(Some(String::new())).is_err());
        let msg = human_sock_from(None).unwrap_err().to_string();
        assert!(msg.contains(HUMAN_SOCK_ENV), "{msg}");
    }

    /// The data socket's refusal surfaces as an `Err` (the caller withholds).
    #[test]
    fn a_human_plane_refusal_is_an_error() {
        use crate::mock::{op_handler, MockArbiter};
        let data = MockArbiter::start(op_handler(|op, _r| match op {
            "resolve" | "desymbolize" => Err(format!(
                "human-plane: '{op}' returns originals and is accepted only on the human socket"
            )),
            other => Err(format!("unexpected {other}")),
        }));
        let mut c = ArbiterClient::new(&data.socket_path);
        match c.resolve("$MDU:x[beef]") {
            Err(ArbiterError::Arbiter(e)) => assert!(e.starts_with("human-plane:"), "{e}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(c.desymbolize("$MDU:x[beef]").is_err());
    }

    /// Plan 14 §11.1 R1: the wire shape of `registerRepository` (arbiter/ipc
    /// protocol.ts `RegisterRepositoryOpRequest` / `RegisterRepositoryResult`).
    #[test]
    fn register_repository_sends_the_root_and_reads_the_answer() {
        use crate::mock::{op_handler, MockArbiter};
        let data = MockArbiter::start(op_handler(|op, r| match op {
            "registerRepository" => {
                let root = r.get("root").and_then(|v| v.as_str()).unwrap_or("").to_string();
                Ok(serde_json::json!({ "axis": true, "root": root, "added": true, "known": 3 }))
            }
            other => Err(format!("unexpected {other}")),
        }));
        let mut c = ArbiterClient::new(&data.socket_path);
        let got = c.register_repository("/w/api").unwrap();
        assert!(got.axis && got.added);
        assert_eq!(got.root.as_deref(), Some("/w/api"));
        assert_eq!(got.known, 3);
        let off: RegisterRepositoryResult = serde_json::from_value(serde_json::json!({ "axis": false, "root": null, "added": false, "known": 0 })).unwrap();
        assert!(off.root.is_none());
    }
}
