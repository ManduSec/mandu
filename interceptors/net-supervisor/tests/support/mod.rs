//! Helpers shared by net-supervisor's integration tests: each test file that
//! needs one says `mod support;` (cargo builds no test target of its own from
//! a subdirectory). One copy, so the rules below hold in every file
//! (docs/design/testing/test-organization.md §8.5). The kernel tests of
//! fs-supervisor and exec-supervisor include it by `#[path]`.
//!
//! - Temporary names carry [`run_tag`], the pid AND a random word, never the
//!   pid alone.
//! - Pipes and socketpairs are close-on-exec ([`pipe`], [`socketpair`]).
//! - A wait for a process or a thread the test started has a deadline
//!   ([`reap_within`], [`join_within`], [`readable_within`]): past it the test
//!   fails by name with what it was waiting for and the /proc state of what
//!   it started (each task's state, kernel wait channel and the syscall it is
//!   blocked in), and kills that tree. It never hangs. A wait with no one
//!   child to blame (an adopted orphan, a peer thread, a polled condition:
//!   [`readable_within_tree`], [`read_to_end_within`], [`until_within`])
//!   fails the same way with the whole tree's state and kills nothing. A
//!   wait inside code the test does not own runs under a [`Watchdog`]
//!   ([`bounded`], [`BoundedCommand`]), which kills this process's
//!   descendants past the limit so that wait returns.
//!
//! Not every file uses every helper.
#![allow(dead_code)]

use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The pid of the test process itself, recorded before `main` (an ELF
/// constructor), so a helper can tell it from a child forked by a test: a
/// child must not unwind into libtest's copy, it exits instead.
static TEST_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_test_pid() {
    // SAFETY: getpid has no preconditions.
    TEST_PID.store(unsafe { libc::getpid() }, Ordering::Relaxed);
}

#[used]
#[link_section = ".init_array"]
static RECORD_TEST_PID: extern "C" fn() = record_test_pid;

/// True in the test process, false in a child a test forked.
pub fn in_test_process() -> bool {
    // SAFETY: getpid has no preconditions.
    TEST_PID.load(Ordering::Relaxed) == unsafe { libc::getpid() }
}

/// How long a test waits for a process or thread it started before it fails:
/// `MANDU_TEST_WAIT_S` seconds, default 240. A test that passes takes a few
/// seconds alone and, in the kernel lane's busiest runs, a little over a
/// minute (`a_rename_racing_…`, 2026-10-16); a wait four times that is a hang.
pub fn wait_limit() -> Duration {
    let s = std::env::var("MANDU_TEST_WAIT_S").ok().and_then(|v| v.parse::<u64>().ok()).filter(|s| *s > 0).unwrap_or(240);
    Duration::from_secs(s)
}

fn read_trim(path: &str) -> String {
    std::fs::read_to_string(path).map(|s| s.trim().to_string()).unwrap_or_else(|e| format!("({e})"))
}

/// One task's line: its comm, state, kernel wait channel and the syscall it
/// is in (`/proc/<pid>/task/<tid>/syscall`: the number and arguments of a
/// blocked call, `running`, or unreadable).
fn task_line(pid: i32, tid: i32) -> String {
    let base = format!("/proc/{pid}/task/{tid}");
    let stat = std::fs::read_to_string(format!("{base}/stat")).unwrap_or_default();
    let state = stat.rfind(')').and_then(|i| stat.get(i + 2..i + 3)).unwrap_or("?").to_string();
    let syscall = read_trim(&format!("{base}/syscall"));
    let nr = syscall.split_whitespace().next().unwrap_or("?").to_string();
    format!("{tid} {} {state} wchan={} syscall={nr}", read_trim(&format!("{base}/comm")), read_trim(&format!("{base}/wchan")))
}

/// Every task of `pid`, one line each.
pub fn tasks_report(pid: i32) -> String {
    let mut tids: Vec<i32> = std::fs::read_dir(format!("/proc/{pid}/task")).map(|rd| rd.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect()).unwrap_or_default();
    tids.sort_unstable();
    if tids.is_empty() {
        return format!("  pid {pid}: gone or unreadable\n");
    }
    tids.iter().map(|t| format!("  pid {pid} task {}\n", task_line(pid, *t))).collect()
}

fn ppid_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.get(stat.rfind(')')? + 2..)?.split_whitespace().nth(1)?.parse().ok()
}

/// `pid` and its descendants (by ppid), `pid` first.
pub fn descendants(pid: i32) -> Vec<i32> {
    let all: Vec<(i32, i32)> = std::fs::read_dir("/proc")
        .map(|rd| rd.flatten().filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok()).filter_map(|p| Some((p, ppid_of(p)?))).collect())
        .unwrap_or_default();
    let mut out = vec![pid];
    let mut i = 0;
    while i < out.len() {
        let parent = out[i];
        out.extend(all.iter().filter(|(_, pp)| *pp == parent).map(|(p, _)| *p));
        i += 1;
    }
    out
}

/// What a stuck wait reports: every task of `pid` and of its descendants,
/// then this process's own threads (the supervisor's workers among them).
pub fn stuck_report(pid: i32) -> String {
    let mut s = String::new();
    for p in descendants(pid) {
        s.push_str(&tasks_report(p));
    }
    // SAFETY: getpid has no preconditions.
    let me = unsafe { libc::getpid() };
    s.push_str(&format!("  this process ({me}):\n"));
    s.push_str(&tasks_report(me));
    s
}

/// What a stuck wait reports when no one child is to blame: every task of
/// this process's children and their descendants, then this process's own
/// threads.
pub fn tree_report() -> String {
    // SAFETY: getpid has no preconditions.
    let me = unsafe { libc::getpid() };
    let mut s = String::new();
    for p in descendants(me).into_iter().skip(1) {
        s.push_str(&tasks_report(p));
    }
    s.push_str(&format!("  this process ({me}):\n"));
    s.push_str(&tasks_report(me));
    s
}

/// Fail with `msg`: panic in the test process, or print it and exit 125 in
/// a forked child (unwinding there would run libtest's copy).
fn fail(msg: &str) -> ! {
    if in_test_process() {
        panic!("{msg}");
    }
    let bytes = msg.as_bytes();
    // SAFETY: write to stderr, then exit without unwinding.
    unsafe {
        libc::write(2, bytes.as_ptr() as *const libc::c_void, bytes.len());
        libc::_exit(125)
    }
}

/// Fail a wait that ran out: kill the tree `pid` heads (SIGKILL, then reap
/// `pid`), then fail naming `what` ([`fail`]).
fn give_up(pid: i32, what: &str, limit: Duration, report: &str) -> ! {
    for p in descendants(pid).into_iter().rev() {
        // SAFETY: a signal to a process this test started (or its child).
        unsafe { libc::kill(p, libc::SIGKILL) };
    }
    let mut st = 0;
    // SAFETY: reap the killed child (it is ours); bounded: SIGKILL ends it.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    fail(&format!("STUCK: {what}: pid {pid} still running after {limit:?}; killed it and its descendants. State before the kill:\n{report}"))
}

/// A child's end: its raw wait status and its resource use (`wait4`).
pub struct Reaped {
    pub status: i32,
    pub usage: libc::rusage,
    pub waited: Duration,
}

impl Reaped {
    /// Its exit code, or None when a signal ended it.
    pub fn code(&self) -> Option<i32> {
        if libc::WIFEXITED(self.status) {
            Some(libc::WEXITSTATUS(self.status))
        } else {
            None
        }
    }
    /// One line for a timing report: how long it was waited for, its CPU
    /// time and context switches (a tracee mostly waiting on its guard shows
    /// little CPU and many voluntary switches; one starved of CPU, many
    /// involuntary ones).
    pub fn timing(&self) -> String {
        let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
        format!(
            "{:.1}s waited, cpu user {:.2}s sys {:.2}s, switches voluntary {} involuntary {}",
            self.waited.as_secs_f64(),
            tv(self.usage.ru_utime),
            tv(self.usage.ru_stime),
            self.usage.ru_nvcsw,
            self.usage.ru_nivcsw
        )
    }
}

/// Wait for the child `pid` for at most `limit`; past it, fail by name
/// (`what`) with its tree's state, killed (`give_up`).
pub fn reap_within(pid: i32, limit: Duration, what: &str) -> Reaped {
    let t0 = Instant::now();
    let mut nap = Duration::from_millis(1);
    loop {
        let mut st = 0;
        // SAFETY: wait4 into locals.
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::wait4(pid, &mut st, libc::WNOHANG, &mut ru) };
        if r == pid {
            return Reaped { status: st, usage: ru, waited: t0.elapsed() };
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            panic!("{what}: wait4({pid}): {}", std::io::Error::last_os_error());
        }
        if t0.elapsed() >= limit {
            give_up(pid, what, limit, &stuck_report(pid));
        }
        std::thread::sleep(nap);
        nap = (nap * 2).min(Duration::from_millis(20));
    }
}

/// Wait until `fd` is readable (or hung up) for at most `limit`, while the
/// child `pid` that should write it runs; past it, fail by name with the
/// child's state, killed.
pub fn readable_within(fd: RawFd, pid: i32, limit: Duration, what: &str) {
    let t0 = Instant::now();
    loop {
        let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: poll one descriptor.
        let rc = unsafe { libc::poll(&mut p, 1, 100) };
        if rc > 0 {
            return;
        }
        if t0.elapsed() >= limit {
            give_up(pid, what, limit, &stuck_report(pid));
        }
    }
}

/// Wait until `fd` is readable (or hung up) for at most `limit` when no one
/// child is to blame (an orphan this process adopted, a peer thread, a
/// server the test runs); past it, fail by name with the state of this
/// process's whole tree ([`tree_report`]). Nothing is killed: the tests of
/// a file share the process, and its children may be another test's.
pub fn readable_within_tree(fd: RawFd, limit: Duration, what: &str) {
    let t0 = Instant::now();
    loop {
        let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: poll one descriptor.
        let rc = unsafe { libc::poll(&mut p, 1, 100) };
        if rc > 0 {
            return;
        }
        if t0.elapsed() >= limit {
            fail(&format!("STUCK: {what}: descriptor {fd} still not readable after {limit:?}. State of this process's tree:\n{}", tree_report()));
        }
    }
}

/// `fd` read to its end (end of file, or an error), every read waited for
/// under one deadline of `limit` in all ([`readable_within_tree`]'s failure
/// past it).
pub fn read_to_end_within(fd: RawFd, limit: Duration, what: &str) -> Vec<u8> {
    read_to_end_by(fd, None, limit, what)
}

/// [`read_to_end_within`] of a descriptor the child `pid` writes: past the
/// deadline its tree is killed ([`readable_within`]'s failure).
pub fn read_to_end_from(fd: RawFd, pid: i32, limit: Duration, what: &str) -> Vec<u8> {
    read_to_end_by(fd, Some(pid), limit, what)
}

fn read_to_end_by(fd: RawFd, pid: Option<i32>, limit: Duration, what: &str) -> Vec<u8> {
    let t0 = Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let left = limit.saturating_sub(t0.elapsed());
        match pid {
            Some(pid) => readable_within(fd, pid, left, what),
            None => readable_within_tree(fd, left, what),
        }
        // SAFETY: read into a local buffer.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
}

/// Wait for `done()` to hold, checking every `every`, for at most `limit`;
/// past it, fail by name with this process's tree ([`readable_within_tree`]'s
/// failure). For a loop that polls a condition (a file appearing, a count
/// reached) with no deadline of its own.
pub fn until_within(limit: Duration, every: Duration, what: &str, mut done: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !done() {
        if t0.elapsed() >= limit {
            fail(&format!("STUCK: {what}: still not so after {limit:?}. State of this process's tree:\n{}", tree_report()));
        }
        std::thread::sleep(every);
    }
}

/// Join `h` for at most `limit`; past it, fail by name with this process's
/// threads (a thread cannot be killed: it is left running, the test fails).
pub fn join_within<T>(h: std::thread::JoinHandle<T>, limit: Duration, what: &str) -> std::thread::Result<T> {
    let t0 = Instant::now();
    while !h.is_finished() {
        if t0.elapsed() >= limit {
            // SAFETY: getpid has no preconditions.
            let me = unsafe { libc::getpid() };
            fail(&format!("STUCK: {what}: thread {:?} still running after {limit:?}. This process's threads:\n{}", h.thread().name(), tasks_report(me)));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    h.join()
}

/// A deadline over a call that waits inside code the test does not own (a
/// supervisor's own fork-and-wait, `exec_supervisor::kernel::supervise_exec`),
/// for as long as it lives. Past `limit` its thread prints the STUCK report
/// (what it covers, then this process's whole tree, [`tree_report`]) and
/// kills every descendant of this process, so the wait inside returns; the
/// guard's drop then fails the test by name. The kill cannot tell the call's
/// children from another test's of the same file: a test running beside it
/// may fail too, after the report names the stuck call first.
pub struct Watchdog {
    done: Arc<AtomicBool>,
    fired: Arc<AtomicBool>,
    what: String,
    limit: Duration,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    pub fn start(limit: Duration, what: &str) -> Watchdog {
        let (done, fired) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let (d, f, w) = (done.clone(), fired.clone(), what.to_string());
        let thread = std::thread::Builder::new()
            .name("test-watchdog".into())
            .spawn(move || {
                let t0 = Instant::now();
                while !d.load(Ordering::SeqCst) {
                    if t0.elapsed() >= limit {
                        eprintln!("STUCK: {w}: still running after {limit:?}; killing this process's descendants. State before the kill:\n{}", tree_report());
                        f.store(true, Ordering::SeqCst);
                        // SAFETY: getpid has no preconditions.
                        let me = unsafe { libc::getpid() };
                        for p in descendants(me).into_iter().skip(1).rev() {
                            // SAFETY: a signal to a descendant of this test process.
                            unsafe { libc::kill(p, libc::SIGKILL) };
                        }
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
            .expect("spawn the test watchdog");
        Watchdog { done, fired, what: what.to_string(), limit, thread: Some(thread) }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if self.fired.load(Ordering::SeqCst) && !std::thread::panicking() {
            fail(&format!("STUCK: {}: ran past {:?}; its tree was killed (the state is above)", self.what, self.limit));
        }
    }
}

/// `f()` under a [`Watchdog`] of [`wait_limit`]: `what` names it if it hangs.
pub fn bounded<T>(what: &str, f: impl FnOnce() -> T) -> T {
    let _w = Watchdog::start(wait_limit(), what);
    f()
}

/// `Command::status` / `Command::output` under a [`Watchdog`] of
/// [`wait_limit`], for a command that runs a sandbox or a supervised probe.
pub trait BoundedCommand {
    fn status_bounded(&mut self, what: &str) -> std::io::Result<std::process::ExitStatus>;
    fn output_bounded(&mut self, what: &str) -> std::io::Result<std::process::Output>;
}

impl BoundedCommand for std::process::Command {
    fn status_bounded(&mut self, what: &str) -> std::io::Result<std::process::ExitStatus> {
        bounded(what, || self.status())
    }
    fn output_bounded(&mut self, what: &str) -> std::io::Result<std::process::Output> {
        bounded(what, || self.output())
    }
}

/// Sets its flag when dropped: a helper thread looping on the flag (a race's
/// flipper) stops however the test ends, a panic included, instead of
/// spinning on a CPU for the rest of the run.
pub struct StopOnDrop(pub Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// This process's tag for the names of its temporary files, sockets and IPC
/// objects: the pid AND a random word. The pid alone collides: the kernel
/// lane runs each crate in a pid namespace of its own, so binaries of two
/// crates (or of two lanes at once) get the same small pid and would share,
/// and remove, each other's directories; a pid is reused, and a name known
/// in advance can be taken first. Call it in the test's own thread before a
/// fork (the first call allocates and draws the word).
pub fn run_tag() -> &'static str {
    static TAG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TAG.get_or_init(|| {
        let mut r = [0u8; 4];
        // SAFETY: getrandom into a local buffer.
        let n = unsafe { libc::getrandom(r.as_mut_ptr() as *mut libc::c_void, r.len(), 0) };
        assert_eq!(n, 4, "getrandom: {}", std::io::Error::last_os_error());
        format!("{}-{:08x}", std::process::id(), u32::from_ne_bytes(r))
    })
}

/// A pipe, both ends close-on-exec: libtest runs a file's tests on threads of
/// one process, and a descriptor without the flag leaks into whatever another
/// test's thread spawns meanwhile (bwrap, git, a shell), holding a peer open
/// or handing a tracee a descriptor it never made. A forked child still
/// inherits both ends, so the harness's own children see no difference; one
/// that must keep an end across its exec clears the flag itself, or `dup2`s
/// the end onto the number it needs (a `dup2` copy carries no flag).
pub fn pipe() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 into a local two-element array.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(rc, 0, "pipe2: {}", std::io::Error::last_os_error());
    (fds[0], fds[1])
}

/// A Unix socketpair of type `ty` (`libc::SOCK_STREAM`, `SOCK_DGRAM`,
/// `SOCK_SEQPACKET`), both ends close-on-exec for the reason [`pipe`] gives.
pub fn socketpair(ty: i32) -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: socketpair into a local two-element array.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair: {}", std::io::Error::last_os_error());
    (fds[0], fds[1])
}

/// The kernel's `struct prctl_mm_map` (linux/prctl.h), for
/// [`empty_own_cmdline`].
#[repr(C)]
struct PrctlMmMap {
    start_code: u64,
    end_code: u64,
    start_data: u64,
    end_data: u64,
    start_brk: u64,
    brk: u64,
    start_stack: u64,
    arg_start: u64,
    arg_end: u64,
    env_start: u64,
    env_end: u64,
    auxv: u64,
    auxv_size: u32,
    exe_fd: u32,
}

/// Empty this process's command line (`arg_end = arg_start`) with an
/// unprivileged `PR_SET_MM_MAP`: it then looks inside an exec
/// (`pipe_flow::exec_in_progress`: a live process with no argv) until
/// [`restore_own_cmdline`], the fixture of a holder whose exec has not
/// settled. The argv range to restore, or None: refused here (no
/// CONFIG_CHECKPOINT_RESTORE, or the map was not accepted); the caller
/// SKIPs. Call it in a forked child.
pub fn empty_own_cmdline() -> Option<(u64, u64)> {
    set_own_args(|start, _| (start, start))
}

/// Give this process back the argv range [`empty_own_cmdline`] returned.
pub fn restore_own_cmdline(range: (u64, u64)) -> bool {
    set_own_args(|_, _| range).is_some()
}

/// Look, until [`unhide`], as every process does from its image switch
/// until its exec is done: an empty command line ([`empty_own_cmdline`])
/// and non-dumpable, so a reader that is not root in this process's user
/// namespace cannot read its `/proc/<pid>/fd` or `maps` (one that is, as
/// the guard of `scripts/kernel-tests.sh`, still can). The argv range to
/// give back, or None: this kernel refuses the fixture (the caller SKIPs).
pub fn hide_as_inside_exec() -> Option<(u64, u64)> {
    let argv = empty_own_cmdline()?;
    // SAFETY: prctl on this process's own dumpable flag.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        restore_own_cmdline(argv);
        return None;
    }
    Some(argv)
}

/// End [`hide_as_inside_exec`]: the "exec" is done.
pub fn unhide(argv: Option<(u64, u64)>) {
    // SAFETY: prctl on this process's own dumpable flag.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
    if let Some(range) = argv {
        restore_own_cmdline(range);
    }
}

/// Can this process (the test, not root in its tree's user namespace when
/// it runs on a host without `scripts/kernel-tests.sh`) read `pid`'s
/// descriptor table? A hidden fixture it can read does not hide from the
/// guard either: the test then shows the verdict, not the window.
pub fn table_readable(pid: i32) -> bool {
    std::fs::read_dir(format!("/proc/{pid}/fd")).is_ok()
}

/// `PR_SET_MM_MAP` with this process's own layout (`/proc/self/stat`) and
/// the argv range `pick(start, end)` makes of the current one; the current
/// one on success.
fn set_own_args(pick: impl FnOnce(u64, u64) -> (u64, u64)) -> Option<(u64, u64)> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let after = stat.rfind(')').map(|i| &stat[i + 1..])?;
    // The fields after the name, from field 3 (the state).
    let f: Vec<u64> = after.split_whitespace().skip(1).map(|v| v.parse::<i64>().unwrap_or(0) as u64).collect();
    let field = |n: usize| f.get(n - 4).copied().unwrap_or(0);
    if f.len() < 48 {
        return None;
    }
    let was = (field(48), field(49));
    let (arg_start, arg_end) = pick(was.0, was.1);
    let m = PrctlMmMap {
        start_code: field(26),
        end_code: field(27),
        start_stack: field(28),
        start_data: field(45),
        end_data: field(46),
        start_brk: field(47),
        brk: unsafe { libc::sbrk(0) } as u64,
        arg_start,
        arg_end,
        env_start: field(50),
        env_end: field(51),
        auxv: 0,
        auxv_size: 0,
        exe_fd: u32::MAX,
    };
    // SAFETY: PR_SET_MM_MAP reads `m` (its size passed) and changes only
    // this process's own recorded layout, which `m` copies but for argv.
    let rc = unsafe { libc::prctl(libc::PR_SET_MM, libc::PR_SET_MM_MAP as libc::c_ulong, &m as *const PrctlMmMap, std::mem::size_of::<PrctlMmMap>() as libc::c_ulong, 0 as libc::c_ulong) };
    let empty = std::fs::read("/proc/self/cmdline").map(|c| c.is_empty()).unwrap_or(false);
    (rc == 0 && empty == (arg_start == arg_end)).then_some(was)
}
