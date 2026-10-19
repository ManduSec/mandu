//! deadline — the supervisor's bounded waits (exec-routing.md §4.4).
//!
//! `supervise_exec` waits on three kinds of thing. The command's own run (the
//! box's exit) is the exec's runtime: a build or a server may legitimately
//! run for hours, so it is bounded only by a deadline the CALLER supplies
//! (`SupervisorConfig::deadline`, `None` in production). The supervisor's own
//! internal waits are another matter: a hand-over from a forked child that
//! never comes (the child stuck before it reports), capture pipes held open
//! by something that outlived the box. Those never block for good: each has
//! a limit of its own, and on expiry the box is killed and the exec refused
//! with a clear error, never continued unsupervised.
//!
//! This module holds the mechanics: the deadline itself, a wait for a child's
//! exit that can give up, a read that can give up, and the kill of a child's
//! whole tree. `Mandu-new`.

#![cfg(feature = "kernel")]

use std::io::{Error, ErrorKind};
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

/// A point past which a wait gives up; `None`: wait as long as it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline(pub Option<Instant>);

impl Deadline {
    /// `limit` from now (`None`: unbounded).
    pub fn after(limit: Option<Duration>) -> Deadline {
        Deadline(limit.map(|d| Instant::now() + d))
    }

    /// The earlier of this deadline and `limit` from now: an internal wait's
    /// own bound, never past the caller's.
    pub fn capped(self, limit: Duration) -> Deadline {
        let own = Instant::now() + limit;
        Deadline(Some(self.0.map_or(own, |d| d.min(own))))
    }

    /// Time left (`None`: unbounded; zero once passed).
    pub fn remaining(self) -> Option<Duration> {
        self.0.map(|d| d.saturating_duration_since(Instant::now()))
    }

    pub fn passed(self) -> bool {
        self.0.is_some_and(|d| Instant::now() >= d)
    }

    /// `poll(2)`'s timeout for at most `tick`: the tick, or less near the end.
    pub fn poll_ms(self, tick: Duration) -> libc::c_int {
        let t = self.remaining().map_or(tick, |r| r.min(tick));
        t.as_millis().min(libc::c_int::MAX as u128) as libc::c_int
    }
}

/// The error a wait that ran out returns: `ErrorKind::TimedOut`, naming it.
pub fn timed_out(what: &str) -> Error {
    Error::new(ErrorKind::TimedOut, format!("{what}: past its deadline; the box was killed (fail-closed)"))
}

/// Wait for the child `pid` to exit until `until`. `keep`: `WNOWAIT`, the
/// child stays waitable (a later wait reaps it). `Ok(None)`: the deadline
/// passed first, the child still running. An unbounded deadline blocks in
/// `waitid`, as the supervisor always did.
pub fn wait_child(pid: i32, until: Deadline, keep: bool) -> std::io::Result<Option<libc::siginfo_t>> {
    let flags = libc::WEXITED | if keep { libc::WNOWAIT } else { 0 } | if until.0.is_some() { libc::WNOHANG } else { 0 };
    let mut nap = Duration::from_millis(1);
    loop {
        // SAFETY: waitid writes into our zeroed, owned siginfo.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, flags) };
        if rc < 0 {
            let e = Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        // SAFETY: si_pid is set by a WEXITED waitid (zero while WNOHANG finds none).
        if unsafe { info.si_pid() } == pid {
            return Ok(Some(info));
        }
        let Some(left) = until.remaining() else { continue };
        if left.is_zero() {
            return Ok(None);
        }
        std::thread::sleep(nap.min(left));
        nap = (nap * 2).min(Duration::from_millis(10));
    }
}

/// A child's end as a status number: its exit code, 128 + the signal that
/// ended it, or `None`.
pub fn exit_code(info: &libc::siginfo_t) -> Option<i32> {
    // SAFETY: si_status is valid for a WEXITED waitid result.
    let st = unsafe { info.si_status() };
    match info.si_code {
        libc::CLD_EXITED => Some(st),
        libc::CLD_KILLED | libc::CLD_DUMPED => Some(128 + st),
        _ => None,
    }
}

/// Has the child `pid` exited (still unreaped)? Never blocks, never reaps.
pub fn has_exited(pid: i32) -> bool {
    // SAFETY: waitid into an owned zeroed siginfo; WNOWAIT leaves it waitable.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
    // ECHILD: nothing to wait for, as good as gone.
    rc < 0 && Error::last_os_error().raw_os_error() == Some(libc::ECHILD) || unsafe { info.si_pid() } == pid
}

/// The pids whose parent is `pid`, and theirs, deepest last (from `/proc`).
fn descendants(pid: i32) -> Vec<i32> {
    let parent_of = |p: i32| -> Option<i32> {
        let stat = std::fs::read_to_string(format!("/proc/{p}/stat")).ok()?;
        stat.get(stat.rfind(')')? + 2..)?.split_whitespace().nth(1)?.parse().ok()
    };
    let all: Vec<(i32, i32)> = std::fs::read_dir("/proc")
        .map(|rd| rd.flatten().filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok()).filter_map(|p| Some((p, parent_of(p)?))).collect())
        .unwrap_or_default();
    let mut out = Vec::new();
    let mut frontier = vec![pid];
    while let Some(p) = frontier.pop() {
        for (c, _) in all.iter().filter(|(_, pp)| *pp == p) {
            out.push(*c);
            frontier.push(*c);
        }
    }
    out
}

/// SIGKILL the child `pid` and every descendant of it, then reap `pid`.
/// The box is bwrap with `--die-with-parent` (its sandbox dies with it); the
/// walk covers the InProcess backend's command and whatever it started.
/// Bounded: a SIGKILLed child ends.
pub fn kill_tree_and_reap(pid: i32) {
    for p in descendants(pid).into_iter().rev() {
        // SAFETY: a signal to a process below our own child.
        unsafe { libc::kill(p, libc::SIGKILL) };
    }
    // SAFETY: our own child.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let mut st = 0;
    loop {
        // SAFETY: reap our own child, killed above.
        let r = unsafe { libc::waitpid(pid, &mut st, 0) };
        if r >= 0 || Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return;
        }
    }
}

/// Is `fd` readable (or hung up) before `until`? `false`: the deadline
/// passed first.
pub fn readable_before(fd: RawFd, until: Deadline) -> bool {
    loop {
        let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: poll one descriptor.
        let rc = unsafe { libc::poll(&mut p, 1, until.poll_ms(Duration::from_secs(3600))) };
        if rc > 0 {
            return true;
        }
        if rc < 0 && Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            // A poll error: let the read that follows report it.
            return true;
        }
        if until.passed() {
            return false;
        }
    }
}

/// `read_exact` of `b` from `fd` before `until`: `Some(true)` read whole,
/// `Some(false)` end of file or an error first, `None` the deadline passed.
pub fn read_exact_before(fd: RawFd, b: &mut [u8], until: Deadline) -> Option<bool> {
    let mut off = 0;
    while off < b.len() {
        if !readable_before(fd, until) {
            return None;
        }
        // SAFETY: reading into our buffer.
        let n = unsafe { libc::read(fd, b[off..].as_mut_ptr() as *mut libc::c_void, b.len() - off) };
        if n < 0 && Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 {
            return Some(false);
        }
        off += n as usize;
    }
    Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fork_sleeper(secs: u32) -> i32 {
        // SAFETY: the child only sleeps and exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::sleep(secs);
                libc::_exit(7);
            }
        }
        pid
    }

    #[test]
    fn a_capped_deadline_never_passes_the_callers() {
        let unbounded = Deadline::after(None);
        assert_eq!(unbounded.remaining(), None);
        assert!(!unbounded.passed());
        let own = unbounded.capped(Duration::from_secs(5)).remaining().unwrap();
        assert!(own <= Duration::from_secs(5) && own > Duration::from_secs(4));
        let caller = Deadline::after(Some(Duration::from_millis(100)));
        assert!(caller.capped(Duration::from_secs(30)).remaining().unwrap() <= Duration::from_millis(100));
        let gone = Deadline::after(Some(Duration::ZERO));
        assert!(gone.passed());
        assert_eq!(gone.remaining(), Some(Duration::ZERO));
    }

    #[test]
    fn a_wait_gives_up_at_its_deadline_and_the_kill_ends_the_child() {
        let pid = fork_sleeper(30);
        let t0 = Instant::now();
        assert!(wait_child(pid, Deadline::after(Some(Duration::from_millis(200))), true).unwrap().is_none());
        assert!(t0.elapsed() < Duration::from_secs(10));
        assert!(!has_exited(pid));
        kill_tree_and_reap(pid);
        // SAFETY: probing a pid we reaped.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "killed and reaped");
    }

    #[test]
    fn a_wait_within_its_deadline_gives_the_exit_and_keep_leaves_it_waitable() {
        let pid = fork_sleeper(0);
        let info = wait_child(pid, Deadline::after(Some(Duration::from_secs(60))), true).unwrap().expect("exited");
        assert_eq!(exit_code(&info), Some(7));
        assert!(has_exited(pid), "WNOWAIT left it waitable");
        let info = wait_child(pid, Deadline::after(None), false).unwrap().expect("reaped");
        assert_eq!(exit_code(&info), Some(7));
    }

    #[test]
    fn a_read_gives_up_at_its_deadline_and_reads_whole_within_it() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let mut b = [0u8; 4];
        let t0 = Instant::now();
        assert_eq!(read_exact_before(fds[0], &mut b, Deadline::after(Some(Duration::from_millis(200)))), None);
        assert!(t0.elapsed() < Duration::from_secs(10));
        unsafe { libc::write(fds[1], b"abcd".as_ptr().cast(), 4) };
        assert_eq!(read_exact_before(fds[0], &mut b, Deadline::after(None)), Some(true));
        assert_eq!(&b, b"abcd");
        unsafe { libc::close(fds[1]) };
        assert_eq!(read_exact_before(fds[0], &mut b, Deadline::after(None)), Some(false), "end of file");
        unsafe { libc::close(fds[0]) };
    }
}
