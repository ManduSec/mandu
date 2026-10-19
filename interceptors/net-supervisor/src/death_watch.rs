//! death_watch — a holder's death stamped when it happens (exec-routing.md
//! §7.5, "A fork after the taint"; confidentiality-plan-13 §4.5.1,
//! 2026-10-09).
//!
//! The orphan rule (`TaintedSet::orphan_holders`, `lineage::orphan_of`)
//! gives an orphan root the taint of every holder whose window
//! `[since, gone_at]` covers the orphan's birth: a process born while a holder
//! lived may descend from it, and once re-parented its parents no longer say
//! so. `gone_at` was stamped by a poll every 200 ms
//! (`TaintedSet::observe_deaths`) or at the next judgement, with that moment's
//! time, so a window stayed open up to 200 ms (more under load) after the
//! holder had died. A process born in that gap was judged its orphan although
//! it could not descend from it: on 2026-10-09 the next Codex call's sandbox
//! (`bwrap --unshare-pid … true`: `true` is a pid namespace init's child, an
//! orphan root) started 170 to 260 ms after the reader's sandbox died and
//! inherited the reader's secret about one run in five under load.
//!
//! Here each holder gets a pidfd (`pidfd_open`, Linux 5.3+, no privilege),
//! watched by one thread in `epoll_wait`. A pidfd becomes readable when its
//! process has exited, after its children were re-parented
//! (`exit_notify`), and the thread stamps `gone_at` with the time it wakes.
//!
//! NOT ON THE THREAD'S SCHEDULE (2026-10-09, CI pipeline 10012). A stamp is
//! the time of a look, and the thread looks when it is scheduled: under
//! load that was after a pid namespace child the tree started 40 ms after
//! the death, which was then judged the holder's orphan. So the guard also
//! takes the deaths a pidfd reports as each trapped call arrives, before it
//! judges or answers the call (`take_ready`, through `TaintedSet::
//! stamp_ready_deaths`, under one lock with the stamps, so a call that finds
//! a death taken by the thread waits for its stamp). A process started
//! after any trapped call that followed the death (Codex `execve`s the next
//! sandbox's bwrap after reaping the last) is then born after the stamp,
//! however late the thread runs. One born before any such call is still
//! judged by when the thread looked: an over-restriction, never a leak.
//!
//! SOUNDNESS. A stamp is never earlier than the real death: the thread reads
//! the clock only after the kernel reported the exit, and every other stamp
//! (the poll, a judgement) is also taken after a look that found the process
//! gone; the set keeps the earliest of them, all at or after the death. So
//! an orphan born no later than its holder's death (born ≤ death ≤ gone_at)
//! is still inside the window and still inherits; only a process born after
//! the stamp, so after the death, falls outside, and such a process cannot
//! descend from the dead holder. The stamp is only closer to the death than
//! the poll's was; the 200 ms poll stays as the fallback (no `pidfd_open`:
//! `ENOSYS` before Linux 5.3, a seccomp policy refusing it, the fd budget
//! spent) and as a backstop. The clock is `CLOCK_BOOTTIME` in clock ticks,
//! the clock of a process's start time in `/proc/<pid>/stat`, so a birth and
//! a stamp compare on one scale (`TaintedSet::now_ticks`).
//!
//! PID REUSE. A key names a process by pid AND start time. The pidfd is
//! opened by pid and then checked against the key's start time in
//! `/proc/<pid>/stat`; a different process under that number (the holder
//! died, its pid reused) is no watch (`Watch::Gone`: the set stamps it at
//! once). A process only exiting (`PF_EXITING`, its children not yet
//! re-parented) is watched, not taken as dead: a stamp taken then could
//! precede the death. Once checked, the pidfd pins that very process: a
//! later reuse of the number cannot reach it. A descriptor number is taken
//! as a death only under the lock that `watch` and `unwatch` hold, so a
//! number closed and reused by another holder's pidfd between a look and
//! its stamp can never stamp that other, living holder.
//!
//! FD BUDGET. At most `cap` pidfds at once (a quarter of the soft
//! `RLIMIT_NOFILE`, at most 4096); past it a holder is left to the poll.
//! A stamped holder's pidfd is closed at once.
//!
//! The decision logic (the key check, the budget, the earliest stamp) is
//! pure and unit-tested; the watching needs no privilege either, so the unit
//! tests watch real child processes.
//!
//! `Mandu-new`.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

/// What `watch` did with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watch {
    /// A pidfd now watches it (or already did).
    Watched,
    /// It names a process that is dead already (or another process under
    /// its number): nothing to watch; the caller may stamp it now
    /// (`TaintedSet::watch_death`).
    Gone,
    /// Not watched (no `pidfd_open`, the budget spent, a key that names no
    /// pid): the 200 ms poll stamps it.
    Fallback,
}

/// The budget of pidfds for a soft descriptor limit `nofile`: a quarter of
/// it, at most 4096, at least 16. Pure.
pub fn fd_cap(nofile: u64) -> usize {
    (nofile / 4).clamp(16, 4096) as usize
}

/// May a pidfd opened for `key`'s pid watch it? Only when the process the
/// number names now has the key's start time and is not dead (`stat`: its
/// `/proc/<pid>/stat`, read after the pidfd was opened). A process that is
/// only exiting is watched: its pidfd reports the death itself, after its
/// children were re-parented, where a stamp taken now could precede it
/// (`lineage::is_dead`). Pure.
pub fn pidfd_names_key(stat: Option<&crate::lineage::ProcStat>, key_start: u64) -> bool {
    !crate::lineage::is_dead(stat, key_start)
}

/// The pidfd watcher: one epoll set, one thread, a stamp callback.
#[derive(Debug)]
pub struct DeathWatch {
    epfd: RawFd,
    cap: usize,
    /// pidfd → key, and the keys watched (for `watch`'s dedup).
    fds: Mutex<(HashMap<RawFd, String>, HashMap<String, RawFd>)>,
    /// `pidfd_open` answered `ENOSYS` (or `EPERM`): never tried again.
    unsupported: std::sync::atomic::AtomicBool,
}

impl DeathWatch {
    /// Start the watcher: its thread calls `wake(watcher)` whenever a
    /// watched process has exited, and `wake` takes the deaths
    /// (`take_ready`); it returns false when nobody needs the watcher any
    /// more, and the thread then ends. None when epoll cannot be had.
    pub fn start(cap: usize, wake: impl Fn(&DeathWatch) -> bool + Send + 'static) -> Option<Arc<Self>> {
        let w = Self::without_thread(cap)?;
        let me = w.clone();
        std::thread::Builder::new()
            .name("guard-death-watch".into())
            .spawn(move || me.run(wake))
            .ok()?;
        Some(w)
    }

    /// The watcher with no thread of its own: deaths are taken only when
    /// someone calls `take_ready` (the unit tests).
    fn without_thread(cap: usize) -> Option<Arc<Self>> {
        // SAFETY: epoll_create1 with a flag; the fd is owned by the watcher.
        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epfd < 0 {
            return None;
        }
        Some(Arc::new(DeathWatch {
            epfd,
            cap,
            fds: Mutex::new((HashMap::new(), HashMap::new())),
            unsupported: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    /// Watch the process `key` names (`pid-start`).
    pub fn watch(&self, key: &str) -> Watch {
        let Some((pid, start)) = crate::lineage::parse_key(key) else { return Watch::Fallback };
        if self.unsupported.load(std::sync::atomic::Ordering::Relaxed) {
            return Watch::Fallback;
        }
        let Ok(mut g) = self.fds.lock() else { return Watch::Fallback };
        if g.1.contains_key(key) {
            return Watch::Watched;
        }
        if g.0.len() >= self.cap {
            return Watch::Fallback;
        }
        // SAFETY: pidfd_open(pid, 0); the fd, when one, is owned below.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as RawFd;
        if fd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error();
            if matches!(e, Some(libc::ENOSYS) | Some(libc::EPERM)) {
                self.unsupported.store(true, std::sync::atomic::Ordering::Relaxed);
                return Watch::Fallback;
            }
            return if e == Some(libc::ESRCH) { Watch::Gone } else { Watch::Fallback };
        }
        // The number may name another process by now: checked after the
        // pidfd pinned whichever process it names.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok();
        let stat = stat.as_deref().and_then(crate::lineage::parse_stat);
        if !pidfd_names_key(stat.as_ref(), start) {
            // SAFETY: closing the fd just opened.
            unsafe { libc::close(fd) };
            return Watch::Gone;
        }
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: fd as u64 };
        // SAFETY: registering an owned fd in the watcher's epoll set.
        if unsafe { libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) } != 0 {
            // SAFETY: closing the fd just opened.
            unsafe { libc::close(fd) };
            return Watch::Fallback;
        }
        g.0.insert(fd, key.to_string());
        g.1.insert(key.to_string(), fd);
        Watch::Watched
    }

    /// Stop watching `key` (the set forgot it).
    pub fn unwatch(&self, key: &str) {
        if let Ok(mut g) = self.fds.lock() {
            if let Some(fd) = g.1.remove(key) {
                g.0.remove(&fd);
                // SAFETY: an fd the watcher owns, removed from both maps.
                unsafe {
                    libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
                    libc::close(fd);
                }
            }
        }
    }

    /// How many pidfds are open now.
    pub fn watched(&self) -> usize {
        self.fds.lock().map(|g| g.0.len()).unwrap_or(0)
    }

    /// The watched holders whose pidfd reports their exit now, each with
    /// the time read after that report (so never before the death), their
    /// pidfds closed. No wait: the watcher thread calls it when epoll wakes
    /// it, and the guard as each trapped call arrives (`TaintedSet::
    /// stamp_ready_deaths`), so a death is stamped before any call the
    /// tree makes after it is answered, however late the thread runs.
    ///
    /// The ready descriptors are read under the lock that `watch` and
    /// `unwatch` hold while they register, close or reuse a descriptor
    /// number, so a reported number is the pidfd the map names: a number
    /// closed (`unwatch`) and reused by another holder's pidfd between a
    /// look and the stamp can never stamp that other, live holder.
    pub fn take_ready(&self) -> Vec<(String, u64)> {
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 64];
        // A look with no lock first: nothing ready, nothing to take (the
        // common case of every trapped call).
        // SAFETY: a non-blocking look at the watcher's own epoll set into a local buffer.
        if unsafe { libc::epoll_wait(self.epfd, events.as_mut_ptr(), events.len() as i32, 0) } <= 0 {
            return Vec::new();
        }
        let Ok(mut g) = self.fds.lock() else { return Vec::new() };
        // SAFETY: as above, under the lock.
        let n = unsafe { libc::epoll_wait(self.epfd, events.as_mut_ptr(), events.len() as i32, 0) };
        let mut dead = Vec::new();
        for ev in &events[..n.max(0) as usize] {
            let fd = ev.u64 as RawFd;
            // Registered and in the map go together under the lock; were
            // they ever not to, the registration is dropped (never the
            // descriptor, which is not the watcher's), so the thread cannot
            // spin on it.
            let Some(k) = g.0.remove(&fd) else {
                // SAFETY: removing a registration from the watcher's own epoll set.
                unsafe { libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
                continue;
            };
            g.1.remove(&k);
            // SAFETY: an fd the watcher owned, now out of both maps.
            unsafe {
                libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
                libc::close(fd);
            }
            dead.push(k);
        }
        drop(g);
        // The clock is read after the kernel reported the exits: never
        // earlier than any of them.
        let now = crate::secret_open::now_ticks();
        dead.into_iter().map(|k| (k, now)).collect()
    }

    fn run(&self, wake: impl Fn(&DeathWatch) -> bool) {
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
        loop {
            // A wake-up only (level-triggered: what is ready stays ready
            // until `take_ready` closes it, whichever thread does).
            // SAFETY: waiting on the watcher's own epoll set into a local buffer.
            let n = unsafe { libc::epoll_wait(self.epfd, events.as_mut_ptr(), 1, -1) };
            if n < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return;
            }
            if !wake(self) {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn the_budget_is_a_quarter_of_the_limit_within_bounds() {
        assert_eq!(fd_cap(1024), 256);
        assert_eq!(fd_cap(1_048_576), 4096);
        assert_eq!(fd_cap(20), 16);
    }

    #[test]
    fn a_pidfd_watches_only_the_process_the_key_names() {
        let me = crate::lineage::parse_stat(&std::fs::read_to_string("/proc/self/stat").unwrap()).unwrap();
        assert!(pidfd_names_key(Some(&me), me.start));
        assert!(!pidfd_names_key(Some(&me), me.start + 1), "another process under the number");
        let exiting = crate::lineage::ProcStat { flags: crate::lineage::PF_EXITING, ..me };
        assert!(pidfd_names_key(Some(&exiting), me.start), "an exiting process is watched: its pidfd reports the death itself");
        let zombie = crate::lineage::ProcStat { state: 'Z', ..me };
        assert!(!pidfd_names_key(Some(&zombie), me.start), "a zombie is dead");
        assert!(!pidfd_names_key(None, me.start), "no such process");
    }

    fn key_of(pid: u32) -> String {
        crate::secret_open::own_key_of(pid as i32)
    }

    #[test]
    fn an_exit_is_stamped_after_it_happens_never_before() {
        let (tx, rx) = mpsc::channel::<(String, u64)>();
        let tx = Mutex::new(tx);
        let w = DeathWatch::start(16, move |w| {
            for (k, t) in w.take_ready() {
                let _ = tx.lock().unwrap().send((k, t));
            }
            true
        })
        .expect("epoll");
        let before = crate::secret_open::now_ticks();
        let mut child = std::process::Command::new("sleep").arg("0.3").spawn().expect("sleep");
        let key = key_of(child.id());
        match w.watch(&key) {
            Watch::Watched => {}
            Watch::Fallback => return, // no pidfd_open here (a kernel before 5.3): the poll is the path
            Watch::Gone => panic!("a live child is not gone"),
        }
        assert_eq!(w.watch(&key), Watch::Watched, "watched once");
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err(), "no stamp while it lives");
        let status = child.wait().unwrap();
        let exited_by = crate::secret_open::now_ticks();
        assert!(status.success());
        let (k, t) = rx.recv_timeout(Duration::from_secs(5)).expect("the exit is stamped");
        assert_eq!(k, key);
        // the stamp is no earlier than the child's own start, and the
        // pidfd only woke after the exit: no later than a moment after it
        // the child slept 0.3 s (30 ticks at 100 Hz) after `before`: a stamp
        // taken before its exit would be earlier than that
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        assert!(t + 1 >= before + 3 * hz / 10, "never stamped before the exit ({t} vs {before})");
        assert!(t <= exited_by + 50, "stamped soon after the exit ({t} vs {exited_by})");
        assert_eq!(w.watched(), 0, "its pidfd is closed");
    }

    /// 2026-10-09: a death is taken the moment it is asked for, with no
    /// thread to wait on (the guard asks as each trapped call arrives), and
    /// a living process is never taken.
    #[test]
    fn a_death_is_taken_when_asked_and_a_living_process_never() {
        let w = DeathWatch::without_thread(16).expect("epoll");
        let mut child = std::process::Command::new("sleep").arg("5").spawn().expect("sleep");
        let key = key_of(child.id());
        match w.watch(&key) {
            Watch::Watched => {}
            Watch::Fallback => {
                let _ = (child.kill(), child.wait());
                return; // no pidfd_open here (a kernel before 5.3)
            }
            Watch::Gone => panic!("a live child is not gone"),
        }
        assert!(w.take_ready().is_empty(), "a living process is not taken");
        assert_eq!(w.watched(), 1);
        let _ = child.kill();
        let _ = child.wait();
        let exited_by = crate::secret_open::now_ticks();
        let taken = w.take_ready();
        assert_eq!(taken.len(), 1, "taken at once, no thread involved");
        assert_eq!(taken[0].0, key);
        assert!(taken[0].1 >= exited_by, "the time is read after the exit was reported");
        assert_eq!(w.watched(), 0, "its pidfd is closed");
        assert!(w.take_ready().is_empty(), "taken once");
    }

    #[test]
    fn a_key_whose_process_is_gone_or_reused_is_not_watched() {
        let w = DeathWatch::start(16, |_| true).expect("epoll");
        let mut child = std::process::Command::new("true").spawn().expect("true");
        let key = key_of(child.id());
        child.wait().unwrap();
        // reaped: the number names nothing (or another process)
        assert!(matches!(w.watch(&key), Watch::Gone | Watch::Fallback));
        // a live number with a wrong start time: another process
        let me = std::process::id() as i32;
        let wrong = format!("{me}-1");
        assert!(matches!(w.watch(&wrong), Watch::Gone | Watch::Fallback));
        assert_eq!(w.watched(), 0);
        assert_eq!(w.watch("not-a-key"), Watch::Fallback);
    }

    #[test]
    fn past_the_budget_a_holder_is_left_to_the_poll() {
        let w = DeathWatch::start(1, |_| true).expect("epoll");
        let mut a = std::process::Command::new("sleep").arg("2").spawn().unwrap();
        let mut b = std::process::Command::new("sleep").arg("2").spawn().unwrap();
        let first = w.watch(&key_of(a.id()));
        if first == Watch::Fallback {
            let _ = (a.kill(), b.kill(), a.wait(), b.wait());
            return; // no pidfd_open here
        }
        assert_eq!(first, Watch::Watched);
        assert_eq!(w.watch(&key_of(b.id())), Watch::Fallback, "the budget is spent");
        w.unwatch(&key_of(a.id()));
        assert_eq!(w.watched(), 0);
        assert_eq!(w.watch(&key_of(b.id())), Watch::Watched, "a freed slot is used");
        let _ = (a.kill(), b.kill(), a.wait(), b.wait());
    }
}
