//! guard_wait — the KERNEL half of following a holder's exit status (feature
//! `kernel`, Linux; plan 13 §4.9 and §9 R4, 2026-10-03). The rule and its
//! reasons are in `wait_flow`, the pure half:
//!
//!   - `status_receivers`: the processes a new holder's status reaches (its
//!     parent, its tracer), which the taint-time sweep makes holders
//!     (`guard_send::sweep_from`) before the reader gets a byte;
//!   - `handle_wait_notif`: a trapped `wait4` / `waitid`, whose caller
//!     becomes a holder (swept) before the kernel performs the wait when a
//!     holder is among the processes it may reap (killed when that sweep
//!     refuses). Never emulated: the guard
//!     judges and CONTINUEs, so a blocking wait blocks in the kernel, not in
//!     a supervisor waiting on a tracee waiting on it, and a signal restarts
//!     it as it would any wait (the trapped call is re-sent, judged again).
//!     Taint first, then CONTINUE: the window between the two can only find
//!     the waiter a holder already.
//!
//! `Mandu-new`.

#![cfg(all(feature = "kernel", target_os = "linux"))]

use std::os::unix::io::RawFd;

use crate::guard_kernel::{answer_continue, answer_errno, GuardConfig};
use crate::secret_open::{ancestor_keys_of, own_key_of, parent_pid_of, tgid_of};
use crate::wait_flow;

/// The keys no status makes a holder (`wait_flow::exempt_keys`): the agent's
/// and every ancestor of the agent's.
pub(crate) fn status_exempt(cfg: &GuardConfig) -> Vec<String> {
    let agents = crate::guard_flow::agent_keys(cfg);
    wait_flow::exempt_keys(&agents, |k| match crate::lineage::parse_key(k) {
        Some((pid, _)) => ancestor_keys_of(pid, 64),
        None => Vec::new(),
    })
}

/// The tracers of any thread of `tgid` (ptrace attaches to a thread).
fn tracers_of(tgid: i32) -> Vec<i32> {
    let mut out: Vec<i32> = Vec::new();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{tgid}/task")) else { return out };
    for t in tasks.flatten() {
        let Ok(status) = std::fs::read_to_string(t.path().join("status")) else { continue };
        if let Some(tr) = wait_flow::tracer_pid(&status) {
            let tr = tgid_of(tr);
            if !out.contains(&tr) {
                out.push(tr);
            }
        }
    }
    out
}

/// The processes that learn `p`'s exit status (its parent, by `wait` or
/// `SIGCHLD`'s `siginfo`) or its stops (its tracer), and that the guard may
/// make holders (`wait_flow::receives_status`): never the agent, above it,
/// init or the guard. Called by the taint-time sweep for every process it
/// makes a holder.
pub(crate) fn status_receivers(cfg: &GuardConfig, p: i32) -> Vec<i32> {
    if cfg.secrets.is_none() {
        return Vec::new();
    }
    // SAFETY: getpid has no failure mode.
    let me = unsafe { libc::getpid() };
    let tgid = tgid_of(p);
    let mut cands: Vec<i32> = Vec::new();
    if let Some(pp) = parent_pid_of(tgid) {
        cands.push(pp);
    }
    for t in tracers_of(tgid) {
        if !cands.contains(&t) {
            cands.push(t);
        }
    }
    cands.retain(|c| *c != tgid);
    if cands.is_empty() {
        return cands;
    }
    let exempt = status_exempt(cfg);
    cands.into_iter().filter(|c| wait_flow::receives_status(*c, &own_key_of(*c), me, &exempt)).collect()
}

/// The children of every thread of `tgid` (a wait from any thread reaps
/// them all).
fn children_of(tgid: i32) -> Vec<i32> {
    let mut out: Vec<i32> = Vec::new();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{tgid}/task")) else { return out };
    for t in tasks.flatten() {
        let Ok(ch) = std::fs::read_to_string(t.path().join("children")) else { continue };
        for c in ch.split_whitespace().filter_map(|c| c.parse::<i32>().ok()) {
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out
}

/// What the handler did with one wait (for tests and the log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaitOutcome {
    /// Left to the kernel: no reapable holder, an exempt waiter, or one
    /// already holding what it reaps.
    Continued,
    /// The waiter was made a holder flowing from the reapable holders, then
    /// the wait was left to the kernel.
    Admitted,
    /// The waiter's sweep refused (an unbound connection, an unjudgeable
    /// socket): the waiter is killed, the wait not performed.
    Refused { dest: String },
}

/// Plan 13 §4.9 (2026-10-03): a trapped `wait4` / `waitid`. See the module
/// doc and `wait_flow`.
pub fn handle_wait_notif(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) -> WaitOutcome {
    if cfg.secrets.is_none() || cfg.tainted.is_empty() {
        answer_continue(listener, notif);
        return WaitOutcome::Continued;
    }
    let tgid = tgid_of(notif.pid as i32);
    let own = own_key_of(tgid);
    let exempt = status_exempt(cfg).iter().any(|k| *k == own);
    if exempt {
        answer_continue(listener, notif);
        return WaitOutcome::Continued;
    }
    let cands: Vec<i32> = match wait_flow::reapable(cfg.tainted.reaps_orphans(tgid)) {
        wait_flow::Reapable::Children => children_of(tgid),
        wait_flow::Reapable::Subtree => crate::guard_send::subtree(tgid).into_iter().filter(|p| *p != tgid).collect(),
    };
    let held: Vec<(String, Vec<String>)> = cands
        .into_iter()
        .filter_map(|c| {
            let k = own_key_of(c);
            let (h, chain) = cfg.tainted.holds_or_inherits(c, &k);
            // A holder traced to no reader that got a byte (a raw open the
            // sweep refused, then forgotten) carries nothing in its status.
            (h && !cfg.tainted.taint_sources(&k).is_empty()).then_some((k, chain))
        })
        .collect();
    // The waiter itself, by its parents (recorded under its own key when it
    // holds, so `covers` can read its sources).
    let _ = cfg.tainted.holds_or_inherits(tgid, &own);
    let held_keys: Vec<String> = held.iter().map(|(k, _)| k.clone()).collect();
    let covered = cfg.tainted.covers(&own, &held_keys);
    match wait_flow::wait_verdict(false, !held.is_empty(), covered) {
        wait_flow::WaitVerdict::Continue => {
            answer_continue(listener, notif);
            WaitOutcome::Continued
        }
        wait_flow::WaitVerdict::Admit => {
            let from = cfg.tainted.flow_sources(&held);
            match crate::guard_flow::admit_receivers(cfg, &[tgid], &from, &[], &[], Some(notif.pid as i32)) {
                Ok(()) => {
                    answer_continue(listener, notif);
                    WaitOutcome::Admitted
                }
                Err((dest, refusal)) => {
                    // The status must not reach a process holding an unbound
                    // connection, and an error in place of it (`ECHILD`)
                    // leaves shells and libuv waiting for a child they can
                    // no longer reap (a hang): the waiter is killed, its wait
                    // never performed.
                    cfg.tainted.refuse_wait(&own);
                    crate::guard_send::emit_tainted(cfg, "reap a process holding a secret while holding a connection to", &dest, &refusal);
                    // SAFETY: a signal to the waiting process, suspended in
                    // this very call (its notification is still pending).
                    unsafe { libc::kill(tgid, libc::SIGKILL) };
                    answer_errno(listener, notif, libc::ECHILD);
                    WaitOutcome::Refused { dest }
                }
            }
        }
    }
}
