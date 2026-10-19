//! guard_signals — the agent tree cannot signal, or starve, its own guard
//! (rootless-confinement-ubuntu-2404.md §12.2).
//!
//! A dead guard fails closed (every trapped syscall returns ENOSYS), so a kill
//! of the guard is a denial of service, never a leak. It is still refused: the
//! guard runs as the agent's uid, so without this the agent could end its own
//! protection at will and leave a tree that fails every open.
//!
//! Which signals can hurt the guard: it ignores or handles every catchable
//! one (`harden_guard` in the guard binary), so only SIGKILL and SIGSTOP, and
//! glibc's two reserved real-time signals (32, 33), whose disposition glibc
//! owns (`HARMFUL`).
//!
//! How a signal could reach the guard, and what stops it:
//!   - By pid or process group (`kill`, `tgkill`, `rt_sigqueueinfo`,
//!     `rt_tgsigqueueinfo`), or by a resource limit that kills (`prlimit64`
//!     with RLIMIT_CPU ends in SIGKILL): the filter hands these to the guard
//!     when the first argument names the guard (its pid, its group, or `-1` /
//!     `0` for `kill`). A `kill` or `rt_sigqueueinfo` of any other positive
//!     number is handed over too when its signal is HARMFUL: the kernel reads
//!     that number as a THREAD id and signals the whole process, so a guard
//!     worker thread's id kills the guard. `prlimit64` of any pid but 0 (the
//!     caller) goes to the guard for the same reason. Every other call runs
//!     at full speed.
//!   - By thread id (`tkill`): the guard's threads are not known when the
//!     filter is built, so every `tkill` is checked (glibc raises with
//!     `tgkill`; `tkill` is rare). `pidfd_open` with flags (a thread pidfd)
//!     is checked the same way.
//!   - By pidfd (`pidfd_send_signal`): every call is checked; the descriptor
//!     is a pidfd (fdinfo `Pid:`) or a `/proc/<pid>` directory (matched by
//!     start time and name, which no pid namespace changes). `pidfd_open` of
//!     the guard's pid is refused up front. A HARMFUL signal by descriptor is
//!     PERFORMED, never continued: the guard copies the caller's descriptor
//!     (`pidfd_getfd`), judges the copy, and signals through the copy, so a
//!     thread that swaps the descriptor number (`dup2`) after the check
//!     changes nothing (`decide_send`). Other signals are checked and
//!     continued: a swap can only deliver a signal the guard ignores.
//!   - By SIGIO (`fcntl(F_SETOWN)` / `FIOSETOWN`): the guard ignores every
//!     catchable fatal signal, so only `F_SETSIG` to SIGKILL or SIGSTOP could
//!     hurt it; those two are refused in the filter itself.
//!   - By process group membership: `setpgid(…, <guard's group>)` is refused
//!     in the filter itself, so no process can join the guard's group between
//!     a `kill(0)` check and the kill.
//!
//! Starving the guard (the scheduler, not a signal): `setpriority`,
//! `ioprio_set` (by thread, by group, by user) and `sched_setscheduler`,
//! `sched_setparam`, `sched_setattr`, `sched_setaffinity` (by thread) of
//! anything but the caller itself go to the guard, which refuses the ones
//! that would reach it. By user reaches every process of the uid, the guard
//! included, so it is refused whenever the caller can see the guard.
//!
//! Pid namespaces: numbers in these calls are the CALLER's. A caller in a pid
//! namespace below the guard's cannot name the guard at all, so a number that
//! happens to equal the guard's pid there is some other process and the call
//! goes on. A caller whose namespace cannot be read is treated as sharing the
//! guard's (fail-closed: the call is refused).
//!
//! PURE (always compiled, unit-tested): which calls are checked, the filter
//! block, and the decisions. KERNEL (`--features kernel`): gathering the facts
//! from procfs for one notification, and performing a signal by descriptor.
//!
//! `Mandu-new`.

/// A call that can reach another process, by what its target argument names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aim {
    /// `kill(pid, …)`: a pid (read as a thread id: any thread of a process
    /// names the process), a process group (negative), `0` (the caller's
    /// group) or `-1` (every process the caller may signal).
    Kill(i32),
    /// A thread group id that the kernel checks as one (`tgkill`,
    /// `rt_tgsigqueueinfo`: the thread must belong to it).
    Tgid(i32),
    /// A thread id, or a pid the kernel resolves as a thread id
    /// (`tkill`, `rt_sigqueueinfo`, `pidfd_open`, `prlimit64`, `sched_*`,
    /// `setpriority` / `ioprio_set` by process).
    Tid(i32),
    /// A pidfd or `/proc/<pid>` directory descriptor (`pidfd_send_signal`).
    Fd(i32),
    /// A process group (`setpriority` / `ioprio_set` by group; `0` is the
    /// caller's).
    Pgrp(i32),
    /// Every process of a user (`setpriority` / `ioprio_set` by user).
    User,
}

/// The signals that can hurt the guard: the two nothing can catch, and
/// glibc's reserved real-time pair (32 is left at its fatal default; 33 has
/// glibc's handler). The guard ignores or forwards every other one.
pub const HARMFUL: [i32; 4] = [libc::SIGKILL, libc::SIGSTOP, 32, 33];

pub fn harmful(sig: i32) -> bool {
    HARMFUL.contains(&sig)
}

const PRIO_PROCESS: u32 = 0;
const PRIO_PGRP: u32 = 1;
const IOPRIO_WHO_PROCESS: u32 = 1;
const IOPRIO_WHO_PGRP: u32 = 2;

/// The scheduling calls that take a thread id first.
fn sched_nrs() -> [i64; 4] {
    [
        libc::SYS_sched_setscheduler as i64,
        libc::SYS_sched_setparam as i64,
        libc::SYS_sched_setattr as i64,
        libc::SYS_sched_setaffinity as i64,
    ]
}

/// The syscalls the filter may hand to the guard for this check.
pub fn signal_nrs() -> [i64; 14] {
    let s = sched_nrs();
    [
        libc::SYS_kill as i64,
        libc::SYS_tgkill as i64,
        libc::SYS_rt_sigqueueinfo as i64,
        libc::SYS_rt_tgsigqueueinfo as i64,
        libc::SYS_pidfd_open as i64,
        libc::SYS_prlimit64 as i64,
        libc::SYS_tkill as i64,
        libc::SYS_pidfd_send_signal as i64,
        libc::SYS_setpriority as i64,
        libc::SYS_ioprio_set as i64,
        s[0],
        s[1],
        s[2],
        s[3],
    ]
}

pub fn is_signal_nr(nr: i64) -> bool {
    signal_nrs().contains(&nr)
}

/// What one trapped call aims at. The kernel reads these arguments as `int`,
/// so only their low 32 bits count. `None`: a call the kernel refuses anyway
/// (an unknown `which`), or not one of ours.
pub fn aim_of(nr: i64, args: &[u64; 6]) -> Option<Aim> {
    let a0 = args[0] as u32 as i32;
    let a1 = args[1] as u32 as i32;
    let by_which = |process: u32, pgrp: u32| match args[0] as u32 {
        w if w == process => Some(Aim::Tid(a1)),
        w if w == pgrp => Some(Aim::Pgrp(a1)),
        _ => Some(Aim::User),
    };
    if nr == libc::SYS_kill as i64 {
        Some(Aim::Kill(a0))
    } else if nr == libc::SYS_tgkill as i64 || nr == libc::SYS_rt_tgsigqueueinfo as i64 {
        Some(Aim::Tgid(a0))
    } else if nr == libc::SYS_pidfd_send_signal as i64 {
        Some(Aim::Fd(a0))
    } else if nr == libc::SYS_setpriority as i64 {
        // PRIO_USER is 2; anything above is EINVAL, and refusing it is harmless.
        by_which(PRIO_PROCESS, PRIO_PGRP)
    } else if nr == libc::SYS_ioprio_set as i64 {
        match args[0] as u32 {
            0 => None,
            _ => by_which(IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP),
        }
    } else if is_signal_nr(nr) {
        Some(Aim::Tid(a0))
    } else {
        None
    }
}

/// What a pidfd_send_signal descriptor names, as far as the guard found out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdTarget {
    /// A live process, by thread group id in the guard's pid namespace.
    Process(i32),
    /// A process that has exited, a process the guard's namespace cannot see,
    /// or no process at all (the kernel refuses it: EBADF / ESRCH).
    NotTheGuard,
    /// A `/proc/<pid>` directory of another process.
    ProcDir,
    /// A `/proc/<pid>` directory with the guard's identity.
    TheGuard,
    /// Could not be inspected: fail-closed.
    Unknown,
}

/// The facts the decision needs, gathered in the guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    /// The guard's pid, which is also its process group id.
    pub guard: i32,
    /// Does the caller share the guard's pid namespace? `None`: unknown.
    pub same_pidns: Option<bool>,
    /// The caller's process group (for `kill(0, …)`, `Pgrp(0)`); `None`:
    /// unknown.
    pub caller_pgrp: Option<i32>,
    /// For `Tid` and a positive `Kill`: the thread group of that thread;
    /// `None`: no such thread.
    pub tid_tgid: Option<i32>,
    /// For `Fd`.
    pub fd: FdTarget,
}

/// Refuse this call (EPERM)?
pub fn refuse(aim: Aim, f: &Facts) -> bool {
    // Numbers are the caller's; below the guard's namespace none is the guard.
    let may_name_guard = f.same_pidns != Some(false);
    let guard_thread = |t: i32| may_name_guard && (t == f.guard || f.tid_tgid == Some(f.guard));
    match aim {
        // kill(0) is the caller's own group, whatever its namespace: a group
        // can span pid namespaces (an unshare keeps it).
        Aim::Kill(0) | Aim::Pgrp(0) => f.caller_pgrp.map_or(true, |g| g == f.guard),
        Aim::Kill(p) if p > 0 => guard_thread(p),
        Aim::Kill(p) => may_name_guard && (p == -f.guard || p == -1),
        Aim::Pgrp(g) => may_name_guard && g == f.guard,
        Aim::User => may_name_guard,
        Aim::Tgid(t) => may_name_guard && t == f.guard,
        Aim::Tid(t) => guard_thread(t),
        Aim::Fd(_) => match f.fd {
            FdTarget::Process(tgid) => tgid == f.guard,
            FdTarget::TheGuard | FdTarget::Unknown => true,
            FdTarget::NotTheGuard | FdTarget::ProcDir => false,
        },
    }
}

// ── a signal by descriptor, performed ────────────────────────────────────────

/// `PIDFD_SIGNAL_PROCESS_GROUP` (Linux 6.9): signal the target's whole
/// process group.
pub const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 1 << 2;

/// What the guard found out about ITS COPY of the caller's descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendFacts {
    pub guard: i32,
    /// What the copy names.
    pub target: FdTarget,
    /// The target's process group, in the guard's namespace; `None`:
    /// unknown (always for a `/proc/<pid>` directory, whose numbers belong
    /// to its procfs mount).
    pub target_pgrp: Option<i32>,
    /// Is the target in the caller's pid namespace or one below it (the
    /// kernel's own rule for a pidfd)? `None`: unknown.
    pub visible: Option<bool>,
    /// The call's flags.
    pub flags: u32,
}

/// Send through the copy (Ok), or answer with this errno. A descriptor that
/// names nothing live is sent anyway: the kernel answers it (EBADF, ESRCH,
/// EINVAL) as it would have answered the caller.
pub fn decide_send(f: &SendFacts) -> Result<(), i32> {
    match f.target {
        FdTarget::TheGuard | FdTarget::Unknown => return Err(libc::EPERM),
        FdTarget::Process(t) if t == f.guard => return Err(libc::EPERM),
        FdTarget::NotTheGuard => return Ok(()),
        FdTarget::Process(_) | FdTarget::ProcDir => {}
    }
    if f.flags & PIDFD_SIGNAL_PROCESS_GROUP != 0 && f.target_pgrp.map_or(true, |g| g == f.guard) {
        return Err(libc::EPERM);
    }
    match f.visible {
        Some(true) => Ok(()),
        // What the kernel answers a caller whose namespace cannot see it.
        Some(false) => Err(libc::EINVAL),
        None => Err(libc::EPERM),
    }
}

// ── the filter block ─────────────────────────────────────────────────────────

/// `F_SETSIG`: the signal SIGIO delivers as.
const F_SETSIG: u32 = 10;

/// seccomp_data offsets: nr at 0, args[i] at 16 + 8*i (the low word first on
/// the little-endian arches this crate builds for).
const NR_OFF: u32 = 0;
fn arg_lo(i: u32) -> u32 {
    16 + 8 * i
}

/// The filter instructions that go in front of the guard's own dispatch. They
/// end by falling through to the next instruction (the dispatch reloads the
/// syscall number) unless they return: USER_NOTIF for a call that may reach
/// the guard, EPERM for `fcntl(F_SETSIG)` to SIGKILL or SIGSTOP and for
/// `setpgid` into the guard's group. `guard` is the guard's pid in the
/// tracee's namespace at install time (the installer is the guard's child).
pub fn filter_block(guard: u32) -> Vec<libc::sock_filter> {
    #[derive(Clone, Copy, PartialEq)]
    enum L {
        Kill,
        Queue,
        Harm,
        Tgid,
        PidfdOpen,
        NonZero0,
        NonZero1,
        Prio,
        Ioprio,
        PgrpWho,
        Setpgid,
        Fcntl,
        SetSig,
        Notif,
        Deny,
        Rest,
    }
    enum I {
        Ld(u32),
        Jeq(u32, L),
        Jset(u32, L),
        Ja(L),
        Ret(u32),
        At(L),
    }
    let neg = |v: u32| (v as i32).wrapping_neg() as u32;
    let mut p: Vec<I> = vec![I::Ld(NR_OFF), I::Jeq(libc::SYS_kill as u32, L::Kill), I::Jeq(libc::SYS_rt_sigqueueinfo as u32, L::Queue)];
    for nr in [libc::SYS_tgkill, libc::SYS_rt_tgsigqueueinfo] {
        p.push(I::Jeq(nr as u32, L::Tgid));
    }
    p.push(I::Jeq(libc::SYS_pidfd_open as u32, L::PidfdOpen));
    p.push(I::Jeq(libc::SYS_prlimit64 as u32, L::NonZero0));
    for nr in sched_nrs() {
        p.push(I::Jeq(nr as u32, L::NonZero0));
    }
    p.push(I::Jeq(libc::SYS_setpriority as u32, L::Prio));
    p.push(I::Jeq(libc::SYS_ioprio_set as u32, L::Ioprio));
    p.push(I::Jeq(libc::SYS_tkill as u32, L::Notif));
    p.push(I::Jeq(libc::SYS_pidfd_send_signal as u32, L::Notif));
    p.push(I::Jeq(libc::SYS_setpgid as u32, L::Setpgid));
    p.push(I::Jeq(libc::SYS_fcntl as u32, L::Fcntl));
    p.push(I::Ja(L::Rest));
    // kill: the guard, its group, everyone, the caller's group; else another
    // group runs, and a positive pid carrying a harmful signal is checked.
    p.extend([I::At(L::Kill), I::Ld(arg_lo(0)), I::Jeq(guard, L::Notif), I::Jeq(neg(guard), L::Notif), I::Jeq(u32::MAX, L::Notif), I::Jeq(0, L::Notif), I::Jset(0x8000_0000, L::Rest), I::Ja(L::Harm)]);
    p.extend([I::At(L::Queue), I::Ld(arg_lo(0)), I::Jeq(guard, L::Notif)]);
    p.push(I::At(L::Harm));
    p.push(I::Ld(arg_lo(1)));
    for s in HARMFUL {
        p.push(I::Jeq(s as u32, L::Notif));
    }
    p.push(I::Ja(L::Rest));
    p.extend([I::At(L::Tgid), I::Ld(arg_lo(0)), I::Jeq(guard, L::Notif), I::Ja(L::Rest)]);
    p.extend([I::At(L::PidfdOpen), I::Ld(arg_lo(0)), I::Jeq(guard, L::Notif), I::Ja(L::NonZero1)]);
    p.extend([I::At(L::NonZero0), I::Ld(arg_lo(0)), I::Jeq(0, L::Rest), I::Ja(L::Notif)]);
    p.extend([I::At(L::Prio), I::Ld(arg_lo(0)), I::Jeq(PRIO_PROCESS, L::NonZero1), I::Jeq(PRIO_PGRP, L::PgrpWho), I::Ja(L::Notif)]);
    p.extend([I::At(L::Ioprio), I::Ld(arg_lo(0)), I::Jeq(IOPRIO_WHO_PROCESS, L::NonZero1), I::Jeq(IOPRIO_WHO_PGRP, L::PgrpWho), I::Ja(L::Notif)]);
    p.extend([I::At(L::NonZero1), I::Ld(arg_lo(1)), I::Jeq(0, L::Rest), I::Ja(L::Notif)]);
    p.extend([I::At(L::PgrpWho), I::Ld(arg_lo(1)), I::Jeq(0, L::Notif), I::Jeq(guard, L::Notif), I::Ja(L::Rest)]);
    p.extend([I::At(L::Setpgid), I::Ld(arg_lo(1)), I::Jeq(guard, L::Deny), I::Ja(L::Rest)]);
    p.extend([I::At(L::Fcntl), I::Ld(arg_lo(1)), I::Jeq(F_SETSIG, L::SetSig), I::Ja(L::Rest)]);
    p.extend([I::At(L::SetSig), I::Ld(arg_lo(2)), I::Jeq(libc::SIGKILL as u32, L::Deny), I::Jeq(libc::SIGSTOP as u32, L::Deny), I::Ja(L::Rest)]);
    p.extend([I::At(L::Notif), I::Ret(libc::SECCOMP_RET_USER_NOTIF), I::At(L::Deny), I::Ret(libc::SECCOMP_RET_ERRNO | libc::EPERM as u32), I::At(L::Rest)]);

    // Resolve labels to positions, then to relative jumps.
    let mut pos: Vec<(L, usize)> = Vec::new();
    let mut n = 0usize;
    for i in &p {
        match i {
            I::At(l) => pos.push((*l, n)),
            _ => n += 1,
        }
    }
    let at = |l: L| pos.iter().find(|(k, _)| *k == l).map(|(_, v)| *v).expect("label");
    let ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let jset = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
    let ja = (libc::BPF_JMP | libc::BPF_JA) as u16;
    let ret = (libc::BPF_RET | libc::BPF_K) as u16;
    let mut out = Vec::with_capacity(n);
    for i in &p {
        let here = out.len();
        let rel = |l: L| at(l) - here - 1;
        out.push(match *i {
            I::Ld(k) => libc::sock_filter { code: ld, jt: 0, jf: 0, k },
            I::Jeq(k, l) => libc::sock_filter { code: jeq, jt: u8::try_from(rel(l)).expect("short jump"), jf: 0, k },
            I::Jset(k, l) => libc::sock_filter { code: jset, jt: u8::try_from(rel(l)).expect("short jump"), jf: 0, k },
            I::Ja(l) => libc::sock_filter { code: ja, jt: 0, jf: 0, k: rel(l) as u32 },
            I::Ret(k) => libc::sock_filter { code: ret, jt: 0, jf: 0, k },
            I::At(_) => continue,
        });
    }
    out
}

// ── a signal that carries data (confidentiality plan 13 §4.9) ───────────────

/// The signal calls that carry a caller-chosen payload (`siginfo_t`, whose
/// `si_value` is eight bytes of the sender's choosing): `rt_sigqueueinfo`
/// and `rt_tgsigqueueinfo` (glibc's `sigqueue`, `pthread_sigqueue`), and
/// `pidfd_send_signal` with a `siginfo` argument. Under a secret policy the
/// guard sees every one (`payload_nrs`), and refuses one from a holder to a
/// process that holds no secret (`guard_flow::payload_signal_refused`): the
/// one signal interface built to carry data. `kill`, `tgkill` and a
/// `pidfd_send_signal` without `siginfo` carry only the signal's number
/// (plan 13 §4.9: a covert channel, with exit codes and timing).
pub fn payload_nrs() -> [i64; 3] {
    [libc::SYS_rt_sigqueueinfo as i64, libc::SYS_rt_tgsigqueueinfo as i64, libc::SYS_pidfd_send_signal as i64]
}

/// Whom a payload signal goes to, from its registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadAim {
    /// A thread group, by number in the caller's pid namespace.
    Tgid(i32),
    /// A pidfd (or `/proc/<pid>` directory) descriptor: refused from a
    /// holder whatever it names (the descriptor could be swapped after a
    /// look; a holder's `pidfd_send_signal` with a payload is rare).
    Fd,
}

/// The aim of a call that carries a payload; None for one that does not
/// (`pidfd_send_signal` with a null `siginfo`, any other call).
pub fn payload_aim(nr: i64, args: &[u64; 6]) -> Option<PayloadAim> {
    if nr == libc::SYS_rt_sigqueueinfo as i64 || nr == libc::SYS_rt_tgsigqueueinfo as i64 {
        return Some(PayloadAim::Tgid(args[0] as u32 as i32));
    }
    if nr == libc::SYS_pidfd_send_signal as i64 && args[2] != 0 {
        return Some(PayloadAim::Fd);
    }
    None
}

// ── procfs parsing (pure) ────────────────────────────────────────────────────

/// `/proc/<pid>/stat`: (name, process group, start time in clock ticks).
pub fn parse_stat(stat: &str) -> Option<(String, i32, u64)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let name = stat.get(open + 1..close)?.to_string();
    let rest: Vec<&str> = stat.get(close + 1..)?.split_whitespace().collect();
    // After the name: state(3) ppid(4) pgrp(5) … starttime(22).
    let pgrp = rest.get(2)?.parse().ok()?;
    let start = rest.get(19)?.parse().ok()?;
    Some((name, pgrp, start))
}

/// A `Key:\t<int>` line of a procfs status / fdinfo file.
pub fn parse_field(text: &str, key: &str) -> Option<i32> {
    text.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix(':')?.split_whitespace().next()?.parse().ok())
}

/// fdinfo of a pidfd: its `Pid:` (in the reader's namespace; 0 when the
/// reader cannot see it, -1 once it has exited), `None` for any other file.
pub fn pidfd_pid(fdinfo: &str) -> Option<i32> {
    parse_field(fdinfo, "Pid")
}

// ── kernel: facts for one notification ───────────────────────────────────────

#[cfg(all(feature = "kernel", target_os = "linux"))]
pub use kernel_facts::{perform_pidfd_send_signal, should_refuse};

#[cfg(all(feature = "kernel", target_os = "linux"))]
mod kernel_facts {
    use super::*;
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    fn read(path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn same_pidns(caller: i32) -> Option<bool> {
        let theirs = std::fs::read_link(format!("/proc/{caller}/ns/pid")).ok()?;
        let ours = std::fs::read_link("/proc/self/ns/pid").ok()?;
        Some(theirs == ours)
    }

    fn tgid_of(tid: i32) -> Option<i32> {
        if tid <= 0 {
            return None;
        }
        parse_field(&read(&format!("/proc/{tid}/status"))?, "Tgid")
    }

    fn pgrp_of(pid: i32) -> Option<i32> {
        parse_stat(&read(&format!("/proc/{pid}/stat"))?).map(|(_, g, _)| g)
    }

    /// The guard's own (name, start time).
    fn own_identity() -> Option<(String, u64)> {
        parse_stat(&read("/proc/self/stat")?).map(|(n, _, s)| (n, s))
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EPERM)
    }

    /// What a descriptor names. `fdinfo` / `fd_path` are its procfs entries
    /// (the caller's, or the guard's own copy). A `/proc/<pid>` directory is
    /// returned open, for the checks that need it.
    fn fd_target(fdinfo: &str, fd_path: &str) -> (FdTarget, Option<OwnedFd>) {
        let fdinfo = match std::fs::read_to_string(fdinfo) {
            Ok(s) => s,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return (FdTarget::NotTheGuard, None),
            Err(_) => return (FdTarget::Unknown, None),
        };
        if let Some(pid) = pidfd_pid(&fdinfo) {
            if pid <= 0 {
                return (FdTarget::NotTheGuard, None);
            }
            // A thread pidfd names a thread: judge its thread group.
            return (FdTarget::Process(tgid_of(pid).unwrap_or(pid)), None);
        }
        // Otherwise only a /proc/<pid> directory can be a pidfd.
        let Ok(path) = std::ffi::CString::new(fd_path) else { return (FdTarget::Unknown, None) };
        // SAFETY: a NUL-terminated path; the result is owned below.
        let dir = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if dir < 0 {
            let e = std::io::Error::last_os_error().raw_os_error();
            return (if matches!(e, Some(libc::ENOTDIR) | Some(libc::ENOENT)) { FdTarget::NotTheGuard } else { FdTarget::Unknown }, None);
        }
        // SAFETY: a descriptor this function just opened.
        let dir = unsafe { OwnedFd::from_raw_fd(dir) };
        // SAFETY: statfs into a zeroed struct.
        let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut sfs) } != 0 {
            return (FdTarget::Unknown, None);
        }
        if sfs.f_type as i64 != 0x9fa0 {
            return (FdTarget::NotTheGuard, None);
        }
        let name = std::ffi::CString::new("stat").expect("static");
        // SAFETY: openat relative to the directory descriptor held above.
        let st = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if st < 0 {
            // Not a process directory (e.g. /proc itself).
            return (FdTarget::NotTheGuard, None);
        }
        // SAFETY: a descriptor this function just opened.
        let mut f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(st) });
        let mut s = String::new();
        if std::io::Read::read_to_string(&mut f, &mut s).is_err() {
            return (FdTarget::Unknown, None);
        }
        match (parse_stat(&s), own_identity()) {
            (Some((n, _, start)), Some((own_n, own_start))) if n == own_n && start == own_start => (FdTarget::TheGuard, None),
            (Some(_), Some(_)) => (FdTarget::ProcDir, Some(dir)),
            _ => (FdTarget::Unknown, None),
        }
    }

    /// Gather the facts for one trapped call and decide. `caller` is the
    /// notification's pid (the guard's namespace).
    pub fn should_refuse(nr: i64, args: &[u64; 6], caller: i32) -> bool {
        let Some(aim) = aim_of(nr, args) else { return false };
        // SAFETY: getpid has no failure mode.
        let guard = unsafe { libc::getpid() };
        let same = same_pidns(caller);
        let facts = Facts {
            guard,
            same_pidns: same,
            caller_pgrp: match aim {
                Aim::Kill(0) | Aim::Pgrp(0) => pgrp_of(caller),
                _ => None,
            },
            tid_tgid: match aim {
                Aim::Tid(t) | Aim::Kill(t) if t > 0 && same != Some(false) => tgid_of(t),
                _ => None,
            },
            fd: match aim {
                Aim::Fd(fd) if fd >= 0 => fd_target(&format!("/proc/{caller}/fdinfo/{fd}"), &format!("/proc/{caller}/fd/{fd}")).0,
                _ => FdTarget::NotTheGuard,
            },
        };
        refuse(aim, &facts)
    }

    /// `NS_GET_PARENT` (ioctl_ns(2)).
    const NS_GET_PARENT: libc::c_ulong = 0xb702;
    /// `KCMP_FILES` (kcmp(2)).
    const KCMP_FILES: libc::c_long = 2;

    fn ns_id(fd: RawFd) -> Option<(u64, u64)> {
        // SAFETY: fstat into a zeroed struct.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev as u64, st.st_ino as u64))
    }

    /// Is the pid namespace `target_ns` (an open `ns/pid` file) the caller's
    /// or one below it? Walks up with NS_GET_PARENT, which stops (EPERM) at
    /// the guard's own namespace.
    fn ns_within(target_ns: OwnedFd, caller: i32) -> Option<bool> {
        let want = {
            let st = std::fs::metadata(format!("/proc/{caller}/ns/pid")).ok()?;
            (std::os::unix::fs::MetadataExt::dev(&st), std::os::unix::fs::MetadataExt::ino(&st))
        };
        let mut cur = target_ns;
        for _ in 0..40 {
            if ns_id(cur.as_raw_fd())? == want {
                return Some(true);
            }
            // SAFETY: an ioctl on a namespace descriptor we hold; returns a new fd.
            let up = unsafe { libc::ioctl(cur.as_raw_fd(), NS_GET_PARENT as _) };
            if up < 0 {
                // EPERM: above the guard's namespace; the caller's was not met.
                return if errno() == libc::EPERM { Some(false) } else { None };
            }
            // SAFETY: a descriptor the ioctl just returned.
            cur = unsafe { OwnedFd::from_raw_fd(up) };
        }
        None
    }

    fn open_ns(path: &str, dirfd: Option<RawFd>) -> Option<OwnedFd> {
        let c = std::ffi::CString::new(path).ok()?;
        // SAFETY: open / openat of a NUL-terminated path; owned below.
        let fd = unsafe {
            match dirfd {
                Some(d) => libc::openat(d, c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC),
                None => libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC),
            }
        };
        // SAFETY: a descriptor just opened.
        (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// The caller's siginfo, when it passed one.
    fn read_siginfo(caller: i32, addr: u64) -> Result<Option<Box<[u8; 128]>>, i32> {
        if addr == 0 {
            return Ok(None);
        }
        let mut buf = Box::new([0u8; 128]);
        let local = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: 128 };
        let remote = libc::iovec { iov_base: addr as *mut libc::c_void, iov_len: 128 };
        // SAFETY: copies at most 128 bytes into our own buffer.
        let n = unsafe { libc::process_vm_readv(caller, &local, 1, &remote, 1, 0) };
        if n != 128 {
            return Err(libc::EFAULT);
        }
        Ok(Some(buf))
    }

    /// PERFORM a `pidfd_send_signal` (rootless-confinement §12.2): copy the
    /// caller's descriptor, judge the copy (`decide_send`), and send through
    /// the copy with `send`, which runs the closure where the caller's
    /// Landlock layers apply (the guard's own thread when it has none).
    /// Returns the answer: 0 or an errno.
    pub fn perform_pidfd_send_signal(
        caller: i32,
        args: &[u64; 6],
        send: impl FnOnce(Box<dyn FnOnce() -> i32 + Send>) -> Result<i32, i32>,
    ) -> i32 {
        let (fd, sig, info, flags) = (args[0] as u32 as i32, args[1] as u32 as i32, args[2], args[3] as u32);
        if fd < 0 {
            return libc::EBADF;
        }
        // SAFETY: getpid has no failure mode.
        let guard = unsafe { libc::getpid() };
        let Some(tgid) = tgid_of(caller) else { return libc::EPERM };
        // pidfd_getfd reads the process's descriptor table; a thread with a
        // table of its own (clone without CLONE_FILES) is refused.
        if tgid != caller {
            // SAFETY: kcmp compares two tasks' file tables; no memory is passed.
            let same = unsafe { libc::syscall(libc::SYS_kcmp, caller as libc::c_long, tgid as libc::c_long, KCMP_FILES, 0 as libc::c_long, 0 as libc::c_long) };
            if same != 0 {
                return libc::EPERM;
            }
        }
        let ours = match fs_supervisor::tracee::tracee_fd(tgid, fd) {
            // SAFETY: a descriptor pidfd_getfd just gave us.
            Ok(o) => unsafe { OwnedFd::from_raw_fd(o) },
            Err(e) if e.raw_os_error() == Some(libc::EBADF) => return libc::EBADF,
            Err(_) => return libc::EPERM,
        };
        let me = ours.as_raw_fd();
        let (target, dir) = fd_target(&format!("/proc/self/fdinfo/{me}"), &format!("/proc/self/fd/{me}"));
        let same = same_pidns(caller);
        let (target_pgrp, target_ns) = match target {
            FdTarget::Process(t) => (pgrp_of(t), open_ns(&format!("/proc/{t}/ns/pid"), None)),
            FdTarget::ProcDir => (None, dir.as_ref().and_then(|d| open_ns("ns/pid", Some(d.as_raw_fd())))),
            _ => (None, None),
        };
        let visible = match (same, target_ns) {
            // The guard's namespace: every target the kernel lets the guard
            // name, it lets the caller name.
            (Some(true), _) => Some(true),
            (_, Some(ns)) => ns_within(ns, caller),
            _ => None,
        };
        let facts = SendFacts { guard, target, target_pgrp, visible, flags };
        if let Err(e) = decide_send(&facts) {
            return e;
        }
        // The facts were read by number; a target still alive now held its
        // number all along (a live process's pid is not reused).
        if matches!(target, FdTarget::Process(_) | FdTarget::ProcDir) {
            // SAFETY: signal 0 through our own copy: an existence check.
            if unsafe { libc::syscall(libc::SYS_pidfd_send_signal, me, 0, 0usize, 0) } != 0 {
                return errno();
            }
        }
        let info = match read_siginfo(caller, info) {
            Ok(i) => i,
            Err(e) => return e,
        };
        let job: Box<dyn FnOnce() -> i32 + Send> = Box::new(move || {
            let p = info.as_ref().map_or(std::ptr::null(), |b| b.as_ptr());
            // SAFETY: our own descriptor copy; `p` is null or our 128-byte buffer.
            let r = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, me, sig, p, flags) };
            if r == 0 {
                0
            } else {
                errno()
            }
        });
        let r = send(job).unwrap_or_else(|e| e);
        drop(ours);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: i32 = 4242;
    fn facts() -> Facts {
        Facts { guard: G, same_pidns: Some(true), caller_pgrp: Some(100), tid_tgid: None, fd: FdTarget::NotTheGuard }
    }

    #[test]
    fn kill_of_the_guard_its_group_and_everyone_is_refused() {
        let f = facts();
        assert!(refuse(Aim::Kill(G), &f));
        assert!(refuse(Aim::Kill(-G), &f));
        assert!(refuse(Aim::Kill(-1), &f));
        assert!(!refuse(Aim::Kill(G + 1), &f));
        assert!(!refuse(Aim::Kill(-100), &f), "another group");
    }

    #[test]
    fn kill_zero_is_refused_only_from_the_guards_group() {
        assert!(!refuse(Aim::Kill(0), &facts()), "the caller's own group, not the guard's");
        assert!(refuse(Aim::Kill(0), &Facts { caller_pgrp: Some(G), ..facts() }), "a caller that joined the guard's group");
        assert!(refuse(Aim::Kill(0), &Facts { caller_pgrp: None, ..facts() }), "unknown group: fail-closed");
        assert!(
            refuse(Aim::Kill(0), &Facts { caller_pgrp: Some(G), same_pidns: Some(false), ..facts() }),
            "a group spans pid namespaces"
        );
    }

    #[test]
    fn below_the_guards_pid_namespace_no_number_is_the_guard() {
        let f = Facts { same_pidns: Some(false), ..facts() };
        assert!(!refuse(Aim::Kill(G), &f));
        assert!(!refuse(Aim::Kill(-1), &f), "kill(-1) there reaches only that namespace");
        assert!(!refuse(Aim::Tgid(G), &f));
        assert!(!refuse(Aim::Tid(G), &f));
        let unknown = Facts { same_pidns: None, ..facts() };
        assert!(refuse(Aim::Kill(G), &unknown), "an unreadable namespace is treated as the guard's");
    }

    #[test]
    fn thread_ids_are_judged_by_their_thread_group() {
        assert!(refuse(Aim::Tid(G), &facts()));
        assert!(refuse(Aim::Tid(G + 7), &Facts { tid_tgid: Some(G), ..facts() }), "a guard worker thread");
        assert!(!refuse(Aim::Tid(G + 7), &Facts { tid_tgid: Some(G + 7), ..facts() }));
        assert!(!refuse(Aim::Tid(G + 7), &facts()), "no such thread: the kernel says ESRCH");
        assert!(refuse(Aim::Tgid(G), &facts()));
        assert!(!refuse(Aim::Tgid(G - 1), &facts()));
    }

    #[test]
    fn descriptors_are_judged_by_what_they_name() {
        assert!(refuse(Aim::Fd(3), &Facts { fd: FdTarget::Process(G), ..facts() }));
        assert!(refuse(Aim::Fd(3), &Facts { fd: FdTarget::TheGuard, ..facts() }));
        assert!(refuse(Aim::Fd(3), &Facts { fd: FdTarget::Unknown, ..facts() }), "fail-closed");
        assert!(!refuse(Aim::Fd(3), &Facts { fd: FdTarget::Process(G + 1), ..facts() }));
        // A descriptor is not a number in the caller's namespace.
        assert!(refuse(Aim::Fd(3), &Facts { fd: FdTarget::Process(G), same_pidns: Some(false), ..facts() }));
    }

    #[test]
    fn arguments_count_by_their_low_32_bits() {
        let mut a = [0u64; 6];
        a[0] = 0xdead_beef_0000_0000 | (G as u64);
        assert_eq!(aim_of(libc::SYS_kill as i64, &a), Some(Aim::Kill(G)));
        a[0] = 0x0000_0000_ffff_ffff;
        assert_eq!(aim_of(libc::SYS_kill as i64, &a), Some(Aim::Kill(-1)));
        assert_eq!(aim_of(libc::SYS_tkill as i64, &a), Some(Aim::Tid(-1)));
        assert_eq!(aim_of(libc::SYS_pidfd_send_signal as i64, &[5, 9, 0, 0, 0, 0]), Some(Aim::Fd(5)));
        assert_eq!(aim_of(libc::SYS_prlimit64 as i64, &[G as u64, 0, 0, 0, 0, 0]), Some(Aim::Tid(G)));
        assert_eq!(aim_of(libc::SYS_tgkill as i64, &[G as u64, 7, 9, 0, 0, 0]), Some(Aim::Tgid(G)));
        assert_eq!(aim_of(libc::SYS_rt_sigqueueinfo as i64, &[G as u64, 9, 0, 0, 0, 0]), Some(Aim::Tid(G)));
        assert_eq!(aim_of(libc::SYS_openat as i64, &a), None);
    }

    #[test]
    fn procfs_parsing() {
        let stat = "4242 (mandu-net) guard) S 1 4242 4242 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 5 0 987654 1000 100 0";
        assert_eq!(parse_stat(stat), Some(("mandu-net) guard".to_string(), 4242, 987654)));
        assert_eq!(parse_field("Name:\tx\nTgid:\t77\nPid:\t78\n", "Tgid"), Some(77));
        assert_eq!(parse_field("Name:\tx\nTgid:\t77\nPid:\t78\n", "Pid"), Some(78));
        assert_eq!(pidfd_pid("pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1\nPid:\t-1\nNSpid:\t-1\n"), Some(-1));
        assert_eq!(pidfd_pid("pos:\t0\nflags:\t02\nmnt_id:\t15\n"), None);
    }

    /// A seccomp-BPF evaluator for the few instructions the block uses:
    /// returns the return value, or None when it fell through (to the rest).
    fn run(prog: &[libc::sock_filter], nr: i64, args: [u64; 6]) -> Option<u32> {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&(nr as u32).to_le_bytes());
        for (i, a) in args.iter().enumerate() {
            data[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_le_bytes());
        }
        let (mut pc, mut acc) = (0usize, 0u32);
        while pc < prog.len() {
            let ins = prog[pc];
            let class = ins.code & 0x07;
            match class as u32 {
                libc::BPF_LD => {
                    let o = ins.k as usize;
                    acc = u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
                    pc += 1;
                }
                libc::BPF_JMP if ins.code & 0xf0 == libc::BPF_JA as u16 => pc += 1 + ins.k as usize,
                libc::BPF_JMP if ins.code & 0xf0 == libc::BPF_JSET as u16 => pc += 1 + if acc & ins.k != 0 { ins.jt as usize } else { ins.jf as usize },
                libc::BPF_JMP => pc += 1 + if acc == ins.k { ins.jt as usize } else { ins.jf as usize },
                libc::BPF_RET => return Some(ins.k),
                _ => panic!("unexpected instruction {:?}", ins.code),
            }
        }
        None
    }

    #[test]
    fn a_payload_signal_is_aimed_by_its_registers() {
        let a = |x: [u64; 3]| [x[0], x[1], x[2], 0, 0, 0];
        assert_eq!(payload_aim(libc::SYS_rt_sigqueueinfo as i64, &a([42, 34, 0x7000])), Some(PayloadAim::Tgid(42)));
        assert_eq!(payload_aim(libc::SYS_rt_tgsigqueueinfo as i64, &a([0xffff_ffff_0000_002a, 43, 34])), Some(PayloadAim::Tgid(42)), "the low 32 bits");
        assert_eq!(payload_aim(libc::SYS_pidfd_send_signal as i64, &a([5, 34, 0x7000])), Some(PayloadAim::Fd));
        assert_eq!(payload_aim(libc::SYS_pidfd_send_signal as i64, &a([5, 15, 0])), None, "no siginfo: the number alone");
        assert_eq!(payload_aim(libc::SYS_kill as i64, &a([42, 15, 0])), None);
        assert!(payload_nrs().iter().all(|n| is_signal_nr(*n)), "every payload call is one the signal path already dispatches");
    }

    #[test]
    fn the_filter_block_traps_only_calls_that_may_reach_the_guard() {
        let prog = filter_block(G as u32);
        let notif = Some(libc::SECCOMP_RET_USER_NOTIF);
        let eperm = Some(libc::SECCOMP_RET_ERRNO | libc::EPERM as u32);
        let a = |x: i64, y: i64| [x as u64, y as u64, 0, 0, 0, 0];
        let kill = libc::SYS_kill as i64;
        for sig in [0, 9, 15] {
            assert_eq!(run(&prog, kill, a(G as i64, sig)), notif, "the guard, any signal");
            assert_eq!(run(&prog, kill, a(-G as i64, sig)), notif);
            assert_eq!(run(&prog, kill, a(-1, sig)), notif);
            assert_eq!(run(&prog, kill, a(0, sig)), notif);
        }
        assert_eq!(run(&prog, kill, [0xffff_ffff, 9, 0, 0, 0, 0]), notif, "-1 without sign extension");
        // Another pid: only a harmful signal is checked (it may be a guard
        // worker thread's id); another group runs.
        for sig in HARMFUL {
            assert_eq!(run(&prog, kill, a(1234, sig as i64)), notif, "kill(tid, {sig})");
            assert_eq!(run(&prog, libc::SYS_rt_sigqueueinfo as i64, a(1234, sig as i64)), notif);
        }
        for sig in [0, libc::SIGTERM, libc::SIGUSR1, libc::SIGCONT] {
            assert_eq!(run(&prog, kill, a(1234, sig as i64)), None, "kill(pid, {sig}) runs at full speed");
            assert_eq!(run(&prog, libc::SYS_rt_sigqueueinfo as i64, a(1234, sig as i64)), None);
        }
        assert_eq!(run(&prog, kill, a(-1234, 9)), None, "another group");
        assert_eq!(run(&prog, libc::SYS_rt_sigqueueinfo as i64, a(G as i64, 10)), notif);
        for nr in [libc::SYS_tgkill, libc::SYS_rt_tgsigqueueinfo] {
            assert_eq!(run(&prog, nr as i64, a(G as i64, 7)), notif);
            assert_eq!(run(&prog, nr as i64, a(1234, 1234)), None, "the kernel checks the thread belongs to the group");
        }
        assert_eq!(run(&prog, libc::SYS_pidfd_open as i64, a(G as i64, 0)), notif);
        assert_eq!(run(&prog, libc::SYS_pidfd_open as i64, a(1234, 0)), None);
        assert_eq!(run(&prog, libc::SYS_pidfd_open as i64, a(1234, 0x80)), notif, "a thread pidfd");
        for nr in [libc::SYS_prlimit64, libc::SYS_sched_setscheduler, libc::SYS_sched_setparam, libc::SYS_sched_setattr, libc::SYS_sched_setaffinity] {
            assert_eq!(run(&prog, nr as i64, a(0, 5)), None, "the caller itself");
            assert_eq!(run(&prog, nr as i64, a(1234, 5)), notif, "any thread");
        }
        let prio = libc::SYS_setpriority as i64;
        assert_eq!(run(&prog, prio, a(0, 0)), None, "nice(): the caller");
        assert_eq!(run(&prog, prio, a(0, 1234)), notif, "PRIO_PROCESS of a thread");
        assert_eq!(run(&prog, prio, a(1, 0)), notif, "PRIO_PGRP of the caller's group");
        assert_eq!(run(&prog, prio, a(1, G as i64)), notif);
        assert_eq!(run(&prog, prio, a(1, 1234)), None, "another group");
        assert_eq!(run(&prog, prio, a(2, 0)), notif, "PRIO_USER");
        let io = libc::SYS_ioprio_set as i64;
        assert_eq!(run(&prog, io, a(1, 0)), None);
        assert_eq!(run(&prog, io, a(1, 1234)), notif);
        assert_eq!(run(&prog, io, a(2, G as i64)), notif);
        assert_eq!(run(&prog, io, a(2, 1234)), None);
        assert_eq!(run(&prog, io, a(3, 0)), notif, "IOPRIO_WHO_USER");
        assert_eq!(run(&prog, libc::SYS_tkill as i64, a(1234, 0)), notif, "every tkill");
        assert_eq!(run(&prog, libc::SYS_pidfd_send_signal as i64, a(3, 0)), notif, "every pidfd signal");
        let setpgid = libc::SYS_setpgid as i64;
        assert_eq!(run(&prog, setpgid, a(0, G as i64)), eperm, "joining the guard's group");
        assert_eq!(run(&prog, setpgid, a(1234, G as i64)), eperm);
        assert_eq!(run(&prog, setpgid, a(0, 0)), None, "a group of its own");
        assert_eq!(run(&prog, setpgid, a(1234, 1234)), None);
        assert_eq!(run(&prog, libc::SYS_fcntl as i64, [3, 10, libc::SIGKILL as u64, 0, 0, 0]), eperm);
        assert_eq!(run(&prog, libc::SYS_fcntl as i64, [3, 10, libc::SIGSTOP as u64, 0, 0, 0]), eperm);
        assert_eq!(run(&prog, libc::SYS_fcntl as i64, [3, 10, libc::SIGUSR1 as u64, 0, 0, 0]), None);
        assert_eq!(run(&prog, libc::SYS_fcntl as i64, [3, 1, 9, 0, 0, 0]), None, "F_GETFD");
        assert_eq!(run(&prog, libc::SYS_openat as i64, a(G as i64, 9)), None);
    }

    #[test]
    fn a_kill_by_a_guard_threads_id_is_refused() {
        // The kernel reads kill(pid) as a thread id and signals its process.
        assert!(refuse(Aim::Kill(G + 3), &Facts { tid_tgid: Some(G), ..facts() }));
        assert!(!refuse(Aim::Kill(G + 3), &Facts { tid_tgid: Some(G + 3), ..facts() }));
        assert!(!refuse(Aim::Kill(G + 3), &Facts { tid_tgid: Some(G), same_pidns: Some(false), ..facts() }));
        assert!(!refuse(Aim::Kill(-(G + 3)), &Facts { tid_tgid: Some(G), ..facts() }), "a group is not a thread");
    }

    #[test]
    fn scheduling_calls_that_reach_the_guard_are_refused() {
        let f = facts();
        assert!(refuse(Aim::Tid(G), &f));
        assert!(refuse(Aim::Tid(G + 3), &Facts { tid_tgid: Some(G), ..f }), "a guard worker thread");
        assert!(!refuse(Aim::Tid(G + 3), &Facts { tid_tgid: Some(G + 3), ..f }));
        assert!(refuse(Aim::Pgrp(G), &f));
        assert!(!refuse(Aim::Pgrp(G + 1), &f));
        assert!(!refuse(Aim::Pgrp(0), &f), "the caller's own group");
        assert!(refuse(Aim::Pgrp(0), &Facts { caller_pgrp: Some(G), ..f }), "the guard leads the caller's group");
        assert!(refuse(Aim::User, &f), "every process of the uid includes the guard");
        assert!(!refuse(Aim::User, &Facts { same_pidns: Some(false), ..f }), "below the guard's namespace it is not visible");
        assert!(refuse(Aim::User, &Facts { same_pidns: None, ..f }), "fail-closed");
        let mut a = [0u64; 6];
        a[0] = 2;
        assert_eq!(aim_of(libc::SYS_setpriority as i64, &a), Some(Aim::User));
        a[0] = 0;
        a[1] = 77;
        assert_eq!(aim_of(libc::SYS_setpriority as i64, &a), Some(Aim::Tid(77)));
        a[0] = 1;
        assert_eq!(aim_of(libc::SYS_setpriority as i64, &a), Some(Aim::Pgrp(77)));
        assert_eq!(aim_of(libc::SYS_ioprio_set as i64, &a), Some(Aim::Tid(77)));
        a[0] = 2;
        assert_eq!(aim_of(libc::SYS_ioprio_set as i64, &a), Some(Aim::Pgrp(77)));
        a[0] = 3;
        assert_eq!(aim_of(libc::SYS_ioprio_set as i64, &a), Some(Aim::User));
        a[0] = 0;
        assert_eq!(aim_of(libc::SYS_ioprio_set as i64, &a), None, "EINVAL from the kernel");
        assert_eq!(aim_of(libc::SYS_sched_setaffinity as i64, &[77, 0, 0, 0, 0, 0]), Some(Aim::Tid(77)));
    }

    #[test]
    fn only_the_uncatchable_and_glibcs_reserved_signals_are_harmful() {
        assert!(harmful(libc::SIGKILL) && harmful(libc::SIGSTOP) && harmful(32) && harmful(33));
        for s in [0, libc::SIGTERM, libc::SIGINT, libc::SIGUSR1, libc::SIGTSTP, libc::SIGCONT, 34, 64] {
            assert!(!harmful(s), "{s}");
        }
    }

    fn send(target: FdTarget) -> SendFacts {
        SendFacts { guard: G, target, target_pgrp: Some(100), visible: Some(true), flags: 0 }
    }

    #[test]
    fn a_performed_signal_goes_only_where_the_caller_could_send_it() {
        assert_eq!(decide_send(&send(FdTarget::Process(G + 1))), Ok(()));
        assert_eq!(decide_send(&send(FdTarget::ProcDir)), Ok(()));
        assert_eq!(decide_send(&send(FdTarget::NotTheGuard)), Ok(()), "the kernel answers EBADF / ESRCH");
        assert_eq!(decide_send(&send(FdTarget::Process(G))), Err(libc::EPERM));
        assert_eq!(decide_send(&send(FdTarget::TheGuard)), Err(libc::EPERM));
        assert_eq!(decide_send(&send(FdTarget::Unknown)), Err(libc::EPERM), "fail-closed");
        // A target outside the caller's pid namespace: the kernel's answer.
        assert_eq!(decide_send(&SendFacts { visible: Some(false), ..send(FdTarget::Process(G + 1)) }), Err(libc::EINVAL));
        assert_eq!(decide_send(&SendFacts { visible: None, ..send(FdTarget::Process(G + 1)) }), Err(libc::EPERM));
    }

    #[test]
    fn a_process_group_signal_by_descriptor_never_reaches_the_guards_group() {
        let pg = |target_pgrp| SendFacts { target_pgrp, flags: PIDFD_SIGNAL_PROCESS_GROUP, ..send(FdTarget::Process(G + 1)) };
        assert_eq!(decide_send(&pg(Some(100))), Ok(()));
        assert_eq!(decide_send(&pg(Some(G))), Err(libc::EPERM), "a member of the guard's group");
        assert_eq!(decide_send(&pg(None)), Err(libc::EPERM), "unknown group: fail-closed");
        assert_eq!(
            decide_send(&SendFacts { target_pgrp: None, flags: PIDFD_SIGNAL_PROCESS_GROUP, ..send(FdTarget::ProcDir) }),
            Err(libc::EPERM),
            "a /proc directory's group numbers belong to its mount"
        );
        assert_eq!(decide_send(&SendFacts { target_pgrp: Some(G), flags: 1, ..send(FdTarget::Process(G + 1)) }), Ok(()), "a thread signal");
    }
}
