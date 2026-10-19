//! tracee — reaching a trapped process's file system the way it would.
//!
//! A seccomp supervisor that acts on a tracee's behalf (connects its socket,
//! opens its file) must resolve the tracee's path in the TRACEE's view, not
//! its own: its root and mount namespace (a bwrap box, the secret-twin wrap),
//! its cwd, its descriptors. Shared by net-supervisor's guard (the supervised
//! Unix connect, exec-routing.md §4.1) and exec-supervisor's box socket
//! allow-list (exec-routing.md §4.2).
//!
//! The planning is PURE (`plan_unix_lookup`, unit-tested with no privilege);
//! the lookups behind the `kernel` feature use `openat2(RESOLVE_IN_ROOT)` on
//! `/proc/<tid>/root` and `pidfd_getfd`.
//!
//! `Mandu-new`.

/// How a supervisor reaches a pathname Unix target in the TRACEE's view
/// (`plan_unix_lookup`), so it can check the inode and then connect exactly
/// that inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnixLookup {
    /// `/proc/self/fd/N`, `/proc/thread-self/fd/N` or `/dev/fd/N`: the
    /// tracee's own descriptor N (opened through `/proc/<tid>/fd/N`, since
    /// procfs `self` would name the supervisor).
    TraceeFd(u32),
    /// This absolute path, resolved under the tracee's root
    /// (`openat2(RESOLVE_IN_ROOT)` on `/proc/<tid>/root`): its absolute
    /// symlinks and `..` stay inside the tracee's root and mount namespace,
    /// so the supervisor never reaches a socket the tracee's own view hides.
    InRoot(Vec<u8>),
}

/// Plan the lookup of a pathname Unix sockaddr (`path`, the raw bytes before
/// the NUL; never abstract). A relative path joins the tracee's cwd as
/// `/proc/<tid>/cwd` reports it (`cwd`; it names the directory in the
/// tracee's own mount namespace). Errors are the errno the tracee gets, the
/// one its own connect would have got: no cwd or a deleted one → ENOENT, an
/// empty path → ENOENT.
pub fn plan_unix_lookup(path: &[u8], cwd: Option<&[u8]>) -> Result<UnixLookup, i32> {
    const ENOENT: i32 = 2;
    if path.is_empty() {
        return Err(ENOENT);
    }
    let abs: Vec<u8> = if path[0] == b'/' {
        path.to_vec()
    } else {
        let cwd = cwd.ok_or(ENOENT)?;
        if cwd.first() != Some(&b'/') || cwd.ends_with(b" (deleted)") {
            return Err(ENOENT);
        }
        let mut a = cwd.to_vec();
        if a.last() != Some(&b'/') {
            a.push(b'/');
        }
        a.extend_from_slice(path);
        a
    };
    for prefix in [&b"/proc/self/fd/"[..], b"/proc/thread-self/fd/", b"/dev/fd/"] {
        if let Some(rest) = abs.strip_prefix(prefix) {
            if !rest.is_empty() && rest.len() <= 9 && rest.iter().all(u8::is_ascii_digit) {
                let n: u32 = std::str::from_utf8(rest).ok().and_then(|r| r.parse().ok()).ok_or(ENOENT)?;
                return Ok(UnixLookup::TraceeFd(n));
            }
        }
    }
    Ok(UnixLookup::InRoot(abs))
}

/// How a supervisor performs a tracee's open in the tracee's own view
/// (confidentiality-plan-10-flow-taint.md §4.1a: the guard performs every
/// read-capable open, so the kernel never resolves a path a second time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenPlan {
    /// This absolute path, resolved under the tracee's root (`RESOLVE_IN_ROOT`).
    InRoot(Vec<u8>),
    /// One of the tracee's own procfs magic links (`hop`: `fd/N`, `cwd`,
    /// `root`, `exe`) of its process (`thread: false`) or its thread, then
    /// `tail` beneath it (empty: the link's target itself). `/proc/self`
    /// names the opener, so the supervisor reaches the tracee's by number.
    OwnMagic { thread: bool, hop: Vec<u8>, tail: Vec<u8> },
    /// A plain entry of the tracee's own procfs directory (`status`, `maps`,
    /// the directory itself): `rest` under it, read from the tracee's procfs
    /// so the numbers are the ones its pid namespace shows.
    OwnProc { thread: bool, rest: Vec<u8> },
}

/// Collapse repeated slashes and `.` components of an absolute path. Never
/// `..`: the kernel walks `..` after following symlinks, so folding it here
/// would name another file.
fn tidy(abs: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(abs.len());
    for comp in abs.split(|b| *b == b'/') {
        if comp.is_empty() || comp == b"." {
            continue;
        }
        out.push(b'/');
        out.extend_from_slice(comp);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    // A trailing slash asks for a directory; keep it.
    if abs.len() > 1 && abs.ends_with(b"/") && !out.ends_with(b"/") {
        out.push(b'/');
    }
    out
}

/// `p` is `prefix` or lies beneath it: the remainder, without its leading `/`.
fn beneath<'a>(p: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let rest = p.strip_prefix(prefix)?;
    if rest.is_empty() {
        return Some(rest);
    }
    rest.strip_prefix(b"/")
}

/// Plan a tracee's open of `path`. A relative path joins `base` (the
/// tracee's cwd or dirfd as `/proc/<tid>` reports it; `None` or a deleted
/// one is ENOENT). `/proc/self`, `/proc/thread-self`, `/dev/fd` and
/// `/dev/std{in,out,err}` are the tracee's own procfs entries. Errors are the
/// errno the tracee's own open would have met.
pub fn plan_open(path: &[u8], base: Option<&[u8]>) -> Result<OpenPlan, i32> {
    const ENOENT: i32 = 2;
    if path.is_empty() {
        return Err(ENOENT);
    }
    let joined: Vec<u8> = if path[0] == b'/' {
        path.to_vec()
    } else {
        let base = base.ok_or(ENOENT)?;
        if base.first() != Some(&b'/') || base.ends_with(b" (deleted)") {
            return Err(ENOENT);
        }
        let mut a = base.to_vec();
        a.push(b'/');
        a.extend_from_slice(path);
        a
    };
    let abs = tidy(&joined);
    let std_fd = |name: &[u8], n: &[u8]| -> Option<Vec<u8>> {
        beneath(&abs, name).map(|r| {
            let mut v = b"fd/".to_vec();
            v.extend_from_slice(n);
            if !r.is_empty() {
                v.push(b'/');
                v.extend_from_slice(r);
            }
            v
        })
    };
    let own: Option<(bool, Vec<u8>)> = if let Some(r) = beneath(&abs, b"/proc/self") {
        Some((false, r.to_vec()))
    } else if let Some(r) = beneath(&abs, b"/proc/thread-self") {
        Some((true, r.to_vec()))
    } else if let Some(r) = beneath(&abs, b"/proc/net") {
        // procfs's own `net -> self/net` and `mounts -> self/mounts`.
        let mut v = b"net".to_vec();
        if !r.is_empty() {
            v.push(b'/');
            v.extend_from_slice(r);
        }
        Some((false, v))
    } else if abs == b"/proc/mounts" {
        Some((false, b"mounts".to_vec()))
    } else if let Some(r) = beneath(&abs, b"/dev/fd") {
        let mut v = b"fd".to_vec();
        if !r.is_empty() {
            v.push(b'/');
            v.extend_from_slice(r);
        }
        Some((false, v))
    } else {
        std_fd(b"/dev/stdin", b"0")
            .or_else(|| std_fd(b"/dev/stdout", b"1"))
            .or_else(|| std_fd(b"/dev/stderr", b"2"))
            .map(|v| (false, v))
    };
    let Some((thread, rest)) = own else { return Ok(OpenPlan::InRoot(abs)) };
    let mut comps = rest.splitn(3, |b| *b == b'/');
    let first = comps.next().unwrap_or(b"");
    let (hop, tail): (Vec<u8>, Vec<u8>) = match first {
        b"fd" => {
            let n = comps.next().unwrap_or(b"");
            if n.is_empty() || !n.iter().all(u8::is_ascii_digit) {
                return Ok(OpenPlan::OwnProc { thread, rest });
            }
            let mut h = b"fd/".to_vec();
            h.extend_from_slice(n);
            (h, comps.next().unwrap_or(b"").to_vec())
        }
        b"cwd" | b"root" | b"exe" => {
            let rest_tail: Vec<u8> = rest[first.len()..].strip_prefix(b"/").unwrap_or(b"").to_vec();
            (first.to_vec(), rest_tail)
        }
        _ => return Ok(OpenPlan::OwnProc { thread, rest }),
    };
    Ok(OpenPlan::OwnMagic { thread, hop, tail })
}

/// What one step of `walk_to_proc_self` found at a path (the kernel side
/// opens it `O_PATH | O_NOFOLLOW` under the tracee's root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkNode {
    /// The root directory of a procfs mount.
    ProcRoot,
    /// Anything that is not a symlink (a directory, a file, a device).
    Plain,
    /// A symlink, with its target text.
    Link(Vec<u8>),
    /// A procfs magic link (`/proc/<n>/fd/N`, `cwd`, `root`, `exe`): its text
    /// is not a path, so the walk gives up.
    Magic,
}

/// Where `walk_to_proc_self` entered a procfs `self` (or `thread-self`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSelf {
    /// The procfs mount the walk was in (`/proc`, `/oldroot/proc`).
    pub proc_root: Vec<u8>,
    pub thread: bool,
    /// What the path names beneath `self` (empty: `self` itself); `..`
    /// components are kept for the open to walk.
    pub rest: Vec<u8>,
}

impl ProcSelf {
    /// The same path spelled under `/proc`, for `plan_open` to classify
    /// (an own entry, or a magic link and what lies beneath it).
    pub fn as_proc(&self) -> Vec<u8> {
        let mut p = if self.thread { b"/proc/thread-self".to_vec() } else { b"/proc/self".to_vec() };
        if !self.rest.is_empty() {
            p.push(b'/');
            p.extend_from_slice(&self.rest);
        }
        p
    }
}

/// When the tracee lives in a pid namespace the supervisor is not in, a
/// procfs `self` the supervisor's own walk meets names nobody (ENOENT): the
/// kernel resolves `self` for the OPENER, and the opener has no pid there.
/// That happens under the whole-agent wrap's `--unshare-pid` for every path
/// that reaches `self` through a symlink (`/etc/mtab`, `/proc/mounts`,
/// `/proc/net`). This walk redoes the resolution by text, one component at a
/// time (`look` reports each prefix, told whether its directory is a procfs
/// root; symlinks are spliced as the kernel would,
/// `..` pops a symlink-free prefix), and stops where the path enters a procfs
/// `self` or `thread-self`: Ok(Some(..)) names where (the procfs mount,
/// which need not be `/proc`: a sandbox mid-setup reads its old root's
/// procfs at `/oldroot/proc`) and what lies beneath it. Ok(None): the walk
/// never met one (the first answer stands). It only decides what to open;
/// the open itself goes through the usual plan. PURE.
pub fn walk_to_proc_self(abs: &[u8], nofollow_last: bool, mut look: impl FnMut(&[u8], bool) -> Result<WalkNode, i32>) -> Result<Option<ProcSelf>, i32> {
    const ELOOP: i32 = 40;
    const MAX_LINKS: u32 = 40;
    let split = |p: &[u8]| -> Vec<Vec<u8>> { p.split(|b| *b == b'/').filter(|c| !c.is_empty() && *c != b".").map(<[u8]>::to_vec).collect() };
    let mut todo: std::collections::VecDeque<Vec<u8>> = split(abs).into();
    // The resolved, symlink-free prefix, and whether each level is a procfs root.
    let mut done: Vec<(Vec<u8>, bool)> = Vec::new();
    let join = |done: &[(Vec<u8>, bool)], last: Option<&[u8]>| -> Vec<u8> {
        let mut out = Vec::new();
        for (c, _) in done {
            out.push(b'/');
            out.extend_from_slice(c);
        }
        if let Some(l) = last {
            out.push(b'/');
            out.extend_from_slice(l);
        }
        if out.is_empty() {
            out.push(b'/');
        }
        out
    };
    let mut links = 0;
    while let Some(c) = todo.pop_front() {
        if c.as_slice() == b".." {
            done.pop();
            continue;
        }
        let in_proc_root = done.last().map(|(_, r)| *r).unwrap_or(false);
        if in_proc_root && (c.as_slice() == b"self" || c.as_slice() == b"thread-self") {
            let rest: Vec<&[u8]> = todo.iter().map(Vec::as_slice).collect();
            return Ok(Some(ProcSelf { proc_root: join(&done, None), thread: c.as_slice() == b"thread-self", rest: rest.join(&b'/') }));
        }
        match look(&join(&done, Some(&c)), in_proc_root)? {
            WalkNode::ProcRoot => done.push((c, true)),
            WalkNode::Plain => done.push((c, false)),
            WalkNode::Magic => return Ok(None),
            WalkNode::Link(_) if todo.is_empty() && nofollow_last => done.push((c, false)),
            WalkNode::Link(target) => {
                links += 1;
                if links > MAX_LINKS {
                    return Err(ELOOP);
                }
                if target.first() == Some(&b'/') {
                    done.clear();
                }
                for t in split(&target).into_iter().rev() {
                    todo.push_front(t);
                }
            }
        }
    }
    Ok(None)
}

/// A tracee's `(tgid, tid)` at each pid-namespace level, outermost (the
/// supervisor's procfs) first, from its `NStgid` and `NSpid` values.
pub fn ns_levels(nstgid: &[i32], nspid: &[i32]) -> Vec<(i32, i32)> {
    nstgid.iter().zip(nspid).map(|(g, t)| (*g, *t)).collect()
}

/// `starttime` (field 22) of a `/proc/<n>/stat` text.
pub fn stat_starttime(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

/// Which level's numbers a procfs mount shows for the tracee: a procfs
/// belongs to one pid namespace, and the tracee may see an outer one (a
/// sandbox's setup before it mounts its own `/proc`). Innermost first, the
/// first level whose `<tgid>/stat` in that procfs carries the tracee's own
/// start time (`starttime_at(tgid)`; the same process, not a namesake in
/// another namespace). One level: that one, no check. None: the procfs shows
/// no entry of the tracee's. PURE.
pub fn pick_level(levels: &[(i32, i32)], want: u64, mut starttime_at: impl FnMut(i32) -> Option<u64>) -> Option<(i32, i32)> {
    if levels.len() == 1 {
        return levels.first().copied();
    }
    levels.iter().rev().copied().find(|(tgid, _)| starttime_at(*tgid) == Some(want))
}

/// The device node of a controlling terminal, from `/proc/<tid>/stat`'s
/// `tty_nr` (the kernel's `new_encode_dev`): a pseudo-terminal
/// (`/dev/pts/N`), a virtual console (`/dev/ttyN`) or a serial line
/// (`/dev/ttySN`). `None`: no terminal, or one this cannot name.
pub fn ctty_node(tty_nr: u64) -> Option<Vec<u8>> {
    if tty_nr == 0 {
        return None;
    }
    let major = (tty_nr >> 8) & 0xfff;
    let minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00);
    match major {
        136..=143 => Some(format!("/dev/pts/{}", (major - 136) * 256 + minor).into_bytes()),
        4 if minor < 64 => Some(format!("/dev/tty{minor}").into_bytes()),
        4 => Some(format!("/dev/ttyS{}", minor - 64).into_bytes()),
        _ => None,
    }
}

/// `O_PATH`, `O_NOCTTY` and `O_CLOEXEC`: the same on x86_64 and aarch64
/// (asm-generic), spelled here because `libc` is the `kernel` feature's
/// (pinned equal to it by `open_flag_constants_match_libc`).
const O_PATH: i32 = 0o10_000_000;
const O_NOCTTY: i32 = 0o400;
const O_CLOEXEC: i32 = 0o2_000_000;

/// The flags of the `openat2` a supervisor issues when it PERFORMS a
/// tracee's open: the tracee's own, close-on-exec (the descriptor is the
/// supervisor's until ADDFD hands it over with the tracee's flags), and
/// `O_NOCTTY` (the supervisor never takes a terminal as its own) EXCEPT
/// with `O_PATH`. `openat2` refuses an `O_PATH` open carrying any flag but
/// `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` (EINVAL; the legacy `openat`
/// drops the rest silently), and an `O_PATH` descriptor opens no device, so
/// there is no terminal to take. Adding it there answered every tracee
/// `openat2(…, O_PATH)` EINVAL: GNU tar 1.35 opens the parent of each
/// argument that has a directory part that way, so `tar cf x.tar dir/f`
/// (any file, a secret or not) failed "Cannot stat: Invalid argument"
/// under the guard (2026-10-03). Pure.
pub fn performed_open_flags(flags: i32) -> i32 {
    if flags & O_PATH != 0 {
        flags | O_CLOEXEC
    } else {
        flags | O_NOCTTY | O_CLOEXEC
    }
}

/// The major number of a device number (`st_dev`), as glibc's `major()`
/// decodes it (bits 8-19 and 32-63). Pure.
pub fn dev_major(dev: u64) -> u64 {
    ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)
}

/// Can a file whose `stat` reports `st_dev` lie on a pseudo filesystem
/// (procfs, sysfs, cgroupfs, debugfs, …)? Every one of them is a superblock
/// with no block device behind it, numbered by the kernel's anonymous device
/// allocator (`set_anon_super`), whose major is always 0, and its inodes
/// report that number (`generic_fillattr`). A non-zero major is a block
/// device's: ext4, xfs, a loop or device-mapper volume, never a pseudo
/// filesystem. So a `fstat` (cheap) answers "no" for most files where an
/// `fstatfs` (about 2.5 µs on a 128-CPU ext4 host: it sums per-CPU free
/// counts) was asked before (runtime-instances.md §14.9). Major 0 (tmpfs,
/// overlayfs, btrfs, FUSE, the pseudo filesystems) still asks `fstatfs`.
/// Pure.
pub fn may_be_pseudo_fs(st_dev: u64) -> bool {
    dev_major(st_dev) == 0
}

/// `O_CREAT` and `__O_TMPFILE` (`O_TMPFILE` without its `O_DIRECTORY` bit):
/// the same on x86_64 and aarch64 (asm-generic).
const O_CREAT: i32 = 0o100;
const O_TMPFILE_BIT: i32 = 0o20_000_000;

/// Does an open with these flags create a file, so that its `mode` means
/// something? The kernel's own test (`WILL_CREATE`: `O_CREAT | __O_TMPFILE`).
/// NOT `flags & (O_CREAT | O_TMPFILE)`: libc's `O_TMPFILE` carries the
/// `O_DIRECTORY` bit, so that test called every `O_DIRECTORY` open a
/// create. Pure.
pub fn open_creates(flags: i32) -> bool {
    flags & (O_CREAT | O_TMPFILE_BIT) != 0
}

/// The mode a supervisor's PERFORMED open carries (`struct open_how`'s
/// `mode`): a create's, masked by the tracee's umask (absent: 022); zero for
/// every other open. The legacy `open`/`openat` ignore the mode register of
/// an open that creates nothing, but `openat2` refuses a nonzero one
/// (EINVAL). Bun (Claude Code) passes 0666 on every open, a directory's
/// `O_DIRECTORY` open too: with that open taken for a create, the guard's
/// openat2 carried the mode and the tracee got EINVAL, and Claude Code
/// stopped at start, "Error processing settings: EINVAL: invalid argument,
/// open '/tmp/claude-<uid>'" (2026-10-16, a launch whose agent is in no
/// Landlock domain, `--no-landlock-net`: the guard's one-step open; under
/// the net-only wrap its split open never passed the mode). Pure.
pub fn performed_open_mode(flags: i32, mode: u32, umask: Option<u32>) -> u32 {
    if open_creates(flags) {
        mode & 0o7777 & !umask.unwrap_or(0o022)
    } else {
        0
    }
}

/// The kernel's answer to an `openat2` whose `struct open_how` carries a
/// `mode` its flags do not take (`build_open_flags`): a mode outside
/// `S_IALLUGO` on a create, any nonzero mode on an open that creates
/// nothing. A supervisor that performs the tracee's `openat2` answers the
/// same instead of opening (it drops the mode of an open that creates
/// nothing). Pure.
pub fn openat2_mode_errno(flags: i32, mode: u64) -> Option<i32> {
    const EINVAL: i32 = 22;
    let ok = if open_creates(flags) { mode & !0o7777 == 0 } else { mode == 0 };
    if ok { None } else { Some(EINVAL) }
}

/// How many times a supervisor issues one `openat2` that the kernel answers
/// EAGAIN, the first `OPENAT2_TIGHT` back to back, the rest after a pause.
pub const OPENAT2_ATTEMPTS: u32 = 64;
const OPENAT2_TIGHT: u32 = 8;
/// The longest pause between two attempts.
const OPENAT2_MAX_PAUSE_US: u64 = 5_000;
/// `RESOLVE_CACHED`: the same on every architecture.
const RESOLVE_CACHED: u64 = 0x20;
const EAGAIN: i32 = 11;

/// Whether, and after what pause, to issue an `openat2` again that failed
/// with `errno` after `attempts` tries. A walk scoped by `RESOLVE_BENEATH` or
/// `RESOLVE_IN_ROOT` (every walk a supervisor performs for a tracee) fails
/// EAGAIN when ANY rename or mount anywhere on the machine happens while it
/// walks a `..` (the kernel cannot then prove the `..` stayed inside), and
/// the man page leaves the retry to the caller. A plain `open`/`openat` never
/// fails that way, so the tracee must not see it: `git filter-branch`, whose
/// index is `.git-rewrite/t/../index`, failed "index file open failed:
/// Resource temporarily unavailable" on a busy CI guest (2026-10-16) after
/// the eight back-to-back attempts this replaced. Eight tight attempts, then
/// pauses doubling from 100 us up to 5 ms, so a burst of renames or mounts
/// (a sandbox starting up, git renaming its lock files) passes; at most
/// `OPENAT2_ATTEMPTS` in all (about a quarter second), then the EAGAIN
/// stands, an error and never an open. `RESOLVE_CACHED`'s EAGAIN ("not in
/// the cache, walk again without it") is the tracee's own to see. `None`:
/// stop. Pure.
pub fn openat2_retry_after(errno: i32, resolve: u64, attempts: u32) -> Option<std::time::Duration> {
    if errno != EAGAIN || resolve & RESOLVE_CACHED != 0 || attempts >= OPENAT2_ATTEMPTS {
        return None;
    }
    if attempts < OPENAT2_TIGHT {
        return Some(std::time::Duration::ZERO);
    }
    let us = 100u64.checked_shl(attempts - OPENAT2_TIGHT).unwrap_or(u64::MAX).min(OPENAT2_MAX_PAUSE_US);
    Some(std::time::Duration::from_micros(us))
}

/// Run `attempt` (one `openat2`: a descriptor or an errno) under
/// `openat2_retry_after`, pausing with `pause`. Generic over both, so the
/// policy is unit-tested with no kernel; allocates nothing (the context
/// helper calls it after a fork).
pub fn retry_openat2(resolve: u64, mut attempt: impl FnMut() -> Result<i32, i32>, mut pause: impl FnMut(std::time::Duration)) -> Result<i32, i32> {
    let mut tries = 0u32;
    loop {
        let r = attempt();
        tries += 1;
        let Err(e) = r else { return r };
        match openat2_retry_after(e, resolve, tries) {
            None => return r,
            Some(d) if d.is_zero() => {}
            Some(d) => pause(d),
        }
    }
}

#[cfg(feature = "kernel")]
pub use live::*;

#[cfg(feature = "kernel")]
mod live {
    use super::{ctty_node, pick_level, plan_open, plan_unix_lookup, stat_starttime, walk_to_proc_self, OpenPlan, ProcSelf, UnixLookup, WalkNode};
    use std::io::Error;
    use std::os::unix::io::RawFd;

    /// pidfd syscalls: the same numbers on x86_64 and aarch64
    /// (pidfd_open 434, kernel ≥ 5.3; pidfd_getfd 438, kernel ≥ 5.6).
    const SYS_PIDFD_OPEN: libc::c_long = 434;
    const SYS_PIDFD_GETFD: libc::c_long = 438;

    fn errno_of(e: Error) -> i32 {
        e.raw_os_error().unwrap_or(libc::EIO)
    }

    fn close_fd(fd: RawFd) {
        // SAFETY: closing a descriptor we own.
        unsafe { libc::close(fd) };
    }

    /// pidfd_open(pid, 0) → an owned pidfd.
    pub fn pidfd_open(pid: i32) -> std::io::Result<RawFd> {
        // SAFETY: pidfd_open with flags=0; returns a new fd or -1.
        let fd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }
        Ok(fd as RawFd)
    }

    /// pidfd_getfd(pidfd, targetfd, 0) → a copy of the tracee's descriptor in
    /// US, referring to the SAME open file description.
    pub fn pidfd_getfd(pidfd: RawFd, targetfd: RawFd) -> std::io::Result<RawFd> {
        // SAFETY: pidfd_getfd with flags=0; returns a new fd or -1.
        let fd = unsafe { libc::syscall(SYS_PIDFD_GETFD, pidfd, targetfd, 0) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }
        Ok(fd as RawFd)
    }

    /// The tracee's descriptor `fd`, copied into this process
    /// (`pidfd_open` + `pidfd_getfd`). `tid` is the calling THREAD (a seccomp
    /// notification names it): `pidfd_open` without PIDFD_THREAD takes only a
    /// thread-group leader (EINVAL for any other thread before Linux 6.9,
    /// ENOENT on 7.0: glibc's and Bun's DNS and Bun's HTTP client run on
    /// worker threads, so their connects meet it), so a worker
    /// is reached through its leader and the copy is kept only if it is the
    /// same file the thread's own `/proc/<tgid>/task/<tid>/fd/<fd>` names (a
    /// thread made without CLONE_FILES has a table of its own: refused, EBADF).
    pub fn tracee_fd(tid: i32, fd: RawFd) -> std::io::Result<RawFd> {
        let copy = |pid: i32| -> std::io::Result<RawFd> {
            let pf = pidfd_open(pid)?;
            let r = pidfd_getfd(pf, fd);
            close_fd(pf);
            r
        };
        match pidfd_open(tid) {
            Ok(pf) => {
                let r = pidfd_getfd(pf, fd);
                close_fd(pf);
                r
            }
            // A non-leader thread: EINVAL before Linux 6.9, ENOENT on newer
            // kernels (7.0 answered ENOENT, 2026-09-30: every connect Claude
            // Code's Bun makes from its HTTP and DNS worker threads missed this
            // arm, the guard held no copy, and each allowed connect was refused
            // EACCES). A thread that is really gone has no /proc status, or is
            // its own leader: the error is returned as it was.
            Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOENT)) => {
                let tgid = read_proc_small(&format!("/proc/{tid}/status"))
                    .and_then(|st| status_values(&st, "Tgid").and_then(|v| v.first()?.parse::<i32>().ok()))
                    .filter(|g| *g != tid)
                    .ok_or(e)?;
                let dup = copy(tgid)?;
                let theirs = {
                    use std::os::unix::fs::MetadataExt;
                    std::fs::metadata(format!("/proc/{tgid}/task/{tid}/fd/{fd}")).ok().map(|m| (m.dev(), m.ino()))
                };
                if theirs.is_none() || fd_identity(dup) != theirs {
                    close_fd(dup);
                    return Err(Error::from_raw_os_error(libc::EBADF));
                }
                Ok(dup)
            }
            Err(e) => Err(e),
        }
    }

    /// `openat2(2)` arguments (`struct open_how`; libc's is non-exhaustive).
    #[repr(C)]
    pub struct OpenHow {
        pub flags: u64,
        pub mode: u64,
        pub resolve: u64,
    }

    /// `openat2(dirfd, path, how)`, retried on the EAGAIN a scoped walk
    /// answers when a rename or a mount races its `..`
    /// (`super::openat2_retry_after`). Err = the errno.
    pub fn openat2(dirfd: RawFd, path: &std::ffi::CStr, how: &OpenHow) -> Result<RawFd, i32> {
        super::retry_openat2(
            how.resolve,
            || {
                // SAFETY: openat2(dirfd, NUL-terminated path, &open_how, size).
                let fd = unsafe {
                    libc::syscall(libc::SYS_openat2, dirfd, path.as_ptr(), how as *const OpenHow, std::mem::size_of::<OpenHow>())
                };
                if fd >= 0 { Ok(fd as RawFd) } else { Err(errno_of(Error::last_os_error())) }
            },
            std::thread::sleep,
        )
    }

    /// Open the absolute path `abs` under the tracee's root
    /// (`/proc/<pid>/root`, `RESOLVE_IN_ROOT`: its absolute symlinks and `..`
    /// cannot leave its root and mount namespace, and a magic link is ELOOP).
    /// Err = the errno for the tracee; ENOSYS = openat2 is missing.
    pub fn open_in_root(pid: i32, abs: &[u8], flags: i32, mode: u32) -> Result<RawFd, i32> {
        let cpath = |b: &[u8]| std::ffi::CString::new(b).map_err(|_| libc::ENOENT);
        let root = cpath(format!("/proc/{pid}/root").as_bytes())?;
        // SAFETY: open with a NUL-terminated path; returns an fd or -1.
        let rootfd = unsafe { libc::open(root.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if rootfd < 0 {
            return Err(errno_of(Error::last_os_error()));
        }
        let rel = abs.iter().position(|b| *b != b'/').map(|i| &abs[i..]).unwrap_or(b".");
        let result = match cpath(rel) {
            Ok(rel) => {
                let how = OpenHow { flags: (flags | libc::O_CLOEXEC) as u64, mode: mode as u64, resolve: libc::RESOLVE_IN_ROOT };
                openat2(rootfd, &rel, &how)
            }
            Err(e) => Err(e),
        };
        close_fd(rootfd);
        result
    }

    /// Open a Unix connect's target `O_PATH`, the way the tracee's own
    /// connect would resolve it (`plan_unix_lookup`): under its root with
    /// `RESOLVE_IN_ROOT`, a relative path joined to its cwd, and
    /// `/proc/self/fd/N` as its own descriptor N. Err = the errno for the
    /// tracee; ENOSYS = openat2 is missing (the caller falls back or refuses).
    pub fn open_unix_target(pid: i32, path: &[u8]) -> Result<RawFd, i32> {
        use std::os::unix::ffi::OsStrExt;
        let cwd = if path.first() == Some(&b'/') {
            None
        } else {
            Some(std::fs::read_link(format!("/proc/{pid}/cwd")).map_err(errno_of)?)
        };
        match plan_unix_lookup(path, cwd.as_ref().map(|c| c.as_os_str().as_bytes()))? {
            UnixLookup::TraceeFd(n) => {
                let p = std::ffi::CString::new(format!("/proc/{pid}/fd/{n}")).map_err(|_| libc::ENOENT)?;
                // SAFETY: open with a NUL-terminated path; returns an fd or -1.
                let fd = unsafe { libc::open(p.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                if fd < 0 { Err(errno_of(Error::last_os_error())) } else { Ok(fd) }
            }
            UnixLookup::InRoot(abs) => open_in_root(pid, &abs, libc::O_PATH, 0),
        }
    }

    /// Read a NUL-terminated path the tracee's syscall points at, byte-exact
    /// (a lossy decoding would open another file). The errno its own call
    /// would meet: EFAULT for memory it cannot read, ENAMETOOLONG past
    /// PATH_MAX.
    pub fn read_path_bytes(pid: i32, addr: u64) -> Result<Vec<u8>, i32> {
        const PATH_MAX: usize = 4096;
        if addr == 0 {
            return Err(libc::EFAULT);
        }
        let mut buf = vec![0u8; PATH_MAX];
        let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
        let remote = libc::iovec { iov_base: addr as *mut libc::c_void, iov_len: buf.len() };
        // SAFETY: reads at most PATH_MAX bytes into our buffer.
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n <= 0 {
            return Err(libc::EFAULT);
        }
        let n = n as usize;
        match buf[..n].iter().position(|b| *b == 0) {
            Some(end) => {
                buf.truncate(end);
                Ok(buf)
            }
            None if n == PATH_MAX => Err(libc::ENAMETOOLONG),
            None => Err(libc::EFAULT),
        }
    }

    /// A small procfs file in ONE `read` (procfs reports size 0, and a
    /// growing buffer re-generates the whole text on every read call: a
    /// `status` read that way cost ~25 syscalls). Up to 8 KiB.
    pub fn read_proc_small(path: &str) -> Option<String> {
        let c = std::ffi::CString::new(path).ok()?;
        // SAFETY: open/read/close on our own buffer.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        let mut buf = vec![0u8; 8192];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        close_fd(fd);
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        String::from_utf8(buf).ok()
    }

    /// A field of a `/proc/<tid>/status` text, its whitespace-separated values.
    pub fn status_values<'a>(status: &'a str, name: &str) -> Option<Vec<&'a str>> {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(':')))
            .map(|r| r.split_whitespace().collect())
    }

    /// The tracee's umask (`Umask:`, octal).
    pub fn tracee_umask(tid: i32) -> Option<u32> {
        let status = read_proc_small(&format!("/proc/{tid}/status"))?;
        status_values(&status, "Umask").and_then(|v| u32::from_str_radix(v.first()?, 8).ok())
    }

    /// `(host tgid, tgid and tid in the tracee's own pid namespace)`.
    fn tracee_ids(tid: i32) -> Option<(i32, i32, i32)> {
        let status = read_proc_small(&format!("/proc/{tid}/status"))?;
        let tgid: i32 = status_values(&status, "Tgid")?.first()?.parse().ok()?;
        let ns_tgid: i32 = status_values(&status, "NStgid").and_then(|v| v.last()?.parse().ok()).unwrap_or(tgid);
        let ns_tid: i32 = status_values(&status, "NSpid").and_then(|v| v.last()?.parse().ok()).unwrap_or(tid);
        Some((tgid, ns_tgid, ns_tid))
    }

    /// The tracee's `(tgid, tid)` at each pid-namespace level, outermost
    /// (this supervisor's procfs) first. One level: it shares our namespace.
    pub fn tracee_levels(tid: i32) -> Option<Vec<(i32, i32)>> {
        let status = read_proc_small(&format!("/proc/{tid}/status"))?;
        let nums = |name: &str| -> Option<Vec<i32>> { status_values(&status, name)?.iter().map(|v| v.parse().ok()).collect() };
        let levels = super::ns_levels(&nums("NStgid")?, &nums("NSpid")?);
        (!levels.is_empty()).then_some(levels)
    }

    /// The tracee lives in a pid namespace below ours: a procfs `self` our
    /// own walk meets there names nobody.
    fn in_foreign_pid_ns(tid: i32) -> bool {
        tracee_levels(tid).map(|l| l.len() > 1).unwrap_or(false)
    }

    /// A small file beneath `dir`, read in one call (no symlink followed).
    fn read_small_at(dir: RawFd, rel: &str) -> Option<String> {
        let how = OpenHow { flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64, mode: 0, resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS };
        let fd = openat2(dir, &cpath(rel.as_bytes()).ok()?, &how).ok()?;
        let mut buf = vec![0u8; 4096];
        // SAFETY: read into our own buffer.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        close_fd(fd);
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        String::from_utf8(buf).ok()
    }

    /// Where the tracee's procfs is, for one of its own entries: a path in
    /// its view (`/proc`, or where a walk found it), or a descriptor of the
    /// procfs root it opened relative to.
    #[derive(Clone, Copy)]
    enum ProcAt<'a> {
        Path(&'a [u8]),
        Fd(RawFd),
    }

    /// A descriptor that is the root of a procfs mount.
    fn is_proc_root(fd: RawFd) -> bool {
        // SAFETY: fstat / fstatfs into zeroed buffers.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::fstat(fd, &mut st) == 0 && libc::fstatfs(fd, &mut sfs) == 0 };
        ok && sfs.f_type == libc::PROC_SUPER_MAGIC && st.st_ino == 1
    }

    /// The tracee's own directory beneath the procfs root `procfd`
    /// (`<tgid>`, or `<tgid>/task/<tid>` for its thread): the numbers of the
    /// pid namespace that procfs belongs to (`pick_level`).
    fn own_entry_in(procfd: RawFd, tid: i32, thread: bool) -> Result<String, i32> {
        let levels = tracee_levels(tid).ok_or(libc::ESRCH)?;
        let (g, t) = if levels.len() == 1 {
            levels[0]
        } else {
            let want = read_proc_small(&format!("/proc/{}/stat", levels[0].0)).as_deref().and_then(stat_starttime).ok_or(libc::ESRCH)?;
            pick_level(&levels, want, |g| read_small_at(procfd, &format!("{g}/stat")).as_deref().and_then(stat_starttime)).ok_or(libc::ENOENT)?
        };
        Ok(if thread { format!("{g}/task/{t}") } else { format!("{g}") })
    }

    /// Open `rest` of the tracee's own procfs entry (`OpenPlan::OwnProc`)
    /// in the procfs `at` names, directly (see `open_as_tracee_via`).
    #[allow(clippy::too_many_arguments)]
    fn open_own_entry(tid: i32, at: ProcAt, thread: bool, rest: &[u8], flags: i32, mode: u32, extra: u64, valid: &dyn Fn() -> bool) -> Result<RawFd, i32> {
        let procfd = match at {
            ProcAt::Fd(fd) => {
                // SAFETY: a duplicate we own and close below.
                let d = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
                if d < 0 {
                    return Err(errno_of(Error::last_os_error()));
                }
                d
            }
            ProcAt::Path(p) => {
                let root = tracee_root(tid)?;
                let rel = p.iter().position(|b| *b != b'/').map(|i| &p[i..]).unwrap_or(b".");
                let how = OpenHow { flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64, mode: 0, resolve: libc::RESOLVE_IN_ROOT };
                let r = cpath(rel).and_then(|c| openat2(root, &c, &how));
                close_fd(root);
                r?
            }
        };
        if !valid() {
            close_fd(procfd);
            return Err(libc::ESRCH);
        }
        let r = own_entry_in(procfd, tid, thread).and_then(|dir| {
            let mut rel = dir.into_bytes();
            if !rest.is_empty() {
                rel.push(b'/');
                rel.extend_from_slice(rest);
            }
            open_from(procfd, &rel, flags, mode, libc::RESOLVE_BENEATH | extra, tid, Finish::Direct)
        });
        close_fd(procfd);
        r
    }

    /// One step of `walk_to_proc_self`: what `abs` is under the tracee's
    /// root, its last component not followed.
    fn look_in_root(root: RawFd, abs: &[u8], parent_is_proc_root: bool) -> Result<WalkNode, i32> {
        let rel = abs.iter().position(|b| *b != b'/').map(|i| &abs[i..]).unwrap_or(b".");
        let how = OpenHow { flags: (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64, mode: 0, resolve: libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_SYMLINKS };
        let fd = openat2(root, &cpath(rel)?, &how)?;
        // SAFETY: fstat / fstatfs into zeroed buffers.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::fstat(fd, &mut st) } == 0 && unsafe { libc::fstatfs(fd, &mut sfs) } == 0;
        if !ok {
            close_fd(fd);
            return Err(libc::EIO);
        }
        let procfs = sfs.f_type == libc::PROC_SUPER_MAGIC;
        let node = match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR if procfs && st.st_ino == 1 => Ok(WalkNode::ProcRoot),
            libc::S_IFLNK if procfs && !parent_is_proc_root => Ok(WalkNode::Magic),
            libc::S_IFLNK => {
                let mut buf = vec![0u8; 4096];
                // SAFETY: readlinkat on an O_PATH|O_NOFOLLOW link, empty path.
                let n = unsafe { libc::readlinkat(fd, b"\0".as_ptr() as *const libc::c_char, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
                if n < 0 {
                    Err(errno_of(Error::last_os_error()))
                } else {
                    buf.truncate(n as usize);
                    Ok(WalkNode::Link(buf))
                }
            }
            _ => Ok(WalkNode::Plain),
        };
        close_fd(fd);
        node
    }

    /// An open under the tracee's root answered ENOENT, and the tracee lives
    /// in a pid namespace below ours: did the walk go through a symlink into
    /// a procfs `self` (which names nobody for us)? Some: where. A path with
    /// no symlink and no `self` at all is settled in one call
    /// (`RESOLVE_NO_SYMLINKS` answers ENOENT again).
    fn self_through_links(tid: i32, abs: &[u8], nofollow_last: bool) -> Option<ProcSelf> {
        let root = tracee_root(tid).ok()?;
        let rel = abs.iter().position(|b| *b != b'/').map(|i| &abs[i..]).unwrap_or(b".");
        let probe = OpenHow { flags: (libc::O_PATH | libc::O_CLOEXEC) as u64, mode: 0, resolve: libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_SYMLINKS };
        let linked = match cpath(rel).and_then(|c| openat2(root, &c, &probe)) {
            Err(libc::ELOOP) => true,
            Ok(fd) => {
                close_fd(fd);
                false
            }
            Err(_) => false,
        };
        let found = if linked {
            walk_to_proc_self(abs, nofollow_last, |p, parent_root| look_in_root(root, p, parent_root)).ok().flatten()
        } else {
            None
        };
        close_fd(root);
        found
    }

    /// `tty_nr` of `/proc/<tid>/stat` (field 7).
    fn tracee_tty_nr(tid: i32) -> Option<u64> {
        let stat = read_proc_small(&format!("/proc/{tid}/stat"))?;
        let after = &stat[stat.rfind(')')? + 1..];
        after.split_whitespace().nth(4)?.parse::<i64>().ok().map(|v| v as u64)
    }

    /// A `/proc/<tid>/…` link's target, byte-exact.
    fn proc_link(tid: i32, suffix: &str) -> Result<Vec<u8>, i32> {
        use std::os::unix::ffi::OsStrExt;
        std::fs::read_link(format!("/proc/{tid}/{suffix}")).map(|p| p.as_os_str().as_bytes().to_vec()).map_err(errno_of)
    }

    /// `/proc/<tid>/root`, `O_PATH`.
    fn tracee_root(tid: i32) -> Result<RawFd, i32> {
        let root = std::ffi::CString::new(format!("/proc/{tid}/root")).map_err(|_| libc::ENOENT)?;
        // SAFETY: open with a NUL-terminated path; returns an fd or -1.
        let fd = unsafe { libc::open(root.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if fd < 0 { Err(errno_of(Error::last_os_error())) } else { Ok(fd) }
    }

    fn cpath(b: &[u8]) -> Result<std::ffi::CString, i32> {
        std::ffi::CString::new(b).map_err(|_| libc::ENOENT)
    }

    /// Our own `(pid, is one of our threads?)` test for a procfs number.
    fn is_ours(n: i32) -> bool {
        // SAFETY: getpid has no failure mode.
        let me = unsafe { libc::getpid() };
        n == me || std::path::Path::new(&format!("/proc/{me}/task/{n}")).exists()
    }

    /// A procfs `self` (or `thread-self`) that the walk met names the OPENER:
    /// a path that reached it through a symlink (`/etc/mtab ->
    /// ../proc/self/mounts`, procfs's own `mounts` and `net`) or relative to a
    /// procfs descriptor (bwrap's `self/mountinfo`) lands in this
    /// supervisor's own entry. Such a file is never handed over: the same
    /// entry of the TRACEE (its process, or its thread) is opened instead,
    /// which is what its own walk would have named.
    ///
    /// A path that NAMES the supervisor's pid itself (`/proc/<guard>/stat`,
    /// read by a tool walking its parents up to init) is not a `self` the
    /// walk met: it is left alone, and the caller reopens it as the tracee
    /// (context_helper), which is what the tracee's own open would give.
    /// Remapping it answered the tracee's OWN entry instead, so a parent walk
    /// never got past the guard (sandbox-security-review follow-up, 2026-09-28).
    fn remap_own_procfs(fd: RawFd, flags: i32, tid: i32, named: &[u8]) -> Result<Opened, i32> {
        let plain = Opened { fd, own_proc: false };
        // A file on a block device is never on procfs (`may_be_pseudo_fs`):
        // one `fstat` instead of an `fstatfs` for most opens.
        // SAFETY: fstat into a zeroed buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } == 0 && !super::may_be_pseudo_fs(st.st_dev) {
            return Ok(plain);
        }
        // SAFETY: fstatfs into a zeroed buffer.
        let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(fd, &mut sfs) } != 0 || sfs.f_type != libc::PROC_SUPER_MAGIC {
            return Ok(plain);
        }
        let own = |fd: RawFd| -> Result<Option<(bool, String)>, i32> {
            let seen = std::fs::read_link(format!("/proc/self/fd/{fd}")).map_err(|_| libc::EACCES)?;
            let seen = seen.to_string_lossy().into_owned();
            let comps: Vec<&str> = seen.trim_start_matches('/').split('/').collect();
            if comps.first() != Some(&"proc") {
                return Ok(None);
            }
            let Some(n) = comps.get(1).and_then(|n| n.parse::<i32>().ok()) else { return Ok(None) };
            if !is_ours(n) || super::path_names_pid(named, n) {
                return Ok(None);
            }
            // /proc/<us>/task/<our tid>/rest is thread-self; /proc/<us>/rest is self.
            if comps.get(2) == Some(&"task") && comps.get(3).and_then(|t| t.parse::<i32>().ok()).map(is_ours).unwrap_or(false) {
                return Ok(Some((true, comps[4..].join("/"))));
            }
            Ok(Some((false, comps[2..].join("/"))))
        };
        let Some((thread, rest)) = own(fd).map_err(|e| {
            close_fd(fd);
            e
        })?
        else {
            return Ok(plain);
        };
        close_fd(fd);
        let (tgid, _, _) = tracee_ids(tid).ok_or(libc::ESRCH)?;
        let mut path = if thread { format!("/proc/{tgid}/task/{tid}") } else { format!("/proc/{tgid}") };
        if !rest.is_empty() {
            path.push('/');
            path.push_str(&rest);
        }
        let flags = (flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC)) | libc::O_NOCTTY | libc::O_CLOEXEC;
        let c = cpath(path.as_bytes())?;
        // SAFETY: open with a NUL-terminated path; returns an fd or -1.
        let fd = unsafe { libc::open(c.as_ptr(), flags) };
        if fd < 0 { Err(errno_of(Error::last_os_error())) } else { Ok(Opened { fd, own_proc: true }) }
    }

    /// What `open_as_tracee` opened: this supervisor's descriptor, and
    /// whether it is one of the tracee's OWN procfs entries (named for it by
    /// number, or re-opened as its own after a walk met `self`), which is
    /// the tracee's to open whatever its credentials.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Opened {
        pub fd: RawFd,
        pub own_proc: bool,
    }

    /// The last step of an open, when another thread must take it (a
    /// Landlock mirror, confidentiality-plan-10 §4.1a): the path is already
    /// resolved, `O_PATH`, by the caller's thread; only the access remains.
    pub enum Final {
        /// Reopen this `O_PATH` descriptor with these flags (`reopen`).
        Reopen { fd: RawFd, flags: i32 },
        /// Create `name` in this directory (`O_CREAT`), or an unnamed file
        /// in it (`O_TMPFILE`, `name` = `.`).
        Create { dir: RawFd, name: Vec<u8>, flags: i32, mode: u32, resolve: u64 },
    }

    /// Where the last step of an open runs.
    #[derive(Clone, Copy)]
    pub enum Finish<'a> {
        /// Here, in one step with the resolution.
        Direct,
        /// On the given executor, after an `O_PATH` resolution here.
        Via(&'a dyn Fn(Final) -> Result<RawFd, i32>),
    }

    /// Run a `Final` step on the calling thread.
    pub fn run_final(step: Final) -> Result<RawFd, i32> {
        match step {
            Final::Reopen { fd, flags } => reopen(fd, flags),
            Final::Create { dir, name, flags, mode, resolve } => {
                let how = OpenHow { flags: super::performed_open_flags(flags) as u64, mode: mode as u64, resolve };
                openat2(dir, &cpath(&name)?, &how)
            }
        }
    }

    /// The split form of `open_from` (`Finish::Via`): resolve `O_PATH` here,
    /// hand the access to `f`.
    fn open_via(dirfd: RawFd, rel: &[u8], flags: i32, mode: u32, resolve: u64, tid: i32, f: &dyn Fn(Final) -> Result<RawFd, i32>) -> Result<RawFd, i32> {
        let rel: &[u8] = if rel.is_empty() { b"." } else { rel };
        let path_how = |extra: i32| OpenHow { flags: (libc::O_PATH | libc::O_CLOEXEC | extra) as u64, mode: 0, resolve };
        if flags & libc::O_TMPFILE == libc::O_TMPFILE {
            let dir = openat2(dirfd, &cpath(rel)?, &path_how(libc::O_DIRECTORY))?;
            let r = f(Final::Create { dir, name: b".".to_vec(), flags, mode, resolve: 0 });
            close_fd(dir);
            return r;
        }
        if flags & libc::O_CREAT != 0 {
            let (parent, name): (&[u8], &[u8]) = match rel.iter().rposition(|b| *b == b'/') {
                Some(i) => (&rel[..i.max(1)], &rel[i + 1..]),
                None => (b".", rel),
            };
            if name.is_empty() || name == b"." || name == b".." {
                return Err(libc::EISDIR);
            }
            let parent: &[u8] = if parent.is_empty() { b"." } else { parent };
            let dir = openat2(dirfd, &cpath(parent)?, &path_how(libc::O_DIRECTORY))?;
            let step_resolve = libc::RESOLVE_BENEATH | (resolve & (libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV));
            let r = f(Final::Create { dir, name: name.to_vec(), flags, mode, resolve: step_resolve });
            close_fd(dir);
            return r;
        }
        let opath = openat2(dirfd, &cpath(rel)?, &path_how(flags & (libc::O_NOFOLLOW | libc::O_DIRECTORY)))?;
        // /dev/tty is the TRACEE's controlling terminal (an `O_PATH` open
        // names the node itself, as the tracee's own would).
        // SAFETY: fstat into a zeroed stat buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let ok = flags & libc::O_PATH == 0 && unsafe { libc::fstat(opath, &mut st) } == 0;
        let target = if ok && st.st_mode & libc::S_IFMT == libc::S_IFCHR && st.st_rdev == libc::makedev(5, 0) {
            close_fd(opath);
            let node = tracee_tty_nr(tid).and_then(ctty_node).ok_or(libc::ENXIO)?;
            let rel = node.strip_prefix(b"/").unwrap_or(&node).to_vec();
            let root = tracee_root(tid)?;
            let how = OpenHow { flags: (libc::O_PATH | libc::O_CLOEXEC) as u64, mode: 0, resolve: libc::RESOLVE_IN_ROOT };
            let r = openat2(root, &cpath(&rel)?, &how);
            close_fd(root);
            r?
        } else {
            opath
        };
        let r = f(Final::Reopen { fd: target, flags });
        close_fd(target);
        r
    }

    /// Open `rel` beneath `dirfd` the way the tracee would, in one step (a
    /// creating open's mode already masked by its umask). The supervisor
    /// never takes a terminal as its own (`O_NOCTTY`), and `/dev/tty` means
    /// the TRACEE's controlling terminal: an open that turned out to be it
    /// (its inode is 5:0) is redone on the tracee's own terminal, and one
    /// that failed ENXIO (this supervisor has none) is looked at `O_PATH`.
    fn open_from(dirfd: RawFd, rel: &[u8], flags: i32, mode: u32, resolve: u64, tid: i32, finish: Finish) -> Result<RawFd, i32> {
        if let Finish::Via(f) = finish {
            return open_via(dirfd, rel, flags, mode, resolve, tid, f);
        }
        let rel: &[u8] = if rel.is_empty() { b"." } else { rel };
        let c = cpath(rel)?;
        // `O_NOCTTY` only without `O_PATH` (`performed_open_flags`): openat2
        // refuses the pair (EINVAL), and an `O_PATH` open of `/dev/tty`
        // names the node itself, as the tracee's own would (no redirect).
        let how = OpenHow { flags: super::performed_open_flags(flags) as u64, mode: mode as u64, resolve };
        let is_dev_tty = |fd: RawFd| {
            if flags & libc::O_PATH != 0 {
                return false;
            }
            // SAFETY: fstat into a zeroed stat buffer.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let ok = unsafe { libc::fstat(fd, &mut st) } == 0;
            ok && st.st_mode & libc::S_IFMT == libc::S_IFCHR && st.st_rdev == libc::makedev(5, 0)
        };
        let dev_tty = match openat2(dirfd, &c, &how) {
            Ok(fd) if !is_dev_tty(fd) => return Ok(fd),
            Ok(fd) => {
                close_fd(fd);
                true
            }
            Err(libc::ENXIO) if !super::open_creates(flags) => {
                let probe = OpenHow { flags: (libc::O_PATH | libc::O_CLOEXEC | (flags & (libc::O_NOFOLLOW | libc::O_DIRECTORY))) as u64, mode: 0, resolve };
                let Ok(opath) = openat2(dirfd, &c, &probe) else { return Err(libc::ENXIO) };
                let t = is_dev_tty(opath);
                close_fd(opath);
                if !t {
                    return Err(libc::ENXIO);
                }
                true
            }
            Err(e) => return Err(e),
        };
        debug_assert!(dev_tty);
        let node = tracee_tty_nr(tid).and_then(ctty_node).ok_or(libc::ENXIO)?;
        let rel = node.strip_prefix(b"/").unwrap_or(&node);
        let how = OpenHow { flags: ((flags & !(libc::O_CLOEXEC | libc::O_CREAT | libc::O_EXCL)) | libc::O_NOCTTY | libc::O_CLOEXEC) as u64, mode: 0, resolve: libc::RESOLVE_IN_ROOT };
        let root = tracee_root(tid)?;
        let r = openat2(root, &cpath(rel)?, &how);
        close_fd(root);
        r
    }

    /// Reopen a descriptor (the target of a procfs magic link) with the
    /// tracee's flags: the file it names, with no path resolution.
    fn reopen(opath: RawFd, flags: i32) -> Result<RawFd, i32> {
        let flags = (flags & !(libc::O_NOFOLLOW | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC)) | libc::O_NOCTTY | libc::O_CLOEXEC;
        let p = cpath(format!("/proc/self/fd/{opath}").as_bytes())?;
        // SAFETY: open with a NUL-terminated path; returns an fd or -1.
        let fd = unsafe { libc::open(p.as_ptr(), flags) };
        if fd < 0 { Err(errno_of(Error::last_os_error())) } else { Ok(fd) }
    }

    /// Perform the tracee's open (`open`/`openat`/`openat2` with this
    /// `dirfd`, `path`, `flags`, `mode` and openat2 `resolve`) in the
    /// tracee's own view, and return this supervisor's descriptor of what it
    /// opened: the caller checks that file's identity and injects it
    /// (`ADDFD`). The path is resolved ONCE; the kernel never resolves it
    /// again. Err = the errno for the tracee. `valid`: is the notification
    /// still pending (checked after every lookup through `/proc/<tid>`, so a
    /// reused pid is never acted on).
    pub fn open_as_tracee(tid: i32, dirfd: i32, path: &[u8], flags: i32, mode: u32, resolve: u64, valid: &dyn Fn() -> bool) -> Result<Opened, i32> {
        open_as_tracee_via(tid, dirfd, path, flags, mode, resolve, valid, Finish::Direct)
    }

    /// `open_as_tracee` with the last step (the access to the file) taken by
    /// `finish` (a thread that carries the tracee's Landlock domain). The
    /// tracee's OWN procfs entries are opened directly: Landlock never
    /// restricts a task's access to itself, and a mirror, a sibling domain,
    /// would be refused there.
    #[allow(clippy::too_many_arguments)]
    pub fn open_as_tracee_via(tid: i32, dirfd: i32, path: &[u8], flags: i32, mode: u32, resolve: u64, valid: &dyn Fn() -> bool, finish: Finish) -> Result<Opened, i32> {
        let creating = super::open_creates(flags);
        let mode = if creating { super::performed_open_mode(flags, mode, tracee_umask(tid)) } else { 0 };
        let result = (|| {
            // openat2 with RESOLVE_BENEATH / RESOLVE_IN_ROOT: the tracee's own
            // descriptor (or cwd) is the root of the walk; nothing leaves it.
            if resolve & (libc::RESOLVE_BENEATH | libc::RESOLVE_IN_ROOT) != 0 {
                let base = if dirfd == libc::AT_FDCWD {
                    let c = cpath(format!("/proc/{tid}/cwd").as_bytes())?;
                    // SAFETY: open with a NUL-terminated path.
                    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
                    if fd < 0 { return Err(errno_of(Error::last_os_error())) }
                    fd
                } else {
                    tracee_fd(tid, dirfd).map_err(errno_of)?
                };
                if !valid() {
                    close_fd(base);
                    return Err(libc::ESRCH);
                }
                let r = open_from(base, path, flags, mode, resolve, tid, finish);
                close_fd(base);
                return r.and_then(|fd| remap_own_procfs(fd, flags, tid, path));
            }
            let extra = resolve & (libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV | libc::RESOLVE_CACHED);
            // A relative path: walk from the tracee's own directory (its cwd or
            // dirfd, through its magic link), as the kernel would. Anything that
            // would leave that directory (`..` above it, an absolute symlink, a
            // magic link) or lands in this supervisor's own procfs entry takes
            // the root-based plan below instead.
            if path.first() != Some(&b'/') && !path.is_empty() {
                let link = if dirfd == libc::AT_FDCWD { format!("/proc/{tid}/cwd") } else { format!("/proc/{tid}/fd/{dirfd}") };
                let c = cpath(link.as_bytes())?;
                // SAFETY: open with a NUL-terminated path (a magic link, followed).
                let base = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
                if base < 0 {
                    let e = errno_of(Error::last_os_error());
                    return Err(if dirfd != libc::AT_FDCWD && e == libc::ENOENT { libc::EBADF } else { e });
                }
                if !valid() {
                    close_fd(base);
                    return Err(libc::ESRCH);
                }
                let fast = open_from(base, path, flags, mode, libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | extra, tid, finish);
                // A procfs `self` met from outside the tracee's pid namespace
                // names nobody (ENOENT). Relative to a procfs root it opened
                // (bwrap's `self/mountinfo` after its pivot_root, where no
                // path to that procfs is left in its view): the tracee's own
                // entry beneath that very descriptor. Otherwise the
                // root-based plan below names it by number.
                let foreign = matches!(fast, Err(libc::ENOENT)) && in_foreign_pid_ns(tid);
                if foreign && is_proc_root(base) {
                    let first = path.split(|b| *b == b'/').next().unwrap_or(b"");
                    if first == b"self" || first == b"thread-self" {
                        let mut spelled = b"/proc/".to_vec();
                        spelled.extend_from_slice(path);
                        if let Ok(OpenPlan::OwnProc { thread, rest }) = plan_open(&spelled, None) {
                            let own = !matches!(rest.as_slice(), b"uid_map" | b"gid_map" | b"setgroups" | b"projid_map");
                            let r = open_own_entry(tid, ProcAt::Fd(base), thread, &rest, flags, mode, extra, valid);
                            close_fd(base);
                            return r.map(|fd| Opened { fd, own_proc: own });
                        }
                    }
                }
                close_fd(base);
                match fast {
                    Ok(fd) => return remap_own_procfs(fd, flags, tid, path),
                    Err(libc::EXDEV) | Err(libc::ELOOP) => {}
                    Err(libc::ENOENT) if foreign => {}
                    Err(e) => return Err(e),
                }
            }
            let base = if path.first() == Some(&b'/') {
                None
            } else if dirfd == libc::AT_FDCWD {
                Some(proc_link(tid, "cwd")?)
            } else {
                let b = proc_link(tid, &format!("fd/{dirfd}")).map_err(|_| libc::EBADF)?;
                if b.first() != Some(&b'/') {
                    return Err(libc::ENOTDIR);
                }
                Some(b)
            };
            let in_root = |abs: &[u8], finish: Finish| {
                let rel = abs.iter().position(|b| *b != b'/').map(|i| &abs[i..]).unwrap_or(b"");
                let root = tracee_root(tid)?;
                if !valid() {
                    close_fd(root);
                    return Err(libc::ESRCH);
                }
                let r = open_from(root, rel, flags, mode, libc::RESOLVE_IN_ROOT | extra, tid, finish);
                close_fd(root);
                r
            };
            // `at`: where the tracee's procfs is (an own entry's plan is
            // spelled `/proc/self`; a walk may have found it elsewhere).
            let run = |plan: OpenPlan, at: ProcAt| -> Result<(RawFd, bool), i32> {
                Ok(match plan {
                OpenPlan::InRoot(abs) => (in_root(&abs, finish)?, false),
                OpenPlan::OwnProc { thread, rest } => {
                    // Its id maps are judged by the OPENER's user namespace,
                    // its own entries or not: not the tracee's to open freely.
                    let own = !matches!(rest.as_slice(), b"uid_map" | b"gid_map" | b"setgroups" | b"projid_map");
                    // Numbered as that procfs numbers it (the tracee's pid
                    // namespace, or an outer one's before a sandbox mounts
                    // its own procfs); its own entries directly (see the fn doc).
                    (open_own_entry(tid, at, thread, &rest, flags, mode, extra, &valid)?, own)
                }
                OpenPlan::OwnMagic { thread, hop, tail } => {
                    // The link's TARGET is judged like any file; only an
                    // empty tail on a procfs target stays the tracee's own.
                    let (tgid, _, _) = tracee_ids(tid).ok_or(libc::ESRCH)?;
                    let dir = if thread { format!("/proc/{tgid}/task/{tid}/") } else { format!("/proc/{tgid}/") };
                    let mut p = dir.into_bytes();
                    p.extend_from_slice(&hop);
                    let c = cpath(&p)?;
                    // SAFETY: open with a NUL-terminated path (a magic link, followed).
                    let hopfd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                    if hopfd < 0 {
                        return Err(errno_of(Error::last_os_error()));
                    }
                    if !valid() {
                        close_fd(hopfd);
                        return Err(libc::ESRCH);
                    }
                    let r = if tail.is_empty() {
                        if creating && flags & libc::O_EXCL != 0 {
                            Err(libc::EEXIST)
                        } else {
                            match finish {
                                Finish::Direct => reopen(hopfd, flags),
                                Finish::Via(f) => f(Final::Reopen { fd: hopfd, flags }),
                            }
                        }
                    } else {
                        // Beneath the link's target only: a `..` or an absolute
                        // symlink out of it is refused (the kernel would follow
                        // it; rare, and never wider).
                        open_from(hopfd, &tail, flags, mode, libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | extra, tid, finish)
                    };
                    close_fd(hopfd);
                    (r?, false)
                }
                })
            };
            let plan = plan_open(path, base.as_deref())?;
            let retry = match &plan {
                OpenPlan::InRoot(abs) => Some(abs.clone()),
                _ => None,
            };
            let (fd, own_proc) = match run(plan, ProcAt::Path(b"/proc")) {
                // Not there for US: a symlink led into a procfs `self`, which
                // names nobody from outside the tracee's pid namespace. The
                // same walk by text names the tracee's own entry.
                Err(libc::ENOENT) if retry.is_some() && in_foreign_pid_ns(tid) => {
                    let abs = retry.unwrap_or_default();
                    let Some(at) = self_through_links(tid, &abs, flags & libc::O_NOFOLLOW != 0) else { return Err(libc::ENOENT) };
                    match plan_open(&at.as_proc(), None) {
                        Ok(own @ (OpenPlan::OwnProc { .. } | OpenPlan::OwnMagic { .. })) => run(own, ProcAt::Path(&at.proc_root))?,
                        _ => return Err(libc::ENOENT),
                    }
                }
                r => r?,
            };
            remap_own_procfs(fd, flags, tid, path).map(|r| Opened { fd: r.fd, own_proc: own_proc || r.own_proc })
        })();
        result
    }

    /// `(st_dev, st_ino)` of an open descriptor.
    pub fn fd_identity(fd: RawFd) -> Option<(u64, u64)> {
        // SAFETY: fstat into a zeroed stat buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev, st.st_ino))
    }

    /// A pathname `sockaddr_un` (family + path + NUL) as connect(2) bytes.
    pub fn sockaddr_un_bytes(path: &str) -> Vec<u8> {
        let mut b = (libc::AF_UNIX as u16).to_ne_bytes().to_vec();
        b.extend_from_slice(path.as_bytes());
        b.push(0);
        b
    }
}


/// Does the path a tracee passed name process `pid` by number (a component
/// equal to its decimal id)? Pure.
pub fn path_names_pid(path: &[u8], pid: i32) -> bool {
    let want = pid.to_string();
    path.split(|b| *b == b'/').any(|c| c == want.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// glibc's `makedev`, to build the numbers the kernel reports.
    fn makedev(major: u64, minor: u64) -> u64 {
        ((major & 0xffff_f000) << 32) | ((major & 0xfff) << 8) | ((minor & 0xffff_ff00) << 12) | (minor & 0xff)
    }

    /// runtime-instances.md §14.9: the major is decoded as glibc does, a
    /// large major's high bits included; only major 0 (the anonymous
    /// devices every pseudo filesystem is numbered from) may be one.
    #[test]
    fn only_an_anonymous_device_may_be_a_pseudo_filesystem() {
        for (major, minor) in [(8, 1), (259, 3), (253, 0), (7, 12), (4097, 70000), (0x000f_ffff, 0)] {
            let dev = makedev(major, minor);
            assert_eq!(dev_major(dev), major, "{major}:{minor}");
            assert!(!may_be_pseudo_fs(dev), "{major}:{minor} is a block device's");
        }
        for minor in [0, 22, 45, 255, 256, 1 << 19] {
            let dev = makedev(0, minor);
            assert_eq!(dev_major(dev), 0, "0:{minor}");
            assert!(may_be_pseudo_fs(dev), "0:{minor} may be procfs, sysfs, tmpfs, …");
        }
    }

    /// The same over the real file systems: every pseudo filesystem this
    /// host mounts (procfs, sysfs, a cgroup hierarchy, devtmpfs) has major
    /// 0, so the shortcut never skips one. Unprivileged.
    #[cfg(all(feature = "kernel", target_os = "linux"))]
    #[test]
    fn every_pseudo_filesystem_here_has_an_anonymous_device() {
        use std::os::unix::fs::MetadataExt;
        for p in ["/proc/self/status", "/proc/meminfo", "/sys/kernel", "/sys/fs/cgroup", "/dev/null"] {
            let Ok(md) = std::fs::metadata(p) else { continue };
            assert!(may_be_pseudo_fs(md.dev()), "{p}: dev {:#x}", md.dev());
        }
    }

    /// A descriptor named by a WORKER thread's id is copied, on every kernel:
    /// the non-leader error of `pidfd_open` (EINVAL before 6.9, ENOENT on 7.0)
    /// is reached through the leader. On 7.0 the ENOENT form was refused, and
    /// the guard answered every allowed connect from Bun's worker threads with
    /// EACCES (2026-09-30). Unprivileged: the tracee is this test's own process.
    #[cfg(feature = "kernel")]
    #[test]
    fn tracee_fd_copies_a_worker_threads_descriptor() {
        use std::os::fd::AsRawFd;
        use std::sync::mpsc;
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let fd = sock.as_raw_fd();
        let (tid_tx, tid_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            // SAFETY: gettid has no arguments and cannot fail.
            tid_tx.send(unsafe { libc::syscall(libc::SYS_gettid) } as i32).unwrap();
            let _ = done_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        assert_ne!(tid, std::process::id() as i32, "the worker is not the leader");
        let copy = live::tracee_fd(tid, fd);
        let _ = done_tx.send(());
        worker.join().unwrap();
        let copy = copy.expect("a worker thread's descriptor is copied through its leader");
        assert_eq!(live::fd_identity(copy), live::fd_identity(fd), "the copy is the same socket");
        // SAFETY: closing the copy we own.
        unsafe { libc::close(copy) };
    }

    /// A little tree for `walk_to_proc_self`: `/proc` (a procfs root with
    /// `mounts -> self/mounts`, `net -> self/net` and a numbered dir whose
    /// `fd/3` is a magic link), `/etc/mtab -> ../proc/self/mounts`, `/lib ->
    /// usr/lib`, `/loop -> /loop`, and plain files.
    fn toy_fs(p: &[u8], parent_proc_root: bool) -> Result<WalkNode, i32> {
        let link = |t: &[u8]| Ok(WalkNode::Link(t.to_vec()));
        match p {
            b"/proc" => Ok(WalkNode::ProcRoot),
            b"/proc/mounts" => {
                assert!(parent_proc_root);
                link(b"self/mounts")
            }
            b"/proc/net" => link(b"self/net"),
            b"/proc/7" | b"/proc/7/fd" => Ok(WalkNode::Plain),
            b"/proc/7/fd/3" => {
                assert!(!parent_proc_root);
                Ok(WalkNode::Magic)
            }
            b"/etc" | b"/usr" | b"/usr/lib" | b"/usr/lib/libc.so" => Ok(WalkNode::Plain),
            b"/etc/mtab" => link(b"../proc/self/mounts"),
            b"/lib" => link(b"usr/lib"),
            b"/loop" => link(b"/loop"),
            b"/etc/abs" => link(b"/proc/thread-self/comm"),
            b"/oldroot" => Ok(WalkNode::Plain),
            b"/oldroot/proc" => Ok(WalkNode::ProcRoot),
            _ => Err(2),
        }
    }

    #[test]
    fn a_symlink_into_procfs_self_is_named_as_the_tracees_own() {
        // The kernel resolves procfs `self` for the opener: from outside the
        // tracee's pid namespace it names nobody, so the walk stops there and
        // says which procfs and what lies beneath `self`.
        let at = |root: &[u8], thread: bool, rest: &[u8]| Ok(Some(ProcSelf { proc_root: root.to_vec(), thread, rest: rest.to_vec() }));
        assert_eq!(walk_to_proc_self(b"/etc/mtab", false, toy_fs), at(b"/proc", false, b"mounts"));
        assert_eq!(walk_to_proc_self(b"/proc/mounts", false, toy_fs), at(b"/proc", false, b"mounts"));
        assert_eq!(walk_to_proc_self(b"/proc/net/tcp6", false, toy_fs), at(b"/proc", false, b"net/tcp6"));
        assert_eq!(walk_to_proc_self(b"/etc/abs", false, toy_fs), at(b"/proc", true, b"comm"), "an absolute target restarts at the root");
        assert_eq!(walk_to_proc_self(b"//proc/./self/status", false, toy_fs), at(b"/proc", false, b"status"));
        assert_eq!(walk_to_proc_self(b"/etc/../proc/self", false, toy_fs), at(b"/proc", false, b""));
        // A sandbox mid-setup (bwrap after pivot_root) reads its old root's
        // procfs: not at /proc.
        assert_eq!(walk_to_proc_self(b"/oldroot/proc/self/mountinfo", false, toy_fs), at(b"/oldroot/proc", false, b"mountinfo"));
        let got = walk_to_proc_self(b"/etc/mtab", false, toy_fs).unwrap().unwrap();
        assert_eq!(plan_open(&got.as_proc(), None), Ok(OpenPlan::OwnProc { thread: false, rest: b"mounts".to_vec() }));
        let fd = ProcSelf { proc_root: b"/oldroot/proc".to_vec(), thread: false, rest: b"fd/3".to_vec() };
        assert_eq!(plan_open(&fd.as_proc(), None), Ok(own(false, b"fd/3", b"")), "a magic link stays the tracee's descriptor");
    }

    #[test]
    fn a_walk_that_meets_no_procfs_self_changes_nothing() {
        assert_eq!(walk_to_proc_self(b"/lib/libc.so", false, toy_fs), Ok(None), "a symlink elsewhere: the first answer stands");
        assert_eq!(walk_to_proc_self(b"/lib/missing.so", false, toy_fs), Err(2), "a genuinely missing file");
        assert_eq!(walk_to_proc_self(b"/proc/7/fd/3/x", false, toy_fs), Ok(None), "a magic link's text is not a path");
        assert_eq!(walk_to_proc_self(b"/etc/mtab", true, toy_fs), Ok(None), "O_NOFOLLOW: the last link is not followed");
        assert_eq!(walk_to_proc_self(b"/usr/self", false, toy_fs), Err(2), "`self` only means itself in a procfs root");
        assert_eq!(walk_to_proc_self(b"/loop/x", false, toy_fs), Err(40), "a loop ends in ELOOP");
    }

    #[test]
    fn the_tracees_procfs_numbers_come_from_the_namespace_of_that_procfs() {
        // Guard's namespace 900, the wrap's 12, a nested box's 1.
        let levels = ns_levels(&[900, 12, 1], &[901, 12, 1]);
        assert_eq!(levels, vec![(900, 901), (12, 12), (1, 1)]);
        let start = 4242;
        // The box's own /proc: its pid 1 is the tracee.
        assert_eq!(pick_level(&levels, start, |g| (g == 1).then_some(start)), Some((1, 1)));
        // Before the box mounts its own /proc it still sees the wrap's, where
        // 1 is the wrap's first process (another start time): the wrap's 12.
        assert_eq!(pick_level(&levels, start, |g| match g { 1 => Some(77), 12 => Some(start), _ => None }), Some((12, 12)));
        assert_eq!(pick_level(&levels, start, |_| None), None, "no entry of the tracee's in that procfs");
        assert_eq!(pick_level(&[(5, 6)], start, |_| None), Some((5, 6)), "one level: ours, no check");
        let stat = "4242 (a (b) c) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10";
        assert_eq!(stat_starttime(stat), Some(987654));
    }

    #[test]
    fn a_path_names_a_pid_only_by_a_whole_component() {
        assert!(path_names_pid(b"/proc/4242/stat", 4242));
        assert!(path_names_pid(b"4242/comm", 4242), "relative to a procfs descriptor");
        assert!(path_names_pid(b"/proc/4242/task/4242/comm", 4242));
        assert!(!path_names_pid(b"/proc/self/stat", 4242), "self is the walk's, not a name");
        assert!(!path_names_pid(b"/etc/mtab", 4242));
        assert!(!path_names_pid(b"/proc/42424/stat", 4242), "a longer number");
        assert!(!path_names_pid(b"/tmp/x4242", 4242));
    }

    #[test]
    fn unix_lookups_resolve_in_the_tracees_view() {
        assert_eq!(plan_unix_lookup(b"/run/WSL/8_interop", None), Ok(UnixLookup::InRoot(b"/run/WSL/8_interop".to_vec())));
        // Relative: joined to the tracee's cwd; no lexical `..` folding (the
        // kernel walks it, under the tracee's root).
        assert_eq!(plan_unix_lookup(b"s.sock", Some(b"/home/u/p")), Ok(UnixLookup::InRoot(b"/home/u/p/s.sock".to_vec())));
        assert_eq!(plan_unix_lookup(b"../s", Some(b"/")), Ok(UnixLookup::InRoot(b"/../s".to_vec())));
        assert_eq!(plan_unix_lookup(b"s", None), Err(2), "no cwd: ENOENT");
        assert_eq!(plan_unix_lookup(b"s", Some(b"/gone (deleted)")), Err(2), "a deleted cwd: ENOENT");
        assert_eq!(plan_unix_lookup(b"", Some(b"/")), Err(2));
        // procfs `self` would name the supervisor: the tracee's own descriptor.
        assert_eq!(plan_unix_lookup(b"/proc/self/fd/7", None), Ok(UnixLookup::TraceeFd(7)));
        assert_eq!(plan_unix_lookup(b"/proc/thread-self/fd/12", None), Ok(UnixLookup::TraceeFd(12)));
        assert_eq!(plan_unix_lookup(b"/dev/fd/3", None), Ok(UnixLookup::TraceeFd(3)));
        assert_eq!(plan_unix_lookup(b"fd/3", Some(b"/proc/self")), Ok(UnixLookup::TraceeFd(3)));
        // Not exactly a descriptor: resolved in root (a magic link there is
        // ELOOP under RESOLVE_IN_ROOT, answered as is).
        assert_eq!(plan_unix_lookup(b"/proc/self/fd/7/x", None), Ok(UnixLookup::InRoot(b"/proc/self/fd/7/x".to_vec())));
        assert_eq!(plan_unix_lookup(b"/proc/self/cwd/s", None), Ok(UnixLookup::InRoot(b"/proc/self/cwd/s".to_vec())));
        // Non-UTF-8 bytes survive.
        assert_eq!(plan_unix_lookup(b"/tmp/\xff.sock", None), Ok(UnixLookup::InRoot(b"/tmp/\xff.sock".to_vec())));
    }

    fn own(thread: bool, hop: &[u8], tail: &[u8]) -> OpenPlan {
        OpenPlan::OwnMagic { thread, hop: hop.to_vec(), tail: tail.to_vec() }
    }

    #[test]
    fn an_open_is_planned_in_the_tracees_view() {
        let root = |p: &[u8]| OpenPlan::InRoot(p.to_vec());
        assert_eq!(plan_open(b"/etc/hostname", None), Ok(root(b"/etc/hostname")));
        assert_eq!(plan_open(b"notes.txt", Some(b"/home/u/p")), Ok(root(b"/home/u/p/notes.txt")));
        assert_eq!(plan_open(b"./a//b/./c", Some(b"/w/")), Ok(root(b"/w/a/b/c")), "// and . fold");
        assert_eq!(plan_open(b"../x", Some(b"/w/p")), Ok(root(b"/w/p/../x")), "`..` is the kernel's to walk (after symlinks)");
        assert_eq!(plan_open(b"dir/", Some(b"/w")), Ok(root(b"/w/dir/")), "a trailing slash asks for a directory");
        assert_eq!(plan_open(b"/", None), Ok(root(b"/")));
        assert_eq!(plan_open(b"", Some(b"/w")), Err(2));
        assert_eq!(plan_open(b"x", None), Err(2), "no cwd");
        assert_eq!(plan_open(b"x", Some(b"/gone (deleted)")), Err(2), "a deleted cwd");
        assert_eq!(plan_open(b"/tmp/\xff.bin", None), Ok(root(b"/tmp/\xff.bin")), "bytes survive");
    }

    #[test]
    fn the_tracees_own_procfs_is_named_by_number() {
        // `/proc/self` would name the supervisor: the tracee's own entries.
        assert_eq!(plan_open(b"/proc/self/status", None), Ok(OpenPlan::OwnProc { thread: false, rest: b"status".to_vec() }));
        assert_eq!(plan_open(b"/proc/self", None), Ok(OpenPlan::OwnProc { thread: false, rest: vec![] }));
        assert_eq!(plan_open(b"/proc//./self/maps", None), Ok(OpenPlan::OwnProc { thread: false, rest: b"maps".to_vec() }));
        assert_eq!(plan_open(b"/proc/thread-self/comm", None), Ok(OpenPlan::OwnProc { thread: true, rest: b"comm".to_vec() }));
        assert_eq!(plan_open(b"self/environ", Some(b"/proc")), Ok(OpenPlan::OwnProc { thread: false, rest: b"environ".to_vec() }));
        assert_eq!(plan_open(b"/proc/self/fd", None), Ok(OpenPlan::OwnProc { thread: false, rest: b"fd".to_vec() }), "the fd directory itself");
        // Magic links: the tracee's descriptor, cwd, root, executable.
        assert_eq!(plan_open(b"/proc/self/fd/7", None), Ok(own(false, b"fd/7", b"")));
        assert_eq!(plan_open(b"/dev/fd/63", None), Ok(own(false, b"fd/63", b"")), "bash's <(…)");
        assert_eq!(plan_open(b"/dev/stdin", None), Ok(own(false, b"fd/0", b"")));
        assert_eq!(plan_open(b"/dev/stdout", None), Ok(own(false, b"fd/1", b"")));
        assert_eq!(plan_open(b"/dev/stderr", None), Ok(own(false, b"fd/2", b"")));
        assert_eq!(plan_open(b"/proc/self/fd/3/sub/file", None), Ok(own(false, b"fd/3", b"sub/file")));
        assert_eq!(plan_open(b"/proc/self/cwd/a.txt", None), Ok(own(false, b"cwd", b"a.txt")));
        assert_eq!(plan_open(b"/proc/thread-self/root/etc/x", None), Ok(own(true, b"root", b"etc/x")));
        assert_eq!(plan_open(b"/proc/self/exe", None), Ok(own(false, b"exe", b"")));
        assert_eq!(plan_open(b"/proc/self/fd/x", None), Ok(OpenPlan::OwnProc { thread: false, rest: b"fd/x".to_vec() }), "not a number");
        // procfs's own links into `self`.
        assert_eq!(plan_open(b"/proc/mounts", None), Ok(OpenPlan::OwnProc { thread: false, rest: b"mounts".to_vec() }));
        assert_eq!(plan_open(b"/proc/net/tcp", None), Ok(OpenPlan::OwnProc { thread: false, rest: b"net/tcp".to_vec() }));
        assert_eq!(plan_open(b"/proc/net", None), Ok(OpenPlan::OwnProc { thread: false, rest: b"net".to_vec() }));
        assert_eq!(plan_open(b"/proc/network", None), Ok(OpenPlan::InRoot(b"/proc/network".to_vec())));
        // Lookalikes stay ordinary paths.
        assert_eq!(plan_open(b"/proc/selfish", None), Ok(OpenPlan::InRoot(b"/proc/selfish".to_vec())));
        assert_eq!(plan_open(b"/dev/fdx", None), Ok(OpenPlan::InRoot(b"/dev/fdx".to_vec())));
        assert_eq!(plan_open(b"/proc/1234/status", None), Ok(OpenPlan::InRoot(b"/proc/1234/status".to_vec())), "another pid: the tracee's procfs names it");
    }

    /// 2026-10-03: GNU tar 1.35's `openat2(…, O_PATH|O_DIRECTORY|O_NOFOLLOW)`
    /// of an argument's parent was performed with `O_NOCTTY` added, which
    /// openat2 refuses beside `O_PATH`: every `tar cf x.tar dir/f` under the
    /// guard failed "Cannot stat: Invalid argument".
    #[test]
    fn a_performed_open_takes_no_terminal_and_keeps_o_path_valid() {
        const O_DIRECTORY: i32 = if cfg!(target_arch = "aarch64") { 0o40_000 } else { 0o200_000 };
        const O_NOFOLLOW: i32 = if cfg!(target_arch = "aarch64") { 0o100_000 } else { 0o400_000 };
        const O_RDONLY: i32 = 0;
        const O_RDWR: i32 = 2;
        const O_NONBLOCK: i32 = 0o4000;
        // The legacy openat's O_PATH_FLAGS, the only ones openat2 takes with O_PATH.
        let o_path_flags = O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
        // tar's parent open, exactly as strace shows it.
        let tar = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_PATH | O_DIRECTORY;
        assert_eq!(performed_open_flags(tar), tar, "nothing added to an O_PATH open");
        assert_eq!(performed_open_flags(tar) & !o_path_flags, 0, "openat2 accepts it");
        assert_eq!(performed_open_flags(O_PATH), O_PATH | O_CLOEXEC);
        // Every other open: no controlling terminal for the supervisor.
        for f in [O_RDONLY, O_RDWR, O_RDONLY | O_NONBLOCK | O_NOFOLLOW, O_RDONLY | O_CLOEXEC] {
            let p = performed_open_flags(f);
            assert_eq!(p & O_NOCTTY, O_NOCTTY, "{f:#o}");
            assert_eq!(p & O_CLOEXEC, O_CLOEXEC, "{f:#o}");
            assert_eq!(p & !(O_NOCTTY | O_CLOEXEC), f & !O_CLOEXEC, "{f:#o}: the tracee's own flags kept");
        }
        // An O_PATH open with a flag openat2 refuses keeps it: the tracee's
        // own openat2 gets the kernel's EINVAL, not a corrected open.
        assert_eq!(performed_open_flags(O_PATH | O_RDWR), O_PATH | O_RDWR | O_CLOEXEC);
    }

    #[cfg(feature = "kernel")]
    #[test]
    fn open_flag_constants_match_libc() {
        assert_eq!(O_PATH, libc::O_PATH);
        assert_eq!(O_NOCTTY, libc::O_NOCTTY);
        assert_eq!(O_CLOEXEC, libc::O_CLOEXEC);
        assert_eq!(O_CREAT, libc::O_CREAT);
        assert_eq!(O_TMPFILE_BIT, libc::O_TMPFILE & !libc::O_DIRECTORY);
    }

    /// 2026-10-16: an `O_DIRECTORY` open was taken for a create (libc's
    /// `O_TMPFILE` carries the `O_DIRECTORY` bit), so the guard's performed
    /// openat2 carried Bun's 0666 and the tracee got EINVAL: Claude Code
    /// could not open its own `/tmp/claude-<uid>` under `--no-landlock-net`.
    #[test]
    fn only_a_create_carries_a_mode() {
        const O_DIRECTORY: i32 = if cfg!(target_arch = "aarch64") { 0o40_000 } else { 0o200_000 };
        const O_NOFOLLOW: i32 = if cfg!(target_arch = "aarch64") { 0o100_000 } else { 0o400_000 };
        const O_LARGEFILE: i32 = if cfg!(target_arch = "aarch64") { 0o400_000 } else { 0o100_000 };
        const O_RDWR: i32 = 2;
        const O_WRONLY: i32 = 1;
        const O_EXCL: i32 = 0o200;
        let o_tmpfile = O_TMPFILE_BIT | O_DIRECTORY;
        // Bun's open of its tmp dir, exactly as strace shows it (0xb8000 on x86_64).
        let bun_dir = O_LARGEFILE | O_NOFOLLOW | O_CLOEXEC | O_DIRECTORY;
        assert!(!open_creates(bun_dir), "a directory's open creates nothing");
        assert_eq!(performed_open_mode(bun_dir, 0o666, Some(0o022)), 0, "its 0666 is dropped");
        assert_eq!(performed_open_mode(O_DIRECTORY, 0o777, None), 0);
        assert_eq!(performed_open_mode(0, 0o644, Some(0)), 0, "a plain read creates nothing");
        // A create keeps its mode, masked by the umask (022 when unknown).
        assert!(open_creates(O_CREAT | O_WRONLY));
        assert_eq!(performed_open_mode(O_CREAT | O_WRONLY, 0o666, Some(0o022)), 0o644);
        assert_eq!(performed_open_mode(O_CREAT | O_EXCL | O_RDWR, 0o4777, Some(0o077)), 0o4700);
        assert_eq!(performed_open_mode(O_CREAT | O_RDWR, 0o666, None), 0o644);
        assert_eq!(performed_open_mode(O_CREAT | O_RDWR, 0o100_666, Some(0)), 0o666, "file-type bits never reach open_how");
        // O_TMPFILE is a create (its own bit, with or without O_DIRECTORY's).
        assert!(open_creates(o_tmpfile | O_RDWR));
        assert_eq!(performed_open_mode(o_tmpfile | O_RDWR, 0o600, Some(0o022)), 0o600);
        // The kernel's openat2 answer for a mode the flags do not take.
        assert_eq!(openat2_mode_errno(bun_dir, 0), None);
        assert_eq!(openat2_mode_errno(bun_dir, 0o666), Some(22), "a mode on an open that creates nothing: EINVAL");
        assert_eq!(openat2_mode_errno(O_CREAT | O_WRONLY, 0o644), None);
        assert_eq!(openat2_mode_errno(O_CREAT | O_WRONLY, 0o10_644), Some(22), "outside S_IALLUGO: EINVAL");
        assert_eq!(openat2_mode_errno(o_tmpfile | O_RDWR, 0o600), None);
    }

    /// The retry policy for a scoped walk's EAGAIN (2026-10-16: `git
    /// filter-branch`'s `.git-rewrite/t/../index` failed "Resource
    /// temporarily unavailable" on a busy CI guest after eight back-to-back
    /// attempts).
    #[test]
    fn a_scoped_walks_eagain_is_retried_with_pauses_and_a_bound() {
        use std::time::Duration;
        const ENOENT: i32 = 2;
        // Eight back to back, then pauses doubling from 100 us to 5 ms.
        for a in 1..OPENAT2_TIGHT {
            assert_eq!(openat2_retry_after(EAGAIN, 0x10, a), Some(Duration::ZERO), "attempt {a}");
        }
        assert_eq!(openat2_retry_after(EAGAIN, 0x10, 8), Some(Duration::from_micros(100)));
        assert_eq!(openat2_retry_after(EAGAIN, 0x08, 9), Some(Duration::from_micros(200)));
        assert_eq!(openat2_retry_after(EAGAIN, 0x10, 14), Some(Duration::from_micros(5_000)), "capped");
        assert_eq!(openat2_retry_after(EAGAIN, 0x10, OPENAT2_ATTEMPTS - 1), Some(Duration::from_micros(5_000)));
        assert_eq!(openat2_retry_after(EAGAIN, 0x10, OPENAT2_ATTEMPTS), None, "then the EAGAIN stands");
        // Never for another errno, nor for RESOLVE_CACHED's own EAGAIN.
        assert_eq!(openat2_retry_after(ENOENT, 0x10, 1), None);
        assert_eq!(openat2_retry_after(EAGAIN, 0x10 | RESOLVE_CACHED, 1), None);

        // The driver: twenty EAGAINs then a descriptor opens (eight
        // attempts, the old loop, gave the tracee EAGAIN).
        let run = |fails: u32, resolve: u64| {
            let (mut n, mut paused) = (0u32, Duration::ZERO);
            let r = retry_openat2(resolve, || { n += 1; if n <= fails { Err(EAGAIN) } else { Ok(7) } }, |d| paused += d);
            (r, n, paused)
        };
        let (r, n, paused) = run(20, 0x10);
        assert_eq!((r, n), (Ok(7), 21));
        assert!(paused > Duration::ZERO, "the later attempts pause");
        // A storm that never ends: the EAGAIN after OPENAT2_ATTEMPTS, a
        // bounded wait (about a quarter second), never an open.
        let (r, n, paused) = run(u32::MAX, 0x10);
        assert_eq!((r, n), (Err(EAGAIN), OPENAT2_ATTEMPTS));
        assert!(paused < Duration::from_millis(300), "{paused:?}");
        // RESOLVE_CACHED: one attempt, its EAGAIN the tracee's.
        assert_eq!(run(u32::MAX, 0x10 | RESOLVE_CACHED).0, Err(EAGAIN));
        assert_eq!(run(u32::MAX, 0x10 | RESOLVE_CACHED).1, 1);
        // Another error: one attempt.
        let mut n = 0;
        assert_eq!(retry_openat2(0x10, || { n += 1; Err(ENOENT) }, |_| {}), Err(ENOENT));
        assert_eq!(n, 1);
    }

    /// A performed open whose path walks `..` while BURSTS of renames run
    /// elsewhere on the machine (a sandbox starting up mounts and renames
    /// for a few milliseconds; git renames its lock files): never EAGAIN. A
    /// scoped `openat2` (`RESOLVE_IN_ROOT` / `RESOLVE_BENEATH`) fails EAGAIN
    /// when any rename lands during its `..` walk; the walk's length sets
    /// how often. The test picks a length at which three attempts in four fail
    /// in a storm, then runs bursts of 2 ms every 6 ms and performs 400
    /// opens, absolute and dirfd-relative, as the tracee: eight back-to-back
    /// attempts (the old loop) can all land in one burst, the paused ones
    /// reach the quiet between. A storm with no quiet longer than the pauses
    /// still answers EAGAIN (`openat2_retry_after`). Unprivileged.
    #[cfg(feature = "kernel")]
    #[test]
    fn a_dotdot_walk_racing_rename_bursts_is_never_eagain() {
        use std::sync::atomic::{AtomicU8, Ordering};
        use std::sync::Arc;
        const STORM: u8 = 0;
        const BURSTS: u8 = 1;
        const STOP: u8 = 2;
        let dir = std::env::temp_dir().join(format!("mdu-dotdot-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("t/a")).expect("mkdir");
        std::fs::write(dir.join("t/f"), b"F\n").expect("write");
        let phase = Arc::new(AtomicU8::new(STORM));
        let epoch = std::time::Instant::now();
        let renamers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(2, 8);
        let handles: Vec<_> = (0..renamers)
            .map(|i| {
                let (phase, dir) = (phase.clone(), dir.clone());
                std::thread::spawn(move || {
                    let (a, b) = (dir.join(format!("ra{i}")), dir.join(format!("rb{i}")));
                    let _ = std::fs::write(&a, b"");
                    loop {
                        match phase.load(Ordering::Relaxed) {
                            STOP => break,
                            // 2 ms of renames in every 6 ms, all threads at once.
                            BURSTS if epoch.elapsed().as_micros() % 6_000 >= 2_000 => std::thread::yield_now(),
                            _ => {
                                let _ = std::fs::rename(&a, &b);
                                let _ = std::fs::rename(&b, &a);
                            }
                        }
                    }
                })
            })
            .collect();
        let tfd = {
            let c = std::ffi::CString::new(dir.join("t").as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: open of a NUL-terminated path.
            unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) }
        };
        assert!(tfd >= 0);
        // One raw attempt's failure rate for a walk of k `a/..` pairs.
        let rate = |k: usize| {
            let rel = std::ffi::CString::new(format!("{}f", "a/../".repeat(k))).unwrap();
            let how = OpenHow { flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64, mode: 0, resolve: libc::RESOLVE_BENEATH };
            let fails = (0..200)
                .filter(|_| {
                    // SAFETY: openat2 relative to our descriptor.
                    let fd = unsafe { libc::syscall(libc::SYS_openat2, tfd, rel.as_ptr(), &how as *const OpenHow, std::mem::size_of::<OpenHow>()) } as i32;
                    if fd >= 0 {
                        // SAFETY: our own descriptor.
                        unsafe { libc::close(fd) };
                    }
                    fd < 0
                })
                .count();
            fails as f64 / 200.0
        };
        // Small steps, stopping at three in four: a longer walk (a storm
        // failing every attempt) leaves no quiet long enough on a machine
        // busy with other tests as well.
        let mut k = 4usize;
        let mut r = rate(k);
        while r < 0.75 && k < 700 {
            k = (k + k / 12 + 1).min(700);
            r = rate(k);
        }
        phase.store(BURSTS, Ordering::Relaxed);
        eprintln!("{renamers} renamers; a walk of {k} `a/..` pairs fails {:.0}% of raw attempts in a storm", r * 100.0);
        let rel = format!("{}f", "a/../".repeat(k));
        let mut abs = dir.join("t").as_os_str().as_encoded_bytes().to_vec();
        abs.push(b'/');
        abs.extend_from_slice(rel.as_bytes());
        let me = std::process::id() as i32;
        let valid = || true;
        let mut eagain = 0;
        let mut other = Vec::new();
        for i in 0..400 {
            let r = if i % 2 == 0 {
                open_as_tracee(me, libc::AT_FDCWD, &abs, libc::O_RDONLY, 0, 0, &valid)
            } else {
                open_as_tracee(me, tfd, rel.as_bytes(), libc::O_RDONLY, 0, 0, &valid)
            };
            match r {
                Ok(o) => {
                    // SAFETY: our own descriptor.
                    unsafe { libc::close(o.fd) };
                }
                Err(e) if e == libc::EAGAIN => eagain += 1,
                Err(e) => other.push(e),
            }
        }
        phase.store(STOP, Ordering::Relaxed);
        for h in handles {
            let _ = h.join();
        }
        // SAFETY: our own descriptor.
        unsafe { libc::close(tfd) };
        let _ = std::fs::remove_dir_all(&dir);
        assert!(other.is_empty(), "other errors: {other:?}");
        assert_eq!(eagain, 0, "{eagain} of 400 performed opens answered EAGAIN ({:.0}% of raw attempts fail in a storm at {k} pairs)", r * 100.0);
    }

    /// The one-step performed open (`Finish::Direct`, a tracee in no
    /// Landlock domain) of a directory, with the flags and the 0666 Bun
    /// passes: it opens (it was EINVAL). A create still gets its mode under
    /// the umask. Unprivileged: the tracee is this process.
    #[cfg(feature = "kernel")]
    #[test]
    fn a_directory_open_with_a_stray_mode_is_performed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mdu-dirmode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let me = std::process::id() as i32;
        let valid = || true;
        let bun_dir = libc::O_RDONLY | libc::O_LARGEFILE | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY;
        let path = dir.to_str().unwrap().as_bytes().to_vec();
        let o = open_as_tracee(me, libc::AT_FDCWD, &path, bun_dir, 0o666, 0, &valid).unwrap_or_else(|e| panic!("the directory open: errno {e}"));
        // SAFETY: fstat into a zeroed buffer, on our own descriptor.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(o.fd, &mut st) }, 0);
        assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFDIR, "the directory itself");
        // SAFETY: closing our own descriptor.
        unsafe { libc::close(o.fd) };
        // Relative to a descriptor too (the root-based plan above, the cwd-based one here).
        let o = open_as_tracee(me, libc::AT_FDCWD, b".", bun_dir, 0o666, 0, &valid).expect("the cwd's open");
        // SAFETY: closing our own descriptor.
        unsafe { libc::close(o.fd) };
        // A create: its mode, under the umask.
        let f = dir.join("new.txt");
        let o = open_as_tracee(me, libc::AT_FDCWD, f.to_str().unwrap().as_bytes(), libc::O_CREAT | libc::O_WRONLY | libc::O_EXCL, 0o640, 0, &valid).expect("create");
        // SAFETY: closing our own descriptor.
        unsafe { libc::close(o.fd) };
        let umask = tracee_umask(me).unwrap_or(0o022);
        assert_eq!(std::fs::metadata(&f).expect("stat").permissions().mode() & 0o7777, 0o640 & !umask);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The performed openat2 of tar's parent directory succeeds (it was
    /// EINVAL) and yields an `O_PATH` descriptor of that directory; a file
    /// opened `O_PATH` likewise. Unprivileged: the tracee is this process.
    #[cfg(feature = "kernel")]
    #[test]
    fn an_o_path_open_is_performed_as_the_tracee_would() {
        let dir = std::env::temp_dir().join(format!("mdu-opath-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("f.txt"), b"hi\n").expect("write");
        let me = std::process::id() as i32;
        let valid = || true;
        let mut parent = dir.to_str().unwrap().as_bytes().to_vec();
        parent.push(b'/');
        let tar = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_PATH | libc::O_DIRECTORY;
        for (path, flags) in [(parent.clone(), tar), (dir.join("f.txt").to_str().unwrap().as_bytes().to_vec(), libc::O_PATH | libc::O_CLOEXEC)] {
            let o = open_as_tracee(me, libc::AT_FDCWD, &path, flags, 0, 0, &valid).unwrap_or_else(|e| panic!("{}: errno {e}", String::from_utf8_lossy(&path)));
            // SAFETY: F_GETFL on our own descriptor.
            let got = unsafe { libc::fcntl(o.fd, libc::F_GETFL) };
            assert_ne!(got & libc::O_PATH, 0, "an O_PATH descriptor");
            // SAFETY: closing our own descriptor.
            unsafe { libc::close(o.fd) };
        }
        // A plain read still works (and still takes no terminal).
        let o = open_as_tracee(me, libc::AT_FDCWD, dir.join("f.txt").to_str().unwrap().as_bytes(), libc::O_RDONLY, 0, 0, &valid).expect("read open");
        // SAFETY: closing our own descriptor.
        unsafe { libc::close(o.fd) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_controlling_terminal_is_named_by_its_device() {
        let enc = |major: u64, minor: u64| (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12);
        assert_eq!(ctty_node(0), None, "no terminal");
        assert_eq!(ctty_node(enc(136, 3)), Some(b"/dev/pts/3".to_vec()));
        assert_eq!(ctty_node(enc(136, 300)), Some(b"/dev/pts/300".to_vec()), "a minor past 255");
        assert_eq!(ctty_node(enc(137, 4)), Some(b"/dev/pts/260".to_vec()));
        assert_eq!(ctty_node(enc(4, 2)), Some(b"/dev/tty2".to_vec()));
        assert_eq!(ctty_node(enc(4, 65)), Some(b"/dev/ttyS1".to_vec()));
        assert_eq!(ctty_node(enc(188, 0)), None, "a USB serial line: not named here");
    }

}
