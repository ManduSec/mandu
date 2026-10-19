//! context_helper — pseudo-filesystem opens performed with the TRACEE's
//! credentials and namespaces (confidentiality-plan-10-flow-taint.md §4.1a).
//!
//! The guard performs every open that can read (a CONTINUE would let the
//! kernel re-read and re-resolve the path). On a real filesystem the guard's
//! open equals the tracee's: same uid and groups. On procfs, sysfs, cgroupfs
//! and their kin it does not: the kernel judges the OPENER there. bwrap's
//! `/proc/<child>/uid_map` must be opened by a process in the child's parent
//! user namespace; `/proc/<pid>/mem` is checked against the opener's ptrace
//! rights (the guard is an ancestor of every agent process, so Yama would let
//! it in where the tracee is refused); `/proc/sys/net/*` shows the opener's
//! network namespace. Such an open is re-done by a helper process that IS the
//! tracee as far as the kernel's checks go: it joins the tracee's user, net,
//! uts, ipc and cgroup namespaces, drops to exactly its capability sets,
//! sets `no_new_privs` and applies its mirrored Landlock domain, then reopens
//! the descriptor the guard hands it (`/proc/self/fd/N`: no path is resolved
//! again). Never more than the tracee: a tracee whose uid or groups differ
//! from the guard's is refused (the helper could not become it).
//!
//! Helpers are cached per context and exit when the guard closes their
//! socket (idle for `IDLE`).
//!
//! `Mandu-new`.

#![cfg(all(feature = "kernel", target_os = "linux"))]

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A helper unused this long is closed.
const IDLE: Duration = Duration::from_secs(30);

/// `MANDU_NET_GUARD_DEBUG=1`: say why a context was refused.
fn debug(msg: &str) {
    if std::env::var_os("MANDU_NET_GUARD_DEBUG").map(|v| v == "1").unwrap_or(false) {
        eprintln!("mandu-net-guard[helper]: {msg}");
    }
}

/// statfs magic numbers of the filesystems whose opens are judged against
/// the opener's credentials or namespaces.
const PSEUDO_FS: &[i64] = &[
    0x9fa0,             // proc
    0x6265_6572,        // sysfs
    0x0027_e0eb,        // cgroup
    0x6367_7270,        // cgroup2
    0x7363_6673,        // securityfs
    0x6462_6720,        // debugfs
    0x7472_6163,        // tracefs
    0xcafe_4a11,        // bpf
    0x6265_6570,        // configfs
    0xde5e_81e4,        // efivarfs
    0x6165_676c,        // pstore
    0x1980_0202,        // mqueue
    0x4249_4e4d,        // binfmt_misc
    0x6573_5543,        // fusectl
    0x6e73_6673,        // nsfs
];

const PROC_SUPER_MAGIC: i64 = 0x9fa0;

/// What kind of file an opened descriptor is, for this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pseudo {
    /// A real filesystem (or devpts, tmpfs): the guard's open is the tracee's.
    No,
    /// procfs under a process's directory (`/proc/<n>/…`).
    ProcPid,
    /// Any other pseudo-filesystem file.
    Other,
}

/// Classify an opened descriptor.
pub fn pseudo_kind(fd: RawFd) -> Pseudo {
    classify(fd).0
}

/// `pseudo_kind`, and for a procfs file the path its descriptor names
/// (`/proc/<n>/…`, `/proc/meminfo`), read once for every later check.
pub fn classify(fd: RawFd) -> (Pseudo, Option<String>) {
    // SAFETY: fstat into a zeroed buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let stat = (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(&st);
    classify_stat(fd, stat)
}

/// `classify`, given the descriptor's `fstat` when the caller has one
/// (`None`: it failed, or was not taken). A file on a block device is never
/// on a pseudo filesystem (`fs_supervisor::tracee::may_be_pseudo_fs`), so
/// its `fstatfs` is not asked (runtime-instances.md §14.9: about 2.5 µs of
/// every performed open on a 128-CPU ext4 host). Every other file is judged
/// by its `fstatfs`, as before.
pub fn classify_stat(fd: RawFd, stat: Option<&libc::stat>) -> (Pseudo, Option<String>) {
    if stat.is_some_and(|st| !fs_supervisor::tracee::may_be_pseudo_fs(st.st_dev)) {
        return (Pseudo::No, None);
    }
    classify_by_statfs(fd)
}

/// `classify` by the descriptor's `fstatfs` alone (the whole test before
/// 2026-10-18; a unit test compares the two over real files).
fn classify_by_statfs(fd: RawFd) -> (Pseudo, Option<String>) {
    // SAFETY: fstatfs into a zeroed buffer.
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut sfs) } != 0 {
        return (Pseudo::Other, None);
    }
    let t = sfs.f_type as i64;
    if !PSEUDO_FS.contains(&t) {
        return (Pseudo::No, None);
    }
    if t != PROC_SUPER_MAGIC {
        return (Pseudo::Other, None);
    }
    let seen = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok().map(|p| p.to_string_lossy().into_owned());
    let pid_dir = seen.as_deref().map(|s| {
        let mut comps = s.trim_start_matches('/').split('/');
        comps.next() == Some("proc") && comps.next().map(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())).unwrap_or(false)
    });
    (if pid_dir == Some(true) { Pseudo::ProcPid } else { Pseudo::Other }, seen)
}

/// Files under `/proc/<pid>/` whose open the kernel judges by more than a
/// read-mode ptrace check a same-uid, dumpable target always passes:
/// attach-mode (Yama's ancestry rule), the opener's user namespace, an LSM's
/// view. Always opened by the helper.
const PROC_PID_OPENER_BOUND: &[&str] = &[
    "mem", "stack", "syscall", "personality", "map_files", "uid_map", "gid_map", "setgroups", "projid_map", "attr", "timerslack_ns", "clear_refs",
];

/// A global procfs file (not per process) whose content does not depend on
/// the opener's namespaces: everything but `sys/` and `sysvipc/` (`net` and
/// `mounts` are links into `self`, planned as the tracee's own).
fn proc_global_is_plain(seen: &str) -> bool {
    let rest = seen.trim_start_matches('/').strip_prefix("proc").unwrap_or("x").trim_start_matches('/');
    !(rest.starts_with("sys/") || rest == "sys" || rest.starts_with("sysvipc"))
}

/// A task's credentials and namespaces, as the kernel's checks see them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Context {
    /// `(dev, ino)` of the user, net, uts, ipc and cgroup namespaces.
    ns: [(u64, u64); 5],
    /// Effective, permitted, inheritable, bounding, ambient capability sets.
    caps: [u64; 5],
    /// Real, effective, saved, fs uid and gid (as the host sees them).
    uids: [u32; 4],
    gids: [u32; 4],
    groups: Vec<u32>,
    /// The mirrored Landlock domain (its address; 0 = none).
    domain: usize,
}

const NS_NAMES: [&str; 5] = ["user", "net", "uts", "ipc", "cgroup"];
const NS_FLAGS: [libc::c_int; 5] = [libc::CLONE_NEWUSER, libc::CLONE_NEWNET, libc::CLONE_NEWUTS, libc::CLONE_NEWIPC, libc::CLONE_NEWCGROUP];

fn ns_id(pid: &str, name: &str) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("/proc/{pid}/ns/{name}")).ok().map(|m| (m.dev(), m.ino()))
}

impl Context {
    /// The context of task `tid` (`self` for this process).
    fn of(tid: &str, domain: usize) -> Option<Context> {
        let status = fs_supervisor::tracee::read_proc_small(&format!("/proc/{tid}/status"))?;
        let field = |name: &str| status.lines().find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(':'))).map(str::trim);
        let hex = |name: &str| field(name).and_then(|v| u64::from_str_radix(v, 16).ok());
        let ids = |name: &str| -> Option<[u32; 4]> {
            let v: Vec<u32> = field(name)?.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            (v.len() == 4).then(|| [v[0], v[1], v[2], v[3]])
        };
        let mut ns = [(0, 0); 5];
        for (i, n) in NS_NAMES.iter().enumerate() {
            ns[i] = ns_id(tid, n)?;
        }
        let mut groups: Vec<u32> = field("Groups").unwrap_or("").split_whitespace().filter_map(|x| x.parse().ok()).collect();
        groups.sort_unstable();
        Some(Context {
            ns,
            caps: [hex("CapEff")?, hex("CapPrm")?, hex("CapInh")?, hex("CapBnd")?, hex("CapAmb").unwrap_or(0)],
            uids: ids("Uid")?,
            gids: ids("Gid")?,
            groups,
            domain,
        })
    }

    /// Would the guard's own open be the tracee's? Same namespaces, same
    /// credentials, no Landlock domain of its own.
    fn same_as(&self, ours: &Context) -> bool {
        self.ns == ours.ns && self.caps == ours.caps && self.uids == ours.uids && self.gids == ours.gids && self.groups == ours.groups && self.domain == 0
    }
}

/// A running helper: its end of the socket (one request at a time).
struct Helper {
    sock: Mutex<RawFd>,
    pid: i32,
    used: Mutex<Instant>,
}

impl Drop for Helper {
    fn drop(&mut self) {
        let fd = *self.sock.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: closing our end ends the helper's loop; reap it.
        unsafe {
            libc::close(fd);
            libc::waitpid(self.pid, std::ptr::null_mut(), 0);
        }
    }
}

/// The helpers, by context.
#[derive(Default)]
pub struct ContextHelpers {
    helpers: Mutex<HashMap<Context, Arc<Helper>>>,
}

fn send_fd_flags(sock: RawFd, fd: RawFd, flags: i32) -> bool {
    unsafe {
        let payload = flags.to_ne_bytes();
        let mut iov = libc::iovec { iov_base: payload.as_ptr() as *mut libc::c_void, iov_len: 4 };
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if fd >= 0 {
            msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = libc::CMSG_SPACE(4) as usize;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as usize;
            std::ptr::copy_nonoverlapping(&fd as *const RawFd as *const u8, libc::CMSG_DATA(c), 4);
        }
        libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) == 4
    }
}

/// The longest path a lookup request carries (the rest of the message).
const MAX_LOOKUP: usize = 4096;

/// A lookup request: `flags`, `resolve`, then the path (NUL-free), with the
/// descriptor it is resolved beneath (`openat2`). The helper answers like a
/// reopen (`send_fd_flags`).
fn send_lookup(sock: RawFd, base: RawFd, flags: i32, resolve: u64, path: &[u8]) -> bool {
    if path.is_empty() || path.len() > MAX_LOOKUP || path.contains(&0) {
        return false;
    }
    let mut payload = Vec::with_capacity(12 + path.len());
    payload.extend_from_slice(&flags.to_ne_bytes());
    payload.extend_from_slice(&resolve.to_ne_bytes());
    payload.extend_from_slice(path);
    unsafe {
        let mut iov = libc::iovec { iov_base: payload.as_ptr() as *mut libc::c_void, iov_len: payload.len() };
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(4) as usize;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as usize;
        std::ptr::copy_nonoverlapping(&base as *const RawFd as *const u8, libc::CMSG_DATA(c), 4);
        libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) == payload.len() as isize
    }
}

/// A request as the helper receives it: 4 bytes (a reopen's flags), or 12 +
/// a path (a lookup), with at most one descriptor. `(flags, resolve, path
/// length, fd)`; the path is left in `path`.
fn recv_request(sock: RawFd, path: &mut [u8]) -> Option<(i32, u64, usize, RawFd)> {
    unsafe {
        let mut head = [0u8; 12];
        let mut iov = [
            libc::iovec { iov_base: head.as_mut_ptr() as *mut libc::c_void, iov_len: 12 },
            libc::iovec { iov_base: path.as_mut_ptr() as *mut libc::c_void, iov_len: path.len() - 1 },
        ];
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = 2;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cbuf.len();
        let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n < 4 {
            return None;
        }
        let mut fd = -1;
        let c = libc::CMSG_FIRSTHDR(&msg);
        if !c.is_null() && (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
            std::ptr::copy_nonoverlapping(libc::CMSG_DATA(c), &mut fd as *mut RawFd as *mut u8, 4);
        }
        let flags = i32::from_ne_bytes([head[0], head[1], head[2], head[3]]);
        if n == 4 {
            return Some((flags, 0, 0, fd));
        }
        if n < 13 {
            return Some((flags, 0, usize::MAX, fd));
        }
        let mut r = [0u8; 8];
        r.copy_from_slice(&head[4..12]);
        let len = n as usize - 12;
        path[len] = 0;
        Some((flags, u64::from_ne_bytes(r), len, fd))
    }
}

/// Receive a 4-byte value and at most one descriptor (-1 if none).
fn recv_fd_value(sock: RawFd) -> Option<(i32, RawFd)> {
    unsafe {
        let mut payload = [0u8; 4];
        let mut iov = libc::iovec { iov_base: payload.as_mut_ptr() as *mut libc::c_void, iov_len: 4 };
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cbuf.len();
        let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n != 4 {
            return None;
        }
        let mut fd = -1;
        let c = libc::CMSG_FIRSTHDR(&msg);
        if !c.is_null() && (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
            std::ptr::copy_nonoverlapping(libc::CMSG_DATA(c), &mut fd as *mut RawFd as *mut u8, 4);
        }
        Some((i32::from_ne_bytes(payload), fd))
    }
}

/// `capset(2)` version 3.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// The helper's body, in the forked child: become the tracee (as far as the
/// kernel's open-time checks go), then serve reopen requests until EOF.
/// Only syscalls and stack buffers after the fork. Exit codes name the step
/// that failed (the parent refuses the context then).
fn helper_main(sock: RawFd, ns: &[(RawFd, libc::c_int)], caps: [u64; 5], layers: &[RawFd], keep: &mut [RawFd]) -> ! {
    unsafe {
        // Only what it uses stays open: a copy of anything else (another
        // helper's socket, the guard's listener, a pipe of the process it was
        // forked from) would keep a peer waiting for an EOF that never comes.
        keep.sort_unstable();
        let mut from: u32 = 0;
        for fd in keep.iter() {
            let fd = *fd as u32;
            if fd > from {
                libc::syscall(libc::SYS_close_range, from, fd - 1, 0u32);
            }
            from = fd + 1;
        }
        libc::syscall(libc::SYS_close_range, from, u32::MAX, 0u32);
        // The user namespace first: its capabilities are what the others need.
        for (i, (fd, flag)) in ns.iter().enumerate() {
            if libc::setns(*fd, *flag) != 0 {
                // 20 + the step, +100 when EINVAL (the kernel's "not allowed here").
                let e = *libc::__errno_location();
                libc::_exit(20 + i as i32 + if e == libc::EINVAL { 100 } else { 0 });
            }
            libc::close(*fd);
        }
        // Exactly the tracee's capability sets: the bounding set first.
        let [eff, prm, inh, bnd, _amb] = caps;
        for cap in 0..64u64 {
            if bnd & (1 << cap) == 0 {
                // EINVAL past the last capability the kernel knows: fine.
                libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
            }
        }
        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong, 0, 0, 0);
        let hdr = CapHeader { version: 0x2008_0522, pid: 0 };
        let data = [
            CapData { effective: eff as u32, permitted: prm as u32, inheritable: inh as u32 },
            CapData { effective: (eff >> 32) as u32, permitted: (prm >> 32) as u32, inheritable: (inh >> 32) as u32 },
        ];
        if libc::syscall(libc::SYS_capset, &hdr as *const CapHeader, data.as_ptr()) != 0 {
            libc::_exit(12);
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            libc::_exit(13);
        }
        for fd in layers {
            if libc::syscall(crate::landlock_mirror::SYS_LANDLOCK_RESTRICT_SELF, *fd, 0) != 0 {
                libc::_exit(14);
            }
        }
        // Ready.
        send_fd_flags(sock, -1, 0);
        let mut path = [0u8; 64];
        let mut lookup = [0u8; MAX_LOOKUP + 1];
        loop {
            let Some((flags, resolve, len, fd)) = recv_request(sock, &mut lookup) else { libc::_exit(0) };
            let answer = if fd < 0 || len == usize::MAX {
                -libc::EBADF
            } else if len > 0 {
                // A lookup: the whole walk as the tracee (a sysctl's table is
                // chosen by the opener's namespaces at lookup, not at open).
                let how = [flags as u64 | libc::O_CLOEXEC as u64 | libc::O_NOCTTY as u64, 0u64, resolve];
                // Retried like the guard's own (a rename or a mount racing a
                // `..`, `openat2_retry_after`); nothing allocated after the fork.
                let r = fs_supervisor::tracee::retry_openat2(
                    resolve,
                    || {
                        let r = libc::syscall(libc::SYS_openat2, fd, lookup.as_ptr(), how.as_ptr(), 24usize) as i32;
                        if r < 0 { Err(*libc::__errno_location()) } else { Ok(r) }
                    },
                    |d| {
                        let ts = libc::timespec { tv_sec: 0, tv_nsec: d.as_nanos().min(999_999_999) as libc::c_long };
                        libc::nanosleep(&ts, std::ptr::null_mut());
                    },
                );
                r.unwrap_or_else(|e| -e)
            } else {
                // "/proc/self/fd/<fd>\0" on the stack.
                let prefix = b"/proc/self/fd/";
                path[..prefix.len()].copy_from_slice(prefix);
                let mut n = fd as u32;
                let mut digits = [0u8; 10];
                let mut k = 0;
                loop {
                    digits[k] = b'0' + (n % 10) as u8;
                    k += 1;
                    n /= 10;
                    if n == 0 {
                        break;
                    }
                }
                for j in 0..k {
                    path[prefix.len() + j] = digits[k - 1 - j];
                }
                path[prefix.len() + k] = 0;
                let r = libc::open(path.as_ptr() as *const libc::c_char, flags);
                if r < 0 { -*libc::__errno_location() } else { r }
            };
            if fd >= 0 {
                libc::close(fd);
            }
            if answer >= 0 {
                send_fd_flags(sock, answer, 0);
                libc::close(answer);
            } else {
                send_fd_flags(sock, -1, -answer);
            }
        }
    }
}


/// `ioctl_ns`: the owning user namespace of a namespace, the parent of a
/// user namespace (linux/nsfs.h, `_IO(0xb7, 1)` and `_IO(0xb7, 2)`).
const NS_GET_USERNS: libc::c_ulong = 0xb701;
const NS_GET_PARENT: libc::c_ulong = 0xb702;

fn fd_id(fd: RawFd) -> Option<(u64, u64)> {
    // SAFETY: fstat into a zeroed stat buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev, st.st_ino))
}

fn ioctl_fd(fd: RawFd, req: libc::c_ulong) -> Option<RawFd> {
    // SAFETY: an nsfs ioctl returning a new descriptor or -1.
    let r = unsafe { libc::ioctl(fd, req as _) };
    (r >= 0).then_some(r)
}

fn close_all(fds: &[(RawFd, libc::c_int)]) {
    for (f, _) in fds {
        // SAFETY: descriptors we opened.
        unsafe { libc::close(*f) };
    }
}

/// The `setns` steps that take a process in OUR namespaces into the
/// tracee's: its user namespace chain below ours, top-down, each user
/// namespace followed by the tracee's namespaces it owns. Err (EACCES): a
/// namespace owned outside that chain, which cannot be joined.
fn join_plan(tid: i32, theirs: &Context, ours: &Context) -> Result<Vec<(RawFd, libc::c_int)>, i32> {
    let open_ns = |name: &str| -> Result<RawFd, i32> {
        let c = std::ffi::CString::new(format!("/proc/{tid}/ns/{name}")).map_err(|_| libc::EIO)?;
        // SAFETY: open with a NUL-terminated path.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 { Err(libc::EACCES) } else { Ok(fd) }
    };
    // The tracee's user namespace chain up to (not including) ours.
    let mut chain: Vec<RawFd> = Vec::new();
    if theirs.ns[0] != ours.ns[0] {
        let mut cur = open_ns("user")?;
        loop {
            if fd_id(cur) == Some(ours.ns[0]) {
                // SAFETY: our own user namespace is not joined.
                unsafe { libc::close(cur) };
                break;
            }
            chain.push(cur);
            match ioctl_fd(cur, NS_GET_PARENT) {
                Some(p) => cur = p,
                None => {
                    // Not below ours: nothing we could join.
                    for f in &chain {
                        unsafe { libc::close(*f) };
                    }
                    return Err(libc::EACCES);
                }
            }
            if chain.len() > 32 {
                for f in &chain {
                    unsafe { libc::close(*f) };
                }
                return Err(libc::EACCES);
            }
        }
        chain.reverse();
    }
    // The other namespaces that differ, each placed after its owner.
    let mut owned: Vec<(RawFd, libc::c_int, Option<(u64, u64)>)> = Vec::new();
    for i in 1..5 {
        if theirs.ns[i] == ours.ns[i] {
            continue;
        }
        let fd = match open_ns(NS_NAMES[i]) {
            Ok(fd) => fd,
            Err(e) => {
                close_all(&owned.iter().map(|(f, fl, _)| (*f, *fl)).collect::<Vec<_>>());
                for f in &chain {
                    unsafe { libc::close(*f) };
                }
                return Err(e);
            }
        };
        let owner = ioctl_fd(fd, NS_GET_USERNS).map(|o| {
            let id = fd_id(o);
            unsafe { libc::close(o) };
            id
        });
        owned.push((fd, NS_FLAGS[i], owner.flatten()));
    }
    let mut plan: Vec<(RawFd, libc::c_int)> = Vec::new();
    // Owned by our own user namespace: joinable only with CAP_SYS_ADMIN
    // there (a guard running as root in a user namespace); first, before
    // any user namespace is left. Owned by one on the chain: after joining it.
    const CAP_SYS_ADMIN: u64 = 1 << 21;
    if ours.caps[0] & CAP_SYS_ADMIN != 0 {
        for (fd, flag, owner) in &owned {
            if *owner == Some(ours.ns[0]) {
                plan.push((*fd, *flag));
            }
        }
    }
    let chain_ids: Vec<Option<(u64, u64)>> = chain.iter().map(|f| fd_id(*f)).collect();
    for (k, u) in chain.iter().enumerate() {
        plan.push((*u, libc::CLONE_NEWUSER));
        for (fd, flag, owner) in &owned {
            if *owner == chain_ids[k] {
                plan.push((*fd, *flag));
            }
        }
    }
    if plan.iter().filter(|(_, f)| *f != libc::CLONE_NEWUSER).count() != owned.len() {
        close_all(&plan);
        close_all(&owned.iter().filter(|(f, _, _)| !plan.iter().any(|(p, _)| p == f)).map(|(f, fl, _)| (*f, *fl)).collect::<Vec<_>>());
        return Err(libc::EACCES);
    }
    Ok(plan)
}

impl ContextHelpers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reopen `fd` (a pseudo-filesystem file the guard opened for task `tid`)
    /// with `flags`, as the tracee would have opened it. `domain`: its
    /// mirrored Landlock domain, if any. Err = the errno for the tracee.
    pub fn reopen_as(&self, tid: i32, fd: RawFd, flags: i32, kind: Pseudo, seen: Option<&str>, domain: Option<&Arc<crate::landlock_mirror::Domain>>) -> Result<Option<RawFd>, i32> {
        // The guard's own context does not change after it started.
        static OURS: std::sync::OnceLock<Option<Context>> = std::sync::OnceLock::new();
        let ours = OURS.get_or_init(|| Context::of("self", 0)).clone().ok_or(libc::EIO)?;
        // Without a Landlock domain of its own, the guard's open is the
        // tracee's for: a global procfs file that no namespace changes; and
        // another process's entry that a read-mode check decides, when that
        // process is dumpable under our uid (both pass on the uid) or lives in
        // the guard's own user namespace (neither holds a capability there).
        if domain.is_none() {
            if let Some(seen) = seen {
                if kind == Pseudo::Other && proc_global_is_plain(seen) {
                    return Ok(None);
                }
                if kind == Pseudo::ProcPid && self.proc_pid_plain(tid, fd, seen, &ours) {
                    return Ok(None);
                }
            }
        }
        let dom_id = domain.map(|d| Arc::as_ptr(d) as usize).unwrap_or(0);
        // A tracee in the guard's user namespace, while the guard holds no
        // capability: it cannot have other namespaces or credentials either.
        let theirs = if dom_id == 0 && ours.caps[0] == 0 && ns_id(&tid.to_string(), "user") == Some(ours.ns[0]) {
            Context { domain: 0, ..ours.clone() }
        } else {
            Context::of(&tid.to_string(), dom_id).ok_or(libc::ESRCH)?
        };
        // Another process's /proc entry always (the guard's ancestry would
        // beat Yama); anything else only when the contexts differ.
        if kind != Pseudo::ProcPid && theirs.same_as(&ours) {
            return Ok(None);
        }
        // The helper can become the tracee only with the same ids.
        if theirs.uids != ours.uids || theirs.gids != ours.gids || theirs.groups != ours.groups {
            debug(&format!("tid {tid}: ids differ, refused: theirs {theirs:?} ours {ours:?}"));
            return Err(libc::EACCES);
        }
        let helper = self.helper_for(tid, &theirs, &ours, domain)?;
        let sock = helper.sock.lock().unwrap_or_else(|p| p.into_inner());
        *helper.used.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
        let flags = (flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW)) | libc::O_NOCTTY | libc::O_CLOEXEC;
        if !send_fd_flags(*sock, fd, flags) {
            return Err(libc::EIO);
        }
        match recv_fd_value(*sock) {
            Some((_, got)) if got >= 0 => Ok(Some(got)),
            Some((errno, _)) if errno > 0 => Err(errno),
            _ => Err(libc::EIO),
        }
    }

    /// Resolve `path` beneath `base` (`openat2` with `resolve`) and open it
    /// with `flags`, as task `tid`: every lookup of the walk, not only the
    /// open, runs with its credentials and namespaces. For a write to a
    /// pseudo-filesystem file, whose lookup the kernel already judges by the
    /// opener (a sysctl under /proc/sys picks its table by the opener's
    /// namespaces; bwrap writes its own `max_user_namespaces`).
    pub fn lookup_as(&self, tid: i32, base: RawFd, path: &[u8], flags: i32, resolve: u64, domain: Option<&Arc<crate::landlock_mirror::Domain>>) -> Result<RawFd, i32> {
        static OURS: std::sync::OnceLock<Option<Context>> = std::sync::OnceLock::new();
        let ours = OURS.get_or_init(|| Context::of("self", 0)).clone().ok_or(libc::EIO)?;
        let dom_id = domain.map(|d| Arc::as_ptr(d) as usize).unwrap_or(0);
        let theirs = Context::of(&tid.to_string(), dom_id).ok_or(libc::ESRCH)?;
        let flags = (flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC)) | libc::O_NOCTTY | libc::O_CLOEXEC;
        if theirs.same_as(&ours) {
            let c = std::ffi::CString::new(path).map_err(|_| libc::ENOENT)?;
            let how = fs_supervisor::tracee::OpenHow { flags: flags as u64, mode: 0, resolve };
            return fs_supervisor::tracee::openat2(base, &c, &how);
        }
        if theirs.uids != ours.uids || theirs.gids != ours.gids || theirs.groups != ours.groups {
            debug(&format!("tid {tid}: ids differ, lookup refused"));
            return Err(libc::EACCES);
        }
        let helper = self.helper_for(tid, &theirs, &ours, domain)?;
        let sock = helper.sock.lock().unwrap_or_else(|p| p.into_inner());
        *helper.used.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
        if !send_lookup(*sock, base, flags, resolve, path) {
            return Err(libc::EIO);
        }
        match recv_fd_value(*sock) {
            Some((_, got)) if got >= 0 => Ok(got),
            Some((errno, _)) if errno > 0 => Err(errno),
            _ => Err(libc::EIO),
        }
    }

    /// `/proc/<n>/<file>` opened for task `tid`: would the tracee's own open
    /// get exactly this (see `reopen_as`)?
    fn proc_pid_plain(&self, tid: i32, fd: RawFd, seen: &str, ours: &Context) -> bool {
        let mut comps = seen.trim_start_matches('/').split('/').skip(1);
        let Some(n) = comps.next() else { return false };
        let mut file = comps.next().unwrap_or("");
        if file == "task" {
            // /proc/<n>/task/<t>/<file>
            let _ = comps.next();
            file = comps.next().unwrap_or("");
        }
        if PROC_PID_OPENER_BOUND.contains(&file) {
            return false;
        }
        // Dumpable under our uid: the kernel owns a process's entries by its
        // dump owner (root when it is not dumpable).
        // SAFETY: fstat into a zeroed stat buffer; geteuid cannot fail.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } == 0 && st.st_uid == unsafe { libc::geteuid() } {
            return true;
        }
        // Or in the guard's own user namespace, seen through the tracee's
        // procfs (the number is the tracee's view of it).
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(format!("/proc/{tid}/root/proc/{n}/ns/user")).map(|m| (m.dev(), m.ino()) == ours.ns[0]).unwrap_or(false)
    }

    fn helper_for(&self, tid: i32, theirs: &Context, ours: &Context, domain: Option<&Arc<crate::landlock_mirror::Domain>>) -> Result<Arc<Helper>, i32> {
        let mut helpers = self.helpers.lock().unwrap_or_else(|p| p.into_inner());
        helpers.retain(|_, h| Arc::strong_count(h) > 1 || h.used.lock().map(|u| u.elapsed() < IDLE).unwrap_or(false));
        if let Some(h) = helpers.get(theirs) {
            return Ok(h.clone());
        }
        // The namespaces to join, opened here (before the fork), in an order
        // the kernel allows: down the tracee's chain of user namespaces from
        // ours, each user namespace followed by the namespaces it owns (bwrap
        // `--disable-userns` nests one user namespace inside another, and the
        // box's network namespace belongs to the outer one).
        let plan = join_plan(tid, theirs, ours)?;
        let ns: Vec<(RawFd, libc::c_int)> = plan;
        let layers: Vec<RawFd> = domain.map(|d| d.layer_fds()).unwrap_or_default();
        let mut pair = [0 as RawFd; 2];
        // SAFETY: socketpair into our owned array.
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, pair.as_mut_ptr()) } != 0 {
            for (f, _) in &ns {
                unsafe { libc::close(*f) };
            }
            return Err(libc::EIO);
        }
        // Everything else is closed in the child before it does anything.
        let mut keep: Vec<RawFd> = vec![pair[1]];
        keep.extend(ns.iter().map(|(f, _)| *f));
        keep.extend(layers.iter().copied());
        // SAFETY: the child only makes syscalls on its own state, then serves.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            helper_main(pair[1], &ns, theirs.caps, &layers, &mut keep);
        }
        for (f, _) in &ns {
            unsafe { libc::close(*f) };
        }
        unsafe { libc::close(pair[1]) };
        if pid < 0 {
            unsafe { libc::close(pair[0]) };
            return Err(libc::EAGAIN);
        }
        let helper = Arc::new(Helper { sock: Mutex::new(pair[0]), pid, used: Mutex::new(Instant::now()) });
        // Its "ready", or EOF when it could not become the tracee.
        if recv_fd_value(pair[0]).is_none() {
            let mut status = 0;
            // SAFETY: reap the helper that gave up; its exit code names the step.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            debug(&format!("tid {tid}: namespaces differing (user,net,uts,ipc,cgroup): {:?}", (0..5).map(|i| theirs.ns[i] != ours.ns[i]).collect::<Vec<_>>()));
            debug(&format!("tid {tid}: helper could not become the tracee (exit {}: 20+n setns of the n-th differing namespace, +100 if EINVAL; 12 capset, 13 nnp, 14 landlock)", libc::WEXITSTATUS(status)));
            return Err(libc::EACCES);
        }
        helpers.insert(theirs.clone(), helper.clone());
        Ok(helper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_ro(p: &std::path::Path) -> Option<RawFd> {
        let c = std::ffi::CString::new(p.to_str()?).ok()?;
        // SAFETY: open with a NUL-terminated path; the caller closes it.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        (fd >= 0).then_some(fd)
    }

    /// runtime-instances.md §14.9: `classify` with its `fstat` shortcut gives
    /// the answer the `fstatfs` alone gave, over files on every kind of file
    /// system this host has: procfs (a process's entry and a global one),
    /// sysfs, a cgroup hierarchy, devtmpfs, tmpfs, and the build tree's own
    /// (a block device's on a developer host, where the shortcut is taken).
    /// Unprivileged.
    #[test]
    fn the_stat_shortcut_classifies_as_the_statfs_did() {
        let tmp = std::env::temp_dir().join(format!("mandu-classify-{}", std::process::id()));
        std::fs::write(&tmp, b"x").unwrap();
        let built = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let paths: Vec<std::path::PathBuf> = ["/proc/self/status", "/proc/meminfo", "/proc/self", "/sys/kernel", "/sys/fs/cgroup", "/dev/null", "/etc/hostname", "/"]
            .iter()
            .map(std::path::PathBuf::from)
            .chain([tmp.clone(), built])
            .collect();
        let mut shortcut = 0;
        for p in &paths {
            let Some(fd) = open_ro(p) else { continue };
            // SAFETY: fstat into a zeroed buffer.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0);
            if !fs_supervisor::tracee::may_be_pseudo_fs(st.st_dev) {
                shortcut += 1;
            }
            assert_eq!(classify(fd), classify_by_statfs(fd), "{}", p.display());
            assert_eq!(classify_stat(fd, Some(&st)), classify_by_statfs(fd), "{}", p.display());
            assert_eq!(classify_stat(fd, None), classify_by_statfs(fd), "{}", p.display());
            // SAFETY: our own descriptor.
            unsafe { libc::close(fd) };
        }
        let _ = std::fs::remove_file(&tmp);
        eprintln!("{shortcut} of {} files took the stat shortcut", paths.len());
        // A pseudo file is never taken for a real one.
        let fd = open_ro(std::path::Path::new("/proc/self/status")).expect("/proc/self/status");
        assert_eq!(classify(fd).0, Pseudo::ProcPid);
        // SAFETY: our own descriptor.
        unsafe { libc::close(fd) };
    }
}
