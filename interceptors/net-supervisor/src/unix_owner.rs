//! Whose is a listening Unix socket? The allow list's second clause
//! (exec-routing.md §4.3, "The whole agent's Unix sockets"): a socket not on the list is
//! reachable only if its listener is the agent tree's own.
//!
//! `SO_PEERCRED` alone cannot say. It reports the pid NUMBER of whoever called
//! `listen()`, and the kernel keeps reporting that number after the process
//! exits; if the tree then gets the number (an agent can fork until it lands
//! on it), a HOST listener whose creator died would be judged the tree's
//! (fail-open). And a tree server whose listener was made by a parent that
//! then exited (ssh-agent's shape: listen, fork, exit) was refused.
//!
//! So the listener is judged by identities that cannot be reused while the
//! guard looks.
//!
//! **The bind record (2026-10-18), first.** Where the guard traps `bind`
//! with the allow-list on (`GuardConfig::unix_binds`), it performs each
//! Unix stream or seqpacket bind of the tree on a copy of the socket and,
//! once the bind succeeded, records the socket's COOKIE (`BindRecord`): the
//! tree gave that socket its name. A connect to an unlisted socket then looks
//! the listener up by name WITHOUT connecting (`sock_diag`: a socket file by
//! its `UNIX_DIAG_VFS` device and inode, an abstract name by its
//! `UNIX_DIAG_NAME` bytes, `record_verdict`): one listener found → ours iff
//! its cookie is recorded; more than one → refused; none in the guard's
//! network namespace (a listener in another, nobody listening, a kernel
//! without the attributes) → the probe below, as before. A listener the tree
//! inherited was named by the host before the tree saw it (a bind of a bound
//! socket fails, so it is never recorded), and calling `listen()` on it again
//! makes the tree its `listen()` caller but not its namer: refused. The
//! probe is a real connection, queued ahead of the client's (a one-accept
//! server's only accept took it); the lookup is not.
//!
//! **The probe (the fallback).** A probe connection of the guard's own is
//! kept open and the listener is judged by identities that cannot be reused
//! while it looks:
//!
//! 1. **Creator.** `SO_PEERPIDFD` (Linux ≥ 6.5) pins the `listen()` caller
//!    itself; none for a creator that exited. Alive, it decides: in the tree
//!    → ours, outside → not (a host service, whoever else holds a copy: a
//!    listener the agent inherited from its launcher is still the host's).
//!    Before 6.5 only the number is known: a live process outside the tree
//!    at that number → not ours (the creator, or the number's next owner:
//!    refused either way); otherwise the holders decide.
//! 2. **Holder** (the creator gone or unknown). `sock_diag` finds the
//!    listener by the probe: the listening
//!    socket whose queue (`UNIX_DIAG_ICONS`) holds the probe's inode, or,
//!    once the server accepted it, the probe's peer. A tree process that holds
//!    either socket (its fd table, confirmed by the socket COOKIE on a copy,
//!    never by the 32-bit inode number alone) → ours. `sock_diag` sees the
//!    guard's network namespace only; a listener in another is judged by 1,
//!    or by the accepted peer (always the guard's namespace: the kernel makes
//!    it in the connecting socket's).
//!
//! Every candidate process is pinned by a pidfd around its checks. Anything
//! unreadable (a non-dumpable holder, no `sock_diag`, an old kernel) is "not
//! shown to be ours": refused, never allowed.
//!
//! The parsing here is pure and unit-tested; the syscalls are in `sys`
//! (the `kernel` feature).

/// `SOCK_DIAG_BY_FAMILY` (linux/sock_diag.h).
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// `UDIAG_SHOW_NAME` / `UDIAG_SHOW_VFS` / `UDIAG_SHOW_PEER` /
/// `UDIAG_SHOW_ICONS` (linux/unix_diag.h).
pub const UDIAG_SHOW_NAME: u32 = 0x01;
pub const UDIAG_SHOW_VFS: u32 = 0x02;
pub const UDIAG_SHOW_PEER: u32 = 0x04;
pub const UDIAG_SHOW_ICONS: u32 = 0x08;
/// Attribute types: `UNIX_DIAG_NAME`, `UNIX_DIAG_VFS`, `UNIX_DIAG_PEER`,
/// `UNIX_DIAG_ICONS`.
const UNIX_DIAG_NAME: u16 = 0;
const UNIX_DIAG_VFS: u16 = 1;
const UNIX_DIAG_PEER: u16 = 2;
const UNIX_DIAG_ICONS: u16 = 3;
/// A listening socket's `sk_state`.
pub const TCP_LISTEN: u32 = 10;
/// "Any cookie" (`INET_DIAG_NOCOOKIE` in both halves).
pub const NO_COOKIE: u64 = u64::MAX;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_HDRLEN: usize = 16;
const UNIX_DIAG_MSG_LEN: usize = 16;

/// A socket as exactly as the kernel names it: its sockfs inode (32 bits,
/// reused after wrapping) and its cookie (64 bits, never reused).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockId {
    pub ino: u32,
    pub cookie: u64,
}

/// One `unix_diag_msg` with the attributes asked for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiagSock {
    pub ino: u32,
    pub cookie: u64,
    /// `UNIX_DIAG_PEER`: the connected peer's inode.
    pub peer: Option<u32>,
    /// `UNIX_DIAG_ICONS`: a listener's queued connections, each by the
    /// CONNECTING socket's inode.
    pub icons: Vec<u32>,
    /// `UNIX_DIAG_NAME`: the bound address after the family, as the binder
    /// passed it (an abstract name's leading NUL included).
    pub name: Option<Vec<u8>>,
    /// `UNIX_DIAG_VFS`: a pathname socket's file, `(inode, device)`, the
    /// device in the kernel's own encoding (`kernel_dev`).
    pub vfs: Option<(u32, u32)>,
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// A `SOCK_DIAG_BY_FAMILY` request for AF_UNIX: a dump of the sockets in
/// `states` (a bit per `sk_state`), or one socket by inode and cookie. Pure.
pub fn diag_request(states: u32, ino: u32, cookie: u64, show: u32, dump: bool, seq: u32) -> Vec<u8> {
    let len = NLMSG_HDRLEN + 24;
    let mut b = Vec::with_capacity(len);
    b.extend_from_slice(&(len as u32).to_ne_bytes());
    b.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    b.extend_from_slice(&(NLM_F_REQUEST | if dump { NLM_F_DUMP } else { 0 }).to_ne_bytes());
    b.extend_from_slice(&seq.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes());
    // struct unix_diag_req
    b.push(libc::AF_UNIX as u8);
    b.push(0);
    b.extend_from_slice(&0u16.to_ne_bytes());
    b.extend_from_slice(&states.to_ne_bytes());
    b.extend_from_slice(&ino.to_ne_bytes());
    b.extend_from_slice(&show.to_ne_bytes());
    b.extend_from_slice(&(cookie as u32).to_ne_bytes());
    b.extend_from_slice(&((cookie >> 32) as u32).to_ne_bytes());
    b
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_ne_bytes([s[0], s[1]]))
}

/// Parse one `recv` of `sock_diag` replies: the sockets, and whether the dump
/// is done. `Err(errno)` for an `NLMSG_ERROR` (errno positive) or a malformed
/// buffer (`EBADMSG`). Pure.
pub fn parse_diag(buf: &[u8]) -> Result<(Vec<DiagSock>, bool), i32> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + NLMSG_HDRLEN <= buf.len() {
        let len = u32_at(buf, off).ok_or(libc::EBADMSG)? as usize;
        let ty = u16_at(buf, off + 4).ok_or(libc::EBADMSG)?;
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            return Err(libc::EBADMSG);
        }
        let msg = &buf[off + NLMSG_HDRLEN..off + len];
        match ty {
            NLMSG_DONE => return Ok((out, true)),
            NLMSG_ERROR => {
                let e = u32_at(msg, 0).ok_or(libc::EBADMSG)? as i32;
                return Err(if e < 0 { -e } else { libc::EBADMSG });
            }
            SOCK_DIAG_BY_FAMILY => {
                if msg.len() < UNIX_DIAG_MSG_LEN {
                    return Err(libc::EBADMSG);
                }
                let mut s = DiagSock {
                    ino: u32_at(msg, 4).unwrap_or(0),
                    cookie: u64::from(u32_at(msg, 8).unwrap_or(0)) | (u64::from(u32_at(msg, 12).unwrap_or(0)) << 32),
                    ..Default::default()
                };
                let mut a = UNIX_DIAG_MSG_LEN;
                while a + 4 <= msg.len() {
                    let alen = u16_at(msg, a).unwrap_or(0) as usize;
                    let aty = u16_at(msg, a + 2).unwrap_or(0) & 0x3fff;
                    if alen < 4 || a + alen > msg.len() {
                        return Err(libc::EBADMSG);
                    }
                    let data = &msg[a + 4..a + alen];
                    match aty {
                        UNIX_DIAG_PEER => s.peer = u32_at(data, 0),
                        UNIX_DIAG_ICONS => s.icons = data.chunks_exact(4).map(|c| u32::from_ne_bytes([c[0], c[1], c[2], c[3]])).collect(),
                        UNIX_DIAG_NAME => s.name = Some(data.to_vec()),
                        UNIX_DIAG_VFS => s.vfs = u32_at(data, 0).zip(u32_at(data, 4)),
                        _ => {}
                    }
                    a += align4(alen);
                }
                out.push(s);
            }
            _ => {}
        }
        off += align4(len);
    }
    Ok((out, false))
}

/// The listener whose queue holds a connection from the socket `client`
/// (the probe). None if no listener or more than one lists it (a reused
/// inode number: no answer is better than a wrong one). Pure.
pub fn listener_queuing(socks: &[DiagSock], client: u32) -> Option<SockId> {
    let mut found = socks.iter().filter(|s| s.icons.contains(&client));
    let first = found.next()?;
    if found.next().is_some() {
        return None;
    }
    Some(SockId { ino: first.ino, cookie: first.cookie })
}

/// How a connect names its listener, for a look that does not connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerName<'a> {
    /// A socket file, by the `(st_dev, st_ino)` stat(2) gives the file the
    /// guard opened and pinned.
    File { dev: u64, ino: u64 },
    /// An abstract name: the address bytes after the family, the leading
    /// NUL included, exactly as long as the connect passed them.
    Abstract(&'a [u8]),
}

/// stat(2)'s `st_dev` in the kernel's own encoding (`MAJOR << 20 | MINOR`,
/// what `UNIX_DIAG_VFS` carries; glibc's `st_dev` interleaves the halves).
/// None if it does not fit (a major over 12 bits, a minor over 20). Pure.
pub fn kernel_dev(dev: u64) -> Option<u32> {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xffff_f000);
    let minor = (dev & 0xff) | ((dev >> 12) & 0xffff_ff00);
    (major <= 0xfff && minor <= 0xf_ffff).then_some(((major << 20) | minor) as u32)
}

/// The cookies of the sockets in `socks` (a dump of listeners) that `name`
/// names. None = the name cannot be looked up exactly (an inode over 32
/// bits, which `UNIX_DIAG_VFS` truncates; a device it cannot encode; an
/// "abstract" name without its leading NUL): the caller falls back. Pure.
pub fn listeners_named(socks: &[DiagSock], name: &ListenerName) -> Option<Vec<u64>> {
    match *name {
        ListenerName::File { dev, ino } => {
            let key = (u32::try_from(ino).ok()?, kernel_dev(dev)?);
            Some(socks.iter().filter(|s| s.vfs == Some(key)).map(|s| s.cookie).collect())
        }
        ListenerName::Abstract(bytes) => {
            if bytes.first() != Some(&0) {
                return None;
            }
            Some(socks.iter().filter(|s| s.name.as_deref() == Some(bytes)).map(|s| s.cookie).collect())
        }
    }
}

/// What the bind record says of a listener looked up by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordVerdict {
    /// The one listener of that name is a socket the tree bound.
    Ours,
    /// It is not (a host's, an inherited one, even one the tree called
    /// `listen()` on again), or more than one listener answers to the name
    /// (no answer is better than a wrong one).
    NotOurs,
    /// Nothing to judge by: no lookup (`listeners_named` None, `sock_diag`
    /// unavailable), or no listener of that name in the guard's network
    /// namespace (one in another, or nobody listening). The probe decides.
    Undecided,
}

/// `found`: the cookies of the listeners the name names (None: no
/// lookup); `recorded`: is a cookie in the bind record. Pure.
pub fn record_verdict(found: Option<&[u64]>, recorded: impl Fn(u64) -> bool) -> RecordVerdict {
    match found {
        None | Some([]) => RecordVerdict::Undecided,
        Some([c]) if recorded(*c) => RecordVerdict::Ours,
        Some(_) => RecordVerdict::NotOurs,
    }
}

/// The cookies of the Unix stream and seqpacket sockets the tree bound
/// (`GuardConfig::unix_binds`). A cookie is never reused, so an entry can
/// only go stale, never come to name another socket; stale entries are
/// pruned when the record reaches its cap, against the sockets that still
/// exist. Still full after that, a new socket is NOT recorded (its listener
/// is then refused: fail-closed), and `record` says so.
#[derive(Debug)]
pub struct BindRecord {
    cookies: std::sync::Mutex<std::collections::HashSet<u64>>,
    cap: usize,
}

impl BindRecord {
    /// The default cap: far above any real tree's live bound sockets, and a
    /// few hundred KiB at most.
    pub const DEFAULT_CAP: usize = 16384;

    pub fn new(cap: usize) -> Self {
        BindRecord { cookies: std::sync::Mutex::new(std::collections::HashSet::new()), cap }
    }

    /// Did the tree bind the socket with this cookie? A poisoned lock: no.
    pub fn contains(&self, cookie: u64) -> bool {
        self.cookies.lock().map(|s| s.contains(&cookie)).unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.cookies.lock().map(|s| s.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Record `cookie`. At the cap, first keep only the entries `live`
    /// still reports (the cookies of every Unix socket that exists; None:
    /// not known, nothing pruned). False = not recorded (still full, or a
    /// poisoned lock).
    pub fn record(&self, cookie: u64, live: impl FnOnce() -> Option<std::collections::HashSet<u64>>) -> bool {
        let Ok(mut set) = self.cookies.lock() else { return false };
        if set.contains(&cookie) {
            return true;
        }
        if set.len() >= self.cap {
            if let Some(alive) = live() {
                set.retain(|c| alive.contains(c));
            }
            if set.len() >= self.cap {
                return false;
            }
        }
        set.insert(cookie)
    }
}

/// What is known of a listener's `listen()` caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Creator {
    /// Alive and pinned (`SO_PEERPIDFD`): in the tree or not.
    Alive { in_tree: bool },
    /// Exited: no pidfd for it (EINVAL), or one of a dead process.
    Gone,
    /// A kernel without `SO_PEERPIDFD` (< 6.5): only the `SO_PEERCRED`
    /// number. `alive_outside`: a live process outside the tree has it.
    Unpinned { alive_outside: bool },
}

/// The creator's say before any holder is looked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreatorVerdict {
    Ours,
    NotOurs,
    AskHolders,
}

/// A live creator decides; a gone or unknown one leaves it to the holders.
/// Pure.
pub fn creator_verdict(c: Creator) -> CreatorVerdict {
    match c {
        Creator::Alive { in_tree: true } => CreatorVerdict::Ours,
        Creator::Alive { in_tree: false } | Creator::Unpinned { alive_outside: true } => CreatorVerdict::NotOurs,
        Creator::Gone | Creator::Unpinned { alive_outside: false } => CreatorVerdict::AskHolders,
    }
}

/// The inode of a `/proc/<pid>/fd/<n>` link to a socket (`socket:[N]`). Pure.
pub fn socket_link_inode(link: &str) -> Option<u32> {
    link.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

/// The `Pid:` of a pidfd's fdinfo, if the process is alive (the kernel
/// writes -1 once it exited). Pure.
pub fn fdinfo_pid(fdinfo: &str) -> Option<i32> {
    fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .and_then(|v| v.trim().parse::<i32>().ok())
        .filter(|p| *p > 0)
}

#[cfg(all(feature = "kernel", target_os = "linux"))]
pub mod sys {
    //! The syscalls behind the module's answer (see the module docs).
    use super::*;
    use crate::secret_open::{in_tree, parent_pid_of};
    use fs_supervisor::tracee::{pidfd_getfd, pidfd_open, read_proc_small};
    use std::os::unix::io::RawFd;

    /// `SO_PEERPIDFD` (Linux ≥ 6.5) and `SO_COOKIE`, asm-generic numbers
    /// (x86_64 and aarch64 alike).
    const SO_PEERPIDFD: libc::c_int = 77;
    const SO_COOKIE: libc::c_int = 57;
    const NETLINK_SOCK_DIAG: libc::c_int = 4;
    /// pidfd_send_signal (424, Linux ≥ 5.1; the same on both arches).
    const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;
    /// The most processes of the tree looked at for a holder.
    const MAX_TREE: usize = 8192;

    fn close_fd(fd: RawFd) {
        // SAFETY: closing a descriptor we own.
        unsafe { libc::close(fd) };
    }

    fn getsockopt_bytes<T: Copy + Default>(fd: RawFd, opt: libc::c_int) -> Option<T> {
        let mut v = T::default();
        let mut len = std::mem::size_of::<T>() as libc::socklen_t;
        // SAFETY: getsockopt into a T-sized buffer we own.
        let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, opt, &mut v as *mut T as *mut libc::c_void, &mut len) };
        (rc == 0 && len as usize == std::mem::size_of::<T>()).then_some(v)
    }

    /// A socket's cookie (`SO_COOKIE`).
    pub fn sock_cookie(fd: RawFd) -> Option<u64> {
        getsockopt_bytes::<u64>(fd, SO_COOKIE)
    }

    /// A socket's sockfs inode.
    fn sock_ino(fd: RawFd) -> Option<u32> {
        // SAFETY: fstat into a zeroed stat we own.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return None;
        }
        u32::try_from(st.st_ino).ok()
    }

    /// Is the pidfd's process still alive (signal 0; EPERM: it exists)?
    fn alive(pidfd: RawFd) -> bool {
        // SAFETY: pidfd_send_signal(pidfd, 0, NULL, 0) sends nothing.
        let rc = unsafe { libc::syscall(SYS_PIDFD_SEND_SIGNAL, pidfd, 0, std::ptr::null::<libc::c_void>(), 0) };
        rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    /// One `sock_diag` round trip (all the parts of a dump).
    fn diag(req: &[u8], dump: bool) -> Option<Vec<DiagSock>> {
        // SAFETY: a fresh netlink socket of our own, closed below.
        let s = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_SOCK_DIAG) };
        if s < 0 {
            return None;
        }
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        // SAFETY: setsockopt with a timeval we own.
        unsafe { libc::setsockopt(s, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const libc::timeval as *const libc::c_void, std::mem::size_of::<libc::timeval>() as libc::socklen_t) };
        // SAFETY: send a buffer of req.len() bytes.
        if unsafe { libc::send(s, req.as_ptr() as *const libc::c_void, req.len(), 0) } != req.len() as isize {
            close_fd(s);
            return None;
        }
        let mut out = Vec::new();
        let mut buf = vec![0u8; 32768];
        let ok = loop {
            // SAFETY: recv into our buffer.
            let n = unsafe { libc::recv(s, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n <= 0 {
                break false;
            }
            match parse_diag(&buf[..n as usize]) {
                Ok((socks, done)) => {
                    out.extend(socks);
                    if done || !dump {
                        break true;
                    }
                }
                Err(_) => break false,
            }
        };
        close_fd(s);
        ok.then_some(out)
    }

    /// The sockets that are the probe's listener, as far as this network
    /// namespace shows: the listener queuing the probe, and the probe's peer
    /// (the connection the server accepts). Empty = nothing to judge by.
    pub fn probe_keys(probe: RawFd) -> Vec<SockId> {
        let mut keys = Vec::new();
        let (Some(c_ino), Some(c_cookie)) = (sock_ino(probe), sock_cookie(probe)) else { return keys };
        if let Some(all) = diag(&diag_request(1 << TCP_LISTEN, 0, NO_COOKIE, UDIAG_SHOW_ICONS, true, 1), true) {
            keys.extend(listener_queuing(&all, c_ino));
        }
        // The peer, looked up by inode and confirmed by ITS peer being the
        // probe (an inode number can be reused; the cookie on the probe's
        // own lookup is exact).
        let peer = diag(&diag_request(u32::MAX, c_ino, c_cookie, UDIAG_SHOW_PEER, false, 2), false)
            .and_then(|v| v.into_iter().find(|s| s.ino == c_ino && s.cookie == c_cookie))
            .and_then(|s| s.peer);
        if let Some(e) = peer {
            let back = diag(&diag_request(u32::MAX, e, NO_COOKIE, UDIAG_SHOW_PEER, false, 3), false)
                .and_then(|v| v.into_iter().find(|s| s.ino == e));
            if let Some(s) = back.filter(|s| s.peer == Some(c_ino)) {
                keys.push(SockId { ino: s.ino, cookie: s.cookie });
            }
        }
        keys
    }

    /// The bind record's verdict on the listener `name` names, looked up
    /// in this network namespace without a connection (module docs).
    pub fn judge_by_record(record: &BindRecord, name: &ListenerName) -> RecordVerdict {
        let found = diag(&diag_request(1 << TCP_LISTEN, 0, NO_COOKIE, UDIAG_SHOW_NAME | UDIAG_SHOW_VFS, true, 4), true)
            .and_then(|all| listeners_named(&all, name));
        record_verdict(found.as_deref(), |c| record.contains(c))
    }

    /// The cookies of every Unix socket of this network namespace (the
    /// record's pruning). None = `sock_diag` gave no full answer.
    pub fn live_cookies() -> Option<std::collections::HashSet<u64>> {
        diag(&diag_request(u32::MAX, 0, NO_COOKIE, 0, true, 5), true).map(|v| v.into_iter().map(|s| s.cookie).collect())
    }

    /// Record a socket the tree just bound (`fd`: the guard's copy of it),
    /// if it is a Unix stream or seqpacket socket, the only kinds that
    /// listen. False = a listening kind that could not be recorded (no
    /// cookie, the record full): its listener will be refused.
    pub fn record_bound(record: &BindRecord, fd: RawFd) -> bool {
        let domain = getsockopt_bytes::<libc::c_int>(fd, libc::SO_DOMAIN);
        let ty = getsockopt_bytes::<libc::c_int>(fd, libc::SO_TYPE);
        if domain != Some(libc::AF_UNIX) || !matches!(ty, Some(libc::SOCK_STREAM) | Some(libc::SOCK_SEQPACKET)) {
            return true;
        }
        match sock_cookie(fd) {
            Some(c) => record.record(c, live_cookies),
            None => false,
        }
    }

    /// Does `pid` (pinned by `pidfd`) hold one of `keys`? Each descriptor
    /// whose link names a key's inode is copied and its cookie compared.
    fn holds(pid: i32, pidfd: RawFd, keys: &[SockId]) -> bool {
        let Ok(dir) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { return false };
        for e in dir.flatten() {
            let Ok(link) = std::fs::read_link(e.path()) else { continue };
            let Some(ino) = link.to_str().and_then(socket_link_inode) else { continue };
            let Some(key) = keys.iter().find(|k| k.ino == ino) else { continue };
            let Some(n) = e.file_name().to_str().and_then(|s| s.parse::<RawFd>().ok()) else { continue };
            let Ok(copy) = pidfd_getfd(pidfd, n) else { continue };
            let same = sock_cookie(copy) == Some(key.cookie);
            close_fd(copy);
            if same {
                return true;
            }
        }
        false
    }

    /// `pid`, pinned by a pidfd: in the tree, `check` holds of it, and still
    /// the same process afterwards (a live process keeps its number).
    fn pinned_tree_process(pid: i32, roots: &[i32], check: impl FnOnce(RawFd) -> bool) -> bool {
        let Ok(pf) = pidfd_open(pid) else { return false };
        let ok = check(pf) && in_tree(pid, roots, parent_pid_of) && alive(pf);
        close_fd(pf);
        ok
    }

    /// The tree's processes by `children` links from the roots (not by
    /// parent numbers), without `skip`.
    fn tree_pids(roots: &[i32], skip: &[i32]) -> Vec<i32> {
        let mut todo: Vec<i32> = roots.to_vec();
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        while let Some(p) = todo.pop() {
            if seen.len() > MAX_TREE || !seen.insert(p) {
                continue;
            }
            if !skip.contains(&p) {
                out.push(p);
            }
            let Ok(tasks) = std::fs::read_dir(format!("/proc/{p}/task")) else { continue };
            for t in tasks.flatten() {
                let Some(tid) = t.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
                if let Some(ch) = read_proc_small(&format!("/proc/{p}/task/{tid}/children")) {
                    todo.extend(ch.split_whitespace().filter_map(|c| c.parse::<i32>().ok()));
                }
            }
        }
        out
    }

    /// What `SO_PEERPIDFD` (or, before Linux 6.5, the `hint` number) says
    /// of the listener's `listen()` caller.
    fn creator(probe: RawFd, hint: Option<i32>, roots: &[i32]) -> Creator {
        let mut pf: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt into an int we own.
        let rc = unsafe { libc::getsockopt(probe, libc::SOL_SOCKET, SO_PEERPIDFD, &mut pf as *mut libc::c_int as *mut libc::c_void, &mut len) };
        if rc == 0 && pf >= 0 {
            let c = match read_proc_small(&format!("/proc/self/fdinfo/{pf}")).as_deref().and_then(fdinfo_pid) {
                Some(n) => {
                    let t = in_tree(n, roots, parent_pid_of);
                    // Still alive after the walk: the number was its all along.
                    if alive(pf) { Creator::Alive { in_tree: t } } else { Creator::Gone }
                }
                None => Creator::Gone,
            };
            close_fd(pf);
            return c;
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOPROTOOPT) {
            return Creator::Gone;
        }
        let alive_outside = hint.filter(|h| *h > 1).is_some_and(|h| match pidfd_open(h) {
            Ok(hf) => {
                let outside = !in_tree(h, roots, parent_pid_of) && alive(hf);
                close_fd(hf);
                outside
            }
            Err(_) => false,
        });
        Creator::Unpinned { alive_outside }
    }

    /// Is the listener behind `probe` (the guard's open probe connection)
    /// the tree's? `hint`: the pid `SO_PEERCRED` reported, never believed on
    /// its own. See the module docs.
    pub fn owned_by_tree(probe: RawFd, hint: Option<i32>, roots: &[i32]) -> bool {
        match creator_verdict(creator(probe, hint, roots)) {
            CreatorVerdict::Ours => return true,
            CreatorVerdict::NotOurs => return false,
            CreatorVerdict::AskHolders => {}
        }
        // A holder of the listener or of the accepted probe. The guard
        // itself is not asked: its workers hold copies while they check.
        let keys = probe_keys(probe);
        if keys.is_empty() {
            return false;
        }
        // SAFETY: getpid has no failure mode.
        let me = unsafe { libc::getpid() };
        let first = hint.filter(|h| *h > 1 && *h != me);
        if let Some(h) = first {
            if pinned_tree_process(h, roots, |pf| holds(h, pf, &keys)) {
                return true;
            }
        }
        let skip: Vec<i32> = [Some(me), first].into_iter().flatten().collect();
        tree_pids(roots, &skip).into_iter().any(|h| pinned_tree_process(h, roots, |pf| holds(h, pf, &keys)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nlmsg(ty: u16, payload: &[u8]) -> Vec<u8> {
        let len = NLMSG_HDRLEN + payload.len();
        let mut b = Vec::new();
        b.extend_from_slice(&(len as u32).to_ne_bytes());
        b.extend_from_slice(&ty.to_ne_bytes());
        b.extend_from_slice(&0u16.to_ne_bytes());
        b.extend_from_slice(&0u32.to_ne_bytes());
        b.extend_from_slice(&0u32.to_ne_bytes());
        b.extend_from_slice(payload);
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    fn attr(ty: u16, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        b.extend_from_slice(&ty.to_ne_bytes());
        b.extend_from_slice(data);
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    fn diag_msg(ino: u32, cookie: u64, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut p = vec![libc::AF_UNIX as u8, libc::SOCK_STREAM as u8, TCP_LISTEN as u8, 0];
        p.extend_from_slice(&ino.to_ne_bytes());
        p.extend_from_slice(&(cookie as u32).to_ne_bytes());
        p.extend_from_slice(&((cookie >> 32) as u32).to_ne_bytes());
        for a in attrs {
            p.extend_from_slice(a);
        }
        nlmsg(SOCK_DIAG_BY_FAMILY, &p)
    }

    fn icons(v: &[u32]) -> Vec<u8> {
        attr(UNIX_DIAG_ICONS, &v.iter().flat_map(|i| i.to_ne_bytes()).collect::<Vec<u8>>())
    }

    #[test]
    fn the_request_is_a_unix_diag_req_behind_a_netlink_header() {
        let r = diag_request(1 << TCP_LISTEN, 7, 0x1_0000_0002, UDIAG_SHOW_ICONS, true, 9);
        assert_eq!(r.len(), 40);
        assert_eq!(u32_at(&r, 0), Some(40));
        assert_eq!(u16_at(&r, 4), Some(SOCK_DIAG_BY_FAMILY));
        assert_eq!(u16_at(&r, 6), Some(NLM_F_REQUEST | NLM_F_DUMP));
        assert_eq!(u32_at(&r, 8), Some(9));
        assert_eq!(r[16], libc::AF_UNIX as u8);
        assert_eq!(u32_at(&r, 20), Some(1 << 10), "the states");
        assert_eq!(u32_at(&r, 24), Some(7), "the inode");
        assert_eq!(u32_at(&r, 28), Some(UDIAG_SHOW_ICONS));
        assert_eq!((u32_at(&r, 32), u32_at(&r, 36)), (Some(2), Some(1)), "the cookie, low half first");
        let one = diag_request(u32::MAX, 7, NO_COOKIE, UDIAG_SHOW_PEER, false, 1);
        assert_eq!(u16_at(&one, 6), Some(NLM_F_REQUEST), "an exact query is not a dump");
    }

    #[test]
    fn a_dump_parses_into_sockets_with_their_queues_and_peers() {
        let mut buf = diag_msg(100, 0xAB_0000_0001, &[icons(&[5, 6])]);
        buf.extend(diag_msg(200, 2, &[attr(UNIX_DIAG_PEER, &300u32.to_ne_bytes()), attr(9, &[1, 2, 3])]));
        let (socks, done) = parse_diag(&buf).unwrap();
        assert!(!done, "no NLMSG_DONE yet: the next recv continues the dump");
        assert_eq!(socks.len(), 2);
        assert_eq!((socks[0].ino, socks[0].cookie, socks[0].icons.clone()), (100, 0xAB_0000_0001, vec![5, 6]));
        assert_eq!((socks[1].peer, socks[1].icons.len()), (Some(300), 0), "an unknown attribute skipped");
        buf.extend(nlmsg(NLMSG_DONE, &0i32.to_ne_bytes()));
        assert!(parse_diag(&buf).unwrap().1);
    }

    #[test]
    fn an_error_or_a_torn_reply_is_no_answer() {
        assert_eq!(parse_diag(&nlmsg(NLMSG_ERROR, &(-libc::ESTALE).to_ne_bytes())), Err(libc::ESTALE));
        let whole = diag_msg(1, 1, &[icons(&[2])]);
        assert_eq!(parse_diag(&whole[..whole.len() - 4]), Err(libc::EBADMSG), "a message longer than the buffer");
        let mut bad_attr = diag_msg(1, 1, &[]);
        bad_attr.extend_from_slice(&[0xff, 0x00, 0x03, 0x00]);
        let len = bad_attr.len() as u32;
        bad_attr[..4].copy_from_slice(&len.to_ne_bytes());
        assert_eq!(parse_diag(&bad_attr), Err(libc::EBADMSG), "an attribute past its message");
    }

    #[test]
    fn the_listener_is_the_one_queuing_the_probe_and_only_if_unique() {
        let l = DiagSock { ino: 10, cookie: 11, icons: vec![3, 4], ..Default::default() };
        let other = DiagSock { ino: 20, cookie: 21, icons: vec![5], ..Default::default() };
        assert_eq!(listener_queuing(&[other.clone(), l.clone()], 4), Some(SockId { ino: 10, cookie: 11 }));
        assert_eq!(listener_queuing(&[other.clone()], 4), None, "accepted already, or another namespace");
        let twin = DiagSock { ino: 30, cookie: 31, icons: vec![4], ..Default::default() };
        assert_eq!(listener_queuing(&[l, twin], 4), None, "a reused inode number: no answer");
    }

    #[test]
    fn a_live_creator_decides_and_only_a_gone_one_leaves_it_to_the_holders() {
        use CreatorVerdict::*;
        assert_eq!(creator_verdict(Creator::Alive { in_tree: true }), Ours);
        // A host service's listener stays the host's even if the agent
        // inherited a copy (its launcher leaked one): no holder is asked.
        assert_eq!(creator_verdict(Creator::Alive { in_tree: false }), NotOurs);
        // The TODO's fail-open: the creator exited and the tree took its
        // number. The number decides nothing any more: the holders do.
        assert_eq!(creator_verdict(Creator::Gone), AskHolders);
        assert_eq!(creator_verdict(Creator::Unpinned { alive_outside: true }), NotOurs);
        assert_eq!(creator_verdict(Creator::Unpinned { alive_outside: false }), AskHolders, "before 6.5: a number in the tree proves nothing");
    }

    fn vfs(ino: u32, dev: u32) -> Vec<u8> {
        attr(UNIX_DIAG_VFS, &[ino.to_ne_bytes(), dev.to_ne_bytes()].concat())
    }

    #[test]
    fn a_dump_carries_each_listeners_name_and_file() {
        let mut buf = diag_msg(1, 0x10, &[attr(UNIX_DIAG_NAME, b"/run/a.sock\0"), vfs(77, 252 << 20)]);
        buf.extend(diag_msg(2, 0x20, &[attr(UNIX_DIAG_NAME, b"\0ab")]));
        let (socks, _) = parse_diag(&buf).unwrap();
        assert_eq!((socks[0].name.as_deref(), socks[0].vfs), (Some(&b"/run/a.sock\0"[..]), Some((77, 252 << 20))));
        assert_eq!((socks[1].name.as_deref(), socks[1].vfs), (Some(&b"\0ab"[..]), None), "an abstract socket has no file");
        let req = diag_request(1 << TCP_LISTEN, 0, NO_COOKIE, UDIAG_SHOW_NAME | UDIAG_SHOW_VFS, true, 4);
        assert_eq!(u32_at(&req, 28), Some(0x03), "the lookup asks for the name and the file");
    }

    #[test]
    fn stat_devices_are_put_in_the_kernels_encoding() {
        // 252:0 (a device-mapper volume): glibc's st_dev 0xfc00, the
        // kernel's s_dev 0x0fc0_0000 (what UNIX_DIAG_VFS reported for it).
        assert_eq!(kernel_dev(0xfc00), Some(0x0fc0_0000));
        // 0:42 (tmpfs): the same either way.
        assert_eq!(kernel_dev(42), Some(42));
        // 259:300 (an NVMe partition with a minor over 255).
        let glibc = (300 & 0xff) | (259 << 8) | ((300u64 & !0xff) << 12);
        assert_eq!(kernel_dev(glibc), Some((259 << 20) | 300));
        assert_eq!(kernel_dev(0x1000u64 << 32), None, "a major over 12 bits (glibc keeps its high part from bit 44) does not fit");
        assert_eq!(kernel_dev(1u64 << 32), None, "a minor over 20 bits (1 << 20) does not fit");
    }

    fn listener(cookie: u64, name: &[u8], file: Option<(u32, u32)>) -> DiagSock {
        DiagSock { ino: cookie as u32, cookie, name: Some(name.to_vec()), vfs: file, ..Default::default() }
    }

    #[test]
    fn a_listener_is_found_by_its_file_or_its_exact_abstract_name() {
        let socks = [
            listener(1, b"/a.sock\0", Some((7, 42))),
            listener(2, b"\0name", None),
            listener(3, b"\0name\0\0", None),
            listener(4, b"rel.sock\0", Some((8, 42))),
        ];
        assert_eq!(listeners_named(&socks, &ListenerName::File { dev: 42, ino: 7 }), Some(vec![1]));
        assert_eq!(listeners_named(&socks, &ListenerName::File { dev: 42, ino: 8 }), Some(vec![4]), "a relative bind's file is found by its identity");
        assert_eq!(listeners_named(&socks, &ListenerName::File { dev: 43, ino: 7 }), Some(vec![]), "another device");
        assert_eq!(listeners_named(&socks, &ListenerName::Abstract(b"\0name")), Some(vec![2]), "the length is part of an abstract name");
        assert_eq!(listeners_named(&socks, &ListenerName::Abstract(b"\0name\0\0")), Some(vec![3]));
        assert_eq!(listeners_named(&socks, &ListenerName::Abstract(b"\0nam")), Some(vec![]));
        assert_eq!(listeners_named(&socks, &ListenerName::File { dev: 42, ino: (1 << 32) | 7 }), None, "an inode the attribute truncates: no exact lookup");
        assert_eq!(listeners_named(&socks, &ListenerName::Abstract(b"/a.sock\0")), None, "not an abstract name");
        assert_eq!(listeners_named(&socks, &ListenerName::Abstract(b"")), None);
    }

    #[test]
    fn the_record_decides_one_listener_and_leaves_none_to_the_probe() {
        use RecordVerdict::*;
        let rec = |c: u64| c == 5;
        assert_eq!(record_verdict(Some(&[5]), rec), Ours, "a socket the tree bound");
        // An inherited host listener, also after the tree called listen()
        // on it again (the listen() caller is not the namer).
        assert_eq!(record_verdict(Some(&[6]), rec), NotOurs);
        assert_eq!(record_verdict(Some(&[5, 6]), rec), NotOurs, "two listeners of one name: no answer");
        assert_eq!(record_verdict(Some(&[5, 5]), rec), NotOurs);
        assert_eq!(record_verdict(Some(&[]), rec), Undecided, "another network namespace, or nobody listening");
        assert_eq!(record_verdict(None, rec), Undecided, "no lookup");
    }

    #[test]
    fn the_record_is_bounded_pruned_against_live_sockets_and_full_is_not_recorded() {
        use std::collections::HashSet;
        let r = BindRecord::new(2);
        assert!(r.is_empty());
        assert!(r.record(1, || panic!("no pruning below the cap")));
        assert!(r.record(2, || panic!("no pruning below the cap")));
        assert!(r.record(2, || panic!("already there")), "recording twice is no new entry");
        // At the cap: 1 is closed, so it goes and 3 comes in.
        assert!(r.record(3, || Some(HashSet::from([2, 3, 99]))));
        assert!(!r.contains(1) && r.contains(2) && r.contains(3));
        // Full of live sockets: not recorded (fail-closed), nothing lost.
        assert!(!r.record(4, || Some(HashSet::from([2, 3]))));
        assert!(!r.contains(4) && r.len() == 2);
        // The live set unknown: nothing pruned, nothing recorded.
        assert!(!r.record(5, || None));
        assert!(r.contains(2) && r.contains(3) && !r.contains(5));
    }

    #[test]
    fn socket_links_and_pidfd_info_parse() {
        assert_eq!(socket_link_inode("socket:[670590080]"), Some(670590080));
        assert_eq!(socket_link_inode("pipe:[12]"), None);
        assert_eq!(socket_link_inode("/tmp/socket:[1]"), None);
        assert_eq!(fdinfo_pid("pos:\t0\nflags:\t02000002\nPid:\t1290913\nNSpid:\t1290913\n"), Some(1290913));
        assert_eq!(fdinfo_pid("pos:\t0\nPid:\t-1\n"), None, "the process exited");
        assert_eq!(fdinfo_pid("pos:\t0\n"), None);
    }
}
