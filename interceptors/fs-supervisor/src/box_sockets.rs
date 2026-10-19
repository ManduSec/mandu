//! box_sockets — the command box's Unix-socket allow-list (exec-routing.md §4.2).
//!
//! A boxed command may connect only to Unix sockets the box itself bound. The
//! supervisor that traps the box's `connect` and `bind` (the box's own
//! listener, or the whole-agent guard when it holds the only listener the
//! kernel allows in the chain) keeps this registry:
//!
//! - **bind** runs as issued (it reaches nothing). The supervisor keeps a copy
//!   of the socket (`pidfd_getfd`) and, once the bind has completed, asks the
//!   kernel which file it created (`SIOCUNIXFILE`: an `O_PATH` descriptor of
//!   exactly the bound inode, no path re-resolved), and records that file's
//!   identity under the socket's network namespace.
//! - **connect** is performed by the supervisor: a pathname target is opened
//!   in the tracee's view (`tracee::open_unix_target`), its identity must be
//!   one the box bound, and the tracee's socket is connected to exactly that
//!   inode (`/proc/self/fd/N`). Every other address is connected as read, on
//!   the supervisor's copy of the socket. Nothing is CONTINUEd: the kernel
//!   would re-read the address and re-resolve the path.
//!
//! An identity is `(st_dev, st_ino)` plus the file's birth time (its change
//! time where the filesystem has none), so a reused inode never inherits a
//! dead socket's standing and no descriptor has to be held to pin one.
//!
//! The registry and the address classification are PURE (unit-tested with no
//! privilege); the kernel calls live behind the `kernel` feature.
//!
//! `Mandu-new`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// `AF_UNIX`, the same on every Linux arch (declared so the pure build needs
/// no libc).
const AF_UNIX: u16 = 1;

/// The path bytes of a PATHNAME `AF_UNIX` sockaddr (up to the first NUL), the
/// way the kernel's `unix_validate_addr` reads it: the family is `AF_UNIX`,
/// the address is longer than the family, and `sun_path[0]` is not NUL.
/// `None` for another family, an abstract or unnamed address, or a short one.
pub fn unix_pathname(raw: &[u8]) -> Option<&[u8]> {
    if raw.len() < 3 || u16::from_ne_bytes([raw[0], raw[1]]) != AF_UNIX || raw[2] == 0 {
        return None;
    }
    let p = &raw[2..];
    Some(&p[..p.iter().position(|b| *b == 0).unwrap_or(p.len())])
}

/// A socket file's identity: `(st_dev, st_ino)` and its birth time (or, on a
/// filesystem without one, its change time), as `(seconds, nanoseconds)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SockIdent {
    pub dev: u64,
    pub ino: u64,
    pub born: (i64, u32),
}

/// What asking a pending socket for its bound file gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Bound: the socket's network namespace (its cookie; 0 where the kernel
    /// has none) and the bound file's identity.
    Bound(u64, SockIdent),
    /// Not bound (yet): the bind may still be running.
    NotYet,
    /// It will never say (the kernel refused the question): drop it.
    Never,
}

/// How long a bound-but-unanswered socket copy is kept: a bind that failed
/// never answers, and the copy must not keep the socket alive for long.
pub const PENDING_GRACE: Duration = Duration::from_secs(2);
/// The most identities kept; the oldest go first (a connect to a forgotten
/// one is refused: fail-closed).
pub const OWN_CAP: usize = 16384;
/// The most socket copies waiting on their bind.
pub const PENDING_CAP: usize = 256;

/// The sockets the box bound, by network namespace. `S` is the supervisor's
/// copy of a socket whose bind has not been read back yet.
pub struct OwnSockets<S> {
    known: HashMap<u64, HashSet<SockIdent>>,
    order: VecDeque<(u64, SockIdent)>,
    pending: VecDeque<(S, Instant)>,
    cap: usize,
}

impl<S> Default for OwnSockets<S> {
    fn default() -> Self {
        Self::with_cap(OWN_CAP)
    }
}

impl<S> OwnSockets<S> {
    pub fn with_cap(cap: usize) -> Self {
        OwnSockets { known: HashMap::new(), order: VecDeque::new(), pending: VecDeque::new(), cap: cap.max(1) }
    }

    /// A pathname bind was issued on this socket (its copy): read it back on
    /// the next `settle`. Past `PENDING_CAP` the oldest copy is released
    /// (that socket is then never recorded: fail-closed).
    pub fn add_pending(&mut self, sock: S, now: Instant, release: impl FnOnce(S)) {
        if self.pending.len() >= PENDING_CAP {
            if let Some((old, _)) = self.pending.pop_front() {
                release(old);
            }
        }
        self.pending.push_back((sock, now));
    }

    /// Read back every pending bind: a bound one is recorded and its copy
    /// released; one still unbound after `PENDING_GRACE`, or one the kernel
    /// will not answer, is released unrecorded.
    pub fn settle(&mut self, now: Instant, mut probe: impl FnMut(&S) -> Probe, mut release: impl FnMut(S)) {
        let mut keep = VecDeque::with_capacity(self.pending.len());
        while let Some((sock, since)) = self.pending.pop_front() {
            match probe(&sock) {
                Probe::Bound(ns, id) => {
                    self.record(ns, id);
                    release(sock);
                }
                Probe::NotYet if now.saturating_duration_since(since) < PENDING_GRACE => keep.push_back((sock, since)),
                _ => release(sock),
            }
        }
        self.pending = keep;
    }

    /// Record a socket file the box bound, in network namespace `ns`.
    pub fn record(&mut self, ns: u64, id: SockIdent) {
        if !self.known.entry(ns).or_default().insert(id) {
            return;
        }
        self.order.push_back((ns, id));
        while self.order.len() > self.cap {
            if let Some((ns, id)) = self.order.pop_front() {
                if let Some(set) = self.known.get_mut(&ns) {
                    set.remove(&id);
                    if set.is_empty() {
                        self.known.remove(&ns);
                    }
                }
            }
        }
    }

    /// Did the box of network namespace `ns` bind this socket file?
    pub fn is_own(&self, ns: u64, id: &SockIdent) -> bool {
        self.known.get(&ns).map(|s| s.contains(id)).unwrap_or(false)
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(feature = "kernel")]
pub use live::*;

#[cfg(feature = "kernel")]
mod live {
    use super::{unix_pathname, OwnSockets, Probe, SockIdent};
    use crate::tracee::{open_unix_target, sockaddr_un_bytes, tracee_fd};
    use std::io::Error;
    use std::os::unix::io::RawFd;
    use std::sync::Mutex;
    use std::time::Instant;

    /// `SIOCUNIXFILE` (`SIOCPROTOPRIVATE + 0`, linux/un.h): an `O_PATH`
    /// descriptor of the file a Unix socket is bound to. Needs CAP_NET_ADMIN
    /// in the user namespace owning the socket's network namespace, which the
    /// supervisor holds over the box (bwrap creates the box's namespaces as
    /// a child of the supervisor's user namespace, owned by its uid).
    const SIOCUNIXFILE: libc::c_ulong = 0x89E0;
    /// `SO_NETNS_COOKIE` (kernel ≥ 5.14; asm-generic on both arches).
    const SO_NETNS_COOKIE: libc::c_int = 71;

    fn close_fd(fd: RawFd) {
        // SAFETY: closing a descriptor we own.
        unsafe { libc::close(fd) };
    }

    fn errno() -> i32 {
        Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
    }

    /// A socket's network namespace cookie; `None` before kernel 5.14.
    pub fn netns_cookie(fd: RawFd) -> Option<u64> {
        let mut v: u64 = 0;
        let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
        // SAFETY: getsockopt into a u64.
        let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, SO_NETNS_COOKIE, &mut v as *mut u64 as *mut libc::c_void, &mut len) };
        (rc == 0).then_some(v)
    }

    /// This process's own network namespace cookie (a throwaway socket's).
    pub fn own_netns_cookie() -> Option<u64> {
        // SAFETY: a throwaway socket, closed at once.
        let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if s < 0 {
            return None;
        }
        let c = netns_cookie(s);
        close_fd(s);
        c
    }

    /// The identity of an open descriptor: `(dev, ino)` and its birth time,
    /// or its change time where the filesystem records no birth.
    pub fn ident_of_fd(fd: RawFd) -> Option<SockIdent> {
        // SAFETY: statx on our descriptor (AT_EMPTY_PATH) into a zeroed buffer.
        let mut st: libc::statx = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::statx(fd, b"\0".as_ptr() as *const libc::c_char, libc::AT_EMPTY_PATH, libc::STATX_INO | libc::STATX_BTIME | libc::STATX_CTIME, &mut st)
        };
        if rc != 0 {
            return None;
        }
        let dev = libc::makedev(st.stx_dev_major, st.stx_dev_minor);
        let born = if st.stx_mask & libc::STATX_BTIME != 0 {
            (st.stx_btime.tv_sec, st.stx_btime.tv_nsec)
        } else {
            (st.stx_ctime.tv_sec, st.stx_ctime.tv_nsec)
        };
        Some(SockIdent { dev, ino: st.stx_ino, born })
    }

    /// Ask a socket copy which file its bind created (`SIOCUNIXFILE`).
    pub fn probe_bound(sock: RawFd) -> Probe {
        // SAFETY: SIOCUNIXFILE returns a new O_PATH descriptor or -1.
        let pf = unsafe { libc::ioctl(sock, SIOCUNIXFILE as _, 0) };
        if pf < 0 {
            return if errno() == libc::ENOENT { Probe::NotYet } else { Probe::Never };
        }
        let id = ident_of_fd(pf);
        close_fd(pf);
        match id {
            Some(id) => Probe::Bound(netns_cookie(sock).unwrap_or(0), id),
            None => Probe::Never,
        }
    }

    /// `connect(fd, raw)`: 0 or the errno.
    pub fn connect_raw(fd: RawFd, raw: &[u8]) -> i32 {
        // SAFETY: connect with a buffer of raw.len() bytes.
        let rc = unsafe { libc::connect(fd, raw.as_ptr() as *const libc::sockaddr, raw.len() as libc::socklen_t) };
        if rc == 0 { 0 } else { errno() }
    }

    /// The box's allow-list, shared by the supervisor's threads.
    #[derive(Default)]
    pub struct BoxSockets {
        reg: Mutex<OwnSockets<RawFd>>,
    }

    impl BoxSockets {
        pub fn new() -> Self {
            Self::default()
        }

        fn settle(reg: &mut OwnSockets<RawFd>) {
            reg.settle(Instant::now(), |s| probe_bound(*s), close_fd);
        }

        /// A `bind(sockfd, raw)` by `pid` (the address already read): a
        /// pathname Unix bind is kept to be read back once it has run. The
        /// caller answers CONTINUE; nothing here decides. `valid`: is the
        /// notification still pending (the pid still the tracee's)?
        pub fn note_bind(&self, pid: i32, sockfd: RawFd, raw: &[u8], valid: &dyn Fn() -> bool) {
            let mut reg = self.reg.lock().unwrap_or_else(|p| p.into_inner());
            Self::settle(&mut reg);
            if unix_pathname(raw).is_none() {
                return;
            }
            if let Ok(copy) = tracee_fd(pid, sockfd) {
                if valid() {
                    reg.add_pending(copy, Instant::now(), close_fd);
                } else {
                    close_fd(copy);
                }
            }
        }

        /// Is this file a socket the box bound, in the network namespace of
        /// the socket `sock`?
        pub fn is_own(&self, sock: RawFd, target: RawFd) -> bool {
            let mut reg = self.reg.lock().unwrap_or_else(|p| p.into_inner());
            Self::settle(&mut reg);
            let ns = netns_cookie(sock).unwrap_or(0);
            ident_of_fd(target).map(|id| reg.is_own(ns, &id)).unwrap_or(false)
        }

        /// Perform `connect(sockfd, raw)` for `pid`; the errno to answer
        /// (0 = connected). A pathname target must be a socket the box bound
        /// (else ECONNREFUSED, what a masked socket answers); any other
        /// address is connected as read. `foreign_netns`: a socket of this
        /// network namespace (the supervisor's own, which has a route out) is
        /// refused ENETUNREACH, as the box's own namespace would. `valid`: is
        /// the notification still pending? Checked after every lookup through
        /// `/proc/<pid>`, so a pid reused by another process is never acted on.
        pub fn connect_for(&self, pid: i32, sockfd: RawFd, raw: &[u8], foreign_netns: Option<u64>, valid: &dyn Fn() -> bool) -> i32 {
            let sock = match tracee_fd(pid, sockfd) {
                Ok(fd) => fd,
                Err(e) => return e.raw_os_error().unwrap_or(libc::EBADF),
            };
            let answer = if valid() { self.connect_copy(pid, sock, raw, foreign_netns, valid) } else { libc::ESRCH };
            close_fd(sock);
            answer
        }

        fn connect_copy(&self, pid: i32, sock: RawFd, raw: &[u8], foreign_netns: Option<u64>, valid: &dyn Fn() -> bool) -> i32 {
            if foreign_netns.is_some() && netns_cookie(sock) == foreign_netns {
                return libc::ENETUNREACH;
            }
            let Some(path) = unix_pathname(raw) else { return connect_raw(sock, raw) };
            let target = match open_unix_target(pid, path) {
                Ok(fd) => fd,
                // No openat2: nothing can be checked, so nothing connects.
                Err(libc::ENOSYS) => return libc::ECONNREFUSED,
                Err(e) => return e,
            };
            let answer = if !valid() {
                libc::ESRCH
            } else if self.is_own(sock, target) {
                connect_raw(sock, &sockaddr_un_bytes(&format!("/proc/self/fd/{target}")))
            } else {
                libc::ECONNREFUSED
            };
            close_fd(target);
            answer
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sun(path: &[u8]) -> Vec<u8> {
        let mut b = AF_UNIX.to_ne_bytes().to_vec();
        b.extend_from_slice(path);
        b
    }

    #[test]
    fn a_pathname_is_what_the_kernel_would_resolve() {
        assert_eq!(unix_pathname(&sun(b"/tmp/s.sock\0")), Some(&b"/tmp/s.sock"[..]));
        assert_eq!(unix_pathname(&sun(b"rel/s\0junk")), Some(&b"rel/s"[..]), "up to the first NUL");
        assert_eq!(unix_pathname(&sun(b"/no/nul")), Some(&b"/no/nul"[..]), "a full sun_path without NUL");
        assert_eq!(unix_pathname(&sun(b"\0abstract")), None, "abstract: the box's own namespace");
        assert_eq!(unix_pathname(&sun(b"")), None, "unnamed (autobind)");
        assert_eq!(unix_pathname(&[1]), None, "short");
        let mut inet = 2u16.to_ne_bytes().to_vec();
        inet.extend_from_slice(b"/tmp/x");
        assert_eq!(unix_pathname(&inet), None, "another family is never a path");
    }

    fn id(ino: u64, born: i64) -> SockIdent {
        SockIdent { dev: 7, ino, born: (born, 0) }
    }

    #[test]
    fn a_bind_is_recorded_once_it_has_run_and_only_in_its_namespace() {
        let t0 = Instant::now();
        let mut reg: OwnSockets<u32> = OwnSockets::default();
        let mut released = Vec::new();
        reg.add_pending(1, t0, |_| {});
        // Not bound yet: kept.
        reg.settle(t0, |_| Probe::NotYet, |s| released.push(s));
        assert_eq!(reg.pending_len(), 1);
        assert!(released.is_empty());
        // Bound: recorded under its namespace, the copy released.
        reg.settle(t0 + Duration::from_millis(5), |_| Probe::Bound(42, id(9, 100)), |s| released.push(s));
        assert_eq!(released, vec![1]);
        assert_eq!(reg.pending_len(), 0);
        assert!(reg.is_own(42, &id(9, 100)));
        assert!(!reg.is_own(43, &id(9, 100)), "another box's namespace");
        assert!(!reg.is_own(42, &id(9, 101)), "the same inode reborn is another file");
        assert!(!reg.is_own(42, &id(8, 100)));
    }

    #[test]
    fn a_bind_that_never_answers_is_dropped() {
        let t0 = Instant::now();
        let mut reg: OwnSockets<u32> = OwnSockets::default();
        let mut released = Vec::new();
        reg.add_pending(1, t0, |_| {});
        reg.add_pending(2, t0, |_| {});
        reg.settle(t0 + PENDING_GRACE, |s| if *s == 1 { Probe::NotYet } else { Probe::Never }, |s| released.push(s));
        released.sort();
        assert_eq!(released, vec![1, 2], "past the grace, and a refusal, both go");
        assert_eq!(reg.pending_len(), 0);
    }

    #[test]
    fn the_registry_is_bounded_and_forgets_the_oldest() {
        let mut reg: OwnSockets<u32> = OwnSockets::with_cap(2);
        reg.record(1, id(1, 1));
        reg.record(1, id(2, 1));
        reg.record(1, id(2, 1));
        reg.record(2, id(3, 1));
        assert!(!reg.is_own(1, &id(1, 1)), "the oldest is forgotten: its connects are refused");
        assert!(reg.is_own(1, &id(2, 1)));
        assert!(reg.is_own(2, &id(3, 1)));
        let t0 = Instant::now();
        let mut released = Vec::new();
        for s in 0..(PENDING_CAP as u32 + 3) {
            reg.add_pending(s, t0, |old| released.push(old));
        }
        assert_eq!(reg.pending_len(), PENDING_CAP);
        assert_eq!(released, vec![0, 1, 2], "the oldest copies go first");
    }
}
