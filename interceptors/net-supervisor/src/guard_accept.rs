//! guard_accept — the KERNEL half of judging an accept (feature `kernel`,
//! Linux; exec-routing.md §7.5, "A holder's accept", 2026-10-02).
//!
//! Under a secret policy the filter hands `accept` and `accept4`
//! to the guard (`guard_filter`), and the guard performs the call on its copy
//! of the listening socket (`pidfd_getfd`):
//!
//! 1. the flags are checked as the kernel checks them, the socket copied;
//! 2. the guard waits for a connection the way the tracee's call would: at
//!    once on a non-blocking socket (EAGAIN when there is none), else on a
//!    thread of its own, polling, while the call is live and within
//!    `SO_RCVTIMEO` (a call the tracee stopped waiting for, a signal, takes
//!    no connection);
//! 3. inside the egress gate (`send_guard::EgressGate`), so a taint arriving
//!    meanwhile waits for this connection and its sweep sees it, the
//!    connection is judged (`accept_guard::accept_verdict`): a process that
//!    holds no secret gets it; a holder gets one from this machine or from a
//!    host its secrets are bound to, and a Unix connection unless its peer
//!    already queued a descriptor on it (`guard_rights::queued_rights`; one
//!    passed later is judged at its sender, `guard_rights`); any other is
//!    reset (`SO_LINGER` 0) and the call answers ECONNABORTED, with the
//!    plan 10 §4.3 event;
//! 3b. (plan 13 §9 R1, 2026-10-02) a holder's connection from a process of
//!    the guard's tree (a Unix client, or this machine's TCP client, found
//!    by the connection's two ends in `/proc/net/tcp{,6}`): that client
//!    receives what the holder writes back, so it becomes a holder flowing
//!    from it and its tree is swept before the holder gets the connection
//!    (`guard_flow::accepted_flow`); a client already holding a connection
//!    to an unbound peer has this one reset (ECONNABORTED);
//! 4. the peer's address is copied out as `move_addr_to_user` would, and the
//!    connection is installed in the tracee with `ADDFD` (`SEND`: its number
//!    is the call's answer, close-on-exec as `SOCK_CLOEXEC` asked; the
//!    guard's `accept4` gave it `SOCK_NONBLOCK` as asked).
//!
//! `Mandu-new`.

#![cfg(all(feature = "kernel", target_os = "linux"))]

use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

use fs_supervisor::kernel::notif_id_valid;
use fs_supervisor::tracee::tracee_fd;

use crate::accept_guard::{self as ag, AcceptVerdict, Accepted};
use crate::guard_kernel::{
    answer_errno, close_fd, inject, proto_of_fd, read_tracee_exact, socket_in_our_netns,
    sockopt_int, write_tracee, GuardConfig, TaintedRefusal,
};
use crate::send_guard::{self as sg, QueueCheck};

/// What the handler did with one accept (for the tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// The connection was installed in the tracee.
    Admitted,
    /// A holder's connection from an unbound peer, reset; ECONNABORTED.
    Refused { peer: String },
    /// The call failed as the kernel's would (the errno answered).
    Failed { errno: i32 },
    /// The call went away before a connection came (a signal, an exit).
    Gone,
}

/// Handle one trapped `accept` / `accept4` end to end (module docs). Runs on
/// a thread of its own: it may wait for a connection.
pub fn handle_accept_notif(
    listener: RawFd,
    cfg: &GuardConfig,
    notif: &libc::seccomp_notif,
) -> AcceptOutcome {
    let pid = notif.pid as i32;
    let nr = notif.data.nr as i64;
    let a = notif.data.args;
    let fail = |errno: i32| {
        answer_errno(listener, notif, errno);
        AcceptOutcome::Failed { errno }
    };
    let flags = match ag::accept_flags(nr, a[3]) {
        Ok(f) => f,
        Err(e) => return fail(e),
    };
    let copy = match tracee_fd(pid, a[0] as RawFd) {
        Ok(c) => c,
        Err(e) => {
            return fail(if e.raw_os_error() == Some(libc::EBADF) {
                libc::EBADF
            } else {
                libc::EACCES
            })
        }
    };
    let Some(family) = sockopt_int(copy, libc::SO_DOMAIN).map(|f| f as u16) else {
        close_fd(copy);
        return fail(libc::ENOTSOCK);
    };
    let got = wait_and_accept(listener, notif, copy, flags);
    close_fd(copy);
    let (conn, peer_raw) = match got {
        Ok(c) => c,
        Err(None) => return AcceptOutcome::Gone,
        Err(Some(e)) => return fail(e),
    };
    // The gate: a taint arriving now waits until this connection is the
    // tracee's (its sweep then sees it), and one recorded before is seen.
    let _in_flight = cfg
        .secrets
        .as_ref()
        .map(|_| cfg.egress.enter(crate::secret_open::tgid_of(pid)));
    let taint = crate::guard_send::taint_of(cfg, pid);
    let held = matches!(taint, Some((_, true, _)));
    let accepted = classify(conn, family, &peer_raw);
    let proto = proto_of_fd(conn);
    let mut refusal: Option<TaintedRefusal> = None;
    let verdict = ag::accept_verdict(held, &accepted, |ip, port| {
        let (own, _, chain) = taint.clone()?;
        let b = crate::guard_send::taint_bindings(cfg, &own, chain);
        let admitted = b
            .as_ref()
            .map(|b| crate::guard_send::bindings_admit(cfg, &b.bindings, ip, port, proto));
        refusal = Some(b.unwrap_or_default());
        admitted
    });
    let peer_text = match &accepted {
        Accepted::Inet { peer, port, .. } => match peer {
            IpAddr::V6(v6) => format!("[{v6}]:{port}/{}", proto.name()),
            v4 => format!("{v4}:{port}/{}", proto.name()),
        },
        Accepted::Unix => "unix".to_string(),
        Accepted::Other => format!("family {family}"),
        Accepted::OtherNetns => "another network namespace".to_string(),
    };
    if verdict == AcceptVerdict::Refuse {
        reset(conn);
        crate::guard_send::emit_tainted(
            cfg,
            "accept a connection from",
            &peer_text,
            &refusal.unwrap_or_default(),
        );
        answer_errno(listener, notif, ag::ECONNABORTED);
        return AcceptOutcome::Refused { peer: peer_text };
    }
    // A holder's Unix connection: what its peer queued before the accept is
    // read for descriptors (one sent later is judged at its sender).
    if held && accepted == Accepted::Unix {
        if let QueueCheck::Rights | QueueCheck::Unknown(_) =
            crate::guard_rights::queued_rights(conn)
        {
            reset(conn);
            crate::guard_send::emit_tainted(
                cfg,
                "accept a connection from",
                "unix: a peer that queued a descriptor",
                &TaintedRefusal::default(),
            );
            answer_errno(listener, notif, ag::ECONNABORTED);
            return AcceptOutcome::Refused {
                peer: "unix (descriptors queued)".into(),
            };
        }
    }
    // Plan 13 §9 R1 (A): a holder's connection from a process of the
    // guard's tree (a Unix client, this machine's TCP client): that process
    // receives what the holder writes back, so it becomes a holder flowing
    // from it before the holder gets the connection, and its tree is swept;
    // one that already holds a connection to an unbound peer refuses this
    // connection, as a reader already connected out refuses its raw open.
    if held {
        if let Some(client) = client_inode(conn, &accepted) {
            // Plan 13 §4.5.1, the proxy leg (2026-10-02): the client is the
            // session's net-proxy, re-originating a request of the agent or
            // of a tool process from outside the tree; the reply would reach
            // whichever process asked, unattributed. Reset.
            if let Some(why) = crate::guard_flow::relayed_by_proxy(cfg, client) {
                reset(conn);
                crate::guard_send::emit_tainted(
                    cfg,
                    "accept a connection from",
                    &format!("{peer_text}, relayed by {why}"),
                    &TaintedRefusal::default(),
                );
                answer_errno(listener, notif, ag::ECONNABORTED);
                return AcceptOutcome::Refused {
                    peer: format!("{peer_text} (relayed by the session's net-proxy)"),
                };
            }
            if let Err((dest, refusal)) = crate::guard_flow::accepted_flow(cfg, pid, client) {
                reset(conn);
                crate::guard_send::emit_tainted(
                    cfg,
                    "accept a connection from",
                    &format!("{peer_text}, whose process {} {dest}", crate::local_exits::held_exit_phrase(&dest).1),
                    &refusal,
                );
                answer_errno(listener, notif, ag::ECONNABORTED);
                return AcceptOutcome::Refused {
                    peer: format!("{peer_text} (its client {} {dest})", crate::local_exits::held_exit_phrase(&dest).1),
                };
            }
        }
    }
    // The peer's address, as `move_addr_to_user` copies it.
    if a[1] != 0 {
        if let Err(e) = copy_out_addr(listener, notif, a[1], a[2], &peer_raw) {
            close_fd(conn);
            return fail(e);
        }
    }
    let cloexec = if flags & ag::SOCK_CLOEXEC != 0 {
        libc::O_CLOEXEC
    } else {
        0
    };
    let r = inject(listener, notif, conn, cloexec);
    close_fd(conn);
    match r {
        Ok(()) => AcceptOutcome::Admitted,
        // The call went away between the accept and the answer: the
        // connection is closed (its peer sees it end).
        Err(_) => AcceptOutcome::Gone,
    }
}

/// Wait for and take one connection on `copy`, as the tracee's own call
/// would. `Err(None)`: the call went away first.
fn wait_and_accept(
    listener: RawFd,
    notif: &libc::seccomp_notif,
    copy: RawFd,
    flags: i32,
) -> Result<(RawFd, Vec<u8>), Option<i32>> {
    // SAFETY: fcntl F_GETFL on our own descriptor.
    let fl = unsafe { libc::fcntl(copy, libc::F_GETFL) };
    let nonblocking = fl >= 0 && fl & libc::O_NONBLOCK != 0;
    let listening = sockopt_int(copy, libc::SO_ACCEPTCONN) == Some(1);
    if nonblocking || !listening {
        // At once: a connection, EAGAIN, or the kernel's own refusal of a
        // socket that does not listen.
        return accept_once(copy, flags);
    }
    let timeout = rcvtimeo(copy);
    let started = Instant::now();
    loop {
        if !notif_id_valid(listener, notif.id) {
            return Err(None);
        }
        let mut pfd = libc::pollfd {
            fd: copy,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll one descriptor of ours, bounded.
        let rc = unsafe { libc::poll(&mut pfd, 1, 100) };
        if rc > 0 && pfd.revents != 0 {
            // Another accepter may take it first: then this blocks for the
            // next one, as the tracee's own call would.
            return accept_once(copy, flags);
        }
        if let Some(t) = timeout {
            if started.elapsed() >= t {
                return Err(Some(libc::EAGAIN));
            }
        }
    }
}

fn accept_once(copy: RawFd, flags: i32) -> Result<(RawFd, Vec<u8>), Option<i32>> {
    // SAFETY: a zeroed sockaddr_storage for accept4 to fill.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: accept4 into our buffer; the new descriptor is ours.
    let fd = unsafe {
        libc::accept4(
            copy,
            &mut ss as *mut _ as *mut libc::sockaddr,
            &mut len,
            libc::SOCK_CLOEXEC | (flags & ag::SOCK_NONBLOCK),
        )
    };
    if fd < 0 {
        return Err(Some(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO),
        ));
    }
    let n = (len as usize).min(std::mem::size_of::<libc::sockaddr_storage>());
    // SAFETY: the kernel wrote `n` bytes of the storage.
    let raw = unsafe { std::slice::from_raw_parts(&ss as *const _ as *const u8, n) }.to_vec();
    Ok((fd, raw))
}

/// `SO_RCVTIMEO` of the listener (an accept honors it), when set.
fn rcvtimeo(fd: RawFd) -> Option<Duration> {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: getsockopt into a timeval.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &mut tv as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 || (tv.tv_sec == 0 && tv.tv_usec == 0) {
        return None;
    }
    Some(Duration::from_secs(tv.tv_sec as u64) + Duration::from_micros(tv.tv_usec as u64))
}

fn local_ip(fd: RawFd) -> Option<IpAddr> {
    // SAFETY: getsockname into a sockaddr_storage.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe { libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len) } != 0 {
        return None;
    }
    // SAFETY: the kernel wrote `len` bytes.
    let bytes = unsafe { std::slice::from_raw_parts(&ss as *const _ as *const u8, len as usize) };
    match crate::guard::decode_sockaddr(bytes) {
        crate::guard::ConnTarget::Inet(e) => Some(e.ip),
        _ => None,
    }
}

/// What the accepted connection is (`accept_guard::Accepted`).
fn classify(conn: RawFd, family: u16, peer_raw: &[u8]) -> Accepted {
    match family {
        sg::AF_INET | sg::AF_INET6 => {
            if socket_in_our_netns(conn) == Some(false) {
                return Accepted::OtherNetns;
            }
            match crate::guard::decode_sockaddr(peer_raw) {
                crate::guard::ConnTarget::Inet(e) => Accepted::Inet {
                    peer: e.ip,
                    port: e.port,
                    local: local_ip(conn),
                },
                // An INET connection whose peer the guard cannot read is judged
                // as a peer from nowhere: a holder does not take it.
                _ => Accepted::Other,
            }
        }
        sg::AF_UNIX => Accepted::Unix,
        _ => Accepted::Other,
    }
}

/// Plan 13 §9 R1: the inode of the client socket of an accepted connection
/// on this machine: a Unix connection's peer (`unix_diag`), or the TCP
/// socket in this namespace's `/proc/net/tcp{,6}` whose local end is the
/// connection's peer and whose remote end is its local address. None for a
/// peer from elsewhere, another namespace, or one that is already gone.
fn client_inode(conn: RawFd, accepted: &Accepted) -> Option<u64> {
    match accepted {
        Accepted::Unix => {
            // SAFETY: fstat into a zeroed stat.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(conn, &mut st) } != 0 {
                return None;
            }
            crate::guard_rights::unix_peer_of(st.st_ino).map(u64::from)
        }
        Accepted::Inet { peer, port, .. } => {
            let (lip, lport) = local_addr(conn)?;
            for (table, v6) in [("tcp", false), ("tcp6", true)] {
                let Ok(text) = std::fs::read_to_string(format!("/proc/self/net/{table}")) else { continue };
                if let Some(ino) = sg::proc_net_inode_by_addrs(&text, (*peer, *port), (lip, lport), v6) {
                    return Some(ino);
                }
            }
            None
        }
        Accepted::Other | Accepted::OtherNetns => None,
    }
}

pub(crate) fn local_addr(fd: RawFd) -> Option<(IpAddr, u16)> {
    // SAFETY: getsockname into a sockaddr_storage.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe { libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len) } != 0 {
        return None;
    }
    // SAFETY: the kernel wrote `len` bytes.
    let bytes = unsafe { std::slice::from_raw_parts(&ss as *const _ as *const u8, len as usize) };
    match crate::guard::decode_sockaddr(bytes) {
        crate::guard::ConnTarget::Inet(e) => Some((e.ip, e.port)),
        _ => None,
    }
}

/// Reset a connection (`SO_LINGER` 0, then close): its peer sees it refused.
fn reset(fd: RawFd) {
    let lg = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: setsockopt of a linger struct; close our own descriptor.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &lg as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as u32,
        )
    };
    close_fd(fd);
}

/// The peer's address into the tracee's buffer: `*addrlen` read (EFAULT if
/// it cannot be, EINVAL if negative), at most that many bytes copied, the
/// full length written back.
fn copy_out_addr(
    listener: RawFd,
    notif: &libc::seccomp_notif,
    addr: u64,
    addrlen: u64,
    raw: &[u8],
) -> Result<(), i32> {
    let pid = notif.pid as i32;
    let ulen = read_tracee_exact(pid, addrlen, 4)
        .map(|b| i32::from_ne_bytes(b[..4].try_into().unwrap()))?;
    let n = ag::addr_copy_len(ulen, raw.len())?;
    if n > 0 {
        write_tracee(listener, notif, addr, &raw[..n]).map_err(|e| e.unwrap_or(libc::EFAULT))?;
    }
    write_tracee(listener, notif, addrlen, &(raw.len() as u32).to_ne_bytes())
        .map_err(|e| e.unwrap_or(libc::EFAULT))
}
