//! guard_rights — a descriptor passed to a process holding a secret
//! (feature `kernel`, Linux; exec-routing.md §7.5, "A descriptor passed to a
//! holder", 2026-10-02).
//!
//! A holder may get a socket after its taint without connecting it: another
//! process passes it over `SCM_RIGHTS` (an unnamed socketpair from a parent,
//! or a Unix connection it already had), and the holder writes to it with
//! `write(2)`, which is not trapped. `recvmsg` is not trapped either (it is
//! the hot path of every IPC and UDP receiver). The guard judges the pass at
//! its SENDER instead: every `sendmsg` is already trapped and performed by
//! the guard (`guard_send`), which copies each descriptor it passes on. When
//! one of them is a socket the receiver could carry bytes out on (a
//! connected INET socket, a Unix socket connected to a named peer, or one
//! with descriptors of its own queued), the guard finds the receiving
//! socket with `sock_diag` (the sending socket's peer, or the socket bound
//! at the address a datagram names), the processes that hold it, and for
//! each that holds a secret judges the passed sockets exactly as the
//! taint-time sweep judges the sockets a reader already holds
//! (`send_guard::sweep_verdict`: a session proxy, or a binding). An unbound
//! one refuses the send (EACCES, the plan 10 §4.3 event, "receive a
//! connection to"). The receivers' egress gates are held until the send is
//! done, so a receiver becoming tainted meanwhile waits and its sweep sees
//! the descriptor in its queue. A listening socket, an unconnected one, a
//! file or a pipe passes as before (a holder's accept, its sends with an
//! address, its opens are judged where it uses them), except a writable
//! descriptor that is itself an exit (plan 13 §9 R4 (b), 2026-10-04,
//! `passed_exit`): a file on a mount that leaves the machine is judged
//! against the holder's `mount:` bindings, and a device other than the
//! terminal and the sinks that keep nothing refuses the send, since the
//! holder writes to it with no open the guard would see.
//!
//! Plan 13 §9 R1 (2026-10-02): a pass also JOINS two processes when what it
//! passes is a socket pair end, a connected Unix socket or a pipe end: the
//! receivers and the processes at its other end. When either side holds a
//! secret, the other becomes a holder before the send is performed
//! (`guard_flow::pass_flows`), its tree swept like a reader's pipe
//! receivers at a taint; one already holding a connection to an unbound
//! peer refuses the send. (A holder that makes a socket pair after its
//! taint and passes one end on, and an untainted process that passes one
//! end of its own pair to a holder, are the two shapes.)
//!
//! What a Unix socket already has queued is read with a peek
//! (`queued_rights`): the taint-time sweep refuses the raw open, and a
//! holder's accept refuses the connection, when a descriptor is queued (or
//! the queue cannot be seen through), since its receipt is no call the
//! guard sees.
//!
//! Not used: `SO_PASSRIGHTS` (Linux 6.16), which makes the kernel refuse
//! every descriptor sent to a socket. Sealing a holder's sockets refuses
//! benign passes too (Node's cluster hands a worker its listening socket
//! this way), and leaves a socket the holder binds after its taint
//! unsealed; judging what is passed refuses only a connection to an unbound
//! peer, on every kernel.
//!
//! `Mandu-new`.

#![cfg(all(feature = "kernel", target_os = "linux"))]

use std::os::unix::io::RawFd;

use crate::guard_kernel::{close_fd, sockopt_int, GuardConfig, TaintedRefusal};
use crate::send_guard::{self as sg, InFlightEgress, QueueCheck};

/// What a Unix socket has queued (`send_guard::queue_verdict`): a peek of
/// its receive queue, every descriptor it would deliver closed at once (the
/// peek hands the guard copies of them).
pub fn queued_rights(fd: RawFd) -> QueueCheck {
    let stream = sockopt_int(fd, libc::SO_TYPE) == Some(libc::SOCK_STREAM);
    let mut queued: libc::c_int = 0;
    if stream {
        // SAFETY: FIONREAD (SIOCINQ) into an int.
        if unsafe { libc::ioctl(fd, libc::FIONREAD, &mut queued) } != 0 {
            return QueueCheck::Unknown("SIOCINQ failed");
        }
        if queued <= 0 {
            return QueueCheck::Clear;
        }
        if queued as usize > sg::PEEK_MAX {
            return sg::queue_verdict(true, queued as usize, Some(0), false);
        }
    }
    let mut buf = vec![0u8; if stream { queued as usize } else { 65536 }];
    let mut cbuf = [0u64; 512];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: a zeroed msghdr over our buffers.
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    m.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    m.msg_controllen = std::mem::size_of_val(&cbuf) as _;
    // SAFETY: recvmsg with MSG_PEEK into our buffers.
    let n = unsafe {
        libc::recvmsg(
            fd,
            &mut m,
            libc::MSG_PEEK | libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
            QueueCheck::Clear
        } else {
            QueueCheck::Unknown("the peek failed")
        };
    }
    let mut rights = m.msg_flags & libc::MSG_CTRUNC != 0;
    // SAFETY: walk the control messages the kernel wrote; close each descriptor.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&m);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                rights = true;
                let data = libc::CMSG_DATA(c);
                let k = ((*c).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize) / 4;
                for i in 0..k {
                    let mut fdv: RawFd = -1;
                    std::ptr::copy_nonoverlapping(
                        data.add(i * 4),
                        &mut fdv as *mut RawFd as *mut u8,
                        4,
                    );
                    if fdv >= 0 {
                        close_fd(fdv);
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&m, c);
        }
    }
    sg::queue_verdict(stream, queued.max(0) as usize, Some(n as usize), rights)
}

/// One `unix_diag` query; None when the kernel cannot answer (no
/// `unix_diag`, a refused netlink socket).
fn unix_diag(ino: u32, show: u32, dump: bool) -> Option<Vec<sg::UnixDiag>> {
    // SAFETY: a netlink socket of ours, closed below.
    let s = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            sg::NETLINK_SOCK_DIAG,
        )
    };
    if s < 0 {
        return None;
    }
    let req = sg::unix_diag_request(1, ino, show, dump);
    // SAFETY: send our request buffer.
    if unsafe { libc::send(s, req.as_ptr() as *const libc::c_void, req.len(), 0) }
        != req.len() as isize
    {
        close_fd(s);
        return None;
    }
    let mut all = Vec::new();
    let mut buf = vec![0u8; 65536];
    let result = loop {
        // SAFETY: recv into our buffer.
        let n = unsafe { libc::recv(s, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            break None;
        }
        match sg::parse_unix_diag(&buf[..n as usize], dump) {
            Ok((mut socks, done)) => {
                all.append(&mut socks);
                if done {
                    break Some(all);
                }
            }
            Err(_) => break if dump { None } else { Some(Vec::new()) },
        }
    };
    close_fd(s);
    result
}

/// The peer inode of the Unix socket with inode `ino` (plan 13 D2: a
/// socket pair's other end); None when it has none or the kernel cannot say.
pub(crate) fn unix_peer_of(ino: u64) -> Option<u32> {
    let socks = unix_diag(ino as u32, sg::UDIAG_SHOW_PEER, false)?;
    socks.into_iter().find(|d| d.ino as u64 == ino).and_then(|d| d.peer).filter(|p| *p != 0)
}

/// The name the Unix socket with inode `ino` is bound to (`sun_path` bytes;
/// empty when unnamed). None when the kernel cannot say.
pub(crate) fn unix_name_of(ino: u32) -> Option<Vec<u8>> {
    let socks = unix_diag(ino, sg::UDIAG_SHOW_NAME, false)?;
    Some(socks.into_iter().find(|d| d.ino == ino).and_then(|d| d.name).unwrap_or_default())
}

fn inode_of(fd: RawFd) -> Option<(u64, u64)> {
    // SAFETY: fstat into a zeroed stat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev, st.st_ino))
}

fn is_socket(fd: RawFd) -> bool {
    // SAFETY: fstat into a zeroed stat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(fd, &mut st) == 0 && st.st_mode & libc::S_IFMT == libc::S_IFSOCK }
}

/// Where a pass's descriptors arrive.
pub enum Receiver<'a> {
    /// The sending socket's peer (a connected or paired socket).
    Peer,
    /// The socket bound at the path the checks pinned (`pin`, `O_PATH`).
    Path(RawFd),
    /// The socket bound to this abstract name (`sun_path` bytes, leading NUL).
    Abstract(&'a [u8]),
}

/// The inode of the receiving socket; Err when it cannot be found out.
fn receiving_inode(sender: RawFd, to: &Receiver) -> Result<Option<u32>, ()> {
    match to {
        Receiver::Peer => {
            let (_, ino) = inode_of(sender).ok_or(())?;
            let socks = unix_diag(ino as u32, sg::UDIAG_SHOW_PEER, false).ok_or(())?;
            Ok(socks
                .into_iter()
                .find(|d| d.ino as u64 == ino)
                .and_then(|d| d.peer)
                .filter(|p| *p != 0))
        }
        Receiver::Path(pin) => {
            let (dev, ino) = inode_of(*pin).ok_or(())?;
            let socks = unix_diag(0, sg::UDIAG_SHOW_VFS, true).ok_or(())?;
            Ok(socks
                .into_iter()
                .find(|d| {
                    d.vfs
                        .map(|(vi, vd)| vi as u64 == ino && sg::kernel_dev_to_user(vd) == dev)
                        .unwrap_or(false)
                })
                .map(|d| d.ino))
        }
        Receiver::Abstract(name) => {
            let socks = unix_diag(0, sg::UDIAG_SHOW_NAME, true).ok_or(())?;
            Ok(socks
                .into_iter()
                .find(|d| d.name.as_deref() == Some(*name))
                .map(|d| d.ino))
        }
    }
}

/// The processes (thread groups) holding socket inode `ino`, by their
/// descriptor tables.
fn holders_of(ino: u32) -> Vec<i32> {
    let want = format!("socket:[{ino}]");
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return out;
    };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        // A table hidden by an exec in progress is read once the exec has
        // ended, and one hidden past the bound counts as a holder (2026-10-17,
        // `pipe_flow::holds_any`: read inside the exec it was "holds
        // nothing", and a receiver of the pass went unjudged).
        if crate::pipe_flow::holds_any(pid, std::slice::from_ref(&want)) {
            out.push(pid);
        }
    }
    out
}

/// What a passed descriptor (the guard's copy) joins its receiver to, for
/// plan 13 §9 R1 (`guard_flow::PassedEnd`): a Unix socket with a peer (not a
/// listener), a pipe / FIFO, or (the file shapes, 2026-10-02) a regular file
/// (`object_flow`), with the access the receiver gets. None for anything
/// else (a listener, an INET socket: those are judged as exits above, or
/// where they are used; an `O_PATH` descriptor, whose reopen is an open).
fn passed_end(c: RawFd) -> Option<crate::guard_flow::PassedEnd> {
    // SAFETY: fstat into a zeroed stat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(c, &mut st) } != 0 {
        return None;
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFSOCK => {
            if sockopt_int(c, libc::SO_DOMAIN) != Some(libc::AF_UNIX) || sockopt_int(c, libc::SO_ACCEPTCONN) == Some(1) {
                return None;
            }
            let ino = st.st_ino;
            let peer = unix_peer_of(ino)?;
            let named = |i: u32| unix_name_of(i).map(|n| !n.is_empty()).unwrap_or(false);
            Some(crate::guard_flow::PassedEnd::Socket { ino, peer: format!("socket:[{peer}]"), own_named: named(ino as u32), peer_named: named(peer) })
        }
        libc::S_IFIFO => {
            let link = std::fs::read_link(format!("/proc/self/fd/{c}")).ok()?.to_str()?.to_string();
            // SAFETY: fcntl F_GETFL on our own descriptor.
            let fl = unsafe { libc::fcntl(c, libc::F_GETFL) };
            if fl < 0 {
                return None;
            }
            let acc = fl & libc::O_ACCMODE;
            Some(crate::guard_flow::PassedEnd::Pipe { link, reads: crate::pipe_flow::accmode_reads(acc), writes: crate::pipe_flow::accmode_writes(acc) })
        }
        // Plan 13 §9 R1, the file shapes: a regular file (a memfd, an
        // unlinked file, a `/dev/shm` file, any file).
        libc::S_IFREG => {
            // SAFETY: fcntl F_GETFL on our own descriptor.
            let fl = unsafe { libc::fcntl(c, libc::F_GETFL) };
            if fl < 0 || fl & libc::O_PATH != 0 {
                return None;
            }
            let acc = fl & libc::O_ACCMODE;
            let target = crate::object_flow::fd_object(c)?;
            Some(crate::guard_flow::PassedEnd::File { target, reads: crate::pipe_flow::accmode_reads(acc), writes: crate::pipe_flow::accmode_writes(acc) })
        }
        _ => None,
    }
}

/// Plan 13 §9 R4 (b), 2026-10-04: a passed descriptor that is an exit that
/// is a path: a writable descriptor of a file on a mount that leaves the
/// machine (`local_exits::mount_verdict`: its destination), or a writable
/// descriptor of a device other than the terminal and the sinks that keep
/// nothing (`device:…`, no binding admits it). None for anything else (a
/// read-only or `O_PATH` descriptor: what a holder does with it is a call
/// the guard judges). `sender`: whose mount namespace names the mount.
pub(crate) fn passed_exit(cfg: &GuardConfig, sender: i32, c: RawFd) -> Option<String> {
    use crate::local_exits as le;
    // SAFETY: fcntl F_GETFL on our own descriptor.
    let fl = unsafe { libc::fcntl(c, libc::F_GETFL) };
    if fl < 0 || fl & libc::O_PATH != 0 || !crate::pipe_flow::accmode_writes(fl & libc::O_ACCMODE) {
        return None;
    }
    // SAFETY: fstat into a zeroed stat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(c, &mut st) } != 0 {
        // A descriptor the guard holds and cannot stat: refused.
        return Some("mount:unknown".into());
    }
    let kind = st.st_mode & libc::S_IFMT;
    if kind == libc::S_IFCHR || kind == libc::S_IFBLK {
        let (major, minor) = le::dev_major_minor(st.st_rdev);
        if le::device_write_allowed(kind == libc::S_IFBLK, major, minor) {
            return None;
        }
        let seen = std::fs::read_link(format!("/proc/self/fd/{c}")).ok().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        return Some(le::device_destination(&seen, major, minor));
    }
    if kind != libc::S_IFREG {
        return None;
    }
    match le::mount_verdict(&le::fd_fs_facts(c, Some(sender)), &cfg.extra_remote_devs) {
        le::MountVerdict::Local => None,
        le::MountVerdict::Remote(dest) => Some(dest),
    }
}

/// Judge the descriptors a send passes (`copies`, the guard's copies) for
/// the processes that will receive them. `Ok(gates)`: pass them, and hold
/// `gates` until the send is done; `Err((dest, refusal))`: refuse the send.
/// `caller`: the sending process (plan 13 §9 R1: a pass can make it a
/// holder, and its sweep must not wait for this very send).
pub fn judge_pass(
    cfg: &GuardConfig,
    caller: i32,
    sender: RawFd,
    to: Receiver,
    copies: &[RawFd],
) -> Result<Vec<InFlightEgress>, (String, TaintedRefusal)> {
    // What could carry bytes out of a holder: classified as the sweep
    // classifies a socket a reader already holds.
    let mut passed = Vec::new();
    for c in copies {
        if !is_socket(*c) {
            continue;
        }
        let ino = inode_of(*c).map(|(_, i)| i).unwrap_or(0);
        let h = crate::guard_send::classify_copy(*c, ino);
        if !matches!(
            h,
            sg::HeldSocket::NotInet
                | sg::HeldSocket::OtherNetns
                | sg::HeldSocket::Listening
                | sg::HeldSocket::Unconnected
        ) {
            passed.push(h);
        }
    }
    // Plan 13 §9 R1: what joins two processes as a flow (a socket pair end,
    // a connected Unix socket, a pipe end), judged while any holder lives.
    // A regular file passed is listed for its receivers whether or not any
    // process holds a secret yet (`ObjectOpens::note`): a holder's write to a
    // file born moments ago looks only at the processes listed for it.
    let ends: Vec<crate::guard_flow::PassedEnd> = if cfg.secrets.is_some() {
        copies
            .iter()
            .filter_map(|c| passed_end(*c))
            .filter(|e| !cfg.tainted.is_empty() || matches!(e, crate::guard_flow::PassedEnd::File { .. }))
            .collect()
    } else {
        Vec::new()
    };
    // Plan 13 §9 R4 (b), 2026-10-04: a writable descriptor of a file on a
    // mount that leaves the machine, or of a device, handed to a holder that
    // never opens it. Listed whether or not anyone holds a secret yet, so
    // the receivers' gates below are entered (a receiver becoming a holder
    // meanwhile finds it queued, and its sweep refuses the raw open).
    let exits: Vec<String> = if cfg.secrets.is_some() { copies.iter().filter_map(|c| passed_exit(cfg, caller, *c)).collect() } else { Vec::new() };
    if (passed.is_empty() && ends.is_empty() && exits.is_empty()) || cfg.secrets.is_none() {
        return Ok(Vec::new());
    }
    let ino = match receiving_inode(sender, &to) {
        Ok(Some(i)) => i,
        // Nobody bound there, or no peer: nothing will receive it.
        Ok(None) => return Ok(Vec::new()),
        Err(()) => {
            return Err((
                "a descriptor whose receiver the guard cannot find (sock_diag)".into(),
                TaintedRefusal::default(),
            ))
        }
    };
    let receivers = holders_of(ino);
    for e in &ends {
        if let crate::guard_flow::PassedEnd::File { target, .. } = e {
            for r in &receivers {
                cfg.object_opens.note(*r, &target.keys);
            }
        }
    }
    // Plan 13 §9 R1 (C): a pass that joins a holder to an untainted process
    // makes the untainted side a holder before a byte can flow (the send is
    // performed after this), or refuses the send when that side already
    // holds a connection to an unbound peer. Before the receivers' gates
    // are entered: the sweep of a receiver waits for its egress in flight,
    // which these gates would be.
    crate::guard_flow::pass_flows(cfg, caller, &receivers, &ends)?;
    // A receiver becoming tainted meanwhile waits for this send, and then
    // its sweep sees the descriptor queued.
    let gates: Vec<InFlightEgress> = receivers.iter().map(|p| cfg.egress.enter(*p)).collect();
    for r in receivers {
        let own = crate::secret_open::own_key_of(r);
        let (held, chain) = crate::guard_flow::holder(cfg, r, &own);
        if !held {
            continue;
        }
        let Some(b) = crate::guard_send::taint_bindings(cfg, &own, chain) else {
            return Err(("a connection for a process holding a secret (the arbiter could not be asked for its bindings)".into(), TaintedRefusal::default()));
        };
        // A device: no binding admits it. A mount: its `mount:` binding.
        if let Some(dest) = exits.iter().find(|d| !d.starts_with("mount:") || !crate::local_exits::mount_bound(&b.bindings, d)) {
            return Err((dest.clone(), b));
        }
        let admitted = |ip, port, proto| {
            sg::is_session_proxy(ip, port, proto, &cfg.proxy_ports)
                || crate::guard_send::bindings_admit(cfg, &b.bindings, ip, port, proto)
        };
        let unix_admitted = |name: &str| crate::guard_send::unix_bindings_admit(&b.bindings, name);
        if let Err(dest) = sg::sweep_verdict(&passed, admitted, unix_admitted) {
            return Err((dest, b));
        }
    }
    Ok(gates)
}
