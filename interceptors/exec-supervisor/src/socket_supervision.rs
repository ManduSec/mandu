//! socket_supervision — who serves the command box's socket allow-list
//! (exec-routing.md §4.2), and the serving loop when the box does it itself.
//!
//! The box may connect only to Unix sockets it bound (`fs_supervisor::
//! box_sockets`). The kernel allows ONE seccomp listener in a process's filter
//! chain (`has_duplicate_listener`: a second `NEW_LISTENER` is EBUSY), so one
//! of three things holds for each box, decided in its forked child before it
//! execs bwrap:
//!
//! - **Own**: the child installs `seccomp_filter::box_socket_notify_filter`
//!   with a new listener; the parent copies the listener out of it
//!   (`pidfd_getfd`: an `SCM_RIGHTS` handoff would be a `sendmsg`, and this
//!   parent is the one that answers) and serves it on a thread while it waits
//!   for the box.
//! - **Guard**: EBUSY, and the whole-agent guard serves boxes
//!   (`MANDU_NET_GUARD_BOX_SOCKETS=1`, set by the launcher on the guard's
//!   launch): it traps every `connect` and `bind` of the agent's tree already
//!   and applies the same allow-list to a box's threads. The variable is
//!   inherited and could be set by the agent; that gains nothing, because a
//!   program able to wrap this binary in its own listener already runs outside
//!   every box (a boxed process cannot create a listener at all: EBUSY).
//! - **ConnectDenied**: no listener could be installed (a kernel without user
//!   notification or `pidfd_getfd`, an unsupported arch, a setuid bwrap, a
//!   foreign listener in the chain) and no guard serves the box: the box's
//!   deny-filter refuses every `connect` (fail-closed).
//!
//! `Mandu-new`.

#![cfg(feature = "kernel")]

use std::os::unix::io::RawFd;
use std::sync::Arc;

use fs_supervisor::box_sockets::{own_netns_cookie, BoxSockets};

use crate::kernel::{kernel_at_least, notif_id_valid, notif_recv, respond_continue, respond_errno};

/// How this box's connects are supervised (reported on `ExecOutcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BoxSocketMode {
    /// Not an AgentShell box (HumanShell, the legacy InProcess backend), or a
    /// test's control run.
    #[default]
    NotBoxed,
    /// The box's own listener, served by this process.
    Own,
    /// The whole-agent guard serves the box.
    Guard,
    /// Nobody can: every connect in the box is refused.
    ConnectDenied,
}

/// The launcher sets this on the guard's launch when the command box is on;
/// the guard then traps `bind` too and serves boxes' connects.
pub const GUARD_BOX_SOCKETS_ENV: &str = "MANDU_NET_GUARD_BOX_SOCKETS";

/// `SECCOMP_FILTER_FLAG_NEW_LISTENER` and `..._WAIT_KILLABLE_RECV` (kernel
/// ≥ 5.19: once the supervisor has received a notification, only a fatal
/// signal interrupts the tracee, so a connect the supervisor performed is
/// never restarted and performed twice).
const FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
const FLAG_WAIT_KILLABLE_RECV: libc::c_ulong = 1 << 5;

/// What the parent decided before the fork, for every attempt of this exec.
#[derive(Debug, Clone)]
pub(crate) struct SocketPlan {
    /// The notify program; empty = the box cannot have its own listener.
    pub prog: Vec<u8>,
    pub killable: bool,
    pub guard_serves: bool,
}

impl SocketPlan {
    /// `bwrap`: the bubblewrap the box runs (sandbox::resolve_bwrap).
    pub(crate) fn resolve(bwrap: Option<&str>) -> SocketPlan {
        let own_ok = kernel_at_least(5, 6) && !bwrap.is_some_and(bwrap_is_setuid);
        SocketPlan {
            prog: if own_ok { crate::seccomp_filter::box_socket_notify_filter() } else { Vec::new() },
            killable: kernel_at_least(5, 19),
            guard_serves: std::env::var(GUARD_BOX_SOCKETS_ENV).map(|v| v == "1").unwrap_or(false),
        }
    }
}

/// A setuid-root bwrap cannot run under `no_new_privs`, which a listener
/// needs; such a host takes the guard or the fail-closed posture.
fn bwrap_is_setuid(bwrap: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(bwrap)
        .ok()
        .map(|m| m.permissions().mode() & 0o4000 != 0 && {
            use std::os::unix::fs::MetadataExt;
            m.uid() == 0
        })
        .unwrap_or(false)
}

/// The two pipes of the child → parent listener handoff, all close-on-exec.
pub(crate) struct Handoff {
    /// The child writes one i32: its listener fd (≥ 0), -1 (the guard serves
    /// the box) or -2 (nobody: connect denied).
    pub report_r: RawFd,
    pub report_w: RawFd,
    /// The parent writes one byte: 1 = it holds the listener, 0 = it does not
    /// (the child then fails the box's setup).
    pub ack_r: RawFd,
    pub ack_w: RawFd,
}

const REPORT_GUARD: i32 = -1;
const REPORT_DENY: i32 = -2;

fn close_fd(fd: RawFd) {
    // SAFETY: closing a descriptor we own.
    unsafe { libc::close(fd) };
}

fn pipe_cloexec() -> Option<(RawFd, RawFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 writes two fds into our owned array.
    (unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == 0).then_some((fds[0], fds[1]))
}

impl Handoff {
    pub(crate) fn new() -> Option<Handoff> {
        let (report_r, report_w) = pipe_cloexec()?;
        let Some((ack_r, ack_w)) = pipe_cloexec() else {
            close_fd(report_r);
            close_fd(report_w);
            return None;
        };
        Some(Handoff { report_r, report_w, ack_r, ack_w })
    }
}

fn write_all(fd: RawFd, b: &[u8]) -> bool {
    let mut off = 0;
    while off < b.len() {
        // SAFETY: writing from our buffer.
        let n = unsafe { libc::write(fd, b[off..].as_ptr() as *const libc::c_void, b.len() - off) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

fn read_exact(fd: RawFd, b: &mut [u8]) -> bool {
    let mut off = 0;
    while off < b.len() {
        // SAFETY: reading into our buffer.
        let n = unsafe { libc::read(fd, b[off..].as_mut_ptr() as *mut libc::c_void, b.len() - off) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

/// CHILD side, after the fork and before bwrap is exec'd: install the box's
/// listener, or say who serves the box instead. `Ok(deny_connect)`; `Err(())`
/// = the parent could not take the listener (the caller fails the setup: the
/// filter is installed and nobody would answer it).
pub(crate) fn child_side(plan: &SocketPlan, h: &Handoff) -> Result<bool, ()> {
    close_fd(h.report_r);
    close_fd(h.ack_w);
    let installed = install_listener(&plan.prog, plan.killable);
    let (report, deny) = match installed {
        Ok(fd) => (fd, false),
        Err(libc::EBUSY) if plan.guard_serves => (REPORT_GUARD, false),
        Err(_) => (REPORT_DENY, true),
    };
    if !write_all(h.report_w, &report.to_ne_bytes()) {
        return Err(());
    }
    close_fd(h.report_w);
    let Ok(listener) = installed else {
        close_fd(h.ack_r);
        return Ok(deny);
    };
    let mut ack = [0u8; 1];
    let taken = read_exact(h.ack_r, &mut ack) && ack[0] == 1;
    close_fd(h.ack_r);
    // The box must never hold its own listener: it could answer itself.
    close_fd(listener);
    if taken { Ok(false) } else { Err(()) }
}

/// `no_new_privs` + the notify filter with a new listener. Err = the errno
/// (ENOSYS for an empty program).
fn install_listener(prog: &[u8], killable: bool) -> Result<RawFd, i32> {
    if prog.is_empty() {
        return Err(libc::ENOSYS);
    }
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS) on ourselves.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EPERM));
    }
    let fprog = libc::sock_fprog { len: (prog.len() / 8) as u16, filter: prog.as_ptr() as *mut libc::sock_filter };
    let mut flags = FLAG_NEW_LISTENER | if killable { FLAG_WAIT_KILLABLE_RECV } else { 0 };
    loop {
        // SAFETY: SET_MODE_FILTER; the kernel copies the program in.
        let fd = unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, flags, &fprog as *const libc::sock_fprog) };
        if fd >= 0 {
            return Ok(fd as RawFd);
        }
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL);
        // A kernel that predates WAIT_KILLABLE_RECV says EINVAL: retry without.
        if e == libc::EINVAL && flags & FLAG_WAIT_KILLABLE_RECV != 0 {
            flags = FLAG_NEW_LISTENER;
            continue;
        }
        return Err(e);
    }
}

/// PARENT side, right after the fork: read the child's report, take its
/// listener, start serving. The mode, and the server to stop once the box
/// has exited. A child that died before reporting fails its own setup.
/// `None`: no report came before `until` (the child is alive and stuck
/// before it, `crate::deadline`): the caller kills the box and refuses the
/// exec. Nothing was taken, and the child, which reads the ack next, sees
/// its end of file and fails its own setup if it ever gets that far.
pub(crate) fn parent_side(child: i32, h: Handoff, until: crate::deadline::Deadline) -> Option<(BoxSocketMode, Option<SocketServer>)> {
    close_fd(h.report_w);
    close_fd(h.ack_r);
    let mut b = [0u8; 4];
    let Some(got) = crate::deadline::read_exact_before(h.report_r, &mut b, until) else {
        close_fd(h.report_r);
        close_fd(h.ack_w);
        return None;
    };
    close_fd(h.report_r);
    let report = i32::from_ne_bytes(b);
    let result = match (got, report) {
        (false, _) => (BoxSocketMode::ConnectDenied, None),
        (true, REPORT_GUARD) => (BoxSocketMode::Guard, None),
        (true, n) if n < 0 => (BoxSocketMode::ConnectDenied, None),
        (true, n) => match fs_supervisor::tracee::tracee_fd(child, n).ok().and_then(SocketServer::spawn) {
            Some(server) => {
                if write_all(h.ack_w, &[1]) {
                    (BoxSocketMode::Own, Some(server))
                } else {
                    (BoxSocketMode::ConnectDenied, Some(server))
                }
            }
            None => {
                let _ = write_all(h.ack_w, &[0]);
                (BoxSocketMode::ConnectDenied, None)
            }
        },
    };
    close_fd(h.ack_w);
    Some(result)
}

/// The listener, closed when the loop and every connect worker are done.
struct Listener(RawFd);

impl Drop for Listener {
    fn drop(&mut self) {
        close_fd(self.0);
    }
}

/// The serving thread of a box's own listener.
pub(crate) struct SocketServer {
    stop_w: RawFd,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SocketServer {
    fn spawn(listener: RawFd) -> Option<SocketServer> {
        let Some((stop_r, stop_w)) = pipe_cloexec() else {
            close_fd(listener);
            return None;
        };
        let l = Arc::new(Listener(listener));
        match std::thread::Builder::new().name("box-sockets".into()).spawn(move || serve(l, stop_r)) {
            Ok(thread) => Some(SocketServer { stop_w, thread: Some(thread) }),
            Err(_) => {
                // The closure (the listener, the read end) was dropped with it.
                close_fd(stop_w);
                None
            }
        }
    }

    /// Stop serving (the box has exited) and join the loop, on drop. A
    /// connect worker still blocked in a connect finishes on its own.
    fn halt(&mut self) {
        if let Some(t) = self.thread.take() {
            let _ = write_all(self.stop_w, &[1]);
            let _ = t.join();
            close_fd(self.stop_w);
        }
    }
}

impl Drop for SocketServer {
    fn drop(&mut self) {
        self.halt();
    }
}

/// Read a sockaddr of `len` bytes at `addr` out of the tracee (suspended on
/// the notification). The errno its own call would have met: EINVAL past
/// `sockaddr_storage`, EFAULT for memory it cannot read.
fn read_sockaddr(pid: i32, addr: u64, len: u64) -> Result<Vec<u8>, i32> {
    const SOCKADDR_MAX: u64 = 128;
    if len > SOCKADDR_MAX {
        return Err(libc::EINVAL);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    if addr == 0 {
        return Err(libc::EFAULT);
    }
    let mut buf = vec![0u8; len as usize];
    let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
    let remote = libc::iovec { iov_base: addr as *mut libc::c_void, iov_len: buf.len() };
    // SAFETY: reads into our buffer of exactly iov_len bytes.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n != len as isize {
        return Err(libc::EFAULT);
    }
    Ok(buf)
}

fn serve(l: Arc<Listener>, stop_r: RawFd) {
    let sockets = Arc::new(BoxSockets::new());
    // The supervisor's own network namespace has a route out; a box thread
    // connecting a socket of it (inherited from the agent) is refused.
    let host_ns = own_netns_cookie();
    let (nr_connect, nr_bind) = crate::seccomp_filter::BOX_SOCKET_NRS;
    loop {
        let mut fds = [
            libc::pollfd { fd: l.0, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: stop_r, events: libc::POLLIN, revents: 0 },
        ];
        // SAFETY: poll over our two descriptors.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if rc < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        if fds[1].revents != 0 {
            break;
        }
        if fds[0].revents & libc::POLLIN == 0 {
            // POLLHUP: no task uses the filter any more.
            if fds[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                break;
            }
            continue;
        }
        // ENOENT: the tracee went away between the wakeup and the receive.
        let Ok(notif) = notif_recv(l.0) else { continue };
        let pid = notif.pid as i32;
        let sockfd = notif.data.args[0] as RawFd;
        let (addr, len) = (notif.data.args[1], notif.data.args[2]);
        let nr = notif.data.nr as u32;
        if nr == nr_bind {
            // bind reaches nothing: it runs as issued, and the file it creates
            // is read back before the next decision.
            if let Ok(raw) = read_sockaddr(pid, addr, len) {
                sockets.note_bind(pid, sockfd, &raw, &|| notif_id_valid(l.0, notif.id));
            }
            let _ = respond_continue(l.0, notif.id);
        } else if nr == nr_connect {
            // A connect can block (a full backlog): its own thread.
            let (lw, sockets) = (l.clone(), sockets.clone());
            let spawned = std::thread::Builder::new().name("box-connect".into()).spawn(move || {
                let l = lw;
                let answer = match read_sockaddr(pid, addr, len) {
                    Ok(raw) => sockets.connect_for(pid, sockfd, &raw, host_ns, &|| notif_id_valid(l.0, notif.id)),
                    Err(e) => e,
                };
                let _ = respond_errno(l.0, notif.id, answer);
            });
            if spawned.is_err() {
                let _ = respond_errno(l.0, notif.id, libc::EAGAIN);
            }
        } else {
            let _ = respond_errno(l.0, notif.id, libc::ENOSYS);
        }
    }
    close_fd(stop_r);
}
