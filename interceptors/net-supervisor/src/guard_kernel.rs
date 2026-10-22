//! guard_kernel — the connect-guard's KERNEL enactment (feature `kernel`, Linux).
//!
//! Trap `connect(2)` with seccomp user-notification, read the target `sockaddr`
//! out of the tracee, ask the PURE `guard::GuardPolicy`, and enact:
//!   • DENY  → return `-EACCES` to the tracee (no connection is ever made);
//!   • ALLOW → perform the connect ON THE TRACEE'S BEHALF from the supervisor
//!             (grab the tracee's socket fd via `pidfd_getfd`, `connect()` it to
//!             the address WE decoded, and answer the syscall with that result),
//!             which is TOCTOU-safe (a racing thread cannot swap the address
//!             between the check and the actual connect) and, because the
//!             supervisor lives OUTSIDE the Landlock port wrap, works regardless
//!             of the coarse port posture (exec-routing.md §7.5);
//!   • non-INET family (AF_UNIX &c.) or a different network namespace →
//!             `CONTINUE` (pass through — the arbiter's own AF_UNIX socket keeps
//!             working; a nested net-dead box stays confined by its OWN netns).
//!             Except on WSL (`GuardConfig::wsl`): the Windows interop socket
//!             and any AF_VSOCK address → `-EACCES` (exec-routing.md §4.1).
//!             A pathname AF_UNIX connect a check applies to (WSL, a secret
//!             socket, a tainted process) is supervised instead: the guard
//!             opens the target in the tracee's view, checks that inode and
//!             connects the tracee's socket to it (`supervised_unix_connect`).
//!
//! UNPRIVILEGED — and MORE portable than the Landlock-net wrap: seccomp
//! `NEW_LISTENER` needs only `no_new_privs` (settable by ANY process), NOT
//! CAP_SYS_ADMIN, a user namespace, or root (empirically confirmed as a plain
//! unprivileged uid); `pidfd_getfd` (the supervisor-connect enact) works
//! parent→child unprivileged. So the only real floor is kernel version — ≥ 5.0
//! for USER_NOTIF, ≥ 5.5 for CONTINUE, ≥ 5.6 for the supervisor-connect enact —
//! versus Landlock-net's ≥ 6.7 (ABI 4). It touches NO global host state, so it
//! sits well inside the non-root privilege boundary — unlike the TPROXY leg
//! (`kernel.rs`: root + host-global nftables), which is DECIDED won't-implement
//! (2026-07-16; permanently out of scope under the non-root principle,
//! privilege-model.md §0 — not deferred work), making this guard the permanent
//! kernel-leg egress answer. It reuses fs-supervisor's
//! seccomp ioctl plumbing rather than re-deriving it.
//!
//! `Mandu-new`.

#![cfg(all(feature = "kernel", target_os = "linux"))]

use std::io::{Error, ErrorKind, Result};
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fs_supervisor::kernel::{
    kernel_at_least, notif_id_valid, notif_recv, respond_continue, respond_errno, set_no_new_privs,
};

/// Re-exported so the connect-guard's integration test can RECV a notification
/// through this crate's API (the seccomp ioctl plumbing is fs-supervisor's).
pub use fs_supervisor::kernel::notif_recv as recv_notif;

use crate::guard::{decode_sockaddr, ConnTarget, Decision, Endpoint, GuardPolicy, HostResolver, Proto};

/// `connect(2)` syscall number, pinned to the host arch from libc.
const SYS_CONNECT: libc::c_long = libc::SYS_connect;

/// SPIKE (confidentiality-plan-10-flow-taint.md §7.1): also trap the open
/// family and answer CONTINUE at once, to measure the pure cost of routing
/// every open in the agent tree through this supervisor. Env-gated
/// (`MANDU_NET_GUARD_TRAP_OPEN=1`), never on by default; no path is read.
pub const TRAP_OPEN_ENV: &str = "MANDU_NET_GUARD_TRAP_OPEN";
use crate::guard_filter::SYS_INTROSPECT;
/// policy.yaml `protect:` (or the launcher's write-protect list) is in the
/// secret policy file: trap `bind` too, to judge a socket file like any new
/// file (learn-from-nono §4 item 8). Set by the launcher. The delete / rename
/// and write families are trapped under every secret policy without it since
/// 2026-10-04 (plan 13 §9 R4 (b)).
pub const PROTECT_ENV: &str = "MANDU_NET_GUARD_PROTECT";
pub fn protect_requested() -> bool {
    std::env::var_os(PROTECT_ENV).map(|v| v == "1").unwrap_or(false)
}

/// exec-routing.md §4.2: the launcher runs the command box too, and the
/// kernel allows one seccomp listener per filter chain, so the guard serves
/// the box's socket allow-list: it traps `bind` as well and applies
/// `fs_supervisor::box_sockets` to a box's `connect`s. Read by the box too
/// (`exec_supervisor::socket_supervision`), to know the guard serves it.
pub const BOX_SOCKETS_ENV: &str = "MANDU_NET_GUARD_BOX_SOCKETS";
pub fn box_sockets_requested() -> bool {
    std::env::var_os(BOX_SOCKETS_ENV).map(|v| v == "1").unwrap_or(false)
}
/// The command box's binary: a process below it in its own network namespace
/// is a boxed process (`is_box_thread`).
pub const BOX_ANCESTOR: &str = "mandu-exec-box";

/// confidentiality.md §7.2a: the guard serves the twins with no bind (the
/// guard-only posture), so it also answers a stat by path of a twinned file
/// with the twin's metadata (`stat_twin`). Set by the launcher.
pub const STAT_TWINS_ENV: &str = "MANDU_NET_GUARD_STAT_TWINS";
pub fn stat_twins_requested() -> bool {
    std::env::var_os(STAT_TWINS_ENV).map(|v| v == "1").unwrap_or(false)
}

/// confidentiality.md §7.2a "The size a reader sees" (2026-10-04): with the
/// stat trap, which `lstat`s of a path the guard answers too. Unset (the
/// launcher's guard-only posture): `LstatTrap::Cwd`. `0`: none (`lstat` runs
/// free, the residual before 2026-10-04); `all`: every one, a directory
/// descriptor's too. Read only with `STAT_TWINS_ENV`.
pub const LSTAT_TWINS_ENV: &str = "MANDU_NET_GUARD_LSTAT_TWINS";
pub fn lstat_twins_requested() -> crate::guard_filter::LstatTrap {
    crate::guard_filter::LstatTrap::from_env_value(std::env::var(LSTAT_TWINS_ENV).ok().as_deref())
}

/// supported-agents.md §2.3.1: the agent's executable for the private-server
/// allowance (`own_server::OWN_SERVER_ENV`), or None (off). Set by the
/// launcher for an OpenCode 2 launch.
pub fn own_server_exe_requested() -> Option<String> {
    crate::own_server::exe_from_env_value(std::env::var(crate::own_server::OWN_SERVER_ENV).ok().as_deref())
}

pub fn trap_open_requested() -> bool {
    std::env::var_os(TRAP_OPEN_ENV).map(|v| v == "1").unwrap_or(false)
}

/// The largest sockaddr we read back (== `sizeof(struct sockaddr_storage)`); a
/// connect addrlen never exceeds this.
const SOCKADDR_MAX: usize = 128;

// ── seccomp filter install: trap connect(2) → USER_NOTIF ─────────────────────

/// Install a seccomp filter on the CURRENT thread that traps `connect(2)` with
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER`, returning the listener fd. The caller must
/// have set `no_new_privs` first (see `install_connect_filter_self`). Mirrors
/// fs-supervisor's openat listener, but for the network egress syscall.
pub fn install_connect_listener() -> Result<RawFd> {
    install_listener(false)
}

pub use crate::guard_filter::FilterTraps;

impl FilterTraps {
    pub fn from_env() -> Self {
        let secrets = secrets_policy_requested();
        FilterTraps {
            open: trap_open_requested() || secrets,
            secrets,
            protect: protect_requested(),
            box_sockets: box_sockets_requested(),
            own_server: own_server_exe_requested().is_some(),
            guard_pid: 0,
            stat: stat_twins_requested(),
            lstat: lstat_twins_requested(),
            no_sends: !kernel_at_least(crate::guard_filter::SEND_TRAP_MIN_KERNEL.0, crate::guard_filter::SEND_TRAP_MIN_KERNEL.1),
        }
    }
}

/// The filter builder: connect(2) always; the open family too under the §7.1
/// spike (`trap_open`); the rest as the launch's variables say.
pub fn install_listener(trap_open: bool) -> Result<RawFd> {
    install_listener_traps(FilterTraps { open: trap_open, ..FilterTraps::from_env() })
}

/// `install_listener` with the traps given, not read from the environment.
/// The program is `guard_filter::build_program` (pure, unit-tested there).
pub fn install_listener_traps(t: FilterTraps) -> Result<RawFd> {
    let mut prog = crate::guard_filter::build_program(&t);
    let mut fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };
    // SAFETY: SET_MODE_FILTER + NEW_LISTENER; the kernel copies the program in.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &mut fprog as *mut libc::sock_fprog,
        )
    };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    Ok(fd as RawFd)
}

/// Child side of handing the listener to the supervisor (exec-routing.md §7.5,
/// 2026-10-01). The filter now traps `sendmsg`, and the one process that
/// would answer the child's `sendmsg` of the listener is the supervisor
/// waiting for it: a deadlock. So the child names the descriptor by NUMBER
/// (and its pid) with `write(2)`, which no filter traps, and the supervisor
/// copies it out with `pidfd_getfd` (`receive_listener`). `by_number` false
/// (a kernel without `pidfd_getfd`, where the filter traps no send:
/// `FilterTraps::no_sends`) sends it over `SCM_RIGHTS` as before. Returns
/// once the supervisor holds its copy (it answers one byte), so the child
/// may close the listener then. Makes only system calls on the stack: safe
/// between fork and exec.
pub fn hand_listener(sock: RawFd, listener: RawFd, by_number: bool) -> bool {
    if !offer_listener(sock, listener, by_number) {
        return false;
    }
    let mut ack = 0u8;
    // SAFETY: a one-byte read into a local.
    unsafe { libc::read(sock, &mut ack as *mut u8 as *mut libc::c_void, 1) == 1 }
}

fn offer_listener(sock: RawFd, listener: RawFd, by_number: bool) -> bool {
    // SAFETY: getpid has no failure mode.
    let pid = unsafe { libc::getpid() };
    let mut payload = [0u8; 8];
    payload[..4].copy_from_slice(&(if by_number { listener } else { -1 }).to_ne_bytes());
    payload[4..].copy_from_slice(&pid.to_ne_bytes());
    if by_number {
        // SAFETY: an 8-byte write from a stack buffer.
        return unsafe { libc::write(sock, payload.as_ptr() as *const libc::c_void, 8) } == 8;
    }
    let mut iov = libc::iovec { iov_base: payload.as_mut_ptr() as *mut libc::c_void, iov_len: 8 };
    let mut cmsg_buf = [0u64; 4];
    // SAFETY: a zeroed msghdr over stack buffers; one SCM_RIGHTS message.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = std::mem::size_of_val(&cmsg_buf) as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(&listener as *const RawFd as *const u8, libc::CMSG_DATA(cmsg), std::mem::size_of::<RawFd>());
        msg.msg_controllen = (*cmsg).cmsg_len as _;
        libc::sendmsg(sock, &msg, 0) == 8
    }
}

/// Supervisor side of `hand_listener`: the listener (a descriptor of our
/// own) and the child's pid.
pub fn receive_listener(sock: RawFd) -> Result<(RawFd, i32)> {
    let mut payload = [0u8; 8];
    let mut iov = libc::iovec { iov_base: payload.as_mut_ptr() as *mut libc::c_void, iov_len: 8 };
    let mut cmsg_buf = [0u64; 4];
    // SAFETY: recvmsg into owned buffers; the control message is checked before use.
    let (n, passed) = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = std::mem::size_of_val(&cmsg_buf) as _;
        let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        let passed = if n > 0 && !cmsg.is_null() && (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
            let mut fd: RawFd = -1;
            std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg), &mut fd as *mut RawFd as *mut u8, std::mem::size_of::<RawFd>());
            Some(fd)
        } else {
            None
        };
        (n, passed)
    };
    if n != 8 {
        return Err(Error::new(ErrorKind::UnexpectedEof, "the child did not hand over its listener"));
    }
    let number = i32::from_ne_bytes(payload[..4].try_into().unwrap());
    let pid = i32::from_ne_bytes(payload[4..].try_into().unwrap());
    let fd = match passed {
        Some(fd) => fd,
        None => {
            let pidfd = fs_supervisor::tracee::pidfd_open(pid)?;
            let r = fs_supervisor::tracee::pidfd_getfd(pidfd, number);
            close_fd(pidfd);
            r?
        }
    };
    // The child may close its listener now.
    // SAFETY: a one-byte write from a static buffer.
    if unsafe { libc::write(sock, b"l".as_ptr() as *const libc::c_void, 1) } != 1 {
        close_fd(fd);
        return Err(Error::last_os_error());
    }
    Ok((fd, pid))
}

/// Tracee-side convenience: `no_new_privs` + install the connect listener, return
/// the listener fd (which the tracee hands to the supervisor, `hand_listener`).
pub fn install_connect_filter_self() -> Result<RawFd> {
    install_guard_filter_self(FilterTraps::from_env())
}

/// `no_new_privs` + the guard's filter with exactly these traps.
pub fn install_guard_filter_self(t: FilterTraps) -> Result<RawFd> {
    set_no_new_privs()?;
    install_listener_traps(t)
}

/// The launcher's secret policy file (plan 10 §4.1), when the launch has one.
pub const SECRETS_ENV: &str = "MANDU_NET_GUARD_SECRETS";
pub fn secrets_policy_requested() -> bool {
    std::env::var_os(SECRETS_ENV).map(|v| !v.is_empty()).unwrap_or(false)
}

// ── reading the tracee's sockaddr ────────────────────────────────────────────

/// `process_vm_readv` the connect target `sockaddr` (up to `addrlen`, clamped to
/// `SOCKADDR_MAX`) out of tracee `pid` at `addr`. The tracee is SUSPENDED on the
/// unanswered notification, so the read is race-free.
pub fn read_sockaddr(pid: i32, addr: u64, addrlen: u64) -> Result<Vec<u8>> {
    let want = (addrlen as usize).min(SOCKADDR_MAX);
    if addr == 0 || want < 2 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; want];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: want,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: want,
    };
    // SAFETY: reads `want` bytes of tracee memory into our buffer; both iovecs are
    // valid for `want` bytes and the tracee is frozen on the trap.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n < 0 {
        return Err(Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// The sockaddr exactly as the kernel would take it: EINVAL past
/// `sockaddr_storage`, EFAULT for memory the tracee's own call could not read.
pub(crate) fn read_sockaddr_exact(pid: i32, addr: u64, addrlen: u64) -> std::result::Result<Vec<u8>, i32> {
    if addrlen > SOCKADDR_MAX as u64 {
        return Err(libc::EINVAL);
    }
    if addrlen == 0 {
        return Ok(Vec::new());
    }
    if addr == 0 {
        return Err(libc::EFAULT);
    }
    match read_sockaddr(pid, addr, addrlen) {
        Ok(raw) if raw.len() == addrlen as usize => Ok(raw),
        _ => Err(libc::EFAULT),
    }
}

/// Is `pid` a boxed process (exec-routing.md §4.2)? One below a
/// `box_ancestor` process that does not share the guard's network namespace
/// (the box's own; the box binary itself, bwrap's outer process and a
/// HumanShell command it runs directly share ours). A namespace the guard
/// cannot read, under a box ancestor, counts as boxed (fail-closed).
pub(crate) fn is_box_thread(pid: i32, box_ancestor: &str) -> bool {
    let ours = netns_id("/proc/self/ns/net");
    let theirs = netns_id(&format!("/proc/{pid}/ns/net"));
    if ours.is_some() && ours == theirs {
        return false;
    }
    has_ancestor_named(pid, box_ancestor)
}

/// Does an ancestor of `pid` (its parent up) run a binary named `name`?
fn has_ancestor_named(pid: i32, name: &str) -> bool {
    let mut p = pid;
    for _ in 0..64 {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{p}/stat")) else { return false };
        // "pid (comm) state ppid ...": the comm may hold spaces and parens.
        let Some(ppid) = stat.rfind(')').and_then(|i| stat[i + 1..].split_whitespace().nth(1)).and_then(|v| v.parse::<i32>().ok()) else {
            return false;
        };
        if ppid <= 0 {
            return false;
        }
        p = ppid;
        let exe = std::fs::read_link(format!("/proc/{p}/exe")).ok();
        if exe.as_deref().and_then(|e| e.file_name()).map(|n| n == name).unwrap_or(false) {
            return true;
        }
    }
    false
}

/// The guard's own network namespace cookie (a boxed process's socket of it
/// has a route out: refused, exec-routing.md §4.2).
pub(crate) fn guard_netns_cookie() -> Option<u64> {
    static OURS: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *OURS.get_or_init(fs_supervisor::box_sockets::own_netns_cookie)
}

/// A `bind` (trapped for the command box, the agent's own server, and every
/// secret policy): a boxed process's pathname Unix bind is noted, to be read
/// back once it has run; a pathname Unix bind under the write-protect list
/// or by a holder is performed by the guard (`perform_bind`); every other
/// bind runs as issued.
pub fn handle_bind_notif(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) {
    let pid = notif.pid as i32;
    // A boxed process's bind runs as issued (it reaches nothing in the box's
    // own network namespace) and is noted for the box socket allow-list.
    if let Some(boxed) = cfg.box_sockets.as_ref().filter(|_| is_box_thread(pid, &cfg.box_ancestor)) {
        if let Ok(raw) = read_sockaddr_exact(pid, notif.data.args[1], notif.data.args[2]) {
            boxed.note_bind(pid, notif.data.args[0] as RawFd, &raw, &|| notif_id_valid(listener, notif.id));
        }
        answer_continue(listener, notif);
        return;
    }
    // supported-agents.md §2.3.1 (`own_server`): the client's own server
    // binds an ephemeral loopback port, which the launch's port wrap refuses
    // (no bind port is granted). Performed here on a copy of the socket, so
    // the wrap does not see it; every other bind goes on below unchanged.
    if cfg.own_server.is_some() {
        if let Some(answered) = own_server_bind(cfg, notif) {
            answer_errno(listener, notif, answered);
            return;
        }
    }
    // Finding 3 + the path-change TOCTOU: a pathname Unix bind creates a file,
    // so under the write-protect list (the arbiter's socket among the deny
    // entries) it is pinned, judged like any new file, and PERFORMED on the
    // tracee's own socket — never CONTINUEd, which would let the kernel
    // re-resolve a parent a racing thread swapped a symlink for. No program in
    // the tree can then stand up an impostor arbiter where the interceptors
    // dial.
    // Plan 13 §9 R4 (b), 2026-10-04: a holder's socket name on a mount that
    // leaves the machine is judged there too (`judge_change`).
    // exec-routing.md §4.3 (2026-10-18): under the bind record every Unix
    // bind is performed, so the guard knows it succeeded before it records
    // the socket as one the tree named (a CONTINUEd bind's outcome is never
    // seen, and a failed bind of an inherited, already-named listener must
    // not be recorded).
    let recording = cfg.unix_binds.is_some();
    if recording || cfg.secrets.as_ref().map(|i| !i.write_protect.is_empty()).unwrap_or(false) || call_holder(cfg, pid).is_some() {
        if let Ok(raw) = read_sockaddr_exact(pid, notif.data.args[1], notif.data.args[2]) {
            if let Some(p) = crate::guard::unix_pathname_bytes(&raw) {
                perform_bind(listener, cfg, notif, p);
                return;
            }
            if recording {
                if let Some(answered) = perform_unnamed_bind(cfg, notif, &raw) {
                    answer_errno(listener, notif, answered);
                    return;
                }
            }
        }
    }
    answer_continue(listener, notif);
}

/// exec-routing.md §4.3, the bind record: an abstract-name bind, or an
/// autobind (the family alone), of a Unix stream or seqpacket socket,
/// performed on a copy of the tracee's socket with the address bytes read
/// once, and the socket recorded once the bind succeeded. An abstract name
/// creates no file, so nothing else judges it; the name lives in the
/// socket's own network namespace, whoever binds it. Some(errno) =
/// answered; None = not such a bind (another family or kind, no copy):
/// CONTINUEd, and not recorded.
fn perform_unnamed_bind(cfg: &GuardConfig, notif: &libc::seccomp_notif, raw: &[u8]) -> Option<i32> {
    let record = cfg.unix_binds.as_ref()?;
    if raw.len() < 2 || u16::from_ne_bytes([raw[0], raw[1]]) != libc::AF_UNIX as u16 || (raw.len() > 2 && raw[2] != 0) {
        return None;
    }
    let fd = tracee_fd(notif.pid as i32, notif.data.args[0] as RawFd).ok()?;
    let listens = sockopt_int(fd, libc::SO_DOMAIN) == Some(libc::AF_UNIX) && matches!(sockopt_int(fd, libc::SO_TYPE), Some(libc::SOCK_STREAM) | Some(libc::SOCK_SEQPACKET));
    if !listens {
        close_fd(fd);
        return None;
    }
    // SAFETY: bind our copy of the tracee's socket (the same socket object)
    // to the exact bytes it passed.
    let rc = unsafe { libc::bind(fd, raw.as_ptr() as *const libc::sockaddr, raw.len() as libc::socklen_t) };
    let answered = if rc == 0 { 0 } else { Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) };
    if answered == 0 {
        note_unix_bind(record, fd);
    }
    close_fd(fd);
    Some(answered)
}

/// A bind the guard performed succeeded on `fd` (its copy): record the
/// socket for the allow-list (`unix_owner::BindRecord`). One that cannot be
/// recorded is said once: its listener will be refused.
fn note_unix_bind(record: &crate::unix_owner::BindRecord, fd: RawFd) {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !crate::unix_owner::sys::record_bound(record, fd) && !SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
        crate::diag!("mandu-net-guard: a Unix socket the agent bound could not be recorded (the record is full of live sockets, or no cookie): its listener is refused under the allow-list");
    }
}

/// supported-agents.md §2.3.1 (`own_server`): perform the bind when it is
/// the client's own server binding a stream socket to a loopback address at
/// port 0 (`own_server::bind_allowed`), on a copy of the tracee's socket and
/// with the address bytes read once (no re-read to race). A Landlock layer
/// the task nested itself still decides (`landlock_mirror::connect_via`);
/// only the launch's own port wrap is superseded. Some(errno) = answered;
/// None = not this allowance's bind: the caller goes on as before (the
/// launch's wrap then decides).
fn own_server_bind(cfg: &GuardConfig, notif: &libc::seccomp_notif) -> Option<i32> {
    let exe = cfg.own_server.as_deref()?;
    let pid = notif.pid as i32;
    let raw = read_sockaddr_exact(pid, notif.data.args[1], notif.data.args[2]).ok()?;
    let ConnTarget::Inet(ep) = decode_sockaddr(&raw) else { return None };
    if ep.port != 0 || !crate::own_server::is_loopback(ep.ip) {
        return None;
    }
    let clients = crate::guard_flow::own_server_clients(cfg);
    let caller = crate::guard_flow::own_server_facts(pid);
    if !crate::own_server::is_own_server(exe, &clients, &caller) {
        return None;
    }
    let fd = tracee_fd(pid, notif.data.args[0] as RawFd).ok()?;
    if !crate::own_server::bind_allowed(exe, &clients, &caller, ep.ip, ep.port, proto_of_fd(fd) == Proto::Tcp) {
        close_fd(fd);
        return None;
    }
    let bind = move |fd: RawFd, addr: &[u8]| -> i32 {
        // SAFETY: bind our copy of the tracee's socket to the exact bytes it
        // passed (read once above); the socket is shared, so the tracee's
        // descriptor is bound.
        let rc = unsafe { libc::bind(fd, addr.as_ptr() as *const libc::sockaddr, addr.len() as libc::socklen_t) };
        if rc == 0 { 0 } else { Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) }
    };
    let answered = match cfg.landlock.connect_via(pid) {
        Ok(crate::landlock_mirror::ConnectVia::Guard) => bind(fd, &raw),
        Ok(crate::landlock_mirror::ConnectVia::Mirror(d)) => {
            let addr = raw.clone();
            d.run(move || bind(fd, &addr)).unwrap_or_else(|e| e)
        }
        Err(e) => e,
    };
    close_fd(fd);
    Some(answered)
}

/// Pin the bind path's parent, judge the new name, and bind the tracee's own
/// socket (a `pidfd_getfd` copy) to the leaf relative to the pinned directory
/// (the binding thread `fchdir`s to it) — one component, no parent
/// re-resolved (the path-change TOCTOU close for `bind`). Fail closed
/// (EACCES) when the guard cannot act exactly as the tracee (no socket copy,
/// no private cwd). Honors the tracee's Landlock MAKE_SOCK right and umask.
fn perform_bind(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, path: &[u8]) {
    let pid = notif.pid as i32;
    let sockfd = notif.data.args[0] as RawFd;
    let (pin, leaf) = match pin_parent_bytes(listener, cfg, notif, libc::AT_FDCWD, path) {
        Ok(v) => v,
        Err(e) => {
            answer_errno(listener, notif, e);
            return;
        }
    };
    match judge_change(listener, cfg, notif, pin, &leaf, crate::secret_open::ChangeRole::NewName) {
        ChangeVerdict::Proceed => {}
        ChangeVerdict::Refused => {
            close_fd(pin);
            answer_errno(listener, notif, libc::EACCES);
            return;
        }
        ChangeVerdict::Gone => {
            close_fd(pin);
            return;
        }
    }
    // Bind the tracee's own socket to exactly the pinned directory + leaf: on
    // a thread whose cwd is the pinned directory (`with_private_fs`, fchdir),
    // the address is the one-component leaf, relative. The parent cannot be
    // re-walked, and any leaf the tracee's own `sun_path` held fits (no
    // `/proc/self/fd/<pin>/` prefix to overflow the 108 bytes). The socket
    // file gets the tracee's umask, not the guard's 0.
    let Some(addr) = crate::secret_open::relative_unix_addr(&leaf) else {
        close_fd(pin);
        answer_errno(listener, notif, libc::EINVAL);
        return;
    };
    let dup = match tracee_fd(pid, sockfd) {
        Ok(d) => d,
        Err(_) => {
            close_fd(pin);
            answer_errno(listener, notif, libc::EACCES);
            return;
        }
    };
    let umask = tracee_umask_of(pid);
    let answered = perform_under_domain(cfg, pid, move || {
        with_private_fs(Some(pin), umask, || {
            // SAFETY: bind our copy of the tracee's socket to the leaf,
            // relative to the pinned cwd; the copy shares the socket object,
            // so the tracee's socket is bound. len is the exact sockaddr bytes.
            let rc = unsafe { libc::bind(dup, addr.as_ptr() as *const libc::sockaddr, addr.len() as libc::socklen_t) };
            if rc == 0 { 0 } else { Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) }
        })
    });
    // exec-routing.md §4.3: the tree named this socket.
    if let (0, Some(record)) = (answered, cfg.unix_binds.as_ref()) {
        note_unix_bind(record, dup);
    }
    close_fd(dup);
    close_fd(pin);
    answer_errno(listener, notif, answered);
}

// ── namespace + socket introspection ─────────────────────────────────────────

/// The (dev, ino) identity of a `/proc/<pid>/ns/net` symlink target, or None.
fn netns_id(path: &str) -> Option<(u64, u64)> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // stat() (not lstat) follows the nsfs magic symlink to the namespace inode.
    let rc = unsafe { libc::stat(c.as_ptr(), &mut st) };
    if rc != 0 {
        return None;
    }
    Some((st.st_dev as u64, st.st_ino as u64))
}

/// Does the tracee share OUR network namespace? Only same-netns connects are
/// enforced (and supervisor-connected); a different netns means a nested sandbox
/// whose OWN netns is the boundary — we CONTINUE and let that boundary hold. A
/// stat failure (race / permission) is treated as "same" (fail toward enforcing).
pub fn tracee_shares_our_netns(pid: i32) -> bool {
    let ours = netns_id("/proc/self/ns/net");
    let theirs = netns_id(&format!("/proc/{pid}/ns/net"));
    match (ours, theirs) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

/// `SO_NETNS_COOKIE` (kernel ≥ 5.14; asm-generic, the same on x86_64 and
/// aarch64): a socket's network namespace, readable without privilege.
const SO_NETNS_COOKIE: libc::c_int = 71;

fn netns_cookie(fd: RawFd) -> Option<u64> {
    let mut v: u64 = 0;
    let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
    // SAFETY: getsockopt into a u64.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, SO_NETNS_COOKIE, &mut v as *mut u64 as *mut libc::c_void, &mut len) };
    (rc == 0).then_some(v)
}

/// Is this socket in the guard's own network namespace? `None` = the kernel
/// cannot say (no `SO_NETNS_COOKIE`).
pub(crate) fn socket_in_our_netns(fd: RawFd) -> Option<bool> {
    static OURS: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    let ours = *OURS.get_or_init(|| {
        // SAFETY: a throwaway socket in our namespace, closed at once.
        let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if s < 0 {
            return None;
        }
        let c = netns_cookie(s);
        close_fd(s);
        c
    });
    Some(netns_cookie(fd)? == ours?)
}

// pidfd_open / pidfd_getfd (the supervisor-connect enact, kernel ≥ 5.6) are
// fs-supervisor's (`tracee`), shared with the command box's socket allow-list.
use fs_supervisor::tracee::{fd_identity, open_unix_target as open_tracee_unix_target, sockaddr_un_bytes, tracee_fd};

/// A socket's protocol from `SO_TYPE` and `SO_PROTOCOL` (`send_guard::
/// proto_of`): TCP, UDP, or `Other` (an ICMP echo socket, UDP-Lite, SCTP),
/// which only a protocol-agnostic rule covers. Before 2026-10-01 a datagram
/// socket was UDP whatever its protocol, so `udp:*:53` admitted an ICMP echo
/// to any host on "port" 53.
pub(crate) fn proto_of_fd(fd: RawFd) -> Proto {
    crate::send_guard::proto_of(sockopt_int(fd, libc::SO_TYPE), sockopt_int(fd, libc::SO_PROTOCOL))
}

/// An integer `SOL_SOCKET` option of a socket, or None.
pub(crate) fn sockopt_int(fd: RawFd, opt: libc::c_int) -> Option<i32> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt into an int.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, opt, &mut v as *mut _ as *mut libc::c_void, &mut len) };
    (rc == 0).then_some(v)
}

pub(crate) fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

// ── the caching, getaddrinfo-backed resolver ─────────────────────────────────

/// Resolves hostname rules to their current IP set via `getaddrinfo`
/// (`ToSocketAddrs`), memoized with a short TTL so a burst of connects does not
/// re-resolve per packet. `Send + Sync` for the threaded supervisor.
pub struct CachingResolver {
    ttl: Duration,
    cache: Mutex<std::collections::HashMap<String, (Instant, Vec<IpAddr>)>>,
}

impl CachingResolver {
    pub fn new(ttl: Duration) -> Self {
        CachingResolver {
            ttl,
            cache: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for CachingResolver {
    fn default() -> Self {
        // 30s is short enough to follow a DNS change without re-resolving per connect.
        CachingResolver::new(Duration::from_secs(30))
    }
}

impl HostResolver for CachingResolver {
    fn resolve(&self, host: &str) -> Vec<IpAddr> {
        if let Ok(cache) = self.cache.lock() {
            if let Some((at, ips)) = cache.get(host) {
                if at.elapsed() < self.ttl {
                    return ips.clone();
                }
            }
        }
        // Resolve fresh (port 0 — we only want the addresses). A failure yields an
        // empty set → the Host rule matches nothing this round (fail-closed).
        use std::net::ToSocketAddrs;
        let ips: Vec<IpAddr> = (host, 0u16)
            .to_socket_addrs()
            .map(|it| it.map(|sa| sa.ip()).collect())
            .unwrap_or_default();
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(host.to_string(), (Instant::now(), ips.clone()));
        }
        ips
    }
}

// ── the per-notification handler ─────────────────────────────────────────────

/// The config a handler needs: the compiled policy + a resolver, plus an OPTIONAL
/// best-effort observability emitter — shared across the per-connect handler
/// threads.
#[derive(Clone)]
pub struct GuardConfig {
    pub policy: Arc<GuardPolicy>,
    pub resolver: Arc<dyn HostResolver + Send + Sync>,
    /// Best-effort connect-decision events to the arbiter (the dashboard's
    /// allowed/denied-destination view, exec-routing.md §7.5). `None` = no
    /// emission (the default, and every test). Off the security path: a locked
    /// arbiter miss never changes the seccomp answer. The `Mutex` serializes the
    /// shared client across worker threads.
    pub emitter: Option<Arc<Mutex<mandu_arbiter::ArbiterClient>>>,
    /// Session id stamped on emitted events (`events::guard_session_id`:
    /// `MANDU_SESSION_ID`, else `MANDU_SCOPE_ID`, else `net-guard`).
    pub session_id: String,
    /// Plan 10 §4.1: the registered secrets, when the launcher handed them
    /// over. Present ⇒ the open family is trapped and secret_open decides.
    pub secrets: Option<Arc<crate::secret_open::SecretIndex>>,
    /// Plan 10 §4: the processes this guard handed raw bytes to (readers).
    /// Their connects are limited to their secrets' bindings (§4.3) and the
    /// files they write inherit the taint (the filesystem exit).
    pub tainted: Arc<crate::secret_open::TaintedSet>,
    /// The processes that exec'd the enforce-clean applier
    /// (`secret_open::is_clean_box_exec`): a secret open by one of them, or
    /// a descendant, is refused without an ask, so the clean attempt never
    /// consumes the human's answer meant for the real run.
    pub clean_boxes: Arc<crate::secret_open::TaintedSet>,
    /// WSL: refuse the Windows interop door (`guard::WslGuard`). `None` off
    /// WSL (and in every test that does not pin it); the bin sets it from
    /// `mandu_arbiter::wsl::probe_host`.
    pub wsl: Option<crate::guard::WslGuard>,
    /// exec-routing.md §4.2: the command box's socket allow-list, served here
    /// when the launch runs the box (`BOX_SOCKETS_ENV`). `None` = not served.
    pub box_sockets: Option<Arc<fs_supervisor::box_sockets::BoxSockets>>,
    /// Plan 10 §4.1a: the Landlock domains of the tree, mirrored so an open
    /// the guard performs for a sandboxed task is decided by that sandbox.
    pub landlock: Arc<crate::landlock_mirror::LandlockMirror>,
    /// Plan 10 §4.1a: pseudo-filesystem opens (procfs, sysfs, cgroupfs, …)
    /// re-done with the tracee's credentials and namespaces.
    pub helpers: Arc<crate::context_helper::ContextHelpers>,
    /// The ancestor that marks a boxed process (`BOX_ANCESTOR`; tests pin
    /// their own binary's name).
    pub box_ancestor: String,
    /// The agent tree's roots for the Unix socket allow-list: the guard's
    /// child, and the guard itself (the tree's subreaper, so a server the
    /// tree daemonized keeps it as an ancestor). Empty = no process is in
    /// the tree (every socket not on the list is refused).
    pub tree_roots: Vec<i32>,
    /// exec-routing.md §4.3 (2026-10-18): the bind record of the Unix
    /// socket allow-list (`unix_owner::BindRecord`). Some = every Unix bind
    /// of the tree reaches `handle_bind_notif` (the filter traps `bind`,
    /// `FilterTraps::traps_bind`) from before the tree runs, and the guard
    /// performs it and records the sockets it named; an unlisted listener of
    /// this network namespace is then judged by the record, with no probe
    /// connection. None (the default; a posture or a kernel where binds are
    /// not all seen) = the probe judges, as before.
    pub unix_binds: Option<Arc<crate::unix_owner::BindRecord>>,
    /// The launch's own proxy ports (`send_guard::PROXY_PORTS_ENV`): the
    /// only loopback destinations a TAINTED process reaches without a
    /// binding, over TCP to 127.0.0.1 / ::1 (exec-routing.md §7.5,
    /// 2026-10-01; before, every port of 127.0.0.1). Empty = none.
    pub proxy_ports: Vec<u16>,
    /// The connects and sends in flight per process: a process becomes
    /// tainted only once those judged before it are done
    /// (`send_guard::EgressGate`, the taint-time sweep).
    pub egress: Arc<crate::send_guard::EgressGate>,
    /// P0 1c (2026-10-07): the queue sends let go for a process holding no
    /// secret, each keeping its gate entered until the kernel has copied
    /// the buffer (`object_flow::QueueSends`).
    pub queue_sends: Arc<crate::object_flow::QueueSends>,
    /// supported-agents.md §2.3.1 (`own_server`): the agent's executable for
    /// the private-server allowance, from `own_server::OWN_SERVER_ENV`.
    /// None = off (the default; every test that does not set it).
    pub own_server: Option<String>,
    /// The client processes of that allowance once found
    /// (`guard_flow::own_server_clients`).
    pub own_server_clients: Arc<Mutex<Vec<String>>>,
    /// Plan 13 D2: the agent's proc keys once found
    /// (`guard_flow::agent_keys`), never made holders through a pipe.
    pub agent: Arc<Mutex<Vec<String>>>,
    /// Plan 13 §4.5.1: the agent's channels (`socket:[ino]`) whose other end
    /// a holder writes into, recorded at the arbiter as agent flows and
    /// watched until the agent no longer holds them (then reported closed,
    /// `guard_flow::observe_agent_closes`).
    pub agent_flows: Arc<Mutex<Vec<String>>>,
    /// Plan 13 §9 R1, the file shapes: the reading opens (and `shmat`s) in
    /// flight, and the lock under which a holder's write marks an object
    /// (`object_flow::ObjectOpens`), so a reader racing a holder's write is
    /// seen by one side or the other.
    pub object_opens: Arc<crate::object_flow::ObjectOpens>,
    /// Plan 13 §4.5.1, the proxy leg (2026-10-02): the pids of the session's
    /// net-proxy once found (`guard_flow::proxy_pids`: the processes holding
    /// its listener at a `proxy_ports` port).
    pub proxy: Arc<Mutex<Vec<i32>>>,
    /// Plan 13 §4.5.1, a FIFO the agent reads (2026-10-02): held from the
    /// moment a holder's write-open or the agent's read-open of a FIFO is
    /// performed until its descriptor is the tracee's, so the two looks
    /// (`guard_flow::holder_fifo_open`, `agent_fifo_open`) never miss each
    /// other when both opens complete at once.
    pub fifo_gate: Arc<Mutex<()>>,
    /// The filter does not hand `accept` to the guard (the old-kernel degrade,
    /// no `pidfd_getfd`: `FilterTraps::no_sends`), so a holder takes a
    /// connection unjudged: the agent's own flow to a holder is recorded at
    /// its connect and at the taint-time sweep's look at a listener's backlog
    /// instead (plan 13 §4.5.1, 2026-10-02). Set as `FilterTraps::from_env`
    /// sets `no_sends`.
    pub accepts_untrapped: bool,
    /// Plan 13 §9 R4 (b): file systems (by `st_dev`) counted as leaving the
    /// machine besides the built-in network and FUSE types
    /// (`local_exits::mount_verdict`). Empty in production: no launch
    /// variable sets it; the kernel tests set it, no FUSE server being at
    /// hand there.
    pub extra_remote_devs: Vec<u64>,
    /// Plan 13 §4.9 (2026-10-07): the mount tables of the namespaces a raw
    /// open was judged in, kept until a `poll` says one changed
    /// (`visible_mounts`).
    pub mount_views: Arc<crate::visible_mounts::MountViews>,
    /// confidentiality.md §4, "A held command's refused connection"
    /// (2026-10-12): the sockets a human's Allow once connected for a HIGH
    /// session's held command, so their own sends reach that peer
    /// (`held_ask::OnceAdmitted`).
    pub once_admitted: Arc<crate::held_ask::OnceAdmitted>,
}

impl GuardConfig {
    /// A config with no observability emitter (production default until an arbiter
    /// sock is present; and every unit/integration test).
    pub fn new(policy: Arc<GuardPolicy>, resolver: Arc<dyn HostResolver + Send + Sync>) -> Self {
        GuardConfig {
            policy,
            resolver,
            emitter: None,
            session_id: "net-guard".into(),
            secrets: None,
            tainted: Arc::new(crate::secret_open::TaintedSet::default()),
            clean_boxes: Arc::new(crate::secret_open::TaintedSet::default()),
            wsl: None,
            box_sockets: None,
            landlock: Arc::new(crate::landlock_mirror::LandlockMirror::new()),
            helpers: Arc::new(crate::context_helper::ContextHelpers::new()),
            box_ancestor: BOX_ANCESTOR.to_string(),
            tree_roots: Vec::new(),
            unix_binds: None,
            proxy_ports: Vec::new(),
            egress: Arc::new(crate::send_guard::EgressGate::default()),
            queue_sends: Arc::new(crate::object_flow::QueueSends::default()),
            own_server: None,
            own_server_clients: Arc::new(Mutex::new(Vec::new())),
            agent: Arc::new(Mutex::new(Vec::new())),
            agent_flows: Arc::new(Mutex::new(Vec::new())),
            object_opens: Arc::new(crate::object_flow::ObjectOpens::default()),
            proxy: Arc::new(Mutex::new(Vec::new())),
            fifo_gate: Arc::new(Mutex::new(())),
            accepts_untrapped: !kernel_at_least(5, 6),
            extra_remote_devs: Vec::new(),
            mount_views: Arc::new(crate::visible_mounts::MountViews::new()),
            once_admitted: Arc::new(crate::held_ask::OnceAdmitted::new()),
        }
    }
}

/// What the handler did with one trapped connect — surfaced so the integration
/// test can assert behavior without scraping logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardOutcome {
    /// Non-INET family (or unreadable/malformed sockaddr) → CONTINUE.
    PassedThrough { why: &'static str },
    /// The socket (or, without a copy of it, the tracee) is in a different
    /// netns: its own netns is the boundary. Connected by the guard on its
    /// copy of the socket, or CONTINUE when there is none.
    DifferentNetns,
    /// Policy DENIED this destination → the tracee's connect got `-EACCES`.
    Denied { ip: IpAddr, port: u16 },
    /// Policy ALLOWED and we supervisor-connected the socket; `answered` is the
    /// errno we returned to the tracee (0 = connected, EINPROGRESS = nonblocking
    /// in flight, or the connect's own error faithfully mirrored).
    AllowedSupervised { ip: IpAddr, port: u16, answered: i32 },
    /// Policy ALLOWED but supervisor-connect was unavailable (kernel < 5.6 /
    /// getfd failed) → we CONTINUE'd so the tracee runs its own connect to the
    /// (allowed) address. Documented TOCTOU-degraded fallback.
    AllowedContinue { ip: IpAddr, port: u16 },
    /// Refused before any policy lookup (WSL's interop door, `guard::WslGuard`):
    /// the tracee's connect got `-EACCES`.
    Refused { why: &'static str },
    /// A pathname AF_UNIX connect the guard ran itself on the inode it checked
    /// (`supervised_unix_connect`); `answered` is the errno returned (0 =
    /// connected, or the lookup's / the connect's own error).
    UnixSupervised { answered: i32 },
    /// A boxed process's non-INET connect, performed under the box's socket
    /// allow-list (exec-routing.md §4.2); `answered` is the errno returned.
    BoxSocket { answered: i32 },
    /// Another family's connect (AF_UNSPEC, netlink, vsock off WSL, …),
    /// performed on the guard's copy of the socket with the address it read
    /// (`other_family_connect`); `answered` is the errno returned.
    OtherPerformed { answered: i32 },
}

/// Handle exactly one already-received connect notification end to end: read the
/// sockaddr, decide, and enact. Factored out of the loop so the integration test
/// can drive one connect deterministically. Safe to call from a worker thread —
/// the tracee stays suspended until we answer THIS `notif.id`.
pub fn handle_connect_notif(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) -> Result<GuardOutcome> {
    let pid = notif.pid as i32;
    let sockfd = notif.data.args[0] as RawFd; // connect(sockfd, addr, addrlen)
    let addr_ptr = notif.data.args[1];
    let addrlen = notif.data.args[2];

    // A boxed process (exec-routing.md §4.2): every non-INET connect is
    // performed here under the box's allow-list (its own Unix sockets only),
    // never CONTINUEd (the kernel would re-read the address). INET goes on
    // below: its socket's namespace decides.
    if let Some(boxed) = cfg.box_sockets.as_ref().filter(|_| is_box_thread(pid, &cfg.box_ancestor)) {
        let raw = match read_sockaddr_exact(pid, addr_ptr, addrlen) {
            Ok(raw) => raw,
            Err(errno) => {
                answer_errno(listener, notif, errno);
                return Ok(GuardOutcome::BoxSocket { answered: errno });
            }
        };
        if !matches!(decode_sockaddr(&raw), ConnTarget::Inet(_)) {
            let answered = boxed.connect_for(pid, sockfd, &raw, guard_netns_cookie(), &|| notif_id_valid(listener, notif.id));
            answer_errno(listener, notif, answered);
            return Ok(GuardOutcome::BoxSocket { answered });
        }
    }

    // Read + decode the target. An unreadable/malformed/non-INET address is passed
    // through (a bad sockaddr fails in the kernel anyway; AF_UNIX must keep working).
    let raw = read_sockaddr(pid, addr_ptr, addrlen).unwrap_or_default();
    let ep = match decode_sockaddr(&raw) {
        ConnTarget::Inet(e) => e,
        ConnTarget::Passthrough => {
            // A pathname AF_UNIX connect that a check applies to (WSL's
            // interop door, a secret socket, a TAINTED process's bindings) is
            // SUPERVISED: the guard opens the target itself in the tracee's
            // view, checks THAT inode, and connects the tracee's socket to
            // exactly that inode (`supervised_unix_connect`), so a symlink
            // swapped in after the check has nothing to race. Everything else,
            // and a kernel without openat2 / pidfd_getfd (< 5.6), takes the
            // path-string checks below and CONTINUE.
            // Whether the connecting process holds (or inherits) a secret:
            // asked once per Unix connect, only in secrets mode.
            let taint = match (cfg.secrets.as_ref(), crate::secret_open::unix_path_of(&raw)) {
                (Some(_), Some(_)) => {
                    let own = crate::secret_open::own_key_of(pid);
                    let (held, chain) = crate::guard_flow::holder(cfg, pid, &own);
                    Some((own, held, chain))
                }
                _ => None,
            };
            // Finding 1: with the confidentiality axis on, every Unix connect
            // is allow-listed, so every one is supervised; one that cannot be
            // (no openat2 / pidfd_getfd) is refused, never continued.
            let unix_listed = cfg.secrets.as_ref().map(|i| i.unix_policy.is_some()).unwrap_or(false);
            // arbiter-human-plane.md §5: the human-plane directory is denied
            // to every connect of the tree, allow-list or not.
            let unix_denying = cfg.secrets.as_ref().map(|i| !i.unix_deny.is_empty()).unwrap_or(false);
            // exec-routing.md §7.5 (2026-10-02), gap (e): under a secret
            // policy (or WSL) every pathname and abstract Unix connect is
            // supervised, in EVERY posture (checks or none), so a thread
            // cannot swap an INET socket under the descriptor between the
            // check and the kernel's connect. Before, a posture with no Unix
            // allow-list CONTINUEd one, and the static list was defeated by
            // that swap. With no secret policy at all there is nothing to
            // protect, so AF_UNIX passes through untouched (cheaper).
            let supervise_unix = cfg.secrets.is_some() || cfg.wsl.is_some();
            if let Some(pbytes) = crate::guard::unix_pathname_bytes(&raw) {
                if supervise_unix && kernel_at_least(5, 6) {
                    if let Some(outcome) = supervised_unix_connect(listener, cfg, notif, pbytes, taint.clone()) {
                        return Ok(outcome);
                    }
                }
                if unix_listed {
                    let dest = format!("unix:{}", String::from_utf8_lossy(pbytes));
                    return Ok(refuse_unix(listener, cfg, notif, &dest, "this kernel cannot supervise the connect (openat2 / pidfd_getfd)"));
                }
                // No supervision (< 5.6) and no allow-list: the deny list is
                // judged on the path string, resolved in the tracee's cwd and
                // canonicalized here. Residue of this fallback (the WSL one's):
                // a symlink swapped in before the kernel re-resolves.
                if let Some(index) = cfg.secrets.as_ref().filter(|_| unix_denying) {
                    let upath = resolve_tracee_unix_path(pid, &String::from_utf8_lossy(pbytes));
                    if index.unix_denied_now(Some(&upath), path_identity(&upath)).is_some() {
                        return Ok(refuse_unix(listener, cfg, notif, &format!("unix:{upath}"), HUMAN_PLANE_REFUSAL));
                    }
                }
            } else if is_abstract_unix(&raw) && supervise_unix && kernel_at_least(5, 6) {
                // The same for an abstract name (2026-10-02: every posture
                // under a secret policy).
                return Ok(supervised_abstract_connect(listener, cfg, notif, &raw, taint.clone()));
            }
            // WSL: the interop socket and AF_VSOCK start or reach a Windows
            // program outside every Linux wrap (guard::WslGuard). AF_VSOCK
            // always lands here; a Unix path only on the fallback (no openat2
            // / pidfd_getfd), checked on the tracee's path resolved against
            // ITS cwd and canonicalized here. Residue of that fallback
            // (exec-routing.md §4.1): the kernel re-resolves the path on
            // CONTINUE, so a symlink swapped in between is a race.
            if let Some(w) = cfg.wsl.as_ref() {
                let family = if raw.len() >= 2 { u16::from_ne_bytes([raw[0], raw[1]]) } else { 0 };
                let upath = crate::secret_open::unix_path_of(&raw).map(|p| resolve_tracee_unix_path(pid, &p));
                if let Some(why) = w.refusal(family, upath.as_deref()) {
                    answer_errno(listener, notif, libc::EACCES);
                    if let Some(emitter) = &cfg.emitter {
                        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok().and_then(|p| p.to_str().map(String::from)).unwrap_or_default();
                        let dest = upath.map(|p| format!("unix:{p}")).unwrap_or_else(|| "vsock".to_string());
                        let ev = crate::events::guard_wsl_refusal_event(&cfg.session_id, &dest, why, &exe);
                        if let Ok(mut client) = emitter.lock() {
                            mandu_arbiter::safe_emit(&mut client, &ev);
                        }
                    }
                    return Ok(GuardOutcome::Refused { why });
                }
            }
            // §4.3, AF_UNIX: a TAINTED process may reach only its `unix:` bindings
            // and the arbiter's own socket; anyone else passes through as before.
            if let (Some(index), Some(upath)) = (cfg.secrets.as_ref(), crate::secret_open::unix_path_of(&raw)) {
                // A socket that is itself a secret (the ssh-agent, learn-from-
                // nono §3.5): only a listed reader connects, by name and, with
                // `from:`, by who started it. Everyone else: EACCES.
                if let Some(sock) = index.socket(&upath) {
                    let (admitted, exe) = secret_socket_admits(cfg, index, sock, pid);
                    if !admitted {
                        answer_errno(listener, notif, libc::EACCES);
                        if let Some(emitter) = &cfg.emitter {
                            let ev = crate::events::guard_socket_refusal_event(&cfg.session_id, &format!("unix:{upath}"), sock.label.as_deref().unwrap_or("secret socket"), &exe);
                            if let Ok(mut client) = emitter.lock() {
                                mandu_arbiter::safe_emit(&mut client, &ev);
                            }
                        }
                        return Ok(GuardOutcome::PassedThrough { why: "secret socket: not a listed reader, refused" });
                    }
                }
            }
            if let Some((own, held, chain)) = taint {
                if let Some(upath) = crate::secret_open::unix_path_of(&raw) {
                    if held && !is_arbiter_socket(&upath) {
                        if let Some(refused) = tainted_unix_refusal(cfg, &own, chain, &upath) {
                            answer_errno(listener, notif, libc::EACCES);
                            // The refusal's event (plan 10 §8 phase 3, the owed
                            // one): same rule name as the proxied leg.
                            emit_tainted_refusal(cfg, &format!("unix:{upath}"), &refused);
                            return Ok(GuardOutcome::PassedThrough { why: "tainted process → unbound unix socket: refused" });
                        }
                    }
                }
            }
            return Ok(other_family_connect(listener, cfg, notif, &raw));
        }
    };

    // Grab the tracee's socket so we can (a) learn its protocol and network
    // namespace for the decision and (b) connect it ourselves on ALLOW. If we
    // cannot (kernel < 5.6 / race), fall back to an assumed-TCP decision
    // enacted with CONTINUE/EACCES.
    let getfd_ok = kernel_at_least(5, 6);
    let dupfd = if getfd_ok {
        match tracee_fd(pid, sockfd) {
            Ok(fd) => Some(fd),
            Err(_) => None,
        }
    } else {
        None
    };

    // A socket of a different network namespace belongs to a nested sandbox
    // (the command box's net-off namespace: loopback only); that namespace is
    // the boundary. Judged by the SOCKET's namespace (`SO_NETNS_COOKIE`), not
    // the process's: the command box's supervisor connects the box's sockets
    // on its behalf from this namespace (exec-routing.md §4.2), and a boxed
    // process holding a socket of THIS namespace is judged like anyone else.
    // The guard connects its own copy of the checked socket, never CONTINUE:
    // a thread could swap another socket onto the descriptor in between.
    // Without a copy (or a kernel < 5.14 without the cookie) the process's
    // namespace decides, as before.
    match dupfd.map(|fd| (fd, socket_in_our_netns(fd))) {
        Some((fd, Some(false))) => {
            let answered = supervisor_connect(fd, &raw);
            close_fd(fd);
            answer_errno(listener, notif, answered);
            return Ok(GuardOutcome::DifferentNetns);
        }
        Some((_, Some(true))) => {}
        _ if !tracee_shares_our_netns(pid) => {
            if let Some(fd) = dupfd {
                close_fd(fd);
            }
            answer_continue(listener, notif);
            return Ok(GuardOutcome::DifferentNetns);
        }
        _ => {}
    }

    // The egress gate (send_guard::EgressGate), held until this connect is
    // done: a taint arriving meanwhile waits for it, then sweeps the socket.
    let _in_flight = cfg.secrets.as_ref().map(|_| cfg.egress.enter(crate::secret_open::tgid_of(pid)));
    let proto = dupfd.map(proto_of_fd).unwrap_or(Proto::Tcp);
    let target = Endpoint { ip: ep.ip, port: ep.port, proto };
    let (mut decision, matched) = cfg.policy.decide_matched(&target, cfg.resolver.as_ref());

    // supported-agents.md §2.3.1 (`own_server`): the client's connect to its
    // own private server, which no allow rule names (its port is
    // ephemeral). Only a client process, only TCP to loopback, only to a
    // listener every holder of which is the client's own server: the
    // server's descendants (the agent's commands), a nested process of the
    // same executable and every listener outside the tree stay refused.
    // Performed below like any allowed connect (on the guard's thread,
    // outside the launch's port wrap).
    if decision == Decision::Deny && proto == Proto::Tcp && cfg.policy.blocked_reason(&target).is_none() && crate::own_server::is_loopback(ep.ip) {
        if let Some(exe) = cfg.own_server.as_deref() {
            let clients = crate::guard_flow::own_server_clients(cfg);
            let caller = crate::secret_open::own_key_of(pid);
            if clients.contains(&caller) {
                let listeners = crate::guard_flow::own_server_listeners(cfg, (ep.ip, ep.port));
                if crate::own_server::connect_allowed(exe, &clients, &caller, ep.ip, true, &listeners) {
                    decision = Decision::Allow;
                }
            }
        }
    }

    // Plan 10 §4.3, the network exit of a TAINTED process: a reader (or a
    // descendant of one) may connect only to its secrets' bindings, the
    // session's own proxies excepted: TCP to 127.0.0.1 / ::1 on the launch's
    // proxy ports (proxied HTTP is judged again at the net-proxy, which sees
    // the host; exec-routing.md §7.5, 2026-10-01: before, every port of
    // 127.0.0.1, so a resolver forwarding on 127.0.0.1:53 carried a secret
    // off the machine). The arbiter answers the bindings; unreachable ⇒ deny
    // (fail-closed: a tainted process talking to an unknown place is the
    // flow this leg exists for).
    let mut tainted_refusal: Option<TaintedRefusal> = None;
    // confidentiality.md §4, "A held command's refused connection"
    // (2026-10-12): a HIGH session's held command refused here asks the
    // human (the session's own network question); an Allow once admits this
    // one connect, and the socket is remembered so its own sends reach that
    // peer (`held_ask`).
    let mut once_admitted = false;
    if decision == Decision::Allow && cfg.secrets.is_some() && !crate::send_guard::is_session_proxy(ep.ip, ep.port, proto, &cfg.proxy_ports) {
        let own = crate::secret_open::own_key_of(pid);
        let (held, chain) = crate::guard_flow::holder(cfg, pid, &own);
        if held {
            if let Some(refused) = tainted_connect_refusal(cfg, &own, chain.clone(), &target) {
                if held_connect_once(cfg, &own, chain, &target) {
                    once_admitted = true;
                    crate::diag!("mandu-net-guard: {}:{} allowed once for a held command (the user's answer)", ep.ip, ep.port);
                } else {
                    crate::guard_trace::trace(|| format!("refused {own} → {}:{}: agent {:?}", ep.ip, ep.port, crate::guard_flow::agent_keys(cfg)));
                    decision = Decision::Deny;
                    tainted_refusal = Some(refused);
                }
            }
        }
        // Plan 13 §4.5.1, the old-kernel degrade (2026-10-02): the agent's
        // own connect to a holder's listener is recorded as an agent flow
        // here, before it is performed; where the holder's accept is not
        // trapped, this is the only event that sees it. A record that fails
        // refuses the connect (fail-closed).
        if decision == Decision::Allow && proto == Proto::Tcp {
            let agent_sock = dupfd.and_then(|fd| fd_identity(fd).map(|(_, ino)| ino)).or_else(|| {
                std::fs::read_link(format!("/proc/{pid}/fd/{sockfd}")).ok()?.to_str()?.strip_prefix("socket:[")?.strip_suffix(']')?.parse::<u64>().ok()
            });
            if let Err(e) = crate::guard_flow::agent_connect_flow(cfg, pid, agent_sock, (ep.ip, ep.port)) {
                crate::diag!("mandu-net-guard: the agent's connect to {}:{} refused: a holder listens there and the flow could not be recorded ({e})", ep.ip, ep.port);
                decision = Decision::Deny;
            }
        }
    }

    // Best-effort observability (off the security path): emit the noteworthy
    // decisions (all denies + non-loopback allows) to the arbiter for the
    // dashboard's allowed/denied-destination view. A locked/failed emit is
    // swallowed and never touches the seccomp answer below. A refusal of the
    // taint leg gets its own event (the static policy DID allow the host; the
    // reason must say the process, not the rule table, is why).
    match &tainted_refusal {
        Some(refused) => {
            let proto = target.proto.name();
            emit_tainted_refusal(cfg, &format!("{}:{}/{proto}", target.ip, target.port), refused);
        }
        None => emit_decision(cfg, &target, decision, matched),
    }

    match (decision, dupfd) {
        (Decision::Deny, fd) => {
            if let Some(fd) = fd {
                close_fd(fd);
            }
            answer_errno(listener, notif, libc::EACCES);
            Ok(GuardOutcome::Denied { ip: ep.ip, port: ep.port })
        }
        (Decision::Allow, Some(fd)) => {
            // A task in a Landlock sandbox of its own (a layer nested inside
            // the launch's wrap chain): the connect runs on a mirror of it, so
            // the kernel decides the port as it would for the tracee. The
            // launch's own port wrap is superseded by the allow list above.
            let answered = match cfg.landlock.connect_via(pid) {
                Ok(crate::landlock_mirror::ConnectVia::Guard) => supervisor_connect(fd, &raw),
                Ok(crate::landlock_mirror::ConnectVia::Mirror(d)) => {
                    let addr = raw.clone();
                    d.run(move || supervisor_connect(fd, &addr)).unwrap_or_else(|e| e)
                }
                Err(e) => e,
            };
            if once_admitted && (answered == 0 || answered == libc::EINPROGRESS) {
                if let Some((_, ino)) = fd_identity(fd) {
                    cfg.once_admitted.admit(ino, ep.ip, ep.port);
                }
            }
            close_fd(fd);
            answer_errno(listener, notif, answered);
            Ok(GuardOutcome::AllowedSupervised { ip: ep.ip, port: ep.port, answered })
        }
        (Decision::Allow, None) => match allowed_without_copy(getfd_ok) {
            // A kernel with `pidfd_getfd` that could not copy THIS socket (the
            // tracee exited, `ptrace_scope` >= 2, an LSM): refused. CONTINUE
            // would let the kernel re-read an address the tracee can rewrite
            // after the check (sandbox-security-review finding 8).
            NoCopy::Refuse => {
                answer_errno(listener, notif, libc::EACCES);
                Ok(GuardOutcome::Refused { why: "allowed connect: the guard could not copy the socket to connect it itself" })
            }
            // A kernel < 5.6 has no way to copy a socket at all: the tracee's
            // own connect runs (exec-routing.md, the documented old-kernel
            // degrade; the Landlock port wrap is the backstop).
            NoCopy::Continue => {
                answer_continue(listener, notif);
                Ok(GuardOutcome::AllowedContinue { ip: ep.ip, port: ep.port })
            }
        },
    }
}

/// What an ALLOWED connect does when the guard holds no copy of the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoCopy {
    Refuse,
    Continue,
}

/// Only a kernel without `pidfd_getfd` (< 5.6) degrades to CONTINUE; any other
/// failure to copy is refused (fail-closed). Pure.
pub fn allowed_without_copy(getfd_supported: bool) -> NoCopy {
    if getfd_supported { NoCopy::Refuse } else { NoCopy::Continue }
}

/// An abstract `AF_UNIX` address with a name (not the unnamed autobind
/// form): the family, a NUL, then at least one byte.
pub(crate) fn is_abstract_unix(raw: &[u8]) -> bool {
    raw.len() > 3 && u16::from_ne_bytes([raw[0], raw[1]]) == libc::AF_UNIX as u16 && raw[2] == 0
}

/// Why a connect into a `unixDeny` entry is refused (arbiter-human-plane.md §5).
const HUMAN_PLANE_REFUSAL: &str = "Mandu's human plane (the arbiter's originals) is never reachable from the agent's process tree";

/// Refuse a Unix connect (EACCES) under the allow-list, with its event.
pub(crate) fn refuse_unix(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, dest: &str, why: &'static str) -> GuardOutcome {
    answer_errno(listener, notif, libc::EACCES);
    emit_unix_refusal(cfg, notif.pid as i32, dest, why);
    GuardOutcome::Refused { why }
}

/// The event of a refused Unix destination (best-effort).
pub(crate) fn emit_unix_refusal(cfg: &GuardConfig, pid: i32, dest: &str, why: &'static str) {
    if let Some(emitter) = &cfg.emitter {
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok().and_then(|p| p.to_str().map(String::from)).unwrap_or_default();
        let ev = crate::events::guard_unix_refusal_event(&cfg.session_id, dest, &exe, why);
        if let Ok(mut client) = emitter.lock() {
            mandu_arbiter::safe_emit(&mut client, &ev);
        }
    }
}

/// The last leg of a connect the families above did not take: AF_UNSPEC (a
/// disconnect), netlink, vsock off WSL, an unnamed or malformed Unix
/// address, any other family. Until 2026-10-01 each was CONTINUEd, and the
/// kernel then read the address and the descriptor again: another thread
/// could turn the `AF_UNSPEC` it read into an `AF_INET` address, or put an
/// INET socket under the descriptor, and connect anywhere unjudged
/// (exec-routing.md §7.5, "the connect leg's last CONTINUE"). Now the guard
/// connects its own copy of the socket to the bytes it read (the kernel's
/// own errno for an unreadable or oversized address), and a TAINTED process
/// may not address a family no binding can name
/// (`send_guard::tainted_may_address`). Since 2026-10-02 every pathname and
/// abstract Unix connect is supervised before it gets here UNDER A SECRET
/// POLICY (or WSL), in every posture (exec-routing.md §7.5 gap (e): a posture
/// without the Unix allow-list continued one, and a thread could swap an INET
/// socket under the descriptor); with no secret policy there is nothing to
/// protect and AF_UNIX passes through here. A kernel without `pidfd_getfd`
/// (< 5.6) continues too, the documented old-kernel degrade.
fn other_family_connect(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, raw: &[u8]) -> GuardOutcome {
    let pid = notif.pid as i32;
    let sockfd = notif.data.args[0] as RawFd;
    let family = if raw.len() >= 2 { u16::from_ne_bytes([raw[0], raw[1]]) } else { 0 };
    if cfg.secrets.is_some()
        && raw.len() >= 2
        && family != crate::send_guard::AF_UNSPEC
        && !crate::send_guard::tainted_may_address(family)
        && cfg.tainted.pid_tainted(pid)
    {
        answer_errno(listener, notif, libc::EACCES);
        emit_tainted_refusal(cfg, &format!("family {family}"), &TaintedRefusal::default());
        return GuardOutcome::Refused { why: "a process holding a secret addresses only INET and Unix destinations" };
    }
    // AF_UNIX reaches this leg only when it is NOT supervised (no secret
    // policy and not WSL, or no openat2): passed through, as before. The
    // swap-race fix (gap (e)) is in the supervised path, which runs under a
    // secret policy for every Unix connect.
    if family == crate::send_guard::AF_UNIX || !kernel_at_least(5, 6) {
        answer_continue(listener, notif);
        return GuardOutcome::PassedThrough { why: "non-INET or malformed sockaddr" };
    }
    // The bytes judged above are the bytes connected: never read again (a
    // thread can rewrite them in between). Short of the length the tracee
    // passed, the kernel's own answer: EINVAL past `sockaddr_storage`, else
    // EFAULT for memory its call could not read.
    let addrlen = notif.data.args[2];
    if addrlen > SOCKADDR_MAX as u64 || raw.len() as u64 != addrlen {
        let e = if addrlen > SOCKADDR_MAX as u64 { libc::EINVAL } else { libc::EFAULT };
        answer_errno(listener, notif, e);
        return GuardOutcome::OtherPerformed { answered: e };
    }
    let exact = raw.to_vec();
    match tracee_fd(pid, sockfd) {
        Ok(dup) => {
            let answered = supervisor_connect(dup, &exact);
            close_fd(dup);
            answer_errno(listener, notif, answered);
            GuardOutcome::OtherPerformed { answered }
        }
        Err(e) => {
            let errno = if e.raw_os_error() == Some(libc::EBADF) { libc::EBADF } else { libc::EACCES };
            answer_errno(listener, notif, errno);
            GuardOutcome::OtherPerformed { answered: errno }
        }
    }
}

/// What a probe connection of the guard's own finds at a Unix address.
#[derive(Debug, PartialEq, Eq)]
pub enum ListenerProbe {
    /// A listener: the probe connection, still open (the caller closes it),
    /// and the pid `SO_PEERCRED` reports. That pid is a HINT only: it is the
    /// number of whoever called `listen()`, still reported after that
    /// process exited, and then possibly another's (`unix_owner`).
    Listening { probe: RawFd, hint: Option<i32> },
    /// Nobody listens (a stale socket file: ECONNREFUSED; ENOENT): the
    /// tracee's own connect would fail the same way, and there is nothing to
    /// reach, so that errno is its answer.
    Nobody(i32),
    /// Not known: a datagram socket (no listener credentials), a full
    /// backlog, any other failure.
    Unknown,
}

/// A connect(2) errno that means nothing listens at the address. Pure.
pub fn nobody_listens(errno: i32) -> bool {
    errno == libc::ECONNREFUSED || errno == libc::ENOENT
}

/// Probe `addr` with a socket of `like`'s type (non-blocking), kept open
/// while the listener is judged, then closed: the listener sees a
/// connection that ends before a byte is sent.
fn probe_listener(like: RawFd, addr: &[u8]) -> ListenerProbe {
    let mut ty: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt into an int.
    if unsafe { libc::getsockopt(like, libc::SOL_SOCKET, libc::SO_TYPE, &mut ty as *mut libc::c_int as *mut libc::c_void, &mut len) } != 0 {
        return ListenerProbe::Unknown;
    }
    if ty != libc::SOCK_STREAM && ty != libc::SOCK_SEQPACKET {
        return ListenerProbe::Unknown;
    }
    // SAFETY: a fresh socket of our own, closed below.
    let s = unsafe { libc::socket(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if s < 0 {
        return ListenerProbe::Unknown;
    }
    // SAFETY: connect with a buffer of addr.len() bytes.
    let rc = unsafe { libc::connect(s, addr.as_ptr() as *const libc::sockaddr, addr.len() as libc::socklen_t) };
    if rc != 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        close_fd(s);
        return if nobody_listens(e) { ListenerProbe::Nobody(e) } else { ListenerProbe::Unknown };
    }
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut clen = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt into a ucred.
    let got = unsafe { libc::getsockopt(s, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut libc::ucred as *mut libc::c_void, &mut clen) } == 0;
    ListenerProbe::Listening { probe: s, hint: (got && cred.pid > 0).then_some(cred.pid) }
}

/// The allow-list's answer for an unlisted address, by its listener: the
/// agent tree's (a socket it bound, by the bind record and with no
/// connection; else, by a probe connection, its live creator or a holder,
/// never a pid number alone: `unix_owner`) → connect it; nobody listening →
/// the kernel's own errno (Claude Code probes `cc-socks/<pid>.sock` and
/// takes ECONNREFUSED as "stale, bind it"; an EACCES there stopped every
/// session after the first under the wrap's pid namespace, where the agent
/// is always pid 2); else refused. `name`: the listener's name for the
/// record's lookup (the pinned file's identity, or the abstract name).
pub(crate) fn unlisted_verdict(cfg: &GuardConfig, like: RawFd, addr: &[u8], name: Option<crate::unix_owner::ListenerName>) -> std::result::Result<(), Option<i32>> {
    // exec-routing.md §4.3 (2026-10-18): the record first. Its lookup makes
    // no connection, so the server's first accept is its client's.
    if let (Some(record), Some(name)) = (cfg.unix_binds.as_ref(), name) {
        if matches!(sockopt_int(like, libc::SO_TYPE), Some(libc::SOCK_STREAM) | Some(libc::SOCK_SEQPACKET)) {
            match crate::unix_owner::sys::judge_by_record(record, &name) {
                crate::unix_owner::RecordVerdict::Ours => return Ok(()),
                crate::unix_owner::RecordVerdict::NotOurs => return Err(None),
                crate::unix_owner::RecordVerdict::Undecided => {}
            }
        }
    }
    match probe_listener(like, addr) {
        ListenerProbe::Listening { probe, hint } => {
            let ours = crate::unix_owner::sys::owned_by_tree(probe, hint, &cfg.tree_roots);
            close_fd(probe);
            if ours { Ok(()) } else { Err(None) }
        }
        ListenerProbe::Nobody(e) => Err(Some(e)),
        _ => Err(None),
    }
}

/// An abstract-name Unix connect (finding 1; in every posture since
/// 2026-10-02): a holder's is judged against its `unix:@…` bindings, then,
/// under the allow-list, a listed name or a listener in the agent's tree is
/// connected by the guard on a copy of the tracee's socket with the address
/// it read (never CONTINUEd: the kernel would read the address and the
/// descriptor again). A socket of another network namespace (abstract names
/// are per namespace; one the tree made itself has no host service in it)
/// is connected on its copy too.
fn supervised_abstract_connect(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, raw: &[u8], taint: Option<(String, bool, Vec<String>)>) -> GuardOutcome {
    let pid = notif.pid as i32;
    let sockfd = notif.data.args[0] as RawFd;
    let dest = format!("unix:@{}", String::from_utf8_lossy(&raw[3..]).trim_end_matches('\0'));
    // Without an allow-list too (2026-10-02): connected on the copy, never
    // CONTINUEd (a thread could swap an INET socket under the descriptor).
    let dup = match tracee_fd(pid, sockfd) {
        Ok(d) => d,
        Err(_) => return refuse_unix(listener, cfg, notif, &dest, "no handle on the socket to check it with"),
    };
    if socket_in_our_netns(dup) == Some(false) {
        // Abstract names are per namespace; one the tree made itself has no
        // host service in it. Connected on the copy, never CONTINUEd (a
        // thread could put another socket under the descriptor).
        let answered = supervisor_connect(dup, raw);
        close_fd(dup);
        answer_errno(listener, notif, answered);
        return GuardOutcome::DifferentNetns;
    }
    let outcome = match abstract_unix_verdict(cfg, pid, dup, raw, taint) {
        UnixVerdict::Go { addr, .. } => {
            let answered = supervisor_connect(dup, &addr);
            answer_errno(listener, notif, answered);
            GuardOutcome::UnixSupervised { answered }
        }
        UnixVerdict::Errno(e) => {
            answer_errno(listener, notif, e);
            GuardOutcome::UnixSupervised { answered: e }
        }
        UnixVerdict::Refused(o) => {
            answer_errno(listener, notif, libc::EACCES);
            o
        }
        UnixVerdict::NoHandle { .. } => {
            answer_errno(listener, notif, libc::EACCES);
            GuardOutcome::Refused { why: "no handle on the socket to check it with" }
        }
    };
    close_fd(dup);
    outcome
}

/// What the checks of a Unix destination decided, for a connect or for a
/// send that names it (exec-routing.md §7.5, 2026-10-01: a datagram sent to
/// a path or a name is judged like a connect to it).
pub(crate) enum UnixVerdict {
    /// Reach this address: `/proc/self/fd/<pin>` of the inode the checks
    /// opened (a pathname), or the abstract name as read. `pin` is the
    /// guard's descriptor of that inode, the caller's to close.
    Go { addr: Vec<u8>, pin: Option<RawFd>, dest: String },
    /// Answer this errno (the lookup's own, or nobody listening).
    Errno(i32),
    /// Refused: answer EACCES (the event is emitted).
    Refused(GuardOutcome),
    /// The checks passed, but the allow-list needs a handle on the socket
    /// and there is none; `pin` is the caller's to close.
    NoHandle { pin: RawFd, dest: String },
}

/// The checks of an abstract-name destination: a TAINTED process reaches
/// only its `unix:@…` bindings (plan 10 §4.3; until 2026-10-01 an abstract
/// name skipped the taint leg whenever an allow-list was in force), then the
/// allow-list (a listed name, or a listener in the agent's tree).
pub(crate) fn abstract_unix_verdict(cfg: &GuardConfig, pid: i32, dup: RawFd, raw: &[u8], taint: Option<(String, bool, Vec<String>)>) -> UnixVerdict {
    let dest = format!("unix:@{}", String::from_utf8_lossy(&raw[3..]).trim_end_matches('\0'));
    if let (Some((own, true, chain)), Some(name)) = (taint, crate::secret_open::unix_path_of(raw)) {
        if let Some(refused) = tainted_unix_refusal(cfg, &own, chain, &name) {
            emit_tainted_refusal(cfg, &dest, &refused);
            return UnixVerdict::Refused(GuardOutcome::PassedThrough { why: "tainted process → unbound unix socket: refused" });
        }
    }
    let Some(policy) = cfg.secrets.as_ref().and_then(|i| i.unix_policy.as_ref()) else {
        return UnixVerdict::Go { addr: raw.to_vec(), pin: None, dest };
    };
    // The name is the bytes after the NUL, up to the address length.
    if !crate::secret_open::abstract_allowed(policy, &raw[3..]) {
        match unlisted_verdict(cfg, dup, raw, Some(crate::unix_owner::ListenerName::Abstract(&raw[2..]))) {
            Ok(()) => {}
            Err(Some(e)) => return UnixVerdict::Errno(e),
            Err(None) => {
                let why = "not on the list, and its listener is not in the agent's process tree";
                emit_unix_refusal(cfg, pid, &dest, why);
                return UnixVerdict::Refused(GuardOutcome::Refused { why });
            }
        }
    }
    UnixVerdict::Go { addr: raw.to_vec(), pin: None, dest }
}

/// The supervised pathname AF_UNIX connect (exec-routing.md §4.1, "Whole
/// agent"). `None` = supervision is unavailable here (openat2 missing), so the
/// caller falls back to the path-string checks; otherwise the tracee has been
/// answered and the outcome says how.
///
/// 1. Open the target `O_PATH` in the TRACEE's view (`open_tracee_unix_target`:
///    its root and cwd, `RESOLVE_IN_ROOT`, its own descriptor for
///    `/proc/self/fd/N`). A lookup error is answered as the connect's errno,
///    the one the kernel would have given (fail-closed: never CONTINUE, which
///    would re-resolve).
/// 2. Check THAT inode: WSL's interop sockets by identity and path, a secret
///    socket's readers, a tainted process's `unix:` bindings.
/// 3. Grab the tracee's socket (`pidfd_getfd`) and connect it to
///    `/proc/self/fd/<N>` of the checked descriptor, so the kernel connects
///    exactly the checked inode; answer with that result.
fn supervised_unix_connect(
    listener: RawFd,
    cfg: &GuardConfig,
    notif: &libc::seccomp_notif,
    pbytes: &[u8],
    taint: Option<(String, bool, Vec<String>)>,
) -> Option<GuardOutcome> {
    let pid = notif.pid as i32;
    let sockfd = notif.data.args[0] as RawFd;
    let dup = tracee_fd(pid, sockfd).ok();
    let Some(verdict) = unix_path_verdict(cfg, pid, pbytes, taint, dup) else {
        if let Some(d) = dup {
            close_fd(d);
        }
        return None;
    };
    let listed = cfg.secrets.as_ref().and_then(|i| i.unix_policy.as_ref()).is_some();
    let outcome = match (verdict, dup) {
        (UnixVerdict::Errno(e), _) => {
            answer_errno(listener, notif, e);
            GuardOutcome::UnixSupervised { answered: e }
        }
        (UnixVerdict::Refused(o), _) => {
            answer_errno(listener, notif, libc::EACCES);
            o
        }
        // Connect the tracee's own socket to the checked inode.
        (UnixVerdict::Go { addr, pin, .. }, Some(d)) => {
            let answered = supervisor_connect(d, &addr);
            if let Some(p) = pin {
                close_fd(p);
            }
            answer_errno(listener, notif, answered);
            GuardOutcome::UnixSupervised { answered }
        }
        (UnixVerdict::Go { pin: Some(pin), dest, .. } | UnixVerdict::NoHandle { pin, dest }, None) if listed => {
            // Finding 1: nothing to probe the listener with, and CONTINUE
            // would re-resolve the path: refused.
            close_fd(pin);
            refuse_unix(listener, cfg, notif, &dest, "no handle on the socket to check it with")
        }
        (UnixVerdict::Go { pin, .. }, None) => {
            // No handle on the socket (a racing exit, a ptrace-restricted
            // host): the checks above passed on the inode, but only the
            // kernel could run the connect now, re-reading the path and the
            // descriptor. Refused (2026-10-02, as an INET connect without a
            // copy is: `allowed_without_copy`); it was CONTINUEd.
            if let Some(p) = pin {
                close_fd(p);
            }
            answer_errno(listener, notif, libc::EACCES);
            GuardOutcome::Refused { why: "unix: no handle on the socket to connect it with" }
        }
        (UnixVerdict::NoHandle { pin, dest }, _) => {
            close_fd(pin);
            refuse_unix(listener, cfg, notif, &dest, "no handle on the socket to check it with")
        }
    };
    if let Some(d) = dup {
        close_fd(d);
    }
    Some(outcome)
}

/// The checks of a pathname Unix destination, shared by a connect
/// (`supervised_unix_connect`) and a send that names it (`guard_send`).
/// `None` = no supervision on this kernel (openat2 missing).
///
/// 1. Open the target `O_PATH` in the TRACEE's view (`open_tracee_unix_target`:
///    its root and cwd, `RESOLVE_IN_ROOT`, its own descriptor for
///    `/proc/self/fd/N`). A lookup error is the answer, the errno the kernel
///    would have given (fail-closed: never CONTINUE, which would re-resolve).
/// 2. Check THAT inode: the human plane, WSL's interop sockets by identity
///    and path, a secret socket's readers, a tainted process's `unix:`
///    bindings, then the allow-list (with `dup`, the tracee's socket, to
///    probe an unlisted listener with).
/// 3. `Go`: the caller connects (or sends on) the tracee's socket to
///    `/proc/self/fd/<N>` of the checked descriptor, so the kernel reaches
///    exactly the checked inode.
/// Plan 13 D8: what a secret socket's reader check needs about the
/// connecting process (`socket_reader_match`): its executable, whether that
/// binary is out of the agent's reach AND runs with a clean loader
/// environment, and its ancestors' (executable, trusted) pairs.
fn socket_opener_facts(index: &crate::secret_open::SecretIndex, pid: i32) -> (String, Option<String>, bool, Vec<(String, bool)>) {
    let id = index.identity.exe(pid);
    let clean = !id.path.is_empty() && index.identity.findings(pid, &id.path).is_some_and(|v| v.is_empty());
    let ancestors = index.identity.ancestors(pid, 16);
    (id.path, id.sha256, id.system && clean, ancestors)
}

/// May `pid` connect to the secret socket `sock`? Its reader entry, by name,
/// trust and lineage (`socket_reader_match`; the findings behind the trust
/// include an interpreter by its content, `runs:`), and then the arbiter's
/// identity of its binary (`readerProgram`, Plan 13 D8, 2026-10-03): by name
/// and by the hashes of the host's installed programs, so a byte-identical
/// copy of a printer or of a program that runs code under a leaf program's
/// name is refused as every other reader list refuses it. The arbiter
/// unreachable, or the binary unhashed: refused (`socket_identity_admits`).
/// Returns the verdict and the executable (for the refusal's event).
fn secret_socket_admits(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex, sock: &crate::secret_open::SocketSecret, pid: i32) -> (bool, String) {
    let (exe, sha256, trusted, ancestors) = socket_opener_facts(index, pid);
    if crate::secret_open::socket_reader_match(&sock.readers, &exe, trusted, &ancestors).is_none() {
        return (false, exe);
    }
    let answer = sha256.as_ref().and_then(|sha| {
        let c = cfg.emitter.as_ref()?;
        let mut client = c.lock().ok()?;
        let args = mandu_arbiter::protocol::ReaderProgramArgs { exe: exe.clone(), sha256: Some(sha.clone()) };
        client.reader_program(&args).ok().map(|r| (r.prints, r.runs_code))
    });
    (crate::secret_open::socket_identity_admits(answer), exe)
}

pub(crate) fn unix_path_verdict(cfg: &GuardConfig, pid: i32, pbytes: &[u8], taint: Option<(String, bool, Vec<String>)>, dup: Option<RawFd>) -> Option<UnixVerdict> {
    let target = match open_tracee_unix_target(pid, pbytes) {
        Ok(fd) => fd,
        Err(libc::ENOSYS) => return None,
        Err(errno) => return Some(UnixVerdict::Errno(errno)),
    };
    let id = fd_identity(target);
    let seen = std::fs::read_link(format!("/proc/self/fd/{target}")).ok().and_then(|p| p.to_str().map(String::from));
    let dest = format!("unix:{}", seen.clone().unwrap_or_else(|| String::from_utf8_lossy(pbytes).into_owned()));
    let exe_of = || std::fs::read_link(format!("/proc/{pid}/exe")).ok().and_then(|p| p.to_str().map(String::from)).unwrap_or_default();
    let refused = |outcome: GuardOutcome| {
        close_fd(target);
        Some(UnixVerdict::Refused(outcome))
    };

    // arbiter-human-plane.md §5: the human-plane directory, FIRST and
    // unconditionally — judged on the opened inode (its path now, and its
    // identity among the directory's entries), so a symlink, a hard link or
    // a bind mount of the human socket is refused like the socket itself.
    if let Some(index) = cfg.secrets.as_ref() {
        if index.unix_denied_now(seen.as_deref(), id).is_some() {
            emit_unix_refusal(cfg, pid, &dest, HUMAN_PLANE_REFUSAL);
            return refused(GuardOutcome::Refused { why: HUMAN_PLANE_REFUSAL });
        }
    }

    // WSL: the interop door, by identity (every entry of /run/WSL and the
    // $WSL_INTEROP socket, stat'ed now) and by the opened file's path.
    if let (Some(w), Some(id)) = (cfg.wsl.as_ref(), id) {
        if let Some(why) = w.refusal_by_identity(id, seen.as_deref(), &interop_ids_now(w)) {
            if let Some(emitter) = &cfg.emitter {
                let ev = crate::events::guard_wsl_refusal_event(&cfg.session_id, &dest, why, &exe_of());
                if let Ok(mut client) = emitter.lock() {
                    mandu_arbiter::safe_emit(&mut client, &ev);
                }
            }
            return refused(GuardOutcome::Refused { why });
        }
    }
    // A socket that is itself a secret (the ssh-agent): only a listed reader.
    if let (Some(index), Some(id)) = (cfg.secrets.as_ref(), id) {
        if let Some(sock) = index.socket_for_inode(seen.as_deref(), id, path_identity) {
            let (admitted, exe) = secret_socket_admits(cfg, index, sock, pid);
            if !admitted {
                if let Some(emitter) = &cfg.emitter {
                    let ev = crate::events::guard_socket_refusal_event(&cfg.session_id, &dest, sock.label.as_deref().unwrap_or("secret socket"), &exe);
                    if let Ok(mut client) = emitter.lock() {
                        mandu_arbiter::safe_emit(&mut client, &ev);
                    }
                }
                return refused(GuardOutcome::PassedThrough { why: "secret socket: not a listed reader, refused" });
            }
        }
    }
    // §4.3: a TAINTED process reaches only its `unix:` bindings and the
    // arbiter's own socket (both judged on the opened inode).
    if let Some((own, true, chain)) = taint {
        let arbiter = std::env::var("MANDU_ARBITER_SOCK").ok().filter(|s| !s.is_empty());
        let is_arbiter = id.is_some() && arbiter.as_deref().and_then(path_identity) == id;
        if !is_arbiter {
            let checked = seen.clone().unwrap_or_else(|| String::from_utf8_lossy(pbytes).into_owned());
            if let Some(refusal) = tainted_unix_refusal(cfg, &own, chain, &checked) {
                emit_tainted_refusal(cfg, &dest, &refusal);
                return refused(GuardOutcome::PassedThrough { why: "tainted process → unbound unix socket: refused" });
            }
        }
    }

    // Finding 1: the allow-list. The arbiter's socket, a listed socket, or a
    // socket whose listener is the agent tree's own (the bind record, by the
    // pinned file's identity; else a probe connection of the guard's own
    // finds its live creator or a holder: `unix_owner`; the socket file is
    // pinned by `target`, so the listener cannot change under it).
    let pinned = sockaddr_un_bytes(&format!("/proc/self/fd/{target}"));
    if let Some(policy) = cfg.secrets.as_ref().and_then(|i| i.unix_policy.as_ref()) {
        let arbiter = std::env::var("MANDU_ARBITER_SOCK").ok().filter(|s| !s.is_empty());
        let is_arbiter = id.is_some() && arbiter.as_deref().and_then(path_identity) == id;
        let listed_here = is_arbiter || crate::secret_open::unix_allowed(policy, seen.as_deref(), id, path_identity).is_some();
        if !listed_here {
            let Some(d) = dup else { return Some(UnixVerdict::NoHandle { pin: target, dest }) };
            let name = id.map(|(dev, ino)| crate::unix_owner::ListenerName::File { dev, ino });
            match unlisted_verdict(cfg, d, &pinned, name) {
                Ok(()) => {}
                Err(Some(e)) => {
                    close_fd(target);
                    return Some(UnixVerdict::Errno(e));
                }
                Err(None) => {
                    let why = "not on the list, and its listener is not in the agent's process tree";
                    emit_unix_refusal(cfg, pid, &dest, why);
                    return refused(GuardOutcome::Refused { why });
                }
            }
        }
    }
    Some(UnixVerdict::Go { addr: pinned, pin: Some(target), dest })
}

/// `(st_dev, st_ino)` of a path (symlinks followed), for the identity checks.
pub(crate) fn path_identity(p: &str) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))
}

/// WSL: the identities of the interop sockets NOW: every entry of `/run/WSL`
/// (a later session's socket included) and the socket `$WSL_INTEROP` named.
pub(crate) fn interop_ids_now(w: &crate::guard::WslGuard) -> Vec<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let mut ids: Vec<(u64, u64)> = std::fs::read_dir(mandu_arbiter::wsl::INTEROP_DIR)
        .map(|rd| rd.flatten().filter_map(|e| std::fs::metadata(e.path()).ok()).map(|m| (m.dev(), m.ino())).collect())
        .unwrap_or_default();
    if let Some(id) = w.interop_env.as_deref().and_then(path_identity) {
        ids.push(id);
    }
    ids
}

/// What a write-protect judge decided for one change.
enum WriteJudgement {
    /// Not under a write-protect entry, or the human allowed it: go on.
    Proceed,
    /// Refused: answer EACCES (the event is already emitted).
    Refused,
    /// The tracee's call went away while held: answer nothing.
    Gone,
}

/// What a write-open resolved, pinned by a descriptor of the guard's own
/// (the write-open race: the check and the change see the same file).
#[derive(Clone, Copy)]
enum PinnedWrite<'a> {
    /// An existing file, `O_PATH` (or open).
    File(RawFd),
    /// A file to be created as `name` in this directory.
    NewIn(RawFd, &'a [u8]),
}

/// A marker the write-open judge returns for a pseudo-filesystem target (no
/// real errno is this large).
const PSEUDO_WRITE: i32 = 0x7ffe;

/// A write open of a pseudo-filesystem file, performed by the context helper
/// with the tracee's credentials and namespaces for the WHOLE walk: an
/// absolute path under the tracee's root (`RESOLVE_IN_ROOT`), a relative one
/// beneath its cwd or `dirfd` (`RESOLVE_BENEATH`: a `..` out of it is
/// refused, rare for such a file).
fn pseudo_write_as_tracee(cfg: &GuardConfig, pid: i32, dirfd: i32, raw: &[u8], flags: i32, resolve: u64, domain: Option<&Arc<crate::landlock_mirror::Domain>>) -> std::result::Result<RawFd, i32> {
    let extra = resolve & (libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV);
    let open_path = |p: String| -> std::result::Result<RawFd, i32> {
        let c = std::ffi::CString::new(p).map_err(|_| libc::ENOENT)?;
        // SAFETY: open with a NUL-terminated path; returns an fd or -1.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if fd < 0 { Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)) } else { Ok(fd) }
    };
    let (base, rel, how) = if raw.first() == Some(&b'/') {
        let rel = raw.iter().position(|b| *b != b'/').map(|i| &raw[i..]).unwrap_or(b".");
        (open_path(format!("/proc/{pid}/root"))?, rel, libc::RESOLVE_IN_ROOT | extra)
    } else if dirfd == libc::AT_FDCWD {
        (open_path(format!("/proc/{pid}/cwd"))?, raw, libc::RESOLVE_BENEATH | extra)
    } else {
        (tracee_fd(pid, dirfd).map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF))?, raw, libc::RESOLVE_BENEATH | extra)
    };
    let r = cfg.helpers.lookup_as(pid, base, rel, flags, how, domain);
    close_fd(base);
    r
}

/// The write-protect entry a pinned target falls under
/// (`write_protected_hit_pinned`): matched by the path its descriptor names
/// and by identity, its own and its directories'. `Err(())`: the descriptor
/// names no path (refused, fail-closed).
fn pinned_write_hit(cfg: &GuardConfig, pinned: PinnedWrite) -> std::result::Result<Option<(String, crate::secret_open::WriteProtect)>, ()> {
    use std::os::unix::fs::MetadataExt;
    let Some(index) = cfg.secrets.as_ref() else { return Ok(None) };
    if index.write_protect.is_empty() {
        return Ok(None);
    }
    let link = |fd: RawFd| std::fs::read_link(format!("/proc/self/fd/{fd}")).ok().map(|p| p.to_string_lossy().into_owned());
    let (seen, own, dir) = match pinned {
        PinnedWrite::File(fd) => {
            let seen = link(fd).ok_or(())?;
            let dir = std::path::Path::new(&seen).parent().map(|p| p.to_string_lossy().into_owned());
            (seen, fd_identity(fd), dir)
        }
        PinnedWrite::NewIn(dir, name) => {
            let d = link(dir).ok_or(())?;
            let mut seen = d.clone();
            if !seen.ends_with('/') {
                seen.push('/');
            }
            seen.push_str(&String::from_utf8_lossy(name));
            // An existing file of that name (a rename's destination, an
            // unlink's target) is judged by its own identity too.
            (seen, leaf_identity(dir, name), Some(d))
        }
    };
    let id = |p: &str| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
    let mut ancestors: Vec<(u64, u64)> = dir.as_deref().map(|d| std::path::Path::new(d).ancestors().filter_map(|a| a.to_str().and_then(id)).collect()).unwrap_or_default();
    // The pinned directory's own `..` chain: a spelling of a write-protected
    // folder that exists only in the tracee's mount namespace (a bind) names
    // nothing in the guard's view, so the path-derived chain above misses it.
    if let PinnedWrite::NewIn(pin, _) = pinned {
        for i in pinned_dir_chain(pin) {
            if !ancestors.contains(&i) {
                ancestors.push(i);
            }
        }
    }
    if let Some(e) = crate::secret_open::write_protected_hit_pinned(&index.write_protect, &seen, own, &ancestors, id) {
        return Ok(Some((seen, e.clone())));
    }
    // The `name` / `prefix` / `self` entries (Mandu's runtime registry,
    // runtime-instances.md §2): by the leaf's name in the directory the
    // change lands in, that directory matched by identity (a bind or a
    // symlinked spelling of the runtime base), or by the target's own
    // identity, a link not followed.
    let leaf = match pinned {
        PinnedWrite::NewIn(_, name) => String::from_utf8_lossy(name).into_owned(),
        PinnedWrite::File(_) => std::path::Path::new(&seen).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
    };
    let dir_id = match pinned {
        PinnedWrite::NewIn(pin, _) => fs_supervisor::tracee::fd_identity(pin),
        PinnedWrite::File(_) => dir.as_deref().and_then(id),
    };
    let lid = |p: &str| std::fs::symlink_metadata(p).ok().map(|m| (m.dev(), m.ino()));
    Ok(crate::secret_open::write_protected_hit_named(&index.write_protect, &leaf, own, dir_id, id, lid).cloned().map(|e| (seen, e)))
}

/// The write-protect entry that lies strictly below the name `leaf` in the
/// pinned directory `pin` (`secret_open::write_protected_ancestor_hit`):
/// removing, renaming or creating that name replaces the entry's file or
/// directory with no write under it. By path (the pinned parent's path plus
/// the leaf) and, for an existing directory, by identity. Err: the pinned
/// parent's path cannot be read (refused, fail-closed).
fn pinned_ancestor_write_hit(cfg: &GuardConfig, pin: RawFd, leaf: &[u8]) -> std::result::Result<Option<(String, crate::secret_open::WriteProtect)>, ()> {
    use std::os::unix::fs::MetadataExt;
    let Some(index) = cfg.secrets.as_ref() else { return Ok(None) };
    if index.write_protect.is_empty() {
        return Ok(None);
    }
    let dir = std::fs::read_link(format!("/proc/self/fd/{pin}")).map_err(|_| ())?;
    let mut seen = dir.to_string_lossy().into_owned();
    if !seen.ends_with('/') {
        seen.push('/');
    }
    seen.push_str(&String::from_utf8_lossy(leaf));
    let dir_self = leaf_dir_identity(pin, leaf);
    let id = |p: &str| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
    Ok(crate::secret_open::write_protected_ancestor_hit(&index.write_protect, &seen, dir_self, id).cloned().map(|e| (seen, e)))
}

/// The identity of `leaf` in the pinned directory when it is a directory
/// (not following a final symlink), else None.
fn leaf_dir_identity(pin: RawFd, leaf: &[u8]) -> Option<(u64, u64)> {
    let name = std::ffi::CString::new(leaf).ok()?;
    // SAFETY: fstatat into a zeroed stat buffer; `name` is NUL-terminated.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::fstatat(pin, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0;
    (ok && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR).then_some((st.st_dev, st.st_ino))
}

/// A change to `target`, which falls under `entry` of the write-protect list:
/// refused (`deny`), or held for the human (`ask`).
fn judge_write_hit(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, target: &str, entry: &crate::secret_open::WriteProtect) -> WriteJudgement {
    let Some(index) = cfg.secrets.as_ref() else { return WriteJudgement::Proceed };
    let pid = notif.pid as i32;
    let refuse = |why: &str| {
        if let Some(emitter) = &cfg.emitter {
            let ev = crate::events::guard_write_refusal_event(&cfg.session_id, target, &entry.path, &entry.label, why);
            if let Ok(mut client) = emitter.lock() {
                mandu_arbiter::safe_emit(&mut client, &ev);
            }
        }
        WriteJudgement::Refused
    };
    if entry.answer() == crate::secret_open::WriteAnswer::Deny {
        return refuse("Mandu's own files are never changed from the agent's side");
    }
    // The writer's identity, as an opener's (write-protection.md §2.1, the
    // Plan 13 D8 follow-up): the binary's path and the hash of the inode it
    // runs key the human's verdict, and the loader / interpreter variables
    // the launch did not give, or agent-writable code mapped in, refuse it
    // (reader_identity). Unreadable facts are sent absent: the arbiter
    // refuses.
    let identity = index.identity.exe(pid);
    let opener_env = if identity.path.is_empty() { None } else { index.identity.findings(pid, &identity.path) };
    // Plan 13 §8 decision (c): an interpreter writer's verdict names the
    // script it runs (R5's facts, as for an opener); inline code and the like
    // are a reason, and the arbiter keys such a writer's answer by its run.
    let (script, script_problem) = match if identity.path.is_empty() { None } else { index.identity.script(pid, &identity.path) } {
        None => (None, None),
        Some(Ok(f)) => (Some(mandu_arbiter::protocol::ScriptFactsWire { path: f.path, sha256: f.sha256, system: f.system, isolated: f.isolated, traced: f.traced }), None),
        Some(Err(why)) => (None, Some(why)),
    };
    let args = mandu_arbiter::protocol::DecideProtectedWriteArgs {
        path: target.to_string(),
        exe: identity.path.clone(),
        sha256: identity.sha256.clone(),
        exe_system: Some(identity.system),
        opener_env,
        script,
        script_problem,
        proc_key: crate::secret_open::own_key_of(pid),
        label: entry.label.clone(),
        session: index.session.clone(),
        held_ms: None,
    };
    let decide = |args: &mandu_arbiter::protocol::DecideProtectedWriteArgs| -> Option<mandu_arbiter::protocol::ProtectedWriteVerdict> {
        let c = cfg.emitter.as_ref()?;
        let mut client = c.lock().ok()?;
        client.decide_protected_write(args).ok()
    };
    let deadline = Instant::now() + Duration::from_millis(index.ask_timeout_ms);
    let mut v = match decide(&args) {
        Some(v) => v,
        None => return refuse("the arbiter could not be asked"),
    };
    while v.verdict == "ask" {
        if !notif_id_valid(listener, notif.id) {
            return WriteJudgement::Gone;
        }
        if Instant::now() >= deadline {
            let expired = mandu_arbiter::protocol::DecideProtectedWriteArgs { held_ms: Some(index.ask_timeout_ms), ..args.clone() };
            v = decide(&expired).unwrap_or(mandu_arbiter::protocol::ProtectedWriteVerdict {
                verdict: "deny".into(),
                reason: format!("held for {} s, nobody answered", index.ask_timeout_ms / 1000),
                approval_id: None,
            });
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
        v = match decide(&args) {
            Some(next) => next,
            None => return refuse("the arbiter could not be asked"),
        };
    }
    if v.verdict == "allow" {
        return WriteJudgement::Proceed;
    }
    let why = if v.reason.is_empty() { "not allowed".to_string() } else { v.reason.clone() };
    refuse(&why)
}

/// A delete or rename (policy.yaml `protect:`, and the write-protect list),
/// or a link, symlink, truncate, creat, mknod, mode change or extended-
/// attribute change (the write-protect list) in the agent's tree. The guard PERFORMS the call on the tracee's behalf and never
/// CONTINUEs it (the path-change TOCTOU, sandbox-security-review-2026-09-28
/// findings 6/7): each parent is pinned to an `O_PATH` directory descriptor
/// resolved in the tracee's view, the judge runs on the pinned directory plus
/// the leaf, and the mutating `*at` syscall runs relative to those pinned
/// descriptors with a one-component leaf, so the kernel never re-resolves a
/// path a racing thread could rewrite or a parent it could swap a symlink for.
/// `protect:` refuses with EACCES when a named path, or an ancestor of one,
/// would disappear or be replaced; the write-protect list is judged for every
/// path the call names; a registered secret named as a rename source, a hard-
/// link source or a truncate target, or whose mode or extended attributes a
/// call would change, is refused (`xattr_change` has the attribute rule). The guard fails closed (EACCES
/// or the tracee's own errno) whenever it cannot act exactly as the tracee.
// The pass-through test below lists, term by term, what makes a call worth
// guarding (decision logic): it stays in that form, not clippy's De Morgan one.
#[allow(clippy::nonminimal_bool)]
fn handle_path_change_notif(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) {
    let Some(index) = cfg.secrets.as_ref() else { answer_continue(listener, notif); return };
    let nr = notif.data.nr as i64;
    let deleting = crate::secret_open::is_delete_nr(nr);
    // x86_64 `creat`: the write-open path performs and judges it (pinned dir +
    // name, O_TRUNC after the secret lookup), so route it there.
    #[cfg(target_arch = "x86_64")]
    if nr == libc::SYS_creat as i64 {
        let _ = handle_open_notif(listener, cfg, notif);
        return;
    }
    let is_rename = nr == libc::SYS_renameat as i64 || nr == libc::SYS_renameat2 as i64 || { #[cfg(target_arch = "x86_64")] { nr == libc::SYS_rename as i64 } #[cfg(not(target_arch = "x86_64"))] { false } };
    let is_link = nr == libc::SYS_linkat as i64 || { #[cfg(target_arch = "x86_64")] { nr == libc::SYS_link as i64 } #[cfg(not(target_arch = "x86_64"))] { false } };
    let is_symlink = nr == libc::SYS_symlinkat as i64 || { #[cfg(target_arch = "x86_64")] { nr == libc::SYS_symlink as i64 } #[cfg(not(target_arch = "x86_64"))] { false } };
    let is_truncate = nr == libc::SYS_truncate as i64;
    let is_mknod = crate::secret_open::is_mknod_nr(nr);
    let is_mode = crate::secret_open::is_mode_nr(nr);
    let is_xattr = crate::xattr_change::is_xattr_nr(nr);
    // Plan 13 §9 R4 (b), 2026-10-04: a holder's name or attribute on a mount
    // that leaves the machine is refused unless bound (`judge_change`,
    // `holder_change_refusal`), so a holder's call is always performed on
    // what the guard pinned and judged. Nobody holding a secret: no lookup.
    let holder = call_holder(cfg, notif.pid as i32).is_some();
    if crate::secret_open::is_mkdir_nr(nr) {
        // Trapped for the holder rule alone: anyone else's runs at once.
        if holder {
            perform_mkdir(listener, cfg, notif, nr);
        } else {
            answer_continue(listener, notif);
        }
        return;
    }
    // Nothing any role of THIS call could refuse ⇒ CONTINUE (no perform cost):
    // the write-protect list matters for every call, the `protect:` list for
    // deletes/renames, and a registered secret for a rename source or
    // destination, a hard-link source, a removed name, a truncate target, a
    // mode change's or an attribute change's target.
    let secret_relevant = is_rename || is_link || is_truncate || is_mode || is_xattr || deleting;
    // Plan 14 §11.1 R4: with a lock in force, a rename, a hard link, an
    // unlink and a truncate may move or unanchor a locked object.
    let lock_relevant = (is_rename || is_link || is_truncate || deleting) && index.git_locks().is_some();
    // Confidentiality plan 13 D4: a renamed or hard-linked derived file's
    // label follows it (`derived_follows`), wherever an arbiter can record it.
    // Plan 13 §9 R4 (b): a mode or ACL change may open a derived file to
    // other local users (`pinned_derived`).
    let derived_relevant = (is_rename || is_link || is_mode || is_xattr) && cfg.emitter.is_some();
    if index.write_protect.is_empty()
        && (!deleting || index.protect.is_empty())
        && !(secret_relevant && index.has_registered_secrets())
        && !lock_relevant
        && !derived_relevant
        && !holder
    {
        answer_continue(listener, notif);
        return;
    }
    if is_rename {
        perform_rename(listener, cfg, notif, nr);
    } else if is_link {
        perform_link(listener, cfg, notif, nr);
    } else if is_symlink {
        perform_symlink(listener, cfg, notif, nr);
    } else if is_truncate {
        perform_truncate(listener, cfg, notif);
    } else if is_mknod {
        perform_mknod(listener, cfg, notif, nr);
    } else if is_mode {
        perform_chmod(listener, cfg, notif, nr);
    } else if is_xattr {
        perform_xattr(listener, cfg, notif, nr);
    } else {
        // The unlink family (unlinkat / unlink / rmdir).
        perform_unlink(listener, cfg, notif, nr);
    }
}

/// The verdict a per-target judge reaches. `Refused` has already emitted its
/// event; the caller answers EACCES. `Gone` means the notification withdrew
/// while the judge held for a human; the caller answers nothing.
enum ChangeVerdict {
    Proceed,
    Refused,
    Gone,
}

/// The mode a pinned leaf is opened `O_PATH` in for its identity: a rename
/// source, a hard-link source with `AT_SYMLINK_FOLLOW`, and a truncate follow
/// the final symlink; a name being removed, replaced or created does not.
fn open_leaf(pin: RawFd, leaf: &[u8], follow: bool) -> Option<RawFd> {
    let c = std::ffi::CString::new(leaf).ok()?;
    let mut flags = libc::O_PATH | libc::O_CLOEXEC;
    if !follow {
        flags |= libc::O_NOFOLLOW;
    }
    // SAFETY: openat resolves a single leaf component relative to the pinned
    // directory fd; no path is re-walked. Returns an fd or -1.
    let fd = unsafe { libc::openat(pin, c.as_ptr(), flags) };
    if fd < 0 { None } else { Some(fd) }
}

/// Pin the PARENT directory of the tracee's path argument to an `O_PATH`
/// directory descriptor, resolved in the tracee's own view
/// (`open_as_tracee`), and return it with the final component (the leaf, never
/// resolved). Err = the errno the tracee's own call would meet (fail-closed:
/// the guard never CONTINUEs to let the kernel re-resolve).
fn pin_parent(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, dirfd: i32, addr: u64) -> std::result::Result<(RawFd, Vec<u8>), i32> {
    let raw = fs_supervisor::tracee::read_path_bytes(notif.pid as i32, addr)?;
    pin_parent_bytes(listener, cfg, notif, dirfd, &raw)
}

/// `pin_parent` for a path already read from the tracee (a `bind` sockaddr's
/// path, read by `addrlen` and possibly un-terminated, comes this way).
fn pin_parent_bytes(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, dirfd: i32, raw: &[u8]) -> std::result::Result<(RawFd, Vec<u8>), i32> {
    let _ = cfg;
    let (parent, leaf) = crate::secret_open::split_parent_leaf(raw).ok_or(libc::EACCES)?;
    let fd = resolve_opath_as_tracee(listener, notif, dirfd, &parent, libc::O_DIRECTORY)?;
    Ok((fd, leaf))
}

/// Resolve `path` in the tracee's view to an `O_PATH` descriptor the guard
/// owns (a directory with `O_DIRECTORY`, symlinks in intermediate components
/// followed; `extra` = `O_NOFOLLOW`/`O_DIRECTORY`). Uses the split `Via`
/// resolution (`open_via`'s `O_PATH` step) and keeps that resolved
/// descriptor, never a reopen of it. Err = the errno for the tracee.
fn resolve_opath_as_tracee(listener: RawFd, notif: &libc::seccomp_notif, dirfd: i32, path: &[u8], extra: i32) -> std::result::Result<RawFd, i32> {
    use fs_supervisor::tracee::{Final, Finish};
    let pid = notif.pid as i32;
    let valid = || notif_id_valid(listener, notif.id);
    let keep = |step: Final| match step {
        // SAFETY: a duplicate of the resolved O_PATH descriptor, which the
        // resolver closes when it returns.
        Final::Reopen { fd, .. } => match unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) } {
            d if d >= 0 => Ok(d),
            _ => Err(Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)),
        },
        // A parent/target that would have to be created is not a resolution the
        // name-family judge asks for (no O_CREAT is set).
        Final::Create { .. } => Err(libc::ENOENT),
    };
    let opened = fs_supervisor::tracee::open_as_tracee_via(pid, dirfd, path, libc::O_PATH | extra, 0, 0, &valid, Finish::Via(&keep))?;
    Ok(opened.fd)
}

/// Read a path argument's bytes, or answer the tracee its errno and return None.
fn read_change_path(listener: RawFd, notif: &libc::seccomp_notif, addr: u64) -> Option<Vec<u8>> {
    match fs_supervisor::tracee::read_path_bytes(notif.pid as i32, addr) {
        Ok(p) => Some(p),
        Err(e) => {
            answer_errno(listener, notif, e);
            None
        }
    }
}

/// The `protect:` entry a pinned parent + leaf falls under (a named path, or
/// an ancestor of one, that would disappear or be replaced): by the resolved
/// path the pinned directory names plus the leaf, and by the files'
/// identities taken from the pinned descriptor itself (the leaf by
/// `fstatat`, the parents by its `..` chain), never by re-resolving a path
/// string in the guard's view: a spelling that exists only in the tracee's
/// mount namespace (a bind of the protected folder) names nothing there.
/// Each entry is matched in the guard's view and in the tracee's
/// (`/proc/<pid>/root`). `None` = not protected.
fn pinned_protected_hit(cfg: &GuardConfig, pid: i32, pin: RawFd, leaf: &[u8]) -> Option<String> {
    let index = cfg.secrets.as_ref()?;
    pinned_hit_in(pid, pin, leaf, &index.protect)
}

/// `pinned_protected_hit` over any list of paths (`protect:`, or the
/// registered files the guard holds no inode of, `SecretIndex::unpinned`).
fn pinned_hit_in(pid: i32, pin: RawFd, leaf: &[u8], list: &[String]) -> Option<String> {
    if list.is_empty() {
        return None;
    }
    let dir = std::fs::read_link(format!("/proc/self/fd/{pin}")).ok().map(|p| p.to_string_lossy().into_owned());
    if let Some(dir) = dir {
        let mut seen = dir;
        if !seen.ends_with('/') {
            seen.push('/');
        }
        seen.push_str(&String::from_utf8_lossy(leaf));
        if let Some(hit) = crate::secret_open::protected_hit(list, &seen) {
            return Some(hit.to_string());
        }
    }
    use std::os::unix::fs::MetadataExt;
    let t_self = leaf_identity(pin, leaf);
    let t_parents = pinned_dir_chain(pin);
    let guard_view = |p: &str| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
    let tracee_view = |p: &str| std::fs::metadata(format!("/proc/{pid}/root{p}")).ok().map(|m| (m.dev(), m.ino()));
    crate::secret_open::protected_hit_by_ids(list, t_self, &t_parents, guard_view)
        .or_else(|| crate::secret_open::protected_hit_by_ids(list, t_self, &t_parents, tracee_view))
        .map(str::to_string)
}

/// The rename rule over the registered files the guard holds no inode of
/// (`SecretIndex::unpinned`), fail closed (2026-10-16): `Ok(Some(file))` a
/// hit, `Ok(None)` none, `Err(why)` when it cannot be told (the pinned
/// parent cannot be named, or a listed file or a folder above it cannot be
/// identified): the caller refuses either way. An empty list: `Ok(None)`.
fn unpinned_hit(pid: i32, pin: RawFd, leaf: &[u8], list: &[String]) -> std::result::Result<Option<String>, String> {
    if list.is_empty() {
        return Ok(None);
    }
    let Ok(dir) = std::fs::read_link(format!("/proc/self/fd/{pin}")) else {
        return Err(format!("{} (the folder being renamed could not be named)", list[0]));
    };
    let mut seen = dir.to_string_lossy().into_owned();
    if !seen.ends_with('/') {
        seen.push('/');
    }
    seen.push_str(&String::from_utf8_lossy(leaf));
    if let Some(hit) = crate::secret_open::protected_hit(list, &seen) {
        return Ok(Some(hit.to_string()));
    }
    use std::os::unix::fs::MetadataExt;
    let t_self = leaf_identity(pin, leaf);
    let t_parents = pinned_dir_chain(pin);
    let guard_view = |p: &str| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
    match crate::secret_open::protected_hit_by_ids_strict(list, t_self, &t_parents, guard_view) {
        Ok(Some(hit)) => return Ok(Some(hit.to_string())),
        Ok(None) => {}
        Err(p) => return Err(format!("{p} (its identity could not be read)")),
    }
    let tracee_view = |p: &str| std::fs::metadata(format!("/proc/{pid}/root{p}")).ok().map(|m| (m.dev(), m.ino()));
    Ok(crate::secret_open::protected_hit_by_ids(list, t_self, &t_parents, tracee_view).map(str::to_string))
}

/// Is `leaf` inside the pinned directory a directory (not following a final
/// symlink)?
fn leaf_is_dir(pin: RawFd, leaf: &[u8]) -> bool {
    let Ok(name) = std::ffi::CString::new(leaf) else { return false };
    // SAFETY: fstatat into a zeroed stat buffer; `name` is NUL-terminated.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstatat(pin, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0) && st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

/// The identity of `leaf` inside the pinned directory, not following a final
/// symlink (removing a link removes the link). None when it does not exist.
fn leaf_identity(pin: RawFd, leaf: &[u8]) -> Option<(u64, u64)> {
    let name = std::ffi::CString::new(leaf).ok()?;
    // SAFETY: fstatat into a zeroed stat buffer; `name` is NUL-terminated.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstatat(pin, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0).then_some((st.st_dev, st.st_ino))
}

/// For a name being removed: what is at its pack's name
/// (`git_lock::pack_name_of`) in the pinned directory, the one the unlink
/// acts on (`git_lock::PackBeside`), by `fstatat(AT_SYMLINK_NOFOLLOW)`: any
/// name there (a symlink named like the pack included) is `Present`, and
/// what it is is never asked (a twinned pack's inode may be reachable under
/// another name, which only this index lets the backstop judge).
fn pack_beside(pin: RawFd, leaf: &[u8]) -> crate::git_lock::PackBeside {
    let Some(pack) = crate::git_lock::pack_name_of(leaf) else { return crate::git_lock::PackBeside::NotAnIndex };
    let Ok(name) = std::ffi::CString::new(pack) else { return crate::git_lock::PackBeside::Unknown };
    // SAFETY: fstatat into a zeroed stat buffer; `name` is NUL-terminated.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let found = if unsafe { libc::fstatat(pin, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))
    };
    crate::git_lock::beside_of(found)
}

/// The identities of a pinned directory and every directory above it,
/// nearest first, by walking `..` from the descriptor (in the mount tree the
/// descriptor belongs to, the tracee's). Stops at the root (`..` of the root
/// is itself) or after 4096 steps.
fn pinned_dir_chain(pin: RawFd) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let Some(first) = fs_supervisor::tracee::fd_identity(pin) else { return out };
    out.push(first);
    let dotdot = b"..\0";
    let mut cur = pin;
    for _ in 0..4096 {
        // SAFETY: openat on a directory descriptor we hold; O_PATH, no side effect.
        let up = unsafe { libc::openat(cur, dotdot.as_ptr() as *const libc::c_char, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if cur != pin {
            close_fd(cur);
        }
        if up < 0 {
            return out;
        }
        match fs_supervisor::tracee::fd_identity(up) {
            Some(i) if Some(&i) != out.last() => out.push(i),
            _ => {
                close_fd(up);
                return out;
            }
        }
        cur = up;
    }
    if cur != pin {
        close_fd(cur);
    }
    out
}

/// The registered secret whose real file the pinned descriptor is (by its
/// path and identity), if any. A regular file only (`file_identity`): a
/// symlink pinned without following is a name of its own.
fn pinned_registered_secret(cfg: &GuardConfig, fd: RawFd) -> Option<&crate::secret_open::SecretEntry> {
    let index = cfg.secrets.as_ref()?;
    let id = file_identity(fd)?;
    let seen = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok().map(|p| p.to_string_lossy().into_owned());
    index.lookup_opened(seen.as_deref().unwrap_or(""), id, crate::secret_open::file_id)
}

/// Is the pinned descriptor a registered secret's real file? An attribute
/// change of one is refused (`perform_xattr`).
fn pinned_is_registered_secret(cfg: &GuardConfig, fd: RawFd) -> bool {
    pinned_registered_secret(cfg, fd).is_some()
}

/// Is a change in `role` of the pinned file refused because it is a
/// registered secret's real file? The rule by role and entry kind is
/// `secret_open::registered_secret_refuses`: a rename source or destination,
/// a hard-link source, a removed name, a truncate or a mode target (its
/// bytes must not be moved, replaced, removed, linked to a new name,
/// emptied, or opened to others; git's object store is replaced and removed
/// as git does).
fn pinned_secret_refuses(cfg: &GuardConfig, fd: RawFd, role: crate::secret_open::ChangeRole) -> bool {
    pinned_registered_secret(cfg, fd).is_some_and(|e| crate::secret_open::registered_secret_refuses(role, e.kind.as_deref()))
}

/// 2026-10-17: is the rename onto the pinned destination `fd` (`O_PATH`, not
/// followed) refused because it is a non-empty labelled file the launch did
/// not register (`label_index::rename_dest_checked`, `labelled_entry`) and
/// `pid` is not the agent's own process? One whose label cannot be checked
/// is refused too (fail-closed).
fn labelled_dest_refuses(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex, pid: i32, fd: RawFd) -> bool {
    // SAFETY: fstat into a zeroed stat buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return false;
    }
    if !crate::label_index::rename_dest_checked(st.st_mode & libc::S_IFMT == libc::S_IFREG, st.st_size.max(0) as u64) {
        return false;
    }
    let Some(seen) = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok().map(|p| p.to_string_lossy().into_owned()) else { return false };
    !matches!(labelled_entry(cfg, index, Some(pid), &seen, (st.st_dev, st.st_ino), ctime_ns_of(&st), st.st_nlink as u64), Ok(None))
}

/// Plan 14 §11.1 R4: is this access to the object-store file at `seen` (the
/// path of a descriptor the guard pinned; `st` its fstat) refused because it
/// holds a locked object the launch prepared no sanitized copy of, or its
/// verdict cannot be reached? `Some(reason)` = refused; the first refused
/// READ in a repository (`git_lock::reported`) is reported (the notice
/// file, and the event: the repository
/// and the file, never a byte). `None` for every other file (the prefilter:
/// one lexical look at the path) and when no lock is in force.
fn git_lock_refusal(cfg: &GuardConfig, seen: &str, st: &libc::stat, access: crate::git_lock::Access) -> Option<String> {
    let gl = cfg.secrets.as_ref()?.git_locks()?;
    let (file, verdict) = gl.verdict_for(seen, &crate::git_lock::FileKey::of(st))?;
    if !crate::git_lock::refuses(&file, &verdict, access) {
        return None;
    }
    let why = crate::git_lock::refusal_reason(&verdict);
    // Only a refused read is told in the notice and registered
    // (`git_lock::reported`): an index kept anchored stops nothing git
    // needs. It is still recorded, every time, as a refused change of the
    // index (2026-10-16): what tampering with the anchor looks like.
    if !crate::git_lock::reported(access) {
        if let Some(emitter) = &cfg.emitter {
            let ev = crate::events::guard_git_index_change_refusal_event(&cfg.session_id, seen, &why);
            if let Ok(mut client) = emitter.lock() {
                mandu_arbiter::safe_emit(&mut client, &ev);
            }
        }
        return Some(format!("{seen}: {why}"));
    }
    if let Some(repo) = gl.report(seen, &why) {
        if let Some(emitter) = &cfg.emitter {
            let ev = crate::events::guard_git_lock_refusal_event(&cfg.session_id, seen, &repo, &why);
            if let Ok(mut client) = emitter.lock() {
                mandu_arbiter::safe_emit(&mut client, &ev);
            }
            // R1: the arbiter registers the repository, so the next launch
            // resolves its locks (and, with R3, prepares a sanitized copy).
            // Off the syscall's answer: best-effort, its refusals (not a work
            // tree, a bare repository, a full registry) change nothing here.
            let emitter = Arc::clone(emitter);
            // Best effort: no thread to spare, no registration (never a panic
            // on the path that answers the call).
            let _ = std::thread::Builder::new().spawn(move || {
                if let Ok(mut client) = emitter.lock() {
                    let _ = client.register_repository(&repo);
                }
            });
        }
    }
    Some(format!("{seen}: {why}"))
}

/// `git_lock_refusal` for a pinned descriptor (a rename or link source, a
/// name removed or replaced, a truncate target): a regular file only (a
/// symlink renamed moves no bytes).
fn git_lock_refusal_fd(cfg: &GuardConfig, fd: RawFd, access: crate::git_lock::Access) -> Option<String> {
    cfg.secrets.as_ref()?.git_locks()?;
    // SAFETY: fstat into a zeroed stat buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None;
    }
    let seen = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?.to_string_lossy().into_owned();
    git_lock_refusal(cfg, &seen, &st, access)
}

/// Judge one pinned target by its role: `protect:` (delete-family roles), the
/// registered-secret refusal (rename source and destination, link source,
/// removed name), and the
/// write-protect list (`pinned_write_hit` + `judge_write_hit`). Emits the
/// refusal event; the caller answers the errno.
fn judge_change(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, pin: RawFd, leaf: &[u8], role: crate::secret_open::ChangeRole) -> ChangeVerdict {
    use crate::secret_open::ChangeRole::*;
    let Some(index) = cfg.secrets.as_ref() else { return ChangeVerdict::Proceed };
    // Plan 13 §9 R4 (b), 2026-10-04: a holder's name made, moved, linked or
    // removed in a directory on a mount that leaves the machine (the pinned
    // parent's mount; a rename or link names both sides).
    if holder_change_refused(cfg, notif.pid as i32, pin) {
        return ChangeVerdict::Refused;
    }
    // `protect:` — a named path or an ancestor disappearing or being replaced.
    if matches!(role, Remove | RenameSrc | Dest) {
        if let Some(hit) = pinned_protected_hit(cfg, notif.pid as i32, pin, leaf) {
            if let Some(emitter) = &cfg.emitter {
                let ev = crate::events::guard_protect_refusal_event(&cfg.session_id, &String::from_utf8_lossy(leaf), &hit);
                if let Ok(mut client) = emitter.lock() {
                    mandu_arbiter::safe_emit(&mut client, &ev);
                }
            }
            return ChangeVerdict::Refused;
        }
    }
    // 2026-10-16 (`inode_pins`): a registered protected file the guard holds
    // no inode of (past the pin budget, or its open failed) would leave its
    // identity behind if a directory above it moved: such a rename is
    // refused, as for a `protect:` path (fail closed). A held file needs
    // nothing: its inode is that secret under any name.
    if matches!(role, RenameSrc) {
        // A directory about to move: the pins are brought up to date first
        // (a protected file replaced since the last rebuild is held now).
        if leaf_is_dir(pin, leaf) {
            index.refresh_pins();
        }
        let unpinned = index.unpinned();
        // Fail closed (2026-10-16): a folder that cannot be named, or a
        // listed file (or a folder above it) whose identity cannot be read,
        // refuses the rename as a hit would.
        let refused = match unpinned_hit(notif.pid as i32, pin, leaf, &unpinned) {
            Ok(None) => None,
            Ok(Some(hit)) => Some(hit),
            Err(why) => Some(why),
        };
        if let Some(hit) = refused {
            if let Some(emitter) = &cfg.emitter {
                let ev = crate::events::guard_unpinned_rename_refusal_event(&cfg.session_id, &String::from_utf8_lossy(leaf), &hit);
                if let Ok(mut client) = emitter.lock() {
                    mandu_arbiter::safe_emit(&mut client, &ev);
                }
            }
            return ChangeVerdict::Refused;
        }
    }
    // The pinned leaf (followed for a link source), for the secret refusal and
    // the write-protect identity check.
    let follow = matches!(role, LinkSource);
    let leaf_fd = open_leaf(pin, leaf, follow);
    // Plan 14 §11.1 R4: a locked object never leaves its checked name (a
    // rename or hard link of it), and a pack's index, the anchor of its
    // verdict, is never removed or replaced.
    let git_access = match role {
        RenameSrc => Some(crate::git_lock::Access::RenameSrc),
        LinkSource => Some(crate::git_lock::Access::LinkSource),
        // An index whose pack is gone from this directory anchors nothing
        // (2026-10-16, `git_lock::removal_access`): looked up through the
        // pinned parent, the directory the unlink acts on, in the tracee's
        // view. An index beside any pack, a twinned one included, stays.
        Remove => Some(crate::git_lock::removal_access(pack_beside(pin, leaf))),
        Dest => Some(crate::git_lock::Access::ReplaceDest),
        _ => None,
    };
    if let (Some(access), Some(fd)) = (git_access, leaf_fd) {
        if git_lock_refusal_fd(cfg, fd, access).is_some() {
            close_fd(fd);
            return ChangeVerdict::Refused;
        }
    }
    // A registered secret's real file is never moved, hard-linked, replaced
    // by a rename onto it, or removed (2026-10-02: `Dest` and `Remove`
    // joined; in the guard-only posture an in-place writer's rename over the
    // real path lost the credential). The leaf is pinned without following
    // (but for a link source), so a symlink to the secret is replaced or
    // removed as the name it is.
    if matches!(role, RenameSrc | LinkSource | Dest | Remove) {
        if let Some(fd) = leaf_fd {
            if pinned_secret_refuses(cfg, fd, role) {
                close_fd(fd);
                return ChangeVerdict::Refused;
            }
        }
    }
    // 2026-10-17: nor is a labelled file the launch did not register
    // replaced by a rename onto it, but by the agent's own process (which a
    // label does not gate, so it read the real text): any other program may
    // have built its new text from the placeholder (`sed -i`, `perl -i`, an
    // editor's save), which would then stand in for the real file.
    if matches!(role, Dest) {
        if let Some(fd) = leaf_fd {
            if labelled_dest_refuses(cfg, index, notif.pid as i32, fd) {
                close_fd(fd);
                return ChangeVerdict::Refused;
            }
        }
    }
    // The write-protect list, on the pinned file (or the pinned dir + new name).
    if !index.write_protect.is_empty() {
        let pinned = match leaf_fd {
            Some(fd) => PinnedWrite::File(fd),
            None => PinnedWrite::NewIn(pin, leaf),
        };
        let hit = pinned_write_hit(cfg, pinned);
        if let Some(fd) = leaf_fd {
            close_fd(fd);
        }
        // P0 (D), 2026-10-07: a name removed, renamed or created at a strict
        // ancestor of an entry replaces what the entry protects (`mv ~/.ssh
        // ~/.ssh.old; mv ~/planted ~/.ssh`), as `protect:` refuses above.
        let hit = match hit {
            Ok(None) if matches!(role, Remove | RenameSrc | Dest | NewName) => pinned_ancestor_write_hit(cfg, pin, leaf),
            other => other,
        };
        match hit {
            Err(()) => return ChangeVerdict::Refused,
            Ok(None) => {}
            Ok(Some((seen, entry))) => {
                return match judge_write_hit(listener, cfg, notif, &seen, &entry) {
                    WriteJudgement::Proceed => ChangeVerdict::Proceed,
                    WriteJudgement::Refused => ChangeVerdict::Refused,
                    WriteJudgement::Gone => ChangeVerdict::Gone,
                };
            }
        }
    } else if let Some(fd) = leaf_fd {
        close_fd(fd);
    }
    ChangeVerdict::Proceed
}

/// Run the mutating step under the tracee's Landlock domain, if it has one
/// (its REFER / TRUNCATE / MAKE_* rights must be honored). `job` returns 0 or
/// the errno; a domain that cannot run it answers its own errno.
fn perform_under_domain(cfg: &GuardConfig, pid: i32, job: impl FnOnce() -> i32 + Send + 'static) -> i32 {
    match cfg.landlock.domain_of(pid) {
        None => job(),
        Some(d) => d.run(job).unwrap_or_else(|e| e),
    }
}

/// The unlink family: pin the parent, judge the leaf, `unlinkat` relative to
/// the pin (`AT_REMOVEDIR` for `rmdir`, or the tracee's flag for `unlinkat`).
fn perform_unlink(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, nr: i64) {
    let a = &notif.data.args;
    let (dirfd, addr, removedir): (i32, u64, bool) = if nr == libc::SYS_unlinkat as i64 {
        (a[0] as i32, a[1], a[2] as i32 & libc::AT_REMOVEDIR != 0)
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            (libc::AT_FDCWD, a[0], nr == libc::SYS_rmdir as i64)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            answer_continue(listener, notif);
            return;
        }
    };
    let (pin, leaf) = match pin_parent(listener, cfg, notif, dirfd, addr) {
        Ok(v) => v,
        Err(e) => {
            answer_errno(listener, notif, e);
            return;
        }
    };
    match judge_change(listener, cfg, notif, pin, &leaf, crate::secret_open::ChangeRole::Remove) {
        ChangeVerdict::Proceed => {}
        ChangeVerdict::Refused => {
            close_fd(pin);
            answer_errno(listener, notif, libc::EACCES);
            return;
        }
        ChangeVerdict::Gone => {
            close_fd(pin);
            return;
        }
    }
    let pid = notif.pid as i32;
    let flags = if removedir { libc::AT_REMOVEDIR } else { 0 };
    let leaf_c = leaf.clone();
    let answered = perform_under_domain(cfg, pid, move || {
        let c = match std::ffi::CString::new(leaf_c) {
            Ok(c) => c,
            Err(_) => return libc::ENOENT,
        };
        // SAFETY: unlinkat with a one-component leaf relative to the pinned dir.
        let rc = unsafe { libc::syscall(libc::SYS_unlinkat, pin, c.as_ptr(), flags) };
        if rc == 0 { 0 } else { Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) }
    });
    close_fd(pin);
    answer_errno(listener, notif, answered);
}

/// The rename family: pin both parents, judge source and destination (both
/// sides on `RENAME_EXCHANGE`), `renameat2` relative to the pins with the
/// tracee's flags (NOREPLACE / EXCHANGE / WHITEOUT passed through; EXDEV
/// preserved).
fn perform_rename(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, nr: i64) {
    use crate::secret_open::ChangeRole;
    let a = &notif.data.args;
    let (od, op, nd, np, flags): (i32, u64, i32, u64, u32) = if nr == libc::SYS_renameat as i64 {
        (a[0] as i32, a[1], a[2] as i32, a[3], 0)
    } else if nr == libc::SYS_renameat2 as i64 {
        (a[0] as i32, a[1], a[2] as i32, a[3], a[4] as u32)
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            (libc::AT_FDCWD, a[0], libc::AT_FDCWD, a[1], 0)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            answer_continue(listener, notif);
            return;
        }
    };
    let (opin, oleaf) = match pin_parent(listener, cfg, notif, od, op) {
        Ok(v) => v,
        Err(e) => {
            answer_errno(listener, notif, e);
            return;
        }
    };
    let (npin, nleaf) = match pin_parent(listener, cfg, notif, nd, np) {
        Ok(v) => v,
        Err(e) => {
            close_fd(opin);
            answer_errno(listener, notif, e);
            return;
        }
    };
    let exchange = flags & (libc::RENAME_EXCHANGE as u32) != 0;
    let dst_role = if exchange { ChangeRole::RenameSrc } else { ChangeRole::Dest };
    for (pin, leaf, role) in [(opin, &oleaf, ChangeRole::RenameSrc), (npin, &nleaf, dst_role)] {
        match judge_change(listener, cfg, notif, pin, leaf, role) {
            ChangeVerdict::Proceed => {}
            ChangeVerdict::Refused => {
                close_fd(opin);
                close_fd(npin);
                answer_errno(listener, notif, libc::EACCES);
                return;
            }
            ChangeVerdict::Gone => {
                close_fd(opin);
                close_fd(npin);
                return;
            }
        }
    }
    // Plan 13 D4: a derived file's label follows it to its new name (both
    // ways on RENAME_EXCHANGE), recorded before the rename runs.
    let follows = derived_follows(cfg, opin, &oleaf, npin, &nleaf, "rename")
        .and_then(|()| if exchange { derived_follows(cfg, npin, &nleaf, opin, &oleaf, "rename") } else { Ok(()) });
    if let Err(e) = follows {
        close_fd(opin);
        close_fd(npin);
        answer_errno(listener, notif, e);
        return;
    }
    // 2026-10-16: what a folder rename carries (derived copies and protected
    // files below it), labelled at their new paths only after the rename
    // ran (`dir_follows`, `label_follows`).
    let dir_carries = dir_follows(cfg, opin, &oleaf, npin, &nleaf).and_then(|mut v| {
        if exchange {
            v.extend(dir_follows(cfg, npin, &nleaf, opin, &oleaf)?);
        }
        Ok(v)
    });
    let dir_carries = match dir_carries {
        Ok(v) => v,
        Err(e) => {
            close_fd(opin);
            close_fd(npin);
            answer_errno(listener, notif, e);
            return;
        }
    };
    let pid = notif.pid as i32;
    let run = |from: RawFd, fl: Vec<u8>, to: RawFd, tl: Vec<u8>, how: u32| {
        perform_under_domain(cfg, pid, move || {
            let (Ok(fc), Ok(tc)) = (std::ffi::CString::new(fl), std::ffi::CString::new(tl)) else { return libc::ENOENT };
            // SAFETY: renameat2 with one-component leaves relative to the pinned dirs.
            let rc = unsafe { libc::syscall(libc::SYS_renameat2, from, fc.as_ptr(), to, tc.as_ptr(), how as libc::c_uint) };
            if rc == 0 { 0 } else { Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) }
        })
    };
    // 2026-10-16 (`inode_pins`): a directory that moves carries registered
    // files with it. The rename runs under the identity lock and every file
    // it moved is held at its new path before the answer (a person's save
    // over one between the guard's checks and the rename included); one that
    // cannot be held undoes the rename. A folder that cannot be named while
    // pinning is on is refused (fail closed).
    let moves_dir = index_pins_on(cfg) && (leaf_is_dir(opin, &oleaf) || (exchange && leaf_is_dir(npin, &nleaf)));
    let pinned_index = cfg.secrets.as_ref().filter(|_| moves_dir);
    let undo_flags = if exchange { libc::RENAME_EXCHANGE as u32 } else { libc::RENAME_NOREPLACE as u32 };
    let undo = || if exchange { run(opin, oleaf.clone(), npin, nleaf.clone(), undo_flags) } else { run(npin, nleaf.clone(), opin, oleaf.clone(), undo_flags) };
    let answered = if let Some(index) = pinned_index {
        match (pinned_path(opin, &oleaf), pinned_path(npin, &nleaf)) {
            (Some(o), Some(n)) => {
                let moves = if exchange { vec![(o.clone(), n.clone()), (n, o)] } else { vec![(o, n)] };
                index.rename_dirs_holding_pins(&moves, || run(opin, oleaf.clone(), npin, nleaf.clone(), flags), &undo)
            }
            _ => libc::EACCES,
        }
    } else {
        run(opin, oleaf.clone(), npin, nleaf.clone(), flags)
    };
    // The labels of what the folder carried, now that it moved: one that
    // cannot be recorded undoes the rename (no label is left for a rename
    // that did not stand). An undo that fails leaves the rename standing:
    // the carried files are then known by their new paths for the session
    // (path aliases, and the strictest derived label), the pins hold them.
    let unlabelled: std::cell::RefCell<Vec<(String, String)>> = std::cell::RefCell::new(Vec::new());
    let answered = crate::inode_pins::label_after_rename(
        answered,
        !dir_carries.is_empty(),
        || {
            let failed = label_follows(cfg, &dir_carries);
            let ok = failed.is_empty();
            *unlabelled.borrow_mut() = failed;
            ok
        },
        undo,
        || {
            if let Some(index) = cfg.secrets.as_ref() {
                for (from, to) in &dir_carries {
                    if !index.add_alias(to, from) {
                        index.derived.insert(to, "no-model", resolve_for_index(to));
                    }
                }
                // The next session would not know these new paths: said at
                // the end of this one, with how to label them.
                for (from, to) in unlabelled.borrow().iter() {
                    index.note_moved_unlabelled(from, to);
                }
            }
        },
    );
    close_fd(opin);
    close_fd(npin);
    answer_errno(listener, notif, answered);
}

/// Is inode pinning on (a secret index with `SecretIndex::enable_pins`)?
fn index_pins_on(cfg: &GuardConfig) -> bool {
    cfg.secrets.as_ref().is_some_and(|i| i.pins_on())
}

/// The guard-view path of `leaf` in the pinned directory (`/proc/self/fd`
/// link of the pin, then the leaf), or None when the pin cannot be named.
fn pinned_path(pin: RawFd, leaf: &[u8]) -> Option<String> {
    let dir = std::fs::read_link(format!("/proc/self/fd/{pin}")).ok()?;
    let mut p = dir.to_str()?.to_string();
    if !p.ends_with('/') {
        p.push('/');
    }
    p.push_str(std::str::from_utf8(leaf).ok()?);
    Some(p)
}

/// The link family: pin both parents, refuse a registered-secret or write-
/// protected source, judge the new name, `linkat` relative to the pins.
/// `AT_EMPTY_PATH` (which needs CAP_DAC_READ_SEARCH and names the source fd
/// directly) is refused; `AT_SYMLINK_FOLLOW` is passed through.
fn perform_link(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, nr: i64) {
    use crate::secret_open::ChangeRole;
    let a = &notif.data.args;
    let (od, op, nd, np, flags): (i32, u64, i32, u64, i32) = if nr == libc::SYS_linkat as i64 {
        (a[0] as i32, a[1], a[2] as i32, a[3], a[4] as i32)
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            (libc::AT_FDCWD, a[0], libc::AT_FDCWD, a[1], 0)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            answer_continue(listener, notif);
            return;
        }
    };
    if flags & libc::AT_EMPTY_PATH != 0 {
        answer_errno(listener, notif, libc::EACCES);
        return;
    }
    let (opin, oleaf) = match pin_parent(listener, cfg, notif, od, op) {
        Ok(v) => v,
        Err(e) => {
            answer_errno(listener, notif, e);
            return;
        }
    };
    let (npin, nleaf) = match pin_parent(listener, cfg, notif, nd, np) {
        Ok(v) => v,
        Err(e) => {
            close_fd(opin);
            answer_errno(listener, notif, e);
            return;
        }
    };
    for (pin, leaf, role) in [(opin, &oleaf, ChangeRole::LinkSource), (npin, &nleaf, ChangeRole::NewName)] {
        match judge_change(listener, cfg, notif, pin, leaf, role) {
            ChangeVerdict::Proceed => {}
            ChangeVerdict::Refused => {
                close_fd(opin);
                close_fd(npin);
                answer_errno(listener, notif, libc::EACCES);
                return;
            }
            ChangeVerdict::Gone => {
                close_fd(opin);
                close_fd(npin);
                return;
            }
        }
    }
    // Plan 13 D4: a derived file's label follows it to the new name.
    if let Err(e) = derived_follows(cfg, opin, &oleaf, npin, &nleaf, "link") {
        close_fd(opin);
        close_fd(npin);
        answer_errno(listener, notif, e);
        return;
    }
    let pid = notif.pid as i32;
    let at_flags = flags & libc::AT_SYMLINK_FOLLOW;
    let (oc, nc) = (oleaf.clone(), nleaf.clone());
    let answered = perform_under_domain(cfg, pid, move || {
        let (Ok(oc), Ok(nc)) = (std::ffi::CString::new(oc), std::ffi::CString::new(nc)) else { return libc::ENOENT };
        // SAFETY: linkat with one-component leaves relative to the pinned dirs;
        // never AT_EMPTY_PATH.
        let rc = unsafe { libc::syscall(libc::SYS_linkat, opin, oc.as_ptr(), npin, nc.as_ptr(), at_flags) };
        if rc == 0 { 0 } else { Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) }
    });
    close_fd(opin);
    close_fd(npin);
    answer_errno(listener, notif, answered);
}

/// The symlink family: the target text is stored verbatim (never resolved);
/// pin the new name's parent, judge it, `symlinkat` relative to the pin.
fn perform_symlink(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, nr: i64) {
    let a = &notif.data.args;
    let (target_addr, nd, np): (u64, i32, u64) = if nr == libc::SYS_symlinkat as i64 {
        (a[0], a[1] as i32, a[2])
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            (a[0], libc::AT_FDCWD, a[1])
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            answer_continue(listener, notif);
            return;
        }
    };
    let Some(target) = read_change_path(listener, notif, target_addr) else { return };
    let (npin, nleaf) = match pin_parent(listener, cfg, notif, nd, np) {
        Ok(v) => v,
        Err(e) => {
            answer_errno(listener, notif, e);
            return;
        }
    };
    match judge_change(listener, cfg, notif, npin, &nleaf, crate::secret_open::ChangeRole::NewName) {
        ChangeVerdict::Proceed => {}
        ChangeVerdict::Refused => {
            close_fd(npin);
            answer_errno(listener, notif, libc::EACCES);
            return;
        }
        ChangeVerdict::Gone => {
            close_fd(npin);
            return;
        }
    }
    let pid = notif.pid as i32;
    let (tc, nc) = (target, nleaf.clone());
    let answered = perform_under_domain(cfg, pid, move || {
        let (Ok(tc), Ok(nc)) = (std::ffi::CString::new(tc), std::ffi::CString::new(nc)) else { return libc::ENOENT };
        // SAFETY: symlinkat with a one-component new name relative to the pinned dir.
        let rc = unsafe { libc::syscall(libc::SYS_symlinkat, tc.as_ptr(), npin, nc.as_ptr()) };
        if rc == 0 { 0 } else { Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) }
    });
    close_fd(npin);
    answer_errno(listener, notif, answered);
}

/// `truncate(path, len)` follows symlinks: resolve the WHOLE path to a pinned
/// descriptor in the tracee's view, refuse a registered secret, judge a
/// write-protected file, then `ftruncate` a write reopen of exactly that inode
/// (`/proc/self/fd/N`: no path re-walked) under the tracee's domain. A pseudo-
/// filesystem target fails closed (truncate of a sysctl is not a real change).
fn perform_truncate(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) {
    let pid = notif.pid as i32;
    let len = notif.data.args[1] as i64;
    let Some(raw) = read_change_path(listener, notif, notif.data.args[0]) else { return };
    // O_PATH, symlinks followed (no O_NOFOLLOW): the file the tracee's own
    // truncate would reach, resolved once.
    let fd = match resolve_opath_as_tracee(listener, notif, libc::AT_FDCWD, &raw, 0) {
        Ok(fd) => fd,
        Err(e) => {
            answer_errno(listener, notif, e);
            return;
        }
    };
    // A pseudo-filesystem file (a swapped component led to procfs/sysfs): fail
    // closed rather than truncate it as the guard. Plan 13 §9 R4 (b): a
    // holder's truncate of a file on a mount that leaves the machine (its
    // length is a value it chooses).
    if crate::context_helper::pseudo_kind(fd) != crate::context_helper::Pseudo::No || holder_change_refused(cfg, pid, fd) {
        close_fd(fd);
        answer_errno(listener, notif, libc::EACCES);
        return;
    }
    if pinned_secret_refuses(cfg, fd, crate::secret_open::ChangeRole::Truncate) || git_lock_refusal_fd(cfg, fd, crate::git_lock::Access::Truncate).is_some() {
        close_fd(fd);
        answer_errno(listener, notif, libc::EACCES);
        return;
    }
    if let Some(index) = cfg.secrets.as_ref() {
        if !index.write_protect.is_empty() {
            match pinned_write_hit(cfg, PinnedWrite::File(fd)) {
                Err(()) => {
                    close_fd(fd);
                    answer_errno(listener, notif, libc::EACCES);
                    return;
                }
                Ok(Some((seen, entry))) => match judge_write_hit(listener, cfg, notif, &seen, &entry) {
                    WriteJudgement::Proceed => {}
                    WriteJudgement::Refused => {
                        close_fd(fd);
                        answer_errno(listener, notif, libc::EACCES);
                        return;
                    }
                    WriteJudgement::Gone => {
                        close_fd(fd);
                        return;
                    }
                },
                Ok(None) => {}
            }
        }
    }
    let answered = perform_under_domain(cfg, pid, move || {
        // Reopen the pinned inode for writing (the magic link resolves to
        // exactly it), then ftruncate — governed by the tracee's Landlock
        // TRUNCATE right on the mirror thread.
        let c = match std::ffi::CString::new(format!("/proc/self/fd/{fd}")) {
            Ok(c) => c,
            Err(_) => return libc::EIO,
        };
        // SAFETY: reopen our own O_PATH descriptor's file for writing.
        let wfd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        if wfd < 0 {
            return Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
        }
        // SAFETY: ftruncate a descriptor we own.
        let rc = unsafe { libc::ftruncate(wfd, len as libc::off_t) };
        let e = if rc == 0 { 0 } else { Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) };
        unsafe { libc::close(wfd) };
        e
    });
    close_fd(fd);
    answer_errno(listener, notif, answered);
}

/// Run `job` on this thread with a filesystem context of its own
/// (`unshare(CLONE_FS)`: cwd, root and umask stop being shared with the
/// guard's other threads), its cwd at `cwd` when given and its umask the
/// tracee's, then put the thread's cwd and umask back. So a creating call the
/// guard performs gets exactly the tracee's permission bits (the guard runs
/// with umask 0, and a default ACL on the parent overrides the umask as the
/// kernel decides, not as the guard pre-masks), and a relative name resolves
/// against a pinned directory. `job` returns 0 or the errno; a context that
/// cannot be set up answers its errno (fail-closed: the call is not made).
fn with_private_fs(cwd: Option<RawFd>, umask: u32, job: impl FnOnce() -> i32) -> i32 {
    let errno = || Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
    // SAFETY: unshare(CLONE_FS) affects only the calling thread's fs_struct
    // (allowed in a multithreaded process, no privilege needed).
    if unsafe { libc::unshare(libc::CLONE_FS) } != 0 {
        return errno();
    }
    // SAFETY: an O_PATH descriptor of this thread's current directory, to come
    // back to (-1 when it cannot be opened: then back to "/").
    let saved = unsafe { libc::open(b".\0".as_ptr() as *const libc::c_char, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if let Some(dir) = cwd {
        // SAFETY: fchdir to a directory descriptor we hold (O_PATH is allowed).
        if unsafe { libc::fchdir(dir) } != 0 {
            let e = errno();
            if saved >= 0 {
                close_fd(saved);
            }
            return e;
        }
    }
    // SAFETY: umask has no failure mode; it now affects this thread only.
    let old = unsafe { libc::umask(umask as libc::mode_t & 0o777) };
    let r = job();
    unsafe { libc::umask(old) };
    if cwd.is_some() {
        // SAFETY: back to where the thread was (or "/"), best effort: the
        // guard never resolves a relative path on its own behalf.
        unsafe {
            if saved < 0 || libc::fchdir(saved) != 0 {
                libc::chdir(b"/\0".as_ptr() as *const libc::c_char);
            }
        }
    }
    if saved >= 0 {
        close_fd(saved);
    }
    r
}

/// The tracee's umask (`/proc/<pid>/status`), 022 when it cannot be read.
fn tracee_umask_of(pid: i32) -> u32 {
    fs_supervisor::tracee::tracee_umask(pid).unwrap_or(0o022)
}

/// `mknodat` / `mknod` (write-protection.md §2, closed 2026-09-29): a node is
/// a new name. Pin the parent in the tracee's view, judge the leaf like any
/// new file (`NewName`), then `mknodat` relative to the pin with the tracee's
/// mode and device, under its umask (`with_private_fs`) and its Landlock
/// domain (the MAKE_FIFO / MAKE_SOCK / MAKE_REG / MAKE_CHAR / MAKE_BLOCK
/// rights). Never CONTINUEd.
fn perform_mknod(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, nr: i64) {
    let pid = notif.pid as i32;
    let Some((dirfd, addr, mode, dev)) = crate::secret_open::mknod_call(nr, &notif.data.args) else {
        answer_errno(listener, notif, libc::EACCES);
        return;
    };
    let (pin, leaf) = match pin_parent(listener, cfg, notif, dirfd, addr) {
        Ok(v) => v,
        Err(e) => {
            answer_errno(listener, notif, e);
            return;
        }
    };
    match judge_change(listener, cfg, notif, pin, &leaf, crate::secret_open::ChangeRole::NewName) {
        ChangeVerdict::Proceed => {}
        ChangeVerdict::Refused => {
            close_fd(pin);
            answer_errno(listener, notif, libc::EACCES);
            return;
        }
        ChangeVerdict::Gone => {
            close_fd(pin);
            return;
        }
    }
    let umask = tracee_umask_of(pid);
    let answered = perform_under_domain(cfg, pid, move || {
        let Ok(c) = std::ffi::CString::new(leaf) else { return libc::ENOENT };
        with_private_fs(None, umask, || {
            // SAFETY: mknodat with a one-component leaf relative to the pinned dir.
            let rc = unsafe { libc::syscall(libc::SYS_mknodat, pin, c.as_ptr(), mode as libc::c_uint, dev as libc::c_uint) };
            if rc == 0 { 0 } else { Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) }
        })
    });
    close_fd(pin);
    answer_errno(listener, notif, answered);
}

/// `mkdirat` / `mkdir` by a holder (plan 13 §9 R4 (b), 2026-10-04; anyone
/// else's is CONTINUEd by `handle_path_change_notif`): pin the parent in the
/// tracee's view, refuse a directory on a mount that leaves the machine
/// unless what the holder holds is bound to it, then `mkdirat` relative to
/// the pin with the tracee's mode, under its umask and Landlock domain (the
/// MAKE_DIR right). Never CONTINUEd: the kernel would walk the path again.
/// The write-protect list does not judge a new directory (it never did).
fn perform_mkdir(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, nr: i64) {
    let pid = notif.pid as i32;
    let Some((dirfd, addr, mode)) = crate::secret_open::mkdir_call(nr, &notif.data.args) else {
        answer_errno(listener, notif, libc::EACCES);
        return;
    };
    let Some(raw) = read_change_path(listener, notif, addr) else { return };
    // An empty path, "/", or a last component "." or "..": the kernel makes
    // no name for these (ENOENT / EEXIST), so its own answer is safe.
    if crate::secret_open::split_parent_leaf(&raw).is_none() {
        answer_continue(listener, notif);
        return;
    }
    let (pin, leaf) = match pin_parent_bytes(listener, cfg, notif, dirfd, &raw) {
        Ok(v) => v,
        Err(e) => {
            answer_errno(listener, notif, e);
            return;
        }
    };
    if holder_change_refused(cfg, pid, pin) {
        close_fd(pin);
        answer_errno(listener, notif, libc::EACCES);
        return;
    }
    let umask = tracee_umask_of(pid);
    let answered = perform_under_domain(cfg, pid, move || {
        let Ok(c) = std::ffi::CString::new(leaf) else { return libc::ENOENT };
        with_private_fs(None, umask, || {
            // SAFETY: mkdirat with a one-component leaf relative to the pinned dir.
            let rc = unsafe { libc::syscall(libc::SYS_mkdirat, pin, c.as_ptr(), mode as libc::c_uint) };
            if rc == 0 { 0 } else { Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) }
        })
    });
    close_fd(pin);
    answer_errno(listener, notif, answered);
}

/// P0 5c (2026-10-07): the owner and timestamp families (`owner_time`). A
/// non-holder's call runs as issued (CONTINUE: nothing else judges it). A
/// holder's is pinned as `perform_chmod` pins (a path resolved whole in the
/// tracee's view, the final symlink followed unless `AT_SYMLINK_NOFOLLOW`
/// or `lchown`; a descriptor by a `pidfd_getfd` copy), refused when the
/// pinned file is on a mount that leaves the machine its holdings are not
/// bound to, a no-op included (the server sees the request all the same),
/// and otherwise PERFORMED on exactly that file under the tracee's Landlock
/// domain: never CONTINUEd, which would let the kernel re-walk a path a
/// racing thread swapped. Fails closed (EACCES) where the guard cannot act
/// exactly as the tracee (no copy, an id its user namespace does not map).
fn handle_owner_time_notif(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) {
    use crate::owner_time::{Op, Target};
    let pid = notif.pid as i32;
    if call_holder(cfg, pid).is_none() {
        answer_continue(listener, notif);
        return;
    }
    let call = match crate::owner_time::decode(notif.data.nr as i64, &notif.data.args) {
        Ok(Some(c)) => c,
        Ok(None) => return answer_errno(listener, notif, libc::EACCES),
        Err(e) => return answer_errno(listener, notif, e),
    };
    // The timestamps first, as the kernel copies them before any lookup.
    let times = match call.op {
        Op::Times(arg) => {
            let (ptr, len) = arg.ptr_len();
            let bytes = if ptr == 0 {
                None
            } else {
                match read_tracee_exact(pid, ptr, len) {
                    Ok(b) => Some(b),
                    Err(e) => return answer_errno(listener, notif, e),
                }
            };
            match crate::owner_time::timespecs(arg, bytes.as_deref()) {
                Ok(t) => t,
                Err(e) => return answer_errno(listener, notif, e),
            }
        }
        Op::Owner { .. } => None,
    };
    // An owner and a group as the guard's user namespace names them.
    let owner = match call.op {
        Op::Owner { uid, gid } if tracee_in_other_userns(pid) != Some(false) && (uid != u32::MAX || gid != u32::MAX) => {
            let map = |f: &str| fs_supervisor::tracee::read_proc_small(&format!("/proc/{pid}/{f}")).map(|t| crate::xattr_change::parse_id_map(&t));
            let (Some(um), Some(gm)) = (map("uid_map"), map("gid_map")) else { return answer_errno(listener, notif, libc::EACCES) };
            let one = |m: &[(u32, u32, u32)], id: u32| if id == u32::MAX { Some(id) } else { crate::xattr_change::map_id(m, id) };
            match (one(&um, uid), one(&gm, gid)) {
                (Some(u), Some(g)) => Some((u, g)),
                // An id the namespace does not map: the kernel's EINVAL.
                _ => return answer_errno(listener, notif, libc::EINVAL),
            }
        }
        Op::Owner { uid, gid } => Some((uid, gid)),
        Op::Times(_) => None,
    };
    // (the pinned file, how to act on it)
    enum On {
        /// The tracee's own open file (an O_PATH copy answers EBADF).
        Fd,
        /// `O_PATH` resolved with the final symlink followed: through
        /// `/proc/self/fd/N`, the pinned inode on every kernel.
        Magic,
        /// `O_PATH` of the inode itself, a symlink included: `AT_EMPTY_PATH`.
        Empty,
    }
    let copy = |fd: i32| -> std::result::Result<RawFd, i32> {
        tracee_fd(pid, fd).map_err(|e| if e.raw_os_error() == Some(libc::EBADF) { libc::EBADF } else { libc::EACCES })
    };
    let pinned = match call.target {
        Target::Fd { fd } => copy(fd).map(|f| (f, On::Fd)),
        Target::Path { dirfd, addr, follow, empty_path } => {
            let raw = if addr == 0 && empty_path {
                Vec::new()
            } else {
                match read_change_path(listener, notif, addr) {
                    Some(p) => p,
                    None => return,
                }
            };
            if raw.is_empty() {
                if !empty_path {
                    Err(libc::ENOENT)
                } else if dirfd == libc::AT_FDCWD {
                    resolve_opath_as_tracee(listener, notif, libc::AT_FDCWD, b".", 0).map(|f| (f, On::Empty))
                } else {
                    copy(dirfd).map(|f| (f, On::Empty))
                }
            } else {
                let extra = if follow { 0 } else { libc::O_NOFOLLOW };
                resolve_opath_as_tracee(listener, notif, dirfd, &raw, extra).map(|f| (f, if follow { On::Magic } else { On::Empty }))
            }
        }
    };
    let (fd, on) = match pinned {
        Ok(v) => v,
        Err(e) => return answer_errno(listener, notif, e),
    };
    // A descriptor form on an O_PATH descriptor: the kernel's fdget refuses
    // it (EBADF) before anything changes.
    // SAFETY: F_GETFL on a descriptor we hold.
    if matches!(on, On::Fd) && unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_PATH != 0 {
        close_fd(fd);
        return answer_errno(listener, notif, libc::EBADF);
    }
    // A pseudo-filesystem file: refused, as chmod. The mount judgement.
    if crate::context_helper::pseudo_kind(fd) != crate::context_helper::Pseudo::No || holder_change_refused(cfg, pid, fd) {
        close_fd(fd);
        return answer_errno(listener, notif, libc::EACCES);
    }
    let answered = perform_under_domain(cfg, pid, move || {
        let errno = || Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
        let empty = b"\0".as_ptr() as *const libc::c_char;
        let magic = std::ffi::CString::new(format!("/proc/self/fd/{fd}")).unwrap_or_default();
        let tp = times.as_ref().map_or(std::ptr::null(), |t| t.as_ptr());
        // SAFETY: each call acts on a descriptor we hold (or its magic link),
        // with our own buffers.
        let rc = unsafe {
            match (owner, &on) {
                (Some((u, g)), On::Fd) => libc::fchown(fd, u, g),
                (Some((u, g)), On::Magic) => libc::fchownat(libc::AT_FDCWD, magic.as_ptr(), u, g, 0),
                (Some((u, g)), On::Empty) => libc::fchownat(fd, empty, u, g, libc::AT_EMPTY_PATH),
                (None, On::Fd) => libc::futimens(fd, tp),
                (None, On::Magic) => libc::utimensat(libc::AT_FDCWD, magic.as_ptr(), tp, 0),
                (None, On::Empty) => libc::utimensat(fd, empty, tp, libc::AT_EMPTY_PATH),
            }
        };
        if rc == 0 { 0 } else { errno() }
    });
    close_fd(fd);
    answer_errno(listener, notif, answered);
}

/// The chmod family (write-protection.md §2, closed 2026-09-29): `chmod`,
/// `fchmodat`, `fchmodat2` and `fchmod`. The file the call changes is pinned
/// first — a path resolved WHOLE in the tracee's view (the final symlink
/// followed unless `AT_SYMLINK_NOFOLLOW`), or for `fchmod` (and `fchmodat2`'s
/// `AT_EMPTY_PATH` on a descriptor) a `pidfd_getfd` copy of the tracee's own
/// descriptor — then judged on that pinned file, and the mode is set on
/// exactly it, never by a path re-walked. A mode that is already the file's
/// is set without a judgement. A pseudo-filesystem target, a registered
/// secret, an uncopyable descriptor, and a write-protect `deny` are refused
/// (EACCES); an `ask` entry is held like a write.
fn perform_chmod(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, nr: i64) {
    use crate::secret_open::ModeCall;
    let pid = notif.pid as i32;
    let call = match crate::secret_open::mode_call(nr, &notif.data.args) {
        Ok(Some(c)) => c,
        Ok(None) => {
            answer_errno(listener, notif, libc::EACCES);
            return;
        }
        Err(e) => {
            answer_errno(listener, notif, e);
            return;
        }
    };
    // A copy of a tracee descriptor: the file it names, exactly (a dup2 after
    // this changes nothing). EBADF is the tracee's own answer; any other
    // failure to copy is refused.
    let copy = |fd: i32| -> std::result::Result<RawFd, i32> {
        tracee_fd(pid, fd).map_err(|e| if e.raw_os_error() == Some(libc::EBADF) { libc::EBADF } else { libc::EACCES })
    };
    // (pinned file, requested mode, how to set it)
    enum Set {
        /// `fchmod` on the tracee's own open file (an O_PATH copy answers
        /// EBADF, as the tracee's call would).
        Fd,
        /// `fchmodat2(fd, "", mode, AT_EMPTY_PATH)`: the pinned inode itself,
        /// a symlink included (`AT_SYMLINK_NOFOLLOW`, or `AT_EMPTY_PATH` on
        /// the tracee's descriptor).
        EmptyPath,
        /// `chmod("/proc/self/fd/N")`: the pinned inode (never a symlink:
        /// the resolution followed it), on every kernel.
        Magic,
    }
    let (fd, mode, how) = match call {
        ModeCall::Fd { fd, mode } => match copy(fd) {
            Ok(c) => (c, mode, Set::Fd),
            Err(e) => {
                answer_errno(listener, notif, e);
                return;
            }
        },
        ModeCall::Path { dirfd, addr, mode, follow, empty_path } => {
            let raw = if addr == 0 && empty_path {
                Vec::new()
            } else {
                match read_change_path(listener, notif, addr) {
                    Some(p) => p,
                    None => return,
                }
            };
            let pinned = if raw.is_empty() {
                if !empty_path {
                    Err(libc::ENOENT)
                } else if dirfd == libc::AT_FDCWD {
                    // The tracee's cwd itself.
                    resolve_opath_as_tracee(listener, notif, libc::AT_FDCWD, b".", 0).map(|f| (f, Set::EmptyPath))
                } else {
                    copy(dirfd).map(|f| (f, Set::EmptyPath))
                }
            } else {
                let extra = if follow { 0 } else { libc::O_NOFOLLOW };
                resolve_opath_as_tracee(listener, notif, dirfd, &raw, extra).map(|f| (f, if follow { Set::Magic } else { Set::EmptyPath }))
            };
            match pinned {
                Ok((f, how)) => (f, mode, how),
                Err(e) => {
                    answer_errno(listener, notif, e);
                    return;
                }
            }
        }
    };
    // A pseudo-filesystem file (a cgroup, a sysfs attribute): the guard would
    // change it with its own view of the namespaces; fail closed, as truncate.
    // Plan 13 §9 R4 (b): a holder's mode change of a file on a mount that
    // leaves the machine, a no-op included (the server sees it all the same).
    if crate::context_helper::pseudo_kind(fd) != crate::context_helper::Pseudo::No || holder_change_refused(cfg, pid, fd) {
        close_fd(fd);
        answer_errno(listener, notif, libc::EACCES);
        return;
    }
    // SAFETY: fstat of a descriptor we hold into a zeroed buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let current = (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st.st_mode);
    if !current.is_some_and(|m| crate::secret_open::mode_change_is_noop(m, mode)) {
        if pinned_secret_refuses(cfg, fd, crate::secret_open::ChangeRole::Mode) {
            close_fd(fd);
            answer_errno(listener, notif, libc::EACCES);
            return;
        }
        // Plan 13 §9 R4 (b): a derived file (a copy a holder wrote, created
        // or narrowed to no group or other bits) is not opened to other
        // local users again, by anyone in the tree. Unknown: refused.
        if crate::local_exits::mode_opens_to_others(mode) && pinned_derived(cfg, fd) != Ok(false) {
            close_fd(fd);
            answer_errno(listener, notif, libc::EACCES);
            return;
        }
        if let Some(index) = cfg.secrets.as_ref() {
            if !index.write_protect.is_empty() {
                let verdict = match pinned_write_hit(cfg, PinnedWrite::File(fd)) {
                    Err(()) => WriteJudgement::Refused,
                    Ok(None) => WriteJudgement::Proceed,
                    Ok(Some((seen, entry))) => judge_write_hit(listener, cfg, notif, &seen, &entry),
                };
                match verdict {
                    WriteJudgement::Proceed => {}
                    WriteJudgement::Refused => {
                        close_fd(fd);
                        answer_errno(listener, notif, libc::EACCES);
                        return;
                    }
                    WriteJudgement::Gone => {
                        close_fd(fd);
                        return;
                    }
                }
            }
        }
    }
    let answered = perform_under_domain(cfg, pid, move || {
        let errno = || Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
        let rc = match how {
            // SAFETY: fchmod of our copy of the tracee's descriptor.
            Set::Fd => unsafe { libc::fchmod(fd, mode as libc::mode_t) as libc::c_long },
            // SAFETY: fchmodat2 on a descriptor we hold, empty path.
            Set::EmptyPath => unsafe { libc::syscall(crate::secret_open::SYS_FCHMODAT2, fd, b"\0".as_ptr() as *const libc::c_char, mode as libc::c_uint, libc::AT_EMPTY_PATH) },
            Set::Magic => match std::ffi::CString::new(format!("/proc/self/fd/{fd}")) {
                // SAFETY: chmod through our own descriptor's magic link.
                Ok(c) => unsafe { libc::chmod(c.as_ptr(), mode as libc::mode_t) as libc::c_long },
                Err(_) => return libc::EIO,
            },
        };
        if rc == 0 { 0 } else { errno() }
    });
    close_fd(fd);
    answer_errno(listener, notif, answered);
}

/// Read `len` bytes of the tracee's memory at `addr`, all or nothing: EFAULT
/// for memory its own call could not read (a short read included). A zero
/// length reads nothing (the pointer is not looked at, as the kernel does
/// for an empty value).
pub(crate) fn read_tracee_exact(pid: i32, addr: u64, len: usize) -> std::result::Result<Vec<u8>, i32> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if addr == 0 {
        return Err(libc::EFAULT);
    }
    let mut buf = vec![0u8; len];
    let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: len };
    let remote = libc::iovec { iov_base: addr as *mut libc::c_void, iov_len: len };
    // SAFETY: reads at most `len` bytes of tracee memory into our buffer.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n < 0 || n as usize != len {
        return Err(libc::EFAULT);
    }
    Ok(buf)
}

/// An attribute name as the kernel copies it (`strncpy_from_user` of up to
/// `XATTR_NAME_MAX + 1` bytes; `xattr_change::decode_name`). A read that
/// runs into unmapped memory returns what it got, so a name that ends before
/// the hole is still read.
fn read_tracee_xattr_name(pid: i32, addr: u64) -> std::result::Result<Vec<u8>, i32> {
    const ASK: usize = crate::xattr_change::XATTR_NAME_MAX + 1;
    if addr == 0 {
        return Err(libc::EFAULT);
    }
    let mut buf = vec![0u8; ASK];
    let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: ASK };
    let remote = libc::iovec { iov_base: addr as *mut libc::c_void, iov_len: ASK };
    // SAFETY: reads at most ASK bytes of tracee memory into our buffer.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n <= 0 {
        return Err(libc::EFAULT);
    }
    buf.truncate(n as usize);
    crate::xattr_change::decode_name(&buf)
}

/// Does this kernel have `setxattrat` / `removexattrat` (Linux 6.13)? Probed
/// once each, with arguments every kernel that has them refuses before
/// touching memory (a `usize` under version 0; unknown `at_flags`): ENOSYS
/// = absent. The guard never emulates a call the kernel does not have.
fn kernel_has_xattrat(nr: i64) -> bool {
    static SET: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    static REMOVE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let probe = || {
        // SAFETY: fails its argument checks before any pointer is read.
        let rc = unsafe { libc::syscall(nr as libc::c_long, -1, 0usize, u32::MAX, 0usize, 0usize, 0usize) };
        !(rc < 0 && Error::last_os_error().raw_os_error() == Some(libc::ENOSYS))
    };
    if nr == crate::xattr_change::SYS_SETXATTRAT { *SET.get_or_init(probe) } else { *REMOVE.get_or_init(probe) }
}

/// Is the tracee in another user namespace than the guard? `None` when
/// either cannot be read (then treated as another: its maps are read, and an
/// unreadable map refuses).
fn tracee_in_other_userns(pid: i32) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    let id = |p: &str| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
    Some(id(&format!("/proc/{pid}/ns/user"))? != id("/proc/self/ns/user")?)
}

/// An attribute call's arguments, read once from the tracee: what is judged
/// is what is set.
struct XattrArgs {
    /// A copy of the tracee's descriptor (`f*` forms).
    fd_copy: Option<RawFd>,
    name: Vec<u8>,
    /// `None` for a removal.
    value: Option<Vec<u8>>,
    flags: i32,
}

/// Read and check an attribute call's arguments in the kernel's order:
/// `setxattrat`'s struct, then the `*at` flags; an `f*` form's descriptor;
/// the set flags, the name, the value. Err = the tracee's own errno.
fn read_xattr_args(pid: i32, call: &crate::xattr_change::XattrCall) -> std::result::Result<XattrArgs, i32> {
    use crate::xattr_change::{self as xc, XattrOp, XattrTarget};
    let set = match call.op {
        XattrOp::SetAt { args, usize } => {
            xc::check_xattr_args_size(usize)?;
            let raw = read_tracee_exact(pid, args, usize as usize)?;
            Some(xc::decode_xattr_args(&raw)?)
        }
        XattrOp::Set { value, size, flags } => Some((value, size, flags)),
        XattrOp::Remove => None,
    };
    if call.bad_at_flags {
        return Err(libc::EINVAL);
    }
    let fd_copy = match call.target {
        XattrTarget::Fd { fd } => Some(tracee_fd(pid, fd).map_err(|e| if e.raw_os_error() == Some(libc::EBADF) { libc::EBADF } else { libc::EACCES })?),
        XattrTarget::Path { .. } => None,
    };
    let rest = || -> std::result::Result<(Vec<u8>, Option<Vec<u8>>, i32), i32> {
        if let Some((_, _, flags)) = set {
            xc::check_set_flags(flags)?;
        }
        let name = read_tracee_xattr_name(pid, call.name)?;
        match set {
            Some((addr, size, flags)) => Ok((name, Some(read_tracee_exact(pid, addr, xc::check_value_size(size)?)?), flags as i32)),
            None => Ok((name, None, 0)),
        }
    };
    match rest() {
        Ok((name, value, flags)) => Ok(XattrArgs { fd_copy, name, value, flags }),
        Err(e) => {
            if let Some(f) = fd_copy {
                close_fd(f);
            }
            Err(e)
        }
    }
}

/// The extended-attribute family (write-protection.md §2, closed
/// 2026-09-29): `setxattr`, `lsetxattr`, `fsetxattr`, `setxattrat` and the
/// `removexattr` family, performed like the chmod family and never
/// CONTINUEd. The name and value are read ONCE from the tracee
/// (`read_xattr_args`); the file is pinned — a path resolved WHOLE in the
/// tracee's view (the final symlink followed unless `l*` /
/// `AT_SYMLINK_NOFOLLOW`), or for the `f*` forms and an `*at` with
/// `AT_EMPTY_PATH` a `pidfd_getfd` copy of the tracee's descriptor; the rule
/// (`xattr_change::xattr_verdict`) runs on that pinned file; and the change
/// is made on exactly it: `fsetxattr` / `fremovexattr` on the copy, else
/// through the pinned descriptor's magic link (`/proc/self/fd/N`, on every
/// kernel: `setxattrat(fd, "", AT_EMPTY_PATH)` refuses an `O_PATH`
/// descriptor, as `fsetxattr` does). A POSIX ACL's named ids are moved to
/// the guard's user namespace first (`translate_acl_ids`): the kernel reads
/// them in the caller's.
fn perform_xattr(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, nr: i64) {
    use crate::xattr_change::{self as xc, XattrTarget};
    let pid = notif.pid as i32;
    let Some(call) = xc::xattr_call(nr, &notif.data.args) else {
        answer_errno(listener, notif, libc::EACCES);
        return;
    };
    // A call this kernel does not have: its own ENOSYS, never an emulation.
    if (nr == xc::SYS_SETXATTRAT || nr == xc::SYS_REMOVEXATTRAT) && !kernel_has_xattrat(nr) {
        answer_errno(listener, notif, libc::ENOSYS);
        return;
    }
    let XattrArgs { fd_copy, name, value, flags } = match read_xattr_args(pid, &call) {
        Ok(a) => a,
        Err(e) => {
            answer_errno(listener, notif, e);
            return;
        }
    };
    if !notif_id_valid(listener, notif.id) {
        if let Some(f) = fd_copy {
            close_fd(f);
        }
        return;
    }
    // Pin the file: (descriptor, changed through it by the f* calls rather
    // than through its magic link).
    let (fd, by_fd) = match (fd_copy, call.target) {
        (Some(f), _) => (f, true),
        (None, XattrTarget::Path { dirfd, addr, follow, empty_path }) => {
            let raw = if addr == 0 && empty_path {
                Vec::new()
            } else {
                match read_change_path(listener, notif, addr) {
                    Some(p) => p,
                    None => return,
                }
            };
            let pinned = if raw.is_empty() {
                // `AT_EMPTY_PATH`: the descriptor itself, as the kernel's
                // fdget takes it (AT_FDCWD is no descriptor: EBADF).
                if !empty_path {
                    Err(libc::ENOENT)
                } else {
                    tracee_fd(pid, dirfd).map(|f| (f, true)).map_err(|e| if e.raw_os_error() == Some(libc::EBADF) { libc::EBADF } else { libc::EACCES })
                }
            } else {
                let extra = if follow { 0 } else { libc::O_NOFOLLOW };
                resolve_opath_as_tracee(listener, notif, dirfd, &raw, extra).map(|f| (f, false))
            };
            match pinned {
                Ok(v) => v,
                Err(e) => {
                    answer_errno(listener, notif, e);
                    return;
                }
            }
        }
        (None, XattrTarget::Fd { .. }) => {
            // read_xattr_args copies an f* form's descriptor or fails.
            answer_errno(listener, notif, libc::EBADF);
            return;
        }
    };
    let refuse = |e: i32| {
        close_fd(fd);
        answer_errno(listener, notif, e);
    };
    // A descriptor call on an O_PATH descriptor: the kernel's fdget refuses
    // it (EBADF) before anything is changed; answered before any judgement.
    // SAFETY: F_GETFL on a descriptor we hold.
    if by_fd && unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_PATH != 0 {
        return refuse(libc::EBADF);
    }
    // A pseudo-filesystem file (a cgroup's attributes): refused, as chmod.
    if crate::context_helper::pseudo_kind(fd) != crate::context_helper::Pseudo::No {
        return refuse(libc::EACCES);
    }
    // Plan 13 §9 R4 (b), 2026-10-04: a holder's attribute (its name and its
    // value) on a file on a mount that leaves the machine, before the guard's
    // own read of the attribute asks the server for that name.
    if holder_change_refused(cfg, pid, fd) {
        return refuse(libc::EACCES);
    }
    // A POSIX ACL naming users or groups by id, from a tracee in another
    // user namespace: the ids as the guard's namespace names them.
    let value = match value {
        Some(v) if xc::classify(&name) == xc::XattrClass::PosixAcl && xc::acl_has_named_ids(&v) && tracee_in_other_userns(pid) != Some(false) => {
            let map = |f: &str| fs_supervisor::tracee::read_proc_small(&format!("/proc/{pid}/{f}")).map(|t| xc::parse_id_map(&t));
            match (map("uid_map"), map("gid_map")) {
                (Some(u), Some(g)) => match xc::translate_acl_ids(&v, &u, &g) {
                    Ok(t) => Some(t),
                    Err(e) => return refuse(e),
                },
                _ => return refuse(libc::EACCES),
            }
        }
        other => other,
    };
    let Ok(cname) = std::ffi::CString::new(name.clone()) else { return refuse(libc::EINVAL) };
    let Ok(magic) = std::ffi::CString::new(format!("/proc/self/fd/{fd}")) else { return refuse(libc::EIO) };
    // The attribute's current value and the file's mode, for the no-op test.
    let mut buf = vec![0u8; xc::XATTR_SIZE_MAX as usize];
    // SAFETY: getxattr into a buffer of the length we pass; the name and the
    // path are NUL-terminated.
    let n = unsafe {
        if by_fd {
            libc::fgetxattr(fd, cname.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        } else {
            libc::getxattr(magic.as_ptr(), cname.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        }
    };
    let cur = if n >= 0 {
        buf.truncate(n as usize);
        xc::Current::Value(&buf)
    } else if Error::last_os_error().raw_os_error() == Some(libc::ENODATA) {
        xc::Current::Absent
    } else {
        xc::Current::Unknown
    };
    // SAFETY: fstat of a descriptor we hold into a zeroed buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mode = (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st.st_mode);
    let noop = xc::xattr_change_is_noop(&name, value.as_deref(), cur, mode);
    // Plan 13 §9 R4 (b): a POSIX ACL set on a derived file is a mode change
    // by another name (a named user's entry opens it to that user): refused
    // like a registered secret's attribute change. Unknown: refused.
    let acl_on_derived = || value.is_some() && xc::classify(&name) == xc::XattrClass::PosixAcl && pinned_derived(cfg, fd) != Ok(false);
    let secret = !noop && (pinned_is_registered_secret(cfg, fd) || acl_on_derived());
    let hit = match cfg.secrets.as_ref() {
        Some(index) if !noop && !secret && !index.write_protect.is_empty() => pinned_write_hit(cfg, PinnedWrite::File(fd)),
        _ => Ok(None),
    };
    // A descriptor that names no path: refused (fail-closed), as a write.
    let Ok(hit) = hit else { return refuse(libc::EACCES) };
    match xc::xattr_verdict(noop, secret, hit.is_some()) {
        xc::XattrVerdict::Perform => {}
        xc::XattrVerdict::Refuse => return refuse(libc::EACCES),
        xc::XattrVerdict::Judge => {
            let Some((seen, entry)) = hit else { return refuse(libc::EACCES) };
            match judge_write_hit(listener, cfg, notif, &seen, &entry) {
                WriteJudgement::Proceed => {}
                WriteJudgement::Refused => return refuse(libc::EACCES),
                WriteJudgement::Gone => {
                    close_fd(fd);
                    return;
                }
            }
        }
    }
    let answered = perform_under_domain(cfg, pid, move || {
        // SAFETY: the attribute call on a descriptor we hold, or through its
        // magic link, with our own copies of the name and value.
        let rc = unsafe {
            match (&value, by_fd) {
                (Some(v), true) => libc::fsetxattr(fd, cname.as_ptr(), v.as_ptr() as *const libc::c_void, v.len(), flags),
                (Some(v), false) => libc::setxattr(magic.as_ptr(), cname.as_ptr(), v.as_ptr() as *const libc::c_void, v.len(), flags),
                (None, true) => libc::fremovexattr(fd, cname.as_ptr()),
                (None, false) => libc::removexattr(magic.as_ptr(), cname.as_ptr()),
            }
        };
        if rc == 0 { 0 } else { Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) }
    });
    close_fd(fd);
    answer_errno(listener, notif, answered);
}

/// The arbiter's own socket (the guard's and every interceptor's channel).
/// A Unix sockaddr path as the TRACEE means it: abstract (`@…`) verbatim; a
/// relative path joined to the tracee's cwd; then canonicalized (symlinks
/// resolved) when it exists, else kept lexically. For the WSL interop check.
fn resolve_tracee_unix_path(pid: i32, p: &str) -> String {
    if p.starts_with('@') {
        return p.to_string();
    }
    let abs = if p.starts_with('/') {
        std::path::PathBuf::from(p)
    } else {
        match std::fs::read_link(format!("/proc/{pid}/cwd")) {
            Ok(cwd) => cwd.join(p),
            Err(_) => return p.to_string(),
        }
    };
    std::fs::canonicalize(&abs)
        .ok()
        .and_then(|c| c.to_str().map(String::from))
        .unwrap_or_else(|| abs.to_string_lossy().into_owned())
}

pub(crate) fn is_arbiter_socket(path: &str) -> bool {
    std::env::var("MANDU_ARBITER_SOCK").map(|s| !s.is_empty() && s == path).unwrap_or(false)
}

/// What a refused taint-leg connect knows about itself, for its event: the
/// secret files the process (or an ancestor) read raw and the bindings it may
/// reach. Empty when the arbiter could not be asked (the refusal then says
/// "a secret" / "no host").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaintedRefusal {
    pub files: Vec<String>,
    pub bindings: Vec<String>,
}

/// §4.3 for AF_UNIX: `None` (allowed) iff the arbiter says the process is
/// untainted or the path falls under one of its `unix:` bindings; otherwise
/// the refusal. Unreachable ⇒ refused.
pub(crate) fn tainted_unix_refusal(cfg: &GuardConfig, own: &str, ancestors: Vec<String>, upath: &str) -> Option<TaintedRefusal> {
    let Some(c) = cfg.emitter.as_ref() else { return Some(TaintedRefusal::default()) };
    let Ok(mut client) = c.lock() else { return Some(TaintedRefusal::default()) };
    let session = cfg.secrets.as_ref().and_then(|s| s.session.clone());
    let flows_from = crate::guard_flow::flows_from(cfg, own, &ancestors);
    let Ok(b) = client.tainted_process_bindings(&mandu_arbiter::protocol::TaintedProcessBindingsArgs {
        proc_key: own.to_string(),
        ancestors: if ancestors.is_empty() { None } else { Some(ancestors) },
        session,
        flows_from,
        ..Default::default()
    }) else { return Some(TaintedRefusal::default()) };
    // Bindings are matched as written and as resolved (the supervised leg
    // checks the kernel's path for the opened inode, which is canonical).
    let mut bound = b.bindings.clone();
    bound.extend(b.bindings.iter().filter_map(|p| std::fs::canonicalize(p).ok().and_then(|c| c.to_str().map(String::from))));
    if !b.tainted || crate::secret_open::unix_path_bound(upath, &bound) {
        return None;
    }
    Some(TaintedRefusal { files: b.files, bindings: b.bindings })
}

/// Best-effort emit of a taint-leg refusal (plan 10 §4.3): the event the
/// direct-connect case owed. Never touches the seccomp answer.
pub(crate) fn emit_tainted_refusal(cfg: &GuardConfig, dest: &str, refused: &TaintedRefusal) {
    let Some(emitter) = &cfg.emitter else { return };
    let ev = crate::events::guard_tainted_refusal_event(&cfg.session_id, dest, &refused.files, &refused.bindings);
    if let Ok(mut client) = emitter.lock() {
        mandu_arbiter::safe_emit(&mut client, &ev);
    }
}

/// The taint leg's verdict: `None` (allow) iff the destination matches one of
/// the bindings the arbiter returned, parsed as guard specs (`host:*` when a
/// binding carries no port); otherwise the refusal, with what the event
/// needs. No emitter / unreachable arbiter ⇒ refused (nothing known).
pub(crate) fn tainted_connect_refusal(cfg: &GuardConfig, own: &str, ancestors: Vec<String>, target: &Endpoint) -> Option<TaintedRefusal> {
    let Some(c) = cfg.emitter.as_ref() else { return Some(TaintedRefusal::default()) };
    let Ok(mut client) = c.lock() else { return Some(TaintedRefusal::default()) };
    let session = cfg.secrets.as_ref().and_then(|s| s.session.clone());
    let flows_from = crate::guard_flow::flows_from(cfg, own, &ancestors);
    let answer = client.tainted_process_bindings(&mandu_arbiter::protocol::TaintedProcessBindingsArgs {
        proc_key: own.to_string(),
        ancestors: if ancestors.is_empty() { None } else { Some(ancestors) },
        session,
        flows_from,
        ..Default::default()
    });
    let Ok(b) = answer else { return Some(TaintedRefusal::default()) };
    if !b.tainted {
        return None;
    }
    let refused = TaintedRefusal { files: b.files.clone(), bindings: b.bindings.clone() };
    // `unix:` bindings belong to the AF_UNIX leg and `mount:` ones to the
    // write-open (plan 13 §9 R4 (b)); here only host specs.
    let specs: Vec<String> = b.bindings.iter().filter(|h| crate::local_exits::is_host_binding(h)).map(|h| binding_to_spec(h)).collect();
    match crate::guard::parse_rules(&specs) {
        Ok(rules) => {
            let policy = GuardPolicy::new(rules);
            if policy.decide(target, cfg.resolver.as_ref()) == Decision::Allow { None } else { Some(refused) }
        }
        Err(_) => Some(refused),
    }
}

/// confidentiality.md §4, "A held command's refused connection"
/// (2026-10-12): the connect leg refused a holder; name the address to the
/// arbiter (human plane) so it consults, and spends, the human's answer for
/// the HIGH session's own network question, or files it. True only for an
/// approval of that question (`held_ask::ask_admits`); a process holding
/// anything but what its session read is never asked here
/// (`sessionAskOnly`), and no emitter, a locked client or an arbiter that
/// cannot answer leaves the refusal standing.
pub(crate) fn held_connect_once(cfg: &GuardConfig, own: &str, ancestors: Vec<String>, target: &Endpoint) -> bool {
    let Some(c) = cfg.emitter.as_ref() else { return false };
    let Ok(mut client) = c.lock() else { return false };
    let session = cfg.secrets.as_ref().and_then(|s| s.session.clone());
    let flows_from = crate::guard_flow::flows_from(cfg, own, &ancestors);
    let answer = client.tainted_process_bindings(&mandu_arbiter::protocol::TaintedProcessBindingsArgs {
        proc_key: own.to_string(),
        ancestors: if ancestors.is_empty() { None } else { Some(ancestors) },
        session,
        flows_from,
        destination: Some(crate::held_ask::held_destination(target.ip, target.port)),
        session_ask_only: Some(true),
    });
    matches!(answer, Ok(b) if b.tainted && crate::held_ask::ask_admits(b.ask.as_ref()))
}

/// A binding (`host`, `host:port`, `*.suffix`, an IP/CIDR) as a guard spec:
/// a missing port means any port.
pub fn binding_to_spec(binding: &str) -> String {
    let b = binding.trim();
    if b.starts_with('[') {
        // [v6]:port or [v6]
        return if b.contains("]:") { b.to_string() } else { format!("{b}:*") };
    }
    let colons = b.matches(':').count();
    if colons == 1 {
        return b.to_string();
    }
    format!("{b}:*")
}

/// Best-effort emit of a connect-guard decision event (docs/design/integrity/exec-routing.md
/// §7.5). No-op when no emitter is configured or the decision is not noteworthy
/// (a loopback ALLOW = proxy/forwarder chatter). Swallows a locked/failed client.
fn emit_decision(cfg: &GuardConfig, target: &Endpoint, decision: Decision, matched: Option<&crate::guard::AllowRule>) {
    let Some(emitter) = &cfg.emitter else { return };
    if !crate::events::guard_decision_is_noteworthy(decision, target.ip) {
        return;
    }
    let rule = matched.map(|r| r.to_string());
    let blocked = match decision {
        Decision::Deny => cfg.policy.blocked_reason(target),
        Decision::Allow => None,
    };
    let ev = crate::events::guard_connect_event(&cfg.session_id, 0, target, decision, rule.as_deref(), blocked);
    if let Ok(mut client) = emitter.lock() {
        mandu_arbiter::safe_emit(&mut client, &ev);
    }
}

/// Perform the connect on the tracee's socket (our dup, same file description) to
/// the address WE decoded — TOCTOU-safe. Returns the errno to hand back to the
/// tracee: 0 = connected, EINPROGRESS = a nonblocking connect now in flight (the
/// tracee polls its own fd), or the connect's real error, faithfully mirrored.
///
/// We NEVER alter the fd's flags (`pidfd_getfd` shares the open file description
/// with the tracee, so an O_NONBLOCK toggle would leak into the tracee). We simply
/// `connect()` and mirror the result — a blocking socket blocks THIS worker thread
/// (which is exactly what the tracee's own blocking connect would have done), a
/// nonblocking socket returns EINPROGRESS immediately.
pub(crate) fn supervisor_connect(fd: RawFd, sockaddr: &[u8]) -> i32 {
    // SAFETY: connect with the exact bytes/len the tracee passed (we copied them),
    // on a socket fd we own. Returns 0 or -1/errno.
    let rc = unsafe {
        libc::connect(
            fd,
            sockaddr.as_ptr() as *const libc::sockaddr,
            sockaddr.len() as libc::socklen_t,
        )
    };
    if rc == 0 {
        0
    } else {
        Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
    }
}

/// CONTINUE, guarded by ID_VALID (best-effort; a dead tracee just drops).
pub(crate) fn answer_continue(listener: RawFd, notif: &libc::seccomp_notif) {
    if notif_id_valid(listener, notif.id) {
        let _ = respond_continue(listener, notif.id);
    }
}

/// Return `errno` to the tracee's connect (0 = success), guarded by ID_VALID.
pub(crate) fn answer_errno(listener: RawFd, notif: &libc::seccomp_notif, errno: i32) {
    if notif_id_valid(listener, notif.id) {
        let _ = respond_errno(listener, notif.id, errno);
    }
}

// ── the supervisor loop ──────────────────────────────────────────────────────

/// Own the listener fd and loop: poll → on a notification, hand it to a worker
/// thread that decides + enacts; on POLLHUP (the last process holding the seccomp
/// filter has exited — the whole agent tree is gone) return cleanly.
///
// ── plan 10 §4.1: the open-family handler ────────────────────────────────────

/// What the handler did with one open notification (for tests and the log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenOutcome {
    /// An open that cannot read (write-only or `O_PATH`, flags in a register)
    /// of a file that is not a registered secret: the syscall ran as issued.
    Continued { why: &'static str },
    /// Not a registered secret: the guard opened it in the tracee's view and
    /// injected its own descriptor (plan 10 §4.1a).
    Performed,
    /// The open failed as the tracee's own would have; the errno returned.
    Failed { errno: i32 },
    /// A reader: the REAL file's descriptor was injected.
    Raw { app: String },
    /// The twin's descriptor was injected.
    Twin,
    /// EACCES.
    Denied { reason: String },
}

/// The open family's arguments: `(dirfd, path pointer, flags, mode,
/// openat2 resolve flags, is openat2)`. openat2 carries its flags in memory
/// (`struct open_how`), read once here: the kernel would re-read it on
/// CONTINUE, so an openat2 is always performed by the guard.
fn open_args(pid: i32, notif: &libc::seccomp_notif) -> std::result::Result<(i32, u64, i32, u32, u64, bool), i32> {
    let nr = notif.data.nr as i64;
    let a = &notif.data.args;
    if let Some((dirfd, path, flags)) = crate::secret_open::decode_open_args(nr, a) {
        let mode = if nr == libc::SYS_openat as i64 { a[3] } else { a[2] } as u32;
        return Ok((dirfd, path, flags, mode, 0, false));
    }
    // x86_64 `creat(path, mode)` == `open(path, O_CREAT|O_WRONLY|O_TRUNC)`: it
    // is trapped with the delete/write family (no filter had it before), and
    // routed here so the write-open path performs and judges it, pinned,
    // before the create/truncate takes effect (the path-change TOCTOU close).
    #[cfg(target_arch = "x86_64")]
    if nr == libc::SYS_creat as i64 {
        return Ok((libc::AT_FDCWD, a[0], libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC, a[1] as u32, 0, false));
    }
    // openat2(dirfd, path, how, size): size ≥ 24 (OPEN_HOW_SIZE_VER0); a
    // larger struct's extra bytes must be zero (E2BIG otherwise).
    let size = a[3] as usize;
    if size < 24 {
        return Err(libc::EINVAL);
    }
    if size > 4096 {
        return Err(libc::E2BIG);
    }
    let how = read_sockaddr(pid, a[2], size as u64).map_err(|_| libc::EFAULT)?;
    if how.len() != size {
        return Err(libc::EFAULT);
    }
    if how[24..].iter().any(|b| *b != 0) {
        return Err(libc::E2BIG);
    }
    let word = |i: usize| u64::from_ne_bytes(how[i * 8..i * 8 + 8].try_into().unwrap());
    let (flags, mode, resolve) = (word(0), word(1), word(2));
    if flags > u32::MAX as u64 {
        return Err(libc::EINVAL);
    }
    // The kernel's answer to a mode the flags do not take (a nonzero one on
    // an open that creates nothing): the performed open drops such a mode.
    if let Some(e) = fs_supervisor::tracee::openat2_mode_errno(flags as i32, mode) {
        return Err(e);
    }
    Ok((a[0] as i32, a[1], flags as i32, mode as u32, resolve, true))
}

/// ADDFD `fd` into the tracee as the answer to its open, close-on-exec as it
/// asked. Err = the errno to answer instead (never CONTINUE).
pub(crate) fn inject(listener: RawFd, notif: &libc::seccomp_notif, fd: RawFd, flags: i32) -> std::result::Result<(), i32> {
    // A notification that went away answers ENOENT here: nothing to answer.
    let addfd = libc::seccomp_notif_addfd {
        id: notif.id,
        flags: libc::SECCOMP_ADDFD_FLAG_SEND as u32,
        srcfd: fd as u32,
        newfd: 0,
        newfd_flags: (flags & libc::O_CLOEXEC) as u32,
    };
    // SAFETY: ADDFD reads a seccomp_notif_addfd by pointer.
    let rc = unsafe { libc::ioctl(listener, fs_supervisor::kernel::SECCOMP_IOCTL_NOTIF_ADDFD as _, &addfd as *const libc::seccomp_notif_addfd) };
    if rc < 0 { Err(Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)) } else { Ok(()) }
}

/// Hand `fd`, a descriptor the guard opened for the tracee, over as the
/// answer to its open (close-on-exec as it asked), and close the guard's own
/// copy. Consumes `fd` on every path. Err = the errno to answer instead.
///
/// A descriptor that holds its file for writing is closed BEFORE the tracee
/// resumes (plan 10 §4.1a, "The descriptor handed over"): ADDFD without
/// `SECCOMP_ADDFD_FLAG_SEND`, which installs it and leaves the tracee
/// waiting, then the guard's close, then the answer with the installed
/// number. With the atomic SEND the guard closed only after the tracee ran
/// on, and a tracee that wrote a program and ran it at once (`cp prog ws/p
/// && ws/p`) met ETXTBSY whenever the guard's thread was descheduled in
/// between (CI under load: 96-182 of 2000 such runs on 4 vCPUs). Any other
/// descriptor keeps the one-step SEND.
pub fn hand_over(listener: RawFd, notif: &libc::seccomp_notif, fd: RawFd, flags: i32) -> std::result::Result<(), i32> {
    // SAFETY: F_GETFL on our own descriptor.
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if status < 0 || !crate::secret_open::holds_for_writing(status) {
        let r = inject(listener, notif, fd, flags);
        close_fd(fd);
        return r;
    }
    let addfd = libc::seccomp_notif_addfd {
        id: notif.id,
        flags: 0,
        srcfd: fd as u32,
        newfd: 0,
        newfd_flags: (flags & libc::O_CLOEXEC) as u32,
    };
    // SAFETY: ADDFD reads a seccomp_notif_addfd by pointer; it returns the
    // number installed in the tracee, whose call is still waiting.
    let rc = unsafe { libc::ioctl(listener, fs_supervisor::kernel::SECCOMP_IOCTL_NOTIF_ADDFD as _, &addfd as *const libc::seccomp_notif_addfd) };
    let err = (rc < 0).then(|| Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
    close_fd(fd);
    if let Some(e) = err {
        return Err(e);
    }
    // A notification gone meanwhile (the tracee killed, or a signal that
    // interrupts its call) answers ENOENT: the descriptor stays in its table
    // (a dying process's, or an interrupted open's leftover number), the one
    // the guard had decided to give it.
    fs_supervisor::kernel::respond_value(listener, notif.id, rc as i64).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

/// Plan 13 D4 (2026-10-04): hand a derived file's twin to the tracee at the
/// lowest free descriptor number at or above `stat_twin::TWIN_FD_BASE` its
/// soft `RLIMIT_NOFILE` allows (`SECCOMP_ADDFD_FLAG_SETFD`), so a stat of
/// that descriptor reaches the guard (`handle_fd_stat_notif`) and reports
/// the identity of the file the twin stands for. No room there, a limit that
/// cannot be read, or a kernel that refuses the number: the lowest free
/// number, as `inject` (only the identity is then the twin's).
pub(crate) fn inject_twin_high(listener: RawFd, notif: &libc::seccomp_notif, fd: RawFd, flags: i32) -> std::result::Result<(), i32> {
    let pid = notif.pid as i32;
    let open: Vec<i32> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|d| d.filter_map(|e| e.ok().and_then(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))).collect())
        .unwrap_or_default();
    let soft = std::fs::read_to_string(format!("/proc/{pid}/limits")).ok().and_then(|t| crate::stat_twin::soft_nofile(&t));
    let Some(slot) = soft.and_then(|s| crate::stat_twin::twin_fd_slot(&open, s)) else {
        return inject(listener, notif, fd, flags);
    };
    let addfd = libc::seccomp_notif_addfd {
        id: notif.id,
        flags: (libc::SECCOMP_ADDFD_FLAG_SETFD | libc::SECCOMP_ADDFD_FLAG_SEND) as u32,
        srcfd: fd as u32,
        newfd: slot as u32,
        newfd_flags: (flags & libc::O_CLOEXEC) as u32,
    };
    // SAFETY: ADDFD reads a seccomp_notif_addfd by pointer.
    let rc = unsafe { libc::ioctl(listener, fs_supervisor::kernel::SECCOMP_IOCTL_NOTIF_ADDFD as _, &addfd as *const libc::seccomp_notif_addfd) };
    if rc >= 0 {
        return Ok(());
    }
    match Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) {
        // The number refused (a limit lowered meanwhile): the ordinary way.
        libc::EBADF | libc::EMFILE | libc::EINVAL => inject(listener, notif, fd, flags),
        e => Err(e),
    }
}

/// Plan 10 §4.1, with §4.1a: every open that can READ is performed by the
/// guard in the tracee's view (`fs_supervisor::tracee::open_as_tracee`), and
/// the file it actually opened is matched by identity. The kernel never
/// resolves such a path a second time, so neither a symlink swapped in nor a
/// path buffer rewritten by another thread can turn an innocent open into a
/// raw secret. Only an open that cannot read (`open`/`openat`, write-only or
/// `O_PATH`: its flags are a register, not memory) still runs as issued when
/// its path is not a secret. Every failure is answered with an errno.
/// Say the first cgroup refusal of the session where the guard's messages
/// go (`diag`), so a tool that fails on it (podman, crun) is explained once.
fn note_cgroup_refusal(path: &str, refused: crate::cgroup_guard::Refusal) {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
        crate::diag::say(&format!(
            "mandu-net-guard: refused opening {path} for writing ({}): the guard's own cgroup is kept out of the session's reach, so tools that move processes between cgroups (podman, crun) fail inside a session",
            refused.reason()
        ));
    }
}

pub fn handle_open_notif(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) -> OpenOutcome {
    use crate::secret_open::supervisor_open_flags;
    use fs_supervisor::kernel::canonicalize_for_tracee;
    use fs_supervisor::tracee::{open_as_tracee, read_path_bytes};

    let Some(index) = cfg.secrets.as_ref() else {
        answer_continue(listener, notif);
        return OpenOutcome::Continued { why: "no secret policy" };
    };
    let pid = notif.pid as i32;
    let fail = |errno: i32| {
        answer_errno(listener, notif, errno);
        OpenOutcome::Failed { errno }
    };
    let (dirfd, path_addr, flags, mode, resolve, is_openat2) = match open_args(pid, notif) {
        Ok(a) => a,
        Err(e) => return fail(e),
    };
    let raw_path = match read_path_bytes(pid, path_addr) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    // Findings 2 and 6, and the write-open race: an open that can change a
    // file is PERFORMED, never continued, and judged against the
    // write-protect list on what it resolved (the file, or the directory a
    // create lands in), pinned by a descriptor, before any O_CREAT or O_TRUNC
    // takes effect (`judged` below). O_TRUNC itself waits until the file is
    // also known not to be a registered secret.
    let write_intent = crate::secret_open::is_write_intent(flags) && flags & libc::O_PATH == 0;
    let reads = flags & libc::O_PATH == 0 && flags & libc::O_ACCMODE != libc::O_WRONLY;
    // §4.1: `/proc/<P>/mem`, `environ`, `fd/…` of a TAINTED process P, opened by
    // a process that does not already carry all of P's taint: refused (P's
    // own reads of itself continue; `introspection_refused`). The number in
    // the path is the procfs's own pid namespace's: translated to host pids
    // before the (host-keyed) taint set is asked.
    let introspects_tainted = |path: &str, dev: Option<u64>| -> Option<i32> {
        if cfg.tainted.is_empty() {
            return None;
        }
        let n = crate::secret_open::proc_introspection_target(path)?;
        introspection_refused(cfg, pid, &procfs_targets(cfg, pid, n, dev))
    };

    // An open that cannot read, of a path that is not a secret: it runs as
    // issued (a swapped path yields a write-only or O_PATH descriptor, which
    // reads nothing; re-opening one to read is itself an open that reads).
    let entry = if !reads && !is_openat2 && !write_intent {
        // The path as named, lexically (the key the policy registers).
        let spelling = canonicalize_for_tracee(pid, dirfd, &String::from_utf8_lossy(&raw_path));
        if let Some(target) = spelling.as_deref().and_then(|p| introspects_tainted(p, None)) {
            answer_errno(listener, notif, libc::EACCES);
            return OpenOutcome::Denied { reason: format!("introspection of tainted process {target}") };
        }
        // A directory hidden from the agent (Mandu's shadow repositories in
        // `secrets` mode): nothing under it opens, O_PATH and writes included.
        let hidden: Option<String> = spelling.as_deref().and_then(|p| {
            if let Some(x) = index.denied_prefix(p) {
                return Some(x.to_string());
            }
            let real = std::fs::canonicalize(p).ok()?;
            index.denied_prefix(real.to_str()?).map(str::to_string)
        });
        if let Some(prefix) = hidden {
            answer_errno(listener, notif, libc::EACCES);
            return OpenOutcome::Denied { reason: format!("under {prefix}, hidden from the agent") };
        }
        match spelling.as_deref().and_then(|p| index.lookup(p)) {
            Some(e) => e.clone(),
            None => {
                // Plan 13 D4: an `O_PATH` descriptor of a derived file would
                // re-open it raw through `/proc/self/fd`: it is gated as a
                // read is (the twin's descriptor, or the real one for an
                // opener).
                let derived = if flags & libc::O_PATH != 0 {
                    match spelling.as_deref().map(|p| derived_entry_by_path(cfg, index, Some(pid), p, flags & libc::O_NOFOLLOW != 0)) {
                        Some(Err(())) => {
                            answer_errno(listener, notif, libc::EACCES);
                            return OpenOutcome::Denied { reason: UNCHECKED_LABEL.into() };
                        }
                        Some(Ok(d)) => d,
                        None => None,
                    }
                } else {
                    None
                };
                match derived {
                    Some(e) => e,
                    None => {
                        let writer = crate::guard_flow::tainted_writer(cfg, pid, flags);
                        answer_continue(listener, notif);
                        label_tainted_write(cfg, index, writer, spelling, None);
                        return OpenOutcome::Continued { why: "cannot read, not a registered secret" };
                    }
                }
            }
        }
    } else {
        // Performed: resolve once in the tracee's view, then judge the file opened.
        let valid = || notif_id_valid(listener, notif.id);
        use fs_supervisor::tracee::{open_as_tracee_via, Final, Finish};
        // A task in a Landlock sandbox: the access runs on a mirror of it,
        // unless its sandbox governs no file (the launch's net-only wrap
        // alone, `Domain::governs_files`): the same split open (resolved
        // `O_PATH`, then reopened) then runs on this thread, where Landlock
        // would decide it the same way, without the mirror's two handoffs
        // (plan 10 §4.1a, the cost of the mirror). A pseudo-filesystem file
        // is still reopened by the context helper under the WHOLE mirrored
        // domain (`mirror`): Landlock's ptrace scoping, which every domain
        // carries, decides `/proc/<pid>/…` whatever rights it handles.
        let mirror = cfg.landlock.domain_of(pid);
        let domain = mirror.clone().filter(|d| d.governs_files());
        let split_here = mirror.is_some() && domain.is_none();
        let trunc_later = write_intent && crate::secret_open::truncate_after_lookup(flags);
        let open_flags = if trunc_later { flags & !libc::O_TRUNC } else { flags };
        // 1 = refused as write-protected, 2 = the tracee's call went away.
        let write_refused = std::cell::Cell::new(0u8);
        // Plan 13 §9 R4 (b): a holder's write-capable open. Its create gets
        // no group or other bits (another local user is not interposed), and
        // a file system that leaves the machine is a destination, judged
        // before the create or the reopen (`local_exits`).
        let holder = if write_intent { crate::guard_flow::tainted_writer(cfg, pid, flags) } else { None };
        let open_mode = if holder.is_some() { crate::local_exits::holder_create_mode(mode) } else { mode };
        let exit_refused: std::cell::RefCell<Option<(String, TaintedRefusal)>> = std::cell::RefCell::new(None);
        let run_step = |step: Final| -> std::result::Result<RawFd, i32> {
            match domain.as_ref() {
                None => fs_supervisor::tracee::run_final(step),
                Some(d) => d.run(move || fs_supervisor::tracee::run_final(step)).and_then(|r| r),
            }
        };
        let judge = |hit: Option<(String, crate::secret_open::WriteProtect)>| -> std::result::Result<(), i32> {
            let Some((seen, entry)) = hit else { return Ok(()) };
            match judge_write_hit(listener, cfg, notif, &seen, &entry) {
                WriteJudgement::Proceed => Ok(()),
                WriteJudgement::Refused => {
                    write_refused.set(1);
                    Err(libc::EACCES)
                }
                WriteJudgement::Gone => {
                    write_refused.set(2);
                    Err(libc::ESRCH)
                }
            }
        };
        // A write to a pseudo-filesystem file (a sysctl, a cgroup file) is
        // looked up again by the context helper, as the tracee: the kernel
        // judges such a LOOKUP by the opener (a sysctl picks its table by the
        // opener's namespaces), so the guard's own resolution names another
        // file. Such a file is never on the write-protect list.
        let pseudo_write = std::cell::Cell::new(false);
        let judged = |step: Final| -> std::result::Result<RawFd, i32> {
            if let Final::Reopen { fd, .. } = &step {
                if crate::context_helper::pseudo_kind(*fd) != crate::context_helper::Pseudo::No {
                    pseudo_write.set(true);
                    return Err(PSEUDO_WRITE);
                }
            }
            let (pinned, creating) = match &step {
                Final::Reopen { fd, .. } => (PinnedWrite::File(*fd), false),
                Final::Create { dir, name, .. } => (PinnedWrite::NewIn(*dir, name), true),
            };
            if let Some((own, chain)) = holder.as_ref() {
                let on = match &step {
                    Final::Reopen { fd, .. } => *fd,
                    Final::Create { dir, .. } => *dir,
                };
                if let Some(refused) = holder_mount_refusal(cfg, pid, on, own, chain) {
                    *exit_refused.borrow_mut() = Some(refused);
                    return Err(libc::EACCES);
                }
            }
            let before = pinned_write_hit(cfg, pinned).map_err(|_| libc::EACCES)?;
            let asked = before.is_some();
            judge(before)?;
            let fd = run_step(step)?;
            // A create that opened a file already there (no O_EXCL): judged
            // by what it is too (a hard link to a protected file), unless the
            // directory's check already asked.
            if creating && !asked {
                let after = match pinned_write_hit(cfg, PinnedWrite::File(fd)) {
                    Ok(h) => h,
                    Err(()) => {
                        close_fd(fd);
                        return Err(libc::EACCES);
                    }
                };
                if let Err(e) = judge(after) {
                    close_fd(fd);
                    return Err(e);
                }
            }
            Ok(fd)
        };
        let opened = if write_intent {
            open_as_tracee_via(pid, dirfd, &raw_path, open_flags, open_mode, resolve, &valid, Finish::Via(&judged))
        } else {
            match domain.as_ref() {
                None if split_here => {
                    OPENS_UNDER_WRAP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    open_as_tracee_via(pid, dirfd, &raw_path, flags, mode, resolve, &valid, Finish::Via(&fs_supervisor::tracee::run_final))
                }
                None => open_as_tracee(pid, dirfd, &raw_path, flags, mode, resolve, &valid),
                Some(d) => {
                    OPENS_MIRRORED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let via = |step: Final| d.run(move || fs_supervisor::tracee::run_final(step)).and_then(|r| r);
                    open_as_tracee_via(pid, dirfd, &raw_path, flags, mode, resolve, &valid, Finish::Via(&via))
                }
            }
        };
        let opened = if pseudo_write.get() {
            pseudo_write_as_tracee(cfg, pid, dirfd, &raw_path, open_flags, resolve, mirror.as_ref()).and_then(|fd| {
                // What the tracee's own walk found: still a pseudo file, or
                // (a component swapped since) a real one, judged like any.
                if crate::context_helper::pseudo_kind(fd) == crate::context_helper::Pseudo::No {
                    let hit = match pinned_write_hit(cfg, PinnedWrite::File(fd)) {
                        Ok(h) => h,
                        Err(()) => {
                            close_fd(fd);
                            return Err(libc::EACCES);
                        }
                    };
                    if let Err(e) = judge(hit) {
                        close_fd(fd);
                        return Err(e);
                    }
                }
                // Opened as the tracee already: never reopened by the helper.
                Ok(fs_supervisor::tracee::Opened { fd, own_proc: true })
            })
        } else {
            opened
        };
        match write_refused.get() {
            1 => {
                answer_errno(listener, notif, libc::EACCES);
                return OpenOutcome::Denied { reason: format!("{} is write-protected", String::from_utf8_lossy(&raw_path)) };
            }
            2 => return OpenOutcome::Failed { errno: libc::ESRCH },
            _ => {}
        }
        if let Some((dest, refusal)) = exit_refused.borrow_mut().take() {
            if let Ok(o) = &opened {
                close_fd(o.fd);
            }
            answer_errno(listener, notif, libc::EACCES);
            crate::guard_send::emit_tainted(cfg, "write to", &dest, &refusal);
            return OpenOutcome::Denied { reason: format!("{} is on {dest}, which is not a binding of what the writer holds: the write is refused", String::from_utf8_lossy(&raw_path)) };
        }
        // Refused to the guard: a pseudo-filesystem file may still be the
        // tracee's to open (its namespaces, its rights). Resolve it `O_PATH`
        // and let the helper decide as the tracee.
        let opened = match opened {
            Err(e) if e == libc::EACCES || e == libc::EPERM => {
                let keep = |step: Final| match step {
                    // SAFETY: a duplicate of the resolved O_PATH descriptor.
                    Final::Reopen { fd, .. } => match unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) } {
                        d if d >= 0 => Ok(d),
                        _ => Err(e),
                    },
                    Final::Create { .. } => Err(e),
                };
                match open_as_tracee_via(pid, dirfd, &raw_path, flags, mode, resolve, &valid, Finish::Via(&keep)) {
                    Ok(o) if crate::context_helper::pseudo_kind(o.fd) != crate::context_helper::Pseudo::No => Ok(o),
                    Ok(o) => {
                        close_fd(o.fd);
                        Err(e)
                    }
                    Err(_) => Err(e),
                }
            }
            other => other,
        };
        let opened = match opened {
            Ok(o) => o,
            Err(e) => return fail(e),
        };
        // What was opened, looked at once (runtime-instances.md §14.9): its
        // `fstat` and the path its descriptor names, each read once here
        // and given to every check below, where each check read its own
        // before (four `fstat`s, two or three `readlink`s and two `fstatfs`
        // an open). The descriptor's file never changes; its name is the
        // same snapshot of a live name each read was.
        // SAFETY: fstat into a zeroed stat buffer.
        let mut opened_st: libc::stat = unsafe { std::mem::zeroed() };
        let opened_stat = (unsafe { libc::fstat(opened.fd, &mut opened_st) } == 0).then_some(opened_st);
        let link_once: std::cell::OnceCell<Option<std::path::PathBuf>> = std::cell::OnceCell::new();
        let opened_link = || link_once.get_or_init(|| std::fs::read_link(format!("/proc/self/fd/{}", opened.fd)).ok()).as_deref();
        // A hidden directory (deny prefixes), judged by the file actually
        // opened: its resolved path, whatever spelling led there.
        if !index.deny_prefixes.is_empty() {
            let seen = opened_link().map(|p| p.to_string_lossy().into_owned());
            if let Some(prefix) = seen.as_deref().and_then(|p| index.denied_prefix(p)).map(str::to_string) {
                close_fd(opened.fd);
                answer_errno(listener, notif, libc::EACCES);
                return OpenOutcome::Denied { reason: format!("under {prefix}, hidden from the agent") };
            }
        }
        let mut fd = opened.fd;
        let (kind, procfs_seen) = crate::context_helper::classify_stat(fd, opened_stat.as_ref());
        if kind != crate::context_helper::Pseudo::No {
            // A pseudo-filesystem file (procfs, sysfs, cgroupfs, …) is never a
            // registered secret. §4.1: procfs of a TAINTED process, opened by an
            // untainted one, is refused. The kernel judges such a file against
            // its OPENER: unless it is the tracee's own procfs entry, a helper
            // with the tracee's credentials and namespaces opens it again
            // (context_helper); the guard's open is never handed over where
            // the two could differ.
            if let Some(target) = procfs_seen.as_deref().and_then(|p| introspects_tainted(p, fd_identity(fd).map(|(dev, _)| dev))) {
                close_fd(fd);
                answer_errno(listener, notif, libc::EACCES);
                return OpenOutcome::Denied { reason: format!("introspection of tainted process {target}") };
            }
            if flags & libc::O_PATH != 0 {
                // An `O_PATH` descriptor cannot be installed by ADDFD: a
                // directory is answered by itself reopened read-only, as the
                // tracee (the helper, or here for its own entry or where the
                // guard's open is the tracee's); anything else ENOSYS
                // (`o_path_reply`).
                let own = opened.own_proc;
                let reply = crate::secret_open::o_path_reply(fd_mode(fd), |want| {
                    if !own {
                        if let Some(again) = cfg.helpers.reopen_as(pid, fd, want, kind, procfs_seen.as_deref(), mirror.as_ref())? {
                            return Ok(again);
                        }
                    }
                    fs_supervisor::tracee::run_final(fs_supervisor::tracee::Final::Reopen { fd, flags: want })
                });
                close_fd(fd);
                fd = match reply {
                    Ok(d) => d,
                    Err(e) => return fail(e),
                };
            } else if !opened.own_proc {
                match cfg.helpers.reopen_as(pid, fd, flags, kind, procfs_seen.as_deref(), mirror.as_ref()) {
                    Ok(Some(again)) => {
                        close_fd(fd);
                        fd = again;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        close_fd(fd);
                        return fail(e);
                    }
                }
            }
            // The guard's own cgroup (rootless-confinement §12.2, "The
            // cgroup"): a write-capable descriptor of a cgroup2 file of the
            // guard's cgroup or one above it, or of a task list a move
            // could take the guard through, is never handed over. Judged
            // on the descriptor about to be handed over, after any reopen.
            if let Some(refused) = crate::cgroup_guard_kernel::refusal(fd, flags) {
                close_fd(fd);
                answer_errno(listener, notif, libc::EACCES);
                let what = String::from_utf8_lossy(&raw_path).into_owned();
                note_cgroup_refusal(&what, refused);
                return OpenOutcome::Denied { reason: format!("{what}: {}", refused.reason()) };
            }
            let r = inject(listener, notif, fd, flags);
            close_fd(fd);
            return match r {
                Ok(()) => OpenOutcome::Performed,
                Err(e) => fail(e),
            };
        }
        // A registered secret (and its twin) is a regular file: a directory, a
        // device, a FIFO opened is never one, whatever it was called. A regular
        // file is named by the descriptor itself (symlinks resolved; under the
        // twin bind, the bind's path).
        let (hit, seen) = match opened_stat.as_ref().and_then(regular_identity) {
            Some(id) => {
                let seen = opened_link().map(|p| p.to_string_lossy().into_owned());
                (index.lookup_opened(seen.as_deref().unwrap_or(""), id, crate::secret_open::file_id), seen)
            }
            None => (None, None),
        };
        // Plan 13 D4: a derived file (a copy a process holding a secret
        // wrote) is gated as a labelled file with no reader list, when the
        // open can read it; and so is (2026-10-17) a file a human label
        // covers that the launch did not register (`labelled_entry`), and
        // (2026-10-17) such a labelled file's write-only open when it is not
        // empty, as a registered file's is (`label_index::open_gate`). Err:
        // it may be one and cannot be checked.
        let derived = |st: &libc::stat| -> std::result::Result<Option<crate::secret_open::SecretEntry>, ()> {
            let (seen, id, ctime, nlink) = (seen.as_deref().unwrap_or(""), (st.st_dev, st.st_ino), ctime_ns_of(st), st.st_nlink as u64);
            let holder = !reads && write_intent && crate::guard_flow::tainted_writer(cfg, pid, flags).is_some();
            match crate::label_index::open_gate(reads, write_intent, st.st_size.max(0) as u64, holder) {
                crate::label_index::OpenGate::Ungated => Ok(None),
                crate::label_index::OpenGate::Read => gated_entry(cfg, index, Some(pid), seen, id, ctime, nlink),
                crate::label_index::OpenGate::LabelledWrite => labelled_entry(cfg, index, Some(pid), seen, id, ctime, nlink),
            }
        };
        match hit {
            Some(e) => {
                close_fd(fd);
                e.clone()
            }
            None => {
                // The `fstat` taken once above (zeroed when it failed: no
                // file type, so neither a regular file nor a FIFO).
                // SAFETY: a zeroed stat buffer is a valid `libc::stat`.
                let st: libc::stat = opened_stat.unwrap_or_else(|| unsafe { std::mem::zeroed() });
                let regular = opened_stat.is_some() && st.st_mode & libc::S_IFMT == libc::S_IFREG;
                // Plan 14 §11.1 R4: an object-store file holding a locked
                // object (or one whose verdict cannot be reached) that the
                // launch prepared no sanitized copy of is refused, whatever
                // the intent: judged on the file the guard pinned, before
                // any O_TRUNC below.
                if regular {
                    // A temporary file of object content this open CREATED
                    // (git's `O_CREAT|O_EXCL`) is the session's own; any
                    // other is refused below (2026-10-17, `GitLockGuard::created`).
                    if flags & libc::O_CREAT != 0 && flags & libc::O_EXCL != 0 {
                        if let (Some(gl), Some(s)) = (index.git_locks(), seen.as_deref()) {
                            gl.created(s, &crate::git_lock::FileKey::of(&st));
                        }
                    }
                    if let Some(why) = seen.as_deref().and_then(|s| git_lock_refusal(cfg, s, &st, crate::git_lock::Access::Open)) {
                        close_fd(fd);
                        answer_errno(listener, notif, libc::EACCES);
                        return OpenOutcome::Denied { reason: why };
                    }
                }
                let derived = if regular { derived(&st) } else { Ok(None) };
                match derived {
                    Err(()) => {
                        close_fd(fd);
                        answer_errno(listener, notif, libc::EACCES);
                        return OpenOutcome::Denied { reason: UNCHECKED_LABEL.into() };
                    }
                    Ok(Some(e)) => {
                        // Gated below like a registered file (the twin, or
                        // the real file for an opener a human named).
                        close_fd(fd);
                        e
                    }
                    Ok(None) => {
                        let writer = crate::guard_flow::tainted_writer(cfg, pid, flags);
                        // Plan 13 §9 R4 (b), before the descriptor is handed
                        // over and before any O_TRUNC: a holder's write onto
                        // a mount that leaves the machine (again: the open
                        // may have made a holder of it since the check before
                        // the create), into a device that is not the
                        // terminal or a sink that keeps nothing, or into a
                        // file other local users could read (narrowed here,
                        // or refused).
                        if let Some((own, chain)) = writer.as_ref() {
                            if let Err((dest, refusal, why)) = holder_written_file(cfg, pid, fd, &st, own, chain) {
                                close_fd(fd);
                                answer_errno(listener, notif, libc::EACCES);
                                crate::guard_send::emit_tainted(cfg, "write to", &dest, &refusal);
                                return OpenOutcome::Denied { reason: why };
                            }
                        }
                        // Plan 13 §9 R1, the file shapes (`object_flow`), before
                        // the descriptor is handed over and before any O_TRUNC:
                        // a holder's write-capable open makes every process
                        // already reading the file a holder (`tail -f log |
                        // curl … &` started before), or is refused when one of
                        // them holds an unbound connection; a reading open of
                        // a file a holder wrote that no label gates (an
                        // unlinked file, an O_TMPFILE linked into place)
                        // makes the opener one; any other reading open is in
                        // flight until its descriptor is in its table.
                        let object = if regular { crate::object_flow::object_of(&st, opened_link()) } else { None };
                        if let (Some(t), Some(w)) = (object.as_ref(), writer.as_ref()) {
                            if let Err((dest, refusal)) = crate::guard_flow::object_written(cfg, w, pid, t, crate::object_flow::born_recently(fd), None) {
                                close_fd(fd);
                                answer_errno(listener, notif, libc::EACCES);
                                let file = seen.clone().unwrap_or_default();
                                crate::guard_send::emit_sweep_refusal(cfg, &file, &dest, &refusal);
                                return OpenOutcome::Denied { reason: format!("{file} is read by a process that {} {dest}, which is not a binding of what the writer holds: the write is refused", crate::local_exits::held_exit_phrase(&dest).1) };
                            }
                        }
                        // A FIFO is named by its path, the link D2 marks: a
                        // reading open of one a holder wrote into makes the
                        // opener a holder before it gets the descriptor (one
                        // that read and closed it before its next trapped
                        // call escaped before 2026-10-02), and the open is
                        // listed in flight for a holder's write-open racing it.
                        let fifo_link = (st.st_mode & libc::S_IFMT == libc::S_IFIFO).then(|| opened_link().and_then(|p| p.to_str().map(String::from))).flatten();
                        let object = object.or_else(|| fifo_link.clone().map(|l| crate::object_flow::ObjectTarget { keys: vec![l], path: None }));
                        // The agent's own read of a holder's FIFO is recorded as
                        // an agent flow below (`agent_fifo_open`), never refused.
                        let agent_fifo = fifo_link.is_some() && reads && crate::guard_flow::is_agent_pid(cfg, pid);
                        let ticket = match object.as_ref().filter(|_| reads && !agent_fifo) {
                            Some(t) => match crate::guard_flow::object_open(cfg, pid, t) {
                                Ok(tk) => tk,
                                Err((dest, refusal)) => {
                                    close_fd(fd);
                                    answer_errno(listener, notif, libc::EACCES);
                                    let file = seen.clone().unwrap_or_default();
                                    crate::guard_send::emit_sweep_refusal(cfg, &file, &dest, &refusal);
                                    return OpenOutcome::Denied { reason: format!("{file} was written by a process holding a secret: {dest}") };
                                }
                            },
                            None => None,
                        };
                        let end = |t: Option<u64>| {
                            if let Some(t) = t {
                                cfg.object_opens.end(t);
                            }
                        };
                        // O_TRUNC, held back until the file was known to be neither
                        // write-protected nor a registered secret. The kernel
                        // truncates only a regular file (a device, a FIFO ignore it).
                        if trunc_later && regular {
                            // A read-only descriptor's writable reopen runs
                            // where the open's last step ran (the tracee's
                            // Landlock domain, if any).
                            let reopen = |f: RawFd| run_step(fs_supervisor::tracee::Final::Reopen { fd: f, flags: libc::O_WRONLY });
                            if let Err(e) = truncate_held_back(fd, flags, &reopen) {
                                close_fd(fd);
                                end(ticket);
                                return fail(e);
                            }
                        }
                        // Plan 13 D2: a holder opening a FIFO to write sends into it
                        // whoever reads it (an O_WRONLY open completes only once a
                        // reader has it open): they become holders before the
                        // descriptor is handed over, and a reader the guard does not
                        // watch refuses the open (`guard_flow::fifo_write_open`).
                        if let (Some(link), Some(w)) = (fifo_link.as_ref(), writer.as_ref()) {
                            // P0 1a (2026-10-07): an O_RDWR open needs an in-tree
                            // reader too (the kernel completes it with none).
                            let needs_reader = flags & libc::O_ACCMODE != libc::O_RDONLY;
                            if let Err((dest, refusal)) = crate::guard_flow::fifo_write_open(cfg, w, pid, link, (st.st_dev, st.st_ino), needs_reader) {
                                close_fd(fd);
                                end(ticket);
                                answer_errno(listener, notif, libc::EACCES);
                                crate::guard_send::emit_sweep_refusal(cfg, link, &dest, &refusal);
                                return OpenOutcome::Denied { reason: format!("the named pipe {link} is read by {dest}: the write is refused") };
                            }
                        }
                        // The file takes the writer's label BEFORE the writer
                        // gets its descriptor (2026-10-02): labelled after,
                        // the writer could write and exit and the next
                        // program read the copy raw before the label reached
                        // the derived index (derived-label-live, CI pipeline
                        // 8105: `cp .env copy.txt; cat copy.txt` printed the
                        // key under load). A label for an open that then
                        // fails labels a file nobody wrote: the strict side.
                        // Plan 13 §4.5.1 (2026-10-02): a FIFO the agent ITSELF
                        // reads (its file tool on a named pipe) and a holder
                        // writes. D2 makes no holder of the agent, so the later
                        // of the two opens records an agent flow on the
                        // agent's read end before the descriptor is handed
                        // over (the model exit then masks the agent's results
                        // in that window), under one gate so two opens that
                        // complete together never miss each other. A record
                        // that fails refuses this open (fail-closed).
                        let fifo_id = (st.st_mode & libc::S_IFMT == libc::S_IFIFO).then_some((st.st_dev, st.st_ino));
                        let agent_reads = fifo_id.is_some() && reads && crate::guard_flow::is_agent_pid(cfg, pid);
                        let holder_writes = fifo_id.is_some() && writer.is_some();
                        let _fifo_gate = (agent_reads || holder_writes).then(|| cfg.fifo_gate.lock().ok()).flatten();
                        if let (Some(id), Some(w), true) = (fifo_id, writer.as_ref(), holder_writes) {
                            if let Err(e) = crate::guard_flow::holder_fifo_open(cfg, w, id) {
                                close_fd(fd);
                                end(ticket);
                                answer_errno(listener, notif, libc::EACCES);
                                return OpenOutcome::Denied { reason: format!("a FIFO the agent reads, written by a process holding a secret: the flow could not be recorded ({e})") };
                            }
                        }
                        if let (Some(id), true) = (fifo_id, agent_reads) {
                            let link = opened_link().and_then(|p| p.to_str().map(String::from)).unwrap_or_default();
                            if let Err(e) = crate::guard_flow::agent_fifo_open(cfg, &link, id) {
                                close_fd(fd);
                                end(ticket);
                                answer_errno(listener, notif, libc::EACCES);
                                return OpenOutcome::Denied { reason: format!("a FIFO a process holding a secret writes: the agent's flow could not be recorded ({e})") };
                            }
                        }
                        label_tainted_write(cfg, index, writer, seen, None);
                        // An `O_PATH` descriptor cannot be installed by ADDFD
                        // (EBADF): a directory is answered by itself reopened
                        // read-only, as the tracee's own open would get it
                        // (tar's parent openat2); anything else, or a
                        // directory the tracee may not list, ENOSYS
                        // (`o_path_reply`).
                        if flags & libc::O_PATH != 0 {
                            let reply = crate::secret_open::o_path_reply(st.st_mode, |want| run_step(fs_supervisor::tracee::Final::Reopen { fd, flags: want }));
                            close_fd(fd);
                            match reply {
                                Ok(d) => fd = d,
                                Err(e) => {
                                    end(ticket);
                                    return fail(e);
                                }
                            }
                        }
                        // A write-capable descriptor is closed before the
                        // tracee resumes (`hand_over`): a program it writes
                        // and runs at once must not meet ETXTBSY.
                        let r = hand_over(listener, notif, fd, flags);
                        // In the tracee's table now (or never): a writer's
                        // scan of `/proc` finds it from here on.
                        end(ticket);
                        return match r {
                            Ok(()) => OpenOutcome::Performed,
                            Err(e) => fail(e),
                        };
                    }
                }
            }
        }
    };

    // A git object-store entry (launcher git-object-twins.ts) is answered
    // here, without the arbiter: a pack or its index gets the sanitized twin,
    // a file that would expose a protected version is refused. No reader is
    // ever handed the real pack.
    match entry.answer(crate::secret_open::is_write_intent(flags)) {
        crate::secret_open::EntryAnswer::Arbiter => {}
        crate::secret_open::EntryAnswer::Deny => {
            answer_errno(listener, notif, libc::EACCES);
            return OpenOutcome::Denied { reason: format!("{} would expose a protected file's committed bytes", entry.path) };
        }
        crate::secret_open::EntryAnswer::Twin => {
            return match open_twin_for(listener, notif, dirfd, &raw_path, &entry.twin, flags) {
                Some(fd) => {
                    let r = inject(listener, notif, fd, flags);
                    // SAFETY: our own descriptor; ADDFD duplicated it into the tracee.
                    unsafe { libc::close(fd) };
                    match r {
                        Ok(()) => OpenOutcome::Twin,
                        Err(e) => fail(e),
                    }
                }
                None => {
                    answer_errno(listener, notif, libc::EACCES);
                    OpenOutcome::Denied { reason: "the sanitized twin could not be opened: refused (fail-closed)".into() }
                }
            };
        }
    }

    let proc_key = crate::secret_open::own_key_of(pid);
    // Inside the enforce-clean box (exec-output-trust §4 rung 2) a secret is
    // refused without asking: the box reads only its verified roots, so the
    // open would fail under its Landlock anyway, and an ask here would spend
    // the human's once-answer on the clean attempt while the ordinary rerun,
    // which produces the real output, re-asked into silence (drill S7,
    // 2026-09-24). The rerun runs outside the box and asks once.
    if cfg.clean_boxes.holds_or_inherits(pid, &proc_key).0 {
        answer_errno(listener, notif, libc::EACCES);
        return OpenOutcome::Denied { reason: "a secret inside the enforce-clean box: refused without an ask (the rerun outside the box asks)".into() };
    }

    // The opener's identity (§11.2, Plan 13 D8): its executable, the hash of
    // the inode it runs, whether the agent could have written that binary,
    // the loader / interpreter variables it runs with that the launch did
    // not give, and its ancestors' trust for `from:` (reader_identity).
    let identity = index.identity.exe(pid);
    let exe = identity.path.clone();
    let sha256 = identity.sha256.clone();
    let opener_env = if exe.is_empty() { None } else { index.identity.findings(pid, &exe) };
    // Plan 13 R5: for an interpreter, the script it runs (a reader entry may
    // pin the pair); inline code and the like are a reason, never facts.
    let (script, script_problem) = match if exe.is_empty() { None } else { index.identity.script(pid, &exe) } {
        None => (None, None),
        Some(Ok(f)) => (Some(mandu_arbiter::protocol::ScriptFactsWire { path: f.path, sha256: f.sha256, system: f.system, isolated: f.isolated, traced: f.traced }), None),
        Some(Err(why)) => (None, Some(why)),
    };
    let ancestors = index.identity.ancestors(pid, 16);
    let is_agent = !index.agent_exe.is_empty() && exe == index.agent_exe;
    // Plan 13 D7: the opener's live chain, so the arbiter links it to its
    // call's root through any subshell that never exec'd.
    let ancestor_keys = crate::secret_open::lineage_chain_of(pid);
    let parent_key = ancestor_keys.first().cloned().or_else(|| crate::secret_open::parent_key_of(pid));
    let orphan_root = orphan_root_for(cfg, pid, &proc_key, &ancestor_keys);

    // The arbiter decides and records (§4.1 step 3). Unreachable ⇒ the twin
    // (fail-closed: the guard alone may be what stands between the tracee and
    // the real file, §4.1a). An `ask` verdict is the hold of §11.1: the tracee
    // stays suspended on this notification while the guard re-asks every half
    // second until the human's answer changes the verdict or the ceiling
    // (§12.2) passes. The ceiling is ONE more ask that carries `heldMs`: the
    // arbiter records the unanswered hold as a denial (the tool result's
    // "held:" note, §11.8) and answers deny; the Inbox row outlives the hold.
    // Only an arbiter that has gone away during the hold leaves the guard to
    // serve the twin on its own.
    let args = mandu_arbiter::protocol::DecideSecretOpenArgs {
        path: entry.path.clone(),
        exe: exe.clone(),
        sha256: sha256.clone(),
        is_agent,
        proc_key: proc_key.clone(),
        parent_key: parent_key.clone(),
        ancestor_keys: if ancestor_keys.is_empty() { None } else { Some(ancestor_keys) },
        orphan_root,
        ancestor_exes: Some(ancestors.iter().map(|(e, _)| e.clone()).collect()),
        ancestor_trusted: Some(ancestors.iter().map(|(_, t)| *t).collect()),
        exe_system: Some(identity.system),
        opener_env,
        script,
        script_problem,
        session: index.session.clone(),
        ask: index.ask.clone(),
        held_ms: None,
    };
    let decide = |cfg: &GuardConfig, args: &mandu_arbiter::protocol::DecideSecretOpenArgs| -> Option<mandu_arbiter::protocol::SecretOpenVerdict> {
        let c = cfg.emitter.as_ref()?;
        let mut client = c.lock().ok()?;
        client.decide_secret_open(args).ok()
    };
    let verdict = match decide(cfg, &args) {
        None => "twin".to_string(),
        Some(mut v) => {
            if v.verdict == "ask" {
                let deadline = Instant::now() + Duration::from_millis(index.ask_timeout_ms);
                loop {
                    if !notif_id_valid(listener, notif.id) {
                        return OpenOutcome::Failed { errno: libc::ESRCH };
                    }
                    if Instant::now() >= deadline {
                        let expired = mandu_arbiter::protocol::DecideSecretOpenArgs { held_ms: Some(index.ask_timeout_ms), ..args.clone() };
                        v = match decide(cfg, &expired) {
                            // deny with the recorded "held for …" reason, or a late answer
                            Some(next) => next,
                            None => mandu_arbiter::protocol::SecretOpenVerdict {
                                verdict: "deny".into(),
                                reason: format!("held for {} s, nobody answered; the approval is still waiting in the dashboard", index.ask_timeout_ms / 1000),
                                ..v
                            },
                        };
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                    match decide(cfg, &args) {
                        Some(next) if next.verdict != "ask" => {
                            v = next;
                            break;
                        }
                        Some(_) => continue,
                        None => {
                            v.verdict = "twin".into();
                            break;
                        }
                    }
                }
            }
            // Plan 13 §4.9 (2026-10-07, "refuse raw if visible"): a holder's
            // lookups and read offsets on a network or FUSE mount reach its
            // server, and no trap judges every path walk. So the real file
            // is withheld (the twin is served, as to a program that is no
            // reader) while such a mount is visible in the opener's mount
            // namespace, unbound and not trusted for lookups.
            if v.verdict == "raw" {
                if let Some(why) = raw_withheld_by_visible_mount(cfg, index, pid, &proc_key, &entry.path) {
                    emit_raw_withheld(cfg, &entry.path, &exe, &why);
                    v.verdict = "twin".into();
                }
            }
            if v.verdict == "raw" {
                return match open_for_tracee(&entry.path, supervisor_open_flags(flags, false)) {
                    Some(fd) => {
                        // Remembered for the network and filesystem exits
                        // (§4.3, §4) BEFORE the ADDFD resumes the reader
                        // (TaintedSet::taint_then), and the sockets the
                        // reader and its descendants ALREADY hold judged
                        // before it gets a byte (exec-routing.md §7.5,
                        // 2026-10-01: a socket connected before the taint
                        // carried the secret, judged only at its connect).
                        let held_before = cfg.tainted.contains(&proc_key);
                        cfg.tainted.insert(&proc_key);
                        let held_writes = match crate::guard_send::sweep_before_taint(cfg, pid) {
                            Ok(w) => w,
                            Err((dest, refusal)) => {
                                // Plan 13 §4.9 (2026-10-03): refused, the
                                // reader got no byte; one that held nothing
                                // before is no holder, or its shell would be
                                // judged a holder's reaper at its next wait
                                // (`guard_wait`) for a status that carries
                                // nothing (`exec 3<>/dev/udp/…; K=$(cat .env)`).
                                if !held_before {
                                    cfg.tainted.forget(&proc_key);
                                }
                                // SAFETY: our own descriptor.
                                unsafe { libc::close(fd) };
                                answer_errno(listener, notif, libc::EACCES);
                                crate::guard_send::emit_sweep_refusal(cfg, &entry.path, &dest, &refusal);
                                return OpenOutcome::Denied { reason: format!("{} {} {dest}, which is not a binding of {}: the raw file is refused", v.app, crate::local_exits::held_exit_phrase(&dest).1, entry.path) };
                            }
                        };
                        // Plan 13 D5: the files the reader and its
                        // descendants ALREADY hold open for writing take the
                        // taint's label now, before a byte arrives (the
                        // later of the two events, §4.5): `reader > out.txt`.
                        for w in held_writes {
                            label_tainted_write(cfg, index, Some((w.own, w.chain)), Some(w.path), w.id);
                        }
                        // The reader's O_TRUNC, held back from the open
                        // (`supervisor_open_flags`) until the refusals above
                        // are behind: a reader that rewrites its file shorter
                        // (`aws configure`) leaves no stale tail
                        // (`truncate_after_lookup`, 2026-10-10). The real
                        // file was opened by the guard, as the guard: so is
                        // a read-only descriptor's writable reopen.
                        if crate::secret_open::truncate_after_lookup(flags) {
                            let reopen = |f: RawFd| open_for_tracee(&format!("/proc/self/fd/{f}"), libc::O_WRONLY).ok_or_else(|| std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EACCES));
                            if let Err(e) = truncate_held_back(fd, flags, &reopen) {
                                if !held_before {
                                    cfg.tainted.forget(&proc_key);
                                }
                                close_fd(fd);
                                return fail(e);
                            }
                        }
                        let r = cfg.tainted.taint_then(&proc_key, || inject(listener, notif, fd, flags));
                        // SAFETY: our own descriptor; ADDFD duplicated it into the tracee.
                        unsafe { libc::close(fd) };
                        match r {
                            Ok(()) => OpenOutcome::Raw { app: v.app },
                            Err(e) => fail(e),
                        }
                    }
                    None => {
                        answer_errno(listener, notif, libc::EACCES);
                        OpenOutcome::Denied { reason: "the real file could not be opened by the guard".into() }
                    }
                };
            }
            if v.verdict != "twin" {
                answer_errno(listener, notif, libc::EACCES);
                return OpenOutcome::Denied { reason: v.reason };
            }
            v.verdict
        }
    };
    debug_assert_eq!(verdict, "twin");
    // Plan 13 D4: a derived file has no twin from the launch; the guard makes
    // one from the arbiter's symbol (none ⇒ refused below, fail-closed).
    // 2026-10-17: and so has a labelled file the launch did not register.
    let derived = entry.twin_on_demand();
    let twin = if derived { derived_twin(cfg, index, &entry.path, entry.kind.as_deref() == Some("labelled")).unwrap_or_default() } else { entry.twin.clone() };
    if twin.is_empty() {
        answer_errno(listener, notif, libc::EACCES);
        return OpenOutcome::Denied { reason: format!("no twin of a {} file could be made: refused (fail-closed)", entry.kind.as_deref().unwrap_or("protected")) };
    }
    match open_twin_for(listener, notif, dirfd, &raw_path, &twin, flags) {
        Some(fd) => {
            // Plan 13 D4 (2026-10-04): a derived twin's descriptor at the
            // twin base, where its fstat reports the real file's identity.
            let r = if derived { inject_twin_high(listener, notif, fd, flags) } else { inject(listener, notif, fd, flags) };
            // SAFETY: our own descriptor; ADDFD duplicated it into the tracee.
            unsafe { libc::close(fd) };
            match r {
                Ok(()) => OpenOutcome::Twin,
                Err(e) => fail(e),
            }
        }
        None => {
            answer_errno(listener, notif, libc::EACCES);
            OpenOutcome::Denied { reason: "the twin could not be opened: refused (fail-closed)".into() }
        }
    }
}

// ── confidentiality.md §7.2a: the stat family on a guard-only twin ───────────

/// What the handler did with one stat notification (for tests and the log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatOutcome {
    /// Left to the kernel (not a twinned file, a flag the guard does not
    /// emulate, or any failure): the real file's metadata, as before.
    Continued { why: &'static str },
    /// The twin's metadata was written into the tracee's buffer.
    Twin,
    /// The tracee's buffer could not be written: the errno returned.
    Failed { errno: i32 },
}

/// Write `bytes` at `addr` in the tracee, as the kernel's own copy-out
/// would (a buffer that is not writable is EFAULT). The notification is
/// checked just before, so a tracee gone meanwhile is never written to.
/// Err(Some(e)) = answer `e`; Err(None) = the guard cannot reach the
/// tracee's memory at all (continue).
pub(crate) fn write_tracee(listener: RawFd, notif: &libc::seccomp_notif, addr: u64, bytes: &[u8]) -> std::result::Result<(), Option<i32>> {
    if addr == 0 {
        return Err(Some(libc::EFAULT));
    }
    if !notif_id_valid(listener, notif.id) {
        return Err(Some(libc::ESRCH));
    }
    let local = libc::iovec { iov_base: bytes.as_ptr() as *mut libc::c_void, iov_len: bytes.len() };
    let remote = libc::iovec { iov_base: addr as *mut libc::c_void, iov_len: bytes.len() };
    // SAFETY: writes `bytes.len()` bytes from our buffer into the tracee.
    let n = unsafe { libc::process_vm_writev(notif.pid as i32, &local, 1, &remote, 1, 0) };
    if n == bytes.len() as isize {
        return Ok(());
    }
    if n >= 0 {
        // A partial write: the buffer ends in an unmapped page.
        return Err(Some(libc::EFAULT));
    }
    match Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) {
        libc::EFAULT => Err(Some(libc::EFAULT)),
        libc::ESRCH => Err(Some(libc::ESRCH)),
        _ => Err(None),
    }
}

/// The twin's metadata in the form the call asked for. `None`: the twin
/// cannot be stat'ed (continue).
fn twin_metadata(twin: &str, form: crate::stat_twin::StatForm) -> Option<Vec<u8>> {
    let c = std::ffi::CString::new(twin).ok()?;
    match form {
        crate::stat_twin::StatForm::Stat => {
            // SAFETY: stat into a zeroed buffer; `c` is NUL-terminated.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            (unsafe { libc::stat(c.as_ptr(), &mut st) } == 0).then(|| crate::stat_twin::stat_bytes(&st))
        }
        crate::stat_twin::StatForm::Statx { mask, sync } => {
            // SAFETY: statx into a zeroed buffer; `c` is NUL-terminated.
            let mut sx: libc::statx = unsafe { std::mem::zeroed() };
            (unsafe { libc::statx(libc::AT_FDCWD, c.as_ptr(), sync, mask, &mut sx) } == 0).then(|| crate::stat_twin::statx_bytes(&sx))
        }
    }
}

/// confidentiality.md §7.2a: a stat by path (`stat`, `lstat`, `newfstatat`,
/// `statx` without `AT_EMPTY_PATH`) in the guard-only posture. A path no
/// name of a registered file can be reached by continues at once
/// (`stat_twin::stat_probe`: an `lstat` of another leaf while no registered
/// file has another link, or a directory name). Otherwise the guard
/// resolves it ONCE in the tracee's view to
/// an `O_PATH` descriptor (`O_NOFOLLOW` for lstat), matches the file it
/// pinned by path and identity (`SecretIndex::lookup_opened`, as an open
/// is), and answers a registered file with its TWIN's metadata, written
/// into the tracee's buffer: what the bind shows there, and what `fstat` of
/// the descriptor the guard hands out on open says. No byte of any file is
/// read or handed over; every other case continues to the kernel.
pub fn handle_stat_notif(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) -> StatOutcome {
    let cont = |why: &'static str| {
        answer_continue(listener, notif);
        StatOutcome::Continued { why }
    };
    let Some(index) = cfg.secrets.as_ref() else { return cont("no secret policy") };
    let Some(call) = crate::stat_twin::stat_call(notif.data.nr as i64, &notif.data.args) else { return cont("not a stat call") };
    if !call.answerable {
        return cont("flags the guard does not emulate");
    }
    // An unreadable path: EFAULT / ENAMETOOLONG, answered here as the open
    // path answers it (P0 4d, 2026-10-07): a caller that made itself
    // non-dumpable, whose memory the guard cannot read, never gets the real
    // file's metadata by continuing.
    let raw = match fs_supervisor::tracee::read_path_bytes(notif.pid as i32, call.path) {
        Ok(r) => r,
        Err(e) => {
            answer_errno(listener, notif, e);
            return StatOutcome::Failed { errno: e };
        }
    };
    // P0 4c (2026-10-09): another leaf is resolved too where a symlink (a
    // following stat) or a hard link (a registered file with another link)
    // can reach a registered file under it; the match below is by path and
    // identity, so every such name answers the twin's metadata.
    let probe = crate::stat_twin::stat_probe(index.stat_names.leaf(&raw), call.follow, || index.any_linked(crate::secret_open::file_id));
    if probe == crate::stat_twin::StatProbe::Continue {
        return cont("no name of a registered file");
    }
    let extra = if call.follow { 0 } else { libc::O_NOFOLLOW };
    let Ok(pin) = resolve_opath_as_tracee(listener, notif, call.dirfd, &raw, extra) else { return cont("does not resolve") };
    let entry = file_identity(pin).and_then(|id| {
        let seen = std::fs::read_link(format!("/proc/self/fd/{pin}")).ok().map(|p| p.to_string_lossy().into_owned());
        index.lookup_opened(seen.as_deref().unwrap_or(""), id, crate::secret_open::file_id)
    });
    close_fd(pin);
    let Some(twin) = entry.and_then(crate::stat_twin::stat_twin_of) else { return cont("not a registered file") };
    let Some(bytes) = twin_metadata(twin, call.form) else { return cont("the twin cannot be stat'ed") };
    match write_tracee(listener, notif, call.buf, &bytes) {
        Ok(()) => {
            answer_errno(listener, notif, 0);
            StatOutcome::Twin
        }
        Err(Some(e)) => {
            answer_errno(listener, notif, e);
            StatOutcome::Failed { errno: e }
        }
        // P0 4d: the twin's metadata cannot be written into the caller's
        // buffer (a non-dumpable caller): refused, never continued to the
        // real file's.
        Err(None) => {
            answer_errno(listener, notif, libc::EACCES);
            StatOutcome::Failed { errno: libc::EACCES }
        }
    }
}

/// Plan 13 D4 (2026-10-04): a stat of a descriptor at the twin base
/// (`fstat`, or `newfstatat`/`statx` with `AT_EMPTY_PATH` and an empty
/// path). When the descriptor is a derived twin the guard made
/// (`DerivedIndex::path_of_twin`, by the open file's identity), the answer
/// is the twin's metadata with the `st_dev`/`st_ino` of the derived file it
/// stands for, as the path's own `stat` reports it: a reader that checks the
/// descriptor is the file it named (Claude Code's task-output read-back)
/// accepts the twin. Everything else continues to the kernel. Metadata
/// only: no byte of either file is read or handed over.
pub fn handle_fd_stat_notif(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) -> StatOutcome {
    use std::os::unix::fs::MetadataExt;
    let cont = |why: &'static str| {
        answer_continue(listener, notif);
        StatOutcome::Continued { why }
    };
    let Some(index) = cfg.secrets.as_ref() else { return cont("no secret policy") };
    let Some(call) = crate::stat_twin::fd_stat_call(notif.data.nr as i64, &notif.data.args) else { return cont("not a descriptor stat") };
    if !call.answerable {
        return cont("flags the guard does not emulate");
    }
    if let Some(p) = call.path {
        // AT_EMPTY_PATH with a path: a stat relative to the descriptor.
        match fs_supervisor::tracee::read_path_bytes(notif.pid as i32, p) {
            Ok(b) if b.is_empty() => {}
            _ => return cont("a path relative to the descriptor"),
        }
    }
    let fd_path = format!("/proc/{}/fd/{}", notif.pid, call.fd);
    let Some(twin_id) = std::fs::metadata(&fd_path).ok().map(|m| (m.dev(), m.ino())) else {
        return cont("the descriptor cannot be stat'ed");
    };
    let Some(path) = index.derived.path_of_twin(twin_id) else { return cont("not a derived twin") };
    let Some((dev, ino)) = std::fs::metadata(&path).ok().map(|m| (m.dev(), m.ino())) else {
        return cont("the derived file is gone");
    };
    let Some(bytes) = twin_metadata_with_identity(&fd_path, call.form, dev, ino) else { return cont("the twin cannot be stat'ed") };
    match write_tracee(listener, notif, call.buf, &bytes) {
        Ok(()) => {
            answer_errno(listener, notif, 0);
            StatOutcome::Twin
        }
        Err(Some(e)) => {
            answer_errno(listener, notif, e);
            StatOutcome::Failed { errno: e }
        }
        Err(None) => cont("the tracee's memory is out of reach"),
    }
}

/// The metadata of the open twin (`fd_path`, `/proc/<pid>/fd/<n>`) in the
/// form asked, with the identity `(dev, ino)` of the file it stands for.
fn twin_metadata_with_identity(fd_path: &str, form: crate::stat_twin::StatForm, dev: u64, ino: u64) -> Option<Vec<u8>> {
    let c = std::ffi::CString::new(fd_path).ok()?;
    match form {
        crate::stat_twin::StatForm::Stat => {
            // SAFETY: stat into a zeroed buffer; `c` is NUL-terminated.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            (unsafe { libc::stat(c.as_ptr(), &mut st) } == 0).then(|| crate::stat_twin::stat_bytes(&crate::stat_twin::with_identity(st, dev, ino)))
        }
        crate::stat_twin::StatForm::Statx { mask, sync } => {
            // SAFETY: statx into a zeroed buffer; `c` is NUL-terminated.
            let mut sx: libc::statx = unsafe { std::mem::zeroed() };
            (unsafe { libc::statx(libc::AT_FDCWD, c.as_ptr(), sync, mask, &mut sx) } == 0).then(|| crate::stat_twin::statx_bytes(&crate::stat_twin::with_identity_x(sx, dev, ino)))
        }
    }
}

/// `(dev, ino, links)` of an open REGULAR file, as the secret index compares
/// it; `None` for anything else (a registered secret is a regular file).
fn file_identity(fd: RawFd) -> Option<crate::secret_open::FileId> {
    // SAFETY: fstat into a zeroed stat buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::fstat(fd, &mut st) } == 0;
    if ok { regular_identity(&st) } else { None }
}

/// `file_identity` from a `fstat` the caller already took.
fn regular_identity(st: &libc::stat) -> Option<crate::secret_open::FileId> {
    (st.st_mode & libc::S_IFMT == libc::S_IFREG).then_some(crate::secret_open::FileId { dev: st.st_dev, ino: st.st_ino, links: st.st_nlink as u64, ctime_ns: crate::secret_open::ctime_ns(st.st_ctime, st.st_ctime_nsec) })
}

/// Plan 13 §9 R4 (b), a mount as a destination: `Some((dest, refusal))`
/// when the descriptor `on` (the file, or the directory a create lands in)
/// is on a file system that leaves the machine (`local_exits::
/// mount_verdict`) and what the holder `own` holds is not bound to it
/// (`mount:<fstype>:<source>`, by equality). The arbiter unreachable:
/// refused. A device, a FIFO or a socket opened is no file on the mount.
pub(crate) fn holder_mount_refusal(cfg: &GuardConfig, pid: i32, on: RawFd, own: &str, chain: &[String]) -> Option<(String, TaintedRefusal)> {
    // SAFETY: fstat of a descriptor we hold into a zeroed buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(on, &mut st) } == 0 && matches!(st.st_mode & libc::S_IFMT, libc::S_IFCHR | libc::S_IFBLK | libc::S_IFIFO | libc::S_IFSOCK) {
        return None;
    }
    mount_refusal_on(cfg, pid, on, own, chain)
}

/// Plan 13 §4.9 (2026-10-07): is the raw open the arbiter granted `pid`
/// (`own`) of `file` withheld because a mount that sees lookups is visible
/// in its mount namespace (`visible_mounts`), not trusted for lookups in
/// policy.yaml and not a binding of what the opener would hold? `Some(why)`
/// when it is. The common case (no such mount) costs a `stat` of the
/// namespace and a `poll` of its kept table, no arbiter round trip. A table
/// that cannot be read, or an arbiter that cannot say the bindings,
/// withholds (fail-closed).
pub(crate) fn raw_withheld_by_visible_mount(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex, pid: i32, own: &str, file: &str) -> Option<String> {
    use crate::visible_mounts::{untrusted, withheld_reason, withholding};
    let found = match cfg.mount_views.visible_for(pid, &cfg.extra_remote_devs) {
        Ok(f) => f,
        Err(e) => return Some(format!("{file}: the real file is withheld (the placeholder copy is served): the mounts the reader sees could not be read ({e})")),
    };
    let candidates = untrusted(found, &index.trust_lookups);
    if candidates.is_empty() {
        return None;
    }
    // The arbiter recorded this open's taint before it answered raw, so
    // the bindings it lists now are those of everything the opener would
    // hold, this file's included.
    let (_, chain) = crate::guard_flow::holder(cfg, pid, own);
    let bindings = crate::guard_send::taint_bindings(cfg, own, chain).map(|b| b.bindings);
    let unbound = withholding(&candidates, bindings.as_deref());
    (!unbound.is_empty()).then(|| withheld_reason(file, &unbound))
}

/// The event of a withheld raw open (`raw_withheld_by_visible_mount`).
fn emit_raw_withheld(cfg: &GuardConfig, file: &str, exe: &str, why: &str) {
    let Some(emitter) = &cfg.emitter else { return };
    let ev = crate::events::guard_raw_withheld_event(&cfg.session_id, file, exe, why);
    if let Ok(mut client) = emitter.lock() {
        mandu_arbiter::safe_emit(&mut client, &ev);
    }
}

/// The calling process when it holds a secret (`guard_flow::holder`): its
/// key and chain. Nobody holding one: None at once, no `/proc` read.
pub(crate) fn call_holder(cfg: &GuardConfig, pid: i32) -> Option<(String, Vec<String>)> {
    if cfg.secrets.is_none() || cfg.tainted.is_empty() {
        return None;
    }
    let own = crate::secret_open::own_key_of(pid);
    let (held, chain) = crate::guard_flow::holder(cfg, pid, &own);
    held.then_some((own, chain))
}

/// Plan 13 §9 R4 (b), 2026-10-04: is a name or attribute change by `pid` on
/// the pinned descriptor `on` (the directory a name is made, moved, linked
/// or removed in; the file a truncate, a mode or an attribute changes)
/// refused, the caller holding a secret and `on` being on a mount that
/// leaves the machine its holdings are not bound to? Emits the refusal; the
/// caller answers EACCES. A special file counts here (its inode is on the
/// mount). Not a holder: false, nothing read.
pub(crate) fn holder_change_refused(cfg: &GuardConfig, pid: i32, on: RawFd) -> bool {
    let Some((own, chain)) = call_holder(cfg, pid) else { return false };
    match mount_refusal_on(cfg, pid, on, &own, &chain) {
        None => false,
        Some((dest, refusal)) => {
            crate::guard_send::emit_tainted(cfg, "make or change a name or an attribute on", &dest, &refusal);
            true
        }
    }
}

/// The mount verdict of the descriptor `on` for the holder `own`:
/// `Some((dest, refusal))` when it leaves the machine unbound (or the
/// arbiter cannot say).
fn mount_refusal_on(cfg: &GuardConfig, pid: i32, on: RawFd, own: &str, chain: &[String]) -> Option<(String, TaintedRefusal)> {
    let facts = crate::local_exits::fd_fs_facts(on, Some(pid));
    let crate::local_exits::MountVerdict::Remote(dest) = crate::local_exits::mount_verdict(&facts, &cfg.extra_remote_devs) else { return None };
    match crate::guard_send::taint_bindings(cfg, own, chain.to_vec()) {
        Some(b) if crate::local_exits::mount_bound(&b.bindings, &dest) => None,
        Some(b) => Some((dest, b)),
        None => Some((dest, TaintedRefusal::default())),
    }
}

/// Plan 13 §9 R4 (b): the checks of a holder's write-capable open of `fd`
/// (`st` its fstat), after the open and before the descriptor is handed
/// over: a mount that leaves the machine (`holder_mount_refusal`), a device
/// node that is not the terminal or a sink that keeps nothing, and a file
/// other local users could read, whose group and other bits are stripped
/// now (a mode the guard cannot narrow refuses the open). `Err((dest,
/// refusal, reason))`: refused.
pub(crate) fn holder_written_file(cfg: &GuardConfig, pid: i32, fd: RawFd, st: &libc::stat, own: &str, chain: &[String]) -> std::result::Result<(), (String, TaintedRefusal, String)> {
    let seen = || std::fs::read_link(format!("/proc/self/fd/{fd}")).ok().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let kind = st.st_mode & libc::S_IFMT;
    if kind == libc::S_IFCHR || kind == libc::S_IFBLK {
        let (major, minor) = crate::local_exits::dev_major_minor(st.st_rdev);
        if crate::local_exits::device_write_allowed(kind == libc::S_IFBLK, major, minor) {
            return Ok(());
        }
        let dest = crate::local_exits::device_destination(&seen(), major, minor);
        let why = format!("{dest} is a device: a process holding a secret writes to no device but the terminal and the sinks that keep nothing");
        return Err((dest, TaintedRefusal::default(), why));
    }
    if kind != libc::S_IFREG {
        return Ok(());
    }
    if let Some((dest, refusal)) = holder_mount_refusal(cfg, pid, fd, own, chain) {
        let why = format!("{} is on {dest}, which is not a binding of what the writer holds: the write is refused", seen());
        return Err((dest, refusal, why));
    }
    if let Some(narrow) = crate::local_exits::narrowed_mode(st.st_mode) {
        // SAFETY: fchmod of a descriptor we hold.
        if unsafe { libc::fchmod(fd, narrow as libc::mode_t) } != 0 {
            let file = seen();
            let why = format!("{file} can be read by other local users and its mode could not be narrowed: a process holding a secret may not write it");
            return Err((format!("other local users ({file})"), TaintedRefusal::default(), why));
        }
    }
    Ok(())
}

/// Is the pinned descriptor a derived file (plan 13 D4: a copy a holder
/// wrote)? Err: it may be one and cannot be checked (refuse).
fn pinned_derived(cfg: &GuardConfig, fd: RawFd) -> std::result::Result<bool, ()> {
    let Some(index) = cfg.secrets.as_ref() else { return Ok(false) };
    // SAFETY: fstat of a descriptor we hold into a zeroed buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Ok(false);
    }
    let seen = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    derived_entry(cfg, index, &seen, (st.st_dev, st.st_ino), ctime_ns_of(&st)).map(|e| e.is_some())
}

/// Plan 10, the filesystem exit: a write by a tainted process (or a
/// descendant) labels the file at the taint's level. The request goes
/// BEFORE the writer gets its descriptor (an open the guard performs; the
/// files D5's sweep finds, before the taint lands), so the label is in the
/// derived index before a byte can be written, and no later open of the
/// file can beat it (plan 13 D4). WHO wrote is taken before the answer,
/// `TaintedSet::tainted_writer`. `held`: the identity of the file a sweep
/// found held open for writing, read with its path from the descriptor
/// (`guard_send::HeldWrite`): the index keys the label by that file
/// (`index_resolution`), so a path renamed over in between never moves the
/// label off the file that is written (2026-10-17).
fn label_tainted_write(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex, writer: Option<(String, Vec<String>)>, spelling: Option<String>, held: Option<(u64, u64)>) {
    let (Some(path), Some((own, chain))) = (spelling, writer) else { return };
    let flows_from = crate::guard_flow::flows_from(cfg, &own, &chain);
    if let Some(c) = cfg.emitter.as_ref() {
        let answer = c.lock().ok().and_then(|mut client| {
            client
                .label_written_path_tainted(&mandu_arbiter::protocol::LabelWrittenPathTaintedArgs {
                    path: path.clone(),
                    proc_key: own,
                    ancestors: if chain.is_empty() { None } else { Some(chain) },
                    session: index.session.clone(),
                    flows_from,
                })
                .ok()
        });
        // Confidentiality plan 13 D4: the labelled file joins the guard's
        // live index at once, so the next open of it is gated.
        if let Some(a) = answer.filter(|a| a.labeled) {
            index.derived.insert(&path, &a.level, crate::derived_index::held_resolution(resolve_for_index(&path), held));
        }
    }
}

/// Plan 13 §9 R1: the files the receivers of a channel joined after a
/// holder's taint already hold open for writing (`guard_send::sweep_receivers`)
/// take the label now, as the sweep's files do at a raw open (D5).
pub(crate) fn label_held_writes(cfg: &GuardConfig, writes: Vec<crate::guard_send::HeldWrite>) {
    let Some(index) = cfg.secrets.as_ref() else { return };
    for w in writes {
        label_tainted_write(cfg, index, Some((w.own, w.chain)), Some(w.path), w.id);
    }
}

// ── confidentiality plan 13 D4: derived labels at the program gate ──────────

/// A path's canonical spelling and identity now, for the derived index.
fn resolve_for_index(path: &str) -> crate::derived_index::Resolved {
    let canon = std::fs::canonicalize(path).ok().and_then(|p| p.to_str().map(String::from));
    (canon, crate::secret_open::file_id(path).map(|i| i.key()))
}

/// The `st_mode` of what a descriptor names (an `O_PATH` one included); 0
/// when it cannot be read (no file type: no stand-in).
fn fd_mode(fd: RawFd) -> u32 {
    // SAFETY: fstat into a zeroed stat buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } == 0 { st.st_mode } else { 0 }
}

/// A stat's ctime as ns since the epoch.
fn ctime_ns_of(st: &libc::stat) -> i128 {
    st.st_ctime as i128 * 1_000_000_000 + st.st_ctime_nsec as i128
}

/// Read what changed in the arbiter's derived labels into the index
/// (`derivedLabelsSince`). Err: the arbiter could not be asked.
fn refresh_derived(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex) -> std::result::Result<(), ()> {
    let started = crate::secret_open::now_ns();
    let (epoch, since) = index.derived.cursor();
    let answer = cfg.emitter.as_ref().and_then(|c| c.lock().ok()).and_then(|mut client| {
        client.derived_labels_since(&mandu_arbiter::protocol::DerivedLabelsSinceArgs { epoch, since: Some(since) }).ok()
    });
    match answer {
        Some(Some(r)) => {
            let rows: Vec<(String, String)> = r.labels.into_iter().map(|l| (l.path, l.level)).collect();
            index.derived.apply(started, &r.epoch, r.gen, &rows, resolve_for_index);
            Ok(())
        }
        Some(None) => {
            // An arbiter older than this guard: it cannot list its derived
            // labels, so the guard gates the ones it mints itself (the
            // pre-2026-10-02 behaviour for the rest). Said once.
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| crate::diag!("mandu-net-guard: the arbiter cannot list derived labels (older than this guard); only the copies this guard labels are gated at the open"));
            index.derived.apply(started, "unsupported", 0, &[], resolve_for_index);
            Ok(())
        }
        None => {
            index.derived.note_failure(started);
            Err(())
        }
    }
}

/// Ask the arbiter to label `to` with the derived label of `from` (`how`:
/// rename | link | identity), and add `to` to the index. Err: not recorded.
fn follow_derived(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex, from: &str, to: &str, how: &str) -> std::result::Result<(), ()> {
    let answer = cfg.emitter.as_ref().and_then(|c| c.lock().ok()).and_then(|mut client| {
        client
            .follow_derived_label(&mandu_arbiter::protocol::FollowDerivedLabelArgs {
                from: from.to_string(),
                to: to.to_string(),
                how: how.to_string(),
                session: index.session.clone(),
            })
            .ok()
    });
    match answer {
        Some(a) if a.labeled => {
            index.derived.insert(to, a.level.as_deref().unwrap_or("no-model"), resolve_for_index(to));
            Ok(())
        }
        _ => Err(()),
    }
}

/// Plan 13 D4: the derived label covering a regular file the guard resolved
/// (`seen`: the path its descriptor names; `id`; `ctime_ns`), as an entry to
/// gate like a labelled file with no reader list. Ok(None): not derived (or
/// no arbiter, so no label can be minted this session). Err: unknown and the
/// file changed since the guard started, or the label could not follow it
/// to this name: refuse (fail-closed).
fn derived_entry(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex, seen: &str, id: (u64, u64), ctime_ns: i128) -> std::result::Result<Option<crate::secret_open::SecretEntry>, ()> {
    if cfg.emitter.is_none() || seen.is_empty() {
        return Ok(None);
    }
    let mut hit = index.derived.hit(seen, Some(id));
    if hit.is_none() && index.derived.stale_for(ctime_ns) {
        let fresh = index.derived.fresh_since_start(ctime_ns);
        let refreshed = if index.derived.backing_off(crate::secret_open::now_ns()) { Err(()) } else { refresh_derived(cfg, index) };
        match refreshed {
            Ok(()) => hit = index.derived.hit(seen, Some(id)),
            Err(()) if fresh => return Err(()),
            Err(()) => return Ok(None),
        }
    }
    let Some((label, level)) = hit else { return Ok(None) };
    // The path the arbiter knows the label by: the label's own, when `seen`
    // is it or another spelling of it; else this is the same file under
    // another name (a rename or a hard link the guard did not perform), and
    // the label follows it here before it is served.
    let path = if index.derived.names(&label, seen) {
        label
    } else {
        follow_derived(cfg, index, &label, seen, "identity")?;
        seen.to_string()
    };
    Ok(Some(crate::secret_open::SecretEntry { path, twin: String::new(), level, kind: Some("derived".into()) }))
}

/// The refusal of an open whose label cannot be checked.
const UNCHECKED_LABEL: &str = "a file that may carry a label that cannot be checked (the arbiter is unreachable): refused";

/// Plan 13 D4 and 2026-10-17: the entry a reading open of a regular file the
/// launch did not register is gated under: a derived file's
/// (`derived_entry`), else a labelled file's (`labelled_entry`). `pid`: the
/// opener, when there is one (the agent's own reads are not gated by a
/// label, `labelled_entry`). Err: it may be one and cannot be checked
/// (refuse).
fn gated_entry(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex, pid: Option<i32>, seen: &str, id: (u64, u64), ctime_ns: i128, nlink: u64) -> std::result::Result<Option<crate::secret_open::SecretEntry>, ()> {
    // The label first (2026-10-17): a labelled file's twin is recorded for
    // the session-end notice (`derived_twin`), and a hard link of one made
    // in the session is also a derived file (its label followed).
    match labelled_entry(cfg, index, pid, seen, id, ctime_ns, nlink)? {
        Some(e) => Ok(Some(e)),
        None => derived_entry(cfg, index, seen, id, ctime_ns),
    }
}

/// Read the arbiter's label roots into the index (`labelRootsSince`). Err:
/// the arbiter could not be asked (the last list stays in force).
fn refresh_labels(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex) -> std::result::Result<(), ()> {
    let started = crate::secret_open::now_ns();
    let key = index.labels.key();
    // The session names the launch HOME whose catalog places the arbiter
    // lists too (2026-10-17).
    let args = mandu_arbiter::protocol::LabelRootsSinceArgs { key, session: index.session.clone() };
    let answer = cfg.emitter.as_ref().and_then(|c| c.lock().ok()).and_then(|mut client| client.label_roots_since(&args).ok());
    match answer {
        Some(Some(r)) => {
            let roots = r
                .roots
                .into_iter()
                .map(|x| crate::label_index::Root { path: x.path, shape: x.shape.map(|s| crate::label_index::Shape { head: s.head, tail: s.tail, exact: s.exact }) })
                .collect();
            let catalog = r.catalog.map(|c| crate::label_index::Catalog {
                names: c.names.into_iter().map(|a| crate::label_index::NameAnchor { exact: a.exact, prefix: a.prefix, suffix: a.suffix, contains: a.contains, not_suffixes: a.not_suffixes, ci: a.ci }).collect(),
                homes: c.homes,
                skip: c.skip_dirs.into_iter().collect(),
            });
            index.labels.apply(started, &r.key, r.unchanged, roots, r.skip_dirs, catalog);
            Ok(())
        }
        Some(None) => {
            // An arbiter older than this guard: it lists no label roots, so
            // the guard gates the registered and derived files only (the
            // behaviour before 2026-10-17). Said once.
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| crate::diag!("mandu-net-guard: the arbiter cannot list its label roots (older than this guard); a labelled file the launch did not register is not gated at the open"));
            index.labels.apply(started, "unsupported", false, Vec::new(), Vec::new(), None);
            Ok(())
        }
        None => {
            index.labels.note_failure(started);
            Err(())
        }
    }
}

/// 2026-10-17 (confidentiality.md §6, "Read by a program the launch did not
/// see"): the human label covering a regular file the launch did not
/// register (`seen`: the path its descriptor names; `id`; `ctime_ns`), as an
/// entry to gate like a derived file: the twin made on demand (its
/// `registerSecret` registers the file, so the value backstop knows its
/// values), the real file for a reader the human named. Only a file under a
/// label root (`label_index`) costs a round trip; its level is cached per
/// file state and label set. The agent's own process is not gated here: its
/// reads reach the model through its tool's result, which the model proxy
/// classifies by the path the tool names (the label's own place), as before.
/// A path under no root is still gated when it is another name of a file
/// gated by its label (`nlink`, its link count; `other_name_level`).
/// The same for a file the secret catalog names (2026-10-17): its prefixes
/// are roots, its basename shapes the index's name prefilter, and the
/// arbiter's level is the walk's verdict on it.
/// Ok(None): no label covers it (or no arbiter, or one that lists no roots).
/// Err: under a root and the arbiter cannot classify it: refuse
/// (fail-closed).
fn labelled_entry(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex, pid: Option<i32>, seen: &str, id: (u64, u64), ctime_ns: i128, nlink: u64) -> std::result::Result<Option<crate::secret_open::SecretEntry>, ()> {
    if cfg.emitter.is_none() || seen.is_empty() {
        return Ok(None);
    }
    if index.labels.due(crate::secret_open::now_ns()) {
        // A failure keeps the last list read (none: nothing is gated, as
        // before the change).
        let _ = refresh_labels(cfg, index);
    }
    let is_agent = || pid.map(|p| crate::guard_flow::is_agent_pid(cfg, p)).unwrap_or(false);
    if !index.labels.candidate(seen) {
        // 2026-10-17: another name of a file gated by its label (a hard
        // link outside every root), as that file (`other_name_level`).
        let Some(level) = index.labels.other_name_level(id, nlink) else { return Ok(None) };
        if is_agent() {
            return Ok(None);
        }
        return Ok(Some(crate::secret_open::SecretEntry { path: seen.to_string(), twin: String::new(), level, kind: Some("labelled".into()) }));
    }
    if is_agent() {
        // 2026-10-17 (confidentiality.md §6, "The base follows the shell"):
        // the agent's own open stays ungated, and is recorded at the arbiter
        // (`agent_open_record`) so the file tool that named this file by a
        // relative path is classified at the file the kernel opened.
        return agent_open_record(cfg, index, seen, id, ctime_ns).map(|()| None);
    }
    let level = match index.labels.cached(id, ctime_ns) {
        Some(l) => l,
        None => {
            let answer = cfg.emitter.as_ref().and_then(|c| c.lock().ok()).and_then(|mut client| {
                client.labelled_level(&mandu_arbiter::protocol::LabelledLevelArgs { path: seen.to_string(), session: index.session.clone(), agent_open: None }).ok()
            });
            match answer {
                Some(Some(r)) => {
                    index.labels.remember(id, ctime_ns, &r.key, &r.level);
                    r.level
                }
                // An arbiter that listed roots but cannot classify: refuse.
                Some(None) | None => return Err(()),
            }
        }
    };
    let gated = crate::label_index::gated_level(&level);
    index.labels.note_gated(id, &level, gated);
    if !gated {
        return Ok(None);
    }
    Ok(Some(crate::secret_open::SecretEntry { path: seen.to_string(), twin: String::new(), level, kind: Some("labelled".into()) }))
}

/// 2026-10-17 (confidentiality.md §6, "The base follows the shell"): the
/// AGENT process itself opens `seen`, a file under a label root, for
/// reading. Its read is not gated (its tool's result is classified at the
/// model door), but that classify only has the path the tool NAMES, and a
/// relative one (Claude Code's `Read {file_path: "plan.md"}`) is resolved by
/// the agent against its own directory, which a `cd` in an earlier `Bash`
/// call or EnterWorktree moved and which no request names. So the open is
/// reported (`labelledLevel` with `agentOpen`): the arbiter records a file
/// above `public` and reads the tool's relative value at it, raise-only.
/// A file the arbiter already called `public` in this state costs nothing.
/// Err: the report could not be made (the arbiter is unreachable): the open
/// is refused, as an unchecked label's is (fail-closed). An older arbiter
/// (`unknown op`, or one that ignores the flag) answers as before.
fn agent_open_record(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex, seen: &str, id: (u64, u64), ctime_ns: i128) -> std::result::Result<(), ()> {
    if !crate::label_index::agent_open_reported(index.labels.cached(id, ctime_ns).as_deref()) {
        return Ok(());
    }
    let answer = cfg.emitter.as_ref().and_then(|c| c.lock().ok()).map(|mut client| {
        client
            .labelled_level(&mandu_arbiter::protocol::LabelledLevelArgs { path: seen.to_string(), session: index.session.clone(), agent_open: Some(true) })
            .ok()
    });
    match crate::label_index::agent_open_answer(answer) {
        crate::label_index::AgentOpenAnswer::Level(r) => {
            index.labels.remember(id, ctime_ns, &r.key, &r.level);
            Ok(())
        }
        crate::label_index::AgentOpenAnswer::Older => Ok(()),
        crate::label_index::AgentOpenAnswer::Unanswered => Err(()),
    }
}

/// `gated_entry` for a path the guard did not open (an `O_PATH` open it
/// lets run): the file it names now, a regular file only (`nofollow`: a
/// final symlink is a name of its own).
fn derived_entry_by_path(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex, pid: Option<i32>, path: &str, nofollow: bool) -> std::result::Result<Option<crate::secret_open::SecretEntry>, ()> {
    use std::os::unix::fs::MetadataExt;
    let md = if nofollow { std::fs::symlink_metadata(path) } else { std::fs::metadata(path) };
    let Ok(md) = md else { return Ok(None) };
    if !md.is_file() {
        return Ok(None);
    }
    let real = if nofollow {
        path.to_string()
    } else {
        std::fs::canonicalize(path).ok().and_then(|p| p.to_str().map(String::from)).unwrap_or_else(|| path.to_string())
    };
    gated_entry(cfg, index, pid, &real, (md.dev(), md.ino()), md.ctime() as i128 * 1_000_000_000 + md.ctime_nsec() as i128, md.nlink())
}

/// Plan 13 D4: the twin of a derived file, made from the arbiter's
/// `registerSecret` (the arbiter reads the file; its bytes never pass here)
/// in the launch's `derived-twins/` directory, remade when the file changes.
/// An empty file's twin is empty. None: no twin (refuse).
///
/// 2026-10-17, a `labelled` file's twin (the launch did not register it):
/// a write a program makes through the gate lands in the twin, as a
/// registered file's does, so the session's end names the file
/// (`TWIN_RECORDS`, launcher twin-writes.ts). Its twin is never made over an
/// earlier one (a remade twin takes the next free name,
/// `label_index::twin_name_candidates`: a change already in the old copy
/// stays there to be named), and each one made is recorded: the twin's size,
/// hash and identity, the real file's identity (no size, no hash). A twin
/// whose record cannot be written is still served: the record only words
/// the notice.
fn derived_twin(cfg: &GuardConfig, index: &crate::secret_open::SecretIndex, path: &str, labelled: bool) -> Option<String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let md = std::fs::metadata(path).ok()?;
    let marked_ns = crate::secret_open::now_ns();
    let key = crate::derived_index::TwinKey { dev: md.dev(), ino: md.ino(), size: md.size(), mtime_ns: md.mtime() as i128 * 1_000_000_000 + md.mtime_nsec() as i128 };
    if let Some(t) = index.derived.cached_twin(path, &key) {
        return Some(t);
    }
    let content = if md.size() == 0 {
        String::new()
    } else {
        let r = cfg.emitter.as_ref()?.lock().ok()?.register_secret(path).ok()?;
        match (r.twin, r.symbol) {
            // A twin the arbiter rendered (structured, or a file that holds
            // only the name of an existing directory, plan 13 D4: no symbol).
            (Some(t), _) => t,
            (None, Some(symbol)) => crate::derived_index::whole_file_twin_text(&symbol, r.terminator.as_deref()),
            (None, None) => return None,
        }
    };
    let dir = index.policy_dir.as_ref()?.join("derived-twins");
    std::fs::create_dir_all(&dir).ok()?;
    // The guard writes here as the user, outside every sandbox: a symlink
    // planted for the directory or the temporary name must not redirect
    // the write (the directory must be one, the file is created anew).
    if !std::fs::symlink_metadata(&dir).map(|m| m.file_type().is_dir()).unwrap_or(false) {
        return None;
    }
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    let name = crate::derived_index::twin_file_name(path);
    let tmp = dir.join(format!(".{name}.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp).ok()?;
        f.write_all(content.as_bytes()).ok()?;
    }
    let twin = if labelled {
        // A new name, never over an earlier twin (`link` does not replace).
        let mut made = None;
        for n in crate::label_index::twin_name_candidates(&name) {
            let at = dir.join(&n);
            match std::fs::hard_link(&tmp, &at) {
                Ok(()) => {
                    made = Some(at);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => break,
            }
        }
        let _ = std::fs::remove_file(&tmp);
        made?
    } else {
        let twin = dir.join(&name);
        std::fs::rename(&tmp, &twin).ok()?;
        twin
    };
    let twin_md = std::fs::symlink_metadata(&twin).ok();
    if let Some(t) = twin_md.as_ref() {
        index.derived.note_twin_identity((t.dev(), t.ino()), path);
    }
    let twin = twin.to_str()?.to_string();
    if labelled {
        if let Some(t) = twin_md.as_ref() {
            use sha2::{Digest, Sha256};
            let sha256: String = Sha256::digest(content.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
            let rec = crate::label_index::TwinRecord {
                target: path.to_string(),
                twin: twin.clone(),
                sha256,
                size: content.len() as u64,
                twin_id: (t.dev(), t.ino()),
                real_id: (md.dev(), md.ino()),
                real_mtime_ns: key.mtime_ns,
                real_ctime_ns: md.ctime() as i128 * 1_000_000_000 + md.ctime_nsec() as i128,
                marked_ns,
            };
            record_labelled_twin(&dir, &rec);
        }
    }
    index.derived.set_twin(path, key, twin.clone());
    Some(twin)
}

/// Append `rec` to the launch's `TWIN_RECORDS` (a regular file of one link,
/// never through a symlink: `git_lock::open_notice`). Best effort: one
/// `write` of one line, under a lock so two threads' lines never interleave.
fn record_labelled_twin(dir: &std::path::Path, rec: &crate::label_index::TwinRecord) {
    static RECORDS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _held = RECORDS.lock().unwrap_or_else(|p| p.into_inner());
    let Some(file) = dir.join(crate::label_index::TWIN_RECORDS).to_str().and_then(crate::git_lock::open_notice) else { return };
    use std::io::Write;
    let _ = (&file).write_all(crate::label_index::twin_record_line(rec).as_bytes());
}

/// Plan 13 D4: before a performed rename or hard link, the label of a derived
/// source follows it to the new name (the arbiter records it before the
/// change runs, so the next launch's discovery finds the file under its new
/// name). `from_pin`/`from_leaf` name the source, `to_pin`/`to_leaf` the new
/// name. Err(errno): the label could not follow, so the change is refused.
fn derived_follows(cfg: &GuardConfig, from_pin: RawFd, from_leaf: &[u8], to_pin: RawFd, to_leaf: &[u8], how: &str) -> std::result::Result<(), i32> {
    let Some(index) = cfg.secrets.as_ref() else { return Ok(()) };
    if cfg.emitter.is_none() {
        return Ok(());
    }
    let dir_of = |pin: RawFd| std::fs::read_link(format!("/proc/self/fd/{pin}")).ok().and_then(|p| p.to_str().map(String::from));
    let (Some(from_dir), Some(to_dir)) = (dir_of(from_pin), dir_of(to_pin)) else { return Ok(()) };
    let join = |d: &str, leaf: &[u8]| format!("{}/{}", d.trim_end_matches('/'), String::from_utf8_lossy(leaf));
    let (from, to) = (join(&from_dir, from_leaf), join(&to_dir, to_leaf));
    // The source as it is now: a regular file (a symlink renamed moves no bytes).
    let Some(fd) = open_leaf(from_pin, from_leaf, how == "link") else { return Ok(()) };
    // SAFETY: fstat into a zeroed stat buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::fstat(fd, &mut st) } == 0 && st.st_mode & libc::S_IFMT == libc::S_IFREG;
    close_fd(fd);
    if !ok {
        return Ok(());
    }
    // 2026-10-17: a labelled file the launch did not register too: its
    // label follows it out from under the label (`followDerivedLabel`
    // carries a protected file's own level, server.ts).
    match gated_entry(cfg, index, None, &from, (st.st_dev, st.st_ino), ctime_ns_of(&st), st.st_nlink as u64) {
        Ok(None) => Ok(()),
        // `e.path`: the name the arbiter knows the label by.
        Ok(Some(e)) => follow_derived(cfg, index, &e.path, &to, how).map_err(|_| libc::EACCES),
        Err(()) => Err(libc::EACCES),
    }
}

/// 2026-10-16: what a FOLDER rename carries: each `(label path, new path)`
/// for every derived copy and every registered protected file below the
/// folder (`DerivedIndex::under`, `SecretIndex::protected_under`, mapped by
/// `inode_pins::moved_path`). Computed before the rename; the labels are
/// asked for only after it succeeded (`label_follows`), so a refused or
/// undone rename leaves none behind. The derived list is read afresh first
/// (labels minted in an earlier session): an arbiter that cannot be read
/// refuses the rename. Not a folder: nothing.
///
/// Fail closed on spelling (review of !1603): the paths are matched as text,
/// in the guard's view (`/proc/self/fd` of the pinned parents). When that
/// text does not name the same folder the tracee pinned (a bind visible only
/// in the sandbox's mount namespace), or the destination's parent, and the
/// folder holds a registered file or a derived copy (by identity: the
/// folder is an ancestor of one), the rename is refused; with nothing below
/// it, it runs and carries nothing.
fn dir_follows(cfg: &GuardConfig, from_pin: RawFd, from_leaf: &[u8], to_pin: RawFd, to_leaf: &[u8]) -> std::result::Result<Vec<(String, String)>, i32> {
    let Some(index) = cfg.secrets.as_ref() else { return Ok(Vec::new()) };
    if !leaf_is_dir(from_pin, from_leaf) {
        return Ok(Vec::new());
    }
    use std::os::unix::fs::MetadataExt;
    let ident = |p: &str| std::fs::symlink_metadata(p).ok().map(|m| (m.dev(), m.ino()));
    let (from, to) = (pinned_path(from_pin, from_leaf), pinned_path(to_pin, to_leaf));
    let dir_id = leaf_identity(from_pin, from_leaf);
    let to_parent_id = {
        // SAFETY: fstat into a zeroed stat buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        (unsafe { libc::fstat(to_pin, &mut st) } == 0).then_some((st.st_dev, st.st_ino))
    };
    let spelled = match (&from, &to) {
        (Some(f), Some(t)) => {
            let t_parent = std::path::Path::new(t).parent().and_then(|p| p.to_str()).unwrap_or("/");
            dir_id.is_some() && ident(f) == dir_id && to_parent_id.is_some() && ident(t_parent) == to_parent_id
        }
        _ => false,
    };
    if cfg.emitter.is_some() && refresh_derived(cfg, index).is_err() {
        return Err(libc::EACCES);
    }
    if !spelled {
        let mut below: Vec<String> = index.protected_under("/");
        below.extend(index.derived.under("/").into_iter().map(|(_, p)| p));
        // Fail closed as `unpinned_hit` does: a listed file (or a folder
        // above it) whose identity cannot be read counts as held below. A
        // listed path with nothing there (ENOENT: a file since moved or
        // removed) cannot lie below the folder and is left out.
        below.retain(|p| !matches!(std::fs::symlink_metadata(p), Err(e) if e.kind() == std::io::ErrorKind::NotFound));
        let holds = match dir_id {
            None => true,
            Some(d) => !matches!(crate::secret_open::protected_hit_by_ids_strict(&below, Some(d), &[], |p: &str| ident(p)), Ok(None)),
        };
        return if holds { Err(libc::EACCES) } else { Ok(Vec::new()) };
    }
    let (Some(from), Some(to)) = (from, to) else { return Err(libc::EACCES) };
    let mut carried: Vec<(String, String, String)> = index.derived.under(&from).into_iter().filter_map(|(label, below)| crate::inode_pins::moved_path(&below, &from, &to).map(|d| (label, below, d))).collect();
    carried.extend(index.protected_under(&from).into_iter().filter_map(|p| crate::inode_pins::moved_path(&p, &from, &to).map(|d| (p.clone(), p, d))));
    // Only what is there now moves (a registered path whose file already left
    // carries nothing). A registered file going back to its own registered
    // path (an exchange the agent reverses) needs no label there: it IS that
    // entry, by its held inode. Anything else that would land on a
    // registered path refuses the rename here, BEFORE it runs (review of
    // !1603): an undo after the fact can be made to fail by the agent (an
    // untrapped mkdir of the old name), which would leave one registered
    // file's bytes under another's path.
    let mut out = Vec::new();
    for (label, below, dest) in carried {
        // Only ENOENT means nothing is there to move; any other error (an
        // intermediate folder the agent chmod-ed) cannot be told apart from a
        // file that moves: refused (third review of !1603).
        match crate::inode_pins::carried_present(std::fs::symlink_metadata(&below).map(|_| ())) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(()) => return Err(libc::EACCES),
        }
        if index.is_held_at_home(&below, &dest) {
            continue;
        }
        if index.is_registered(&dest) {
            return Err(libc::EACCES);
        }
        out.push((label, dest));
    }
    Ok(out)
}

/// Ask the arbiter to label each new path (`followDerivedLabel`, "rename"),
/// AFTER the rename ran: `false` when one could not (the caller undoes the
/// rename). No arbiter at all (no label is minted this session; the pins
/// cover it): nothing to ask, `true`.
///
/// Every label is asked, a failure does not stop the rest (review of !1603):
/// the ones that could not be recorded are returned, the rest stand. So a
/// rename undone for one failure can leave the others' labels on paths it
/// vacated: a derived row by reference to the moved file, which only makes a
/// later file at that path stricter, never looser (`DerivedLabelStore.raise`).
fn label_follows(cfg: &GuardConfig, follows: &[(String, String)]) -> Vec<(String, String)> {
    let Some(index) = cfg.secrets.as_ref() else { return Vec::new() };
    if cfg.emitter.is_none() {
        return Vec::new();
    }
    follows.iter().filter(|(from, to)| follow_derived(cfg, index, from, to, "rename").is_err()).cloned().collect()
}

/// The guard's tree (itself, the tree roots and every descendant, threads
/// included, through `/proc/<p>/task/<t>/children`) with each task's
/// numbers per pid-namespace level (`NSpid`, outermost first).
fn tree_tasks_ns(cfg: &GuardConfig) -> Vec<(i32, Vec<i32>)> {
    use fs_supervisor::tracee::{read_proc_small, status_values};
    // SAFETY: getpid has no failure mode.
    let mut todo: Vec<i32> = vec![unsafe { libc::getpid() }];
    todo.extend(cfg.tree_roots.iter().copied());
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    while let Some(p) = todo.pop() {
        if seen.len() > 8192 || !seen.insert(p) {
            continue;
        }
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{p}/task")) else { continue };
        for t in tasks.flatten() {
            let Some(tid) = t.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
            let levels = read_proc_small(&format!("/proc/{p}/task/{tid}/status"))
                .and_then(|st| status_values(&st, "NSpid").and_then(|v| v.iter().map(|x| x.parse().ok()).collect::<Option<Vec<i32>>>()));
            if let Some(levels) = levels {
                out.push((tid, levels));
            }
            if let Some(ch) = read_proc_small(&format!("/proc/{p}/task/{tid}/children")) {
                todo.extend(ch.split_whitespace().filter_map(|c| c.parse::<i32>().ok()));
            }
        }
    }
    out
}

/// The host pids a `/proc/<n>/…` path names for §4.1. `dev`: the opened
/// procfs file's device (None: not opened; the tracee's `/proc/<n>` is
/// looked at). On the guard's own procfs the number is the host's; on
/// another (the whole-agent wrap's `--unshare-pid` mount) it is translated
/// through the tree, by start time where that procfs is reachable in the
/// tracee's view, else every match (the caller refuses if any is tainted).
fn procfs_targets(cfg: &GuardConfig, tracee: i32, n: i32, dev: Option<u64>) -> Vec<i32> {
    use fs_supervisor::tracee::{openat2, read_proc_small, OpenHow};
    static HOST_PROC_DEV: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    let host_dev = *HOST_PROC_DEV.get_or_init(|| {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc").ok().map(|m| m.dev())
    });
    if dev.is_some() && dev == host_dev {
        return vec![n];
    }
    // The tracee's own `/proc/<n>`: its device, and the start time it shows.
    let seen: Option<(u64, Option<u64>)> = (|| {
        let root = std::ffi::CString::new(format!("/proc/{tracee}/root")).ok()?;
        // SAFETY: open with a NUL-terminated path; returns an fd or -1.
        let rootfd = unsafe { libc::open(root.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if rootfd < 0 {
            return None;
        }
        let how = OpenHow { flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64, mode: 0, resolve: libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_SYMLINKS };
        let d = std::ffi::CString::new(format!("proc/{n}")).ok().and_then(|c| openat2(rootfd, &c, &how).ok());
        unsafe { libc::close(rootfd) };
        let d = d?;
        let id = fd_identity(d).map(|(dev, _)| dev);
        let start = read_proc_small(&format!("/proc/self/fd/{d}/stat")).as_deref().and_then(mandu_arbiter::proc::parse_starttime_from_stat);
        unsafe { libc::close(d) };
        Some((id?, start))
    })();
    let procfs_dev = dev.or(seen.map(|(d, _)| d));
    if procfs_dev.is_some() && procfs_dev == host_dev {
        return vec![n];
    }
    let start = seen.filter(|(d, _)| Some(*d) == procfs_dev).and_then(|(_, s)| s);
    let same = |h: i32| match start {
        Some(s) => read_proc_small(&format!("/proc/{h}/stat")).as_deref().and_then(mandu_arbiter::proc::parse_starttime_from_stat) == Some(s),
        None => true,
    };
    crate::secret_open::host_pids_named(n, None, &tree_tasks_ns(cfg), same)
}

/// §4.1 (exec-routing.md §7.5, 2026-10-02): the first of `targets` (host
/// pids a `/proc/<n>` or a `ptrace` / `process_vm_*` target names) whose
/// introspection by `opener` (a thread) is refused, or None. The opener may
/// read a tainted target only when it carries every taint the target does
/// (`secret_open::introspection_allowed`). Before, any tainted opener
/// was exempt: a holder of one secret read another holder's environment or
/// memory and the guard never learned that flow.
fn introspection_refused(cfg: &GuardConfig, opener: i32, targets: &[i32]) -> Option<i32> {
    use crate::secret_open::{introspection_allowed, own_key_of, tgid_of};
    let me = tgid_of(opener);
    let mut mine: Option<Vec<String>> = None;
    for t in targets {
        let tg = tgid_of(*t);
        if tg == me {
            continue;
        }
        // Both sides as the set records them (own reads, parents, the
        // flows recorded at the sweeps and at the processes' own events).
        // Never a descriptor look here (`guard_flow::holder`): it RECORDS
        // what it finds, and a target may be any process, the guard's own
        // included, whose pipe ends would make it, and through it the whole
        // tree, a holder (2026-10-02, found in the VM: the test process that
        // made the pipes became one, and `ps` below it read the holder).
        if !cfg.tainted.pid_tainted(tg) {
            continue;
        }
        let key = own_key_of(tg);
        let sources = mine.get_or_insert_with(|| {
            let own = own_key_of(me);
            if cfg.tainted.pid_tainted(me) { cfg.tainted.taint_sources(&own) } else { Vec::new() }
        });
        if !introspection_allowed(me, sources, tg, true, &cfg.tainted.taint_sources(&key)) {
            return Some(*t);
        }
    }
    None
}

/// §4.1: `ptrace(req, pid, …)` / `process_vm_readv(pid, …)`: the target pid is
/// arg 1 for ptrace, arg 0 for process_vm_*. A tainted target and a caller
/// that does not carry all of its taint ⇒ EPERM (the way a sibling would
/// read a sourced key out of a tainted shell's memory;
/// `introspection_refused`). Its own process, an untainted target, or a
/// caller that already carries the target's taint (a tainted shell's strace
/// of its child) ⇒ CONTINUE.
pub fn handle_introspect_notif(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) {
    let nr = notif.data.nr as libc::c_long;
    let caller = notif.pid as i32;
    let target = if nr == libc::SYS_ptrace { notif.data.args[1] as i32 } else { notif.data.args[0] as i32 };
    // The target is a number in the CALLER's pid namespace (the whole-agent
    // wrap's, under `--unshare-pid`): translated to host pids first.
    let hosts = || {
        let depth = fs_supervisor::tracee::tracee_levels(caller).map(|l| l.len().saturating_sub(1)).unwrap_or(0);
        if depth == 0 { vec![target] } else { crate::secret_open::host_pids_named(target, Some(depth), &tree_tasks_ns(cfg), |_| true) }
    };
    // supported-agents.md §2.3.1 (`own_server`): the private server's client
    // is the one process that may reach the server, so no other process may
    // trace it or read or write its memory (which would let it connect in
    // the client's name, whatever Yama's ptrace scope). Its own threads may.
    if target > 0 && cfg.own_server.is_some() {
        let clients = crate::guard_flow::own_server_clients(cfg);
        let me = crate::secret_open::own_key_of(caller);
        let targets: Vec<String> = hosts().iter().map(|h| crate::secret_open::own_key_of(*h)).collect();
        if crate::own_server::introspection_refused(&clients, &me, &targets) {
            answer_errno(listener, notif, libc::EPERM);
            return;
        }
    }
    if target > 0 && cfg.secrets.is_some() && !cfg.tainted.is_empty() {
        let hosts = hosts();
        if introspection_refused(cfg, caller, &hosts).is_some() {
            answer_errno(listener, notif, libc::EPERM);
            return;
        }
    }
    answer_continue(listener, notif);
}

/// Plan 13 §4.9 (2026-10-02): a signal with a payload (`guard_signals::
/// payload_aim`) from a holder to a process that holds no secret: refused
/// (EPERM). Eight caller-chosen bytes per signal, thousands of signals a
/// second: the one signal interface built to carry data. To the holder
/// itself or another holder it goes on; by pidfd it is refused whatever the
/// descriptor names (a `dup2` could swap it after the look). The target's
/// number is the caller's pid namespace's, translated as `ptrace`'s is.
pub(crate) fn payload_signal_refused(cfg: &GuardConfig, nr: i64, args: &[u64; 6], caller: i32) -> bool {
    if cfg.secrets.is_none() || cfg.tainted.is_empty() {
        return false;
    }
    let Some(aim) = crate::guard_signals::payload_aim(nr, args) else { return false };
    let own = crate::secret_open::own_key_of(caller);
    if !crate::guard_flow::holder(cfg, caller, &own).0 {
        return false;
    }
    let refused = match aim {
        crate::guard_signals::PayloadAim::Fd => true,
        crate::guard_signals::PayloadAim::Tgid(t) if t <= 0 => false,
        crate::guard_signals::PayloadAim::Tgid(t) => {
            let depth = fs_supervisor::tracee::tracee_levels(caller).map(|l| l.len().saturating_sub(1)).unwrap_or(0);
            let hosts = if depth == 0 { vec![t] } else { crate::secret_open::host_pids_named(t, Some(depth), &tree_tasks_ns(cfg), |_| true) };
            let me = crate::secret_open::tgid_of(caller);
            // No process of that number in view: the kernel answers ESRCH.
            hosts.iter().any(|h| crate::secret_open::tgid_of(*h) != me && !cfg.tainted.pid_tainted(*h))
        }
    };
    if refused {
        crate::guard_send::emit_tainted(cfg, "signal with a payload", "a process that holds no secret", &TaintedRefusal::default());
    }
    refused
}

/// Plan 10 §4.2: an exec in the agent tree. The argv is read while the tracee
/// is suspended (its image is replaced once the exec proceeds), the exec is
/// CONTINUEd at once, and the arbiter learns the (child, parent, signature)
/// afterwards. Nothing here can refuse an exec: the exec gate is elsewhere.
///
/// In three parts (runtime-instances.md §14.8, 2026-10-18): what is read
/// while the exec is held (`exec_seen`, `/proc` reads only, on the worker
/// that received it), the one arbiter ask that must come before the exec
/// goes (`exec_ask`, a call root in a session with a secret policy, on a
/// thread of its own as before), and the record (`exec_report`, after the
/// CONTINUE, on a thread of its own). `dispatch` runs them.
struct ExecSeen {
    pid: i32,
    argv: Vec<String>,
    lineage: crate::secret_open::ExecLineage,
    cwd: Option<String>,
    session: Option<String>,
    call_root: bool,
}

/// The reads (and the guard's own records) an exec needs before it is let
/// go. `/proc` and the tracee's memory only: no arbiter call, nothing that
/// waits on another process.
fn exec_seen(cfg: &GuardConfig, notif: &libc::seccomp_notif) -> ExecSeen {
    use crate::secret_open::{exec_argv_ptr, read_tracee_argv};
    let pid = notif.pid as i32;
    let nr = notif.data.nr as i64;
    let argv = exec_argv_ptr(nr, &notif.data.args).map(|p| read_tracee_argv(pid, p)).unwrap_or_default();
    // Plan 13 D7: the process's own key and the whole live chain, read while
    // the tracee is suspended: a subshell between it and the call's root
    // that never execs is alive now (it is this process's parent or above),
    // and gets its edge here. One walk (`exec_lineage_of`).
    let lineage = crate::secret_open::exec_lineage_of(pid);
    // Plan 10 §4.1a: a sandboxed task keeps its mirrored sandbox under its own
    // key from here on, whatever happens to its parent.
    cfg.landlock.on_exec(pid);
    // The enforce-clean box announces itself by its applier's exec; the proc
    // key survives the exec into the command (same pid), and the command's
    // children inherit through the /proc walk. Recorded BEFORE the exec is
    // let go: the box's first open may reach another guard worker at once
    // (TaintedSet::taint_then; a failed exec leaves a membership that only
    // withholds raw bytes).
    if crate::secret_open::is_clean_box_exec(&argv) {
        cfg.clean_boxes.insert(&lineage.own);
    }
    // 2026-10-04 (confidentiality.md §6): the directory the exec'ing process
    // is in, read while it is suspended (once the exec is let go the program
    // may `cd` at once). Reported with a call root only: the directory the
    // arbiter reads the call's relative path tokens in (Claude Code's Bash
    // names none). One readlink per exec of the tree.
    let cwd = crate::lineage::reported_cwd(std::fs::read_link(format!("/proc/{pid}/cwd")).ok().as_deref());
    let session = cfg.secrets.as_ref().and_then(|s| s.session.clone());
    // Plan 13 D7, the call-root recorder: an exec by the agent's own child is
    // the shell the agent runs one tool call in (Claude Code's `zsh -c
    // '… eval <command> …'`, Codex's `bash -lc <command>`, OpenCode 2's
    // shell under its private server, which `agent_keys` counts as the
    // agent); the arbiter binds the call whose command it carries to it.
    // Decided while the exec is held (the agent's keys are cached; a miss
    // scans the tree): a HIGH session's command must be a holder before it
    // runs (`exec_ask`).
    let call_root = !argv.is_empty() && crate::lineage::is_call_root(lineage.parent_key.as_deref(), &crate::guard_flow::agent_keys(cfg));
    ExecSeen { pid, argv, lineage, cwd, session, call_root }
}

/// Does this exec wait for the arbiter before it goes (`exec_ask`)?
fn exec_asks(cfg: &GuardConfig, seen: &ExecSeen) -> bool {
    seen.call_root && cfg.secrets.is_some() && cfg.emitter.is_some()
}

/// confidentiality.md §4, "What Allow once means for a command": in a
/// session that read secret content into the model's context, a tool call's
/// shell holds what the session read. The arbiter records the session's
/// rows on it and the guard makes it a holder BEFORE the exec goes, so its
/// first connect and its first write are already judged (only the bindings
/// of what the session read; writes labeled).
fn exec_ask(cfg: &GuardConfig, seen: &ExecSeen) {
    if let Some(c) = cfg.emitter.as_ref() {
        let answer = match c.lock() {
            Ok(mut client) => client.session_exec_root(&mandu_arbiter::protocol::SessionExecRootArgs { proc_key: seen.lineage.own.clone(), session: seen.session.clone() }),
            Err(_) => Err(mandu_arbiter::client::ArbiterError::Protocol("the arbiter client is poisoned".into())),
        };
        if crate::lineage::session_holder(&answer) {
            cfg.tainted.insert(&seen.lineage.own);
        }
    }
}

/// Does this exec have a record to send once it is let go (`exec_report`)?
fn exec_reports(cfg: &GuardConfig, seen: &ExecSeen) -> bool {
    !seen.argv.is_empty() && cfg.emitter.is_some()
}

/// The exec's record, after the CONTINUE (the arbiter learns it off the
/// syscall path).
fn exec_report(cfg: &GuardConfig, seen: ExecSeen) {
    if !exec_reports(cfg, &seen) {
        return;
    }
    let ExecSeen { pid, argv, lineage, cwd, session, call_root } = seen;
    let crate::secret_open::ExecLineage { own: proc_key, ancestors, parent_key } = lineage;
    // Plan 13 D7, the orphan subshell: a process off the agent's tree whose
    // topmost ancestor was re-parented after the agent started (its parent,
    // a call's shell, exited before it acted): named so the arbiter folds it
    // into the calls that may have started it.
    let orphan_root = if call_root { None } else { orphan_root_for(cfg, pid, &proc_key, &ancestors) };
    if let Some(c) = cfg.emitter.as_ref() {
        if let Ok(mut client) = c.lock() {
            let ancestors = if ancestors.is_empty() { None } else { Some(ancestors) };
            let cwd = if call_root { cwd } else { None };
            let call_root = if call_root { Some(true) } else { None };
            let _ = client.record_exec_root(&mandu_arbiter::protocol::RecordExecRootArgs { proc_key, parent_key, ancestors, argv, session, call_root, cwd, orphan_root });
        }
    }
}

/// Plan 13 D7, the orphan subshell (2026-10-02): the orphan root to report
/// with an event of `pid` (`lineage::orphan_root_report`). The agent's keys
/// and the chain decide first; only a process off the agent's tree pays the
/// `/proc` walk to its reaper.
fn orphan_root_for(cfg: &GuardConfig, pid: i32, own: &str, chain: &[String]) -> Option<String> {
    let agents = crate::guard_flow::agent_keys(cfg);
    if agents.is_empty() || agents.iter().any(|a| a == own || chain.iter().any(|c| c == a)) {
        return None;
    }
    let (rpid, st) = cfg.tainted.orphan_root_of(pid)?;
    let key = crate::secret_open::own_key_of(rpid);
    crate::lineage::orphan_root_report(own, chain, &agents, Some((key.as_str(), st.start)))
}

// ── exec-routing.md §7.5 (2026-10-02): a holder's lineage ───────────────────

/// `prctl(PR_SET_CHILD_SUBREAPER)`: the caller reaps the orphans below it
/// from now on; an orphan re-parented to it is judged as one (`lineage`).
pub fn handle_prctl_notif(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) {
    if notif.data.args[0] == crate::lineage::PR_SET_CHILD_SUBREAPER && notif.data.args[1] != 0 {
        cfg.tainted.add_reaper(&crate::secret_open::own_key_of(notif.pid as i32));
    }
    answer_continue(listener, notif);
}

/// Truncate the file behind `fd` to zero, if it is a regular file (the
/// kernel's `O_TRUNC` leaves a device or a FIFO as it is). Err = the errno.
fn truncate_regular(fd: RawFd) -> std::result::Result<(), i32> {
    // SAFETY: fstat into a zeroed stat buffer; ftruncate of our own descriptor.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFREG || unsafe { libc::ftruncate(fd, 0) } == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))
}

/// The tracee's held-back `O_TRUNC` (`truncate_after_lookup`) on the file
/// the guard opened for it: `ftruncate` on its descriptor, or, for a
/// read-only one (Linux truncates `O_RDONLY|O_TRUNC` when the opener may
/// write), on a writable reopen of it (`reopen_writable`), so the write
/// permission is judged as the kernel's own `O_TRUNC` judges it (an opener
/// that may not write gets the reopen's errno, as the kernel refuses its
/// open).
fn truncate_held_back(fd: RawFd, flags: i32, reopen_writable: &dyn Fn(RawFd) -> std::result::Result<RawFd, i32>) -> std::result::Result<(), i32> {
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return truncate_regular(fd);
    }
    let w = reopen_writable(fd)?;
    let r = truncate_regular(w);
    close_fd(w);
    r
}

/// Open a path in THIS process with the given flags; None on failure.
fn open_for_tracee(path: &str, flags: i32) -> Option<RawFd> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: a NUL-terminated path; mode 0600 only matters with O_CREAT (twin).
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
    if fd < 0 { None } else { Some(fd) }
}

/// The twin's descriptor for this open (plan 10 §4.1). Where the path the
/// tracee named already reaches the twin (the bind posture), the guard
/// resolves it in the tracee's view and hands over THAT file, re-opened with
/// the twin's flags: it names the path the agent named, as an open under
/// the bind alone does (`secret_open::view_reaches_twin`,
/// differential-interactive.md §20). Otherwise (no bind, a write, a path
/// that no longer resolves) the twin by its own path, as before. The file
/// handed over is the twin either way: its identity is checked on the
/// descriptor that is re-opened, so a path swapped meanwhile cannot turn it
/// into the real file.
fn open_twin_for(listener: RawFd, notif: &libc::seccomp_notif, dirfd: i32, raw_path: &[u8], twin: &str, flags: i32) -> Option<RawFd> {
    let want = crate::secret_open::supervisor_open_flags(flags, true);
    let write = crate::secret_open::is_write_intent(flags) && flags & libc::O_PATH == 0;
    if !write {
        if let Ok(p) = resolve_opath_as_tracee(listener, notif, dirfd, raw_path, flags & libc::O_NOFOLLOW) {
            let seen = file_identity(p).map(|i| i.key());
            let twin_id = crate::secret_open::file_id(twin).map(|i| i.key());
            let fd = if crate::secret_open::view_reaches_twin(write, seen, twin_id) {
                // Re-open the resolved file itself (the magic link keeps its
                // mount and dentry, so the name is kept); read flags only:
                // O_NOFOLLOW would refuse the link, O_TRUNC/O_CREAT never apply.
                open_for_tracee(&format!("/proc/self/fd/{p}"), want & !(libc::O_NOFOLLOW | libc::O_TRUNC | libc::O_CREAT))
                    .filter(|fd| file_identity(*fd).map(|i| i.key()) == twin_id || { close_fd(*fd); false })
            } else {
                None
            };
            close_fd(p);
            if fd.is_some() {
                return fd;
            }
        }
    }
    open_for_tracee(twin, want)
}


/// Why the supervisor watches poll(2) and not only a blocking NOTIF_RECV: a
/// blocking RECV does not wake when the tracee tree exits WITHOUT a pending
/// notification (an agent that never calls connect), so the supervisor would
/// hang forever after the agent quit. The seccomp notifier's `.poll` reports
/// `EPOLLHUP` on filter release, the authoritative "tree gone" signal: the
/// main thread waits for exactly that, while receiving workers (each polling
/// with a timeout before it receives) take the notifications. Threading
/// matters because a blocking supervisor-connect must not stall other
/// tracees' connects, and the tree's opens are performed where they arrive.
/// Opens trapped under the §7.1 spike (reported at exit by the binary).
pub static OPEN_TRAPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Plan 10 §4.1a, the cost of the mirror (2026-10-05): reading opens of a
/// task in a Landlock domain, reopened on the guard's own thread because the
/// domain is the launch's net-only wrap alone (`Domain::governs_files`)…
pub static OPENS_UNDER_WRAP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// …and reopened on a mirror thread. Written at exit to the file
/// `OPEN_STATS_ENV` names (a test's proof of which path ran; no decision
/// depends on them).
pub static OPENS_MIRRORED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Runtime-instances.md §14.8 (2026-10-18), the cost of an exec: the execs
/// answered on the worker that received them…
pub static EXECS_HELD_HERE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// …the execs held on a thread of their own (a call root that waits for
/// the arbiter, `exec_asks`)…
pub static EXECS_HELD_ON_THREAD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// …and how long they were held in all, from the receipt to the CONTINUE,
/// in nanoseconds. Written at exit beside the open counts (a test's proof
/// and a diagnostic; no decision depends on them).
pub static EXEC_HELD_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Where the guard writes `OPENS_UNDER_WRAP` / `OPENS_MIRRORED` (and the
/// exec counts) at exit.
pub const OPEN_STATS_ENV: &str = "MANDU_NET_GUARD_OPEN_STATS";

/// The handlers still running, on a worker or on a thread of their own. Once
/// the tree is gone the supervisor waits for them, `DRAIN`: an answered
/// tracee can exit while its handler still owes the arbiter a report (the
/// label of a file it wrote, the record of an exec), and returning at once
/// ended that request with the process (CI 2026-09-29: a tainted shell's
/// write went unlabeled, about one run in sixteen under load).
///
/// One count per supervisor (2026-10-17): a process-wide count made every
/// supervisor wait for every other one's handlers, so a clean run's
/// supervisor (clean_host_kernel) waited out the agent tree's, and in the
/// integration tests, where dozens of supervisors share a process, nearly
/// every guarded run's end waited the whole `DRAIN` for its neighbours.
pub struct InFlight(std::sync::atomic::AtomicUsize);

/// One running handler of one supervisor; counted until dropped.
pub struct Busy(Arc<InFlight>);

impl InFlight {
    pub const fn new() -> Self {
        InFlight(std::sync::atomic::AtomicUsize::new(0))
    }
    pub fn busy(self: &Arc<Self>) -> Busy {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Busy(self.clone())
    }
    pub fn running(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
    /// Wait until no handler runs or `bound` passes; true when none runs.
    pub fn drain(&self, bound: Duration) -> bool {
        let end = Instant::now() + bound;
        while self.running() > 0 {
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.0 .0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The most the supervisor waits for its handlers after the tree is gone.
const DRAIN: Duration = Duration::from_secs(5);

/// Run `f` on a thread made by `b`; false when none could be made.
fn spawn_detached<T: Send + 'static>(b: std::thread::Builder, f: impl FnOnce() -> T + Send + 'static) -> bool {
    b.spawn(f).is_ok()
}

/// A handler on a thread of its own (2026-10-17). When no thread can be made
/// (a task or memory limit reached), the call is refused with EAGAIN at once,
/// never continued: `std::thread::spawn` panicked there instead, which ended
/// the worker that received the notification and left the tracee suspended
/// on it with nobody to answer, so the agent hung in that call for good.
/// The handler's `Busy` goes with the closure, so the count stays right.
fn on_own_thread<T: Send + 'static>(listener: RawFd, notif: &libc::seccomp_notif, f: impl FnOnce() -> T + Send + 'static) {
    if !spawn_detached(std::thread::Builder::new().name("guard-handler".into()), f) {
        answer_errno(listener, notif, libc::EAGAIN);
    }
}

/// Run `f`, a report owed for a call already answered, on a thread made by
/// `b`; here, on the calling worker, when none can be made (a task or
/// memory limit reached): the call is answered, so there is nothing to
/// refuse, and the report is never dropped for want of a thread.
fn after_answer<F: FnOnce() + Send + 'static>(b: std::thread::Builder, f: F) {
    let slot = Arc::new(Mutex::new(Some(f)));
    let theirs = slot.clone();
    let made = spawn_detached(b, move || {
        let f = theirs.lock().ok().and_then(|mut g| g.take());
        if let Some(f) = f {
            f();
        }
    });
    if !made {
        let f = slot.lock().ok().and_then(|mut g| g.take());
        if let Some(f) = f {
            f();
        }
    }
}

/// Count an exec answered `held` after it was received.
fn exec_held(on: &std::sync::atomic::AtomicU64, held: Instant) {
    on.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    EXEC_HELD_NS.fetch_add(held.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
}

/// Handle one received notification: an open or a bind on the calling thread
/// (plan 10 §4.1a: the common open pays one wakeup, no thread creation);
/// everything that can block for long (a supervised connect, an exec's
/// arbiter call, a delete, an introspection check) on a thread of its own,
/// as before.
fn dispatch(listener: RawFd, cfg: &GuardConfig, notif: libc::seccomp_notif, in_flight: &Arc<InFlight>) {
    // Counted until the handler returns, here or on its own thread.
    let busy = in_flight.busy();
    let nr = notif.data.nr as libc::c_long;
    if crate::guard_signals::is_signal_nr(nr as i64) {
        // rootless-confinement §12.2: the tree cannot signal (or starve) its
        // guard.
        if crate::guard_signals::should_refuse(nr as i64, &notif.data.args, notif.pid as i32) || payload_signal_refused(cfg, nr as i64, &notif.data.args, notif.pid as i32) {
            answer_errno(listener, &notif, libc::EPERM);
        } else if nr == libc::SYS_pidfd_send_signal && crate::guard_signals::harmful(notif.data.args[1] as u32 as i32) {
            // A signal that can hurt the guard, by descriptor: performed on a
            // copy of the descriptor, so a dup2 after the check changes
            // nothing. It runs where the caller's own Landlock layers apply
            // (a program may scope its signals); the launch's layer sets no
            // signal scope (fs-supervisor landlock.rs), so connect_via's
            // choice is the right one here too.
            let cfg = cfg.clone();
            on_own_thread(listener, &notif, move || {
                let _busy = busy;
                let pid = notif.pid as i32;
                let answer = crate::guard_signals::perform_pidfd_send_signal(pid, &notif.data.args, |job| match cfg.landlock.connect_via(pid) {
                    Ok(crate::landlock_mirror::ConnectVia::Guard) => Ok(job()),
                    Ok(crate::landlock_mirror::ConnectVia::Mirror(d)) => d.run(job),
                    Err(e) => Err(e),
                });
                answer_errno(listener, &notif, answer);
            });
        } else {
            answer_continue(listener, &notif);
        }
    } else if SYS_INTROSPECT.contains(&nr) {
        // §4.1: ptrace / process_vm_* against a TAINTED process by an
        // untainted one is refused; everything else continues.
        let cfg = cfg.clone();
        on_own_thread(listener, &notif, move || {
            let _busy = busy;
            handle_introspect_notif(listener, &cfg, &notif)
        });
    } else if crate::object_flow::is_memfd_nr(nr as i64) {
        // P0 triage 1b: a holder's memfd is made and marked by the guard.
        // Nobody holds a secret: on at once, here (a JIT runtime's memfds).
        if cfg.secrets.is_none() || cfg.tainted.is_empty() {
            answer_continue(listener, &notif);
        } else {
            let cfg = cfg.clone();
            on_own_thread(listener, &notif, move || {
                let _busy = busy;
                crate::guard_flow::handle_memfd_notif(listener, &cfg, &notif)
            });
        }
    } else if crate::object_flow::is_ipc_nr(nr as i64) {
        // Plan 13 §9 R1, the file shapes: `shmat`, a message queue send. A
        // holder's attach sweeps the segment's other users (it may wait for
        // their egress in flight), so on a thread of its own.
        let cfg = cfg.clone();
        on_own_thread(listener, &notif, move || {
            let _busy = busy;
            crate::guard_flow::handle_ipc_notif(listener, &cfg, &notif)
        });
    } else if crate::owner_time::is_owner_time_nr(nr as i64) {
        // P0 5c (2026-10-07): trapped for a holder's owner or timestamps on
        // a mount that leaves the machine; nobody holds a secret: on at once.
        if cfg.secrets.is_none() || cfg.tainted.is_empty() {
            answer_continue(listener, &notif);
        } else {
            let cfg = cfg.clone();
            on_own_thread(listener, &notif, move || {
                let _busy = busy;
                handle_owner_time_notif(listener, &cfg, &notif)
            });
        }
    } else if crate::secret_open::is_mkdir_nr(nr as i64) && (cfg.secrets.is_none() || cfg.tainted.is_empty()) {
        // Plan 13 §9 R4 (b): trapped for a holder's directory name on a mount
        // that leaves the machine; nobody holds a secret: on at once, here.
        answer_continue(listener, &notif);
    } else if crate::secret_open::is_delete_nr(nr as i64) || crate::secret_open::is_write_nr(nr as i64) || crate::secret_open::is_mkdir_nr(nr as i64) {
        let cfg = cfg.clone();
        on_own_thread(listener, &notif, move || {
            let _busy = busy;
            handle_path_change_notif(listener, &cfg, &notif)
        });
    } else if crate::secret_open::is_exec_nr(nr as i64) {
        // Plan 10 §4.2: read argv BEFORE the exec proceeds, let it go, then
        // tell the arbiter off the syscall path. The reads run here, on the
        // receiving worker, like an open's (runtime-instances.md §14.8,
        // 2026-10-18: a thread made per exec held each exec about 100 µs
        // before its first read on the test host); only an exec that waits
        // for the arbiter before it goes (`exec_asks`) is held on a thread of
        // its own, as before, and the record is sent from one after the
        // CONTINUE.
        let held = Instant::now();
        let seen = exec_seen(cfg, &notif);
        if exec_asks(cfg, &seen) {
            let cfg = cfg.clone();
            on_own_thread(listener, &notif, move || {
                let _busy = busy;
                exec_ask(&cfg, &seen);
                answer_continue(listener, &notif);
                exec_held(&EXECS_HELD_ON_THREAD, held);
                exec_report(&cfg, seen);
            });
        } else {
            answer_continue(listener, &notif);
            exec_held(&EXECS_HELD_HERE, held);
            if exec_reports(cfg, &seen) {
                let cfg = cfg.clone();
                after_answer(std::thread::Builder::new().name("guard-report".into()), move || {
                    let _busy = busy;
                    exec_report(&cfg, seen);
                });
            }
        }
    } else if crate::stat_twin::fd_stat_call(nr as i64, &notif.data.args).is_some() {
        // Plan 13 D4 (2026-10-04): a stat of a descriptor at the twin base
        // (`fd_stat_block`): a derived twin reports its file's identity.
        let _ = handle_fd_stat_notif(listener, cfg, &notif);
    } else if crate::stat_twin::is_stat_nr(nr as i64) {
        // confidentiality.md §7.2a: a stat by path of a guard-only twin.
        let _ = handle_stat_notif(listener, cfg, &notif);
    } else if nr == libc::SYS_bind {
        // exec-routing.md §4.2: the command box's own sockets.
        handle_bind_notif(listener, cfg, &notif);
    } else if crate::guard_send::is_send_nr(nr) {
        // exec-routing.md §7.5 (2026-10-01): a send that can name an address,
        // performed by the guard on its copy of the socket. On this worker:
        // the common send does not block; one that would hands its wait to a
        // thread of its own (guard_send::perform).
        let _ = crate::guard_send::handle_send_notif(listener, cfg, &notif);
    } else if crate::wait_flow::is_wait_nr(nr as i64) {
        // Plan 13 §4.9 (2026-10-03): the reaper of a holder becomes one
        // before the kernel performs the wait (CONTINUE, never emulated).
        // Nobody holds a secret: continued here at once. Otherwise the
        // waiter may be swept (it waits for egress in flight): on a thread.
        if cfg.secrets.is_none() || cfg.tainted.is_empty() {
            answer_continue(listener, &notif);
        } else {
            let cfg = cfg.clone();
            on_own_thread(listener, &notif, move || {
                let _busy = busy;
                let _ = crate::guard_wait::handle_wait_notif(listener, &cfg, &notif);
            });
        }
    } else if crate::lineage::is_prctl_nr(nr as i64) {
        // exec-routing.md §7.5 (2026-10-02): a reaper the tree makes (the
        // orphan backstop). /proc reads only; nothing that waits.
        handle_prctl_notif(listener, cfg, &notif);
    } else if crate::accept_guard::is_accept_nr(nr as i64) {
        // A holder's accept: performed by the guard; it may wait for a
        // connection, so on a thread of its own.
        let cfg = cfg.clone();
        on_own_thread(listener, &notif, move || {
            let _busy = busy;
            let _ = crate::guard_accept::handle_accept_notif(listener, &cfg, &notif);
        });
    } else if nr == crate::landlock_mirror::SYS_LANDLOCK_RESTRICT_SELF {
        // Plan 10 §4.1a: mirror the sandbox before it takes effect.
        match cfg.landlock.on_restrict(notif.pid as i32, notif.data.args[0] as RawFd) {
            Ok(()) => answer_continue(listener, &notif),
            Err(e) => answer_errno(listener, &notif, e),
        }
    } else if nr != SYS_CONNECT {
        OPEN_TRAPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if cfg.secrets.is_some() {
            // Plan 10 §4.1/§4.1a: the guard performs the open (or decides a secret).
            let _ = handle_open_notif(listener, cfg, &notif);
        } else {
            // §7.1 spike mode: CONTINUE at once, no path read.
            answer_continue(listener, &notif);
        }
    } else {
        // One short-lived worker per connect. The tracee stays suspended on
        // its own notif.id until this worker answers, so concurrent connects
        // each get their own frozen tracee.
        let cfg = cfg.clone();
        on_own_thread(listener, &notif, move || {
            let _busy = busy;
            let _ = handle_connect_notif(listener, &cfg, &notif);
        });
    }
}

/// The receiving workers' shared state.
struct Workers {
    idle: std::sync::atomic::AtomicUsize,
    total: std::sync::atomic::AtomicUsize,
    done: std::sync::atomic::AtomicBool,
    /// This supervisor's handlers still running (`InFlight`).
    in_flight: Arc<InFlight>,
}

impl Workers {
    const MIN: usize = 4;
    const MAX: usize = 64;
}

/// A worker: receive a notification and handle it, until the supervisor is
/// done. It holds its OWN duplicate of the listener, so it can never receive
/// from another listener that took over the descriptor number later. The
/// kernel hands each notification to exactly one waiting receiver. A worker
/// that takes the last idle slot starts another (up to `Workers::MAX`), so
/// opens that block (a FIFO waiting for its peer, a held ask) never hold the
/// rest back.
fn spawn_worker(listener: RawFd, cfg: GuardConfig, w: Arc<Workers>) {
    use std::sync::atomic::Ordering::SeqCst;
    // SAFETY: dup of the listener; the worker closes its copy when it ends.
    let mine = unsafe { libc::fcntl(listener, libc::F_DUPFD_CLOEXEC, 0) };
    if mine < 0 {
        return;
    }
    w.total.fetch_add(1, SeqCst);
    w.idle.fetch_add(1, SeqCst);
    let spawned = std::thread::Builder::new().name("guard-worker".into()).spawn({
        let w = w.clone();
        move || {
            loop {
                if w.done.load(SeqCst) {
                    break;
                }
                // Bounded wait, so a finished supervisor is noticed.
                let mut pfd = libc::pollfd { fd: mine, events: libc::POLLIN, revents: 0 };
                // SAFETY: poll one fd with a timeout.
                let rc = unsafe { libc::poll(&mut pfd, 1, 200) };
                if rc <= 0 {
                    continue;
                }
                if pfd.revents & libc::POLLIN == 0 {
                    // The tree is gone.
                    break;
                }
                // Another worker may take it first: this one then waits here
                // for the next notification of THIS listener (its own copy).
                let Ok(notif) = notif_recv(mine) else { continue };
                // 2026-10-09 (`death_watch`, exec-routing.md §7.5 (d)): the
                // holders whose pidfd reports their exit are stamped before
                // this call is judged or answered, so a process its caller
                // starts after it is born after every death that preceded
                // it, whenever the watcher's own thread gets to run. One
                // non-blocking epoll look when nothing is ready.
                cfg.tainted.stamp_ready_deaths();
                if w.idle.fetch_sub(1, SeqCst) == 1 && w.total.load(SeqCst) < Workers::MAX {
                    spawn_worker(mine, cfg.clone(), w.clone());
                }
                dispatch(mine, &cfg, notif, &w.in_flight);
                w.idle.fetch_add(1, SeqCst);
            }
            w.idle.fetch_sub(1, SeqCst);
            w.total.fetch_sub(1, SeqCst);
            // SAFETY: the worker's own duplicate.
            unsafe { libc::close(mine) };
        }
    });
    if spawned.is_err() {
        w.total.fetch_sub(1, SeqCst);
        w.idle.fetch_sub(1, SeqCst);
        // SAFETY: the duplicate made above.
        unsafe { libc::close(mine) };
    }
}

pub fn run_guard_supervisor(listener: RawFd, cfg: GuardConfig) -> Result<()> {
    let workers = Arc::new(Workers {
        idle: std::sync::atomic::AtomicUsize::new(0),
        total: std::sync::atomic::AtomicUsize::new(0),
        done: std::sync::atomic::AtomicBool::new(false),
        in_flight: Arc::new(InFlight::new()),
    });
    // 2026-10-09: the death watch starts before the first worker, so no
    // holder is recorded before a pidfd can watch it (a holder recorded
    // without one was left to the 200 ms poll; `enable_death_watch` also
    // watches any recorded before it).
    if cfg.secrets.is_some() {
        let mut lim = libc::rlimit { rlim_cur: 1024, rlim_max: 1024 };
        // SAFETY: getrlimit into a local.
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
        let _ = cfg.tainted.enable_death_watch(crate::death_watch::fd_cap(lim.rlim_cur as u64));
    }
    for _ in 0..Workers::MIN {
        spawn_worker(listener, cfg.clone(), workers.clone());
    }
    // exec-routing.md §7.5 (2026-10-02): a holder's death is stamped soon
    // after it happens, so the window in which an orphan inherits from it
    // closes (`TaintedSet::observe_deaths`).
    // Plan 13 §4.5.1: the same look reports the agent's channels to a holder
    // that the agent has dropped (`guard_flow::observe_agent_closes`), so a
    // later tool result is not masked for a connection already gone.
    if cfg.secrets.is_some() {
        // 2026-10-09 (`death_watch`): and stamped when it happens, through a
        // pidfd per holder (started above, before the workers), so a process
        // born after the death is no orphan of it; the poll below stays the
        // fallback. Budget: a quarter of the soft descriptor limit (at most
        // 4096 pidfds).
        let (tainted, w, watch) = (cfg.tainted.clone(), workers.clone(), cfg.clone());
        let _ = std::thread::Builder::new().name("guard-deaths".into()).spawn(move || {
            while !w.done.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(200));
                if !tainted.is_empty() {
                    tainted.observe_deaths();
                }
                crate::guard_flow::observe_agent_closes(&watch);
            }
        });
    }
    let result = loop {
        // Only the hang-up is watched here (no POLLIN interest): the last
        // filter holder exited, the agent tree is gone.
        let mut pfd = libc::pollfd { fd: listener, events: 0, revents: 0 };
        // SAFETY: poll one fd, no timeout.
        let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, -1) };
        if rc < 0 {
            let e = Error::last_os_error();
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            break Err(e);
        }
        if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            break Ok(());
        }
    };
    workers.done.store(true, std::sync::atomic::Ordering::SeqCst);
    // The tree is gone, but a handler may still owe the arbiter its report.
    workers.in_flight.drain(DRAIN);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::parse_rule;

    #[test]
    fn an_allowed_connect_without_a_socket_copy_is_refused_where_getfd_exists() {
        // Finding 8: only a kernel that cannot copy a socket at all continues.
        assert_eq!(allowed_without_copy(true), NoCopy::Refuse);
        assert_eq!(allowed_without_copy(false), NoCopy::Continue);
    }

    #[test]
    fn a_handler_thread_that_cannot_be_made_is_reported_not_a_panic() {
        // The refusal path of `on_own_thread`: a thread no system can give
        // (a 64 TiB stack) is reported as false, and its closure, with the
        // handler's count, is dropped.
        let f = Arc::new(InFlight::new());
        let busy = f.busy();
        assert_eq!(f.running(), 1);
        let made = spawn_detached(std::thread::Builder::new().stack_size(1 << 46), move || drop(busy));
        assert!(!made, "no thread of that size");
        assert_eq!(f.running(), 0, "the handler's count went with its closure");
        assert!(spawn_detached(std::thread::Builder::new(), || ()), "an ordinary thread is made");
    }

    #[test]
    fn a_report_owed_after_the_answer_runs_on_its_thread_or_here_never_dropped() {
        // runtime-instances.md §14.8: an exec's record, sent once the exec
        // was let go. On a thread of its own when one can be made…
        let f = Arc::new(InFlight::new());
        let (tx, rx) = std::sync::mpsc::channel();
        let busy = f.busy();
        after_answer(std::thread::Builder::new().name("guard-report".into()), move || {
            let _busy = busy;
            tx.send(std::thread::current().name().map(String::from)).unwrap();
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap().as_deref(), Some("guard-report"));
        assert!(f.drain(Duration::from_secs(10)), "the handler's count went with the report");
        // …and here, on the calling worker, when none can be (a 64 TiB stack):
        // the call is already answered, so the report is the only thing left.
        let (tx, rx) = std::sync::mpsc::channel();
        let busy = f.busy();
        let me = std::thread::current().id();
        after_answer(std::thread::Builder::new().stack_size(1 << 46), move || {
            let _busy = busy;
            tx.send(std::thread::current().id()).unwrap();
        });
        assert_eq!(rx.try_recv().ok(), Some(me), "run here, before after_answer returned");
        assert_eq!(f.running(), 0, "its count released when it ran");
    }

    #[test]
    fn the_supervisor_waits_for_running_handlers_but_not_forever() {
        let f = Arc::new(InFlight::new());
        assert!(f.drain(Duration::from_millis(1)), "nothing running: no wait");
        let a = f.busy();
        let b = f.busy();
        assert_eq!(f.running(), 2);
        let t0 = Instant::now();
        assert!(!f.drain(Duration::from_millis(50)), "a handler still running: the wait is bounded");
        assert!(t0.elapsed() >= Duration::from_millis(50));
        drop(a);
        std::thread::scope(|sc| {
            sc.spawn(move || {
                std::thread::sleep(Duration::from_millis(30));
                drop(b);
            });
            assert!(f.drain(Duration::from_secs(5)), "the last handler finishing ends the wait");
        });
        assert_eq!(f.running(), 0);
    }

    #[test]
    fn a_unix_address_nobody_listens_on_gets_the_kernels_own_answer() {
        // Nothing to reach: the tracee learns only what its own connect
        // would have told it (a stale socket file, a vanished name).
        assert!(nobody_listens(libc::ECONNREFUSED));
        assert!(nobody_listens(libc::ENOENT));
        assert!(!nobody_listens(libc::EAGAIN), "a full backlog: someone listens");
        assert!(!nobody_listens(libc::EACCES));
    }

    #[test]
    fn caching_resolver_memoizes_localhost() {
        let r = CachingResolver::new(Duration::from_secs(60));
        // "localhost" reliably resolves to a loopback address on any host.
        let a = r.resolve("localhost");
        assert!(a.iter().any(|ip| ip.is_loopback()), "localhost → loopback: {a:?}");
        // Second call hits the cache (same answer).
        assert_eq!(r.resolve("localhost"), a);
        // An unresolvable name yields empty (fail-closed for a Host rule).
        assert!(r.resolve("no.such.host.mandu.invalid").is_empty());
    }

    #[test]
    fn guard_config_is_send_sync() {
        // The loop moves GuardConfig into worker threads; assert the bounds hold.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GuardConfig>();
        // And it composes from real parts.
        let cfg = GuardConfig::new(
            Arc::new(GuardPolicy::new(vec![parse_rule("127.0.0.0/8:8788").unwrap()])),
            Arc::new(CachingResolver::default()),
        );
        assert_eq!(cfg.policy.rules.len(), 1);
        assert!(cfg.emitter.is_none(), "no emitter by default");
    }
}
