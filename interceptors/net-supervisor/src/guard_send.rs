//! guard_send — the KERNEL half of judging a send (feature `kernel`, Linux;
//! exec-routing.md §7.5, "Sends are judged like connects", 2026-10-01).
//!
//! The guard's filter traps `sendmsg`, `sendmmsg`, and `sendto` with a
//! non-null address (`guard_filter`), in every posture. For each:
//!
//! 1. The call is read ONCE out of the tracee (the `msghdr`s, their
//!    addresses, iovecs, payloads and ancillary data), checked the way the
//!    kernel checks it (`send_guard::check_msghdr`, …), and the socket is
//!    copied (`pidfd_getfd`).
//! 2. Each message's destination is the one the KERNEL would use
//!    (`send_guard::inet_send_destination`), judged like a connect to it: the
//!    static allow list, then the taint leg (a process holding a secret may
//!    reach only its secrets' bindings and the session's proxies). A Unix
//!    address takes the checks of a Unix connect (`unix_path_verdict`,
//!    `abstract_unix_verdict`) and is reached by the inode the checks opened.
//!    A send with no address by a TAINTED process is judged by the socket's
//!    peer (a socket it got after the sweep: by `accept`, or over
//!    `SCM_RIGHTS`).
//! 3. The guard SENDS what it read, on its copy: never CONTINUE, which would
//!    let the kernel read the address, the bytes and the descriptor again
//!    after the check (another thread can rewrite all three). Bytes copied
//!    inside the egress gate, before a taint, cannot hold the secret: the
//!    taint waits for the gate.
//!
//! What the tracee sees: the count sent (or, for `sendmmsg`, the messages
//! sent with each `msg_len` written back), or the errno its own call would
//! have got; EACCES for a destination refused; SIGPIPE raised on EPIPE as
//! its own send would have. A blocking send that would block is waited for
//! on a thread of its own, polling, while the call is still live (a send the
//! tracee stopped waiting for is never made). Differences from the tracee's
//! own send, all on rare paths: `MSG_ZEROCOPY` is sent copied (no
//! completion is posted); `SCM_CREDENTIALS` is refused (EPERM: only the
//! sender can vouch for its pid); a receiver with `SO_PASSCRED` sees the
//! guard's credentials. A kernel without `pidfd_getfd` (< 5.6) judges the
//! address read and continues, the documented old-kernel degrade of the
//! connect leg.
//!
//! Also here: the TAINT-TIME SWEEP (`sweep_before_taint`), run by the open
//! handler before a reader gets a raw descriptor.
//!
//! `Mandu-new`.

#![cfg(all(feature = "kernel", target_os = "linux"))]

use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

use fs_supervisor::kernel::{kernel_at_least, notif_id_valid, respond_value};
use fs_supervisor::tracee::tracee_fd;

use crate::guard::{Decision, Endpoint, Proto};
use crate::guard_kernel::{
    abstract_unix_verdict, answer_continue, answer_errno, binding_to_spec, close_fd, emit_unix_refusal, is_abstract_unix,
    is_box_thread, proto_of_fd, sockopt_int, socket_in_our_netns, unix_path_verdict, GuardConfig, TaintedRefusal, UnixVerdict,
};
use crate::send_guard::{self as sg, InetDest, MsgHdr};

/// `sendto`, `sendmsg`, `sendmmsg`.
pub fn is_send_nr(nr: libc::c_long) -> bool {
    nr == libc::SYS_sendto || nr == libc::SYS_sendmsg || nr == libc::SYS_sendmmsg
}

/// What the handler did with one send (for tests and the log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// Sent by the guard on its copy of the socket: the answer (bytes, or
    /// messages for `sendmmsg`, or the errno).
    Sent { answered: Result<usize, i32> },
    /// A destination refused before anything was sent (EACCES, EPERM).
    Refused { errno: i32, why: &'static str },
    /// The call was malformed (or the socket gone): the kernel's own errno,
    /// answered without sending.
    Invalid { errno: i32 },
    /// Kernel < 5.6 (no copy of a socket can be had): judged on the address
    /// read, then CONTINUEd.
    Continued { why: &'static str },
    /// The send had to wait and went on a thread of its own; it answers
    /// from there.
    Waiting,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Call {
    Sendto,
    Sendmsg,
    Sendmmsg,
}

/// One message, read once.
struct Message {
    /// The address exactly as passed (empty: none).
    name: Vec<u8>,
    payload: Vec<u8>,
    control: Vec<u8>,
}

/// A message ready to send: the address to use, the ancillary data with the
/// guard's own descriptors in it, and what to close afterwards.
struct Ready {
    name: Vec<u8>,
    payload: Vec<u8>,
    control: Vec<u8>,
    /// Descriptors the guard holds for this message (SCM_RIGHTS copies, the
    /// pinned inode of a Unix path).
    hold: Vec<RawFd>,
    /// An explicit destination: sent where the tracee's own Landlock layers
    /// apply (`landlock_mirror`), as a connect to it is.
    explicit: bool,
    /// The egress gates of the processes receiving the descriptors it
    /// passes (`guard_rights::judge_pass`), held until it is sent.
    _gates: Vec<sg::InFlightEgress>,
}

impl Drop for Ready {
    fn drop(&mut self) {
        for fd in self.hold.drain(..) {
            close_fd(fd);
        }
    }
}

/// Read `len` bytes of the tracee at `addr`, exactly: EFAULT for memory its
/// own call could not read.
fn read_exact(pid: i32, addr: u64, len: usize) -> Result<Vec<u8>, i32> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if addr == 0 {
        return Err(libc::EFAULT);
    }
    let mut buf = vec![0u8; len];
    let mut done = 0usize;
    while done < len {
        let local = libc::iovec { iov_base: buf[done..].as_mut_ptr() as *mut libc::c_void, iov_len: len - done };
        let remote = libc::iovec { iov_base: (addr + done as u64) as *mut libc::c_void, iov_len: len - done };
        // SAFETY: reads at most `len - done` bytes into our buffer; the tracee
        // is suspended on its notification.
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n <= 0 {
            return Err(libc::EFAULT);
        }
        done += n as usize;
    }
    Ok(buf)
}

/// One `msghdr`'s message.
fn read_message(pid: i32, h: &MsgHdr, datagram: bool) -> Result<Message, i32> {
    let namelen = sg::check_msghdr(h)?;
    let name = read_exact(pid, h.name, namelen)?;
    let iov_bytes = read_exact(pid, h.iov, h.iovlen as usize * sg::IOVEC_LEN)?;
    let iovs = sg::parse_iovecs(&iov_bytes, h.iovlen as usize);
    let mut payload = Vec::new();
    for (base, len) in sg::payload_plan(&iovs, datagram)? {
        payload.extend_from_slice(&read_exact(pid, base, len)?);
    }
    let control = read_exact(pid, h.control, h.controllen as usize)?;
    Ok(Message { name, payload, control })
}

/// The call's messages, read once. For `sendmmsg`, a message that cannot be
/// read ends the batch there (the kernel sends the ones before it); the
/// error is returned only when it is the first.
fn read_call(pid: i32, call: Call, a: &[u64; 6], datagram: bool) -> Result<Vec<Message>, i32> {
    match call {
        Call::Sendto => {
            let len = sg::check_sendto_addrlen(a[4], a[5])?;
            let name = read_exact(pid, a[4], len)?;
            let mut payload = Vec::new();
            for (base, n) in sg::payload_plan(&[(a[1], a[2])], datagram)? {
                payload.extend_from_slice(&read_exact(pid, base, n)?);
            }
            Ok(vec![Message { name, payload, control: Vec::new() }])
        }
        Call::Sendmsg => {
            let h = sg::parse_msghdr(&read_exact(pid, a[1], sg::MSGHDR_LEN)?).ok_or(libc::EFAULT)?;
            Ok(vec![read_message(pid, &h, datagram)?])
        }
        Call::Sendmmsg => {
            let vlen = a[2].min(sg::UIO_MAXIOV) as usize;
            let mut out = Vec::new();
            for i in 0..vlen {
                let m = read_exact(pid, a[1] + (i * sg::MMSGHDR_LEN) as u64, sg::MSGHDR_LEN)
                    .and_then(|b| sg::parse_msghdr(&b).ok_or(libc::EFAULT))
                    .and_then(|h| read_message(pid, &h, datagram));
                match m {
                    Ok(m) => out.push(m),
                    Err(e) if i == 0 => return Err(e),
                    Err(_) => break,
                }
            }
            Ok(out)
        }
    }
}

/// Is the calling process (or an ancestor) holding a secret? Its own key
/// and chain, for the arbiter. Nothing tainted at all: no `/proc` read.
pub(crate) fn taint_of(cfg: &GuardConfig, pid: i32) -> Option<(String, bool, Vec<String>)> {
    cfg.secrets.as_ref()?;
    if cfg.tainted.is_empty() {
        return Some((String::new(), false, Vec::new()));
    }
    let own = crate::secret_open::own_key_of(pid);
    let (held, chain) = crate::guard_flow::holder(cfg, pid, &own);
    Some((own, held, chain))
}

/// The bindings the arbiter answers for a tainted process: `None` when it
/// cannot be asked (the caller refuses). An arbiter that says "untainted"
/// for a process the guard knows holds a secret answers no binding.
pub(crate) fn taint_bindings(cfg: &GuardConfig, own: &str, chain: Vec<String>) -> Option<TaintedRefusal> {
    let c = cfg.emitter.as_ref()?;
    let mut client = c.lock().ok()?;
    let session = cfg.secrets.as_ref().and_then(|s| s.session.clone());
    let flows_from = crate::guard_flow::flows_from(cfg, own, &chain);
    let b = client
        .tainted_process_bindings(&mandu_arbiter::protocol::TaintedProcessBindingsArgs {
            proc_key: own.to_string(),
            ancestors: if chain.is_empty() { None } else { Some(chain) },
            session,
            flows_from,
            ..Default::default()
        })
        .ok()?;
    Some(TaintedRefusal { files: b.files, bindings: if b.tainted { b.bindings } else { Vec::new() } })
}

/// Does a binding list admit this INET destination (`host[:port]`, suffix,
/// CIDR, as a connect's taint leg reads it)?
pub(crate) fn bindings_admit(cfg: &GuardConfig, bindings: &[String], ip: IpAddr, port: u16, proto: Proto) -> bool {
    let specs: Vec<String> = bindings.iter().filter(|h| crate::local_exits::is_host_binding(h)).map(|h| binding_to_spec(h)).collect();
    match crate::guard::parse_rules(&specs) {
        Ok(rules) => crate::guard::GuardPolicy::new(rules).decide(&Endpoint { ip, port, proto }, cfg.resolver.as_ref()) == Decision::Allow,
        Err(_) => false,
    }
}

fn emit_send_decision(cfg: &GuardConfig, target: &Endpoint, decision: Decision, matched: Option<&crate::guard::AllowRule>) {
    let Some(emitter) = &cfg.emitter else { return };
    if !crate::events::guard_decision_is_noteworthy(decision, target.ip) {
        return;
    }
    let rule = matched.map(|r| r.to_string());
    let blocked = match decision {
        Decision::Deny => cfg.policy.blocked_reason(target),
        Decision::Allow => None,
    };
    let ev = crate::events::guard_egress_event(&cfg.session_id, 0, "send", target, decision, rule.as_deref(), blocked);
    if let Ok(mut client) = emitter.lock() {
        mandu_arbiter::safe_emit(&mut client, &ev);
    }
}

pub(crate) fn emit_tainted(cfg: &GuardConfig, verb: &str, dest: &str, r: &TaintedRefusal) {
    let Some(emitter) = &cfg.emitter else { return };
    let ev = crate::events::guard_tainted_refusal_event_verb(&cfg.session_id, verb, dest, &r.files, &r.bindings);
    if let Ok(mut client) = emitter.lock() {
        mandu_arbiter::safe_emit(&mut client, &ev);
    }
}

fn inet_dest_text(ip: IpAddr, port: u16, proto: Proto) -> String {
    match ip {
        IpAddr::V6(v6) => format!("[{v6}]:{port}/{}", proto.name()),
        v4 => format!("{v4}:{port}/{}", proto.name()),
    }
}

/// The taint leg for one INET destination of a holder: `Ok` admitted
/// (a session proxy, or a binding), `Err` refused (its event emitted).
fn taint_leg(cfg: &GuardConfig, verb: &str, taint: &Option<(String, bool, Vec<String>)>, ip: IpAddr, port: u16, proto: Proto) -> Result<(), ()> {
    let Some((own, true, chain)) = taint else { return Ok(()) };
    if sg::is_session_proxy(ip, port, proto, &cfg.proxy_ports) {
        return Ok(());
    }
    let dest = inet_dest_text(ip, port, proto);
    match taint_bindings(cfg, own, chain.clone()) {
        Some(b) if bindings_admit(cfg, &b.bindings, ip, port, proto) => Ok(()),
        Some(b) => {
            emit_tainted(cfg, verb, &dest, &b);
            Err(())
        }
        None => {
            emit_tainted(cfg, verb, &dest, &TaintedRefusal::default());
            Err(())
        }
    }
}

/// Handle one trapped send end to end (module docs).
pub fn handle_send_notif(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) -> SendOutcome {
    let pid = notif.pid as i32;
    let a = notif.data.args;
    let nr = notif.data.nr as libc::c_long;
    let call = if nr == libc::SYS_sendto {
        Call::Sendto
    } else if nr == libc::SYS_sendmsg {
        Call::Sendmsg
    } else {
        Call::Sendmmsg
    };
    let flags = match call {
        Call::Sendmsg => a[2],
        _ => a[3],
    } as u32 as i32;
    if !kernel_at_least(5, 6) {
        return degraded(listener, cfg, notif, call, flags);
    }
    // The gate first: the taint is read, and the bytes copied, inside it.
    let in_flight = cfg.secrets.as_ref().map(|_| cfg.egress.enter(crate::secret_open::tgid_of(pid)));
    let dup = match tracee_fd(pid, a[0] as RawFd) {
        Ok(d) => d,
        Err(e) => {
            let errno = if e.raw_os_error() == Some(libc::EBADF) { libc::EBADF } else { libc::EACCES };
            answer_errno(listener, notif, errno);
            return SendOutcome::Invalid { errno };
        }
    };
    let Some(family) = sockopt_int(dup, libc::SO_DOMAIN).map(|f| f as u16) else {
        close_fd(dup);
        answer_errno(listener, notif, libc::ENOTSOCK);
        return SendOutcome::Invalid { errno: libc::ENOTSOCK };
    };
    let sotype = sockopt_int(dup, libc::SO_TYPE).unwrap_or(libc::SOCK_STREAM);
    let datagram = sotype != libc::SOCK_STREAM;
    let msgs = match read_call(pid, call, &a, datagram) {
        Ok(m) => m,
        Err(e) => {
            close_fd(dup);
            answer_errno(listener, notif, e);
            return SendOutcome::Invalid { errno: e };
        }
    };
    if msgs.is_empty() {
        close_fd(dup);
        let _ = respond_value(listener, notif.id, 0);
        return SendOutcome::Sent { answered: Ok(0) };
    }
    let ctx = Ctx { other_ns: socket_in_our_netns(dup) == Some(false), taint: taint_of(cfg, pid), proto: proto_of_fd(dup) };
    let mut ready = Vec::with_capacity(msgs.len());
    let mut first_err: Option<(i32, Option<&'static str>)> = None;
    for m in msgs {
        match prepare(cfg, pid, dup, family, sotype, flags, &ctx, m) {
            Ok(r) => ready.push(r),
            Err(e) => {
                first_err = Some(e);
                break;
            }
        }
    }
    if ready.is_empty() {
        close_fd(dup);
        let (errno, why) = first_err.unwrap_or((libc::EINVAL, None));
        answer_errno(listener, notif, errno);
        return match why {
            Some(why) => SendOutcome::Refused { errno, why },
            None => SendOutcome::Invalid { errno },
        };
    }
    let job = Job {
        listener,
        id: notif.id,
        pid,
        call,
        flags,
        sotype,
        dup,
        mmsg_vec: a[1],
        ready,
        refused_after: first_err,
        cfg: cfg.clone(),
        _in_flight: in_flight,
        at: 0,
        off: 0,
        results: Vec::new(),
    };
    job.start()
}

/// What every message of one call shares.
struct Ctx {
    /// The socket is of another network namespace (a nested net-dead box):
    /// that namespace is the boundary.
    other_ns: bool,
    taint: Option<(String, bool, Vec<String>)>,
    proto: Proto,
}

/// Judge one message and make it ready to send. `Err((errno, why))`: `why`
/// is set for a refusal of the destination, None for the kernel's own
/// refusal of the message.
#[allow(clippy::too_many_arguments)]
fn prepare(cfg: &GuardConfig, pid: i32, dup: RawFd, family: u16, sotype: i32, flags: i32, ctx: &Ctx, m: Message) -> Result<Ready, (i32, Option<&'static str>)> {
    let other_ns = ctx.other_ns;
    let taint = &ctx.taint;
    let held = matches!(taint, Some((_, true, _)));
    let mut hold: Vec<RawFd> = Vec::new();
    let mut pinned: Option<RawFd> = None;
    let mut gates: Vec<sg::InFlightEgress> = Vec::new();
    let mut name = m.name;
    let mut explicit = false;
    let refuse = |why: &'static str| Err((libc::EACCES, Some(why)));
    let cmsgs = sg::parse_cmsgs(&m.control).map_err(|e| (e, None))?;
    let mut plan = sg::plan_control(family, cmsgs).map_err(|e| (e, if e == libc::EPERM { Some("ancillary data the guard does not send") } else { None }))?;
    match family {
        sg::AF_INET | sg::AF_INET6 => {
            let proto = ctx.proto;
            match sg::inet_send_destination(family, sotype, flags, &name) {
                InetDest::Refused(e) => return Err((e, None)),
                InetDest::Ignored => name.clear(),
                InetDest::NoAddress => {
                    // A holder's send on a connected socket is judged by its
                    // peer: a socket the sweep did not see (accepted, or
                    // received over SCM_RIGHTS after the taint).
                    if held && !other_ns {
                        if let Some((ip, port)) = peer_of(dup) {
                            // A socket a human's Allow once connected to this
                            // peer (confidentiality.md §4, `held_ask`): its
                            // own sends are that connection.
                            let once = fs_supervisor::tracee::fd_identity(dup).is_some_and(|(_, ino)| cfg.once_admitted.contains(ino, ip, port));
                            if !once && taint_leg(cfg, "send", taint, ip, port, proto).is_err() {
                                return refuse("a process holding a secret sends only to its bindings");
                            }
                        }
                    }
                }
                InetDest::Judge(ip, port) => {
                    explicit = true;
                    if !other_ns {
                        let target = Endpoint { ip, port, proto };
                        let (decision, matched) = cfg.policy.decide_matched(&target, cfg.resolver.as_ref());
                        if decision == Decision::Deny {
                            emit_send_decision(cfg, &target, decision, None);
                            return refuse("destination not on the allow list");
                        }
                        if taint_leg(cfg, "send", taint, ip, port, proto).is_err() {
                            return refuse("a process holding a secret sends only to its bindings");
                        }
                        emit_send_decision(cfg, &target, decision, matched);
                    }
                }
            }
        }
        sg::AF_UNIX => {
            if !name.is_empty() {
                explicit = true;
                if cfg.box_sockets.is_some() && is_box_thread(pid, &cfg.box_ancestor) {
                    emit_unix_refusal(cfg, pid, "unix: a datagram from the command box", "the command box connects only to the sockets it bound");
                    return refuse("the command box sends to no Unix address");
                }
                if let Some(pbytes) = crate::guard::unix_pathname_bytes(&name) {
                    match unix_path_verdict(cfg, pid, pbytes, taint.clone(), Some(dup)) {
                        None => return refuse("this kernel cannot resolve a Unix address in the tracee's view"),
                        Some(UnixVerdict::Go { addr, pin, .. }) => {
                            name = addr;
                            pinned = pin;
                            hold.extend(pin);
                        }
                        Some(UnixVerdict::Errno(e)) => return Err((e, None)),
                        Some(UnixVerdict::Refused(_)) => return refuse("Unix address refused"),
                        Some(UnixVerdict::NoHandle { pin, .. }) => {
                            close_fd(pin);
                            return refuse("Unix address refused");
                        }
                    }
                } else if is_abstract_unix(&name) && !other_ns {
                    match abstract_unix_verdict(cfg, pid, dup, &name, taint.clone()) {
                        UnixVerdict::Go { .. } => {}
                        UnixVerdict::Errno(e) => return Err((e, None)),
                        _ => return refuse("Unix address refused"),
                    }
                }
            }
            // P0 2b (2026-10-09): a holder's send with no address on one end
            // of a socket pair whose other end a process outside the guard's
            // tree holds (one the sweep did not see: accepted, passed, or
            // joined outside since) is refused, before a byte is sent.
            if name.is_empty() && held && !other_ns {
                if let Some(dest) = crate::guard_flow::outside_pair_receiver(cfg, dup) {
                    emit_tainted(cfg, "send to", &dest, &TaintedRefusal::default());
                    return refuse("a process holding a secret sends nothing to a program outside Mandu's watch");
                }
            }
            // The tracee's descriptors, copied, in place of its numbers.
            let mut copies = Vec::with_capacity(plan.descriptors.len());
            for n in &plan.descriptors {
                match tracee_fd(pid, *n) {
                    Ok(c) => copies.push(c),
                    Err(_) => {
                        for c in copies {
                            close_fd(c);
                        }
                        for h in hold {
                            close_fd(h);
                        }
                        return Err((libc::EBADF, None));
                    }
                }
            }
            // 2026-10-02: a descriptor passed to a process holding a secret
            // is judged like a socket it already held (guard_rights).
            if !copies.is_empty() && !other_ns {
                let to = match (pinned, name.is_empty()) {
                    (Some(pin), _) => crate::guard_rights::Receiver::Path(pin),
                    (None, false) if is_abstract_unix(&name) => crate::guard_rights::Receiver::Abstract(&name[2..]),
                    _ => crate::guard_rights::Receiver::Peer,
                };
                match crate::guard_rights::judge_pass(cfg, pid, dup, to, &copies) {
                    Ok(g) => gates = g,
                    Err((dest, refusal)) => {
                        for c in copies {
                            close_fd(c);
                        }
                        for h in hold {
                            close_fd(h);
                        }
                        if dest.starts_with("mount:") || dest.starts_with("device:") {
                            emit_tainted(cfg, "receive a writable descriptor of", &dest, &refusal);
                            return refuse("a process holding a secret receives no writable descriptor of a file on an unbound mount or of a device");
                        }
                        emit_tainted(cfg, "receive a connection to", &dest, &refusal);
                        return refuse("a process holding a secret receives no connection to an unbound peer");
                    }
                }
            } else if !copies.is_empty() && other_ns && cfg.secrets.is_some() {
                // Plan 13 §9 R4 (b), 2026-10-04: in a network namespace of
                // its own the guard's `sock_diag` cannot find who receives a
                // descriptor; a writable one of a file on a mount that leaves
                // the machine, or of a device, is not passed there at all
                // (a file is no network object: the namespace changes
                // nothing about where its writes go).
                if let Some(dest) = copies.iter().find_map(|c| crate::guard_rights::passed_exit(cfg, pid, *c)) {
                    for c in copies {
                        close_fd(c);
                    }
                    for h in hold {
                        close_fd(h);
                    }
                    emit_tainted(cfg, "pass, where the guard cannot see who receives it, a writable descriptor of", &dest, &TaintedRefusal::default());
                    return refuse("a writable descriptor of a file on a mount that leaves the machine, or of a device, is not passed in a network namespace the guard cannot see into");
                }
            }
            sg::substitute_descriptors(&mut plan.keep, &copies);
            hold.extend(copies);
        }
        _ => {
            if !name.is_empty() {
                explicit = true;
                if cfg.wsl.is_some() && family == libc::AF_VSOCK as u16 {
                    return refuse("WSL: no AF_VSOCK from the agent's tree");
                }
                if held && !sg::tainted_may_address(family) {
                    emit_tainted(cfg, "send", &format!("family {family}"), &TaintedRefusal::default());
                    return refuse("a process holding a secret addresses only INET and Unix destinations");
                }
            }
        }
    }
    Ok(Ready { name, payload: m.payload, control: sg::build_cmsgs(&plan.keep), hold, explicit, _gates: gates })
}

/// The socket's peer, when it has one.
pub(crate) fn peer_of(fd: RawFd) -> Option<(IpAddr, u16)> {
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: getpeername into a sockaddr_storage.
    if unsafe { libc::getpeername(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len) } != 0 {
        return None;
    }
    // SAFETY: the kernel wrote `len` bytes of the storage.
    let bytes = unsafe { std::slice::from_raw_parts(&ss as *const _ as *const u8, len as usize) };
    match crate::guard::decode_sockaddr(bytes) {
        crate::guard::ConnTarget::Inet(e) => Some((e.ip, e.port)),
        _ => None,
    }
}

/// Send one message on `fd` with `flags`; the count or the errno.
fn send_one(fd: RawFd, name: &[u8], payload: &[u8], control: &[u8], flags: i32) -> Result<usize, i32> {
    let mut iov = libc::iovec { iov_base: payload.as_ptr() as *mut libc::c_void, iov_len: payload.len() };
    // SAFETY: a zeroed msghdr, filled with pointers into buffers that outlive the call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    if !name.is_empty() {
        msg.msg_name = name.as_ptr() as *mut libc::c_void;
        msg.msg_namelen = name.len() as libc::socklen_t;
    }
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !control.is_empty() {
        msg.msg_control = control.as_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.len() as _;
    }
    // SAFETY: sendmsg on a descriptor we own, with the msghdr above.
    let n = unsafe { libc::sendmsg(fd, &msg, flags) };
    if n < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))
    } else {
        Ok(n as usize)
    }
}

/// A send judged and read, to be performed and answered.
struct Job {
    listener: RawFd,
    id: u64,
    pid: i32,
    call: Call,
    flags: i32,
    sotype: i32,
    dup: RawFd,
    mmsg_vec: u64,
    ready: Vec<Ready>,
    /// A message after the first that was refused or malformed: the batch
    /// ends before it (sendmmsg).
    refused_after: Option<(i32, Option<&'static str>)>,
    cfg: GuardConfig,
    _in_flight: Option<sg::InFlightEgress>,
    /// Progress: the message being sent, the bytes of it sent so far, and
    /// the results of the messages before it.
    at: usize,
    off: usize,
    results: Vec<Result<usize, i32>>,
}

impl Drop for Job {
    fn drop(&mut self) {
        close_fd(self.dup);
    }
}

/// Where a job stands after a run.
enum Progress {
    Done,
    /// The next send would block, and the tracee's would have waited.
    MustWait,
    /// The call went away while waiting: nothing more is sent or answered.
    Gone,
}

impl Job {
    /// Does the tracee's own send block (no `MSG_DONTWAIT`, a blocking file)?
    fn blocking(&self) -> bool {
        if self.flags & sg::MSG_DONTWAIT != 0 {
            return false;
        }
        // SAFETY: F_GETFL on a descriptor we own.
        let fl = unsafe { libc::fcntl(self.dup, libc::F_GETFL) };
        fl >= 0 && fl & libc::O_NONBLOCK == 0
    }

    /// Send what is left of message `i` from byte `off`, never blocking. The
    /// address and the ancillary data go with the first bytes only (a stream
    /// send that continues is a plain send). Under the tracee's own Landlock
    /// layers when it names a destination, as a connect to it is.
    fn attempt(&self, i: usize, off: usize) -> Result<usize, i32> {
        let flags = sg::performed_flags(self.flags) | sg::MSG_DONTWAIT;
        let r = &self.ready[i];
        let first = off == 0;
        let (name, control): (&[u8], &[u8]) = if first { (&r.name, &r.control) } else { (&[], &[]) };
        let payload = &r.payload[off..];
        if !(r.explicit && first) {
            return send_one(self.dup, name, payload, control, flags);
        }
        match self.cfg.landlock.connect_via(self.pid) {
            Ok(crate::landlock_mirror::ConnectVia::Guard) => send_one(self.dup, name, payload, control, flags),
            Ok(crate::landlock_mirror::ConnectVia::Mirror(d)) => {
                // The mirror thread gets its own copies of what it sends.
                let (fd, name, payload, control) = (self.dup, name.to_vec(), payload.to_vec(), control.to_vec());
                d.run(move || send_one(fd, &name, &payload, &control, flags)).unwrap_or_else(Err)
            }
            Err(e) => Err(e),
        }
    }

    /// Send the messages in order. A blocking STREAM send is sent whole (the
    /// kernel's own blocking send returns only when every byte is queued); a
    /// datagram goes in one piece or not at all. `can_wait` false: return
    /// `MustWait` where the tracee's send would have waited; true: wait for
    /// room (polling, while the call is live, within `SO_SNDTIMEO`).
    fn run(&mut self, can_wait: bool) -> Progress {
        let blocking = self.blocking();
        let stream = self.sotype == libc::SOCK_STREAM;
        let timeout = sndtimeo(self.dup);
        let mut waited_since: Option<Instant> = None;
        while self.at < self.ready.len() {
            let len = self.ready[self.at].payload.len();
            match self.attempt(self.at, self.off) {
                Ok(n) => {
                    self.off += n;
                    waited_since = None;
                    if stream && blocking && self.off < len {
                        continue;
                    }
                    self.results.push(Ok(self.off));
                    self.at += 1;
                    self.off = 0;
                }
                Err(libc::EAGAIN) if blocking => {
                    if !can_wait {
                        return Progress::MustWait;
                    }
                    let since = *waited_since.get_or_insert_with(Instant::now);
                    if timeout.map(|t| since.elapsed() >= t).unwrap_or(false) {
                        let r = if self.off > 0 { Ok(self.off) } else { Err(libc::EAGAIN) };
                        self.results.push(r);
                        break;
                    }
                    if !notif_id_valid(self.listener, self.id) {
                        return Progress::Gone;
                    }
                    let mut pfd = libc::pollfd { fd: self.dup, events: libc::POLLOUT, revents: 0 };
                    // SAFETY: poll one descriptor we own.
                    let ready = unsafe { libc::poll(&mut pfd, 1, 100) } > 0;
                    if !notif_id_valid(self.listener, self.id) {
                        return Progress::Gone;
                    }
                    if ready {
                        // Writable, and still EAGAIN next time (a Unix
                        // datagram peer's queue is full): back off.
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
                Err(e) => {
                    // Bytes already sent of a stream send are its answer.
                    self.results.push(if self.off > 0 { Ok(self.off) } else { Err(e) });
                    break;
                }
            }
            if self.results.last().map(|r| r.is_err()).unwrap_or(false) {
                break;
            }
        }
        Progress::Done
    }

    /// Run on the receiving worker; a send that must wait goes on a thread of
    /// its own, so no worker is held by a tracee's full socket.
    fn start(mut self) -> SendOutcome {
        match self.run(false) {
            Progress::Done => self.answer(),
            Progress::Gone => SendOutcome::Waiting,
            Progress::MustWait => {
                std::thread::spawn(move || {
                    if let Progress::Done = self.run(true) {
                        self.answer();
                    }
                });
                SendOutcome::Waiting
            }
        }
    }

    /// Answer the call from the per-message results.
    fn answer(&self) -> SendOutcome {
        let results = &self.results;
        let answered = match self.call {
            Call::Sendmmsg => {
                // msg_len of each message sent, then the count.
                for (i, r) in results.iter().enumerate() {
                    if let Ok(n) = r {
                        let at = self.mmsg_vec + (i * sg::MMSGHDR_LEN + sg::MMSG_LEN_OFF) as u64;
                        if write_u32(self.pid, at, *n as u32).is_err() {
                            break;
                        }
                    }
                }
                let mut a = sg::mmsg_answer(results);
                if let (Ok(0), Some((e, _))) = (a, self.refused_after) {
                    a = Err(e);
                }
                a
            }
            _ => results.first().copied().unwrap_or(Err(libc::EIO)),
        };
        match answered {
            Ok(n) => {
                if notif_id_valid(self.listener, self.id) {
                    let _ = respond_value(self.listener, self.id, n as i64);
                }
            }
            Err(e) => {
                if self.sotype == libc::SOCK_STREAM && sg::raises_sigpipe(self.flags, e) {
                    raise_sigpipe(self.pid);
                }
                if notif_id_valid(self.listener, self.id) {
                    let _ = fs_supervisor::kernel::respond_errno(self.listener, self.id, e);
                }
            }
        }
        SendOutcome::Sent { answered }
    }
}

/// `SO_SNDTIMEO` of a socket (None: no timeout).
fn sndtimeo(fd: RawFd) -> Option<Duration> {
    let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
    let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: getsockopt into a timeval.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDTIMEO, &mut tv as *mut _ as *mut libc::c_void, &mut len) };
    if rc != 0 || (tv.tv_sec == 0 && tv.tv_usec == 0) {
        return None;
    }
    Some(Duration::from_secs(tv.tv_sec as u64) + Duration::from_micros(tv.tv_usec as u64))
}

/// Write a `u32` into the tracee (a `sendmmsg` `msg_len`).
fn write_u32(pid: i32, addr: u64, v: u32) -> Result<(), i32> {
    let bytes = v.to_ne_bytes();
    let local = libc::iovec { iov_base: bytes.as_ptr() as *mut libc::c_void, iov_len: 4 };
    let remote = libc::iovec { iov_base: addr as *mut libc::c_void, iov_len: 4 };
    // SAFETY: writes 4 bytes from our buffer into the tracee.
    let n = unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
    if n == 4 { Ok(()) } else { Err(libc::EFAULT) }
}

/// SIGPIPE to the calling thread, as its own send on a broken stream would.
fn raise_sigpipe(tid: i32) {
    let tgid = crate::secret_open::tgid_of(tid);
    // SAFETY: tgkill with integer arguments.
    unsafe { libc::syscall(libc::SYS_tgkill, tgid, tid, libc::SIGPIPE) };
}

/// Kernel < 5.6: no copy of the socket, so nothing can be sent for the
/// tracee. An INET address in the call is judged as read (static list, then
/// a holder's bindings) and refused or CONTINUEd; the kernel re-reads it (the
/// connect leg's documented old-kernel degrade). A holder's send with an
/// address that is not INET is refused.
fn degraded(listener: RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif, call: Call, flags: i32) -> SendOutcome {
    let pid = notif.pid as i32;
    let a = notif.data.args;
    let name = match call {
        Call::Sendto => sg::check_sendto_addrlen(a[4], a[5]).ok().and_then(|n| read_exact(pid, a[4], n).ok()),
        Call::Sendmsg => read_exact(pid, a[1], sg::MSGHDR_LEN)
            .ok()
            .and_then(|b| sg::parse_msghdr(&b))
            .and_then(|h| sg::check_msghdr(&h).ok().and_then(|n| read_exact(pid, h.name, n).ok())),
        // Every message would need judging: refused where a secret is held.
        Call::Sendmmsg => None,
    };
    let taint = taint_of(cfg, pid);
    let held = matches!(taint, Some((_, true, _)));
    match (name, call) {
        (None, Call::Sendmmsg) if held => {
            answer_errno(listener, notif, libc::EACCES);
            SendOutcome::Refused { errno: libc::EACCES, why: "old kernel: a holder's batch send is refused" }
        }
        (Some(name), _) if !name.is_empty() => {
            let fam = if name.len() >= 2 { u16::from_ne_bytes([name[0], name[1]]) } else { 0 };
            let dest = match fam {
                sg::AF_INET6 => sg::inet_send_destination(sg::AF_INET6, libc::SOCK_DGRAM, flags, &name),
                sg::AF_INET | sg::AF_UNSPEC => sg::inet_send_destination(sg::AF_INET, libc::SOCK_DGRAM, flags, &name),
                _ => InetDest::NoAddress,
            };
            if let InetDest::Judge(ip, port) = dest {
                let target = Endpoint { ip, port, proto: Proto::Udp };
                if cfg.policy.decide(&target, cfg.resolver.as_ref()) == Decision::Deny || taint_leg(cfg, "send", &taint, ip, port, Proto::Udp).is_err() {
                    answer_errno(listener, notif, libc::EACCES);
                    return SendOutcome::Refused { errno: libc::EACCES, why: "destination refused" };
                }
            } else if held && fam != sg::AF_UNIX && fam != sg::AF_NETLINK {
                answer_errno(listener, notif, libc::EACCES);
                return SendOutcome::Refused { errno: libc::EACCES, why: "old kernel: a holder's address is refused" };
            }
            answer_continue(listener, notif);
            SendOutcome::Continued { why: "kernel < 5.6: judged as read, continued" }
        }
        _ => {
            answer_continue(listener, notif);
            SendOutcome::Continued { why: "kernel < 5.6: no address, continued" }
        }
    }
}

// ── the taint-time sweep ────────────────────────────────────────────────────

/// The processes a taint of `tgid` reaches: it and its descendants, by
/// `/proc/<p>/task/<t>/children`.
pub(crate) fn subtree(tgid: i32) -> Vec<i32> {
    let mut out = Vec::new();
    let mut todo = vec![tgid];
    let mut seen = std::collections::HashSet::new();
    while let Some(p) = todo.pop() {
        if seen.len() > 8192 || !seen.insert(p) {
            continue;
        }
        out.push(p);
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{p}/task")) else { continue };
        for t in tasks.flatten() {
            let Some(tid) = t.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
            if let Ok(ch) = std::fs::read_to_string(format!("/proc/{p}/task/{tid}/children")) {
                todo.extend(ch.split_whitespace().filter_map(|c| c.parse::<i32>().ok()));
            }
        }
    }
    out
}

/// The socket inodes a process's descriptor tables hold: `(fd, inode)` of
/// the leader's table, and whether a thread holds a socket the leader's
/// table does not (a thread with a table of its own).
pub(crate) fn socket_fds(p: i32) -> (Vec<(RawFd, u64)>, bool) {
    let read = |dir: String| -> Vec<(RawFd, u64)> {
        let Ok(rd) = std::fs::read_dir(&dir) else { return Vec::new() };
        rd.flatten()
            .filter_map(|e| {
                let fd = e.file_name().to_str()?.parse::<RawFd>().ok()?;
                let link = std::fs::read_link(e.path()).ok()?;
                let ino = link.to_str()?.strip_prefix("socket:[")?.strip_suffix(']')?.parse::<u64>().ok()?;
                Some((fd, ino))
            })
            .collect()
    };
    // The leader's table once any exec it is inside has ended (2026-10-17:
    // read inside one it was empty, and a connection that survives the exec
    // went unjudged; `pipe_flow::fd_table_read`).
    let leader: Vec<(RawFd, u64)> = crate::pipe_flow::fd_table(p)
        .into_iter()
        .filter_map(|h| Some((h.fd, h.link.strip_prefix("socket:[")?.strip_suffix(']')?.parse::<u64>().ok()?)))
        .collect();
    let mut own_table = false;
    if let Ok(tasks) = std::fs::read_dir(format!("/proc/{p}/task")) {
        for t in tasks.flatten() {
            let Some(tid) = t.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
            if tid == p {
                continue;
            }
            if read(format!("/proc/{p}/task/{tid}/fd")).iter().any(|(_, ino)| !leader.iter().any(|(_, l)| l == ino)) {
                own_table = true;
            }
        }
    }
    (leader, own_table)
}

/// What a held socket is (`send_guard::HeldSocket`).
fn classify(p: i32, fd: RawFd, ino: u64) -> sg::HeldSocket {
    let copy = match tracee_fd(p, fd) {
        Ok(c) => c,
        // Closed since the listing: not held.
        Err(e) if matches!(e.raw_os_error(), Some(libc::EBADF) | Some(libc::ENOENT) | Some(libc::ESRCH)) => return sg::HeldSocket::NotInet,
        Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => return classify_by_proc_net(ino),
        Err(_) => return sg::HeldSocket::Unknown("no copy of the socket"),
    };
    let out = classify_copy(copy, ino);
    close_fd(copy);
    out
}

pub(crate) fn classify_copy(copy: RawFd, ino: u64) -> sg::HeldSocket {
    let Some(family) = sockopt_int(copy, libc::SO_DOMAIN).map(|f| f as u16) else { return sg::HeldSocket::Unknown("no SO_DOMAIN") };
    if family == sg::AF_UNIX {
        return classify_unix(copy);
    }
    if family != sg::AF_INET && family != sg::AF_INET6 {
        return if sg::tainted_may_address(family) { sg::HeldSocket::NotInet } else { sg::HeldSocket::Unknown("a socket of a family no binding names") };
    }
    if socket_in_our_netns(copy) == Some(false) {
        return sg::HeldSocket::OtherNetns;
    }
    if sockopt_int(copy, libc::SO_ACCEPTCONN) == Some(1) {
        return sg::HeldSocket::Listening;
    }
    let proto = proto_of_fd(copy);
    if let Some((ip, port)) = peer_of(copy) {
        return sg::HeldSocket::Peer(ip, port, proto);
    }
    // No peer name: unconnected, or a connect in flight (SYN_SENT answers
    // ENOTCONN), which /proc/net names. A TCP socket says which by its state
    // (an unconnected one is in no /proc/net table at all).
    if proto == Proto::Tcp {
        return match tcp_state(copy) {
            Some(sg::TCP_CLOSE) => sg::HeldSocket::Unconnected,
            Some(sg::TCP_SYN_SENT) => match classify_by_proc_net(ino) {
                p @ sg::HeldSocket::Peer(..) => p,
                _ => sg::HeldSocket::Unknown("a TCP connect in flight that /proc/net does not list"),
            },
            _ => sg::HeldSocket::Unknown("a TCP socket with no peer name"),
        };
    }
    sg::HeldSocket::Unconnected
}

/// A Unix socket a process holds when it becomes tainted (2026-10-02): what
/// it already queued is read for a descriptor (`guard_rights::
/// queued_rights`: its receipt would be no call the guard sees); then it is
/// judged by its peer: a listener is the accept gate's, a connection to a
/// NAMED peer (a path, `@name`) is judged like a tainted Unix connect to it,
/// an unnamed peer (a socketpair, a client of the holder's own listener) is
/// local IPC like a pipe. (Also how a Unix socket PASSED to a holder is
/// judged, `guard_rights::judge_pass`.)
fn classify_unix(copy: RawFd) -> sg::HeldSocket {
    if sockopt_int(copy, libc::SO_ACCEPTCONN) == Some(1) {
        return sg::HeldSocket::Listening;
    }
    match crate::guard_rights::queued_rights(copy) {
        sg::QueueCheck::Clear => {}
        sg::QueueCheck::Rights => return sg::HeldSocket::Unknown("a descriptor queued on a Unix socket"),
        sg::QueueCheck::Unknown(why) => return sg::HeldSocket::Unknown(why),
    }
    match unix_peer_name(copy) {
        Some(name) => sg::HeldSocket::UnixPeer(name),
        None => sg::HeldSocket::NotInet,
    }
}

/// The name a Unix socket's peer is bound to (`/path`, or `@name` for the
/// abstract namespace); None for an unnamed peer or none.
pub(crate) fn unix_peer_name(fd: RawFd) -> Option<String> {
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: getpeername into a sockaddr_storage.
    if unsafe { libc::getpeername(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len) } != 0 {
        return None;
    }
    // SAFETY: the kernel wrote `len` bytes of the storage.
    let bytes = unsafe { std::slice::from_raw_parts(&ss as *const _ as *const u8, (len as usize).min(std::mem::size_of::<libc::sockaddr_storage>())) };
    crate::secret_open::unix_path_of(bytes).filter(|n| !n.is_empty() && n != "@")
}

/// Do a holder's bindings admit a named Unix peer: the arbiter's socket, or
/// a `unix:` binding (as written and as resolved), as the AF_UNIX taint leg
/// reads them.
pub(crate) fn unix_bindings_admit(bindings: &[String], name: &str) -> bool {
    if crate::guard_kernel::is_arbiter_socket(name) {
        return true;
    }
    let mut bound = bindings.to_vec();
    bound.extend(bindings.iter().filter_map(|p| p.strip_prefix("unix:")).filter_map(|p| std::fs::canonicalize(p).ok()).filter_map(|c| c.to_str().map(|c| format!("unix:{c}"))));
    crate::secret_open::unix_path_bound(name, &bound)
}

/// `tcpi_state`, the first byte of `TCP_INFO`.
fn tcp_state(fd: RawFd) -> Option<u8> {
    let mut info = [0u8; 256];
    let mut len = info.len() as libc::socklen_t;
    // SAFETY: getsockopt into a byte buffer of `len` bytes.
    let rc = unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, info.as_mut_ptr() as *mut libc::c_void, &mut len) };
    (rc == 0 && len >= 1).then_some(info[0])
}

/// Classify a socket by its inode in this namespace's `/proc/net` tables
/// (no copy: an old kernel, or a TCP connect in flight). Not found in any:
/// a Unix socket is NotInet; anything else is Unknown.
fn classify_by_proc_net(ino: u64) -> sg::HeldSocket {
    for (table, v6, proto) in [
        ("tcp", false, Proto::Tcp),
        ("tcp6", true, Proto::Tcp),
        ("udp", false, Proto::Udp),
        ("udp6", true, Proto::Udp),
        ("udplite", false, Proto::Other),
        ("udplite6", true, Proto::Other),
        ("raw", false, Proto::Other),
        ("raw6", true, Proto::Other),
        ("icmp", false, Proto::Other),
        ("icmp6", true, Proto::Other),
    ] {
        let Ok(text) = std::fs::read_to_string(format!("/proc/self/net/{table}")) else { continue };
        if let Some(s) = sg::proc_net_lookup(&text, ino, v6) {
            if s.state == sg::TCP_LISTEN && proto == Proto::Tcp {
                return sg::HeldSocket::Listening;
            }
            let unspecified = match s.remote {
                IpAddr::V4(a) => a.is_unspecified(),
                IpAddr::V6(a) => a.is_unspecified(),
            };
            return if unspecified && s.port == 0 { sg::HeldSocket::Unconnected } else { sg::HeldSocket::Peer(s.remote, s.port, proto) };
        }
    }
    let is_unix = std::fs::read_to_string("/proc/self/net/unix")
        .map(|t| t.lines().skip(1).any(|l| l.split_whitespace().nth(6).and_then(|v| v.parse::<u64>().ok()) == Some(ino)))
        .unwrap_or(false);
    let is_netlink = std::fs::read_to_string("/proc/self/net/netlink")
        .map(|t| t.lines().skip(1).any(|l| l.split_whitespace().nth(9).and_then(|v| v.parse::<u64>().ok()) == Some(ino)))
        .unwrap_or(false);
    if is_unix || is_netlink { sg::HeldSocket::NotInet } else { sg::HeldSocket::Unknown("a socket /proc/net does not list") }
}

/// Plan 10 §4.3 for sockets that exist when a process becomes tainted
/// (exec-routing.md §7.5, 2026-10-01, finding path 2). Called by the open
/// handler AFTER it recorded the taint and BEFORE the reader gets a byte:
///
/// 1. the processes the taint reaches (the reader and its descendants) wait
///    for their connects and sends judged before the taint
///    (`EgressGate::wait_idle`, bounded by `TAINT_WAIT`), so none completes
///    after this look;
/// 2. every INET socket they hold is classified (`classify`) and its peer
///    judged like a tainted connect to it: a session proxy, or a binding of
///    what the process holds; since 2026-10-02 a Unix socket connected to a
///    named peer is judged like a tainted Unix connect (`classify_unix`),
///    and what a Unix socket has queued is read for a descriptor;
/// 3. the listing repeats until no new process appears (a fork racing the
///    sweep); each descendant is remembered as a holder, with its chain.
///
/// 4. (plan 13 D5, 2026-10-02) every REGULAR file they hold open for
///    writing is listed (`pipe_flow::written_files`): the caller labels each
///    at the taint's level before the reader gets a byte, as if it had been
///    opened after the taint (`python3 reader.py > out.txt` opens `out.txt`
///    before python reads the secret).
/// 5. (plan 13 D2, 2026-10-02) every process of the guard's tree that
///    receives what they write through a pipe, a FIFO or an unnamed socket
///    pair (`guard_flow::flow_readers`; never the agent) becomes a holder
///    flowing from them, and its tree is swept the same way: its sockets
///    judged (an unbound one refuses THIS open: `reader | nc evil 80`), its
///    files listed, its own pipes followed (`a | b | c`).
/// 6. (plan 13 §4.9, 2026-10-03) the parent and the tracer of every process
///    made a holder here learn its exit status (`guard_wait::
///    status_receivers`; never the agent or above it): each becomes a
///    holder flowing from it and its tree is swept the same way, up the
///    chain (`cat .env | prog; curl "…?b=$?"`: the shell).
///
/// `Err((dest, refusal))` = the open must be refused (fail-closed: a socket
/// the guard cannot judge, an arbiter that cannot be asked, or in-flight
/// egress that does not finish in time are refusals too). A thread with a
/// descriptor table of its own is a socket the guard cannot see: refused.
pub fn sweep_before_taint(cfg: &GuardConfig, pid: i32) -> Result<Vec<HeldWrite>, (String, TaintedRefusal)> {
    let tgid = crate::secret_open::tgid_of(pid);
    sweep_from(cfg, vec![tgid], Some(tgid), &[], &[], None)
}

/// Plan 13 §9 R1 (2026-10-02): sweep processes that have just become
/// holders through a channel joined AFTER a holder's taint (a connection
/// the holder accepts, a socket-pair end or pipe end passed over
/// `SCM_RIGHTS`), as the taint-time sweep sweeps a reader's pipe receivers:
/// their trees' sockets judged against what they now hold (an unbound one
/// refuses the event that joins them), their files listed for the label,
/// their own pipes followed. `receivers` are already holders flowing from
/// the writer (`TaintedSet::insert_flow`). `channel`: the socket inodes
/// that join them to the holder, which are the flow itself and not an exit
/// (a client's connection to the holder's listener would otherwise be
/// judged as a connect to that listener). `exclude`: the writer's
/// processes, never re-swept as receivers of the receivers.
///
/// `caller`: the process whose own call is being judged (a sender that the
/// pass makes a holder), whose one call in flight is not waited for.
pub fn sweep_receivers(cfg: &GuardConfig, receivers: Vec<i32>, channel: &[u64], exclude: &[i32], caller: Option<i32>) -> Result<Vec<HeldWrite>, (String, TaintedRefusal)> {
    let roots: Vec<i32> = receivers.into_iter().map(crate::secret_open::tgid_of).collect();
    sweep_from(cfg, roots, None, channel, exclude, caller.map(crate::secret_open::tgid_of))
}

/// The most trees one sweep follows (the reader's, its receivers', their
/// ancestors' for the exit status); more refuses the event (fail-closed).
const MAX_SWEEP_ROOTS: usize = 256;

/// The sweep's worklist (`sweep_before_taint`'s steps 1 to 5) from `roots`;
/// `reader`: the process whose raw open is being answered (the others are
/// remembered as inheriting holders).
fn sweep_from(cfg: &GuardConfig, roots: Vec<i32>, reader: Option<i32>, channel: &[u64], exclude: &[i32], caller: Option<i32>) -> Result<Vec<HeldWrite>, (String, TaintedRefusal)> {
    let deadline = Instant::now() + sg::TAINT_WAIT;
    let mut swept: std::collections::HashSet<i32> = std::collections::HashSet::new();
    let mut seen_inodes: std::collections::HashSet<u64> = channel.iter().copied().collect();
    let mut writes: Vec<HeldWrite> = Vec::new();
    // Plan 13 D2: the trees to sweep, the reader's first, then the tree of
    // each process found receiving what a swept tree writes (a pipeline's
    // next stage, a FIFO's reader, a socket pair's other end).
    let mut roots: Vec<i32> = roots;
    let mut next = 0;
    while next < roots.len() {
        if next >= MAX_SWEEP_ROOTS {
            return Err(("more processes receiving what a holder holds than the guard follows at once".into(), TaintedRefusal::default()));
        }
        let root = roots[next];
        next += 1;
        // Plan 13 §9 R1, the file shapes: the objects this tree can write.
        let mut root_objects: Vec<crate::object_flow::ObjectTarget> = Vec::new();
        // Per tree: each round lists the tree again until nothing new
        // appears (an ancestor's tree, swept for the exit status below,
        // takes two rounds however deep the chain).
        let mut rounds = 0;
        loop {
            rounds += 1;
            if rounds > 64 {
                return Err(("a process tree that kept growing while the guard looked".into(), TaintedRefusal::default()));
            }
            let procs = subtree(root);
            let fresh: Vec<i32> = procs.iter().copied().filter(|p| !swept.contains(p)).collect();
            if fresh.is_empty() {
                break;
            }
            if !cfg.egress.wait_idle_but(&procs, caller, deadline.saturating_duration_since(Instant::now())) {
                return Err(("a connect or send still in flight".into(), TaintedRefusal::default()));
            }
            for p in fresh {
                swept.insert(p);
                // 2026-10-17: a process inside an exec hides its descriptor
                // table and its mappings until the exec ends; every look
                // below waits for that (`pipe_flow::fd_table_read`). One
                // whose exec does not end is refused, as a table the sweep
                // cannot read whole is (fail-closed).
                if crate::pipe_flow::fd_table_read(p) == crate::pipe_flow::TableRead::Unsettled {
                    return Err(("a process whose descriptor table an exec that does not end hides".into(), TaintedRefusal::default()));
                }
                let (fds, own_table) = socket_fds(p);
                if own_table {
                    return Err(("a socket held by a thread with its own descriptor table".into(), TaintedRefusal::default()));
                }
                let mut held: Vec<sg::HeldSocket> = Vec::new();
                for (fd, ino) in fds {
                    if !seen_inodes.insert(ino) {
                        continue;
                    }
                    // Plan 13 §4.5.1 (decision 2026-10-02): a connection whose
                    // other end the agent itself holds (a keep-alive it opened
                    // before this process read its secret) is recorded as an
                    // agent flow, which the model exit masks, not judged as an
                    // exit (that refused the raw open: an HTTP MCP server could
                    // not read its `.env` while the agent was connected); the
                    // agent's connections waiting on a listener are recorded
                    // too (the old-kernel degrade); a connection the session's
                    // net-proxy relays refuses the raw open (the proxy leg). A
                    // record that fails refuses the raw open (fail-closed).
                    match crate::guard_flow::sweep_local_channel(cfg, p, ino) {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(e) => return Err((e, TaintedRefusal::default())),
                    }
                    held.push(classify(p, fd, ino));
                }
                let own = crate::secret_open::own_key_of(p);
                let chain = crate::secret_open::ancestor_keys_of(p, 16);
                if Some(p) != reader {
                    cfg.tainted.inherit(&own, &chain);
                }
                // Plan 13 §9 R4 (b): what it already writes that leaves this
                // machine or this user (a file on a network or FUSE mount, a
                // device node, a file other users can read: narrowed now).
                held_local_exits(cfg, p, &own, &chain)?;
                for f in crate::pipe_flow::written_files(p) {
                    writes.push(HeldWrite { own: own.clone(), chain: chain.clone(), path: f.path, id: Some(f.id) });
                }
                // Plan 13 §9 R1, the file shapes: every object it can write
                // (a descriptor, a writable shared mapping: a `/dev/shm`
                // file, a memfd, an unlinked file, a SysV segment). A mapped
                // file with a path takes the label as a descriptor's does.
                // A writable shared MAPPING is narrowed by its path here;
                // a descriptor only by its copy above (`held_local_exits`),
                // never by the path its link showed a moment ago.
                for m in crate::object_flow::written_mappings(p) {
                    if let Some(path) = m.path.as_deref().and_then(crate::pipe_flow::labelable_target) {
                        mapped_local_exit(cfg, p, path, &m.keys, &own, &chain)?;
                    }
                }
                for o in crate::object_flow::written_objects(p) {
                    if let Some(path) = o.path.as_deref().and_then(crate::pipe_flow::labelable_target) {
                        if !writes.iter().any(|w| w.own == own && w.path == path) {
                            let id = o.keys.iter().find_map(|k| crate::object_flow::file_id_of_key(k));
                            writes.push(HeldWrite { own: own.clone(), chain: chain.clone(), path: path.to_string(), id });
                        }
                    }
                    if !root_objects.contains(&o) {
                        root_objects.push(o);
                    }
                }
                let needs_bindings = held.iter().any(|h| match h {
                    sg::HeldSocket::Peer(ip, port, proto) => !sg::is_session_proxy(*ip, *port, *proto, &cfg.proxy_ports),
                    sg::HeldSocket::UnixPeer(name) => !crate::guard_kernel::is_arbiter_socket(name),
                    _ => false,
                });
                let bindings = if needs_bindings { taint_bindings(cfg, &own, chain) } else { Some(TaintedRefusal::default()) };
                let Some(bindings) = bindings else {
                    return Err(("an unbound peer (the arbiter could not be asked for the bindings)".into(), TaintedRefusal::default()));
                };
                let admitted = |ip: IpAddr, port: u16, proto: Proto| sg::is_session_proxy(ip, port, proto, &cfg.proxy_ports) || bindings_admit(cfg, &bindings.bindings, ip, port, proto);
                let unix_admitted = |name: &str| unix_bindings_admit(&bindings.bindings, name);
                if let Err(dest) = sg::sweep_verdict(&held, admitted, unix_admitted) {
                    return Err((dest, bindings));
                }
            }
        }
        // Plan 13 §4.9 (2026-10-03): the root's exit status reaches its
        // parent (by `wait`, and by `SIGCHLD`'s `siginfo` at the exit
        // itself) and its tracer, a channel open since the fork, like a
        // pipe this sweep finds: each becomes a holder flowing from the
        // root and its tree is swept next (an unbound connection it holds
        // refuses the raw open), and so on up to the agent's own child.
        // Never the agent, above it, or the guard (`guard_wait`).
        let receivers = crate::guard_wait::status_receivers(cfg, root);
        if receivers.iter().any(|r| !swept.contains(r) && !roots.contains(r) && !exclude.contains(r)) {
            let from = cfg.tainted.flow_sources(&[crate::guard_flow::writer_entry(root)]);
            for r in receivers {
                if swept.contains(&r) || roots.contains(&r) || exclude.contains(&r) {
                    continue;
                }
                crate::guard_flow::flow_holder(cfg, &crate::secret_open::own_key_of(r), &from);
                roots.push(r);
            }
        }
        // Plan 13 D2: who receives what this tree writes. Each becomes a
        // holder flowing from the tree's root (and what the root flows
        // from), and its own tree is swept next.
        let tree: Vec<i32> = subtree(root).into_iter().filter(|p| swept.contains(p)).collect();
        let targets = crate::guard_flow::flow_targets(&tree);
        if targets.is_empty() && root_objects.is_empty() {
            continue;
        }
        let from = cfg.tainted.flow_sources(&[crate::guard_flow::writer_entry(root)]);
        // Marked, so a receiver that acts after this tree is gone is judged
        // by them (`guard_flow::holder`).
        for t in &targets {
            cfg.tainted.mark_link(t, &from);
        }
        // Plan 13 §4.5.1 (2026-10-02): a FIFO this tree writes that the
        // agent itself reads (its file tool on a named pipe; never a
        // receiver below) is an agent flow, recorded before a byte flows.
        if let Err(e) = crate::guard_flow::sweep_fifo_writes(cfg, &tree, &from) {
            return Err((format!("the agent's read end of a FIFO this process writes (the arbiter could not record it: {e})"), TaintedRefusal::default()));
        }
        let mut skip: std::collections::HashSet<i32> = swept.clone();
        skip.extend(roots.iter().copied());
        skip.extend(exclude.iter().copied());
        // Before the raw open (or the joining event) is answered: no byte
        // has flowed yet.
        let mut readers = if targets.is_empty() { Vec::new() } else { crate::guard_flow::flow_readers(cfg, &targets, &skip, true) };
        // Plan 13 §9 R1, the file shapes: who reads an object this tree
        // can write (marked first, so an open racing this look is seen by
        // one side or the other, `object_flow::ObjectOpens`).
        let mut object_readers: Vec<i32> = Vec::new();
        if !root_objects.is_empty() {
            // Plan 13 §4.5.1 (2026-10-02): the agent itself reading one (never
            // a receiver below) is an agent flow, recorded before a byte flows.
            if let Err(e) = crate::guard_flow::agent_object_reads(cfg, &root_objects, &from, true) {
                return Err((format!("the agent, which reads a file this process writes (the arbiter could not record its flow: {e})"), TaintedRefusal::default()));
            }
            for q in crate::guard_flow::object_receivers(cfg, &root_objects, &from, &skip, true) {
                if !object_readers.contains(&q) {
                    object_readers.push(q);
                }
                if !readers.contains(&q) {
                    readers.push(q);
                }
            }
        }
        // The named pipes among the targets (a path, not `pipe:[…]` or a
        // socket): what a file tool can open.
        let fifo_targets: Vec<String> = targets.iter().filter(|t| t.starts_with('/')).cloned().collect();
        for q in readers {
            let q = crate::secret_open::tgid_of(q);
            // A reader the agent ran itself (a file tool's child, Grep's
            // `rg`) of a named pipe or a file object: its output is the
            // agent's tool result, masked by an agent flow. Not for an
            // anonymous pipe or a socket pair (a Bash call's stages, an MCP
            // server's own child: their results are folded elsewhere, and an
            // agent flow would mask every tool result in its window).
            let own = crate::secret_open::own_key_of(q);
            if object_readers.contains(&q) || crate::pipe_flow::reads_any(q, &fifo_targets) {
                if let Err(e) = crate::guard_flow::agent_child_receipt(cfg, &[q], &format!("flow:{own}"), &from) {
                    return Err((format!("an agent tool reading what a holder writes (the flow could not be recorded: {e})"), TaintedRefusal::default()));
                }
            }
            crate::guard_flow::flow_holder(cfg, &own, &from);
            if !roots.contains(&q) {
                roots.push(q);
            }
        }
    }
    // P0 2b (2026-10-09): a process OUTSIDE the guard's tree that receives
    // what a swept process writes (the read end of its pipe, the other end
    // of its socket pair, a FIFO it holds open for writing) is no receiver
    // the guard can confine: the event is refused, before a byte flows. The
    // session's human plane (the stdio the launch handed the tree) is left
    // out; one scan of `/proc` for every tree swept.
    let all: Vec<i32> = swept.iter().copied().collect();
    let (chans, fifos) = crate::guard_flow::written_channels(&all);
    if let Some(dest) = crate::guard_flow::outside_receiver(cfg, &chans, &fifos) {
        return Err((dest, TaintedRefusal::default()));
    }
    Ok(writes)
}

/// The mount verdict of a file a process about to hold writes: `Err` when it
/// leaves the machine and what `own` holds is not bound to it.
fn mount_exit(cfg: &GuardConfig, facts: &crate::local_exits::FsFacts, own: &str, chain: &[String]) -> Result<(), (String, TaintedRefusal)> {
    use crate::local_exits as le;
    let le::MountVerdict::Remote(dest) = le::mount_verdict(facts, &cfg.extra_remote_devs) else { return Ok(()) };
    match taint_bindings(cfg, own, chain.to_vec()) {
        Some(b) if le::mount_bound(&b.bindings, &dest) => Ok(()),
        Some(b) => Err((dest, b)),
        None => Err((dest, TaintedRefusal::default())),
    }
}

/// Plan 13 §9 R4 (b) at the taint-time sweep (the later of the two events,
/// §4.5): the descriptors process `p` holds open for writing, before it
/// holds a secret. A device that is not the terminal or a sink that keeps
/// nothing, and a file on a mount that leaves the machine (unless bound),
/// refuse the raw open; a file other local users can read has its group
/// and other bits stripped now (one the guard cannot narrow refuses the raw
/// open).
///
/// Each candidate is judged and narrowed on a `pidfd_getfd` COPY of the
/// descriptor (2026-10-04): its access mode, type, file system and mode are
/// read from that one open file and `fchmod` acts on it. Looked up again
/// through `/proc/<p>/fd/<n>`, a descriptor the process closed and reused
/// meanwhile named another file (seen in the kernel tests: a protected file
/// a concurrent test had pinned went 0600), and a file the process held only
/// to read, or as `O_PATH`, could be narrowed. A descriptor closed meanwhile
/// is not held; one the guard cannot copy refuses the raw open.
fn held_local_exits(cfg: &GuardConfig, p: i32, own: &str, chain: &[String]) -> Result<(), (String, TaintedRefusal)> {
    for h in crate::pipe_flow::fd_table(p) {
        // The cheap look first: a descriptor that reads only is not copied
        // (one reopened for writing after this look is an open the guard
        // performs for a holder).
        if !crate::pipe_flow::accmode_of(p, h.fd).map(crate::pipe_flow::accmode_writes).unwrap_or(false) {
            continue;
        }
        let copy = match tracee_fd(p, h.fd) {
            Ok(c) => c,
            Err(e) if matches!(e.raw_os_error(), Some(libc::EBADF) | Some(libc::ENOENT) | Some(libc::ESRCH)) => continue,
            Err(_) => return Err((format!("a descriptor the guard could not copy ({})", h.link), TaintedRefusal::default())),
        };
        let r = held_copy_exit(cfg, p, copy, &h.link, own, chain);
        close_fd(copy);
        r?;
    }
    Ok(())
}

/// `held_local_exits` for one descriptor, on the guard's copy `c` of it.
fn held_copy_exit(cfg: &GuardConfig, p: i32, c: RawFd, link: &str, own: &str, chain: &[String]) -> Result<(), (String, TaintedRefusal)> {
    use crate::local_exits as le;
    // SAFETY: F_GETFL on our own descriptor.
    let fl = unsafe { libc::fcntl(c, libc::F_GETFL) };
    if fl < 0 || fl & libc::O_PATH != 0 || !crate::pipe_flow::accmode_writes(fl & libc::O_ACCMODE) {
        return Ok(());
    }
    // SAFETY: fstat of our own descriptor into a zeroed buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(c, &mut st) } != 0 {
        return Err((format!("a descriptor the guard could not read ({link})"), TaintedRefusal::default()));
    }
    let kind = st.st_mode & libc::S_IFMT;
    if kind == libc::S_IFCHR || kind == libc::S_IFBLK {
        let (major, minor) = le::dev_major_minor(st.st_rdev);
        if !le::device_write_allowed(kind == libc::S_IFBLK, major, minor) {
            return Err((le::device_destination(link, major, minor), TaintedRefusal::default()));
        }
        return Ok(());
    }
    if kind != libc::S_IFREG {
        return Ok(());
    }
    mount_exit(cfg, &le::fd_fs_facts(c, Some(p)), own, chain)?;
    if let Some(narrow) = le::narrowed_mode(st.st_mode) {
        // SAFETY: fchmod of our copy: exactly the file the process holds.
        if unsafe { libc::fchmod(c, narrow as libc::mode_t) } != 0 {
            return Err((format!("other local users ({link})"), TaintedRefusal::default()));
        }
    }
    Ok(())
}

/// `held_local_exits` for a file a process has mapped shared and writable
/// (plan 13 §9 R1's file shapes), named by the path `/proc/<p>/maps` gives
/// and `keys` (`object_flow::file_key`, its device and inode). The path is
/// opened once and judged only when it is still that file (2026-10-04): a
/// path renamed onto meanwhile names another file, which is not narrowed;
/// the mapped one then cannot be, and the raw open is refused.
fn mapped_local_exit(cfg: &GuardConfig, p: i32, path: &str, keys: &[String], own: &str, chain: &[String]) -> Result<(), (String, TaintedRefusal)> {
    use crate::local_exits as le;
    let Ok(cpath) = std::ffi::CString::new(path) else { return Ok(()) };
    // SAFETY: an O_PATH open of a NUL-terminated path; closed below.
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Ok(());
    }
    let r = (|| {
        // SAFETY: fstat of our own descriptor into a zeroed buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Ok(());
        }
        let wide = le::narrowed_mode(st.st_mode);
        if !crate::object_flow::key_names_file(keys, st.st_dev, st.st_ino) {
            // Another file at the path now: the mapped one is not looked at
            // again by name, and cannot be narrowed (fail-closed).
            return Err((format!("other local users ({path})"), TaintedRefusal::default()));
        }
        mount_exit(cfg, &le::fd_fs_facts(fd, Some(p)), own, chain)?;
        if let Some(narrow) = wide {
            let magic = std::ffi::CString::new(format!("/proc/self/fd/{fd}")).map_err(|_| (format!("other local users ({path})"), TaintedRefusal::default()))?;
            // SAFETY: chmod through our own O_PATH descriptor's magic link:
            // exactly the file just checked.
            if unsafe { libc::chmod(magic.as_ptr(), narrow as libc::mode_t) } != 0 {
                return Err((format!("other local users ({path})"), TaintedRefusal::default()));
            }
        }
        Ok(())
    })();
    close_fd(fd);
    r
}

/// A file a process held open for writing when it became a holder (plan 13
/// D5): labeled by the caller as written by `own` (with `chain`, the
/// ancestors through which it holds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldWrite {
    pub own: String,
    pub chain: Vec<String>,
    pub path: String,
    /// The held file's `(st_dev, st_ino)`, read with its path from the
    /// descriptor (`pipe_flow::fd_file`, 2026-10-17): the derived index keys
    /// the label by THIS file, not by whatever the path names when the
    /// label lands.
    pub id: Option<(u64, u64)>,
}

/// The refusal of a raw open by the sweep: the plan 10 §4.3 event, named for
/// what was refused (the connection the reader already held, or the file on
/// a mount, the device, the file other users read that it held open for
/// writing: `local_exits::held_exit_phrase`).
pub fn emit_sweep_refusal(cfg: &GuardConfig, file: &str, dest: &str, refusal: &TaintedRefusal) {
    let mut r = refusal.clone();
    if r.files.is_empty() {
        r.files = vec![file.to_string()];
    }
    emit_tainted(cfg, crate::local_exits::held_exit_phrase(dest).0, dest, &r);
}
