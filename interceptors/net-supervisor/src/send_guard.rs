//! send_guard — the PURE half of judging a SEND (exec-routing.md §7.5,
//! "Sends are judged like connects", 2026-10-01).
//!
//! Until 2026-10-01 the guard judged a process's egress at `connect(2)` only,
//! so three paths skipped it (the OPEN FINDING of that day): a datagram sent
//! with an explicit address (`sendto`, `sendmsg`, `sendmmsg`, a DNS query
//! among them), a socket connected before the process read a secret, and
//! `127.0.0.1` on any port for a tainted process. The kernel leg
//! (`guard_send`, feature `kernel`) now traps every send that can carry an
//! address and performs it on its own copy of the socket; the taint leg
//! judges, at the moment a process becomes tainted, every INET socket it and
//! its descendants already hold (`guard_kernel` "the taint-time sweep").
//!
//! This module holds what those legs decide, with no syscalls:
//!   - which destination the KERNEL would use for an address a send names, by
//!     the socket's family and type (`inet_send_destination`): a stream
//!     socket ignores it unless `MSG_FASTOPEN`; a UDP socket of `AF_INET`
//!     takes an `AF_UNSPEC` address as an `AF_INET` one; an `AF_INET6` socket
//!     takes an `AF_INET` address (v4 over v6) and treats `AF_UNSPEC` as no
//!     address. Judging what the kernel will use, not what the family field
//!     says, is the point: the guard sends the very bytes it judged.
//!   - the `msghdr` / `mmsghdr` / `iovec` / `cmsghdr` layouts (LP64) and the
//!     kernel's own refusals of a malformed message, so the guard answers what
//!     the tracee's own call would have;
//!   - which ancillary data the guard passes on, translates (`SCM_RIGHTS` on a
//!     Unix socket) or refuses (`SCM_CREDENTIALS`, which only the sender can
//!     vouch for; an IPv6 routing header or IPv4 options, which send the
//!     packet to an address other than the one judged);
//!   - the session-proxy exception of the taint leg, narrowed from "127.0.0.1
//!     on any port" to the launch's own proxy ports over TCP
//!     (`is_session_proxy`, `MANDU_NET_GUARD_PROXY_PORTS`);
//!   - the families a tainted process may address at all;
//!   - the egress gate (`EgressGate`): no connect or send judged for an
//!     untainted process is still in flight when that process becomes
//!     tainted;
//!   - a `/proc/net/{tcp,udp}{,6}` line reader, for a socket whose connect is
//!     still in flight (`getpeername` answers ENOTCONN in `SYN_SENT`);
//!   - (2026-10-02) the sweep's Unix sockets: one connected to a NAMED peer
//!     is judged like a tainted Unix connect to that name (`HeldSocket::
//!     UnixPeer`), and what a Unix socket has queued is read for descriptors
//!     (`queue_verdict`); a descriptor passed over `SCM_RIGHTS` to a holder
//!     is judged at its sender like a socket the holder already held, the
//!     receiving socket found with `sock_diag` (`unix_diag_request`,
//!     `parse_unix_diag`).
//!
//! `Mandu-new`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::guard::Proto;

// ── constants (LP64 Linux; the same on x86_64 and aarch64) ──────────────────

pub const AF_UNSPEC: u16 = 0;
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_NETLINK: u16 = 16;

pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;

pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;
pub const IPPROTO_IPV6: i32 = 41;
/// Multipath TCP: a TCP socket to every rule (its subflows are TCP).
pub const IPPROTO_MPTCP: i32 = 262;

/// `MSG_FASTOPEN`: a stream send that connects (TCP Fast Open).
pub const MSG_FASTOPEN: i32 = 0x2000_0000;
pub const MSG_NOSIGNAL: i32 = 0x4000;
pub const MSG_DONTWAIT: i32 = 0x40;
pub const MSG_ZEROCOPY: i32 = 0x400_0000;

/// `SOL_SOCKET` and its two descriptor/credential messages.
pub const SOL_SOCKET: i32 = 1;
pub const SCM_RIGHTS: i32 = 1;
pub const SCM_CREDENTIALS: i32 = 2;
/// `IP_OPTIONS` (setsockopt) and `IP_RETOPTS` (its ancillary twin): IPv4
/// options, a loose/strict source route among them.
pub const IP_OPTIONS: i32 = 4;
pub const IP_RETOPTS: i32 = 7;
/// IPv6 routing headers (RFC 3542 and the RFC 2292 spelling) and the old
/// sticky packet options, which carry any of them.
pub const IPV6_2292PKTOPTIONS: i32 = 6;
pub const IPV6_2292RTHDR: i32 = 5;
pub const IPV6_RTHDR: i32 = 57;

/// `struct msghdr`, `struct mmsghdr`, `struct iovec`, `struct cmsghdr` (LP64).
pub const MSGHDR_LEN: usize = 56;
pub const MMSGHDR_LEN: usize = 64;
/// `mmsghdr.msg_len`, written back per message sent.
pub const MMSG_LEN_OFF: usize = 56;
pub const IOVEC_LEN: usize = 16;
pub const CMSGHDR_LEN: usize = 16;
/// The kernel's caps: `UIO_MAXIOV` iovecs a message (and messages a
/// `sendmmsg`), `sizeof(struct sockaddr_storage)`, `SCM_MAX_FD` descriptors.
pub const UIO_MAXIOV: u64 = 1024;
pub const SOCKADDR_MAX: usize = 128;
pub const SCM_MAX_FD: usize = 253;
/// The most ancillary data the guard reads (the kernel's `optmem_max` is
/// 20 KiB to 128 KiB): beyond it the kernel's own answer is ENOBUFS.
pub const CONTROL_MAX: u64 = 64 * 1024;
/// The most payload the guard copies for one message. A datagram is never
/// larger (UDP 64 KiB, a Unix datagram the socket's send buffer); a stream
/// send beyond it is sent in part, which a stream send may do (the caller
/// sees a short count and sends the rest).
pub const PAYLOAD_MAX: u64 = 4 * 1024 * 1024;

// ── the session-proxy exception (finding path 3) ────────────────────────────

/// The launch's own proxy ports (the model proxy, the net-proxy, the U-LLM
/// forwarder), comma-separated; set by the launcher (net-guard-setup.ts).
pub const PROXY_PORTS_ENV: &str = "MANDU_NET_GUARD_PROXY_PORTS";

/// Parse `MANDU_NET_GUARD_PROXY_PORTS`. Empty = no exception at all. A bad
/// entry is an error (the bin refuses to start, fail-closed: a launcher bug
/// must not widen the exception).
pub fn parse_proxy_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.parse::<u16>() {
            Ok(p) if p > 0 => {
                if !out.contains(&p) {
                    out.push(p);
                }
            }
            _ => return Err(format!("bad proxy port {part:?} in {PROXY_PORTS_ENV}")),
        }
    }
    Ok(out)
}

/// The loopback address the session's proxies listen on: exactly 127.0.0.1
/// (and its v4-mapped form) or ::1. Other loopback addresses are ordinary
/// destinations for the taint leg.
pub fn is_proxy_host(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4 == Ipv4Addr::LOCALHOST,
        IpAddr::V6(v6) => v6 == Ipv6Addr::LOCALHOST || v6.to_ipv4_mapped() == Some(Ipv4Addr::LOCALHOST),
    }
}

/// Plan 10 §4.3's exception, narrowed (2026-10-01): a tainted process may
/// reach the session's own proxies, i.e. TCP to 127.0.0.1 / ::1 on one of
/// the launch's proxy ports (the launcher lists only the net-proxy's). This
/// holds only because the net-proxy judges the sender again on EVERY leg
/// (plan 13 D6, 2026-10-02): plain HTTP, each request on the TLS-inspected
/// leg, and a blind CONNECT at the tunnel and before each chunk, by every
/// process holding the client's socket; an unattributed leg is refused
/// while the session holds a secret. Before, every port of 127.0.0.1 passed, so a
/// resolver forwarding on 127.0.0.1:53 (dnsmasq, unbound) carried a secret off
/// the machine. UDP never passes: a proxy is TCP, and a UDP port of the same
/// number is anyone's to bind.
pub fn is_session_proxy(ip: IpAddr, port: u16, proto: Proto, ports: &[u16]) -> bool {
    proto == Proto::Tcp && is_proxy_host(ip) && ports.contains(&port)
}

// ── protocol and family ─────────────────────────────────────────────────────

/// The transport a socket is, from `SO_TYPE` and `SO_PROTOCOL`: TCP (MPTCP
/// included) and UDP by name, everything else `Other` (an ICMP echo socket,
/// UDP-Lite, SCTP), which only a protocol-agnostic rule covers. A protocol
/// the kernel did not report (`None`) keeps the type's default.
pub fn proto_of(sotype: Option<i32>, protocol: Option<i32>) -> Proto {
    match (sotype, protocol) {
        (Some(SOCK_STREAM), None | Some(0) | Some(IPPROTO_TCP) | Some(IPPROTO_MPTCP)) => Proto::Tcp,
        (Some(SOCK_DGRAM), None | Some(0) | Some(IPPROTO_UDP)) => Proto::Udp,
        (None, _) => Proto::Tcp,
        _ => Proto::Other,
    }
}

/// May a TAINTED process address a socket of this family at all (a connect,
/// or a send that names an address)? INET is judged against its bindings and
/// AF_UNIX against its `unix:` bindings; netlink reaches only this kernel.
/// Every other family (vsock to a hypervisor, TIPC, RDS, CAN, Bluetooth, …)
/// has no binding to match and is refused: fail-closed.
pub fn tainted_may_address(family: u16) -> bool {
    matches!(family, AF_INET | AF_INET6 | AF_UNIX | AF_NETLINK)
}

// ── the destination the kernel would use ────────────────────────────────────

/// What an address named by a send on an INET socket means to the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InetDest {
    /// No address (or one the kernel treats as none): the socket's peer.
    NoAddress,
    /// An address the kernel ignores (a stream send without `MSG_FASTOPEN`).
    Ignored,
    /// The destination the kernel would send to.
    Judge(IpAddr, u16),
    /// The kernel would refuse the address with this errno; the guard answers
    /// it without sending (never sends to an address it did not judge).
    Refused(i32),
}

/// `name` is the address exactly as the tracee passed it (its length is the
/// length it passed). Mirrors `udp_sendmsg` / `udpv6_sendmsg` /
/// `ping_v4_sendmsg` / `tcp_sendmsg_fastopen`'s reading, judging the stricter
/// reading where they differ (an `AF_UNSPEC` address on an `AF_INET` socket is
/// judged as the IPv4 address in its bytes, as UDP uses it).
pub fn inet_send_destination(sock_family: u16, sotype: i32, flags: i32, name: &[u8]) -> InetDest {
    if name.is_empty() {
        return InetDest::NoAddress;
    }
    if sotype == SOCK_STREAM && flags & MSG_FASTOPEN == 0 {
        return InetDest::Ignored;
    }
    if name.len() < 2 {
        return InetDest::Refused(libc_einval());
    }
    let fam = u16::from_ne_bytes([name[0], name[1]]);
    let v4 = |b: &[u8]| -> InetDest {
        if b.len() < 16 {
            return InetDest::Refused(libc_einval());
        }
        InetDest::Judge(IpAddr::V4(Ipv4Addr::new(b[4], b[5], b[6], b[7])), u16::from_be_bytes([b[2], b[3]]))
    };
    match sock_family {
        AF_INET => match fam {
            AF_INET | AF_UNSPEC => v4(name),
            _ => InetDest::Refused(libc_eafnosupport()),
        },
        AF_INET6 => match fam {
            AF_INET6 => {
                // SIN6_LEN_RFC2133: the kernel's floor for a v6 address.
                if name.len() < 24 {
                    return InetDest::Refused(libc_einval());
                }
                let mut o = [0u8; 16];
                o.copy_from_slice(&name[8..24]);
                InetDest::Judge(IpAddr::V6(Ipv6Addr::from(o)), u16::from_be_bytes([name[2], name[3]]))
            }
            AF_INET => v4(name),
            AF_UNSPEC => InetDest::NoAddress,
            _ => InetDest::Refused(libc_einval()),
        },
        _ => InetDest::Refused(libc_eafnosupport()),
    }
}

const fn libc_einval() -> i32 {
    22
}
const fn libc_eafnosupport() -> i32 {
    97
}

// ── message layouts ─────────────────────────────────────────────────────────

/// `struct msghdr` as the tracee wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsgHdr {
    pub name: u64,
    pub namelen: u32,
    pub iov: u64,
    pub iovlen: u64,
    pub control: u64,
    pub controllen: u64,
}

fn word(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(b[at..at + 8].try_into().unwrap())
}

/// Parse a `struct msghdr` (56 bytes, LP64: name, namelen + pad, iov,
/// iovlen, control, controllen, flags + pad).
pub fn parse_msghdr(b: &[u8]) -> Option<MsgHdr> {
    if b.len() < MSGHDR_LEN {
        return None;
    }
    Some(MsgHdr {
        name: word(b, 0),
        namelen: u32::from_ne_bytes(b[8..12].try_into().unwrap()),
        iov: word(b, 16),
        iovlen: word(b, 24),
        control: word(b, 32),
        controllen: word(b, 40),
    })
}

/// The kernel's own checks of a `msghdr` for a send (`__copy_msghdr`,
/// `____sys_sendmsg`), in its order, and the address length it would use:
/// no name ⇒ 0; a negative length ⇒ EINVAL; a length past
/// `sockaddr_storage` is CLAMPED (a sendmsg, unlike a sendto, does not refuse
/// it); more than `UIO_MAXIOV` iovecs ⇒ EMSGSIZE; ancillary data past
/// `INT_MAX` ⇒ ENOBUFS (and past what the guard reads, the kernel's
/// `optmem_max` answer, ENOBUFS).
pub fn check_msghdr(h: &MsgHdr) -> Result<usize, i32> {
    let namelen = if h.name == 0 { 0 } else { h.namelen as i32 };
    if namelen < 0 {
        return Err(libc_einval());
    }
    let namelen = (namelen as usize).min(SOCKADDR_MAX);
    if h.iovlen > UIO_MAXIOV {
        return Err(90); // EMSGSIZE
    }
    if h.controllen > i32::MAX as u64 || h.controllen > CONTROL_MAX {
        return Err(105); // ENOBUFS
    }
    Ok(namelen)
}

/// A `sendto`'s address length, as `move_addr_to_kernel` takes it: a null
/// pointer is no address; a length past `sockaddr_storage` (or negative) is
/// EINVAL.
pub fn check_sendto_addrlen(addr: u64, addrlen: u64) -> Result<usize, i32> {
    if addr == 0 {
        return Ok(0);
    }
    let len = addrlen as u32 as i32;
    if len < 0 || len as usize > SOCKADDR_MAX {
        return Err(libc_einval());
    }
    Ok(len as usize)
}

/// Parse `n` `struct iovec`s.
pub fn parse_iovecs(b: &[u8], n: usize) -> Vec<(u64, u64)> {
    (0..n).filter(|i| (i + 1) * IOVEC_LEN <= b.len()).map(|i| (word(b, i * IOVEC_LEN), word(b, i * IOVEC_LEN + 8))).collect()
}

/// The payload to copy: the iovecs' total, capped at `PAYLOAD_MAX` (a
/// datagram larger than that is EMSGSIZE in the kernel anyway; a stream send
/// is sent in part). A length that overflows `ssize_t` is EINVAL, as the
/// kernel's `import_iovec` answers.
pub fn payload_plan(iovs: &[(u64, u64)], datagram: bool) -> Result<Vec<(u64, usize)>, i32> {
    let mut total: u64 = 0;
    let mut out = Vec::new();
    for &(_, len) in iovs {
        if len > isize::MAX as u64 {
            return Err(libc_einval());
        }
        total = total.checked_add(len).ok_or(libc_einval())?;
        if total > isize::MAX as u64 {
            return Err(libc_einval());
        }
    }
    if datagram && total > PAYLOAD_MAX {
        return Err(90); // EMSGSIZE
    }
    let mut left = PAYLOAD_MAX;
    for &(base, len) in iovs {
        if left == 0 {
            break;
        }
        let take = len.min(left);
        if take > 0 {
            out.push((base, take as usize));
        }
        left -= take;
    }
    Ok(out)
}

// ── ancillary data ──────────────────────────────────────────────────────────

/// One control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmsg {
    pub level: i32,
    pub ty: i32,
    pub data: Vec<u8>,
}

const fn cmsg_align(n: usize) -> usize {
    (n + 7) & !7
}

/// Walk a control buffer as the kernel does (`for_each_cmsghdr` + `CMSG_OK`):
/// a header whose length is below its own size or past the buffer is EINVAL;
/// fewer bytes than a header left at the end end the walk.
pub fn parse_cmsgs(b: &[u8]) -> Result<Vec<Cmsg>, i32> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + CMSGHDR_LEN <= b.len() {
        let len = word(b, at) as usize;
        if len < CMSGHDR_LEN || len > b.len() - at {
            return Err(libc_einval());
        }
        let level = i32::from_ne_bytes(b[at + 8..at + 12].try_into().unwrap());
        let ty = i32::from_ne_bytes(b[at + 12..at + 16].try_into().unwrap());
        out.push(Cmsg { level, ty, data: b[at + CMSGHDR_LEN..at + len].to_vec() });
        at += cmsg_align(len);
    }
    Ok(out)
}

/// Serialize control messages back into a buffer (`CMSG_SPACE` each).
pub fn build_cmsgs(cmsgs: &[Cmsg]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in cmsgs {
        let len = CMSGHDR_LEN + c.data.len();
        out.extend_from_slice(&(len as u64).to_ne_bytes());
        out.extend_from_slice(&c.level.to_ne_bytes());
        out.extend_from_slice(&c.ty.to_ne_bytes());
        out.extend_from_slice(&c.data);
        out.resize(out.len() + (cmsg_align(len) - len), 0);
    }
    out
}

/// What the guard does with a message's ancillary data on a socket of
/// `family`: the messages to pass on (an `SCM_RIGHTS` among them still holds
/// the TRACEE's descriptor numbers, `descriptors` lists them in order for the
/// caller to copy and substitute), or the errno to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlan {
    pub keep: Vec<Cmsg>,
    pub descriptors: Vec<i32>,
}

/// Decide a message's ancillary data. Refused (EPERM, the kernel's answer to a
/// sender that may not do this):
///   - `SCM_CREDENTIALS` on a Unix socket: the kernel checks the claimed pid
///     against the SENDER, which would be the guard; only the tracee could
///     vouch for itself;
///   - an IPv6 routing header (`IPV6_RTHDR`, `IPV6_2292RTHDR`): with one, the
///     packet's destination is the header's address, not the one judged
///     (`fl6_update_dst`), and a type-2 header is accepted unprivileged;
///   - IPv4 options (`IP_RETOPTS`): a source route sends the packet to its
///     first hop.
/// Dropped (the kernel ignores them on that family): `SCM_RIGHTS` /
/// `SCM_CREDENTIALS` on a non-Unix socket. Everything else passes as written.
pub fn plan_control(family: u16, cmsgs: Vec<Cmsg>) -> Result<ControlPlan, i32> {
    let mut keep = Vec::new();
    let mut descriptors = Vec::new();
    for c in cmsgs {
        match (c.level, c.ty) {
            (SOL_SOCKET, SCM_RIGHTS) if family == AF_UNIX => {
                if c.data.len() % 4 != 0 {
                    return Err(libc_einval());
                }
                for ch in c.data.chunks(4) {
                    descriptors.push(i32::from_ne_bytes(ch.try_into().unwrap()));
                }
                if descriptors.len() > SCM_MAX_FD {
                    return Err(libc_einval());
                }
                keep.push(c);
            }
            (SOL_SOCKET, SCM_CREDENTIALS) if family == AF_UNIX => return Err(1), // EPERM
            (SOL_SOCKET, SCM_RIGHTS | SCM_CREDENTIALS) => {}
            (IPPROTO_IPV6, IPV6_RTHDR | IPV6_2292RTHDR) => return Err(1),
            (IPPROTO_IP, IP_RETOPTS) => return Err(1),
            _ => keep.push(c),
        }
    }
    Ok(ControlPlan { keep, descriptors })
}

/// Put the guard's copies of the descriptors in place of the tracee's numbers,
/// in the order `plan_control` listed them.
pub fn substitute_descriptors(keep: &mut [Cmsg], copies: &[i32]) {
    let mut it = copies.iter();
    for c in keep.iter_mut().filter(|c| c.level == SOL_SOCKET && c.ty == SCM_RIGHTS) {
        for ch in c.data.chunks_mut(4) {
            if let Some(fd) = it.next() {
                ch.copy_from_slice(&fd.to_ne_bytes());
            }
        }
    }
}

// ── flags and answers ───────────────────────────────────────────────────────

/// The flags of the send the guard performs: the tracee's, never
/// `MSG_ZEROCOPY` (the kernel would keep reading the guard's buffer after
/// the call, and the completion it posts is the tracee's to read, so the
/// send copies; a program that waits for zerocopy completions does not get
/// one), always `MSG_NOSIGNAL` (an EPIPE raises the tracee's SIGPIPE
/// instead, `raises_sigpipe`).
pub fn performed_flags(tracee_flags: i32) -> i32 {
    (tracee_flags & !MSG_ZEROCOPY) | MSG_NOSIGNAL
}

/// Whether the tracee's own send would have raised SIGPIPE.
pub fn raises_sigpipe(tracee_flags: i32, errno: i32) -> bool {
    errno == 32 && tracee_flags & MSG_NOSIGNAL == 0
}

/// `sendmmsg`'s answer from the per-message results in order (the guard stops
/// at the first error): the count sent, or the first error when nothing was.
pub fn mmsg_answer(results: &[Result<usize, i32>]) -> Result<usize, i32> {
    let sent = results.iter().take_while(|r| r.is_ok()).count();
    if sent > 0 {
        return Ok(sent);
    }
    match results.first() {
        Some(Err(e)) => Err(*e),
        _ => Ok(0),
    }
}

// ── /proc/net ───────────────────────────────────────────────────────────────

/// One socket of `/proc/net/{tcp,udp,raw,icmp}{,6}`: its remote address and
/// port and its state (`TCP_SYN_SENT` = 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcNetSocket {
    pub remote: IpAddr,
    pub port: u16,
    pub state: u8,
}

pub const TCP_ESTABLISHED: u8 = 1;
pub const TCP_SYN_SENT: u8 = 2;
pub const TCP_LISTEN: u8 = 10;
pub const TCP_CLOSE: u8 = 7;

/// Find the socket with inode `inode` in a `/proc/net/…` table. The address
/// columns print each 32-bit word in host order (`%08X` of the in-memory
/// word), the port in host order.
pub fn proc_net_lookup(table: &str, inode: u64, v6: bool) -> Option<ProcNetSocket> {
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || f[9].parse::<u64>().ok() != Some(inode) {
            continue;
        }
        let (addr, port) = f[2].split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let state = u8::from_str_radix(f[3], 16).ok()?;
        let remote = if v6 {
            if addr.len() != 32 {
                return None;
            }
            let mut o = [0u8; 16];
            for w in 0..4 {
                let v = u32::from_str_radix(&addr[w * 8..w * 8 + 8], 16).ok()?;
                o[w * 4..w * 4 + 4].copy_from_slice(&v.to_ne_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(o))
        } else {
            if addr.len() != 8 {
                return None;
            }
            let v = u32::from_str_radix(addr, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(v.to_ne_bytes()))
        };
        return Some(ProcNetSocket { remote, port, state });
    }
    None
}

/// One address column of a `/proc/net/…` table (`0100007F:1F90`): each
/// 32-bit word of the address in host order, the port in hex.
pub fn parse_proc_net_addr(field: &str, v6: bool) -> Option<(IpAddr, u16)> {
    let (addr, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = if v6 {
        if addr.len() != 32 {
            return None;
        }
        let mut o = [0u8; 16];
        for w in 0..4 {
            let v = u32::from_str_radix(&addr[w * 8..w * 8 + 8], 16).ok()?;
            o[w * 4..w * 4 + 4].copy_from_slice(&v.to_ne_bytes());
        }
        IpAddr::V6(Ipv6Addr::from(o))
    } else {
        if addr.len() != 8 {
            return None;
        }
        let v = u32::from_str_radix(addr, 16).ok()?;
        IpAddr::V4(Ipv4Addr::from(v.to_ne_bytes()))
    };
    Some((ip, port))
}

/// Plan 13 §9 R1: the inode of the socket in a `/proc/net/tcp{,6}` table
/// whose LOCAL end is `local` and whose REMOTE end is `remote`: the client
/// of a connection a holder accepted from this machine (its local end is
/// the accepted connection's peer, its remote end the connection's local
/// address). Addresses compare with IPv4-mapped IPv6 unwrapped, so a v4
/// client of a dual-stack listener is found. Inode 0 (a socket in
/// `TIME_WAIT`, owned by no process) is never an answer.
pub fn proc_net_inode_by_addrs(table: &str, local: (IpAddr, u16), remote: (IpAddr, u16), v6: bool) -> Option<u64> {
    let canon = |ip: IpAddr| match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)),
        v4 => v4,
    };
    let (l, r) = ((canon(local.0), local.1), (canon(remote.0), remote.1));
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (Some(a), Some(b)) = (parse_proc_net_addr(f[1], v6), parse_proc_net_addr(f[2], v6)) else { continue };
        if (canon(a.0), a.1) == l && (canon(b.0), b.1) == r {
            if let Some(ino) = f[9].parse::<u64>().ok().filter(|i| *i != 0) {
                return Some(ino);
            }
        }
    }
    None
}

/// Plan 13 §4.5.1: is `local` the address of a LISTENING socket in a
/// `/proc/net/tcp{,6}` table (the same port, the same address or a wildcard
/// one)? A connection whose local end is such a port is the SERVER's end, one
/// its owner accepted, not one it dialled out. IPv4-mapped addresses compare
/// unwrapped. Pure.
pub fn proc_net_listens(table: &str, local: (IpAddr, u16), v6: bool) -> bool {
    let canon = |ip: IpAddr| match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)),
        v4 => v4,
    };
    let want = canon(local.0);
    table.lines().skip(1).any(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || u8::from_str_radix(f[3], 16).ok() != Some(TCP_LISTEN) {
            return false;
        }
        let Some((ip, port)) = parse_proc_net_addr(f[1], v6) else { return false };
        let ip = canon(ip);
        let wildcard = match ip {
            IpAddr::V4(a) => a.is_unspecified(),
            IpAddr::V6(a) => a.is_unspecified(),
        };
        port == local.1 && (wildcard || ip == want)
    })
}

/// One row of a `/proc/net/tcp{,6}` table: its two ends, its state and the
/// inode of the socket (0: owned by no descriptor, a connection still in a
/// listener's backlog or one in `TIME_WAIT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcNetRow {
    pub local: (IpAddr, u16),
    pub remote: (IpAddr, u16),
    pub state: u8,
    pub inode: u64,
}

/// An address with IPv4-mapped IPv6 unwrapped (`::ffff:127.0.0.1` is
/// `127.0.0.1`), so the two tables compare.
fn canon_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)),
        v4 => v4,
    }
}

fn same_end(a: (IpAddr, u16), b: (IpAddr, u16)) -> bool {
    a.1 == b.1 && canon_ip(a.0) == canon_ip(b.0)
}

/// Every row of a `/proc/net/tcp{,6}` table (the header and a malformed line
/// skipped). Pure.
pub fn proc_net_rows(table: &str, v6: bool) -> Vec<ProcNetRow> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            Some(ProcNetRow {
                local: parse_proc_net_addr(f[1], v6)?,
                remote: parse_proc_net_addr(f[2], v6)?,
                state: u8::from_str_radix(f[3], 16).ok()?,
                inode: f[9].parse::<u64>().ok()?,
            })
        })
        .collect()
}

/// What the `/proc/net/tcp{,6}` rows say a TCP socket is (plan 13 §4.5.1),
/// for a guard that has no copy of it (the taint-time sweep; the old kernel
/// has no `pidfd_getfd` at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpFacts {
    /// A listener, at this address (a wildcard one takes every address of
    /// this machine).
    Listening((IpAddr, u16)),
    /// A connection: the inode of its other end when that end is a socket of
    /// this machine owned by a descriptor (None: a peer elsewhere, or an end
    /// still in a backlog), and whether its own end is on a listening port
    /// (its holder accepted it rather than dialled it).
    Connected { other: Option<u64>, serves: bool },
}

/// The facts of the TCP socket `ino`; None when no row names it (not TCP,
/// or another network namespace's). Pure.
pub fn tcp_socket_facts(rows: &[ProcNetRow], ino: u64) -> Option<TcpFacts> {
    if ino == 0 {
        return None;
    }
    let r = rows.iter().find(|r| r.inode == ino)?;
    if r.state == TCP_LISTEN {
        return Some(TcpFacts::Listening(r.local));
    }
    let other = rows.iter().find(|o| o.inode != 0 && o.inode != ino && same_end(o.local, r.remote) && same_end(o.remote, r.local)).map(|o| o.inode);
    let serves = rows.iter().any(|l| {
        l.state == TCP_LISTEN && l.local.1 == r.local.1 && {
            let ip = canon_ip(l.local.0);
            ip.is_unspecified() || ip == canon_ip(r.local.0)
        }
    });
    Some(TcpFacts::Connected { other, serves })
}

/// Plan 13 §4.5.1, the proxy leg (2026-10-02): the inodes of the sockets
/// LISTENING at one of the launch's proxy ports (`is_session_proxy`) on a
/// loopback or wildcard address: the session's net-proxy's listener, whose
/// holders are the processes that re-originate the tree's proxied requests
/// from OUTSIDE the guard. Pure.
pub fn proxy_listener_inodes(rows: &[ProcNetRow], ports: &[u16]) -> Vec<u64> {
    rows.iter()
        .filter(|r| r.state == TCP_LISTEN && r.inode != 0 && ports.contains(&r.local.1))
        .filter(|r| {
            let ip = canon_ip(r.local.0);
            ip.is_loopback() || ip.is_unspecified()
        })
        .map(|r| r.inode)
        .collect()
}

/// Plan 13 §4.5.1 (the old-kernel degrade, 2026-10-02): the inodes of the
/// sockets LISTENING for a connection to `dest`: at its port, on its own
/// address, or on a wildcard one when `dest_local` (the address is this
/// machine's, so a wildcard listener takes it). Pure.
pub fn listeners_for(rows: &[ProcNetRow], dest: (IpAddr, u16), dest_local: bool) -> Vec<u64> {
    rows.iter()
        .filter(|r| r.state == TCP_LISTEN && r.inode != 0 && r.local.1 == dest.1)
        .filter(|r| {
            let ip = canon_ip(r.local.0);
            ip == canon_ip(dest.0) || (dest_local && ip.is_unspecified())
        })
        .map(|r| r.inode)
        .collect()
}

/// Plan 13 §4.5.1 (the old-kernel degrade, 2026-10-02): the client sockets
/// on this machine of the connections to a listener at `listen` (its address
/// may be a wildcard): a row whose remote end is at the listener's port (on
/// its address, any address for a wildcard) and whose server end is a row
/// too (local and remote swapped: both ends are this machine's), whether
/// the listener has accepted it yet or it still waits in the backlog (that
/// end's inode is then 0). Pure.
pub fn clients_of_listener(rows: &[ProcNetRow], listen: (IpAddr, u16)) -> Vec<u64> {
    let wildcard = canon_ip(listen.0).is_unspecified();
    rows.iter()
        .filter(|c| c.state != TCP_LISTEN && c.inode != 0 && c.remote.1 == listen.1)
        .filter(|c| wildcard || canon_ip(c.remote.0) == canon_ip(listen.0))
        .filter(|c| rows.iter().any(|s| s.state != TCP_LISTEN && same_end(s.local, c.remote) && same_end(s.remote, c.local)))
        .map(|c| c.inode)
        .collect()
}

// ── the egress gate ─────────────────────────────────────────────────────────

/// The connects and sends the guard is performing, per thread group. A
/// process becomes tainted only after its in-flight egress, judged while it
/// was untainted, has finished (`wait_idle`): the open that taints records
/// the taint first (so nothing judged after sees it untainted), then waits
/// here, then sweeps the sockets the process holds. Without the wait, a
/// connect judged untainted could complete after the sweep looked, and leave
/// a tainted process a socket to an unbound peer; a send judged untainted
/// could carry bytes read after the taint.
#[derive(Default)]
pub struct EgressGate {
    busy: Mutex<std::collections::HashMap<i32, usize>>,
    idle: Condvar,
}

/// One egress in flight; ends when dropped. Owns a handle on its gate, so a
/// send that has to wait can take it to a thread of its own.
pub struct InFlightEgress {
    gate: std::sync::Arc<EgressGate>,
    tgid: i32,
}

impl EgressGate {
    pub fn enter(self: &std::sync::Arc<Self>, tgid: i32) -> InFlightEgress {
        if let Ok(mut m) = self.busy.lock() {
            *m.entry(tgid).or_insert(0) += 1;
        }
        InFlightEgress { gate: self.clone(), tgid }
    }

    /// Wait until none of `tgids` has egress in flight, or `bound` passes.
    /// True when none has.
    pub fn wait_idle(&self, tgids: &[i32], bound: Duration) -> bool {
        self.wait_idle_but(tgids, None, bound)
    }

    /// `wait_idle`, except that `caller` (the process whose own call is
    /// being judged, plan 13 §9 R1: a send that passes a descriptor and makes
    /// its sender a holder) may keep that one call in flight: waiting for it
    /// would wait for itself.
    pub fn wait_idle_but(&self, tgids: &[i32], caller: Option<i32>, bound: Duration) -> bool {
        let end = Instant::now() + bound;
        let Ok(mut m) = self.busy.lock() else { return false };
        loop {
            let allowed = |t: &i32| if Some(*t) == caller { 1 } else { 0 };
            if !tgids.iter().any(|t| m.get(t).copied().unwrap_or(0) > allowed(t)) {
                return true;
            }
            let now = Instant::now();
            if now >= end {
                return false;
            }
            match self.idle.wait_timeout(m, end - now) {
                Ok((g, _)) => m = g,
                Err(_) => return false,
            }
        }
    }

    pub fn in_flight(&self, tgid: i32) -> usize {
        self.busy.lock().map(|m| m.get(&tgid).copied().unwrap_or(0)).unwrap_or(0)
    }
}

impl Drop for InFlightEgress {
    fn drop(&mut self) {
        if let Ok(mut m) = self.gate.busy.lock() {
            if let Some(n) = m.get_mut(&self.tgid) {
                *n -= 1;
                if *n == 0 {
                    m.remove(&self.tgid);
                }
            }
        }
        self.gate.idle.notify_all();
    }
}

// ── the taint-time sweep ────────────────────────────────────────────────────

/// What the sweep found one held socket to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeldSocket {
    /// Not an INET socket (a Unix stdio pair, netlink): the AF_UNIX leg judges
    /// its connects; not this sweep's.
    NotInet,
    /// An INET socket of another network namespace (a nested net-dead box):
    /// that namespace is the boundary.
    OtherNetns,
    /// Listening: it has no peer (what it accepts later is a residual,
    /// exec-routing.md §7.5).
    Listening,
    /// No peer and no connect in flight: every send needs an address, which
    /// the send trap judges.
    Unconnected,
    /// Connected (or connecting) to this peer.
    Peer(IpAddr, u16, Proto),
    /// A Unix socket connected to this named peer (a path, or `@name`): a
    /// tainted Unix connect to it would be judged (2026-10-02).
    UnixPeer(String),
    /// The guard could not tell (no copy, no answer): refused.
    Unknown(&'static str),
}

/// The sweep's answer for one process's sockets: `Ok` when every socket is
/// harmless for a tainted holder (`admitted` says which INET peers are,
/// `unix_admitted` which named Unix peers), else the first that is not,
/// with why.
pub fn sweep_verdict(held: &[HeldSocket], admitted: impl Fn(IpAddr, u16, Proto) -> bool, unix_admitted: impl Fn(&str) -> bool) -> Result<(), String> {
    for h in held {
        match h {
            HeldSocket::UnixPeer(name) if !unix_admitted(name) => return Err(format!("unix:{name}")),
            HeldSocket::Peer(ip, port, proto) if !admitted(*ip, *port, *proto) => {
                let ip = match ip {
                    IpAddr::V6(v6) => format!("[{v6}]"),
                    v4 => v4.to_string(),
                };
                return Err(format!("{ip}:{port}/{}", proto.name()));
            }
            HeldSocket::Unknown(why) => return Err(format!("a socket the guard cannot judge ({why})")),
            _ => {}
        }
    }
    Ok(())
}

/// How long a taint waits for egress judged before it to finish.
pub const TAINT_WAIT: Duration = Duration::from_secs(5);

// ── descriptors queued on a holder's Unix socket (2026-10-02) ───────────────

/// What a Unix socket has queued: a holder would receive a descriptor in it
/// without any call the guard traps (`recvmsg` is not trapped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueCheck {
    /// Nothing queued can carry a descriptor.
    Clear,
    /// A descriptor is queued: the holder would receive it.
    Rights,
    /// The guard cannot see the whole queue (refused, fail-closed).
    Unknown(&'static str),
}

/// The most a stream peek reads to find a queued descriptor.
pub const PEEK_MAX: usize = 4 * 1024 * 1024;

/// Judge a peek of a sealed Unix socket's receive queue. `stream`: a stream
/// socket, whose peek walks the queue until a message that carries
/// descriptors (`unix_stream_read_generic` stops there, and at a change of
/// credentials when `SO_PASSCRED` is on); `queued`: the bytes `SIOCINQ`
/// says are queued (a stream socket); `peeked`: what the peek returned
/// (None: nothing queued, EAGAIN); `rights`: it carried `SCM_RIGHTS` (or was
/// cut short, `MSG_CTRUNC`). A datagram socket's peek sees only the first
/// message, so a queued datagram is a queue the guard cannot see through.
pub fn queue_verdict(stream: bool, queued: usize, peeked: Option<usize>, rights: bool) -> QueueCheck {
    if rights {
        return QueueCheck::Rights;
    }
    match (stream, peeked) {
        (_, None) => QueueCheck::Clear,
        (true, Some(_)) if queued > PEEK_MAX => QueueCheck::Unknown("more queued than the guard reads"),
        (true, Some(n)) if n < queued => QueueCheck::Unknown("a queue the peek stopped in"),
        (true, Some(_)) => QueueCheck::Clear,
        (false, Some(_)) => QueueCheck::Unknown("a datagram queued (the guard sees only the first)"),
    }
}

// ── sock_diag for Unix sockets: who receives a descriptor (2026-10-02) ──────

/// `NETLINK_SOCK_DIAG`, `SOCK_DIAG_BY_FAMILY`, and the netlink header flags
/// and message types the query uses.
pub const NETLINK_SOCK_DIAG: i32 = 4;
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
/// `unix_diag_req.udiag_show` bits and the attributes they add.
pub const UDIAG_SHOW_NAME: u32 = 0x1;
pub const UDIAG_SHOW_VFS: u32 = 0x2;
pub const UDIAG_SHOW_PEER: u32 = 0x4;
const UNIX_DIAG_NAME: u16 = 0;
const UNIX_DIAG_VFS: u16 = 1;
const UNIX_DIAG_PEER: u16 = 2;

/// One Unix socket as `unix_diag` describes it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnixDiag {
    pub ino: u32,
    /// The socket at the other end (a connected or paired socket).
    pub peer: Option<u32>,
    /// The bound path's inode and device (the KERNEL's dev_t encoding).
    pub vfs: Option<(u32, u32)>,
    /// The bound name as `sun_path` holds it (a leading NUL: abstract).
    pub name: Option<Vec<u8>>,
}

/// A `SOCK_DIAG_BY_FAMILY` request for Unix sockets: the one with inode
/// `ino` (`dump` false), or every one (`dump` true), with `show`'s
/// attributes.
pub fn unix_diag_request(seq: u32, ino: u32, show: u32, dump: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(40);
    b.extend_from_slice(&40u32.to_ne_bytes());
    b.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    b.extend_from_slice(&(NLM_F_REQUEST | if dump { NLM_F_DUMP } else { 0 }).to_ne_bytes());
    b.extend_from_slice(&seq.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes());
    // struct unix_diag_req
    b.push(AF_UNIX as u8);
    b.push(0);
    b.extend_from_slice(&0u16.to_ne_bytes());
    b.extend_from_slice(&u32::MAX.to_ne_bytes()); // every state
    b.extend_from_slice(&ino.to_ne_bytes());
    b.extend_from_slice(&show.to_ne_bytes());
    b.extend_from_slice(&u32::MAX.to_ne_bytes()); // INET_DIAG_NOCOOKIE
    b.extend_from_slice(&u32::MAX.to_ne_bytes());
    b
}

/// Parse a buffer of netlink messages answering `unix_diag_request`: the
/// sockets, and whether the answer is complete (`NLMSG_DONE`, or one
/// message for an exact query). `Err(errno)` for `NLMSG_ERROR`.
pub fn parse_unix_diag(buf: &[u8], dump: bool) -> Result<(Vec<UnixDiag>, bool), i32> {
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut done = false;
    while at + 16 <= buf.len() {
        let len = u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(buf[at + 4..at + 6].try_into().unwrap());
        if len < 16 || at + len > buf.len() {
            break;
        }
        let body = &buf[at + 16..at + len];
        match ty {
            NLMSG_DONE => done = true,
            NLMSG_ERROR => {
                let e = body.get(0..4).map(|b| i32::from_ne_bytes(b.try_into().unwrap())).unwrap_or(-5);
                if e != 0 {
                    return Err(-e);
                }
                done = true;
            }
            SOCK_DIAG_BY_FAMILY if body.len() >= 16 => {
                let mut d = UnixDiag { ino: u32::from_ne_bytes(body[4..8].try_into().unwrap()), ..Default::default() };
                let mut a = 16usize;
                while a + 4 <= body.len() {
                    let alen = u16::from_ne_bytes(body[a..a + 2].try_into().unwrap()) as usize;
                    let aty = u16::from_ne_bytes(body[a + 2..a + 4].try_into().unwrap());
                    if alen < 4 || a + alen > body.len() {
                        break;
                    }
                    let v = &body[a + 4..a + alen];
                    match aty {
                        UNIX_DIAG_NAME => d.name = Some(v.to_vec()),
                        UNIX_DIAG_VFS if v.len() >= 8 => {
                            d.vfs = Some((u32::from_ne_bytes(v[0..4].try_into().unwrap()), u32::from_ne_bytes(v[4..8].try_into().unwrap())))
                        }
                        UNIX_DIAG_PEER if v.len() >= 4 => d.peer = Some(u32::from_ne_bytes(v[0..4].try_into().unwrap())),
                        _ => {}
                    }
                    a += (alen + 3) & !3;
                }
                out.push(d);
                if !dump {
                    done = true;
                }
            }
            _ => {}
        }
        at += (len + 3) & !3;
    }
    Ok((out, done))
}

/// The kernel's internal `dev_t` (`MAJOR << 20 | MINOR`, what `unix_diag`
/// reports) as `stat`'s `st_dev`.
pub fn kernel_dev_to_user(dev: u32) -> u64 {
    let (major, minor) = ((dev >> 20) as u64, (dev & 0xfffff) as u64);
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sin(fam: u16, ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        b[0..2].copy_from_slice(&fam.to_ne_bytes());
        b[2..4].copy_from_slice(&port.to_be_bytes());
        b[4..8].copy_from_slice(&ip);
        b
    }

    fn sin6(ip: Ipv6Addr, port: u16) -> Vec<u8> {
        let mut b = vec![0u8; 28];
        b[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        b[2..4].copy_from_slice(&port.to_be_bytes());
        b[8..24].copy_from_slice(&ip.octets());
        b
    }

    #[test]
    fn proxy_ports_parse_and_refuse_junk() {
        assert_eq!(parse_proxy_ports("").unwrap(), Vec::<u16>::new());
        assert_eq!(parse_proxy_ports("8788, 8790,8788").unwrap(), vec![8788, 8790]);
        assert!(parse_proxy_ports("8788,x").is_err());
        assert!(parse_proxy_ports("0").is_err());
        assert!(parse_proxy_ports("70000").is_err());
    }

    #[test]
    fn the_session_proxy_is_tcp_to_localhost_on_a_proxy_port_only() {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let ports = [8788u16, 8790];
        assert!(is_session_proxy(lo, 8788, Proto::Tcp, &ports));
        assert!(is_session_proxy("::1".parse().unwrap(), 8790, Proto::Tcp, &ports));
        assert!(is_session_proxy("::ffff:127.0.0.1".parse().unwrap(), 8790, Proto::Tcp, &ports));
        // Finding path 3: a forwarder on 127.0.0.1:53, any other port.
        assert!(!is_session_proxy(lo, 53, Proto::Tcp, &ports));
        assert!(!is_session_proxy(lo, 53, Proto::Udp, &ports));
        assert!(!is_session_proxy(lo, 9999, Proto::Tcp, &ports));
        // UDP to a proxy's port number is anyone's.
        assert!(!is_session_proxy(lo, 8788, Proto::Udp, &ports));
        assert!(!is_session_proxy(lo, 8788, Proto::Other, &ports));
        // Other loopback addresses are ordinary destinations.
        assert!(!is_session_proxy("127.0.0.2".parse().unwrap(), 8788, Proto::Tcp, &ports));
        assert!(!is_session_proxy("127.0.0.53".parse().unwrap(), 8788, Proto::Tcp, &ports));
        // No ports: no exception at all.
        assert!(!is_session_proxy(lo, 8788, Proto::Tcp, &[]));
    }

    #[test]
    fn protocol_is_read_from_type_and_protocol() {
        assert_eq!(proto_of(Some(SOCK_STREAM), Some(IPPROTO_TCP)), Proto::Tcp);
        assert_eq!(proto_of(Some(SOCK_STREAM), Some(IPPROTO_MPTCP)), Proto::Tcp);
        assert_eq!(proto_of(Some(SOCK_DGRAM), Some(IPPROTO_UDP)), Proto::Udp);
        assert_eq!(proto_of(Some(SOCK_DGRAM), None), Proto::Udp);
        // An unprivileged ICMP echo socket is a datagram socket, not UDP.
        assert_eq!(proto_of(Some(SOCK_DGRAM), Some(1)), Proto::Other);
        assert_eq!(proto_of(Some(SOCK_DGRAM), Some(58)), Proto::Other);
        assert_eq!(proto_of(Some(SOCK_DGRAM), Some(136)), Proto::Other); // UDP-Lite
        assert_eq!(proto_of(Some(SOCK_STREAM), Some(132)), Proto::Other); // SCTP
        assert_eq!(proto_of(Some(3), Some(255)), Proto::Other); // SOCK_RAW
        // No socket copy at all: the connect leg's old default.
        assert_eq!(proto_of(None, None), Proto::Tcp);
    }

    #[test]
    fn an_icmp_socket_is_not_covered_by_a_udp_rule() {
        use crate::guard::{parse_rules, Decision, Endpoint, GuardPolicy, NoResolver};
        let policy = GuardPolicy::new(parse_rules(&["udp:*:53".into(), "tcp:*:443".into()]).unwrap());
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let udp = Endpoint { ip, port: 53, proto: Proto::Udp };
        let icmp = Endpoint { ip, port: 53, proto: proto_of(Some(SOCK_DGRAM), Some(1)) };
        assert_eq!(policy.decide(&udp, &NoResolver), Decision::Allow);
        assert_eq!(policy.decide(&icmp, &NoResolver), Decision::Deny);
        let any = GuardPolicy::new(parse_rules(&["any:8.8.8.8:*".into()]).unwrap());
        assert_eq!(any.decide(&icmp, &NoResolver), Decision::Allow);
    }

    #[test]
    fn tainted_processes_address_only_judged_families() {
        for f in [AF_INET, AF_INET6, AF_UNIX, AF_NETLINK] {
            assert!(tainted_may_address(f), "{f}");
        }
        for f in [40u16 /* vsock */, 30 /* tipc */, 21 /* rds */, 29 /* can */, 31 /* bluetooth */, 17 /* packet */, 0] {
            assert!(!tainted_may_address(f), "{f}");
        }
    }

    #[test]
    fn the_destination_is_the_one_the_kernel_would_use() {
        let lo3 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
        // UDP over IPv4: the address, and AF_UNSPEC read as IPv4 (udp_sendmsg).
        assert_eq!(inet_send_destination(AF_INET, SOCK_DGRAM, 0, &sin(AF_INET, [127, 0, 0, 3], 53)), InetDest::Judge(lo3, 53));
        assert_eq!(inet_send_destination(AF_INET, SOCK_DGRAM, 0, &sin(AF_UNSPEC, [127, 0, 0, 3], 53)), InetDest::Judge(lo3, 53));
        assert_eq!(inet_send_destination(AF_INET, SOCK_DGRAM, 0, &sin(AF_INET6, [127, 0, 0, 3], 53)), InetDest::Refused(97));
        assert_eq!(inet_send_destination(AF_INET, SOCK_DGRAM, 0, &sin(AF_INET, [127, 0, 0, 3], 53)[..8]), InetDest::Refused(22));
        assert_eq!(inet_send_destination(AF_INET, SOCK_DGRAM, 0, &[]), InetDest::NoAddress);
        // A stream send ignores its address, unless it connects (TFO).
        assert_eq!(inet_send_destination(AF_INET, SOCK_STREAM, 0, &sin(AF_INET, [1, 2, 3, 4], 443)), InetDest::Ignored);
        assert_eq!(
            inet_send_destination(AF_INET, SOCK_STREAM, MSG_FASTOPEN, &sin(AF_INET, [1, 2, 3, 4], 443)),
            InetDest::Judge("1.2.3.4".parse().unwrap(), 443)
        );
        // IPv6: its own family, v4 over v6, and AF_UNSPEC as no address.
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(inet_send_destination(AF_INET6, SOCK_DGRAM, 0, &sin6(v6, 53)), InetDest::Judge(IpAddr::V6(v6), 53));
        assert_eq!(inet_send_destination(AF_INET6, SOCK_DGRAM, 0, &sin6(v6, 53)[..20]), InetDest::Refused(22));
        assert_eq!(inet_send_destination(AF_INET6, SOCK_DGRAM, 0, &sin(AF_INET, [127, 0, 0, 3], 53)), InetDest::Judge(lo3, 53));
        assert_eq!(inet_send_destination(AF_INET6, SOCK_DGRAM, 0, &sin(AF_UNSPEC, [127, 0, 0, 3], 53)), InetDest::NoAddress);
        assert_eq!(inet_send_destination(AF_INET6, SOCK_DGRAM, 0, &sin(AF_UNIX, [127, 0, 0, 3], 53)), InetDest::Refused(22));
        assert_eq!(inet_send_destination(AF_INET6, SOCK_DGRAM, 0, &[10]), InetDest::Refused(22));
    }

    fn msghdr_bytes(h: &MsgHdr) -> Vec<u8> {
        let mut b = vec![0u8; MSGHDR_LEN];
        b[0..8].copy_from_slice(&h.name.to_ne_bytes());
        b[8..12].copy_from_slice(&h.namelen.to_ne_bytes());
        b[16..24].copy_from_slice(&h.iov.to_ne_bytes());
        b[24..32].copy_from_slice(&h.iovlen.to_ne_bytes());
        b[32..40].copy_from_slice(&h.control.to_ne_bytes());
        b[40..48].copy_from_slice(&h.controllen.to_ne_bytes());
        b
    }

    #[test]
    fn a_msghdr_round_trips_and_is_checked_like_the_kernel() {
        let h = MsgHdr { name: 0x1000, namelen: 16, iov: 0x2000, iovlen: 2, control: 0x3000, controllen: 24 };
        assert_eq!(parse_msghdr(&msghdr_bytes(&h)), Some(h));
        assert_eq!(parse_msghdr(&[0u8; 40]), None);
        assert_eq!(check_msghdr(&h), Ok(16));
        // A name pointer of 0 means no name, whatever the length says.
        assert_eq!(check_msghdr(&MsgHdr { name: 0, namelen: 999, ..h }), Ok(0));
        // A length past sockaddr_storage is clamped, not refused (sendmsg).
        assert_eq!(check_msghdr(&MsgHdr { namelen: 200, ..h }), Ok(128));
        assert_eq!(check_msghdr(&MsgHdr { namelen: u32::MAX, ..h }), Err(22));
        assert_eq!(check_msghdr(&MsgHdr { iovlen: 1025, ..h }), Err(90));
        assert_eq!(check_msghdr(&MsgHdr { controllen: 1 << 40, ..h }), Err(105));
        // sendto: a length past sockaddr_storage IS refused.
        assert_eq!(check_sendto_addrlen(0, 999), Ok(0));
        assert_eq!(check_sendto_addrlen(0x1000, 16), Ok(16));
        assert_eq!(check_sendto_addrlen(0x1000, 129), Err(22));
        assert_eq!(check_sendto_addrlen(0x1000, u32::MAX as u64), Err(22));
    }

    #[test]
    fn iovecs_and_payload_plan() {
        let mut b = Vec::new();
        for (base, len) in [(0x10u64, 3u64), (0x20, 0), (0x30, 5)] {
            b.extend_from_slice(&base.to_ne_bytes());
            b.extend_from_slice(&len.to_ne_bytes());
        }
        let iovs = parse_iovecs(&b, 3);
        assert_eq!(iovs, vec![(0x10, 3), (0x20, 0), (0x30, 5)]);
        assert_eq!(payload_plan(&iovs, true), Ok(vec![(0x10, 3), (0x30, 5)]));
        // A datagram larger than the cap is EMSGSIZE; a stream send is cut.
        let big = vec![(0x10u64, PAYLOAD_MAX), (0x20, 10)];
        assert_eq!(payload_plan(&big, true), Err(90));
        assert_eq!(payload_plan(&big, false), Ok(vec![(0x10, PAYLOAD_MAX as usize)]));
        // Overflow is EINVAL.
        assert_eq!(payload_plan(&[(0, u64::MAX)], false), Err(22));
        assert_eq!(payload_plan(&[(0, isize::MAX as u64), (0, 2)], false), Err(22));
    }

    #[test]
    fn control_messages_parse_and_rebuild() {
        let fds = Cmsg { level: SOL_SOCKET, ty: SCM_RIGHTS, data: [5i32, 7].iter().flat_map(|f| f.to_ne_bytes()).collect() };
        let ttl = Cmsg { level: IPPROTO_IP, ty: 2, data: 64i32.to_ne_bytes().to_vec() };
        let buf = build_cmsgs(&[fds.clone(), ttl.clone()]);
        assert_eq!(buf.len(), 24 + 24);
        assert_eq!(parse_cmsgs(&buf), Ok(vec![fds, ttl]));
        // Trailing bytes shorter than a header end the walk.
        let mut tail = buf.clone();
        tail.extend_from_slice(&[0u8; 8]);
        assert_eq!(parse_cmsgs(&tail).unwrap().len(), 2);
        // A length below the header, or past the buffer: EINVAL.
        let mut bad = buf.clone();
        bad[0..8].copy_from_slice(&8u64.to_ne_bytes());
        assert_eq!(parse_cmsgs(&bad), Err(22));
        let mut bad = buf;
        bad[0..8].copy_from_slice(&4096u64.to_ne_bytes());
        assert_eq!(parse_cmsgs(&bad), Err(22));
        assert_eq!(parse_cmsgs(&[]), Ok(vec![]));
    }

    #[test]
    fn ancillary_data_is_passed_translated_or_refused() {
        let rights = Cmsg { level: SOL_SOCKET, ty: SCM_RIGHTS, data: [5i32, 7].iter().flat_map(|f| f.to_ne_bytes()).collect() };
        let creds = Cmsg { level: SOL_SOCKET, ty: SCM_CREDENTIALS, data: vec![0; 12] };
        let pktinfo = Cmsg { level: IPPROTO_IP, ty: 8, data: vec![0; 12] };
        // Unix: descriptors listed for translation, in order.
        let p = plan_control(AF_UNIX, vec![rights.clone()]).unwrap();
        assert_eq!(p.descriptors, vec![5, 7]);
        let mut keep = p.keep;
        substitute_descriptors(&mut keep, &[100, 101]);
        assert_eq!(keep[0].data, [100i32, 101].iter().flat_map(|f| f.to_ne_bytes()).collect::<Vec<u8>>());
        // Credentials only the sender can vouch for.
        assert_eq!(plan_control(AF_UNIX, vec![creds.clone()]), Err(1));
        // INET: the Unix-only messages are dropped (the kernel ignores them).
        let p = plan_control(AF_INET, vec![rights.clone(), creds, pktinfo.clone()]).unwrap();
        assert_eq!(p.keep, vec![pktinfo.clone()]);
        assert!(p.descriptors.is_empty());
        // A routing header or IPv4 options would send to another address.
        for (level, ty) in [(IPPROTO_IPV6, IPV6_RTHDR), (IPPROTO_IPV6, IPV6_2292RTHDR), (IPPROTO_IP, IP_RETOPTS)] {
            let c = Cmsg { level, ty, data: vec![0; 24] };
            assert_eq!(plan_control(AF_INET6, vec![pktinfo.clone(), c.clone()]), Err(1), "{level}/{ty}");
            assert_eq!(plan_control(AF_INET, vec![c]), Err(1), "{level}/{ty}");
        }
        // A descriptor list that is not whole ints, or too long.
        assert_eq!(plan_control(AF_UNIX, vec![Cmsg { level: SOL_SOCKET, ty: SCM_RIGHTS, data: vec![0; 6] }]), Err(22));
        let many = Cmsg { level: SOL_SOCKET, ty: SCM_RIGHTS, data: vec![0; 4 * 254] };
        assert_eq!(plan_control(AF_UNIX, vec![many]), Err(22));
    }

    #[test]
    fn flags_and_answers() {
        assert_eq!(performed_flags(0), MSG_NOSIGNAL);
        assert_eq!(performed_flags(MSG_ZEROCOPY | MSG_DONTWAIT), MSG_DONTWAIT | MSG_NOSIGNAL);
        assert!(raises_sigpipe(0, 32));
        assert!(!raises_sigpipe(MSG_NOSIGNAL, 32));
        assert!(!raises_sigpipe(0, 11));
        assert_eq!(mmsg_answer(&[Ok(3), Ok(4), Err(11)]), Ok(2));
        assert_eq!(mmsg_answer(&[Err(13)]), Err(13));
        assert_eq!(mmsg_answer(&[]), Ok(0));
    }

    #[test]
    fn proc_net_tables_are_read_by_inode() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0 100 0 0 10 0\n\
   1: 0100007F:A1B2 0300007F:0035 02 00000001:00000000 01:00000064 00000000  1000        0 222 2 0 100 0 0 10 -1\n";
        assert_eq!(
            proc_net_lookup(tcp, 222, false),
            Some(ProcNetSocket { remote: "127.0.0.3".parse().unwrap(), port: 53, state: TCP_SYN_SENT })
        );
        assert_eq!(proc_net_lookup(tcp, 111, false).map(|s| s.state), Some(TCP_LISTEN));
        assert_eq!(proc_net_lookup(tcp, 333, false), None);
        // IPv6: four host-order words. ::1 prints as 00000000000000000000000001000000.
        let tcp6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000001000000:A1B2 B80D0120000000000000000001000000:0035 02 00000000:00000000 00:00000000 00000000  1000        0 444 1\n";
        assert_eq!(
            proc_net_lookup(tcp6, 444, true),
            Some(ProcNetSocket { remote: "2001:db8::1".parse().unwrap(), port: 53, state: TCP_SYN_SENT })
        );
    }

    #[test]
    fn the_client_of_an_accepted_connection_is_found_by_its_two_ends() {
        // Plan 13 §9 R1: the server accepted 127.0.0.1:8080 ← 127.0.0.1:41394.
        // Its own accepted socket (inode 501) has local 8080, remote 41394;
        // the client's (inode 502) the other way round; a TIME_WAIT leftover
        // of an earlier client has inode 0 and is never an answer.
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 500 1 0 100 0 0 10 0\n\
   1: 0100007F:1F90 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1000        0 501 1 0 100 0 0 10 0\n\
   2: 0100007F:A1B2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 502 1 0 100 0 0 10 0\n\
   3: 0100007F:A1B3 0100007F:1F90 06 00000000:00000000 00:00000000 00000000     0        0 0 1 0 100 0 0 10 0\n";
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(proc_net_inode_by_addrs(tcp, (lo, 0xA1B2), (lo, 0x1F90), false), Some(502));
        assert_eq!(proc_net_inode_by_addrs(tcp, (lo, 0x1F90), (lo, 0xA1B2), false), Some(501), "the other end, asked the other way");
        assert_eq!(proc_net_inode_by_addrs(tcp, (lo, 0xA1B3), (lo, 0x1F90), false), None, "TIME_WAIT: owned by no process");
        assert_eq!(proc_net_inode_by_addrs(tcp, (lo, 0xA1B4), (lo, 0x1F90), false), None);
        // A dual-stack listener reports a v4 client as ::ffff:127.0.0.1; the
        // client's own socket is in the v4 table.
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(proc_net_inode_by_addrs(tcp, (mapped, 0xA1B2), (mapped, 0x1F90), false), Some(502));
        // A v6 client in the tcp6 table (::1 prints as four host-order words).
        let tcp6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000001000000:A1B2 00000000000000000000000001000000:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 601 1\n";
        let v6lo: IpAddr = "::1".parse().unwrap();
        assert_eq!(proc_net_inode_by_addrs(tcp6, (v6lo, 0xA1B2), (v6lo, 0x1F90), true), Some(601));
        assert_eq!(parse_proc_net_addr("0100007F:1F90", false), Some((lo, 8080)));
        assert_eq!(parse_proc_net_addr("bad", false), None);
        // Plan 13 §4.5.1: the server's end is the one on a listening port.
        assert!(proc_net_listens(tcp, (lo, 0x1F90), false), "8080 listens: 501 is the server's end");
        assert!(!proc_net_listens(tcp, (lo, 0xA1B2), false), "41394 is a client's ephemeral port");
        let wild = "  sl  local_address rem_address   st\n   0: 00000000:1F91 00000000:0000 0A 00000000:00000000\n";
        assert!(proc_net_listens(wild, (lo, 0x1F91), false), "a wildcard listener");
        assert!(proc_net_listens(wild, (mapped, 0x1F91), false), "an IPv4-mapped local end");
        let tcp6l = "  sl  local_address remote_address st\n   0: 00000000000000000000000000000000:1F92 00000000000000000000000000000000:0000 0A 0\n";
        assert!(proc_net_listens(tcp6l, (v6lo, 0x1F92), true), "a v6 wildcard listener");
    }

    #[test]
    fn the_proxy_listener_a_destinations_listeners_and_a_listeners_clients_are_read_from_proc_net() {
        // Plan 13 §4.5.1 (2026-10-02). 9000 (0x2328): the net-proxy on
        // 127.0.0.1 (inode 700). 3000 (0x0BB8): a dev server on the wildcard
        // address (inode 710) with one accepted client (the server end 711,
        // the client 712) and one still in the backlog (the server end has no
        // inode yet; the client 714). 0x0BB9: another machine's port 3001
        // (the client 715 has no server end here). 10.0.0.10:9000 (inode
        // 716): another program on the machine's own address at the proxy's
        // port, which is not the proxy.
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 700 1 0 100 0 0 10 0\n\
   1: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 710 1 0 100 0 0 10 0\n\
   2: 0100007F:0BB8 0100007F:A000 01 00000000:00000000 00:00000000 00000000  1000        0 711 1 0 100 0 0 10 0\n\
   3: 0100007F:A000 0100007F:0BB8 01 00000000:00000000 00:00000000 00000000  1000        0 712 1 0 100 0 0 10 0\n\
   4: 0100007F:0BB8 0100007F:A001 01 00000000:00000000 00:00000000 00000000  1000        0 0 1 0 100 0 0 10 0\n\
   5: 0100007F:A001 0100007F:0BB8 01 00000000:00000000 00:00000000 00000000  1000        0 714 1 0 100 0 0 10 0\n\
   6: 0A00000A:A002 0B00000A:0BB8 01 00000000:00000000 00:00000000 00000000  1000        0 715 1 0 100 0 0 10 0\n\
   7: 0A00000A:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 716 1 0 100 0 0 10 0\n";
        let rows = proc_net_rows(tcp, false);
        assert_eq!(rows.len(), 8);
        assert_eq!(rows[0], ProcNetRow { local: ("127.0.0.1".parse().unwrap(), 9000), remote: ("0.0.0.0".parse().unwrap(), 0), state: TCP_LISTEN, inode: 700 });
        // The proxy's listener: loopback or wildcard only (10.0.0.10:9000 is
        // another program's socket on the machine's own address).
        assert_eq!(proxy_listener_inodes(&rows, &[9000]), vec![700]);
        assert_eq!(proxy_listener_inodes(&rows, &[]), Vec::<u64>::new());
        assert_eq!(proxy_listener_inodes(&rows, &[3000]), vec![710], "a wildcard listener at a proxy port");
        // Who listens for a connection to 127.0.0.1:3000 (a wildcard one
        // takes it), and for 10.0.0.11:3000 when that address is not this
        // machine's (none).
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let far: IpAddr = "10.0.0.11".parse().unwrap();
        assert_eq!(listeners_for(&rows, (lo, 3000), true), vec![710]);
        assert_eq!(listeners_for(&rows, (far, 3000), false), Vec::<u64>::new(), "another machine's port");
        assert_eq!(listeners_for(&rows, (far, 3000), true), vec![710], "an address of this machine: the wildcard takes it");
        assert_eq!(listeners_for(&rows, (lo, 3002), true), Vec::<u64>::new());
        // The clients of the dev server's listener: the accepted one and the
        // one in the backlog, never the server ends nor another machine's.
        let wild: IpAddr = "0.0.0.0".parse().unwrap();
        assert_eq!(clients_of_listener(&rows, (wild, 3000)), vec![712, 714]);
        assert_eq!(clients_of_listener(&rows, (lo, 3000)), vec![712, 714]);
        assert_eq!(clients_of_listener(&rows, ("127.0.0.2".parse().unwrap(), 3000)), Vec::<u64>::new(), "a listener on another address");
        // A v4 client of a dual-stack listener: its server end is in tcp6.
        let tcp6 = "  sl  local_address remote_address st tx rx tr tm retr uid timeout inode\n\
   0: 00000000000000000000000000000000:0BBA 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 720 1\n\
   1: 0000000000000000FFFF00000100007F:0BBA 0000000000000000FFFF00000100007F:A003 01 00000000:00000000 00:00000000 00000000  1000 0 721 1\n";
        let mut both = proc_net_rows(tcp, false);
        both.extend(proc_net_rows(tcp6, true));
        let v4client = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:A003 0100007F:0BBA 01 00000000:00000000 00:00000000 00000000  1000        0 722 1 0 100 0 0 10 0\n";
        both.extend(proc_net_rows(v4client, false));
        let v6wild: IpAddr = "::".parse().unwrap();
        assert_eq!(clients_of_listener(&both, (v6wild, 3002)), vec![722]);
        assert_eq!(listeners_for(&both, (lo, 3002), true), vec![720]);
        // A socket's facts without a copy of it: the listener; the server
        // end the holder accepted (its client 712); the client's own end (it
        // dialled); a client whose server end is still in the backlog (no
        // inode there: no other end yet); a peer elsewhere; no row at all.
        assert_eq!(tcp_socket_facts(&rows, 710), Some(TcpFacts::Listening((wild, 3000))));
        assert_eq!(tcp_socket_facts(&rows, 711), Some(TcpFacts::Connected { other: Some(712), serves: true }));
        assert_eq!(tcp_socket_facts(&rows, 712), Some(TcpFacts::Connected { other: Some(711), serves: false }));
        assert_eq!(tcp_socket_facts(&rows, 714), Some(TcpFacts::Connected { other: None, serves: false }));
        assert_eq!(tcp_socket_facts(&rows, 715), Some(TcpFacts::Connected { other: None, serves: false }));
        assert_eq!(tcp_socket_facts(&rows, 999), None);
        assert_eq!(tcp_socket_facts(&rows, 0), None);
        // The v4 server end of a dual-stack listener, found across tables.
        assert_eq!(tcp_socket_facts(&both, 721), Some(TcpFacts::Connected { other: Some(722), serves: true }));
    }

    #[test]
    fn a_caller_judged_in_its_own_call_waits_only_for_its_other_egress() {
        let gate = std::sync::Arc::new(EgressGate::default());
        let own = gate.enter(10);
        assert!(!gate.wait_idle(&[10], Duration::from_millis(5)), "plain: its own call is in flight");
        assert!(gate.wait_idle_but(&[10, 11], Some(10), Duration::from_millis(5)), "its own call alone is allowed");
        let other = gate.enter(10);
        assert!(!gate.wait_idle_but(&[10], Some(10), Duration::from_millis(5)), "a second call of it (another thread) is waited for");
        drop(other);
        let busy = gate.enter(11);
        assert!(!gate.wait_idle_but(&[10, 11], Some(10), Duration::from_millis(5)), "another process is waited for");
        drop((busy, own));
    }

    #[test]
    fn the_gate_waits_for_egress_in_flight() {
        let gate = std::sync::Arc::new(EgressGate::default());
        assert!(gate.wait_idle(&[10], Duration::from_millis(1)));
        let g = gate.enter(10);
        assert_eq!(gate.in_flight(10), 1);
        // Another process's egress does not hold this one.
        assert!(gate.wait_idle(&[11], Duration::from_millis(1)));
        assert!(!gate.wait_idle(&[10, 11], Duration::from_millis(20)));
        let g2 = gate.clone();
        let waiter = std::thread::spawn(move || g2.wait_idle(&[10], Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(30));
        drop(g);
        assert!(waiter.join().unwrap());
        assert_eq!(gate.in_flight(10), 0);
    }

    #[test]
    fn the_sweep_refuses_an_unadmitted_peer_or_an_unknown_socket() {
        let ok = |ip: IpAddr, port: u16, proto: Proto| is_session_proxy(ip, port, proto, &[8788]) || ip == "127.0.0.2".parse::<IpAddr>().unwrap();
        let lo = "127.0.0.1".parse().unwrap();
        let harmless = [HeldSocket::NotInet, HeldSocket::OtherNetns, HeldSocket::Listening, HeldSocket::Unconnected, HeldSocket::Peer(lo, 8788, Proto::Tcp), HeldSocket::Peer("127.0.0.2".parse().unwrap(), 53, Proto::Udp)];
        let unix_ok = |n: &str| n == "/run/bound/db.sock";
        assert_eq!(sweep_verdict(&harmless, ok, unix_ok), Ok(()));
        // Finding path 2: a socket connected before the taint, to an unbound peer.
        let mut held = harmless.to_vec();
        held.push(HeldSocket::Peer("127.0.0.3".parse().unwrap(), 53, Proto::Udp));
        assert_eq!(sweep_verdict(&held, ok, unix_ok), Err("127.0.0.3:53/udp".into()));
        // Path 3 through the sweep: 127.0.0.1 off the proxy ports.
        assert_eq!(sweep_verdict(&[HeldSocket::Peer(lo, 53, Proto::Udp)], ok, unix_ok), Err("127.0.0.1:53/udp".into()));
        assert!(sweep_verdict(&[HeldSocket::Peer("2001:db8::1".parse().unwrap(), 443, Proto::Tcp)], ok, unix_ok).unwrap_err().starts_with("[2001:db8::1]:443"));
        // Fail-closed on what cannot be told.
        assert!(sweep_verdict(&[HeldSocket::Unknown("no copy")], ok, unix_ok).unwrap_err().contains("no copy"));
        // 2026-10-02: a Unix socket connected before the taint to a named
        // peer is judged like a tainted Unix connect; a bound one passes.
        assert_eq!(sweep_verdict(&[HeldSocket::UnixPeer("/tmp/relay.sock".into())], ok, unix_ok), Err("unix:/tmp/relay.sock".into()));
        assert_eq!(sweep_verdict(&[HeldSocket::UnixPeer("@relay".into())], ok, unix_ok), Err("unix:@relay".into()));
        assert_eq!(sweep_verdict(&[HeldSocket::UnixPeer("/run/bound/db.sock".into())], ok, unix_ok), Ok(()));
    }

    #[test]
    fn unix_diag_requests_and_answers() {
        let r = unix_diag_request(7, 4242, UDIAG_SHOW_PEER, false);
        assert_eq!(r.len(), 40);
        assert_eq!(u32::from_ne_bytes(r[0..4].try_into().unwrap()), 40);
        assert_eq!(u16::from_ne_bytes(r[4..6].try_into().unwrap()), SOCK_DIAG_BY_FAMILY);
        assert_eq!(u16::from_ne_bytes(r[6..8].try_into().unwrap()), NLM_F_REQUEST);
        assert_eq!(r[16], AF_UNIX as u8);
        assert_eq!(u32::from_ne_bytes(r[24..28].try_into().unwrap()), 4242);
        assert_eq!(u32::from_ne_bytes(r[28..32].try_into().unwrap()), UDIAG_SHOW_PEER);
        let d = unix_diag_request(1, 0, UDIAG_SHOW_VFS | UDIAG_SHOW_NAME, true);
        assert_eq!(u16::from_ne_bytes(d[6..8].try_into().unwrap()), NLM_F_REQUEST | NLM_F_DUMP);
        // An answer: two sockets (one with a peer, one bound with a name and
        // a vfs entry), then DONE.
        let msg = |ino: u32, attrs: &[(u16, Vec<u8>)]| -> Vec<u8> {
            let mut body = vec![AF_UNIX as u8, 1, 1, 0];
            body.extend_from_slice(&ino.to_ne_bytes());
            body.extend_from_slice(&[0u8; 8]);
            for (ty, v) in attrs {
                let alen = 4 + v.len();
                body.extend_from_slice(&(alen as u16).to_ne_bytes());
                body.extend_from_slice(&ty.to_ne_bytes());
                body.extend_from_slice(v);
                body.resize(body.len() + ((alen + 3) & !3) - alen, 0);
            }
            let mut m = Vec::new();
            m.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
            m.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
            m.extend_from_slice(&[0u8; 10]);
            m.extend_from_slice(&body);
            m
        };
        let mut buf = msg(100, &[(UNIX_DIAG_PEER, 101u32.to_ne_bytes().to_vec())]);
        let mut vfs = 555u32.to_ne_bytes().to_vec();
        vfs.extend_from_slice(&((8u32 << 20) | 1).to_ne_bytes());
        buf.extend(msg(101, &[(UNIX_DIAG_NAME, b"/tmp/s.sock".to_vec()), (UNIX_DIAG_VFS, vfs)]));
        let (socks, done) = parse_unix_diag(&buf, true).unwrap();
        assert!(!done, "no DONE yet");
        assert_eq!(socks[0], UnixDiag { ino: 100, peer: Some(101), ..Default::default() });
        assert_eq!(socks[1].name.as_deref(), Some(&b"/tmp/s.sock"[..]));
        assert_eq!(socks[1].vfs, Some((555, (8 << 20) | 1)));
        let mut done_msg = vec![0u8; 20];
        done_msg[0..4].copy_from_slice(&20u32.to_ne_bytes());
        done_msg[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        buf.extend(done_msg);
        assert!(parse_unix_diag(&buf, true).unwrap().1);
        // An exact query is complete with its one answer; an error is an errno.
        assert!(parse_unix_diag(&msg(100, &[]), false).unwrap().1);
        let mut err = vec![0u8; 20];
        err[0..4].copy_from_slice(&20u32.to_ne_bytes());
        err[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        err[16..20].copy_from_slice(&(-2i32).to_ne_bytes());
        assert_eq!(parse_unix_diag(&err, false), Err(2));
        // dev_t: sda1 (8:1) as the kernel keeps it and as stat shows it.
        assert_eq!(kernel_dev_to_user((8 << 20) | 1), 0x801);
        assert_eq!(kernel_dev_to_user(0x123u32), 0x123 & 0xff | ((0x123 & !0xff) << 12));
    }

    #[test]
    fn a_sealed_queue_is_read_for_descriptors() {
        // Nothing queued.
        assert_eq!(queue_verdict(true, 0, None, false), QueueCheck::Clear);
        assert_eq!(queue_verdict(false, 0, None, false), QueueCheck::Clear);
        // A descriptor anywhere the peek reached.
        assert_eq!(queue_verdict(true, 100, Some(40), true), QueueCheck::Rights);
        assert_eq!(queue_verdict(false, 0, Some(0), true), QueueCheck::Rights);
        // A stream peek that read the whole queue and found none.
        assert_eq!(queue_verdict(true, 100, Some(100), false), QueueCheck::Clear);
        // One that stopped early (a credentials boundary), or a queue past the cap.
        assert!(matches!(queue_verdict(true, 100, Some(40), false), QueueCheck::Unknown(_)));
        assert!(matches!(queue_verdict(true, PEEK_MAX + 1, Some(PEEK_MAX), false), QueueCheck::Unknown(_)));
        // A datagram queued: only the first is seen.
        assert!(matches!(queue_verdict(false, 0, Some(12), false), QueueCheck::Unknown(_)));
    }
}
