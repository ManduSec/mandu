//! accept_guard — the PURE half of judging an ACCEPT (exec-routing.md §7.5,
//! "A holder's accept", 2026-10-02).
//!
//! Until 2026-10-02 `accept` was not trapped: a process holding a secret
//! that listened (a dev server tainted by its `.env`, or `node -e` that read
//! `~/.npmrc` and serves it) answered whoever connected, local or remote.
//! Under a secret policy the guard now performs every `accept` and
//! `accept4` itself, on its copy of the listening socket (the kernel half,
//! `guard_accept`), and judges the connection before the tracee gets it:
//!
//!   - a process that holds NO secret gets every connection, as before (the
//!     guard performs its accept only so that one which completes while the
//!     process becomes a holder is judged too: the taint waits for it,
//!     `send_guard::EgressGate`);
//!   - a holder gets a connection from THIS machine (a loopback address, or
//!     the connection's own local address: the user's browser on
//!     `localhost:3000`, the agent's own `curl`, the net-proxy), the IPC that
//!     plan 10 §6 accepts like a pipe, and one from a host its secrets are
//!     bound to (judged like a connect to the peer's address); every other
//!     peer is refused: the guard resets the connection and the tracee's
//!     call answers ECONNABORTED, which every runtime's accept loop takes as
//!     "that one went away, accept the next" (libuv, Go, Python's
//!     socketserver);
//!   - a holder's Unix connection is local IPC and is taken, sealed against
//!     descriptors passed in later where the kernel can (`SO_PASSRIGHTS`,
//!     `guard_accept`).
//!
//! This module decides, with no syscalls: the call's flags as the kernel
//! checks them, whether a peer is on this machine, the verdict, and how
//! much of the peer's address the tracee's buffer takes.
//!
//! `Mandu-new`.

use std::net::IpAddr;

/// `accept4` flags (the same on x86_64 and aarch64).
pub const SOCK_NONBLOCK: i32 = 0o4000;
pub const SOCK_CLOEXEC: i32 = 0o2000000;

const EINVAL: i32 = 22;
/// What a refused connection's accept answers.
pub const ECONNABORTED: i32 = 103;

/// The accept family the filter hands to the supervisor.
pub fn accept_nrs() -> [i64; 2] {
    [libc::SYS_accept as i64, libc::SYS_accept4 as i64]
}

pub fn is_accept_nr(nr: i64) -> bool {
    accept_nrs().contains(&nr)
}

/// The flags of the call: `accept` has none; `accept4`'s are checked as
/// `__sys_accept4` checks them (anything but `SOCK_CLOEXEC | SOCK_NONBLOCK`
/// is EINVAL, before the descriptor is looked at).
pub fn accept_flags(nr: i64, arg3: u64) -> Result<i32, i32> {
    if nr != libc::SYS_accept4 as i64 {
        return Ok(0);
    }
    let f = arg3 as u32 as i32;
    if f & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
        return Err(EINVAL);
    }
    Ok(f)
}

fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Is a peer on THIS machine: a loopback address (no packet with such a
/// source comes in from a wire), or the connection's own local address (a
/// client here that reached a non-loopback address of this host gets that
/// address as its source)? A container's or another namespace's address is
/// not: it is judged like any remote peer.
pub fn is_local_peer(peer: IpAddr, local: Option<IpAddr>) -> bool {
    let p = unmapped(peer);
    if p.is_loopback() {
        return true;
    }
    match local.map(unmapped) {
        Some(l) => !l.is_unspecified() && l == p,
        None => false,
    }
}

/// The verdict on one accepted connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptVerdict {
    Admit,
    /// Reset it; the tracee's call answers ECONNABORTED.
    Refuse,
}

/// What the guard knows about one accepted connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accepted {
    /// An INET connection: the peer, and the connection's local address.
    Inet {
        peer: IpAddr,
        port: u16,
        local: Option<IpAddr>,
    },
    /// A Unix connection (local IPC).
    Unix,
    /// Any other family (it has no binding to name it).
    Other,
    /// A socket of another network namespace (a nested net-dead box): that
    /// namespace is the boundary.
    OtherNetns,
}

/// Judge one connection a process accepted. `held`: the process holds (or
/// inherits) a secret. `bound(ip, port)`: its secrets' bindings admit the
/// peer as a destination (`None` when they cannot be asked: refused).
pub fn accept_verdict(
    held: bool,
    conn: &Accepted,
    bound: impl FnOnce(IpAddr, u16) -> Option<bool>,
) -> AcceptVerdict {
    if !held {
        return AcceptVerdict::Admit;
    }
    match conn {
        Accepted::Unix | Accepted::OtherNetns => AcceptVerdict::Admit,
        Accepted::Other => AcceptVerdict::Refuse,
        Accepted::Inet { peer, port, local } => {
            if is_local_peer(*peer, *local) {
                return AcceptVerdict::Admit;
            }
            match bound(*peer, *port) {
                Some(true) => AcceptVerdict::Admit,
                _ => AcceptVerdict::Refuse,
            }
        }
    }
}

/// How many bytes of the peer's address (`klen` long) go into the tracee's
/// buffer, given the length it passed in `*addrlen`: `move_addr_to_user`
/// refuses a negative length (EINVAL) and truncates to the buffer; it then
/// writes the FULL length back.
pub fn addr_copy_len(user_len: i32, klen: usize) -> Result<usize, i32> {
    if user_len < 0 {
        return Err(EINVAL);
    }
    Ok((user_len as usize).min(klen))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn flags_are_checked_like_the_kernel() {
        let a4 = libc::SYS_accept4 as i64;
        assert_eq!(
            accept_flags(libc::SYS_accept as i64, 0xdead),
            Ok(0),
            "accept has no flags argument"
        );
        assert_eq!(accept_flags(a4, 0), Ok(0));
        assert_eq!(
            accept_flags(a4, (SOCK_CLOEXEC | SOCK_NONBLOCK) as u64),
            Ok(SOCK_CLOEXEC | SOCK_NONBLOCK)
        );
        assert_eq!(accept_flags(a4, 1), Err(EINVAL));
        assert_eq!(accept_flags(a4, (SOCK_CLOEXEC | 0x40) as u64), Err(EINVAL));
        // The kernel reads an int: the high word is not part of it.
        assert_eq!(
            accept_flags(a4, (1u64 << 32) | SOCK_NONBLOCK as u64),
            Ok(SOCK_NONBLOCK)
        );
        assert!(
            is_accept_nr(a4)
                && is_accept_nr(libc::SYS_accept as i64)
                && !is_accept_nr(libc::SYS_connect as i64)
        );
    }

    #[test]
    fn a_peer_on_this_machine_is_loopback_or_the_connections_own_address() {
        assert!(is_local_peer(ip("127.0.0.1"), Some(ip("127.0.0.1"))));
        assert!(is_local_peer(ip("127.0.0.7"), Some(ip("10.0.0.5"))));
        assert!(is_local_peer(ip("::1"), None));
        assert!(is_local_peer(
            ip("::ffff:127.0.0.1"),
            Some(ip("::ffff:127.0.0.1"))
        ));
        // A client here that dialed this host's LAN address.
        assert!(is_local_peer(ip("192.168.1.5"), Some(ip("192.168.1.5"))));
        assert!(is_local_peer(
            ip("::ffff:192.168.1.5"),
            Some(ip("192.168.1.5"))
        ));
        // Another machine, a container on a bridge, another namespace.
        assert!(!is_local_peer(ip("192.168.1.9"), Some(ip("192.168.1.5"))));
        assert!(!is_local_peer(ip("172.17.0.2"), Some(ip("172.17.0.1"))));
        assert!(!is_local_peer(ip("10.77.0.2"), None));
        assert!(!is_local_peer(ip("0.0.0.0"), Some(ip("0.0.0.0"))));
    }

    #[test]
    fn a_holder_takes_local_and_bound_peers_only() {
        let remote = Accepted::Inet {
            peer: ip("10.77.0.2"),
            port: 40000,
            local: Some(ip("10.77.0.1")),
        };
        let local = Accepted::Inet {
            peer: ip("127.0.0.1"),
            port: 40000,
            local: Some(ip("127.0.0.1")),
        };
        let never =
            |_: IpAddr, _: u16| -> Option<bool> { panic!("an untainted accept asks nothing") };
        // An untainted process: every connection, as before.
        assert_eq!(accept_verdict(false, &remote, never), AcceptVerdict::Admit);
        assert_eq!(
            accept_verdict(false, &Accepted::Other, never),
            AcceptVerdict::Admit
        );
        // A holder.
        let unbound = |_: IpAddr, _: u16| Some(false);
        assert_eq!(
            accept_verdict(true, &local, unbound),
            AcceptVerdict::Admit,
            "the user's browser, the agent's curl"
        );
        assert_eq!(
            accept_verdict(true, &remote, unbound),
            AcceptVerdict::Refuse,
            "another machine"
        );
        assert_eq!(
            accept_verdict(true, &remote, |p, _| Some(p == ip("10.77.0.2"))),
            AcceptVerdict::Admit,
            "a bound host"
        );
        assert_eq!(
            accept_verdict(true, &remote, |_, _| None),
            AcceptVerdict::Refuse,
            "the bindings cannot be asked"
        );
        assert_eq!(
            accept_verdict(true, &Accepted::Unix, unbound),
            AcceptVerdict::Admit
        );
        assert_eq!(
            accept_verdict(true, &Accepted::OtherNetns, unbound),
            AcceptVerdict::Admit
        );
        assert_eq!(
            accept_verdict(true, &Accepted::Other, unbound),
            AcceptVerdict::Refuse
        );
    }

    #[test]
    fn the_peer_address_is_copied_like_move_addr_to_user() {
        assert_eq!(addr_copy_len(128, 16), Ok(16));
        assert_eq!(addr_copy_len(8, 16), Ok(8));
        assert_eq!(addr_copy_len(0, 16), Ok(0));
        assert_eq!(addr_copy_len(-1, 16), Err(EINVAL));
    }
}
