//! held_ask — a HIGH session's HELD command, refused at an unbound address,
//! asks the human (confidentiality.md §4, "A held command's refused
//! connection", 2026-10-12). `Mandu-new`.
//!
//! Under the guard every command of a HIGH session holds what the session
//! read (`sessionExecRoot`, one `session` taint row per datum), so its
//! connections go only to those data's bound hosts. When the connect leg
//! refuses one, the guard names the address to the arbiter
//! (`taintedProcessBindings` with `destination` and `sessionAskOnly`, human
//! plane): the arbiter consults (and spends) the human's answer for the
//! session's own network question (`session-net:<session>` × the address)
//! or files it. Only `approved` on THAT question lets this one connect go;
//! the arbiter spends a once in the same call, so the next connect asks
//! again. Anything else (pending, denied, a holder's question, no answer,
//! an arbiter that cannot be asked) leaves the refusal standing.
//!
//! A connection let through this way is then a socket whose peer is not
//! among the holder's bindings; the send trap judges a holder's addressless
//! send by its peer, so it remembers the socket (`OnceAdmitted`) and lets
//! that socket's own sends go to that peer. Nothing else is widened: another
//! socket, another peer, or a send with an address is judged as before.
//!
//! Pure: the address words, the answer's reading and the remembered set.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;

use mandu_arbiter::protocol::TaintAsk;

/// The address a held connect names (`ip:port`, `[v6]:port`): what the row
/// is keyed by, the card shows, and the next connect must name again.
pub fn held_destination(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => format!("{v4}:{port}"),
            None => format!("[{v6}]:{port}"),
        },
    }
}

/// Does the arbiter's answer let this one connect go? Only a human's
/// approval of the HIGH session's own question (the arbiter spent a once
/// in giving it). Fail-closed on anything else.
pub fn ask_admits(ask: Option<&TaintAsk>) -> bool {
    matches!(ask, Some(a) if a.status == "approved" && a.question.as_deref() == Some("session") && !a.approval_id.is_empty())
}

/// The most sockets remembered; the oldest is forgotten first (its sends,
/// should it still be open, are then judged by its peer again: refused).
pub const ONCE_ADMITTED_MAX: usize = 1024;

/// The sockets a human's Allow once connected, by (socket inode, peer
/// address, peer port): a send on one of them to that peer is the
/// connection the human allowed, not a new one. An inode reused by a later
/// socket matches only with the same peer, the host the human allowed.
#[derive(Debug, Default)]
pub struct OnceAdmitted {
    inner: Mutex<VecDeque<(u64, IpAddr, u16)>>,
}

impl OnceAdmitted {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember a socket connected under an Allow once.
    pub fn admit(&self, ino: u64, ip: IpAddr, port: u16) {
        let Ok(mut q) = self.inner.lock() else { return };
        let key = (ino, canonical(ip), port);
        if q.contains(&key) {
            return;
        }
        if q.len() >= ONCE_ADMITTED_MAX {
            q.pop_front();
        }
        q.push_back(key);
    }

    /// Was this socket, with this peer, connected under an Allow once?
    /// A poisoned lock answers no (fail-closed).
    pub fn contains(&self, ino: u64, ip: IpAddr, port: u16) -> bool {
        self.inner.lock().map(|q| q.contains(&(ino, canonical(ip), port))).unwrap_or(false)
    }
}

/// An IPv4-mapped v6 peer is the v4 address it maps (a dual-stack socket's
/// `getpeername` and the address its connect named can differ in form).
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ask(status: &str, question: Option<&str>) -> TaintAsk {
        TaintAsk { approval_id: "egr-1".into(), status: status.into(), scope: Some("once".into()), question: question.map(String::from) }
    }

    #[test]
    fn the_destination_is_the_address_as_the_row_keys_it() {
        assert_eq!(held_destination(ip("203.0.113.9"), 443), "203.0.113.9:443");
        assert_eq!(held_destination(ip("2001:db8::1"), 8443), "[2001:db8::1]:8443");
        assert_eq!(held_destination(ip("::ffff:127.0.0.1"), 80), "127.0.0.1:80", "a mapped v4 address is named as v4");
    }

    #[test]
    fn only_an_approval_of_the_session_question_admits() {
        assert!(ask_admits(Some(&ask("approved", Some("session")))));
        assert!(!ask_admits(Some(&ask("pending", Some("session")))), "asked, not answered");
        assert!(!ask_admits(Some(&ask("denied", Some("session")))), "Block is final");
        assert!(!ask_admits(Some(&ask("approved", Some("holder")))), "a holder's question is not this leg's");
        assert!(!ask_admits(Some(&ask("approved", None))), "an older arbiter's answer names no question");
        assert!(!ask_admits(None), "no answer: refused");
        let mut no_id = ask("approved", Some("session"));
        no_id.approval_id.clear();
        assert!(!ask_admits(Some(&no_id)));
    }

    #[test]
    fn a_remembered_socket_matches_only_its_own_peer() {
        let s = OnceAdmitted::new();
        s.admit(42, ip("203.0.113.9"), 443);
        assert!(s.contains(42, ip("203.0.113.9"), 443));
        assert!(s.contains(42, ip("::ffff:203.0.113.9"), 443), "the same peer in mapped form");
        assert!(!s.contains(42, ip("203.0.113.9"), 80), "another port");
        assert!(!s.contains(42, ip("198.51.100.7"), 443), "another peer");
        assert!(!s.contains(43, ip("203.0.113.9"), 443), "another socket");
    }

    #[test]
    fn the_set_is_bounded_and_forgets_the_oldest() {
        let s = OnceAdmitted::new();
        for i in 0..(ONCE_ADMITTED_MAX as u64 + 1) {
            s.admit(i, ip("203.0.113.9"), 443);
        }
        assert!(!s.contains(0, ip("203.0.113.9"), 443), "the oldest is forgotten");
        assert!(s.contains(ONCE_ADMITTED_MAX as u64, ip("203.0.113.9"), 443));
        s.admit(1, ip("203.0.113.9"), 443);
        assert!(s.contains(1, ip("203.0.113.9"), 443), "admitting again is idempotent");
    }
}
