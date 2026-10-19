//! events — build `net_action` observability events for ingress/egress and the
//! connect-guard's per-connect decisions. PURE. Best-effort emission (off the
//! security path).

use std::net::IpAddr;

use mandu_arbiter::event::*;
use mandu_arbiter::protocol::Trust;

use crate::guard::{Decision, Endpoint};
use crate::transform::{EgressResult, EgressSymbol, IngressResult};

/// `net_action` for one connect-guard DECISION (docs/design/integrity/exec-routing.md §7.5)
/// — the dashboard's allowed/denied-destination view. HumanView lane (an egress
/// decision on the wire side): `usage` is "allow" | "deny", and the reason names
/// the destination + the matched rule (or its absence). A DENY is the SAFE
/// outcome (the connect never leaves), so it never violates the ingress invariant.
pub fn guard_connect_event(
    session_id: &str,
    turn: u64,
    target: &Endpoint,
    decision: Decision,
    matched_rule: Option<&str>,
    blocked: Option<&str>,
) -> ManduEvent {
    guard_egress_event(session_id, turn, "connect", target, decision, matched_rule, blocked)
}

/// `guard_connect_event` for any egress the guard judges: `verb` is
/// "connect", or "send" for a datagram sent with an address
/// (exec-routing.md §7.5, 2026-10-01).
pub fn guard_egress_event(
    session_id: &str,
    turn: u64,
    verb: &str,
    target: &Endpoint,
    decision: Decision,
    matched_rule: Option<&str>,
    blocked: Option<&str>,
) -> ManduEvent {
    let proto = target.proto.name();
    let dest = format!("{}:{}/{proto}", target.ip, target.port);
    let (usage, reason) = match decision {
        Decision::Allow => (
            "allow",
            match matched_rule {
                Some(r) => format!("{verb} {dest} — ALLOWED (rule {r})"),
                None => format!("{verb} {dest} — ALLOWED"),
            },
        ),
        Decision::Deny => (
            "deny",
            match (blocked, matched_rule) {
                (Some(what), _) => format!("{verb} {dest} — DENIED in-kernel (always denied: {what}; EACCES)"),
                (None, Some(r)) => format!("{verb} {dest} — DENIED in-kernel (deny rule {r}; EACCES)"),
                (None, None) => format!("{verb} {dest} — DENIED in-kernel (no allow rule; EACCES)"),
            },
        ),
    };
    let policy = EventPolicy {
        usage: Some(usage.into()),
        reason: Some(reason),
        ..Default::default()
    };
    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::NetAction,
        view: View::HumanView,
        boundary: Boundary::Network,
        emitter: Emitter::NetSupervisor,
        input: None,
        // The destination is the renderable payload; no symbolization here.
        output: Some(DualRepr::new(dest, None, vec![])),
        policy: Some(policy),
        invariant: EventInvariant::ok(),
    }
}

/// Plan 10 §4.3, the network exit of a TAINTED process: the guard refused a
/// connect (INET or AF_UNIX) because the destination is not one of the
/// bindings of the secrets the process (or an ancestor) read raw. Carries the
/// SAME rule name as the net-proxy's proxied leg (`egress:tainted-process-
/// unbound`, net-proxy/src/egress.ts) so the dashboard reads the two legs as
/// one rule. HumanView lane, `usage` "deny"; the safe outcome, never a
/// violation. Names the secret FILES (paths, never contents) and the bindings.
pub fn guard_tainted_refusal_event(
    session_id: &str,
    dest: &str,
    files: &[String],
    bindings: &[String],
) -> ManduEvent {
    guard_tainted_refusal_event_verb(session_id, "connect", dest, files, bindings)
}

/// `guard_tainted_refusal_event` for any egress: `verb` is "connect",
/// "send" (a datagram with an address, or a send on a socket whose peer is
/// unbound), or "hold a connection to" (the taint-time sweep: the raw open
/// was refused because the process already held a socket to `dest`;
/// exec-routing.md §7.5, 2026-10-01), "accept a connection from" (a
/// holder's accept, ECONNABORTED) or "receive a connection to" (a socket
/// passed to a holder over SCM_RIGHTS; both 2026-10-02).
pub fn guard_tainted_refusal_event_verb(
    session_id: &str,
    verb: &str,
    dest: &str,
    files: &[String],
    bindings: &[String],
) -> ManduEvent {
    let what = if files.is_empty() { "a secret".to_string() } else { files.join(", ") };
    let to = if bindings.is_empty() { "no host".to_string() } else { bindings.join(", ") };
    // A refused accept answers ECONNABORTED (exec-routing.md §7.5, 2026-10-02).
    let errno = if verb.starts_with("accept") { "ECONNABORTED" } else { "EACCES" };
    let reason = format!(
        "{verb} {dest} — REFUSED in-kernel (egress:tainted-process-unbound: a process holding {what} may reach only {to}; {errno})"
    );
    let policy = EventPolicy {
        usage: Some("deny".into()),
        reason: Some(reason),
        ..Default::default()
    };
    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn: 0,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::NetAction,
        view: View::HumanView,
        boundary: Boundary::Network,
        emitter: Emitter::NetSupervisor,
        input: None,
        output: Some(DualRepr::new(dest.to_string(), None, vec![])),
        policy: Some(policy),
        invariant: EventInvariant::ok(),
    }
}

/// A connect to a secret socket (policy.yaml `ssh_agent`) by a program that
/// is not one of its readers (learn-from-nono §3.5).
pub fn guard_socket_refusal_event(session_id: &str, dest: &str, label: &str, exe: &str) -> ManduEvent {
    let reason = format!(
        "connect {dest} — REFUSED in-kernel (secret-socket-reader: {exe} is not a listed reader of the {label}; EACCES)"
    );
    let policy = EventPolicy {
        usage: Some("deny".into()),
        reason: Some(reason),
        ..Default::default()
    };
    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn: 0,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::NetAction,
        view: View::HumanView,
        boundary: Boundary::Network,
        emitter: Emitter::NetSupervisor,
        input: None,
        output: Some(DualRepr::new(dest.to_string(), None, vec![])),
        policy: Some(policy),
        invariant: EventInvariant::ok(),
    }
}

/// A connect refused on WSL because it would open the Windows interop door
/// (`guard::WslGuard`): the interop socket, or an AF_VSOCK address.
pub fn guard_wsl_refusal_event(session_id: &str, dest: &str, why: &str, exe: &str) -> ManduEvent {
    let reason = format!("connect {dest} by {exe} — REFUSED in-kernel ({why}; EACCES)");
    let policy = EventPolicy {
        usage: Some("deny".into()),
        reason: Some(reason),
        ..Default::default()
    };
    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn: 0,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::NetAction,
        view: View::HumanView,
        boundary: Boundary::Network,
        emitter: Emitter::NetSupervisor,
        input: None,
        output: Some(DualRepr::new(dest.to_string(), None, vec![])),
        policy: Some(policy),
        invariant: EventInvariant::ok(),
    }
}

/// A change under a write-protected path (the launcher's `writeProtect`,
/// sandbox-security-review-2026-09-28 findings 2 and 6), refused outright
/// (`deny` entries) or after an unanswered or denied hold (`ask` entries).
pub fn guard_write_refusal_event(session_id: &str, dest: &str, protected: &str, label: &str, why: &str) -> ManduEvent {
    let what = if label.is_empty() { String::new() } else { format!(", {label}") };
    let reason = format!("change of {dest} — REFUSED (write-protect: {protected}{what}; {why}; EACCES)");
    let policy = EventPolicy {
        usage: Some("deny".into()),
        reason: Some(reason),
        ..Default::default()
    };
    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn: 0,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::NetAction,
        view: View::HumanView,
        boundary: Boundary::Network,
        emitter: Emitter::NetSupervisor,
        input: None,
        output: Some(DualRepr::new(dest.to_string(), None, vec![])),
        policy: Some(policy),
        invariant: EventInvariant::ok(),
    }
}

/// A Unix socket connect refused by the allow-list
/// (sandbox-security-review-2026-09-28 finding 1): not on the list, and its
/// listener is not a process of the agent's tree.
pub fn guard_unix_refusal_event(session_id: &str, dest: &str, exe: &str, why: &str) -> ManduEvent {
    let who = if exe.is_empty() { String::new() } else { format!(" by {exe}") };
    let reason = format!("connect to {dest}{who} — REFUSED (unix-socket allow-list: {why}; EACCES)");
    let policy = EventPolicy {
        usage: Some("deny".into()),
        reason: Some(reason),
        ..Default::default()
    };
    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn: 0,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::NetAction,
        view: View::HumanView,
        boundary: Boundary::Network,
        emitter: Emitter::NetSupervisor,
        input: None,
        output: Some(DualRepr::new(dest.to_string(), None, vec![])),
        policy: Some(policy),
        invariant: EventInvariant::ok(),
    }
}

/// A delete or rename of a protected path (policy.yaml `protect:`).
pub fn guard_protect_refusal_event(session_id: &str, dest: &str, protected: &str) -> ManduEvent {
    protect_refusal(session_id, dest, &format!("{protected} is protected in policy.yaml"))
}

/// 2026-10-16 (`inode_pins`): a rename of a folder above a protected file
/// the guard holds no inode of (past the pin budget), refused. The same
/// `protected-path` shape as `guard_protect_refusal_event`.
pub fn guard_unpinned_rename_refusal_event(session_id: &str, dest: &str, file: &str) -> ManduEvent {
    protect_refusal(session_id, dest, &format!("{file} is a protected file Mandu could not hold by its inode, so a folder above it cannot move"))
}

fn protect_refusal(session_id: &str, dest: &str, why: &str) -> ManduEvent {
    let reason = format!("delete or rename of {dest} — REFUSED in-kernel (protected-path: {why}; EACCES)");
    let policy = EventPolicy {
        usage: Some("deny".into()),
        reason: Some(reason),
        ..Default::default()
    };
    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn: 0,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::NetAction,
        view: View::HumanView,
        boundary: Boundary::Network,
        emitter: Emitter::NetSupervisor,
        input: None,
        output: Some(DualRepr::new(dest.to_string(), None, vec![])),
        policy: Some(policy),
        invariant: EventInvariant::ok(),
    }
}

/// Plan 14 §11.1 R4: an object-store file of a repository the launch did not
/// prepare, refused because it holds a locked object (or its verdict could
/// not be reached). Names the repository and the file, never a byte; the
/// guard emits it once per repository per session.
pub fn guard_git_lock_refusal_event(session_id: &str, file: &str, repo: &str, why: &str) -> ManduEvent {
    let reason = format!(
        "read of {file} — REFUSED (git-lock: the repository {repo}: {why}; relaunch in it, or run `mandu policy suggest --root {repo}`; EACCES)"
    );
    let policy = EventPolicy {
        usage: Some("deny".into()),
        reason: Some(reason),
        ..Default::default()
    };
    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn: 0,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::NetAction,
        view: View::HumanView,
        boundary: Boundary::Network,
        emitter: Emitter::NetSupervisor,
        input: None,
        output: Some(DualRepr::new(repo.to_string(), None, vec![])),
        policy: Some(policy),
        invariant: EventInvariant::ok(),
    }
}

/// Plan 13 §4.9 (2026-10-07): a reader's raw open of `file` answered with
/// the placeholder twin because a network or FUSE mount that would see its
/// lookups is visible to it (`visible_mounts`; `why` names the mounts and
/// how to admit them). Names the file and the mounts, never a byte.
/// 2026-10-16 (docs/design/confidentiality/guard-file-identity.md §1, a history rewrite under the
/// guard): a refused removal, replacement or truncate of a git pack index
/// that anchors a locked pack's check (`git_lock::refuses`). Recorded on
/// every refusal (what tampering with the anchor looks like), but never told
/// in the end-of-session notice nor registered with the arbiter: it stops
/// nothing git needs (`git_lock::reported`).
pub fn guard_git_index_change_refusal_event(session_id: &str, file: &str, why: &str) -> ManduEvent {
    let reason = format!("change of {file} — REFUSED (git-index: a change to a git index that lists a locked object, or whose contents could not be told, while its pack is beside it: {why}; EACCES)");
    let policy = EventPolicy {
        usage: Some("deny".into()),
        reason: Some(reason),
        ..Default::default()
    };
    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn: 0,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::NetAction,
        view: View::HumanView,
        boundary: Boundary::Filesystem,
        emitter: Emitter::NetSupervisor,
        input: None,
        output: Some(DualRepr::new(file.to_string(), None, vec![])),
        policy: Some(policy),
        invariant: EventInvariant::ok(),
    }
}

pub fn guard_raw_withheld_event(session_id: &str, file: &str, exe: &str, why: &str) -> ManduEvent {
    let who = if exe.is_empty() { String::new() } else { format!(" by {exe}") };
    let reason = format!("read of {file}{who} — REAL FILE WITHHELD (remote-mount-visible: {why}; the placeholder copy was served)");
    let policy = EventPolicy {
        usage: Some("deny".into()),
        reason: Some(reason),
        ..Default::default()
    };
    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn: 0,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::NetAction,
        view: View::HumanView,
        boundary: Boundary::Filesystem,
        emitter: Emitter::NetSupervisor,
        input: None,
        output: Some(DualRepr::new(file.to_string(), None, vec![])),
        policy: Some(policy),
        invariant: EventInvariant::ok(),
    }
}

/// Which connect decisions are worth an event: every DENY (the security-relevant
/// blocked-exfil signal) plus every ALLOW to a NON-loopback destination. Loopback
/// ALLOWs (the model proxy / forwarder the agent hammers constantly) are skipped
/// so the event log is not flooded with service chatter.
pub fn guard_decision_is_noteworthy(decision: Decision, ip: IpAddr) -> bool {
    matches!(decision, Decision::Deny) || !ip.is_loopback()
}

/// The session the guard's events are filed under (exec-routing.md §7.5,
/// "Whose session"). `MANDU_SESSION_ID`, which the launcher sets for the
/// guard to its session id; else `MANDU_SCOPE_ID`, the same id, which every
/// launch puts in the agent's environment (the guard wraps the agent, so it
/// inherits it); else the sessionless `net-guard` log, for a guard run by
/// hand. An empty value counts as unset. Before 2026-10-07 the launcher set
/// neither for the guard to read, so a live session's refused connects landed
/// in the `net-guard` log and the session's own showed none of them.
pub fn guard_session_id(get: impl Fn(&str) -> Option<String>) -> String {
    for name in ["MANDU_SESSION_ID", "MANDU_SCOPE_ID"] {
        if let Some(v) = get(name) {
            let v = v.trim();
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    "net-guard".into()
}

/// `net_action` for an INGRESS transform. Symbolized untrusted bodies render in
/// AgentView; trusted passthrough renders in HumanView.
pub fn ingress_event(session_id: &str, turn: u64, origin: &str, r: &IngressResult) -> ManduEvent {
    let view = if r.trust == Trust::Untrusted {
        View::AgentView
    } else {
        View::HumanView
    };
    let symbols = match &r.symbol {
        Some(name) => vec![SymbolRef {
            name: name.clone(),
            tool: "net".into(),
            field: None,
            origin: Some(origin.to_string()),
            value: None,
            derived_from: None,
            line_range: None,
        }],
        None => vec![],
    };
    let policy = EventPolicy {
        trust: Some(match r.trust {
            Trust::Trusted => "TRUSTED",
            Trust::Untrusted => "UNTRUSTED",
        }
        .into()),
        category: r.category.clone(),
        reason: Some(r.reason.clone()),
        ..Default::default()
    };
    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::NetAction,
        view,
        boundary: Boundary::Network,
        emitter: Emitter::NetSupervisor,
        // output = what re-enters the agent (the symbolized body), with the raw
        // original on the HumanView pane.
        input: None,
        output: Some(DualRepr::new(
            r.agent_visible.clone(),
            Some(r.original.clone()),
            symbols,
        )),
        policy: Some(policy),
        invariant: if r.violated {
            EventInvariant::violated("un-symbolized untrusted bytes reached the agent")
        } else {
            EventInvariant::ok()
        },
    }
}

/// `net_action` for an EGRESS transform. HumanView lane (the wire carries the
/// desymbolized request); withheld symbols mark a needs-approval egress.
pub fn egress_event(
    session_id: &str,
    turn: u64,
    destination: &str,
    original_body: &str,
    r: &EgressResult,
) -> ManduEvent {
    let usage = if r.any_withheld {
        "needs_approval"
    } else {
        "allow"
    };
    let policy = EventPolicy {
        usage: Some(usage.into()),
        reason: Some(format!(
            "egress to '{destination}': {} symbol(s) decided, withheld={}",
            r.decisions.len(),
            r.decisions
                .iter()
                .filter(|d| matches!(d, EgressSymbol::Withheld { .. }))
                .count()
        )),
        ..Default::default()
    };
    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::NetAction,
        view: View::HumanView,
        boundary: Boundary::Network,
        emitter: Emitter::NetSupervisor,
        // input = the agent's symbolic body (AgentView) vs the wire bytes (Human).
        input: Some(DualRepr::new(
            original_body.to_string(),
            Some(r.wire_bytes.clone()),
            vec![],
        )),
        output: None,
        policy: Some(policy),
        // Withholding is the SAFE outcome; egress never violates the ingress
        // invariant (it is the desymbolization side).
        invariant: EventInvariant::ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::Proto;

    #[test]
    fn the_guard_files_its_events_under_the_launch_session() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
        };
        assert_eq!(guard_session_id(env(&[("MANDU_SESSION_ID", "s-1"), ("MANDU_SCOPE_ID", "scope")])), "s-1");
        // The launch's scope id, which every agent env carries, when the
        // session variable is absent or empty.
        assert_eq!(guard_session_id(env(&[("MANDU_SCOPE_ID", "1700000000-42")])), "1700000000-42");
        assert_eq!(guard_session_id(env(&[("MANDU_SESSION_ID", " "), ("MANDU_SCOPE_ID", "scope")])), "scope");
        // A guard run by hand: the sessionless log.
        assert_eq!(guard_session_id(env(&[])), "net-guard");
        assert_eq!(guard_session_id(env(&[("MANDU_SCOPE_ID", "")])), "net-guard");
    }

    #[test]
    fn a_send_and_a_sweep_name_their_own_verb() {
        let target = Endpoint { ip: "127.0.0.3".parse().unwrap(), port: 53, proto: Proto::Udp };
        let ev = guard_egress_event("s", 0, "send", &target, Decision::Deny, None, None);
        let reason = ev.policy.unwrap().reason.unwrap();
        assert!(reason.starts_with("send 127.0.0.3:53/udp — DENIED in-kernel"), "{reason}");
        let ev = guard_connect_event("s", 0, &target, Decision::Deny, None, None);
        assert!(ev.policy.unwrap().reason.unwrap().starts_with("connect 127.0.0.3:53/udp"));
        let ev = guard_tainted_refusal_event_verb("s", "hold a connection to", "127.0.0.3:53/udp", &["/h/.env".into()], &["127.0.0.2".into()]);
        let reason = ev.policy.unwrap().reason.unwrap();
        assert!(reason.starts_with("hold a connection to 127.0.0.3:53/udp — REFUSED"), "{reason}");
        assert!(reason.contains("egress:tainted-process-unbound") && reason.contains("/h/.env") && reason.contains("127.0.0.2"), "{reason}");
        let ev = guard_tainted_refusal_event("s", "1.2.3.4:443/tcp", &[], &[]);
        assert!(ev.policy.unwrap().reason.unwrap().starts_with("connect 1.2.3.4:443/tcp — REFUSED"));
        // 2026-10-02: a holder's refused accept says what its call answered.
        let ev = guard_tainted_refusal_event_verb("s", "accept a connection from", "10.77.0.2:40000/tcp", &[], &[]);
        let reason = ev.policy.unwrap().reason.unwrap();
        assert!(reason.starts_with("accept a connection from 10.77.0.2:40000/tcp — REFUSED") && reason.ends_with("ECONNABORTED)"), "{reason}");
        let ev = guard_tainted_refusal_event_verb("s", "receive a connection to", "203.0.113.9:443/tcp", &[], &[]);
        assert!(ev.policy.unwrap().reason.unwrap().ends_with("EACCES)"));
    }
    use crate::transform::EgressSymbol;

    #[test]
    fn ingress_untrusted_event_is_agentview() {
        let r = IngressResult {
            agent_visible: "$MDU:net[c0de]".into(),
            original: "evil".into(),
            trust: Trust::Untrusted,
            category: Some("URL".into()),
            symbol: Some("$MDU:net[c0de]".into()),
            reason: "untrusted".into(),
            arbiter_miss: false,
            violated: false,
        };
        let ev = ingress_event("s", 0, "http://evil", &r);
        assert_eq!(ev.view, View::AgentView);
        assert_eq!(ev.kind, EventKind::NetAction);
        assert!(!ev.invariant.violated_invariant);
        let out = ev.output.unwrap();
        assert_eq!(out.symbols.len(), 1);
        assert!(out.differs); // symbol != raw
    }

    #[test]
    fn git_lock_refusal_event_names_the_repository_and_the_fix() {
        let ev = guard_git_lock_refusal_event("s", "/w/a/.git/objects/pack/pack-1.pack", "/w/a", "it holds a locked object");
        assert_eq!(ev.policy.as_ref().unwrap().usage.as_deref(), Some("deny"));
        let reason = ev.policy.unwrap().reason.unwrap();
        assert!(reason.contains("/w/a/.git/objects/pack/pack-1.pack") && reason.contains("git-lock") && reason.contains("mandu policy suggest --root /w/a"), "{reason}");
        assert_eq!(ev.output.unwrap().symbolized, "/w/a");
        assert!(!ev.invariant.violated_invariant);
    }

    #[test]
    fn a_refused_folder_rename_above_an_unheld_file_is_a_protected_path_refusal() {
        let ev = guard_unpinned_rename_refusal_event("s", ".aws", "/h/.aws/credentials");
        let reason = ev.policy.unwrap().reason.unwrap();
        // The shape the session page reads as a protected-path refusal.
        assert!(reason.starts_with("delete or rename of .aws — REFUSED in-kernel (protected-path: /h/.aws/credentials is a protected file"), "{reason}");
        assert!(!reason.contains("policy.yaml"), "{reason}");
        let ev = guard_protect_refusal_event("s", "x", "/p");
        assert_eq!(ev.policy.unwrap().reason.unwrap(), "delete or rename of x — REFUSED in-kernel (protected-path: /p is protected in policy.yaml; EACCES)");
    }

    #[test]
    fn a_refused_index_change_is_recorded_as_a_change_never_as_a_refused_read() {
        let ev = guard_git_index_change_refusal_event("s", "/w/a/.git/objects/pack/pack-1.idx", "it lists a locked object");
        assert_eq!(ev.policy.as_ref().unwrap().usage.as_deref(), Some("deny"));
        assert_eq!(ev.boundary, Boundary::Filesystem);
        let reason = ev.policy.unwrap().reason.unwrap();
        assert!(reason.starts_with("change of /w/a/.git/objects/pack/pack-1.idx — REFUSED (git-index: a change to a git index that lists a locked object"), "{reason}");
        // Not the read refusal the session page counts as "git was refused",
        // and no repository advice.
        assert!(!reason.starts_with("read of") && !reason.contains("git-lock:") && !reason.contains("policy suggest"), "{reason}");
        assert_eq!(ev.output.unwrap().symbolized, "/w/a/.git/objects/pack/pack-1.idx");
        assert!(!ev.invariant.violated_invariant);
    }

    #[test]
    fn a_withheld_raw_open_names_the_file_the_reader_and_the_mounts() {
        let ev = guard_raw_withheld_event("s", "/h/.env", "/usr/bin/psql", "/home (nfs4, nas:/home) is visible");
        assert_eq!(ev.policy.as_ref().unwrap().usage.as_deref(), Some("deny"));
        assert_eq!(ev.boundary, Boundary::Filesystem);
        let reason = ev.policy.unwrap().reason.unwrap();
        assert!(reason.starts_with("read of /h/.env by /usr/bin/psql — REAL FILE WITHHELD (remote-mount-visible: /home (nfs4"), "{reason}");
        assert!(reason.ends_with("the placeholder copy was served)"), "{reason}");
        assert_eq!(ev.output.unwrap().symbolized, "/h/.env");
        assert!(!ev.invariant.violated_invariant);
    }

    #[test]
    fn guard_deny_event_is_deny_and_noteworthy() {
        let target = Endpoint { ip: "1.2.3.4".parse().unwrap(), port: 443, proto: Proto::Tcp };
        let ev = guard_connect_event("s", 0, &target, Decision::Deny, None, None);
        assert_eq!(ev.kind, EventKind::NetAction);
        assert_eq!(ev.emitter, Emitter::NetSupervisor);
        assert_eq!(ev.policy.as_ref().unwrap().usage.as_deref(), Some("deny"));
        assert!(ev.policy.unwrap().reason.unwrap().contains("1.2.3.4:443/tcp"));
        assert!(!ev.invariant.violated_invariant, "a deny is the safe outcome");
        // A deny to any host is always worth an event.
        assert!(guard_decision_is_noteworthy(Decision::Deny, "1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn guard_deny_event_names_an_always_denied_destination() {
        let target = Endpoint { ip: "169.254.169.254".parse().unwrap(), port: 80, proto: Proto::Tcp };
        let ev = guard_connect_event("s", 0, &target, Decision::Deny, None, Some("cloud metadata endpoint"));
        let reason = ev.policy.unwrap().reason.unwrap();
        assert!(reason.contains("always denied: cloud metadata endpoint"), "{reason}");
    }

    #[test]
    fn guard_deny_event_names_the_deny_rule() {
        let target = Endpoint { ip: "9.9.9.9".parse().unwrap(), port: 443, proto: Proto::Tcp };
        let ev = guard_connect_event("s", 0, &target, Decision::Deny, Some("tcp:upload.example:*"), None);
        let reason = ev.policy.unwrap().reason.unwrap();
        assert!(reason.contains("deny rule tcp:upload.example:*"), "{reason}");
    }

    #[test]
    fn guard_allow_event_names_the_rule_and_loopback_is_skipped() {
        let target = Endpoint { ip: "1.2.3.4".parse().unwrap(), port: 443, proto: Proto::Tcp };
        let ev = guard_connect_event("s", 0, &target, Decision::Allow, Some("tcp:1.2.3.4:443"), None);
        assert_eq!(ev.policy.as_ref().unwrap().usage.as_deref(), Some("allow"));
        assert!(ev.policy.unwrap().reason.unwrap().contains("rule tcp:1.2.3.4:443"));
        // A non-loopback allow IS noteworthy; a loopback allow (proxy chatter) is NOT.
        assert!(guard_decision_is_noteworthy(Decision::Allow, "1.2.3.4".parse().unwrap()));
        assert!(!guard_decision_is_noteworthy(Decision::Allow, "127.0.0.1".parse().unwrap()));
        assert!(!guard_decision_is_noteworthy(Decision::Allow, "::1".parse().unwrap()));
    }

    #[test]
    fn tainted_refusal_event_names_the_rule_files_and_bindings() {
        let files = vec!["/home/u/.pgpass".to_string()];
        let bindings = vec!["db.internal:5432".to_string(), "unix:/run/postgresql".to_string()];
        let ev = guard_tainted_refusal_event("s", "10.0.0.9:443/tcp", &files, &bindings);
        assert_eq!(ev.kind, EventKind::NetAction);
        assert_eq!(ev.view, View::HumanView);
        assert_eq!(ev.emitter, Emitter::NetSupervisor);
        let policy = ev.policy.unwrap();
        assert_eq!(policy.usage.as_deref(), Some("deny"));
        let reason = policy.reason.unwrap();
        // the net-proxy's rule name, so both legs read as one rule
        assert!(reason.contains("egress:tainted-process-unbound"), "{reason}");
        assert!(reason.contains("10.0.0.9:443/tcp") && reason.contains(".pgpass") && reason.contains("db.internal:5432"), "{reason}");
        assert!(!ev.invariant.violated_invariant, "a refusal is the safe outcome");
        // no files / no bindings: still a sentence
        let ev2 = guard_tainted_refusal_event("s", "unix:/tmp/x.sock", &[], &[]);
        let r2 = ev2.policy.unwrap().reason.unwrap();
        assert!(r2.contains("a secret") && r2.contains("no host"), "{r2}");
    }

    #[test]
    fn egress_withheld_event_marks_needs_approval() {
        let r = EgressResult {
            wire_bytes: "leak=$MDU:net[c0de]".into(),
            decisions: vec![EgressSymbol::Withheld {
                symbol: "$MDU:net[c0de]".into(),
                requires_approval: true,
                reason: "untrusted destination".into(),
            }],
            any_withheld: true,
            arbiter_miss: false,
        };
        let ev = egress_event("s", 0, "evil.example", "leak=$MDU:net[c0de]", &r);
        assert_eq!(ev.view, View::HumanView);
        assert_eq!(ev.policy.unwrap().usage.as_deref(), Some("needs_approval"));
    }

    #[test]
    fn a_wsl_refusal_names_the_door_and_the_program() {
        let ev = guard_wsl_refusal_event("s", "unix:/run/WSL/8_interop", "wsl-interop: the Windows interop socket", "/usr/bin/python3");
        assert_eq!(ev.kind, EventKind::NetAction);
        assert_eq!(ev.view, View::HumanView);
        let p = ev.policy.unwrap();
        assert_eq!(p.usage.as_deref(), Some("deny"));
        let reason = p.reason.unwrap();
        assert!(reason.contains("wsl-interop") && reason.contains("/usr/bin/python3") && reason.contains("EACCES"), "{reason}");
    }
}
