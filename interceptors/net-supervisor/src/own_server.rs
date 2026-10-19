//! own_server — the agent's PRIVATE server under the kernel layer
//! (supported-agents.md §2.3.1, exec-routing.md §7.5 "The agent's own
//! server"; 2026-10-05).
//!
//! OpenCode 2's CLI is a client of an OpenCode server. Mandu launches it with
//! `--standalone` (launcher opencode-argv.ts): the client (the first-started
//! process of the agent's executable, `guard_flow::agent_keys`'s rule)
//! spawns its server as a CHILD running the same executable
//! (`opencode serve --stdio --port 0`), which binds an ephemeral port on
//! 127.0.0.1, and the client talks to it over loopback TCP. The server runs
//! the model calls and the agent's tools (its `shell` tool's commands are the
//! server's children).
//!
//! Under the default kernel layer neither leg worked: the whole-agent
//! landlock-net wrap refuses the bind (no bind port is granted) and the guard
//! refuses the connect (only Mandu's own loopback ports are allowed). Opening
//! either the way an allow-list could (an ephemeral bind for the tree, a
//! loopback port for the tree) would hand every process of the tree the
//! server's API, and that API carries a program's output into the
//! conversation as the user's own message (`POST /api/session/<id>/shell`,
//! measured on 2.0.23), past every tool-result check. So the guard admits
//! exactly two things, only when the launch names the agent's executable in
//! `OWN_SERVER_ENV` (an OpenCode 2 launch):
//!
//!   - BIND: a stream socket of the client's OWN SERVER (a direct child of a
//!     client process, running the agent's executable, not itself a client)
//!     to a loopback address at port 0 (an ephemeral port). The guard
//!     performs it on its copy of the socket, outside the launch's port
//!     wrap (a Landlock layer the server nested itself still decides:
//!     `landlock_mirror::connect_via`). Every other bind runs as before.
//!   - CONNECT: a TCP connect FROM a client process TO a loopback listener
//!     every holder of which is the client's own server (each listening
//!     socket at that destination has at least one holder in the tree, and
//!     every holder is an own server). Never from the server's descendants
//!     (the agent's commands), never from a later process of the same
//!     executable (a nested `opencode run`), never to a listener outside the
//!     tree (the user's background service).
//!
//!   - and no other process may trace the client or read or write its
//!     memory (ptrace, process_vm_*; `introspection_refused`), nor copy a
//!     descriptor out of any process (pidfd_getfd is refused for the whole
//!     tree): either would let it connect in the client's name.
//!
//! The decisions are pure here (the facts in, a verdict out); reading the
//! facts from /proc and enacting them is `guard_kernel`'s (feature `kernel`).
//!
//! `Mandu-new`.

use std::net::IpAddr;

/// The launch variable naming the agent's executable (its real path) for
/// this allowance; unset or empty = off. The launcher sets it for an
/// OpenCode 2 launch only.
pub const OWN_SERVER_ENV: &str = "MANDU_NET_GUARD_OWN_SERVER";

/// The executable named by `OWN_SERVER_ENV`'s value, or None (off). An
/// executable must be an absolute path: anything else is off (fail-closed:
/// nothing is admitted). Pure.
pub fn exe_from_env_value(v: Option<&str>) -> Option<String> {
    let v = v?.trim();
    (v.starts_with('/') && v.len() > 1).then(|| v.to_string())
}

/// What the guard knows of one process for these decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcFacts {
    /// Its proc key (`<tgid>-<start>`).
    pub key: String,
    /// Its parent's proc key, when it could be read.
    pub parent_key: Option<String>,
    /// Its executable's path (`/proc/<pid>/exe`), when it could be read.
    pub exe: Option<String>,
}

/// Is `ip` a loopback address (127.0.0.0/8, ::1, or a v4-mapped 127/8)?
pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_loopback(),
        IpAddr::V6(a) => a.is_loopback() || a.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(false),
    }
}

/// Is `p` the client's own server: a direct child of a client process,
/// running the agent's executable, and not itself a client? Pure.
pub fn is_own_server(exe: &str, client_keys: &[String], p: &ProcFacts) -> bool {
    !client_keys.is_empty()
        && p.exe.as_deref() == Some(exe)
        && p.parent_key.as_ref().map(|k| client_keys.contains(k)).unwrap_or(false)
        && !client_keys.contains(&p.key)
}

/// May `caller` bind its socket to (`ip`, `port`)? Only the client's own
/// server, only a stream socket, only a loopback address, only port 0. Pure.
pub fn bind_allowed(exe: &str, client_keys: &[String], caller: &ProcFacts, ip: IpAddr, port: u16, stream: bool) -> bool {
    stream && port == 0 && is_loopback(ip) && is_own_server(exe, client_keys, caller)
}

/// May the process `caller_key` connect over TCP to a loopback destination
/// whose listening sockets have these holders (one list per listening
/// socket at that destination, the holders the guard found in its tree)?
/// Only a client process, only TCP, only loopback, and only when there is a
/// listener and every listener's every holder is the client's own server (a
/// listener with no holder in the tree is someone else's: refused). Pure.
pub fn connect_allowed(exe: &str, client_keys: &[String], caller_key: &str, ip: IpAddr, tcp: bool, listeners: &[Vec<ProcFacts>]) -> bool {
    tcp && is_loopback(ip)
        && client_keys.iter().any(|k| k == caller_key)
        && !listeners.is_empty()
        && listeners.iter().all(|holders| !holders.is_empty() && holders.iter().all(|h| is_own_server(exe, client_keys, h)))
}

/// Is `p` a fork of the client's own server that has not exec'd yet: a direct
/// child of `parent`, an own server, still on the agent's executable (a fork
/// keeps its parent's image until its exec)? Until that exec it holds a copy
/// of every descriptor of the server, the listener included. The guard waits
/// for such a holder to drop the listener (it holds it only through
/// close-on-exec descriptors) before it judges the client's connect, the way
/// the sweep waits for a fork of the agent (`guard_flow::flow_readers`): the
/// server spawns its commands as the client connects, and on a loaded host
/// the connect landed in a fork's window and was refused (OpenCode 2's
/// "Transport: Was there a typo in the url or port?", 2026-10-07). Waiting
/// admits nothing new: a holder still there at the deadline, or one that is
/// not such a fork, refuses as before. Pure.
pub fn own_server_fork(exe: &str, client_keys: &[String], p: &ProcFacts, parent: &ProcFacts) -> bool {
    p.exe.as_deref() == Some(exe)
        && p.parent_key.as_deref() == Some(parent.key.as_str())
        && !client_keys.contains(&p.key)
        && is_own_server(exe, client_keys, parent)
}

/// What the guard's first look at a holder of the own server's listener
/// finds (`first_look`), for the connect's wait (`guard_flow::
/// own_server_listeners`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderLook {
    /// A child of the own server caught INSIDE its exec: past the switch to
    /// the new image (`/proc/<pid>/exe` already names it), with no argv yet
    /// (`pipe_flow::exec_in_progress`), and still holding every descriptor
    /// of the server, which the kernel closes a moment later in the same
    /// exec. Waited for until that exec ends, then judged on the table it
    /// ends with (`guard_flow::wait_exec_done`).
    InsideExec,
    /// A fork of the own server before its exec (`own_server_fork`) that
    /// holds the listener only through close-on-exec descriptors: waited for
    /// to drop it (`guard_flow::wait_close_on_exec_drop`).
    ForkBeforeExec,
    /// Anything else: a holder now.
    Holder,
}

/// Is `p` a child of the client's own server `parent` caught inside its
/// exec (`cmdline` and `state` are `p`'s `/proc/<pid>/cmdline` and stat
/// state)? Its image is not looked at: inside the exec it shows the new one.
/// Pure.
pub fn own_server_child_inside_exec(exe: &str, client_keys: &[String], p: &ProcFacts, parent: &ProcFacts, cmdline: &[u8], state: char) -> bool {
    p.parent_key.as_deref() == Some(parent.key.as_str())
        && !client_keys.contains(&p.key)
        && is_own_server(exe, client_keys, parent)
        && crate::pipe_flow::exec_in_progress(cmdline, state)
}

/// The first look at `p`, a holder of the own server's listener: `parent`
/// is its parent's facts, `cmdline` and `state` its `/proc/<pid>/cmdline`
/// and stat state, `only_cloexec` whether it holds the listener only through
/// close-on-exec descriptors (`pipe_flow::receives_only_until_exec`).
///
/// 2026-10-17: a first look that landed inside the fork's exec (the image
/// switched, the close-on-exec descriptors not closed yet) found a process
/// on another image holding the listener, a holder: the client's connect
/// was refused though the exec closes that descriptor a moment later (the
/// residual !982 left). Inside the exec is checked first: a process faking
/// it (`exec_in_progress`) on the agent's image is waited for no longer than
/// a fork before its exec, and judged no more leniently. Pure.
pub fn first_look(exe: &str, client_keys: &[String], p: &ProcFacts, parent: &ProcFacts, cmdline: &[u8], state: char, only_cloexec: bool) -> HolderLook {
    if own_server_child_inside_exec(exe, client_keys, p, parent, cmdline, state) {
        HolderLook::InsideExec
    } else if own_server_fork(exe, client_keys, p, parent) && only_cloexec {
        HolderLook::ForkBeforeExec
    } else {
        HolderLook::Holder
    }
}

/// The agent (confidentiality-plan-13 D2) when the launch runs a private
/// server: the client processes `clients` AND their own servers among
/// `children` (the client processes' children). Under OpenCode 2 the server
/// is the process that holds every tool call's output, makes the model calls
/// and spawns each tool call's shell, which is what D2's agent is: never made
/// a holder by what reaches it (the model exit masks it), the parent of the
/// call roots (D7), the process whose own receipts are agent flows. The
/// client stays in too (it receives the server's stream over its loopback
/// connection). With no client, nothing (fail-closed: no exemption). Pure.
pub fn agent_with_own_servers(exe: &str, clients: &[String], children: &[ProcFacts]) -> Vec<String> {
    let mut out = clients.to_vec();
    for c in children {
        if is_own_server(exe, clients, c) && !out.contains(&c.key) {
            out.push(c.key.clone());
        }
    }
    out
}

/// May the process `caller_key` trace, or read or write the memory of, the
/// processes `target_keys` (ptrace, process_vm_*)? Not when one of them is a
/// client and the caller is not that client: it could then connect to the
/// private server in the client's name. Pure.
pub fn introspection_refused(client_keys: &[String], caller_key: &str, target_keys: &[String]) -> bool {
    !client_keys.iter().any(|k| k == caller_key) && target_keys.iter().any(|t| client_keys.contains(t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const EXE: &str = "/opt/oc/bin/opencode.exe";

    fn p(key: &str, parent: Option<&str>, exe: Option<&str>) -> ProcFacts {
        ProcFacts { key: key.into(), parent_key: parent.map(Into::into), exe: exe.map(Into::into) }
    }
    fn clients() -> Vec<String> {
        vec!["100-1".into()]
    }
    const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[test]
    fn the_variable_names_an_absolute_executable_or_nothing() {
        assert_eq!(exe_from_env_value(Some(EXE)), Some(EXE.to_string()));
        assert_eq!(exe_from_env_value(Some(" /x/oc ")), Some("/x/oc".to_string()));
        for v in [None, Some(""), Some("  "), Some("opencode"), Some("./oc"), Some("/")] {
            assert_eq!(exe_from_env_value(v), None, "{v:?}");
        }
    }

    #[test]
    fn loopback_is_127_8_and_v6_localhost_and_their_mapped_form() {
        assert!(is_loopback(LO));
        assert!(is_loopback(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9))));
        assert!(is_loopback(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_loopback(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped())));
        assert!(!is_loopback(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!is_loopback(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!is_loopback(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
    }

    #[test]
    fn the_own_server_is_a_direct_child_of_a_client_on_the_agents_executable() {
        assert!(is_own_server(EXE, &clients(), &p("200-5", Some("100-1"), Some(EXE))));
        // A grandchild (an agent's command under the server), even on the same executable.
        assert!(!is_own_server(EXE, &clients(), &p("300-9", Some("200-5"), Some(EXE))));
        // A child of the client on another executable (a shell, a helper).
        assert!(!is_own_server(EXE, &clients(), &p("201-6", Some("100-1"), Some("/bin/sh"))));
        // Unreadable facts, or no client known: never.
        assert!(!is_own_server(EXE, &clients(), &p("202-7", None, Some(EXE))));
        assert!(!is_own_server(EXE, &clients(), &p("203-8", Some("100-1"), None)));
        assert!(!is_own_server(EXE, &[], &p("200-5", Some("100-1"), Some(EXE))));
        // A client is never its own server (a script launcher's child is a client too).
        let two = vec!["100-1".to_string(), "101-2".to_string()];
        assert!(!is_own_server(EXE, &two, &p("101-2", Some("100-1"), Some(EXE))));
    }

    #[test]
    fn bind_only_the_own_server_only_loopback_only_an_ephemeral_stream_port() {
        let server = p("200-5", Some("100-1"), Some(EXE));
        assert!(bind_allowed(EXE, &clients(), &server, LO, 0, true));
        assert!(bind_allowed(EXE, &clients(), &server, IpAddr::V6(Ipv6Addr::LOCALHOST), 0, true));
        assert!(!bind_allowed(EXE, &clients(), &server, LO, 4096, true), "a fixed port: the launch's bind list decides");
        assert!(!bind_allowed(EXE, &clients(), &server, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, true), "a wildcard is reachable from the network");
        assert!(!bind_allowed(EXE, &clients(), &server, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 0, true));
        assert!(!bind_allowed(EXE, &clients(), &server, LO, 0, false), "a datagram socket");
        // The client itself, an agent's command, a nested opencode's server: no.
        assert!(!bind_allowed(EXE, &clients(), &p("100-1", Some("1-1"), Some(EXE)), LO, 0, true));
        assert!(!bind_allowed(EXE, &clients(), &p("300-9", Some("200-5"), Some(EXE)), LO, 0, true));
        assert!(!bind_allowed(EXE, &clients(), &p("400-3", Some("300-9"), Some(EXE)), LO, 0, true));
    }

    #[test]
    fn the_agent_is_the_client_and_its_own_server() {
        let c = clients();
        let kids = vec![
            p("200-5", Some("100-1"), Some(EXE)),                  // the own server
            p("201-6", Some("100-1"), Some("/bin/sh")),            // another child of the client
            p("300-9", Some("200-5"), Some(EXE)),                  // a grandchild on the same executable (nested opencode)
            p("202-7", Some("100-1"), None),                       // unreadable
        ];
        assert_eq!(agent_with_own_servers(EXE, &c, &kids), vec!["100-1".to_string(), "200-5".to_string()]);
        // No server yet: the client alone (D2 as before).
        assert_eq!(agent_with_own_servers(EXE, &c, &[]), c);
        // No client known: nobody is the agent.
        assert!(agent_with_own_servers(EXE, &[], &kids).is_empty());
        // Another executable named for the allowance: no server joins.
        assert_eq!(agent_with_own_servers("/usr/bin/other", &c, &kids), c);
        // A server listed twice is listed once.
        assert_eq!(agent_with_own_servers(EXE, &c, &[kids[0].clone(), kids[0].clone()]).len(), 2);
    }

    #[test]
    fn a_fork_of_the_own_server_before_its_exec_is_one_to_wait_for() {
        let server = p("200-5", Some("100-1"), Some(EXE));
        let client = p("100-1", Some("1-1"), Some(EXE));
        assert!(own_server_fork(EXE, &clients(), &p("300-9", Some("200-5"), Some(EXE)), &server));
        // Exec'd already (another image), unreadable, or not this server's child.
        assert!(!own_server_fork(EXE, &clients(), &p("300-9", Some("200-5"), Some("/bin/sh")), &server));
        assert!(!own_server_fork(EXE, &clients(), &p("300-9", Some("200-5"), None), &server));
        assert!(!own_server_fork(EXE, &clients(), &p("300-9", Some("201-6"), Some(EXE)), &server));
        // The parent is no own server: the client itself (its other children),
        // or a grandchild of the client (a command's fork).
        assert!(!own_server_fork(EXE, &clients(), &p("201-6", Some("100-1"), Some(EXE)), &client));
        let command = p("300-9", Some("200-5"), Some(EXE));
        assert!(!own_server_fork(EXE, &clients(), &p("400-3", Some("300-9"), Some(EXE)), &command));
        // No client known.
        assert!(!own_server_fork(EXE, &[], &p("300-9", Some("200-5"), Some(EXE)), &server));
    }

    /// The first look from `/proc` snapshots of one holder: its
    /// `/proc/<pid>/stat` line (the state, the parent, the start time),
    /// `/proc/<pid>/exe`, `/proc/<pid>/cmdline`.
    fn look(stat: &str, exe: Option<&str>, cmdline: &[u8], parent: &ProcFacts, only_cloexec: bool) -> HolderLook {
        let st = crate::lineage::parse_stat(stat).expect("a stat line");
        let key = format!("300-{}", st.start);
        let parent_key = if st.ppid == 200 { parent.key.clone() } else { format!("{}-1", st.ppid) };
        first_look(EXE, &clients(), &p(&key, Some(&parent_key), exe), parent, cmdline, st.state, only_cloexec)
    }
    fn stat(state: char, ppid: i32) -> String {
        // pid (comm) state ppid pgrp session tty tpgid flags, 13 more, start (field 22), ...
        format!("300 (opencode) {state} {ppid} 300 300 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 9 0 0")
    }

    #[test]
    fn a_first_look_inside_the_forks_exec_is_waited_for_not_a_holder() {
        let server = p("200-5", Some("100-1"), Some(EXE));
        let argv: &[u8] = b"opencode\0serve\0";
        // Before its exec: the agent's image, its parent's argv.
        assert_eq!(look(&stat('R', 200), Some(EXE), argv, &server, true), HolderLook::ForkBeforeExec);
        // Before its exec but holding a descriptor without the flag: a holder.
        assert_eq!(look(&stat('R', 200), Some(EXE), argv, &server, false), HolderLook::Holder);
        // Inside its exec: the new image, no argv yet, the server's descriptors
        // still there (their fdinfo flags need not be readable meanwhile).
        for st in ['R', 'S', 'D'] {
            assert_eq!(look(&stat(st, 200), Some("/usr/bin/sleep"), b"", &server, false), HolderLook::InsideExec, "{st}");
        }
        assert_eq!(look(&stat('R', 200), None, b"", &server, true), HolderLook::InsideExec, "exe unreadable mid-exec");
        // Faked on the agent's image (an emptied argv): waited for, the same bound.
        assert_eq!(look(&stat('S', 200), Some(EXE), b"", &server, true), HolderLook::InsideExec);
        // Past its exec, still holding the listener: a holder at once (its
        // descriptor was not close-on-exec, or it got one since).
        assert_eq!(look(&stat('S', 200), Some("/usr/bin/sleep"), b"sleep\x001\0", &server, false), HolderLook::Holder);
        assert_eq!(look(&stat('S', 200), Some("/usr/bin/sleep"), b"sleep\x001\0", &server, true), HolderLook::Holder);
        // A zombie's command line is empty too: no exec to wait for.
        assert_eq!(look(&stat('Z', 200), None, b"", &server, false), HolderLook::Holder);
        // Another parent (not the server's child): a holder.
        assert_eq!(look(&stat('R', 201), Some("/usr/bin/sleep"), b"", &server, true), HolderLook::Holder);
    }

    #[test]
    fn only_the_own_servers_child_is_waited_for_inside_an_exec() {
        let server = p("200-5", Some("100-1"), Some(EXE));
        let client = p("100-1", Some("1-1"), Some(EXE));
        let command = p("300-9", Some("200-5"), Some(EXE));
        let inside = |q: &ProcFacts, parent: &ProcFacts| own_server_child_inside_exec(EXE, &clients(), q, parent, b"", 'R');
        assert!(inside(&p("300-9", Some("200-5"), Some("/bin/sh")), &server));
        // Not this parent's child (another start time on the parent's pid:
        // the pid was reused), or its parent unreadable.
        assert!(!inside(&p("300-9", Some("200-6"), Some("/bin/sh")), &server));
        assert!(!inside(&p("300-9", None, Some("/bin/sh")), &server));
        // The parent is no own server: the client (its other children), a
        // command of the server (a grandchild's exec).
        assert!(!inside(&p("201-6", Some("100-1"), Some("/bin/sh")), &client));
        assert!(!inside(&p("400-3", Some("300-9"), Some("/bin/sh")), &command));
        // No client known, or the child is a client.
        assert!(!own_server_child_inside_exec(EXE, &[], &p("300-9", Some("200-5"), None), &server, b"", 'R'));
        let two = vec!["100-1".to_string(), "300-9".to_string()];
        assert!(!own_server_child_inside_exec(EXE, &two, &p("300-9", Some("200-5"), None), &server, b"", 'R'));
        // Its exec is done (an argv): no.
        assert!(!own_server_child_inside_exec(EXE, &clients(), &p("300-9", Some("200-5"), Some("/bin/sh")), &server, b"sh\0", 'R'));
        // A grandchild of the client inside an exec: a holder.
        let grand = p("400-3", Some("300-9"), Some("/bin/sh"));
        assert_eq!(first_look(EXE, &clients(), &grand, &command, b"", 'R', true), HolderLook::Holder);
    }

    #[test]
    fn nobody_but_the_client_traces_or_reads_the_client() {
        let c = clients();
        assert!(introspection_refused(&c, "300-9", &["100-1".to_string()]), "an agent's command");
        assert!(introspection_refused(&c, "200-5", &["100-1".to_string()]), "its own server");
        assert!(!introspection_refused(&c, "100-1", &["100-1".to_string()]), "itself");
        assert!(!introspection_refused(&c, "300-9", &["400-3".to_string()]), "another process: the rest of the guard decides");
        assert!(!introspection_refused(&[], "300-9", &["100-1".to_string()]), "no client known");
    }

    #[test]
    fn connect_only_from_a_client_to_a_listener_held_only_by_its_own_server() {
        let server = p("200-5", Some("100-1"), Some(EXE));
        let own = vec![vec![server.clone()]];
        assert!(connect_allowed(EXE, &clients(), "100-1", LO, true, &own));
        // From anyone else: the server itself, an agent's command, a nested opencode.
        for caller in ["200-5", "300-9", "400-3"] {
            assert!(!connect_allowed(EXE, &clients(), caller, LO, true, &own), "{caller}");
        }
        // To a listener with no holder in the tree (the user's background service).
        assert!(!connect_allowed(EXE, &clients(), "100-1", LO, true, &[vec![]]));
        assert!(!connect_allowed(EXE, &clients(), "100-1", LO, true, &[]), "nothing listens");
        // A listener an agent's command also holds (inherited, or its own on the same port).
        let shared = vec![vec![server.clone(), p("300-9", Some("200-5"), Some("/bin/sh"))]];
        assert!(!connect_allowed(EXE, &clients(), "100-1", LO, true, &shared));
        // Two listeners at the destination (a wildcard one too): both must be the server's.
        assert!(connect_allowed(EXE, &clients(), "100-1", LO, true, &[vec![server.clone()], vec![server.clone()]]));
        assert!(!connect_allowed(EXE, &clients(), "100-1", LO, true, &[vec![server.clone()], vec![]]));
        // Not loopback, not TCP, no client known.
        assert!(!connect_allowed(EXE, &clients(), "100-1", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), true, &own));
        assert!(!connect_allowed(EXE, &clients(), "100-1", LO, false, &own));
        assert!(!connect_allowed(EXE, &[], "100-1", LO, true, &own));
    }
}
