//! guard_flow — a taint follows the bytes along a descriptor (feature
//! `kernel`, Linux; confidentiality-plan-13 D2 and §4.5.1, 2026-10-02).
//!
//! The parent walk (`TaintedSet::holds_or_inherits`) makes a holder's
//! descendants holders. A pipeline's later stage is the reader's SIBLING:
//! `python3 -c 'print(open("x.txt").read())' | curl --data-binary @- …`
//! sent the file anywhere the static list allowed, and `… | tee copy.txt`
//! wrote it unlabeled. Here a process holding the READ end of a pipe, a FIFO
//! or an unnamed socket pair whose WRITE end a holder holds becomes a holder
//! too, remembered with the writers it flows from (`TaintedSet::insert_flow`;
//! the arbiter is told them as `flowsFrom`, never as lineage edges):
//!
//!   - at the taint, by the sweep (`guard_send::sweep_before_taint`): the
//!     write ends the reader and its descendants hold, the processes of the
//!     guard's tree holding a read end (`flow_readers`), each then swept like
//!     the reader (its sockets judged, its files labeled, its own pipes
//!     followed);
//!   - at a later event of an untainted process (a connect, a send, an
//!     accept, a write-open), for a pipe or FIFO joined after the taint
//!     (`holder`): its read ends against the write ends of the live holders'
//!     trees (and, since §9 R1, its Unix sockets against their peers).
//!
//! Never the agent: it holds the read end of every tool call's output, and
//! what reaches it goes to the model through the model exit (the tool
//! result is folded over the call's tree, plan 10 §3.2). Tainting it would
//! refuse its own connections and label every file it writes. The agent is
//! the first-started live process of the agent's executable in the guard's
//! tree (`pipe_flow::pick_agent`); a later process of the same executable
//! is not, except the agent's own private server where the launch names one
//! (`own_server`, OpenCode 2: the server holds the tool calls' output and
//! makes the model calls; `agent_keys`).
//!
//! Plan 13 §9 R1 (2026-10-02): a channel joined AFTER the taint carries it
//! too, judged at the event that joins it, before a byte can flow:
//!
//!   - a holder's accept (the guard performs it) of a connection from a
//!     process of the tree (a Unix client, this machine's TCP client found
//!     in `/proc/net`) makes that client a holder, its tree swept; one that
//!     already holds a connection to an unbound peer is refused
//!     (`accepted_flow`);
//!   - a descriptor passed over `SCM_RIGHTS` (the guard performs every
//!     `sendmsg`) that joins a holder to an untainted process, either way (a
//!     socket pair end, a connected Unix socket, a pipe end), makes the
//!     untainted side a holder, or refuses the send (`pass_flows`);
//!   - the later-event look also reads Unix sockets whose other end a live
//!     holder's tree holds (the old-kernel degrade, where accept and
//!     sendmsg are not trapped).
//!
//! Every flow the guard finds is also recorded at the arbiter
//! (`flow_holder`, `recordProcessFlow`), whose model-exit fold then counts
//! it: before, the arbiter learned the writers only as `flowsFrom` on the
//! network and write exits, so a tool call whose process received a
//! holder's bytes from outside the call's tree reached the model raw.
//!
//! Plan 13 §9 R1's file shapes (2026-10-02, `object_flow`): the same rule
//! for a FILE OBJECT two processes share (a file a reader already holds
//! when a holder writes it, shared memory, an unlinked file, an
//! `O_TMPFILE`, a memfd), keyed by the object: `object_written` at a
//! holder's write-capable open or `shmat`, `object_receivers` at the sweep,
//! `object_open` at a later reading open or `shmat` of a marked object, the
//! `File` arm of `pass_flows`, and `handle_ipc_notif` (which also refuses a
//! holder's message queue send).
//!
//! The agent's own receipt (plan 13 §4.5.1, 2026-10-02) is recorded as an
//! agent flow, never made a holder: its connection to a holder (at the
//! holder's accept, at the taint-time sweep, and at its own connect where
//! the accept is not trapped), and a FIFO a holder writes that it reads
//! itself (at the later of the two opens, or the sweep). A holder's
//! connection the session's net-proxy holds is refused: the proxy relays
//! the reply to a requester no record can name.
//!
//! A holder's FIFO (2026-10-02): judged at its write-open before the
//! descriptor is handed over, a reader outside the tree refused
//! (`fifo_write_open`); a reading open of a FIFO a holder wrote makes the
//! opener (other than the agent) a holder (`object_open`).
//!
//! P0 2b (2026-10-09): a pipe, a socket pair or a FIFO a holder writes
//! whose receiving end a process OUTSIDE the tree holds refuses the event
//! (the sweep, a pass, a holder's `sendmsg` on the pair: `written_channels`,
//! `outside_receiver`, `outside_pair_receiver`), the human plane (the
//! guard's own stdio) excepted.
//!
//! Not covered (plan 13 §4.5.1): a pipe between two processes outside the
//! guard's tree; a receiver outside that joins after the look, or whose
//! descriptors the guard cannot read (another user's, non-dumpable; one of
//! the tree hidden only by the exec it is inside is waited for:
//! `unseen_drops`); a signal's
//! number (§4.9). (A receiver that closes the channel before any trapped
//! call where the accept or the pass is not judged needs a kernel below
//! 5.6, which serves no raw open: no holder exists there.)
//!
//! `Mandu-new`.

#![cfg(all(feature = "kernel", target_os = "linux"))]

use crate::guard_kernel::GuardConfig;
use crate::pipe_flow;
use crate::secret_open::{ancestor_keys_of, own_key_of, tgid_of};

/// Every process of the guard's tree: the guard's descendants and the tree
/// roots' (the guard itself excluded).
pub(crate) fn tree_procs(cfg: &GuardConfig) -> Vec<i32> {
    // SAFETY: getpid has no failure mode.
    let me = unsafe { libc::getpid() };
    let mut out: Vec<i32> = Vec::new();
    let mut roots = vec![me];
    roots.extend(cfg.tree_roots.iter().copied());
    for r in roots {
        for p in crate::guard_send::subtree(r) {
            if p != me && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

/// The agent's proc keys (see the module doc and `pipe_flow::pick_agent`),
/// cached while the first of them lives; empty when the launch named no
/// agent executable (then no process is exempt: fail-closed).
///
/// supported-agents.md §2.3.1 ("The agent is the server"): when the launch
/// runs the agent's private server (`own_server`, the same executable named
/// for both), the client's own server is the agent too: it holds the tool
/// calls' output, makes the model calls and spawns each call's shell
/// (`own_server::agent_with_own_servers`). The servers are looked up live
/// (the client's children), never cached: one may start after the client
/// was first found.
pub(crate) fn agent_keys(cfg: &GuardConfig) -> Vec<String> {
    let exe = cfg.secrets.as_ref().map(|s| s.agent_exe.clone()).unwrap_or_default();
    let clients = agent_keys_of(cfg, &exe, &cfg.agent);
    match cfg.own_server.as_deref() {
        Some(own) if own == exe && !clients.is_empty() => {
            let children: Vec<crate::own_server::ProcFacts> = clients.iter().flat_map(|k| children_of_key(k)).map(own_server_facts).collect();
            crate::own_server::agent_with_own_servers(own, &clients, &children)
        }
        _ => clients,
    }
}

/// The live children of the process `key` names (every thread's).
fn children_of_key(key: &str) -> Vec<i32> {
    let Some((pid, _)) = crate::lineage::parse_key(key) else { return Vec::new() };
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else { return Vec::new() };
    let mut out: Vec<i32> = Vec::new();
    for t in tasks.flatten() {
        let Ok(ch) = std::fs::read_to_string(t.path().join("children")) else { continue };
        for c in ch.split_whitespace().filter_map(|c| c.parse::<i32>().ok()) {
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out
}

/// The agent's proc keys for the executable `exe` (`agent_keys`' rule),
/// cached in `cache` while the first of them lives. Empty when `exe` is.
fn agent_keys_of(cfg: &GuardConfig, exe: &str, cache: &std::sync::Mutex<Vec<String>>) -> Vec<String> {
    if exe.is_empty() {
        return Vec::new();
    }
    let alive = |k: &str| crate::lineage::parse_key(k).map(|(pid, start)| !crate::lineage::is_gone(read_stat(pid).as_ref(), start)).unwrap_or(false);
    if let Ok(cached) = cache.lock() {
        if cached.first().map(|k| alive(k)).unwrap_or(false) {
            return cached.clone();
        }
    }
    let cands: Vec<pipe_flow::AgentCandidate> = tree_procs(cfg)
        .into_iter()
        .filter_map(|p| {
            let image = std::fs::read_link(format!("/proc/{p}/exe")).ok()?.to_str()?.to_string();
            let by_script = if image == exe {
                false
            } else {
                let cmd = std::fs::read(format!("/proc/{p}/cmdline")).ok()?;
                let script = pipe_flow::script_arg(&cmd)?;
                let path = if script.starts_with('/') { std::path::PathBuf::from(&script) } else { std::path::Path::new(&format!("/proc/{p}/cwd")).join(&script) };
                if std::fs::canonicalize(path).ok()?.to_str()? != exe {
                    return None;
                }
                true
            };
            Some(pipe_flow::AgentCandidate { key: own_key_of(p), start: read_stat(p)?.start, by_script })
        })
        .collect();
    let keys = pipe_flow::pick_agent(&cands);
    if let Ok(mut cached) = cache.lock() {
        if *cached != keys {
            crate::guard_trace::trace(|| format!("agent pick for {exe}: {keys:?} of {cands:?} (was {:?})", *cached));
        }
        *cached = keys.clone();
    }
    keys
}

// ── supported-agents.md §2.3.1: the agent's own private server ──────────────

/// The client processes for the private-server allowance (`own_server`):
/// `agent_keys`' rule with the launch's `OWN_SERVER_ENV` executable. Empty
/// when the allowance is off (nothing is admitted).
pub(crate) fn own_server_clients(cfg: &GuardConfig) -> Vec<String> {
    match cfg.own_server.as_deref() {
        Some(exe) => agent_keys_of(cfg, exe, &cfg.own_server_clients),
        None => Vec::new(),
    }
}

/// What `own_server` needs of a process: its key, its parent's, its image.
pub(crate) fn own_server_facts(pid: i32) -> crate::own_server::ProcFacts {
    let tgid = tgid_of(pid);
    crate::own_server::ProcFacts {
        key: own_key_of(tgid),
        parent_key: crate::secret_open::parent_pid_of(tgid).filter(|p| *p > 0).map(own_key_of),
        exe: std::fs::read_link(format!("/proc/{tgid}/exe")).ok().and_then(|p| p.to_str().map(str::to_string)),
    }
}

/// The holders, among the guard's tree, of each socket LISTENING for a TCP
/// connection to `dest` (one list per listening socket; an empty list: none
/// of the tree holds it, so it is someone else's). A fork of the own server
/// on its way to an exec, holding the listener only through close-on-exec
/// descriptors, is given until `FORK_EXEC_WAIT` to drop it and is no holder
/// when it has (`own_server::own_server_fork`): the connect is held back
/// meanwhile, so nothing reaches the listener before the holders are judged.
pub(crate) fn own_server_listeners(cfg: &GuardConfig, dest: (std::net::IpAddr, u16)) -> Vec<Vec<crate::own_server::ProcFacts>> {
    let rows = tcp_rows();
    let inodes = crate::send_guard::listeners_for(&rows, dest, this_machine(dest.0));
    if inodes.is_empty() {
        return Vec::new();
    }
    let tree = tree_procs(cfg);
    let clients = own_server_clients(cfg);
    let deadline = std::time::Instant::now() + FORK_EXEC_WAIT;
    inodes
        .iter()
        .map(|ino| {
            let link = [format!("socket:[{ino}]")];
            let mut seen = std::collections::HashSet::new();
            tree.iter()
                // A holder, or a process whose table could not be read (one
                // inside its exec may hold it: `dropped_on_look`).
                .filter(|p| pipe_flow::holds_any_look(**p, &link) != Some(false))
                .filter(|p| !own_server_fork_drops(cfg, **p, &link, &clients, deadline))
                .map(|p| own_server_facts(*p))
                .filter(|f| seen.insert(f.key.clone()))
                .collect()
        })
        .collect()
}

/// Did `q` drop `link` (an exec, a close, an exit), at once or, while it is a
/// fork of the own server holding it only through close-on-exec descriptors,
/// or a child of the own server caught inside its exec, by `deadline`?
fn own_server_fork_drops(cfg: &GuardConfig, q: i32, link: &[String], clients: &[String], deadline: std::time::Instant) -> bool {
    use crate::own_server::HolderLook;
    let look: TableLook = pipe_flow::holds_any_look;
    let Some(exe) = cfg.own_server.as_deref() else { return !pipe_flow::holds_any(q, link) };
    match look(q, link) {
        Some(false) => return true,
        None => return unseen_drops(q, link, deadline, look),
        Some(true) => {}
    }
    // The first look decides what it is (`own_server::first_look`): a child
    // of the own server inside its exec, a fork of it before its exec, or a
    // holder now.
    match own_server_look(exe, clients, q, link) {
        Some((HolderLook::InsideExec, key)) => wait_exec_done(q, &key, link, deadline, look),
        Some((HolderLook::ForkBeforeExec, key)) => {
            // Its image is not looked at again (`wait_close_on_exec_drop`),
            // unless the wait ended with the fork inside its exec (a look
            // there may find the flags unreadable).
            wait_close_on_exec_drop(q, &key, link, deadline, look) || own_server_exec_ends_dropping(exe, clients, q, link, deadline)
        }
        // It may have exec'd between the two looks: then it dropped it, or
        // it is inside that exec now (its image switched while it was looked
        // at) and drops it in a moment.
        Some((HolderLook::Holder, _)) | None => own_server_exec_ends_dropping(exe, clients, q, link, deadline) || dropped_on_look(q, link, deadline, look),
    }
}

/// A look at a process's descriptor table for some links
/// (`pipe_flow::holds_any_look`, `reads_any_look`): None when the table
/// could not be read.
type TableLook = fn(i32, &[String]) -> Option<bool>;

/// Does `q` hold none of `links` on this look, its table read, or, when the
/// table cannot be read, once the exec it is inside ends (`unseen_drops`)?
fn dropped_on_look(q: i32, links: &[String], deadline: std::time::Instant, look: TableLook) -> bool {
    match look(q, links) {
        Some(held) => !held,
        None => unseen_drops(q, links, deadline, look),
    }
}

/// `q`'s descriptor table could not be read. Inside an exec the kernel hides
/// it (`pipe_flow::fd_table_look`) while the process still holds every
/// descriptor of its old image, the ones that survive the exec among them:
/// wait, until `deadline`, for that exec to end and judge the table it ends
/// with (`wait_exec_done`). 2026-10-17: such a look was read as "holds
/// nothing", and a descriptor without the close-on-exec flag went unseen
/// through the exec. Not inside an exec: look once more, and a table that
/// still cannot be read is a process the guard cannot see (non-dumpable,
/// another user's), no holder, as before (the documented gap).
fn unseen_drops(q: i32, links: &[String], deadline: std::time::Instant, look: TableLook) -> bool {
    match inside_exec_key(q) {
        Some(key) => wait_exec_done(q, &key, links, deadline, look),
        None => look(q, links) != Some(true),
    }
}

/// Is `q` inside an exec now (`pipe_flow::exec_in_progress`)? Its proc key
/// on that look, or None.
fn inside_exec_key(q: i32) -> Option<String> {
    let key = own_key_of(q);
    let st = read_stat(q)?;
    pipe_flow::exec_in_progress(&std::fs::read(format!("/proc/{q}/cmdline")).unwrap_or_default(), st.state).then_some(key)
}

/// The first look at `q`, a holder of the own server's listener `link`, and
/// its proc key on that look (the waits watch it for a reused pid). None:
/// gone (its stat unreadable).
fn own_server_look(exe: &str, clients: &[String], q: i32, link: &[String]) -> Option<(crate::own_server::HolderLook, String)> {
    let st = read_stat(q)?;
    let facts = own_server_facts(q);
    let parent = own_server_facts(st.ppid);
    let cmdline = std::fs::read(format!("/proc/{q}/cmdline")).unwrap_or_default();
    let only_cloexec = pipe_flow::receives_only_until_exec(q, link);
    let key = facts.key.clone();
    Some((crate::own_server::first_look(exe, clients, &facts, &parent, &cmdline, st.state, only_cloexec), key))
}

/// Is `q` a child of the own server inside its exec now, and does that exec
/// end, by `deadline`, with `link` dropped (`wait_exec_done`)?
fn own_server_exec_ends_dropping(exe: &str, clients: &[String], q: i32, link: &[String], deadline: std::time::Instant) -> bool {
    match own_server_look(exe, clients, q, link) {
        Some((crate::own_server::HolderLook::InsideExec, key)) => wait_exec_done(q, &key, link, deadline, pipe_flow::holds_any_look),
        _ => false,
    }
}

/// The wait for a fork identified on its first look (`own_server_fork_drops`,
/// `agent_fork_reaches_exec`): until `deadline`, while it is the same process
/// and holds `link` only through close-on-exec descriptors, look again. Its
/// image is NOT looked at again: `execve` switches the image
/// (`/proc/<pid>/exe`) before it closes the close-on-exec descriptors, and a
/// look in between (a task preempted there, on a loaded host) found a
/// process no longer on the agent's image that still held the link, and
/// judged it a holder: the client's connect was refused (CI pipeline 9606,
/// own_server_integration's fork-window test). Once the exec is done the
/// kernel has closed them, so a process that still holds the link after it
/// holds it through a descriptor without the flag, and the next look ends
/// the wait with a holder. Nothing new is admitted: the caller judges once
/// the link is gone, or at the deadline as held. `key` is `q`'s proc key on
/// the look that identified it. A look whose table cannot be read (inside
/// the exec) waits for that exec to end (`unseen_drops`), never reads it as
/// the link gone.
fn wait_close_on_exec_drop(q: i32, key: &str, link: &[String], deadline: std::time::Instant, look: TableLook) -> bool {
    loop {
        match look(q, link) {
            Some(false) => return true,
            None => return unseen_drops(q, link, deadline, look),
            Some(true) => {}
        }
        if own_key_of(q) != key || !pipe_flow::receives_only_until_exec(q, link) {
            // Another process on the pid, or a descriptor without the flag:
            // a holder, unless it dropped the link between the looks.
            return dropped_on_look(q, link, deadline, look);
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

fn is_agent(cfg: &GuardConfig, key: &str) -> bool {
    agent_keys(cfg).iter().any(|k| k == key)
}

fn read_stat(pid: i32) -> Option<crate::lineage::ProcStat> {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().as_deref().and_then(crate::lineage::parse_stat)
}

/// The peer of a Unix socket inode when that peer is UNNAMED (a socket
/// pair's other end, or the client of a listener): the link (`socket:[n]`)
/// the receiving process holds. A named peer is no flow: the sweep judges a
/// socket connected to one like a connect to it.
fn unnamed_unix_peer(ino: u64) -> Option<String> {
    let peer = crate::guard_rights::unix_peer_of(ino)?;
    if crate::guard_rights::unix_name_of(peer).map(|n| !n.is_empty()).unwrap_or(false) {
        return None;
    }
    Some(format!("socket:[{peer}]"))
}

/// The links through which `procs` (holders) send bytes to another
/// process: the pipes and FIFOs they can write, the unnamed peers of their
/// Unix sockets.
pub(crate) fn flow_targets(procs: &[i32]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in procs {
        let (links, socks) = pipe_flow::write_ends(*p);
        for l in links {
            if !out.contains(&l) {
                out.push(l);
            }
        }
        for s in socks {
            if let Some(l) = unnamed_unix_peer(s) {
                if !out.contains(&l) {
                    out.push(l);
                }
            }
        }
    }
    out
}

/// P0 2b (2026-10-09): the session's human plane, the descriptors the
/// launch handed the agent's tree: the guard's own standard input, output
/// and error (the guard forks the tree's root and execs it with them), as
/// links (`pipe:[ino]`, `socket:[ino]`, a path) and identities. What the
/// tree writes there goes toward the human (the launcher's reply relay, the
/// terminal, the pipeline the user started Mandu in), by design; the
/// outside-reader rule leaves it out.
pub(crate) fn human_plane() -> (Vec<String>, Vec<(u64, u64)>) {
    use std::os::unix::fs::MetadataExt;
    let mut links = Vec::new();
    let mut ids = Vec::new();
    for fd in 0..=2 {
        let p = format!("/proc/self/fd/{fd}");
        if let Some(l) = std::fs::read_link(&p).ok().and_then(|l| l.to_str().map(String::from)) {
            links.push(l);
        }
        if let Ok(m) = std::fs::metadata(&p) {
            ids.push((m.dev(), m.ino()));
        }
    }
    (links, ids)
}

/// Is the Unix socket `ino` bound to a name? A name the kernel cannot give
/// counts as none (the strict side: the socket is then judged as a pair's).
fn unix_named(ino: u64) -> bool {
    u32::try_from(ino).ok().and_then(crate::guard_rights::unix_name_of).is_some_and(|n| !n.is_empty())
}

/// P0 2b: the other end of a SOCKET PAIR whose end `ino` is (both ends
/// unnamed): `socket:[peer]`. A side bound to a name is a client's
/// connection to a named server (an exit the connect judged) or a server's
/// accepted end (its client is outside the boundary, plan 13 §4.9); a socket
/// `sock_diag` does not find in the guard's network namespace (one the tree
/// made in a namespace of its own, whose other end can leave only over a
/// pass the guard judges) has none here.
fn pair_peer(ino: u64) -> Option<String> {
    let peer = crate::guard_rights::unix_peer_of(ino)?;
    if unix_named(ino) || unix_named(u64::from(peer)) {
        return None;
    }
    Some(format!("socket:[{peer}]"))
}

/// P0 2b (2026-10-09): what `procs` (holders) write into that a process
/// outside the guard's tree could receive: the anonymous pipes they hold
/// open for writing, the socket pairs they hold (`pair_peer`), and the
/// identities of the FIFOs they hold open for writing (a FIFO opened
/// before the taint: its write-open was judged before anything was held).
pub(crate) fn written_channels(procs: &[i32]) -> (Vec<pipe_flow::WrittenChannel>, Vec<(u64, u64)>) {
    let mut chans: Vec<pipe_flow::WrittenChannel> = Vec::new();
    let mut fifos: Vec<(u64, u64)> = Vec::new();
    let mut seen_socks: Vec<u64> = Vec::new();
    for p in procs {
        for h in pipe_flow::fd_table(*p) {
            match pipe_flow::flow_kind(&h.link) {
                pipe_flow::FlowKind::Pipe => {
                    if !chans.iter().any(|c| c.own == h.link) && pipe_flow::accmode_of(*p, h.fd).map(pipe_flow::accmode_writes).unwrap_or(true) {
                        chans.push(pipe_flow::WrittenChannel { own: h.link.clone(), target: h.link });
                    }
                }
                pipe_flow::FlowKind::Socket(ino) => {
                    if seen_socks.contains(&ino) {
                        continue;
                    }
                    seen_socks.push(ino);
                    if let Some(target) = pair_peer(ino) {
                        chans.push(pipe_flow::WrittenChannel { own: h.link, target });
                    }
                }
                pipe_flow::FlowKind::Path => {
                    if pipe_flow::accmode_of(*p, h.fd).map(pipe_flow::accmode_writes).unwrap_or(false) {
                        if let Some(id) = fifo_id_of(*p, h.fd) {
                            if !fifos.contains(&id) {
                                fifos.push(id);
                            }
                        }
                    }
                }
                pipe_flow::FlowKind::None => {}
            }
        }
    }
    (chans, fifos)
}

/// P0 2b (2026-10-09): the first process outside the guard's tree (and not
/// the guard) that receives what is written into `chans` or `fifos`, named
/// for a refusal (`local_exits::OUTSIDE_RECEIVER`); None when there is none
/// the guard can see. The session's human plane is left out
/// (`human_plane`). A process whose descriptors the guard cannot read
/// (another user's; a non-dumpable one of the user's, as `ssh-agent`) is not
/// seen, as for a FIFO's reader (`pipe_flow::outside_receivers`).
pub(crate) fn outside_receiver(cfg: &GuardConfig, chans: &[pipe_flow::WrittenChannel], fifos: &[(u64, u64)]) -> Option<String> {
    let (human, human_ids) = human_plane();
    let targets = pipe_flow::outside_rule_targets(chans, &human);
    let fifos: Vec<(u64, u64)> = fifos.iter().copied().filter(|id| !human_ids.contains(id)).collect();
    if targets.is_empty() && fifos.is_empty() {
        return None;
    }
    // SAFETY: getpid has no failure mode.
    let me = unsafe { libc::getpid() };
    let tree: std::collections::HashSet<i32> = tree_procs(cfg).into_iter().map(tgid_of).collect();
    let found = pipe_flow::outside_receivers(&targets, &fifos, &|p| in_tree_now(cfg, &tree, me, p));
    found.into_iter().next().map(|(p, link)| format!("{} (pid {p}, {link})", crate::local_exits::OUTSIDE_RECEIVER))
}

/// Is `p` in the guard's tree: in `snapshot` (`tree_procs`, taken before a
/// `/proc` scan), the guard itself, or else by its live parent chain a
/// descendant of the guard or of a tree root (`secret_open::in_tree`).
/// The chain is the second look for a process a tree member forked AFTER
/// the snapshot: between its fork and its exec it holds every descriptor
/// of its parent, a pipe's or a socket pair's read end among them, and the
/// scan found it there. Judged by the snapshot alone it was "a program
/// outside Mandu's watch" and a reader's raw open was refused while the
/// agent spawned its next tool call's shell (the call-tree D7 flake,
/// 2026-10-11). A process outside the tree cannot pass this look: it is
/// never re-parented into the tree (the guard is its tree's subreaper, and
/// only the tree's orphans come to it), so its chain meets init.
pub(crate) fn in_tree_now(cfg: &GuardConfig, snapshot: &std::collections::HashSet<i32>, me: i32, p: i32) -> bool {
    if p == me || snapshot.contains(&p) {
        return true;
    }
    let mut roots = vec![me];
    roots.extend(cfg.tree_roots.iter().copied());
    crate::secret_open::in_tree(p, &roots, crate::secret_open::parent_pid_of)
}

/// How long a holder's send on a socket pair trusts an earlier look that
/// found no process outside the tree holding the pair's other end
/// (`outside_pair_receiver`). Within the tree, a process gets that end only
/// by a fork (in the tree) or a pass the guard judges at the sender (a pass
/// to a process outside goes over a channel whose other end is outside,
/// which this rule refuses, uncached); only a process outside can add one
/// meanwhile (reopening nothing: a socket cannot be reopened through
/// `/proc`), so the window bounds an outside actor's race, not the tree's.
pub(crate) const OUTSIDE_CLEAN_TTL: std::time::Duration = std::time::Duration::from_secs(1);

/// The pair ends found clean, by target link, with when (`OUTSIDE_CLEAN_TTL`).
static OUTSIDE_CLEAN: std::sync::Mutex<Vec<(String, std::time::Instant)>> = std::sync::Mutex::new(Vec::new());

/// The most entries `OUTSIDE_CLEAN` keeps (the oldest go first).
const OUTSIDE_CLEAN_MAX: usize = 256;

/// P0 2b (2026-10-09), at a holder's send on a Unix socket with no address
/// (the guard performs every `sendmsg`): when the socket is one end of a
/// socket pair (`pair_peer`) that is not the human plane, a process outside
/// the guard's tree holding the other end receives what the holder sends:
/// named for the refusal. A clean look is trusted for `OUTSIDE_CLEAN_TTL`
/// per pair end, so a holder's stream of sends pays one `/proc` scan a
/// second at most; a refusal is never cached.
pub(crate) fn outside_pair_receiver(cfg: &GuardConfig, sock: std::os::unix::io::RawFd) -> Option<String> {
    // SAFETY: fstat into a zeroed stat, on the guard's copy.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(sock, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return None;
    }
    let own = format!("socket:[{}]", st.st_ino);
    let target = pair_peer(st.st_ino)?;
    let now = std::time::Instant::now();
    if let Ok(c) = OUTSIDE_CLEAN.lock() {
        if c.iter().any(|(t, at)| *t == target && now.duration_since(*at) < OUTSIDE_CLEAN_TTL) {
            return None;
        }
    }
    let chans = [pipe_flow::WrittenChannel { own, target: target.clone() }];
    let found = outside_receiver(cfg, &chans, &[]);
    if found.is_none() {
        if let Ok(mut c) = OUTSIDE_CLEAN.lock() {
            c.retain(|(t, at)| *t != target && now.duration_since(*at) < OUTSIDE_CLEAN_TTL);
            if c.len() >= OUTSIDE_CLEAN_MAX {
                c.remove(0);
            }
            c.push((target, now));
        }
    }
    found
}

/// How long the sweep waits for a fork of the agent to reach its exec (see
/// `flow_readers`). A fork that keeps the agent's descriptors past it is a
/// receiver like any other.
pub(crate) const FORK_EXEC_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// The processes of the guard's tree that receive through `targets` (see
/// `pipe_flow::reads_any`), other than `exclude` and the agent.
///
/// `before_bytes`: the caller holds the writer's descriptor back (the sweep,
/// before the raw open is answered), so nothing has flowed yet. Then a fork
/// of the agent on its way to an exec (a child of the agent running the
/// agent's own image, holding the targets only through close-on-exec
/// descriptors: its copy of the agent's end of a tool call's socket pair) is
/// given until `FORK_EXEC_WAIT` to drop them, and is no receiver when it has.
/// The agent starts tool calls in parallel, and each spawn's child holds a
/// copy of every descriptor of the agent until its exec; judged at that
/// moment, the next tool call's shell was made a holder and its copy of the
/// agent's connection to the model refused a listed reader's raw open
/// (2026-10-02, the D7 call-root test, about 1 run in 45 under load). Waiting
/// is safe only while no byte has flowed: a fork that read nothing and then
/// dropped the descriptor can read nothing later.
pub(crate) fn flow_readers(cfg: &GuardConfig, targets: &[String], exclude: &std::collections::HashSet<i32>, before_bytes: bool) -> Vec<i32> {
    if targets.is_empty() {
        return Vec::new();
    }
    let agents = agent_keys(cfg);
    let deadline = std::time::Instant::now() + FORK_EXEC_WAIT;
    tree_procs(cfg)
        .into_iter()
        .filter(|q| !exclude.contains(q))
        // A receiver, or a process whose table could not be read (one inside
        // its exec may be one: `receiver_drops`).
        .filter(|q| pipe_flow::reads_any_look(*q, targets) != Some(false))
        .filter(|q| !agents.contains(&own_key_of(*q)))
        .filter(|q| !receiver_drops(*q, targets, &agents, deadline, before_bytes))
        .collect()
}

/// Is `q`, found receiving from `targets` or with a table that could not be
/// read, no receiver after all? A table that cannot be read is waited for
/// whatever the bytes (`unseen_drops`: only the exec it is inside hides it,
/// and the wait can only find a receiver the look missed, never lose one);
/// a fork of the agent on its way to an exec only before any byte flowed
/// (`agent_fork_reaches_exec`).
fn receiver_drops(q: i32, targets: &[String], agents: &[String], deadline: std::time::Instant, before_bytes: bool) -> bool {
    match pipe_flow::reads_any_look(q, targets) {
        Some(false) => true,
        None => unseen_drops(q, targets, deadline, pipe_flow::reads_any_look),
        Some(true) => before_bytes && agent_fork_reaches_exec(q, targets, agents, deadline),
    }
}

/// Did `q` drop every descriptor through which it received from `targets`
/// (an exec, a close, an exit), at once or, when it is a fork of the agent
/// still on its way to an exec, or a child of the agent caught inside its
/// exec, by `deadline`? Only for a caller that holds the bytes back
/// (`flow_readers`' `before_bytes`).
fn agent_fork_reaches_exec(q: i32, targets: &[String], agents: &[String], deadline: std::time::Instant) -> bool {
    let look: TableLook = pipe_flow::reads_any_look;
    match look(q, targets) {
        Some(false) => return true,
        None => return unseen_drops(q, targets, deadline, look),
        Some(true) => {}
    }
    if let Some(key) = agent_child_inside_exec(q, agents) {
        return wait_exec_done(q, &key, targets, deadline, look);
    }
    if !agent_fork_in_flight(q, targets, agents) {
        // It may have exec'd between the two looks: then it dropped them,
        // or it is inside that exec now (its image switched while it was
        // looked at) and drops them in a moment.
        if let Some(key) = agent_child_inside_exec(q, agents) {
            return wait_exec_done(q, &key, targets, deadline, look);
        }
        return dropped_on_look(q, targets, deadline, look);
    }
    // Its image is not looked at again (`wait_close_on_exec_drop`), unless
    // the wait ended with the fork inside its exec.
    wait_close_on_exec_drop(q, &own_key_of(q), targets, deadline, look)
        || agent_child_inside_exec(q, agents).is_some_and(|key| wait_exec_done(q, &key, targets, deadline, look))
}

/// Is `q` a child of the agent caught INSIDE its exec
/// (`pipe_flow::exec_in_progress`: past the switch to the new image, whose
/// memory holds no argv yet)? Its proc key on that look, or None.
/// 2026-10-11: such a child already shows the
/// new image (`/proc/<pid>/exe`) while it still holds every descriptor of
/// the agent, which the kernel closes a moment later in the same exec (its
/// `fdinfo` flags need not be readable meanwhile). Judged by its image it
/// was "exec'd" and a receiver at once, and the next tool call's shell,
/// spawned while a reader of another call was being answered, took that
/// call's taint (the call-tree D7 flake: a clean call masked, about 1 run
/// in 100 on a loaded guest).
fn agent_child_inside_exec(q: i32, agents: &[String]) -> Option<String> {
    let key = own_key_of(q);
    let st = read_stat(q)?;
    (agents.contains(&own_key_of(st.ppid)) && pipe_flow::exec_in_progress(&std::fs::read(format!("/proc/{q}/cmdline")).unwrap_or_default(), st.state)).then_some(key)
}

/// Wait, until `deadline`, for the exec `q` is inside to end, and judge `q`
/// on the descriptor table it ends with: a descriptor that survives the
/// exec (one not marked close-on-exec) keeps it a holder, so the wait is
/// never more lenient than a look after the exec. `key` is `q`'s proc key
/// on the look that found it inside (another start time later: the pid was
/// reused, and the table is judged as final); `look` the test of `links`
/// (`pipe_flow::reads_any_look` for the sweep, `holds_any_look` for the own
/// server's listener; a table the kernel hides inside the exec is looked at
/// again, never read as empty). The looks back off
/// (`pipe_flow::exec_wait_pause`), each one decided by
/// `pipe_flow::exec_wait_step`. True: it dropped every one of `links` (or
/// is gone). Used by the sweep (`agent_fork_reaches_exec`, `unseen_drops`)
/// and, since 2026-10-17, the own server's connect (`own_server_fork_drops`).
fn wait_exec_done(q: i32, key: &str, links: &[String], deadline: std::time::Instant, look: TableLook) -> bool {
    use pipe_flow::ExecWaitStep;
    let mut n: u32 = 0;
    loop {
        let held = look(q, links);
        let inside = held != Some(false) && read_stat(q).is_some_and(|st| pipe_flow::exec_in_progress(&std::fs::read(format!("/proc/{q}/cmdline")).unwrap_or_default(), st.state));
        let now_key = own_key_of(q);
        match pipe_flow::exec_wait_step(key, &now_key, held, inside, std::time::Instant::now() >= deadline) {
            ExecWaitStep::Dropped => return true,
            // The exec ended (or the process went): the table is final. One
            // that still cannot be read is a process the guard cannot see
            // (a set-id image: non-dumpable), no holder as before.
            ExecWaitStep::Settled => return look(q, links) != Some(true),
            ExecWaitStep::Refuse => return false,
            ExecWaitStep::Again => {}
        }
        std::thread::sleep(pipe_flow::exec_wait_pause(n));
        n = n.saturating_add(1);
    }
}

/// Is `q` a fork of the agent (its parent is the agent, its image the
/// agent's) that receives from `targets` only through close-on-exec
/// descriptors, i.e. only until its exec?
fn agent_fork_in_flight(q: i32, targets: &[String], agents: &[String]) -> bool {
    let Some(st) = read_stat(q) else { return false };
    if !agents.contains(&own_key_of(st.ppid)) {
        return false;
    }
    let exe = |p: i32| std::fs::read_link(format!("/proc/{p}/exe")).ok();
    match (exe(q), exe(st.ppid)) {
        (Some(a), Some(b)) if a == b => {}
        _ => return false,
    }
    // 2026-10-09 (confidentiality-plan-13 §4.5.1): a child that has exec'd
    // already is no fork on its way to an exec, even on the agent's own
    // image (Codex runs each command through itself as
    // `codex-linux-sandbox`, which reads its preflight's stderr through a
    // close-on-exec pipe): waiting for an exec that already happened held
    // every such sweep the whole FORK_EXEC_WAIT (2 s). Judged a receiver at
    // once instead: only ever stricter.
    let cmdline = |p: i32| std::fs::read(format!("/proc/{p}/cmdline")).unwrap_or_default();
    if !pipe_flow::not_yet_execd(&cmdline(q), &cmdline(st.ppid)) {
        return false;
    }
    pipe_flow::receives_only_until_exec(q, targets)
}

/// A writer as `TaintedSet::flow_sources` takes it: its key and chain.
pub(crate) fn writer_entry(p: i32) -> (String, Vec<String>) {
    (own_key_of(p), ancestor_keys_of(p, 16))
}

/// The Unix sockets `pid` holds through which it receives what the process
/// at the other end writes (plan 13 §9 R1): its own socket links
/// (`socket:[ino]`, which a sweep marks when a holder's socket has this one
/// as its unnamed peer) and the links of their peers (`socket:[peer]`, for a
/// holder found holding one). A socket bound to a NAME is skipped: it is
/// the server's end of a connection a client made to it, which the sweep
/// and the connect judge from the client's side (a holder's connect to a
/// named peer is an exit, never a flow). Not a socket at all, or not Unix
/// (no `sock_diag` answer): skipped.
fn socket_flow_links(pid: i32) -> (Vec<String>, Vec<String>) {
    let mut own: Vec<String> = Vec::new();
    let mut peers: Vec<String> = Vec::new();
    for h in pipe_flow::fd_table(pid) {
        let pipe_flow::FlowKind::Socket(ino) = pipe_flow::flow_kind(&h.link) else { continue };
        if own.contains(&h.link) {
            continue;
        }
        let Some(peer) = crate::guard_rights::unix_peer_of(ino) else { continue };
        if crate::guard_rights::unix_name_of(ino as u32).map(|n| !n.is_empty()).unwrap_or(false) {
            continue;
        }
        own.push(h.link);
        peers.push(format!("socket:[{peer}]"));
    }
    (own, peers)
}

/// Plan 13 D2's later event: is `pid` (untainted by its parents) reading a
/// pipe or FIFO a live holder, or a holder's descendant, writes into? The
/// flows it then holds (`TaintedSet::flow_sources` of those writers).
///
/// Plan 13 §9 R1 (2026-10-02): or a Unix socket whose other end a live
/// holder's tree holds (a socket pair end, or a connection to a holder's
/// listener, joined after the taint by a route the guard did not judge at
/// the moment it was made: an accept or a pass are judged there,
/// `accepted_flow`, `pass_flows`), or whose own end a holder's sweep
/// marked.
fn later_flow(cfg: &GuardConfig, pid: i32) -> Option<Vec<String>> {
    let tgid = tgid_of(pid);
    if is_agent(cfg, &own_key_of(tgid)) {
        return None;
    }
    // Plan 13 §9 R1, the file shapes: a file object or SysV segment it can
    // read that a holder wrote (marked at the holder's taint, write-open,
    // `shmat` or pass, and kept after the writer exits).
    if cfg.tainted.has_object_marks() {
        let marked = cfg.tainted.link_flows(&crate::object_flow::read_keys(tgid));
        if !marked.is_empty() {
            return Some(marked);
        }
    }
    let reads = pipe_flow::read_ends(tgid);
    let (own_socks, peer_socks) = socket_flow_links(tgid);
    if reads.is_empty() && own_socks.is_empty() {
        return None;
    }
    // A link a holder wrote into (marked at its taint or its FIFO
    // write-open), whether or not that writer still lives.
    let mut links = reads.clone();
    links.extend(own_socks.iter().cloned());
    let marked = cfg.tainted.link_flows(&links);
    if !marked.is_empty() {
        return Some(marked);
    }
    let mut writers: Vec<(String, Vec<String>)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for h in cfg.tainted.live_holder_pids() {
        for q in crate::guard_send::subtree(h) {
            if q == tgid || !seen.insert(q) {
                continue;
            }
            if pipe_flow::writes_any(q, &reads) || pipe_flow::holds_any(q, &peer_socks) {
                writers.push(writer_entry(q));
            }
        }
    }
    if writers.is_empty() {
        return None;
    }
    // A writer found under a holder holds through it: make sure the set
    // knows (its chain names the holder for the arbiter).
    for (k, chain) in &writers {
        if !cfg.tainted.contains(k) {
            cfg.tainted.inherit(k, chain);
        }
    }
    Some(cfg.tainted.flow_sources(&writers))
}

/// Plan 13 §4.5.1 (2026-10-03): a reader that the agent ran DIRECTLY (its
/// child: Claude Code's Grep runs `rg`) receives a holder's bytes through a
/// FIFO or a file object. D2 makes that child a holder, but its output
/// reaches the model as the agent's own file tool result, which no call
/// tree folds; so the receipt is also recorded as an agent flow on a file
/// channel (`channel`: the FIFO's path, the file's path or key), and the
/// model exit masks a file tool's result in its window, as for the agent's
/// own read of the FIFO (`agent_fifo_open`). A child that is the agent's
/// shell for a Bash call adds a record its call's fold already covers (the
/// window then also masks a file tool's result run beside it: the stricter
/// side). `Err`: the record failed; the caller refuses the event.
pub(crate) fn agent_child_receipt(cfg: &GuardConfig, receivers: &[i32], channel: &str, from: &[String]) -> Result<(), String> {
    let agents = agent_keys(cfg);
    if agents.is_empty() || from.is_empty() {
        return Ok(());
    }
    let child_of_agent = |p: i32| read_stat(p).map(|st| agents.contains(&own_key_of(st.ppid)) && !agents.contains(&own_key_of(p))).unwrap_or(false);
    if receivers.iter().any(|r| child_of_agent(tgid_of(*r))) {
        record_agent_flow(cfg, channel, from)?;
    }
    Ok(())
}

/// The channel name `agent_child_receipt` records for an object.
pub(crate) fn object_channel(t: &crate::object_flow::ObjectTarget) -> String {
    t.path.clone().or_else(|| t.keys.first().cloned()).unwrap_or_default()
}

/// How long a holder's write-open of a FIFO waits for a reader of the
/// guard's tree to show (a reader's blocking open completes with the
/// writer's, and its descriptor reaches its table a moment later).
pub(crate) const FIFO_READER_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Plan 13 D2, at a holder's (`writer`, process `wpid`) write-open of the
/// FIFO `link`, BEFORE the descriptor is handed over (so before a byte is
/// written; until 2026-10-02 this ran after, and a reader that read and
/// closed the FIFO before its next trapped call escaped). The link is
/// marked under the open registry's lock (a reader whose open of it races
/// this one is listed, or sees the mark at its own open, `object_open`),
/// and every process of the tree reading it becomes a holder flowing from
/// the writer, its tree swept (`Err`: an unbound connection one holds
/// refuses the write-open).
///
/// `needs_reader` (an `O_WRONLY` open, which the kernel completes only once
/// the FIFO has a reader, and since 2026-10-07 an `O_RDWR` one, which the
/// kernel completes with no reader at all): when no process of the guard's
/// tree reads it within `FIFO_READER_WAIT`, the reader is a process the
/// guard does not watch (outside the tree: a daemon, a process of another
/// session), or none yet, and the write-open is refused (`Err`,
/// fail-closed). The agent counts as a reader present (it is never made a
/// holder; plan 13 §4.5.1 flags its own read of a holder's FIFO).
///
/// P0 1a (2026-10-07): a reader OUTSIDE the tree that already has the FIFO
/// (`fifo`, its device and inode) open refuses the write-open too, beside
/// an in-tree reader or not (`O_RDWR` gave it the holder's bytes with no
/// reader found, and one in-tree reader stopped the look): every process of
/// the caller's user (`/proc/*/fd`, by the FIFO's identity) other than the
/// tree and the guard itself. Left: a reader outside that opens the FIFO
/// later, and one running as another user.
pub(crate) fn fifo_write_open(cfg: &GuardConfig, writer: &(String, Vec<String>), wpid: i32, link: &str, fifo: (u64, u64), needs_reader: bool) -> Result<(), (String, crate::guard_kernel::TaintedRefusal)> {
    let from = cfg.tainted.flow_sources(std::slice::from_ref(writer));
    let target = crate::object_flow::ObjectTarget { keys: vec![link.to_string()], path: None };
    let listed = mark_objects(cfg, std::slice::from_ref(&target), &from);
    let wt = tgid_of(wpid);
    let links = [link.to_string()];
    // A reader outside the tree (P0 1a): looked for before the wait (a
    // refusal needs no wait) and after it (a reader that came meanwhile).
    // SAFETY: getpid has no failure mode.
    let me = unsafe { libc::getpid() };
    let outside_reader = || {
        // A read-only open (O_CREAT on an existing FIFO) writes nothing.
        if !needs_reader {
            return false;
        }
        let tree: std::collections::HashSet<i32> = tree_procs(cfg).into_iter().map(tgid_of).collect();
        !pipe_flow::fifo_readers(fifo.0, fifo.1, &|p| p == wt || in_tree_now(cfg, &tree, me, p)).is_empty()
    };
    let refuse_outside = || ("a reader of the named pipe outside the processes Mandu watches".to_string(), crate::guard_kernel::TaintedRefusal::default());
    if outside_reader() {
        return Err(refuse_outside());
    }
    let deadline = std::time::Instant::now() + FIFO_READER_WAIT;
    let readers: Vec<i32> = loop {
        let mut rs: Vec<i32> = tree_procs(cfg).into_iter().map(tgid_of).filter(|q| *q != wt && pipe_flow::reads_any(*q, &links)).collect();
        for p in listed.now.iter().copied().map(tgid_of) {
            if p != wt && !rs.contains(&p) {
                rs.push(p);
            }
        }
        // The writer holding a read end itself (the non-blocking open of
        // both ends) may be the reader the kernel saw: as for O_RDWR.
        if !rs.is_empty() || !needs_reader || pipe_flow::reads_any(wt, &links) {
            break rs;
        }
        if std::time::Instant::now() >= deadline {
            return Err(refuse_outside());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    if outside_reader() {
        return Err(refuse_outside());
    }
    let agents = agent_keys(cfg);
    let mut receivers: Vec<i32> = Vec::new();
    for p in readers {
        if !agents.contains(&own_key_of(p)) && !receivers.contains(&p) {
            receivers.push(p);
        }
    }
    agent_child_receipt(cfg, &receivers, link, &from).map_err(|e| (format!("an agent tool reading the named pipe (the flow could not be recorded: {e})"), crate::guard_kernel::TaintedRefusal::default()))?;
    admit_receivers(cfg, &receivers, &from, &[], &[wt], None)
}

// ── plan 13 §9 R1, the file shapes (`object_flow`) ─────────────────────────

/// The processes of the guard's tree that READ one of `targets` (a
/// descriptor whose access mode reads, or any mapping of it), other than
/// `exclude` and the agent.
pub(crate) fn object_readers(cfg: &GuardConfig, targets: &[crate::object_flow::ObjectTarget], exclude: &std::collections::HashSet<i32>) -> Vec<i32> {
    if targets.is_empty() {
        return Vec::new();
    }
    let agents = agent_keys(cfg);
    tree_procs(cfg)
        .into_iter()
        .filter(|q| !exclude.contains(q))
        .filter(|q| !agents.contains(&own_key_of(*q)))
        .filter(|q| crate::object_flow::reads_object(*q, targets))
        .collect()
}

/// Mark `targets` as carrying what `from` holds, under the open registry's
/// lock (`object_flow::ObjectOpens::mark_then`); the readers listed for
/// them: in flight (counted whatever `/proc` shows yet) and recent.
pub(crate) fn mark_objects(cfg: &GuardConfig, targets: &[crate::object_flow::ObjectTarget], from: &[String]) -> crate::object_flow::ListedReaders {
    let keys: Vec<String> = targets.iter().flat_map(|t| t.keys.iter().cloned()).collect();
    if keys.is_empty() {
        return crate::object_flow::ListedReaders::default();
    }
    cfg.object_opens.mark_then(&keys, || {
        for k in &keys {
            cfg.tainted.mark_link(k, from);
        }
    })
}

/// The readers of `targets` a holder's write reaches, each once, by thread
/// group, never the agent nor `exclude`: the ones listed in flight, and
/// every process of the tree that reads one (`object_readers`). Marks the
/// targets as carrying `from`. `all` false is for an object born less than
/// `object_flow::FRESH` ago: a process other than its writer can hold it
/// only by an open since (listed), a pass (listed, `note`), or a fork of
/// one of those; so when NOTHING is listed for it the tree is not read (a
/// holder writing many new files, a build, pays no look at every process
/// for each), and when anything is, it is (a lister's fork may have left
/// it, as a double fork leaves any parent).
pub(crate) fn object_receivers(cfg: &GuardConfig, targets: &[crate::object_flow::ObjectTarget], from: &[String], exclude: &std::collections::HashSet<i32>, all: bool) -> Vec<i32> {
    let listed = mark_objects(cfg, targets, from);
    let agents = agent_keys(cfg);
    let look = all || !listed.now.is_empty() || !listed.recent.is_empty();
    let mut found: Vec<i32> = listed.now;
    if look {
        found.extend(object_readers(cfg, targets, exclude));
    }
    let mut out: Vec<i32> = Vec::new();
    for p in found.into_iter().map(tgid_of) {
        if !exclude.contains(&p) && !agents.contains(&own_key_of(p)) && !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// Plan 13 §9 R1, the file shapes: a holder (`writer`, process `wpid`) is
/// about to write `target` (its write-capable open of a regular file, its
/// writable `shmat` of a SysV segment), before the descriptor or the
/// mapping is handed over, so before a byte is written. The object is
/// marked (a later opener is judged by it), and every process of the tree
/// that already reads it becomes a holder flowing from the writer, its tree
/// swept (`admit_receivers`): one that holds a connection to an unbound
/// peer refuses the write (`Err`, fail-closed). `tail -f log | curl … &`
/// left running by an earlier call is the shape. `fresh`: the object was
/// born less than `object_flow::FRESH` ago (a file this very open created,
/// `object_flow::born_recently`), so its readers are all listed and the
/// tree is not read (a holder writing many new files, a build, pays no
/// look at every process for each).
pub(crate) fn object_written(cfg: &GuardConfig, writer: &(String, Vec<String>), wpid: i32, target: &crate::object_flow::ObjectTarget, fresh: bool, caller: Option<i32>) -> Result<(), (String, crate::guard_kernel::TaintedRefusal)> {
    let from = cfg.tainted.flow_sources(std::slice::from_ref(writer));
    let wt = tgid_of(wpid);
    let exclude: std::collections::HashSet<i32> = [wt].into_iter().collect();
    let receivers = object_receivers(cfg, std::slice::from_ref(target), &from, &exclude, !fresh);
    // Plan 13 §4.5.1 (2026-10-02): the agent itself reading it (never one of
    // the receivers above) gets an agent flow, before a byte is written.
    if let Err(e) = agent_object_reads(cfg, std::slice::from_ref(target), &from, !fresh) {
        return Err((format!("the agent, which reads this file (the arbiter could not record its flow: {e})"), crate::guard_kernel::TaintedRefusal::default()));
    }
    agent_child_receipt(cfg, &receivers, &object_channel(target), &from).map_err(|e| (format!("an agent tool reading the file (the flow could not be recorded: {e})"), crate::guard_kernel::TaintedRefusal::default()))?;
    admit_receivers(cfg, &receivers, &from, &[], &[wt], caller)
}

/// Plan 13 §4.5.1 (2026-10-02): the AGENT itself reads one of `targets`
/// (a regular file, a mapping) that a holder is about to write
/// (`object_written`) or can write at its taint (the sweep). D2 and the
/// file shapes never make the agent a holder, and its descriptor was opened
/// before the label existed, so what it reads reached the model as a file
/// tool's result whose path may carry no label (another spelling of the
/// file, an unlinked one). An agent flow on a file-like channel (the
/// agent's own link, else the object's path or key) is recorded instead:
/// the model exit masks the agent's file and network tools while it lasts.
/// An open of the object by the agent in flight (`ObjectOpens`, its
/// descriptor not in its table yet) counts too. `scan`: also read the
/// agent's descriptors and mappings (false for an object born a moment ago
/// that no agent open is listed for: it cannot hold it). `Err`: a record
/// failed (the caller refuses the write, or the raw open).
pub(crate) fn agent_object_reads(cfg: &GuardConfig, targets: &[crate::object_flow::ObjectTarget], from: &[String], scan: bool) -> Result<(), String> {
    if targets.is_empty() || from.is_empty() {
        return Ok(());
    }
    let agent_pids: Vec<i32> = agent_keys(cfg).iter().filter_map(|k| crate::lineage::parse_key(k).map(|(p, _)| p)).collect();
    if agent_pids.is_empty() {
        return Ok(());
    }
    let keys: Vec<String> = targets.iter().flat_map(|t| t.keys.iter().cloned()).collect();
    let listed = cfg.object_opens.mark_then(&keys, || {});
    let is_agent_pid = |p: &i32| agent_pids.contains(&tgid_of(*p));
    let mut channels: Vec<String> = Vec::new();
    if listed.now.iter().any(is_agent_pid) {
        for t in targets {
            if let Some(c) = t.path.clone().or_else(|| t.keys.first().cloned()) {
                if !channels.contains(&c) {
                    channels.push(c);
                }
            }
        }
    }
    if scan || listed.recent.iter().any(is_agent_pid) || !channels.is_empty() {
        for p in &agent_pids {
            for o in crate::object_flow::held_objects(*p) {
                if !o.reads || !targets.iter().any(|t| crate::object_flow::same_object(&o, t)) {
                    continue;
                }
                if let Some(c) = o.path.clone().or_else(|| o.keys.first().cloned()) {
                    if !channels.contains(&c) {
                        channels.push(c);
                    }
                }
            }
        }
    }
    for c in channels {
        record_agent_flow(cfg, &c, from)?;
    }
    Ok(())
}

/// Plan 13 §9 R1, the file shapes: process `pid` is about to receive a
/// reading descriptor (or a mapping) of `target`. A mark (a holder wrote
/// it, and no label gates it: an unlinked file reopened, an `O_TMPFILE`
/// linked into place, a segment a holder left) makes it a holder flowing
/// from the writers before it gets a byte, its tree swept (`Err`: it holds
/// an unbound connection, the open is refused). The agent is never made a
/// holder: its open of such an object is refused (`Err`), as a labelled
/// file would reach it only as its twin. `Ok(Some(ticket))`: not marked,
/// registered in flight until the caller's `end` (or `end_after`).
pub(crate) fn object_open(cfg: &GuardConfig, pid: i32, target: &crate::object_flow::ObjectTarget) -> Result<Option<u64>, (String, crate::guard_kernel::TaintedRefusal)> {
    let look = cfg.object_opens.begin(pid, &target.keys, |ks| cfg.tainted.link_flows(ks));
    let from = match look {
        crate::object_flow::OpenLook::InFlight(t) => return Ok(Some(t)),
        crate::object_flow::OpenLook::Marked(from) => from,
    };
    let tgid = tgid_of(pid);
    let own = own_key_of(tgid);
    let from: Vec<String> = from.into_iter().filter(|f| *f != own).collect();
    if from.is_empty() {
        return Ok(None);
    }
    if is_agent(cfg, &own) {
        return Err(("a file a holder wrote, which no label gates (the agent is never made a holder)".into(), crate::guard_kernel::TaintedRefusal::default()));
    }
    agent_child_receipt(cfg, &[tgid], &object_channel(target), &from).map_err(|e| (format!("an agent tool's read of a file a holder wrote (the flow could not be recorded: {e})"), crate::guard_kernel::TaintedRefusal::default()))?;
    admit_receivers(cfg, &[tgid], &from, &[], &[], None)?;
    Ok(None)
}

/// `key` holds what `from` holds, through a descriptor (plan 13 D2, §9 R1):
/// remembered in the guard's set (`TaintedSet::insert_flow`, its connects
/// and writes then judged with `flowsFrom`) and recorded at the arbiter
/// (`recordProcessFlow`), whose model-exit fold then counts it too: a tool
/// call whose process received a holder's bytes through a channel from
/// OUTSIDE the call's tree (a holder left running by an earlier call) is
/// masked like one that read the file. Best-effort at the arbiter: an older
/// arbiter that does not know the op keeps the guard-side confinement.
pub(crate) fn flow_holder(cfg: &GuardConfig, key: &str, from: &[String]) {
    cfg.tainted.insert_flow(key, from);
    let flows: Vec<String> = from.iter().filter(|f| f.as_str() != key).cloned().collect();
    if flows.is_empty() {
        return;
    }
    let Some(c) = cfg.emitter.as_ref() else { return };
    let session = cfg.secrets.as_ref().and_then(|s| s.session.clone());
    if let Ok(mut client) = c.lock() {
        let _ = client.record_process_flow(&mandu_arbiter::protocol::RecordProcessFlowArgs {
            proc_key: key.to_string(),
            flows_from: flows,
            session,
        });
    }
}

/// Plan 13 §9 R1: `receivers` take what `from` holds through a channel
/// joined AFTER the holder's taint (a connection the holder accepts, a
/// socket-pair or pipe end passed over `SCM_RIGHTS`). Each becomes a holder
/// flowing from it (`flow_holder`), and its tree is swept like a pipe
/// receiver's at a taint (`guard_send::sweep_receivers`): a socket to an
/// unbound peer refuses the joining event (`Err`, fail-closed: the caller
/// resets the connection or refuses the send, so no byte flows), a file
/// held open for writing takes the label, its own pipes are followed.
/// `channel`: the sockets of the channel itself (not exits); `exclude`: the
/// writer's processes.
pub(crate) fn admit_receivers(cfg: &GuardConfig, receivers: &[i32], from: &[String], channel: &[u64], exclude: &[i32], caller: Option<i32>) -> Result<(), (String, crate::guard_kernel::TaintedRefusal)> {
    if receivers.is_empty() {
        return Ok(());
    }
    for q in receivers {
        flow_holder(cfg, &own_key_of(tgid_of(*q)), from);
    }
    let writes = crate::guard_send::sweep_receivers(cfg, receivers.to_vec(), channel, exclude, caller)?;
    crate::guard_kernel::label_held_writes(cfg, writes);
    Ok(())
}

/// Does the agent process itself (`agent_keys`) hold `link`?
pub(crate) fn agent_holds(cfg: &GuardConfig, link: &str) -> bool {
    let links = [link.to_string()];
    agent_keys(cfg)
        .iter()
        .filter_map(|k| crate::lineage::parse_key(k).map(|(pid, _)| pid))
        .any(|pid| pipe_flow::holds_any(pid, &links))
}

/// Plan 13 §4.5.1 (decision 2026-10-02: mask, do not refuse): record at the
/// arbiter that the agent holds `link`, whose other end the holders `from`
/// write into, and watch it until the agent drops it. The agent is never
/// made a holder (D2): its connections stay its own, and the model exit
/// masks what it received in that window. `Err`: the record could not be
/// made (no arbiter, an older one, a failed request); the caller refuses
/// the event that would let the holder's bytes reach the agent
/// (fail-closed).
pub(crate) fn record_agent_flow(cfg: &GuardConfig, link: &str, from: &[String]) -> Result<(), String> {
    let Some(c) = cfg.emitter.as_ref() else { return Err("no arbiter to record it at".into()) };
    let session = cfg.secrets.as_ref().and_then(|s| s.session.clone());
    let flows: Vec<String> = from.iter().filter(|f| !f.is_empty()).cloned().collect();
    if flows.is_empty() {
        return Err("no holder to record".into());
    }
    {
        let mut client = c.lock().map_err(|_| "the arbiter client is poisoned".to_string())?;
        client
            .record_agent_flow(&mandu_arbiter::protocol::RecordAgentFlowArgs { channel: link.to_string(), flows_from: Some(flows), closed: None, session })
            .map_err(|e| e.to_string())?;
    }
    if let Ok(mut open) = cfg.agent_flows.lock() {
        if !open.iter().any(|l| l == link) {
            open.push(link.to_string());
        }
    }
    Ok(())
}

/// Plan 13 §4.5.1: report every watched agent channel the agent no longer
/// holds as closed (from the guard's periodic look, `run_guard_supervisor`).
/// A report that fails keeps the channel watched (open at the arbiter: the
/// window only stays wider).
pub(crate) fn observe_agent_closes(cfg: &GuardConfig) {
    let open: Vec<String> = cfg.agent_flows.lock().map(|v| v.clone()).unwrap_or_default();
    if open.is_empty() {
        return;
    }
    let closed = pipe_flow::closed_agent_links(&open, |l| agent_holds(cfg, l));
    if closed.is_empty() {
        return;
    }
    let Some(c) = cfg.emitter.as_ref() else { return };
    let session = cfg.secrets.as_ref().and_then(|s| s.session.clone());
    let mut done: Vec<String> = Vec::new();
    if let Ok(mut client) = c.lock() {
        for link in closed {
            if client
                .record_agent_flow(&mandu_arbiter::protocol::RecordAgentFlowArgs { channel: link.clone(), flows_from: None, closed: Some(true), session: session.clone() })
                .is_ok()
            {
                done.push(link);
            }
        }
    }
    if let Ok(mut open) = cfg.agent_flows.lock() {
        open.retain(|l| !done.contains(l));
    }
}

/// The rows of this network namespace's `/proc/net/tcp` and `tcp6` (the
/// guard's, which is the tree's: a socket of a nested namespace is in none).
pub(crate) fn tcp_rows() -> Vec<crate::send_guard::ProcNetRow> {
    let mut rows = Vec::new();
    for (t, v6) in [("tcp", false), ("tcp6", true)] {
        if let Ok(text) = std::fs::read_to_string(format!("/proc/self/net/{t}")) {
            rows.extend(crate::send_guard::proc_net_rows(&text, v6));
        }
    }
    rows
}

/// What a holder's socket `ino` is (`pipe_flow::HolderSocket`), read from
/// `/proc/net` and `sock_diag` with no copy of the socket, so the taint-time
/// sweep reads it on a kernel without `pidfd_getfd` too.
fn holder_socket_of(rows: &[crate::send_guard::ProcNetRow], ino: u64) -> pipe_flow::HolderSocket {
    use crate::send_guard::TcpFacts;
    match crate::send_guard::tcp_socket_facts(rows, ino) {
        Some(TcpFacts::Connected { other: Some(other), serves }) => pipe_flow::HolderSocket::TcpLocal { other, holder_serves: serves },
        Some(_) => pipe_flow::HolderSocket::Other,
        None => match crate::guard_rights::unix_peer_of(ino) {
            Some(peer) => pipe_flow::HolderSocket::Unix {
                own_named: crate::guard_rights::unix_name_of(ino as u32).map(|n| !n.is_empty()).unwrap_or(false),
                peer: Some(u64::from(peer)),
            },
            None => pipe_flow::HolderSocket::Other,
        },
    }
}

/// Plan 13 §4.5.1, at the taint-time sweep, before the socket `ino` of the
/// new holder `p` is judged as an exit (`classify`):
///
/// - (the proxy leg, 2026-10-02) a connection the holder accepted from the
///   session's net-proxy (`pipe_flow::relayed_channel`): `Err`, the raw
///   open is refused. The proxy hands the holder's reply to whichever
///   process asked it, over upstream connections it pools, so no flow can
///   be recorded for it; the exit check alone admitted it whenever the
///   holder's bindings named this machine;
/// - a connection whose other end the agent holds (a keep-alive the agent
///   opened to an HTTP MCP server or a dev server before that server read
///   its secret): recorded as an agent flow and admitted (`Ok(true)`: the
///   sweep does not judge it as an exit, which refused the raw open before);
/// - (the old-kernel degrade, 2026-10-02) a LISTENING socket, where the
///   accept is not trapped (`accepts_untrapped`): the agent's connections to
///   it, accepted or still in its backlog, are recorded as agent flows (the
///   holder takes the one in its backlog unjudged; where the accept is
///   trapped, `accepted_flow` records it there); `Ok(false)`, the listener
///   is classified as before.
///
/// `Ok(false)`: none of these; `Err`: refused, or a record that failed
/// (fail-closed: the raw open is refused).
pub(crate) fn sweep_local_channel(cfg: &GuardConfig, p: i32, ino: u64) -> Result<bool, String> {
    let agent_named = cfg.secrets.as_ref().map(|s| !s.agent_exe.is_empty()).unwrap_or(false);
    if !agent_named && cfg.proxy_ports.is_empty() {
        return Ok(false);
    }
    let rows = tcp_rows();
    if let Some(crate::send_guard::TcpFacts::Listening(at)) = crate::send_guard::tcp_socket_facts(&rows, ino) {
        if agent_named && cfg.accepts_untrapped {
            let from = cfg.tainted.flow_sources(&[writer_entry(tgid_of(p))]);
            for client in crate::send_guard::clients_of_listener(&rows, at) {
                let link = format!("socket:[{client}]");
                if agent_holds(cfg, &link) {
                    record_agent_flow(cfg, &link, &from).map_err(|e| format!("the agent's connection waiting on this listener (the arbiter could not record it: {e})"))?;
                }
            }
        }
        return Ok(false);
    }
    let facts = holder_socket_of(&rows, ino);
    if pipe_flow::relayed_channel(&facts, |l| proxy_holds(cfg, l).unwrap_or(true)).is_some() {
        return Err("a connection the session's net-proxy relays (it hands the reply to a requester the guard cannot attribute: plan 13 §4.5.1)".into());
    }
    if !agent_named {
        return Ok(false);
    }
    let Some(link) = pipe_flow::agent_channel(&facts, |l| agent_holds(cfg, l)) else { return Ok(false) };
    let from = cfg.tainted.flow_sources(&[writer_entry(tgid_of(p))]);
    record_agent_flow(cfg, &link, &from).map_err(|e| format!("the agent's connection (the arbiter could not record it: {e})"))?;
    Ok(true)
}

// ── plan 13 §4.5.1, the proxy leg (2026-10-02) ──────────────────────────────

/// Every process of this machine (`/proc/<pid>`), the guard's tree or not.
fn all_pids() -> Vec<i32> {
    let Ok(rd) = std::fs::read_dir("/proc") else { return Vec::new() };
    rd.flatten().filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok()).collect()
}

/// The processes of the session's net-proxy: those holding a socket that
/// listens at one of the launch's proxy ports on a loopback or wildcard
/// address (`send_guard::proxy_listener_inodes`), found once by a look at
/// every process and kept while one of them still holds it. `Ok(empty)`:
/// no proxy listens (none in this launch, or it is gone: nothing relays).
/// `Err`: one listens and no process holding it can be read (the caller
/// fails closed).
fn proxy_pids(cfg: &GuardConfig) -> Result<Vec<i32>, String> {
    if cfg.proxy_ports.is_empty() {
        return Ok(Vec::new());
    }
    let inodes = crate::send_guard::proxy_listener_inodes(&tcp_rows(), &cfg.proxy_ports);
    if inodes.is_empty() {
        return Ok(Vec::new());
    }
    let links: Vec<String> = inodes.iter().map(|i| format!("socket:[{i}]")).collect();
    let cached: Vec<i32> = cfg.proxy.lock().map(|c| c.clone()).unwrap_or_default();
    let live: Vec<i32> = cached.into_iter().filter(|p| pipe_flow::holds_any(*p, &links)).collect();
    if !live.is_empty() {
        return Ok(live);
    }
    let found: Vec<i32> = all_pids().into_iter().filter(|p| pipe_flow::holds_any(*p, &links)).collect();
    if found.is_empty() {
        return Err("the session's net-proxy listens, but no process holding its listener can be read".into());
    }
    if let Ok(mut c) = cfg.proxy.lock() {
        *c = found.clone();
    }
    Ok(found)
}

/// Does the session's net-proxy hold `link`? `Err`: it cannot be told.
pub(crate) fn proxy_holds(cfg: &GuardConfig, link: &str) -> Result<bool, String> {
    let pids = proxy_pids(cfg)?;
    let links = [link.to_string()];
    Ok(pids.iter().any(|p| pipe_flow::holds_any(*p, &links)))
}

/// Plan 13 §4.5.1, the proxy leg (2026-10-02), at a holder's accept: is the
/// client socket (inode `client`) the session's net-proxy's? The proxy
/// re-originates the tree's proxied requests from outside the tree (an
/// address of this machine `NO_PROXY` does not name: its LAN address, a
/// hostname resolving to it, `127.0.0.2`) and hands the reply to whichever
/// process asked, the agent or a tool process, over upstream connections it
/// pools; the guard saw a client outside its tree and admitted it, so the
/// reply reached the asker unmasked and unconfined. Some(why): the caller
/// resets the connection before the holder gets it. A proxy that cannot be
/// told apart is refused too (fail-closed).
pub(crate) fn relayed_by_proxy(cfg: &GuardConfig, client: u64) -> Option<String> {
    match proxy_holds(cfg, &format!("socket:[{client}]")) {
        Ok(true) => Some("the session's net-proxy, which relays the reply to a requester the guard cannot attribute".into()),
        Ok(false) => None,
        Err(e) => Some(format!("a client the guard cannot tell from the session's net-proxy ({e})")),
    }
}

// ── plan 13 §4.5.1, the old-kernel degrade (2026-10-02) ─────────────────────

/// Is `ip` an address of this machine (loopback, the wildcard, or one a
/// socket of this network namespace can bind)?
fn this_machine(ip: std::net::IpAddr) -> bool {
    let ip = match ip {
        std::net::IpAddr::V6(a) => a.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(std::net::IpAddr::V6(a)),
        v4 => v4,
    };
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let (family, raw): (i32, Vec<u8>) = match ip {
        std::net::IpAddr::V4(a) => {
            let sa = libc::sockaddr_in { sin_family: libc::AF_INET as u16, sin_port: 0, sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(a.octets()) }, sin_zero: [0; 8] };
            // SAFETY: viewing a plain-old-data sockaddr as bytes.
            (libc::AF_INET, unsafe { std::slice::from_raw_parts(&sa as *const _ as *const u8, std::mem::size_of_val(&sa)) }.to_vec())
        }
        std::net::IpAddr::V6(a) => {
            let sa = libc::sockaddr_in6 { sin6_family: libc::AF_INET6 as u16, sin6_port: 0, sin6_flowinfo: 0, sin6_addr: libc::in6_addr { s6_addr: a.octets() }, sin6_scope_id: 0 };
            // SAFETY: as above.
            (libc::AF_INET6, unsafe { std::slice::from_raw_parts(&sa as *const _ as *const u8, std::mem::size_of_val(&sa)) }.to_vec())
        }
    };
    // SAFETY: a datagram socket of our own, bound to probe the address, closed.
    unsafe {
        let s = libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return false;
        }
        let ok = libc::bind(s, raw.as_ptr() as *const libc::sockaddr, raw.len() as libc::socklen_t) == 0;
        libc::close(s);
        ok
    }
}

/// Plan 13 §4.5.1, the old-kernel degrade (2026-10-02): the AGENT connects
/// over TCP to `dest`, a listener a live holder's tree holds on this
/// machine. Where the guard performs the holder's accept
/// (`accepted_flow`), the flow is recorded there and this does nothing;
/// where the accept is not trapped (`accepts_untrapped`: no `pidfd_getfd`,
/// < 5.6), only the taint-time sweep saw the
/// agent's connection, so one made after the taint reached the model
/// unmasked. The connect is trapped on every kernel: the flow is recorded
/// here, before the connect is performed (or continued). `agent_sock`: the
/// inode of the agent's socket (None: it could not be read). `Err`: the
/// caller refuses the connect (fail-closed).
pub(crate) fn agent_connect_flow(cfg: &GuardConfig, pid: i32, agent_sock: Option<u64>, dest: (std::net::IpAddr, u16)) -> Result<(), String> {
    if !cfg.accepts_untrapped || cfg.tainted.is_empty() || cfg.secrets.is_none() || !is_agent(cfg, &own_key_of(tgid_of(pid))) {
        return Ok(());
    }
    let rows = tcp_rows();
    if !rows.iter().any(|r| r.state == crate::send_guard::TCP_LISTEN && r.local.1 == dest.1) {
        return Ok(());
    }
    let listeners = crate::send_guard::listeners_for(&rows, dest, this_machine(dest.0));
    if listeners.is_empty() {
        return Ok(());
    }
    let links: Vec<String> = listeners.iter().map(|i| format!("socket:[{i}]")).collect();
    let mut writers: Vec<(String, Vec<String>)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for h in cfg.tainted.live_holder_pids() {
        for q in crate::guard_send::subtree(h) {
            if seen.insert(q) && pipe_flow::holds_any(q, &links) {
                writers.push(writer_entry(q));
            }
        }
    }
    if writers.is_empty() {
        return Ok(());
    }
    let Some(ino) = agent_sock else { return Err("the agent's socket could not be named".into()) };
    let from = cfg.tainted.flow_sources(&writers);
    record_agent_flow(cfg, &format!("socket:[{ino}]"), &from)
}

// ── plan 13 §4.5.1, a FIFO the agent itself reads (2026-10-02) ──────────────

/// A FIFO by its identity, as a link the taint set marks
/// (`TaintedSet::mark_link`): its spellings differ (a hard link, a bind
/// mount), its inode does not.
fn fifo_mark(id: (u64, u64)) -> String {
    format!("fifo:{}:{}", id.0, id.1)
}

/// The identity of `pid`'s descriptor `fd` when it is a FIFO.
fn fifo_id_of(pid: i32, fd: std::os::unix::io::RawFd) -> Option<(u64, u64)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let m = std::fs::metadata(format!("/proc/{pid}/fd/{fd}")).ok()?;
    m.file_type().is_fifo().then_some((m.dev(), m.ino()))
}

/// The FIFOs `pid` holds that the access mode says it `writes` (or reads):
/// their identity and the descriptor's link.
fn fifo_ends(pid: i32, writes: bool) -> Vec<((u64, u64), String)> {
    pipe_flow::fd_table(pid)
        .into_iter()
        .filter(|h| pipe_flow::flow_kind(&h.link) == pipe_flow::FlowKind::Path)
        .filter(|h| pipe_flow::accmode_of(pid, h.fd).map(|a| if writes { pipe_flow::accmode_writes(a) } else { pipe_flow::accmode_reads(a) }).unwrap_or(false))
        .filter_map(|h| fifo_id_of(pid, h.fd).map(|id| (id, h.link)))
        .collect()
}

/// The agent's own links (the path its descriptor names) of its read ends
/// of the FIFO `id`.
fn agent_fifo_reads(cfg: &GuardConfig, id: (u64, u64)) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for k in agent_keys(cfg) {
        let Some((pid, _)) = crate::lineage::parse_key(&k) else { continue };
        for (i, link) in fifo_ends(pid, false) {
            if i == id && !out.contains(&link) {
                out.push(link);
            }
        }
    }
    out
}

/// Plan 13 §4.5.1 (2026-10-02): a holder (`writer`) is opening the FIFO `id`
/// to write, its descriptor not yet its own. The FIFO is marked (by
/// identity) as carrying what the writer holds, and an agent already
/// holding it for reading gets an agent flow recorded on its read end. D2
/// skips the agent as a reader and the model exit folds no tree for the
/// agent's own file tool, so a named pipe the agent reads with it reached
/// the model unmasked. `Err`: the record failed; the caller refuses the
/// write-open (fail-closed). Called under `fifo_gate`.
pub(crate) fn holder_fifo_open(cfg: &GuardConfig, writer: &(String, Vec<String>), id: (u64, u64)) -> Result<(), String> {
    let from = cfg.tainted.flow_sources(std::slice::from_ref(writer));
    cfg.tainted.mark_link(&fifo_mark(id), &from);
    for link in agent_fifo_reads(cfg, id) {
        record_agent_flow(cfg, &link, &from)?;
    }
    Ok(())
}

/// Plan 13 §4.5.1 (2026-10-02): the agent is opening the FIFO `id` (its
/// link `link`) to read, its descriptor not yet its own. When a holder has
/// written into it (a mark, by identity or by the path a sweep marked) or a
/// live holder's tree holds it open for writing, an agent flow is recorded
/// on `link` first. `Err`: the record failed; the caller refuses the open
/// (fail-closed). Called under `fifo_gate`.
pub(crate) fn agent_fifo_open(cfg: &GuardConfig, link: &str, id: (u64, u64)) -> Result<(), String> {
    let mut from = cfg.tainted.link_flows(&[fifo_mark(id), link.to_string()]);
    let mut writers: Vec<(String, Vec<String>)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for h in cfg.tainted.live_holder_pids() {
        for q in crate::guard_send::subtree(h) {
            if seen.insert(q) && fifo_ends(q, true).iter().any(|(i, _)| *i == id) {
                writers.push(writer_entry(q));
            }
        }
    }
    for f in cfg.tainted.flow_sources(&writers) {
        if !from.contains(&f) {
            from.push(f);
        }
    }
    if from.is_empty() {
        return Ok(());
    }
    record_agent_flow(cfg, link, &from)
}

/// Plan 13 §4.5.1 (2026-10-02), at the taint-time sweep: the FIFOs `procs`
/// (a swept tree) hold open for writing carry what `from` holds: each is
/// marked by identity, and an agent read end of it gets an agent flow
/// recorded before the raw open is answered. `Err`: a record failed (the
/// caller refuses the raw open).
pub(crate) fn sweep_fifo_writes(cfg: &GuardConfig, procs: &[i32], from: &[String]) -> Result<(), String> {
    let mut ids: Vec<(u64, u64)> = Vec::new();
    for p in procs {
        for (id, _) in fifo_ends(*p, true) {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    for id in ids {
        cfg.tainted.mark_link(&fifo_mark(id), from);
        for link in agent_fifo_reads(cfg, id) {
            record_agent_flow(cfg, &link, from)?;
        }
    }
    Ok(())
}

/// Is the process `pid` (any thread of it) the agent?
pub(crate) fn is_agent_pid(cfg: &GuardConfig, pid: i32) -> bool {
    is_agent(cfg, &own_key_of(tgid_of(pid)))
}

/// Plan 13 §9 R1 (A): a holder (`acceptor`) is about to take a connection
/// whose client socket has inode `client` (a Unix client, or this machine's
/// TCP client found in `/proc/net`). The processes of the guard's tree
/// holding that socket (never the agent: what reaches it goes to the model
/// through a tool result, §4.5.1) receive what the holder writes back:
/// they become holders flowing from it before the holder gets the
/// connection, and their trees are swept (`admit_receivers`). A client
/// outside the guard's tree (the user's browser) is outside the boundary
/// (§4.9), as before.
pub(crate) fn accepted_flow(cfg: &GuardConfig, acceptor: i32, client: u64) -> Result<(), (String, crate::guard_kernel::TaintedRefusal)> {
    let tgid = tgid_of(acceptor);
    let link = format!("socket:[{client}]");
    let from = cfg.tainted.flow_sources(&[writer_entry(tgid)]);
    // Plan 13 §4.5.1 (decision 2026-10-02): the agent itself is the client
    // (an HTTP MCP server, a dev server it fetches). Never made a holder;
    // the flow is recorded at the arbiter before the holder gets the
    // connection, so the model exit masks what the agent receives. A record
    // that fails resets the connection (fail-closed).
    if agent_holds(cfg, &link) {
        if let Err(e) = record_agent_flow(cfg, &link, &from) {
            return Err((format!("the agent (its connection could not be recorded: {e})"), crate::guard_kernel::TaintedRefusal::default()));
        }
    }
    cfg.tainted.mark_link(&link, &from);
    let exclude: std::collections::HashSet<i32> = [tgid].into_iter().collect();
    let receivers: Vec<i32> = flow_readers(cfg, std::slice::from_ref(&link), &exclude, true).into_iter().map(tgid_of).collect();
    admit_receivers(cfg, &receivers, &from, &[client], &[tgid], None)
}

/// What a descriptor passed over `SCM_RIGHTS` joins its receiver to (plan
/// 13 §9 R1 (C)), from the guard's copy of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PassedEnd {
    /// A connected or paired Unix socket (inode): it carries both ways, to
    /// whoever holds its peer (`peer`, `socket:[ino]`). A side bound to a
    /// NAME is a server's end: a holder's connection to a named server is an
    /// exit the connect judged (bindings), never a flow into the server, the
    /// rule of the taint-time sweep (`unnamed_unix_peer`). So the receivers
    /// take the other side's bytes only when the passed end is not named
    /// (`own_named`), and give theirs only when the peer is not (`peer_named`).
    Socket { ino: u64, peer: String, own_named: bool, peer_named: bool },
    /// A pipe or FIFO (`pipe:[ino]`, or the FIFO's path) and whether the
    /// receiver may read it and write it.
    Pipe { link: String, reads: bool, writes: bool },
    /// A regular file (a memfd, an unlinked file, a `/dev/shm` file, any
    /// file: `object_flow`) and whether the receiver may read and write it.
    /// Its bytes are the object's, past and future: the receivers read what
    /// the sender (or any holder that writes it) put there, and the
    /// processes reading it read what the receivers write.
    File { target: crate::object_flow::ObjectTarget, reads: bool, writes: bool },
}

/// Plan 13 §9 R1 (C): the descriptors `copies` (the guard's copies) are
/// about to reach `receivers` (the processes holding the receiving socket).
/// A pass joins two sides, either of which may hold a secret: the receivers
/// (who will hold the passed end) and the processes holding the other end
/// (a socket's peer, a pipe's other side). When one side holds, the other
/// side becomes a holder flowing from it, before the send is performed (so
/// before a byte can flow), and is swept (`admit_receivers`): a socket to an
/// unbound peer it already holds refuses the send. A holder passing an end
/// of a socket pair it made after its taint (`socketpair`, then
/// `sendmsg(SCM_RIGHTS)` to an untainted peer), and an untainted process
/// passing one end of its own pair to a holder and keeping the other, are
/// the two shapes. Never the agent; a process outside the guard's tree is
/// outside the boundary (§4.9), except that a holder handed an end whose
/// other side such a process holds refuses the pass (P0 2b, 2026-10-09).
pub(crate) fn pass_flows(cfg: &GuardConfig, caller: i32, receivers: &[i32], ends: &[PassedEnd]) -> Result<(), (String, crate::guard_kernel::TaintedRefusal)> {
    if ends.is_empty() || cfg.tainted.is_empty() || cfg.secrets.is_none() {
        return Ok(());
    }
    let tree = tree_procs(cfg);
    let agents = agent_keys(cfg);
    let in_scope = |p: i32| tree.contains(&p) && !agents.contains(&own_key_of(p));
    let receivers: Vec<i32> = receivers.iter().copied().map(tgid_of).filter(|p| in_scope(*p)).collect();
    if receivers.is_empty() {
        return Ok(());
    }
    // Who holds, by the set alone (its own taint, its parents', a flow it was
    // already given). Not `holder`: its later-event look would make a
    // process a holder on the spot WITHOUT sweeping what it already holds,
    // and this pass must sweep every process it makes one.
    let held_entry = |p: i32| -> Option<(String, Vec<String>)> {
        let own = own_key_of(p);
        let (held, chain) = cfg.tainted.holds_or_inherits(p, &own);
        held.then_some((own, chain))
    };
    let held_recv: Vec<(String, Vec<String>)> = receivers.iter().filter_map(|p| held_entry(*p)).collect();
    let held_recv_pids: Vec<i32> = receivers.iter().copied().filter(|p| held_recv.iter().any(|(k, _)| *k == own_key_of(*p))).collect();
    let unheld_recv: Vec<i32> = receivers.iter().copied().filter(|p| !held_recv_pids.contains(p)).collect();
    let sender = tgid_of(caller);
    for end in ends {
        // Plan 13 §9 R1, the file shapes: a regular file passed. Not a
        // channel with another end but an object: the receivers read what
        // is in it (the sender's taint when it holds, since it may have
        // written there or passed its raw descriptor of a secret; any
        // holder that writes it; a mark), and whoever reads it reads what a
        // holding receiver writes there.
        if let PassedEnd::File { target, reads, writes } = end {
            let targets = std::slice::from_ref(target);
            if *reads && !unheld_recv.is_empty() {
                let mut writers: Vec<(String, Vec<String>)> = Vec::new();
                if let Some(e) = held_entry(sender) {
                    writers.push(e);
                }
                for q in tree.iter().copied().filter(|q| !receivers.contains(q) && *q != sender) {
                    if crate::object_flow::written_objects(q).iter().any(|w| w.keys.iter().any(|k| target.keys.contains(k)) || (w.path.is_some() && w.path == target.path)) {
                        if let Some(e) = held_entry(q) {
                            writers.push(e);
                        }
                    }
                }
                let mut from = cfg.tainted.flow_sources(&writers);
                for f in cfg.tainted.link_flows(&target.keys) {
                    if !from.contains(&f) {
                        from.push(f);
                    }
                }
                if !from.is_empty() {
                    admit_receivers(cfg, &unheld_recv, &from, &[], &[], Some(caller))?;
                    mark_objects(cfg, targets, &from);
                }
            }
            if *writes && !held_recv.is_empty() {
                let from = cfg.tainted.flow_sources(&held_recv);
                let exclude: std::collections::HashSet<i32> = held_recv_pids.iter().copied().collect();
                let readers = object_receivers(cfg, targets, &from, &exclude, true);
                admit_receivers(cfg, &readers, &from, &[], &held_recv_pids, Some(caller))?;
            }
            continue;
        }
        let (other_link, channel, kind) = match end {
            PassedEnd::Socket { ino, peer, own_named, peer_named } => (peer.clone(), vec![*ino], pipe_flow::PassKind::Socket { own_named: *own_named, peer_named: *peer_named }),
            PassedEnd::Pipe { link, reads, writes } => (link.clone(), Vec::new(), pipe_flow::PassKind::Pipe { reads: *reads, writes: *writes }),
            PassedEnd::File { .. } => continue,
        };
        let (into_receivers, out_of_receivers) = pipe_flow::pass_directions(kind);
        // The other side's processes (never a receiver).
        let others: Vec<i32> = tree
            .iter()
            .copied()
            .filter(|q| !receivers.contains(q))
            .filter(|q| match end {
                PassedEnd::Socket { .. } => pipe_flow::holds_any(*q, std::slice::from_ref(&other_link)),
                // The receiver reads: who writes the pipe; it writes: who reads it.
                PassedEnd::Pipe { .. } | PassedEnd::File { .. } => (into_receivers && pipe_flow::writes_any(*q, std::slice::from_ref(&other_link))) || (out_of_receivers && pipe_flow::reads_any(*q, std::slice::from_ref(&other_link))),
            })
            .collect();
        // Into the receivers: the other side holds, or the link was marked
        // by a holder that wrote into it.
        if into_receivers && !unheld_recv.is_empty() {
            let writers: Vec<(String, Vec<String>)> = others
                .iter()
                .filter(|q| match end {
                    PassedEnd::Pipe { .. } | PassedEnd::File { .. } => pipe_flow::writes_any(**q, std::slice::from_ref(&other_link)),
                    PassedEnd::Socket { .. } => true,
                })
                .filter_map(|q| held_entry(*q))
                .collect();
            let mut from = cfg.tainted.flow_sources(&writers);
            for f in cfg.tainted.link_flows(std::slice::from_ref(&other_link)) {
                if !from.contains(&f) {
                    from.push(f);
                }
            }
            if !from.is_empty() {
                let unheld: Vec<i32> = unheld_recv.clone();
                let exclude: Vec<i32> = others.clone();
                admit_receivers(cfg, &unheld, &from, &channel, &exclude, Some(caller))?;
                // The link the receivers read through, marked once they are
                // swept (a later fork or pass of it is judged by it).
                let read_link = match end {
                    PassedEnd::Socket { ino, .. } => format!("socket:[{ino}]"),
                    PassedEnd::Pipe { link, .. } => link.clone(),
                    PassedEnd::File { .. } => continue,
                };
                cfg.tainted.mark_link(&read_link, &from);
            }
        }
        // Out of the receivers: a holder will hold the passed end, so the
        // other side receives what it writes.
        if out_of_receivers && !held_recv.is_empty() {
            // P0 2b (2026-10-09): the other side is held OUTSIDE the guard's
            // tree (a pipe's read end, a socket pair's other end that a
            // process the guard does not watch holds): no receiver it can
            // confine, so the pass is refused. The human plane is left out.
            let own_link = match end {
                PassedEnd::Socket { ino, .. } => format!("socket:[{ino}]"),
                PassedEnd::Pipe { link, .. } => link.clone(),
                PassedEnd::File { .. } => continue,
            };
            let chans = [pipe_flow::WrittenChannel { own: own_link, target: other_link.clone() }];
            if let Some(dest) = outside_receiver(cfg, &chans, &[]) {
                return Err((dest, crate::guard_kernel::TaintedRefusal::default()));
            }
            let from = cfg.tainted.flow_sources(&held_recv);
            let readers: Vec<i32> = others
                .iter()
                .copied()
                .filter(|q| match end {
                    PassedEnd::Pipe { .. } | PassedEnd::File { .. } => pipe_flow::reads_any(*q, std::slice::from_ref(&other_link)),
                    PassedEnd::Socket { .. } => true,
                })
                .filter(|q| held_entry(*q).is_none())
                .collect();
            let other_channel: Vec<u64> = match end {
                PassedEnd::Socket { .. } => other_link.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')).and_then(|n| n.parse().ok()).into_iter().collect(),
                PassedEnd::Pipe { .. } | PassedEnd::File { .. } => Vec::new(),
            };
            admit_receivers(cfg, &readers, &from, &other_channel, &held_recv_pids, Some(caller))?;
            // Marked once they are swept: a process that takes the link
            // later (a fork, a further pass) is judged by it.
            cfg.tainted.mark_link(&other_link, &from);
        }
    }
    Ok(())
}

/// Is the calling process a holder: by its parents (`holds_or_inherits`),
/// or, failing that, by a pipe or FIFO a holder writes into (plan 13 D2,
/// the later event)? Its own key's chain, as `holds_or_inherits` answers.
/// Nothing tainted at all: no `/proc` read beyond the parent walk's.
pub(crate) fn holder(cfg: &GuardConfig, pid: i32, own: &str) -> (bool, Vec<String>) {
    let (held, chain) = cfg.tainted.holds_or_inherits(pid, own);
    if held || cfg.tainted.is_empty() || cfg.secrets.is_none() {
        return (held, chain);
    }
    match later_flow(cfg, pid) {
        Some(from) => {
            cfg.tainted.inherit(own, &chain);
            flow_holder(cfg, own, &from);
            (true, chain)
        }
        None => (false, chain),
    }
}

/// The writer of a write-intent open when it holds (`holder`): its key and
/// chain, for `labelWrittenPathTainted` (`TaintedSet::tainted_writer`'s
/// contract: taken before the open is answered).
pub(crate) fn tainted_writer(cfg: &GuardConfig, pid: i32, flags: i32) -> Option<(String, Vec<String>)> {
    if !crate::secret_open::is_write_intent(flags) || cfg.tainted.is_empty() {
        return None;
    }
    let own = own_key_of(pid);
    let (held, chain) = holder(cfg, pid, &own);
    held.then_some((own, chain))
}

/// `flowsFrom` for the arbiter: None when the process flows from nothing
/// (the request stays as it was).
pub(crate) fn flows_from(cfg: &GuardConfig, own: &str, chain: &[String]) -> Option<Vec<String>> {
    let f = cfg.tainted.flows_for(own, chain);
    (!f.is_empty()).then_some(f)
}

/// How long a continued `shmat` stays in flight after the guard answered
/// (the kernel maps the segment once the tracee resumes; a writer's look at
/// `/proc/<pid>/maps` before then still counts it).
pub(crate) const ATTACH_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Plan 13 §9 R1, the file shapes, for SysV and POSIX IPC (under a secret
/// policy; `object_flow::ipc_call`):
///
///   - `shmat` by a holder, writable: the segment is marked and every process
///     of the tree that has it attached becomes a holder flowing from it,
///     swept (`object_written`); one holding an unbound connection refuses
///     the attach (EACCES).
///   - `shmat` by any other process (or read-only): a segment a holder wrote
///     (marked, also after the holder detached or exited) makes it a holder
///     (`object_open`; EACCES when it holds an unbound connection); else it
///     is in flight for `ATTACH_GRACE`, so a holder attaching meanwhile
///     counts it.
///   - `msgsnd` / `mq_timedsend` by a holder: refused (EACCES). A queue's
///     reader receives with no call the guard could judge before the bytes
///     arrive (`msgrcv` blocks inside the kernel), so the send is the one
///     point; an untainted process's send goes on.
///
/// The segment is named by the caller's IPC namespace and its id
/// (`object_flow::sysv_key`); a namespace the guard cannot read refuses the
/// call while any process holds a secret (fail-closed).
pub fn handle_ipc_notif(listener: std::os::unix::io::RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) {
    use crate::guard_kernel::{answer_continue, answer_errno};
    let pid = notif.pid as i32;
    let Some(call) = crate::object_flow::ipc_call(notif.data.nr as i64, &notif.data.args) else {
        answer_continue(listener, notif);
        return;
    };
    if cfg.secrets.is_none() {
        answer_continue(listener, notif);
        return;
    }
    let tgid = tgid_of(pid);
    let own = own_key_of(tgid);
    match call {
        crate::object_flow::IpcCall::QueueSend => {
            // Judged with the sends: a taint of this process waits for it.
            let gate = cfg.egress.enter(tgid);
            // This thread's last send let go is over (P0 1c).
            cfg.queue_sends.settle(pid);
            let (held, _) = holder(cfg, pid, &own);
            if held {
                crate::guard_send::emit_tainted(cfg, "send on", "a message queue", &crate::guard_kernel::TaintedRefusal::default());
                answer_errno(listener, notif, libc::EACCES);
            } else {
                // P0 1c (2026-10-07): the kernel copies the buffer AFTER this
                // answer; dropped here, the gate let another thread of the
                // process read a secret raw and write it into the buffer in
                // between. Kept until this thread is seen out of the send.
                cfg.queue_sends.hold(tgid, pid, notif.data.nr as i64, gate);
                answer_continue(listener, notif);
            }
        }
        crate::object_flow::IpcCall::Attach { shmid, writes } => {
            if shmid < 0 {
                // The kernel's own EINVAL.
                answer_continue(listener, notif);
                return;
            }
            let Some(ns) = crate::object_flow::ipc_ns_of(pid) else {
                if cfg.tainted.is_empty() {
                    answer_continue(listener, notif);
                } else {
                    answer_errno(listener, notif, libc::EACCES);
                }
                return;
            };
            let target = crate::object_flow::ObjectTarget { keys: vec![crate::object_flow::sysv_key(ns, shmid as u64)], path: None };
            let (held, chain) = if cfg.tainted.is_empty() { (false, Vec::new()) } else { holder(cfg, pid, &own) };
            if held && writes {
                match object_written(cfg, &(own, chain), pid, &target, false, None) {
                    Ok(()) => answer_continue(listener, notif),
                    Err((dest, refusal)) => {
                        crate::guard_send::emit_tainted(cfg, "attach shared memory read by a process holding a connection to", &dest, &refusal);
                        answer_errno(listener, notif, libc::EACCES);
                    }
                }
                return;
            }
            match object_open(cfg, pid, &target) {
                Ok(Some(ticket)) => {
                    answer_continue(listener, notif);
                    cfg.object_opens.end_after(ticket, ATTACH_GRACE);
                }
                Ok(None) => answer_continue(listener, notif),
                Err((dest, refusal)) => {
                    crate::guard_send::emit_tainted(cfg, "attach shared memory a holder wrote, holding", &dest, &refusal);
                    answer_errno(listener, notif, libc::EACCES);
                }
            }
        }
    }
}

/// P0 triage 1b (2026-10-07): a trapped `memfd_create` (under a secret
/// policy; `object_flow::is_memfd_nr`). Anyone but a holder: CONTINUE, the
/// kernel makes it (a holder's memfds held at its taint are listed by the
/// sweep). A holder: the guard makes the memfd itself (the caller's name and
/// flags; `object_flow::memfd_name`, `memfd_flags`), marks the new object's
/// key as carrying what the holder holds (`object_written`, born now, so no
/// reader is looked for) and only then hands the descriptor over (ADDFD as
/// the answer): whoever comes to hold it later (a process sharing the
/// holder's descriptor table, which is neither its parent nor its child) is
/// a holder at its next event by the mark, also after the holder exits.
/// Memory of the caller the guard cannot read: EACCES, as an open answers
/// (fail-closed); a pointer that does not reach a name: the kernel's EFAULT
/// or EINVAL. The memfd is made in the guard's pid namespace, so the
/// guard's `vm.memfd_noexec` applies to it (the tree's is the guard's, or
/// was inherited from it).
pub fn handle_memfd_notif(listener: std::os::unix::io::RawFd, cfg: &GuardConfig, notif: &libc::seccomp_notif) {
    use crate::guard_kernel::{answer_continue, answer_errno};
    let pid = notif.pid as i32;
    if cfg.secrets.is_none() || cfg.tainted.is_empty() {
        answer_continue(listener, notif);
        return;
    }
    let tgid = tgid_of(pid);
    let own = own_key_of(tgid);
    let (held, chain) = holder(cfg, pid, &own);
    if !held {
        answer_continue(listener, notif);
        return;
    }
    let name = match read_memfd_name(pid, notif.data.args[0]).and_then(|r| crate::object_flow::memfd_name(&r)) {
        Ok(n) => n,
        Err(e) => {
            answer_errno(listener, notif, e);
            return;
        }
    };
    let Ok(cname) = std::ffi::CString::new(name) else {
        answer_errno(listener, notif, libc::EINVAL);
        return;
    };
    let (flags, fd_flags) = crate::object_flow::memfd_flags(notif.data.args[1]);
    // SAFETY: a valid C string; the flags are the caller's, judged by the kernel.
    let fd = unsafe { libc::memfd_create(cname.as_ptr(), flags) };
    if fd < 0 {
        answer_errno(listener, notif, std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
        return;
    }
    let Some(target) = crate::object_flow::fd_object(fd) else {
        crate::guard_kernel::close_fd(fd);
        answer_errno(listener, notif, libc::EACCES);
        return;
    };
    if let Err((dest, refusal)) = object_written(cfg, &(own, chain), pid, &target, true, None) {
        crate::guard_kernel::close_fd(fd);
        crate::guard_send::emit_tainted(cfg, "create a memfd read by a process holding a connection to", &dest, &refusal);
        answer_errno(listener, notif, libc::EACCES);
        return;
    }
    // Closed before the caller resumes (`hand_over`): a memfd is writable,
    // and a program written into one and run at once (fexecve) must not
    // meet ETXTBSY while the guard still holds it.
    if let Err(e) = crate::guard_kernel::hand_over(listener, notif, fd, fd_flags) {
        // A notification that went away (ENOENT) has no one to answer.
        if e != libc::ENOENT {
            answer_errno(listener, notif, e);
        }
    }
}

/// Up to `MFD_NAME_MAX_LEN + 1` bytes of the caller's memory at `addr`
/// (fewer when the read runs into unmapped memory, where the kernel's own
/// string copy stops too): EFAULT for a pointer that reaches nothing, EACCES
/// when the guard may not read the caller's memory at all.
fn read_memfd_name(pid: i32, addr: u64) -> Result<Vec<u8>, i32> {
    const ASK: usize = crate::object_flow::MFD_NAME_MAX_LEN + 1;
    if addr == 0 {
        return Err(libc::EFAULT);
    }
    let mut buf = vec![0u8; ASK];
    let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: ASK };
    let remote = libc::iovec { iov_base: addr as *mut libc::c_void, iov_len: ASK };
    // SAFETY: reads at most ASK bytes of the caller's memory into our buffer.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n < 0 {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EFAULT) => libc::EFAULT,
            _ => libc::EACCES,
        });
    }
    buf.truncate(n as usize);
    Ok(buf)
}
