//! report_channel — which arbiter socket the guard reports on
//! (confidentiality plan 13 §3 D9, exec-routing.md §7.5 "Authenticated
//! reports"). Mandu-new, no reference origin.
//!
//! The guard's records (lineage chains, the agent's own shells, raw opens
//! with the opener's identity facts, protected writes, pipe flows) decide
//! what the model is shown. The arbiter believes them only from a channel the
//! agent's process tree cannot reach: its HUMAN-plane socket, walled off from
//! the agent world by this very guard's `unixDeny`, the secret-twins tmpfs and
//! the Unix allow-list (arbiter-human-plane.md §6). On the DATA socket every
//! report is a claim: the arbiter may add taint for it but never lowers one,
//! so a guard that cannot reach the human socket fails closed (its opens are
//! twins, its protected writes refused) until it finds the human plane and
//! moves there ([`decide_upgrade`], arbiter-human-plane.md §5.2).
//!
//! The guard runs OUTSIDE its own filter and outside the wrap, so it can dial
//! the human socket; its environment is the agent's (the guard execs the agent
//! with it), which never carries `MANDU_ARBITER_HUMAN_SOCK`, so the path is
//! discovered from the data socket's `hello` before the agent starts, and
//! confirmed by the human socket's own `hello` answering `channel: human`.
//! The path is not a secret: the walls are the boundary, as for every
//! human-plane consumer. The connection is the guard's own (close-on-exec,
//! opened in the supervisor after the fork) and the guard is not dumpable, so
//! no process of the agent can borrow it.
//!
//! Pure decision, unit-tested; the bin performs the two `hello`s.

/// Where the guard sends its reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportChannel {
    /// The human-plane socket: the arbiter believes the reports.
    Human(String),
    /// The data socket: every report is a claim (fail-closed), and why.
    Data { sock: String, why: String },
}

impl ReportChannel {
    /// The socket path the guard's client dials.
    pub fn socket(&self) -> &str {
        match self {
            ReportChannel::Human(p) => p,
            ReportChannel::Data { sock, .. } => sock,
        }
    }
}

/// The client the guard reports on (arbiter-human-plane.md §5.1). On the
/// human plane it follows an arbiter restart: the human socket's name carries
/// the instance id, so a restarted arbiter listens elsewhere, and the client
/// re-learns the path from `data_sock`'s `hello` (the same checks as
/// [`choose`]'s: `channel: human`, plus the walled directory and the instance
/// id) instead of failing every report closed until the session ends. On the
/// data socket nothing is re-learned: the reports stay claims.
pub fn client_for(channel: &ReportChannel, data_sock: &str) -> mandu_arbiter::ArbiterClient {
    match channel {
        ReportChannel::Human(p) => mandu_arbiter::ArbiterClient::human_plane(p, Some(std::path::Path::new(data_sock))),
        ReportChannel::Data { sock, .. } => mandu_arbiter::ArbiterClient::new(sock),
    }
}

/// Choose the report socket at the guard's start (arbiter-human-plane.md
/// §5.2, 2026-10-17: under the same checks as a later move, [`decide_upgrade`];
/// before, the start took any socket the data socket's `hello` named once it
/// answered `channel: human`). `env_human`: an explicit
/// `MANDU_ARBITER_HUMAN_SOCK` (a test rig; the launcher never gives the agent,
/// hence the guard, one): it names the candidate in place of the data
/// socket's `hello`, and every check still applies. Anything short of all of
/// them, the data socket not answering included: the data socket, every
/// report a claim (fail-closed), and the guard keeps looking (§5.2).
pub fn choose(
    data_sock: &str,
    env_human: Option<&str>,
    walled: &[String],
    uid: u32,
    ask: impl Fn(&str) -> Asked,
    private_place: impl Fn(&str) -> Result<(), String>,
    in_tree: impl Fn(i32) -> bool,
) -> ReportChannel {
    let data = |why: String| ReportChannel::Data { sock: data_sock.to_string(), why };
    match judge(data_sock, env_human, walled, uid, ask, private_place, in_tree) {
        Judged::Human(p) => ReportChannel::Human(p),
        Judged::DataDown => data("the data socket does not answer (the arbiter is down or not started)".into()),
        Judged::Refused(why) => data(why),
    }
}

/// What §5.2's checks decided.
enum Judged {
    Human(String),
    DataDown,
    Refused(String),
}

/// The checks of [`choose`] and [`decide_upgrade`] (see the latter's list).
fn judge(
    data_sock: &str,
    env_human: Option<&str>,
    walled: &[String],
    uid: u32,
    ask: impl Fn(&str) -> Asked,
    private_place: impl Fn(&str) -> Result<(), String>,
    in_tree: impl Fn(i32) -> bool,
) -> Judged {
    let refused = |why: String| Judged::Refused(why);
    let data = match ask(data_sock) {
        Asked::Answered(a) => a,
        Asked::Unreachable => return Judged::DataDown,
        Asked::Failed(e) => return refused(format!("the data socket's hello failed ({e})")),
    };
    let named = env_human.filter(|p| !p.is_empty()).map(String::from).or_else(|| data.hello.human_sock.clone().filter(|s| !s.is_empty()));
    let Some(cand) = named else {
        return refused("the arbiter names no human-plane socket (an older arbiter, or none bound)".into());
    };
    let data_path = std::path::Path::new(data_sock);
    if std::path::Path::new(&cand) == data_path {
        return refused("the human-plane socket named is the data socket".into());
    }
    let in_walled = walled
        .iter()
        .any(|d| mandu_arbiter::client::acceptable_human_sock(&cand, &std::path::Path::new(d).join("_.sock"), data_path));
    if !in_walled {
        return refused(format!("{cand} is not a socket directly in a human-plane directory this guard walls off"));
    }
    if let Err(e) = private_place(&cand) {
        return refused(format!("{cand}: {e}"));
    }
    let human = match ask(&cand) {
        Asked::Answered(a) => a,
        Asked::Unreachable => return refused(format!("{cand} does not answer")),
        Asked::Failed(e) => return refused(format!("{cand}'s hello failed ({e})")),
    };
    match human.hello.channel.as_deref() {
        Some("human") => {}
        Some(other) => return refused(format!("{cand} answers as the {other} channel, not the human plane")),
        None => return refused(format!("{cand} does not answer as the arbiter's human plane")),
    }
    if let Some(id) = data.hello.instance_id.as_deref() {
        if human.hello.instance_id.as_deref() != Some(id) {
            return refused(format!("{cand} answers for another arbiter instance than the data socket ({id})"));
        }
    }
    let (Some(dp), Some(hp)) = (data.peer, human.peer) else {
        return refused("who listens on the arbiter's sockets could not be read (SO_PEERCRED)".into());
    };
    if dp.pid <= 0 {
        return refused("the arbiter's process is not visible here (another pid namespace)".into());
    }
    if hp.pid != dp.pid {
        return refused(format!("{cand} is served by process {}, not by the arbiter that answers the data socket ({})", hp.pid, dp.pid));
    }
    if dp.uid != uid || hp.uid != uid {
        return refused(format!("the arbiter's sockets are served by uid {}/{}, not this account's ({uid})", dp.uid, hp.uid));
    }
    if in_tree(dp.pid) {
        return refused(format!("the process serving the arbiter's sockets ({}) runs in the agent's tree", dp.pid));
    }
    Judged::Human(cand)
}

// ── moving to the human plane later (arbiter-human-plane.md §5.2) ─────────────
//
// A guard that started with no human plane (the arbiter down or restarting at
// its start, an arbiter that named none, a human socket that did not answer)
// reported on the data socket for the rest of the session before 2026-10-17,
// every report a claim. Now it keeps looking, and moves when the human plane
// is up, under the checks the start applies too ([`judge`]; the start took any
// `channel: human` answer before 2026-10-17); it moves once and never back.

/// The first wait between two looks for the human plane, and the longest.
/// While the arbiter does not answer at all the wait does not grow (a look
/// costs one failed connect), so the first look after it is up moves.
pub const UPGRADE_FIRST: std::time::Duration = std::time::Duration::from_millis(250);
pub const UPGRADE_MAX: std::time::Duration = std::time::Duration::from_secs(30);

/// One socket's answer as the guard read it, on ONE connection: its `hello`
/// and who listens there (`SO_PEERCRED`, which no answer can change).
#[derive(Debug, Clone)]
pub struct Answer {
    pub hello: mandu_arbiter::protocol::HelloResult,
    pub peer: Option<mandu_arbiter::client::PeerCred>,
}

/// What asking one socket gave.
#[derive(Debug, Clone)]
pub enum Asked {
    Answered(Answer),
    /// Nothing listens there.
    Unreachable,
    /// It answered with an error, or not in time.
    Failed(String),
}

/// What one look for the human plane decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upgrade {
    /// Move the reports to this human socket.
    To(String),
    /// The data socket does not answer: look again soon, the wait unchanged.
    Unreachable,
    /// The arbiter answered and nothing it names may be believed: stay, and
    /// wait longer. The reason, for the guard's log.
    Refused(String),
}

/// The decision of one look (PURE: the probes are injected). `data_sock`:
/// the launcher's `MANDU_ARBITER_SOCK`, the root of trust, which the agent's
/// world cannot replace (the runtime registries are on the guard's
/// write-protect list). `walled`: the human-plane directories this guard walls
/// off from the agent's world (its policy's `unixDeny`, both spellings).
/// `uid`: the guard's own. Moves only when ALL of:
///
/// 1. the data socket's `hello` names a human socket that is an absolute
///    `.sock`, not the data socket, directly in one of `walled`
///    ([`mandu_arbiter::client::acceptable_human_sock`] against that directory);
/// 2. `private_place(candidate)`: that directory is a real directory of this
///    account's, mode `0700`, and the candidate a socket of this account's;
/// 3. the candidate's own `hello` answers `channel: human`, with the instance
///    id the data socket reported (the start's check, and §5.1's);
/// 4. the process listening on the candidate is the one listening on the data
///    socket (`SO_PEERCRED`, read on the connections the two `hello`s came
///    on), of this account, visible here, and not in the guard's own tree
///    (`in_tree`): a socket a program of the agent stood up in the human
///    directory (where the write-protect list, if the launcher wrote it,
///    already refuses its bind) is served by that program, a descendant of
///    this guard, its subreaper.
pub fn decide_upgrade(
    data_sock: &str,
    walled: &[String],
    uid: u32,
    ask: impl Fn(&str) -> Asked,
    private_place: impl Fn(&str) -> Result<(), String>,
    in_tree: impl Fn(i32) -> bool,
) -> Upgrade {
    match judge(data_sock, None, walled, uid, ask, private_place, in_tree) {
        Judged::Human(p) => Upgrade::To(p),
        Judged::DataDown => Upgrade::Unreachable,
        Judged::Refused(why) => Upgrade::Refused(why),
    }
}

/// The wait before the next look, after one that decided `last`.
pub fn next_wait(wait: std::time::Duration, last: &Upgrade) -> std::time::Duration {
    match last {
        Upgrade::Refused(_) => (wait * 2).min(UPGRADE_MAX),
        _ => wait,
    }
}

/// Is `pid` `root` or one of its descendants (`ppid_of` reads a parent)? A
/// chain that cannot be read to its end counts as in the tree (fail-closed:
/// the guard then does not move). PURE.
pub fn in_tree_of(pid: i32, root: i32, ppid_of: impl Fn(i32) -> Option<i32>) -> bool {
    let mut cur = pid;
    for _ in 0..4096 {
        if cur == root {
            return true;
        }
        if cur <= 1 {
            return false;
        }
        match ppid_of(cur) {
            Some(p) => cur = p,
            None => return true,
        }
    }
    true
}

/// [`Asked`] over a real socket: one `hello`, bounded like a rediscovery's,
/// and the credentials of the listener on the connection it came on.
pub fn ask_socket(path: &str) -> Asked {
    let mut c = mandu_arbiter::ArbiterClient::new(path).with_io_timeout(Some(mandu_arbiter::client::REDISCOVER_HELLO_TIMEOUT));
    match c.hello() {
        Ok(hello) => Asked::Answered(Answer { hello, peer: c.peer_cred() }),
        Err(e) if e.is_dead_endpoint() => Asked::Unreachable,
        Err(e) => Asked::Failed(e.to_string()),
    }
}

/// The place check of [`decide_upgrade`] over the filesystem (no link
/// followed at the last component): the socket's directory a real directory
/// owned by `uid` with no group or other access, the socket a socket owned
/// by `uid`.
pub fn private_socket_place(path: &str, uid: u32) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let p = std::path::Path::new(path);
    let dir = p.parent().ok_or("no directory")?;
    let d = std::fs::symlink_metadata(dir).map_err(|e| format!("its directory cannot be read ({e})"))?;
    if !d.file_type().is_dir() {
        return Err(format!("{} is not a real directory", dir.display()));
    }
    if d.uid() != uid || d.mode() & 0o077 != 0 {
        return Err(format!("{} is not this account's private directory (uid {}, mode {:o})", dir.display(), d.uid(), d.mode() & 0o7777));
    }
    let s = std::fs::symlink_metadata(p).map_err(|e| format!("cannot be read ({e})"))?;
    if !s.file_type().is_socket() || s.uid() != uid {
        return Err("not a socket of this account's".into());
    }
    Ok(())
}

/// Move the guard's report client to the human plane (`human`): built as at
/// start ([`client_for`], so it follows a later restart and never sends a
/// report to the data socket), swapped in UNDER the shared client's mutex, so
/// a report in flight on the data socket completes there first (each is
/// bounded, !1720) and every report after it goes to the human plane. Nothing
/// sent before is sent again: what the data socket took stays a claim.
/// `announce` runs on the new client while the mutex is still held (the
/// guard's `guardAttach`, refused on the data socket at start), so it is the
/// first report the human plane gets.
pub fn switch_to_human(
    emitter: &std::sync::Mutex<mandu_arbiter::ArbiterClient>,
    human: &str,
    data_sock: &str,
    announce: impl FnOnce(&mut mandu_arbiter::ArbiterClient),
) {
    let mut client = emitter.lock().unwrap_or_else(|p| p.into_inner());
    // the guard's `MANDU_NET_GUARD_EVENTS` setting rides along (§5.3)
    let events = client.events_enabled();
    *client = client_for(&ReportChannel::Human(human.to_string()), data_sock).with_events(events);
    announce(&mut client);
}

/// The looker: on its own thread, look for the human plane (first after
/// [`UPGRADE_FIRST`], then by [`next_wait`]) until [`decide_upgrade`] moves,
/// then [`switch_to_human`] and stop. `look` is one decision (the bin passes
/// [`decide_upgrade`] over [`ask_socket`] and [`private_socket_place`]);
/// `say` gets each new refusal reason once, and the move.
pub fn spawn_upgrader(
    emitter: std::sync::Arc<std::sync::Mutex<mandu_arbiter::ArbiterClient>>,
    data_sock: String,
    look: impl Fn() -> Upgrade + Send + 'static,
    announce: impl FnOnce(&mut mandu_arbiter::ArbiterClient) + Send + 'static,
    say: impl Fn(&str) + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<String>> {
    std::thread::Builder::new().name("report-upgrade".into()).spawn(move || {
        let mut wait = UPGRADE_FIRST;
        let mut said = String::new();
        loop {
            std::thread::sleep(wait);
            let last = look();
            match &last {
                Upgrade::To(human) => {
                    switch_to_human(&emitter, human, &data_sock, announce);
                    say(&format!("the human plane is up: reporting on {human} from now on (earlier reports stay claims)"));
                    return human.clone();
                }
                Upgrade::Refused(why) if *why != said => {
                    say(&format!("still reporting on the data socket: {why}"));
                    said = why.clone();
                }
                _ => {}
            }
            wait = next_wait(wait, &last);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(env_human: Option<&str>, ask: impl Fn(&str) -> Asked) -> ReportChannel {
        choose(DATA, env_human, &[WALLED.to_string()], UID, ask, |_| Ok(()), |pid| pid != ARBITER)
    }

    fn data_why(c: &ReportChannel, needle: &str) -> bool {
        matches!(c, ReportChannel::Data { sock, why } if sock == DATA && why.contains(needle))
    }

    #[test]
    fn the_discovered_human_socket_is_chosen_once_every_check_passes() {
        let c = start(None, arbiter);
        assert_eq!(c, ReportChannel::Human(HUMAN.into()));
        assert_eq!(c.socket(), HUMAN);
    }

    #[test]
    fn an_explicit_human_socket_names_the_candidate_and_every_check_still_applies() {
        assert_eq!(start(Some(HUMAN), arbiter), ReportChannel::Human(HUMAN.into()));
        // a rig's path outside the walled directory is not the human plane
        let c = start(Some("/x/h.sock"), |p| if p == DATA { arbiter(p) } else { panic!("{p} must not be asked") });
        assert!(data_why(&c, "not a socket directly in a human-plane directory"), "{c:?}");
        // an empty value is no value
        assert_eq!(start(Some(""), arbiter).socket(), HUMAN);
    }

    #[test]
    fn no_human_socket_reports_on_the_data_socket_as_claims() {
        let none = |p: &str| if p == DATA { answered(None, "data", "i2", ARBITER, UID) } else { panic!("nothing to ask at {p}") };
        assert!(data_why(&start(None, none), "no human-plane socket"));
        let empty = |p: &str| if p == DATA { answered(Some(""), "data", "i2", ARBITER, UID) } else { panic!("nothing to ask at {p}") };
        assert!(data_why(&start(None, empty), "no human-plane socket"));
        // the arbiter not up yet at the guard's start
        assert!(data_why(&start(None, |_| Asked::Unreachable), "does not answer"));
        // no walled directory (an `off` launch, a rig without unixDeny): no human plane is believed
        let c = choose(DATA, None, &[], UID, arbiter, |_| Ok(()), |_| false);
        assert!(data_why(&c, "not a socket directly in"));
    }

    /// arbiter-human-plane.md §5.2 (2026-10-17): the start refuses what a later
    /// move refuses. Before, it took any socket the data socket named (or the
    /// rig's variable) once that answered `channel: human`.
    #[test]
    fn at_start_a_human_socket_the_agent_could_serve_or_name_is_refused() {
        // the data socket spelled as the human one
        assert!(data_why(&start(Some(DATA), arbiter), "is the data socket"));
        // answers as data, or not at all
        let as_data = |p: &str| if p == HUMAN { answered(Some(HUMAN), "data", "i2", ARBITER, UID) } else { arbiter(p) };
        assert!(data_why(&start(None, as_data), "data channel"));
        let silent = |p: &str| if p == HUMAN { Asked::Unreachable } else { arbiter(p) };
        assert!(data_why(&start(None, silent), "does not answer"));
        // a socket another process serves at the named path, answering every word as the arbiter
        let planted = |p: &str| if p == HUMAN { answered(Some(HUMAN), "human", "i2", 777, UID) } else { arbiter(p) };
        assert!(data_why(&start(None, planted), "served by process 777"));
        // both sockets served by a program of the guard's tree
        let fake_both = |p: &str| if p == DATA { answered(Some(HUMAN), "data", "i2", 777, UID) } else { answered(Some(HUMAN), "human", "i2", 777, UID) };
        let c = choose(DATA, None, &[WALLED.into()], UID, fake_both, |_| Ok(()), |pid| pid == 777);
        assert!(data_why(&c, "runs in the agent's tree"));
        // an arbiter in another pid namespace: a claims guard (it keeps looking)
        let hidden = |p: &str| if p == DATA { answered(Some(HUMAN), "data", "i2", 0, UID) } else { answered(Some(HUMAN), "human", "i2", 0, UID) };
        assert!(data_why(&start(None, hidden), "another pid namespace"));
        // a directory that is not this account's private one
        let c = choose(DATA, None, &[WALLED.into()], UID, arbiter, |_| Err("mode 755".into()), |_| false);
        assert!(data_why(&c, "mode 755"));
    }

    /// arbiter-human-plane.md §5.1: the arbiter restarted and its human socket
    /// moved. The guard's report client re-learns it from the data socket's
    /// `hello` and its reports reach the new human plane; the data socket gets
    /// only the `hello`.
    #[test]
    fn the_report_client_follows_a_restarted_arbiters_human_socket() {
        use mandu_arbiter::mock::{op_handler, MockArbiter};
        let new_human = MockArbiter::start(op_handler(|op, _| match op {
            "hello" => Ok(serde_json::json!({ "channel": "human", "instanceId": "i2" })),
            "ping" => Ok(serde_json::json!({ "pong": true, "protocolVersion": 1 })),
            other => Err(format!("unexpected {other}")),
        }));
        let new_path = new_human.socket_path.to_string_lossy().to_string();
        let data = MockArbiter::start(op_handler(move |op, _| match op {
            "hello" => Ok(serde_json::json!({ "humanSock": new_path.clone(), "channel": "data", "instanceId": "i2" })),
            other => Err(format!("the data socket must not get {other}")),
        }));
        let data_sock = data.socket_path.to_string_lossy().to_string();
        let stale = new_human.socket_path.with_file_name(format!("mandu-gone-report-{}.sock", std::process::id()));
        let mut c = client_for(&ReportChannel::Human(stale.to_string_lossy().into()), &data_sock);
        assert!(c.ping().unwrap().pong);
        assert_eq!(c.socket_path(), new_human.socket_path.as_path());
        assert_eq!(data.request_count(), 1, "one hello, nothing else");
        // On the data socket nothing is re-learned.
        let c = client_for(&ReportChannel::Data { sock: data_sock.clone(), why: "x".into() }, &data_sock);
        assert_eq!(c.socket_path(), data.socket_path.as_path());
    }

    // ── §5.2: a guard that started on the data socket moves later ─────────────

    use mandu_arbiter::client::PeerCred;
    use mandu_arbiter::protocol::HelloResult;

    const DATA: &str = "/run/mandu/current/arbiter.sock";
    const WALLED: &str = "/run/mandu/human";
    const HUMAN: &str = "/run/mandu/human/i2.sock";
    const UID: u32 = 1000;
    const ARBITER: i32 = 4242;

    fn answered(human_sock: Option<&str>, channel: &str, id: &str, pid: i32, uid: u32) -> Asked {
        Asked::Answered(Answer {
            hello: HelloResult { human_sock: human_sock.map(String::from), channel: Some(channel.into()), instance_id: Some(id.into()) },
            peer: Some(PeerCred { pid, uid }),
        })
    }

    /// The real arbiter: both sockets served by one process outside the tree.
    fn arbiter(p: &str) -> Asked {
        match p {
            DATA => answered(Some(HUMAN), "data", "i2", ARBITER, UID),
            HUMAN => answered(Some(HUMAN), "human", "i2", ARBITER, UID),
            _ => Asked::Unreachable,
        }
    }

    fn decide(ask: impl Fn(&str) -> Asked) -> Upgrade {
        decide_upgrade(DATA, &[WALLED.to_string()], UID, ask, |_| Ok(()), |pid| pid != ARBITER)
    }

    fn refused_with(u: &Upgrade, needle: &str) -> bool {
        matches!(u, Upgrade::Refused(why) if why.contains(needle))
    }

    #[test]
    fn a_late_human_plane_is_moved_to_when_the_data_sockets_arbiter_serves_it() {
        assert_eq!(decide(arbiter), Upgrade::To(HUMAN.into()));
        // the walled directory in its other spelling (unixDeny carries both)
        let u = decide_upgrade(DATA, &["/srv/x/human".into(), WALLED.into()], UID, arbiter, |_| Ok(()), |_| false);
        assert_eq!(u, Upgrade::To(HUMAN.into()));
        // an arbiter that predates the instance id: the other checks decide
        let no_id = |p: &str| match arbiter(p) {
            Asked::Answered(mut a) => {
                a.hello.instance_id = None;
                Asked::Answered(a)
            }
            o => o,
        };
        assert_eq!(decide(no_id), Upgrade::To(HUMAN.into()));
    }

    #[test]
    fn while_the_arbiter_is_down_or_names_nothing_the_guard_stays() {
        assert_eq!(decide(|_| Asked::Unreachable), Upgrade::Unreachable);
        assert!(refused_with(&decide(|_| Asked::Failed("timed out".into())), "hello failed"));
        let none = |p: &str| if p == DATA { answered(None, "data", "i2", ARBITER, UID) } else { panic!("nothing to ask at {p}") };
        assert!(refused_with(&decide(none), "names no human-plane socket"));
        let empty = |p: &str| if p == DATA { answered(Some(""), "data", "i2", ARBITER, UID) } else { panic!("nothing to ask at {p}") };
        assert!(refused_with(&decide(empty), "names no human-plane socket"));
        // named, but its socket is not up yet
        let not_yet = |p: &str| if p == DATA { arbiter(p) } else { Asked::Unreachable };
        assert!(refused_with(&decide(not_yet), "does not answer"));
    }

    /// The impersonations the move must refuse (the data socket is the root
    /// of trust: the agent's world cannot replace it).
    #[test]
    fn a_human_socket_the_agent_could_serve_or_name_is_never_moved_to() {
        // named outside every walled directory, or the data socket itself
        for named in ["/tmp/fake.sock", DATA, "/run/mandu/human/../current/arbiter.sock", "/run/mandu/human/sub/x.sock", "human/i2.sock", "/run/mandu/human/i2.txt"] {
            let ask = |p: &str| if p == DATA { answered(Some(named), "data", "i2", ARBITER, UID) } else { panic!("{named} must not be asked") };
            let u = decide(ask);
            assert!(refused_with(&u, "not a socket directly in a human-plane directory") || refused_with(&u, "is the data socket"), "{named}: {u:?}");
        }
        // no walled directory at all: nothing is believed
        let u = decide_upgrade(DATA, &[], UID, arbiter, |_| Ok(()), |_| false);
        assert!(refused_with(&u, "not a socket directly in"));
        // the directory or the socket is not this account's private one
        let u = decide_upgrade(DATA, &[WALLED.into()], UID, arbiter, |_| Err("mode 755".into()), |_| false);
        assert!(refused_with(&u, "mode 755"));
        // it answers as the data channel, or not as any channel, or for another instance
        let as_data = |p: &str| if p == HUMAN { answered(Some(HUMAN), "data", "i2", ARBITER, UID) } else { arbiter(p) };
        assert!(refused_with(&decide(as_data), "data channel"));
        let no_channel = |p: &str| match arbiter(p) {
            Asked::Answered(mut a) if p == HUMAN => {
                a.hello.channel = None;
                Asked::Answered(a)
            }
            o => o,
        };
        assert!(refused_with(&decide(no_channel), "does not answer as the arbiter's human plane"));
        let other_instance = |p: &str| if p == HUMAN { answered(Some(HUMAN), "human", "i1", ARBITER, UID) } else { arbiter(p) };
        assert!(refused_with(&decide(other_instance), "another arbiter instance"));
        // a socket the agent stood up at the named path (a launch whose
        // write-protect list does not refuse the bind), answering every word
        // as the arbiter would: another process serves it
        let planted = |p: &str| if p == HUMAN { answered(Some(HUMAN), "human", "i2", 777, UID) } else { arbiter(p) };
        assert!(refused_with(&decide(planted), "served by process 777, not by the arbiter"));
        // both sockets served by one program of the agent's tree
        let fake_both = |p: &str| match p {
            DATA => answered(Some(HUMAN), "data", "i2", 777, UID),
            _ => answered(Some(HUMAN), "human", "i2", 777, UID),
        };
        let u = decide_upgrade(DATA, &[WALLED.into()], UID, fake_both, |_| Ok(()), |pid| pid == 777);
        assert!(refused_with(&u, "runs in the agent's tree"));
        // another account's process, an arbiter in another pid namespace, credentials unread
        let other_uid = |p: &str| if p == HUMAN { answered(Some(HUMAN), "human", "i2", ARBITER, 0) } else { arbiter(p) };
        assert!(refused_with(&decide(other_uid), "not this account's"));
        let hidden = |p: &str| match p {
            DATA => answered(Some(HUMAN), "data", "i2", 0, UID),
            _ => answered(Some(HUMAN), "human", "i2", 0, UID),
        };
        assert!(refused_with(&decide(hidden), "another pid namespace"));
        let unread = |p: &str| match arbiter(p) {
            Asked::Answered(mut a) if p == HUMAN => {
                a.peer = None;
                Asked::Answered(a)
            }
            o => o,
        };
        assert!(refused_with(&decide(unread), "SO_PEERCRED"));
    }

    #[test]
    fn the_wait_grows_only_while_the_arbiter_names_nothing_usable() {
        use std::time::Duration;
        assert_eq!(next_wait(UPGRADE_FIRST, &Upgrade::Unreachable), UPGRADE_FIRST, "the arbiter down: the next look comes as soon");
        assert_eq!(next_wait(UPGRADE_FIRST, &Upgrade::Refused("x".into())), UPGRADE_FIRST * 2);
        assert_eq!(next_wait(Duration::from_secs(20), &Upgrade::Refused("x".into())), UPGRADE_MAX);
        assert_eq!(next_wait(UPGRADE_MAX, &Upgrade::Unreachable), UPGRADE_MAX);
    }

    #[test]
    fn a_process_is_in_the_tree_when_its_chain_reaches_the_guard_or_cannot_be_read() {
        // 30 → 20 → 10 (the guard) → 1
        let ppid = |p: i32| match p {
            30 => Some(20),
            20 => Some(10),
            10 => Some(1),
            50 => Some(1),
            _ => None,
        };
        assert!(in_tree_of(30, 10, ppid));
        assert!(in_tree_of(10, 10, ppid), "the guard itself");
        assert!(!in_tree_of(50, 10, ppid), "a process under init, beside the guard");
        assert!(!in_tree_of(1, 10, ppid));
        assert!(in_tree_of(99, 10, ppid), "a chain that cannot be read: in the tree (fail-closed)");
        // the real /proc: this test process is not in a child's tree; it is in its own
        let me = std::process::id() as i32;
        assert!(in_tree_of(me, me, crate::secret_open::parent_pid_of));
        let mut child = std::process::Command::new("sleep").arg("5").spawn().expect("sleep");
        assert!(!in_tree_of(me, child.id() as i32, crate::secret_open::parent_pid_of));
        assert!(in_tree_of(child.id() as i32, me, crate::secret_open::parent_pid_of));
        let _ = child.kill();
        let _ = child.wait();
    }

    /// A private directory for a test's human socket (mode 0700), removed on drop.
    struct Walled(std::path::PathBuf);
    impl Walled {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let d = std::env::temp_dir().join(format!("mdu-hp-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            Walled(d)
        }
        fn sock(&self, name: &str) -> String {
            self.0.join(name).to_string_lossy().into_owned()
        }
    }
    impl Drop for Walled {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn uid() -> u32 {
        // SAFETY: geteuid has no failure mode.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn the_place_check_wants_this_accounts_private_directory_and_a_real_socket() {
        use std::os::unix::fs::PermissionsExt;
        let w = Walled::new("place");
        let sock = w.sock("h.sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert_eq!(private_socket_place(&sock, uid()), Ok(()));
        assert!(private_socket_place(&sock, uid() + 1).is_err(), "another account's");
        let file = w.sock("f.sock");
        std::fs::write(&file, "").unwrap();
        assert!(private_socket_place(&file, uid()).unwrap_err().contains("not a socket"));
        assert!(private_socket_place(&w.sock("none.sock"), uid()).is_err());
        // a symlink at the directory's place
        let link = w.0.with_extension("lnk");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&w.0, &link).unwrap();
        let via = link.join("h.sock").to_string_lossy().into_owned();
        assert!(private_socket_place(&via, uid()).unwrap_err().contains("not a real directory"));
        let _ = std::fs::remove_file(&link);
        // group or other access
        std::fs::set_permissions(&w.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_socket_place(&sock, uid()).unwrap_err().contains("private directory"));
    }

    fn data_mock(human: String, seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>) -> mandu_arbiter::mock::MockArbiter {
        mandu_arbiter::mock::MockArbiter::start(mandu_arbiter::mock::op_handler(move |op, _| {
            seen.lock().unwrap().push(op.to_string());
            match op {
                "hello" => Ok(serde_json::json!({ "humanSock": human.clone(), "channel": "data", "instanceId": "i2" })),
                _ => Ok(serde_json::json!({ "pong": true, "protocolVersion": 1 })),
            }
        }))
    }

    fn human_mock(at: &str, seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>) -> mandu_arbiter::mock::MockArbiter {
        mandu_arbiter::mock::MockArbiter::start_at(
            at,
            mandu_arbiter::mock::op_handler(move |op, _| {
                seen.lock().unwrap().push(op.to_string());
                match op {
                    "hello" => Ok(serde_json::json!({ "channel": "human", "instanceId": "i2" })),
                    "guardAttach" => Ok(serde_json::json!({ "attached": true })),
                    _ => Ok(serde_json::json!({ "pong": true, "protocolVersion": 1 })),
                }
            }),
        )
    }

    /// The switch, under the shared client's mutex: a report before it went
    /// to the data socket (and stays there: nothing is sent again), the
    /// announcement is the human plane's first report, and every report after
    /// it goes there; a report in flight holds the switch until it is done.
    #[test]
    fn the_switch_happens_under_the_shared_mutex_and_replays_nothing() {
        use std::sync::{Arc, Mutex};
        let w = Walled::new("switch");
        let human_path = w.sock("i2.sock");
        let (data_seen, human_seen) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
        let data = data_mock(human_path.clone(), data_seen.clone());
        let _human = human_mock(&human_path, human_seen.clone());
        let data_sock = data.socket_path.to_string_lossy().into_owned();
        // a guard with MANDU_NET_GUARD_EVENTS=0 (§5.3): the setting survives the move
        let emitter = Arc::new(Mutex::new(client_for(&ReportChannel::Data { sock: data_sock.clone(), why: "x".into() }, &data_sock).with_events(false)));
        assert!(emitter.lock().unwrap().ping().unwrap().pong, "a report while on the data socket");

        // a report in flight (the lock held) holds the switch
        let held = emitter.lock().unwrap();
        let announced = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (e2, d2, h2, a2) = (emitter.clone(), data_sock.clone(), human_path.clone(), announced.clone());
        let t = std::thread::spawn(move || {
            switch_to_human(&e2, &h2, &d2, |c| {
                assert!(c.guard_attach(&mandu_arbiter::protocol::GuardAttachArgs { session_key: "s".into() }).unwrap().attached);
                a2.store(true, std::sync::atomic::Ordering::SeqCst);
            })
        });
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(!announced.load(std::sync::atomic::Ordering::SeqCst), "the switch waits for the report in flight");
        drop(held);
        t.join().unwrap();
        assert!(announced.load(std::sync::atomic::Ordering::SeqCst));

        assert!(emitter.lock().unwrap().ping().unwrap().pong, "a report after the switch");
        assert_eq!(emitter.lock().unwrap().socket_path(), std::path::Path::new(&human_path));
        assert!(!emitter.lock().unwrap().events_enabled(), "events stay off on the human plane");
        assert_eq!(*data_seen.lock().unwrap(), vec!["ping".to_string()], "the data socket got the one report before, and nothing after");
        assert_eq!(*human_seen.lock().unwrap(), vec!["guardAttach".to_string(), "ping".to_string()], "nothing sent before the switch is sent again");
    }

    /// The looker over real sockets: the data socket's arbiter serves the
    /// human socket it names (one process: this test's), outside the guard's
    /// tree (the guard: a child of this test), so it moves, once.
    #[test]
    fn the_looker_moves_once_the_human_plane_is_up_and_never_back() {
        use std::sync::{Arc, Mutex};
        let w = Walled::new("looker");
        let human_path = w.sock("i2.sock");
        let (data_seen, human_seen) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
        let data = data_mock(human_path.clone(), data_seen.clone());
        let data_sock = data.socket_path.to_string_lossy().into_owned();
        let walled = vec![w.0.to_string_lossy().into_owned()];
        let mut guard_proc = std::process::Command::new("sleep").arg("30").spawn().expect("sleep");
        let guard_pid = guard_proc.id() as i32;
        let (ds, wl) = (data_sock.clone(), walled.clone());
        let look = move || decide_upgrade(&ds, &wl, uid(), ask_socket, |p| private_socket_place(p, uid()), |pid| in_tree_of(pid, guard_pid, crate::secret_open::parent_pid_of));

        // the human plane is not up yet: the look refuses, the guard stays
        assert!(matches!(look(), Upgrade::Refused(why) if why.contains("cannot be read")));
        let emitter = Arc::new(Mutex::new(client_for(&ReportChannel::Data { sock: data_sock.clone(), why: "x".into() }, &data_sock)));
        let _human = human_mock(&human_path, human_seen.clone());
        let said = Arc::new(Mutex::new(Vec::<String>::new()));
        let s2 = said.clone();
        let h = spawn_upgrader(emitter.clone(), data_sock.clone(), look, |c| { let _ = c.guard_attach(&mandu_arbiter::protocol::GuardAttachArgs { session_key: "s".into() }); }, move |m| s2.lock().unwrap().push(m.to_string())).unwrap();
        assert_eq!(h.join().unwrap(), human_path);
        assert_eq!(emitter.lock().unwrap().socket_path(), std::path::Path::new(&human_path));
        assert!(said.lock().unwrap().iter().any(|m| m.contains("the human plane is up")));
        assert_eq!(human_seen.lock().unwrap().iter().filter(|o| *o == "guardAttach").count(), 1);
        let before = data_seen.lock().unwrap().len();
        assert!(emitter.lock().unwrap().ping().unwrap().pong);
        assert_eq!(data_seen.lock().unwrap().len(), before, "after the move no report reaches the data socket");
        // (the mock serves one connection at a time: close the guard's)
        drop(emitter);

        // the same sockets judged from a guard whose tree holds this process:
        // a program of the agent serving both is refused
        let me = std::process::id() as i32;
        let (ds, wl) = (data_sock.clone(), walled.clone());
        let u = decide_upgrade(&ds, &wl, uid(), ask_socket, |p| private_socket_place(p, uid()), |pid| in_tree_of(pid, me, crate::secret_open::parent_pid_of));
        assert!(matches!(&u, Upgrade::Refused(why) if why.contains("agent's tree")), "{u:?}");
        let _ = guard_proc.kill();
        let _ = guard_proc.wait();
    }
}
