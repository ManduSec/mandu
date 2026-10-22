//! cgroup_guard — the guard keeps its own cgroup out of the agent's reach
//! (rootless-confinement-ubuntu-2404.md §12.2, "The cgroup").
//!
//! The launcher runs the guard and the agent in one `systemd-run --user
//! --scope`, under `user@UID.service/app.slice`, which the user owns
//! (nsdelegate delegation): any process of the uid may make a child cgroup,
//! move the guard into it, and freeze, throttle or kill the scope, the child
//! or `app.slice`. A frozen guard does not fail closed (the tree's trapped
//! calls wait): no leak, but the session hangs. Every write to a cgroup file
//! starts with an open the guard performs, so the guard refuses (`EACCES`),
//! for a WRITE-CAPABLE open of a file on cgroup2 (statfs magic
//! `0x63677270`, read from the descriptor opened, never from a path):
//!
//!   1. any file of the guard's own cgroup or of a cgroup above it
//!      (`cgroup.freeze`, `cgroup.kill`, `cpu.max`, `memory.max`,
//!      `cgroup.procs`, `cgroup.subtree_control`, …);
//!   2. `cgroup.procs` / `cgroup.threads` of any other cgroup a move could
//!      take the guard into: cgroup v2 lets a writer move a task from cgroup S
//!      to D when it may write D's `cgroup.procs` (the open) and that of the
//!      COMMON ANCESTOR of S and D (a permission check at the write, not an
//!      open). With S the guard's cgroup, the common ancestor is the first
//!      cgroup above D that is also the guard's or above it; the open is
//!      allowed only when that ancestor's `cgroup.procs` is NOT writable to
//!      the opener (the guard under a root-owned SSH `session-N.scope`: its
//!      common ancestor with any user cgroup is root's), so no move can
//!      reach the guard.
//!
//! Fail-closed: a guard that cannot find its own cgroup (no `0::` line, no
//! cgroup2 mount that holds it, its own pid not listed there), or cannot
//! place the target (its directory not reachable from the guard's view by
//! the path its descriptor names, checked by identity), or whose target
//! shares no cgroup with its own in that view (the target could be above
//! what the view shows), refuses the open. The cost: a tool in the session
//! that moves processes between cgroups (podman / crun placing a container
//! in a cgroup of its own) or writes the session's own cgroup files is
//! refused while the guard's cgroup is the user's.
//!
//! Pure (no privilege): the flag and file-system tests, the `/proc/self/
//! cgroup` and `mountinfo` parsing, the permission rule, `decide`. The
//! enactment (descriptors, `fstatfs`, the `..` walks) is
//! `cgroup_guard_kernel`, behind the `kernel` feature. `Mandu-new`.

use std::path::PathBuf;

/// `CGROUP2_SUPER_MAGIC` (linux/magic.h).
pub const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

/// A file's identity: (`st_dev`, `st_ino`). On cgroup2 the inode number is
/// the kernfs node id, unique in the hierarchy and the same under every
/// mount of it.
pub type NodeId = (u64, u64);

/// Does an open with these flags (or a descriptor with these status flags)
/// get a descriptor that can write? `O_PATH` cannot; anything but a plain
/// `O_RDONLY` access mode can (the unused mode 3 included: fail-closed).
pub fn write_capable(flags: i32) -> bool {
    crate::secret_open::holds_for_writing(flags)
}

/// Is this statfs `f_type` cgroup2's?
pub fn is_cgroup2(f_type: i64) -> bool {
    f_type == CGROUP2_SUPER_MAGIC
}

/// Is `leaf` a file whose write moves tasks into its cgroup?
pub fn moves_tasks(leaf: &str) -> bool {
    leaf == "cgroup.procs" || leaf == "cgroup.threads"
}

/// The guard's cgroup v2 path from a `/proc/self/cgroup` text: the `0::`
/// line's path, relative to the reader's cgroup namespace root. None (fail
/// closed) without one, for a relative or `(deleted)` path, or for one that
/// climbs (`/..`: the cgroup is outside the reader's namespace).
pub fn own_cgroup_path(proc_self_cgroup: &str) -> Option<String> {
    let path = proc_self_cgroup.lines().find_map(|l| l.strip_prefix("0::"))?.trim_end();
    if !path.starts_with('/') || path.ends_with(" (deleted)") || path.split('/').any(|c| c == "..") {
        return None;
    }
    Some(path.to_string())
}

/// A cgroup2 mount of the reader's view: the hierarchy directory it shows at
/// its mount point (`root`, relative to the reader's cgroup namespace root)
/// and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cgroup2Mount {
    pub root: String,
    pub mount_point: String,
}

/// The cgroup2 mounts of a `/proc/self/mountinfo` text, in its order.
pub fn cgroup2_mounts(mountinfo: &str) -> Vec<Cgroup2Mount> {
    mountinfo
        .lines()
        .filter_map(|line| {
            let (head, tail) = line.split_once(" - ")?;
            if tail.split(' ').next()? != "cgroup2" {
                return None;
            }
            let mut h = head.split(' ');
            let root = crate::local_exits::unescape(h.nth(3)?);
            let mount_point = crate::local_exits::unescape(h.next()?);
            Some(Cgroup2Mount { root, mount_point })
        })
        .collect()
}

/// Where the guard's cgroup `own` (from `own_cgroup_path`) shows in the
/// reader's view: one directory per cgroup2 mount that holds it, the mount
/// with the shortest root first (it shows the most cgroups above the
/// guard's). A mount whose root climbs out of the reader's namespace, or
/// does not hold `own`, is left out. Each candidate is still to be checked
/// (its `cgroup.procs` lists the guard).
pub fn own_cgroup_dirs(own: &str, mounts: &[Cgroup2Mount]) -> Vec<PathBuf> {
    let mut found: Vec<(usize, PathBuf)> = mounts
        .iter()
        .filter(|m| m.root.starts_with('/') && !m.root.split('/').any(|c| c == "..") && m.mount_point.starts_with('/'))
        .filter_map(|m| {
            let root = m.root.trim_end_matches('/');
            let rest = if root.is_empty() {
                own
            } else if own == root {
                ""
            } else {
                own.strip_prefix(root).filter(|r| r.starts_with('/'))?
            };
            let mut dir = PathBuf::from(&m.mount_point);
            for c in rest.split('/').filter(|c| !c.is_empty()) {
                dir.push(c);
            }
            Some((root.len(), dir))
        })
        .collect();
    found.sort_by_key(|(len, _)| *len);
    found.into_iter().map(|(_, d)| d).collect()
}

/// Does a cgroup `pids` text (a `cgroup.procs` read) list `pid`?
pub fn lists_pid(procs: &str, pid: i32) -> bool {
    procs.lines().any(|l| l.trim().parse::<i32>().ok() == Some(pid))
}

/// May a process with effective uid `euid` and groups `groups` write a file
/// of `mode` owned by `uid`:`gid`? kernfs has no ACLs, so the mode bits
/// decide; root may write anything. Pure.
pub fn may_write(mode: u32, uid: u32, gid: u32, euid: u32, groups: &[u32]) -> bool {
    if euid == 0 {
        return true;
    }
    if uid == euid {
        return mode & 0o200 != 0;
    }
    if groups.contains(&gid) {
        return mode & 0o020 != 0;
    }
    mode & 0o002 != 0
}

/// Why a write-capable cgroup2 open is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The guard could not find its own cgroup.
    OwnUnknown,
    /// The opened file's cgroup could not be placed in the guard's view.
    TargetUnknown,
    /// A file of the guard's own cgroup or of one above it.
    OwnOrAbove,
    /// A task-moving file whose move could reach the guard.
    MoveReachesGuard,
    /// A file whose cgroup shares no cgroup the guard can see with the
    /// guard's (it could be above the guard's view), or a task-moving file
    /// whose common ancestor's permission is unknown.
    Unplaced,
}

impl Refusal {
    /// The reason the refusal event and the debug line carry.
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::OwnUnknown => "a cgroup file opened for writing while the guard cannot tell its own cgroup",
            Refusal::TargetUnknown => "a cgroup file opened for writing whose cgroup the guard cannot place",
            Refusal::OwnOrAbove => "a file of the guard's own cgroup or one above it, opened for writing",
            Refusal::MoveReachesGuard => "a cgroup's task list, opened for writing, through which the guard could be moved",
            Refusal::Unplaced => "a cgroup file opened for writing that the guard cannot relate to its own cgroup",
        }
    }
}

/// What the guard knows about one write-capable cgroup2 open.
#[derive(Debug, Clone, Copy)]
pub struct WriteFacts<'a> {
    /// The opened file's name.
    pub leaf: &'a str,
    /// The file's cgroup and every cgroup above it the guard's view shows,
    /// nearest first; None when it could not be placed.
    pub target: Option<&'a [NodeId]>,
    /// The guard's cgroup and every cgroup above it, nearest first; None
    /// when it could not be found.
    pub own: Option<&'a [NodeId]>,
}

/// The verdict on a write-capable open of a cgroup2 file. `writable(i)`
/// says whether the `cgroup.procs` of `target[i]` is writable to the opener
/// (None: unknown), asked only for a task-moving file's common ancestor.
/// Pure.
pub fn decide(f: WriteFacts<'_>, writable: impl FnOnce(usize) -> Option<bool>) -> Result<(), Refusal> {
    let own = match f.own {
        Some(o) if !o.is_empty() => o,
        _ => return Err(Refusal::OwnUnknown),
    };
    let target = match f.target {
        Some(t) if !t.is_empty() => t,
        _ => return Err(Refusal::TargetUnknown),
    };
    if own.contains(&target[0]) {
        return Err(Refusal::OwnOrAbove);
    }
    // The first cgroup above the target's that is also the guard's or above
    // it: the common ancestor. None: the two views share nothing, and the
    // target could be a cgroup above what the guard's view shows.
    let Some(common) = target.iter().position(|n| own.contains(n)) else {
        return Err(Refusal::Unplaced);
    };
    if !moves_tasks(f.leaf) {
        return Ok(());
    }
    match writable(common) {
        Some(false) => Ok(()),
        Some(true) => Err(Refusal::MoveReachesGuard),
        None => Err(Refusal::Unplaced),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: u64 = 0x99;
    // /, user.slice, user-1000.slice, user@1000.service, app.slice, run-x.scope
    const ROOT: NodeId = (D, 1);
    const USER_SLICE: NodeId = (D, 2);
    const USER_1000: NodeId = (D, 3);
    const MANAGER: NodeId = (D, 4);
    const APP: NodeId = (D, 5);
    const SCOPE: NodeId = (D, 6);
    const OWN: &[NodeId] = &[SCOPE, APP, MANAGER, USER_1000, USER_SLICE, ROOT];

    fn facts<'a>(leaf: &'a str, target: &'a [NodeId]) -> WriteFacts<'a> {
        WriteFacts { leaf, target: Some(target), own: Some(OWN) }
    }

    #[test]
    fn write_capable_means_any_write_mode_and_never_o_path() {
        assert!(!write_capable(libc::O_RDONLY));
        assert!(!write_capable(libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK));
        assert!(write_capable(libc::O_WRONLY));
        assert!(write_capable(libc::O_RDWR | libc::O_CLOEXEC));
        assert!(write_capable(libc::O_ACCMODE), "the unused mode 3 counts as writing");
        assert!(!write_capable(libc::O_PATH | libc::O_WRONLY));
    }

    #[test]
    fn only_cgroup2_is_judged() {
        assert!(is_cgroup2(0x6367_7270));
        assert!(!is_cgroup2(0x0027_e0eb), "cgroup v1 is not delegated to users");
        assert!(!is_cgroup2(0x6265_6572), "sysfs");
        assert!(!is_cgroup2(0xEF53), "ext4");
    }

    #[test]
    fn the_task_moving_files() {
        assert!(moves_tasks("cgroup.procs"));
        assert!(moves_tasks("cgroup.threads"));
        for leaf in ["cgroup.freeze", "cgroup.kill", "cpu.max", "tasks", "cgroup.procs2", "cgroup.subtree_control"] {
            assert!(!moves_tasks(leaf), "{leaf}");
        }
    }

    #[test]
    fn the_own_cgroup_is_the_v2_line_and_fails_closed() {
        let text = "12:pids:/user.slice\n0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-u7.scope\n";
        assert_eq!(own_cgroup_path(text).as_deref(), Some("/user.slice/user-1000.slice/user@1000.service/app.slice/run-u7.scope"));
        assert_eq!(own_cgroup_path("0::/\n").as_deref(), Some("/"));
        assert_eq!(own_cgroup_path("12:pids:/user.slice\n"), None, "v1 only: unknown");
        assert_eq!(own_cgroup_path(""), None);
        assert_eq!(own_cgroup_path("0::/a/b (deleted)\n"), None);
        assert_eq!(own_cgroup_path("0::/../../x\n"), None, "outside the reader's namespace");
        assert_eq!(own_cgroup_path("0::relative\n"), None);
    }

    #[test]
    fn mountinfo_gives_the_cgroup2_mounts_unescaped() {
        let text = "\
29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
35 24 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
36 24 0:31 / /sys/fs/cgroup/pids rw shared:10 - cgroup cgroup rw,pids
90 29 0:30 /user.slice /mnt/my\\040cg rw - cgroup2 cgroup2 rw
";
        assert_eq!(
            cgroup2_mounts(text),
            vec![
                Cgroup2Mount { root: "/".into(), mount_point: "/sys/fs/cgroup".into() },
                Cgroup2Mount { root: "/user.slice".into(), mount_point: "/mnt/my cg".into() },
            ]
        );
        assert!(cgroup2_mounts("garbage\n").is_empty());
    }

    #[test]
    fn the_own_cgroup_shows_under_each_mount_that_holds_it_shortest_root_first() {
        let own = "/user.slice/user-1000.slice/run.scope";
        let mounts = vec![
            Cgroup2Mount { root: "/user.slice".into(), mount_point: "/mnt/u".into() },
            Cgroup2Mount { root: "/".into(), mount_point: "/sys/fs/cgroup".into() },
            Cgroup2Mount { root: "/system.slice".into(), mount_point: "/mnt/s".into() },
            Cgroup2Mount { root: "/user.slice/user-1000.slice/run.scope".into(), mount_point: "/mnt/self".into() },
            Cgroup2Mount { root: "/user.slice/user-1".into(), mount_point: "/mnt/prefix-not-parent".into() },
            Cgroup2Mount { root: "/../x".into(), mount_point: "/mnt/above".into() },
        ];
        assert_eq!(
            own_cgroup_dirs(own, &mounts),
            vec![
                PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/run.scope"),
                PathBuf::from("/mnt/u/user-1000.slice/run.scope"),
                PathBuf::from("/mnt/self"),
            ]
        );
        assert_eq!(own_cgroup_dirs("/", &mounts[1..2]), vec![PathBuf::from("/sys/fs/cgroup")]);
        assert!(own_cgroup_dirs(own, &[]).is_empty());
    }

    #[test]
    fn a_pid_list_is_matched_by_whole_numbers() {
        assert!(lists_pid("12\n345\n6\n", 345));
        assert!(!lists_pid("12\n3456\n", 345));
        assert!(!lists_pid("", 1));
    }

    #[test]
    fn write_permission_follows_the_mode_bits() {
        assert!(may_write(0o644, 1000, 1000, 1000, &[1000]), "the owner");
        assert!(!may_write(0o444, 1000, 1000, 1000, &[1000]), "the owner without the bit");
        assert!(!may_write(0o644, 0, 0, 1000, &[1000]), "root's file");
        assert!(may_write(0o664, 0, 50, 1000, &[50]), "a group the writer is in");
        assert!(!may_write(0o664, 0, 50, 1000, &[1000]), "a group the writer is not in");
        assert!(may_write(0o646, 0, 0, 1000, &[]), "world-writable");
        assert!(!may_write(0o466, 1000, 1000, 1000, &[1000]), "the owner class decides for the owner");
        assert!(may_write(0o444, 7, 7, 0, &[]), "root");
    }

    #[test]
    fn any_file_of_the_own_cgroup_or_above_is_refused() {
        for leaf in ["cgroup.freeze", "cgroup.kill", "cpu.max", "memory.max", "pids.max", "cgroup.procs", "cgroup.threads", "cgroup.subtree_control"] {
            for dir in OWN {
                let chain: Vec<NodeId> = OWN.iter().skip_while(|n| *n != dir).copied().collect();
                assert_eq!(decide(facts(leaf, &chain), |_| Some(false)), Err(Refusal::OwnOrAbove), "{leaf} in {dir:?}");
            }
        }
    }

    #[test]
    fn a_file_of_a_cgroup_beside_or_below_the_guard_is_allowed_unless_it_moves_tasks() {
        let sibling = [(D, 70), APP, MANAGER, USER_1000, USER_SLICE, ROOT];
        let child = [(D, 71), SCOPE, APP, MANAGER, USER_1000, USER_SLICE, ROOT];
        for target in [&sibling[..], &child[..]] {
            for leaf in ["cgroup.freeze", "cgroup.kill", "cpu.max", "cgroup.subtree_control"] {
                assert_eq!(decide(facts(leaf, target), |_| panic!("not asked")), Ok(()), "{leaf}");
            }
        }
    }

    #[test]
    fn a_move_into_a_cgroup_whose_common_ancestor_is_writable_is_refused() {
        // Into a child of the scope (podman / crun inside the session) and
        // into a sibling under app.slice: the common ancestor is the
        // scope, app.slice: the user's.
        let child = [(D, 71), SCOPE, APP, MANAGER, USER_1000, USER_SLICE, ROOT];
        let sibling = [(D, 70), APP, MANAGER, USER_1000, USER_SLICE, ROOT];
        for (target, common) in [(&child[..], 1usize), (&sibling[..], 1usize)] {
            for leaf in ["cgroup.procs", "cgroup.threads"] {
                let mut asked = None;
                assert_eq!(
                    decide(facts(leaf, target), |i| {
                        asked = Some(i);
                        Some(true)
                    }),
                    Err(Refusal::MoveReachesGuard)
                );
                assert_eq!(asked, Some(common), "the common ancestor is the one asked");
            }
        }
    }

    #[test]
    fn a_move_whose_common_ancestor_is_not_writable_is_allowed() {
        // The guard under a root-owned SSH session scope; the target under
        // the user's manager: the common ancestor is user-1000.slice, root's.
        let own: &[NodeId] = &[(D, 40), USER_1000, USER_SLICE, ROOT];
        let target = [(D, 70), APP, MANAGER, USER_1000, USER_SLICE, ROOT];
        let mut asked = None;
        let f = WriteFacts { leaf: "cgroup.procs", target: Some(&target), own: Some(own) };
        assert_eq!(
            decide(f, |i| {
                asked = Some(i);
                Some(false)
            }),
            Ok(())
        );
        assert_eq!(asked, Some(3));
        assert_eq!(decide(f, |_| None), Err(Refusal::Unplaced), "unknown permission: refused");
    }

    #[test]
    fn what_cannot_be_placed_is_refused() {
        // No common cgroup in sight (a mount whose cgroups the guard's own
        // view does not reach: one of them could be above the guard): any
        // file refused.
        let target = [(D, 80), (D, 81)];
        assert_eq!(decide(facts("cgroup.procs", &target), |_| panic!("not asked")), Err(Refusal::Unplaced));
        assert_eq!(decide(facts("cgroup.freeze", &target), |_| panic!("not asked")), Err(Refusal::Unplaced));
        // The guard's own cgroup unknown: every write-capable open refused.
        for own in [None, Some(&[][..])] {
            let f = WriteFacts { leaf: "cpu.max", target: Some(&target), own };
            assert_eq!(decide(f, |_| None), Err(Refusal::OwnUnknown));
        }
        // The target unknown.
        for t in [None, Some(&[][..])] {
            let f = WriteFacts { leaf: "cpu.max", target: t, own: Some(OWN) };
            assert_eq!(decide(f, |_| None), Err(Refusal::TargetUnknown));
        }
        for r in [Refusal::OwnUnknown, Refusal::TargetUnknown, Refusal::OwnOrAbove, Refusal::MoveReachesGuard, Refusal::Unplaced] {
            assert!(!r.reason().is_empty());
        }
    }
}
