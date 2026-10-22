//! cgroup_guard_kernel — the enactment of `cgroup_guard`
//! (rootless-confinement-ubuntu-2404.md §12.2, "The cgroup"): the facts of
//! one write-capable open of a cgroup2 file, read from the descriptor the
//! guard is about to hand over.
//!
//! The file's cgroup is placed in the GUARD's view by the path its
//! descriptor names (`/proc/self/fd/N`), and believed only when that
//! directory, opened here, holds the very file opened (same device and
//! inode: a kernfs node has one parent), so a path that names something
//! else in the guard's mount namespace (the tracee's own private mount, a
//! component the tracee swapped) refuses instead of misleading. The cgroups
//! above it, and above the guard's own, are walked by `..` while the file
//! system stays cgroup2. The guard's own cgroup is `/proc/self/cgroup`'s
//! `0::` path under a cgroup2 mount of its `mountinfo`, believed only when
//! that directory's `cgroup.procs` lists the guard. Any step that fails
//! leaves a fact unknown, which `cgroup_guard::decide` refuses.
//! `Mandu-new`.

#![cfg(all(feature = "kernel", target_os = "linux"))]

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::io::RawFd;
use std::path::Path;

use crate::cgroup_guard::{self, NodeId, Refusal, WriteFacts};

/// More levels than any cgroup hierarchy has (the kernel's own limit is
/// `cgroup.max.depth`, unlimited by default; systemd's trees are < 10).
const MAX_DEPTH: usize = 256;

/// The verdict on handing the tracee `fd`, opened with `flags`: None when
/// it may be handed over (not write-capable, not on cgroup2, or allowed),
/// the refusal otherwise.
pub fn refusal(fd: RawFd, flags: i32) -> Option<Refusal> {
    // What the descriptor can do, by the open's flags and by its own status
    // flags (whichever says it can write).
    // SAFETY: F_GETFL on a descriptor this process holds.
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if !cgroup_guard::write_capable(flags) && (status < 0 || !cgroup_guard::write_capable(status)) {
        return None;
    }
    match fs_type(fd) {
        Some(t) if !cgroup_guard::is_cgroup2(t) => return None,
        Some(_) => {}
        None => return Some(Refusal::TargetUnknown),
    }
    let target = target_chain(fd);
    let own = own_chain();
    let leaf = target.as_ref().map(|t| t.leaf.clone()).unwrap_or_default();
    let target_ids: Option<Vec<NodeId>> = target.as_ref().map(|t| t.dirs.iter().map(|(id, _)| *id).collect());
    let own_ids: Option<Vec<NodeId>> = own.as_ref().map(|o| o.iter().map(|(id, _)| *id).collect());
    let facts = WriteFacts { leaf: &leaf, target: target_ids.as_deref(), own: own_ids.as_deref() };
    let writable = |i: usize| -> Option<bool> {
        let (_, dir) = target.as_ref()?.dirs.get(i)?;
        procs_writable(dir.as_raw_fd())
    };
    cgroup_guard::decide(facts, writable).err()
}

/// A descriptor's statfs `f_type`.
fn fs_type(fd: RawFd) -> Option<i64> {
    // SAFETY: fstatfs into a zeroed buffer.
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstatfs(fd, &mut sfs) } == 0).then_some(sfs.f_type as i64)
}

fn identity(fd: RawFd) -> Option<NodeId> {
    // SAFETY: fstat into a zeroed buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev, st.st_ino))
}

fn open_at(dir: RawFd, name: &str, flags: i32) -> Option<OwnedFd> {
    let c = CString::new(name).ok()?;
    // SAFETY: openat with a NUL-terminated name; the result is owned below.
    let fd = unsafe { libc::openat(dir, c.as_ptr(), flags | libc::O_CLOEXEC) };
    // SAFETY: a fresh descriptor this process owns.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_dir(path: &Path) -> Option<OwnedFd> {
    open_at(libc::AT_FDCWD, path.to_str()?, libc::O_PATH | libc::O_DIRECTORY)
}

/// The opened file's name and its cgroup's chain.
struct Target {
    leaf: String,
    dirs: Vec<(NodeId, OwnedFd)>,
}

/// Place the file `fd` opened in the guard's view (module doc).
fn target_chain(fd: RawFd) -> Option<Target> {
    let file = identity(fd)?;
    let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
    if !link.is_absolute() || link.to_string_lossy().ends_with(" (deleted)") {
        return None;
    }
    let leaf = link.file_name()?.to_str()?.to_string();
    let parent = open_dir(link.parent()?)?;
    let again = open_at(parent.as_raw_fd(), &leaf, libc::O_PATH | libc::O_NOFOLLOW)?;
    if identity(again.as_raw_fd())? != file {
        return None;
    }
    Some(Target { leaf, dirs: chain_from(parent)? })
}

/// `dir` and every directory above it while the file system is cgroup2,
/// nearest first. None if `dir` is not on cgroup2 or a step fails.
fn chain_from(dir: OwnedFd) -> Option<Vec<(NodeId, OwnedFd)>> {
    if !cgroup_guard::is_cgroup2(fs_type(dir.as_raw_fd())?) {
        return None;
    }
    let mut chain = vec![(identity(dir.as_raw_fd())?, dir)];
    while chain.len() < MAX_DEPTH {
        let (id, cur) = chain.last()?;
        let up = open_at(cur.as_raw_fd(), "..", libc::O_PATH | libc::O_DIRECTORY)?;
        let up_id = identity(up.as_raw_fd())?;
        if up_id == *id || !cgroup_guard::is_cgroup2(fs_type(up.as_raw_fd())?) {
            return Some(chain);
        }
        chain.push((up_id, up));
    }
    None
}

/// The guard's own cgroup and those above it (module doc).
fn own_chain() -> Option<Vec<(NodeId, OwnedFd)>> {
    let own = cgroup_guard::own_cgroup_path(&std::fs::read_to_string("/proc/self/cgroup").ok()?)?;
    let mounts = cgroup_guard::cgroup2_mounts(&std::fs::read_to_string("/proc/self/mountinfo").ok()?);
    // SAFETY: getpid has no failure mode.
    let me = unsafe { libc::getpid() };
    for dir in cgroup_guard::own_cgroup_dirs(&own, &mounts) {
        let Some(fd) = open_dir(&dir) else { continue };
        let listed = open_at(fd.as_raw_fd(), "cgroup.procs", libc::O_RDONLY)
            .and_then(|p| std::io::read_to_string(std::fs::File::from(p)).ok())
            .map(|procs| cgroup_guard::lists_pid(&procs, me))
            .unwrap_or(false);
        if listed {
            if let Some(chain) = chain_from(fd) {
                return Some(chain);
            }
        }
    }
    None
}

/// Is `dir`'s `cgroup.procs` writable to this process (the tracee's uid and
/// groups: the context helper refuses any other)? kernfs keeps no ACLs, so
/// the mode bits decide (`cgroup_guard::may_write`); a read-only mount does
/// not matter (the kernel's common-ancestor check is on the inode).
fn procs_writable(dir: RawFd) -> Option<bool> {
    let c = CString::new("cgroup.procs").ok()?;
    // SAFETY: fstatat into a zeroed buffer, a NUL-terminated name.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dir, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return None;
    }
    // SAFETY: plain id getters.
    let euid = unsafe { libc::geteuid() };
    let mut groups = vec![unsafe { libc::getegid() }];
    // SAFETY: getgroups(0, NULL) returns the count; the second call fills.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n > 0 {
        let mut more = vec![0 as libc::gid_t; n as usize];
        let got = unsafe { libc::getgroups(n, more.as_mut_ptr()) };
        if got < 0 {
            return None;
        }
        more.truncate(got as usize);
        groups.extend(more);
    }
    Some(cgroup_guard::may_write(st.st_mode, st.st_uid, st.st_gid, euid, &groups))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_descriptor_that_cannot_write_or_is_not_on_cgroup2_is_never_refused() {
        let dir = std::env::temp_dir().join(format!("mandu-cgguard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f");
        std::fs::write(&p, "x").unwrap();
        let w = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        assert_eq!(refusal(w.as_raw_fd(), libc::O_WRONLY), None, "a regular file");
        let r = std::fs::File::open(&p).unwrap();
        assert_eq!(refusal(r.as_raw_fd(), libc::O_RDONLY), None, "read-only");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_own_cgroup_is_found_and_read_only_opens_there_pass() {
        let Some(own) = own_chain() else {
            eprintln!("SKIP: the guard's own cgroup is not visible here (no cgroup2 mount that holds it)");
            return;
        };
        assert!(!own.is_empty());
        let (id, dir) = &own[0];
        let events = open_at(dir.as_raw_fd(), "cgroup.events", libc::O_RDONLY).expect("cgroup.events of the own cgroup");
        assert_eq!(refusal(events.as_raw_fd(), libc::O_RDONLY), None, "a read-only open is never judged");
        let placed = target_chain(events.as_raw_fd()).expect("the own cgroup's file is placed by its path");
        assert_eq!(placed.leaf, "cgroup.events");
        assert_eq!(placed.dirs[0].0, *id, "its cgroup is the guard's");
        assert_eq!(placed.dirs.len(), own.len(), "the same cgroups above it");
    }
}
