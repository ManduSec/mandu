//! inode_pins — the guard holds every registered protected file by its inode
//! (docs/design/confidentiality/guard-file-identity.md §2,
//! 2026-10-16).
//!
//! The guard knows a registered file by its path and by its `(dev, inode)`
//! (`SecretIndex::by_identity`: a hard link, a case spelling). Its identity
//! list was re-`stat`ed by path every `ID_REFRESH`, so once the agent renamed
//! a directory above a registered file (`mv ~/.aws ~/.aws2`: only the leaf is
//! refused), the next rebuild found nothing at the registered path, dropped
//! the identity, and in the guard-only posture the file read raw under its
//! new path. Now the guard holds an `O_PATH` descriptor on each registered
//! entry (every kind but `object`, `deny`, `derived`: `pinned_kind`) from
//! the policy's load, before the agent's first trapped call is answered. While it is held the inode
//! cannot be freed, so its number is never reused: a `(dev, inode)` match is
//! exact for the whole session, whatever names reach the file.
//!
//! When a pin is dropped (`plan`, at every identity-list rebuild): its file
//! has no name left (`st_nlink` 0 on the held descriptor: deleted, or
//! replaced by a rename over its last name, an editor's save through a
//! temporary file). The inode then at the registered path is pinned at the
//! same rebuild. A held file that still has a name somewhere stays pinned
//! (moved with its directory, or a hard link made before the session): it
//! still holds the secret.
//!
//! The budget: at most `budget(nofile)` pins (a quarter of the guard's soft
//! `RLIMIT_NOFILE`, 16..=4096, as the death watch's pidfds; lowered, never
//! raised, by `MANDU_NET_GUARD_PIN_MAX`). A registered file that is not
//! pinned (past the budget, or its open failed) is listed `unpinned`, and a
//! rename of any directory above it is refused (`guard_kernel::judge_change`,
//! the `protect:` rule over that list): fail closed.
//!
//! A rename that moves a directory runs under the identity lock
//! (`SecretIndex::rename_dirs_holding_pins`): the pins are rebuilt, the rename
//! runs, and every registered file below a moved directory is held at its new
//! path (`moved_path`, `PinSet::pin_moved`) before any lookup that misses the
//! pins is answered; one that cannot be held undoes the rename. Its label
//! follows to the next session through the arbiter
//! (`guard_kernel::dir_follows`, asked after the rename stood: `label_after_rename`).
//!
//! Git's object-store entries (`object`, `deny`) are not pinned: git removes
//! and replaces them as it works, and a moved pack is judged by the backstop
//! (`git_lock`). Twins live in Mandu's write-protected scope directory and
//! never move.
//!
//! `plan` is pure; `PinSet` holds the descriptors (plain `open`/`fstat`, no
//! privilege, no seccomp: compiled and unit-tested in the default build).
//! `Mandu-new`.

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Mutex;

/// The env var that LOWERS the pin budget (a test of the fallback; a value
/// above the budget changes nothing).
pub const PIN_MAX_ENV: &str = "MANDU_NET_GUARD_PIN_MAX";

/// The pin budget for a soft descriptor limit `nofile`: a quarter of it, at
/// least 16, at most 4096; `cap` (`PIN_MAX_ENV`) lowers it. Pure.
pub fn budget(nofile: u64, cap: Option<usize>) -> usize {
    let b = (nofile / 4).clamp(16, 4096) as usize;
    cap.map_or(b, |c| c.min(b))
}

/// Is a registered entry of this `kind` pinned? Every kind but git's
/// object-store entries (`object`, `deny`: git removes and replaces them, and
/// the backstop judges a moved pack) and `derived` / `labelled` (the guard's
/// own entries, never in the launcher's list): a protected file (no kind,
/// or `file`) and, fail-closed as `registered_secret_refuses` treats it, any
/// kind this guard does not know (2026-10-16). Pure.
pub fn pinned_kind(kind: Option<&str>) -> bool {
    !matches!(kind, Some("object") | Some("deny") | Some("derived") | Some("labelled"))
}

/// What one rebuild does (`plan`).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Held inodes to release (no name left).
    pub release: Vec<(u64, u64)>,
    /// Registered paths to pin (what they name now is not held).
    pub pin: Vec<String>,
    /// Registered paths that exist, are not held and get no pin: past the
    /// budget.
    pub over_budget: Vec<String>,
}

/// The rebuild's plan. `held`: each held inode and whether it still has a
/// name (`st_nlink > 0` on its descriptor). `registered`: each pinned-kind
/// registered path and the identity it names now (`None`: nothing there).
/// A registered path whose inode is held (still, or under a kept pin) needs
/// nothing; one that names an unheld inode is pinned while the budget lasts
/// (held pins that stay count against it). Pure.
pub fn plan(held: &[((u64, u64), bool)], registered: &[(String, Option<(u64, u64)>)], budget: usize) -> Plan {
    let mut out = Plan::default();
    let mut kept: HashSet<(u64, u64)> = HashSet::new();
    for (k, named) in held {
        if *named {
            kept.insert(*k);
        } else {
            out.release.push(*k);
        }
    }
    let mut count = kept.len();
    let mut planned: HashSet<(u64, u64)> = HashSet::new();
    for (path, now) in registered {
        let Some(k) = now else { continue };
        if kept.contains(k) || planned.contains(k) {
            continue;
        }
        if count < budget {
            out.pin.push(path.clone());
            planned.insert(*k);
            count += 1;
        } else {
            out.over_budget.push(path.clone());
        }
    }
    out
}

/// Where a rename of the directory `old_dir` to `new_dir` puts the file at
/// `path`: `Some(new path)` when `path` is below `old_dir` (absolute,
/// normalized paths, as the registered ones and `/proc/self/fd` links are),
/// else `None`. Pure.
pub fn moved_path(path: &str, old_dir: &str, new_dir: &str) -> Option<String> {
    let old = old_dir.trim_end_matches('/');
    let rest = path.strip_prefix(old)?.strip_prefix('/')?;
    (!old.is_empty() && !rest.is_empty()).then(|| format!("{}/{rest}", new_dir.trim_end_matches('/')))
}

/// Is a carried file there to move (`guard_kernel::dir_follows`), from the
/// `lstat` of its path: `Ok(true)` it is, `Ok(false)` nothing is there
/// (ENOENT only), `Err` any other error (EACCES on a folder above it, …):
/// the caller refuses the rename, since such a file may well move. Pure.
#[allow(clippy::result_unit_err)]
pub fn carried_present(stat: std::io::Result<()>) -> Result<bool, ()> {
    match stat {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(()),
    }
}

/// A folder rename's labels, in order (2026-10-16, review of !1603): the
/// rename first (`renamed`: its errno); only once it stood are the carried
/// files' labels asked for (`label`), so a refused or undone rename leaves
/// none behind; a label that cannot be recorded undoes the rename (`undo`)
/// and answers EACCES; an undo that fails leaves the rename standing
/// (`stand`: the caller makes the moved files known by their new paths) and
/// answers 0. Nothing carried: `renamed` as it is. Pure but for the closures.
pub fn label_after_rename(renamed: i32, carried: bool, label: impl FnOnce() -> bool, undo: impl FnOnce() -> i32, stand: impl FnOnce()) -> i32 {
    if renamed != 0 || !carried || label() {
        return renamed;
    }
    if undo() == 0 {
        return libc::EACCES;
    }
    stand();
    0
}

/// One held inode: the registered path it was pinned for, and its descriptor.
#[derive(Debug)]
struct Pin {
    path: String,
    fd: OwnedFd,
}

/// The held inodes of a session.
#[derive(Debug, Default)]
pub struct PinSet {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    budget: usize,
    on: bool,
    pins: HashMap<(u64, u64), Pin>,
    unpinned: Vec<String>,
}

fn fstat(fd: i32) -> Option<libc::stat> {
    // SAFETY: fstat into a zeroed buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st)
}

/// `O_PATH | O_CLOEXEC` of `path` (following symlinks, as the identity list's
/// `stat` does) and its identity, when it is a regular file.
fn open_pin(path: &str) -> Option<(OwnedFd, (u64, u64))> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: open with a NUL-terminated path; the descriptor is owned below.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    // SAFETY: a descriptor this function just opened, owned once.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let st = fstat(fd.as_raw_fd())?;
    (st.st_mode & libc::S_IFMT == libc::S_IFREG).then_some((fd, (st.st_dev, st.st_ino)))
}

impl PinSet {
    /// Pinning on, with `budget` descriptors at most. Until this is called
    /// nothing is pinned (a guard with no policy, a unit test's index).
    pub fn enable(&self, budget: usize) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.on = true;
        s.budget = budget;
    }

    /// Is pinning on?
    pub fn is_on(&self) -> bool {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).on
    }

    /// One rebuild (`plan`), enacted: release the inodes with no name left,
    /// pin what the registered paths name now. `paths`: the pinned-kind
    /// registered paths. A pin whose descriptor's identity is not what the
    /// path named a moment before (the path was swapped meanwhile) is still
    /// taken (it is what the path names now), and the other is looked up at
    /// the next rebuild.
    pub fn refresh<'a>(&self, paths: impl Iterator<Item = &'a str>) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !s.on {
            return;
        }
        let held: Vec<((u64, u64), bool)> = s.pins.iter().map(|(k, p)| (*k, fstat(p.fd.as_raw_fd()).is_some_and(|st| st.st_nlink > 0))).collect();
        let registered: Vec<(String, Option<(u64, u64)>)> = paths
            .map(|p| {
                use std::os::unix::fs::MetadataExt;
                let now = std::fs::metadata(p).ok().filter(|m| m.is_file()).map(|m| (m.dev(), m.ino()));
                (p.to_string(), now)
            })
            .collect();
        let pl = plan(&held, &registered, s.budget);
        for k in &pl.release {
            s.pins.remove(k);
        }
        let mut unpinned = pl.over_budget;
        for path in pl.pin {
            match open_pin(&path) {
                Some((fd, k)) => {
                    s.pins.entry(k).or_insert(Pin { path, fd });
                }
                None => unpinned.push(path),
            }
        }
        // A path that names nothing now is not unpinned: there is nothing to
        // move. One whose inode is held is covered.
        s.unpinned = unpinned;
    }

    /// After a directory rename moved the registered file `registered` to
    /// `now_at`: hold what is there now (`guard_kernel::perform_rename`,
    /// under the identity lock). `true` when it is held (already, or now), or
    /// nothing regular is there to hold; `false` when a regular file is there
    /// and cannot be held (past the budget, or its open failed): the caller
    /// undoes the rename.
    pub fn pin_moved(&self, registered: &str, now_at: &str) -> bool {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !s.on {
            return true;
        }
        // Already held: nothing to open (an open failing for want of a
        // descriptor must not report a held file as unholdable).
        match std::fs::metadata(now_at) {
            Ok(m) if m.is_file() => {
                use std::os::unix::fs::MetadataExt;
                if s.pins.contains_key(&(m.dev(), m.ino())) {
                    return true;
                }
            }
            Ok(_) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) => return false,
        }
        let Some((fd, k)) = open_pin(now_at) else { return false };
        if s.pins.contains_key(&k) {
            return true;
        }
        if s.pins.len() >= s.budget {
            return false;
        }
        s.pins.insert(k, Pin { path: registered.to_string(), fd });
        true
    }

    /// The registered path whose held inode is `key`, if one is held: exact
    /// (a held inode's number is never reused).
    pub fn path_of(&self, key: (u64, u64)) -> Option<String> {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).pins.get(&key).map(|p| p.path.clone())
    }

    /// The registered files that exist and are not pinned (past the budget,
    /// or their open failed): a rename of a directory above one is refused.
    pub fn unpinned(&self) -> Vec<String> {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).unpinned.clone()
    }

    /// Held inodes (for tests and the launch log).
    pub fn held(&self) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).pins.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_is_a_quarter_of_the_soft_limit_and_only_lowered() {
        assert_eq!(budget(1024, None), 256);
        assert_eq!(budget(32, None), 16);
        assert_eq!(budget(1 << 20, None), 4096);
        assert_eq!(budget(1024, Some(0)), 0);
        assert_eq!(budget(1024, Some(5)), 5);
        assert_eq!(budget(1024, Some(100_000)), 256, "never raised");
    }

    #[test]
    fn every_kind_but_the_object_store_and_derived_is_pinned() {
        assert!(pinned_kind(None) && pinned_kind(Some("file")));
        // An unknown kind (a launcher newer than this guard): pinned, fail
        // closed, as `registered_secret_refuses` treats it.
        assert!(pinned_kind(Some("other")) && pinned_kind(Some("")));
        for k in ["object", "deny", "derived", "labelled"] {
            assert!(!pinned_kind(Some(k)), "{k}");
        }
    }

    #[test]
    fn a_carried_file_is_skipped_only_when_nothing_is_there() {
        use std::io::{Error, ErrorKind};
        assert_eq!(carried_present(Ok(())), Ok(true));
        assert_eq!(carried_present(Err(Error::from(ErrorKind::NotFound))), Ok(false));
        for e in [libc::EACCES, libc::ELOOP, libc::ENOTDIR, libc::EIO, libc::ENAMETOOLONG] {
            assert_eq!(carried_present(Err(Error::from_raw_os_error(e))), Err(()), "errno {e}: refused, never skipped");
        }
        // The real thing: a folder above the file made unsearchable.
        let d = tmp("eacces");
        std::fs::create_dir_all(d.join("a")).unwrap();
        std::fs::write(d.join("a").join("f"), "x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.join("a"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = carried_present(std::fs::symlink_metadata(d.join("a").join("f")).map(|_| ()));
        std::fs::set_permissions(d.join("a"), std::fs::Permissions::from_mode(0o755)).unwrap();
        // Root reads through a mode-000 folder: only an unprivileged run sees EACCES.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(r, Err(()));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_folder_rename_labels_only_after_it_stood_and_undoes_when_a_label_fails() {
        use std::cell::Cell;
        let (labelled, undone, stood) = (Cell::new(0), Cell::new(0), Cell::new(0));
        let label = |ok: bool| {
            let l = &labelled;
            move || {
                l.set(l.get() + 1);
                ok
            }
        };
        let undo = |rc: i32| {
            let u = &undone;
            move || {
                u.set(u.get() + 1);
                rc
            }
        };
        let stand = || stood.set(stood.get() + 1);
        // The rename failed (or was refused, or undone for a pin): no label.
        assert_eq!(label_after_rename(libc::EACCES, true, label(true), undo(0), stand), libc::EACCES);
        assert_eq!(labelled.get(), 0, "no label is asked for a rename that did not stand");
        // Nothing carried: nothing asked.
        assert_eq!(label_after_rename(0, false, label(true), undo(0), stand), 0);
        assert_eq!(labelled.get(), 0);
        // Labelled after it stood.
        assert_eq!(label_after_rename(0, true, label(true), undo(0), stand), 0);
        assert_eq!((labelled.get(), undone.get()), (1, 0));
        // A label that cannot be recorded: undone, EACCES.
        assert_eq!(label_after_rename(0, true, label(false), undo(0), stand), libc::EACCES);
        assert_eq!((undone.get(), stood.get()), (1, 0));
        // ... and an undo that fails: the rename stands, the files are known
        // by their new paths.
        assert_eq!(label_after_rename(0, true, label(false), undo(libc::EEXIST), stand), 0);
        assert_eq!(stood.get(), 1);
    }

    #[test]
    fn a_path_below_a_moved_directory_moves_with_it() {
        assert_eq!(moved_path("/h/.aws/credentials", "/h/.aws", "/h/.aws2").as_deref(), Some("/h/.aws2/credentials"));
        assert_eq!(moved_path("/h/.aws/credentials", "/h", "/x/y/").as_deref(), Some("/x/y/.aws/credentials"));
        assert_eq!(moved_path("/h/.aws/credentials", "/h/.aws/", "/h/b").as_deref(), Some("/h/b/credentials"));
        // Not below: a sibling with a common prefix, the file itself, elsewhere.
        assert_eq!(moved_path("/h/.aws-other/credentials", "/h/.aws", "/h/x"), None);
        assert_eq!(moved_path("/h/.aws", "/h/.aws", "/h/x"), None);
        assert_eq!(moved_path("/w/.env", "/h", "/x"), None);
    }

    #[test]
    fn a_file_moved_by_a_directory_rename_is_held_at_its_new_path() {
        let d = tmp("moved");
        std::fs::create_dir_all(d.join("a")).unwrap();
        let f = d.join("a").join("f");
        std::fs::write(&f, "x").unwrap();
        let set = PinSet::default();
        set.enable(1);
        let reg = f.to_str().unwrap();
        // Off: nothing to do.
        assert!(PinSet::default().pin_moved(reg, reg));
        std::fs::rename(d.join("a"), d.join("b")).unwrap();
        let now = d.join("b").join("f");
        assert!(set.pin_moved(reg, now.to_str().unwrap()));
        assert_eq!(set.path_of(key(&now)).as_deref(), Some(reg));
        assert!(set.pin_moved(reg, now.to_str().unwrap()), "already held");
        // Nothing there, or a directory: nothing to hold.
        assert!(set.pin_moved(reg, d.join("none").to_str().unwrap()));
        assert!(set.pin_moved(reg, d.to_str().unwrap()));
        // Past the budget: a regular file that cannot be held.
        let g = d.join("b").join("g");
        std::fs::write(&g, "y").unwrap();
        assert!(!set.pin_moved(reg, g.to_str().unwrap()));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_plan_keeps_named_inodes_releases_nameless_ones_and_pins_what_is_new() {
        let a = ("/h/.aws/credentials".to_string(), Some((9, 42)));
        // First rebuild: nothing held, both registered files exist.
        let p = plan(&[], &[a.clone(), ("/w/.env".into(), Some((9, 50)))], 10);
        assert_eq!(p, Plan { release: vec![], pin: vec!["/h/.aws/credentials".into(), "/w/.env".into()], over_budget: vec![] });
        // Moved with its directory: the path names nothing, the held inode
        // still has a name: kept, nothing to do.
        let p = plan(&[((9, 42), true)], &[("/h/.aws/credentials".into(), None)], 10);
        assert_eq!(p, Plan::default());
        // An editor saved through a temporary file and a rename: the old
        // inode has no name left (released), the new one is pinned.
        let p = plan(&[((9, 42), false)], &[("/h/.aws/credentials".into(), Some((9, 77)))], 10);
        assert_eq!(p, Plan { release: vec![(9, 42)], pin: vec!["/h/.aws/credentials".into()], over_budget: vec![] });
        // The same, with a hard link to the old inode left (made before the
        // session): the old one is kept (it still holds the old secret).
        let p = plan(&[((9, 42), true)], &[("/h/.aws/credentials".into(), Some((9, 77)))], 10);
        assert_eq!(p, Plan { release: vec![], pin: vec!["/h/.aws/credentials".into()], over_budget: vec![] });
        // Deleted: released, nothing to pin.
        let p = plan(&[((9, 42), false)], &[("/h/.aws/credentials".into(), None)], 10);
        assert_eq!(p, Plan { release: vec![(9, 42)], pin: vec![], over_budget: vec![] });
        // Two registered names of one inode: one pin.
        let p = plan(&[], &[a.clone(), ("/h/.AWS/credentials".into(), Some((9, 42)))], 10);
        assert_eq!(p.pin, vec!["/h/.aws/credentials".to_string()]);
    }

    #[test]
    fn past_the_budget_a_file_is_listed_unpinned() {
        let reg = vec![("/a".to_string(), Some((1, 1))), ("/b".to_string(), Some((1, 2))), ("/c".to_string(), Some((1, 3)))];
        let p = plan(&[], &reg, 2);
        assert_eq!(p.pin, vec!["/a".to_string(), "/b".to_string()]);
        assert_eq!(p.over_budget, vec!["/c".to_string()]);
        // Held pins count against the budget.
        let p = plan(&[((1, 9), true)], &reg, 2);
        assert_eq!(p.pin, vec!["/a".to_string()]);
        assert_eq!(p.over_budget, vec!["/b".to_string(), "/c".to_string()]);
        // A budget of 0: every existing file is unpinned.
        assert_eq!(plan(&[], &reg, 0).over_budget.len(), 3);
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("mandu-pins-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn key(p: &std::path::Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(p).unwrap();
        (m.dev(), m.ino())
    }

    #[test]
    fn a_held_inode_survives_its_directory_being_renamed_and_an_editors_save_is_followed() {
        let d = tmp("real");
        std::fs::create_dir_all(d.join("aws")).unwrap();
        let cred = d.join("aws").join("credentials");
        std::fs::write(&cred, "secret").unwrap();
        let reg = cred.to_str().unwrap().to_string();
        let set = PinSet::default();
        set.refresh(std::iter::once(reg.as_str()));
        assert_eq!(set.held(), 0, "off until enabled");
        set.enable(8);
        set.refresh(std::iter::once(reg.as_str()));
        let k = key(&cred);
        assert_eq!(set.path_of(k).as_deref(), Some(reg.as_str()));
        // The directory is renamed: the registered path names nothing; the
        // held inode is still that file under its new name.
        std::fs::rename(d.join("aws"), d.join("aws2")).unwrap();
        set.refresh(std::iter::once(reg.as_str()));
        assert_eq!(key(&d.join("aws2").join("credentials")), k);
        assert_eq!(set.path_of(k).as_deref(), Some(reg.as_str()), "kept: it still has a name");
        assert!(set.unpinned().is_empty());
        // Back, then an editor's save: a temporary file renamed over it.
        std::fs::rename(d.join("aws2"), d.join("aws")).unwrap();
        let tmpf = d.join("aws").join(".credentials.swp");
        std::fs::write(&tmpf, "new secret").unwrap();
        std::fs::rename(&tmpf, &cred).unwrap();
        let k2 = key(&cred);
        set.refresh(std::iter::once(reg.as_str()));
        assert_eq!(set.path_of(k2).as_deref(), Some(reg.as_str()), "the new inode is pinned");
        assert_eq!(set.path_of(k), None, "the old one, with no name left, is released");
        assert_eq!(set.held(), 1);
        // Deleted on purpose: released.
        std::fs::remove_file(&cred).unwrap();
        set.refresh(std::iter::once(reg.as_str()));
        assert_eq!(set.held(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn past_the_budget_the_file_is_unpinned() {
        let d = tmp("budget");
        let a = d.join("a");
        let b = d.join("b");
        std::fs::write(&a, "x").unwrap();
        std::fs::write(&b, "y").unwrap();
        let set = PinSet::default();
        set.enable(1);
        let paths = [a.to_str().unwrap(), b.to_str().unwrap()];
        set.refresh(paths.iter().copied());
        assert_eq!(set.held(), 1);
        assert_eq!(set.unpinned().len(), 1);
        // A directory or nothing at a registered path is neither.
        let set = PinSet::default();
        set.enable(4);
        let dir = d.to_str().unwrap();
        let none = d.join("none");
        set.refresh([dir, none.to_str().unwrap()].into_iter());
        assert_eq!((set.held(), set.unpinned().len()), (0, 0));
        let _ = std::fs::remove_dir_all(&d);
    }
}
