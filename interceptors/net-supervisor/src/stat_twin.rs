//! stat_twin — the METADATA half of a twin the guard serves alone
//! (confidentiality.md §7.2a "Guard-only metadata", 2026-09-30).
//!
//! Where no bind puts the twin over the real path (`--no-secret-bind`, a
//! bubblewrap that forbids nesting, no bind possible), the guard hands a
//! reader the twin's DESCRIPTOR on open, but a `stat` by path still reached
//! the real file. The two disagree on the size, and git checks exactly that:
//! `add_packed_git` records the `.pack`'s `st_size` from a `stat` by path,
//! and `open_packed_git_1` refuses the pack when `fstat` of the opened
//! descriptor differs ("packfile … size changed"), which drops the WHOLE
//! sanitized pack and every other object in it. A size-checked reader of a
//! credential twin (stat, then read exactly `st_size`) is the same class.
//!
//! With the launcher's `MANDU_NET_GUARD_STAT_TWINS=1` (guard-only posture
//! with at least one twin), the guard also traps the stat family that names
//! a path AND follows its final symlink, and answers a registered path with
//! the TWIN's metadata, exactly what the bind shows there: x86_64's `stat`,
//! and `newfstatat`/`statx` without `AT_EMPTY_PATH` or
//! `AT_SYMLINK_NOFOLLOW`. `fstat` needs nothing for a registered file: the
//! descriptor IS the twin. (A DERIVED file's twin is the one case where the
//! guard answers a descriptor stat: below, `fd_stat_call`.)
//!
//! `lstat` (2026-10-04, §7.2a "The size a reader sees"): a reader that
//! `lstat`s a path, opens it and reads exactly `st_size` bytes (`git diff
//! --no-index`, `git grep --no-index`, `rsync`) read the twin by the REAL
//! file's size: cut short, or past its end. With the stat trap the filter
//! also hands over an `lstat` relative to the cwd or absolute
//! (`guard_filter::LstatTrap::Cwd`, the default: x86_64's `lstat`, and
//! `newfstatat`/`statx` with `AT_SYMLINK_NOFOLLOW` on `AT_FDCWD`), which
//! the guard resolves with `O_NOFOLLOW`. One relative to a directory
//! descriptor (the fts walkers: `find`, `du`) runs free unless the trap is
//! `LstatTrap::All`: trapping every `lstat` doubled `find` and cost `git
//! status` 60 % (measured, §7.2a "Cost").
//!
//! Another name (P0 4c, 2026-10-09): a symlink of another name (`ln -s
//! ~/.env /tmp/x; stat -L /tmp/x`) or a hard link made before the launch
//! reaches the same file, and the leaf-name prefilter let both go to the
//! kernel (the real size, times, inode and link count). `stat_probe` now
//! resolves every FOLLOWING stat of another leaf, and an `lstat` of one
//! while a registered file has another link; the handler matches what it
//! reaches by path and identity, so every name that resolves to a
//! registered inode answers the twin's metadata.
//!
//! The pure parts, unit-tested here: which numbers and flags the filter
//! traps, the call decoded, the flags the guard answers itself (anything
//! else is left to the kernel), the leaf-name prefilter and which stats it
//! resolves (`stat_probe`), and what an entry answers. The notification handler is `guard_kernel::handle_stat_notif`.
//!
//! Direction: this is utility, not a boundary. A stat reveals metadata, never
//! a byte; a stat the guard does not answer (not a twinned name, a flag it
//! does not emulate, any failure) CONTINUEs to the kernel, which answers
//! with the real file's metadata as before this change. `Mandu-new`.

use std::collections::HashSet;

/// `AT_EMPTY_PATH` (0x1000): a call with it may name its descriptor alone
/// (`fstat` in glibc ≥ 2.33 is `newfstatat(fd, "", buf, AT_EMPTY_PATH)`).
pub const AT_EMPTY_PATH: u32 = libc::AT_EMPTY_PATH as u32;

/// The flags that let a `newfstatat`/`statx` run at full speed with the
/// `lstat` trap off (`guard_filter::LstatTrap::Off`): `AT_EMPTY_PATH` (a
/// descriptor's own stat) and `AT_SYMLINK_NOFOLLOW` (an lstat).
pub const RUNS_FREE: u32 = AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW as u32;

/// `AT_STATX_SYNC_TYPE` (statx's two sync bits, 0x6000).
pub const AT_STATX_SYNC_TYPE: i32 = 0x6000;

/// `STATX__RESERVED`: a mask bit the kernel refuses (EINVAL).
pub const STATX_RESERVED: u32 = 0x8000_0000;

/// The stat-family numbers the filter hands over BY NUMBER alone: x86_64's
/// legacy `stat`, which names a path and follows it in every form (its
/// `lstat` is `lstat_nrs_by_number`).
pub fn stat_nrs_by_number() -> Vec<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        vec![libc::SYS_stat as i64]
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Vec::new()
    }
}

/// x86_64's legacy `lstat` (its path is relative to the cwd or absolute),
/// handed over BY NUMBER when the filter traps `lstat`s too
/// (`guard_filter::LstatTrap`). Empty elsewhere: aarch64 has only
/// `newfstatat` and `statx`.
pub fn lstat_nrs_by_number() -> Vec<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        vec![libc::SYS_lstat as i64]
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Vec::new()
    }
}

/// The stat-family numbers the filter hands over unless a `RUNS_FREE` flag
/// is set, with the argument index of their flags: `newfstatat(dirfd, path,
/// buf, flags)` and `statx(dirfd, path, flags, mask, buf)`.
pub fn stat_nrs_by_flags() -> Vec<(i64, usize)> {
    vec![(libc::SYS_newfstatat as i64, 3), (libc::SYS_statx as i64, 2)]
}

/// Is this a stat-family number the guard may be handed?
pub fn is_stat_nr(nr: i64) -> bool {
    stat_nrs_by_number().contains(&nr) || lstat_nrs_by_number().contains(&nr) || stat_nrs_by_flags().iter().any(|(n, _)| *n == nr)
}

/// Which struct the call fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatForm {
    /// The kernel's `struct stat` (`stat`, `lstat`, `newfstatat`).
    Stat,
    /// `struct statx`, with the caller's mask and sync bits.
    Statx { mask: u32, sync: i32 },
}

/// A stat-family call, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatCall {
    pub dirfd: i32,
    /// The path pointer in the tracee.
    pub path: u64,
    /// The result buffer in the tracee.
    pub buf: u64,
    /// The final symlink is followed (no `AT_SYMLINK_NOFOLLOW`, not `lstat`).
    pub follow: bool,
    pub form: StatForm,
    /// The guard answers only flags it emulates exactly; anything else (an
    /// unknown bit, a statx mask or sync value the kernel refuses) is left
    /// to the kernel.
    pub answerable: bool,
}

/// Decode a stat-family call. `None`: not one. Pure.
pub fn stat_call(nr: i64, args: &[u64; 6]) -> Option<StatCall> {
    #[cfg(target_arch = "x86_64")]
    {
        if nr == libc::SYS_stat as i64 || nr == libc::SYS_lstat as i64 {
            return Some(StatCall { dirfd: libc::AT_FDCWD, path: args[0], buf: args[1], follow: nr == libc::SYS_stat as i64, form: StatForm::Stat, answerable: true });
        }
    }
    // `AT_EMPTY_PATH` changes nothing for a non-empty path, and an empty
    // one never names a twinned leaf (the prefilter passes it on): the flag
    // reaches the guard only on `AT_FDCWD` (P0 4b, `guard_filter::stat_block`).
    if nr == libc::SYS_newfstatat as i64 {
        let flags = args[3] as u32 as i32;
        let known = libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT | libc::AT_EMPTY_PATH;
        return Some(StatCall {
            dirfd: args[0] as i32,
            path: args[1],
            buf: args[2],
            follow: flags & libc::AT_SYMLINK_NOFOLLOW == 0,
            form: StatForm::Stat,
            answerable: flags & !known == 0,
        });
    }
    if nr == libc::SYS_statx as i64 {
        let flags = args[2] as u32 as i32;
        let mask = args[3] as u32;
        let sync = flags & AT_STATX_SYNC_TYPE;
        let known = libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE | libc::AT_EMPTY_PATH;
        return Some(StatCall {
            dirfd: args[0] as i32,
            path: args[1],
            buf: args[4],
            follow: flags & libc::AT_SYMLINK_NOFOLLOW == 0,
            form: StatForm::Statx { mask, sync },
            answerable: flags & !known == 0 && sync != AT_STATX_SYNC_TYPE && mask & STATX_RESERVED == 0,
        });
    }
    None
}

/// The final component a path names, lexically: trailing slashes trimmed.
/// `None` for an empty path, `/`, `.` or `..` (never a registered file's
/// name). Pure.
pub fn leaf_of(path: &[u8]) -> Option<&[u8]> {
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }
    let p = &path[..end];
    let leaf = match p.iter().rposition(|b| *b == b'/') {
        Some(i) => &p[i + 1..],
        None => p,
    };
    if leaf.is_empty() || leaf == b"." || leaf == b".." { None } else { Some(leaf) }
}

/// The prefilter: the final components of every registered path. A stat
/// whose leaf is a registered name is resolved; one whose leaf is another
/// name only when another name could reach a registered file there
/// (`stat_probe`, P0 4c). Anything else continues at once, nothing resolved
/// (one path read and a set lookup).
#[derive(Debug, Default, Clone)]
pub struct StatNames(HashSet<Vec<u8>>);

impl StatNames {
    pub fn new<'a>(paths: impl IntoIterator<Item = &'a str>) -> Self {
        StatNames(paths.into_iter().filter_map(|p| leaf_of(p.as_bytes()).map(<[u8]>::to_vec)).collect())
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Could this path name a registered file BY ITS OWN NAME? Pure.
    pub fn candidate(&self, path: &[u8]) -> bool {
        leaf_of(path).is_some_and(|l| self.0.contains(l))
    }
    /// The path's leaf, as `stat_probe` weighs it. Pure.
    pub fn leaf(&self, path: &[u8]) -> Leaf {
        match leaf_of(path) {
            None => Leaf::NoFile,
            Some(l) if self.0.contains(l) => Leaf::Registered,
            Some(_) => Leaf::Other,
        }
    }
}

/// A stat's path, by its final component alone (no resolution).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leaf {
    /// Empty, `/`, `.` or `..`: a directory, never a registered file.
    NoFile,
    /// The final component of a registered path.
    Registered,
    /// Any other name.
    Other,
}

/// What the guard does with a trapped stat by path (P0 4c, 2026-10-09;
/// confidentiality.md §7.2a "Another name for a twinned file").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatProbe {
    /// No name this stat can reach is a registered file: continue at once.
    Continue,
    /// Resolve the path once in the tracee's view and match the file it
    /// reaches by path and by `(st_dev, st_ino)` (`lookup_opened`).
    Resolve,
}

/// Which trapped stats are resolved. A registered leaf always is. Another
/// leaf reaches a registered file only
/// - through a symlink (of any name, made before the launch or by the
///   agent, one hop or many, or a magic link under `/proc`): only a stat
///   that FOLLOWS its final component (`stat`, `newfstatat`/`statx` without
///   `AT_SYMLINK_NOFOLLOW`) gets there. An `lstat` of a symlink is the
///   link's own metadata, and a symlink in a DIRECTORY component keeps the
///   registered leaf;
/// - or through a hard link of another name. The guard refuses a link made
///   in the session, so one exists only while a registered file's
///   `st_nlink` is above 1 (`linked`, asked only here: it reads the identity
///   list, refreshed every `ID_REFRESH`), and then an `lstat` of another
///   leaf is resolved too.
///
/// Pure.
pub fn stat_probe(leaf: Leaf, follow: bool, linked: impl FnOnce() -> bool) -> StatProbe {
    match leaf {
        Leaf::NoFile => StatProbe::Continue,
        Leaf::Registered => StatProbe::Resolve,
        Leaf::Other if follow || linked() => StatProbe::Resolve,
        Leaf::Other => StatProbe::Continue,
    }
}

/// The file whose metadata answers a stat that resolved to a registered
/// entry: its twin, whatever the entry's kind (a protected file, a pack or
/// its index, a `deny` file's empty stand-in), as the bind shows it. `None`
/// (continue to the kernel) for an entry with no twin. Pure.
pub fn stat_twin_of(entry: &crate::secret_open::SecretEntry) -> Option<&str> {
    let t = entry.twin.trim();
    (!t.is_empty()).then_some(entry.twin.as_str())
}

/// The bytes a stat answer writes into the tracee's buffer: the struct as
/// the kernel lays it out (`libc::stat` is the kernel's `struct stat` on
/// x86_64 and aarch64; `libc::statx` is `struct statx`). Pure.
pub fn stat_bytes(st: &libc::stat) -> Vec<u8> {
    // SAFETY: a plain-old-data struct viewed as its bytes.
    unsafe { std::slice::from_raw_parts(st as *const libc::stat as *const u8, std::mem::size_of::<libc::stat>()) }.to_vec()
}

/// `stat_bytes` for `struct statx`. Pure.
pub fn statx_bytes(st: &libc::statx) -> Vec<u8> {
    // SAFETY: a plain-old-data struct viewed as its bytes.
    unsafe { std::slice::from_raw_parts(st as *const libc::statx as *const u8, std::mem::size_of::<libc::statx>()) }.to_vec()
}

// ── a derived twin's descriptor (plan 13 D4, 2026-10-04) ─────────────────────
//
// A derived file (one a holder wrote) has no bind: the guard serves its twin
// by descriptor (`derived_twin`), so `lstat`/`stat` of the path report the
// REAL file and `fstat` of the descriptor the twin, two different inodes. A
// reader that checks the descriptor is the file it named refuses it: Claude
// Code 2.1.288 reads a Bash call's output back from its task file exactly so
// (`lstat`, `open(O_NOFOLLOW)`, `fstat`, compare `st_dev`/`st_ino`, else
// "output file identity changed"), so every call whose tree held a secret
// came back as "output file could not be read". The guard places a derived
// twin's descriptor at `TWIN_FD_BASE` or above, the filter hands it the
// descriptor stat calls on such numbers only (`fstat`, `newfstatat`/`statx`
// with `AT_EMPTY_PATH`), and it answers the twin's metadata with the REAL
// file's `st_dev`/`st_ino`: the identity of the file the twin stands for,
// as under a bind, while the size and times stay the twin's (what a read
// of the descriptor returns). Metadata only: no byte of either file moves.

/// The lowest descriptor number a derived twin is placed at. Below 1024
/// (glibc's default soft `RLIMIT_NOFILE`, and `FD_SETSIZE`), above what an
/// ordinary process reaches: the stat calls on lower numbers, nearly all of
/// them, run at full speed.
pub const TWIN_FD_BASE: u32 = 768;

/// A descriptor stat call, decoded: `fstat(fd, buf)`, or `newfstatat`/
/// `statx` with `AT_EMPTY_PATH` (`path`: its path pointer, to be read and
/// found empty).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdStatCall {
    pub fd: i32,
    pub path: Option<u64>,
    pub buf: u64,
    pub form: StatForm,
    /// The guard answers only flags it emulates exactly (see `StatCall`).
    pub answerable: bool,
}

/// Decode a descriptor stat call on a number at or above `TWIN_FD_BASE`.
/// `None`: not one (a path stat, a lower or negative descriptor). Pure.
pub fn fd_stat_call(nr: i64, args: &[u64; 6]) -> Option<FdStatCall> {
    let fd = args[0] as u32;
    if !(TWIN_FD_BASE..0x8000_0000).contains(&fd) {
        return None;
    }
    let fd = fd as i32;
    if nr == libc::SYS_fstat as i64 {
        return Some(FdStatCall { fd, path: None, buf: args[1], form: StatForm::Stat, answerable: true });
    }
    let empty = libc::AT_EMPTY_PATH;
    if nr == libc::SYS_newfstatat as i64 {
        let flags = args[3] as u32 as i32;
        if flags & empty == 0 {
            return None;
        }
        let known = empty | libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT;
        return Some(FdStatCall { fd, path: Some(args[1]), buf: args[2], form: StatForm::Stat, answerable: flags & !known == 0 });
    }
    if nr == libc::SYS_statx as i64 {
        let flags = args[2] as u32 as i32;
        if flags & empty == 0 {
            return None;
        }
        let mask = args[3] as u32;
        let sync = flags & AT_STATX_SYNC_TYPE;
        let known = empty | libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE;
        return Some(FdStatCall {
            fd,
            path: Some(args[1]),
            buf: args[4],
            form: StatForm::Statx { mask, sync },
            answerable: flags & !known == 0 && sync != AT_STATX_SYNC_TYPE && mask & STATX_RESERVED == 0,
        });
    }
    None
}

/// The descriptor stat numbers the filter routes by their descriptor
/// (`fd_stat_block`), with the argument index of their flags (`None`:
/// `fstat`, which has none and always names a descriptor).
pub fn fd_stat_nrs() -> Vec<(i64, Option<usize>)> {
    vec![(libc::SYS_fstat as i64, None), (libc::SYS_newfstatat as i64, Some(3)), (libc::SYS_statx as i64, Some(2))]
}

/// Where to place a derived twin's descriptor in a process whose open
/// descriptors are `open` and whose soft `RLIMIT_NOFILE` is `soft`: the
/// lowest free number at or above `TWIN_FD_BASE` below the limit. `None`:
/// no room there (the twin goes to the lowest free number, as before). Pure.
pub fn twin_fd_slot(open: &[i32], soft: u64) -> Option<i32> {
    let taken: HashSet<i32> = open.iter().copied().collect();
    (TWIN_FD_BASE as i64..soft.min(0x8000_0000) as i64).map(|n| n as i32).find(|n| !taken.contains(n))
}

/// The soft `Max open files` of a `/proc/<pid>/limits` text. `None`: not
/// found. `unlimited` reads as `u64::MAX`. Pure.
pub fn soft_nofile(limits: &str) -> Option<u64> {
    let line = limits.lines().find(|l| l.starts_with("Max open files"))?;
    let soft = line["Max open files".len()..].split_whitespace().next()?;
    if soft == "unlimited" { Some(u64::MAX) } else { soft.parse().ok() }
}

/// The twin's `struct stat` with the identity of the file it stands for.
/// Pure.
pub fn with_identity(mut st: libc::stat, dev: u64, ino: u64) -> libc::stat {
    st.st_dev = dev as _;
    st.st_ino = ino as _;
    st
}

/// `with_identity` for `struct statx` (the device as major and minor). Pure.
pub fn with_identity_x(mut sx: libc::statx, dev: u64, ino: u64) -> libc::statx {
    sx.stx_dev_major = libc::major(dev as libc::dev_t) as u32;
    sx.stx_dev_minor = libc::minor(dev as libc::dev_t) as u32;
    sx.stx_ino = ino;
    sx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_open::SecretEntry;

    #[test]
    fn a_descriptor_stat_is_decoded_only_at_or_above_the_twin_base() {
        let b = TWIN_FD_BASE as u64;
        assert_eq!(fd_stat_call(libc::SYS_fstat as i64, &args(&[b, 0x20])), Some(FdStatCall { fd: b as i32, path: None, buf: 0x20, form: StatForm::Stat, answerable: true }));
        assert_eq!(fd_stat_call(libc::SYS_fstat as i64, &args(&[3, 0x20])), None, "an ordinary descriptor runs free");
        assert_eq!(fd_stat_call(libc::SYS_fstat as i64, &args(&[b - 1, 0x20])), None);
        let at = libc::AT_FDCWD as u32 as u64;
        let e = libc::AT_EMPTY_PATH as u64;
        assert_eq!(fd_stat_call(libc::SYS_newfstatat as i64, &args(&[at, 1, 2, e])), None, "AT_FDCWD is negative, never a twin");
        let n = fd_stat_call(libc::SYS_newfstatat as i64, &args(&[b + 5, 0x10, 0x30, e])).unwrap();
        assert_eq!(n, FdStatCall { fd: b as i32 + 5, path: Some(0x10), buf: 0x30, form: StatForm::Stat, answerable: true });
        assert_eq!(fd_stat_call(libc::SYS_newfstatat as i64, &args(&[b, 0x10, 0x30, 0])), None, "a path stat relative to the descriptor is not a descriptor stat");
        assert!(!fd_stat_call(libc::SYS_newfstatat as i64, &args(&[b, 1, 2, e | 0x8000_0000])).unwrap().answerable, "an unknown bit: the kernel's");
        let x = fd_stat_call(libc::SYS_statx as i64, &args(&[b, 0x10, e, 0x7ff, 0x40])).unwrap();
        assert_eq!(x, FdStatCall { fd: b as i32, path: Some(0x10), buf: 0x40, form: StatForm::Statx { mask: 0x7ff, sync: 0 }, answerable: true });
        assert!(!fd_stat_call(libc::SYS_statx as i64, &args(&[b, 1, e | 0x6000, 0x7ff, 2])).unwrap().answerable);
        assert_eq!(fd_stat_call(libc::SYS_statx as i64, &args(&[b, 1, 0, 0x7ff, 2])), None);
        assert_eq!(fd_stat_call(libc::SYS_openat as i64, &args(&[b, 1, 0])), None);
    }

    #[test]
    fn the_twin_slot_is_the_lowest_free_number_from_the_base_below_the_limit() {
        let b = TWIN_FD_BASE as i32;
        assert_eq!(twin_fd_slot(&[0, 1, 2, 3], 1024), Some(b));
        assert_eq!(twin_fd_slot(&[0, 1, 2, b, b + 1], 1024), Some(b + 2));
        assert_eq!(twin_fd_slot(&[0, 1, 2], TWIN_FD_BASE as u64), None, "a soft limit at the base: no room");
        assert_eq!(twin_fd_slot(&[b], TWIN_FD_BASE as u64 + 1), None, "the one slot taken");
        assert_eq!(twin_fd_slot(&[], u64::MAX), Some(b), "unlimited");
    }

    #[test]
    fn the_soft_nofile_limit_is_read_from_proc_limits() {
        let t = "Limit                     Soft Limit           Hard Limit           Units     \nMax cpu time              unlimited            unlimited            seconds   \nMax open files            1024                 524288               files     \n";
        assert_eq!(soft_nofile(t), Some(1024));
        assert_eq!(soft_nofile("Max open files            unlimited            unlimited            files\n"), Some(u64::MAX));
        assert_eq!(soft_nofile("Max processes 10 10 processes\n"), None);
    }

    #[test]
    fn the_answer_keeps_the_twins_size_with_the_real_files_identity() {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_size = 24;
        st.st_dev = 1;
        st.st_ino = 2;
        st.st_nlink = 1;
        let h = with_identity(st, 0x0803, 4242);
        assert_eq!((h.st_dev as u64, h.st_ino as u64, h.st_size, h.st_nlink as u64), (0x0803, 4242, 24, 1));
        let mut sx: libc::statx = unsafe { std::mem::zeroed() };
        sx.stx_size = 24;
        let hx = with_identity_x(sx, libc::makedev(8, 3) as u64, 4242);
        assert_eq!((hx.stx_dev_major, hx.stx_dev_minor, hx.stx_ino, hx.stx_size), (8, 3, 4242, 24));
    }

    fn args(v: &[u64]) -> [u64; 6] {
        let mut a = [0u64; 6];
        a[..v.len()].copy_from_slice(v);
        a
    }

    #[test]
    fn newfstatat_decodes_follow_and_the_flags_it_answers() {
        let at = libc::AT_FDCWD as u32 as u64;
        let c = stat_call(libc::SYS_newfstatat as i64, &args(&[at, 0x1000, 0x2000, 0])).unwrap();
        assert_eq!(c, StatCall { dirfd: libc::AT_FDCWD, path: 0x1000, buf: 0x2000, follow: true, form: StatForm::Stat, answerable: true });
        let l = stat_call(libc::SYS_newfstatat as i64, &args(&[3, 0x1000, 0x2000, libc::AT_SYMLINK_NOFOLLOW as u64])).unwrap();
        assert!(!l.follow && l.answerable && l.dirfd == 3);
        let na = stat_call(libc::SYS_newfstatat as i64, &args(&[at, 1, 2, libc::AT_NO_AUTOMOUNT as u64])).unwrap();
        assert!(na.answerable, "AT_NO_AUTOMOUNT changes nothing the guard answers");
        // P0 4b (2026-10-07): AT_EMPTY_PATH with a path is that path's stat
        // (an empty path never names a twinned leaf: the prefilter passes it
        // on); with AT_SYMLINK_NOFOLLOW, that lstat. Unknown bits: the kernel's.
        let e = stat_call(libc::SYS_newfstatat as i64, &args(&[at, 1, 2, libc::AT_EMPTY_PATH as u64])).unwrap();
        assert!(e.answerable && e.follow, "{e:?}");
        let el = stat_call(libc::SYS_newfstatat as i64, &args(&[at, 1, 2, (libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW) as u64])).unwrap();
        assert!(el.answerable && !el.follow, "{el:?}");
        assert!(!stat_call(libc::SYS_newfstatat as i64, &args(&[at, 1, 2, 0x8000_0000])).unwrap().answerable);
    }

    #[test]
    fn statx_decodes_mask_sync_and_refuses_what_the_kernel_refuses() {
        let at = libc::AT_FDCWD as u32 as u64;
        let c = stat_call(libc::SYS_statx as i64, &args(&[at, 0x1000, 0x2000 /* AT_STATX_FORCE_SYNC */, 0x7ff, 0x3000])).unwrap();
        assert_eq!(c, StatCall { dirfd: libc::AT_FDCWD, path: 0x1000, buf: 0x3000, follow: true, form: StatForm::Statx { mask: 0x7ff, sync: 0x2000 }, answerable: true });
        let l = stat_call(libc::SYS_statx as i64, &args(&[at, 1, libc::AT_SYMLINK_NOFOLLOW as u64, 0xfff, 2])).unwrap();
        assert!(!l.follow && l.answerable);
        assert!(!stat_call(libc::SYS_statx as i64, &args(&[at, 1, 0x6000, 0x7ff, 2])).unwrap().answerable, "both sync bits: EINVAL, the kernel's to say");
        assert!(!stat_call(libc::SYS_statx as i64, &args(&[at, 1, 0, STATX_RESERVED as u64, 2])).unwrap().answerable, "a reserved mask bit: EINVAL");
        let e = stat_call(libc::SYS_statx as i64, &args(&[at, 1, libc::AT_EMPTY_PATH as u64, 0x7ff, 2])).unwrap();
        assert!(e.answerable && e.follow, "AT_EMPTY_PATH with a path (P0 4b): {e:?}");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn legacy_stat_and_lstat_name_a_path() {
        let s = stat_call(libc::SYS_stat as i64, &args(&[0x10, 0x20])).unwrap();
        assert_eq!(s, StatCall { dirfd: libc::AT_FDCWD, path: 0x10, buf: 0x20, follow: true, form: StatForm::Stat, answerable: true });
        let l = stat_call(libc::SYS_lstat as i64, &args(&[0x10, 0x20])).unwrap();
        assert_eq!(l, StatCall { dirfd: libc::AT_FDCWD, path: 0x10, buf: 0x20, follow: false, form: StatForm::Stat, answerable: true });
        assert!(is_stat_nr(libc::SYS_stat as i64));
        assert!(is_stat_nr(libc::SYS_lstat as i64), "routed to the stat handler when the filter traps lstat (LstatTrap)");
        assert_eq!(lstat_nrs_by_number(), vec![libc::SYS_lstat as i64]);
        assert!(!stat_nrs_by_number().contains(&(libc::SYS_lstat as i64)), "never with the follow forms: the filter adds it only under LstatTrap");
    }

    #[test]
    fn fstat_and_other_calls_are_not_stat_calls() {
        assert!(stat_call(libc::SYS_fstat as i64, &args(&[3, 0x20])).is_none(), "fstat reads the descriptor, which is the twin already");
        assert!(!is_stat_nr(libc::SYS_fstat as i64));
        assert!(!is_stat_nr(libc::SYS_openat as i64));
        assert!(is_stat_nr(libc::SYS_newfstatat as i64) && is_stat_nr(libc::SYS_statx as i64));
    }

    #[test]
    fn leaf_is_the_last_component_lexically() {
        assert_eq!(leaf_of(b"/r/.git/objects/pack/pack-1.pack"), Some(&b"pack-1.pack"[..]));
        assert_eq!(leaf_of(b"pack-1.pack"), Some(&b"pack-1.pack"[..]));
        assert_eq!(leaf_of(b"dir/name//"), Some(&b"name"[..]));
        for none in [&b""[..], b"/", b"//", b".", b"a/..", b"a/./"] {
            assert_eq!(leaf_of(none), None, "{:?}", String::from_utf8_lossy(none));
        }
    }

    #[test]
    fn the_prefilter_admits_only_registered_names() {
        let names = StatNames::new(["/r/.git/objects/pack/pack-1.pack", "/r/.git/objects/pack/pack-1.idx", "/home/u/.aws/credentials"]);
        assert!(names.candidate(b".git/objects/pack/pack-1.pack"));
        assert!(names.candidate(b"/elsewhere/pack-1.idx"), "the name is enough to look closer; identity decides");
        assert!(names.candidate(b"credentials"));
        assert!(!names.candidate(b"/r/.git/objects/pack/pack-2.pack"));
        assert!(!names.candidate(b"README.md"));
        assert!(!names.candidate(b""));
        assert!(StatNames::new([]).is_empty());
    }

    #[test]
    fn another_leaf_is_resolved_where_a_symlink_or_a_hard_link_can_reach_a_registered_file() {
        let names = StatNames::new(["/home/u/.env", "/r/.git/objects/pack/pack-1.pack"]);
        assert_eq!(names.leaf(b"/home/u/.env"), Leaf::Registered);
        assert_eq!(names.leaf(b"elsewhere/pack-1.pack"), Leaf::Registered);
        assert_eq!(names.leaf(b"/tmp/x"), Leaf::Other);
        for none in [&b""[..], b"/", b".", b"a/.."] {
            assert_eq!(names.leaf(none), Leaf::NoFile, "{:?}", String::from_utf8_lossy(none));
        }
        let never = || -> bool { panic!("the link count is not asked here") };
        // A registered leaf: resolved, whatever the form (as before 4c).
        assert_eq!(stat_probe(Leaf::Registered, true, never), StatProbe::Resolve);
        assert_eq!(stat_probe(Leaf::Registered, false, never), StatProbe::Resolve);
        // `stat -L /tmp/x` where x -> ~/.env: a stat that follows another
        // leaf may cross a symlink to the secret (P0 4c): resolved, without
        // asking the link count.
        assert_eq!(stat_probe(Leaf::Other, true, never), StatProbe::Resolve);
        // An lstat of another leaf: a symlink there is its own metadata, so
        // only a hard link of another name reaches the secret.
        assert_eq!(stat_probe(Leaf::Other, false, || false), StatProbe::Continue, "no registered file has another link: nothing to resolve");
        assert_eq!(stat_probe(Leaf::Other, false, || true), StatProbe::Resolve, "a registered file with st_nlink > 1: its other name may be this one");
        // A directory name never reaches a regular file.
        assert_eq!(stat_probe(Leaf::NoFile, true, never), StatProbe::Continue);
        assert_eq!(stat_probe(Leaf::NoFile, false, never), StatProbe::Continue);
    }

    #[test]
    fn every_entry_with_a_twin_answers_with_it() {
        let e = |kind: Option<&str>, twin: &str| SecretEntry { path: "/r/p".into(), twin: twin.into(), level: "no-model".into(), kind: kind.map(String::from) };
        assert_eq!(stat_twin_of(&e(Some("object"), "/c/p.pack")), Some("/c/p.pack"));
        assert_eq!(stat_twin_of(&e(None, "/t/cred")), Some("/t/cred"), "a protected file: the placeholder copy, as the bind shows it");
        assert_eq!(stat_twin_of(&e(Some("deny"), "/t/denied")), Some("/t/denied"), "a deny entry: its empty mode-000 stand-in");
        assert_eq!(stat_twin_of(&e(Some("object"), "")), None, "no twin: the kernel answers");
    }

    #[test]
    fn the_answer_is_the_kernel_struct_byte_for_byte() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(std::mem::size_of::<libc::stat>(), 144);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(std::mem::size_of::<libc::stat>(), 128);
        assert_eq!(std::mem::size_of::<libc::statx>(), 256);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_size = 0x0102_0304;
        let b = stat_bytes(&st);
        assert_eq!(b.len(), std::mem::size_of::<libc::stat>());
        let off = (std::ptr::addr_of!(st.st_size) as usize) - (&st as *const libc::stat as usize);
        assert_eq!(&b[off..off + 8], &0x0102_0304i64.to_ne_bytes());
        let mut sx: libc::statx = unsafe { std::mem::zeroed() };
        sx.stx_size = 77;
        let bx = statx_bytes(&sx);
        let off = (std::ptr::addr_of!(sx.stx_size) as usize) - (&sx as *const libc::statx as usize);
        assert_eq!(&bx[off..off + 8], &77u64.to_ne_bytes());
    }
}
