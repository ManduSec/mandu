//! local_exits — confidentiality plan 13 §9 R4 (b), the exits that are paths:
//! where a holder's write lands somewhere other than this machine's own
//! storage for this user, though no `connect()` happens (decided 2026-10-03,
//! plan 13 §4.6 and §4.9).
//!
//!   - **A network or FUSE mount** (NFS, SMB/CIFS, 9p, Ceph, AFS, every FUSE
//!     file system: sshfs, rclone mount, virtiofs, ntfs-3g, …): the write is a
//!     send at the VFS. The mount is a destination
//!     `mount:<fstype>:<source>`; a holder's write-capable open of a file on
//!     one, or a create in a directory on one, is refused unless every datum
//!     it holds is bound to that destination (the binding is matched by
//!     equality, like a `unix:` one). The file system is read from the
//!     descriptor the guard opened (`fstatfs`'s magic, then its mount's row
//!     in `mountinfo` by `mnt_id`), never from a path, so no rename races it.
//!     Either says remote ⇒ remote; neither readable ⇒ refused. A stacking
//!     file system (overlayfs, eCryptfs, shiftfs) is judged by the mount its
//!     writes land on (2026-10-04): an overlay by its `upperdir=`, the other
//!     two by their source directory, each resolved and judged like any
//!     destination; a stack whose lower half cannot be found is remote
//!     (`mount:<fstype>:<source>`), and aufs always is. That path is a string
//!     the mounter chose and resolved in its own view at mount time, so it is
//!     followed only for a stack the tree cannot have made (P0 5d,
//!     2026-10-09): one whose superblock is mounted in the guard's own mount
//!     namespace (the launcher's, which the tree cannot mount in), and there
//!     the path must resolve in the guard's own view (the tracee's view is
//!     judged beside it). A stack mounted only in a namespace of the tree's
//!     own (a user namespace it made) is remote, named by itself, whatever
//!     its `upperdir=` says: the tree could have laid a local directory at
//!     that path in every view, or unmounted the remote one under it, while
//!     the real upper is remote (`stack_known`, `lands_of`). The same rule holds
//!     for the names a holder makes or changes and the attributes it sets
//!     there (`mkdir`, `rename`, `link`, `symlink`, `mknod`, `unlink`,
//!     `truncate`, `chmod`, the `setxattr` family), and for a writable
//!     descriptor of a file there passed to a holder over `SCM_RIGHTS`.
//!   - **Another local user.** A file a holder writes is labelled (plan 13
//!     §4.6) and another user's processes are not interposed: the guard
//!     creates the file without group or other bits and strips them from an
//!     existing file before the holder gets its descriptor (or, for a file
//!     the holder held before its taint, before the raw open is answered).
//!     A mode it cannot narrow refuses the open. A later `chmod` or POSIX
//!     ACL that would open a derived file to others again is refused.
//!   - **A device node.** A holder's write-capable open of a character or
//!     block device is refused unless the device is the terminal or a sink
//!     that keeps nothing (`/dev/null`, `/dev/zero`, `/dev/full`, the random
//!     devices, `/dev/tty`, `/dev/ptmx`, a pseudo-terminal, a virtual
//!     console). A serial port, a printer, a USB device, a disk, `/dev/kmsg`
//!     (the kernel log other users read) and `/dev/fuse` (how a FUSE server
//!     answers its readers) are refused, with no binding; so is such a
//!     device's descriptor passed to a holder over `SCM_RIGHTS`.
//!
//! The display server needs nothing here: its socket is a Unix socket, and
//! a holder reaches only its `unix:` bindings (`guard_kernel::
//! unix_path_verdict`, the taint-time sweep's `unix_bindings_admit`).
//!
//! Pure: decoding and decisions only. The guard's kernel half reads the
//! numbers from the descriptors (`guard_kernel`, `guard_send::sweep_from`).
//! `Mandu-new`.

use std::os::unix::io::RawFd;

/// `statfs.f_type` values of file systems whose writes leave this machine
/// or are served by a user-space process (linux/magic.h, and the out-of-tree
/// file systems' own). The low 32 bits are compared: the kernel stores the
/// magic in an unsigned long.
pub const REMOTE_MAGICS: &[(u32, &str)] = &[
    (0x0000_6969, "nfs"),
    (0x0000_517B, "smbfs"),
    (0xFF53_4D42, "cifs"),
    (0xFE53_4D42, "smb3"),
    (0x0102_1997, "9p"),
    (0x6573_5546, "fuse"),
    (0x00C3_6400, "ceph"),
    (0x5346_414F, "afs"),
    (0x6B41_4653, "afs"),
    (0x7375_7245, "coda"),
    (0x0000_564C, "ncpfs"),
    (0x0BD0_0BD0, "lustre"),
    (0x1983_0326, "beegfs"),
    (0x4750_4653, "gpfs"),
    (0x2003_0528, "orangefs"),
    (0x7461_636F, "ocfs2"),
    (0x0116_1970, "gfs2"),
    (0x786F_4256, "vboxsf"),
    (0x00C0_FFEE, "hostfs"),
];

/// Is this `f_type` a file system whose writes leave the machine? Its name
/// when it is.
pub fn remote_fs_magic(f_type: u64) -> Option<&'static str> {
    let low = (f_type & 0xFFFF_FFFF) as u32;
    REMOTE_MAGICS.iter().find(|(m, _)| *m == low).map(|(_, n)| *n)
}

/// Is a `mountinfo` file-system type one whose writes leave the machine (or
/// are served by a user-space process)? Every FUSE type (`fuse`,
/// `fuse.<name>`, `fuseblk`), the network file systems and the host shares.
pub fn remote_fstype(fstype: &str) -> bool {
    let t = fstype.to_ascii_lowercase();
    if t == "fuse" || t == "fuseblk" || t.starts_with("fuse.") || t == "virtiofs" {
        return true;
    }
    if t.starts_with("nfs") || t.starts_with("smb") || t.starts_with("ceph") {
        return true;
    }
    matches!(
        t.as_str(),
        "cifs" | "9p" | "afs" | "coda" | "ncpfs" | "ncp" | "lustre" | "beegfs" | "gpfs" | "orangefs" | "pvfs2" | "ocfs2" | "gfs2" | "glusterfs" | "davfs" | "vboxsf" | "vmhgfs" | "hostfs" | "drvfs" | "sshfs" | "s3fs"
    )
}

/// One `mountinfo` row, as far as the destination needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountRow {
    pub id: u64,
    pub mount_point: String,
    pub fstype: String,
    pub source: String,
    /// The super options as `mountinfo` prints them (still escaped: a comma
    /// inside a value is `\054`, so a raw comma separates options).
    pub superopts: String,
}

/// `mountinfo`'s octal escapes (`\040` for a space, `\011`, `\012`, `\134`).
pub(crate) fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 4 <= b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let v = (b[i + 1] - b'0') as u32 * 64 + (b[i + 2] - b'0') as u32 * 8 + (b[i + 3] - b'0') as u32;
            if v <= 0xFF {
                out.push(v as u8);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse one `/proc/<pid>/mountinfo` line (proc(5)): `id parent major:minor
/// root mount-point options [optional fields…] - fstype source super-options`.
pub fn parse_mountinfo_line(line: &str) -> Option<MountRow> {
    let (head, tail) = line.split_once(" - ")?;
    let mut h = head.split(' ');
    let id = h.next()?.parse::<u64>().ok()?;
    let _parent = h.next()?;
    let _dev = h.next()?;
    let _root = h.next()?;
    let mount_point = unescape(h.next()?);
    let mut t = tail.split(' ');
    let fstype = unescape(t.next()?);
    let source = unescape(t.next()?);
    let superopts = t.next().unwrap_or("").to_string();
    if fstype.is_empty() {
        return None;
    }
    Some(MountRow { id, mount_point, fstype, source, superopts })
}

/// The row of mount `id` in a `mountinfo` text.
pub fn mount_row(mountinfo: &str, id: u64) -> Option<MountRow> {
    mountinfo.lines().filter_map(parse_mountinfo_line).find(|r| r.id == id)
}

/// `mnt_id:` of a `/proc/<pid>/fdinfo/<fd>` text.
pub fn fdinfo_mnt_id(fdinfo: &str) -> Option<u64> {
    fdinfo.lines().find_map(|l| l.strip_prefix("mnt_id:")).and_then(|v| v.trim().parse().ok())
}

/// The destination a mount is named by (plan 13 §4.6):
/// `mount:<fstype>:<source>`.
pub fn mount_destination(fstype: &str, source: &str) -> String {
    format!("mount:{fstype}:{source}")
}

/// Is a binding a host binding (what the INET legs parse as a guard spec)?
/// A `unix:` and a `mount:` binding belong to other legs; handed to the
/// spec parser they would fail it, and with it every host binding.
pub fn is_host_binding(b: &str) -> bool {
    !b.starts_with("unix:") && !b.starts_with("mount:")
}

/// Do a holder's bindings admit this mount destination? By equality only.
pub fn mount_bound(bindings: &[String], dest: &str) -> bool {
    bindings.iter().any(|b| b.trim() == dest)
}

/// `statfs.f_type` of the stacking file systems: their writes land on
/// another mount (linux/magic.h; aufs and shiftfs out of tree).
pub const OVERLAYFS_MAGIC: u32 = 0x794C_7630;
pub const ECRYPTFS_MAGIC: u32 = 0x0000_F15F;
pub const AUFS_MAGIC: u32 = 0x6175_6673;
pub const SHIFTFS_MAGIC: u32 = 0x6A65_6A62;

/// Where a stacking file system's writes land (`stacking`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stack {
    /// Not a stacking file system: judged as itself.
    No,
    /// An overlay with no upper layer: nothing can be written through it.
    ReadOnly,
    /// Its writes land in this directory (an overlay's `upperdir=`, an
    /// eCryptfs or shiftfs source), as the mount names it.
    Lands(String),
    /// A stacking file system whose lower half the guard cannot name (aufs,
    /// a missing row, a relative path): judged remote.
    Undetermined,
}

/// The value of option `key` in a `mountinfo` super options field,
/// unescaped. The last one counts, as the kernel's parser keeps it.
pub fn superopt(superopts: &str, key: &str) -> Option<String> {
    superopts.split(',').filter_map(|o| o.split_once('=')).filter(|(k, _)| *k == key).last().map(|(_, v)| unescape(v))
}

/// Is this file system one that stacks on another, and where do its writes
/// land? By the magic or the type name; the row says where. Pure.
pub fn stacking(f_type: u64, row: Option<&MountRow>) -> Stack {
    let low = (f_type & 0xFFFF_FFFF) as u32;
    let name = row.map(|r| r.fstype.to_ascii_lowercase()).unwrap_or_default();
    let abs = |p: String| if p.starts_with('/') { Stack::Lands(p) } else { Stack::Undetermined };
    if low == OVERLAYFS_MAGIC || name == "overlay" || name == "overlayfs" {
        let Some(r) = row else { return Stack::Undetermined };
        return match superopt(&r.superopts, "upperdir") {
            Some(up) => abs(up),
            None => Stack::ReadOnly,
        };
    }
    if low == ECRYPTFS_MAGIC || low == SHIFTFS_MAGIC || name == "ecryptfs" || name == "shiftfs" {
        return match row {
            Some(r) => abs(r.source.clone()),
            None => Stack::Undetermined,
        };
    }
    if low == AUFS_MAGIC || name == "aufs" {
        return Stack::Undetermined;
    }
    Stack::No
}

/// Where a stacking file system's writes were found to land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lands {
    /// Nowhere: a read-only overlay.
    Nowhere,
    /// The directory, judged in each view it resolved in (the guard's, the
    /// tracee's): any remote ⇒ remote.
    On(Vec<FsFacts>),
    /// Not found in the guard's own view, or not to be named: remote.
    Undetermined,
    /// A stack mounted only in a namespace of the tree's own (P0 5d): its
    /// `upperdir=` is not followed, and it is remote, named by itself.
    Foreign,
}

/// P0 5d (2026-10-09): may the guard follow a stacking mount's own account of
/// where its writes land? Only when its superblock is mounted in the guard's
/// own mount namespace: the mount's row was found there by `mnt_id`
/// (`in_own`), or a row there has the same device (`sb_dev`, the row's
/// `major:minor`: the superblock, shared by every copy and bind of it) and
/// type. The tree cannot mount in the guard's namespace (the launcher's), and
/// a mount it makes in a namespace of its own never propagates there, so a
/// superblock seen there was not made by the tree. Pure.
pub fn stack_known(in_own: bool, sb_dev: u64, fstype: &str, own: &[crate::visible_mounts::Row]) -> bool {
    in_own || own.iter().any(|r| r.dev == sb_dev && r.row.fstype.eq_ignore_ascii_case(fstype))
}

/// P0 5d: where a stacking mount's writes land, from what the guard found:
/// `known` (`stack_known`), and the directory its row names judged in the
/// guard's own view and in the tracee's (`None`: it did not resolve there).
/// A stack the tree may have made is `Foreign`; a known one whose directory
/// the guard's own view does not resolve is `Undetermined` (the tracee's
/// view alone could be the tree's); else every view found is judged. Pure.
pub fn lands_of(known: bool, own_view: Option<FsFacts>, tracee_view: Option<FsFacts>) -> Lands {
    if !known {
        return Lands::Foreign;
    }
    match own_view {
        None => Lands::Undetermined,
        Some(o) => Lands::On(std::iter::once(o).chain(tracee_view).collect()),
    }
}

/// What the guard knows about the file system a descriptor is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsFacts {
    /// `f_type` from `fstatfs`, `st_dev`, and the mount's row (when found).
    Known { f_type: u64, dev: u64, row: Option<MountRow> },
    /// A stacking file system (`stacking`): `name` is its own destination
    /// (`mount:<fstype>:<source>`), `lands` where its writes go.
    Stacked { name: String, dev: u64, lands: Lands },
    /// Nothing could be read.
    Unknown,
}

/// The verdict on a holder's write onto a file system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountVerdict {
    /// This machine's own storage.
    Local,
    /// Leaves the machine: the destination it is named by.
    Remote(String),
}

/// Decide from the facts (fail-closed: unknown is remote). `extra_devs`: the
/// file systems (by `st_dev`) a test counts as remote, no FUSE server being
/// at hand there; empty in production.
pub fn mount_verdict(facts: &FsFacts, extra_devs: &[u64]) -> MountVerdict {
    match facts {
        FsFacts::Unknown => MountVerdict::Remote("mount:unknown".into()),
        FsFacts::Stacked { name, dev, lands } => {
            if extra_devs.contains(dev) {
                return MountVerdict::Remote(name.clone());
            }
            match lands {
                Lands::Nowhere => MountVerdict::Local,
                Lands::Undetermined | Lands::Foreign => MountVerdict::Remote(name.clone()),
                Lands::On(views) if views.is_empty() => MountVerdict::Remote(name.clone()),
                Lands::On(views) => views.iter().map(|v| mount_verdict(v, extra_devs)).find(|v| *v != MountVerdict::Local).unwrap_or(MountVerdict::Local),
            }
        }
        FsFacts::Known { f_type, dev, row } => {
            let by_magic = remote_fs_magic(*f_type);
            let by_name = row.as_ref().is_some_and(|r| remote_fstype(&r.fstype));
            if by_magic.is_none() && !by_name && !extra_devs.contains(dev) {
                return MountVerdict::Local;
            }
            MountVerdict::Remote(match row {
                Some(r) => mount_destination(&r.fstype, &r.source),
                None => mount_destination(by_magic.unwrap_or("unknown"), "unknown"),
            })
        }
    }
}

/// A mode with group and other bits stripped, when it has any (the file
/// type bits dropped).
pub fn narrowed_mode(st_mode: u32) -> Option<u32> {
    let perm = st_mode & 0o7777;
    (perm & 0o077 != 0).then_some(perm & !0o077)
}

/// The mode a holder's create asks for, narrowed (the umask applies on top).
pub fn holder_create_mode(mode: u32) -> u32 {
    mode & !0o077
}

/// Would this mode let another local user at the file (any group or other
/// bit)?
pub fn mode_opens_to_others(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// May a holder open this device to write? Only the terminal and the sinks
/// that keep nothing. Block devices never.
pub fn device_write_allowed(block: bool, major: u32, minor: u32) -> bool {
    if block {
        return false;
    }
    match major {
        // mem: null, zero, full, random, urandom.
        1 => matches!(minor, 3 | 5 | 7 | 8 | 9),
        // the virtual consoles tty0..tty63 (64 and up are serial ports).
        4 => minor < 64,
        // /dev/tty and /dev/ptmx (not /dev/console, 5:1).
        5 => matches!(minor, 0 | 2),
        // the Unix98 pseudo-terminal slaves.
        136..=143 => true,
        _ => false,
    }
}

/// `major` / `minor` of an `st_rdev` (glibc's encoding, as `makedev`).
pub fn dev_major_minor(rdev: u64) -> (u32, u32) {
    let major = ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff);
    let minor = (rdev & 0xff) | ((rdev >> 12) & !0xff);
    (major as u32, minor as u32)
}

/// The destination a refused device write is named by.
pub fn device_destination(path: &str, major: u32, minor: u32) -> String {
    format!("device:{path} ({major}:{minor})")
}

// ── reading the facts (no privilege; a descriptor or `/proc`) ──────────────

/// `fstatfs` + `fstat` of a descriptor the guard holds, and its mount's row
/// (`mnt_id` from the guard's own `fdinfo`, looked up in `pid`'s
/// `mountinfo`, then the guard's: the tracee may be in another mount
/// namespace, and a mount id is unique system-wide). A stacking file system
/// is followed to where its writes land (`stacking`, `Lands`) when its
/// superblock is mounted in the guard's own namespace (`stack_known`), and
/// is `Lands::Foreign` (remote) when it is not.
pub fn fd_fs_facts(fd: RawFd, pid: Option<i32>) -> FsFacts {
    fd_facts_at(fd, pid, 0)
}

/// How deep a stack of stacking file systems is followed; deeper is
/// `Lands::Undetermined` (remote).
pub const STACK_DEPTH: u32 = 4;

fn fd_facts_at(fd: RawFd, pid: Option<i32>, depth: u32) -> FsFacts {
    // SAFETY: fstatfs / fstat into zeroed buffers, on a descriptor we hold.
    let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut sf) } != 0 || unsafe { libc::fstat(fd, &mut st) } != 0 {
        return FsFacts::Unknown;
    }
    let mnt = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).ok().as_deref().and_then(fdinfo_mnt_id);
    let found = mnt.and_then(|id| row_for(id, pid));
    let row = found.as_ref().map(|f| f.row.clone());
    let f_type = sf.f_type as u64;
    let lands = match stacking(f_type, row.as_ref()) {
        Stack::No => return FsFacts::Known { f_type, dev: st.st_dev, row },
        Stack::ReadOnly => Lands::Nowhere,
        Stack::Undetermined => Lands::Undetermined,
        Stack::Lands(_) if depth >= STACK_DEPTH => Lands::Undetermined,
        Stack::Lands(dir) => {
            // `Lands` comes only from a row, so `found` is there; the
            // guard's own table unreadable: not known (remote).
            let known = found.as_ref().is_some_and(|f| {
                f.in_own || std::fs::read_to_string("/proc/self/mountinfo").is_ok_and(|t| stack_known(false, f.dev, &f.row.fstype, &crate::visible_mounts::parse_rows(&t)))
            });
            if known {
                let (own, theirs) = lower_views(&dir, pid, depth + 1);
                lands_of(true, own, theirs)
            } else {
                lands_of(false, None, None)
            }
        }
    };
    let name = match &row {
        Some(r) => mount_destination(&r.fstype, &r.source),
        None => mount_destination("stacked", "unknown"),
    };
    FsFacts::Stacked { name, dev: st.st_dev, lands }
}

/// `openat2`'s `struct open_how`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;

/// The directory a stack's writes land in, judged as the guard's own view
/// resolves its path and as the tracee's does (inside its root,
/// `RESOLVE_IN_ROOT`): `(own, tracee's)`, `None` where it does not resolve.
fn lower_views(dir: &str, pid: Option<i32>, depth: u32) -> (Option<FsFacts>, Option<FsFacts>) {
    let Ok(c) = std::ffi::CString::new(dir) else { return (None, None) };
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
    // SAFETY: open of a NUL-terminated path, O_PATH; closed below.
    let own_fd = unsafe { libc::open(c.as_ptr(), flags) };
    let own = (own_fd >= 0).then(|| {
        let f = fd_facts_at(own_fd, pid, depth);
        // SAFETY: our own descriptor.
        unsafe { libc::close(own_fd) };
        f
    });
    let mut theirs = None;
    if let Some(p) = pid {
        let Ok(root) = std::ffi::CString::new(format!("/proc/{p}/root")) else { return (own, None) };
        // SAFETY: the tracee's root, O_PATH; closed below.
        let r = unsafe { libc::open(root.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if r >= 0 {
            let how = OpenHow { flags: flags as u64, mode: 0, resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS };
            // SAFETY: openat2 relative to a descriptor we hold, with a
            // NUL-terminated path and an open_how of the size we pass.
            let fd = unsafe { libc::syscall(libc::SYS_openat2, r, c.as_ptr(), &how as *const OpenHow, std::mem::size_of::<OpenHow>()) } as i32;
            if fd >= 0 {
                theirs = Some(fd_facts_at(fd, pid, depth));
                // SAFETY: our own descriptor.
                unsafe { libc::close(fd) };
            }
            // SAFETY: our own descriptor.
            unsafe { libc::close(r) };
        }
    }
    (own, theirs)
}

/// The same facts for a descriptor of another process, through its magic
/// link (the taint-time sweep: a file a process held before its taint).
pub fn proc_fd_fs_facts(pid: i32, fd: RawFd) -> FsFacts {
    path_fs_facts(&format!("/proc/{pid}/fd/{fd}"), Some(pid))
}

/// The facts for a path (followed), through an `O_PATH` descriptor of it
/// (so its mount is known by id).
pub fn path_fs_facts(path: &str, pid: Option<i32>) -> FsFacts {
    let Ok(c) = std::ffi::CString::new(path) else { return FsFacts::Unknown };
    // SAFETY: open of a NUL-terminated path, O_PATH; closed below.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return FsFacts::Unknown;
    }
    let facts = fd_fs_facts(fd, pid);
    // SAFETY: our own descriptor.
    unsafe { libc::close(fd) };
    facts
}

/// A mount's row as the guard found it: its device (`major:minor`, the
/// superblock) and whether it was in the guard's own table.
struct FoundRow {
    row: MountRow,
    dev: u64,
    in_own: bool,
}

/// The row and device of mount `id` in a `mountinfo` text.
pub fn mount_row_dev(mountinfo: &str, id: u64) -> Option<(MountRow, u64)> {
    mountinfo.lines().filter_map(|l| Some((parse_mountinfo_line(l)?, crate::visible_mounts::mountinfo_dev(l)?))).find(|(r, _)| r.id == id)
}

fn row_for(id: u64, pid: Option<i32>) -> Option<FoundRow> {
    let theirs = pid.and_then(|p| std::fs::read_to_string(format!("/proc/{p}/mountinfo")).ok()).and_then(|t| mount_row_dev(&t, id));
    if let Some((row, dev)) = theirs {
        return Some(FoundRow { row, dev, in_own: false });
    }
    let (row, dev) = std::fs::read_to_string("/proc/self/mountinfo").ok().and_then(|t| mount_row_dev(&t, id))?;
    Some(FoundRow { row, dev, in_own: true })
}

/// How a refusal names a process outside the guard's tree that receives
/// what a holder writes into a pipe or socket pair (P0 2b, 2026-10-09):
/// `"<this> (pid N, pipe:[ino])"`.
pub const OUTSIDE_RECEIVER: &str = "a program outside Mandu's watch";

/// The phrase a refusal of the taint-time sweep is named by (`dest` as the
/// sweep's judges name it): a mount, a device, a file other users can read,
/// a program outside the guard's tree reading a pipe or socket pair, or
/// else a connection. `(infinitive, third person)`.
pub fn held_exit_phrase(dest: &str) -> (&'static str, &'static str) {
    if dest.starts_with("mount:") {
        ("hold open for writing a file on", "holds open for writing a file on")
    } else if dest.starts_with("device:") {
        ("hold open for writing", "holds open for writing")
    } else if dest.starts_with("other local users") {
        ("hold open for writing a file readable by", "holds open for writing a file readable by")
    } else if dest.starts_with(OUTSIDE_RECEIVER) {
        // P0 2b (2026-10-09): `guard_flow::outside_receiver`.
        ("write into a pipe or socket pair read by", "writes into a pipe or socket pair read by")
    } else {
        ("hold a connection to", "holds a connection to")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_network_and_fuse_magics_are_remote_and_local_ones_are_not() {
        for (m, n) in [(0x6969u64, "nfs"), (0xFF53_4D42, "cifs"), (0xFE53_4D42, "smb3"), (0x0102_1997, "9p"), (0x6573_5546, "fuse"), (0x00C3_6400, "ceph")] {
            assert_eq!(remote_fs_magic(m), Some(n), "{m:#x}");
        }
        // The kernel's unsigned long, sign-extended by a 32-bit reading.
        assert_eq!(remote_fs_magic(0xFFFF_FFFF_FF53_4D42), Some("cifs"));
        // ext4, tmpfs, btrfs, xfs, overlay, proc.
        for m in [0xEF53u64, 0x0102_1994, 0x9123_683E, 0x5846_5342, 0x794C_7630, 0x9FA0] {
            assert_eq!(remote_fs_magic(m), None, "{m:#x}");
        }
    }

    #[test]
    fn every_fuse_type_and_the_network_names_are_remote() {
        for t in ["fuse", "fuseblk", "fuse.sshfs", "fuse.rclone", "fuse.gvfsd-fuse", "virtiofs", "nfs", "nfs4", "cifs", "smb3", "9p", "ceph", "glusterfs", "drvfs", "vboxsf", "NFS4"] {
            assert!(remote_fstype(t), "{t}");
        }
        for t in ["ext4", "tmpfs", "btrfs", "xfs", "overlay", "proc", "sysfs", "devtmpfs", "zfs", "f2fs", "squashfs", "fusectl"] {
            assert!(!remote_fstype(t), "{t}");
        }
    }

    #[test]
    fn mountinfo_rows_parse_with_optional_fields_and_escapes() {
        let mi = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
98 22 0:51 / /mnt/nas rw,relatime shared:40 master:3 - nfs4 nas.lan:/export/home rw,vers=4.2
120 22 0:60 / /home/u/remote\\040dir rw,nosuid - fuse.sshfs u@host:/srv rw,user_id=1000
";
        let r = mount_row(mi, 98).unwrap();
        assert_eq!((r.mount_point.as_str(), r.fstype.as_str(), r.source.as_str()), ("/mnt/nas", "nfs4", "nas.lan:/export/home"));
        let s = mount_row(mi, 120).unwrap();
        assert_eq!(s.mount_point, "/home/u/remote dir");
        assert_eq!(mount_destination(&s.fstype, &s.source), "mount:fuse.sshfs:u@host:/srv");
        assert!(mount_row(mi, 7).is_none());
        assert!(parse_mountinfo_line("garbage").is_none());
        assert_eq!(fdinfo_mnt_id("pos:\t0\nflags:\t02\nmnt_id:\t98\nino:\t5\n"), Some(98));
        assert_eq!(fdinfo_mnt_id("pos:\t0\n"), None);
    }

    #[test]
    fn the_verdict_is_remote_by_magic_or_by_name_and_unknown_is_remote() {
        let nfs_row = Some(MountRow { id: 98, mount_point: "/mnt/nas".into(), fstype: "nfs4".into(), source: "nas:/x".into(), superopts: String::new() });
        assert_eq!(mount_verdict(&FsFacts::Known { f_type: 0x6969, dev: 1, row: nfs_row.clone() }, &[]), MountVerdict::Remote("mount:nfs4:nas:/x".into()));
        // A name the magic table lacks still counts.
        let gl = Some(MountRow { id: 1, mount_point: "/g".into(), fstype: "glusterfs".into(), source: "g:/v".into(), superopts: String::new() });
        assert_eq!(mount_verdict(&FsFacts::Known { f_type: 0x1234, dev: 1, row: gl }, &[]), MountVerdict::Remote("mount:glusterfs:g:/v".into()));
        // No row found: still remote by magic, named as well as known.
        assert_eq!(mount_verdict(&FsFacts::Known { f_type: 0x6573_5546, dev: 1, row: None }, &[]), MountVerdict::Remote("mount:fuse:unknown".into()));
        assert_eq!(mount_verdict(&FsFacts::Known { f_type: 0xEF53, dev: 1, row: None }, &[]), MountVerdict::Local);
        assert_eq!(mount_verdict(&FsFacts::Unknown, &[]), MountVerdict::Remote("mount:unknown".into()));
        // The test hook: a local file system counted as remote by device.
        let tmp = Some(MountRow { id: 5, mount_point: "/dev/shm".into(), fstype: "tmpfs".into(), source: "tmpfs".into(), superopts: String::new() });
        assert_eq!(mount_verdict(&FsFacts::Known { f_type: 0x0102_1994, dev: 42, row: tmp.clone() }, &[42]), MountVerdict::Remote("mount:tmpfs:tmpfs".into()));
        assert_eq!(mount_verdict(&FsFacts::Known { f_type: 0x0102_1994, dev: 43, row: tmp }, &[42]), MountVerdict::Local);
    }

    #[test]
    fn mount_bindings_match_by_equality_and_never_reach_the_host_parser() {
        let b = vec!["api.example.com".to_string(), "mount:nfs4:nas:/x".to_string(), "unix:/run/pg".to_string()];
        assert!(mount_bound(&b, "mount:nfs4:nas:/x"));
        assert!(!mount_bound(&b, "mount:nfs4:nas:/y"));
        assert!(!mount_bound(&b, "mount:nfs4:nas"));
        let hosts: Vec<&String> = b.iter().filter(|h| is_host_binding(h)).collect();
        assert_eq!(hosts, vec!["api.example.com"]);
    }

    #[test]
    fn a_holders_files_lose_group_and_other_bits() {
        assert_eq!(narrowed_mode(0o100644), Some(0o600));
        assert_eq!(narrowed_mode(0o100755), Some(0o700));
        assert_eq!(narrowed_mode(0o104750), Some(0o4700));
        assert_eq!(narrowed_mode(0o100600), None);
        assert_eq!(narrowed_mode(0o100400), None);
        assert_eq!(holder_create_mode(0o666), 0o600);
        assert_eq!(holder_create_mode(0o777), 0o700);
        assert!(mode_opens_to_others(0o640));
        assert!(mode_opens_to_others(0o604));
        assert!(mode_opens_to_others(0o601));
        assert!(!mode_opens_to_others(0o700));
        assert!(!mode_opens_to_others(0o4700));
    }

    #[test]
    fn only_the_terminal_and_the_sinks_that_keep_nothing_take_a_holders_write() {
        for (maj, min) in [(1, 3), (1, 5), (1, 7), (1, 8), (1, 9), (5, 0), (5, 2), (136, 0), (136, 7), (143, 255), (4, 1), (4, 63)] {
            assert!(device_write_allowed(false, maj, min), "{maj}:{min}");
        }
        // /dev/mem, /dev/kmsg, /dev/console, a serial port, lp0, /dev/fuse,
        // /dev/net/tun, a USB-serial, hidraw, a sound card, the loop control.
        for (maj, min) in [(1, 1), (1, 11), (5, 1), (4, 64), (6, 0), (10, 229), (10, 200), (188, 0), (240, 0), (116, 3), (10, 237)] {
            assert!(!device_write_allowed(false, maj, min), "{maj}:{min}");
        }
        // Any block device, even with an allowed number.
        assert!(!device_write_allowed(true, 1, 3));
        assert!(!device_write_allowed(true, 8, 16));
    }

    #[test]
    // `big` spells glibc's makedev term by term, the no-op masks included.
    #[allow(clippy::identity_op)]
    fn rdev_decodes_as_glibc_encodes() {
        // makedev(1, 3), makedev(136, 4), makedev(259, 1048575) (a large minor).
        assert_eq!(dev_major_minor(0x103), (1, 3));
        assert_eq!(dev_major_minor((136 << 8) | 4), (136, 4));
        let big = ((259u64 & 0xfff) << 8) | ((259u64 & !0xfff) << 32) | (1_048_575u64 & 0xff) | ((1_048_575u64 & !0xff) << 12);
        assert_eq!(dev_major_minor(big), (259, 1_048_575));
        assert_eq!(device_destination("/dev/ttyUSB0", 188, 0), "device:/dev/ttyUSB0 (188:0)");
    }

    #[test]
    fn the_facts_of_a_local_descriptor_read_as_local() {
        let f = std::fs::File::open("/proc/self/exe").unwrap();
        use std::os::unix::io::AsRawFd;
        // Known, or Stacked where the build tree is a container's overlay.
        let facts = fd_fs_facts(f.as_raw_fd(), None);
        assert!(!matches!(facts, FsFacts::Unknown), "{facts:?}");
        let pf = proc_fd_fs_facts(std::process::id() as i32, f.as_raw_fd());
        assert!(!matches!(pf, FsFacts::Unknown), "{pf:?}");
        assert!(matches!(path_fs_facts("/proc/self/exe", None), FsFacts::Known { .. } | FsFacts::Stacked { .. }));
        assert_eq!(path_fs_facts("/nonexistent/mandu-r4b", None), FsFacts::Unknown);
    }

    fn row(fstype: &str, source: &str, superopts: &str) -> MountRow {
        MountRow { id: 7, mount_point: "/m".into(), fstype: fstype.into(), source: source.into(), superopts: superopts.into() }
    }

    #[test]
    fn super_options_parse_with_escapes_and_the_last_value_counts() {
        let so = "rw,lowerdir=/l1:/l2,upperdir=/srv/up\\054per,workdir=/srv/work,uuid=on";
        assert_eq!(superopt(so, "upperdir").as_deref(), Some("/srv/up,per"));
        assert_eq!(superopt(so, "workdir").as_deref(), Some("/srv/work"));
        assert_eq!(superopt(so, "redirect_dir"), None);
        assert_eq!(superopt("rw,upperdir=/a,upperdir=/b", "upperdir").as_deref(), Some("/b"));
        let line = "300 22 0:90 / /merged rw,relatime - overlay overlay rw,lowerdir=/lo,upperdir=/nfs/up\\040dir,workdir=/nfs/work";
        let r = parse_mountinfo_line(line).unwrap();
        assert_eq!(superopt(&r.superopts, "upperdir").as_deref(), Some("/nfs/up dir"));
    }

    #[test]
    fn a_stacking_file_system_is_judged_where_its_writes_land() {
        let ov = row("overlay", "overlay", "rw,lowerdir=/lo,upperdir=/nfs/up,workdir=/nfs/work");
        assert_eq!(stacking(OVERLAYFS_MAGIC as u64, Some(&ov)), Stack::Lands("/nfs/up".into()));
        // By name alone, and by magic alone (no row: nothing to follow).
        assert_eq!(stacking(0, Some(&ov)), Stack::Lands("/nfs/up".into()));
        assert_eq!(stacking(OVERLAYFS_MAGIC as u64, None), Stack::Undetermined);
        // An overlay with no upper layer cannot be written through.
        assert_eq!(stacking(OVERLAYFS_MAGIC as u64, Some(&row("overlay", "overlay", "ro,lowerdir=/a:/b"))), Stack::ReadOnly);
        // A relative upper is no path the guard can name.
        assert_eq!(stacking(OVERLAYFS_MAGIC as u64, Some(&row("overlay", "overlay", "rw,upperdir=up,workdir=wk"))), Stack::Undetermined);
        // eCryptfs and shiftfs land in their source directory.
        assert_eq!(stacking(ECRYPTFS_MAGIC as u64, Some(&row("ecryptfs", "/home/u/.Private", "rw,ecryptfs_sig=x"))), Stack::Lands("/home/u/.Private".into()));
        assert_eq!(stacking(0, Some(&row("shiftfs", "/var/lib/x", "rw"))), Stack::Lands("/var/lib/x".into()));
        // aufs: its branches are not named here: remote.
        assert_eq!(stacking(AUFS_MAGIC as u64, Some(&row("aufs", "none", "rw,si=1"))), Stack::Undetermined);
        // Not stacking.
        assert_eq!(stacking(0xEF53, Some(&row("ext4", "/dev/sda1", "rw"))), Stack::No);
        assert_eq!(stacking(0x6969, Some(&row("nfs4", "nas:/x", "rw"))), Stack::No);
    }

    #[test]
    fn an_overlay_is_remote_when_its_upper_is_and_when_it_cannot_be_found() {
        let nfs = FsFacts::Known { f_type: 0x6969, dev: 9, row: Some(row("nfs4", "nas:/x", "rw")) };
        let ext4 = FsFacts::Known { f_type: 0xEF53, dev: 8, row: Some(row("ext4", "/dev/sda1", "rw")) };
        let ov = |lands| FsFacts::Stacked { name: "mount:overlay:overlay".into(), dev: 50, lands };
        // The upper on NFS: named by the NFS mount (a binding of it admits).
        assert_eq!(mount_verdict(&ov(Lands::On(vec![nfs.clone()])), &[]), MountVerdict::Remote("mount:nfs4:nas:/x".into()));
        assert_eq!(mount_verdict(&ov(Lands::On(vec![ext4.clone()])), &[]), MountVerdict::Local);
        // Two views disagree (a tracee's view shadowing the path): remote.
        assert_eq!(mount_verdict(&ov(Lands::On(vec![ext4.clone(), nfs.clone()])), &[]), MountVerdict::Remote("mount:nfs4:nas:/x".into()));
        // Not found anywhere: remote, named by the overlay itself.
        assert_eq!(mount_verdict(&ov(Lands::Undetermined), &[]), MountVerdict::Remote("mount:overlay:overlay".into()));
        assert_eq!(mount_verdict(&ov(Lands::On(vec![])), &[]), MountVerdict::Remote("mount:overlay:overlay".into()));
        // An upper that is unreadable is remote.
        assert_eq!(mount_verdict(&ov(Lands::On(vec![FsFacts::Unknown])), &[]), MountVerdict::Remote("mount:unknown".into()));
        // Read-only: nothing lands anywhere.
        assert_eq!(mount_verdict(&ov(Lands::Nowhere), &[]), MountVerdict::Local);
        // An overlay over an overlay whose upper is remote.
        let inner = ov(Lands::On(vec![nfs.clone()]));
        assert_eq!(mount_verdict(&ov(Lands::On(vec![inner])), &[]), MountVerdict::Remote("mount:nfs4:nas:/x".into()));
        // The test hook reaches the upper's device, and the overlay's own.
        let shm = FsFacts::Known { f_type: 0x0102_1994, dev: 42, row: Some(row("tmpfs", "tmpfs", "rw")) };
        assert_eq!(mount_verdict(&ov(Lands::On(vec![shm])), &[42]), MountVerdict::Remote("mount:tmpfs:tmpfs".into()));
        assert_eq!(mount_verdict(&ov(Lands::On(vec![ext4])), &[50]), MountVerdict::Remote("mount:overlay:overlay".into()));
    }

    // ── P0 5d: an overlay the tree may have mounted (2026-10-09) ─────────────

    #[test]
    fn a_stack_is_known_only_when_its_superblock_is_in_the_guards_own_table() {
        let own = crate::visible_mounts::parse_rows(
            "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
             300 22 0:90 / /var/lib/x/merged rw - overlay overlay rw,lowerdir=/lo,upperdir=/nfs/up,workdir=/nfs/wk\n",
        );
        let ovl_dev = crate::visible_mounts::makedev(0, 90);
        // Found in the guard's own table by mount id.
        assert!(stack_known(true, 0, "overlay", &[]));
        // A copy or a bind of a superblock the guard's namespace mounts (the
        // tracee's copy of the launcher's table): same device, same type.
        assert!(stack_known(false, ovl_dev, "overlay", &own));
        assert!(stack_known(false, ovl_dev, "OVERLAY", &own));
        // A superblock only the tree's namespace has: a device the guard's
        // table lacks, or that device under another type.
        assert!(!stack_known(false, crate::visible_mounts::makedev(0, 91), "overlay", &own));
        assert!(!stack_known(false, ovl_dev, "ecryptfs", &own));
        // The guard's own table unreadable or empty: not known.
        assert!(!stack_known(false, ovl_dev, "overlay", &[]));
    }

    #[test]
    fn a_stack_the_tree_may_have_made_is_remote_whatever_its_upper_says() {
        let ext4 = FsFacts::Known { f_type: 0xEF53, dev: 8, row: Some(row("ext4", "/dev/sda1", "rw")) };
        let nfs = FsFacts::Known { f_type: 0x6969, dev: 9, row: Some(row("nfs4", "nas:/x", "rw")) };
        let tmp = FsFacts::Known { f_type: 0x0102_1994, dev: 77, row: Some(row("tmpfs", "tmpfs", "rw")) };
        // THE SHADOW: the tree's overlay names an upper that both views
        // resolve to a local directory (a tmpfs laid over the path, or the
        // remote mount under it detached): not followed, remote, named by
        // the overlay itself.
        assert_eq!(lands_of(false, Some(ext4.clone()), Some(tmp.clone())), Lands::Foreign);
        assert_eq!(lands_of(false, None, None), Lands::Foreign);
        let ov = |lands| FsFacts::Stacked { name: "mount:overlay:mandu-ovl".into(), dev: 50, lands };
        assert_eq!(mount_verdict(&ov(Lands::Foreign), &[]), MountVerdict::Remote("mount:overlay:mandu-ovl".into()));
        // A binding of the overlay itself admits; one of the mount its
        // upper names does not (the guard cannot tell where it is).
        assert!(mount_bound(&["mount:overlay:mandu-ovl".into()], "mount:overlay:mandu-ovl"));
        assert!(!mount_bound(&["mount:tmpfs:tmpfs".into()], "mount:overlay:mandu-ovl"));
        // A known stack: the guard's own view must resolve; the tracee's is
        // judged beside it (any remote ⇒ remote).
        assert_eq!(lands_of(true, None, Some(ext4.clone())), Lands::Undetermined, "the tracee's view alone could be the tree's");
        assert_eq!(mount_verdict(&ov(lands_of(true, None, Some(ext4.clone()))), &[]), MountVerdict::Remote("mount:overlay:mandu-ovl".into()));
        assert_eq!(lands_of(true, Some(ext4.clone()), None), Lands::On(vec![ext4.clone()]));
        assert_eq!(mount_verdict(&ov(lands_of(true, Some(ext4.clone()), Some(ext4.clone()))), &[]), MountVerdict::Local);
        assert_eq!(mount_verdict(&ov(lands_of(true, Some(nfs.clone()), Some(ext4.clone()))), &[]), MountVerdict::Remote("mount:nfs4:nas:/x".into()));
        assert_eq!(mount_verdict(&ov(lands_of(true, Some(ext4), Some(nfs))), &[]), MountVerdict::Remote("mount:nfs4:nas:/x".into()));
    }

    #[test]
    fn a_rows_device_is_its_superblocks() {
        let mi = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
300 22 0:90 / /merged rw,relatime - overlay mandu-ovl rw,lowerdir=/lo,upperdir=/up,workdir=/wk
";
        let (r, dev) = mount_row_dev(mi, 300).unwrap();
        assert_eq!((r.fstype.as_str(), r.source.as_str(), dev), ("overlay", "mandu-ovl", crate::visible_mounts::makedev(0, 90)));
        assert_eq!(mount_row_dev(mi, 22).map(|(_, d)| d), Some(crate::visible_mounts::makedev(8, 1)));
        assert!(mount_row_dev(mi, 7).is_none());
    }

    #[test]
    fn the_guards_own_mounts_are_known_to_it() {
        // Every row of the guard's own table is known by its own device, so
        // a stack the launcher's namespace mounts (a container's root, a
        // host overlay) is followed as before.
        let t = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let own = crate::visible_mounts::parse_rows(&t);
        assert!(!own.is_empty());
        for r in &own {
            assert!(stack_known(false, r.dev, &r.row.fstype, &own), "{r:?}");
            assert_eq!(mount_row_dev(&t, r.row.id).map(|(_, d)| d), Some(r.dev));
        }
    }

    #[test]
    fn a_sweep_refusal_names_the_mount_the_device_or_the_users() {
        assert_eq!(held_exit_phrase("mount:nfs4:nas:/x").0, "hold open for writing a file on");
        assert_eq!(held_exit_phrase("device:/dev/fuse (10:229)").1, "holds open for writing");
        assert_eq!(held_exit_phrase("other local users (/p/x)").0, "hold open for writing a file readable by");
        assert_eq!(held_exit_phrase("203.0.113.9:443/tcp").0, "hold a connection to");
        assert_eq!(held_exit_phrase(&format!("{OUTSIDE_RECEIVER} (pid 7, pipe:[9])")).1, "writes into a pipe or socket pair read by");
    }
}
