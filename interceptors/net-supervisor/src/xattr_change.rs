//! xattr_change — the extended-attribute family the whole-agent guard traps
//! and performs (write-protection.md §2, "Extended attributes", 2026-09-29).
//!
//! PURE (always compiled, unit-tested, no privilege): the syscall numbers,
//! the decode of each form's arguments, the kernel's own argument checks in
//! its own order, the name classes, THE RULE, the no-op test, and the
//! translation of a POSIX ACL's user and group ids from the tracee's user
//! namespace to the guard's. `guard_kernel::perform_xattr` enacts it.
//!
//! **The rule.** An extended-attribute change (`setxattr`, `lsetxattr`,
//! `fsetxattr`, `setxattrat`, and the `removexattr` family) of a registered
//! secret's file is refused, and one of a file on the write-protect list is
//! judged like a write (`deny` refused, `ask` held for the human), whatever
//! the attribute's name, exactly as the chmod family is. A change that
//! changes nothing is performed without a judgement. Every other file's
//! change is performed as the tracee asked. Why every name, not only the
//! POSIX ACLs:
//!
//! - `system.posix_acl_access` IS a mode change: its owner, group and other
//!   entries are the permission bits (`setfacl -m u::rwx` arms a hook), a
//!   named-user entry opens the file to another local user, and
//!   `system.posix_acl_default` on a protected directory does the same for
//!   every file made in it. Other filesystems carry ACLs under other
//!   `system.*` names (`system.nfs4_acl`, `system.richacl`,
//!   `system.ntfs_security`, `system.cifs_acl`); judging only the two POSIX
//!   names would leave those open.
//! - `security.*` and `trusted.*` fail for an unprivileged tracee anyway, but
//!   not in a user namespace that grants the capability: a namespaced file
//!   capability (`security.capability` v3) is set by the namespace's root,
//!   and a privilege on a protected file is a change to it.
//! - `user.*` is data to most programs, but not to all: an unprivileged
//!   overlayfs (`userxattr`) reads `user.overlay.*` to decide what a merged
//!   directory shows. Refusing it on Mandu's own files and holding it on a
//!   hook costs nothing ordinary work does; a rule by name would have to be
//!   re-checked every time a program starts reading a new name.
//!
//! Judging every change was chosen over "refuse only a change that widens
//! access" because the latter needs each filesystem's ACL semantics right;
//! the no-op exemption covers what makes the former noisy: an editor that
//! re-applies a file's (minimal) ACL after a write the human allowed.

/// `setxattrat(dfd, path, at_flags, name, uargs, usize)` (Linux 6.13): the
/// same number on every arch (the unified table).
pub const SYS_SETXATTRAT: i64 = 463;
/// `removexattrat(dfd, path, at_flags, name)` (Linux 6.13).
pub const SYS_REMOVEXATTRAT: i64 = 466;
/// The longest name (`XATTR_NAME_MAX`); the kernel copies at most one byte
/// more, and a name that fills it is `ERANGE`.
pub const XATTR_NAME_MAX: usize = 255;
/// The largest value (`XATTR_SIZE_MAX`); larger is `E2BIG`.
pub const XATTR_SIZE_MAX: u64 = 65536;
/// `struct xattr_args { u64 value; u32 size; u32 flags; }`, version 0.
pub const XATTR_ARGS_SIZE_VER0: u64 = 16;
/// `setxattrat` refuses a `usize` over a page with `E2BIG`.
const XATTR_ARGS_MAX: u64 = 4096;
const XATTR_CREATE: u32 = 1;
const XATTR_REPLACE: u32 = 2;

/// The POSIX ACL names (`include/uapi/linux/xattr.h`).
pub const POSIX_ACL_ACCESS: &[u8] = b"system.posix_acl_access";
pub const POSIX_ACL_DEFAULT: &[u8] = b"system.posix_acl_default";

/// The attribute family, every arch: the three set forms, the three remove
/// forms, and the two `*at` forms of Linux 6.13 (trapped on every kernel:
/// one that lacks them answers ENOSYS, and the guard never emulates them).
pub fn xattr_nrs() -> Vec<i64> {
    vec![
        libc::SYS_setxattr as i64,
        libc::SYS_lsetxattr as i64,
        libc::SYS_fsetxattr as i64,
        libc::SYS_removexattr as i64,
        libc::SYS_lremovexattr as i64,
        libc::SYS_fremovexattr as i64,
        SYS_SETXATTRAT,
        SYS_REMOVEXATTRAT,
    ]
}

pub fn is_xattr_nr(nr: i64) -> bool {
    xattr_nrs().contains(&nr)
}

/// The file an attribute call changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrTarget {
    /// A path (`dirfd`, pointer), resolved whole in the tracee's view: the
    /// final symlink followed unless `follow` is false (`l*`, or
    /// `AT_SYMLINK_NOFOLLOW`); `empty_path` = `AT_EMPTY_PATH`, where an empty
    /// path names the descriptor `dirfd` itself.
    Path { dirfd: i32, addr: u64, follow: bool, empty_path: bool },
    /// `fsetxattr` / `fremovexattr`: the tracee's own descriptor.
    Fd { fd: i32 },
}

/// What the call does to the attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrOp {
    /// `setxattr` / `lsetxattr` / `fsetxattr`: the value pointer, its size and
    /// the `XATTR_CREATE` / `XATTR_REPLACE` flags, in the arguments.
    Set { value: u64, size: u64, flags: u32 },
    /// `setxattrat`: a `struct xattr_args` of `usize` bytes at `args`.
    SetAt { args: u64, usize: u64 },
    /// The `removexattr` family.
    Remove,
}

/// An attribute call, decoded (`xattr_call`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XattrCall {
    pub target: XattrTarget,
    /// The name's pointer.
    pub name: u64,
    pub op: XattrOp,
    /// `*at` flags other than `AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH`: EINVAL,
    /// answered where the kernel checks them (after `setxattrat`'s argument
    /// struct is copied, first for `removexattrat`).
    pub bad_at_flags: bool,
}

/// Decode an attribute call. `None`: not in the family. Pure.
pub fn xattr_call(nr: i64, a: &[u64; 6]) -> Option<XattrCall> {
    let path = |addr: u64, follow: bool| XattrTarget::Path { dirfd: libc::AT_FDCWD, addr, follow, empty_path: false };
    let set = XattrOp::Set { value: a[2], size: a[3], flags: a[4] as u32 };
    let call = |target, name, op| Some(XattrCall { target, name, op, bad_at_flags: false });
    if nr == libc::SYS_setxattr as i64 {
        return call(path(a[0], true), a[1], set);
    }
    if nr == libc::SYS_lsetxattr as i64 {
        return call(path(a[0], false), a[1], set);
    }
    if nr == libc::SYS_fsetxattr as i64 {
        return call(XattrTarget::Fd { fd: a[0] as i32 }, a[1], set);
    }
    if nr == libc::SYS_removexattr as i64 {
        return call(path(a[0], true), a[1], XattrOp::Remove);
    }
    if nr == libc::SYS_lremovexattr as i64 {
        return call(path(a[0], false), a[1], XattrOp::Remove);
    }
    if nr == libc::SYS_fremovexattr as i64 {
        return call(XattrTarget::Fd { fd: a[0] as i32 }, a[1], XattrOp::Remove);
    }
    if nr == SYS_SETXATTRAT || nr == SYS_REMOVEXATTRAT {
        let at = a[2] as u32 as i32;
        let target = XattrTarget::Path {
            dirfd: a[0] as i32,
            addr: a[1],
            follow: at & libc::AT_SYMLINK_NOFOLLOW == 0,
            empty_path: at & libc::AT_EMPTY_PATH != 0,
        };
        let op = if nr == SYS_SETXATTRAT { XattrOp::SetAt { args: a[4], usize: a[5] } } else { XattrOp::Remove };
        let bad_at_flags = at & !(libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH) != 0;
        return Some(XattrCall { target, name: a[3], op, bad_at_flags });
    }
    None
}

/// `setxattrat`'s `usize`, checked before the struct is copied: EINVAL under
/// version 0's 16 bytes, E2BIG over a page. Pure.
pub fn check_xattr_args_size(usize: u64) -> Result<(), i32> {
    if usize < XATTR_ARGS_SIZE_VER0 {
        return Err(libc::EINVAL);
    }
    if usize > XATTR_ARGS_MAX {
        return Err(libc::E2BIG);
    }
    Ok(())
}

/// `struct xattr_args` from the `usize` bytes the tracee passed
/// (`copy_struct_from_user`: a longer struct's tail must be zero, else
/// E2BIG): `(value pointer, size, flags)`. Pure.
pub fn decode_xattr_args(b: &[u8]) -> Result<(u64, u64, u32), i32> {
    check_xattr_args_size(b.len() as u64)?;
    if b[16..].iter().any(|x| *x != 0) {
        return Err(libc::E2BIG);
    }
    let value = u64::from_ne_bytes(b[0..8].try_into().unwrap());
    let size = u32::from_ne_bytes(b[8..12].try_into().unwrap()) as u64;
    let flags = u32::from_ne_bytes(b[12..16].try_into().unwrap());
    Ok((value, size, flags))
}

/// A set's flags, checked first (`setxattr_copy`): EINVAL beyond
/// `XATTR_CREATE | XATTR_REPLACE`. Pure.
pub fn check_set_flags(flags: u32) -> Result<(), i32> {
    if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 { Err(libc::EINVAL) } else { Ok(()) }
}

/// A value's size, checked after the name: E2BIG over `XATTR_SIZE_MAX`. Pure.
pub fn check_value_size(size: u64) -> Result<usize, i32> {
    if size > XATTR_SIZE_MAX { Err(libc::E2BIG) } else { Ok(size as usize) }
}

/// The name as `strncpy_from_user(kname, name, XATTR_NAME_MAX + 1)` takes
/// it, from the bytes the guard could read (`read`: the bytes of the tracee's
/// memory it got, up to `XATTR_NAME_MAX + 1`): ERANGE for an empty name or
/// one with no NUL in the first 256 bytes, EFAULT when the memory ends
/// before a NUL. Pure.
pub fn decode_name(read: &[u8]) -> Result<Vec<u8>, i32> {
    match read.iter().position(|b| *b == 0) {
        Some(0) => Err(libc::ERANGE),
        Some(end) => Ok(read[..end].to_vec()),
        None if read.len() > XATTR_NAME_MAX => Err(libc::ERANGE),
        None => Err(libc::EFAULT),
    }
}

/// The namespace a name belongs to (documentation of the rule; every class
/// is judged on a protected or secret file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrClass {
    /// `system.posix_acl_access` / `_default`: permission bits and named
    /// users and groups.
    PosixAcl,
    /// Another `system.*` name: a filesystem's own ACL (`system.nfs4_acl`,
    /// `system.richacl`, `system.ntfs_security`, `system.cifs_acl`).
    System,
    /// `security.*`: file capabilities, LSM labels.
    Security,
    /// `trusted.*`: CAP_SYS_ADMIN (overlayfs's own).
    Trusted,
    /// `user.*`: data, and an unprivileged overlay's `user.overlay.*`.
    User,
    /// Anything else: the kernel answers EOPNOTSUPP.
    Other,
}

pub fn classify(name: &[u8]) -> XattrClass {
    if name == POSIX_ACL_ACCESS || name == POSIX_ACL_DEFAULT {
        XattrClass::PosixAcl
    } else if name.starts_with(b"system.") {
        XattrClass::System
    } else if name.starts_with(b"security.") {
        XattrClass::Security
    } else if name.starts_with(b"trusted.") {
        XattrClass::Trusted
    } else if name.starts_with(b"user.") {
        XattrClass::User
    } else {
        XattrClass::Other
    }
}

/// What the guard does with an attribute change, once the file is pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrVerdict {
    /// Perform it as the tracee asked.
    Perform,
    /// Refuse it (EACCES): a registered secret's file.
    Refuse,
    /// Judge it by the write-protect entry the file falls under (`deny`
    /// refused, `ask` held for the human), as a write.
    Judge,
}

/// THE RULE (module doc): a change that changes nothing is performed; else a
/// registered secret refused, a write-protected file judged, anything else
/// performed. The name does not enter: every class is judged. Pure.
pub fn xattr_verdict(noop: bool, secret: bool, write_protected: bool) -> XattrVerdict {
    if noop {
        XattrVerdict::Perform
    } else if secret {
        XattrVerdict::Refuse
    } else if write_protected {
        XattrVerdict::Judge
    } else {
        XattrVerdict::Perform
    }
}

/// The attribute's current value on the pinned file, as the guard read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Current<'a> {
    /// `ENODATA`: the file has no such attribute (for an access ACL: its
    /// permission bits are its whole access).
    Absent,
    Value(&'a [u8]),
    /// Could not be read (EACCES, EOPNOTSUPP, …): never a no-op.
    Unknown,
}

/// A change that changes nothing, performed without a judgement (the chmod
/// family's `mode_change_is_noop`): removing an attribute the file does not
/// have; setting the value it already has; and setting a MINIMAL access ACL
/// (owner, group, other: equivalent to a mode) whose bits are the file's
/// mode on a file with no access ACL, which the kernel stores as that mode
/// (vim re-applies a file's ACL after every write). `new` is `None` for a
/// removal. `mode` is the file's `st_mode`. Pure.
pub fn xattr_change_is_noop(name: &[u8], new: Option<&[u8]>, current: Current<'_>, mode: Option<u32>) -> bool {
    match (new, current) {
        (None, Current::Absent) => true,
        (Some(v), Current::Value(cur)) => v == cur,
        (Some(v), Current::Absent) => name == POSIX_ACL_ACCESS && mode.is_some_and(|m| acl_equiv_mode(v) == Some(m & 0o777)),
        _ => false,
    }
}

// ── the POSIX ACL value (`include/uapi/linux/posix_acl_xattr.h`) ─────────────

const ACL_XATTR_VERSION: u32 = 0x0002;
pub const ACL_USER_OBJ: u16 = 0x01;
pub const ACL_USER: u16 = 0x02;
pub const ACL_GROUP_OBJ: u16 = 0x04;
pub const ACL_GROUP: u16 = 0x08;
pub const ACL_MASK: u16 = 0x10;
pub const ACL_OTHER: u16 = 0x20;

/// The entries of a POSIX ACL value: `(tag, perm, id)`. `None`: not a
/// version-2 value of whole 8-byte entries.
fn acl_entries(v: &[u8]) -> Option<Vec<(u16, u16, u32)>> {
    if v.len() < 4 || (v.len() - 4) % 8 != 0 || u32::from_le_bytes(v[0..4].try_into().ok()?) != ACL_XATTR_VERSION {
        return None;
    }
    Some(
        v[4..]
            .chunks_exact(8)
            .map(|e| (u16::from_le_bytes([e[0], e[1]]), u16::from_le_bytes([e[2], e[3]]), u32::from_le_bytes([e[4], e[5], e[6], e[7]])))
            .collect(),
    )
}

/// The mode a MINIMAL access ACL is equivalent to: exactly the owner, group
/// and other entries, in the kernel's order, with rwx bits only. `None` for
/// any other value (a mask or a named entry is never a mode). Pure.
pub fn acl_equiv_mode(v: &[u8]) -> Option<u32> {
    let e = acl_entries(v)?;
    match e.as_slice() {
        [(ACL_USER_OBJ, u, _), (ACL_GROUP_OBJ, g, _), (ACL_OTHER, o, _)] if (u | g | o) & !7 == 0 => {
            Some(((*u as u32) << 6) | ((*g as u32) << 3) | *o as u32)
        }
        _ => None,
    }
}

/// Does the ACL name a user or group by id (a named entry, whose id the
/// kernel reads in the CALLER's user namespace)? Pure.
pub fn acl_has_named_ids(v: &[u8]) -> bool {
    acl_entries(v).is_some_and(|e| e.iter().any(|(t, _, _)| *t == ACL_USER || *t == ACL_GROUP))
}

/// A `/proc/<pid>/uid_map` or `gid_map`: `(inside, outside, count)` lines,
/// `outside` in the reader's namespace. Unparseable lines are dropped (an id
/// they would map is then unmapped: refused). Pure.
pub fn parse_id_map(text: &str) -> Vec<(u32, u32, u32)> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace().map(|x| x.parse::<u32>().ok());
            Some((f.next()??, f.next()??, f.next()??))
        })
        .collect()
}

/// An id inside the tracee's namespace as the reader's namespace names it.
/// Pure.
pub fn map_id(map: &[(u32, u32, u32)], id: u32) -> Option<u32> {
    map.iter().find(|(inside, _, count)| id >= *inside && (id - inside) < *count).map(|(inside, outside, _)| outside + (id - inside))
}

/// The ACL value with every named user and group id moved from the tracee's
/// user namespace to the guard's (`posix_acl_from_xattr` reads ids in the
/// caller's namespace, and the guard, not the tracee, makes the call). An
/// id the maps do not cover is EINVAL, as the tracee's own call would get.
/// A malformed value passes unchanged: the kernel refuses it in any
/// namespace. Pure.
pub fn translate_acl_ids(v: &[u8], uid_map: &[(u32, u32, u32)], gid_map: &[(u32, u32, u32)]) -> Result<Vec<u8>, i32> {
    let Some(entries) = acl_entries(v) else { return Ok(v.to_vec()) };
    let mut out = v[0..4].to_vec();
    for (tag, perm, id) in entries {
        let id = match tag {
            ACL_USER => map_id(uid_map, id).ok_or(libc::EINVAL)?,
            ACL_GROUP => map_id(gid_map, id).ok_or(libc::EINVAL)?,
            _ => id,
        };
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&perm.to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
    }
    Ok(out)
}

/// Build a POSIX ACL value from `(tag, perm, id)` entries (tests and the
/// kernel tests' tracees). Pure.
pub fn acl_value(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut v = ACL_XATTR_VERSION.to_le_bytes().to_vec();
    for (t, p, id) in entries {
        v.extend_from_slice(&t.to_le_bytes());
        v.extend_from_slice(&p.to_le_bytes());
        v.extend_from_slice(&id.to_le_bytes());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    const U: u32 = u32::MAX; // ACL_UNDEFINED_ID

    #[test]
    fn every_form_of_the_family_is_decoded() {
        let a = [100u64, 200, 300, 12, 1, 0];
        let path = |addr, follow| XattrTarget::Path { dirfd: libc::AT_FDCWD, addr, follow, empty_path: false };
        let set = XattrOp::Set { value: 300, size: 12, flags: 1 };
        let c = |nr: libc::c_long| xattr_call(nr as i64, &a).unwrap();
        assert_eq!(c(libc::SYS_setxattr), XattrCall { target: path(100, true), name: 200, op: set, bad_at_flags: false });
        assert_eq!(c(libc::SYS_lsetxattr), XattrCall { target: path(100, false), name: 200, op: set, bad_at_flags: false });
        assert_eq!(c(libc::SYS_fsetxattr), XattrCall { target: XattrTarget::Fd { fd: 100 }, name: 200, op: set, bad_at_flags: false });
        assert_eq!(c(libc::SYS_removexattr), XattrCall { target: path(100, true), name: 200, op: XattrOp::Remove, bad_at_flags: false });
        assert_eq!(c(libc::SYS_lremovexattr), XattrCall { target: path(100, false), name: 200, op: XattrOp::Remove, bad_at_flags: false });
        assert_eq!(c(libc::SYS_fremovexattr), XattrCall { target: XattrTarget::Fd { fd: 100 }, name: 200, op: XattrOp::Remove, bad_at_flags: false });
        // setxattrat(dfd, path, at_flags, name, uargs, usize)
        let at = [7u64, 100, (libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH) as u64, 200, 400, 16];
        assert_eq!(
            xattr_call(SYS_SETXATTRAT, &at).unwrap(),
            XattrCall { target: XattrTarget::Path { dirfd: 7, addr: 100, follow: false, empty_path: true }, name: 200, op: XattrOp::SetAt { args: 400, usize: 16 }, bad_at_flags: false }
        );
        let rm = [7u64, 100, 0, 200, 0, 0];
        assert_eq!(
            xattr_call(SYS_REMOVEXATTRAT, &rm).unwrap(),
            XattrCall { target: XattrTarget::Path { dirfd: 7, addr: 100, follow: true, empty_path: false }, name: 200, op: XattrOp::Remove, bad_at_flags: false }
        );
        let bad = [7u64, 100, libc::AT_REMOVEDIR as u64, 200, 0, 0];
        assert!(xattr_call(SYS_REMOVEXATTRAT, &bad).unwrap().bad_at_flags);
        assert!(xattr_call(libc::SYS_getxattr as i64, &a).is_none(), "reads are not trapped");
        assert!(xattr_call(libc::SYS_openat as i64, &a).is_none());
        for nr in xattr_nrs() {
            assert!(is_xattr_nr(nr) && xattr_call(nr, &a).is_some());
        }
        assert!(!is_xattr_nr(libc::SYS_getxattr as i64) && !is_xattr_nr(libc::SYS_listxattr as i64));
    }

    #[test]
    fn the_kernels_own_argument_checks_answer_its_own_errnos() {
        assert_eq!(check_set_flags(0), Ok(()));
        assert_eq!(check_set_flags(XATTR_CREATE), Ok(()));
        assert_eq!(check_set_flags(XATTR_REPLACE), Ok(()));
        assert_eq!(check_set_flags(4), Err(libc::EINVAL));
        assert_eq!(check_value_size(0), Ok(0));
        assert_eq!(check_value_size(65536), Ok(65536));
        assert_eq!(check_value_size(65537), Err(libc::E2BIG));
        assert_eq!(check_xattr_args_size(15), Err(libc::EINVAL));
        assert_eq!(check_xattr_args_size(16), Ok(()));
        assert_eq!(check_xattr_args_size(4097), Err(libc::E2BIG));
        let mut args = Vec::new();
        args.extend_from_slice(&0x1234u64.to_ne_bytes());
        args.extend_from_slice(&9u32.to_ne_bytes());
        args.extend_from_slice(&XATTR_CREATE.to_ne_bytes());
        assert_eq!(decode_xattr_args(&args), Ok((0x1234, 9, XATTR_CREATE)));
        let mut longer = args.clone();
        longer.extend_from_slice(&[0; 8]);
        assert_eq!(decode_xattr_args(&longer), Ok((0x1234, 9, XATTR_CREATE)), "a longer struct with a zero tail");
        longer[20] = 1;
        assert_eq!(decode_xattr_args(&longer), Err(libc::E2BIG), "a tail this kernel does not know");
        assert_eq!(decode_xattr_args(&args[..12]), Err(libc::EINVAL));
    }

    #[test]
    fn a_name_is_read_as_strncpy_from_user_takes_it() {
        assert_eq!(decode_name(b"user.x\0junk"), Ok(b"user.x".to_vec()));
        assert_eq!(decode_name(b"\0"), Err(libc::ERANGE), "an empty name");
        let long = vec![b'a'; 256];
        assert_eq!(decode_name(&long), Err(libc::ERANGE), "no NUL in XATTR_NAME_MAX + 1 bytes");
        let mut max = vec![b'a'; 255];
        max.push(0);
        assert_eq!(decode_name(&max).map(|n| n.len()), Ok(255), "the longest name");
        assert_eq!(decode_name(b"user.x"), Err(libc::EFAULT), "memory ends before a NUL");
        assert_eq!(decode_name(b""), Err(libc::EFAULT));
    }

    #[test]
    fn names_fall_in_their_namespaces() {
        assert_eq!(classify(b"system.posix_acl_access"), XattrClass::PosixAcl);
        assert_eq!(classify(b"system.posix_acl_default"), XattrClass::PosixAcl);
        assert_eq!(classify(b"system.nfs4_acl"), XattrClass::System);
        assert_eq!(classify(b"security.capability"), XattrClass::Security);
        assert_eq!(classify(b"trusted.overlay.opaque"), XattrClass::Trusted);
        assert_eq!(classify(b"user.overlay.redirect"), XattrClass::User);
        assert_eq!(classify(b"user.xdg.origin.url"), XattrClass::User);
        assert_eq!(classify(b"bogus"), XattrClass::Other);
    }

    #[test]
    fn the_rule_judges_every_name_on_a_protected_or_secret_file() {
        use XattrVerdict::*;
        // The verdict does not depend on the name: every class is covered by
        // the same three answers (module doc).
        assert_eq!(xattr_verdict(false, true, false), Refuse, "a registered secret");
        assert_eq!(xattr_verdict(false, true, true), Refuse, "a secret under a protected path: refused, not asked");
        assert_eq!(xattr_verdict(false, false, true), Judge, "a write-protected file");
        assert_eq!(xattr_verdict(false, false, false), Perform, "any other file, as today");
        assert_eq!(xattr_verdict(true, true, true), Perform, "a change that changes nothing");
    }

    #[test]
    fn only_a_change_that_changes_nothing_escapes_the_judgement() {
        let minimal_644 = acl_value(&[(ACL_USER_OBJ, 6, U), (ACL_GROUP_OBJ, 4, U), (ACL_OTHER, 4, U)]);
        let arm_755 = acl_value(&[(ACL_USER_OBJ, 7, U), (ACL_GROUP_OBJ, 5, U), (ACL_OTHER, 5, U)]);
        let named = acl_value(&[(ACL_USER_OBJ, 6, U), (ACL_USER, 4, 1001), (ACL_GROUP_OBJ, 4, U), (ACL_MASK, 4, U), (ACL_OTHER, 0, U)]);
        let reg644 = Some(libc::S_IFREG | 0o644);
        // vim re-applying the file's own (minimal) ACL after a write: no-op.
        assert!(xattr_change_is_noop(POSIX_ACL_ACCESS, Some(&minimal_644), Current::Absent, reg644));
        // setfacl -m u::rwx: the mode changes.
        assert!(!xattr_change_is_noop(POSIX_ACL_ACCESS, Some(&arm_755), Current::Absent, reg644));
        // A named user opened to the file.
        assert!(!xattr_change_is_noop(POSIX_ACL_ACCESS, Some(&named), Current::Absent, reg644));
        // A minimal ACL over an extended one drops the named entries and can
        // widen the owning group (its bits become the mask's): a change.
        assert!(!xattr_change_is_noop(POSIX_ACL_ACCESS, Some(&minimal_644), Current::Value(&named), reg644));
        // A default ACL is never a mode.
        assert!(!xattr_change_is_noop(POSIX_ACL_DEFAULT, Some(&minimal_644), Current::Absent, Some(libc::S_IFDIR | 0o644)));
        // The same bytes again.
        assert!(xattr_change_is_noop(POSIX_ACL_ACCESS, Some(&named), Current::Value(&named), reg644));
        assert!(xattr_change_is_noop(b"user.x", Some(b"v"), Current::Value(b"v"), reg644));
        assert!(!xattr_change_is_noop(b"user.x", Some(b"w"), Current::Value(b"v"), reg644));
        assert!(!xattr_change_is_noop(b"user.x", Some(b"v"), Current::Absent, reg644), "a new attribute");
        // Removing what is not there (the kernel answers ENODATA).
        assert!(xattr_change_is_noop(b"user.x", None, Current::Absent, reg644));
        assert!(!xattr_change_is_noop(POSIX_ACL_ACCESS, None, Current::Value(&named), reg644));
        // Unreadable: never a no-op.
        assert!(!xattr_change_is_noop(b"user.x", Some(b"v"), Current::Unknown, reg644));
        assert!(!xattr_change_is_noop(b"user.x", None, Current::Unknown, reg644));
        assert!(!xattr_change_is_noop(POSIX_ACL_ACCESS, Some(&minimal_644), Current::Absent, None), "no mode known");
    }

    #[test]
    fn a_minimal_acl_is_a_mode_and_nothing_else_is() {
        assert_eq!(acl_equiv_mode(&acl_value(&[(ACL_USER_OBJ, 7, U), (ACL_GROUP_OBJ, 5, U), (ACL_OTHER, 1, U)])), Some(0o751));
        assert_eq!(acl_equiv_mode(&acl_value(&[(ACL_USER_OBJ, 7, U), (ACL_GROUP_OBJ, 5, U), (ACL_MASK, 5, U), (ACL_OTHER, 1, U)])), None, "a mask");
        assert_eq!(acl_equiv_mode(&acl_value(&[(ACL_USER_OBJ, 7, U), (ACL_USER, 7, 5), (ACL_GROUP_OBJ, 5, U), (ACL_OTHER, 1, U)])), None);
        assert_eq!(acl_equiv_mode(&acl_value(&[(ACL_USER_OBJ, 0o17, U), (ACL_GROUP_OBJ, 5, U), (ACL_OTHER, 1, U)])), None, "bits beyond rwx");
        assert_eq!(acl_equiv_mode(&acl_value(&[(ACL_GROUP_OBJ, 5, U), (ACL_USER_OBJ, 7, U), (ACL_OTHER, 1, U)])), None, "out of order");
        assert_eq!(acl_equiv_mode(b"\x01\0\0\0"), None, "version 1");
        assert_eq!(acl_equiv_mode(&[2, 0, 0, 0, 1]), None, "a partial entry");
        assert_eq!(acl_equiv_mode(b""), None);
    }

    #[test]
    fn named_ids_move_to_the_guards_namespace_or_are_refused() {
        // `setfacl -m u:5:r` in a namespace that maps 5 → 1000.
        let uid_map = parse_id_map("         0     100000          5\n         5       1000          1\n         6     100006      65530\n");
        let gid_map = parse_id_map("5 1000 1\n");
        assert_eq!(map_id(&uid_map, 5), Some(1000));
        assert_eq!(map_id(&uid_map, 4), Some(100004));
        assert_eq!(map_id(&uid_map, 7), Some(100007));
        assert_eq!(map_id(&uid_map, 65536), None, "past the last range");
        assert_eq!(map_id(&gid_map, 6), None);
        let v = acl_value(&[(ACL_USER_OBJ, 6, U), (ACL_USER, 4, 5), (ACL_GROUP_OBJ, 4, U), (ACL_GROUP, 4, 5), (ACL_MASK, 4, U), (ACL_OTHER, 0, U)]);
        assert!(acl_has_named_ids(&v));
        let want = acl_value(&[(ACL_USER_OBJ, 6, U), (ACL_USER, 4, 1000), (ACL_GROUP_OBJ, 4, U), (ACL_GROUP, 4, 1000), (ACL_MASK, 4, U), (ACL_OTHER, 0, U)]);
        assert_eq!(translate_acl_ids(&v, &parse_id_map("5 1000 1"), &gid_map), Ok(want));
        // An id the namespace does not map: the tracee's own call's EINVAL.
        let unmapped = acl_value(&[(ACL_USER_OBJ, 6, U), (ACL_USER, 4, 42), (ACL_GROUP_OBJ, 4, U), (ACL_MASK, 4, U), (ACL_OTHER, 0, U)]);
        assert_eq!(translate_acl_ids(&unmapped, &gid_map, &gid_map), Err(libc::EINVAL));
        // The object entries carry no id; a minimal ACL needs no map.
        let minimal = acl_value(&[(ACL_USER_OBJ, 6, U), (ACL_GROUP_OBJ, 4, U), (ACL_OTHER, 4, U)]);
        assert!(!acl_has_named_ids(&minimal));
        assert_eq!(translate_acl_ids(&minimal, &[], &[]), Ok(minimal.clone()));
        // A malformed value is the kernel's to refuse.
        assert_eq!(translate_acl_ids(b"\x02\0\0\0\x02", &[], &[]), Ok(b"\x02\0\0\0\x02".to_vec()));
        assert!(parse_id_map("x y z\n1 2\n").is_empty());
    }
}
