//! owner_time — the owner and timestamp families a holder's call is judged
//! in (P0 5c, 2026-10-07; confidentiality plan 13 §9 R4 (b)).
//!
//! On a mount that leaves the machine (NFS, CIFS, sshfs, any FUSE) a
//! `chown` and a `utimensat` are requests the server sees: about 128 bits
//! per call in two timestamps, and an owner and a group, set on a file a
//! holder can name or has open (read-only is enough for `fchown` and
//! `futimens` on a file it owns). The rest of the name and attribute
//! families were judged since 2026-10-04 (`secret_open::write_nrs`); these
//! two ran free. Now trapped under every secret policy: a non-holder's call
//! is CONTINUEd at once (nothing else judges them), a holder's is performed
//! by the guard on what it pinned (a path resolved whole in the tracee's
//! view, or a `pidfd_getfd` copy of its descriptor) after the mount
//! judgement (`guard_kernel::holder_change_refused`), never re-walked by
//! the kernel.
//!
//! PURE (always compiled, unit-tested, no privilege): the numbers, the
//! decode of each form, the kernel's own argument checks, and the
//! timestamps in the form the guard performs them (`utimensat`'s two
//! `timespec`s). `guard_kernel::perform_owner_time` enacts it.

/// The owner family: `fchownat`, `fchown`, and x86_64's `chown` and `lchown`.
pub fn owner_nrs() -> Vec<i64> {
    let mut v = vec![libc::SYS_fchownat as i64, libc::SYS_fchown as i64];
    #[cfg(target_arch = "x86_64")]
    v.extend([libc::SYS_chown as i64, libc::SYS_lchown as i64]);
    v
}

/// The timestamp family: `utimensat` (glibc's `futimens` too), and x86_64's
/// `utime`, `utimes` and `futimesat`.
pub fn time_nrs() -> Vec<i64> {
    let mut v = vec![libc::SYS_utimensat as i64];
    #[cfg(target_arch = "x86_64")]
    v.extend([libc::SYS_utime as i64, libc::SYS_utimes as i64, libc::SYS_futimesat as i64]);
    v
}

/// Both families: what the filter traps under a secret policy.
pub fn nrs() -> Vec<i64> {
    let mut v = owner_nrs();
    v.extend(time_nrs());
    v
}

pub fn is_owner_time_nr(nr: i64) -> bool {
    nrs().contains(&nr)
}

/// The file a call changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// A path (`dirfd`, pointer), resolved whole in the tracee's view: the
    /// final symlink followed unless `follow` is false; `empty_path` =
    /// `AT_EMPTY_PATH`, where an empty path names `dirfd` itself.
    Path { dirfd: i32, addr: u64, follow: bool, empty_path: bool },
    /// The tracee's own descriptor (`fchown`; `utimensat(fd, NULL, …)`,
    /// glibc's `futimens`; `futimesat(fd, NULL, …)`): its open file, an
    /// `O_PATH` one refused with EBADF as the kernel's `fdget` does.
    Fd { fd: i32 },
}

/// The layout of the timestamps the tracee passes (a null pointer: now).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimesArg {
    /// `struct utimbuf { time_t actime, modtime; }` (`utime`).
    Utimbuf(u64),
    /// `struct timeval[2]` (`utimes`, `futimesat`).
    Timeval(u64),
    /// `struct timespec[2]` (`utimensat`).
    Timespec(u64),
}

impl TimesArg {
    /// The pointer and the bytes to read there (0 for a null pointer).
    pub fn ptr_len(&self) -> (u64, usize) {
        match *self {
            TimesArg::Utimbuf(p) => (p, if p == 0 { 0 } else { 16 }),
            TimesArg::Timeval(p) | TimesArg::Timespec(p) => (p, if p == 0 { 0 } else { 32 }),
        }
    }
}

/// What the call sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// An owner and a group, in the tracee's user namespace (`-1`: unchanged).
    Owner { uid: u32, gid: u32 },
    Times(TimesArg),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Call {
    pub target: Target,
    pub op: Op,
}

/// Decode a call of either family. `Ok(None)`: not one. `Err(errno)`: the
/// kernel refuses it before it looks anything up (flags it does not know, a
/// null path the call cannot take), answered as the kernel would. Pure.
pub fn decode(nr: i64, args: &[u64; 6]) -> Result<Option<Call>, i32> {
    let known = libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;
    if nr == libc::SYS_fchownat as i64 {
        let flags = args[4] as u32 as i32;
        if flags & !known != 0 {
            return Err(libc::EINVAL);
        }
        let target = Target::Path { dirfd: args[0] as i32, addr: args[1], follow: flags & libc::AT_SYMLINK_NOFOLLOW == 0, empty_path: flags & libc::AT_EMPTY_PATH != 0 };
        return Ok(Some(Call { target, op: Op::Owner { uid: args[2] as u32, gid: args[3] as u32 } }));
    }
    if nr == libc::SYS_fchown as i64 {
        return Ok(Some(Call { target: Target::Fd { fd: args[0] as i32 }, op: Op::Owner { uid: args[1] as u32, gid: args[2] as u32 } }));
    }
    if nr == libc::SYS_utimensat as i64 {
        let (dirfd, path, flags) = (args[0] as i32, args[1], args[3] as u32 as i32);
        let times = Op::Times(TimesArg::Timespec(args[2]));
        if path == 0 {
            // `do_utimes`: a null path names the descriptor itself, with no
            // flags; on the cwd there is no descriptor to name.
            if dirfd == libc::AT_FDCWD {
                return Err(libc::EFAULT);
            }
            if flags != 0 {
                return Err(libc::EINVAL);
            }
            return Ok(Some(Call { target: Target::Fd { fd: dirfd }, op: times }));
        }
        if flags & !known != 0 {
            return Err(libc::EINVAL);
        }
        let target = Target::Path { dirfd, addr: path, follow: flags & libc::AT_SYMLINK_NOFOLLOW == 0, empty_path: flags & libc::AT_EMPTY_PATH != 0 };
        return Ok(Some(Call { target, op: times }));
    }
    #[cfg(target_arch = "x86_64")]
    {
        let at = libc::AT_FDCWD;
        let path = |addr: u64, follow: bool| Target::Path { dirfd: at, addr, follow, empty_path: false };
        if nr == libc::SYS_chown as i64 || nr == libc::SYS_lchown as i64 {
            return Ok(Some(Call { target: path(args[0], nr == libc::SYS_chown as i64), op: Op::Owner { uid: args[1] as u32, gid: args[2] as u32 } }));
        }
        if nr == libc::SYS_utime as i64 {
            return Ok(Some(Call { target: path(args[0], true), op: Op::Times(TimesArg::Utimbuf(args[1])) }));
        }
        if nr == libc::SYS_utimes as i64 {
            return Ok(Some(Call { target: path(args[0], true), op: Op::Times(TimesArg::Timeval(args[1])) }));
        }
        if nr == libc::SYS_futimesat as i64 {
            let (dirfd, p) = (args[0] as i32, args[1]);
            let target = if p == 0 {
                if dirfd == at {
                    return Err(libc::EFAULT);
                }
                Target::Fd { fd: dirfd }
            } else {
                Target::Path { dirfd, addr: p, follow: true, empty_path: false }
            };
            return Ok(Some(Call { target, op: Op::Times(TimesArg::Timeval(args[2])) }));
        }
    }
    Ok(None)
}

/// The timestamps as `utimensat` takes them, from the bytes the tracee
/// passed (`None`: a null pointer, "now"). A `timeval`'s microseconds
/// outside `0..1_000_000` are EINVAL, as the kernel's `utimes` checks; a
/// `timespec`'s nanoseconds are left to the kernel's own check
/// (`UTIME_NOW` and `UTIME_OMIT` included). A buffer of the wrong length is
/// EFAULT. Pure.
pub fn timespecs(arg: TimesArg, bytes: Option<&[u8]>) -> Result<Option<[libc::timespec; 2]>, i32> {
    let Some(b) = bytes else { return Ok(None) };
    let word = |i: usize| -> i64 { i64::from_ne_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()) };
    let ts = |sec: i64, nsec: i64| libc::timespec { tv_sec: sec as libc::time_t, tv_nsec: nsec as _ };
    match arg {
        TimesArg::Utimbuf(_) => {
            if b.len() != 16 {
                return Err(libc::EFAULT);
            }
            Ok(Some([ts(word(0), 0), ts(word(1), 0)]))
        }
        TimesArg::Timeval(_) => {
            if b.len() != 32 {
                return Err(libc::EFAULT);
            }
            let (s0, u0, s1, u1) = (word(0), word(1), word(2), word(3));
            if !(0..1_000_000).contains(&u0) || !(0..1_000_000).contains(&u1) {
                return Err(libc::EINVAL);
            }
            Ok(Some([ts(s0, u0 * 1000), ts(s1, u1 * 1000)]))
        }
        TimesArg::Timespec(_) => {
            if b.len() != 32 {
                return Err(libc::EFAULT);
            }
            Ok(Some([ts(word(0), word(1)), ts(word(2), word(3))]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[u64]) -> [u64; 6] {
        let mut x = [0u64; 6];
        x[..v.len()].copy_from_slice(v);
        x
    }

    #[test]
    fn both_families_are_listed_by_number() {
        let n = nrs();
        for nr in [libc::SYS_fchownat as i64, libc::SYS_fchown as i64, libc::SYS_utimensat as i64] {
            assert!(n.contains(&nr) && is_owner_time_nr(nr), "{nr}");
        }
        #[cfg(target_arch = "x86_64")]
        for nr in [libc::SYS_chown, libc::SYS_lchown, libc::SYS_utime, libc::SYS_utimes, libc::SYS_futimesat] {
            assert!(is_owner_time_nr(nr as i64), "{nr}");
        }
        assert!(!is_owner_time_nr(libc::SYS_fchmod as i64) && !is_owner_time_nr(libc::SYS_getxattr as i64));
    }

    #[test]
    fn fchownat_decodes_its_target_and_refuses_unknown_flags() {
        let at = libc::AT_FDCWD as u32 as u64;
        let c = decode(libc::SYS_fchownat as i64, &a(&[at, 0x10, 1000, u32::MAX as u64, 0])).unwrap().unwrap();
        assert_eq!(c, Call { target: Target::Path { dirfd: libc::AT_FDCWD, addr: 0x10, follow: true, empty_path: false }, op: Op::Owner { uid: 1000, gid: u32::MAX } });
        let l = decode(libc::SYS_fchownat as i64, &a(&[3, 0x10, 1, 2, (libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH) as u64])).unwrap().unwrap();
        assert_eq!(l.target, Target::Path { dirfd: 3, addr: 0x10, follow: false, empty_path: true });
        assert_eq!(decode(libc::SYS_fchownat as i64, &a(&[at, 0x10, 1, 2, 0x8000])), Err(libc::EINVAL));
        let f = decode(libc::SYS_fchown as i64, &a(&[7, 1, 2])).unwrap().unwrap();
        assert_eq!(f, Call { target: Target::Fd { fd: 7 }, op: Op::Owner { uid: 1, gid: 2 } });
    }

    #[test]
    fn utimensat_names_a_path_or_its_descriptor() {
        let at = libc::AT_FDCWD as u32 as u64;
        let p = decode(libc::SYS_utimensat as i64, &a(&[at, 0x10, 0x20, 0])).unwrap().unwrap();
        assert_eq!(p, Call { target: Target::Path { dirfd: libc::AT_FDCWD, addr: 0x10, follow: true, empty_path: false }, op: Op::Times(TimesArg::Timespec(0x20)) });
        let l = decode(libc::SYS_utimensat as i64, &a(&[4, 0x10, 0, libc::AT_SYMLINK_NOFOLLOW as u64])).unwrap().unwrap();
        assert_eq!(l.target, Target::Path { dirfd: 4, addr: 0x10, follow: false, empty_path: false });
        // glibc's futimens: a null path names the descriptor.
        let f = decode(libc::SYS_utimensat as i64, &a(&[5, 0, 0x20, 0])).unwrap().unwrap();
        assert_eq!(f.target, Target::Fd { fd: 5 });
        assert_eq!(decode(libc::SYS_utimensat as i64, &a(&[5, 0, 0x20, libc::AT_SYMLINK_NOFOLLOW as u64])), Err(libc::EINVAL));
        assert_eq!(decode(libc::SYS_utimensat as i64, &a(&[at, 0, 0x20, 0])), Err(libc::EFAULT));
        assert_eq!(decode(libc::SYS_utimensat as i64, &a(&[at, 0x10, 0x20, 0x8000])), Err(libc::EINVAL));
        assert_eq!(decode(libc::SYS_read as i64, &a(&[])), Ok(None));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_legacy_forms_decode_on_x86_64() {
        let at = libc::AT_FDCWD;
        let c = decode(libc::SYS_chown as i64, &a(&[0x10, 1, 2])).unwrap().unwrap();
        assert_eq!(c.target, Target::Path { dirfd: at, addr: 0x10, follow: true, empty_path: false });
        let l = decode(libc::SYS_lchown as i64, &a(&[0x10, 1, 2])).unwrap().unwrap();
        assert_eq!(l.target, Target::Path { dirfd: at, addr: 0x10, follow: false, empty_path: false });
        assert_eq!(decode(libc::SYS_utime as i64, &a(&[0x10, 0x20])).unwrap().unwrap().op, Op::Times(TimesArg::Utimbuf(0x20)));
        assert_eq!(decode(libc::SYS_utimes as i64, &a(&[0x10, 0])).unwrap().unwrap().op, Op::Times(TimesArg::Timeval(0)));
        let fa = decode(libc::SYS_futimesat as i64, &a(&[6, 0, 0x20])).unwrap().unwrap();
        assert_eq!(fa.target, Target::Fd { fd: 6 });
        assert_eq!(decode(libc::SYS_futimesat as i64, &a(&[at as u32 as u64, 0, 0x20])), Err(libc::EFAULT));
    }

    #[test]
    fn timestamps_are_converted_as_the_kernel_reads_them() {
        let words = |w: &[i64]| -> Vec<u8> { w.iter().flat_map(|x| x.to_ne_bytes()).collect() };
        assert!(timespecs(TimesArg::Timespec(0), None).unwrap().is_none(), "a null pointer: now");
        let t = timespecs(TimesArg::Utimbuf(1), Some(&words(&[11, 22]))).unwrap().unwrap();
        assert_eq!((t[0].tv_sec, t[0].tv_nsec, t[1].tv_sec, t[1].tv_nsec), (11, 0, 22, 0));
        let t = timespecs(TimesArg::Timeval(1), Some(&words(&[1, 5, 2, 999_999]))).unwrap().unwrap();
        assert_eq!((t[0].tv_nsec, t[1].tv_nsec), (5_000, 999_999_000));
        assert_eq!(timespecs(TimesArg::Timeval(1), Some(&words(&[1, 1_000_000, 2, 0]))).err(), Some(libc::EINVAL));
        assert_eq!(timespecs(TimesArg::Timeval(1), Some(&words(&[1, -1, 2, 0]))).err(), Some(libc::EINVAL));
        let t = timespecs(TimesArg::Timespec(1), Some(&words(&[3, libc::UTIME_OMIT, 4, libc::UTIME_NOW]))).unwrap().unwrap();
        assert_eq!((t[0].tv_nsec, t[1].tv_nsec), (libc::UTIME_OMIT, libc::UTIME_NOW));
        assert_eq!(timespecs(TimesArg::Timespec(1), Some(&[0u8; 8])).err(), Some(libc::EFAULT));
        assert_eq!(TimesArg::Timeval(0).ptr_len(), (0, 0));
        assert_eq!(TimesArg::Utimbuf(9).ptr_len(), (9, 16));
    }
}
