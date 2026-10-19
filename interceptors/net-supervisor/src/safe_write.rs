//! safe_write — the files the guard itself writes by name (its status record
//! for the launcher, its opt-in trace and open-stats files), never through a
//! link on the way (runtime-instances.md §2, "planted paths", 2026-10-17).
//!
//! The guard runs outside the agent's confinement, as the agent's user, and
//! its status file (`MANDU_NET_GUARD_STATUS`) lives in the session's scope
//! dir, which the agent may write while it runs. A plain
//! `std::fs::write("<status>.tmp")` at the guard's exit followed a link the
//! agent planted there and truncated the file it named (a shell startup
//! file) to `exited 0`. Here, as the launcher's `safe-log.ts`:
//!
//!   - the directory is opened ONCE, component by component from `/`, each
//!     relative to the one before (`openat`), `O_DIRECTORY|O_NOFOLLOW`; a
//!     link on the way is followed only when the system owns it (root, or the
//!     overflow uid a user namespace shows for an owner it does not map: one
//!     the agent could not have made, as macOS's `/tmp`); each directory must
//!     be the system's or this user's, and none another account may write
//!     unless it is sticky (`dir_problem`);
//!   - a record replaces its file: the leftover temp name is unlinked
//!     (`unlinkat` never follows), a fresh one created
//!     `O_CREAT|O_EXCL|O_NOFOLLOW` 0600 in the directory's descriptor, and
//!     `renameat` puts it over the name (replacing a link there, never
//!     writing through it);
//!   - an appended file is opened `O_APPEND|O_CREAT|O_NOFOLLOW|O_NONBLOCK`
//!     in the directory's descriptor and must be a regular file of its own
//!     (one link).
//!
//! The decisions are pure (`dir_problem`, `link_followable`, `split_path`);
//! the rest is thin `openat` plumbing.
//!
//! Mandu-new (no reference origin).

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// The overflow uid a user namespace shows for an owner it does not map.
fn overflow_uid() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/overflowuid").ok().and_then(|s| s.trim().parse().ok()).filter(|&n| n > 0).unwrap_or(65534)
}

/// Why a directory owned by `owner` with `mode` may not be on the way to a
/// file the guard writes, for a guard running as `me` (`system`: the owners
/// the agent cannot be), or None. Pure.
pub fn dir_problem(owner: u32, mode: u32, me: u32, system: &[u32]) -> Option<String> {
    if owner != me && !system.contains(&owner) {
        return Some(format!("is owned by uid {owner}, not by you (uid {me}) or the system"));
    }
    if mode & 0o002 != 0 && mode & 0o1000 == 0 {
        return Some(format!("is writable by every account (mode {:o}) and not sticky", mode & 0o7777));
    }
    None
}

/// May a link owned by `owner` on the way be followed? Only one the system
/// owns, never one of the guard's own user (the agent's). Pure.
pub fn link_followable(owner: u32, me: u32, system: &[u32]) -> bool {
    owner != me && system.contains(&owner)
}

/// An absolute, normalized path split into its directories and its file
/// name; None otherwise (relative, `.`/`..`, an empty component, no name). Pure.
pub fn split_path(path: &str) -> Option<(Vec<&str>, &str)> {
    let rest = path.strip_prefix('/')?;
    let mut parts: Vec<&str> = rest.split('/').collect();
    if parts.iter().any(|p| p.is_empty() || *p == "." || *p == "..") {
        return None;
    }
    let name = parts.pop()?;
    Some((parts, name))
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn fstatat_nofollow(dir: i32, name: &CString) -> io::Result<libc::stat> {
    // SAFETY: fstatat into a zeroed stat buffer we own; `name` is NUL-terminated.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

fn fstat(fd: i32) -> io::Result<libc::stat> {
    // SAFETY: fstat into a zeroed stat buffer we own.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

fn openat(dir: i32, name: &CString, flags: i32, mode: libc::c_uint) -> io::Result<OwnedFd> {
    // SAFETY: openat with a NUL-terminated name; the descriptor it returns is
    // ours alone and is owned from here.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn refused(what: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, what)
}

/// Open the directory `dirs` (from `/`), each component checked as above.
fn open_dir(dirs: &[&str]) -> io::Result<OwnedFd> {
    // SAFETY: geteuid has no failure mode.
    let me = unsafe { libc::geteuid() };
    let system = [0, overflow_uid()];
    let mut cur = openat(libc::AT_FDCWD, &cstr("/")?, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    let mut here = String::new();
    for d in dirs {
        here.push('/');
        here.push_str(d);
        let name = cstr(d)?;
        let st = fstatat_nofollow(cur.as_raw_fd(), &name)?;
        let next = if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
            if !link_followable(st.st_uid, me, &system) {
                return Err(refused(format!("{here} is a symbolic link on the way; refusing to write through it")));
            }
            openat(cur.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
        } else {
            let fd = openat(cur.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW, 0)?;
            let now = fstat(fd.as_raw_fd())?;
            if now.st_dev != st.st_dev || now.st_ino != st.st_ino {
                return Err(refused(format!("{here} changed while it was opened")));
            }
            fd
        };
        let now = fstat(next.as_raw_fd())?;
        if let Some(p) = dir_problem(now.st_uid, now.st_mode, me, &system) {
            return Err(refused(format!("{here} {p}")));
        }
        cur = next;
    }
    Ok(cur)
}

/// A file the guard writes, by its directory's descriptor (opened once, at
/// `open`) and its name.
pub struct DirFile {
    dir: OwnedFd,
    name: String,
}

impl DirFile {
    /// Open `path`'s directory, every component checked. Err: refused, or
    /// not an absolute, normalized path naming a file.
    pub fn open(path: &str) -> io::Result<DirFile> {
        let (dirs, name) = split_path(path).ok_or_else(|| refused(format!("{path} is not an absolute, normalized path to a file")))?;
        Ok(DirFile { dir: open_dir(&dirs)?, name: name.to_string() })
    }

    /// Replace the file with `bytes`: a fresh `<name>.tmp` made exclusively,
    /// then renamed over the name, so a reader never sees half and a link at
    /// either name is replaced, never followed.
    pub fn replace(&self, bytes: &[u8]) -> io::Result<()> {
        let tmp = cstr(&format!("{}.tmp", self.name))?;
        let name = cstr(&self.name)?;
        let d = self.dir.as_raw_fd();
        // SAFETY: unlinkat of a NUL-terminated name in a directory we hold;
        // it never follows a link. A missing leftover is the usual case.
        unsafe { libc::unlinkat(d, tmp.as_ptr(), 0) };
        let fd = openat(d, &tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW, 0o600)?;
        let mut f = std::fs::File::from(fd);
        io::Write::write_all(&mut f, bytes)?;
        drop(f);
        // SAFETY: renameat within the directory we hold, both names NUL-terminated.
        if unsafe { libc::renameat(d, tmp.as_ptr(), d, name.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Append `bytes` to the file (created 0600 when missing): never through
    /// a link, a FIFO, or a hard link to another file.
    pub fn append(&self, bytes: &[u8]) -> io::Result<()> {
        let name = cstr(&self.name)?;
        let fd = openat(self.dir.as_raw_fd(), &name, libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0o600)?;
        let st = fstat(fd.as_raw_fd())?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_nlink != 1 {
            return Err(refused(format!("{} is not a regular file of its own", self.name)));
        }
        let mut f = std::fs::File::from(fd);
        io::Write::write_all(&mut f, bytes)
    }
}

/// `DirFile::open(path)` then `replace`: a one-shot record.
pub fn replace_file(path: &str, bytes: &[u8]) -> io::Result<()> {
    DirFile::open(path)?.replace(bytes)
}

/// `DirFile::open(path)` then `append`: one line of a log.
pub fn append_file(path: &str, bytes: &[u8]) -> io::Result<()> {
    DirFile::open(path)?.append(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn a_directory_on_the_way_is_the_systems_or_ours_and_never_writable_by_all_unless_sticky() {
        let sys = [0, 65534];
        assert_eq!(dir_problem(1000, 0o40700, 1000, &sys), None);
        assert_eq!(dir_problem(1000, 0o40775, 1000, &sys), None, "group write (user private groups)");
        assert_eq!(dir_problem(0, 0o41777, 1000, &sys), None, "/tmp");
        assert_eq!(dir_problem(65534, 0o40755, 1000, &sys), None, "an owner the namespace does not map");
        assert!(dir_problem(0, 0o40777, 1000, &sys).is_some());
        assert!(dir_problem(1001, 0o40700, 1000, &sys).is_some(), "another account's");
        assert!(link_followable(0, 1000, &sys));
        assert!(!link_followable(1000, 1000, &sys), "a link of ours (the agent's) is never followed");
        assert!(!link_followable(1001, 1000, &sys));
        assert!(!link_followable(0, 0, &sys), "running as root, a root link could be the agent's");
    }

    #[test]
    fn only_an_absolute_normalized_path_to_a_file_splits() {
        assert_eq!(split_path("/a/b/c.txt"), Some((vec!["a", "b"], "c.txt")));
        assert_eq!(split_path("/c.txt"), Some((vec![], "c.txt")));
        assert_eq!(split_path("a/c.txt"), None);
        assert_eq!(split_path("/a/../c.txt"), None);
        assert_eq!(split_path("/a//c.txt"), None);
        assert_eq!(split_path("/a/"), None);
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("mandu-safe-write-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(&d).unwrap()
    }

    #[test]
    fn a_record_replaces_its_file_and_never_writes_through_a_planted_link() {
        let d = tmp("replace");
        let victim = d.join("victim.rc");
        std::fs::write(&victim, "keep me\n").unwrap();
        let status = d.join("net-guard.status");
        symlink(&victim, d.join("net-guard.status.tmp")).unwrap();
        symlink(&victim, &status).unwrap();
        replace_file(status.to_str().unwrap(), b"exited 0\n").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me\n", "the linked file is untouched");
        assert!(!std::fs::symlink_metadata(&status).unwrap().file_type().is_symlink(), "the link at the name was replaced");
        assert_eq!(std::fs::read_to_string(&status).unwrap(), "exited 0\n");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_directory_on_the_way_that_is_a_link_of_ours_gets_nothing() {
        let d = tmp("dirlink");
        let victim = d.join("victim");
        std::fs::create_dir(&victim).unwrap();
        symlink(&victim, d.join("scope")).unwrap();
        let p = d.join("scope").join("net-guard.status");
        let e = replace_file(p.to_str().unwrap(), b"exited 0\n").unwrap_err();
        assert!(e.to_string().contains("is a symbolic link on the way"), "{e}");
        let e = append_file(d.join("scope").join("trace.log").to_str().unwrap(), b"x\n").unwrap_err();
        assert!(e.to_string().contains("symbolic link on the way"), "{e}");
        assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 0, "nothing made in the linked-to folder");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_appended_log_refuses_a_link_a_hard_link_and_a_fifo_at_its_name() {
        let d = tmp("append");
        let log = d.join("trace.log");
        append_file(log.to_str().unwrap(), b"one\n").unwrap();
        append_file(log.to_str().unwrap(), b"two\n").unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "one\ntwo\n");
        assert_eq!(std::fs::metadata(&log).unwrap().permissions().mode() & 0o777, 0o600);
        let victim = d.join("victim.rc");
        std::fs::write(&victim, "keep me\n").unwrap();
        symlink(&victim, d.join("linked.log")).unwrap();
        assert!(append_file(d.join("linked.log").to_str().unwrap(), b"x\n").is_err());
        std::fs::hard_link(&victim, d.join("hard.log")).unwrap();
        assert!(append_file(d.join("hard.log").to_str().unwrap(), b"x\n").is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me\n");
        let fifo = cstr(d.join("fifo.log").to_str().unwrap()).unwrap();
        // SAFETY: mkfifo of a NUL-terminated path in our temp dir.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(append_file(d.join("fifo.log").to_str().unwrap(), b"x\n").is_err(), "no reader: refused at once, never a hang");
        let _ = std::fs::remove_dir_all(&d);
    }
}
