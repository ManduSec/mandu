//! Write a file a test will EXECUTE without ever holding a write descriptor to
//! it in the test process. Shared by exec-supervisor's and net-supervisor's
//! integration tests (net-supervisor includes it with `#[path]`).
//!
//! The race this closes (the ETXTBSY fork race): cargo runs a test binary's
//! tests as THREADS of one process, and many of them fork (the supervisor's
//! sandbox child, `std::process::Command`, `netns_available`'s probe child).
//! A fork copies the whole descriptor table, including a write descriptor a
//! sibling thread holds while it writes a script. `O_CLOEXEC` drops the copy
//! only when that child execs or exits, and a sandbox child first unshares
//! namespaces and mounts, which can take tens of milliseconds. Until then the
//! file has a writer, and `execve` of it fails with ETXTBSY: the supervisor's
//! child reports 126 ("execvp failed") instead of the probe's own exit code.
//! That was `execve_routes_to_agentshell_by_default_and_humanshell_when_needed`
//! failing about once in 22 CI runs on 16 CPUs.
//!
//! Writing the file in a forked, single-threaded child removes the window: the
//! write descriptor exists only in that child's table, and a sibling thread's
//! fork copies THIS process's table, which never holds it. When the helper
//! returns, no process has the file open for writing.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Create (or truncate) `path` with `contents`, mode 0755, from a forked child.
pub fn write_exec_script(path: &Path, contents: &[u8]) -> io::Result<()> {
    // Everything the child touches is prepared here: after a fork in a
    // multi-threaded process the child may only make async-signal-safe calls,
    // so it must not allocate (another thread may hold the allocator's lock).
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has a NUL byte"))?;
    // SAFETY: the child calls only open/write/fchmod/close/_exit on memory
    // allocated before the fork, then exits without returning.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe { libc::_exit(child_write(&cpath, contents)) };
    }
    let mut status = 0;
    loop {
        // SAFETY: waits for the child forked above.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            break;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        Ok(())
    } else if libc::WIFEXITED(status) {
        // The child exits with the errno of the step that failed.
        Err(io::Error::from_raw_os_error(libc::WEXITSTATUS(status)))
    } else {
        Err(io::Error::new(io::ErrorKind::Other, format!("script writer died: status {status}")))
    }
}

/// The child's half: 0 on success, else the failing call's errno (1 if none).
fn child_write(cpath: &CString, contents: &[u8]) -> i32 {
    let errno = || io::Error::last_os_error().raw_os_error().unwrap_or(1).clamp(1, 255);
    // SAFETY: plain syscalls on a path and a buffer that outlive the call.
    unsafe {
        let fd = libc::open(
            cpath.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
            0o755 as libc::c_uint,
        );
        if fd < 0 {
            return errno();
        }
        let mut off = 0;
        while off < contents.len() {
            let n = libc::write(fd, contents[off..].as_ptr().cast(), contents.len() - off);
            if n < 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return errno();
            }
            off += n as usize;
        }
        // The umask may have stripped bits from the create mode; an existing
        // file keeps its old mode under O_TRUNC. Set it explicitly.
        if libc::fchmod(fd, 0o755) != 0 {
            return errno();
        }
        if libc::close(fd) != 0 {
            return errno();
        }
    }
    0
}
