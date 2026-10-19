//! kernel — the seccomp-unotify supervisor loop (PRIVILEGED, feature-gated).
//!
//! Compiled ONLY with `--features kernel`. It needs:
//!   - root, OR CAP_SYS_ADMIN — which is also satisfied as *root-in-an-unprivileged
//!     user namespace* (`unshare --user --map-root-user`): installing a seccomp
//!     filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER` requires CAP_SYS_ADMIN in the
//!     filter's user namespace plus `no_new_privs`. Both are obtainable unprivileged
//!     in a userns, which is why the interception path is testable on this host;
//!   - kernel ≥ 5.0 with CONFIG_SECCOMP_USER_NOTIFICATION for the LISTENER + RECV +
//!     reading args (works even on a 5.4 kernel; the dev host is now 6.8).
//!
//! ── Kernel-version reality (honest matrix) ──────────────────────────────────
//! The three pieces of the user-notif protocol landed in different kernels:
//!   - LISTENER (NEW_LISTENER) + NOTIF_RECV + reading args (process_vm_readv):  5.0+
//!   - SECCOMP_USER_NOTIF_FLAG_CONTINUE (let the trapped syscall proceed):      5.5+
//!   - SECCOMP_IOCTL_NOTIF_ADDFD (inject a substitute fd = the REDIRECT):       5.9+
//! So on a 5.4 host this loop can install the listener, trap openat/openat2, read
//! the path, and DECIDE (redirect-vs-passthrough). It can ALLOW or DENY (errno) the
//! syscall, but it can neither inject the AgentView fd (no ADDFD) nor let the
//! original syscall proceed unchanged (no CONTINUE). `addfd_supported()` /
//! `continue_supported()` probe these at runtime and the loop degrades cleanly:
//! the full redirect is only verifiable on a ≥ 5.9 kernel (the 6.8 dev host
//! qualifies and runs it live; `scripts/kernel-vm.sh` covers older kernels).
//!
//! HOW IT MAPS TO THE PURE CORE: the loop reads the openat(2) arguments
//! (dirfd, user-space path pointer, flags) out of each `seccomp_notif`, resolves
//! the path against the tracked roots via `decision::decide_open` (delegated to the
//! unit-tested pure `step`), and then EITHER:
//!   - Redirect: opens the rewritten AgentView path itself and installs the FD into
//!     the target with SECCOMP_IOCTL_NOTIF_ADDFD (kernel ≥ 5.9), answering the
//!     notification so the original openat returns that FD; OR
//!   - Passthrough: answers SECCOMP_USER_NOTIF_FLAG_CONTINUE (kernel ≥ 5.5) so the
//!     kernel runs the real openat unchanged. On 5.4 (no CONTINUE) the documented
//!     degraded answer is ALLOW-via-self-open is unavailable, so passthrough on an
//!     untracked path falls back to a fresh `O_RDONLY` open of the *same* path we
//!     inject — see `passthrough_fallback`. The decision/rewrite is delegated
//!     entirely to the pure functions; this module is just the syscall plumbing.
//!
//! HOW TO RUN ON A PRIVILEGED HOST (see crate README for the full recipe):
//!   cargo build -p fs-supervisor --features kernel
//!   # real root, or an unprivileged user namespace (no host state changed):
//!   unshare --user --map-root-user --mount --pid --fork -- \
//!     bash -c 'cd interceptors && cargo test -p fs-supervisor --features kernel \
//!                -- --ignored --nocapture'

#![cfg(feature = "kernel")]

use std::io::{Error, ErrorKind, Result};
use std::os::unix::io::RawFd;

use crate::decision::{decide_open, Access, FirstTouchSet, OpenDecision, TrackedRoots};

/// The openat(2) syscall number on the target arch — the seccomp filter traps
/// this and SECCOMP_USER_NOTIF delivers the notification we read args from.
/// Sourced from libc so the feature build pins it to the host arch.
pub const SYS_OPENAT: libc::c_long = libc::SYS_openat;

/// openat2(2) — the modern, struct-arg open. A filter that traps only `openat`
/// is bypassable by an `openat2` caller, so we trap it too (kernel ≥ 5.6 exposes
/// the syscall; the constant is always defined on x86_64/aarch64 libc).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub const SYS_OPENAT2: libc::c_long = libc::SYS_openat2;

// ── seccomp ioctl request numbers ──────────────────────────────────────────
// libc 0.2 ships the seccomp_notif* STRUCTS and the SECCOMP_* flag constants,
// but NOT the SECCOMP_IOCTL_NOTIF_* ioctl request numbers. They are derived from
// the kernel's `linux/seccomp.h`:
//   #define SECCOMP_IOC_MAGIC  '!'   (0x21)
//   SECCOMP_IOCTL_NOTIF_RECV     = _IOWR('!', 0, struct seccomp_notif)
//   SECCOMP_IOCTL_NOTIF_SEND     = _IOWR('!', 1, struct seccomp_notif_resp)
//   SECCOMP_IOCTL_NOTIF_ID_VALID = _IOW ('!', 2, __u64)
//   SECCOMP_IOCTL_NOTIF_ADDFD    = _IOW ('!', 3, struct seccomp_notif_addfd)
// We hard-code the resolved values (cross-checked against the canonical _IO*
// macros for these exact struct sizes — see the crate's kernel_integration test
// which re-asserts the struct sizes the encoding depends on):
//   RECV     = 0xc0502100   (size field 0x50 = sizeof(seccomp_notif)      = 80)
//   SEND     = 0xc0182101   (size field 0x18 = sizeof(seccomp_notif_resp) = 24)
//   ID_VALID = 0x40082102   (size field 0x08 = sizeof(__u64)             =  8)
//   ADDFD    = 0x40182103   (size field 0x18 = sizeof(seccomp_notif_addfd)= 24)
pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;
pub const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;

/// AUDIT_ARCH_* for the filter's architecture check (not exported by libc 0.2).
/// EM_X86_64=62 | __AUDIT_ARCH_64BIT(0x80000000) | __AUDIT_ARCH_LE(0x40000000).
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
/// EM_AARCH64=183 | 64BIT | LE.
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

/// Reading openat() path/flags out of the seccomp_notif requires reading the
/// target's address space. We expose a small, testable shim so the loop body can
/// be exercised against a fake reader; the real impl is `VmReader` below.
pub trait NotifReader {
    /// Read a NUL-terminated path the syscall's `path` argument points at, from
    /// the tracee `pid`'s address space at `addr`.
    fn read_path(&self, pid: i32, addr: u64) -> Result<String>;
}

/// The production `NotifReader`: `process_vm_readv(2)` of the tracee's memory.
/// Reads a bounded window and stops at the first NUL (paths are PATH_MAX-bounded).
pub struct VmReader {
    pub max_len: usize,
}

impl Default for VmReader {
    fn default() -> Self {
        // PATH_MAX is 4096 on Linux; one window covers any legal path.
        VmReader { max_len: 4096 }
    }
}

impl NotifReader for VmReader {
    fn read_path(&self, pid: i32, addr: u64) -> Result<String> {
        if addr == 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "null path pointer"));
        }
        let mut buf = vec![0u8; self.max_len];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY: `local` points at our owned `buf` of `iov_len` bytes; `remote`
        // names the tracee's address space. process_vm_readv copies up to the min
        // of the two iov lengths and never writes past `buf`.
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            return Err(Error::last_os_error());
        }
        let n = n as usize;
        let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
        Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
    }
}

// ── path canonicalization against the TRACEE (TOCTOU-safe) ──────────────────
//
// `decide_open`/`rewrite_to_worktree` do a lexical PREFIX match on a CANONICAL
// ABSOLUTE path; if we fed them the RAW path the tracee passed, a relative path
// or a `..`-escape would either miss the tracked root entirely or — worse — let an
// attacker craft a string that prefix-matches the tracked root while the kernel
// would actually resolve it elsewhere. So before `decide_open` we resolve the
// (dirfd, raw_path) pair to a normalized absolute path, exactly mirroring the
// cooperative `fs-preload::absolutize` algorithm, but resolved against the TRACEE
// (`/proc/<pid>/cwd`, `/proc/<pid>/fd/<dirfd>`) instead of `/proc/self`.
//
// WHY THIS IS RACE-FREE HERE: seccomp user-notif SUSPENDS the tracee until the
// supervisor responds to the notification. While we are handling it, the tracee's
// `/proc/<pid>/cwd` and `/proc/<pid>/fd/<dirfd>` are STABLE — the tracee cannot
// chdir/close/reopen them under us — so reading them to resolve the path is NOT a
// TOCTOU race. `notif.pid` is the tracee pid; we use it.
//
// SYMLINKS ARE NOT RESOLVED (documented caveat): like `decide_open` and the
// fs-preload path, this is PURE STRING MATH (collapse `//`, drop `.`, pop on `..`).
// A symlinked component inside the tracked tree is not realpath-resolved; the
// launcher canonicalizes the tracked root and `/proc/<pid>/cwd` is already a
// realpath, so lexical math lands in the same prefix for the common case. Symlink
// resolution is intentionally out of scope (identical posture to the cooperative
// boundary).

/// Lexically normalize an ABSOLUTE path with pure string math — NO syscalls, NO
/// symlink resolution. Collapses repeated `/`, drops `.` segments, pops the prior
/// segment on `..` (never above `/`). The result is what `rewrite_to_worktree`
/// expects: absolute, no `.`/`..`/`//`. (Mirror of `fs-preload::normalize_lexical`.)
fn normalize_lexical(path: &str) -> String {
    debug_assert!(path.starts_with('/'), "normalize_lexical expects absolute");
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            // "" from a leading/trailing '/' or "//"; "." is a no-op.
            "" | "." => {}
            // Pop the previous real segment; at the root ".." is a no-op (can't go
            // above "/"), matching the kernel's path walk.
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut s = String::with_capacity(path.len());
    for seg in &out {
        s.push('/');
        s.push_str(seg);
    }
    if s.is_empty() {
        s.push('/');
    }
    s
}

/// Join a (possibly relative) `path` onto an absolute `base` directory and return a
/// normalized absolute path. If `path` is already absolute, `base` is ignored
/// (POSIX openat semantics). (Mirror of `fs-preload::join_and_normalize`.)
fn join_and_normalize(base: &str, path: &str) -> String {
    if path.starts_with('/') {
        return normalize_lexical(path);
    }
    let joined = format!("{}/{}", base.trim_end_matches('/'), path);
    normalize_lexical(&joined)
}

/// Read a `/proc/<pid>/...` symlink (`cwd` or `fd/<n>`) for the TRACEE, returning
/// the absolute directory path it points at. `None` (fail-safe) if readlink fails,
/// the target is non-UTF-8, or it is not an absolute path (e.g. an
/// `anon_inode:[...]`/pipe/socket dirfd, or a `(deleted)`-suffixed target we can't
/// safely join onto). Plain `readlink(2)` — no openat, no recursion.
fn read_proc_link(pid: i32, suffix: &str) -> Option<String> {
    let link = format!("/proc/{pid}/{suffix}\0");
    let mut buf = [0u8; 4096];
    // SAFETY: `link` is NUL-terminated; `buf` is a valid writable region of len().
    let n = unsafe {
        libc::readlink(
            link.as_ptr() as *const libc::c_char,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if n <= 0 {
        return None;
    }
    let target = std::str::from_utf8(&buf[..n as usize]).ok()?;
    // Must be a real absolute directory path. Reject anon_inode/pipe/socket targets
    // and anything non-absolute — we can't safely join onto it, so fail safe.
    if !target.starts_with('/') {
        return None;
    }
    Some(target.to_string())
}

/// `AT_FDCWD` (openat "use the cwd" sentinel). libc exposes it; we name it locally
/// so the canonicalizer reads clearly.
const AT_FDCWD: i32 = libc::AT_FDCWD;

/// Resolve a (`dirfd`, `raw_path`) openat pair issued by the TRACEE `pid` into a
/// normalized ABSOLUTE path string, applying POSIX openat semantics against the
/// SUSPENDED tracee's `/proc/<pid>` (race-free, see the module note above):
///
///   - absolute `raw_path` → used as-is (dirfd ignored), normalized.
///   - relative + `dirfd == AT_FDCWD` → joined onto `readlink(/proc/<pid>/cwd)`.
///   - relative + real `dirfd` → joined onto `readlink(/proc/<pid>/fd/<dirfd>)`.
///
/// Returns `None` (caller FAILS SAFE — passthrough/allow, does NOT redirect) when
/// the dirfd can't be resolved to a directory path (readlink fails, or it points at
/// a pipe/socket/anon_inode rather than a dir). NO symlink resolution (lexical
/// only) — documented caveat, matching `decide_open`'s contract + the fs-preload
/// posture.
pub fn canonicalize_for_tracee(pid: i32, dirfd: i32, raw_path: &str) -> Option<String> {
    if raw_path.starts_with('/') {
        // Absolute: dirfd is irrelevant (POSIX). Normalize so the prefix match is
        // robust to `.`/`..`/`//`.
        return Some(normalize_lexical(raw_path));
    }
    // Relative: resolve the base directory against the SUSPENDED tracee.
    let base = if dirfd == AT_FDCWD {
        read_proc_link(pid, "cwd")?
    } else {
        read_proc_link(pid, &format!("fd/{dirfd}"))?
    };
    Some(join_and_normalize(&base, raw_path))
}

/// Outcome the loop will enact for one notification. Mirrors `OpenDecision` but
/// names the kernel action explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifAction {
    /// Open this AgentView path and ADDFD it into the target (kernel ≥ 5.9).
    AddFd { agent_view_path: String },
    /// Answer with SECCOMP_USER_NOTIF_FLAG_CONTINUE (run the real syscall).
    Continue,
}

/// Pure loop-body step: given a resolved (canonical) path + flags, decide the
/// kernel action. Separated from the ioctl glue so the privileged integration
/// test can drive it deterministically.
pub fn step(roots: &TrackedRoots, seen: &mut FirstTouchSet, path: &str, flags: i32) -> NotifAction {
    let first_touch = seen.touch(path);
    match decide_open(roots, path, flags, first_touch) {
        OpenDecision::Redirect { agent_view_path, .. } => NotifAction::AddFd { agent_view_path },
        OpenDecision::Passthrough { .. } => NotifAction::Continue,
    }
}

// ── seccomp filter install (the "listener fd" side) ─────────────────────────

/// Install a seccomp filter trapping `openat`/`openat2` with
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER`, returning the listener fd. The CALLER must
/// have already set `PR_SET_NO_NEW_PRIVS` (see `install_filter_self`) — the kernel
/// rejects the install otherwise (unless privileged).
///
/// This is normally called in the tracee (the process to be supervised), which
/// then sends the returned fd to the supervisor over a unix socket / inherits it.
/// In-process (test) use installs it on the current thread and keeps the fd here.
pub fn install_openat_listener() -> Result<RawFd> {
    let mut prog = openat_filter_program();
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };

    // SAFETY: SYS_seccomp(SET_MODE_FILTER, NEW_LISTENER, &fprog). The kernel copies
    // the program in; `prog`/`fprog` outlive the call. On success it returns the
    // listener fd. Requires no_new_privs + CAP_SYS_ADMIN-in-userns.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const libc::sock_fprog,
        )
    };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    Ok(fd as RawFd)
}

/// x86_64 x32-ABI syscalls carry this bit in `nr` under the SAME audit arch.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The openat listener's program: validate arch, refuse x32 numbers (ENOSYS:
/// `openat | X32` would miss the plain-number traps on a kernel with x32
/// enabled; sandbox-security-review-2026-09-28 finding 10), then trap
/// openat/openat2 → USER_NOTIF, else ALLOW.
pub fn openat_filter_program() -> Vec<libc::sock_filter> {
    // BPF offsets into struct seccomp_data: arch @ 4, nr @ 0.
    const ARCH_OFF: u32 = 4;
    const NR_OFF: u32 = 0;
    let openat = SYS_OPENAT as u32;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let openat2 = SYS_OPENAT2 as u32;

    let mut prog: Vec<libc::sock_filter> = Vec::new();
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };

    let bpf_ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let bpf_jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let bpf_ret = (libc::BPF_RET | libc::BPF_K) as u16;

    // 1) Load arch; if != AUDIT_ARCH → KILL_PROCESS (defensive; a foreign-arch
    //    syscall would misread nr/args).
    prog.push(stmt(bpf_ld, ARCH_OFF));
    prog.push(jump(bpf_jeq, AUDIT_ARCH, 1, 0)); // arch ok → skip the kill
    prog.push(stmt(bpf_ret, libc::SECCOMP_RET_KILL_PROCESS));
    // 2) Load nr.
    prog.push(stmt(bpf_ld, NR_OFF));
    // 2b) x32 number → ENOSYS.
    #[cfg(target_arch = "x86_64")]
    {
        let bpf_jset = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
        prog.push(jump(bpf_jset, X32_SYSCALL_BIT, 0, 1));
        prog.push(stmt(bpf_ret, libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32)));
    }
    // 3) nr == openat → USER_NOTIF.
    prog.push(jump(bpf_jeq, openat, 0, 1)); // match → next; miss → skip next
    prog.push(stmt(bpf_ret, libc::SECCOMP_RET_USER_NOTIF));
    // 4) nr == openat2 → USER_NOTIF.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        prog.push(jump(bpf_jeq, openat2, 0, 1));
        prog.push(stmt(bpf_ret, libc::SECCOMP_RET_USER_NOTIF));
    }
    // 5) default → ALLOW (every other syscall runs normally).
    prog.push(stmt(bpf_ret, libc::SECCOMP_RET_ALLOW));
    prog
}

/// Set `PR_SET_NO_NEW_PRIVS` on the current thread (prerequisite for an
/// unprivileged-in-userns seccomp filter install). Idempotent.
pub fn set_no_new_privs() -> Result<()> {
    // SAFETY: prctl with no pointer args; sets a thread flag.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Convenience for the tracee side: no_new_privs + install the openat listener,
/// returning the listener fd (which the tracee then hands to the supervisor).
pub fn install_filter_self() -> Result<RawFd> {
    set_no_new_privs()?;
    install_openat_listener()
}

// ── notification receive / respond ──────────────────────────────────────────

/// Receive one notification off the listener fd (blocking). Returns the raw
/// `seccomp_notif` (id/pid/flags/data). EINTR is surfaced to the caller.
pub fn notif_recv(listener_fd: RawFd) -> Result<libc::seccomp_notif> {
    // Zero-initialize: the kernel requires a clean buffer for NOTIF_RECV.
    let mut notif: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    // SAFETY: ioctl writes a full seccomp_notif into our stack buffer.
    let rc = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_RECV as _,
            &mut notif as *mut libc::seccomp_notif,
        )
    };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(notif)
}

/// True iff this notification id is still valid (the tracee has not died /
/// been interrupted). Must be checked after any slow work (e.g. opening a file)
/// and before ADDFD, to avoid acting on a stale notification.
pub fn notif_id_valid(listener_fd: RawFd, id: u64) -> bool {
    // SAFETY: ID_VALID reads an __u64 by pointer; returns 0 if still valid.
    let rc = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_ID_VALID as _,
            &id as *const u64,
        )
    };
    rc == 0
}

/// Send a plain response: make the trapped syscall return `val` (≥ 0) or fail
/// with `-errno` (`error` < 0). `flags` carries SECCOMP_USER_NOTIF_FLAG_CONTINUE
/// when we want the kernel to run the real syscall instead.
fn notif_send(listener_fd: RawFd, resp: &libc::seccomp_notif_resp) -> Result<()> {
    // SAFETY: SEND reads a seccomp_notif_resp by pointer.
    let rc = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_SEND as _,
            resp as *const libc::seccomp_notif_resp,
        )
    };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Answer the notification with CONTINUE — the kernel runs the original syscall
/// unchanged. Kernel ≥ 5.5. (On 5.4 this returns ENOSYS/EINVAL from the kernel.)
pub fn respond_continue(listener_fd: RawFd, id: u64) -> Result<()> {
    let resp = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: 0,
        flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    };
    notif_send(listener_fd, &resp)
}

/// Answer the notification with an errno — the trapped syscall returns `-errno`
/// to the tracee, and the real syscall is NOT run. Used as the fail-closed /
/// degraded answer on kernels without CONTINUE.
pub fn respond_errno(listener_fd: RawFd, id: u64, errno: i32) -> Result<()> {
    let resp = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: -errno.abs(),
        flags: 0,
    };
    notif_send(listener_fd, &resp)
}

/// Answer the notification with a return VALUE — the trapped syscall returns
/// `val` to the tracee and the real syscall is NOT run (the supervisor did the
/// work: a send it performed answers the bytes it sent).
pub fn respond_value(listener_fd: RawFd, id: u64, val: i64) -> Result<()> {
    let resp = libc::seccomp_notif_resp { id, val, error: 0, flags: 0 };
    notif_send(listener_fd, &resp)
}

/// ADDFD: install `src_fd` (an fd WE hold — the opened AgentView file) into the
/// tracee, and make the trapped openat return that fd number. Kernel ≥ 5.9.
/// Uses SECCOMP_ADDFD_FLAG_SEND so the addfd + the notif response are atomic.
/// Returns the new fd number assigned in the tracee, or an error (e.g. ENOTTY /
/// EINVAL on kernels < 5.9 where ADDFD is unsupported).
pub fn respond_addfd(listener_fd: RawFd, id: u64, src_fd: RawFd) -> Result<i32> {
    let addfd = libc::seccomp_notif_addfd {
        id,
        // ADDFD_FLAG_SEND: deliver the response atomically with the fd install,
        // so the syscall returns the new fd in one step (no separate SEND).
        flags: libc::SECCOMP_ADDFD_FLAG_SEND as u32,
        srcfd: src_fd as u32,
        newfd: 0,
        newfd_flags: 0,
    };
    // SAFETY: ADDFD reads a seccomp_notif_addfd by pointer; on success returns the
    // new fd number installed in the tracee.
    let rc = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_ADDFD as _,
            &addfd as *const libc::seccomp_notif_addfd,
        )
    };
    if rc < 0 {
        return Err(Error::last_os_error());
    }
    Ok(rc)
}

/// Is SECCOMP_IOCTL_NOTIF_ADDFD (the redirect primitive) available on this kernel?
///
/// AUTHORITATIVE GATE = kernel version ≥ 5.9 (when ADDFD landed). We deliberately
/// trust the version, not an ioctl probe, because the probe is ambiguous:
///
///   Empirically (measured on the then-5.4 dev host, in an unprivileged userns): an ADDFD
///   ioctl with a bogus notification id (`u64::MAX`) returns **EINVAL (22)** — the
///   kernel rejects the unknown ioctl number. BUT on a ≥ 5.9 kernel the SAME bogus
///   id ALSO fails the id-validation with EINVAL. So `EINVAL` cannot distinguish
///   "ioctl absent" (5.4) from "ioctl present, id invalid" (≥ 5.9): a probe-only
///   check would FALSE-NEGATIVE on a 5.9+ kernel and wrongly disable the redirect.
///
/// Hence: version-gate. (ENOTTY would unambiguously mean "absent", but 5.4 returns
/// EINVAL, not ENOTTY — see the probe note above.) On a ≥ 5.9 kernel (this 6.8
/// host included) this returns true
/// and the full ADDFD redirect path in `handle_notif` runs.
pub fn addfd_supported(_listener_fd: RawFd) -> bool {
    kernel_at_least(5, 9)
}

/// Coarse kernel-version probe: returns `(major, minor)` from `uname.release`.
/// Used by the integration test to gate the REDIRECT assertion on ≥ 5.9.
pub fn kernel_version() -> (u32, u32) {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return (0, 0);
    }
    // release is a C string like "6.8.0-1060-aws".
    let rel: Vec<u8> = uts
        .release
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    let rel = String::from_utf8_lossy(&rel);
    let mut it = rel.split(|c: char| c == '.' || c == '-');
    let major = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor)
}

/// True iff the running kernel is ≥ the given (major, minor).
pub fn kernel_at_least(major: u32, minor: u32) -> bool {
    let (km, kn) = kernel_version();
    (km, kn) >= (major, minor)
}

// ── the supervisor loop ─────────────────────────────────────────────────────

/// How the supervisor answers a passthrough (untracked-path) notification when
/// the kernel lacks SECCOMP_USER_NOTIF_FLAG_CONTINUE (< 5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedPassthrough {
    /// Open the SAME path ourselves and ADDFD it back (needs ADDFD ⇒ ≥ 5.9). This
    /// reproduces a passthrough without CONTINUE, but only where ADDFD exists.
    SelfOpen,
    /// Deny the syscall with EPERM. Strict mode: an untracked open the supervisor
    /// cannot faithfully pass through is refused rather than silently dropped.
    DenyEperm,
}

/// Loop configuration: the tracked roots + the degraded-mode policy + an injected
/// reader (so tests can drive it with a fake address-space reader; production
/// passes `VmReader::default()`).
pub struct LoopConfig<R: NotifReader> {
    pub roots: TrackedRoots,
    pub reader: R,
    /// Used only on kernels without CONTINUE (< 5.5).
    pub degraded_passthrough: DegradedPassthrough,
    /// Arbiter for the best-effort write-taint hook (design §3.1). When `Some`, a
    /// WRITE-intent open of a tracked path by a tainted process taints the file.
    /// Optional + off the redirect path — a miss never changes the seccomp answer.
    pub arbiter: Option<mandu_arbiter::ArbiterClient>,
}

/// One-notification outcome, surfaced so callers/tests can assert what happened
/// without scraping logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandledNotif {
    /// A tracked path was redirected: we opened `agent_view_path` and ADDFD'd it,
    /// the tracee's open now returns `new_fd`.
    Redirected { agent_view_path: String, new_fd: i32 },
    /// A tracked path WOULD be redirected, but ADDFD is unavailable (< 5.9). We
    /// answered with the degraded response and recorded the intended target.
    RedirectUnavailable { agent_view_path: String, answered: &'static str },
    /// An untracked path was passed through (CONTINUE), or — on < 5.5 — handled by
    /// the degraded passthrough policy.
    PassedThrough { answered: &'static str },
}

/// Handle exactly one already-received notification: read the path, run the pure
/// `step`, and enact the answer. Factored out of `run_supervisor` so the
/// integration test can drive a single notification deterministically.
///
/// `flags_arg_index`/`path_arg_index` are the seccomp_data.args slots for the
/// trapped syscall: openat(dirfd, path, flags, mode) → path=args[1], flags=args[2].
pub fn handle_notif<R: NotifReader>(
    listener_fd: RawFd,
    cfg: &mut LoopConfig<R>,
    seen: &mut FirstTouchSet,
    notif: &libc::seccomp_notif,
) -> Result<HandledNotif> {
    let pid = notif.pid as i32;
    let dirfd = notif.data.args[0] as i32;
    let path_addr = notif.data.args[1];
    let flags = notif.data.args[2] as i32;

    let raw_path = cfg.reader.read_path(pid, path_addr)?;
    // Canonicalize the RAW path the tracee passed against the tracee's own
    // `dirfd`/cwd BEFORE matching — this closes the TOCTOU residue: a relative path
    // or a `..`-escape is resolved to its real absolute target so `decide_open`'s
    // lexical prefix match can't be tricked (a `..`-escape lands OUTSIDE the root →
    // passthrough; a relative path inside the root → redirect). Race-free because
    // user-notif SUSPENDS the tracee, so `/proc/<pid>/cwd` + `/proc/<pid>/fd/<dirfd>`
    // are stable while we read them (see the module note + `canonicalize_for_tracee`).
    //
    // FAIL-SAFE on an unresolvable dirfd (pipe/socket/anon_inode, or readlink fail):
    // `canonicalize_for_tracee` returns None → we do NOT redirect; we treat the open
    // as a PASSTHROUGH (the same answer `decide_open` gives an untracked path). This
    // cannot expose raw HumanView bytes for a tracked file (a tracked file always has
    // a resolvable dir), and never blindly prefix-matches an unresolved raw string.
    let path = match canonicalize_for_tracee(pid, dirfd, &raw_path) {
        Some(p) => p,
        None => {
            // Unresolvable base dir → can't safely redirect. Pass through.
            return passthrough(listener_fd, notif, cfg, &raw_path);
        }
    };

    match step(&cfg.roots, seen, &path, flags) {
        NotifAction::AddFd { agent_view_path } => {
            if !addfd_supported(listener_fd) {
                // No ADDFD (< 5.9): we cannot inject the AgentView fd. Degrade
                // WITHOUT exposing raw bytes: deny so the agent does not silently
                // read un-redirected HumanView content. The redirect is the
                // security boundary; if we can't enact it, fail closed.
                if notif_id_valid(listener_fd, notif.id) {
                    respond_errno(listener_fd, notif.id, libc::EPERM)?;
                }
                return Ok(HandledNotif::RedirectUnavailable {
                    agent_view_path,
                    answered: "EPERM (no ADDFD < 5.9; fail-closed, no raw bytes)",
                });
            }
            // Open the AgentView target ourselves (O_RDONLY|O_CLOEXEC) and inject.
            let src_fd = open_agent_view(&agent_view_path)?;
            // Re-check the id after the (slow) open: the tracee may have died.
            if !notif_id_valid(listener_fd, notif.id) {
                close_fd(src_fd);
                return Err(Error::new(ErrorKind::Other, "notification expired before ADDFD"));
            }
            let new_fd = respond_addfd(listener_fd, notif.id, src_fd);
            close_fd(src_fd); // the kernel dup'd it into the tracee; ours is done.
            let new_fd = new_fd?;
            // ── best-effort write-taint (design §3.1), OFF the redirect path: if
            //    this open WRITES and the trapped writer is tainted, taint the file
            //    so a later read is recognized untrusted-by-origin. The redirect +
            //    seccomp answer above are UNCHANGED; a arbiter miss here is swallowed.
            maybe_taint_written_file(cfg, notif.pid as i32, &path, flags);
            Ok(HandledNotif::Redirected { agent_view_path, new_fd })
        }
        NotifAction::Continue => passthrough(listener_fd, notif, cfg, &path),
    }
}

/// Enact a PASSTHROUGH (untracked path, or an unresolvable-dirfd fail-safe): prefer
/// CONTINUE (≥ 5.5) so the kernel runs the real syscall unchanged; on < 5.5 fall
/// back to the configured degraded policy. `passthrough_path` is the path the
/// degraded `SelfOpen` re-opens (the canonical path for a normal passthrough, or
/// the raw path when canonicalization could not produce one).
fn passthrough<R: NotifReader>(
    listener_fd: RawFd,
    notif: &libc::seccomp_notif,
    cfg: &LoopConfig<R>,
    passthrough_path: &str,
) -> Result<HandledNotif> {
    // Prefer CONTINUE (≥ 5.5); else apply degraded policy.
    if kernel_at_least(5, 5) {
        if notif_id_valid(listener_fd, notif.id) {
            respond_continue(listener_fd, notif.id)?;
        }
        Ok(HandledNotif::PassedThrough { answered: "CONTINUE (≥ 5.5)" })
    } else {
        match cfg.degraded_passthrough {
            DegradedPassthrough::SelfOpen if addfd_supported(listener_fd) => {
                let src_fd = open_agent_view(passthrough_path)?; // same path, raw
                if !notif_id_valid(listener_fd, notif.id) {
                    close_fd(src_fd);
                    return Err(Error::new(ErrorKind::Other, "notification expired"));
                }
                let nf = respond_addfd(listener_fd, notif.id, src_fd);
                close_fd(src_fd);
                nf?;
                Ok(HandledNotif::PassedThrough { answered: "self-open ADDFD (no CONTINUE)" })
            }
            _ => {
                if notif_id_valid(listener_fd, notif.id) {
                    respond_errno(listener_fd, notif.id, libc::EPERM)?;
                }
                Ok(HandledNotif::PassedThrough {
                    answered: "EPERM (no CONTINUE < 5.5, strict degraded)",
                })
            }
        }
    }
}

/// Open an AgentView path read-only for ADDFD injection. O_CLOEXEC so our copy
/// never leaks; the kernel dups it into the tracee on ADDFD.
fn open_agent_view(path: &str) -> Result<RawFd> {
    let c = std::ffi::CString::new(path)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "path has interior NUL"))?;
    // SAFETY: open with a valid NUL-terminated path; flags are constants.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    Ok(fd)
}

fn close_fd(fd: RawFd) {
    // SAFETY: closing an fd we own; ignore EINTR/EBADF on a best-effort close.
    unsafe {
        libc::close(fd);
    }
}

/// The supervisor loop entry point. Owns the listener fd and loops:
///   NOTIF_RECV → read path → `step` → ADDFD / CONTINUE / degraded answer.
///
/// Runs until the listener fd returns an error that is not EINTR (e.g. the tracee
/// exited and the last notification drained → ENOENT/EBADF on RECV), which is the
/// normal termination. Production passes `VmReader::default()`.
pub fn run_supervisor(listener_fd: RawFd, roots: TrackedRoots) -> Result<()> {
    let mut cfg = LoopConfig {
        roots,
        reader: VmReader::default(),
        degraded_passthrough: DegradedPassthrough::DenyEperm,
        // Attach the arbiter for the best-effort write-taint hook; a missing env
        // var (e.g. the arbiter is not running) → None, the hook is simply inert.
        arbiter: mandu_arbiter::ArbiterClient::from_env().ok(),
    };
    let mut seen = FirstTouchSet::new();
    loop {
        match notif_recv(listener_fd) {
            Ok(notif) => {
                // A failure handling ONE notification must not kill the loop; log
                // (best-effort) and continue so one bad open can't wedge the agent.
                let _ = handle_notif(listener_fd, &mut cfg, &mut seen, &notif);
            }
            Err(e) => match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                // No more notifications / tracee gone → normal shutdown.
                Some(libc::ENOENT) | Some(libc::EBADF) => return Ok(()),
                _ => return Err(e),
            },
        }
    }
}

/// Best-effort: taint the just-written tracked file if the trapped WRITER process
/// is tainted (design §3.1). NO-OP unless `cfg.arbiter` is set and the open is a
/// write. Off the security path: any arbiter error is swallowed (never changes the
/// redirect/answer). Reuses the pure `decision::record_file_taint_if_tainted`.
fn maybe_taint_written_file<R: NotifReader>(
    cfg: &mut LoopConfig<R>,
    writer_pid: i32,
    path: &str,
    flags: i32,
) {
    // Only writes taint the file; a pure read does not.
    if matches!(Access::from_flags(flags), Access::Read) {
        return;
    }
    let Some(client) = cfg.arbiter.as_mut() else { return };
    let Some(writer_key) = mandu_arbiter::proc::proc_key_for_pid(writer_pid) else {
        return; // /proc race for the writer → skip the tag (best-effort)
    };
    // content-hash on the kernel path is out of scope here (we don't read the file
    // bytes in the notif handler); pass the path as both the hash-less key and the
    // path index. origin_host is unknown at the fs layer (the taint came from net),
    // so the arbiter correlates by the writer's process_taint origin — pass "" and
    // let record_file_taint_if_tainted record the file under the path index.
    let _ = crate::decision::record_file_taint_if_tainted(
        client,
        &writer_key,
        /*content_hash=*/ path, // path-keyed; content-hash enrichment is deferred
        path,
        /*origin_host=*/ "",
    );
}

#[cfg(test)]
mod tests {
    /// Run the openat program on one (nr, arch): its return value.
    fn run_openat_filter(nr: u32, arch: u32) -> u32 {
        let prog = openat_filter_program();
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&nr.to_ne_bytes());
        data[4..8].copy_from_slice(&arch.to_ne_bytes());
        let (mut pc, mut acc) = (0usize, 0u32);
        loop {
            let ins = prog[pc];
            match (ins.code & 0x07) as u32 {
                libc::BPF_LD => {
                    let o = ins.k as usize;
                    acc = u32::from_ne_bytes(data[o..o + 4].try_into().unwrap());
                    pc += 1;
                }
                libc::BPF_JMP if ins.code & 0xf0 == libc::BPF_JSET as u16 => pc += 1 + if acc & ins.k != 0 { ins.jt as usize } else { ins.jf as usize },
                libc::BPF_JMP => pc += 1 + if acc == ins.k { ins.jt as usize } else { ins.jf as usize },
                libc::BPF_RET => return ins.k,
                _ => panic!("unexpected instruction {:?}", ins.code),
            }
        }
    }

    #[test]
    fn openat_filter_traps_the_opens_and_allows_the_rest() {
        assert_eq!(run_openat_filter(SYS_OPENAT as u32, AUDIT_ARCH), libc::SECCOMP_RET_USER_NOTIF);
        assert_eq!(run_openat_filter(SYS_OPENAT2 as u32, AUDIT_ARCH), libc::SECCOMP_RET_USER_NOTIF);
        assert_eq!(run_openat_filter(libc::SYS_read as u32, AUDIT_ARCH), libc::SECCOMP_RET_ALLOW);
        assert_eq!(run_openat_filter(libc::SYS_read as u32, 0x4000_0003), libc::SECCOMP_RET_KILL_PROCESS);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn openat_filter_refuses_x32_numbers() {
        let enosys = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
        assert_eq!(run_openat_filter(SYS_OPENAT as u32 | X32_SYSCALL_BIT, AUDIT_ARCH), enosys);
        assert_eq!(run_openat_filter(libc::SYS_read as u32 | X32_SYSCALL_BIT, AUDIT_ARCH), enosys);
    }

    use super::*;
    use crate::layout::ViewLayout;

    fn roots() -> TrackedRoots {
        TrackedRoots::with_layouts(vec![ViewLayout::new("/home/u/proj", "/state")])
    }

    #[test]
    fn step_redirects_tracked_and_passes_untracked() {
        let mut seen = FirstTouchSet::new();
        match step(&roots(), &mut seen, "/home/u/proj/secret.txt", 0) {
            NotifAction::AddFd { agent_view_path } => {
                assert_eq!(
                    agent_view_path,
                    "/state/workspaces/proj-9c09f8055a26/agentview/secret.txt"
                );
            }
            other => panic!("expected AddFd, got {other:?}"),
        }
        assert_eq!(
            step(&roots(), &mut seen, "/etc/passwd", 0),
            NotifAction::Continue
        );
    }

    #[test]
    fn ioctl_numbers_match_canonical_seccomp_h() {
        // These are the published SECCOMP_IOCTL_NOTIF_* values, and the struct
        // sizes the _IO* encoding depends on. If libc ever changes the struct
        // layout, this guards the hard-coded ioctl numbers.
        assert_eq!(std::mem::size_of::<libc::seccomp_notif>(), 0x50);
        assert_eq!(std::mem::size_of::<libc::seccomp_notif_resp>(), 0x18);
        assert_eq!(std::mem::size_of::<libc::seccomp_notif_addfd>(), 0x18);
        assert_eq!(SECCOMP_IOCTL_NOTIF_RECV, 0xc050_2100);
        assert_eq!(SECCOMP_IOCTL_NOTIF_SEND, 0xc018_2101);
        assert_eq!(SECCOMP_IOCTL_NOTIF_ID_VALID, 0x4008_2102);
        assert_eq!(SECCOMP_IOCTL_NOTIF_ADDFD, 0x4018_2103);
    }

    #[test]
    fn kernel_version_parses() {
        let (maj, _min) = kernel_version();
        // Any Linux we run on is ≥ 3; this just proves the parser isn't returning 0.
        assert!(maj >= 3, "unexpected kernel major {maj}");
    }

    // ── path canonicalization (pure string math; no /proc reads here) ───────────

    #[test]
    fn normalize_collapses_slashes_and_dots() {
        assert_eq!(normalize_lexical("/a/b/c"), "/a/b/c");
        assert_eq!(normalize_lexical("/a//b/./c/"), "/a/b/c");
        assert_eq!(normalize_lexical("/a/b/."), "/a/b");
        assert_eq!(normalize_lexical("///"), "/");
        assert_eq!(normalize_lexical("/"), "/");
    }

    #[test]
    fn normalize_pops_on_dotdot_and_stops_at_root() {
        assert_eq!(normalize_lexical("/a/b/../c"), "/a/c");
        assert_eq!(normalize_lexical("/a/../b"), "/b");
        // ".." at/above the root is a no-op (can't escape "/").
        assert_eq!(normalize_lexical("/.."), "/");
        assert_eq!(normalize_lexical("/../../a"), "/a");
        assert_eq!(normalize_lexical("/a/../.."), "/");
    }

    #[test]
    fn join_relative_uses_base_then_normalizes() {
        assert_eq!(join_and_normalize("/home/u/proj", "notes.txt"), "/home/u/proj/notes.txt");
        assert_eq!(join_and_normalize("/home/u/proj", "./sub/secret.txt"), "/home/u/proj/sub/secret.txt");
        // A `..` that escapes the base is resolved lexically (the security point):
        // pop one segment per `..`. From "/home/u/proj/sub" three `..` reach "/home".
        assert_eq!(join_and_normalize("/home/u/proj/sub", "../notes.txt"), "/home/u/proj/notes.txt");
        assert_eq!(join_and_normalize("/home/u/proj/sub", "../../../etc/passwd"), "/home/etc/passwd");
        // A trailing slash on the base is tolerated (single join slash).
        assert_eq!(join_and_normalize("/home/u/proj/", "a.txt"), "/home/u/proj/a.txt");
    }

    #[test]
    fn join_absolute_path_ignores_base() {
        // Absolute `path` ignores the base entirely (POSIX openat), still normalized.
        assert_eq!(join_and_normalize("/anything", "/etc/passwd"), "/etc/passwd");
        assert_eq!(join_and_normalize("/anything", "/a//b/../c"), "/a/c");
    }

    #[test]
    fn canonicalize_absolute_ignores_dirfd_and_normalizes() {
        // An absolute raw path resolves WITHOUT touching /proc (dirfd irrelevant), so
        // this is testable unprivileged. Bogus pid/dirfd prove they go unused.
        let got = canonicalize_for_tracee(/* pid */ -1, /* dirfd */ -999, "/home/u/proj/./x/../y.txt");
        assert_eq!(got.as_deref(), Some("/home/u/proj/y.txt"));
        // A `..`-escape baked into an absolute path is collapsed lexically too
        // (one pop per `..`): /home/u/proj + 2×`..` → /home, then /etc/passwd.
        let esc = canonicalize_for_tracee(-1, -999, "/home/u/proj/../../etc/passwd");
        assert_eq!(esc.as_deref(), Some("/home/etc/passwd"));
    }

    #[test]
    fn canonicalize_relative_resolves_against_tracee_cwd() {
        // Resolve a relative open against THIS process's cwd via /proc/self/cwd
        // (pid 0 ≡ "self" in procfs). Proves the dirfd==AT_FDCWD branch reads the
        // tracee link and joins correctly — exercisable unprivileged.
        let self_pid = std::process::id() as i32;
        let cwd = std::fs::read_link(format!("/proc/{self_pid}/cwd"))
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let got = canonicalize_for_tracee(self_pid, AT_FDCWD, "sub/./secret.txt").expect("cwd resolves");
        assert_eq!(got, format!("{}/sub/secret.txt", cwd.trim_end_matches('/')));
        // A `..`-escape from the cwd resolves to the real absolute target.
        let esc = canonicalize_for_tracee(self_pid, AT_FDCWD, "../sibling.txt").expect("cwd resolves");
        let parent = std::path::Path::new(&cwd)
            .parent()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(esc, format!("{}/sibling.txt", parent.trim_end_matches('/')));
    }

    #[test]
    fn canonicalize_relative_with_unresolvable_dirfd_is_none() {
        // A dirfd that doesn't name a directory we can readlink → None (fail-safe:
        // the caller passes through, never redirects on an unresolved base). fd -1
        // has no /proc/<pid>/fd/-1 link.
        let self_pid = std::process::id() as i32;
        let got = canonicalize_for_tracee(self_pid, /* bogus dirfd */ -7, "name");
        assert!(got.is_none(), "unresolvable dirfd must fail safe to None");
    }
}
