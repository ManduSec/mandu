//! fs-preload — Mandu unprivileged FS interposer (Tier-1-on-old-kernels / Tier 2).
//!
//! An `LD_PRELOAD` cdylib that interposes the libc open family and, for paths that
//! fs-supervisor's `decide_open` says belong to a tracked workspace, rewrites the
//! path to the **AgentView git worktree** before calling the REAL libc function.
//! This is the filesystem two-views mechanism for hosts where the seccomp-unotify
//! `openat` REDIRECT is unavailable — kernel < 5.9 (the ADDFD ioctl
//! `SECCOMP_IOCTL_NOTIF_ADDFD` it needs is ≥ 5.9), or any host where the kernel
//! layer cannot attach. (The dev host, once 5.4, now runs 6.8 and enacts the
//! seccomp redirect live; this crate stays as the PORTABLE wrapper-layer
//! fallback — see `docs/design/architecture/privilege-model.md` §3.2.) It needs **zero
//! privilege**: no root, no CAP, no kernel feature, no user namespace.
//!
//! REUSE, DON'T REWRITE: the redirect *decision* is fs-supervisor's pure,
//! unit-tested `decide_open` / `TrackedRoots` / `ViewLayout` — see
//! `config.rs`. This file is only the C-ABI *transport*: dlsym the real open*,
//! guard against recursion, and swap the path argument. It mirrors the seccomp
//! supervisor's semantics exactly (kernel.rs `step()` → Redirect opens the
//! AgentView path / Passthrough runs the original), just without the kernel.
//!
//! THREAT MODEL (privilege-model.md §3.1): this is a **cooperative** boundary. It
//! captures the real adversary — a prompt-injected agent driving its normal
//! libc/Node tools (`openat` through glibc) — because injected instructions cannot
//! make the agent issue raw syscalls or scrub `LD_PRELOAD`. It is BYPASSABLE by a
//! native binary issuing raw `syscall(SYS_openat, ...)`, a statically-linked
//! binary (no dynamic loader → no preload), or a non-libc runtime. Those are out
//! of scope for the IPI defense (Tier 1 userns / host root are the hard-boundary
//! answers).

pub mod config;

use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::OnceLock;

use config::Config;

// ---------------------------------------------------------------------------
// Lazily-resolved interposer state.
// ---------------------------------------------------------------------------

/// The parsed env config, resolved once. `None` if the env contract is absent →
/// every interposed call is an inert passthrough (never rewrites a path).
fn config() -> Option<&'static Config> {
    static CFG: OnceLock<Option<Config>> = OnceLock::new();
    CFG.get_or_init(|| {
        // NOTE: do NOT wrap this in `with_guard`. `config()` is called from INSIDE
        // an interposer's `with_guard`, so a nested guard would short-circuit to
        // `None` and poison the OnceLock with `None` forever. `from_env()` only
        // reads process env via getenv (no openat), so it is safe to run directly.
        // The OUTER guard (in each interposer) already prevents our own std calls
        // from recursing.
        Config::from_env()
    })
    .as_ref()
}

thread_local! {
    /// Recursion guard. Our own code path (dlsym, getenv, stderr writes, and any
    /// std call) can itself call openat; without this we would re-enter the
    /// interposer and recurse forever. While set, interposers go straight to the
    /// real libc function with the ORIGINAL path.
    static IN_INTERPOSER: Cell<bool> = const { Cell::new(false) };
}

/// Run `f` with the recursion guard set; returns `None` if we were ALREADY inside
/// the interposer (caller must then take the raw passthrough path). On `Some`, the
/// guard is restored on the way out (panic-safe via the Drop guard).
fn with_guard<T>(f: impl FnOnce() -> T) -> Option<T> {
    IN_INTERPOSER.with(|flag| {
        if flag.get() {
            return None;
        }
        flag.set(true);
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                IN_INTERPOSER.with(|f| f.set(false));
            }
        }
        let _reset = Reset;
        Some(f())
    })
}

// ---------------------------------------------------------------------------
// Real libc function pointers, resolved once via dlsym(RTLD_NEXT, ...).
// ---------------------------------------------------------------------------

type OpenatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, ...) -> c_int;
type OpenFn = unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int;

/// dlsym the next `openat` in the chain (the real glibc one). Cached.
fn real_openat() -> OpenatFn {
    static P: OnceLock<usize> = OnceLock::new();
    let addr = *P.get_or_init(|| dlsym_next(b"openat\0"));
    // SAFETY: dlsym returned the address of libc openat with this exact ABI.
    unsafe { std::mem::transmute::<usize, OpenatFn>(addr) }
}

fn real_open() -> OpenFn {
    static P: OnceLock<usize> = OnceLock::new();
    let addr = *P.get_or_init(|| dlsym_next(b"open\0"));
    unsafe { std::mem::transmute::<usize, OpenFn>(addr) }
}

/// Resolve a symbol from the NEXT object in the load order (i.e. the real libc,
/// skipping our own preload). Aborts loudly if missing — a missing real `openat`
/// means the process is unusable, and silently returning a bad pointer is worse.
fn dlsym_next(sym_nul: &[u8]) -> usize {
    // SAFETY: sym_nul is a NUL-terminated byte string; RTLD_NEXT is the documented
    // way to reach the next definition past this preload library.
    let ptr = unsafe { libc::dlsym(libc::RTLD_NEXT, sym_nul.as_ptr() as *const c_char) };
    if ptr.is_null() {
        // No real symbol — cannot interpose. Abort rather than loop/UB.
        std::process::abort();
    }
    ptr as usize
}

// ---------------------------------------------------------------------------
// Absolute-ization + lexical normalization (so RELATIVE / dirfd-relative opens
// resolve to the canonical absolute path the rewrite logic prefix-matches on).
// ---------------------------------------------------------------------------

/// Lexically normalize an ABSOLUTE path with pure string math — NO syscalls, NO
/// symlink resolution (deliberately, see below). Collapses repeated `/`, drops `.`
/// segments, and pops the previous segment on `..` (without going above `/`). The
/// result is what `rewrite_to_worktree` expects: an absolute path with no `.`/`..`/
/// `//`, so its prefix-match against the canonical tracked root is exact.
///
/// We do NOT call `realpath`/resolve symlinks on purpose: the launcher canonicalizes
/// the tracked root and `getcwd` is already canonical/absolute, so lexical math is
/// enough to land in the same prefix. The cost is that a *symlinked component inside
/// the tree* is not symlink-resolved — identical posture to the seccomp path
/// (`decide_open` matches the path as given) and documented as a remaining caveat.
fn normalize_lexical(path: &str) -> String {
    debug_assert!(path.starts_with('/'), "normalize_lexical expects absolute");
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            // "" comes from a leading '/', trailing '/', or "//"; "." is a no-op.
            "" | "." => {}
            ".." => {
                // Pop the previous real segment; at the root, ".." is a no-op
                // (can't go above "/"), matching the kernel's path walk.
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

/// Join a (possibly relative) `path` onto a base directory and return a normalized
/// absolute path. If `path` is already absolute, `base` is ignored (POSIX openat
/// semantics). Both are byte-slices so non-UTF-8 callers are handled upstream.
fn join_and_normalize(base: &str, path: &str) -> String {
    if path.starts_with('/') {
        return normalize_lexical(path);
    }
    // base is absolute (getcwd / readlink of a dir fd); join with a single '/'.
    let joined = format!("{}/{}", base.trim_end_matches('/'), path);
    normalize_lexical(&joined)
}

/// `getcwd(3)` via libc into an owned `String`, or `None` if it fails / is non-UTF-8.
/// Plain libc call — it does not route through our `open*` interposers, but we still
/// only call it under the recursion guard (held by the caller).
fn cwd() -> Option<String> {
    // PATH_MAX-ish; getcwd returns ERANGE if too small, then we give up (None).
    let mut buf = [0u8; 4096];
    // SAFETY: buf is a valid writable region of `buf.len()` bytes.
    let ret = unsafe { libc::getcwd(buf.as_mut_ptr() as *mut c_char, buf.len()) };
    if ret.is_null() {
        return None;
    }
    // SAFETY: on success getcwd wrote a NUL-terminated absolute path into buf.
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
    std::str::from_utf8(cstr.to_bytes()).ok().map(String::from)
}

/// The directory a `dirfd` points at, via `readlink("/proc/self/fd/<dirfd>")`.
/// Returns `None` if readlink fails or yields a non-path target (e.g. a pipe/socket
/// `"anon_inode:..."` or a deleted ` (deleted)` suffix) or non-UTF-8 — caller then
/// fails safe (passes the original through, no redirect). Plain libc call.
fn dir_of_fd(dirfd: c_int) -> Option<String> {
    let link = format!("/proc/self/fd/{dirfd}\0");
    let mut buf = [0u8; 4096];
    // SAFETY: link is NUL-terminated; buf is a valid writable region.
    let n = unsafe {
        libc::readlink(
            link.as_ptr() as *const c_char,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    if n <= 0 {
        return None;
    }
    let target = std::str::from_utf8(&buf[..n as usize]).ok()?;
    // Must be a real absolute directory path; reject anon_inode/pipe/socket targets
    // and anything that isn't absolute (we can't safely join onto it → fail safe).
    if !target.starts_with('/') {
        return None;
    }
    Some(target.to_string())
}

/// Resolve a (dirfd, path) pair to a normalized ABSOLUTE path string, applying POSIX
/// openat semantics. `Some` only when we can produce an absolute path; `None` means
/// "fail safe — pass the original through" (non-UTF-8, or a dirfd we can't resolve).
///
/// - absolute `path` → used as-is (dirfd ignored), just normalized.
/// - relative + `dirfd == AT_FDCWD` → joined onto `getcwd`.
/// - relative + real `dirfd` → joined onto `readlink(/proc/self/fd/<dirfd>)`.
fn absolutize(dirfd: c_int, path_bytes: &[u8]) -> Option<String> {
    // decide_open works on UTF-8 &str; non-UTF-8 paths are passed through raw
    // (rare; documented). lossy would change bytes, so require valid UTF-8.
    let path = std::str::from_utf8(path_bytes).ok()?;
    if path.starts_with('/') {
        // Absolute: dirfd irrelevant (POSIX). Preserve prior behavior exactly,
        // but normalize so `decide_open`'s prefix match is robust to `.`/`..`.
        return Some(normalize_lexical(path));
    }
    // Relative: resolve the base directory.
    let base = if dirfd == libc::AT_FDCWD {
        cwd()?
    } else {
        dir_of_fd(dirfd)?
    };
    Some(join_and_normalize(&base, path))
}

// ---------------------------------------------------------------------------
// Path rewrite helper shared by all interposers.
// ---------------------------------------------------------------------------

/// Given the (dirfd, C path) the program asked to open, return an owned redirected
/// `CString` IFF it resolves to a path under a tracked root. Untracked paths,
/// already-redirected paths, and paths we cannot resolve return `None` (caller
/// passes the original pointer through, unchanged — fail safe).
///
/// Resolution covers ABSOLUTE, relative-to-CWD (`AT_FDCWD` or plain `open`), and
/// `dirfd`-relative opens: `absolutize` turns the pair into a normalized absolute
/// path before the (unchanged) `decide_open`/`rewrite_to_worktree` logic runs.
/// `open`/`open64` pass `AT_FDCWD` for `dirfd` so they share this one path.
fn rewrite_c_path(dirfd: c_int, path: *const c_char, flags: c_int) -> Option<CString> {
    if path.is_null() {
        return None;
    }
    let cfg = config()?;
    // SAFETY: libc guarantees `path` is a NUL-terminated C string for open*.
    let cstr = unsafe { CStr::from_ptr(path) };
    let bytes = cstr.to_bytes();
    // Turn (dirfd, path) into a normalized absolute path. None → fail safe.
    let abs = absolutize(dirfd, bytes)?;
    let rewritten = cfg.rewrite(&abs, flags)?;
    if rewritten == abs {
        // Idempotent (already in worktree) — no need to reallocate/redirect.
        return None;
    }
    if cfg.debug {
        debug_line("redirect", &abs, &rewritten);
    }
    CString::new(rewritten).ok()
}

/// Best-effort stderr debug line (guarded; never on the security path).
fn debug_line(kind: &str, from: &str, to: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "[fs-preload] {kind}: {from} -> {to}");
}

// ---------------------------------------------------------------------------
// The interposers. Each: guard → rewrite → call the real function.
// ---------------------------------------------------------------------------

/// Interpose `openat(dirfd, path, flags, mode?)`. The variadic `mode` is only read
/// by libc when O_CREAT/O_TMPFILE is set; we forward a `mode_t` unconditionally —
/// harmless when libc ignores it, correct when it doesn't.
///
/// # Safety
///
/// Matches the C ABI of glibc `openat`. Called by the dynamic loader in
/// place of libc's symbol.
#[no_mangle]
pub unsafe extern "C" fn openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    // If we're already inside our own logic (recursion), or the guard says so,
    // go straight to real libc with the original path.
    let rewritten = with_guard(|| rewrite_c_path(dirfd, path, flags)).flatten();
    let real = real_openat();
    match rewritten {
        // Redirect target is an ABSOLUTE worktree path, so passing AT_FDCWD as the
        // dirfd would be equivalent — but we keep the caller's dirfd to avoid any
        // surprise: an absolute path ignores dirfd per POSIX.
        Some(new_path) => real(dirfd, new_path.as_ptr(), flags, mode),
        None => real(dirfd, path, flags, mode),
    }
}

/// Interpose `open(path, flags, mode?)` — delegates to the same rewrite, then the
/// real `open`.
///
/// # Safety
///
/// Matches the C ABI of glibc `open`.
#[no_mangle]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    // `open` has no dirfd → relative paths resolve against CWD, so we hand the
    // rewrite logic AT_FDCWD (which it resolves via getcwd).
    let rewritten = with_guard(|| rewrite_c_path(libc::AT_FDCWD, path, flags)).flatten();
    let real = real_open();
    match rewritten {
        Some(new_path) => real(new_path.as_ptr(), flags, mode),
        None => real(path, flags, mode),
    }
}

// On glibc, `open64`/`openat64` are the LFS aliases the compiler emits for normal
// `open`/`openat` when `_FILE_OFFSET_BITS=64` (the default for most builds, incl.
// `cat`/coreutils). They share the same ABI, so we interpose them identically and
// route through the SAME rewrite. Resolving the *real* symbol uses the 64-bit name
// so we land on libc's LFS implementation.

type Openat64Fn = unsafe extern "C" fn(c_int, *const c_char, c_int, ...) -> c_int;
type Open64Fn = unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int;

fn real_openat64() -> Openat64Fn {
    static P: OnceLock<usize> = OnceLock::new();
    let addr = *P.get_or_init(|| dlsym_next(b"openat64\0"));
    unsafe { std::mem::transmute::<usize, Openat64Fn>(addr) }
}

fn real_open64() -> Open64Fn {
    static P: OnceLock<usize> = OnceLock::new();
    let addr = *P.get_or_init(|| dlsym_next(b"open64\0"));
    unsafe { std::mem::transmute::<usize, Open64Fn>(addr) }
}

/// # Safety
///
/// glibc `openat64` ABI (LFS alias of openat).
#[no_mangle]
pub unsafe extern "C" fn openat64(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    let rewritten = with_guard(|| rewrite_c_path(dirfd, path, flags)).flatten();
    let real = real_openat64();
    match rewritten {
        Some(new_path) => real(dirfd, new_path.as_ptr(), flags, mode),
        None => real(dirfd, path, flags, mode),
    }
}

/// # Safety
///
/// glibc `open64` ABI (LFS alias of open).
#[no_mangle]
pub unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    let rewritten = with_guard(|| rewrite_c_path(libc::AT_FDCWD, path, flags)).flatten();
    let real = real_open64();
    match rewritten {
        Some(new_path) => real(new_path.as_ptr(), flags, mode),
        None => real(path, flags, mode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_blocks_reentry() {
        // Outer guard acquires; inner sees it held and returns None.
        let outer = with_guard(|| {
            let inner = with_guard(|| 42);
            assert!(inner.is_none(), "reentrant guard must return None");
            7
        });
        assert_eq!(outer, Some(7));
        // After unwinding, the guard is released → next acquire succeeds.
        assert_eq!(with_guard(|| 1), Some(1));
    }

    #[test]
    fn guard_released_after_panic() {
        let r = std::panic::catch_unwind(|| {
            with_guard(|| panic!("boom"));
        });
        assert!(r.is_err());
        // The Drop-based reset must have released the guard despite the panic.
        assert_eq!(with_guard(|| 1), Some(1), "guard leaked after panic");
    }

    #[test]
    fn rewrite_c_path_null_is_none() {
        let got = with_guard(|| rewrite_c_path(libc::AT_FDCWD, std::ptr::null(), 0)).flatten();
        assert!(got.is_none());
    }

    // -- absolute-ization + lexical normalization --------------------------------

    #[test]
    fn normalize_collapses_slashes_and_dots() {
        assert_eq!(normalize_lexical("/a/b/c"), "/a/b/c");
        // Repeated and trailing slashes collapse; "." segments drop.
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
        // Relative path is joined onto the (stubbed) base dir and normalized.
        assert_eq!(join_and_normalize("/home/u/proj", "notes.txt"), "/home/u/proj/notes.txt");
        assert_eq!(join_and_normalize("/home/u/proj", "./sub/secret.txt"), "/home/u/proj/sub/secret.txt");
        assert_eq!(join_and_normalize("/home/u/proj/sub", "../notes.txt"), "/home/u/proj/notes.txt");
        // A trailing slash on the base is tolerated (single join slash).
        assert_eq!(join_and_normalize("/home/u/proj/", "a.txt"), "/home/u/proj/a.txt");
    }

    #[test]
    fn join_absolute_path_ignores_base() {
        // An absolute `path` ignores the base entirely (POSIX openat semantics),
        // and is still normalized.
        assert_eq!(join_and_normalize("/anything", "/etc/passwd"), "/etc/passwd");
        assert_eq!(join_and_normalize("/anything", "/a//b/../c"), "/a/c");
    }

    #[test]
    fn absolutize_absolute_passthrough_normalized() {
        // Absolute input: dirfd is irrelevant; result is the normalized path.
        let got = absolutize(/* dirfd */ -999, b"/home/u/proj/./x/../y.txt");
        assert_eq!(got.as_deref(), Some("/home/u/proj/y.txt"));
    }

    #[test]
    fn absolutize_at_fdcwd_relative_joins_real_cwd() {
        // AT_FDCWD + a relative path resolves against the process CWD. We assert
        // the *shape* (absolute, contains our filename, no "." segment) since the
        // CWD is the real test process dir — the cwd() helper is exercised live.
        let got = absolutize(libc::AT_FDCWD, b"sub/./secret.txt").expect("cwd resolves");
        assert!(got.starts_with('/'), "result must be absolute: {got}");
        assert!(got.ends_with("/sub/secret.txt"), "joined onto cwd: {got}");
        assert!(!got.contains("/./"), "normalized away '.': {got}");
        // It equals cwd()+"/sub/secret.txt".
        let cwd = cwd().expect("getcwd works in test");
        assert_eq!(got, format!("{}/sub/secret.txt", cwd.trim_end_matches('/')));
    }

    #[test]
    fn absolutize_dirfd_relative_string_math() {
        // The readlink(/proc/self/fd/N) part is integration-tested by the shell
        // e2e; here we cover the dirfd-relative JOIN + normalization at the string
        // level (the exact transform absolutize applies once dir_of_fd returns).
        let base = "/home/u/proj/sub"; // what readlink would yield for the dirfd
        assert_eq!(join_and_normalize(base, "secret.txt"), "/home/u/proj/sub/secret.txt");
        assert_eq!(join_and_normalize(base, "../notes.txt"), "/home/u/proj/notes.txt");
        assert_eq!(join_and_normalize(base, "./a/b"), "/home/u/proj/sub/a/b");
    }

    #[test]
    fn absolutize_non_utf8_is_none() {
        // Invalid UTF-8 path bytes → None (caller passes the original through).
        let got = absolutize(libc::AT_FDCWD, &[0xff, 0xfe, b'/', b'x']);
        assert!(got.is_none());
    }
}
