//! reader_identity — who a process that opens a secret really is (Plan 13 D8,
//! docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md §3, §7 step 8;
//! confidentiality-plan-10-flow-taint.md §2.3).
//!
//! A reader of a secret file is matched by its resolved executable and that
//! file's hash (a pin, plan 10 §11.2). Three facts the pin alone does not
//! give, each computed here for the guard to send with `decideSecretOpen`:
//!
//! - **out of reach** (`exeSystem`): the executable (the inode the process
//!   runs, read through `/proc/<pid>/exe`) and every directory above its
//!   path are unwritable by the agent's uid. Only such a binary is pinned on
//!   first use: a bare name (`readers: [psql]`) or a known consumer must not
//!   be pinned to a `psql` the agent wrote into its workspace, `/tmp` or the
//!   session's scratch. The agent runs as the guard's uid, so "writable by
//!   the agent" is "writable by us": owned by us, or group-writable by a
//!   group we are in, or world-writable (a sticky `/tmp` too). Root as the
//!   agent's uid reaches everything: nothing is out of reach, and so does a
//!   uid holding a capability that overrides file permissions (any but the
//!   few `CAPS_NO_REACH` names; `Who::caps`). Root, or such a capability, in
//!   a child user namespace (the unprivileged sandboxes) reaches only files
//!   whose owner the namespace maps (`Who::ns_overflow`). An inode that
//!   carries an ACL beyond its mode bits (a named user or group entry, a
//!   mask, an NFSv4 ACL, an ACL that cannot be read) and a directory with a
//!   default ACL are in reach, whoever the entries name: fail closed
//!   (P0 triage 2d, 2026-10-07; `Perm::acl`).
//! - **the loader and interpreter environment** (`openerEnv`): a variable
//!   that makes a pinned program load or run other code (`LD_PRELOAD`,
//!   `LD_LIBRARY_PATH`, `LD_AUDIT`, any `LD_*`, `GCONV_PATH`; for an
//!   interpreter its own: `PYTHON*`, `NODE_*`, `PERL*`, `RUBY*`, a shell's
//!   `BASH_ENV` / `ENV` / exported functions, Java's options) set to a
//!   value the launch did not give. The allowlist is the launch's own
//!   environment (the guard's, which it passed to the agent unchanged), plus
//!   the empty value and, for `NODE_OPTIONS`, flags that load no code. Since
//!   an injected library can scrub `/proc/<pid>/environ` before the open,
//!   the executable FILE mappings (`/proc/<pid>/maps`) other than the binary
//!   itself are checked too: one the agent could have written is reported as
//!   `code:<path>`. Such an opener is not the pinned program; the arbiter
//!   treats it as no reader. Names only ever leave this module, never values.
//! - **trusted ancestors** (`ancestorTrusted`): `from: git` counts only
//!   under an ancestor that is out of reach AND runs with a clean
//!   environment, AND (P0 item 14) whose content is no interpreter or
//!   printers' package its name does not say (`ancestor_trusted`); a
//!   basename is the program's choice (`cp /bin/sh ./git`). And only an
//!   ancestor inside the session, below the guard (`ancestors`,
//!   `lineage::session_ancestors`, 2026-10-17): what launched Mandu is none.
//! - **an interpreter by its content** (`runs:<family>` among the findings,
//!   Plan 13 §8 decision (b) by content, 2026-10-03): a binary no name on the
//!   code-running list names (`secret_open::runs_code`) whose bytes carry a
//!   language interpreter's own front end (`RUNTIME_MARKERS`: CPython's
//!   `Py_BytesMain`, node's `node::Start`, …): a pyenv python renamed
//!   `mytool`, an nvm node, a static busybox, which neither its name nor the
//!   arbiter's hashes of the host's installed programs catch. Read in the
//!   same pass as the hash, once per inode, for the process the guard
//!   decides about, and for an ancestor out of the agent's reach (a `from:`
//!   parent, since P0 item 14). An executable that cannot be read is not
//!   judged clean.
//! - **a printer or a launcher by its package** (`pkg:<package>`, Plan 13 D8
//!   (13), P0 item 14, 2026-10-07): a binary neither list names whose bytes
//!   carry the text every program of a package of printers or launchers
//!   carries (`PACKAGE_MARKERS`: GNU coreutils' name, findutils',
//!   util-linux's version, …; coreutils' checksum tools excepted): a GNU
//!   `env` or `cat` of another version renamed `mytool`, which no host hash
//!   knows. The arbiter treats it as a printer.
//!
//! The hash is taken from the inode the process runs (`/proc/<pid>/exe`),
//! cached by (device, inode, ctime, size): the path can be renamed over
//! after the exec, and a path-keyed cache would vouch for the file that used
//! to be there.
//!
//! Decision logic is pure (`untrusted_env`, `writable_by`,
//! `dirs_out_of_reach`) and unit-tested with no privilege; the `/proc`
//! readers are thin.
//!
//! Mandu-new (no reference origin).

use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;

/// Variables every dynamically linked program obeys: the loader's, and
/// glibc's module paths; and OpenSSL's configuration and module paths, which
/// load an engine or a provider library into any program linked with it
/// (curl, git's https helper, psql over TLS) once it starts TLS, possibly
/// after its secret open, where the mapping check below would miss it
/// (Plan 13 D8, code by argument, 2026-10-02).
/// And .NET's (P0 item 14, 2026-10-07): a .NET program's apphost takes any
/// name, and these load managed code into it (a startup hook, extra
/// dependencies, another runtime, a profiler), which is read as data and
/// JIT-compiled, so the mapping check misses it.
const UNIVERSAL_EXACT: &[&str] = &[
    "GCONV_PATH", "GLIBC_TUNABLES", "OPENSSL_CONF", "OPENSSL_ENGINES", "OPENSSL_MODULES",
    "DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS", "DOTNET_SHARED_STORE", "DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_ROOT_ARM64",
    "CORECLR_ENABLE_PROFILING", "CORECLR_PROFILER", "CORECLR_PROFILER_PATH", "CORECLR_PROFILER_PATH_64",
];
const UNIVERSAL_PREFIX: &[&str] = &["LD_"];

/// An interpreter family: the executable names (matched like
/// `app_name_matches`, so `python3` covers `python3.12`) and the variables
/// that make it run other code at start.
struct Family {
    names: &'static [&'static str],
    exact: &'static [&'static str],
    prefix: &'static [&'static str],
}

const FAMILIES: &[Family] = &[
    Family { names: &["python", "python2", "python3", "pypy", "pypy3"], exact: &[], prefix: &["PYTHON"] },
    Family { names: &["node", "nodejs", "bun", "deno"], exact: &[], prefix: &["NODE_"] },
    Family { names: &["perl"], exact: &[], prefix: &["PERL"] },
    Family { names: &["ruby"], exact: &[], prefix: &["RUBY"] },
    Family {
        names: &["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "busybox"],
        exact: &["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS4", "ZDOTDIR"],
        prefix: &["BASH_FUNC_"],
    },
    Family { names: &["java"], exact: &["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"], prefix: &[] },
];

/// `NODE_OPTIONS` flags that load no code: a value made only of these (or
/// of flags the launch's own value carries) is admitted.
const NODE_OPTIONS_SAFE_EXACT: &[&str] = &[
    "--no-warnings", "--no-deprecation", "--enable-source-maps", "--use-openssl-ca", "--use-bundled-ca",
    "--use-system-ca", "--trace-warnings", "--trace-deprecation", "--trace-uncaught",
];
const NODE_OPTIONS_SAFE_PREFIX: &[&str] = &[
    "--disable-warning=", "--max-old-space-size=", "--max-semi-space-size=", "--dns-result-order=",
    "--unhandled-rejections=", "--stack-trace-limit=",
];

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Does the variable `name` change what the program `exe` loads or runs?
pub fn is_loader_var(exe: &str, name: &str) -> bool {
    if UNIVERSAL_EXACT.contains(&name) || UNIVERSAL_PREFIX.iter().any(|p| name.starts_with(p)) {
        return true;
    }
    let base = basename(exe);
    FAMILIES.iter().any(|f| {
        f.names.iter().any(|n| crate::secret_open::app_name_matches(base, n))
            && (f.exact.contains(&name) || f.prefix.iter().any(|p| name.starts_with(p)))
    })
}

/// The launch's own values of the variables any family checks: the
/// allowlist. Built from the guard's environment, which it hands to the
/// agent unchanged (the agent cannot change it after the start).
#[derive(Debug, Clone, Default)]
pub struct EnvBaseline {
    vars: HashMap<String, String>,
}

impl EnvBaseline {
    pub fn from_vars<I: IntoIterator<Item = (String, String)>>(vars: I) -> Self {
        // Kept for every family: which family applies depends on the opener.
        let keep = |k: &str| {
            UNIVERSAL_EXACT.contains(&k)
                || UNIVERSAL_PREFIX.iter().any(|p| k.starts_with(p))
                || FAMILIES.iter().any(|f| f.exact.contains(&k) || f.prefix.iter().any(|p| k.starts_with(p)))
                || crate::args_code::is_rule_var(k)
        };
        EnvBaseline { vars: vars.into_iter().filter(|(k, _)| keep(k)).collect() }
    }

    /// The guard's own environment at start.
    pub fn from_process() -> Self {
        Self::from_vars(std::env::vars_os().map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned())))
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }
}

/// `/proc/<pid>/environ` bytes as (name, value) pairs. An entry without `=`
/// is kept as a name with an empty value.
pub fn parse_environ(bytes: &[u8]) -> Vec<(String, String)> {
    bytes
        .split(|b| *b == 0)
        .filter(|e| !e.is_empty())
        .map(|e| {
            let s = String::from_utf8_lossy(e);
            match s.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (s.into_owned(), String::new()),
            }
        })
        .collect()
}

fn node_options_admitted(value: &str, launch: Option<&str>) -> bool {
    let launch_tokens: Vec<&str> = launch.map(|l| l.split_whitespace().collect()).unwrap_or_default();
    value.split_whitespace().all(|t| {
        launch_tokens.contains(&t) || NODE_OPTIONS_SAFE_EXACT.contains(&t) || NODE_OPTIONS_SAFE_PREFIX.iter().any(|p| t.starts_with(p) && t.len() > p.len())
    })
}

/// The loader / interpreter variables `exe` runs with set to a value the
/// launch did not give, by name, sorted and deduplicated. Empty = clean.
/// Pure.
pub fn untrusted_env(exe: &str, environ: &[(String, String)], launch: &EnvBaseline) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (name, value) in environ {
        if !is_loader_var(exe, name) || value.is_empty() {
            continue;
        }
        let given = launch.get(name);
        if given == Some(value.as_str()) {
            continue;
        }
        if name == "NODE_OPTIONS" && node_options_admitted(value, given) {
            continue;
        }
        if !out.contains(name) {
            out.push(name.clone());
        }
    }
    out.sort();
    out
}

/// `untrusted_env` for a live process: `None` when its environment cannot be
/// read (gone, or not ours to read), which the arbiter treats as unclean.
pub fn opener_env(pid: i32, exe: &str, launch: &EnvBaseline) -> Option<Vec<String>> {
    let bytes = fs::read(format!("/proc/{pid}/environ")).ok()?;
    Some(untrusted_env(exe, &parse_environ(&bytes), launch))
}

/// The agent's identity for the reach test: the guard's effective uid and
/// groups (the agent runs as the guard's user) and the capabilities it may
/// use (`caps`). Root reaches everything in the initial user namespace, and
/// so does a uid with a capability that overrides file permissions there;
/// root of a CHILD namespace (the unprivileged sandboxes, `unshare
/// --map-root-user`), or a uid with such a capability in one, reaches only
/// files whose owner is mapped into it, and every unmapped owner shows as the
/// overflow uid (`ns_overflow`). The default (uid 0, initial namespace)
/// reaches everything, so nothing is out of reach: fail-closed.
#[derive(Debug, Clone, Default)]
pub struct Who {
    pub uid: u32,
    pub groups: Vec<u32>,
    /// A child user namespace: the uid an unmapped owner shows as (None: the
    /// initial namespace, or a map that could not be read).
    pub ns_overflow: Option<u32>,
    /// The capability bits the agent may use: the guard's `CapPrm | CapEff`
    /// (a permitted capability can be raised at will). The agent's tree runs
    /// under `no_new_privs` from the guard's own fork, so no process in it
    /// holds a capability of the initial namespace the guard lacks; what a
    /// child user namespace grants is scoped by `ns_overflow`.
    pub caps: u64,
}

/// Capabilities that give no way to change a file the mode bits deny
/// (`include/uapi/linux/capability.h` numbers): network, scheduling, memory
/// locking, clocks, leases, audit, wake alarms. Every other bit
/// (`CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_CHOWN`, `CAP_SETUID`,
/// `CAP_SYS_ADMIN`, `CAP_MKNOD`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`, `CAP_BPF`,
/// one a later kernel adds, …) counts as reaching every file: fail closed.
pub const CAPS_NO_REACH: &[u32] = &[
    10, // CAP_NET_BIND_SERVICE
    11, // CAP_NET_BROADCAST
    12, // CAP_NET_ADMIN
    13, // CAP_NET_RAW
    14, // CAP_IPC_LOCK
    23, // CAP_SYS_NICE
    24, // CAP_SYS_RESOURCE
    25, // CAP_SYS_TIME
    28, // CAP_LEASE
    29, // CAP_AUDIT_WRITE
    35, // CAP_WAKE_ALARM
    36, // CAP_BLOCK_SUSPEND
    37, // CAP_AUDIT_READ
];

/// Do these capability bits override file permissions (any bit outside
/// `CAPS_NO_REACH`)? Pure.
pub fn caps_reach(caps: u64) -> bool {
    let benign = CAPS_NO_REACH.iter().fold(0u64, |m, &c| m | (1u64 << c));
    caps & !benign != 0
}

/// `CapPrm | CapEff` of a `/proc/<pid>/status` text; None when either is
/// missing or malformed. Pure.
pub fn status_caps(status: &str) -> Option<u64> {
    let field = |name: &str| status.lines().find_map(|l| l.strip_prefix(name)).and_then(|v| u64::from_str_radix(v.trim(), 16).ok());
    Some(field("CapPrm:")? | field("CapEff:")?)
}

/// Is this `/proc/self/uid_map` the initial namespace's identity map?
pub fn is_initial_uid_map(map: &str) -> bool {
    let rows: Vec<Vec<&str>> = map.lines().map(|l| l.split_whitespace().collect()).filter(|r: &Vec<&str>| !r.is_empty()).collect();
    rows.len() == 1 && rows[0] == ["0", "0", "4294967295"]
}

impl Who {
    pub fn current() -> Self {
        // SAFETY: plain getters.
        let uid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        let mut groups = vec![egid];
        // SAFETY: first call sizes, second fills a buffer of that size.
        let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if n > 0 {
            let mut buf = vec![0 as libc::gid_t; n as usize];
            let got = unsafe { libc::getgroups(n, buf.as_mut_ptr()) };
            if got > 0 {
                groups.extend(buf.into_iter().take(got as usize));
            }
        }
        // A child namespace: unmapped owners are out of the reach of its root
        // and of its capabilities. An unreadable map counts as the initial
        // namespace (root or a capability reaches everything).
        let ns_overflow = match fs::read_to_string("/proc/self/uid_map") {
            Ok(m) if !is_initial_uid_map(&m) => {
                Some(fs::read_to_string("/proc/sys/kernel/overflowuid").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(65534))
            }
            _ => None,
        };
        // Unreadable capabilities count as every one: fail closed.
        let caps = fs::read_to_string("/proc/self/status").ok().as_deref().and_then(status_caps).unwrap_or(u64::MAX);
        Who { uid, groups, ns_overflow, caps }
    }
}

/// What the reach test reads of a file or a directory: its owner, group and
/// mode, and whether it carries an ACL beyond those bits (`acl`: a named user
/// or group entry or a mask in its access ACL, a default ACL on a directory,
/// an NFSv4 ACL, or an ACL that could not be read; `acl_beyond_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Perm {
    pub owner: u32,
    pub gid: u32,
    pub mode: u32,
    pub acl: bool,
}

impl Perm {
    /// Mode bits alone, no ACL.
    pub const fn bits(owner: u32, gid: u32, mode: u32) -> Self {
        Perm { owner, gid, mode, acl: false }
    }
}

/// Could `who` change a file or directory with these permissions? Pure. Any
/// ACL beyond the mode bits counts as in reach whatever its entries name (a
/// named user, a group the agent may be in, a mask): fail closed. Root, or a
/// capability that overrides file permissions (`caps_reach`), reaches
/// everything in the initial namespace and every mapped owner's file in a
/// child one.
pub fn writable_by(p: Perm, who: &Who) -> bool {
    if p.acl {
        return true;
    }
    if who.uid == 0 || caps_reach(who.caps) {
        match who.ns_overflow {
            None => return true,
            // CAP_DAC_OVERRIDE in a child namespace covers mapped owners only
            Some(overflow) if p.owner != overflow || p.mode & 0o022 != 0 => return true,
            Some(_) => {}
        }
    }
    p.owner == who.uid || p.mode & 0o002 != 0 || (p.mode & 0o020 != 0 && who.groups.contains(&p.gid))
}

/// `include/uapi/linux/posix_acl_xattr.h`: a version word, then 8-byte
/// entries (tag u16, perm u16, id u32), little-endian.
const ACL_XATTR_VERSION: u32 = 2;
const ACL_USER_OBJ: u16 = 0x01;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_OTHER: u16 = 0x20;

/// Does a `system.posix_acl_access` value say more than the mode bits (an
/// entry other than the owner's, the owning group's and other's: a named
/// user or group, a mask)? A malformed value counts as more. Pure.
pub fn posix_acl_extended(value: &[u8]) -> bool {
    if value.len() < 4 || (value.len() - 4) % 8 != 0 {
        return true;
    }
    if u32::from_le_bytes([value[0], value[1], value[2], value[3]]) != ACL_XATTR_VERSION {
        return true;
    }
    value[4..].chunks_exact(8).any(|e| !matches!(u16::from_le_bytes([e[0], e[1]]), ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_OTHER))
}

/// One extended attribute's read: absent (`ENODATA`, or a filesystem that
/// keeps none: `EOPNOTSUPP`), its value, or unreadable (any other error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XattrRead {
    Absent,
    Value(Vec<u8>),
    Unreadable,
}

/// From the reads of an inode's ACL attributes, does it carry an ACL beyond
/// its mode bits? An access ACL beyond the three base entries, any default
/// ACL on a directory, any NFSv4 ACL, any that could not be read. Pure.
pub fn acl_state(access: &XattrRead, default: &XattrRead, nfs4: &XattrRead, is_dir: bool) -> bool {
    let access = match access {
        XattrRead::Absent => false,
        XattrRead::Value(v) => posix_acl_extended(v),
        XattrRead::Unreadable => true,
    };
    access || (is_dir && *default != XattrRead::Absent) || *nfs4 != XattrRead::Absent
}

/// `getxattr` (`follow`) or `lgetxattr` of `name` on `path`.
pub fn read_xattr(path: &str, name: &str, follow: bool) -> XattrRead {
    let (Ok(p), Ok(n)) = (std::ffi::CString::new(path), std::ffi::CString::new(name)) else { return XattrRead::Unreadable };
    let get = |buf: *mut libc::c_void, len: usize| -> isize {
        // SAFETY: valid C strings; `buf` is null with `len` 0 (a size
        // query) or a buffer of `len` bytes.
        unsafe {
            if follow {
                libc::getxattr(p.as_ptr(), n.as_ptr(), buf, len)
            } else {
                libc::lgetxattr(p.as_ptr(), n.as_ptr(), buf, len)
            }
        }
    };
    let absent_or = |e: Option<i32>| match e {
        Some(libc::ENODATA) | Some(libc::EOPNOTSUPP) => XattrRead::Absent,
        _ => XattrRead::Unreadable,
    };
    for _ in 0..3 {
        let size = get(std::ptr::null_mut(), 0);
        if size < 0 {
            return absent_or(std::io::Error::last_os_error().raw_os_error());
        }
        let mut buf = vec![0u8; size as usize];
        let got = get(buf.as_mut_ptr().cast(), buf.len());
        if got >= 0 {
            buf.truncate(got as usize);
            return XattrRead::Value(buf);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ERANGE) => continue, // it grew between the two calls
            e => return absent_or(e),
        }
    }
    XattrRead::Unreadable
}

/// Does the inode at `path` (followed when `follow`) carry an ACL beyond its
/// mode bits (`acl_state`)? Two or three `getxattr` calls.
pub fn acl_beyond_mode(path: &str, follow: bool, is_dir: bool) -> bool {
    let access = read_xattr(path, "system.posix_acl_access", follow);
    let default = if is_dir { read_xattr(path, "system.posix_acl_default", follow) } else { XattrRead::Absent };
    let nfs4 = read_xattr(path, "system.nfs4_acl", follow);
    acl_state(&access, &default, &nfs4, is_dir)
}

/// The reach facts of a followed `fs::metadata` of `path`, its ACLs read at
/// `path` (followed).
pub fn perm_of(path: &str, m: &fs::Metadata) -> Perm {
    use std::os::unix::fs::MetadataExt;
    Perm { owner: m.uid(), gid: m.gid(), mode: m.mode(), acl: acl_beyond_mode(path, true, m.is_dir()) }
}

/// Is every directory above the absolute `path` out of `who`'s reach?
/// `stat` gives a directory's permissions (`Perm`, its ACLs included) and
/// whether it is one, without following a final symlink (a symlinked
/// component is no directory: refused). Pure.
pub fn dirs_out_of_reach(path: &str, who: &Who, stat: impl Fn(&str) -> Option<(Perm, bool)>) -> bool {
    if !path.starts_with('/') || path.ends_with(" (deleted)") {
        return false;
    }
    let mut dir = path;
    loop {
        dir = match dir.rfind('/') {
            Some(0) => "/",
            Some(i) => &dir[..i],
            None => return false,
        };
        match stat(dir) {
            Some((perm, is_dir)) if is_dir && !writable_by(perm, who) => {}
            _ => return false,
        }
        if dir == "/" {
            return true;
        }
    }
}

/// The `dirs_out_of_reach` stat of a real directory: `lstat` and, for a
/// directory, its ACLs (a symlink is no directory; its ACLs are not read).
pub fn lstat_dir(p: &str) -> Option<(Perm, bool)> {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(p).ok().map(|m| {
        let is_dir = m.file_type().is_dir();
        let acl = is_dir && acl_beyond_mode(p, false, true);
        (Perm { owner: m.uid(), gid: m.gid(), mode: m.mode(), acl }, is_dir)
    })
}

/// What the guard knows about a process's executable.
#[derive(Debug, Clone, Default)]
pub struct ExeIdentity {
    /// `/proc/<pid>/exe`, resolved ("" when unreadable).
    pub path: String,
    /// sha256 of the inode the process runs, hex.
    pub sha256: Option<String>,
    /// That inode and every directory above `path` are out of the agent's reach.
    pub system: bool,
}

/// sha256 of executables, keyed by the inode's identity and change time
/// (dev, ino, ctime, ctime_nsec, size): a file rewritten in place gets a new
/// ctime, a renamed-over path is another inode.
#[derive(Debug, Default)]
pub struct HashCache {
    by_inode: Mutex<HashMap<InodeKey, String>>,
    /// An executable's hash and what its content shows (`content_of`: the
    /// interpreter, the package), from one read.
    contents: Mutex<HashMap<InodeKey, (String, Content)>>,
}

/// (dev, ino, ctime, ctime_nsec, size).
type InodeKey = (u64, u64, i64, i64, u64);

impl HashCache {
    pub(crate) fn get_or(&self, key: InodeKey, compute: impl FnOnce() -> Option<String>) -> Option<String> {
        if let Some(h) = self.by_inode.lock().ok().and_then(|c| c.get(&key).cloned()) {
            return Some(h);
        }
        let h = compute()?;
        if let Ok(mut c) = self.by_inode.lock() {
            c.insert(key, h.clone());
        }
        Some(h)
    }

    /// The sha256 of the file at `path` (the inode `key` names) and what its
    /// content shows (`content_of`), read once per inode; None when it
    /// cannot be read.
    pub(crate) fn content_or(&self, key: InodeKey, path: &str) -> Option<(String, Content)> {
        if let Some(hit) = self.contents.lock().ok().and_then(|c| c.get(&key).cloned()) {
            return Some(hit);
        }
        let bytes = fs::read(path).ok()?;
        let v = (sha256_hex(&bytes), content_of(&bytes));
        if let Ok(mut c) = self.contents.lock() {
            c.insert(key, v.clone());
        }
        Some(v)
    }
}

/// Is the inode `pid` runs (stat through `/proc/<pid>/exe`) out of the
/// agent's reach, and every directory above its path `exe`?
fn inode_out_of_reach(pid: i32, exe: &str, who: &Who) -> bool {
    let link = format!("/proc/{pid}/exe");
    fs::metadata(&link).ok().is_some_and(|m| m.is_file() && !writable_by(perm_of(&link, &m), who))
        && dirs_out_of_reach(exe, who, lstat_dir)
}

/// The identity of `pid`'s executable: its path, the hash of the inode it
/// runs (opened through `/proc/<pid>/exe`, never by path) and whether that
/// inode and its directories are out of the agent's reach.
pub fn exe_identity(pid: i32, who: &Who, cache: &HashCache) -> ExeIdentity {
    let link = format!("/proc/{pid}/exe");
    let path = fs::read_link(&link).ok().and_then(|p| p.to_str().map(String::from)).unwrap_or_default();
    if path.is_empty() {
        return ExeIdentity::default();
    }
    let meta = fs::metadata(&link).ok();
    let system = inode_out_of_reach(pid, &path, who);
    let sha256 = meta.and_then(|m| cache.content_or(inode_key(&m), &link)).map(|(h, _)| h);
    ExeIdentity { path, sha256, system }
}

fn inode_key(m: &fs::Metadata) -> InodeKey {
    use std::os::unix::fs::MetadataExt;
    (m.dev(), m.ino(), m.ctime(), m.ctime_nsec(), m.size())
}

/// sha256 of the file at `path`, hex; None when it cannot be read.
pub fn sha256_file(path: &str) -> Option<String> {
    fs::read(path).ok().map(|b| sha256_hex(&b))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().fold(String::with_capacity(64), |mut out, b| {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Plan 13 §8 decision (b) by content (2026-10-03, a leftover of the
/// renamed-copy fix): what marks an executable as a language interpreter,
/// whatever its name, version or build. Each is the interpreter's own front
/// end, the entry its `main` hands the command line to, or a text only that
/// front end prints: CPython's `Py_BytesMain` / `Py_Main` (a shared build's
/// small binary imports it, a static build carries it), node's
/// `node::Start(int, char**)` and Electron's run-as-node switch, perl's
/// `perl_parse`, ruby's `ruby_run_node`, lua's usage line, Tcl's `Tcl_Main`
/// and Tk's `Tk_MainEx`, Java's launcher `JLI_Launch` (java, and keytool
/// and its kin, which take `-J` options), PHP's `php_execute_script`,
/// BusyBox's banner, bash's version line, zsh's `zsh_main`, and the ash
/// family's (dash) `set -o` header, which the pdksh line (mksh, posh) and
/// ksh93 print too. Chosen over library names (a static build names no
/// libpython) and over the symbols an EMBEDDING program shares
/// (`Py_Initialize` is in vim and gdb, `lua_pcall` in nmap): on a Debian
/// desktop each marker is found in its interpreter and nowhere else in
/// /usr/bin but `tailscaled` (BusyBox's banner).
///
/// The families !506 left out (2026-10-04), each checked against the
/// distribution's build and, where one exists, an older or upstream one:
/// ksh93's `.sh.subshell` variable (93u+m and ksh2020), mksh's and lksh's
/// version strings, posh's and yash's own texts, tcsh's version line, BSD
/// csh's exit hint, fish's interpreter-directive error (fish 3 in C++ and
/// fish 4 in Rust; its `fish_indent` shares the code),
/// toybox's usage line, LuaJIT's front-end option help (not the library
/// that OpenResty and neovim embed), guile's `scm_shell` import and its
/// locale warning (2.2 and 3.0), Racket CS's `racket_boot` (its argv is
/// racket's command line), R's `R_running_as_main_program` (the `exec/R`
/// binary the `R` script runs; `Rscript` only execs it) and littler's
/// `/etc/littler.r`, julia's launcher import `jl_load_repl` (1.6 on: the
/// small `julia` binary, not libjulia), bun's crash-restart message (1.0.0
/// to a September 2026 release, and every `bun build --compile` program,
/// which carries the whole runtime) and its `BUN_BE_BUN` switch (which
/// turns such a program into bun), deno's CLI description (1.30 to 2.x; not `denort`,
/// which `deno compile` programs run), and the name of the assembly
/// PowerShell's .NET apphost (`pwsh`, the file exec'd) loads.
///
/// The families known by name only until P0 item 14 (2026-10-07), each
/// checked against the real binaries (fetched, not installed): elvish's
/// shell package (`src.elv.sh/pkg/shell`, 0.18 to 0.21; its older module
/// path, 0.14), nushell's REPL module and crate (`nu_cli::repl`,
/// `crates/nu-cli/src/`, 0.60 to 0.116), the .NET muxer's usage line (the
/// `dotnet` host, 3.1 and 8, which runs any assembly; an app's own apphost
/// does not carry it), Racket BC's command-line help (7.9, and `gracket`,
/// which runs racket code too), julia's own front end before 1.6 (its
/// economy-REPL warning, 1.0 and 1.5; 1.6 on moved it into the library and
/// is `jl_load_repl`), and the public-domain ksh line's version string
/// (OpenBSD's ksh, `oksh`, `loksh`, `pdksh`, which the ash header named `sh`
/// before). Not covered, stated: an interpreter none of these marks under a
/// name the list does not know and not byte-identical to an installed one;
/// a program built to carry no marker (content identity is for copies and
/// builds of known programs: an adversarial binary is the human's to vouch
/// for or not).
///
/// Stored masked (each byte XOR `MARKER_MASK`, applied at compile time), so
/// that no binary carrying this table (the guard, its tests) holds a marker
/// whole and is taken for an interpreter itself: plain literals were pooled
/// into one (the family name `php` before `hp_execute_script`). Order
/// matters only for the family named: the shells' shared `set -o` header
/// comes last, so a ksh is named `ksh`.
pub const RUNTIME_MARKERS: &[(&str, &[u8])] = &[
    ("python", &masked(b"Py_BytesMain")),
    ("python", &masked(b"Py_Main")),
    ("node", &masked(b"_ZN4node5StartEiPPc")),
    ("node", &masked(b"ELECTRON_RUN_AS_NODE")),
    ("perl", &masked(b"perl_parse")),
    ("ruby", &masked(b"ruby_run_node")),
    ("lua", &masked(b"usage: %s [options] [script [args]]")),
    ("tcl", &masked(b"Tcl_Main")),
    ("tcl", &masked(b"Tk_MainEx")),
    ("java", &masked(b"JLI_Launch")),
    ("php", &masked(b"php_execute_script")),
    ("busybox", &masked(b"BusyBox v")),
    ("bash", &masked(b"GNU bash, version")),
    ("zsh", &masked(b"zsh_main")),
    // 2026-10-04, the families !506 left out
    ("ksh", &masked(b".sh.subshell")),
    ("mksh", &masked(b"@(#)MIRBSD KSH")),
    ("mksh", &masked(b"@(#)LEGACY KSH")),
    ("posh", &masked(b"posh_builtin_getopts")),
    ("yash", &masked(b"Yet another shell, version")),
    ("tcsh", &masked(b"tcsh %d.%.2d.%.2d")),
    ("csh", &masked(b"Use \"exit\" to leave csh.")),
    ("fish", &masked(b"fish scripts require an interpreter directive")),
    ("toybox", &masked(b"usage: toybox [--long")),
    ("luajit", &masked(b"Perform LuaJIT control command")),
    ("guile", &masked(b"scm_shell\0")),
    ("guile", &masked(b"guile: warning: failed to install locale")),
    ("racket", &masked(b"racket_boot")),
    ("R", &masked(b"R_running_as_main_program")),
    ("R", &masked(b"/etc/littler.r")),
    ("julia", &masked(b"jl_load_repl")),
    ("bun", &masked(b"Bun is auto-restarting due to crash")),
    ("bun", &masked(b"BUN_BE_BUN")),
    ("deno", &masked(b"A modern JavaScript and TypeScript runtime")),
    ("pwsh", &masked(b"pwsh.dll")),
    // 2026-10-07 (P0 item 14), the families known by name only
    ("elvish", &masked(b"src.elv.sh/pkg/shell")),
    ("elvish", &masked(b"github.com/elves/elvish/pkg/shell")),
    ("nushell", &masked(b"nu_cli::repl")),
    ("nushell", &masked(b"crates/nu-cli/src/")),
    ("dotnet", &masked(b"Usage: dotnet [path-to-application]")),
    ("racket", &masked(b"--eval <exprs> : Evaluate <exprs>")),
    ("julia", &masked(b"falling back to economy mode repl")),
    ("pdksh", &masked(b"@(#)PD KSH v")),
    // last: the ash family's header, which the ksh line prints too
    ("sh", &masked(b"Current option settings")),
];

/// P0 item 14 (2026-10-07), plan 13 D8 (13): the packages whose programs
/// print the files they read or run another program, each by a text every
/// program of the package carries (its name as `--version` prints it, or
/// its usage line). A binary carrying one, under a name neither list knows
/// and byte-identical to no installed program (another version, a static
/// download, a build of the human's own), is that package's program: a
/// non-identical GNU `env`, `cat` or `xargs` renamed `mytool`. Swept over
/// the 19,647 ELF files of the development host: GNU coreutils' text is in
/// coreutils' programs and the uutils multi-call binary (a printer by its
/// path anyway), findutils' in `find` and `xargs`, util-linux's version in
/// its 112 programs and none of its libraries, diffutils' in `diff`,
/// `cmp`, `diff3`, `sdiff`, GNU sed's in `sed` and BusyBox (an interpreter
/// first), grep's and tar's usage lines in `grep` and `tar` alone (their
/// package names were also in `dpkg`, `as` and Claude Code's binary).
pub const PACKAGE_MARKERS: &[(&str, &[u8])] = &[
    ("coreutils", &masked(b"GNU coreutils")),
    ("findutils", &masked(b"GNU findutils")),
    ("util-linux", &masked(b"util-linux 2.")),
    ("diffutils", &masked(b"GNU diffutils")),
    ("sed", &masked(b"GNU sed")),
    ("grep", &masked(b"Search for PATTERNS in each FILE")),
    ("grep", &masked(b"Search for PATTERN in each FILE")),
    ("tar", &masked(b"saves many files together into a single tape or disk archive")),
];

/// A package's programs that neither print a file nor run one: coreutils'
/// checksum tools (`sha256sum`, `md5sum`, `b2sum`, `sum`, the leaf readers
/// the human names with `prints: nothing`), by their shared usage line. Not
/// for a multi-call binary (`PACKAGE_MULTICALL`), which is every program of
/// its package.
pub const PACKAGE_LEAVES: &[(&str, &[u8])] = &[("coreutils", &masked(b"Print or check %s (%d-bit) checksums."))];

/// GNU coreutils' multi-call switch: such a binary is any coreutils program.
pub const PACKAGE_MULTICALL: &[(&str, &[u8])] = &[("coreutils", &masked(b"--coreutils-prog"))];

/// The mask of `RUNTIME_MARKERS`' bytes (high bit set: no text byte).
pub const MARKER_MASK: u8 = 0xA5;

const fn masked<const N: usize>(s: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = s[i] ^ MARKER_MASK;
        i += 1;
    }
    out
}

/// The window `runtime_of` searches at a time (see there).
pub const SCAN_WINDOW: usize = 256 * 1024;

/// The interpreter family whose front end `bytes` (an executable's content)
/// carries (`RUNTIME_MARKERS`), or None: the first in the table's order.
/// Pure.
pub fn runtime_of(bytes: &[u8]) -> Option<&'static str> {
    content_of(bytes).runtime
}

/// What an executable's content shows it is: the interpreter family whose
/// front end it carries (`RUNTIME_MARKERS`, the first in the table's order),
/// else the package of printers or launchers it belongs to
/// (`PACKAGE_MARKERS`, the first in order, a package's leaf program
/// excepted: `PACKAGE_LEAVES`, `PACKAGE_MULTICALL`). An interpreter wins:
/// it runs code, which says more than its package does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Content {
    pub runtime: Option<&'static str>,
    pub package: Option<&'static str>,
}

/// What a marker of the joined search table stands for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MarkerKind {
    Runtime,
    Package,
    Leaf,
    Multicall,
}

/// `Content` of `bytes` (an executable's content). Pure.
pub fn content_of(bytes: &[u8]) -> Content {
    // One searcher per marker, unmasked once (memchr's SIMD substring
    // search): the runtimes first, in their order, then the packages, the
    // leaves and the multi-call switches.
    type Finders = Vec<(MarkerKind, &'static str, memchr::memmem::Finder<'static>)>;
    static FINDERS: std::sync::OnceLock<Finders> = std::sync::OnceLock::new();
    let finders = FINDERS.get_or_init(|| {
        let tables: [(MarkerKind, &[(&str, &[u8])]); 4] = [
            (MarkerKind::Runtime, RUNTIME_MARKERS),
            (MarkerKind::Package, PACKAGE_MARKERS),
            (MarkerKind::Leaf, PACKAGE_LEAVES),
            (MarkerKind::Multicall, PACKAGE_MULTICALL),
        ];
        tables
            .iter()
            .flat_map(|(kind, table)| {
                table.iter().map(move |(name, m)| {
                    let plain: Vec<u8> = m.iter().map(|k| k ^ MARKER_MASK).collect();
                    (*kind, *name, memchr::memmem::Finder::new(&plain).into_owned())
                })
            })
            .collect()
    });
    let runtimes = RUNTIME_MARKERS.len();
    // Searched a window at a time, every marker over a window while it is in
    // the cache, rather than the whole file once per marker from memory:
    // with thirty-six markers, one pass each took a 234 MB binary 0.8 s; by
    // window, 0.37 s, what fifteen took before (2026-10-04). A window runs
    // on past its chunk by the longest marker less one byte, so a marker
    // that starts in a chunk is whole in its window. The first runtime in
    // the table's order wins, as with one pass per marker: a later window
    // looks only for the runtimes before the best found so far, and, once
    // one is found, for no package (an interpreter wins). A marker found is
    // not looked for again.
    let longest = finders.iter().map(|(_, _, f)| f.needle().len()).max().unwrap_or(1);
    let mut found = vec![false; finders.len()];
    let mut best = runtimes;
    let mut start = 0;
    while start < bytes.len() {
        let wanted = |i: usize, found: &[bool], best: usize| !found[i] && if i < runtimes { i < best } else { best == runtimes };
        if !(0..finders.len()).any(|i| wanted(i, &found, best)) {
            break;
        }
        let window = &bytes[start..(start + SCAN_WINDOW + longest - 1).min(bytes.len())];
        for i in 0..finders.len() {
            if wanted(i, &found, best) && finders[i].2.find(window).is_some() {
                found[i] = true;
                if i < runtimes {
                    best = i;
                }
            }
        }
        start += SCAN_WINDOW;
    }
    if best < runtimes {
        return Content { runtime: Some(finders[best].1), package: None };
    }
    let has = |kind: MarkerKind, name: &str| finders.iter().zip(&found).any(|((k, n, _), f)| *f && *k == kind && *n == name);
    let package = finders
        .iter()
        .zip(&found)
        .filter(|((k, _, _), f)| **f && *k == MarkerKind::Package)
        .map(|((_, n, _), _)| *n)
        .find(|n| !has(MarkerKind::Leaf, n) || has(MarkerKind::Multicall, n));
    Content { runtime: None, package }
}

/// The paths of the executable FILE mappings in `/proc/<pid>/maps` text
/// (permissions with `x`; anonymous, `[vdso]` and the like have no path).
/// Pure.
pub fn exec_mapped_paths(maps: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in maps.lines() {
        // address perms offset dev inode pathname (the pathname may hold spaces)
        let mut rest = line;
        let mut fields: Vec<&str> = Vec::with_capacity(5);
        for _ in 0..5 {
            rest = rest.trim_start();
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            fields.push(&rest[..end]);
            rest = &rest[end..];
        }
        let path = rest.trim_start();
        if fields.len() == 5 && fields[1].contains('x') && path.starts_with('/') && !out.iter().any(|p| p == path) {
            out.push(path.to_string());
        }
    }
    out
}

/// Everything the guard needs to judge who an opener is, built once per
/// launch: the agent's uid and groups, the launch's environment, the hashes
/// by inode, and the files already found out of reach (only a root-owned
/// tree is out of reach, and only root can change that, so a positive answer
/// is kept for the guard's life).
#[derive(Debug, Default)]
pub struct IdentityCtx {
    pub who: Who,
    pub launch: EnvBaseline,
    pub hashes: HashCache,
    out_of_reach: Mutex<std::collections::HashSet<String>>,
}

impl IdentityCtx {
    pub fn current() -> Self {
        IdentityCtx { who: Who::current(), launch: EnvBaseline::from_process(), ..Default::default() }
    }

    /// Is the file at `path` (followed) and every directory above it out of
    /// the agent's reach?
    pub fn file_out_of_reach(&self, path: &str) -> bool {
        if self.out_of_reach.lock().is_ok_and(|s| s.contains(path)) {
            return true;
        }
        let ok = fs::metadata(path).ok().is_some_and(|m| m.is_file() && !writable_by(perm_of(path, &m), &self.who))
            && dirs_out_of_reach(path, &self.who, lstat_dir);
        if ok {
            if let Ok(mut s) = self.out_of_reach.lock() {
                s.insert(path.to_string());
            }
        }
        ok
    }

    /// The identity of `pid`'s executable (`exe_identity`).
    pub fn exe(&self, pid: i32) -> ExeIdentity {
        exe_identity(pid, &self.who, &self.hashes)
    }

    /// What the content of the inode `pid` runs shows (`content_of`: the
    /// interpreter, the package), read through `/proc/<pid>/exe` with its
    /// hash, once per inode; `None` when it cannot be read.
    pub fn exe_content(&self, pid: i32) -> Option<Content> {
        let link = format!("/proc/{pid}/exe");
        let m = fs::metadata(&link).ok()?;
        self.hashes.content_or(inode_key(&m), &link).map(|(_, c)| c)
    }

    /// The interpreter family the content of the inode `pid` runs shows
    /// (`exe_content`'s runtime); `None` when it cannot be read.
    pub fn exe_runtime(&self, pid: i32) -> Option<Option<&'static str>> {
        self.exe_content(pid).map(|c| c.runtime)
    }

    /// Plan 13 R5: the script `pid` (running the interpreter `exe`) runs
    /// (`script_identity::script_facts`); None for a program that is no
    /// script interpreter.
    pub fn script(&self, pid: i32, exe: &str) -> Option<Result<crate::script_identity::ScriptFacts, String>> {
        crate::script_identity::script_facts(pid, exe, &self.who, &self.hashes)
    }

    /// What makes `pid` (running `exe`) not the program its name or pin
    /// says: the loader / interpreter variables the launch did not give (by
    /// name, `untrusted_env`), and every executable file mapped into it,
    /// other than `exe` itself, that the agent could have written
    /// (`code:<path>`: a library LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT or a
    /// dlopen brought in). The mappings close what the environment alone
    /// cannot: an injected library may scrub `/proc/<pid>/environ` before
    /// the open, but must stay mapped to run. Then, for a program with
    /// argument rules, what its command line and environment hand it to run
    /// (`args:<program> <option>`, `args_code`). And for a binary no name on
    /// the code-running list marks, the interpreter its content shows
    /// (`runs:<family>`, `runtime_of`). `None` when any of them cannot be
    /// read: the arbiter treats that as unclean. Empty = clean.
    pub fn findings(&self, pid: i32, exe: &str) -> Option<Vec<String>> {
        self.findings_of(pid, exe, true)
    }

    /// `findings`, with the content check (`runs:`, `pkg:`) only when
    /// `by_content`: an ancestor in the agent's reach is never a trusted
    /// `from:` parent, so it is not read whole (the agent's own binary is
    /// often one, a quarter of a gigabyte); one out of its reach is
    /// (`ancestors`).
    fn findings_of(&self, pid: i32, exe: &str, by_content: bool) -> Option<Vec<String>> {
        let environ = parse_environ(&fs::read(format!("/proc/{pid}/environ")).ok()?);
        let mut out = untrusted_env(exe, &environ, &self.launch);
        // Plan 13 §8 decision (b) by content: a binary its name does not
        // mark as running code, whose content is an interpreter's
        // (`runtime_of`), is one (`runs:<family>`). Plan 13 D8 (13), P0 item
        // 14 (2026-10-07): one neither list names, whose content is a
        // program of a package of printers or launchers (`content_of`'s
        // package: a non-identical GNU `env` renamed), is one
        // (`pkg:<package>`). Its content unread: not judged clean.
        if by_content && !crate::secret_open::runs_code(exe) {
            let content = self.exe_content(pid)?;
            if let Some(family) = content.runtime {
                out.push(format!("runs:{family}"));
            } else if let Some(package) = content.package.filter(|_| !crate::secret_open::prints(exe)) {
                out.push(format!("pkg:{package}"));
            }
        }
        // Plan 13 D8, code by argument: a program whose command line or
        // environment hands it code (`git -c alias.x=!sh`, `ssh -o
        // ProxyCommand=…`, `less +!cmd`) is not the program the human named
        // (`args_code`). Its command line unread: not judged clean.
        if crate::args_code::has_rules(exe) {
            let cmd = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
            out.extend(crate::args_code::code_by_arguments(exe, &crate::script_identity::parse_cmdline(&cmd), &environ, &self.launch));
        }
        let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
        let mut code: Vec<String> = exec_mapped_paths(&maps)
            .into_iter()
            .filter(|p| p != exe && !self.file_out_of_reach(p))
            .map(|p| format!("code:{p}"))
            .collect();
        code.sort();
        out.extend(code);
        Some(out)
    }

    /// The ancestors of `pid`, nearest first, up to `max` levels: each one's
    /// executable path, and whether it is trusted as a `from:` parent
    /// (`ancestor_trusted`: its binary out of reach, and `findings` empty,
    /// its content included since P0 item 14, so a disguised interpreter
    /// under the parent's name is not that parent; only an out-of-reach
    /// ancestor is read, once per inode). Only the ancestors INSIDE the
    /// session, below the guard (this process): what launched Mandu is no
    /// `from:` parent, and a chain that does not reach the guard gives none
    /// (`lineage::session_ancestors`, 2026-10-17). Stops at the first
    /// ancestor whose executable cannot be read, or that is no longer the
    /// process the walk found (its start time changed).
    pub fn ancestors(&self, pid: i32, max: usize) -> Vec<(String, bool)> {
        self.ancestors_below(pid, std::process::id() as i32, max)
    }

    /// `ancestors`, bounded by `guard` instead of this process.
    pub fn ancestors_below(&self, pid: i32, guard: i32, max: usize) -> Vec<(String, bool)> {
        let stat_of = |p: i32| fs::read_to_string(format!("/proc/{p}/stat")).ok().and_then(|s| crate::lineage::parse_stat(&s));
        let mut out = Vec::new();
        for (pp, start) in crate::lineage::session_ancestors(pid, guard, max, stat_of) {
            let Some(exe) = fs::read_link(format!("/proc/{pp}/exe")).ok().and_then(|p| p.to_str().map(String::from)) else { break };
            let reach = inode_out_of_reach(pp, &exe, &self.who);
            let trusted = ancestor_trusted(reach, if reach { self.findings_of(pp, &exe, true) } else { None }.as_deref());
            // The number the walk read may have been reused since: the facts
            // above are then another process's.
            if stat_of(pp).map(|s| s.start) != Some(start) {
                break;
            }
            out.push((exe, trusted));
        }
        out
    }
}

/// Is an ancestor a trusted `from:` parent? Its binary out of the agent's
/// reach, and its findings read and empty: no loader variable the launch
/// did not give, no agent-writable code mapped, no code by argument, and,
/// by its content (P0 item 14, plan 13 D8 (13)), no interpreter (`runs:`)
/// or package of printers or launchers (`pkg:`) its name does not say. Pure.
pub fn ancestor_trusted(out_of_reach: bool, findings: Option<&[String]>) -> bool {
    out_of_reach && findings.is_some_and(|f| f.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn a_loader_variable_the_launch_did_not_give_is_named_never_its_value() {
        let launch = EnvBaseline::from_vars(env(&[("LD_LIBRARY_PATH", "/opt/cuda/lib64"), ("PATH", "/usr/bin")]));
        assert_eq!(untrusted_env("/usr/bin/psql", &env(&[("LD_PRELOAD", "/tmp/x/evil.so"), ("HOME", "/h")]), &launch), vec!["LD_PRELOAD"]);
        assert!(untrusted_env("/usr/bin/psql", &env(&[("LD_LIBRARY_PATH", "/opt/cuda/lib64")]), &launch).is_empty(), "the launch's own value is admitted");
        assert_eq!(untrusted_env("/usr/bin/psql", &env(&[("LD_LIBRARY_PATH", "/ws/lib")]), &launch), vec!["LD_LIBRARY_PATH"], "another value is not");
        assert_eq!(untrusted_env("/usr/bin/psql", &env(&[("LD_AUDIT", "/ws/a.so"), ("GCONV_PATH", "/ws/g")]), &launch), vec!["GCONV_PATH", "LD_AUDIT"]);
        assert_eq!(untrusted_env("/usr/bin/curl", &env(&[("OPENSSL_CONF", "/ws/o.cnf"), ("OPENSSL_MODULES", "/ws/m")]), &launch), vec!["OPENSSL_CONF", "OPENSSL_MODULES"], "OpenSSL loads an engine or a provider from these");
        assert!(untrusted_env("/usr/bin/psql", &env(&[("LD_PRELOAD", "")]), &launch).is_empty(), "an empty value loads nothing");
        let out = untrusted_env("/usr/bin/psql", &env(&[("LD_PRELOAD", "/tmp/secret-looking-value")]), &launch);
        assert!(out.iter().all(|n| !n.contains("secret-looking")), "names only");
    }

    #[test]
    fn an_interpreters_own_variables_count_only_for_that_interpreter() {
        let launch = EnvBaseline::default();
        let agent = env(&[("PYTHONPATH", "/ws"), ("NODE_OPTIONS", "--require /ws/hook.js"), ("PERL5OPT", "-Mevil"), ("RUBYOPT", "-revil"), ("BASH_ENV", "/ws/rc"), ("BASH_FUNC_cat%%", "() { :; }")]);
        assert!(untrusted_env("/usr/bin/psql", &agent, &launch).is_empty(), "psql reads none of them: a dev's PYTHONPATH does not refuse it");
        assert_eq!(untrusted_env("/usr/bin/python3.12", &agent, &launch), vec!["PYTHONPATH"]);
        assert_eq!(untrusted_env("/usr/bin/node", &agent, &launch), vec!["NODE_OPTIONS"]);
        assert_eq!(untrusted_env("/usr/bin/perl", &agent, &launch), vec!["PERL5OPT"]);
        assert_eq!(untrusted_env("/usr/bin/ruby", &agent, &launch), vec!["RUBYOPT"]);
        assert_eq!(untrusted_env("/usr/bin/bash", &agent, &launch), vec!["BASH_ENV", "BASH_FUNC_cat%%"]);
        assert!(is_loader_var("/usr/bin/zsh", "ZDOTDIR") && is_loader_var("/usr/lib/jvm/bin/java", "JAVA_TOOL_OPTIONS"));
        assert!(!is_loader_var("/usr/bin/ssh2", "PYTHONPATH"));
    }

    #[test]
    fn node_options_flags_that_load_no_code_are_admitted() {
        let launch = EnvBaseline::from_vars(env(&[("NODE_OPTIONS", "--disable-warning=UNDICI-EHPA")]));
        assert!(untrusted_env("/usr/bin/node", &env(&[("NODE_OPTIONS", "--disable-warning=UNDICI-EHPA")]), &launch).is_empty());
        assert!(untrusted_env("/usr/bin/node", &env(&[("NODE_OPTIONS", "--disable-warning=UNDICI-EHPA --max-old-space-size=4096")]), &launch).is_empty());
        for bad in ["--require /ws/x.js", "-r /ws/x.js", "--import=/ws/x.mjs", "--loader /ws/l.mjs", "--disable-warning=X --experimental-loader=/ws/l.mjs", "--max-old-space-size="] {
            assert_eq!(untrusted_env("/usr/bin/node", &env(&[("NODE_OPTIONS", bad)]), &launch), vec!["NODE_OPTIONS"], "{bad}");
        }
    }

    /// Plan 13 D8, code by argument: `findings` reads a live opener's
    /// command line (no privilege: our own child). `tar --to-command` is
    /// reported by its option name; a plain `tar -xf -` is not.
    #[test]
    fn findings_carry_a_live_childs_code_arguments() {
        let Ok(tar) = fs::canonicalize("/usr/bin/tar").or_else(|_| fs::canonicalize("/bin/tar")) else { return };
        let tar = tar.to_str().unwrap().to_string();
        let ctx = IdentityCtx::current();
        let run = |args: &[&str]| -> Option<Vec<String>> {
            let mut child = std::process::Command::new(&tar)
                .args(args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let pid = child.id() as i32;
            let mut got = None;
            for _ in 0..2000 {
                // Until the exec, the child's command line is this test binary's.
                let cmd = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
                if crate::script_identity::parse_cmdline(&cmd).get(1).map(String::as_str) == args.first().copied() {
                    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok().and_then(|p| p.to_str().map(String::from)).unwrap_or_default();
                    got = ctx.findings(pid, &exe);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let _ = child.kill();
            let _ = child.wait();
            got
        };
        let name = tar.rsplit('/').next().unwrap().to_string();
        let coded = run(&["--to-command=true", "-xf", "-"]).expect("findings read");
        assert!(coded.iter().any(|f| f == &format!("args:{name} --to-command")), "{coded:?}");
        let plain = run(&["-xf", "-"]).expect("findings read");
        assert!(plain.iter().all(|f| !f.starts_with("args:")), "{plain:?}");
    }

    #[test]
    fn environ_bytes_parse_into_pairs() {
        let p = parse_environ(b"A=1\0LD_PRELOAD=/x.so\0EMPTY=\0junk\0\0");
        assert_eq!(p, env(&[("A", "1"), ("LD_PRELOAD", "/x.so"), ("EMPTY", ""), ("junk", "")]));
    }

    fn who() -> Who {
        Who { uid: 1000, groups: vec![1000, 27], ns_overflow: None, caps: 0 }
    }

    const fn b(owner: u32, gid: u32, mode: u32) -> Perm {
        Perm::bits(owner, gid, mode)
    }

    #[test]
    fn writable_by_the_agent_is_its_own_its_groups_or_the_worlds() {
        let w = who();
        assert!(!writable_by(b(0, 0, 0o755), &w), "root's 755: out of reach");
        assert!(writable_by(b(1000, 1000, 0o755), &w), "the agent's own file");
        assert!(writable_by(b(0, 0, 0o1777), &w), "a sticky world-writable dir (/tmp) is in reach");
        assert!(writable_by(b(0, 27, 0o775), &w), "group-writable by a group the agent is in");
        assert!(!writable_by(b(0, 50, 0o775), &w), "group-writable by a group it is not in");
        assert!(!writable_by(b(1001, 1001, 0o755), &w), "another user's 755");
        assert!(writable_by(b(0, 0, 0o755), &Who { uid: 0, groups: vec![0], ns_overflow: None, caps: 0 }), "a root agent reaches everything");
        // root of a child user namespace (unshare --map-root-user): the host's
        // root files show as the overflow uid and are out of its reach; its
        // own (mapped) files are not
        let ns_root = Who { uid: 0, groups: vec![0], ns_overflow: Some(65534), caps: u64::MAX };
        assert!(!writable_by(b(65534, 65534, 0o755), &ns_root), "an unmapped owner's 755");
        assert!(writable_by(b(0, 0, 0o755), &ns_root), "the namespace's own (the user's) file");
        assert!(writable_by(b(65534, 65534, 0o1777), &ns_root), "a world-writable dir is in reach");
        assert!(is_initial_uid_map("         0          0 4294967295\n"));
        assert!(!is_initial_uid_map("         0       1000          1\n"));
        assert!(!is_initial_uid_map(""));
    }

    // P0 triage 2d: a capability that overrides file permissions puts every
    // file in reach (outside a user namespace), whatever the mode bits say.
    #[test]
    fn a_capability_that_overrides_file_permissions_reaches_every_file() {
        const DAC_OVERRIDE: u64 = 1 << 1;
        const FOWNER: u64 = 1 << 3;
        const CHOWN: u64 = 1 << 0;
        const SETUID: u64 = 1 << 7;
        const SYS_ADMIN: u64 = 1 << 21;
        const NET_BIND: u64 = 1 << 10;
        const NET_RAW: u64 = 1 << 13;
        let root_755 = b(0, 0, 0o755);
        for (cap, name) in [(DAC_OVERRIDE, "CAP_DAC_OVERRIDE"), (FOWNER, "CAP_FOWNER"), (CHOWN, "CAP_CHOWN"), (SETUID, "CAP_SETUID"), (SYS_ADMIN, "CAP_SYS_ADMIN"), (1u64 << 41, "a capability a later kernel adds")] {
            assert!(caps_reach(cap), "{name}");
            let w = Who { caps: cap, ..who() };
            assert!(writable_by(root_755, &w), "{name}: root's 755 is in reach");
            assert!(writable_by(b(1001, 1001, 0o700), &w), "{name}: another user's 700 is in reach");
            // the same capability in a child user namespace covers mapped owners only
            let ns = Who { caps: cap, ns_overflow: Some(65534), ..who() };
            assert!(!writable_by(b(65534, 65534, 0o755), &ns), "{name} in a child namespace: an unmapped owner's 755");
            assert!(writable_by(b(0, 0, 0o755), &ns), "{name} in a child namespace: a mapped owner's file");
        }
        for (cap, name) in [(NET_BIND, "CAP_NET_BIND_SERVICE"), (NET_RAW, "CAP_NET_RAW"), (NET_BIND | NET_RAW, "both")] {
            assert!(!caps_reach(cap), "{name}");
            assert!(!writable_by(root_755, &Who { caps: cap, ..who() }), "{name} leaves root's 755 out of reach");
        }
        assert!(!caps_reach(0));
        // CapPrm | CapEff, read from /proc/<pid>/status
        let status = "Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000002\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";
        assert_eq!(status_caps(status), Some(DAC_OVERRIDE), "a permitted capability can be raised: it counts");
        assert_eq!(status_caps("CapEff:\t0000000000000008\nCapPrm:\t0000000000000000\n"), Some(FOWNER));
        assert_eq!(status_caps("CapPrm:\tzz\nCapEff:\t0\n"), None, "malformed");
        assert_eq!(status_caps("Name:\tx\n"), None, "missing");
        // the live identity reads them: this test runs with none of them, or
        // as root (which reaches everything anyway)
        let me = Who::current();
        assert!(me.uid == 0 || !caps_reach(me.caps) || me.caps == u64::MAX || me.ns_overflow.is_some(), "{me:?}");
    }

    /// A `system.posix_acl_access` value: (tag, perm, id) entries.
    fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut v = 2u32.to_le_bytes().to_vec();
        for &(tag, perm, id) in entries {
            v.extend_from_slice(&tag.to_le_bytes());
            v.extend_from_slice(&perm.to_le_bytes());
            v.extend_from_slice(&id.to_le_bytes());
        }
        v
    }
    const UNDEF: u32 = u32::MAX;

    // P0 triage 2d: any ACL beyond the mode bits puts the inode in reach,
    // whoever its entries name (fail closed), and so does a default ACL on a
    // directory or one that cannot be read.
    #[test]
    fn an_acl_beyond_the_mode_bits_puts_a_file_in_reach() {
        let base = acl(&[(0x01, 7, UNDEF), (0x04, 5, UNDEF), (0x20, 5, UNDEF)]);
        assert!(!posix_acl_extended(&base), "the three base entries are the mode bits");
        let named_user = acl(&[(0x01, 7, UNDEF), (0x02, 6, 1000), (0x04, 5, UNDEF), (0x10, 7, UNDEF), (0x20, 5, UNDEF)]);
        assert!(posix_acl_extended(&named_user), "a named user");
        let named_group_ro = acl(&[(0x01, 7, UNDEF), (0x04, 5, UNDEF), (0x08, 4, 27), (0x10, 5, UNDEF), (0x20, 5, UNDEF)]);
        assert!(posix_acl_extended(&named_group_ro), "a named group, even read-only: fail closed");
        assert!(posix_acl_extended(&[2, 0, 0]), "truncated");
        assert!(posix_acl_extended(&acl(&[(0x01, 7, UNDEF)])[..9]), "a partial entry");
        let mut v1 = base.clone();
        v1[0] = 1;
        assert!(posix_acl_extended(&v1), "an unknown version");

        use XattrRead::*;
        let ext = Value(named_user.clone());
        assert!(!acl_state(&Absent, &Absent, &Absent, false), "no ACL");
        assert!(!acl_state(&Value(base.clone()), &Absent, &Absent, false), "a base-only access ACL");
        assert!(acl_state(&ext, &Absent, &Absent, false), "an extended access ACL");
        assert!(acl_state(&Unreadable, &Absent, &Absent, false), "an access ACL that cannot be read");
        assert!(acl_state(&Absent, &Value(base.clone()), &Absent, true), "any default ACL on a directory");
        assert!(acl_state(&Absent, &Unreadable, &Absent, true), "an unreadable default ACL on a directory");
        assert!(!acl_state(&Absent, &Value(base.clone()), &Absent, false), "a file has no default ACL");
        assert!(acl_state(&Absent, &Absent, &Value(vec![0; 8]), false), "an NFSv4 ACL");
        assert!(acl_state(&Absent, &Absent, &Unreadable, false), "an NFSv4 ACL that cannot be read");

        // the reach test: root's 755 binary with an ACL is in reach, and a
        // directory above a binary with one makes the binary in reach
        let w = who();
        assert!(writable_by(Perm { acl: true, ..b(0, 0, 0o755) }, &w), "root's 755 with an ACL");
        assert!(!writable_by(b(0, 0, 0o755), &w));
        let fs_map = |p: &str| -> Option<(Perm, bool)> {
            match p {
                "/" | "/usr" | "/usr/bin" | "/opt" => Some((b(0, 0, 0o755), true)),
                "/opt/acl" => Some((Perm { acl: true, ..b(0, 0, 0o755) }, true)),
                _ => None,
            }
        };
        assert!(dirs_out_of_reach("/usr/bin/psql", &w, fs_map));
        assert!(!dirs_out_of_reach("/opt/acl/psql", &w, fs_map), "a directory with an ACL above it");
        assert!(!dirs_out_of_reach("/opt/acl/sub/psql", &w, fs_map));
    }

    // P0 triage 2d on a real filesystem: an ACL the kernel stores is read
    // back as one (an access ACL on a file, a default ACL on a directory);
    // a minimal ACL the kernel folds into the mode bits is not. No privilege:
    // the test owns the files. Self-SKIPs where the filesystem keeps no ACLs.
    #[test]
    fn acls_on_a_real_filesystem_are_read() {
        struct Gone(std::path::PathBuf);
        impl Drop for Gone {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let dir = std::env::temp_dir().join(format!("mandu-acl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let _gone = Gone(dir.clone());
        let file = dir.join("bin");
        fs::write(&file, b"#!/bin/sh\n").unwrap();
        let file_s = file.to_str().unwrap().to_string();
        let dir_s = dir.to_str().unwrap().to_string();
        let set = |p: &str, name: &str, v: &[u8]| -> i32 {
            let (cp, cn) = (std::ffi::CString::new(p).unwrap(), std::ffi::CString::new(name).unwrap());
            // SAFETY: valid C strings and a buffer of v.len() bytes.
            if unsafe { libc::setxattr(cp.as_ptr(), cn.as_ptr(), v.as_ptr().cast(), v.len(), 0) } == 0 {
                0
            } else {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            }
        };
        assert!(!acl_beyond_mode(&file_s, true, false), "a fresh file has no ACL");
        assert!(!acl_beyond_mode(&dir_s, false, true), "a fresh directory has none");
        // The entry names the test's own uid: the one sure to be mapped in a
        // user namespace (an unmapped id is EINVAL). Which uid it names does
        // not matter: any named entry puts the file in reach.
        // SAFETY: plain getter.
        let me = unsafe { libc::geteuid() };
        let other = 4242u32;
        let named = acl(&[(0x01, 6, UNDEF), (0x02, 6, me), (0x04, 4, UNDEF), (0x10, 6, UNDEF), (0x20, 4, UNDEF)]);
        match set(&file_s, "system.posix_acl_access", &named) {
            0 => {}
            e if e == libc::EOPNOTSUPP => {
                eprintln!("SKIP: {} keeps no POSIX ACLs", dir.display());
                return;
            }
            e => panic!("setxattr: errno {e}"),
        }
        assert!(acl_beyond_mode(&file_s, true, false), "the named-user entry is read");
        let m = fs::metadata(&file).unwrap();
        let p = perm_of(&file_s, &m);
        assert!(p.acl, "{p:?}");
        // uid 4242, who the mode bits leave out, is in reach through any ACL
        let them = Who { uid: other, groups: vec![other], ns_overflow: None, caps: 0 };
        assert!(!writable_by(Perm { acl: false, ..p }, &them), "the mode bits alone leave it out");
        assert!(writable_by(p, &them), "the ACL puts it in reach");
        // a default ACL on the directory
        let default = acl(&[(0x01, 7, UNDEF), (0x04, 5, UNDEF), (0x20, 5, UNDEF)]);
        assert_eq!(set(&dir_s, "system.posix_acl_default", &default), 0);
        assert!(acl_beyond_mode(&dir_s, false, true), "a default ACL on a directory");
        let (dp, is_dir) = lstat_dir(&dir_s).unwrap();
        assert!(is_dir && dp.acl, "{dp:?}");
        // a minimal access ACL is folded into the mode bits: nothing more
        let other_file = dir.join("plain");
        fs::write(&other_file, b"x").unwrap();
        let other_s = other_file.to_str().unwrap();
        assert_eq!(set(other_s, "system.posix_acl_access", &acl(&[(0x01, 6, UNDEF), (0x04, 4, UNDEF), (0x20, 4, UNDEF)])), 0);
        assert!(!acl_beyond_mode(other_s, true, false), "a minimal ACL is the mode bits");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_binary_is_out_of_reach_only_when_every_directory_above_it_is() {
        let w = who();
        let fs_map = |p: &str| -> Option<(Perm, bool)> {
            match p {
                "/" | "/usr" | "/usr/bin" => Some((b(0, 0, 0o755), true)),
                "/tmp" => Some((b(0, 0, 0o1777), true)),
                "/tmp/x" => Some((b(1000, 1000, 0o755), true)),
                "/home" => Some((b(0, 0, 0o755), true)),
                "/home/u" | "/home/u/ws" | "/home/u/.local" | "/home/u/.local/bin" => Some((b(1000, 1000, 0o755), true)),
                "/opt" => Some((b(0, 0, 0o755), true)),
                "/opt/link" => Some((b(0, 0, 0o777), false)),
                "/srv" => Some((b(0, 0, 0o755), true)),
                "/srv/brew" => Some((b(1001, 1001, 0o755), true)),
                _ => None,
            }
        };
        assert!(dirs_out_of_reach("/usr/bin/psql", &w, fs_map));
        assert!(!dirs_out_of_reach("/tmp/x/psql", &w, fs_map), "the agent's dir");
        assert!(!dirs_out_of_reach("/tmp/psql", &w, fs_map), "a world-writable dir");
        assert!(!dirs_out_of_reach("/home/u/ws/psql", &w, fs_map), "the workspace");
        assert!(!dirs_out_of_reach("/home/u/.local/bin/psql", &w, fs_map), "the user's own bin: the agent can write it");
        assert!(!dirs_out_of_reach("/opt/link/psql", &w, fs_map), "a symlinked component is no directory");
        assert!(dirs_out_of_reach("/srv/brew/psql", &w, fs_map), "another user's tree is out of reach");
        assert!(!dirs_out_of_reach("/nowhere/psql", &w, fs_map), "unknown: not out of reach");
        assert!(!dirs_out_of_reach("/usr/bin/psql (deleted)", &w, fs_map), "a deleted executable");
        assert!(!dirs_out_of_reach("psql", &w, fs_map), "a relative path");
    }


    #[test]
    fn maps_name_the_executable_file_mappings_only() {
        let maps = "\
55d0c0000000-55d0c0002000 r--p 00000000 08:01 131 /usr/bin/cat
55d0c0002000-55d0c0006000 r-xp 00002000 08:01 131 /usr/bin/cat
7f00aa000000-7f00aa028000 r-xp 00028000 08:01 200 /usr/lib/x86_64-linux-gnu/libc.so.6
7f00ab000000-7f00ab001000 r-xp 00001000 00:2a 77 /home/u/ws/my lib/evil.so
7f00ac000000-7f00ac001000 rwxp 00000000 00:00 0
7f00ad000000-7f00ad001000 r-xp 00000000 00:01 9 /memfd:x (deleted)
7ffd00000000-7ffd00002000 r-xp 00000000 00:00 0                          [vdso]
7f00aa028000-7f00aa030000 r--p 00030000 08:01 200 /usr/lib/x86_64-linux-gnu/libc.so.6
";
        assert_eq!(
            exec_mapped_paths(maps),
            vec!["/usr/bin/cat", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/home/u/ws/my lib/evil.so", "/memfd:x (deleted)"],
            "file-backed, executable, deduplicated; a path with spaces kept whole; anonymous and [vdso] skipped"
        );
    }

    #[test]
    fn a_clean_process_has_no_findings_and_a_preloaded_one_names_the_variable_and_the_library() {
        let ctx = IdentityCtx::current();
        if ctx.who.uid == 0 && ctx.who.ns_overflow.is_none() {
            return; // a root agent reaches every file: every mapping would be a finding
        }
        let me = std::process::id() as i32;
        let exe = ctx.exe(me).path;
        assert_eq!(ctx.findings(me, &exe), Some(vec![]), "the test binary maps only system libraries and runs with the launch's environment");
        // a copy of a system library in a directory this uid writes, preloaded into `sleep`
        let Some(lib) = ["/lib/x86_64-linux-gnu/libm.so.6", "/usr/lib/x86_64-linux-gnu/libm.so.6", "/usr/lib64/libm.so.6", "/lib/aarch64-linux-gnu/libm.so.6", "/usr/lib/libm.so.6"]
            .into_iter()
            .find(|p| std::path::Path::new(p).is_file())
        else {
            return; // SKIP: no libm to copy
        };
        let dir = std::env::temp_dir().join(format!("mandu-ri-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("libm-copy.so.6");
        fs::copy(lib, &copy).unwrap();
        let Ok(mut child) = std::process::Command::new("sleep").arg("5").env("LD_PRELOAD", &copy).spawn() else {
            let _ = fs::remove_dir_all(&dir);
            return; // SKIP: no sleep
        };
        let pid = child.id() as i32;
        let mut got = None;
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let exe = ctx.exe(pid).path;
            if exe.ends_with("/sleep") {
                got = ctx.findings(pid, &exe);
                if got.as_ref().is_some_and(|v| v.iter().any(|f| f.starts_with("code:"))) {
                    break;
                }
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&dir);
        let got = got.expect("the child's environment and maps are readable");
        assert!(got.contains(&"LD_PRELOAD".to_string()), "{got:?}");
        assert!(got.iter().any(|f| f == &format!("code:{}", fs::canonicalize(&copy).unwrap_or(copy.clone()).display()) || f.ends_with("libm-copy.so.6")), "{got:?}");
    }

    #[test]
    fn a_live_process_identity_hashes_the_inode_it_runs() {
        let me = std::process::id() as i32;
        let cache = HashCache::default();
        let id = exe_identity(me, &Who::current(), &cache);
        assert!(!id.path.is_empty());
        let h = id.sha256.clone().expect("our own executable is readable");
        assert_eq!(h.len(), 64);
        assert_eq!(exe_identity(me, &Who::current(), &cache).sha256.as_deref(), Some(h.as_str()), "memoized by inode");
        // the test binary lives in the build tree, which this uid writes (as
        // itself, as root, or as root of a namespace that maps its owner)
        assert!(!id.system, "a binary in a tree the agent writes is not out of reach: {}", id.path);
        assert!(opener_env(me, &id.path, &EnvBaseline::from_process()).is_some(), "our own environment is readable");
        assert!(exe_identity(i32::MAX, &Who::current(), &cache).path.is_empty(), "no such process: no identity");
    }

    /// Marker `i` whole, unmasked at run time (the table keeps it masked).
    fn marker(i: usize) -> Vec<u8> {
        RUNTIME_MARKERS[i].1.iter().map(|k| k ^ MARKER_MASK).collect()
    }

    #[test]
    fn runtime_of_finds_each_front_end_anywhere_in_the_bytes_and_nothing_else() {
        for (i, (family, _)) in RUNTIME_MARKERS.iter().enumerate() {
            let mut b = b"\x7fELF\x02\x01\x01 some code".to_vec();
            b.extend_from_slice(&marker(i));
            b.extend_from_slice(b"\0more");
            assert_eq!(runtime_of(&b), Some(*family), "{}", String::from_utf8_lossy(&marker(i)));
            // the marker ending the file, and a marker cut short
            assert_eq!(runtime_of(&marker(i)), Some(*family));
            let cut = marker(i);
            assert_eq!(runtime_of(&cut[..cut.len() - 1]), None, "a prefix is no marker");
        }
        assert_eq!(runtime_of(b""), None);
        // what an embedding program carries is no front end
        assert_eq!(runtime_of(b"\0Py_Initialize\0lua_pcall\0luaL_openlibs\0BASH_VERSION\0"), None);
        // nor what a library or a compiled program shares with an
        // interpreter: LuaJIT's library banner, guile's other entry points,
        // R's embedding API, deno's runtime crate (what `denort` carries),
        // a .NET apphost's own texts
        assert_eq!(
            runtime_of(b"\0LuaJIT 2.1.0\0luaJIT_setmode\0scm_boot_guile\0scm_shell_usage\0Rf_initEmbeddedR\0Rf_mainloop\0deno_runtime\0Could not find denort\0hostfxr_main_startupinfo\0DOTNET_ROOT\0app.dll\0"),
            None
        );
        // the table never holds a marker whole, so the binary carrying it is no interpreter
        let me = fs::read("/proc/self/exe").expect("our own executable is readable");
        assert_eq!(runtime_of(&me), None, "the guard's own code (this test binary) carries no marker whole");
    }

    #[test]
    fn a_shell_of_the_ksh_line_is_named_for_itself_not_the_shared_set_o_header() {
        // ksh93, mksh and posh print the ash family's `set -o` header too;
        // the table names each for itself (the header's entry comes last).
        let sh = RUNTIME_MARKERS.iter().position(|(f, _)| *f == "sh").expect("the set -o header");
        assert_eq!(sh, RUNTIME_MARKERS.len() - 1, "the shared header is the last entry");
        let header = marker(sh);
        for family in ["ksh", "mksh", "posh"] {
            let i = RUNTIME_MARKERS.iter().position(|(f, _)| *f == family).unwrap();
            let mut b = header.clone();
            b.extend_from_slice(b"\0");
            b.extend_from_slice(&marker(i));
            assert_eq!(runtime_of(&b), Some(family));
        }
        assert_eq!(runtime_of(&header), Some("sh"), "dash alone is the ash family");
    }

    #[test]
    fn installed_interpreters_are_known_by_content_and_leaf_programs_are_not() {
        // Each found on this host (SKIP per program where absent), resolved
        // through its links.
        let want = [
            ("/usr/bin/python3", "python"), ("/usr/bin/perl", "perl"), ("/usr/bin/ruby", "ruby"), ("/usr/bin/node", "node"),
            ("/usr/bin/lua", "lua"), ("/usr/bin/tclsh", "tcl"), ("/usr/bin/php", "php"), ("/usr/bin/java", "java"),
            ("/usr/bin/busybox", "busybox"), ("/bin/bash", "bash"), ("/usr/bin/zsh", "zsh"), ("/bin/dash", "sh"),
            // the families !506 left out (2026-10-04), where installed
            ("/usr/bin/ksh93", "ksh"), ("/usr/bin/ksh2020", "ksh"), ("/usr/bin/mksh", "mksh"), ("/usr/bin/lksh", "mksh"),
            ("/usr/bin/posh", "posh"), ("/usr/bin/yash", "yash"), ("/usr/bin/tcsh", "tcsh"), ("/usr/bin/bsd-csh", "csh"),
            ("/usr/bin/fish", "fish"), ("/usr/bin/toybox", "toybox"), ("/usr/bin/luajit", "luajit"), ("/usr/bin/guile", "guile"),
            ("/usr/bin/guile-3.0", "guile"), ("/usr/bin/racket", "racket"), ("/usr/lib/R/bin/exec/R", "R"), ("/usr/bin/r", "R"),
            ("/usr/bin/bun", "bun"), ("/usr/local/bin/bun", "bun"),
            ("/usr/bin/deno", "deno"), ("/usr/local/bin/deno", "deno"), ("/opt/microsoft/powershell/7/pwsh", "pwsh"),
        ];
        let mut seen = 0;
        for (p, family) in want {
            let Ok(real) = fs::canonicalize(p) else { continue };
            let Ok(bytes) = fs::read(&real) else { continue };
            if !bytes.starts_with(b"\x7fELF") {
                continue; // a wrapper script (an alternatives shim): not this test's
            }
            seen += 1;
            assert_eq!(runtime_of(&bytes), Some(family), "{}", real.display());
        }
        assert!(seen > 0 || !std::path::Path::new("/bin/bash").exists(), "no interpreter found to check");
        for p in [
            "/usr/bin/ssh", "/usr/bin/git", "/usr/bin/curl", "/usr/bin/psql", "/usr/bin/ssh-add", "/usr/bin/ls", "/usr/bin/tar",
            "/usr/bin/gpg", "/usr/bin/openssl", "/usr/bin/jq", "/usr/bin/Rscript",
        ] {
            let Ok(bytes) = fs::read(p) else { continue };
            assert_eq!(runtime_of(&bytes), None, "{p} is a leaf program");
        }
    }

    #[test]
    fn a_renamed_python_build_no_hash_knows_is_a_python_by_its_content() {
        // A pyenv- or self-built python under another name: here the host's
        // python with a byte appended (it still runs; its hash is no
        // installed program's), copied as `mdu-pycopy`.
        let Ok(real) = fs::canonicalize("/usr/bin/python3") else { return }; // SKIP: no python3
        let Ok(mut bytes) = fs::read(&real) else { return };
        if !bytes.starts_with(b"\x7fELF") {
            return;
        }
        bytes.push(0);
        let dir = std::env::temp_dir().join(format!("mandu-rt-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("mdu-pycopy");
        fs::write(&copy, &bytes).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o755)).unwrap();
        let Ok(mut child) = std::process::Command::new(&copy).args(["-c", "import time; time.sleep(5)"]).spawn() else {
            let _ = fs::remove_dir_all(&dir);
            return; // SKIP: the copy does not run here
        };
        let ctx = IdentityCtx::current();
        let pid = child.id() as i32;
        let mut got = None;
        let mut sha = None;
        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let id = ctx.exe(pid);
            if id.path.ends_with("/mdu-pycopy") {
                sha = id.sha256;
                got = ctx.findings(pid, &id.path);
                break;
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&dir);
        let got = got.expect("the copy's facts are readable");
        assert!(got.contains(&"runs:python".to_string()), "{got:?}");
        assert_ne!(sha, sha256_file(real.to_str().unwrap()), "not byte-identical to the installed python");
        // the installed python itself, by its own name, gets no such finding:
        // its name already says it runs code (the script pin is its way in)
        assert!(crate::secret_open::runs_code(real.to_str().unwrap()));
    }

    /// `s` reversed: a marker spelled backwards in the test's source, so this
    /// test binary never carries one whole (see the self-check above).
    fn unrev(s: &str) -> Vec<u8> {
        s.bytes().rev().collect()
    }

    #[test]
    fn the_interpreters_known_by_name_only_are_known_by_content() {
        // P0 item 14 (2026-10-07): the families !533 left by name only, each
        // marker checked against the real binaries (plan 13 D8 (13)).
        let cases = [
            ("llehs/gkp/hs.vle.crs", "elvish"),            // elvish 0.18 to 0.21 (src.elv.sh/pkg/shell)
            ("llehs/gkp/hsivle/sevle/moc.buhtig", "elvish"), // elvish 0.14 (github.com/elves/elvish/pkg/shell)
            ("lper::ilc_un", "nushell"),                    // nu 0.60 to 0.116 (nu_cli::repl)
            ("/crs/ilc-un/setarc", "nushell"),              // crates/nu-cli/src/
            ("]noitacilppa-ot-htap[ tentod :egasU", "dotnet"), // the .NET muxer, 3.1 and 8
            (">srpxe< etaulavE : >srpxe< lave--", "racket"), // Racket BC's command line (7.9)
            ("lper edom ymonoce ot kcab gnillaf", "julia"),  // julia 1.0 to 1.5's own front end
            ("v HSK DP)#(@", "pdksh"),                      // OpenBSD ksh, oksh, loksh, pdksh
        ];
        for (rev, family) in cases {
            let mut b = b"\x7fELF\x02\x01\x01 code ".to_vec();
            b.extend_from_slice(&unrev(rev));
            b.extend_from_slice(b"\0more");
            assert_eq!(runtime_of(&b), Some(family), "{}", String::from_utf8_lossy(&unrev(rev)));
        }
        // oksh prints the ash family's `set -o` header too: it is named for itself
        let mut b = marker(RUNTIME_MARKERS.len() - 1);
        b.extend_from_slice(&unrev("v HSK DP)#(@"));
        assert_eq!(runtime_of(&b), Some("pdksh"));
        // a .NET apphost (an app's own launcher) is not the muxer
        assert_eq!(runtime_of(b"\0hostfxr_main_startupinfo\0DOTNET_ROOT\0app.dll\0Usage: dotnet [options]\0"), None);
    }

    #[test]
    fn a_printers_or_launchers_package_is_known_by_content_and_a_checksum_tool_is_not() {
        // P0 item 14: a GNU printer or launcher that is no byte-identical
        // copy of an installed one (another version, a static download) is
        // known by its package's own text (plan 13 D8 (13)).
        let with = |parts: &[&str]| -> Vec<u8> {
            let mut b = b"\x7fELF\x02\x01\x01 code\0".to_vec();
            for p in parts {
                b.extend_from_slice(&unrev(p));
                b.push(0);
            }
            b
        };
        let coreutils = "slitueroc UNG";
        assert_eq!(content_of(&with(&[coreutils])).package, Some("coreutils"));
        assert_eq!(content_of(&with(&["slitudnif UNG"])).package, Some("findutils"));
        assert_eq!(content_of(&with(&[".2 xunil-litu"])).package, Some("util-linux"));
        assert_eq!(content_of(&with(&["slituffid UNG"])).package, Some("diffutils"));
        assert_eq!(content_of(&with(&["des UNG"])).package, Some("sed"));
        assert_eq!(content_of(&with(&["ELIF hcae ni SNRETTAP rof hcraeS"])).package, Some("grep"));
        assert_eq!(content_of(&with(&["evihcra ksid ro epat elgnis a otni rehtegot selif ynam sevas"])).package, Some("tar"));
        // coreutils' checksum tools (sha256sum, md5sum, b2sum: the leaf
        // readers the tests name) are no printer, unless the binary is the
        // multi-call one, which is every coreutils program
        let digest = ".smuskcehc )tib-d%( s% kcehc ro tnirP";
        assert_eq!(content_of(&with(&[coreutils, digest])).package, None);
        assert_eq!(content_of(&with(&[coreutils, digest, "gorp-slitueroc--"])).package, Some("coreutils"));
        // an interpreter's marker wins: busybox carries GNU sed's name
        let c = content_of(&with(&["des UNG", "v xoBysuB"]));
        assert_eq!((c.runtime, c.package), (Some("busybox"), None));
        assert_eq!(content_of(b"\0GNU\0coreutils\0").package, None);
    }

    #[test]
    fn installed_printers_and_launchers_are_known_by_their_package() {
        // Each found on this host (SKIP per program where absent), only
        // when it is GNU's build (on a uutils host GNU's coreutils carry the
        // `gnu` prefix).
        let want = [
            ("/usr/bin/gnucat", Some("coreutils")), ("/usr/bin/gnuenv", Some("coreutils")), ("/usr/bin/gnusleep", Some("coreutils")),
            ("/usr/bin/xargs", Some("findutils")), ("/usr/bin/find", Some("findutils")), ("/usr/bin/setsid", Some("util-linux")),
            ("/usr/bin/flock", Some("util-linux")), ("/usr/bin/diff", Some("diffutils")), ("/usr/bin/gnusha256sum", None),
            ("/usr/bin/ssh", None), ("/usr/bin/ssh-add", None), ("/usr/bin/git", None), ("/usr/bin/curl", None), ("/usr/bin/psql", None),
        ];
        let mut seen = 0;
        for (p, package) in want {
            let Ok(real) = fs::canonicalize(p) else { continue };
            if real.starts_with("/usr/lib/cargo") {
                continue; // uutils: a printer by its path
            }
            let Ok(bytes) = fs::read(&real) else { continue };
            if !bytes.starts_with(b"\x7fELF") {
                continue;
            }
            seen += 1;
            assert_eq!(content_of(&bytes).package, package, "{}", real.display());
        }
        assert!(seen > 0 || !std::path::Path::new("/usr/bin/xargs").exists(), "no program found to check");
    }

    #[test]
    fn a_renamed_gnu_program_no_hash_knows_is_its_package() {
        // A GNU coreutils program, not byte-identical to an installed one (a
        // byte appended), under a name no list knows: `pkg:coreutils`.
        let Some(real) = ["/usr/bin/gnusleep", "/usr/bin/sleep", "/bin/sleep"]
            .into_iter()
            .filter_map(|p| fs::canonicalize(p).ok())
            .find(|r| !r.starts_with("/usr/lib/cargo") && fs::read(r).is_ok_and(|b| b.starts_with(b"\x7fELF") && content_of(&b).package == Some("coreutils")))
        else {
            return; // SKIP: no GNU sleep
        };
        let mut bytes = fs::read(&real).unwrap();
        bytes.push(0);
        let dir = std::env::temp_dir().join(format!("mandu-pkg-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("mdu-waiter");
        fs::write(&copy, &bytes).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o755)).unwrap();
        let Ok(mut child) = std::process::Command::new(&copy).arg("5").spawn() else {
            let _ = fs::remove_dir_all(&dir);
            return; // SKIP: the copy does not run here
        };
        let ctx = IdentityCtx::current();
        let pid = child.id() as i32;
        let mut got = None;
        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let id = ctx.exe(pid);
            if id.path.ends_with("/mdu-waiter") {
                got = ctx.findings(pid, &id.path);
                break;
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&dir);
        let got = got.expect("the copy's facts are readable");
        assert!(got.contains(&"pkg:coreutils".to_string()), "{got:?}");
        assert!(!got.iter().any(|f| f.starts_with("runs:")), "{got:?}");
    }

    #[test]
    fn an_ancestor_is_trusted_only_out_of_reach_clean_and_not_disguised() {
        // P0 item 14: a `from:` parent is read for its content too, so a
        // disguised interpreter or a printer's package under the parent's
        // name is not that parent (plan 13 D8 (13)).
        assert!(ancestor_trusted(true, Some(&[])));
        assert!(!ancestor_trusted(false, Some(&[])), "in the agent's reach");
        assert!(!ancestor_trusted(true, None), "its facts unread");
        assert!(!ancestor_trusted(true, Some(&["runs:python".to_string()])), "an interpreter by its content");
        assert!(!ancestor_trusted(true, Some(&["pkg:coreutils".to_string()])), "a printer's or a launcher's package");
        assert!(!ancestor_trusted(true, Some(&["LD_PRELOAD".to_string()])));
    }

    #[test]
    fn a_live_readers_ancestors_end_below_the_guard() {
        // This test process stands for the guard: `sh -c 'sleep 30; :'` is
        // its child (the session's root), and sleep the reader. sh is the
        // reader's one session ancestor; the test's own parents (cargo, the
        // shell that ran it) are none, whatever they are.
        let ctx = IdentityCtx::current();
        let me = std::process::id() as i32;
        let mut sh = std::process::Command::new("/bin/sh").args(["-c", "sleep 30; :"]).spawn().expect("spawn sh");
        let shp = sh.id() as i32;
        let mut reader = None;
        for _ in 0..250 {
            let kids = fs::read_to_string(format!("/proc/{shp}/task/{shp}/children")).unwrap_or_default();
            if let Some(k) = kids.split_whitespace().next().and_then(|k| k.parse::<i32>().ok()) {
                reader = Some(k);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let got = reader.map(|r| (ctx.ancestors(r, 16), ctx.ancestors_below(r, me, 16), ctx.ancestors_below(r, i32::MAX - 1, 16), ctx.ancestors(shp, 16)));
        let sh_exe = fs::read_link(format!("/proc/{shp}/exe")).ok().and_then(|p| p.to_str().map(String::from));
        let _ = sh.kill();
        let _ = sh.wait();
        let Some((default_bound, below_me, unanchored, of_root)) = got else {
            eprintln!("SKIP: no /proc/<pid>/task/<pid>/children (CONFIG_PROC_CHILDREN) to find the reader");
            return;
        };
        let names = |v: &[(String, bool)]| v.iter().map(|(e, _)| e.clone()).collect::<Vec<_>>();
        assert_eq!(names(&below_me), vec![sh_exe.clone().expect("sh's exe")], "only sh, below the guard");
        assert_eq!(names(&default_bound), names(&below_me), "the default bound is this process");
        assert!(unanchored.is_empty(), "a chain that never meets the guard gives no parent: {unanchored:?}");
        assert!(of_root.is_empty(), "the guard's own child has none: {of_root:?}");
    }

    #[test]
    fn the_dotnet_hooks_are_loader_variables_of_every_program() {
        // A .NET program's apphost takes any name; these make it load
        // managed code (not mapped executable, so the maps check misses it).
        let launch = EnvBaseline::default();
        for v in ["DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS", "DOTNET_ROOT", "CORECLR_PROFILER_PATH", "CORECLR_ENABLE_PROFILING"] {
            assert_eq!(untrusted_env("/opt/tool/mytool", &env(&[(v, "/ws/x")]), &launch), vec![v.to_string()], "{v}");
        }
        let launch = EnvBaseline::from_vars(env(&[("DOTNET_ROOT", "/usr/lib/dotnet")]));
        assert!(untrusted_env("/opt/tool/mytool", &env(&[("DOTNET_ROOT", "/usr/lib/dotnet")]), &launch).is_empty(), "the launch's own value");
    }

    #[test]
    fn runtime_of_searches_by_window_and_misses_no_marker_across_one_nor_the_tables_order() {
        let fam = |f: &str| RUNTIME_MARKERS.iter().position(|(g, _)| *g == f).unwrap();
        // a marker across each window boundary, at every split
        let m = marker(fam("fish"));
        for cut in 1..m.len() {
            let mut b = vec![b'x'; 3 * SCAN_WINDOW];
            let at = 2 * SCAN_WINDOW - cut;
            b[at..at + m.len()].copy_from_slice(&m);
            assert_eq!(runtime_of(&b), Some("fish"), "split {cut}");
        }
        // the first in the table's order wins, wherever each lies: a later
        // entry in the first window, an earlier one in the last
        let (early, late) = (fam("python"), fam("pwsh"));
        assert!(early < late);
        let mut b = vec![0u8; 4 * SCAN_WINDOW];
        b[10..10 + marker(late).len()].copy_from_slice(&marker(late));
        let at = 4 * SCAN_WINDOW - marker(early).len();
        b[at..].copy_from_slice(&marker(early));
        assert_eq!(runtime_of(&b), Some("python"));
        // and the shells' shared header, last in the table, in an early
        // window loses to a ksh marker in a later one
        let mut b = vec![0u8; 3 * SCAN_WINDOW];
        let h = marker(RUNTIME_MARKERS.len() - 1);
        b[..h.len()].copy_from_slice(&h);
        let k = marker(fam("ksh"));
        b[2 * SCAN_WINDOW + 7..2 * SCAN_WINDOW + 7 + k.len()].copy_from_slice(&k);
        assert_eq!(runtime_of(&b), Some("ksh"));
    }
}
