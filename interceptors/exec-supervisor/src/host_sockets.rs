//! host_sockets — find the host's Unix sockets the AgentShell box must not
//! reach (exec-routing.md §4.2).
//!
//! PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
//!
//! The box's base is the whole host filesystem, read-only. Read-only does not
//! stop `connect(2)` on a Unix socket, and `--unshare-net` cuts only the
//! ABSTRACT socket namespace (it is per network namespace), not pathname
//! sockets. So a boxed command could reach `/run/docker.sock` (start a
//! privileged container: a full escape), the session bus (`systemd-run
//! --user`), the ssh-agent (sign as the user), a tmux server (`send-keys` into
//! another pane) and so on. The box closes them by mount: `/dev/null` over
//! each socket the scan below finds (`sandbox::socket_box_hide`).
//!
//! This is a scan of the places sockets live, not an allow-list: a socket
//! outside the roots (the workspace, an arbitrary directory) stays visible
//! unless an environment variable names it (`sandbox::socket_paths_from_env`).
//! The roots and depths are in `default_roots`.
//!
//! Filesystem I/O with std only (no libc), so the default unprivileged build
//! compiles and unit-tests it on real temporary directories. The kernel
//! backend calls it PARENT side, before the fork.

use crate::sandbox::SocketScan;
use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

/// One place to look, and how many directory levels below it to read
/// (`max_depth = 1` lists the root's own entries only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRoot {
    pub path: String,
    pub max_depth: usize,
}

impl ScanRoot {
    pub fn new(path: impl Into<String>, max_depth: usize) -> Self {
        ScanRoot { path: path.into(), max_depth }
    }
}

/// Directory entries the whole scan may read before it stops (`truncated`).
/// `/run` on a busy desktop is a few thousand; this leaves room for an order
/// of magnitude more.
pub const SCAN_BUDGET: usize = 60_000;

/// Where host sockets live OUTSIDE `/run` (the box replaces `/run` wholesale:
/// `sandbox::run_box_hide`). System: `/var/run` when it is not the usual
/// symlink to `/run`, `/var/lib/*` (`lxd`, `incus`), `/var/snap/*/common/*`
/// (snap `lxd`, `microk8s`). The user's `$XDG_RUNTIME_DIR` when it is not
/// under `/run` or `/tmp`. In `$HOME`: its own entries
/// (`~/.bitwarden-ssh-agent.sock`) and the dot-directories that hold agent or
/// VM sockets (ssh ControlMaster sockets, gpg-agent, Docker Desktop, Colima,
/// Lima, Rancher Desktop, 1Password, podman machine).
///
/// `/tmp` is a root only when the box shows the REAL `/tmp` (`real_tmp`:
/// the integrity-OFF box, `sandbox::shares_real_tmp`, exec-routing.md §7.2
/// "The agent's own /tmp"), and then only for its OWN entries
/// ([`TMP_SOCKET_DEPTH`]: a database's `/tmp/.s.PGSQL.5432`, a
/// `/tmp/mysql.sock`); the service directories in it (tmux, X11, ssh-agent)
/// are hidden whole instead ([`tmp_service_dirs`]), and a `$XDG_RUNTIME_DIR`
/// under it is read as anywhere else. Not deeper: a mask under the real
/// `/tmp` is a bind onto the HOST tree, so a socket that vanished between the
/// scan and the box's setup would be re-created by bwrap as an empty file in
/// the real `/tmp` (a stray that a server restarting there then fails to
/// bind over). Short-lived sockets live in subdirectories (a program's own
/// temp dir); top-level sockets and service directories are long-lived. A
/// socket deeper down stays visible in-box, where the box's connect
/// allow-list (exec-routing.md §4.2, `socket_supervision`) still refuses
/// every connect the guard or the box does not allow. Otherwise the box's
/// fresh tmpfs already hides all of `/tmp`. `/tmp` comes LAST, so a large
/// `/tmp` can only run out the entry budget after every other root was read.
pub fn default_roots(home: Option<&str>, runtime_dir: Option<&str>, real_tmp: bool) -> Vec<ScanRoot> {
    let mut roots = vec![
        ScanRoot::new("/var/run", 8),
        ScanRoot::new("/var/lib", 2),
        ScanRoot::new("/var/snap", 4),
    ];
    if let Some(rt) = runtime_dir.map(|r| r.trim_end_matches('/')).filter(|r| r.starts_with('/') && r.len() > 1) {
        let under_tmp = rt == "/tmp" || rt.starts_with("/tmp/");
        if !(rt == "/run" || rt.starts_with("/run/") || rt == "/tmp" || (under_tmp && !real_tmp)) {
            roots.push(ScanRoot::new(rt, 8));
        }
    }
    if let Some(h) = home.map(|h| h.trim_end_matches('/')).filter(|h| h.starts_with('/') && h.len() > 1) {
        roots.push(ScanRoot::new(h, 1));
        for (rel, depth) in HOME_SOCKET_DIRS {
            roots.push(ScanRoot::new(format!("{h}/{rel}"), *depth));
        }
    }
    if real_tmp {
        roots.push(ScanRoot::new("/tmp", TMP_SOCKET_DEPTH));
    }
    roots
}

/// How deep the real `/tmp` is read for sockets (`default_roots`): its own
/// entries only (see there for why not deeper).
pub const TMP_SOCKET_DEPTH: usize = 1;

/// Is a directory directly in `/tmp` named `name` a host service's socket
/// directory, hidden whole (an empty tmpfs) in the box that shows the real
/// `/tmp`? The X11 family (`.X11-unix`, `.ICE-unix`, `.XIM-unix`,
/// `.font-unix`, `.Test-unix`), a tmux server's `tmux-<uid>`, an
/// ssh-agent's `ssh-<random>`, GNU screen's `screens`/`.screen`, and
/// `pulse-<random>`. Long-lived directories that hold the sockets which run
/// code or type for their caller. PURE.
pub fn is_tmp_service_dir(name: &str) -> bool {
    const EXACT: &[&str] = &[".X11-unix", ".ICE-unix", ".XIM-unix", ".font-unix", ".Test-unix", "screens", ".screen"];
    if EXACT.contains(&name) {
        return true;
    }
    let digits_after = |p: &str| name.strip_prefix(p).is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()));
    let token_after = |p: &str| name.strip_prefix(p).is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_alphanumeric()));
    digits_after("tmux-") || token_after("ssh-") || token_after("pulse-")
}

/// The service directories directly in `dir` (the real `/tmp`) to hide whole
/// ([`is_tmp_service_dir`]): real directories only, never a symlink.
pub fn tmp_service_dirs(dir: &str) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut out: Vec<String> = rd
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .filter(|n| is_tmp_service_dir(n))
        .map(|n| if dir == "/" { format!("/{n}") } else { format!("{dir}/{n}") })
        .collect();
    out.sort();
    out
}

/// `$HOME`-relative directories that hold sockets, with the depth to read.
pub const HOME_SOCKET_DIRS: &[(&str, usize)] = &[
    (".ssh", 3),                     // ControlMaster sockets (a live remote shell)
    (".gnupg", 2),                   // gpg-agent when there is no runtime dir
    (".docker", 4),                  // Docker Desktop: ~/.docker/{run,desktop}/docker.sock
    (".colima", 3),                  // Colima's docker.sock
    (".lima", 3),                    // Lima VMs' sock/ dirs
    (".rd", 2),                      // Rancher Desktop
    (".1password", 1),               // 1Password's ssh agent.sock
    (".local/share/containers/podman", 4), // podman machine (not storage/)
];

/// Filesystem types the scan descends into when a directory is a mount point.
/// Anything else met at a mount boundary (FUSE such as gvfs or the document
/// portal, NFS/CIFS/9p, pseudo filesystems) is skipped: slow or hanging reads,
/// and not where host daemons put their sockets.
const LOCAL_FS: &[&str] = &["tmpfs", "ramfs", "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "bcachefs", "overlay", "jfs", "reiserfs"];

/// `/proc/self/mountinfo` → mount point → filesystem type. PURE parse (the
/// mount point is octal-unescaped: `\040` is a space).
pub fn parse_mountinfo(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let Some((pre, post)) = line.split_once(" - ") else { continue };
        let mut pre_f = pre.split(' ');
        let Some(mp) = pre_f.nth(4) else { continue };
        let Some(fstype) = post.split(' ').next() else { continue };
        out.insert(unescape_octal(mp), fstype.to_string());
    }
    out
}

fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Scan `roots` for Unix sockets, then add the canonical target of each
/// `named` path that is a socket (the environment's pointers). A root that is
/// a symlink (`/var/run` → `/run`) or missing is skipped. Symlinks inside the
/// tree are not followed (the entry's own type, from `readdir`). A directory
/// that is a mount point of a non-local filesystem (`LOCAL_FS`, looked up in
/// `mounts`) is skipped without a stat; every other directory is descended.
/// A directory `read_dir` refuses with EACCES is reported as opaque when we
/// can still SEARCH it (`searchable`): only then can a caller who knows a name
/// inside reach it. One we cannot search hides its contents from us already.
pub fn scan(roots: &[ScanRoot], named: &[String], mounts: &HashMap<String, String>, budget: usize) -> SocketScan {
    let mut out = SocketScan::default();
    let mut left = budget;
    let me = std::fs::metadata("/proc/self").map(|m| m.uid()).ok();
    for root in roots {
        let Ok(meta) = std::fs::symlink_metadata(&root.path) else { continue };
        if !meta.is_dir() || root.max_depth == 0 {
            continue;
        }
        // (path, levels already below the root)
        let mut stack: Vec<(String, usize)> = vec![(root.path.clone(), 0)];
        while let Some((dir, level)) = stack.pop() {
            let rd = match std::fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    if std::fs::metadata(&dir).map(|m| searchable(m.uid(), m.mode(), me)).unwrap_or(true) {
                        out.opaque_dirs.push(dir);
                    }
                    continue;
                }
                Err(_) => continue,
            };
            for entry in rd.flatten() {
                if left == 0 {
                    out.truncated = true;
                    break;
                }
                left -= 1;
                let Ok(ft) = entry.file_type() else { continue };
                let Some(name) = entry.file_name().to_str().map(String::from) else { continue };
                let path = if dir == "/" { format!("/{name}") } else { format!("{dir}/{name}") };
                if ft.is_socket() || ft.is_fifo() {
                    out.sockets.push(path);
                } else if ft.is_dir() && level + 1 < root.max_depth {
                    // A non-local mount is skipped BEFORE any stat of it (a
                    // stuck FUSE daemon would block the stat itself).
                    if mounts.get(&path).is_some_and(|fstype| !LOCAL_FS.contains(&fstype.as_str())) {
                        continue;
                    }
                    stack.push((path, level + 1));
                }
            }
            if out.truncated {
                break;
            }
        }
        if out.truncated {
            break;
        }
    }
    for n in named {
        let Ok(canon) = std::fs::canonicalize(n) else { continue };
        let Ok(m) = std::fs::metadata(&canon) else { continue };
        if m.file_type().is_socket() {
            if let Some(c) = canon.to_str() {
                if !out.sockets.iter().any(|s| s == c) {
                    out.sockets.push(c.to_string());
                }
            }
        }
    }
    out
}

/// Could the process with uid `me` search (x) a directory with this owner and
/// mode? The group bit counts as yes (group membership is not looked up, so
/// the answer errs toward hiding); an unknown `me` is yes.
pub fn searchable(owner: u32, mode: u32, me: Option<u32>) -> bool {
    match me {
        Some(uid) if uid == owner => mode & 0o100 != 0,
        Some(_) => mode & 0o011 != 0,
        None => true,
    }
}

/// The production scan: `default_roots` from `$HOME` / `$XDG_RUNTIME_DIR` (and
/// `/tmp` when the box shows the real one, `real_tmp`), the sockets the
/// environment names, `/proc/self/mountinfo` for the mount boundaries,
/// `SCAN_BUDGET`.
pub fn scan_host(get_env: impl Fn(&str) -> Option<String>, real_tmp: bool) -> SocketScan {
    let roots = default_roots(get_env("HOME").as_deref(), get_env("XDG_RUNTIME_DIR").as_deref(), real_tmp);
    let named = crate::sandbox::socket_paths_from_env(&get_env);
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").map(|t| parse_mountinfo(&t)).unwrap_or_default();
    let mut out = scan(&roots, &named, &mounts, SCAN_BUDGET);
    if real_tmp {
        out.opaque_dirs.extend(tmp_service_dirs("/tmp"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("mandu-hs-{tag}-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn s(p: &std::path::Path) -> String {
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn finds_sockets_at_every_level_within_the_depth() {
        let base = tmp("depth");
        std::fs::create_dir_all(base.join("a/b/c")).unwrap();
        let _l0 = UnixListener::bind(base.join("top.sock")).unwrap();
        let _l1 = UnixListener::bind(base.join("a/one.sock")).unwrap();
        let _l3 = UnixListener::bind(base.join("a/b/c/deep.sock")).unwrap();
        std::fs::write(base.join("a/plain"), "x").unwrap();
        let r = scan(&[ScanRoot::new(s(&base), 2)], &[], &HashMap::new(), 1000);
        assert!(r.sockets.contains(&s(&base.join("top.sock"))));
        assert!(r.sockets.contains(&s(&base.join("a/one.sock"))));
        assert!(!r.sockets.iter().any(|p| p.ends_with("deep.sock")), "past max_depth: {r:?}");
        assert!(!r.sockets.iter().any(|p| p.ends_with("plain")));
        let deep = scan(&[ScanRoot::new(s(&base), 4)], &[], &HashMap::new(), 1000);
        assert!(deep.sockets.contains(&s(&base.join("a/b/c/deep.sock"))));
        assert!(!deep.truncated);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn symlinks_are_not_followed_and_a_symlinked_root_is_skipped() {
        let base = tmp("links");
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let _l = UnixListener::bind(real.join("x.sock")).unwrap();
        std::os::unix::fs::symlink(&real, base.join("alias")).unwrap();
        std::os::unix::fs::symlink(real.join("x.sock"), base.join("link.sock")).unwrap();
        let r = scan(&[ScanRoot::new(s(&base.join("alias")), 3)], &[], &HashMap::new(), 1000);
        assert!(r.sockets.is_empty(), "a symlinked root (the /var/run → /run case) is skipped: {r:?}");
        let r = scan(&[ScanRoot::new(s(&base), 3)], &[], &HashMap::new(), 1000);
        assert_eq!(r.sockets, vec![s(&real.join("x.sock"))], "the real socket once, never via a link");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_named_socket_is_added_by_its_canonical_path() {
        let base = tmp("named");
        let _l = UnixListener::bind(base.join("agent.sock")).unwrap();
        std::os::unix::fs::symlink(base.join("agent.sock"), base.join("via-link")).unwrap();
        std::fs::write(base.join("not-a-socket"), "").unwrap();
        let named = vec![s(&base.join("via-link")), s(&base.join("not-a-socket")), s(&base.join("gone"))];
        let r = scan(&[], &named, &HashMap::new(), 1000);
        let canon = s(&std::fs::canonicalize(base.join("agent.sock")).unwrap());
        assert_eq!(r.sockets, vec![canon]);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_unlistable_directory_is_opaque() {
        let base = tmp("opaque");
        let locked = base.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o111)).unwrap();
        // Root reads everything; the opaque leg is only observable unprivileged.
        let listable = std::fs::read_dir(&locked).is_ok();
        let r = scan(&[ScanRoot::new(s(&base), 3)], &[], &HashMap::new(), 1000);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        if listable {
            eprintln!("SKIP: running as a user that can list a 0111 directory");
        } else {
            assert_eq!(r.opaque_dirs, vec![s(&locked)]);
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn only_a_searchable_unlistable_dir_is_opaque() {
        assert!(searchable(0, 0o711, Some(1000)), "others may search");
        assert!(searchable(0, 0o710, Some(1000)), "a group we may be in: hide");
        assert!(!searchable(0, 0o700, Some(1000)), "root's private dir: nothing reachable, nothing to hide");
        assert!(searchable(1000, 0o300, Some(1000)), "our own dir, x without r");
        assert!(!searchable(1000, 0o600, Some(1000)));
        assert!(searchable(0, 0o700, None), "unknown uid: hide");
    }

    #[test]
    fn the_budget_truncates() {
        let base = tmp("budget");
        for i in 0..20 {
            std::fs::write(base.join(format!("f{i}")), "").unwrap();
        }
        let r = scan(&[ScanRoot::new(s(&base), 1)], &[], &HashMap::new(), 5);
        assert!(r.truncated);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn mountinfo_parses_and_unescapes() {
        let t = "36 35 98:0 /mnt1 /mnt/with\\040space rw,noatime master:1 - ext3 /dev/root rw\n\
                 40 25 0:35 / /run/user/1000/gvfs rw,nosuid shared:1 - fuse.gvfsd-fuse gvfsd-fuse rw\n\
                 41 25 0:36 / /run/user/1000 rw,nosuid - tmpfs tmpfs rw\n";
        let m = parse_mountinfo(t);
        assert_eq!(m.get("/mnt/with space").map(String::as_str), Some("ext3"));
        assert_eq!(m.get("/run/user/1000/gvfs").map(String::as_str), Some("fuse.gvfsd-fuse"));
        assert_eq!(m.get("/run/user/1000").map(String::as_str), Some("tmpfs"));
    }

    #[test]
    fn default_roots_cover_run_var_home_and_an_outside_runtime_dir() {
        let r = default_roots(Some("/home/u/"), Some("/run/user/1000"), false);
        let paths: Vec<&str> = r.iter().map(|x| x.path.as_str()).collect();
        for want in ["/var/run", "/var/lib", "/var/snap", "/home/u", "/home/u/.ssh", "/home/u/.docker"] {
            assert!(paths.contains(&want), "{want} in {paths:?}");
        }
        assert!(!paths.iter().any(|p| *p == "/run" || p.starts_with("/run/")), "the box replaces /run wholesale");
        assert_eq!(r.iter().find(|x| x.path == "/home/u").unwrap().max_depth, 1, "HOME itself: its own entries only");
        let odd = default_roots(None, Some("/srv/rt"), false);
        assert!(odd.iter().any(|x| x.path == "/srv/rt"));
        assert!(!default_roots(None, Some("/tmp/rt"), false).iter().any(|x| x.path == "/tmp/rt"), "the box's scratch hides /tmp");
        assert!(!paths.iter().any(|p| *p == "/tmp" || p.starts_with("/tmp/")), "a fresh /tmp: not scanned");
        assert!(!default_roots(Some("relative"), None, false).iter().any(|x| x.path.starts_with("relative")));
    }

    #[test]
    fn the_real_tmp_is_scanned_last_and_a_runtime_dir_under_it_too() {
        // exec-routing.md §7.2 "The agent's own /tmp": the integrity-OFF box
        // shows the real /tmp, so its sockets (tmux, X11, ssh-agent) are masked.
        let r = default_roots(Some("/home/u"), Some("/tmp/rt"), true);
        let last = r.last().unwrap();
        assert_eq!((last.path.as_str(), last.max_depth), ("/tmp", TMP_SOCKET_DEPTH), "/tmp last: it cannot starve the other roots");
        assert!(r.iter().any(|x| x.path == "/tmp/rt" && x.max_depth == 8), "a runtime dir under the real /tmp is read in full");
        assert!(!default_roots(None, Some("/tmp"), true).iter().any(|x| x.path == "/tmp" && x.max_depth == 8), "/tmp itself only at its own depth");
        assert!(!default_roots(None, None, true).iter().any(|x| x.path == "/run" || x.path.starts_with("/run/")));
    }

    #[test]
    fn the_real_tmp_masks_its_own_sockets_and_hides_its_service_dirs_whole() {
        // A stand-in /tmp: a top-level socket (masked), the tmux, X11 and
        // ssh-agent directories (hidden whole), and a short-lived socket in a
        // program's own temp dir, left to the connect allow-list: masking it
        // would let bwrap re-create it as a stray file in the real /tmp once
        // it vanished (the CI run of 2026-10-19 that found mock sockets left).
        let base = tmp("tmpshape");
        for d in ["tmux-1000", ".X11-unix", "ssh-AbCd12", "prog-tmp"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        let _p = UnixListener::bind(base.join(".s.PGSQL.5432")).unwrap();
        let _t = UnixListener::bind(base.join("tmux-1000/default")).unwrap();
        let _d = UnixListener::bind(base.join("prog-tmp/mock.sock")).unwrap();
        std::os::unix::fs::symlink(base.join("tmux-1000"), base.join("tmux-2000")).unwrap();
        let r = scan(&[ScanRoot::new(s(&base), TMP_SOCKET_DEPTH)], &[], &HashMap::new(), SCAN_BUDGET);
        assert!(r.sockets.contains(&s(&base.join(".s.PGSQL.5432"))), "{:?}", r.sockets);
        assert!(!r.sockets.contains(&s(&base.join("prog-tmp/mock.sock"))), "not below /tmp's own entries");
        let dirs = tmp_service_dirs(&s(&base));
        let want: Vec<String> = [".X11-unix", "ssh-AbCd12", "tmux-1000"].iter().map(|d| s(&base.join(d))).collect();
        assert_eq!(dirs, want, "service dirs, sorted; never a symlink nor another dir");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn tmp_service_dir_names() {
        for yes in [".X11-unix", ".ICE-unix", ".XIM-unix", ".font-unix", ".Test-unix", "tmux-1000", "ssh-XXXXabc123", "pulse-PKdhtXMmr18n", "screens", ".screen"] {
            assert!(is_tmp_service_dir(yes), "{yes}");
        }
        for no in ["tmux-", "tmux-10a", "ssh-", "ssh-a/b", "ssh-x.y", "mandu-run-1", "systemd-private-x", ".X11-unix2", "prog-tmp"] {
            assert!(!is_tmp_service_dir(no), "{no}");
        }
    }
}
