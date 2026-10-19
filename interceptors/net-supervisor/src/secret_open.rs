//! secret_open — plan 10 §4.1, the READER half of the interposer
//! (docs/design/confidentiality/confidentiality-plan-10-flow-taint.md).
//!
//! The launcher hands the guard a policy file (`MANDU_NET_GUARD_SECRETS`):
//! the registered secret files (real path, twin path, level), the agent's own
//! executable, the prompting mode. With it the guard also traps the open
//! family. An open whose canonical path is NOT a registered secret continues
//! at once (no arbiter round trip: that is the §7.1 cost, ~25 µs). An open of a
//! secret goes to the arbiter (`decideSecretOpen`), which decides from the law
//! (readers, pins, consumer table) and RECORDS the taint before answering:
//!
//!   raw  → the guard opens the REAL file (it runs OUTSIDE the twin bind, so it
//!          sees the real bytes) and injects that descriptor (ADDFD).
//!   twin → the guard opens the TWIN and injects it: this is what makes the
//!          structured twin work even where no bind could be mounted (§11.7,
//!          the `gated` posture) — the bind, where present, is belt and braces.
//!   deny → EACCES. `ask` is answered by the arbiter (deny until the Inbox hold
//!          of §11.1 ships, with a reason the tool result carries).
//!
//! Fail-safe direction: any failure on the guard's side (unreadable path arg,
//! arbiter unreachable, ADDFD refused) answers CONTINUE, which lands on the
//! twin bind where one exists and on the real file only where the launch has
//! no confinement at all (the `gated` posture already says so loudly).
//! `openat2` on a secret is answered ENOSYS so libc retries with `openat`, which
//! keeps one decode path for the flags.
//!
//! The pure parts (policy file, index, flag decode, hashing) are unit-tested;
//! the notification handler is `kernel`-gated like the connect guard.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// One registered secret as the launcher wrote it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretEntry {
    /// The REAL path (realpath at registration).
    pub path: String,
    /// The twin file (structured or whole-file) the launcher materialized.
    pub twin: String,
    /// no-model | any-model
    pub level: String,
    /// What the entry is (launcher git-object-twins.ts): absent or `file` = a
    /// protected file, decided by the arbiter (readers get the real file);
    /// `object` = a git object-store file (a pack, its index) whose twin is a
    /// sanitized copy: always the twin, never the arbiter, never raw;
    /// `deny` = an object-store file that would expose a protected version
    /// (a loose copy, a multi-pack-index, a bitmap): always EACCES;
    /// `derived` = never in the launcher's list: the guard's own entry for a
    /// derived file it gates at the open (confidentiality plan 13 D4,
    /// `derived_index`), decided by the arbiter, its twin made on demand;
    /// `labelled` = the same for a file a human label covers that the launch
    /// did not register (confidentiality.md §6, 2026-10-17, `label_index`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

impl SecretEntry {
    /// Is this the guard's own entry, whose twin it makes on demand from the
    /// arbiter's `registerSecret` (`derived`, `labelled`)?
    pub fn twin_on_demand(&self) -> bool {
        matches!(self.kind.as_deref(), Some("derived") | Some("labelled"))
    }
}

/// How the guard answers an open of a registered entry, before any arbiter
/// round trip (`SecretEntry::kind`). Pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryAnswer {
    /// Ask the arbiter (a protected file).
    Arbiter,
    /// Serve the twin without asking (an object-store file, read).
    Twin,
    /// Refuse with EACCES without asking.
    Deny,
}

impl SecretEntry {
    /// The answer this entry's kind fixes. An unknown kind is refused
    /// (fail-closed: a launcher newer than this guard). A write-intent open of
    /// an object-store file is refused: git never rewrites a pack in place,
    /// and a write through the twin would be a write to the sanitized copy.
    pub fn answer(&self, write_intent: bool) -> EntryAnswer {
        match self.kind.as_deref() {
            // `derived`: a file a process holding a secret wrote (plan 13 D4),
            // never in the launcher's list, gated like a labelled file.
            // `labelled`: a file a human label covers that the launch did not
            // register (2026-10-17), gated the same way.
            None | Some("file") | Some("derived") | Some("labelled") => EntryAnswer::Arbiter,
            Some("object") if !write_intent => EntryAnswer::Twin,
            _ => EntryAnswer::Deny,
        }
    }
}

/// A path the agent's tree may not change (the launcher's `writeProtect`,
/// sandbox-security-review-2026-09-28 findings 2 and 6): Mandu's own config,
/// state and install directories (`deny`), and files that run later outside
/// Mandu (shell startup files, systemd user units, autostart entries, git
/// hooks: `ask`, the Inbox hold). A file entry covers that file; a directory
/// entry covers everything below it, except what `except` names.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WriteProtect {
    /// Absolute, `~` expanded by the launcher.
    pub path: String,
    /// Directories below `path` this entry does not cover (the Mandu home's
    /// carve-outs, on-disk-layout.md §4: the integrity modes' AgentView).
    /// A carve-out spares only its own entry; another entry that covers the
    /// same place still applies. Absolute, resolved as far as they exist.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub except: Vec<String>,
    /// `deny` | `ask`. Anything else is refused like `deny` (fail-closed: a
    /// launcher newer than this guard).
    #[serde(default)]
    pub answer: String,
    /// What the entry is, in plain words ("a shell startup file"), for the
    /// Inbox sentence and the refusal event.
    #[serde(default)]
    pub label: String,
    /// How `path` names what it covers (`WriteForm`): absent or `path` = the
    /// path resolved (links followed) and everything below it; `name` = the
    /// entry ITSELF under its own name, a link included (its directory
    /// resolved, its last component not: `current`), and everything below
    /// that name; `prefix` = every name in that directory that starts with
    /// the last component (`.current.tmp-`), and everything below one; `self`
    /// = the entry itself only, not what is below it (a directory that must
    /// not be renamed or removed while its contents stay writable: the
    /// runtime base). Mandu's runtime registry entries use the last three
    /// (runtime-instances.md §2, "planted paths").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub form: String,
}

/// How a write-protect entry's path names what it covers (`WriteProtect::form`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteForm {
    Path,
    Name,
    Prefix,
    SelfOnly,
}

/// How the guard answers a change under a `WriteProtect` entry. Pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAnswer {
    Deny,
    Ask,
}

impl WriteProtect {
    pub fn answer(&self) -> WriteAnswer {
        if self.answer == "ask" { WriteAnswer::Ask } else { WriteAnswer::Deny }
    }

    /// The entry's form; a word this guard does not know is `Path` (the
    /// widest: the entry and everything below it).
    pub fn form(&self) -> WriteForm {
        match self.form.as_str() {
            "name" => WriteForm::Name,
            "prefix" => WriteForm::Prefix,
            "self" => WriteForm::SelfOnly,
            _ => WriteForm::Path,
        }
    }

    /// Does the entry cover `target` by its spelling? Both absolute and
    /// normalized. Pure.
    pub fn covers_lexically(&self, target: &str) -> bool {
        let t = target.trim_end_matches('/');
        match self.form() {
            WriteForm::Path | WriteForm::Name => lexically_under(&self.path, t),
            WriteForm::SelfOnly => {
                let p = self.path.trim_end_matches('/');
                !p.is_empty() && t == p
            }
            WriteForm::Prefix => {
                let (dir, pre) = split_last(&self.path);
                !pre.is_empty() && t.strip_prefix(dir).and_then(|r| r.strip_prefix('/')).map(|r| r.starts_with(pre)).unwrap_or(false)
            }
        }
    }

    /// Does a target named `leaf`, in a directory whose identity is `dir_id`,
    /// fall under this `name`/`prefix`/`self` entry by identity (the entry's
    /// directory reached under another spelling: a bind, a symlinked
    /// parent)? `id` gives a path's identity, links followed. Never for a
    /// `path` entry (its identity rules are `write_protected_hit`'s). Pure.
    pub fn covers_by_dir(&self, leaf: &str, dir_id: Option<(u64, u64)>, id: impl Fn(&str) -> Option<(u64, u64)>) -> bool {
        let form = self.form();
        if form == WriteForm::Path || dir_id.is_none() {
            return false;
        }
        let (dir, last) = split_last(&self.path);
        let named = match form {
            WriteForm::Prefix => !last.is_empty() && leaf.starts_with(last),
            _ => !last.is_empty() && leaf == last,
        };
        named && id(if dir.is_empty() { "/" } else { dir }) == dir_id
    }
}

/// `/a/b/c` → (`/a/b`, `c`); `/c` → (``, `c`). Pure.
fn split_last(p: &str) -> (&str, &str) {
    let p = p.trim_end_matches('/');
    match p.rfind('/') {
        Some(i) => (&p[..i], &p[i + 1..]),
        None => ("", p),
    }
}

/// The write-protect entry `target` falls under: the entry itself or anything
/// below it, by path, then by the files themselves (`id` follows symlinks,
/// `lid` does not; the target is matched both ways, so a symlink or a hard
/// link that leads to a protected file hits, and so does a target whose
/// parent directory is a bind or another spelling of a protected one). Paths
/// are absolute and normalized. Pure.
pub fn write_protected_hit<'a>(
    entries: &'a [WriteProtect],
    target: &str,
    id: impl Fn(&str) -> Option<(u64, u64)>,
    lid: impl Fn(&str) -> Option<(u64, u64)>,
) -> Option<&'a WriteProtect> {
    let t = target.trim_end_matches('/');
    for e in entries {
        if e.covers_lexically(t) && !e.except.iter().any(|x| carves(&e.path, x) && lexically_under(x, t)) {
            return Some(e);
        }
    }
    let tp = std::path::Path::new(t);
    let selves: Vec<(u64, u64)> = [id(t), lid(t)].into_iter().flatten().collect();
    let parents: Vec<(u64, u64)> = tp.parent().map(|p| p.ancestors().filter_map(|a| a.to_str().and_then(&id)).collect()).unwrap_or_default();
    let reaches = |p: &str| id(p.trim_end_matches('/')).map(|x| selves.contains(&x) || parents.contains(&x)).unwrap_or(false);
    for e in entries.iter().filter(|e| e.form() == WriteForm::Path) {
        if reaches(&e.path) && !e.except.iter().any(|x| carves(&e.path, x) && (lexically_under(x, t) || reaches(x))) {
            return Some(e);
        }
    }
    // A `name`/`prefix`/`self` entry by identity: the target's directory is
    // the entry's, under another spelling, or the target is the entry itself
    // (by its own identity, a link not followed).
    let leaf = tp.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let dir_id = tp.parent().and_then(|p| p.to_str()).and_then(&id);
    let own = lid(t);
    entries.iter().filter(|e| e.form() != WriteForm::Path).find(|e| e.covers_by_dir(leaf, dir_id, &id) || (e.form() != WriteForm::Prefix && own.is_some() && lid(&e.path) == own))
}

/// Is `except` a carve-out of `entry`: strictly below it? One AT the entry
/// (or elsewhere) spares nothing, so a launcher mistake cannot void an
/// entry. Pure.
fn carves(entry: &str, except: &str) -> bool {
    except.trim_end_matches('/') != entry.trim_end_matches('/') && lexically_under(entry, except)
}

/// Is `target` the path `prefix` names or below it (whole components)?
/// Both absolute and normalized; an empty prefix names nothing. Pure.
pub fn lexically_under(prefix: &str, target: &str) -> bool {
    let p = prefix.trim_end_matches('/');
    let t = target.trim_end_matches('/');
    !p.is_empty() && (t == p || t.starts_with(&format!("{p}/")))
}

/// `write_protected_hit` for a PINNED target: the file an open resolved (or
/// the directory a create lands in), by the path its descriptor names now and
/// by identity, so no component swapped after the check can redirect the
/// change (the write-open race). `seen`: the pinned file's path (or the new
/// file's, its directory's plus the name); `own`: the pinned file's identity
/// (None for a file not yet created); `ancestors`: the identities of the
/// directories above it; `id`: an entry path's identity. PURE.
pub fn write_protected_hit_pinned<'a>(
    entries: &'a [WriteProtect],
    seen: &str,
    own: Option<(u64, u64)>,
    ancestors: &[(u64, u64)],
    id: impl Fn(&str) -> Option<(u64, u64)>,
) -> Option<&'a WriteProtect> {
    let t = seen.trim_end_matches('/');
    if let Some(e) = entries.iter().find(|e| e.covers_lexically(t) && !e.except.iter().any(|x| carves(&e.path, x) && lexically_under(x, t))) {
        return Some(e);
    }
    let reaches = |p: &str| id(p.trim_end_matches('/')).map(|x| own == Some(x) || ancestors.contains(&x)).unwrap_or(false);
    entries.iter().filter(|e| e.form() == WriteForm::Path).find(|e| reaches(&e.path) && !e.except.iter().any(|x| carves(&e.path, x) && (lexically_under(x, t) || reaches(x))))
}

/// `write_protected_hit_pinned` for the `name`/`prefix`/`self` entries, by
/// identity: the pinned target is named `leaf` in the directory whose
/// identity is `dir_id` (the pinned directory of a create, rename or unlink),
/// and that directory is the entry's under another spelling; or the target's
/// own identity `own` (a link not followed) is the entry's (`lid`). The
/// lexical match is `write_protected_hit_pinned`'s. Pure.
pub fn write_protected_hit_named<'a>(
    entries: &'a [WriteProtect],
    leaf: &str,
    own: Option<(u64, u64)>,
    dir_id: Option<(u64, u64)>,
    id: impl Fn(&str) -> Option<(u64, u64)>,
    lid: impl Fn(&str) -> Option<(u64, u64)>,
) -> Option<&'a WriteProtect> {
    entries
        .iter()
        .filter(|e| e.form() != WriteForm::Path)
        .find(|e| e.covers_by_dir(leaf, dir_id, &id) || (e.form() != WriteForm::Prefix && own.is_some() && lid(&e.path) == own))
}

/// The write-protect entry a name change AT A STRICT ANCESTOR of it would
/// replace (P0 (D), 2026-10-07; write-protection.md §2): renaming `~/.ssh`
/// aside and a planted directory into its place (or a symlink named
/// `~/.ssh`) puts a new `~/.ssh/config` there with no write under the entry,
/// as `protect:` already refuses for its paths (`protected_hit`). `seen` is
/// the changed name (its pinned parent's path plus the leaf, so a symlinked
/// spelling of the parent is already resolved); `dir_self` is its identity
/// when it is an existing DIRECTORY (None otherwise: a file or a symlink is
/// matched by path only, and an unlink of a file, the common case, costs no
/// stat); `id` names a directory's identity, following symlinks. Matched by
/// path (an entry lies strictly below `seen`) or, for a directory, by
/// identity (it is one of the directories above an entry: a bind or another
/// spelling). Pure.
pub fn write_protected_ancestor_hit<'a>(
    entries: &'a [WriteProtect],
    seen: &str,
    dir_self: Option<(u64, u64)>,
    id: impl Fn(&str) -> Option<(u64, u64)>,
) -> Option<&'a WriteProtect> {
    let t = seen.trim_end_matches('/');
    if let Some(e) = entries.iter().find(|e| {
        let p = e.path.trim_end_matches('/');
        !p.is_empty() && p != t && (t.is_empty() || p.starts_with(&format!("{t}/")))
    }) {
        return Some(e);
    }
    let me = dir_self?;
    entries.iter().find(|e| {
        let pp = std::path::Path::new(e.path.trim_end_matches('/'));
        pp.parent().is_some_and(|parent| parent.ancestors().filter_map(|a| a.to_str().and_then(&id)).any(|x| x == me))
    })
}

/// sandbox-security-review-2026-09-28 finding 1: with the confidentiality
/// axis on, a Unix socket connect from the agent's tree is refused unless the
/// socket is on this allow-list or its listener is itself a process of the
/// tree. Host services that run code on request (the systemd user manager,
/// the D-Bus session bus, docker, a tmux or editor server) listen on sockets
/// the agent could otherwise reach, and what they run is outside every Mandu
/// confinement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UnixPolicy {
    /// Socket files, or directories whose sockets are all allowed.
    #[serde(default)]
    pub allow: Vec<UnixAllow>,
    /// Abstract names (without the leading NUL): exact, or a prefix when the
    /// entry ends in `*`.
    #[serde(rename = "abstractAllow", default)]
    pub abstract_allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnixAllow {
    pub path: String,
    #[serde(default)]
    pub label: String,
}

/// The allow entry a socket file falls under: the entry itself or anything
/// below a directory entry, by the socket's resolved path (`seen`), then by
/// identity (`id` of the entry, `target` the socket file's). Pure.
pub fn unix_allowed<'a>(policy: &'a UnixPolicy, seen: Option<&str>, target: Option<(u64, u64)>, id: impl Fn(&str) -> Option<(u64, u64)>) -> Option<&'a UnixAllow> {
    if let Some(s) = seen {
        let s = s.trim_end_matches('/');
        for a in &policy.allow {
            let p = a.path.trim_end_matches('/');
            if !p.is_empty() && (s == p || s.starts_with(&format!("{p}/"))) {
                return Some(a);
            }
        }
    }
    let t = target?;
    policy.allow.iter().find(|a| id(a.path.trim_end_matches('/')) == Some(t))
}

/// The Unix-connect DENY entry a socket falls under (arbiter-human-plane.md
/// §5: the arbiter's human-plane directory), or None. Unlike the allow-list
/// this list is ALWAYS applied when present, whatever `unixPolicy` says (the
/// `MANDU_UNIX_POLICY=0` opt-out drops the allow-list, never this). A socket
/// is denied by its resolved path (`seen`: the entry itself or anything below
/// it) or by identity (`target` among `ids_under(entry)`: the entry and the
/// files directly in it, stat'ed now), so a symlink, a hard link or a bind
/// mount of the socket elsewhere is denied too. Pure.
pub fn unix_denied<'a>(
    deny: &'a [String],
    seen: Option<&str>,
    target: Option<(u64, u64)>,
    ids_under: impl Fn(&str) -> Vec<(u64, u64)>,
) -> Option<&'a str> {
    if let Some(s) = seen {
        if let Some(d) = deny.iter().find(|d| lexically_under(d, s)) {
            return Some(d.as_str());
        }
    }
    let t = target?;
    deny.iter().find(|d| ids_under(d.trim_end_matches('/')).contains(&t)).map(|d| d.as_str())
}

/// `(st_dev, st_ino)` of `dir` itself and of each entry directly in it
/// (symlinks followed), for `unix_denied`'s identity leg. Empty when `dir`
/// cannot be read.
pub fn ids_under_dir(dir: &str) -> Vec<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let mut ids: Vec<(u64, u64)> = fs::metadata(dir).ok().map(|m| vec![(m.dev(), m.ino())]).unwrap_or_default();
    if let Ok(rd) = fs::read_dir(dir) {
        ids.extend(rd.flatten().filter_map(|e| fs::metadata(e.path()).ok()).map(|m| (m.dev(), m.ino())));
    }
    ids
}

/// Is this abstract name (the bytes after the leading NUL) allowed? Pure.
pub fn abstract_allowed(policy: &UnixPolicy, name: &[u8]) -> bool {
    policy.abstract_allow.iter().any(|a| match a.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix.as_bytes()),
        None => name == a.as_bytes(),
    })
}

/// Is `pid` one of `roots` or a descendant of one, walking `parent_of` up at
/// most 256 steps? The guard is its tree's subreaper, so a server the tree
/// daemonized still has the guard (a root) above it. Pure.
pub fn in_tree(pid: i32, roots: &[i32], parent_of: impl Fn(i32) -> Option<i32>) -> bool {
    let mut cur = pid;
    for _ in 0..256 {
        if cur <= 1 {
            return false;
        }
        if roots.contains(&cur) {
            return true;
        }
        match parent_of(cur) {
            Some(p) if p != cur => cur = p,
            _ => return false,
        }
    }
    false
}

/// The deny prefix a path falls under (the path itself or anything below
/// it), or None. Paths are absolute and normalized. Pure.
pub fn under_deny_prefix<'a>(prefixes: &'a [String], path: &str) -> Option<&'a str> {
    let t = path.trim_end_matches('/');
    prefixes.iter().map(|p| p.trim_end_matches('/')).find(|p| !p.is_empty() && (t == *p || t.starts_with(&format!("{p}/"))))
}

/// The deny prefix that hides `path`, carve-outs honoured
/// (on-disk-layout.md §4: the Mandu home is one prefix; the integrity modes'
/// AgentView below it is a carve-out). A carve-out spares a path only from
/// the prefixes it lies strictly below; any other prefix that
/// covers the path still hides it, so a deny prefix inside a carve-out keeps
/// its effect. Paths are absolute and normalized. Pure.
pub fn hidden_by<'a>(prefixes: &'a [String], except: &[String], path: &str) -> Option<&'a str> {
    let t = path.trim_end_matches('/');
    prefixes.iter().map(|p| p.trim_end_matches('/')).find(|p| {
        lexically_under(p, t) && !except.iter().any(|x| x.trim_end_matches('/') != *p && lexically_under(p, x) && lexically_under(x, t))
    })
}

/// The policy file `MANDU_NET_GUARD_SECRETS` points at.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretPolicyFile {
    /// The agent's own executable, resolved: never a reader, always the twin.
    #[serde(rename = "agentExe", default)]
    pub agent_exe: String,
    /// known | always | never (§11.1); passed through to the arbiter.
    #[serde(default)]
    pub ask: Option<String>,
    #[serde(default)]
    pub session: Option<String>,
    /// §12.2: how long a held open waits for the human (ms; default 60 000).
    #[serde(rename = "askTimeoutMs", default)]
    pub ask_timeout_ms: Option<u64>,
    #[serde(default)]
    pub secrets: Vec<SecretEntry>,
    /// Sockets that are secrets (learn-from-nono §3.5): the ssh-agent's
    /// `$SSH_AUTH_SOCK`. Only a listed reader may connect.
    #[serde(default)]
    pub sockets: Vec<SocketSecret>,
    /// Paths no program in the agent's tree may delete or rename
    /// (policy.yaml `protect:`, learn-from-nono §4 item 8). Absolute, `~`
    /// already expanded by the launcher.
    #[serde(default)]
    pub protect: Vec<String>,
    /// Directories no program in the agent's tree may open anything under
    /// (launcher secret-setup.ts `shadowRepoMaskDir`: Mandu's own shadow
    /// repositories in `secrets` mode). Absolute, resolved by the launcher.
    #[serde(rename = "denyPrefixes", default)]
    pub deny_prefixes: Vec<String>,
    /// Directories below a deny prefix that stay open to the agent (the
    /// Mandu home's carve-outs, on-disk-layout.md §4: the integrity modes'
    /// AgentView and, in `full`, its shadow repository). `hidden_by`.
    #[serde(rename = "denyExcept", default)]
    pub deny_except: Vec<String>,
    /// Paths no program in the agent's tree may change (`WriteProtect`).
    #[serde(rename = "writeProtect", default)]
    pub write_protect: Vec<WriteProtect>,
    /// Present ⇒ Unix socket connects are allow-listed (`UnixPolicy`).
    #[serde(rename = "unixPolicy", default)]
    pub unix_policy: Option<UnixPolicy>,
    /// Unix sockets no program in the agent's tree may connect to, whatever
    /// `unixPolicy` allows or whether it is present at all (`unix_denied`):
    /// the arbiter's human-plane directory (arbiter-human-plane.md §5).
    /// Absolute, resolved by the launcher.
    #[serde(rename = "unixDeny", default)]
    pub unix_deny: Vec<String>,
    /// Plan 14 §11.1 R4: the locked objects (`GitLocksPolicy`). Present
    /// with ids ⇒ the guard checks every open of an object-store file
    /// (`git_lock`).
    #[serde(rename = "gitLocks", default)]
    pub git_locks: Option<GitLocksPolicy>,
    /// policy.yaml `remote_mounts.trust_lookups` (plan 13 §4.9, 2026-10-07):
    /// the network and FUSE mounts whose servers may see a holder's lookups,
    /// so their being visible does not withhold a raw open
    /// (`visible_mounts`). Mount points as written, `~` expanded by the
    /// launcher.
    #[serde(rename = "trustLookups", default)]
    pub trust_lookups: Vec<crate::visible_mounts::TrustLookup>,
    /// 2026-10-16 (guard-file-identity.md §2): where the guard appends
    /// `<old path>\t<new path>` for a protected file a folder rename moved
    /// whose label could not follow and whose rename could not be undone,
    /// for the launcher's end-of-session notice (launcher
    /// moved-files-notice.ts). Opened once at load (`git_lock::open_notice`).
    #[serde(rename = "movedNotice", default, skip_serializing_if = "Option::is_none")]
    pub moved_notice: Option<String>,
}

/// `gitLocks` in the policy file (launcher secret-setup.ts `gitLocksField`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GitLocksPolicy {
    /// Every locked object id the launch knows, `sha1:<40 hex>` or
    /// `sha256:<64 hex>`: the `blobs:` locks above `public`, and the
    /// protected versions the launch's history walks resolved.
    #[serde(default)]
    pub ids: Vec<String>,
    /// Where the guard appends each refused repository once, for the
    /// launcher's notice at the end of the session.
    #[serde(rename = "noticeFile", default, skip_serializing_if = "Option::is_none")]
    pub notice_file: Option<String>,
}

/// The delete / rename family the protect guard traps (arch-specific: the
/// legacy `unlink`/`rmdir`/`rename` exist on x86_64 only).
pub fn is_delete_nr(nr: i64) -> bool {
    delete_nrs().contains(&nr)
}

pub fn delete_nrs() -> Vec<i64> {
    let mut v = vec![libc::SYS_unlinkat as i64, libc::SYS_renameat as i64, libc::SYS_renameat2 as i64];
    #[cfg(target_arch = "x86_64")]
    v.extend([libc::SYS_unlink as i64, libc::SYS_rmdir as i64, libc::SYS_rename as i64]);
    v
}

/// `fchmodat2(dirfd, path, mode, flags)` (Linux 6.6): 452 on every arch. libc
/// does not export it for aarch64.
pub const SYS_FCHMODAT2: i64 = 452;

/// The calls that create or change a file by NAME without an open the guard
/// sees: a hard link or symlink made (the new name, and for a hard link the
/// file it names, which becomes writable through the new name), `truncate`,
/// x86_64's `creat` (an `open(O_CREAT|O_WRONLY|O_TRUNC)` under its own
/// number), a node made (`mknod_nrs`), a mode change (`mode_nrs`), and an
/// extended attribute set or removed (`xattr_change::xattr_nrs`: a POSIX ACL
/// is a mode change by another name).
/// Trapped with the delete family under every secret policy (plan 13 §9 R4
/// (b): with a write-protect list until 2026-10-04).
pub fn write_nrs() -> Vec<i64> {
    let mut v = vec![libc::SYS_linkat as i64, libc::SYS_symlinkat as i64, libc::SYS_truncate as i64];
    #[cfg(target_arch = "x86_64")]
    v.extend([libc::SYS_link as i64, libc::SYS_symlink as i64, libc::SYS_creat as i64]);
    v.extend(mknod_nrs());
    v.extend(mode_nrs());
    v.extend(crate::xattr_change::xattr_nrs());
    v
}

/// `mknodat` (and x86_64's `mknod`): a FIFO, socket, device or regular file
/// made under a name (write-protection.md §2: judged like any new name).
pub fn mknod_nrs() -> Vec<i64> {
    let mut v = vec![libc::SYS_mknodat as i64];
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_mknod as i64);
    v
}

pub fn is_mknod_nr(nr: i64) -> bool {
    mknod_nrs().contains(&nr)
}

/// `mkdirat` (and x86_64's `mkdir`): a directory made under a name. Trapped
/// under every secret policy for one reason only, a holder's name on a mount
/// that leaves the machine (confidentiality plan 13 §9 R4 (b), 2026-10-04);
/// anyone else's runs at once (`guard_kernel` answers CONTINUE).
pub fn mkdir_nrs() -> Vec<i64> {
    let mut v = vec![libc::SYS_mkdirat as i64];
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_mkdir as i64);
    v
}

pub fn is_mkdir_nr(nr: i64) -> bool {
    mkdir_nrs().contains(&nr)
}

/// `mkdirat(dirfd, path, mode)` / `mkdir(path, mode)`: (dirfd, path
/// pointer, mode). Pure.
pub fn mkdir_call(nr: i64, args: &[u64; 6]) -> Option<(i32, u64, u32)> {
    if nr == libc::SYS_mkdirat as i64 {
        return Some((args[0] as i32, args[1], args[2] as u32));
    }
    #[cfg(target_arch = "x86_64")]
    if nr == libc::SYS_mkdir as i64 {
        return Some((libc::AT_FDCWD, args[0], args[1] as u32));
    }
    None
}

/// The mode family: `fchmodat`, `fchmodat2`, `fchmod` (by descriptor), and
/// x86_64's `chmod`. A mode change arms a script (`chmod +x` of a git hook),
/// or opens a protected or secret file to other users; none is an open the
/// guard sees, and `fchmod` needs only a read-only (or any) descriptor.
pub fn mode_nrs() -> Vec<i64> {
    let mut v = vec![libc::SYS_fchmodat as i64, SYS_FCHMODAT2, libc::SYS_fchmod as i64];
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_chmod as i64);
    v
}

pub fn is_mode_nr(nr: i64) -> bool {
    mode_nrs().contains(&nr)
}

/// A mode-family call, decoded (`mode_call`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeCall {
    /// A path (`dirfd`, pointer): `follow` = the final symlink is followed
    /// (every form but `fchmodat2(AT_SYMLINK_NOFOLLOW)`); `empty_path` =
    /// `fchmodat2(AT_EMPTY_PATH)`, where an empty path names `dirfd` itself.
    Path { dirfd: i32, addr: u64, mode: u32, follow: bool, empty_path: bool },
    /// `fchmod(fd, mode)`: the tracee's own open file.
    Fd { fd: i32, mode: u32 },
}

/// Decode a mode-family call. `Err(EINVAL)`: `fchmodat2` flags the kernel
/// refuses (anything but `AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH`), answered as
/// the kernel would. `Ok(None)`: not a mode call. Pure.
pub fn mode_call(nr: i64, args: &[u64; 6]) -> Result<Option<ModeCall>, i32> {
    let mode = args[2] as u32;
    if nr == libc::SYS_fchmodat as i64 {
        return Ok(Some(ModeCall::Path { dirfd: args[0] as i32, addr: args[1], mode, follow: true, empty_path: false }));
    }
    if nr == SYS_FCHMODAT2 {
        let flags = args[3] as u32 as i32;
        if flags & !(libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH) != 0 {
            return Err(libc::EINVAL);
        }
        let follow = flags & libc::AT_SYMLINK_NOFOLLOW == 0;
        let empty_path = flags & libc::AT_EMPTY_PATH != 0;
        return Ok(Some(ModeCall::Path { dirfd: args[0] as i32, addr: args[1], mode, follow, empty_path }));
    }
    if nr == libc::SYS_fchmod as i64 {
        return Ok(Some(ModeCall::Fd { fd: args[0] as i32, mode: args[1] as u32 }));
    }
    #[cfg(target_arch = "x86_64")]
    if nr == libc::SYS_chmod as i64 {
        return Ok(Some(ModeCall::Path { dirfd: libc::AT_FDCWD, addr: args[0], mode: args[1] as u32, follow: true, empty_path: false }));
    }
    Ok(None)
}

/// Decode a `mknod`-family call: `(dirfd, path pointer, mode, dev)`. Pure.
pub fn mknod_call(nr: i64, args: &[u64; 6]) -> Option<(i32, u64, u32, u32)> {
    if nr == libc::SYS_mknodat as i64 {
        return Some((args[0] as i32, args[1], args[2] as u32, args[3] as u32));
    }
    #[cfg(target_arch = "x86_64")]
    if nr == libc::SYS_mknod as i64 {
        return Some((libc::AT_FDCWD, args[0], args[1] as u32, args[2] as u32));
    }
    None
}

/// A mode change that changes nothing (the permission bits asked for are the
/// ones the file has): performed without a judgement, so an editor or `cp -p`
/// that re-applies a protected file's own mode after a write is not asked
/// twice. Only the 07777 bits are compared (the kernel keeps the type). Pure.
pub fn mode_change_is_noop(current: u32, requested: u32) -> bool {
    current & 0o7777 == requested & 0o7777
}

/// A `sockaddr_un` naming `leaf` RELATIVE to the binding thread's cwd (the
/// guard `fchdir`s to the pinned parent first, so no parent is re-walked and
/// no `/proc/self/fd/<pin>/` prefix has to fit `sun_path`): the family, the
/// leaf, and a NUL when it fits (a 108-byte name is legal unterminated).
/// `None`: a leaf `sun_path` cannot hold, or one with a `/` or a NUL. Pure.
pub fn relative_unix_addr(leaf: &[u8]) -> Option<Vec<u8>> {
    const SUN_PATH: usize = 108;
    if leaf.is_empty() || leaf.len() > SUN_PATH || leaf.contains(&b'/') || leaf.contains(&0) {
        return None;
    }
    let mut b = (libc::AF_UNIX as u16).to_ne_bytes().to_vec();
    b.extend_from_slice(leaf);
    if leaf.len() < SUN_PATH {
        b.push(0);
    }
    Some(b)
}

pub fn is_write_nr(nr: i64) -> bool {
    write_nrs().contains(&nr)
}

/// The (dirfd, path pointer) pairs a write-family call names (`write_nrs`).
/// Pure.
pub fn write_targets(nr: i64, args: &[u64; 6]) -> Vec<(i32, u64)> {
    let at = libc::AT_FDCWD;
    if nr == libc::SYS_linkat as i64 {
        return vec![(args[0] as i32, args[1]), (args[2] as i32, args[3])];
    }
    if nr == libc::SYS_symlinkat as i64 {
        return vec![(args[1] as i32, args[2])];
    }
    if nr == libc::SYS_truncate as i64 {
        return vec![(at, args[0])];
    }
    if let Some((d, p, _, _)) = mknod_call(nr, args) {
        return vec![(d, p)];
    }
    if let Ok(Some(ModeCall::Path { dirfd, addr, .. })) = mode_call(nr, args) {
        return vec![(dirfd, addr)];
    }
    #[cfg(target_arch = "x86_64")]
    {
        if nr == libc::SYS_link as i64 {
            return vec![(at, args[0]), (at, args[1])];
        }
        if nr == libc::SYS_symlink as i64 {
            return vec![(at, args[1])];
        }
        if nr == libc::SYS_creat as i64 {
            return vec![(at, args[0])];
        }
    }
    vec![]
}

/// The (dirfd, path pointer) pairs a delete/rename call names: the SOURCE of a
/// rename (what disappears from its place) and, for a rename, the destination
/// too (a rename OVER a protected file replaces it). Pure.
pub fn delete_targets(nr: i64, args: &[u64; 6]) -> Vec<(i32, u64)> {
    let at = libc::AT_FDCWD;
    if nr == libc::SYS_unlinkat as i64 {
        return vec![(args[0] as i32, args[1])];
    }
    if nr == libc::SYS_renameat as i64 || nr == libc::SYS_renameat2 as i64 {
        return vec![(args[0] as i32, args[1]), (args[2] as i32, args[3])];
    }
    #[cfg(target_arch = "x86_64")]
    {
        if nr == libc::SYS_unlink as i64 || nr == libc::SYS_rmdir as i64 {
            return vec![(at, args[0])];
        }
        if nr == libc::SYS_rename as i64 {
            return vec![(at, args[0]), (at, args[1])];
        }
    }
    let _ = at;
    vec![]
}

/// The part a path plays in a name-family change the guard PERFORMS on the
/// tracee's behalf (`handle_path_change_notif`; the perform-on-behalf close of
/// the path-change TOCTOU, sandbox-security-review-2026-09-28 findings 6/7).
/// The judge each role runs is fixed by the role, not the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeRole {
    /// A name removed (`unlink`/`unlinkat`/`rmdir`): refuse when it, or an
    /// ancestor, is a `protect:` path, it is under a write-protect entry, or
    /// it is a registered secret's file (`registered_secret_refuses`).
    Remove,
    /// A rename SOURCE: it disappears from its place. Judged like `Remove`,
    /// and additionally a source that resolves to a registered secret's real
    /// file is refused (its bytes must not be moved out from under the twin).
    RenameSrc,
    /// A rename DESTINATION: the name a rename creates or replaces. Judged
    /// like a new file under the write-protect list, like `protect:`
    /// (replacing a protected path), and a registered secret's file it would
    /// replace is refused (`registered_secret_refuses`). Either side of a
    /// `RENAME_EXCHANGE` is judged as a `RenameSrc` instead.
    Dest,
    /// The existing file a hard link names (`link`/`linkat` oldpath): the new
    /// name would reach it, so a registered secret or a write-protected file
    /// is refused.
    LinkSource,
    /// A new name a `link`/`symlink` creates: judged like a new file.
    NewName,
    /// A `truncate` target: the WHOLE path (symlinks followed), opened for
    /// write; a registered secret is refused, a write-protected file judged.
    Truncate,
    /// A mode change's target (`chmod`/`fchmodat`/`fchmodat2`): the WHOLE path,
    /// the final symlink followed unless `AT_SYMLINK_NOFOLLOW`, pinned; a
    /// registered secret is refused, a write-protected file judged.
    Mode,
}

/// Is a name-family change in `role` of a registered secret's file (an entry
/// of `kind`, `SecretEntry::kind`) refused? The guard asks only when the
/// pinned target IS one (by path or identity; a symlink to one is a name of
/// its own and never matches). Pure.
///
/// - `RenameSrc`, `LinkSource`, `Truncate`, `Mode`: always (its bytes must not
///   be moved, hard-linked to a new name, emptied, or opened to others).
/// - `Dest`, `Remove` (2026-10-02, maintainer decision: refuse, not an Inbox
///   hold): a protected file (`kind` absent or `file`) and an unknown kind
///   (fail-closed). In the guard-only posture an in-place writer (`sed -i`,
///   `perl -pi`, an editor's save) writes the placeholder it read to a temp
///   file and renames it OVER the real path, and `rm` removes it: the real
///   credential would be lost. Under the twin bind the same calls meet the
///   mount point (`EBUSY`), so both postures now refuse. An object-store
///   entry (`object`, `deny`) is git's content-addressed store: a pack, a
///   companion or a loose object replaced or removed exposes and loses
///   nothing (`git_lock::refuses` keeps the one anchor, a locked pack's
///   index), and `git gc` / `repack` must keep working.
/// - `NewName`: never (a new name replaces nothing; the kernel answers
///   `EEXIST`).
pub fn registered_secret_refuses(role: ChangeRole, kind: Option<&str>) -> bool {
    use ChangeRole::*;
    match role {
        RenameSrc | LinkSource | Truncate | Mode => true,
        Dest | Remove => !matches!(kind, Some("object") | Some("deny")),
        NewName => false,
    }
}

/// The roles of a name-family call's targets, in the order
/// `delete_targets`/`write_targets` lists them (so `pinned_change_targets`
/// zips the two). `creat` is routed to the write-open path, not here, so it
/// has no roles. Pure.
pub fn change_roles(nr: i64) -> Vec<ChangeRole> {
    use ChangeRole::*;
    if nr == libc::SYS_unlinkat as i64 {
        return vec![Remove];
    }
    if nr == libc::SYS_renameat as i64 || nr == libc::SYS_renameat2 as i64 {
        return vec![RenameSrc, Dest];
    }
    if nr == libc::SYS_linkat as i64 {
        return vec![LinkSource, NewName];
    }
    if nr == libc::SYS_symlinkat as i64 {
        return vec![NewName];
    }
    if nr == libc::SYS_truncate as i64 {
        return vec![Truncate];
    }
    // A node is a new name; `fchmod` names no path (judged by its descriptor).
    if is_mknod_nr(nr) {
        return vec![NewName];
    }
    if nr == libc::SYS_fchmodat as i64 || nr == SYS_FCHMODAT2 {
        return vec![Mode];
    }
    #[cfg(target_arch = "x86_64")]
    {
        if nr == libc::SYS_chmod as i64 {
            return vec![Mode];
        }
        if nr == libc::SYS_unlink as i64 || nr == libc::SYS_rmdir as i64 {
            return vec![Remove];
        }
        if nr == libc::SYS_rename as i64 {
            return vec![RenameSrc, Dest];
        }
        if nr == libc::SYS_link as i64 {
            return vec![LinkSource, NewName];
        }
        if nr == libc::SYS_symlink as i64 {
            return vec![NewName];
        }
    }
    vec![]
}

/// Every `(dirfd, path pointer, role)` a name-family call names, so the guard
/// pins each parent, judges by role, and performs the call relative to the
/// pinned descriptors (never CONTINUE, which re-resolves). `creat` yields
/// nothing (routed to the write-open path). Pure.
pub fn pinned_change_targets(nr: i64, args: &[u64; 6]) -> Vec<(i32, u64, ChangeRole)> {
    let targets = if is_delete_nr(nr) { delete_targets(nr, args) } else { write_targets(nr, args) };
    let roles = change_roles(nr);
    if targets.len() != roles.len() {
        return Vec::new();
    }
    targets.into_iter().zip(roles).map(|((d, p), r)| (d, p, r)).collect()
}

/// Split a path into `(parent, leaf)`: everything up to the last `/`, and the
/// final component (never resolved: the guard performs the call relative to
/// the pinned parent with this leaf, one component the kernel cannot re-walk
/// through a swapped directory). One trailing `/` is trimmed first (`a/b/`
/// names `b`). A path with no `/` has parent `.` (the call's dirfd or cwd).
/// `/`, empty, or a path whose leaf is `.`/`..` yields `None` (nothing a
/// single-component change names). Pure.
pub fn split_parent_leaf(path: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if path.is_empty() {
        return None;
    }
    // Trim one trailing slash (but not the root "/").
    let p: &[u8] = if path.len() > 1 && *path.last().unwrap() == b'/' {
        let mut end = path.len();
        while end > 1 && path[end - 1] == b'/' {
            end -= 1;
        }
        &path[..end]
    } else {
        path
    };
    if p == b"/" {
        return None;
    }
    let (parent, leaf): (&[u8], &[u8]) = match p.iter().rposition(|b| *b == b'/') {
        Some(0) => (b"/", &p[1..]),
        Some(i) => (&p[..i], &p[i + 1..]),
        None => (b".", p),
    };
    if leaf.is_empty() || leaf == b"." || leaf == b".." {
        return None;
    }
    Some((parent.to_vec(), leaf.to_vec()))
}

/// Is `target` a protected path, inside one, or an ancestor of one (removing
/// or renaming an ancestor takes the protected tree with it)? Returns the
/// protected entry it hits. Paths are absolute and normalized. Pure.
pub fn protected_hit<'a>(protect: &'a [String], target: &str) -> Option<&'a str> {
    let t = target.trim_end_matches('/');
    for p in protect {
        let p = p.trim_end_matches('/');
        if p.is_empty() {
            continue;
        }
        let inside = t == p || t.starts_with(&format!("{p}/"));
        let ancestor = p.starts_with(&format!("{t}/")) || t.is_empty();
        if inside || ancestor {
            return Some(p);
        }
    }
    None
}

/// `protected_hit` by the files themselves, for a target the path compare
/// misses: a different-case spelling on a case-folding filesystem (WSL
/// drvfs), a hard link, a bind or symlinked spelling of an ancestor. The
/// target is inside a protected path when it IS that file or directory or one
/// of the target's parent directories is; an ancestor when it is one of the
/// protected path's parent directories. `id` follows symlinks (the parent
/// chain, the protected paths); `lid` does not (the target itself: removing a
/// link removes the link). Returns the protected entry it hits.
pub fn protected_hit_by_id<'a>(
    protect: &'a [String],
    target: &str,
    id: impl Fn(&str) -> Option<(u64, u64)>,
    lid: impl Fn(&str) -> Option<(u64, u64)>,
) -> Option<&'a str> {
    let chain = |p: &std::path::Path| -> Vec<(u64, u64)> { p.ancestors().filter_map(|a| a.to_str().and_then(&id)).collect() };
    let t = std::path::Path::new(target);
    let t_parents = t.parent().map(chain).unwrap_or_default();
    protected_hit_by_ids(protect, lid(target), &t_parents, id)
}

/// `protected_hit_by_id` on identities the caller already holds: `t_self` is
/// the target's own (not following a final symlink), `t_parents` its parent
/// directories' (nearest first, as a pinned descriptor's `..` chain gives
/// them: no path is re-resolved, so a spelling that exists only in the
/// tracee's mount namespace, a bind of a protected folder, is still matched).
/// `id` names a protected entry's identity. Pure.
pub fn protected_hit_by_ids<'a>(
    protect: &'a [String],
    t_self: Option<(u64, u64)>,
    t_parents: &[(u64, u64)],
    id: impl Fn(&str) -> Option<(u64, u64)>,
) -> Option<&'a str> {
    let chain = |p: &std::path::Path| -> Vec<(u64, u64)> { p.ancestors().filter_map(|a| a.to_str().and_then(&id)).collect() };
    for p in protect {
        let pp = std::path::Path::new(p.trim_end_matches('/'));
        let Some(p_self) = id(&pp.to_string_lossy()) else { continue };
        let inside = t_self == Some(p_self) || t_parents.contains(&p_self);
        let ancestor = t_self.is_some_and(|ts| pp.parent().map(chain).unwrap_or_default().contains(&ts));
        if inside || ancestor {
            return Some(p);
        }
    }
    None
}

/// `protected_hit_by_ids`, fail closed (2026-10-16, the rename rule over the
/// registered files the guard holds no inode of): a listed path, or a
/// directory above it, whose identity cannot be read is `Err(that path)`
/// (the caller refuses), where `protected_hit_by_ids` skips it. Pure.
pub fn protected_hit_by_ids_strict<'a>(
    list: &'a [String],
    t_self: Option<(u64, u64)>,
    t_parents: &[(u64, u64)],
    id: impl Fn(&str) -> Option<(u64, u64)>,
) -> Result<Option<&'a str>, &'a str> {
    for p in list {
        let pp = std::path::Path::new(p.trim_end_matches('/'));
        let Some(p_self) = id(&pp.to_string_lossy()) else { return Err(p) };
        let mut chain = Vec::new();
        for a in pp.ancestors().skip(1) {
            match a.to_str().and_then(&id) {
                Some(i) => chain.push(i),
                None => return Err(p),
            }
        }
        let inside = t_self == Some(p_self) || t_parents.contains(&p_self);
        let ancestor = t_self.is_some_and(|ts| chain.contains(&ts));
        if inside || ancestor {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

/// A socket only listed programs may connect to (policy.yaml `ssh_agent`).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SocketSecret {
    pub path: String,
    /// What the refusal calls it ("ssh-agent").
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub readers: Vec<ReaderSpec>,
}

/// A reader: a program name, or `{ app, from?, prints? }` (from: a program
/// that must be among the connecting process's ancestors; prints: `nothing`,
/// the human's word that the program keeps what it reads out of what it
/// prints, Plan 13 D8 (12)).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum ReaderSpec {
    Name(String),
    Pin {
        app: String,
        #[serde(default)]
        from: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prints: Option<String>,
    },
}

/// Does an executable's basename name this program? Exactly, or the file a
/// name resolves to through a version or an alternatives link (`python3` names
/// `python3.12`, `nc` names `nc.openbsd`); the suffix needs a leading dot and
/// only letters and digits, so `ssh` never names `ssh2`. Twin of
/// arbiter/policy/flow-taint.ts appNameMatches.
pub fn app_name_matches(base: &str, name: &str) -> bool {
    if base == name {
        return true;
    }
    match base.strip_prefix(name) {
        Some(rest) => rest.starts_with('.') && rest[1..].split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric())),
        None => false,
    }
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Programs that run code they are given: shells, language interpreters and
/// command launchers. Twin of arbiter/policy/flow-taint.ts
/// `CODE_RUNNING_READERS` (tests/stack/reader-identity.test.ts pins the
/// copies to one table). Plan 13 §8 decision (b), 2026-10-02: such a program
/// is never a reader by name (`readers: [bash]` would let any script the
/// agent writes use the socket); the file readers' script pin has no socket
/// form.
pub const CODE_RUNNING_READERS: &[&str] = &[
    // exec-identifier.ts INTERPRETERS
    "node", "bun", "deno", "bunx", "npx", "yarn", "pnpm", "tsx", "ts-node",
    "python", "python2", "python3", "ruby", "perl", "sh", "bash", "zsh",
    // shells
    "dash", "ash", "ksh", "mksh", "fish", "csh", "tcsh", "busybox",
    // language runtimes
    "php", "lua", "luajit", "tclsh", "wish", "Rscript", "R", "julia", "java", "jshell", "guile", "racket", "pwsh", "osascript",
    // programs that run another program, or a script, from their arguments
    "env", "xargs", "find", "make", "awk", "gawk", "mawk", "nawk", "nohup", "timeout", "nice", "stdbuf", "setsid", "watch", "script", "sudo", "doas",
    // editors, debuggers, tracers and shells of a command language that run
    // what they are given or load (an rc file, -c, a plugin, `.shell`), Plan 13
    // D8 "code by argument" (2026-10-02)
    "vi", "vim", "nvim", "ex", "view", "rvim", "rview", "vimdiff", "gvim", "gview", "evim", "vimx", "emacs", "emacsclient", "ed", "red",
    "gdb", "lldb", "strace", "ltrace", "sqlite3", "expect", "m4",
    // more launchers
    "time", "parallel", "flock", "chroot", "unshare", "nsenter", "bwrap", "firejail", "systemd-run", "su", "runuser", "pkexec", "taskset", "ionice", "chrt", "prlimit",
    // multi-call binaries that carry a shell or a launcher (`toybox sh`,
    // `coreutils env`), beside busybox (Plan 13 D8 leftover (3a), 2026-10-03)
    "toybox", "coreutils",
    // relays that run a program from their arguments and hand it the socket
    // (`nc -e`, `ncat --sh-exec` / `--lua-exec`, `socat EXEC:` / `SYSTEM:`); as
    // a reader of the ssh-agent socket each hands the agent's signing to
    // whatever drives it (leftover (3b))
    "nc", "ncat", "netcat", "socat",
    // fetch and transfer clients that run a command they are given, by an
    // option or an rc file in $HOME (2026-10-03): ftp's `!cmd` and `get f
    // |cmd`, aria2c's `--on-download-*` hooks, lftp's `!`, sftp's `!`,
    // `--use-askpass`, rclone's `--password-command`, `gio launch`,
    // `kioclient exec`, a text browser's `!` and mailcap viewers, httpie's
    // plugins; on the socket's list each would run the agent's command
    "ftp", "tnftp", "netkit-ftp", "pftp", "inetutils-ftp", "aria2c", "lftp", "sftp", "wget", "wget2", "rclone",
    "gio", "kioclient", "kioclient5", "kioclient6", "lynx", "w3m", "elinks", "links", "links2", "http", "https", "httpie",
    // more editors that run a command or load code from an rc file
    "nvi", "elvis", "vis", "kak", "hx", "helix", "joe", "jstar", "jmacs", "jpico", "rjoe", "jed", "mg", "zile", "jove",
    "mcedit", "mc", "ne", "xemacs",
    // more launchers
    "valgrind", "perf", "rr", "setpriv", "sg", "unbuffer", "faketime", "torsocks", "proxychains", "proxychains4",
    "fakeroot", "eatmydata", "xvfb-run", "dbus-run-session", "tmux", "screen", "entr",
    // build tools and task runners that run the commands of a build file or of
    // their arguments (2026-10-04, probed): `cmake -P <script>` and `cmake -E
    // env <cmd>`, `ctest -S`, `ninja -f`, `go run` / `go generate`, `cargo
    // build` (the package's build.rs), `rustup run`, `run-parts <dir>`, and
    // the like; `npm` and `cargo` are consumer-table programs (`.npmrc`,
    // `.cargo/credentials`) that run the package's code, served the twin as
    // node is (decision (b))
    "cmake", "ctest", "cpack", "ninja", "samu", "go", "cargo", "rustup", "bazel", "bazelisk", "buck", "buck2", "please",
    "just", "task", "mage", "xmake", "premake", "qmake", "qtchooser", "bmake", "pmake", "remake", "gn",
    "scons", "meson", "muon", "gradle", "mvn", "ant", "sbt", "rake", "npm", "corepack", "pnpx",
    "nix", "nix-shell", "nix-build", "nix-instantiate", "guix", "dotnet", "terraform", "tofu", "packer", "podman", "buildah",
    "run-parts", "at", "batch",
    // more language runtimes and REPLs
    "nodejs", "pypy", "pypy3", "jython", "ipython", "irb", "erb", "jruby", "php-cgi", "php-fpm", "raku", "rakudo", "perl6", "hy",
    "erl", "erlexec", "beam", "escript", "elixir", "iex", "mix", "ocaml", "ocamlrun", "utop", "swipl", "gprolog",
    "sbcl", "clisp", "ecl", "csi", "gsi", "scheme", "chez", "chezscheme", "petite", "raco",
    "kotlin", "scala", "groovy", "clojure", "clj", "bb", "jrunscript", "mono", "runghc", "runhaskell", "ghci",
    "nim", "crystal", "zig", "dart", "swift", "tcc", "qjs", "gjs", "gforth", "wasmtime", "wasmer",
    "dc", "bc", "octave", "octave-cli", "gnuplot", "maxima",
    // more shells
    "rbash", "yash", "posh", "elvish", "nushell", "xonsh", "osh", "ysh",
    // the names these install as (P0 item 14, 2026-10-07): nushell's binary,
    // the public-domain ksh line (OpenBSD's ksh ported), Racket's two builds
    "nu", "oksh", "loksh", "pdksh", "racketbc", "racketcs",
    // TeX engines (`\write18`, `\directlua`)
    "tex", "etex", "pdftex", "xetex", "luatex", "luahbtex", "luajittex", "latex", "pdflatex", "xelatex", "lualatex", "mpost", "context", "mtxrun",
];

/// Programs whose job is to copy or print bytes. Twin of
/// arbiter/policy/flow-taint.ts `PRINTER_READERS` (Plan 13 D8, printers admit
/// nothing, the maintainer's decision of 2026-10-03; pinned equal by
/// tests/stack/reader-identity.test.ts). The arbiter judges every file open
/// with it; the guard judges the ssh-agent socket's readers with it
/// (leftover (3b) of !437): a printer that connects to the socket (`socat`,
/// `openssl s_client -unix`) relays the agent to whatever drives it, the
/// agent's own code included, so a printer named there admits nothing.
pub const PRINTER_READERS: &[&str] = &[
    // print or page a file
    "cat", "tac", "head", "tail", "less", "more", "most", "pg", "nl", "rev", "pr", "pv", "bat", "batcat",
    "zless", "zmore", "bzless", "bzmore", "xzless", "xzmore", "zstdless", "lzless", "lzmore",
    // copy a file
    "tee", "dd", "cp", "install", "rsync", "socat", "xclip", "xsel", "wl-copy",
    // encode or dump its bytes
    "base64", "base32", "basenc", "uuencode", "uudecode", "xxd", "od", "hexdump", "hd", "hexyl", "strings",
    // filter, reorder or reshape its lines
    "sed", "awk", "gawk", "mawk", "nawk", "cut", "paste", "join", "sort", "uniq", "shuf", "tr", "fold", "fmt", "column",
    "expand", "unexpand", "look", "tsort", "ptx", "split", "csplit",
    "grep", "egrep", "fgrep", "rg", "ag", "ack", "zgrep", "zegrep", "zfgrep", "xzgrep", "bzgrep", "zstdgrep",
    // compare (prints the differing lines or bytes)
    "diff", "diff3", "sdiff", "cmp", "comm", "colordiff", "wdiff", "zdiff", "zcmp", "xzdiff", "xzcmp", "bzdiff", "bzcmp",
    // convert its encoding or line ends
    "iconv", "recode", "uconv", "dos2unix", "unix2dos", "mac2unix", "unix2mac",
    // compress or archive
    "gzip", "gunzip", "zcat", "pigz", "unpigz", "bzip2", "bunzip2", "bzcat", "pbzip2", "xz", "unxz", "xzcat", "pixz",
    "lzma", "unlzma", "lzcat", "lzip", "lzop", "lz4", "unlz4", "lz4cat", "zstd", "unzstd", "zstdcat", "zstdmt", "brotli",
    "tar", "gtar", "bsdtar", "bsdcat", "bsdcpio", "zip", "unzip", "funzip", "7z", "7za", "7zr", "cpio", "pax", "ar",
    // structured data processors
    "jq", "gojq", "jaq", "yq", "xq", "tomlq", "dasel", "gron", "mlr", "xmllint", "xmlstarlet", "envsubst",
    // crypto tools that print or transform (`openssl s_client -unix` also
    // relays a Unix socket)
    "openssl", "gpg", "gpg2",
    // editors that show the file on the terminal the agent reads
    "nano", "pico", "micro",
    // multi-call binaries
    "busybox", "toybox", "coreutils",
    // fetch or transfer a URL or a file, a local one included (the !437
    // leftover (1)): `curl file:///…`, `wget -i <file>`, `scp a b`, `gio cat`
    "curl", "curlie", "wget", "wget2", "aria2c", "http", "https", "xh", "xhs", "lftp", "rclone", "scp", "sftp",
    "gio", "gvfs-cat", "gvfs-copy", "kioclient", "kioclient5", "kioclient6", "lynx", "w3m", "links", "links2", "elinks",
    // the Postgres client tools that print a file (probed 2026-10-04 against a
    // throwaway server: `psql -f <file>` and `\i <file>` / `\copy t from
    // <file>` on its standard input print the file's lines; `pg_restore -f -
    // <dump>` prints the dump as SQL): plan 13 D8 (12). psql also runs a shell
    // command it is given (`\!`, a backquoted `\set`). pg_dump prints no file
    // (a `--filter` file's well-formed patterns echo when unmatched only).
    "psql", "pg_restore",
    // the other SQL and database shells (2026-10-07, P0 (D)), by their
    // documented commands: each prints a file it is pointed at and runs a
    // command or code it is given, from its command line, its standard input
    // or an rc file the agent can write (`~/.my.cnf`'s `[mysql] pager=`,
    // `~/.duckdbrc`, `~/.mongoshrc.js`), as psql does: mysql's and mariadb's
    // `source <file>` (the server's error quotes the lines) and `\!` / `pager`;
    // mysqlsh's `\source` and `\system`; duckdb's `.read`, `.shell` and
    // `read_text('<file>')`; usql's `\i` and `\!`; sqlcmd's `:r` and `!!`;
    // sqlplus's `@<file>` and `HOST`; clickhouse's `file('<file>')` table
    // function; the MongoDB shells' `cat('<file>')` and `load()` (JavaScript).
    // Unprobed (none installed on the probe host): listed fail-closed
    "mysql", "mariadb", "mysqlsh", "duckdb", "usql", "sqlcmd", "sqlplus", "clickhouse", "clickhouse-client", "clickhouse-local",
    "mongosh", "mongo",
    // read names, dates or hosts from a file and print each one it cannot
    // use (2026-10-04): `file -f <file>` ("<line>: cannot open"), `date -f`,
    // `wc` / `du --files0-from=<file>`, `logger -s -f`, `ssh-keyscan -f`
    "file", "date", "wc", "du", "logger", "ssh-keyscan",
    // typeset or format a document or a manual page, whose text is the
    // output (`nroff <file>`, `man -l <file>`, `ul`), or echo the lines they
    // reject (`tic <file>`, `whatis -C <file>`); `scriptreplay` replays one
    "groff", "nroff", "troff", "preconv", "soelim", "zsoelim", "tbl", "eqn", "neqn", "pic", "refer", "grn", "grotty", "mandoc",
    "man", "whatis", "apropos", "lexgrog", "ul", "colcrt", "tic", "scriptreplay",
    // compile, assemble or link: `cpp <file>` and `cc -E` print it, an
    // `@<file>` response file comes back word by word in the errors (gcc,
    // clang, binutils), `objcopy -I binary <file> /dev/stdout` copies it,
    // `objdump -s -b binary` dumps it, a parser generator quotes what it
    // rejects; gettext's catalog tools print the catalog (`msgcat <file>`)
    "cpp", "cc", "c++", "gcc", "g++", "cc1", "cc1plus", "collect2", "clang", "clang++", "clang-cpp", "rustc",
    "as", "ld", "gold", "nm", "ranlib", "c++filt", "objcopy", "objdump", "readelf", "size", "strip", "elfedit", "gprof", "addr2line",
    "bison", "yacc", "byacc", "rpcgen",
    "msgcat", "msguniq", "msgconv", "msggrep", "msgattrib", "msgen", "msgmerge", "msginit", "msgcomm", "msgfilter", "msgexec",
    "msgfmt", "msgunfmt", "xgettext",
    // git (plan 13 §4.9 option (a), 2026-10-04): `git diff --no-index
    // /dev/null <file>`, `git grep --no-index`, `git config -f <file>
    // --list`; its credential helper (git itself under that name) and its
    // HTTP transport, and (2026-10-07) the programs git builds on their own
    // that read `.netrc` through libcurl or send a file named by a request.
    // git never connects to the ssh-agent socket (its ssh does: `{ app:
    // ssh, from: git }`)
    "git", "git-credential-store", "git-remote-http", "git-remote-https", "git-remote-ftp", "git-remote-ftps",
    "git-http-fetch", "git-http-push", "git-imap-send", "git-http-backend",
];

/// Twin of arbiter/policy/flow-taint.ts `VETTED_READERS` (Plan 13 D8 (12),
/// the allow-list, the maintainer's decision of 2026-10-04; pinned equal by
/// tests/stack/reader-identity.test.ts): the programs probed not to print a
/// file they are pointed at. On the ssh-agent socket's list a reader that is
/// not one connects only when its entry carries the human's word.
pub const VETTED_READERS: &[&str] = &["ssh", "ssh-add"];

/// Is this program name (a basename or a path) a vetted reader? Its
/// basename exactly or through an alternatives suffix, and never a printer
/// or a program that runs code. Twin of flow-taint.ts `readerVetted`.
pub fn vetted(name: &str) -> bool {
    if admits_nothing(name) {
        return false;
    }
    let base = basename(name);
    VETTED_READERS.iter().any(|v| app_name_matches(base, v))
}

/// Twin of flow-taint.ts `MULTICALL_PRINTER_DIRS`: uutils coreutils picks its
/// program from argv[0], so every file there is `cat` and `env` whatever its
/// name.
const MULTICALL_DIRS: &[&str] = &["/usr/lib/cargo/bin/coreutils/"];

/// Twin of flow-taint.ts `READER_NAME_PREFIXES`: Ubuntu 26.04's GNU coreutils
/// are `gnucat`, `gnuenv`, …; Homebrew's `gcat`, `genv`, `gmake`; some
/// packages name uutils' programs `uu-cat` / `uu_env`.
const READER_NAME_PREFIXES: &[&str] = &["gnu", "g", "uu-", "uu_"];

/// Does `name` (a basename or a path) name a program of `list`, by an
/// alternatives suffix (`app_name_matches`), under a distribution's prefix,
/// or as a file of a multi-call binary's directory?
fn names_one_of(name: &str, list: &[&str]) -> bool {
    if MULTICALL_DIRS.iter().any(|d| name.starts_with(d)) {
        return true;
    }
    let base = basename(name);
    // A prefix alone names no program (`gnu` is not `g` + `nu`).
    let bare_prefix = READER_NAME_PREFIXES.contains(&base);
    let stripped = READER_NAME_PREFIXES.iter().filter(|_| !bare_prefix).filter_map(|p| base.strip_prefix(p).filter(|rest| !rest.is_empty()));
    let forms: Vec<&str> = std::iter::once(base).chain(stripped).collect();
    let unversioned: Vec<&str> = forms.iter().filter_map(|n| without_version(n)).collect();
    forms.iter().chain(unversioned.iter()).any(|n| list.iter().any(|l| app_name_matches(n, l)))
}

/// Twin of flow-taint.ts `withoutVersion`: the name without a trailing
/// version after a letter (`php8.5` → `php`, `lua5.4` → `lua`, `gcc-15` →
/// `gcc`), or None. `app_name_matches` takes only a dot suffix.
fn without_version(name: &str) -> Option<&str> {
    let head = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    let version = &name[head.len()..];
    if version.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) || version.split('.').any(|p| p.is_empty()) {
        return None;
    }
    let head = head.strip_suffix('-').or_else(|| head.strip_suffix('_')).unwrap_or(head);
    head.ends_with(|c: char| c.is_ascii_alphabetic() || c == '+').then_some(head)
}

/// Does this program name (a basename, or a path) run code it is given?
/// Twin of flow-taint.ts `readerRunsCode`.
pub fn runs_code(name: &str) -> bool {
    names_one_of(name, CODE_RUNNING_READERS)
}

/// Does this program name (a basename, or a path) print or copy bytes?
/// Twin of flow-taint.ts `readerPrints`.
pub fn prints(name: &str) -> bool {
    names_one_of(name, PRINTER_READERS) || printer_prefixed(name)
}

/// Twin of flow-taint.ts `PRINTER_NAME_PREFIXES` (2026-10-07): a git
/// credential helper of any name prints the password it reads (`get`
/// answers `password=…`), so `git-credential-<anything>` is a printer.
pub const PRINTER_NAME_PREFIXES: &[&str] = &["git-credential-"];

/// Does `name` (a basename or a path), or its form under a distribution's
/// prefix, start with a printer prefix and carry something after it?
fn printer_prefixed(name: &str) -> bool {
    let base = basename(name);
    let stripped = READER_NAME_PREFIXES.iter().filter_map(|p| base.strip_prefix(p).filter(|rest| !rest.is_empty()));
    std::iter::once(base)
        .chain(stripped)
        .any(|n| PRINTER_NAME_PREFIXES.iter().any(|p| n.len() > p.len() && n.starts_with(p)))
}

/// A reader name that admits nothing on the socket's list: it runs code it
/// is given (Plan 13 §8 decision (b)) or prints / relays what it reads (Plan
/// 13 D8, printers admit nothing; leftover (3b) of !437).
pub fn admits_nothing(name: &str) -> bool {
    runs_code(name) || prints(name)
}

/// The reader a connecting process matches, or None (refuse). `exe` is the
/// resolved executable; `exe_trusted` says it is out of the agent's reach and
/// runs with a clean loader environment (Plan 13 D8, `reader_identity`): a
/// socket reader is a NAME, so only a binary the agent cannot have written,
/// started without the agent's preload, may carry it. `ancestors` are
/// (resolved executable, trusted) pairs, nearest first; `from:` counts only
/// under a trusted ancestor of that name (a basename alone is the program's
/// choice: a copy of sh may be called anything). Pure.
pub fn socket_reader_match<'a>(readers: &'a [ReaderSpec], exe: &str, exe_trusted: bool, ancestors: &[(String, bool)]) -> Option<&'a str> {
    if !exe_trusted {
        return None;
    }
    let base = basename(exe);
    // Plan 13 §8 decision (b): a shell or an interpreter runs whatever the
    // agent hands it, so neither it nor an entry naming one is a reader.
    // Plan 13 D8, printers admit nothing (leftover (3b) of !437): nor a
    // printer or a relay (`socat`, `nc`, `openssl`), which hands the agent's
    // signing to whatever drives it. The executable is judged by its path
    // too (a uutils multi-call file is every program of the set).
    if admits_nothing(exe) {
        return None;
    }
    for r in readers {
        let (app, from, word) = match r {
            ReaderSpec::Name(n) => (n.as_str(), None, false),
            ReaderSpec::Pin { app, from, prints } => (app.as_str(), from.as_deref(), prints.as_deref() == Some("nothing")),
        };
        if admits_nothing(app) || !app_name_matches(base, app) {
            continue;
        }
        // Plan 13 D8 (12), the allow-list: a program that is not vetted
        // connects only when its entry carries the human's word.
        if !word && !vetted(exe) {
            continue;
        }
        if let Some(f) = from {
            if !ancestors.iter().any(|(a, trusted)| *trusted && app_name_matches(basename(a), f)) {
                continue;
            }
        }
        return Some(app);
    }
    None
}

/// The arbiter's word on a secret socket's reader binary (`readerProgram`:
/// `(prints, runsCode)`, judged by name and by the hashes of the host's
/// installed programs, as every other reader list is; Plan 13 D8, 2026-10-03).
/// Only a binary the arbiter found to be neither a printer nor a program
/// that runs code may connect; no answer (the arbiter unreachable, no hash)
/// refuses. Pure.
pub fn socket_identity_admits(answer: Option<(bool, bool)>) -> bool {
    matches!(answer, Some((false, false)))
}

/// `p` with its longest existing prefix canonicalized (symlinks resolved) and
/// the rest kept as given: a protected directory that does not exist yet
/// (`~/.config/autostart`) keeps the spelling it will have. Absolute paths.
pub fn resolve_existing(p: &str) -> String {
    let path = std::path::Path::new(p);
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cur = path;
    loop {
        if let Ok(real) = fs::canonicalize(cur) {
            let mut out = real;
            for c in rest.iter().rev() {
                out.push(c);
            }
            return out.to_string_lossy().into_owned();
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                cur = parent;
            }
            _ => return p.to_string(),
        }
    }
}

/// `p` with its directory resolved (`resolve_existing`) and its last
/// component kept as written: the entry itself, a link included.
pub fn resolve_dir_keep_name(p: &str) -> String {
    let (dir, last) = split_last(p);
    if last.is_empty() || dir.is_empty() {
        return p.to_string();
    }
    let d = resolve_existing(dir);
    format!("{}/{}", d.trim_end_matches('/'), last)
}

/// The lookup the notification path uses: canonical real path → entry.
#[derive(Debug, Default)]
pub struct SecretIndex {
    by_path: HashMap<String, SecretEntry>,
    /// `(st_dev, st_ino)` → registered path, each registered file `stat`ed
    /// (refreshed at most every `ID_REFRESH`): the same file under another
    /// name is the same secret. A hard link (`ln ~/.aws/credentials x`) and a
    /// different-case spelling on a filesystem that folds case (WSL's drvfs:
    /// `.AWS/CREDENTIALS`) open the registered inode, which neither the path
    /// map nor the twin bind (a mount on one dentry) catches.
    by_id: Mutex<Option<IdList>>,
    /// 2026-10-16 (`inode_pins`): each registered protected file held by an
    /// `O_PATH` descriptor from the policy's load (`enable_pins`), so its
    /// `(dev, ino)` is its own for the whole session, whatever directory it
    /// is moved with; refreshed at every identity-list rebuild.
    pins: crate::inode_pins::PinSet,
    /// 2026-10-16: in-memory path aliases (alias → registered path) for
    /// files a folder rename moved and could not move back (`add_alias`).
    aliases: Mutex<HashMap<String, String>>,
    /// The end-of-session notice of moved files whose label could not
    /// follow (`SecretPolicyFile::moved_notice`, `note_moved_unlabelled`).
    moved_notice: Option<Mutex<std::fs::File>>,
    /// The registered paths lower-cased: an open whose spelling folds to one
    /// of them (or whose file has another link) re-`stat`s the registered
    /// files at once instead of trusting a list up to `ID_REFRESH` old.
    folded: std::collections::HashSet<String>,
    sockets: HashMap<String, SocketSecret>,
    /// policy.yaml `protect:` (absolute paths, resolved where they exist).
    pub protect: Vec<String>,
    /// `SecretPolicyFile::deny_prefixes`, resolved where they exist.
    pub deny_prefixes: Vec<String>,
    /// `SecretPolicyFile::deny_except`, resolved where they exist.
    pub deny_except: Vec<String>,
    /// `SecretPolicyFile::write_protect`, each path resolved as far as it
    /// exists (`resolve_existing`).
    pub write_protect: Vec<WriteProtect>,
    /// `SecretPolicyFile::unix_policy`, paths resolved as far as they exist.
    pub unix_policy: Option<UnixPolicy>,
    /// `SecretPolicyFile::unix_deny`: each entry as written AND resolved as
    /// far as it exists (both spellings are denied).
    pub unix_deny: Vec<String>,
    pub agent_exe: String,
    pub ask: Option<String>,
    pub session: Option<String>,
    pub ask_timeout_ms: u64,
    /// The final components of the registered paths: the stat trap's
    /// prefilter (`stat_twin::StatNames`).
    pub stat_names: crate::stat_twin::StatNames,
    /// Plan 14 §11.1 R4: the locked objects, `None` when the launch knows
    /// none.
    pub git_locks: Option<crate::git_lock::GitLockGuard>,
    /// Plan 13 D8 (`reader_identity`): who an opener is. The launch's own
    /// loader / interpreter environment (the guard's, handed to the agent
    /// unchanged) as the allowlist, the agent's uid and groups for the
    /// out-of-reach test, executable hashes by inode (never by path: a path
    /// renamed over after the exec would keep the old file's hash).
    pub identity: crate::reader_identity::IdentityCtx,
    /// Confidentiality plan 13 D4: the derived labels the guard gates at the
    /// open, kept current from the arbiter (`derived_index`).
    pub derived: crate::derived_index::DerivedIndex,
    /// 2026-10-17 (confidentiality.md §6): where the human labels lie, so a
    /// labelled file the launch did not register is gated at the open too,
    /// kept current from the arbiter (`label_index`).
    pub labels: crate::label_index::LabelIndex,
    /// The directory of the policy file this index was loaded from: the
    /// launch's own, where the twins of derived files are made
    /// (`derived-twins/`). None for an index built in memory.
    pub policy_dir: Option<std::path::PathBuf>,
    /// `SecretPolicyFile::trust_lookups`.
    pub trust_lookups: Vec<crate::visible_mounts::TrustLookup>,
}

/// Now as ns since the epoch (the derived index's clock).
pub fn now_ns() -> i128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as i128).unwrap_or(0)
}

impl SecretIndex {
    pub fn from_file(file: SecretPolicyFile) -> Self {
        let mut by_path = HashMap::new();
        let mut folded = std::collections::HashSet::new();
        let stat_names = crate::stat_twin::StatNames::new(file.secrets.iter().map(|e| e.path.as_str()));
        for e in file.secrets {
            folded.insert(e.path.to_lowercase());
            by_path.insert(e.path.clone(), e);
        }
        let mut sockets = HashMap::new();
        for s in file.sockets {
            if let Some(real) = fs::canonicalize(&s.path).ok().and_then(|p| p.to_str().map(String::from)) {
                sockets.insert(real, s.clone());
            }
            sockets.insert(s.path.clone(), s);
        }
        let resolved = |v: &[String]| -> Vec<String> { v.iter().map(|p| fs::canonicalize(p).ok().and_then(|r| r.to_str().map(String::from)).unwrap_or_else(|| p.clone())).collect() };
        let protect = resolved(&file.protect);
        let deny_prefixes = resolved(&file.deny_prefixes);
        let deny_except = resolved(&file.deny_except);
        let write_protect = file
            .write_protect
            .into_iter()
            .map(|w| {
                // A `name`/`prefix`/`self` entry names its last component as
                // written: only its directory is resolved (resolving `current`
                // would protect the instance it points at, not the link).
                let path = if w.form() == WriteForm::Path { resolve_existing(&w.path) } else { resolve_dir_keep_name(&w.path) };
                WriteProtect { path, except: w.except.iter().map(|x| resolve_existing(x)).collect(), ..w }
            })
            .collect();
        let unix_policy = file.unix_policy.map(|u| UnixPolicy { allow: u.allow.into_iter().map(|a| UnixAllow { path: resolve_existing(&a.path), ..a }).collect(), ..u });
        let mut unix_deny: Vec<String> = Vec::new();
        for d in file.unix_deny.iter().filter(|d| d.starts_with('/') && d.trim_end_matches('/') != "") {
            for spelling in [d.trim_end_matches('/').to_string(), resolve_existing(d)] {
                if !unix_deny.contains(&spelling) {
                    unix_deny.push(spelling);
                }
            }
        }
        let git_locks = file.git_locks.and_then(|g| {
            let (set, bad) = crate::git_lock::LockedSet::from_ids(g.ids.iter().map(String::as_str));
            if !bad.is_empty() {
                crate::diag!("mandu-net-guard: {} locked object id(s) not understood, ignored: {}", bad.len(), bad.join(", "));
            }
            (!set.is_empty()).then(|| crate::git_lock::GitLockGuard::new(set, g.notice_file))
        });
        SecretIndex { by_path, by_id: Mutex::new(None), pins: crate::inode_pins::PinSet::default(), aliases: Mutex::new(HashMap::new()), moved_notice: file.moved_notice.as_deref().and_then(crate::git_lock::open_notice).map(Mutex::new), folded, sockets, protect, deny_prefixes, deny_except, write_protect, unix_policy, unix_deny, agent_exe: file.agent_exe, ask: file.ask, session: file.session, ask_timeout_ms: file.ask_timeout_ms.unwrap_or(60_000), stat_names, git_locks, identity: crate::reader_identity::IdentityCtx::current(), derived: crate::derived_index::DerivedIndex::new(now_ns()), labels: crate::label_index::LabelIndex::default(), policy_dir: None, trust_lookups: file.trust_lookups }
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = fs::read_to_string(path)?;
        let file: SecretPolicyFile = serde_json::from_str(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let mut idx = Self::from_file(file);
        idx.policy_dir = path.parent().map(Path::to_path_buf);
        // 2026-10-17: the guard's own twins are never gated as catalog files
        // (their names repeat the files they stand for): the launch's, and
        // the directory of the ones it makes (`derived-twins/`).
        let canon = |p: &Path| fs::canonicalize(p).ok().and_then(|c| c.to_str().map(String::from));
        let files: Vec<String> = idx.by_path.values().filter(|e| !e.twin.is_empty()).filter_map(|e| canon(Path::new(&e.twin))).collect();
        let dirs: Vec<String> = idx.policy_dir.as_deref().and_then(canon).map(|d| format!("{}/derived-twins", d.trim_end_matches('/'))).into_iter().collect();
        idx.labels.set_exclude(files, dirs);
        Ok(idx)
    }

    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty() && self.sockets.is_empty() && self.protect.is_empty() && self.deny_prefixes.is_empty() && self.write_protect.is_empty() && self.unix_policy.is_none() && self.unix_deny.is_empty() && self.git_locks.is_none()
    }

    /// The locked objects, when the launch knows any (plan 14 §11.1 R4).
    pub fn git_locks(&self) -> Option<&crate::git_lock::GitLockGuard> {
        self.git_locks.as_ref().filter(|g| !g.is_empty())
    }

    /// The `unixDeny` entry a Unix connect target falls under (`unix_denied`,
    /// identities read now), or None.
    pub fn unix_denied_now(&self, seen: Option<&str>, target: Option<(u64, u64)>) -> Option<&str> {
        unix_denied(&self.unix_deny, seen, target, ids_under_dir)
    }

    /// The deny prefix that hides a path, carve-outs honoured (`hidden_by`).
    pub fn denied_prefix(&self, path: &str) -> Option<&str> {
        hidden_by(&self.deny_prefixes, &self.deny_except, path)
    }

    /// The socket secret a connect targets, by the path as given or resolved.
    pub fn socket(&self, path: &str) -> Option<&SocketSecret> {
        if let Some(s) = self.sockets.get(path) {
            return Some(s);
        }
        let real = fs::canonicalize(path).ok()?;
        self.sockets.get(real.to_str()?)
    }

    /// Are any files registered as secrets? (A rename source or destination,
    /// a hard-link source, a removed name or a truncate target that is one is
    /// refused even with no write-protect list; `registered_secret_refuses`.)
    pub fn has_registered_secrets(&self) -> bool {
        !self.by_path.is_empty()
    }

    /// Are any sockets registered as secrets?
    pub fn has_sockets(&self) -> bool {
        !self.sockets.is_empty()
    }

    /// The socket secret whose file IS this inode (`id` = `(st_dev, st_ino)`
    /// of the target the guard opened itself), by the path the kernel reports
    /// for it (`seen`) or by identity: each registered socket is `stat`ed now
    /// (`stat`), so a hardlink or a symlink swapped in after the open cannot
    /// hide it (guard_kernel's supervised Unix connect).
    pub fn socket_for_inode(&self, seen: Option<&str>, id: (u64, u64), stat: impl Fn(&str) -> Option<(u64, u64)>) -> Option<&SocketSecret> {
        if let Some(s) = seen.and_then(|p| self.sockets.get(p)) {
            return Some(s);
        }
        self.sockets.iter().find(|(p, _)| stat(p) == Some(id)).map(|(_, s)| s)
    }

    /// The entry for a canonical path, trying the path as given, then its
    /// filesystem-resolved form (a symlinked spelling of a registered file),
    /// then the file's identity (`lookup_with`).
    pub fn lookup(&self, canonical: &str) -> Option<&SecretEntry> {
        self.lookup_with(canonical, file_id)
    }

    /// `lookup` with the file identity supplied (`FileId`, following
    /// symlinks): a path that names a registered file's inode is that secret
    /// whatever it is called (a hard link, a different-case spelling on a
    /// case-folding filesystem). The registered files' identities are
    /// re-`stat`ed at most every `ID_REFRESH`, and at once when the opened
    /// file looks like another name for one of them (it has another link, or
    /// its spelling folds to a registered path) and the list does not know it:
    /// a credential file an editor just replaced is never missed that way. A
    /// hit from a list not just built stands only for an inode unchanged
    /// since it was listed or one the registered path (or its twin) still
    /// names: a removed file's inode number reused by a new file is never
    /// taken for it (`by_identity`, `stale_hit_stands`).
    pub fn lookup_with(&self, canonical: &str, id: impl Fn(&str) -> Option<FileId>) -> Option<&SecretEntry> {
        if let Some(e) = self.by_path.get(canonical) {
            return Some(self.held_elsewhere(canonical, || id(canonical).map(|i| i.key())).unwrap_or(e));
        }
        let real = fs::canonicalize(canonical).ok().and_then(|p| p.to_str().map(String::from));
        if let Some((r, e)) = real.as_deref().and_then(|r| self.by_path.get(r).map(|e| (r, e))) {
            return Some(self.held_elsewhere(r, || id(r).map(|i| i.key())).unwrap_or(e));
        }
        if self.by_path.is_empty() {
            return None;
        }
        if let Some(e) = self.alias_of(canonical).or_else(|| real.as_deref().and_then(|r| self.alias_of(r))) {
            return Some(e);
        }
        let spelling = real.as_deref().unwrap_or(canonical);
        let seen = id(spelling)?;
        self.by_identity(canonical, spelling, seen, id)
    }

    /// The entry for a file the guard OPENED itself (confidentiality-plan-10
    /// §4.1a: the guard performs every read-capable open): by the path the
    /// tracee named (`spelling`, lexical), then by the opened file's identity
    /// (`seen`, from `fstat` of that descriptor: the file actually opened,
    /// whatever path games led to it). A twin's inode is its secret's entry
    /// too, so a reader under the twin bind is still recognized.
    pub fn lookup_opened(&self, spelling: &str, seen: FileId, id: impl Fn(&str) -> Option<FileId>) -> Option<&SecretEntry> {
        if let Some(e) = self.by_path.get(spelling) {
            return Some(self.held_elsewhere(spelling, || Some(seen.key())).unwrap_or(e));
        }
        if self.by_path.is_empty() {
            return None;
        }
        if let Some(e) = self.alias_of(spelling) {
            return Some(e);
        }
        self.by_identity(spelling, spelling, seen, id)
    }

    /// 2026-10-16 (review of !1603): a path that matched the registered entry
    /// `hit` names a file whose inode the guard holds for ANOTHER registered
    /// path Q (a folder rename put Q's file at `hit`'s path, and could not
    /// be undone): that entry is Q's. The inode is the stronger evidence (a
    /// held inode's number is never reused, the path is only where the file
    /// lies now), and Q's entry is the one that decides who may read those
    /// bytes and where they may go; `hit`'s readers and destinations never
    /// apply to Q's bytes. `key` is asked only with pinning on.
    fn held_elsewhere(&self, hit: &str, key: impl FnOnce() -> Option<(u64, u64)>) -> Option<&SecretEntry> {
        if !self.pins.is_on() {
            return None;
        }
        let k = key()?;
        let q = self.pins.path_of(k)?;
        if q == hit {
            return None;
        }
        let eq = self.by_path.get(&q)?;
        // Q's own path still names this inode: `hit` and Q are two
        // registered names of ONE file (a hard link both were registered
        // by), only one of them carries the pin, and both entries are that
        // file's own: the stricter decides, the same whichever name was
        // pinned first (`stricter_entry`). Else the file left Q's path for
        // `hit`'s: its rule is Q's.
        if file_id(&q).is_some_and(|i| i.key() == k) {
            let eh = self.by_path.get(hit)?;
            return Some(stricter_entry(eh, eq));
        }
        Some(eq)
    }

    /// The entry an in-memory path alias names (`add_alias`).
    fn alias_of(&self, path: &str) -> Option<&SecretEntry> {
        let reg = self.aliases.lock().unwrap_or_else(|p| p.into_inner()).get(path).cloned()?;
        self.by_path.get(&reg)
    }

    /// Tell the person, at the end of the session, that the protected file
    /// `from` now lies at `to` with no label there (2026-10-16: its label
    /// could not be recorded and the rename could not be undone; the next
    /// session would not know the new path). One `<from>\t<to>` line in the
    /// notice file (fields on one line, `git_lock::notice_field`).
    pub fn note_moved_unlabelled(&self, from: &str, to: &str) {
        if let Some(f) = self.moved_notice.as_ref() {
            use std::io::Write;
            let line = format!("{}\t{}\n", crate::git_lock::notice_field(from), crate::git_lock::notice_field(to));
            let _ = f.lock().unwrap_or_else(|p| p.into_inner()).write_all(line.as_bytes());
        }
    }

    /// Know `alias` as the registered file `registered` for the rest of the
    /// session (2026-10-16: a folder rename that moved it and could not be
    /// undone). `false` when `registered` is no registered path.
    pub fn add_alias(&self, alias: &str, registered: &str) -> bool {
        if !self.by_path.contains_key(registered) {
            return false;
        }
        self.aliases.lock().unwrap_or_else(|p| p.into_inner()).insert(alias.to_string(), registered.to_string());
        true
    }

    /// The identity list as of now: re-`stat`ed when `ID_REFRESH` old
    /// (`true`: it was).
    fn id_list(&self, cache: &mut Option<IdList>, id: &impl Fn(&str) -> Option<FileId>, force: bool) -> bool {
        let stale = force || cache.as_ref().map(|l| l.at.elapsed() >= ID_REFRESH).unwrap_or(true);
        if stale {
            *cache = Some(IdList::of(&self.by_path, id));
            // The strictest name first: when two registered names are one file
            // (a hard link), the pin carries the one that decides
            // (`stricter_entry`), the same at every rebuild.
            let mut entries: Vec<&SecretEntry> = self.by_path.values().filter(|e| crate::inode_pins::pinned_kind(e.kind.as_deref())).collect();
            entries.sort_by(|a, b| if std::ptr::eq(stricter_entry(a, b), *a) { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater });
            self.pins.refresh(entries.into_iter().map(|e| e.path.as_str()));
        }
        stale
    }

    /// 2026-10-16 (`inode_pins`): hold every registered protected file by its
    /// inode from now on, `budget` descriptors at most, and take the first
    /// pins at once (the guard calls this after loading the policy, before
    /// it answers the agent's first trapped call). Returns (held, unpinned).
    pub fn enable_pins(&self, budget: usize) -> (usize, usize) {
        self.pins.enable(budget);
        let mut cache = self.by_id.lock().unwrap_or_else(|p| p.into_inner());
        self.id_list(&mut cache, &file_id, true);
        drop(cache);
        (self.pins.held(), self.pins.unpinned().len())
    }

    /// Rebuild the identity list and the pins now (`inode_pins`), when pinning
    /// is on: the guard calls this before it performs a rename of a
    /// directory, so a protected file replaced since the last rebuild (an
    /// editor's save through a rename) is held before a folder above it can
    /// move.
    pub fn refresh_pins(&self) {
        if !self.pins.is_on() {
            return;
        }
        let mut cache = self.by_id.lock().unwrap_or_else(|p| p.into_inner());
        self.id_list(&mut cache, &file_id, true);
    }

    /// The registered protected files (every kind `inode_pins::pinned_kind`
    /// holds) below the directory `dir` (2026-10-16: their labels follow a
    /// folder moved above them).
    pub fn protected_under(&self, dir: &str) -> Vec<String> {
        let d = format!("{}/", dir.trim_end_matches('/'));
        let mut v: Vec<String> = self.by_path.iter().filter(|(p, e)| p.starts_with(&d) && crate::inode_pins::pinned_kind(e.kind.as_deref())).map(|(p, _)| p.clone()).collect();
        v.sort();
        v
    }

    /// Is `path` a registered path (any kind)?
    pub fn is_registered(&self, path: &str) -> bool {
        self.by_path.contains_key(path)
    }

    /// Is the file now at `now_at` the registered file `dest` itself, by its
    /// held inode (`inode_pins`), so that a rename putting it at `dest` puts
    /// a registered file back at its own path? `false` when `dest` is no
    /// registered path, nothing regular is at `now_at`, or its inode is not
    /// the one held for `dest`.
    pub fn is_held_at_home(&self, now_at: &str, dest: &str) -> bool {
        use std::os::unix::fs::MetadataExt;
        if !self.by_path.contains_key(dest) {
            return false;
        }
        let Ok(m) = fs::metadata(now_at) else { return false };
        m.is_file() && self.pins.path_of((m.dev(), m.ino())).as_deref() == Some(dest)
    }

    /// Is inode pinning on (`enable_pins`)?
    pub fn pins_on(&self) -> bool {
        self.pins.is_on()
    }

    /// A rename that moves directories (`moves`: each `(old dir, new dir)`,
    /// both ways for an exchange), run so no pinned-kind registered file is
    /// left unheld below them (2026-10-16, `inode_pins`). Under the identity
    /// lock (a lookup that misses the pins waits for it, then asks them
    /// again): the pins are brought up to date, `rename` runs, and every
    /// registered file that was below a moved directory is held at its new
    /// path. A file saved over its registered path between the rebuild and
    /// the rename (a person's editor, outside the agent's tree) is held this
    /// way too. A file there that cannot be held makes the call `undo` the
    /// rename and answer EACCES; an undo that fails leaves the rename
    /// standing (0), every moved file known by its new path for the session
    /// (`add_alias`). Returns the errno (0 = renamed). With pinning off, or
    /// nothing registered below, `rename` alone runs.
    ///
    /// The lock is held across the rename itself, so a lookup that misses the
    /// pins waits for it; when the tracee is in a Landlock sandbox the rename
    /// runs on its mirror, and a busy mirror pool makes that wait longer
    /// (`landlock_mirror`): a stall of identity lookups, never a deadlock
    /// (the mirror's threads take no guard lock).
    pub fn rename_dirs_holding_pins(&self, moves: &[(String, String)], rename: impl FnOnce() -> i32, undo: impl FnOnce() -> i32) -> i32 {
        if !self.pins.is_on() {
            return rename();
        }
        let mut cache = self.by_id.lock().unwrap_or_else(|p| p.into_inner());
        self.id_list(&mut cache, &file_id, true);
        let affected: Vec<(String, String)> = self
            .by_path
            .iter()
            .filter(|(_, e)| crate::inode_pins::pinned_kind(e.kind.as_deref()))
            .flat_map(|(p, _)| moves.iter().filter_map(move |(o, n)| crate::inode_pins::moved_path(p, o, n).map(|m| (p.clone(), m))))
            .collect();
        let rc = rename();
        if rc != 0 || affected.is_empty() {
            return rc;
        }
        if affected.iter().all(|(p, m)| self.pins.pin_moved(p, m)) {
            return 0;
        }
        if undo() == 0 {
            return libc::EACCES;
        }
        // The undo failed (the agent can make a name again where the folder
        // was: mkdir is not trapped): the rename stands, and every file it
        // moved is known by its new path for the rest of the session.
        for (p, m) in &affected {
            self.add_alias(m, p);
        }
        drop(cache);
        0
    }

    /// The registered protected files that exist and are not held
    /// (`inode_pins`: past the budget, or their open failed): a rename of a
    /// directory above one is refused.
    pub fn unpinned(&self) -> Vec<String> {
        self.pins.unpinned()
    }

    /// The identity half of `lookup_with` / `lookup_opened`: the registered
    /// files' (and their twins') `(dev, ino)`, re-`stat`ed at most every
    /// `ID_REFRESH`, and at once for a suspicious miss.
    fn by_identity(&self, canonical: &str, spelling: &str, seen: FileId, id: impl Fn(&str) -> Option<FileId>) -> Option<&SecretEntry> {
        // A held inode (`inode_pins`) is exact: its number cannot be reused
        // while the guard holds it, and it is that registered file under
        // whatever name reaches it now (a renamed parent directory).
        if let Some(p) = self.pins.path_of(seen.key()) {
            if let Some(e) = self.by_path.get(&p) {
                return Some(e);
            }
        }
        // A poisoned lock (a panicked worker) still holds a usable map.
        let mut cache = self.by_id.lock().unwrap_or_else(|p| p.into_inner());
        // Asked again under the lock: a directory rename holds it until the
        // files it moved are held (`rename_dirs_holding_pins`).
        if let Some(p) = self.pins.path_of(seen.key()) {
            if let Some(e) = self.by_path.get(&p) {
                return Some(e);
            }
        }
        let fresh = self.id_list(&mut cache, &id, false);
        let look = |c: &Option<IdList>| c.as_ref().and_then(|l| l.ids.get(&seen.key()).cloned());
        let mut hit = look(&cache);
        // 2026-10-16: a hit from a list up to `ID_REFRESH` old is checked
        // before it is trusted (`stale_hit_stands`). A registered file
        // removed since the list was built (git's repack removing a twinned
        // pack, its prune removing a loose object) frees its inode NUMBER,
        // and the next file created on that filesystem may get it: matched
        // against the old list, a brand-new unrelated file was that entry,
        // and its create was refused (an object entry's write: EACCES) or
        // its read was given a twin. A hit stands when the registered path
        // or its twin still has that identity, or when the opened file's
        // status-change time is the one listed (the same inode, unchanged:
        // a name the guard did not see move, such as a renamed parent
        // directory, keeps the hit until the next rebuild, as before);
        // otherwise the list is rebuilt now and the file judged against it.
        let unconfirmed = !fresh && hit.as_ref().is_some_and(|(p, ctime)| !stale_hit_stands(*ctime, seen.ctime_ns, || self.still_names(p, seen.key(), &id)));
        let suspicious = seen.links > 1 || self.folded.contains(&spelling.to_lowercase()) || self.folded.contains(&canonical.to_lowercase());
        if unconfirmed || (hit.is_none() && !fresh && suspicious) {
            self.id_list(&mut cache, &id, true);
            hit = look(&cache);
        }
        drop(cache);
        self.by_path.get(&hit?.0)
    }

    /// Does the registered file at `path`, or its twin, still have the
    /// identity `key` (one `stat` each, as `IdList::of` takes them)? A
    /// registered path with no entry is not confirmed.
    fn still_names(&self, path: &str, key: (u64, u64), id: &impl Fn(&str) -> Option<FileId>) -> bool {
        let Some(e) = self.by_path.get(path) else { return false };
        id(path).is_some_and(|i| i.key() == key) || id(&e.twin).is_some_and(|i| i.key() == key)
    }

    /// P0 4c (2026-10-09): has a registered file a hard link besides its
    /// registered name (`st_nlink > 1`)? Then another name may reach it
    /// without a symlink, and the stat trap resolves an `lstat` of another
    /// leaf too (`stat_twin::stat_probe`). From the identity list, at most
    /// `ID_REFRESH` old: the guard refuses a link made in the session, so
    /// the count grows only from outside the agent's tree. No registered
    /// file: false.
    pub fn any_linked(&self, id: impl Fn(&str) -> Option<FileId>) -> bool {
        if self.by_path.is_empty() {
            return false;
        }
        let mut cache = self.by_id.lock().unwrap_or_else(|p| p.into_inner());
        self.id_list(&mut cache, &id, false);
        cache.as_ref().is_some_and(|l| l.linked)
    }
}

/// Of two entries for one file (two registered names of one inode), the one
/// that decides: the stricter level (no-model above local-model above
/// any-model, an unknown level strictest), then the protected-file kind
/// over any other, then the smaller path, so the answer never depends on
/// which name was pinned first. Pure.
pub fn stricter_entry<'a>(a: &'a SecretEntry, b: &'a SecretEntry) -> &'a SecretEntry {
    let rank = |l: &str| match l {
        "no-model" => 3,
        "local-model" => 2,
        "any-model" => 1,
        _ => 4,
    };
    let key = |e: &SecretEntry| (rank(&e.level), matches!(e.kind.as_deref(), None | Some("file")), std::cmp::Reverse(e.path.clone()));
    if key(a) >= key(b) { a } else { b }
}

/// Does a hit from an identity list that was not just built stand
/// (`SecretIndex::by_identity`, 2026-10-16)? Yes when the opened file's
/// status-change time is the one listed for that identity (the same inode,
/// unchanged since it was listed, whatever name reaches it now), else when
/// the registered path or its twin still has that identity (`still_names`,
/// asked only then). A file created since, on a removed entry's reused
/// inode number, has neither. Pure given `still_names`.
pub fn stale_hit_stands(listed_ctime_ns: i128, seen_ctime_ns: i128, still_names: impl FnOnce() -> bool) -> bool {
    listed_ctime_ns == seen_ctime_ns || still_names()
}

/// The registered files' identities (`SecretIndex::by_identity`): `(dev,
/// ino)` of each file and of its twin → the registered path and the
/// status-change time the inode had then, when taken, and whether a
/// registered file has another link.
#[derive(Debug)]
struct IdList {
    at: std::time::Instant,
    ids: HashMap<(u64, u64), (String, i128)>,
    linked: bool,
}

impl IdList {
    fn of(by_path: &HashMap<String, SecretEntry>, id: &impl Fn(&str) -> Option<FileId>) -> IdList {
        let mut ids: HashMap<(u64, u64), (String, i128)> = HashMap::new();
        let mut linked = false;
        for (p, e) in by_path {
            if let Some(i) = id(&e.twin) {
                ids.insert(i.key(), (p.clone(), i.ctime_ns));
            }
            if let Some(i) = id(p) {
                ids.insert(i.key(), (p.clone(), i.ctime_ns));
                linked |= i.links > 1;
            }
        }
        IdList { at: std::time::Instant::now(), ids, linked }
    }
}

/// How long the registered files' identities are trusted before a lookup
/// re-`stat`s them (`SecretIndex::lookup_with`).
pub const ID_REFRESH: std::time::Duration = std::time::Duration::from_secs(2);

/// `(st_dev, st_ino)` and the link count of the file a path names,
/// following symlinks. Only a regular file's links say "another name for
/// it": a directory always has two or more, and counting those forced a full
/// re-`stat` of the registered files on every directory open.
pub fn file_id(path: &str) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).ok().map(|m| FileId { dev: m.dev(), ino: m.ino(), links: if m.is_file() { m.nlink() } else { 1 }, ctime_ns: ctime_ns(m.ctime(), m.ctime_nsec()) })
}

/// A status-change time as one number of nanoseconds.
pub fn ctime_ns(sec: i64, nsec: i64) -> i128 {
    sec as i128 * 1_000_000_000 + nsec as i128
}

/// A file's identity as `lookup_with` compares it, plus its link count and
/// its status-change time (`stale_hit_stands`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
    pub links: u64,
    pub ctime_ns: i128,
}

impl FileId {
    pub fn key(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }
}

/// Hex sha256 of a file's bytes.
pub fn sha256_file(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = fs::read(path).ok()?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// The (dirfd, path pointer, flags) of an open-family syscall, or None for a
/// number this module does not decode (`openat2` carries its flags in a
/// struct; the handler answers ENOSYS so libc falls back to `openat`).
pub fn decode_open_args(nr: i64, args: &[u64; 6]) -> Option<(i32, u64, i32)> {
    if nr == libc::SYS_openat as i64 {
        return Some((args[0] as i32, args[1], args[2] as i32));
    }
    #[cfg(target_arch = "x86_64")]
    if nr == libc::SYS_open as i64 {
        return Some((libc::AT_FDCWD, args[0], args[1] as i32));
    }
    None
}

/// The open family the guard traps (arch-specific, like `delete_nrs`: the
/// legacy `open` exists on x86_64 only; aarch64's generic ABI has just
/// `openat`/`openat2`, so nothing opens a file around this list there).
pub fn open_nrs() -> Vec<i64> {
    let mut v = vec![libc::SYS_openat as i64, libc::SYS_openat2 as i64];
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_open as i64);
    v
}

/// Is this an open-family syscall number?
pub fn is_open_nr(nr: i64) -> bool {
    open_nrs().contains(&nr)
}

/// Is this an exec-family syscall number (plan 10 §4.2: the tree's roots)?
pub fn is_exec_nr(nr: i64) -> bool {
    nr == libc::SYS_execve as i64 || nr == libc::SYS_execveat as i64
}

/// The argv pointer argument of an exec syscall.
pub fn exec_argv_ptr(nr: i64, args: &[u64; 6]) -> Option<u64> {
    if nr == libc::SYS_execve as i64 {
        Some(args[1])
    } else if nr == libc::SYS_execveat as i64 {
        Some(args[2])
    } else {
        None
    }
}

/// Which HOST pids a process number names when the tracee spells it
/// (§4.1's targets: `/proc/<n>/…`, `ptrace(n, …)`). The taint set is keyed by
/// host pids, and a number is its pid namespace's: under the whole-agent
/// wrap's `--unshare-pid` the agent's 2 is not the host's 2. `depth`: the
/// pid-namespace level the number belongs to (0: the guard's own, so the
/// number is the host's); None: unknown (a procfs the check cannot reach),
/// any level below ours. `tree`: the guard's descendants with their numbers
/// per level (`NSpid`, outermost first). `same`: an exact identity check
/// (start time) where one is possible. Several answers where two sibling
/// namespaces reuse a number: the caller refuses if any is tainted. PURE.
pub fn host_pids_named(n: i32, depth: Option<usize>, tree: &[(i32, Vec<i32>)], same: impl Fn(i32) -> bool) -> Vec<i32> {
    if depth == Some(0) {
        return vec![n];
    }
    tree.iter()
        .filter(|(_, levels)| match depth {
            Some(d) => levels.get(d) == Some(&n),
            None => levels.iter().skip(1).any(|v| *v == n),
        })
        .map(|(h, _)| *h)
        .filter(|h| same(*h))
        .collect()
}

/// The thread group (`Tgid:`) a `/proc/<tid>/status` names. Pure.
pub fn tgid_from_status(status: &str) -> Option<i32> {
    status.lines().find_map(|l| l.strip_prefix("Tgid:")).and_then(|v| v.trim().parse().ok())
}

/// The thread group of a thread id (a seccomp notification names the calling
/// THREAD). Itself when it is a leader, or when `/proc` cannot say.
pub fn tgid_of(tid: i32) -> i32 {
    fs::read_to_string(format!("/proc/{tid}/status")).ok().as_deref().and_then(tgid_from_status).unwrap_or(tid)
}

/// The proc key of the PROCESS a thread belongs to (exec-routing.md §7.5,
/// 2026-10-01). A notification names the calling thread, and a worker
/// thread's own `<tid>-<its start>` key is no key the taint set or the
/// arbiter knows: a reader whose worker thread opened the secret (Node's
/// `fs.readFile`, on the libuv pool) was tainted under that thread's key,
/// and its main thread's connects were judged as an untainted process's;
/// the other way round, a worker thread's connect (glibc's resolver under
/// Node's `dns.lookup`, Bun's HTTP client) of a reader tainted on its main
/// thread was judged untainted too, since a thread's parent is the process's
/// parent, not its leader. Every key of the taint leg is the thread group's:
/// `<tgid>-<the leader's start>`, which is also what the process's key is
/// after an exec from any thread (the exec'ing thread takes the leader's pid
/// and start time).
pub fn own_key_of(pid: i32) -> String {
    let tgid = tgid_of(pid);
    mandu_arbiter::proc::proc_key_for_pid(tgid).unwrap_or_else(|| tgid.to_string())
}

/// The parent pid from `/proc/<pid>/status` (`PPid:`), for the lineage edge.
pub fn parent_pid_of(pid: i32) -> Option<i32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// The ancestor proc keys of `pid`, nearest first, up to `max` levels (pid 1
/// and the guard's own ancestors excluded by the caller's policy: the chain
/// simply stops at an unreadable or init process).
pub fn ancestor_keys_of(pid: i32, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = pid;
    for _ in 0..max {
        let Some(pp) = parent_pid_of(cur) else { break };
        if pp <= 1 {
            break;
        }
        match mandu_arbiter::proc::proc_key_for_pid(pp) {
            Some(k) => out.push(k),
            None => break,
        }
        cur = pp;
    }
    out
}

/// Plan 13 D7: the live ancestor chain of `pid` the arbiter records as
/// lineage edges (at every exec and every secret open), nearest first,
/// stopped BELOW the calling process (the guard: it and everything above it
/// belong to no tool call), at init, or at an unreadable process; at most 32
/// levels. A subshell forked without an exec has no event of its own; the
/// first exec or open below it reports it here, while it is still alive.
pub fn lineage_chain_of(pid: i32) -> Vec<String> {
    // SAFETY: getpid has no failure mode.
    let me = unsafe { libc::getpid() };
    let mut out = Vec::new();
    let mut cur = pid;
    for _ in 0..32 {
        let Some(pp) = parent_pid_of(cur) else { break };
        if !crate::lineage::chain_continues(pp, me) {
            break;
        }
        match mandu_arbiter::proc::proc_key_for_pid(pp) {
            Some(k) => out.push(k),
            None => break,
        }
        cur = pp;
    }
    out
}

/// What an exec's record names of the exec'ing process (plan 10 §4.2, plan
/// 13 D7): its own key (`own_key_of`), its live ancestor chain
/// (`lineage_chain_of`) and its parent's key (the chain's first, else
/// `parent_key_of`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecLineage {
    pub own: String,
    pub ancestors: Vec<String>,
    pub parent_key: Option<String>,
}

/// `PPid:` from a `/proc/<pid>/status` (`parent_pid_of`'s field). Pure.
pub fn ppid_from_status(status: &str) -> Option<i32> {
    status.lines().find_map(|l| l.strip_prefix("PPid:")).and_then(|v| v.trim().parse().ok())
}

/// The start time (field 22, `proc_key_for_pid`'s parse) and the parent
/// (field 4) from one `/proc/<pid>/stat` line: the start None when it does
/// not parse, the parent None when only it does not. Pure.
pub fn stat_start_and_ppid(stat: &str) -> (Option<u64>, Option<i32>) {
    let start = mandu_arbiter::proc::parse_starttime_from_stat(stat);
    let ppid = stat.rfind(')').and_then(|c| stat.get(c + 1..)).and_then(|rest| rest.split_whitespace().nth(1)).and_then(|v| v.parse().ok());
    (start, ppid)
}

/// `lineage_chain_of`'s walk from the exec'ing process's parent `first`,
/// with `stat(p)` the `(start, ppid)` of process `p` (`stat_start_and_ppid`
/// of its `/proc/<p>/stat`): each ancestor's key and the next parent come
/// from the SAME read. It stops where `lineage_chain_of` stops: below
/// `guard`, at init, at a process whose start cannot be read, after 32
/// levels, and where the next parent is unknown. Pure.
pub fn chain_from(first: Option<i32>, guard: i32, stat: impl Fn(i32) -> (Option<u64>, Option<i32>)) -> Vec<String> {
    let mut out = Vec::new();
    let mut next = first;
    for _ in 0..32 {
        let Some(pp) = next else { break };
        if !crate::lineage::chain_continues(pp, guard) {
            break;
        }
        let (start, ppid) = stat(pp);
        let Some(start) = start else { break };
        out.push(mandu_arbiter::proc::proc_key_from(pp, start));
        next = ppid;
    }
    out
}

/// `own_key_of`, `lineage_chain_of` and the parent's key of `pid` in one
/// walk (runtime-instances.md §14.8, 2026-10-18), the same answer from fewer
/// `/proc` reads: the thread's `status` once (its `Tgid:` and `PPid:`; the
/// three separate calls read it three times), its process's `stat` for the
/// start, and one `stat` per ancestor for both its start and ITS parent
/// (`stat`'s field 4 is the value `status` prints as `PPid:`; the separate
/// walk read each ancestor's `status` too). Read while the tracee is
/// suspended, as before; an ancestor's key and its parent now come from one
/// read, so no exit between two reads can pair them across two processes.
pub fn exec_lineage_of(pid: i32) -> ExecLineage {
    // SAFETY: getpid has no failure mode.
    let me = unsafe { libc::getpid() };
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok();
    let tgid = status.as_deref().and_then(tgid_from_status).unwrap_or(pid);
    let own = mandu_arbiter::proc::proc_key_for_pid(tgid).unwrap_or_else(|| tgid.to_string());
    let ppid = status.as_deref().and_then(ppid_from_status);
    let ancestors = chain_from(ppid, me, |p| fs::read_to_string(format!("/proc/{p}/stat")).map(|s| stat_start_and_ppid(&s)).unwrap_or((None, None)));
    let parent_key = ancestors.first().cloned().or_else(|| ppid.filter(|p| *p > 1).and_then(mandu_arbiter::proc::proc_key_for_pid));
    ExecLineage { own, ancestors, parent_key }
}

/// May the guard serve a registered entry's twin with the descriptor the
/// tracee's OWN path reaches (plan 10 §4.1; differential-interactive.md §20)?
/// Only when that file IS the twin (`seen == twin`, by `(st_dev, st_ino)`):
/// the bind posture, where the twin is mounted over the real path in the
/// agent's namespace. Such a descriptor names the path the agent named, as
/// an open under the bind alone does; the twin opened by its own path names
/// `<scope>/secret-twins/NNN-name`. Claude Code resolves a path with Bun's
/// `realpathSync` (an `O_PATH` open + `readlink /proc/self/fd/N`) before it
/// asks, and its Read tool refuses a file whose opened descriptor names
/// another path than the one it checked, so every open of one file must
/// name the same path: the file's own under the bind, the twin's without
/// it. A write-intent open never takes this road (the twin by its own path,
/// as before). Pure.
pub fn view_reaches_twin(write_intent: bool, seen: Option<(u64, u64)>, twin: Option<(u64, u64)>) -> bool {
    !write_intent && seen.is_some() && seen == twin
}

/// Is `flags` a write-intent open (the filesystem exit of plan 10 §4)?
pub fn is_write_intent(flags: i32) -> bool {
    let acc = flags & libc::O_ACCMODE;
    acc == libc::O_WRONLY || acc == libc::O_RDWR || (flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND)) != 0
}

/// Does a descriptor with these status flags (`F_GETFL`) hold its file open
/// for writing? The kernel refuses to exec a file while any open file
/// description holds it so (ETXTBSY), and ADDFD hands the tracee the guard's
/// own description, so such a descriptor is closed before the tracee resumes
/// (`guard_kernel::hand_over`). An `O_PATH` descriptor holds nothing. Pure.
pub fn holds_for_writing(status_flags: i32) -> bool {
    status_flags & libc::O_PATH == 0 && status_flags & libc::O_ACCMODE != libc::O_RDONLY
}

/// Is this exec the enforce-clean box's applier (exec-output-trust §4 rung 2:
/// `mandu-landlock-apply --clean …`)? The exec-box interposes it between
/// bwrap and the command, so the process that execs it, and everything it
/// forks, IS the clean box. A secret open inside that subtree is refused by
/// the guard without an ask (guard_kernel::handle_open_notif): the box may
/// read only its verified roots (a raw descriptor injected there would hand
/// it a file outside that set), and the clean attempt of a command that
/// touches a secret always falls back to the ordinary rerun, which asks
/// once. Before this (2026-09-24, drill S7) the clean-box `cat` consumed the
/// human's once-answer and the rerun's fresh hold timed out unanswered.
/// Spoofable only towards a denial: a tree that execs a look-alike applier
/// denies itself.
pub fn is_clean_box_exec(argv: &[String]) -> bool {
    let Some(arg0) = argv.first() else { return false };
    let base = arg0.rsplit('/').next().unwrap_or(arg0);
    base == "mandu-landlock-apply" && argv[1..].iter().any(|a| a == "--clean")
}

/// The guard's own memory of which processes it handed raw bytes to (by proc
/// key), so a WRITE by one of them, or by a descendant, is labeled without a
/// round trip per write. Descendants are found by walking `/proc` parents.
/// (Also the shape of the clean-box set: the processes that exec'd the
/// enforce-clean applier, `is_clean_box_exec`.)
///
/// A descendant found through its ancestors is REMEMBERED under its own key,
/// with the chain it was found through (exec-routing.md §7.5, 2026-10-01): a
/// tainted shell's subshell that outlives it is reparented (to the wrap's pid
/// 1, or the guard as subreaper), and a walk of its parents no longer meets
/// the shell. A process the guard judged once as a holder stays one, and the
/// arbiter is asked with the chain that made it one.
///
/// Since 2026-10-02 (exec-routing.md §7.5, "A fork after the taint") each
/// entry also keeps when it became a holder, when its trapped exit took a
/// snapshot of its descendants, and when it was seen gone; an orphan whose
/// parents no longer lead to a holder inherits from every holder that died
/// while it lived (`holds_or_inherits`, `lineage::in_window`). The set also
/// knows the reapers an orphan is re-parented to (`add_reaper`).
///
/// Since 2026-10-09 (`death_watch`) a holder's death is stamped when it
/// happens, through a pidfd, with the 200 ms poll as the fallback; and at the
/// stamp, the processes that the death made orphans (re-parented to a reaper,
/// born in the holder's window) are recorded as holders flowing from it
/// (`adopt_orphans`).
#[derive(Debug, Default)]
pub struct TaintedSet {
    /// key → what is known of that holder.
    keys: Mutex<std::collections::HashMap<String, Held>>,
    /// Proc keys of the processes that reap orphans in the tree besides pid 1
    /// and a pid namespace's init: the guard (the tree's subreaper) and every
    /// process that made itself a subreaper (`prctl`, trapped).
    reapers: Mutex<std::collections::HashSet<String>>,
    /// Plan 13 D2: the descriptor links (`pipe:[ino]`, a FIFO's path, a
    /// socket pair end's `socket:[ino]`) a holder wrote into, with the keys
    /// whose taint they carry. Kept after the writer exits: a receiver that
    /// joins or acts later is judged by them.
    links: Mutex<std::collections::HashMap<String, Vec<String>>>,
    /// Plan 13 §4.9 (2026-10-03, `guard_wait`): the waiters whose sweep at a
    /// wait refused (an unbound connection): recorded as holders all the
    /// same, so they never count as already covering what they reap.
    wait_refused: Mutex<std::collections::HashSet<String>>,
    /// The pidfd watcher that stamps a holder's death when it happens
    /// (`enable_death_watch`); unset in tests and where it cannot start.
    #[cfg(target_os = "linux")]
    deaths: std::sync::OnceLock<std::sync::Arc<crate::death_watch::DeathWatch>>,
    /// Held from taking the deaths a pidfd reports to the end of their
    /// stamps (`stamp_ready_deaths`): a caller that finds a death already
    /// taken by another thread waits here until it is stamped.
    #[cfg(target_os = "linux")]
    stamping: Mutex<()>,
}

/// One holder, as `TaintedSet` keeps it.
#[derive(Debug, Clone, Default)]
struct Held {
    /// The ancestor chain it inherited through (empty: tainted itself).
    chain: Vec<String>,
    /// Plan 13 D2 (2026-10-02): holders whose taint reached it NOT through
    /// its parents: the writers of a pipe, FIFO or unnamed socket pair it
    /// reads from (`pipe_flow`), and the lost holders of an orphan. Handed
    /// to the arbiter as `flowsFrom` (the union of their taint), never as
    /// lineage edges, which would record a parent the process never had.
    flows: Vec<String>,
    /// Clock ticks since boot from which it is a holder (the start of its
    /// orphans' window): its read for a direct reader, its birth for one
    /// recorded as a descendant or an orphan (`inherit`), the recording for
    /// a descriptor's receiver.
    since: u64,
    /// When it was seen gone (the end of its orphans' window): the earliest
    /// of the looks that found it dead (its pidfd's report, the poll, a
    /// judgement), each taken AFTER the death, so never earlier than it.
    gone_at: Option<u64>,
    /// It read a secret itself (`insert`), whatever it also inherits or
    /// flows from: one of the holders `taint_sources` names (§4.1).
    direct: bool,
    /// Its live ancestors (proc keys, nearest first) when it became a
    /// holder: no process among them can be its orphan (`orphan_holders`).
    ancestors: Vec<String>,
}

/// A holder whose death was just stamped, for `adopt_orphans`.
struct DeadHolder {
    key: String,
    since: u64,
    until: u64,
    ancestors: Vec<String>,
}

/// Is `ancestor` on `pid`'s parent chain (at most 64 levels up)?
fn descends_from(pid: i32, ancestor: i32) -> bool {
    let mut cur = pid;
    for _ in 0..64 {
        let Some(st) = read_stat(cur) else { return false };
        if st.ppid == ancestor {
            return true;
        }
        if st.ppid <= 1 {
            return false;
        }
        cur = st.ppid;
    }
    false
}

/// The live ancestors of the process `key` names, when it is still that
/// process (its start time); empty otherwise (a synthetic key, a process
/// gone). Read when a key becomes a holder.
fn ancestors_now(key: &str) -> Vec<String> {
    let Some((pid, start)) = crate::lineage::parse_key(key) else { return Vec::new() };
    if read_stat(pid).map(|s| s.start) != Some(start) {
        return Vec::new();
    }
    ancestor_keys_of(pid, 32)
}

/// When the window of a holder recorded as a descendant or an orphan starts
/// (`TaintedSet::inherit`): its key's start time, or now if that is earlier
/// or the key names none. Pure but for the clock.
fn born_or_now(key: &str) -> u64 {
    let now = now_ticks();
    crate::lineage::parse_key(key).map_or(now, |(_, start)| start.min(now))
}

/// Clock ticks since boot (the unit of `/proc/<pid>/stat`'s start time), now.
pub fn now_ticks() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime into a local.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    // SAFETY: sysconf has no failure mode that matters here (100 if unknown).
    let hz = match unsafe { libc::sysconf(libc::_SC_CLK_TCK) } {
        n if n > 0 => n as u64,
        _ => 100,
    };
    (ts.tv_sec as u64) * hz + (ts.tv_nsec as u64) * hz / 1_000_000_000
}

fn read_stat(pid: i32) -> Option<crate::lineage::ProcStat> {
    fs::read_to_string(format!("/proc/{pid}/stat")).ok().as_deref().and_then(crate::lineage::parse_stat)
}

impl TaintedSet {
    pub fn insert(&self, key: &str) {
        let ancestors = if self.contains(key) { Vec::new() } else { ancestors_now(key) };
        if !self.contains(key) {
            crate::guard_trace::trace(|| format!("holder {key}: direct (ancestors {ancestors:?})"));
        }
        if let Ok(mut s) = self.keys.lock() {
            let h = s.entry(key.to_string()).or_insert_with(|| Held { since: now_ticks(), ancestors, ..Default::default() });
            h.direct = true;
        }
        self.watch_death(key);
    }
    /// Start stamping holders' deaths when they happen (`death_watch`): a
    /// pidfd per holder, up to `cap` at once, for every holder recorded from
    /// now on. Without it (or past `cap`, or with no `pidfd_open`) the 200 ms
    /// poll (`observe_deaths`) stamps them, as before. Idempotent.
    #[cfg(target_os = "linux")]
    pub fn enable_death_watch(self: &std::sync::Arc<Self>, cap: usize) -> bool {
        if self.deaths.get().is_some() {
            return true;
        }
        let weak = std::sync::Arc::downgrade(self);
        match crate::death_watch::DeathWatch::start(cap, move |_| match weak.upgrade() {
            Some(set) => {
                set.stamp_ready_deaths();
                true
            }
            None => false,
        }) {
            Some(w) => {
                let _ = self.deaths.set(w);
                // The holders recorded before the watcher ran (a guard that
                // judged a call before it started): watched now, a dead
                // one reported at once.
                let living: Vec<String> = match self.keys.lock() {
                    Ok(s) => s.iter().filter(|(_, h)| h.gone_at.is_none()).map(|(k, _)| k.clone()).collect(),
                    Err(_) => Vec::new(),
                };
                for k in living {
                    self.watch_death(&k);
                }
                true
            }
            None => false,
        }
    }
    /// Stamp now the holders whose pidfd already reports their exit
    /// (`DeathWatch::take_ready`), with no wait. The guard calls it as each
    /// trapped call arrives, before judging it: a call the tree makes after
    /// a holder's death is answered only after that death is stamped, so a
    /// process the call's caller starts afterwards is born after the stamp
    /// and is no orphan of the holder, however late the watcher's own
    /// thread runs under load (2026-10-09, exec-routing.md §7.5 (d)).
    ///
    /// The watcher's thread takes them through here too, and a death is
    /// taken and stamped under one lock (`stamping`): a call that arrives
    /// while the thread has taken a death but not yet stamped it waits for
    /// that stamp rather than finding nothing ready and going on. Nothing
    /// ready: one uncontended lock and one non-blocking epoll look.
    pub fn stamp_ready_deaths(&self) {
        #[cfg(target_os = "linux")]
        if let Some(w) = self.deaths.get() {
            let _held = self.stamping.lock();
            let ready = w.take_ready();
            if !ready.is_empty() {
                self.stamp_deaths(&ready);
            }
        }
    }
    /// Watch `key`'s death, when the watcher runs (`enable_death_watch`).
    /// A key whose process is already gone (`Watch::Gone`: it exited before
    /// it was recorded, or its number names another process) is stamped at
    /// once, with a time read after that look, rather than at the next poll.
    fn watch_death(&self, key: &str) {
        #[cfg(target_os = "linux")]
        if let Some(w) = self.deaths.get() {
            if w.watch(key) == crate::death_watch::Watch::Gone {
                self.stamp_deaths(&[(key.to_string(), now_ticks())]);
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = key;
    }
    /// The holders whose death the watcher reported at `t` (each `(key, t)`):
    /// `gone_at` becomes the earliest look that found it dead, then the
    /// processes its death made orphans are recorded (`adopt_orphans`).
    /// Every stamp passed here was taken after the death it reports.
    pub fn stamp_deaths(&self, stamps: &[(String, u64)]) {
        let mut dead: Vec<DeadHolder> = Vec::new();
        if let Ok(mut s) = self.keys.lock() {
            for (k, t) in stamps {
                if let Some(h) = s.get_mut(k) {
                    let first = h.gone_at.is_none();
                    h.gone_at = Some(crate::lineage::earliest_stamp(h.gone_at, *t));
                    if first {
                        dead.push(DeadHolder { key: k.clone(), since: h.since, until: h.gone_at.unwrap_or(*t), ancestors: h.ancestors.clone() });
                    }
                }
            }
        }
        if !dead.is_empty() {
            self.adopt_orphans(&dead);
        }
    }
    /// At a holder's death, the processes it made orphans: every process of
    /// this process's tree (the guard's: its descendants) whose parent is a
    /// reaper (`is_reaper`), not yet a holder, born in a dead holder's window
    /// and not one of its ancestors (`lineage::orphan_of`) inherits from it
    /// (`insert_flow`, as `holds_or_inherits` does at a judgement). Recorded
    /// now, while it lives: an orphan that forks and dies before any trapped
    /// call leaves its own child an orphan root born after the holder died,
    /// which the holder's exact window no longer reaches; with the orphan
    /// recorded (and its own death watched), that child is born in the
    /// orphan's window and inherits.
    fn adopt_orphans(&self, dead: &[DeadHolder]) {
        let me = std::process::id() as i32;
        let Ok(dir) = fs::read_dir("/proc") else { return };
        for e in dir.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else { continue };
            if pid == me {
                continue;
            }
            let Some(st) = read_stat(pid) else { continue };
            if !self.is_reaper(st.ppid) || !descends_from(pid, me) {
                continue;
            }
            let own = own_key_of(pid);
            if self.contains(&own) {
                continue;
            }
            let from: Vec<(String, Vec<String>)> = dead
                .iter()
                .filter(|d| match crate::lineage::parse_key(&d.key) {
                    Some((_, start)) => crate::lineage::orphan_of(st.start, start, d.since, d.until, d.ancestors.contains(&own)),
                    None => false,
                })
                .map(|d| (d.key.clone(), self.chain_of(&d.key).unwrap_or_default()))
                .collect();
            if from.is_empty() {
                continue;
            }
            let sources = self.flow_sources(&from);
            self.inherit(&own, &ancestor_keys_of(pid, 16));
            self.insert_flow(&own, &sources);
        }
    }
    /// The holders whose taint `key` carries (§4.1, 2026-10-02): the keys
    /// that read a secret themselves (`insert`) among `key` itself, the
    /// holders on its chain and the ones it flows from, followed through
    /// their own chains and flows. Sorted; empty when the set knows nothing
    /// `key` carries.
    pub fn taint_sources(&self, key: &str) -> Vec<String> {
        let Ok(s) = self.keys.lock() else { return Vec::new() };
        let mut out: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut todo = vec![key.to_string()];
        while let Some(k) = todo.pop() {
            if seen.len() > 4096 || !seen.insert(k.clone()) {
                continue;
            }
            let Some(h) = s.get(&k) else { continue };
            if h.direct {
                out.push(k.clone());
            }
            todo.extend(h.chain.iter().cloned());
            todo.extend(h.flows.iter().cloned());
        }
        out.sort();
        out
    }
    /// Remember a descendant of a tainted process under its own key, with the
    /// chain (nearest first) through which it inherits. A key tainted itself
    /// keeps its empty chain.
    ///
    /// Its window (`since`) starts at its own birth, not when the guard
    /// first saw it (2026-10-09): a descendant (or an orphan, which the
    /// backstop records through here too) carries the taint from its fork,
    /// and a child it forked before the guard recorded it, orphaned when it
    /// dies, is born in that window. Starting it at the recording left that
    /// child outside every window: the kernel test's round (c) leaked once
    /// in 102 runs when the adoption at the holder's death came late, after
    /// the adopted orphan had forked its child. An earlier start only widens
    /// the window (fail-closed); its own ancestors stay outside it
    /// (`lineage::orphan_of`: born no earlier than it).
    pub fn inherit(&self, key: &str, chain: &[String]) {
        if !self.contains(key) {
            crate::guard_trace::trace(|| format!("holder {key}: inherits (chain {chain:?})"));
        }
        if let Ok(mut s) = self.keys.lock() {
            s.entry(key.to_string()).or_insert_with(|| Held { chain: chain.to_vec(), since: born_or_now(key), ancestors: chain.to_vec(), ..Default::default() });
        }
        self.watch_death(key);
    }
    /// Plan 13 D2: `key` holds what `from` held, through a descriptor (or
    /// as an orphan of `from`). Remembered under its own key; `from` adds to
    /// what it already flows from.
    pub fn insert_flow(&self, key: &str, from: &[String]) {
        let ancestors = if self.contains(key) { Vec::new() } else { ancestors_now(key) };
        crate::guard_trace::trace(|| format!("holder {key}: flows from {from:?}"));
        if let Ok(mut s) = self.keys.lock() {
            let h = s.entry(key.to_string()).or_insert_with(|| Held { since: now_ticks(), ancestors, ..Default::default() });
            for f in from {
                if f != key && !h.flows.contains(f) {
                    h.flows.push(f.clone());
                }
            }
        }
        self.watch_death(key);
    }
    /// The keys whose taint reaches `own` other than through its parents:
    /// the flows of `own` and of every holder on its `chain` (a child of a
    /// pipe reader holds what the pipe carried). Empty for the common case.
    pub fn flows_for(&self, own: &str, chain: &[String]) -> Vec<String> {
        let Ok(s) = self.keys.lock() else { return Vec::new() };
        let mut out: Vec<String> = Vec::new();
        for k in std::iter::once(own).chain(chain.iter().map(String::as_str)) {
            if let Some(h) = s.get(k) {
                for f in &h.flows {
                    if !out.contains(f) {
                        out.push(f.clone());
                    }
                }
            }
        }
        out
    }
    /// What a process that receives from `writers` flows from: each writer,
    /// the holders on its chain, and what each of them flows from (so the
    /// arbiter's union needs no lineage edge the guard never reported).
    pub fn flow_sources(&self, writers: &[(String, Vec<String>)]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let add = |k: &str, out: &mut Vec<String>| {
            if !out.iter().any(|o| o == k) {
                out.push(k.to_string());
            }
        };
        for (w, chain) in writers {
            add(w, &mut out);
            for k in chain {
                if self.contains(k) {
                    add(k, &mut out);
                }
            }
            for f in self.flows_for(w, chain) {
                add(&f, &mut out);
            }
        }
        out
    }
    /// Plan 13 D2: `link` carries what `from` holds.
    pub fn mark_link(&self, link: &str, from: &[String]) {
        if let Ok(mut l) = self.links.lock() {
            let e = l.entry(link.to_string()).or_default();
            for f in from {
                if !e.contains(f) {
                    e.push(f.clone());
                }
            }
        }
    }
    /// What the marked links among `links` carry (empty: none marked).
    pub fn link_flows(&self, links: &[String]) -> Vec<String> {
        let Ok(l) = self.links.lock() else { return Vec::new() };
        let mut out: Vec<String> = Vec::new();
        for k in links {
            for f in l.get(k).into_iter().flatten() {
                if !out.contains(f) {
                    out.push(f.clone());
                }
            }
        }
        out
    }
    /// Plan 13 §9 R1, the file shapes (`object_flow`): is any file object or
    /// SysV segment marked as written by a holder? None: an untainted
    /// process's later event reads no object of its own.
    pub fn has_object_marks(&self) -> bool {
        self.links.lock().map(|l| l.keys().any(|k| crate::object_flow::is_object_key(k))).unwrap_or(true)
    }
    /// The pids of the holders recorded under their own key that are still
    /// alive (start time checked), for the later-event pipe check.
    pub fn live_holder_pids(&self) -> Vec<i32> {
        let keys: Vec<String> = match self.keys.lock() {
            Ok(s) => s.iter().filter(|(_, h)| h.gone_at.is_none()).map(|(k, _)| k.clone()).collect(),
            Err(_) => return Vec::new(),
        };
        keys.iter()
            .filter_map(|k| crate::lineage::parse_key(k).map(|(pid, _)| (pid, k)))
            .filter(|(_, k)| !key_gone(k))
            .map(|(pid, _)| pid)
            .collect()
    }
    pub fn contains(&self, key: &str) -> bool {
        self.keys.lock().map(|s| s.contains_key(key)).unwrap_or(false)
    }
    fn chain_of(&self, key: &str) -> Option<Vec<String>> {
        self.keys.lock().ok().and_then(|s| s.get(key).map(|h| h.chain.clone()))
    }
    /// A process that reaps orphans (the guard; a process that made itself
    /// a subreaper), by its proc key.
    pub fn add_reaper(&self, key: &str) {
        if let Ok(mut r) = self.reapers.lock() {
            r.insert(key.to_string());
        }
    }
    /// Stamp `gone_at` on every holder now gone (the guard runs this every
    /// few hundred milliseconds, so an orphan's window closes soon after its
    /// holder died; a check at judge time does the same, later).
    pub fn observe_deaths(&self) {
        let alive: Vec<String> = match self.keys.lock() {
            Ok(s) => s.iter().filter(|(_, h)| h.gone_at.is_none()).map(|(k, _)| k.clone()).collect(),
            Err(_) => return,
        };
        // Each look finding a key dead comes after its death, and so does a
        // time read after the look. Dead, not only exiting (`key_dead`,
        // 2026-10-09): a holder seen with `PF_EXITING` has not re-parented
        // its children yet, so a stamp then could precede the death, and the
        // adoption it runs (`adopt_orphans`, once, at the first stamp) found
        // the orphan-to-be still the dying holder's child and skipped it
        // (the kernel test's round (c) leaked 3 times in 105 runs under a
        // starved guard).
        let mut gone: Vec<(String, u64)> = Vec::new();
        for k in alive {
            if key_dead(&k) {
                gone.push((k, now_ticks()));
            }
        }
        if !gone.is_empty() {
            self.stamp_deaths(&gone);
        }
    }
    /// Plan 13 §4.9 (2026-10-03): does `waiter` already hold every source
    /// the holders `held` carry (`taint_sources`), with no refused wait of
    /// its own? Then a wait that reaps them teaches it nothing it was not
    /// judged for: its connections were swept against those sources when it
    /// took them, and its later ones are judged by them. Empty `held`: true.
    pub fn covers(&self, waiter: &str, held: &[String]) -> bool {
        if self.wait_refused.lock().map(|r| r.contains(waiter)).unwrap_or(true) {
            return false;
        }
        if !self.contains(waiter) {
            return held.is_empty();
        }
        let mine = self.taint_sources(waiter);
        held.iter().all(|h| self.taint_sources(h).iter().all(|s| mine.contains(s)))
    }
    /// Plan 13 §4.9 (2026-10-03): drop `key`, recorded as a holder for a raw
    /// open the taint-time sweep then refused (no byte reached it). Only for
    /// a key that held nothing before that open: the caller checks.
    pub fn forget(&self, key: &str) {
        if let Ok(mut s) = self.keys.lock() {
            s.remove(key);
        }
        #[cfg(target_os = "linux")]
        if let Some(w) = self.deaths.get() {
            w.unwatch(key);
        }
    }
    /// Plan 13 §4.9: `waiter`'s sweep at a wait refused; it is never
    /// `covers`' answer again.
    pub fn refuse_wait(&self, waiter: &str) {
        if let Ok(mut r) = self.wait_refused.lock() {
            r.insert(waiter.to_string());
        }
    }
    /// Does the process `pid` reap orphans (a pid namespace's init, a
    /// recorded subreaper)? `guard_wait`: such a waiter may reap any process
    /// of its subtree.
    pub fn reaps_orphans(&self, pid: i32) -> bool {
        pid > 1 && self.is_reaper(pid)
    }
    /// Does `ppid` reap orphans: pid 1, a pid namespace's init, or a
    /// recorded reaper?
    fn is_reaper(&self, ppid: i32) -> bool {
        if ppid <= 1 {
            return true;
        }
        let key = mandu_arbiter::proc::proc_key_for_pid(ppid);
        if let (Some(k), Ok(r)) = (key, self.reapers.lock()) {
            if r.contains(&k) {
                return true;
            }
        }
        fs::read_to_string(format!("/proc/{ppid}/status")).map(|s| crate::lineage::is_pidns_init(&s)).unwrap_or(false)
    }
    /// The backstop for an orphan (exec-routing.md §7.5, "A fork after the
    /// taint"): when `pid`'s parent is a reaper, the holders that were gone
    /// and that held a secret when it was born (`lineage::in_window`). An
    /// orphan's own parents no longer say whose child it was; every holder
    /// that could have been is named (fail-closed).
    /// The ORPHAN ROOT above `pid`: the first process, walking up from `pid`
    /// (itself included), whose parent is a reaper; its pid and `stat`. An
    /// orphan need not be the caller itself: in `( sleep 1; node … ) &` the
    /// subshell is the orphan (re-parented to the reaper when its shell
    /// exits) and `node` is its child, whose own parent (the live subshell)
    /// is no reaper. Every process eventually meets the tree's own root, whose
    /// parent is the guard; that root started before the agent and any taint.
    ///
    /// The walk starts at the PROCESS `pid`'s thread belongs to (2026-10-15):
    /// a notification names the calling thread, and a thread's own `stat`
    /// carries the thread's start time with the process's parent. A worker
    /// thread the agent started while a tool call's holder lived (Claude
    /// Code 2.1.299 starts them all session long) was judged a root born in
    /// that holder's window, and the agent became the holder's orphan: its
    /// model connection refused, every file it wrote labelled.
    pub fn orphan_root_of(&self, pid: i32) -> Option<(i32, crate::lineage::ProcStat)> {
        let mut cur = tgid_of(pid);
        for _ in 0..32 {
            let st = read_stat(cur)?;
            if self.is_reaper(st.ppid) {
                return Some((cur, st));
            }
            if st.ppid <= 1 {
                return None;
            }
            cur = st.ppid;
        }
        None
    }
    fn orphan_holders(&self, pid: i32) -> Vec<String> {
        // The root's start time is what the window is judged by: the tree's
        // own root lies in no holder's window.
        let Some((root_pid, st)) = self.orphan_root_of(pid) else { return Vec::new() };
        let root_key = mandu_arbiter::proc::proc_key_for_pid(root_pid);
        // A lost parent is a real process with a real key; a holder whose
        // key does not parse (a synthetic one, a test's) names no pid to
        // match and is not an orphan's ancestor. Copied out so no /proc read
        // holds the lock.
        // A holder the root is an ANCESTOR of (recorded when it became one)
        // is not the root's lost parent: the root started it. Start times
        // alone cannot say so within a clock tick (2026-10-03: the guard's
        // own child `sh`, its subshell and the subshell's `cat .env` all
        // started in one tick, and the shell was judged cat's orphan).
        let entries: Vec<(String, u64, u64, Option<u64>, bool)> = match self.keys.lock() {
            Ok(s) => s
                .iter()
                .filter_map(|(k, h)| {
                    let below = root_key.as_ref().map(|r| h.ancestors.contains(r) || h.chain.contains(r)).unwrap_or(false);
                    crate::lineage::parse_key(k).map(|(_, start)| (k, start, h.since, h.gone_at, below))
                })
                .filter(|(_, start, from, _, _)| st.start >= *start && st.start.saturating_add(1) >= *from)
                .map(|(k, start, from, gone, below)| (k.clone(), start, from, gone, below))
                .collect(),
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for (k, start, from, gone_at, below) in entries {
            let until = match gone_at {
                Some(g) => g,
                None if key_gone(&k) => {
                    // 2026-10-09: the time is read after the look that found
                    // it gone (it was read once before all the looks, and
                    // could precede the death), and it is kept only once
                    // the holder is dead (not only exiting: its children are
                    // not re-parented yet), through `stamp_deaths`, so the
                    // adoption at its death runs (a stamp set here directly
                    // made every later one a second stamp, and no adoption
                    // ever ran). This judgement uses it either way.
                    let dead = key_dead(&k);
                    let t = now_ticks();
                    if dead {
                        self.stamp_deaths(&[(k.clone(), t)]);
                    }
                    t
                }
                None => continue,
            };
            if crate::lineage::orphan_of(st.start, start, from, until, below) {
                out.push(k);
            }
        }
        out
    }
    /// Nothing tainted yet (the common case: every §4.1 check is moot).
    pub fn is_empty(&self) -> bool {
        self.keys.lock().map(|s| s.is_empty()).unwrap_or(false)
    }
    /// Is this pid (its own key, or an ancestor's) tainted? For the
    /// introspection clauses of §4.1: a `/proc/<pid>/mem` open, a `ptrace`.
    pub fn pid_tainted(&self, pid: i32) -> bool {
        let own = own_key_of(pid);
        self.holds_or_inherits(pid, &own).0
    }
    /// Hand raw bytes to the process `key` names: record its taint FIRST,
    /// then `answer` (the ADDFD that resumes it). The other order let the
    /// resumed process's next syscall, taken by another guard worker, find
    /// it untainted: under load its write went unlabeled (CI 2026-09-29,
    /// secret-readers-live) and its connect would have been judged as an
    /// untainted process's (fail-open). A failed answer keeps the taint: the
    /// process got no bytes this time, and a taint too many only restricts.
    pub fn taint_then<T>(&self, key: &str, answer: impl FnOnce() -> T) -> T {
        self.insert(key);
        answer()
    }
    /// The writer of a write-intent open, when it or an ancestor is tainted:
    /// its own key and the ancestor chain, for `labelWrittenPathTainted`.
    /// Taken BEFORE the open is answered: the answer resumes the writer, and
    /// under load it wrote, exited and took its `/proc` entry with it before
    /// the guard looked; its key fell back to a bare pid no taint was
    /// recorded under, and the file it wrote went unlabeled (CI 2026-09-29,
    /// secret-readers-live). Nothing tainted: None, without reading `/proc`.
    pub fn tainted_writer(&self, pid: i32, flags: i32) -> Option<(String, Vec<String>)> {
        if !is_write_intent(flags) || self.is_empty() {
            return None;
        }
        let own = own_key_of(pid);
        let (held, chain) = self.holds_or_inherits(pid, &own);
        held.then_some((own, chain))
    }
    /// The process itself or any ancestor in the set? Returns the ancestor
    /// chain it walked (nearest first) so the caller can hand it on.
    ///
    /// When the walk meets no holder and the process is an orphan, the
    /// holders that died while it lived (`orphan_holders`) are appended to
    /// its chain, and it is remembered as one of theirs.
    pub fn holds_or_inherits(&self, pid: i32, own_key: &str) -> (bool, Vec<String>) {
        if let Some(chain) = self.chain_of(own_key) {
            return (true, chain);
        }
        let chain = ancestor_keys_of(pid, 16);
        let hit = chain.iter().any(|k| self.contains(k));
        if hit {
            self.inherit(own_key, &chain);
            return (true, chain);
        }
        if self.is_empty() {
            return (false, chain);
        }
        let orphaned_by = self.orphan_holders(pid);
        if orphaned_by.is_empty() {
            return (false, chain);
        }
        // The lost holders are flows, not ancestors: appended to the chain
        // they were reported to the arbiter as lineage edges (the topmost
        // real ancestor recorded as a holder's child), which made every
        // later walk through that ancestor inherit their taint.
        let writers: Vec<(String, Vec<String>)> = orphaned_by.iter().map(|k| (k.clone(), self.chain_of(k).unwrap_or_default())).collect();
        let from = self.flow_sources(&writers);
        self.inherit(own_key, &chain);
        self.insert_flow(own_key, &from);
        (true, chain)
    }
}

/// Is the process a proc key names gone (or exiting)? A key without a start
/// time cannot be checked: gone (fail-closed, it only widens an orphan's
/// inheritance).
fn key_gone(key: &str) -> bool {
    match crate::lineage::parse_key(key) {
        Some((pid, start)) => crate::lineage::is_gone(read_stat(pid).as_ref(), start),
        None => true,
    }
}

/// Is the process a proc key names dead (gone, reused or a zombie; not one
/// only exiting, `lineage::is_dead`)? Only then is its death stamped. A key
/// without a start time cannot be checked: dead (its stamp is the time of
/// this look, as before).
fn key_dead(key: &str) -> bool {
    match crate::lineage::parse_key(key) {
        Some((pid, start)) => crate::lineage::is_dead(read_stat(pid).as_ref(), start),
        None => true,
    }
}

/// §4.1: the `/proc/<pid>/…` entries that expose a process's memory, argv,
/// environment or descriptors: the pid they belong to, or None.
///
/// `cmdline` since 2026-10-02 (plan 10 §11.13.1, "found on the way"): a
/// listed reader that expands its secret into a command line (`curl -H
/// "Authorization: Bearer $KEY"`) put the bytes in the child's argv, which
/// any untainted process could read while the child ran (`ps -ef` in another
/// tool call printed them to the model). Not listed, on purpose: `stat`,
/// `status` and `comm` (what `ps` lists a process by: a name of at most 15
/// bytes the program sets itself, a covert channel of the kind plan 10 §6
/// accepts), and the symlinks `cwd`, `root`, `exe`, which a readlink reads
/// without an open.
pub fn proc_introspection_target(path: &str) -> Option<i32> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid_s, tail) = rest.split_once('/')?;
    let pid: i32 = pid_s.parse().ok()?;
    let tail = if let Some(t) = tail.strip_prefix("task/") { t.split_once('/').map(|(_, r)| r).unwrap_or("") } else { tail };
    let sensitive = ["mem", "cmdline", "environ", "maps", "smaps", "stack", "syscall", "auxv", "pagemap"];
    if sensitive.contains(&tail) || tail.starts_with("fd/") || tail.starts_with("fdinfo/") || tail.starts_with("map_files/") {
        Some(pid)
    } else {
        None
    }
}

/// §4.1 (plan 10; exec-routing.md §7.5, 2026-10-02): may a process read
/// another's introspection entries (`/proc/<P>/{mem,environ,cmdline,fd/…}`,
/// `ptrace`, `process_vm_*`)? `opener` / `target`: their thread groups;
/// `target_holds`: whether the target holds a secret; the `_sources`: the
/// holders whose taint each carries (`TaintedSet::taint_sources`). Its own
/// process always; a process that holds nothing always; a holder only when
/// the opener already carries every taint the holder does. Before, a
/// tainted opener read every holder: a holder of one secret lifted another
/// holder's secret out of its memory, and the guard never learned the flow
/// (the bytes then left under the first secret's bindings). PURE.
pub fn introspection_allowed(opener: i32, opener_sources: &[String], target: i32, target_holds: bool, target_sources: &[String]) -> bool {
    if opener == target || !target_holds {
        return true;
    }
    !target_sources.is_empty() && target_sources.iter().all(|t| opener_sources.contains(t))
}

/// The path of an AF_UNIX sockaddr (`@…` for the abstract namespace), or None
/// for any other family or a malformed buffer.
pub fn unix_path_of(raw: &[u8]) -> Option<String> {
    if raw.len() < 3 {
        return None;
    }
    let family = u16::from_ne_bytes([raw[0], raw[1]]);
    if family != libc::AF_UNIX as u16 {
        return None;
    }
    let p = &raw[2..];
    if p[0] == 0 {
        let end = p[1..].iter().position(|b| *b == 0).map(|i| i + 1).unwrap_or(p.len());
        return Some(format!("@{}", String::from_utf8_lossy(&p[1..end])));
    }
    let end = p.iter().position(|b| *b == 0).unwrap_or(p.len());
    Some(String::from_utf8_lossy(&p[..end]).into_owned())
}

/// §4.3: does a unix socket path fall under a `unix:<prefix>` binding
/// (exact, or a descendant of a directory prefix)?
pub fn unix_path_bound(path: &str, bindings: &[String]) -> bool {
    bindings.iter().any(|b| {
        let Some(prefix) = b.strip_prefix("unix:") else { return false };
        let prefix = prefix.trim_end_matches('/');
        !prefix.is_empty() && (path == prefix || path.starts_with(&format!("{prefix}/")))
    })
}

/// The parent's proc key, when the parent is alive and readable.
pub fn parent_key_of(pid: i32) -> Option<String> {
    let ppid = parent_pid_of(pid)?;
    if ppid <= 1 {
        return None;
    }
    mandu_arbiter::proc::proc_key_for_pid(ppid)
}

/// Read a tracee's `argv` (a NUL-terminated array of pointers to NUL-terminated
/// strings) with `process_vm_readv`, bounded (64 elements, 4096 bytes each).
/// Must run BEFORE the exec is allowed to proceed: the image is replaced after.
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub fn read_tracee_argv(pid: i32, argv_ptr: u64) -> Vec<String> {
    use fs_supervisor::kernel::{NotifReader, VmReader};
    const MAX_ARGS: usize = 64;
    let mut out = Vec::new();
    if argv_ptr == 0 {
        return out;
    }
    let mut ptrs = vec![0u64; MAX_ARGS];
    let local = libc::iovec { iov_base: ptrs.as_mut_ptr() as *mut libc::c_void, iov_len: MAX_ARGS * 8 };
    let remote = libc::iovec { iov_base: argv_ptr as *mut libc::c_void, iov_len: MAX_ARGS * 8 };
    // SAFETY: `local` is our owned buffer; the remote range is bounded; a short
    // read (the array ends before MAX_ARGS) is fine, we stop at the first NULL.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n <= 0 {
        return out;
    }
    let got = (n as usize) / 8;
    let reader = VmReader::default();
    for p in ptrs.iter().take(got) {
        if *p == 0 {
            break;
        }
        match reader.read_path(pid, *p) {
            Ok(s) => out.push(s),
            Err(_) => break,
        }
    }
    out
}

/// The flags the supervisor uses when it opens on the tracee's behalf: the
/// tracee's access mode and the harmless modifiers; O_CLOEXEC is dropped
/// because ADDFD installs the descriptor with its own flags. The REAL file
/// (a reader's `raw`) is never opened with O_CREAT (it exists: it was just
/// looked up) nor O_TRUNC: the truncation the tracee asked for is applied
/// to the descriptor once every refusal is behind (`truncate_after_lookup`),
/// so a raw open the taint sweep then refuses has not emptied the file.
pub fn supervisor_open_flags(tracee_flags: i32, for_twin: bool) -> i32 {
    let keep = libc::O_RDONLY | libc::O_WRONLY | libc::O_RDWR | libc::O_APPEND | libc::O_NONBLOCK | libc::O_NOFOLLOW;
    let mut f = tracee_flags & keep;
    if for_twin {
        // the twin is the launcher's own file: a write goes there, not to the secret
        f |= tracee_flags & (libc::O_TRUNC | libc::O_CREAT);
    }
    f
}

/// Does the guard hold the tracee's `O_TRUNC` back from the open it
/// performs, and apply it (`ftruncate`) once the file is judged? Whatever
/// the access mode: Linux truncates on `O_RDONLY|O_TRUNC` too when the
/// opener may write. The open itself never truncates: its file is not yet
/// known to be neither write-protected nor a registered secret
/// (`write-protection.md` §2; a read-only truncating open of a secret's
/// real path emptied it before the lookup served the twin, until
/// 2026-10-10). The real file a reader is handed (`raw`) is truncated
/// after every refusal of that open, before the descriptor is handed over,
/// so a shorter rewrite (`aws configure`) leaves no stale tail of the
/// longer value (`supervisor_open_flags` dropped the flag outright until
/// 2026-10-10). Pure.
pub fn truncate_after_lookup(tracee_flags: i32) -> bool {
    tracee_flags & libc::O_TRUNC != 0 && tracee_flags & libc::O_PATH == 0
}

/// The descriptor a PERFORMED `O_PATH` open hands the tracee instead of the
/// `O_PATH` one, which ADDFD cannot install (the kernel's `fget` refuses an
/// `O_PATH` file: EBADF). The guard performs every `openat2` (its flags are
/// memory the tracee could rewrite after a CONTINUE), and GNU tar 1.35 opens
/// each argument's parent `openat2(…, O_PATH|O_DIRECTORY|O_NOFOLLOW)`, so
/// `tar cf x.tar dir/f` failed under the guard (2026-10-03).
///
/// A DIRECTORY (`st_mode`) gets the same directory reopened `O_RDONLY |
/// O_DIRECTORY`: it serves every `O_PATH` use of a directory (a base for
/// `*at` calls, `fchdir`, `fstat`), and adds only listing its names, which
/// the tracee's own `open(dir, O_RDONLY)` gets in the same view (the reopen
/// runs as the tracee's open does, in its Landlock domain; a directory is
/// never a registered secret, a hidden one was refused before). Anything
/// else: `None`, no stand-in (a readable descriptor of a file, a FIFO or a
/// device is not what an `O_PATH` open may give), and the open fails as
/// before. Pure.
pub fn o_path_stand_in_flags(st_mode: u32) -> Option<i32> {
    (st_mode & libc::S_IFMT == libc::S_IFDIR).then_some(libc::O_RDONLY | libc::O_DIRECTORY)
}

/// The answer to a PERFORMED `O_PATH` open (an `openat2`; an `open`/
/// `openat` `O_PATH` of a file that is no secret runs as issued and is the
/// kernel's own) of a file that is no registered secret, whose resolution
/// (`st_mode`, the guard's `O_PATH` descriptor) succeeded: the descriptor
/// to inject, or the errno. The kernel's own answer, an `O_PATH`
/// descriptor, cannot be given: ADDFD refuses one (`fget` skips an
/// `FMODE_PATH` file, EBADF on every kernel through 7.0), and answering
/// CONTINUE would let the kernel read the `open_how` again, which another
/// thread can have turned into a read of a secret meanwhile.
///
/// A directory gets its read-only stand-in (`o_path_stand_in_flags`),
/// opened by `reopen` as the tracee's own open would be (its Landlock
/// domain, its namespaces). Anything else, and a directory the tracee may
/// not list (search-only, or outside its Landlock rights), is `ENOSYS`,
/// what a kernel without `openat2` answers: a caller that copes with one
/// (cap-std, the gnulib-less fallbacks) takes its `openat` path, where
/// `O_PATH` is the kernel's own. Until 2026-10-17 such an open answered
/// ADDFD's `EBADF`, and the search-only directory the stand-in's
/// `EACCES`, which no caller treats as "use the other call". Pure but for
/// `reopen`.
pub fn o_path_reply(st_mode: u32, reopen: impl FnOnce(i32) -> Result<i32, i32>) -> Result<i32, i32> {
    match o_path_stand_in_flags(st_mode) {
        Some(want) => reopen(want).map_err(|_| O_PATH_UNSERVED),
        None => Err(O_PATH_UNSERVED),
    }
}

/// `o_path_reply`'s errno when no stand-in serves: `ENOSYS`.
pub const O_PATH_UNSERVED: i32 = libc::ENOSYS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_o_path_open_of_a_directory_is_answered_by_a_read_only_directory() {
        assert_eq!(o_path_stand_in_flags(libc::S_IFDIR | 0o755), Some(libc::O_RDONLY | libc::O_DIRECTORY));
        assert_eq!(o_path_stand_in_flags(libc::S_IFDIR), Some(libc::O_RDONLY | libc::O_DIRECTORY), "whatever its mode bits");
        for other in [libc::S_IFREG | 0o644, libc::S_IFIFO | 0o600, libc::S_IFCHR | 0o666, libc::S_IFBLK, libc::S_IFSOCK, libc::S_IFLNK | 0o777] {
            assert_eq!(o_path_stand_in_flags(other), None, "{other:#o}: no readable stand-in for a non-directory");
        }
        let f = o_path_stand_in_flags(libc::S_IFDIR).unwrap();
        assert_eq!(f & libc::O_PATH, 0, "never O_PATH: ADDFD refuses one");
        assert!(!is_write_intent(f), "read-only");
    }

    /// A performed `O_PATH` open that no stand-in serves is `ENOSYS` (what a
    /// kernel without `openat2` answers, so a caller takes its `openat`
    /// path), never ADDFD's `EBADF` nor the stand-in's own errno (a
    /// search-only directory's `EACCES`, which the kernel's `O_PATH` open of
    /// it never answers). A directory the stand-in opens is that stand-in,
    /// asked for read-only.
    #[test]
    fn an_o_path_open_no_stand_in_serves_is_enosys_not_ebadf() {
        assert_eq!(O_PATH_UNSERVED, libc::ENOSYS);
        let asked = std::cell::Cell::new(None);
        let dir = o_path_reply(libc::S_IFDIR | 0o755, |want| {
            asked.set(Some(want));
            Ok(42)
        });
        assert_eq!(dir, Ok(42), "a listable directory: its stand-in");
        assert_eq!(asked.get(), Some(libc::O_RDONLY | libc::O_DIRECTORY));
        for refused in [libc::EACCES, libc::EPERM, libc::ESRCH, libc::EMFILE] {
            assert_eq!(o_path_reply(libc::S_IFDIR | 0o311, |_| Err(refused)), Err(libc::ENOSYS), "the stand-in refused ({refused}): ENOSYS");
        }
        for other in [libc::S_IFREG | 0o644, libc::S_IFREG, libc::S_IFIFO | 0o600, libc::S_IFCHR | 0o666, libc::S_IFBLK, libc::S_IFSOCK, libc::S_IFLNK | 0o777, 0] {
            let reply = o_path_reply(other, |_| panic!("{other:#o}: nothing is reopened for a non-directory"));
            assert_eq!(reply, Err(libc::ENOSYS), "{other:#o}: no stand-in, ENOSYS");
        }
    }

    /// Plan 13 D7, the orphan subshell: `( sleep 5 ) &` once its shell
    /// returned. The subshell is re-parented to this process (a subreaper,
    /// as the guard is) and is the orphan root of the `sleep` under it, whose
    /// own parent (the live subshell) is no reaper; the shell's direct child
    /// while it lives has the shell itself as its root.
    /// 2026-10-15: a thread started after a holder is no orphan of it. This
    /// process (a root: its parent is made a reaper) starts a holder, then a
    /// worker thread, and the holder exits; the thread's own start time lies
    /// in the dead holder's window, but the process it belongs to started
    /// before the holder.
    #[test]
    fn a_later_thread_is_judged_as_its_process() {
        let me = std::process::id() as i32;
        let set = TaintedSet::default();
        set.add_reaper(&own_key_of(read_stat(me).expect("own stat").ppid));
        let mut holder = std::process::Command::new("sleep").arg("5").spawn().expect("spawn sleep");
        set.insert(&own_key_of(holder.id() as i32));
        std::thread::sleep(std::time::Duration::from_millis(40));
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            // SAFETY: gettid has no failure mode.
            tid_tx.send(unsafe { libc::gettid() }).unwrap();
            let _ = done_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        let _ = (holder.kill(), holder.wait());
        let root = set.orphan_root_of(tid).map(|(p, _)| p);
        let held = set.holds_or_inherits(tid, &own_key_of(tid)).0;
        done_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(!held, "a thread born in a holder's window does not make its process the holder's orphan");
        assert_eq!(root, Some(me), "the root of a thread is its process");
    }

    #[test]
    fn orphan_root_of_names_the_topmost_reparented_ancestor() {
        use std::io::{BufRead, Write};
        // SAFETY: prctl with integer arguments.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, 0);
        let me = own_key_of(std::process::id() as i32);
        let set = TaintedSet::default();
        set.add_reaper(&me);
        let mut shell = std::process::Command::new("sh")
            .args(["-c", "read go; sh -c 'sleep 5 & echo $!; echo $$; wait' & sleep 0.3; exit 0"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let shell_pid = shell.id() as i32;
        // While the shell lives, its own child's root is the shell (its parent is this reaper).
        assert_eq!(set.orphan_root_of(shell_pid).map(|(p, _)| p), Some(shell_pid));
        writeln!(shell.stdin.as_mut().unwrap(), "go").unwrap();
        let mut out = std::io::BufReader::new(shell.stdout.take().unwrap());
        let (mut a, mut b) = (String::new(), String::new());
        out.read_line(&mut a).unwrap();
        out.read_line(&mut b).unwrap();
        let _ = shell.wait();
        let sleep: i32 = a.trim().parse().expect("sleep pid");
        let sub: i32 = b.trim().parse().expect("subshell pid");
        // the shell is gone: the subshell was re-parented here
        for _ in 0..50 {
            if read_stat(sub).map(|s| s.ppid) == Some(std::process::id() as i32) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let root = set.orphan_root_of(sleep);
        let sub_start = read_stat(sub).map(|s| s.start);
        // SAFETY: kill and waitpid on our own (adopted) children.
        unsafe {
            libc::kill(sleep, libc::SIGKILL);
            libc::kill(sub, libc::SIGKILL);
            libc::waitpid(sub, std::ptr::null_mut(), 0);
        }
        assert_eq!(root.map(|(p, st)| (p, st.start)), Some((sub, sub_start.unwrap())), "the sleep's orphan root is the re-parented subshell");
    }

    /// 2026-10-09 (`death_watch`, `stamp_deaths`): at a holder's death, the
    /// child it left running (re-parented to this reaper) is recorded as a
    /// holder flowing from it; a process born after the stamp is no orphan
    /// of it; one stamped late by the poll keeps the earlier stamp.
    #[test]
    fn a_death_adopts_the_orphans_it_made_and_no_later_birth() {
        use std::io::{BufRead, Write};
        // SAFETY: prctl with integer arguments.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, 0);
        let me = own_key_of(std::process::id() as i32);
        let set = TaintedSet::default();
        set.add_reaper(&me);
        // the holder: a shell that, once tainted, starts a child and exits
        // on its stdin. The child is started AFTER the taint, as the window
        // requires (one born before it is the taint-time sweep's, not the
        // window's): until 2026-10-09 the shell started it before `insert`,
        // and under load (CI, !1171's first pipeline) the taint's tick came
        // more than the tick of margin after the child's birth, so the child
        // was outside the window and not adopted.
        let mut holder = std::process::Command::new("sh")
            .args(["-c", "read tainted; sleep 5 & echo $!; read go; exit 0"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let hkey = own_key_of(holder.id() as i32);
        set.insert(&hkey);
        writeln!(holder.stdin.as_mut().unwrap(), "tainted").unwrap();
        let mut out = std::io::BufReader::new(holder.stdout.take().unwrap());
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        let child: i32 = line.trim().parse().expect("child pid");
        writeln!(holder.stdin.as_mut().unwrap(), "go").unwrap();
        let _ = holder.wait();
        for _ in 0..50 {
            if read_stat(child).map(|s| s.ppid) == Some(std::process::id() as i32) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // the watcher's report (a time read after the death)
        let dead_at = now_ticks();
        set.stamp_deaths(&[(hkey.clone(), dead_at)]);
        let ckey = own_key_of(child);
        let adopted = set.contains(&ckey);
        let sources = set.taint_sources(&ckey);
        // a later, earlier-looking report keeps the earliest stamp
        set.stamp_deaths(&[(hkey.clone(), dead_at + 50)]);
        let kept = set.keys.lock().unwrap().get(&hkey).and_then(|h| h.gone_at);
        // a process born after the stamp (more than the tick of margin)
        std::thread::sleep(std::time::Duration::from_millis(60));
        let mut later = std::process::Command::new("sleep").arg("2").spawn().expect("sleep");
        let lpid = later.id() as i32;
        // (other tests of this process run children under this reaper too:
        // only this holder's window is the question)
        let later_from_holder = set.orphan_holders(lpid).contains(&hkey);
        // SAFETY: kill and waitpid on our own (adopted) children.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        let _ = (later.kill(), later.wait());
        assert!(adopted, "the child the holder left running is recorded at its death");
        assert_eq!(sources, vec![hkey.clone()], "flowing from the holder");
        assert_eq!(kept, Some(dead_at), "the earliest stamp is kept");
        assert!(!later_from_holder, "a process born after the holder's death is no orphan of it");
    }

    /// 2026-10-09: a holder recorded as a descendant or an orphan (`inherit`)
    /// has a window from its own birth, not from when the guard saw it, so
    /// a child it forked before that, orphaned at its death, is in it; a
    /// holder that read the secret itself (`insert`) has one from the read.
    #[test]
    fn a_descendants_window_starts_at_its_birth() {
        let set = TaintedSet::default();
        let now = now_ticks();
        let born = now.saturating_sub(500);
        let key = format!("4242-{born}");
        set.inherit(&key, &[]);
        let since = set.keys.lock().unwrap().get(&key).map(|h| h.since);
        assert_eq!(since, Some(born), "from its birth");
        // a child it forked 1 s later, before the guard recorded it, then
        // orphaned at its death (stamped now): its orphan
        assert!(crate::lineage::orphan_of(born + 100, born, born, now, false));
        // a key from the future (no such process yet) or with no start: now
        set.inherit("4243-99999999999", &[]);
        let fut = set.keys.lock().unwrap().get("4243-99999999999").map(|h| h.since).unwrap();
        assert!(fut >= now && fut < 99_999_999_999);
        set.inherit("nokey", &[]);
        assert!(set.keys.lock().unwrap().get("nokey").map(|h| h.since).unwrap() >= now);
        // a direct reader's window starts at its taint
        let reader = format!("4244-{born}");
        set.insert(&reader);
        assert!(set.keys.lock().unwrap().get(&reader).map(|h| h.since).unwrap() >= now);
    }

    /// 2026-10-09: a holder's death first seen by a judgement (no watcher,
    /// no poll yet) is stamped through `stamp_deaths`, so the orphans it
    /// made are adopted then. Until then the judgement set the stamp
    /// directly, every later stamp was a second one, and no adoption ever
    /// ran: an orphan that forked and died before any trapped call left its
    /// child outside every window (the kernel test's round (c)).
    #[test]
    fn a_death_first_seen_by_a_judgement_still_adopts_its_orphans() {
        use std::io::{BufRead, Write};
        // SAFETY: prctl with integer arguments.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, 0);
        let me = own_key_of(std::process::id() as i32);
        let set = TaintedSet::default();
        set.add_reaper(&me);
        let mut holder = std::process::Command::new("sh")
            .args(["-c", "read tainted; sleep 5 & echo $!; read go; exit 0"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let hkey = own_key_of(holder.id() as i32);
        set.insert(&hkey);
        writeln!(holder.stdin.as_mut().unwrap(), "tainted").unwrap();
        let mut out = std::io::BufReader::new(holder.stdout.take().unwrap());
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        let child: i32 = line.trim().parse().expect("child pid");
        writeln!(holder.stdin.as_mut().unwrap(), "go").unwrap();
        let _ = holder.wait();
        for _ in 0..50 {
            if read_stat(child).map(|s| s.ppid) == Some(std::process::id() as i32) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // a judgement of another process is the first look at the death
        let mut other = std::process::Command::new("sleep").arg("2").spawn().expect("sleep");
        let _ = set.orphan_holders(other.id() as i32);
        let stamped = set.keys.lock().unwrap().get(&hkey).and_then(|h| h.gone_at);
        let ckey = own_key_of(child);
        let adopted = set.contains(&ckey);
        // SAFETY: kill and waitpid on our own (adopted) child.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        let _ = (other.kill(), other.wait());
        assert!(stamped.is_some(), "the judgement stamps the death");
        assert!(adopted, "and adopts the orphan it made");
    }

    /// 2026-10-09 (CI pipeline 10012, `the_orphan_window_ends_at_the_
    /// holders_death` (a)): the stamp came when the watcher's thread ran,
    /// which under load was after a process the tree started 40 ms after
    /// the death, and that process was judged the holder's orphan. Now a
    /// call that arrives after the death finds it stamped before it is
    /// judged: `stamp_ready_deaths` takes the death itself or waits for the
    /// thread that took it.
    #[test]
    fn a_death_is_stamped_before_the_next_call_is_judged() {
        let set = std::sync::Arc::new(TaintedSet::default());
        if !set.enable_death_watch(16) {
            return; // no epoll here
        }
        let mut child = std::process::Command::new("sleep").arg("5").spawn().expect("sleep");
        let key = own_key_of(child.id() as i32);
        let born = crate::lineage::parse_key(&key).unwrap().1;
        set.insert(&key);
        if set.deaths.get().unwrap().watched() != 1 {
            let _ = (child.kill(), child.wait());
            return; // no pidfd_open here: the poll is the path
        }
        let _ = child.kill();
        let _ = child.wait();
        let dead_by = now_ticks();
        // the next trapped call, however the watcher's thread is scheduled
        set.stamp_ready_deaths();
        let stamped = set.keys.lock().unwrap().get(&key).and_then(|h| h.gone_at);
        let after = now_ticks();
        let t = stamped.expect("stamped before the call goes on");
        assert!(t >= born && t <= after, "a time read after the exit ({born} <= {t} <= {after})");
        // and a process started now, after that stamp, in a later tick,
        // is no orphan of it; one started no later than the stamp's tick is
        let later = t + 1;
        assert!(!crate::lineage::orphan_of(later, born, born, t, false));
        assert!(crate::lineage::orphan_of(dead_by.min(t), born, born, t, false));
    }

    /// 2026-10-09: a holder recorded before the watcher started is watched
    /// when it starts (the guard's first worker could judge a call before
    /// the watcher ran), and one recorded already dead is stamped at once
    /// rather than at the next 200 ms poll.
    #[test]
    fn holders_recorded_before_the_watcher_or_already_dead_are_stamped_at_once() {
        let set = std::sync::Arc::new(TaintedSet::default());
        let mut early = std::process::Command::new("sleep").arg("5").spawn().expect("sleep");
        let ekey = own_key_of(early.id() as i32);
        set.insert(&ekey);
        if !set.enable_death_watch(16) {
            let _ = (early.kill(), early.wait());
            return;
        }
        let watched = set.deaths.get().unwrap().watched();
        let _ = early.kill();
        let _ = early.wait();
        set.stamp_ready_deaths();
        let early_stamp = set.keys.lock().unwrap().get(&ekey).and_then(|h| h.gone_at);
        // a holder already reaped when it is recorded
        let mut gone = std::process::Command::new("true").spawn().expect("true");
        let gkey = own_key_of(gone.id() as i32);
        let _ = gone.wait();
        set.insert(&gkey);
        let gone_stamp = set.keys.lock().unwrap().get(&gkey).and_then(|h| h.gone_at);
        if watched == 0 {
            return; // no pidfd_open here: both are the poll's
        }
        assert_eq!(watched, 1, "the early holder is watched when the watcher starts");
        assert!(early_stamp.is_some(), "and stamped at its death");
        assert!(gone_stamp.is_some(), "a holder recorded dead is stamped at once");
    }

    /// 2026-10-10 (exec-routing.md §7.5 (d), "One process's tree"): a
    /// holder whose parent exited before its taint has lost its lineage (its
    /// ancestors, read at the taint, start at the reaper), so a child of the
    /// reaper born in the holder's own clock tick (in fact its grandparent:
    /// the tree's root) cannot be told from a child the holder left running,
    /// and at the holder's death it is adopted as its orphan. Fail-closed,
    /// and kept: nothing sound breaks the tie (a pid order wraps; the kernel
    /// exposes no finer start time and no original parent). A root born in
    /// an EARLIER tick than the holder is no orphan of it: what the kernel
    /// test's round (a) now waits for before its root starts the holder.
    #[test]
    fn a_root_in_the_tick_of_a_holder_whose_lineage_is_lost_is_its_orphan() {
        use std::io::BufRead;
        // SAFETY: prctl with integer arguments.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, 0);
        let mypid = std::process::id() as i32;
        let me = own_key_of(mypid);
        let start_of = |pid: i32| read_stat(pid).map(|s| s.start);
        // One root, its holder started at once ("") or 30 ms later (three
        // ticks at 100 Hz): is the root adopted at the holder's death, and
        // were the two born in one tick?
        let run = |delay: &str| -> Option<(bool, bool)> {
            // The subshell starts the holder and exits at once: the holder
            // is re-parented to this reaper before its taint is recorded.
            let script = format!("{delay}( sleep 0.2 & echo $! ); read y");
            let mut root = std::process::Command::new("sh")
                .args(["-c", &script])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("spawn sh");
            let rpid = root.id() as i32;
            let rkey = own_key_of(rpid);
            let mut line = String::new();
            std::io::BufReader::new(root.stdout.take().unwrap()).read_line(&mut line).unwrap();
            let holder: i32 = line.trim().parse().expect("the holder's pid");
            let hs = start_of(holder);
            for _ in 0..200 {
                if read_stat(holder).map(|s| s.ppid) == Some(mypid) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let reparented = read_stat(holder).map(|s| s.ppid) == Some(mypid);
            let set = TaintedSet::default();
            set.add_reaper(&me);
            let hkey = own_key_of(holder);
            set.insert(&hkey);
            let lost = !set.keys.lock().unwrap().get(&hkey).map(|h| h.ancestors.contains(&rkey)).unwrap_or(true);
            // Its taint from its first tick, so the window is no excuse.
            if let (Ok(mut s), Some(h)) = (set.keys.lock(), hs) {
                s.get_mut(&hkey).unwrap().since = h;
            }
            for _ in 0..400 {
                if key_dead(&hkey) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let dead = key_dead(&hkey);
            // the watcher's report: a time read after the death
            set.stamp_deaths(&[(hkey.clone(), now_ticks())]);
            let adopted = set.contains(&rkey);
            let same_tick = start_of(rpid).is_some() && start_of(rpid) == hs;
            let _ = root.kill();
            let _ = root.wait();
            // SAFETY: reaping the re-parented holder (or nothing).
            unsafe { libc::waitpid(holder, std::ptr::null_mut(), libc::WNOHANG) };
            // Only a holder re-parented before its taint, then dead, is the case.
            (reparented && lost && dead).then_some((adopted, same_tick))
        };
        // (Another test's wait may reap the holder before it is seen
        // re-parented: that attempt does not count.)
        let (adopted, same_tick) = (0..5).find_map(|_| run("sleep 0.03; ")).expect("the holder is re-parented, then dies");
        assert!(!same_tick, "30 ms is more than a tick");
        assert!(!adopted, "a root born in a tick before the holder is no orphan of it");
        for attempt in 0..20 {
            let Some((adopted, same_tick)) = run("") else { continue };
            if !same_tick {
                eprintln!("attempt {attempt}: the root and the holder started in different ticks; again");
                continue;
            }
            assert!(adopted, "a root in the tick of a holder whose lineage is lost is its orphan (fail-closed)");
            return;
        }
        eprintln!("the root and its holder never started in one tick in 20 attempts: only the earlier-tick half ran");
    }

    #[test]
    fn the_reapers_own_child_is_no_orphan_of_a_holder_it_started() {
        // 2026-10-03, secret-readers-live's pipe-holder check: the guard's
        // child `sh` started a subshell whose `cat .env` read the secret and
        // exited. All three started in one clock tick, so by the ticks the
        // shell could have been cat's orphan; it was judged one, and every
        // process it then started (the sibling that read the pipe holder's
        // /proc entries) carried cat's taint. The shell is cat's ancestor.
        //
        // The holder must be ALIVE when it is recorded, as the guard records
        // one (stopped in its trapped open, `taint_then`): its ancestors are
        // read then. Until 2026-10-03 the holder was `sh -c 'read x' &`,
        // whose stdin a non-interactive shell points at /dev/null (an
        // asynchronous list's default), so it read EOF and exited at once;
        // when its shell reaped it before `insert` read its ancestors (CI
        // gl-8398, gl-8485), none were recorded and the root was judged its
        // orphan: the fail-closed answer for a holder whose lineage is
        // unknown, not a product fault. The holder now reads the root's
        // stdin through fd 3 and exits only on the "go" below.
        use std::io::{BufRead, Write};
        // SAFETY: prctl with integer arguments.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, 0);
        let me = own_key_of(std::process::id() as i32);
        let start_of = |pid: i32| read_stat(pid).map(|s| s.start);
        // Retry until the shell and its child share a tick (the case; a
        // fork takes well under one), at most 20 times.
        for attempt in 0..20 {
            // The root waits for the holder, then blocks on its own stdin
            // (killed below; no process outlives the test).
            let mut root = std::process::Command::new("sh")
                .args(["-c", "{ sh -c 'read x' <&3 & } 3<&0; echo $!; wait; read y"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("spawn sh");
            let rpid = root.id() as i32;
            let mut line = String::new();
            std::io::BufReader::new(root.stdout.take().unwrap()).read_line(&mut line).unwrap();
            let holder: i32 = line.trim().parse().expect("the holder's pid");
            let (rs, hs) = (start_of(rpid), start_of(holder));
            let set = TaintedSet::default();
            set.add_reaper(&me);
            let hkey = own_key_of(holder);
            set.insert(&hkey);
            let recorded = set.keys.lock().unwrap().get(&hkey).map(|h| h.ancestors.clone()).unwrap_or_default();
            assert_eq!(start_of(holder), hs, "the holder is still alive (it waits for \"go\")");
            assert_eq!(recorded.first(), Some(&own_key_of(rpid)), "a live holder's ancestors are recorded, its shell first");
            // Its taint from its first tick, so the window is no excuse.
            if let (Ok(mut s), Some(h)) = (set.keys.lock(), hs) {
                s.get_mut(&hkey).unwrap().since = h;
            }
            writeln!(root.stdin.as_mut().unwrap(), "go").unwrap();
            for _ in 0..200 {
                if key_gone(&hkey) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // Gone, so the orphan backstop is what judges the root.
            assert!(key_gone(&hkey), "the holder exits on \"go\"");
            let held = set.holds_or_inherits(rpid, &own_key_of(rpid)).0;
            let _ = root.kill();
            let _ = root.wait();
            if rs != hs || rs.is_none() {
                eprintln!("attempt {attempt}: the shell and its child started in different ticks; again");
                continue;
            }
            assert!(!held, "the root shell was judged the orphan of the holder it started");
            return;
        }
        panic!("the shell and its child never started in one tick in 20 attempts");
    }

    #[test]
    fn a_waiter_covers_only_the_sources_it_already_holds() {
        // Plan 13 §4.9 (2026-10-03): a wait needs no sweep when the waiter
        // already holds what every holder it may reap holds.
        let set = TaintedSet::default();
        set.insert("10-1"); // the shell read a secret itself
        set.inherit("11-2", &["10-1".into()]); // its child, by lineage only
        set.insert("12-3"); // another child read a second secret
        set.inherit("12-3", &["10-1".into()]);
        assert!(set.covers("10-1", &["11-2".into()]), "a child that holds through the waiter teaches it nothing");
        assert!(!set.covers("10-1", &["12-3".into()]), "a child's own read is a source the waiter lacks");
        assert!(!set.covers("99-9", &["11-2".into()]), "a waiter that holds nothing covers no holder");
        assert!(set.covers("99-9", &[]), "nothing to reap");
        // Once the waiter flows from that child it covers it.
        set.insert_flow("10-1", &["12-3".into()]);
        assert!(set.covers("10-1", &["12-3".into()]));
        // A refused wait is never covered again: the waiter was recorded
        // although the sweep found an unbound connection.
        set.refuse_wait("10-1");
        assert!(!set.covers("10-1", &["11-2".into()]));
        // A reader whose raw open was refused is forgotten: no holder.
        set.insert("13-4");
        set.forget("13-4");
        assert!(!set.contains("13-4"));
        assert!(set.contains("12-3"), "only that key");
    }

    #[test]
    fn an_orphan_inherits_from_the_holder_that_died_while_it_lived() {
        // exec-routing.md §7.5, "A fork after the taint": a holder's child
        // that made no trapped call while the holder lived is re-parented
        // when the holder dies, and its parents no longer lead to it. This
        // test process is the reaper (a subreaper, as the guard is).
        use std::io::{BufRead, Write};
        // SAFETY: prctl with integer arguments.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, 0);
        let me = own_key_of(std::process::id() as i32);
        // The holder: waits for a line, then leaves a background child and exits.
        let spawn = || {
            std::process::Command::new("sh")
                .args(["-c", "read go; sleep 5 & echo $!; exit 0"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("spawn sh")
        };
        let orphan_of = |child: &mut std::process::Child| -> i32 {
            writeln!(child.stdin.as_mut().unwrap(), "go").unwrap();
            let mut line = String::new();
            std::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
            let _ = child.wait();
            line.trim().parse().expect("the orphan's pid")
        };
        let reap = |pid: i32| {
            // SAFETY: kill and waitpid on our own (adopted) child.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
        };

        let set = TaintedSet::default();
        set.add_reaper(&me);
        let mut holder = spawn();
        let hkey = own_key_of(holder.id() as i32);
        set.insert(&hkey);
        let orphan = orphan_of(&mut holder);
        let okey = own_key_of(orphan);
        let (held, chain) = set.holds_or_inherits(orphan, &okey);
        assert!(held, "the orphan of a holder that died is a holder");
        assert!(!chain.contains(&hkey), "the lost holder is no ancestor (no false lineage edge): {chain:?}");
        assert!(set.flows_for(&okey, &chain).contains(&hkey), "named as a flow from that holder");
        assert!(set.contains(&okey), "and remembered");
        reap(orphan);

        // A grandchild of the lost holder: `( sleep 5 ) &` — the subshell is
        // the orphan (its parent the reaper), the `sleep` its child, whose own
        // parent (the live subshell) is no reaper. Found through the orphan
        // root (the sandbox suite's leak, 2026-10-02).
        let deep = TaintedSet::default();
        deep.add_reaper(&me);
        let mut holder = std::process::Command::new("sh")
            .args(["-c", "read go; sh -c 'sleep 5 & echo $!; wait' & sleep 0.3; exit 0"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let hkey = own_key_of(holder.id() as i32);
        deep.insert(&hkey);
        let grandchild = orphan_of(&mut holder);
        let middle = crate::lineage::parse_stat(&fs::read_to_string(format!("/proc/{grandchild}/stat")).unwrap()).unwrap().ppid;
        let (held, chain) = deep.holds_or_inherits(grandchild, &own_key_of(grandchild));
        assert!(held, "the grandchild of a holder that died is a holder");
        assert!(deep.flows_for(&own_key_of(grandchild), &chain).contains(&hkey), "{chain:?}");
        reap(grandchild);
        reap(middle);

        // Controls. Not a reaper's child: the walk alone decides.
        let unreaped = TaintedSet::default();
        let mut holder = spawn();
        unreaped.insert(&own_key_of(holder.id() as i32));
        let orphan = orphan_of(&mut holder);
        assert!(!unreaped.holds_or_inherits(orphan, &own_key_of(orphan)).0, "a parent that is no reaper: not an orphan");
        reap(orphan);
        // A holder recorded only after the orphan was born: not its orphan.
        let late = TaintedSet::default();
        late.add_reaper(&me);
        let mut holder = spawn();
        let hkey = own_key_of(holder.id() as i32);
        let orphan = orphan_of(&mut holder);
        std::thread::sleep(std::time::Duration::from_millis(50));
        late.insert(&hkey);
        assert!(!late.holds_or_inherits(orphan, &own_key_of(orphan)).0, "born before the taint (the sweep's case)");
        reap(orphan);
        // A holder still alive did not orphan anyone.
        let alive = TaintedSet::default();
        alive.add_reaper(&me);
        let mut other = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        alive.insert(&own_key_of(other.id() as i32));
        let mut holder = spawn();
        let orphan = orphan_of(&mut holder);
        assert!(!alive.holds_or_inherits(orphan, &own_key_of(orphan)).0, "a live holder is not the orphan's lost parent");
        reap(orphan);
        let _ = other.kill();
        let _ = other.wait();
        // The test process stays a subreaper: the tests run side by side,
        // and until 2026-10-10 this one turned it off at its end, under the
        // others that need it (their orphans then went to init).
    }

    #[test]
    fn a_flow_is_handed_on_to_a_readers_children_and_never_becomes_an_edge() {
        // Plan 13 D2: H read the secret; R reads H's pipe; C is R's child.
        let set = TaintedSet::default();
        set.insert("H-1");
        let from = set.flow_sources(&[("H-1".to_string(), vec![])]);
        assert_eq!(from, vec!["H-1".to_string()]);
        set.insert_flow("R-2", &from);
        assert!(set.contains("R-2"), "the reader is a holder");
        assert_eq!(set.flows_for("R-2", &[]), vec!["H-1".to_string()]);
        // R's child: found through R on its chain, flows from H.
        assert_eq!(set.flows_for("C-3", &["R-2".to_string(), "sh-0".to_string()]), vec!["H-1".to_string()]);
        // A second stage (`H | R | S`): S flows from R and from what R flows from.
        let from2 = set.flow_sources(&[("R-2".to_string(), vec!["sh-0".to_string()])]);
        assert_eq!(from2, vec!["R-2".to_string(), "H-1".to_string()]);
        // A descendant of H writing the pipe: H on the writer's chain counts.
        let from3 = set.flow_sources(&[("kid-9".to_string(), vec!["H-1".to_string(), "sh-0".to_string()])]);
        assert_eq!(from3, vec!["kid-9".to_string(), "H-1".to_string()]);
        // Flows add, without duplicates or self-references.
        set.insert_flow("R-2", &["H-1".to_string(), "R-2".to_string(), "X-5".to_string()]);
        assert_eq!(set.flows_for("R-2", &[]), vec!["H-1".to_string(), "X-5".to_string()]);
        // No flow: nothing.
        assert!(set.flows_for("H-1", &[]).is_empty());
        assert!(set.flows_for("Z-7", &["sh-0".to_string()]).is_empty());
    }

    #[test]
    fn observe_deaths_stamps_the_gone_and_leaves_the_living() {
        let set = TaintedSet::default();
        // An unparseable key cannot be checked: gone (fail-closed).
        set.insert("nokey");
        set.observe_deaths();
        assert!(set.keys.lock().unwrap().get("nokey").unwrap().gone_at.is_some());
        // A live process is not.
        let me = own_key_of(std::process::id() as i32);
        set.insert(&me);
        set.observe_deaths();
        assert!(set.keys.lock().unwrap().get(&me).unwrap().gone_at.is_none());
    }

    #[test]
    fn a_descendant_found_once_stays_tainted_with_its_chain() {
        // A child of THIS process: a walk of its parents finds us. Taint our
        // key and the child inherits, and is remembered with the chain.
        let mut child = std::process::Command::new("sleep").arg("5").spawn().expect("spawn sleep");
        let pid = child.id() as i32;
        let own = own_key_of(pid);
        let chain = ancestor_keys_of(pid, 16);
        let me = own_key_of(std::process::id() as i32);
        assert_eq!(chain.first(), Some(&me), "the child's nearest ancestor is this process");
        let set = TaintedSet::default();
        assert_eq!(set.holds_or_inherits(pid, &own), (false, chain.clone()));
        assert!(!set.contains(&own), "an untainted walk remembers nothing");
        set.insert(&me);
        assert_eq!(set.holds_or_inherits(pid, &own), (true, chain.clone()));
        assert!(set.contains(&own), "remembered under its own key");
        // Reparented (its parent's key gone from the walk): still a holder,
        // with the chain it was found through.
        let other = TaintedSet::default();
        other.inherit(&own, &chain);
        assert_eq!(other.holds_or_inherits(pid, &own), (true, chain.clone()));
        // A key tainted itself keeps its empty chain.
        let direct = TaintedSet::default();
        direct.insert(&own);
        direct.inherit(&own, &chain);
        assert_eq!(direct.holds_or_inherits(pid, &own), (true, vec![]));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn the_exec_walk_parses_the_parent_from_status_and_stat() {
        // runtime-instances.md §14.8: `stat`'s field 4 is `status`'s PPid.
        let status = "Name:\tnode\nTgid:\t4242\nPid:\t4250\nPPid:\t17\n";
        assert_eq!(ppid_from_status(status), Some(17));
        assert_eq!(ppid_from_status("Name:\tx\n"), None);
        assert_eq!(ppid_from_status("PPid:\tnope\n"), None);
        // A name may hold spaces and parentheses: the fields count from the last `)`.
        let line = "1234 (my (weird) proc) S 77 1234 1234 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 9999 12345678 0 0 0";
        assert_eq!(stat_start_and_ppid(line), (Some(9999), Some(77)));
        assert_eq!(stat_start_and_ppid(line).0, mandu_arbiter::proc::parse_starttime_from_stat(line), "the start is proc_key_for_pid's parse");
        assert_eq!(stat_start_and_ppid("1 (x) S 2 3"), (None, Some(2)), "a short line: no start");
        assert_eq!(stat_start_and_ppid("garbage"), (None, None));
    }

    #[test]
    fn the_exec_chain_stops_where_the_separate_walk_stops() {
        // pid → (start, ppid): 30 → 20 → 10 → 1 (init); 40's start unreadable.
        let table = |p: i32| match p {
            30 => (Some(300), Some(20)),
            20 => (Some(200), Some(10)),
            10 => (Some(100), Some(1)),
            40 => (None, Some(20)),
            50 => (Some(500), None),
            _ => (None, None),
        };
        assert_eq!(chain_from(Some(30), 999, table), vec!["30-300", "20-200", "10-100"], "nearest first, not to init");
        assert_eq!(chain_from(Some(30), 20, table), vec!["30-300"], "stopped below the guard");
        assert_eq!(chain_from(Some(40), 999, table), Vec::<String>::new(), "a start that cannot be read ends the chain");
        assert_eq!(chain_from(Some(50), 999, table), vec!["50-500"], "an unknown next parent ends it after this one");
        assert_eq!(chain_from(None, 999, table), Vec::<String>::new());
        assert_eq!(chain_from(Some(1), 999, table), Vec::<String>::new());
        // At most 32 levels, as lineage_chain_of.
        let long = |p: i32| (Some(p as u64), Some(p + 1));
        assert_eq!(chain_from(Some(100), 0, long).len(), 32);
    }

    #[test]
    fn the_exec_walk_answers_what_the_three_separate_reads_answer() {
        // runtime-instances.md §14.8, over the real /proc: this process plays
        // the guard. A grandchild (its chain: the sh), a child (no chain: its
        // parent is the guard, named as the parent key), a worker thread of
        // this process (its process's key) and a gone process.
        use std::io::Read;
        let old = |pid: i32| {
            let ancestors = lineage_chain_of(pid);
            let parent_key = ancestors.first().cloned().or_else(|| parent_key_of(pid));
            ExecLineage { own: own_key_of(pid), ancestors, parent_key }
        };
        let mut sh = std::process::Command::new("sh").args(["-c", "sleep 30 & echo $!; wait"]).stdout(std::process::Stdio::piped()).spawn().expect("sh");
        let mut line = String::new();
        let mut out = sh.stdout.take().unwrap();
        let mut b = [0u8; 1];
        while out.read(&mut b).map(|n| n == 1).unwrap_or(false) && b[0] != b'\n' {
            line.push(b[0] as char);
        }
        let sleep: i32 = line.trim().parse().expect("sleep pid");
        let sh_pid = sh.id() as i32;
        let me = std::process::id() as i32;
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            // SAFETY: gettid has no failure mode.
            tx.send(unsafe { libc::syscall(libc::SYS_gettid) } as i32).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(300));
        });
        let tid = rx.recv().unwrap();
        let got = [exec_lineage_of(sleep), exec_lineage_of(sh_pid), exec_lineage_of(tid), exec_lineage_of(i32::MAX)];
        let want = [old(sleep), old(sh_pid), old(tid), old(i32::MAX)];
        let sh_key = mandu_arbiter::proc::proc_key_for_pid(sh_pid).unwrap_or_default();
        // SAFETY: plain kill of our own grandchild.
        unsafe { libc::kill(sleep, libc::SIGKILL) };
        let _ = sh.kill();
        let _ = sh.wait();
        worker.join().unwrap();
        assert_eq!(got, want);
        assert_eq!(got[0].ancestors, vec![sh_key.clone()], "the grandchild's chain is the sh");
        assert_eq!(got[0].parent_key.as_deref(), Some(sh_key.as_str()));
        assert!(got[1].ancestors.is_empty(), "the child's walk stops below this process");
        assert_eq!(got[1].parent_key, mandu_arbiter::proc::proc_key_for_pid(me), "its parent: this process");
        assert_eq!(got[2].own, own_key_of(me), "a thread: its process's key");
        assert_eq!(got[3], ExecLineage { own: i32::MAX.to_string(), ancestors: vec![], parent_key: None }, "a gone process");
    }

    #[test]
    fn a_threads_key_is_its_thread_groups() {
        // exec-routing.md §7.5 (2026-10-01): a notification names a thread.
        let status = "Name:\tnode\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\nNgid:\t0\nPid:\t4250\nPPid:\t17\n";
        assert_eq!(tgid_from_status(status), Some(4242));
        assert_eq!(tgid_from_status("Name:\tx\n"), None);
        // This process: the key of a worker thread is the process's key.
        let me = std::process::id() as i32;
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            // SAFETY: gettid has no failure mode.
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            tx.send(tid).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
        });
        let tid = rx.recv().unwrap();
        assert_ne!(tid, me);
        assert_eq!(tgid_of(tid), me);
        assert_eq!(own_key_of(tid), own_key_of(me));
        assert_eq!(own_key_of(me), mandu_arbiter::proc::proc_key_for_pid(me).unwrap());
        worker.join().unwrap();
    }

    fn ua(path: &str) -> UnixAllow {
        UnixAllow { path: path.into(), label: "x".into() }
    }

    #[test]
    fn unix_allow_matches_a_socket_a_directory_and_an_identity() {
        let p = UnixPolicy { allow: vec![ua("/run/user/1/mandu/current/arbiter.sock"), ua("/tmp/.X11-unix")], abstract_allow: vec![] };
        let none = |_: &str| None;
        assert!(unix_allowed(&p, Some("/run/user/1/mandu/current/arbiter.sock"), None, none).is_some());
        assert!(unix_allowed(&p, Some("/tmp/.X11-unix/X0"), None, none).is_some(), "below a directory entry");
        assert!(unix_allowed(&p, Some("/run/user/1/bus"), None, none).is_none(), "the D-Bus session bus");
        assert!(unix_allowed(&p, Some("/tmp/.X11-unix-evil/X0"), None, none).is_none(), "a look-alike");
        // Another spelling of the arbiter socket (a bind, a hard link): by identity.
        let id = |q: &str| (q == "/run/user/1/mandu/current/arbiter.sock").then_some((3, 30));
        assert!(unix_allowed(&p, Some("/elsewhere/a.sock"), Some((3, 30)), id).is_some());
        assert!(unix_allowed(&p, Some("/elsewhere/a.sock"), Some((3, 31)), id).is_none());
    }

    #[test]
    fn abstract_names_match_exactly_or_by_a_star_prefix() {
        let p = UnixPolicy { allow: vec![], abstract_allow: vec!["/tmp/.X11-unix/X*".into(), "exact-name".into()] };
        assert!(abstract_allowed(&p, b"/tmp/.X11-unix/X0"));
        assert!(abstract_allowed(&p, b"exact-name"));
        assert!(!abstract_allowed(&p, b"exact-name-longer"));
        assert!(!abstract_allowed(&p, b"/tmp/dbus-XXXX"));
        assert!(!abstract_allowed(&UnixPolicy::default(), b"anything"));
    }

    #[test]
    fn a_number_the_tracee_names_is_translated_to_host_pids() {
        // Host 900 (the agent, wrap pid 2), 901 (its shell, wrap 3), 950 (a
        // boxed command: wrap 7, box 1), 960 (another box: wrap 8, box 1).
        let tree = vec![(900, vec![900, 2]), (901, vec![901, 3]), (950, vec![950, 7, 1]), (960, vec![960, 8, 1])];
        let any = |_: i32| true;
        assert_eq!(host_pids_named(2, Some(0), &tree, any), vec![2], "our own namespace: the number is the host's");
        assert_eq!(host_pids_named(2, Some(1), &tree, any), vec![900]);
        assert_eq!(host_pids_named(7, Some(1), &tree, any), vec![950]);
        assert_eq!(host_pids_named(1, Some(2), &tree, any), vec![950, 960], "sibling boxes reuse 1: both, the caller refuses if either is tainted");
        assert_eq!(host_pids_named(1, Some(2), &tree, |h| h == 960), vec![960], "a start-time check picks the one");
        assert_eq!(host_pids_named(3, None, &tree, any), vec![901], "unknown level: any level below ours");
        assert!(host_pids_named(42, Some(1), &tree, any).is_empty(), "nobody in the tree");
    }

    #[test]
    fn a_pinned_write_target_is_matched_by_where_it_is_and_what_it_is() {
        let wp = |path: &str| WriteProtect { path: path.into(), answer: "ask".into(), label: "l".into(), ..Default::default() };
        let entries = vec![wp("/home/u/.bashrc"), wp("/home/u/.config/systemd/user")];
        let ids = |p: &str| match p { "/home/u/.bashrc" => Some((1, 10)), "/home/u/.config/systemd/user" => Some((1, 20)), _ => None };
        // By the path the descriptor names (a symlink swapped in before the
        // open was followed: the pinned file IS .bashrc).
        assert!(write_protected_hit_pinned(&entries, "/home/u/.bashrc", Some((1, 10)), &[], ids).is_some());
        // By identity: a hard link elsewhere, a bind mount showing another path.
        assert!(write_protected_hit_pinned(&entries, "/tmp/link", Some((1, 10)), &[], ids).is_some());
        // A new file in a protected directory, by its path or by the pinned
        // directory's identity (reached through a symlinked parent).
        assert!(write_protected_hit_pinned(&entries, "/home/u/.config/systemd/user/evil.service", None, &[], ids).is_some());
        assert!(write_protected_hit_pinned(&entries, "/tmp/d/evil.service", None, &[(1, 20), (1, 2)], ids).is_some());
        // Elsewhere: nothing.
        assert!(write_protected_hit_pinned(&entries, "/home/u/notes.txt", Some((1, 99)), &[(1, 3)], ids).is_none());
        assert!(write_protected_hit_pinned(&entries, "/home/u/.bashrc.bak", Some((1, 98)), &[], ids).is_none(), "a prefix of a name is not a parent");
    }

    #[test]
    fn a_name_change_at_an_ancestor_of_a_write_protected_path_hits_it() {
        // P0 (D), 2026-10-07: `mv ~/.ssh ~/.ssh.old; mv ~/planted ~/.ssh`
        // replaced ~/.ssh/config with no write under the entry.
        let wp = |path: &str| WriteProtect { path: path.into(), answer: "ask".into(), label: "an ssh setting".into(), ..Default::default() };
        let entries = vec![wp("/home/u/.ssh/config"), wp("/home/u/.ssh/config.d"), wp("/home/u/.orbstack/ssh/config")];
        let ids = |p: &str| match p { "/home/u/.ssh" => Some((1, 30)), "/home/u" => Some((1, 2)), "/home" => Some((1, 1)), "/" => Some((1, 0)), _ => None };
        let hit = |seen: &str, own: Option<(u64, u64)>| write_protected_ancestor_hit(&entries, seen, own, ids).map(|w| w.path.clone());
        // By path: the entry's parent, a grandparent, a parent that does not
        // exist yet (a planted directory renamed or linked into its place).
        assert_eq!(hit("/home/u/.ssh", None).as_deref(), Some("/home/u/.ssh/config"));
        assert_eq!(hit("/home/u/.orbstack", None).as_deref(), Some("/home/u/.orbstack/ssh/config"));
        assert_eq!(hit("/home/u/.orbstack/ssh/", None).as_deref(), Some("/home/u/.orbstack/ssh/config"));
        // By identity: a directory reached under another spelling (a bind).
        assert_eq!(hit("/mnt/bound-ssh", Some((1, 30))).as_deref(), Some("/home/u/.ssh/config"));
        // The entry itself and what lies below it are write_protected_hit's;
        // siblings, look-alikes and unrelated directories are nothing.
        assert_eq!(hit("/home/u/.ssh/config", None), None);
        assert_eq!(hit("/home/u/.ssh/config.d/x.conf", None), None);
        assert_eq!(hit("/home/u/.ssh-old", None), None);
        assert_eq!(hit("/home/u/.orb", None), None, "a prefix of a name is not a parent");
        assert_eq!(hit("/home/u/notes", Some((1, 99))), None);
        // A file or a symlink (no directory identity) is matched by path only.
        assert_eq!(hit("/tmp/x", None), None);
    }

    #[test]
    fn in_tree_walks_up_to_a_root_and_stops_at_init() {
        // 100 (guard) → 101 (agent) → 102 (bash) → 103 (server); 50 is a host
        // service under init.
        let parent = |p: i32| match p { 103 => Some(102), 102 => Some(101), 101 => Some(100), 100 => Some(1), 50 => Some(1), _ => None };
        assert!(in_tree(103, &[101], parent));
        assert!(in_tree(103, &[100], parent), "the guard as a root (the subreaper)");
        assert!(!in_tree(50, &[101, 100], parent), "a host service");
        assert!(!in_tree(0, &[101], parent), "no peer pid (another pid namespace)");
        assert!(!in_tree(999, &[101], parent), "gone");
        let cyc = |p: i32| Some(p); // a parent_of that never moves
        assert!(!in_tree(7, &[101], cyc));
    }

    #[test]
    fn unix_deny_matches_by_path_and_by_identity_only() {
        let deny = vec!["/run/user/1/mandu/human".to_string()];
        let none = |_: &str| -> Vec<(u64, u64)> { vec![] };
        assert_eq!(unix_denied(&deny, Some("/run/user/1/mandu/human/i.sock"), None, none), Some("/run/user/1/mandu/human"));
        assert_eq!(unix_denied(&deny, Some("/run/user/1/mandu/human"), None, none), Some("/run/user/1/mandu/human"), "the directory itself");
        assert_eq!(unix_denied(&deny, Some("/run/user/1/mandu/human-evil/i.sock"), None, none), None, "a look-alike");
        assert_eq!(unix_denied(&deny, Some("/run/user/1/mandu/current/arbiter.sock"), None, none), None, "the data socket");
        // A hard link / bind mount elsewhere: the path is not under the entry,
        // the identity is one of the entry's files.
        let ids = |d: &str| -> Vec<(u64, u64)> { if d == "/run/user/1/mandu/human" { vec![(1, 10), (1, 11)] } else { vec![] } };
        assert_eq!(unix_denied(&deny, Some("/tmp/link.sock"), Some((1, 11)), ids), Some("/run/user/1/mandu/human"));
        assert_eq!(unix_denied(&deny, Some("/tmp/other.sock"), Some((1, 12)), ids), None);
        assert_eq!(unix_denied(&[], Some("/run/user/1/mandu/human/i.sock"), Some((1, 11)), ids), None, "no list, no deny");
    }

    #[test]
    fn unix_deny_is_carried_resolved_and_alone_makes_the_index_non_empty() {
        let dir = std::env::temp_dir().join(format!("mandu-ud-{}", std::process::id()));
        let real_dir = dir.join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        let link = dir.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();
        let text = format!(r#"{{"unixDeny":["{}"]}}"#, link.display());
        let f: SecretPolicyFile = serde_json::from_str(&text).unwrap();
        let idx = SecretIndex::from_file(f);
        assert!(!idx.is_empty(), "a deny list alone makes the index non-empty (the guard loads it)");
        let real = std::fs::canonicalize(&real_dir).unwrap();
        // Both spellings are denied: the one written and the resolved one.
        assert!(idx.unix_denied_now(Some(&format!("{}/x.sock", link.display())), None).is_some());
        assert!(idx.unix_denied_now(Some(&format!("{}/x.sock", real.display())), None).is_some());
        // By identity: a file in the directory, reached under another name.
        std::fs::write(real_dir.join("f"), b"").unwrap();
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(real_dir.join("f")).unwrap();
        assert!(idx.unix_denied_now(Some("/elsewhere/f"), Some((m.dev(), m.ino()))).is_some());
        assert!(idx.unix_denied_now(Some("/elsewhere/g"), Some((m.dev(), m.ino() + 1_000_000))).is_none());
        let empty: SecretPolicyFile = serde_json::from_str("{}").unwrap();
        assert!(empty.unix_deny.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_policy_file_carries_the_unix_policy() {
        let f: SecretPolicyFile = serde_json::from_str(r#"{"unixPolicy":{"allow":[{"path":"/x.sock","label":"ssh-agent"}],"abstractAllow":["/tmp/.X11-unix/X*"]}}"#).unwrap();
        let u = f.unix_policy.clone().unwrap();
        assert_eq!(u.allow[0].path, "/x.sock");
        assert_eq!(u.abstract_allow, vec!["/tmp/.X11-unix/X*".to_string()]);
        let idx = SecretIndex::from_file(f);
        assert!(!idx.is_empty(), "a unix policy alone makes the index non-empty");
        let none: SecretPolicyFile = serde_json::from_str("{}").unwrap();
        assert!(none.unix_policy.is_none(), "absent ⇒ no allow-list (the confidentiality axis off)");
    }

    fn wp(path: &str, answer: &str) -> WriteProtect {
        WriteProtect { path: path.into(), answer: answer.into(), label: "x".into(), ..Default::default() }
    }

    #[test]
    fn write_protect_matches_the_entry_and_everything_below_it() {
        let e = vec![wp("/h/.config/mandu", "deny"), wp("/h/.bashrc", "ask")];
        let none = |_: &str| None;
        assert_eq!(write_protected_hit(&e, "/h/.config/mandu", none, none).map(|w| w.answer()), Some(WriteAnswer::Deny));
        assert_eq!(write_protected_hit(&e, "/h/.config/mandu/policy.yaml", none, none).map(|w| w.answer()), Some(WriteAnswer::Deny));
        assert_eq!(write_protected_hit(&e, "/h/.bashrc", none, none).map(|w| w.answer()), Some(WriteAnswer::Ask));
        // Siblings and look-alikes are not inside.
        assert!(write_protected_hit(&e, "/h/.config/mandu-other/x", none, none).is_none());
        assert!(write_protected_hit(&e, "/h/.bashrc.bak", none, none).is_none());
        assert!(write_protected_hit(&e, "/h/.config", none, none).is_none(), "an ancestor is not inside");
    }

    #[test]
    fn write_protect_matches_by_file_identity() {
        // A hard link or a symlink elsewhere that names the protected file, and
        // a target whose parent directory is the protected directory under
        // another spelling (a bind, a folded case).
        let e = vec![wp("/h/.bashrc", "ask"), wp("/h/.config/systemd/user", "ask")];
        let ids = |p: &str| match p {
            "/h/.bashrc" | "/tmp/alias" => Some((1, 10)),
            "/h/.config/systemd/user" | "/mnt/bound" => Some((1, 20)),
            "/tmp/link" => Some((1, 10)), // follows the symlink
            _ => None,
        };
        let lids = |p: &str| match p {
            "/h/.bashrc" | "/tmp/alias" => Some((1, 10)),
            "/tmp/link" => Some((1, 99)), // the symlink itself
            _ => None,
        };
        assert_eq!(write_protected_hit(&e, "/tmp/alias", ids, lids).map(|w| w.path.as_str()), Some("/h/.bashrc"), "hard link");
        assert_eq!(write_protected_hit(&e, "/tmp/link", ids, lids).map(|w| w.path.as_str()), Some("/h/.bashrc"), "symlink to it");
        assert_eq!(write_protected_hit(&e, "/mnt/bound/evil.service", ids, lids).map(|w| w.path.as_str()), Some("/h/.config/systemd/user"), "bound parent");
        assert!(write_protected_hit(&e, "/tmp/other", ids, lids).is_none());
    }

    fn wpf(path: &str, form: &str) -> WriteProtect {
        WriteProtect { path: path.into(), answer: "deny".into(), label: "Mandu's own files".into(), form: form.into(), ..Default::default() }
    }

    #[test]
    fn the_runtime_registry_forms_match_by_name_prefix_and_self() {
        // runtime-instances.md §2 "planted paths": `current` is a link (the
        // entry itself), `.current.tmp-` and `dashboard-` are name prefixes,
        // the base itself may not be renamed while its scope dirs stay
        // writable.
        let e = vec![wpf("/r/mandu/current", "name"), wpf("/r/mandu/.current.tmp-", "prefix"), wpf("/r/mandu/dashboard-", "prefix"), wpf("/r/mandu", "self")];
        let none = |_: &str| None;
        let hit = |t: &str| write_protected_hit(&e, t, none, none).map(|w| w.path.clone());
        assert_eq!(hit("/r/mandu/current").as_deref(), Some("/r/mandu/current"));
        assert_eq!(hit("/r/mandu/current/arbiter.sock").as_deref(), Some("/r/mandu/current"), "below the name too");
        assert_eq!(hit("/r/mandu/current2"), None, "a longer name is another entry");
        assert_eq!(hit("/r/mandu/.current.tmp-4242").as_deref(), Some("/r/mandu/.current.tmp-"));
        assert_eq!(hit("/r/mandu/.current.tmp-"), Some("/r/mandu/.current.tmp-".into()), "the prefix itself");
        assert_eq!(hit("/r/mandu/dashboard-77.port.123.ab.tmp").as_deref(), Some("/r/mandu/dashboard-"));
        assert_eq!(hit("/r/mandu/dashboard-x/inner").as_deref(), Some("/r/mandu/dashboard-"), "below a prefixed name");
        assert_eq!(hit("/r/mandu/x.current.tmp-1"), None, "the prefix starts the name");
        assert_eq!(hit("/r/mandu/sub/.current.tmp-1"), None, "only in the entry's own directory");
        assert_eq!(hit("/r/mandu").as_deref(), Some("/r/mandu"), "the base itself (a rename, a removal)");
        assert_eq!(hit("/r/mandu/1700000000-42/exec-shims/curl"), None, "what is below a `self` entry stays writable");
        assert_eq!(hit("/r/mandu/dashboard.log"), None, "dashboard.log is its own `name` entry, not under `dashboard-`");
        assert_eq!(wpf("/x", "spline").form(), WriteForm::Path, "an unknown form is the widest");
    }

    #[test]
    fn the_runtime_registry_forms_match_by_identity_under_another_spelling() {
        // The base bound (or linked) elsewhere: /mnt/b is /r/mandu.
        let e = vec![wpf("/r/mandu/current", "name"), wpf("/r/mandu/.current.tmp-", "prefix"), wpf("/r/mandu", "self")];
        let id = |p: &str| match p {
            "/r/mandu" | "/mnt/b" => Some((1, 5)),
            "/r/mandu/current" => Some((1, 6)), // the instance it points at
            _ => None,
        };
        let lid = |p: &str| match p {
            "/r/mandu" | "/mnt/b" => Some((1, 5)),
            "/r/mandu/current" | "/mnt/b/current" => Some((1, 9)), // the link itself
            "/tmp/hard" => Some((1, 9)),
            _ => None,
        };
        let named = |leaf: &str, own: Option<(u64, u64)>, dir: Option<(u64, u64)>| write_protected_hit_named(&e, leaf, own, dir, id, lid).map(|w| w.path.clone());
        assert_eq!(named("current", Some((1, 9)), Some((1, 5))).as_deref(), Some("/r/mandu/current"), "a rename over /mnt/b/current");
        assert_eq!(named(".current.tmp-7", None, Some((1, 5))).as_deref(), Some("/r/mandu/.current.tmp-"), "a new name under the prefix, in the base by identity");
        assert_eq!(named("current", Some((1, 9)), Some((1, 77))).as_deref(), Some("/r/mandu/current"), "the link itself by its own identity (a hard link to it)");
        assert_eq!(named("current", None, Some((1, 77))), None, "the same name in another directory");
        assert_eq!(named("1700000000-42", None, Some((1, 5))), None, "a scope dir in the base is not an entry");
        assert_eq!(named("b", Some((1, 5)), Some((1, 2))).as_deref(), Some("/r/mandu"), "the base itself, by its identity (`self`)");
        // write_protected_hit (the unpinned form) agrees.
        assert_eq!(write_protected_hit(&e, "/mnt/b/current", id, lid).map(|w| w.path.as_str()), Some("/r/mandu/current"));
        assert_eq!(write_protected_hit(&e, "/mnt/b/.current.tmp-1", id, lid).map(|w| w.path.as_str()), Some("/r/mandu/.current.tmp-"));
        assert!(write_protected_hit(&e, "/mnt/b/1700000000-42", id, lid).is_none());
        // A `name` entry is not matched by what its link points at: a write
        // inside the instance is the `instances/` entry's business.
        assert!(write_protected_hit_pinned(&e, "/r/mandu/instances/i1/x", None, &[(1, 6)], id).is_none());
    }

    #[test]
    fn a_name_entry_keeps_its_last_component_when_the_index_resolves_it() {
        let dir = std::env::temp_dir().join(format!("mandu-wp-name-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("instances").join("i1")).unwrap();
        std::os::unix::fs::symlink("instances/i1", dir.join("current")).unwrap();
        let d = fs::canonicalize(&dir).unwrap().to_string_lossy().into_owned();
        let body = format!(
            r#"{{"agentExe":"","writeProtect":[{{"path":"{d}/current","answer":"deny","label":"x","form":"name"}},{{"path":"{d}/current","answer":"deny","label":"y"}}]}}"#
        );
        let idx = SecretIndex::from_file(serde_json::from_str(&body).unwrap());
        assert_eq!(idx.write_protect[0].path, format!("{d}/current"), "the link itself");
        assert_eq!(idx.write_protect[1].path, format!("{d}/instances/i1"), "a `path` entry follows it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_write_answer_is_a_denial() {
        assert_eq!(wp("/x", "ask").answer(), WriteAnswer::Ask);
        assert_eq!(wp("/x", "deny").answer(), WriteAnswer::Deny);
        assert_eq!(wp("/x", "").answer(), WriteAnswer::Deny);
        assert_eq!(wp("/x", "allow").answer(), WriteAnswer::Deny, "fail-closed on a word this guard does not know");
    }

    #[test]
    fn the_policy_file_carries_write_protect() {
        let f: SecretPolicyFile = serde_json::from_str(r#"{"agentExe":"/bin/claude","writeProtect":[{"path":"/h/.bashrc","answer":"ask","label":"a shell startup file"}]}"#).unwrap();
        assert_eq!(f.write_protect, vec![WriteProtect { path: "/h/.bashrc".into(), answer: "ask".into(), label: "a shell startup file".into(), ..Default::default() }]);
        let idx = SecretIndex::from_file(f);
        assert!(!idx.is_empty(), "a write-protect list alone makes the index non-empty");
        assert_eq!(idx.write_protect.len(), 1);
    }

    #[test]
    fn resolve_existing_keeps_the_missing_tail() {
        let dir = std::env::temp_dir().join(format!("mandu-wp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = std::fs::canonicalize(&dir).unwrap();
        let got = resolve_existing(&format!("{}/not/yet/here", dir.display()));
        assert_eq!(got, format!("{}/not/yet/here", real.display()));
        assert_eq!(resolve_existing(&dir.to_string_lossy()), real.to_string_lossy());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_targets_name_every_created_or_changed_path() {
        let a = [3u64, 100, 4, 200, 0, 0];
        assert_eq!(write_targets(libc::SYS_linkat as i64, &a), vec![(3, 100), (4, 200)], "linkat: the file named and the new name");
        let s = [100u64, 5, 300, 0, 0, 0];
        assert_eq!(write_targets(libc::SYS_symlinkat as i64, &s), vec![(5, 300)], "symlinkat: the new name only");
        assert_eq!(write_targets(libc::SYS_truncate as i64, &[400, 0, 0, 0, 0, 0]), vec![(libc::AT_FDCWD, 400)]);
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(write_targets(libc::SYS_creat as i64, &[500, 0o644, 0, 0, 0, 0]), vec![(libc::AT_FDCWD, 500)]);
            assert_eq!(write_targets(libc::SYS_link as i64, &[1, 2, 0, 0, 0, 0]), vec![(libc::AT_FDCWD, 1), (libc::AT_FDCWD, 2)]);
            assert_eq!(write_targets(libc::SYS_symlink as i64, &[1, 2, 0, 0, 0, 0]), vec![(libc::AT_FDCWD, 2)]);
        }
        assert!(write_targets(libc::SYS_read as i64, &a).is_empty());
        for nr in write_nrs() {
            assert!(is_write_nr(nr));
            assert!(!is_delete_nr(nr), "the two families are disjoint");
        }
    }

    #[test]
    fn protected_paths_refuse_inside_and_ancestors_not_siblings() {
        let p = vec!["/home/u/Documents".to_string()];
        assert_eq!(protected_hit(&p, "/home/u/Documents"), Some("/home/u/Documents"));
        assert_eq!(protected_hit(&p, "/home/u/Documents/tax/2025.pdf"), Some("/home/u/Documents"));
        assert_eq!(protected_hit(&p, "/home/u"), Some("/home/u/Documents"), "renaming an ancestor moves the tree");
        assert_eq!(protected_hit(&p, "/home/u/Documents2"), None, "a sibling with a shared prefix");
        assert_eq!(protected_hit(&p, "/home/u/work/tmp"), None);
        assert_eq!(protected_hit(&[], "/home/u/Documents"), None);
    }

    #[test]
    fn protected_paths_refuse_by_identity_what_the_path_compare_misses() {
        let protect = vec!["/mnt/c/Users/bob/Documents".to_string()];
        // drvfs: every spelling folds to one directory tree.
        let ids: HashMap<&str, (u64, u64)> = [
            ("/mnt/c/users/bob/documents", (9, 10)),
            ("/mnt/c/users/bob/documents/tax.pdf", (9, 11)),
            ("/mnt/c/users/bob", (9, 3)),
            ("/mnt/c/users", (9, 2)),
            ("/mnt/c", (9, 1)),
            ("/mnt", (1, 5)),
            ("/", (1, 2)),
            ("/mnt/c/users/bob/scratch.txt", (9, 12)),
        ]
        .into_iter()
        .collect();
        let id = |p: &str| ids.get(p.to_lowercase().as_str()).copied();
        assert_eq!(protected_hit(&protect, "/mnt/c/users/BOB/documents/tax.pdf"), None, "the path compare misses the spelling");
        let hit = |t: &str| protected_hit_by_id(&protect, t, id, id);
        assert_eq!(hit("/mnt/c/users/BOB/documents/tax.pdf"), Some("/mnt/c/Users/bob/Documents"), "inside, by a parent's identity");
        assert_eq!(hit("/mnt/c/USERS/bob/DOCUMENTS"), Some("/mnt/c/Users/bob/Documents"), "the protected dir itself");
        assert_eq!(hit("/mnt/c/users/Bob"), Some("/mnt/c/Users/bob/Documents"), "an ancestor");
        assert_eq!(hit("/mnt/c/users/bob/scratch.txt"), None, "a sibling file");
        assert_eq!(hit("/mnt/c/users/bob/missing"), None, "a target that is not there");
        // A protected path that does not exist protects nothing by identity.
        let gone = vec!["/nowhere".to_string()];
        assert_eq!(protected_hit_by_id(&gone, "/mnt/c/users/bob/scratch.txt", id, id), None);
    }

    #[test]
    fn protected_paths_refuse_by_pinned_identities_a_spelling_the_guard_cannot_see() {
        // A bind of the protected folder at /home/u/alias exists only in the
        // tracee's mount namespace: the guard resolves no such path, so the
        // identities come from the pinned descriptor (its `..` chain) and the
        // leaf's fstatat, never from a path string.
        let protect = vec!["/home/u/Documents".to_string()];
        let ids: HashMap<&str, (u64, u64)> =
            [("/home/u/Documents", (7, 40)), ("/home/u", (7, 30)), ("/home", (7, 20)), ("/", (7, 2))].into_iter().collect();
        let id = |p: &str| ids.get(p).copied();
        // rm alias/tax.pdf: the pin is the bound folder itself (same inode).
        let pin_chain = [(7, 40), (7, 30), (7, 20), (7, 2)];
        assert_eq!(protected_hit_by_ids(&protect, Some((7, 41)), &pin_chain, id), Some("/home/u/Documents"), "inside, by the pin's own identity");
        // rmdir alias (the leaf is the protected folder).
        assert_eq!(protected_hit_by_ids(&protect, Some((7, 40)), &[(7, 30), (7, 20), (7, 2)], id), Some("/home/u/Documents"), "the folder itself");
        // An ancestor of the protected folder disappearing.
        assert_eq!(protected_hit_by_ids(&protect, Some((7, 30)), &[(7, 20), (7, 2)], id), Some("/home/u/Documents"), "an ancestor");
        // A sibling folder's file.
        assert_eq!(protected_hit_by_ids(&protect, Some((7, 51)), &[(7, 50), (7, 30), (7, 20), (7, 2)], id), None, "elsewhere");
        // The leaf is gone: judged by the parents alone.
        assert_eq!(protected_hit_by_ids(&protect, None, &pin_chain, id), Some("/home/u/Documents"));
        assert_eq!(protected_hit_by_ids(&protect, None, &[(7, 50), (7, 30)], id), None);
    }

    #[test]
    fn delete_targets_name_both_sides_of_a_rename() {
        let args = [3u64, 100, 4, 200, 0, 0];
        assert_eq!(delete_targets(libc::SYS_unlinkat as i64, &args), vec![(3, 100)]);
        assert_eq!(delete_targets(libc::SYS_renameat2 as i64, &args), vec![(3, 100), (4, 200)]);
        assert!(is_delete_nr(libc::SYS_unlinkat as i64));
        assert!(!is_delete_nr(libc::SYS_openat as i64));
    }

    #[test]
    fn pinned_change_targets_carry_the_parent_and_role_of_every_name_family_call() {
        use ChangeRole::*;
        // unlinkat: one Remove target, dirfd from arg0.
        assert_eq!(pinned_change_targets(libc::SYS_unlinkat as i64, &[3, 100, 0, 0, 0, 0]), vec![(3, 100, Remove)]);
        // renameat2: source then destination, EXCHANGE or not (the flags do
        // not change the roles; the perform step reads them).
        assert_eq!(
            pinned_change_targets(libc::SYS_renameat2 as i64, &[3, 100, 4, 200, libc::RENAME_EXCHANGE as u64, 0]),
            vec![(3, 100, RenameSrc), (4, 200, Dest)],
        );
        assert_eq!(pinned_change_targets(libc::SYS_renameat as i64, &[3, 100, 4, 200, 0, 0]), vec![(3, 100, RenameSrc), (4, 200, Dest)]);
        // linkat: the linked file (source) and the new name.
        assert_eq!(pinned_change_targets(libc::SYS_linkat as i64, &[3, 100, 4, 200, 0, 0]), vec![(3, 100, LinkSource), (4, 200, NewName)]);
        // symlinkat: the new name only (arg0 is the target text, not a path).
        assert_eq!(pinned_change_targets(libc::SYS_symlinkat as i64, &[999, 5, 300, 0, 0, 0]), vec![(5, 300, NewName)]);
        // truncate follows symlinks: the whole path is the target.
        assert_eq!(pinned_change_targets(libc::SYS_truncate as i64, &[400, 4096, 0, 0, 0, 0]), vec![(libc::AT_FDCWD, 400, Truncate)]);
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(pinned_change_targets(libc::SYS_rename as i64, &[100, 200, 0, 0, 0, 0]), vec![(libc::AT_FDCWD, 100, RenameSrc), (libc::AT_FDCWD, 200, Dest)]);
            assert_eq!(pinned_change_targets(libc::SYS_link as i64, &[100, 200, 0, 0, 0, 0]), vec![(libc::AT_FDCWD, 100, LinkSource), (libc::AT_FDCWD, 200, NewName)]);
            assert_eq!(pinned_change_targets(libc::SYS_symlink as i64, &[999, 200, 0, 0, 0, 0]), vec![(libc::AT_FDCWD, 200, NewName)]);
            assert_eq!(pinned_change_targets(libc::SYS_unlink as i64, &[100, 0, 0, 0, 0, 0]), vec![(libc::AT_FDCWD, 100, Remove)]);
            assert_eq!(pinned_change_targets(libc::SYS_rmdir as i64, &[100, 0, 0, 0, 0, 0]), vec![(libc::AT_FDCWD, 100, Remove)]);
            // creat is routed to the write-open path, not judged here.
            assert!(pinned_change_targets(libc::SYS_creat as i64, &[100, 0o644, 0, 0, 0, 0]).is_empty());
        }
        assert!(pinned_change_targets(libc::SYS_read as i64, &[0; 6]).is_empty(), "a call that names nothing");
    }

    #[test]
    fn a_registered_secrets_file_is_never_replaced_removed_moved_or_emptied() {
        use ChangeRole::*;
        // A protected file (kind absent or `file`): every role that would
        // move, link, empty, re-mode, REPLACE (a rename onto it: `sed -i`'s
        // last step) or REMOVE it is refused (2026-10-02: Dest and Remove
        // joined the rest; before, a rename onto the real file went through).
        for kind in [None, Some("file")] {
            for role in [RenameSrc, LinkSource, Truncate, Mode, Dest, Remove] {
                assert!(registered_secret_refuses(role, kind), "{role:?} of a {kind:?} entry");
            }
            assert!(!registered_secret_refuses(NewName, kind), "a new name replaces nothing");
        }
        // An unknown kind (a launcher newer than this guard): fail-closed.
        assert!(registered_secret_refuses(Dest, Some("future")));
        assert!(registered_secret_refuses(Remove, Some("future")));
        // git's object store: replaced and removed as git does (gc, repack);
        // its bytes still never move or get a second name.
        for kind in [Some("object"), Some("deny")] {
            assert!(!registered_secret_refuses(Dest, kind), "{kind:?} replaced");
            assert!(!registered_secret_refuses(Remove, kind), "{kind:?} removed");
            for role in [RenameSrc, LinkSource, Truncate, Mode] {
                assert!(registered_secret_refuses(role, kind), "{role:?} of a {kind:?} entry");
            }
        }
    }

    #[test]
    fn mknod_and_mode_changes_are_name_family_calls_with_their_roles() {
        use ChangeRole::*;
        // mknodat: a new name (dirfd arg0, path arg1).
        assert_eq!(pinned_change_targets(libc::SYS_mknodat as i64, &[3, 100, 0o10644, 0, 0, 0]), vec![(3, 100, NewName)]);
        // fchmodat / fchmodat2: the whole path is the target.
        assert_eq!(pinned_change_targets(libc::SYS_fchmodat as i64, &[3, 100, 0o755, 0, 0, 0]), vec![(3, 100, Mode)]);
        assert_eq!(pinned_change_targets(SYS_FCHMODAT2, &[3, 100, 0o755, libc::AT_SYMLINK_NOFOLLOW as u64, 0, 0]), vec![(3, 100, Mode)]);
        // fchmod names no path: judged by its descriptor, not here.
        assert!(pinned_change_targets(libc::SYS_fchmod as i64, &[5, 0o755, 0, 0, 0, 0]).is_empty());
        // The xattr family is judged on the file it pins, not by a parent
        // and leaf (guard_kernel::perform_xattr), and is a write-family call.
        for nr in crate::xattr_change::xattr_nrs() {
            assert!(pinned_change_targets(nr, &[3, 100, 200, 0, 0, 0]).is_empty(), "nr {nr}");
            assert!(is_write_nr(nr) && !is_delete_nr(nr) && !is_mode_nr(nr) && !is_mknod_nr(nr));
        }
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(pinned_change_targets(libc::SYS_mknod as i64, &[100, 0o10644, 0, 0, 0, 0]), vec![(libc::AT_FDCWD, 100, NewName)]);
            assert_eq!(pinned_change_targets(libc::SYS_chmod as i64, &[100, 0o755, 0, 0, 0, 0]), vec![(libc::AT_FDCWD, 100, Mode)]);
        }
        for nr in mknod_nrs().into_iter().chain(mode_nrs()) {
            assert!(is_write_nr(nr), "nr {nr} is trapped with the write family");
            assert!(!is_delete_nr(nr));
        }
        // fchmodat2 is 452 on every arch.
        assert_eq!(SYS_FCHMODAT2, 452);
    }

    #[test]
    fn mkdir_calls_decode_and_stand_apart_from_the_other_families() {
        // Plan 13 §9 R4 (b), 2026-10-04: a holder's directory name on a
        // remote mount. mkdirat(dirfd, path, mode).
        assert_eq!(mkdir_call(libc::SYS_mkdirat as i64, &[3, 100, 0o755, 0, 0, 0]), Some((3, 100, 0o755)));
        #[cfg(target_arch = "x86_64")]
        assert_eq!(mkdir_call(libc::SYS_mkdir as i64, &[100, 0o700, 0, 0, 0, 0]), Some((libc::AT_FDCWD, 100, 0o700)));
        assert_eq!(mkdir_call(libc::SYS_mknodat as i64, &[3, 100, 0o755, 0, 0, 0]), None);
        for nr in mkdir_nrs() {
            assert!(is_mkdir_nr(nr));
            assert!(!is_write_nr(nr) && !is_delete_nr(nr) && !is_open_nr(nr), "nr {nr}: dispatched on its own");
        }
    }

    #[test]
    fn mode_call_decodes_every_form_and_refuses_unknown_fchmodat2_flags() {
        assert_eq!(
            mode_call(libc::SYS_fchmodat as i64, &[3, 100, 0o755, 0xdead, 0, 0]),
            Ok(Some(ModeCall::Path { dirfd: 3, addr: 100, mode: 0o755, follow: true, empty_path: false })),
            "the fchmodat syscall has no flags argument: arg3 is ignored, the final symlink followed",
        );
        assert_eq!(
            mode_call(SYS_FCHMODAT2, &[3, 100, 0o700, libc::AT_SYMLINK_NOFOLLOW as u64, 0, 0]),
            Ok(Some(ModeCall::Path { dirfd: 3, addr: 100, mode: 0o700, follow: false, empty_path: false })),
        );
        assert_eq!(
            mode_call(SYS_FCHMODAT2, &[7, 100, 0o700, libc::AT_EMPTY_PATH as u64, 0, 0]),
            Ok(Some(ModeCall::Path { dirfd: 7, addr: 100, mode: 0o700, follow: true, empty_path: true })),
        );
        assert_eq!(mode_call(SYS_FCHMODAT2, &[3, 100, 0o700, libc::AT_REMOVEDIR as u64, 0, 0]), Err(libc::EINVAL));
        assert_eq!(mode_call(libc::SYS_fchmod as i64, &[5, 0o4755, 0, 0, 0, 0]), Ok(Some(ModeCall::Fd { fd: 5, mode: 0o4755 })));
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            mode_call(libc::SYS_chmod as i64, &[100, 0o755, 0, 0, 0, 0]),
            Ok(Some(ModeCall::Path { dirfd: libc::AT_FDCWD, addr: 100, mode: 0o755, follow: true, empty_path: false })),
        );
        assert_eq!(mode_call(libc::SYS_openat as i64, &[0; 6]), Ok(None));
        assert_eq!(mknod_call(libc::SYS_mknodat as i64, &[3, 100, libc::S_IFIFO as u64 | 0o644, 0, 0, 0]), Some((3, 100, libc::S_IFIFO | 0o644, 0)));
        #[cfg(target_arch = "x86_64")]
        assert_eq!(mknod_call(libc::SYS_mknod as i64, &[100, libc::S_IFREG as u64 | 0o600, 0, 0, 0, 0]), Some((libc::AT_FDCWD, 100, libc::S_IFREG | 0o600, 0)));
        assert_eq!(mknod_call(libc::SYS_openat as i64, &[0; 6]), None);
    }

    #[test]
    fn a_mode_change_to_the_files_own_bits_is_a_noop() {
        assert!(mode_change_is_noop(libc::S_IFREG | 0o644, 0o644));
        assert!(mode_change_is_noop(libc::S_IFREG | 0o644, 0o100644), "type bits in the request are ignored");
        assert!(!mode_change_is_noop(libc::S_IFREG | 0o644, 0o755), "arming a script is a change");
        assert!(!mode_change_is_noop(libc::S_IFREG | 0o755, 0o4755), "a setuid bit is a change");
        assert!(!mode_change_is_noop(libc::S_IFREG | 0o600, 0o644), "opening a file to others is a change");
    }

    #[test]
    fn relative_unix_addr_holds_any_leaf_sun_path_can() {
        let fam = (libc::AF_UNIX as u16).to_ne_bytes();
        let a = relative_unix_addr(b"arbiter.sock").unwrap();
        assert_eq!(&a[..2], &fam);
        assert_eq!(&a[2..], b"arbiter.sock\0");
        // 107 bytes + NUL fills sun_path; 108 is legal unterminated.
        let l107 = vec![b'x'; 107];
        assert_eq!(relative_unix_addr(&l107).unwrap().len(), 2 + 108);
        let l108 = vec![b'x'; 108];
        assert_eq!(relative_unix_addr(&l108).unwrap().len(), 2 + 108);
        assert!(relative_unix_addr(&[b'x'; 109]).is_none());
        assert!(relative_unix_addr(b"a/b").is_none(), "one component only");
        assert!(relative_unix_addr(b"").is_none());
        assert!(relative_unix_addr(b"a\0b").is_none());
    }

    #[test]
    fn split_parent_leaf_names_the_final_component_only() {
        let sp = |p: &str| split_parent_leaf(p.as_bytes()).map(|(a, b)| (String::from_utf8(a).unwrap(), String::from_utf8(b).unwrap()));
        assert_eq!(sp("/a/b/c"), Some(("/a/b".into(), "c".into())));
        assert_eq!(sp("/a"), Some(("/".into(), "a".into())), "a leaf directly under root");
        assert_eq!(sp("a/b"), Some(("a".into(), "b".into())), "relative: parent is a walk from the dirfd");
        assert_eq!(sp("foo"), Some((".".into(), "foo".into())), "no slash: the dirfd's own directory");
        assert_eq!(sp("/a/b/"), Some(("/a".into(), "b".into())), "one trailing slash is trimmed");
        assert_eq!(sp("/a/b///"), Some(("/a".into(), "b".into())), "several trailing slashes");
        assert_eq!(sp("/"), None, "root is not a single-component change");
        assert_eq!(sp(""), None);
        assert_eq!(sp("/a/."), None, "a dot leaf names the directory itself");
        assert_eq!(sp("/a/.."), None, "a dotdot leaf walks up");
    }

    #[test]
    fn socket_readers_follow_the_arbiters_identity_of_the_binary() {
        // Plan 13 D8 (2026-10-03): the socket's list judged by name only;
        // a byte-identical copy of perl as `perl5.40.1`, or of env under a
        // leaf program's name, passed. Now the arbiter's `readerProgram`
        // (name and host hash) must find the binary neither a printer nor a
        // program that runs code, and no answer refuses.
        assert!(socket_identity_admits(Some((false, false))), "a leaf program the arbiter knows as one");
        assert!(!socket_identity_admits(Some((false, true))), "a copy of a program that runs code");
        assert!(!socket_identity_admits(Some((true, false))), "a copy of a printer");
        assert!(!socket_identity_admits(Some((true, true))));
        assert!(!socket_identity_admits(None), "the arbiter unreachable, or the binary unhashed: refused");
        // the name rule alone admitted the versioned perl (its suffix is no
        // alternatives suffix), which is why the hash must be asked; since
        // 2026-10-04 the name rule takes a trailing version off too
        // (`without_version`), and the hash is still asked for a copy under
        // any other name
        let listed: Vec<ReaderSpec> = serde_json::from_str(r#"["perl5.40.1"]"#).unwrap();
        assert_eq!(socket_reader_match(&listed, "/usr/bin/perl5.40.1", true, &[]), None);
    }

    #[test]
    fn socket_readers_match_by_name_and_lineage() {
        let readers: Vec<ReaderSpec> = serde_json::from_str(r#"["ssh-add", {"app":"ssh","from":"git"}]"#).unwrap();
        let t = |v: &[&str]| -> Vec<(String, bool)> { v.iter().map(|a| (a.to_string(), true)).collect() };
        let git = t(&["/usr/lib/git-core/git", "/usr/bin/bash"]);
        let shell = t(&["/usr/bin/bash", "/usr/bin/node"]);
        assert_eq!(socket_reader_match(&readers, "/usr/bin/ssh", true, &git), Some("ssh"));
        assert_eq!(socket_reader_match(&readers, "/usr/bin/ssh", true, &shell), None, "an ssh the agent runs directly");
        assert_eq!(socket_reader_match(&readers, "/usr/bin/ssh-add", true, &shell), Some("ssh-add"));
        assert_eq!(socket_reader_match(&readers, "/usr/bin/curl", true, &git), None);
        // Plan 13 D8: a name is carried only by a binary out of the agent's
        // reach and run with a clean loader environment; `from:` only by a
        // trusted ancestor (a renamed shell is not the program it is named for)
        assert_eq!(socket_reader_match(&readers, "/home/u/ws/ssh-add", false, &shell), None, "the agent's own ssh-add");
        assert_eq!(socket_reader_match(&readers, "/usr/bin/ssh", false, &git), None, "ssh run with LD_PRELOAD");
        let renamed = vec![("/home/u/ws/git".to_string(), false), ("/usr/bin/bash".to_string(), true)];
        assert_eq!(socket_reader_match(&readers, "/usr/bin/ssh", true, &renamed), None, "a copy of sh under the parent's name");
        // Plan 13 §8 decision (b): a shell or an interpreter named on the
        // list admits nothing (any script the agent writes would sign with
        // the human's key), whatever its trust.
        let shells: Vec<ReaderSpec> = serde_json::from_str(r#"["bash", "python3", {"app":"sh","from":"git"}, "ssh-add"]"#).unwrap();
        assert_eq!(socket_reader_match(&shells, "/usr/bin/bash", true, &shell), None, "readers: [bash] admits no bash");
        assert_eq!(socket_reader_match(&shells, "/usr/bin/python3.12", true, &shell), None, "readers: [python3] admits no python");
        assert_eq!(socket_reader_match(&shells, "/usr/bin/sh", true, &git), None, "nor a shell under a trusted git");
        assert_eq!(socket_reader_match(&shells, "/usr/bin/ssh-add", true, &shell), Some("ssh-add"), "a leaf program on the same list still is");
        assert!(runs_code("/usr/bin/python3.12") && runs_code("bash") && !runs_code("ssh-add") && !runs_code("bashful"));
        // 2026-10-04: build tools, more runtimes, the TeX engines, and a
        // trailing version after a letter (`without_version`)
        for n in ["cmake", "ninja", "go", "cargo", "npm", "run-parts", "beam.smp", "erl", "pdftex", "php8.5", "/usr/bin/lua5.4", "tclsh8.6", "ruby3.3", "perl5.40.1", "guile-3.0"] {
            assert!(runs_code(n), "{n}");
        }
        assert!(prints("gcc-15") && prints("clang-18") && !runs_code("psql16") && !runs_code("kubectl1.30") && !runs_code("gofmt"));
        // P0 item 14 (2026-10-07): the names nushell, the pdksh line and
        // Racket's two builds install as; elvish and dotnet were known
        for n in ["nu", "/usr/bin/nu", "oksh", "loksh", "pdksh", "racketbc", "racketcs", "elvish", "nushell", "dotnet"] {
            assert!(runs_code(n), "{n}");
            assert_eq!(socket_reader_match(&[ReaderSpec::Name(n.rsplit('/').next().unwrap().to_string())], &format!("/usr/bin/{}", n.rsplit('/').next().unwrap()), true, &[]), None, "{n}");
        }
        assert!(!runs_code("nuke") && !runs_code("numfmt"));
        assert_eq!(without_version("php8.5"), Some("php"));
        assert_eq!(without_version("gcc-15"), Some("gcc"));
        assert_eq!(without_version("perl5.40.1"), Some("perl"));
        for n in ["x86_64", "1.2", "a.1", "a1.", "a1..2", "psql", "abc--1"] {
            assert_eq!(without_version(n), None, "{n}");
        }
        assert!(app_name_matches("python3.12", "python3"));
        assert!(!app_name_matches("ssh2", "ssh"));
        assert!(!app_name_matches("python3.12-config", "python3"));
        assert!(!app_name_matches("python3.", "python3"));
        assert!(app_name_matches("nc.openbsd", "nc"));
    }

    /// Plan 13 D8 leftover (3a): a launcher is one under a distribution's
    /// prefix too (Ubuntu 26.04's GNU coreutils are `gnuenv`, `gnutimeout`,
    /// …; Homebrew's `genv`, `gmake`; `uu-env`), a multi-call binary
    /// (`toybox`, `coreutils`) is every launcher it carries, and every file
    /// of uutils' multi-call directory is `env` whatever its name. A relay
    /// that runs a program from its arguments (`nc -e`, `ncat --sh-exec`,
    /// `socat EXEC:`) is one as well.
    #[test]
    fn launchers_run_code_under_every_name_the_arbiter_knows() {
        for n in [
            "gnuenv", "gnutimeout", "gnunice", "gnustdbuf", "gnunohup", "gnuchroot", "gnusetsid", "gnuxargs", "gnufind",
            "genv", "gtimeout", "gnice", "gstdbuf", "gxargs", "gfind", "gmake", "uu-env", "uu_timeout", "uu-nice", "uu_stdbuf",
            "toybox", "coreutils", "busybox", "/usr/bin/toybox", "/usr/lib/cargo/bin/coreutils/env",
            "/usr/lib/cargo/bin/coreutils/wc", "nc", "nc.openbsd", "nc.traditional", "ncat", "netcat", "socat",
        ] {
            assert!(runs_code(n), "{n} runs another program");
        }
        for n in ["ssh-add", "ssh", "git", "gh", "gpg-agent", "psql", "gnome-keyring-daemon", "bashful", "u", "g", "gnu", "uu-"] {
            assert!(!runs_code(n), "{n} is a leaf program");
        }
    }

    /// 2026-10-03: the fetch and transfer clients that run a command they
    /// are given (tnftp's `!cmd`, aria2c's `--on-download-*` hooks, sftp's
    /// `!`, `--use-askpass`, `gio launch`, …), more editors and more
    /// launchers run code: on the ssh-agent socket's list each admits
    /// nothing, under its alternatives name too (`/usr/bin/tnftp`).
    #[test]
    fn fetchers_editors_and_launchers_that_run_a_command_admit_nothing_on_the_socket() {
        let shell: Vec<(String, bool)> = vec![("/usr/bin/bash".to_string(), true)];
        for n in [
            "ftp", "/usr/bin/tnftp", "netkit-ftp", "pftp", "inetutils-ftp", "aria2c", "lftp", "sftp", "wget", "wget2", "rclone", "gio",
            "kioclient5", "lynx", "w3m", "elinks", "links2", "nvi", "kak", "hx", "joe", "jed", "mg", "zile", "mcedit", "valgrind",
            "perf", "setpriv", "unbuffer", "torsocks", "proxychains4", "fakeroot", "xvfb-run", "tmux", "screen", "entr",
        ] {
            assert!(runs_code(n) && admits_nothing(n), "{n} runs a command it is given");
            let listed: Vec<ReaderSpec> = vec![ReaderSpec::Name(basename(n).to_string())];
            assert_eq!(socket_reader_match(&listed, &format!("/usr/bin/{}", basename(n)), true, &shell), None, "{n} listed admits nothing");
        }
        for n in ["ssh-add", "ssh", "git", "curl", "scp", "psql"] {
            assert!(!runs_code(n), "{n} runs no command it is given by name alone");
        }
    }

    /// Plan 13 D8 (12), the allow-list (2026-10-04): on the ssh-agent
    /// socket's list a program that is not vetted connects only when its
    /// entry carries the human's word (`prints: nothing`); a printer or a
    /// program that runs code never does, word or not. Red before: a listed
    /// `my-signer` connected.
    #[test]
    fn socket_readers_follow_the_allow_list() {
        assert_eq!(VETTED_READERS, &["ssh", "ssh-add"]);
        for n in ["ssh", "ssh-add", "/usr/bin/ssh", "ssh.openssh"] {
            assert!(vetted(n), "{n}");
        }
        for n in ["git", "my-signer", "gh", "aws", "cat", "bash", "sshd", "ssh2", "psql", "pg_dump", "pg_restore"] {
            assert!(!vetted(n), "{n}");
        }
        let shell: Vec<(String, bool)> = vec![("/usr/bin/bash".to_string(), true)];
        let bare: Vec<ReaderSpec> = serde_json::from_str(r#"["my-signer", "ssh-add"]"#).unwrap();
        assert_eq!(socket_reader_match(&bare, "/usr/bin/my-signer", true, &shell), None, "unvetted, no word");
        assert_eq!(socket_reader_match(&bare, "/usr/bin/ssh-add", true, &shell), Some("ssh-add"), "vetted");
        let word: Vec<ReaderSpec> = serde_json::from_str(r#"[{"app":"my-signer","prints":"nothing"}, {"app":"socat","prints":"nothing"}, {"app":"bash","prints":"nothing"}]"#).unwrap();
        assert_eq!(socket_reader_match(&word, "/usr/bin/my-signer", true, &shell), Some("my-signer"), "the human's word");
        assert_eq!(socket_reader_match(&word, "/usr/bin/socat", true, &shell), None, "no word lifts a printer");
        assert_eq!(socket_reader_match(&word, "/usr/bin/bash", true, &shell), None, "nor a program that runs code");
        let other: Vec<ReaderSpec> = serde_json::from_str(r#"[{"app":"my-signer","prints":"everything"}]"#).unwrap();
        assert_eq!(socket_reader_match(&other, "/usr/bin/my-signer", true, &shell), None, "only `nothing` is the word");
    }

    /// Plan 13 D8 leftover (3b), printers admit nothing (2026-10-03) for the
    /// ssh-agent socket as for a file: a printer or a relay named among its
    /// readers (`socat`, `nc`, `openssl s_client -unix`) hands the agent's
    /// signing to whatever drives it, the agent's own code included, so the
    /// entry admits nothing, bare or under `from:`, and a listed leaf
    /// program beside it still connects.
    #[test]
    fn socket_readers_admit_no_printer_or_relay() {
        let readers: Vec<ReaderSpec> = serde_json::from_str(
            r#"["socat", "nc", {"app":"openssl","from":"git"}, "cat", "gnuenv", "toybox", {"app":"ncat","from":"git"}, "ssh-add"]"#,
        )
        .unwrap();
        let t = |v: &[&str]| -> Vec<(String, bool)> { v.iter().map(|a| (a.to_string(), true)).collect() };
        let git = t(&["/usr/lib/git-core/git", "/usr/bin/bash"]);
        let shell = t(&["/usr/bin/bash", "/usr/bin/node"]);
        for exe in [
            "/usr/bin/socat", "/usr/bin/nc", "/usr/bin/nc.openbsd", "/usr/bin/openssl", "/usr/bin/cat", "/usr/bin/gnucat",
            "/usr/bin/gnuenv", "/usr/bin/toybox", "/usr/bin/ncat", "/usr/lib/cargo/bin/coreutils/cat",
        ] {
            assert_eq!(socket_reader_match(&readers, exe, true, &git), None, "{exe} listed under git admits nothing");
            assert_eq!(socket_reader_match(&readers, exe, true, &shell), None, "{exe} listed admits nothing");
        }
        assert_eq!(socket_reader_match(&readers, "/usr/bin/ssh-add", true, &shell), Some("ssh-add"), "a leaf program on the same list still is");
        // the opener is judged too: a printer that a listed name would match
        // by an alternatives link is still a printer
        let named: Vec<ReaderSpec> = serde_json::from_str(r#"["xz"]"#).unwrap();
        assert_eq!(socket_reader_match(&named, "/usr/bin/xz.alt", true, &shell), None);
        assert!(prints("socat") && prints("/usr/bin/gnucat") && prints("uu-base64") && prints("/usr/lib/cargo/bin/coreutils/wc"));
        assert!(!prints("ssh-add") && !prints("ssh") && !prints("gh") && !prints("category") && !prints("gpg-agent"));
        assert!(!prints("gitk") && !prints("git-lfs") && !prints("ssh-agent"));
        // the !437 leftover (1): a fetcher or a transfer tool is a printer
        // (scp itself never connects: the ssh it runs does, and is judged)
        assert!(prints("curl") && prints("/usr/bin/wget") && prints("scp") && prints("sftp") && prints("gio") && prints("lynx"));
        // 2026-10-04: what prints a file when asked (`file -f`, `date -f`,
        // `wc --files0-from`, `cc -E`, an `@file` response file, `nroff`)
        for n in ["file", "/usr/bin/file", "date", "gnudate", "wc", "gnuwc", "du", "cpp", "gcc", "g++", "clang", "as", "ld", "ld.bfd", "nroff", "man", "tic", "msgcat"] {
            assert!(prints(n), "{n}");
        }
        assert!(!prints("sha256sum") && !prints("/usr/bin/gnusha256sum") && !prints("ssh-keygen") && !prints("stat"));
        let fetchers: Vec<ReaderSpec> = serde_json::from_str(r#"["curl", "scp", {"app":"ssh","from":"scp"}]"#).unwrap();
        assert_eq!(socket_reader_match(&fetchers, "/usr/bin/curl", true, &shell), None);
        assert_eq!(socket_reader_match(&fetchers, "/usr/bin/scp", true, &shell), None);
        let scp = t(&["/usr/bin/scp", "/usr/bin/bash"]);
        assert_eq!(socket_reader_match(&fetchers, "/usr/bin/ssh", true, &scp), Some("ssh"), "ssh under scp, a `from:` parent, still connects");
    }

    /// Plan 13 §4.9 option (a) (2026-10-04): git is a printer (`git diff
    /// --no-index /dev/null <file>`), with its credential helper and its
    /// HTTP transport; named on the ssh-agent socket's list it admits
    /// nothing, while `{ app: ssh, from: git }` (the ssh git starts, which
    /// is what connects) still does.
    #[test]
    fn git_is_a_printer_and_its_ssh_still_connects() {
        for n in [
            "git", "/usr/bin/git", "/usr/lib/git-core/git", "git-credential-store", "/usr/lib/git-core/git-credential-store",
            "git-remote-http", "git-remote-https", "/usr/libexec/git-core/git-remote-https", "git-remote-ftp", "git-remote-ftps", "git.real",
            // 2026-10-07: git's own separately built programs (libcurl reads
            // .netrc for the first three; the CGI server sends a named file)
            "git-http-fetch", "/usr/lib/git-core/git-http-push", "git-imap-send", "git-http-backend",
            // 2026-10-07: every git credential helper, by its prefix
            "git-credential-libsecret", "/usr/local/bin/git-credential-manager", "git-credential-osxkeychain",
        ] {
            assert!(prints(n) && admits_nothing(n), "{n} prints a file it is pointed at");
        }
        for n in ["git-credential-", "mygit-credential-x", "credential-helper", "git-lfs"] {
            assert!(!prints(n), "{n} is no printer by the prefix");
        }
        let shell: Vec<(String, bool)> = vec![("/usr/bin/bash".to_string(), true)];
        let listed: Vec<ReaderSpec> = serde_json::from_str(r#"["git", "git-credential-store", {"app":"ssh","from":"git"}]"#).unwrap();
        assert_eq!(socket_reader_match(&listed, "/usr/bin/git", true, &shell), None, "git listed admits nothing");
        assert_eq!(socket_reader_match(&listed, "/usr/lib/git-core/git-credential-store", true, &shell), None);
        let under_git: Vec<(String, bool)> = vec![("/usr/lib/git-core/git".to_string(), true), ("/usr/bin/bash".to_string(), true)];
        assert_eq!(socket_reader_match(&listed, "/usr/bin/ssh", true, &under_git), Some("ssh"), "ssh under git, a `from:` parent, still connects");
        assert_eq!(socket_reader_match(&listed, "/usr/bin/ssh", true, &shell), None, "an ssh the agent runs itself is not git's");
    }

    #[test]
    fn socket_secrets_parse_and_index() {
        let f: SecretPolicyFile = serde_json::from_str(r#"{"sockets":[{"path":"/run/x/agent.sock","label":"ssh-agent","readers":[{"app":"ssh","from":"git"}]}]}"#).unwrap();
        let idx = SecretIndex::from_file(f);
        assert!(!idx.is_empty(), "a socket alone makes the index non-empty");
        assert_eq!(idx.socket("/run/x/agent.sock").and_then(|s| s.label.clone()).as_deref(), Some("ssh-agent"));
        assert!(idx.socket("/run/x/other.sock").is_none());
        assert!(idx.has_sockets() && !SecretIndex::from_file(SecretPolicyFile::default()).has_sockets());
    }

    #[test]
    fn a_socket_secret_is_found_by_the_inode_the_guard_opened() {
        let f: SecretPolicyFile = serde_json::from_str(r#"{"sockets":[{"path":"/run/x/agent.sock","label":"ssh-agent","readers":["ssh"]}]}"#).unwrap();
        let idx = SecretIndex::from_file(f);
        let stat = |p: &str| (p == "/run/x/agent.sock").then_some((5u64, 50u64));
        // By the path the kernel reports for the opened file.
        assert!(idx.socket_for_inode(Some("/run/x/agent.sock"), (0, 0), |_| None).is_some());
        // By identity: a hardlink (or a swapped symlink's target) elsewhere.
        assert_eq!(idx.socket_for_inode(Some("/tmp/innocent"), (5, 50), stat).and_then(|s| s.label.as_deref()), Some("ssh-agent"));
        assert!(idx.socket_for_inode(Some("/tmp/innocent"), (5, 51), stat).is_none());
        assert!(idx.socket_for_inode(None, (6, 50), stat).is_none());
    }

    #[test]
    fn policy_file_parses_and_indexes() {
        let f: SecretPolicyFile = serde_json::from_str(
            r#"{"agentExe":"/usr/bin/node","ask":"known","session":"s1","secrets":[{"path":"/h/.pgpass","twin":"/run/t/000","level":"no-model"}]}"#,
        )
        .unwrap();
        let idx = SecretIndex::from_file(f);
        assert_eq!(idx.agent_exe, "/usr/bin/node");
        assert_eq!(idx.ask.as_deref(), Some("known"));
        assert_eq!(idx.lookup("/h/.pgpass").unwrap().twin, "/run/t/000");
        assert!(idx.lookup("/h/other").is_none());
        assert!(!idx.is_empty());
        assert!(SecretIndex::from_file(SecretPolicyFile::default()).is_empty());
    }

    #[test]
    fn another_name_for_a_registered_file_is_that_secret() {
        let fid = |dev: u64, ino: u64| Some(FileId { dev, ino, links: 1, ctime_ns: 0 });
        let f: SecretPolicyFile = serde_json::from_str(
            r#"{"agentExe":"","secrets":[{"path":"/mnt/c/Users/bob/.aws/credentials","twin":"/run/t/001","level":"no-model"}]}"#,
        )
        .unwrap();
        let idx = SecretIndex::from_file(f);
        // drvfs folds case: every spelling of the file is one inode.
        let folding = |p: &str| if p.to_lowercase() == "/mnt/c/users/bob/.aws/credentials" { fid(9, 42) } else { None };
        let hit = idx.lookup_with("/mnt/c/users/BOB/.AWS/CREDENTIALS", folding).map(|e| e.twin.as_str());
        assert_eq!(hit, Some("/run/t/001"));
        // A case-sensitive filesystem: the other spelling is another file.
        let idx = SecretIndex::from_file(serde_json::from_str(r#"{"agentExe":"","secrets":[{"path":"/h/.aws/credentials","twin":"/t","level":"no-model"}]}"#).unwrap());
        let distinct = |p: &str| match p {
            "/h/.aws/credentials" => fid(9, 42),
            "/t" => fid(8, 1),
            _ => fid(9, 43),
        };
        assert!(idx.lookup_with("/h/.AWS/credentials", distinct).is_none());
        // A path that does not exist has no identity: no match.
        assert!(idx.lookup_with("/h/.aws/nope", |p| if p == "/h/.aws/credentials" { fid(9, 42) } else { None }).is_none());
        // No registered secrets: nothing is stat'ed.
        let empty = SecretIndex::from_file(SecretPolicyFile::default());
        assert!(empty.lookup_with("/h/x", |p| panic!("stat of {p}")).is_none());
    }

    #[test]
    fn a_file_the_guard_opened_is_a_secret_by_its_identity_or_its_twins() {
        // confidentiality-plan-10 §4.1a: the guard opens the file itself and
        // matches what it opened, whatever path led there.
        let idx = SecretIndex::from_file(serde_json::from_str(r#"{"agentExe":"","secrets":[{"path":"/h/.aws/credentials","twin":"/run/t/001","level":"no-model"}]}"#).unwrap());
        let ids = |p: &str| match p {
            "/h/.aws/credentials" => Some(FileId { dev: 9, ino: 42, links: 1, ctime_ns: 0 }),
            "/run/t/001" => Some(FileId { dev: 30, ino: 5, links: 1, ctime_ns: 0 }),
            _ => None,
        };
        let opened = |dev, ino| FileId { dev, ino, links: 1, ctime_ns: 0 };
        // The path as named.
        assert!(idx.lookup_opened("/h/.aws/credentials", opened(1, 1), ids).is_some());
        // A symlink swapped in (the tracee named ~/innocent, the guard opened the secret).
        assert_eq!(idx.lookup_opened("/h/innocent", opened(9, 42), ids).map(|e| e.path.as_str()), Some("/h/.aws/credentials"));
        // Under the twin bind the registered path opens the twin's inode: still that secret.
        assert_eq!(idx.lookup_opened("/elsewhere", opened(30, 5), ids).map(|e| e.path.as_str()), Some("/h/.aws/credentials"));
        // Anything else is not a secret.
        assert!(idx.lookup_opened("/h/innocent", opened(9, 43), ids).is_none());
    }

    #[test]
    fn a_replaced_secret_is_known_by_its_new_inode_at_once_when_the_open_looks_like_another_name() {
        let idx = SecretIndex::from_file(serde_json::from_str(r#"{"agentExe":"","secrets":[{"path":"/h/.aws/credentials","twin":"/t","level":"no-model"}]}"#).unwrap());
        // The list is built while the file is inode 42.
        let before = |p: &str| Some(if p == "/t" { FileId { dev: 8, ino: 1, links: 1, ctime_ns: 0 } } else { FileId { dev: 9, ino: if p == "/h/.aws/credentials" { 42 } else { 7 }, links: 1, ctime_ns: 0 } });
        assert!(idx.lookup_with("/h/unrelated", before).is_none());
        // An editor replaced it (inode 50); the list is fresh, so not stale.
        let replaced = |links: u64| move |p: &str| Some(if p == "/t" { FileId { dev: 8, ino: 1, links: 1, ctime_ns: 0 } } else { FileId { dev: 9, ino: if p == "/h/.aws/credentials" || p == "/h/link" || p == "/h/.AWS/credentials" { 50 } else { 7 }, links: if p == "/h/link" { links } else { 1 }, ctime_ns: 0 } });
        // A hard link to the new file: it has two links, so the list is rebuilt now.
        assert!(idx.lookup_with("/h/link", replaced(2)).is_some(), "another link: re-stat at once");
        let idx = SecretIndex::from_file(serde_json::from_str(r#"{"agentExe":"","secrets":[{"path":"/h/.aws/credentials","twin":"/t","level":"no-model"}]}"#).unwrap());
        assert!(idx.lookup_with("/h/unrelated", before).is_none());
        // A case spelling of the new file: it folds to the registered path.
        assert!(idx.lookup_with("/h/.AWS/credentials", replaced(1)).is_some(), "a folded spelling: re-stat at once");
        // An ordinary file with one link and its own name never forces a rebuild.
        let idx = SecretIndex::from_file(serde_json::from_str(r#"{"agentExe":"","secrets":[{"path":"/h/.aws/credentials","twin":"/t","level":"no-model"}]}"#).unwrap());
        assert!(idx.lookup_with("/h/unrelated", before).is_none());
        let calls = std::cell::Cell::new(0);
        let counting = |p: &str| { calls.set(calls.get() + 1); before(p) };
        assert!(idx.lookup_with("/h/other", counting).is_none());
        assert_eq!(calls.get(), 1, "only the opened file is stat'ed");
    }

    #[test]
    fn a_removed_entrys_inode_number_reused_by_a_new_file_is_not_that_entry() {
        // 2026-10-16 (a history rewrite under the guard): git's repack removed
        // a twinned pack, and the next file the agent created got its inode
        // number; matched against the identity list of before, the create
        // was refused as a write to an object-store file.
        let pack = "/r/.git/objects/pack/pack-1.pack";
        let entry = || {
            SecretIndex::from_file(
                serde_json::from_str(&format!(r#"{{"agentExe":"","secrets":[{{"path":"{pack}","twin":"/t/p","level":"no-model","kind":"object"}}]}}"#)).unwrap(),
            )
        };
        let f = |ino: u64, ctime_ns: i128| FileId { dev: 9, ino, links: 1, ctime_ns };
        let twin = FileId { dev: 30, ino: 5, links: 1, ctime_ns: 10 };
        // The list is built while the pack is inode 42, its status changed at 100.
        let present = |p: &str| match p {
            "/t/p" => Some(twin),
            p if p == pack => Some(f(42, 100)),
            _ => Some(f(7, 1)),
        };
        let idx = entry();
        assert!(idx.lookup_opened("/w/unrelated", f(7, 1), present).is_none());
        // While the pack is there, its inode under any name is still that entry
        // (fail closed), and so is its twin's.
        assert!(idx.lookup_opened("/w/other-name", f(42, 100), present).is_some());
        assert!(idx.lookup_opened("/elsewhere", twin, present).is_some());
        // The pack is removed; a new file gets inode 42 (a later status
        // change) within ID_REFRESH: not the entry.
        let removed = |p: &str| match p {
            "/t/p" => Some(twin),
            p if p == pack => None,
            _ => Some(f(42, 500)),
        };
        let calls = std::cell::Cell::new(0);
        let counting = |p: &str| {
            calls.set(calls.get() + 1);
            removed(p)
        };
        assert!(idx.lookup_opened("/w/new/f1", f(42, 500), counting).is_none(), "a new file is not the removed entry");
        assert!(calls.get() >= 2, "the hit was checked against the registered path and its twin");
        // The twin is still the entry after the real file is gone.
        assert!(idx.lookup_opened("/elsewhere", twin, removed).is_some());
        // A pack REPLACED under its name (a new inode there): the old number
        // in a new file is not the entry, the new inode is.
        let idx = entry();
        assert!(idx.lookup_opened("/w/unrelated", f(7, 1), present).is_none());
        let replaced = |p: &str| match p {
            "/t/p" => Some(twin),
            p if p == pack => Some(f(50, 600)),
            _ => Some(f(42, 500)),
        };
        assert!(idx.lookup_opened("/w/new/f1", f(42, 500), replaced).is_none());
        assert!(idx.lookup_opened("/w/alias", FileId { links: 2, ..f(50, 600) }, replaced).is_some(), "the file now at the registered path");
        // No weaker than before for a name the guard did not see move: the
        // registered file itself reached under another name after a parent
        // directory was renamed (the registered path names nothing now, the
        // inode is unchanged) keeps the hit until the next rebuild.
        let idx = entry();
        assert!(idx.lookup_opened("/w/unrelated", f(7, 1), present).is_none());
        let moved = |p: &str| match p {
            "/t/p" => Some(twin),
            p if p == pack => None,
            _ => Some(f(42, 100)),
        };
        let calls = std::cell::Cell::new(0);
        let counting = |p: &str| {
            calls.set(calls.get() + 1);
            moved(p)
        };
        assert!(idx.lookup_opened("/r/.git/objects/pack2/pack-1.pack", f(42, 100), counting).is_some(), "the same inode, unchanged");
        assert_eq!(calls.get(), 0, "an unchanged inode stands without a stat");
    }

    #[test]
    fn a_pinned_file_moved_with_its_directory_is_still_that_secret_after_any_rebuild() {
        // 2026-10-16 (`inode_pins`): `mv ~/.aws ~/.aws2` renames no leaf;
        // before, the next identity rebuild found nothing at the registered
        // path and the moved file read raw (guard-only posture).
        let d = std::env::temp_dir().join(format!("mandu-pin-idx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("aws")).unwrap();
        let cred = d.join("aws").join("credentials");
        std::fs::write(&cred, "k").unwrap();
        let reg = cred.to_str().unwrap().to_string();
        let object = d.join("pack-1.pack");
        std::fs::write(&object, "p").unwrap();
        let file = SecretPolicyFile {
            secrets: vec![
                serde_json::from_value(serde_json::json!({"path": reg, "twin": "/nonexistent-twin", "level": "no-model"})).unwrap(),
                serde_json::from_value(serde_json::json!({"path": object.to_str().unwrap(), "twin": "/nonexistent-twin2", "level": "no-model", "kind": "object"})).unwrap(),
            ],
            ..Default::default()
        };
        let idx = SecretIndex::from_file(file);
        assert_eq!(idx.enable_pins(8), (1, 0), "the protected file is held; the object entry is not pinned");
        std::fs::rename(d.join("aws"), d.join("aws2")).unwrap();
        let moved = d.join("aws2").join("credentials");
        for round in 0..3 {
            // Force the rebuild that, before pinning, dropped the identity.
            {
                let mut c = idx.by_id.lock().unwrap();
                idx.id_list(&mut c, &file_id, true);
            }
            assert_eq!(idx.lookup(moved.to_str().unwrap()).map(|e| e.path.as_str()), Some(reg.as_str()), "rebuild {round}: the moved file is the secret");
        }
        // Without pinning (the negative control): the rebuild drops it.
        let file = SecretPolicyFile {
            secrets: vec![serde_json::from_value(serde_json::json!({"path": d.join("aws").join("credentials").to_str().unwrap(), "twin": "/nonexistent-twin", "level": "no-model"})).unwrap()],
            ..Default::default()
        };
        std::fs::rename(d.join("aws2"), d.join("aws")).unwrap();
        let unpinned = SecretIndex::from_file(file);
        assert!(unpinned.lookup(cred.to_str().unwrap()).is_some());
        std::fs::rename(d.join("aws"), d.join("aws2")).unwrap();
        {
            let mut c = unpinned.by_id.lock().unwrap();
            unpinned.id_list(&mut c, &file_id, true);
        }
        assert!(unpinned.lookup(moved.to_str().unwrap()).is_none(), "unpinned, the rebuild forgets the moved file");
        let _ = std::fs::remove_dir_all(&d);
    }

    fn one_file_index(path: &std::path::Path, kind: Option<&str>) -> SecretIndex {
        let mut e = serde_json::json!({"path": path.to_str().unwrap(), "twin": "/nonexistent-twin", "level": "no-model"});
        if let Some(k) = kind {
            e["kind"] = serde_json::json!(k);
        }
        SecretIndex::from_file(SecretPolicyFile { secrets: vec![serde_json::from_value(e).unwrap()], ..Default::default() })
    }

    fn force_rebuild(idx: &SecretIndex) {
        let mut c = idx.by_id.lock().unwrap();
        idx.id_list(&mut c, &file_id, true);
    }

    #[test]
    fn a_save_over_the_file_racing_a_folder_rename_is_held_at_its_new_path() {
        // 2026-10-16: the person's editor saves over the registered path
        // after the guard's checks and before the folder moves; the new inode
        // is held anyway, at the place the rename put it.
        let d = std::env::temp_dir().join(format!("mandu-pin-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("aws")).unwrap();
        let cred = d.join("aws").join("credentials");
        std::fs::write(&cred, "k1").unwrap();
        let save_then_move = || {
            let tmpf = d.join("aws").join(".swp");
            std::fs::write(&tmpf, "k2").unwrap();
            std::fs::rename(&tmpf, &cred).unwrap();
            match std::fs::rename(d.join("aws"), d.join("aws2")) {
                Ok(()) => 0,
                Err(e) => e.raw_os_error().unwrap_or(libc::EIO),
            }
        };
        let moves = vec![(d.join("aws").to_str().unwrap().to_string(), d.join("aws2").to_str().unwrap().to_string())];
        let moved = d.join("aws2").join("credentials");
        // Held: the saved file is that secret at its new path, after any rebuild.
        let idx = one_file_index(&cred, None);
        assert_eq!(idx.enable_pins(8), (1, 0));
        assert_eq!(idx.rename_dirs_holding_pins(&moves, save_then_move, || 0), 0);
        force_rebuild(&idx);
        assert!(idx.lookup(moved.to_str().unwrap()).is_some(), "the saved file, moved, is held");
        // The negative control: the same race with a plain rename (no hold):
        // the saved file was never held, and the rebuild forgets it.
        std::fs::rename(d.join("aws2"), d.join("aws")).unwrap();
        let idx = one_file_index(&cred, None);
        idx.enable_pins(8);
        assert_eq!(save_then_move(), 0);
        force_rebuild(&idx);
        assert!(idx.lookup(moved.to_str().unwrap()).is_none(), "without the hold the saved, moved file is lost");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_moved_file_that_cannot_be_held_undoes_the_folder_rename() {
        let d = std::env::temp_dir().join(format!("mandu-pin-undo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("aws")).unwrap();
        let cred = d.join("aws").join("credentials");
        std::fs::write(&cred, "k1").unwrap();
        let idx = one_file_index(&cred, None);
        // Budget 1, held: a save over it during the rename needs a second pin.
        assert_eq!(idx.enable_pins(1), (1, 0));
        let moves = vec![(d.join("aws").to_str().unwrap().to_string(), d.join("aws2").to_str().unwrap().to_string())];
        let rc = idx.rename_dirs_holding_pins(
            &moves,
            || {
                let tmpf = d.join("aws").join(".swp");
                std::fs::write(&tmpf, "k2").unwrap();
                std::fs::rename(&tmpf, &cred).unwrap();
                std::fs::rename(d.join("aws"), d.join("aws2")).map(|()| 0).unwrap_or(libc::EIO)
            },
            || std::fs::rename(d.join("aws2"), d.join("aws")).map(|()| 0).unwrap_or(libc::EIO),
        );
        assert_eq!(rc, libc::EACCES);
        assert!(cred.exists() && !d.join("aws2").exists(), "undone: the folder is back");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_folder_rename_that_cannot_be_undone_leaves_its_files_known_by_their_new_paths() {
        let d = std::env::temp_dir().join(format!("mandu-pin-alias-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("aws")).unwrap();
        let cred = d.join("aws").join("credentials");
        std::fs::write(&cred, "k1").unwrap();
        let idx = one_file_index(&cred, None);
        assert_eq!(idx.enable_pins(1), (1, 0));
        let moves = vec![(d.join("aws").to_str().unwrap().to_string(), d.join("aws2").to_str().unwrap().to_string())];
        let rc = idx.rename_dirs_holding_pins(
            &moves,
            || {
                // A save over it: a second pin is needed and the budget is 1.
                let tmpf = d.join("aws").join(".swp");
                std::fs::write(&tmpf, "k2").unwrap();
                std::fs::rename(&tmpf, &cred).unwrap();
                std::fs::rename(d.join("aws"), d.join("aws2")).map(|()| 0).unwrap_or(libc::EIO)
            },
            // The agent made a folder at the old name meanwhile: the undo fails.
            || libc::EEXIST,
        );
        assert_eq!(rc, 0, "the rename stands");
        let moved = d.join("aws2").join("credentials");
        force_rebuild(&idx);
        assert!(idx.lookup(moved.to_str().unwrap()).is_some(), "the moved file is known by its new path");
        assert!(idx.add_alias("/x", cred.to_str().unwrap()) && !idx.add_alias("/x", "/not/registered"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_registered_file_left_on_another_registered_path_is_judged_as_itself() {
        // Review of !1603: a folder exchange put registered file B's inode on
        // registered file A's path and its undo failed (forced here: the
        // exchange is simply left standing). A's path must not lend A's
        // entry (A's readers, A's destinations) to B's bytes.
        let d = std::env::temp_dir().join(format!("mandu-pin-cross-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("app")).unwrap();
        std::fs::create_dir_all(d.join("lib")).unwrap();
        let a = d.join("app").join(".env");
        let b = d.join("lib").join(".env");
        std::fs::write(&a, "A=1").unwrap();
        std::fs::write(&b, "B=2").unwrap();
        let file = SecretPolicyFile {
            secrets: vec![
                serde_json::from_value(serde_json::json!({"path": a.to_str().unwrap(), "twin": "/nonexistent-a", "level": "no-model"})).unwrap(),
                serde_json::from_value(serde_json::json!({"path": b.to_str().unwrap(), "twin": "/nonexistent-b", "level": "any-model"})).unwrap(),
            ],
            ..Default::default()
        };
        let idx = SecretIndex::from_file(file);
        assert_eq!(idx.enable_pins(8), (2, 0));
        let (ap, bp) = (a.to_str().unwrap(), b.to_str().unwrap());
        assert_eq!(idx.lookup(ap).map(|e| e.path.as_str()), Some(ap), "before: each path is its own file");
        // The exchange stands: B's bytes at A's path, A's at B's.
        std::fs::rename(d.join("app"), d.join("tmp")).unwrap();
        std::fs::rename(d.join("lib"), d.join("app")).unwrap();
        std::fs::rename(d.join("tmp"), d.join("lib")).unwrap();
        let k = |p: &std::path::Path| {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata(p).unwrap();
            FileId { dev: m.dev(), ino: m.ino(), links: 1, ctime_ns: 0 }
        };
        assert_eq!(idx.lookup(ap).map(|e| e.path.as_str()), Some(bp), "A's path now holds B's bytes: B's entry");
        assert_eq!(idx.lookup(bp).map(|e| e.path.as_str()), Some(ap));
        assert_eq!(idx.lookup_opened(ap, k(&a), file_id).map(|e| e.path.as_str()), Some(bp));
        assert_eq!(idx.lookup_opened(ap, k(&a), file_id).map(|e| e.level.as_str()), Some("any-model"), "B's own level, B's own rules");
        // Without pins (the control): the path alone decides, A's entry for B's bytes.
        let file = SecretPolicyFile {
            secrets: vec![
                serde_json::from_value(serde_json::json!({"path": ap, "twin": "/nonexistent-a", "level": "no-model"})).unwrap(),
                serde_json::from_value(serde_json::json!({"path": bp, "twin": "/nonexistent-b", "level": "any-model"})).unwrap(),
            ],
            ..Default::default()
        };
        assert_eq!(SecretIndex::from_file(file).lookup(ap).map(|e| e.path.as_str()), Some(ap));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn one_file_under_two_registered_names_is_judged_by_the_stricter_whichever_name_is_opened() {
        let d = std::env::temp_dir().join(format!("mandu-pin-twonames-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let a = d.join("a.env");
        let b = d.join("b.env");
        std::fs::write(&a, "K=1").unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        let (ap, bp) = (a.to_str().unwrap(), b.to_str().unwrap());
        for (la, lb) in [("no-model", "any-model"), ("any-model", "no-model")] {
            let file = SecretPolicyFile {
                secrets: vec![
                    serde_json::from_value(serde_json::json!({"path": ap, "twin": "/nonexistent-a", "level": la})).unwrap(),
                    serde_json::from_value(serde_json::json!({"path": bp, "twin": "/nonexistent-b", "level": lb})).unwrap(),
                ],
                ..Default::default()
            };
            let idx = SecretIndex::from_file(file);
            assert_eq!(idx.enable_pins(8), (1, 0), "one inode, one pin");
            for p in [ap, bp] {
                assert_eq!(idx.lookup(p).map(|e| e.level.as_str()), Some("no-model"), "{p} with {la}/{lb}: the stricter name decides");
            }
        }
        // The pure rule: level first, then the protected-file kind, then the smaller path.
        let e = |p: &str, l: &str, k: Option<&str>| SecretEntry { path: p.into(), twin: String::new(), level: l.into(), kind: k.map(String::from) };
        let (x, y) = (e("/b", "no-model", None), e("/a", "any-model", None));
        assert_eq!(stricter_entry(&x, &y).path, "/b");
        let (x, y) = (e("/b", "no-model", None), e("/a", "no-model", None));
        assert_eq!(stricter_entry(&x, &y).path, "/a", "a tie: the smaller path, either order");
        assert_eq!(stricter_entry(&y, &x).path, "/a");
        let (x, y) = (e("/a", "no-model", Some("derived")), e("/b", "no-model", Some("file")));
        assert_eq!(stricter_entry(&x, &y).path, "/b", "the protected file's own entry over another kind");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_moved_file_left_unlabelled_is_written_to_the_notice() {
        let d = std::env::temp_dir().join(format!("mandu-moved-notice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let notice = d.join("moved-unlabelled");
        let file = SecretPolicyFile { moved_notice: Some(notice.to_str().unwrap().to_string()), ..Default::default() };
        let idx = SecretIndex::from_file(file);
        idx.note_moved_unlabelled("/h/.aws/credentials", "/h/.aws2/credentials");
        idx.note_moved_unlabelled("/w/a\tb", "/w/x\ny");
        assert_eq!(std::fs::read_to_string(&notice).unwrap(), "/h/.aws/credentials\t/h/.aws2/credentials\n/w/a b\t/w/x y\n");
        // No notice file: nothing written, nothing fails.
        SecretIndex::from_file(SecretPolicyFile::default()).note_moved_unlabelled("/a", "/b");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_the_held_registered_file_itself_goes_home_without_a_label() {
        let d = std::env::temp_dir().join(format!("mandu-pin-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("aws")).unwrap();
        std::fs::create_dir_all(d.join("other")).unwrap();
        let cred = d.join("aws").join("credentials");
        std::fs::write(&cred, "k1").unwrap();
        let planted = d.join("other").join("credentials");
        std::fs::write(&planted, "a copy of something else").unwrap();
        let idx = one_file_index(&cred, None);
        idx.enable_pins(8);
        let reg = cred.to_str().unwrap();
        assert!(idx.is_held_at_home(reg, reg), "the registered file, where it is");
        assert!(!idx.is_held_at_home(planted.to_str().unwrap(), reg), "another file bound for the registered path: not home (its follow is refused)");
        assert!(!idx.is_held_at_home(reg, planted.to_str().unwrap()), "a destination that is no registered path");
        std::fs::rename(d.join("aws"), d.join("away")).unwrap();
        assert!(idx.is_held_at_home(d.join("away").join("credentials").to_str().unwrap(), reg), "moved away, going back: home");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_unknown_kind_is_held_and_an_object_entry_is_not() {
        let d = std::env::temp_dir().join(format!("mandu-pin-kind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("f");
        std::fs::write(&f, "k").unwrap();
        assert_eq!(one_file_index(&f, Some("a-kind-from-a-newer-launcher")).enable_pins(8), (1, 0));
        assert_eq!(one_file_index(&f, Some("object")).enable_pins(8), (0, 0));
        assert_eq!(one_file_index(&f, Some("deny")).enable_pins(8), (0, 0));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_unheld_rename_rule_fails_closed_when_an_identity_cannot_be_read() {
        let ids = |p: &str| -> Option<(u64, u64)> {
            match p {
                "/" => Some((1, 1)),
                "/h" => Some((1, 2)),
                "/h/.aws" => Some((1, 3)),
                "/h/.aws/credentials" => Some((1, 4)),
                "/h/other" => Some((1, 5)),
                _ => None,
            }
        };
        let list = vec!["/h/.aws/credentials".to_string()];
        assert_eq!(protected_hit_by_ids_strict(&list, Some((1, 3)), &[(1, 2), (1, 1)], ids), Ok(Some("/h/.aws/credentials")), "its folder");
        assert_eq!(protected_hit_by_ids_strict(&list, Some((1, 2)), &[(1, 1)], ids), Ok(Some("/h/.aws/credentials")), "a folder above");
        assert_eq!(protected_hit_by_ids_strict(&list, Some((1, 5)), &[(1, 2), (1, 1)], ids), Ok(None), "a sibling");
        // The listed file, or a folder above it, cannot be identified: refused.
        let gone = |p: &str| if p == "/h/.aws/credentials" { None } else { ids(p) };
        assert_eq!(protected_hit_by_ids_strict(&list, Some((1, 5)), &[(1, 2)], gone), Err("/h/.aws/credentials"));
        let no_parent = |p: &str| if p == "/h" { None } else { ids(p) };
        assert_eq!(protected_hit_by_ids_strict(&list, Some((1, 5)), &[(1, 2)], no_parent), Err("/h/.aws/credentials"));
        // The lenient form skips what it cannot read (the `protect:` rule).
        assert_eq!(protected_hit_by_ids(&list, Some((1, 5)), &[(1, 2)], gone), None);
        // An empty list never refuses.
        assert_eq!(protected_hit_by_ids_strict(&[], Some((1, 5)), &[], |_| None), Ok(None));
    }

    #[test]
    fn past_the_pin_budget_the_file_is_listed_for_the_rename_refusal() {
        let d = std::env::temp_dir().join(format!("mandu-pin-budget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let cred = d.join(".env");
        std::fs::write(&cred, "k").unwrap();
        let file = SecretPolicyFile {
            secrets: vec![serde_json::from_value(serde_json::json!({"path": cred.to_str().unwrap(), "twin": "/nonexistent-twin", "level": "no-model"})).unwrap()],
            ..Default::default()
        };
        let idx = SecretIndex::from_file(file);
        assert_eq!(idx.enable_pins(0), (0, 1));
        assert_eq!(idx.unpinned(), vec![cred.to_str().unwrap().to_string()]);
        // The rename rule over that list: the file's directory and every one
        // above it are its ancestors; a sibling directory is not.
        let ids = |p: &str| -> Option<(u64, u64)> {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))
        };
        let list = idx.unpinned();
        assert!(protected_hit_by_ids(&list, ids(d.to_str().unwrap()), &[], ids).is_some(), "the file's own directory");
        std::fs::create_dir_all(d.join("other")).unwrap();
        assert!(protected_hit_by_ids(&list, ids(d.join("other").to_str().unwrap()), &[], ids).is_none(), "a sibling directory");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_stale_hit_stands_on_an_unchanged_inode_or_a_registered_name() {
        assert!(stale_hit_stands(100, 100, || panic!("not asked")));
        assert!(stale_hit_stands(100, 500, || true));
        assert!(!stale_hit_stands(100, 500, || false));
    }

    #[test]
    fn a_hard_link_or_other_case_matches_on_a_real_file() {
        let dir = std::env::temp_dir().join(format!("mandu-fold-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("credentials");
        std::fs::write(&real, "k").unwrap();
        // A hard link under another case: the same inode, another spelling
        // (what a case-folding filesystem hands the opener too).
        let other = dir.join("CREDENTIALS");
        std::fs::hard_link(&real, &other).unwrap();
        let file = SecretPolicyFile {
            secrets: vec![serde_json::from_value(serde_json::json!({"path": real.to_str().unwrap(), "twin": "/t", "level": "no-model"})).unwrap()],
            ..Default::default()
        };
        let idx = SecretIndex::from_file(file);
        assert!(idx.lookup(other.to_str().unwrap()).is_some());
        let elsewhere = dir.join("innocent-name");
        std::fs::hard_link(&real, &elsewhere).unwrap();
        assert!(idx.lookup(elsewhere.to_str().unwrap()).is_some(), "a hard link under any name");
        std::fs::remove_file(&other).unwrap();
        std::fs::write(&other, "not the secret").unwrap();
        assert!(idx.lookup(other.to_str().unwrap()).is_none(), "a distinct file under the other case");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_registered_file_with_another_link_is_said_linked() {
        // P0 4c: the stat trap resolves an lstat of another leaf only while
        // a registered file has a hard link besides its own name.
        let file = |paths: &[&str]| SecretPolicyFile {
            secrets: paths.iter().map(|p| serde_json::from_value(serde_json::json!({"path": p, "twin": format!("{p}.twin"), "level": "no-model"})).unwrap()).collect(),
            ..Default::default()
        };
        let links = std::cell::Cell::new(1u64);
        let asked = std::cell::Cell::new(0u32);
        let id = |p: &str| {
            asked.set(asked.get() + 1);
            // The twin is a file of its own, one link (never counted).
            let twin = p.ends_with(".twin");
            Some(FileId { dev: 7, ino: if twin { 99 } else { 42 }, links: if twin { 5 } else { links.get() }, ctime_ns: 0 })
        };
        let idx = SecretIndex::from_file(file(&["/home/u/.env"]));
        assert!(!idx.any_linked(id), "one link, the registered name's own");
        let after_first = asked.get();
        links.set(2);
        assert!(!idx.any_linked(id), "the list is reused within ID_REFRESH: no re-stat per stat call");
        assert_eq!(asked.get(), after_first);
        *idx.by_id.lock().unwrap() = None;
        assert!(idx.any_linked(id), "a hard link made before the launch (or outside the agent's tree)");
        assert!(!SecretIndex::from_file(file(&[])).any_linked(id), "no registered file: nothing is linked");

        // On a real file: a hard link of another name.
        let dir = std::env::temp_dir().join(format!("mandu-linked-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join(".env");
        std::fs::write(&real, "TOKEN=x").unwrap();
        let idx = SecretIndex::from_file(file(&[real.to_str().unwrap()]));
        assert!(!idx.any_linked(file_id));
        std::fs::hard_link(&real, dir.join("innocent")).unwrap();
        *idx.by_id.lock().unwrap() = None;
        assert!(idx.any_linked(file_id));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn object_store_entries_answer_without_the_arbiter() {
        let e = |kind: Option<&str>| SecretEntry { path: "/r/.git/objects/pack/pack-1.pack".into(), twin: "/c/p.pack".into(), level: "no-model".into(), kind: kind.map(String::from) };
        assert_eq!(e(None).answer(false), EntryAnswer::Arbiter, "a protected file asks the arbiter");
        assert_eq!(e(Some("file")).answer(true), EntryAnswer::Arbiter);
        assert_eq!(e(Some("object")).answer(false), EntryAnswer::Twin, "a pack read gets the sanitized twin");
        assert_eq!(e(Some("object")).answer(true), EntryAnswer::Deny, "a pack is never opened for writing through its twin");
        assert_eq!(e(Some("deny")).answer(false), EntryAnswer::Deny);
        assert_eq!(e(Some("from-a-newer-launcher")).answer(false), EntryAnswer::Deny, "an unknown kind fails closed");
    }

    #[test]
    fn policy_file_carries_kinds_and_deny_prefixes() {
        let text = r#"{"agentExe":"","secrets":[
            {"path":"/r/.git/objects/pack/pack-1.pack","twin":"/c/p.pack","level":"no-model","kind":"object"},
            {"path":"/r/.env","twin":"/t/env","level":"no-model"}],
            "denyPrefixes":["/nonexistent-mandu-test/.mandu/workspaces"]}"#;
        let file: SecretPolicyFile = serde_json::from_str(text).unwrap();
        assert_eq!(file.secrets[0].kind.as_deref(), Some("object"));
        assert_eq!(file.secrets[1].kind, None, "an older launcher's entry is a protected file");
        let idx = SecretIndex::from_file(file);
        assert_eq!(idx.denied_prefix("/nonexistent-mandu-test/.mandu/workspaces/ws-1/repo.git/HEAD"), Some("/nonexistent-mandu-test/.mandu/workspaces"));
        assert_eq!(idx.denied_prefix("/nonexistent-mandu-test/.mandu/workspaces"), Some("/nonexistent-mandu-test/.mandu/workspaces"));
        assert_eq!(idx.denied_prefix("/nonexistent-mandu-test/.mandu/workspaces2/x"), None, "a sibling with a shared prefix");
        assert_eq!(idx.denied_prefix("/nonexistent-mandu-test/.mandu/mandu.db"), None);
        let only_prefix = SecretIndex::from_file(SecretPolicyFile { deny_prefixes: vec!["/x".into()], ..Default::default() });
        assert!(!only_prefix.is_empty(), "a policy with only a hidden directory still arms the open trap");
    }

    #[test]
    fn git_locks_are_read_from_the_policy_file() {
        // Plan 14 §11.1 R4: `gitLocks` as the launcher writes it.
        let id = format!("sha1:{}", "3b".repeat(20));
        let text = format!(r#"{{"agentExe":"","secrets":[],"gitLocks":{{"ids":["{id}","sha1:NOPE"],"noticeFile":"/run/scope/git-lock-refusals"}}}}"#);
        let file: SecretPolicyFile = serde_json::from_str(&text).unwrap();
        assert_eq!(file.git_locks.as_ref().unwrap().notice_file.as_deref(), Some("/run/scope/git-lock-refusals"));
        let idx = SecretIndex::from_file(file);
        let gl = idx.git_locks().expect("a lock is in force");
        assert_eq!(gl.set().len(), 1, "the malformed id is ignored, the good one kept");
        assert!(!idx.is_empty(), "a policy with only locks still arms the open trap");
        let none = SecretIndex::from_file(serde_json::from_str::<SecretPolicyFile>(r#"{"gitLocks":{"ids":[]}}"#).unwrap());
        assert!(none.git_locks().is_none(), "no id, no backstop");
        let absent = SecretIndex::from_file(serde_json::from_str::<SecretPolicyFile>(r#"{"secrets":[]}"#).unwrap());
        assert!(absent.git_locks().is_none(), "an older launcher's file: no backstop");
    }

    #[test]
    fn the_home_is_one_deny_prefix_with_carve_outs() {
        // on-disk-layout.md §4: the whole home hidden; the integrity modes'
        // AgentView (and, in `full`, its repo.git) below it stays open.
        let home = vec!["/h/.mandu".to_string(), "/run/scope/events".to_string()];
        let except = vec!["/h/.mandu/state/workspaces/ws-1/agentview".to_string()];
        assert_eq!(hidden_by(&home, &except, "/h/.mandu"), Some("/h/.mandu"), "the home itself");
        assert_eq!(hidden_by(&home, &except, "/h/.mandu/mandu.db"), Some("/h/.mandu"), "a stray file at the top");
        assert_eq!(hidden_by(&home, &except, "/h/.mandu/state/new-file"), Some("/h/.mandu"), "a new file under state/");
        assert_eq!(hidden_by(&home, &except, "/h/.mandu/cache/object-twins/k/p.pack"), Some("/h/.mandu"), "the twin cache by its own path");
        assert_eq!(hidden_by(&home, &except, "/h/.mandu/state/workspaces/ws-1"), Some("/h/.mandu"), "the carve-out's parent");
        assert_eq!(hidden_by(&home, &except, "/h/.mandu/state/workspaces/ws-1/repo.git/HEAD"), Some("/h/.mandu"), "a sibling of the carve-out");
        assert_eq!(hidden_by(&home, &except, "/h/.mandu/state/workspaces/ws-1/agentviewX"), Some("/h/.mandu"), "whole components");
        assert_eq!(hidden_by(&home, &except, "/h/.mandu/state/workspaces/ws-1/agentview"), None, "the carve-out");
        assert_eq!(hidden_by(&home, &except, "/h/.mandu/state/workspaces/ws-1/agentview/src/a.rs"), None, "below it");
        assert_eq!(hidden_by(&home, &except, "/run/scope/events/s.ndjson"), Some("/run/scope/events"));
        assert_eq!(hidden_by(&home, &except, "/h/notes"), None);
        // A carve-out spares only the prefixes it lies in: a prefix inside
        // it (or one it is not under) still hides.
        let nested = vec!["/h/.mandu".to_string(), "/h/.mandu/state/workspaces/ws-1/agentview/.secret".to_string()];
        assert_eq!(hidden_by(&nested, &except, "/h/.mandu/state/workspaces/ws-1/agentview/.secret/k"), Some("/h/.mandu/state/workspaces/ws-1/agentview/.secret"));
        let outside = vec!["/elsewhere".to_string()];
        assert_eq!(hidden_by(&outside, &["/elsewhere/".to_string()], "/elsewhere/x"), Some("/elsewhere"), "a carve-out must lie strictly below the prefix: one AT it spares nothing");
        let file: SecretPolicyFile = serde_json::from_str(r#"{"denyPrefixes":["/nonexistent-mandu-test/.mandu"],"denyExcept":["/nonexistent-mandu-test/.mandu/state/workspaces/w/agentview"]}"#).unwrap();
        let idx = SecretIndex::from_file(file);
        assert_eq!(idx.denied_prefix("/nonexistent-mandu-test/.mandu/state/workspaces/w/agentview/f"), None);
        assert_eq!(idx.denied_prefix("/nonexistent-mandu-test/.mandu/state/mandu.db"), Some("/nonexistent-mandu-test/.mandu"));
    }

    #[test]
    fn a_write_protect_carve_out_spares_only_its_own_entry() {
        let mut home = wp("/h/.mandu", "deny");
        home.except = vec!["/h/.mandu/state/workspaces/w/agentview".into()];
        let e = vec![home, wp("/h/.mandu/state/workspaces/w/agentview/.git/hooks", "ask")];
        let none = |_: &str| None;
        let hit = |t: &str| write_protected_hit(&e, t, none, none).map(|w| w.path.clone());
        assert_eq!(hit("/h/.mandu/new-file"), Some("/h/.mandu".into()), "a new file at the top of the home");
        assert_eq!(hit("/h/.mandu/state/x"), Some("/h/.mandu".into()), "a new file under state/");
        assert_eq!(hit("/h/.mandu/state/workspaces/w/repo.git/HEAD"), Some("/h/.mandu".into()));
        assert_eq!(hit("/h/.mandu/state/workspaces/w/agentview/src/a.rs"), None, "the AgentView is the agent's to write");
        assert_eq!(hit("/h/.mandu/state/workspaces/w/agentview/.git/hooks/pre-commit"), Some("/h/.mandu/state/workspaces/w/agentview/.git/hooks".into()), "another entry inside the carve-out still applies");
        // By identity: a target reached through another spelling of the
        // home is caught, one reached through another spelling of the
        // carve-out is spared.
        let ids = |p: &str| match p {
            "/h/.mandu" | "/mnt/home-bind" => Some((1, 1)),
            "/h/.mandu/state/workspaces/w/agentview" | "/mnt/av-bind" => Some((1, 2)),
            _ => None,
        };
        let pinned = |seen: &str, anc: &[(u64, u64)]| write_protected_hit_pinned(&e, seen, None, anc, ids).map(|w| w.path.clone());
        assert_eq!(pinned("/mnt/home-bind/evil", &[(1, 1)]), Some("/h/.mandu".into()));
        assert_eq!(pinned("/mnt/av-bind/ok", &[(1, 2), (1, 1)]), None);
        assert_eq!(write_protected_hit(&e, "/mnt/av-bind/ok", ids, none).map(|w| w.path.clone()), None);
        assert_eq!(write_protected_hit(&e, "/mnt/home-bind/evil", ids, none).map(|w| w.path.clone()), Some("/h/.mandu".into()));
        let mut void = wp("/h/.mandu", "deny");
        void.except = vec!["/h/.mandu/".into(), "/elsewhere".into()];
        let v = vec![void];
        assert!(write_protected_hit(&v, "/h/.mandu/x", none, none).is_some(), "a carve-out AT the entry (or outside it) spares nothing");
        let f: SecretPolicyFile = serde_json::from_str(r#"{"writeProtect":[{"path":"/h/.mandu","answer":"deny","label":"x","except":["/h/.mandu/a"]}]}"#).unwrap();
        assert_eq!(f.write_protect[0].except, vec!["/h/.mandu/a".to_string()]);
    }

    #[test]
    fn deny_prefix_matches_whole_components() {
        let p = vec!["/h/.mandu/workspaces/".to_string(), String::new()];
        assert_eq!(under_deny_prefix(&p, "/h/.mandu/workspaces/a/b"), Some("/h/.mandu/workspaces"));
        assert_eq!(under_deny_prefix(&p, "/h/.mandu/workspacesX"), None);
        assert_eq!(under_deny_prefix(&p, "/h/.mandu"), None, "an ancestor is not hidden");
        assert_eq!(under_deny_prefix(&[], "/anything"), None);
    }

    #[test]
    fn clean_box_exec_is_the_applier_with_clean() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(is_clean_box_exec(&s(&["/usr/lib/mandu/mandu-landlock-apply", "--clean", "--read", "/usr", "--", "cat", ".env"])));
        assert!(is_clean_box_exec(&s(&["mandu-landlock-apply", "--clean"])));
        // the ordinary (non-clean) applier is not the clean box
        assert!(!is_clean_box_exec(&s(&["/usr/lib/mandu/mandu-landlock-apply", "--rw", "/ws", "--", "cat", ".env"])));
        // `--clean` as the command's own argument is not the applier's
        assert!(!is_clean_box_exec(&s(&["/usr/bin/make", "--clean"])));
        assert!(!is_clean_box_exec(&s(&["cat", ".env"])));
        assert!(!is_clean_box_exec(&[]));
    }

    /// The open family per arch, by number: the guard's filter traps exactly
    /// these, and a name missing on one arch must not drop another's (the
    /// linux-arm64 bundle, packaging.md §11.3). x86_64: open=2, openat=257,
    /// openat2=437; aarch64 (generic ABI): openat=56, openat2=437, no `open`.
    #[test]
    fn open_nrs_are_the_arch_open_family() {
        let mut nrs = open_nrs();
        nrs.sort();
        #[cfg(target_arch = "x86_64")]
        assert_eq!(nrs, vec![2, 257, 437]);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(nrs, vec![56, 437]);
        for nr in open_nrs() {
            assert!(is_open_nr(nr));
        }
        assert!(!is_open_nr(libc::SYS_connect as i64));
    }

    #[test]
    fn open_args_decode_per_syscall() {
        let mut a = [0u64; 6];
        a[0] = 7; a[1] = 0xdead; a[2] = libc::O_RDONLY as u64;
        assert_eq!(decode_open_args(libc::SYS_openat as i64, &a), Some((7, 0xdead, libc::O_RDONLY)));
        #[cfg(target_arch = "x86_64")]
        {
            a[0] = 0xbeef; a[1] = libc::O_WRONLY as u64;
            assert_eq!(decode_open_args(libc::SYS_open as i64, &a), Some((libc::AT_FDCWD, 0xbeef, libc::O_WRONLY)));
        }
        assert!(is_exec_nr(libc::SYS_execve as i64) && is_exec_nr(libc::SYS_execveat as i64) && !is_exec_nr(libc::SYS_openat as i64));
        let mut e = [0u64; 6];
        e[1] = 0x1000; e[2] = 0x2000;
        assert_eq!(exec_argv_ptr(libc::SYS_execve as i64, &e), Some(0x1000));
        assert_eq!(exec_argv_ptr(libc::SYS_execveat as i64, &e), Some(0x2000));
        assert_eq!(exec_argv_ptr(libc::SYS_openat as i64, &e), None);
        // the parent of this test process is readable
        assert!(parent_pid_of(std::process::id() as i32).unwrap() > 0);
        assert_eq!(decode_open_args(libc::SYS_openat2 as i64, &a), None);
        assert!(is_open_nr(libc::SYS_openat2 as i64));
        assert!(!is_open_nr(libc::SYS_connect as i64));
    }

    #[test]
    fn introspection_targets_unix_paths_and_unix_bindings() {
        assert_eq!(proc_introspection_target("/proc/123/mem"), Some(123));
        assert_eq!(proc_introspection_target("/proc/123/environ"), Some(123));
        assert_eq!(proc_introspection_target("/proc/123/fd/4"), Some(123));
        assert_eq!(proc_introspection_target("/proc/123/task/456/mem"), Some(123));
        // A command line holds what a shell expanded into it (plan 10 §11.13.1).
        assert_eq!(proc_introspection_target("/proc/123/cmdline"), Some(123));
        assert_eq!(proc_introspection_target("/proc/123/task/456/cmdline"), Some(123));
        // What `ps` lists a process by stays readable.
        assert_eq!(proc_introspection_target("/proc/123/status"), None);
        assert_eq!(proc_introspection_target("/proc/123/stat"), None);
        assert_eq!(proc_introspection_target("/proc/123/comm"), None);
        assert_eq!(proc_introspection_target("/proc/123/task/456/stat"), None);
        assert_eq!(proc_introspection_target("/proc/self/cmdline"), None);
        assert_eq!(proc_introspection_target("/proc/self/mem"), None, "self is resolved by the kernel; the opener's own memory is its own");
        assert_eq!(proc_introspection_target("/etc/passwd"), None);
        let mut raw = vec![0u8; 2];
        raw[0..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
        raw.extend_from_slice(b"/run/x.sock\0");
        assert_eq!(unix_path_of(&raw).as_deref(), Some("/run/x.sock"));
        let mut abs = vec![0u8; 2];
        abs[0..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
        abs.extend_from_slice(b"\0abstract\0");
        assert_eq!(unix_path_of(&abs).as_deref(), Some("@abstract"));
        let mut inet = vec![0u8; 8];
        inet[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        assert_eq!(unix_path_of(&inet), None);
        let b = vec!["unix:/var/run/postgresql".to_string(), "db.internal:5432".to_string()];
        assert!(unix_path_bound("/var/run/postgresql/.s.PGSQL.5432", &b));
        assert!(unix_path_bound("/var/run/postgresql", &b));
        assert!(!unix_path_bound("/tmp/evil.sock", &b));
        assert!(!unix_path_bound("/var/run/postgresql2", &b));
    }

    #[test]
    fn the_twin_is_served_by_the_agents_own_path_only_where_that_path_is_the_twin() {
        let twin = Some((64769, 42));
        // under the bind: the path the agent named reaches the twin's inode
        assert!(view_reaches_twin(false, Some((64769, 42)), twin));
        // no bind: the agent's path reaches the REAL file, never handed over
        assert!(!view_reaches_twin(false, Some((64769, 7)), twin));
        // the same inode number on another device is another file
        assert!(!view_reaches_twin(false, Some((2049, 42)), twin));
        // a write goes to the twin by its own path
        assert!(!view_reaches_twin(true, Some((64769, 42)), twin));
        // unresolvable on either side: the twin by its own path
        assert!(!view_reaches_twin(false, None, twin));
        assert!(!view_reaches_twin(false, Some((64769, 42)), None));
        assert!(!view_reaches_twin(false, None, None));
    }

    #[test]
    fn taint_sources_name_the_holders_that_read_a_secret_themselves() {
        let set = TaintedSet::default();
        set.insert("H-1");
        set.insert("K-2");
        // A child of H, and its child.
        set.inherit("C-3", &["H-1".to_string(), "init-0".to_string()]);
        set.inherit("G-4", &["C-3".to_string(), "H-1".to_string()]);
        // A pipe reader of K (plan 13 D2), and its child.
        set.insert_flow("R-5", &["K-2".to_string()]);
        set.inherit("RC-6", &["R-5".to_string()]);
        // Inherited from H, then read K's file itself.
        set.inherit("B-7", &["H-1".to_string()]);
        set.insert("B-7");
        assert_eq!(set.taint_sources("H-1"), vec!["H-1"]);
        assert_eq!(set.taint_sources("C-3"), vec!["H-1"]);
        assert_eq!(set.taint_sources("G-4"), vec!["H-1"]);
        assert_eq!(set.taint_sources("R-5"), vec!["K-2"]);
        assert_eq!(set.taint_sources("RC-6"), vec!["K-2"]);
        assert_eq!(set.taint_sources("B-7"), vec!["B-7", "H-1"], "a read after the inheritance is its own");
        assert!(set.taint_sources("nobody-9").is_empty());
    }

    #[test]
    fn introspection_of_a_holder_needs_all_of_its_taint() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // Its own process, and a target that holds nothing: always.
        assert!(introspection_allowed(10, &[], 10, true, &s(&["H-1"])));
        assert!(introspection_allowed(10, &[], 11, false, &[]));
        // An untainted opener of a holder: refused (the original clause).
        assert!(!introspection_allowed(10, &[], 11, true, &s(&["H-1"])));
        // A holder of ANOTHER secret: refused (2026-10-02; it was exempt).
        assert!(!introspection_allowed(10, &s(&["K-2"]), 11, true, &s(&["H-1"])));
        assert!(!introspection_allowed(10, &s(&["H-1"]), 11, true, &s(&["H-1", "K-2"])), "a target that read more than the opener carries");
        // The opener already carries all of it (a holder's strace of its child).
        assert!(introspection_allowed(10, &s(&["H-1"]), 11, true, &s(&["H-1"])));
        assert!(introspection_allowed(10, &s(&["H-1", "K-2"]), 11, true, &s(&["K-2"])));
        // A holder the set names no source for: refused, fail-closed.
        assert!(!introspection_allowed(10, &s(&["H-1"]), 11, true, &[]));
    }

    #[test]
    fn a_descriptor_holds_its_file_for_writing_by_its_access_mode_alone() {
        // What makes the kernel refuse an exec (ETXTBSY) while the guard
        // still holds the description it handed over.
        assert!(holds_for_writing(libc::O_WRONLY));
        assert!(holds_for_writing(libc::O_RDWR));
        assert!(holds_for_writing(libc::O_WRONLY | libc::O_APPEND | libc::O_LARGEFILE));
        assert!(holds_for_writing(libc::O_RDWR | libc::O_CLOEXEC), "a memfd's");
        assert!(!holds_for_writing(libc::O_RDONLY));
        assert!(!holds_for_writing(libc::O_RDONLY | libc::O_LARGEFILE | libc::O_NOATIME));
        // A create flag is no write access: a read-only open that created
        // its file holds it for reading. An O_PATH descriptor holds nothing.
        assert!(!holds_for_writing(libc::O_RDONLY | libc::O_CREAT));
        assert!(!holds_for_writing(libc::O_PATH));
    }

    #[test]
    fn write_intent_and_the_tainted_set() {
        assert!(!is_write_intent(libc::O_RDONLY));
        assert!(is_write_intent(libc::O_WRONLY));
        assert!(is_write_intent(libc::O_RDWR));
        assert!(is_write_intent(libc::O_RDONLY | libc::O_CREAT));
        let set = TaintedSet::default();
        assert!(!set.contains("a-1"));
        set.insert("a-1");
        assert!(set.contains("a-1"));
        // this test process holds nothing; its ancestors are not in the set
        let me = std::process::id() as i32;
        let (hit, chain) = set.holds_or_inherits(me, "self-key");
        assert!(!hit);
        assert!(chain.len() <= 16);
    }

    #[test]
    fn the_taint_is_recorded_before_the_reader_is_answered() {
        let set = TaintedSet::default();
        // What `answer` sees is what a worker handling the resumed reader's
        // next syscall sees: the taint must already be there.
        let seen = set.taint_then("r-1", || set.contains("r-1"));
        assert!(seen, "the reader was answered before its taint was recorded");
        let failed: Result<(), i32> = set.taint_then("r-2", || Err(libc::ENOENT));
        assert_eq!(failed, Err(libc::ENOENT), "the answer's result comes back as is");
        assert!(set.contains("r-2"), "a failed answer keeps the taint (fail-closed)");
    }

    #[test]
    fn a_tainted_writer_is_named_by_its_full_key_while_it_lives() {
        let set = TaintedSet::default();
        let me = std::process::id() as i32;
        let wr = libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC;
        assert_eq!(set.tainted_writer(me, wr), None, "nothing tainted: no writer");
        set.insert("someone-else-1");
        assert_eq!(set.tainted_writer(me, wr), None, "an untainted writer");
        let own = mandu_arbiter::proc::proc_key_for_pid(me).expect("this test's own key");
        assert!(own.contains('-'), "a live process's key carries its start time: {own}");
        set.insert(&own);
        let (key, _) = set.tainted_writer(me, wr).expect("the tainted writer");
        assert_eq!(key, own, "the key the taint was recorded under, not a bare pid");
        assert_eq!(set.tainted_writer(me, libc::O_RDONLY), None, "a read-only open writes nothing");
    }

    #[test]
    fn supervisor_flags_never_create_or_truncate_the_real_file_at_the_open() {
        let t = libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC;
        assert_eq!(supervisor_open_flags(t, false), libc::O_WRONLY);
        assert_eq!(supervisor_open_flags(t, true), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC);
        assert_eq!(supervisor_open_flags(libc::O_RDONLY | libc::O_CLOEXEC, false), libc::O_RDONLY);
    }

    #[test]
    fn every_truncating_open_is_truncated_after_the_lookup_never_dropped() {
        // `aws configure` (open O_WRONLY|O_CREAT|O_TRUNC, write shorter):
        // the open itself does not truncate the real file
        // (`supervisor_open_flags`), and the truncation is applied to the
        // descriptor afterwards, not dropped.
        let aws = libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC;
        assert_eq!(supervisor_open_flags(aws, false) & libc::O_TRUNC, 0);
        assert!(truncate_after_lookup(aws));
        assert!(truncate_after_lookup(libc::O_RDWR | libc::O_TRUNC));
        // Linux truncates O_RDONLY|O_TRUNC too (the opener may write).
        assert!(truncate_after_lookup(libc::O_RDONLY | libc::O_TRUNC));
        // No O_TRUNC, an append: the file keeps its bytes.
        assert!(!truncate_after_lookup(libc::O_WRONLY));
        assert!(!truncate_after_lookup(libc::O_WRONLY | libc::O_APPEND));
        assert!(!truncate_after_lookup(libc::O_WRONLY | libc::O_CREAT));
        assert!(!truncate_after_lookup(libc::O_PATH | libc::O_TRUNC));
    }

    #[test]
    fn sha256_of_a_file_is_hex() {
        let dir = std::env::temp_dir().join(format!("mandu-so-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bin");
        fs::write(&p, b"hello").unwrap();
        assert_eq!(sha256_file(p.to_str().unwrap()).unwrap(), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        let _ = fs::remove_dir_all(&dir);
    }
}
