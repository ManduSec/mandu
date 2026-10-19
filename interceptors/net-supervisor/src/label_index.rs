//! label_index — the HUMAN labels at the program gate (2026-10-17,
//! docs/design/confidentiality/confidentiality.md §6 "Read by a program the
//! launch did not see").
//!
//! The guard's secret index is the launch's registered list, loaded once.
//! A file a human labelled that the launch did not register (created after
//! the launch, labelled mid-session, deeper than the discovery walk or past
//! its cap) was opened raw by every program, so a recursive or indirect read
//! (`grep -r password .`, `tar cf - .`, `os.walk`, a symlink, `curl
//! file://`) printed it to the model in clear: no name in the command said
//! which file it read, and its values were no registered secret.
//!
//! Now the guard knows WHERE the labels lie: the arbiter's label roots
//! (`labelRootsSince`), each a literal label's path or a pattern's literal
//! directory prefix (`/` when it has none) with the literal anchors of the
//! pattern's last segment (`Shape`, a prefilter: never the matcher, which
//! stays the arbiter's). A reading open of a regular file under a root is a
//! candidate; the arbiter classifies it (`labelledLevel`), cached here per
//! `(dev, ino)` with its ctime and the roots' key; a secret level gates it as
//! a derived file is gated (the twin made from `registerSecret`, which
//! registers the file so the value backstop knows its values; the real file
//! for a reader the human named). A file under no root never costs a round
//! trip, nor does one below the root inside a directory the discovery walk
//! never enters (`skipDirs`: `.git`, `node_modules`, `target`, …): the walk
//! would not have registered it, and the toolchains in a labelled project
//! keep reading their files.
//!
//! Writes follow a registered file's (2026-10-17): a write-only open of a
//! non-empty labelled file is gated too (`open_gate`), a rename onto one is
//! checked (`rename_dest_checked`), another name of a gated file is gated
//! as it (`LabelIndex::other_name_level`), and each twin the guard makes of
//! one is recorded (`TWIN_RECORDS`, `twin_record_line`) so the launcher
//! names, at the session's end, each file whose twin a program changed.
//!
//! The list is read when the guard first needs it and again at most every
//! `REFRESH_NS` (an unchanged list costs one small answer); a failed read is
//! not retried for `BACKOFF_NS` and the last list read stays in force. A
//! candidate the arbiter cannot classify is refused by the caller
//! (fail-closed); a guard that never read the list (no arbiter, or one older
//! than the guard) gates as before.
//!
//! The CATALOG too (2026-10-17, the same section): a `.env`, a key, a
//! credential file the launch did not register (created mid-session, deeper
//! than the walk, past its cap, outside HOME) was read raw the same way. The
//! catalog's prefixes come as roots of their own; its basename shapes as a
//! prefilter of literal anchors (`Catalog`, `NameAnchor`): a regular file
//! whose name meets one, with no directory below the deepest of the catalog's
//! homes holding it (below `/` outside every one) the walk would skip, is a
//! candidate, classified by the same `labelledLevel` (which applies the
//! walk's own prunes, secret-discovery.ts `gateVerdict`). A name no anchor
//! admits costs no round trip. Nothing below the guard's own directory (the
//! launch's twins, `exclude`) is a candidate.
//!
//! PURE but for the clock, which the callers pass in; the round trips are
//! guard_kernel's.
//!
//! Mandu-new (no reference origin).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// How often the list is read again, ns: a label set mid-session reaches the
/// gate within this (the arbiter registers the files already under it at
/// once, server.ts `syncLabelRegistrations`).
pub const REFRESH_NS: i128 = 1_000_000_000;

/// How long a failed read of the list is not retried, ns.
pub const BACKOFF_NS: i128 = 1_000_000_000;

/// The classification cache's bound: past it the cache starts afresh.
pub const CACHE_MAX: usize = 65_536;

/// The literal anchors of a pattern's last segment: a path segment the
/// segment matches starts with `head` and ends with `tail` (`exact`: is
/// `head`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Shape {
    pub head: String,
    pub tail: String,
    pub exact: bool,
}

impl Shape {
    /// Could the pattern's last segment match the name `seg`? A necessary
    /// condition only (the wildcards between the anchors are not checked).
    pub fn admits(&self, seg: &str) -> bool {
        if self.exact {
            return seg == self.head;
        }
        seg.len() >= self.head.len() + self.tail.len() && seg.starts_with(&self.head) && seg.ends_with(&self.tail)
    }
}

/// One root: where a label lies, and for a pattern the shape of its last
/// segment (None: any file below may be labelled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    pub path: String,
    pub shape: Option<Shape>,
}

/// The part of `path` below `root` (`""` for the root itself), or None when
/// `path` is not at or below it. Segment-aware: `/a/docs` is not below
/// `/a/doc`. Pure.
pub fn below<'a>(root: &str, path: &'a str) -> Option<&'a str> {
    if root == "/" {
        return path.strip_prefix('/');
    }
    let root = root.trim_end_matches('/');
    let rest = path.strip_prefix(root)?;
    if rest.is_empty() {
        return Some("");
    }
    rest.strip_prefix('/')
}

/// Could a label at `root` cover `path`, and is it a file the guard gates
/// there? Under the root, in no directory below it named in `skip` (the
/// discovery walk's SKIP_DIRS), and for a pattern some segment below it
/// admits the last segment's shape (a recursive pattern covers what is below
/// a directory it matches, so the matching segment need not be the last).
/// Pure.
pub fn may_cover(root: &Root, path: &str, skip: &HashSet<String>) -> bool {
    let Some(rest) = below(&root.path, path) else { return false };
    let segs: Vec<&str> = rest.split('/').filter(|x| !x.is_empty()).collect();
    if segs.len() > 1 && segs[..segs.len() - 1].iter().any(|d| skip.contains(*d)) {
        return false;
    }
    match &root.shape {
        None => true,
        Some(s) => segs.iter().any(|seg| s.admits(seg)),
    }
}

/// One catalog name anchor (secret-catalog.ts `NameAnchor`): a NECESSARY
/// condition on a file name for a catalog shape to match, never the matcher
/// (the arbiter's). Every condition given must hold; `ci` folds ASCII case,
/// all a non-`u` JavaScript `i` flag folds for an ASCII pattern.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NameAnchor {
    pub exact: Option<String>,
    pub prefix: Option<String>,
    pub suffix: Option<String>,
    pub contains: Option<String>,
    /// The name ends in none of these (2026-10-17: the `*credentials*`
    /// shape's documentation and program-source extensions, so a
    /// `credentials.ts` costs no round trip). No condition by itself.
    pub not_suffixes: Vec<String>,
    pub ci: bool,
}

impl NameAnchor {
    /// Does the name `name` meet every condition? Pure.
    pub fn admits(&self, name: &str) -> bool {
        self.clone().folded().admits_folded(name, &name.to_ascii_lowercase())
    }

    /// The same anchor with a `ci` one's texts lower-cased once, for
    /// `admits_folded` (the hot path folds the name once, never the texts).
    pub fn folded(mut self) -> NameAnchor {
        if self.ci {
            for t in [&mut self.exact, &mut self.prefix, &mut self.suffix, &mut self.contains].into_iter().flatten() {
                t.make_ascii_lowercase();
            }
            for t in &mut self.not_suffixes {
                t.make_ascii_lowercase();
            }
        }
        self
    }

    /// `admits` for an anchor already `folded`, given the name and its ASCII
    /// lower case. Allocates nothing.
    fn admits_folded(&self, name: &str, lower: &str) -> bool {
        let n = if self.ci { lower } else { name };
        self.exact.as_deref().map_or(true, |x| n == x)
            && self.prefix.as_deref().map_or(true, |x| n.starts_with(x))
            && self.suffix.as_deref().map_or(true, |x| n.ends_with(x))
            && self.contains.as_deref().map_or(true, |x| n.contains(x))
            && !self.not_suffixes.iter().any(|x| n.ends_with(x.as_str()))
    }

    fn is_empty(&self) -> bool {
        self.exact.is_none() && self.prefix.is_none() && self.suffix.is_none() && self.contains.is_none()
    }
}

/// The catalog's name prefilter: its anchors, the homes it is read in, and
/// the directory names (beyond the walk's) below which a name-matched file
/// is not gated (`site-packages`, `dist-packages`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Catalog {
    /// Each `folded` (`Catalog::new`, `LabelIndex::apply`).
    pub names: Vec<NameAnchor>,
    pub homes: Vec<String>,
    pub skip: HashSet<String>,
}

impl Catalog {
    pub fn new(names: Vec<NameAnchor>, homes: Vec<String>, skip: HashSet<String>) -> Catalog {
        Catalog { names: names.into_iter().map(NameAnchor::folded).collect(), homes, skip }
    }
}

/// Could a catalog basename shape cover `path` (the canonical path of an
/// opened regular file)? Its name meets an anchor (an anchor with no
/// condition admits nothing: a malformed row must not make every file a
/// candidate), and no directory below the deepest home holding it (below
/// `/` outside every home) is named in `walk_skip` or the catalog's own
/// `skip`, as the walk would have pruned it. Pure.
pub fn catalog_may_cover(c: &Catalog, walk_skip: &HashSet<String>, path: &str) -> bool {
    let Some((_, name)) = path.rsplit_once('/') else { return false };
    if name.is_empty() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    if !c.names.iter().any(|a| !a.is_empty() && a.admits_folded(name, &lower)) {
        return false;
    }
    let base = c.homes.iter().filter(|h| below(h, path).is_some()).max_by_key(|h| h.len()).map(String::as_str).unwrap_or("/");
    let rest = below(base, path).unwrap_or("");
    let segs: Vec<&str> = rest.split('/').filter(|x| !x.is_empty()).collect();
    segs.len() < 2 || !segs[..segs.len() - 1].iter().any(|d| walk_skip.contains(*d) || c.skip.contains(*d))
}

#[derive(Default)]
struct State {
    key: Option<String>,
    roots: Vec<Root>,
    /// The roots with no shape, by path (`candidate` looks each ancestor of
    /// a path up: the catalog's prefixes make dozens of them).
    literal: HashSet<String>,
    skip: HashSet<String>,
    /// The catalog's name prefilter (None: an arbiter that ships none).
    catalog: Option<Catalog>,
    /// The guard's own files and directories, never a candidate
    /// (`set_exclude`).
    exclude_files: HashSet<String>,
    exclude_dirs: Vec<String>,
    refreshed_ns: Option<i128>,
    failed_ns: Option<i128>,
    /// `(dev, ino)` → (ctime ns, roots' key, level)
    cache: HashMap<(u64, u64), (i128, String, String)>,
    /// `(dev, ino)` → level, of every file gated by its label (`note_gated`).
    gated: HashMap<(u64, u64), String>,
}

/// The human label roots the guard gates opens under.
#[derive(Default)]
pub struct LabelIndex {
    state: Mutex<State>,
}

impl std::fmt::Debug for LabelIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.lock();
        f.debug_struct("LabelIndex").field("roots", &(st.roots.len() + st.literal.len())).field("key", &st.key).finish()
    }
}

impl LabelIndex {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A poisoned lock (a panicked worker) still holds a usable list.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Must the list be read (again) at `now_ns`? Never read, or older than
    /// `REFRESH_NS`, and no failure in the last `BACKOFF_NS`.
    pub fn due(&self, now_ns: i128) -> bool {
        let st = self.lock();
        if st.failed_ns.map(|f| now_ns - f < BACKOFF_NS).unwrap_or(false) {
            return false;
        }
        st.refreshed_ns.map(|r| now_ns - r >= REFRESH_NS).unwrap_or(true)
    }

    /// The key of the list in force (what to send as `key`).
    pub fn key(&self) -> Option<String> {
        self.lock().key.clone()
    }

    /// Apply an answer to a read started at `started_ns`: `unchanged` keeps
    /// the list, otherwise `roots` and `catalog` replace it under `key`;
    /// `skip_dirs` replaces the directory names not gated below a root.
    pub fn apply(&self, started_ns: i128, key: &str, unchanged: bool, roots: Vec<Root>, skip_dirs: Vec<String>, catalog: Option<Catalog>) {
        let mut st = self.lock();
        if !unchanged || st.key.as_deref() != Some(key) {
            st.literal = roots.iter().filter(|r| r.shape.is_none()).map(|r| r.path.trim_end_matches('/').to_string()).filter(|p| !p.is_empty()).collect();
            st.roots = roots.into_iter().filter(|r| r.shape.is_some() || r.path.trim_end_matches('/').is_empty()).collect();
            st.catalog = catalog.map(|c| Catalog::new(c.names, c.homes, c.skip));
            st.key = Some(key.to_string());
        }
        if !skip_dirs.is_empty() || !unchanged {
            st.skip = skip_dirs.into_iter().collect();
        }
        st.refreshed_ns = Some(st.refreshed_ns.map_or(started_ns, |r| r.max(started_ns)));
        st.failed_ns = None;
    }

    /// Record a failed read started at `started_ns` (the last list stays).
    pub fn note_failure(&self, started_ns: i128) {
        self.lock().failed_ns = Some(started_ns);
    }

    /// Has a list ever been read?
    pub fn loaded(&self) -> bool {
        self.lock().key.is_some()
    }

    /// Could a label cover `path` (the canonical path of an opened regular
    /// file)?
    pub fn candidate(&self, path: &str) -> bool {
        if path.is_empty() {
            return false;
        }
        let st = self.lock();
        if st.exclude_files.contains(path) || st.exclude_dirs.iter().any(|d| below(d, path).is_some()) {
            return false;
        }
        // A literal root: the path itself or one of its ancestors.
        let literal = !st.literal.is_empty()
            && path.char_indices().filter(|(i, c)| *c == '/' && *i > 0).map(|(i, _)| &path[..i]).chain(std::iter::once(path)).any(|a| {
                st.literal.contains(a) && may_cover(&Root { path: a.to_string(), shape: None }, path, &st.skip)
            });
        literal || st.roots.iter().any(|r| may_cover(r, path, &st.skip)) || st.catalog.as_ref().is_some_and(|c| catalog_may_cover(c, &st.skip, path))
    }

    /// The guard's own files are never candidates: the launch's twins
    /// (`files`) and the directory of the twins it makes (`dirs`), whose
    /// names repeat the files they stand for (`…-.env`).
    pub fn set_exclude(&self, files: Vec<String>, dirs: Vec<String>) {
        let mut st = self.lock();
        st.exclude_files = files.into_iter().filter(|f| f.starts_with('/')).collect();
        st.exclude_dirs = dirs.into_iter().filter(|d| d.starts_with('/') && d != "/").collect();
    }

    /// The level the arbiter gave the file `id` while its ctime was
    /// `ctime_ns`, under the list in force.
    pub fn cached(&self, id: (u64, u64), ctime_ns: i128) -> Option<String> {
        let st = self.lock();
        let key = st.key.as_deref()?;
        st.cache.get(&id).filter(|(c, k, _)| *c == ctime_ns && k == key).map(|(_, _, l)| l.clone())
    }

    /// Remember the arbiter's level for the file `id` at `ctime_ns`, under
    /// the roots' `key` it was decided with.
    pub fn remember(&self, id: (u64, u64), ctime_ns: i128, key: &str, level: &str) {
        let mut st = self.lock();
        if st.cache.len() >= CACHE_MAX {
            st.cache.clear();
        }
        st.cache.insert(id, (ctime_ns, key.to_string(), level.to_string()));
    }

    /// 2026-10-17: the file `id` was gated by its label at `level`, or (not
    /// `gated`) classified `public`: kept for its other names
    /// (`other_name_level`).
    pub fn note_gated(&self, id: (u64, u64), level: &str, gated: bool) {
        let mut st = self.lock();
        if !gated {
            st.gated.remove(&id);
            return;
        }
        if st.gated.len() >= CACHE_MAX {
            st.gated.clear();
        }
        st.gated.insert(id, level.to_string());
    }

    /// 2026-10-17 (a write via a second name): the level of the file `id`,
    /// opened by a name no label root covers, when the guard gated it by its
    /// label under another name and it still has more than one (`nlink`): a
    /// hard link outside the label (made in the session, its label then
    /// followed as a derived one, or before it) reaches the same text, so it
    /// is gated as the labelled name is, its writes included. One link: the
    /// labelled name is gone and the inode may be another file's now.
    pub fn other_name_level(&self, id: (u64, u64), nlink: u64) -> Option<String> {
        if nlink < 2 {
            return None;
        }
        self.lock().gated.get(&id).cloned()
    }

    /// How many roots the guard knows.
    pub fn len(&self) -> usize {
        let st = self.lock();
        st.roots.len() + st.literal.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Is `level` one a file is gated at (above `public`)? An unknown level is
/// (fail-closed). Pure.
pub fn gated_level(level: &str) -> bool {
    level != "public"
}

/// Whether the agent's open of a file under a label root is reported: not
/// when the arbiter already called the file, in this state, `public`. Pure.
pub fn agent_open_reported(cached: Option<&str>) -> bool {
    cached.map_or(true, gated_level)
}

/// What the report's answer means (`agent_open_record`).
#[derive(Debug, Clone, PartialEq)]
pub enum AgentOpenAnswer {
    /// The arbiter's level (it recorded the open when above `public`).
    Level(mandu_arbiter::protocol::LabelledLevel),
    /// An arbiter that does not know the op: as before, nothing is
    /// recorded and the open runs.
    Older,
    /// No answer (unreachable, a failed request, a poisoned client): the
    /// open is refused (fail-closed).
    Unanswered,
}

/// Read the report's answer: the outer `Option` is the client, the middle
/// the request, the inner the op (`labelled_level`'s `None`). Pure.
pub fn agent_open_answer(answer: Option<Option<Option<mandu_arbiter::protocol::LabelledLevel>>>) -> AgentOpenAnswer {
    match answer {
        Some(Some(Some(r))) => AgentOpenAnswer::Level(r),
        Some(Some(None)) => AgentOpenAnswer::Older,
        Some(None) | None => AgentOpenAnswer::Unanswered,
    }
}

/// Which gate an open of a regular file the launch did not register passes
/// (guard_kernel `handle_open_notif`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenGate {
    /// Not gated: the open runs on the real file.
    Ungated,
    /// A reading open: a derived file's gate, else a labelled file's.
    Read,
    /// A write-only open of a non-empty file: a labelled file's gate alone.
    LabelledWrite,
}

/// 2026-10-17 (confidentiality.md §6, "Read by a program the launch did not
/// see", the writes): the gate for an open of a regular file of `size` bytes
/// the launch did not register. A reading open (`reads`, `O_RDWR` included)
/// is gated as before. A write-only open of a NON-EMPTY file is gated too,
/// by a human label only, as a registered file's is (its twin, or the real
/// file for a reader a human named): a program that read the placeholder
/// and writes the file back (`s=$(cat f); echo "${s/a/b}" > f`, `python
/// open(p).read()` then `open(p, "w")`, `cp edited f`) would otherwise put
/// placeholder text over the real file, and an append (`echo x >> f`) lands
/// where a registered file's does, in the copy the session-end notice
/// names. An EMPTY file's write-only open (a file the open creates, `echo x
/// > new.md` under a label) runs on the real file: there is no text to
/// replace, and a write-only descriptor reads nothing. Nor is a HOLDER's
/// (`holder`: the writer, or an ancestor, holds a secret raw): its write
/// runs on the real file, which takes its label as before (plan 13 D5,
/// `label_tainted_write`), since bytes it wrote into a twin would be served
/// as written to every later reader of that twin. A derived file's
/// write-only open stays ungated (its holders write it). `size` is the
/// file's before any `O_TRUNC` (held back until after the lookup). Pure.
pub fn open_gate(reads: bool, write_intent: bool, size: u64, holder: bool) -> OpenGate {
    if reads {
        OpenGate::Read
    } else if write_intent && size > 0 && !holder {
        OpenGate::LabelledWrite
    } else {
        OpenGate::Ungated
    }
}

/// 2026-10-17: is a rename onto `dest` (the existing file the call would
/// replace, `regular` and of `size` bytes) one the caller must check for a
/// human label? A non-empty regular file only: the program renaming may have
/// built its new text from the placeholder (`sed -i`, `perl -i`, an editor's
/// save), and the real file is never replaced by it, as a registered file is
/// not (`secret_open::registered_secret_refuses`, `Dest`). Pure.
pub fn rename_dest_checked(regular: bool, size: u64) -> bool {
    regular && size > 0
}

/// Where the guard records each twin it makes of a labelled file, in the
/// launch's `derived-twins/` directory (one JSON object per line, appended):
/// the launcher names, at the session's end, each labelled file whose twin a
/// program changed (launcher twin-writes.ts `LABELLED_TWIN_RECORDS`). No twin
/// is named like it (theirs start with sixteen hex digits,
/// `derived_index::twin_file_name`).
pub const TWIN_RECORDS: &str = "labelled-twins.ndjson";

/// One labelled file's twin as the guard made it. The twin's size and hash
/// (of placeholder text the reader is shown anyway), and the REAL file's
/// identity only: never its size or a hash of its bytes, which a short
/// secret could be guessed from (the directory is the agent's to read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwinRecord {
    pub target: String,
    pub twin: String,
    pub sha256: String,
    pub size: u64,
    /// The twin file's `(dev, ino)`.
    pub twin_id: (u64, u64),
    /// The real file's `(dev, ino)`, mtime and ctime (ns) when the twin was made.
    pub real_id: (u64, u64),
    pub real_mtime_ns: i128,
    pub real_ctime_ns: i128,
    /// When the guard looked at the real file (ns since the epoch): a change
    /// within one timestamp tick of that look leaves the identity as it was
    /// (same inode, mtime and ctime), so the launcher clears the real file
    /// as unchanged only when its times lie well before this (twin-writes.ts
    /// `REAL_TIME_SLACK_NS`).
    pub marked_ns: i128,
}

/// `rec` as one line of `TWIN_RECORDS` (with its newline). Numbers that may
/// pass 2^53 are strings, as the launcher's bigint stats print them. Pure.
pub fn twin_record_line(rec: &TwinRecord) -> String {
    let v = serde_json::json!({
        "v": 1,
        "targetPath": rec.target,
        "twinPath": rec.twin,
        "sha256": rec.sha256,
        "size": rec.size,
        "dev": rec.twin_id.0.to_string(),
        "ino": rec.twin_id.1.to_string(),
        "real": {
            "dev": rec.real_id.0.to_string(),
            "ino": rec.real_id.1.to_string(),
            "mtimeNs": rec.real_mtime_ns.to_string(),
            "ctimeNs": rec.real_ctime_ns.to_string(),
            "markedNs": rec.marked_ns.to_string(),
        },
    });
    format!("{v}\n")
}

/// The names a labelled file's twin may take, in order: its own
/// (`derived_index::twin_file_name`), then `<name>.1`, `<name>.2`, … The
/// guard takes the first that does not exist, so a twin remade after the
/// real file changed never replaces an earlier one a program may have
/// written to (the notice compares each against its own record). Pure.
pub fn twin_name_candidates(name: &str) -> impl Iterator<Item = String> + '_ {
    (0..TWIN_NAME_TRIES).map(move |n| if n == 0 { name.to_string() } else { format!("{name}.{n}") })
}

/// How many names `twin_name_candidates` offers: past them no twin is made
/// (the open is refused, fail-closed).
pub const TWIN_NAME_TRIES: u32 = 4096;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agents_own_open_is_reported_unless_known_public_and_an_unanswered_report_refuses() {
        // 2026-10-17 (confidentiality.md §6, "The base follows the shell").
        assert!(agent_open_reported(None), "a file the arbiter has not judged: reported");
        assert!(agent_open_reported(Some("no-model")), "a labelled file: reported at every open (each is a record)");
        assert!(!agent_open_reported(Some("public")), "a file the arbiter called public in this state: no round trip");
        let level = mandu_arbiter::protocol::LabelledLevel { level: "no-model".into(), key: "k".into(), recorded: true };
        assert_eq!(agent_open_answer(Some(Some(Some(level.clone())))), AgentOpenAnswer::Level(level));
        assert_eq!(agent_open_answer(Some(Some(None))), AgentOpenAnswer::Older, "an older arbiter (unknown op): the open runs, as before");
        assert_eq!(agent_open_answer(Some(None)), AgentOpenAnswer::Unanswered, "a failed request: refuse (fail-closed)");
        assert_eq!(agent_open_answer(None), AgentOpenAnswer::Unanswered, "no client to ask: refuse (fail-closed)");
    }

    const S: i128 = 1_000_000_000;

    fn lit(p: &str) -> Root {
        Root { path: p.into(), shape: None }
    }
    fn pat(p: &str, head: &str, tail: &str, exact: bool) -> Root {
        Root { path: p.into(), shape: Some(Shape { head: head.into(), tail: tail.into(), exact }) }
    }

    #[test]
    fn below_is_segment_aware() {
        assert_eq!(below("/ws/vault", "/ws/vault/plan.md"), Some("plan.md"));
        assert_eq!(below("/ws/vault", "/ws/vault"), Some(""));
        assert_eq!(below("/ws/vault/", "/ws/vault/a/b"), Some("a/b"));
        assert_eq!(below("/ws/vault", "/ws/vaults/plan.md"), None, "a sibling with a longer name is not below");
        assert_eq!(below("/ws/vault", "/ws/plan.md"), None);
        assert_eq!(below("/", "/etc/x.pem"), Some("etc/x.pem"));
    }

    #[test]
    fn a_literal_root_covers_everything_at_or_below_it() {
        let r = lit("/ws/vault");
        let none = HashSet::new();
        assert!(may_cover(&r, "/ws/vault/plan.md", &none));
        assert!(may_cover(&r, "/ws/vault/a/b/c/d/e/deep.md", &none), "any depth below the label");
        assert!(may_cover(&lit("/ws/plan.md"), "/ws/plan.md", &none), "a labelled file is its own root");
        assert!(!may_cover(&r, "/ws/other/plan.md", &none));
    }

    #[test]
    fn a_pattern_root_admits_only_paths_with_a_segment_of_its_shape() {
        let none = HashSet::new();
        // `/ws/notes/*.md`
        let r = pat("/ws/notes", "", ".md", false);
        assert!(may_cover(&r, "/ws/notes/plan.md", &none));
        assert!(!may_cover(&r, "/ws/notes/readme.txt", &none), "the prefilter spares a file the pattern cannot match");
        assert!(!may_cover(&r, "/ws/other/plan.md", &none));
        // `**/*.pem`: no prefix, root `/`
        let pem = pat("/", "", ".pem", false);
        assert!(may_cover(&pem, "/home/u/keys/server.pem", &none));
        assert!(!may_cover(&pem, "/home/u/keys/server.txt", &none));
        // `/proj/*/secrets` recursive: the matching segment is an ancestor
        let dir = pat("/proj", "secrets", "secrets", true);
        assert!(may_cover(&dir, "/proj/a/secrets/token.txt", &none));
        assert!(!may_cover(&dir, "/proj/a/secret/token.txt", &none));
        // `secret-*.md`: both anchors, and at least their length
        let both = pat("/ws", "secret-", ".md", false);
        assert!(may_cover(&both, "/ws/secret-plan.md", &none));
        assert!(!may_cover(&both, "/ws/secret-.m", &none), "shorter than its anchors");
        assert!(!may_cover(&both, "/ws/plan.md", &none));
    }

    #[test]
    fn a_directory_the_walk_never_enters_is_not_gated_below_a_root() {
        let skip: HashSet<String> = ["node_modules", ".git", "target"].iter().map(|s| s.to_string()).collect();
        let r = lit("/ws/proj");
        assert!(!may_cover(&r, "/ws/proj/node_modules/x/index.js", &skip), "a toolchain's files in a labelled project");
        assert!(!may_cover(&r, "/ws/proj/.git/objects/pack/p.pack", &skip));
        assert!(may_cover(&r, "/ws/proj/src/plan.md", &skip));
        assert!(may_cover(&r, "/ws/proj/target", &skip), "a FILE named like one is gated");
        assert!(may_cover(&lit("/ws/proj/node_modules/secret-pkg"), "/ws/proj/node_modules/secret-pkg/key.txt", &skip), "a label inside one speaks for itself");
        let ix = LabelIndex::default();
        ix.apply(0, "k", false, vec![r], skip.into_iter().collect(), None);
        assert!(!ix.candidate("/ws/proj/node_modules/x/index.js") && ix.candidate("/ws/proj/src/plan.md"));
    }

    #[test]
    fn the_list_is_read_when_first_needed_then_at_most_every_refresh_and_backs_off_after_a_failure() {
        let ix = LabelIndex::default();
        assert!(ix.due(100 * S) && !ix.loaded());
        assert!(!ix.candidate("/ws/vault/plan.md"), "an index never read gates nothing");
        ix.apply(100 * S, "k1", false, vec![lit("/ws/vault")], Vec::new(), None);
        assert!(ix.loaded() && ix.candidate("/ws/vault/plan.md"));
        assert!(!ix.due(100 * S + S / 2), "fresh");
        assert!(ix.due(101 * S), "stale after REFRESH_NS");
        ix.note_failure(101 * S);
        assert!(!ix.due(101 * S + S / 2), "backing off");
        assert!(ix.candidate("/ws/vault/plan.md"), "the last list read stays in force");
        assert!(ix.due(102 * S));
        // unchanged keeps the list; a new key replaces it
        ix.apply(102 * S, "k1", true, Vec::new(), Vec::new(), None);
        assert!(ix.candidate("/ws/vault/plan.md"));
        ix.apply(103 * S, "k2", false, vec![lit("/ws/notes")], Vec::new(), None);
        assert!(!ix.candidate("/ws/vault/plan.md") && ix.candidate("/ws/notes/a"));
        assert_eq!(ix.key().as_deref(), Some("k2"));
    }

    #[test]
    fn a_cached_level_holds_only_for_the_same_file_state_under_the_same_roots() {
        let ix = LabelIndex::default();
        ix.apply(0, "k1", false, vec![lit("/ws/vault")], Vec::new(), None);
        ix.remember((7, 42), 5, "k1", "no-model");
        assert_eq!(ix.cached((7, 42), 5).as_deref(), Some("no-model"));
        assert_eq!(ix.cached((7, 42), 6), None, "the file changed (ctime)");
        assert_eq!(ix.cached((7, 43), 5), None, "another file");
        ix.apply(1, "k2", false, vec![lit("/ws/vault")], Vec::new(), None);
        assert_eq!(ix.cached((7, 42), 5), None, "the labels changed (key)");
    }

    #[test]
    fn a_reading_open_is_gated_and_a_write_only_open_only_of_a_non_empty_file() {
        // O_RDONLY / O_RDWR (empty or not, O_CREAT or not): the read gate.
        assert_eq!(open_gate(true, false, 10, false), OpenGate::Read);
        assert_eq!(open_gate(true, true, 0, false), OpenGate::Read);
        assert_eq!(open_gate(true, true, 9, true), OpenGate::Read, "a holder's reading open too");
        // `echo x >> f`, `> f`, `cp a f`: a non-empty file's write-only open.
        assert_eq!(open_gate(false, true, 1, false), OpenGate::LabelledWrite);
        // A holder's write runs on the real file (its label taints it, D5):
        // its bytes in a twin would be served raw to the twin's readers.
        assert_eq!(open_gate(false, true, 1, true), OpenGate::Ungated);
        // `echo x > new.md`: the open created it (empty), runs on the real file.
        assert_eq!(open_gate(false, true, 0, false), OpenGate::Ungated);
        // An open that neither reads nor writes (O_PATH is gated elsewhere).
        assert_eq!(open_gate(false, false, 10, false), OpenGate::Ungated);
    }

    #[test]
    fn a_rename_onto_a_non_empty_regular_file_is_checked() {
        assert!(rename_dest_checked(true, 5));
        assert!(!rename_dest_checked(true, 0), "an empty file holds no text a placeholder would replace");
        assert!(!rename_dest_checked(false, 5), "a directory, a symlink: not a labelled file's text");
    }

    #[test]
    fn a_twin_record_names_the_twin_and_only_the_real_files_identity() {
        let rec = TwinRecord {
            target: "/w/vault/plan.md".into(),
            twin: "/s/secret-twins/derived-twins/0123456789abcdef-plan.md".into(),
            sha256: "ab".repeat(32),
            size: 24,
            twin_id: (u64::MAX, 7),
            real_id: (2049, 9_007_199_254_740_993),
            real_mtime_ns: 1_700_000_000_123_456_789,
            real_ctime_ns: 1_700_000_001_000_000_000,
            marked_ns: 1_700_000_005_000_000_000,
        };
        let line = twin_record_line(&rec);
        assert!(line.ends_with('\n') && line.matches('\n').count() == 1, "{line}");
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["targetPath"], "/w/vault/plan.md");
        assert_eq!(v["size"], 24);
        assert_eq!(v["dev"], u64::MAX.to_string(), "past 2^53: a string");
        assert_eq!(v["real"]["ino"], "9007199254740993");
        assert_eq!(v["real"]["mtimeNs"], "1700000000123456789");
        let real = v["real"].as_object().unwrap();
        let mut keys: Vec<&str> = real.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["ctimeNs", "dev", "ino", "markedNs", "mtimeNs"], "never the real file's size or a hash of its bytes");
        assert_eq!(v["real"]["markedNs"], "1700000005000000000");
    }

    #[test]
    fn a_remade_twin_takes_a_fresh_name() {
        let names: Vec<String> = twin_name_candidates("0123-plan.md").take(3).collect();
        assert_eq!(names, ["0123-plan.md", "0123-plan.md.1", "0123-plan.md.2"]);
        assert_eq!(twin_name_candidates("x").count(), TWIN_NAME_TRIES as usize);
        assert!(twin_name_candidates("0123-plan.md").all(|n| n != TWIN_RECORDS));
    }

    #[test]
    fn another_name_of_a_gated_file_is_gated_while_the_file_has_more_than_one() {
        let ix = LabelIndex::default();
        assert_eq!(ix.other_name_level((7, 42), 2), None, "never gated");
        ix.note_gated((7, 42), "no-model", true);
        assert_eq!(ix.other_name_level((7, 42), 2).as_deref(), Some("no-model"));
        assert_eq!(ix.other_name_level((7, 42), 1), None, "one name left: the inode may be another file's");
        assert_eq!(ix.other_name_level((7, 43), 3), None);
        ix.note_gated((7, 42), "public", false);
        assert_eq!(ix.other_name_level((7, 42), 2), None, "the label was cleared");
    }

    #[test]
    fn public_is_the_only_level_not_gated() {
        assert!(!gated_level("public"));
        for l in ["any-model", "local-model", "no-model", "weird"] {
            assert!(gated_level(l), "{l}");
        }
    }

    fn anchor(exact: Option<&str>, prefix: Option<&str>, suffix: Option<&str>, contains: Option<&str>, ci: bool) -> NameAnchor {
        let s = |x: Option<&str>| x.map(String::from);
        NameAnchor { exact: s(exact), prefix: s(prefix), suffix: s(suffix), contains: s(contains), not_suffixes: Vec::new(), ci }
    }

    /// The `*credentials*` anchor as the arbiter ships it, with a few of its
    /// documentation and source suffixes (secret-catalog.ts SOURCE_EXTS).
    fn credentials() -> NameAnchor {
        let not_suffixes = [".md", ".rst", ".ts", ".tsx", ".js", ".py", ".rs", ".go", ".java", ".h"].map(String::from).to_vec();
        NameAnchor { not_suffixes, ..anchor(None, None, None, Some("credentials"), true) }
    }

    /// A few of the arbiter's anchors (secret-catalog.ts SECRET_BASENAME_SHAPES).
    fn catalog(homes: &[&str]) -> Catalog {
        Catalog {
            names: vec![
                anchor(Some(".env"), None, None, None, false),
                anchor(None, Some(".env."), None, None, false),
                anchor(None, None, Some(".env"), None, false),
                credentials(),
                anchor(None, None, Some(".json"), Some("secret"), true),
                anchor(None, None, Some("key.pem"), None, true),
            ],
            homes: homes.iter().map(|h| h.to_string()).collect(),
            skip: ["site-packages".to_string(), "dist-packages".to_string()].into_iter().collect(),
        }
    }

    #[test]
    fn a_name_anchor_holds_every_condition_it_names_and_folds_ascii_case_only() {
        assert!(anchor(None, None, Some(".json"), Some("secret"), true).admits("My-SECRETS.JSON"));
        assert!(!anchor(None, None, Some(".json"), Some("secret"), true).admits("secrets.yaml"), "both conditions");
        assert!(!anchor(None, Some("secrets"), Some(".json"), None, false).admits("Secrets.json"), "case-sensitive without ci");
        assert!(anchor(Some(".env"), None, None, None, false).admits(".env"));
        assert!(!anchor(Some(".env"), None, None, None, false).admits(".env.local"));
        assert!(!anchor(None, None, None, Some("secret"), true).admits("\u{17F}ecret"), "a non-ASCII letter never folds to an ASCII one");
        assert!(anchor(None, None, None, None, false).admits("x") && !catalog_may_cover(&Catalog { names: vec![NameAnchor::default()], ..Default::default() }, &HashSet::new(), "/a/x"), "an anchor with no condition makes no candidate");
    }

    #[test]
    fn a_not_suffix_spares_a_source_or_documentation_name_and_folds_with_ci() {
        let a = credentials().folded();
        for n in ["credentials", "credentials.json", "aws_credentials", "Credentials.xml", "credentials.sh", "credentials.yml.enc", "credentials.tfrc.json", "credentials.ts.bak", ".credentials.json"] {
            assert!(a.admits(n), "{n}: a data file, still a candidate");
        }
        for n in ["credentials.ts", "credentials.test.ts", "Credentials.TS", "credentials.d.ts", "CredentialsProvider.java", "credentials.py", "credentials.rs", "credentials.h", "credentials.md", "credentials.RST"] {
            assert!(!a.admits(n), "{n}: source or documentation, no round trip");
        }
        // Case-sensitive without ci; a not-suffix alone is no condition.
        let cs = NameAnchor { not_suffixes: vec![".ts".into()], ..anchor(None, None, None, Some("credentials"), false) };
        assert!(cs.admits("credentials.TS") && !cs.admits("credentials.ts"));
        let only = NameAnchor { not_suffixes: vec![".ts".into()], ..NameAnchor::default() };
        assert!(!catalog_may_cover(&Catalog::new(vec![only], Vec::new(), HashSet::new()), &HashSet::new(), "/a/x.json"), "an anchor with only not-suffixes makes no candidate");
        // The gate has no depth cap: a source file deeper than the walk is spared, a data file is not.
        let c = catalog(&["/home/u"]);
        assert!(!catalog_may_cover(&c, &HashSet::new(), "/home/u/proj/src/auth/providers/a/b/credentials.ts"));
        assert!(catalog_may_cover(&c, &HashSet::new(), "/home/u/proj/src/auth/providers/a/b/credentials.json"));
    }

    #[test]
    fn the_catalog_prefilter_admits_a_shaped_name_at_any_depth_and_spares_the_walks_skipped_directories() {
        let walk: HashSet<String> = ["node_modules", ".git", "build", ".cache"].iter().map(|s| s.to_string()).collect();
        let c = catalog(&["/home/u"]);
        assert!(catalog_may_cover(&c, &walk, "/home/u/proj/.env"));
        assert!(catalog_may_cover(&c, &walk, "/home/u/proj/a/b/c/d/e/f/.env.local"), "deeper than the walk");
        assert!(catalog_may_cover(&c, &walk, "/home/u/proj/aws_Credentials.ini"));
        assert!(catalog_may_cover(&c, &walk, "/srv/app/prod.env"), "outside every home");
        assert!(!catalog_may_cover(&c, &walk, "/home/u/proj/index.js"), "no anchor: no round trip");
        assert!(!catalog_may_cover(&c, &walk, "/home/u/proj/node_modules/pkg/.env"), "the walk never enters node_modules");
        assert!(!catalog_may_cover(&c, &walk, "/home/u/venv/lib/python3.12/site-packages/botocore/data/credentials.json"), "nor a Python install tree");
        assert!(!catalog_may_cover(&c, &walk, "/srv/build/app/.env"), "outside every home, every directory counts");
        assert!(catalog_may_cover(&catalog(&["/home/u/build"]), &walk, "/home/u/build/proj/.env"), "below a home only the directories under it count");
        assert!(catalog_may_cover(&c, &walk, "/home/u/.env"), "a file right in a home");
        assert!(catalog_may_cover(&c, &walk, "/home/u/build.env"), "a FILE named like a skipped directory, but for its anchor");
    }

    #[test]
    fn the_catalog_and_its_prefixes_reach_candidate_and_the_guards_own_directory_never_does() {
        let ix = LabelIndex::default();
        let walk: Vec<String> = vec!["node_modules".into()];
        ix.apply(0, "k1", false, vec![lit("/home/u/.ssh")], walk.clone(), Some(catalog(&["/home/u"])));
        assert!(ix.candidate("/home/u/.ssh/config.d/work"), "a catalog prefix is a root");
        assert!(ix.candidate("/home/u/proj/.env"));
        assert!(!ix.candidate("/home/u/proj/main.rs"));
        ix.set_exclude(vec!["/run/u/mandu/secret-twins/0a1b2c3d-.env".into()], vec!["/run/u/mandu/secret-twins/derived-twins".into()]);
        assert!(!ix.candidate("/run/u/mandu/secret-twins/0a1b2c3d-.env"), "a twin's name repeats its file's");
        assert!(!ix.candidate("/run/u/mandu/secret-twins/derived-twins/9f-.env"));
        assert!(ix.candidate("/run/u/mandu/secret-twins/other.env"), "only the twins themselves");
        // an unchanged answer keeps the catalog; a new list without one drops it
        ix.apply(1, "k1", true, Vec::new(), Vec::new(), None);
        assert!(ix.candidate("/home/u/proj/.env"));
        ix.apply(2, "k2", false, Vec::new(), walk, None);
        assert!(!ix.candidate("/home/u/proj/.env"), "an arbiter that ships no catalog gates none");
    }

    /// The prefilter's cost on the hot path: an open of a file no root and no
    /// anchor admits (the overwhelming case). `cargo test -p net-supervisor
    /// --release candidate_cost -- --ignored --nocapture` prints it.
    #[test]
    #[ignore]
    fn candidate_cost() {
        let ix = LabelIndex::default();
        let roots: Vec<Root> = (0..90).map(|i| lit(&format!("/home/u/.prefix{i:02}"))).collect();
        let mut c = catalog(&["/home/u", "/home/launch"]);
        for i in 0..20 {
            c.names.push(anchor(None, None, Some(&format!(".ext{i}")), None, true));
        }
        ix.apply(0, "k", false, roots, vec!["node_modules".into(), ".git".into()], Some(c));
        let paths = ["/home/u/proj/src/lib/module/index.ts", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/home/u/proj/target/debug/build/x/out/y.rs"];
        // The kernel lane runs it with `--include-ignored` in a debug build
        // (about 14 us an open there): a short loop, so it does not hold a
        // core for seconds beside the binary's timing tests.
        let n = if cfg!(debug_assertions) { 10_000 } else { 200_000 };
        let t = std::time::Instant::now();
        let mut hits = 0;
        for i in 0..n {
            hits += ix.candidate(paths[i % paths.len()]) as usize;
        }
        let per = t.elapsed().as_nanos() as f64 / n as f64;
        eprintln!("candidate(): {per:.0} ns per open of an unshaped file, {hits} hits");
        assert_eq!(hits, 0);
    }
}
