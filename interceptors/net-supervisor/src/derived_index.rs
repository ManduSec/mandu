//! derived_index — confidentiality plan 13 D4: the DERIVED labels at the
//! program gate (docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md §3
//! D4, §4.6, §7 step 5).
//!
//! A derived label is the arbiter's record that a file was written by a
//! process holding a secret (plan 10's filesystem exit) or by a high session
//! (Plan 9). Before this module the guard loaded its secret index once at
//! start and nothing ever added a derived path to it, so a copy of `.env` a
//! reader made was opened raw by every program (`curl --data @copy.txt`).
//! Now the guard keeps the derived paths it knows here and gates an open of
//! one like an open of a registered file with no reader list: the arbiter
//! decides (the twin for everyone but an opener a human named), and the twin
//! is made on demand from the arbiter's `registerSecret`.
//!
//! How the list stays current (the channel): the guard PULLS. Each read-
//! capable open of a regular file the list does not know asks the arbiter for
//! what changed (`derivedLabelsSince`, an epoch and a change number, so an
//! unchanged list costs one small round trip) when the file changed (its
//! ctime) at or after the start of the last good read of the list, minus
//! `SLACK_NS`. A file untouched since then cannot carry a label the list
//! lacks: Plan 9 labels a path before the agent's write runs, and the guard
//! adds the labels it mints itself (`insert`) as soon as the arbiter answers,
//! which is before the writer holds its descriptor (no later open can beat
//! it). The first open after the guard starts always reads the whole list.
//!
//! Fail-closed: when the list cannot be read, a file that changed since the
//! guard started (`fresh_since_start`) is refused, since it may be a copy made
//! in this session; an older file opens as before, because the launch's
//! discovery registered every derived file the arbiter knew at the start
//! (plan 13 step 5's other half). A failure is not retried for `BACKOFF_NS`,
//! so a hung arbiter does not stall every open. An arbiter older than the
//! guard (it does not know the op) is said once and leaves the guard gating
//! the copies it labels itself (the behaviour before the fix for the rest).
//!
//! The label follows its file: a hit by identity under another name (a
//! rename or hard link the guard did not perform) and the guard's own
//! performed rename and link of a derived file make the arbiter label the
//! new name (`followDerivedLabel`) before the new name is served.
//!
//! PURE but for the clock and the filesystem resolution, which the callers
//! pass in; the arbiter round trips are guard_kernel's.
//!
//! Mandu-new (no reference origin).

use std::collections::HashMap;
use std::sync::Mutex;

/// The ctime margin of the freshness checks, ns. Covers the coarse clock the
/// kernel stamps file times with and the moment between a write-open being
/// answered and the label the guard asks for it landing.
pub const SLACK_NS: i128 = 2_000_000_000;

/// How long a failed read of the list is not retried, ns.
pub const BACKOFF_NS: i128 = 1_000_000_000;

/// What a path resolves to on the filesystem: its canonical spelling and its
/// `(st_dev, st_ino)`, either absent when it does not resolve.
pub type Resolved = (Option<String>, Option<(u64, u64)>);

/// The resolution to key a label by when the labelled file is one a process
/// holds open (the taint sweep's held writes, 2026-10-17): the path's
/// canonical spelling now, and the HELD file's identity, read with its path
/// from the descriptor, when known (else the path's own now). A path
/// renamed over between the sweep and the label then keys the held file,
/// not the one that took its name. Pure.
pub fn held_resolution(now: Resolved, held: Option<(u64, u64)>) -> Resolved {
    (now.0, held.or(now.1))
}

#[derive(Default)]
struct State {
    epoch: Option<String>,
    gen: u64,
    /// label path → level
    labels: HashMap<String, String>,
    /// another spelling (the canonical one) → label path
    spellings: HashMap<String, String>,
    /// `(dev, ino)` → label path
    ids: HashMap<(u64, u64), String>,
    /// When the last good read of the list STARTED, ns.
    refreshed_ns: Option<i128>,
    /// When the last failed read started, ns.
    failed_ns: Option<i128>,
}

/// A twin the guard made for a derived file, and what the file was then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwinKey {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i128,
}

/// The derived paths the guard gates at the open.
pub struct DerivedIndex {
    state: Mutex<State>,
    started_ns: i128,
    twins: Mutex<HashMap<String, (TwinKey, String)>>,
    /// `(dev, ino)` of every twin file the guard made → the derived path it
    /// stands for: a descriptor stat of a twin reports that file's identity
    /// (`stat_twin::fd_stat_call`). Kept for twins since replaced, which a
    /// descriptor served earlier may still hold.
    twin_ids: Mutex<HashMap<(u64, u64), String>>,
}

impl Default for DerivedIndex {
    /// An index whose guard started now.
    fn default() -> Self {
        DerivedIndex::new(crate::secret_open::now_ns())
    }
}

impl std::fmt::Debug for DerivedIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedIndex").field("labels", &self.len()).field("started_ns", &self.started_ns).finish()
    }
}

impl DerivedIndex {
    /// An empty index for a guard started at `now_ns`.
    pub fn new(now_ns: i128) -> Self {
        DerivedIndex { state: Mutex::new(State::default()), started_ns: now_ns, twins: Mutex::new(HashMap::new()), twin_ids: Mutex::new(HashMap::new()) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A poisoned lock (a panicked worker) still holds a usable map.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The label covering the opened file (`seen`, the path its descriptor
    /// names; `id`, its identity): `(label path, level)`, by path, by another
    /// spelling of a label path, or by identity (a hard link, a renamed file).
    pub fn hit(&self, seen: &str, id: Option<(u64, u64)>) -> Option<(String, String)> {
        let st = self.lock();
        let label = st
            .labels
            .contains_key(seen)
            .then(|| seen.to_string())
            .or_else(|| st.spellings.get(seen).cloned())
            .or_else(|| id.and_then(|i| st.ids.get(&i).cloned()))?;
        let level = st.labels.get(&label)?.clone();
        Some((label, level))
    }

    /// Is `seen` the label path itself or a known spelling of it?
    pub fn names(&self, label: &str, seen: &str) -> bool {
        label == seen || self.lock().spellings.get(seen).map(|l| l == label).unwrap_or(false)
    }

    /// Must the list be read afresh before a miss for a file whose ctime is
    /// `ctime_ns` is believed? Always before the first good read.
    pub fn stale_for(&self, ctime_ns: i128) -> bool {
        match self.lock().refreshed_ns {
            None => true,
            Some(r) => ctime_ns >= r - SLACK_NS,
        }
    }

    /// Did the file change since the guard started (so a list that cannot be
    /// read must refuse it)?
    pub fn fresh_since_start(&self, ctime_ns: i128) -> bool {
        ctime_ns >= self.started_ns - SLACK_NS
    }

    /// Did a read of the list fail less than `BACKOFF_NS` before `now_ns`?
    pub fn backing_off(&self, now_ns: i128) -> bool {
        self.lock().failed_ns.map(|f| now_ns - f < BACKOFF_NS).unwrap_or(false)
    }

    /// Record a failed read of the list started at `started_ns`.
    pub fn note_failure(&self, started_ns: i128) {
        self.lock().failed_ns = Some(started_ns);
    }

    /// What to ask the arbiter: the epoch and change number last seen.
    pub fn cursor(&self) -> (Option<String>, u64) {
        let st = self.lock();
        (st.epoch.clone(), st.gen)
    }

    /// Apply the arbiter's answer to a read started at `started_ns`: a new
    /// epoch replaces the list (the answer then holds every row), the same
    /// epoch adds to it. `resolve` gives each path's canonical spelling and
    /// identity now.
    pub fn apply(&self, started_ns: i128, epoch: &str, gen: u64, rows: &[(String, String)], resolve: impl Fn(&str) -> Resolved) {
        let resolved: Vec<(String, String, Resolved)> = rows.iter().map(|(p, l)| (p.clone(), l.clone(), resolve(p))).collect();
        let mut st = self.lock();
        if st.epoch.as_deref() != Some(epoch) {
            // Every row comes with a new epoch: start over, so a row the new
            // arbiter no longer has (a human cleared it) is gone too.
            st.labels.clear();
            st.spellings.clear();
            st.ids.clear();
            st.epoch = Some(epoch.to_string());
            // The new epoch's numbers start afresh: its own, never the old
            // epoch's (a larger old number would skip the new rows).
            st.gen = gen;
        }
        st.gen = st.gen.max(gen);
        for (path, level, r) in resolved {
            add(&mut st, &path, &level, r);
        }
        st.refreshed_ns = Some(st.refreshed_ns.map_or(started_ns, |r| r.max(started_ns)));
        st.failed_ns = None;
    }

    /// Add one label the guard learned from its own request (a write it
    /// labelled, a label that followed a rename).
    pub fn insert(&self, path: &str, level: &str, resolved: Resolved) {
        add(&mut self.lock(), path, level, resolved);
    }

    /// The labels below the directory `dir` (2026-10-16, a folder moved over
    /// derived files): each `(label path, the spelling below dir)`, by the
    /// label's own path or a known other spelling of it. Pure over the list.
    pub fn under(&self, dir: &str) -> Vec<(String, String)> {
        let d = format!("{}/", dir.trim_end_matches('/'));
        let st = self.lock();
        let mut out: Vec<(String, String)> = st.labels.keys().filter(|p| p.starts_with(&d)).map(|p| (p.clone(), p.clone())).collect();
        out.extend(st.spellings.iter().filter(|(s, _)| s.starts_with(&d)).map(|(s, l)| (l.clone(), s.clone())));
        out.sort();
        out.dedup();
        out
    }

    /// How many derived paths the guard knows.
    pub fn len(&self) -> usize {
        self.lock().labels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The twin made for `path` while the file was `key`, if any.
    pub fn cached_twin(&self, path: &str, key: &TwinKey) -> Option<String> {
        let t = self.twins.lock().unwrap_or_else(|p| p.into_inner());
        t.get(path).filter(|(k, _)| k == key).map(|(_, twin)| twin.clone())
    }

    /// Remember the twin made for `path` while the file was `key`.
    pub fn set_twin(&self, path: &str, key: TwinKey, twin: String) {
        self.twins.lock().unwrap_or_else(|p| p.into_inner()).insert(path.to_string(), (key, twin));
    }

    /// Remember that the twin file `twin_id` stands for `path`.
    pub fn note_twin_identity(&self, twin_id: (u64, u64), path: &str) {
        self.twin_ids.lock().unwrap_or_else(|p| p.into_inner()).insert(twin_id, path.to_string());
    }

    /// The derived path a twin file (by its identity) stands for, if the
    /// guard made it.
    pub fn path_of_twin(&self, twin_id: (u64, u64)) -> Option<String> {
        self.twin_ids.lock().unwrap_or_else(|p| p.into_inner()).get(&twin_id).cloned()
    }
}

fn add(st: &mut State, path: &str, level: &str, (canon, id): Resolved) {
    // A label never weakens here: the stricter level of two answers stays
    // (no-model above local-model above any-model).
    let rank = |l: &str| match l {
        "no-model" => 3,
        "local-model" => 2,
        "any-model" => 1,
        _ => 3, // an unknown level is the strictest (fail-closed)
    };
    let keep = match st.labels.get(path) {
        Some(old) if rank(old) >= rank(level) => old.clone(),
        _ => level.to_string(),
    };
    st.labels.insert(path.to_string(), keep);
    if let Some(c) = canon.filter(|c| c != path) {
        st.spellings.insert(c, path.to_string());
    }
    if let Some(i) = id {
        st.ids.insert(i, path.to_string());
    }
}

/// The whole-file twin's text (launcher secret-twins.ts `wholeFileTwinText`):
/// the symbol, then the original's final line terminator when the arbiter
/// reported one of `""`, `"\n"`, `"\r\n"`, else `"\n"`. Pure.
pub fn whole_file_twin_text(symbol: &str, terminator: Option<&str>) -> String {
    let end = match terminator {
        Some("") => "",
        Some("\r\n") => "\r\n",
        _ => "\n",
    };
    format!("{symbol}{end}")
}

/// The twin file's name for a derived path: a hash of the path (no two
/// paths share one) and its basename, made safe. Pure.
pub fn twin_file_name(path: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(path.as_bytes());
    let hex: String = h.iter().take(8).map(|b| format!("{b:02x}")).collect();
    let base = path.rsplit('/').next().unwrap_or("derived");
    let safe: String = base.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' }).take(40).collect();
    format!("{hex}-{safe}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i128 = 1_000_000_000;

    fn none(_: &str) -> Resolved {
        (None, None)
    }

    #[test]
    fn a_held_writes_label_is_keyed_by_the_held_file_not_by_what_took_its_name() {
        // The sweep read out.txt's descriptor: file (7, 42). Before the label
        // landed, another file (7, 99) was renamed over out.txt.
        let now: Resolved = (Some("/real/w/out.txt".into()), Some((7, 99)));
        assert_eq!(held_resolution(now.clone(), Some((7, 42))), (Some("/real/w/out.txt".into()), Some((7, 42))));
        assert_eq!(held_resolution(now.clone(), None), now, "no held identity: the path's own");
        let d = DerivedIndex::new(100 * S);
        d.insert("/w/out.txt", "no-model", held_resolution(now, Some((7, 42))));
        assert_eq!(d.hit("/w/moved.txt", Some((7, 42))), Some(("/w/out.txt".into(), "no-model".into())), "the held file, moved away, is still hit by identity");
        assert_eq!(d.hit("/w/other.txt", Some((7, 99))), None, "the file that took the name is not keyed by identity");
    }

    #[test]
    fn an_empty_index_misses_and_must_be_read_first() {
        let d = DerivedIndex::new(100 * S);
        assert_eq!(d.hit("/w/copy.txt", Some((1, 2))), None);
        assert!(d.stale_for(0), "before the first good read every miss is unproven");
        assert_eq!(d.cursor(), (None, 0));
    }

    #[test]
    fn a_label_is_hit_by_path_by_spelling_and_by_identity() {
        let d = DerivedIndex::new(100 * S);
        d.apply(101 * S, "e1", 3, &[("/w/copy.txt".into(), "no-model".into())], |p| {
            assert_eq!(p, "/w/copy.txt");
            (Some("/real/w/copy.txt".into()), Some((7, 42)))
        });
        assert_eq!(d.hit("/w/copy.txt", None), Some(("/w/copy.txt".into(), "no-model".into())));
        assert_eq!(d.hit("/real/w/copy.txt", None), Some(("/w/copy.txt".into(), "no-model".into())));
        // a hard link or a renamed file: another name, the same inode
        assert_eq!(d.hit("/w/c2.txt", Some((7, 42))), Some(("/w/copy.txt".into(), "no-model".into())));
        assert!(d.names("/w/copy.txt", "/real/w/copy.txt"));
        assert!(!d.names("/w/copy.txt", "/w/c2.txt"));
        assert_eq!(d.hit("/w/other.txt", Some((7, 43))), None);
        assert_eq!(d.cursor(), (Some("e1".into()), 3));
    }

    #[test]
    fn a_twin_files_identity_names_the_derived_path_it_stands_for() {
        let d = DerivedIndex::new(100 * S);
        assert_eq!(d.path_of_twin((9, 1)), None);
        d.note_twin_identity((9, 1), "/w/task.output");
        d.note_twin_identity((9, 2), "/w/task.output");
        assert_eq!(d.path_of_twin((9, 1)).as_deref(), Some("/w/task.output"), "a replaced twin still names its file");
        assert_eq!(d.path_of_twin((9, 2)).as_deref(), Some("/w/task.output"));
        assert_eq!(d.path_of_twin((8, 1)), None, "another device's inode is not a twin");
    }

    #[test]
    fn freshness_a_file_changed_since_the_last_read_asks_again() {
        let d = DerivedIndex::new(100 * S);
        d.apply(200 * S, "e1", 1, &[], none);
        assert!(!d.stale_for(150 * S), "changed well before the last read: the list already knew of any label");
        assert!(d.stale_for(199 * S), "inside the slack: ask again");
        assert!(d.stale_for(250 * S), "changed after the last read: ask again");
        assert!(d.fresh_since_start(150 * S));
        assert!(!d.fresh_since_start(50 * S), "older than the guard: the launch's discovery covered it");
    }

    #[test]
    fn the_same_epoch_adds_another_epoch_replaces() {
        let d = DerivedIndex::new(0);
        d.apply(S, "e1", 1, &[("/a".into(), "no-model".into())], none);
        d.apply(2 * S, "e1", 2, &[("/b".into(), "any-model".into())], none);
        assert_eq!(d.len(), 2);
        d.apply(3 * S, "e2", 1, &[("/b".into(), "any-model".into())], none);
        assert_eq!(d.len(), 1, "a restarted arbiter answers every row: what it no longer has is gone");
        assert_eq!(d.hit("/a", None), None);
        assert_eq!(d.cursor(), (Some("e2".into()), 1), "a new epoch's change number is its own (the old epoch's 2 would skip its rows 2..)");
        // within an epoch the number never goes back (two answers in flight)
        d.apply(4 * S, "e2", 5, &[], none);
        d.apply(4 * S, "e2", 3, &[], none);
        assert_eq!(d.cursor(), (Some("e2".into()), 5));
    }

    #[test]
    fn the_labels_below_a_folder_are_listed_by_path_and_spelling() {
        let ix = DerivedIndex::new(0);
        ix.insert("/w/sub/a.txt", "no-model", (None, None));
        ix.insert("/w/sub/deep/b.txt", "no-model", (Some("/real/sub/deep/b.txt".into()), None));
        ix.insert("/w/subway/c.txt", "no-model", (None, None));
        ix.insert("/w/other.txt", "no-model", (Some("/w/sub/link-name.txt".into()), None));
        assert_eq!(
            ix.under("/w/sub"),
            vec![
                ("/w/other.txt".to_string(), "/w/sub/link-name.txt".to_string()),
                ("/w/sub/a.txt".to_string(), "/w/sub/a.txt".to_string()),
                ("/w/sub/deep/b.txt".to_string(), "/w/sub/deep/b.txt".to_string()),
            ]
        );
        assert_eq!(ix.under("/real/sub/"), vec![("/w/sub/deep/b.txt".to_string(), "/real/sub/deep/b.txt".to_string())]);
        assert!(ix.under("/elsewhere").is_empty());
    }

    #[test]
    fn a_level_never_weakens_and_an_unknown_one_is_strictest() {
        let d = DerivedIndex::new(0);
        d.insert("/a", "no-model", (None, None));
        d.insert("/a", "any-model", (None, None));
        assert_eq!(d.hit("/a", None).unwrap().1, "no-model");
        d.insert("/b", "any-model", (None, None));
        d.insert("/b", "something-new", (None, None));
        assert_eq!(d.hit("/b", None).unwrap().1, "something-new");
    }

    #[test]
    fn a_failed_read_backs_off_and_a_good_one_clears_it() {
        let d = DerivedIndex::new(0);
        d.note_failure(10 * S);
        assert!(d.backing_off(10 * S + S / 2));
        assert!(!d.backing_off(12 * S));
        d.apply(13 * S, "e", 0, &[], none);
        assert!(!d.backing_off(13 * S));
    }

    #[test]
    fn twins_are_cached_per_file_state() {
        let d = DerivedIndex::new(0);
        let k = TwinKey { dev: 1, ino: 2, size: 10, mtime_ns: 5 };
        assert_eq!(d.cached_twin("/a", &k), None);
        d.set_twin("/a", k.clone(), "/t/a".into());
        assert_eq!(d.cached_twin("/a", &k), Some("/t/a".into()));
        let changed = TwinKey { size: 11, ..k };
        assert_eq!(d.cached_twin("/a", &changed), None, "the file changed: a new twin is made");
    }

    #[test]
    fn whole_file_twin_text_keeps_the_terminator() {
        assert_eq!(whole_file_twin_text("$MDU:x", None), "$MDU:x\n");
        assert_eq!(whole_file_twin_text("$MDU:x", Some("")), "$MDU:x");
        assert_eq!(whole_file_twin_text("$MDU:x", Some("\r\n")), "$MDU:x\r\n");
        assert_eq!(whole_file_twin_text("$MDU:x", Some("weird")), "$MDU:x\n");
    }

    #[test]
    fn twin_file_names_differ_per_path_and_are_safe() {
        let a = twin_file_name("/w/copy.txt");
        let b = twin_file_name("/v/copy.txt");
        assert_ne!(a, b);
        assert!(a.ends_with("-copy.txt"));
        assert!(!twin_file_name("/w/a b/$x;").contains(['/', ' ', '$', ';']));
    }
}
