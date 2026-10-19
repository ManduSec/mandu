//! mirror_records — when the Landlock mirror forgets the records of tasks
//! that are gone (confidentiality-plan-10-flow-taint.md §4.1a, "The mirror's
//! records over a session").
//!
//! The mirror (`landlock_mirror`) keeps a record per task it has looked up,
//! keyed by proc key (`${pid}-${starttime}`): the mirrored domain the task is
//! in, or none. A record holds its domain, and a domain holds its mirror
//! threads and its copied ruleset descriptors, so a record left behind by a
//! task that exited keeps a thread and descriptors alive in the guard. Every
//! boxed command restricts itself once (the box's applier), so before this
//! module the guard grew a thread per boxed command until the map reached
//! 4096 records: about 500 threads, and every boxed command (whose new
//! namespaces get a context helper, forked from the guard) slowed from about
//! 80 to 130 ms over a few hundred of them.
//!
//! The sweep now runs when the map holds twice what the last sweep left (and
//! at least `MIN_SWEEP`): each record is looked at about twice over its life
//! (amortized O(1) reads of `/proc` per record added), and the records of
//! gone tasks number at most `MIN_SWEEP` plus twice the live ones.
//!
//! WHY FORGETTING IS SAFE: a record is dropped only when its key names no
//! live task (the process is gone, or its pid now names another process: the
//! start time differs). A lookup (`domain_of`) starts from a live task's own
//! key and walks its live parent links, so a gone task's key is never looked
//! up again; dropping its record changes no answer. A live task's domain
//! stays held by its own record or its pid namespace's record.
//!
//! Pure (no `/proc` reads of its own: the caller passes the liveness test).
//! `Mandu-new`.

use std::collections::HashMap;

/// The fewest records worth a sweep (a sweep reads `/proc` once a record).
pub const MIN_SWEEP: usize = 64;

/// When a map of per-task records is next swept: once it holds twice what
/// the last sweep left, and at least `MIN_SWEEP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepSchedule {
    next: usize,
}

impl Default for SweepSchedule {
    fn default() -> Self {
        SweepSchedule { next: MIN_SWEEP }
    }
}

impl SweepSchedule {
    /// Is a map of `len` records due a sweep?
    pub fn due(&self, len: usize) -> bool {
        len >= self.next
    }

    /// A sweep left `left` records: the next one is due at twice that.
    pub fn swept(&mut self, left: usize) {
        self.next = MIN_SWEEP.max(left.saturating_mul(2));
    }

    /// The size the next sweep is due at (tests, diagnostics).
    pub fn next(&self) -> usize {
        self.next
    }
}

/// Does `key` (`${pid}-${starttime}`) still name a live task? `key_of` reads
/// the current key of a pid (None: no such process). A key of another shape
/// names nothing live.
pub fn key_is_live(key: &str, key_of: impl Fn(i32) -> Option<String>) -> bool {
    let pid: i32 = key.split('-').next().and_then(|p| p.parse().ok()).unwrap_or(0);
    pid > 0 && key_of(pid).as_deref() == Some(key)
}

/// If `records` is due a sweep, drop every record whose key `live` says
/// names no live task. Returns how many were dropped.
pub fn sweep_gone<V>(records: &mut HashMap<String, V>, schedule: &mut SweepSchedule, live: impl Fn(&str) -> bool) -> usize {
    if !schedule.due(records.len()) {
        return 0;
    }
    let before = records.len();
    records.retain(|k, _| live(k));
    schedule.swept(records.len());
    before - records.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashSet;

    #[test]
    fn a_sweep_is_due_at_twice_what_the_last_one_left_and_never_below_the_floor() {
        let mut s = SweepSchedule::default();
        assert!(!s.due(MIN_SWEEP - 1));
        assert!(s.due(MIN_SWEEP));
        s.swept(10);
        assert_eq!(s.next(), MIN_SWEEP, "a small live set keeps the floor");
        s.swept(500);
        assert_eq!(s.next(), 1000);
        assert!(!s.due(999) && s.due(1000));
        s.swept(0);
        assert_eq!(s.next(), MIN_SWEEP);
    }

    #[test]
    fn only_the_records_of_gone_tasks_are_dropped() {
        let live: HashSet<&str> = ["10-100", "11-110"].into_iter().collect();
        let mut m: HashMap<String, u32> = HashMap::new();
        for i in 0..MIN_SWEEP as u32 {
            m.insert(format!("{}-{}", 1000 + i, 5), i);
        }
        m.insert("10-100".into(), 1);
        m.insert("11-110".into(), 2);
        let mut s = SweepSchedule::default();
        let dropped = sweep_gone(&mut m, &mut s, |k| live.contains(k));
        assert_eq!(dropped, MIN_SWEEP);
        let mut left: Vec<&String> = m.keys().collect();
        left.sort();
        assert_eq!(left, ["10-100", "11-110"]);
        // Not due again until the floor: nothing is read.
        let reads = Cell::new(0);
        m.insert("12-1".into(), 3);
        assert_eq!(sweep_gone(&mut m, &mut s, |_| { reads.set(reads.get() + 1); false }), 0);
        assert_eq!(reads.get(), 0);
    }

    #[test]
    fn a_reused_pid_is_another_task_and_a_gone_one_is_none() {
        let key_of = |pid: i32| match pid {
            10 => Some("10-999".to_string()), // pid 10 now names another process
            11 => Some("11-110".to_string()),
            _ => None,
        };
        assert!(!key_is_live("10-100", key_of), "reused pid");
        assert!(key_is_live("11-110", key_of));
        assert!(!key_is_live("12-120", key_of), "gone");
        for k in ["", "x-1", "0-1", "-3", "11"] {
            assert!(!key_is_live(k, key_of), "{k:?}");
        }
    }

    /// The cost bound: over any run of inserts (a churn of short-lived tasks
    /// with a few live ones), the liveness reads stay within two per insert
    /// plus the floor, and the records never exceed the floor plus twice the
    /// live set by more than the inserts since the last sweep.
    #[test]
    fn sweeping_costs_about_two_reads_per_record_added_and_keeps_the_map_bounded() {
        let mut m: HashMap<String, ()> = HashMap::new();
        let mut s = SweepSchedule::default();
        let reads = Cell::new(0usize);
        let mut live: HashSet<String> = HashSet::new();
        let mut max_len = 0;
        let inserts = 100_000;
        for i in 0..inserts {
            let k = format!("{}-{}", i + 2, i);
            m.insert(k.clone(), ());
            // Every 50th task stays alive for a while; the others exit at once.
            if i % 50 == 0 {
                live.insert(k);
            }
            if i % 5000 == 0 {
                live.clear(); // a wave of long-lived tasks ends
            }
            sweep_gone(&mut m, &mut s, |k| {
                reads.set(reads.get() + 1);
                live.contains(k)
            });
            max_len = max_len.max(m.len());
        }
        assert!(reads.get() <= 2 * inserts + MIN_SWEEP, "reads {} for {inserts} inserts", reads.get());
        assert!(max_len <= MIN_SWEEP.max(2 * 100) + 1, "the map peaked at {max_len}");
    }
}
