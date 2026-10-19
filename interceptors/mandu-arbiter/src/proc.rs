//! proc — the ONE cross-layer process-key format for the taint registry.
//!
//! PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code. It STANDARDIZES the key
//! the TS `exec-wrap/src/lineage.ts::provisionalProcKey` already emits
//! (`${pid}-${starttime}`) so the net / fs / exec chokepoints all produce + consume
//! a byte-identical key — `taintProcess` from net, `processLineage` child from exec,
//! and `taintFile.writer_proc` from fs correlate to the SAME string for the SAME
//! process (design §2: `process_taint.proc_key = pid + start-time`; start-time
//! defeats pid reuse).
//!
//! PRIVILEGE-FREE: `proc_key_from` is pure; `read_starttime` reads
//! `/proc/<pid>/stat` field 22, which is world-readable — no root, no `kernel`
//! feature. The kernel-feature chokepoint paths call these to build a real key from
//! a pid they already hold (the connecting pid, the fork child pid, the seccomp-
//! trapped pid). The cross-layer FORMAT lives here so there is exactly ONE source
//! of truth; the per-chokepoint ATTRIBUTION (which pid) lives in each crate.

/// Format a process key from a pid + its start-time in clock ticks. This is the
/// canonical cross-layer key — `${pid}-${starttime}` — byte-for-byte identical to
/// the TS `provisionalProcKey`. NO unit conversion: `starttime` is the raw integer
/// from `/proc/<pid>/stat` field 22 (clock ticks since boot).
pub fn proc_key_from(pid: i32, starttime_ticks: u64) -> String {
    format!("{pid}-{starttime_ticks}")
}

/// Parse field 22 (starttime, clock ticks) out of a `/proc/<pid>/stat` LINE.
/// PURE — no I/O; takes the already-read line so it is testable on a fixture.
///
/// `/proc/<pid>/stat` is: `pid (comm) state ppid pgrp ... starttime ...`. The
/// `comm` field (2nd) is wrapped in parens and MAY itself contain spaces and
/// parens, so we anchor on the LAST `')'` and parse the space-separated fields
/// AFTER it. In that post-comm remainder, `state` is field #3 overall (index 0),
/// so `starttime` (field #22 overall) is index 19. Returns `None` if the line has
/// no `')'`, is truncated, or field 22 does not parse as an integer.
pub fn parse_starttime_from_stat(stat_line: &str) -> Option<u64> {
    let close = stat_line.rfind(')')?;
    // Skip the ')' and the single space after it; split the rest on whitespace.
    let after = stat_line.get(close + 1..)?.trim_start();
    let mut fields = after.split_whitespace();
    // index 0 = state ... index 19 = starttime (field 22 overall).
    let starttime = fields.nth(19)?;
    starttime.parse::<u64>().ok()
}

/// Read `/proc/<pid>/stat` and return its start-time (clock ticks). Privilege-free
/// (`/proc/<pid>/stat` is world-readable). `None` on any read/parse failure (the
/// caller — a best-effort, off-the-security-path emitter — then skips the tag).
pub fn read_starttime(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_starttime_from_stat(&stat)
}

/// Convenience: build the full proc key for `pid` by reading its start-time.
/// `None` if the stat read/parse fails (the caller skips the tag, fail-quiet —
/// emission is off the security path).
pub fn proc_key_for_pid(pid: i32) -> Option<String> {
    Some(proc_key_from(pid, read_starttime(pid)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_key_format_is_pid_dash_starttime() {
        // The ONE cross-layer format. Byte-for-byte identical to the TS
        // exec-wrap provisionalProcKey output for the same inputs.
        assert_eq!(proc_key_from(1234, 9), "1234-9");
        assert_eq!(proc_key_from(2, 56789012), "2-56789012");
    }

    #[test]
    fn parse_starttime_handles_comm_with_spaces_and_parens() {
        // /proc/<pid>/stat: "pid (comm) state ppid ... starttime(=field 22) ...".
        // comm can contain spaces AND parens, so we split AFTER the last ')'.
        // Field 22 overall = index 19 of the post-')'-space remainder (state is
        // index 0 there). Synthetic line: 24 fields after the comm, starttime=9999.
        let line = "1234 (my (weird) proc) S 1 1234 1234 0 -1 4194304 \
                    100 0 0 0 10 5 0 0 20 0 1 0 9999 12345678 0 0 0";
        assert_eq!(parse_starttime_from_stat(line), Some(9999));
    }

    #[test]
    fn parse_starttime_simple_comm() {
        let line = "42 (cat) R 7 42 7 34816 42 4194304 \
                    90 0 0 0 1 0 0 0 20 0 1 0 555 4096 0 0 0";
        assert_eq!(parse_starttime_from_stat(line), Some(555));
    }

    #[test]
    fn parse_starttime_rejects_garbage() {
        assert_eq!(parse_starttime_from_stat(""), None);
        assert_eq!(parse_starttime_from_stat("no parens here"), None);
        // A line with too few post-comm fields → None (no field 22).
        assert_eq!(parse_starttime_from_stat("1 (x) S 2 3"), None);
    }

    #[test]
    fn read_starttime_of_self_is_some_and_key_roundtrips() {
        // Privilege-free: /proc/self/stat field 22 is world-readable.
        let pid = std::process::id();
        let st = read_starttime(pid as i32).expect("self starttime readable");
        let key = proc_key_from(pid as i32, st);
        assert_eq!(key, format!("{pid}-{st}"));
        assert!(key.contains('-'));
    }
}
