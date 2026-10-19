//! diag — where the guard's own non-fatal messages go (packaging.md §5,
//! "Launch display policy", 2026-10-18).
//!
//! The guard's stderr is the agent's terminal. A launch in the default
//! display names its log in `MANDU_LAUNCH_LOG` and says `compact` in
//! `MANDU_LAUNCH_DISPLAY`: then a message goes to that log only, never over
//! the agent's screen. A verbose launch (no `compact`) gets it on stderr AND
//! in the log; a guard run outside a launch (no log named), or one whose log
//! cannot be written, says it on stderr as before. Fatal messages (the guard
//! refuses to run its target) and a degrade said before the agent starts do
//! not come here: they stay on stderr, where the launch shows them.
//!
//! Best-effort: a write that fails falls back to stderr, and nothing on the
//! security path reads the log. The append never follows a link and never
//! writes a FIFO or another file's hard link (`safe_write`): the guard runs
//! unconfined.

/// The env var naming the launch's log file (launcher/src/launch-log.ts).
pub const LAUNCH_LOG_ENV: &str = "MANDU_LAUNCH_LOG";
/// The env var naming the launch's display (`compact` = the default one).
pub const LAUNCH_DISPLAY_ENV: &str = "MANDU_LAUNCH_DISPLAY";

/// Whether a message also goes to stderr: always under a verbose launch,
/// and whenever the log did not take it. Pure.
pub fn also_stderr(compact: bool, logged: bool) -> bool {
    !compact || !logged
}

/// Say `msg` (one line, no newline): to the launch's log, and to stderr as
/// `also_stderr` decides.
pub fn say(msg: &str) {
    let compact = std::env::var(LAUNCH_DISPLAY_ENV).map(|v| v == "compact").unwrap_or(false);
    let log = std::env::var(LAUNCH_LOG_ENV).ok().filter(|p| p.starts_with('/'));
    let logged = log.map(|p| append(&p, msg).is_ok()).unwrap_or(false);
    if also_stderr(compact, logged) {
        eprintln!("{msg}");
    }
}

/// Append `msg` as one line to the log at `path` (absolute).
pub fn append(path: &str, msg: &str) -> std::io::Result<()> {
    crate::safe_write::append_file(path, format!("{}\n", msg.replace(['\n', '\r'], " ")).as_bytes())
}

/// `diag!("…", args)`: `diag::say(&format!(…))`.
#[macro_export]
macro_rules! diag {
    ($($t:tt)*) => { $crate::diag::say(&format!($($t)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_launch_with_a_log_keeps_the_terminal_clear() {
        assert!(!also_stderr(true, true), "default display, logged: the log only");
        assert!(also_stderr(true, false), "the log did not take it: stderr, never lost");
        assert!(also_stderr(false, true), "a verbose launch: stderr too");
        assert!(also_stderr(false, false));
    }

    #[test]
    fn append_writes_one_line_per_message() {
        let dir = std::env::temp_dir().join(format!("diag-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("launch.log");
        let ps = p.to_str().unwrap();
        append(ps, "mandu-net-guard: first").unwrap();
        append(ps, "mandu-net-guard: two\nlines").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "mandu-net-guard: first\nmandu-net-guard: two lines\n");
        // A link at the name is never followed.
        let link = dir.join("link.log");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(append(link.to_str().unwrap(), "x").is_err(), "a link at the name is refused");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
