//! guard_trace — the guard's own diagnostic trace, off by default.
//!
//! `MANDU_NET_GUARD_TRACE=<file>` appends one line per event to that file:
//! which process the guard took as the agent (and the candidates it chose
//! from), why a process first became a holder, and each connect the taint
//! leg refused with the agent set it was judged against. A file, not stderr:
//! the guard's stderr is the agent's terminal. Best-effort: a write that
//! fails is dropped, and nothing on the security path reads it
//! (confidentiality-plan-13-reader-set-labels.md §4.5.1, "Tracing the
//! agent pick").

use std::path::Path;

/// The env var naming the trace file.
pub const TRACE_ENV: &str = "MANDU_NET_GUARD_TRACE";

/// Append `msg()` to the trace file when `TRACE_ENV` names one; `msg` is not
/// built otherwise.
pub fn trace(msg: impl FnOnce() -> String) {
    if let Some(path) = std::env::var_os(TRACE_ENV).filter(|p| !p.is_empty()) {
        let _ = append(Path::new(&path), &msg());
    }
}

/// One trace line: milliseconds since the epoch, the guard's pid, the
/// message on one line.
pub fn line(millis: u128, pid: u32, msg: &str) -> String {
    format!("{millis} guard[{pid}] {}\n", msg.replace(['\n', '\r'], " "))
}

/// Append one line for `msg` to `path` (created 0600 when missing; a
/// relative path is the guard's working directory's), never through a link
/// on the way or at the name, a FIFO or a hard link to another file
/// (`safe_write`, 2026-10-17: the guard runs unconfined, and the agent may
/// write where a trace was pointed).
pub fn append(path: &Path, msg: &str) -> std::io::Result<()> {
    let millis = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let abs = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
    let p = abs.to_str().ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    crate::safe_write::append_file(p, line(millis, std::process::id(), msg).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_one_line_with_time_and_pid() {
        assert_eq!(line(12, 34, "agent pick: a\nb"), "12 guard[34] agent pick: a b\n");
    }

    #[test]
    fn append_adds_lines_to_the_file() {
        let dir = std::env::temp_dir().join(format!("guard-trace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let f = dir.join("trace.txt");
        let _ = std::fs::remove_file(&f);
        append(&f, "one").unwrap();
        append(&f, "two").unwrap();
        let text = std::fs::read_to_string(&f).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with(" one") && lines[1].ends_with(" two"), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unwritable_path_is_an_error_not_a_panic() {
        assert!(append(Path::new("/nonexistent-dir/x/trace.txt"), "m").is_err());
    }
}
