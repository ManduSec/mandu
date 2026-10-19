//! child_status — the exit code the guard reports for the tree it served
//! (`mandu-net-guard`, rootless-confinement-ubuntu-2404.md §12.2).
//!
//! The guard exits with its child's status so the launcher, and the human's
//! shell behind it, see the agent's own. A child that exited reports its code;
//! a child a signal killed reports 128 + the signal number, as a shell does
//! and as the launcher does for its own children (`launcher/src/spawn.ts`).
//! Until 2026-10-07 a signal death was reported as 126, the code the crate
//! keeps for "exec failed": a claude ended by SIGINT during its own exit
//! looked like a launch that never ran (docs/testing/differential-interactive.md
//! §21.2).
//!
//! `Mandu-new`.

/// The shell's exit code for a `waitpid` status: the code of a child that
/// exited, 128 + the signal of one a signal killed, `None` for anything else
/// (a stopped or continued child is not an end).
pub fn shell_code(status: i32) -> Option<i32> {
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Some(128 + libc::WTERMSIG(status))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::shell_code;

    #[test]
    fn an_exit_reports_its_code() {
        assert_eq!(shell_code(0), Some(0));
        assert_eq!(shell_code(3 << 8), Some(3));
        assert_eq!(shell_code(126 << 8), Some(126), "a child's own 126 passes through");
    }

    #[test]
    fn a_signal_death_reports_128_plus_the_signal() {
        assert_eq!(shell_code(libc::SIGINT), Some(130), "not the exec-failure 126");
        assert_eq!(shell_code(libc::SIGKILL), Some(137));
        assert_eq!(shell_code(libc::SIGTERM | 0x80), Some(143), "a core dump changes nothing");
    }

    #[test]
    fn a_stop_is_not_an_end() {
        assert_eq!(shell_code((libc::SIGSTOP << 8) | 0x7f), None);
        assert_eq!(shell_code(0xffff), None, "continued");
    }
}
