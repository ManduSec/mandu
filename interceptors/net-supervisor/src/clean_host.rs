//! clean_host — the guard hosts the command box's clean attempt
//! (exec-routing.md §8.5.3, sandbox-security-review-2026-09-28 finding 4).
//!
//! A clean verdict un-masks a Bash result, so only a reporter outside the
//! agent's process tree may send one. The whole-agent guard is outside it:
//! the launcher starts it, the agent cannot signal, trace or read it. So the
//! command box (inside the tree) asks the guard, over a socket the guard
//! serves in the session run dir, to run the command; the guard runs the box
//! binary the launcher named, with the environment the launcher composed,
//! stdin `/dev/null`, under its own seccomp supervision (a registered secret
//! stays refused there as in any clean attempt), and reports the verdict
//! with the reporter token it claimed from the arbiter before its agent
//! started (`claimCleanReporter`). The requester only receives the bytes.
//!
//! This module is the PURE half: the guard's arguments, the box argv, the
//! report. The sockets and the supervised child are `clean_host_kernel`.
//! `Mandu-new`.

use mandu_arbiter::clean_run::CleanRequest;
use mandu_arbiter::protocol::ExecCleanVerdictReport;

/// `mandu-exec-box --clean-only`: the attempt is void.
pub const EXIT_CLEAN_VOID: i32 = 79;

/// The guard's clean-host arguments, all launcher-given:
/// `--clean-socket <path> --clean-session <key> --clean-box <bin>
/// [--clean-env KEY=VALUE]...`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanHostArgs {
    pub socket: Option<String>,
    pub session: Option<String>,
    pub box_bin: Option<String>,
    pub env: Vec<(String, String)>,
}

/// The complete configuration (`CleanHostArgs::complete`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanHostConfig {
    pub socket: String,
    pub session: String,
    pub box_bin: String,
    pub env: Vec<(String, String)>,
}

impl CleanHostArgs {
    /// Consume `arg` (and its value from `next`) when it is one of ours.
    /// `Ok(false)`: not ours. `Err`: ours but malformed.
    pub fn take(&mut self, arg: &str, next: &mut dyn FnMut() -> Option<String>) -> Result<bool, String> {
        let mut value = |name: &str| next().ok_or_else(|| format!("{name} needs a value"));
        match arg {
            "--clean-socket" => self.socket = Some(value(arg)?),
            "--clean-session" => self.session = Some(value(arg)?),
            "--clean-box" => self.box_bin = Some(value(arg)?),
            "--clean-env" => self.env.push(parse_env_pair(&value(arg)?)?),
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// All three of socket, session and box, or none (no clean host). The
    /// socket and the box must be absolute paths; an empty value is refused.
    pub fn complete(&self) -> Result<Option<CleanHostConfig>, String> {
        match (&self.socket, &self.session, &self.box_bin) {
            (None, None, None) if self.env.is_empty() => Ok(None),
            (Some(sock), Some(session), Some(bin)) => {
                if !sock.starts_with('/') || !bin.starts_with('/') {
                    return Err("--clean-socket and --clean-box must be absolute paths".into());
                }
                if session.is_empty() {
                    return Err("--clean-session must not be empty".into());
                }
                Ok(Some(CleanHostConfig { socket: sock.clone(), session: session.clone(), box_bin: bin.clone(), env: self.env.clone() }))
            }
            _ => Err("--clean-socket, --clean-session and --clean-box go together".into()),
        }
    }
}

/// `KEY=VALUE`, KEY a portable environment name.
pub fn parse_env_pair(s: &str) -> Result<(String, String), String> {
    let (k, v) = s.split_once('=').ok_or_else(|| format!("--clean-env {s:?} is not KEY=VALUE"))?;
    let ok_key = !k.is_empty()
        && !k.as_bytes()[0].is_ascii_digit()
        && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !ok_key || v.contains('\0') {
        return Err(format!("--clean-env {s:?} is not KEY=VALUE"));
    }
    Ok((k.to_string(), v.to_string()))
}

/// What the guard executes for one request: the launcher's box binary in its
/// clean-only mode, the requester's cwd and argv as data.
pub fn box_argv(box_bin: &str, req: &CleanRequest) -> Vec<String> {
    let mut v = vec![box_bin.to_string(), "--clean-only".into(), "--cwd".into(), req.cwd.clone(), "--".into()];
    v.extend(req.argv.iter().cloned());
    v
}

/// The verdict the guard reports for a completed attempt. `proc_key` is the
/// REQUESTER's (the box process in the agent's tree whose lineage the arbiter
/// re-checks), not the hosted child's: the hosted run is a clean function of
/// the command, and the command came from that process.
pub fn hosted_report(call_id: &str, proc_key: Option<String>, output_sha256: &str, session: &str) -> ExecCleanVerdictReport {
    ExecCleanVerdictReport {
        call_id: call_id.to_string(),
        clean: true,
        boxed: Some(true),
        shell: Some("AgentShell".into()),
        proc_key,
        output_sha256: Some(output_sha256.to_string()),
        reason: Some(
            "guard-hosted clean box: run by the session's guard outside the agent's process tree \
             (Landlock read-allow of system roots, AgentView write-only, fresh scratch, net off, stdin /dev/null)"
                .into(),
        ),
        session_key: Some(session.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(args: &[&str]) -> Result<CleanHostArgs, String> {
        let mut a = CleanHostArgs::default();
        let mut it = args.iter().map(|s| s.to_string());
        while let Some(x) = it.next() {
            let mut next = || it.next();
            if !a.take(&x, &mut next)? {
                return Err(format!("not ours: {x}"));
            }
        }
        Ok(a)
    }

    #[test]
    fn the_three_paths_come_together_or_not_at_all() {
        assert_eq!(feed(&[]).unwrap().complete(), Ok(None));
        let full = feed(&["--clean-socket", "/run/s/clean.sock", "--clean-session", "S1", "--clean-box", "/opt/mandu-exec-box", "--clean-env", "MANDU_ARBITER_SOCK=/run/a.sock"]).unwrap();
        let c = full.complete().unwrap().unwrap();
        assert_eq!(c.session, "S1");
        assert_eq!(c.env, vec![("MANDU_ARBITER_SOCK".to_string(), "/run/a.sock".to_string())]);
        assert!(feed(&["--clean-socket", "/run/s/clean.sock"]).unwrap().complete().is_err());
        assert!(feed(&["--clean-env", "A=b"]).unwrap().complete().is_err());
        assert!(feed(&["--clean-socket", "rel.sock", "--clean-session", "S", "--clean-box", "/b"]).unwrap().complete().is_err());
        assert!(feed(&["--clean-socket", "/s", "--clean-session", "", "--clean-box", "/b"]).unwrap().complete().is_err());
        assert!(feed(&["--clean-socket"]).is_err());
    }

    #[test]
    fn an_env_pair_is_a_portable_name_and_a_value() {
        assert_eq!(parse_env_pair("PATH=/usr/bin:/bin"), Ok(("PATH".into(), "/usr/bin:/bin".into())));
        assert_eq!(parse_env_pair("EMPTY="), Ok(("EMPTY".into(), String::new())));
        assert_eq!(parse_env_pair("A_1=x=y"), Ok(("A_1".into(), "x=y".into())));
        for bad in ["NOEQ", "=v", "1A=v", "A-B=v", "A B=v"] {
            assert!(parse_env_pair(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_box_runs_clean_only_with_the_request_as_data() {
        let req = CleanRequest { argv: vec!["cat".into(), "--cwd".into(), "a b".into()], cwd: "/ws".into() };
        assert_eq!(
            box_argv("/opt/box", &req),
            ["/opt/box", "--clean-only", "--cwd", "/ws", "--", "cat", "--cwd", "a b"].map(String::from).to_vec()
        );
    }

    #[test]
    fn the_report_carries_the_requesters_lineage_and_the_guards_session() {
        let r = hosted_report("toolu_1", Some("boot:42".into()), &"c".repeat(64), "S1");
        assert!(r.clean && r.boxed == Some(true));
        assert_eq!(r.shell.as_deref(), Some("AgentShell"));
        assert_eq!(r.proc_key.as_deref(), Some("boot:42"));
        assert_eq!(r.session_key.as_deref(), Some("S1"));
    }
}
