//! clean_run — the wire between the command box and the guard that hosts its
//! clean attempt (exec-routing.md §8.5.3, sandbox-security-review finding 4).
//!
//! The box runs inside the agent's process tree, so it cannot vouch for a run:
//! it asks the session's guard, over a Unix socket the guard serves in the
//! session run dir, to run the command in the clean box. The guard runs it
//! itself (the box binary it was given at launch, a cleared environment,
//! stdin `/dev/null`), reports the verdict with its own reporter token, and
//! answers with the captured bytes. The requester only sees the answer.
//!
//! Framing (both directions on one stream connection):
//!   request: one JSON line `{"argv":[…],"cwd":"…"}`, at most
//!            [`MAX_REQUEST`] bytes;
//!   reply:   one JSON header line (`CleanReply`), then exactly `stdout` bytes
//!            of stdout and `stderr` bytes of stderr.
//!
//! PURE: encoding and parsing only; the sockets live in the two callers.
//! `Mandu-new`.

use serde::{Deserialize, Serialize};

/// The request line cap (argv of a boxed command, plus the cwd).
pub const MAX_REQUEST: usize = 256 * 1024;
/// The reply header cap.
pub const MAX_REPLY_HEADER: usize = 16 * 1024;
/// Per-stream cap on what the guard captures and returns. Above it the
/// attempt is void (the box's own caps are lower; this bounds the guard).
pub const MAX_STREAM: u64 = 32 * 1024 * 1024;

/// One clean-run request: the boxed command and where it runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanRequest {
    pub argv: Vec<String>,
    pub cwd: String,
}

/// The guard's answer. `completed`: the command ran to exit 0 under the clean
/// ruleset and the bytes that follow are its output; otherwise nothing
/// follows and the requester runs the ordinary box (the §4 fallback).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CleanReply {
    pub completed: bool,
    #[serde(default)]
    pub stdout: u64,
    #[serde(default)]
    pub stderr: u64,
    /// The tool_use id the guard resolved (None: no recorded decision).
    #[serde(rename = "callId", default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// What the arbiter resolved the guard's report to.
    #[serde(default)]
    pub clean: bool,
    /// Why the attempt is void, or the arbiter's reason (observability).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Why a request or a header was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    TooLong,
    Malformed(String),
    EmptyArgv,
    RelativeCwd,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::TooLong => write!(f, "line too long"),
            WireError::Malformed(e) => write!(f, "malformed: {e}"),
            WireError::EmptyArgv => write!(f, "empty argv"),
            WireError::RelativeCwd => write!(f, "cwd must be absolute"),
        }
    }
}

/// The request line, newline-terminated.
pub fn encode_request(req: &CleanRequest) -> Vec<u8> {
    let mut v = serde_json::to_vec(req).unwrap_or_default();
    v.push(b'\n');
    v
}

/// Parse one request line (without its newline). An empty argv, a NUL in any
/// string (it could not reach execve intact) and a relative cwd are refused.
pub fn parse_request(line: &[u8]) -> Result<CleanRequest, WireError> {
    if line.len() > MAX_REQUEST {
        return Err(WireError::TooLong);
    }
    let req: CleanRequest = serde_json::from_slice(line).map_err(|e| WireError::Malformed(e.to_string()))?;
    if req.argv.is_empty() || req.argv[0].is_empty() {
        return Err(WireError::EmptyArgv);
    }
    if req.argv.iter().chain(std::iter::once(&req.cwd)).any(|s| s.contains('\0')) {
        return Err(WireError::Malformed("NUL in a string".into()));
    }
    if !req.cwd.starts_with('/') {
        return Err(WireError::RelativeCwd);
    }
    Ok(req)
}

/// The reply header line, newline-terminated.
pub fn encode_reply_header(reply: &CleanReply) -> Vec<u8> {
    let mut v = serde_json::to_vec(reply).unwrap_or_default();
    v.push(b'\n');
    v
}

/// Parse the reply header line (without its newline). A reply that claims
/// more than [`MAX_STREAM`] per stream is refused.
pub fn parse_reply_header(line: &[u8]) -> Result<CleanReply, WireError> {
    if line.len() > MAX_REPLY_HEADER {
        return Err(WireError::TooLong);
    }
    let r: CleanReply = serde_json::from_slice(line).map_err(|e| WireError::Malformed(e.to_string()))?;
    if r.stdout > MAX_STREAM || r.stderr > MAX_STREAM {
        return Err(WireError::TooLong);
    }
    if !r.completed && (r.stdout != 0 || r.stderr != 0) {
        return Err(WireError::Malformed("a void attempt carries no bytes".into()));
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_round_trips_and_ends_in_one_newline() {
        let req = CleanRequest { argv: vec!["cat".into(), "notes.md".into()], cwd: "/ws".into() };
        let line = encode_request(&req);
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(line.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(parse_request(&line[..line.len() - 1]).unwrap(), req);
    }

    #[test]
    fn a_request_the_guard_could_not_run_as_given_is_refused() {
        let bad = |argv: Vec<&str>, cwd: &str| {
            let req = CleanRequest { argv: argv.into_iter().map(String::from).collect(), cwd: cwd.into() };
            let line = encode_request(&req);
            parse_request(&line[..line.len() - 1])
        };
        assert_eq!(bad(vec![], "/ws"), Err(WireError::EmptyArgv));
        assert_eq!(bad(vec![""], "/ws"), Err(WireError::EmptyArgv));
        assert_eq!(bad(vec!["cat"], "ws"), Err(WireError::RelativeCwd));
        assert!(matches!(bad(vec!["ca\0t"], "/ws"), Err(WireError::Malformed(_))));
        assert!(matches!(parse_request(b"{\"argv\":1}"), Err(WireError::Malformed(_))));
        assert_eq!(parse_request(&vec![b' '; MAX_REQUEST + 1]), Err(WireError::TooLong));
    }

    #[test]
    fn a_reply_header_round_trips_and_bounds_what_follows() {
        let r = CleanReply { completed: true, stdout: 12, stderr: 0, call_id: Some("toolu_1".into()), clean: true, reason: String::new() };
        let line = encode_reply_header(&r);
        assert_eq!(parse_reply_header(&line[..line.len() - 1]).unwrap(), r);
        let void = CleanReply { completed: false, reason: "exit 1".into(), ..Default::default() };
        let line = encode_reply_header(&void);
        assert_eq!(parse_reply_header(&line[..line.len() - 1]).unwrap(), void);
        let huge = CleanReply { completed: true, stdout: MAX_STREAM + 1, ..Default::default() };
        let line = encode_reply_header(&huge);
        assert_eq!(parse_reply_header(&line[..line.len() - 1]), Err(WireError::TooLong));
        let liar = CleanReply { completed: false, stdout: 3, ..Default::default() };
        let line = encode_reply_header(&liar);
        assert!(matches!(parse_reply_header(&line[..line.len() - 1]), Err(WireError::Malformed(_))));
    }
}
