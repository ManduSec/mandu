//! decision — the PURE openat() routing decision for the FS supervisor.
//!
//! PURE / unit-tested by default. The kernel feature's seccomp-unotify loop reads
//! the openat() arguments (dirfd, path, flags) out of the notified syscall and
//! hands them to `decide_open`; the loop then enacts the returned `OpenDecision`
//! (addfd a rewritten FD + respond CONTINUE-suppressed, or just CONTINUE). All the
//! policy lives HERE so it is testable without the kernel.
//!
//! Routing rule (design §3, mandu.md):
//!   - A path under a TRACKED workspace root → the AgentView worktree. Reads see
//!     symbolized content; writes are captured into AgentView (the sync daemon
//!     reconciles to HumanView).
//!   - A path outside every tracked root → PASSTHROUGH (raw). The supervisor does
//!     not interpose untracked paths.
//!
//! FAIL-CLOSED: if the arbiter is unreachable on the FIRST-TOUCH classify/symbolize
//! of a tracked read, we DO NOT fall back to serving raw HumanView bytes — we keep
//! the redirect to AgentView (where content is already symbolized by the sync
//! daemon) and flag the arbiter miss. Never expose un-symbolized untrusted content
//! to the agent.

use std::path::PathBuf;

use mandu_arbiter::protocol::{
    Boundary, ClassifyRequest, FileTrustArgs, SymbolizeArgs, TaintFileArgs, Trust,
};
use mandu_arbiter::{ArbiterClient, ArbiterError};

use crate::layout::{rewrite_to_worktree, ViewLayout};

/// O_* open-flag bits we care about (subset of fcntl.h). We avoid pulling libc on
/// the default build, so we define the constants we use. These are the
/// Linux/x86-64 values (stable across the common arches we target).
pub const O_WRONLY: i32 = 0o1;
pub const O_RDWR: i32 = 0o2;
pub const O_CREAT: i32 = 0o100;
pub const O_TRUNC: i32 = 0o1000;

/// Access intent derived from the open flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    ReadWrite,
}

impl Access {
    /// Classify O_* flags into a read/write intent.
    pub fn from_flags(flags: i32) -> Access {
        let writes = (flags & O_WRONLY) != 0 || (flags & O_CREAT) != 0 || (flags & O_TRUNC) != 0;
        let reads_too = (flags & O_RDWR) != 0 || (flags & (O_WRONLY)) == 0;
        if (flags & O_RDWR) != 0 {
            Access::ReadWrite
        } else if writes && !reads_too {
            Access::Write
        } else if writes {
            Access::ReadWrite
        } else {
            Access::Read
        }
    }
}

/// What the supervisor should do with one openat().
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenDecision {
    /// Path is untracked → let the kernel open the original path unchanged.
    Passthrough { reason: String },
    /// Path is tracked → open this REWRITTEN path (the AgentView worktree) instead.
    /// `agent_view_path` is what the seccomp loop should `openat` + `addfd`.
    Redirect {
        original: String,
        agent_view_path: String,
        access: Access,
        reason: String,
        /// True iff this is the first touch of this path in the session and the
        /// supervisor should attempt a arbiter classify/symbolize (best-effort
        /// for observability; the redirect itself is unconditional).
        first_touch: bool,
    },
}

impl OpenDecision {
    pub fn is_redirect(&self) -> bool {
        matches!(self, OpenDecision::Redirect { .. })
    }
    pub fn rewritten(&self) -> Option<&str> {
        match self {
            OpenDecision::Redirect { agent_view_path, .. } => Some(agent_view_path),
            _ => None,
        }
    }
}

/// The set of tracked workspaces the supervisor watches. The pure decision only
/// needs the layouts; the kernel loop owns the live set + first-touch memo.
#[derive(Debug, Clone, Default)]
pub struct TrackedRoots {
    layouts: Vec<ViewLayout>,
}

impl TrackedRoots {
    pub fn new() -> Self {
        TrackedRoots { layouts: Vec::new() }
    }

    pub fn with_layouts(layouts: Vec<ViewLayout>) -> Self {
        TrackedRoots { layouts }
    }

    pub fn add(&mut self, layout: ViewLayout) {
        self.layouts.push(layout);
    }

    pub fn is_empty(&self) -> bool {
        self.layouts.is_empty()
    }

    /// Find the layout whose tracked root contains `path` and the rewritten
    /// AgentView path, or `None` if no tracked root matches. Mirrors how the
    /// fs-sync `rewriteToWorktree` short-circuits on the first matching root.
    pub fn match_path(&self, path: &str) -> Option<(&ViewLayout, String)> {
        for l in &self.layouts {
            if let Some(rewritten) = rewrite_to_worktree(l, path) {
                return Some((l, rewritten));
            }
        }
        None
    }
}

/// Resolve an openat (already-canonical absolute `path` + open `flags`) to a pure
/// `OpenDecision`. `first_touch` says whether the caller has seen this path before
/// (the kernel loop tracks this in a set; tests pass it explicitly).
pub fn decide_open(roots: &TrackedRoots, path: &str, flags: i32, first_touch: bool) -> OpenDecision {
    match roots.match_path(path) {
        None => OpenDecision::Passthrough {
            reason: "path outside every tracked workspace root → raw open".into(),
        },
        Some((_layout, agent_view_path)) => {
            let access = Access::from_flags(flags);
            OpenDecision::Redirect {
                original: path.to_string(),
                agent_view_path,
                access,
                reason: format!(
                    "tracked path → AgentView worktree ({})",
                    match access {
                        Access::Read => "read: symbolized content",
                        Access::Write => "write: captured into AgentView",
                        Access::ReadWrite => "read+write: AgentView (sync reconciles)",
                    }
                ),
                first_touch,
            }
        }
    }
}

/// Outcome of the best-effort arbiter first-touch on a tracked READ. This is
/// observability/policy metadata; it NEVER changes the redirect (the redirect to
/// AgentView already enforces the invariant).
#[derive(Debug, Clone)]
pub struct FirstTouch {
    pub trust: Trust,
    pub category: Option<String>,
    pub symbol: Option<String>,
    pub reason: String,
    /// True iff the arbiter call failed → we proceed with the redirect (fail-safe
    /// to AgentView) but flag the miss so the supervisor can record it.
    pub arbiter_miss: bool,
}

/// Best-effort: on first touch of a tracked read, ask the arbiter to classify the
/// content's origin and (if untrusted) allocate a symbol. The CALLER passes the
/// content it read from the AgentView (or a path-derived origin) — we do not read
/// the FS here (purity). Returns metadata for the emitted `fs_action` event.
///
/// FAIL-SAFE: a arbiter error returns `arbiter_miss=true` with a fail-closed
/// UNTRUSTED classification — the supervisor keeps the AgentView redirect. We
/// never downgrade to raw on a arbiter miss.
pub fn first_touch_classify(
    client: &mut ArbiterClient,
    tool: &str,
    origin: &str,
    content_for_symbol: Option<&str>,
) -> FirstTouch {
    let classify = client.classify(&ClassifyRequest {
        tool: tool.to_string(),
        field: None,
        value: content_for_symbol.unwrap_or("").to_string(),
        boundary: Boundary::Filesystem,
        origin: Some(origin.to_string()),
        params: None,
    });

    match classify {
        Ok(res) => {
            // Only allocate a symbol for untrusted content and when we have a
            // value to symbolize.
            let symbol = if res.trust == Trust::Untrusted {
                if let Some(content) = content_for_symbol {
                    match client.symbolize(&SymbolizeArgs {
                        tool: tool.to_string(),
                        value: content.to_string(),
                        field: None,
                        origin: Some(origin.to_string()),
                        ..Default::default()
                    }) {
                        Ok(s) => Some(s.symbol),
                        Err(_) => None, // symbolize miss: redirect still stands
                    }
                } else {
                    None
                }
            } else {
                None
            };
            FirstTouch {
                trust: res.trust,
                category: res.category,
                symbol,
                reason: res.reason,
                arbiter_miss: false,
            }
        }
        Err(e) => fail_closed_first_touch(&e),
    }
}

fn fail_closed_first_touch(e: &ArbiterError) -> FirstTouch {
    FirstTouch {
        trust: Trust::Untrusted,
        category: None,
        symbol: None,
        reason: format!("arbiter unreachable ({e}) → fail-closed UNTRUSTED, keep AgentView redirect"),
        arbiter_miss: true,
    }
}

/// fs INBOUND trust on a read (design §3.3, §2.3): UNTRUSTED if EITHER the path
/// classify OR the file-taint registry says untrusted. Fail-closed — a arbiter
/// error on EITHER call yields UNTRUSTED + `arbiter_miss = true`. When untrusted
/// and `content_for_symbol` is present, allocate a symbol (reuse the symbolize
/// op). PURE re. the FS: the caller passes `content_hash` (hashed on the kernel
/// path) and the content; we never read the filesystem here.
///
/// `path` is the HumanView/relative path passed to `fileTrust`; `origin` is the
/// classify origin hint (conventionally the same path).
pub fn fs_inbound_trust(
    client: &mut ArbiterClient,
    tool: &str,
    origin: &str,
    path: &str,
    content_hash: Option<&str>,
    content_for_symbol: Option<&str>,
) -> FirstTouch {
    // 1. Path classify (data-trust policy). A arbiter error is fail-closed.
    let classify = client.classify(&ClassifyRequest {
        tool: tool.to_string(),
        field: None,
        value: content_for_symbol.unwrap_or("").to_string(),
        boundary: Boundary::Filesystem,
        origin: Some(origin.to_string()),
        params: None,
    });
    let (classify_untrusted, classify_miss, mut category, mut reason) = match classify {
        Ok(res) => (
            res.trust == Trust::Untrusted,
            false,
            res.category,
            res.reason,
        ),
        Err(e) => (
            true,
            true,
            None,
            format!("classify arbiter miss ({e}) → fail-closed UNTRUSTED"),
        ),
    };

    // 2. File-taint registry lookup. A arbiter error is fail-closed.
    let file_trust = client.file_trust(&FileTrustArgs {
        content_hash: content_hash.map(|s| s.to_string()),
        path: Some(path.to_string()),
    });
    let (taint_untrusted, taint_miss, taint_origin) = match file_trust {
        Ok(r) => (r.untrusted, false, r.origin),
        Err(e) => {
            reason = format!("{reason}; fileTrust arbiter miss ({e}) → fail-closed UNTRUSTED");
            (true, true, None)
        }
    };

    let untrusted = classify_untrusted || taint_untrusted;
    let arbiter_miss = classify_miss || taint_miss;
    if taint_untrusted {
        if let Some(o) = taint_origin {
            category = category.or(Some("TAINT".into()));
            reason = format!("{reason}; file-taint hit origin={o}");
        }
    }

    // 3. Symbolize untrusted content if we were given a value. A symbolize miss
    //    leaves the verdict UNTRUSTED (the redirect still stands) — never raw.
    let symbol = if untrusted {
        if let Some(content) = content_for_symbol {
            match client.symbolize(&SymbolizeArgs {
                tool: tool.to_string(),
                value: content.to_string(),
                field: None,
                origin: Some(origin.to_string()),
                ..Default::default()
            }) {
                Ok(s) => Some(s.symbol),
                Err(_) => None,
            }
        } else {
            None
        }
    } else {
        None
    };

    FirstTouch {
        trust: if untrusted {
            Trust::Untrusted
        } else {
            Trust::Trusted
        },
        category,
        symbol,
        reason,
        arbiter_miss,
    }
}

/// fs OUTBOUND taint on a write (design §3.1, §3.2): if the writing process is
/// tainted, record `taintFile` so a later read of this content is recognized as
/// untrusted-by-origin. Returns true iff the file was tainted.
///
/// FAIL-CLOSED: if `is_process_tainted` errors (arbiter unreachable), we cannot
/// determine the writer's provenance — be conservative and TREAT THE WRITER AS
/// TAINTED, taint the file, and report true. (A write whose origin we can't
/// determine is assumed untrusted; never silently skip.)
pub fn record_file_taint_if_tainted(
    client: &mut ArbiterClient,
    writer_proc_key: &str,
    content_hash: &str,
    path: &str,
    origin_host: &str,
) -> bool {
    let tainted = match client.is_process_tainted(writer_proc_key) {
        Ok(r) => r.tainted,
        Err(_) => true, // fail-closed: unknown provenance → assume tainted
    };
    if !tainted {
        return false;
    }
    // Best-effort taint record. A taintFile error does not change the verdict —
    // we still report the conservative tainted=true to the caller.
    let _ = client.taint_file(&TaintFileArgs {
        content_hash: content_hash.to_string(),
        path: path.to_string(),
        origin_host: origin_host.to_string(),
        writer_proc: Some(writer_proc_key.to_string()),
        session: None,
    });
    true
}

/// The session-scoped first-touch memo the kernel loop owns (so `decide_open`
/// stays pure). Pulled out so it is also unit-testable.
#[derive(Debug, Default)]
pub struct FirstTouchSet {
    seen: std::collections::HashSet<String>,
}

impl FirstTouchSet {
    pub fn new() -> Self {
        Self::default()
    }
    /// Record `path`; return true iff this was the FIRST time we saw it.
    pub fn touch(&mut self, path: &str) -> bool {
        self.seen.insert(path.to_string())
    }
    pub fn contains(&self, path: &str) -> bool {
        self.seen.contains(path)
    }
}

/// Helper for the kernel loop: the AgentView path a redirect would `openat`,
/// as an owned PathBuf (parity with the layout helpers).
pub fn redirect_target(decision: &OpenDecision) -> Option<PathBuf> {
    decision.rewritten().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mandu_arbiter::mock::{op_handler, MockArbiter};

    fn roots() -> TrackedRoots {
        TrackedRoots::with_layouts(vec![ViewLayout::new("/home/u/proj", "/state")])
    }

    #[test]
    fn access_from_flags() {
        assert_eq!(Access::from_flags(0), Access::Read); // O_RDONLY
        assert_eq!(Access::from_flags(O_WRONLY), Access::Write);
        assert_eq!(Access::from_flags(O_RDWR), Access::ReadWrite);
        // O_WRONLY|O_CREAT is a write.
        assert_eq!(Access::from_flags(O_WRONLY | O_CREAT), Access::Write);
    }

    #[test]
    fn tracked_read_redirects_to_agentview() {
        let d = decide_open(&roots(), "/home/u/proj/secret.txt", 0, true);
        assert!(d.is_redirect());
        assert_eq!(
            d.rewritten().unwrap(),
            "/state/workspaces/proj-9c09f8055a26/agentview/secret.txt"
        );
        match d {
            OpenDecision::Redirect { access, first_touch, .. } => {
                assert_eq!(access, Access::Read);
                assert!(first_touch);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn untracked_path_passes_through() {
        let d = decide_open(&roots(), "/etc/passwd", 0, true);
        assert!(!d.is_redirect());
        matches!(d, OpenDecision::Passthrough { .. });
    }

    #[test]
    fn no_tracked_roots_means_passthrough() {
        let d = decide_open(&TrackedRoots::new(), "/home/u/proj/x", 0, true);
        matches!(d, OpenDecision::Passthrough { .. });
    }

    #[test]
    fn write_to_tracked_path_is_captured_into_agentview() {
        let d = decide_open(&roots(), "/home/u/proj/out.txt", O_WRONLY | O_CREAT, false);
        match d {
            OpenDecision::Redirect { access, .. } => assert_eq!(access, Access::Write),
            _ => panic!("expected redirect"),
        }
        // Still redirected — writes go to AgentView, never the raw HumanView path.
        assert!(d.rewritten().unwrap().contains("/agentview/"));
    }

    #[test]
    fn first_touch_set_dedups() {
        let mut set = FirstTouchSet::new();
        assert!(set.touch("/a"));
        assert!(!set.touch("/a"));
        assert!(set.contains("/a"));
        assert!(set.touch("/b"));
    }

    #[test]
    fn first_touch_classify_untrusted_allocates_symbol() {
        let arbiter = MockArbiter::start(op_handler(|op, _req| match op {
            "classify" => Ok(serde_json::json!({
                "trust": "UNTRUSTED", "category": "DIR", "reason": "origin rule"
            })),
            "symbolize" => Ok(serde_json::json!({ "symbol": "$MDU:Read[ab12].v" })),
            _ => Err("nope".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let ft = first_touch_classify(&mut c, "Read", "/home/u/proj/secret.txt", Some("evil text"));
        assert_eq!(ft.trust, Trust::Untrusted);
        assert_eq!(ft.symbol.as_deref(), Some("$MDU:Read[ab12].v"));
        assert!(!ft.arbiter_miss);
    }

    #[test]
    fn first_touch_classify_trusted_skips_symbol() {
        let arbiter = MockArbiter::start(op_handler(|op, _req| match op {
            "classify" => Ok(serde_json::json!({
                "trust": "TRUSTED", "category": null, "reason": "trusted origin"
            })),
            _ => Err("should not symbolize".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let ft = first_touch_classify(&mut c, "Read", "/home/u/proj/safe.txt", Some("hello"));
        assert_eq!(ft.trust, Trust::Trusted);
        assert!(ft.symbol.is_none());
        assert!(!ft.arbiter_miss);
    }

    #[test]
    fn first_touch_classify_arbiter_miss_is_fail_closed() {
        // No arbiter running → connect fails → fail-closed UNTRUSTED + arbiter_miss.
        let mut c = ArbiterClient::new("/nonexistent/mandu.sock");
        let ft = first_touch_classify(&mut c, "Read", "/home/u/proj/x", Some("data"));
        assert_eq!(ft.trust, Trust::Untrusted);
        assert!(ft.arbiter_miss);
        assert!(ft.symbol.is_none());
    }

    // ── fs_inbound_trust: classify ∪ fileTrust (fail-closed) ────────────────────

    #[test]
    fn fs_inbound_trust_untrusted_when_classify_trusted_but_filetrust_untrusted() {
        let arbiter = MockArbiter::start(op_handler(|op, _req| match op {
            "classify" => Ok(serde_json::json!({
                "trust": "TRUSTED", "category": null, "reason": "trusted origin"
            })),
            "fileTrust" => Ok(serde_json::json!({ "untrusted": true, "origin": "example.test" })),
            "symbolize" => Ok(serde_json::json!({ "symbol": "$MDU:Read[ab12].v" })),
            _ => Err("nope".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let ft = fs_inbound_trust(
            &mut c,
            "Read",
            "/home/u/proj/setup.md",
            "/home/u/proj/setup.md",
            Some("h1"),
            Some("evil text"),
        );
        assert_eq!(ft.trust, Trust::Untrusted);
        assert_eq!(ft.symbol.as_deref(), Some("$MDU:Read[ab12].v"));
        assert!(!ft.arbiter_miss);
    }

    #[test]
    fn fs_inbound_trust_untrusted_when_classify_alone_untrusted() {
        let arbiter = MockArbiter::start(op_handler(|op, _req| match op {
            "classify" => Ok(serde_json::json!({
                "trust": "UNTRUSTED", "category": "DIR", "reason": "origin rule"
            })),
            "fileTrust" => Ok(serde_json::json!({ "untrusted": false })),
            "symbolize" => Ok(serde_json::json!({ "symbol": "$MDU:Read[cd34].v" })),
            _ => Err("nope".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let ft = fs_inbound_trust(
            &mut c,
            "Read",
            "/home/u/proj/x",
            "/home/u/proj/x",
            Some("h2"),
            Some("data"),
        );
        assert_eq!(ft.trust, Trust::Untrusted);
        assert_eq!(ft.symbol.as_deref(), Some("$MDU:Read[cd34].v"));
        assert!(!ft.arbiter_miss);
    }

    #[test]
    fn fs_inbound_trust_trusted_when_both_trusted() {
        let arbiter = MockArbiter::start(op_handler(|op, _req| match op {
            "classify" => Ok(serde_json::json!({
                "trust": "TRUSTED", "category": null, "reason": "trusted origin"
            })),
            "fileTrust" => Ok(serde_json::json!({ "untrusted": false })),
            _ => Err("should not symbolize".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let ft = fs_inbound_trust(
            &mut c,
            "Read",
            "/home/u/proj/safe.txt",
            "/home/u/proj/safe.txt",
            Some("h3"),
            Some("hello"),
        );
        assert_eq!(ft.trust, Trust::Trusted);
        assert!(ft.symbol.is_none());
        assert!(!ft.arbiter_miss);
    }

    #[test]
    fn fs_inbound_trust_fail_closed_on_arbiter_miss() {
        // No arbiter → classify connect fails → fail-closed UNTRUSTED + arbiter_miss.
        let mut c = ArbiterClient::new("/nonexistent/mandu.sock");
        let ft = fs_inbound_trust(
            &mut c,
            "Read",
            "/home/u/proj/x",
            "/home/u/proj/x",
            Some("h4"),
            Some("data"),
        );
        assert_eq!(ft.trust, Trust::Untrusted);
        assert!(ft.arbiter_miss);
        assert!(ft.symbol.is_none());
    }

    // ── record_file_taint_if_tainted: taint-the-file when the writer is tainted ──

    #[test]
    fn record_file_taint_when_writer_tainted() {
        let arbiter = MockArbiter::start(op_handler(|op, _req| match op {
            "isProcessTainted" => Ok(serde_json::json!({ "tainted": true, "originHost": "evil.example" })),
            "taintFile" => Ok(serde_json::json!({ "ok": true })),
            _ => Err("nope".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let tainted = record_file_taint_if_tainted(
            &mut c,
            "curl-2",
            "h1",
            "/home/u/proj/setup.md",
            "evil.example",
        );
        assert!(tainted);
    }

    #[test]
    fn record_file_taint_skipped_when_writer_clean() {
        let arbiter = MockArbiter::start(op_handler(|op, _req| match op {
            "isProcessTainted" => Ok(serde_json::json!({ "tainted": false })),
            "taintFile" => Err("taintFile must NOT be called for a clean writer".into()),
            _ => Err("nope".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let tainted = record_file_taint_if_tainted(
            &mut c,
            "vim-7",
            "h2",
            "/home/u/proj/notes.md",
            "n/a",
        );
        assert!(!tainted);
    }

    #[test]
    fn record_file_taint_fail_closed_on_arbiter_miss() {
        // No arbiter → is_process_tainted errors → conservative: treat as tainted
        // and taint the file (a write whose provenance we cannot determine is
        // assumed untrusted). The taintFile call also fails, but the function
        // still REPORTS tainted=true so the caller records the conservative verdict.
        let mut c = ArbiterClient::new("/nonexistent/mandu.sock");
        let tainted = record_file_taint_if_tainted(
            &mut c,
            "ghost-1",
            "h3",
            "/home/u/proj/x",
            "unknown",
        );
        assert!(tainted);
    }

    /// A wedged arbiter (connected, never answering), the case the kernel
    /// loop's write-taint hook meets while the agent's NEXT open waits on the
    /// loop: the provenance question gives up at the client's deadline and
    /// takes the miss branch (tainted). Before 2026-10-17 it waited for good.
    #[test]
    fn record_file_taint_fail_closed_on_a_wedged_arbiter() {
        let limit = std::time::Duration::from_millis(200);
        let arbiter = mandu_arbiter::mock::StallingArbiter::wedged();
        let mut c = ArbiterClient::new(&arbiter.socket_path).with_io_timeout(Some(limit));
        let t0 = std::time::Instant::now();
        let tainted = record_file_taint_if_tainted(&mut c, "ghost-1", "h3", "/home/u/proj/x", "unknown");
        assert!(tainted);
        // isProcessTainted, then taintFile on a fresh connection: two deadlines.
        assert!(t0.elapsed() < limit * 10, "the hook waited {:?}", t0.elapsed());
        let mut seen = arbiter.requests_after(2); // each connection's thread reads in its own time
        seen.sort();
        assert_eq!(seen, vec![(1, "isProcessTainted".to_string()), (2, "taintFile".to_string())]);
    }
}
