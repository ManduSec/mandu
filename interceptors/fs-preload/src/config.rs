//! config — PURE env/config parsing + the path-rewrite decision wrapper.
//!
//! Provenance: this module ADAPTS the redirect semantics of
//! `interceptors/fs-supervisor/src/decision.rs` (`decide_open`, `TrackedRoots`)
//! and `.../src/layout.rs` (`ViewLayout`, `rewrite_to_worktree`). Per the repo
//! convention "Reuse, don't rewrite", we do NOT reimplement the tracked-root
//! matching or the AgentView path math — we build the SAME `TrackedRoots` the
//! seccomp supervisor uses and call the SAME `decide_open`. The only thing this
//! crate adds is the *transport*: an unprivileged LD_PRELOAD interposer instead of
//! the kernel-≥5.9 seccomp-ADDFD redirect (see docs/design/architecture/privilege-model.md §3.2:
//! on kernels < 5.9 the ADDFD ioctl is unavailable, so the FS two-views use
//! LD_PRELOAD / FUSE instead).
//!
//! PURE: no syscalls beyond reading process env; unit-tested by default.

use std::path::PathBuf;

use fs_supervisor::decision::{decide_open, OpenDecision, TrackedRoots};
use fs_supervisor::layout::ViewLayout;

/// Env var: colon-separated list of CANONICAL absolute tracked-workspace roots
/// (HumanView paths). A file open under any of these is redirected to AgentView.
/// Example: `MANDU_PRELOAD_WORKSPACE=/home/u/proj:/home/u/other`.
pub const ENV_WORKSPACE: &str = "MANDU_PRELOAD_WORKSPACE";

/// Env var: the view **state base** (mirrors fs-sync `defaultStateBase`,
/// normally `$HOME/.mandu`). The AgentView worktree for a workspace lives at
/// `<state-base>/workspaces/<basename>-<sha256(root)[:12]>/agentview/`. We reuse
/// `ViewLayout` so the LD_PRELOAD redirect lands on the EXACT same worktree
/// path the fs-sync daemon and the seccomp supervisor compute.
/// Example: `MANDU_PRELOAD_AGENTVIEW=/home/u/.mandu`.
pub const ENV_AGENTVIEW: &str = "MANDU_PRELOAD_AGENTVIEW";

/// Env var (optional): set to `1`/`true` to print one line per redirect/passthrough
/// to stderr. Off by default so the interposer is silent on the hot path.
pub const ENV_DEBUG: &str = "MANDU_PRELOAD_DEBUG";

/// Resolved, immutable interposer config: the tracked roots (already turned into
/// the fs-supervisor `TrackedRoots`) + the debug flag.
#[derive(Debug, Clone)]
pub struct Config {
    roots: TrackedRoots,
    pub debug: bool,
}

impl Config {
    /// Build a `Config` from explicit values (used by tests and by `from_env`).
    /// `workspace_roots` are CANONICAL absolute HumanView roots; `state_base` is
    /// the view state base. We construct one `ViewLayout` per root — the
    /// SAME object the supervisor uses — so the rewrite target is identical.
    pub fn build(workspace_roots: &[String], state_base: &str) -> Config {
        let layouts: Vec<ViewLayout> = workspace_roots
            .iter()
            .filter(|r| !r.is_empty())
            .map(|r| ViewLayout::new(r, state_base))
            .collect();
        Config {
            roots: TrackedRoots::with_layouts(layouts),
            debug: false,
        }
    }

    /// Parse the env contract. Returns `None` (interposer becomes a no-op) when the
    /// required vars are absent or empty — so an un-configured LD_PRELOAD is inert
    /// rather than accidentally rewriting paths.
    pub fn from_env() -> Option<Config> {
        let workspace = std::env::var(ENV_WORKSPACE).ok()?;
        let state_base = std::env::var(ENV_AGENTVIEW).ok()?;
        let roots = parse_workspace_list(&workspace);
        if roots.is_empty() || state_base.is_empty() {
            return None;
        }
        let mut cfg = Config::build(&roots, &state_base);
        cfg.debug = parse_bool(std::env::var(ENV_DEBUG).ok().as_deref());
        if cfg.roots.is_empty() {
            return None;
        }
        Some(cfg)
    }

    /// The redirect decision for one open. Delegates ENTIRELY to fs-supervisor's
    /// `decide_open` — same tracked-root match, same AgentView rewrite, same
    /// read/write access intent. We pass `first_touch=false`: first-touch is a
    /// arbiter-observability concern the kernel loop owns; the LD_PRELOAD path only
    /// needs the redirect target, which is independent of first-touch.
    pub fn decide(&self, path: &str, flags: i32) -> OpenDecision {
        decide_open(&self.roots, path, flags, false)
    }

    /// Convenience: the AgentView path to open instead of `path`, or `None` for an
    /// untracked (passthrough) open. This is the single function the C-ABI
    /// interposers call.
    pub fn rewrite(&self, path: &str, flags: i32) -> Option<String> {
        match self.decide(path, flags) {
            OpenDecision::Redirect { agent_view_path, .. } => Some(agent_view_path),
            OpenDecision::Passthrough { .. } => None,
        }
    }

    pub fn roots_is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

/// Split the `MANDU_PRELOAD_WORKSPACE` value on ':' into roots, trimming empties.
/// (':' matches PATH-style lists; workspace roots are absolute so a leading/trailing
/// or doubled ':' just yields an empty segment we drop.)
pub fn parse_workspace_list(value: &str) -> Vec<String> {
    value
        .split(':')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn parse_bool(v: Option<&str>) -> bool {
    matches!(
        v.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// PathBuf parity helper (mirrors `decision::redirect_target`) for callers that
/// want an owned path.
pub fn rewrite_target(cfg: &Config, path: &str, flags: i32) -> Option<PathBuf> {
    cfg.rewrite(path, flags).map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_supervisor::decision::Access;

    const STATE: &str = "/state";
    const ROOT: &str = "/home/u/proj";
    // The AgentView worktree the supervisor + fs-sync compute for ROOT under STATE
    // (workspace-id = <basename>-<sha256(root)[:12]>, mirroring workspaceIdFor).
    const WT: &str = "/state/workspaces/proj-9c09f8055a26/agentview";

    fn cfg() -> Config {
        Config::build(&[ROOT.to_string()], STATE)
    }

    #[test]
    fn parse_workspace_list_splits_and_trims() {
        assert_eq!(parse_workspace_list("/a"), vec!["/a"]);
        assert_eq!(parse_workspace_list("/a:/b"), vec!["/a", "/b"]);
        // Empty segments (leading/trailing/doubled ':') are dropped.
        assert_eq!(parse_workspace_list(":/a::/b:"), vec!["/a", "/b"]);
        assert!(parse_workspace_list("").is_empty());
        assert!(parse_workspace_list("::").is_empty());
        // Surrounding whitespace trimmed.
        assert_eq!(parse_workspace_list(" /a : /b "), vec!["/a", "/b"]);
    }

    #[test]
    fn parse_bool_variants() {
        for t in ["1", "true", "TRUE", "yes", "on", " On "] {
            assert!(parse_bool(Some(t)), "{t} should be true");
        }
        for f in ["0", "false", "no", "off", "", "garbage"] {
            assert!(!parse_bool(Some(f)), "{f} should be false");
        }
        assert!(!parse_bool(None));
    }

    #[test]
    fn tracked_read_rewrites_to_agentview() {
        // This is the SAME mapping fs-supervisor's decide_open produces — we are
        // exercising the reused logic, not a parallel implementation.
        let got = cfg().rewrite("/home/u/proj/secret.txt", 0);
        assert_eq!(got.as_deref(), Some(&*format!("{WT}/secret.txt")));
    }

    #[test]
    fn tracked_write_still_redirects_to_agentview() {
        // O_WRONLY | O_CREAT → Write, still captured into AgentView (never raw).
        let flags = fs_supervisor::decision::O_WRONLY | fs_supervisor::decision::O_CREAT;
        let got = cfg().rewrite("/home/u/proj/out.txt", flags);
        assert_eq!(got.as_deref(), Some(&*format!("{WT}/out.txt")));
        // And the decision still classifies it as a write.
        match cfg().decide("/home/u/proj/out.txt", flags) {
            OpenDecision::Redirect { access, .. } => assert_eq!(access, Access::Write),
            _ => panic!("expected redirect"),
        }
    }

    #[test]
    fn untracked_path_is_passthrough_none() {
        assert_eq!(cfg().rewrite("/etc/passwd", 0), None);
        assert_eq!(cfg().rewrite("/home/u/other/x", 0), None);
        // Prefix-but-not-subdir must NOT match (boundary safety from rewrite_to_worktree).
        assert_eq!(cfg().rewrite("/home/u/proj-evil/x", 0), None);
    }

    #[test]
    fn already_in_worktree_is_idempotent() {
        // A path already under AgentView is returned unchanged (rewrite_to_worktree
        // idempotence) — so our own redirected open does not double-rewrite.
        let inner = format!("{WT}/src/main.rs");
        assert_eq!(cfg().rewrite(&inner, 0).as_deref(), Some(&*inner));
    }

    #[test]
    fn multiple_roots_each_match() {
        let c = Config::build(&["/home/u/proj".into(), "/srv/data".into()], STATE);
        assert!(c.rewrite("/home/u/proj/a", 0).is_some());
        assert!(c
            .rewrite("/srv/data/b", 0)
            .unwrap()
            .contains("data-96b53e47e3fc/agentview"));
        assert_eq!(c.rewrite("/tmp/x", 0), None);
    }

    #[test]
    fn empty_roots_make_inert_config() {
        let c = Config::build(&[], STATE);
        assert!(c.roots_is_empty());
        assert_eq!(c.rewrite("/home/u/proj/a", 0), None);
    }

    #[test]
    fn from_env_requires_both_vars() {
        // Drive from_env deterministically by setting/clearing in-process. Tests in
        // one file run on one thread by default for env safety here.
        std::env::remove_var(ENV_WORKSPACE);
        std::env::remove_var(ENV_AGENTVIEW);
        assert!(Config::from_env().is_none());

        std::env::set_var(ENV_WORKSPACE, "/home/u/proj");
        assert!(Config::from_env().is_none(), "missing AGENTVIEW → None");

        std::env::set_var(ENV_AGENTVIEW, "/state");
        let c = Config::from_env().expect("both set → Some");
        assert!(c.rewrite("/home/u/proj/x", 0).is_some());

        std::env::remove_var(ENV_WORKSPACE);
        std::env::remove_var(ENV_AGENTVIEW);
    }
}
