//! layout — pure view path math, mirroring `fs-sync/src/layout.ts` +
//! `git.ts::rewriteToWorktree`.
//!
//! PURE: no syscalls beyond optional canonicalization; unit-tested by default.
//!
//! The physical layout (from `fs-sync`):
//!   <stateBase>/workspaces/<workspace-id>/
//!       repo.git/         shadow repo slot
//!       agentview/        the AgentView git worktree (symbolized content)
//!       workspace.json
//!       commit.lock
//!       conflicts.log
//!
//! `workspace-id` = `<sanitized-basename>-<sha256(canonical-path)[:12]>`
//! (`workspaceIdFor`). `rewriteToWorktree` maps a path under the tracked
//! HumanView root to the same relative path under the AgentView worktree. We
//! reproduce that exactly so the Rust supervisor and the TS sync daemon agree on
//! where a tracked file lives.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Workspace id for a canonical HumanView path — an EXACT mirror of fs-sync's
/// `workspaceIdFor` (`fs-sync/src/layout.ts`): `<basename>-<sha256(path)[:12]>`.
///
/// The basename prefix is cosmetic (human-recognizable at a glance); identity +
/// collision-freedom come from the 12-hex sha256 over the FULL canonical path.
/// Sanitization mirrors the TS `.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 40)`
/// per UTF-16 code unit so both languages produce byte-identical dir names.
/// The two implementations are locked together by a shared golden vector:
/// `workspace_id_matches_fs_sync_golden_vector` below and
/// `fs-sync/test/unit/workspace-id.test.ts` assert the SAME literal ids — if you
/// change the scheme, change both implementations and both tests in one commit.
pub fn workspace_id_for(canonical_human_path: &str) -> String {
    let digest = Sha256::digest(canonical_human_path.as_bytes());
    let hash: String = digest[..6].iter().map(|b| format!("{b:02x}")).collect();
    let base: String = Path::new(canonical_human_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
        .encode_utf16()
        .map(|u| match u {
            0x2D | 0x2E | 0x5F => u as u8 as char, // - . _
            u if (0x30..=0x39).contains(&u)
                || (0x41..=0x5A).contains(&u)
                || (0x61..=0x7A).contains(&u) =>
            {
                u as u8 as char // 0-9 A-Z a-z
            }
            _ => '_',
        })
        .take(40)
        .collect();
    if base.is_empty() {
        format!("root-{hash}")
    } else {
        format!("{base}-{hash}")
    }
}

/// Resolved view layout for one tracked workspace. Pure value object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewLayout {
    /// Canonical HumanView path (the user's real workspace dir).
    pub human_path: PathBuf,
    pub workspace_id: String,
    /// `<stateBase>/workspaces/<workspace-id>/`.
    pub workspace_dir: PathBuf,
}

impl ViewLayout {
    /// Build a layout from an ALREADY-CANONICAL human path + a state base.
    ///
    /// The caller is responsible for canonicalization (the kernel path needs a
    /// real `realpath`; tests pass canonical absolute paths directly). We keep
    /// this pure so it runs without touching the filesystem.
    pub fn new(canonical_human_path: impl AsRef<Path>, state_base: impl AsRef<Path>) -> Self {
        let human_path = canonical_human_path.as_ref().to_path_buf();
        let workspace_id = workspace_id_for(&human_path.to_string_lossy());
        let workspace_dir = state_base
            .as_ref()
            .join("workspaces")
            .join(&workspace_id);
        ViewLayout {
            human_path,
            workspace_id,
            workspace_dir,
        }
    }

    /// Shadow bare-ish repo dir (layout parity with fs-sync).
    pub fn git_dir(&self) -> PathBuf {
        self.workspace_dir.join("repo.git")
    }

    /// The AgentView git worktree (symbolized content the agent sees).
    pub fn agent_view_path(&self) -> PathBuf {
        self.workspace_dir.join("agentview")
    }

    pub fn workspace_json_path(&self) -> PathBuf {
        self.workspace_dir.join("workspace.json")
    }

    pub fn commit_lock_path(&self) -> PathBuf {
        self.workspace_dir.join("commit.lock")
    }

    pub fn conflicts_log_path(&self) -> PathBuf {
        self.workspace_dir.join("conflicts.log")
    }
}

/// The view state base for `env` and `home`: the path table's `view-state`
/// (the Mandu home's `state/`, `$MANDU_HOME` or `<home>/.mandu`; no per-path
/// override since phase 4, on-disk-layout.md §3, §5, §9),
/// the mirror of fs-sync's `defaultStateBase`. Pure.
pub fn state_base_for(env: &dyn Fn(&str) -> Option<String>, home: &str) -> PathBuf {
    let p = mandu_paths::path(mandu_paths::names::VIEW_STATE, env, home)
        .expect("view-state is an entry of the generated path table");
    PathBuf::from(p)
}

/// Default view state base from the process environment (`state_base_for`
/// with `$HOME`, or `.` when `$HOME` is unset).
pub fn default_state_base() -> PathBuf {
    let home = mandu_paths::process_env("HOME").unwrap_or_else(|| ".".to_string());
    state_base_for(&mandu_paths::process_env, &home)
}

/// The AgentView worktree path for a layout (mirror of `getWorktreePath`). In the
/// fs-sync "fixed" mode this is `<workspaceDir>/agentview`.
pub fn worktree_path(layout: &ViewLayout) -> PathBuf {
    layout.agent_view_path()
}

/// Rewrite an absolute HumanView path into the AgentView worktree, returning
/// `None` if the path is NOT under the tracked root. This is a faithful port of
/// `fs-sync/src/git.ts::rewriteToWorktree`:
///
///   - a path already inside the worktree is returned unchanged (idempotent);
///   - a path under `humanPath` is re-rooted under the worktree, preserving the
///     relative suffix;
///   - anything else → `None` (untracked; the supervisor passes it through raw).
///
/// `~/` expansion (the TS helper handles it) is left to the caller's
/// canonicalization step; the supervisor canonicalizes before calling.
pub fn rewrite_to_worktree(layout: &ViewLayout, file_path: &str) -> Option<String> {
    let git_root = layout.human_path.to_string_lossy().to_string();
    let wt = worktree_path(layout).to_string_lossy().to_string();

    // Already inside the worktree → idempotent passthrough.
    if file_path.starts_with(&format!("{wt}/")) || file_path == wt {
        return Some(file_path.to_string());
    }
    // Under the tracked HumanView root → re-root under the worktree.
    if file_path.starts_with(&format!("{git_root}/")) {
        let suffix = &file_path[git_root.len()..];
        return Some(format!("{wt}{suffix}"));
    }
    if file_path == git_root {
        return Some(wt);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_id_matches_fs_sync_golden_vector() {
        // GOLDEN CROSS-LANGUAGE VECTOR — these literals were generated by the
        // REAL fs-sync `workspaceIdFor` and are asserted verbatim on the TS side
        // in fs-sync/test/unit/workspace-id.test.ts. The LD_PRELOAD/seccomp
        // redirect lands on the worktree fs-sync seeded ONLY if both languages
        // derive the same dir name, so a scheme change must update both
        // implementations and both tests in the same commit.
        assert_eq!(workspace_id_for("/home/u/proj"), "proj-9c09f8055a26");
        assert_eq!(workspace_id_for("/srv/data"), "data-96b53e47e3fc");
        // Empty basename (the filesystem root) falls back to `root`.
        assert_eq!(workspace_id_for("/"), "root-8a5edab28263");
        // Non [A-Za-z0-9._-] chars in the basename sanitize to '_'; the hash is
        // over the UNsanitized full path.
        assert_eq!(workspace_id_for("/tmp/My Proj!"), "My_Proj_-175f9f42097a");
    }

    #[test]
    fn workspace_id_is_a_single_bounded_safe_component() {
        // Same properties fs-sync's unit test locks: one path component, safe
        // charset, bounded length (basename capped at 40 + '-' + 12 hex).
        let deep = format!("/very/deep{}/workspace", "/x".repeat(120));
        let id = workspace_id_for(&deep);
        assert!(!id.contains('/'), "id must not contain a path separator");
        assert!(id.len() <= 53, "id length {} stays bounded", id.len());
        assert!(id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')));
        // Distinct paths sharing a basename must not collide.
        assert_ne!(
            workspace_id_for("/tmp/proj-one/workspace"),
            workspace_id_for("/tmp/proj-two/workspace")
        );
    }

    #[test]
    fn layout_paths() {
        let l = ViewLayout::new("/home/u/proj", "/state");
        assert_eq!(l.workspace_id, "proj-9c09f8055a26");
        assert_eq!(
            l.workspace_dir,
            PathBuf::from("/state/workspaces/proj-9c09f8055a26")
        );
        assert_eq!(
            l.agent_view_path(),
            PathBuf::from("/state/workspaces/proj-9c09f8055a26/agentview")
        );
    }

    #[test]
    fn rewrite_path_under_root() {
        let l = ViewLayout::new("/home/u/proj", "/state");
        let wt = "/state/workspaces/proj-9c09f8055a26/agentview";
        assert_eq!(
            rewrite_to_worktree(&l, "/home/u/proj/src/main.rs").as_deref(),
            Some(&*format!("{wt}/src/main.rs"))
        );
        // The root itself maps to the worktree root.
        assert_eq!(rewrite_to_worktree(&l, "/home/u/proj").as_deref(), Some(wt));
    }

    #[test]
    fn rewrite_path_already_in_worktree_is_idempotent() {
        let l = ViewLayout::new("/home/u/proj", "/state");
        let wt = "/state/workspaces/proj-9c09f8055a26/agentview";
        let inner = format!("{wt}/src/main.rs");
        assert_eq!(rewrite_to_worktree(&l, &inner).as_deref(), Some(&*inner));
        assert_eq!(rewrite_to_worktree(&l, wt).as_deref(), Some(wt));
    }

    #[test]
    fn state_base_comes_from_the_path_table() {
        let env_of = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| pairs.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string())
        };
        assert_eq!(state_base_for(&env_of(&[]), "/home/u"), PathBuf::from("/home/u/.mandu/state"));
        assert_eq!(state_base_for(&env_of(&[]), "/home/u/"), PathBuf::from("/home/u/.mandu/state"));
        assert_eq!(state_base_for(&env_of(&[("MANDU_VIEW_STATE", "/v/state")]), "/h"), PathBuf::from("/h/.mandu/state"), "MANDU_VIEW_STATE is retired");
        assert_eq!(state_base_for(&env_of(&[("MANDU_HOME", "")]), "/h"), PathBuf::from("/h/.mandu/state"), "empty counts as unset");
        assert_eq!(state_base_for(&env_of(&[("MANDU_HOME", "/m")]), "/h"), PathBuf::from("/m/state"), "MANDU_HOME moves it");
        assert_eq!(state_base_for(&env_of(&[("XDG_STATE_HOME", "/x")]), "/h"), PathBuf::from("/h/.mandu/state"), "XDG roots do not move it");
        // An unset HOME resolves relative to `.`, as before the one home.
        assert_eq!(state_base_for(&env_of(&[]), "."), PathBuf::from(".mandu/state"));
        // The layout under it is unchanged.
        let l = ViewLayout::new("/home/u/proj", state_base_for(&env_of(&[]), "/home/u"));
        assert_eq!(l.workspace_dir, PathBuf::from("/home/u/.mandu/state/workspaces/proj-9c09f8055a26"));
    }

    #[test]
    fn default_state_base_is_the_process_view_of_the_table() {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        assert_eq!(default_state_base(), state_base_for(&mandu_paths::process_env, &home));
    }

    #[test]
    fn rewrite_untracked_path_is_none() {
        let l = ViewLayout::new("/home/u/proj", "/state");
        assert_eq!(rewrite_to_worktree(&l, "/etc/passwd"), None);
        assert_eq!(rewrite_to_worktree(&l, "/home/u/other/x"), None);
        // Prefix-but-not-subdir must NOT match (no trailing slash boundary).
        assert_eq!(rewrite_to_worktree(&l, "/home/u/proj-evil/x"), None);
    }
}
