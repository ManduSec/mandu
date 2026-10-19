//! GENERATED FILE: do not edit. Source: scripts/paths/mandu-paths.mjs
//! (docs/design/architecture/on-disk-layout.md §5). Regenerate with
//! `node scripts/paths/mandu-paths.mjs generate`; scripts/test/mandu-paths.test.mjs fails
//! when this copy differs from the table.
//!
//! Pure resolvers: `(env, home)` in, a path string out, no file access.
//! Paths are joined like node's `path.posix.join`, so every copy agrees
//! byte for byte.

/// Where a base falls back to when no variable in its chain is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    /// A path under the caller's home.
    Home(&'static str),
    /// An absolute path.
    Abs(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base {
    pub name: &'static str,
    /// Variables tried in order; the first non-empty one is the base.
    pub chain: &'static [&'static str],
    pub fallback: Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dir,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub name: &'static str,
    /// A base, or the entry this one sits under.
    pub base: &'static str,
    pub rel: &'static str,
    pub kind: Kind,
    /// The mode Mandu creates it with; `None` when it is not Mandu's to set.
    pub mode: Option<u32>,
    /// Whether the agent may read it by its own path (on-disk-layout.md §4).
    pub agent_readable: bool,
    /// The per-path override, used verbatim when non-empty.
    pub env: Option<&'static str>,
}

/// Entry names, for callers.
pub mod names {
    pub const MANDU_HOME: &str = "mandu-home";
    pub const CONFIG_ROOT: &str = "config-root";
    pub const CONFIG_TOML: &str = "config-toml";
    pub const POLICY: &str = "policy";
    pub const PACKS: &str = "packs";
    pub const PACK_KEYS: &str = "pack-keys";
    pub const PROMPT_FILTERS: &str = "prompt-filters";
    pub const SECRETS_JSON: &str = "secrets-json";
    pub const DASHBOARD_ENV: &str = "dashboard-env";
    pub const STATE_ROOT: &str = "state-root";
    pub const SYMBOL_DB: &str = "symbol-db";
    pub const SYMBOL_DB_TEST: &str = "symbol-db-test";
    pub const VIEW_STATE: &str = "view-state";
    pub const WORKSPACES: &str = "workspaces";
    pub const OBJECT_WALKS: &str = "object-walks";
    pub const PAIRED_APPROVALS: &str = "paired-approvals";
    pub const BROWSER_PROFILE: &str = "browser-profile";
    pub const LAUNCH_LOGS: &str = "launch-logs";
    pub const EVENTS: &str = "events";
    pub const EVENTS_TEST: &str = "events-test";
    pub const RUNS_ROOT: &str = "runs-root";
    pub const TEST_RUNS: &str = "test-runs";
    pub const TEST_RUN_RESULTS: &str = "test-run-results";
    pub const LIVE_DRILL_RUNS: &str = "live-drill-runs";
    pub const CI_RUNS: &str = "ci-runs";
    pub const MATRIX_RESULTS: &str = "matrix-results";
    pub const EVAL_RUNS: &str = "eval-runs";
    pub const REPLAY_DRILL_RUNS: &str = "replay-drill-runs";
    pub const DRILL_BASELINES: &str = "drill-baselines";
    pub const DEV_ROOT: &str = "dev-root";
    pub const DOCKER_E2E_HOME: &str = "docker-e2e-home";
    pub const CACHE_ROOT: &str = "cache-root";
    pub const OBJECT_TWINS: &str = "object-twins";
    pub const CI_CACHE: &str = "ci-cache";
    pub const CI_HOST_OUT: &str = "ci-host-out";
    pub const DASHBOARD_CACHE: &str = "dashboard-cache";
    pub const UPDATE_CHECK: &str = "update-check";
    pub const RUNTIME_DIR: &str = "runtime-dir";
    pub const INSTALL_PREFIX: &str = "install-prefix";
    pub const EXEC_BOX_CACHE: &str = "exec-box-cache";
    pub const BIN_DIR: &str = "bin-dir";
}

pub const BASES: &[Base] = &[
    Base { name: "home", chain: &[], fallback: Fallback::Home("") },
    Base { name: "mandu", chain: &["MANDU_HOME"], fallback: Fallback::Home(".mandu") },
    Base { name: "runtime", chain: &["XDG_RUNTIME_DIR", "TMPDIR"], fallback: Fallback::Abs("/tmp") },
    Base { name: "install", chain: &[], fallback: Fallback::Home(".local/share") },
];

pub const PATHS: &[Entry] = &[
    // the one Mandu home; the agent may neither read nor write it (§4)
    Entry { name: "mandu-home", base: "mandu", rel: "", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // what a human edits: the top level of the home
    Entry { name: "config-root", base: "mandu-home", rel: "", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // launcher defaults
    Entry { name: "config-toml", base: "config-root", rel: "config.toml", kind: Kind::File, mode: Some(0o600), agent_readable: false, env: None },
    // the law; MANDU_POLICY_FILE, the one per-path override left, is the arbiter's (§9)
    Entry { name: "policy", base: "config-root", rel: "policy.yaml", kind: Kind::File, mode: Some(0o600), agent_readable: false, env: None },
    // signed consumer packs
    Entry { name: "packs", base: "config-root", rel: "packs", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // trusted pack keys
    Entry { name: "pack-keys", base: "config-root", rel: "pack-keys", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // the person's prompt filter packs (confidentiality-plan-15 §4.2)
    Entry { name: "prompt-filters", base: "config-root", rel: "prompt-filters", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // developer API keys
    Entry { name: "secrets-json", base: "config-root", rel: "secrets.json", kind: Kind::File, mode: Some(0o600), agent_readable: false, env: None },
    // a resident dashboard's EnvironmentFile (DASHBOARD_BASIC_AUTH); the live suites' auth reads it (dashboard.md §6)
    Entry { name: "dashboard-env", base: "config-root", rel: "dashboard.env", kind: Kind::File, mode: Some(0o600), agent_readable: false, env: None },
    // durable: losing it loses approvals and history
    Entry { name: "state-root", base: "mandu-home", rel: "state", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // symbol table + every durable policy table; holds originals
    Entry { name: "symbol-db", base: "state-root", rel: "mandu.db", kind: Kind::File, mode: Some(0o600), agent_readable: false, env: None },
    // the test tenant's DB
    Entry { name: "symbol-db-test", base: "state-root", rel: "mandu-test.db", kind: Kind::File, mode: Some(0o600), agent_readable: false, env: None },
    // fs-sync's state base
    Entry { name: "view-state", base: "state-root", rel: "", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // shadow repos + AgentView; the integrity modes carve the AgentView out (§4)
    Entry { name: "workspaces", base: "view-state", rel: "workspaces", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // git history-walk cache; names protected blobs
    Entry { name: "object-walks", base: "state-root", rel: "object-walks", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // one-shot approvals for paired evaluation runs
    Entry { name: "paired-approvals", base: "state-root", rel: "paired-approvals", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // the Chrome profile `mandu --browser` starts the agent's browser with (devtools-relay.md §6.4): the person's logins and cookies on the sites the agent uses
    Entry { name: "browser-profile", base: "state-root", rel: "browser", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // one log per launch: every launch line and Mandu helper message the terminal did not show by default; the last 20 kept (packaging.md §5 "Launch display policy")
    Entry { name: "launch-logs", base: "state-root", rel: "launch-logs", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // session history; holds originals
    Entry { name: "events", base: "mandu-home", rel: "events", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // the test tenant's events
    Entry { name: "events-test", base: "events", rel: "test", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // results the dashboard reads; developer hosts only
    Entry { name: "runs-root", base: "mandu-home", rel: "runs", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // the dashboard's test-run history
    Entry { name: "test-runs", base: "runs-root", rel: "test-runs.json", kind: Kind::File, mode: Some(0o600), agent_readable: false, env: None },
    // each dashboard Tests-tab run's summary.json, junit.xml and logs/ (run-suites --out), by run id: what the Coverage view attributes per suite (dashboard.md §4.29)
    Entry { name: "test-run-results", base: "runs-root", rel: "test-runs", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // live-drill run records, the drill runner's store (test-reorganization.md §4; runs/watch before 2026-10-02)
    Entry { name: "live-drill-runs", base: "runs-root", rel: "drills/live", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // CI run results the dashboard reads
    Entry { name: "ci-runs", base: "runs-root", rel: "ci", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // OS-matrix run results
    Entry { name: "matrix-results", base: "runs-root", rel: "matrix", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // evaluation run outputs (the operator's --out wins)
    Entry { name: "eval-runs", base: "runs-root", rel: "eval", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // replay-drill run records (test-reorganization.md §6.7)
    Entry { name: "replay-drill-runs", base: "runs-root", rel: "drills/replay", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // the plain-agent baseline cache of the replay drills (test-reorganization.md §6.3)
    Entry { name: "drill-baselines", base: "runs-root", rel: "drills/baselines", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // developer-only; made only when used
    Entry { name: "dev-root", base: "mandu-home", rel: "dev", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // developer-only credentials
    Entry { name: "docker-e2e-home", base: "dev-root", rel: "docker-e2e-home", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // regenerable; safe to delete
    Entry { name: "cache-root", base: "mandu-home", rel: "cache", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // sanitized git packs; the agent reads them only through the bind or fd
    Entry { name: "object-twins", base: "cache-root", rel: "object-twins", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // CI VM images
    Entry { name: "ci-cache", base: "cache-root", rel: "ci", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // a host-mode CI run's output before it is collected
    Entry { name: "ci-host-out", base: "ci-cache", rel: "host-out", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // the dashboard's persisted listing summaries (record heads, run metas, events-log counts), each valid only at its file's identity (dashboard.md §4.30)
    Entry { name: "dashboard-cache", base: "cache-root", rel: "dashboard", kind: Kind::Dir, mode: Some(0o700), agent_readable: false, env: None },
    // the last release check's answer, so a launch prints the update notice without waiting on the network (packaging.md §11.5)
    Entry { name: "update-check", base: "cache-root", rel: "update-check.json", kind: Kind::File, mode: Some(0o600), agent_readable: false, env: None },
    // sockets, instances, per-launch scope dirs; per-boot
    Entry { name: "runtime-dir", base: "runtime", rel: "mandu", kind: Kind::Dir, mode: Some(0o700), agent_readable: true, env: Some("MANDU_RUNTIME_DIR") },
    // the installed program; the agent runs parts of it
    Entry { name: "install-prefix", base: "install", rel: "mandu", kind: Kind::Dir, mode: Some(0o755), agent_readable: true, env: Some("MANDU_PREFIX") },
    // staged exec-box applier when the runtime dir is under /tmp; the agent runs it, never writes it
    Entry { name: "exec-box-cache", base: "install-prefix", rel: "exec-box", kind: Kind::Dir, mode: Some(0o755), agent_readable: true, env: None },
    // where the installer writes the mandu wrapper
    Entry { name: "bin-dir", base: "home", rel: ".local/bin", kind: Kind::Dir, mode: None, agent_readable: true, env: Some("MANDU_BIN_DIR") },
];

/// The base named `name`, or `None` for an unknown name.
pub fn base_def(name: &str) -> Option<&'static Base> {
    BASES.iter().find(|b| b.name == name)
}

/// The entry named `name`, or `None` for an unknown name.
pub fn entry(name: &str) -> Option<&'static Entry> {
    PATHS.iter().find(|e| e.name == name)
}

fn set(env: &dyn Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    env(key).filter(|v| !v.is_empty())
}

/// A base for `env` and `home`. Pure: reads no file.
pub fn base(name: &str, env: &dyn Fn(&str) -> Option<String>, home: &str) -> Option<String> {
    let b = base_def(name)?;
    for k in b.chain {
        if let Some(v) = set(env, k) {
            return Some(v);
        }
    }
    Some(match b.fallback {
        Fallback::Home(rel) => join(home, rel),
        Fallback::Abs(p) => p.to_string(),
    })
}

/// An entry's path for `env` and `home`: its override when set, else its
/// parent joined with `rel`. Pure: reads no file.
pub fn path(name: &str, env: &dyn Fn(&str) -> Option<String>, home: &str) -> Option<String> {
    let e = entry(name)?;
    if let Some(v) = e.env.and_then(|k| set(env, k)) {
        return Some(v);
    }
    let parent = if base_def(e.base).is_some() { base(e.base, env, home)? } else { path(e.base, env, home)? };
    Some(join(&parent, e.rel))
}

/// The process environment, for callers that resolve against it.
pub fn process_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// node's `path.posix.join(a, b)`.
pub fn join(a: &str, b: &str) -> String {
    let joined = match (a.is_empty(), b.is_empty()) {
        (true, true) => return ".".to_string(),
        (false, true) => a.to_string(),
        (true, false) => b.to_string(),
        (false, false) => format!("{a}/{b}"),
    };
    normalize(&joined)
}

/// node's `path.posix.normalize`.
pub fn normalize(p: &str) -> String {
    if p.is_empty() {
        return ".".to_string();
    }
    let absolute = p.starts_with('/');
    let trailing = p.ends_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|s| *s != "..") {
                    out.pop();
                } else if !absolute {
                    out.push("..");
                }
            }
            s => out.push(s),
        }
    }
    let mut s = out.join("/");
    if s.is_empty() {
        return if absolute { "/".to_string() } else if trailing { "./".to_string() } else { ".".to_string() };
    }
    if trailing {
        s.push('/');
    }
    if absolute {
        format!("/{s}")
    } else {
        s
    }
}

#[cfg(test)]
mod generated_cases {
    use super::*;

    type Case = (&'static str, &'static [(&'static str, &'static str)], &'static str, &'static str, &'static str);

    /// (fixture, env, home, entry, what the table resolves it to).
    const CASES: &[Case] = &[
        ("home only", &[], "/home/u", "mandu-home", "/home/u/.mandu"),
        ("home only", &[], "/home/u", "config-root", "/home/u/.mandu"),
        ("home only", &[], "/home/u", "config-toml", "/home/u/.mandu/config.toml"),
        ("home only", &[], "/home/u", "policy", "/home/u/.mandu/policy.yaml"),
        ("home only", &[], "/home/u", "packs", "/home/u/.mandu/packs"),
        ("home only", &[], "/home/u", "pack-keys", "/home/u/.mandu/pack-keys"),
        ("home only", &[], "/home/u", "prompt-filters", "/home/u/.mandu/prompt-filters"),
        ("home only", &[], "/home/u", "secrets-json", "/home/u/.mandu/secrets.json"),
        ("home only", &[], "/home/u", "dashboard-env", "/home/u/.mandu/dashboard.env"),
        ("home only", &[], "/home/u", "state-root", "/home/u/.mandu/state"),
        ("home only", &[], "/home/u", "symbol-db", "/home/u/.mandu/state/mandu.db"),
        ("home only", &[], "/home/u", "symbol-db-test", "/home/u/.mandu/state/mandu-test.db"),
        ("home only", &[], "/home/u", "view-state", "/home/u/.mandu/state"),
        ("home only", &[], "/home/u", "workspaces", "/home/u/.mandu/state/workspaces"),
        ("home only", &[], "/home/u", "object-walks", "/home/u/.mandu/state/object-walks"),
        ("home only", &[], "/home/u", "paired-approvals", "/home/u/.mandu/state/paired-approvals"),
        ("home only", &[], "/home/u", "browser-profile", "/home/u/.mandu/state/browser"),
        ("home only", &[], "/home/u", "launch-logs", "/home/u/.mandu/state/launch-logs"),
        ("home only", &[], "/home/u", "events", "/home/u/.mandu/events"),
        ("home only", &[], "/home/u", "events-test", "/home/u/.mandu/events/test"),
        ("home only", &[], "/home/u", "runs-root", "/home/u/.mandu/runs"),
        ("home only", &[], "/home/u", "test-runs", "/home/u/.mandu/runs/test-runs.json"),
        ("home only", &[], "/home/u", "test-run-results", "/home/u/.mandu/runs/test-runs"),
        ("home only", &[], "/home/u", "live-drill-runs", "/home/u/.mandu/runs/drills/live"),
        ("home only", &[], "/home/u", "ci-runs", "/home/u/.mandu/runs/ci"),
        ("home only", &[], "/home/u", "matrix-results", "/home/u/.mandu/runs/matrix"),
        ("home only", &[], "/home/u", "eval-runs", "/home/u/.mandu/runs/eval"),
        ("home only", &[], "/home/u", "replay-drill-runs", "/home/u/.mandu/runs/drills/replay"),
        ("home only", &[], "/home/u", "drill-baselines", "/home/u/.mandu/runs/drills/baselines"),
        ("home only", &[], "/home/u", "dev-root", "/home/u/.mandu/dev"),
        ("home only", &[], "/home/u", "docker-e2e-home", "/home/u/.mandu/dev/docker-e2e-home"),
        ("home only", &[], "/home/u", "cache-root", "/home/u/.mandu/cache"),
        ("home only", &[], "/home/u", "object-twins", "/home/u/.mandu/cache/object-twins"),
        ("home only", &[], "/home/u", "ci-cache", "/home/u/.mandu/cache/ci"),
        ("home only", &[], "/home/u", "ci-host-out", "/home/u/.mandu/cache/ci/host-out"),
        ("home only", &[], "/home/u", "dashboard-cache", "/home/u/.mandu/cache/dashboard"),
        ("home only", &[], "/home/u", "update-check", "/home/u/.mandu/cache/update-check.json"),
        ("home only", &[], "/home/u", "runtime-dir", "/tmp/mandu"),
        ("home only", &[], "/home/u", "install-prefix", "/home/u/.local/share/mandu"),
        ("home only", &[], "/home/u", "exec-box-cache", "/home/u/.local/share/mandu/exec-box"),
        ("home only", &[], "/home/u", "bin-dir", "/home/u/.local/bin"),
        ("home with trailing slash", &[], "/home/u/", "mandu-home", "/home/u/.mandu"),
        ("home with trailing slash", &[], "/home/u/", "config-root", "/home/u/.mandu"),
        ("home with trailing slash", &[], "/home/u/", "config-toml", "/home/u/.mandu/config.toml"),
        ("home with trailing slash", &[], "/home/u/", "policy", "/home/u/.mandu/policy.yaml"),
        ("home with trailing slash", &[], "/home/u/", "packs", "/home/u/.mandu/packs"),
        ("home with trailing slash", &[], "/home/u/", "pack-keys", "/home/u/.mandu/pack-keys"),
        ("home with trailing slash", &[], "/home/u/", "prompt-filters", "/home/u/.mandu/prompt-filters"),
        ("home with trailing slash", &[], "/home/u/", "secrets-json", "/home/u/.mandu/secrets.json"),
        ("home with trailing slash", &[], "/home/u/", "dashboard-env", "/home/u/.mandu/dashboard.env"),
        ("home with trailing slash", &[], "/home/u/", "state-root", "/home/u/.mandu/state"),
        ("home with trailing slash", &[], "/home/u/", "symbol-db", "/home/u/.mandu/state/mandu.db"),
        ("home with trailing slash", &[], "/home/u/", "symbol-db-test", "/home/u/.mandu/state/mandu-test.db"),
        ("home with trailing slash", &[], "/home/u/", "view-state", "/home/u/.mandu/state"),
        ("home with trailing slash", &[], "/home/u/", "workspaces", "/home/u/.mandu/state/workspaces"),
        ("home with trailing slash", &[], "/home/u/", "object-walks", "/home/u/.mandu/state/object-walks"),
        ("home with trailing slash", &[], "/home/u/", "paired-approvals", "/home/u/.mandu/state/paired-approvals"),
        ("home with trailing slash", &[], "/home/u/", "browser-profile", "/home/u/.mandu/state/browser"),
        ("home with trailing slash", &[], "/home/u/", "launch-logs", "/home/u/.mandu/state/launch-logs"),
        ("home with trailing slash", &[], "/home/u/", "events", "/home/u/.mandu/events"),
        ("home with trailing slash", &[], "/home/u/", "events-test", "/home/u/.mandu/events/test"),
        ("home with trailing slash", &[], "/home/u/", "runs-root", "/home/u/.mandu/runs"),
        ("home with trailing slash", &[], "/home/u/", "test-runs", "/home/u/.mandu/runs/test-runs.json"),
        ("home with trailing slash", &[], "/home/u/", "test-run-results", "/home/u/.mandu/runs/test-runs"),
        ("home with trailing slash", &[], "/home/u/", "live-drill-runs", "/home/u/.mandu/runs/drills/live"),
        ("home with trailing slash", &[], "/home/u/", "ci-runs", "/home/u/.mandu/runs/ci"),
        ("home with trailing slash", &[], "/home/u/", "matrix-results", "/home/u/.mandu/runs/matrix"),
        ("home with trailing slash", &[], "/home/u/", "eval-runs", "/home/u/.mandu/runs/eval"),
        ("home with trailing slash", &[], "/home/u/", "replay-drill-runs", "/home/u/.mandu/runs/drills/replay"),
        ("home with trailing slash", &[], "/home/u/", "drill-baselines", "/home/u/.mandu/runs/drills/baselines"),
        ("home with trailing slash", &[], "/home/u/", "dev-root", "/home/u/.mandu/dev"),
        ("home with trailing slash", &[], "/home/u/", "docker-e2e-home", "/home/u/.mandu/dev/docker-e2e-home"),
        ("home with trailing slash", &[], "/home/u/", "cache-root", "/home/u/.mandu/cache"),
        ("home with trailing slash", &[], "/home/u/", "object-twins", "/home/u/.mandu/cache/object-twins"),
        ("home with trailing slash", &[], "/home/u/", "ci-cache", "/home/u/.mandu/cache/ci"),
        ("home with trailing slash", &[], "/home/u/", "ci-host-out", "/home/u/.mandu/cache/ci/host-out"),
        ("home with trailing slash", &[], "/home/u/", "dashboard-cache", "/home/u/.mandu/cache/dashboard"),
        ("home with trailing slash", &[], "/home/u/", "update-check", "/home/u/.mandu/cache/update-check.json"),
        ("home with trailing slash", &[], "/home/u/", "runtime-dir", "/tmp/mandu"),
        ("home with trailing slash", &[], "/home/u/", "install-prefix", "/home/u/.local/share/mandu"),
        ("home with trailing slash", &[], "/home/u/", "exec-box-cache", "/home/u/.local/share/mandu/exec-box"),
        ("home with trailing slash", &[], "/home/u/", "bin-dir", "/home/u/.local/bin"),
        ("root home", &[], "/", "mandu-home", "/.mandu"),
        ("root home", &[], "/", "config-root", "/.mandu"),
        ("root home", &[], "/", "config-toml", "/.mandu/config.toml"),
        ("root home", &[], "/", "policy", "/.mandu/policy.yaml"),
        ("root home", &[], "/", "packs", "/.mandu/packs"),
        ("root home", &[], "/", "pack-keys", "/.mandu/pack-keys"),
        ("root home", &[], "/", "prompt-filters", "/.mandu/prompt-filters"),
        ("root home", &[], "/", "secrets-json", "/.mandu/secrets.json"),
        ("root home", &[], "/", "dashboard-env", "/.mandu/dashboard.env"),
        ("root home", &[], "/", "state-root", "/.mandu/state"),
        ("root home", &[], "/", "symbol-db", "/.mandu/state/mandu.db"),
        ("root home", &[], "/", "symbol-db-test", "/.mandu/state/mandu-test.db"),
        ("root home", &[], "/", "view-state", "/.mandu/state"),
        ("root home", &[], "/", "workspaces", "/.mandu/state/workspaces"),
        ("root home", &[], "/", "object-walks", "/.mandu/state/object-walks"),
        ("root home", &[], "/", "paired-approvals", "/.mandu/state/paired-approvals"),
        ("root home", &[], "/", "browser-profile", "/.mandu/state/browser"),
        ("root home", &[], "/", "launch-logs", "/.mandu/state/launch-logs"),
        ("root home", &[], "/", "events", "/.mandu/events"),
        ("root home", &[], "/", "events-test", "/.mandu/events/test"),
        ("root home", &[], "/", "runs-root", "/.mandu/runs"),
        ("root home", &[], "/", "test-runs", "/.mandu/runs/test-runs.json"),
        ("root home", &[], "/", "test-run-results", "/.mandu/runs/test-runs"),
        ("root home", &[], "/", "live-drill-runs", "/.mandu/runs/drills/live"),
        ("root home", &[], "/", "ci-runs", "/.mandu/runs/ci"),
        ("root home", &[], "/", "matrix-results", "/.mandu/runs/matrix"),
        ("root home", &[], "/", "eval-runs", "/.mandu/runs/eval"),
        ("root home", &[], "/", "replay-drill-runs", "/.mandu/runs/drills/replay"),
        ("root home", &[], "/", "drill-baselines", "/.mandu/runs/drills/baselines"),
        ("root home", &[], "/", "dev-root", "/.mandu/dev"),
        ("root home", &[], "/", "docker-e2e-home", "/.mandu/dev/docker-e2e-home"),
        ("root home", &[], "/", "cache-root", "/.mandu/cache"),
        ("root home", &[], "/", "object-twins", "/.mandu/cache/object-twins"),
        ("root home", &[], "/", "ci-cache", "/.mandu/cache/ci"),
        ("root home", &[], "/", "ci-host-out", "/.mandu/cache/ci/host-out"),
        ("root home", &[], "/", "dashboard-cache", "/.mandu/cache/dashboard"),
        ("root home", &[], "/", "update-check", "/.mandu/cache/update-check.json"),
        ("root home", &[], "/", "runtime-dir", "/tmp/mandu"),
        ("root home", &[], "/", "install-prefix", "/.local/share/mandu"),
        ("root home", &[], "/", "exec-box-cache", "/.local/share/mandu/exec-box"),
        ("root home", &[], "/", "bin-dir", "/.local/bin"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "mandu-home", "/home/u/.mandu"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "config-root", "/home/u/.mandu"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "config-toml", "/home/u/.mandu/config.toml"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "policy", "/home/u/.mandu/policy.yaml"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "packs", "/home/u/.mandu/packs"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "pack-keys", "/home/u/.mandu/pack-keys"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "prompt-filters", "/home/u/.mandu/prompt-filters"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "secrets-json", "/home/u/.mandu/secrets.json"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "dashboard-env", "/home/u/.mandu/dashboard.env"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "state-root", "/home/u/.mandu/state"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "symbol-db", "/home/u/.mandu/state/mandu.db"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "symbol-db-test", "/home/u/.mandu/state/mandu-test.db"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "view-state", "/home/u/.mandu/state"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "workspaces", "/home/u/.mandu/state/workspaces"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "object-walks", "/home/u/.mandu/state/object-walks"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "paired-approvals", "/home/u/.mandu/state/paired-approvals"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "browser-profile", "/home/u/.mandu/state/browser"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "launch-logs", "/home/u/.mandu/state/launch-logs"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "events", "/home/u/.mandu/events"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "events-test", "/home/u/.mandu/events/test"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "runs-root", "/home/u/.mandu/runs"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "test-runs", "/home/u/.mandu/runs/test-runs.json"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "test-run-results", "/home/u/.mandu/runs/test-runs"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "live-drill-runs", "/home/u/.mandu/runs/drills/live"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "ci-runs", "/home/u/.mandu/runs/ci"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "matrix-results", "/home/u/.mandu/runs/matrix"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "eval-runs", "/home/u/.mandu/runs/eval"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "replay-drill-runs", "/home/u/.mandu/runs/drills/replay"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "drill-baselines", "/home/u/.mandu/runs/drills/baselines"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "dev-root", "/home/u/.mandu/dev"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "docker-e2e-home", "/home/u/.mandu/dev/docker-e2e-home"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "cache-root", "/home/u/.mandu/cache"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "object-twins", "/home/u/.mandu/cache/object-twins"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "ci-cache", "/home/u/.mandu/cache/ci"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "ci-host-out", "/home/u/.mandu/cache/ci/host-out"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "dashboard-cache", "/home/u/.mandu/cache/dashboard"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "update-check", "/home/u/.mandu/cache/update-check.json"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "runtime-dir", "/run/user/1000/mandu"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "install-prefix", "/home/u/.local/share/mandu"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "exec-box-cache", "/home/u/.local/share/mandu/exec-box"),
        ("every XDG root set", &[("XDG_STATE_HOME", "/x/state"), ("XDG_CONFIG_HOME", "/x/config"), ("XDG_CACHE_HOME", "/x/cache"), ("XDG_RUNTIME_DIR", "/run/user/1000"), ("XDG_DATA_HOME", "/x/data")], "/home/u", "bin-dir", "/home/u/.local/bin"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "mandu-home", "/home/u/.mandu"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "config-root", "/home/u/.mandu"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "config-toml", "/home/u/.mandu/config.toml"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "policy", "/home/u/.mandu/policy.yaml"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "packs", "/home/u/.mandu/packs"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "pack-keys", "/home/u/.mandu/pack-keys"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "prompt-filters", "/home/u/.mandu/prompt-filters"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "secrets-json", "/home/u/.mandu/secrets.json"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "dashboard-env", "/home/u/.mandu/dashboard.env"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "state-root", "/home/u/.mandu/state"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "symbol-db", "/home/u/.mandu/state/mandu.db"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "symbol-db-test", "/home/u/.mandu/state/mandu-test.db"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "view-state", "/home/u/.mandu/state"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "workspaces", "/home/u/.mandu/state/workspaces"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "object-walks", "/home/u/.mandu/state/object-walks"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "paired-approvals", "/home/u/.mandu/state/paired-approvals"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "browser-profile", "/home/u/.mandu/state/browser"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "launch-logs", "/home/u/.mandu/state/launch-logs"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "events", "/home/u/.mandu/events"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "events-test", "/home/u/.mandu/events/test"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "runs-root", "/home/u/.mandu/runs"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "test-runs", "/home/u/.mandu/runs/test-runs.json"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "test-run-results", "/home/u/.mandu/runs/test-runs"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "live-drill-runs", "/home/u/.mandu/runs/drills/live"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "ci-runs", "/home/u/.mandu/runs/ci"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "matrix-results", "/home/u/.mandu/runs/matrix"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "eval-runs", "/home/u/.mandu/runs/eval"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "replay-drill-runs", "/home/u/.mandu/runs/drills/replay"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "drill-baselines", "/home/u/.mandu/runs/drills/baselines"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "dev-root", "/home/u/.mandu/dev"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "docker-e2e-home", "/home/u/.mandu/dev/docker-e2e-home"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "cache-root", "/home/u/.mandu/cache"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "object-twins", "/home/u/.mandu/cache/object-twins"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "ci-cache", "/home/u/.mandu/cache/ci"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "ci-host-out", "/home/u/.mandu/cache/ci/host-out"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "dashboard-cache", "/home/u/.mandu/cache/dashboard"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "update-check", "/home/u/.mandu/cache/update-check.json"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "runtime-dir", "/tmp/mandu"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "install-prefix", "/home/u/.local/share/mandu"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "exec-box-cache", "/home/u/.local/share/mandu/exec-box"),
        ("empty XDG values fall through", &[("MANDU_HOME", ""), ("XDG_STATE_HOME", ""), ("XDG_CONFIG_HOME", ""), ("XDG_CACHE_HOME", ""), ("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")], "/home/u", "bin-dir", "/home/u/.local/bin"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "mandu-home", "/m/"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "config-root", "/m/"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "config-toml", "/m/config.toml"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "policy", "/m/policy.yaml"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "packs", "/m/packs"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "pack-keys", "/m/pack-keys"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "prompt-filters", "/m/prompt-filters"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "secrets-json", "/m/secrets.json"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "dashboard-env", "/m/dashboard.env"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "state-root", "/m/state"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "symbol-db", "/m/state/mandu.db"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "symbol-db-test", "/m/state/mandu-test.db"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "view-state", "/m/state"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "workspaces", "/m/state/workspaces"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "object-walks", "/m/state/object-walks"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "paired-approvals", "/m/state/paired-approvals"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "browser-profile", "/m/state/browser"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "launch-logs", "/m/state/launch-logs"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "events", "/m/events"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "events-test", "/m/events/test"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "runs-root", "/m/runs"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "test-runs", "/m/runs/test-runs.json"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "test-run-results", "/m/runs/test-runs"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "live-drill-runs", "/m/runs/drills/live"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "ci-runs", "/m/runs/ci"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "matrix-results", "/m/runs/matrix"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "eval-runs", "/m/runs/eval"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "replay-drill-runs", "/m/runs/drills/replay"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "drill-baselines", "/m/runs/drills/baselines"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "dev-root", "/m/dev"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "docker-e2e-home", "/m/dev/docker-e2e-home"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "cache-root", "/m/cache"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "object-twins", "/m/cache/object-twins"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "ci-cache", "/m/cache/ci"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "ci-host-out", "/m/cache/ci/host-out"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "dashboard-cache", "/m/cache/dashboard"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "update-check", "/m/cache/update-check.json"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "runtime-dir", "/tmp/mandu"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "install-prefix", "/home/u/.local/share/mandu"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "exec-box-cache", "/home/u/.local/share/mandu/exec-box"),
        ("MANDU_HOME moves the home", &[("MANDU_HOME", "/m/")], "/home/u", "bin-dir", "/home/u/.local/bin"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "mandu-home", "/home/u/.mandu"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "config-root", "/home/u/.mandu"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "config-toml", "/home/u/.mandu/config.toml"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "policy", "/home/u/.mandu/policy.yaml"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "packs", "/home/u/.mandu/packs"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "pack-keys", "/home/u/.mandu/pack-keys"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "prompt-filters", "/home/u/.mandu/prompt-filters"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "secrets-json", "/home/u/.mandu/secrets.json"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "dashboard-env", "/home/u/.mandu/dashboard.env"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "state-root", "/home/u/.mandu/state"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "symbol-db", "/home/u/.mandu/state/mandu.db"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "symbol-db-test", "/home/u/.mandu/state/mandu-test.db"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "view-state", "/home/u/.mandu/state"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "workspaces", "/home/u/.mandu/state/workspaces"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "object-walks", "/home/u/.mandu/state/object-walks"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "paired-approvals", "/home/u/.mandu/state/paired-approvals"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "browser-profile", "/home/u/.mandu/state/browser"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "launch-logs", "/home/u/.mandu/state/launch-logs"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "events", "/home/u/.mandu/events"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "events-test", "/home/u/.mandu/events/test"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "runs-root", "/home/u/.mandu/runs"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "test-runs", "/home/u/.mandu/runs/test-runs.json"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "test-run-results", "/home/u/.mandu/runs/test-runs"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "live-drill-runs", "/home/u/.mandu/runs/drills/live"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "ci-runs", "/home/u/.mandu/runs/ci"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "matrix-results", "/home/u/.mandu/runs/matrix"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "eval-runs", "/home/u/.mandu/runs/eval"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "replay-drill-runs", "/home/u/.mandu/runs/drills/replay"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "drill-baselines", "/home/u/.mandu/runs/drills/baselines"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "dev-root", "/home/u/.mandu/dev"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "docker-e2e-home", "/home/u/.mandu/dev/docker-e2e-home"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "cache-root", "/home/u/.mandu/cache"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "object-twins", "/home/u/.mandu/cache/object-twins"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "ci-cache", "/home/u/.mandu/cache/ci"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "ci-host-out", "/home/u/.mandu/cache/ci/host-out"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "dashboard-cache", "/home/u/.mandu/cache/dashboard"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "update-check", "/home/u/.mandu/cache/update-check.json"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "runtime-dir", "/var/tmp/mandu"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "install-prefix", "/home/u/.local/share/mandu"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "exec-box-cache", "/home/u/.local/share/mandu/exec-box"),
        ("TMPDIR only for runtime", &[("TMPDIR", "/var/tmp/")], "/home/u", "bin-dir", "/home/u/.local/bin"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "mandu-home", "/home/u/.mandu"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "config-root", "/home/u/.mandu"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "config-toml", "/home/u/.mandu/config.toml"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "policy", "/home/u/.mandu/policy.yaml"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "packs", "/home/u/.mandu/packs"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "pack-keys", "/home/u/.mandu/pack-keys"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "prompt-filters", "/home/u/.mandu/prompt-filters"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "secrets-json", "/home/u/.mandu/secrets.json"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "dashboard-env", "/home/u/.mandu/dashboard.env"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "state-root", "/home/u/.mandu/state"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "symbol-db", "/home/u/.mandu/state/mandu.db"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "symbol-db-test", "/home/u/.mandu/state/mandu-test.db"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "view-state", "/home/u/.mandu/state"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "workspaces", "/home/u/.mandu/state/workspaces"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "object-walks", "/home/u/.mandu/state/object-walks"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "paired-approvals", "/home/u/.mandu/state/paired-approvals"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "browser-profile", "/home/u/.mandu/state/browser"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "launch-logs", "/home/u/.mandu/state/launch-logs"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "events", "/home/u/.mandu/events"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "events-test", "/home/u/.mandu/events/test"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "runs-root", "/home/u/.mandu/runs"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "test-runs", "/home/u/.mandu/runs/test-runs.json"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "test-run-results", "/home/u/.mandu/runs/test-runs"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "live-drill-runs", "/home/u/.mandu/runs/drills/live"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "ci-runs", "/home/u/.mandu/runs/ci"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "matrix-results", "/home/u/.mandu/runs/matrix"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "eval-runs", "/home/u/.mandu/runs/eval"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "replay-drill-runs", "/home/u/.mandu/runs/drills/replay"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "drill-baselines", "/home/u/.mandu/runs/drills/baselines"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "dev-root", "/home/u/.mandu/dev"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "docker-e2e-home", "/home/u/.mandu/dev/docker-e2e-home"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "cache-root", "/home/u/.mandu/cache"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "object-twins", "/home/u/.mandu/cache/object-twins"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "ci-cache", "/home/u/.mandu/cache/ci"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "ci-host-out", "/home/u/.mandu/cache/ci/host-out"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "dashboard-cache", "/home/u/.mandu/cache/dashboard"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "update-check", "/home/u/.mandu/cache/update-check.json"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "runtime-dir", "/o/runtime-dir"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "install-prefix", "/o/install-prefix"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "exec-box-cache", "/o/install-prefix/exec-box"),
        ("every override set", &[("MANDU_RUNTIME_DIR", "/o/runtime-dir"), ("MANDU_PREFIX", "/o/install-prefix"), ("MANDU_BIN_DIR", "/o/bin-dir")], "/home/u", "bin-dir", "/o/bin-dir"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "mandu-home", "/home/u/.mandu"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "config-root", "/home/u/.mandu"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "config-toml", "/home/u/.mandu/config.toml"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "policy", "/home/u/.mandu/policy.yaml"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "packs", "/home/u/.mandu/packs"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "pack-keys", "/home/u/.mandu/pack-keys"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "prompt-filters", "/home/u/.mandu/prompt-filters"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "secrets-json", "/home/u/.mandu/secrets.json"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "dashboard-env", "/home/u/.mandu/dashboard.env"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "state-root", "/home/u/.mandu/state"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "symbol-db", "/home/u/.mandu/state/mandu.db"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "symbol-db-test", "/home/u/.mandu/state/mandu-test.db"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "view-state", "/home/u/.mandu/state"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "workspaces", "/home/u/.mandu/state/workspaces"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "object-walks", "/home/u/.mandu/state/object-walks"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "paired-approvals", "/home/u/.mandu/state/paired-approvals"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "browser-profile", "/home/u/.mandu/state/browser"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "launch-logs", "/home/u/.mandu/state/launch-logs"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "events", "/home/u/.mandu/events"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "events-test", "/home/u/.mandu/events/test"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "runs-root", "/home/u/.mandu/runs"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "test-runs", "/home/u/.mandu/runs/test-runs.json"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "test-run-results", "/home/u/.mandu/runs/test-runs"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "live-drill-runs", "/home/u/.mandu/runs/drills/live"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "ci-runs", "/home/u/.mandu/runs/ci"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "matrix-results", "/home/u/.mandu/runs/matrix"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "eval-runs", "/home/u/.mandu/runs/eval"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "replay-drill-runs", "/home/u/.mandu/runs/drills/replay"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "drill-baselines", "/home/u/.mandu/runs/drills/baselines"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "dev-root", "/home/u/.mandu/dev"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "docker-e2e-home", "/home/u/.mandu/dev/docker-e2e-home"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "cache-root", "/home/u/.mandu/cache"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "object-twins", "/home/u/.mandu/cache/object-twins"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "ci-cache", "/home/u/.mandu/cache/ci"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "ci-host-out", "/home/u/.mandu/cache/ci/host-out"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "dashboard-cache", "/home/u/.mandu/cache/dashboard"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "update-check", "/home/u/.mandu/cache/update-check.json"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "runtime-dir", "/tmp/mandu"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "install-prefix", "/home/u/.local/share/mandu"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "exec-box-cache", "/home/u/.local/share/mandu/exec-box"),
        ("empty overrides fall through", &[("MANDU_RUNTIME_DIR", ""), ("MANDU_PREFIX", ""), ("MANDU_BIN_DIR", "")], "/home/u", "bin-dir", "/home/u/.local/bin"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "mandu-home", "/home/u/.mandu"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "config-root", "/home/u/.mandu"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "config-toml", "/home/u/.mandu/config.toml"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "policy", "/home/u/.mandu/policy.yaml"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "packs", "/home/u/.mandu/packs"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "pack-keys", "/home/u/.mandu/pack-keys"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "prompt-filters", "/home/u/.mandu/prompt-filters"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "secrets-json", "/home/u/.mandu/secrets.json"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "dashboard-env", "/home/u/.mandu/dashboard.env"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "state-root", "/home/u/.mandu/state"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "symbol-db", "/home/u/.mandu/state/mandu.db"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "symbol-db-test", "/home/u/.mandu/state/mandu-test.db"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "view-state", "/home/u/.mandu/state"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "workspaces", "/home/u/.mandu/state/workspaces"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "object-walks", "/home/u/.mandu/state/object-walks"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "paired-approvals", "/home/u/.mandu/state/paired-approvals"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "browser-profile", "/home/u/.mandu/state/browser"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "launch-logs", "/home/u/.mandu/state/launch-logs"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "events", "/home/u/.mandu/events"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "events-test", "/home/u/.mandu/events/test"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "runs-root", "/home/u/.mandu/runs"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "test-runs", "/home/u/.mandu/runs/test-runs.json"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "test-run-results", "/home/u/.mandu/runs/test-runs"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "live-drill-runs", "/home/u/.mandu/runs/drills/live"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "ci-runs", "/home/u/.mandu/runs/ci"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "matrix-results", "/home/u/.mandu/runs/matrix"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "eval-runs", "/home/u/.mandu/runs/eval"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "replay-drill-runs", "/home/u/.mandu/runs/drills/replay"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "drill-baselines", "/home/u/.mandu/runs/drills/baselines"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "dev-root", "/home/u/.mandu/dev"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "docker-e2e-home", "/home/u/.mandu/dev/docker-e2e-home"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "cache-root", "/home/u/.mandu/cache"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "object-twins", "/home/u/.mandu/cache/object-twins"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "ci-cache", "/home/u/.mandu/cache/ci"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "ci-host-out", "/home/u/.mandu/cache/ci/host-out"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "dashboard-cache", "/home/u/.mandu/cache/dashboard"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "update-check", "/home/u/.mandu/cache/update-check.json"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "runtime-dir", "/tmp/mandu"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "install-prefix", "/home/u/.local/share/mandu"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "exec-box-cache", "/home/u/.local/share/mandu/exec-box"),
        ("the retired per-path overrides move nothing", &[("MANDU_CONFIG", "/o/c"), ("MANDU_SECRETS", "/o/s"), ("MANDU_SYMBOL_DB", "/o/db"), ("MANDU_VIEW_STATE", "/o/v"), ("MANDU_EVENT_DIR", "/o/e"), ("MANDU_CI_RUNS_DIR", "/o/r"), ("MANDU_MATRIX_RESULTS_DIR", "/o/m"), ("MANDU_DOCKER_HOME", "/o/d"), ("MANDU_CI_CACHE", "/o/k")], "/home/u", "bin-dir", "/home/u/.local/bin"),
    ];

    #[test]
    fn every_entry_resolves_like_the_table() {
        for (label, env, home, name, want) in CASES {
            let get = |k: &str| env.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string());
            assert_eq!(path(name, &get, home).as_deref(), Some(*want), "{label}: {name}");
        }
    }
}
