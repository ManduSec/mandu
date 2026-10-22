// GENERATED FILE: do not edit. Source: scripts/paths/mandu-paths.mjs
// (docs/design/architecture/on-disk-layout.md §5). Regenerate with
// `node scripts/paths/mandu-paths.mjs generate`; scripts/test/mandu-paths.test.mjs fails
// when this copy differs from the table.

import { posix } from "node:path";

/** Environment lookups; a variable counts only when it is non-empty. */
export type ManduPathEnv = Readonly<Record<string, string | undefined>>;

export type ManduBaseName = "home" | "mandu" | "runtime" | "install";

export type ManduPathName =
  | "mandu-home"
  | "config-root"
  | "config-toml"
  | "policy"
  | "packs"
  | "pack-keys"
  | "prompt-filters"
  | "secrets-json"
  | "dashboard-env"
  | "state-root"
  | "symbol-db"
  | "symbol-db-test"
  | "view-state"
  | "workspaces"
  | "object-walks"
  | "paired-approvals"
  | "browser-profile"
  | "launch-logs"
  | "dashboard-account"
  | "last-scan"
  | "events"
  | "events-test"
  | "runs-root"
  | "test-runs"
  | "test-run-results"
  | "live-drill-runs"
  | "ci-runs"
  | "matrix-results"
  | "eval-runs"
  | "replay-drill-runs"
  | "drill-baselines"
  | "dev-root"
  | "docker-e2e-home"
  | "cache-root"
  | "object-twins"
  | "ci-cache"
  | "ci-host-out"
  | "dashboard-cache"
  | "update-check"
  | "runtime-dir"
  | "install-prefix"
  | "exec-box-cache"
  | "bin-dir";

export interface ManduBase {
  /** Variables tried in order; the first non-empty one is the base. */
  readonly chain: readonly string[];
  /** Else a path under the caller's home, or an absolute path. */
  readonly fallback: readonly ["home" | "abs", string];
}

export interface ManduPathEntry {
  readonly name: ManduPathName;
  /** A base, or the entry this one sits under. */
  readonly base: ManduBaseName | ManduPathName;
  readonly rel: string;
  readonly kind: "dir" | "file";
  /** The mode Mandu creates it with; null when it is not Mandu's to set. */
  readonly mode: number | null;
  /** Whether the agent may read it by its own path (on-disk-layout.md §4). */
  readonly agentReadable: boolean;
  /** The per-path override, used verbatim when non-empty. */
  readonly env: string | null;
}

export const MANDU_BASES: Readonly<Record<ManduBaseName, ManduBase>> = {
  "home": { chain: [], fallback: ["home", ""] },
  "mandu": { chain: ["MANDU_HOME"], fallback: ["home", ".mandu"] },
  "runtime": { chain: ["XDG_RUNTIME_DIR", "TMPDIR"], fallback: ["abs", "/tmp"] },
  "install": { chain: [], fallback: ["home", ".local/share"] },
};

export const MANDU_PATHS: Readonly<Record<ManduPathName, ManduPathEntry>> = {
  // the one Mandu home; the agent may neither read nor write it (§4)
  "mandu-home": { name: "mandu-home", base: "mandu", rel: "", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // what a human edits: the top level of the home
  "config-root": { name: "config-root", base: "mandu-home", rel: "", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // launcher defaults
  "config-toml": { name: "config-toml", base: "config-root", rel: "config.toml", kind: "file", mode: 0o600, agentReadable: false, env: null },
  // the law; MANDU_POLICY_FILE, the one per-path override left, is the arbiter's (§9)
  "policy": { name: "policy", base: "config-root", rel: "policy.yaml", kind: "file", mode: 0o600, agentReadable: false, env: null },
  // signed consumer packs
  "packs": { name: "packs", base: "config-root", rel: "packs", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // trusted pack keys
  "pack-keys": { name: "pack-keys", base: "config-root", rel: "pack-keys", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // the person's prompt filter packs (confidentiality-plan-15 §4.2)
  "prompt-filters": { name: "prompt-filters", base: "config-root", rel: "prompt-filters", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // developer API keys
  "secrets-json": { name: "secrets-json", base: "config-root", rel: "secrets.json", kind: "file", mode: 0o600, agentReadable: false, env: null },
  // a resident dashboard's EnvironmentFile (DASHBOARD_BASIC_AUTH); the live suites' auth reads it (dashboard.md §6)
  "dashboard-env": { name: "dashboard-env", base: "config-root", rel: "dashboard.env", kind: "file", mode: 0o600, agentReadable: false, env: null },
  // durable: losing it loses approvals and history
  "state-root": { name: "state-root", base: "mandu-home", rel: "state", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // symbol table + every durable policy table; holds originals
  "symbol-db": { name: "symbol-db", base: "state-root", rel: "mandu.db", kind: "file", mode: 0o600, agentReadable: false, env: null },
  // the test tenant's DB
  "symbol-db-test": { name: "symbol-db-test", base: "state-root", rel: "mandu-test.db", kind: "file", mode: 0o600, agentReadable: false, env: null },
  // fs-sync's state base
  "view-state": { name: "view-state", base: "state-root", rel: "", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // shadow repos + AgentView; the integrity modes carve the AgentView out (§4)
  "workspaces": { name: "workspaces", base: "view-state", rel: "workspaces", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // git history-walk cache; names protected blobs
  "object-walks": { name: "object-walks", base: "state-root", rel: "object-walks", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // one-shot approvals for paired evaluation runs
  "paired-approvals": { name: "paired-approvals", base: "state-root", rel: "paired-approvals", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // the Chrome profile `mandu --browser` starts the agent's browser with (devtools-relay.md §6.4): the person's logins and cookies on the sites the agent uses
  "browser-profile": { name: "browser-profile", base: "state-root", rel: "browser", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // one log per launch: every launch line and Mandu helper message the terminal did not show by default; the last 20 kept (packaging.md §5 "Launch display policy")
  "launch-logs": { name: "launch-logs", base: "state-root", rel: "launch-logs", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // the Mandu dashboard account: a username and a salted scrypt hash of its password, never the password (dashboard.md §6.z); `mandu dashboard --set-password` writes it
  "dashboard-account": { name: "dashboard-account", base: "state-root", rel: "dashboard-account.json", kind: "file", mode: 0o600, agentReadable: false, env: null },
  // the last `mandu scan`'s report: kinds, masks, names, files, counts, hosts, dates, never a value (confidentiality-plan-17 §3 item 12)
  "last-scan": { name: "last-scan", base: "state-root", rel: "last-scan.json", kind: "file", mode: 0o600, agentReadable: false, env: null },
  // session history; holds originals
  "events": { name: "events", base: "mandu-home", rel: "events", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // the test tenant's events
  "events-test": { name: "events-test", base: "events", rel: "test", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // results the dashboard reads; developer hosts only
  "runs-root": { name: "runs-root", base: "mandu-home", rel: "runs", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // the dashboard's test-run history
  "test-runs": { name: "test-runs", base: "runs-root", rel: "test-runs.json", kind: "file", mode: 0o600, agentReadable: false, env: null },
  // each dashboard Tests-tab run's summary.json, junit.xml and logs/ (run-suites --out), by run id: what the Coverage view attributes per suite (dashboard.md §4.29)
  "test-run-results": { name: "test-run-results", base: "runs-root", rel: "test-runs", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // live-drill run records, the drill runner's store (test-reorganization.md §4; runs/watch before 2026-10-02)
  "live-drill-runs": { name: "live-drill-runs", base: "runs-root", rel: "drills/live", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // CI run results the dashboard reads
  "ci-runs": { name: "ci-runs", base: "runs-root", rel: "ci", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // OS-matrix run results
  "matrix-results": { name: "matrix-results", base: "runs-root", rel: "matrix", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // evaluation run outputs (the operator's --out wins)
  "eval-runs": { name: "eval-runs", base: "runs-root", rel: "eval", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // replay-drill run records (test-reorganization.md §6.7)
  "replay-drill-runs": { name: "replay-drill-runs", base: "runs-root", rel: "drills/replay", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // the plain-agent baseline cache of the replay drills (test-reorganization.md §6.3)
  "drill-baselines": { name: "drill-baselines", base: "runs-root", rel: "drills/baselines", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // developer-only; made only when used
  "dev-root": { name: "dev-root", base: "mandu-home", rel: "dev", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // developer-only credentials
  "docker-e2e-home": { name: "docker-e2e-home", base: "dev-root", rel: "docker-e2e-home", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // regenerable; safe to delete
  "cache-root": { name: "cache-root", base: "mandu-home", rel: "cache", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // sanitized git packs; the agent reads them only through the bind or fd
  "object-twins": { name: "object-twins", base: "cache-root", rel: "object-twins", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // CI VM images
  "ci-cache": { name: "ci-cache", base: "cache-root", rel: "ci", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // a host-mode CI run's output before it is collected
  "ci-host-out": { name: "ci-host-out", base: "ci-cache", rel: "host-out", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // the dashboard's persisted listing summaries (record heads, run metas, events-log counts), each valid only at its file's identity (dashboard.md §4.30)
  "dashboard-cache": { name: "dashboard-cache", base: "cache-root", rel: "dashboard", kind: "dir", mode: 0o700, agentReadable: false, env: null },
  // the last release check's answer, so a launch prints the update notice without waiting on the network (packaging.md §11.5)
  "update-check": { name: "update-check", base: "cache-root", rel: "update-check.json", kind: "file", mode: 0o600, agentReadable: false, env: null },
  // sockets, instances, per-launch scope dirs; per-boot
  "runtime-dir": { name: "runtime-dir", base: "runtime", rel: "mandu", kind: "dir", mode: 0o700, agentReadable: true, env: "MANDU_RUNTIME_DIR" },
  // the installed program; the agent runs parts of it
  "install-prefix": { name: "install-prefix", base: "install", rel: "mandu", kind: "dir", mode: 0o755, agentReadable: true, env: "MANDU_PREFIX" },
  // staged exec-box applier when the runtime dir is under /tmp; the agent runs it, never writes it
  "exec-box-cache": { name: "exec-box-cache", base: "install-prefix", rel: "exec-box", kind: "dir", mode: 0o755, agentReadable: true, env: null },
  // where the installer writes the mandu wrapper
  "bin-dir": { name: "bin-dir", base: "home", rel: ".local/bin", kind: "dir", mode: null, agentReadable: true, env: "MANDU_BIN_DIR" },
};

function isBase(name: string): name is ManduBaseName {
  return Object.prototype.hasOwnProperty.call(MANDU_BASES, name);
}

/** A base for `env` and `home`. Pure: reads no file. */
export function manduBase(name: ManduBaseName, env: ManduPathEnv, home: string): string {
  const b = MANDU_BASES[name];
  for (const k of b.chain) {
    const v = env[k];
    if (v) return v;
  }
  return b.fallback[0] === "home" ? posix.join(home, b.fallback[1]) : b.fallback[1];
}

/** An entry's path for `env` and `home`: its override when set, else its
 *  parent joined with `rel`. Pure: reads no file. */
export function manduPath(name: ManduPathName, env: ManduPathEnv, home: string): string {
  const e = MANDU_PATHS[name];
  if (e.env !== null) {
    const v = env[e.env];
    if (v) return v;
  }
  const parent = isBase(e.base) ? manduBase(e.base, env, home) : manduPath(e.base, env, home);
  return posix.join(parent, e.rel);
}
