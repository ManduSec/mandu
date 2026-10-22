#!/usr/bin/env node
// scripts/paths/mandu-paths.mjs — THE table of where Mandu keeps its files
// (docs/design/architecture/on-disk-layout.md §5), and the generator of its per-package
// copies.
//
// Since phase 3c (2026-09-29) every location Mandu stores is in the one Mandu
// home, the `mandu` base (`MANDU_HOME`, else `$HOME/.mandu`); outside it are
// only the per-boot runtime dir and the install. There is no migration from
// the layout before it (§6: a clean start). Callers name entries, never roots.
//
// The packages stay standalone (docs/development.md): each one that resolves a path gets
// a GENERATED copy of the table and its resolver, never an import of this file.
//
//   node scripts/paths/mandu-paths.mjs generate   write every copy
//   node scripts/paths/mandu-paths.mjs check      exit 1 when a copy is stale
//
// scripts/test/mandu-paths.test.mjs runs `check` and pins the table;
// tests/stack/mandu-paths-parity.test.ts proves each TS copy
// resolves like this file; the Rust copy carries its own generated cases.
//
// Resolution. A resolver takes `(env, home)` and touches no file. An
// environment variable counts only when it is non-empty (the `||` the
// hand-written rules use). An entry's own override (`env`) wins verbatim;
// else its parent (a base or another entry) is resolved and `rel` joined with
// node's `path.posix.join`. A base tries its `chain` of variables in order,
// else its fallback: a path under `home`, or an absolute path.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

// ── the table ─────────────────────────────────────────────────────────────────

/** The roots. `fallback`: ["home", rel] (under the caller's home) or
 *  ["abs", path]. */
export const BASES = {
  home: { chain: [], fallback: ["home", ""] },
  mandu: { chain: ["MANDU_HOME"], fallback: ["home", ".mandu"] },
  runtime: { chain: ["XDG_RUNTIME_DIR", "TMPDIR"], fallback: ["abs", "/tmp"] },
  install: { chain: [], fallback: ["home", ".local/share"] },
};

const DIR = 0o700;
const FILE = 0o600;

/** One row per location. `base` names a base or an earlier entry; `mode` is
 *  what Mandu creates it with (null: not Mandu's to set); `agentReadable` is
 *  whether the agent may read it by its own path (§4); `env` is the
 *  per-path override. Since phase 4 (2026-09-29) only the locations outside
 *  the home have one: MANDU_HOME alone moves anything in it (§9 1); a
 *  component that must place a store elsewhere is told by a flag
 *  (the arbiter's --symbol-db / --event-dir), never by the environment. */
function p(name, base, rel, kind, mode, agentReadable, env, note) {
  return { name, base, rel, kind, mode, agentReadable, env, note };
}

export const PATHS = [
  // ~/.mandu (MANDU_HOME): the one Mandu home (§3)
  p("mandu-home", "mandu", "", "dir", DIR, false, null, "the one Mandu home; the agent may neither read nor write it (§4)"),
  // the top level: what a human edits
  p("config-root", "mandu-home", "", "dir", DIR, false, null, "what a human edits: the top level of the home"),
  p("config-toml", "config-root", "config.toml", "file", FILE, false, null, "launcher defaults"),
  p("policy", "config-root", "policy.yaml", "file", FILE, false, null, "the law; MANDU_POLICY_FILE, the one per-path override left, is the arbiter's (§9)"),
  p("packs", "config-root", "packs", "dir", DIR, false, null, "signed consumer packs"),
  p("pack-keys", "config-root", "pack-keys", "dir", DIR, false, null, "trusted pack keys"),
  p("prompt-filters", "config-root", "prompt-filters", "dir", DIR, false, null, "the person's prompt filter packs (confidentiality-plan-15 §4.2)"),
  p("secrets-json", "config-root", "secrets.json", "file", FILE, false, null, "developer API keys"),
  p("dashboard-env", "config-root", "dashboard.env", "file", FILE, false, null, "a resident dashboard's EnvironmentFile (DASHBOARD_BASIC_AUTH); the live suites' auth reads it (dashboard.md §6)"),
  // state/: durable
  p("state-root", "mandu-home", "state", "dir", DIR, false, null, "durable: losing it loses approvals and history"),
  p("symbol-db", "state-root", "mandu.db", "file", FILE, false, null, "symbol table + every durable policy table; holds originals"),
  p("symbol-db-test", "state-root", "mandu-test.db", "file", FILE, false, null, "the test tenant's DB"),
  p("view-state", "state-root", "", "dir", DIR, false, null, "fs-sync's state base"),
  p("workspaces", "view-state", "workspaces", "dir", DIR, false, null, "shadow repos + AgentView; the integrity modes carve the AgentView out (§4)"),
  p("object-walks", "state-root", "object-walks", "dir", DIR, false, null, "git history-walk cache; names protected blobs"),
  p("paired-approvals", "state-root", "paired-approvals", "dir", DIR, false, null, "one-shot approvals for paired evaluation runs"),
  p("browser-profile", "state-root", "browser", "dir", DIR, false, null, "the Chrome profile `mandu --browser` starts the agent's browser with (devtools-relay.md §6.4): the person's logins and cookies on the sites the agent uses"),
  p("launch-logs", "state-root", "launch-logs", "dir", DIR, false, null, "one log per launch: every launch line and Mandu helper message the terminal did not show by default; the last 20 kept (packaging.md §5 \"Launch display policy\")"),
  p("dashboard-account", "state-root", "dashboard-account.json", "file", FILE, false, null, "the Mandu dashboard account: a username and a salted scrypt hash of its password, never the password (dashboard.md §6.z); `mandu dashboard --set-password` writes it"),
  p("last-scan", "state-root", "last-scan.json", "file", FILE, false, null, "the last `mandu scan`'s report: kinds, masks, names, files, counts, hosts, dates, never a value (confidentiality-plan-17 §3 item 12)"),
  // events/: history, holds originals
  p("events", "mandu-home", "events", "dir", DIR, false, null, "session history; holds originals"),
  p("events-test", "events", "test", "dir", DIR, false, null, "the test tenant's events"),
  // runs/: results the dashboard reads, made only when used
  p("runs-root", "mandu-home", "runs", "dir", DIR, false, null, "results the dashboard reads; developer hosts only"),
  p("test-runs", "runs-root", "test-runs.json", "file", FILE, false, null, "the dashboard's test-run history"),
  p("test-run-results", "runs-root", "test-runs", "dir", DIR, false, null, "each dashboard Tests-tab run's summary.json, junit.xml and logs/ (run-suites --out), by run id: what the Coverage view attributes per suite (dashboard.md §4.29)"),
  p("live-drill-runs", "runs-root", "drills/live", "dir", DIR, false, null, "live-drill run records, the drill runner's store (test-reorganization.md §4; runs/watch before 2026-10-02)"),
  p("ci-runs", "runs-root", "ci", "dir", DIR, false, null, "CI run results the dashboard reads"),
  p("matrix-results", "runs-root", "matrix", "dir", DIR, false, null, "OS-matrix run results"),
  p("eval-runs", "runs-root", "eval", "dir", DIR, false, null, "evaluation run outputs (the operator's --out wins)"),
  p("replay-drill-runs", "runs-root", "drills/replay", "dir", DIR, false, null, "replay-drill run records (test-reorganization.md §6.7)"),
  p("drill-baselines", "runs-root", "drills/baselines", "dir", DIR, false, null, "the plain-agent baseline cache of the replay drills (test-reorganization.md §6.3)"),
  // dev/: developer-only
  p("dev-root", "mandu-home", "dev", "dir", DIR, false, null, "developer-only; made only when used"),
  p("docker-e2e-home", "dev-root", "docker-e2e-home", "dir", DIR, false, null, "developer-only credentials"),
  // cache/: regenerable, safe to delete
  p("cache-root", "mandu-home", "cache", "dir", DIR, false, null, "regenerable; safe to delete"),
  p("object-twins", "cache-root", "object-twins", "dir", DIR, false, null, "sanitized git packs; the agent reads them only through the bind or fd"),
  p("ci-cache", "cache-root", "ci", "dir", DIR, false, null, "CI VM images"),
  p("ci-host-out", "ci-cache", "host-out", "dir", DIR, false, null, "a host-mode CI run's output before it is collected"),
  p("dashboard-cache", "cache-root", "dashboard", "dir", DIR, false, null, "the dashboard's persisted listing summaries (record heads, run metas, events-log counts), each valid only at its file's identity (dashboard.md §4.30)"),
  p("update-check", "cache-root", "update-check.json", "file", FILE, false, null, "the last release check's answer, so a launch prints the update notice without waiting on the network (packaging.md §11.5)"),
  // outside the home
  p("runtime-dir", "runtime", "mandu", "dir", DIR, true, "MANDU_RUNTIME_DIR", "sockets, instances, per-launch scope dirs; per-boot"),
  p("install-prefix", "install", "mandu", "dir", 0o755, true, "MANDU_PREFIX", "the installed program; the agent runs parts of it"),
  // Not in the home: the agent RUNS the staged applier (inside its box), and
  // the home is closed to it (§4); the install prefix is readable and
  // write-protected, which is exactly what a staged copy of Mandu's own
  // binary needs.
  p("exec-box-cache", "install-prefix", "exec-box", "dir", 0o755, true, null, "staged exec-box applier when the runtime dir is under /tmp; the agent runs it, never writes it"),
  p("bin-dir", "home", ".local/bin", "dir", null, true, "MANDU_BIN_DIR", "where the installer writes the mandu wrapper"),
];

const BY_NAME = new Map(PATHS.map((e) => [e.name, e]));

// ── the reference resolver ────────────────────────────────────────────────────

/** A base for `env` and `home`. */
export function resolveBase(name, env, home) {
  const b = BASES[name];
  if (!b) throw new Error(`unknown base ${name}`);
  for (const k of b.chain) if (env[k]) return env[k];
  return b.fallback[0] === "home" ? posix.join(home, b.fallback[1]) : b.fallback[1];
}

/** An entry's path for `env` and `home`. */
export function resolvePath(name, env, home) {
  const e = BY_NAME.get(name);
  if (!e) throw new Error(`unknown path ${name}`);
  if (e.env !== null && env[e.env]) return env[e.env];
  const parent = e.base in BASES ? resolveBase(e.base, env, home) : resolvePath(e.base, env, home);
  return posix.join(parent, e.rel);
}

/** Problems with the table itself (empty when it is sound). */
export function tableProblems() {
  const out = [];
  const seen = new Set();
  for (const e of PATHS) {
    if (!/^[a-z][a-z0-9-]*$/.test(e.name)) out.push(`${e.name}: name must be lower-case kebab`);
    if (seen.has(e.name) || e.name in BASES) out.push(`${e.name}: duplicate name`);
    if (!(e.base in BASES) && !seen.has(e.base)) out.push(`${e.name}: base ${e.base} is neither a base nor an earlier entry`);
    seen.add(e.name);
    if (e.rel.startsWith("/") || e.rel.split("/").includes("..")) out.push(`${e.name}: rel must stay under its base`);
    if (e.kind !== "dir" && e.kind !== "file") out.push(`${e.name}: kind is dir or file`);
    if (e.mode !== null && !(Number.isInteger(e.mode) && e.mode >= 0 && e.mode <= 0o777)) out.push(`${e.name}: bad mode`);
    if (typeof e.agentReadable !== "boolean") out.push(`${e.name}: agentReadable is a boolean`);
    if (e.env !== null && !/^[A-Z][A-Z0-9_]*$/.test(e.env)) out.push(`${e.name}: bad env name`);
    const parent = BY_NAME.get(e.base);
    if (parent && parent.kind === "file") out.push(`${e.name}: parent ${e.base} is a file`);
  }
  return out;
}

// ── fixtures: the env shapes every copy is checked on ─────────────────────────

/** [label, env, home]. Every variable the table reads appears set and unset,
 *  plus the empty-string and trailing-slash cases. */
export const FIXTURES = [
  ["home only", {}, "/home/u"],
  ["home with trailing slash", {}, "/home/u/"],
  ["root home", {}, "/"],
  [
    "every XDG root set",
    { XDG_STATE_HOME: "/x/state", XDG_CONFIG_HOME: "/x/config", XDG_CACHE_HOME: "/x/cache", XDG_RUNTIME_DIR: "/run/user/1000", XDG_DATA_HOME: "/x/data" },
    "/home/u",
  ],
  [
    "empty XDG values fall through",
    { MANDU_HOME: "", XDG_STATE_HOME: "", XDG_CONFIG_HOME: "", XDG_CACHE_HOME: "", XDG_RUNTIME_DIR: "", TMPDIR: "" },
    "/home/u",
  ],
  ["MANDU_HOME moves the home", { MANDU_HOME: "/m/" }, "/home/u"],
  ["TMPDIR only for runtime", { TMPDIR: "/var/tmp/" }, "/home/u"],
  [
    "every override set",
    Object.fromEntries(PATHS.filter((e) => e.env !== null).map((e) => [e.env, `/o/${e.name}`])),
    "/home/u",
  ],
  ["empty overrides fall through", Object.fromEntries(PATHS.filter((e) => e.env !== null).map((e) => [e.env, ""])), "/home/u"],
  [
    "the retired per-path overrides move nothing",
    {
      MANDU_CONFIG: "/o/c", MANDU_SECRETS: "/o/s", MANDU_SYMBOL_DB: "/o/db", MANDU_VIEW_STATE: "/o/v",
      MANDU_EVENT_DIR: "/o/e", MANDU_CI_RUNS_DIR: "/o/r", MANDU_MATRIX_RESULTS_DIR: "/o/m",
      MANDU_DOCKER_HOME: "/o/d", MANDU_CI_CACHE: "/o/k",
    },
    "/home/u",
  ],
];

// ── generators ────────────────────────────────────────────────────────────────

const SOURCE = "scripts/paths/mandu-paths.mjs";

/** The generated copies, repo-relative. */
export const COPIES = [
  { lang: "ts", path: "arbiter/src/generated/mandu-paths.ts" },
  { lang: "ts", path: "launcher/src/generated/mandu-paths.ts" },
  { lang: "ts", path: "dashboard/src/generated/mandu-paths.ts" },
  { lang: "ts", path: "fs-sync/src/generated/mandu-paths.ts" },
  { lang: "ts", path: "eval/lib/generated/mandu-paths.ts" },
  { lang: "rust", path: "interceptors/mandu-paths/src/lib.rs" },
  { lang: "sh", path: "scripts/paths/mandu-paths.sh" },
];

const q = (s) => JSON.stringify(s);
const octal = (m) => (m === null ? "null" : `0o${m.toString(8)}`);

function headerLines(comment) {
  return [
    `${comment} GENERATED FILE: do not edit. Source: ${SOURCE}`,
    `${comment} (docs/design/architecture/on-disk-layout.md §5). Regenerate with`,
    `${comment} \`node ${SOURCE} generate\`; scripts/test/mandu-paths.test.mjs fails`,
    `${comment} when this copy differs from the table.`,
  ];
}

export function generateTs() {
  const L = [...headerLines("//"), ""];
  L.push(`import { posix } from "node:path";`, "");
  L.push("/** Environment lookups; a variable counts only when it is non-empty. */");
  L.push("export type ManduPathEnv = Readonly<Record<string, string | undefined>>;", "");
  L.push(`export type ManduBaseName = ${Object.keys(BASES).map(q).join(" | ")};`, "");
  L.push("export type ManduPathName =");
  PATHS.forEach((e, i) => L.push(`  | ${q(e.name)}${i === PATHS.length - 1 ? ";" : ""}`));
  L.push("");
  L.push("export interface ManduBase {");
  L.push("  /** Variables tried in order; the first non-empty one is the base. */");
  L.push("  readonly chain: readonly string[];");
  L.push("  /** Else a path under the caller's home, or an absolute path. */");
  L.push(`  readonly fallback: readonly ["home" | "abs", string];`);
  L.push("}", "");
  L.push("export interface ManduPathEntry {");
  L.push("  readonly name: ManduPathName;");
  L.push("  /** A base, or the entry this one sits under. */");
  L.push("  readonly base: ManduBaseName | ManduPathName;");
  L.push("  readonly rel: string;");
  L.push(`  readonly kind: "dir" | "file";`);
  L.push("  /** The mode Mandu creates it with; null when it is not Mandu's to set. */");
  L.push("  readonly mode: number | null;");
  L.push("  /** Whether the agent may read it by its own path (on-disk-layout.md §4). */");
  L.push("  readonly agentReadable: boolean;");
  L.push("  /** The per-path override, used verbatim when non-empty. */");
  L.push("  readonly env: string | null;");
  L.push("}", "");
  L.push("export const MANDU_BASES: Readonly<Record<ManduBaseName, ManduBase>> = {");
  for (const [name, b] of Object.entries(BASES)) {
    L.push(`  ${q(name)}: { chain: [${b.chain.map(q).join(", ")}], fallback: [${q(b.fallback[0])}, ${q(b.fallback[1])}] },`);
  }
  L.push("};", "");
  L.push("export const MANDU_PATHS: Readonly<Record<ManduPathName, ManduPathEntry>> = {");
  for (const e of PATHS) {
    L.push(`  // ${e.note}`);
    L.push(
      `  ${q(e.name)}: { name: ${q(e.name)}, base: ${q(e.base)}, rel: ${q(e.rel)}, kind: ${q(e.kind)}, ` +
        `mode: ${octal(e.mode)}, agentReadable: ${e.agentReadable}, env: ${e.env === null ? "null" : q(e.env)} },`,
    );
  }
  L.push("};", "");
  L.push("function isBase(name: string): name is ManduBaseName {");
  L.push("  return Object.prototype.hasOwnProperty.call(MANDU_BASES, name);");
  L.push("}", "");
  L.push("/** A base for `env` and `home`. Pure: reads no file. */");
  L.push("export function manduBase(name: ManduBaseName, env: ManduPathEnv, home: string): string {");
  L.push("  const b = MANDU_BASES[name];");
  L.push("  for (const k of b.chain) {");
  L.push("    const v = env[k];");
  L.push("    if (v) return v;");
  L.push("  }");
  L.push(`  return b.fallback[0] === "home" ? posix.join(home, b.fallback[1]) : b.fallback[1];`);
  L.push("}", "");
  L.push("/** An entry's path for `env` and `home`: its override when set, else its");
  L.push(" *  parent joined with `rel`. Pure: reads no file. */");
  L.push("export function manduPath(name: ManduPathName, env: ManduPathEnv, home: string): string {");
  L.push("  const e = MANDU_PATHS[name];");
  L.push("  if (e.env !== null) {");
  L.push("    const v = env[e.env];");
  L.push("    if (v) return v;");
  L.push("  }");
  L.push("  const parent = isBase(e.base) ? manduBase(e.base, env, home) : manduPath(e.base, env, home);");
  L.push("  return posix.join(parent, e.rel);");
  L.push("}", "");
  return L.join("\n");
}

function rustConst(name) {
  return name.toUpperCase().replace(/-/g, "_");
}

export function generateRust() {
  const L = [...headerLines("//!"), "//!", "//! Pure resolvers: `(env, home)` in, a path string out, no file access."];
  L.push("//! Paths are joined like node's `path.posix.join`, so every copy agrees", "//! byte for byte.", "");
  L.push("/// Where a base falls back to when no variable in its chain is set.");
  L.push("#[derive(Debug, Clone, Copy, PartialEq, Eq)]");
  L.push("pub enum Fallback {");
  L.push("    /// A path under the caller's home.");
  L.push("    Home(&'static str),");
  L.push("    /// An absolute path.");
  L.push("    Abs(&'static str),");
  L.push("}", "");
  L.push("#[derive(Debug, Clone, Copy, PartialEq, Eq)]");
  L.push("pub struct Base {");
  L.push("    pub name: &'static str,");
  L.push("    /// Variables tried in order; the first non-empty one is the base.");
  L.push("    pub chain: &'static [&'static str],");
  L.push("    pub fallback: Fallback,");
  L.push("}", "");
  L.push("#[derive(Debug, Clone, Copy, PartialEq, Eq)]");
  L.push("pub enum Kind {");
  L.push("    Dir,");
  L.push("    File,");
  L.push("}", "");
  L.push("#[derive(Debug, Clone, Copy, PartialEq, Eq)]");
  L.push("pub struct Entry {");
  L.push("    pub name: &'static str,");
  L.push("    /// A base, or the entry this one sits under.");
  L.push("    pub base: &'static str,");
  L.push("    pub rel: &'static str,");
  L.push("    pub kind: Kind,");
  L.push("    /// The mode Mandu creates it with; `None` when it is not Mandu's to set.");
  L.push("    pub mode: Option<u32>,");
  L.push("    /// Whether the agent may read it by its own path (on-disk-layout.md §4).");
  L.push("    pub agent_readable: bool,");
  L.push("    /// The per-path override, used verbatim when non-empty.");
  L.push("    pub env: Option<&'static str>,");
  L.push("}", "");
  L.push("/// Entry names, for callers.");
  L.push("pub mod names {");
  for (const e of PATHS) L.push(`    pub const ${rustConst(e.name)}: &str = ${q(e.name)};`);
  L.push("}", "");
  L.push("pub const BASES: &[Base] = &[");
  for (const [name, b] of Object.entries(BASES)) {
    const fb = b.fallback[0] === "home" ? `Fallback::Home(${q(b.fallback[1])})` : `Fallback::Abs(${q(b.fallback[1])})`;
    L.push(`    Base { name: ${q(name)}, chain: &[${b.chain.map(q).join(", ")}], fallback: ${fb} },`);
  }
  L.push("];", "");
  L.push("pub const PATHS: &[Entry] = &[");
  for (const e of PATHS) {
    L.push(`    // ${e.note}`);
    L.push(
      `    Entry { name: ${q(e.name)}, base: ${q(e.base)}, rel: ${q(e.rel)}, kind: Kind::${e.kind === "dir" ? "Dir" : "File"}, ` +
        `mode: ${e.mode === null ? "None" : `Some(${octal(e.mode)})`}, agent_readable: ${e.agentReadable}, ` +
        `env: ${e.env === null ? "None" : `Some(${q(e.env)})`} },`,
    );
  }
  L.push("];", "");
  L.push(RUST_BODY);
  L.push("#[cfg(test)]");
  L.push("mod generated_cases {");
  L.push("    use super::*;", "");
  L.push("    type Case = (&'static str, &'static [(&'static str, &'static str)], &'static str, &'static str, &'static str);", "");
  L.push("    /// (fixture, env, home, entry, what the table resolves it to).");
  L.push("    const CASES: &[Case] = &[");
  for (const [label, env, home] of FIXTURES) {
    const envLit = `&[${Object.entries(env).map(([k, v]) => `(${q(k)}, ${q(v)})`).join(", ")}]`;
    for (const e of PATHS) L.push(`        (${q(label)}, ${envLit}, ${q(home)}, ${q(e.name)}, ${q(resolvePath(e.name, env, home))}),`);
  }
  L.push("    ];", "");
  L.push("    #[test]");
  L.push("    fn every_entry_resolves_like_the_table() {");
  L.push("        for (label, env, home, name, want) in CASES {");
  L.push("            let get = |k: &str| env.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string());");
  L.push("            assert_eq!(path(name, &get, home).as_deref(), Some(*want), \"{label}: {name}\");");
  L.push("        }");
  L.push("    }");
  L.push("}", "");
  return L.join("\n");
}

const RUST_BODY = `/// The base named \`name\`, or \`None\` for an unknown name.
pub fn base_def(name: &str) -> Option<&'static Base> {
    BASES.iter().find(|b| b.name == name)
}

/// The entry named \`name\`, or \`None\` for an unknown name.
pub fn entry(name: &str) -> Option<&'static Entry> {
    PATHS.iter().find(|e| e.name == name)
}

fn set(env: &dyn Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    env(key).filter(|v| !v.is_empty())
}

/// A base for \`env\` and \`home\`. Pure: reads no file.
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

/// An entry's path for \`env\` and \`home\`: its override when set, else its
/// parent joined with \`rel\`. Pure: reads no file.
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

/// node's \`path.posix.join(a, b)\`.
pub fn join(a: &str, b: &str) -> String {
    let joined = match (a.is_empty(), b.is_empty()) {
        (true, true) => return ".".to_string(),
        (false, true) => a.to_string(),
        (true, false) => b.to_string(),
        (false, false) => format!("{a}/{b}"),
    };
    normalize(&joined)
}

/// node's \`path.posix.normalize\`.
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
`;

// ── the shell copy ────────────────────────────────────────────────────────────

/** A bash test for "the variable is set and non-empty". */
const shSet = (k) => `[ -n "\${${k}:-}" ]`;

export function generateSh() {
  const L = ["# shellcheck shell=bash", ...headerLines("#")];
  L.push("#", "# Source it, then `mandu_path <name> [home]` / `mandu_base <name> [home]`");
  L.push("# print the path (home defaults to $HOME). Pure: reads no file. Paths are");
  L.push("# joined like node's `path.posix.join`, so every copy agrees byte for byte.", "");
  L.push(SH_BODY);
  L.push("mandu_base() {");
  L.push('  local h="${2-$HOME}"');
  L.push('  case "$1" in');
  for (const [name, b] of Object.entries(BASES)) {
    const fb = b.fallback[0] === "home" ? `_mandu_join "$h" ${q(b.fallback[1])}` : `printf '%s\\n' ${q(b.fallback[1])}`;
    if (b.chain.length === 0) {
      L.push(`    ${name}) ${fb} ;;`);
    } else {
      const arms = b.chain.map((k, i) => `${i === 0 ? "if" : "elif"} ${shSet(k)}; then printf '%s\\n' "$${k}"`);
      L.push(`    ${name}) ${arms.join("; ")}; else ${fb}; fi ;;`);
    }
  }
  L.push(`    *) printf 'mandu_base: unknown base %s\\n' "$1" >&2; return 2 ;;`);
  L.push("  esac");
  L.push("}", "");
  L.push("mandu_path() {");
  L.push('  local h="${2-$HOME}" parent');
  L.push('  case "$1" in');
  for (const e of PATHS) {
    const parentCmd = e.base in BASES ? `mandu_base ${e.base} "$h"` : `mandu_path ${e.base} "$h"`;
    const joined = `parent="$(${parentCmd})" && _mandu_join "$parent" ${q(e.rel)}`;
    if (e.env === null) L.push(`    ${e.name}) ${joined} ;;`);
    else L.push(`    ${e.name}) if ${shSet(e.env)}; then printf '%s\\n' "$${e.env}"; else ${joined}; fi ;;`);
  }
  L.push(`    *) printf 'mandu_path: unknown path %s\\n' "$1" >&2; return 2 ;;`);
  L.push("  esac");
  L.push("}", "");
  L.push("# Every entry name, for callers that list them.");
  L.push(`MANDU_PATH_NAMES=(${PATHS.map((e) => e.name).join(" ")})`, "");
  return L.join("\n");
}

const SH_BODY = `# node's path.posix.normalize.
_mandu_normalize() {
  local p="$1" abs="" trail="" seg s IFS=/
  if [ -z "$p" ]; then printf '.\\n'; return; fi
  [ "\${p:0:1}" = / ] && abs=1
  [ "\${p: -1}" = / ] && trail=1
  local -a parts=() out=()
  read -r -a parts <<< "$p"
  for seg in "\${parts[@]}"; do
    case "$seg" in
      "" | .) ;;
      ..)
        if [ "\${#out[@]}" -gt 0 ] && [ "\${out[\${#out[@]}-1]}" != .. ]; then
          unset "out[\${#out[@]}-1]"
          out=("\${out[@]}")
        elif [ -z "$abs" ]; then
          out+=(..)
        fi ;;
      *) out+=("$seg") ;;
    esac
  done
  s="\${out[*]}"
  if [ -z "$s" ]; then
    if [ -n "$abs" ]; then printf '/\\n'; elif [ -n "$trail" ]; then printf './\\n'; else printf '.\\n'; fi
    return
  fi
  [ -n "$trail" ] && s="$s/"
  [ -n "$abs" ] && s="/$s"
  printf '%s\\n' "$s"
}

# node's path.posix.join(a, b).
_mandu_join() {
  if [ -z "$1" ] && [ -z "$2" ]; then printf '.\\n'
  elif [ -z "$2" ]; then _mandu_normalize "$1"
  elif [ -z "$1" ]; then _mandu_normalize "$2"
  else _mandu_normalize "$1/$2"
  fi
}
`;

// ── CLI ───────────────────────────────────────────────────────────────────────

/** Each copy with the text it must hold. */
export function expectedCopies() {
  const text = { ts: generateTs(), rust: generateRust(), sh: generateSh() };
  return COPIES.map((c) => ({ ...c, text: text[c.lang] }));
}

/** Copies that are missing or differ from the table (repo-relative paths). */
export function staleCopies(root = ROOT) {
  const out = [];
  for (const c of expectedCopies()) {
    let have = null;
    try { have = readFileSync(join(root, c.path), "utf8"); } catch { /* missing */ }
    if (have !== c.text) out.push(c.path);
  }
  return out;
}

function main(argv) {
  const cmd = argv[0];
  const problems = tableProblems();
  if (problems.length > 0) {
    process.stderr.write(`mandu-paths: the table is unsound:\n${problems.map((x) => `  - ${x}`).join("\n")}\n`);
    return 1;
  }
  if (cmd === "generate") {
    for (const c of expectedCopies()) {
      mkdirSync(dirname(join(ROOT, c.path)), { recursive: true });
      writeFileSync(join(ROOT, c.path), c.text);
      process.stdout.write(`wrote ${c.path}\n`);
    }
    return 0;
  }
  if (cmd === "check") {
    const stale = staleCopies();
    if (stale.length === 0) {
      process.stdout.write(`mandu-paths: ${COPIES.length} copies match the table\n`);
      return 0;
    }
    process.stderr.write(
      `mandu-paths: stale copies (run \`node ${SOURCE} generate\`):\n${stale.map((x) => `  - ${x}`).join("\n")}\n`,
    );
    return 1;
  }
  process.stderr.write(`usage: node ${SOURCE} generate|check\n`);
  return 2;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exitCode = main(process.argv.slice(2));
}
