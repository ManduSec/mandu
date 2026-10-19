/**
 * doctor-secrets — `mandu doctor --secrets`: the DRY RUN of the secret walk
 * (docs/design/confidentiality/secret-discovery.md §1.3). Runs discovery and the
 * twin planner exactly as a launch would, against THIS user's real HOME and
 * workspace, but starts no agent, enters no namespace and registers nothing:
 * it prints what a launch would mask, what it would leave RAW (the "not
 * covered" ledger: depth and file caps, unreadable candidates, dangling and
 * directory links, the agent's own credentials), which environment variables
 * it would mask (names only — no value ever crosses the socket), the posture
 * it would run at, and whether the launch would succeed or refuse.
 *
 * NEVER prints file contents or symbol originals: the report is paths,
 * levels, rules and reasons. The arbiter does the walk (it owns the catalog
 * and the user labels); a reachable resident arbiter with the secrets axis
 * ON is asked directly, otherwise a THROWAWAY arbiter on a private socket
 * and a temporary Mandu home answers and is stopped afterwards.
 *
 * Every host/process seam is injectable so the report logic is unit-tested
 * with no arbiter; the fixture-home live suite runs it for real and asserts
 * its verdict agrees with the real launch (§7).
 *
 * Mandu-new (no reference origin).
 */
import { closeSync, copyFileSync, mkdirSync, mkdtempSync, openSync, rmSync } from "node:fs";
import { spawn } from "node:child_process";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { resolveArbiterSock } from "./arbiter-sock.js";
import { pollSocket } from "./arbiter.js";
import { existsSync, readFileSync } from "node:fs";
import { depthAreasWords, discoverWireOpts, loginEnvOf, ndjsonCall, notCoveredNotice, packageCacheEnv, probeWindowsProfiles, resolveSecretTarget, type DiscoverOptions, type DiscoveryReport } from "./secret-setup.js";
import { agentDisplayName, loginKeptWhere, otherAgentLoginsRaw } from "./agent-login.js";
import { ullmCliBinary } from "./parse.js";
import { TARGETS, isTarget, type Target } from "./types.js";
import { hostIsWsl, windowsProfileSecretRoots } from "./wsl.js";
import { resolveNativeBin } from "./services/native-bins.js";
import { planSecretTwins } from "./secret-twins.js";
import { gatherConfinement, realDoctorDeps, type DoctorDeps } from "./doctor.js";
import { bindOnlyLines, gapExplanation, guardOnlyLines, onConfinementFailure, POSTURE_SENTENCE, type HostPosture } from "./confinement-posture.js";
import type { Layout } from "./services/layout.js";
import { manduPath } from "./generated/mandu-paths.js";

type Env = Record<string, string | undefined>;

/** The arbiter the dry run asks. */
export interface DryRunArbiter {
  sock: string;
  kind: "resident" | "throwaway";
  /** The resident arbiter's confidentiality axis (null = unknown / not asked). */
  axisOn: boolean | null;
  /** A throwaway whose store was seeded, read-only, from the resident
   *  store (`throwawayArbiter`'s `seedFrom`): it holds the remembered
   *  answers and the changes waiting in Approvals. */
  seeded?: boolean;
  stop: () => Promise<void>;
}

export interface DoctorSecretsDeps {
  /** Attach to a resident arbiter (secrets axis ON) or start a throwaway. */
  arbiter: (env: Env, layout: Layout) => Promise<DryRunArbiter>;
  /** `stateBase`: the view state base the launch would use, the home's
   *  `state/` (sent explicitly: a throwaway arbiter has its own home).
   *  `login`: the agent the dry run is for (`--target`) and where agents
   *  log in (secret-discovery.md §1.10); no target keeps every agent's
   *  login raw. */
  discover: (sock: string, roots: string[], home: string, stateBase?: string, cacheEnv?: Record<string, string>, login?: Pick<DiscoverOptions, "target" | "ullmBinary" | "loginEnv">) => Promise<DiscoveryReport>;
  /** Which of these variable NAMES would be masked (values never sent). */
  envNames: (sock: string, names: string[]) => Promise<string[]>;
  /** `env` names a guard the user turned off (doctor.ts guardOptedOut). */
  confinement: (env: Env) => HostPosture & { detail?: string };
  resolveTarget: (p: string) => string | null;
  now: () => number;
  /** WSL: the Windows user profiles a launch also discovers, each as its own
   *  home (secret-setup.ts, wsl.ts `windowsProfiles`). Empty off WSL.
   *  Optional: a fixture without it has none. */
  windowsProfiles?: () => string[];
  /** Would a guard be around the launch (the resolver net-guard-setup.ts
   *  uses)? Only asked when a Windows profile's file is found. Optional: a
   *  fixture without it has one. */
  guardAvailable?: () => boolean;
  /** The arbiter's `scanSecretHistory` (secret-discovery.md §3): the reachable
   *  git history of each root's work tree, scanned FOR US by the arbiter
   *  (it reads the blobs; no value crosses the socket). Optional: a fixture
   *  without it reports no history section. */
  historyScan?: (sock: string, roots: string[], home: string) => Promise<HistoryScanWire>;
  /** The resident arbiter's `gitHistoryLocks` (no roots: registers nothing),
   *  for the preparation of sanitized copies (plan 14 §11.1 R3). Optional: a
   *  fixture without it reports no such section. */
  gitLocks?: (sock: string) => Promise<{ axis?: boolean; preparation?: PreparationWire }>;
  /** The host the launch would run on (default: this process's). A macOS
   *  launch hides no git history (confidentiality.md §7.3), so the report
   *  words the history for it. A test knob. */
  platform?: NodeJS.Platform;
}

/** The arbiter's `gitHistoryLocks` `preparation` (arbiter/ipc/protocol.ts;
 *  names and counts, never a value). */
export interface PreparationWire {
  ready: number;
  pending: string[];
  capped: Array<{ root: string; reason: string }>;
  failed: Array<{ root: string; reason: string }>;
  paused?: string;
  bytes: number;
  caps: { cycleBytes: number; totalBytes: number };
  at: number | null;
}

// ── The git-history scan's wire (a narrow mirror of the arbiter's
//    ScanSecretHistoryResultWire, arbiter/policy/secret-history-scan.ts;
//    the packages ship standalone) ──────────────────────────────────────────

export type HistoryDetectorWire =
  | { kind: "content-shape"; rule: string; line: number; preview: string }
  | { kind: "catalog-path"; rule: string; path: string; level: string };

export interface HistoryFindingWire {
  repoRoot: string;
  blob: string;
  paths: string[];
  firstCommit: string | null;
  lastCommit: string | null;
  inHead: boolean;
  inIndex: boolean;
  stillPresent: boolean;
  pathStillSecretByCatalog: boolean;
  detector: HistoryDetectorWire;
  detectors: HistoryDetectorWire[];
}

export interface HistoryScanWire {
  axis: boolean;
  repos: Array<{ root: string; repoRoot: string | null; reason?: string }>;
  counts: { blobs: number; scanned: number; classified: number };
  capped: { tooBig: number; overTotal: number; overTime: number; binary: number; pathsUnchecked: number; untraced: number; unlisted: boolean; lines: string[] };
  findings: HistoryFindingWire[];
  limits: { blobMaxBytes: number; totalMaxBytes: number; timeoutMs: number; traceMax: number; classifyMax: number };
  ms: number;
}

/** What would close a finding (secret-discovery.md §3.2 item 6). */
export type HistoryClass = "covered" | "file-unprotected" | "history-only";

export function historyClass(f: HistoryFindingWire): HistoryClass {
  return f.pathStillSecretByCatalog ? "covered" : f.stillPresent ? "file-unprotected" : "history-only";
}

/** The doctor's history section. */
export interface DoctorHistory {
  /** `scanned`: `scan` holds the answer; otherwise `reason` says why not. */
  status: "scanned" | "skipped" | "failed";
  reason?: string;
  scan?: HistoryScanWire;
  /** Per finding (same order as `scan.findings`): what would close it. */
  classes?: HistoryClass[];
}

export interface DoctorSecretsReport {
  /** The host the report is for (`historyHiddenHere` reads it). */
  platform?: string;
  /** The agent the dry run is for (`--target`), or null: then every
   *  agent's login is counted as left raw (secret-discovery.md §1.10).
   *  Absent from an older report. */
  target?: string | null;
  roots: string[];
  /** WSL: the Windows profiles probed as second homes (empty elsewhere). */
  windowsProfiles: string[];
  posture: HostPosture & { detail?: string };
  arbiter: { kind: DryRunArbiter["kind"]; sock: string; axisOn: boolean | null } | null;
  /** What a launch would mask, one row per discovered file. */
  files: Array<{
    path: string;
    /** The real path the twin binds over, when it differs (a symlinked secret). */
    real?: string;
    /** The Windows profile it was found under (WSL), when not the HOME. */
    profile?: string;
    level: string;
    rule: string;
    /** `bind` (or the guard's descriptor) — or why the planner dropped it. */
    bind: "bind" | "skipped";
    skipReason?: string;
    /** Another agent's login (secret-discovery.md §1.10): whose. */
    agentLogin?: string;
    /** MANDU_OTHER_AGENT_LOGINS=raw: a launch registers it but leaves it
     *  readable (no placeholder copy), as the agent's own key file. */
    readable?: true;
  }>;
  notCovered: {
    counts: Record<string, number>; skipped: Array<{ path: string; reason: string }>; limits: { maxDepth: number; maxFiles: number }; truncated: boolean;
    /** The `depth` records by folder (secret-discovery.md §1.9 H), when the arbiter sent them. */
    depthAreas?: Array<{ path: string; count: number }>;
  };
  env: { checked: number; masked: string[] };
  /** The git-history scan (secret-discovery.md §3): null when no scan was
   *  asked (a fixture without the seam, or the walk failed first). */
  history: DoctorHistory | null;
  /** Plan 14 §11.1 R3: the resident arbiter's preparation of sanitized
   *  copies for the repositories holding a locked key; null when not asked
   *  (a throwaway arbiter prepares nothing) or not answered. */
  preparation: PreparationWire | null;
  timings: { discoverMs: number; envMs: number; historyMs: number };
  launch: { ok: boolean; reason: string | null };
  warnings: string[];
}

const truthy = (v: string | undefined): boolean => ["1", "true", "yes", "on"].includes((v ?? "").toLowerCase());

/** The env-var NAMES a launch would consider (the same filter applyEnvSecrets
 *  applies before asking the arbiter: set and non-empty). */
export function envCandidates(env: Env): string[] {
  return Object.entries(env).filter(([, v]) => v !== undefined && v !== "").map(([k]) => k).sort();
}

/** Run the dry run. Pure over deps. */
export async function gatherSecrets(env: Env, layout: Layout, deps: DoctorSecretsDeps, opts: { cwd?: string; history?: boolean; target?: Target; noMcp?: boolean } = {}): Promise<DoctorSecretsReport> {
  const home = env["HOME"] ?? homedir();
  const roots = [home, opts.cwd ?? process.cwd()];
  const stateBase = manduPath("view-state", env, home);
  const posture = deps.confinement(env);
  const warnings: string[] = [];
  // The agents' logins (secret-discovery.md §1.10): with `--target`, the
  // walk a launch of that agent asks for (its own logins and the AI
  // helper's CLI's stay raw: none with `--no-mcp`, which turns the helper
  // off, as launchLoginKeying has it); without, every agent's login stays raw.
  const ullmBinary = opts.target !== undefined && opts.noMcp !== true ? ullmCliBinary(opts.target, env) : null;
  // MANDU_OTHER_AGENT_LOGINS=raw: such a launch leaves another agent's login
  // readable (registered, no placeholder copy), and says so per file.
  const otherLoginsRaw = opts.target !== undefined && otherAgentLoginsRaw(env);
  const loginEnv = loginEnvOf(env);
  const login: Pick<DiscoverOptions, "target" | "ullmBinary" | "loginEnv"> = {
    ...(opts.target !== undefined ? { target: opts.target } : {}),
    ...(ullmBinary !== null ? { ullmBinary } : {}),
    ...(Object.keys(loginEnv).length > 0 ? { loginEnv } : {}),
  };
  const report: DoctorSecretsReport = {
    platform: deps.platform ?? process.platform,
    target: opts.target ?? null,
    roots, windowsProfiles: [], posture, arbiter: null, files: [],
    notCovered: { counts: {}, skipped: [], limits: { maxDepth: 0, maxFiles: 0 }, truncated: false },
    env: { checked: 0, masked: [] }, history: null, preparation: null, timings: { discoverMs: 0, envMs: 0, historyMs: 0 },
    launch: { ok: true, reason: null }, warnings,
  };

  // The posture verdict first: it needs no arbiter and it is the one thing a
  // launch refuses over by host condition.
  const strict = { requireConfinement: truthy(env["MANDU_REQUIRE_CONFINEMENT"]), bestEffort: false };
  if (posture.gap !== undefined && onConfinementFailure("host", strict) === "refuse") {
    const { cause, fix } = gapExplanation(posture.gap);
    report.launch = { ok: false, reason: `--require-confinement is set and this host cannot confine: ${cause}${fix ? ` (fix: ${fix})` : ""}` };
  }

  let arb: DryRunArbiter;
  try {
    arb = await deps.arbiter(env, layout);
  } catch (e) {
    report.launch = { ok: false, reason: `no arbiter could answer the walk (${(e as Error).message}); a launch would refuse for the same reason` };
    return report;
  }
  report.arbiter = { kind: arb.kind, sock: arb.sock, axisOn: arb.axisOn };
  try {
    if (arb.kind === "resident" && arb.axisOn === false) {
      warnings.push(`the running arbiter at ${arb.sock} has the secrets axis OFF: a launch attaching to it masks NOTHING (run \`mandu stop\`, or \`mandu mode\` to check the saved mode); the inventory below is what a secrets-mode launch would do`);
    }
    const t0 = deps.now();
    let disc: DiscoveryReport;
    try {
      // The caches this environment moves, as a launch sends them (§1.9 G).
      disc = await deps.discover(arb.sock, roots, home, stateBase, packageCacheEnv(env), login);
    } catch (e) {
      report.launch = { ok: false, reason: `the arbiter could not discover secrets (${(e as Error).message}); a launch refuses on this unless --best-effort` };
      return report;
    }
    report.notCovered = {
      counts: { ...(disc.counts ?? {}) },
      skipped: [...(disc.skipped ?? [])],
      limits: disc.limits ?? { maxDepth: 0, maxFiles: 0 },
      truncated: disc.truncated === true,
      ...(disc.depthAreas && disc.depthAreas.length > 0 ? { depthAreas: [...disc.depthAreas] } : {}),
    };
    // WSL: each Windows profile is a second home, probed exactly as the
    // launch probes it (the catalog's paths under it, never a walk).
    const found: Array<DiscoveryReport["files"][number] & { profile?: string }> = [...disc.files];
    const seen = new Set(found.map((f) => f.path));
    report.windowsProfiles = deps.windowsProfiles?.() ?? [];
    for (const profile of report.windowsProfiles) {
      let win: DiscoveryReport;
      try {
        win = await deps.discover(arb.sock, windowsProfileSecretRoots(profile), profile, stateBase);
      } catch (e) {
        report.launch = { ok: false, reason: `the arbiter could not discover secrets under ${profile} (${(e as Error).message}); a launch refuses on this unless --best-effort` };
        return report;
      }
      for (const f of win.files) {
        if (!seen.has(f.path)) { seen.add(f.path); found.push({ ...f, profile }); }
      }
      for (const [k, v] of Object.entries(win.counts ?? {})) report.notCovered.counts[k] = (report.notCovered.counts[k] ?? 0) + v;
      report.notCovered.skipped.push(...(win.skipped ?? []));
      if (win.truncated === true) report.notCovered.truncated = true;
    }
    report.timings.discoverMs = deps.now() - t0;
    // The twin planner, exactly as the launch runs it (one bind per REAL
    // file; a vanished file dropped, loudly). The symbol is a placeholder:
    // nothing is registered in a dry run.
    const plan = planSecretTwins(
      found.map((f) => ({ path: f.path, symbol: "$MDU:nomodel_Read[dryrun]" })),
      "/dev/null/twins", "bwrap", { resolveTarget: deps.resolveTarget },
    );
    const skipped = new Map(plan.skipped.map((s) => [s.path, s.reason]));
    for (const f of found) {
      const real = deps.resolveTarget(f.path);
      const row: DoctorSecretsReport["files"][number] = {
        path: f.path, level: f.level ?? "no-model", rule: f.rule ?? "catalog",
        bind: skipped.has(f.path) ? "skipped" : "bind",
      };
      if (f.profile !== undefined) row.profile = f.profile;
      if (real !== null && real !== f.path) row.real = real;
      if (typeof f.agentLogin === "string") {
        row.agentLogin = f.agentLogin;
        if (otherLoginsRaw) row.readable = true;
      }
      const why = skipped.get(f.path);
      if (why !== undefined) row.skipReason = why;
      report.files.push(row);
    }
    // The launch's WSL rule (secret-setup.ts): Windows credentials without
    // the guard refuse, since the bind alone misses another spelling.
    const onProfiles = report.files.filter((f) => f.profile !== undefined);
    if (onProfiles.length > 0 && report.launch.ok && deps.guardAvailable?.() === false) {
      report.launch = {
        ok: false,
        reason: `${onProfiles.length} Windows credential file(s) sit on a drive that ignores case and the whole-agent guard that recognizes another spelling of them is not available (--best-effort protects only their exact spellings)`,
      };
    }
    const t1 = deps.now();
    const names = envCandidates(env);
    try {
      report.env = { checked: names.length, masked: await deps.envNames(arb.sock, names) };
    } catch (e) {
      warnings.push(`environment inventory unavailable (${(e as Error).message}); a launch masks the environment fail-soft and says so`);
    }
    report.timings.envMs = deps.now() - t1;
    // The git history of the workspace (secret-discovery.md §3, phase 1):
    // advisory, never part of the launch verdict. The arbiter reads the
    // blobs; the answer carries no value.
    if (opts.history === false) {
      report.history = { status: "skipped", reason: "--no-history" };
    } else if (deps.historyScan) {
      const t2 = deps.now();
      try {
        const scan = await deps.historyScan(arb.sock, [roots[1]!], home);
        report.history = scan.axis
          ? { status: "scanned", scan, classes: scan.findings.map(historyClass) }
          : { status: "skipped", reason: "the Mandu service that answered has secret protection off" };
      } catch (e) {
        report.history = { status: "failed", reason: (e as Error).message };
      }
      report.timings.historyMs = deps.now() - t2;
    }
    // Plan 14 §11.1 R3: how many repositories holding a locked key have
    // their sanitized copies prepared (git works there in a launch) and how
    // many do not yet (git there is refused). Only a resident arbiter
    // prepares; advisory, never part of the verdict.
    if (deps.gitLocks && arb.kind === "resident") {
      try {
        const got = await deps.gitLocks(arb.sock);
        if (got.axis !== false && got.preparation !== undefined && isPreparation(got.preparation)) report.preparation = got.preparation;
      } catch { /* an older arbiter, a timeout: no section */ }
    }
    if (report.timings.discoverMs > 5000) warnings.push(`the walk took ${(report.timings.discoverMs / 1000).toFixed(1)} s (budget: 5 s); prune with a smaller HOME walk or report the tree shape`);
  } finally {
    await arb.stop();
  }
  return report;
}

/** A file level as the dashboard's glossary words it (rule-words.ts TERMS),
 *  short enough for the table column. */
function levelShort(level: string): string {
  return level === "any-model" ? "any AI" : level === "local-model" ? "own AI only" : level === "public" ? "not secret" : "no AI";
}

const tilde = (p: string, home: string): string => (p === home ? "~" : p.startsWith(home + "/") ? "~" + p.slice(home.length) : p);

/** Render the report. Pure. Paths, levels, rules, reasons — never contents. */
export function renderSecrets(r: DoctorSecretsReport, home: string = r.roots[0] ?? homedir()): string {
  const L: string[] = [];
  const OK = "✓", NO = "✗", DOT = "·";
  L.push("Mandu doctor --secrets  (a dry run: nothing registered, no agent started, nothing changed)");
  L.push(`  roots: ${r.roots.map((p) => tilde(p, home)).join(", ")}`);
  if (r.target) L.push(`  agent: ${agentDisplayName(r.target)} (--target ${r.target}: the logins this launch runs on stay raw, listed below; every other agent's is masked)`);
  if (r.windowsProfiles.length > 0) L.push(`  Windows profiles (WSL, their credential stores only): ${r.windowsProfiles.join(", ")}`);
  L.push("");
  L.push("Protection (what a launch would get)");
  const c = r.posture;
  L.push(c.posture === "gated"
    ? `  ${NO} credential files are NOT protected from programs the AI runs (posture: gated)`
    : `  ${OK} credential files are protected (posture: ${c.posture}${c.bindGap !== undefined ? ", by the guard alone" : ""})`);
  L.push(`    ${POSTURE_SENTENCE[c.posture]}`);
  for (const line of guardOnlyLines(c)) L.push(`    ${line}`);
  for (const line of bindOnlyLines(c)) L.push(`    ${line}`);
  if (c.gap !== undefined) {
    const { cause, fix } = gapExplanation(c.gap);
    L.push(`    cause: ${cause}${c.detail ? ` (${c.detail})` : ""}`);
    if (fix !== null) L.push(`    fix: ${fix}`);
  }
  L.push("");
  if (r.arbiter !== null) {
    L.push(`Checked by: ${r.arbiter.kind === "resident" ? `the running Mandu service at ${r.arbiter.sock} (secret protection ${r.arbiter.axisOn === null ? "unknown" : r.arbiter.axisOn ? "on" : "off"})` : "a temporary Mandu service (none was running), stopped again"}`);
    L.push("");
  }
  // MANDU_OTHER_AGENT_LOGINS=raw: another agent's login is registered but
  // left readable, so it is not among the masked files (secret-discovery.md §1.10).
  const masked = r.files.filter((f) => f.readable !== true);
  const readable = r.files.filter((f) => f.readable === true);
  L.push(`Would be masked: ${masked.length} credential file${masked.length === 1 ? "" : "s"} (search took ${r.timings.discoverMs} ms)`);
  if (masked.length > 0) L.push(`  ${"".padEnd(50)} ${"the AI".padEnd(16)} matched by`);
  if (masked.length === 0) L.push("  (none found under the roots)");
  for (const f of masked) {
    const where = f.real !== undefined ? `${tilde(f.path, home)} → ${tilde(f.real, home)}` : tilde(f.path, home);
    const how = f.bind === "bind" ? "" : `   SKIPPED: ${f.skipReason ?? "dropped by the planner"}`;
    L.push(`  ${f.bind === "bind" ? OK : DOT} ${where.padEnd(48)} ${levelShort(f.level).padEnd(16)} ${f.rule}${how}`);
  }
  for (const f of readable) {
    L.push(`  ${DOT} ${tilde(f.path, home).padEnd(48)} left readable: ${agentDisplayName(f.agentLogin ?? "")}'s login (MANDU_OTHER_AGENT_LOGINS=raw), its values masked in what reaches the AI`);
  }
  L.push("");
  const m = r.env.masked;
  L.push(`Environment: ${m.length} of ${r.env.checked} variable${r.env.checked === 1 ? "" : "s"} would be masked${m.length > 0 ? `: ${m.join(", ")}` : ""}`);
  L.push("  (names only; a URL-shaped value with a password, or a key in a known format such as a GitHub or Stripe token, is masked at launch even when its name is not listed here, and a listed *_PWD holding a directory, such as HOST_PWD, stays as it is)");
  L.push("");
  L.push("Not covered (a launch leaves these as they are, unmasked)");
  const n = r.notCovered;
  const group = (reason: string, one: string, many: string, mark: string): void => {
    const count = n.counts[reason] ?? 0;
    if (count === 0) return;
    const ps = n.skipped.filter((s) => s.reason === reason).map((s) => tilde(s.path, home));
    L.push(`  ${mark} ${count} ${count === 1 ? one : many}${ps.length ? `: ${ps.slice(0, 6).join(", ")}${count > 6 ? `, +${count - 6} more` : ""}` : ""}`);
  };
  group("depth", `directory below depth ${n.limits.maxDepth} not searched`, `directories below depth ${n.limits.maxDepth} not searched`, NO);
  // By folder (§1.9 H): where the too-deep directories are, all of them.
  const areas = depthAreasWords(n.depthAreas ?? [], n.counts["depth"] ?? 0, home, 10);
  if (areas) L.push(`      by folder: ${areas}`);
  group("count", `credential file beyond the ${n.limits.maxFiles}-file cap`, `credential files beyond the ${n.limits.maxFiles}-file cap`, NO);
  group("unreadable", "unreadable candidate", "unreadable candidates", NO);
  // §1.9 F: listed so nothing is dropped silently, but never the launch notice.
  group("package-cache", `directory below depth ${n.limits.maxDepth} inside a package cache not searched (skipped package caches: downloaded third-party code)`, `directories below depth ${n.limits.maxDepth} inside package caches not searched (skipped package caches: downloaded third-party code)`, DOT);
  group("special-file", "socket, pipe or device named like a secret (no file to mask)", "sockets, pipes or devices named like secrets (no file to mask)", DOT);
  group("dangling-symlink","dangling link named like a secret", "dangling links named like secrets", DOT);
  group("symlinked-directory", "directory link not followed", "directory links not followed", DOT);
  group("unreadable-dir", "unreadable directory", "unreadable directories", DOT);
  // secret-discovery.md §1.10: an agent's own data stays raw in every
  // launch; a login only in a launch that runs that agent.
  const OWN_DATA = "left raw in every session: the agent reads and writes it; a command that names the path is masked for the AI";
  group("agent-auth", `AI agent's own data folder (${OWN_DATA})`, `AI agents' own data folders (${OWN_DATA})`, DOT);
  const LOGIN = r.target
    ? "left raw: the agent this launch runs, or Mandu's AI helper running that agent's program, logs in with it; a command that names the path is masked for the AI. Another agent's login is masked like the credential files above (MANDU_OTHER_AGENT_LOGINS=raw leaves those readable)"
    : `left raw in a session that runs that agent (Claude Code's: ${loginKeptWhere("claude")}; Codex's: ${loginKeptWhere("codex")}; OpenCode's: ${loginKeptWhere("opencode")}); ` +
      "in any other session it is masked like any credential file (`--target <agent>` shows one launch; MANDU_OTHER_AGENT_LOGINS=raw leaves other agents' logins readable)";
  group("agent-login", `AI agent login file (${LOGIN})`, `AI agent login files (${LOGIN})`, DOT);
  group("mandu-state", "Mandu data folder not searched (Mandu already knows the working copies it keeps there)", "Mandu data folders not searched (Mandu already knows the working copies it keeps there)", DOT);
  group("mandu-install", "Mandu install directory not walked (Mandu's own package or Node)", "Mandu install directories not walked (Mandu's own package and Node)", DOT);
  group("agentview-symbolized", "AI working copy already masked by Mandu (only placeholders inside)", "AI working copies already masked by Mandu (only placeholders inside)", DOT);
  if (n.truncated) L.push(`  ${NO} the walk stopped at the ${n.limits.maxFiles}-file cap: directories not yet visited were not searched`);
  const consequential = (n.counts["depth"] ?? 0) + (n.counts["count"] ?? 0) + (n.counts["unreadable"] ?? 0) + (n.truncated ? 1 : 0);
  if (Object.values(n.counts).every((v) => v === 0) && !n.truncated) L.push(`  ${OK} nothing skipped`);
  else if (consequential === 0) L.push(`  ${OK} nothing consequential: every catalog match the walk reached is covered`);
  L.push("");
  const hidden = historyHiddenHere(r);
  const hist = renderHistory(r.history, home, hidden);
  if (hist.length > 0) L.push(...hist, "");
  const prep = renderPreparation(r.preparation, home);
  if (prep.length > 0) L.push(...prep, "");
  for (const w of r.warnings) L.push(`WARNING: ${w}`);
  if (r.warnings.length) L.push("");
  L.push(r.launch.ok ? `Launch: would start (posture: ${c.posture})` : `Launch: would REFUSE to start: ${r.launch.reason}`);
  return L.join("\n") + "\n";
}

/** The preparation's answer, checked (a shape not understood: no section). */
function isPreparation(v: unknown): v is PreparationWire {
  const o = v as Partial<PreparationWire> | null;
  const named = (x: unknown): boolean => Array.isArray(x) && x.every((e) => e !== null && typeof e === "object" && typeof (e as { root?: unknown }).root === "string");
  return o !== null && typeof o === "object" && typeof o.ready === "number" && Array.isArray(o.pending) && o.pending.every((p) => typeof p === "string")
    && named(o.capped) && named(o.failed) && typeof o.bytes === "number";
}

/** Does a launch on the report's host hide a file's committed versions?
 *  Only the Linux launch does (the object twins, the prepared copies, the
 *  guard's backstop: confidentiality-plan-14 §8, §11.1); a macOS launch
 *  hides none (confidentiality.md §7.3). A report without a platform (an
 *  older one) is judged by its posture: `read-blocked` is macOS. Pure. */
export function historyHiddenHere(r: Pick<DoctorSecretsReport, "platform" | "posture">): boolean {
  return r.platform !== undefined ? r.platform !== "darwin" : r.posture.posture !== "read-blocked";
}

/** The preparation section (plan 14 §11.1 R3). Pure. Paths and counts.
 *  Linux only in practice: the daemon prepares nothing on macOS
 *  (arbiter/policy/prepared-copies.ts `preparedCopiesOff`), so a macOS
 *  arbiter's `gitHistoryLocks` carries no `preparation` and the report has
 *  no such section. */
export function renderPreparation(p: PreparationWire | null, home: string): string[] {
  if (p === null) return [];
  const total = p.ready + p.pending.length + p.capped.length + p.failed.length;
  if (total === 0 && p.paused === undefined) return [];
  const mb = (n: number): number => Math.ceil(n / 1048576);
  const L: string[] = [];
  L.push(`Locked keys in other repositories' git history: ${total} repositor${total === 1 ? "y" : "ies"} Mandu knows hold${total === 1 ? "s" : ""} one`);
  const list = (xs: string[]): string => `${xs.slice(0, 5).map((x) => tilde(x, home)).join(", ")}${xs.length > 5 ? `, +${xs.length - 5} more` : ""}`;
  L.push(`  ${p.ready} prepared (a launch anywhere serves their sanitized copies: git works there, the locked versions are missing)`);
  if (p.pending.length > 0) L.push(`  ${p.pending.length} pending (being prepared; until then git there is refused in a launch): ${list(p.pending)}`);
  if (p.capped.length > 0) {
    L.push(`  ${p.capped.length} not prepared, over a size cap (git there is refused in a launch; MANDU_GIT_PREP_CYCLE_MB ${mb(p.caps.cycleBytes)} MiB, MANDU_GIT_PREP_TOTAL_MB ${mb(p.caps.totalBytes)} MiB): ${list(p.capped.map((c) => c.root))}`);
  }
  if (p.failed.length > 0) L.push(`  ${p.failed.length} could not be prepared: ${list(p.failed.map((c) => c.root))}`);
  if (p.paused !== undefined) L.push(`  paused: ${p.paused} (nothing is prepared while a launch runs unprotected)`);
  L.push(`  prepared copies stand for ${mb(p.bytes)} MiB of packs; to work in a repository that is not prepared, start mandu in it`);
  return L;
}

/** A detector in the user's words (paths, kinds, masks: never a value). */
const SHAPE_WORDS: Record<string, string> = {
  "private-key": "private key",
  "aws-access-key-id": "AWS access key",
  "aws-secret-key": "AWS secret key",
  "github-token": "GitHub token",
  "gitlab-token": "GitLab token",
  "anthropic-key": "Anthropic API key",
  "openai-key": "OpenAI-style API key",
  "slack-token": "Slack token",
  "stripe-key": "Stripe live key",
  "google-api-key": "Google API key",
  "npm-token": "npm token",
  "pypi-token": "PyPI token",
  "huggingface-token": "Hugging Face token",
  "url-password": "password in a URL",
  "credential-assignment": "credential assignment",
};

function detectorWords(d: HistoryDetectorWire): string {
  return d.kind === "content-shape"
    ? `${SHAPE_WORDS[d.rule] ?? d.rule} ${d.preview} (line ${d.line})`
    : `a deleted file named like a credential file (${d.path}, ${d.rule})`;
}

const short = (c: string | null): string => (c === null ? "?" : c.slice(0, 8));

/** What would close each class (secret-discovery.md §3.2 item 6). */
export const HISTORY_ADVICE: Record<HistoryClass, string> = {
  "history-only":
    "nothing hides these from the AI today (a `git log -p` or `git show` of the old commit reads them). " +
    "Rotate the key: it is in every clone. If the repository is shared, remove it from the history (git filter-repo). " +
    "`mandu policy suggest` offers the rule that hides them from the AI (review it, then apply).",
  "file-unprotected":
    "if the file still holds the key, protect it (`mandu policy suggest`, the dashboard's Rules page, or a `paths:` entry in policy.yaml): " +
    "the next launch then hides the file and every committed version of it. Rotate the key either way.",
  "covered":
    "the file is protected now, so a launch hides it and every committed version of it from the AI. " +
    "Rotate the key if the repository is shared.",
};

/** The same advice on macOS, where a launch hides no committed version
 *  (confidentiality.md §7.3): a rule makes a file that still exists
 *  unreadable, and that is all. */
export const HISTORY_ADVICE_MACOS: Record<HistoryClass, string> = {
  "history-only":
    "nothing hides these from the AI (a `git log -p` or `git show` of the old commit reads them), and on macOS a rule " +
    "does not either: only Linux hides a file's git history. Rotate the key: it is in every clone. If the repository is " +
    "shared, remove it from the history (git filter-repo). `mandu policy suggest` offers the rule that hides them on Linux.",
  "file-unprotected":
    "if the file still holds the key, protect it (`mandu policy suggest`, the dashboard's Rules page, or a `paths:` entry in policy.yaml): " +
    "the next launch then makes the file unreadable to the AI, but on macOS its committed versions stay readable " +
    "(git show, git log -p): only Linux hides them. Rotate the key either way.",
  "covered":
    "the file is protected now, so a launch makes it unreadable to the AI, but on macOS its committed versions stay " +
    "readable (git show, git log -p): only Linux hides them. Rotate the key, and remove it from the history if the " +
    "repository is shared.",
};

const CLASS_HEAD: Record<HistoryClass, string> = {
  "history-only": "only in git history, not protected",
  "file-unprotected": "still in the work tree, not protected",
  "covered": "covered (protected now)",
};

/** macOS: a protected file's history is not covered there. */
const CLASS_HEAD_MACOS: Record<HistoryClass, string> = {
  ...CLASS_HEAD,
  "covered": "protected now, its git history still readable on macOS",
};

/** The history section. Pure. Paths, kinds, masks, commits: never a value.
 *  `hidden` false (macOS, `historyHiddenHere`): no class is covered, and the
 *  advice says that the committed versions stay readable. */
export function renderHistory(h: DoctorHistory | null, home: string, hidden = true): string[] {
  if (h === null) return [];
  const L: string[] = [];
  const OK = "✓", NO = "✗", DOT = "·";
  if (h.status !== "scanned" || h.scan === undefined) {
    L.push(`Git history: not scanned (${h.reason ?? h.status})`);
    return L;
  }
  const s = h.scan;
  const repos = s.repos.filter((r) => r.repoRoot !== null).map((r) => tilde(r.repoRoot!, home));
  if (repos.length === 0) {
    L.push(`Git history: not scanned (${s.repos[0]?.reason ?? "no repository"})`);
    return L;
  }
  L.push(`Git history of ${repos.join(", ")} (${s.counts.scanned} of ${s.counts.blobs} file version${s.counts.blobs === 1 ? "" : "s"} read in ${(s.ms / 1000).toFixed(1)} s; values are never shown)`);
  const classes = h.classes ?? s.findings.map(historyClass);
  if (s.findings.length === 0) L.push(`  ${OK} no secret-shaped file version found`);
  const SHOW = 20;
  for (const cls of ["history-only", "file-unprotected", "covered"] as const) {
    const rows = s.findings.filter((_, i) => classes[i] === cls);
    if (rows.length === 0) continue;
    // One entry per path: the versions of one file are one thing to act on.
    const groups = new Map<string, HistoryFindingWire[]>();
    for (const f of rows) {
      const key = f.paths[0] ?? "(no path)";
      groups.set(key, [...(groups.get(key) ?? []), f]);
    }
    const head = hidden ? CLASS_HEAD : CLASS_HEAD_MACOS;
    L.push(`  ${cls === "covered" && hidden ? OK : NO} ${groups.size} ${groups.size === 1 ? "file" : "files"} ${head[cls]}${rows.length > groups.size ? ` (${rows.length} versions)` : ""}:`);
    for (const [key, fs] of [...groups].slice(0, SHOW)) {
      const f = fs[0]!;
      const where = `${key}${f.paths.length > 1 ? ` (+${f.paths.length - 1} more name${f.paths.length === 2 ? "" : "s"})` : ""}`;
      const when = f.firstCommit !== null
        ? `added ${short(f.firstCommit)}${f.lastCommit !== null && f.lastCommit !== f.firstCommit ? `, last ${short(f.lastCommit)}` : ""}`
        : f.inIndex ? "staged, in no commit" : "commit not traced";
      const more = [
        ...(f.detectors.length > 1 ? [`${f.detectors.length - 1} more hit${f.detectors.length === 2 ? "" : "s"} in it`] : []),
        ...(fs.length > 1 ? [`${fs.length - 1} other version${fs.length === 2 ? "" : "s"} of this file too`] : []),
      ];
      L.push(`    ${where}   ${detectorWords(f.detector)}`);
      L.push(`      blob ${short(f.blob)}, ${when}${more.length > 0 ? `; ${more.join("; ")}` : ""}`);
    }
    if (groups.size > SHOW) L.push(`    +${groups.size - SHOW} more files (--json lists every version)`);
    L.push(`    what would close it: ${(hidden ? HISTORY_ADVICE : HISTORY_ADVICE_MACOS)[cls]}`);
  }
  for (const line of s.capped.lines) L.push(`  ${DOT} not scanned: ${line}`);
  return L;
}

// ── the real seams ────────────────────────────────────────────────────────────

/** Start a throwaway arbiter on a private socket and a temporary Mandu home
 *  (its own symbol DB and events; secrets axis ON), still reading the user's
 *  policy; stop() kills its process group and removes the dir.
 *
 *  `seedFrom` (`mandu why` with no Mandu running, comparisons.md §3.2): its
 *  store starts as a copy of what the resident arbiter keeps in that store
 *  (remembered answers, changes waiting in Approvals, the content in force
 *  while a disk edit waits, dashboard labels, registered files'
 *  placeholders), read from it read-only by the arbiter itself
 *  (arbiter/db/store-seed.ts; no original is copied). It reads a copy of the
 *  policy file, so a declined edit it would restore is never written over
 *  the person's file. A seed that fails refuses the start: this throws, and
 *  the caller asks an unseeded one. */
export async function throwawayArbiter(env: Env, layout: Layout, opts: { seedFrom?: string } = {}): Promise<DryRunArbiter> {
  const dir = mkdtempSync(join(env["TMPDIR"] || tmpdir(), "mdu-dr-"));
  const sock = join(dir, "a.sock");
  mkdirSync(join(dir, "home"), { recursive: true, mode: 0o700 });
  const spec = layout.daemon("arbiter", "arbiter", false);
  // The user's law (their labels and origins), not the temp home's none.
  const policy = env["MANDU_POLICY_FILE"] || manduPath("policy", env, env["HOME"] ?? homedir());
  let policyFile = policy;
  const seedArgs: string[] = [];
  if (opts.seedFrom !== undefined) {
    policyFile = join(dir, "policy.yaml");
    try {
      copyFileSync(policy, policyFile);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        rmSync(dir, { recursive: true, force: true });
        throw err;
      }
    }
    seedArgs.push("--seed-from", opts.seedFrom, "--seed-policy", policy);
  }
  const out = openSync(join(dir, "arbiter.log"), "a");
  const childEnv: NodeJS.ProcessEnv = {
    ...(env as NodeJS.ProcessEnv),
    MANDU_ARBITER_SOCK: sock, MANDU_HOME: join(dir, "home"),
    MANDU_POLICY_FILE: policyFile,
    MANDU_CONFIDENTIALITY: "1", MANDU_INTEGRITY: "0", MANDU_PROMOTE: "", MANDU_RUNTIME_DIR: dir,
  };
  delete childEnv["MANDU_ARBITER_SOCKET"];
  const child = spawn(spec.cmd, [...spec.args, ...seedArgs], { cwd: spec.cwd, env: { ...childEnv, ...spec.env }, detached: true, stdio: ["ignore", out, out] });
  closeSync(out);
  let exited = false;
  child.on("error", () => { exited = true; });
  child.on("exit", () => { exited = true; });
  const stop = async (): Promise<void> => {
    try { if (child.pid) process.kill(-child.pid, "SIGTERM"); } catch { /* gone */ }
    await new Promise((r) => setTimeout(r, 200));
    try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch { /* gone */ }
    rmSync(dir, { recursive: true, force: true });
  };
  if (!(await pollSocket(sock, 100, 100, () => exited))) {
    // The arbiter's own words for a refused start (a seed it could not make).
    let why = "";
    try { why = /\[arbiter\] fatal: (.*)/.exec(readFileSync(join(dir, "arbiter.log"), "utf8"))?.[1] ?? ""; } catch { /* no log */ }
    await stop();
    throw new Error(exited ? `a throwaway arbiter refused to start${why ? `: ${why}` : ""}` : "a throwaway arbiter did not come up in 10 s");
  }
  return { sock, kind: "throwaway", axisOn: true, ...(opts.seedFrom !== undefined ? { seeded: true } : {}), stop };
}

/** The resident arbiter answering `hello` at the socket `env` resolves to,
 *  with its confidentiality axis (null: not said), or null when none does. */
export async function helloResident(env: Env): Promise<{ sock: string; axisOn: boolean | null } | null> {
  const sock = resolveArbiterSock(env).sock;
  let hello: Record<string, unknown> | null = null;
  try { hello = await ndjsonCall<Record<string, unknown>>(sock, "hello", {}, 2000); } catch { hello = null; }
  if (hello === null) return null;
  return { sock, axisOn: typeof hello["confidentiality"] === "boolean" ? (hello["confidentiality"] as boolean) : null };
}

export function realDoctorSecretsDeps(doctorDeps: DoctorDeps = realDoctorDeps): DoctorSecretsDeps {
  return {
    arbiter: async (env, layout) => {
      const hello = await helloResident(env);
      if (hello !== null) {
        const { sock, axisOn } = hello;
        if (axisOn !== false) return { sock, kind: "resident", axisOn, stop: async () => {} };
        // A resident arbiter with the axis OFF discovers nothing: answer from a
        // throwaway and let the report say what the resident one would do.
        const t = await throwawayArbiter(env, layout);
        return { ...t, kind: "throwaway", axisOn: false };
      }
      return throwawayArbiter(env, layout);
    },
    discover: (sock, roots, home, stateBase, cacheEnv, login) => ndjsonCall<DiscoveryReport>(sock, "discoverSecrets", { roots, home, ...discoverWireOpts({ stateBase, cacheEnv, ...login }) }, 30_000),
    envNames: async (sock, names) => (await ndjsonCall<{ matched: string[] }>(sock, "envSecretNames", { names }, 5000)).matched,
    historyScan: (sock, roots, home) => ndjsonCall<HistoryScanWire>(sock, "scanSecretHistory", { roots, home }, historyCallTimeoutMs(process.env)),
    gitLocks: (sock) => ndjsonCall<{ axis?: boolean; preparation?: PreparationWire }>(sock, "gitHistoryLocks", {}, 5000),
    platform: process.platform,
    confinement: (env) => gatherConfinement(doctorDeps, env),
    resolveTarget: resolveSecretTarget,
    now: () => Date.now(),
    guardAvailable: () => (doctorDeps.nativeBin ?? resolveNativeBin)("mandu-net-guard") !== null,
    windowsProfiles: () => {
      const readFile = (p: string): string | null => { try { return readFileSync(p, "utf8"); } catch { return null; } };
      const onWsl = process.platform === "linux" && hostIsWsl({ readFile, fileExists: existsSync, env: process.env });
      return onWsl ? probeWindowsProfiles() : [];
    },
  };
}

/** How long the doctor waits for `scanSecretHistory`: the scan's own budget
 *  (MANDU_HISTORY_SCAN_TIMEOUT_S, 60 s by default) plus a margin, so only a
 *  wedged arbiter trips it. Pure. */
export function historyCallTimeoutMs(env: Env): number {
  const s = Number(env["MANDU_HISTORY_SCAN_TIMEOUT_S"]);
  return (Number.isFinite(s) && s > 0 ? s * 1000 : 60_000) + 30_000;
}

export function wantsSecrets(rest: string[]): boolean {
  return rest.includes("--secrets");
}

/** `mandu doctor --secrets [--target <agent> [--no-mcp]] [--json]
 *  [--no-history]`. Exit 0 when a launch would succeed, 1 when it would
 *  refuse (the reason is in the report), 2 on a bad `--target`; the
 *  git-history findings are advisory and never change the exit code.
 *  `--target` makes the dry run the walk of that agent's launch: the logins
 *  it runs on stay raw, every other agent's is masked (secret-discovery.md
 *  §1.10); `--no-mcp` as on a launch (no AI helper, so its program's login
 *  is not kept for it). Without `--target` every agent's login is listed as
 *  left raw. */
export async function runDoctorSecrets(
  rest: string[], env: Env, layout: Layout, deps: DoctorSecretsDeps = realDoctorSecretsDeps(),
  io: { out?: (s: string) => void; cwd?: string } = {},
): Promise<number> {
  const out = io.out ?? ((s: string) => { process.stdout.write(s); });
  const at = rest.indexOf("--target");
  const target = at >= 0 ? rest[at + 1] : undefined;
  if (at >= 0 && (target === undefined || !isTarget(target))) {
    process.stderr.write(`mandu doctor --secrets: --target wants one of ${TARGETS.join("|")}\n`);
    return 2;
  }
  const report = await gatherSecrets(env, layout, deps, {
    history: !rest.includes("--no-history"), ...(io.cwd !== undefined ? { cwd: io.cwd } : {}), ...(target !== undefined ? { target: target as Target } : {}),
    ...(rest.includes("--no-mcp") ? { noMcp: true } : {}),
  });
  if (rest.includes("--json")) out(JSON.stringify(report, null, 2) + "\n");
  else out(renderSecrets(report, env["HOME"] ?? homedir()));
  return report.launch.ok ? 0 : 1;
}

/** Shared with the launch notice: the same words for the same gap. */
export { notCoveredNotice };
