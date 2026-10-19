/**
 * secret-setup — establish the secret confinement for a launch
 * (docs/design/confidentiality/confidentiality.md §7.2/§7.3; plan 4′).
 *
 * The sequence, once per launch, when the confidentiality axis is on (modes `secrets`, `full`):
 *
 *   1. ASK the arbiter which catalog secret files exist under HOME + the
 *      workspace (`discoverSecrets`).
 *   2. ASK the arbiter to register each one (`registerSecret`) — THE ARBITER
 *      READS THE FILE, so raw secret bytes never enter THIS process. We only
 *      ever hold the symbol.
 *   3. Materialize a twin file per secret (content = the symbol) and wrap the
 *      agent exec so the twin is what the agent's world shows at that path
 *      (Linux) — or record the deny set so the path is unreadable (macOS:
 *      `result.seatbelt`, which the launch's one whole-agent Seatbelt
 *      profile carries, seatbelt-setup.ts).
 *
 * ROOT STAYS OPTIONAL (rootless-confinement-ubuntu-2404.md §2, §3.1): when the
 * HOST cannot confine (no bwrap, no unprivileged userns, an unsupported
 * platform) the launch proceeds in the named, weaker `gated` posture with a
 * loud, specific notice on every launch. It never claims what `confined`
 * claims: `cat ~/.aws/credentials | curl …` still works there
 * (confidentiality.md §10.1). `--require-confinement` restores the refusal and
 * wins over `--best-effort`. An ARBITER failure mid-setup is an incident, not a
 * host condition: it still REFUSES unless `--best-effort`. The decision table
 * is `confinement-posture.ts` `onConfinementFailure`.
 *
 * Mandu-new (no reference origin).
 */
import { resolveEnvSource, type EnvSource, type SourceResolver } from "./env-sources.js";
import { resolveWrapBwrap } from "./bwrap-grant.js";
import { systemBwrap } from "./bwrap-path.js";
import { connect } from "node:net";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import {
  bareTwinWrap,
  homeMaskOps,
  nestedSandboxProbeArgv,
  planSecretTwins,
  withObjectTwins,
  type SecretTwin,
} from "./secret-twins.js";
import {
  defaultGitRunner,
  groupByRepo,
  inventoryObjectDir,
  lockedNamesFor,
  maxRebuildBytesFromEnv,
  objectDirsOf,
  PREPARED_MAX_PACKS,
  preparedCopyTwins,
  preparedMaxReposFromEnv,
  prepareGitObjectTwins,
  repoRootAt,
  servedCopyDirs,
  type GitObjectTwinOpts,
  type GitObjectTwinResult,
  type GitRunner,
  type ObjectTwin,
  type PreparedCopyOpts,
  type PreparedCopyResult,
} from "./git-object-twins.js";
import type { CacheSealClient, CacheSealsWire, SealEntry, SealRejection } from "./cache-seals.js";
import { launchHintFile } from "./launch-hint.js";
import { preparePlaceholderWatch, type TwinSource, type WatchedRepo } from "./placeholder-commits.js";
import { cleanTwinsInIndex, endTwinIndexSession, livePeerRecords, TwinIndexRecorder, twinIndexRecordDir, type CleanedIndex } from "./twin-index-stat.js";
import type { TwinPrefetch } from "./twin-prefetch.js";
import type { GitSession } from "./git-session.js";
import { scopeTwinDir, watchTwins, type TwinWatch } from "./twin-writes.js";
import { basename, dirname, join as pathJoin } from "node:path";
import { manduPath } from "./generated/mandu-paths.js";
import { accountHome, cwdsInsideHome, homeCarveOuts } from "./own-paths.js";
import { storeLinkProblems, storeLinkRefusal, type StoreLinkFs } from "./store-links.js";
import type { LaunchMutation, LaunchPlan } from "./types.js";
import { APPARMOR_USERNS_SYSCTL, usernsGapHint } from "./userns.js";
import { docsUrl } from "./docs-url.js";
import {
  hostIsWsl, MOUNTINFO, parseMountinfo, windowsProfiles, windowsProfileSecretRoots, wslTwinWrapFlags,
} from "./wsl.js";

function readOrNull(p: string): string | null {
  try { return readFileSync(p, "utf8"); } catch { return null; }
}

/** The Windows user profiles on this WSL host (wsl.ts `windowsProfiles` over
 *  the live mount table). One readdir per drive's `Users`; nothing deeper. */
export function probeWindowsProfiles(): string[] {
  return windowsProfiles(parseMountinfo(readOrNull(MOUNTINFO) ?? ""), (p) => {
    try { return readdirSync(p, { withFileTypes: true }).map((d) => ({ name: d.name, dir: d.isDirectory() })); } catch { return null; }
  });
}
import {
  gapExplanation,
  gatedNotice,
  onConfinementFailure,
  type ConfinementPosture,
  type HostGap,
} from "./confinement-posture.js";
import { probeBwrapSymlink, symlinkProbeWarning, type SymlinkProbeResult } from "./bwrap-symlink-probe.js";
import { gitLocksField, lockedIdsOf } from "./git-lock-backstop.js";
import { movedNoticeField } from "./moved-files-notice.js";
import { compileHistoryLabels, historyPathspecs, withRealSpellings } from "./history-labels.js";
import { sandboxExecAvailable } from "./seatbelt-profile.js";
import { cachedProbe } from "./probe-cache.js";
import { publishFile } from "./safe-file.js";
import { gooseRoutedKeyVars } from "./goose-route.js";
import { AGENT_LOGIN_NAMES, LOGIN_ENV, launchLoginKeying, loginEnvOf, otherAgentLoginsRaw } from "./agent-login.js";

/** What `discoverSecrets` answers since 2026-09-24 (arbiter protocol
 *  DiscoverSecretsResultWire; secret-discovery.md §1.3): the files
 *  to mask plus the "not covered" ledger. Every field but `files` is optional
 *  here so an older arbiter's bare reply, and every existing mock, still
 *  types; `asDiscoveryReport` normalizes both shapes. */
export interface DiscoveryReport {
  /** `agentLogin`: another agent's login file, one this launch does not
   *  run on (secret-discovery.md §1.10). */
  files: Array<{ path: string; level?: string; rule?: string; agentLogin?: string }>;
  skipped?: Array<{ path: string; reason: string }>;
  counts?: Record<string, number>;
  limits?: { maxDepth: number; maxFiles: number };
  truncated?: boolean;
  /** The `depth` records grouped by folder, the most first (capped; an
   *  older arbiter sends none): secret-discovery.md §1.9 H. */
  depthAreas?: Array<{ path: string; count: number }>;
}

/** How many folders a "not searched" line names before "and N more
 *  elsewhere". */
export const DEPTH_AREAS_SHOWN = 3;

/** `depth` directories by folder, in words: `~/a (216), ~/b (91) and 33
 *  more elsewhere` (the count beyond the folders named, against the
 *  complete `depth` count); "" without areas. Pure. */
export function depthAreasWords(areas: ReadonlyArray<{ path: string; count: number }>, depth: number, home = "", shown = DEPTH_AREAS_SHOWN): string {
  if (areas.length === 0 || depth <= 0) return "";
  const tilde = (p: string): string => (home.length > 1 && (p === home || p.startsWith(home + "/")) ? "~" + p.slice(home.length) : p);
  const named = areas.slice(0, shown);
  const rest = depth - named.reduce((n, a) => n + a.count, 0);
  const list = named.map((a) => `${tilde(a.path)} (${a.count})`);
  return rest > 0 ? `${list.join(", ")} and ${rest} more elsewhere` : list.length > 1 ? `${list.slice(0, -1).join(", ")} and ${list[list.length - 1]}` : list[0]!;
}

/** Old shape (an array) or new (a report) → the report. */
export function asDiscoveryReport(r: Array<{ path: string }> | DiscoveryReport): DiscoveryReport {
  return Array.isArray(r) ? { files: r } : r;
}

const LEVELS = new Set(["public", "any-model", "local-model", "no-model"]);
const MARKER_LEVEL: Readonly<Record<string, string>> = { nomodel: "no-model", localmodel: "local-model", anymodel: "any-model" };

/** The level to record for one confined secret (confidentiality-plan-11 D5):
 *  the level the arbiter's discovery reports for the file (the label's level
 *  for a `paths:` entry, `no-model` for a catalog match); else the level the
 *  registered symbol's marker names (`$MDU:localmodel_…`); else `no-model`,
 *  the strictest, when neither says. Pure. */
export function secretLevel(discovered: string | undefined, symbol: string | null): string {
  if (discovered !== undefined && LEVELS.has(discovered)) return discovered;
  const m = symbol === null ? null : /^\$MDU:(nomodel|localmodel|anymodel)_/.exec(symbol);
  return m ? MARKER_LEVEL[m[1]!]! : "no-model";
}

/** The WARNING lines a launch (and the dry run) print for what the walk left
 *  RAW (secret-discovery.md §1.2 gap 1): a secret below the depth
 *  cap, a match beyond the file cap, an unreadable candidate, a truncated
 *  walk. Empty when nothing consequential was skipped — dangling links,
 *  directory links, the agent's own auth, too-deep directories inside a
 *  package cache (`package-cache`) and sockets/FIFOs named like a secret
 *  (`special-file`, §1.9 F) are expected and stay quiet here
 *  (`mandu doctor --secrets` lists them). Pure. */
export function notCoveredNotice(r: DiscoveryReport, maxPaths = 3, home = ""): string[] {
  const counts = r.counts ?? {};
  const limits = r.limits ?? { maxDepth: 0, maxFiles: 0 };
  const paths = (reason: string): string => {
    const ps = (r.skipped ?? []).filter((s) => s.reason === reason).map((s) => s.path);
    if (ps.length === 0) return "";
    return `: ${ps.slice(0, maxPaths).join(", ")}${ps.length > maxPaths ? `, +${ps.length - maxPaths} more` : ""}`;
  };
  const items: string[] = [];
  const depth = counts["depth"] ?? 0;
  if (depth > 0) {
    // By folder when the arbiter grouped them (§1.9 H): hundreds of deep
    // folders of a few checkouts read as those checkouts, not as 3 paths.
    const areas = depthAreasWords(r.depthAreas ?? [], depth, home);
    items.push(`${depth} director${depth === 1 ? "y" : "ies"} below depth ${limits.maxDepth} not searched${areas ? `, in ${areas}` : paths("depth")}`);
  }
  if ((counts["count"] ?? 0) > 0) items.push(`${counts["count"]} credential file${counts["count"] === 1 ? "" : "s"} beyond the ${limits.maxFiles}-file cap${paths("count")}`);
  if ((counts["unreadable"] ?? 0) > 0) items.push(`${counts["unreadable"]} unreadable candidate${counts["unreadable"] === 1 ? "" : "s"}${paths("unreadable")}`);
  if (r.truncated === true) items.push(`the walk stopped at the ${limits.maxFiles}-file cap: directories not yet visited were not searched`);
  if (items.length === 0) return [];
  return [
    "WARNING: mandu: secrets NOT covered by the walk (a program the agent runs could read these raw):",
    ...items.map((i) => `  - ${i}`),
    "  Details and the full inventory: mandu doctor --secrets",
  ];
}

/** What the walk needs beyond its roots and home: the launch's view
 *  state base (the path table's `view-state`, the home's `state/`), so the arbiter prunes Mandu's own
 *  state from the walk and finds the AgentView copies of the workspace
 *  through fs-sync's persisted view map instead
 *  (secret-discovery.md §1.9). Unset = fs-sync's default. */
export interface DiscoverOptions {
  stateBase?: string;
  /** The launch's package-cache variables (`packageCacheEnv`): a cache
   *  they move is recorded like a default one (secret-discovery.md §1.9 G). */
  cacheEnv?: Record<string, string>;
  /** The launched agent and the AI helper's CLI (agent-login.ts
   *  `launchLoginKeying`): only their login files stay raw; every other
   *  agent's is discovered and twinned (secret-discovery.md §1.10). Absent:
   *  every agent's login stays raw (the dry run without `--target`). */
  target?: string;
  ullmBinary?: string;
  /** The launch's login variables (`loginEnvOf`): where they move an
   *  agent's login file. */
  loginEnv?: Record<string, string>;
}

/**
 * The variables that move a package cache away from its default (Cargo's
 * registry under CARGO_HOME, Go's module cache under GOMODCACHE, …). MIRROR
 * of the arbiter's PACKAGE_CACHE_ENV (arbiter/policy/secret-discovery.ts
 * RELOCATED_PACKAGE_CACHES, which says what each one moves); the launcher
 * never imports the arbiter, so tests/stack/package-cache-env-parity.test.ts
 * pins the two lists equal. The arbiter is shared by every launch and cannot
 * read this session's environment, so the launcher sends these names, and
 * ONLY these names: they hold paths, while the rest of the environment can
 * hold keys.
 */
export const PACKAGE_CACHE_ENV: readonly string[] = [
  "CARGO_HOME", "GOMODCACHE", "GOPATH", "GRADLE_USER_HOME", "RUSTUP_HOME", "NVM_DIR",
  "npm_config_cache", "NPM_CONFIG_CACHE", "XDG_CACHE_HOME", "PIP_CACHE_DIR", "YARN_CACHE_FOLDER",
];

/** The PACKAGE_CACHE_ENV values set (non-empty) in `env`. Pure. */
export function packageCacheEnv(env: Readonly<Record<string, string | undefined>>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of PACKAGE_CACHE_ENV) {
    const v = env[name];
    if (typeof v === "string" && v !== "") out[name] = v;
  }
  return out;
}

/** The variables that move an agent's login file and the launch's values
 *  of them: agent-login.ts, re-exported for the callers of this module. */
export { LOGIN_ENV, loginEnvOf };

/** What a launch asks the walk with, beyond its roots: the view state base,
 *  the moved caches and where the agents log in, read from the launch's
 *  environment, and the agents it runs (`launch`: agent-login.ts
 *  `launchLoginKeying`). ONE function for run.ts's prefetch and the secret
 *  setup, so the prefetch is served (`withPrefetchedDiscovery` matches on
 *  these exactly). Pure. */
export function launchDiscoverOptions(
  env: Readonly<Record<string, string | undefined>>,
  home: string,
  launch?: { target: string; ullmBinary?: string },
): DiscoverOptions {
  const loginEnv = loginEnvOf(env);
  return {
    stateBase: manduPath("view-state", env, home), cacheEnv: packageCacheEnv(env),
    ...(launch?.target ? { target: launch.target } : {}),
    ...(launch?.target && launch.ullmBinary !== undefined ? { ullmBinary: launch.ullmBinary } : {}),
    ...(Object.keys(loginEnv).length > 0 ? { loginEnv } : {}),
  };
}

/** The discovery wire fields for `opts` (absent ones left out). */
export function discoverWireOpts(opts: DiscoverOptions | undefined): Record<string, unknown> {
  return {
    ...(opts?.stateBase ? { stateBase: opts.stateBase } : {}),
    ...(opts?.cacheEnv && Object.keys(opts.cacheEnv).length > 0 ? { cacheEnv: opts.cacheEnv } : {}),
    ...(opts?.target ? { target: opts.target } : {}),
    ...(opts?.ullmBinary ? { ullmBinary: opts.ullmBinary } : {}),
    ...(opts?.loginEnv && Object.keys(opts.loginEnv).length > 0 ? { loginEnv: opts.loginEnv } : {}),
  };
}

/** The narrow arbiter surface this module needs (CONTRIBUTING.md arbiter-client pattern). */
export interface SecretArbiter {
  /** The files to mask (an older arbiter / a plain mock answers the bare
   *  array; the real one answers the report). `home` is the LAUNCH's HOME:
   *  the catalog's `~/…` rules must resolve against the session's home, not
   *  the resident arbiter's (fixture-home table, 2026-09-24). */
  discoverSecrets(roots: string[], home?: string, opts?: DiscoverOptions): Promise<Array<{ path: string }> | DiscoveryReport>;
  /** `loginEnv`: the launch's login variables, sent for another agent's
   *  login file (discovery's `agentLogin`), so one a variable moved out of
   *  the catalog's places is registered as the walk found it
   *  (secret-discovery.md §1.10). */
  registerSecret(path: string, home?: string, loginEnv?: Record<string, string>): Promise<{ symbol: string | null; reason: string; twin?: string; fields?: number; readers?: { named: number; pinned: number }; terminator?: "" | "\n" | "\r\n" }>;
  /** Plan 10 §11.4: which of these variables are secrets, and what the agent's
   *  environment should carry for each. Optional so older mocks still type. */
  registerEnvSecrets?(vars: Array<{ name: string; value: string; agentKey?: boolean }>): Promise<{
    vars: Array<{ name: string; symbol: string | null; twin?: string; reason: string }>;
  }>;
  /** policy.yaml env.sources (comparisons.md §3.4). Optional so older mocks type. */
  envSources?(): Promise<{ sources: EnvSource[] }>;
  /** policy.yaml ssh_agent.readers (§3.5), or null when the agent socket is ungated. */
  sshAgentPolicy?(): Promise<{ readers: unknown[] | null }>;
  /** policy.yaml protect: paths no program may delete or rename. */
  protectPaths?(): Promise<{ paths: string[] }>;
  /** The signed consumer packs in force, and the ones refused. */
  consumerPacks?(): Promise<{ packs: Array<{ name: string; version: string; keyId: string; consumers: number }>; refused: string[] }>;
  /** What the object twins hide beyond the confined files
   *  (confidentiality-plan-14 §8.1, §8.2): the law's blob locks above
   *  `public` and the human labels, every level. Optional so older mocks type. */
  gitHistoryLocks?(roots?: readonly string[]): Promise<GitHistoryLocksWire>;
  /** Plan 14 §11.2 (HUMAN PLANE): the current epoch's seals for these cache
   *  entries. Present only when the arbiter reported a human socket; absent,
   *  no git-history cache is trusted (every launch walks and rebuilds). */
  cacheSeals?(kind: string, keys: string[]): Promise<CacheSealsWire>;
  /** Plan 14 §11.2 (HUMAN PLANE): seal entries just written or verified;
   *  report the ones not used. */
  sealCacheEntries?(entries: SealEntry[], rejected: SealRejection[]): Promise<unknown>;
}

/** What `hideGitHistory` (applySecretTwins) produced. */
interface HiddenHistory {
  twins: ObjectTwin[];
  /** The locked set for the guard's backstop (git-lock-backstop.ts). */
  lockedIds: string[];
  gitObjects?: { repos: number; blobs: number; files: number; packsRebuilt: number; cacheHits: number };
}

/** The arbiter's `gitHistoryLocks` answer (arbiter/ipc/protocol.ts
 *  `GitHistoryLocksResult`; the launcher does not import the arbiter). */
export interface GitHistoryLocksWire {
  axis: boolean;
  blobs: Array<{ id: string; level: string }>;
  labels: Array<{ path: string; level: string; recursive: boolean; glob?: true }>;
  /** Plan 14 §11.1 R2 (an arbiter that resolves in the background): the
   *  repositories it resolved, each with its resolution key and labelled
   *  versions. Absent from an older arbiter; an entry the launcher cannot
   *  read is dropped (that repository is walked here, as before). */
  repos?: Array<{ root: string; format: "sha1" | "sha256"; key: string; blobs: string[] }>;
  /** Plan 14 §11.1 R2: the GLOBAL locked set, bare hex names per object
   *  format (every known repository's labelled versions and the `blobs:`
   *  locks above `public`). The guard's backstop gets it (R4), merged with
   *  what this launch resolved itself (the set can lag a repository's new
   *  commits by one of the arbiter's cycles). Absent from an older arbiter. */
  lockedSet?: { sha1: string[]; sha256: string[] };
  /** Plan 14 §11.1 R3: the repositories whose sanitized copies the arbiter
   *  prepared ahead of time. A hint (preparedCopyTwins checks each copy's
   *  exclusion and seals itself); a malformed entry is dropped (that
   *  repository stays with the guard's backstop). Absent from an older
   *  arbiter, or with preparation off. */
  prepared?: Array<{ root: string; format: "sha1" | "sha256" }>;
}

/** `lockedSet` as the arbiter answers it: bare lowercase hex, 40 digits under
 *  `sha1`, 64 under `sha256`. A malformed one refuses like the rest of the
 *  answer (it would only ever shrink what the guard refuses). */
function isLockedSet(v: unknown): v is { sha1: string[]; sha256: string[] } {
  const o = v as { sha1?: unknown; sha256?: unknown } | null;
  const hexes = (x: unknown, n: number): boolean => Array.isArray(x) && x.every((h) => typeof h === "string" && h.length === n && /^[0-9a-f]+$/.test(h));
  return o !== null && typeof o === "object" && hexes(o.sha1, 40) && hexes(o.sha256, 64);
}

const HEX_NAME = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

/** The answer, checked: a shape the launcher does not understand is a
 *  failure (the caller's fail-closed path), never "no locks". The
 *  background resolution (`repos`) only saves a walk, so a malformed entry
 *  there is dropped rather than refused: the launcher walks that
 *  repository itself. */
export function asGitHistoryLocks(v: unknown): GitHistoryLocksWire {
  const o = v as Partial<GitHistoryLocksWire> | null;
  const str = (x: unknown): x is string => typeof x === "string" && x !== "";
  if (o === null || typeof o !== "object" || typeof o.axis !== "boolean" || !Array.isArray(o.blobs) || !Array.isArray(o.labels)
    || !o.blobs.every((b) => b !== null && typeof b === "object" && str(b.id) && str(b.level))
    || !o.labels.every((l) => l !== null && typeof l === "object" && str(l.path) && str(l.level) && typeof l.recursive === "boolean")
    || (o.lockedSet !== undefined && !isLockedSet(o.lockedSet))) {
    throw new Error("gitHistoryLocks: the arbiter's answer is not {axis, blobs[], labels[], lockedSet?: {sha1[], sha256[]}}");
  }
  const repos = Array.isArray(o.repos)
    ? o.repos.filter((r): r is NonNullable<GitHistoryLocksWire["repos"]>[number] =>
      r !== null && typeof r === "object" && str(r.root) && r.root.startsWith("/") && (r.format === "sha1" || r.format === "sha256")
      && str(r.key) && Array.isArray(r.blobs)
      && r.blobs.every((b) => typeof b === "string" && HEX_NAME.test(b) && b.length === (r.format === "sha256" ? 64 : 40)))
      .map((r) => ({ root: r.root, format: r.format, key: r.key, blobs: [...r.blobs] }))
    : undefined;
  const prepared = Array.isArray(o.prepared)
    ? o.prepared.filter((r): r is NonNullable<GitHistoryLocksWire["prepared"]>[number] =>
      r !== null && typeof r === "object" && str(r.root) && r.root.startsWith("/") && !r.root.includes("\0") && (r.format === "sha1" || r.format === "sha256"))
      .slice(0, 256).map((r) => ({ root: r.root, format: r.format }))
    : undefined;
  return {
    axis: o.axis,
    blobs: o.blobs.map((b) => ({ id: b.id, level: b.level })),
    labels: o.labels.map((l) => ({ path: l.path, level: l.level, recursive: l.recursive, ...(l.glob === true ? { glob: true as const } : {}) })),
    ...(repos !== undefined ? { repos } : {}),
    ...(prepared !== undefined ? { prepared } : {}),
    ...(o.lockedSet !== undefined ? { lockedSet: { sha1: [...o.lockedSet.sha1], sha256: [...o.lockedSet.sha256] } } : {}),
  };
}

/** The seal client the object twins use (cache-seals.ts), or undefined when
 *  the arbiter adapter has no seal ops (no human socket, an older arbiter, a
 *  mock): then no git-history cache is trusted. */
export function sealClientOf(arbiter: SecretArbiter): CacheSealClient | undefined {
  const lookup = arbiter.cacheSeals?.bind(arbiter);
  const record = arbiter.sealCacheEntries?.bind(arbiter);
  if (lookup === undefined || record === undefined) return undefined;
  return { lookup: (kind, keys) => lookup(kind, keys), record: (entries, rejected) => record(entries, rejected) };
}

/** Is this an arbiter that predates `gitHistoryLocks` (its dispatch answers
 *  an unknown op)? Such an arbiter cannot hold a blob lock either: its
 *  validator refuses a `blobs:` section. */
export function isUnknownOpError(e: unknown): boolean {
  return /unknown op/i.test((e as Error)?.message ?? "");
}

/** Per-call deadline, mirroring the arbiter client's fail-closed bound
 *  (arbiter/ipc/client.ts `DEFAULT_REQUEST_TIMEOUT_MS`): an arbiter that is
 *  reachable but wedged — accepting but never replying, or stalled mid-accept —
 *  must surface as a rejection, which `applySecretTwins` turns into its
 *  fail-closed refusal. Without it, a silent socket hangs the whole
 *  `--confidentiality` launch forever. */
export const REQUEST_TIMEOUT_MS = 5000;

/**
 * confidentiality.md §7.2a (2026-09-30): where the guard serves the twins
 * with NO bind over them (the guard-only posture), it also answers a stat by
 * path that follows links (`stat`, `newfstatat`, `statx`), and an `lstat`
 * relative to the cwd (2026-10-04, §7.2a "The size a reader sees"), of a
 * twinned file with the twin's metadata, as the bind would (mandu-net-guard
 * `stat_twin`; `MANDU_NET_GUARD_LSTAT_TWINS=0` leaves `lstat` free).
 * Without it git stats the real pack, reads the sanitized one by descriptor,
 * finds the sizes differ and drops the whole pack, and `git diff --no-index`
 * prints a twin cut at the real file's size. Set in that posture, and under
 * the bind only when a protected file has a hard link besides its own name
 * (`linkedSecretFiles`, P0 4c): the bind covers one name, so a second link
 * made before the launch would show the real file's size; elsewhere the
 * path already IS the twin, and the trap costs every such stat in the tree
 * a round trip to the guard.
 */
export const GUARD_STAT_TWINS_ENV = "MANDU_NET_GUARD_STAT_TWINS";

/**
 * confidentiality.md §7.2a "Another name for a twinned file" (P0 4c,
 * 2026-10-09): the protected files (their resolved targets) that have a
 * hard link besides their own name. Under the bind the twin covers one
 * name; another link, made before the launch, would show the real file's
 * size, times and inode, so the launcher turns the guard's stat trap on
 * for that session, and the guard answers every name of the file with the
 * twin's metadata (it matches by `(st_dev, st_ino)`). The guard refuses a
 * hard link made in the session, so a file with one link at launch keeps
 * the trap off and its cost at nothing. `linkCount` null (the file could
 * not be stat'ed): counted as linked, fail-closed (the cost, never the
 * size). Pure.
 */
export function linkedSecretFiles(targets: readonly string[], linkCount: (path: string) => number | null): string[] {
  return targets.filter((t) => {
    const n = linkCount(t);
    return n === null || n > 1;
  });
}

/** A file's hard-link count (`st_nlink`), following a symlink; null when it
 *  cannot be stat'ed. */
export function fileLinkCount(path: string): number | null {
  try {
    return statSync(path).nlink;
  } catch {
    return null;
  }
}

/** `discoverSecrets` walks HOME + the workspace roots (real filesystem I/O
 *  over a cold cache), the one op whose honest worst case exceeds the 5s
 *  bound — the same carve-out as the arbiter client's
 *  `DISCOVER_SECRETS_TIMEOUT_MS`. Once per launch, off any hot path. */
export const DISCOVER_SECRETS_TIMEOUT_MS = 30_000;

/** One NDJSON request/response over the arbiter's unix socket. The launcher
 *  deliberately does not import the arbiter package (no repo workspace); the
 *  protocol is one JSON line each way. The deadline spans connect + write +
 *  reply (a wedged peer can stall the dial too). Unlike the shared
 *  `ArbiterClient` — which on expiry must NOT destroy its long-lived socket
 *  lest it fail concurrent in-flight calls — this socket is one-shot per call,
 *  so destroying it on every settle path IS the cleanup. */
export function ndjsonCall<T>(
  sock: string,
  op: string,
  args: Record<string, unknown>,
  timeoutMs: number,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const c = connect(sock);
    let buf = "";
    let timer: ReturnType<typeof setTimeout> | undefined;
    const done = (err: Error | null, val?: T): void => {
      if (timer !== undefined) clearTimeout(timer);
      c.destroy();
      if (err) reject(err);
      else resolve(val as T);
    };
    timer = setTimeout(
      () => done(new Error(`arbiter ${op} timed out after ${timeoutMs}ms — fail closed`)),
      timeoutMs,
    );
    c.setEncoding("utf8");
    c.on("error", (e) => done(e));
    c.on("connect", () => c.write(JSON.stringify({ id: 1, op, ...args }) + "\n"));
    c.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try {
        const resp = JSON.parse(buf.slice(0, nl)) as
          | { ok: true; result: T }
          | { ok: false; error: string };
        if (resp.ok) done(null, resp.result);
        else done(new Error(resp.error));
      } catch (e) {
        done(e as Error);
      }
    });
  });
}

/** The real arbiter, over its socket. `requestTimeoutMs` overrides BOTH ops'
 *  deadlines (a test knob; production callers take the defaults). */
/** The discovery walk started ahead of `applySecretTwins`, so it overlaps
 *  the rest of the launch (the proxies, the network confine): on a real
 *  home it walks ~50,000 directories, seconds of every launch. */
export interface DiscoveryPrefetch {
  roots: string[];
  home: string;
  opts: DiscoverOptions;
  result: ReturnType<SecretArbiter["discoverSecrets"]>;
}

/** Start the walk now. A failure is held for whoever awaits `result` (the
 *  secret setup's fail-closed refusal), never an unhandled rejection. The
 *  caller starts it only once the AgentView is seeded: the walk reads this
 *  workspace's AgentView copy (secret-discovery.ts `agentViewRoots`). */
export function prefetchDiscovery(arbiter: SecretArbiter, roots: string[], home: string, opts: DiscoverOptions): DiscoveryPrefetch {
  const result = arbiter.discoverSecrets(roots, home, opts);
  result.catch(() => { /* surfaced where `result` is awaited */ });
  return { roots, home, opts, result };
}

/** `arbiter`, answering the FIRST `discoverSecrets` call whose arguments are
 *  exactly the prefetch's from the prefetch. Any other call (other roots, a
 *  WSL profile, a second call) asks the arbiter as before. */
export function withPrefetchedDiscovery(arbiter: SecretArbiter, prefetch: DiscoveryPrefetch | undefined): SecretArbiter {
  if (prefetch === undefined) return arbiter;
  const key = (roots: string[], home: string | undefined, opts: DiscoverOptions | undefined) =>
    JSON.stringify([roots, home ?? null, opts?.stateBase ?? null, opts?.cacheEnv ?? {}, opts?.target ?? null, opts?.ullmBinary ?? null, opts?.loginEnv ?? {}]);
  const want = key(prefetch.roots, prefetch.home, prefetch.opts);
  let used = false;
  // Every other method is the arbiter's own, through the prototype chain (a
  // spread would drop a class's methods and silently lose an optional op).
  const wrapped = Object.create(arbiter) as SecretArbiter;
  wrapped.discoverSecrets = (roots, home, opts) => {
    if (!used && key(roots, home, opts) === want) {
      used = true;
      return prefetch.result;
    }
    return arbiter.discoverSecrets(roots, home, opts);
  };
  return wrapped;
}

export function socketSecretArbiter(
  sock: string,
  opts?: { requestTimeoutMs?: number; humanSock?: string | null },
): SecretArbiter {
  const perCall = opts?.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
  const discover = opts?.requestTimeoutMs ?? DISCOVER_SECRETS_TIMEOUT_MS;
  const human = opts?.humanSock ?? null;
  // Plan 14 §11.2: the seal ops are human plane, so they exist only with the
  // human socket the arbiter reported (never the data socket in its place).
  const sealOps: Pick<SecretArbiter, "cacheSeals" | "sealCacheEntries"> = human === null ? {} : {
    async cacheSeals(kind, keys) {
      return ndjsonCall<CacheSealsWire>(human, "cacheSeals", { kind, keys }, perCall);
    },
    async sealCacheEntries(entries, rejected) {
      return ndjsonCall<unknown>(human, "sealCacheEntries", { entries, ...(rejected.length > 0 ? { rejected } : {}) }, perCall);
    },
  };
  return {
    ...sealOps,
    async discoverSecrets(roots, home, opts) {
      return ndjsonCall<DiscoveryReport>(
        sock, "discoverSecrets",
        { roots, ...(home ? { home } : {}), ...discoverWireOpts(opts) },
        discover,
      );
    },
    async registerSecret(path, home, loginEnv) {
      // Over the human socket when the arbiter reported one: only there does
      // the launch HOME's `.npmrc` / pip.conf earn its wire grant
      // (confidentiality.md §2.1); over the data socket, which the agent's
      // world can reach, the file is registered with no grant.
      return ndjsonCall<{ symbol: string | null; reason: string; twin?: string; fields?: number; terminator?: "" | "\n" | "\r\n" }>(
        human ?? sock, "registerSecret", { path, ...(home ? { home } : {}), ...(loginEnv && Object.keys(loginEnv).length > 0 ? { loginEnv } : {}) }, perCall,
      );
    },
    async registerEnvSecrets(vars) {
      // Over the human socket when the arbiter reported one: a pip index
      // variable's wire grant is then RECORDED and kept across an arbiter
      // restart (confidentiality.md §2.1); over the data socket, which the
      // agent's world can reach, it stays in the arbiter's memory.
      return ndjsonCall<{ vars: Array<{ name: string; symbol: string | null; twin?: string; reason: string }> }>(
        human ?? sock, "registerEnvSecrets", { vars }, perCall,
      );
    },
    async envSources() {
      return ndjsonCall<{ sources: EnvSource[] }>(sock, "envSources", {}, perCall);
    },
    async sshAgentPolicy() {
      return ndjsonCall<{ readers: unknown[] | null }>(sock, "sshAgentPolicy", {}, perCall);
    },
    async protectPaths() {
      return ndjsonCall<{ paths: string[] }>(sock, "protectPaths", {}, perCall);
    },
    async consumerPacks() {
      return ndjsonCall<{ packs: Array<{ name: string; version: string; keyId: string; consumers: number }>; refused: string[] }>(sock, "consumerPacks", {}, perCall);
    },
    async gitHistoryLocks(roots) {
      // `roots`: the launch's workspace, registered with the arbiter's
      // known-repository registry (plan 14 §11.1 R1). An older arbiter
      // ignores the field.
      return ndjsonCall<GitHistoryLocksWire>(sock, "gitHistoryLocks", roots !== undefined && roots.length > 0 ? { roots: [...roots] } : {}, perCall);
    },
  };
}

export interface SecretSetupDeps {
  arbiter: SecretArbiter;
  /** Is a command there? `bwrap` is looked up on PATH; macOS asks for
   *  `/usr/bin/sandbox-exec` by its absolute path, which `command -v` checks
   *  as a file (seatbelt-profile.ts `sandboxExecAvailable`). */
  commandExists: (cmd: string) => boolean;
  /** Can we create an unprivileged user+mount namespace? (Linux only.) */
  usernsOk: () => boolean;
  /** WHY not (src/userns.ts `usernsGapHint`): the cause + fix appended to the
   *  refusal so "Fix it" names the knob. Default reads the kernel sysctls. */
  usernsHint?: () => string;
  /** kernel.apparmor_restrict_unprivileged_userns reads 1: the one userns gap
   *  `mandu setup` can fix. Default reads the sysctl. */
  apparmorRestricted?: () => boolean;
  platform: "linux" | "darwin" | "win32";
  log: (msg: string) => void;
  home?: string;
  /** Workspace roots to scan in addition to HOME (typically the cwd). */
  workspaceRoots?: string[];
  /** $SSH_AUTH_SOCK override (a test knob; production reads the environment). */
  sshAuthSock?: string;
  /** The environment Mandu's own paths are resolved against
   *  (`ownStoresHidden`: MANDU_HOME, the CA dir; the discovery walk's state
   *  base; the git twin caches). A test knob; production reads the
   *  launcher's environment. */
  env?: NodeJS.ProcessEnv;
  /** Create the Mandu home owner-only when it is missing (`makeHomeDir`).
   *  A test knob. */
  makeHome?: (dir: string) => void;
  /** The filesystem the store-link check reads (store-links.ts). A test knob. */
  storeLinkFs?: StoreLinkFs;
  /** The account's passwd home, whose `~/.mandu` is denied too (default:
   *  `accountHome()`); null denies none beyond the launch's own. A test knob. */
  accountHome?: string | null;
  /** Registered path → real bind target (default: `resolveSecretTarget`, i.e.
   *  realpath). A test knob; production takes the default. */
  resolveTarget?: (path: string) => string | null;
  /** Plan 10 §11.7 / phase 6: the whole-agent guard is wrapped around this
   *  launch and will serve every registered secret by descriptor (the twin to
   *  non-readers, the real file to readers). With it, a host that cannot
   *  mount the twin bind (no user namespace) is still CONFINED: the twins
   *  are materialized and named in the guard's policy file, no bind. */
  guardServesTwins?: boolean;
  /** A protected file's hard-link count (`linkedSecretFiles`). Default:
   *  `fileLinkCount` (a stat). A test knob. */
  linkCount?: (path: string) => number | null;
  /** Can a sandbox start INSIDE the bind wrap (secret-twins.ts
   *  `nestedSandboxProbeArgv`; true iff it exits 0)? Asked only when the
   *  bind is about to be used. Default: run the probe. A test knob. */
  nestingOk?: (argv: string[]) => boolean;
  /** The CVE-2026-87766 probe of the wrap's bwrap (bwrap-symlink-probe.ts),
   *  asked only when the bind is about to be used; a `vulnerable` answer is
   *  one WARNING line, never a refusal. Default: run the probe. A test knob. */
  symlinkProbe?: (bwrap: string) => SymlinkProbeResult;
  /** The bwrap the twin wrap runs: Mandu's own copy where `mandu setup`
   *  installed it and its grant is loaded, else the distribution's by absolute
   *  path (bwrap-grant.ts
   *  `resolveWrapBwrap`). A test knob. */
  wrapBwrap?: string;
  /** Is this a WSL host (wsl.ts `hostIsWsl`)? Adds the interop hiding to the
   *  twin wrap. Default: probe the running host. A test knob. */
  onWsl?: boolean;
  /** Does a path exist (the WSL paths the wrap hides)? Default: existsSync. */
  pathExists?: (path: string) => boolean;
  /** WSL: the Windows user profiles whose credential stores are discovered
   *  too, each as its own home (wsl.ts `windowsProfiles`). Default on WSL:
   *  probe the drvfs mounts; never consulted off WSL. A test knob. */
  windowsProfiles?: string[];
  /** The object-store twins for the confined files' committed bytes
   *  (git-object-twins.ts `prepareGitObjectTwins`). A test knob. */
  gitObjectTwins?: (realPaths: string[], opts: GitObjectTwinOpts) => Promise<GitObjectTwinResult>;
  /** The copies the arbiter prepared ahead of time (git-object-twins.ts
   *  `preparedCopyTwins`, plan 14 §11.1 R3). A test knob. */
  preparedCopies?: (repos: ReadonlyArray<{ root: string; format: "sha1" | "sha256" }>, opts: PreparedCopyOpts) => Promise<PreparedCopyResult>;
  /** The git reads started at launch start (twin-prefetch.ts
   *  `startTwinPrefetch`): its states and hashes are used only where they
   *  are what the twins would compute now. The caller closes it. */
  twinPrefetch?: Pick<TwinPrefetch, "hashes" | "take">;
  /** The launch's git session (git-session.ts): the history step's and the
   *  placeholder watch's git calls run in its one sandbox. The caller opens
   *  it at launch start and closes it after this setup. Unset: the step
   *  opens its own; the watch runs one sandbox per call. */
  gitSession?: GitSession;
  /** THIS launch's agent's own credential files (`agentOwnCredentialFiles`):
   *  registered like any secret (so a tool output that carries one of their
   *  values reaches the model as a placeholder) but neither twinned nor
   *  denied, because the agent itself reads its key from them to start
   *  (secret-discovery.ts AGENT_LOGIN_FILES, keyed by the walk itself, is
   *  the same rule for Claude Code's, Codex's and OpenCode's logins; another
   *  agent's login comes back tagged `agentLogin` and is twinned, or left
   *  readable like these under MANDU_OTHER_AGENT_LOGINS=raw). Matched by
   *  real path. */
  agentOwnFiles?: readonly string[];
  /** THIS launch's agent's own login files it holds an auth grant for
   *  (agent-key-grant.ts `registerCodexKeyGrant`, agent-sign-in.md §3.9:
   *  Codex's `auth.json` with a saved key). The walk leaves the launched
   *  agent's login out (secret-discovery.md §1.10); these are registered
   *  and twinned anyway, as any catalog secret, because the model proxy
   *  puts the key back. */
  grantedLoginFiles?: readonly string[];
  /** macOS: the repositories where a confined file is committed
   *  (`trackedSecretRepos`). A test knob. */
  gitTracked?: (realPaths: string[]) => Promise<Array<{ root: string; checked: boolean }>>;
  /** macOS: this launch's repositories holding a version a history lock
   *  covers (`lockedHistoryRepos`). A test knob. */
  gitLocked?: (launch: LockedHistoryLaunch, locks: GitHistoryLocksWire) => Promise<Array<{ root: string; checked: boolean }>>;
  /** The twinned files inside a git work tree, watched for a commit of
   *  their placeholder (placeholder-commits.ts `preparePlaceholderWatch`).
   *  A test knob. */
  placeholderWatch?: (files: TwinSource[]) => Promise<WatchedRepo[]>;
  /** The tracked twinned files made to look clean to git in the agent's
   *  world (twin-index-stat.ts `cleanTwinsInIndex`). A test knob. */
  twinIndex?: (repos: WatchedRepo[]) => Promise<CleanedIndex[]>;
}

/** The repositories a macOS launch reaches, for `lockedHistoryRepos`. */
export interface LockedHistoryLaunch {
  /** The launch's workspace (the roots `gitHistoryLocks` was given). */
  workspaceRoots: readonly string[];
  /** The confined files' real paths. */
  realPaths: readonly string[];
}

/**
 * macOS: which of this launch's repositories (the workspace's work tree, a
 * confined file's) hold a version the plan-14 history locks cover: a
 * policy.yaml `blobs:` lock above `public`, a labelled path's version the
 * arbiter resolved there, or an id of its global locked set (a clone or a
 * fork holds the same blob). A Linux launch hides those versions (object
 * twins, prepared copies, the guard's backstop: confidentiality-plan-14 §8,
 * §11.1); macOS has none of those layers, so they stay readable to programs
 * the agent runs and the launch says where. NOTHING HERE ENFORCES.
 *
 * Found by name only, as the Linux planner finds them (git-object-twins.ts
 * `objectDirsOf` and `inventoryObjectDir`: each pack's `.idx` by its fanout
 * and a binary search, the loose objects by path); no blob is read. A
 * workspace repository the arbiter has not resolved yet (it lists each root
 * it was given in `repos` once resolved) while a label above `public`
 * reaches inside it, or a repository git cannot name the object store of,
 * is reported as not checked (and counted: a notice errs loud). Sorted by
 * root.
 */
export async function lockedHistoryRepos(
  launch: LockedHistoryLaunch,
  locks: GitHistoryLocksWire,
  opts: { git?: GitRunner; exists?: (p: string) => boolean; realpath?: (p: string) => string } = {},
): Promise<Array<{ root: string; checked: boolean }>> {
  if (!locks.axis) return [];
  const git = opts.git ?? defaultGitRunner;
  const exists = opts.exists ?? existsSync;
  const real = opts.realpath ?? ((p: string): string => { try { return realpathSync(p); } catch { return p; } });
  const asked = new Set(launch.workspaceRoots.map((w) => repoRootAt(real(w), exists)).filter((r): r is string => r !== null));
  const roots = [...new Set([...asked, ...groupByRepo([...launch.realPaths], exists).keys()])].sort();
  const resolved = new Map((locks.repos ?? []).map((r) => [r.root, r]));
  // Every id a Linux launch would keep out of these repositories: the blob
  // locks, the global set, and what the arbiter resolved (git-lock-backstop.ts).
  const ids = lockedIdsOf({
    blobs: locks.blobs,
    resolved: (locks.repos ?? []).flatMap((r) => r.blobs.map((b) => `${r.format}:${b}`)),
    ...(locks.lockedSet !== undefined ? { lockedSet: locks.lockedSet } : {}),
  });
  const labels = compileHistoryLabels(withRealSpellings(locks.labels, real));
  const out: Array<{ root: string; checked: boolean }> = [];
  for (const root of roots) {
    const specs = historyPathspecs(root, labels);
    const unresolved = asked.has(root) && !resolved.has(root) && (specs === null || specs.length > 0);
    let held: boolean | null = false;
    if (ids.length > 0) {
      try {
        const { dirs, hashLen } = await objectDirsOf(git, root);
        const names = lockedNamesFor(ids, hashLen);
        held = names.length > 0 && dirs.some((d) => {
          const inv = inventoryObjectDir(d, names, hashLen);
          return inv.looseProtected.length > 0 || inv.packs.some((p) => p.held.length > 0);
        });
      } catch {
        held = null;
      }
    }
    if (held === true) out.push({ root, checked: true });
    else if (held === null || unresolved) out.push({ root, checked: false });
  }
  return out;
}

/**
 * macOS: the repositories where one of `realPaths` is committed or staged
 * (its bytes are in the object store, where the Seatbelt deny on the file
 * does not reach: `git show`, `git log -p`). One `ls-files` and, when that
 * is empty, one `log --all -1` per repository, concurrently, each bounded; a
 * repository git cannot answer for is reported as not checked (and counted
 * as committed: a notice errs loud). Sorted by root.
 */
export async function trackedSecretRepos(
  realPaths: readonly string[],
  opts: { git?: GitRunner; exists?: (p: string) => boolean; timeoutMs?: number } = {},
): Promise<Array<{ root: string; checked: boolean }>> {
  const git = opts.git ?? defaultGitRunner;
  const timeoutMs = opts.timeoutMs ?? 5000;
  const byRepo = [...groupByRepo(realPaths, opts.exists ?? existsSync)];
  const verdicts = await Promise.all(byRepo.map(async ([root, rels]) => {
    const idx = await git(["ls-files", "--", ...rels], { cwd: root, timeoutMs });
    if (idx.code === 0 && idx.stdout.trim() !== "") return { root, checked: true, tracked: true };
    const hist = await git(["log", "--all", "-1", "--format=%H", "--", ...rels], { cwd: root, timeoutMs });
    if (hist.code === 0) return { root, checked: true, tracked: hist.stdout.trim() !== "" };
    return { root, checked: false, tracked: true };
  }));
  return verdicts.filter((v) => v.tracked).map(({ root, checked }) => ({ root, checked })).sort((a, b) => (a.root < b.root ? -1 : a.root > b.root ? 1 : 0));
}

/** The one WARNING a macOS launch prints for the git history it cannot
 *  hide, or null when there is none: the repositories where a protected file
 *  is committed (`trackedSecretRepos`) and those holding a version a history
 *  lock covers (`lockedHistoryRepos`: a `blobs:` lock, a labelled path's
 *  earlier versions). One line whichever of the two it names. Pure. */
export function gitHistoryNotice(
  repos: ReadonlyArray<{ root: string; checked: boolean }>,
  locked: ReadonlyArray<{ root: string; checked: boolean }> = [],
): string | null {
  if (repos.length === 0 && locked.length === 0) return null;
  const names = repos.map((r) => (r.checked ? r.root : `${r.root} (git did not answer; assumed committed)`));
  const lockNames = locked.map((r) => (r.checked ? r.root : `${r.root} (not checked; assumed)`));
  const lockPart = "a history lock (policy.yaml `blobs:`, or a labelled path's earlier versions) covers committed versions in";
  if (locked.length === 0) {
    return (
      `WARNING: mandu: a protected file is committed to git in ${names.join(", ")}: on macOS its committed bytes stay ` +
      "readable to programs the agent runs (git show, git log -p); only Linux hides a protected file's git history. " +
      "Remove it from the history, or rotate the secret."
    );
  }
  if (repos.length === 0) {
    return (
      `WARNING: mandu: ${lockPart} ${lockNames.join(", ")}: on macOS they stay readable to programs the agent runs ` +
      "(git show, git log -p); only Linux hides locked git history. Remove them from the history, or rotate the secret."
    );
  }
  return (
    `WARNING: mandu: a protected file is committed to git in ${names.join(", ")}, and ${lockPart} ${lockNames.join(", ")}: ` +
    "on macOS those committed bytes stay readable to programs the agent runs (git show, git log -p); only Linux hides " +
    "a protected file's or a lock's git history. Remove them from the history, or rotate the secret."
  );
}

/** Make the Mandu home `0700` when it is missing, before the launch hides
 *  it: a home the agent could create would be a directory Mandu later
 *  trusts with its stores. Where it cannot be made (a parent this user may
 *  not write, a test's `/dev/null/...` home), the agent, running as the
 *  same user, cannot make it either, and the deny rule still names it. */
export function makeHomeDir(dir: string): void {
  try { mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch { /* see above */ }
}

/** Mandu's own shadow repositories (`<home>/state/workspaces`): hidden from
 *  the agent when integrity is OFF (`secrets` mode), where no AgentView
 *  worktree exists and nothing the agent runs needs them; their `mdu-main`
 *  line holds raw bytes of every tracked file, protected ones included
 *  (fs-sync.md §3.8). They lie inside the Mandu home, which
 *  `ownStoresHidden` hides whole; this names them for the launch notice.
 *  Returns the real directory, or null when the mask does not apply. */
export function shadowRepoMaskDir(plan: LaunchPlan, home: string, exists: (p: string) => boolean, env: NodeJS.ProcessEnv = process.env): string | null {
  if ((plan.effectiveAxes?.integrity ?? plan.integrity) === true) return null;
  const dir = manduPath("workspaces", env, home);
  if (!exists(dir)) return null;
  try { return realpathSync(dir); } catch { return null; }
}

/** The carve-outs of the Mandu home this launch's agent may read and write
 *  (own-paths.ts `homeCarveOuts`, on-disk-layout.md §4): in the integrity
 *  modes the AgentView it runs in (its cwd, its view map's AgentView sides),
 *  and in `full` that workspace's `repo.git`. Real paths, existing ones
 *  only (a bind needs its source; a missing one has nothing to open). The
 *  write-protect list takes the same value (write-protect.ts
 *  `writeProtectList`'s `carveOuts`). */
export function launchHomeCarveOuts(
  plan: LaunchPlan,
  home: string,
  env: NodeJS.ProcessEnv,
  exists: (p: string) => boolean = existsSync,
  real: (p: string) => string = realpathSync,
): string[] {
  const realOr = (p: string): string => {
    try { return real(p); } catch { return p; }
  };
  const axes = {
    confidentiality: (plan.effectiveAxes?.confidentiality ?? plan.confidentiality) === true,
    integrity: (plan.effectiveAxes?.integrity ?? plan.integrity) === true,
  };
  const candidates = [plan.cwd, ...(plan.viewMap ?? []).map((v) => v.agent)]
    .filter((p): p is string => typeof p === "string" && p !== "")
    .map(realOr);
  return homeCarveOuts(axes, realOr(manduPath("mandu-home", env, home)), candidates).filter((p) => exists(p));
}

/** The Mandu home's locations for a launch (on-disk-layout.md §4): the home
 *  (MANDU_HOME, else ~/.mandu) and, when MANDU_HOME moves it, the default
 *  `~/.mandu` too (a relocated home never un-hides the default one's
 *  stores). Unresolved, effective home first. */
export function manduHomes(env: NodeJS.ProcessEnv, home: string, account: string | null = accountHome()): string[] {
  // The account's own `~/.mandu` too: a launch with a scratch HOME (an eval
  // leg, a test) must not reach the real home's stores either.
  const own = account ? [manduPath("mandu-home", {}, account)] : [];
  return [...new Set([manduPath("mandu-home", env, home), manduPath("mandu-home", {}, home), ...own])];
}

/** What the agent may not reach, for the layers that hide it
 *  (on-disk-layout.md §4: ONE rule, deny read and write under the Mandu
 *  home, with the integrity modes' carve-outs). The home holds every store
 *  of originals: the symbol DB (`symbols.value` maps every `$MDU:`
 *  placeholder to its original), the event log (`DualRepr.original`), the
 *  shadow repositories' raw bytes, the history-walk cache, the law, the
 *  developer API keys, and any stray file an older layout left there.
 *  Outside it: this launch's event dir and egress CA private key. Nothing
 *  the agent runs needs them: it reaches the symbol table and the events
 *  through the arbiter socket, and its own components take their settings
 *  from the environment and the scope run dir.
 *
 *  `guard`: real paths for the guard's deny prefixes (a prefix matches whole
 *  path components). The object-twin cache is under the home, so no program
 *  opens a twin by its own path; the guard serves it by descriptor at the
 *  repository's own pack path, and judges a hidden prefix by the path the
 *  opened file resolves to, which under the bind is the pack path.
 *  `wrap`: existing directories the whole-agent wrap masks with a tmpfs (the
 *  home, the launch's event dir). bwrap takes bind sources from the host, so
 *  the object twins and the carve-outs under the masked home still bind.
 *  `carveOuts`: existing directories under the home the agent keeps (the
 *  guard's `denyExcept`, a bind of each back at its own path over the
 *  tmpfs, a Seatbelt allow after the deny). */
export interface OwnStores {
  guard: string[];
  wrap: string[];
  /** Existing store FILES no `wrap` mask covers (this launch's CA key): the
   *  wrap binds an unreadable file over each. */
  files: string[];
  /** The home's carve-outs for this launch (`launchHomeCarveOuts`). */
  carveOuts: string[];
}

/** Throws `SecretConfinementError` (the launch refuses; fail-closed,
 *  on-disk-layout.md §4) when the agent's working directory, or the
 *  launch's own (the HumanView), lies inside the Mandu home outside every
 *  carve-out: the agent would run where it may neither read nor write, and
 *  Mandu will not open its home to make that work. */
export function ownStoresHidden(
  plan: LaunchPlan,
  home: string,
  env: NodeJS.ProcessEnv,
  scopeRunDir: string,
  exists: (p: string) => boolean,
  real: (p: string) => string = realpathSync,
  account: string | null = accountHome(),
): OwnStores {
  const realOr = (p: string): string => {
    try { return real(p); } catch { return p; }
  };
  // A file that may not exist yet: its directory's real path.
  const realFile = (p: string): string => pathJoin(realOr(dirname(p)), basename(p));
  const guard = new Set<string>();
  const wrap = new Set<string>();
  const storeFiles = new Set<string>();

  const homes = manduHomes(env, home, account).map(realOr);
  const carveOuts = launchHomeCarveOuts(plan, home, env, exists, real);
  const cwds = [plan.cwd, plan.humanCwd].filter((p): p is string => typeof p === "string" && p !== "").map(realOr);
  for (const h of homes) {
    const inside = cwdsInsideHome(h, carveOuts, cwds);
    if (inside.length > 0) {
      throw new SecretConfinementError(
        `mandu: the working directory ${inside[0]} is inside Mandu's home (${h}), which the agent may neither read nor ` +
        "write (on-disk-layout.md §4). Launch from another directory; to change Mandu's settings, use `mandu mode`, " +
        "`mandu policy` or edit the files yourself outside the agent.",
      );
    }
    guard.add(h);
    if (exists(h)) wrap.add(h);
  }

  for (const dir of new Set([plan.eventDir, pathJoin(scopeRunDir, "events")])) {
    if (typeof dir !== "string" || dir === "") continue;
    guard.add(realOr(dir));
    if (exists(dir)) wrap.add(realOr(dir));
  }

  const caDir = env["MANDU_NET_PROXY_MITM_CA_DIR"] || pathJoin(scopeRunDir, "egress-mitm-ca");
  guard.add(realFile(pathJoin(caDir, "mandu-egress-ca.key")));
  storeFiles.add(realFile(pathJoin(caDir, "mandu-egress-ca.key")));

  // A mask inside another mask is redundant (and bwrap would mount it on the
  // outer tmpfs); keep the outermost.
  const wrapDirs = [...wrap].filter((d) => ![...wrap].some((o) => o !== d && d.startsWith(o + "/")));
  // A file under a masked dir is gone already (and a bind onto the tmpfs
  // would fail: its target does not exist there).
  const files = [...storeFiles].filter((f) => exists(f) && !wrapDirs.some((d) => f.startsWith(d + "/")));
  return { guard: [...guard].sort(), wrap: wrapDirs.sort(), files: files.sort(), carveOuts };
}

export interface SecretSetupResult {
  /** The secrets actually confined (empty ⇒ nothing to do). */
  confined: SecretTwin[];
  /** Human-readable state for `doctor` / the launch banner. */
  status: string;
  /** The secret posture this launch runs at (confinement-posture.ts); "off"
   *  when the confidentiality axis is off. */
  posture: ConfinementPosture | "off";
  /** Why the posture is `gated`: a host gap code, or "arbiter". */
  gap?: HostGap | "arbiter";
  /** `confined` by the guard ALONE because the bind would have stopped the
   *  agent's own sandboxes (confinement-posture.ts `bindGap`). */
  bindGap?: HostGap;
  /** How many confined files got a STRUCTURED twin (keys raw, values as
   *  symbols; plan 10 §2.4). The rest are whole-file twins. */
  structured?: number;
  /** How many raw readers are PINNED by hash across the confined files
   *  (plan 10 §11.2, §12.5): the mode line's "N readers pinned". */
  readersPinned?: number;
  /** The committed bytes of the confined files (git-object-twins.ts): how
   *  many repositories and object-store files were masked. */
  gitObjects?: { repos: number; blobs: number; files: number; packsRebuilt: number; cacheHits: number };
  /** Mandu's shadow repositories hidden from the agent (`secrets` mode). */
  shadowMasked?: string;
  /** Mandu's own stores of originals hidden from the agent (the guard's deny
   *  prefixes, `ownStoresHidden`). */
  ownStoresHidden?: string[];
  /** macOS (posture `read-blocked`): what the launch's ONE Seatbelt profile
   *  must carry for the secrets (seatbelt-setup.ts renders and applies it
   *  once every component is known): each confined file in both spellings
   *  (the registered path and its real target), policy.yaml `protect:`, and
   *  Mandu's own stores of originals (`ownStoresHidden`; macOS has no mask and
   *  no guard, so the profile denies them by path) with the carve-outs the
   *  profile allows back after those denies (the integrity modes' AgentView,
   *  `full`'s repo.git; on-disk-layout.md §4).
   *  Absent on Linux and when nothing is confined. */
  seatbelt?: { secrets: string[]; noDelete: string[]; ownStores?: string[]; carveOuts?: string[] };
  /** macOS: the repositories where a confined file is committed (its
   *  committed bytes stay readable there; the Linux history masking has no
   *  macOS counterpart). */
  gitTrackedRepos?: string[];
  /** macOS: this launch's repositories holding a version a plan-14 history
   *  lock covers (`lockedHistoryRepos`): readable there, since only Linux
   *  enforces the locks. */
  gitLockedRepos?: string[];
  /** Linux: each twin file as written and each real file as found
   *  (twin-writes.ts `watchTwins`; the real files' marks in memory only), so
   *  the launcher can name, after the agent exits, the registered files whose
   *  placeholder copy the session changed and say whether the real file
   *  changed too (plan 10 §4.1). The twins' snapshots are also left beside
   *  them for `mandu reap`. Absent where no twin was written. */
  twinWatch?: TwinWatch;
  /** Linux: the object-twin cache entries (one directory per sanitized copy)
   *  this launch serves, which run.ts keeps marked used for the session's
   *  life (git-object-twins.ts `keepCopiesInUse`, plan 14 §11.1 R3 (a)). */
  objectCopyDirs?: string[];
  /** Linux: the twinned files inside a git work tree, and their
   *  repositories' tips (placeholder-commits.ts): the caller records them
   *  and checks after the agent exits that git holds no placeholder of
   *  them. Absent when there is none. */
  placeholderWatch?: WatchedRepo[];
  /** Linux: the index entries whose cached stat the launch set to their
   *  twin's (twin-index-stat.ts), so a tracked protected file looks clean to
   *  git in the agent's world; the caller puts the launch stat back after
   *  the agent exits (`restoreTwinIndexes`). Absent when there is none. */
  twinIndex?: CleanedIndex[];
  /** The crash record of `twinIndex` (twin-index-stat.ts), removed by the
   *  caller once every entry is put back. */
  twinIndexRecorder?: TwinIndexRecorder;
}

export interface EnvSecretsResult {
  /** The variable names now carrying a symbol in the agent's environment. */
  masked: string[];
  status: string;
}

/** The nesting probe. In a launch a pass is kept for the boot, keyed by both
 *  bubblewraps' identities and the whole argv (probe-cache.ts); a wrong kept
 *  pass puts the bind up where a nested sandbox cannot start, so the agent's
 *  own sandboxes fail (closed) rather than the bind being left off. */
const defaultNestingOk = (argv: string[]): boolean =>
  cachedProbe("nesting", () => ({ bins: [argv[0]!], argv }), () =>
    spawnSync(argv[0]!, argv.slice(1), { stdio: "ignore", timeout: 10_000 }).status === 0);

const defaultApparmorRestricted = (): boolean => {
  try { return readFileSync(APPARMOR_USERNS_SYSCTL, "utf8").trim() === "1"; } catch { return false; }
};

/** The error thrown when confinement was requested but cannot be established. */
export class SecretConfinementError extends Error {}

/** Where a registered secret's bind must land: its REAL path. The registry
 *  records paths as the discovery walk saw them; a spelling through a symlink
 *  (`~/tools/linux/…` → `/mnt/…`) is a mount point bwrap cannot create
 *  (`Can't mkdir parents`), and fail-closed then refused EVERY launch on the
 *  host (2026-09-05). null = the file is gone since discovery — nothing to
 *  confine, and the planner skips it (logged, never silent). */
export function resolveSecretTarget(p: string): string | null {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}

/**
 * Establish secret confinement and record the wrap on `mut.launchPrefix`.
 * No-ops entirely unless the confidentiality axis is ON for this launch
 * (`plan.effectiveAxes`, else the requested `plan.confidentiality`).
 */
export async function applySecretTwins(
  plan: LaunchPlan,
  scopeRunDir: string,
  mut: LaunchMutation,
  deps: SecretSetupDeps,
): Promise<SecretSetupResult> {
  // The index entries the setup patched (twin-index-stat.ts): put back here
  // when the setup throws after the patch (review of !1642, L2), since no
  // result then reaches the caller's end of session.
  const held: TwinIndexHeld = {};
  try {
    return await applySecretTwinsInner(plan, scopeRunDir, mut, deps, held);
  } catch (e) {
    endTwinIndexSession(held.cleaned, held.recorder, { log: deps.log });
    throw e;
  }
}

interface TwinIndexHeld { cleaned?: CleanedIndex[]; recorder?: TwinIndexRecorder | undefined }

async function applySecretTwinsInner(
  plan: LaunchPlan,
  scopeRunDir: string,
  mut: LaunchMutation,
  deps: SecretSetupDeps,
  held: TwinIndexHeld,
): Promise<SecretSetupResult> {
  // The EFFECTIVE axis (run.ts: what the attached arbiter runs), falling back
  // to the request for callers that never ran the preflight (unit tests).
  if ((plan.effectiveAxes?.confidentiality ?? plan.confidentiality) !== true) {
    return { confined: [], status: "off", posture: "off" };
  }

  const strict = { requireConfinement: plan.requireConfinement === true, bestEffort: plan.bestEffort };
  const RAW_GAP =
    "Without it a shell command the agent runs can read your credential files " +
    `directly and send them anywhere (${docsUrl("docs/design/confidentiality/confidentiality.md")} §10.1).`;

  // ── Can the HOST confine at all? A known condition: degrade unless strict. ──
  let hostGap: { gap: HostGap; why: string } | null = null;
  if (deps.platform === "win32") {
    hostGap = { gap: "unsupported-os", why: "Windows secret confinement is not implemented" };
  } else if (deps.platform === "linux") {
    // The bwrap the wrap would run (Mandu's own copy, else the distribution's
    // by absolute path, never one inside the workspace: bwrap-path.ts). None
    // is a host gap like a missing package. A test that names its own
    // `wrapBwrap` still answers presence through `commandExists`.
    const wrap = deps.wrapBwrap !== undefined ? deps.wrapBwrap : resolveWrapBwrap();
    if (wrap === null || (wrap === "bwrap" && !deps.commandExists("bwrap"))) {
      const refused = deps.wrapBwrap === undefined ? systemBwrap().refused : undefined;
      hostGap = {
        gap: "no-bwrap",
        why: refused !== undefined
          ? `your administrator's bubblewrap cannot be used (${refused})`
          : "`bwrap` (bubblewrap) is not installed (none on PATH outside the working directory)",
      };
    } else if (!deps.usernsOk()) {
      const restricted = (deps.apparmorRestricted ?? defaultApparmorRestricted)();
      hostGap = {
        gap: restricted ? "apparmor-userns" : "userns-off",
        why: `unprivileged user namespaces are unavailable (${(deps.usernsHint ?? usernsGapHint)()})`,
      };
    }
  } else if (!sandboxExecAvailable(deps.commandExists)) {
    // /usr/bin/sandbox-exec by path: the binary the wrap runs, never a PATH
    // entry that could stand in for it (seatbelt-profile.ts SANDBOX_EXEC).
    hostGap = { gap: "no-sandbox-exec", why: "`/usr/bin/sandbox-exec` is unavailable" };
  }
  if (hostGap !== null && onConfinementFailure("host", strict) === "refuse") {
    const { fix } = gapExplanation(hostGap.gap);
    throw new SecretConfinementError(
      `mandu: --require-confinement is set, but ${hostGap.why}. ${RAW_GAP}\n` +
      `  Fix it${fix !== null ? ` (${fix})` : ""}, or drop --require-confinement to launch GATED, ` +
      "or turn secret protection off for this launch (--mode off).",
    );
  }
  // Phase 6 (plan 10 §11.7): on Linux the guard alone confines. A host gap
  // that is only "no bind possible" is closed by the guard's descriptor
  // injection; the twins are still written (the guard opens them), no bwrap.
  let guardOnly = false;
  if (hostGap !== null && deps.platform === "linux" && deps.guardServesTwins === true && hostGap.gap !== "unsupported-os") {
    deps.log(
      `mandu: confidentiality — ${hostGap.why}; the whole-agent guard serves the secret twins by descriptor instead ` +
      "(no bind mount; plan 10 §11.7). Posture: confined.",
    );
    guardOnly = true;
    hostGap = null;
  }
  if (hostGap !== null) deps.log(gatedNotice(hostGap.gap).join("\n"));
  const gated = hostGap !== null;
  /** The wrap's bwrap, for a step that runs the wrap. The host check above
   *  found one whenever such a step is reached; if it is gone by then the
   *  launch refuses (fail closed), never a bare `bwrap` that a PATH search
   *  could resolve inside the workspace (bwrap-path.ts). */
  const wrapBwrapOrRefuse = (): string => {
    const b = deps.wrapBwrap ?? resolveWrapBwrap();
    if (b === null) {
      throw new SecretConfinementError(
        "mandu: the mount layer needs bubblewrap, and none is available any more (none on PATH outside the working directory). " +
        "Mandu never runs one from the workspace. Install it (sudo apt install bubblewrap, or sudo dnf install bubblewrap) and launch again.",
      );
    }
    return b;
  };
  // Bind-only (sandbox-security-review-2026-09-28 finding 7): the host can
  // mount the twin bind but no guard is around the launch. The bind still
  // goes up (a partial layer), but a secret file the HOST replaces while the
  // agent runs detaches it and the new real file is readable; only the
  // guard's by-path open catches that. So the posture is `gated`, and
  // --require-confinement refuses. Everything below runs as before.
  let bindOnly: HostGap | null = null;
  if (!gated && !guardOnly && deps.platform === "linux" && deps.guardServesTwins !== true) {
    bindOnly = plan.netGuard === false ? "guard-off" : "no-guard";
    if (onConfinementFailure("host", strict) === "refuse") {
      throw new SecretConfinementError(
        `mandu: --require-confinement is set, but ${plan.netGuard === false ? "the whole-agent guard is turned off for this launch" : "the whole-agent guard (mandu-net-guard) is not available"}. ` +
        "Without it a credential file the host replaces while the agent runs (a token refresh, an editor save) is readable to " +
        `programs the agent runs (${docsUrl("docs/design/confidentiality/confidentiality.md")} §10.1).\n` +
        `  ${plan.netGuard === false ? "Drop the opt-out (--no-net-guard, MANDU_NET_GUARD=0, net-guard = false, --no-kernel)" : "Make the guard available (a source checkout: scripts/build-native.sh)"}, ` +
        "or drop --require-confinement to launch GATED, or turn secret protection off for this launch (--mode off).",
      );
    }
    deps.log(gatedNotice(bindOnly).join("\n"));
  }
  /** The posture every later return reports (bind-only is `gated`). */
  const settled = (ok: ConfinementPosture): { posture: ConfinementPosture; gap?: HostGap } =>
    bindOnly !== null ? { posture: "gated", gap: bindOnly } : { posture: ok };
  // The soak switch before the bind is retired (plan 10 §8 phase 6): on a host
  // that COULD bind, `--no-secret-bind` runs the guard-only posture on purpose.
  // Without a guard around the launch there is nothing to hand the twins out,
  // so the request is refused loudly and the bind stays.
  if (!gated && !guardOnly && plan.secretBind === false && deps.platform === "linux") {
    if (deps.guardServesTwins === true) {
      deps.log(
        "mandu: confidentiality — bind mount SKIPPED (--no-secret-bind): the whole-agent guard alone serves the secret " +
        "twins by descriptor (plan 10 §8 phase 6 soak). Posture: confined.",
      );
      guardOnly = true;
    } else {
      deps.log("WARNING: mandu: --no-secret-bind ignored — no guard is around this launch (net-guard off or its binary missing); the bind mount stays.");
    }
  }

  const home = deps.home ?? homedir();
  const exists = deps.pathExists ?? existsSync;
  const onWsl = deps.platform === "linux" && (deps.onWsl ?? hostIsWsl({ readFile: readOrNull, fileExists: exists, env: process.env }));
  const ownEnv = deps.env ?? process.env;
  // The state base the discovery walk prunes (and reads the view map in):
  // the same value run.ts prefetches with, so the prefetched walk is used.
  // With it, the agents this launch runs, so only their logins stay raw
  // (secret-discovery.md §1.10).
  const discoverOpts = launchDiscoverOptions(ownEnv, home, launchLoginKeying(plan));
  // MANDU_OTHER_AGENT_LOGINS=raw: another agent's login is registered but
  // left readable (the `agentOwnFiles` posture).
  const otherLoginsRaw = otherAgentLoginsRaw(ownEnv, deps.log);
  const stateBase = discoverOpts.stateBase!;
  const shadowMask = deps.platform === "linux" ? shadowRepoMaskDir(plan, home, exists, ownEnv) : null;
  // The Mandu home (ownStoresHidden, on-disk-layout.md §4): hidden in every
  // launch with confidentiality on, secrets found or not, since the symbol
  // table holds the originals of every earlier launch too. A home that does
  // not exist yet is made now, owner-only, so the agent cannot make it (and
  // plant what Mandu would later trust there) under the mask.
  if (deps.platform === "linux" || deps.platform === "darwin") (deps.makeHome ?? makeHomeDir)(manduPath("mandu-home", ownEnv, home));
  // Plan 14 §11.2 residual (c): the layers below name the home, so a store
  // inside it that resolves outside (a symlink or a hard link planted while
  // something ran unconfined) would be behind none of them. Refuse
  // (store-links.ts); the message names the store and the fix.
  if (deps.platform === "linux" || deps.platform === "darwin") {
    const account = deps.accountHome === undefined ? accountHome() : deps.accountHome;
    const linkProblems = [...new Set([
      ...storeLinkProblems(ownEnv, home, deps.storeLinkFs),
      ...storeLinkProblems({}, home, deps.storeLinkFs),
      ...(account !== null ? storeLinkProblems({}, account, deps.storeLinkFs) : []),
    ])];
    if (linkProblems.length > 0) throw new SecretConfinementError(storeLinkRefusal(linkProblems, "mandu: refusing to launch"));
  }
  const own: OwnStores | null = deps.platform === "linux" || deps.platform === "darwin"
    ? ownStoresHidden(plan, home, ownEnv, scopeRunDir, exists, undefined, deps.accountHome === undefined ? accountHome() : deps.accountHome)
    : null;
  const ownNote = "Mandu's own stores (its whole home: the placeholder table, the event log) hidden";
  // macOS has no mask and no guard: Seatbelt denies every one of them by
  // path, the carve-outs allowed after.
  const ownSeatbelt = own !== null ? [...own.guard, ...own.wrap] : [];
  const ownCarveOuts = own?.carveOuts ?? [];
  /** The own-store part of the macOS profile record (SecretSetupResult
   *  `seatbelt`): the denies, and the carve-outs allowed after them. */
  const ownSeatbeltRecord = (): { ownStores?: string[]; carveOuts?: string[] } => ownSeatbelt.length === 0 ? {} : {
    ownStores: [...new Set(ownSeatbelt)].sort(),
    ...(ownCarveOuts.length > 0 ? { carveOuts: [...new Set(ownCarveOuts)].sort() } : {}),
  };
  // The wrap's mask of the home: a tmpfs over it, each carve-out bound back
  // from the host's tree. Among the wrap's leading flags, BEFORE every
  // secret-twin bind, so a twin whose file lies in a carve-out (the
  // AgentView copy of a credential in `full` mode) is bound over the
  // carve-out rather than hidden under it.
  // The arbiter's human plane (arbiter-human-plane.md §5): a tmpfs over each
  // human-plane directory that exists, AFTER the home mask and its carve-out
  // binds (nothing bound later lies in it), so the agent's world has an empty
  // directory where the human socket is. The guard's `unixDeny` (run.ts) is
  // the other wall; on macOS the launch's one Seatbelt profile denies both
  // (seatbelt-setup.ts, from plan.humanPlaneDirs).
  const realOrSelf = (p: string): string => { try { return realpathSync(p); } catch { return p; } };
  const humanDirs = [...new Set((plan.humanPlaneDirs ?? []).filter((d) => d.startsWith("/")))];
  const humanWrap = [...new Set(humanDirs.filter((d) => exists(d)).map(realOrSelf))].sort();
  const homeMask = [
    ...(own !== null ? homeMaskOps(own.wrap, ownCarveOuts) : []),
    ...humanWrap.flatMap((d) => ["--tmpfs", d]),
  ];
  /** The unreadable file bound over a path the agent must not read. */
  const deniedFile = (twinDir: string): string => {
    const f = `${twinDir}/git-object-denied`;
    publishFile(f, "", { mode: 0o000 });
    return f;
  };
  /**
   * Hide the stores in a launch that confines no secret (none found, all
   * gone, or an arbiter failure under --best-effort on a host that could
   * confine): the guard's deny list where a guard runs; else, on Linux, the
   * wrap started for this alone; on macOS a Seatbelt profile of denies.
   * Never called on a `gated` host (no guard, no bind): nothing can hide
   * them there.
   */
  const hideOwnStoresOnly = (objectTwins: ObjectTwin[] = [], lockedIds: readonly string[] = []): boolean => {
    if (own === null) return false;
    // Never a sandbox for nothing: a host with no store yet needs no wrap
    // (the guard's list costs nothing, so it goes on regardless).
    const anyStore = deps.platform === "darwin" ? ownSeatbelt.some((p) => exists(p)) : own.wrap.length > 0 || own.files.length > 0;
    if (!anyStore && objectTwins.length === 0 && deps.guardServesTwins !== true) return false;
    const dir = `${scopeRunDir.replace(/\/$/, "")}/secret-twins`;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (deps.platform === "darwin") {
      // macOS: the launch's ONE Seatbelt profile (seatbelt-setup.ts, applied
      // by run.ts) carries them; a second sandbox-exec wrap here would nest,
      // and macOS refuses a sandbox inside a sandbox. Recorded in the result.
      return true;
    }
    if (deps.guardServesTwins === true) {
      const policyPath = `${dir}/secret-policy.json`;
      // No secret file to confine, but a labelled path's or a locked blob's
      // committed bytes (plan 14 §8.1, §8.2): the guard serves those
      // object-store files exactly as it does beside a confined file.
      const secrets = objectTwins.map((o) => ({ path: o.targetPath, twin: o.twinPath, level: "no-model", kind: o.kind }));
      // Plan 14 §11.1 R4: the locked set, for the guard's backstop in every
      // repository this launch did not prepare.
      const locks = gitLocksField(lockedIds, scopeRunDir);
      publishFile(policyPath, JSON.stringify({ agentExe: resolveAgentExe(plan), session: plan.scopeId, secrets, denyPrefixes: own.guard, denyExcept: own.carveOuts, ...locks }, null, 2), { mode: 0o600 });
      mut.env["MANDU_NET_GUARD_SECRETS"] = policyPath;
      if (locks.gitLocks !== undefined) mut.env["MANDU_NET_GUARD_PROTECT"] = "1";
      // The object-store twins also get the mount layer wherever the host
      // can bind, as beside a confined file (the second layer). Where they
      // cannot, the guard answers a stat of a twinned pack with the twin's
      // metadata (GUARD_STAT_TWINS_ENV), so git does not see the real
      // pack's size beside the sanitized descriptor and drop the pack.
      if (objectTwins.length === 0) return true;
      if (guardOnly) {
        mut.env[GUARD_STAT_TWINS_ENV] = "1";
        return true;
      }
      const wrapBin = wrapBwrapOrRefuse();
      const extraFlags = [...wslTwinWrapFlags(onWsl, exists), ...homeMask];
      if (!(deps.nestingOk ?? defaultNestingOk)(nestedSandboxProbeArgv(wrapBin, extraFlags))) {
        mut.env[GUARD_STAT_TWINS_ENV] = "1";
        return true;
      }
      const denied = own.files.length > 0 ? deniedFile(dir) : "";
      const storeBinds = own.files.map((t) => ({ twinPath: denied, targetPath: t }));
      mut.launchPrefix = [...mut.launchPrefix, ...withObjectTwins(bareTwinWrap(wrapBin, extraFlags), [...objectTwins, ...storeBinds], [])];
      const warn = symlinkProbeWarning((deps.symlinkProbe ?? probeBwrapSymlink)(wrapBin));
      if (warn !== null) deps.log(warn);
      return true;
    }
    // No guard: the wrap alone, as a launch with secrets would run it (the
    // posture is `gated`, bind-only, either way). Where the host's bubblewrap
    // forbids nesting this stops the agent's own sandboxes; keeping the
    // originals of every earlier launch out wins, as it does for a secret.
    const wrapBin = wrapBwrapOrRefuse();
    const extraFlags = [...wslTwinWrapFlags(onWsl, exists), ...homeMask];
    if (!(deps.nestingOk ?? defaultNestingOk)(nestedSandboxProbeArgv(wrapBin, extraFlags))) {
      deps.log(
        "WARNING: mandu: the mount layer that hides Mandu's own stores (the placeholder table, the event log) stops every " +
        "sandbox the agent's tools start (this host's bubblewrap AppArmor profile forbids nesting, and the guard that could " +
        "hide them instead is not running): Codex's shell and Mandu's command box will fail. `mandu doctor` says why the guard is off.",
      );
    }
    const denied = own.files.length > 0 ? deniedFile(dir) : "";
    const binds = own.files.map((t) => ({ twinPath: denied, targetPath: t }));
    mut.launchPrefix = [...mut.launchPrefix, ...withObjectTwins(bareTwinWrap(wrapBin, extraFlags), [...objectTwins, ...binds], [])];
    const warn = symlinkProbeWarning((deps.symlinkProbe ?? probeBwrapSymlink)(wrapBin));
    if (warn !== null) deps.log(warn);
    return true;
  };

  /**
   * The committed bytes (git-object-twins.ts): a confined file committed to
   * git also lives in the object store, which no file twin covers; so do a
   * labelled path that no longer exists in the work tree and a locked blob
   * (plan 14 §8.1, §8.2; their labels and ids come from the arbiter's
   * `gitHistoryLocks`). Packs holding a protected version are served
   * sanitized, loose copies and the indexes by position made unreadable.
   * FAIL-CLOSED like an arbiter failure: a repository that cannot be
   * sanitized, or locks the arbiter could not tell, refuse the launch
   * unless --best-effort. Linux only (the caller).
   */
  /** The cache entries the object twins are served from, which the launcher
   *  keeps marked used while the session runs (`keepCopiesInUse`). */
  let servedCopies: string[] = [];
  const hideGitHistory = async (realPaths: string[], denyFile: string): Promise<HiddenHistory> => {
    const refuseOrWarn = (why: string, fix: string): void => {
      if (onConfinementFailure("arbiter", strict) === "refuse") {
        throw new SecretConfinementError(
          `mandu: ${why}. A program the agent runs (git show, git log -p) could read the committed bytes.\n` +
          (strict.requireConfinement
            ? "  Fix it, or turn secret protection off for this launch: --mode off (--require-confinement is set)."
            : `  Fix it${fix}, or re-run with --best-effort to proceed with the history readable, ` +
              "or turn secret protection off for this launch: --mode off."),
        );
      }
      deps.log(`WARNING: mandu: ${why}; the committed bytes stay readable to programs the agent runs (--best-effort).`);
    };
    let locks: GitHistoryLocksWire = { axis: true, blobs: [], labels: [] };
    if (deps.arbiter.gitHistoryLocks) {
      try {
        locks = asGitHistoryLocks(await deps.arbiter.gitHistoryLocks(deps.workspaceRoots ?? []));
      } catch (e) {
        if (isUnknownOpError(e)) {
          // An arbiter older than this launcher: it holds no blob lock (its
          // validator refuses the section), and labelled paths gone from the
          // work tree were never hidden by it. Said, never silent.
          deps.log("WARNING: mandu: the arbiter predates git-history locks (restart it to update); labelled files that no longer exist keep their git history readable for this launch.");
        } else {
          // Refusing, this throws; under --best-effort the confined files'
          // history is still hidden below, only the locks are missing.
          refuseOrWarn(`the arbiter could not tell which git history to hide beyond the confined files (${(e as Error).message})`, "");
        }
      }
    }
    const blobLocks = locks.blobs.map((b) => b.id);
    const labels = locks.labels;
    // Plan 14 §11.1 R4: what the guard's backstop looks up in every other
    // repository (the blob locks, the global set once the arbiter has one;
    // below, what this launch's walks resolve).
    const seals = sealClientOf(deps.arbiter);
    const baseLocked = lockedIdsOf({ blobs: locks.blobs, ...(locks.lockedSet !== undefined ? { lockedSet: locks.lockedSet } : {}) });
    if (realPaths.length === 0 && blobLocks.length === 0 && !labels.some((l) => l.level !== "public")) return { twins: [], lockedIds: baseLocked };
    try {
      // Under --best-effort a repository that cannot be sanitized loses
      // only its own history's cover (named below); every other repository
      // keeps its twins. Refusing, the first failure refuses the launch.
      const degrade = onConfinementFailure("arbiter", strict) === "degrade";
      const got = await (deps.gitObjectTwins ?? prepareGitObjectTwins)(realPaths, {
        cacheDir: manduPath("object-twins", ownEnv, home),
        // The history-walk cache sits in Mandu's state dir, which
        // write-protect denies the agent (write-protect.ts ownFiles): an
        // entry with a version left out would leave it readable next launch.
        walkCacheDir: manduPath("object-walks", ownEnv, home),
        // The next launch's prefetch starts from what this one read
        // (launch-hint.ts); the launch-start reads of this one, each
        // checked before use (twin-prefetch.ts).
        hintFile: launchHintFile(manduPath("object-walks", ownEnv, home), deps.workspaceRoots ?? []),
        ...(deps.twinPrefetch !== undefined ? { statePrefetch: deps.twinPrefetch, hashes: deps.twinPrefetch.hashes } : {}),
        ...(deps.gitSession !== undefined ? { gitSession: deps.gitSession } : {}),
        denyFile,
        maxRebuildBytes: maxRebuildBytesFromEnv(process.env),
        log: deps.log,
        continueOnFailure: degrade,
        labels,
        blobLocks,
        // Plan 14 §11.1 R2/R3: the global locked set too, so a workspace
        // pack excludes every id the guard's backstop refuses (its twin is
        // served before the backstop runs) and shares its cache key with
        // the arbiter's prepared copy of the same pack.
        globalLocked: baseLocked,
        repoHints: deps.workspaceRoots ?? [],
        // Plan 14 §11.1 R2: what the arbiter already resolved in the
        // background stands in for a repository's label walk, only on an
        // equal resolution key (git-object-twins.ts `labelledBlobsOf`).
        ...(locks.repos !== undefined ? { resolved: new Map(locks.repos.map((r) => [r.root, { key: r.key, blobs: r.blobs }])) } : {}),
        // Plan 14 §11.2: a cached pack or walk is used only when a seal of
        // the arbiter's current epoch vouches for it; without the seal ops
        // (no human socket) nothing cached is trusted.
        ...(seals !== undefined ? { seals } : {}),
      });
      for (const f of got.failed ?? []) {
        deps.log(`WARNING: mandu: the git history of a protected file could not be hidden (${f.reason}); the committed bytes in ${f.root} stay readable to programs the agent runs (--best-effort). Every other repository's history stays hidden.`);
      }
      const lockedIds = lockedIdsOf({ blobs: locks.blobs, resolved: got.lockedIds ?? [], ...(locks.lockedSet !== undefined ? { lockedSet: locks.lockedSet } : {}) });
      // Plan 14 §11.1 R3: every other repository holding a locked object
      // whose copies the arbiter prepared ahead of time: bound (or served by
      // the guard) when each copy excludes exactly the ids of the guard's set
      // its pack holds and is sealed now. The rest stay with the backstop.
      const prep = await preparedHistory(locks.prepared ?? [], lockedIds, got, denyFile, seals);
      const twins = [...got.twins, ...prep.twins];
      if (twins.length === 0) return { twins: [], lockedIds };
      servedCopies = servedCopyDirs(twins, manduPath("object-twins", ownEnv, home));
      if (got.twins.length > 0) {
        deps.log(
          `mandu: confidentiality — git history: ${got.blobs} committed version(s) of protected files in ${got.repos} ` +
          `repositor${got.repos === 1 ? "y" : "ies"} hidden from the agent (${got.twins.length} object file(s) masked` +
          `${got.packsRebuilt > 0 ? `, ${got.packsRebuilt} pack(s) sanitized` : ""})`,
        );
      }
      return {
        twins,
        lockedIds,
        gitObjects: { repos: got.repos + prep.bound.length, blobs: got.blobs, files: twins.length, packsRebuilt: got.packsRebuilt, cacheHits: got.cacheHits },
      };
    } catch (e) {
      if (e instanceof SecretConfinementError) throw e;
      refuseOrWarn(`the git history of a protected file could not be hidden (${(e as Error).message})`, " (MANDU_GIT_TWIN_MAX_MB raises the size cap)");
      return { twins: [], lockedIds: baseLocked };
    }
  };

  /** Plan 14 §11.1 R3: the prepared copies' twins (preparedCopyTwins), said
   *  in one line each way. Never throws: a copy that cannot be used leaves
   *  its repository to the guard's backstop. */
  const preparedHistory = async (
    prepared: ReadonlyArray<{ root: string; format: "sha1" | "sha256" }>, lockedIds: readonly string[], got: GitObjectTwinResult,
    denyFile: string, seals: CacheSealClient | undefined,
  ): Promise<PreparedCopyResult> => {
    const none: PreparedCopyResult = { twins: [], bound: [], notReady: [], overCap: [] };
    if (prepared.length === 0 || lockedIds.length === 0) return none;
    let res: PreparedCopyResult;
    try {
      res = await (deps.preparedCopies ?? preparedCopyTwins)(prepared, {
        cacheDir: manduPath("object-twins", ownEnv, home),
        denyFile,
        lockedIds,
        skipRoots: new Set(got.roots ?? []),
        skipTargets: new Set(got.twins.map((t) => t.targetPath)),
        ...(seals !== undefined ? { seals } : {}),
        ...(deps.twinPrefetch !== undefined ? { hashes: deps.twinPrefetch.hashes } : {}),
        log: deps.log,
        maxRepos: preparedMaxReposFromEnv(process.env),
      });
    } catch (e) {
      deps.log(`mandu: the copies prepared ahead of time could not be used (${(e as Error).message}); git in those repositories is refused by the file guard instead`);
      return none;
    }
    if (res.bound.length > 0) {
      deps.log(
        `mandu: confidentiality — git history: sanitized copies prepared ahead of time served for ${res.bound.length} other ` +
        `repositor${res.bound.length === 1 ? "y" : "ies"} holding a locked key (${res.twins.length} object file(s) masked)`,
      );
    }
    const left = res.notReady.length + res.overCap.length;
    if (left > 0) {
      deps.log(
        `mandu: ${left} repositor${left === 1 ? "y" : "ies"} holding a locked key ${left === 1 ? "has" : "have"} no ready copy this launch` +
        `${res.overCap.length > 0 ? ` (${res.overCap.length} over the launch's cap of ${preparedMaxReposFromEnv(process.env)} repositories or ${PREPARED_MAX_PACKS} packs, MANDU_GIT_PREPARED_REPOS)` : ""}; ` +
        "git there is refused by the file guard for the session",
      );
    }
    return res;
  };

  /**
   * macOS: the plan-14 history locks this launch's repositories hold, which
   * only a Linux launch hides (`hideGitHistory` runs there alone). Asked of
   * the arbiter exactly as the Linux launch asks it, so the workspace joins
   * the known-repository registry the same way (plan 14 §11.1 R1), then
   * looked up in the repositories (`lockedHistoryRepos`). Honesty only,
   * never a refusal (nothing here would protect anything): an older arbiter
   * holds no lock; any other failure is said. Never throws.
   */
  const darwinLockedHistory = async (realPaths: readonly string[]): Promise<Array<{ root: string; checked: boolean }>> => {
    if (!deps.arbiter.gitHistoryLocks) return [];
    let locks: GitHistoryLocksWire;
    try {
      locks = asGitHistoryLocks(await deps.arbiter.gitHistoryLocks(deps.workspaceRoots ?? []));
    } catch (e) {
      if (!isUnknownOpError(e)) {
        deps.log(
          `WARNING: mandu: the history locks could not be read (${(e as Error).message}); on macOS a locked blob's or a ` +
          "labelled path's committed versions stay readable to programs the agent runs wherever they are (only Linux hides them)",
        );
      }
      return [];
    }
    try {
      return await (deps.gitLocked ?? ((l, k) => lockedHistoryRepos(l, k)))({ workspaceRoots: deps.workspaceRoots ?? [], realPaths }, locks);
    } catch (e) {
      deps.log(
        `WARNING: mandu: which repositories hold a locked version was not checked (${(e as Error).message}); on macOS their ` +
        "committed versions stay readable to programs the agent runs (only Linux hides them)",
      );
      return [];
    }
  };

  // An ARBITER failure is an incident, not a host condition. On a host that
  // could have confined it refuses unless --best-effort; on a host that is
  // already gated there is no confinement left to lose, so it only warns.
  const arbiterFailed = (why: string): SecretSetupResult => {
    if (gated) {
      deps.log(`mandu: ${why}; secrets stay GATED (no registry entry was added).`);
      return { confined: [], status: `gated: ${hostGap!.why}`, posture: "gated", gap: hostGap!.gap };
    }
    if (onConfinementFailure("arbiter", strict) === "refuse") {
      throw new SecretConfinementError(
        `mandu: this mode protects your secrets (modes secrets and full), but ${why}. ${RAW_GAP}\n` +
        (strict.requireConfinement
          ? "  Fix it, or turn secret protection off for this launch: --mode off (--require-confinement is set)."
          : "  Fix it, or re-run with --best-effort to proceed GATED, or turn secret protection off for this launch: --mode off."),
      );
    }
    deps.log(
      `WARNING: mandu: secrets are GATED, not confined, for this session: ${why}. ${RAW_GAP} ` +
      "Proceeding (--best-effort).",
    );
    // The stores need no arbiter to be hidden. On macOS the one Seatbelt
    // profile (run.ts, seatbelt-setup.ts) carries them only through this
    // record, as `ownStoresOnly` hands it over: without it a launch in an
    // integrity mode (whose profile seals no state of its own) said the home
    // was hidden while nothing denied it.
    const hid = hideOwnStoresOnly();
    return {
      confined: [], status: `gated: ${why}`, posture: "gated", gap: "arbiter",
      ...(hid ? { ownStoresHidden: own!.guard } : {}),
      ...(hid && deps.platform === "darwin" ? { seatbelt: { secrets: [], noDelete: [], ...ownSeatbeltRecord() } } : {}),
    };
  };

  // ── Discover + register (the arbiter reads the files, never this process) ──
  const roots = [home, ...(deps.workspaceRoots ?? [])];
  // Each found file keeps the home its catalog rule is anchored to: the
  // launch's HOME, or (WSL) the Windows profile it was found under, so the
  // arbiter re-classifies it against the same home at registration.
  let found: Array<{ path: string; home: string; level?: string; agentLogin?: string }>;
  try {
    // The launch's state base rides along (the same value fs-view handed
    // fs-sync-cli): the walk prunes it and reads the view map it holds.
    // With it, the caches this session's environment moves (CARGO_HOME, …),
    // recorded like the defaults (secret-discovery.md §1.9 G); the same
    // options run.ts prefetches with (`launchDiscoverOptions`).
    const report = asDiscoveryReport(await deps.arbiter.discoverSecrets(roots, home, discoverOpts));
    found = report.files.map((f) => ({
      path: f.path, home, ...(f.level !== undefined ? { level: f.level } : {}),
      ...(typeof f.agentLogin === "string" ? { agentLogin: f.agentLogin } : {}),
    }));
    // The launched agent's own login a grant covers (§3.9): twinned too.
    for (const p of deps.grantedLoginFiles ?? []) {
      if (exists(p) && !found.some((f) => f.path === p)) found.push({ path: p, home });
    }
    // What the walk left RAW is never silent (secret-discovery.md §1
    // §2 gap 1): the caps and unreadable candidates are said on every launch.
    const notice = notCoveredNotice(report, 3, home);
    if (notice.length > 0) deps.log(notice.join("\n"));
    // WSL: every Windows user profile is a second home holding the same
    // stores (`/mnt/c/Users/<name>/.aws/credentials`). Discovery gets the
    // catalog's own paths under it as roots, with the profile as the home
    // their `~/` rules resolve against: a bounded probe, never a walk of the
    // profile (drvfs is 9p; wsl.ts `WINDOWS_PROFILE_SECRET_PATHS`).
    const seen = new Set(found.map((f) => f.path));
    for (const profile of onWsl ? (deps.windowsProfiles ?? probeWindowsProfiles()) : []) {
      const win = asDiscoveryReport(await deps.arbiter.discoverSecrets(
        windowsProfileSecretRoots(profile), profile, { stateBase },
      ));
      for (const f of win.files) {
        if (!seen.has(f.path)) { seen.add(f.path); found.push({ path: f.path, home: profile, ...(f.level !== undefined ? { level: f.level } : {}) }); }
      }
      const winNotice = notCoveredNotice(win, 3, profile);
      if (winNotice.length > 0) deps.log(winNotice.join("\n"));
    }
  } catch (e) {
    return arbiterFailed(`the arbiter could not discover secrets (${(e as Error).message})`);
  }

  const confined: SecretTwin[] = [];
  let readersPinned = 0;
  const realOf = (p: string): string => { try { return realpathSync(p); } catch { return p; } };
  const agentOwn = new Set((deps.agentOwnFiles ?? []).map(realOf));
  /** Other agents' logins confined here (secret-discovery.md §1.10), for the
   *  launch note. */
  const otherLogins: Array<{ path: string; agent: string }> = [];
  const loginName = (agent: string): string => AGENT_LOGIN_NAMES[agent] ?? agent;
  for (const f of found) {
    let reg: { symbol: string | null; reason: string; twin?: string; fields?: number; readers?: { named: number; pinned: number }; terminator?: "" | "\n" | "\r\n" };
    try {
      // Another agent's login: with the launch's login variables, so one
      // CODEX_HOME moved out of the catalog's places registers as found.
      reg = f.agentLogin !== undefined && discoverOpts.loginEnv !== undefined
        ? await deps.arbiter.registerSecret(f.path, f.home, discoverOpts.loginEnv)
        : await deps.arbiter.registerSecret(f.path, f.home);
    } catch (e) {
      return arbiterFailed(`the arbiter could not register ${f.path} (${(e as Error).message})`);
    }
    if (reg.symbol === null) {
      // A file we found but could not symbolize (unreadable, empty). It is NOT
      // confined — say so rather than silently leaving a hole.
      deps.log(`mandu: secret ${f.path} NOT ${gated ? "registered" : "confined"} — ${reg.reason}`);
      continue;
    }
    if (agentOwn.has(realOf(f.path))) {
      // The agent's own key file: registered (its values are masked in what
      // reaches the model) but left readable, or the agent could not log in
      // (it would send the placeholder as its key; supported-agents.md §5.6.1).
      deps.log(`mandu: ${f.path} is the agent's own key file: left readable to it, its values masked in what reaches the model`);
      continue;
    }
    if (f.agentLogin !== undefined && otherLoginsRaw) {
      // The opt-out: another agent's login, registered (masked in what
      // reaches the model) but readable, so that agent started inside this
      // session can still log in; this session's net-proxy does not trip on
      // its values (agent-login.ts `sessionLogins`), so that agent can also
      // use them with its own services.
      deps.log(`mandu: ${f.path} is ${loginName(f.agentLogin)}'s login: left readable (MANDU_OTHER_AGENT_LOGINS=raw), so ${loginName(f.agentLogin)} started in this session can use it; its values masked in what reaches the model`);
      continue;
    }
    if (f.agentLogin !== undefined) otherLogins.push({ path: f.path, agent: f.agentLogin });
    confined.push({
      path: f.path,
      symbol: reg.symbol,
      ...(reg.twin !== undefined ? { twin: reg.twin } : {}),
      ...(reg.terminator !== undefined ? { terminator: reg.terminator } : {}),
      level: secretLevel(f.level, reg.symbol),
    });
    // Readers are handed the real file by the Linux guard; macOS has none
    // (read-blocked: every program's read fails), so none is ever pinned.
    if (deps.platform === "linux") readersPinned += reg.readers?.pinned ?? 0;
  }

  const ok: ConfinementPosture = deps.platform === "linux" ? "confined" : "read-blocked";
  if (gated) {
    // Pre-registration still pays off without a wrap: the registry labels are
    // authoritative for Track A's model-context masking (confidentiality.md
    // §7.3 "pre-registration"). No twin, no wrap: the files stay readable.
    deps.log(
      `mandu: confidentiality — ${confined.length} secret(s) registered for masking, NONE confined (posture: gated)`,
    );
    return {
      confined: [],
      status: `gated: ${confined.length} registered, none confined (${hostGap!.why})`,
      posture: "gated",
      gap: hostGap!.gap,
    };
  }
  // Another agent's login is a credential like any other in a session that
  // does not run that agent (secret-discovery.md §1.10). Said, since that
  // agent started inside this session cannot log in with the placeholder.
  if (otherLogins.length > 0) {
    const agents = [...new Set(otherLogins.map((o) => loginName(o.agent)))];
    const one = otherLogins.length === 1;
    deps.log(
      `mandu: ${otherLogins.map((o) => o.path).join(", ")}: ${agents.map((a) => `${a}'s`).join(" and ")} login${one ? "" : "s"}, ` +
      `${deps.platform === "darwin" ? "unreadable" : "a placeholder copy"} in this session, which does not run ${agents.join(" or ")} ` +
      `(MANDU_OTHER_AGENT_LOGINS=raw leaves ${one ? "it" : "them"} readable)`,
    );
  }
  /** No secret to confine, but the symbol table and the event log hold
   *  earlier launches' originals, and the shadow repositories may hold an
   *  older file's bytes: hidden all the same (`hideOwnStoresOnly`). */
  const ownStoresOnly = async (what: string): Promise<SecretSetupResult> => {
    // No file to confine, but a labelled path that is gone from the work
    // tree, or a locked blob, may still sit in a repository's history (plan
    // 14 §8.1, §8.2, C17): hidden the same way, fail-closed the same way.
    let history: HiddenHistory = { twins: [], lockedIds: [] };
    if (deps.platform === "linux") {
      const dir = `${scopeRunDir.replace(/\/$/, "")}/secret-twins`;
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      history = await hideGitHistory([], deniedFile(dir));
    }
    // macOS hides no history; the locks that reach this launch are said
    // (with no confined file there is nothing else to name).
    let lockedRepos: string[] | undefined;
    if (deps.platform === "darwin") {
      const locked = await darwinLockedHistory([]);
      const notice = gitHistoryNotice([], locked);
      if (notice !== null) { deps.log(notice); lockedRepos = locked.map((r) => r.root); }
    }
    const hid = hideOwnStoresOnly(history.twins, history.lockedIds);
    if (hid) deps.log(`mandu: confidentiality — ${what}; ${ownNote} from the agent`);
    const git = hid ? history.gitObjects : undefined;
    return {
      confined: [],
      status: `on: ${what}${hid ? ` (${ownNote}${git !== undefined ? `, git history hidden in ${git.repos} repo${git.repos === 1 ? "" : "s"}` : ""})` : ""}`,
      ...settled(ok),
      ...(hid ? { ownStoresHidden: own!.guard } : {}),
      ...(hid && deps.platform === "darwin"
        ? { seatbelt: { secrets: [], noDelete: [], ...ownSeatbeltRecord() } }
        : {}),
      ...(hid && shadowMask !== null ? { shadowMasked: shadowMask } : {}),
      ...(git !== undefined ? { gitObjects: git } : {}),
      ...(lockedRepos !== undefined ? { gitLockedRepos: lockedRepos } : {}),
      ...(hid && servedCopies.length > 0 ? { objectCopyDirs: servedCopies } : {}),
    };
  };
  if (confined.length === 0) return ownStoresOnly("no secrets found to confine");
  // WSL: a Windows drive folds case, so `.AWS/CREDENTIALS` opens the file the
  // twin bind covers only as `.aws/credentials` (a mount sits on one
  // dentry). The guard closes that by matching the file itself (plan 10
  // §4.1); without it the bind alone would leave every other spelling raw,
  // so the launch refuses unless --best-effort (fail-closed, confidentiality.md
  // §7.2 "WSL2").
  const onProfiles = found.filter((f) => f.home !== home && confined.some((c) => c.path === f.path)).map((f) => f.path);
  if (onProfiles.length > 0 && deps.guardServesTwins !== true) {
    const why =
      `${onProfiles.length} Windows credential file(s) (${onProfiles.slice(0, 3).join(", ")}${onProfiles.length > 3 ? ", …" : ""}) ` +
      "sit on a drive that ignores case, and only the whole-agent guard recognizes another spelling of them; the guard is not running " +
      "(`mandu doctor` says why)";
    if (!strict.bestEffort) {
      throw new SecretConfinementError(
        `mandu: ${why}. A program the agent runs could read them as e.g. .AWS/CREDENTIALS.\n` +
        "  Fix the guard, or re-run with --best-effort to protect only the exact spellings, or turn secret protection off " +
        "for this launch: --mode off.",
      );
    }
    deps.log(`WARNING: mandu: ${why}; only their exact spellings are protected for this session (--best-effort).`);
  }

  // ── Materialize + wrap ────────────────────────────────────────────────────
  const twinDir = scopeTwinDir(scopeRunDir);
  mkdirSync(twinDir, { recursive: true, mode: 0o700 });

  const resolveTarget = deps.resolveTarget ?? resolveSecretTarget;
  let effective: SecretTwin[] = confined;
  let objectTwins: ObjectTwin[] = [];
  let gitObjects: SecretSetupResult["gitObjects"];
  let bindGap: HostGap | undefined;
  let seatbelt: SecretSetupResult["seatbelt"];
  let gitTrackedRepos: string[] | undefined;
  let gitLockedRepos: string[] | undefined;
  let twinWatch: TwinWatch | undefined;
  let placeholderWatch: WatchedRepo[] = [];
  let twinIndex: CleanedIndex[] = [];
  let twinIndexRecorder: TwinIndexRecorder | undefined;
  if (deps.platform === "linux") {
    const extraFlags = [...wslTwinWrapFlags(onWsl, exists), ...homeMask];
    // Guard-only runs no wrap (its argv is emptied below), so it needs no bwrap.
    const wrapBin = guardOnly ? "" : wrapBwrapOrRefuse();
    // The bind must not stop the sandboxes the agent's own tools start
    // (os-test-matrix.md §10.14.1 item 6): on Ubuntu 26.04 everything a
    // bwrap sandbox runs is barred from a user namespace, so under the bind
    // Codex's shell and Mandu's exec box fail every command. Probe the wrap
    // the launch would run; where it forbids nesting, the guard alone serves
    // the twins (the same posture as --no-secret-bind). Without a guard the
    // bind stays: keeping raw bytes out wins over the agent's shell. Where
    // `mandu setup` installed Mandu's own bubblewrap (bwrap-grant.ts) the wrap
    // runs that copy, whose profile lets a sandbox nest, so the probe passes
    // and the bind stays on (rootless-confinement-ubuntu-2404.md §12.3).
    if (!guardOnly && !(deps.nestingOk ?? defaultNestingOk)(nestedSandboxProbeArgv(wrapBin, extraFlags))) {
      if (deps.guardServesTwins === true) {
        deps.log(
          "mandu: confidentiality — the mount layer is off: this host's bubblewrap AppArmor profile lets no sandbox " +
          "start inside it, which would stop the agent's own command sandboxes; the whole-agent guard alone serves the " +
          "secret twins by descriptor. Posture: confined.",
        );
        guardOnly = true;
        bindGap = "bwrap-nesting";
      } else {
        deps.log(
          "WARNING: mandu: the mount layer that puts placeholders over your credential files stops every sandbox the agent's tools start " +
          "(this host's bubblewrap AppArmor profile forbids nesting, and the guard that could replace the mount is not " +
          "running): Codex's shell and Mandu's command box will fail. `mandu doctor` says why the guard is off.",
        );
      }
    }
    const twinPlan = planSecretTwins(confined, twinDir, wrapBin, { resolveTarget, extraFlags });
    // A dropped twin is never silent: say which registered path got no bind
    // and why (a duplicate spelling of a file already bound, or a file gone).
    for (const sk of twinPlan.skipped) deps.log(`mandu: secret ${sk.path} — ${sk.reason}`);
    const skippedPaths = new Set(twinPlan.skipped.map((sk) => sk.path));
    effective = confined.filter((c) => !skippedPaths.has(c.path));
    if (twinPlan.files.length === 0) return ownStoresOnly("no secrets left to confine (all registered files gone)");
    for (const f of twinPlan.files) {
      // Never through a link planted in the scope dir (safe-file.ts).
      publishFile(f.twinPath, f.content, { mode: 0o600 });
    }
    // Each twin as written (size, hash and inode) and each real file as
    // found (size and hash, kept in memory only), so the end of the session
    // can name the registered files whose placeholder copy changed and say
    // whether the real file did: a write to a registered file lands in its
    // twin, under the bind and under the guard alike, and is discarded with
    // it (plan 10 §4.1). The twins' snapshots also go beside them, for a
    // session whose launcher dies before it can say so (`mandu reap`).
    twinWatch = watchTwins(twinPlan.files, twinDir);
    if (guardOnly) {
      // No bind: the guard's policy file (below) is the whole mechanism,
      // for the metadata of a twinned path too (§7.2a).
      twinPlan.wrapArgv.length = 0;
      mut.env[GUARD_STAT_TWINS_ENV] = "1";
    }
    // The committed bytes (git-object-twins.ts): a confined file committed to
    // git also lives in the object store, which no twin above covers. Packs
    // holding a protected version are served sanitized, loose copies and the
    // indexes by position made unreadable. FAIL-CLOSED like an arbiter
    // failure: a repository that cannot be sanitized refuses the launch
    // unless --best-effort.
    //
    // Beside it (both only read git): the twinned files inside a git work
    // tree, tracked or not, with the ids their twins would get and what the
    // index holds of them, and their repositories' tips.
    // git in the agent's world reads the twin, so a `git commit -a` there
    // records the placeholder in the user's repository; the caller checks for
    // that after the agent exits (placeholder-commits.ts, confidentiality.md
    // §7.2a "A placeholder in your repository"). Advisory: never refuses the
    // launch, whether the watch rejects or throws, and each of its git calls
    // is cut off after 5 s, so a slow repository cannot hold the launch up.
    const sources: TwinSource[] = twinPlan.files.map((f) => ({ targetPath: f.targetPath, content: f.content, twinPath: f.twinPath }));
    const watch = deps.placeholderWatch ?? ((fs: TwinSource[]) => preparePlaceholderWatch(fs, {
      log: deps.log, ...(deps.gitSession !== undefined ? { git: deps.gitSession.runner() } : {}),
    }));
    const watchP = Promise.resolve().then(() => watch(sources)).catch((): WatchedRepo[] => []);
    const denyFile = deniedFile(twinDir);
    const history = await hideGitHistory(twinPlan.files.map((f) => f.targetPath), denyFile);
    objectTwins = history.twins;
    gitObjects = history.gitObjects;
    placeholderWatch = await watchP;
    // A tracked twinned file whose real bytes are its index blob: its
    // twin's stat goes into its index entry, so git in the agent's world
    // finds it clean (a clean tree for filter-branch, rebase, stash; a
    // `commit -a` that leaves it out) until the agent edits it
    // (twin-index-stat.ts, confidentiality.md §7.2a "A twinned file git
    // tracks looks clean"). Advisory, like the watch: never refuses.
    // Each patch is recorded in the Mandu home BEFORE it lands, so a launch
    // that dies is repaired by the next one (or `mandu reap`); a record that
    // cannot be written leaves that index alone.
    //
    // ONLY WHERE THE GUARD SERVES THE TWINS (review of !1642, M1). The patch
    // shows the real file modified to git outside the session, and the
    // human's `git stash`, `reset --hard`, `checkout -- .`, an editor's
    // "Discard changes" then rewrite the real file (a new inode). Under the
    // bind alone (bind-only, `gated`) a replaced file detaches the bind and
    // the agent's programs read the new real file
    // (rootless-confinement-ubuntu-2404.md §13 finding 7); the guard's
    // by-path open covers it. So without the guard nothing is patched (the
    // twin shows modified there, as before).
    const recordHome = manduPath("mandu-home", ownEnv, home);
    const recordDir = twinIndexRecordDir(manduPath("object-walks", ownEnv, home));
    const cleanIndex = deps.twinIndex ?? ((rs: WatchedRepo[]) => {
      twinIndexRecorder = new TwinIndexRecorder(recordDir, recordHome, plan.scopeId);
      return cleanTwinsInIndex(rs, {
        log: deps.log, ...(deps.gitSession !== undefined ? { git: deps.gitSession.runner() } : {}),
        recorder: twinIndexRecorder, peers: () => livePeerRecords(recordDir, recordHome),
      });
    });
    if (deps.guardServesTwins === true) {
      twinIndex = await Promise.resolve().then(() => cleanIndex(placeholderWatch)).catch((): CleanedIndex[] => []);
      // The caller's wrapper puts it back if anything below throws (no
      // result reaches run.ts then).
      held.cleaned = twinIndex;
      held.recorder = twinIndexRecorder;
    }
    if (shadowMask !== null) {
      deps.log(`mandu: confidentiality — Mandu's shadow repositories (${shadowMask}) hidden from the agent`);
    }
    // Plan 10 §4.1: the interposer's policy file. The net-guard (outside this
    // bind) traps the open family and, for these real paths, asks the arbiter
    // who may read raw; a reader gets the REAL file's descriptor, everyone
    // else the twin's. Written beside the twins; the guard reads it at start.
    const askTimeoutMs = Number(process.env["MANDU_SECRETS_ASK_TIMEOUT"] ?? "") || 60_000;
    const secretPolicy = {
      agentExe: resolveAgentExe(plan),
      ask: plan.secretsAsk ?? "known",
      askTimeoutMs,
      session: plan.scopeId,
      secrets: twinPlan.files.map((f) => ({
        path: f.targetPath,
        twin: f.twinPath,
        // The level the user labeled (confidentiality-plan-11 D5), so the
        // guard's `[mandu:secret]` note and its events name `local-model`
        // where that is what policy.yaml says. The guard's open decision does
        // not read it; the strictest level stands in when none is known.
        level: f.level ?? "no-model",
      })).concat(objectTwins.map((o) => ({
        // An object-store file (git-object-twins.ts): the guard serves the
        // sanitized twin (`object`) or refuses (`deny`) without asking the
        // arbiter; no reader is ever handed the real pack.
        path: o.targetPath,
        twin: o.twinPath,
        level: "no-model",
        kind: o.kind,
      }))),
      // The Mandu home whole, this launch's event dir and CA key
      // (ownStoresHidden): every open under them is refused, but in the
      // home's carve-outs (the integrity modes' AgentView).
      denyPrefixes: own?.guard ?? [],
      denyExcept: own?.carveOuts ?? [],
      // The ssh-agent socket as a secret (comparisons.md §3.5): with a
      // policy.yaml ssh_agent section, the guard lets only its readers
      // connect to $SSH_AUTH_SOCK. No section, or no agent: ungated as before.
      sockets: await sshAgentSockets(deps, deps.sshAuthSock ?? process.env["SSH_AUTH_SOCK"]),
      // policy.yaml protect: (learn-from-nono §4 item 8): the guard refuses a
      // delete or rename of these (and of their ancestors).
      protect: await protectedPaths(deps, deps.home ?? homedir()),
      // Plan 14 §11.1 R4: the locked set, for the guard's backstop in every
      // repository this launch did not prepare (git-lock-backstop.ts).
      ...gitLocksField(history.lockedIds, scopeRunDir),
      // guard-file-identity.md §2: the moved-files notice (moved-files-notice.ts).
      ...movedNoticeField(scopeRunDir),
    };
    await announceConsumerPacks(deps);
    const policyPath = `${twinDir}/secret-policy.json`;
    publishFile(policyPath, JSON.stringify(secretPolicy, null, 2), { mode: 0o600 });
    mut.env["MANDU_NET_GUARD_SECRETS"] = policyPath;
    // The rename / link / unlink family is trapped for `protect:`, and for a
    // lock too: a locked object must not leave its checked name.
    if (secretPolicy.protect.length > 0 || secretPolicy.gitLocks !== undefined) mut.env["MANDU_NET_GUARD_PROTECT"] = "1";
    // INNER of the reply-filter wrapper (applied before it), so the filter
    // stays outside the sandbox and the agent runs inside.
    if (twinPlan.wrapArgv.length > 0) {
      // P0 4c (confidentiality.md §7.2a "Another name for a twinned file"):
      // the bind covers one name. A protected file with a hard link of
      // another name made before the launch turns the guard's stat trap on,
      // so that name shows the twin's size too; one link: off, no cost.
      if (deps.guardServesTwins === true) {
        const linked = linkedSecretFiles(twinPlan.files.map((f) => f.targetPath), deps.linkCount ?? fileLinkCount);
        if (linked.length > 0) {
          mut.env[GUARD_STAT_TWINS_ENV] = "1";
          deps.log(
            `mandu: confidentiality — ${linked.length} protected file(s) (${linked.slice(0, 3).join(", ")}${linked.length > 3 ? ", …" : ""}) ` +
            "also have another name on disk (a hard link); Mandu answers a look at their size under every name, " +
            "which makes file lookups slower this session.",
          );
        }
      }
      // A store file no mask covers (the DB in `full` mode) gets the
      // unreadable file bound over it, like a git index made unreadable.
      const storeBinds = (own?.files ?? []).map((t) => ({ twinPath: denyFile, targetPath: t }));
      mut.launchPrefix = [...mut.launchPrefix, ...withObjectTwins(twinPlan.wrapArgv, [...objectTwins, ...storeBinds], [])];
      // CVE-2026-87766 (finding 14): the wrap's bwrap follows a symlink in a
      // mount destination? One WARNING line; never a refusal, never a
      // posture change (bwrap-symlink-probe.ts has the assessment).
      const warn = symlinkProbeWarning((deps.symlinkProbe ?? probeBwrapSymlink)(wrapBin));
      if (warn !== null) deps.log(warn);
    }
  } else {
    // macOS (confidentiality.md §7.3): no twin, a DENY. The launch's ONE
    // Seatbelt profile (seatbelt-profile.ts; applied by seatbelt-setup.ts
    // once the network, write-protect and socket components are known)
    // denies read and write of each file in BOTH spellings — the registered
    // path and its real target, so neither `cat ~/link` nor `cat /real/file`
    // reads it — and the rename or removal of every folder above them (a
    // rename then a read of the new name was the verified bypass of the old
    // read-only deny, 2026-09-29). Here the set is only recorded.
    const denied = new Set<string>();
    const reals: string[] = [];
    for (const c of confined) {
      denied.add(c.path);
      const real = resolveTarget(c.path);
      if (real !== null) { denied.add(real); reals.push(real); }
    }
    seatbelt = {
      secrets: [...denied].sort(),
      noDelete: await protectedPaths(deps, home),
      // Mandu's own stores of originals go in the same ONE profile.
      ...ownSeatbeltRecord(),
    };
    // The committed bytes (the Linux object-store twins have no macOS
    // counterpart), and the plan-14 history locks (the Linux object twins,
    // prepared copies and guard backstop, none of which exists here): say
    // where they stay readable, on every launch, in one WARNING.
    const realSet = [...new Set(reals)].sort();
    let tracked: Array<{ root: string; checked: boolean }> = [];
    try {
      tracked = await (deps.gitTracked ?? ((ps: string[]) => trackedSecretRepos(ps)))(realSet);
    } catch (e) {
      deps.log(`WARNING: mandu: whether a protected file is committed to git was not checked (${(e as Error).message}); its committed bytes, if any, stay readable on macOS`);
    }
    const locked = await darwinLockedHistory(realSet);
    const notice = gitHistoryNotice(tracked, locked);
    if (notice !== null) {
      deps.log(notice);
      if (tracked.length > 0) gitTrackedRepos = tracked.map((r) => r.root);
      if (locked.length > 0) gitLockedRepos = locked.map((r) => r.root);
    }
  }

  const readBlocked = deps.platform !== "linux";
  const how = readBlocked ? "the Seatbelt profile" : "symbolized twins";

  if (own !== null) deps.log(`mandu: confidentiality — ${ownNote} from the agent`);
  deps.log(bindOnly !== null
    ? `mandu: confidentiality — ${effective.length} secret(s) behind placeholder copies by the mount layer only ` +
      "(posture: gated: no file guard, so a file replaced while the agent runs is readable)"
    : readBlocked
      ? `mandu: confidentiality — ${effective.length} credential file(s) unreadable (read-blocked by the Seatbelt profile: ` +
        "a read fails, and neither the file nor a folder above it can be written, renamed or removed)"
      : `mandu: confidentiality — ${effective.length} secret(s) confined via ${how} ` +
        "(raw bytes are absent from the agent's world)");
  const structuredEffective = effective.filter((c) => c.twin !== undefined).length;
  return {
    confined: effective,
    status: readBlocked
      ? `on: ${effective.length} read-blocked (${how})`
      : `${bindOnly !== null ? "gated" : "on"}: ${effective.length} ${bindOnly !== null ? "behind placeholders" : "confined"} (${guardOnly ? "by the guard, no bind" : bindOnly !== null ? "mount layer only, no guard" : how}${structuredEffective > 0 ? `, ${structuredEffective} structured` : ""}${readersPinned > 0 ? `, ${readersPinned} reader${readersPinned === 1 ? "" : "s"} pinned` : ""}${gitObjects !== undefined ? `, git history hidden in ${gitObjects.repos} repo${gitObjects.repos === 1 ? "" : "s"}` : ""})`,
    ...settled(ok),
    ...(bindGap !== undefined ? { bindGap } : {}),
    structured: structuredEffective,
    ...(readBlocked ? {} : { readersPinned }),
    ...(gitObjects !== undefined ? { gitObjects } : {}),
    ...(shadowMask !== null ? { shadowMasked: shadowMask } : {}),
    ...(own !== null ? { ownStoresHidden: own.guard } : {}),
    ...(seatbelt !== undefined ? { seatbelt } : {}),
    ...(gitTrackedRepos !== undefined ? { gitTrackedRepos } : {}),
    ...(gitLockedRepos !== undefined ? { gitLockedRepos } : {}),
    ...(twinWatch !== undefined ? { twinWatch } : {}),
    ...(servedCopies.length > 0 ? { objectCopyDirs: servedCopies } : {}),
    ...(placeholderWatch.length > 0 ? { placeholderWatch } : {}),
    ...(twinIndex.length > 0 ? { twinIndex } : {}),
    ...(twinIndexRecorder?.file != null ? { twinIndexRecorder } : {}),
  };
}

/**
 * Mask the secret-shaped variables of the agent's environment (plan 10
 * §11.4). The arbiter decides which are secrets (name shapes, URL passwords,
 * the agent's own credential exempt) and mints `$MDU:nomodel_Env[h].NAME`; this
 * puts the returned value into `mut.env`, which reaches the agent through
 * BOTH the direct childEnv and the systemd --setenv path. Variables the
 * launcher itself sets (`mut.env`) are never candidates. No-op unless the
 * confidentiality axis is ON and the switch is (default) on. Fail-soft: an
 * arbiter error leaves the environment unmasked and SAYS so; confinement of
 * files is the fail-closed half, this is a launcher-side convenience the
 * launch must not die on.
 */
export async function applyEnvSecrets(
  plan: LaunchPlan,
  env: Record<string, string | undefined>,
  mut: LaunchMutation,
  deps: {
    arbiter: SecretArbiter; log: (msg: string) => void; resolveSource?: SourceResolver;
    /** The agent's own key variables this launch holds an auth grant for
     *  (agent-key-grant.ts `registerClaudeKeyGrant`, agent-sign-in.md
     *  §3.8): sent with `agentKey`, so the arbiter masks them although
     *  their name is exempt, and the model proxy puts the key back. */
    agentKeys?: readonly string[];
  },
): Promise<EnvSecretsResult> {
  if ((plan.effectiveAxes?.confidentiality ?? plan.confidentiality) !== true) {
    return { masked: [], status: "off: confidentiality axis is off" };
  }
  if (plan.envSecrets === false) return { masked: [], status: "off: --no-env-secrets" };
  if (!deps.arbiter.registerEnvSecrets) return { masked: [], status: "off: arbiter has no registerEnvSecrets op" };
  const vars: Array<{ name: string; value: string; agentKey?: boolean }> = [];
  const agentKeys = new Set(deps.agentKeys ?? []);
  // policy.yaml env.sources: fetched here, registered like any variable, and
  // put in the agent's environment ONLY as a placeholder (below). A failed
  // source falls back to the shell's own value, if any, which the arbiter
  // masks as a secret too (it treats every sourced name as one).
  const sourced = new Set<string>();
  let sources: EnvSource[] = [];
  try {
    sources = (await deps.arbiter.envSources?.())?.sources ?? [];
  } catch (e) {
    deps.log(`WARNING: mandu: env.sources not read (${(e as Error).message}); those variables are left unset`);
  }
  for (const src of sources) {
    if (src.name in mut.env) continue;
    const r = (deps.resolveSource ?? resolveEnvSource)(src.source);
    if ("error" in r) {
      deps.log(`WARNING: mandu: ${src.name}: its source (${src.source.split(":")[0]}) failed (${r.error}); ${env[src.name] ? "using the shell's value, masked" : "left unset"}`);
      continue;
    }
    sourced.add(src.name);
    vars.push({ name: src.name, value: r.value });
  }
  // The agent's own model credential for a Goose provider this launch
  // routes (goose-route.ts gooseRoutedKeyVars), left as the arbiter leaves
  // ANTHROPIC_API_KEY and OPENAI_API_KEY: Goose sends it to the model proxy.
  // Unless the launch granted it (`agentKeys`, agent-sign-in.md §3.10): then
  // it is masked and the model proxy puts the key back.
  const ownKeys = new Set((plan.target === "goose" ? gooseRoutedKeyVars(plan.gooseRouting) : []).filter((k) => !agentKeys.has(k)));
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined || value === "" || name in mut.env || sourced.has(name) || ownKeys.has(name)) continue;
    vars.push(agentKeys.has(name) ? { name, value, agentKey: true } : { name, value });
  }
  if (vars.length === 0) return { masked: [], status: "on: nothing to check" };
  let res: { vars: Array<{ name: string; symbol: string | null; twin?: string; reason: string }> };
  try {
    res = await deps.arbiter.registerEnvSecrets(vars);
  } catch (e) {
    deps.log(`WARNING: mandu: environment variables NOT masked — the arbiter could not register them (${(e as Error).message})`);
    return { masked: [], status: `error: ${(e as Error).message}` };
  }
  const masked: string[] = [];
  for (const v of res.vars) {
    if (v.symbol === null || v.twin === undefined) {
      // A sourced value the arbiter would not register must not reach the
      // agent raw: the launcher never copies it into the environment, and a
      // shell value of the same name is emptied so it is not silently used.
      if (sourced.has(v.name)) {
        mut.env[v.name] = "";
        deps.log(`WARNING: mandu: ${v.name} left empty: its sourced value was not registered (${v.reason})`);
      }
      continue;
    }
    mut.env[v.name] = v.twin;
    masked.push(v.name);
  }
  masked.sort();
  if (masked.length > 0) deps.log(`mandu: environment: ${masked.length} secret variable${masked.length === 1 ? "" : "s"} masked (${masked.join(", ")})`);
  return { masked, status: masked.length > 0 ? `on: ${masked.length} masked` : "on: no secret variables" };
}

/** The launch banner line for signed consumer packs (comparisons.md
 *  §3.3): which are in force, by version and key, and which were refused. */
export async function announceConsumerPacks(deps: { arbiter: SecretArbiter; log: (m: string) => void }): Promise<void> {
  if (!deps.arbiter.consumerPacks) return;
  try {
    const { packs, refused } = await deps.arbiter.consumerPacks();
    if (packs.length) deps.log(`mandu: consumer packs: ${packs.map((p) => `${p.name} ${p.version} (key ${p.keyId})`).join(", ")}`);
    for (const r of refused) deps.log(`WARNING: mandu: consumer pack refused: ${r}`);
  } catch { /* an older arbiter: nothing to announce */ }
}

/** policy.yaml protect:, `~` expanded against the launching user's HOME. A
 *  failed lookup protects nothing and says so (an added guard, not the
 *  fail-closed half). */
export async function protectedPaths(deps: { arbiter: SecretArbiter; log: (m: string) => void }, home: string): Promise<string[]> {
  if (!deps.arbiter.protectPaths) return [];
  try {
    const { paths } = await deps.arbiter.protectPaths();
    const out = paths.map((p) => (p === "~" ? home : p.startsWith("~/") ? `${home}/${p.slice(2)}` : p));
    if (out.length) deps.log(`mandu: protected from deletion: ${out.join(", ")}`);
    return out;
  } catch (e) {
    deps.log(`WARNING: mandu: protect paths not read (${(e as Error).message}); nothing is protected from deletion`);
    return [];
  }
}

/** The guard's socket-secret entry for the ssh-agent, or none. A failed
 *  lookup leaves the agent socket ungated and says so (the file secrets are
 *  the fail-closed half; this is an added gate). */
export async function sshAgentSockets(deps: { arbiter: SecretArbiter; log: (m: string) => void }, sock: string | undefined): Promise<Array<{ path: string; label: string; readers: unknown[] }>> {
  if (!sock || !deps.arbiter.sshAgentPolicy) return [];
  try {
    const { readers } = await deps.arbiter.sshAgentPolicy();
    if (!readers) return [];
    deps.log(`mandu: ssh-agent: only ${readers.map((r) => (typeof r === "string" ? r : `${(r as { app: string }).app}${(r as { from?: string }).from ? ` from ${(r as { from?: string }).from}` : ""}`)).join(", ")} may use it`);
    return [{ path: sock, label: "ssh-agent", readers }];
  } catch (e) {
    deps.log(`WARNING: mandu: ssh_agent policy not read (${(e as Error).message}); the ssh-agent is not gated`);
    return [];
  }
}

/** The agent's own executable, resolved on the launch PATH: the one program
 *  that always reads the twin (plan 10 §2.1). Empty when unresolvable (then no
 *  process is treated as the agent, which only costs a would-be reader). */
export function resolveAgentExe(plan: LaunchPlan): string {
  const argv0 = plan.argv?.[0] ?? "";
  if (argv0 === "") return "";
  const candidates = argv0.includes("/") ? [argv0] : (plan.basePath ?? process.env["PATH"] ?? "").split(":").filter(Boolean).map((d) => `${d}/${argv0}`);
  for (const c of candidates) {
    let real: string;
    try { real = realpathSync(c); } catch { continue; }
    return npmWrappedNative(real) ?? real;
  }
  return "";
}

/** The npm packages whose `bin` is a node script that runs the real agent
 *  binary as its child: the script's path suffix, and the platform package
 *  and file the script runs (read off the script itself; codex-cli 0.144.1
 *  to 0.162.0, `bin/codex.js` `findCodexExecutable`). */
const NPM_WRAPPERS: ReadonlyArray<{ script: string; scope: string; platformPackage: (os: string, arch: string) => string | null; files: (triple: string) => string[][]; triple: (os: string, arch: string) => string | null }> = [{
  script: "/@openai/codex/bin/codex.js",
  scope: "@openai",
  platformPackage: (os, arch) => (["linux", "darwin", "win32"].includes(os) && ["x64", "arm64"].includes(arch) ? `codex-${os}-${arch}` : null),
  triple: (os, arch) => {
    const cpu = arch === "x64" ? "x86_64" : arch === "arm64" ? "aarch64" : null;
    if (cpu === null) return null;
    return os === "linux" ? `${cpu}-unknown-linux-musl` : os === "darwin" ? `${cpu}-apple-darwin` : null;
  },
  files: (triple) => [[triple, "bin", "codex"], [triple, "codex", "codex"]],
}];

/**
 * The real agent binary an npm wrapper script runs, or null when `real` is
 * no known wrapper or its binary is not where the script would find it
 * (2026-10-09, confidentiality-plan-13 §4.5.1, "The agent is never made a
 * holder"). npm's `codex` is a node script that starts the native Codex as
 * its child; the guard knows the agent by its executable, so the launch
 * names the native binary, the process that holds the model connection and
 * the session files. Before, the script was named, the native Codex was no
 * agent, and a listed reader's raw read in one call made it a holder: its
 * model connection was refused and its own session file labelled. The
 * lookup is the script's own (Node's resolution of the platform package from
 * the script's directory upward, then the package's own `vendor/`). Pure
 * apart from the file system reads.
 */
export function npmWrappedNative(real: string, os: string = process.platform, arch: string = process.arch): string | null {
  for (const w of NPM_WRAPPERS) {
    if (!real.endsWith(w.script)) continue;
    const pkgRoot = real.slice(0, real.length - w.script.length) + w.script.split("/").slice(0, 3).join("/");
    const platformPackage = w.platformPackage(os, arch);
    const triple = w.triple(os, arch);
    if (platformPackage === null || triple === null) return null;
    const vendors: string[] = [];
    for (let d = pkgRoot; ; d = dirname(d)) {
      vendors.push(pathJoin(d, "node_modules", w.scope, platformPackage, "vendor"));
      if (dirname(d) === d) break;
    }
    vendors.push(pathJoin(pkgRoot, "vendor"));
    for (const v of vendors) {
      for (const f of w.files(triple)) {
        try { return realpathSync(pathJoin(v, ...f)); } catch { /* next */ }
      }
    }
    return null;
  }
  return null;
}

