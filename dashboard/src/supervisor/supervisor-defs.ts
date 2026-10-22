/**
 * supervisor-defs — the control-plane supervisor's public types, defaults, and
 * production ServiceDefinitions (extracted VERBATIM from supervisor.ts in
 * the supervisor decomposition). The stateful process machinery (spawn/
 * readiness/logs/kill) stays in supervisor.ts; this module is the pure "what to
 * run" layer other dashboard modules code against.
 */

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { pathToFileURL } from "node:url";
import { INTEGRITY_OPT_IN_ENV } from "../config-axes.js";
import { manduPath } from "../generated/mandu-paths.js";

// ─────────────────────────────────────────────────────────────────────────────
// Public types (other dashboard modules code against these — do not deviate)
// ─────────────────────────────────────────────────────────────────────────────

/** The five supervised services. `test-arbiter` is the TEST-tenant arbiter
 *  (policy-surface.md §2.7): its own socket, DB and event dir, started
 *  with MANDU_TENANT=test, so test runs never touch the live store. */
export type ServiceId = "arbiter" | "anthropic-proxy" | "openai-proxy" | "net-proxy" | "test-arbiter";
export type ServiceState = "stopped" | "starting" | "running" | "crashed";

/** The arbiter's `hello` identity (runtime-instances.md), as the supervisor
 *  records it on start/adopt. Mirrors arbiter protocol HelloResult (narrow
 *  structural copy — this package stays standalone, no arbiter import). */
export interface ArbiterIdentity {
  pid: number;
  startedAt: string;
  instanceId: string | null;
  gitRev: string;
  gitDirty: boolean;
  sockPath: string;
  /** The arbiter's HUMAN-PLANE socket (docs/design/architecture/arbiter-human-plane.md):
   *  where the originals-returning ops are served. The supervisor hands it to
   *  the services that need it (the net-proxy's shallow resolve) as
   *  MANDU_ARBITER_HUMAN_SOCK at spawn. null/absent = none (an older arbiter). */
  humanSock?: string | null;
  eventDir: string;
  symbolDb: string;
  /** The release the arbiter's code belongs to (runtime-instances.md §4.1);
   *  absent on an arbiter from before 2026-10-09. */
  version?: string;
  /** Which build of it (arbiter/ipc/build-identity.ts): the SHA-256 prefix
   *  of the bundle it runs (null from source) and the checkout rev it came
   *  from (null for an install). Absent before 2026-10-17. */
  build?: { bundle: string | null; rev: string | null };
  /** Every real arbiter's hello carries it (an identity with it and without
   *  `version` is a release from before the version check). */
  protocolVersion?: number;
}

/** What this dashboard would start for the arbiter (arbiterReleaseStaleness):
 *  its release, and the hash of the arbiter bundle it spawns (null when it
 *  has none). `installed`: the bundle is all it can spawn (no checkout). */
export interface OwnArbiterBuild {
  version: string | null;
  bundle: string | null;
  installed: boolean;
}

export interface ServiceStatus {
  id: ServiceId;
  label: string;
  state: ServiceState;
  pid: number | null;
  since: number | null;
  lastError: string | null;
  endpoint: string;
  /** True when this service was ADOPTED — already listening when the supervisor
   *  went to start it — rather than spawned here. An adopted service has NO child
   *  pid in this process, so the supervisor neither reaps it on stop()/stopAll()
   *  nor on a dashboard self-restart: it is not ours to kill. The control panel
   *  badges it, because an adopted daemon quietly surviving a "Stop all" is
   *  exactly the stale-daemon trap this flag exists to surface. */
  adopted?: boolean;
  /** hello identity of the LISTENING daemon (arbiter only; null = no answer). */
  identity?: ArbiterIdentity | null;
  /** Socket-owner discovery (socket-owner.ts): the /proc-verified pid listening
   *  on the endpoint, filled ONLY while an adopted daemon has no hello identity
   *  — it is the OS's answer where the daemon gave none, and what makes Replace
   *  possible on a hello-less daemon. Null = not findable from this process
   *  (other uid, container pid namespace, TCP endpoint). */
  ownerPid?: number | null;
  ownerCmdline?: string | null;
  /** True when the listening arbiter serves stale code (the recurring incident
   *  this scheme fixes). SCOPE-HONEST since 2026-07-16: a gitRev differing from
   *  this repo's HEAD flags only when the commit range touches `arbiter/`, or
   *  when the rev cannot be resolved at all (see arbiterStaleness below). */
  stale?: boolean;
  /** Human-readable cause when stale, else null (arbiter only). */
  staleReason?: string | null;
}

export interface LogLine {
  ts: number;
  stream: "stdout" | "stderr";
  line: string;
}

export interface SupervisorOptions {
  repoRoot: string; // resolve service cwds from here (dev: the checkout)
  /** INSTALLED layout (packaging.md §5; os-test-matrix.md §10.11 finding
   *  2): the dashboard runs from the @mandusec/mandu bundle (`dist/dashboard.mjs`)
   *  and there is no checkout — `arbiter/`, `interceptors/<pkg>/` and their
   *  `npm run serve` scripts do not exist, and a missing cwd surfaced as
   *  `spawn node ENOENT`. With this set, every service is spawned exactly as
   *  the launcher's layout resolver spawns it (launcher/src/services/layout.ts
   *  `daemon`): `node --no-warnings=ExperimentalWarning <pkgRoot>/dist/<name>.mjs`,
   *  cwd pkgRoot, the proxies pointed at the co-located arbiter-client bundle.
   *  Absent ⇒ the dev (checkout) definitions: each service from the
   *  checkout's own prebuilt bundle while its build record says it matches
   *  the source, else from source as one `node --import <tsx>` process
   *  (packaging.md §5.1; `checkoutDist`, `bundleFresh`). */
  layout?: { mode: "installed"; pkgRoot: string };
  /** DEV layout: the checkout's prebuilt bundle directory (default
   *  `<repoRoot>/launcher/dist`, what launcher/mandu-run.sh runs). A test
   *  points it at a private build. */
  checkoutDist?: string;
  /** DEV layout: is the bundle in `distDir` what the source at `repoRoot`
   *  would build now? Asked at EVERY spawn (start, restart), so a bundle
   *  that went stale while the dashboard ran is never started. Default:
   *  the launcher's own build-record check (checkoutBundleFresh). TEST SEAM. */
  bundleFresh?: (distDir: string, repoRoot: string) => Promise<BundleFreshness>;
  arbiterSock: string; // arbiter socket path + MANDU_ARBITER_SOCK for proxies
  // (the human-plane socket is not an option: it is per arbiter INSTANCE, so
  // the supervisor reads it from the arbiter's `hello` when it spawns a
  // service that requires the arbiter — see Supervisor.humanPlaneEnv.)
  /** Runtime-instances mode (runtime-instances.md): when set, the supervised
   *  arbiter is spawned WITHOUT an explicit socket — it creates
   *  `<base>/instances/<id>/arbiter.sock` and (MANDU_PROMOTE=1) atomically
   *  repoints `<base>/current` at itself. `arbiterSock` should then be the
   *  `<base>/current/arbiter.sock` spelling so every client resolves through
   *  the promotion symlink. Unset → legacy explicit-path spawn. */
  arbiterInstanceBase?: string;
  /** The LIVE arbiter's event dir / symbol DB, passed to it as `--event-dir` /
   *  `--symbol-db`. Unset (the dashboard's own use) → no flag: the arbiter's
   *  path-table defaults under MANDU_HOME. The test tenant never follows
   *  these (testTenantPaths). */
  eventDir?: string;
  symbolDb?: string;
  modelProxyPort?: number; // default 8788
  openaiProxyPort?: number; // default 8789
  egressProxyPort?: number; // default 8790
  proxyHost?: string; // default 127.0.0.1
  upstreamAnthropic?: string; // default https://api.anthropic.com
  upstreamOpenai?: string; // default https://api.openai.com
  logRingMax?: number; // default 50000 (the in-memory live tail)
  /** Directory for durable per-module log files; default
   *  `join(dirname(arbiterSock), "logs")`. One `<id>.log` per service. */
  logDir?: string;
  startTimeoutMs?: number; // readiness timeout, default ~10000
  stopGraceMs?: number; // SIGTERM->SIGKILL grace, default ~4000
  autoStartArbiter?: boolean; // default true: starting a proxy starts the arbiter first if down
  /** Optional offline web-mock YAML for the net-proxy (MANDU_NET_PROXY_MOCK_SITES).
   *  When set, the supervised net-proxy serves canned responses for the configured
   *  URLs — for deterministic real-agent loops / demos. */
  mockSitesPath?: string;
  /**
   * Axis plumbing for the ARBITER spawn (dashboard.md §4.19; default: the real
   * config.toml reader, src/config-axes.ts `arbiterAxisSpawnEnv`): resolves the
   * config file's `mode` + `integrity`/`confidentiality` keys (and an exported
   * MANDU_MODE, which it translates: the arbiter reads only the axis vars) into
   * MANDU_INTEGRITY/MANDU_CONFIDENTIALITY fill-ins, honoring the launcher's
   * precedence (an explicitly-set process env var wins; config fills only unset
   * keys; both absent → nothing set, the arbiter defaults rule). Evaluated AT
   * SPAWN TIME so a Protection-drawer config edit lands on the next restart.
   * Overridable as a TEST SEAM.
   */
  axisEnv?: (processEnv: NodeJS.ProcessEnv) => Record<string, string>;
  log?: (msg: string) => void;
  /** TEST HOOK: override the production definitions with fakes. */
  definitions?: Partial<Record<ServiceId, ServiceDefinition>>;
  /** TEST SEAMS — arbiter staleness (default: the real git helpers from
   *  self-status.ts, the same pair DashboardSelf uses). */
  gitRev?: (repoRoot: string) => string;
  gitChangedInRange?: (repoRoot: string, from: string, to: string, dir: string) => string[] | null;
  /** TEST SEAM — the release and arbiter build this dashboard would start
   *  (default: its own package.json and a hash of the arbiter bundle,
   *  supervisor.ts ownArbiterBuildOf). Read per status poll (cached by the
   *  bundle's size and mtime), so a rebuild flags without a restart. */
  ownArbiterBuild?: () => OwnArbiterBuild;
  /** TEST SEAMS — replace() takeover of an adopted daemon (default: /proc
   *  cmdline read + process.kill). procCmdline is the recycled-pid guard:
   *  replace() signals nothing whose cmdline it cannot read and recognize. */
  procCmdline?: (pid: number) => string | null;
  killPid?: (pid: number, sig: NodeJS.Signals | 0) => void;
  /** TEST SEAM — unix-socket owner discovery (default: the real /proc walk in
   *  socket-owner.ts). The Replace fallback when the daemon never answered
   *  hello, and the ownerPid enrichment on adopted identity-less rows. */
  discoverSocketOwner?: (sockPath: string) => { pid: number; cmdline: string | null } | null;
  /** Replace, rather than adopt, a STALE arbiter found answering at start
   *  when no `mandu` session uses its stack (instance mode only:
   *  runtime-instances.md §4.1b). Default true. */
  replaceStaleOnAdopt?: boolean;
  /** TEST SEAM — the `mandu` sessions on the stack at a runtime base, or null
   *  when that cannot be told, which counts as in use (default:
   *  stack-sessions.ts liveSessionsOn). */
  liveSessions?: (base: string) => number[] | null;
  /** Called once when a service this supervisor started exits on its own
   *  while it was running (state `crashed`); not for a stop or a restart. */
  onCrash?: (id: ServiceId, reason: string) => void;
}

/** ServiceDefinition.ready: the three readiness kinds. */
export type ReadySpec =
  | { kind: "socket"; path: string }
  | { kind: "tcp"; host: string; port: number }
  | { kind: "port-file"; path: string; host: string };

export interface ServiceDefinition {
  label: string;
  command: string;
  args: string[];
  cwd: string; // absolute
  env: NodeJS.ProcessEnv; // merged over process.env at spawn
  /**
   * How the supervisor knows the service is up:
   *   - `socket`: a Unix socket at `path` accepts a connection;
   *   - `tcp`: `host:port` accepts a connection (a port fixed in advance);
   *   - `port-file` (test-organization.md §8.4): the service binds port 0 and
   *     writes the port it got to `MANDU_PORT_FILE`, which the supervisor sets
   *     to `path` (after removing a stale file); ready = the file names a port
   *     and `host:<that port>` accepts a connection. No port is picked and
   *     released before the service starts, so nothing running alongside can
   *     take it. Never ADOPTED: a kernel-assigned port is no address to find
   *     an already-running instance at.
   */
  ready: ReadySpec;
  endpoint: string; // human label, e.g. "127.0.0.1:8788" or the sock path
  requires?: ServiceId[]; // e.g. proxies require ["arbiter"]
  /**
   * ADMIN CHANNEL (policy-surface.md §2.6): spawn with an extra stdio
   * socketpair at fd 3 and tell the child about it (`MANDU_ADMIN_FD=3`). The
   * supervisor keeps the parent end; the arbiter accepts its human-decision
   * ops (approvals, labels, posture, session deletion) ONLY on that channel.
   * An inherited fd has no filesystem name, so a same-uid process — the
   * agent, its shims, an MCP child — cannot connect to it. Requires spawning
   * the daemon's node DIRECTLY: measured 2026-09-05, an extra fd survives
   * `sh → node` but neither the `tsx` CLI nor `npm run` pass it through.
   */
  adminChannel?: boolean;
  /**
   * DEV layout only (packaging.md §5.1): the same service from the checkout's
   * prebuilt bundle. The definition's own command/args/cwd are the SOURCE
   * form (one `node --import <tsx> <entry.ts>` process); the supervisor
   * spawns this form instead only when, at that spawn, the bundle's build
   * record says it still matches the source. A stale bundle never runs.
   */
  checkoutBundle?: CheckoutBundleForm;
}

/** A dev service's bundled form (ServiceDefinition.checkoutBundle). */
export interface CheckoutBundleForm {
  command: string;
  args: string[];
  cwd: string;
  /** Merged over the definition's env (the arbiter-client bundle). */
  env: NodeJS.ProcessEnv;
  /** The bundle directory whose build record decides, and the repository the
   *  record must name. */
  distDir: string;
  repoRoot: string;
}

/** The answer of a build-record check (launcher/scripts/bundle-stamp.mjs
 *  `checkStamp`). */
export type BundleFreshness = { fresh: true } | { fresh: false; reason: string };

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

export const SERVICE_IDS: ServiceId[] = ["arbiter", "anthropic-proxy", "openai-proxy", "net-proxy", "test-arbiter"];

/**
 * Where the TEST-tenant arbiter lives (policy-surface.md §2.7 1b):
 * never the live paths. The socket is a PINNED path under `<base>/test/`
 * (pinned mode still registers in the instance registry; it must never be
 * promoted to `current`, which is the live rendezvous). The DB and the event
 * dir are the path table's `symbol-db-test` and `events-test` under the Mandu
 * home (on-disk-layout.md §3, §5): `<home>/state/mandu-test.db` and
 * `<home>/events/test`. buildDefinitions hands both to the test arbiter as
 * `--symbol-db` / `--event-dir` flags.
 */
export interface TestTenantPaths {
  sock: string;
  symbolDb: string;
  eventDir: string;
}

export function testTenantPaths(
  o: Pick<SupervisorOptions, "arbiterSock" | "arbiterInstanceBase">,
  env: NodeJS.ProcessEnv = process.env,
): TestTenantPaths {
  const base = o.arbiterInstanceBase ?? dirname(o.arbiterSock);
  const home = env.HOME || homedir();
  return {
    sock: join(base, "test", "arbiter.sock"),
    symbolDb: manduPath("symbol-db-test", env, home),
    eventDir: manduPath("events-test", env, home),
  };
}

/** The arbiter's store flags (arbiter/ipc/server-main.ts): `--symbol-db` and
 *  `--event-dir`, each only when a path is given. None given → no flags, and
 *  the arbiter uses the path table's `symbol-db` / `events` under its
 *  MANDU_HOME. Pure; exported for the unit test. */
export function arbiterStoreArgs(p: { symbolDb?: string; eventDir?: string }): string[] {
  return [
    ...(p.symbolDb ? ["--symbol-db", p.symbolDb] : []),
    ...(p.eventDir ? ["--event-dir", p.eventDir] : []),
  ];
}

/**
 * The prompt filter plugins' confinement flags (confidentiality-plan-15
 * §4.3, §12 2026-10-03): `--net-guard <path>` (the address guard, required
 * for any plugin to run) and `--landlock-apply <path>` when the classifier's
 * flags (`already`) did not pass it. Mirrors the launcher's
 * `arbiterPluginArgs`. Pure over `exists`.
 */
export function arbiterPluginArgs(
  already: readonly string[],
  o: { repoRoot: string; installedPkgRoot: string | null },
  env: Record<string, string | undefined> = process.env,
  exists: (p: string) => boolean = existsSync,
): string[] {
  const bin = (name: string): string[] => o.installedPkgRoot !== null
    ? [join(o.installedPkgRoot, "dist", "native", `${process.platform}-${process.arch}`, name)]
    : ["release", "debug"].map((b) => join(o.repoRoot, "interceptors", "target", b, name));
  const first = (override: string | undefined, name: string): string | undefined =>
    [...(override ? [override] : []), ...bin(name)].find((p) => p.startsWith("/") && exists(p));
  const out: string[] = [];
  const guard = first(env["MANDU_NET_GUARD"], "mandu-net-guard");
  if (guard) out.push("--net-guard", guard);
  if (!already.includes("--landlock-apply")) {
    const applier = first(env["MANDU_LANDLOCK_APPLY"], "mandu-landlock-apply");
    if (applier) out.push("--landlock-apply", applier);
  }
  return out;
}

/**
 * The arbiter's policy-classifier flags (confidentiality-plan-14 §14.3):
 * `--classifier <json argv>` (inspect-mcp's classify-main) and
 * `--landlock-apply <path>` (the applier that confines the classifier's
 * network, when it is built). The classifier runs in the form of the arbiter
 * that runs it (packaging.md §5.1): the bundle when installed; in a checkout,
 * the checkout's bundle `<checkoutDist>/policy-classifier.mjs` for the
 * arbiter's bundled form (whose build record the supervisor checks before
 * that spawn), else, and for the source form, inspect-mcp's source through
 * its own tsx. The arbiter learns them only from its argv; without them its
 * model ops answer "not available in this install". Pure over `exists`;
 * exported for the unit test. Mirrors the launcher's `arbiterClassifierArgs`
 * (launcher/src/arbiter.ts, through Layout.policyClassifier), for the arbiter
 * the launcher starts itself.
 */
export function arbiterClassifierArgs(
  o: { repoRoot: string; installedPkgRoot: string | null; checkoutDist?: string },
  env: Record<string, string | undefined> = process.env,
  exists: (p: string) => boolean = existsSync,
): string[] {
  let argv: string[] | null = null;
  let appliers: string[];
  if (o.installedPkgRoot !== null) {
    const bundle = join(o.installedPkgRoot, "dist", "policy-classifier.mjs");
    if (exists(bundle)) argv = [process.execPath, ...BUNDLE_NODE_FLAGS, bundle];
    appliers = [join(o.installedPkgRoot, "dist", "native", `${process.platform}-${process.arch}`, "mandu-landlock-apply")];
  } else {
    const bundle = o.checkoutDist !== undefined ? join(o.checkoutDist, "policy-classifier.mjs") : null;
    const dir = join(o.repoRoot, "interceptors", "inspect-mcp");
    const tsx = join(dir, "node_modules", "tsx", "dist", "esm", "index.mjs");
    if (bundle !== null && exists(bundle)) argv = [process.execPath, ...BUNDLE_NODE_FLAGS, bundle];
    else if (exists(tsx)) argv = [process.execPath, "--import", pathToFileURL(tsx).href, join(dir, "src", "classify-main.ts")];
    appliers = ["release", "debug"].map((b) => join(o.repoRoot, "interceptors", "target", b, "mandu-landlock-apply"));
  }
  if (argv === null) return [];
  const override = env["MANDU_LANDLOCK_APPLY"];
  const applier = [...(override ? [override] : []), ...appliers].find((p) => p.startsWith("/") && exists(p));
  return ["--classifier", JSON.stringify(argv), ...(applier ? ["--landlock-apply", applier] : [])];
}

/**
 * The readiness deadline from the environment: MANDU_SERVICE_READY_TIMEOUT_MS
 * (milliseconds, a positive integer), or undefined for DEFAULTS.startTimeoutMs.
 * The launcher's stack autostart sets it on the supervisor it spawns to its own
 * load-aware deadline (launcher services/primitives.ts serviceReadyDeadlineMs;
 * runtime-instances.md §10 "Autostart deadlines under load"): a fixed 10 s
 * readiness timeout SIGKILLed a supervised arbiter that a saturated host was
 * still starting, and the dashboard then served with no arbiter at all.
 */
export function startTimeoutFromEnv(env: Record<string, string | undefined>): number | undefined {
  const raw = env["MANDU_SERVICE_READY_TIMEOUT_MS"]?.trim();
  return raw && /^\d+$/.test(raw) && Number(raw) > 0 ? Number(raw) : undefined;
}

export const DEFAULTS = {
  modelProxyPort: 8788,
  openaiProxyPort: 8789,
  egressProxyPort: 8790,
  proxyHost: "127.0.0.1",
  upstreamAnthropic: "https://api.anthropic.com",
  upstreamOpenai: "https://api.openai.com",
  logRingMax: 50_000,
  startTimeoutMs: 10_000,
  stopGraceMs: 4_000,
} as const;

/** SupervisorOptions after the constructor fills the defaults (the shape the
 *  class and buildDefinitions actually work with). */
export type ResolvedSupervisorOptions = Required<
  Omit<
    SupervisorOptions,
    "eventDir" | "symbolDb" | "definitions" | "log" | "logDir" | "mockSitesPath" | "arbiterInstanceBase" | "layout" | "checkoutDist"
  >
> &
  Pick<SupervisorOptions, "eventDir" | "symbolDb" | "definitions" | "mockSitesPath" | "arbiterInstanceBase" | "layout" | "checkoutDist"> & {
    log: (msg: string) => void;
  };

/** node flags every bundle is spawned with (mirrors launcher/src/services/layout.ts
 *  NODE_FLAGS: the node:sqlite ExperimentalWarning the arbiter bundle emits). */
const BUNDLE_NODE_FLAGS = ["--no-warnings=ExperimentalWarning"];

/** The installed-layout spawn for one bundled service (`dist/<name>.mjs`).
 *  `needsClient` adds MANDU_ARBITER_CLIENT_MODULE (the interceptors
 *  dynamic-import the arbiter client; the arbiter itself never does). Pure;
 *  exported for the unit test. */
export function bundledSpawn(
  pkgRoot: string,
  name: "arbiter" | "anthropic-proxy" | "openai-proxy" | "net-proxy",
  needsClient: boolean,
  distDir: string = join(pkgRoot, "dist"),
): Pick<ServiceDefinition, "command" | "args" | "cwd"> & { clientEnv: NodeJS.ProcessEnv } {
  const bundle = (n: string): string => join(distDir, `${n}.mjs`);
  return {
    command: process.execPath,
    args: [...BUNDLE_NODE_FLAGS, bundle(name)],
    cwd: pkgRoot,
    clientEnv: needsClient ? { MANDU_ARBITER_CLIENT_MODULE: bundle("arbiter-client") } : {},
  };
}

/** Each supervised service's source package and TypeScript entry, relative
 *  to the repo root (mirrors launcher/src/services/layout.ts SERVICE_SOURCES;
 *  the unit test holds them equal). */
export const CHECKOUT_SOURCES = {
  "arbiter": { pkg: "arbiter", entry: "arbiter/ipc/server-main.ts" },
  "anthropic-proxy": { pkg: "interceptors/anthropic-proxy", entry: "interceptors/anthropic-proxy/src/server-main.ts" },
  "openai-proxy": { pkg: "interceptors/openai-proxy", entry: "interceptors/openai-proxy/src/server-main.ts" },
  "net-proxy": { pkg: "interceptors/net-proxy", entry: "interceptors/net-proxy/src/server-main.ts" },
} as const;

/**
 * The SOURCE form of a service in a checkout (packaging.md §5.1; the
 * launcher's Layout.daemon source form): its TypeScript entry through the
 * package's own tsx as ONE node process, `node --import <file URL of tsx's
 * ESM entry> <entry.ts>`, cwd the package. Never `npm run serve` (npm, then
 * sh, then the tsx binary re-spawning node: three extra processes and about
 * a second per start). Pure; exported for the unit test.
 */
export function checkoutSourceSpawn(
  repoRoot: string,
  name: keyof typeof CHECKOUT_SOURCES,
): Pick<ServiceDefinition, "command" | "args" | "cwd"> {
  const s = CHECKOUT_SOURCES[name];
  const dir = join(repoRoot, s.pkg);
  const tsx = join(dir, "node_modules", "tsx", "dist", "esm", "index.mjs");
  return { command: process.execPath, args: ["--import", pathToFileURL(tsx).href, join(repoRoot, s.entry)], cwd: dir };
}

/**
 * The launcher's own build-record check (launcher/scripts/bundle-stamp.mjs
 * `checkStamp`, the rule launcher/mandu-run.sh applies), loaded from the
 * checkout at run time: the dashboard does not import the launcher package,
 * and an installed dashboard never asks (it has no checkout). Anything that
 * goes wrong (no script, a read error) answers STALE: the source form runs.
 */
export async function checkoutBundleFresh(distDir: string, repoRoot: string): Promise<BundleFreshness> {
  try {
    const script = join(repoRoot, "launcher", "scripts", "bundle-stamp.mjs");
    const mod = (await import(pathToFileURL(script).href)) as {
      checkStamp: (dist: string, o: { repoRoot: string }) => { fresh: boolean; reason?: string };
    };
    const r = mod.checkStamp(distDir, { repoRoot });
    return r.fresh ? { fresh: true } : { fresh: false, reason: r.reason ?? "stale" };
  } catch (err) {
    return { fresh: false, reason: `its build record could not be checked (${(err as Error).message})` };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Arbiter staleness (scope-honest)
// ─────────────────────────────────────────────────────────────────────────────

/** The supervisor's verdict on the LISTENING arbiter's code freshness. */
export interface StalenessVerdict {
  stale: boolean;
  /** Human-readable cause when stale, else null. */
  staleReason: string | null;
}

const FRESH: StalenessVerdict = { stale: false, staleReason: null };

/**
 * The listening arbiter against the release and build this dashboard would
 * start (runtime-instances.md §4, §4.1), before the scope-honest rev rule:
 *   - another release (its hello `version`; a real arbiter that reports none
 *     is a release from before the version check) → stale;
 *   - two bundles whose hashes differ → stale (another build of one release:
 *     two commits of one version, the S8 miss);
 *   - an installation's dashboard over an arbiter that runs a checkout's
 *     source (a rev, no bundle) → stale: two different places.
 * Null when none applies: the caller goes on to arbiterStaleness. Unknown
 * on either side (no version, no build) is no evidence. Pure.
 */
export function arbiterReleaseStaleness(identity: ArbiterIdentity | null, own: OwnArbiterBuild): StalenessVerdict | null {
  if (!identity) return null;
  const ours = own.version && own.version !== "unknown" ? own.version : null;
  const theirs = typeof identity.version === "string" && identity.version.trim() !== "" ? identity.version.trim() : null;
  if (ours !== null) {
    if (theirs === null && typeof identity.protocolVersion === "number") {
      return { stale: true, staleReason: `it runs an older Mandu release (one that does not report its version); this dashboard is Mandu ${ours}` };
    }
    if (theirs !== null && theirs !== ours) {
      return { stale: true, staleReason: `it runs Mandu ${theirs}; this dashboard is Mandu ${ours}` };
    }
  }
  const b = identity.build;
  const theirBundle = b && typeof b.bundle === "string" && b.bundle !== "" ? b.bundle : null;
  const theirRev = b && typeof b.rev === "string" && b.rev !== "" ? b.rev : null;
  if (own.bundle !== null && theirBundle !== null && own.bundle !== theirBundle) {
    return {
      stale: true,
      staleReason: `it runs another build of ${theirs ? `Mandu ${theirs}` : "this release"} (bundle ${theirBundle}${theirRev ? `, rev ${theirRev}` : ""}) ` +
        `than this dashboard starts (bundle ${own.bundle})`,
    };
  }
  if (own.installed && own.bundle !== null && theirBundle === null && theirRev !== null) {
    return {
      stale: true,
      staleReason: `it runs a checkout's source (rev ${theirRev}), not this installation's build (bundle ${own.bundle})`,
    };
  }
  return null;
}

/**
 * Scope-honest staleness of the listening arbiter (its `hello` identity) vs
 * THIS repo checkout. A rev mismatch alone is NOT stale — only a mismatch whose
 * commit range actually touches `arbiter/` (the arbiter is a standalone package
 * importing nothing outside its dir). A dashboard-only commit must not banner
 * the arbiter: an over-eager badge trains the operator to ignore it — the same
 * committed-drift rule as DashboardSelf.status() (self-status.ts).
 *
 * One deliberate asymmetry vs that self-check: an UNRESOLVABLE rev flags STALE
 * (fail-loud), not quiet. bootRev there is self-captured from this checkout, so
 * failing to resolve it means repo breakage; identity.gitRev here is a foreign
 * daemon's claim, and "this repo cannot even resolve the rev it is running"
 * (rebased away, another checkout's unpushed commit) is the masquerading
 * stale-daemon trap itself, not noise.
 *
 * Pure decision logic — git access only through the two injected helpers.
 */
export function arbiterStaleness(
  identity: ArbiterIdentity | null,
  repoRoot: string,
  gitRev: (repoRoot: string) => string,
  gitChangedInRange: (repoRoot: string, from: string, to: string, dir: string) => string[] | null,
): StalenessVerdict {
  if (!identity || identity.gitRev === "nogit") return FRESH;
  const repoRev = gitRev(repoRoot);
  if (repoRev === "nogit" || identity.gitRev === repoRev) return FRESH;
  const touched = gitChangedInRange(repoRoot, identity.gitRev, repoRev, join(repoRoot, "arbiter"));
  if (touched === null) {
    return {
      stale: true,
      staleReason:
        `running rev ${identity.gitRev} is not in this repo's history (HEAD ${repoRev}) — ` +
        `cannot scope the diff, assuming stale`,
    };
  }
  if (touched.length > 0) {
    return {
      stale: true,
      staleReason:
        `arbiter code changed between its rev and this repo's HEAD ` +
        `(${identity.gitRev} → ${repoRev}, ${touched.length} file${touched.length === 1 ? "" : "s"})`,
    };
  }
  return FRESH; // HEAD moved, but not the arbiter's code — restarting would load identical code
}

// ─────────────────────────────────────────────────────────────────────────────
// Production ServiceDefinitions
// ─────────────────────────────────────────────────────────────────────────────

export function buildDefinitions(
  o: ResolvedSupervisorOptions,
  env: NodeJS.ProcessEnv = process.env,
): Record<ServiceId, ServiceDefinition> {
  const override = o.definitions ?? {};

  // Instance mode (runtime-instances.md): spawn the arbiter WITHOUT an explicit
  // socket — it binds inside its own `instances/<id>/` dir and PROMOTES itself
  // (atomic `current` symlink swap). MANDU_ARBITER_SOCK is cleared explicitly
  // because service env is merged OVER process.env, which may carry it.
  // Legacy mode: pin the socket path verbatim as before.
  const arbiterEnv: NodeJS.ProcessEnv = o.arbiterInstanceBase
    ? { MANDU_RUNTIME_DIR: o.arbiterInstanceBase, MANDU_PROMOTE: "1", MANDU_ARBITER_SOCK: "" }
    : { MANDU_ARBITER_SOCK: o.arbiterSock };
  // The supervised arbiter IS the live tenant (policy-surface.md
  // §2.7): it refuses test-stamped events and stamps unstamped ones live. Test
  // runs go to the test-arbiter below.
  arbiterEnv.MANDU_TENANT = "live";

  const test = testTenantPaths(o, env);
  const testArbiterEnv: NodeJS.ProcessEnv = {
    MANDU_TENANT: "test",
    MANDU_ARBITER_SOCK: test.sock, // pinned — never promoted to `current`
    MANDU_PROMOTE: "",
    ...(o.arbiterInstanceBase ? { MANDU_RUNTIME_DIR: o.arbiterInstanceBase } : {}),
    // The axis switches a test-tenant arbiter runs are the harness's business
    // (CONF scenarios spawn their own posture); the shared test arbiter runs
    // `injection` (integrity ON, confidentiality OFF) regardless of the
    // operator's live config.toml and of the product default — unless a
    // TEST-tenant posture is pinned explicitly (MANDU_TEST_INTEGRITY /
    // MANDU_TEST_CONFIDENTIALITY): a GROUPED live run proves one fold of the
    // int×conf matrix decided by the arbiter it rides, and its posture guard
    // hard-fails on a mismatch (docker-e2e.md §1.5 group (iii) boots conf ON), so CI maps
    // the job's axis env onto these in the docker rig's entrypoint. The live
    // operator's config never reaches the test arbiter either way.
    // STATED, never inherited from the built-in default (protection-modes.md
    // §4): the ungrouped live suites that ride this arbiter prove the symbol-only
    // invariant, which exists only with integrity ON. If the product default
    // moves (it becomes `secrets`), this arbiter must not move with it, or those
    // suites would pass with the axis they test switched off.
    MANDU_INTEGRITY: env.MANDU_TEST_INTEGRITY || "1",
    MANDU_CONFIDENTIALITY: env.MANDU_TEST_CONFIDENTIALITY || "0",
    // The integrity axis is frozen (docs/design/architecture/protection-modes.md §10) and the
    // arbiter refuses it without the opt-in. This rig is the frozen lane's
    // (its live suites prove the integrity invariant), so it opts in by name;
    // the operator's LIVE arbiter above never does.
    [INTEGRITY_OPT_IN_ENV]: "1",
  };

  // Every service is spawned as ONE node process (never `npm run serve`): the
  // arbiter because its admin channel is an inherited fd and only a direct
  // node spawn keeps it (ServiceDefinition.adminChannel), the proxies because
  // npm → sh → the tsx binary → node cost about a second a start.
  // DEV layout (a checkout, packaging.md §5.1): the definition is the source
  // form (checkoutSourceSpawn) and carries the bundled form
  // (`checkoutBundle`, the checkout's launcher/dist); the supervisor picks
  // the bundle at each spawn only while its build record says it is fresh.
  // INSTALLED layout: the bundle is all there is (see SupervisorOptions
  // .layout).
  // Store paths ride the argv (`--symbol-db` / `--event-dir`, appended to the
  // arbiter's args in both layouts), never the env: the live arbiter gets
  // them only when an explicit option names a path, the test arbiter always.
  const installed = o.layout?.mode === "installed" ? o.layout.pkgRoot : null;
  const dist = o.checkoutDist ?? join(o.repoRoot, "launcher", "dist");
  type Spawn = { command: string; args: string[]; cwd: string; clientEnv: NodeJS.ProcessEnv; bundle: CheckoutBundleForm | null };
  const spawnOf = (name: keyof typeof CHECKOUT_SOURCES, needsClient: boolean): Spawn => {
    if (installed !== null) return { ...bundledSpawn(installed, name, needsClient), bundle: null };
    // The checkout's bundle has the installed shape over its own dist (cwd
    // its parent, launcher/, as the launcher's Layout.daemon runs it).
    const b = bundledSpawn(dirname(dist), name, needsClient, dist);
    return {
      ...checkoutSourceSpawn(o.repoRoot, name),
      clientEnv: {},
      bundle: { command: b.command, args: b.args, cwd: b.cwd, env: b.clientEnv, distDir: dist, repoRoot: o.repoRoot },
    };
  };
  /** The bundled form with the definition's tail arguments (store flags …). */
  const withTail = (b: CheckoutBundleForm | null, tail: string[]): { checkoutBundle?: CheckoutBundleForm } =>
    b === null ? {} : { checkoutBundle: { ...b, args: [...b.args, ...tail] } };

  const arbiterSpawn = spawnOf("arbiter", false);
  // The arbiter's tail: its store flags, the classifier it runs and the
  // plugins' confinement flags. The classifier follows the arbiter's form:
  // the bundled arbiter runs the bundled classifier from the same build, the
  // source arbiter the source one (arbiterClassifierArgs).
  const arbiterTailOf = (checkoutDist?: string): string[] => {
    const classifier = arbiterClassifierArgs({ repoRoot: o.repoRoot, installedPkgRoot: installed, ...(checkoutDist !== undefined ? { checkoutDist } : {}) }, env);
    return [
      ...arbiterStoreArgs({ symbolDb: o.symbolDb, eventDir: o.eventDir }),
      ...classifier,
      ...arbiterPluginArgs(classifier, { repoRoot: o.repoRoot, installedPkgRoot: installed }, env),
    ];
  };
  const arbiterTail = arbiterTailOf();
  const arbiter: ServiceDefinition = {
    label: "Arbiter",
    command: arbiterSpawn.command,
    args: [...arbiterSpawn.args, ...arbiterTail],
    cwd: arbiterSpawn.cwd,
    env: arbiterEnv,
    ready: { kind: "socket", path: o.arbiterSock },
    endpoint: o.arbiterSock,
    requires: [],
    adminChannel: true,
    ...withTail(arbiterSpawn.bundle, arbiterSpawn.bundle === null ? [] : arbiterTailOf(arbiterSpawn.bundle.distDir)),
  };

  const modelSpawn = spawnOf("anthropic-proxy", true);
  const modelProxy: ServiceDefinition = {
    label: "Anthropic proxy (Claude)",
    command: modelSpawn.command,
    args: modelSpawn.args,
    cwd: modelSpawn.cwd,
    env: {
      ...modelSpawn.clientEnv,
      MANDU_ARBITER_SOCK: o.arbiterSock,
      MANDU_PROXY_PORT: String(o.modelProxyPort),
      MANDU_PROXY_HOST: o.proxyHost,
      MANDU_UPSTREAM: o.upstreamAnthropic,
    },
    ready: { kind: "tcp", host: o.proxyHost, port: o.modelProxyPort },
    endpoint: `${o.proxyHost}:${o.modelProxyPort}`,
    requires: ["arbiter"],
    ...withTail(modelSpawn.bundle, []),
  };

  const openaiSpawn = spawnOf("openai-proxy", true);
  const openaiProxy: ServiceDefinition = {
    label: "OpenAI proxy (Codex)",
    command: openaiSpawn.command,
    args: openaiSpawn.args,
    cwd: openaiSpawn.cwd,
    env: {
      ...openaiSpawn.clientEnv,
      MANDU_ARBITER_SOCK: o.arbiterSock,
      MANDU_PROXY_PORT: String(o.openaiProxyPort),
      MANDU_PROXY_HOST: o.proxyHost,
      MANDU_UPSTREAM: o.upstreamOpenai,
    },
    ready: { kind: "tcp", host: o.proxyHost, port: o.openaiProxyPort },
    endpoint: `${o.proxyHost}:${o.openaiProxyPort}`,
    requires: ["arbiter"],
    ...withTail(openaiSpawn.bundle, []),
  };

  const egressSpawn = spawnOf("net-proxy", true);
  const egressProxy: ServiceDefinition = {
    label: "Net proxy (network egress)",
    command: egressSpawn.command,
    args: egressSpawn.args,
    cwd: egressSpawn.cwd,
    env: {
      ...egressSpawn.clientEnv,
      MANDU_ARBITER_SOCK: o.arbiterSock,
      MANDU_NET_PROXY_PORT: String(o.egressProxyPort),
      MANDU_NET_PROXY_HOST: o.proxyHost,
      // Offline web mock (optional): the net-proxy serves canned responses for
      // configured URLs so a real-agent loop / demo is deterministic + offline.
      ...(o.mockSitesPath ? { MANDU_NET_PROXY_MOCK_SITES: o.mockSitesPath } : {}),
    },
    ready: { kind: "tcp", host: o.proxyHost, port: o.egressProxyPort },
    endpoint: `${o.proxyHost}:${o.egressProxyPort}`,
    requires: ["arbiter"],
    ...withTail(egressSpawn.bundle, []),
  };

  // The TEST-tenant arbiter: same binary, same direct-node spawn (admin
  // channel), its own socket/DB/event dir, no dependents — the proxies serve
  // live sessions; a test run's proxies are the harness's own.
  const testArbiter: ServiceDefinition = {
    label: "Test arbiter (test tenant)",
    command: arbiterSpawn.command,
    args: [...arbiterSpawn.args, ...arbiterStoreArgs({ symbolDb: test.symbolDb, eventDir: test.eventDir })],
    cwd: arbiterSpawn.cwd,
    env: testArbiterEnv,
    ready: { kind: "socket", path: test.sock },
    endpoint: test.sock,
    requires: [],
    adminChannel: true,
    ...withTail(arbiterSpawn.bundle, arbiterStoreArgs({ symbolDb: test.symbolDb, eventDir: test.eventDir })),
  };

  return {
    arbiter: override.arbiter ?? arbiter,
    "anthropic-proxy": override["anthropic-proxy"] ?? modelProxy,
    "openai-proxy": override["openai-proxy"] ?? openaiProxy,
    "net-proxy": override["net-proxy"] ?? egressProxy,
    "test-arbiter": override["test-arbiter"] ?? testArbiter,
  };
}
