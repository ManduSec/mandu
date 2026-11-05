/**
 * attachment-pool — `mandu serve`'s proxy pool: one model proxy per declared
 * attachment session (docs/design/agents/openclaw-plugin.md §3.2), run by the
 * service's main process, the dashboard as the arbiter's supervisor, when the
 * unit says so (`MANDU_SERVE=1`). Mandu-new (no reference origin).
 *
 * Why here and not a process of its own: the unit's main process is the
 * dashboard, which already supervises the arbiter, reads its human socket
 * from `hello` and spawns the anthropic-proxy in every layout (an installed
 * bundle, a checkout's fresh bundle, the source). A separate process would
 * need a second unit or the dashboard spawning the launcher, and would still
 * have to be stopped and restarted with the stack. Here the pool stops with
 * the service (the dashboard's exit path) and its proxies hold a lifeline to
 * this process (`MANDU_LIFELINE=stdin`), so a SIGKILLed dashboard leaves no
 * proxy serving.
 *
 * Per declared session (attachment-contract.ts), in order:
 *   0. SECRETS: the launcher's `mandu serve register-secrets --agent <id>`
 *      (launcher/src/serve-secrets.ts) discovers the secret files under HOME
 *      and the agent's workspace and registers them with the arbiter, as a
 *      launch would: a user who never launches still has values to swap. A
 *      failure keeps the session unregistered and unserved, and is retried
 *      with a backoff; it runs again every `secretsMs` (10 min) and at every
 *      start of the service, and a failed rerun stops the proxy (fail
 *      closed) until a rerun succeeds.
 *   1. REGISTER: `beginAttachment {sessionId, kind, coverage}` on the
 *      arbiter's human socket, the coverage `ATTACHMENT_COVERAGE[kind]`. No
 *      proxy runs before the arbiter has the session: a refusal or an
 *      unreachable arbiter is retried with a backoff, and nothing serves.
 *   2. START the proxy with the environment a launch gives its proxy
 *      (services/context-proxy.ts) for this session: its arbiter socket and
 *      human socket, `MANDU_SESSION_KEY=<session>`,
 *      `MANDU_INBOUND_SPEC=openclaw-agent`, tenant `live`, secret posture
 *      `gated`, no view map, no agent directory; its upstreams from the
 *      declared providers (Route 1, openclaw-plugin.md §8.1: the
 *      Anthropic-wire provider's own address as MANDU_UPSTREAM, each
 *      OpenAI-wire provider's in MANDU_OPENAI_UPSTREAMS, the proxy's
 *      per-provider routes; `declaredUpstreamEnv`), the service's own
 *      environment only where none is declared; on the declared port when it
 *      is free, else any. A change of the declared providers restarts the
 *      proxy, and the pool record names the providers it was started with
 *      (`providersKey`), which `mandu openclaw install` waits for.
 *   3. PUBLISH the contract's port file, once the proxy listens and its
 *      identity names this session and this arbiter.
 *   4. RENEW every `renewMs` (20 s, a third of the 60 s lease). `renewed:
 *      false` registers again at once; when that fails, or the arbiter has
 *      been unreachable past the lease, the proxy is stopped and its port
 *      file removed (fail closed), and the session starts over at 1.
 *   5. A proxy that exits loses its port file at once (so `mandu openclaw
 *      install` and the doctor fail closed) and is started again with a
 *      backoff; the registration stays, since the Gateway's programs still
 *      reach the human socket while its proxy is down.
 *   6. STOP (the session undeclared, or the pool stopped): the port file
 *      first, then the proxy, then `endAttachment`, then the directory.
 *   7. THE ROUTE CHECK (openclaw-plugin.md §3.6): every `routeMs` (30 s) and
 *      on every change of the config or a file it includes (fs.watch on
 *      their folders, where the platform has it), the session's OpenClaw
 *      config (the one `mandu openclaw install` recorded in the declaration,
 *      else the service's own `$OPENCLAW_CONFIG_PATH` / `~/.openclaw/
 *      openclaw.json`) is read as OpenClaw reads it and judged by the
 *      doctor's own functions (attachment-contract.ts attachState +
 *      routeVerdict): routed, or lost (the plugin missing or off, the
 *      Anthropic route elsewhere or gone, a model with its own endpoint, the
 *      config unreadable). A lost route is said loudly (the service log, the
 *      pool record `mandu serve status` and `mandu doctor` read) and the
 *      coverage the session declares loses its rows (`attachmentCoverage`),
 *      sent with `updateAttachment` over the admin channel so the arbiter
 *      records a BELIEVED posture (`gated` / `model-route-lost` when model
 *      calls may go around the proxy) the dashboard's Home and session page
 *      show; a route back sends the full coverage again. The user's config
 *      is never written. A route is "lost" only once ARMED (an install
 *      recorded the config, or this pool saw it routed); before, "pending".
 *      Why 30 s: fs.watch reports an edit at once where it works; the timer
 *      is the floor where it does not (a network file system, an include
 *      outside the watched folders), and a Gateway reads its config only
 *      when it starts, so the check reports the file, ahead of the restart
 *      that would act on it. One small file read per session per 30 s.
 *
 * The decisions are pure and exported for the unit test
 * (test/unit/attachment-pool.test.ts); the class drives them over injectable
 * effects (`PoolDeps`). tests/stack/serve-pool-invariant.test.ts runs it
 * over a real arbiter and the real proxy.
 */
import { spawn as nodeSpawn } from "node:child_process";
import { chmodSync, lstatSync, mkdirSync, openSync, closeSync, readdirSync, readFileSync, rmSync, watch as fsWatch, type FSWatcher } from "node:fs";
import { request as httpRequest } from "node:http";
import net from "node:net";
import { basename, dirname, join } from "node:path";

import {
  anthropicProxyPortFile,
  attachmentDir,
  attachmentsRoot,
  ATTACHMENT_DIR_MODE,
  identityProblem,
  parseDeclared,
  parsePortFile,
  poolMarkerFile,
  poolRecordPid,
  POOL_RECORD_FILE,
  PORT_FILE_MODE,
  portFileText,
  attachState,
  GEMINI_BUILTIN_BASE,
  isGoogleWire,
  isOllamaWire,
  OLLAMA_BUILTIN_BASES,
  OPENAI_BUILTIN_BASE,
  providersKey,
  ROUTE_FIX,
  routeLostOf,
  routeStateOf,
  routeVerdict,
  serviceProxyUrl,
  unreadableRouteVerdict,
  parseSandboxStatus,
  sandboxRecordOf,
  sandboxStatusFile,
  SANDBOX_FIX,
  type DeclaredAttachment,
  type DeclaredProvider,
  type GatewayEnvFacts,
  type RouteRecord,
  type SandboxRecord,
  type ServiceIdentity,
} from "../attachment-contract.js";

/** Is `pid` a live process (EPERM: alive, another user's)? */
function pidLive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
}
import { ATTACHMENT_COVERAGE, attachmentCoverage, type Coverage } from "../confinement-posture.js";
import { openclawConfigPath, readOpenclawConfig, type OpenclawConfigRead } from "../openclaw/openclaw-config-read.js";
import { gatewayAzureEnv } from "../openclaw/openclaw-gateway-env.js";
import { dirProblem, publishFile } from "../safe-file.js";

// ── The pure part ───────────────────────────────────────────────────────────

/** The file the proxy publishes its bound port to (its own MANDU_PORT_FILE),
 *  beside the contract's: the pool reads it, then publishes the contract's
 *  only once the session is served. */
export const BOUND_PORT_FILE = "anthropic-proxy.bound";

/** The upstream keys a pool proxy takes from the SERVICE's environment (the
 *  unit's `Environment=`, a drop-in): where a launch's proxy gets them from
 *  its plan (a declared main model, routed providers) or lets the ambient
 *  value ride through (services/context-proxy.ts), the service's own
 *  environment is the operator's configuration. The supervisor's spawn form
 *  carries a default `MANDU_UPSTREAM` (api.anthropic.com) for its shared
 *  proxy; it must never win over the service's (the fresh-VM leg, 2026-10-25:
 *  the pool proxy dialed api.anthropic.com past a configured upstream). */
export const POOL_UPSTREAM_KEYS = [
  "MANDU_UPSTREAM", "MANDU_UPSTREAM_LOCAL", "MANDU_UPSTREAM_TLS", "MANDU_UPSTREAM_IS_BASE_URL",
  "MANDU_OPENAI_UPSTREAMS", "MANDU_OPENAI_TEXT_CALLS", "MANDU_GOOGLE_UPSTREAMS", "MANDU_OLLAMA_UPSTREAMS",
] as const;

/** The environment of a pool proxy: the service's own environment and the
 *  supervisor's spawn form (`form`: how it runs the proxy), with every key a
 *  launch's proxy sets for its session set here; the upstream keys from the
 *  service's environment (`POOL_UPSTREAM_KEYS`; `upstream` overrides
 *  MANDU_UPSTREAM, else the form's default applies), and every other key a
 *  launch derives from its plan explicitly UNSET, so an ambient value can
 *  never give a pool proxy another session's view map, directory or TLS
 *  inspection claim. Pure. */
export function poolProxyEnv(o: {
  service: NodeJS.ProcessEnv;
  form?: NodeJS.ProcessEnv;
  arbiterSock: string;
  humanSock: string | null;
  session: string;
  port: number;
  boundFile: string;
  upstream?: string;
  ownerPid: number;
  /** The session's declared providers (Route 1): each one's address wins. */
  providers?: readonly DeclaredProvider[];
  /** The agent's workspace (absolute), where its relative tool paths start
   *  (OpenClaw resolves `read path` and runs `exec` there): the proxy's
   *  MANDU_AGENT_CWD, so a path label or a binding keyed on the file's real
   *  path applies to `read memo/brief.md` as it does under a launch. */
  agentCwd?: string;
}): NodeJS.ProcessEnv {
  const form = o.form ?? {};
  const upstreams: NodeJS.ProcessEnv = {};
  for (const k of POOL_UPSTREAM_KEYS) upstreams[k] = o.service[k] || undefined;
  upstreams["MANDU_UPSTREAM"] = o.upstream ?? (o.service["MANDU_UPSTREAM"] || form["MANDU_UPSTREAM"]);
  Object.assign(upstreams, declaredUpstreamEnv(o.providers, o.service));
  return {
    ...o.service,
    ...form,
    ...upstreams,
    MANDU_ARBITER_SOCK: o.arbiterSock,
    MANDU_ARBITER_HUMAN_SOCK: o.humanSock ?? undefined,
    MANDU_PROXY_HOST: "127.0.0.1",
    MANDU_PROXY_PORT: String(o.port),
    MANDU_PORT_FILE: o.boundFile,
    MANDU_SESSION_KEY: o.session,
    MANDU_INBOUND_SPEC: "openclaw-agent",
    MANDU_TENANT: "live",
    MANDU_SECRET_POSTURE: "gated",
    MANDU_LIFELINE: "stdin",
    MANDU_OWNER_PID: String(o.ownerPid),
    // A launch's plan-derived keys with no service-level meaning: never from
    // the ambient environment. The agent's directory is the session's own
    // (its workspace, from the registration), never the service's.
    MANDU_VIEW_MAP: undefined,
    MANDU_AGENT_CWD: o.agentCwd !== undefined && o.agentCwd.startsWith("/") ? o.agentCwd : undefined,
    MANDU_NET_TLS_INSPECTED: undefined,
    MANDU_ADMIN_FD: undefined,
    // Route 1 routes no Vertex AI provider (openclaw-plugin.md §8.1, "Vertex
    // AI"): the pool proxy serves none, whatever the environment says.
    MANDU_VERTEX_UPSTREAMS: undefined,
  };
}

/** The upstream keys the declared providers set (Route 1, openclaw-plugin.md
 *  §8.1), over the service environment's: the Anthropic-wire provider's
 *  own address becomes MANDU_UPSTREAM (and the environment's TLS and
 *  local-model claims about ITS upstream are dropped with it); the
 *  OpenAI-wire providers become MANDU_OPENAI_UPSTREAMS and the Gemini-wire
 *  ones MANDU_GOOGLE_UPSTREAMS (model-wires.md §5), the Ollama-wire ones
 *  MANDU_OLLAMA_UPSTREAMS (model-wires.md "The Ollama wire"), each at its own
 *  address, a built-in one (null) at the environment's address for it, else
 *  the vendor's (OpenAI's, Google's, a local Ollama's or Ollama Cloud's). A key no declared provider decides is left
 *  to the environment (nothing declared: all of them). Pure. */
export function declaredUpstreamEnv(providers: readonly DeclaredProvider[] | undefined, service: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  if (providers === undefined) return out;
  const messages = providers.find((p) => p.wire === "anthropic-messages" && p.upstream !== null);
  if (messages !== undefined) {
    out["MANDU_UPSTREAM"] = messages.upstream!;
    out["MANDU_UPSTREAM_LOCAL"] = undefined;
    out["MANDU_UPSTREAM_TLS"] = undefined;
  }
  const table = (key: "MANDU_OPENAI_UPSTREAMS" | "MANDU_GOOGLE_UPSTREAMS" | "MANDU_OLLAMA_UPSTREAMS", list: readonly DeclaredProvider[], builtins: Readonly<Record<string, string>>): void => {
    if (list.length === 0) return;
    let envMap: Record<string, unknown> = {};
    try {
      const v = JSON.parse(service[key] ?? "{}") as unknown;
      if (v !== null && typeof v === "object" && !Array.isArray(v)) envMap = v as Record<string, unknown>;
    } catch { /* the declared ones stand alone */ }
    const map: Record<string, string> = {};
    for (const p of list) {
      const fromEnv = typeof envMap[p.id] === "string" ? envMap[p.id] as string : undefined;
      const url = p.upstream ?? fromEnv ?? (Object.prototype.hasOwnProperty.call(builtins, p.id) ? builtins[p.id] : undefined);
      if (url !== undefined) map[p.id] = url;
    }
    out[key] = JSON.stringify(map);
  };
  const routes = providers.filter((p) => p.wire !== "anthropic-messages");
  table("MANDU_OPENAI_UPSTREAMS", routes.filter((p) => !isGoogleWire(p.wire) && !isOllamaWire(p.wire)), { openai: OPENAI_BUILTIN_BASE });
  table("MANDU_GOOGLE_UPSTREAMS", routes.filter((p) => isGoogleWire(p.wire)), { google: GEMINI_BUILTIN_BASE });
  table("MANDU_OLLAMA_UPSTREAMS", routes.filter((p) => isOllamaWire(p.wire)), OLLAMA_BUILTIN_BASES);
  return out;
}

/** The wait before the `failures`-th consecutive restart (or registration
 *  retry): 1 s, 2 s, 4 s, … at most `maxMs`. Pure. */
export function backoffMs(failures: number, baseMs = 1000, maxMs = 30_000): number {
  const n = Math.max(0, Math.min(failures, 20));
  return Math.min(maxMs, baseMs * 2 ** n);
}

/** What a reconcile does: the declared sessions with no slot start, the
 *  slots no longer declared (or whose declaration changed its port) stop.
 *  Pure. */
export function reconcilePlan(
  declared: readonly DeclaredAttachment[],
  running: ReadonlyMap<string, DeclaredAttachment>,
): { start: DeclaredAttachment[]; stop: string[] } {
  const want = new Map(declared.map((d) => [d.session, d] as const));
  const stop: string[] = [];
  for (const [session, cur] of running) {
    const d = want.get(session);
    // A change of the routed providers restarts the proxy (Route 1: its
    // upstreams are its environment, read once at boot).
    if (d === undefined || d.port !== cur.port || d.kind !== cur.kind || providersKey(d.providers) !== providersKey(cur.providers)) stop.push(session);
  }
  const start = declared.filter((d) => !running.has(d.session) || stop.includes(d.session));
  return { start, stop };
}

/** The port to ask for: the declared one when nothing listens there, else
 *  any (0). Pure. */
export function pickPort(declared: number | null, busy: boolean): number {
  return declared !== null && !busy ? declared : 0;
}

/** The coverage a session declares: its kind's, less what a lost route lost
 *  (openclaw-plugin.md §3.6). A pending or unchecked route claims the kind's:
 *  nothing was attached yet to lose. Pure. */
export function routeCoverage(decl: DeclaredAttachment, route: RouteRecord | null): Coverage {
  return route?.state === "lost" ? attachmentCoverage(decl.kind, routeLostOf(route.problems)) : ATTACHMENT_COVERAGE[decl.kind];
}

/** What the arbiter's record carries of a route (server.ts AttachmentRoute):
 *  routed or lost; nothing while pending or unchecked. Pure. */
export function routeReport(route: RouteRecord | null): { state: "routed" | "lost"; problems: RouteRecord["problems"]; config: string } | undefined {
  if (route === null || route.state === "pending") return undefined;
  return { state: route.state, problems: route.problems.slice(0, 8).map((p) => ({ code: p.code, detail: p.detail.slice(0, 400) })), config: route.config };
}

/** The next route record from a check: the state and problems the verdict
 *  gives, `since` kept while nothing changed. Pure. */
export function nextRouteRecord(prev: RouteRecord | null, o: { state: RouteRecord["state"]; problems: RouteRecord["problems"]; config: string; now: string }): { record: RouteRecord; changed: boolean } {
  const changed = prev === null || prev.state !== o.state || prev.config !== o.config || JSON.stringify(prev.problems) !== JSON.stringify(o.problems);
  return { record: { state: o.state, problems: o.problems, config: o.config, since: changed ? o.now : prev!.since, checkedAt: o.now }, changed };
}

/** What the arbiter answered to `beginAttachment`, or why it is not usable. Pure. */
export function parseRegistration(v: unknown): { token: string; expiresAt: number; leaseMs: number } | { error: string } {
  const r = v !== null && typeof v === "object" ? (v as Record<string, unknown>) : null;
  if (r === null || typeof r["token"] !== "string" || r["token"] === "") return { error: "the arbiter answered without a token" };
  const leaseMs = typeof r["leaseMs"] === "number" && r["leaseMs"] > 0 ? r["leaseMs"] : 60_000;
  const expiresAt = typeof r["expiresAt"] === "number" ? r["expiresAt"] : Date.now() + leaseMs;
  return { token: r["token"], expiresAt, leaseMs };
}

// ── The effects ─────────────────────────────────────────────────────────────

/** How the dashboard spawns the anthropic-proxy (Supervisor.serviceSpawn). */
export interface SpawnForm {
  command: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
}

/** A spawned proxy, as the pool drives it. */
export interface PoolChild {
  pid: number | null;
  onExit(cb: (code: number | null, signal: NodeJS.Signals | null) => void): void;
  /** Signal its process group. */
  kill(sig: NodeJS.Signals): void;
  exited(): boolean;
}

export interface PoolTiming {
  /** How often the session's secret files are discovered and registered again. */
  secretsMs: number;
  /** How often the declared file is read again. */
  reconcileMs: number;
  /** How often a live attachment is renewed (a third of the lease). */
  renewMs: number;
  /** How long a proxy has to listen and answer as the session's. */
  readyMs: number;
  /** SIGTERM → SIGKILL. */
  stopGraceMs: number;
  /** Backoff base and cap (backoffMs). */
  backoffBaseMs: number;
  backoffMaxMs: number;
  /** A proxy that ran this long resets its restart backoff. */
  stableMs: number;
  /** How often each session's OpenClaw config is read again (the route
   *  check, openclaw-plugin.md §3.6), and how long a burst of file changes
   *  is let settle before it is. */
  routeMs: number;
  routeDebounceMs: number;
}

export const DEFAULT_POOL_TIMING: PoolTiming = {
  secretsMs: 600_000,
  reconcileMs: 2_000,
  renewMs: 20_000,
  readyMs: 30_000,
  stopGraceMs: 4_000,
  backoffBaseMs: 1_000,
  backoffMaxMs: 30_000,
  stableMs: 60_000,
  routeMs: 30_000,
  routeDebounceMs: 250,
};

export interface PoolDeps {
  runtimeBase: string;
  arbiterSock: string;
  /** The declared file's text (null: none). */
  readDeclared(): string | null;
  proxySpawn(): Promise<SpawnForm>;
  spawn(form: SpawnForm, env: NodeJS.ProcessEnv, logPath: string): PoolChild;
  /** The arbiter's human socket (its `hello`), or null. */
  humanSock(): Promise<string | null>;
  /** One NDJSON request; rejects on an error answer or no answer. */
  call(sock: string, op: string, args: Record<string, unknown>): Promise<unknown>;
  probeIdentity(port: number): Promise<ServiceIdentity | null>;
  portBusy(port: number): Promise<boolean>;
  /** Discover and register the session's secret files (the launcher's
   *  `mandu serve register-secrets`); ok false fails the session closed. */
  registerSecrets(decl: DeclaredAttachment): Promise<SecretsRun>;
  /** Read an OpenClaw config as OpenClaw does (openclaw/openclaw-config-read.ts,
   *  the launcher's reader). Absent: no route check (a test's pool). */
  readRouteConfig?(path: string): OpenclawConfigRead;
  /** Where the Gateway of a config sets OpenClaw's Azure endpoint variables
   *  (openclaw/openclaw-gateway-env.ts; model-wires.md §9.1). Absent: not
   *  read, so a routed Azure provider is "not verified". */
  readGatewayEnv?(configPath: string): GatewayEnvFacts;
  /** Read a small text file (the plugin's sandbox status, openclaw-plugin.md
   *  §10.6); null when there is none. Absent: never read (a test's pool),
   *  so the tier is judged on its config alone. */
  readText?(path: string): string | null;
  /** The config the route check reads for a session whose declaration names
   *  none (the service's own resolution). */
  routeConfigPath?: string;
  /** Call `cb` when one of `files` changes (fs.watch on their folders); the
   *  closer. Absent, or nothing to watch: the timer alone. */
  watchFiles?(files: readonly string[], cb: () => void): () => void;
  /** `updateAttachment` on the arbiter's ADMIN channel, which the arbiter
   *  believes while the attachment holds the human plane exposed. Absent or
   *  failing: the human socket, where the record is a claim the dashboard
   *  does not show over the believed one. */
  updateAttachmentAdmin?(args: Record<string, unknown>): Promise<unknown>;
  /** Where the proxies' logs go. */
  logDir: string;
  upstream?: string;
  /** The service's own environment (the proxies' base). */
  env: NodeJS.ProcessEnv;
  ownerPid: number;
  uid?: number;
  now(): number;
  log(msg: string): void;
  timing: PoolTiming;
}

/** One secret registration run, as the launcher answered it. */
export interface SecretsRun {
  ok: boolean;
  found?: number;
  registered?: number;
  /** The agent's workspace the registration resolved (absolute), for the
   *  proxy's MANDU_AGENT_CWD (poolProxyEnv). */
  workspace?: string;
  error?: string;
}

/** The launcher's `--json` answer (its last line), or a failure. Pure. */
export function parseSecretsRun(stdout: string, code: number | null): SecretsRun {
  const line = stdout.trim().split("\n").filter((l) => l.trim() !== "").at(-1) ?? "";
  try {
    const o = JSON.parse(line) as Record<string, unknown>;
    const ok = o["ok"] === true && code === 0;
    return {
      ok,
      ...(typeof o["found"] === "number" ? { found: o["found"] } : {}),
      ...(typeof o["registered"] === "number" ? { registered: o["registered"] } : {}),
      ...(typeof o["workspace"] === "string" && o["workspace"].startsWith("/") ? { workspace: o["workspace"] } : {}),
      ...(!ok ? { error: typeof o["error"] === "string" ? o["error"] : `the registration exited ${code}` } : {}),
    };
  } catch {
    return { ok: false, error: `the registration exited ${code} without an answer` };
  }
}

/** One session's state, as `list()` reports it. */
export interface PoolEntry {
  session: string;
  declaredPort: number | null;
  /** registering → starting → serving; backoff between tries. */
  state: "registering" | "starting" | "serving" | "backoff" | "stopping";
  registered: boolean;
  port: number | null;
  proxyPid: number | null;
  restarts: number;
  lastError: string | null;
  /** The last successful secret registration (null: none yet). */
  secrets: { found: number; registered: number; at: string } | null;
  /** The last route check (null: none yet, or no route check). */
  route: RouteRecord | null;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Make `dir` a real 0700 directory of this user's (created when absent). */
function ensurePrivateDir(dir: string, uid: number | undefined): void {
  try { mkdirSync(dir, { mode: ATTACHMENT_DIR_MODE }); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e; }
  const problem = dirProblem(dir, uid !== undefined ? { uid } : {});
  if (problem !== null) throw new Error(`refusing ${dir}: ${problem}`);
  if ((lstatSync(dir).mode & 0o077) !== 0) chmodSync(dir, ATTACHMENT_DIR_MODE);
}

class Slot {
  readonly session: string;
  state: PoolEntry["state"] = "registering";
  token: string | null = null;
  expiresAt = 0;
  child: PoolChild | null = null;
  port: number | null = null;
  startedAt = 0;
  restarts = 0;
  failures = 0;
  regFailures = 0;
  lastError: string | null = null;
  stopped = false;
  secretsOk = false;
  /** The agent's workspace the last registration resolved: the proxy's MANDU_AGENT_CWD. */
  agentCwd: string | undefined;
  secrets: PoolEntry["secrets"] = null;
  route: RouteRecord | null = null;
  /** The confined-commands tier's check (openclaw-plugin.md §10.6); null:
   *  not installed for this session. */
  sandbox: SandboxRecord | null = null;
  private seenRouted = false;
  private routeTimer: NodeJS.Timeout | null = null;
  private routeSettle: NodeJS.Timeout | null = null;
  private routeUnwatch: (() => void) | null = null;
  private routeWatchKey = "";
  private checking = false;
  private recheck = false;
  /** What the arbiter last accepted for the current token (coverage and
   *  route), so a check that changes nothing sends nothing. */
  private reportedKey: string | null = null;
  private secretsTimer: NodeJS.Timeout | null = null;
  private refreshing = false;
  private renewTimer: NodeJS.Timeout | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private renewing = false;

  constructor(public decl: DeclaredAttachment, private readonly d: PoolDeps) {
    this.session = decl.session;
  }

  /** The declaration changed in place (its config recorded by an install):
   *  check the route again now. */
  redeclare(decl: DeclaredAttachment): void {
    this.decl = decl;
    void this.checkRoute();
  }

  private get dir(): string { return attachmentDir(this.d.runtimeBase, this.session); }
  private get portFile(): string { return anthropicProxyPortFile(this.d.runtimeBase, this.session); }
  private get boundFile(): string { return join(this.dir, BOUND_PORT_FILE); }

  entry(): PoolEntry {
    return {
      session: this.session,
      declaredPort: this.decl.port,
      state: this.state,
      registered: this.token !== null,
      port: this.state === "serving" ? this.port : null,
      proxyPid: this.child?.pid ?? null,
      restarts: this.restarts,
      lastError: this.lastError,
      secrets: this.secrets,
      route: this.route,
    };
  }

  begin(): void {
    void this.register();
  }

  private fail(why: string): void {
    this.lastError = why;
    this.d.log(`attachment ${this.session}: ${why}`);
  }

  private schedule(fn: () => void, ms: number): void {
    if (this.stopped) return;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.state = "backoff";
    this.retryTimer = setTimeout(() => { this.retryTimer = null; if (!this.stopped) fn(); }, ms);
    this.retryTimer.unref?.();
  }

  /** beginAttachment; the token, or null (and why, logged). */
  private async beginAttachment(): Promise<boolean> {
    const human = await this.d.humanSock().catch(() => null);
    if (human === null) {
      this.fail("not registered: the arbiter's human socket is not known (no answer to hello)");
      return false;
    }
    let r: unknown;
    // The coverage as the route check last found it: a re-registration
    // while the route is lost keeps it lost on the record.
    const coverage = routeCoverage(this.decl, this.route);
    const route = routeReport(this.route);
    try {
      r = await this.d.call(human, "beginAttachment", {
        sessionId: this.session,
        kind: this.decl.kind,
        coverage,
        ...(route !== undefined ? { route } : {}),
      });
    } catch (e) {
      this.fail(`not registered: the arbiter refused or did not answer (${(e as Error).message})`);
      return false;
    }
    const reg = parseRegistration(r);
    if ("error" in reg) {
      this.fail(`not registered: ${reg.error}`);
      return false;
    }
    this.token = reg.token;
    this.expiresAt = reg.expiresAt;
    this.reportedKey = JSON.stringify({ coverage, route });
    return true;
  }

  // ── The route check (openclaw-plugin.md §3.6) ─────────────────────────────

  /** The URL the Gateway's route must name: the serving proxy's, else the
   *  declared port's (null: nothing to compare with yet). */
  private expectedUrl(): string | null {
    const port = this.state === "serving" && this.port !== null ? this.port : this.decl.port;
    return port !== null ? serviceProxyUrl(port) : null;
  }

  private armRoute(): void {
    if (this.routeTimer || this.d.readRouteConfig === undefined) return;
    this.routeTimer = setInterval(() => void this.checkRoute(), this.d.timing.routeMs);
    this.routeTimer.unref?.();
  }

  /** Check the route now (one at a time; a change during a check checks again). */
  async checkRoute(): Promise<void> {
    if (this.stopped || this.d.readRouteConfig === undefined) return;
    if (this.checking) { this.recheck = true; return; }
    this.checking = true;
    try {
      do {
        this.recheck = false;
        await this.checkRouteOnce();
      } while (this.recheck && !this.stopped);
    } catch (e) {
      this.d.log(`attachment ${this.session}: the route check failed (${(e as Error).message}); trying again in ${Math.round(this.d.timing.routeMs / 1000)} s`);
    } finally {
      this.checking = false;
    }
  }

  private async checkRouteOnce(): Promise<void> {
    const url = this.expectedUrl();
    const read = this.d.readRouteConfig;
    if (url === null || read === undefined || this.stopped) return;
    const path = this.decl.config ?? this.d.routeConfigPath;
    if (path === undefined) return;
    const r = read(path);
    this.watchRoute([path, ...r.files]);
    // Every provider the install routed (Route 1), any added since, and the
    // model fence against the one the install recorded.
    const routes = this.decl.providers !== undefined
      ? { providers: this.decl.providers, unprotected: this.decl.unprotected ?? [], ...(this.decl.allowlist !== undefined ? { allowlist: this.decl.allowlist } : {}) }
      : undefined;
    // The Gateway's environment, read only while an Azure OpenAI provider is
    // routed (the only wire it can send elsewhere; model-wires.md §9.1).
    const azure = (this.decl.providers ?? []).some((p) => p.wire === "azure-openai-responses");
    const gatewayEnv = azure && this.d.readGatewayEnv ? this.d.readGatewayEnv(path) : undefined;
    const v = r.ok
      ? routeVerdict(attachState(r.effective, { serviceUrl: url, ...(routes ? { routes } : {}), ...(gatewayEnv ? { gatewayEnv } : {}) }), url)
      : unreadableRouteVerdict(r.error);
    if (v.routed) this.seenRouted = true;
    const state = routeStateOf(v, this.decl.config !== undefined || this.seenRouted);
    const prev = this.route;
    const { record, changed } = nextRouteRecord(prev, { state, problems: v.problems, config: path, now: new Date(this.d.now()).toISOString() });
    this.route = record;
    if (changed) {
      if (state === "lost") {
        this.d.log(`attachment ${this.session}: ROUTE LOST: ${path} no longer routes it through Mandu: ${v.problems.map((p) => p.detail).join("; ")}. ` +
          `The Gateway keeps the config it loaded until it restarts, so this takes effect at its next restart. Fix: ${ROUTE_FIX}`);
      } else if (prev?.state === "lost") {
        this.d.log(`attachment ${this.session}: the route is back: ${path} routes it through Mandu again`);
      } else if (state === "routed") {
        this.d.log(`attachment ${this.session}: ${path} routes it through Mandu`);
      }
    }
    // The confined-commands tier (openclaw-plugin.md §10.6): the config's
    // sandbox keys, and the plugin's report that OpenClaw's "mandu" backend
    // is its own (last writer wins). Said loudly when a command may run
    // outside Mandu's box; the attachment's posture never claimed the box,
    // so its coverage is unchanged.
    if (this.decl.sandbox !== undefined && r.ok) {
      const status = parseSandboxStatus(this.d.readText?.(sandboxStatusFile(this.d.runtimeBase, this.session)) ?? null, this.d.now(), pidLive);
      const next = sandboxRecordOf(r.effective, this.decl.agent, status, new Date(this.d.now()).toISOString());
      const was = this.sandbox;
      if (JSON.stringify(was?.problems ?? null) !== JSON.stringify(next.problems) || was?.state !== next.state) {
        if (next.state === "lost") {
          this.d.log(`attachment ${this.session}: SANDBOX LOST: commands may run outside Mandu's box: ${next.problems.filter((p) => p.severity === "unconfined").map((p) => p.words).join("; ")}. Fix: ${SANDBOX_FIX}`);
        } else if (was?.state === "lost") {
          this.d.log(`attachment ${this.session}: the confined-commands tier is back: commands run in Mandu's box`);
        }
      }
      this.sandbox = next;
    } else if (this.decl.sandbox === undefined) {
      this.sandbox = null;
    }
    this.writeRecord();
    await this.reportRoute();
  }

  /** Send the coverage and route the check found, when the arbiter does not
   *  hold them yet for this token: the admin channel (believed), else the
   *  human socket (a claim). A failure is tried again at the next check. */
  private async reportRoute(): Promise<void> {
    const token = this.token;
    if (token === null || this.stopped) return;
    const coverage = routeCoverage(this.decl, this.route);
    const route = routeReport(this.route);
    const key = JSON.stringify({ coverage, route });
    if (key === this.reportedKey) return;
    const args = { token, coverage, ...(route !== undefined ? { route } : {}) };
    let why = "";
    if (this.d.updateAttachmentAdmin) {
      try {
        await this.d.updateAttachmentAdmin(args);
        if (this.token === token) this.reportedKey = key;
        return;
      } catch (e) {
        why = `the admin channel: ${(e as Error).message}; `;
      }
    }
    const human = await this.d.humanSock().catch(() => null);
    try {
      if (human === null) throw new Error("the arbiter's human socket is not known");
      await this.d.call(human, "updateAttachment", args);
      if (this.token === token) this.reportedKey = key;
      this.d.log(`attachment ${this.session}: its route was recorded over the human socket, as a claim (${why}no admin channel): the dashboard keeps the believed record`);
    } catch (e) {
      this.d.log(`attachment ${this.session}: its route could not be recorded with the arbiter (${why}${(e as Error).message}); trying again at the next check`);
    }
  }

  /** Watch the config's files (their folders: an editor's or the
   *  installer's rename replaces the file a watch on it would follow). */
  private watchRoute(files: readonly string[]): void {
    if (this.d.watchFiles === undefined || this.stopped) return;
    const key = [...new Set(files)].sort().join("\n");
    if (key === this.routeWatchKey) return;
    this.routeUnwatch?.();
    this.routeWatchKey = key;
    this.routeUnwatch = this.d.watchFiles([...new Set(files)], () => {
      if (this.stopped) return;
      if (this.routeSettle) clearTimeout(this.routeSettle);
      this.routeSettle = setTimeout(() => { this.routeSettle = null; void this.checkRoute(); }, this.d.timing.routeDebounceMs);
      this.routeSettle.unref?.();
    });
  }

  private stopRoute(): void {
    if (this.routeTimer) { clearInterval(this.routeTimer); this.routeTimer = null; }
    if (this.routeSettle) { clearTimeout(this.routeSettle); this.routeSettle = null; }
    this.routeUnwatch?.();
    this.routeUnwatch = null;
    this.routeWatchKey = "";
  }

  /** Run the secret registration; true when it succeeded. */
  private async runSecrets(): Promise<boolean> {
    let r: SecretsRun;
    try {
      r = await this.d.registerSecrets(this.decl);
    } catch (e) {
      r = { ok: false, error: (e as Error).message };
    }
    if (!r.ok) {
      this.secretsOk = false;
      this.fail(`its secret files were not registered (${r.error ?? "unknown"}): not served (fail closed)`);
      return false;
    }
    this.secretsOk = true;
    this.agentCwd = r.workspace;
    this.secrets = { found: r.found ?? 0, registered: r.registered ?? 0, at: new Date(this.d.now()).toISOString() };
    this.writeRecord();
    return true;
  }

  private async register(): Promise<void> {
    if (this.stopped) return;
    this.state = "registering";
    if (!this.secretsOk && !(await this.runSecrets())) {
      if (this.stopped) return;
      this.schedule(() => void this.register(), backoffMs(this.regFailures++, this.d.timing.backoffBaseMs, this.d.timing.backoffMaxMs));
      return;
    }
    if (this.stopped) return;
    this.armSecrets();
    // The route first (on the declared port), so the registration carries
    // what the config says now: a service that starts with the route already
    // lost never records it as covered.
    await this.checkRoute();
    if (this.stopped) return;
    if (!(await this.beginAttachment())) {
      if (this.stopped) return;
      this.schedule(() => void this.register(), backoffMs(this.regFailures++, this.d.timing.backoffBaseMs, this.d.timing.backoffMaxMs));
      return;
    }
    if (this.stopped) { await this.end(); return; }
    this.regFailures = 0;
    this.lastError = null;
    this.d.log(`attachment ${this.session}: registered (posture gated, gap ${this.route?.state === "lost" && routeLostOf(this.route.problems).modelContext ? "model-route-lost" : this.decl.kind})`);
    this.armRenew();
    this.armRoute();
    await this.startProxy();
  }

  private armSecrets(): void {
    if (this.secretsTimer) return;
    this.secretsTimer = setInterval(() => void this.refreshSecrets(), this.d.timing.secretsMs);
    this.secretsTimer.unref?.();
  }

  /** The timer's rerun: a failure stops the proxy until a rerun succeeds
   *  (the attachment stays registered: the Gateway still runs). */
  private async refreshSecrets(): Promise<void> {
    if (this.stopped || this.refreshing) return;
    this.refreshing = true;
    try {
      if (await this.runSecrets()) return;
      if (this.stopped) return;
      this.unpublish();
      const c = this.child;
      this.child = null;
      if (c && !c.exited()) c.kill("SIGTERM");
      this.schedule(() => void this.serveAfterSecrets(), backoffMs(this.failures++, this.d.timing.backoffBaseMs, this.d.timing.backoffMaxMs));
    } finally {
      this.refreshing = false;
    }
  }

  private async serveAfterSecrets(): Promise<void> {
    if (this.stopped) return;
    if (!(await this.runSecrets())) {
      this.schedule(() => void this.serveAfterSecrets(), backoffMs(this.failures++, this.d.timing.backoffBaseMs, this.d.timing.backoffMaxMs));
      return;
    }
    if (this.token === null) { void this.register(); return; }
    if (this.child === null) await this.startProxy();
  }

  private armRenew(): void {
    if (this.renewTimer) clearInterval(this.renewTimer);
    this.renewTimer = setInterval(() => void this.renew(), this.d.timing.renewMs);
    this.renewTimer.unref?.();
  }

  private async renew(): Promise<void> {
    if (this.stopped || this.token === null || this.renewing) return;
    this.renewing = true;
    try {
      const human = await this.d.humanSock().catch(() => null);
      let answer: unknown;
      let reached = false;
      if (human !== null) {
        try {
          answer = await this.d.call(human, "renewAttachment", { token: this.token });
          reached = true;
        } catch { /* below */ }
      }
      if (this.stopped) return;
      if (reached) {
        const a = answer !== null && typeof answer === "object" ? (answer as Record<string, unknown>) : {};
        if (a["renewed"] === true) {
          if (typeof a["expiresAt"] === "number") this.expiresAt = a["expiresAt"];
          return;
        }
        // The lease ran out, or another registration replaced this one.
        this.d.log(`attachment ${this.session}: the arbiter no longer holds it; registering again`);
        this.token = null;
        if (await this.beginAttachment()) return;
        this.lose("its registration was lost and could not be renewed");
        return;
      }
      if (this.d.now() >= this.expiresAt) {
        this.token = null;
        this.lose("the arbiter did not answer for a whole lease");
      }
    } finally {
      this.renewing = false;
    }
  }

  /** The registration is gone: the proxy must not serve. Start over. */
  private lose(why: string): void {
    this.fail(`${why}: stopping its proxy (fail closed)`);
    if (this.renewTimer) { clearInterval(this.renewTimer); this.renewTimer = null; }
    this.unpublish();
    const c = this.child;
    this.child = null;
    if (c && !c.exited()) c.kill("SIGTERM");
    this.schedule(() => void this.register(), backoffMs(this.regFailures++, this.d.timing.backoffBaseMs, this.d.timing.backoffMaxMs));
  }

  private unpublish(): void {
    try { rmSync(this.portFile, { force: true }); } catch { /* gone */ }
  }

  private writeRecord(): void {
    if (this.stopped) return;
    try {
      ensurePrivateDir(attachmentsRoot(this.d.runtimeBase), this.d.uid);
      ensurePrivateDir(this.dir, this.d.uid);
      publishFile(join(this.dir, POOL_RECORD_FILE), JSON.stringify({
        pid: this.d.ownerPid, proxyPid: this.child?.pid ?? null, session: this.session, startedAt: new Date(this.d.now()).toISOString(),
        ...(this.secrets !== null ? { secrets: this.secrets } : {}),
        ...(this.route !== null ? { route: this.route } : {}),
        ...(this.sandbox !== null ? { sandbox: this.sandbox } : {}),
        // What its proxy forwards (Route 1): `mandu openclaw install` waits
        // for a proxy started with the providers it declared.
        providers: providersKey(this.decl.providers),
      }) + "\n", { mode: PORT_FILE_MODE, ...(this.d.uid !== undefined ? { uid: this.d.uid } : {}) });
    } catch (e) {
      this.d.log(`attachment ${this.session}: could not write its pool record (${(e as Error).message})`);
    }
  }

  private async startProxy(): Promise<void> {
    if (this.stopped || this.token === null || !this.secretsOk) return;
    this.state = "starting";
    let human: string | null = null;
    let form: SpawnForm;
    try {
      ensurePrivateDir(attachmentsRoot(this.d.runtimeBase), this.d.uid);
      ensurePrivateDir(this.dir, this.d.uid);
      rmSync(this.boundFile, { force: true });
      this.unpublish();
      human = await this.d.humanSock().catch(() => null);
      form = await this.d.proxySpawn();
    } catch (e) {
      this.fail(`its proxy could not be started: ${(e as Error).message}`);
      this.restartLater();
      return;
    }
    if (this.stopped || this.token === null) return;
    const busy = this.decl.port !== null ? await this.d.portBusy(this.decl.port) : false;
    if (this.stopped || this.token === null) return;
    const askPort = pickPort(this.decl.port, busy);
    if (busy) this.d.log(`attachment ${this.session}: its port ${this.decl.port} is taken; using a free one (\`mandu doctor\` will call the Gateway's route stale)`);
    const env = poolProxyEnv({
      service: this.d.env,
      form: form.env,
      arbiterSock: this.d.arbiterSock,
      humanSock: human,
      session: this.session,
      port: askPort,
      boundFile: this.boundFile,
      ...(this.d.upstream !== undefined ? { upstream: this.d.upstream } : {}),
      ownerPid: this.d.ownerPid,
      ...(this.decl.providers !== undefined ? { providers: this.decl.providers } : {}),
      ...(this.agentCwd !== undefined ? { agentCwd: this.agentCwd } : {}),
    });
    let child: PoolChild;
    try {
      child = this.d.spawn(form, env, join(this.d.logDir, `attachment-${this.session.replace(/[^A-Za-z0-9._-]/g, "-")}.log`));
    } catch (e) {
      this.fail(`its proxy could not be spawned: ${(e as Error).message}`);
      this.restartLater();
      return;
    }
    this.child = child;
    this.startedAt = this.d.now();
    child.onExit((code, signal) => this.onExit(child, code, signal));
    this.writeRecord();

    const deadline = this.d.now() + this.d.timing.readyMs;
    let port: number | null = null;
    while (port === null && this.d.now() < deadline && this.child === child && !child.exited()) {
      try { port = parsePortFile(readFileSync(this.boundFile, "utf8").trim() + "\n"); } catch { /* not yet */ }
      if (port === null) await sleep(100);
    }
    let ok = false;
    while (port !== null && !ok && this.d.now() < deadline && this.child === child && !child.exited()) {
      const id = await this.d.probeIdentity(port);
      ok = identityProblem(id, this.session) === null && id?.arbiterSock === this.d.arbiterSock;
      if (!ok) await sleep(100);
    }
    if (this.child !== child) return; // stopped or lost meanwhile
    if (!ok || port === null) {
      this.fail(port === null ? "its proxy did not publish a port in time" : `the proxy on port ${port} did not answer as ${this.session} in time`);
      child.kill("SIGTERM");
      return; // onExit restarts it
    }
    if (this.stopped || this.token === null) { child.kill("SIGTERM"); return; }
    try {
      publishFile(this.portFile, portFileText(port), { mode: PORT_FILE_MODE, ...(this.d.uid !== undefined ? { uid: this.d.uid } : {}) });
    } catch (e) {
      this.fail(`its port file could not be written (${(e as Error).message})`);
      child.kill("SIGTERM");
      return;
    }
    this.port = port;
    this.state = "serving";
    this.lastError = null;
    this.d.log(`attachment ${this.session}: serving on 127.0.0.1:${port}`);
    // The route names this port now (or names another: a route lost).
    void this.checkRoute();
  }

  private restartLater(): void {
    this.schedule(() => void this.startProxy(), backoffMs(this.failures++, this.d.timing.backoffBaseMs, this.d.timing.backoffMaxMs));
  }

  private onExit(child: PoolChild, code: number | null, signal: NodeJS.Signals | null): void {
    if (this.child !== child) return; // a proxy the pool already let go
    this.child = null;
    this.port = null;
    this.unpublish();
    if (this.stopped) return;
    this.restarts++;
    if (this.d.now() - this.startedAt >= this.d.timing.stableMs) this.failures = 0;
    this.fail(`its proxy exited (${code !== null ? `code ${code}` : `signal ${signal}`}); starting it again`);
    if (this.token === null || !this.secretsOk) return; // lose() / refreshSecrets() already scheduled the way back
    this.restartLater();
  }

  private async end(): Promise<void> {
    const token = this.token;
    this.token = null;
    if (token === null) return;
    const human = await this.d.humanSock().catch(() => null);
    if (human === null) return; // the lease lapses on its own
    try {
      await this.d.call(human, "endAttachment", { token });
      this.d.log(`attachment ${this.session}: ended`);
    } catch { /* the lease lapses on its own */ }
  }

  async stop(): Promise<void> {
    this.stopped = true;
    this.state = "stopping";
    if (this.renewTimer) { clearInterval(this.renewTimer); this.renewTimer = null; }
    if (this.retryTimer) { clearTimeout(this.retryTimer); this.retryTimer = null; }
    if (this.secretsTimer) { clearInterval(this.secretsTimer); this.secretsTimer = null; }
    this.stopRoute();
    this.unpublish();
    const c = this.child;
    this.child = null;
    if (c && !c.exited()) {
      c.kill("SIGTERM");
      const deadline = Date.now() + this.d.timing.stopGraceMs;
      while (!c.exited() && Date.now() < deadline) await sleep(50);
      if (!c.exited()) c.kill("SIGKILL");
    }
    await this.end();
    try { rmSync(this.dir, { recursive: true, force: true }); } catch { /* reap collects it */ }
  }
}

/** The pool: reconciles the declared file into slots. */
export class AttachmentPool {
  private readonly slots = new Map<string, Slot>();
  private timer: NodeJS.Timeout | null = null;
  private stopped = false;
  private lastProblems = "";
  private reconciling: Promise<void> | null = null;

  constructor(private readonly d: PoolDeps) {}

  /** Start: clean what a previous pool left, then reconcile now and on a timer. */
  start(): void {
    this.sweepStale();
    try {
      ensurePrivateDir(attachmentsRoot(this.d.runtimeBase), this.d.uid);
      publishFile(poolMarkerFile(this.d.runtimeBase), JSON.stringify({ pid: this.d.ownerPid, startedAt: new Date(this.d.now()).toISOString() }) + "\n",
        { mode: PORT_FILE_MODE, ...(this.d.uid !== undefined ? { uid: this.d.uid } : {}) });
    } catch (e) {
      this.d.log(`attachments: could not write the pool's record (${(e as Error).message}); \`mandu openclaw install\` will not see the pool`);
    }
    void this.reconcile();
    this.timer = setInterval(() => void this.reconcile(), this.d.timing.reconcileMs);
    this.timer.unref?.();
  }

  /** The port files and directories a previous run left (a SIGKILLed
   *  dashboard), unless a live pool other than this one still serves them. */
  private sweepStale(): void {
    const root = attachmentsRoot(this.d.runtimeBase);
    let names: string[] = [];
    try { names = readdirSync(root); } catch { return; }
    for (const name of names) {
      const dir = join(root, name);
      try {
        if (!lstatSync(dir).isDirectory()) continue;
        let owner: number | null = null;
        try { owner = poolRecordPid(readFileSync(join(dir, POOL_RECORD_FILE), "utf8")); } catch { /* none */ }
        if (owner !== null && owner !== this.d.ownerPid && pidAlive(owner)) continue;
        rmSync(dir, { recursive: true, force: true });
      } catch { /* left for reap */ }
    }
  }

  async reconcile(): Promise<void> {
    if (this.reconciling) return this.reconciling;
    this.reconciling = (async () => {
      if (this.stopped) return;
      const { attachments, problems } = parseDeclared(this.d.readDeclared());
      const p = problems.join("; ");
      if (p !== this.lastProblems) {
        if (p !== "") this.d.log(`attachments: the declared file: ${p}`);
        this.lastProblems = p;
      }
      const running = new Map([...this.slots].map(([k, s]) => [k, s.decl] as const));
      const plan = reconcilePlan(attachments, running);
      for (const session of plan.stop) {
        const s = this.slots.get(session);
        this.slots.delete(session);
        if (s) {
          this.d.log(`attachment ${session}: no longer declared; stopping it`);
          await s.stop();
        }
      }
      if (this.stopped) return;
      // A declaration changed in place (its config recorded by an install,
      // its routes or its model fence recorded again): the slot keeps
      // running and checks the route again.
      for (const d of attachments) {
        const s = this.slots.get(d.session);
        if (s && !plan.start.includes(d) && (s.decl.config !== d.config || JSON.stringify(s.decl.unprotected ?? []) !== JSON.stringify(d.unprotected ?? []) ||
            JSON.stringify(s.decl.providers ?? null) !== JSON.stringify(d.providers ?? null) ||
            JSON.stringify(s.decl.allowlist ?? null) !== JSON.stringify(d.allowlist ?? null))) s.redeclare(d);
      }
      for (const decl of plan.start) {
        const s = new Slot(decl, this.d);
        this.slots.set(decl.session, s);
        s.begin();
      }
    })();
    try { await this.reconciling; } finally { this.reconciling = null; }
  }

  list(): PoolEntry[] {
    return [...this.slots.values()].map((s) => s.entry());
  }

  /** Stop every session (the service is stopping). */
  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    if (this.reconciling) await this.reconciling.catch(() => {});
    const all = [...this.slots.values()];
    this.slots.clear();
    await Promise.all(all.map((s) => s.stop()));
    try {
      const marker = poolMarkerFile(this.d.runtimeBase);
      if (poolRecordPid(readFileSync(marker, "utf8")) === this.d.ownerPid) rmSync(marker, { force: true });
    } catch { /* none */ }
  }
}

function pidAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
}

// ── The real effects ────────────────────────────────────────────────────────

/** Spawn a proxy in its own process group, its stdin our lifeline pipe
 *  (never written: it EOFs when this process dies), its output to `logPath`. */
export function realSpawn(form: SpawnForm, env: NodeJS.ProcessEnv, logPath: string): PoolChild {
  let fd: number | "ignore" = "ignore";
  try { fd = openSync(logPath, "a", 0o600); } catch { /* no log */ }
  const child = nodeSpawn(form.command, form.args, { cwd: form.cwd, env, detached: true, stdio: ["pipe", fd, fd] });
  if (typeof fd === "number") closeSync(fd);
  let done = false;
  const cbs: Array<(c: number | null, s: NodeJS.Signals | null) => void> = [];
  child.once("exit", (c, s) => { done = true; for (const cb of cbs) cb(c, s); });
  child.once("error", () => { if (!done) { done = true; for (const cb of cbs) cb(null, null); } });
  // The lifeline's write end: kept open, never written, not holding us up.
  (child.stdin as unknown as { unref?: () => void } | null)?.unref?.();
  child.stdin?.on("error", () => { /* the child closed its end */ });
  child.unref();
  return {
    pid: child.pid ?? null,
    onExit: (cb) => { cbs.push(cb); },
    kill: (sig) => {
      if (child.pid === undefined || done) return;
      try { process.kill(-child.pid, sig); } catch { try { child.kill(sig); } catch { /* gone */ } }
    },
    exited: () => done,
  };
}

/** One NDJSON request on a unix socket. */
export function ndjsonRequest(sock: string, op: string, args: Record<string, unknown>, timeoutMs = 5_000): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let buf = "";
    let settled = false;
    const done = (err: Error | null, v?: unknown): void => {
      if (settled) return;
      settled = true;
      try { c.destroy(); } catch { /* ignore */ }
      if (err) reject(err); else resolve(v);
    };
    const c = net.connect({ path: sock });
    c.setTimeout(timeoutMs, () => done(new Error(`${op}: no answer in ${timeoutMs} ms`)));
    c.once("error", (e) => done(e));
    c.once("connect", () => c.write(JSON.stringify({ id: 1, op, ...args }) + "\n"));
    c.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try {
        const resp = JSON.parse(buf.slice(0, nl)) as { ok?: boolean; result?: unknown; error?: { message?: string } | string };
        if (resp.ok === false) {
          const msg = typeof resp.error === "string" ? resp.error : resp.error?.message ?? "error";
          done(new Error(msg));
        } else done(null, resp.result);
      } catch (e) {
        done(e as Error);
      }
    });
  });
}

/** `GET /_mandu/identity` on 127.0.0.1:`port`, or null. */
export function probeServiceIdentity(port: number, timeoutMs = 1_500): Promise<ServiceIdentity | null> {
  return new Promise((resolve) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "GET", path: "/_mandu/identity", timeout: timeoutMs }, (res) => {
      let b = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (b += c));
      res.on("end", () => {
        try {
          const o = JSON.parse(b) as unknown;
          resolve(o !== null && typeof o === "object" ? (o as ServiceIdentity) : null);
        } catch { resolve(null); }
      });
    });
    req.on("timeout", () => { req.destroy(); resolve(null); });
    req.on("error", () => resolve(null));
    req.end();
  });
}

/** Does anything accept a TCP connection on 127.0.0.1:`port`? */
export function tcpBusy(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.connect({ host: "127.0.0.1", port });
    s.setTimeout(500, () => { s.destroy(); resolve(false); });
    s.once("connect", () => { s.destroy(); resolve(true); });
    s.once("error", () => resolve(false));
  });
}

/** Run the launcher's `mandu serve register-secrets --agent <id> --json`
 *  (`launcher`: the argv that starts this install's launcher). */
export function launcherRegisterSecrets(launcher: readonly string[], env: NodeJS.ProcessEnv, timeoutMs = 180_000): (decl: DeclaredAttachment) => Promise<SecretsRun> {
  return (decl) => new Promise((resolve) => {
    const [cmd, ...pre] = launcher;
    if (cmd === undefined) { resolve({ ok: false, error: "no launcher to run" }); return; }
    let out = "";
    let errText = "";
    let settled = false;
    const child = nodeSpawn(cmd, [...pre, "serve", "register-secrets", "--agent", decl.agent, "--json"], {
      env: { ...env, MANDU_OWNER_PID: String(process.pid) }, stdio: ["ignore", "pipe", "pipe"],
    });
    const finish = (r: SecretsRun): void => { if (!settled) { settled = true; clearTimeout(timer); resolve(r); } };
    const timer = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* gone */ } finish({ ok: false, error: `the registration did not finish in ${Math.round(timeoutMs / 1000)} s` }); }, timeoutMs);
    timer.unref?.();
    child.stdout?.on("data", (c: Buffer) => { out += c.toString("utf8"); });
    child.stderr?.on("data", (c: Buffer) => { errText = (errText + c.toString("utf8")).slice(-2000); });
    child.once("error", (e) => finish({ ok: false, error: `the launcher could not be run (${e.message})` }));
    child.once("exit", (code) => {
      const r = parseSecretsRun(out, code);
      finish(r.ok || errText.trim() === "" ? r : { ...r, error: `${r.error}; ${errText.trim().split("\n").at(-1)}` });
    });
  });
}

/** Watch `files` through their folders (an editor or the installer replaces
 *  a file by rename, which a watch on the file itself would not follow): `cb`
 *  on any event naming one of them. A folder that cannot be watched is left
 *  to the timer. Returns the closer. */
export function watchConfigFiles(files: readonly string[], cb: () => void): () => void {
  const byDir = new Map<string, Set<string>>();
  for (const f of files) {
    const dir = dirname(f);
    const names = byDir.get(dir) ?? new Set<string>();
    names.add(basename(f));
    byDir.set(dir, names);
  }
  const watchers: FSWatcher[] = [];
  for (const [dir, names] of byDir) {
    try {
      const w = fsWatch(dir, { persistent: false }, (_ev, name) => {
        if (name === null || names.has(String(name))) cb();
      });
      w.on("error", () => { try { w.close(); } catch { /* closed */ } });
      watchers.push(w);
    } catch { /* not watchable here: the timer reads it */ }
  }
  return () => { for (const w of watchers) { try { w.close(); } catch { /* closed */ } } };
}

/** What the pool needs of the supervisor (Supervisor implements it). */
export interface PoolSupervisor {
  serviceSpawn(id: "anthropic-proxy"): Promise<SpawnForm>;
  arbiterHumanSock(): Promise<string | null>;
  readonly serviceLogDir: string;
}

/** The pool of the service's main process: its declared file read from the
 *  path table's `serve-attachments`, its proxies spawned as the supervisor
 *  spawns its own, its registrations on the supervised arbiter's human
 *  socket. */
export function servicePool(sup: PoolSupervisor, o: {
  runtimeBase: string;
  arbiterSock: string;
  declaredFile: string;
  env: NodeJS.ProcessEnv;
  /** The argv that starts this install's launcher (the secret registration). */
  launcher: readonly string[];
  log: (m: string) => void;
  timing?: Partial<PoolTiming>;
  /** `updateAttachment` on the supervised arbiter's admin channel. */
  updateAttachmentAdmin?: (args: Record<string, unknown>) => Promise<unknown>;
}): AttachmentPool {
  const uid = process.getuid?.();
  return new AttachmentPool({
    runtimeBase: o.runtimeBase,
    arbiterSock: o.arbiterSock,
    readDeclared: () => { try { return readFileSync(o.declaredFile, "utf8"); } catch { return null; } },
    proxySpawn: () => sup.serviceSpawn("anthropic-proxy"),
    spawn: realSpawn,
    humanSock: () => sup.arbiterHumanSock(),
    call: (sock, op, args) => ndjsonRequest(sock, op, args),
    probeIdentity: (port) => probeServiceIdentity(port),
    portBusy: (port) => tcpBusy(port),
    registerSecrets: launcherRegisterSecrets(o.launcher, o.env),
    readRouteConfig: (path) => readOpenclawConfig(path, o.env),
    readGatewayEnv: (path) => gatewayAzureEnv(path, o.env),
    readText: (path) => { try { return readFileSync(path, "utf8"); } catch { return null; } },
    routeConfigPath: openclawConfigPath(o.env),
    watchFiles: watchConfigFiles,
    ...(o.updateAttachmentAdmin ? { updateAttachmentAdmin: o.updateAttachmentAdmin } : {}),
    logDir: sup.serviceLogDir,
    env: o.env,
    ownerPid: process.pid,
    ...(uid !== undefined ? { uid } : {}),
    now: () => Date.now(),
    log: o.log,
    timing: { ...DEFAULT_POOL_TIMING, ...(o.timing ?? {}) },
  });
}
