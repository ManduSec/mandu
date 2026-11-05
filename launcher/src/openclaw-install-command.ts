/**
 * openclaw-install-command — `mandu openclaw install` / `uninstall`, and the
 * facts the `mandu doctor` check reads (docs/design/agents/openclaw-plugin.md
 * §8). The I/O half of openclaw-attach.ts. Mandu-new (no reference origin).
 *
 * install, in order, writing nothing until every check passed (fail closed):
 *   1. the plugin directory exists (a source checkout ships it);
 *   2. the session's service proxy is running: its port file (the contract in
 *      openclaw-attach.ts) is trusted and the proxy on that port answers as
 *      this session's (`mandu serve` starts it);
 *   3. the user's `openclaw.json` ($OPENCLAW_CONFIG_PATH, else
 *      `$OPENCLAW_STATE_DIR/openclaw.json`, else `~/.openclaw/openclaw.json`)
 *      exists and parses as JSON5 with its `$include`s resolved, as OpenClaw
 *      reads it;
 *   4. every model it can run is one the service proxy routes (Anthropic;
 *      the launch-time check, agent-model-route.ts openclawModelPlan), and
 *      nothing in it would keep the plugin from loading or send Anthropic
 *      calls elsewhere (installRefusal);
 *   5. the planned file, with its includes resolved again, routes through the
 *      service proxy and enables the plugin (the post-check).
 * Then it backs the file up (`<file>.mandu-backup-<time>`) and writes the new
 * one atomically. A second run that changes nothing writes nothing.
 * uninstall removes what install added (planUninstall), with the same backup.
 *
 * The main file is edited and its `$include` files are not: keys written in
 * the main file merge over included ones (OpenClaw's include rule), and the
 * post-check proves the result. A JSON5 file (comments, unquoted keys) is
 * rewritten as plain JSON: the data is kept, the comments only in the backup.
 */
import { copyFileSync, constants, existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

import { runtimeBase } from "./arbiter-sock.js";
import {
  parseSandboxStatus, providersKey, sandboxStatusFile, sandboxTierProblems, SANDBOX_FIX,
  type DeclaredRoutes, type DeclaredSandbox, type GatewayEnvFacts, type SandboxProblem, type SandboxStatusRecord,
} from "./attachment-contract.js";
import { applySandboxInstall, applySandboxUninstall, hasSandboxBlock, sandboxOriginal, sandboxTierRefusal, sandboxWriteProtect } from "./openclaw-sandbox.js";
import { probeUserns, usernsGapHint } from "./userns.js";
import { manduPath } from "./generated/mandu-paths.js";
import {
  attachedSession,
  attachmentSession,
  attachState,
  endpointWords,
  installRefusal,
  looksAttached,
  normalizeAgentId,
  planInstall,
  planUninstall,
  providerRouteUrl,
  routeVerdict,
  type AttachState,
  type RouteVerdict,
  type ServiceIdentity,
} from "./openclaw-attach.js";
import { builtinAddress, fenceKeysToReclaim, planModelFence, planProviders, wireWords, type PlanOptions, type UnroutableProvider } from "./openclaw-providers.js";
import { AZURE_ENDPOINT_ENV } from "./agent-model-route.js";
import { gatewayAzureEnv } from "./services/openclaw-gateway-env.js";
import {
  attachmentExposureLines, ensureDeclared, livePool, readDeclaredList, readServiceProxy, recordDeclaredConfig, recordDeclaredSandbox, removeDeclared,
  restoreDeclaredEntry, servedProvidersKey, waitServiceProxy, type ServiceProxy,
} from "./serve-attachments.js";
import { openclawPluginDir } from "./services/agent-config.js";
import { openclawConfigPath, readOpenclawConfig } from "./services/openclaw-config-read.js";
import { resolveOpenclawIncludes } from "./services/openclaw-include.js";
import { probeIdentity } from "./services/primitives.js";
import type { Layout } from "./services/layout.js";
import { publishFile } from "./safe-file.js";

type Env = Record<string, string | undefined>;
type Json = Record<string, unknown>;

// The service proxy reader lives with the pool's other readers
// (serve-attachments.ts); re-exported for this module's callers.
export { readServiceProxy, type ServiceProxy } from "./serve-attachments.js";

/** The I/O the command does (real by default; tests pass a temp HOME env and
 *  keep the real file system, or replace pieces). */
export interface AttachDeps {
  pluginDir: string;
  uid: number | undefined;
  probe(port: number): Promise<ServiceIdentity | null>;
  out(s: string): void;
  err(s: string): void;
  now(): Date;
  /** How long install waits for the service's pool to serve a session it
   *  just declared (0 or absent: no wait; the real command waits). */
  serviceWaitMs?: number;
  /** Is the service's proxy pool running (its record names a live pid)?
   *  Absent: never (a test's deps, unless it says otherwise). */
  poolRunning?(env: Env): boolean;
  sleep?(ms: number): Promise<void>;
  /** Whether the Node.js running the service's proxy has zstd (absent:
   *  this one's; model-wires.md §9.3). */
  hasZstd?: boolean;
  /** Where the Gateway of a config sets OpenClaw's Azure endpoint variables
   *  (services/openclaw-gateway-env.ts). Absent: the real reader. */
  gatewayEnv?: GatewayEnvReader;
  /** The argv that runs this Mandu launcher (the confined-commands tier's box
   *  is a launch; Layout.launcherArgv). Absent: `--sandbox` is refused. */
  launcher?: string[];
  /** The host facts the tier needs (openclaw-sandbox.ts sandboxTierRefusal). */
  platform?: string;
  usernsOk?: () => boolean;
  usernsHint?: () => string;
}

export function realAttachDeps(layout: Layout): AttachDeps {
  return {
    pluginDir: openclawPluginDir(layout),
    uid: process.getuid?.(),
    probe: (port) => probeIdentity("127.0.0.1", port),
    out: (s) => process.stdout.write(s),
    err: (s) => process.stderr.write(s),
    now: () => new Date(),
    serviceWaitMs: 30_000,
    poolRunning: (env) => livePool(env, pidAlive) !== null,
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    launcher: layout.launcherArgv(),
    platform: process.platform,
    usernsOk: () => probeUserns(),
    usernsHint: () => usernsGapHint(),
  };
}

function pidAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
}

function homeOf(env: Env): string {
  return env["HOME"] || homedir();
}

interface ReadConfig {
  path: string;
  /** The file actually written (a symlinked config writes its target). */
  target: string;
  text: string;
  raw: Json;
  effective: Json;
  /** Every file read: the main file, then each it includes. */
  files: string[];
}

/** The user's config, read as OpenClaw reads it: the one reader the
 *  service's route check uses too (services/openclaw-config-read.ts). */
function readConfig(env: Env): ReadConfig | { error: string; path: string; absent?: true } {
  const home = homeOf(env);
  const r = readOpenclawConfig(openclawConfigPath(env, home), env, home);
  if (!r.ok) return { error: r.error, path: r.path, ...(r.absent ? { absent: true as const } : {}) };
  return { path: r.path, target: r.target, text: r.text, raw: r.raw, effective: r.effective, files: r.files };
}

/** The plugin entry's config object in `doc` (null: none). */
function pluginEntryConfig(doc: Json): Json | null {
  const c = (((doc["plugins"] as Json | undefined)?.["entries"] as Json | undefined)?.["mandu-inspect"] as Json | undefined)?.["config"];
  return c !== null && typeof c === "object" && !Array.isArray(c) ? c as Json : null;
}

/** OpenClaw's state folder for `env` ($OPENCLAW_STATE_DIR, else ~/.openclaw). */
function openclawStateDir(env: Env): string {
  return env["OPENCLAW_STATE_DIR"] || resolve(homeOf(env), ".openclaw");
}

/**
 * Where install can see OpenClaw's Azure endpoint variables set for the
 * Gateway of `configPath` (AZURE_ENDPOINT_ENV; model-wires.md §9.1): its
 * own environment (the user's shell, which a Gateway started from it
 * inherits), and what services/openclaw-gateway-env.ts reads: the running
 * Gateway's environment, its systemd user unit (`Environment=`,
 * `EnvironmentFile=`), OpenClaw's global dotenv files. `unverified`: why a
 * running Gateway's environment could not be read.
 */
export function azureEndpointEnvSeen(env: Env, configPath: string, read: GatewayEnvReader = gatewayAzureEnv): { set: string[]; unverified?: string; facts: GatewayEnvFacts } {
  const set: string[] = [];
  for (const name of AZURE_ENDPOINT_ENV) {
    if ((env[name] ?? "").trim() !== "") set.push(`${name} (the environment of mandu openclaw install)`);
  }
  const facts = read(configPath, env);
  set.push(...facts.set);
  return { set, facts, ...(facts.verified ? {} : { unverified: facts.why ?? "the Gateway's environment could not be read" }) };
}

/** Reads where a config's Gateway sets the Azure endpoint variables. */
export type GatewayEnvReader = (configPath: string, env: Env) => GatewayEnvFacts;

/** Tell the service which config this session's route lives in (the pool's
 *  route check reads it, and is armed by it: openclaw-plugin.md §3.6). Only
 *  for a session already declared; best-effort (the check then reads the
 *  service's own resolution of the config path). */
function recordConfig(env: Env, session: string, path: string): void {
  try { recordDeclaredConfig(env, session, path); } catch { /* the service checks its own path */ }
}

function stamp(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}

/** Back up `target` beside itself (never over an existing file) and write
 *  `text` atomically with the file's own mode. Returns the backup path.
 *  Two runs in one second (an install, then a re-install that takes a
 *  route back) get `-2`, `-3`, … rather than refusing. */
function backupAndWrite(target: string, text: string, now: Date): string {
  const base = `${target}.mandu-backup-${stamp(now)}`;
  let backup = base;
  for (let n = 2; ; n++) {
    try {
      copyFileSync(target, backup, constants.COPYFILE_EXCL);
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST" || n > 100) throw e;
      backup = `${base}-${n}`;
    }
  }
  const mode = statSync(target).mode & 0o777;
  publishFile(target, text, { mode: mode === 0 ? 0o600 : mode, dirMayBeLink: true });
  return backup;
}

function isPlainJson(text: string): boolean {
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

const RESTART = "Restart the Gateway so it reads the change: openclaw gateway restart";
const POLICY_NOTE =
  "The plugin refuses tool calls that change this file, read Mandu's state or stop the service, but that is a " +
  "policy against obvious attempts, not a boundary: the agent's programs run as you. The Mandu service checks " +
  "this file every 30 seconds and on every change, and says so in `mandu serve status`, `mandu doctor` and the " +
  "dashboard when it stops routing through Mandu; `mandu openclaw gateway` (the Gateway under the wrapper) is the confined form.";

function usage(): string {
  return [
    "usage: mandu openclaw install [--agent <id>] [--leave-unprotected <provider>[,<provider>…]] [--sandbox|--no-sandbox]",
    "       mandu openclaw uninstall",
    "",
    "Attach Mandu to the OpenClaw Gateway you run as a service: writes the Mandu plugin into your",
    "openclaw.json (backed up first) and routes every model provider whose wire Mandu reads",
    "(Anthropic Messages; OpenAI Responses and Chat Completions, OpenAI-compatible providers such",
    "as OpenRouter, LiteLLM, vLLM or Ollama included; Azure OpenAI; a ChatGPT sign-in) through",
    "Mandu's service proxy, which sends",
    "each one on to that provider's own address with your keys and headers untouched. The",
    "service must be running (mandu serve). --agent names the OpenClaw agent whose session the",
    "route carries (default: main).",
    "",
    "A provider Mandu cannot route (Google, Bedrock, a catalog provider not declared in",
    "models.providers, …) makes install refuse, naming it. --leave-unprotected names the ones",
    "you choose to leave as they are: their calls do not cross Mandu, so what their models read",
    "is NOT masked.",
    "",
    "--sandbox (Linux) also makes Mandu OpenClaw's sandbox backend: every command the agent runs",
    "and every file its tools touch runs in Mandu's confined box, where a protected file reads as",
    "its placeholder, the network goes only through Mandu's egress check (real values only to the",
    "hosts your rules name), and Mandu's own files are out of reach. It sets the sandbox mode to",
    "all, keeps chat, web and plugin tools allowed in it, and turns elevated exec off. A later",
    "install keeps it; --no-sandbox takes it out again (your earlier sandbox settings come back).",
    "",
  ].join("\n");
}

/** The value of `--<name> X` / `--<name>=X` (null: the flag without a value). */
function flagValue(rest: readonly string[], name: string): string | null | undefined {
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === `--${name}`) return rest[i + 1] ?? null;
    if (a.startsWith(`--${name}=`)) return a.slice(name.length + 3);
  }
  return undefined;
}

function agentFlag(rest: readonly string[]): string | null | undefined {
  return flagValue(rest, "agent");
}

/** Every `--leave-unprotected` value, split on commas (null: one without a value). */
function leaveFlags(rest: readonly string[]): string[] | null {
  const out: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    let v: string | undefined;
    if (a === "--leave-unprotected") { v = rest[i + 1]; if (v === undefined || v.startsWith("-")) return null; i++; }
    else if (a.startsWith("--leave-unprotected=")) v = a.slice("--leave-unprotected=".length);
    if (v !== undefined) out.push(...v.split(",").map((s) => s.trim()).filter((s) => s !== ""));
  }
  return out;
}

const VALUE_FLAGS: Readonly<Record<string, readonly string[]>> = { install: ["agent", "leave-unprotected"], uninstall: [] };
const BOOL_FLAGS: Readonly<Record<string, readonly string[]>> = { install: ["sandbox", "no-sandbox"], uninstall: [] };

/** `--sandbox` (true), `--no-sandbox` (false), neither (undefined); both is null. */
function sandboxFlag(rest: readonly string[]): boolean | null | undefined {
  const on = rest.includes("--sandbox");
  const off = rest.includes("--no-sandbox");
  return on && off ? null : on ? true : off ? false : undefined;
}

/** `mandu openclaw install|uninstall [...]`. Exit 0 done (or nothing to do),
 *  1 refused (nothing written), 2 usage. */
export async function runOpenclawAttach(verb: "install" | "uninstall", rest: readonly string[], env: Env, deps: AttachDeps): Promise<number> {
  if (rest.includes("--help") || rest.includes("-h")) {
    deps.out(usage());
    return 0;
  }
  const allowed = VALUE_FLAGS[verb]!;
  const bools = BOOL_FLAGS[verb]!;
  const unknown = rest.filter((a, i) => a.startsWith("-") &&
    !bools.some((f) => a === `--${f}`) &&
    !allowed.some((f) => a === `--${f}` || a.startsWith(`--${f}=`)) &&
    !allowed.some((f) => rest[i - 1] === `--${f}`));
  if (unknown.length > 0) {
    deps.err(`mandu openclaw ${verb}: unknown option ${unknown[0]}\n${usage()}`);
    return 2;
  }
  if (verb === "install" && sandboxFlag(rest) === null) {
    deps.err(`mandu openclaw install: --sandbox and --no-sandbox together\n${usage()}`);
    return 2;
  }
  if (verb === "install" && leaveFlags(rest) === null) {
    deps.err(`mandu openclaw install: --leave-unprotected needs a provider id\n${usage()}`);
    return 2;
  }
  return verb === "install" ? install(rest, env, deps) : uninstall(env, deps);
}

async function install(rest: readonly string[], env: Env, deps: AttachDeps): Promise<number> {
  const refuse = (why: string): number => {
    deps.err(`mandu: refusing to install the OpenClaw plugin: ${why}. Nothing was written.\n`);
    return 1;
  };
  const flag = agentFlag(rest);
  if (flag === null) return refuse("--agent needs an agent id");
  const agentId = normalizeAgentId(flag);
  const session = attachmentSession(agentId);
  const leave = leaveFlags(rest) ?? [];

  if (!existsSync(deps.pluginDir)) {
    return refuse(`the plugin is not at ${deps.pluginDir} (it ships in a source checkout of Mandu)`);
  }
  const cfg = readConfig(env);
  if ("error" in cfg) {
    return refuse(cfg.absent ? `${cfg.error}; set OpenClaw up first (openclaw onboard)` : cfg.error);
  }
  // Installed here before (Mandu's marks in the config, or the service
  // recorded this config): a route changed since is LOST, and this install
  // is the fix that takes it back (openclaw-plugin.md §3.6).
  const declaredBefore = readDeclaredList(env).attachments.find((a) => a.session === session) ?? null;
  const reclaim = looksAttached(attachState(cfg.effective, { serviceUrl: null })) || declaredBefore?.config === resolve(cfg.path);
  const why = installRefusal(cfg.effective, { reclaim });
  if (why !== null) return refuse(why);

  // The confined-commands tier (openclaw-plugin.md §10): asked for, or kept
  // from an earlier install unless --no-sandbox takes it out. Refused where
  // it cannot confine (fail closed: never a silent fall-through).
  const tierFlag = sandboxFlag(rest) ?? undefined;
  const tierBefore = declaredBefore?.sandbox !== undefined || hasSandboxBlock(pluginEntryConfig(cfg.raw));
  const wantTier = tierFlag ?? tierBefore;
  if (wantTier) {
    const tierWhy = sandboxTierRefusal(deps.platform ?? process.platform, (deps.usernsOk ?? (() => false))(), (deps.usernsHint ?? (() => "unknown"))());
    if (tierWhy !== null) return refuse(tierWhy);
    if (!deps.launcher || deps.launcher.length === 0 || !deps.launcher[0]!.startsWith("/")) {
      return refuse("this Mandu cannot name its own launcher for the confined-commands box (--sandbox)");
    }
  }

  // Route 1 (openclaw-plugin.md §8.1): every provider whose wire the proxy
  // reads is routed to its own address; one it cannot route is refused
  // unless the user leaves it as it is, by name.
  const priorFence = declaredBefore?.allowlist ?? [];
  const azureSeen = azureEndpointEnvSeen(env, cfg.path, deps.gatewayEnv);
  const planOpts: PlanOptions = {
    azureEndpointEnv: azureSeen.set,
    ...(azureSeen.unverified !== undefined ? { azureEndpointUnverified: azureSeen.unverified } : {}),
    ...(deps.hasZstd !== undefined ? { hasZstd: deps.hasZstd } : {}),
  };
  let plan = planProviders(cfg.effective, cfg.raw, declaredBefore?.providers ?? [], priorFence, planOpts);
  // The model fence taken back (openclaw-plugin.md §3.6, "The model fence"):
  // over a config a fenced install wrote, a key added since that opens a
  // switch around Mandu is removed, as a changed route is routed back.
  const reclaimed = reclaim && declaredBefore?.allowlist !== undefined
    ? fenceKeysToReclaim(cfg.effective, plan, [...leave, ...(declaredBefore.unprotected ?? [])], priorFence)
    : [];
  if (reclaimed.length > 0) plan = planProviders(cfg.effective, cfg.raw, declaredBefore?.providers ?? [], [...priorFence, ...reclaimed], planOpts);
  const hard = plan.cannot.filter((c) => c.hard === true);
  if (hard.length > 0) return refuse(hard.map((c) => `provider ${c.id}: ${c.why}`).join("; "));
  const unleft = plan.cannot.filter((c) => !leave.includes(c.id));
  if (unleft.length > 0) {
    return refuse(
      `Mandu cannot route ${unleft.length === 1 ? "this provider" : "these providers"} of your config, so ${unleft.length === 1 ? "its" : "their"} models would read ` +
      `tool results unmasked: ${unleft.map(cannotWords).join("; ")}. Remove ${unleft.length === 1 ? "it" : "them"} (or the models that name ${unleft.length === 1 ? "it" : "them"}), ` +
      `or leave ${unleft.length === 1 ? "it" : "them"} unprotected on purpose: mandu openclaw install --leave-unprotected ${unleft.map((c) => c.id).join(",")}`,
    );
  }
  const strange = leave.filter((id) => !plan.cannot.some((c) => c.id === id) && !plan.routed.some((p) => p.id === id));
  if (strange.length > 0) return refuse(`--leave-unprotected names ${strange.join(", ")}, which ${strange.length === 1 ? "is not a provider" : "are not providers"} of your config`);
  if (plan.routed.length === 0) return refuse("no provider of your config is one Mandu can route, so nothing would cross Mandu");
  // The model fence (openclaw-plugin.md §8.1): OpenClaw's model allowlist
  // narrowed to what Mandu routes (or the user left), so a switch mid-session
  // cannot reach a model around the proxy. A user's own allowlist is theirs.
  const fence = planModelFence(cfg.effective, plan, priorFence, reclaimed);
  const routes: DeclaredRoutes = { providers: plan.routed, unprotected: plan.cannot.map((c) => c.id), allowlist: fence.record };
  const ignoredLeave = leave.filter((id) => plan.routed.some((p) => p.id === id));

  // The service runs a proxy for every declared session (`mandu serve attach`,
  // openclaw-plugin.md §3.2), forwarding each routed provider where the
  // declaration says: declare this one with its routes, so one command
  // attaches the Gateway, and wait for the pool to serve them. On any refusal
  // below the declaration is put back as it was (nothing is left behind).
  let changedHere = false;
  const putBack = (): void => {
    if (!changedHere) return;
    changedHere = false;
    try { restoreDeclaredEntry(env, session, declaredBefore); } catch { /* mandu serve detach removes it */ }
  };
  const refuseAll = (why: string): number => { putBack(); return refuse(why); };
  const pool = deps.poolRunning?.(env) === true;
  let service: ServiceProxy;
  if (pool) {
    try {
      changedHere = (await ensureDeclared(env, agentId, null, routes)).changed;
    } catch (e) {
      return refuse(`could not declare ${session} with the Mandu service (${(e as Error).message})`);
    }
    const want = providersKey(routes.providers);
    service = await readServiceProxy(env, session, deps);
    if (service.ok && servedProvidersKey(env, session) !== want) service = { ok: false, why: "its proxy still forwards the providers of an earlier install" };
    if (!service.ok && (deps.serviceWaitMs ?? 0) > 0) {
      deps.out(`mandu: waiting for the Mandu service to start the proxy of ${session}…\n`);
      service = await waitServiceProxy(env, session, {
        uid: deps.uid, probe: deps.probe,
        sleep: deps.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))),
        now: () => deps.now().getTime(),
      }, deps.serviceWaitMs!, want);
    }
  } else {
    service = await readServiceProxy(env, session, deps);
    // A proxy serves the session though no pool record is readable (a
    // service from before the record, or a test's stand-in): nothing says
    // where it forwards, so a provider with an address of its own cannot be
    // vouched for (its calls, with its key, could reach Anthropic instead).
    const own = routes.providers.filter((p) => p.upstream !== null);
    if (service.ok && own.length > 0) {
      return refuse(`the Mandu service serving ${session} does not say where it forwards each provider (no pool record), so ` +
        `${own.map((p) => p.id).join(", ")} (at ${own.length === 1 ? "its own address" : "their own addresses"}) cannot be routed through it. ` +
        "Upgrade and restart the service: mandu serve upgrade");
    }
  }
  if (!service.ok) {
    return refuseAll(`Mandu's service proxy for ${session} is not running (${service.why}). Start the service first: mandu serve start` +
      (pool ? " (it runs, but did not serve the session in time: mandu serve status says why)" : " (mandu serve install sets it up)"));
  }
  if (!pool) {
    // Declare it anyway, with its routes, so the service keeps serving it
    // after a restart.
    try { changedHere = (await ensureDeclared(env, agentId, declaredBefore === null ? service.port : null, routes)).changed; } catch { /* the route still works now */ }
  }

  const home = homeOf(env);
  const { doc, dropped } = planInstall(cfg.raw, {
    pluginDir: deps.pluginDir,
    agentId,
    session,
    proxyUrl: service.url,
    arbiterSock: service.arbiterSock,
    manduPaths: [manduPath("mandu-home", env, home), runtimeBase(env)],
    providers: routes.providers,
    fence,
  }, { reclaim });
  // The tier, written or taken out (openclaw-sandbox.ts). What it replaces
  // is recorded at its first install and kept across later ones.
  let tierRecord: DeclaredSandbox | null = declaredBefore?.sandbox ?? null;
  let tierChanges: string[] = [];
  const entryConfig = pluginEntryConfig(doc);
  if (wantTier && entryConfig !== null) {
    tierRecord ??= { original: sandboxOriginal(cfg.raw) };
    tierChanges = applySandboxInstall(doc, entryConfig, {
      launcher: deps.launcher!,
      writeProtect: sandboxWriteProtect({
        configPath: resolve(cfg.path), configTarget: resolve(cfg.target), includes: cfg.files.slice(1),
        stateDir: openclawStateDir(env), pluginDir: deps.pluginDir,
      }),
      statusFile: sandboxStatusFile(runtimeBase(env), session),
    });
  } else if (tierFlag === false && tierBefore) {
    tierChanges = applySandboxUninstall(doc, entryConfig, declaredBefore?.sandbox?.original ?? null);
    tierRecord = null;
  }
  let after: Json;
  try {
    after = resolveOpenclawIncludes(doc, cfg.path, { env }) as Json;
  } catch (e) {
    return refuseAll(`the edited config would not load (${(e as Error).message})`);
  }
  // The post-check: the route check's own verdict over the planned file.
  const verdict = routeVerdict(attachState(after, { pluginDir: deps.pluginDir, serviceUrl: service.url, routes, gatewayEnv: azureSeen.facts }), service.url);
  const fenceAfter = configAllowKeys(after);
  const fenceLost = fence.write.filter((k) => !fenceAfter.includes(k));
  if (fenceLost.length > 0) {
    return refuseAll(
      `after the edit, your config's model allowlist (agents.defaults.models) would not hold ${fenceLost.join(", ")}, which Mandu ` +
      "writes so that a model switch cannot go around Mandu; a file it includes may override the key",
    );
  }
  if (!verdict.routed) {
    return refuseAll(
      `after the edit, your config would still not route through Mandu (${verdict.problems.map((p) => p.detail).join("; ")}); ` +
      "a file it includes may override the keys Mandu writes",
    );
  }
  // The tier's post-check: the edited file, includes resolved, must hold it.
  const tierLost = wantTier ? sandboxTierProblems(after, agentId, null).filter((p) => p.severity === "unconfined") : [];
  if (tierLost.length > 0) {
    return refuseAll(
      `after the edit, your config would still not run commands in Mandu's box (${tierLost.map((p) => p.words).join("; ")}); ` +
      "a file it includes, or the agent's own entry in agents.list, may override the keys Mandu writes",
    );
  }
  const recordTier = (): void => {
    if (JSON.stringify(declaredBefore?.sandbox ?? null) === JSON.stringify(tierRecord)) return;
    try { recordDeclaredSandbox(env, session, tierRecord); } catch { /* uninstall then removes Mandu's values only */ }
  };
  const routeLines = routes.providers.map((p) => `  ${p.id} (${wireWords(p.wire)}): ${providerRouteUrl(service.url, p)} → ${p.upstream ?? `${builtinAddress(p)} (its own)`}`);
  const leftLines = plan.cannot.map((c) => `  ${c.id}: LEFT AS IS, NOT PROTECTED (--leave-unprotected): ${c.why}`);
  const where = (u: string | null): string => (u === null ? "its built-in address" : endpointWords(u));
  const keptLines = plan.kept.map((k) => `  took the ${k.id} route back from ${where(k.now)} (it changed after Mandu's install; the backup keeps it): Mandu keeps sending ${k.id} to the address the install recorded, ${where(k.recorded)}; to adopt the new address on purpose: mandu openclaw uninstall, then install`);
  const fenceBackLines = reclaimed.length > 0
    ? [`  took the model fence back: removed ${reclaimed.join(", ")} from agents.defaults.models (added after Mandu's install, ${reclaimed.length === 1 ? "it lets" : "they let"} a model switch go around Mandu; the backup keeps ${reclaimed.length === 1 ? "it" : "them"}); ` +
      "to allow such a model on purpose: mandu openclaw install --leave-unprotected <provider>, or list the openrouter model in models.providers.openrouter.models"]
    : [];
  const notes = [
    ...keptLines,
    ...fenceBackLines,
    ...ignoredLeave.map((id) => `  --leave-unprotected ${id}: Mandu routes it, so it is protected anyway`),
  ];
  if (JSON.stringify(doc) === JSON.stringify(cfg.raw)) {
    recordConfig(env, session, cfg.path);
    recordTier();
    deps.out(`mandu: the OpenClaw plugin is already installed in ${cfg.path} (session ${session}, ${service.url}); nothing written.\n`);
    if (notes.length > 0) deps.out(notes.join("\n") + "\n");
    deps.out("  If the Gateway restarted while the file did not route through Mandu, restart it again: openclaw gateway restart\n");
    return 0;
  }
  let backup: string;
  try {
    backup = backupAndWrite(cfg.target, JSON.stringify(doc, null, 2) + "\n", deps.now());
  } catch (e) {
    return refuseAll(`could not write ${cfg.target}: ${(e as Error).message}`);
  }
  // Written: the service's route check reads this file from now on, and
  // says so loudly when it stops routing through Mandu.
  recordConfig(env, session, cfg.path);
  recordTier();
  const lostRoute = reclaim ? lostRouteWords(cfg.effective) : [];
  const tierLines = wantTier
    ? [
      "  confined commands (--sandbox): OpenClaw runs every command and file tool of this agent in Mandu's box, where a protected",
      "    file reads as its placeholder, the network goes only through Mandu's egress check and Mandu's own files are out of",
      "    reach; chat, web and plugin tools stay allowed, the browser, nodes and the Gateway tool stay off (they run outside any box),",
      "    elevated exec is off. The box starts with the first command (a few seconds) and lives as long as the Gateway.",
      ...tierChanges.map((c) => `    ${c}`),
    ]
    : tierChanges.length > 0
      ? ["  confined commands taken out (--no-sandbox): commands run where OpenClaw runs them again", ...tierChanges.map((c) => `    ${c}`)]
      : [];
  const lines = [
    `mandu: installed the OpenClaw plugin in ${cfg.path}`,
    `  session ${session}: model calls go through Mandu's service proxy at ${service.url}, each on to its provider's own address:`,
    ...routeLines.map((l) => `  ${l}`),
    ...leftLines,
    ...(fence.write.length > 0 || fence.remove.length > 0
      ? [`  model fence: OpenClaw's model allowlist (agents.defaults.models) names ${fence.record.join(", ")}, so a model switch (/model, a subagent's model) cannot go around Mandu; uninstall removes it`]
      : []),
    ...tierLines,
    ...attachmentExposureLines([session]).map((l) => `  ${l}`),
    `  backup: ${backup}`,
    ...lostRoute.map((l) => `  ${l}`),
    ...notes,
    ...(dropped.length > 0 ? [`  dropped ${dropped.join(", ")} from your model entries (a model's own endpoint would go around Mandu)`] : []),
    ...(!isPlainJson(cfg.text) ? ["  the file was JSON5; it is now plain JSON (your comments are in the backup)"] : []),
    `  ${RESTART}`,
    `  ${POLICY_NOTE}`,
    "",
  ];
  deps.out(lines.join("\n"));
  return 0;
}

/** The keys of a config's model allowlist (`agents.defaults.models`). */
function configAllowKeys(doc: Json): string[] {
  const agents = doc["agents"];
  const defaults = agents !== null && typeof agents === "object" && !Array.isArray(agents) ? (agents as Json)["defaults"] : undefined;
  const models = defaults !== null && typeof defaults === "object" && !Array.isArray(defaults) ? (defaults as Json)["models"] : undefined;
  return models !== null && typeof models === "object" && !Array.isArray(models) ? Object.keys(models as Json) : [];
}

/** A provider install cannot route, in words: why, and where the config
 *  names a model of it. */
function cannotWords(c: UnroutableProvider): string {
  return `${c.id} (${c.why}${c.refs.length > 0 ? `; named by ${c.refs.slice(0, 3).join(", ")}${c.refs.length > 3 ? ", …" : ""}` : ""})`;
}

async function uninstall(env: Env, deps: AttachDeps): Promise<number> {
  const cfg = readConfig(env);
  if ("error" in cfg) {
    if (cfg.absent) {
      deps.out(`mandu: ${cfg.error}; nothing to uninstall.\n`);
      return 0;
    }
    deps.err(`mandu: refusing to uninstall: ${cfg.error}. Nothing was written.\n`);
    return 1;
  }
  const session = attachedSession(cfg.effective);
  // Each routed provider goes back exactly as the install recorded it
  // (Route 1, openclaw-plugin.md §8.1).
  const entry = session !== null ? readDeclaredList(env).attachments.find((a) => a.session === session) : undefined;
  const recorded = entry?.providers;
  const { doc, changed: routesChanged, unrestored } = planUninstall(cfg.raw, deps.pluginDir, recorded, entry?.allowlist);
  // The confined-commands tier (openclaw-plugin.md §10): every value the
  // install replaced goes back as it was (the user's own sandbox settings).
  const tierChanges = applySandboxUninstall(doc, null, entry?.sandbox?.original ?? null);
  const changed = routesChanged || tierChanges.length > 0;
  if (!changed) {
    deps.out(`mandu: the OpenClaw plugin is not installed in ${cfg.path}; nothing written.\n`);
    const left = readDeclaredList(env).attachments;
    if (left.length > 0) {
      deps.out(`  the Mandu service still runs a proxy for ${left.map((a) => a.session).join(", ")}; mandu serve detach openclaw --agent <id> stops it\n`);
    }
    return 0;
  }
  let backup: string;
  try {
    backup = backupAndWrite(cfg.target, JSON.stringify(doc, null, 2) + "\n", deps.now());
  } catch (e) {
    deps.err(`mandu: could not write ${cfg.target}: ${(e as Error).message}. Nothing was written.\n`);
    return 1;
  }
  let detached = false;
  if (session !== null) {
    try { detached = removeDeclared(env, session) !== null; } catch { /* below: still declared */ }
  }
  const restored = (recorded ?? []).map((p) => p.id);
  deps.out([
    `mandu: removed the OpenClaw plugin and Mandu's model routes from ${cfg.path}`,
    `  backup: ${backup}`,
    ...(restored.length > 0 ? [`  put back the address of ${restored.join(", ")} as it was before the install`] : []),
    ...unrestored.map((id) => `  provider ${id} still points at a Mandu route and no record says where it pointed before: set models.providers.${id}.baseUrl again (the install's backup, ${cfg.path}.mandu-backup-…, has it)`),
    ...(tierChanges.length > 0 ? ["  took out the confined-commands tier (Mandu's sandbox backend):", ...tierChanges.map((c) => `    ${c}`)] : []),
    ...(detached ? [`  detached ${session} from the Mandu service: its proxy stops, and confined launches get their guard's attestation back`] : []),
    "  Model calls now go to each provider directly: Mandu no longer masks what the Gateway's models read.",
    `  ${RESTART}`,
    "",
  ].join("\n"));
  return 0;
}

/** What a second install takes back besides the routes (the plugin denied
 *  since the first, openclaw-plugin.md §3.6), in lines for its report. Pure. */
function lostRouteWords(effective: Json): string[] {
  const out: string[] = [];
  const deny = (effective["plugins"] as { deny?: unknown } | undefined)?.deny;
  if (Array.isArray(deny) && deny.includes("mandu-inspect")) out.push("removed mandu-inspect from plugins.deny");
  return out;
}

// ── The doctor check ─────────────────────────────────────────────────────────

/** What `mandu doctor` reports about an attachment (null: none configured). */
export interface OpenclawAttachFacts {
  configPath: string;
  /** The config could not be read (the rest is then absent). */
  unreadable?: string;
  session?: string;
  state?: AttachState;
  /** The route verdict over `state` (attachment-contract.ts routeVerdict:
   *  the decision the service's route check makes too). */
  verdict?: RouteVerdict;
  service?: ServiceProxy;
  /** The providers the install left as they are (Route 1, the declaration's). */
  unprotected?: string[];
  /** The confined-commands tier, when installed (openclaw-plugin.md §10):
   *  what is not as the install wrote it, and the plugin's own report (null:
   *  none fresh, e.g. no Gateway running). */
  sandbox?: { problems: SandboxProblem[]; status: SandboxStatusRecord | null };
}

/** The tier's facts for the doctor and `mandu serve status`, or undefined
 *  when the tier is not installed for `session`. */
export function sandboxFacts(env: Env, effective: Json, session: string, agentId: string, declared: DeclaredSandbox | undefined, readText: (p: string) => string | null = readTextOr, now = Date.now()): OpenclawAttachFacts["sandbox"] {
  if (declared === undefined && !hasSandboxBlock(pluginEntryConfig(effective))) return undefined;
  const status = parseSandboxStatus(readText(sandboxStatusFile(runtimeBase(env), session)), now, pidAlive);
  return { problems: sandboxTierProblems(effective, agentId, status), status };
}

function readTextOr(p: string): string | null {
  try { return readFileSync(p, "utf8"); } catch { return null; }
}

/** The tier's doctor rows (openclaw-plugin.md §10.6). Pure. */
export function sandboxRows(s: NonNullable<OpenclawAttachFacts["sandbox"]>, marks: { ok: string; no: string; dot: string }): string[] {
  const L: string[] = [];
  const bad = s.problems.filter((p) => p.severity === "unconfined");
  if (bad.length === 0) {
    L.push(`  ${marks.ok} confined commands: OpenClaw runs this agent's commands and file tools in Mandu's box (sandbox mode all, backend mandu, elevated off)`);
  } else {
    for (const p of bad) L.push(`  ${marks.no} confined commands: ${p.words}`);
    L.push(`      fix: ${SANDBOX_FIX}`);
  }
  for (const p of s.problems.filter((x) => x.severity === "utility")) L.push(`  ${marks.no} ${p.words}`);
  if (s.status === null) {
    L.push(`  ${marks.dot} the Gateway's plugin has not reported its sandbox backend lately (no Gateway running?): Mandu cannot check that no other plugin took the "mandu" backend`);
  } else if (s.status.ours === true) {
    L.push(`  ${marks.ok} the Gateway's sandbox backend "mandu" is Mandu's (its plugin checked at ${s.status.checkedAt})`);
  }
  return L;
}

/** Gather the doctor facts: null when the user's openclaw.json shows no sign
 *  of an attachment (or there is none). */
export async function gatherOpenclawAttach(env: Env, deps: Pick<AttachDeps, "uid" | "probe" | "pluginDir" | "gatewayEnv">): Promise<OpenclawAttachFacts | null> {
  const cfg = readConfig(env);
  if ("error" in cfg) {
    if (cfg.absent) return null;
    // Only worth a row when the file mentions Mandu's plugin at all.
    let mentions = false;
    try { mentions = readFileSync(cfg.path, "utf8").includes("mandu-inspect"); } catch { /* unreadable */ }
    return mentions ? { configPath: cfg.path, unreadable: cfg.error } : null;
  }
  const session = attachedSession(cfg.effective);
  const service = session !== null ? await readServiceProxy(env, session, deps) : undefined;
  const serviceUrl = service?.ok ? service.url : null;
  // The routes the install recorded (Route 1): every routed provider is
  // judged, as the service's route check judges it.
  const d = session !== null ? readDeclaredList(env).attachments.find((a) => a.session === session) : undefined;
  const routes = d?.providers !== undefined ? { providers: d.providers, unprotected: d.unprotected ?? [], ...(d.allowlist !== undefined ? { allowlist: d.allowlist } : {}) } : undefined;
  // The Gateway's environment, while an Azure OpenAI provider is routed
  // (model-wires.md §9.1): the doctor says what the route check says.
  const azure = (routes?.providers ?? []).some((p) => p.wire === "azure-openai-responses");
  const gatewayEnv = azure ? (deps.gatewayEnv ?? gatewayAzureEnv)(cfg.path, env) : undefined;
  const state = attachState(cfg.effective, { pluginDir: deps.pluginDir, serviceUrl, ...(routes ? { routes } : {}), ...(gatewayEnv ? { gatewayEnv } : {}) });
  if (!looksAttached(state)) return null;
  const agentId = normalizeAgentId(String(pluginEntryConfig(cfg.effective)?.["agentId"] ?? "main"));
  const sandbox = session !== null ? sandboxFacts(env, cfg.effective, session, agentId, d?.sandbox) : undefined;
  return {
    configPath: cfg.path, ...(session !== null ? { session } : {}), state, verdict: routeVerdict(state, serviceUrl), ...(service ? { service } : {}),
    ...((d?.unprotected ?? []).length > 0 ? { unprotected: d!.unprotected! } : {}),
    ...(sandbox !== undefined ? { sandbox } : {}),
  };
}

/** Is the Mandu plugin installed, enabled and in attachment mode in the
 *  user's openclaw.json? Synchronous, for the launch refusal's wording
 *  (openclaw-argv.ts); any read failure is "no". */
export function openclawAttachmentInstalled(env: Env): boolean {
  const cfg = readConfig(env);
  if ("error" in cfg) return false;
  const s = attachState(cfg.effective, { serviceUrl: null });
  return s.plugin === "enabled" && s.attachment;
}

/** The doctor's default gatherer (real I/O). */
export function realOpenclawAttachFacts(layout: Layout): (env: Env) => Promise<OpenclawAttachFacts | null> {
  return (env) => gatherOpenclawAttach(env, realAttachDeps(layout));
}

/** `mandu openclaw install|uninstall` is a Mandu verb, not an OpenClaw launch:
 *  the verb, or null for any other argv. */
export function openclawAttachVerb(argv: readonly string[], cmdIdx: number): "install" | "uninstall" | null {
  if (argv[cmdIdx] !== "openclaw") return null;
  const v = argv[cmdIdx + 1];
  return v === "install" || v === "uninstall" ? v : null;
}

