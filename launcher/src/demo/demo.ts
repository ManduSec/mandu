/**
 * demo — `mandu demo`: about thirty seconds that show the default protection
 * working, with Claude Code and with Codex (release checklist d2;
 * docs/design/distribution/mandu-demo.md).
 *
 * Three scenes per agent, run through the REAL defense, each on that agent's
 * own wire:
 *   1. the agent reads `.env`: the AI gets the key only as a placeholder, and
 *      YOU see the real value (the model proxy, then the reply filter);
 *   2. the agent USES the key: a curl to the host the key is bound to leaves
 *      with the real value filled in (the egress proxy, TLS inspection, the
 *      arbiter's egress gate and its human-plane resolve);
 *   3. the agent tries to send the key to another host: the request is
 *      refused before anything leaves, and an Approvals row is raised for
 *      the human (the same gate).
 * The demo plays each agent's part only: it sends the agent's requests, runs
 * the tool calls the model answers with (a Read of `.env`, or the shell
 * commands, under `sh` in the agent's view of the project, inside the real
 * whole-agent guard where this host has it, guard.ts), and sends the
 * results back. Every check reads the real components' own output: the
 * request bodies the stand-in model captured, the bytes the stand-in sites
 * received, the arbiter's approval queue, the reply filter's output. Exit 0
 * only when all of them hold; exit 1 otherwise.
 *
 * Offline and keyless by construction: the model is a stand-in on 127.0.0.1
 * (stand-in-model.ts), the two web hosts are stand-in listeners on
 * 127.0.0.1 that the egress proxy's host routes dial instead of the internet,
 * with a catch-all for every other host (stand-in-sites.ts); no credential is
 * sent, and every service runs in a throwaway sandbox (sandbox.ts) with its
 * own HOME, symbol DB, event store, policy and runtime dir, pinned to
 * `secrets` mode. The services start through Layout.daemon and the
 * lifeline-carrying primitives, so the same code runs from source and from
 * the installed bundle (dist/*.mjs).
 *
 * Mandu-new (no reference origin).
 */
import { spawn, spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Layout } from "../services/layout.js";
import { realDeps, type DetachedHandle } from "../services/primitives.js";
import {
  basicAuth, BOUND_HOST, claudeAssistantMessage, claudeRequest, claudeToolResult, codexRequest,
  codexToolOutput, codexTurnItems, codexUserItem, envFileText, hideSymbols, KNOWN_COMMANDS, lastToolResultText,
  makeFakeSecrets, parseClaudeSse, parseCodexSse, policyYaml, PROMPTS, readRendering, sceneCommand, secretForms,
  symbolsIn, UNBOUND_HOST, type FakeSecrets, type ModelTurn, type SceneId, type ToolCall,
} from "./fixture.js";
import { createTeardownGuard } from "../teardown-signals.js";
import { HUMAN_SOCK_ENV, readArbiterHumanSock } from "../human-plane.js";
import { ndjsonCall } from "../secret-setup.js";
import { createSandbox, pickTempBase, sandboxEnv, type SandboxPaths } from "./sandbox.js";
import {
  agentExeOf, agentGuard, demoHumanPlaneDirs, findDemoGuard, guardedRun, guardServed, parseRunnerOutput, wholeFileWhy,
  type AgentGuard, type DemoGuardFind, type GuardAbsence,
} from "./guard.js";
import { startStandInModel, type StandInModel, type Wire } from "./stand-in-model.js";
import { opensslAvailable, routesYaml, startStandInSites, type StandInSites } from "./stand-in-sites.js";
import {
  agentHeading, compactLine, headerLines, pickStyle, sceneLines, serviceLine, summaryLines,
  type AgentId, type SceneView, type Style, type Summary,
} from "./render.js";

type Env = Record<string, string | undefined>;

export interface RunResult { code: number; stdout: string; stderr: string }

/** The slice of `process` the run's signal handling needs; tests pass a
 *  fake emitter. It also satisfies teardown-signals' SignalHost. */
export interface DemoSignalHost {
  on(sig: "SIGINT" | "SIGTERM", fn: () => void): unknown;
  off(sig: "SIGINT" | "SIGTERM", fn: () => void): unknown;
  readonly pid: number;
}

/** The line the first ^C during the demo's cleanup prints (stderr). Pure. */
export function demoSigintNote(pid: number): string {
  return (
    "mandu demo: cleaning up (stopping the demo's services, removing its sandbox); " +
    `^C is ignored until that is done. To end it now: kill ${pid}`
  );
}

/** A started background service: `stop` resolves once it has exited. */
export interface Started { stop: () => void | Promise<void> }

/** How long a stopped service gets to exit before its group is SIGKILLed. */
export const SERVICE_STOP_MS = 10_000;

/**
 * SIGTERM a service's process group and resolve once its process has exited
 * (SIGKILL the group after `ms`), so the sandbox is removed only after every
 * service is gone. A service still shutting down writes into the sandbox:
 * the arbiter appends to its event log, whose directory it re-creates when it
 * is missing, and checkpoints its symbol DB. A removal that raced it left the
 * sandbox behind (the launcher's component `demo.test.ts`, "the sandbox is
 * removed on a failed run too", on loaded CI guests, 2026-10-09; traced: the
 * arbiter appended events 15 ms before the removal began and exited 25 ms
 * after it ended).
 */
export async function stopAndWait(
  h: Pick<DetachedHandle, "pid" | "stop" | "exited">,
  ms: number = SERVICE_STOP_MS,
  o: { sleep?: (ms: number) => Promise<void>; now?: () => number; kill?: (pid: number, sig: NodeJS.Signals) => void } = {},
): Promise<void> {
  const sleep = o.sleep ?? ((d: number) => new Promise<void>((r) => setTimeout(r, d)));
  const now = o.now ?? Date.now;
  const kill = o.kill ?? ((pid: number, sig: NodeJS.Signals) => { process.kill(pid, sig); });
  h.stop();
  if (h.exited === undefined) return;
  const gone = (): boolean => h.exited!() !== null;
  let end = now() + ms;
  while (!gone() && now() < end) await sleep(20);
  if (gone() || h.pid === undefined) return;
  try { kill(-h.pid, "SIGKILL"); } catch { /* gone */ }
  end = now() + 2_000;
  while (!gone() && now() < end) await sleep(20);
}

export type DemoService = "arbiter" | "anthropic-proxy" | "openai-proxy" | "net-proxy";

/** Injectable I/O so the orchestration is unit-tested without real services. */
export interface DemoDeps {
  tmpBase: () => string;
  createSandbox: (base: string) => SandboxPaths;
  removeSandbox: (root: string) => void;
  writeFile: (path: string, text: string) => void;
  secrets: () => FakeSecrets;
  startModel: (project: string) => Promise<StandInModel>;
  /** The stand-in web hosts (null: not started, the network scenes skip). */
  startSites: (dir: string) => Promise<StandInSites>;
  /** curl and openssl on PATH (the network scenes need both). */
  tools: () => { curl: boolean; openssl: boolean };
  /** Start a background service (a Layout daemon) with `env`, logging to `log`. */
  startService: (name: DemoService, env: Record<string, string>, log: string) => Started;
  /** Resolve true once `path` exists (non-empty), false after `timeoutMs`. */
  waitForPath: (path: string, timeoutMs: number) => Promise<boolean>;
  readText: (path: string) => string | null;
  /** One arbiter op over its data socket. */
  arbiterCall: (sock: string, op: string, args: Record<string, unknown>) => Promise<unknown>;
  /** POST a model-API body to a proxy; the raw response. */
  postModel: (port: number, wire: Wire, body: string, session: string) => Promise<{ status: number; body: string }>;
  /** Run one program (`argv`) in `cwd` with `env`: a command the agent
   *  runs, `sh -c <command>`, or the same under the guard (guard.ts). */
  runCommand: (argv: string[], cwd: string, env: Record<string, string>) => Promise<RunResult>;
  /** The whole-agent guard, found as a launch finds it (guard.ts), or why
   *  there is none. */
  findGuard: () => DemoGuardFind;
  /** The agent stand-in's executable under the guard (its `agentExe`). */
  agentExe: () => string;
  /** Run the reply filter over `cat <replyFile>`, capturing its output. */
  runReplyFilter: (env: Record<string, string>, replyFile: string) => Promise<RunResult>;
  /** The arbiter's human-plane socket (its `hello`), which the reply filter
   *  and the egress proxy resolve over (arbiter-human-plane.md); null = none.
   *  Default: ask it. */
  readHumanSock?: (arbiterSock: string) => Promise<string | null>;
  now: () => number;
  out: (s: string) => void;
  style: Style;
  /** Signal handling during the run and its cleanup (default: `process`). */
  signals?: DemoSignalHost;
  /** Where the one ignored-^C line goes (default: stderr). */
  note?: (line: string) => void;
  /** The exit after a signal-driven cleanup (default: `process.exit`). */
  exit?: (code: number) => void;
}

const SERVICE_PKG: Record<DemoService, string> = {
  arbiter: "arbiter",
  "anthropic-proxy": join("interceptors", "anthropic-proxy"),
  "openai-proxy": join("interceptors", "openai-proxy"),
  "net-proxy": join("interceptors", "net-proxy"),
};

function commandRuns(cmd: string, args: string[]): boolean {
  try { return spawnSync(cmd, args, { stdio: "ignore", timeout: 5_000 }).status === 0; } catch { return false; }
}

export function realDemoDeps(layout: Layout, env: Env): DemoDeps {
  return {
    tmpBase: () => pickTempBase(tmpdir()),
    createSandbox,
    // Every service has exited by now (stopAndWait); the retries stay for
    // anything else still closing a file there.
    removeSandbox: (root) => rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }),
    writeFile: (path, text) => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, text, { mode: 0o600 }); },
    secrets: () => makeFakeSecrets(),
    startModel: startStandInModel,
    startSites: startStandInSites,
    tools: () => ({ curl: commandRuns("curl", ["--version"]), openssl: opensslAvailable() }),
    startService: (name, svcEnv, log) => {
      // The arbiter never imports its own IPC client (needsClient=false).
      const spec = layout.daemon(name, SERVICE_PKG[name], name !== "arbiter");
      const h = realDeps.startDetachedCmd(spec.cmd, spec.args, { cwd: spec.cwd, env: { ...svcEnv, ...spec.env } }, log);
      return { stop: () => stopAndWait(h) };
    },
    // The socket appears once the arbiter listens; a proxy publishes its
    // port file by an atomic rename; the egress CA is written whole. Either
    // way, a non-empty file is readiness.
    waitForPath: (path, timeoutMs) => realDeps.waitFor(() => {
      try { return existsSync(path) && (statSync(path).isSocket() || statSync(path).size > 0); } catch { return false; }
    }, { tries: Math.ceil(timeoutMs / 50), delayMs: 50 }),
    readText: (path) => { try { return readFileSync(path, "utf8"); } catch { return null; } },
    arbiterCall: (sock, op, args) => ndjsonCall(sock, op, args, 10_000),
    postModel,
    runCommand: (argv, cwd, cmdEnv) => capture(argv, cmdEnv, cwd),
    findGuard: () => findDemoGuard(process.platform, env),
    agentExe: () => agentExeOf(),
    runReplyFilter: (rfEnv, replyFile) => {
      const rf = layout.replyFilter();
      const argv = [...rf.tokens, "--mandu-output-format=text", "--", "cat", replyFile];
      return capture(argv, { ...rfEnv, ...rf.env });
    },
    now: () => Date.now(),
    out: (s) => { process.stdout.write(s); },
    style: pickStyle(process.stdout.isTTY === true, env),
  };
}

function postModel(port: number, wire: Wire, body: string, session: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1", port, method: "POST", path: wire === "anthropic" ? "/v1/messages" : "/v1/responses",
        // No credential of any kind: the stand-in needs none, and the demo
        // must not carry the user's.
        headers: {
          "content-type": "application/json",
          ...(wire === "anthropic" ? { "anthropic-version": "2023-06-01", "x-mandu-session-id": session } : {}),
        },
        timeout: 20_000,
      },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c: string) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("timeout", () => req.destroy(new Error("the model proxy did not answer within 20s")));
    req.on("error", reject);
    req.end(body);
  });
}

function capture(argv: string[], env: Record<string, string>, cwd?: string): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = spawn(argv[0]!, argv.slice(1), { env, cwd, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (c: string) => (stdout += c));
    child.stderr.setEncoding("utf8").on("data", (c: string) => (stderr += c));
    const timer = setTimeout(() => child.kill("SIGKILL"), 30_000);
    child.on("error", (e) => { clearTimeout(timer); resolve({ code: 127, stdout, stderr: stderr + String(e) }); });
    child.on("close", (code) => { clearTimeout(timer); resolve({ code: code ?? 1, stdout, stderr }); });
  });
}

const SERVICE_TIMEOUT_MS = 30_000;

/** The last lines of a service log, for a failed start. */
function logTail(deps: DemoDeps, path: string): string {
  const t = (deps.readText(path) ?? "").trim().split("\n").slice(-3).join(" / ");
  return t ? ` (log: ${t})` : "";
}

/** The `KEY=value` rows of a `.env` as the AI or the human saw it; any
 *  other non-comment rows when there are none (a whole-file placeholder). */
export function envRows(text: string): string[] {
  const rows = text.replace(/\r/g, "").split("\n").map((l) => l.trimEnd()).filter((l) => l !== "" && !l.startsWith("#"));
  const kv = rows.filter((l) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(l));
  return kv.length > 0 ? kv : rows;
}

/** The pending Approvals rows for the unbound host (arbiter `egressApprovals`). */
interface ApprovalRow { id: string; symbol: string; destination: string; status: string; count: number }

function approvalsFor(v: unknown): ApprovalRow[] {
  const rows = (v as { approvals?: unknown } | null)?.approvals;
  if (!Array.isArray(rows)) return [];
  return (rows as ApprovalRow[]).filter((r) => r && typeof r.destination === "string" && r.destination.split(":")[0] === UNBOUND_HOST);
}

/** One agent's conversation, on its own wire. */
class Conversation {
  private readonly history: unknown[] = [];
  constructor(readonly wire: Wire) {}
  prompt(text: string): void {
    this.history.push(this.wire === "anthropic" ? { role: "user", content: text } : codexUserItem(text));
  }
  turn(t: ModelTurn): void {
    if (this.wire === "anthropic") this.history.push(claudeAssistantMessage(t));
    else this.history.push(...codexTurnItems(t));
  }
  toolResult(call: ToolCall, text: string): void {
    this.history.push(this.wire === "anthropic" ? claudeToolResult(call.id, text) : codexToolOutput(call.id, text));
  }
  request(): string {
    return JSON.stringify(this.wire === "anthropic" ? claudeRequest(this.history) : codexRequest(this.history));
  }
  parse(sse: string): ModelTurn {
    return this.wire === "anthropic" ? parseClaudeSse(sse) : parseCodexSse(sse);
  }
}

const AGENT: Record<AgentId, { service: "anthropic-proxy" | "openai-proxy"; wire: Wire; session: string; portFile: (p: SandboxPaths) => string; proxyLabel: string }> = {
  claude: { service: "anthropic-proxy", wire: "anthropic", session: "mandu-demo-claude", portFile: (p) => p.claudeProxyPortFile, proxyLabel: "the model-API proxy for Claude Code (anthropic-proxy)" },
  codex: { service: "openai-proxy", wire: "openai", session: "mandu-demo-codex", portFile: (p) => p.codexProxyPortFile, proxyLabel: "the model-API proxy for Codex (openai-proxy)" },
};

/** The parsed command line. */
export interface DemoArgs { keep: boolean; verbose: boolean; agents: AgentId[] }

/** Parse `mandu demo` options; a string is the usage error. Pure. */
export function parseDemoArgs(rest: string[]): DemoArgs | string {
  let keep = false;
  let verbose = false;
  let agents: AgentId[] = ["claude", "codex"];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === "--keep") keep = true;
    else if (a === "--verbose" || a === "-v") verbose = true;
    else if (a === "--agent" || a.startsWith("--agent=")) {
      const v = a === "--agent" ? rest[++i] : a.slice("--agent=".length);
      if (v !== "claude" && v !== "codex") return `--agent takes claude or codex${v === undefined ? "" : `, not '${v}'`}`;
      agents = [v];
    } else return `unknown option '${a}'`;
  }
  return { keep, verbose, agents };
}

/** Everything one run shares across the agents. */
interface Ctx {
  deps: DemoDeps;
  p: SandboxPaths;
  denv: Record<string, string>;
  secrets: FakeSecrets;
  model: StandInModel;
  humanSock: string | null;
  /** The egress proxy's port and session CA; null = the network scenes skip. */
  net: { port: number; caCert: string; sites: StandInSites } | null;
  skipWhy: string | null;
  envPath: string;
  agentEnvPath: string;
  stops: Array<() => void | Promise<void>>;
  /** The whole-agent guard the agent's programs run under, or why not. */
  guard: DemoGuardFind;
  agentExe: string;
}

/** Fake values found in `text` (any form). */
function leaksIn(text: string, s: FakeSecrets): string[] {
  return secretForms(s).filter((v) => text.includes(v));
}

/** The environment a command the agent runs gets: the sandbox's, plus the
 *  session's egress proxy and its CA (what a launch sets for the agent). */
function commandEnv(ctx: Ctx): Record<string, string> {
  if (ctx.net === null) return ctx.denv;
  const proxy = `http://127.0.0.1:${ctx.net.port}`;
  return {
    ...ctx.denv,
    HTTPS_PROXY: proxy, https_proxy: proxy, HTTP_PROXY: proxy, http_proxy: proxy,
    NO_PROXY: "", no_proxy: "",
    CURL_CA_BUNDLE: ctx.net.caCert, SSL_CERT_FILE: ctx.net.caCert,
  };
}

/** What running one tool call gave: the tool result, and for a command its
 *  run and whether the guard served it. */
interface Executed { output: string; run?: RunResult; guarded?: boolean; guardLog?: string }

/** Run one tool call the model answered with, as the agent would: a Read
 *  of `.env` returns the agent's copy in Read's rendering; a shell command
 *  runs under `sh` in the agent's view of the project, inside the
 *  whole-agent guard when this machine has it (guard.ts), as a launch runs
 *  the agent's programs. Only the demo's own calls run: anything else fails
 *  the scene. */
async function executeCall(ctx: Ctx, agent: AgentId, scene: SceneId, call: ToolCall, ag: AgentGuard | null): Promise<Executed> {
  const expected = sceneCommand(scene);
  if (agent === "claude" && scene === 1) {
    if (call.name !== "Read" || call.filePath !== ctx.envPath) throw new Error(`the model asked for ${call.name}(${call.filePath ?? call.command ?? ""}), not a Read of .env`);
    return { output: readRendering(ctx.deps.readText(ctx.agentEnvPath) ?? "") };
  }
  const cmd = call.command ?? "";
  if (cmd !== expected || !KNOWN_COMMANDS.includes(cmd)) {
    throw new Error(`the agent was handed a command the demo did not expect: ${JSON.stringify(cmd.slice(0, 160))}`);
  }
  if (ag === null) {
    const run = await ctx.deps.runCommand(["sh", "-c", cmd], ctx.p.agentView, commandEnv(ctx));
    return { output: run.stdout + (run.stderr ? run.stderr : ""), run };
  }
  // Under the guard: its status file says whether it served the tree (a
  // kernel it cannot attach on runs the command unguarded, --skip-unsupported).
  const status = join(ctx.p.run, `net-guard-${agent}-${scene}.status`);
  const g = guardedRun(ag, ctx.agentExe, cmd, status, commandEnv(ctx));
  const raw = await ctx.deps.runCommand(g.argv, ctx.p.agentView, g.env);
  const run = parseRunnerOutput(raw.stdout);
  if (run === null) {
    const tail = raw.stderr.trim().split("\n").slice(-2).join(" / ");
    throw new Error(`the agent's command did not run under Mandu's guard (exit ${raw.code}${tail ? `: ${tail}` : ""})`);
  }
  return { output: run.stdout + run.stderr, run, guarded: guardServed(ctx.deps.readText(status)), guardLog: raw.stderr.trim() };
}

/** Why a command ran without the guard, when it did. */
function absenceOf(ctx: Ctx, ex: Executed): GuardAbsence | null {
  if ("absent" in ctx.guard) return ctx.guard.absent;
  return ex.guarded === false ? "kernel" : null;
}

/** One scene, start to finish, for one agent. */
async function runScene(ctx: Ctx, agent: AgentId, port: number, conv: Conversation, scene: SceneId, ag: AgentGuard | null): Promise<SceneView> {
  const { deps } = ctx;
  const v: SceneView = { scene, ok: false, verbose: [] };
  if (scene !== 1 && ctx.net === null) return { ...v, ok: true, skipped: ctx.skipWhy ?? "this step needs curl and openssl", verbose: [] };
  const before = ctx.model.bodies.length;
  const boundBefore = ctx.net?.sites.bound.received.length ?? 0;
  const unboundBefore = ctx.net?.sites.unbound.received.length ?? 0;
  const approvalsBefore = scene === 3 ? approvalsFor(await deps.arbiterCall(ctx.p.arbiterSock, "egressApprovals", { status: "pending" }).catch(() => null)) : [];

  const ask = async (): Promise<ModelTurn> => {
    const r = await deps.postModel(port, AGENT[agent].wire, conv.request(), AGENT[agent].session);
    if (r.status !== 200) throw new Error(`the model proxy answered ${r.status}: ${r.body.slice(0, 200)}`);
    return conv.parse(r.body);
  };
  conv.prompt(PROMPTS[scene]);
  const t1 = await ask();
  const call = t1.calls[0];
  if (call === undefined || t1.calls.length !== 1) throw new Error(`the model answered scene ${scene} with ${t1.calls.length} tool calls, not one`);
  const ex = await executeCall(ctx, agent, scene, call, ag);
  const { output, run } = ex;
  const absent = ex.run !== undefined ? absenceOf(ctx, ex) : null;
  conv.turn(t1);
  conv.toolResult(call, output);
  const t2 = await ask();
  conv.turn(t2);

  const bodies = ctx.model.bodies.slice(before);
  for (const b of bodies) {
    try { appendFileSync(ctx.p.modelRequests, JSON.stringify({ agent, scene, wire: b.wire, body: b.body }) + "\n", { mode: 0o600 }); } catch { /* evidence only */ }
  }
  const leaked = [...new Set(bodies.flatMap((b) => leaksIn(b.body, ctx.secrets)))];
  const bytes = bodies.reduce((n, b) => n + Buffer.byteLength(b.body, "utf8"), 0);
  v.verbose.push(`the model received ${bodies.length} requests (${bytes.toLocaleString("en-US")} bytes); ${leaked.length === 0 ? "none holds the key" : "THE KEY IS IN THEM"}`);
  const fails: string[] = [];
  if (ex.run !== undefined) {
    v.verbose.push(`ran: ${call.command ?? ""}`);
    v.verbose.push(absent === null
      ? "  under Mandu's guard (mandu-net-guard), which recorded the command's processes for the arbiter"
      : `  without Mandu's guard (${absent}${ex.guardLog ? `: ${ex.guardLog.split("\n").slice(-1)[0]!.slice(0, 120)}` : ""})`);
  }
  if (leaked.length > 0) fails.push("the AI received the real key");
  if (bodies.length === 0) fails.push("the model received nothing");

  if (scene === 1) {
    // What the AI got: the tool result as the model proxy forwarded it.
    const seen = lastToolResultText(bodies[bodies.length - 1]?.body ?? "") ?? "";
    const placeholder = symbolsIn(seen)[0] ?? null;
    v.aiGot = envRows(hideSymbols(seen));
    // A whole-file placeholder (no keys shown): say what it stands for, and,
    // for a shell read, why. The arbiter shows a shell result per key only
    // on the guard's record of the call's processes (plan 10 §11.8): without
    // the guard the whole file is the right answer, and the screen says so;
    // under the guard it is a failed check (the demo shows the real thing).
    if (v.aiGot.length === 1 && v.aiGot[0] === "‹hidden›") {
      v.aiGot = ["‹hidden› (the whole file)"];
      v.wholeFile = true;
      if (absent !== null) v.aiGot.push(wholeFileWhy(absent));
      else if (ex.guarded === true) fails.push("the AI got the whole file, not each key, under Mandu's guard");
    }
    const note = seen.split("\n").find((l) => l.startsWith("[mandu:"));
    if (note) v.verbose.push(`Mandu's note to the model: ${note.slice(0, 120)}…`);
    if (placeholder) v.verbose.unshift(`the AI's placeholder: ${placeholder}`);
    else fails.push("the AI was not given a placeholder for the key");
    // What you see: the model's reply, through the reply filter.
    deps.writeFile(ctx.p.replyFile, t2.text + "\n");
    const rf = await deps.runReplyFilter({
      ...ctx.denv, MANDU_REPLY_FILTER_PTY: "0", MANDU_SCOPE_ID: "mandu-demo",
      ...(ctx.humanSock ? { [HUMAN_SOCK_ENV]: ctx.humanSock } : {}),
    }, ctx.p.replyFile);
    if (rf.code !== 0) throw new Error(`the reply filter exited ${rf.code}: ${rf.stderr.trim().split("\n").slice(-2).join(" / ")}`);
    v.youSee = envRows(rf.stdout);
    v.verbose.push(`the model's reply, as it left the model: ${JSON.stringify(t2.text.split("\n").slice(1).join(" | "))}`);
    if (!rf.stdout.includes(ctx.secrets.stripeKey)) fails.push("your screen did not show the real key");
  } else if (scene === 2) {
    const got = ctx.net!.sites.bound.received.slice(boundBefore);
    const want = basicAuth(ctx.secrets.stripeKey);
    const auth = got.map((g) => /\r\nauthorization:\s*([^\r\n]*)/i.exec(g.head)?.[1] ?? "");
    v.verbose.push(`${BOUND_HOST} received ${got.length} request(s): ${auth.map((a) => `Authorization: ${a}`).join(", ") || "no Authorization"}`);
    v.verbose.push(`curl printed: ${(run?.stdout ?? "").trim().slice(0, 120)}`);
    if (got.length === 0) fails.push(`${BOUND_HOST} received nothing`);
    else if (!auth.every((a) => a === want)) fails.push(`${BOUND_HOST} did not receive the real key exactly`);
    if (got.some((g) => g.head.includes("$MDU:") || g.body.includes("$MDU:"))) fails.push(`${BOUND_HOST} received a placeholder`);
  } else {
    const got = ctx.net!.sites.unbound.received.slice(unboundBefore);
    const said = (run?.stdout ?? "").trim();
    const reason = /"message":"([^"]*)"/.exec(said)?.[1];
    v.verbose.push(`the request was answered on this machine: ${reason ?? said.slice(0, 120)}`);
    if (got.length > 0) fails.push(`${UNBOUND_HOST} received the request`);
    const after = approvalsFor(await deps.arbiterCall(ctx.p.arbiterSock, "egressApprovals", { status: "pending" }).catch(() => null));
    const raised = after.find((r) => {
      const was = approvalsBefore.find((b) => b.id === r.id);
      return r.symbol.startsWith("$MDU:") && (was === undefined || r.count > was.count);
    });
    if (raised) v.verbose.push(`Approvals row ${raised.id}: ${raised.symbol} → ${raised.destination}, pending, asked ${raised.count} time(s)`);
    else fails.push("no approval was raised for you");
  }
  v.ok = fails.length === 0;
  if (!v.ok) v.why = fails.join("; ");
  return v;
}

/** Start one agent's model proxy and run its three scenes. */
async function runAgent(ctx: Ctx, agent: AgentId, verbose: boolean, onScene: (v: SceneView) => void): Promise<SceneView[]> {
  const { deps, p } = ctx;
  const a = AGENT[agent];
  const t0 = deps.now();
  const log = join(p.run, `${a.service}.log`);
  const portFile = a.portFile(p);
  ctx.stops.push(deps.startService(a.service, {
    ...ctx.denv,
    MANDU_PROXY_HOST: "127.0.0.1",
    MANDU_PROXY_PORT: "0",
    MANDU_PORT_FILE: portFile,
    MANDU_UPSTREAM: ctx.model.origin,
    MANDU_SESSION_KEY: a.session,
    ...(ctx.humanSock ? { [HUMAN_SOCK_ENV]: ctx.humanSock } : {}),
  }, log).stop);
  if (!(await deps.waitForPath(portFile, SERVICE_TIMEOUT_MS))) throw new Error(`${a.proxyLabel} did not start${logTail(deps, log)}`);
  const port = Number((deps.readText(portFile) ?? "").trim());
  if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error(`${a.proxyLabel} published no usable port`);
  if (verbose) deps.out(serviceLine(a.proxyLabel, deps.now() - t0, deps.style) + "\n");
  // The guard around this agent's programs, as a launch puts it around the
  // agent: its policy names the agent, the agent's session (the one its
  // model proxy files calls under) and the registered `.env`.
  let ag: AgentGuard | null = null;
  if ("bin" in ctx.guard) {
    const policyPath = join(p.run, `guard-policy-${agent}.json`);
    ag = agentGuard({
      bin: ctx.guard.bin, agent, agentExe: ctx.agentExe, session: a.session, policyPath,
      modelProxyPort: port, netProxyPort: ctx.net?.port ?? null, envPath: ctx.envPath, agentEnvPath: ctx.agentEnvPath,
      // The launch's human-plane wall (run.ts: humanPlaneDirs, then
      // applyHumanPlaneDeny), which the guard also checks the human socket
      // against before it believes it (arbiter-human-plane.md §5.2).
      humanPlaneDirs: demoHumanPlaneDirs(ctx.humanSock, ctx.denv["MANDU_RUNTIME_DIR"]),
    });
    deps.writeFile(policyPath, ag.policy);
  }
  const conv = new Conversation(a.wire);
  const views: SceneView[] = [];
  for (const scene of [1, 2, 3] as SceneId[]) {
    const t = deps.now();
    const v = await runScene(ctx, agent, port, conv, scene, ag);
    if (verbose) v.verbose.push(`took ${((deps.now() - t) / 1000).toFixed(1)}s`);
    views.push(v);
    onScene(v);
  }
  return views;
}

export async function runDemo(rest: string[], env: Env, layout: Layout, deps: DemoDeps = realDemoDeps(layout, env)): Promise<number> {
  const args = parseDemoArgs(rest);
  if (typeof args === "string") {
    process.stderr.write(`mandu demo: ${args} (see mandu demo --help)\n`);
    return 2;
  }
  const { keep, verbose } = args;
  const st = deps.style;
  const out = (lines: string[]): void => deps.out(lines.map((l) => l + "\n").join(""));

  const p = deps.createSandbox(deps.tmpBase());
  const stops: Array<() => void | Promise<void>> = [];
  // ^C-safe cleanup (mandu-demo.md §3 "Signals", the launcher's teardown guard in
  // teardown-signals.ts). During the run a SIGINT or SIGTERM aborts it: stop
  // the services, remove the sandbox, exit 130. Once cleanup starts, from that
  // abort or from the normal end, SIGINT is IGNORED (one plain line on the
  // first press) and SIGTERM keeps its default action. The guard is armed
  // BEFORE the run-time handler comes off, so SIGINT never has its default
  // action in between: without a handler a ^C mid-cleanup (say, inside the
  // synchronous sandbox removal) killed the demo and left the sandbox behind.
  const signals: DemoSignalHost = deps.signals ?? process;
  const note = deps.note ?? ((line: string): void => { process.stderr.write(line + "\n"); });
  const exit = deps.exit ?? ((code: number): void => process.exit(code));
  const guard = createTeardownGuard({ host: signals, note: () => note(demoSigintNote(signals.pid)) });
  let cleaning = false;
  const beginCleanup = (): void => {
    cleaning = true;
    guard.arm();
    signals.off("SIGINT", onSignal);
    signals.off("SIGTERM", onSignal);
  };
  const onSignal = (): void => {
    if (cleaning) return;
    beginCleanup();
    for (const s of stops.reverse()) { try { void s(); } catch { /* best effort */ } }
    if (!keep) { try { deps.removeSandbox(p.root); } catch { /* best effort */ } }
    exit(130);
  };
  signals.on("SIGINT", onSignal);
  signals.on("SIGTERM", onSignal);

  const summary: Summary = { ok: false, failures: [], skippedNetwork: false };
  const results: Array<{ agent: AgentId; views: SceneView[] }> = [];
  try {
    out(headerLines(st));
    const secrets = deps.secrets();
    const envPath = join(p.project, ".env");
    deps.writeFile(envPath, envFileText(secrets));
    const denv = sandboxEnv(env, p);
    // The sandbox's own policy: `.env` is a secret bound to the Stripe API.
    deps.writeFile(denv["MANDU_POLICY_FILE"]!, policyYaml(envPath));

    const model = await deps.startModel(p.project);
    stops.push(() => model.close());

    // The arbiter: symbol table + policy, pinned to `secrets` mode.
    let t0 = deps.now();
    const arbiterLog = join(p.run, "arbiter.log");
    stops.push(deps.startService("arbiter", denv, arbiterLog).stop);
    if (!(await deps.waitForPath(p.arbiterSock, SERVICE_TIMEOUT_MS))) {
      throw new Error(`the protection service (arbiter) did not start${logTail(deps, arbiterLog)}`);
    }
    // The human plane: the reply filter and the egress proxy resolve over
    // it, as a launch wires them (human-plane.ts), never the data socket.
    const humanSock = await (deps.readHumanSock ?? readArbiterHumanSock)(p.arbiterSock);
    if (verbose) out([serviceLine("the protection service (arbiter)", deps.now() - t0, st)]);

    // The agent's copy of .env, as a launch makes it (secret-twins): the
    // arbiter registers the file and answers its placeholder copy.
    const reg = await deps.arbiterCall(p.arbiterSock, "registerSecret", { path: envPath, home: p.home }) as { symbol?: string | null; twin?: string; reason?: string } | null;
    if (!reg?.twin) throw new Error(`Mandu made no placeholder copy of .env (${reg?.reason ?? "no answer"})`);
    const agentEnvPath = join(p.agentView, ".env");
    deps.writeFile(agentEnvPath, reg.twin);
    if (verbose) out([st.dim(`  · .env registered as ${reg.symbol ?? "?"}; the agent's copy holds placeholders`)]);

    // The egress proxy, with TLS inspection, routed to the stand-in sites.
    const tools = deps.tools();
    let net: Ctx["net"] = null;
    let skipWhy: string | null = null;
    if (!tools.curl || !tools.openssl) {
      skipWhy = `this step needs ${[!tools.curl ? "curl" : "", !tools.openssl ? "openssl" : ""].filter(Boolean).join(" and ")}, not found`;
      summary.skippedNetwork = true;
    } else {
      t0 = deps.now();
      const sites = await deps.startSites(p.sitesDir);
      stops.push(() => sites.close());
      deps.writeFile(p.routesFile, routesYaml(sites));
      const netLog = join(p.run, "net-proxy.log");
      stops.push(deps.startService("net-proxy", {
        ...denv,
        MANDU_NET_PROXY_HOST: "127.0.0.1",
        MANDU_NET_PROXY_PORT: "0",
        MANDU_PORT_FILE: p.netProxyPortFile,
        MANDU_SESSION_KEY: "mandu-demo",
        MANDU_NET_PROXY_MITM: "1",
        MANDU_NET_PROXY_MITM_CA_DIR: p.mitmCaDir,
        MANDU_NET_PROXY_MOCK_SITES: p.routesFile,
        ...(humanSock ? { [HUMAN_SOCK_ENV]: humanSock } : {}),
      }, netLog).stop);
      const caCert = join(p.mitmCaDir, "mandu-egress-ca.pem");
      if (!(await deps.waitForPath(p.netProxyPortFile, SERVICE_TIMEOUT_MS)) || !(await deps.waitForPath(caCert, SERVICE_TIMEOUT_MS))) {
        throw new Error(`the egress proxy (net-proxy) did not start${logTail(deps, netLog)}`);
      }
      const port = Number((deps.readText(p.netProxyPortFile) ?? "").trim());
      if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error("the egress proxy published no usable port");
      net = { port, caCert, sites };
      if (verbose) out([serviceLine("the egress proxy with TLS inspection (net-proxy), routed to the stand-in sites", deps.now() - t0, st)]);
    }
    // The whole-agent guard the agent's programs run under (guard.ts).
    const guard = deps.findGuard();
    if (verbose) {
      out([st.dim("bin" in guard
        ? `  · Mandu's guard (mandu-net-guard) runs around the agent's commands: ${guard.bin}`
        : `  · no guard around the agent's commands (${guard.absent}): a shell read of .env is hidden whole`)]);
      if ("bin" in guard && guard.stale) out([st.dim(`  · ${guard.stale}`)]);
    }
    if (verbose) out([""]);

    const ctx: Ctx = { deps, p, denv, secrets, model, humanSock, net, skipWhy, envPath, agentEnvPath, stops, guard, agentExe: deps.agentExe() };
    for (const [i, agent] of args.agents.entries()) {
      // The first agent prints each scene as it completes; a second one,
      // when it passes, folds into one line (it is the same three steps).
      // Not when it got .env whole (no guard here): that step was not the
      // same, and the full lines say why.
      const compact = i > 0 && !verbose;
      const buffered: string[] = [];
      if (!compact) out([agentHeading(agent, st)]);
      const views = await runAgent(ctx, agent, verbose, (v) => {
        const lines = sceneLines(v, st, verbose);
        if (compact) buffered.push(...lines);
        else out(lines);
      });
      if (compact) {
        if (views.every((v) => v.ok && v.wholeFile !== true)) out([agentHeading(agent, st), compactLine(agent, views, st)]);
        else out([agentHeading(agent, st), ...buffered]);
      }
      results.push({ agent, views });
    }
    // Nothing the demo did reached any host but the two it names.
    if (net !== null && net.sites.elsewhere.received.length > 0) summary.failures.push("a request reached a host outside the demo");
    for (const r of results) {
      for (const v of r.views) if (!v.ok) summary.failures.push(`${r.agent === "claude" ? "Claude Code" : "Codex"} step ${v.scene}: ${v.why}`);
    }
    summary.ok = summary.failures.length === 0;
    out([""]);
  } catch (e) {
    summary.ok = false;
    summary.error = (e as Error).message;
  } finally {
    beginCleanup();
    for (const s of stops.reverse()) { try { await s(); } catch { /* best effort */ } }
    if (keep) deps.out(st.dim(`  (kept the sandbox: ${p.root})`) + "\n");
    else {
      try { deps.removeSandbox(p.root); } catch (e) {
        deps.out(st.dim(`  (could not remove the sandbox ${p.root}: ${(e as Error).message})`) + "\n");
      }
    }
  }
  // Disarm last: the sandbox is gone and the caller exits right after.
  try { out(summaryLines(summary, st)); } finally { guard.disarm(); }
  return summary.ok ? 0 : 1;
}
