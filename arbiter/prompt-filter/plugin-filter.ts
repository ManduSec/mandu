/**
 * plugin-filter — an out-of-process prompt filter plugin as a filter
 * (confidentiality-plan-15-prompt-filter.md §4.3, §5, §12 2026-10-03).
 * Mandu-new (no reference origin).
 *
 * A plugin pack (packs.ts) becomes a `PluginFilter`. Each scan:
 *
 *   1. resolves the classifier's endpoint when the plugin needs one: the
 *      policy's `endpoint:` must name a `local: true`, not cloud-backed
 *      `models:` entry (`resolveLocalEndpoint`, again at every spawn; §5);
 *   2. checks the pins (the program, the script, every module) and runs the
 *      verified private copy (plugin-pin.ts), which may read its copies and
 *      the system roots only;
 *   3. runs it under the confinement the probe found (plugin-confine.ts):
 *      no run without the network guard;
 *   4. writes ONE request on stdin, reads at most 1 MiB of stdout, discards
 *      stderr, and kills the process group at the deadline (the pack's
 *      `deadline_ms`, default 5 s): a timeout is an error;
 *   5. checks the answer against the closed shape (plugin-protocol.ts).
 *
 * Every failure THROWS: the engine applies the filter's `on_error` (§4.4;
 * the default `block` whenever a category it may report enforces). The
 * engine batches a request's uncached segments into one run (`scanMany`).
 * At most `MAX_CONCURRENT_RUNS` runs of one plugin at a time; later ones
 * wait their turn (the wait is not the plugin's deadline).
 *
 * The stats (`PluginStats`: runs, errors, the last latency and error, the
 * legs it ran under) are the panel's (§8.1); they never hold a prompt.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";

import type { ModelEndpoint } from "../policy/compiled-policy.js";
import { resolveLocalEndpoint } from "../policy/policy-model.js";
import type { FilterContext, PromptFilter, ScanResult } from "./filter.js";
import type { LoadedPromptPack, PluginCategory, PluginSpec } from "./packs.js";
import { endpointAllowSpecs, planPluginArgv, pluginEnv, type ConfineLegs, type ConfineTools } from "./plugin-confine.js";
import type { PluginPins } from "./plugin-pin.js";
import { buildPluginRequest, MAX_PLUGIN_ANSWER_BYTES, parsePluginAnswer, type PluginEndpoint, type PluginSegment } from "./plugin-protocol.js";

export const MAX_CONCURRENT_RUNS = 2;

/** What the panel shows of one plugin (§8.1); never a prompt. */
export interface PluginStats {
  runs: number;
  errors: number;
  /** The last run's wall time (ms), success or failure. */
  lastMs?: number;
  lastAt?: string;
  /** The last error, one line (never a segment's text). */
  lastError?: string;
  lastErrorAt?: string;
  /** The endpoint the last run used. */
  lastEndpoint?: string;
}

/** One run of the composed argv: `input` on stdin, stdout back. Never
 *  rejects. */
export type PluginProcessRunner = (argv: readonly string[], input: string, opts: { env: NodeJS.ProcessEnv; cwd: string; timeoutMs: number }) =>
  Promise<{ code: number | null; signal: NodeJS.Signals | null; stdout: string; timedOut: boolean; overflow: boolean }>;

export interface PluginFilterDeps {
  pins: PluginPins;
  /** The confinement legs (probed once, memoized by the caller). */
  legs: () => Promise<ConfineLegs>;
  tools: ConfineTools;
  /** The declared models in force (for the endpoint, at every spawn). */
  models: () => readonly ModelEndpoint[];
  /** The arbiter's private directory for scratch directories. */
  scratchRoot: string;
  /** The stats of this plugin (kept across pack reloads by the caller). */
  stats: PluginStats;
  hostEnv?: NodeJS.ProcessEnv;
  run?: PluginProcessRunner;
  now?: () => number;
}

/** The production runner: spawn detached (a new session and process
 *  group), write stdin, keep at most 1 MiB of stdout, discard stderr, kill
 *  the group at the deadline. */
export const spawnPlugin: PluginProcessRunner = (argv, input, opts) => new Promise((resolve) => {
  let stdout = "";
  let timedOut = false;
  let overflow = false;
  let settled = false;
  let child: ChildProcess;
  try {
    child = spawn(argv[0]!, argv.slice(1), { stdio: ["pipe", "pipe", "ignore"], env: opts.env, cwd: opts.cwd, detached: true });
  } catch {
    resolve({ code: null, signal: null, stdout: "", timedOut: false, overflow: false });
    return;
  }
  const kill = (): void => { try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch { try { child.kill("SIGKILL"); } catch { /* gone */ } } };
  const timer = setTimeout(() => { timedOut = true; kill(); }, opts.timeoutMs);
  timer.unref?.();
  child.stdout!.setEncoding("utf8");
  child.stdout!.on("data", (c: string) => {
    if (overflow) return;
    stdout += c;
    if (stdout.length > MAX_PLUGIN_ANSWER_BYTES) { overflow = true; stdout = ""; kill(); }
  });
  const done = (code: number | null, signal: NodeJS.Signals | null): void => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    // The whole group goes, even when its leader exited first.
    kill();
    resolve({ code, signal, stdout, timedOut, overflow });
  };
  child.on("error", () => done(null, null));
  child.on("close", (code, signal) => done(code, signal));
  child.stdin!.on("error", () => { /* the child exited early */ });
  child.stdin!.end(input);
});

/** A plugin's failure, one line, never with a prompt in it. */
export class PluginRunError extends Error {}

export class PluginFilter implements PromptFilter {
  readonly id: string;
  readonly cost: "inline" | "model";
  readonly categories: readonly string[];
  readonly spec: PluginSpec;
  private readonly declared: readonly PluginCategory[];
  private active = 0;
  private readonly waiting: Array<() => void> = [];

  constructor(readonly pack: LoadedPromptPack, private readonly deps: PluginFilterDeps) {
    if (!pack.doc.plugin) throw new Error(`pack ${pack.doc.pack} is not a plugin pack`);
    this.id = pack.doc.pack;
    this.spec = pack.doc.plugin;
    this.cost = this.spec.cost;
    this.declared = pack.doc.categories ?? [];
    this.categories = this.declared.map((c) => c.category);
  }

  async scan(text: string, ctx: FilterContext): Promise<ScanResult> {
    const r = await this.scanMany([{ id: "s", origin: ctx.origin, text }], ctx);
    return r.get("s")!;
  }

  /** One run over several segments; throws on any failure. */
  async scanMany(segments: readonly PluginSegment[], ctx: Pick<FilterContext, "endpoint">): Promise<Map<string, ScanResult>> {
    const now = this.deps.now ?? Date.now;
    await this.slot();
    const t0 = now();
    const stats = this.deps.stats;
    try {
      const out = await this.runOnce(segments, ctx.endpoint);
      stats.runs++;
      stats.lastMs = now() - t0;
      stats.lastAt = new Date(now()).toISOString();
      return out;
    } catch (err) {
      stats.runs++;
      stats.errors++;
      stats.lastMs = now() - t0;
      stats.lastAt = new Date(now()).toISOString();
      stats.lastError = String((err as Error)?.message ?? err).split("\n")[0]!.slice(0, 300);
      stats.lastErrorAt = stats.lastAt;
      throw err;
    } finally {
      this.release();
    }
  }

  private async slot(): Promise<void> {
    if (this.active < MAX_CONCURRENT_RUNS) { this.active++; return; }
    await new Promise<void>((r) => this.waiting.push(r));
    this.active++;
  }

  private release(): void {
    this.active--;
    const next = this.waiting.shift();
    if (next) next();
  }

  /** The endpoint this run may use (§5), checked now. */
  private endpoint(name: string | undefined): { entry: ModelEndpoint; allow: string[] } | null {
    if (this.spec.endpoint === "none") {
      if (name !== undefined) throw new PluginRunError(`it uses no model, but the policy names one (${name}); remove endpoint: from its switch`);
      return null;
    }
    if (name === undefined) throw new PluginRunError("it needs a model, and the policy names none (endpoint: in its switch)");
    const r = resolveLocalEndpoint(name, this.deps.models());
    if (!r.ok) throw new PluginRunError(r.why);
    const a = endpointAllowSpecs(r.endpoint);
    if ("why" in a) throw new PluginRunError(`the model ${name}: ${a.why}`);
    return { entry: r.endpoint, allow: a.specs };
  }

  private async runOnce(segments: readonly PluginSegment[], endpointName: string | undefined): Promise<Map<string, ScanResult>> {
    const ep = this.endpoint(endpointName);
    this.deps.stats.lastEndpoint = ep?.entry.name;
    const legs = await this.deps.legs();
    if (!legs.guard || this.deps.tools.netGuard === null) {
      throw new PluginRunError(`the network guard (mandu-net-guard) is not available${legs.notes.length > 0 ? ` (${legs.notes[0]})` : ""}; a plugin runs only under it`);
    }
    let verified;
    try {
      verified = await this.deps.pins.verify(this.spec);
    } catch (err) {
      throw new PluginRunError(`its pin: ${(err as Error).message}`);
    }
    const scratch = mkdtempSync(join(this.deps.scratchRoot, "run-"));
    try {
      const target = [verified.exec, ...(verified.script ? [verified.script] : []), ...this.spec.args];
      const argv = planPluginArgv({
        legs, tools: this.deps.tools, allow: ep?.allow ?? [],
        readDirs: verified.copyDirs, scratch, target,
      });
      const endpoint: PluginEndpoint | undefined = ep
        ? { name: ep.entry.name, url: ep.entry.url, wire: ep.entry.wire, ...(ep.entry.model ? { model: ep.entry.model } : {}), ...(ep.entry.tokenEnv ? { tokenEnv: ep.entry.tokenEnv } : {}) }
        : undefined;
      const req = buildPluginRequest({ filter: this.id, segments, categories: this.declared, deadlineMs: this.spec.deadlineMs, ...(endpoint ? { endpoint } : {}) });
      const env = pluginEnv({ scratch, hostEnv: this.deps.hostEnv ?? process.env, ...(ep ? { endpointUrl: ep.entry.url, ...(ep.entry.tokenEnv ? { tokenEnv: ep.entry.tokenEnv } : {}) } : {}) });
      const res = await (this.deps.run ?? spawnPlugin)(argv, JSON.stringify(req), { env, cwd: scratch, timeoutMs: this.spec.deadlineMs });
      if (res.timedOut) throw new PluginRunError(`it did not answer within ${this.spec.deadlineMs} ms`);
      if (res.overflow) throw new PluginRunError(`its answer is larger than ${MAX_PLUGIN_ANSWER_BYTES} bytes`);
      if (res.code !== 0) throw new PluginRunError(`it exited ${res.code === null ? `on ${res.signal ?? "a spawn failure"}` : `with ${res.code}`}`);
      const parsed = parsePluginAnswer(res.stdout, req, this.declared);
      if (!parsed.ok) throw new PluginRunError(parsed.why);
      const out = new Map<string, ScanResult>();
      for (const s of segments) out.set(s.id, { findings: parsed.findings.get(s.id) ?? [], skipped: 0 });
      return out;
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  }
}
