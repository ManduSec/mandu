/**
 * serve-attachments — the launcher's side of `mandu serve`'s proxy pool
 * (docs/design/agents/openclaw-plugin.md §3.2): `mandu serve attach|detach
 * openclaw` (the declared-attachments file the pool reads), the facts
 * `mandu serve status` and `mandu doctor` show for each attachment (its
 * proxy's port and health, its registration, its posture), and the service
 * proxy reader `mandu openclaw install` adopts a port through.
 *
 * The pool itself runs in the service's main process
 * (dashboard/src/supervisor/attachment-pool.ts); the two agree through
 * attachment-contract.ts. Every effect here is injectable (`AttachmentDeps`).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { lstatSync, mkdirSync, readFileSync } from "node:fs";
import { createServer } from "node:net";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";

import { assertRuntimeBaseTrusted, resolveArbiterSock, runtimeBase } from "./arbiter-sock.js";
import {
  anthropicProxyPortFile,
  attachmentDir,
  POOL_RECORD_FILE,
  attachmentSession,
  declareAttachment,
  identityProblem,
  normalizeAgentId,
  parseDeclared,
  parsePortFile,
  parseRouteRecord,
  poolRecordProvidersKey,
  restoreDeclared,
  ROUTE_FIX,
  routeLostOf,
  poolMarkerFile,
  poolRecordPid,
  portFileProblem,
  renderDeclared,
  serviceProxyUrl,
  undeclareAttachment,
  withDeclaredSandbox,
  parseSandboxRecord,
  sandboxLostLines,
  type SandboxRecord,
  type DeclaredAttachment,
  type DeclaredProvider,
  type DeclaredRoutes,
  type DeclaredSandbox,
  type RouteRecord,
  type ServiceIdentity,
} from "./attachment-contract.js";
import { attachmentCoverage, postureSentence, resolvePosture } from "./confinement-posture.js";
import { manduPath } from "./generated/mandu-paths.js";
import { attachmentWords, parseHumanPlaneStatus } from "./human-plane-watch.js";
import { publishFile } from "./safe-file.js";
import { ndjsonCall } from "./secret-setup.js";

type Env = Record<string, string | undefined>;

// ── The declared file ───────────────────────────────────────────────────────

/** Where the declared attachments are kept (the path table's `serve-attachments`). */
export function declaredFilePath(env: Env): string {
  return manduPath("serve-attachments", env, env["HOME"] || homedir());
}

/** The declared attachments (an unreadable file is none, with its problem). */
export function readDeclaredList(env: Env): { path: string; attachments: DeclaredAttachment[]; problems: string[] } {
  const path = declaredFilePath(env);
  let text: string | null = null;
  try { text = readFileSync(path, "utf8"); } catch { /* none */ }
  return { path, ...parseDeclared(text) };
}

/** Write the declared attachments whole (0600, never through a link), making
 *  the Mandu home's state folder 0700 when it is absent. */
export function writeDeclaredList(env: Env, list: readonly DeclaredAttachment[]): string {
  const path = declaredFilePath(env);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  publishFile(path, renderDeclared(list), { mode: 0o600 });
  return path;
}

/** A port nothing listens on now (the kernel's pick on 127.0.0.1). */
export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
  });
}

/** Declare `agentId`'s session (idempotent): the entry, whether it was added,
 *  what it was before (null: not declared), and the file. A new entry gets
 *  `port`, else a free port now; `routes` (Route 1) replace the entry's. */
export async function ensureDeclared(
  env: Env,
  agentId: string,
  port: number | null = null,
  routes?: DeclaredRoutes,
): Promise<{ entry: DeclaredAttachment; added: boolean; changed: boolean; path: string; before: DeclaredAttachment | null }> {
  const cur = readDeclaredList(env);
  const session = attachmentSession(agentId);
  const before = cur.attachments.find((a) => a.session === session) ?? null;
  const want = port ?? (before !== null ? null : await freePort());
  const r = declareAttachment(cur.attachments, agentId, want, undefined, routes);
  const path = r.changed ? writeDeclaredList(env, r.list) : cur.path;
  return { entry: r.entry, added: before === null, changed: r.changed, path, before };
}

/** Put a session's declaration back as it was (`entry`; null: undeclared). */
export function restoreDeclaredEntry(env: Env, session: string, entry: DeclaredAttachment | null): void {
  const cur = readDeclaredList(env);
  const next = restoreDeclared(cur.attachments, session, entry);
  if (JSON.stringify(next) !== JSON.stringify(cur.attachments)) writeDeclaredList(env, next);
}

/** The providers key of the proxy the pool runs for `session` (its pool
 *  record; attachment-contract.ts providersKey), or null (no record, an
 *  older service that records none). */
export function servedProvidersKey(env: Env, session: string): string | null {
  try {
    return poolRecordProvidersKey(readFileSync(`${attachmentDir(runtimeBase(env), session)}/${POOL_RECORD_FILE}`, "utf8"));
  } catch {
    return null;
  }
}

/** Record the OpenClaw config a declared session's route was written into
 *  (`mandu openclaw install`; the pool's route check reads it and is armed
 *  by it, openclaw-plugin.md §3.6). A session not declared is left alone:
 *  false. */
export function recordDeclaredConfig(env: Env, session: string, configPath: string): boolean {
  const cur = readDeclaredList(env);
  const d = cur.attachments.find((a) => a.session === session);
  if (d === undefined) return false;
  const r = declareAttachment(cur.attachments, d.agent, null, resolve(configPath));
  if (r.changed) writeDeclaredList(env, r.list);
  return true;
}

/** Record the confined-commands tier of a declared session (null: removed;
 *  openclaw-plugin.md §10): what `mandu openclaw install --sandbox` replaced,
 *  for uninstall. A session not declared is left alone: false. */
export function recordDeclaredSandbox(env: Env, session: string, sandbox: DeclaredSandbox | null): boolean {
  const cur = readDeclaredList(env);
  if (!cur.attachments.some((a) => a.session === session)) return false;
  const r = withDeclaredSandbox(cur.attachments, session, sandbox);
  if (r.changed) writeDeclaredList(env, r.list);
  return true;
}

/** Undeclare a session; the removed entry, or null when it was not declared. */
export function removeDeclared(env: Env, session: string): DeclaredAttachment | null {
  const cur = readDeclaredList(env);
  const r = undeclareAttachment(cur.attachments, session);
  if (r.removed !== null) writeDeclaredList(env, r.list);
  return r.removed;
}

// ── The service proxy of a session (the port-file contract) ─────────────────

/** The service proxy of a session, or why there is none. */
export type ServiceProxy =
  | { ok: true; port: number; url: string; arbiterSock: string }
  | { ok: false; why: string };

/** Read the session's service proxy through the port-file contract: a
 *  trusted port file, and a proxy on that port answering as this session's. */
export async function readServiceProxy(
  env: Env,
  session: string,
  deps: { uid: number | undefined; probe(port: number): Promise<ServiceIdentity | null> },
): Promise<ServiceProxy> {
  try {
    assertRuntimeBaseTrusted(env);
  } catch (e) {
    return { ok: false, why: (e as Error).message };
  }
  const file = anthropicProxyPortFile(runtimeBase(env), session);
  let st;
  try {
    st = lstatSync(file);
  } catch {
    return { ok: false, why: `no service proxy for ${session} (${file} is absent)` };
  }
  const problem = portFileProblem({ isFile: st.isFile(), uid: st.uid, mode: st.mode }, deps.uid);
  if (problem !== null) return { ok: false, why: `${file} ${problem}` };
  let port: number | null = null;
  try {
    port = parsePortFile(readFileSync(file, "utf8"));
  } catch { /* unreadable */ }
  if (port === null) return { ok: false, why: `${file} holds no port` };
  const id = await deps.probe(port);
  const idProblem = identityProblem(id, session);
  if (idProblem !== null) return { ok: false, why: `port ${port} (from ${file}): ${idProblem}` };
  return { ok: true, port, url: serviceProxyUrl(port), arbiterSock: id!.arbiterSock! };
}

/** The pid of the service's running pool, or null (no record, a dead pid). */
export function livePool(env: Env, pidAlive: (pid: number) => boolean): number | null {
  try {
    const pid = poolRecordPid(readFileSync(poolMarkerFile(runtimeBase(env)), "utf8"));
    return pid !== null && pidAlive(pid) ? pid : null;
  } catch {
    return null;
  }
}

/** Wait up to `ms` for the session's service proxy (the pool reads the
 *  declared file every 2 s, registers, then starts the proxy). `providers`:
 *  the providers key the proxy must have been started with (Route 1: the
 *  pool records it beside the proxy; a proxy still running with other
 *  routes is not the one to write the config for). */
export async function waitServiceProxy(
  env: Env,
  session: string,
  deps: { uid: number | undefined; probe(port: number): Promise<ServiceIdentity | null>; sleep(ms: number): Promise<void>; now(): number },
  ms: number,
  providers?: string,
): Promise<ServiceProxy> {
  const deadline = deps.now() + ms;
  for (;;) {
    let r = await readServiceProxy(env, session, deps);
    if (r.ok && providers !== undefined && servedProvidersKey(env, session) !== providers) {
      r = { ok: false, why: `the proxy serving ${session} was not started with the providers this install routes yet` };
    }
    if (r.ok || deps.now() >= deadline) return r;
    await deps.sleep(250);
  }
}

// ── What status and doctor show ─────────────────────────────────────────────

/** One attachment session, as `mandu serve status` and `mandu doctor` show it. */
export interface AttachmentProxy {
  session: string;
  /** Declared in the file the pool reads. */
  declared: boolean;
  declaredPort: number | null;
  /** The port its port file names (null: none, or not trusted). */
  port: number | null;
  /** The proxy on that port answers as this session's. */
  healthy: boolean;
  /** Why it is not serving (no port file, a wrong identity, …), or null. */
  problem: string | null;
  /** The arbiter holds it live (humanPlaneStatus names it); null: unknown. */
  registered: boolean | null;
  /** The service's last secret registration for it (serve-secrets.ts, read
   *  from the pool's record): files found and registered; null: none yet. */
  secrets: { found: number; registered: number; at: string } | null;
  /** The service's route check of the OpenClaw config (openclaw-plugin.md
   *  §3.6, read from the pool's record): routed, lost (with what), or
   *  pending; null: not checked yet (or an older service). */
  route: RouteRecord | null;
  /** The service's check of the confined-commands tier (openclaw-plugin.md
   *  §10.6, the pool record's `sandbox`); null: not installed or not checked. */
  sandbox?: SandboxRecord | null;
  /** The providers its proxy routes (Route 1, the declaration's; absent:
   *  none recorded, the Anthropic route as the service's environment says)
   *  and the ones the user left unprotected. */
  providers?: DeclaredProvider[];
  unprotected?: string[];
  /** The posture the arbiter decides for it, its gap and the gap's sentence. */
  posture: string;
  gap: string;
  sentence: string;
}

/** The facts behind the list (injectable). */
export interface AttachmentDeps {
  uid: number | undefined;
  probe(port: number): Promise<ServiceIdentity | null>;
  /** The arbiter's `humanPlaneStatus` answer (null: no answer). */
  humanPlaneStatus(env: Env): Promise<unknown>;
}

/** The arbiter's `humanPlaneStatus` (human plane, read-only), over the
 *  human socket its `hello` names; null when it does not answer. */
export async function humanPlaneStatusOf(env: Env, timeoutMs = 3_000): Promise<unknown> {
  let sock: string;
  try { sock = resolveArbiterSock(env).sock; } catch { return null; }
  try {
    const hello = await ndjsonCall<{ humanSock?: unknown }>(sock, "hello", {}, timeoutMs);
    const human = typeof hello?.humanSock === "string" && hello.humanSock !== "" ? hello.humanSock : null;
    if (human === null) return null;
    return await ndjsonCall<unknown>(human, "humanPlaneStatus", {}, timeoutMs);
  } catch {
    return null;
  }
}

/** The posture an `openclaw-plugin` attachment gets (the arbiter decides it
 *  by the same function, over the coverage the service declares): with a
 *  route found lost (`route`), the coverage the pool declares then. */
export function attachmentPosture(route: RouteRecord | null = null): { posture: string; gap: string; sentence: string } {
  const lost = route?.state === "lost" ? routeLostOf(route.problems) : {};
  const p = resolvePosture(attachmentCoverage("openclaw-plugin", lost));
  const gap = "gap" in p && p.gap !== undefined ? p.gap : "openclaw-plugin";
  return { posture: p.posture, gap, sentence: postureSentence({ posture: p.posture, gap }) };
}

/** The lines a lost route gets wherever a session is listed (`mandu serve
 *  status`, `mandu doctor`): what changed and the fix, said loudly. Empty
 *  unless lost. Pure. */
export function routeLostLines(session: string, route: RouteRecord | null): string[] {
  if (route?.state !== "lost") return [];
  return [
    `${session}: the OpenClaw config no longer routes through Mandu (${route.config}, since ${route.since}): ` +
      route.problems.map((p) => p.detail).join("; "),
    `the Gateway keeps the config it loaded until it restarts, so this takes effect at its next restart; fix: ${ROUTE_FIX}`,
  ];
}

export { sandboxLostLines };

/** The attachments live in the arbiter, by session (empty when it answered
 *  none; null when it did not answer). Pure. */
export function liveAttachmentSessions(status: unknown): Set<string> | null {
  const st = parseHumanPlaneStatus(status);
  if (st === null) return null;
  return new Set(st.launches.filter((l) => l.attachment !== undefined && l.session !== undefined).map((l) => l.session!));
}

/** The secret counts a session's pool record carries, or null. Pure. */
export function poolRecordSecrets(text: string): AttachmentProxy["secrets"] {
  try {
    const s = (JSON.parse(text) as { secrets?: { found?: unknown; registered?: unknown; at?: unknown } }).secrets;
    if (s && typeof s.found === "number" && typeof s.registered === "number" && typeof s.at === "string") return { found: s.found, registered: s.registered, at: s.at };
  } catch { /* torn */ }
  return null;
}

/** Every attachment: the declared ones, and any the arbiter holds live
 *  without a declaration (a lease not yet lapsed). */
export async function gatherAttachments(env: Env, deps: AttachmentDeps): Promise<AttachmentProxy[]> {
  const decl = readDeclaredList(env).attachments;
  let live: Set<string> | null = null;
  try { live = liveAttachmentSessions(await deps.humanPlaneStatus(env)); } catch { live = null; }
  const sessions = [...decl.map((d) => d.session), ...[...(live ?? [])].filter((s) => !decl.some((d) => d.session === s))];
  const out: AttachmentProxy[] = [];
  for (const session of sessions) {
    const d = decl.find((x) => x.session === session);
    const svc = await readServiceProxy(env, session, deps);
    let secrets: AttachmentProxy["secrets"] = null;
    let route: RouteRecord | null = null;
    let sandbox: SandboxRecord | null = null;
    try {
      const rec = readFileSync(`${attachmentDir(runtimeBase(env), session)}/${POOL_RECORD_FILE}`, "utf8");
      secrets = poolRecordSecrets(rec);
      route = parseRouteRecord(rec);
      sandbox = parseSandboxRecord(rec);
    } catch { /* none */ }
    const posture = attachmentPosture(route);
    out.push({
      session,
      declared: d !== undefined,
      declaredPort: d?.port ?? null,
      port: svc.ok ? svc.port : null,
      healthy: svc.ok,
      problem: svc.ok ? null : svc.why,
      registered: live === null ? null : live.has(session),
      secrets,
      route,
      ...(sandbox !== null ? { sandbox } : {}),
      ...(d?.providers !== undefined ? { providers: d.providers } : {}),
      ...(d?.unprotected !== undefined ? { unprotected: d.unprotected } : {}),
      ...posture,
    });
  }
  return out;
}

/** The cost of a live attachment in one sentence, and how to avoid it (the
 *  maintainer's "weaken + warn", 2026-10-25): every surface that names a
 *  live attachment says this. Pure. */
export function attachmentExposureLines(sessions: readonly string[]): string[] {
  if (sessions.length === 0) return [];
  const who = sessions.length === 1 ? `session ${sessions[0]}` : `sessions ${sessions.join(", ")}`;
  return [
    `a plugin session is running (${attachmentWords("openclaw-plugin")}, ${who}): while it runs, confined launches on this machine have lost their guard's attestation, ` +
      "because the Gateway's programs can reach Mandu's own controls (their secret files open as placeholders, protected writes are refused, shell output is masked once they read a secret)",
    "to avoid it: run the Gateway under Mandu instead (mandu openclaw gateway), or stop the service while you use confined launches (mandu serve stop); mandu openclaw uninstall detaches it for good",
  ];
}

// ── `mandu serve attach|detach openclaw` ────────────────────────────────────

/** What attach/detach needs beyond the files. */
export interface AttachCommandDeps {
  uid: number | undefined;
  probe(port: number): Promise<ServiceIdentity | null>;
  /** Is the service's unit active? */
  serviceActive(): boolean;
  sleep(ms: number): Promise<void>;
  now(): number;
  /** How long attach waits for the proxy. */
  waitMs: number;
  out(s: string): void;
  err(s: string): void;
}

/** `mandu serve attach|detach` arguments (after the verb). Pure. */
export function parseAttachArgs(rest: readonly string[]): { kind: "openclaw"; agent: string; port: number | null } | { error: string } {
  const [kind, ...flags] = rest;
  if (kind !== "openclaw") return { error: `attach what? only openclaw is supported (mandu serve attach openclaw [--agent <id>] [--port <n>])` };
  let agent = "main";
  let port: number | null = null;
  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    const val = (name: string): string | null => f === name ? (flags[++i] ?? null) : f.startsWith(`${name}=`) ? f.slice(name.length + 1) : null;
    if (f === "--agent" || f.startsWith("--agent=")) {
      const v = val("--agent");
      if (v === null || v.trim() === "") return { error: "--agent needs an OpenClaw agent id" };
      agent = v;
    } else if (f === "--port" || f.startsWith("--port=")) {
      const v = val("--port");
      const n = Number(v);
      if (v === null || !/^[0-9]+$/.test(v) || n < 1024 || n > 65535) return { error: "--port needs a port from 1024 to 65535" };
      port = n;
    } else {
      return { error: `unknown option '${f}'` };
    }
  }
  return { kind: "openclaw", agent: normalizeAgentId(agent), port };
}

/** `mandu serve attach openclaw [--agent <id>] [--port <n>]`: declare the
 *  agent's session, and while the service runs, wait for its proxy. Exit 0
 *  declared (and serving, when the service runs), 1 failed, 2 usage, 3
 *  declared but the service is not running or the proxy is not up yet. */
export async function runServeAttach(rest: readonly string[], env: Env, deps: AttachCommandDeps): Promise<number> {
  const a = parseAttachArgs(rest);
  if ("error" in a) { deps.err(`mandu serve attach: ${a.error}\n`); return 2; }
  let r;
  try {
    r = await ensureDeclared(env, a.agent, a.port);
  } catch (e) {
    deps.err(`mandu serve attach: could not write ${declaredFilePath(env)}: ${(e as Error).message}\n`);
    return 1;
  }
  const { entry } = r;
  deps.out(`mandu serve: ${r.added ? "attached" : r.changed ? "updated" : "already attached:"} ${entry.session} (OpenClaw agent ${entry.agent}` +
    `${entry.port !== null ? `, port ${entry.port}` : ""}) in ${r.path}\n`);
  for (const l of attachmentExposureLines([entry.session])) deps.out(`  ${l}\n`);
  if (!deps.serviceActive()) {
    deps.out("  the service is not running, so no proxy serves it yet: mandu serve start (mandu serve install sets it up)\n");
    return 3;
  }
  const svc = await waitServiceProxy(env, entry.session, deps, deps.waitMs);
  if (!svc.ok) {
    deps.out(`  its proxy is not up yet (${svc.why}); mandu serve status shows it\n`);
    return 3;
  }
  deps.out(`  serving at ${svc.url}; next: mandu openclaw install${entry.agent === "main" ? "" : ` --agent ${entry.agent}`} routes the Gateway through it\n`);
  return 0;
}

/** `mandu serve detach openclaw [--agent <id>]`: undeclare the session (the
 *  pool stops its proxy and ends its attachment within a few seconds). */
export function runServeDetach(rest: readonly string[], env: Env, deps: Pick<AttachCommandDeps, "out" | "err">): number {
  const a = parseAttachArgs(rest);
  if ("error" in a) { deps.err(`mandu serve detach: ${a.error.replace("attach what?", "detach what?")}\n`); return 2; }
  if (a.port !== null) { deps.err("mandu serve detach: --port is not an option here\n"); return 2; }
  const session = attachmentSession(a.agent);
  let removed;
  try {
    removed = removeDeclared(env, session);
  } catch (e) {
    deps.err(`mandu serve detach: could not write ${declaredFilePath(env)}: ${(e as Error).message}\n`);
    return 1;
  }
  if (removed === null) {
    deps.out(`mandu serve: ${session} is not attached; nothing to do\n`);
    return 0;
  }
  deps.out(`mandu serve: detached ${session}: the service stops its proxy and ends its attachment within a few seconds, ` +
    "and confined launches get their guard's attestation back. The Gateway's model calls fail until it is routed elsewhere " +
    "(mandu openclaw uninstall removes the route and the plugin).\n");
  return 0;
}
