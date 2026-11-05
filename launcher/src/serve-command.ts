/**
 * serve-command — `mandu serve install|uninstall|start|stop|status|upgrade`:
 * the resident Mandu service as a systemd user unit (runtime-instances.md
 * §4.1d, openclaw-plugin.md §3.2).
 *
 * The decisions are serve-unit.ts's (pure); this module gathers the facts
 * and carries the decisions out. Every effect goes through `ServeDeps`:
 * `systemctl --user` through an injectable runner, the unit file, the
 * stack's processes, the arbiter's `hello`. The tests drive it with a fake
 * runner (test/unit/serve-command.test.ts) and against a real dashboard and
 * arbiter that a fake systemd starts from the rendered unit
 * (test/component/serve-command.test.ts). Nothing here needs root, and the
 * only host state it writes is this account's own unit file.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { arbiterRevOf, arbiterTreesMatch, promotedSockPath } from "./arbiter.js";
import { assertRuntimeBaseTrusted } from "./arbiter-sock.js";
import { endpointWords } from "./attachment-contract.js";
import { ownArbiterBuild, versionVerdict, type VersionVerdict } from "./arbiter-version.js";
import { docsUrl } from "./docs-url.js";
import { connectHost, dashboardUrl, liveDashboards, type LiveDashboard } from "./live-dashboards.js";
import { realReapDeps } from "./reap.js";
import { resolveRuntimeBase } from "./runtime-base.js";
import { ndjsonCall } from "./secret-setup.js";
import {
  hostRefusal, parseUnitFile, planStart, planUpgrade, renderServeUnit, SERVE_UNIT, serveHost,
  serveUnitInput, stopBlockedBy, unitFilePath, unitRuntimeDir, type CodeVerdict, type ServeHost,
} from "./serve-unit.js";
import { probeIdentity, realDeps, serviceReadyDeadlineMs } from "./services/primitives.js";
import {
  attachmentExposureLines, gatherAttachments, humanPlaneStatusOf, routeLostLines, runServeAttach, runServeDetach, sandboxLostLines, type AttachmentProxy,
} from "./serve-attachments.js";
import { runRegisterSecrets } from "./serve-secrets.js";
import type { Layout } from "./services/layout.js";
import { parseSystemctlShow, realSupervisorDeps, serviceUnitOfCgroup, stackService } from "./stack-supervisor.js";
// A cycle (subcommands dispatches here), used only at call time.
import { liveLaunchersOn, residentPidsOn } from "./subcommands.js";
import { launcherVersion } from "./update-check.js";

type Env = Record<string, string | undefined>;

/** One `systemctl --user <args>` run; code 127 when there is no systemctl. */
export interface SystemctlResult { code: number; stdout: string; stderr: string }
export type SystemctlRunner = (args: string[]) => SystemctlResult;

/**
 * The proxy pool's sessions as `status` shows them (openclaw-plugin.md §3.2):
 * the pool runs in the service's main process (dashboard/src/supervisor/
 * attachment-pool.ts); `list()` reads what it left to read (the declared
 * file, the port files, each proxy's `/_mandu/identity`, the arbiter's live
 * attachments; serve-attachments.ts gatherAttachments).
 */
export type { AttachmentProxy } from "./serve-attachments.js";
export interface AttachmentPool { list(): Promise<AttachmentProxy[]> }

/** This mandu: what the unit is rendered from and what the stack is judged against. */
export interface ServeSelf {
  version: string;
  install: "npm" | "checkout";
  root: string;
  node: string;
  layout: Pick<Layout, "daemon">;
  /** The stack's runtime dir and how it was chosen (runtime-base.ts). */
  base: string;
  baseSource: "explicit" | "xdg" | "tmpdir" | "fallback";
  /** The running arbiter's `hello` against this mandu (arbiter-version.ts). */
  verdict: (hello: unknown) => VersionVerdict;
}

/** The effects `mandu serve` needs, injectable for tests. */
export interface ServeDeps {
  platform: string;
  self: ServeSelf;
  systemctl: SystemctlRunner;
  /** loginctl's Linger for this account: true, false, or null (unknown). */
  linger: () => boolean | null;
  readFile: (p: string) => string | null;
  writeFile: (p: string, text: string) => void;
  removeFile: (p: string) => void;
  /** One `hello`; resolves undefined or rejects when nothing answers. */
  hello: (sock: string) => Promise<unknown>;
  /** `mandu` sessions on the stack (subcommands.ts liveLaunchersOn). */
  sessions: (base: string) => number[];
  /** The stack's resident daemons (subcommands.ts residentPidsOn). */
  residentPids: (base: string) => number[];
  /** The systemd unit a process runs in, or null. */
  unitOfPid: (pid: number) => string | null;
  /** Another systemd service running the stack (stack-supervisor.ts
   *  stackService), or null; the shipped unit itself never counts. */
  otherService: (base: string) => string | null;
  /** SIGTERM `pids` and wait for them; returns the survivors. */
  stopPids: (pids: readonly number[]) => Promise<number[]>;
  dashboards: (env: Env) => LiveDashboard[];
  probePort: (host: string, port: number) => Promise<boolean>;
  sleep: (ms: number) => Promise<void>;
  /** How long a start waits for the arbiter to answer. */
  readyMs: number;
  /** How often `upgrade --wait` looks at the sessions again. */
  waitPollMs: number;
  pool?: AttachmentPool;
  /** `GET /_mandu/identity` of a proxy on 127.0.0.1 (attach waits for one). */
  probeIdentity?: (port: number) => Promise<{ mandu?: boolean; service?: string; sessionKey?: string; arbiterSock?: string } | null>;
  /** How long `attach` waits for the pool to serve a new session (default 30 s). */
  attachWaitMs?: number;
  out: (s: string) => void;
  err: (s: string) => void;
}

/** Exit codes: 0 done, 1 refused or failed, 2 usage or a host without
 *  systemd --user, 3 not installed / not running (status) or deferred while
 *  sessions run (start, stop, upgrade, uninstall, an install's start). */
export const SERVE_EXIT = { ok: 0, failed: 1, usage: 2, deferred: 3 } as const;

const VERBS = ["install", "uninstall", "start", "stop", "status", "upgrade", "attach", "detach", "register-secrets"] as const;
/** Verbs that keep their own arguments (`rest`). `register-secrets` is the
 *  pool's (serve-secrets.ts), not shown in the usage. */
const PASS_THROUGH = ["attach", "detach", "register-secrets"] as const;
type PassVerb = (typeof PASS_THROUGH)[number];
type Verb = (typeof VERBS)[number];

/** `mandu serve` arguments; an error for a malformed one. `attach` and
 *  `detach` keep their own arguments in `rest` (serve-attachments.ts
 *  parseAttachArgs). Pure. */
export function parseServeArgs(rest: string[]): { verb: Verb; force: boolean; wait: boolean; json: boolean; rest: string[] } | { error: string } {
  const [verb, ...flags] = rest;
  const shown = VERBS.filter((v) => v !== "register-secrets").join("|");
  if (verb === undefined) return { error: `which one? mandu serve ${shown}` };
  if (!(VERBS as readonly string[]).includes(verb)) return { error: `unknown verb '${verb}' (mandu serve ${shown})` };
  if ((PASS_THROUGH as readonly string[]).includes(verb)) return { verb: verb as Verb, force: false, wait: false, json: false, rest: flags };
  const allowed: Record<Exclude<Verb, PassVerb>, string[]> = {
    install: ["--force"], uninstall: ["--force"], start: ["--force"], stop: ["--force"],
    status: ["--json"], upgrade: ["--force", "--wait"],
  };
  for (const f of flags) {
    if (!allowed[verb as Exclude<Verb, PassVerb>].includes(f)) return { error: `mandu serve ${verb}: unknown option '${f}'` };
  }
  return { verb: verb as Verb, force: flags.includes("--force"), wait: flags.includes("--wait"), json: flags.includes("--json"), rest: [] };
}

/** The unit's state from `systemctl --user show mandu.service`. */
export interface UnitState {
  load: string;
  active: string;
  sub: string;
  enabled: string;
  mainPid: number | null;
  since: string | null;
  restarts: number | null;
}

function unitState(deps: ServeDeps): UnitState | null {
  const r = deps.systemctl(["show", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "UnitFileState",
    "-p", "MainPID", "-p", "ActiveEnterTimestamp", "-p", "NRestarts", "--", SERVE_UNIT]);
  if (r.code !== 0) return null;
  const p = parseSystemctlShow(r.stdout);
  const pid = Number(p["MainPID"]);
  const restarts = Number(p["NRestarts"]);
  return {
    load: p["LoadState"] ?? "unknown",
    active: p["ActiveState"] ?? "unknown",
    sub: p["SubState"] ?? "",
    enabled: p["UnitFileState"] ?? "",
    mainPid: Number.isInteger(pid) && pid > 0 ? pid : null,
    since: p["ActiveEnterTimestamp"] && p["ActiveEnterTimestamp"] !== "n/a" ? p["ActiveEnterTimestamp"] : null,
    restarts: Number.isInteger(restarts) && p["NRestarts"] !== "" ? restarts : null,
  };
}

/** The stack's arbiter as `hello` reports it. */
interface ArbiterFacts {
  running: boolean;
  version: string | null;
  pid: number | null;
  verdict: CodeVerdict;
  /** Its process is in the shipped unit (null: unknown, no pid). */
  insideUnit: boolean | null;
}

async function arbiterFacts(sock: string, deps: ServeDeps): Promise<ArbiterFacts> {
  let hello: unknown;
  try { hello = await deps.hello(sock); } catch { hello = undefined; }
  const h = hello && typeof hello === "object" ? (hello as Record<string, unknown>) : null;
  if (h === null || typeof h["protocolVersion"] !== "number") {
    return { running: false, version: null, pid: null, verdict: "not-running", insideUnit: null };
  }
  const pid = typeof h["pid"] === "number" && Number.isInteger(h["pid"]) && (h["pid"] as number) > 0 ? (h["pid"] as number) : null;
  return {
    running: true,
    version: typeof h["version"] === "string" ? h["version"] : null,
    pid,
    verdict: deps.self.verdict(hello).kind,
    insideUnit: pid === null ? null : deps.unitOfPid(pid) === SERVE_UNIT,
  };
}

/** The unit text this mandu would write. */
function rendered(env: Env, deps: ServeDeps): string {
  const s = deps.self;
  return renderServeUnit(serveUnitInput({
    version: s.version,
    install: s.install,
    root: s.root,
    node: s.node,
    daemon: s.layout.daemon("dashboard", "dashboard"),
    runtimeDir: unitRuntimeDir(s.base, s.baseSource),
    env,
    docs: docsUrl("docs/usage.md#the-mandu-service"),
  }));
}

function hostOf(deps: ServeDeps): ServeHost {
  if (deps.platform !== "linux") return serveHost(deps.platform, null);
  const r = deps.systemctl(["show", "-p", "Version", "--value"]);
  return serveHost(deps.platform, { code: r.code, stderr: r.stderr });
}

/** What `mandu serve status` reports (also its --json). */
export interface ServeStatus {
  host: ServeHost["kind"];
  unitFile: { path: string | null; state: "absent" | "ours" | "foreign"; current: boolean | null; runs: string | null };
  unit: UnitState | null;
  stack: { base: string; sock: string; arbiter: ArbiterFacts };
  thisMandu: { version: string; install: "npm" | "checkout"; root: string };
  dashboard: { url: string; pid: number; answering: boolean; insideUnit: boolean } | null;
  sessions: number[];
  linger: boolean | null;
  /** The proxy pool's sessions (the seam above): null until it is built. */
  attachments: AttachmentProxy[] | null;
  problems: string[];
}

async function gatherStatus(env: Env, deps: ServeDeps, host: ServeHost): Promise<ServeStatus> {
  const s = deps.self;
  const path = unitFilePath(env);
  const text = path === null ? null : deps.readFile(path);
  const parsed = text === null ? null : parseUnitFile(text);
  const state = text === null ? "absent" : parsed!.ours ? "ours" : "foreign";
  const current = text === null ? null : text === rendered(env, deps);
  const unit = host.kind === "ok" ? unitState(deps) : null;
  const sock = promotedSockPath(s.base);
  const arbiter = await arbiterFacts(sock, deps);
  let dashboard: ServeStatus["dashboard"] = null;
  const dashes = deps.dashboards(env);
  const pick = dashes.find((d) => deps.unitOfPid(d.pid) === SERVE_UNIT) ?? dashes[0];
  if (pick) {
    dashboard = {
      url: dashboardUrl(pick),
      pid: pick.pid,
      answering: await deps.probePort(connectHost(pick.host), pick.port),
      insideUnit: deps.unitOfPid(pick.pid) === SERVE_UNIT,
    };
  }
  const st: Omit<ServeStatus, "problems"> = {
    host: host.kind,
    unitFile: { path, state, current, runs: parsed?.workingDirectory ?? null },
    unit,
    stack: { base: s.base, sock, arbiter },
    thisMandu: { version: s.version, install: s.install, root: s.root },
    dashboard,
    sessions: deps.sessions(s.base),
    linger: host.kind === "ok" ? deps.linger() : null,
    attachments: deps.pool ? await deps.pool.list() : null,
  };
  return { ...st, problems: statusProblems(st) };
}

/** The problems `status` names, each with what to run. Pure. */
export function statusProblems(st: Omit<ServeStatus, "problems">): string[] {
  const out: string[] = [];
  if (st.unitFile.state === "foreign") out.push(`${st.unitFile.path} was not written by mandu serve; mandu serve leaves it alone`);
  if (st.unitFile.state === "absent" || st.unit === null) return out;
  if (st.unitFile.state === "ours" && st.unitFile.current === false) {
    out.push("the unit file is from another mandu release, install or node: mandu serve upgrade");
  }
  if (st.unit.active !== "active") {
    out.push(`the service is ${st.unit.active}${st.unit.sub ? ` (${st.unit.sub})` : ""}: mandu serve start` +
      (st.unit.active === "failed" ? `; its log: journalctl --user -u ${SERVE_UNIT}` : ""));
    return out;
  }
  const a = st.stack.arbiter;
  if (!a.running) out.push(`the service runs but its arbiter does not answer at ${st.stack.sock}; its log: journalctl --user -u ${SERVE_UNIT}`);
  else if (a.verdict !== "match" && a.verdict !== "unknown") {
    out.push(`the service's arbiter is ${a.version ? `Mandu ${a.version}` : "an older Mandu"}${a.verdict === "build" ? " of another build" : ""}, not this mandu (${st.thisMandu.version}): mandu serve upgrade`);
  } else if (a.insideUnit === false) {
    out.push(`the stack's arbiter (pid ${a.pid}) is not the service's own process (a launch or another dashboard started it): mandu serve upgrade replaces it`);
  }
  if (st.dashboard === null) out.push("no dashboard is registered for the stack");
  else if (!st.dashboard.answering) out.push(`the dashboard at ${st.dashboard.url} does not answer`);
  for (const p of st.attachments ?? []) {
    if (!p.declared) continue;
    // A lost route first: the Gateway's next restart sends model calls
    // around Mandu (openclaw-plugin.md §3.6, the service's route check).
    const lost = routeLostLines(p.session, p.route);
    if (lost.length > 0) out.push(`✗ ${lost.join("; ")}`);
    // The confined-commands tier (openclaw-plugin.md §10.6): a command may
    // run outside Mandu's box.
    const tier = sandboxLostLines(p.session, p.sandbox ?? null);
    if (tier.length > 0) out.push(`✗ ${tier.join("; ")}`);
    if (!p.healthy) {
      out.push(`${p.session} has no proxy serving (${p.problem ?? "unknown"}): the Gateway's model calls fail until it does; its log: journalctl --user -u ${SERVE_UNIT}`);
    } else if (p.registered === false) {
      out.push(`${p.session}'s proxy answers but the arbiter does not hold its attachment: the service stops it (fail closed) and registers again`);
    }
  }
  return out;
}

function renderStatus(st: ServeStatus): string {
  const L: string[] = [];
  const col = (k: string, v: string): void => { L.push(`  ${k.padEnd(11)}${v}`); };
  if (st.host !== "ok") {
    L.push("Mandu service (mandu serve): not available on this host (see mandu serve install)");
  } else if (st.unitFile.state === "absent") {
    L.push("Mandu service (mandu serve): not installed (mandu serve install sets it up)");
  } else {
    const u = st.unit;
    const running = u?.active === "active";
    L.push(`Mandu service (mandu serve): ${running ? (st.problems.length === 0 ? "running" : "running, with problems") : u?.active ?? "unknown"}`);
    if (u) {
      col("unit:", `${SERVE_UNIT}, ${u.active}${u.sub ? ` (${u.sub})` : ""}, ${u.enabled || "unknown"}` +
        (u.mainPid ? `, pid ${u.mainPid}` : "") + (u.since && running ? `, since ${u.since}` : "") +
        (u.restarts ? `, restarted ${u.restarts} time${u.restarts === 1 ? "" : "s"}` : ""));
    }
    col("unit file:", `${st.unitFile.path} (${st.unitFile.state === "foreign" ? "not written by mandu serve" : st.unitFile.current ? "current" : "out of date"})`);
    if (st.unitFile.runs) col("runs from:", st.unitFile.runs);
  }
  const a = st.stack.arbiter;
  col("arbiter:", a.running
    ? `answering at ${st.stack.sock} (${a.version ? `Mandu ${a.version}` : "an older Mandu"}${a.pid ? `, pid ${a.pid}` : ""}` +
      (a.insideUnit === true ? ", the service's own" : a.insideUnit === false ? ", started outside the service" : "") + ")"
    : `not answering at ${st.stack.sock}`);
  col("versions:", `this mandu ${st.thisMandu.version} (${st.thisMandu.install === "npm" ? "npm package" : "source checkout"} at ${st.thisMandu.root})` +
    (a.running ? `; the arbiter ${a.verdict === "match" ? "matches it" : a.verdict === "unknown" ? "cannot be compared" : a.verdict === "build" ? "is another build" : `is ${a.version ?? "older"}`}` : ""));
  col("dashboard:", st.dashboard ? `${st.dashboard.url}${st.dashboard.answering ? "" : " (not answering)"}` : "none registered");
  if (st.sessions.length > 0) col("sessions:", `${st.sessions.length} mandu session${st.sessions.length === 1 ? "" : "s"} use the stack (pid ${st.sessions.join(", ")})`);
  if (st.attachments !== null) {
    if (st.attachments.length === 0) {
      col("attached:", "no attachment sessions (mandu openclaw install attaches an OpenClaw Gateway)");
    } else {
      st.attachments.forEach((p, i) => col(i === 0 ? "attached:" : "", attachmentLine(p)));
      col("posture:", `${st.attachments[0]!.posture}, gap ${st.attachments[0]!.gap}: ${st.attachments[0]!.sentence}`);
      for (const l of attachmentExposureLines(st.attachments.filter((p) => p.registered === true).map((p) => p.session))) {
        L.push(`  warning:   ${l}`);
      }
    }
  }
  if (st.linger === false && st.unitFile.state === "ours") {
    col("note:", "the service stops when you log out; to keep it running: loginctl enable-linger");
  }
  for (const p of st.problems) L.push(`  problem:   ${p}`);
  return L.join("\n") + "\n";
}

/** One attachment in `status`: its proxy, its registration, its posture. Pure. */
export function attachmentLine(p: AttachmentProxy): string {
  const proxy = p.healthy ? `proxy on 127.0.0.1:${p.port}, answering` : `no proxy serving (${p.problem ?? "unknown"})`;
  const reg = p.registered === true ? "registered" : p.registered === false ? "not registered" : "registration unknown (the arbiter did not answer)";
  const port = p.declaredPort !== null && p.port !== null && p.port !== p.declaredPort ? `; not on its port ${p.declaredPort}: mandu openclaw install moves the Gateway's route` : "";
  const secrets = p.secrets === null ? ", secret files not registered yet"
    : `, ${p.secrets.registered} secret file${p.secrets.registered === 1 ? "" : "s"} registered${p.secrets.found > p.secrets.registered ? ` of ${p.secrets.found} found` : ""}`;
  const route = p.route === null ? ""
    : p.route.state === "routed" ? ", the OpenClaw config routes through it"
    : p.route.state === "pending" ? ", the OpenClaw config does not route through it yet (mandu openclaw install)"
    : ", ROUTE LOST (see the problem below)";
  // Route 1: the providers its proxy routes, each to its own address, and
  // the ones the user left unprotected.
  const routed = p.providers === undefined ? ""
    : `, routes ${p.providers.map((r) => `${r.id} → ${r.upstream !== null ? endpointWords(r.upstream) : "its own address"}`).join(", ")}`;
  const left = (p.unprotected ?? []).length > 0 ? `, NOT PROTECTED (left as is): ${p.unprotected!.join(", ")}` : "";
  return `${p.session}: ${proxy}, ${reg}${p.declared ? secrets : ""}${p.declared ? routed + left : ""}${p.declared ? route : ""}, posture ${p.posture} (gap ${p.gap})${p.declared ? "" : ", no longer declared (its lease runs out)"}${port}`;
}

/** Poll `hello` until the arbiter answers or `readyMs` passes (or the unit
 *  fails). */
async function waitForArbiter(deps: ServeDeps): Promise<ArbiterFacts> {
  const sock = promotedSockPath(deps.self.base);
  const deadline = Date.now() + deps.readyMs;
  for (;;) {
    const a = await arbiterFacts(sock, deps);
    if (a.running) return a;
    const u = unitState(deps);
    if (u && u.active === "failed") return a;
    if (Date.now() >= deadline) return a;
    await deps.sleep(200);
  }
}

/** The stack's resident daemons that are not the shipped unit's. */
function outsidePids(deps: ServeDeps): number[] {
  return deps.residentPids(deps.self.base).filter((p) => deps.unitOfPid(p) !== SERVE_UNIT);
}

function pids(ps: readonly number[]): string {
  return ps.join(", ");
}

/** Start the unit under planStart's rule, then wait for its arbiter. */
async function startUnit(force: boolean, deps: ServeDeps, from: "start" | "install" | "upgrade"): Promise<number> {
  const base = deps.self.base;
  const plan = planStart({ otherService: deps.otherService(base), outside: outsidePids(deps), sessions: deps.sessions(base), force });
  if (plan.kind === "refuse-other-service") {
    deps.err(`mandu serve: the Mandu services for ${base} are already run by the systemd user service ${plan.unit}. ` +
      `Two services on one stack would replace each other's processes. Stop that one for good first ` +
      `(systemctl --user disable --now ${plan.unit}), then run mandu serve ${from === "install" ? "install" : "start"} again.\n`);
    return SERVE_EXIT.failed;
  }
  if (plan.kind === "defer") {
    deps.out(`mandu serve: not started now: the Mandu services already run for ${base} outside the service (pid ${pids(plan.outside)}), ` +
      `and ${plan.sessions.length === 1 ? "a mandu session uses them" : `${plan.sessions.length} mandu sessions use them`} ` +
      `(pid ${pids(plan.sessions)}); starting the service replaces them, which would cut ${plan.sessions.length === 1 ? "it" : "them"} off. ` +
      `Run mandu serve start once ${plan.sessions.length === 1 ? "it ends" : "they end"}, or mandu serve start --force now.\n`);
    return SERVE_EXIT.deferred;
  }
  if (plan.stopOutside.length > 0) {
    deps.out(`mandu serve: stopping the Mandu services that run for ${base} outside the service (pid ${pids(plan.stopOutside)}), so the service runs them\n`);
    const left = await deps.stopPids(plan.stopOutside);
    if (left.length > 0) {
      deps.err(`mandu serve: pid ${pids(left)} did not stop; nothing started. mandu stop --stack ${base} stops them\n`);
      return SERVE_EXIT.failed;
    }
  }
  const r = deps.systemctl(["start", SERVE_UNIT]);
  if (r.code !== 0) {
    deps.err(`mandu serve: systemctl --user start ${SERVE_UNIT} failed: ${r.stderr.trim() || `exit ${r.code}`}. Its log: journalctl --user -u ${SERVE_UNIT}\n`);
    return SERVE_EXIT.failed;
  }
  const a = await waitForArbiter(deps);
  if (!a.running) {
    deps.err(`mandu serve: the service started, but its arbiter did not answer at ${promotedSockPath(base)} within ` +
      `${Math.round(deps.readyMs / 1000)} s. Its log: journalctl --user -u ${SERVE_UNIT}\n`);
    return SERVE_EXIT.failed;
  }
  if (a.verdict !== "match" && a.verdict !== "unknown") {
    deps.err(`mandu serve: the service is up, but its arbiter is ${a.version ? `Mandu ${a.version}` : "an older Mandu"}, not this mandu (${deps.self.version}): mandu serve upgrade\n`);
    return SERVE_EXIT.failed;
  }
  const dash = deps.dashboards({ MANDU_RUNTIME_DIR: base }).find((d) => deps.unitOfPid(d.pid) === SERVE_UNIT);
  deps.out(`mandu serve: running: the arbiter at ${promotedSockPath(base)}${a.pid ? ` (pid ${a.pid})` : ""}` +
    (dash ? `, the dashboard at ${dashboardUrl(dash)}` : "") + ". Launches (mandu claude, ...) attach to it.\n");
  return SERVE_EXIT.ok;
}

/** Refuse on a host the unit cannot run on; null when it can. */
function refuseHost(deps: ServeDeps): number | null {
  const h = hostOf(deps);
  if (h.kind === "ok") return null;
  deps.err(hostRefusal(h) + "\n");
  return SERVE_EXIT.usage;
}

function unitFileOrRefuse(env: Env, deps: ServeDeps): string | null {
  const p = unitFilePath(env);
  if (p === null) deps.err("mandu serve: cannot tell where systemd user units go (set HOME or XDG_CONFIG_HOME)\n");
  return p;
}

function linesForSessions(n: readonly number[], what: string): string {
  return `${what} ends the protection of ${n.length === 1 ? "a running mandu session" : `${n.length} running mandu sessions`} ` +
    `(pid ${pids(n)}): ${n.length === 1 ? "it fails" : "they fail"} closed until the service is back. Run it again once ` +
    `${n.length === 1 ? "it ends" : "they end"}, or add --force.`;
}

async function install(env: Env, force: boolean, deps: ServeDeps): Promise<number> {
  const refused = refuseHost(deps);
  if (refused !== null) return refused;
  const path = unitFileOrRefuse(env, deps);
  if (path === null) return SERVE_EXIT.failed;
  const old = deps.readFile(path);
  if (old !== null && !parseUnitFile(old).ours) {
    deps.err(`mandu serve: ${path} exists and was not written by mandu serve; refusing to replace it. Move it away first.\n`);
    return SERVE_EXIT.failed;
  }
  const other = deps.otherService(deps.self.base);
  if (other !== null) {
    deps.err(`mandu serve: the Mandu services for ${deps.self.base} are already run by the systemd user service ${other}. ` +
      `Two services on one stack would replace each other's processes. Stop that one for good first ` +
      `(systemctl --user disable --now ${other}), then run mandu serve install again.\n`);
    return SERVE_EXIT.failed;
  }
  const text = rendered(env, deps);
  if (old !== text) {
    deps.writeFile(path, text);
    deps.out(`mandu serve: wrote ${path}\n`);
  } else {
    deps.out(`mandu serve: ${path} is already current\n`);
  }
  for (const args of [["daemon-reload"], ["enable", SERVE_UNIT]]) {
    const r = deps.systemctl(args);
    if (r.code !== 0) {
      deps.err(`mandu serve: systemctl --user ${args.join(" ")} failed: ${r.stderr.trim() || `exit ${r.code}`}\n`);
      return SERVE_EXIT.failed;
    }
  }
  deps.out(`mandu serve: enabled: it starts at your login and whenever it stops\n`);
  const rc = await startUnit(force, deps, "install");
  if (rc === SERVE_EXIT.ok && deps.linger() === false) {
    deps.out("mandu serve: it stops when you log out; to keep it running for a resident agent: loginctl enable-linger\n");
  }
  return rc;
}

async function start(env: Env, force: boolean, deps: ServeDeps): Promise<number> {
  const refused = refuseHost(deps);
  if (refused !== null) return refused;
  const path = unitFileOrRefuse(env, deps);
  if (path === null) return SERVE_EXIT.failed;
  if (deps.readFile(path) === null) {
    deps.err("mandu serve: not installed: mandu serve install\n");
    return SERVE_EXIT.deferred;
  }
  return startUnit(force, deps, "start");
}

async function stop(force: boolean, deps: ServeDeps): Promise<number> {
  const refused = refuseHost(deps);
  if (refused !== null) return refused;
  const u = unitState(deps);
  const active = u?.active === "active" || u?.active === "activating";
  if (!active) {
    deps.out("mandu serve: the service is not running\n");
    return SERVE_EXIT.ok;
  }
  const blocked = stopBlockedBy(active, deps.sessions(deps.self.base), force);
  if (blocked.length > 0) {
    deps.err(`mandu serve: not stopped: stopping the service ${linesForSessions(blocked, "now")}\n`);
    return SERVE_EXIT.deferred;
  }
  const r = deps.systemctl(["stop", SERVE_UNIT]);
  if (r.code !== 0) {
    deps.err(`mandu serve: systemctl --user stop ${SERVE_UNIT} failed: ${r.stderr.trim() || `exit ${r.code}`}\n`);
    return SERVE_EXIT.failed;
  }
  deps.out(`mandu serve: stopped. It is still enabled, so it starts at your next login (mandu serve uninstall removes it); ` +
    `until then the next launch starts the protection service itself.\n`);
  return SERVE_EXIT.ok;
}

async function uninstall(env: Env, force: boolean, deps: ServeDeps): Promise<number> {
  const refused = refuseHost(deps);
  if (refused !== null) return refused;
  const path = unitFileOrRefuse(env, deps);
  if (path === null) return SERVE_EXIT.failed;
  const old = deps.readFile(path);
  if (old === null) {
    deps.out("mandu serve: not installed; nothing to remove\n");
    return SERVE_EXIT.ok;
  }
  if (!parseUnitFile(old).ours) {
    deps.err(`mandu serve: ${path} was not written by mandu serve; refusing to remove it\n`);
    return SERVE_EXIT.failed;
  }
  const u = unitState(deps);
  const active = u?.active === "active" || u?.active === "activating";
  const blocked = stopBlockedBy(active, deps.sessions(deps.self.base), force);
  if (blocked.length > 0) {
    deps.err(`mandu serve: not removed: removing the running service ${linesForSessions(blocked, "now")}\n`);
    return SERVE_EXIT.deferred;
  }
  const r = deps.systemctl(["disable", "--now", SERVE_UNIT]);
  if (r.code !== 0) deps.err(`mandu serve: systemctl --user disable --now ${SERVE_UNIT}: ${r.stderr.trim() || `exit ${r.code}`} (removing the file anyway)\n`);
  deps.removeFile(path);
  deps.systemctl(["daemon-reload"]);
  deps.out(`mandu serve: removed ${path}. Launches start the protection service themselves again.\n`);
  return SERVE_EXIT.ok;
}

async function upgrade(env: Env, force: boolean, wait: boolean, deps: ServeDeps): Promise<number> {
  const refused = refuseHost(deps);
  if (refused !== null) return refused;
  const path = unitFileOrRefuse(env, deps);
  if (path === null) return SERVE_EXIT.failed;
  const old = deps.readFile(path);
  const text = rendered(env, deps);
  const u = unitState(deps);
  const active = u?.active === "active";
  const a = active ? await arbiterFacts(promotedSockPath(deps.self.base), deps) : null;
  const plan = planUpgrade({
    onDisk: old === null ? "absent" : parseUnitFile(old).ours ? "ours" : "foreign",
    unitChanged: old !== text,
    active,
    verdict: a?.verdict ?? "not-running",
    arbiterOutside: a?.insideUnit === false,
    sessions: deps.sessions(deps.self.base),
    force,
    wait,
  });
  if (plan.kind === "not-installed") {
    deps.err("mandu serve: not installed: mandu serve install\n");
    return SERVE_EXIT.deferred;
  }
  if (plan.kind === "foreign") {
    deps.err(`mandu serve: ${path} was not written by mandu serve; refusing to rewrite it\n`);
    return SERVE_EXIT.failed;
  }
  if (plan.write) {
    deps.writeFile(path, text);
    const r = deps.systemctl(["daemon-reload"]);
    if (r.code !== 0) {
      deps.err(`mandu serve: systemctl --user daemon-reload failed: ${r.stderr.trim() || `exit ${r.code}`}\n`);
      return SERVE_EXIT.failed;
    }
    deps.out(`mandu serve: rewrote ${path} for this mandu (${deps.self.version})\n`);
  }
  if (plan.kind === "current") {
    deps.out(`mandu serve: the service already runs this mandu (${deps.self.version}); nothing to restart\n`);
    return SERVE_EXIT.ok;
  }
  if (plan.kind === "defer") {
    deps.out(`mandu serve: restart deferred (${plan.why}): restarting ${linesForSessions(plan.sessions, "now")}` +
      " Or add --wait to restart as soon as they end.\n");
    return SERVE_EXIT.deferred;
  }
  if (plan.kind === "wait") {
    deps.out(`mandu serve: a restart is due (${plan.why}); waiting for ${plan.sessions.length === 1 ? "a mandu session" : `${plan.sessions.length} mandu sessions`} ` +
      `(pid ${pids(plan.sessions)}) to end first\n`);
    while (deps.sessions(deps.self.base).length > 0) await deps.sleep(deps.waitPollMs);
  } else {
    deps.out(`mandu serve: restarting the service (${plan.why})\n`);
  }
  if (active) {
    const r = deps.systemctl(["stop", SERVE_UNIT]);
    if (r.code !== 0) {
      deps.err(`mandu serve: systemctl --user stop ${SERVE_UNIT} failed: ${r.stderr.trim() || `exit ${r.code}`}\n`);
      return SERVE_EXIT.failed;
    }
  }
  // The unit was running: under --force, or with no session left, what
  // still runs for the stack outside it (an adopted arbiter, a launch's own
  // dashboard) is replaced with the rest. A unit that was not running starts
  // under start's own rule (deferred while sessions use an outside stack).
  return startUnit(active ? true : force, deps, "upgrade");
}

/** `mandu serve <verb>`. */
export async function runServe(rest: string[], env: Env, deps: ServeDeps): Promise<number> {
  const args = parseServeArgs(rest);
  if ("error" in args) {
    deps.err(`mandu serve: ${args.error}\n`);
    return SERVE_EXIT.usage;
  }
  switch (args.verb) {
    case "install": return install(env, args.force, deps);
    case "uninstall": return uninstall(env, args.force, deps);
    case "start": return start(env, args.force, deps);
    case "stop": return stop(args.force, deps);
    case "upgrade": return upgrade(env, args.force, args.wait, deps);
    case "attach": {
      const u = deps.platform === "linux" ? unitState(deps) : null;
      return runServeAttach(args.rest, env, {
        uid: process.getuid?.(),
        probe: deps.probeIdentity ?? ((port) => probeIdentity("127.0.0.1", port)),
        serviceActive: () => u?.active === "active",
        sleep: deps.sleep,
        now: () => Date.now(),
        waitMs: deps.attachWaitMs ?? 30_000,
        out: deps.out,
        err: deps.err,
      });
    }
    case "detach": return runServeDetach(args.rest, env, deps);
    case "register-secrets": return runRegisterSecrets(args.rest, env, deps);
    case "status": {
      const host = hostOf(deps);
      const st = await gatherStatus(env, deps, host);
      deps.out(args.json ? JSON.stringify(st, null, 2) + "\n" : renderStatus(st));
      if (host.kind !== "ok" || st.unitFile.state === "absent" || st.unit?.active !== "active") return SERVE_EXIT.deferred;
      return st.problems.length > 0 ? SERVE_EXIT.failed : SERVE_EXIT.ok;
    }
  }
}

// ── the real effects ──────────────────────────────────────────────────────

/** This mandu, from the layout it runs in. */
export function realServeSelf(layout: Layout, env: Env): ServeSelf {
  const version = launcherVersion();
  const r = resolveRuntimeBase(env);
  return {
    version,
    install: layout.mode === "installed" ? "npm" : "checkout",
    root: layout.mode === "installed" ? layout.pkgRoot : layout.repoRoot,
    node: process.execPath,
    layout,
    base: r.base,
    baseSource: r.source,
    verdict: (hello) => versionVerdict(version, hello, {
      own: () => ownArbiterBuild(layout, { revOf: arbiterRevOf }),
      sameArbiterTree: (a, b) => arbiterTreesMatch(layout.repoRoot, a, b),
    }),
  };
}

export function realSystemctl(args: string[]): SystemctlResult {
  const r = spawnSync("systemctl", ["--user", ...args], { encoding: "utf8", timeout: 120_000, stdio: ["ignore", "pipe", "pipe"] });
  if (r.error && (r.error as NodeJS.ErrnoException).code === "ENOENT") return { code: 127, stdout: "", stderr: "systemctl is not installed" };
  return { code: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? (r.error ? r.error.message : "") };
}

function realUnitOfPid(pid: number): string | null {
  const cg = realSupervisorDeps.cgroupOf(pid);
  const u = cg === null ? null : serviceUnitOfCgroup(cg);
  return u !== null && u.user ? u.unit : null;
}

export function realServeDeps(layout: Layout, env: Env): ServeDeps {
  const pidAlive = realReapDeps.pidAlive;
  return {
    platform: process.platform,
    self: realServeSelf(layout, env),
    systemctl: realSystemctl,
    linger: () => {
      const uid = typeof process.getuid === "function" ? process.getuid() : null;
      if (uid === null) return null;
      const r = spawnSync("loginctl", ["show-user", String(uid), "-p", "Linger", "--value"], { encoding: "utf8", timeout: 5_000 });
      const v = r.status === 0 ? (r.stdout ?? "").trim() : "";
      return v === "yes" ? true : v === "no" ? false : null;
    },
    readFile: (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } },
    writeFile: (p, text) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text, { mode: 0o644 }); },
    removeFile: (p) => rmSync(p, { force: true }),
    hello: (sock) => ndjsonCall<unknown>(sock, "hello", {}, 3_000),
    sessions: (base) => liveLaunchersOn(base),
    residentPids: (base) => residentPidsOn(base),
    unitOfPid: realUnitOfPid,
    otherService: (base) => {
      const s = stackService(base);
      return s === null || (s.user && s.unit === SERVE_UNIT) ? null : s.unit;
    },
    stopPids: async (ps) => {
      for (const p of ps) { try { process.kill(p, "SIGTERM"); } catch { /* already gone */ } }
      const deadline = Date.now() + 15_000;
      let left = ps.filter(pidAlive);
      while (left.length > 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 100));
        left = left.filter(pidAlive);
      }
      return left;
    },
    dashboards: (e) => liveDashboards({ ...env, ...e }, pidAlive),
    probePort: (h, p) => realDeps.probePort(h, p),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    readyMs: 2 * serviceReadyDeadlineMs(env),
    waitPollMs: 5_000,
    pool: {
      list: () => gatherAttachments(env, {
        uid: process.getuid?.(),
        probe: (port) => probeIdentity("127.0.0.1", port),
        humanPlaneStatus: (e) => humanPlaneStatusOf(e),
      }),
    },
    probeIdentity: (port) => probeIdentity("127.0.0.1", port),
    attachWaitMs: 2 * serviceReadyDeadlineMs(env),
    out: (s) => { process.stdout.write(s); },
    err: (s) => { process.stderr.write(s); },
  };
}

/** `mandu serve …` from the dispatcher. */
export function runServeCommand(rest: string[], env: Env, layout: Layout): Promise<number> {
  try {
    assertRuntimeBaseTrusted(env);
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n`);
    return Promise.resolve(SERVE_EXIT.failed);
  }
  return runServe(rest, env, realServeDeps(layout, env));
}
