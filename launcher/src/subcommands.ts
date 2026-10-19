/**
 * subcommands — the `mandu` management verbs (packaging.md §5 parity gaps):
 * `status`, `stop`, `dashboard`. Dispatched from run.ts BEFORE parse, only in
 * the bare form where the first non-flag token is a reserved word — `mandu --
 * status` still LAUNCHES a program named "status".
 *
 * These operate over the canonical titled process set (runtime-instances.md §7):
 * the resident daemons carry `mandu-<svc>` titles, the launcher carries
 * `mandu`, and the per-session helpers carry `mandu-<role>`.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { assertRuntimeBaseTrusted, resolveArbiterSock, runtimeBase } from "./arbiter-sock.js";
import { accountRendezvous, ensurePrivateIfFallback, isSharedStickyMode, ownedDirProblem, type DirStat } from "./runtime-base.js";
import { requestSignInLink, SIGN_IN_HOW, wantsSignInLink, type SignInOutcome } from "./dashboard-sign-in.js";
import { lastStartFailure } from "./arbiter.js";
import { listDashboards, listInstances, planReap, readDashManifestLite, readManifestLite, realReapDeps, runReap, type ReapAction, type ReapDeps } from "./reap.js";
import { realDeps } from "./services/primitives.js";
import { runDoctor } from "./doctor.js";
import { realSetupDeps, runSetup } from "./setup.js";
import { runDoctorLive, wantsLive } from "./doctor-live.js";
import { runDoctorSecrets, wantsSecrets } from "./doctor-secrets.js";
import { configPath, DEFAULT_CONFIG_TOML } from "./config.js";
import { runMode } from "./mode-command.js";
import { runWhy } from "./why.js";
import { runRevert } from "./revert-command.js";
import { runDemo } from "./demo/demo.js";
import { runPaths } from "./paths-command.js";
import { runVersion } from "./version-report.js";
import { runLog } from "./launch-log.js";
import { runPolicy } from "./policy-suggest.js";
import { subcommandUsage, wantsHelp } from "./subcommand-help.js";
import type { Layout } from "./services/layout.js";

/** Reserved management verbs. Anything else (claude/codex/any binary) launches. */
export const RESERVED_SUBCOMMANDS = new Set(["status", "stop", "dashboard", "doctor", "init", "reap", "setup", "mode", "why", "revert", "demo", "paths", "policy", "log", "version"]);

type Env = Record<string, string | undefined>;

/** Resident background daemons — the default `stop` target set.
 *  DELIBERATELY NOT LISTED: `mandu-inspect-mcp` — it is a per-SESSION stdio
 *  MCP child owned by a live agent process (claude spawns it from mcp.json),
 *  not a resident daemon; SIGTERMing it breaks that session's inspect_symbol
 *  tool while the session is still running. It dies with its owner (stdio
 *  EOF); `--all` can still sweep orphaned survivors. */
const RESIDENT_TITLES = [
  "mandu-arbiter",
  "mandu-anthropic-proxy",
  "mandu-openai-proxy",
  "mandu-net-proxy",
  "mandu-dashboard",
];

export interface Proc { pid: number; title: string; container?: boolean }

/** Injectable process ops so status/stop are unit-testable without a real ps/kill. */
export interface ProcOps {
  list: () => Proc[];
  kill: (pid: number, sig: NodeJS.Signals) => void;
  /** The stack (runtime base) a process belongs to, or null when that cannot
   *  be told; `bases` are the stacks whose registries may name it. Absent =
   *  unknown for every process. */
  stackOf?: (pid: number, bases: readonly string[]) => string | null;
  /** The operator's stack (`operatorStack`). Absent = the env's default
   *  (`defaultStack`), so a mock that names none keeps its caller the
   *  operator; the real ops read it from the OS. */
  operatorStack?: (env: Env) => string;
}

/** The arbiter socket this deployment would use (arbiter-sock.ts — the same
 *  env → `current` → legacy order the launch itself resolves; these verbs
 *  used to hardcode the legacy fixed path and misreport a promoted arbiter). */
function arbiterSock(env: Env): string {
  return resolveArbiterSock(env).sock;
}

/** Parse `ps -o pid=,args=` output into mandu-titled procs, excluding selfPid.
 *  Pure (testable): the title lands in argv/cmdline via process.title; trailing
 *  NUL/space padding is trimmed. */
export function parsePsLines(stdout: string, selfPid: number): Proc[] {
  const out: Proc[] = [];
  for (const line of stdout.split("\n")) {
    const m = line.match(/^\s*(\d+)\s+(.*)$/);
    if (!m) continue;
    const pid = Number(m[1]);
    const title = m[2]!.trim();
    if (pid === selfPid) continue;
    if (title === "mandu" || title.startsWith("mandu-")) out.push({ pid, title });
  }
  return out;
}

/** True when a `/proc/<pid>/cgroup` body places the process inside a container
 *  (docker/containerd/podman/k8s scopes). CI and the dashboard's docker e2e
 *  runner run Mandu stacks in containers under this SAME uid (`docker run
 *  --user`), and their pids are visible+signalable from the host — so a bare
 *  uid+title sweep would SIGTERM a CI job's daemons mid-run. The cgroup path
 *  is the host-visible marker that a pid belongs to a container's stack, not
 *  this host's. Pure (testable). */
export function isContainerCgroup(cgroupText: string): boolean {
  return /(^|\/)(docker[-/]|libpod-|containerd[-/]|kubepods|lxc[./])/m.test(cgroupText);
}

/** The subset of `procs` that `stop` signals: resident daemons, or all mandu
 *  procs under `--all` — NEVER container-scoped procs (see isContainerCgroup).
 *  Pure (testable). */
export function stopTargets(procs: Proc[], all: boolean): Proc[] {
  return procs.filter((p) => !p.container && (all ? true : RESIDENT_TITLES.includes(p.title)));
}

/** Container-scoped procs that WOULD have matched `stop` — reported to the
 *  operator, never signalled (they belong to a CI / docker-e2e stack whose
 *  lifecycle is the container's `--rm --init`, not ours). Pure (testable). */
export function containerSkips(procs: Proc[], all: boolean): Proc[] {
  return procs.filter((p) => p.container && (all ? true : RESIDENT_TITLES.includes(p.title)));
}

/** A stack's identity: its runtime base, absolute, without a trailing slash. */
export function normStack(base: string): string {
  return resolve(base).replace(/\/+$/, "") || "/";
}

/** The stack the environment selects when it names none (MANDU_RUNTIME_DIR
 *  unset), `$XDG_RUNTIME_DIR/mandu` on a usual host. It follows the caller's
 *  env, so an isolated XDG_RUNTIME_DIR or TMPDIR moves it too: `stop` asks
 *  `operatorStack` who the operator is. */
export function defaultStack(env: Env): string {
  return normStack(runtimeBase({ ...env, MANDU_RUNTIME_DIR: undefined }));
}

/** The host facts `operatorStack` reads, injectable for tests. */
export interface OperatorStackDeps {
  platform?: string;
  /** Default process.getuid(); null = unknown. */
  uid?: number | null;
  isDir?: (p: string) => boolean;
  darwinTempDir?: () => string;
}

function isDirReal(p: string): boolean {
  try { return statSync(p).isDirectory(); } catch { return false; }
}

/**
 * The OPERATOR's stack: the one this account's own login session selects,
 * read from the OS, never from the caller's env (runtime-instances.md §10.3).
 * Linux: `/run/user/<uid>/mandu` when logind made `/run/user/<uid>`; macOS:
 * the account's rendezvous (DARWIN_USER_TEMP_DIR's rule, in practice
 * `/tmp/mandu-<uid>`). Elsewhere (no logind dir, no uid) the env's default,
 * as before. A caller whose env selects any OTHER stack is isolated, however
 * it got there: MANDU_RUNTIME_DIR (2026-10-04), or an XDG_RUNTIME_DIR or
 * TMPDIR of its own (2026-10-09: a test harness's `XDG_RUNTIME_DIR=<own dir>
 * mandu stop` SIGTERMed the systemd dashboard and two live drill runs'
 * arbiters, whose OpenClaw sessions then failed closed).
 */
export function operatorStack(env: Env, deps: OperatorStackDeps = {}): string {
  const platform = deps.platform ?? process.platform;
  const uid = deps.uid !== undefined ? deps.uid : (typeof process.getuid === "function" ? process.getuid() : null);
  if (uid !== null) {
    if (platform === "darwin") {
      return normStack(accountRendezvous(uid, { platform, ...(deps.darwinTempDir ? { darwinTempDir: deps.darwinTempDir } : {}) }));
    }
    if (platform === "linux" && (deps.isDir ?? isDirReal)(`/run/user/${uid}`)) {
      return normStack(accountRendezvous(uid, { platform }));
    }
  }
  return defaultStack(env);
}

/** A `/proc/<pid>/environ` body as an env. Pure (testable). */
export function parseEnviron(text: string): Env {
  const env: Env = {};
  for (const kv of text.split("\0")) {
    const i = kv.indexOf("=");
    if (i > 0) env[kv.slice(0, i)] = kv.slice(i + 1);
  }
  return env;
}

/** The pids a stack's registry names (runtime-instances.md §10): its arbiter
 *  instances, its dashboards, and its sessions' launchers (scope run dirs
 *  `<epochSec>-<pid>`). */
export function registeredPids(base: string): number[] {
  const pids: number[] = [];
  let ids: string[] = [];
  try { ids = readdirSync(join(base, "instances")); } catch { /* none */ }
  for (const id of ids) {
    const m = readManifestLite(join(base, "instances", id));
    if (m) pids.push(m.pid);
  }
  let dashes: string[] = [];
  try { dashes = readdirSync(join(base, "dashboards")); } catch { /* none */ }
  for (const name of dashes.filter((n) => n.endsWith(".json"))) {
    const m = readDashManifestLite(join(base, "dashboards", name));
    if (m) pids.push(m.pid);
  }
  let names: string[] = [];
  try { names = readdirSync(base); } catch { /* none */ }
  for (const name of names) {
    const m = /^\d+-(\d+)$/.exec(name);
    if (m) pids.push(Number(m[1]));
  }
  return pids;
}

/** May `base`'s registry say which stack a process is in? Only a real
 *  directory of this uid, and, directly in a shared sticky dir (/tmp), one
 *  no other account can write (runtime-base.ts ownedDirProblem, the
 *  launcher's rule for such a base, runtime-instances.md §3b): entries in a
 *  `/tmp/mandu` another user made first are anyone's, and would let them
 *  move a process from one stack to another in `mandu stop`'s plan. An
 *  absent base has no registry to read. */
export function registryTrusted(
  base: string,
  lstat: (p: string) => DirStat = (p) => lstatSync(p),
  statMode: (p: string) => number = (p) => statSync(p).mode,
): boolean {
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  try {
    const st = lstat(base);
    if (st.isSymbolicLink() || !st.isDirectory() || (uid !== null && st.uid !== uid)) return false;
    let sharedParent = false;
    try { sharedParent = isSharedStickyMode(statMode(dirname(resolve(base)))); } catch { /* no parent: nothing shared */ }
    return !sharedParent || ownedDirProblem(st, uid) === null;
  } catch {
    return false;
  }
}

/** Which stack a live process belongs to: the runtime base its own
 *  environment selects (the same resolution its arbiter, dashboard or launch
 *  used), else the stack among `bases` whose registry names its pid, else
 *  null. An unreadable environ (another user's process, one gone meanwhile)
 *  with no registry entry stays unknown, and so does one only an untrusted
 *  registry names (registryTrusted). */
function realStackOf(pid: number, bases: readonly string[]): string | null {
  try {
    const env = parseEnviron(readFileSync(`/proc/${pid}/environ`, "utf8"));
    if (env["MANDU_RUNTIME_DIR"] || env["XDG_RUNTIME_DIR"] || env["HOME"]) return normStack(runtimeBase(env));
  } catch { /* fall through to the registries */ }
  for (const base of bases) if (registryTrusted(base) && registeredPids(base).includes(pid)) return normStack(base);
  return null;
}

/** Which processes `stop` aims at: every stack of this user (the bare form),
 *  every stack said explicitly (`--every-stack`), or one stack (`--stack`). */
export type StopScope = { kind: "user" } | { kind: "every" } | { kind: "stack"; base: string };

/** `mandu stop` arguments; an error string for a malformed one. Pure. */
export function parseStopArgs(rest: string[], cwd: string = process.cwd()): { all: boolean; scope: StopScope } | { error: string } {
  let all = false;
  let every = false;
  let stack: string | null = null;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === "--all") all = true;
    else if (a === "--every-stack") every = true;
    else if (a === "--stack" || a.startsWith("--stack=")) {
      const v = a === "--stack" ? rest[++i] : a.slice("--stack=".length);
      if (!v || v.startsWith("--")) return { error: "--stack needs the runtime dir of the stack to stop" };
      stack = v;
    }
  }
  if (every && stack !== null) return { error: "--stack and --every-stack contradict each other; give one" };
  const scope: StopScope = stack !== null ? { kind: "stack", base: normStack(resolve(cwd, stack)) } : every ? { kind: "every" } : { kind: "user" };
  return { all, scope };
}

export interface StopPlanInput {
  procs: Proc[];
  all: boolean;
  scope: StopScope;
  /** The stack the caller's environment selects, and the operator's
   *  (`operatorStack`; named `defaultStack` here for the bare form's sake). */
  callerStack: string;
  defaultStack: string;
  stackOf: (pid: number) => string | null;
}

export interface StopPlan {
  targets: Proc[];
  /** Matched, container-scoped: reported, never signalled. */
  containerSkips: Proc[];
  /** Matched, of another stack, left alone (`--stack`). */
  otherStacks: Proc[];
  /** Set when a bare stop is refused: the targets outside the caller's stack. */
  refused?: Array<Proc & { stack: string | null }>;
}

/**
 * What `stop` signals (runtime-instances.md §10.3). The bare form keeps its
 * meaning, every stack of this user, for a caller on the default stack (the
 * operator). A caller whose environment selects ANOTHER stack (an isolated
 * MANDU_RUNTIME_DIR, XDG_RUNTIME_DIR or TMPDIR: a benchmark, a test, a second
 * stack; `operatorStack` says which is the operator's) is refused when the
 * sweep would reach a process outside that stack, an unknown one included:
 * it named its own stack, and a sweep from it once stopped the shared stack
 * and two live sessions (2026-10-04). `--stack` signals only the named
 * stack's processes, an unknown one never; `--every-stack` is the sweep, said
 * explicitly. Container-scoped processes are never signalled. Pure.
 */
export function planStop(i: StopPlanInput): StopPlan {
  const host = stopTargets(i.procs, i.all);
  const plan: StopPlan = { targets: host, containerSkips: containerSkips(i.procs, i.all), otherStacks: [] };
  if (i.scope.kind === "stack") {
    const base = i.scope.base;
    plan.targets = host.filter((p) => i.stackOf(p.pid) === base);
    plan.otherStacks = host.filter((p) => i.stackOf(p.pid) !== base);
  } else if (i.scope.kind === "user" && i.callerStack !== i.defaultStack) {
    const foreign = host.map((p) => ({ ...p, stack: i.stackOf(p.pid) })).filter((p) => p.stack !== i.callerStack);
    if (foreign.length > 0) { plan.targets = []; plan.refused = foreign; }
  }
  return plan;
}

/** Best-effort container check for a live pid; a vanished /proc entry reads as
 *  "not a container" — the subsequent kill just ESRCHes harmlessly. */
function pidInContainer(pid: number): boolean {
  try {
    return isContainerCgroup(readFileSync(`/proc/${pid}/cgroup`, "utf8"));
  } catch {
    return false;
  }
}

/** Enumerate this user's `mandu*` processes by ps title, excluding this process. */
function manduProcs(): Proc[] {
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  const args = ["-o", "pid=,args="];
  if (uid !== undefined) args.push("-u", String(uid));
  const r = spawnSync("ps", args, { encoding: "utf8" });
  if (r.status !== 0 || !r.stdout) return [];
  return parsePsLines(r.stdout, process.pid).map((p) => ({ ...p, container: pidInContainer(p.pid) }));
}

const realProcOps: ProcOps = {
  list: manduProcs,
  kill: (pid, sig) => process.kill(pid, sig),
  stackOf: realStackOf,
  operatorStack: (env) => operatorStack(env),
};

/** Injectable pieces of `mandu status` (tests never touch a real registry). */
export interface StatusOpts {
  ops?: ProcOps;
  verbose?: boolean;
  reapDeps?: ReapDeps;
  out?: (s: string) => void;
}

/** "2 services from ended sessions, 1 stale record": what `mandu reap`
 *  would clean, grouped the way a user thinks about it. Pure. */
export function leftoverSummary(actions: ReapAction[]): string | null {
  const services = actions.filter((a) => a.kind === "kill-orphan-arbiter" || a.kind === "kill-orphan-dashboard").length;
  const vms = actions.filter((a) => a.kind === "kill-orphan-guest").length;
  const records = actions.length - services - vms;
  const parts: string[] = [];
  if (services > 0) parts.push(`${services} service${services === 1 ? "" : "s"} from ended sessions`);
  if (vms > 0) parts.push(`${vms} test VM${vms === 1 ? "" : "s"} from ended runs`);
  if (records > 0) parts.push(`${records} stale record${records === 1 ? "" : "s"}`);
  return parts.length > 0 ? parts.join(", ") : null;
}

/**
 * `mandu status` — read-only. By default a plain summary (release checklist
 * d4): is Mandu running, where is the dashboard, is there anything left over
 * from ended sessions. `--verbose` adds the registry (every arbiter and
 * dashboard, with owner and liveness) and every Mandu process of this user,
 * which on a shared dev or CI host includes other stacks'.
 */
export async function runStatus(env: Env, opts: StatusOpts = {}): Promise<number> {
  const ops = opts.ops ?? realProcOps;
  const reapDeps = opts.reapDeps ?? realReapDeps;
  const out = opts.out ?? ((s: string) => { process.stdout.write(s); });
  const sock = arbiterSock(env);
  const arbiterUp = existsSync(sock) && await reapDeps.socketLive(sock);
  const dashes = liveDashboards(env, reapDeps.pidAlive);

  out(arbiterUp ? "Mandu is running.\n" : "Mandu is not running (the next launch starts it).\n");
  out(`  arbiter:   ${arbiterUp ? "running" : "not running"} (${sock})\n`);
  if (dashes.length === 0) {
    out("  dashboard: not running (`mandu dashboard` starts one)\n");
  } else {
    const more = dashes.length > 1 ? ` (+${dashes.length - 1} more; --verbose lists them)` : "";
    out(`  dashboard: ${dashboardUrl(dashes[0]!)}${more}\n`);
  }
  const leftovers = leftoverSummary(await planReap(runtimeBase(env), reapDeps));
  if (leftovers !== null) {
    out(`  leftovers: ${leftovers} (\`mandu reap\` cleans them up; \`mandu reap --dry-run\` lists them)\n`);
  }
  if (!opts.verbose) {
    out("(`mandu status --verbose` lists every registered service and Mandu process)\n");
    return 0;
  }

  // The instance registry (runtime-instances.md §10): every arbiter — pinned
  // or instance-mode — registers here, so orphans are visible by name.
  const instances = listInstances(env, reapDeps);
  if (instances.length > 0) {
    out(`registered arbiters (${instances.length}):\n${instances.join("\n")}\n`);
  }
  // Dashboards register too (2026-07-19 — five side-by-side dashboards, four
  // stale on forgotten ports, were invisible to every enumeration surface).
  const dashboards = listDashboards(env, reapDeps);
  if (dashboards.length > 0) {
    out(`registered dashboards (${dashboards.length}):\n${dashboards.join("\n")}\n`);
  }
  const procs = ops.list().sort((a, b) => a.title.localeCompare(b.title) || a.pid - b.pid);
  if (procs.length === 0) {
    out("Mandu processes: none running\n");
    return 0;
  }
  out(`Mandu processes of this user, any stack (${procs.length}):\n`);
  for (const p of procs) {
    out(`  ${String(p.pid).padStart(7)}  ${p.title}${p.container ? "  (container)" : ""}\n`);
  }
  return 0;
}

/**
 * `mandu stop` — SIGTERM the resident daemons (default) or every mandu
 * process (`--all`, includes launchers + per-session helpers), of every stack
 * of this user; `--stack <runtime dir>` limits it to one stack, and a caller
 * on an isolated stack must say which it means (planStop). Read-only-safe:
 * prints what it signals; never touches other users' processes, this process,
 * or container-scoped procs (a CI / docker-e2e stack runs under this uid with
 * host-visible pids — signalling it would kill someone else's run mid-test).
 */
export async function runStop(
  rest: string[],
  env: Env,
  ops: ProcOps = realProcOps,
  out: (s: string) => void = (s) => { process.stdout.write(s); },
  err: (s: string) => void = (s) => { process.stderr.write(s); },
): Promise<number> {
  const args = parseStopArgs(rest);
  if ("error" in args) {
    err(`mandu stop: ${args.error}\n`);
    return 2;
  }
  const { all, scope } = args;
  const callerStack = normStack(runtimeBase(env));
  const dflt = ops.operatorStack ? ops.operatorStack(env) : defaultStack(env);
  const bases = [...new Set([callerStack, dflt, ...(scope.kind === "stack" ? [scope.base] : [])])];
  const stackOf = (pid: number): string | null => ops.stackOf?.(pid, bases) ?? null;
  const plan = planStop({ procs: ops.list(), all, scope, callerStack, defaultStack: dflt, stackOf });
  if (plan.refused) {
    const flag = all ? " --all" : "";
    err(
      `mandu stop: refused. This environment selects the stack at ${callerStack} (through its MANDU_RUNTIME_DIR, ` +
        `XDG_RUNTIME_DIR or TMPDIR), not this account's own at ${dflt}, ` +
        `but a bare \`mandu stop\` signals every stack of this user, and ${plan.refused.length} of its ` +
        `target(s) belong to another stack:\n`,
    );
    for (const p of plan.refused) {
      err(`  ${String(p.pid).padStart(7)}  ${p.title}  (${p.stack ?? "stack unknown"})\n`);
    }
    err(`Stop only this environment's stack:  mandu stop${flag} --stack ${callerStack}\n`);
    err(`Stop every stack anyway:             mandu stop${flag} --every-stack\n`);
    return 2;
  }
  for (const p of plan.containerSkips) {
    out(
      `  (skip)  ${String(p.pid).padStart(7)}  ${p.title} — container-scoped (owned by a CI/docker stack)\n`,
    );
  }
  const of = scope.kind === "stack" ? ` of the stack at ${scope.base}` : "";
  const left = plan.otherStacks.length > 0 ? ` (${plan.otherStacks.length} of other stacks left running)` : "";
  if (plan.targets.length === 0) {
    out(
      all ? `no mandu processes${of} to stop${left}\n` : `no resident mandu daemons${of} to stop (try --all)${left}\n`,
    );
    return 0;
  }
  let signalled = 0;
  for (const p of plan.targets) {
    try {
      ops.kill(p.pid, "SIGTERM");
      out(`  SIGTERM ${String(p.pid).padStart(7)}  ${p.title}\n`);
      signalled++;
    } catch (e) {
      out(`  (skip)  ${String(p.pid).padStart(7)}  ${p.title} — ${(e as Error).message}\n`);
    }
  }
  out(`stopped ${signalled} process(es)${of}${all ? "" : " (resident daemons; --all also stops launchers)"}${left}\n`);
  return 0;
}

/**
 * The other `mandu` sessions of this user on the stack at `base`: launchers
 * (title exactly `mandu`, runtime-instances.md §7) whose stack is `base`, read
 * as `stop` reads it (a session's own environment, else the stack's registry,
 * where every launch has its `<epochSec>-<pid>` scope dir, §10.4). A
 * container-scoped one belongs to another stack. Short-lived verbs (`mandu
 * status`) carry the title too and count: a refusal is the safe side. Used by
 * the release check (arbiter-version.ts) before it restarts a stack.
 */
export function liveLaunchersOn(base: string, ops: ProcOps = realProcOps): number[] {
  const stack = normStack(base);
  return ops.list()
    .filter((p) => p.title === "mandu" && !p.container && ops.stackOf?.(p.pid, [stack]) === stack)
    .map((p) => p.pid);
}

/** The pids of the resident daemons (arbiter, proxies, dashboard) of the
 *  stack at `base`, a container's excepted: what a systemd service may run
 *  (stack-supervisor.ts). */
export function residentPidsOn(base: string, ops: ProcOps = realProcOps): number[] {
  const stack = normStack(base);
  return ops.list()
    .filter((p) => RESIDENT_TITLES.includes(p.title) && !p.container && ops.stackOf?.(p.pid, [stack]) === stack)
    .map((p) => p.pid);
}

/**
 * Stop the resident daemons of the stack at `base` (what `mandu stop --stack
 * <base>` signals: SIGTERM, never a container's) and wait up to `waitMs` for
 * them to exit. Returns the pids signalled and those still alive at the end.
 */
export async function stopStackAndWait(
  base: string,
  waitMs = 15_000,
  ops: ProcOps = realProcOps,
  pidAlive: (pid: number) => boolean = realReapDeps.pidAlive,
): Promise<{ stopped: number[]; survivors: number[] }> {
  const stack = normStack(base);
  const plan = planStop({
    procs: ops.list(), all: false, scope: { kind: "stack", base: stack }, callerStack: stack, defaultStack: stack,
    stackOf: (pid) => ops.stackOf?.(pid, [stack]) ?? null,
  });
  const stopped: number[] = [];
  for (const p of plan.targets) {
    try { ops.kill(p.pid, "SIGTERM"); stopped.push(p.pid); } catch { /* already gone */ }
  }
  const deadline = Date.now() + waitMs;
  let survivors = stopped.filter(pidAlive);
  while (survivors.length > 0 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 100));
    survivors = survivors.filter(pidAlive);
  }
  return { stopped, survivors };
}

/** A registered dashboard this user runs (registry.ts manifest, lite). */
export interface LiveDashboard { id: string; pid: number; host: string; port: number; basePath?: string; signInSock?: string }

/** The URL a user opens for a registered dashboard: loopback for a wildcard
 *  bind, the dashboard's own base path (registry entry; entries from before
 *  2026-09-26 carry none and were served under /mandu), and a trailing /. */
export function dashboardUrl(d: { host: string; port: number; basePath?: string }): string {
  const prefix = (d.basePath ?? "/mandu").replace(/\/+$/, "");
  return `http://${connectHost(d.host)}:${d.port}${prefix}/`;
}

/** This user's registered dashboards whose process is alive, newest first. */
export function liveDashboards(env: Env, pidAlive: (pid: number) => boolean = realReapDeps.pidAlive): LiveDashboard[] {
  return registeredDashboards(env).filter((d) => pidAlive(d.pid));
}

/** Injectable I/O for `mandu dashboard` (tests never touch a real port). */
export interface DashboardDeps {
  /** Registered dashboards of THIS user (their runtime base), newest first. */
  registered: (env: Env) => LiveDashboard[];
  pidAlive: (pid: number) => boolean;
  probePort: (host: string, port: number) => Promise<boolean>;
  /** Start the dashboard daemon; returns a stop() for a failed start. */
  start: (env: Record<string, string | undefined>, logPath: string) => { stop: () => void };
  waitFor: (pred: () => Promise<boolean> | boolean) => Promise<boolean>;
  readPortFile: (path: string) => number | null;
  sockExists: (sock: string) => boolean;
  out: (s: string) => void;
  err: (s: string) => void;
  /** Size of the log before a start, and what the start appended (the
   *  failure line, release checklist d6). Optional: absent = no reason. */
  logSize?: (path: string) => number;
  logSince?: (path: string, offset: number) => string | null;
  /** Make the runtime dir safe to write under (default: runtime-base.ts
   *  ensurePrivateIfFallback — the /tmp fallback created 0700 or verified
   *  private, runtime-instances.md §3b). Throws to refuse. */
  ensureRuntimeDir?: (dir: string) => void;
  /** Whether stdout is a terminal (the sign-in link is printed only there,
   *  or with MANDU_PRINT_SIGNIN_LINK=1). Optional: absent = not a terminal. */
  isTTY?: boolean;
  /** Ask a dashboard's sign-in socket for a one-time link
   *  (dashboard-sign-in.ts requestSignInLink). Optional: absent = no link. */
  signIn?: (d: LiveDashboard, env: Env) => Promise<SignInOutcome>;
}

/** The runtime registry the dashboard writes (dashboard/src/registry.ts,
 *  runtime-instances.md §10): `<runtimeBase>/dashboards/<id>.json`. Per user
 *  by construction (the runtime base lives under XDG_RUNTIME_DIR, the
 *  per-user TMPDIR, or the private 0700 /tmp/mandu-<uid>, §3b). */
export function registeredDashboards(env: Env): LiveDashboard[] {
  const dir = join(runtimeBase(env), "dashboards");
  let names: string[] = [];
  try { names = readdirSync(dir); } catch { return []; }
  const out: LiveDashboard[] = [];
  for (const name of names.filter((n) => n.endsWith(".json")).sort().reverse()) {
    const m = readDashManifestLite(join(dir, name));
    if (!m || typeof m.port !== "number" || m.port <= 0) continue;
    out.push({
      id: name.replace(/\.json$/, ""), pid: m.pid, host: m.host ?? "127.0.0.1", port: m.port,
      ...(typeof m.basePath === "string" ? { basePath: m.basePath } : {}),
      ...(typeof m.signInSock === "string" ? { signInSock: m.signInSock } : {}),
    });
  }
  return out;
}

/** A wildcard bind is reached over loopback. */
function connectHost(host: string): string {
  return host === "0.0.0.0" || host === "::" || host === "" ? "127.0.0.1" : host;
}

function realDashboardDeps(layout: Layout): DashboardDeps {
  return {
    registered: registeredDashboards,
    pidAlive: realReapDeps.pidAlive,
    probePort: (h, p) => realDeps.probePort(h, p),
    start: (daemonEnv, logPath) => {
      const spec = layout.daemon("dashboard", "dashboard");
      return realDeps.startDetachedCmd(spec.cmd, spec.args, { cwd: spec.cwd, env: { ...daemonEnv, ...spec.env } }, logPath);
    },
    waitFor: (pred) => realDeps.waitFor(pred, { tries: 100, delayMs: 100 }),
    readPortFile: (path) => {
      try {
        const n = Number(readFileSync(path, "utf8").trim());
        return Number.isInteger(n) && n > 0 && n <= 65535 ? n : null;
      } catch { return null; }
    },
    sockExists: (sock) => existsSync(sock),
    logSize: (path) => { try { return statSync(path).size; } catch { return 0; } },
    logSince: (path, offset) => {
      try { const b = readFileSync(path); return b.subarray(Math.min(offset, b.length)).toString("utf8"); } catch { return null; }
    },
    out: (m) => { process.stdout.write(m); },
    err: (m) => { process.stderr.write(m); },
    isTTY: process.stdout.isTTY === true,
    signIn: (d, env) => requestSignInLink(d, runtimeBase(env)),
  };
}

/**
 * `mandu dashboard` — attach to this user's dashboard, or start one, and
 * print its URL (release checklist a1, runtime-instances.md §8).
 *
 * The port is NOT a fixed 4500 any more. A fixed port on a shared host
 * belongs to whoever bound it first: another user's dashboard answered a
 * second user's `mandu dashboard` as "already up" (a stranger's URL), and a
 * resident deployment made every other stack's dashboard fail to bind. Now:
 *   1. DASHBOARD_PORT unset (no env, no config `dashboard-port`): REUSE a live
 *      dashboard from this user's runtime registry (its pid alive AND its
 *      port answering; the newest wins), else START one on a kernel-assigned
 *      port (DASHBOARD_PORT=0, published through MANDU_PORT_FILE) — the
 *      dashboard registers the bound port itself, so the next call reuses it.
 *      An explicit DASHBOARD_PORT=0 means the same ("any free port").
 *   2. DASHBOARD_PORT pinned to a real port: that port. A listener there is adopted only when
 *      it is one of this user's registered dashboards; anything else is a
 *      refusal naming the conflict (never a stranger's URL).
 * A dashboard run directly (`npm run serve`, a systemd unit) keeps its own
 * default of 4500 — the resident deployment's bookmark — and, registered like
 * every dashboard, is what step 1 finds.
 */
export async function runDashboard(
  rest: string[],
  env: Env,
  layout: Layout,
  deps: DashboardDeps = realDashboardDeps(layout),
): Promise<number> {
  const host = env["DASHBOARD_HOST"] || "127.0.0.1";
  // The prefix a dashboard started here serves under (the dashboard's own
  // default is none); a dashboard found in the registry carries its own.
  const basePath = env["DASHBOARD_BASE_PATH"] ?? "";
  const urlOf = (h: string, port: number): string => dashboardUrl({ host: h, port, basePath });
  const pinnedRaw = env["DASHBOARD_PORT"] ?? "";
  const pinned = pinnedRaw !== "";
  const port = pinned ? Number(pinnedRaw) : 0;
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    deps.err(`mandu: DASHBOARD_PORT must be a port number 0..65535 (0 = a free port), got '${pinnedRaw}'\n`);
    return 2;
  }

  // The registry and the arbiter rendezvous live under the runtime base: a
  // shared-/tmp fallback that is not a private dir of this uid is refused
  // before an entry in it is trusted — it could hand the user a stranger's
  // dashboard URL (resolveArbiterSock verifies it, runtime-instances.md §3b).
  let sock: string;
  try {
    sock = arbiterSock(env);
  } catch (err) {
    deps.err(`${(err as Error).message}\n`);
    return 1;
  }

  // This user's live dashboards: registered, pid alive, port answering.
  const live: LiveDashboard[] = [];
  for (const d of deps.registered(env)) {
    if (!deps.pidAlive(d.pid)) continue;
    if (await deps.probePort(connectHost(d.host), d.port)) live.push(d);
  }

  if (pinned && port !== 0) {
    if (await deps.probePort(host, port)) {
      const mine = live.find((d) => d.port === port);
      if (mine) {
        deps.out(`dashboard already up — ${dashboardUrl(mine)}\n`);
        await printSignIn(mine, env, deps);
        return 0;
      }
      deps.err(
        `mandu: ${host}:${port} is in use by something that is not one of your Mandu dashboards — ` +
        `refusing to point you at it. Unset DASHBOARD_PORT (a free port is picked) or pin another one.\n`,
      );
      return 1;
    }
  } else if (port === 0 && live.length > 0) {
    // Unset, or an explicit 0 ("any free port"): reuse before starting another.
    const d = live[0]!;
    deps.out(`dashboard already up — ${dashboardUrl(d)}\n`);
    await printSignIn(d, env, deps);
    return 0;
  }

  if (!deps.sockExists(sock)) {
    deps.err(
      `mandu: arbiter socket ${sock} is absent — start a session first (mandu claude …) ` +
      `or point MANDU_ARBITER_SOCK at a running arbiter.\n`,
    );
    return 2;
  }

  // The runtime base: the path table's `runtime-dir` (arbiter-sock.ts), the
  // same root the scope dirs use; the shared-/tmp fallback is made private
  // (0700, this uid) before anything is written under it (runtime-base.ts,
  // runtime-instances.md §3b).
  const base = runtimeBase(env);
  try {
    (deps.ensureRuntimeDir ?? ((d: string) => ensurePrivateIfFallback(d, env)))(base);
  } catch (err) {
    deps.err(`mandu: ${(err as Error).message}\n`);
    return 1;
  }
  const logPath = `${base}/dashboard.log`;
  // Port 0: the kernel picks, the dashboard publishes the bound port here
  // (server-main's atomic tmp+rename) — the same rendezvous the proxies use.
  const portFile = port === 0 ? `${base}/dashboard-${process.pid}.port` : undefined;
  if (portFile) rmSync(portFile, { force: true });
  const daemonEnv: Record<string, string | undefined> = {
    ...process.env,
    MANDU_ARBITER_SOCK: sock,
    DASHBOARD_HOST: host,
    DASHBOARD_PORT: String(port),
    DASHBOARD_BASE_PATH: basePath,
    MANDU_PORT_FILE: portFile,
    // Resident: this CLI exits right away, so it must not be the owner (reap
    // would stop the dashboard as an orphan the moment this command returns).
    MANDU_OWNER_PID: "none",
  };
  const logOffset = deps.logSize?.(logPath) ?? 0;
  const handle = deps.start(daemonEnv, logPath);
  const reason = (): string => {
    const why = lastStartFailure(deps.logSince?.(logPath, logOffset) ?? null);
    return why ? `: ${why}` : "";
  };

  let bound = port;
  if (portFile) {
    let got: number | null = null;
    await deps.waitFor(() => { got = deps.readPortFile(portFile); return got !== null; });
    rmSync(portFile, { force: true });
    if (got === null) {
      handle.stop();
      deps.err(`mandu: the dashboard did not start${reason()} (log: ${logPath})\n`);
      return 1;
    }
    bound = got;
  }
  const up = await deps.waitFor(() => deps.probePort(host, bound));
  if (!up) {
    handle.stop();
    deps.err(`mandu: the dashboard did not answer on ${host}:${bound}${reason()} (log: ${logPath})\n`);
    return 1;
  }
  deps.out(`dashboard up — ${urlOf(host, bound)}\n`);
  if (deps.signIn && wantsSignInLink(deps.isTTY, env)) {
    // The new dashboard registers itself (with its sign-in socket) just
    // after it publishes its port: wait for the entry.
    let entry: LiveDashboard | undefined;
    await deps.waitFor(() => { entry = deps.registered(env).find((d) => d.port === bound); return entry !== undefined; });
    if (entry) await printSignIn(entry, env, deps);
    else deps.err(`mandu: no sign-in link: the new dashboard did not register; ${SIGN_IN_HOW} once it has\n`);
  }
  return 0;
}

/**
 * Print a one-time sign-in link for `d` (policy-surface.md §2.6 "Signing
 * in"): to stdout, only when it is a terminal. Asked over the dashboard's
 * sign-in socket, which an agent's sandbox cannot reach: run from inside
 * one, this says so instead of printing a link.
 */
async function printSignIn(d: LiveDashboard, env: Env, deps: DashboardDeps): Promise<void> {
  if (!deps.signIn || !wantsSignInLink(deps.isTTY, env)) return;
  let outcome: SignInOutcome;
  try {
    outcome = await deps.signIn(d, env);
  } catch (e) {
    outcome = { kind: "unavailable", why: (e as Error).message };
  }
  switch (outcome.kind) {
    case "link":
      deps.out(`sign in (this link works once): ${outcome.url}\n`);
      return;
    case "password":
      deps.out("sign in with the dashboard's password\n");
      return;
    case "not-asked":
      return;
    case "refused":
      deps.err(`mandu: no sign-in link: ${outcome.why}\n`);
      return;
    case "unavailable":
      deps.err(
        `mandu: no sign-in link: ${outcome.why} (an agent's sandbox cannot reach the sign-in channel, by design: ` +
        "run `mandu dashboard` in your own terminal)\n",
      );
      return;
  }
}

/**
 * `mandu init` — write a commented config.toml (packaging.md §7). Skips an
 * existing file unless `--force`; the template is all-commented, so a fresh
 * config behaves exactly like no config (all defaults).
 */
export async function runInit(rest: string[], env: Env): Promise<number> {
  const path = configPath(env);
  if (!path) {
    process.stderr.write("mandu: cannot resolve a config path (set HOME or MANDU_HOME).\n");
    return 2;
  }
  if (existsSync(path) && !rest.includes("--force")) {
    process.stdout.write(`mandu: config already exists at ${path} (pass --force to overwrite).\n`);
    return 0;
  }
  try {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, DEFAULT_CONFIG_TOML);
  } catch (e) {
    process.stderr.write(`mandu: could not write ${path}: ${(e as Error).message}\n`);
    return 1;
  }
  process.stdout.write(`mandu: wrote ${path}\n  edit it to set per-user defaults (flags > env > config > defaults).\n`);
  return 0;
}

/** Dispatch a reserved subcommand. `rest` is the args after the verb. */
export async function runSubcommand(
  sub: string,
  rest: string[],
  env: Env,
  layout: Layout,
  /** env BEFORE config.toml was folded in (run.ts); `mode` reports from it. */
  userEnv?: Env,
): Promise<number> {
  // `mandu <verb> --help` prints the verb's usage and does nothing else
  // (subcommand-help.ts: several verbs used to ACT on it).
  const usage = wantsHelp(rest) ? subcommandUsage(sub) : null;
  if (usage !== null) { process.stdout.write(usage); return 0; }
  switch (sub) {
    case "status": return runStatus(env, { verbose: rest.includes("--verbose") || rest.includes("-v") });
    case "stop": return runStop(rest, env);
    case "dashboard": return runDashboard(rest, env, layout);
    case "doctor": return wantsSecrets(rest) ? runDoctorSecrets(rest, env, layout) : wantsLive(rest) ? runDoctorLive(env, layout, rest) : runDoctor(env, layout);
    case "init": return runInit(rest, env);
    case "reap":
      // Reap signals the pids the manifests under the base name: an untrusted
      // /tmp fallback is refused first (runtime-instances.md §3b).
      assertRuntimeBaseTrusted(env);
      return runReap(rest, env);
    case "setup": return runSetup(rest, realSetupDeps(layout));
    case "mode": return runMode(rest, env, userEnv ?? env);
    case "why": return runWhy(rest, env, layout);
    case "revert": return runRevert(rest, env, layout);
    case "demo": return runDemo(rest, env, layout);
    case "paths": return runPaths(rest, env);
    case "log": return runLog(rest, env);
    case "policy": return runPolicy(rest, env, layout);
    case "version": return runVersion(rest, env, layout);
    default:
      process.stderr.write(`mandu: unknown subcommand '${sub}'\n`);
      return 2;
  }
}
