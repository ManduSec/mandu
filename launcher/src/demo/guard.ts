/**
 * demo/guard — the whole-agent guard (`mandu-net-guard`) around the programs
 * the demo's agent runs, as a launch puts it around the agent
 * (docs/design/distribution/mandu-demo.md §3, "the guard").
 *
 * Why the demo needs it: Codex reads `.env` with its shell (`cat .env`), and
 * the arbiter shows a shell result per key only on the guard's evidence: it
 * recorded the call's process tree and no process in it opened a secret raw
 * (confidentiality-plan-10-flow-taint.md §11.8, "The twin in a shell
 * result"). With no guard the text alone is not enough, and the result is
 * one placeholder for the whole file.
 *
 * What is the launch's own code: the bin is resolved by the launch's
 * resolver (services/native-bins.ts), its allow rules and wrap argv come
 * from net-guard.ts (`computeNetGuardSpecs`, `planNetGuard`, with
 * `--skip-unsupported`), its policy file has the launch's shape
 * (guard-policy-file.ts `guardPolicyBase`, the secret entry of
 * secret-setup.ts), the status file is guard-death.ts's, and the guard finds
 * the arbiter's human plane from the data socket's `hello` as in a launch.
 * What the demo adds is only its stand-in agent: a node process (the policy's
 * `agentExe`) that runs each command as `sh -c <command>`, so the guard sees
 * the shell as the agent's own child, the call root a real agent's shell is.
 *
 * Mandu-new.
 */
import { realpathSync } from "node:fs";
import { dirname } from "node:path";
import { humanPlaneDirs } from "../human-plane.js";
import { computeNetGuardSpecs, NET_GUARD_PROXY_PORTS_ENV, planNetGuard, sessionProxyPorts } from "../net-guard.js";
import { NET_GUARD_STATUS_ENV } from "../guard-death.js";
import { guardPolicyBase } from "../guard-policy-file.js";
import { resolveNativeBin, staleNativeBinNote } from "../services/native-bins.js";
import type { AgentId } from "./render.js";

type Env = Record<string, string | undefined>;

/** Why the demo runs its commands without the guard. */
export type GuardAbsence =
  | "linux-only" //  not Linux: the guard is seccomp user notification
  | "not-built" //   Linux, but no mandu-net-guard bin resolves
  | "turned-off" //  MANDU_NET_GUARD=0, the launch's own opt-out
  | "kernel"; //     the bin ran but could not attach (it ran the command unguarded)

/** The guard found for this run, or why there is none. */
export type DemoGuardFind = { bin: string; stale?: string | null } | { absent: GuardAbsence };

/** `MANDU_NET_GUARD` as a launch reads it (parse.ts `truthy`): only "0"
 *  turns it off; unset or empty leaves the default (on). */
function turnedOff(env: Env): boolean {
  return env["MANDU_NET_GUARD"] === "0";
}

/** Find the guard as a launch does (net-guard-setup.ts: Linux only, the
 *  launch's resolver, the launch's opt-out). Pure over its inputs. */
export function findDemoGuard(
  platform: string,
  env: Env,
  resolve: () => string | null = () => resolveNativeBin("mandu-net-guard", { env }),
  stale: (bin: string) => string | null = (bin) => staleNativeBinNote("mandu-net-guard", bin),
): DemoGuardFind {
  if (platform !== "linux") return { absent: "linux-only" };
  if (turnedOff(env)) return { absent: "turned-off" };
  const bin = resolve();
  if (bin === null) return { absent: "not-built" };
  return { bin, stale: stale(bin) };
}

/** The plain-words line under a whole-file `.env` read (default output: no
 *  internals). */
export function wholeFileWhy(a: GuardAbsence): string {
  switch (a) {
    case "linux-only": return "the keys show only under Mandu's guard, which is Linux only";
    case "not-built": return "the keys show only under Mandu's guard, not built on this machine";
    case "turned-off": return "the keys show only under Mandu's guard, turned off (MANDU_NET_GUARD=0)";
    case "kernel": return "the keys show only under Mandu's guard, which this kernel cannot run";
  }
}

/** The agent stand-in under the guard (`node -e AGENT_RUNNER <command>`):
 *  runs the command as the agent runs a shell call, `sh -c <command>`, and
 *  prints what it returned as ONE JSON line, so the guard's own stderr never
 *  mixes into the tool result (in a launch it goes to the terminal). */
export const AGENT_RUNNER =
  'const r=require("node:child_process").spawnSync("sh",["-c",process.argv[1]],{encoding:"utf8",maxBuffer:1<<24});' +
  'process.stdout.write(JSON.stringify({code:r.status===null?1:r.status,stdout:r.stdout||"",stderr:(r.stderr||"")+(r.error?String(r.error):"")}));';

/** The agent's executable for the guard's policy (`agentExe`): the node
 *  that runs the stand-in, resolved as resolveAgentExe resolves an agent. */
export function agentExeOf(execPath: string = process.execPath): string {
  try { return realpathSync(execPath); } catch { return execPath; }
}

/** The model API host a launch admits on :443 for this agent
 *  (net-guard-setup.ts `apiHostFor`). */
function apiHost(agent: AgentId): string {
  return agent === "codex" ? "api.openai.com" : "api.anthropic.com";
}

/** One agent's guard: the policy file text and the wrap, as a launch builds
 *  them for that agent. Pure. */
export interface AgentGuard {
  /** guard-policy.json: the agent, its session, the registered `.env` and
   *  the agent's copy as its twin. */
  policy: string;
  /** `mandu-net-guard --allow … --skip-unsupported --` */
  wrapArgv: string[];
  /** The env the guard reads, without the per-command status file. */
  env: Record<string, string>;
}

export function agentGuard(opts: {
  bin: string;
  agent: AgentId;
  agentExe: string;
  session: string;
  policyPath: string;
  modelProxyPort: number;
  netProxyPort: number | null;
  envPath: string;
  agentEnvPath: string;
  /** The human-plane directories (human-plane.ts `humanPlaneDirs`): the
   *  guard's always-deny `unixDeny`, as `applyHumanPlaneDeny` writes it for a
   *  launch. Also what the guard checks its human socket against before it
   *  believes it (arbiter-human-plane.md §5.2): without it the guard reports
   *  on the data socket, and Codex's `.env` read is one placeholder. */
  humanPlaneDirs?: readonly string[];
}): AgentGuard {
  const specs = computeNetGuardSpecs({
    targetProxyPort: opts.modelProxyPort,
    netProxyPort: opts.netProxyPort,
    ullmForwarderPort: null,
    apiHost: apiHost(opts.agent),
    strict: false,
  });
  const { wrapArgv } = planNetGuard({ binPath: opts.bin, specs });
  const policy = {
    ...guardPolicyBase({ agentExe: opts.agentExe, session: opts.session }),
    // The secret entry applySecretTwins writes: the real file, the copy the
    // agent gets instead, its level.
    secrets: [{ path: opts.envPath, twin: opts.agentEnvPath, level: "no-model" }],
    ...((opts.humanPlaneDirs ?? []).length > 0 ? { unixDeny: [...opts.humanPlaneDirs!] } : {}),
  };
  return {
    policy: JSON.stringify(policy, null, 2),
    wrapArgv,
    env: {
      MANDU_NET_GUARD_SECRETS: opts.policyPath,
      [NET_GUARD_PROXY_PORTS_ENV]: sessionProxyPorts({ netProxyPort: opts.netProxyPort }).join(","),
      MANDU_SESSION_ID: opts.session,
    },
  };
}

/** The demo's human-plane directories, as a launch computes them
 *  (human-plane.ts `humanPlaneDirs`: the human socket's directory and
 *  `<runtime base>/human`); with no runtime base, the socket's directory
 *  alone. Pure. */
export function demoHumanPlaneDirs(humanSock: string | null, runtimeBase: string | undefined): string[] {
  if (runtimeBase) return humanPlaneDirs(humanSock, runtimeBase);
  return humanSock ? [dirname(humanSock)] : [];
}

/** The argv and env of one command under the guard. Pure. */
export function guardedRun(g: AgentGuard, agentExe: string, cmd: string, statusFile: string, env: Record<string, string>): { argv: string[]; env: Record<string, string> } {
  return {
    argv: [...g.wrapArgv, agentExe, "-e", AGENT_RUNNER, cmd],
    env: { ...env, ...g.env, [NET_GUARD_STATUS_ENV]: statusFile },
  };
}

/** Did the guard serve the run? It writes its status file only once it
 *  supervises the tree (`supervising …`, then `exited <code>`); a guard
 *  that could not attach (`--skip-unsupported`) runs the command without
 *  writing it. Pure. */
export function guardServed(status: string | null): boolean {
  return status !== null && /^(supervising|exited) /.test(status);
}

/** The stand-in's one JSON line back as a command result; null when it
 *  printed none (it did not run). Pure. */
export function parseRunnerOutput(stdout: string): { code: number; stdout: string; stderr: string } | null {
  try {
    const v = JSON.parse(stdout.trim()) as { code?: unknown; stdout?: unknown; stderr?: unknown };
    if (typeof v?.code !== "number" || typeof v.stdout !== "string" || typeof v.stderr !== "string") return null;
    return { code: v.code, stdout: v.stdout, stderr: v.stderr };
  } catch {
    return null;
  }
}
