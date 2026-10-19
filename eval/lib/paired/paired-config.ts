/** Explicit product comparison; no legacy full/none interpretation.
 * PROVENANCE: NEW Mandu code, launch shape adapted from launcher-live.ts.
 */
import { join } from "node:path";

export type PairSide = "unwrapped" | "wrapped-default";
export type PairMode = "prepare" | "scripted" | "real" | "subscription";

export interface PairConfig {
  model: string;
  inspectionModel: string;
  agentBinary: string;
  repoRoot: string;
  timeoutMs: number;
  /** Uses the logged-in first-party CLI on both model channels. */
  subscription?: boolean;
  /** The protection mode of the wrapped leg (protection-modes.md). Default:
   *  the shipping default, `secrets`. It sets BOTH the leg's arbiter axes
   *  (`wrappedAxes`) and the launcher's `--mode`, so the launcher's axis
   *  preflight can never refuse the leg for a mismatch. */
  wrappedMode?: WrappedMode;
}

export type WrappedMode = "secrets" | "injection" | "full";

/** The arbiter axes of a wrapped leg's mode. */
export function wrappedAxes(mode: WrappedMode = "secrets"): { integrity: boolean; confidentiality: boolean } {
  return { integrity: mode !== "secrets", confidentiality: mode !== "injection" };
}

/** A leg's dirs while it runs (leg-work.ts). `root` is the leg's RESULTS dir
 *  under the run's output dir, which the runner alone writes (reports, the
 *  runner-owned arbiter's DB and events, captures). Everything the agent under
 *  test touches sits in `work`, a short per-leg dir outside every Mandu home:
 *  a default output dir lies inside `~/.mandu`, which the agent may not reach
 *  (on-disk-layout.md §4), and is too deep for the 107-byte socket limit. */
export interface RunPaths {
  /** The leg's results dir, under the output dir. */
  root: string;
  /** The agent-facing work dir; the rest below live in it. */
  work: string;
  workspace: string;
  /** HOME (with its CLAUDE_CONFIG_DIR, XDG config and cache). */
  home: string;
  /** The wrapped leg's own MANDU_HOME. */
  manduHome: string;
  /** XDG_RUNTIME_DIR, and the launcher's MANDU_RUNTIME_DIR registry. */
  runtime: string;
  /** TMPDIR (tsx's IPC pipe). */
  tmp: string;
  /** The leg's arbiter socket. */
  sock: string;
}

export interface LaunchSpec {
  command: string;
  args: string[];
  env: Record<string, string>;
}

/** Allowlist intentionally excludes inherited agent, proxy, credential and policy configuration. */
export function baseEnvironment(paths: RunPaths, ambient: NodeJS.ProcessEnv): Record<string, string> {
  return {
    PATH: ambient.PATH ?? "/usr/bin:/bin",
    HOME: paths.home,
    PWD: paths.workspace,
    TMPDIR: paths.tmp,
    XDG_CONFIG_HOME: join(paths.home, ".config"),
    XDG_CACHE_HOME: join(paths.home, ".cache"),
    XDG_RUNTIME_DIR: paths.runtime,
    CLAUDE_CONFIG_DIR: join(paths.home, ".claude"),
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    DISABLE_AUTOUPDATER: "1",
    MAX_THINKING_TOKENS: "1024",
    LANG: "C.UTF-8",
  };
}

export function launchSpec(
  config: PairConfig, side: PairSide, paths: RunPaths, prompt: string,
  endpoints: { model: string; inspection: string; arbiterSock: string },
  ambient: NodeJS.ProcessEnv = process.env,
): LaunchSpec {
  const args = [
    "--model", config.model, "--output-format", "stream-json", "--verbose",
    "--permission-mode", "dontAsk", "--strict-mcp-config",
    "--tools", "Read,Write,Edit,Glob,Grep",
    "--allowedTools", "Read,Write,Edit,Glob,Grep,mcp__mandu-inspect__inspect_symbol",
    "--setting-sources", "", "-p", prompt,
  ];
  const env = baseEnvironment(paths, ambient);
  // Observers own real provider credentials; agents only see a local dummy.
  if (!config.subscription) env.ANTHROPIC_API_KEY = "sk-ant-mandu-benign-local";
  else {
    env.CLAUDE_CODE_MAX_OUTPUT_TOKENS = "4096";
    env.CLAUDE_CODE_MAX_RETRIES = "0";
  }
  if (side === "unwrapped") {
    env.ANTHROPIC_BASE_URL = endpoints.model;
    return { command: config.agentBinary, args, env };
  }
  Object.assign(env, {
    // A per-run Mandu home: no config.toml, and the view state lands in its state/.
    MANDU_HOME: paths.manduHome,
    MANDU_ARBITER_SOCK: endpoints.arbiterSock,
    MANDU_NO_ARBITER_AUTOSTART: "1",
    MANDU_TENANT: "test",
    MANDU_RUNTIME_DIR: join(paths.runtime, "registry"),
    MANDU_PROXY_PORT: "0", MANDU_OPENAI_PROXY_PORT: "0", MANDU_NET_PROXY_PORT: "0",
    MANDU_UPSTREAM: endpoints.model,
    MANDU_ULLM_BASE_URL: endpoints.inspection,
    ...(!config.subscription ? { MANDU_ULLM_API_KEY: "sk-ant-mandu-benign-local" } : {}),
    MANDU_ULLM_MODEL: config.inspectionModel,
  });
  return {
    command: join(config.repoRoot, "launcher/node_modules/.bin/tsx"),
    args: [join(config.repoRoot, "launcher/src/run.ts"), "--mode", config.wrappedMode ?? "secrets", "--target", "claude", "--", config.agentBinary, ...args],
    env,
  };
}

export function pairOrder(index: number): PairSide[] {
  return index % 2 === 0 ? ["unwrapped", "wrapped-default"] : ["wrapped-default", "unwrapped"];
}
