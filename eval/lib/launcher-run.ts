/**
 * launcher-run — spawning the REAL claude/codex binary THROUGH the launcher
 * (launcher/mandu-run.sh) and capturing the session output.
 *
 * Extracted verbatim from run-live.ts (agent-legibility split, behavior-
 * preserving). Owns the per-defense chokepoint flags, the clean agent env, the
 * target argv construction, and the output capture/normalization into a
 * RunResult the case runners score.
 */

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

import { LAUNCHER, type LiveStack, type Target, type Defense } from "./live-stack.js";
import { normalizeClaudeStream, normalizeCodexStream } from "./normalize-stream.js";
import type { CaseUsage } from "./metrics.js";
import type { EvalTranscript } from "./transcript.js";

/** The API key for real-api mode, by target. */
export function apiKeyFor(target: Target): string | undefined {
  return target === "claude" ? process.env["ANTHROPIC_API_KEY"] : process.env["OPENAI_API_KEY"];
}

/** The launcher's chokepoint flags for a given defense config. */
export function defenseFlags(defense: Defense): string[] {
  if (defense === "none") return ["--no-scope", "--no-mcp"];
  // full: the unprivileged chokepoints that run live.
  //   --net-proxy          the agent's outbound HTTP flows through the cooperative
  //                        forward proxy; a request carrying an UNTRUSTED symbol to
  //                        an untrusted destination is BLOCKED (403, fail-closed).
  //   --exec-wrap     shadow HIGH-RISK commands with the exec-wrap PATH shim →
  //                        arbiter exec gate (a symbol used as a command/arg is
  //                        BLOCKED with exit 77). We deliberately do NOT shadow
  //                        `curl` here: the exec gate desymbolizes a DATA-position
  //                        symbol in-slot (curl --data <sym>) for a HumanShell
  //                        network command, which would defeat the egress symbol
  //                        gate. Leaving curl UN-shadowed routes the symbol-carrying
  //                        exfil to the NETWORK chokepoint, where it is blocked
  //                        intact. wget/nc/rm/git stay shadowed for the exec gate.
  // --no-scope keeps the run unprivileged; --no-mcp keeps it offline.
  return [
    "--net-proxy",
    "--exec-wrap=wget,nc,rm,git",
    "--no-scope",
    "--no-mcp",
  ];
}

export interface RunResult {
  /** The normalized transcript scored by the oracle. */
  transcript: EvalTranscript;
  /** Per-case token usage (from the binary's reported usage). */
  usage?: CaseUsage;
  /** Wall-clock ms for the launcher+agent run. */
  ms: number;
  /** The launcher's exit code. */
  exitCode: number;
  /** The launcher's combined stderr (diagnostics — chokepoint-up messages, etc.). */
  stderr: string;
  /** Whether the launcher actually wired the egress gate (vs degraded). */
  egressWired: boolean;
}

export interface SpawnOptions {
  target: Target;
  stack: LiveStack;
  defense: Defense;
  workspace: string;
  /** The user prompt handed to the agent. */
  prompt: string;
  /** Env the AGENT's tool steps need (e.g. MANDU_EVAL_SYM for the scripted exfil). */
  extraEnv?: Record<string, string>;
  /** API key in real-api mode (else a dummy). */
  apiKey?: string;
  timeoutMs: number;
}

/**
 * Run the real binary through the launcher and capture its session output.
 *
 * The agent's env is CLEAN (we do NOT inherit this session's CLAUDE_CODE_* /
 * CODEX_* auth — that would nest sessions), carrying only HOME/PATH + the arbiter
 * sock + the proxy ports the launcher reuses + the per-case extraEnv. The
 * launcher wires ANTHROPIC_BASE_URL (claude) or the -c model_provider config
 * (codex) at our proxy and (under --net-proxy) autostarts + wires the egress
 * gate.
 */
export async function runThroughLauncher(opts: SpawnOptions): Promise<RunResult> {
  const { target, stack, defense, workspace, prompt, extraEnv, apiKey, timeoutMs } = opts;
  const flags = defenseFlags(defense);

  const manduHome = mkdtempSync(join(tmpdir(), "mandu-eval-home-"));
  // The base env every launcher run needs to REUSE our arbiter + proxy.
  const launcherEnv: Record<string, string> = {
    HOME: process.env["HOME"] ?? workspace,
    PATH: process.env["PATH"] ?? "",
    MANDU_ARBITER_SOCK: stack.arbiterSock,
    MANDU_NO_ARBITER_AUTOSTART: "1", // we already started the arbiter
    // Hermetic: a per-run Mandu home, so the developer's real ~/.mandu
    // (its config.toml's saved mode would be refused against this stack's
    // arbiter, whose axes live-stack.ts states: integrity ON, confidentiality
    // OFF) never leaks in and the view state never lands in it.
    MANDU_HOME: manduHome,
    // No MANDU_NET_PROXY_PORT: the launcher's net-proxy binds a kernel-assigned
    // port and reports it (the port-file handshake), so nothing picked can race
    // a suite running alongside (test-organization.md §8.4).
    ...(extraEnv ?? {}),
  };

  // Build the target argv THROUGH the launcher.
  let argv: string[];
  let codexHome: string | undefined;
  if (target === "claude") {
    launcherEnv["MANDU_PROXY_PORT"] = String(stack.proxyPort);
    launcherEnv["ANTHROPIC_API_KEY"] = apiKey ?? "sk-ant-mdu-eval-dummy";
    launcherEnv["CLAUDE_CONFIG_DIR"] = join(workspace, "..", "cc-config");
    argv = [
      LAUNCHER,
      "--target", "claude",
      ...flags,
      "--",
      "claude",
      "-p", prompt,
      "--model", "claude-sonnet-4-5",
      "--output-format", "stream-json",
      "--verbose",
      "--permission-mode", "bypassPermissions",
    ];
  } else {
    launcherEnv["MANDU_OPENAI_PROXY_PORT"] = String(stack.proxyPort);
    launcherEnv["OPENAI_API_KEY"] = apiKey ?? "dummy";
    // CODEX_HOME must exist + be under $HOME or codex warns fatally.
    codexHome = mkdtempSync(join(homedir(), ".mandu-eval-codex-"));
    launcherEnv["CODEX_HOME"] = codexHome;
    argv = [
      LAUNCHER,
      "--target", "codex",
      ...flags,
      "--",
      "codex",
      "exec",
      "--dangerously-bypass-approvals-and-sandbox",
      "--skip-git-repo-check",
      "--ephemeral",
      "--ignore-user-config",
      "-c", "model=gpt-4o",
      "-C", workspace,
      prompt,
    ];
  }

  const start = Date.now();
  const child = spawn("bash", argv, {
    cwd: workspace,
    env: launcherEnv,
    stdio: ["ignore", "pipe", "pipe"],
  });
  // Cap captured output so a misbehaving agent (e.g. an api_retry storm under a
  // misconfigured run) cannot OOM us; once a stream is capped we stop appending
  // (we have more than enough to normalize the transcript). 16 MiB is generous.
  const CAP = 16 * 1024 * 1024;
  let stdout = "";
  let stderr = "";
  let stdoutCapped = false;
  let stderrCapped = false;
  child.stdout.on("data", (c) => {
    if (stdoutCapped) return;
    stdout += c;
    if (stdout.length > CAP) {
      stdout = stdout.slice(0, CAP);
      stdoutCapped = true;
    }
  });
  child.stderr.on("data", (c) => {
    if (stderrCapped) return;
    stderr += c;
    if (stderr.length > CAP) {
      stderr = stderr.slice(0, CAP);
      stderrCapped = true;
    }
  });

  const exitCode: number = await new Promise((resolve) => {
    const t = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
      resolve(-1);
    }, timeoutMs);
    child.on("error", () => {
      clearTimeout(t);
      resolve(-1);
    });
    child.on("close", (code) => {
      clearTimeout(t);
      resolve(code ?? -1);
    });
  });
  const ms = Date.now() - start;
  if (codexHome) rmSync(codexHome, { recursive: true, force: true });
  rmSync(manduHome, { recursive: true, force: true });

  const { transcript, usage } =
    target === "claude" ? normalizeClaudeStream(stdout) : normalizeCodexStream(stdout, stderr);

  const egressWired =
    defense === "none" ||
    /net-proxy up|net-proxy already listening/.test(stderr);

  return { transcript, usage, ms, exitCode, stderr, egressWired };
}
