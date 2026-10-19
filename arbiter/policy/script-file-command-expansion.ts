/**
 * script-file-command-expansion — command rewriting (`python fix.py` → inline).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/script-file-command-expansion.ts
 *   Purpose: the COMMAND-REWRITING rule the design (§4) calls out — expand a
 *   direct script-file exec invocation (`python fix.py`, `bash run.sh`, a direct
 *   `./tool.py`) into the equivalent synthetic inline-code command
 *   (`python -c '<file content>'`). The expanded command is read from the
 *   TRUSTED view of the script (HumanView/agent-authored), so the exec analysis
 *   sees the actual code that will run and can apply the symbol-as-command
 *   detector to it. The returned normalized command is ANALYSIS-ONLY — callers
 *   must NOT replace the real exec command with it.
 *
 *   Adaptation for Mandu — FLAGGED:
 *     - No OpenClaw runtime coupling exists in this module (it imports only
 *       node fs/path/os + the lifted exec-identifier). Lifted verbatim aside
 *       from this header.
 *     - The `trustedPathFor` callback stays an injected dependency: the arbiter
 *       does not own the AgentView/HumanView worktree mapping (that is the
 *       fs-sync subagent's domain). The exec-supervisor passes a resolver that
 *       maps an abs script path to its trusted-view path, or null if the script
 *       is not in a tracked/trusted location (→ no expansion, fail-closed).
 */

import { readFileSync, statSync } from "fs";
import { extname, isAbsolute, resolve } from "path";
import { homedir } from "os";
import {
  basename,
  INLINE_CODE_FLAGS,
  tokenize,
} from "./exec-identifier.js";

type TokenMatcher = string | RegExp;

export type ScriptFileExecutionRuleId =
  | "python_script_file"
  | "shell_script_file"
  | "node_script_file"
  | "direct_script_file";

export interface ScriptFileExecutionRule {
  id: ScriptFileExecutionRuleId;
  runners?: readonly TokenMatcher[];
  inlineRunner: string;
  inlineFlag: "-c" | "-e";
}

export interface ScriptFileCommandExpansion {
  source: "script_file";
  ruleId: ScriptFileExecutionRuleId;
  originalCommand: string;
  normalizedCommand: string;
  scriptPath: string;
  trustedScriptPath: string;
  runner: string;
  inlineRunner: string;
  inlineFlag: "-c" | "-e";
  contentBytes: number;
}

export interface ScriptFileCommandExpansionOptions {
  command: string;
  workdir: string;
  /** Map an absolute script path to its TRUSTED-view path, or null if the
   * script is not in a tracked/trusted location. Injected by the caller (the
   * exec-supervisor) — the arbiter does not own the view mapping. */
  trustedPathFor: (absScriptPath: string) => string | null;
  maxBytes?: number;
}

const DEFAULT_MAX_SCRIPT_BYTES = 256 * 1024;
const PYTHON_RUNNER = /^python(?:\d+(?:\.\d+)*)?$/;

export const SCRIPT_FILE_EXECUTION_RULES: readonly ScriptFileExecutionRule[] = [
  {
    id: "python_script_file",
    runners: [PYTHON_RUNNER],
    inlineRunner: "python",
    inlineFlag: "-c",
  },
  {
    id: "shell_script_file",
    runners: ["sh", "bash", "zsh"],
    inlineRunner: "sh",
    inlineFlag: "-c",
  },
  {
    id: "node_script_file",
    runners: ["node"],
    inlineRunner: "node",
    inlineFlag: "-e",
  },
  {
    id: "direct_script_file",
    inlineRunner: "sh",
    inlineFlag: "-c",
  },
];

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function tokenMatches(matcher: TokenMatcher, token: string): boolean {
  if (typeof matcher === "string") return matcher === token;
  matcher.lastIndex = 0;
  return matcher.test(token);
}

function isLeadingEnvAssignment(token: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);
}

function commandStartIndex(tokens: string[]): number {
  let idx = 0;
  while (idx < tokens.length && isLeadingEnvAssignment(tokens[idx])) idx++;
  return idx;
}

function resolveScriptPath(scriptToken: string, workdir: string): string {
  if (scriptToken.startsWith("~/")) return resolve(homedir(), scriptToken.slice(2));
  if (isAbsolute(scriptToken)) return resolve(scriptToken);
  return resolve(workdir, scriptToken);
}

function readTrustedText(path: string, maxBytes: number): { text: string; bytes: number } | null {
  let st;
  try {
    st = statSync(path);
  } catch {
    return null;
  }
  if (!st.isFile() || st.size > maxBytes) return null;

  const buf = readFileSync(path);
  if (buf.subarray(0, 8192).includes(0)) return null;
  return { text: buf.toString("utf8"), bytes: buf.length };
}

function pythonScriptToken(tokens: string[], runnerIndex: number): string | null {
  for (let i = runnerIndex + 1; i < tokens.length; i++) {
    const token = tokens[i];
    if (token === "-c" || token === "-m" || token === "-") return null;
    if (INLINE_CODE_FLAGS.has(token)) return null;
    if (token.startsWith("-")) continue;
    return token;
  }
  return null;
}

function shellScriptToken(tokens: string[], runnerIndex: number): string | null {
  for (let i = runnerIndex + 1; i < tokens.length; i++) {
    const token = tokens[i];
    if (/^-[^-]*[cs][^-]*$/.test(token) || token === "--command") return null;
    if (token.startsWith("-")) continue;
    return token;
  }
  return null;
}

function nodeScriptToken(tokens: string[], runnerIndex: number): string | null {
  for (let i = runnerIndex + 1; i < tokens.length; i++) {
    const token = tokens[i];
    if (token === "-e" || token === "--eval" || token === "-p" || token === "--print") return null;
    if (token === "-r" || token === "--require" || token === "--loader" || token === "--import") {
      i++;
      continue;
    }
    if (token.startsWith("-")) continue;
    return token;
  }
  return null;
}

function isDirectScriptToken(token: string): boolean {
  if (token.startsWith("/") || token.startsWith("./") || token.startsWith("../") || token.startsWith("~/")) {
    return true;
  }
  return /\.(?:sh|bash|zsh|py|js|mjs|cjs)$/.test(token);
}

function directScriptInlineRule(scriptPath: string, text: string): Pick<ScriptFileCommandExpansion, "inlineRunner" | "inlineFlag"> {
  const firstLine = text.split(/\r?\n/, 1)[0] ?? "";
  if (firstLine.startsWith("#!")) {
    const shebang = firstLine.toLowerCase();
    if (shebang.includes("python")) return { inlineRunner: "python", inlineFlag: "-c" };
    if (shebang.includes("node")) return { inlineRunner: "node", inlineFlag: "-e" };
    if (shebang.includes("bash")) return { inlineRunner: "bash", inlineFlag: "-c" };
    if (shebang.includes("zsh")) return { inlineRunner: "zsh", inlineFlag: "-c" };
    if (shebang.includes("sh")) return { inlineRunner: "sh", inlineFlag: "-c" };
  }

  switch (extname(scriptPath)) {
    case ".py": return { inlineRunner: "python", inlineFlag: "-c" };
    case ".js":
    case ".mjs":
    case ".cjs": return { inlineRunner: "node", inlineFlag: "-e" };
    case ".bash": return { inlineRunner: "bash", inlineFlag: "-c" };
    case ".zsh": return { inlineRunner: "zsh", inlineFlag: "-c" };
    default: return { inlineRunner: "sh", inlineFlag: "-c" };
  }
}

function buildExpansion(
  opts: ScriptFileCommandExpansionOptions,
  ruleId: ScriptFileExecutionRuleId,
  runner: string,
  scriptToken: string,
  inlineRunner: string,
  inlineFlag: "-c" | "-e",
): ScriptFileCommandExpansion | null {
  const scriptPath = resolveScriptPath(scriptToken, opts.workdir);
  const trustedScriptPath = opts.trustedPathFor(scriptPath);
  if (!trustedScriptPath) return null;

  const content = readTrustedText(trustedScriptPath, opts.maxBytes ?? DEFAULT_MAX_SCRIPT_BYTES);
  if (!content) return null;

  return {
    source: "script_file",
    ruleId,
    originalCommand: opts.command,
    normalizedCommand: `${inlineRunner} ${inlineFlag} ${shellQuote(content.text)}`,
    scriptPath,
    trustedScriptPath,
    runner,
    inlineRunner,
    inlineFlag,
    contentBytes: content.bytes,
  };
}

export function expandScriptFileCommandForDetection(
  opts: ScriptFileCommandExpansionOptions,
): ScriptFileCommandExpansion | null {
  const tokens = tokenize(opts.command);
  const start = commandStartIndex(tokens);
  if (start >= tokens.length) return null;

  const runnerToken = tokens[start]!;
  const runner = basename(runnerToken);

  for (const rule of SCRIPT_FILE_EXECUTION_RULES) {
    if (rule.id === "direct_script_file") continue;
    if (!(rule.runners ?? []).some((matcher) => tokenMatches(matcher, runner))) continue;

    const scriptToken =
      rule.id === "python_script_file" ? pythonScriptToken(tokens, start)
      : rule.id === "shell_script_file" ? shellScriptToken(tokens, start)
      : rule.id === "node_script_file" ? nodeScriptToken(tokens, start)
      : null;
    if (!scriptToken) return null;
    return buildExpansion(opts, rule.id, runner, scriptToken, runner, rule.inlineFlag);
  }

  if (!isDirectScriptToken(runnerToken)) return null;
  const scriptPath = resolveScriptPath(runnerToken, opts.workdir);
  const trustedScriptPath = opts.trustedPathFor(scriptPath);
  if (!trustedScriptPath) return null;
  const content = readTrustedText(trustedScriptPath, opts.maxBytes ?? DEFAULT_MAX_SCRIPT_BYTES);
  if (!content) return null;

  const inline = directScriptInlineRule(scriptPath, content.text);
  return {
    source: "script_file",
    ruleId: "direct_script_file",
    originalCommand: opts.command,
    normalizedCommand: `${inline.inlineRunner} ${inline.inlineFlag} ${shellQuote(content.text)}`,
    scriptPath,
    trustedScriptPath,
    runner,
    inlineRunner: inline.inlineRunner,
    inlineFlag: inline.inlineFlag,
    contentBytes: content.bytes,
  };
}
