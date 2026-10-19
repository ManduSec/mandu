/**
 * untrusted-command-execution — detect symbol-as-command/code flow in exec.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/untrusted-command-execution.ts
 *   Purpose: detect the HIGH-RISK exec.command shapes where an `$MDU:*`
 *   symbol is positioned as command/code TEXT rather than an ordinary data
 *   argument — the whole command IS a symbol, a symbol sits inside `sh -c …`,
 *   inside `python -c` / `node -e`, or inside a heredoc/stdin code body. These
 *   are exactly the cases the data-usage policy treats as "untrusted symbol used
 *   as a command" → human approval. The egress gate (asCommand) and the
 *   exec-supervisor both consume this detector.
 *
 *   Adaptation for Mandu — FLAGGED, minimal:
 *     - `getActiveFormat` / `unescapeSymbols` now import from
 *       "../symbol-table/index.js"; `ExecArgvSymbolResolution` from the lifted
 *       "./exec-argv-mode.js". Same symbols, lifted location.
 *     - Pattern table + detectors lifted verbatim (security-critical).
 */

import { getActiveFormat, unescapeSymbols } from "../symbol-table/index.js";
import {
  basename,
  INLINE_CODE_FLAGS,
  tokenize,
} from "./exec-identifier.js";
import type { ExecArgvSymbolResolution } from "./exec-argv-mode.js";

export type UntrustedCommandExecutionPatternId =
  | "command_is_symbol"
  | "shell_c_contains_symbol"
  | "interpreter_inline_code_contains_symbol"
  | "stdin_code_contains_symbol";

export interface UntrustedCommandExecutionMatch {
  patternId: UntrustedCommandExecutionPatternId;
  symbols: string[];
  evidence: string;
  action: "audit" | "block";
}

export interface UntrustedCommandExecutionOptions {
  action: "audit" | "block";
}

export type TokenMatcher = string | RegExp;
export type RunnerMatcher = TokenMatcher;

export type CommandPatternSource =
  | { kind: "whole_command_symbol" }
  | { kind: "flag_argument"; flags: readonly TokenMatcher[] }
  | { kind: "heredoc_body"; stdinMarkers?: readonly TokenMatcher[] };

export interface UntrustedCommandExecutionPattern {
  id: UntrustedCommandExecutionPatternId;
  source: CommandPatternSource;
  runners?: readonly RunnerMatcher[];
}

const PYTHON_RUNNER = /^python(?:\d+(?:\.\d+)*)?$/;
const SHELL_COMMAND_FLAG = /^-[^-]*c[^-]*$/;
const SHELL_STDIN_FLAG = /^-[^-]*s[^-]*$/;

export const UNTRUSTED_COMMAND_EXECUTION_PATTERNS: readonly UntrustedCommandExecutionPattern[] = [
  {
    id: "command_is_symbol",
    source: { kind: "whole_command_symbol" },
  },
  {
    id: "shell_c_contains_symbol",
    runners: ["sh", "bash", "zsh"],
    source: {
      kind: "flag_argument",
      flags: ["-c", "--command", SHELL_COMMAND_FLAG],
    },
  },
  {
    id: "interpreter_inline_code_contains_symbol",
    runners: [PYTHON_RUNNER, "node"],
    source: {
      kind: "flag_argument",
      flags: Array.from(INLINE_CODE_FLAGS),
    },
  },
  {
    id: "stdin_code_contains_symbol",
    runners: ["sh", "bash", "zsh"],
    source: {
      kind: "heredoc_body",
      stdinMarkers: [SHELL_STDIN_FLAG],
    },
  },
  {
    id: "stdin_code_contains_symbol",
    runners: [PYTHON_RUNNER],
    source: {
      kind: "heredoc_body",
      stdinMarkers: ["-"],
    },
  },
];

function isLeadingEnvAssignment(token: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);
}

function commandStartIndex(tokens: string[]): number {
  let idx = 0;
  while (idx < tokens.length && isLeadingEnvAssignment(tokens[idx])) idx++;
  return idx;
}

export function extractSymbolsFromCommandText(text: string): string[] {
  const normalized = unescapeSymbols(text);
  const fmt = getActiveFormat();
  if (!normalized.includes(fmt.prefix)) return [];

  const pat = fmt.pattern;
  pat.lastIndex = 0;
  const out: string[] = [];
  for (;;) {
    const match = pat.exec(normalized);
    if (!match) break;
    const sym = match[0];
    if (!out.includes(sym)) out.push(sym);
    if (sym.length === 0) pat.lastIndex++;
  }
  return out;
}

function stripWrappingQuotes(text: string): string {
  let out = text.trim();
  for (;;) {
    if (out.length < 2) return out;
    const first = out[0];
    const last = out[out.length - 1];
    if ((first === "'" || first === '"') && first === last) {
      out = out.slice(1, -1).trim();
      continue;
    }
    return out;
  }
}

function commandIsSingleSymbol(command: string): string[] {
  const normalized = stripWrappingQuotes(unescapeSymbols(command));
  const symbols = extractSymbolsFromCommandText(normalized);
  return symbols.length === 1 && normalized === symbols[0] ? symbols : [];
}

function tokenMatches(matcher: TokenMatcher, token: string): boolean {
  if (typeof matcher === "string") return matcher === token;
  matcher.lastIndex = 0;
  return matcher.test(token);
}

function tokenMatchesAny(token: string, matchers: readonly TokenMatcher[] | undefined): boolean {
  return (matchers ?? []).some((matcher) => tokenMatches(matcher, token));
}

function runnerMatches(matcher: RunnerMatcher, runner: string): boolean {
  return tokenMatches(matcher, runner);
}

function patternMatchesRunner(pattern: UntrustedCommandExecutionPattern, runner: string): boolean {
  return (pattern.runners ?? []).some((matcher) => runnerMatches(matcher, runner));
}

function followingArgumentIndexForMatcher(tokens: string[], runnerIndex: number, matchers: readonly TokenMatcher[]): number | null {
  for (let i = runnerIndex + 1; i < tokens.length; i++) {
    const token = tokens[i];
    if (tokenMatchesAny(token, matchers)) {
      return i + 1 < tokens.length ? i + 1 : null;
    }
    if (!token.startsWith("-")) return null;
  }
  return null;
}

function followingArgumentForMatcher(tokens: string[], runnerIndex: number, matchers: readonly TokenMatcher[]): string | null {
  const index = followingArgumentIndexForMatcher(tokens, runnerIndex, matchers);
  return index === null ? null : tokens[index]!;
}

function hasHeredocToken(tokens: string[]): boolean {
  return tokens.some((token) => token.startsWith("<<"));
}

function heredocIsCodeStdin(tokens: string[], runnerIndex: number, stdinMarkers: readonly TokenMatcher[] | undefined): boolean {
  for (let i = runnerIndex + 1; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.startsWith("<<")) return true;
    if (tokenMatchesAny(token, stdinMarkers)) continue;
    if (token.startsWith("-")) continue;
    return false;
  }
  return hasHeredocToken(tokens);
}

function firstLine(command: string): string {
  return command.split(/\r?\n/, 1)[0] ?? "";
}

function heredocBody(command: string): string {
  const idx = command.search(/\r?\n/);
  return idx < 0 ? "" : command.slice(idx + (command[idx] === "\r" ? 2 : 1));
}

function addMatch(
  matches: UntrustedCommandExecutionMatch[],
  patternId: UntrustedCommandExecutionPatternId,
  symbols: string[],
  evidence: string,
  action: "audit" | "block",
): void {
  if (symbols.length === 0) return;
  matches.push({
    patternId,
    symbols,
    evidence: evidence.length > 240 ? `${evidence.slice(0, 237)}...` : evidence,
    action,
  });
}

export function detectUntrustedCommandExecutionPatterns(
  command: string,
  opts: UntrustedCommandExecutionOptions = { action: "audit" },
): UntrustedCommandExecutionMatch[] {
  const matches: UntrustedCommandExecutionMatch[] = [];

  const tokens = tokenize(command);
  const start = commandStartIndex(tokens);
  const line1 = firstLine(command);

  for (const pattern of UNTRUSTED_COMMAND_EXECUTION_PATTERNS) {
    if (pattern.source.kind === "whole_command_symbol") {
      addMatch(
        matches,
        pattern.id,
        commandIsSingleSymbol(command),
        command.trim(),
        opts.action,
      );
      continue;
    }

    if (pattern.source.kind === "flag_argument") {
      if (start >= tokens.length) continue;
      const runner = basename(tokens[start]);
      if (!patternMatchesRunner(pattern, runner)) continue;
      const evidence = followingArgumentForMatcher(tokens, start, pattern.source.flags);
      if (evidence === null) continue;
      addMatch(
        matches,
        pattern.id,
        extractSymbolsFromCommandText(evidence),
        evidence,
        opts.action,
      );
      continue;
    }

    if (pattern.source.kind === "heredoc_body") {
      if (!line1.includes("<<")) continue;
      const lineTokens = tokenize(line1);
      const runnerIndex = commandStartIndex(lineTokens);
      if (runnerIndex >= lineTokens.length) continue;
      const runner = basename(lineTokens[runnerIndex]);
      if (!patternMatchesRunner(pattern, runner)) continue;
      if (!heredocIsCodeStdin(lineTokens, runnerIndex, pattern.source.stdinMarkers)) continue;
      const body = heredocBody(command);
      addMatch(
        matches,
        pattern.id,
        extractSymbolsFromCommandText(body),
        body,
        opts.action,
      );
    }
  }

  return matches;
}

/**
 * Detect command/code-position symbol flow after a symbolized exec command has
 * been lowered to argv IR (exec-argv-mode.ts). Inspects the TEMPLATE argv plan,
 * before symbol values are substituted, so resolved raw values are not
 * re-scanned and ordinary data arguments stay distinguishable from code sinks.
 */
export function detectUntrustedCommandExecutionPatternsFromExecArgvResolution(
  resolution: ExecArgvSymbolResolution,
  opts: UntrustedCommandExecutionOptions = { action: "audit" },
): UntrustedCommandExecutionMatch[] {
  const matches: UntrustedCommandExecutionMatch[] = [];

  addMatch(
    matches,
    "command_is_symbol",
    commandIsSingleSymbol(resolution.originalCommand),
    resolution.originalCommand.trim(),
    opts.action,
  );

  if (resolution.templateProgram.kind !== "program") return matches;

  for (const step of resolution.templateProgram.steps) {
    const argv = step.argv;
    if (argv.length === 0) continue;
    const runner = basename(argv[0]!);

    for (const pattern of UNTRUSTED_COMMAND_EXECUTION_PATTERNS) {
      if (pattern.source.kind !== "flag_argument") continue;
      if (!patternMatchesRunner(pattern, runner)) continue;

      const evidenceIndex = followingArgumentIndexForMatcher(argv, 0, pattern.source.flags);
      if (evidenceIndex === null) continue;
      const evidence = argv[evidenceIndex]!;
      addMatch(
        matches,
        pattern.id,
        extractSymbolsFromCommandText(evidence),
        evidence,
        opts.action,
      );
    }
  }

  return matches;
}
