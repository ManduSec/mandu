/**
 * exec-argv-mode — argv-mode command preparation for HumanShell exec.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/exec-argv-mode.ts
 *   Purpose: when T-LLM emits an exec command that contains `$MDU:*`
 *   symbols, the command TEMPLATE is tokenized BEFORE any symbol is resolved.
 *   Except for a bare whole-command symbol, resolved symbol values replace bytes
 *   inside an existing argv slot and are never re-tokenized, so shell
 *   metacharacters in untrusted values cannot become shell syntax or extra argv
 *   entries. This is the safe argv lowering used by the HumanShell desymbolize
 *   path (resolveExecArgv).
 *
 *   Adaptation for Mandu — FLAGGED, minimal:
 *     - `SymbolEntry` now imports from "../symbol-table/index.js"; `getActiveFormat`
 *       / `unescapeSymbols` likewise (reference imported from the in-plugin
 *       adfi-symbol-table / adfi-symbol-format). Same symbols, lifted location.
 *     - No other OpenClaw coupling. Tokenizers + the restricted-shell parser are
 *       lifted verbatim (this is security-critical metacharacter handling — see
 *       shell-symbol-resolution.ts / untrusted-command-execution.ts).
 */

import type { SymbolEntry } from "../symbol-table/index.js";
import { findByCandidates, getActiveFormat, unescapeSymbols } from "../symbol-table/index.js";

export type ExecArgvSymbolAction = "resolved" | "preserved" | "unknown";

/** Entry lookup via the shared candidate walk (symbol-format): a
 *  model-mutated token — an invented field suffix, a glued trailing
 *  dot-run, or a stream-stranded base aliasing its one field extension — is
 *  looked up as the real name it mutates, in lockstep with the exec gate
 *  (exec-classify) and the table (findSymbolByName). */
function entryForToken(
  symbols: Map<string, SymbolEntry>,
  token: string,
): { name: string; entry: SymbolEntry } | undefined {
  const r = findByCandidates(token, (n) => symbols.get(n), () => symbols.keys());
  return r ? { name: r.name, entry: r.hit } : undefined;
}

/** The entry's value plus any trailing dot-run the scanner glued onto the
 *  match beyond the resolved name (byte preservation for command text); an
 *  invented field suffix is dropped. */
function resolvedTokenText(token: string, hit: { name: string; entry: SymbolEntry }): string {
  const dots = /\.+$/.exec(token.slice(hit.name.length))?.[0] ?? "";
  return hit.entry.value + dots;
}

export interface ExecArgvSymbolDecision {
  symbol: string;
  argvIndex: number;
  action: ExecArgvSymbolAction;
}

export interface ExecArgvCommandStep {
  argv: string[];
  op?: "&&" | "||";
}

export type ExecArgvProgram =
  | { kind: "program"; steps: ExecArgvCommandStep[] }
  | { kind: "unsupported"; reason: string; evidence: string };

export interface ExecArgvSymbolResolution {
  originalCommand: string;
  argv: string[];
  templateProgram: ExecArgvProgram;
  program: ExecArgvProgram;
  mode: "template_argv" | "whole_command_symbol_argv";
  changed: boolean;
  decisions: ExecArgvSymbolDecision[];
}

export interface SymbolMatch {
  symbol: string;
  start: number;
  end: number;
}

export function findSymbolMatches(text: string): SymbolMatch[] {
  const normalized = unescapeSymbols(text);
  const fmt = getActiveFormat();
  if (!normalized.includes(fmt.prefix)) return [];

  const pat = fmt.pattern;
  pat.lastIndex = 0;
  const matches: SymbolMatch[] = [];
  for (;;) {
    const match = pat.exec(normalized);
    if (!match) break;
    matches.push({
      symbol: match[0],
      start: match.index,
      end: match.index + match[0].length,
    });
    if (match[0].length === 0) pat.lastIndex++;
  }
  return matches;
}

export function commandContainsMduSymbol(command: string): boolean {
  return findSymbolMatches(command).length > 0;
}

function bareWholeCommandSymbol(command: string): string | null {
  const normalized = unescapeSymbols(command).trim();
  const matches = findSymbolMatches(normalized);
  return matches.length === 1 && normalized === matches[0]!.symbol ? matches[0]!.symbol : null;
}

function symbolAt(text: string, offset: number): SymbolMatch | null {
  for (const match of findSymbolMatches(text)) {
    if (match.start === offset) return match;
  }
  return null;
}

/**
 * Minimal shell-word tokenizer for command templates. Recognizes quoting and
 * backslash escapes only to preserve argv boundaries; does NOT interpret pipes,
 * redirects, control operators, variables, globs, or command substitutions.
 */
export function tokenizeExecArgvTemplate(command: string): string[] {
  const normalized = unescapeSymbols(command);
  const argv: string[] = [];
  let current = "";
  let inToken = false;
  let quote: "none" | "single" | "double" = "none";
  let i = 0;

  const flush = (): void => {
    if (!inToken) return;
    argv.push(current);
    current = "";
    inToken = false;
  };

  while (i < normalized.length) {
    const ch = normalized[i]!;

    if (quote === "none") {
      if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
        flush();
        i++;
        continue;
      }
      inToken = true;
      if (ch === "'") {
        quote = "single";
        i++;
        continue;
      }
      if (ch === "\"") {
        quote = "double";
        i++;
        continue;
      }
      if (ch === "\\" && i + 1 < normalized.length) {
        current += normalized[i + 1]!;
        i += 2;
        continue;
      }
      current += ch;
      i++;
      continue;
    }

    inToken = true;
    if (quote === "single") {
      if (ch === "'") {
        quote = "none";
      } else {
        current += ch;
      }
      i++;
      continue;
    }

    if (ch === "\"") {
      quote = "none";
      i++;
      continue;
    }
    if (ch === "\\" && i + 1 < normalized.length) {
      current += normalized[i + 1]!;
      i += 2;
      continue;
    }
    current += ch;
    i++;
  }

  flush();
  return argv;
}

type RestrictedToken =
  | { kind: "word"; value: string }
  | { kind: "op"; value: "&&" | "||" };

type RestrictedParseResult =
  | { ok: true; commands: Array<{ argv: string[]; op?: "&&" | "||" }> }
  | { ok: false; reason: string; evidence: string };

const SHELL_KEYWORDS_AND_BUILTINS = new Set<string>([
  "case",
  "cd",
  "do",
  "done",
  "elif",
  "else",
  "esac",
  "eval",
  "exec",
  "export",
  "fi",
  "for",
  "function",
  "if",
  "set",
  "source",
  "then",
  "trap",
  "while",
  ".",
]);

function unsupported(reason: string, evidence: string): RestrictedParseResult {
  return { ok: false, reason, evidence };
}

function parseRestrictedShellTemplate(command: string): RestrictedParseResult {
  const normalized = unescapeSymbols(command);
  const tokens: RestrictedToken[] = [];
  let current = "";
  let inToken = false;
  let quote: "none" | "single" | "double" = "none";
  let i = 0;

  const flushWord = (): void => {
    if (!inToken) return;
    tokens.push({ kind: "word", value: current });
    current = "";
    inToken = false;
  };

  const addOp = (op: "&&" | "||"): void => {
    flushWord();
    tokens.push({ kind: "op", value: op });
  };

  while (i < normalized.length) {
    const ch = normalized[i]!;

    if (quote === "single") {
      inToken = true;
      if (ch === "'") {
        quote = "none";
      } else {
        current += ch;
      }
      i++;
      continue;
    }

    if (quote === "double") {
      inToken = true;
      if (ch === "\"") {
        quote = "none";
        i++;
        continue;
      }
      if (ch === "`") return unsupported("command_substitution_unsupported", "`");
      if (ch === "$") {
        if (normalized[i + 1] === "(") return unsupported("command_substitution_unsupported", "$(");
        const sym = symbolAt(normalized, i);
        if (sym) {
          current += sym.symbol;
          i = sym.end;
          continue;
        }
        return unsupported("variable_expansion_unsupported", normalized.slice(i, i + 24));
      }
      if (ch === "\\" && i + 1 < normalized.length) {
        current += normalized[i + 1]!;
        i += 2;
        continue;
      }
      current += ch;
      i++;
      continue;
    }

    if (ch === " " || ch === "\t" || ch === "\r") {
      flushWord();
      i++;
      continue;
    }
    if (ch === "\n") return unsupported("newline_separator_unsupported", "\\n");
    if (ch === "'") {
      inToken = true;
      quote = "single";
      i++;
      continue;
    }
    if (ch === "\"") {
      inToken = true;
      quote = "double";
      i++;
      continue;
    }
    if (ch === "\\" && i + 1 < normalized.length) {
      inToken = true;
      current += normalized[i + 1]!;
      i += 2;
      continue;
    }
    if (ch === "&") {
      if (normalized[i + 1] === "&") {
        addOp("&&");
        i += 2;
        continue;
      }
      return unsupported("background_operator_unsupported", "&");
    }
    if (ch === "|") {
      if (normalized[i + 1] === "|") {
        addOp("||");
        i += 2;
        continue;
      }
      return unsupported("pipe_unsupported", "|");
    }
    if (ch === ";" || ch === "<" || ch === ">" || ch === "(" || ch === ")" || ch === "{" || ch === "}" || ch === "!" || ch === "#") {
      return unsupported("shell_construct_unsupported", ch);
    }
    if (ch === "`") return unsupported("command_substitution_unsupported", "`");
    if (ch === "*" || ch === "?") return unsupported("glob_unsupported", ch);
    if (ch === "$") {
      if (normalized[i + 1] === "(") return unsupported("command_substitution_unsupported", "$(");
      const sym = symbolAt(normalized, i);
      if (sym) {
        inToken = true;
        current += sym.symbol;
        i = sym.end;
        continue;
      }
      return unsupported("variable_expansion_unsupported", normalized.slice(i, i + 24));
    }

    inToken = true;
    current += ch;
    i++;
  }

  if (quote !== "none") return unsupported("unterminated_quote", quote);
  flushWord();
  if (tokens.length === 0) return unsupported("empty_command", "");

  const commands: Array<{ argv: string[]; op?: "&&" | "||" }> = [];
  let pendingOp: "&&" | "||" | undefined;
  let argv: string[] = [];

  const flushCommand = (): RestrictedParseResult | null => {
    if (argv.length === 0) return unsupported("empty_command_around_operator", pendingOp ?? "");
    const first = argv[0]!;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(first)) return unsupported("env_assignment_unsupported", first);
    if (commandContainsMduSymbol(first)) return unsupported("symbol_in_command_position", first);
    if (SHELL_KEYWORDS_AND_BUILTINS.has(first)) return unsupported("shell_builtin_or_keyword_unsupported", first);
    commands.push(pendingOp ? { argv, op: pendingOp } : { argv });
    argv = [];
    pendingOp = undefined;
    return null;
  };

  for (const token of tokens) {
    if (token.kind === "word") {
      argv.push(token.value);
      continue;
    }
    const err = flushCommand();
    if (err) return err;
    pendingOp = token.value;
  }

  const err = flushCommand();
  if (err) return err;
  return { ok: true, commands };
}

function replaceSymbolsInArgvSlot(
  value: string,
  argvIndex: number,
  symbols: Map<string, SymbolEntry>,
  resolveSymbols: boolean,
  decisions: ExecArgvSymbolDecision[],
): string {
  const normalized = unescapeSymbols(value);
  const matches = findSymbolMatches(normalized);
  if (matches.length === 0) return normalized;

  let out = "";
  let cursor = 0;
  for (const match of matches) {
    const hit = entryForToken(symbols, match.symbol);
    out += normalized.slice(cursor, match.start);
    if (hit && resolveSymbols) {
      out += resolvedTokenText(match.symbol, hit);
      decisions.push({ symbol: match.symbol, argvIndex, action: "resolved" });
    } else {
      out += match.symbol;
      decisions.push({
        symbol: match.symbol,
        argvIndex,
        action: hit ? "preserved" : "unknown",
      });
    }
    cursor = match.end;
  }
  out += normalized.slice(cursor);
  return out;
}

export function prepareExecArgvSymbolResolution(
  command: string,
  symbols: Map<string, SymbolEntry>,
  opts: { resolveSymbols: boolean },
): ExecArgvSymbolResolution | null {
  if (!commandContainsMduSymbol(command)) return null;

  const templateArgv = tokenizeExecArgvTemplate(command);
  if (templateArgv.length === 0) return null;

  const decisions: ExecArgvSymbolDecision[] = [];
  const wholeCommandSymbol = bareWholeCommandSymbol(command);
  if (wholeCommandSymbol && opts.resolveSymbols) {
    const hit = entryForToken(symbols, wholeCommandSymbol);
    if (hit) {
      decisions.push({ symbol: wholeCommandSymbol, argvIndex: -1, action: "resolved" });
      const argv = tokenizeExecArgvTemplate(hit.entry.value);
      return {
        originalCommand: command,
        argv,
        templateProgram: { kind: "program", steps: [{ argv: templateArgv }] },
        program: { kind: "program", steps: [{ argv }] },
        mode: "whole_command_symbol_argv",
        changed: JSON.stringify(argv) !== JSON.stringify(templateArgv),
        decisions,
      };
    }
  }

  const parsed = parseRestrictedShellTemplate(command);
  if (!parsed.ok) {
    return {
      originalCommand: command,
      argv: [],
      templateProgram: {
        kind: "unsupported",
        reason: parsed.reason,
        evidence: parsed.evidence,
      },
      program: {
        kind: "unsupported",
        reason: parsed.reason,
        evidence: parsed.evidence,
      },
      mode: "template_argv",
      changed: false,
      decisions,
    };
  }

  const steps = parsed.commands.map((step) => ({
    ...step,
    argv: step.argv.map((slot, index) =>
      replaceSymbolsInArgvSlot(slot, index, symbols, opts.resolveSymbols, decisions),
    ),
  }));
  const argv = steps[0]?.argv ?? [];

  return {
    originalCommand: command,
    argv,
    templateProgram: { kind: "program", steps: parsed.commands },
    program: { kind: "program", steps },
    mode: "template_argv",
    changed: JSON.stringify(steps.map((step) => step.argv)) !== JSON.stringify(parsed.commands.map((step) => step.argv)),
    decisions,
  };
}
