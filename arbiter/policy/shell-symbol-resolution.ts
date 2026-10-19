/**
 * shell-symbol-resolution — shell-context-aware symbol resolution for HumanShell.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/shell-symbol-resolution.ts
 *   Purpose: desymbolize an unrestricted (HumanShell) exec.command string while
 *   PRESERVING shell-quoting context, so a resolved untrusted value can never
 *   break out of its quoting and become shell syntax. A symbol in an unquoted
 *   word is re-emitted single-quoted; inside double quotes its dangerous chars
 *   are escaped; inside single quotes the `'` byte is escaped. This is the
 *   "desymbolize argv only AFTER the data-usage check" primitive — the gate
 *   decides WHETHER to resolve; this decides HOW to resolve safely.
 *
 *   Adaptation for Mandu — FLAGGED, minimal:
 *     - `SymbolEntry` / `getActiveFormat` / `unescapeSymbols` now import from
 *       "../symbol-table/index.js" (reference imported from the in-plugin
 *       modules). Same symbols, lifted location. No other coupling.
 *     - Security-critical quoting/escaping logic lifted verbatim.
 */

import type { SymbolEntry } from "../symbol-table/index.js";
import { findByCandidates, getActiveFormat, unescapeSymbols } from "../symbol-table/index.js";

export type ShellSymbolContext = "unquoted" | "single_quoted" | "double_quoted" | "mixed_token";
export type ShellSymbolResolutionAction = "applied" | "skipped";
export type ShellSymbolSkipReason = "unknown_symbol" | "unsupported_mixed_token";

export interface ShellSymbolResolutionDecision {
  symbol: string;
  context: ShellSymbolContext;
  action: ShellSymbolResolutionAction;
  reason?: ShellSymbolSkipReason;
  fallback?: "raw_resolve" | "preserve_symbol";
}

export interface ShellCommandSymbolResolution {
  command: string;
  originalCommand: string;
  changed: boolean;
  decisions: ShellSymbolResolutionDecision[];
}

interface ShellWord {
  start: number;
  end: number;
  text: string;
}

interface SymbolMatch {
  symbol: string;
  start: number;
  end: number;
}

interface Replacement {
  start: number;
  end: number;
  text: string;
}

const SHELL_WORD_SEPARATORS = new Set([" ", "\t", "\n", "\r", ";", "&", "|", "(", ")", "<", ">"]);

function isShellWordSeparator(ch: string): boolean {
  return SHELL_WORD_SEPARATORS.has(ch);
}

function parseShellWords(command: string): ShellWord[] {
  const words: ShellWord[] = [];
  let wordStart: number | null = null;
  let quote: "none" | "single" | "double" = "none";
  let i = 0;

  const beginWord = (): void => {
    if (wordStart === null) wordStart = i;
  };
  const flushWord = (): void => {
    if (wordStart !== null) {
      words.push({ start: wordStart, end: i, text: command.slice(wordStart, i) });
      wordStart = null;
    }
  };

  while (i < command.length) {
    const ch = command[i]!;

    if (quote === "none") {
      if (isShellWordSeparator(ch)) {
        flushWord();
        i++;
        continue;
      }
      beginWord();
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
      if (ch === "\\" && i + 1 < command.length) {
        i += 2;
        continue;
      }
      i++;
      continue;
    }

    beginWord();
    if (quote === "single") {
      if (ch === "'") quote = "none";
      i++;
      continue;
    }

    if (ch === "\"") {
      quote = "none";
      i++;
      continue;
    }
    if (ch === "\\" && i + 1 < command.length) {
      i += 2;
      continue;
    }
    i++;
  }

  flushWord();
  return words;
}

function findSymbolMatches(text: string): SymbolMatch[] {
  const fmt = getActiveFormat();
  if (!text.includes(fmt.prefix)) return [];

  const pat = fmt.pattern;
  pat.lastIndex = 0;
  const matches: SymbolMatch[] = [];
  for (;;) {
    const match = pat.exec(text);
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

/** Entry lookup via the shared candidate walk (symbol-format): a
 *  model-mutated token — an invented field suffix, a glued trailing
 *  dot-run, or a stream-stranded base aliasing its one field extension — is
 *  looked up as the real name it mutates, keeping this module's notion of
 *  "known" in lockstep with the exec gate's (exec-classify) and the table's
 *  (findSymbolByName). */
function entryForToken(
  symbols: Map<string, SymbolEntry>,
  token: string,
): { name: string; entry: SymbolEntry } | undefined {
  const r = findByCandidates(token, (n) => symbols.get(n), () => symbols.keys());
  return r ? { name: r.name, entry: r.hit } : undefined;
}

/** The text a matched token resolves to: the entry's value, plus any trailing
 *  dot-run the scanner glued onto the match beyond the resolved name (byte
 *  preservation for command text); an invented field suffix is dropped. */
function resolvedTokenText(token: string, hit: { name: string; entry: SymbolEntry }): string {
  const dots = /\.+$/.exec(token.slice(hit.name.length))?.[0] ?? "";
  return hit.entry.value + dots;
}

export function shellSingleQuote(value: string): string {
  return `'${escapeForSingleQuotedShell(value)}'`;
}

function escapeForSingleQuotedShell(value: string): string {
  return value.replace(/'/g, "'\\''");
}

function escapeForDoubleQuotedShell(value: string): string {
  let out = "";
  for (const ch of value) {
    if (ch === "\n") {
      out += "\"'\n'\"";
    } else if (ch === "\"" || ch === "\\" || ch === "$" || ch === "`") {
      out += `\\${ch}`;
    } else {
      out += ch;
    }
  }
  return out;
}

function standaloneContext(wordText: string, match: SymbolMatch): ShellSymbolContext {
  if (wordText === match.symbol) return "unquoted";
  if (wordText === `"${match.symbol}"` && match.start === 1 && match.end === wordText.length - 1) {
    return "double_quoted";
  }
  if (wordText === `'${match.symbol}'` && match.start === 1 && match.end === wordText.length - 1) {
    return "single_quoted";
  }
  return "mixed_token";
}

function replacementForContext(context: ShellSymbolContext, value: string): string {
  if (context === "unquoted") return shellSingleQuote(value);
  if (context === "double_quoted") return escapeForDoubleQuotedShell(value);
  if (context === "single_quoted") return escapeForSingleQuotedShell(value);
  return value;
}

function isWholeCommandSymbolWord(
  command: string,
  words: ShellWord[],
  word: ShellWord,
  match: SymbolMatch,
): boolean {
  return words.length === 1 &&
    word.text === match.symbol &&
    command.slice(0, word.start).trim().length === 0 &&
    command.slice(word.end).trim().length === 0;
}

function applyReplacements(text: string, replacements: Replacement[]): string {
  if (replacements.length === 0) return text;
  const ordered = [...replacements].sort((a, b) => a.start - b.start);
  let out = "";
  let cursor = 0;
  for (const replacement of ordered) {
    out += text.slice(cursor, replacement.start);
    out += replacement.text;
    cursor = replacement.end;
  }
  out += text.slice(cursor);
  return out;
}

export function resolveShellCommandSymbols(
  command: string,
  symbols: Map<string, SymbolEntry>,
): ShellCommandSymbolResolution {
  const normalized = unescapeSymbols(command);
  const words = parseShellWords(normalized);
  const decisions: ShellSymbolResolutionDecision[] = [];
  const replacements: Replacement[] = [];

  for (const word of words) {
    const matches = findSymbolMatches(word.text);
    if (matches.length === 0) continue;

    if (matches.length > 1) {
      for (const match of matches) {
        const hit = entryForToken(symbols, match.symbol);
        decisions.push({
          symbol: match.symbol,
          context: "mixed_token",
          action: "skipped",
          reason: "unsupported_mixed_token",
          fallback: hit ? "raw_resolve" : "preserve_symbol",
        });
        if (hit) {
          replacements.push({
            start: word.start + match.start,
            end: word.start + match.end,
            text: resolvedTokenText(match.symbol, hit),
          });
        }
      }
      continue;
    }

    const match = matches[0]!;
    const hit = entryForToken(symbols, match.symbol);
    const context = standaloneContext(word.text, match);
    if (!hit) {
      decisions.push({
        symbol: match.symbol,
        context,
        action: "skipped",
        reason: "unknown_symbol",
        fallback: "preserve_symbol",
      });
      continue;
    }

    if (context === "mixed_token") {
      decisions.push({
        symbol: match.symbol,
        context,
        action: "skipped",
        reason: "unsupported_mixed_token",
        fallback: "raw_resolve",
      });
      replacements.push({
        start: word.start + match.start,
        end: word.start + match.end,
        text: resolvedTokenText(match.symbol, hit),
      });
      continue;
    }

    decisions.push({
      symbol: match.symbol,
      context,
      action: "applied",
    });
    if (isWholeCommandSymbolWord(normalized, words, word, match)) {
      replacements.push({
        start: word.start,
        end: word.end,
        text: resolvedTokenText(match.symbol, hit),
      });
      continue;
    }

    replacements.push({
      start: word.start + match.start,
      end: word.start + match.end,
      text: replacementForContext(context, resolvedTokenText(match.symbol, hit)),
    });
  }

  const resolved = applyReplacements(normalized, replacements);
  return {
    command: resolved,
    originalCommand: command,
    changed: resolved !== command,
    decisions,
  };
}
