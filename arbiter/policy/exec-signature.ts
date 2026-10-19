/**
 * exec-signature — the correlation key that bridges the proxy↔execve gap
 * (exec-routing.md §4 step 1). Mandu-new, no reference origin.
 *
 * The model proxy sees a command as the model WROTE it (`curl https://x/$SYM`);
 * the exec-supervisor sees the GROUND-TRUTH argv at execve, which is typically the
 * shell wrapper the agent spawns (`bash -lc "curl https://x/$SYM"`) or a leaf
 * child (`curl https://x/$SYM`). To let the supervisor look up the proxy's
 * recorded exec decision, both sides normalize a command to the SAME stable
 * `signature`:
 *
 *   1. unwrap a shell `-c`/`-lc` wrapper down to its code payload (recursively),
 *      so `bash -lc "<cmd>"` and the bare `<cmd>` collapse to the same core;
 *      the payload is read once, as the shell reads it: it is already
 *      unquoted (an argv element, or a word the tokenizer unquoted), so it is
 *      tokenized as it stands, never stripped of another quote layer;
 *   2. write the core's words back in one canonical quoting: a word with no
 *      whitespace, quote or backslash bare, any other (and an empty word)
 *      single-quoted, joined by single spaces. Runs of unquoted whitespace
 *      collapse (the tokenizer splits on them); argument boundaries and the
 *      bytes inside a word are kept, so `echo "a b"` and `echo a b`, or a
 *      payload with an extra quote layer and the command inside it, are
 *      different signatures (plan 13 D7: a call binds to the shells of its
 *      signature only; 2026-10-03, D8 leftover (5)).
 *
 * The correlation is defense-in-depth for the exec gate (a MISS costs only
 * the proxy-hint: the supervisor's own classifyExec still decides,
 * fail-closed to AgentShell), and the call-root recorder's key (plan 13 D7:
 * a miss leaves the call unbound, masked whole while the session holds a
 * raw read; a collision folds or outnumbers, so it never unmasks a call, but
 * the signature is kept as exact as the tokenizer allows). Exact argv
 * reconstruction across shell expansion is impossible; the signature never
 * desymbolizes and never inspects values; it is a pure text normalization.
 */

import { basename, tokenize, INLINE_CODE_FLAGS } from "./exec-identifier.js";

/** Shells whose `-c`/`-lc` argument is a code payload we unwrap to the core. */
const SHELLS: ReadonlySet<string> = new Set(["sh", "bash", "zsh", "dash", "ash"]);

/** A `-c` family flag (single-dash cluster containing `c`, e.g. `-c`, `-lc`). */
function isCommandFlag(token: string): boolean {
  return token === "--command" || /^-[A-Za-z]*c[A-Za-z]*$/.test(token);
}

/** One word in the signature's canonical quoting: bare when it holds no
 *  whitespace, quote or backslash (and is not empty), else single-quoted
 *  (`'` written `'"'"'`). The tokenizer reads it back to the same word, so
 *  the joined words name one token list (injective). */
function canonicalWord(w: string): string {
  return w !== "" && !/[\s'"\\]/.test(w) ? w : `'${w.replace(/'/g, `'"'"'`)}'`;
}

/** The canonical text of a token list (see the header, step 2). */
function canonical(tokens: readonly string[]): string {
  return tokens.map(canonicalWord).join(" ");
}

/** True for a `VAR=val` env-assignment prefix. */
function isEnvAssignment(token: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);
}

/**
 * Unwrap a shell `-c <payload>` (or interpreter inline-code) invocation down to
 * its innermost code core, recursively, operating on a TOKEN list. This is the
 * shared core so both entry points preserve argument boundaries:
 *   - `execSignature` tokenizes the command string first (quotes → one token);
 *   - `execSignatureForArgv` passes the observed argv AS the tokens, so a shell
 *     `-c` payload that is one argv element stays one token (a space-join would
 *     have split `bash -lc "curl a"` into `bash -lc curl a`, losing the payload).
 * When the head is a shell/interpreter with a code flag, recurse into the flag's
 * argument; otherwise the tokens ARE the core. Bounded recursion.
 */
function unwrapTokens(tokens: string[], depth = 0): string[] {
  if (depth > 8 || tokens.length === 0) return tokens;
  // Skip leading `VAR=val` / `env` prefixes to find the program word.
  let i = 0;
  while (i < tokens.length && (isEnvAssignment(tokens[i]!) || basename(tokens[i]!) === "env")) i++;
  if (i >= tokens.length) return tokens;
  const prog = basename(tokens[i]!);
  const isShell = SHELLS.has(prog);
  const isInterp = prog === "node" || /^python(\d(\.\d+)*)?$/.test(prog);
  if (!isShell && !isInterp) return tokens;

  // Find the code flag and recurse into the FOLLOWING argument as the payload.
  for (let j = i + 1; j < tokens.length; j++) {
    const t = tokens[j]!;
    const isCode = isShell ? isCommandFlag(t) : INLINE_CODE_FLAGS.has(t);
    if (isCode && j + 1 < tokens.length) {
      // The payload is already unquoted: read it as the shell does, once.
      return unwrapTokens(tokenize(tokens[j + 1]!), depth + 1);
    }
    // A non-flag before any code flag → not a `-c` invocation; stop.
    if (!t.startsWith("-")) break;
  }
  return tokens;
}

/**
 * The stable correlation signature for a command string. Unwraps shell `-c`
 * wrappers to the code core, then writes it in the canonical quoting.
 * Empty input → "".
 */
export function execSignature(command: string): string {
  if (typeof command !== "string" || command.trim() === "") return "";
  return canonical(unwrapTokens(tokenize(command.trim())));
}

/** The signature for an observed argv (the supervisor's input). Uses the argv
 * elements AS tokens, so a shell `-c` payload that is one argv element is
 * unwrapped correctly (a space-join would have lost the boundary). */
export function execSignatureForArgv(argv: string[]): string {
  if (argv.length === 0) return "";
  return canonical(unwrapTokens(argv.slice()));
}

/** The payload of a shell `-c` invocation in an observed argv: the first
 *  non-option argument after a `-c`-family flag (`bash -c -l '<payload>'`
 *  takes options after `-c` too). Null when the argv is no shell `-c`. */
export function shellPayload(argv: readonly string[]): string | null {
  let i = 0;
  while (i < argv.length && (isEnvAssignment(argv[i]!) || basename(argv[i]!) === "env")) i++;
  if (i >= argv.length || !SHELLS.has(basename(argv[i]!))) return null;
  let sawC = false;
  for (let j = i + 1; j < argv.length; j++) {
    const t = argv[j]!;
    if (t === "--") continue;
    if (t.startsWith("-") && t.length > 1) {
      if (isCommandFlag(t)) sawC = true;
      continue;
    }
    return sawC ? t : null;
  }
  return null;
}

/** A shell `-c` invocation whose payload is missing: `zsh -c` with nothing
 *  after the flag(s). The guard reads each argv element up to a bound and
 *  stops at the first one over it, so a shell handed a long payload (Codex's
 *  shell-snapshot preamble) is recorded this way. Pure. */
export function isPayloadlessShellC(argv: readonly string[]): boolean {
  if (argv.length < 2 || !SHELLS.has(basename(argv[0]!))) return false;
  const rest = argv.slice(1);
  return rest.every((t) => t.startsWith("-")) && rest.some((t) => isCommandFlag(t));
}

/**
 * Plan 13 D7, the call-root recorder: every command signature an exec of the
 * agent's own child can be the root of. The agent runs each shell tool call
 * in a shell of its own, which the guard reports as an exec whose parent is
 * the agent; the model proxy knows the command the model wrote. Two shapes:
 *
 *   - Codex, OpenCode, OpenClaw: `bash -lc '<command>'`, whose signature IS
 *     the command's (`execSignatureForArgv`);
 *   - Claude Code: `zsh -c 'source <snapshot> … && eval '<quoted command>'
 *     && pwd -P >| /tmp/claude-…-cwd'`: the command is the word after an
 *     `eval` in the payload, shell-unquoted (every `eval` word is listed, so a
 *     command that itself starts with `eval` matches too).
 *
 * A signature listed here that is not the call's own can only add a
 * candidate root: the binding then folds every candidate (fail-closed), never
 * fewer. Pure; never throws.
 */
export function rootSignaturesOfArgv(argv: readonly string[]): string[] {
  if (!Array.isArray(argv) || argv.length === 0 || !argv.every((a) => typeof a === "string")) return [];
  const out = new Set<string>();
  const own = execSignatureForArgv(argv.slice());
  if (own !== "") out.add(own);
  const payload = shellPayload(argv);
  if (payload !== null) {
    const toks = tokenize(payload);
    for (let k = 0; k + 1 < toks.length; k++) {
      if (toks[k] !== "eval") continue;
      const sig = execSignature(toks[k + 1]!);
      if (sig !== "") out.add(sig);
    }
  }
  return [...out];
}
