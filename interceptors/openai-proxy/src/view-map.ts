/**
 * view-map — the bidirectional HumanView↔AgentView prefix map for the Codex
 * (OpenAI Responses API) wire format (fs-sync.md §1.3, P4 parity).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   The ViewMap CORE (constructor pair-filtering, normalize, mapPath, mapText,
 *   withinRoots, underRoot, substitutePrefix, parseViewMapEnv) is COPIED from
 *   the proven, unit-tested
 *     interceptors/anthropic-proxy/src/view-map.ts
 *   (each interceptor package installs + typechecks standalone with its own
 *   rootDir, so the sibling module is mirrored here rather than cross-imported —
 *   same convention as arbiter-client.ts). Only the AGENT-SPECIFIC surface
 *   differs: Codex has NO typed path fields (Claude's Read.file_path etc.).
 *   Every Codex path lives inside a free-text shell command string
 *   (`function_call.arguments.cmd`) — the exact analog of Claude's
 *   `Bash.command` — so the Codex adapters are TEXTUAL:
 *     forward  (model→agent): map the command string of each response
 *              function_call (HumanView→AgentView);
 *     reverse  (agent→model): map function_call_output text + the echoed
 *              function_call command string (AgentView→HumanView).
 *
 * CONSERVATIVE, same as the Bash.command rule (fs-sync.md §1.3 rule 2):
 * textual substitution rewrites ONLY absolute-path prefixes under a known root
 * (segment-aware); relative paths, and paths NOT under a root, ride through
 * untouched. A workspace-absolute path that appears as data inside the command
 * (a "mention") is rewritten too — accepted residue for shell strings, which
 * are the exec chokepoint's turf (identical to the Claude Bash.command
 * behavior). This is why Codex has NO context-proxy sensitive-path gate (P3):
 * there are no typed path FIELDS to gate — see fs-sync.md §1.4.1.
 */

import { homedir } from "node:os";
import path from "node:path";

import {
  type ResponsesRequest,
  type FunctionCallItem,
  type ToolOutputItem,
  isCustomToolCallItem,
  isFunctionCallItem,
  isMessageItem,
  isToolOutputItem,
} from "./responses-types.js";

/** One workspace root pair: the real tree and its AgentView worktree. */
export interface ViewRootPair {
  human: string;
  agent: string;
}

export type ViewMapDirection = "forward" | "reverse";

export interface ViewMapOptions {
  dialect?: "posix" | "win32";
  home?: string;
}

/**
 * Codex function_call argument keys that carry a SHELL COMMAND string (the path
 * surface). `cmd` is what codex 0.136 emits for `exec_command`; the alternates
 * mirror originFor() in rewrite-request.ts so the map tracks tool/param drift.
 */
export const CODEX_COMMAND_KEYS: readonly string[] = ["cmd", "command"];

/**
 * Argument keys that carry a bare DIRECTORY the command runs in. The script
 * cell (codex ≥ 0.154) passes `workdir`, and the model spells it the way it
 * sees the tree — HumanView — so without the forward map the command would
 * run in the user's real tree, outside the AgentView twin (observed
 * 2026-09-24: `"workdir":"/…/ws-probe"` next to the AgentView cwd). Mapped in
 * both directions exactly like a command string (a bare path is a one-token
 * text).
 */
export const CODEX_PATH_KEYS: readonly string[] = ["workdir", "cwd"];

function isPathTokenChar(c: string | undefined, dialect: "posix" | "win32"): boolean {
  if (c === undefined) return false;
  if (c === "/") return false;
  if (dialect === "win32" && c === "\\") return false;
  return /[A-Za-z0-9._\-~+@%]/.test(c);
}

/**
 * A character BEFORE a matched root that means the match is NOT a fresh path
 * start (so the substitution must be skipped). `undefined` (start-of-string) is
 * a valid boundary. Blockers: path-token chars (infix, e.g. `/backup/home/u/ws`);
 * a separator `/` (or `\` on win32) — a sub-path of a longer absolute path; and
 * `:` — a `host:path`/`scheme:path`, whose path is not local (`scp host:~/ws/f`
 * must stay remote). Everything else (whitespace, quotes, `=`, shell operators)
 * is a genuine left boundary.
 */
function isLeftBoundaryBlocker(c: string | undefined, dialect: "posix" | "win32"): boolean {
  if (c === undefined) return false;
  if (c === "/" || c === ":") return true;
  if (dialect === "win32" && c === "\\") return true;
  return isPathTokenChar(c, dialect);
}

/**
 * At text[i] (the char right after a matched root), does a run of `.` read as
 * SENTENCE punctuation (period / ellipsis) rather than the continuation of a
 * longer file name? True iff one or more `.` are followed by end-of-string or a
 * char that neither continues a path token (`agentview.bak` — a sibling dir)
 * nor opens a separator (`agentview./sub` — a genuinely different directory).
 * Only the REVERSE direction consults this (mapText): the CWD-leak class is
 * agent-generated prose naming the worktree root at a sentence end ("your
 * current working directory is <root>."), and over-mapping there errs toward
 * confidentiality — T-LLM must never see the AgentView spelling. In a forward
 * command a trailing `.` legitimately spells a file named `ws.`, so forward
 * keeps the strict token rule.
 */
function isSentenceDotRun(text: string, i: number, dialect: "posix" | "win32"): boolean {
  if (text[i] !== ".") return false;
  let j = i;
  while (text[j] === ".") j++;
  const next = text[j];
  if (next === undefined) return true;
  if (next === "/" || (dialect === "win32" && next === "\\")) return false;
  return !isPathTokenChar(next, dialect);
}

export class ViewMap {
  private readonly dialect: "posix" | "win32";
  private readonly home: string;
  private readonly pairs: ViewRootPair[];

  constructor(pairs: ViewRootPair[], opts: ViewMapOptions = {}) {
    this.dialect = opts.dialect ?? (process.platform === "win32" ? "win32" : "posix");
    this.home = opts.home ?? homedir();
    this.pairs = pairs
      .filter((p) => p && typeof p.human === "string" && typeof p.agent === "string")
      .map((p) => ({ human: this.normalize(p.human), agent: this.normalize(p.agent) }))
      .filter(
        (p) =>
          p.human !== "" &&
          p.agent !== "" &&
          !this.samePath(p.human, p.agent) &&
          !this.isFilesystemRoot(p.human) &&
          !this.isFilesystemRoot(p.agent) &&
          this.underRoot(p.human, p.agent) === null &&
          this.underRoot(p.agent, p.human) === null,
      );
  }

  get active(): boolean {
    return this.pairs.length > 0;
  }

  roots(): readonly ViewRootPair[] {
    return this.pairs;
  }

  // ── path-level mapping ──────────────────────────────────────────────────────

  mapPath(p: string, dir: ViewMapDirection): string {
    if (!this.active || typeof p !== "string" || p === "") return p;
    const norm = this.normalize(p);
    if (!this.isAbsolute(norm)) return p;
    for (const pair of this.pairs) {
      const [from, to] = dir === "forward" ? [pair.human, pair.agent] : [pair.agent, pair.human];
      if (this.underRoot(norm, to) !== null) return p; // idempotent
      const rel = this.underRoot(norm, from);
      if (rel !== null) return this.joinRoot(to, rel);
    }
    return p;
  }

  // ── text-level mapping (the Codex command surface) ─────────────────────────

  mapText(text: string, dir: ViewMapDirection): string {
    if (!this.active || typeof text !== "string" || text === "") return text;
    // Reverse only: a sentence period/ellipsis right after the root is a valid
    // boundary (the CWD-note leak class — see isSentenceDotRun).
    const sentenceDots = dir === "reverse";
    let out = text;
    for (const pair of this.pairs) {
      const [from, to] = dir === "forward" ? [pair.human, pair.agent] : [pair.agent, pair.human];
      out = this.substitutePrefix(out, from, to, sentenceDots);
      if (this.dialect === "posix") {
        const tilde = this.tildeSpelling(from);
        if (tilde) out = this.substitutePrefix(out, tilde, to, sentenceDots);
      }
    }
    return out;
  }

  /**
   * Is (normalized) `p` inside ANY workspace root, either view? (Parity helper
   * with the anthropic-proxy; not used by the Codex gate — Codex has none — but
   * kept so the core stays identical and future structured tools can use it.)
   */
  withinRoots(p: string): boolean {
    if (!this.active || typeof p !== "string" || p === "") return false;
    const norm = this.normalize(p);
    for (const pair of this.pairs) {
      if (this.underRoot(norm, pair.human) !== null) return true;
      if (this.underRoot(norm, pair.agent) !== null) return true;
    }
    return false;
  }

  // ── Codex adapter: map the command string of a function_call arguments blob ──

  /**
   * Rewrite the SHELL COMMAND string(s) inside a Codex function_call `arguments`
   * JSON string. Returns the rewritten arguments JSON, or null when nothing
   * changed / the arguments are not the expected shape (conservative: re-emit
   * the ORIGINAL bytes). Only CODEX_COMMAND_KEYS are touched — never other
   * argument fields (structural use-vs-mention safety, rule 2).
   */
  rewriteFunctionCallArguments(argumentsJson: string, dir: ViewMapDirection): string | null {
    if (!this.active || typeof argumentsJson !== "string" || argumentsJson.trim() === "") return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(argumentsJson);
    } catch {
      return null; // rule 3: never rewrite what we cannot parse
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const src = parsed as Record<string, unknown>;
    let changed = false;
    const out: Record<string, unknown> = { ...src };
    for (const key of [...CODEX_COMMAND_KEYS, ...CODEX_PATH_KEYS]) {
      const v = src[key];
      if (typeof v === "string" && v !== "") {
        const mapped = this.mapText(v, dir);
        if (mapped !== v) {
          out[key] = mapped;
          changed = true;
        }
      } else if (Array.isArray(v)) {
        // Some Codex builds send `command` as an argv array (["bash","-lc","…"]).
        const arr = v.map((el) => (typeof el === "string" ? this.mapText(el, dir) : el));
        if (arr.some((el, i) => el !== v[i])) {
          out[key] = arr;
          changed = true;
        }
      }
    }
    return changed ? JSON.stringify(out) : null;
  }

  // ── normalization (rule 4) ──────────────────────────────────────────────────

  normalize(p: string): string {
    if (typeof p !== "string") return "";
    let s = p.trim();
    if (s === "") return "";
    if (s === "~") s = this.home;
    else if (s.startsWith("~/") || (this.dialect === "win32" && s.startsWith("~\\"))) {
      s = this.pathApi().join(this.home, s.slice(2));
    }
    let norm = this.pathApi().normalize(s);
    if (norm.length > 1 && (norm.endsWith("/") || (this.dialect === "win32" && norm.endsWith("\\")))) {
      if (!this.isFilesystemRoot(norm)) norm = norm.slice(0, -1);
    }
    return norm;
  }

  // ── internals ───────────────────────────────────────────────────────────────

  private pathApi(): path.PlatformPath {
    return this.dialect === "win32" ? path.win32 : path.posix;
  }

  private isAbsolute(p: string): boolean {
    return this.pathApi().isAbsolute(p);
  }

  private samePath(a: string, b: string): boolean {
    return this.dialect === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
  }

  private isFilesystemRoot(p: string): boolean {
    const norm = this.pathApi().normalize(p);
    return this.pathApi().dirname(norm) === norm;
  }

  private underRoot(p: string, root: string): string | null {
    const cmpP = this.dialect === "win32" ? p.toLowerCase() : p;
    const cmpR = this.dialect === "win32" ? root.toLowerCase() : root;
    if (cmpP === cmpR) return "";
    const sep = this.dialect === "win32" ? "\\" : "/";
    if (cmpP.startsWith(cmpR + sep)) return p.slice(root.length + 1);
    if (this.dialect === "win32" && cmpP.startsWith(cmpR + "/")) return p.slice(root.length + 1);
    return null;
  }

  private joinRoot(root: string, rel: string): string {
    return rel === "" ? root : this.pathApi().join(root, rel);
  }

  private tildeSpelling(abs: string): string | null {
    const rel = this.underRoot(abs, this.normalize(this.home));
    if (rel === null) return null;
    return rel === "" ? "~" : `~/${rel}`;
  }

  private substitutePrefix(text: string, from: string, to: string, sentenceDots = false): string {
    if (from === "") return text;
    const haystack = this.dialect === "win32" ? text.toLowerCase() : text;
    const needle = this.dialect === "win32" ? from.toLowerCase() : from;
    let result = "";
    let i = 0;
    for (;;) {
      const hit = haystack.indexOf(needle, i);
      if (hit < 0) {
        result += text.slice(i);
        return result;
      }
      const before = hit > 0 ? text[hit - 1] : undefined;
      const after = text[hit + from.length];
      // A genuine path-prefix match must be bounded on BOTH sides: a fresh start
      // on the left (not an infix, not a `host:~/ws` remote) and a segment end
      // on the right. Any other case is skipped (conservative pass-through).
      // With `sentenceDots` (reverse direction), a period/ellipsis run that ends
      // the token is a valid right boundary: `<root>. Next sentence` rewrites,
      // `<root>.bak` still does not.
      const rightBlocked =
        isPathTokenChar(after, this.dialect) &&
        !(sentenceDots && isSentenceDotRun(text, hit + from.length, this.dialect));
      if (isLeftBoundaryBlocker(before, this.dialect) || rightBlocked) {
        result += text.slice(i, hit + from.length);
        i = hit + from.length;
        continue;
      }
      result += text.slice(i, hit) + to;
      i = hit + from.length;
    }
  }
}

// ── request-side walker (agent→model): reverse-map AgentView paths → HumanView ─

/**
 * Reverse-map AgentView paths back to HumanView in the spans the AGENT
 * machine-generated: function_call_output text (a trusted-passthrough tool
 * output naming the worktree), the echoed function_call command args (the
 * client replays the forward-mapped command as history), and user/assistant
 * MESSAGE text (the client machine-generates conversation text too — the
 * anthropic dual's @-mention pre-read reminder, caught live by E28
 * 2026-07-14 — and the codex CLI may echo worktree paths into either role).
 * After this pass T-LLM sees only HumanView paths in the conversation, so it
 * never learns the worktree exists. System/developer message items stay
 * untouched — the agent's own environment text legitimately names its real
 * CWD (the anthropic dual leaves `req.system` alone for the same reason).
 *
 * MUST run AFTER symbolization: an UNTRUSTED function_call_output is already an
 * opaque $MDU:* token (no paths to map; the symbol table keeps the true
 * original); only TRUSTED pass-through output is reverse-mapped here. Mutates
 * `req` in place (the proxy owns the clone it forwards).
 */
export function reverseMapRequestPaths(req: ResponsesRequest, map: ViewMap): void {
  if (!map.active) return;
  for (const item of req.input ?? []) {
    if (isMessageItem(item)) {
      if (item.role !== "user" && item.role !== "assistant") continue;
      if (typeof item.content === "string") {
        item.content = map.mapText(item.content, "reverse");
      } else if (Array.isArray(item.content)) {
        for (const part of item.content) {
          if (part && typeof part === "object" && typeof (part as { text?: unknown }).text === "string") {
            (part as { text: string }).text = map.mapText((part as { text: string }).text, "reverse");
          }
        }
      }
    } else if (isFunctionCallItem(item)) {
      const fc = item as FunctionCallItem;
      if (typeof fc.arguments === "string") {
        const mapped = map.rewriteFunctionCallArguments(fc.arguments, "reverse");
        if (mapped !== null) fc.arguments = mapped;
      }
    } else if (isCustomToolCallItem(item)) {
      // The echoed script cell: JavaScript source naming the AgentView cwd
      // (its `workdir`, a path inside `cmd`) — a free-text surface, mapped
      // like a command string so T-LLM never learns the worktree exists.
      if (typeof item.input === "string") item.input = map.mapText(item.input, "reverse");
    } else if (isToolOutputItem(item)) {
      const out = item as ToolOutputItem;
      if (typeof out.output === "string") {
        out.output = map.mapText(out.output, "reverse");
      } else if (Array.isArray(out.output)) {
        // The parts array — the script-cell wire's normal shape, and the
        // structured variant rewrite-request's flattenOutput defends against.
        // A TRUSTED pass-through output can carry AgentView worktree paths in
        // its `text` fields; reverse-map each so T-LLM never learns the
        // worktree exists.
        // (UNTRUSTED outputs were already replaced by an opaque symbol string,
        // so they never reach this branch.)
        for (const part of out.output) {
          if (part && typeof part === "object" && typeof (part as { text?: unknown }).text === "string") {
            (part as { text: string }).text = map.mapText((part as { text: string }).text, "reverse");
          }
        }
      }
    }
  }
}

// ── env-spec parsing (server-main / launcher contract) ────────────────────────

/**
 * Parse the MANDU_VIEW_MAP env value: a JSON array of {human, agent} pairs.
 * Returns [] for unset/empty; THROWS on malformed JSON / wrong shape (a
 * silently-dropped map would run without the rewrite the launcher asked for).
 * Identical contract to the anthropic-proxy so the launcher exports ONE env var.
 */
export function parseViewMapEnv(raw: string | undefined): ViewRootPair[] {
  if (raw === undefined || raw.trim() === "") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`MANDU_VIEW_MAP is not valid JSON: ${(err as Error).message}`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error("MANDU_VIEW_MAP must be a JSON array of {human, agent} pairs");
  }
  return parsed.map((e, i) => {
    const pair = e as { human?: unknown; agent?: unknown };
    if (!pair || typeof pair.human !== "string" || typeof pair.agent !== "string" ||
        pair.human === "" || pair.agent === "") {
      throw new Error(`MANDU_VIEW_MAP[${i}] must be {human: string, agent: string}`);
    }
    return { human: pair.human, agent: pair.agent };
  });
}
