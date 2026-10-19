/**
 * view-map — the bidirectional HumanView↔AgentView prefix map (fs chokepoint,
 * cooperative tier: fs-portable-core.md §3 "The rewrite, precisely").
 *
 * Mandu Track A (interceptors/anthropic-proxy). P2 of the portable fs core:
 * the model-API proxy rewrites *absolute paths on the model wire, both
 * directions* so T-LLM speaks HumanView paths while the agent process (whose
 * CWD is the AgentView worktree, P1) operates on the AgentView copies:
 *
 *   forward  (model→agent, response tool_use args): HumanView → AgentView
 *   reverse  (agent→model, request tool_result content, echoed assistant
 *             tool_use args + conversation free text): AgentView → HumanView
 *
 * Conservative rules (fs-portable-core.md §3 — every one is load-bearing):
 *   1. One (humanRoot, agentRoot) pair per workspace root; forward is
 *      IDEMPOTENT (an AgentView-prefixed input passes through unchanged).
 *   2. Field-level, registry-driven: only the path-typed fields of tools in
 *      CLAUDE_CODE_PATH_FIELDS are rewritten, plus textual prefix substitution
 *      inside Bash.command. Content-typed fields (Write.content,
 *      Edit.new_string/old_string, …) are NEVER rewritten — by construction
 *      (they are not in the registry), killing the use-vs-mention corruption
 *      class (gap class 4).
 *   3. Unknown tool ⇒ no rewrite (rewriteToolUseInput returns null) — the
 *      caller falls back to CWD scoping + the context backstop.
 *   4. Lexical normalization before matching: `~`, `.`/`..`, doubled
 *      separators; the `win32` dialect speaks drive letters, backslashes,
 *      case-insensitivity and UNC prefixes.
 *
 * SECURITY NOTE: this rewrite is a *view-consistency* mechanism, not the
 * symbolization boundary. Its failure mode (no rewrite) degrades to P1's CWD
 * scoping + the fail-closed context backstop — untrusted bytes still get
 * symbolized on the way into T-LLM. That is why every ambiguous case here
 * resolves to "pass through unchanged", never to "guess".
 */

import { homedir } from "node:os";
import path from "node:path";

import {
  type MessagesRequest,
  type ToolResultBlock,
  isToolUseBlock,
  isToolResultBlock,
  isTextBlock,
} from "./messages-types.js";
import { parseApplyPatch, rewritePatchPaths } from "./apply-patch.js";
// (isToolUseBlock is used by reverseMapRequestPaths below; the response-side
// forward walk lives in proxy.ts where the P2 map composes with the P3 gate.)

/** One workspace root pair: the real tree and its AgentView worktree. */
export interface ViewRootPair {
  /** HumanView root (the user's real workspace, e.g. the git toplevel). */
  human: string;
  /** AgentView root (the symbolized worktree the agent runs in). */
  agent: string;
}

export type ViewMapDirection = "forward" | "reverse";

export interface ViewMapOptions {
  /** Path dialect. Default: the local platform. Tests force "win32" on Linux. */
  dialect?: "posix" | "win32";
  /** Home dir for `~` expansion. Default: os.homedir(). */
  home?: string;
}

/**
 * Path-typed input fields per Claude Code tool (registry-driven, rule 2).
 * Mirrors originFor() in rewrite-request.ts — keep the two in sync when the
 * supported-agent registry grows. Bash is special-cased (textual substitution
 * inside `command`), so it does not appear here.
 */
export const CLAUDE_CODE_PATH_FIELDS: Readonly<Record<string, readonly string[]>> = {
  Read: ["file_path"],
  Write: ["file_path"],
  Edit: ["file_path"],
  MultiEdit: ["file_path"],
  NotebookEdit: ["notebook_path"],
  Glob: ["path"],
  Grep: ["path"],
  LS: ["path"],
};

/** The one tool whose path surface is a shell string, not a typed field. */
const TEXTUAL_TOOLS: Readonly<Record<string, readonly string[]>> = {
  Bash: ["command"],
};

/** What each registry tool DOES to its path — the `mode` the P3 sensitive-path
 * gate reports to the arbiter (and the approval queue keys on). */
export const FS_MODE_BY_TOOL: Readonly<Record<string, "read" | "write">> = {
  Read: "read",
  Glob: "read",
  Grep: "read",
  LS: "read",
  Write: "write",
  Edit: "write",
  MultiEdit: "write",
  NotebookEdit: "write",
};

/** The per-agent registry a rewrite may use instead of Claude Code's: the
 *  path-typed fields per tool and the shell tools' command field (textual
 *  substitution). Structurally the gate surface (gate-surface.ts). */
export interface ToolFieldSurface {
  paths: Readonly<Record<string, { fields: readonly string[] }>>;
  exec: Readonly<Record<string, string>>;
  /** Tools whose paths are the file headers of a patch text (gate-surface.ts
   *  PatchToolFields): only the header paths are mapped, never a content
   *  line (apply-patch.ts rewritePatchPaths). */
  patch?: Readonly<Record<string, { field: string }>>;
}

/** Result of a registry-driven tool_use input rewrite. */
export interface ToolInputRewrite {
  /** The rewritten input (a fresh object; the caller's input is untouched). */
  input: Record<string, unknown>;
  /** True iff at least one field changed. */
  changed: boolean;
}

/**
 * A character that may continue a path token. Used to detect the *segment
 * boundary* after a matched prefix in free text: `/a/b` must not rewrite
 * inside `/a/bc` or `/a/b_backup`.
 */
function isPathTokenChar(c: string | undefined, dialect: "posix" | "win32"): boolean {
  if (c === undefined) return false;
  if (c === "/" ) return false; // a separator ENDS the prefix segment — allowed
  if (dialect === "win32" && c === "\\") return false;
  // Conservative: letters, digits and common filename punctuation continue a token.
  return /[A-Za-z0-9._\-~+@%]/.test(c);
}

/**
 * A character BEFORE a matched root that means the match is NOT a fresh path
 * start — so the substitution must be skipped. `undefined` (start-of-string) is
 * a valid boundary. Blockers:
 *   - path-token chars (letters/digits/`._-~+@%`): the root is glued to a
 *     preceding token, so it is an infix, e.g. `/backup/home/u/ws` — the
 *     embedded `/home/u/ws` must not be rewritten;
 *   - a separator (`/`, or `\` on win32): the root is a sub-path of a longer
 *     absolute path;
 *   - `:`: a `host:path` (scp/rsync) or `scheme:path` — the path after it is
 *     NOT a local absolute path, e.g. `scp host:~/ws/f` must stay remote.
 * Everything else (whitespace, quotes, `=`, `(`, `,`, shell operators, …) is a
 * genuine left boundary where the path begins fresh.
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
 * Bash.command a trailing `.` legitimately spells a file named `ws.`, so
 * forward keeps the strict token rule.
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
  /** Normalized root pairs (both directions match against these). */
  private readonly pairs: ViewRootPair[];

  constructor(pairs: ViewRootPair[], opts: ViewMapOptions = {}) {
    this.dialect = opts.dialect ?? (process.platform === "win32" ? "win32" : "posix");
    this.home = opts.home ?? homedir();
    this.pairs = pairs
      .filter((p) => p && typeof p.human === "string" && typeof p.agent === "string")
      .map((p) => ({
        human: this.normalize(p.human),
        agent: this.normalize(p.agent),
      }))
      // A degenerate pair (empty / identical / root-dir / NESTED roots) could
      // rewrite half the filesystem or loop on itself — refuse it rather than
      // be clever (rule 3's spirit). Nested roots cannot happen in the real
      // layout (view state lives OUTSIDE the workspace by design), and
      // refusing them keeps mapText trivially idempotent.
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

  /** True when the map has at least one usable root pair. */
  get active(): boolean {
    return this.pairs.length > 0;
  }

  /** The normalized pairs (read-only view, for logging / tests). */
  roots(): readonly ViewRootPair[] {
    return this.pairs;
  }

  /**
   * Is (normalized) `p` inside ANY workspace root, HumanView or AgentView?
   * The P3 sensitive-path gate consults this: in-workspace paths are never
   * gated; everything else goes to the arbiter's fsPathDecision.
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

  // ── path-level mapping ──────────────────────────────────────────────────────

  /**
   * Map one absolute path HumanView→AgentView (forward) or back (reverse).
   * IDEMPOTENT: a path already under the destination root returns unchanged
   * (rule 1), so a model that echoes an already-mapped path round-trips cleanly.
   * A path under neither root returns unchanged (in its ORIGINAL spelling —
   * normalization is for matching only, never a gratuitous rewrite).
   */
  mapPath(p: string, dir: ViewMapDirection): string {
    if (!this.active || typeof p !== "string" || p === "") return p;
    const norm = this.normalize(p);
    if (!this.isAbsolute(norm)) return p; // relative paths are CWD scoping's job
    for (const pair of this.pairs) {
      const [from, to] = dir === "forward" ? [pair.human, pair.agent] : [pair.agent, pair.human];
      // Idempotency first: already under the destination root → unchanged.
      if (this.underRoot(norm, to) !== null) return p;
      const rel = this.underRoot(norm, from);
      if (rel !== null) return this.joinRoot(to, rel);
    }
    return p;
  }

  // ── text-level mapping (Bash.command forward; tool_result content reverse) ──

  /**
   * Substitute every root-prefixed absolute path inside free text. Matches are
   * segment-aware (a matched root must end at a separator, whitespace, quote or
   * end-of-string — `/ws` never rewrites inside `/ws2`; in REVERSE, sentence
   * punctuation also ends it — `/ws. Next` rewrites, `/ws.bak` does not — see
   * isSentenceDotRun). Only the PREFIX is
   * substituted; the tail (including any `..` games) rides along untouched —
   * gap class 2 is documented residue, absorbed lexically only at the typed
   * field level where we can normalize the whole path.
   *
   * `applied` (optional, observability only): each root pair whose prefix
   * substitution actually changed the text is pushed onto it, so the caller can
   * report WHICH translation applied without diffing the strings itself.
   */
  mapText(text: string, dir: ViewMapDirection, applied?: ViewRootPair[]): string {
    if (!this.active || typeof text !== "string" || text === "") return text;
    // Reverse only: a sentence period/ellipsis right after the root is a valid
    // boundary (the CWD-note leak class — see isSentenceDotRun).
    const sentenceDots = dir === "reverse";
    let out = text;
    for (const pair of this.pairs) {
      const [from, to] = dir === "forward" ? [pair.human, pair.agent] : [pair.agent, pair.human];
      // Idempotency: occurrences already under the destination root are left
      // alone by construction (we only replace `from`-prefixed spans; `to` is
      // never a prefix of `from` — degenerate pairs were filtered).
      const before = out;
      out = this.substitutePrefix(out, from, to, sentenceDots);
      if (this.dialect === "posix") {
        // Also catch the `~`-spelled form of the same root in free text.
        const tilde = this.tildeSpelling(from);
        if (tilde) out = this.substitutePrefix(out, tilde, to, sentenceDots);
      }
      if (applied && out !== before) applied.push(pair);
    }
    return out;
  }

  // ── registry-driven tool_use input rewrite ─────────────────────────────────

  /**
   * Rewrite the path-typed fields of one tool_use input (rule 2). Returns null
   * for a tool outside the registry (rule 3 — the caller MUST treat null as
   * "pass through unchanged and rely on CWD + backstop"). Never touches fields
   * that are not in the registry, so content-typed fields are structurally safe.
   */
  rewriteToolUseInput(
    toolName: string,
    input: unknown,
    dir: ViewMapDirection,
    surface?: ToolFieldSurface,
  ): ToolInputRewrite | null {
    if (!this.active) return null;
    const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
    // The session agent's own tool names when the proxy knows them
    // (gate-surface.ts); Claude Code's otherwise.
    const pathFields = surface
      ? (own(surface.paths, toolName) ? surface.paths[toolName]!.fields : undefined)
      : CLAUDE_CODE_PATH_FIELDS[toolName];
    const textFields = surface
      ? (own(surface.exec, toolName) ? [surface.exec[toolName]!] : undefined)
      : TEXTUAL_TOOLS[toolName];
    const patchField = surface?.patch && own(surface.patch, toolName) ? surface.patch[toolName]!.field : undefined;
    if (!pathFields && !textFields && !patchField) return null; // unknown tool ⇒ no rewrite
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      return null; // malformed input ⇒ conservative pass-through
    }
    const src = input as Record<string, unknown>;
    const out: Record<string, unknown> = { ...src };
    let changed = false;
    for (const f of pathFields ?? []) {
      const v = src[f];
      if (typeof v === "string" && v !== "") {
        const mapped = this.mapPath(v, dir);
        if (mapped !== v) {
          out[f] = mapped;
          changed = true;
        }
      } else if (Array.isArray(v)) {
        // an array of paths (browser `paths`, image `images`): each string
        const next = v.map((el) => (typeof el === "string" && el !== "" ? this.mapPath(el, dir) : el));
        if (next.some((el, i) => el !== v[i])) {
          out[f] = next;
          changed = true;
        }
      }
    }
    if (patchField !== undefined && typeof src[patchField] === "string") {
      // The header paths of a patch; a patch that does not parse passes
      // through (the gate has already refused it on the forward wire).
      const text = src[patchField] as string;
      const parsed = parseApplyPatch(text);
      if (parsed.ok) {
        const next = new Map<number, string>();
        parsed.paths.forEach((p, i) => {
          if (p.path === "") return;
          const mapped = this.mapPath(p.path, dir);
          if (mapped !== p.path) next.set(i, mapped);
        });
        if (next.size > 0) {
          out[patchField] = rewritePatchPaths(text, parsed.paths, next);
          changed = true;
        }
      }
    }
    for (const f of textFields ?? []) {
      const v = src[f];
      if (typeof v === "string" && v !== "") {
        const mapped = this.mapText(v, dir);
        if (mapped !== v) {
          out[f] = mapped;
          changed = true;
        }
      }
    }
    return { input: out, changed };
  }

  // ── normalization (rule 4) ──────────────────────────────────────────────────

  /**
   * Lexical normalization for MATCHING: expand `~`, collapse doubled
   * separators, resolve `.`/`..` segments, unify the dialect's separator
   * (win32: backslash), strip a trailing separator. Purely lexical — never
   * touches the filesystem (no realpath: symlink aliasing is gap class 3,
   * absorbed elsewhere).
   */
  normalize(p: string): string {
    if (typeof p !== "string") return "";
    let s = p.trim();
    if (s === "") return "";
    if (s === "~") s = this.home;
    else if (s.startsWith("~/") || (this.dialect === "win32" && s.startsWith("~\\"))) {
      s = this.pathApi().join(this.home, s.slice(2));
    }
    let norm = this.pathApi().normalize(s);
    // Strip a trailing separator (normalize keeps it), except a bare root.
    if (norm.length > 1 && (norm.endsWith("/") || (this.dialect === "win32" && norm.endsWith("\\")))) {
      const stripped = norm.slice(0, -1);
      if (!this.isFilesystemRoot(norm)) norm = stripped;
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

  /** Dialect-aware equality (win32: case-insensitive). */
  private samePath(a: string, b: string): boolean {
    return this.dialect === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
  }

  private isFilesystemRoot(p: string): boolean {
    const norm = this.pathApi().normalize(p);
    return this.pathApi().dirname(norm) === norm;
  }

  /**
   * If normalized `p` is `root` itself or below it, return the RELATIVE tail
   * ("" for the root itself); else null. Segment-aware: `/a/b` is not under
   * `/a/bc`.
   */
  private underRoot(p: string, root: string): string | null {
    const cmpP = this.dialect === "win32" ? p.toLowerCase() : p;
    const cmpR = this.dialect === "win32" ? root.toLowerCase() : root;
    if (cmpP === cmpR) return "";
    const sep = this.dialect === "win32" ? "\\" : "/";
    if (cmpP.startsWith(cmpR + sep)) return p.slice(root.length + 1);
    // win32 tolerates forward slashes on the wire.
    if (this.dialect === "win32" && cmpP.startsWith(cmpR + "/")) return p.slice(root.length + 1);
    return null;
  }

  private joinRoot(root: string, rel: string): string {
    return rel === "" ? root : this.pathApi().join(root, rel);
  }

  /** The `~/…` spelling of an absolute path under home, or null. */
  private tildeSpelling(abs: string): string | null {
    const rel = this.underRoot(abs, this.normalize(this.home));
    if (rel === null) return null;
    return rel === "" ? "~" : `~/${rel}`;
  }

  /**
   * Replace every occurrence of absolute-path prefix `from` in `text` with
   * `to`, requiring a segment boundary right after the match. Win32 matching is
   * case-insensitive and separator-tolerant only in the trivial sense (the
   * literal spelling must match; the map speaks the local dialect — rule 4).
   */
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
      // on the left (not an infix like `/backup/home/u/ws`, not a `host:~/ws`
      // remote), and a segment end on the right (not `/ws` inside `/ws2`). Any
      // other case is skipped — conservative "pass through unchanged". With
      // `sentenceDots` (reverse direction), a period/ellipsis run that ends the
      // token is a valid right boundary: `<root>. Next sentence` rewrites,
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

// ── request/response walkers (the proxy's two hook points) ───────────────────

/** One reverse-map application, reported for observability (the proxy emits a
 * `path_rewrite` event per record — see events.ts makePathRewrite). Typed
 * tool_use fields report both full spellings; free-text content (tool_result
 * content, conversation text blocks) reports the root PAIR that applied (the
 * substitution is prefix-level, and the full before/after text can be
 * arbitrarily large). */
export interface ReverseMapChange {
  block: "tool_use" | "tool_result" | "text";
  /** tool_use.id / tool_result.tool_use_id — correlates to the tool call. */
  callId: string | null;
  tool: string | null;
  /** The rewritten typed field, "content" for tool_result free text, or
   *  "text" for a conversation text block / string body. */
  field: string;
  /** AgentView spelling (before, as the agent echoed it). */
  agent: string;
  /** HumanView spelling (after, as forwarded to T-LLM). */
  human: string;
}

/**
 * Request side (agent→model): reverse-map AgentView paths back to HumanView in
 * the spans the AGENT machine-generated — tool_result content (error messages
 * naming the worktree), the echoed assistant tool_use args (the client
 * received the forward-rewritten form and echoes it back as history), and
 * CONVERSATION free text (user/assistant text blocks and string bodies). After
 * this pass T-LLM sees only HumanView paths in the messages it reasons over,
 * so it never learns the worktree exists (fs-portable-core.md §2 worked
 * example).
 *
 * Conversation free text was originally NOT touched ("user text is the
 * human's own words" — rule 2's conservative reading), but the client
 * machine-generates user-message text too: an @-mention in the typed prompt
 * is pre-read CLIENT-side (CWD = the AgentView worktree) and lands as a
 * `<system-reminder>Called the Read tool with the following input:
 * {"file_path":"<agentview>/…"}</system-reminder>` USER text block — the twin
 * spelling straight into T-LLM's context, caught live by E28's
 * no-agentview-path-in-model oracle (2026-07-14). Reverse-mapping ALL
 * conversation text closes the shape; over-mapping errs toward
 * confidentiality (same argument as isSentenceDotRun). Thinking blocks are
 * never touched (mutating them would invalidate their signature), and
 * `req.system` is deliberately out of scope: the agent's own env block
 * legitimately names the AgentView CWD (session-paths.ts reads it from
 * exactly there).
 *
 * MUST run AFTER symbolization (rewrite-request.ts): untrusted tool_result
 * content is already an opaque `$MDU:*` token (no paths to map, and the
 * symbol table keeps the true original for HumanView restore); only TRUSTED
 * pass-through content gets reverse-mapped here.
 *
 * Mutates `req` in place (the proxy owns the clone it forwards). Returns the
 * list of applications so the caller can EMIT them (observability only; an
 * ignoring caller loses nothing).
 */
export function reverseMapRequestPaths(req: MessagesRequest, map: ViewMap, surface?: ToolFieldSurface): ReverseMapChange[] {
  const changes: ReverseMapChange[] = [];
  if (!map.active) return changes;
  // Free-text application: report at root-pair granularity, once per pair per span.
  const reportText = (applied: ViewRootPair[]) => {
    const seen = new Set<string>();
    for (const p of applied) {
      const key = `${p.agent} ${p.human}`;
      if (seen.has(key)) continue;
      seen.add(key);
      changes.push({
        block: "text", callId: null, tool: null,
        field: "text", agent: p.agent, human: p.human,
      });
    }
  };
  for (const msg of req.messages ?? []) {
    if (typeof msg.content === "string") {
      // String-body message: the whole content is conversation free text.
      const applied: ViewRootPair[] = [];
      msg.content = map.mapText(msg.content, "reverse", applied);
      reportText(applied);
      continue;
    }
    if (!Array.isArray(msg.content)) continue;
    for (const block of msg.content) {
      if (msg.role === "assistant" && isToolUseBlock(block)) {
        const before = block.input as Record<string, unknown> | null;
        const r = map.rewriteToolUseInput(block.name, block.input, "reverse", surface);
        if (r?.changed) {
          // Report each changed field with both spellings (before=agent, after=human).
          for (const [field, after] of Object.entries(r.input)) {
            const prev = before?.[field];
            if (typeof prev === "string" && typeof after === "string" && prev !== after) {
              changes.push({
                block: "tool_use", callId: block.id, tool: block.name,
                field, agent: prev, human: after,
              });
            }
          }
          block.input = r.input;
        }
      } else if (isToolResultBlock(block)) {
        const tr = block as ToolResultBlock;
        const applied: ViewRootPair[] = [];
        if (typeof tr.content === "string") {
          tr.content = map.mapText(tr.content, "reverse", applied);
        } else if (Array.isArray(tr.content)) {
          for (const c of tr.content) {
            if (c && typeof c === "object" && c.type === "text" && typeof c.text === "string") {
              c.text = map.mapText(c.text, "reverse", applied);
            }
          }
        }
        // Free text: report at root-pair granularity, once per pair per block.
        const seen = new Set<string>();
        for (const p of applied) {
          const key = `${p.agent} ${p.human}`;
          if (seen.has(key)) continue;
          seen.add(key);
          changes.push({
            block: "tool_result", callId: tr.tool_use_id ?? null, tool: null,
            field: "content", agent: p.agent, human: p.human,
          });
        }
      } else if (isTextBlock(block)) {
        // Conversation free text (user OR assistant): the client machine-
        // generates user text too (@-mention pre-read reminders) — see the
        // function docblock. The `type === "text"` gate means thinking /
        // redacted_thinking / image blocks are never touched.
        const applied: ViewRootPair[] = [];
        block.text = map.mapText(block.text, "reverse", applied);
        reportText(applied);
      }
    }
  }
  return changes;
}

// ── env-spec parsing (server-main / launcher contract) ────────────────────────

/**
 * Parse the MANDU_VIEW_MAP env value: a JSON array of {human, agent} pairs,
 * e.g. `[{"human":"/home/u/ws","agent":"/home/u/.mandu/workspaces/x/agentview"}]`.
 * Returns [] for an unset/empty value. THROWS on malformed JSON or wrong shape —
 * the caller must fail LOUDLY (a silently-dropped map would run the session
 * without the rewrite while the operator believes it is on).
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
