/**
 * unmapped-upload-core — the unmapped upload leg's pure core, one text in
 * both model proxies (guarantees.md §3, "A tool that uploads a local file by
 * its path"; supported-agents.md §2, "The upload residuals").
 *
 * Mandu-new (no reference origin). A COPY of
 * interceptors/anthropic-proxy/src/unmapped-upload-core.ts, kept byte-equal
 * below the marker line (no cross-package import; this package's unit test
 * pins the two equal). The leg for Codex (which tools it runs for, the code
 * cells, which earlier calls of a turn count as writers) is this package's
 * unmapped-upload.ts; what is shared lives here: finding the local paths a
 * tool's input names, asking the arbiter's `fileUploadDecision` about each
 * in its UNMAPPED form, withholding a held path (it becomes a path under
 * Mandu's denied namespace, which names no file), the window rule's verdict,
 * and the notices the model reads. Fail-closed throughout.
 *
 * Pure but for the arbiter call; never throws.
 */

// ── the shared core: byte-equal in both proxies below this line ──

import path from "node:path";
import { homedir } from "node:os";

import type { Arbiter, FileUploadDecision, RuleRef } from "./arbiter-client.js";

/** Bound on the path-like strings one call may put to the arbiter. A call
 *  with more has every one withheld (fail-closed). */
export const UNMAPPED_UPLOAD_MAX_PATHS = 256;

/** Fail-closed ceiling for one arbiter answer (the upload gate's value: the
 *  arbiter client's whole-call bound for a streamed scan; a silent arbiter
 *  still fails closed at the client's 5 s idle timeout). */
export const DEFAULT_UNMAPPED_UPLOAD_TIMEOUT_MS = 60_000;

/** How deep into the input the leg looks (object values, array elements).
 *  A list or object nested deeper is withheld whole (fail-closed: a path
 *  hidden below the bound would go unchecked). */
export const UNMAPPED_UPLOAD_MAX_DEPTH = 32;

/** Longest string read as a path (PATH_MAX). */
const MAX_PATH_LEN = 4096;

/** Keys under which a RELATIVE string is read as a path (compared
 *  case-insensitively, as a substring of the key: `localPath`, `file_paths`,
 *  `attachments`, `src`, `out_dir`). */
export const PATH_KEY_RE = /path|file|dir|folder|attach|upload|source|src/i;

/** Where in the input a string sits: the keys and indexes from the top. */
export type InputLoc = ReadonlyArray<string | number>;

/** One local path a tool's input names. */
export interface UploadPathCandidate {
  loc: InputLoc;
  /** The string as the model wrote it. */
  shown: string;
  /** The absolute path it names ("" for a `deep` one). */
  path: string;
  /** A list or object nested past UNMAPPED_UPLOAD_MAX_DEPTH: not looked
   *  into, withheld whole. */
  deep?: true;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** The absolute local path one input string names, or null. `key` is the
 *  nearest object key above it (a relative string counts only under a
 *  path-like key, and only with a launch directory to place it). Pure. */
export function localPathOf(raw: string, key: string | null, home: string, launchDir?: string): string | null {
  const s = raw.trim();
  if (s === "" || s.length > MAX_PATH_LEN || /[\0\r\n]/.test(s)) return null;
  if (/^file:/i.test(s)) {
    let u: URL;
    try { u = new URL(s); } catch { return null; }
    if (u.protocol !== "file:" || (u.hostname !== "" && u.hostname.toLowerCase() !== "localhost")) return null;
    let p: string;
    try { p = decodeURIComponent(u.pathname); } catch { return null; }
    return p.startsWith("/") && !p.includes("\0") ? path.posix.resolve(p) : null;
  }
  if (s.startsWith("//")) return null; // a scheme-relative URL, not a path
  if (s.startsWith("/")) return path.posix.resolve(s);
  if (s === "~" || s.startsWith("~/")) return path.posix.resolve(home, s.slice(2));
  if (key === null || !PATH_KEY_RE.test(key) || launchDir === undefined || !launchDir.startsWith("/")) return null;
  // A relative path under a path-like key: one word, no scheme, no option.
  if (/\s/.test(s) || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(s) || s.startsWith("-")) return null;
  return path.posix.resolve(launchDir, s);
}

/** Every local path a tool's input names, depth-first in input order, at
 *  most `max` + 1 (the caller reads one past the bound as overflow). Pure. */
export function uploadPathCandidates(
  input: unknown,
  opts: { home?: string; launchDir?: string; max?: number } = {},
): UploadPathCandidate[] {
  const home = opts.home ?? homedir();
  const max = opts.max ?? UNMAPPED_UPLOAD_MAX_PATHS;
  const out: UploadPathCandidate[] = [];
  const walk = (v: unknown, loc: Array<string | number>, key: string | null, depth: number): void => {
    if (out.length > max) return;
    if (depth > UNMAPPED_UPLOAD_MAX_DEPTH) {
      if (v !== null && typeof v === "object") out.push({ loc: [...loc], shown: "(a value nested too deep to check)", path: "", deep: true });
      return;
    }
    if (typeof v === "string") {
      const p = localPathOf(v, key, home, opts.launchDir);
      if (p !== null) out.push({ loc: [...loc], shown: v, path: p });
      return;
    }
    if (Array.isArray(v)) {
      v.forEach((el, i) => walk(el, [...loc, i], key, depth + 1));
      return;
    }
    if (isObj(v)) for (const [k, el] of Object.entries(v)) walk(el, [...loc, k], k, depth + 1);
  };
  walk(input, [], null, 0);
  return out;
}

/** The input with the string at each `loc` replaced; a deep copy along the
 *  changed branches only. Pure. */
export function replaceAtLocs(input: unknown, edits: ReadonlyArray<{ loc: InputLoc; value: string }>): unknown {
  const set = (node: unknown, loc: InputLoc, i: number, value: string): unknown => {
    if (i === loc.length) return value;
    const k = loc[i]!;
    if (Array.isArray(node) && typeof k === "number") {
      const copy = node.slice();
      copy[k] = set(node[k], loc, i + 1, value);
      return copy;
    }
    if (isObj(node) && typeof k === "string") return { ...node, [k]: set(node[k], loc, i + 1, value) };
    return node;
  };
  let cur = input;
  for (const e of edits) cur = set(cur, e.loc, 0, e.value);
  return cur;
}

/** Where a withheld path goes: under Mandu's denied namespace
 *  (`/mandu/denied`, the anthropic-proxy's fs-gate.ts DENIED_NAMESPACE; its
 *  unit test pins the two equal), so it names no file. */
export const UPLOAD_DENIED_ROOT = "/mandu/denied/upload";

/** The string a withheld path becomes: a path that names no file. */
export function withheldPath(p: string): string {
  return `${UPLOAD_DENIED_ROOT}${p}`;
}

/** One path the leg withheld. */
export interface WithheldPath {
  loc: InputLoc;
  shown: string;
  path: string;
  reason: string;
  ruleRef: RuleRef;
  requiresApproval: boolean;
  approvalId?: string;
}

export interface UnmappedUploadOutcome {
  decision: "allow" | "block";
  reason: string;
  /** What the model reads in place of the call's result, when blocked. */
  notice?: string;
  /** Every path withheld (the first decided the notice). */
  withheld: WithheldPath[];
  /** Every path the arbiter allowed, with its rule (observability). */
  allowed: Array<{ path: string; ruleRef?: RuleRef }>;
}

export interface UnmappedUploadResult {
  input: unknown;
  /** Absent: the input names no local path, so nothing was asked. */
  outcome?: UnmappedUploadOutcome;
}

export interface UnmappedUploadOptions {
  arbiter: Pick<Arbiter, "fileUploadDecision">;
  /** The approval row's session, and whose mapping and guard the arbiter reads. */
  sessionKey?: string;
  /** The agent's launch directory (a relative path under a path-like key). */
  launchDir?: string;
  home?: string;
  timeoutMs?: number;
  log?: (m: string) => void;
  /** An earlier call of the same turn that may write files (proxy.ts). */
  priorWriter?: string;
}

/** Rules under which the arbiter allowed a path WITHOUT judging the file
 *  (the tool keeps its own legs, or the guard confines it): the window rule
 *  does not apply to them. */
const EXEMPT_RULES: ReadonlySet<string> = new Set(["fs:upload-mapped-tool", "fs:upload-confined-server"]);

function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(message)), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e as Error); },
    );
  });
}

const APPROVALS_HINT =
  " The user can allow it on the Mandu dashboard's Approvals page (mandu dashboard): tell them, and do not retry before they answer.";

/** Why a file was held, in the model's words (the mapped upload gate,
 *  upload-gate.ts, and the unmapped leg below): the plain reason, the rule
 *  id, and whether the person's OK can let it go. Pure. */
export function uploadHeldWords(shown: string, d: FileUploadDecision | null, failure?: string): { plain: string; id: string; asks: boolean } {
  const id = d?.ruleRef?.id ?? "proxy:arbiter-unreachable";
  let plain: string;
  if (d === null) {
    plain = `Mandu could not check the file ${shown} (${failure ?? "the Mandu service did not answer"}; mandu status shows the service)`;
  } else if (id === "fs:upload-unreadable") {
    plain = `Mandu could not read the file ${shown} to check what it holds`;
  } else if (id === "fs:upload-invalid-path") {
    plain = `Mandu could not tell which file ${shown} names`;
  } else if (id === "fs:upload-unattested") {
    plain = "Mandu could not check the upload on its own channel";
  } else if (id === "proxy:upload-unreadable") {
    plain = `Mandu could not read the call well enough to check ${shown}`;
  } else if (id === "fs:upload-process-file") {
    plain = `${shown} is a file of a running process or of the system, which Mandu cannot check as the tool would read it`;
  } else if (d.ruleRef?.source === "verdict") {
    plain = `the user declined uploading ${shown}`;
  } else {
    plain = `${shown} is a secret file, or holds a secret, and Mandu keeps secrets from leaving this computer without a rule or the user's OK`;
  }
  const asks = d !== null && d.allow === false && d.requiresApproval;
  return { plain, id, asks };
}

/** What the model reads when a path was withheld. Names the path the model
 *  itself wrote and the rule; never what the file holds. */
export function unmappedUploadNotice(tool: string, w: WithheldPath, failure?: string): string {
  const { plain, id, asks } = uploadHeldWords(w.shown, failure === undefined ? { allow: false, requiresApproval: w.requiresApproval, reason: w.reason, ruleRef: w.ruleRef } : null, failure);
  return `mandu-upload-gate: ${tool} was not given the file ${w.shown} (the path now names no file), since Mandu cannot tell where this tool sends it: ${plain}.${asks ? APPROVALS_HINT : ""} (rule: ${id})`;
}

/** The window rule's notice (the module header, THE WINDOW). */
export function unmappedAfterWriteNotice(tool: string, shown: string, writer: string): string {
  return `mandu-upload-gate: ${tool} was not given the file ${shown} (the path now names no file): an earlier call of this turn (${writer}) runs first and may change it, and Mandu checks a file before the call runs, not when the tool reads it. Call ${tool} again on its own, in a later turn, once the other calls have finished. (rule: proxy:upload-after-write)`;
}

/**
 * The unmapped upload leg for one call (module header). The CALLER decides
 * the tool is unmapped (no table of the session's gate surface names it).
 * NEVER THROWS: an arbiter that errors or does not answer withholds every
 * candidate path.
 */
export async function gateUnmappedUploadToolUse(name: string, input: unknown, opts: UnmappedUploadOptions): Promise<UnmappedUploadResult> {
  if (!isObj(input)) return { input };
  const home = opts.home ?? homedir();
  const all = uploadPathCandidates(input, { home, ...(opts.launchDir !== undefined ? { launchDir: opts.launchDir } : {}) });
  if (all.length === 0) return { input };
  const failAll = (why: string, ruleId: string, candidates: readonly UploadPathCandidate[]): UnmappedUploadResult => {
    const ruleRef: RuleRef = { source: "fail-closed", id: ruleId };
    const withheld = candidates.map((c) => ({ loc: c.loc, shown: c.shown, path: c.path, reason: why, ruleRef, requiresApproval: false }));
    opts.log?.(`unmapped-upload: ${name} → ${withheld.length} path(s) WITHHELD (${why})`);
    return {
      input: replaceAtLocs(input, withheld.map((w) => ({ loc: w.loc, value: withheldPath(w.path) }))),
      outcome: { decision: "block", reason: why, notice: unmappedUploadNotice(name, withheld[0]!, why), withheld, allowed: [] },
    };
  };
  if (all.length > UNMAPPED_UPLOAD_MAX_PATHS) {
    // every path-like string of the call, past the bound too
    const every = uploadPathCandidates(input, { home, ...(opts.launchDir !== undefined ? { launchDir: opts.launchDir } : {}), max: Number.MAX_SAFE_INTEGER });
    return failAll(`more than ${UNMAPPED_UPLOAD_MAX_PATHS} file paths in one call`, "proxy:upload-unreadable", every);
  }
  const decide = opts.arbiter.fileUploadDecision?.bind(opts.arbiter);
  if (!decide) return failAll("this arbiter cannot judge an upload", "proxy:arbiter-unreachable", all);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_UNMAPPED_UPLOAD_TIMEOUT_MS;
  const verdicts = new Map<string, FileUploadDecision>();
  for (const c of all) {
    if (c.deep || verdicts.has(c.path)) continue;
    try {
      const d = await withTimeout(
        decide({ tool: name, path: c.path, destination: "", unmapped: true, ...(opts.sessionKey ? { sessionKey: opts.sessionKey } : {}) }),
        timeoutMs,
        `arbiter fileUploadDecision timed out after ${timeoutMs}ms`,
      );
      verdicts.set(c.path, d);
    } catch (err) {
      return failAll(`arbiter unreachable — fail closed: ${(err as Error).message}`, "proxy:arbiter-unreachable", all);
    }
  }
  const withheld: WithheldPath[] = [];
  const allowed: UnmappedUploadOutcome["allowed"] = [];
  for (const c of all) {
    if (c.deep) {
      withheld.push({
        loc: c.loc, shown: c.shown, path: c.path, reason: "a value nested too deep for Mandu to check — fail closed",
        ruleRef: { source: "fail-closed", id: "proxy:upload-unreadable" }, requiresApproval: false,
      });
      continue;
    }
    const d = verdicts.get(c.path)!;
    const exempt = d.allow && EXEMPT_RULES.has(d.ruleRef?.id ?? "");
    if (d.allow && (exempt || opts.priorWriter === undefined)) {
      allowed.push({ path: c.path, ...(d.ruleRef ? { ruleRef: d.ruleRef } : {}) });
      continue;
    }
    if (d.allow) {
      // judged by its bytes, after a possible writer of the same turn
      withheld.push({
        loc: c.loc, shown: c.shown, path: c.path,
        reason: `${opts.priorWriter} runs before ${name} in the same turn and may change ${c.shown}`,
        ruleRef: { source: "fail-closed", id: "proxy:upload-after-write" }, requiresApproval: false,
      });
      continue;
    }
    withheld.push({
      loc: c.loc, shown: c.shown, path: c.path, reason: d.reason,
      ruleRef: d.ruleRef ?? { source: "fail-closed", id: "proxy:upload-unreadable" },
      requiresApproval: d.requiresApproval,
      ...(d.approvalId ? { approvalId: d.approvalId } : {}),
    });
  }
  if (withheld.length === 0) return { input, outcome: { decision: "allow", reason: `${allowed.length} local path(s) checked`, withheld, allowed } };
  // A held file (the arbiter's) decides the notice before the window rule.
  const first = withheld.find((w) => w.ruleRef.id !== "proxy:upload-after-write") ?? withheld[0]!;
  for (const w of withheld) opts.log?.(`unmapped-upload: ${name} ${w.path} WITHHELD (${w.reason})`);
  return {
    input: replaceAtLocs(input, withheld.map((w) => ({ loc: w.loc, value: withheldPath(w.path) }))),
    outcome: {
      decision: "block", reason: first.reason,
      notice: first.ruleRef.id === "proxy:upload-after-write" ? unmappedAfterWriteNotice(name, first.shown, opts.priorWriter!) : unmappedUploadNotice(name, first),
      withheld, allowed,
    },
  };
}
