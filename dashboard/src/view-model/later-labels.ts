/**
 * view-model/later-labels — a file the AI read as it was, labelled a secret
 * AFTER that read (dashboard.md §4.25b, *Labelled after the session*).
 * Mandu-new (no reference origin).
 *
 * WHY. A session's own record learns of a label only when one of its later
 * requests carries the earlier read masked (dual-lanes `maskedLater`). A
 * session that ended before the file was marked, or sent nothing after, never
 * does: its page told that read as a plain one ("Nothing here needed
 * guarding.") though the AI got what is now a secret (the first-session
 * tour, step 3). The rule-change log knows when each label was made, so the
 * page matches each Read's file against the labels in force now and their
 * times: a Read that reached the AI as it was, before its file's label, says
 * so, and *Your secrets* gets an entry for the file with no placeholder.
 *
 * HONEST CLAIMS ONLY. A label's time is the recorded change that wrote the
 * rule as it stands (policy.yaml rows, from the change log, `ruleOrigins`;
 * a Rules page label, from its own record), never a guess: a rule nobody
 * recorded, or one a later unrecorded edit changed, gives no time and so no
 * claim. Only a read whose result reached the AI with nothing masked, before
 * that time, counts. Which label decides a file is the arbiter's answer
 * (`pathLevels`), not a match made here. A level the AI may read
 * (`any-model`) or `public` is no secret from the AI and is left out.
 *
 * NEVER A VALUE. Paths, levels and times only. Pure.
 */

import type { SessionViewModel } from "../view-model.js";
import type { DualToolStep } from "./dual-lanes.js";
import type { PathLevelsEntryWire } from "./file-browser.js";
import { tokensIn } from "./held-tokens.js";
import { ruleOrigins, type PolicyChangeRow } from "./policy-proposals.js";
import { noteMasks } from "./secret-note.js";
import { pathArg, toolFamily } from "./tool-family.js";

/** A file's label in force now, and since when (ISO), from the change log. */
export interface LabelTime {
  /** The file as the session's reads name it, absolute. */
  path: string;
  /** Its level now (`no-model`, `local-model`, or one read fail-closed). */
  level: string;
  /** When the rule that decides it was made, as recorded (ISO). */
  at: string;
}

/** A Read whose result reached the AI as it was. */
export interface PlainRead {
  stepId: string;
  ts: string;
  /** The file, absolute (resolved against the session's folder and `~`). */
  path: string;
}

/** A file labelled after the session read it: the reads before its label. */
export interface LaterLabel extends LabelTime {
  /** Oldest first; at least one. */
  reads: PlainRead[];
}

/** The level a label time is kept for: one that keeps the value from an
 *  outside AI. `any-model` and `public` let the AI read it. An unknown level
 *  reads as a secret (fail-closed, as rule-words `levelWords` reads it). */
export function hidesFromAi(level: string): boolean {
  return level !== "public" && level !== "any-model" && level !== "";
}

function argsOf(input: string | null): Record<string, unknown> {
  if (!input) return {};
  try {
    const v = JSON.parse(input);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** `.`/`..` segments and doubled slashes removed from an absolute path. */
function normalize(p: string): string {
  const out: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") out.pop();
    else out.push(seg);
  }
  return "/" + out.join("/");
}

/** A Read's file as an absolute path: absolute as named, `~/…` under
 *  `home`, else under the session's folder `cwd`; null when it cannot be
 *  placed (a relative path and no folder recorded). */
export function readPath(p: string, cwd: string | null, home: string): string | null {
  const v = p.trim();
  if (!v || tokensIn(v).length) return null;
  if (v.startsWith("/")) return normalize(v);
  if ((v === "~" || v.startsWith("~/")) && home) return normalize(home + v.slice(1));
  if (cwd && cwd.startsWith("/")) return normalize(cwd + "/" + v);
  return null;
}

/** The step's result reached the AI with nothing masked, and no check
 *  stopped or held it: what the AI got is the file as it was. */
function reachedAsItWas(s: DualToolStep): boolean {
  if (s.violated || s.quarantine || s.readsTwin || s.maskedLater || s.readRefused) return false;
  if (s.usage === "deny" || s.usage === "needs_approval") return false;
  if (s.gates.some((g) => g.usage === "deny" || g.usage === "needs_approval")) return false;
  if (s.resultAgent === null || !s.resultAgent.trim() || tokensIn(s.resultAgent).length) return false;
  if (s.newSymbols.length || s.upSyms.length || noteMasks(s.secretNote)) return false;
  return true;
}

/** A read step's file, absolute: the recorded origin when it is an absolute
 *  path, else the path its arguments name, placed by `readPath`; null when
 *  it cannot be placed. *Your secrets* names a key's file by the same rule
 *  (secret-story.ts `mintedPaths`). */
export function readStepPath(s: Pick<DualToolStep, "origin" | "input">, cwd: string | null, home: string): string | null {
  const named = s.origin && s.origin.startsWith("/") ? s.origin : pathArg(argsOf(s.input));
  return named ? readPath(named, cwd, home) : null;
}

/** Every Read (any agent's, tool-family.ts) whose result reached the AI as it
 *  was, by its file (`readStepPath`). In the session's order. */
export function plainReads(vm: SessionViewModel, cwd: string | null, home: string): PlainRead[] {
  const out: PlainRead[] = [];
  for (const s of vm.dualLanes.steps) {
    if (s.step !== "tool" || toolFamily(s.tool) !== "read" || !reachedAsItWas(s)) continue;
    const path = readStepPath(s, cwd, home);
    if (path) out.push({ stepId: s.id, ts: s.ts, path });
  }
  return out;
}

/** The files labelled after the session read them as they were: each label
 *  time with the reads of its file strictly before it. A time or a read
 *  whose moment cannot be read makes no claim. In the order the files were
 *  first read. */
export function laterLabels(reads: readonly PlainRead[], times: readonly LabelTime[]): LaterLabel[] {
  const byPath = new Map<string, LabelTime>();
  for (const l of times) if (hidesFromAi(l.level) && Number.isFinite(Date.parse(l.at))) byPath.set(l.path, l);
  const out = new Map<string, LaterLabel>();
  for (const r of reads) {
    const l = byPath.get(r.path);
    const ms = Date.parse(r.ts);
    if (!l || !Number.isFinite(ms) || ms >= Date.parse(l.at)) continue;
    const had = out.get(r.path);
    if (had) had.reads.push(r);
    else out.set(r.path, { ...l, reads: [r] });
  }
  return [...out.values()];
}

/** The later labels of a session, by the step that read the file. */
export function laterByStep(later: readonly LaterLabel[]): Map<string, LaterLabel> {
  const out = new Map<string, LaterLabel>();
  for (const l of later) for (const r of l.reads) out.set(r.stepId, l);
  return out;
}

/** One Rules page label as the arbiter reports it (`confidentialityState`). */
export interface PageLabelTime {
  path: string;
  source: string;
  updatedAt: number;
}

/**
 * When the rule that decides `entry` (the arbiter's `pathLevels` answer) was
 * made, epoch ms, or null when no record says. A policy.yaml rule: the newest
 * recorded change that wrote its row (`lock:<path>`, `ruleOrigins`), unless
 * a later unrecorded edit changed it since. A Rules page label: its own
 * record's time. A built-in rule, a model key, or no rule: null.
 */
export function labelSince(entry: PathLevelsEntryWire, changes: readonly PolicyChangeRow[] | null, pageLabels: readonly PageLabelTime[] | null): number | null {
  if (!hidesFromAi(entry.level) || !entry.rule?.startsWith("label:")) return null;
  const via = entry.rule.slice("label:".length);
  if (entry.store === "policy") {
    if (!changes) return null;
    const o = ruleOrigins(changes)[`lock:${via}`];
    return o && o.recorded && !o.changedSince && o.at !== null ? o.at : null;
  }
  if (entry.store === "page") {
    const l = pageLabels?.find((x) => x.path === via && x.source !== "policy-file");
    return l && Number.isFinite(l.updatedAt) ? l.updatedAt : null;
  }
  return null;
}

/** The label times of the files `entries` answer for. */
export function labelTimes(entries: readonly PathLevelsEntryWire[], changes: readonly PolicyChangeRow[] | null, pageLabels: readonly PageLabelTime[] | null): LabelTime[] {
  const out: LabelTime[] = [];
  for (const e of entries) {
    const ms = labelSince(e, changes, pageLabels);
    if (ms !== null) out.push({ path: e.path, level: e.level, at: new Date(ms).toISOString() });
  }
  return out;
}
