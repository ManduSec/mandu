/**
 * view-model/secret-path — where one secret went, for its card on the
 * product's session page and its row in the developer view's *Where each
 * went* (dashboard.md §4.25b *Where it went*, symbol-lineage.md §5.6).
 * Mandu-new (no reference origin).
 *
 * Three pieces, each pure:
 *
 * WHERE IT IS KEPT. A registered secret's placeholder (`$MDU:nomodel_Read[…]`)
 * stands for a file the arbiter's registry names (`confidentialityState`'s
 * `secrets`: the base symbol and the absolute path, never a value). The
 * session's own record does not: a placeholder that reached the AI in a
 * command's output carries that COMMAND as its origin, which once named the
 * card "`ORDERHUB_PASSPHRASE` in `DEBUG=1 sh orders-app/bin/sync-orders.sh`"
 * and linked Rules to a file of that name (2026-10-28). `registeredFiles`
 * reads the registry's answer into a map by base symbol, and
 * `registeredFileOf` finds a token's file in it.
 *
 * WHERE IT WENT. `SecretPathNode`: the path a card draws, one node a fact,
 * each on its side of the wall: on this computer (where the real value is)
 * or at the AI (where only a placeholder is). secret-story.ts builds the
 * nodes from the same edges and events its lines read, so the path never
 * says more than the lines.
 *
 * WHEN IT LEAKED WITHOUT MANDU. The last `mandu scan` the launcher kept
 * (last-scan.ts) lists each of your secrets that reached an AI in a session
 * without Mandu, by its file and key name. `earlierLeak` matches a card's
 * file and name to one of those findings, and `earlierParts` words it:
 * "Without Mandu, OpenClaw gave the AI its real value on 27 Oct, 09:37:
 * `DEBUG=1 sh …` printed it." The scan's own words, its masked command and
 * its times; never a value (the scan keeps none).
 */

import type { StoryPart } from "./agent-page-types.js";
import { agentName, scanItemIdOf, sessionsWithoutMandu, type LastScanWire, type ScanExampleWire, type ScanFindingWire } from "./last-scan.js";

/** One fact on a secret's path. */
export interface SecretPathNode {
  /** Where the fact is: on this computer, where the real value is; at the
   *  AI, where only a placeholder is; or off this computer, where Mandu
   *  sent the real value (the hosts it filled it in for). */
  side: "computer" | "ai" | "off";
  /** The node's caption ("Kept in", "Brought in by", "The AI got", …). */
  label: string;
  parts: StoryPart[];
  /** "good": the node says Mandu kept the value back; "warn": something
   *  waits for the person; "plain": what happened. */
  tone: "good" | "warn" | "plain";
}

/** The registry's entries, as the arbiter's `confidentialityState` answers
 *  (secrets-routes.ts `RegisteredSecret`): only the two fields read here. */
export interface RegisteredSecretRef {
  path: string;
  symbol: string;
}

/** The registered secrets' files by base symbol (`$MDU:nomodel_Read[0404]`
 *  → `/home/me/app/.env`). Only absolute paths; a malformed row is left out. */
export function registeredFiles(secrets: readonly RegisteredSecretRef[] | null | undefined): Map<string, string> {
  const out = new Map<string, string>();
  for (const s of secrets ?? []) {
    if (typeof s?.symbol !== "string" || typeof s.path !== "string" || !s.path.startsWith("/")) continue;
    const base = baseSymbol(s.symbol);
    if (base && !out.has(base)) out.set(base, s.path);
  }
  return out;
}

const BASE_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;

/** A token's base symbol, its field path dropped (`….ORDERHUB_PASSPHRASE`). */
export function baseSymbol(token: string): string | null {
  return BASE_RE.exec(token)?.[0] ?? null;
}

/** The file a token stands for, by the registry (absolute), or null. */
export function registeredFileOf(token: string, files: ReadonlyMap<string, string> | undefined): string | null {
  if (!files?.size) return null;
  const base = baseSymbol(token);
  return base ? files.get(base) ?? null : null;
}

/** What the kept scan found of one secret in sessions without Mandu. */
export interface EarlierLeak {
  /** Sessions without Mandu where it reached the AI. */
  sessions: number;
  /** The first such moment the scan recorded (ISO), or null. */
  at: string | null;
  /** The agent, as the scan names it (`openclaw`). */
  agent: string | null;
  /** How it got into the request (`command-output`, `read-file`, …). */
  how: string | null;
  /** The command that printed it, masked as the scan masks it. */
  command: string | null;
  /** Its row on the Scan page (`f3`), which a link opens at *Where the
   *  real value is now*; null when it has none. */
  item: string | null;
}

/** A scan path, `~/…` or absolute, as an absolute path; null otherwise. */
function absPath(p: string, home: string): string | null {
  if (p.startsWith("/")) return p;
  if (p.startsWith("~/") && home) return `${home.replace(/\/+$/, "")}/${p.slice(2)}`;
  return null;
}

/** The examples of a finding from sessions without Mandu, earliest first. */
function withoutExamples(f: ScanFindingWire): ScanExampleWire[] {
  const all = [...(f.examples ?? []), ...Object.values(f.examplesByHow ?? {}).flat()];
  return all
    .filter((e) => e.mandu === "without")
    .sort((a, b) => (a.at ?? "￿").localeCompare(b.at ?? "￿"));
}

/**
 * The kept scan's finding for the secret at `file` (absolute) named `name`
 * (a key in it; null: the whole file), when it reached an AI in a session
 * without Mandu. A finding counts only when its file is the same file and,
 * for a key, its name is the same name: two `.env` files' `API_KEY` are two
 * secrets. Among several (a whole file's keys), the earliest. Null: no scan
 * kept, or none matches. Pure.
 */
export function earlierLeak(file: string | null, name: string | null, scan: LastScanWire | null | undefined, home: string): EarlierLeak | null {
  if (!file || !scan) return null;
  let best: EarlierLeak | null = null;
  for (const f of scan.findings) {
    if (f.kind !== "known" || !f.source) continue;
    if (absPath(f.source.path, home) !== file) continue;
    if (name !== null && f.source.name !== name) continue;
    const sessions = sessionsWithoutMandu(f);
    if (sessions <= 0) continue;
    const ex = withoutExamples(f)[0];
    const at = ex?.at ?? f.outsideMandu?.first ?? ((f.sessionsUnderMandu ?? 0) === 0 ? f.first : undefined) ?? null;
    const hows = Object.entries(f.outsideMandu?.how ?? f.how).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
    const found: EarlierLeak = {
      sessions, at,
      agent: ex?.agent ?? f.agents[0] ?? null,
      how: ex?.how ?? hows[0]?.[0] ?? null,
      command: ex?.how === "command-output" && ex.command ? ex.command : null,
      item: scanItemIdOf(scan, f),
    };
    if (!best || (found.at !== null && (best.at === null || found.at < best.at))) best = found;
  }
  return best;
}

/** How it reached the AI, after "gave the AI its real value". */
function howParts(e: EarlierLeak): StoryPart[] {
  if (e.command) return [{ kind: "text", text: ": " }, { kind: "code", text: e.command }, { kind: "text", text: " printed it" }];
  switch (e.how) {
    case "read-file": return [{ kind: "text", text: ": the agent read the file" }];
    case "command-output": return [{ kind: "text", text: ": a command printed it" }];
    case "tool-result": return [{ kind: "text", text: ": a tool returned it" }];
    case "your-message": return [{ kind: "text", text: ": it was in your message" }];
    case "context": return [{ kind: "text", text: ": the agent attached it" }];
    default: return [];
  }
}

/** The line a card says of an earlier leak: "Without Mandu, OpenClaw gave
 *  the AI its real value on 27 Oct, 09:37: `DEBUG=1 sh …` printed it.
 *  `mandu scan` found it in 1 session; the AI's provider still has it."
 *  The time is a whole moment (`clock`), drawn in the viewer's clock. */
export function earlierParts(e: EarlierLeak): StoryPart[] {
  const who = e.agent ? agentName(e.agent) : "an agent";
  const out: StoryPart[] = [{ kind: "text", text: `Without Mandu, ${who} gave the AI its real value` }];
  if (e.at) out.push({ kind: "text", text: " on " }, { kind: "time", text: e.at, clock: true });
  out.push(...howParts(e), { kind: "text", text: ". " }, { kind: "code", text: "mandu scan" });
  out.push({ kind: "text", text: ` found it in ${e.sessions === 1 ? "1 session" : `${e.sessions.toLocaleString("en-US")} sessions`} without Mandu; the AI's provider still has it, so change it where it was issued.` });
  return out;
}

// ── the developer view's notes (symbol-lineage.md §5.6) ─────────────────────

/** What the server knows beyond a session's record: the registry's files,
 *  the kept scan, and the folder `~` stands for. */
export interface LineageFacts {
  files: ReadonlyMap<string, string>;
  scan: LastScanWire | null;
  home: string;
}

/** One *Where each went* row's note: the file the item is kept in (`~/…`)
 *  and the line an earlier leak gives (`earlierParts`). */
export interface FlowNote {
  file?: string;
  earlier?: StoryPart[];
}

const TWIN_FIELD_RE = /^\$MDU:(?:nomodel|localmodel|anymodel)_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\]\.(.+)$/;

/** `~/…` for a path under `home`, else the path. */
function tilde(path: string, home: string): string {
  const h = home.replace(/\/+$/, "");
  return h && (path === h || path.startsWith(h + "/")) ? "~" + path.slice(h.length) : path;
}

/**
 * The notes of each flow root the registry places (`registeredFileOf`): its
 * file and, when the kept scan found the same file's same key reached an AI
 * without Mandu, the line that says so. Only placed roots get a note, so a
 * row never names a file the registry did not. Pure.
 */
export function lineageNotes(roots: readonly string[], facts: LineageFacts): Record<string, FlowNote> {
  const out: Record<string, FlowNote> = {};
  for (const root of roots) {
    const file = registeredFileOf(root, facts.files);
    if (!file) continue;
    const e = earlierLeak(file, TWIN_FIELD_RE.exec(root)?.[1] ?? null, facts.scan, facts.home);
    out[root] = { file: tilde(file, facts.home), ...(e ? { earlier: earlierParts(e) } : {}) };
  }
  return out;
}
