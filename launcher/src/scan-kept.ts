/**
 * scan-kept — the last `mandu scan`'s report, kept where Mandu keeps its own
 * state (`~/.mandu/state/last-scan.json`, the path table's `last-scan`), so
 * the dashboard's Home and Scan page and `mandu doctor` can show it
 * (confidentiality-plan-17-past-sessions-scan.md §3 item 12).
 *
 * What it holds is the scan op's answer, which carries no value, no length
 * and no hash of one (plan 17 §3 item 2): kinds, fixed masks, key names,
 * files, counts, the hosts commands sent to and the URLs there (masked:
 * the path kept, credentials and query values masked), dates, the scan's
 * range, the riskier sessions' counts and, per finding, its examples (a command with
 * every secret in it already replaced by its mask, a file read, a URL a
 * web fetch fetched, masked the same way, a project).
 * `keepScan` copies only the fields named below, each checked for its type
 * and cut to a length, so nothing the answer might carry beyond them (a
 * newer arbiter's field) is written. The file is written whole (a temporary
 * file renamed over it), mode 0600, in a 0700 folder the agent cannot open
 * (on-disk-layout.md §4).
 *
 * The scan itself still runs in a throwaway arbiter (plan 17 §3 item 7):
 * this file is written by the command, after the arbiter has answered.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { mkdirSync, readFileSync, renameSync, writeFileSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import { manduPath } from "./generated/mandu-paths.js";

type Env = Record<string, string | undefined>;

export const LAST_SCAN_VERSION = 1;
/** Findings kept (the "looks like a key" tier ran to 276 on one machine). */
export const KEPT_FINDINGS_MAX = 2000;
export const KEPT_SENDS_MAX = 500;
export const KEPT_EXAMPLES_MAX = 10;
export const KEPT_PROJECTS_MAX = 20;
/** A command as an example shows it (the scan already cuts it to 240). */
export const KEPT_COMMAND_MAX = 240;
/** URLs kept per send (the scan keeps 5, each cut to 160 characters). */
export const KEPT_SEND_URLS_MAX = 5;
export const KEPT_SEND_URL_MAX = 160;

/** One example of how a finding got there (plan 17 §3 item 12): already
 *  masked by the arbiter. */
export interface KeptExample {
  at?: string;
  agent: string;
  how: string;
  command?: string;
  file?: string;
  /** The URL a web fetch fetched, masked like a command. */
  url?: string;
  tool?: string;
  project?: string;
  mandu?: "under" | "by-time" | "without";
  provider?: string;
}

export interface KeptFinding {
  kind: string;
  preview: string;
  source?: { path: string; name?: string };
  sessions: number;
  agents: string[];
  first?: string;
  last?: string;
  how: Record<string, number>;
  projects: string[];
  projectCount?: number;
  duringMandu: number;
  /** Sessions known to have run under Mandu, and those only marked by time
   *  (plan 17 §3 item 6); the rest ran without it. Absent: not said. */
  sessionsUnderMandu?: number;
  sessionsByTime?: number;
  examples?: KeptExample[];
  /** Up to 10 examples per way it got there (the scan gives them for its
   *  first 500 findings). */
  examplesByHow?: Record<string, KeptExample[]>;
  /** The hosts commands sent it to (plan 17 §3 item 11). */
  sentToHosts?: string[];
  /** A key-shaped value that looks like a test value (item 14). */
  looksLikeTest?: true;
}

export interface KeptSend {
  kind: string;
  preview: string;
  source?: { path: string; name?: string };
  to: "own-service" | "other-host";
  host: string;
  /** The URLs at `host` it was sent to, masked by the arbiter (the path
   *  kept, credentials and query values masked). */
  urls?: string[];
  sessions: number;
  ran: number;
  stoppedByMandu: number;
  via: string[];
  /** How it left (item 11): `http` (absent in a scan kept before
   *  2026-10-22), `ssh`, `git`, `script`, or `mcp` (`host` is then the MCP
   *  tool's name). */
  channel?: "http" | "ssh" | "git" | "script" | "mcp";
  looksLikeTest?: true;
  by: Array<"value" | "variable">;
  agents: string[];
  last?: string;
  duringMandu: number;
  sessionsUnderMandu?: number;
  sessionsByTime?: number;
  examples?: KeptExample[];
}

/** What the running arbiter answered the scan's files (plan 17 §3 item 13). */
export interface KeptSuggestions {
  /** Suggestions on the files of "your secrets", pending now. */
  pending: number;
  filed: number;
  /** Files a rule already protects. */
  covered: number;
}

export interface LastScan {
  version: typeof LAST_SCAN_VERSION;
  /** When the scan ran (ISO). */
  ranAt: string;
  /** `--since`, when it narrowed the scan (ISO). */
  since?: string;
  sessions: Record<string, number>;
  from?: string;
  to?: string;
  duringMandu: number;
  /** Sessions known to have run under Mandu, and those only marked by time. */
  sessionsUnderMandu?: number;
  sessionsByTime?: number;
  /** Secrets Mandu found on this computer to look for. */
  known: number;
  findings: KeptFinding[];
  dropped: number;
  capped: { overTime: number; overBytes: number; tooBig: number; overFiles: number; readFailed: number };
  risk?: { skippedPrompts: number; skippedWithSecret: number; envDumps: number };
  sends?: KeptSend[];
  sendsDropped?: number;
  /** Sessions of agents whose store the scan counts but cannot read
   *  (Cursor's chats, plan 17 §4), by agent. */
  notRead?: Record<string, number>;
  /** null: no Mandu was running to file them (or an older one). */
  suggestions: KeptSuggestions | null;
}

// ── the field checks ────────────────────────────────────────────────────────

/** A string, its control characters dropped and its length cut; else undefined. */
function str(v: unknown, max = 512): string | undefined {
  if (typeof v !== "string") return undefined;
  // eslint-disable-next-line no-control-regex
  const s = v.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ");
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}
/** An ISO time, re-written; else undefined. */
function iso(v: unknown): string | undefined {
  if (typeof v !== "string" || v.length > 40) return undefined;
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString();
}
/** A count; else 0. */
function count(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), 1e9) : 0;
}
function optCount(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), 1e9) : undefined;
}
function strs(v: unknown, maxItems: number, maxLen = 256): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const x of v) {
    const s = str(x, maxLen);
    if (s !== undefined && out.length < maxItems) out.push(s);
  }
  return out;
}
function obj(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}
function source(v: unknown): { path: string; name?: string } | undefined {
  const o = obj(v);
  const path = o ? str(o["path"], 1024) : undefined;
  if (path === undefined) return undefined;
  const name = str(o!["name"], 256);
  return name === undefined ? { path } : { path, name };
}
/** Set `k` on `out` only when `v` is defined (exactOptionalPropertyTypes). */
function put<T extends object, K extends keyof T>(out: T, k: K, v: T[K] | undefined): void {
  if (v !== undefined) out[k] = v;
}

const MANDU_MARKS = new Set(["under", "by-time", "without"]);

function example(v: unknown): KeptExample | null {
  const o = obj(v);
  if (o === null) return null;
  const agent = str(o["agent"], 64);
  const how = str(o["how"], 64);
  if (agent === undefined || how === undefined) return null;
  const out: KeptExample = { agent, how };
  put(out, "at", iso(o["at"]));
  put(out, "command", str(o["command"], KEPT_COMMAND_MAX + 1));
  put(out, "file", str(o["file"], 1024));
  put(out, "url", str(o["url"], KEPT_COMMAND_MAX + 1));
  put(out, "tool", str(o["tool"], 128));
  put(out, "project", str(o["project"], 1024));
  const m = o["mandu"];
  if (typeof m === "string" && MANDU_MARKS.has(m)) out.mandu = m as KeptExample["mandu"];
  put(out, "provider", str(o["provider"], 64));
  return out;
}
function examples(v: unknown): KeptExample[] | undefined {
  if (!Array.isArray(v)) return undefined;
  return v.map(example).filter((e): e is KeptExample => e !== null).slice(0, KEPT_EXAMPLES_MAX);
}

function finding(v: unknown): KeptFinding | null {
  const o = obj(v);
  if (o === null) return null;
  const kind = str(o["kind"], 64);
  const preview = str(o["preview"], 1100);
  if (kind === undefined || preview === undefined) return null;
  const how: Record<string, number> = {};
  for (const [k, n] of Object.entries(obj(o["how"]) ?? {}).slice(0, 16)) {
    const key = str(k, 64);
    if (key !== undefined) how[key] = count(n);
  }
  const out: KeptFinding = {
    kind, preview, sessions: count(o["sessions"]), agents: strs(o["agents"], 8, 64), how,
    projects: strs(o["projects"], KEPT_PROJECTS_MAX, 1024), duringMandu: count(o["duringMandu"]),
  };
  put(out, "source", source(o["source"]));
  put(out, "first", iso(o["first"]));
  put(out, "last", iso(o["last"]));
  put(out, "projectCount", optCount(o["projectCount"]));
  put(out, "sessionsUnderMandu", optCount(o["sessionsUnderMandu"]));
  put(out, "sessionsByTime", optCount(o["sessionsByTime"]));
  put(out, "examples", examples(o["examples"]));
  const byHow = obj(o["examplesByHow"]);
  if (byHow !== null) {
    const groups: Record<string, KeptExample[]> = {};
    for (const [k, v] of Object.entries(byHow).slice(0, 8)) {
      const key = str(k, 64);
      const ex = examples(v);
      if (key !== undefined && ex !== undefined && ex.length > 0) groups[key] = ex;
    }
    out.examplesByHow = groups;
  }
  if (Array.isArray(o["sentToHosts"])) out.sentToHosts = strs(o["sentToHosts"], 20, 256);
  if (o["looksLikeTest"] === true && kind !== "known") out.looksLikeTest = true;
  return out;
}

function send(v: unknown): KeptSend | null {
  const o = obj(v);
  if (o === null) return null;
  const kind = str(o["kind"], 64);
  const preview = str(o["preview"], 1100);
  const host = str(o["host"], 256);
  const to = o["to"];
  if (kind === undefined || preview === undefined || host === undefined || (to !== "own-service" && to !== "other-host")) return null;
  const out: KeptSend = {
    kind, preview, to, host, sessions: count(o["sessions"]), ran: count(o["ran"]), stoppedByMandu: count(o["stoppedByMandu"]),
    via: strs(o["via"], 8, 64), by: strs(o["by"], 2, 16).filter((b): b is "value" | "variable" => b === "value" || b === "variable"),
    agents: strs(o["agents"], 8, 64), duringMandu: count(o["duringMandu"]),
  };
  put(out, "source", source(o["source"]));
  const ch = o["channel"];
  if (ch === "http" || ch === "ssh" || ch === "git" || ch === "script" || ch === "mcp") out.channel = ch;
  if (o["looksLikeTest"] === true && kind !== "known") out.looksLikeTest = true;
  if (Array.isArray(o["urls"])) {
    const urls = strs(o["urls"], KEPT_SEND_URLS_MAX, KEPT_SEND_URL_MAX + 1);
    if (urls.length > 0) out.urls = urls;
  }
  put(out, "last", iso(o["last"]));
  put(out, "sessionsUnderMandu", optCount(o["sessionsUnderMandu"]));
  put(out, "sessionsByTime", optCount(o["sessionsByTime"]));
  put(out, "examples", examples(o["examples"]));
  return out;
}

/** The record from a scan answer (or from the file again): only the fields
 *  named above, each checked. Null when it is not a scan answer with the
 *  axis on. Pure. */
export function keepScan(answer: unknown, meta: { ranAt: number | string; since?: number | string; suggestions?: KeptSuggestions | null }): LastScan | null {
  const r = obj(answer);
  if (r === null || r["axis"] === false || !Array.isArray(r["findings"])) return null;
  const ranAt = iso(typeof meta.ranAt === "number" ? new Date(meta.ranAt).toISOString() : meta.ranAt);
  if (ranAt === undefined) return null;
  const sessions: Record<string, number> = {};
  for (const [k, n] of Object.entries(obj(r["sessions"]) ?? {}).slice(0, 16)) {
    const key = str(k, 64);
    if (key !== undefined) sessions[key] = count(n);
  }
  const capped = obj(r["capped"]) ?? {};
  const out: LastScan = {
    version: LAST_SCAN_VERSION,
    ranAt,
    sessions,
    duringMandu: count(r["duringMandu"]),
    known: count(r["known"]),
    findings: (r["findings"] as unknown[]).map(finding).filter((f): f is KeptFinding => f !== null).slice(0, KEPT_FINDINGS_MAX)
      // The examples by way are kept for the first 500, as the scan gives them.
      .map((f, i) => { if (i >= 500) delete f.examplesByHow; return f; }),
    dropped: count(r["dropped"]) + Math.max(0, (r["findings"] as unknown[]).length - KEPT_FINDINGS_MAX),
    capped: { overTime: count(capped["overTime"]), overBytes: count(capped["overBytes"]), tooBig: count(capped["tooBig"]), overFiles: count(capped["overFiles"]), readFailed: count(capped["readFailed"]) },
    suggestions: null,
  };
  put(out, "since", meta.since === undefined ? undefined : iso(typeof meta.since === "number" ? new Date(meta.since).toISOString() : meta.since));
  put(out, "sessionsUnderMandu", optCount(r["sessionsUnderMandu"]));
  put(out, "sessionsByTime", optCount(r["sessionsByTime"]));
  put(out, "from", iso(r["from"]));
  put(out, "to", iso(r["to"]));
  const risk = obj(r["risk"]);
  if (risk !== null) out.risk = { skippedPrompts: count(risk["skippedPrompts"]), skippedWithSecret: count(risk["skippedWithSecret"]), envDumps: count(risk["envDumps"]) };
  if (Array.isArray(r["sends"])) {
    out.sends = (r["sends"] as unknown[]).map(send).filter((s): s is KeptSend => s !== null).slice(0, KEPT_SENDS_MAX);
    out.sendsDropped = count(r["sendsDropped"]) + Math.max(0, (r["sends"] as unknown[]).length - KEPT_SENDS_MAX);
  }
  const notRead: Record<string, number> = {};
  for (const [k, n] of Object.entries(obj(r["notRead"]) ?? {}).slice(0, 16)) {
    const key = str(k, 64);
    if (key !== undefined && count(n) > 0) notRead[key] = count(n);
  }
  if (Object.keys(notRead).length > 0) out.notRead = notRead;
  const sg = meta.suggestions ?? null;
  if (sg !== null) out.suggestions = { pending: count(sg.pending), filed: count(sg.filed), covered: count(sg.covered) };
  return out;
}

// ── the file ────────────────────────────────────────────────────────────────

/** Where the last scan is kept. */
export function lastScanPath(env: Env, home: string): string {
  return manduPath("last-scan", env, home);
}

/** Write the record whole: a temporary file, mode 0600, renamed over the
 *  last one, in its 0700 folder. Throws on a failed write. */
export function writeLastScan(path: string, rec: LastScan): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(rec)}\n`, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

/** The kept record, checked again; null when there is none or it does not
 *  read as one. Never throws. */
export function readLastScan(path: string): LastScan | null {
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    if (raw === null || typeof raw !== "object" || raw["version"] !== LAST_SCAN_VERSION) return null;
    return keepScan({ ...raw, axis: true }, {
      ranAt: String(raw["ranAt"] ?? ""),
      ...(typeof raw["since"] === "string" ? { since: raw["since"] } : {}),
      suggestions: (obj(raw["suggestions"]) as unknown as KeptSuggestions | null) ?? null,
    });
  } catch {
    return null;
  }
}

// ── what reads it ───────────────────────────────────────────────────────────

/** The sessions of a finding that ran without Mandu (plan 17 §3 item 6):
 *  every one, less those known to have run under it. A session only marked
 *  by time is counted as without: the mark is not a verdict. */
export function sessionsWithoutMandu(f: Pick<KeptFinding, "sessions" | "sessionsUnderMandu">): number {
  return Math.max(0, f.sessions - (f.sessionsUnderMandu ?? 0));
}

/** "Your secrets" (values found on this computer now) that reached the AI
 *  in a session without Mandu. */
export function secretsBeforeMandu(rec: LastScan): KeptFinding[] {
  return rec.findings.filter((f) => f.kind === "known" && sessionsWithoutMandu(f) > 0);
}

/** `19 Oct` from an ISO time. */
export function dayWords(iso: string | undefined): string {
  if (iso === undefined) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : `${d.getUTCDate()} ${["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getUTCMonth()]}`;
}

/** `mandu doctor`'s one line (without its mark). Pure. */
export function lastScanLine(rec: LastScan | null): string {
  if (rec === null) return "No scan of your agents' past sessions yet: mandu scan shows which of your secrets they already sent to the AI";
  const n = secretsBeforeMandu(rec).length;
  const what = n === 0 ? "none of your secrets reached the AI in sessions without Mandu" : `${n === 1 ? "1 of your secrets" : `${n} of your secrets`} reached the AI in sessions without Mandu`;
  const waiting = rec.suggestions && rec.suggestions.pending > 0 ? `; ${rec.suggestions.pending === 1 ? "1 rule waits" : `${rec.suggestions.pending} rules wait`} for you in the dashboard` : "";
  return `Last scan (${dayWords(rec.ranAt)}): ${what}${waiting} (mandu scan to check again)`;
}

/** What `keepLastScan` needs: the running Mandu's socket (null: none runs,
 *  or its secrets protection is off), its `suggestFromScan`, the write. */
export interface KeepDeps {
  resident: (env: Env) => Promise<string | null>;
  suggest: (sock: string, home: string, files: ReturnType<typeof suggestFilesOf>) => Promise<{ filed?: unknown; covered?: unknown; suggestions?: unknown }>;
  write: (path: string, rec: LastScan) => void;
}

/**
 * After a scan: name the files of "your secrets" to the running Mandu, if
 * one runs, so each that no rule covers becomes a suggestion (plan 17 §3
 * item 13), then keep the report with what it answered. Never throws: a
 * failure is a note for the person (`error`), and the report still prints.
 */
export async function keepLastScan(
  answer: unknown,
  ctx: { env: Env; home: string; ranAt: number; since?: number },
  deps: KeepDeps,
): Promise<{ rec: LastScan | null; error?: string }> {
  const meta = { ranAt: ctx.ranAt, ...(ctx.since !== undefined ? { since: ctx.since } : {}) };
  const rec = keepScan(answer, meta);
  if (rec === null) return { rec: null };
  const files = suggestFilesOf(rec, ctx.home);
  if (files.length > 0) {
    try {
      const sock = await deps.resident(ctx.env);
      if (sock !== null) {
        const a = await deps.suggest(sock, ctx.home, files);
        const pending = Array.isArray(a.suggestions) ? a.suggestions.filter((s) => obj(s)?.["status"] === "pending").length : 0;
        rec.suggestions = { pending, filed: Array.isArray(a.filed) ? a.filed.length : 0, covered: count(a.covered) };
      }
    } catch {
      // An older or busy Mandu: the report is kept without suggestions.
      rec.suggestions = null;
    }
  }
  try {
    deps.write(lastScanPath(ctx.env, ctx.home), rec);
  } catch (e) {
    return { rec, error: `could not keep the result for the dashboard: ${(e as Error).message}` };
  }
  return { rec };
}

/** The one line the report adds when the scan's files became suggestions. */
export function suggestionsLine(rec: LastScan | null): string | null {
  const s = rec?.suggestions;
  if (!s || s.pending === 0) return null;
  return `${s.pending === 1 ? "1 file that holds them has" : `${s.pending} files that hold them have`} no rule yet: Mandu suggests one for each in the dashboard (Rules, Files and folders, Suggested). Nothing changes until you save it.`;
}

/** The files "your secrets" came from, as `suggestFromScan` takes them:
 *  absolute paths and key names, never a value. "your environment" and any
 *  path not under HOME are left out. Pure. */
export function suggestFilesOf(rec: LastScan, home: string): Array<{ path: string; names: string[]; sessions: number; last: string | null }> {
  const byPath = new Map<string, { path: string; names: string[]; sessions: number; last: string | null }>();
  for (const f of rec.findings) {
    if (f.kind !== "known" || f.source?.name === undefined) continue;
    const p = f.source.path;
    const abs = p.startsWith("~/") ? `${home.replace(/\/+$/, "")}/${p.slice(2)}` : p;
    if (!abs.startsWith("/")) continue;
    const e = byPath.get(abs) ?? { path: abs, names: [], sessions: 0, last: null };
    if (!e.names.includes(f.source.name) && e.names.length < 32) e.names.push(f.source.name);
    e.sessions = Math.max(e.sessions, f.sessions);
    if (f.last !== undefined && (e.last === null || f.last > e.last)) e.last = f.last;
    byPath.set(abs, e);
  }
  return [...byPath.values()].slice(0, 64);
}
