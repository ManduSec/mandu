/**
 * last-scan — the last `mandu scan` on the product page
 * (confidentiality-plan-17-past-sessions-scan.md §3 item 12; dashboard.md
 * §4.25ai): the Home card beside "secrets masked before the AI saw them",
 * and the Scan page that tells the whole report.
 *
 * The point of the scan is the story of what already happened WITHOUT
 * Mandu: where a secret lived, what the agent did with it (the command, the
 * file it read, when, in which project, which agent), that what it printed
 * went to the AI in the agent's request to its model provider, so it left
 * this computer, and what happened next (the AI wrote it out again, a
 * command sent it on to a host). Each story ends with what Mandu would have
 * done instead. Whether a session ran with Mandu is a footnote.
 *
 * The record is the one the launcher keeps (launcher/src/scan-kept.ts, at
 * the path table's `last-scan`): the scan's answer, which carries no value,
 * no length and no hash (plan 17 §3 item 2). It is read again here with the
 * same field checks (`parseLastScan`), so a field the launcher does not
 * keep is not shown either. The examples' commands are the arbiter's, every
 * secret in them already replaced by its mask. Fields other parts of plan
 * 17's phase 2 add (`sessionsUnderMandu`, `sessionsByTime`, `examples`,
 * `projectCount`, a provider) are optional: without them the page says less.
 *
 * Pure: the server reads the file once per version of it
 * (server/scan-routes.ts `LastScanCache`), and the Scan page goes out in
 * pages (last-scan-pages.ts). Mandu-new (no reference origin).
 */
import { AGENTS, SCAN_ONLY_AGENTS, SCAN_ONLY_NAMES } from "../generated/agents.js";
import { replaceAtFor, type ReplaceAtVM } from "./key-pages.js";
import { startCommandParts, startCommands } from "./start-commands.js";

// ── the record (launcher/src/scan-kept.ts LastScan), declared here so the
//    dashboard typechecks standalone ──────────────────────────────────────────

export interface ScanExampleWire {
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

/** Where a known value sits now (launcher scan-kept.ts `KeptPlace`,
 *  lineage ★2): a chat-history file or an agent's database, home as `~`. */
export interface ScanPlaceWire {
  agent: string;
  file: string;
  mandu: "under" | "by-time" | "without";
  first?: string;
  last?: string;
  sessions: number;
  /** The Mandu sessions it ran under, by id. */
  manduSessions?: string[];
}

export interface ScanFindingWire {
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
  sessionsUnderMandu?: number;
  sessionsByTime?: number;
  examples?: ScanExampleWire[];
  /** Up to 10 examples per way it got there (part D). */
  examplesByHow?: Record<string, ScanExampleWire[]>;
  /** The hosts commands sent this secret to (plan 17 §3 item 11). */
  sentToHosts?: string[];
  /** A key-shaped value that looks like a test value (item 14). */
  looksLikeTest?: true;
  /** When some sessions ran under Mandu and some did not: the dates and
   *  ways of those that did not (transcript-scan.ts `outsideMandu`), the
   *  ones the summary counts. Absent: none ran under Mandu, or every one. */
  outsideMandu?: { first?: string; last?: string; how: Record<string, number> };
  /** A known value's places, and how many more the scan counted. */
  places?: ScanPlaceWire[];
  placesMore?: number;
}

export interface ScanSendWire {
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
  /** How it left (item 11); absent: HTTP. `mcp`: `host` is the tool. */
  channel?: "http" | "ssh" | "git" | "script" | "mcp";
  looksLikeTest?: true;
  by: Array<"value" | "variable">;
  agents: string[];
  last?: string;
  duringMandu: number;
  sessionsUnderMandu?: number;
  sessionsByTime?: number;
  examples?: ScanExampleWire[];
}

export interface LastScanWire {
  version: 1;
  ranAt: string;
  since?: string;
  sessions: Record<string, number>;
  from?: string;
  to?: string;
  duringMandu: number;
  sessionsUnderMandu?: number;
  sessionsByTime?: number;
  known: number;
  findings: ScanFindingWire[];
  dropped: number;
  capped: { overTime: number; overBytes: number; tooBig: number; overFiles: number; readFailed: number; compressed?: number };
  risk?: { skippedPrompts: number; skippedWithSecret: number; envDumps: number };
  sends?: ScanSendWire[];
  sendsDropped?: number;
  /** Sessions of agents whose store the scan counts but cannot read
   *  (Cursor's chats, plan 17 §4), by agent. */
  notRead?: Record<string, number>;
  suggestions: { pending: number; filed: number; covered: number } | null;
}

// ── reading it again ─────────────────────────────────────────────────────────

function str(v: unknown, max = 512): string | undefined {
  if (typeof v !== "string") return undefined;
  // eslint-disable-next-line no-control-regex
  const s = v.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ");
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}
function iso(v: unknown): string | undefined {
  if (typeof v !== "string" || v.length > 40) return undefined;
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString();
}
function count(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), 1e9) : 0;
}
function optCount(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), 1e9) : undefined;
}
function obj(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}
function strs(v: unknown, maxItems: number, maxLen = 256): string[] {
  return Array.isArray(v) ? v.map((x) => str(x, maxLen)).filter((s): s is string => s !== undefined).slice(0, maxItems) : [];
}
function put<T extends object, K extends keyof T>(out: T, k: K, v: T[K] | undefined): void {
  if (v !== undefined) out[k] = v;
}
function source(v: unknown): { path: string; name?: string } | undefined {
  const o = obj(v);
  const path = o ? str(o["path"], 1024) : undefined;
  if (path === undefined) return undefined;
  const name = str(o!["name"], 256);
  return name === undefined ? { path } : { path, name };
}
function examples(v: unknown): ScanExampleWire[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: ScanExampleWire[] = [];
  for (const x of v) {
    const o = obj(x);
    const agent = o ? str(o["agent"], 64) : undefined;
    const how = o ? str(o["how"], 64) : undefined;
    if (o === null || agent === undefined || how === undefined) continue;
    const e: ScanExampleWire = { agent, how };
    put(e, "at", iso(o["at"]));
    put(e, "command", str(o["command"], 241));
    put(e, "file", str(o["file"], 1024));
    put(e, "url", str(o["url"], 241));
    put(e, "tool", str(o["tool"], 128));
    put(e, "project", str(o["project"], 1024));
    if (o["mandu"] === "under" || o["mandu"] === "by-time" || o["mandu"] === "without") e.mandu = o["mandu"];
    put(e, "provider", str(o["provider"], 64));
    if (out.length < 10) out.push(e);
  }
  return out;
}
/** A Mandu session's id as the session page takes it (scan-kept.ts). */
const MANDU_SESSION_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
function places(v: unknown): ScanPlaceWire[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: ScanPlaceWire[] = [];
  for (const x of v.slice(0, 10)) {
    const o = obj(x);
    const agent = o ? str(o["agent"], 64) : undefined;
    const file = o ? str(o["file"], 1024) : undefined;
    const m = o?.["mandu"];
    if (o === null || agent === undefined || file === undefined || (m !== "under" && m !== "by-time" && m !== "without")) continue;
    const p: ScanPlaceWire = { agent, file, mandu: m, sessions: count(o["sessions"]) };
    put(p, "first", iso(o["first"]));
    put(p, "last", iso(o["last"]));
    if (Array.isArray(o["manduSessions"])) {
      const ids = (o["manduSessions"] as unknown[]).filter((s): s is string => typeof s === "string" && MANDU_SESSION_RE.test(s)).slice(0, 3);
      if (ids.length > 0) p.manduSessions = ids;
    }
    out.push(p);
  }
  return out.length > 0 ? out : undefined;
}
function how(v: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [k, n] of Object.entries(obj(v) ?? {}).slice(0, 16)) out[k.slice(0, 64)] = count(n);
  return out;
}

/** The kept record, every field checked; null when it does not read as one. */
export function parseLastScan(raw: unknown): LastScanWire | null {
  const r = obj(raw);
  if (r === null || r["version"] !== 1 || !Array.isArray(r["findings"])) return null;
  const ranAt = iso(r["ranAt"]);
  if (ranAt === undefined) return null;
  const sessions: Record<string, number> = {};
  for (const [k, n] of Object.entries(obj(r["sessions"]) ?? {}).slice(0, 16)) sessions[k.slice(0, 64)] = count(n);
  const capped = obj(r["capped"]) ?? {};
  const findings: ScanFindingWire[] = [];
  for (const x of (r["findings"] as unknown[]).slice(0, 2000)) {
    const o = obj(x);
    const kind = o ? str(o["kind"], 64) : undefined;
    const preview = o ? str(o["preview"], 1100) : undefined;
    if (o === null || kind === undefined || preview === undefined) continue;
    const f: ScanFindingWire = {
      kind, preview, sessions: count(o["sessions"]), agents: strs(o["agents"], 8, 64), how: how(o["how"]),
      projects: strs(o["projects"], 20, 1024), duringMandu: count(o["duringMandu"]),
    };
    put(f, "source", source(o["source"]));
    put(f, "first", iso(o["first"]));
    put(f, "last", iso(o["last"]));
    put(f, "projectCount", optCount(o["projectCount"]));
    put(f, "sessionsUnderMandu", optCount(o["sessionsUnderMandu"]));
    put(f, "sessionsByTime", optCount(o["sessionsByTime"]));
    put(f, "examples", examples(o["examples"]));
    const byHow = obj(o["examplesByHow"]);
    if (byHow) {
      const groups: Record<string, ScanExampleWire[]> = {};
      for (const [k, v] of Object.entries(byHow).slice(0, 8)) {
        const ex = examples(v);
        if (ex && ex.length > 0) groups[k.slice(0, 64)] = ex;
      }
      f.examplesByHow = groups;
    }
    if (Array.isArray(o["sentToHosts"])) f.sentToHosts = strs(o["sentToHosts"], 20, 256);
    if (o["looksLikeTest"] === true && kind !== "known") f.looksLikeTest = true;
    const outside = obj(o["outsideMandu"]);
    if (outside) {
      const om: NonNullable<ScanFindingWire["outsideMandu"]> = { how: how(outside["how"]) };
      put(om, "first", iso(outside["first"]));
      put(om, "last", iso(outside["last"]));
      f.outsideMandu = om;
    }
    if (kind === "known") {
      put(f, "places", places(o["places"]));
      const more = count(o["placesMore"]);
      if (more > 0) f.placesMore = more;
    }
    findings.push(f);
  }
  const out: LastScanWire = {
    version: 1, ranAt, sessions, duringMandu: count(r["duringMandu"]), known: count(r["known"]), findings,
    dropped: count(r["dropped"]),
    capped: { overTime: count(capped["overTime"]), overBytes: count(capped["overBytes"]), tooBig: count(capped["tooBig"]), overFiles: count(capped["overFiles"]), readFailed: count(capped["readFailed"]), ...(count(capped["compressed"]) > 0 ? { compressed: count(capped["compressed"]) } : {}) },
    suggestions: null,
  };
  put(out, "since", iso(r["since"]));
  put(out, "sessionsUnderMandu", optCount(r["sessionsUnderMandu"]));
  put(out, "sessionsByTime", optCount(r["sessionsByTime"]));
  put(out, "from", iso(r["from"]));
  put(out, "to", iso(r["to"]));
  const risk = obj(r["risk"]);
  if (risk) out.risk = { skippedPrompts: count(risk["skippedPrompts"]), skippedWithSecret: count(risk["skippedWithSecret"]), envDumps: count(risk["envDumps"]) };
  if (Array.isArray(r["sends"])) {
    const sends: ScanSendWire[] = [];
    for (const x of (r["sends"] as unknown[]).slice(0, 500)) {
      const o = obj(x);
      const kind = o ? str(o["kind"], 64) : undefined;
      const preview = o ? str(o["preview"], 1100) : undefined;
      const host = o ? str(o["host"], 256) : undefined;
      if (o === null || kind === undefined || preview === undefined || host === undefined || (o["to"] !== "own-service" && o["to"] !== "other-host")) continue;
      const s: ScanSendWire = {
        kind, preview, host, to: o["to"], sessions: count(o["sessions"]), ran: count(o["ran"]), stoppedByMandu: count(o["stoppedByMandu"]),
        via: strs(o["via"], 8, 64), by: strs(o["by"], 2, 16).filter((b): b is "value" | "variable" => b === "value" || b === "variable"),
        agents: strs(o["agents"], 8, 64), duringMandu: count(o["duringMandu"]),
      };
      put(s, "source", source(o["source"]));
      const ch = o["channel"];
      if (ch === "http" || ch === "ssh" || ch === "git" || ch === "script" || ch === "mcp") s.channel = ch;
      if (o["looksLikeTest"] === true && kind !== "known") s.looksLikeTest = true;
      if (Array.isArray(o["urls"])) {
        const urls = strs(o["urls"], 5, 161);
        if (urls.length > 0) s.urls = urls;
      }
      put(s, "last", iso(o["last"]));
      put(s, "sessionsUnderMandu", optCount(o["sessionsUnderMandu"]));
      put(s, "sessionsByTime", optCount(o["sessionsByTime"]));
      put(s, "examples", examples(o["examples"]));
      sends.push(s);
    }
    out.sends = sends;
    out.sendsDropped = count(r["sendsDropped"]);
  }
  const notRead = obj(r["notRead"]);
  if (notRead) {
    const n: Record<string, number> = {};
    for (const [k, v] of Object.entries(notRead).slice(0, 16)) { const key = str(k, 64); if (key !== undefined && count(v) > 0) n[key] = count(v); }
    if (Object.keys(n).length > 0) out.notRead = n;
  }
  const sg = obj(r["suggestions"]);
  if (sg) out.suggestions = { pending: count(sg["pending"]), filed: count(sg["filed"]), covered: count(sg["covered"]) };
  return out;
}

// ── words ────────────────────────────────────────────────────────────────────

/** The command that runs the scan, as the page writes it (code). */
export const SCAN_COMMAND = "mandu scan";
/** The first of the fallback commands (start-commands.ts START_FALLBACK);
 *  a sentence names the agents you use through `startCommands`. */
export const PROTECT_COMMAND = "mandu claude";

const AGENT_NAME: Readonly<Record<string, string>> = {
  "claude-code": "Claude Code", codex: "Codex", opencode: "OpenCode", goose: "Goose", openclaw: "OpenClaw", ...SCAN_ONLY_NAMES,
};

/** Is `a` an agent Mandu does not run (the scan reads it all the same,
 *  plan 17 §4 phase 3)? */
export function unrunAgent(a: string): boolean {
  return (SCAN_ONLY_AGENTS as readonly string[]).includes(a);
}

/** The agents Mandu does not run whose sessions the scan read, in order. */
function unrunRead(rec: LastScanWire): string[] {
  return SCAN_ONLY_AGENTS.filter((a) => (rec.sessions[a] ?? 0) > 0);
}

/** `Mandu does not run Gemini CLI yet; the agents it runs: mandu claude, …`
 *  as parts, or none. */
function unrunParts(rec: LastScanWire): ScanPart[] {
  const others = unrunRead(rec);
  if (others.length === 0) return [];
  const names = others.map(agentName);
  const list = names.length <= 2 ? names.join(" and ") : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
  const out: ScanPart[] = [t(` Mandu does not run ${list} yet; the agents it runs: `)];
  AGENTS.forEach((a, i) => { out.push(code(`mandu ${a}`)); out.push(t(i === AGENTS.length - 1 ? "." : ", ")); });
  return out;
}
/** The model provider an agent's requests go to, when an example does not
 *  name it (`provider`). */
const PROVIDER: Readonly<Record<string, string>> = { "claude-code": "Anthropic", codex: "OpenAI" };

export function agentName(a: string): string {
  return AGENT_NAME[a] ?? a;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/** `19 Oct` from an ISO time (UTC, as the terminal report says it). */
export function dayWords(iso: string | undefined): string {
  if (iso === undefined) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
}
function span(first: string | undefined, last: string | undefined): string {
  const a = dayWords(first);
  const b = dayWords(last);
  if (a === "" && b === "") return "";
  if (a === "" || b === "" || a === b) return a || b;
  return `${a} to ${b}`;
}
const plural = (n: number, one: string, many = `${one}s`): string => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;

/** The sessions read, in words: `812 Claude Code and 16 Codex sessions`. */
export function sessionWords(s: Record<string, number>): string {
  const order = Object.keys(AGENT_NAME);
  const rank = (a: string): number => { const i = order.indexOf(a); return i < 0 ? 99 : i; };
  const parts = Object.entries(s).filter(([, n]) => n > 0).sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b)).map(([a, n]) => `${n.toLocaleString("en-US")} ${agentName(a)}`);
  const total = Object.values(s).reduce((x, n) => x + n, 0);
  if (parts.length === 0) return "no agent sessions";
  const list = parts.length <= 2 ? parts.join(" and ") : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
  return `${list} ${total === 1 ? "session" : "sessions"}`;
}

/** A finding's sessions without Mandu: all, less those known to have run
 *  under it (a session marked only by time is counted without: the mark is
 *  not a verdict, plan 17 §3 item 6). */
export function sessionsWithoutMandu(f: Pick<ScanFindingWire, "sessions" | "sessionsUnderMandu">): number {
  return Math.max(0, f.sessions - (f.sessionsUnderMandu ?? 0));
}
/** A finding as its summary counts it (the terminal report's `leaked`,
 *  plan 17 §2): its sessions not under Mandu, with their dates and ways
 *  (`outsideMandu`; a record without it keeps the finding's own); those
 *  under Mandu, where the AI saw it masked, are the footnote's. With none
 *  under Mandu, or every one (a finding Mandu kept), the finding itself. */
export function reachedPart(f: ScanFindingWire): { sessions: number; first?: string; last?: string; how: Record<string, number> } {
  const without = sessionsWithoutMandu(f);
  if ((f.sessionsUnderMandu ?? 0) === 0 || without === 0) {
    return { sessions: f.sessions, how: f.how, ...(f.first !== undefined ? { first: f.first } : {}), ...(f.last !== undefined ? { last: f.last } : {}) };
  }
  const o = f.outsideMandu;
  const first = o ? o.first : f.first;
  const last = o ? o.last : f.last;
  return { sessions: without, how: o?.how ?? f.how, ...(first !== undefined ? { first } : {}), ...(last !== undefined ? { last } : {}) };
}
/** Your secrets (found on this computer now) that left in a session without Mandu. */
export function leftBeforeMandu(rec: LastScanWire): ScanFindingWire[] {
  return rec.findings.filter((f) => f.kind === "known" && sessionsWithoutMandu(f) > 0);
}

/** How a value got into a request, short (the summary line). */
const HOW_SHORT: Readonly<Record<string, string>> = {
  "read-file": "the agent read the file",
  "command-output": "a command printed it",
  "tool-result": "a tool returned it",
  "your-message": "it was in your message",
  "ai-wrote": "the AI wrote it out",
  context: "the agent attached it",
};
function howShort(h: Record<string, number>): string {
  return Object.entries(h).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]).slice(0, 2).map(([k]) => HOW_SHORT[k] ?? k).join(", ");
}

/** "Looks like a GitHub token", by the detector's kind. */
const SHAPE_WORDS: Readonly<Record<string, string>> = {
  "private-key": "a private key", "aws-access-key-id": "an AWS access key", "aws-secret-key": "an AWS secret key",
  "github-token": "a GitHub token", "gitlab-token": "a GitLab token", "anthropic-key": "an Anthropic API key",
  "openai-key": "an OpenAI-style API key", "slack-token": "a Slack token", "stripe-key": "a Stripe live key",
  "google-api-key": "a Google API key", "npm-token": "an npm token", "pypi-token": "a PyPI token",
  "huggingface-token": "a Hugging Face token", "url-password": "a password in a web address",
  "credential-assignment": "a value named like a secret",
};

/** The vendor shapes listed by default; values only NAMED like a secret and
 *  URL passwords are counted, listed when opened (scan-command.ts's rule). */
const NAMED_ONLY = (kind: string): boolean => kind === "credential-assignment" || kind === "url-password";

// ── the Home card ────────────────────────────────────────────────────────────

/** A part of a sentence: text, or a command drawn as code. */
/** `run`: a command Mandu asks you to run, drawn with a Copy beside it
 *  (dashboard.md §4.25b); only `mandu scan` in `againParts`. */
/** `start`: a part of the commands that start your agent, drawn on the Scan
 *  page from Home's `start` (start-commands.ts `startCommandParts`). */
export type ScanPart = { kind: "text"; text: string; start?: true } | { kind: "code"; text: string; run?: true; start?: true };
const t = (text: string): ScanPart => ({ kind: "text", text });
const code = (text: string): ScanPart => ({ kind: "code", text });
const runCode = (text: string): ScanPart => ({ kind: "code", text, run: true });
const joined = (parts: readonly ScanPart[]): string => parts.map((p) => p.text).join("");

export interface HomeScanTop {
  /** The key's name in its file (`STRIPE_KEY`), or its mask. */
  name: string;
  /** Where it lives (`~/shop/.env`). */
  file: string;
  /** The file Rules opens at (`/rules?file=`): `file` when it is `~/…` or
   *  absolute, else null (no link). */
  ruleFile: string | null;
  /** How it left, short: "a command printed it · Claude Code · 3 sessions, last 19 Oct". */
  how: string;
}

/** Home's card (dashboard.md §4.25ai). */
export interface HomeScanCard {
  /** False: no scan was ever kept; the card says how to run one. */
  ran: boolean;
  headline: string;
  /** The sentence under it, as parts (a command is code). */
  parts: ScanPart[];
  sentence: string;
  /** "Scanned 21 Oct · 828 past sessions", or null. */
  when: string | null;
  top: HomeScanTop[];
  /** Findings past `top`, counted. */
  more: number;
  /** Commands that sent one of your secrets to a host Mandu cannot tie to
   *  the key's own service: "worth a look". */
  worthALook: number;
  worthWords: string | null;
  /** Rules waiting for the files (plan 17 §3 item 13). */
  suggested: string | null;
  /** The way to run it again, as parts. */
  againParts: ScanPart[];
  /** Opens the Scan page. */
  link: string | null;
  /** The card's color, from the server (the page never matches the words):
   *  `bad` some of your secrets left, `ok` none did, null no scan yet. */
  tone: ScanTone | null;
  /** The green line: what Mandu does with these secrets (the terminal's
   *  "✓ With Mandu, …" line, in the product's words), or null when no agent
   *  the scan read is one Mandu runs. */
  safeLine: string | null;
  /** The figure: without Mandu and with it, from the top finding's facts. */
  figure: ScanFigureVM | null;
  /** Which kept scan this is: the opaque `rev` `/api/scan` sends (a hash
   *  of the file's identity, never the path; null, none kept). The server
   *  sets it (home-routes.ts); the Scan page reads again when it changed
   *  (§4.25ai *The Scan page follows a new scan*). Absent: an older server,
   *  or a test seam. */
  rev?: string | null;
  /** When the kept scan ran (the record's `ranAt`), null before one: the
   *  page keys a fold to it, so a new scan opens the card again. */
  ranAt: string | null;
  /** The one line a folded card reads (§4.25ai *A card with nothing to act
   *  on folds*), or null when the card never folds: some of your secrets
   *  left, the scan could not read everything, a send is worth a look or a
   *  rule waits. */
  folded: string | null;
}

/** A color with a meaning (dashboard.md §4.25ai *Color with meaning*): red,
 *  what reached the AI or went to a host Mandu cannot tie to the key; amber,
 *  worth a look; green, what Mandu kept or keeps; plain, neither. The page
 *  draws each with a word or a mark too, never the color alone. */
export type ScanTone = "bad" | "warn" | "ok" | "plain";

/** The figure at the top of the Scan page (and small on Home's card): the
 *  same secret twice, without Mandu (its real value reaches the AI model)
 *  and with it (the model gets only its mask). Every fact is one the scan
 *  already shows: the file, the key's name, the agent, the provider. */
export interface ScanFigureVM {
  /** "What happened, and what Mandu does instead". */
  title: string;
  /** True: a real finding's facts, told as what happened. */
  leaked: boolean;
  /** Where the secret lives (`~/shop/.env`), or null (told in general). */
  file: string | null;
  /** Its name in the file (`STRIPE_KEY`), or null. */
  name: string | null;
  /** The agent ("Claude Code"), or null (told in general: "your agent"). */
  agent: string | null;
  /** The model provider ("Anthropic"), or null when not known. */
  provider: string | null;
  without: { label: string; steps: string[] };
  with: { label: string; steps: string[] };
}

/** A finding's own small flow (the Scan page's rows): the file, the agent,
 *  the provider, and whether the AI got the real value or its mask. */
export interface ScanFlowVM {
  file: string | null;
  agent: string;
  provider: string | null;
  /** `real`: the real value reached the AI; `masked`: only its mask did. */
  reached: "real" | "masked";
}

/** The number of sends worth a look (to a host Mandu cannot tie to the key). */
function worthALook(rec: LastScanWire): number {
  return (rec.sends ?? []).filter((s) => s.to === "other-host" && (s.kind === "known" || !NAMED_ONLY(s.kind))).length;
}

/** Does the scan hold a session of an agent Mandu runs? Only then does the
 *  green line promise anything (scan-command.ts `runsSome`). */
function runsSome(rec: LastScanWire): boolean {
  const read = Object.entries(rec.sessions).filter(([, k]) => k > 0);
  return read.length === 0 || read.some(([a]) => !unrunAgent(a));
}

/** The green line, as the terminal says it ("✓ With Mandu, these 3 secrets
 *  stay safe: …"), "masked" for its placeholder (§4.25u). Of your secrets
 *  only: never "everything" (`secrets` mode does not mask other text). */
function safeLineOf(rec: LastScanWire, left: number): string | null {
  if (!runsSome(rec)) return null;
  if (left === 1) return "With Mandu, this secret stays safe: the AI sees only its mask, and your agent still does its work.";
  if (left > 1) return `With Mandu, these ${left.toLocaleString("en-US")} secrets stay safe: the AI sees only their masks, and your agent still does its work.`;
  return "With Mandu, your secrets stay safe: the AI sees only their masks, and your agent still does its work.";
}

/** How the agent got it, as the figure says it ("Claude Code ran a command
 *  that printed it"). */
const FIG_HOW: Readonly<Record<string, string>> = {
  "read-file": "read the file",
  "command-output": "ran a command that printed it",
  "tool-result": "used a tool that returned it",
  "your-message": "got it in your message",
  "ai-wrote": "had the AI write it out",
  context: "attached it to its request",
};

/** The figure (dashboard.md §4.25ai *The figure*): told with the newest of
 *  your secrets that reached the AI through an agent Mandu runs, else in
 *  general. Pure. */
export function scanFigure(rec: LastScanWire): ScanFigureVM {
  const left = leftBeforeMandu(rec);
  const f = left.find((x) => !unrunAgent(storyExample(x).agent) && storyExample(x).agent !== "");
  if (f === undefined) {
    return {
      title: left.length > 0 ? "What happened, and what Mandu does instead" : "What Mandu does with a secret your agent reads",
      leaked: false, file: null, name: null, agent: null, provider: null,
      without: {
        label: "Without Mandu",
        steps: ["A secret lives in a file on this computer.", "Your agent reads it, or a command prints it.", "Its next request takes the real value to the AI model, off this computer."],
      },
      with: {
        label: "With Mandu",
        steps: ["Mandu masks the secret on its way into your agent.", "The AI model sees only the mask, and your agent still does its work.", "The real value is put back only for a host the secret belongs to, or after you say yes."],
      },
    };
  }
  const e = storyExample(f);
  const agent = agentName(e.agent);
  const p = providerOf(e);
  const provider = p === "the model provider" ? null : p;
  const model = provider === null ? "the AI model" : `${provider}'s AI model`;
  const what = f.source?.name ?? "The secret";
  const file = f.source?.path ?? null;
  return {
    title: "What happened, and what Mandu does instead",
    leaked: true, file, name: f.source?.name ?? null, agent, provider,
    without: {
      label: "Without Mandu: what happened",
      steps: [
        file === null ? `${what} is one of your secrets.` : `${what} lives in ${file}.`,
        `${agent} ${FIG_HOW[e.how] ?? "got it"}.`,
        `Its next request took the real value to ${model}: it left this computer.`,
      ],
    },
    with: {
      label: "With Mandu",
      steps: [
        `Mandu masks it on its way into ${agent}.`,
        `${model.charAt(0).toUpperCase()}${model.slice(1)} sees only the mask, and ${agent} still does its work.`,
        "The real value is put back only for a host the secret belongs to, or after you say yes.",
      ],
    },
  };
}

/** Home's card from the kept record (null: none kept). `start`: the
 *  commands the sentence names (start-commands.ts), Home's own list; absent
 *  (the Scan page's build), those of this record alone, tagged `start` for
 *  the page to draw from Home's list. Pure. */
export function homeScanCard(rec: LastScanWire | null, start?: readonly string[]): HomeScanCard {
  if (rec === null) {
    const parts = [
      t("Your agents keep a record of every past session on this computer. "), code(SCAN_COMMAND),
      t(" reads it and shows which of your secrets already went to the AI, before Mandu. It runs on this computer and sends nothing."),
    ];
    return {
      ran: false, headline: "Did your agents already send a secret to the AI?", parts, sentence: joined(parts), when: null, top: [], more: 0,
      worthALook: 0, worthWords: null, suggested: null, againParts: [t("Run it in a terminal: "), runCode(SCAN_COMMAND)], link: null,
      tone: null, safeLine: null, figure: null, ranAt: null, folded: "Did your agents already send a secret to the AI?",
    };
  }
  const left = leftBeforeMandu(rec);
  const total = Object.values(rec.sessions).reduce((x, n) => x + n, 0);
  // The agents this person uses, not always Claude Code and Codex (§4.25ai).
  const stop = start !== undefined ? startCommandParts(start) : startCommandParts(startCommands(rec.sessions, []), true);
  const partly = (rec.capped.compressed ?? 0) > 0;
  const headline = left.length === 0
    ? `None of your secrets left this computer in your agents' requests${partly ? ", in what Mandu could read" : ""}`
    : `${left.length === 1 ? "1 of your secrets" : `${left.length.toLocaleString("en-US")} of your secrets`} left this computer in your agents' requests`;
  const parts: ScanPart[] = left.length === 0
    ? [t(`None of the ${plural(rec.known, "secret")} Mandu found on this computer was in what your agents sent to the AI in these sessions. To keep it so, start your agent with `), ...stop, t("."), ...unrunParts(rec)]
    : [t(`Each went to the AI in an agent's request to its model provider, in a session without Mandu. They are still where they were found: change them where they were issued. To stop it from now on, start your agent with `), ...stop, t("."), ...unrunParts(rec)];
  // Counted: the sessions without Mandu (a session under it is no leak).
  const top = left.slice(0, 3).map((f) => {
    const p = reachedPart(f);
    return {
      name: f.source?.name ?? f.preview,
      file: f.source?.path ?? "",
      ruleFile: ruleFileOf(f),
      how: [howShort(p.how), f.agents.map(agentName).join(" and "), `${plural(p.sessions, "session")}${p.last ? `, ${p.sessions === 1 ? "" : "last "}${dayWords(p.last)}` : ""}`].filter((x) => x !== "").join(" · "),
    };
  });
  const worth = worthALook(rec);
  const pending = rec.suggestions?.pending ?? 0;
  const tone: ScanTone = left.length > 0 ? "bad" : partly ? "warn" : "ok";
  return {
    ran: true,
    headline,
    parts,
    sentence: joined(parts),
    when: `Scanned ${dayWords(rec.ranAt)} · ${plural(total, "past session")}`,
    top,
    more: Math.max(0, left.length - top.length),
    worthALook: worth,
    worthWords: worth === 0 ? null : `${plural(worth, "send")} to a host Mandu cannot tie to the key's own service ${worth === 1 ? "is" : "are"} worth a look.`,
    suggested: pending === 0 ? null : `${pending === 1 ? "1 file that holds them has" : `${pending} files that hold them have`} no rule yet: Mandu suggests one for each, and nothing changes until you save it.`,
    againParts: [t("Run it again: "), runCode(SCAN_COMMAND)],
    link: "scan",
    tone,
    safeLine: safeLineOf(rec, left.length),
    figure: scanFigure(rec),
    ranAt: rec.ranAt,
    // Nothing left to act on: none left, all read, nothing worth a look,
    // no rule waiting. Every other card stays open.
    folded: tone === "ok" && worth === 0 && pending === 0 ? `Last scan, ${dayWords(rec.ranAt)}: none of your secrets left this computer.` : null,
  };
}

// ── the Scan page ────────────────────────────────────────────────────────────

/** One example, as the detail panel lists it. */
export interface ScanExampleVM {
  /** `19 Oct · ~/shop · Claude Code`. */
  head: string;
  /** "The agent ran:", "The agent read:", or the whole line when nothing follows. */
  did: string;
  /** The command or the file, drawn as code; null when there is none. */
  code: string | null;
  /** With or without Mandu, small, or null when not said. */
  mandu: string | null;
}

/** The examples of one way it got there (`examplesByHow`). */
export interface ScanExampleGroupVM {
  /** "A command printed it (3 sessions)". */
  title: string;
  examples: ScanExampleVM[];
}

/** One step of a finding's story. */
export interface ScanStoryStep {
  /** `lived` · `when` · `did` · `went` · `next` · `instead`. */
  step: "lived" | "when" | "did" | "went" | "next" | "instead";
  parts: ScanPart[];
  text: string;
  /** `went` and `next`: red when the real value left (amber when only the
   *  time marks Mandu, green under it); `instead`: green; else plain. */
  tone: ScanTone;
}

export interface ScanItemVM {
  id: string;
  /** "STRIPE_KEY in ~/shop/.env", or the mask (`ghp_…`). */
  title: string;
  /** "3 sessions, 1 Oct to 19 Oct, 2 projects · a command printed it · Claude Code". */
  summary: string;
  story: ScanStoryStep[];
  /** With or without Mandu, small. */
  footnote: string | null;
  /** The footnote in its parts, each with its tone (without Mandu red,
   *  with Mandu green, by the time only amber); null with no footnote. */
  footnoteParts: Array<{ text: string; tone: ScanTone }> | null;
  /** The row's color and the word that says it too ("Reached the AI"). */
  tone: ScanTone;
  badge: string;
  /** The small flow under the title (your secrets and those Mandu kept),
   *  or null. */
  flow: ScanFlowVM | null;
  /** The detail panel: where the real value is now (one of your secrets),
   *  the date range, the projects, the examples by way. */
  detail: { range: string | null; projects: string | null; groups: ScanExampleGroupVM[]; where: ScanWhereVM | null };
  /** The file its secret lives in, for *Change it in Rules*
   *  (`/rules?file=`): a known secret's or a send's `~/…` or absolute
   *  path; null for a key not in your files, a relative path, or none. */
  file: string | null;
  /** Where its company replaces such a key (key-pages.ts), under the
   *  story: a key-shaped value not in your files (section `looks`) or a
   *  send of one, unless it looks like a test value; empty otherwise
   *  (dashboard.md §4.25ai *A key links to where it is replaced*). */
  replaceAt: ReplaceAtVM[];
  /** Lower-case words the page's filter matches. */
  filter: string;
}

/** One place of *Where the real value is now* (dashboard.md §4.25ai, the
 *  lineage mock's ★2): where it belongs, the AI service that got it, and
 *  each chat-history file it sits in. Names, paths, days and counts only. */
export interface ScanWhereRowVM {
  /** `belongs` its file; `provider` the AI service; `history` a chat
   *  history without Mandu (or only marked by time); `under` one under it. */
  kind: "belongs" | "provider" | "history" | "under";
  /** "Where it belongs", "OpenAI", "OpenClaw's chat history". */
  where: string;
  /** The file, drawn as code; null for none. */
  file: string | null;
  /** How it got there, one line. */
  how: string;
  /** When it was first seen there ("27 Oct"), or null. */
  first: string | null;
  /** What it is now: a few words, and their tone. */
  now: string;
  tone: ScanTone;
  /** The Mandu sessions it ran under: each a link to its session page. */
  sessions: string[];
  /** A file the server checks is still there (`withPresence`): the
   *  chat-history rows' own, `~/…` or absolute. Absent: none to check. */
  check?: string;
}

export interface ScanWhereVM {
  rows: ScanWhereRowVM[];
  /** "And 4 more chat-history files the scan counted." or null. */
  more: string | null;
  /** What to do, under the rows. */
  advice: string;
}

export interface ScanSectionVM {
  id: "yours" | "looks" | "named" | "kept" | "sends-other" | "sends-own";
  heading: string;
  sentence: string;
  items: ScanItemVM[];
  /** Folded at first (a long tier of test values). */
  folded: boolean;
  /** Offers the filter box. */
  filter: boolean;
  /** Said when the section holds nothing. */
  empty: string | null;
  /** The heading's color: red for what reached the AI or went to another
   *  host, amber for worth a look, green for what Mandu kept; an empty
   *  section is plain (no achievement in an empty list). */
  tone: ScanTone;
  /** The empty line's color: green for "none of your secrets reached the
   *  AI", else absent (plain). */
  emptyTone?: ScanTone;
}

export interface ScanPageVM {
  ran: boolean;
  headline: string;
  parts: ScanPart[];
  sentence: string;
  /** What the scan read, its range and when it ran. */
  read: string | null;
  /** What a cap left unread, one line each. */
  notes: string[];
  sections: ScanSectionVM[];
  /** The riskier sessions, one line each. */
  risk: string[];
  /** The way to stop it, as parts. */
  stopParts: ScanPart[];
  /** Rules waiting for the files, or null. */
  suggested: string | null;
  againParts: ScanPart[];
  /** Before any scan, the line under its step (`againParts`, drawn first,
   *  dashboard.md §4.25ai *Before any scan, the step comes first*): what the
   *  page does once it runs. Null after a scan. */
  stepNote: string | null;
  /** The headline's color: `bad` some of your secrets reached the AI, `ok`
   *  none did; null with no scan. */
  tone: ScanTone | null;
  /** The green line (Home's card's), or null. */
  safeLine: string | null;
  /** The figure at the top, or null with no scan. */
  figure: ScanFigureVM | null;
}

/** The footnote on Mandu, in parts: without it (red), under it (green),
 *  marked by time (amber). */
function manduFootnoteParts(f: { sessions: number; duringMandu: number; sessionsUnderMandu?: number; sessionsByTime?: number }): Array<{ text: string; tone: ScanTone }> | null {
  const parts: Array<{ text: string; tone: ScanTone }> = [];
  const under = f.sessionsUnderMandu;
  const byTime = f.sessionsByTime ?? (under === undefined ? f.duringMandu : undefined);
  const known = under !== undefined || f.sessionsByTime !== undefined;
  const without = Math.max(0, f.sessions - (under ?? 0) - (byTime ?? 0));
  if (without > 0) parts.push({ text: `${plural(without, "session")} without Mandu`, tone: "bad" });
  if ((under ?? 0) > 0) parts.push({ text: `${plural(under!, "session")} with Mandu, where the AI saw it masked`, tone: "ok" });
  if ((byTime ?? 0) > 0) parts.push({ text: `${plural(byTime!, "session")} while Mandu ran${known ? "" : " the same agent"} (by the time only: the AI may have seen it masked there)`, tone: "warn" });
  if (parts.length === 0) return null;
  return parts.map((p, i) => ({ text: `${p.text}${i === parts.length - 1 ? "." : "; "}`, tone: p.tone }));
}
/** The footnote on Mandu as one line. */
function manduFootnote(f: { sessions: number; duringMandu: number; sessionsUnderMandu?: number; sessionsByTime?: number }): string | null {
  const parts = manduFootnoteParts(f);
  return parts === null ? null : parts.map((p) => p.text).join("");
}
function exampleMandu(m: ScanExampleWire["mandu"]): string | null {
  if (m === "under") return "with Mandu";
  if (m === "by-time") return "while Mandu ran (by the time only)";
  if (m === "without") return "without Mandu";
  return null;
}

/** An example's head: `19 Oct · ~/shop · Claude Code` (the terminal's). */
function exampleHead(e: ScanExampleWire): string {
  return [dayWords(e.at), e.project ?? "", agentName(e.agent)].filter((p) => p !== "").join(" · ");
}

/** What the agent did, in the terminal report's words (scan-command.ts
 *  `didLine`): a lead, and the command or file as code when there is one. */
function didOf(e: ScanExampleWire): { lead: string; code: string | null } {
  const tool = e.tool !== undefined && e.tool !== "Read" ? ` (${e.tool})` : "";
  switch (e.how) {
    case "command-output":
      return e.command !== undefined ? { lead: "The agent ran:", code: e.command } : { lead: `A command printed it${tool}.`, code: null };
    case "read-file":
      return e.file !== undefined ? { lead: `The agent read${tool}:`, code: e.file } : { lead: `The agent read a file${tool}.`, code: null };
    case "tool-result":
      return e.url !== undefined ? { lead: `The agent fetched${tool}:`, code: e.url } : { lead: `The agent used ${e.tool ?? "a tool"}, and it returned it.`, code: null };
    case "your-message":
      return { lead: "It was in your message to the agent (typed, pasted, or a ! command's output).", code: null };
    case "ai-wrote":
      return e.command !== undefined ? { lead: "The AI wrote it into a command:", code: e.command }
        : e.url !== undefined ? { lead: `The AI wrote it into a web fetch${tool}:`, code: e.url }
        : e.file !== undefined ? { lead: `The AI wrote it into${tool}:`, code: e.file } : { lead: "The AI wrote it out, in its reply or its reasoning.", code: null };
    case "context":
      return e.file !== undefined ? { lead: "The agent attached:", code: e.file } : { lead: "The agent added it to its request on its own.", code: null };
    default:
      return { lead: `${HOW_SHORT[e.how] ? HOW_SHORT[e.how]!.charAt(0).toUpperCase() + HOW_SHORT[e.how]!.slice(1) : "It got there"}.`, code: null };
  }
}

/** The provider an example's request went to: the record's, else the
 *  agent's own (Claude Code to Anthropic, Codex to OpenAI). */
function providerOf(e: { agent: string; provider?: string }): string {
  if (e.provider === "anthropic") return "Anthropic";
  if (e.provider === "openai") return "OpenAI";
  if (e.provider === "google") return "Google";
  if (e.provider === "github") return "GitHub";
  if (e.provider === "other") return "the model provider";
  return PROVIDER[e.agent] ?? "the model provider";
}

/** What it was, as the story calls it. */
const noun = (f: ScanFindingWire): string => (f.kind === "known" ? "the secret" : NAMED_ONLY(f.kind) ? "the value" : "the key");

/** That it left this computer, and to whom (scan-command.ts `wentLine`). */
function wentText(e: ScanExampleWire, f: ScanFindingWire): string {
  const a = agentName(e.agent);
  const p = providerOf(e);
  if (e.mandu === "under") return "This session ran under Mandu: the AI saw it masked; only the record on disk holds the value.";
  if (e.mandu === "by-time") return `This session ran while Mandu ran ${a}, so the request may have carried it masked; the record on disk holds the value.`;
  const to = `it left this computer in ${a}'s next request to ${p}`;
  const n = noun(f);
  switch (e.how) {
    case "command-output": return `The output, with ${n} in it, went to the AI: ${to}.`;
    case "read-file": return `The file's content, with ${n} in it, went to the AI: ${to}.`;
    case "tool-result": return `${e.url !== undefined ? "The page it fetched" : "The result"}, with ${n} in it, went to the AI: ${to}.`;
    case "your-message": return `Your message, with ${n} in it, left this computer in ${a}'s request to ${p}.`;
    case "ai-wrote": return `So the AI had it already, and ${a} sent it back to ${p} with each later request of the session.`;
    default: return `It went to the AI: ${to}.`;
  }
}

/** What Mandu would have done, by how it got there (scan-command.ts
 *  `withManduLine`, in the product's words: masked). */
function insteadText(how: string | undefined): string {
  switch (how) {
    case "read-file": return "With Mandu, the agent would have read the file with the secret masked, and the AI would have seen only the mask.";
    case "command-output": return "With Mandu, the AI would have seen the secret masked in that output; the command itself would still have run.";
    case "your-message": return "With Mandu, the AI would have received it masked: a secret Mandu holds (12 characters or longer) is masked in what you type.";
    case "ai-wrote": return "With Mandu, the AI would have known only the mask, so that is what it would have written; Mandu puts the real value back only on its way to a host the secret belongs to, or after you approve.";
    case "context": return "With Mandu, the AI would have seen it masked: a secret Mandu holds is masked in what the agent attaches too.";
    case "tool-result": return "With Mandu, the AI would have seen the secret masked in that result, or the result hidden whole.";
    default: return "With Mandu, the AI would have seen it masked instead.";
  }
}
const INSTEAD_KEY = "With Mandu, a key like this is masked when it is in a file or variable Mandu protects; one it does not hold reaches the AI as before.";
const INSTEAD_SEND = "With Mandu, the real value is filled in only for a host the secret may go to, or after you say yes.";

/** The ways it got there, most sessions first. */
function howsByCount(h: Record<string, number>): string[] {
  return Object.entries(h).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]).map(([k]) => k);
}

/** The example a story tells: the newest without Mandu, else the newest
 *  (scan-command.ts `storyExample`); else one made from the counts. */
function storyExample(f: ScanFindingWire): ScanExampleWire {
  const ex = f.examples ?? [];
  const pick = ex.find((e) => e.mandu === "without" || e.mandu === undefined) ?? ex[0];
  if (pick) return pick;
  const made: ScanExampleWire = { agent: f.agents[0] ?? "", how: howsByCount(f.how)[0] ?? "" };
  if (f.last !== undefined) made.at = f.last;
  if (f.projects[0] !== undefined) made.project = f.projects[0];
  if (made.how === "read-file" && f.source && f.source.path.startsWith("~")) made.file = f.source.path;
  // Seen only under Mandu: the story says so (before 2026-10-22 a kept
  // finding without examples was told as if it had left).
  if (keptByMandu(f)) made.mandu = "under";
  return made;
}

/** Where a finding was, for its sessions: `3 sessions, 1 Oct to 19 Oct, 2 projects`. */
function spread(f: { sessions: number; first?: string; last?: string; projects?: string[]; projectCount?: number }): string {
  const projects = f.projectCount ?? (f.projects ?? []).length;
  return [plural(f.sessions, "session"), span(f.first, f.last), projects > 1 ? plural(projects, "project") : ""].filter((p) => p !== "").join(", ");
}

function exampleVM(e: ScanExampleWire): ScanExampleVM {
  const d = didOf(e);
  return { head: exampleHead(e), did: d.lead, code: d.code, mandu: exampleMandu(e.mandu) };
}

/** The detail panel: the dates, the projects, and the examples by way
 *  (`examplesByHow`), else the story's examples. */
function detailOf(f: { first?: string; last?: string; projects?: string[]; projectCount?: number; how?: Record<string, number>; examples?: ScanExampleWire[]; examplesByHow?: Record<string, ScanExampleWire[]> }): ScanItemVM["detail"] {
  const projects = f.projects ?? [];
  const n = f.projectCount ?? projects.length;
  const shown = projects.slice(0, 5);
  const groups: ScanExampleGroupVM[] = [];
  const byHow = f.examplesByHow ?? {};
  const ways = Object.keys(byHow).sort((a, b) => (f.how?.[b] ?? 0) - (f.how?.[a] ?? 0));
  for (const how of ways) {
    const ex = (byHow[how] ?? []).slice(0, 10);
    if (ex.length === 0) continue;
    const cap = HOW_SHORT[how] ?? how;
    const k = f.how?.[how];
    groups.push({ title: `${cap.charAt(0).toUpperCase()}${cap.slice(1)}${k ? ` (${plural(k, "session")})` : ""}`, examples: ex.map(exampleVM) });
  }
  if (groups.length === 0 && (f.examples ?? []).length > 0) groups.push({ title: "The newest", examples: (f.examples ?? []).slice(0, 10).map(exampleVM) });
  return {
    range: span(f.first, f.last) || null,
    projects: n === 0 ? null : `${plural(n, "project")}${shown.length ? `: ${shown.join(", ")}${n > shown.length ? ", …" : ""}` : ""}`,
    groups,
    where: null,
  };
}

/** A path the server can check: `~/…` or absolute. */
const checkable = (p: string): boolean => p.startsWith("~/") || p.startsWith("/");

/**
 * *Where the real value is now* (dashboard.md §4.25ai, lineage ★2): one of
 * your secrets' places from the kept scan. Where it belongs (its file);
 * the AI service that got its real value in a session without Mandu
 * (which cannot be taken back); each chat-history file the scan found it
 * in, those without Mandu first, and those under Mandu with their
 * sessions linked. Null for a key that is not yours, or a scan kept
 * before places were. Mandu only shows them: it never changes an agent's
 * chat history (plan 17 §7 item 2). Pure.
 */
export function whereNow(f: ScanFindingWire): ScanWhereVM | null {
  if (f.kind !== "known" || f.places === undefined || f.places.length === 0) return null;
  const rows: ScanWhereRowVM[] = [];
  if (f.source) {
    const file = checkable(f.source.path) ? f.source.path : null;
    rows.push({ kind: "belongs", where: "Where it belongs", file, how: file === null ? `In ${f.source.path}${f.source.name ? ` as ${f.source.name}` : ""}` : f.source.name ? `As ${f.source.name}` : "The whole file", first: null, now: "You keep it here", tone: "plain", sessions: [] });
  }
  const without = sessionsWithoutMandu(f);
  let provider: string | null = null;
  if (without > 0) {
    const part = reachedPart(f);
    const ex = [...(f.examples ?? []), ...Object.values(f.examplesByHow ?? {}).flat()].find((e) => e.mandu !== "under") ?? storyExample(f);
    provider = providerOf(ex);
    rows.push({
      kind: "provider", where: provider === "the model provider" ? "The AI's provider" : provider, file: null,
      how: `Got its real value, in ${plural(without, "session")} without Mandu`,
      first: dayWords(part.first) || null, now: "Can't be taken back", tone: "bad", sessions: [],
    });
  }
  for (const p of f.places) {
    const under = p.mandu === "under";
    const n = p.sessions > 1 ? ` (${plural(p.sessions, "session")})` : "";
    rows.push({
      kind: under ? "under" : "history",
      where: `${agentName(p.agent)}'s chat history`,
      file: p.file,
      how: under ? `Saved on your computer; the AI got only its masked version, under Mandu${n}`
        : p.mandu === "by-time" ? `Saved as the AI got it, while Mandu ran but not provably under it${n}`
          : `Saved as the AI got it, without Mandu${n}`,
      first: dayWords(p.first) || null,
      now: "In it when the scan ran",
      tone: under ? "ok" : p.mandu === "by-time" ? "warn" : "bad",
      sessions: p.manduSessions ?? [],
      ...(checkable(p.file) ? { check: p.file } : {}),
    });
  }
  const more = f.placesMore ?? 0;
  const advice = without > 0
    ? `What reached ${provider === null || provider === "the model provider" ? "the AI's provider" : provider} can't be taken back: change the secret where it was issued. Mandu only shows these places; it never changes an agent's chat history.`
    : "Mandu only shows these places; it never changes an agent's chat history.";
  return { rows, more: more > 0 ? `And ${plural(more, "more chat-history file")} the scan counted.` : null, advice };
}

/**
 * The detail's places with what the server sees now (dashboard.md §4.25ai
 * *Where the real value is now*): a chat-history file still there says
 * so, one gone since the scan says that, in green. `exists` answers for a
 * `~/…` or absolute path; null: it could not tell (the row keeps "In it
 * when the scan ran"). Pure over `exists`.
 */
export function withPresence<D extends { where: ScanWhereVM | null }>(detail: D, exists: (path: string) => boolean | null): D {
  if (detail.where === null) return detail;
  const rows = detail.where.rows.map((r): ScanWhereRowVM => {
    if (r.check === undefined) return r;
    const here = exists(r.check);
    if (here === null) return r;
    if (!here) return { ...r, now: "Gone from this computer", tone: "ok" };
    return { ...r, now: r.kind === "under" ? "Still there, on your computer only" : "Still there" };
  });
  return { ...detail, where: { ...detail.where, rows } };
}

/** The Scan page's row id of one of your secrets that reached the AI (its
 *  section `yours`, numbered first), for a link that opens it; null for a
 *  finding not on that list. Pure. */
export function scanItemIdOf(rec: LastScanWire, f: ScanFindingWire): string | null {
  let i = 0;
  for (const x of rec.findings) {
    if (x.kind !== "known" || keptByMandu(x)) continue;
    if (x === f) return `f${i}`;
    i++;
  }
  return null;
}

function step(s: ScanStoryStep["step"], parts: ScanPart[], tone: ScanTone = "plain"): ScanStoryStep {
  return { step: s, parts, text: joined(parts), tone };
}

/** A row's color and word, by its section (dashboard.md §4.25ai). */
const ROW_TONE: Readonly<Record<ScanSectionVM["id"], { tone: ScanTone; badge: string }>> = {
  yours: { tone: "bad", badge: "Reached the AI" },
  looks: { tone: "warn", badge: "Not in your files now" },
  named: { tone: "warn", badge: "Not in your files now" },
  kept: { tone: "ok", badge: "Kept from the AI" },
  "sends-other": { tone: "bad", badge: "Sent to another host" },
  "sends-own": { tone: "plain", badge: "Sent to its own service" },
};
/** A key-shaped value that looks like a test value (plan 17 §3 item 14):
 *  in its section, told plainly with its own badge, never red. */
const TEST_ROW: { tone: ScanTone; badge: string } = { tone: "plain", badge: "Looks like a test value" };

/** The file Rules can open at for a finding or a send (dashboard.md
 *  §4.25ai): its source when it is a file Mandu found (`~/…` or absolute,
 *  as `/rules?file=` takes); null otherwise. */
function ruleFileOf(x: { kind: string; source?: { path: string } }): string | null {
  const path = x.kind === "known" ? x.source?.path : undefined;
  return path !== undefined && (path.startsWith("~/") || path.startsWith("/")) ? path : null;
}

function findingItem(f: ScanFindingWire, i: number, sends: readonly ScanSendWire[], section: ScanSectionVM["id"]): ScanItemVM {
  const lived = f.kind === "known" && f.source
    ? f.source.path.startsWith("~") || f.source.path.startsWith("/")
      ? step("lived", [t("It lives in "), code(f.source.path), t(f.source.name ? ` as ${f.source.name}.` : ".")])
      : step("lived", [t(`It lives in ${f.source.path}${f.source.name ? ` as ${f.source.name}` : ""}.`)])
    : step("lived", [t(`It looks like ${SHAPE_WORDS[f.kind] ?? "a key"} (${f.preview}), but it is not in your files now: an old key, someone else's, or a test value.`)]);
  const e = storyExample(f);
  const d = didOf(e);
  const story = [lived];
  const head = exampleHead(e);
  // The summary counts the sessions without Mandu (reachedPart); the
  // footnote says those under it apart. The story is the newest of them.
  const part = reachedPart(f);
  if (head !== "") story.push(step("when", [t(part.sessions > 1 ? `The newest: ${head}` : head)]));
  story.push(step("did", d.code === null ? [t(d.lead)] : [t(`${d.lead} `), code(d.code)]));
  const looksTest = f.looksLikeTest === true && f.kind !== "known";
  story.push(step("went", [t(wentText(e, f))], e.mandu === "under" ? "ok" : e.mandu === "by-time" ? "warn" : looksTest ? "plain" : "bad"));
  const wrote = f.how["ai-wrote"] ?? 0;
  // A key-shaped value that looks like a test value (plan 17 §3 item 14)
  // is told plainly, never in red: it is not counted as a leak.
  if (wrote > 0 && e.how !== "ai-wrote") story.push(step("next", [t(`The AI also wrote it out, in its text or a command (${plural(wrote, "session")}).`)], looksTest ? "plain" : "bad"));
  // The network hosts; an MCP tool is no host (its send is listed below).
  const hosts = f.sentToHosts ?? [...new Set(sends.filter((s) => s.channel !== "mcp" && ((f.source && s.source && s.source.path === f.source.path && s.source.name === f.source.name) || (!f.source && !s.source && s.preview === f.preview))).map((s) => s.host))];
  if (hosts.length > 0) story.push(step("next", [t(`A command also sent it on over the network, to ${hosts.slice(0, 5).join(", ")}${hosts.length > 5 ? ` and ${hosts.length - 5} more` : ""} (below).`)], looksTest ? "plain" : "bad"));
  // Green only where it is a promise about the secret: a key Mandu may not
  // hold, or an agent it does not run, is said plainly.
  const unrun = unrunAgent(e.agent);
  story.push(step("instead", [t(f.kind !== "known" ? INSTEAD_KEY : unrun ? `Mandu does not run ${agentName(e.agent)} yet, so there it could not have kept the secret from the AI.` : insteadText(e.how))], f.kind === "known" && !unrun ? "ok" : "plain"));
  const ways = howsByCount(part.how).slice(0, 2).map((h) => HOW_SHORT[h] ?? h).join(", ");
  const ex = [...(f.examples ?? []), ...Object.values(f.examplesByHow ?? {}).flat()];
  const p = providerOf(e);
  const flow: ScanFlowVM | null = (section === "yours" || section === "kept") && e.agent !== ""
    ? { file: f.source?.path ?? null, agent: agentName(e.agent), provider: p === "the model provider" ? null : p, reached: section === "kept" ? "masked" : "real" }
    : null;
  return {
    id: `f${i}`,
    title: f.preview,
    summary: [spread({ sessions: part.sessions, ...(part.first !== undefined ? { first: part.first } : {}), ...(part.last !== undefined ? { last: part.last } : {}), projects: f.projects, ...(f.projectCount !== undefined ? { projectCount: f.projectCount } : {}) }), ways, f.agents.map(agentName).join(" and ")].filter((x) => x !== "").join(" · "),
    story,
    footnote: manduFootnote(f),
    footnoteParts: manduFootnoteParts(f),
    ...(looksTest ? TEST_ROW : ROW_TONE[section]),
    flow,
    detail: { ...detailOf(f), where: section === "yours" || section === "kept" ? whereNow(f) : null },
    file: ruleFileOf(f),
    // Whose key it is is not known here, so the lead is conditional; a key
    // Mandu kept never reached the AI, and one of your files names no detector.
    replaceAt: section === "looks" && !looksTest ? replaceAtFor([f.kind], { unsure: true }) : [],
    filter: [f.preview, f.kind, SHAPE_WORDS[f.kind] ?? "", ...f.projects, ...f.agents.map(agentName), ...ex.map((x) => `${x.command ?? ""} ${x.file ?? ""} ${x.url ?? ""} ${x.project ?? ""}`)].join(" ").toLowerCase(),
  };
}

function sendItem(s: ScanSendWire, i: number): ScanItemVM {
  const lived = s.source
    ? step("lived", [t("It lives in "), code(s.source.path), t(s.source.name ? ` as ${s.source.name}.` : ".")])
    : step("lived", [t(`It looks like ${SHAPE_WORDS[s.kind] ?? "a key"} (${s.preview})${s.looksLikeTest === true ? ", and like a test value" : ""}.`)]);
  const e = s.examples?.[0];
  const story = [lived];
  if (e) story.push(step("when", [t(exampleHead(e))]));
  story.push(step("did", e?.command !== undefined ? [t("The agent ran: "), code(e.command)] : s.channel === "mcp" ? [t(`The agent gave it to an MCP server's tool, ${s.host}.`)] : [t(`The agent ran ${s.via.join(", ") || "a command"} to ${s.host}.`)]));
  const section = s.to === "other-host" ? "sends-other" : "sends-own";
  const by = s.by.includes("value")
    ? `The AI wrote the value into the command, so it was in ${agentName(e?.agent ?? s.agents[0] ?? "")}'s request to ${providerOf({ agent: e?.agent ?? s.agents[0] ?? "", ...(e?.provider !== undefined ? { provider: e.provider } : {}) })} too, and the command sent it to `
    : "The command used its variable, so the AI saw only the name; the command sent the value to ";
  // The URLs there, masked by the arbiter; else the host alone.
  const urls = s.urls ?? [];
  const dest = urls.length === 0 ? [t(s.host)] : urls.flatMap((u, k) => [...(k > 0 ? [t(k === urls.length - 1 ? " and " : ", ")] : []), code(u)]);
  const ran = s.ran === 0 ? (s.sessions === 1 ? " It failed or was refused." : " Every one failed or was refused.") : s.ran < s.sessions ? ` ${s.sessions - s.ran} failed or were refused.` : "";
  const stopped = s.stoppedByMandu > 0 ? ` ${s.stoppedByMandu} ${s.stoppedByMandu === 1 ? "was" : "were"} stopped by Mandu.` : "";
  // Red when the value went to a host Mandu cannot tie to the key, or the
  // AI had it too; plain when only its own service got it.
  story.push(step("went", [t(by), ...dest, t(`.${ran}${stopped}`)], s.to === "other-host" || s.by.includes("value") ? "bad" : "plain"));
  story.push(step("instead", [t(INSTEAD_SEND)], "ok"));
  return {
    id: `s${i}`,
    title: `${s.preview} → ${s.host}`,
    summary: [spread({ sessions: s.sessions, ...(s.last !== undefined ? { last: s.last } : {}) }), s.via.join(", "), s.agents.map(agentName).join(" and ")].filter((x) => x !== "").join(" · "),
    story,
    footnote: manduFootnote(s),
    // To its own service, "without Mandu" is no alarm: said plainly.
    footnoteParts: section === "sends-own" ? (manduFootnoteParts(s)?.map((p) => ({ ...p, tone: p.tone === "bad" ? "plain" as const : p.tone })) ?? null) : manduFootnoteParts(s),
    ...ROW_TONE[section],
    flow: null,
    file: ruleFileOf(s),
    replaceAt: s.kind !== "known" && s.looksLikeTest !== true ? replaceAtFor([s.kind], { unsure: true }) : [],
    detail: detailOf({ ...(s.last !== undefined ? { last: s.last } : {}), ...(s.examples !== undefined ? { examples: s.examples } : {}) }),
    filter: [s.preview, s.host, ...urls, ...s.via, ...s.agents.map(agentName)].join(" ").toLowerCase(),
  };
}

/** The lines for what a cap left unread. */
function cappedNotes(c: LastScanWire["capped"]): string[] {
  const out: string[] = [];
  if (c.overTime > 0) out.push(`${plural(c.overTime, "older session record")} not read: the scan's time ran out.`);
  if (c.overBytes > 0) out.push(`${plural(c.overBytes, "older session record")} not read: over the scan's size budget.`);
  if (c.tooBig > 0) out.push(`${plural(c.tooBig, "session record")} over 512 MiB not read.`);
  if (c.overFiles > 0) out.push(`${plural(c.overFiles, "session record")} past the file cap not read.`);
  if (c.readFailed > 0) out.push(`${plural(c.readFailed, "session record")} could not be read.`);
  if ((c.compressed ?? 0) > 0) out.push(`${plural(c.compressed!, "OpenClaw session")} not read in full: OpenClaw keeps its longer messages compressed, and Mandu reads those on Node 22.15 or later.`);
  return out;
}

/** A finding seen only in sessions known to be under Mandu: the AI saw it
 *  masked, so it is not one that reached the AI (scan-command.ts
 *  `keptByMandu`). */
export function keptByMandu(f: ScanFindingWire): boolean {
  return (f.sessionsUnderMandu ?? 0) > 0 && sessionsWithoutMandu(f) === 0;
}

/** The Scan page from the kept record (null: none kept). Pure. Built once
 *  per kept file, so its start commands are those of the record alone,
 *  tagged `start`: the page draws them from Home's `start` (§4.25ai). */
export function scanPageVM(rec: LastScanWire | null): ScanPageVM {
  const stopParts = [t("To keep your secrets from the AI from now on, start your agent with "), ...startCommandParts(startCommands(rec?.sessions, []), true), t("."), ...(rec !== null ? unrunParts(rec) : [])];
  if (rec === null) {
    const card = homeScanCard(null);
    return { ran: false, headline: card.headline, parts: card.parts, sentence: card.sentence, read: null, notes: [], sections: [], risk: [], stopParts, suggested: null, againParts: card.againParts, stepNote: "This page shows what it found when it finishes.", tone: null, safeLine: null, figure: null };
  }
  const card = homeScanCard(rec);
  const sends = rec.sends ?? [];
  const live = rec.findings.filter((f) => !keptByMandu(f));
  const known = live.filter((f) => f.kind === "known");
  const looks = live.filter((f) => f.kind !== "known" && !NAMED_ONLY(f.kind));
  const named = live.filter((f) => f.kind !== "known" && NAMED_ONLY(f.kind));
  const kept = rec.findings.filter(keptByMandu);
  let n = 0;
  const items = (fs: readonly ScanFindingWire[], section: ScanSectionVM["id"]): ScanItemVM[] => fs.map((f) => findingItem(f, n++, sends, section));
  const listed = sends.filter((s) => s.kind === "known" || !NAMED_ONLY(s.kind));
  let m = 0;
  const sendItems = (ss: readonly ScanSendWire[]): ScanItemVM[] => ss.map((s) => sendItem(s, m++));
  const yours = items(known, "yours");
  const sections: ScanSectionVM[] = [
    {
      id: "yours", heading: "Your secrets that reached the AI",
      sentence: "Values Mandu found on this computer now, exactly as they are in your files.",
      items: yours, folded: false, filter: false,
      empty: (rec.capped.compressed ?? 0) > 0
        ? `None of the ${plural(rec.known, "secret")} Mandu found on this computer reached the AI in what it could read of these sessions (see the notes).`
        : `None of the ${plural(rec.known, "secret")} Mandu found on this computer reached the AI in these sessions.`,
      tone: yours.length > 0 ? "bad" : "plain", emptyTone: (rec.capped.compressed ?? 0) > 0 ? "warn" : "ok",
    },
    {
      id: "looks", heading: `Values that look like keys (${looks.length.toLocaleString("en-US")})`,
      sentence: "They have a key's format but are in none of your files now: an old key, someone else's, or a test value. A project's test values show up here.",
      items: items(looks, "looks"), folded: looks.length > 10, filter: looks.length > 10, empty: null, tone: looks.length > 0 ? "warn" : "plain",
    },
    {
      id: "named", heading: `Values named like a secret (${named.length.toLocaleString("en-US")})`,
      sentence: "A value written after a name such as DB_PASSWORD=, or a password in a web address. Most are a project's own test values.",
      items: items(named, "named"), folded: true, filter: named.length > 10, empty: null, tone: named.length > 0 ? "warn" : "plain",
    },
  ];
  if (kept.length > 0) {
    sections.push({
      id: "kept", heading: `Kept from the AI by Mandu (${kept.length.toLocaleString("en-US")})`,
      sentence: "Seen only in sessions that ran under Mandu: the record on disk holds the value, but the AI saw it masked.",
      items: items(kept, "kept"), folded: true, filter: kept.length > 10, empty: null, tone: "ok",
    });
  }
  if (rec.sends !== undefined) {
    const other = sendItems(listed.filter((s) => s.to === "other-host"));
    sections.push({
      id: "sends-other", heading: "Sent to a host Mandu cannot tie to the key's own service (worth a look)",
      sentence: "Not a verdict: a key with no format sent to its own company's service lands here too.",
      items: other, folded: false, filter: false,
      empty: "No command sent one of these secrets over the network to such a host (curl, wget, HTTPie, xh, a web fetch).",
      tone: other.length > 0 ? "bad" : "plain",
    });
    sections.push({
      id: "sends-own", heading: "Sent to the key's own service",
      sentence: "Where a key is meant to go, by its format or by the file that holds it.",
      items: sendItems(listed.filter((s) => s.to === "own-service")), folded: false, filter: false, empty: null, tone: "plain",
    });
  }
  const risk: string[] = [];
  // The scan counts a session with prompts off where one of your secrets was
  // in the request, under Mandu or not: said only when one reached the AI,
  // so a page whose headline says none did never says one did.
  const anyLeft = leftBeforeMandu(rec).length > 0;
  if (rec.risk && rec.risk.skippedPrompts > 0) {
    risk.push(`${plural(rec.risk.skippedPrompts, "session")} ran with the agent's permission prompts off: every command ran without asking you${rec.risk.skippedWithSecret > 0 && anyLeft ? ` (in ${rec.risk.skippedWithSecret} of them one of your secrets reached the AI)` : ""}.`);
  }
  if (rec.risk && rec.risk.envDumps > 0) risk.push(`${plural(rec.risk.envDumps, "session")} printed your whole environment to the AI (env, printenv, …): every variable in it, secrets too, went into the request.`);
  const notes = cappedNotes(rec.capped);
  for (const [a, k] of Object.entries(rec.notRead ?? {})) notes.push(`${plural(k, `${agentName(a)} chat`)} not read: Mandu cannot read its chat store reliably yet.`);
  if (rec.dropped > 0) notes.push(`${plural(rec.dropped, "more value")} ${rec.dropped === 1 ? "was" : "were"} counted but not kept.`);
  const range = span(rec.from, rec.to);
  const since = rec.since ? `, only those since ${dayWords(rec.since)}` : "";
  return {
    ran: true,
    headline: card.headline,
    parts: card.parts,
    sentence: card.sentence,
    read: `Mandu read ${sessionWords(rec.sessions)} on this computer${range ? ` (${range})` : ""}${since}, on ${dayWords(rec.ranAt)}. Nothing left this computer for the scan, and no secret's value is shown here.`,
    notes,
    sections,
    risk,
    stopParts,
    suggested: card.suggested,
    againParts: card.againParts,
    stepNote: null,
    tone: card.tone,
    safeLine: card.safeLine,
    figure: card.figure,
  };
}
