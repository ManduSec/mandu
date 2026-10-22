/**
 * scan-command — `mandu scan`: which of my secrets have my agents already
 * sent to the AI? (docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md)
 *
 * The scan itself runs in an arbiter (`scanAgentTranscripts`, the one
 * component that may hold secret bytes), always a throwaway one started for
 * this command (doctor-secrets.ts `throwawayArbiter`), so a scan of
 * gigabytes never holds up a running session's arbiter. The answer carries
 * no value; this module only words it. Nothing here opens a network
 * connection. `--open` (plan 17 §3 item 12) then opens the dashboard's
 * Scan page in the browser, starting the dashboard (a server on loopback)
 * through a function the dispatcher hands in, as `mandu dashboard` does.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { homedir } from "node:os";
import { helloResident, throwawayArbiter, type DryRunArbiter } from "./doctor-secrets.js";
import { ndjsonCall } from "./secret-setup.js";
import { manduPath } from "./generated/mandu-paths.js";
import { AGENTS, SCAN_ONLY_AGENTS, SCAN_ONLY_NAMES, type Agent, type ScanOnlyAgent } from "./generated/agents.js";
import type { Layout } from "./services/layout.js";
import { keepLastScan, suggestionsLine, writeLastScan, type KeepDeps } from "./scan-kept.js";
import { connectHost, liveDashboards, scanPageUrl } from "./live-dashboards.js";
import { signInWords, type SignInWith } from "./dashboard-sign-in.js";
import { openUrl, type OpenOutcome } from "./browser-open.js";
import { colorOn, colors, PLAIN, type Style } from "./term-style.js";

type Env = Record<string, string | undefined>;

/** The arbiter's answer (arbiter/ipc/protocol.ts
 *  `ScanAgentTranscriptsResultWire`), as far as this command reads it. */
export interface ScanWire {
  axis: boolean;
  sessions: Partial<Record<AgentId, number>>;
  duringMandu: number;
  /** Of the sessions, those Mandu served (exact) and those marked by time
   *  only (absent from an older arbiter, whose `duringMandu` is by time). */
  sessionsUnderMandu?: number;
  sessionsByTime?: number;
  from?: string;
  to?: string;
  findings: FindingWire[];
  dropped: number;
  known: number;
  bytes: number;
  capped: { overTime: number; overBytes: number; tooBig: number; overFiles: number; readFailed: number };
  ms: number;
  /** The riskier sessions (absent from an older arbiter). */
  risk?: { skippedPrompts: number; skippedWithSecret: number; envDumps: number };
  /** Secrets the agents' commands sent, by host (absent from an older arbiter). */
  sends?: SendWire[];
  sendsDropped?: number;
  /** Sessions of agents whose store the scan counts but cannot read
   *  (plan 17 §4: Cursor's), by agent (absent from an older arbiter). */
  notRead?: Partial<Record<AgentId, number>>;
}

/** One secret sent to one host (arbiter/policy/transcript-scan.ts `SendFinding`). */
export interface SendWire {
  kind: string;
  preview: string;
  source?: { path: string; name?: string };
  to: "own-service" | "other-host";
  host: string;
  /** The URLs at `host`, masked in the arbiter (absent from an older one). */
  urls?: string[];
  sessions: number;
  ran: number;
  stoppedByMandu: number;
  via: string[];
  /** How it left (absent from an older arbiter: HTTP). `mcp`: `host` is
   *  the MCP tool's name. */
  channel?: SendChannel;
  /** The value looks like a test value (a key-shaped one only). */
  looksLikeTest?: boolean;
  by: Array<"value" | "variable">;
  agents: AgentId[];
  last?: string;
  duringMandu: number;
}

/** How a send left (transcript-acts.ts `SendChannel`). */
export type SendChannel = "http" | "ssh" | "git" | "script" | "mcp";

/** The scan's agent ids: the registry's agents (src/generated/agents.ts),
 *  Claude Code as the scan's answer names it, and the agents only the scan
 *  knows (Mandu does not run them, plan 17 §4 phase 3). */
type AgentId = "claude-code" | Exclude<Agent, "claude"> | ScanOnlyAgent;
type How = "read-file" | "command-output" | "tool-result" | "your-message" | "ai-wrote" | "context";

/** With or without Mandu, for one session (transcript-scan.ts `ManduStatus`). */
type ManduStatus = "under" | "by-time" | "without";

/** One example of a finding (transcript-scan.ts `ScanExample`): what the
 *  agent did in one session, redacted in the arbiter. */
export interface ExampleWire {
  at?: string;
  agent: AgentId;
  how: How;
  command?: string;
  file?: string;
  /** The URL a web fetch fetched (absent from an older arbiter). */
  url?: string;
  tool?: string;
  project?: string;
  mandu?: ManduStatus;
  provider?: "anthropic" | "openai" | "google" | "github" | "other";
}

export interface FindingWire {
  kind: string;
  preview: string;
  source?: { path: string; name?: string };
  sessions: number;
  agents: AgentId[];
  first?: string;
  last?: string;
  how: Partial<Record<How, number>>;
  projects: string[];
  duringMandu: number;
  /** Distinct projects (absent from an older arbiter). */
  projectCount?: number;
  examples?: ExampleWire[];
  examplesByHow?: Partial<Record<How, ExampleWire[]>>;
  sentToHosts?: string[];
  /** A key-shaped value that looks like a test value (plan 17 §3 item 14;
   *  absent from an older arbiter): listed apart, not counted as a leak. */
  looksLikeTest?: boolean;
  /** Of `sessions`, those Mandu's own record ties to it, and those only the
   *  time does (the exact join; absent until the arbiter has it). */
  sessionsUnderMandu?: number;
  sessionsByTime?: number;
}

export interface ScanArgs {
  json: boolean;
  share: boolean;
  all: boolean;
  /** Skip transcripts last written before this (ms since the epoch). */
  since?: number;
  /** `--show <n>`: finding n of the report, in full. */
  show?: number;
  /** `--open`: then open the dashboard's Scan page in the browser. */
  open?: boolean;
}

/** `mandu scan [--json] [--share] [--all] [--show <n>] [--since <days>d|<date>] [--open]`;
 *  an error string for a bad line. Pure (`now` for `--since 30d`). */
export function parseScanArgs(rest: readonly string[], now: number): ScanArgs | { error: string } {
  const out: ScanArgs = { json: false, share: false, all: false };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === "--json") out.json = true;
    else if (a === "--share") out.share = true;
    else if (a === "--all") out.all = true;
    else if (a === "--open") out.open = true;
    else if (a === "--show" || a.startsWith("--show=")) {
      const v = a === "--show" ? rest[++i] : a.slice("--show=".length);
      if (v === undefined || !/^[1-9]\d{0,5}$/.test(v)) return { error: "--show wants the number of a finding in the report (mandu scan --show 3)" };
      out.show = Number(v);
    } else if (a === "--since" || a.startsWith("--since=")) {
      const v = a === "--since" ? rest[++i] : a.slice("--since=".length);
      if (v === undefined) return { error: "--since wants a number of days (30d) or a date (2026-09-01)" };
      const days = /^(\d{1,4})d$/.exec(v);
      const t = days ? now - Number(days[1]) * 86_400_000 : /^\d{4}-\d{2}-\d{2}$/.test(v) ? Date.parse(`${v}T00:00:00Z`) : NaN;
      if (!Number.isFinite(t)) return { error: `--since: '${v}' is not a number of days (30d) or a date (2026-09-01)` };
      out.since = t;
    } else return { error: `unknown option '${a}'` };
  }
  if (out.share && out.show !== undefined) return { error: "--share holds counts only: it does not go with --show" };
  // --json and --share are outputs for a program and for pasting: opening a
  // browser, and starting a server for it, is no part of either.
  if (out.open && out.json) return { error: "--open opens the dashboard for you to read: it does not go with --json, the answer for a program" };
  if (out.open && out.share) return { error: "--open opens the dashboard for you to read: it does not go with --share, the text to post" };
  return out;
}

/** The agents' names, in the order the report lists them. */
const AGENT_NAME: Readonly<Record<AgentId, string>> = { "claude-code": "Claude Code", codex: "Codex", opencode: "OpenCode", goose: "Goose", openclaw: "OpenClaw", ...SCAN_ONLY_NAMES };

/** Is `a` an agent Mandu does not run (the scan reads it all the same)? */
const unrun = (a: string): boolean => (SCAN_ONLY_AGENTS as readonly string[]).includes(a);

/** The commands of the agents Mandu runs: `mandu claude, mandu codex, …`. */
const RUN_COMMANDS = AGENTS.map((a) => `mandu ${a}`).join(", ");

/** An agent's place in the report's order (AGENT_NAME's, then any other). */
const agentRank = (a: string): number => { const i = Object.keys(AGENT_NAME).indexOf(a); return i < 0 ? Number.MAX_SAFE_INTEGER : i; };

/** `a`, `a and b`, `a, b and c`. */
const listWords = (parts: readonly string[]): string => (parts.length <= 2 ? parts.join(" and ") : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`);

/** Agents by name, in the report's order: `Claude Code, OpenCode and Goose`. */
function agentNames(ids: readonly string[]): string {
  return listWords([...ids].sort((a, b) => agentRank(a) - agentRank(b) || (a < b ? -1 : a > b ? 1 : 0)).map((a) => AGENT_NAME[a as AgentId] ?? a));
}

/** How a value got into a request, in the person's words. */
const HOW_WORDS: Readonly<Record<How, string>> = {
  "read-file": "the agent read the file",
  "command-output": "a command printed it",
  "tool-result": "a tool returned it",
  "your-message": "it was in your message",
  "ai-wrote": "the AI wrote it out",
  context: "the agent attached it",
};

/** How a value got there, as the compact report says it (most first, at
 *  most three on a line). */
const HOW_SHORT: Readonly<Record<How, string>> = {
  "your-message": "you pasted it",
  "command-output": "a command printed it",
  "read-file": "the agent read the file",
  "ai-wrote": "the AI wrote it",
  context: "the agent attached it",
  "tool-result": "a tool returned it",
};

/** How long a command the compact report shows may be before it is cut. */
const SHORT_COMMAND = 40;

/** How far past the cut a path shortened by its middle may run: its last
 *  part (the file name) tells more than the few characters it costs. */
const PATH_SLACK = 10;

/** A path or URL shortened by its middle to about `room` characters
 *  ({@link PATH_SLACK} more at most): its head (`~`, `/home`, `.`, a URL's
 *  `scheme://host`) and its last part kept, `…` between
 *  (`~/.config/…/credential.json`); else cut after its last `/` that fits
 *  `room`. Undefined when neither fits. Pure. */
function shortPath(word: string, room: number): string | undefined {
  const url = /^([a-z][a-z0-9+.-]*:\/\/[^/]*)(\/.*)$/i.exec(word);
  const head = url !== null ? url[1]! : word.startsWith("/") ? `/${word.slice(1).split("/")[0]}` : word.split("/")[0]!;
  const tail = url !== null ? url[2]! : word.slice(head.length);
  const parts = tail.split("/").filter((p, i, a) => p !== "" || i === a.length - 1);
  const last = parts[parts.length - 1] === "" ? `${parts[parts.length - 2] ?? ""}/` : parts[parts.length - 1] ?? "";
  if (parts.length >= 2 && last !== "/") {
    // As many leading parts as fit `room`; with none, the slack.
    const mids = parts.slice(0, -1);
    for (let k = mids.length - 1; k >= 0; k--) {
      const short = `${head}/${mids.slice(0, k).map((m) => `${m}/`).join("")}…/${last}`;
      if (short.length < word.length && (short.length <= room || (k === 0 && short.length <= room + PATH_SLACK))) return short;
    }
  }
  const slash = word.lastIndexOf("/", room - 1);
  return slash > head.length ? word.slice(0, slash + 1) : undefined;
}

/**
 * A command as the compact report shows it: its first line, cut near
 * {@link SHORT_COMMAND} characters at an argument's end, never inside one.
 * A path (or URL) the cut would fall in is shortened by its middle
 * (`cat ~/.config/…/credential.json`) or cut after one of its `/`; a long
 * word with no `/` is dropped whole unless it is all there is. ` …` marks
 * where anything after was left out. The arbiter redacted it already
 * (transcript-redact.ts `redactShown`: a value is a mask or a name there),
 * so a part of it holds no value either. Pure.
 */
export function shortCommand(cmd: string, max = SHORT_COMMAND): string {
  const lines = cmd.trim().split("\n");
  let s = lines[0]!.trimEnd();
  let after = lines.length > 1;
  if (s.length > max) {
    // The word the cut falls in, and what comes before it.
    const start = s.lastIndexOf(" ", max) + 1;
    const end = s.indexOf(" ", start) < 0 ? s.length : s.indexOf(" ", start);
    const before = s.slice(0, start).trimEnd();
    const word = s.slice(start, end);
    after ||= end < s.length;
    const room = max - (before === "" ? 0 : before.length + 1);
    const path = start <= max && word.includes("/") && !word.includes("‹") ? shortPath(word, Math.max(room, 12)) : undefined;
    if (path !== undefined) {
      s = before === "" ? path : `${before} ${path}`;
      if (!path.includes("/…/")) after = true;
    } else if (before.length > max / 2 || (before !== "" && start > max)) {
      s = before;
      after = true;
    } else {
      // One long word is all there is: cut it after a separator, or hard.
      const sep = Math.max(...["/", "=", ":", ",", ";", "&", "?"].map((c) => s.lastIndexOf(c, max - 1)));
      const mask = s.lastIndexOf("‹", max);
      let at = sep > max / 2 ? sep + 1 : max;
      if (mask >= 0 && mask < at && s.indexOf("›", mask) >= at) at = mask;
      s = s.slice(0, at).trimEnd();
      after = true;
    }
  }
  return !after || s.endsWith("…") ? s : `${s} …`;
}

/** The vendor shapes the report lists by default; a value only NAMED like a
 *  secret (`DB_PASSWORD=…`) or a URL's password is counted and listed with
 *  `--all`, as those are where a project's own test values show up. */
const LISTED_BY_DEFAULT = (kind: string): boolean => kind !== "credential-assignment" && kind !== "url-password";

/** A key-shaped value that looks like a test value (plan 17 §3 item 14):
 *  listed apart from the leaks and not counted with them. Only ever set by
 *  the arbiter on a key-shaped value, and read only for one here. */
const looksLikeTest = (f: FindingWire): boolean => f.kind !== "known" && LISTED_BY_DEFAULT(f.kind) && f.looksLikeTest === true;
/** A key-shaped value counted as leaked: not one that looks like a test value. */
const shapedLeak = (f: FindingWire): boolean => f.kind !== "known" && LISTED_BY_DEFAULT(f.kind) && !looksLikeTest(f);

const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;

/** What makes a value look like a test value, in the report's words. */
const TEST_SIGNS = "a test word, a straight or repeated run, a documented example";

/** `19 Oct` from an ISO time. */
function day(iso: string | undefined): string {
  if (iso === undefined) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : `${d.getUTCDate()} ${["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getUTCMonth()]}`;
}

/** The ways a finding got there, most sessions first. */
function howsByCount(f: FindingWire): How[] {
  return (Object.entries(f.how) as Array<[How, number]>).sort((a, b) => b[1] - a[1]).map(([h]) => h);
}

/** The two most common ways a finding got there. */
function hows(f: FindingWire): string {
  return howsByCount(f).slice(0, 2).map((h) => HOW_WORDS[h] ?? h).join(", ");
}

/** Agents by name, in the report's order (agentNames). */
const agentsWords = (agents: readonly AgentId[]): string => agentNames(agents);

/** A finding's sessions with or without Mandu: the exact join's count when
 *  the arbiter has it, else the time mark's. */
function manduSplit(f: FindingWire): { under: number; byTime: number; without: number } {
  const under = f.sessionsUnderMandu ?? 0;
  const byTime = f.sessionsByTime ?? Math.max(0, f.duringMandu - under);
  return { under, byTime, without: Math.max(0, f.sessions - under - byTime) };
}

/** One finding's summary line, for an older arbiter's answer (no example). */
function detail(f: FindingWire): string {
  const when = f.sessions === 1 ? day(f.last) : `last ${day(f.last)}`;
  return [`${plural(f.sessions, "session")}${when ? `, ${when}` : ""}`, hows(f), agentsWords(f.agents)].filter((p) => p !== "").join(" · ");
}

/** `1 Oct to 19 Oct`, or `19 Oct` for one day. */
function dayRange(first: string | undefined, last: string | undefined): string {
  const a = day(first);
  const b = day(last);
  return a !== "" && b !== "" && a !== b ? `${a} to ${b}` : b || a;
}

/** What it was, as the story calls it. */
const noun = (f: FindingWire): string => (f.kind === "known" ? "the secret" : LISTED_BY_DEFAULT(f.kind) ? "the key" : "the value");

/** Who the request went to. */
function providerName(e: ExampleWire): string {
  if (e.provider === "anthropic") return "Anthropic";
  if (e.provider === "openai") return "OpenAI";
  if (e.provider === "google") return "Google";
  if (e.provider === "github") return "GitHub";
  return "the model provider";
}

/** Step 2 of the story: what the agent did. */
function didLine(e: ExampleWire): string {
  const tool = e.tool !== undefined && e.tool !== "Read" ? ` (${e.tool})` : "";
  switch (e.how) {
    case "command-output":
      return e.command !== undefined ? `The agent ran:  ${e.command}` : `A command printed it${tool}.`;
    case "read-file":
      return e.file !== undefined ? `The agent read:  ${e.file}${tool}` : `The agent read a file${tool}.`;
    case "tool-result":
      return e.url !== undefined ? `The agent fetched:  ${e.url}${tool}` : `The agent used ${e.tool ?? "a tool"}, and it returned it.`;
    case "your-message":
      return "It was in your message to the agent (typed, pasted, or a ! command's output).";
    case "ai-wrote":
      return e.command !== undefined ? `The AI wrote it into a command:  ${e.command}`
        : e.url !== undefined ? `The AI wrote it into a web fetch:  ${e.url}${tool}`
        : e.file !== undefined ? `The AI wrote it into:  ${e.file}${tool}` : "The AI wrote it out, in its reply or its reasoning.";
    case "context":
      return e.file !== undefined ? `The agent attached:  ${e.file}` : "The agent added it to its request on its own.";
    default:
      return HOW_WORDS[e.how as How] ?? String(e.how);
  }
}

/** Step 3: that it left this computer, and to whom; under Mandu, what the
 *  record can and cannot say. */
function wentLine(e: ExampleWire, f: FindingWire): string {
  const a = AGENT_NAME[e.agent] ?? e.agent;
  if (e.mandu === "under") return `This session ran under Mandu: the AI saw a placeholder; only the record on disk holds the value.`;
  if (e.mandu === "by-time") return `This session ran while Mandu ran ${a}, so the request may have carried a placeholder instead; the record on disk holds the value.`;
  const to = `it left this computer in ${a}'s next request to ${providerName(e)}`;
  const n = noun(f);
  switch (e.how) {
    case "command-output": return `The output, with ${n} in it, went to the AI: ${to}.`;
    case "read-file": return `The file's content, with ${n} in it, went to the AI: ${to}.`;
    case "tool-result": return `${e.url !== undefined ? "The page it fetched" : "The result"}, with ${n} in it, went to the AI: ${to}.`;
    case "your-message": return `Your message, with ${n} in it, left this computer in ${a}'s request to ${providerName(e)}.`;
    case "ai-wrote": return `So the AI had it already, and ${a} sent it back to ${providerName(e)} with each later request of the session.`;
    default: return `It went to the AI: ${to}.`;
  }
}

/** Step 4: what the record shows came next. */
function nextLines(f: FindingWire, shownHow: How | undefined): string[] {
  const out: string[] = [];
  const wrote = f.how["ai-wrote"] ?? 0;
  if (wrote > 0 && shownHow !== "ai-wrote") out.push(`The AI also wrote it out, in its text or a command (${plural(wrote, "session")}).`);
  if ((f.sentToHosts ?? []).length > 0) out.push(`A command also sent it on over the network, to ${f.sentToHosts!.join(", ")} (listed below).`);
  return out;
}

/** What Mandu would have done, for one of your secrets, by how it got there
 *  (usage.md, "Placeholders where values were", "A secret in your own
 *  prompt"; backstop-value-only.md for a registered value in any output). */
function withManduLine(how: How | undefined): string {
  switch (how) {
    case "read-file": return "With Mandu, the agent would have read a placeholder ($MDU:…) where the secret is, and the AI would have seen only that.";
    case "command-output": return "With Mandu, the AI would have seen a placeholder ($MDU:…) where the secret is in that output; the command itself would still have run.";
    case "your-message": return "With Mandu, the AI would have received a placeholder ($MDU:…) instead: a secret Mandu holds (12 characters or longer) is replaced in what you type.";
    case "ai-wrote": return "With Mandu, the AI would have known only a placeholder ($MDU:…), so that is what it would have written; Mandu puts the real value back only on its way to a host the secret belongs to, or after you approve.";
    case "context": return "With Mandu, the AI would have seen a placeholder ($MDU:…) instead: a secret Mandu holds is replaced in what the agent attaches too.";
    case "tool-result": return "With Mandu, the AI would have seen a placeholder ($MDU:…) in that result, or the result hidden whole.";
    default: return "With Mandu, the AI would have seen a placeholder ($MDU:…) instead.";
  }
}

/** For a story in an agent Mandu does not run: what it cannot say. */
function unrunLine(agent: string): string {
  return `Mandu does not run ${AGENT_NAME[agent as AgentId] ?? agent} yet, so there it could not have kept the secret from the AI.`;
}

/** The example a story tells: the newest without Mandu, else the newest. */
function storyExample(f: FindingWire): ExampleWire | undefined {
  const ex = f.examples ?? [];
  return ex.find((e) => e.mandu === "without" || e.mandu === undefined) ?? ex[0];
}

/** An example's head: `19 Oct · ~/shop · Claude Code`. */
function exampleHead(e: ExampleWire, withMandu: boolean): string {
  const parts = [day(e.at), e.project ?? "", AGENT_NAME[e.agent] ?? e.agent];
  if (withMandu && e.mandu === "by-time") parts.push("while Mandu ran (by time only)");
  if (withMandu && e.mandu === "under") parts.push("under Mandu");
  return parts.filter((p) => p !== "").join(" · ");
}

/** Where the finding was, for its sessions: `3 sessions, 1 Oct to 19 Oct, 2 projects`. */
function spread(f: FindingWire): string {
  const projects = f.projectCount ?? f.projects.length;
  return [plural(f.sessions, "session"), dayRange(f.first, f.last), projects > 1 ? plural(projects, "project") : ""].filter((p) => p !== "").join(", ");
}

/** One finding's story (the default report): where it lived, what the agent
 *  did, that it left, what came next, and for your own secrets what Mandu
 *  would have done. `pad` is the indent of the lines under the number. */
function storyLines(f: FindingWire, pad: string, opts: { withMandu: boolean }): string[] {
  const e = storyExample(f);
  if (e === undefined) return [`${pad}${detail(f)}`];
  const out: string[] = [];
  if (f.sessions > 1) {
    const ways = howsByCount(f).map((h) => `${HOW_WORDS[h] ?? h} in ${f.how[h]}`).join(", ");
    out.push(`${pad}${spread(f)} (${ways}). The newest:`);
  }
  out.push(`${pad}${exampleHead(e, false)}`);
  out.push(`${pad}  ${didLine(e)}`);
  out.push(`${pad}  ${wentLine(e, f)}`);
  for (const l of nextLines(f, e.how)) out.push(`${pad}  ${l}`);
  if (opts.withMandu) out.push(`${pad}${unrun(e.agent) ? unrunLine(e.agent) : withManduLine(e.how)}`);
  return out;
}

/** A short row's example line: `19 Oct · ~/shop · the agent ran:  cat .env`. */
function exampleLine(e: ExampleWire): string {
  const did = didLine(e);
  return [day(e.at), e.project ?? "", did.charAt(0).toLowerCase() + did.slice(1)].filter((p) => p !== "").join(" · ");
}

/** A short row (a key-like value past the first few): its summary, and one
 *  example line (three with `--all`). */
function shortLines(f: FindingWire, pad: string, all: boolean): string[] {
  const ex = f.examples ?? [];
  if (ex.length === 0) return [`${pad}${detail(f)}`];
  const out = [`${pad}${spread(f)} · ${hows(f)} · ${agentsWords(f.agents)}`];
  for (const e of ex.slice(0, all ? ex.length : 1)) out.push(`${pad}  ${exampleLine(e)}`);
  return out;
}

/** Was a finding seen only in sessions under Mandu (the exact join): the
 *  AI saw a placeholder there, so it is not one that reached the AI. */
const keptByMandu = (f: FindingWire): boolean => { const s = manduSplit(f); return s.under > 0 && s.without === 0 && s.byTime === 0; };

/** The findings in the report's order, which gives each its number for
 *  `--show`: your secrets, the key-like values, the values only named like
 *  a secret, then those Mandu kept from the AI. The same with or without
 *  `--all`, so a number always names the same finding. */
export function numberedFindings(r: ScanWire): FindingWire[] {
  const live = r.findings.filter((f) => !keptByMandu(f));
  return [
    ...live.filter((f) => f.kind === "known"),
    ...live.filter(shapedLeak),
    ...live.filter(looksLikeTest),
    ...live.filter((f) => f.kind !== "known" && !LISTED_BY_DEFAULT(f.kind)),
    ...r.findings.filter(keptByMandu),
  ];
}

/** Key-like values told as a story in the default report; the rest get a
 *  short row. */
const STORIES = 3;

/** The sessions read, in words: `815 Claude Code and 16 Codex sessions`. */
function sessionWords(s: ScanWire["sessions"]): string {
  // A fixed order (AGENT_NAME's, then any other by id), never the order the
  // answer happened to list them in (the scan reads agents concurrently).
  const parts = (Object.entries(s) as Array<[AgentId, number]>)
    .filter(([, n]) => n > 0)
    .sort(([a], [b]) => agentRank(a) - agentRank(b) || (a < b ? -1 : a > b ? 1 : 0))
    .map(([a, n]) => `${n} ${AGENT_NAME[a] ?? a}`);
  const total = Object.values(s).reduce((x, n) => x + (n ?? 0), 0);
  if (parts.length === 0) return "no agent sessions";
  return `${listWords(parts)} ${total === 1 ? "session" : "sessions"}`;
}

/** The sessions of agents whose store the scan counts but does not read:
 *  `3 Cursor chats not read`. */
function notReadLines(n: ScanWire["notRead"]): string[] {
  return (Object.entries(n ?? {}) as Array<[AgentId, number]>).filter(([, k]) => k > 0)
    .map(([a, k]) => `${plural(k, `${AGENT_NAME[a] ?? a} chat`)} not read: Mandu cannot read its chat store reliably yet (it keeps no format Mandu can rely on)`);
}

/** The agents Mandu does not run whose sessions the scan read. */
function unrunRead(r: ScanWire): string[] {
  return (Object.entries(r.sessions) as Array<[AgentId, number]>).filter(([a, k]) => k > 0 && unrun(a)).map(([a]) => a);
}

/** What the caps left unread, one line each. */
function cappedLines(c: ScanWire["capped"]): string[] {
  const out: string[] = [];
  if (c.overTime > 0) out.push(`${plural(c.overTime, "older transcript")} not read: the scan's time ran out (MANDU_TRANSCRIPT_SCAN_TIMEOUT_S, or --since)`);
  if (c.overBytes > 0) out.push(`${plural(c.overBytes, "older transcript")} not read: over the scan's size budget (MANDU_TRANSCRIPT_SCAN_MAX_MB)`);
  if (c.tooBig > 0) out.push(`${plural(c.tooBig, "transcript")} over 512 MiB not read`);
  if (c.overFiles > 0) out.push(`${plural(c.overFiles, "transcript")} past the file cap not read`);
  if (c.readFailed > 0) out.push(`${plural(c.readFailed, "transcript")} could not be read`);
  return out;
}

/** The riskier sessions, one line each (plan 17 §3 item 10). */
function riskLines(r: ScanWire["risk"]): string[] {
  if (r === undefined) return [];
  const out: string[] = [];
  if (r.skippedPrompts > 0) {
    const with_ = r.skippedWithSecret > 0 ? ` (in ${r.skippedWithSecret} of them one of your secrets leaked to the AI)` : "";
    out.push(`${plural(r.skippedPrompts, "session")} ran with the agent's permission prompts off: every command ran without asking you${with_}.`);
  }
  if (r.envDumps > 0) out.push(`${plural(r.envDumps, "session")} printed your whole environment to the AI (env, printenv, …): every variable in it, secrets too, went into the request.`);
  return out;
}

/** One send's detail line. */
function sendDetail(f: SendWire): string {
  const when = f.sessions === 1 ? day(f.last) : `last ${day(f.last)}`;
  const by = f.by.includes("value") ? "the AI wrote the value into the command" : "the command used its variable, so the AI saw only the name";
  const parts = [`${plural(f.sessions, "session")}${when ? `, ${when}` : ""}`, f.via.join(", "), by, agentNames(f.agents)];
  if (f.ran === 0) parts.push(f.sessions === 1 ? "it failed or was refused" : "every one failed or was refused");
  else if (f.ran < f.sessions) parts.push(`${f.sessions - f.ran} failed or refused`);
  if (f.stoppedByMandu > 0) parts.push(`${f.stoppedByMandu} stopped by Mandu`);
  if (f.duringMandu > 0) parts.push(f.duringMandu === f.sessions ? "while Mandu ran" : `${f.duringMandu} while Mandu ran`);
  return parts.filter((p) => p !== "").join(" · ");
}

/** Where a send went, as a row names it: the host, or an MCP tool. */
const sendWhere = (f: SendWire): string => (f.channel === "mcp" ? `an MCP server's tool ${f.host}` : f.host);

/** One send: the secret and where it went, the URLs there (masked in the
 *  arbiter), and the detail line. */
function sendRow(f: SendWire, indent: string): string[] {
  const test = f.looksLikeTest === true && f.kind !== "known" ? " (looks like a test value)" : "";
  return [`${indent}${f.preview} → ${sendWhere(f)}${test}`, ...(f.urls ?? []).map((u) => `${indent}    ${u}`), `${indent}    ${sendDetail(f)}`];
}

/** The channels in the order the report names them, each with the words
 *  before its hosts (`sent over ssh to prod`). */
const CHANNEL_TO: ReadonlyArray<[SendChannel, string]> = [
  ["http", "over HTTP to"], ["ssh", "over ssh to"], ["git", "with git to"], ["script", "by a script to"], ["mcp", "to an MCP server's tool"],
];
const channelOf = (f: SendWire): SendChannel => f.channel ?? "http";
/** What the sends cover, said once above them. */
const SENDS_COVER = "curl, wget, HTTPie, xh, a web fetch; ssh, scp, sftp, rsync; git with a credential in its URL; a python, node, ruby or perl one-liner's HTTP call; an MCP tool's input";

/** The sends of one finding's secret (by its file and key, else its mask). */
function sendsOf(r: ScanWire, f: FindingWire): SendWire[] {
  return (r.sends ?? []).filter((s) => (f.source && s.source ? s.source.path === f.source.path && s.source.name === f.source.name : !f.source && !s.source && s.preview === f.preview));
}

/** Where the agents' commands sent a secret (plan 17 §3 item 11), every
 *  send (the long report's; the compact one says it under each secret): the
 *  hosts the scan cannot tie to the key first, then the keys' own services. */
function sendLines(r: ScanWire): string[] {
  if (r.sends === undefined) return [];
  const sends = r.sends;
  if (sends.length === 0) return [`No command or tool sent one of these secrets on in these sessions (${SENDS_COVER}).`];
  const out = [`Secrets the agents sent on (${SENDS_COVER}):`];
  const group = (title: string, rows: SendWire[]): void => {
    if (rows.length === 0) return;
    out.push("", `  ${title}`);
    for (const f of rows) out.push(...sendRow(f, "    "));
  };
  group("To a host Mandu cannot tie to the key's own service (worth a look):", sends.filter((f) => f.to === "other-host" && channelOf(f) !== "mcp"));
  group("To an MCP server's tool (worth a look: the server may run here or elsewhere, and Mandu cannot see where it sent it):", sends.filter((f) => channelOf(f) === "mcp"));
  group("To the key's own service:", sends.filter((f) => f.to === "own-service" && channelOf(f) !== "mcp"));
  if ((r.sendsDropped ?? 0) > 0) out.push(`  (${r.sendsDropped} more sends were counted but not kept)`);
  return out;
}

/** How the report is drawn: `all` the long form, `style` its colours (none
 *  by default), and for the compact form the dashboard's place (the text
 *  after "Dashboard:", {@link dashboardWhere}) and the running Mandu's
 *  suggestions line, when there are. */
export interface RenderOpts {
  all: boolean;
  style?: Style;
  dashboard?: string;
  suggestions?: string | null;
}

/**
 * The terminal report (plan 17 §2). By default the compact form: your
 * secrets that leaked, one short entry each; the key-shaped values in one
 * line by prefix; the riskier sessions; what to run. `--all` is the long
 * form, every finding's story and the sends by host. No value is in the
 * answer, so none can be here.
 */
export function renderScan(r: ScanWire, opts: RenderOpts): string {
  return opts.all ? renderLong(r, opts.style ?? PLAIN) : renderCompact(r, opts);
}

/** Seen only in sessions while Mandu ran, by the time alone: there the AI
 *  may have seen a placeholder. */
const byTimeOnly = (f: FindingWire): boolean => { const s = manduSplit(f); return s.without === 0 && s.byTime > 0; };

/** A finding's name and, dim, its file: `STRIPE_KEY   ~/shop/.env`. */
function findingTitle(f: FindingWire, st: Style): string {
  return f.source?.name !== undefined ? `${f.source.name}   ${st.dim(f.source.path)}` : f.preview;
}

/** The ways in HOW_SHORT's order, for a tie in the compact report. */
const HOW_ORDER = Object.keys(HOW_SHORT) as How[];

/** The line under a finding in the compact report: its sessions, how it got
 *  there (the three most common ways; a tie in HOW_SHORT's order), and the
 *  command, shortened, when one way and one command is all the record shows. */
function compactDetail(f: FindingWire, st: Style): string {
  const when = f.sessions === 1 ? day(f.last) : `last ${day(f.last)}`;
  const rank = (h: How): number => { const i = HOW_ORDER.indexOf(h); return i < 0 ? HOW_ORDER.length : i; };
  const ways = (Object.entries(f.how) as Array<[How, number]>).sort((a, b) => b[1] - a[1] || rank(a[0]) - rank(b[0])).map(([h]) => h);
  const how = ways.slice(0, 3).map((h) => HOW_SHORT[h] ?? h).join(", ");
  const e = storyExample(f);
  const cmd = how !== "" && ways.length === 1 && e?.command !== undefined ? `: ${shortCommand(e.command)}` : "";
  const note = byTimeOnly(f) ? st.dim(" (only while Mandu ran, by time)") : "";
  return `${[`${plural(f.sessions, "session")}${when ? `, ${when}` : ""}`, `${how}${cmd}`].filter((p) => p !== "").join(" · ")}${note}`;
}

/** `a, b, c, …`: three hosts at most. */
const hostList = (hosts: readonly string[]): string => `${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ", …" : ""}`;

/**
 * The yellow line under one of your secrets that a command or a tool sent
 * on: per way (over HTTP, over ssh, with git, by a script, to an MCP
 * server's tool) the hosts (those Mandu cannot tie to the key first), a
 * host where every send failed or was refused as "tried", and when every
 * send used the secret's variable (the AI saw only its name), "through its
 * variable". Null when none was sent. The sends in full are `--all`'s.
 */
function sentLine(r: ScanWire, f: FindingWire, st: Style): string | null {
  if (r.sends === undefined) {
    const hosts = f.sentToHosts ?? [];
    return hosts.length > 0 ? st.yellow(`also sent over HTTP to ${hostList(hosts)}`) : null;
  }
  const mine = sendsOf(r, f);
  if (mine.length === 0) return null;
  // Per channel, in CHANNEL_TO's order: the hosts it reached, those it only tried.
  const per: Array<{ to: string; sent: string[]; tried: string[] }> = [];
  for (const [ch, to] of CHANNEL_TO) {
    const byHost = new Map<string, { ran: number; other: boolean }>();
    for (const s of mine.filter((x) => channelOf(x) === ch)) {
      const h = byHost.get(s.host) ?? { ran: 0, other: false };
      h.ran += s.ran;
      h.other ||= s.to === "other-host";
      byHost.set(s.host, h);
    }
    if (byHost.size === 0) continue;
    const hosts = [...byHost].sort(([, a], [, b]) => Number(b.other) - Number(a.other));
    per.push({ to, sent: hosts.filter(([, h]) => h.ran > 0).map(([n]) => n), tried: hosts.filter(([, h]) => h.ran === 0).map(([n]) => n) });
  }
  // The ways it went first, then the ways it was only tried.
  const went = per.filter((c) => c.sent.length > 0);
  const words = went.length > 0
    ? `also sent ${[
      ...went.map((c) => `${c.to} ${hostList(c.sent)}${c.tried.length > 0 ? ` · tried ${hostList(c.tried)}` : ""}`),
      ...per.filter((c) => c.sent.length === 0).map((c) => `tried ${c.to} ${hostList(c.tried)}`),
    ].join(" · ")}`
    : `a command tried to send it ${per.map((c) => `${c.to} ${hostList(c.tried)}`).join(" · ")} (it failed or was refused)`;
  const byName = mine.every((s) => !s.by.includes("value")) ? st.dim(" (through its variable)") : "";
  return `${st.yellow(words)}${byName}`;
}

/** The key-shaped values by their masked prefix, most values first:
 *  `sk-… ×190 · ghp_… ×24 · …` (five, then `…`). */
function prefixLine(list: readonly FindingWire[]): string {
  const count = new Map<string, number>();
  for (const f of list) count.set(f.preview, (count.get(f.preview) ?? 0) + 1);
  const top = [...count].sort(([a, x], [b, y]) => y - x || (a < b ? -1 : a > b ? 1 : 0));
  return `${top.slice(0, 5).map(([p, k]) => `${p} ×${k}`).join(" · ")}${top.length > 5 ? " · …" : ""}`;
}

/** The riskier sessions, short (plan 17 §3 item 10), under "Risky sessions". */
function riskShort(r: ScanWire["risk"]): string[] {
  if (r === undefined) return [];
  const out: string[] = [];
  if (r.skippedPrompts > 0) out.push(`${r.skippedPrompts} ran with permission prompts off${r.skippedWithSecret > 0 ? ` (in ${r.skippedWithSecret}, one of your secrets leaked)` : ""}`);
  if (r.envDumps > 0) out.push(`${r.envDumps} printed your whole environment to the AI`);
  return out;
}

/** `29 Sep – 22 Oct`, or one day. */
function spanWords(r: ScanWire): string {
  const a = day(r.from);
  const b = day(r.to);
  return a !== "" && b !== "" && a !== b ? `${a} – ${b}` : b || a;
}

/** The compact report's head: `mandu scan · 834 sessions · Claude Code, Codex · 29 Sep – 22 Oct`. */
function compactHead(r: ScanWire): string {
  const read = (Object.entries(r.sessions) as Array<[AgentId, number]>).filter(([, n]) => n > 0)
    .sort(([a], [b]) => agentRank(a) - agentRank(b) || (a < b ? -1 : a > b ? 1 : 0));
  const total = read.reduce((x, [, n]) => x + n, 0);
  if (total === 0) return "mandu scan · no agent sessions";
  return ["mandu scan", plural(total, "session"), read.map(([a]) => AGENT_NAME[a] ?? a).join(", "), spanWords(r)].filter((p) => p !== "").join(" · ");
}

/** A row of the closing block: `  Protect your agents:  mandu claude`. */
const row = (label: string, text: string): string => `  ${`${label}:`.padEnd(22)}${text}`;

/**
 * The default report, compact (the maintainer's layout, 2026-10-22): the
 * words are direct ("leaked to the AI") because only this terminal report
 * and `--show` use them; `--share`, `--json`, the kept scan and the
 * dashboard still say "reached the AI" (plan 17 §2). Numbers are
 * {@link numberedFindings}'s: your secrets are 1 to k, in the order shown,
 * and `--all` lists the rest under theirs.
 */
function renderCompact(r: ScanWire, opts: RenderOpts): string {
  const st = opts.style ?? PLAIN;
  const lines: string[] = [compactHead(r), "Nothing was sent anywhere; no secret value is shown."];
  for (const c of [...cappedLines(r.capped), ...notReadLines(r.notRead)]) lines.push(st.dim(`  note: ${c}`));
  lines.push("");
  const order = numberedFindings(r);
  const live = order.filter((f) => !keptByMandu(f));
  const known = live.filter((f) => f.kind === "known");
  const shaped = live.filter(shapedLeak);
  const tests = live.filter(looksLikeTest);
  const named = live.filter((f) => f.kind !== "known" && !LISTED_BY_DEFAULT(f.kind));
  const kept = order.filter(keptByMandu);
  if (known.length > 0) {
    lines.push(st.bold(st.red(`✗ ${known.length} of your secrets leaked to the AI`)), "");
    const width = String(known.length).length;
    const pad = " ".repeat(2 + width + 2);
    known.forEach((f, i) => {
      lines.push(`  ${st.red(String(i + 1).padStart(width))}  ${findingTitle(f, st)}`);
      lines.push(`${pad}${compactDetail(f, st)}`);
      const sent = sentLine(r, f, st);
      if (sent !== null) lines.push(`${pad}${sent}`);
    });
    lines.push("", `  → ${known.length === 1 ? "Rotate it now, where it was issued." : `Rotate these ${known.length} now, where they were issued.`}`);
  } else {
    lines.push(`${st.bold(st.green("✓ None of your secrets leaked to the AI"))} ${st.dim(`(Mandu found ${r.known === 0 ? "none" : r.known} on this computer)`)}`);
  }
  if (shaped.length > 0 || tests.length > 0 || named.length > 0 || r.dropped > 0) lines.push("");
  if (shaped.length > 0) {
    const more = known.length > 0 ? "more " : "";
    if (shaped.length === 1) lines.push(`${st.yellow(`! 1 ${more}key-shaped value leaked`)} ${st.dim("(not in your files now: an old")}`, st.dim("  key, someone else's, or a test value)"));
    else lines.push(`${st.yellow(`! ${shaped.length} ${more}key-shaped values leaked`)} ${st.dim("(not in your files now: old")}`, st.dim("  keys, someone else's, or test values)"));
    lines.push(`  ${prefixLine(shaped)}`);
  }
  if (tests.length > 0) lines.push(st.dim(`  ${plural(tests.length, shaped.length > 0 ? "more value" : "key-shaped value")} ${tests.length === 1 ? "looks" : "look"} like ${tests.length === 1 ? "a test value" : "test values"} (${TEST_SIGNS}), not counted: mandu scan --all`));
  if (named.length > 0) lines.push(st.dim(`  ${plural(named.length, shaped.length > 0 || tests.length > 0 ? "more value" : "value")} named like a secret (DB_PASSWORD=…, a password in a URL): mandu scan --all`));
  if (r.dropped > 0) lines.push(st.dim(`  (${r.dropped} more distinct values were counted but not kept)`));
  const risk = riskShort(r.risk);
  if (risk.length > 0) lines.push("", st.yellow("! Risky sessions"), ...risk.map((l) => `  ${l}`));
  // The footnotes: sessions under Mandu or while it ran, what it kept, the
  // agents it does not run.
  const notes: string[] = [];
  const onlyByTime = live.filter(byTimeOnly).length;
  const only = onlyByTime > 0 ? `; ${onlyByTime === 1 ? "1 finding above was" : `${onlyByTime} findings above were`} seen only there` : "";
  if (r.sessionsUnderMandu !== undefined && r.sessionsByTime !== undefined) {
    if (r.sessionsUnderMandu > 0) notes.push(`${plural(r.sessionsUnderMandu, "session")} ran under Mandu: there the AI saw placeholders, not the values.`);
    if (r.sessionsByTime > 0) notes.push(`${plural(r.sessionsByTime, "session")} ran while Mandu ran (by time): there the AI may have seen a placeholder${only}.`);
  } else if (r.duringMandu > 0) {
    notes.push(`${plural(r.duringMandu, "session")} ran while Mandu ran the same agent: there the AI may have seen a placeholder${only}.`);
  }
  if (kept.length > 0) notes.push(`Mandu kept ${plural(kept.length, "more value")} from the AI (only in sessions under Mandu, where the AI saw a placeholder): mandu scan --all`);
  const others = unrunRead(r);
  if (others.length > 0) notes.push(`Mandu does not run ${agentNames(others)} yet; the agents it runs: ${RUN_COMMANDS}.`);
  if (notes.length > 0) lines.push("", ...notes.map((l) => st.dim(l)));
  if (opts.suggestions) lines.push("", opts.suggestions);
  lines.push("");
  const runsSome = others.length === 0 || Object.entries(r.sessions).some(([a, k]) => (k ?? 0) > 0 && !unrun(a));
  if (runsSome) {
    // The promise is for your secrets: a key-shaped value Mandu does not
    // hold reaches the AI as before (the long report says so).
    // Said as security, in green (the maintainer, 2026-10-22: "highlight
    // it's secure"), but only of what Mandu holds: never "everything".
    lines.push(st.green(st.bold(known.length > 0
      ? `✓ With Mandu, ${known.length === 1 ? "this secret stays" : `these ${known.length} secrets stay`} safe: the AI sees only a $MDU:… placeholder, and your agent still does its work.`
      : "✓ With Mandu, your secrets stay safe: the AI sees only a $MDU:… placeholder, and your agent still does its work.")));
    lines.push(row("Protect your agents", `${st.cyan("mandu claude")}  (or ${st.cyan("mandu codex")})`));
  }
  const all = `Everything: ${st.cyan("mandu scan --all")}`;
  lines.push(order.length > 0 ? row("One in full", `${st.cyan("mandu scan --show 1")}   ${all}`) : row("Everything", st.cyan("mandu scan --all")));
  if (opts.dashboard) lines.push(row("Dashboard", opts.dashboard));
  return `${lines.join("\n")}\n`;
}

/** The long report (`--all`): every finding's story, the sends by host,
 *  every footnote in full. */
function renderLong(r: ScanWire, st: Style): string {
  const lines: string[] = [];
  const span = r.from && r.to ? ` (${day(r.from)} to ${day(r.to)})` : "";
  lines.push(`mandu scan: read ${sessionWords(r.sessions)} on this computer${span}.`);
  lines.push("Nothing left this computer, and no secret's value is shown below.");
  for (const c of [...cappedLines(r.capped), ...notReadLines(r.notRead)]) lines.push(`  note: ${c}`);
  lines.push("");
  const order = numberedFindings(r);
  const num = new Map(order.map((f, i) => [f, i + 1]));
  const n = (f: FindingWire): string => `${num.get(f)}.`;
  const live = order.filter((f) => !keptByMandu(f));
  const known = live.filter((f) => f.kind === "known");
  const shapedAll = live.filter(shapedLeak);
  const tests = live.filter(looksLikeTest);
  const named = live.filter((f) => f.kind !== "known" && !LISTED_BY_DEFAULT(f.kind));
  const kept = order.filter(keptByMandu);
  if (known.length > 0) {
    lines.push(st.bold(st.red(`${known.length === 1 ? "1 of your secrets" : `${known.length} of your secrets`} leaked to the AI:`)));
    for (const f of known) {
      lines.push("", `  ${st.red(n(f))} ${f.preview}`);
      lines.push(...storyLines(f, "     ", { withMandu: true }));
    }
    lines.push("");
    lines.push(`${known.length === 1 ? "It is" : "They are"} still where ${known.length === 1 ? "it was" : "they were"} found: change ${known.length === 1 ? "it" : "them"} where ${known.length === 1 ? "it was" : "they were"} issued.`);
  } else {
    lines.push(st.bold(st.green(`None of the ${plural(r.known, "secret")} Mandu found on this computer leaked to the AI in these sessions.`)));
  }
  const rows = (list: FindingWire[], stories: number): void => {
    list.forEach((f, i) => {
      if (i < stories) lines.push("", `  ${n(f)} ${f.preview}`, ...storyLines(f, "     ", { withMandu: false }));
      else lines.push(`  ${n(f)} ${f.preview}`, ...shortLines(f, "     ", true));
    });
  };
  if (shapedAll.length > 0) {
    lines.push("");
    lines.push(st.yellow(`${plural(shapedAll.length, "more value")} ${shapedAll.length === 1 ? "looks" : "look"} like ${shapedAll.length === 1 ? "a key" : "keys"} and leaked to the AI, but ${shapedAll.length === 1 ? "is" : "are"} not in your files now (an old key, someone else's, or a test value; the project and command tell which):`));
    rows(shapedAll.slice(0, STORIES), STORIES);
    if (shapedAll.length > STORIES) lines.push("");
    rows(shapedAll.slice(STORIES), 0);
    lines.push("", "With Mandu, a key like these is masked when it is in a file or variable Mandu protects; one it does not hold reaches the AI as before.");
  }
  if (tests.length > 0) {
    lines.push("", `${plural(tests.length, "value")} ${tests.length === 1 ? "looks" : "look"} like ${tests.length === 1 ? "a key, but reads" : "keys, but read"} as ${tests.length === 1 ? "a test value" : "test values"} (${TEST_SIGNS}), so ${tests.length === 1 ? "it is" : "they are"} not counted as leaked; the project and command tell for sure:`);
    rows(tests, 0);
  }
  if (named.length > 0) {
    lines.push("", `${plural(named.length, "value")} named like a secret (DB_PASSWORD=…, a password in a URL):`);
    rows(named, 0);
  }
  if (kept.length > 0) {
    lines.push("", `Mandu kept ${plural(kept.length, "more value")} from the AI: ${kept.length === 1 ? "it was" : "they were"} only in sessions under Mandu, where the AI saw a placeholder:`);
    rows(kept, 0);
  }
  if (r.dropped > 0) lines.push(`(${r.dropped} more distinct values were counted but not kept)`);
  const sent = sendLines(r);
  if (sent.length > 0) {
    lines.push("");
    lines.push(...sent);
  }
  const risk = riskLines(r.risk);
  if (risk.length > 0) {
    lines.push("");
    lines.push(st.yellow("Riskier sessions:"));
    for (const l of risk) lines.push(`  ${l}`);
  }
  const onlyByTime = live.filter(byTimeOnly).length;
  if (r.duringMandu > 0 || kept.length > 0) {
    lines.push("");
    const only = onlyByTime > 0 ? ` ${onlyByTime === 1 ? "1 of the findings above was" : `${onlyByTime} of the findings above were`} seen only in such sessions.` : "";
    if (r.sessionsUnderMandu !== undefined && r.sessionsByTime !== undefined) {
      if (r.sessionsUnderMandu > 0) lines.push(`${plural(r.sessionsUnderMandu, "session")} ran under Mandu: there Mandu masked the secrets it holds before the AI saw them, though the record on disk shows the values.`);
      if (r.sessionsByTime > 0) lines.push(`${plural(r.sessionsByTime, "session")} ran while Mandu ran (by time): there the AI may have seen a placeholder where the record on disk shows the value.${only}`);
    } else if (r.duringMandu > 0) {
      lines.push(`${plural(r.duringMandu, "session")} ran while Mandu ran the same agent: there the AI may have seen a placeholder where the record on disk shows the value.${only}`);
    }
  }
  lines.push("");
  const others = unrunRead(r);
  if (others.length > 0) lines.push(`Mandu does not run ${agentNames(others)} yet; the agents it runs: ${RUN_COMMANDS}.`);
  if (others.length === 0 || Object.entries(r.sessions).some(([a, k]) => (k ?? 0) > 0 && !unrun(a))) lines.push(`To keep your secrets from the AI from now on: ${st.cyan("mandu claude")} (or ${st.cyan("mandu codex")}).`);
  lines.push(`To share the counts, with no value, path or name: ${st.cyan("mandu scan --share")}`);
  if (order.length > 0) lines.push(`To see one finding in full (every way it got there, up to 10 examples each): ${st.cyan("mandu scan --show <n>")}, n from 1 to ${order.length}`);
  return `${lines.join("\n")}\n`;
}

/** Up to this many examples per way in `--show`. */
const SHOW_EXAMPLES = 10;

/** What a finding is, for `--show`'s title, in the compact report's words
 *  ("leaked to the AI"), and its colour there. */
function tierWords(f: FindingWire, st: Style): string {
  if (keptByMandu(f)) return st.green("kept from the AI by Mandu (only in sessions under Mandu)");
  if (f.kind === "known") return st.red("one of your secrets, leaked to the AI (still where it was found)");
  if (looksLikeTest(f)) return st.dim("a key-shaped value that looks like a test value, sent to the AI (not counted as leaked)");
  if (LISTED_BY_DEFAULT(f.kind)) return st.yellow("a key-shaped value, leaked to the AI (in no file now)");
  return st.yellow("a value named like a secret, leaked to the AI (in no file now)");
}

/**
 * `mandu scan --show <n>`: one finding in full (plan 17 §2): its sessions,
 * dates and projects, with and without Mandu, then every way it got there
 * with up to ten examples each (when, project, agent, the redacted command
 * or the file), that it left this computer and to whom, what came next, and
 * for one of your secrets what Mandu would have done. Null when there is no
 * finding n. No value is in the answer, so none can be here.
 */
export function renderShow(r: ScanWire, n: number, st: Style = PLAIN): string | null {
  const order = numberedFindings(r);
  const f = order[n - 1];
  if (f === undefined) return null;
  const lines: string[] = [];
  lines.push(`mandu scan: finding ${n} of ${order.length}. No secret's value is shown below.`, "");
  lines.push(st.bold(`${n}. ${f.preview}: ${tierWords(f, st)}`));
  const projects = f.projectCount ?? f.projects.length;
  const list = f.projects.length > 0 ? `: ${f.projects.join(", ")}${projects > f.projects.length ? ", …" : ""}` : "";
  lines.push(`   ${plural(f.sessions, "session")}, ${dayRange(f.first, f.last) || "no date in the record"}, ${projects === 0 ? "no project in the record" : `${plural(projects, "project")}${list}`} · ${agentsWords(f.agents)}`);
  const s = manduSplit(f);
  const parts = [s.without > 0 ? `${s.without} without Mandu` : "", s.byTime > 0 ? `${s.byTime} while Mandu ran (by time only, so there the AI may have seen a placeholder)` : "", s.under > 0 ? `${s.under} under Mandu (the AI saw a placeholder)` : ""].filter((p) => p !== "");
  if (s.byTime > 0 || s.under > 0) lines.push(`   ${parts.join(", ")}`);
  const byHow = f.examplesByHow ?? {};
  for (const how of howsByCount(f)) {
    const ex = (byHow[how] ?? (f.examples ?? []).filter((e) => e.how === how)).slice(0, SHOW_EXAMPLES);
    const count = f.how[how] ?? 0;
    lines.push("", `   ${(HOW_WORDS[how] ?? how).replace(/^./, (c) => c.toUpperCase())}, in ${plural(count, "session")}${ex.length < count && ex.length > 0 ? `; the newest ${ex.length}` : ""}:`);
    for (const e of ex) {
      lines.push(`     ${exampleHead(e, true)}`);
      lines.push(`       ${didLine(e)}`);
    }
    const sent = ex.find((e) => e.mandu !== "under" && e.mandu !== "by-time") ?? ex[0];
    if (sent !== undefined && sent.mandu !== "under") {
      const to = [...new Set(ex.filter((e) => e.mandu !== "under").map((e) => `${AGENT_NAME[e.agent] ?? e.agent}'s to ${providerName(e)}`))].join(", ");
      lines.push(`     Each time, ${how === "ai-wrote" ? "the AI had it already, and it went back with each later request" : `${noun(f)} left this computer in the agent's next request`}: ${to}.`);
    }
  }
  // The AI's own writing has its section above; the sends are what is left.
  const next = nextLines(f, "ai-wrote");
  if (next.length > 0) lines.push("", ...next.map((l) => `   ${l}`));
  const sends = sendsOf(r, f);
  if (sends.length > 0) {
    lines.push("", sends.every((x) => channelOf(x) === "http")
      ? "   Sent on over HTTP, by host, with the URLs (their query values and credentials masked):"
      : "   Sent on, by where it went (a host, or an MCP server's tool), with the URLs (their query values and credentials masked):");
    for (const s of sends) lines.push(...sendRow(s, "     "));
  }
  if (f.kind === "known") {
    lines.push("");
    // Only for the agents Mandu runs: for the others it could have done nothing.
    if (f.agents.some((a) => !unrun(a))) for (const how of howsByCount(f)) lines.push(`   ${withManduLine(how).replace(/^With Mandu/, `With Mandu (${HOW_WORDS[how] ?? how})`)}`);
    const others = f.agents.filter(unrun);
    if (others.length > 0) lines.push(`   Mandu does not run ${agentNames(others)} yet: there it could not have kept the secret from the AI (the agents it runs: ${RUN_COMMANDS}).`);
  }
  return `${lines.join("\n")}\n`;
}

/** A short text for the person to post: counts only, no path, mask, name or
 *  project (plan 17 §3 item 9). */
export function shareText(r: ScanWire): string {
  const total = Object.values(r.sessions).reduce((x, n) => x + (n ?? 0), 0);
  const known = r.findings.filter((f) => f.kind === "known").length;
  const keys = r.findings.filter(shapedLeak).length;
  const head = `I checked ${plural(total, "AI agent session")} on my computer with mandu scan:`;
  const found = known === 0 ? "none of my current secrets had reached the AI" : `${known === 1 ? "1 of my secrets" : `${known} of my secrets`} had reached the AI`;
  const more = keys > 0 ? `, and ${plural(keys, "more value")} that ${keys === 1 ? "looks" : "look"} like ${keys === 1 ? "a key" : "keys"}` : "";
  return `${head} ${found}${more}. Check yours (it runs on your computer and sends nothing): npx @mandusec/mandu scan\n`;
}

/** The package a person runs through npx (packaging.md §5). */
export const NPX_PACKAGE = "@mandusec/mandu";

/**
 * Did the person run this command through npx (`npx @mandusec/mandu scan`)?
 * Then the commands this one names must be spelled that way too: most scan
 * users have no `mandu` on their PATH. npm's `exec` (which `npx` is since
 * npm 7) sets `npm_command=exec` and `npm_lifecycle_event=npx` for the
 * command it runs, and `npm_lifecycle_script` to that command (`mandu`,
 * this package's bin): a `mandu` started from some other command npx ran
 * (a shell, `tsx` in a checkout) is not run through npx. Pure.
 */
export function ranThroughNpx(env: Env): boolean {
  if (env["npm_command"] !== "exec" && env["npm_lifecycle_event"] !== "npx") return false;
  const script = (env["npm_lifecycle_script"] ?? "").trim();
  if (script === "") return true;
  const first = script.split(/\s+/)[0]!;
  return first === "mandu" || first.endsWith("/mandu") || first.startsWith(NPX_PACKAGE);
}

/** `mandu <rest>` as the person would type it now: through npx when this
 *  command ran so. Pure. */
export function manduCommand(env: Env, rest: string): string {
  return `${ranThroughNpx(env) ? `npx ${NPX_PACKAGE}` : "mandu"} ${rest}`;
}

/** A dashboard as the report's last line needs it. */
type DashboardAt = { host: string; port: number; basePath?: string; passwordFirst?: boolean; signInWith?: SignInWith };

/**
 * The report's last line: where the person sees it in the dashboard (plan
 * 17 §3 item 12; dashboard.md §4.25ai). A dashboard of this user running:
 * its Scan page's URL. None: the command that opens one (the npx form when
 * this ran through npx), which shows the report kept for it; `mandu
 * dashboard` starts one even when Mandu never ran (subcommands.ts
 * runDashboard). This one-shot command starts no server itself unless
 * `--open` asks it to ({@link openScanPage}, after this line). A
 * dashboard that asks before any page (registry `signInMode` `password`,
 * `basic-auth` or `account`: the Mandu dashboard account, dashboard.md
 * §6.z) says so, in the launch line's words (dashboard-sign-in.ts
 * signInWords): the bare URL answered "Unauthorized" (the maintainer,
 * 2026-10-22). A one-time link does not get past that sign-in page, so
 * none is offered. Pure.
 */
export function dashboardLine(env: Env, dashboards: readonly DashboardAt[]): string {
  return dashboards[0] !== undefined
    ? `This report is in your dashboard too: ${dashboardWhere(env, dashboards)}`
    : `This report is kept for your dashboard: ${dashboardWhere(env, dashboards)}.`;
}

/** Where the report is in the dashboard, the words {@link dashboardLine}
 *  ends with and the compact report's "Dashboard:" row says: the Scan
 *  page's URL (and that it asks for its password first), or the command
 *  that opens one. Pure. */
export function dashboardWhere(env: Env, dashboards: readonly DashboardAt[]): string {
  const d = dashboards[0];
  if (d !== undefined && d.passwordFirst === true) return `${scanPageUrl(d)} (${signInWords({ ...(d.signInWith ? { with: d.signInWith } : {}) })})`;
  if (d !== undefined) return scanPageUrl(d);
  return `run ${manduCommand(env, "dashboard")} and open Scan`;
}

export interface ScanDeps {
  arbiter: (env: Env, layout: Layout) => Promise<DryRunArbiter>;
  call: (sock: string, req: Record<string, unknown>, timeoutMs: number) => Promise<ScanWire>;
  now: () => number;
  /** Keeping the report for the dashboard and doctor, and the running
   *  Mandu's suggestions (plan 17 §3 items 12, 13); absent: not kept. */
  keep?: KeepDeps;
  /** This user's live dashboards, newest first (live-dashboards.ts), for
   *  the report's last line. Absent: no line. */
  dashboards?: (env: Env) => readonly DashboardAt[];
  /** Is stdout a terminal (colour, term-style.ts `colorOn`)? Absent: no. */
  isTTY?: () => boolean;
  /** `--open`: this user's live dashboard, else one started as `mandu
   *  dashboard` starts it (subcommands.ts `dashboardForScan`, handed in by
   *  the dispatcher), with `started` saying which; null when none could be
   *  started (the reason already printed). Absent: `--open` says it cannot. */
  openDashboard?: (env: Env) => Promise<{ d: DashboardAt; started: boolean } | null>;
  /** `--open`: open a URL in the default browser (browser-open.ts
   *  `openUrl`). Absent: none here. */
  browse?: (url: string, env: Env) => Promise<OpenOutcome>;
}

/** How long the command waits for the scan: its own deadline plus a margin,
 *  so only a wedged arbiter trips it. Pure. */
export function scanCallTimeoutMs(env: Env): number {
  const s = Number(env["MANDU_TRANSCRIPT_SCAN_TIMEOUT_S"]);
  return (Number.isFinite(s) && s > 0 ? s * 1000 : 300_000) + 60_000;
}

export const realScanDeps: ScanDeps = {
  arbiter: (env, layout) => throwawayArbiter(env, layout),
  call: (sock, req, timeoutMs) => ndjsonCall<ScanWire>(sock, "scanAgentTranscripts", req, timeoutMs),
  now: () => Date.now(),
  keep: {
    // The running Mandu with its secrets protection on: its own arbiter,
    // never the throwaway the scan ran in.
    resident: async (env) => {
      const h = await helloResident(env);
      return h !== null && h.axisOn !== false ? h.sock : null;
    },
    suggest: (sock, home, files) => ndjsonCall(sock, "suggestFromScan", { home, files }, 15_000),
    write: writeLastScan,
  },
  dashboards: (env) => liveDashboards(env),
  isTTY: () => process.stdout.isTTY === true,
  browse: (url, env) => openUrl(url, env),
};

/** Is `host` this machine's loopback, so an SSH tunnel reaches it? */
const loopback = (host: string): boolean => /^127\./.test(host) || host === "localhost" || host === "::1" || host === "[::1]";

/**
 * `mandu scan --open`, after the report (plan 17 §3 item 12, the
 * maintainer 2026-10-22): this user's dashboard, started if none runs, and
 * its Scan page opened in the browser. The page's plain URL only, never a
 * credential: an argument sits in `ps`, and a one-time sign-in link minted
 * for it would be one; a dashboard that asks for a sign-in shows its own
 * page, and the line says so as the Dashboard line does
 * ({@link dashboardWhere}). With no browser here (an SSH session, no
 * display) nothing is tried: the URL, and over SSH how to forward the port
 * (no real host named). Never changes the scan's exit code: the report is
 * already printed.
 */
export async function openScanPage(
  env: Env, deps: Pick<ScanDeps, "openDashboard" | "browse">, out: (s: string) => void, err: (s: string) => void,
): Promise<void> {
  if (!deps.openDashboard) {
    err("mandu scan: --open: no dashboard can be started from here; run mandu dashboard\n");
    return;
  }
  let found: { d: DashboardAt; started: boolean } | null;
  try { found = await deps.openDashboard(env); } catch (e) {
    err(`mandu scan: --open: ${(e as Error).message}\n`);
    found = null;
  }
  if (found === null) {
    err(`mandu scan: --open: the dashboard did not start, so nothing was opened (${manduCommand(env, "dashboard")} to try again)\n`);
    return;
  }
  const { d, started } = found;
  const url = scanPageUrl(d);
  const where = dashboardWhere(env, [d]);
  let outcome: OpenOutcome;
  try {
    outcome = deps.browse ? await deps.browse(url, env) : { kind: "no-browser", ssh: false };
  } catch (e) {
    outcome = { kind: "failed", cmd: "the browser", why: (e as Error).message };
  }
  if (outcome.kind === "opened") {
    out(`${started ? "Started the dashboard and opened its Scan page" : "Opened the dashboard's Scan page"}: ${where}\n`);
    return;
  }
  out(`${started ? "Started the dashboard; its Scan page" : "The dashboard's Scan page"}: ${where}\n`);
  if (outcome.kind === "failed") {
    err(`mandu scan: could not open a browser (${outcome.cmd}: ${outcome.why}): open the URL above yourself\n`);
    return;
  }
  out("No browser here: open this URL on your computer\n");
  if (outcome.ssh && loopback(connectHost(d.host))) {
    out(`Over SSH, forward its port first: ssh -L ${d.port}:127.0.0.1:${d.port} <this machine>\n`);
  }
}

/** `mandu scan`. Exit 0 with a report (findings do not change it), 1 when
 *  the scan could not run, 2 on a bad option. */
export async function runScan(
  rest: string[], env: Env, layout: Layout, deps: ScanDeps = realScanDeps,
  io: { out?: (s: string) => void; err?: (s: string) => void } = {},
): Promise<number> {
  const out = io.out ?? ((s: string) => { process.stdout.write(s); });
  const err = io.err ?? ((s: string) => { process.stderr.write(s); });
  const args = parseScanArgs(rest, deps.now());
  if ("error" in args) {
    err(`mandu scan: ${args.error}\n`);
    return 2;
  }
  const home = env["HOME"] || homedir();
  if (!args.json && !args.share) err("mandu scan: reading your agents' transcripts on this computer (a minute or two for a few GB)…\n");
  let arb: DryRunArbiter | null = null;
  let opening = false;
  try {
    arb = await deps.arbiter(env, layout);
    const r = await deps.call(arb.sock, {
      home, eventsDir: manduPath("events", env, home), ...(args.since !== undefined ? { since: args.since } : {}),
    }, scanCallTimeoutMs(env));
    // Kept for the dashboard and doctor (plan 17 §3 item 12), with the
    // running Mandu's suggestions for the files (item 13).
    const kept = deps.keep
      ? await keepLastScan(r, { env, home, ranAt: deps.now(), ...(args.since !== undefined ? { since: args.since } : {}) }, deps.keep)
      : null;
    // Where the person sees the report in the dashboard (the last line of
    // the report and of --show; never of --json or --share): only when it
    // was kept there.
    const found = ((): readonly DashboardAt[] | null => {
      if (!deps.dashboards || !kept?.rec || kept.error !== undefined) return null;
      try { return deps.dashboards(env); } catch { return []; /* an unreadable registry: the command */ }
    })();
    const linkOf = (): string => (found === null ? "" : `${dashboardLine(env, found)}\n`);
    // Colour for the terminal only: never --json or --share, nor a pipe.
    const st = colors(!args.json && !args.share && colorOn(deps.isTTY?.() ?? false, env));
    if (args.show !== undefined) {
      const order = numberedFindings(r);
      const f = order[args.show - 1];
      if (f === undefined) {
        err(`mandu scan: there is no finding ${args.show}: ${order.length === 0 ? "this scan found none" : `the report numbers them 1 to ${order.length}`}\n`);
        return 2;
      }
      out(args.json ? `${JSON.stringify({ number: args.show, of: order.length, finding: f }, null, 2)}\n` : renderShow(r, args.show, st)!);
      if (!args.json) out(linkOf());
      opening = args.open === true;
      return 0;
    }
    if (args.json) out(`${JSON.stringify(r, null, 2)}\n`);
    else if (args.share) out(shareText(r));
    else if (args.all) {
      out(renderScan(r, { all: true, style: st }));
      const line = suggestionsLine(kept?.rec ?? null);
      if (line !== null) out(`${line}\n`);
      out(linkOf());
    } else {
      out(renderScan(r, {
        all: false, style: st, suggestions: suggestionsLine(kept?.rec ?? null),
        ...(found !== null ? { dashboard: dashboardWhere(env, found) } : {}),
      }));
    }
    if (kept?.error !== undefined) err(`mandu scan: ${kept.error}\n`);
    opening = args.open === true;
    return 0;
  } catch (e) {
    err(`mandu scan: the scan could not run: ${(e as Error).message}\n`);
    return 1;
  } finally {
    if (arb !== null) await arb.stop();
    // `--open`, once the report is out and the throwaway arbiter stopped;
    // it never changes the exit code (it prints, it does not throw).
    if (opening) await openScanPage(env, deps, out, err);
  }
}
