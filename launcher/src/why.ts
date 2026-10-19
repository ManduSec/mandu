/**
 * why — `mandu why <path>` / `mandu why <host>` (comparisons.md §3.2):
 * one question, answered from the law the arbiter compiles, with the rule that
 * decided. Read-only: it asks the arbiter's `whyPath` / `whyHost` / `testFlow`
 * ops (which record nothing) and computes the connect-guard set a launch would
 * build (net-guard.ts), without launching anything.
 *
 *   mandu why ~/.pgpass                 level, rule, readers, twin, consumers
 *   mandu why .env --to api.stripe.com  ... and what a send there would do
 *   mandu why api.stripe.com            bound secrets, release, reachability
 *   mandu why '$MDU:…'                  where a placeholder came from: for a
 *                                       prompt finding (plan 15 §13.8), the
 *                                       filter, category, action, hold,
 *                                       session and turn, and the ways out
 *   mandu why '$MDU:…' --session <id>   ... searching that session first (the
 *                                       answer searches the placeholder's own
 *                                       and the most recent ones, at most 24)
 *   --json                                the raw answer
 *
 * A placeholder is asked on the HUMAN PLANE (`whySymbol`, the socket the
 * arbiter's `hello` names), since the answer comes from the session events.
 * Where that socket is out of reach (inside the agent's walls) the answer is
 * the data plane's `symbolProvenance` (the minting tool) and a note: never
 * more than the data socket already gives. Never a value.
 *
 * With no Mandu running (`whyArbiter`) a path or a host is asked of a
 * temporary arbiter whose store is seeded read-only from the stopped one's
 * (arbiter db/store-seed.ts, runtime-instances.md §9b): the remembered
 * answers and the changes waiting in Approvals are in the answer, rendered
 * by the same functions as a live one's. A store it cannot read leaves the
 * unseeded temporary arbiter of before, and its notes.
 *
 * Mandu-new (no reference origin).
 */
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { computeNetGuardSpecs } from "./net-guard.js";
import { loginEnvOf, ndjsonCall } from "./secret-setup.js";
import { agentDisplayName, loginKeptWhere } from "./agent-login.js";
import { helloResident, throwawayArbiter, type DryRunArbiter } from "./doctor-secrets.js";
import { manduPath } from "./generated/mandu-paths.js";
import type { Env } from "./doctor-live.js";
import { readArbiterHumanSock } from "./human-plane.js";
import type { Layout } from "./services/layout.js";

/** Where the file's values may go (`mandu why <file>`): one line, or with
 *  `values:` (plan 13 §5.2) one per value and one for the whole file. */
export function mayGoLines(a: Pick<WhyPathAnswer, "bindings" | "values" | "fileBindings">): string[] {
  const hosts = (b: readonly string[]): string => (b.length ? b.join(", ") : "no host (any send is held for your OK)");
  if (!a.values || a.values.length === 0) return [`  may go to  ${hosts(a.bindings)}`];
  return [
    ...a.values.map((v) => `  value      ${v.key} may go to ${hosts(v.bindings)}`),
    `  value      any other may go to ${hosts(a.fileBindings ?? [])}`,
    `  may go to  ${a.bindings.length ? a.bindings.join(", ") : "no host"}, for a program holding the whole file (where every value may go)`,
  ];
}

export interface WhyPathAnswer {
  path: string; axis: boolean; level: string; rule: string | null; bindings: string[];
  /** Plan 13 §5.2: per-value bindings and the file's own; `bindings` is
   *  then the whole file's. Absent from an older arbiter or with no `values:`. */
  values?: Array<{ key: string; bindings: string[] }>; fileBindings?: string[];
  outranked: Array<{ path: string; level: string }>; readers: unknown[]; others: string | null;
  /** Plan 13 §8 decision (b): per reader entry, it admits nothing (a shell or
   *  an interpreter with no `script:` pin). Absent from an older arbiter. */
  readersAdmitNothing?: boolean[];
  /** Plan 13 D8 (2026-10-03): per reader entry, it names a printer (cat,
   *  head, cp, …), which admits nothing in any form. Absent from an older
   *  arbiter. */
  readersPrint?: boolean[];
  /** 2026-10-03: per reader entry, the installed program a pin's hash is
   *  byte for byte (a renamed copy of a printer or an interpreter), else
   *  null. Absent from an older arbiter. */
  readersCopyOf?: Array<string | null>;
  consumers: string[]; wire: { served: boolean; why: string } | null; twinShape: string | null;
  /** 2026-10-09: the twin the arbiter makes of the file as it is now (its
   *  form, the shape, and how many values it masks). Absent from an older
   *  arbiter, or when the file cannot be read: `twinShape` (by the path
   *  alone) is the fallback. */
  twin?: { form: "structured" | "own-text" | "whole-file"; shape: string | null; fields: number };
  /** Plan 13 D8 and §4.9 (2026-10-04): per `consumers` entry, it prints
   *  (curl, scp, git), so it is no default reader. Absent from an older
   *  arbiter. */
  consumersPrint?: boolean[];
  /** Plan 10 §11.13.3: the commands an ssh config's twin withholds, by
   *  line and keyword (never their text). Absent from an older arbiter. */
  withheld?: Array<{ line: number; keyword: string }>;
  /** `exe`: the binary the verdict is for (Plan 13 D8), when the row names
   *  one. `kind`: a held open, or a held change to a file that runs later
   *  (write-protection.md §2.1); absent = open (an older arbiter). */
  /** Plan 13 §8 decision (c): `script`, the script an interpreter's answer
   *  names; `run`, an answer about one run of an interpreter running no
   *  pinned script; `stale`, an answer naming an interpreter alone (written
   *  before the decision), which applies to nothing. Plan 13 D8
   *  (2026-10-03): `printer`, an open answer about a program that prints
   *  the file, which applies to nothing and is never asked again. */
  verdicts: Array<{ kind?: "open" | "write"; app: string; exe?: string; status: string; scope: string; script?: string; run?: boolean; stale?: boolean; printer?: boolean }>;
  /** First-session tour item 17: changes waiting in Approvals that would
   *  change this answer (absent from an older arbiter). */
  pending?: WhyPending[];
  /** An AI agent's own file (secret-discovery.md §1.10): one of its login
   *  files, or its own data. Absent: neither, or an older arbiter. */
  agentFile?: { kind: "login" | "store"; agent: string };
  /** Plan 10 §11.13 (2026-10-17): the running session whose HOME the
   *  answer judged the path under as well (`--session`'s, else the newest
   *  running one); `home: null`, the named session is not running. Absent
   *  from an older arbiter or with no running session. */
  launch?: { session: string; home: string | null; newest: boolean };
}
/** A narrow mirror of the arbiter's `WhyPendingChange` (protocol.ts). */
export interface WhyPending {
  id: string;
  from: "file" | "agent" | "scan" | "other";
  level?: string;
  bindings?: string[];
  rule?: string | null;
}
export interface WhyHostAnswer {
  host: string; axis: boolean;
  bound: Array<{ path: string; level: string; binding: string[]; source: string }>;
  release: { bound: Decided | null; unbound: Decided | null };
  destinations: Array<{ host: string; port: number | "*"; proto: string; connect: string; reason?: string }>;
  verdicts: Array<{ symbol: string; status: string; scope: string }>;
  pending?: WhyPending[];
  issuer?: { id: string; name: string; shapes: string[]; on: boolean };
}
interface Decided { decision: { allow: boolean; requiresApproval?: boolean; reason?: string; ruleRef?: { id?: string } }; stage: string }

/** A narrow mirror of the arbiter's `WhySymbolOpResult`
 *  (arbiter/prompt-filter/why-symbol.ts): the fields the CLI reads. */
export interface WhySymbolAnswer {
  symbol: string; axis: boolean; known: boolean;
  source: "prompt-filter" | "side-call" | "secret" | "other" | "unknown";
  level: string | null; tool: string | null; origin: string | null; field: string | null;
  session: string | null; createdAt: number | null; obsolete: boolean;
  findings: Array<{
    session: string; firstTs: string | null; lastTs: string | null; turn: number | null; requests: number;
    agent: string; origin: "human" | "harness" | "side-call"; filterId: string; category: string; action: string;
    segmentAction: "pass" | "rewrite" | "block"; hold?: { state: string; approvalId?: string }; let?: "once" | "session";
    enforcing: boolean; ref?: string; turnRef?: string;
  }>;
  verdicts: Array<{ approvalId: string; session: string; category: string; scope: "message" | "session"; status: "pending" | "approved" | "denied"; resolvedAt: number | null }>;
  policy: Array<{ category: string; action: string; row: string | null; setBy: "default" | "you" | "administrator"; locked: { action: string; file?: string } | null; onceOnly?: { file?: string }; exceptions: number }>;
  filters?: Array<{ id: string; kind: "built-in" | "pack" | "plugin"; description?: string }>;
  searched: number;
}
/** The data plane's `symbolProvenance` (what the data socket gives today). */
interface SymbolProvenance { tool: string | null; field?: string | null }

export interface WhyDeps {
  arbiter: (env: Env, layout: Layout) => Promise<DryRunArbiter>;
  /** A fresh arbiter over the same law, for a resident one that predates `why`. */
  fresh: (env: Env, layout: Layout) => Promise<DryRunArbiter>;
  call: <T>(sock: string, op: string, args: Record<string, unknown>) => Promise<T>;
  exists: (p: string) => boolean;
  cwd: () => string;
  /** The human-plane socket the arbiter at `sock` names (`hello`), or null. */
  humanSock?: (sock: string) => Promise<string | null>;
  /** Where the command's report goes (default: process.stdout). Tests pass a
   *  collector: patching process.stdout.write swallows the test runner's own
   *  report, which shares the stream. */
  out?: (s: string) => void;
}

/** How `mandu why` finds an arbiter to ask (seams for the unit tests). */
export interface WhyArbiterIo {
  /** The resident arbiter answering `hello`, or null. */
  resident: (env: Env) => Promise<{ sock: string; axisOn: boolean | null } | null>;
  throwaway: (env: Env, layout: Layout, opts?: { seedFrom?: string }) => Promise<DryRunArbiter>;
  exists: (p: string) => boolean;
}

/** The store the resident arbiter keeps, where it keeps it by default
 *  (arbiter server-args.ts `resolveStorePaths`: the path table's `symbol-db`
 *  under `MANDU_HOME`, else `$HOME/.mandu`). */
export function residentStorePath(env: Env): string {
  return manduPath("symbol-db", env, env["HOME"] || homedir());
}

/**
 * The arbiter `mandu why` asks: the resident one; with its secrets axis off,
 * a throwaway (as `mandu doctor --secrets`); with none running, a throwaway
 * seeded read-only from the store the resident one keeps, so the answer
 * holds the remembered answers and the changes waiting in Approvals
 * (`seeded`). A store that is missing, unreadable or of another Mandu version
 * leaves the unseeded throwaway of before, and its notes.
 */
export async function whyArbiter(env: Env, layout: Layout, io: WhyArbiterIo = { resident: helloResident, throwaway: throwawayArbiter, exists: existsSync }): Promise<DryRunArbiter> {
  const r = await io.resident(env);
  if (r !== null && r.axisOn !== false) return { sock: r.sock, kind: "resident", axisOn: r.axisOn, stop: async () => {} };
  if (r !== null) return { ...(await io.throwaway(env, layout)), kind: "throwaway", axisOn: false };
  const store = residentStorePath(env);
  if (io.exists(store)) {
    try {
      return await io.throwaway(env, layout, { seedFrom: store });
    } catch {
      // The arbiter refused the seed (another version, unreadable): ask as before.
    }
  }
  return io.throwaway(env, layout);
}

export function realWhyDeps(): WhyDeps {
  return {
    arbiter: (env, layout) => whyArbiter(env, layout),
    fresh: throwawayArbiter,
    call: (sock, op, args) => ndjsonCall(sock, op, args, 10_000),
    exists: existsSync,
    cwd: () => process.cwd(),
    humanSock: (sock) => readArbiterHumanSock(sock),
  };
}

/** A placeholder as typed: `$MDU:tag[hex]` (quoted), `MDU:tag[hex]`, or the
 *  `:tag[hex]` an unquoted `$MDU` leaves after a shell expanded it (bash).
 *  Returns the complete `$MDU:` name, or null. */
export function parseSymbolArg(arg: string): string | null {
  const m = /^(?:\$?MDU)?:([a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[A-Za-z_][A-Za-z0-9_[\].]{0,255})?)$/.exec(arg.trim());
  return m ? `$MDU:${m[1]}` : null;
}

/** A host when it LOOKS like one and is not a file here; a placeholder when
 *  it is one; everything else is a path. */
export function whyTargetKind(arg: string, exists: (p: string) => boolean, cwd: string): "path" | "host" | "symbol" {
  if (parseSymbolArg(arg) !== null && !exists(join(cwd, arg))) return "symbol";
  if (arg.startsWith("/") || arg.startsWith("./") || arg.startsWith("../") || arg.startsWith("~") || arg.includes("/")) return "path";
  if (exists(join(cwd, arg))) return "path";
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:\d+)?$/i.test(arg) ? "host" : "path";
}

function absolute(arg: string, cwd: string, home: string): string {
  if (arg === "~") return home;
  if (arg.startsWith("~/")) return join(home, arg.slice(2));
  return isAbsolute(arg) ? resolve(arg) : resolve(cwd, arg);
}

/** Would a default launch's connect guard admit `host:port`? By name, the way
 *  the spec was written (the guard resolves a name at connect time). */
export function guardAdmits(specs: string[], host: string, port: number): string | null {
  for (const spec of specs) {
    const m = /^(?:(tcp|udp|any):)?(.+):(\d+|\*)$/.exec(spec);
    if (!m || m[1] === "udp") continue;
    const h = m[2]!.replace(/^\[|\]$/g, "");
    if ((m[3] === "*" || Number(m[3]) === port) && (h === "*" || h.toLowerCase() === host)) return spec;
  }
  return null;
}

const tilde = (p: string, home: string): string => (p === home || p.startsWith(home + "/") ? "~" + p.slice(home.length) : p);

/** Where a remembered answer is listed and removed: the Rules page. */
export const REMEMBERED_HINT = "it is listed under \"Where data may go\" on the dashboard's Rules page, where Remove makes Mandu ask again";

/** Where a held send is answered: the dashboard's Approvals page. */
export const APPROVE_HINT = "you answer it on the dashboard's Approvals page (`mandu dashboard`)";

/** One decision in plain words. The rule id stays (it is what `policy.yaml`
 *  and the dashboard name); the arbiter's internal reason text is left to
 *  --json. */
function decidedLine(d: Decided | null): string {
  if (!d) return "unavailable on this Mandu service";
  // A standing answer of yours decided (testFlow asks with the file's own
  // placeholders, tour 1): say so, and where it is removed.
  if (d.stage === "verdict") {
    const id = d.decision.ruleRef?.id ? ` (${d.decision.ruleRef.id})` : "";
    return d.decision.allow
      ? `released by your remembered answer${id}: the real value goes out; ${REMEMBERED_HINT}`
      : `blocked by your remembered answer${id}; ${REMEMBERED_HINT}`;
  }
  const rule = d.decision.ruleRef?.id ? ` (rule ${d.decision.ruleRef.id})` : "";
  if (d.decision.allow) return `released${rule}: the real value goes out`;
  if (d.decision.requiresApproval) return `held for your OK${rule}: ${APPROVE_HINT}`;
  return `blocked${rule}`;
}

/** A file level in the dashboard glossary's words (rule-words.ts TERMS),
 *  the level name kept in parentheses. */
function levelLine(level: string): string {
  if (level === "public") return "Not secret (public): the AI reads it as is";
  if (level === "any-model") return `Any AI, when it asks (${level}); it is sent only where a rule or your OK allows`;
  if (level === "local-model") return `Your own AI only (${level}); it is sent only where a rule or your OK allows`;
  return `No AI (${level})`;
}

/** The program an answer names (plan 13 §8 decision (c)): the binary, and
 *  the script an interpreter runs or the one run it was about. */
function programWords(v: WhyPathAnswer["verdicts"][number]): string {
  const binary = v.exe ?? v.app;
  return v.script !== undefined ? `${binary} running ${v.script}` : v.run ? `${binary} running its own code (that change only)` : binary;
}
function staleWords(v: WhyPathAnswer["verdicts"][number]): string {
  if (v.printer) return ` — no longer applies: ${v.app} prints the file to whatever reads its output, so it never gets the real file; you will not be asked again`;
  return v.stale ? " — no longer applies: it names the interpreter, not the script it runs; you will be asked again" : "";
}

/** What the agent sees in place of a secret file: the copy the arbiter
 *  makes of the file as it is now (2026-10-09). Until then the line said
 *  "each value is a placeholder" of every file whose path has a structured
 *  shape: a `.json` whose list values stayed raw, and one the arbiter in
 *  fact hid whole. An older arbiter sends no `twin`; then only the path's
 *  shape is known, and the words say what it depends on. */
export function twinWords(a: Pick<WhyPathAnswer, "twin" | "twinShape">): string {
  const t = a.twin;
  const whole = "a whole-file placeholder (one placeholder for the whole file)";
  if (t === undefined) {
    return a.twinShape
      ? `a placeholder copy that keeps the file's structure (${a.twinShape}) when Mandu recognizes a secret value in it, each secret value it recognizes a placeholder; otherwise ${whole}`
      : whole;
  }
  if (t.form === "structured") {
    return `a placeholder copy that keeps the file's structure (${t.shape}); each secret value Mandu recognizes is a placeholder (${t.fields} in the file now)`;
  }
  if (t.form === "own-text") return `the file as it is (${t.shape}): it holds no secret value Mandu recognizes`;
  // 2026-10-10: not "recognizes no secret value": a file whose only secret
  // Mandu recognizes is a list item (a URL's password in `args`) is hidden
  // whole too, since list items only add to a file whose keys gave one.
  return t.shape ? `${whole}: Mandu finds no secret value it can hide in place in this ${t.shape} file, so it hides all of it` : whole;
}

/** Plan 10 §11.13.3: the ssh commands the agent's copy leaves out, where,
 *  why, and the way out (ssh itself prints the short form when it meets
 *  one inside the agent). */
export function withheldLines(withheld: ReadonlyArray<{ line: number; keyword: string }>, file: string): string[] {
  if (withheld.length === 0) return [];
  const where = withheld.map((w) => `line ${w.line} (${w.keyword})`).join(", ");
  return [
    `  withheld   ${where}: programs the agent runs get this file without ${withheld.length === 1 ? "that command" : "those commands"}; ssh prints a notice there instead of running it`,
    "  why        Mandu cannot vouch for a command beyond plain ssh -W and the known relays (nc, socat, cloudflared, aws ssm, ...): its text may hold a secret, and running it would run code holding one",
    "  way out    use ProxyJump (or plain ssh -W) instead; or move the command into a script out of the agent's reach",
    `             and let ssh read the real file: in policy.yaml name ssh a reader of ${file} (readers: [ssh], others: twin;`,
    "             ssh then sends only to the hosts this file is bound to), and if the script opens a secret itself, pin it",
    "             with its interpreter as that secret's reader ({ app: bash, script: /absolute/path/of/the/script });",
    "             or run this ssh outside the agent",
  ];
}

/** Who a waiting change came from, in plain words. */
function pendingSource(p: WhyPending): string {
  if (p.from === "file") return "policy.yaml was changed on disk";
  if (p.from === "agent") return "your agent asked for it";
  if (p.from === "scan") return "Mandu's scan suggests it";
  return "asked for on the dashboard";
}

/** What a waiting change would make a file, in the words of `levelLine`. */
function pendingWould(p: WhyPending): string {
  if (p.level === undefined) return "";
  if (p.level === "public") return "; approved, the file is public (not a secret)";
  const what = p.level === "any-model" ? "a secret any AI may read when it asks"
    : p.level === "local-model" ? "a secret only your own AI may read" : "a secret no AI may read";
  const where = p.bindings && p.bindings.length ? `may go to ${p.bindings.join(", ")}` : "goes nowhere without your OK";
  return `; approved, the file is ${what} (${p.level}) and ${where}`;
}

/** Tour item 17: `mandu why` says when a change to the rule it shows waits
 *  for the human, and that the lines above stay in force until then. */
export function pendingLines(pending: readonly WhyPending[] | undefined, what: "file" | "host"): string[] {
  if (!pending || pending.length === 0) return [];
  const L = pending.map((p) =>
    `  waiting    a change to ${what === "file" ? "this file's rule" : "what may go to this host"} waits for your OK in Approvals (${p.id}: ${pendingSource(p)})${what === "file" ? pendingWould(p) : ""}`);
  L.push(`             ${APPROVE_HINT.replace(/^you /, "until you ")}, the lines above are what Mandu enforces`);
  return L;
}

/** `mandu why` on an agent's login file (secret-discovery.md §1.10): raw
 *  where that agent runs, a credential like any other everywhere else. */
export function agentLoginLines(agent: string): string[] {
  const name = agentDisplayName(agent);
  return [
    `  login      ${name}'s login. Left raw in a session that runs ${name} (${loginKeptWhere(agent)}), because the agent logs in`,
    "             with it: there programs read the real file, it may go to the agent's own services, and a command that names",
    "             this path is masked for the AI",
    "  elsewhere  in every other session it is masked like any credential file, as below; MANDU_OTHER_AGENT_LOGINS=raw leaves",
    "             it readable there too, for that agent started inside (its values still masked in what reaches the AI)",
  ];
}

/** `mandu why` on an agent's own data (secret-discovery.md §1.10): raw in
 *  every session; only a command naming the path is masked. */
export function agentStoreLines(agent: string): string[] {
  const name = agentDisplayName(agent);
  return [
    `  left raw   ${name}'s own data (its sessions, settings, tool outputs): left raw in every session, because the agent`,
    "             reads and writes it; programs the agent runs read it as it is, and its values are not registered",
    "  the AI     sees a placeholder for what a command that names this path prints (a tool's read of it asks first);",
    "             a program that reads it without naming it is not masked. MANDU_OTHER_AGENT_LOGINS does not apply: it is no login",
  ];
}

/** Plan 10 §11.13 (2026-10-17): which running session's HOME the answer
 *  also judged the path under (the files a `~/` rule names are that HOME's
 *  for the session's programs), when it is not the HOME `mandu why` runs
 *  with; or that the session asked about is not running. */
export function launchHomeLines(launch: WhyPathAnswer["launch"], home: string): string[] {
  if (launch === undefined) return [];
  if (launch.home === null) return [`  note       session ${launch.session} is not running on this Mandu service, so only your HOME (${home}) was used`];
  if (launch.home === home) return [];
  return [`  home       also judged under ${launch.home}, the HOME session ${launch.session} was started with${launch.newest ? " (the newest running session; for another, ask again with --session <id>)" : ""}`];
}

export function renderWhyPath(a: WhyPathAnswer, home: string, send?: { host: string; egress: Decided | null; answersUnknown?: boolean }): string {
  const L: string[] = [`${tilde(a.path, home)}`];
  // A held change to a file that runs later is decided whatever the
  // secrets axis says (write-protection.md §2.1): one line per binary, by
  // its path (the hash the verdict is keyed by is not shown).
  const changes = a.verdicts.filter((v) => v.kind === "write").map((v) => `  decided    ${programWords(v)} changing it: ${v.status} (${v.scope})${staleWords(v)}`);
  if (!a.axis) {
    L.push("  secrets protection is off on this Mandu service: nothing is masked (mandu mode secrets turns it on)");
    L.push(...changes);
    return L.join("\n") + "\n";
  }
  const why = a.rule === null ? "no catalog rule or label matched" : a.rule.startsWith("label:") ? `your label (${a.rule.slice(6)})`
    : a.rule.startsWith("derived:") ? `written by a session that held a secret (${a.rule.slice(8)})`
    // secret-discovery.md §1.10: a login a variable (CODEX_HOME, …) moved
    // out of the catalog's places is a login all the same.
    : a.rule.startsWith("agent-login:") ? `${agentDisplayName(a.rule.slice(12))}'s login file, where your environment moved it (${a.rule})`
    // secret-discovery.md §2.6, §2.7: the catalog's content tier.
    : a.rule === "content:personal-document" ? `Mandu read this file and found a personal document (a statement, a tax return, a lab report, household codes: ${a.rule}); the AI reads its labels, each value is a placeholder; a label of yours decides instead`
    : a.rule.startsWith("content:") ? `Mandu found a saved password or key in this config file (${a.rule}); a label of yours decides instead`
    : `the built-in catalog (${a.rule})`;
  L.push(`  level      ${levelLine(a.level)}`, `  because    ${why}`);
  L.push(...launchHomeLines(a.launch, home));
  for (const o of a.outranked) L.push(`  note       your label outranks the stricter pattern ${o.path} (${o.level})`);
  const agent = a.level !== "public" ? a.agentFile : undefined;
  if (agent?.kind === "store") {
    // An agent's own data (secret-discovery.md §1.10): raw in every session,
    // so no placeholder copy and no reader list apply.
    L.push(...agentStoreLines(agent.agent));
  } else if (a.level !== "public") {
    if (agent?.kind === "login") L.push(...agentLoginLines(agent.agent));
    L.push(`  the AI     sees ${twinWords(a)}`);
    const inert = a.readersAdmitNothing ?? [];
    const nameOf = (r: unknown): string => {
      if (typeof r === "string") return r;
      const o = r as { app?: string; path?: string; script?: string };
      return o.app !== undefined && o.script !== undefined ? `${o.app} running ${o.script}` : o.app ?? o.path ?? JSON.stringify(r);
    };
    const listed = a.readers.map((r, i) => `${nameOf(r)}${inert[i] === true ? " (admits nothing)" : ""}`);
    if (listed.length) L.push(`  readers    ${listed.join(", ")} (they read the real file; what they print is masked for the AI)`);
    // Plan 13 §8 decision (b): a shell or an interpreter named alone is no
    // reader; say what to write instead.
    // Plan 13 D8 (2026-10-03): a printer is no reader in any form.
    const prints = a.readersPrint ?? [];
    // 2026-10-03: a pin whose hash is an installed printer's or interpreter's
    // (a renamed copy) is that program; say which.
    const copyOf = a.readersCopyOf ?? [];
    a.readers.forEach((r, i) => {
      const of = copyOf[i];
      if (inert[i] !== true || typeof of !== "string") return;
      L.push(prints[i] === true
        ? `  note       ${nameOf(r)} is a copy of ${of} (byte for byte, by its sha256), which prints the file to whatever reads its output (which can be the agent's own code), so no program reads the file through that entry; name the program that uses the secret instead (e.g. pg_dump, aws)`
        : `  note       ${nameOf(r)} is a copy of ${of} (byte for byte, by its sha256), which runs any code given to it, so no program reads the file through that entry, whatever its name; name the program that needs the file, or pin a script of your own with ${of}: { app: ${of}, script: /absolute/path/of/the/script }`);
    });
    const plain = (i: number): boolean => inert[i] === true && typeof copyOf[i] !== "string";
    const printers = a.readers.filter((_, i) => plain(i) && prints[i] === true).map(nameOf);
    if (printers.length) L.push(`  note       ${printers.join(", ")} ${printers.length === 1 ? "prints" : "print"} the file to whatever reads ${printers.length === 1 ? "its" : "their"} output (which can be the agent's own code), so no program reads the file through ${printers.length === 1 ? "that entry" : "those entries"}, pinned or not; name the program that uses the secret instead (e.g. pg_dump, aws)`);
    const dead = a.readers.filter((_, i) => plain(i) && prints[i] !== true).map(nameOf);
    if (dead.length) L.push(`  note       ${dead.join(", ")} ${dead.length === 1 ? "runs" : "run"} any code given to ${dead.length === 1 ? "it" : "them"}, so no program reads the file through ${dead.length === 1 ? "that entry" : "those entries"}, inline code (${dead[0]} -c …) included; name the program that needs the file, or pin a script of your own with its interpreter: { app: ${dead[0]}, script: /absolute/path/of/the/script }`);
    if (listed.length) { /* the list above */ }
    else if (a.consumers.length) {
      // Plan 13 D8 and §4.9 (2026-10-04): a usual program that prints (curl
      // for .netrc, git for .git-credentials) is no default reader; it gets
      // the placeholder copy (an older arbiter sends no `consumersPrint`).
      const prints = a.consumersPrint ?? [];
      const raw = a.consumers.filter((_, i) => prints[i] !== true);
      const printing = a.consumers.filter((_, i) => prints[i] === true);
      L.push(raw.length
        ? `  readers    none listed; its usual programs read it by default: ${raw.join(", ")}`
        : "  readers    none listed; none of its usual programs reads it by default");
      if (printing.length) L.push(`  note       ${printing.join(", ")} ${printing.length === 1 ? "prints the files it is pointed at, so it gets" : "print the files they are pointed at, so they get"} the placeholder copy too, never the real file`);
    }
    else L.push("  readers    none: every program the agent runs gets the placeholder copy");
    L.push(`  others     ${a.others === "deny" ? "programs not listed are refused" : a.others === "ask" ? `programs not listed are held for your OK (${APPROVE_HINT})` : "programs not listed get the placeholder copy"}`);
    L.push(...withheldLines(a.withheld ?? [], tilde(a.path, home)));
    if (a.wire) L.push(`  over HTTPS ${a.wire.served ? "a placeholder these programs send is put back at a bound host" : `these programs need the real file (${a.wire.why})`}`);
    L.push(...mayGoLines(a));
    for (const v of a.verdicts) if (v.kind !== "write") L.push(`  decided    ${programWords(v)} opening it: ${v.status} (${v.scope})${staleWords(v)}`);
  }
  L.push(...changes);
  if (send) L.push(`  send to ${send.host}: ${decidedLine(send.egress)}`);
  if (send?.answersUnknown) L.push("  note       no Mandu service is running here, so your remembered answers were not consulted (they are kept by the running one)");
  L.push(...pendingLines(a.pending, "file"));
  return L.join("\n") + "\n";
}

export function renderWhyHost(a: WhyHostAnswer, home: string, reach: { spec443: string | null }): string {
  const L: string[] = [a.host];
  L.push(`  reachable  ${reach.spec443 ? `yes on :443 (guard rule ${reach.spec443}${reach.spec443 === "tcp:*:443" ? ", the default any-host HTTPS rule" : ""})` : "not on :443 in a default launch"}`);
  for (const d of a.destinations) L.push(`  rule       ${d.connect} ${d.proto}:${d.host}:${d.port}${d.reason ? ` (${d.reason})` : ""}`);
  if (!a.axis) {
    L.push("  secrets protection is off on this Mandu service: no secret is held back");
    return L.join("\n") + "\n";
  }
  if (a.bound.length) for (const b of a.bound) L.push(`  bound      ${tilde(b.path, home)} (${b.level === "any-model" ? "any AI may read it when it asks" : b.level === "local-model" ? "only your own AI may read it" : "no AI may read it"}, from ${b.source === "label" ? "your label" : "Mandu's secret list"})`);
  else L.push("  bound      no secret may be sent here");
  if (a.issuer) {
    L.push(a.issuer.on
      ? `  issuer     ${a.issuer.name}'s API host: a key in ${a.issuer.name}'s format (${a.issuer.shapes.join(", ")}) from your files or environment is sent here without asking, in the Authorization header over HTTPS only (issuer_bindings in policy.yaml turns it off)`
      : `  issuer     ${a.issuer.name}'s API host: sending a ${a.issuer.name} key here asks you first (issuer_bindings is off for it in policy.yaml)`);
  }
  L.push(`  a bound secret sent here:     ${decidedLine(a.release.bound)}`);
  L.push(`  an unbound secret sent here:  ${decidedLine(a.release.unbound)}`);
  for (const v of a.verdicts) L.push(`  decided    ${v.symbol}: ${v.status} (${v.scope})`);
  L.push(...pendingLines(a.pending, "host"));
  return L.join("\n") + "\n";
}

// ── `mandu why '$MDU:…'` (plan 15 §13.8) ─────────────────────────────────────

/** Where the dashboard lets a finding through (dashboard.md §4.31). */
export const LET_THROUGH_HINT = "on the dashboard (`mandu dashboard`): the note under your message in the session's conversation,\n             for that message or the rest of the session";
/** The same under a locked administrator's `ask` row: that message only. */
export const LET_THROUGH_HINT_ONCE = "on the dashboard (`mandu dashboard`): the note under your message in the session's conversation,\n             for that message only";

/** A category in plain words, the category kept in parentheses. */
export function categoryWords(category: string): string {
  const words = (): string | null => {
    if (category === "secret.registered" || category.startsWith("secret.registered.")) return "a secret Mandu already holds";
    if (category === "secret.shape") return "something shaped like a key or password";
    if (category.startsWith("secret.shape.")) return `something shaped like a key or password (${category.slice(13)})`;
    if (category === "agent-flow") return "text from a program that holds a secret";
    if (category === "pii.email" || category.startsWith("pii.email.")) return "an email address";
    if (category === "pii.payment-card" || category.startsWith("pii.payment-card.")) return "a payment card number";
    if (category === "pii.phone" || category.startsWith("pii.phone.")) return "a phone number";
    if (category === "pii.person" || category.startsWith("pii.person.")) return "a person's name";
    if (category === "pii" || category.startsWith("pii.")) return "personal data";
    return null;
  };
  const w = words();
  return w === null ? category : `${w} (${category})`;
}

/** The filter that found it, in plain words. */
export function filterWords(id: string, filters: WhySymbolAnswer["filters"] = []): string {
  if (id === "registered-value") return "the registered-value filter (the secrets Mandu already holds)";
  if (id === "key-shapes") return "the key-shapes filter (credentials by their format)";
  if (id === "agent-flow") return "the side-call rule (text from a program that holds a secret)";
  const f = filters.find((x) => x.id === id);
  const what = f?.kind === "plugin" ? "the plugin" : "the pack";
  return `${what} ${id}${f?.description ? ` ("${f.description}")` : ""}`;
}

type SymbolFinding = WhySymbolAnswer["findings"][number];

/** What happened to the span, in plain words. */
export function findingOutcome(f: SymbolFinding): string {
  if (f.let === "once") return "you let it through as written, for that message";
  if (f.let === "session") return "you let it through as written, for the rest of the session";
  if (!f.enforcing) return "logged only (secrets protection was off)";
  if (f.action === "ask") {
    switch (f.hold?.state) {
      case "pending": return "held for your answer: the message waits in the dashboard's Inbox (Approvals)";
      case "sent": return "held for your answer; you answered: send it as written";
      case "masked": return "held for your answer; you answered: send it masked (this placeholder)";
      case "cancelled": return "held for your answer; you cancelled the message: nothing was sent";
      case "timed-out": return "held for your answer; no answer came in time, so it went masked (this placeholder)";
      default: return "sent masked (this placeholder) without asking: the request could not wait, or no session to ask in";
    }
  }
  if (f.action === "mask") return "hidden: the AI read this placeholder in its place";
  if (f.action === "block") return f.segmentAction === "block" ? "blocked: the message was refused and nothing was sent" : "blocked earlier; resent without it";
  if (f.action === "redact") return "removed: the AI read [redacted: <category>]";
  return f.action;
}

function when(ts: string | null): string {
  return ts === null ? "" : ts.replace("T", " ").replace(/\.\d+Z$|Z$/, " UTC");
}

function setByWords(p: WhySymbolAnswer["policy"][number]): string {
  if (p.locked) return `locked by your administrator${p.locked.file ? ` (${p.locked.file})` : ""}`;
  if (p.setBy === "you") return `your policy.yaml (prompt_filters.actions.${p.row})`;
  if (p.setBy === "administrator") return "your administrator's default (you may change it)";
  return p.row === null ? "the default for a category no row names" : "the built-in default";
}

function verdictWords(v: WhySymbolAnswer["verdicts"][number]): string {
  const scope = v.scope === "message" ? "that message" : "the rest of the session";
  const what = v.status === "pending" ? "waiting for your answer in the Inbox"
    : v.status === "approved" ? "goes as written (your answer)" : "goes masked (your answer)";
  return `for ${scope}: ${what}`;
}

/** The line that offers `--session` when no finding was found: the answer
 *  searched the placeholder's own session and the most recent ones (at most
 *  24, arbiter why-symbol.ts WHY_SYMBOL_MAX_SESSIONS), so a message in an
 *  older session is missed unless named. */
function sessionHint(a: WhySymbolAnswer): string {
  return `             searched ${a.searched} session${a.searched === 1 ? "" : "s"} for a message that carried it; for a message in another session, ask again with --session <id> (the dashboard lists your sessions)`;
}

/** Plain words for `mandu why '$MDU:…'`. Never a value (the answer holds none).
 *  `opts.session`: the `--session` the person named (it was searched first). */
export function renderWhySymbol(a: WhySymbolAnswer, home: string, opts: { session?: string } = {}): string {
  const L: string[] = [a.symbol];
  if (!a.axis) L.push("  note       secrets protection is off on this Mandu service: the prompt filter only records (mandu mode secrets turns it on)");
  // A named session with no finding in it: the arbiter searches only a
  // session it has, so say both readings.
  if (opts.session !== undefined && !a.findings.some((f) => f.session === opts.session)) {
    L.push(`  note       no finding names this placeholder in session ${opts.session} (or this Mandu service has no such session)`);
  }
  if (!a.known && a.findings.length === 0) {
    L.push("  unknown    this Mandu service holds no such placeholder: it may come from another machine or a deleted session, or be mistyped");
    L.push("             (quote it whole: mandu why '$MDU:tag[1a2b]')");
    if (opts.session === undefined) L.push(sessionHint(a));
    return L.join("\n") + "\n";
  }
  const findings = a.findings.filter((f) => f.origin === "human");
  const other = a.findings.filter((f) => f.origin !== "human");
  const registered = a.source === "secret" || a.findings.some((f) => f.filterId === "registered-value" || f.category === "secret.registered" || f.category.startsWith("secret.registered."));
  const secretWhere = a.source === "secret" && a.origin
    ? (a.origin.startsWith("env:") ? `the environment variable ${a.origin.slice(4)}` : `${tilde(a.origin, home)}${a.field ? ` (${a.field})` : ""}`)
    : null;
  if (findings.length > 0) {
    L.push(registered
      ? `  what       a secret Mandu already holds was in your own message to the AI; the AI read this placeholder in its place`
      : "  what       part of your own message to the AI was hidden from it; the AI read this placeholder in its place");
    L.push("             (the original stays in your own terminal; Mandu does not show it here)");
  } else if (other.length > 0) {
    L.push(`  what       text your agent added on its own (${other[0]!.origin === "side-call" ? "a side call, such as a title request" : "reminders, project instructions"}) was hidden from the AI; it read this placeholder`);
  } else if (a.source === "prompt-filter") {
    L.push("  what       the prompt filter hid part of a message to the AI behind this placeholder (no record of the message was found: its session log is gone, or it is not among the sessions searched)");
  } else if (a.source === "side-call") {
    L.push("  what       a side call of your agent came from a program that holds a secret; Mandu hid its text whole behind this placeholder");
  } else if (a.source === "secret") {
    L.push(`  what       not from the prompt filter: a secret Mandu holds, ${secretWhere ?? "registered by a launch"}`);
  } else {
    L.push(`  what       not from the prompt filter: data a program gave the AI (${a.tool ?? "unknown"}), at level ${a.level ?? "unknown"}`);
  }
  // No finding: it may be in a session the search did not reach.
  if (a.findings.length === 0 && opts.session === undefined) L.push(sessionHint(a));
  if (secretWhere && findings.length + other.length > 0) L.push(`  secret     ${secretWhere}`);
  if (a.obsolete) L.push("  note       this placeholder is no longer in use (its value changed)");
  for (const f of a.findings) {
    L.push(`  found by   ${filterWords(f.filterId, a.filters)}`);
    L.push(`  category   ${categoryWords(f.category)}`);
    L.push(`  action     ${f.action}: ${findingOutcome(f)}`);
    // The event's turn is the proxy's 0-based model-request index.
    const turn = f.turn !== null ? `, model request ${f.turn + 1}` : "";
    const resent = f.requests > 1 ? `; carried again by ${f.requests - 1} later request${f.requests === 2 ? "" : "s"} (your agent resends the conversation)` : "";
    L.push(`  session    ${f.session}${turn}${f.firstTs ? `, ${when(f.firstTs)}` : ""}${resent}`);
  }
  for (const v of a.verdicts) L.push(`  answer     ${categoryWords(v.category)} ${verdictWords(v)}`);
  for (const p of a.policy) L.push(`  policy now ${p.category}: ${p.action} (${setByWords(p)})${p.exceptions > 0 ? `; ${p.exceptions} exception${p.exceptions === 1 ? "" : "s"} in force` : ""}`);
  // The ways out: never in band (a phrase in the prompt), never from here.
  if (registered) {
    L.push("  way out    the prompt filter never lets a secret Mandu holds through as written; it may still go where that secret's rule allows");
    if (a.source === "secret" && a.origin?.startsWith("/")) L.push(`             (mandu why ${tilde(a.origin, home)} says who may read it and where it may go)`);
    return L.join("\n") + "\n";
  }
  const cats = [...new Set(a.findings.filter((f) => f.origin === "human").map((f) => f.category))];
  if (cats.length === 0) return L.join("\n") + "\n";
  const locked = a.policy.filter((p) => cats.includes(p.category) && p.locked !== null && p.locked.action !== "ask");
  if (locked.length > 0) {
    for (const p of locked) L.push(`  way out    none here: your administrator set ${p.category} to ${p.locked!.action} and locked it${p.locked!.file ? ` (${p.locked!.file})` : ""}; ask them`);
    return L.join("\n") + "\n";
  }
  const cat = cats[0]!;
  // A locked administrator's `ask` row (plan 15 §12, 2026-10-04): one
  // message at a time, never the rest of the session (the arbiter refuses a
  // session answer). An older arbiter sends no `onceOnly`; a locked `ask`
  // that decides the action still says so.
  const once = a.policy.find((p) => cats.includes(p.category) && (p.onceOnly !== undefined || p.locked?.action === "ask"));
  if (once) {
    const file = once.onceOnly?.file ?? (once.locked?.action === "ask" ? once.locked.file : undefined);
    L.push(`  way out    let it through: ${LET_THROUGH_HINT_ONCE}`);
    L.push(`             your administrator set ${once.category} to ask every time${file ? ` (${file})` : ""}, so it takes no answer for the rest of the session`);
  } else {
    L.push(`  way out    let it through: ${LET_THROUGH_HINT}`);
  }
  if (a.findings.some((f) => f.hold?.state === "pending")) L.push("             a message still held is answered in the Inbox (Approvals): send as written, send masked, or cancel");
  L.push(`             change what Mandu does with ${cat}: the dashboard's Settings › Prompt filters, or in policy.yaml`);
  L.push(`             prompt_filters: actions: { ${cat}: log } (only records it) or pass`);
  L.push(`             add an exception: Settings › Prompt filters, or prompt_filters: exceptions:`);
  L.push(`             [{ category: ${cat}, match: "<the text, * and ? as wildcards>" }]`);
  return L.join("\n") + "\n";
}

/** The data plane's answer (the human plane out of reach). */
export function renderSymbolProvenance(symbol: string, p: SymbolProvenance): string {
  const L: string[] = [symbol];
  if (p.tool === null) L.push("  unknown    this Mandu service holds no such placeholder");
  else if (p.tool === "prompt_filter") L.push("  what       Mandu's prompt filter made it: part of a message to the AI was hidden behind it");
  else if (p.tool === "side_call") L.push("  what       a side call of the agent was hidden whole behind it (it came from a program that holds a secret)");
  else L.push(`  what       made from data a program gave the AI (${p.tool})`);
  L.push("  note       which filter, the session and the message are shown only outside the agent: run mandu why in your own");
  L.push("             terminal (Mandu's human-plane socket is not reachable from here)");
  return L.join("\n") + "\n";
}

/** Tour item 17: a temporary service (no Mandu running here) reads
 *  policy.yaml as the file says, with none of what waits in Approvals: a
 *  change still waiting for your OK reads as if it were in force. */
export const THROWAWAY_NOTE =
  "mandu why: no Mandu service is running here, so this answer reads policy.yaml as it is on disk; a change in it that still waits for your OK in Approvals reads as if it were in force (start Mandu and ask again)\n";

/** No Mandu running, but its store read (`whyArbiter`'s seeded throwaway):
 *  the answer holds what the running service would, as of its next start. */
export const SEEDED_NOTE =
  "mandu why: no Mandu service is running here, so a temporary one answered from policy.yaml and what Mandu keeps (your remembered answers, the changes waiting in Approvals), as Mandu would enforce them when it starts\n";

/** The longest `--session` id sent (the arbiter ignores a longer hint). */
const MAX_SESSION_HINT = 256;

/** `mandu why <path|host|'$MDU:…'> [--to <host>] [--session <id>] [--json]`. 0 answered, 2 usage, 1 no arbiter. */
export async function runWhy(rest: string[], env: Env, layout: Layout, deps: WhyDeps = realWhyDeps()): Promise<number> {
  const out = deps.out ?? ((s: string) => { process.stdout.write(s); });
  const json = rest.includes("--json");
  const toAt = rest.indexOf("--to");
  const to = toAt >= 0 ? rest[toAt + 1] : undefined;
  const sessionAt = rest.indexOf("--session");
  const session = sessionAt >= 0 ? rest[sessionAt + 1] : undefined;
  const target = rest.filter((a, i) => !a.startsWith("--") && !(toAt >= 0 && i === toAt + 1) && !(sessionAt >= 0 && i === sessionAt + 1))[0];
  if (!target || (toAt >= 0 && (!to || to.startsWith("--"))) || (sessionAt >= 0 && (!session || session.startsWith("--") || session.length > MAX_SESSION_HINT))) {
    process.stderr.write("usage: mandu why <path|host|'$MDU:…'> [--to <host>] [--session <id>] [--json]\n");
    return 2;
  }
  const home = env["HOME"] ?? homedir();
  const cwd = deps.cwd();
  const kind = whyTargetKind(target, deps.exists, cwd);
  if (kind === "symbol") {
    if (to !== undefined) {
      process.stderr.write("mandu why: --to applies to a file, not to a placeholder\n");
      return 2;
    }
    return whySymbolCli(parseSymbolArg(target)!, json, env, layout, deps, out, home, session);
  }
  if (session !== undefined && kind !== "path") {
    process.stderr.write("mandu why: --session applies to a placeholder or a file, not to a host\n");
    return 2;
  }
  let arb: DryRunArbiter;
  try {
    arb = await deps.arbiter(env, layout);
  } catch (err) {
    process.stderr.write(`mandu why: cannot reach a Mandu service to ask (${(err as Error).message})\n`);
    return 1;
  }
  // A resident arbiter older than `why` answers "unknown op": ask a fresh one
  // over the same law (policy.yaml) and say so.
  const ask = async <T>(op: string, args: Record<string, unknown>): Promise<T> => {
    try {
      return await deps.call<T>(arb.sock, op, args);
    } catch (err) {
      if (!/unknown op/i.test((err as Error).message) || arb.kind !== "resident") throw err;
      await arb.stop();
      arb = await deps.fresh(env, layout);
      process.stderr.write("mandu why: the running protection service predates `mandu why`; asked a fresh one over the same policy (restart with `mandu stop` to update it)\n");
      return deps.call<T>(arb.sock, op, args);
    }
  };
  try {
    if (kind === "path") {
      const path = absolute(target, cwd, home);
      // Where this user's agents log in (CODEX_HOME, …): a moved login is
      // named as one (secret-discovery.md §1.10).
      const loginEnv = loginEnvOf(env);
      // Plan 10 §11.13 (2026-10-17): the running session whose HOME the
      // path is judged under as well (`--session`, else the arbiter's
      // newest launch). Only the human plane names a session's HOME, so a
      // resident arbiter is asked there first; walled off (inside the
      // agent's world) or an older arbiter, the data plane's answer.
      const pathArgs = { path, home, ...(Object.keys(loginEnv).length > 0 ? { loginEnv } : {}), ...(session !== undefined ? { session } : {}) };
      let a: WhyPathAnswer | null = null;
      const human = arb.kind === "resident" && deps.humanSock ? await deps.humanSock(arb.sock) : null;
      if (human !== null) {
        try {
          a = await deps.call<WhyPathAnswer>(human, "whyPath", pathArgs);
        } catch (err) {
          const e = err as NodeJS.ErrnoException;
          if (!/unknown op/i.test(e.message) && !(typeof e.code === "string" && UNREACHABLE.has(e.code))) throw err;
        }
      }
      a ??= await ask<WhyPathAnswer>("whyPath", pathArgs);
      if (session !== undefined && a.axis && a.launch === undefined) {
        process.stderr.write("mandu why: --session for a file is answered only outside the agent (Mandu's human-plane socket is not reachable from here, or the service predates it); judged by your HOME alone\n");
      }
      // The host as the network gate keys an answer on it: lowercase, no
      // port (the net-proxy asks with the request's host).
      const host = to?.toLowerCase().replace(/:\d+$/, "");
      const send = host
        ? {
            host,
            egress: (await ask<{ egress: Decided | null }>("testFlow", { source: { tool: "Read", origin: path }, destination: host })).egress,
            // An unseeded throwaway has its own, empty answer store.
            ...(arb.kind === "resident" || arb.seeded === true ? {} : { answersUnknown: true }),
          }
        : undefined;
      out(json ? JSON.stringify({ ...a, ...(send ? { send } : {}) }, null, 2) + "\n" : renderWhyPath(a, home, send));
      if (arb.kind !== "resident") process.stderr.write(arb.seeded === true ? SEEDED_NOTE : THROWAWAY_NOTE);
      return 0;
    }
    const host = target.toLowerCase().replace(/:\d+$/, "");
    const a = await ask<WhyHostAnswer>("whyHost", { host });
    const law = (await ask<{ specs: string[] }>("netConnectAllow", {})).specs;
    const specs = computeNetGuardSpecs({ targetProxyPort: 0, netProxyPort: null, ullmForwarderPort: null, apiHost: "api.anthropic.com", strict: false, extraAllow: law });
    const reach = { spec443: guardAdmits(specs, host, 443) };
    out(json ? JSON.stringify({ ...a, reach }, null, 2) + "\n" : renderWhyHost(a, home, reach));
    if (arb.kind !== "resident") process.stderr.write(arb.seeded === true ? SEEDED_NOTE : THROWAWAY_NOTE);
    return 0;
  } catch (err) {
    process.stderr.write(`mandu why: ${(err as Error).message}\n`);
    return 1;
  } finally {
    await arb.stop();
  }
}

/** Connection errors that mean "this socket is out of reach from here". */
const UNREACHABLE = new Set(["ENOENT", "ECONNREFUSED", "EACCES", "EPERM", "ENOTSOCK"]);

/** `mandu why '$MDU:…'`: the human plane's `whySymbol`, else the data
 *  plane's `symbolProvenance` with a note. Only a RESIDENT arbiter knows a
 *  placeholder (a throwaway one has its own, empty symbol table). */
async function whySymbolCli(symbol: string, json: boolean, env: Env, layout: Layout, deps: WhyDeps, out: (s: string) => void, home: string, session?: string): Promise<number> {
  let arb: DryRunArbiter;
  try {
    arb = await deps.arbiter(env, layout);
  } catch (err) {
    process.stderr.write(`mandu why: cannot reach a Mandu service to ask (${(err as Error).message})\n`);
    return 1;
  }
  try {
    if (arb.kind !== "resident") {
      process.stderr.write("mandu why: no Mandu service is running here; a placeholder is known only to the service that made it (start one with your agent, then ask again)\n");
      return 1;
    }
    const human = deps.humanSock ? await deps.humanSock(arb.sock) : null;
    if (human !== null) {
      try {
        // `--session`: the arbiter searches that session first (its hint).
        const a = await deps.call<WhySymbolAnswer>(human, "whySymbol", { symbol, ...(session !== undefined ? { session } : {}) });
        out(json ? JSON.stringify(a, null, 2) + "\n" : renderWhySymbol(a, home, session !== undefined ? { session } : {}));
        return 0;
      } catch (err) {
        const e = err as NodeJS.ErrnoException;
        if (/unknown op/i.test(e.message)) {
          process.stderr.write("mandu why: the running protection service predates `mandu why` for a placeholder (restart it with `mandu stop` to update it)\n");
          return 1;
        }
        if (!(typeof e.code === "string" && UNREACHABLE.has(e.code))) throw err;
        // Walled off (inside the agent's world): the data plane's answer.
      }
    }
    const p = await deps.call<SymbolProvenance>(arb.sock, "symbolProvenance", { symbol });
    const lean: SymbolProvenance = { tool: p.tool ?? null };
    out(json ? JSON.stringify({ symbol, ...lean, humanPlane: false }, null, 2) + "\n" : renderSymbolProvenance(symbol, lean));
    return 0;
  } catch (err) {
    process.stderr.write(`mandu why: ${(err as Error).message}\n`);
    return 1;
  } finally {
    await arb.stop();
  }
}
