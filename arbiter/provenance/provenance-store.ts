/**
 * provenance-store — arbiter-owned taint registry (origin provenance).
 *
 * Tables live in the SAME SQLite file as the symbol table (mirrors
 * EgressApprovalStore), so a arbiter restart keeps prior taint. Single-writer:
 * owned by the one arbiter process. See docs/design/integrity/fs-provenance.md.
 */
import Database, { type Statement } from "../db/sqlite.js";
import { existsSync, mkdirSync } from "fs";
import { dirname } from "path";
import { getSymbolDbPath } from "../symbol-table/symbol-table.js";
import { confidentialityRank, parseConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { execSignatureForArgv, isPayloadlessShellC, rootSignaturesOfArgv, shellPayload } from "../policy/exec-signature.js";
import { basename } from "../policy/exec-identifier.js";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS process_taint (
  proc_key    TEXT PRIMARY KEY,
  origin_host TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS process_lineage (
  -- child_key is PRIMARY KEY: a process has exactly one parent (fork/exec
  -- model). The FIRST edge recorded wins (plan 13 D7): a process's parent only
  -- changes by reparenting to a subreaper or init, so a later report can only
  -- be less true than an earlier one.
  child_key   TEXT PRIMARY KEY,
  parent_key  TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS file_taint (
  content_hash TEXT NOT NULL,
  path         TEXT NOT NULL,
  origin_host  TEXT NOT NULL,
  writer_proc  TEXT,
  session      TEXT,
  created_at   INTEGER NOT NULL,
  PRIMARY KEY (content_hash, path)
);
CREATE INDEX IF NOT EXISTS idx_file_taint_path ON file_taint(path);
CREATE INDEX IF NOT EXISTS idx_file_taint_hash ON file_taint(content_hash);
-- Plan 10 §3.1: the CONFIDENTIALITY taint of a process that opened a secret
-- file raw. One row per (process, file); the level is the file's, the app is
-- the pinned reader that opened it (its output rule is looked up at fold time).
CREATE TABLE IF NOT EXISTS process_secret_taint (
  proc_key    TEXT NOT NULL,
  path        TEXT NOT NULL,
  level       TEXT NOT NULL,
  app         TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (proc_key, path)
);
CREATE INDEX IF NOT EXISTS idx_lineage_parent ON process_lineage(parent_key);
-- Plan 13 §9 R1 (and D2): a process that received another's bytes through a
-- descriptor (a pipe, a FIFO, a socket pair end, a connection to a holder's
-- listener), as the guard found it: it holds what \`from_key\` holds. Not a
-- lineage edge (the writer is not its parent; an edge would make every walk
-- through its real parents inherit). claimed = 1: reported over the data
-- socket (it only adds taint, so it is kept, as a claimed edge is).
CREATE TABLE IF NOT EXISTS process_flows (
  proc_key    TEXT NOT NULL,
  from_key    TEXT NOT NULL,
  session     TEXT,
  claimed     INTEGER,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (proc_key, from_key)
);
-- Plan 13 D9: lineage edges reported over the DATA socket, which the agent's
-- process tree reaches (a forger, an older guard, an exec box in the agent's
-- tree). Kept apart from the guard's edges so a claim never wins "first edge"
-- over the guard's: a claimed edge only ADDS a parent or a child to a walk
-- (more taint, never less), and is never read where more taint would let a
-- process read something raw (processSecretTaint's attestedOnly).
CREATE TABLE IF NOT EXISTS process_lineage_claims (
  child_key   TEXT NOT NULL,
  parent_key  TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (child_key, parent_key)
);
CREATE INDEX IF NOT EXISTS idx_lineage_claims_parent ON process_lineage_claims(parent_key);
-- Plan 13 D6 (a blind tunnel's chunks): secretTaintedProcesses walks the
-- flows forward, from the process whose bytes went out.
CREATE INDEX IF NOT EXISTS idx_process_flows_from ON process_flows(from_key);
-- Plan 10 §4.2: the root process of a tool call, so the proxy can ask for the
-- fold over that call's tree by callId.
-- Plan 10 §4.2: every exec the guard saw, by signature, so a tool call whose
-- root was never recorded by callId can be matched by its command text.
CREATE TABLE IF NOT EXISTS exec_roots (
  proc_key    TEXT PRIMARY KEY,
  signature   TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exec_roots_sig ON exec_roots(signature, created_at);
-- Plan 10 §11.8: opens the arbiter refused, so the tool result can say why.
CREATE TABLE IF NOT EXISTS secret_open_denials (
  proc_key    TEXT NOT NULL,
  path        TEXT NOT NULL,
  app         TEXT NOT NULL,
  reason      TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (proc_key, path)
);
-- Plan 10 §11.8 (2026-10-04): connections the egress proxy refused, by the
-- sending process, so the tool result can say so. A kind, never a host.
CREATE TABLE IF NOT EXISTS egress_refusals (
  proc_key    TEXT NOT NULL,
  kind        TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (proc_key, kind)
);
-- Plan 10 §11.8, "A refusal no process is tied to" (2026-10-17): a
-- connection the egress proxy refused and could tie to no process. A kind
-- and a time for the session, never a host and never a guessed process;
-- folded into every call of the session whose window (call_pending to
-- call_asked) holds it. One row per (session, kind) per span of calls:
-- recorded only when some outstanding call's window holds no row yet.
CREATE TABLE IF NOT EXISTS egress_refusals_unattributed (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  kind        TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_egress_refusals_unattributed ON egress_refusals_unattributed(session, kind, created_at);
-- Plan 10 §11.13: every exec's argv as the guard read it (exec_roots keeps
-- only the LAST signature per process), so a stdio MCP server's process can be
-- found by the command line the agent spawned it with.
CREATE TABLE IF NOT EXISTS exec_argv (
  proc_key    TEXT NOT NULL,
  parent_key  TEXT,
  argv        TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exec_argv_session ON exec_argv(session, argv);
-- execvp tries each PATH entry under one process: one row per (process, argv).
CREATE UNIQUE INDEX IF NOT EXISTS idx_exec_argv_once ON exec_argv(proc_key, argv);
CREATE TABLE IF NOT EXISTS call_roots (
  call_id     TEXT PRIMARY KEY,
  proc_key    TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL
);
-- Plan 13 D7, the call-root recorder. A candidate root: an exec by a direct
-- child of the agent (the guard's \`callRoot\`), one row per command signature
-- it can be the root of (exec-signature.ts rootSignaturesOfArgv).
CREATE TABLE IF NOT EXISTS call_root_candidates (
  proc_key    TEXT NOT NULL,
  signature   TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (proc_key, signature)
);
CREATE INDEX IF NOT EXISTS idx_call_root_candidates_sig ON call_root_candidates(signature, created_at);
-- 2026-10-04 (confidentiality.md §6): the directory a candidate root started
-- in, as the guard read it from the kernel (\`/proc/<pid>/cwd\`) while that
-- shell's exec was suspended. Kept from the human plane only. The directory
-- a bound call's relative path tokens are read in (callStartDir).
CREATE TABLE IF NOT EXISTS call_root_cwd (
  proc_key    TEXT PRIMARY KEY,
  cwd         TEXT NOT NULL
);
-- When the model proxy gated the call's tool_use (execGate with a callId):
-- the call's root cannot be older than that.
CREATE TABLE IF NOT EXISTS call_pending (
  call_id     TEXT PRIMARY KEY,
  session     TEXT,
  created_at  INTEGER NOT NULL
);
-- Plan 13 D9 follow-up: the command(s) the model proxy recorded for the call
-- on the human plane, by exec signature: \`gate\` (execGate with its callId,
-- the command as the model wrote it) and \`delivered\` (recordCallCommand, the
-- command as the agent received it, after the proxy's own rewrites: the view
-- map's path spelling, a block sentinel). callTaint binds the call by these,
-- never by the text the agent echoes back in its next request.
CREATE TABLE IF NOT EXISTS call_commands (
  call_id     TEXT NOT NULL,
  signature   TEXT NOT NULL,
  source      TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (call_id, source, signature)
);
-- When the proxy first asked for the call's result (callTaint with its
-- command): the call had run by then, so its root is no younger than that;
-- an exec reported later (a stray, or one forged over the agent-reachable
-- socket to clear a call already masked) never binds it.
CREATE TABLE IF NOT EXISTS call_asked (
  call_id     TEXT PRIMARY KEY,
  created_at  INTEGER NOT NULL
);
-- A call's root(s). kind: exact (the recorder found one candidate), shared
-- (several candidates matched: the call is folded over all of them), claimed
-- (recordCallRoot: a caller's statement, not evidence), guess (the most
-- recent exec of the command's signature: not evidence).
CREATE TABLE IF NOT EXISTS call_bindings (
  call_id     TEXT NOT NULL,
  proc_key    TEXT NOT NULL,
  kind        TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (call_id, proc_key)
);
CREATE INDEX IF NOT EXISTS idx_call_bindings_proc ON call_bindings(proc_key);
-- Plan 13 §4.5.1, the agent's own connection to a holder (decision
-- 2026-10-02: mask, do not refuse). The guard found the agent process itself
-- holding the other end of a connection a holder accepted (or held at its
-- taint): what the holder writes on it reaches the agent, which is never made
-- a holder (D2's exemption). One row per (channel, holder): \`channel\` is the
-- agent's socket (\`socket:[ino]\`); \`opened_at\` when the guard recorded it,
-- before the holder got the connection; \`closed_at\` when the guard saw the
-- agent no longer hold it (NULL: open, or never seen closed). A tool result
-- the agent itself produced (not a shell's, not a file tool's) during a call
-- whose window overlaps [opened_at, closed_at] is masked at the holders'
-- level. claimed = 1: reported over the data socket (it only adds masking).
CREATE TABLE IF NOT EXISTS agent_flows (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  channel     TEXT NOT NULL,
  from_key    TEXT NOT NULL,
  session     TEXT,
  claimed     INTEGER,
  opened_at   INTEGER NOT NULL,
  closed_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_agent_flows_channel ON agent_flows(channel, closed_at);
-- 2026-10-17 (confidentiality.md §6, "The base follows the shell"): a file
-- the AGENT process itself opened for reading (Claude Code's Read, Edit,
-- NotebookEdit read in the agent, not in a shell), as the guard saw the open
-- in the kernel: \`path\` the absolute path its descriptor names, kept only
-- when the file classifies above \`public\` and only from the human plane
-- (labelledLevel with agentOpen). A file tool's RELATIVE path is read at
-- each such file opened in its call's window that ends with it (raise-only:
-- callAgentOpens), so the base is the agent's real directory, wherever a
-- \`cd\` or EnterWorktree moved it.
CREATE TABLE IF NOT EXISTS agent_opens (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  path        TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_opens_session ON agent_opens(session, created_at);
-- When the model proxy first asked, on the human plane, about a call's result
-- for the agent-flow leg (agentReceiptTaint): the call had returned by then,
-- so the window it can have received in ends there. With call_pending (the
-- relay) it bounds the call's window; with callTaint's call_asked it says
-- which calls are still outstanding (a side call's window).
CREATE TABLE IF NOT EXISTS call_answered (
  call_id     TEXT PRIMARY KEY,
  session     TEXT,
  created_at  INTEGER NOT NULL
);
-- Plan 13 D7, the orphan subshell (2026-10-02): a process the guard saw act
-- (an exec, a secret open) whose live ancestors hold no agent process and
-- whose topmost ancestor was re-parented to a reaper after the agent started:
-- the ORPHAN ROOT of a tree whose real parent (some tool call's shell) exited
-- before any process of it acted, so no lineage edge links it to that call.
-- Its tree is folded into every call relayed no later than it was first seen
-- (any of them may have started it). claimed = 1: reported over the data
-- socket (it only widens a fold).
CREATE TABLE IF NOT EXISTS orphan_roots (
  proc_key    TEXT PRIMARY KEY,
  session     TEXT,
  claimed     INTEGER,
  first_seen  INTEGER NOT NULL
);
-- Plan 13 D7, a background poll tied to its call (2026-10-09): the model
-- proxy tied the poll \`poll_id\` (Claude Code's BashOutput / TaskOutput) to
-- the call \`call_id\` that started the task it polls, on the human plane. A
-- symbol minted for the poll's output (its own call id) is then evidence for
-- the value backstop when that call's tree held a secret. The first tie wins.
CREATE TABLE IF NOT EXISTS call_polls (
  poll_id     TEXT PRIMARY KEY,
  call_id     TEXT NOT NULL,
  session     TEXT,
  created_at  INTEGER NOT NULL
);
`;

/** Plan 13 §4.5.1 (2026-10-02): is an agent flow's channel file-like (a
 *  FIFO's path the agent read with its own file tool) rather than a socket
 *  (`socket:[ino]`)? A file tool's result counts only these. */
export function isFileChannel(channel: string): boolean {
  return !channel.startsWith("socket:[");
}

/** How a call's tree was found (plan 13 D7). `exact` and `shared` are the
 *  recorder's evidence; `claimed` and `guess` are not. */
export type CallBinding = "exact" | "shared" | "claimed" | "guess" | "none";

/** Is the tree evidence (the recorder bound the call to its root or roots)? */
export function bindingDetermined(b: CallBinding): boolean {
  return b === "exact" || b === "shared";
}

/** A directory as the kernel names it: absolute, no empty, `.` or `..`
 *  segment (a `/proc/<pid>/cwd` link of a removed directory, ` (deleted)`,
 *  or one outside the reader's root, `(unreachable)…`, is none). */
export function isCanonicalDir(d: unknown): d is string {
  if (typeof d !== "string" || !d.startsWith("/") || d.length > 4096 || d.includes("\0")) return false;
  if (d.endsWith(" (deleted)")) return false;
  if (d === "/") return true;
  return d.slice(1).split("/").every((s) => s !== "" && s !== "." && s !== "..");
}

/** How many opened files one relative value is read at (`callAgentOpens`). */
export const AGENT_OPENS_MAX = 16;

/** The part of a relative path value that must end an opened file's path:
 *  lexically normalized, past its leading `./` and `../` segments. null:
 *  absolute, home-relative, empty, or nothing left (`.`, `..`). Pure. */
export function relativeTail(value: string): string | null {
  const v = value.trim();
  if (v === "" || v.startsWith("/") || v.startsWith("~") || v.includes("\0")) return null;
  const segs: string[] = [];
  for (const seg of v.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (segs.length > 0 && segs[segs.length - 1] !== "..") segs.pop();
      else segs.push("..");
      continue;
    }
    segs.push(seg);
  }
  while (segs[0] === "..") segs.shift();
  return segs.length > 0 ? segs.join("/") : null;
}

export interface ProvenanceStoreOptions {
  /** Defaults to getSymbolDbPath() — the same file the symbol table uses. */
  dbPath?: string;
  /** The wall clock (ms) under the store's own clock (tests). Default
   *  `Date.now`. */
  wallClock?: () => number;
}

/** The store clock's least step (ms): a power of two, so the sums stay exact
 *  and a burst of a thousand records moves the clock under 1 ms ahead. */
export const STORE_CLOCK_STEP_MS = 1 / 1024;

/**
 * Every column the store stamps with its clock (`tick`), by table: the
 * floor a new store starts its clock above (plan 13 D7, 2026-10-17). A table
 * or a stamp column added to the schema is listed here too; a unit test
 * fails on a time column of the schema this list misses.
 */
export const STORE_STAMP_COLUMNS: ReadonlyArray<readonly [table: string, column: string]> = [
  ["process_taint", "created_at"],
  ["process_lineage", "created_at"],
  ["file_taint", "created_at"],
  ["process_secret_taint", "created_at"],
  ["process_flows", "created_at"],
  ["process_lineage_claims", "created_at"],
  ["exec_roots", "created_at"],
  ["secret_open_denials", "created_at"],
  ["egress_refusals", "created_at"],
  ["egress_refusals_unattributed", "created_at"],
  ["exec_argv", "created_at"],
  ["call_roots", "created_at"],
  ["call_root_candidates", "created_at"],
  ["call_pending", "created_at"],
  ["call_commands", "created_at"],
  ["call_asked", "created_at"],
  ["call_bindings", "created_at"],
  ["agent_flows", "opened_at"],
  ["agent_flows", "closed_at"],
  ["agent_opens", "created_at"],
  ["call_answered", "created_at"],
  ["orphan_roots", "first_seen"],
  ["call_polls", "created_at"],
];

export interface IsProcessTaintedResult {
  tainted: boolean;
  originHost?: string;
}

export interface FileTrustResult {
  untrusted: boolean;
  origin?: string;
}

/** Plan 10: one secret a process (or an ancestor) holds. */
export interface SecretTaintRow {
  procKey: string;
  path: string;
  level: string;
  app: string;
  /** Plan 13 D3: the opener's executable and its hash, and how the arbiter
   *  let it read (`reader` | `verdict`); absent on a row written without
   *  them, which `readerOutputRule` folds to `secret`. */
  exe?: string;
  sha256?: string;
  via?: "reader" | "verdict" | "session";
  /** Plan 13 R5: the script the interpreter ran and its hash, when the
   *  guard's facts would let a `script:` reader entry match it. */
  script?: string;
  scriptSha256?: string;
  /** The session the row was recorded in (a `session` row: the session
   *  whose reads it holds, confidentiality.md §4). */
  session?: string;
}

export interface ProcessSecretTaintResult {
  /** The strictest level over the process and its ancestors; null = untainted. */
  level: string | null;
  rows: SecretTaintRow[];
}

export interface CallTaintResult {
  /** The strictest level over every process in the call's tree; null = none. */
  level: string | null;
  /** Every (process, file, app) in the tree, for the fold and the story card. */
  rows: SecretTaintRow[];
  /** The root process, when the call was recorded. */
  root: string | null;
  /** Opens refused within the tree (plan 10 §11.8). */
  denied: Array<{ path: string; app: string; reason: string }>;
  /** Connections the egress proxy refused from a process of the tree (plan
   *  10 §11.8, "Refused connections"); absent when none. */
  refusedEgress?: Array<{ app: string; kind: string }>;
  /** Plan 10 §11.8, "Blocked commands": the command lines the exec-wrap
   *  shim was run with in the tree (`shimInvocationArgv` over the guard's
   *  argv records: `[command, ...arguments]`), for the arbiter to recompute
   *  the shim's verdict; absent when none. */
  shimExecs?: string[][];
  /** The subset of `shimExecs` the shim ran under Codex's own command
   *  sandbox with its network off (`codexSandboxNetworkOff` on the run's
   *  process or an ancestor): that sandbox refused the shim's connection,
   *  so there is no verdict to recompute. Absent when none. */
  codexSandboxShims?: string[][];
}

/** Plan 13 D7: callTaint with how the tree was found. */
export interface CallTreeResult extends CallTaintResult {
  /** Every root the call is folded over (one unless `shared`). */
  roots: string[];
  binding: CallBinding;
}

/** Plan 13 §4.5.1: how one call's agent receipt is asked about. */
export interface AgentReceiptOpts {
  session?: string;
  /** A data-socket ask: reads with `now` as the window's end, records nothing. */
  readOnly?: boolean;
  /** A tool this leg does not cover: only its first ask is recorded. */
  recordOnly?: boolean;
  channels?: "all" | "file";
}

/** Plan 13 §4.5.1: the level the agent's own connections mask a call's result at. */
export interface AgentReceipt {
  level: string | null;
  rows: SecretTaintRow[];
  flows: number;
  relayKnown: boolean;
}

/** The exec-wrap shim's entry, as the launcher runs it (layout.execShim):
 *  the checkout's `interceptors/exec-wrap/src/wrap.ts` under tsx, or the
 *  bundle's `exec-shim.mjs` under node. */
const SHIM_ENTRY_RE = /(?:^|\/)(?:interceptors\/exec-wrap\/src\/wrap\.ts|exec-shim\.mjs)$/;

/**
 * Plan 10 §11.8, "Blocked commands": the command line an exec of the
 * exec-wrap shim stood in for, from the argv the guard recorded for it, or
 * null when the argv is not the shim's. The shim script runs `exec -a <cmd>
 * <runtime…> <entry> "$@"` (launcher services/exec-shims.ts), so the
 * kernel's argv is `[<cmd>, <runtime flags…>, <entry>, <the arguments…>]`
 * and the shim judges `[<cmd>, <the arguments…>]` (exec-wrap wrap.ts). Pure.
 */
export function shimInvocationArgv(argv: readonly string[]): string[] | null {
  if (argv.length < 2 || typeof argv[0] !== "string" || argv[0] === "") return null;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (typeof a !== "string") return null;
    if (SHIM_ENTRY_RE.test(a)) return [argv[0], ...argv.slice(i + 1).map(String)];
    // Only runtime flags come before the entry (node's `--import <url>`,
    // `--no-warnings=…`); anything else means the entry is an argument.
    if (!a.startsWith("-") && argv[i - 1] !== "--import") return null;
  }
  return null;
}

/** An exec_argv row's argv, or null when it is not a JSON list of strings. */
function parseArgv(text: string): string[] | null {
  try {
    const a = JSON.parse(text) as unknown;
    return Array.isArray(a) && a.every((x) => typeof x === "string") ? (a as string[]) : null;
  } catch {
    return null;
  }
}

/** Push `argv` into `into` unless an equal one is there. */
/** The rows that mask what the model gets back: all but a HIGH session's
 *  own rows (`via: "session"`, `taintProcessSession`), whose content the
 *  model already read into its context (confidentiality.md §4). */
export function modelVisibleRows<T extends { via?: string }>(rows: readonly T[]): T[] {
  return rows.filter((r) => r.via !== "session");
}

function addArgv(into: string[][], argv: string[]): void {
  const key = JSON.stringify(argv);
  if (!into.some((x) => JSON.stringify(x) === key)) into.push(argv);
}

/**
 * Plan 10 §11.8, "Blocked commands" (2026-10-09): is this argv Codex's own
 * command-sandbox helper with the sandbox's network OFF? Codex runs every
 * sandboxed command through `codex-linux-sandbox` (its own binary under that
 * name; the first exec of the helper's process is `/proc/self/exe
 * --codex-run-as-process-setup … codex-linux-sandbox …`), with the policy as
 * JSON in `--permission-profile`, whose `network` is `"restricted"` or
 * `"enabled"` (read off codex-cli 0.159.1, 0.160.0 and 0.162.0; the e2e passes on 0.144.1 too). With it
 * restricted, the helper's seccomp filter refuses every `connect`, Unix
 * sockets included (supported-agents.md §6.4), so the exec-wrap shim under
 * it cannot reach the arbiter. Anything else (no helper, the network
 * enabled, a policy that does not parse, an older Codex's `--sandbox-policy`
 * form, which was not measured) is false. Pure.
 */
export function codexSandboxNetworkOff(argv: readonly string[]): boolean {
  const at = argv.findIndex((a) => typeof a === "string" && (a === "codex-linux-sandbox" || a.endsWith("/codex-linux-sandbox")));
  if (at < 0) return false;
  for (let i = at + 1; i < argv.length; i++) {
    const a = argv[i];
    if (typeof a !== "string" || a === "--") return false;
    const json = a === "--permission-profile" ? argv[i + 1] : a.startsWith("--permission-profile=") ? a.slice("--permission-profile=".length) : undefined;
    if (json === undefined) continue;
    try {
      const p = JSON.parse(String(json)) as unknown;
      return typeof p === "object" && p !== null && (p as { network?: unknown }).network === "restricted";
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Plan 13 D7, Codex under its own sandbox (2026-10-09): is this argv Codex's
 * command-sandbox helper as the agent starts it? Codex runs each sandboxed
 * command through its own binary under the name `codex-linux-sandbox`
 * (0.144.1: argv[0] `codex-linux-sandbox`; 0.159 to 0.162 the same, after a
 * first exec of `/proc/self/exe --codex-run-as-process-setup …`). Pure.
 */
export function isCodexSandboxHelperArgv(argv: readonly string[]): boolean {
  return argv.some((a) => typeof a === "string" && (a === "codex-linux-sandbox" || a.endsWith("/codex-linux-sandbox") || a === "--codex-run-as-process-setup"));
}

/** A step of that sandbox's plumbing between the helper and the command's
 *  shell: the helper (also as its re-exec inside bubblewrap,
 *  `… --apply-seccomp-then-exec -- …`, 0.144.1) or bubblewrap itself. Pure. */
export function isCodexSandboxPlumbingArgv(argv: readonly string[]): boolean {
  if (argv.length === 0) return false;
  return isCodexSandboxHelperArgv(argv) || argv.includes("--apply-seccomp-then-exec") || basename(argv[0]!) === "bwrap";
}

/** Codex's shell-snapshot preamble (`<shell> -c '<snapshot …> exec <shell>
 *  -c <command>'`): a payload naming Codex's snapshot variables, or a shell
 *  `-c` whose payload the guard's per-element bound cut off. Pure. */
export function isCodexSnapshotPreambleArgv(argv: readonly string[]): boolean {
  if (isPayloadlessShellC(argv)) return true;
  const p = shellPayload(argv);
  return p !== null && p.includes("__CODEX_SNAPSHOT_");
}

/** What `codexSandboxCommandShell` found under a helper. */
export type CodexSandboxShell = { argv: string[]; t: number } | "ambiguous" | null;

export class ProvenanceStore {
  private readonly db: InstanceType<typeof Database>;
  private readonly stmtTaintLookup!: Statement;
  private readonly stmtParentOf!: Statement;
  private readonly stmtClaimedParentsOf!: Statement;
  private readonly wallClock: () => number;
  /** The last time `tick` gave; at construction, the newest stamp the
   *  store already holds (`storedClockFloor`). */
  private lastTick = -Infinity;

  /**
   * Plan 13 D7 (CI pipeline #8378): the store's clock, which stamps every
   * record and every "now" a window is read against. STRICTLY increasing in
   * the order the arbiter handles reports: the wall clock when it moved on,
   * else the last stamp plus `STORE_CLOCK_STEP_MS`. A call's window (its
   * relay, `call_pending`, to its first ask, `call_asked`) and the shells,
   * flows and orphans compared with it are ORDERED facts: a shell reported
   * after a call's first ask is outside that call's window. On the raw
   * millisecond clock, a same-text call's shell reported in the same
   * millisecond as the previous call's first ask (or after the wall clock
   * stepped back) fell inside the previous call's window as well: two calls
   * then "owned" one shell, the lost-record rule (`outnumbered`) left the new
   * call unbound, and its output was masked whole at the session's level
   * (fail-closed, a utility loss). Times keep the wall clock's unit (ms
   * since the epoch), fractional only within a burst.
   *
   * ACROSS A RESTART (2026-10-17). The records outlive the process (they
   * are in mandu.db), so the order must too: a new store starts its clock
   * at the newest stamp it holds (`storedClockFloor`, over every column of
   * `STORE_STAMP_COLUMNS`), and each stamp is max(wall, last + step), a
   * hybrid logical clock whose state is the data itself. Before, the clock
   * started at the wall clock: after an arbiter restart across a backward
   * wall-clock step (a clock that ran ahead and was corrected, a VM
   * resumed), every new stamp sorted BEFORE the stored ones, and a window
   * opened before the restart lost what happened after it. Fail-open
   * cases: an agent flow opened before the restart counted in no later
   * call's window (`agentFlowsOverlapping`: opened after the window's end),
   * so the agent's own receipt from a holder and a side call reached the
   * model unmasked; and an orphan root first seen after the restart folded
   * into no call relayed before it (`orphanRootsFor`), so a bound call's
   * later result (a background poll) went raw. The stamps order records
   * and are read as nothing else (no duration, nothing displayed); while
   * the wall clock is behind the floor they run on in steps above it.
   */
  /** The wall clock, whole milliseconds, for what is displayed (never an
   *  order: that is `tick`). */
  private wallMs(): number {
    return Math.floor(this.wallClock());
  }

  private tick(): number {
    const w = this.wallClock();
    const t = w > this.lastTick ? w : this.lastTick + STORE_CLOCK_STEP_MS;
    this.lastTick = t;
    return t;
  }

  constructor(opts: ProvenanceStoreOptions = {}) {
    // Read at each tick, not captured: a test that replaces Date.now (the
    // stack tests' frozen and stepping clocks) reaches the store.
    this.wallClock = opts.wallClock ?? (() => Date.now());
    const dbPath = opts.dbPath ?? getSymbolDbPath();
    const dir = dirname(dbPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA_SQL);
    // Plan 13 D3: a raw read records WHICH binary read the file and how it
    // was let in, so the fold finds the reader entry of that (file, binary)
    // pair. Added columns: a store from before 2026-10-02 gains them empty,
    // and its rows fold to `secret`.
    const taintCols = this.db.prepare("PRAGMA table_info(process_secret_taint)").all() as Array<{ name: string }>;
    // Plan 13 R5 (2026-10-02): the script an interpreter ran, the same way.
    for (const col of ["exe", "sha256", "via", "script", "script_sha256"]) {
      if (!taintCols.some((c) => c.name === col)) this.db.exec(`ALTER TABLE process_secret_taint ADD COLUMN ${col} TEXT`);
    }
    // Plan 13 D9: a row recorded from the data socket is a CLAIM (1): it
    // taints like any row, folds as `secret` (no binary, no `via`), and never
    // counts as a secret the process holds raw (decideSecretOpen's derived
    // copy). A store from before 2026-10-02 gains the column empty: its rows
    // were all believed then, and still are.
    if (!taintCols.some((c) => c.name === "claimed")) this.db.exec(`ALTER TABLE process_secret_taint ADD COLUMN claimed INTEGER`);
    // Plan 13 D7 across a restart (2026-10-17): `created_at` is the store's
    // clock, which runs above the wall clock after a backward step; the wall
    // clock's time of the read is kept apart for the panel's "since". A
    // store from before gains the column empty: its rows' stamps were the
    // wall clock then.
    if (!taintCols.some((c) => c.name === "wall_at")) this.db.exec(`ALTER TABLE process_secret_taint ADD COLUMN wall_at INTEGER`);
    this.stmtTaintLookup = this.db.prepare(
      `SELECT origin_host FROM process_taint WHERE proc_key = ?`,
    );
    this.stmtParentOf = this.db.prepare(
      `SELECT parent_key FROM process_lineage WHERE child_key = ?`,
    );
    this.stmtClaimedParentsOf = this.db.prepare(
      `SELECT parent_key FROM process_lineage_claims WHERE child_key = ?`,
    );
    // Plan 13 D7 across a restart: never stamp below a stored record.
    this.lastTick = this.storedClockFloor();
  }

  /** The newest stamp the store holds, over every stamp column
   *  (`STORE_STAMP_COLUMNS`), or -Infinity for an empty store. A value that
   *  is not a finite number (a row written by hand) is not a stamp. */
  storedClockFloor(): number {
    const sql = STORE_STAMP_COLUMNS.map(([t, c]) => `SELECT MAX(${c}) AS t FROM ${t}`).join(" UNION ALL ");
    let floor = -Infinity;
    for (const r of this.db.prepare(sql).all() as Array<{ t: unknown }>) {
      const t = typeof r.t === "bigint" ? Number(r.t) : r.t;
      if (typeof t === "number" && Number.isFinite(t) && t > floor) floor = t;
    }
    return floor;
  }

  /** A process's parents for a walk: the guard's edge, and (unless
   *  `attestedOnly`) every claimed one (plan 13 D9). */
  private parentsOf(procKey: string, attestedOnly = false): string[] {
    const out: string[] = [];
    const up = this.stmtParentOf.get(procKey) as { parent_key: string } | undefined;
    if (up) out.push(up.parent_key);
    if (!attestedOnly) {
      for (const r of this.stmtClaimedParentsOf.all(procKey) as Array<{ parent_key: string }>) {
        if (!out.includes(r.parent_key)) out.push(r.parent_key);
      }
    }
    return out;
  }

  /** Mark a process tainted (it touched an untrusted-classified host). Idempotent / first-taint-wins: a repeat with a different origin keeps the original (monotonic taint). */
  /** Plan 10 §3.1: record that `procKey` opened `path` raw, at `level`, as
   *  reader `app`. Idempotent per (process, file). */
  taintProcessSecret(args: { procKey: string; path: string; level: string; app: string; session?: string; exe?: string; sha256?: string; via?: "reader" | "verdict"; script?: string; scriptSha256?: string; claimed?: boolean }): void {
    // Plan 13 D9: a claim carries no binary and no `via` (it folds as
    // `secret`) and never takes the place of the guard's row for the same
    // (process, file): the guard's row is written over a claim.
    if (args.claimed === true) {
      this.db.prepare(
        // A session row (taintProcessSession) is the one row a claim
        // replaces: a claimed raw read masks, a session row does not.
        `INSERT INTO process_secret_taint (proc_key, path, level, app, session, created_at, wall_at, claimed)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1)
         ON CONFLICT (proc_key, path) DO UPDATE SET level = excluded.level, app = excluded.app, session = excluded.session,
           created_at = excluded.created_at, wall_at = excluded.wall_at, via = NULL, claimed = 1
         WHERE process_secret_taint.via = 'session'`,
      ).run(args.procKey, args.path, args.level, args.app, args.session ?? null, this.tick(), this.wallMs());
      return;
    }
    this.db.prepare(
      `INSERT INTO process_secret_taint (proc_key, path, level, app, session, created_at, wall_at, exe, sha256, via, script, script_sha256, claimed)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
       ON CONFLICT (proc_key, path) DO UPDATE SET level = excluded.level, app = excluded.app, session = excluded.session,
         created_at = excluded.created_at, wall_at = excluded.wall_at, exe = excluded.exe, sha256 = excluded.sha256, via = excluded.via,
         script = excluded.script, script_sha256 = excluded.script_sha256, claimed = NULL
       WHERE process_secret_taint.claimed = 1 OR process_secret_taint.via = 'session'`,
    ).run(args.procKey, args.path, args.level, args.app, args.session ?? null, this.tick(), this.wallMs(), args.exe ?? null, args.sha256 ?? null, args.via ?? null, args.script ?? null, args.scriptSha256 ?? null);
  }

  /** A HIGH session's command (confidentiality.md §4, "What Allow once means
   *  for a command"): the call root the guard saw exec in a session that
   *  read secret content into context holds what the session read, one row
   *  per datum (`via: "session"`, app `session`). Its exits are then held
   *  like a raw reader's (bindings, labels on writes), but a session row
   *  never masks a result the model gets back (`modelVisibleRows`) and never
   *  buys a raw read (`attestedOnly` walks leave it out). Idempotent. */
  taintProcessSession(procKey: string, rows: ReadonlyArray<{ path: string; level: string }>, session?: string, opts: { claimed?: boolean } = {}): void {
    // arbiter-human-plane.md §5.2: from a channel whose reports are claims
    // the rows are kept, marked claimed (a session row only confines); the
    // guard's own report of the same row clears the mark.
    const claimed = opts.claimed === true;
    const ins = this.db.prepare(
      `INSERT OR IGNORE INTO process_secret_taint (proc_key, path, level, app, session, created_at, wall_at, via, claimed)
       VALUES (?, ?, ?, 'session', ?, ?, ?, 'session', ?)`,
    );
    const believe = this.db.prepare(
      `UPDATE process_secret_taint SET claimed = NULL WHERE proc_key = ? AND path = ? AND via = 'session' AND claimed = 1`,
    );
    const now = this.tick();
    const wall = this.wallMs();
    for (const r of rows) {
      if (typeof r.path !== "string" || r.path === "") continue;
      ins.run(procKey, r.path, r.level, session ?? null, now, wall, claimed ? 1 : null);
      if (!claimed) believe.run(procKey, r.path);
    }
  }

  /** The secret taint of a process: its own rows plus its ancestors' (a child
   *  inherits, §3.1). Cycle-safe like isProcessTainted. Plan 13 D9: the walk
   *  follows the guard's edges and every claimed one, and counts claimed rows
   *  (a claim may only add taint); `attestedOnly` reads the guard's records
   *  alone, for a decision where MORE taint would let the process read
   *  something raw (a derived copy of what it holds). */
  processSecretTaint(procKey: string, opts: { attestedOnly?: boolean } = {}): ProcessSecretTaintResult {
    const attestedOnly = opts.attestedOnly === true;
    const rows: SecretTaintRow[] = [];
    const seen = new Set<string>();
    const queue: string[] = [procKey];
    while (queue.length > 0) {
      const cur = queue.shift()!;
      if (cur === "" || seen.has(cur)) continue;
      seen.add(cur);
      for (const r of this.secretRowsOf(cur, attestedOnly)) rows.push(r);
      queue.push(...this.parentsOf(cur, attestedOnly));
      // Plan 13 §9 R1: what reached it through a descriptor counts like what
      // it inherited. Never for `attestedOnly` (more held taint would let a
      // process read a derived copy raw).
      if (!attestedOnly) queue.push(...this.flowsOf(cur));
    }
    return { level: strictestLevel(rows), rows };
  }

  /** Plan 13 §9 R1 (and D2): `procKey` received the bytes of each of
   *  `flowsFrom` through a descriptor, as the guard found it (a connection
   *  to a holder's listener, a socket pair or pipe end passed after the
   *  taint, a pipe read). Recorded as flows, never as lineage edges, and
   *  walked like a parent by every taint walk (the model exit's fold
   *  included), so a tool call whose process received a holder's bytes from
   *  OUTSIDE its tree is masked like one that read the file. Only ever adds
   *  taint: a claim (`claimed`, the data socket) is kept as such, and the
   *  guard's record of the same flow clears the claim mark. */
  recordProcessFlow(procKey: string, flowsFrom: readonly string[], session?: string, opts: { claimed?: boolean } = {}): void {
    const stmt = opts.claimed === true
      ? this.db.prepare(`INSERT OR IGNORE INTO process_flows (proc_key, from_key, session, claimed, created_at) VALUES (?, ?, ?, 1, ?)`)
      : this.db.prepare(
        `INSERT INTO process_flows (proc_key, from_key, session, claimed, created_at) VALUES (?, ?, ?, NULL, ?)
         ON CONFLICT (proc_key, from_key) DO UPDATE SET claimed = NULL WHERE process_flows.claimed = 1`,
      );
    const now = this.tick();
    for (const f of new Set(flowsFrom)) {
      if (typeof f !== "string" || f === "" || f === procKey) continue;
      stmt.run(procKey, f, session ?? null, now);
    }
  }

  /** The processes whose bytes reached `procKey` through a descriptor. */
  flowsOf(procKey: string): string[] {
    return (this.db.prepare(`SELECT from_key FROM process_flows WHERE proc_key = ?`).all(procKey) as Array<{ from_key: string }>).map((r) => r.from_key);
  }

  /** Plan 13 D2: a process's secret taint with the taint of `flowsFrom`
   *  (processes whose bytes reached it through a descriptor, not through its
   *  parents) unioned in, each walked like a process of its own. No edge is
   *  recorded: a pipe's writer is not its reader's parent. */
  processSecretTaintWithFlows(procKey: string, flowsFrom: readonly string[] = []): ProcessSecretTaintResult {
    const own = this.processSecretTaint(procKey);
    if (flowsFrom.length === 0) return own;
    const rows = [...own.rows];
    const seen = new Set(rows.map((r) => `${r.procKey}\u0000${r.path}`));
    for (const k of flowsFrom) {
      for (const r of this.processSecretTaint(k).rows) {
        const id = `${r.procKey}\u0000${r.path}`;
        if (!seen.has(id)) { seen.add(id); rows.push(r); }
      }
    }
    return { level: strictestLevel(rows), rows };
  }

  /** Plan 10 §4.2: an exec the guard saw (its lineage + signature). Plan 13
   *  D7: `ancestors` is the exec'ing process's live ancestor chain, nearest
   *  first, as the guard read it from `/proc` before letting the exec go;
   *  every edge of it is recorded (first edge wins), so a subshell that
   *  never execs (`( a; b )`, `$(a; b)`, `{ a; b; } | c`) is linked to the
   *  call's root through the first exec below it. Without `ancestors`, the
   *  `parentKey` edge alone (an older guard). */
  recordExecRoot(args: {
    procKey: string; parentKey?: string; ancestors?: readonly string[]; signature: string; session?: string; argv?: readonly string[];
    /** Plan 13 D7: the exec'ing process is a direct child of the agent (the
     *  guard's `callRoot`): a candidate root of a tool call, under every
     *  signature in `rootSignatures`. */
    callRoot?: boolean;
    rootSignatures?: readonly string[];
    /** 2026-10-04: the directory the candidate root started in, as the
     *  kernel reported it to the guard (kept only with `callRoot`, and only
     *  an absolute path with no `.`/`..` segment). The first report wins. */
    cwd?: string;
  }): void {
    const chain = lineageChain(args.parentKey, args.ancestors);
    const now = this.tick();
    this.db.transaction(() => {
      this.insertChain(args.procKey, chain, args.session);
      this.db.prepare(
        `INSERT OR REPLACE INTO exec_roots (proc_key, signature, session, created_at) VALUES (?, ?, ?, ?)`,
      ).run(args.procKey, args.signature, args.session ?? null, now);
      if (args.argv && args.argv.length > 0) {
        this.db.prepare(
          `INSERT OR IGNORE INTO exec_argv (proc_key, parent_key, argv, session, created_at) VALUES (?, ?, ?, ?, ?)`,
        ).run(args.procKey, chain[0] ?? null, JSON.stringify(args.argv), args.session ?? null, now);
      }
      if (args.callRoot === true) {
        const ins = this.db.prepare(
          `INSERT OR IGNORE INTO call_root_candidates (proc_key, signature, session, created_at) VALUES (?, ?, ?, ?)`,
        );
        for (const sig of new Set([args.signature, ...(args.rootSignatures ?? [])])) {
          if (typeof sig === "string" && sig !== "") ins.run(args.procKey, sig, args.session ?? null, now);
        }
        if (isCanonicalDir(args.cwd)) {
          this.db.prepare(`INSERT OR IGNORE INTO call_root_cwd (proc_key, cwd) VALUES (?, ?)`).run(args.procKey, args.cwd);
        }
      }
    })();
  }

  /**
   * 2026-10-04 (confidentiality.md §6): the directory a tool call's shell
   * started in, for reading the relative path tokens of its command where
   * the kernel says it ran (Claude Code's `Bash` names no directory). Only
   * for a call the call-root recorder bound (`exact` or `shared`: never a
   * caller's claim or a guess, which are not evidence the tree is the
   * call's), and only when every root it is bound to has a recorded
   * directory and all are the same. Otherwise null, and the tokens keep the
   * catalog's verdict. A lookup: it binds nothing (callTaint, on the human
   * plane, binds), so any caller may ask it.
   */
  callStartDir(callId: string): string | null {
    const rows = this.db.prepare(
      `SELECT b.proc_key AS proc_key, b.kind AS kind, c.cwd AS cwd FROM call_bindings b
       LEFT JOIN call_root_cwd c ON c.proc_key = b.proc_key WHERE b.call_id = ?`,
    ).all(callId) as Array<{ proc_key: string; kind: string; cwd: string | null }>;
    // The roots callTree folds once the recorder bound the call (a guess
    // remembered before that is not one of them).
    const determined = rows.filter((r) => bindingDetermined(r.kind as CallBinding));
    if (determined.length === 0) return null;
    const dirs = new Set(determined.map((r) => r.cwd));
    if (dirs.size !== 1) return null;
    const [dir] = [...dirs];
    return isCanonicalDir(dir) ? dir : null;
  }

  /** Plan 13 D7: the model proxy gated this call's tool_use now (execGate
   *  with a callId, before the agent ever saw it): no exec older than this is
   *  the call's root. The first report wins. */
  recordCallPending(callId: string, session?: string): void {
    if (callId === "") return;
    this.db.prepare(
      `INSERT OR IGNORE INTO call_pending (call_id, session, created_at) VALUES (?, ?, ?)`,
    ).run(callId, session ?? null, this.tick());
  }

  /** When the model proxy first gated or recorded this call (`call_pending`,
   *  the store's clock), or null. Plan 15 §13.12: a plain file changed
   *  after it may have been written by the call itself. */
  callRelayTime(callId: string): number | null {
    return (this.db.prepare(`SELECT created_at FROM call_pending WHERE call_id = ?`).get(callId) as { created_at: number } | undefined)?.created_at ?? null;
  }

  /** Plan 13 D7: the model proxy tied the background poll `pollId` to the
   *  call `callId` (human plane only; the first tie wins). */
  recordPollOf(pollId: string, callId: string, session?: string): void {
    if (pollId === "" || callId === "" || pollId === callId) return;
    this.db.prepare(
      `INSERT OR IGNORE INTO call_polls (poll_id, call_id, session, created_at) VALUES (?, ?, ?, ?)`,
    ).run(pollId, callId, session ?? null, this.tick());
  }

  /** The call the poll `pollId` was tied to, or null. */
  pollOf(pollId: string): string | null {
    return (this.db.prepare(`SELECT call_id FROM call_polls WHERE poll_id = ?`).get(pollId) as { call_id: string } | undefined)?.call_id ?? null;
  }

  /** Plan 13 D7, the orphan subshell: the guard reported `procKey` as the
   *  orphan root of the process it saw act (see `orphan_roots`). The first
   *  report fixes when it was first seen; a later one changes nothing but
   *  believes a claimed row. */
  recordOrphanRoot(procKey: string, session?: string, opts: { claimed?: boolean } = {}): void {
    if (procKey === "") return;
    this.db.transaction(() => {
      this.db.prepare(
        `INSERT OR IGNORE INTO orphan_roots (proc_key, session, claimed, first_seen) VALUES (?, ?, ?, ?)`,
      ).run(procKey, session ?? null, opts.claimed === true ? 1 : null, this.tick());
      if (opts.claimed !== true) this.db.prepare(`UPDATE orphan_roots SET claimed = NULL WHERE proc_key = ?`).run(procKey);
    })();
  }

  /** The orphan roots a call may have started: those of its session (and of
   *  no session) first seen no earlier than the proxy relayed the call
   *  (`call_pending`; a call whose relay is unknown: every one, fail-closed).
   *  Nothing narrower is sound: the orphan's lost parent is gone, and its
   *  session id names a pid a deliberate fork loop can reuse. */
  private orphanRootsFor(callId: string, session: string | undefined): string[] {
    const pending = (this.db.prepare(`SELECT created_at FROM call_pending WHERE call_id = ?`).get(callId) as { created_at: number } | undefined)?.created_at ?? null;
    return (this.db.prepare(
      `SELECT proc_key FROM orphan_roots WHERE (? IS NULL OR session = ? OR session IS NULL) AND (? IS NULL OR first_seen >= ?) ORDER BY first_seen, proc_key`,
    ).all(session ?? null, session ?? null, pending, pending) as Array<{ proc_key: string }>).map((r) => r.proc_key);
  }

  /** Plan 13 D9 follow-up: the model proxy recorded this command for the
   *  call on the human plane (`gate`: execGate's command; `delivered`: the
   *  command the agent received, recordCallCommand). Also the call's gate
   *  time when none is recorded yet: the proxy records the command before it
   *  relays the call, so no exec older than now is the call's root. */
  recordCallCommand(callId: string, signature: string, source: "gate" | "delivered", session?: string): void {
    if (callId === "" || signature === "") return;
    const now = this.tick();
    this.db.transaction(() => {
      this.db.prepare(
        `INSERT OR IGNORE INTO call_commands (call_id, signature, source, session, created_at) VALUES (?, ?, ?, ?, ?)`,
      ).run(callId, signature, source, session ?? null, now);
      this.db.prepare(
        `INSERT OR IGNORE INTO call_pending (call_id, session, created_at) VALUES (?, ?, ?)`,
      ).run(callId, session ?? null, now);
    })();
  }

  /** The signatures a call is bound by: the delivered command(s) when the
   *  proxy recorded any, else the gated one(s); empty when the proxy recorded
   *  none (plan 13 D9 follow-up: the call then binds to no shell). */
  callCommandSignatures(callId: string): string[] {
    const rows = this.db.prepare(
      `SELECT signature, source FROM call_commands WHERE call_id = ? ORDER BY created_at, signature`,
    ).all(callId) as Array<{ signature: string; source: string }>;
    const delivered = rows.filter((r) => r.source === "delivered").map((r) => r.signature);
    const sigs = delivered.length > 0 ? delivered : rows.filter((r) => r.source === "gate").map((r) => r.signature);
    return [...new Set(sigs)];
  }

  /** 2026-10-17 (confidentiality.md §6, "The base follows the shell"): the
   *  agent process itself opened `path` (absolute, as the kernel names it)
   *  for reading, a file that classifies above `public`. The guard's
   *  report, on the human plane (the caller checks). */
  recordAgentOpen(path: string, session?: string): void {
    if (!path.startsWith("/") || path.includes("\0")) return;
    this.db.prepare(`INSERT INTO agent_opens (path, session, created_at) VALUES (?, ?, ?)`).run(path, session ?? null, this.tick());
  }

  /**
   * 2026-10-17 (confidentiality.md §6, "The base follows the shell"): the
   * files the agent itself opened (`recordAgentOpen`) that a file tool's
   * RELATIVE path value may name: each opened in the call's window (from the
   * proxy's relay of the call, `call_pending`, to now; a call whose relay is
   * unknown: the whole session, fail-closed) whose path ends with the value
   * past its leading `./` and `../` (`plan.md` names `/w/vault/plan.md`).
   * The agent resolved the value against ITS directory, which a `cd` in an
   * earlier Bash call or EnterWorktree moved and which the proxy never
   * sees; the kernel saw the file it opened. Raise-only for the caller: a
   * match only adds a reading. At most `AGENT_OPENS_MAX` distinct paths per
   * value, the newest first.
   */
  callAgentOpens(callId: string, session: string | undefined, values: readonly string[]): Array<{ token: string; path: string }> {
    const tails = new Map<string, string>();
    for (const v of values) {
      const t = relativeTail(v);
      if (t !== null) tails.set(v, t);
    }
    if (tails.size === 0) return [];
    const pending = callId === "" ? null
      : (this.db.prepare(`SELECT created_at FROM call_pending WHERE call_id = ?`).get(callId) as { created_at: number } | undefined)?.created_at ?? null;
    const rows = this.db.prepare(
      `SELECT path, MAX(created_at) AS t FROM agent_opens WHERE (? IS NULL OR session = ? OR session IS NULL) AND (? IS NULL OR created_at >= ?)
       GROUP BY path ORDER BY t DESC LIMIT 4096`,
    ).all(session ?? null, session ?? null, pending, pending) as Array<{ path: string }>;
    const out: Array<{ token: string; path: string }> = [];
    for (const [token, tail] of tails) {
      let n = 0;
      for (const r of rows) {
        if (!r.path.endsWith(`/${tail}`)) continue;
        out.push({ token, path: r.path });
        if (++n >= AGENT_OPENS_MAX) break;
      }
    }
    return out;
  }

  /** Plan 13 §4.5.1, the agent's own connection to a holder: the agent
   *  holds `channel` (its socket), whose other end the holders `fromKeys`
   *  write into. Recorded open now; a channel already open from the same
   *  holder is not recorded twice. Only adds masking: a claim (`claimed`,
   *  the data socket) is kept and counted like the guard's record. */
  recordAgentFlow(channel: string, fromKeys: readonly string[], session?: string, opts: { claimed?: boolean } = {}): number {
    if (channel === "") return 0;
    const open = this.db.prepare(`SELECT id, claimed FROM agent_flows WHERE channel = ? AND from_key = ? AND closed_at IS NULL`);
    const ins = this.db.prepare(`INSERT INTO agent_flows (channel, from_key, session, claimed, opened_at, closed_at) VALUES (?, ?, ?, ?, ?, NULL)`);
    const believe = this.db.prepare(`UPDATE agent_flows SET claimed = NULL WHERE id = ?`);
    const now = this.tick();
    let n = 0;
    this.db.transaction(() => {
      for (const f of new Set(fromKeys)) {
        if (typeof f !== "string" || f === "") continue;
        const row = open.get(channel, f) as { id: number; claimed: number | null } | undefined;
        if (row) {
          if (opts.claimed !== true && row.claimed === 1) believe.run(row.id);
          continue;
        }
        ins.run(channel, f, session ?? null, opts.claimed === true ? 1 : null, now);
        n++;
      }
    })();
    return n;
  }

  /** The guard saw the agent no longer hold `channel` (attested only: a
   *  close lowers no mask already given, but it narrows the window of every
   *  later call, so it is believed only on the human socket). */
  closeAgentFlow(channel: string): number {
    if (channel === "") return 0;
    return this.db.prepare(`UPDATE agent_flows SET closed_at = ? WHERE channel = ? AND closed_at IS NULL`).run(this.tick(), channel).changes;
  }

  /** Every agent flow of the session (and of no session) that overlaps
   *  [start, end]: opened no later than `end`, and open or closed no earlier
   *  than `start`. `start` null (the call's relay was never recorded): every
   *  flow opened by `end` (fail-closed). */
  agentFlowsOverlapping(start: number | null, end: number, session?: string): Array<{ channel: string; fromKey: string; openedAt: number; closedAt: number | null }> {
    const rows = this.db.prepare(
      `SELECT channel, from_key, opened_at, closed_at FROM agent_flows
       WHERE opened_at <= ? AND (? IS NULL OR closed_at IS NULL OR closed_at >= ?)
         AND (? IS NULL OR session = ? OR session IS NULL)
       ORDER BY opened_at, id`,
    ).all(end, start, start, session ?? null, session ?? null) as Array<{ channel: string; from_key: string; opened_at: number; closed_at: number | null }>;
    return rows.map((r) => ({ channel: r.channel, fromKey: r.from_key, openedAt: r.opened_at, closedAt: r.closed_at }));
  }

  /** What the holders behind `flows` hold (their own rows, parents and
   *  flows): the level the agent's receipt is masked at. */
  private agentFlowRows(flows: ReadonlyArray<{ fromKey: string }>): SecretTaintRow[] {
    const rows: SecretTaintRow[] = [];
    const seen = new Set<string>();
    for (const k of new Set(flows.map((f) => f.fromKey))) {
      for (const r of modelVisibleRows(this.processSecretTaint(k).rows)) {
        const id = `${r.procKey}\u0000${r.path}`;
        if (!seen.has(id)) { seen.add(id); rows.push(r); }
      }
    }
    return rows;
  }

  /**
   * Plan 13 §4.5.1 (decision 2026-10-02): a tool result the agent itself
   * produced is masked at the level of what the holders it was connected to
   * hold, when the call's window overlaps such a connection. The window runs
   * from the proxy's relay of the call (`call_pending`: execGate or
   * recordCallCommand, before the agent saw the call) to the proxy's first
   * ask about its result (`call_answered`, recorded here unless `readOnly`;
   * a data-socket caller reads with `now` as the end, which only widens).
   * A call whose relay was never recorded is unattributable: every flow
   * opened before the end counts (fail-closed).
   */
  agentReceiptTaint(callId: string, opts: AgentReceiptOpts = {}): AgentReceipt {
    const now = this.tick();
    if (opts.readOnly !== true && callId !== "") {
      this.db.prepare(`INSERT OR IGNORE INTO call_answered (call_id, session, created_at) VALUES (?, ?, ?)`).run(callId, opts.session ?? null, now);
    }
    // A tool this leg does not cover: only its first ask is recorded (the
    // side call's "still out" reads it).
    if (opts.recordOnly === true) return { level: null, rows: [], flows: 0, relayKnown: true };
    const answered = (this.db.prepare(`SELECT created_at FROM call_answered WHERE call_id = ?`).get(callId) as { created_at: number } | undefined)?.created_at ?? now;
    const start = (this.db.prepare(`SELECT created_at FROM call_pending WHERE call_id = ?`).get(callId) as { created_at: number } | undefined)?.created_at ?? null;
    // A file tool's result (`channels: "file"`, plan 13 §4.5.1, 2026-10-02)
    // counts only a flow on a file-like channel: a FIFO the agent read.
    const flows = this.agentFlowsOverlapping(start, answered, opts.session)
      .filter((f) => opts.channels !== "file" || isFileChannel(f.channel));
    const rows = this.agentFlowRows(flows);
    return { level: strictestLevel(rows), rows, flows: flows.length, relayKnown: start !== null };
  }

  /**
   * agentReceiptTaint for every call one proxy request asks about, in order
   * and in ONE transaction: each call's first ask is one `call_answered`
   * row, and a commit per row is a WAL sync per row. A request carrying 82
   * results then took 82 syncs inside one arbiter op, which on a slow disk
   * (a loaded CI guest: CI pipelines 10995 and 11016) outran the proxy's 5 s
   * deadline, and the proxy refused the request (its fail-closed 502). The
   * answers are those of the calls made one by one: the same rows, the
   * same strictly increasing stamps, each call reading the rows before it.
   */
  agentReceiptTaints(asks: ReadonlyArray<{ callId: string; opts?: AgentReceiptOpts }>): AgentReceipt[] {
    if (asks.length === 0) return [];
    return this.db.transaction(() => asks.map((a) => this.agentReceiptTaint(a.callId, a.opts)))();
  }

  /**
   * Plan 13 §4.5.1: a SIDE CALL (a model request the harness makes with no
   * tools: Claude Code's WebFetch summarizer, whose one user message is the
   * fetched page) carries what the agent received while a call was out. Its
   * window: from the relay of the oldest call of the session the proxy has
   * not asked about yet (`call_answered`, `call_asked`) to now; with none
   * outstanding, the flows open now. Read-only.
   */
  sideCallAgentTaint(session?: string): { level: string | null; rows: SecretTaintRow[]; flows: number } {
    const now = this.tick();
    const oldest = (this.db.prepare(
      `SELECT MIN(p.created_at) AS t FROM call_pending p
       WHERE (? IS NULL OR p.session = ? OR p.session IS NULL)
         AND NOT EXISTS (SELECT 1 FROM call_answered a WHERE a.call_id = p.call_id)
         AND NOT EXISTS (SELECT 1 FROM call_asked k WHERE k.call_id = p.call_id)`,
    ).get(session ?? null, session ?? null) as { t: number | null } | undefined)?.t ?? null;
    const flows = oldest === null
      ? this.agentFlowsOverlapping(now, now, session)
      : this.agentFlowsOverlapping(oldest, now, session);
    const rows = this.agentFlowRows(flows);
    return { level: strictestLevel(rows), rows, flows: flows.length };
  }

  /** Plan 10 §11.13: the processes of a session that exec'd EXACTLY this argv
   *  (any of the spellings given), oldest first, each once. */
  procsWithArgv(session: string, argvs: ReadonlyArray<readonly string[]>): string[] {
    const out: string[] = [];
    const q = this.db.prepare(`SELECT proc_key FROM exec_argv WHERE session = ? AND argv = ? ORDER BY created_at`);
    for (const argv of argvs) {
      for (const r of q.all(session, JSON.stringify(argv)) as Array<{ proc_key: string }>) {
        if (!out.includes(r.proc_key)) out.push(r.proc_key);
      }
    }
    return out;
  }

  /** The most recent exec whose signature matches (same session when given). */
  execRootBySignature(signature: string, session?: string): string | null {
    if (signature === "") return null;
    const row = (session
      ? this.db.prepare(`SELECT proc_key FROM exec_roots WHERE signature = ? AND session = ? ORDER BY created_at DESC LIMIT 1`).get(signature, session)
      : this.db.prepare(`SELECT proc_key FROM exec_roots WHERE signature = ? ORDER BY created_at DESC LIMIT 1`).get(signature)) as { proc_key: string } | undefined;
    return row?.proc_key ?? null;
  }

  /** Plan 10 §11.8: an open the arbiter refused. */
  recordSecretOpenDenial(args: { procKey: string; path: string; app: string; reason: string; session?: string }): void {
    this.db.prepare(
      `INSERT OR REPLACE INTO secret_open_denials (proc_key, path, app, reason, session, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(args.procKey, args.path, args.app, args.reason, args.session ?? null, this.tick());
  }

  /** Plan 10 §11.8, "Refused connections": the egress proxy refused a
   *  connection from `procKey` (`kind` from a fixed set; never a host). */
  recordEgressRefusal(args: { procKey: string; kind: string; session?: string }): void {
    this.db.prepare(
      `INSERT OR REPLACE INTO egress_refusals (proc_key, kind, session, created_at) VALUES (?, ?, ?, ?)`,
    ).run(args.procKey, args.kind, args.session ?? null, this.tick());
  }

  /**
   * Plan 10 §11.8, "A refusal no process is tied to" (2026-10-17): the
   * egress proxy refused a connection and found no process holding it. The
   * note can only be tied to the calls running when it happened: the calls
   * of the session the model proxy relayed (`call_pending`) and has not
   * asked about yet (`call_asked`). With none outstanding nothing is
   * recorded (no call's result could say it). Deduplicated per (session,
   * kind): a row is added only when the latest such row is older than the
   * latest outstanding call's relay, i.e. when some outstanding call's
   * window holds none yet; a program retrying in a loop adds one row per
   * call, not one per try. Returns whether a row was added.
   */
  recordUnattributedEgressRefusal(args: { kind: string; session?: string }): boolean {
    const session = args.session ?? null;
    return this.db.transaction(() => {
      const latestCall = (this.db.prepare(
        `SELECT MAX(p.created_at) AS t FROM call_pending p
         WHERE (? IS NULL OR p.session = ? OR p.session IS NULL)
           AND NOT EXISTS (SELECT 1 FROM call_asked k WHERE k.call_id = p.call_id)`,
      ).get(session, session) as { t: number | null } | undefined)?.t ?? null;
      if (latestCall === null) return false;
      const latestRow = (this.db.prepare(
        `SELECT MAX(created_at) AS t FROM egress_refusals_unattributed WHERE session IS ? AND kind = ?`,
      ).get(session, args.kind) as { t: number | null } | undefined)?.t ?? null;
      if (latestRow !== null && latestRow >= latestCall) return false;
      this.db.prepare(
        `INSERT INTO egress_refusals_unattributed (kind, session, created_at) VALUES (?, ?, ?)`,
      ).run(args.kind, session, this.tick());
      return true;
    })();
  }

  /**
   * The kinds of the unattributed refusals made while `callId` ran: its
   * window from the proxy's relay (`call_pending`) to its first ask
   * (`call_asked`; still open: now). A call whose relay is unknown gets none
   * (the note would be a guess at which call it was). One entry per kind,
   * oldest first. Display only: never an input to a mask.
   */
  unattributedEgressRefusalsFor(callId: string, session?: string): string[] {
    const from = (this.db.prepare(`SELECT created_at FROM call_pending WHERE call_id = ?`).get(callId) as { created_at: number } | undefined)?.created_at;
    if (from === undefined) return [];
    const until = (this.db.prepare(`SELECT created_at FROM call_asked WHERE call_id = ?`).get(callId) as { created_at: number } | undefined)?.created_at ?? null;
    const rows = this.db.prepare(
      `SELECT kind, MIN(created_at) AS t FROM egress_refusals_unattributed
       WHERE (? IS NULL OR session = ? OR session IS NULL) AND created_at >= ? AND (? IS NULL OR created_at <= ?)
       GROUP BY kind ORDER BY t, kind`,
    ).all(session ?? null, session ?? null, from, until, until) as Array<{ kind: string }>;
    return rows.map((r) => r.kind);
  }

  /** The program a process ran, by its last recorded argv (basename of
   *  argv[0]), or null when the guard recorded none. */
  private appOf(procKey: string): string | null {
    const row = this.db.prepare(`SELECT argv FROM exec_argv WHERE proc_key = ? ORDER BY created_at DESC LIMIT 1`).get(procKey) as { argv: string } | undefined;
    if (!row) return null;
    try {
      const argv = JSON.parse(row.argv) as unknown;
      const a0 = Array.isArray(argv) && typeof argv[0] === "string" ? argv[0] : "";
      return a0 === "" ? null : (a0.split("/").pop() ?? null);
    } catch {
      return null;
    }
  }

  /** Plan 10 §4.2: the root process of a tool call, as a caller states it.
   *  Plan 13 D7: a statement, not evidence (the op is reachable from the
   *  agent's tree): it is folded, but the call still counts as one whose tree
   *  the recorder did not find (`claimed`). Replaces an earlier claim. */
  recordCallRoot(callId: string, procKey: string, session?: string): void {
    this.db.transaction(() => {
      this.db.prepare(`DELETE FROM call_bindings WHERE call_id = ? AND kind = 'claimed'`).run(callId);
      this.db.prepare(
        `INSERT OR IGNORE INTO call_bindings (call_id, proc_key, kind, session, created_at) VALUES (?, ?, 'claimed', ?, ?)`,
      ).run(callId, procKey, session ?? null, this.tick());
    })();
  }

  /** The secret taint over a tool call's WHOLE process tree (the root, its
   *  descendants, and the root's own ancestors), for the fold of §3.2. A call
   *  whose tree is not found has no root and no taint here; the arbiter's
   *  `callTaint` op decides what that means (plan 13 D7: `callTree`). */
  callTaint(callId: string, opts: { signature?: string; session?: string } = {}): CallTaintResult {
    const { level, rows, root, denied, refusedEgress, shimExecs, codexSandboxShims } = this.callTree(callId, opts);
    return {
      level, rows, root, denied, ...(refusedEgress ? { refusedEgress } : {}), ...(shimExecs ? { shimExecs } : {}),
      ...(codexSandboxShims ? { codexSandboxShims } : {}),
    };
  }

  /**
   * Plan 13 D7: the tool call's tree and how it was found.
   *
   *   1. The recorder (`exact` / `shared`): the candidate roots (execs by a
   *      direct child of the agent, `recordExecRoot` with `callRoot`) whose
   *      command signature is one the model proxy RECORDED for the call on
   *      the human plane (`callCommandSignatures`: the command it delivered
   *      to the agent, else the one it gated; plan 13 D9 follow-up: never the
   *      text the agent echoes back, `opts.signature`, which a call with no
   *      such record is never bound by), no older than the proxy's gate of
   *      the call (`recordCallPending`) when that is known, no younger than
   *      the first time the call's result was asked for (it had run by then:
   *      a later exec, stray or forged over the agent-reachable socket to
   *      clear a call already masked, never binds it), and not bound to
   *      another call as its only root. One candidate: the call's root. More
   *      (two calls with the same text running together, or a stray exec of
   *      it): the call is folded over every one of them, and so is every
   *      other call they match, since nothing tells them apart.
   *   2. Otherwise a caller's claim (`recordCallRoot`, `claimed`), else the
   *      most recent exec of the echoed signature (`guess`), remembered:
   *      folded, but not evidence that the tree is the call's (it can only
   *      add taint).
   *
   * A call bound by the recorder is a lookup from then on.
   */
  callTree(callId: string, opts: { signature?: string; session?: string; readOnly?: boolean } = {}): CallTreeResult {
    let bound = this.bindingsOf(callId);
    // Plan 13 D9: a caller on the data socket (`readOnly`) reads the call's
    // bindings as they are and changes nothing: it neither fixes the call's
    // first ask, nor binds it, nor records a guess. Before, a program the
    // agent ran could ask first, naming another call's clean text, and the
    // call was bound to that call's shell.
    if (opts.readOnly === true) return this.foldBindings(bound, this.orphanRootsFor(callId, opts.session));
    if (!bound.some((b) => bindingDetermined(b.kind))) {
      this.db.prepare(`INSERT OR IGNORE INTO call_asked (call_id, created_at) VALUES (?, ?)`).run(callId, this.tick());
      const asked = (this.db.prepare(`SELECT created_at FROM call_asked WHERE call_id = ?`).get(callId) as { created_at: number }).created_at;
      // Plan 13 D9 follow-up: bound by the command the proxy recorded, not
      // the echoed one. Before, the agent could echo another call's clean
      // text for a call whose own shell read a secret and bind it there.
      const recorded = this.callCommandSignatures(callId);
      if (recorded.length > 0 && this.bindByRecorder(callId, recorded, opts.session, asked)) bound = this.bindingsOf(callId);
    }
    if (bound.length === 0 && opts.signature) {
      const g = this.execRootBySignature(opts.signature, opts.session);
      if (g !== null) {
        this.db.prepare(
          `INSERT OR IGNORE INTO call_bindings (call_id, proc_key, kind, session, created_at) VALUES (?, ?, 'guess', ?, ?)`,
        ).run(callId, g, opts.session ?? null, this.tick());
        bound = this.bindingsOf(callId);
      }
    }
    return this.foldBindings(bound, this.orphanRootsFor(callId, opts.session));
  }

  /** callTree's fold over the bindings found, and over the trees of the
   *  orphan roots the call may have started (`orphans`, plan 13 D7): their
   *  taint rows only. Their refused opens are not the call's (a denial note
   *  can release a path-derived mask, which an orphan must never do). */
  private foldBindings(bound: Array<{ procKey: string; kind: CallBinding }>, orphans: readonly string[] = []): CallTreeResult {
    if (bound.length === 0) return { level: null, rows: [], root: null, roots: [], denied: [], binding: "none" };
    const determined = bound.filter((b) => bindingDetermined(b.kind));
    const used = determined.length > 0 ? determined : bound;
    const binding: CallBinding = determined.length > 0
      ? (determined.length > 1 || determined.some((b) => b.kind === "shared") ? "shared" : "exact")
      : bound.some((b) => b.kind === "claimed") ? "claimed" : "guess";
    const roots = used.map((b) => b.procKey);
    const rows: SecretTaintRow[] = [];
    const denied: Array<{ path: string; app: string; reason: string }> = [];
    const refusedEgress: Array<{ app: string; kind: string }> = [];
    const shimExecs: string[][] = [];
    const codexSandboxShims: string[][] = [];
    const seenRow = new Set<string>();
    for (const r of roots) {
      const t = this.treeTaint(r);
      for (const a of t.shimExecs ?? []) addArgv(shimExecs, a);
      for (const a of t.codexSandboxShims ?? []) addArgv(codexSandboxShims, a);
      for (const row of modelVisibleRows(t.rows)) {
        const id = `${row.procKey}\u0000${row.path}`;
        if (!seenRow.has(id)) { seenRow.add(id); rows.push(row); }
      }
      denied.push(...t.denied);
      for (const e of t.refusedEgress ?? []) {
        if (!refusedEgress.some((x) => x.app === e.app && x.kind === e.kind)) refusedEgress.push(e);
      }
    }
    for (const o of orphans) {
      if (roots.includes(o)) continue;
      for (const row of modelVisibleRows(this.treeTaint(o).rows)) {
        const id = `${row.procKey}\u0000${row.path}`;
        if (!seenRow.has(id)) { seenRow.add(id); rows.push(row); }
      }
    }
    return {
      level: strictestLevel(rows), rows, root: roots[0] ?? null, roots, denied, binding,
      ...(refusedEgress.length > 0 ? { refusedEgress } : {}),
      ...(shimExecs.length > 0 ? { shimExecs } : {}),
      ...(codexSandboxShims.length > 0 ? { codexSandboxShims } : {}),
    };
  }

  /**
   * Plan 10 §11.8, "Blocked commands", for a call the recorder did not bind
   * (2026-10-09): the shim's runs under the processes that exec'd the call's
   * own command, for the `blocked:` line only. Codex under its own sandbox is
   * the case: the agent's child is the sandbox helper, whose argv carries a
   * shell-snapshot preamble (cut short in the guard's record), never the
   * command, so the call binds to no shell; a process under the helper then
   * execs `<shell> -c <the command>`. Those processes are found by the
   * call's recorded command (`callCommandSignatures`, through `signatureOf`,
   * the arbiter's execSignatureForArgv), in the call's session, exec'd no
   * earlier than the proxy gated the call and no later than its result was
   * first asked for (now, when never), and each one's descendants are
   * walked. EXPLAINS ONLY: nothing here is a binding, a taint row, a refused
   * open or a refused connection, so it never lowers or raises a mask; a
   * second call with the same text running at the same time, or a process
   * that execs the same text, can at most add a line that is not this
   * call's, as the bound tree's shim runs can (an argv is the agent's to
   * choose). A call with no recorded command or no gate time finds none.
   * Read-only.
   */
  commandShimExecs(callId: string, opts: { session?: string; signatureOf: (argv: string[]) => string }): { shimExecs: string[][]; codexSandboxShims: string[][] } {
    const shimExecs: string[][] = [];
    const codexSandboxShims: string[][] = [];
    const sigs = this.callCommandSignatures(callId);
    const from = (this.db.prepare(`SELECT created_at FROM call_pending WHERE call_id = ?`).get(callId) as { created_at: number } | undefined)?.created_at;
    if (sigs.length === 0 || from === undefined) return { shimExecs, codexSandboxShims };
    const until = (this.db.prepare(`SELECT created_at FROM call_asked WHERE call_id = ?`).get(callId) as { created_at: number } | undefined)?.created_at ?? null;
    const rows = this.db.prepare(
      `SELECT proc_key, argv FROM exec_argv
       WHERE (? IS NULL OR session = ? OR session IS NULL) AND created_at >= ? AND (? IS NULL OR created_at <= ?)
       ORDER BY created_at, proc_key LIMIT 20000`,
    ).all(opts.session ?? null, opts.session ?? null, from, until, until) as Array<{ proc_key: string; argv: string }>;
    const roots: string[] = [];
    for (const r of rows) {
      if (roots.includes(r.proc_key)) continue;
      let argv: unknown;
      try { argv = JSON.parse(r.argv); } catch { continue; }
      if (!Array.isArray(argv) || argv.length === 0 || !argv.every((a) => typeof a === "string")) continue;
      if (sigs.includes(opts.signatureOf(argv as string[]))) roots.push(r.proc_key);
    }
    const sandboxed = new Map<string, boolean>();
    const children = this.db.prepare(`SELECT child_key FROM process_lineage WHERE parent_key = ? UNION SELECT child_key FROM process_lineage_claims WHERE parent_key = ?`);
    const seen = new Set<string>();
    const queue = [...roots];
    while (queue.length > 0 && seen.size < 4096) {
      const k = queue.shift()!;
      if (seen.has(k)) continue;
      seen.add(k);
      this.pushShimExecsOf(k, shimExecs, codexSandboxShims, sandboxed);
      for (const c of children.all(k, k) as Array<{ child_key: string }>) queue.push(c.child_key);
    }
    return { shimExecs, codexSandboxShims };
  }

  /** The shim's runs recorded for process `k` (`shimInvocationArgv` over
   *  its argv rows), each once, into `shimExecs`, and into
   *  `codexSandboxShims` too when `k` runs under Codex's network-off
   *  sandbox (`sandboxed` caches that per process). */
  private pushShimExecsOf(k: string, shimExecs: string[][], codexSandboxShims: string[][], sandboxed: Map<string, boolean>): void {
    for (const r of this.db.prepare(`SELECT argv FROM exec_argv WHERE proc_key = ? ORDER BY created_at`).all(k) as Array<{ argv: string }>) {
      const inv = shimInvocationArgv(parseArgv(r.argv) ?? []);
      if (inv === null) continue;
      addArgv(shimExecs, inv);
      if (this.underCodexSandboxNetworkOff(k, sandboxed)) addArgv(codexSandboxShims, inv);
    }
  }

  /** Does process `k` run under Codex's command sandbox with its network
   *  off: an argv the guard recorded for it or for one of its ancestors
   *  (the exec record's parent, else the lineage edge; at most 16 up) is
   *  that sandbox's helper (`codexSandboxNetworkOff`)? Cached in `memo`. */
  private underCodexSandboxNetworkOff(k: string, memo: Map<string, boolean>): boolean {
    const argvsOf = this.db.prepare(`SELECT argv, parent_key FROM exec_argv WHERE proc_key = ? ORDER BY created_at`);
    const lineageParent = this.db.prepare(`SELECT parent_key FROM process_lineage WHERE child_key = ? LIMIT 1`);
    const chain: string[] = [];
    let cur: string | null = k;
    let found = false;
    for (let depth = 0; cur !== null && depth < 16 && !chain.includes(cur); depth++) {
      const known = memo.get(cur);
      if (known !== undefined) { found = known; break; }
      chain.push(cur);
      const rows = argvsOf.all(cur) as Array<{ argv: string; parent_key: string | null }>;
      if (rows.some((r) => codexSandboxNetworkOff(parseArgv(r.argv) ?? []))) { found = true; break; }
      cur = rows.find((r) => r.parent_key)?.parent_key ?? (lineageParent.get(cur) as { parent_key: string } | undefined)?.parent_key ?? null;
    }
    for (const c of chain) memo.set(c, found);
    return found;
  }

  /**
   * folder-listing-compound.md L8: every argv the guard recorded for a
   * process of the call's tree as the recorder bound it (`exact` or
   * `shared` roots and their descendants by the guard's lineage, never a
   * claim), or
   * null when the call is not so bound or the tree is over the walk's bound
   * (4096 processes). Read-only; explains which programs ran, never a byte
   * they printed.
   */
  callTreeExecArgvs(callId: string): string[][] | null {
    const roots = this.bindingsOf(callId).filter((b) => b.kind === "exact" || b.kind === "shared").map((b) => b.procKey);
    if (roots.length === 0) return null;
    // the guard's own lineage only: a claim comes over the data socket the
    // agent reaches (implementation review round 1)
    const children = this.db.prepare(`SELECT child_key FROM process_lineage WHERE parent_key = ?`);
    const argvsOf = this.db.prepare(`SELECT argv FROM exec_argv WHERE proc_key = ? ORDER BY created_at`);
    const out: string[][] = [];
    const seen = new Set<string>();
    const queue = [...roots];
    while (queue.length > 0) {
      const k = queue.shift()!;
      if (seen.has(k)) continue;
      if (seen.size >= 4096) return null;
      seen.add(k);
      for (const r of argvsOf.all(k) as Array<{ argv: string }>) {
        const a = parseArgv(r.argv);
        if (a !== null) out.push(a);
      }
      for (const c of children.all(k) as Array<{ child_key: string }>) queue.push(c.child_key);
    }
    return out;
  }

  /** The call's bindings, oldest first. */
  private bindingsOf(callId: string): Array<{ procKey: string; kind: CallBinding }> {
    return (this.db.prepare(`SELECT proc_key, kind FROM call_bindings WHERE call_id = ? ORDER BY created_at, proc_key`).all(callId) as Array<{ proc_key: string; kind: string }>)
      .map((r) => ({ procKey: r.proc_key, kind: (["exact", "shared", "claimed", "guess"].includes(r.kind) ? r.kind : "guess") as CallBinding }));
  }

  /** callTree step 1. True when the call was bound. */
  private bindByRecorder(callId: string, signatures: readonly string[], session: string | undefined, asked: number): boolean {
    const pending = (this.db.prepare(`SELECT created_at FROM call_pending WHERE call_id = ?`).get(callId) as { created_at: number } | undefined)?.created_at ?? null;
    const sigs = [...new Set(signatures)].filter((x) => x !== "");
    if (sigs.length === 0) return false;
    const rows = this.db.prepare(
      `SELECT proc_key, signature, created_at AS t FROM call_root_candidates
       WHERE signature IN (${sigs.map(() => "?").join(", ")}) AND (? IS NULL OR session = ? OR session IS NULL) AND (? IS NULL OR created_at >= ?) AND created_at <= ?
       ORDER BY created_at, proc_key`,
    ).all(...sigs, session ?? null, session ?? null, pending, pending, asked) as Array<{ proc_key: string; signature: string; t: number }>;
    rows.push(...this.codexSandboxCandidates(sigs, session, pending, asked));
    const takenAlone = this.db.prepare(`SELECT 1 AS x FROM call_bindings WHERE proc_key = ? AND kind = 'exact' AND call_id <> ? LIMIT 1`);
    const sharedElsewhere = this.db.prepare(`SELECT 1 AS x FROM call_bindings WHERE proc_key = ? AND kind = 'shared' AND call_id <> ? LIMIT 1`);
    const free = rows.filter((r) => takenAlone.get(r.proc_key, callId) === undefined);
    const cands = [...new Set(free.map((r) => r.proc_key))];
    if (cands.length === 0) return false;
    if (this.outnumbered(free, session)) return false;
    const kind = cands.length > 1 || cands.some((k) => sharedElsewhere.get(k, callId) !== undefined) ? "shared" : "exact";
    const now = this.tick();
    this.db.transaction(() => {
      const ins = this.db.prepare(
        `INSERT OR REPLACE INTO call_bindings (call_id, proc_key, kind, session, created_at) VALUES (?, ?, ?, ?, ?)`,
      );
      for (const k of cands) ins.run(callId, k, kind, session ?? null, now);
    })();
    return true;
  }

  /**
   * Plan 13 D7, Codex under its own sandbox (2026-10-09). The agent's child
   * for such a call is the sandbox helper (`isCodexSandboxHelperArgv`), whose
   * recorded argv stops inside the shell-snapshot preamble, so it is no
   * candidate by the command's text. The command runs in a shell the helper
   * starts through its plumbing (`codexSandboxCommandShell`). A helper that
   * is a candidate root (the agent's own child, in the call's session and
   * window) and under which exactly ONE command shell ran, exec'd within the
   * call's window, is a candidate for that shell's root signatures, the
   * candidate being the HELPER, so the whole sandbox tree folds. An
   * ambiguous helper (two command shells of different text) is no candidate
   * for any call: the call stays unbound and masked at the session's level.
   */
  private codexSandboxCandidates(sigs: readonly string[], session: string | undefined, pending: number | null, asked: number): Array<{ proc_key: string; signature: string; t: number }> {
    const helpers = this.db.prepare(
      `SELECT DISTINCT proc_key FROM call_root_candidates
       WHERE (? IS NULL OR session = ? OR session IS NULL) AND (? IS NULL OR created_at >= ?) AND created_at <= ?`,
    ).all(session ?? null, session ?? null, pending, pending, asked) as Array<{ proc_key: string }>;
    const argvsOf = this.db.prepare(`SELECT argv FROM exec_argv WHERE proc_key = ?`);
    const out: Array<{ proc_key: string; signature: string; t: number }> = [];
    for (const { proc_key } of helpers) {
      if (!(argvsOf.all(proc_key) as Array<{ argv: string }>).some((r) => isCodexSandboxHelperArgv(parseArgv(r.argv) ?? []))) continue;
      const shell = this.codexSandboxCommandShell(proc_key);
      if (shell === null || shell === "ambiguous") continue;
      if ((pending !== null && shell.t < pending) || shell.t > asked) continue;
      for (const sig of rootSignaturesOfArgv(shell.argv)) {
        if (sigs.includes(sig)) out.push({ proc_key, signature: sig, t: shell.t });
      }
    }
    return out;
  }

  /**
   * Plan 13 D7: the shell that ran the command of the Codex sandbox helper
   * `helper` (a candidate root), as the guard recorded it:
   *
   *   0.144.1  helper → bwrap → bwrap → S: `codex … --apply-seccomp-then-exec
   *            -- zsh -c <preamble>`, then `zsh -c <preamble>`, then
   *            `zsh -c <command>` (one process, three execs);
   *   0.162.0  helper → bwrap → helper (pid 1 inside) → S: `zsh -c
   *            <preamble>`, then `zsh -c <command>`.
   *
   * Walked down the guard's own lineage edges (never a claimed edge) through
   * plumbing processes only (`isCodexSandboxPlumbingArgv`: every exec of the
   * process is plumbing, or it never exec'd). In each process reached, its
   * first exec that is neither plumbing nor the preamble
   * (`isCodexSnapshotPreambleArgv`) is that process's command shell when it
   * is a shell `-c` with its payload; a process whose first such exec is
   * anything else holds none. A later exec of the same process (the command
   * `exec`ing another shell) and every process below a non-plumbing one
   * (the command's own children) are never looked at. Two command shells of
   * different text (an orphan of the command, re-parented to the sandbox's
   * pid 1, that execs a shell) make the helper ambiguous. Read-only.
   */
  codexSandboxCommandShell(helper: string): CodexSandboxShell {
    const children = this.db.prepare(`SELECT child_key FROM process_lineage WHERE parent_key = ? ORDER BY created_at, child_key`);
    const execsOf = this.db.prepare(`SELECT argv, created_at AS t FROM exec_argv WHERE proc_key = ? ORDER BY created_at`);
    const found: Array<{ argv: string[]; t: number }> = [];
    const seen = new Set<string>([helper]);
    const queue = (children.all(helper) as Array<{ child_key: string }>).map((r) => r.child_key);
    while (queue.length > 0 && seen.size < 4096) {
      const k = queue.shift()!;
      if (seen.has(k)) continue;
      seen.add(k);
      const execs = (execsOf.all(k) as Array<{ argv: string; t: number }>).map((r) => ({ argv: parseArgv(r.argv) ?? [], t: r.t }));
      const other = execs.find((e) => !isCodexSandboxPlumbingArgv(e.argv) && !isCodexSnapshotPreambleArgv(e.argv));
      if (other === undefined) {
        // all plumbing (or a preamble that never got to exec the command, or
        // a fork that never exec'd): the plumbing goes on below it
        if (execs.every((e) => isCodexSandboxPlumbingArgv(e.argv))) {
          for (const c of children.all(k) as Array<{ child_key: string }>) queue.push(c.child_key);
        }
        continue;
      }
      if (shellPayload(other.argv) !== null) found.push(other);
    }
    if (found.length === 0) return null;
    const texts = new Set(found.map((f) => execSignatureForArgv(f.argv)));
    if (texts.size !== 1) return "ambiguous";
    return found[0]!;
  }

  /**
   * Plan 13 D7, a lost shell record (closed 2026-10-02): are the candidate
   * shells of some recorded command fewer than the calls that may own them?
   * For each command signature the candidates carry, the calls of the session
   * whose binding command (`callCommandSignatures`) is that signature and
   * whose window (the proxy's relay of the call, `call_pending`, to its first
   * ask, `call_asked`, or still open) holds one of those shells. More calls
   * than shells: one call's shell was never recorded (a lost report, an exec
   * the guard did not see), and nothing tells which of the calls the
   * recorded shells belong to. Binding any of them could hand a call whose own
   * tree read a secret another call's clean shell; so none is bound, and each
   * is masked at the session's level while the session holds a raw read.
   * Before, the first call asked took the shell `exact` and the other call
   * lost it. Utility cost: two same-text calls whose windows overlap, one of
   * whose shells was not recorded yet when either was asked, are both masked.
   */
  private outnumbered(cands: ReadonlyArray<{ proc_key: string; signature: string; t: number }>, session: string | undefined): boolean {
    const bySig = new Map<string, Array<{ proc_key: string; t: number }>>();
    for (const c of cands) {
      const l = bySig.get(c.signature) ?? [];
      l.push(c);
      bySig.set(c.signature, l);
    }
    const callsOf = this.db.prepare(
      `SELECT DISTINCT c.call_id AS call_id, p.created_at AS start, k.created_at AS asked
       FROM call_commands c JOIN call_pending p ON p.call_id = c.call_id LEFT JOIN call_asked k ON k.call_id = c.call_id
       WHERE c.signature = ? AND (? IS NULL OR c.session = ? OR c.session IS NULL)`,
    );
    for (const [sig, shells] of bySig) {
      const owners = new Set<string>();
      for (const r of callsOf.all(sig, session ?? null, session ?? null) as Array<{ call_id: string; start: number; asked: number | null }>) {
        if (!this.callCommandSignatures(r.call_id).includes(sig)) continue;
        if (shells.some((s) => s.t >= r.start && (r.asked === null || s.t <= r.asked))) owners.add(r.call_id);
      }
      if (owners.size > new Set(shells.map((s) => s.proc_key)).size) return true;
    }
    return false;
  }

  /** Plan 13 D7, the fail-closed answer for a call whose tree is not found:
   *  every raw secret read of the session, and of no session (a guard that
   *  named none); every session's when none is given. */
  heldSessionTaint(session?: string): { level: string | null; rows: SecretTaintRow[] } {
    const rows = ((session !== undefined
      ? this.db.prepare(`SELECT proc_key, path, level, app FROM process_secret_taint WHERE (session = ? OR session IS NULL) AND (via IS NULL OR via != 'session')`).all(session)
      : this.db.prepare(`SELECT proc_key, path, level, app FROM process_secret_taint WHERE via IS NULL OR via != 'session'`).all()) as Array<{ proc_key: string; path: string; level: string; app: string }>)
      .map((r) => ({ procKey: r.proc_key, path: r.path, level: r.level, app: r.app }));
    return { level: strictestLevel(rows), rows };
  }

  /** The secret taint over a process's WHOLE tree: its own ancestors (a
   *  tainted parent taints it) and every descendant the guard recorded, with
   *  the refused opens. callTaint's fold, for a root already known (plan 10
   *  §11.13: an MCP server's process). */
  treeTaint(root: string): { level: string | null; rows: SecretTaintRow[]; denied: Array<{ path: string; app: string; reason: string }>; refusedEgress?: Array<{ app: string; kind: string }>; shimExecs?: string[][]; codexSandboxShims?: string[][] } {
    const rows: SecretTaintRow[] = [];
    const denied: Array<{ path: string; app: string; reason: string }> = [];
    const refusedEgress: Array<{ app: string; kind: string }> = [];
    const shimExecs: string[][] = [];
    const codexSandboxShims: string[][] = [];
    const sandboxed = new Map<string, boolean>();
    const denialsOf = this.db.prepare(`SELECT path, app, reason FROM secret_open_denials WHERE proc_key = ?`);
    const refusalsOf = this.db.prepare(`SELECT kind FROM egress_refusals WHERE proc_key = ? ORDER BY created_at`);
    const pushDenials = (k: string) => {
      for (const d of denialsOf.all(k) as Array<{ path: string; app: string; reason: string }>) denied.push(d);
      for (const r of refusalsOf.all(k) as Array<{ kind: string }>) {
        const app = this.appOf(k) ?? "a program";
        if (!refusedEgress.some((x) => x.app === app && x.kind === r.kind)) refusedEgress.push({ app, kind: r.kind });
      }
    };
    // Plan 10 §11.8, "Blocked commands": the root's and its descendants'
    // execs of the exec-wrap shim (never an ancestor's: the agent itself),
    // and which of them ran under Codex's network-off sandbox.
    const pushShimExecs = (k: string) => this.pushShimExecsOf(k, shimExecs, codexSandboxShims, sandboxed);
    // ancestors (a tainted parent shell taints the call), then the subtree
    const inherited = this.processSecretTaint(root);
    rows.push(...inherited.rows);
    pushDenials(root);
    pushShimExecs(root);
    const seen = new Set<string>([root]);
    const queue: string[] = [];
    // Plan 13 D9: the guard's children and every claimed one (a claim only
    // widens the tree it names).
    const children = this.db.prepare(`SELECT child_key FROM process_lineage WHERE parent_key = ? UNION SELECT child_key FROM process_lineage_claims WHERE parent_key = ?`);
    for (const c of children.all(root, root) as Array<{ child_key: string }>) queue.push(c.child_key);
    // Plan 13 §9 R1: a process of the tree that received a holder's bytes
    // through a descriptor (from outside the tree too) carries its taint.
    const seenRows = new Set(rows.map((r) => `${r.procKey}\u0000${r.path}`));
    const pushRows = (rs: readonly SecretTaintRow[]) => {
      for (const r of rs) {
        const id = `${r.procKey}\u0000${r.path}`;
        if (!seenRows.has(id)) { seenRows.add(id); rows.push(r); }
      }
    };
    while (queue.length > 0) {
      const k = queue.shift()!;
      if (seen.has(k)) continue;
      seen.add(k);
      pushRows(this.secretRowsOf(k));
      for (const f of this.flowsOf(k)) pushRows(this.processSecretTaint(f).rows);
      pushDenials(k);
      pushShimExecs(k);
      for (const c of children.all(k, k) as Array<{ child_key: string }>) queue.push(c.child_key);
    }
    return {
      level: strictestLevel(rows), rows, denied,
      ...(refusedEgress.length > 0 ? { refusedEgress } : {}),
      ...(shimExecs.length > 0 ? { shimExecs } : {}),
      ...(codexSandboxShims.length > 0 ? { codexSandboxShims } : {}),
    };
  }

  /** Plan 10 §11.12: every raw secret read recorded for a SESSION (every
   *  session when none is given), for a tool call the guard never tied to a
   *  process tree: the strictest level any process of the session held is
   *  the most its output could carry. */
  sessionSecretTaint(session?: string): { level: string | null; rows: SecretTaintRow[] } {
    const rows = ((session !== undefined
      ? this.db.prepare(`SELECT proc_key, path, level, app FROM process_secret_taint WHERE session = ?`).all(session)
      : this.db.prepare(`SELECT proc_key, path, level, app FROM process_secret_taint`).all()) as Array<{ proc_key: string; path: string; level: string; app: string }>)
      .map((r) => ({ procKey: r.proc_key, path: r.path, level: r.level, app: r.app }));
    return { level: strictestLevel(rows), rows };
  }

  /** Plan 13 D6 (a blind tunnel's chunks, 2026-10-07): every process key
   *  `processSecretTaint` would answer tainted, as far as the store knows:
   *  each key with a raw-read row (a claimed one included), and, closed
   *  forward, every child the guard or a claim recorded below one and every
   *  process a flow from one reached. The forward image of the walk
   *  processSecretTaint does backward (parents, claimed parents, flows), so
   *  a key outside this set has no tainted parent, claimed parent or flow
   *  source on record. Every session's (the net-proxy's session key need not
   *  be the guard's): the caller narrows to the live processes.
   *
   *  Asked before every chunk of a blind tunnel, so the walk (~4 ms over
   *  2000 raw-read rows) is kept until the database changes: a write on this
   *  connection moves `total_changes()`, a commit by any other connection
   *  (another store of this arbiter, another arbiter on the same file) moves
   *  `PRAGMA data_version`. Either one, and the walk runs again. */
  secretTaintedProcesses(): string[] {
    const tc = (this.db.prepare(`SELECT total_changes() AS n`).get() as { n: number | bigint }).n;
    const dv = (this.db.prepare(`PRAGMA data_version`).get() as { data_version: number | bigint }).data_version;
    const version = `${dv}:${tc}`;
    if (this.taintedMemo?.version === version) return [...this.taintedMemo.keys];
    const rows = this.db.prepare(
      `WITH RECURSIVE t(k) AS (
         SELECT proc_key FROM process_secret_taint
         UNION
         SELECT l.child_key FROM process_lineage l JOIN t ON l.parent_key = t.k
         UNION
         SELECT c.child_key FROM process_lineage_claims c JOIN t ON c.parent_key = t.k
         UNION
         SELECT f.proc_key FROM process_flows f JOIN t ON f.from_key = t.k
       )
       SELECT k FROM t WHERE k <> ''`,
    ).all() as Array<{ k: string }>;
    const keys = rows.map((r) => r.k);
    this.taintedMemo = { version, keys };
    return [...keys];
  }
  /** secretTaintedProcesses's last walk and the database version it saw. */
  private taintedMemo: { version: string; keys: string[] } | null = null;

  /** Plan 10 §11.9: every process that holds a secret, newest first. */
  listSecretTaint(limit = 100): Array<Omit<SecretTaintRow, "session"> & { session: string | null; since: number }> {
    // Newest first by the store's clock (the order the arbiter handled the
    // reads); `since` is the wall clock's time of the read, for display
    // (a row from before `wall_at`: its stamp, which was the wall clock).
    return (this.db.prepare(`SELECT proc_key, path, level, app, session, created_at, wall_at FROM process_secret_taint ORDER BY created_at DESC LIMIT ?`).all(limit) as Array<{ proc_key: string; path: string; level: string; app: string; session: string | null; created_at: number; wall_at: number | null }>)
      .map((r) => ({ procKey: r.proc_key, path: r.path, level: r.level, app: r.app, session: r.session, since: Math.floor(typeof r.wall_at === "number" ? r.wall_at : r.created_at) }));
  }

  private secretRowsOf(procKey: string, attestedOnly = false): SecretTaintRow[] {
    const q = attestedOnly
      ? `SELECT proc_key, path, level, app, exe, sha256, via, script, script_sha256, session FROM process_secret_taint WHERE proc_key = ? AND claimed IS NULL AND (via IS NULL OR via != 'session')`
      : `SELECT proc_key, path, level, app, exe, sha256, via, script, script_sha256, session FROM process_secret_taint WHERE proc_key = ?`;
    return (this.db.prepare(q).all(procKey) as Array<{ proc_key: string; path: string; level: string; app: string; exe: string | null; sha256: string | null; via: string | null; script: string | null; script_sha256: string | null; session: string | null }>)
      .map((r) => ({
        procKey: r.proc_key, path: r.path, level: r.level, app: r.app,
        ...(r.exe !== null ? { exe: r.exe } : {}),
        ...(r.sha256 !== null ? { sha256: r.sha256 } : {}),
        ...(r.via === "reader" || r.via === "verdict" || r.via === "session" ? { via: r.via } : {}),
        ...(r.script !== null ? { script: r.script } : {}),
        ...(r.script_sha256 !== null ? { scriptSha256: r.script_sha256 } : {}),
        ...(r.session !== null ? { session: r.session } : {}),
      }));
  }

  /** Plan 13 R5: has this process started another program the guard
   *  recorded (a lineage child, the guard's edge or a claimed one: a claim
   *  only makes a cleared script's output secret)? */
  hasChildren(procKey: string): boolean {
    return this.db.prepare(`SELECT 1 FROM process_lineage WHERE parent_key = ? UNION SELECT 1 FROM process_lineage_claims WHERE parent_key = ? LIMIT 1`).get(procKey, procKey) !== undefined;
  }

  taintProcess(procKey: string, originHost: string, session?: string): void {
    this.db.prepare(
      `INSERT OR IGNORE INTO process_taint (proc_key, origin_host, session, created_at)
       VALUES (?, ?, ?, ?)`,
    ).run(procKey, originHost, session ?? null, this.tick());
  }

  /** Record a parent→child spawn edge (reported by the exec chokepoint).
   *  The first edge recorded for a child wins (plan 13 D7): a later report
   *  of another parent is a reparenting (the child's parent died and the
   *  subreaper or init adopted it), and replacing the edge would cut the
   *  child out of the tree it was started in. */
  recordLineage(childKey: string, parentKey: string, session?: string, opts: { claimed?: boolean } = {}): void {
    if (childKey === "" || parentKey === "" || childKey === parentKey) return;
    if (opts.claimed === true) {
      // Plan 13 D9: a claim never takes the guard's "first edge" slot.
      this.db.prepare(
        `INSERT OR IGNORE INTO process_lineage_claims (child_key, parent_key, session, created_at) VALUES (?, ?, ?, ?)`,
      ).run(childKey, parentKey, session ?? null, this.tick());
      return;
    }
    this.db.prepare(
      `INSERT OR IGNORE INTO process_lineage (child_key, parent_key, session, created_at)
       VALUES (?, ?, ?, ?)`,
    ).run(childKey, parentKey, session ?? null, this.tick());
  }

  /** Plan 13 D7: record a process's live ancestor chain (nearest first) as
   *  lineage edges, `procKey → chain[0] → chain[1] → …`, the first edge of
   *  each child winning. This is what links a process forked without an
   *  exec (a subshell) to its parent: it has no event of its own, but every
   *  exec and every secret open below it reports it in its chain. */
  recordLineageChain(procKey: string, chain: readonly string[], session?: string, opts: { claimed?: boolean } = {}): void {
    if (chain.length === 0) return;
    if (opts.claimed === true) {
      // Plan 13 D9: every edge of a claimed chain is a claim of its own.
      this.db.transaction(() => {
        let child = procKey;
        for (const parent of chain) {
          if (typeof parent !== "string" || parent === "" || parent === child) break;
          this.recordLineage(child, parent, session, { claimed: true });
          child = parent;
        }
      })();
      return;
    }
    this.db.transaction(() => this.insertChain(procKey, chain, session))();
  }

  /** recordLineageChain's body, for callers already inside a transaction.
   *  Stops at the first child that already has an edge: the chain above it
   *  was recorded with that edge (every producer reports a chain), and a
   *  differing parent there is a reparenting the first edge already beat. */
  private insertChain(procKey: string, chain: readonly string[], session?: string): void {
    let child = procKey;
    for (const parent of chain) {
      if (typeof parent !== "string" || parent === "" || parent === child) break;
      if (this.stmtParentOf.get(child) !== undefined) break;
      this.recordLineage(child, parent, session);
      child = parent;
    }
  }

  /** Tainted if this process OR any transitive ancestor is tainted. */
  isProcessTainted(procKey: string): IsProcessTaintedResult {
    const seen = new Set<string>();
    const queue: string[] = [procKey];
    while (queue.length > 0) {
      const cur = queue.shift()!;
      if (cur === "" || seen.has(cur)) continue;
      seen.add(cur);
      const hit = this.stmtTaintLookup.get(cur) as { origin_host: string } | undefined;
      if (hit) return { tainted: true, originHost: hit.origin_host };
      queue.push(...this.parentsOf(cur));
    }
    return { tainted: false };
  }

  /** Mark a file's content untrusted-by-origin (written by a tainted process).
   *  Idempotent / first-taint-wins for a given (content_hash, path), like taintProcess. */
  taintFile(args: {
    contentHash: string;
    path: string;
    originHost: string;
    writerProc?: string;
    session?: string;
  }): void {
    this.db.prepare(
      `INSERT OR IGNORE INTO file_taint
         (content_hash, path, origin_host, writer_proc, session, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(
      args.contentHash, args.path, args.originHost,
      args.writerProc ?? null, args.session ?? null, this.tick(),
    );
  }

  /** Untrusted if EITHER the content-hash OR the path is on record (fail-closed). */
  fileTrust(args: { contentHash?: string; path?: string }): FileTrustResult {
    if (!args.contentHash && !args.path) {
      throw new Error("fileTrust: at least one of contentHash or path must be provided");
    }
    const row = this.db.prepare(
      `SELECT origin_host FROM file_taint
       WHERE (? IS NOT NULL AND content_hash = ?) OR (? IS NOT NULL AND path = ?)
       LIMIT 1`,
    ).get(
      args.contentHash ?? null, args.contentHash ?? null,
      args.path ?? null, args.path ?? null,
    ) as { origin_host: string } | undefined;
    if (row) return { untrusted: true, origin: row.origin_host };
    return { untrusted: false };
  }

  /**
   * Record a DECLARED net write (exec-routing.md §8.7a) — Track A's
   * substitute for the kernel fs-supervisor's observed writes: the model-
   * context exec gate saw `curl -o <path>` / `wget -O <path>` / `curl … > <path>`
   * and ALLOWED it, so <path> is about to hold bytes from `originHost`. Rows
   * share the `file_taint` table (one registry, two writers) under a synthetic
   * content hash `declared:<session>:<path>` — there is no content to hash yet.
   * First origin wins per (session, path), like taintFile (monotonic taint).
   * A RELATIVE path is meaningful only in the declaring session's cwd, so it is
   * session-scoped (programTextTrust honours that); an absolute path is global.
   */
  declareNetWrite(args: {
    path: string;
    originHost: string;
    session?: string;
    /** The tool_use id of the declaring command (attribution only). */
    callId?: string;
  }): void {
    this.db.prepare(
      `INSERT OR IGNORE INTO file_taint
         (content_hash, path, origin_host, writer_proc, session, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(
      `declared:${args.session ?? ""}:${args.path}`, args.path, args.originHost,
      args.callId ? `declared:${args.callId}` : "declared", args.session ?? null, this.tick(),
    );
  }

  /**
   * Is this PROGRAM TEXT untrusted-by-origin? (§7a, the deny-side question.)
   * An absolute path matches any row bearing it (declared or kernel-observed,
   * any session). A relative path matches only rows of the SAME session
   * (`session IS ?` — a NULL session pairs with NULL): an exact declared path,
   * or a kernel-observed absolute path ending in `/<path>` (the supervisor
   * records absolute paths; the model writes cwd-relative ones). No match ⇒
   * trusted-as-far-as-we-know — deny on AFFIRMATIVE taint only.
   */
  programTextTrust(args: { path: string; session?: string }): FileTrustResult {
    const path = args.path;
    if (path === "") return { untrusted: false };
    const row = path.startsWith("/")
      ? (this.db.prepare(
          `SELECT origin_host FROM file_taint WHERE path = ? LIMIT 1`,
        ).get(path) as { origin_host: string } | undefined)
      : (this.db.prepare(
          `SELECT origin_host FROM file_taint
           WHERE session IS ?
             AND (path = ? OR (substr(path, 1, 1) = '/' AND substr(path, -length(?)) = ?))
           LIMIT 1`,
        ).get(args.session ?? null, path, `/${path}`, `/${path}`) as { origin_host: string } | undefined);
    if (row) return { untrusted: true, origin: row.origin_host };
    return { untrusted: false };
  }

  close(): void {
    this.db.close();
  }
}

/** The lineage chain a report carries: its `ancestors` (nearest first) when
 *  given, else its single `parentKey` edge. */
export function lineageChain(parentKey: string | undefined, ancestors: readonly string[] | undefined): string[] {
  const chain = (ancestors ?? []).filter((k): k is string => typeof k === "string" && k !== "");
  if (chain.length > 0) return chain;
  return parentKey ? [parentKey] : [];
}

/** The strictest level among the rows. Ranks come from the one lattice
 *  (confidentiality.ts); an unknown stored value parses as no-model there,
 *  so it ranks strictest here too (fail-closed). */
export function strictestLevel(rows: readonly SecretTaintRow[]): string | null {
  let best: string | null = null;
  const rank = (l: string) => confidentialityRank(parseConfidentialityLevel(l));
  for (const r of rows) if (best === null || rank(r.level) > rank(best)) best = r.level;
  return best;
}

