/**
 * transcript-stores.test — how the past-sessions scan finds and opens the
 * stores of OpenCode, Goose and OpenClaw (arbiter/policy/transcript-stores.ts,
 * the file layer of transcript-scan.ts;
 * docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md
 * §3 items 6 and 8, §4):
 *
 * - an agent's SQLite store is opened so that it is never written and never
 *   blocks the agent: a live WAL database is read through its WAL (its
 *   newest rows) while the writer keeps writing, a closed one immutable with
 *   no `-wal`/`-shm` created, a rollback-mode one with no lock the writer
 *   waits on, a corrupt one counted as unreadable;
 * - the stores' places follow each agent's environment;
 * - a transcript is never where a known value is taken from;
 * - the scan over a home holding every store: sessions by agent (a child
 *   session with its parent, Goose's request log not counted as one), the
 *   per-session caps and `--since`, the Mandu windows of the new agents, and
 *   every store byte for byte the same afterwards.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { closeStores, isRunTrace, isStoreFile, openAgentStore, sqliteUriFilenames, storeItems, type OpenStores } from "../../policy/transcript-stores.js";
import { fixtureRecords, layOut, REAL_FIXTURES, realFixtures, rowsToDb } from "../helpers/agent-store-fixtures.js";
import { isTranscriptStorePath, manduWindowsFrom, scanAgentTranscripts, transcriptSources } from "../../policy/transcript-scan.js";
import { SCAN_ONLY_AGENTS } from "../../src/generated/agents.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;
const GH = `${"gh" + "p_"}k3Jd8Qm2Lz7Xw4Rt9Yv6Nb1Cs5Hf0Gp2Ae7Wq`;
const AWS = `${"AK" + "IA"}Q7W2ZRTM9PL4KV8H`;
const J = JSON.stringify;

/** Every file of a directory tree, with a hash of its bytes. */
function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      // A live WAL database's `-shm` by its name only: SQLite's shared-memory
      // index, where every reader (the scan's too) sets its read mark.
      else if (e.name.endsWith("-shm")) out.push(`${p.slice(dir.length)} wal-index`);
      else out.push(`${p.slice(dir.length)} ${createHash("sha256").update(readFileSync(p)).digest("hex")} ${statSync(p).mtimeMs}`);
    }
  };
  walk(dir);
  return out.sort();
}

test("openAgentStore: a live WAL database is read through its WAL, and the writer is never held up", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-st-"));
  try {
    const p = join(dir, "opencode.db");
    const w = new DatabaseSync(p);
    w.exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE t(x); INSERT INTO t VALUES (1), (2);");
    const files = readdirSync(dir).sort();
    const { db, mode } = openAgentStore(p);
    assert.equal(mode, "wal-reader");
    assert.equal((db.prepare("SELECT count(*) AS n FROM t").get() as { n: number }).n, 2, "the rows only the WAL holds are read");
    db.exec("BEGIN");
    db.prepare("SELECT * FROM t").all();
    w.exec("INSERT INTO t VALUES (3)"); // the agent writes while the scan holds a read: no SQLITE_BUSY
    db.exec("COMMIT");
    assert.throws(() => db.exec("INSERT INTO t VALUES (4)"), /readonly|read-only/i, "the scan's connection cannot write");
    db.close();
    w.close();
    assert.deepEqual(files, ["opencode.db", "opencode.db-shm", "opencode.db-wal"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("openAgentStore: a closed database is read immutable, with no -wal or -shm created; a rollback one never blocks its writer", (t) => {
  if (!sqliteUriFilenames()) { t.skip("this Node opens no SQLite URI filename (before 22.15): the next test holds what it does instead"); return; }
  const dir = mkdtempSync(join(tmpdir(), "mdu-st-"));
  try {
    const p = join(dir, "sessions.db");
    const w = new DatabaseSync(p);
    w.exec("PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES (1);");
    w.close();
    const before = snapshot(dir);
    const { db, mode } = openAgentStore(p);
    assert.equal(mode, "immutable");
    assert.equal((db.prepare("SELECT count(*) AS n FROM t").get() as { n: number }).n, 1);
    db.close();
    assert.deepEqual(snapshot(dir), before, "nothing created, nothing changed");
    const q = join(dir, "rollback.db");
    const w2 = new DatabaseSync(q);
    w2.exec("CREATE TABLE t(x); INSERT INTO t VALUES (1);");
    const r = openAgentStore(q);
    r.db.exec("BEGIN");
    r.db.prepare("SELECT * FROM t").all();
    w2.exec("INSERT INTO t VALUES (2)"); // an immutable reader takes no lock
    r.db.exec("COMMIT");
    r.db.close();
    w2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("openAgentStore without URI filenames (Node 22.13, 22.14): a live WAL database is still read; a stopped one is refused, nothing created", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-st-"));
  try {
    const live = join(dir, "live.db");
    const w = new DatabaseSync(live);
    w.exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE t(x); INSERT INTO t VALUES (1);");
    const stopped = join(dir, "stopped.db");
    const w2 = new DatabaseSync(stopped);
    w2.exec("PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES (1);");
    w2.close();
    const rollback = join(dir, "rollback.db");
    const w3 = new DatabaseSync(rollback);
    w3.exec("CREATE TABLE t(x); INSERT INTO t VALUES (1);");
    w3.close();
    const before = snapshot(dir);
    const r = openAgentStore(live, { uri: false });
    assert.equal(r.mode, "wal-reader");
    assert.equal((r.db.prepare("SELECT count(*) AS n FROM t").get() as { n: number }).n, 1, "a plain read-only path reads the WAL");
    r.db.close();
    // A plain read-only open of either would create its -wal and -shm, or lock it: refused.
    assert.throws(() => openAgentStore(stopped, { uri: false }), /Node 22\.15 or later/);
    assert.throws(() => openAgentStore(rollback, { uri: false }), /Node 22\.15 or later/);
    assert.deepEqual(snapshot(dir), before, "nothing created, nothing changed");
    w.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("storeItems: a store that is not a database is counted as unreadable, never thrown", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-st-"));
  const open: OpenStores = new Map();
  try {
    const p = join(dir, "opencode.db");
    writeFileSync(p, "this is not a database");
    const failed = { n: 0 };
    assert.deepEqual(storeItems({ agent: "opencode", kind: "opencode-db", root: p }, 10, { n: 0 }, open, failed), []);
    assert.equal(failed.n, 1);
  } finally {
    closeStores(open);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("storeItems: OpenClaw's run trace beside a session is not a session, and still a store file", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-st-"));
  const open: OpenStores = new Map();
  try {
    mkdirSync(join(dir, "main", "sessions"), { recursive: true });
    writeFileSync(join(dir, "main", "sessions", "s1.jsonl"), J({ type: "message", message: { role: "user", content: "hello" } }) + "\n");
    // OpenClaw 2026.7 and later: each run's compiled context, system prompt and tools among it.
    writeFileSync(join(dir, "main", "sessions", "s1.trajectory.jsonl"), J({ traceSchema: "openclaw-trajectory", type: "context.compiled", data: { messages: [{ role: "user", content: "hello" }] } }) + "\n");
    const items = storeItems({ agent: "openclaw", kind: "openclaw-jsonl", root: dir }, 10, { n: 0 }, open, { n: 0 });
    assert.deepEqual(items.map((i) => i.path), [join(dir, "main", "sessions", "s1.jsonl")]);
    assert.equal(isRunTrace("openclaw-jsonl", join(dir, "main", "sessions", "s1.trajectory.jsonl")), true);
    assert.equal(isTranscriptStorePath(join(dir, "main", "sessions", "s1.trajectory.jsonl"), [{ agent: "openclaw", kind: "openclaw-jsonl", root: dir }]), true, "a known value is never taken from it");
  } finally {
    closeStores(open);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("scanAgentTranscripts over the stores the agents wrote: each planted value by how it reached the model, OpenClaw's mask, every store unchanged", async () => {
  const home = mkdtempSync(join(tmpdir(), "mdu-real-"));
  const writers: DatabaseSync[] = [];
  try {
    const fx = realFixtures();
    const rows = (id: string, kind: string) => fx.filter((f) => f.id === id && f.kind === kind).map((f) => ({ name: f.fixture, recs: fixtureRecords(join(REAL_FIXTURES, f.fixture)) }));
    const share = join(home, ".local", "share");
    // OpenCode 1.x and 2.x in one opencode.db, as a 2.x database migrated from 1.x keeps both.
    mkdirSync(join(share, "opencode"), { recursive: true });
    writers.push(rowsToDb(join(share, "opencode", "opencode.db"), [...rows("opencode", "opencode-db"), ...rows("opencode2", "opencode-db")].flatMap((r) => r.recs)));
    mkdirSync(join(share, "goose", "sessions"), { recursive: true });
    writers.push(rowsToDb(join(share, "goose", "sessions", "sessions.db"), rows("goose", "goose-db")[0]!.recs));
    const logs = join(home, ".local", "state", "goose", "logs");
    mkdirSync(logs, { recursive: true });
    for (const r of rows("goose", "goose-request-log")) layOut("goose-request-log", logs, r.recs, /request-log\.([^.]+)\.jsonl$/.exec(r.name)![1]);
    const agents = join(home, ".openclaw", "agents");
    mkdirSync(agents, { recursive: true });
    layOut("openclaw-jsonl", agents, rows("openclaw", "openclaw-jsonl")[0]!.recs, "fixture-openclaw");
    const w = layOut("openclaw-db", agents, rows("openclaw9", "openclaw-db")[0]!.recs).writer;
    if (w) writers.push(w);
    const before = snapshot(home);
    const cmd = `${"sk-ant-"}mdufixture-cmd-Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;
    const file = `${"sk-ant-"}mdufixture-file-Hf0Gp2Ae7Wq5Cs1Nb6Yv9R`;
    const plain = "mdu-fixture-plain-T4kW9qZr2Lx7";
    const r = await scanAgentTranscripts({
      home, sources: transcriptSources(home),
      known: [{ value: cmd, path: "~/vault/cmd", name: "CMD_KEY" }, { value: file, path: "~/project/.env", name: "ANTHROPIC_API_KEY" }, { value: plain, path: "~/project/.env", name: "PARTNER_TOKEN" }],
    });
    assert.deepEqual(r.sessions, { opencode: 2, goose: 1, openclaw: 2 }, "the request log is not a session");
    assert.equal(r.capped.readFailed, 0);
    const known = (name: string) => r.findings.find((f) => f.kind === "known" && f.source?.name === name);
    // OpenClaw masked both keys before its model saw them (and kept only the mask).
    assert.deepEqual([known("CMD_KEY")?.agents, known("CMD_KEY")?.how], [["goose", "opencode"], { "command-output": 3, "tool-result": 1 }]);
    assert.deepEqual([known("ANTHROPIC_API_KEY")?.agents, known("ANTHROPIC_API_KEY")?.how], [["goose", "opencode"], { "read-file": 2, "command-output": 1, "tool-result": 1 }]);
    assert.deepEqual([known("PARTNER_TOKEN")?.agents, known("PARTNER_TOKEN")?.how], [["goose", "openclaw", "opencode"], { "read-file": 4, "command-output": 1, "tool-result": 1 }]);
    assert.deepEqual(r.risk.skippedPrompts, 1, "Goose's auto mode; OpenCode keeps its allow-all config out of the session");
    assert.deepEqual(snapshot(home), before, "no store was written, no file created");
  } finally {
    for (const w of writers) w.close();
    rmSync(home, { recursive: true, force: true });
  }
});

test("transcriptSources: each agent's store where its own environment puts it", () => {
  // The agents Mandu does not run have their own test (transcript-unwrapped.test.ts).
  const roots = (env: Record<string, string>) => transcriptSources("/home/u", env).filter((s) => s.kind !== undefined && !(SCAN_ONLY_AGENTS as readonly string[]).includes(s.agent)).map((s) => `${s.kind} ${s.root}`);
  assert.deepEqual(roots({}), [
    "opencode-db /home/u/.local/share/opencode/opencode.db",
    "goose-db /home/u/.local/share/goose/sessions/sessions.db",
    "goose-jsonl /home/u/.local/share/goose/sessions",
    "goose-request-log /home/u/.local/state/goose/logs",
    "goose-db /home/u/Library/Application Support/Block.goose/sessions/sessions.db",
    "goose-jsonl /home/u/Library/Application Support/Block.goose/sessions",
    "goose-request-log /home/u/Library/Application Support/Block.goose/logs",
    "openclaw-jsonl /home/u/.openclaw/agents",
    "openclaw-db /home/u/.openclaw/agents",
  ]);
  assert.deepEqual(roots({ XDG_DATA_HOME: "/x/data", XDG_STATE_HOME: "/x/state", GOOSE_PATH_ROOT: "/g", OPENCLAW_STATE_DIR: "/oc" }), [
    "opencode-db /x/data/opencode/opencode.db",
    "goose-db /g/data/sessions/sessions.db",
    "goose-jsonl /g/data/sessions",
    "goose-request-log /g/state/logs",
    "openclaw-jsonl /oc/agents",
    "openclaw-db /oc/agents",
  ]);
  assert.deepEqual(roots({ XDG_DATA_HOME: "rel/data" })[0], "opencode-db /home/u/.local/share/opencode/opencode.db", "a relative XDG directory is not the agent's");
});

test("isTranscriptStorePath: a transcript is never where a known value lives; the agents' login files are", () => {
  const src = transcriptSources("/home/u");
  for (const p of [
    "/home/u/.claude/projects/-home-u-shop/s1.jsonl", "/home/u/.local/share/opencode/opencode.db",
    "/home/u/.local/share/goose/sessions/sessions.db", "/home/u/.local/share/goose/sessions/20250101_1.jsonl",
    "/home/u/.local/state/goose/logs/llm_request.0.jsonl", "/home/u/.openclaw/agents/main/sessions/abc.jsonl",
    "/home/u/.openclaw/agents/main/agent/openclaw-agent.sqlite",
  ]) assert.equal(isTranscriptStorePath(p, src), true, p);
  for (const p of [
    "/home/u/.local/share/opencode/auth.json", "/home/u/.openclaw/agents/main/agent/auth-profiles.json", "/home/u/.openclaw/openclaw.json",
    "/home/u/.local/state/goose/logs/cli/2026-10-01.log", "/home/u/.claude/.credentials.json", "/home/u/shop/.env",
  ]) assert.equal(isTranscriptStorePath(p, src), false, p);
  assert.equal(isStoreFile("openclaw-jsonl", "/r", "/r/main/sessions/sessions.json"), false, "OpenClaw's session index is not a transcript");
});

/** A home with a session of each new agent in each of its stores, the
 *  databases left as running agents keep them (WAL, writer open), which
 *  every Node the scan supports reads. Call the result to close them. */
function storesHome(home: string): () => void {
  const share = join(home, ".local", "share");
  // OpenCode 1.x: a session and its subagent's child session.
  mkdirSync(join(share, "opencode"), { recursive: true });
  const oc = new DatabaseSync(join(share, "opencode", "opencode.db"));
  oc.exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;");
  oc.exec(`CREATE TABLE session (id text PRIMARY KEY, parent_id text, directory text NOT NULL, permission text, time_created integer NOT NULL, time_updated integer NOT NULL);
CREATE TABLE message (id text PRIMARY KEY, session_id text NOT NULL, time_created integer NOT NULL, time_updated integer NOT NULL, data text NOT NULL);
CREATE TABLE part (id text PRIMARY KEY, message_id text NOT NULL, session_id text NOT NULL, time_created integer NOT NULL, time_updated integer NOT NULL, data text NOT NULL);`);
  const t1 = Date.parse("2026-10-01T10:00:00Z");
  oc.prepare("INSERT INTO session VALUES (?,?,?,?,?,?)").run("ses_a", null, join(home, "shop"), J([{ permission: "*", pattern: "*", action: "allow" }]), t1, t1);
  oc.prepare("INSERT INTO session VALUES (?,?,?,?,?,?)").run("ses_b", "ses_a", join(home, "shop"), null, t1, t1);
  oc.prepare("INSERT INTO message VALUES (?,?,?,?,?)").run("msg_1", "ses_a", t1, t1, J({ role: "assistant" }));
  oc.prepare("INSERT INTO part VALUES (?,?,?,?,?,?)").run("prt_1", "msg_1", "ses_a", t1, t1, J({ type: "tool", tool: "bash", state: { status: "completed", input: { command: "cat .env" }, output: `STRIPE_KEY=${STRIPE}`, metadata: { output: `aws=${AWS}`, exit: 0 } } }));
  oc.prepare("INSERT INTO message VALUES (?,?,?,?,?)").run("msg_2", "ses_b", t1 + 1000, t1 + 1000, J({ role: "user" }));
  oc.prepare("INSERT INTO part VALUES (?,?,?,?,?,?)").run("prt_2", "msg_2", "ses_b", t1 + 1000, t1 + 1000, J({ type: "text", text: `child sees ${STRIPE}` }));
  // Goose: sessions.db, an older JSONL session and the request log.
  const gd = join(share, "goose", "sessions");
  mkdirSync(gd, { recursive: true });
  const g = new DatabaseSync(join(gd, "sessions.db"));
  g.exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;");
  g.exec(`CREATE TABLE sessions (id TEXT PRIMARY KEY, working_dir TEXT NOT NULL, goose_mode TEXT NOT NULL DEFAULT 'auto', parent_session_id TEXT, updated_at TIMESTAMP);
CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, role TEXT NOT NULL, content_json TEXT NOT NULL, created_timestamp INTEGER NOT NULL, metadata_json TEXT);`);
  g.prepare("INSERT INTO sessions VALUES (?,?,?,?,?)").run("20261002_1", join(home, "shop"), "auto", null, "2026-10-02 09:00:00");
  g.prepare("INSERT INTO messages (session_id, role, content_json, created_timestamp, metadata_json) VALUES (?,?,?,?,?)").run("20261002_1", "user", J([{ type: "text", text: `push with ${GH}` }]), Date.parse("2026-10-02T09:00:00Z") / 1000, J({ agentVisible: true, userVisible: true }));
  writeFileSync(join(gd, "20250101_1.jsonl"), [J({ working_dir: join(home, "shop") }), J({ role: "user", created: Date.parse("2025-01-01T00:00:00Z") / 1000, content: [{ type: "text", text: "an old hello" }] })].join("\n") + "\n");
  utimesSync(join(gd, "20250101_1.jsonl"), new Date("2025-01-01T00:00:00Z"), new Date("2025-01-01T00:00:00Z"));
  const logs = join(home, ".local", "state", "goose", "logs");
  mkdirSync(logs, { recursive: true });
  writeFileSync(join(logs, "llm_request.0.jsonl"), J({ model_config: { model_name: "m" }, input: { system: `hints: ${GH}`, messages: [] } }) + "\n");
  // OpenClaw: a JSONL session and a 9.x database session.
  const ocl = join(home, ".openclaw", "agents", "main");
  mkdirSync(join(ocl, "sessions"), { recursive: true });
  mkdirSync(join(ocl, "agent"), { recursive: true });
  writeFileSync(join(ocl, "sessions", "s1.jsonl"), [
    J({ type: "session", cwd: join(home, "shop"), timestamp: "2026-10-03T00:00:00Z" }),
    J({ type: "message", timestamp: "2026-10-03T00:00:01Z", message: { role: "toolResult", toolCallId: "t", toolName: "read", content: [{ type: "text", text: `K=${STRIPE}` }], details: { raw: AWS } } }),
  ].join("\n") + "\n");
  writeFileSync(join(ocl, "sessions", "sessions.json"), J({ "agent:main:main": { sessionId: "s1" } }));
  writeFileSync(join(ocl, "agent", "auth-profiles.json"), J({ profiles: {} }));
  const od = new DatabaseSync(join(ocl, "agent", "openclaw-agent.sqlite"));
  od.exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE transcript_events (session_id TEXT NOT NULL, seq INTEGER NOT NULL, event_json TEXT, created_at INTEGER NOT NULL, event_zstd BLOB, PRIMARY KEY (session_id, seq));");
  od.prepare("INSERT INTO transcript_events VALUES (?,?,?,?,?)").run("sid-1", 0, J({ type: "message", timestamp: "2026-10-04T00:00:00Z", message: { role: "user", content: "a 9.x hello" } }), Date.parse("2026-10-04T00:00:00Z"), null);
  return () => { oc.close(); g.close(); od.close(); };
}

test("scanAgentTranscripts: every new store under a home, read and left as it was", async () => {
  const home = mkdtempSync(join(tmpdir(), "mdu-sth-"));
  let close = (): void => {};
  try {
    close = storesHome(home);
    const before = snapshot(home);
    const sources = transcriptSources(home);
    const r = await scanAgentTranscripts({ home, sources, known: [{ value: STRIPE, path: "~/shop/.env", name: "STRIPE_KEY" }] });
    assert.deepEqual(r.sessions, { opencode: 1, goose: 2, openclaw: 2 }, "a child session counts with its parent; the request log is not a session");
    const known = r.findings.find((f) => f.kind === "known")!;
    assert.deepEqual([known.sessions, known.agents, known.how, known.projects], [2, ["openclaw", "opencode"], { "command-output": 1, "your-message": 1, "read-file": 1 }, ["~/shop"]]);
    const gh = r.findings.find((f) => f.kind === "github-token")!;
    assert.deepEqual([gh.sessions, gh.agents, gh.how], [2, ["goose"], { "your-message": 1, context: 1 }], "the request log's system prompt counts as one more place");
    assert.equal(r.findings.some((f) => f.kind === "aws-access-key-id"), false, "OpenCode's metadata and OpenClaw's details never reached the model");
    assert.deepEqual(r.risk, { skippedPrompts: 2, skippedWithSecret: 1, envDumps: 0 }, "OpenCode's allow-all rules and Goose's auto mode");
    assert.equal(r.capped.readFailed, 0);
    assert.deepEqual(snapshot(home), before, "no store was written, no file created");
    const recent = await scanAgentTranscripts({ home, sources, since: Date.parse("2026-10-02T00:00:00Z") });
    assert.deepEqual(recent.sessions, { goose: 1, openclaw: 2 }, "--since reads a database's sessions by their own time");
    const capped = await scanAgentTranscripts({ home, sources, limits: { maxFileBytes: 40 } });
    assert.ok(capped.capped.tooBig >= 1 && (capped.sessions.opencode ?? 0) === 0, "a session over the per-file cap is counted, not read");
  } finally {
    close();
    rmSync(home, { recursive: true, force: true });
  }
});

test("manduWindowsFrom: Mandu's OpenCode, Goose and OpenClaw sessions are windows of those agents", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-ev-"));
  try {
    const line = (o: unknown) => J(o);
    for (const [i, target] of ["opencode", "goose", "openclaw"].entries()) {
      writeFileSync(join(dir, `1-${i}.ndjson`), [line({ kind: "launch_posture", target, ts: "2026-10-01T00:00:00.000Z" }), line({ kind: "session_exit", ts: "2026-10-01T01:00:00.000Z" })].join("\n") + "\n");
    }
    assert.deepEqual(manduWindowsFrom(dir).map((w) => w.agent).sort(), ["goose", "openclaw", "opencode"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
