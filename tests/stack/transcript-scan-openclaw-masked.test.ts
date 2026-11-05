/**
 * transcript-scan-openclaw-masked — `mandu scan` over OpenClaw's own stores
 * as the real agents wrote them (the reader fixtures,
 * arbiter/test/fixtures/transcripts/real: OpenClaw 2026.7.1-2's JSONL store
 * and 2026.9.9's SQLite store, each driven against a scripted model with
 * two planted keys, `tests/transcript-fixtures/generate.ts`), through the
 * launcher's `runScan` and its production call against a real
 * ArbiterServer (confidentiality-plan-17-past-sessions-scan.md §6).
 *
 * Both stores keep the keys only as OpenClaw's mask (`sk-ant…Nb4C`). What
 * they mean differs by version, and the scan must tell them apart:
 *
 *   - 2026.7.1-2 sent the keys themselves to the model and masked only what
 *     it saved: a leak, reported as the `.env`'s own value, its session
 *     counted as found by the mask (`matchedMasked`), the report saying so;
 *   - 2026.9.9 masked them before the model too: no leak of the value.
 *
 * The 2026.7.1-2 session is laid out as the Control UI's New session leaves
 * it, renamed `<session>.jsonl.reset.<time>`: the scan reads it as a
 * session. No value and no mask is in any answer; every store is unchanged.
 * Axes stated: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import zlib from "node:zlib";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { fixtureRecords, layOut, REAL_FIXTURES, realFixtures } from "../../arbiter/test/helpers/agent-store-fixtures.js";
import { realScanDeps, runScan, type ScanWire } from "../../launcher/src/scan-command.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../../arbiter/test/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

// The fixtures' planted keys (generate.ts), assembled so no file here holds one whole.
const CMD = `${"sk-ant-"}mdufixture-cmd-Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;
const FILE = `${"sk-ant-"}mdufixture-file-Hf0Gp2Ae7Wq5Cs1Nb6Yv9R`;
const MASKS = [`${"sk-ant"}…Nb4C`, `${"sk-ant"}…Yv9R`];

/** Every file under `dir` with its sha256 (a store must be the same after). */
function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (d: string): void => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      // a live WAL database's `-shm` by its name only: SQLite's shared-memory
      // index, where every reader (the scan's too) sets its read mark
      else if (n.endsWith("-shm")) out[p] = "wal-index";
      else out[p] = createHash("sha256").update(readFileSync(p)).digest("hex");
    }
  };
  walk(dir);
  return out;
}

test("mandu scan over OpenClaw's real stores: 2026.7.1-2's saved mask is the key it sent, reported as your secret and said to be found by the mask, in a reset session too; 2026.9.9's is not a leak", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-scan-ocmask-"));
  const home = join(dir, "home");
  const proj = join(home, "project");
  mkdirSync(proj, { recursive: true });
  // the keys where they live now: the project's .env (the scan's known values)
  writeFileSync(join(proj, ".env"), `ANTHROPIC_API_KEY=${FILE}\nDEPLOY_API_KEY=${CMD}\n`);
  const agents = join(home, ".openclaw", "agents");
  mkdirSync(agents, { recursive: true });
  const rows = (id: string, kind: string) => realFixtures().filter((f) => f.id === id && f.kind === kind).map((f) => fixtureRecords(join(REAL_FIXTURES, f.fixture)));
  layOut("openclaw-jsonl", agents, rows("openclaw", "openclaw-jsonl")[0]!, "fixture-openclaw");
  // the Control UI's New session (sessions.reset) renamed it
  const sessions = join(agents, "main", "sessions");
  renameSync(join(sessions, "fixture-openclaw.jsonl"), join(sessions, "fixture-openclaw.jsonl.reset.2026-10-25T01-41-19.422Z"));
  // left open, as a running Gateway keeps its store (WAL in use): a Node
  // before 22.15 (the floor) reads only such a database (openAgentStore)
  const writer = layOut("openclaw-db", agents, rows("openclaw9", "openclaw-db")[0]!).writer;
  const before = snapshot(join(home, ".openclaw"));

  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const deps = { ...realScanDeps, arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }), keep: undefined, dashboards: () => [] };
  const env = { HOME: home, MANDU_HOME: join(home, ".mandu"), PATH: process.env["PATH"] ?? "/usr/bin:/bin" };
  const run = async (args: string[]): Promise<{ code: number; out: string }> => {
    const out: string[] = [];
    const code = await runScan(args, env, {} as Layout, deps, { out: (s) => out.push(s), err: () => {} });
    return { code, out: out.join("") };
  };
  try {
    const json = await run(["--json"]);
    assert.equal(json.code, 0);
    const r = JSON.parse(json.out) as ScanWire;
    assert.deepEqual(r.sessions, { openclaw: 2 }, "the reset session and 2026.9.9's");
    const mine = (name: string) => r.findings.find((f) => f.kind === "known" && f.source?.name === name);
    for (const [name, how] of [["ANTHROPIC_API_KEY", "read-file"], ["DEPLOY_API_KEY", "command-output"]] as const) {
      const f = mine(name);
      assert.ok(f, `${name}: reported as your secret: ${JSON.stringify(r.findings.map((x) => [x.kind, x.source?.name]))}`);
      assert.equal(f!.sessions, 1, `${name}: 2026.7.1-2's session only (2026.9.9 masked it before the model)`);
      assert.deepEqual(f!.how, { [how]: 1 });
      assert.equal(f!.matchedMasked, 1, `${name}: found by the mask`);
      assert.equal(f!.source?.path, "~/project/.env");
    }
    const text = await run([]);
    assert.equal(text.code, 0);
    assert.match(text.out, /✗ 2 of your secrets leaked to the AI/);
    assert.match(text.out, /That session: found by the masked copy OpenClaw saved \(the value's first 6 and last 4 characters\); OpenClaw 2026\.7 and earlier sent the value itself to the AI and masked only what it saved\./);
    const all = await run(["--all"]);
    for (const [where, s] of [["--json", json.out], ["report", text.out], ["--all", all.out]] as const) {
      for (const v of [CMD, FILE]) for (let i = 0; i + 8 <= v.length; i++) {
        const piece = v.slice(i, i + 8);
        if (piece.startsWith("sk-ant-")) continue; // the format's public prefix
        assert.ok(!s.includes(piece), `${where} holds "${piece}"`);
      }
      for (const m of MASKS) assert.ok(!s.includes(m), `${where} holds OpenClaw's mask ${m}`);
    }
    assert.deepEqual(snapshot(join(home, ".openclaw")), before, "no store was written");
  } finally {
    await server.close();
    writer?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mandu scan over an OpenClaw 2026.8+ store whose tool result is zstd-compressed: read where this Node decompresses zstd (22.15 on), else the session said not read in full and no clean ✓", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-scan-oczstd-"));
  const home = join(dir, "home");
  const proj = join(home, "project");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, ".env"), `DEPLOY_API_KEY=${CMD}\n`);
  const agentDir = join(home, ".openclaw", "agents", "main", "agent");
  mkdirSync(agentDir, { recursive: true });
  // as a running Gateway keeps it: WAL in use, the writer open
  const db = new DatabaseSync(join(agentDir, "openclaw-agent.sqlite"));
  db.exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE transcript_events (session_id TEXT NOT NULL, seq INTEGER NOT NULL, event_json TEXT, created_at INTEGER NOT NULL, event_zstd BLOB, event_utf8_bytes INTEGER, PRIMARY KEY (session_id, seq));");
  const t0 = Date.parse("2026-10-25T00:00:00Z");
  const ev = (o: unknown): string => JSON.stringify(o);
  db.prepare("INSERT INTO transcript_events VALUES (?,?,?,?,?,?)").run("s", 0, ev({ type: "session", version: 4, id: "s", timestamp: "2026-10-25T00:00:00Z", cwd: proj }), t0, null, null);
  db.prepare("INSERT INTO transcript_events VALUES (?,?,?,?,?,?)").run("s", 1, ev({ type: "message", timestamp: "2026-10-25T00:00:01Z", message: { role: "user", content: [{ type: "text", text: "why does the deploy fail?" }] } }), t0 + 1, null, null);
  const result = ev({ type: "message", timestamp: "2026-10-25T00:00:03Z", message: { role: "toolResult", toolCallId: "c1", toolName: "exec", content: [{ type: "text", text: `deploy: using key ${CMD}\n${"deploy: retrying\n".repeat(80)}` }] } });
  const zstd = (zlib as unknown as { zstdCompressSync?: (b: Buffer) => Buffer }).zstdCompressSync;
  db.prepare("INSERT INTO transcript_events VALUES (?,?,?,?,?,?)").run("s", 2, null, t0 + 3, zstd ? zstd(Buffer.from(result)) : Buffer.from("zstd this Node cannot read"), result.length);
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const deps = { ...realScanDeps, arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }), keep: undefined, dashboards: () => [] };
  const env = { HOME: home, MANDU_HOME: join(home, ".mandu"), PATH: process.env["PATH"] ?? "/usr/bin:/bin" };
  const run = async (args: string[]): Promise<string> => {
    const out: string[] = [];
    assert.equal(await runScan(args, env, {} as Layout, deps, { out: (s) => out.push(s), err: () => {} }), 0);
    return out.join("");
  };
  try {
    const r = JSON.parse(await run(["--json"])) as ScanWire;
    const text = await run([]);
    assert.deepEqual(r.sessions, { openclaw: 1 });
    if (zstd) {
      assert.equal(r.capped.compressed ?? 0, 0);
      assert.ok(r.findings.some((f) => f.kind === "known" && f.source?.name === "DEPLOY_API_KEY"), "the compressed tool result was read: the key found");
      assert.match(text, /✗ 1 of your secrets leaked to the AI/);
    } else {
      assert.equal(r.capped.compressed, 1);
      assert.match(text, /note: 1 OpenClaw session not read in full: OpenClaw keeps its longer messages compressed, and Mandu reads those on Node 22\.15 or later/);
      assert.match(text, /! None of your secrets leaked to the AI in what Mandu could read/);
      assert.doesNotMatch(text, /✓ None of your secrets leaked/);
    }
    for (const s of [JSON.stringify(r), text]) assert.ok(!s.includes(CMD.slice(10)), "no value in any answer");
  } finally {
    await server.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
