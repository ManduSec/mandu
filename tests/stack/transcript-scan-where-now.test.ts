/**
 * transcript-scan-where-now e2e — where one of your secrets' real value sits
 * now (confidentiality-plan-17-past-sessions-scan.md §3 item 15; dashboard.md
 * §4.25ai *Where the real value is now*, the lineage mock's ★2). The
 * PRODUCTION path end to end:
 *
 *   1. the launcher's `runScan` with the real `realScanDeps`, the scan in a
 *      REAL ArbiterServer (the throwaway's role), over a fixture home where
 *      a Claude Code session without Mandu ran a command that printed a
 *      project `.env`'s passphrase, and a later session under Mandu (its
 *      response ids in Mandu's event store, `mdu-where-1`) printed it again;
 *   2. the kept file has the finding's places: the session without Mandu's
 *      transcript first, then the one under Mandu with its Mandu session;
 *   3. a REAL DashboardServer reads it: GET /api/scan/item/f0 answers where
 *      it belongs, the AI service that got it ("Can't be taken back"), and
 *      each chat history "Still there" (the one under Mandu "on your
 *      computer only", linked to its session); once the person deletes the
 *      first transcript, the next read says it is gone; the cached head
 *      never looks at a file;
 *   4. on the served Scan page (jsdom) the address `?item=f0` (a session
 *      card's earlier leak) opens that row with its places drawn;
 *   5. the scan only reads: both transcripts are byte for byte as they were;
 *   6. the oracle: no 8-character run of the planted value in the report,
 *      the kept file, any dashboard body or drawn page, or the arbiter's log.
 * Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { realScanDeps, runScan } from "../../launcher/src/scan-command.js";
import { lastScanPath } from "../../launcher/src/scan-kept.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import type { EventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

// A passphrase of no vendor's format, named so the scan counts it a credential.
const VALUE = "Juniper-Harbor-6038-Wren-where";
const CMD = "DEBUG=1 sh bin/sync-orders.sh";

function assertNoValue(where: string, text: string): void {
  for (let i = 0; i + 8 <= VALUE.length; i++) {
    const piece = VALUE.slice(i, i + 8);
    assert.ok(!text.includes(piece), `${where} holds "${piece}" of the planted value`);
  }
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** One Claude Code session: the command, its output with the value, the
 *  model's answer; each response with its id. */
function session(proj: string, day: string, ids: [string, string]): string {
  const line = (o: unknown): string => JSON.stringify(o);
  return [
    line({ type: "user", timestamp: `${day}T00:36:00Z`, cwd: proj, message: { role: "user", content: "Our order sync broke. Run it with debug output and fix it." } }),
    line({ type: "assistant", timestamp: `${day}T00:37:00Z`, cwd: proj, message: { id: ids[0], role: "assistant", content: [{ type: "tool_use", id: "t1", name: "Bash", input: { command: CMD } }] } }),
    line({ type: "user", timestamp: `${day}T00:37:01Z`, cwd: proj, message: { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: `sync: user=bakery pass=${VALUE}\nsync: 401 Unauthorized` }] } }),
    line({ type: "assistant", timestamp: `${day}T00:37:05Z`, cwd: proj, message: { id: ids[1], role: "assistant", content: [{ type: "text", text: "The script reads ORDERHUB_PASSWORD; the file has ORDERHUB_PASSPHRASE." }] } }),
  ].join("\n") + "\n";
}

const noSessions: EventSource = {
  async listSessions() { return []; },
  async readEvents() { return []; },
  subscribe() { return () => {}; },
  close() {},
} as unknown as EventSource;

test("mandu scan keeps where your secret's real value is now; the Scan page shows each place, still there or gone, with the session under Mandu linked; the scan changes nothing", { timeout: 120_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-scan-where-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const proj = join(home, "app");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, ".env"), `ORDERHUB_USER=bakery\nORDERHUB_PASSPHRASE=${VALUE}\n`);
  const cc = join(home, ".claude", "projects", "-home-app");
  mkdirSync(cc, { recursive: true });
  const before = join(cc, "before.jsonl");
  const later = join(cc, "later.jsonl");
  writeFileSync(before, session(proj, "2026-10-27", ["msg_01BeforeMandu000001", "msg_01BeforeMandu000002"]));
  writeFileSync(later, session(proj, "2026-10-28", ["msg_01UnderMandu0000001", "msg_01UnderMandu0000002"]));
  const transcripts = [readFileSync(before), readFileSync(later)];
  // Mandu's event store: the later session ran under Mandu, its proxy
  // recorded both response ids.
  const events = join(home, ".mandu", "events");
  mkdirSync(events, { recursive: true });
  const ev = (o: unknown): string => JSON.stringify(o);
  writeFileSync(join(events, "mdu-where-1.ndjson"), [
    ev({ kind: "launch_posture", target: "claude", ts: "2026-10-28T00:30:00.000Z" }),
    ev({ kind: "tllm_call", ts: "2026-10-28T00:37:00.000Z", model: { id: "claude-x", responseId: "msg_01UnderMandu0000001" } }),
    ev({ kind: "tllm_call", ts: "2026-10-28T00:37:05.000Z", model: { id: "claude-x", responseId: "msg_01UnderMandu0000002" } }),
    ev({ kind: "session_exit", ts: "2026-10-28T01:00:00.000Z" }),
  ].join("\n") + "\n");
  const env = { HOME: home, MANDU_HOME: join(home, ".mandu"), PATH: process.env["PATH"] ?? "/usr/bin:/bin" };
  const logs: string[] = [];
  const scanSock = join(dir, "scan.sock");
  const scanArb = new ArbiterServer({
    socketPath: scanSock, dbPath: join(dir, "scan.sqlite"), eventDir: join(dir, "scan-events"),
    log: (m) => logs.push(m), confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await scanArb.listen();
  const deps = {
    ...realScanDeps,
    arbiter: async () => ({ sock: scanSock, kind: "throwaway" as const, axisOn: true, stop: async () => {} }),
    keep: { ...realScanDeps.keep!, resident: async () => null },
  };
  let dash: DashboardServer | null = null;
  try {
    // ── 1, 2: the scan and the kept places ──
    const out: string[] = [];
    const err: string[] = [];
    const code = await runScan([], env, {} as Layout, deps, { out: (s) => out.push(s), err: (s) => err.push(s) });
    const report = out.join("");
    assert.equal(code, 0, err.join(""));
    const keptText = readFileSync(lastScanPath(env, home), "utf8");
    const rec = JSON.parse(keptText) as { findings: Array<{ kind: string; preview: string; places?: unknown[] }> };
    const f = rec.findings.find((x) => x.kind === "known" && x.preview === "ORDERHUB_PASSPHRASE in ~/app/.env");
    assert.ok(f, JSON.stringify(rec.findings.map((x) => x.preview)));
    assert.deepEqual(f.places, [
      { agent: "claude-code", file: "~/.claude/projects/-home-app/before.jsonl", mandu: "without", sessions: 1, first: "2026-10-27T00:37:01.000Z", last: "2026-10-27T00:37:01.000Z" },
      { agent: "claude-code", file: "~/.claude/projects/-home-app/later.jsonl", mandu: "under", sessions: 1, first: "2026-10-28T00:37:01.000Z", last: "2026-10-28T00:37:01.000Z", manduSessions: ["mdu-where-1"] },
    ]);

    // ── 3: the dashboard's row ──
    dash = new DashboardServer({ source: noSessions, fileBrowserHome: home, configEnv: env, log: () => {}, ...ADMIN_OPTS });
    const base = `http://127.0.0.1:${await dash.listen(0)}`;
    const bodies: string[] = [];
    const get = async (path: string) => {
      const r = await pageFetch(base + path);
      const text = await r.text();
      bodies.push(text);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return { status: r.status, body: JSON.parse(text) as any };
    };
    const head = await get("/api/scan");
    assert.equal(head.status, 200);
    const yours = head.body.scan.sections.find((s: { id: string }) => s.id === "yours");
    assert.equal(yours.items[0].id, "f0");
    assert.equal(yours.items[0].title, "ORDERHUB_PASSPHRASE in ~/app/.env");
    type Row = { kind: string; where: string; file: string | null; now: string; tone: string; sessions: string[] };
    const rowsNow = async (): Promise<Row[]> => {
      const item = await get("/api/scan/item/f0");
      assert.equal(item.status, 200);
      return item.body.detail.where.rows as Row[];
    };
    assert.deepEqual((await rowsNow()).map((r) => [r.kind, r.where, r.file, r.now, r.tone, r.sessions]), [
      ["belongs", "Where it belongs", "~/app/.env", "You keep it here", "plain", []],
      ["provider", "Anthropic", null, "Can't be taken back", "bad", []],
      ["history", "Claude Code's chat history", "~/.claude/projects/-home-app/before.jsonl", "Still there", "bad", []],
      ["under", "Claude Code's chat history", "~/.claude/projects/-home-app/later.jsonl", "Still there, on your computer only", "ok", ["mdu-where-1"]],
    ]);

    // ── 4: the address a session card's earlier leak opens ──
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const where = (doc: any) => doc.querySelector('.scan-item[data-id="f0"] .scan-where');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, "/scan?item=f0", (doc: any) => !!where(doc), async (doc: any) => {
      const rows = [...where(doc).querySelectorAll(".scan-where-row")] as Array<{ dataset: { kind: string }; textContent: string | null; querySelector: (s: string) => { getAttribute: (a: string) => string | null } | null }>;
      assert.deepEqual(rows.map((r) => r.dataset.kind), ["belongs", "provider", "history", "under"]);
      assert.match(rows[2]!.textContent ?? "", /before\.jsonl.*Still there/);
      assert.equal(rows[3]!.querySelector("a.scan-where-session")!.getAttribute("href"), "/agents/mdu-where-1");
      assert.equal(doc.querySelector('.scan-item[data-id="f0"] details.scan-more').open, true);
      bodies.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // ── 5: the scan changed nothing; the person deletes a transcript ──
    assert.deepEqual([readFileSync(before), readFileSync(later)], transcripts, "the scan only reads");
    unlinkSync(before);
    assert.deepEqual((await rowsNow()).filter((r) => r.kind === "history").map((r) => [r.now, r.tone]), [["Gone from this computer", "ok"]]);
    assert.equal(bodies.slice(0, 1).join("").includes("Still there"), false, "the head never looks at a file");

    // ── 6: the oracle ──
    assertNoValue("the report", report + err.join(""));
    assertNoValue("the kept file", keptText);
    for (const b of bodies) assertNoValue("a dashboard body", b);
    assertNoValue("the arbiter's log", logs.join("\n"));
  } finally {
    if (dash) await dash.close();
    await scanArb.close();
  }
});
