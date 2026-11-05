/**
 * scan-pages — the Scan page's reads over a real DashboardServer and a kept
 * scan at about a real machine's scale (dashboard.md §4.25ai *A long scan,
 * in pages*; large-scan-fixture.ts, written as the launcher keeps it under
 * a temp MANDU_HOME, with a planted value in fields the record never has):
 *
 *   - GET /api/scan is the head: each section's count and first rows, no
 *     examples, a fraction of the whole page's 2.8 MB;
 *   - GET /api/scan/section/<id>?after= pages a section to its end, and
 *     `q` finds rows past the head over the whole section;
 *   - GET /api/scan/item/<id> is one row's examples;
 *   - a section or a row the page does not have, a path among them, is a
 *     404; a `rev` of another scan is a 409 (`changed`), and a scan kept
 *     since shows on the next read (the cache follows the file);
 *   - the file is read once while it is unchanged;
 *   - behind the sign-in gate, signed out, each answers 401 before it runs;
 *     with the account's credentials, 200;
 *   - before any scan (no file kept) the head is the step and the line
 *     under it, "This page shows what it found when it finishes." (§4.25ai
 *     *Before any scan, the step comes first*), Home's card without it;
 *     once a scan is kept the next read has no such line, and its sections;
 *   - the oracle: no 8-character run of the planted value in any answer.
 * Axes: none (display only; the record is a `secrets`-mode scan, no arbiter,
 * no model). Mandu-new test.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DashboardServer, type DashboardServerOptions } from "../../src/server.js";
import type { EventSource } from "../../src/event-source.js";
import { ADMIN_OPTS } from "../unit/admin-session.js";
import { largeScanRecord } from "../unit/view-model/large-scan-fixture.js";
import { scanItemIdOf } from "../../src/view-model/last-scan.js";


// Assembled at run time: this file holds no credential-shaped literal.
const PLANT = `${"sk" + "_live_"}ScanPagesOracle0123456789`;
const noSessions = {
  async listSessions() { return []; },
  async readEvents() { return []; },
  subscribe() { return () => {}; },
  close() {},
} as unknown as EventSource;

const dir = mkdtempSync(join(tmpdir(), "mdu-scan-pages-"));
after(() => rmSync(dir, { recursive: true, force: true }));

function homeWith(rec: unknown): { home: string; mh: string; file: string } {
  const root = mkdtempSync(join(dir, "h-"));
  const home = join(root, "home");
  const mh = join(root, "mh");
  mkdirSync(join(mh, "state"), { recursive: true });
  mkdirSync(home, { recursive: true });
  const file = join(mh, "state", "last-scan.json");
  writeFileSync(file, JSON.stringify(rec), { mode: 0o600 });
  return { home, mh, file };
}

async function serve(h: { home: string; mh: string }, extra: Partial<DashboardServerOptions> = {}): Promise<{ base: string; dash: DashboardServer }> {
  const dash = new DashboardServer({ source: noSessions, fileBrowserHome: h.home, configEnv: { HOME: h.home, MANDU_HOME: h.mh }, log: () => {}, ...ADMIN_OPTS, ...extra });
  return { base: `http://127.0.0.1:${await dash.listen(0)}`, dash };
}

function noValue(where: string, text: string): void {
  for (let i = 0; i + 8 <= PLANT.length; i++) {
    const piece = PLANT.slice(i, i + 8);
    if (piece !== "sk_live_") assert.ok(!text.includes(piece), `${where} holds "${piece}" of the planted value`);
  }
}

test("the head, a section's pages and its query, a row's examples; 404, 409; read once; no value in any answer", async () => {
  const h = homeWith(largeScanRecord({ plant: PLANT }));
  const { base, dash } = await serve(h);
  const texts: Array<[string, string]> = [];
  const get = async (path: string): Promise<{ status: number; body: any }> => {
    const res = await fetch(`${base}/api/${path}`);
    const text = await res.text();
    texts.push([path, text]);
    return { status: res.status, body: JSON.parse(text) };
  };
  try {
    const head = await get("scan");
    assert.equal(head.status, 200);
    const scan = head.body.scan;
    const headBytes = Buffer.byteLength(texts[0]![1]);
    assert.ok(headBytes < 200_000, `the head is small (${headBytes} B; the whole page was 2.8 MB)`);
    assert.equal(typeof scan.rev, "string");
    assert.equal(scan.pageRows, 25);
    const named = scan.sections.find((s: { id: string }) => s.id === "named");
    assert.deepEqual([named.total, named.items.length, named.next], [635, 25, 25]);
    assert.ok(!("detail" in named.items[0]) && !("filter" in named.items[0]));

    // The section to its end, each row once.
    const ids: string[] = named.items.map((i: { id: string }) => i.id);
    let next: number | null = named.next;
    while (next !== null) {
      const p = await get(`scan/section/named?after=${next}&rev=${scan.rev}`);
      assert.equal(p.status, 200);
      ids.push(...p.body.items.map((i: { id: string }) => i.id));
      next = p.body.next;
    }
    assert.equal(ids.length, 635);
    assert.equal(new Set(ids).size, 635);

    // The query finds a row the head never sent.
    const lastTitle = "DB_PASSWORD_634=…";
    const q = await get(`scan/section/named?q=${encodeURIComponent(lastTitle.toUpperCase())}&rev=${scan.rev}`);
    assert.equal(q.status, 200);
    assert.equal(q.body.q, lastTitle.toLowerCase());
    assert.ok(q.body.items.some((i: { title: string }) => i.title === lastTitle), "found past the head");
    assert.ok(!named.items.some((i: { title: string }) => i.title === lastTitle));

    // A row's examples.
    const row = scan.sections.find((s: { id: string }) => s.id === "yours").items[0];
    const item = await get(`scan/item/${row.id}?rev=${scan.rev}`);
    assert.equal(item.status, 200);
    assert.equal(item.body.id, row.id);
    assert.ok(item.body.detail.groups[0].examples.length > 0);

    // What the page does not have: a 404, a path never read.
    for (const path of ["scan/section/nope", "scan/section/kept", "scan/item/f99999", "scan/item/..%2F..%2Fetc%2Fpasswd", "scan/item/%2Fetc%2Fpasswd", "scan/section/..%2Fyours"]) {
      const r = await get(path);
      assert.equal(r.status, 404, path);
      assert.ok(!texts[texts.length - 1]![1].includes("root:"), `${path} reads no file`);
    }

    // Read once while unchanged (the head, every page, the item, the 404s).
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cache = (dash as any).scanCache as { reads: number };
    assert.equal(cache.reads, 1, "the kept scan was read once");

    // A scan kept since: an old rev is refused, the new head is read.
    writeFileSync(h.file, JSON.stringify(largeScanRecord({ plant: PLANT, named: 10 })), { mode: 0o600 });
    utimesSync(h.file, new Date(), new Date(Date.now() + 5_000));
    const stale = await get(`scan/item/${row.id}?rev=${scan.rev}`);
    assert.equal(stale.status, 409);
    assert.equal(stale.body.changed, true);
    const staleSection = await get(`scan/section/named?after=25&rev=${scan.rev}`);
    assert.equal(staleSection.status, 409);
    const again = await get("scan");
    assert.notEqual(again.body.scan.rev, scan.rev);
    assert.equal(again.body.scan.sections.find((s: { id: string }) => s.id === "named").total, 10);
    assert.equal(cache.reads, 2);
    // Home's card reads the same cache.
    await get("home");
    assert.equal(cache.reads, 2, "Home's poll does not read the file again");

    for (const [path, text] of texts) noValue(path, text);
  } finally {
    await dash.close();
  }
});

test("before any scan the head is the step and its line; once a scan is kept, the next read has neither and draws the findings", async () => {
  const h = homeWith(null);
  rmSync(h.file);
  const { base, dash } = await serve(h);
  const texts: string[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const get = async (path: string): Promise<any> => {
    const res = await fetch(`${base}/api/${path}`);
    const text = await res.text();
    texts.push(text);
    assert.equal(res.status, 200, path);
    return JSON.parse(text);
  };
  try {
    const none = (await get("scan")).scan;
    assert.equal(none.ran, false);
    assert.deepEqual(none.againParts, [{ kind: "text", text: "Run it in a terminal: " }, { kind: "code", text: "mandu scan", run: true }]);
    assert.equal(none.stepNote, "This page shows what it found when it finishes.");
    assert.deepEqual(none.sections, []);
    assert.match(none.stopParts.map((p: { text: string }) => p.text).join(""), /^To keep your secrets from the AI from now on, start your agent with /);
    const card = (await get("home")).scan;
    assert.equal(card.ran, false);
    assert.equal("stepNote" in card, false, "Home's card is not changed");

    writeFileSync(h.file, JSON.stringify(largeScanRecord({ plant: PLANT, named: 3 })), { mode: 0o600 });
    const kept = (await get("scan")).scan;
    assert.equal(kept.ran, true);
    assert.equal(kept.stepNote, null);
    assert.deepEqual(kept.againParts.map((p: { text: string }) => p.text), ["Run it again: ", "mandu scan"]);
    assert.ok(kept.sections.find((s: { id: string }) => s.id === "yours").items.length > 0, "the findings");
    assert.doesNotMatch(texts[texts.length - 1]!, /shows what it found when it finishes/);
    for (const text of texts) noValue("an answer", text);
  } finally {
    await dash.close();
  }
});

test("behind the sign-in gate, signed out, each Scan read answers 401 before it runs; with the account, 200", async () => {
  const h = homeWith(largeScanRecord({ known: 1, looks: 30, named: 30, plant: PLANT }));
  const { base, dash } = await serve(h, { basicAuth: { user: "u", password: "scan pass words" } });
  const basic = `Basic ${Buffer.from("u:scan pass words").toString("base64")}`;
  try {
    for (const path of ["scan", "scan/section/looks?after=25", "scan/section/looks?q=ghp", "scan/item/f0"]) {
      const res = await fetch(`${base}/api/${path}`, { redirect: "manual" });
      assert.equal(res.status, 401, path);
      const text = await res.text();
      assert.match(JSON.parse(text).error, /sign in required/);
      noValue(path, text);
      const ok = await fetch(`${base}/api/${path}`, { headers: { Authorization: basic } });
      assert.equal(ok.status, 200, `${path} with the account`);
      noValue(path, await ok.text());
    }
  } finally {
    await dash.close();
  }
});

test("a row's places (§4.25ai *Where the real value is now*): the server looks whether each chat-history file is still there, a regular file under the home, its link not followed; a `..` is never looked at", async () => {
  const placed = (file: string) => ({ agent: "claude-code", file, mandu: "without", first: "2026-10-27T00:37:00.000Z", sessions: 1 });
  const rec = {
    version: 1, ranAt: "2026-10-28T09:00:00.000Z", sessions: { "claude-code": 5 }, duringMandu: 0, known: 1, dropped: 0,
    capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 }, suggestions: null,
    findings: [{
      kind: "known", preview: "TOKEN in ~/app/.env", source: { path: "~/app/.env", name: "TOKEN" }, sessions: 5, agents: ["claude-code"], how: { "command-output": 5 }, projects: [], duringMandu: 0,
      examples: [{ at: "2026-10-27T00:37:00.000Z", agent: "claude-code", how: "command-output", command: "cat .env", mandu: "without" }],
      places: [placed("~/.claude/projects/p/here.jsonl"), placed("~/.claude/projects/p/gone.jsonl"), placed("~/.claude/projects/p/link.jsonl"), placed("~/.claude/projects/../p/here.jsonl"), placed("~/.claude/projects/p")],
    }],
  };
  const h = homeWith(rec);
  mkdirSync(join(h.home, ".claude", "projects", "p"), { recursive: true });
  writeFileSync(join(h.home, ".claude", "projects", "p", "here.jsonl"), "{}\n");
  symlinkSync(join(h.home, ".claude", "projects", "p", "here.jsonl"), join(h.home, ".claude", "projects", "p", "link.jsonl"));
  const { base, dash } = await serve(h);
  try {
    const res = await fetch(`${base}/api/scan/item/f0`);
    assert.equal(res.status, 200);
    const rows = ((await res.json()) as { detail: { where: { rows: Array<{ kind: string; file: string | null; now: string }> } } }).detail.where.rows;
    assert.deepEqual(rows.filter((r) => r.kind === "history").map((r) => [r.file, r.now]), [
      ["~/.claude/projects/p/here.jsonl", "Still there"],
      ["~/.claude/projects/p/gone.jsonl", "Gone from this computer"],
      ["~/.claude/projects/p/link.jsonl", "Gone from this computer"],
      ["~/.claude/projects/../p/here.jsonl", "In it when the scan ran"],
      ["~/.claude/projects/p", "Gone from this computer"],
    ], "a link and a folder are no chat-history file; a `..` is not looked at");
    // The head and a section's page are the cached page: no look at a file.
    const head = await (await fetch(`${base}/api/scan`)).text();
    assert.equal(head.includes("Still there"), false);
  } finally {
    await dash.close();
  }
});

test("a link to the 26th of your secrets (§4.25ai *A session card opens its row*): its id is f25, and the section's second page, the read the Scan page reads on with, starts at it; no value in the answer", async () => {
  const rec = largeScanRecord({ known: 30, looks: 5, named: 5, plant: PLANT });
  const h = homeWith(rec);
  const { base, dash } = await serve(h);
  try {
    const known = rec.findings.filter((f) => f.kind === "known");
    assert.equal(known.length, 30);
    assert.equal(scanItemIdOf(rec, known[25]!), "f25", "the link's id: the row's place in the section");
    const head = await fetch(`${base}/api/scan`);
    const scan = (await head.json()).scan;
    const yours = scan.sections.find((s: { id: string }) => s.id === "yours");
    assert.deepEqual([yours.total, yours.items.length, yours.next], [30, 25, 25], "the head draws the first 25 only");
    assert.ok(!yours.items.some((i: { id: string }) => i.id === "f25"));
    const res = await fetch(`${base}/api/scan/section/yours?after=25&rev=${encodeURIComponent(scan.rev)}`);
    const text = await res.text();
    assert.equal(res.status, 200);
    const page = JSON.parse(text);
    assert.deepEqual(page.items.map((i: { id: string }) => i.id), ["f25", "f26", "f27", "f28", "f29"]);
    assert.match(JSON.stringify(page.items[0]), /SERVICE_KEY_25\b/, "the 26th secret's row");
    assert.equal(page.next, null, "the section ends there");
    noValue("scan/section/yours?after=25", text);
  } finally {
    await dash.close();
  }
});
