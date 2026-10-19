/**
 * product-trace.test — dashboard.md §4.25ae over the real server and the
 * fixture sessions, in the product-only build (`new DashboardServer` with no
 * `extensions`): the product page is a whole trace.
 *
 *   - `/history` is a product page; `GET /api/home/history` lists every
 *     session newest first, paged by `?after=` / `?limit=`, open signed out
 *     (metadata only: no event payload, no original);
 *   - the flagged fixture's agent page carries the leak check's finding (its
 *     step, when), signed out too, and never the text the check quoted; the
 *     signed-out event read drops that quote and keeps the flag;
 *   - `GET /api/home/original` is admin: 403 signed out, the step's whole
 *     original signed in, 404 for a step with none, 400 without a step;
 *   - `?background=<turn id>` lists a turn's background steps.
 *
 * Axes: none (recorded fixtures; the server takes no mode).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../unit/admin-session.js";

const FIXTURES_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "fixtures");
const BAD = "sess-bad9";
const GOOD = "sess-7af3";
/** What the flagged fixture's leak check quoted (its `invariant.detail`). */
const QUOTED = "un-symbolized untrusted span reached T-LLM tool_result";

/** A session whose masked web page is longer than the page's cap. */
const LONG = "sess-long";
const PAGE_TEXT = "line of the fetched page\n".repeat(400) + "THE-END";
const TOKEN = "$MDU:WebFetch[abcd]";

let server: DashboardServer;
let base: string;
let longServer: DashboardServer;
let longBase: string;
let dir: string;

function longSession(): string {
  const ev = (seq: number, kind: string, f: Record<string, unknown>) => JSON.stringify({
    id: `long-${seq}`, sessionId: LONG, turn: 0, ts: new Date(Date.parse("2026-06-14T12:00:00.000Z") + seq * 1000).toISOString(), seq,
    callId: null, parentId: null, kind, view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: null, output: null, invariant: { violatedInvariant: false }, ...f,
  });
  const dr = (symbolized: string, original: string | null = null, symbols: unknown[] = []) => ({ symbolized, original, differs: original !== null && original !== symbolized, symbols });
  return [
    ev(0, "tllm_call", { input: dr("▸ user\nRead the page."), output: dr('→ WebFetch({"url":"https://example.com"})') }),
    ev(1, "tool_use", { callId: "c1", input: dr('WebFetch({"url":"https://example.com"})') }),
    // Background: two connections the agent's model calls made.
    ev(2, "net_action", { boundary: "network", emitter: "net-supervisor", action: "forwarded", destination: "api.anthropic.com", method: "POST", scheme: "https", resolved: [] }),
    ev(3, "net_action", { boundary: "network", emitter: "net-supervisor", action: "forwarded", destination: "example.com", method: "GET", scheme: "https", resolved: [] }),
    ev(4, "tool_result", {
      callId: "c1", output: dr(TOKEN, PAGE_TEXT, [{ name: TOKEN, tool: "WebFetch", field: null, origin: "https://example.com", value: PAGE_TEXT }]),
      policy: { trust: "UNTRUSTED", reason: "web content" },
    }),
    ev(5, "tllm_call", { turn: 1, input: dr(`▸ user\nRead the page.\n\n▸ tool_result\n${TOKEN}`), output: dr("Done.") }),
  ].join("\n") + "\n";
}

before(async () => {
  // No `extensions`: the product page only (§4.25ac).
  server = new DashboardServer({ ...ADMIN_OPTS, source: new FileEventSource(FIXTURES_DIR), log: () => {} });
  base = `http://127.0.0.1:${await server.listen(0)}`;
  dir = mkdtempSync(join(tmpdir(), "mandu-product-trace-"));
  writeFileSync(join(dir, `${LONG}.ndjson`), longSession());
  longServer = new DashboardServer({ ...ADMIN_OPTS, source: new FileEventSource(dir), log: () => {} });
  longBase = `http://127.0.0.1:${await longServer.listen(0)}`;
});
after(async () => {
  await server.close();
  await longServer.close();
  rmSync(dir, { recursive: true, force: true });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function get(path: string, admin = false, at = base): Promise<{ status: number; body: any; text: string }> {
  const r = await fetch(at + path, admin ? { headers: CSRF_ADMIN } : {});
  const text = await r.text();
  let body: unknown = null;
  try { body = JSON.parse(text); } catch { body = null; }
  return { status: r.status, body, text };
}

test("/history is a product page; /api/home/history lists every session newest first, paged, signed out, with no payload", async () => {
  const page = await fetch(base + "/history");
  assert.equal(page.status, 200);
  assert.match(await page.text(), /id="page-history"/);
  assert.equal((await fetch(base + "/dev/")).status, 404, "product only");

  const all = await get("/api/home/history");
  assert.equal(all.status, 200);
  const ids = all.body.rows.map((r: { id: string }) => r.id);
  assert.ok(ids.includes(BAD) && ids.includes(GOOD), ids.join(","));
  assert.equal(all.body.total, all.body.rows.length);
  assert.equal(all.body.next, null);
  const lasts = all.body.rows.map((r: { lastAt: string }) => Date.parse(r.lastAt));
  assert.deepEqual([...lasts].sort((a, b) => b - a), lasts, "newest first");
  const bad = all.body.rows.find((r: { id: string }) => r.id === BAD);
  assert.equal(bad.holds, false, "the flagged session says protection failed");
  // Metadata only: no event payload, no original, no token.
  assert.doesNotMatch(all.text, /ignore all prior instructions|acme\.example|\$MDU:/);

  // Paged: one row, then the next after it.
  const first = await get("/api/home/history?limit=1");
  assert.equal(first.body.rows.length, 1);
  assert.equal(first.body.next, first.body.rows[0].id);
  const second = await get(`/api/home/history?limit=1&after=${encodeURIComponent(first.body.next)}`);
  assert.equal(second.body.rows.length, 1);
  assert.notEqual(second.body.rows[0].id, first.body.rows[0].id);
  assert.equal(second.body.rows[0].id, ids[1]);
});

test("the flagged session's agent page says what the leak check found, signed out too, never the quoted text; the signed-out event read drops the quote and keeps the flag", async () => {
  for (const admin of [false, true]) {
    const r = await get(`/api/home/agent?session=${BAD}`, admin);
    assert.equal(r.status, 200);
    const f = r.body.finding;
    assert.ok(f, "a finding");
    assert.equal(f.count, 1);
    assert.equal(f.items.length, 1);
    assert.equal(f.items[0].step, "tool:call_leak");
    assert.match(f.items[0].parts.map((p: { text: string }) => p.text).join(""), /the result of this step reached the AI without a mask/);
    assert.doesNotMatch(JSON.stringify(f), /ignore all prior instructions/);
    assert.doesNotMatch(r.text, new RegExp(QUOTED));
    assert.doesNotMatch(r.text, /detailed trace|developer view/i, "a product-only build names no trace");
  }
  const good = await get(`/api/home/agent?session=${GOOD}`);
  assert.equal(good.body.finding, null);
  const events = await get(`/api/events?session=${BAD}`);
  assert.equal(events.status, 200);
  assert.doesNotMatch(events.text, new RegExp(QUOTED), "signed out, the quote goes");
  assert.match(events.text, /"violatedInvariant":true/, "the flag stays");
  const signedIn = await get(`/api/events?session=${BAD}`, true);
  assert.match(signedIn.text, new RegExp(QUOTED), "signed in, the record as written");
});

test("/api/home/original: refused signed out; signed in, the step's whole original, 404 for a step with none, 400 without one", async () => {
  const step = encodeURIComponent("tool:c1");
  const out = await get(`/api/home/original?session=${LONG}&step=${step}`, false, longBase);
  assert.equal(out.status, 403);
  assert.doesNotMatch(out.text, /line of the fetched page/);
  // The page cuts it at its cap, signed in; signed out it has none.
  const page = await get(`/api/home/agent?session=${LONG}`, true, longBase);
  const shown = page.body.story.flatMap((t: { steps: unknown[] }) => t.steps).find((s: { id: string }) => s.id === "tool:c1");
  assert.equal(shown?.split?.hidden?.truncated, true, JSON.stringify(shown));
  assert.ok(PAGE_TEXT.startsWith(shown.split.hidden.text));
  const signedOut = await get(`/api/home/agent?session=${LONG}`, false, longBase);
  assert.doesNotMatch(signedOut.text, /line of the fetched page/);
  const whole = await get(`/api/home/original?session=${LONG}&step=${step}`, true, longBase);
  assert.equal(whole.status, 200);
  assert.equal(whole.body.text, PAGE_TEXT);
  assert.equal(whole.body.truncated, false);
  assert.equal((await get(`/api/home/original?session=${BAD}&step=${encodeURIComponent("tool:call_leak")}`, true)).status, 404);
  assert.equal((await get(`/api/home/original?session=${LONG}`, true, longBase)).status, 400);
});

test("?background=<turn id> lists that turn's background steps, signed out too; unasked, the count alone", async () => {
  const plain = await get(`/api/home/agent?session=${LONG}`, false, longBase);
  const turn = plain.body.story.find((t: { routine: unknown }) => t.routine);
  assert.ok(turn, JSON.stringify(plain.body.story));
  assert.equal(turn.routine.count, 2);
  assert.equal("items" in turn.routine, false);
  const listed = await get(`/api/home/agent?session=${LONG}&background=${encodeURIComponent(turn.id)}`, false, longBase);
  const again = listed.body.story.find((t: { id: string }) => t.id === turn.id);
  assert.deepEqual(again.routine.items.map((i: { parts: { text: string }[] }) => i.parts.map((p) => p.text).join("")), ["Connected to api.anthropic.com", "Connected to example.com"]);
  assert.equal(again.routine.moreItems, 0);
  assert.doesNotMatch(listed.text, /line of the fetched page/, "signed out: no original");
});
