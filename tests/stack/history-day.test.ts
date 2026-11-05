/**
 * history-day.test — the product page's History lists the sessions from a
 * chosen day back, across the REAL components (dashboard.md §4.25ae *Go to
 * a day*). Mandu-new.
 *
 * Until then History was reachable past its first 25 rows only by Show
 * more. A real ArbiterServer runs at the `secrets` axes, the REAL
 * anthropic-proxy on its production client (`new ArbiterClientAdapter(data,
 * human)`) carries two sessions, and a product-only DashboardServer reads
 * them over a real ArbiterEventSource, signed out:
 *
 *   A   reads a `.env` through the proxy (the model gets a placeholder),
 *       then the launcher's REAL `session_exit` ends it;
 *   B   asks once and ends a day later (its `session_exit` stamped then).
 *
 *   G1  `GET /api/home/history?before=<the start of B's day>` lists A only,
 *       `total` 1, `before.all` 2; without it both;
 *   G2  the served `/history?day=<A's day>`, its clock a minute past B's
 *       end, in Seoul (TZ pinned, no daylight saving time): the box holds
 *       the day, the read carried `before=`, the list is "Yesterday" then A
 *       and no B, the status line "From yesterday back"; Day after goes
 *       to today and lists both (and hides, today being the latest day,
 *       the focus moving to Day before), Day before lists A only again
 *       (queue #245); Show the newest lists both again;
 *   G3  the oracle: the model never got the value, and neither answer nor
 *       the drawn page carries it or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the served page and the route; the stack supplies the real
 * sessions they read.
 */
process.env.TZ = "Asia/Seoul"; // UTC+9, no daylight saving time

import { test } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { emitLauncherEvent, sessionExitEvent } from "../../launcher/src/services/observe.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HistoryVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const A = `1791900200-${process.pid}`;
const B = `1791900300-${process.pid}`;
const VALUE = `sk_live_historyDayCanary_${process.pid}_000000`;
const DAY_MS = 86_400_000;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

function readTurn(path: string): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_gd_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_gd_0", name: "Read", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ file_path: path }) } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

/** The local day of `ms` as a heading's datetime says it. */
function dayKey(ms: number): string {
  const d = new Date(ms);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

/** The start of the local day after `key` (the page's `before=`). */
function dayAfter(key: string): number {
  const [y, m, d] = key.split("-").map(Number);
  return new Date(y!, m! - 1, d! + 1).getTime();
}

test("History goes to a day: the route and the served page list the sessions from that day back, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-history-day-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  // No `extensions`: the product page only, as the shipped package.
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }), configEnv: { MANDU_HOME: join(tmp, "home") }, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? readTurn(env) : buildTextSse("Done.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxyA = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: A, log: () => {} });
  const proxyB = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: B, log: () => {} });
  const portA = await proxyA.listen(0);
  const portB = await proxyB.listen(0);
  const ask = async (port: number, session: string, messages: unknown[]) => {
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
  };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the secret value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  const history = async (query: string): Promise<{ vm: HistoryVM; text: string }> => {
    const res = await pageFetch(`${base}/api/home/history${query}`);
    assert.equal(res.status, 200, "signed out, the History read is open");
    const text = await res.text();
    return { vm: JSON.parse(text) as HistoryVM, text };
  };
  let pageNow = 0;
  const clock = (w: El) => { const real = w.Date.now.bind(w.Date); const opened = real(); w.Date.now = () => pageNow + (real() - opened); };
  const list = (doc: El) => doc.getElementById("history-list");
  const order = (doc: El) => ([...list(doc).children] as El[]).map((x) => x.matches(".history-day") ? `# ${x.textContent}` : x.dataset.session).filter(Boolean);
  try {
    const q = "Read the .env file.";
    await ask(portA, A, [{ role: "user", content: q }]);
    await ask(portA, A, [
      { role: "user", content: q },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_gd_0", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_gd_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
    ]);
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    assert.ok(await emitLauncherEvent(sock, sessionExitEvent({ scopeId: A, code: 0, durationMs: 4_000 }), humanSock), "A's exit lands");
    await ask(portB, B, [{ role: "user", content: "What changed today?" }]);
    const bEnd = Date.now() + DAY_MS;
    assert.ok(await emitLauncherEvent(sock, { ...sessionExitEvent({ scopeId: B, code: 0, durationMs: DAY_MS }), ts: new Date(bEnd).toISOString() }, humanSock), "B's exit lands");
    let all: { vm: HistoryVM; text: string } = { vm: { total: 0, rows: [], next: null }, text: "" };
    const done = (x: HistoryVM) => x.rows[0]?.id === B && x.rows[0]?.state === "idle" && x.rows.some((r) => r.id === A && r.state === "idle" && r.secrets.masked === 1);
    for (let i = 0; i < 400; i++) {
      all = await history("");
      if (done(all.vm)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(done(all.vm), all.text.slice(0, 600));
    noValue(all.text, "/api/home/history");
    const aDay = dayKey(Date.parse(all.vm.rows.find((r) => r.id === A)!.lastAt!));
    assert.notEqual(aDay, dayKey(bEnd), "A and B ended on two days");

    // G1: the route, cut at the end of A's day.
    const cut = await history(`?before=${dayAfter(aDay)}`);
    assert.deepEqual(cut.vm.rows.map((r) => r.id), [A], "from A's day back: A, not B, which ended the next day");
    assert.equal(cut.vm.total, 1);
    assert.deepEqual(cut.vm.before, { at: dayAfter(aDay), all: 2 });
    noValue(cut.text, "/api/home/history?before=");

    // G2: the served page at `?day=`.
    pageNow = bEnd + 60_000;
    await servedProductPage(base, `/history?day=${aDay}`, (doc) => list(doc).querySelectorAll(".row.agent").length === 1, async (doc) => {
      assert.equal(doc.getElementById("history-day").value, aDay, "the box holds the day");
      assert.equal(doc.querySelector('label[for="history-day"]').textContent, "Go to a day");
      assert.deepEqual(order(doc), ["# Yesterday", A], "the first heading is the day; B is not listed");
      assert.equal(doc.getElementById("history-count").textContent, "From yesterday back");
      noValue(doc.body.textContent, "the rendered History page at a day");
      const win = doc.defaultView;
      const until = async (ok: () => boolean) => { for (let i = 0; i < 400 && !ok(); i++) await new Promise((r) => win.setTimeout(r, 25)); };
      // Day after: today, both listed, and no Day after past today.
      const today = dayKey(pageNow);
      doc.getElementById("history-day-after").click();
      await until(() => list(doc).querySelectorAll(".row.agent").length === 2);
      assert.deepEqual(order(doc), ["# Today", B, "# Yesterday", A], "a day on: B's day, both listed");
      assert.equal(win.location.search, `?day=${today}`);
      assert.equal(doc.getElementById("history-day").value, today);
      assert.equal(doc.getElementById("history-day-after").hidden, true, "no Day after on today");
      assert.equal(doc.activeElement, doc.getElementById("history-day-before"), "the focus moves to Day before");
      // Day before: back to A's day, A only.
      doc.getElementById("history-day-before").click();
      await until(() => list(doc).querySelectorAll(".row.agent").length === 1);
      assert.deepEqual(order(doc), ["# Yesterday", A], "a day back: A's day again");
      assert.equal(win.location.search, `?day=${aDay}`);
      noValue(doc.body.textContent, "the rendered History page after the steps");
      // Show the newest: both again, B on top under Today.
      doc.getElementById("history-newest").click();
      for (let i = 0; i < 400 && list(doc).querySelectorAll(".row.agent").length !== 2; i++) await new Promise((r) => win.setTimeout(r, 25));
      assert.deepEqual(order(doc), ["# Today", B, "# Yesterday", A]);
      assert.equal(win.location.search, "", "the address drops the day");
      noValue(doc.body.textContent, "the rendered History page, newest");
    }, { beforeScripts: clock });
  } finally {
    await proxyA.close();
    await proxyB.close();
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
