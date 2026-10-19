/**
 * product-rows-stay.test — the product page's session lists keep the rows
 * that did not change when the poll draws them again, across the REAL
 * components (dashboard.md §4.25 *The rows you read stay still*).
 * Mandu-new.
 *
 * Home's Running now and Earlier and the History page were drawn again from
 * nothing whenever a session came in, ended or counted something. The
 * browser's scroll anchoring holds the rows in view still only while its
 * anchor stays in the page, so in Chromium every row in view moved by a
 * whole row. Here a real ArbiterServer runs at the `secrets` axes, the REAL
 * anthropic-proxy on its production client (`new ArbiterClientAdapter(data,
 * human)`) carries four sessions, the launcher's REAL `session_exit` ends
 * two, and a product-only DashboardServer reads them over a real
 * ArbiterEventSource; the served pages (their own index.html and home.js in
 * jsdom) stay open while the page's own poll draws each change:
 *
 *   K1  History lists B and A, both running (A's `.env` read masked);
 *   K2  C starts and A exits; the poll draws C on top and A ended (History
 *       lists by last activity, so A comes over B), A's row anew, and B's
 *       row is the node already there;
 *   K3  Home: Running now lists C and B, Earlier lists A; D starts and B
 *       exits; the poll draws D in Running now, C's row the node already
 *       there, and B over A in Earlier, A's row the node already there;
 *   K4  the oracle: the model never got the value, and no drawn page
 *       carries it or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
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
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const A = `1791700000-${process.pid}`;
const B = `1791700100-${process.pid}`;
const C = `1791700200-${process.pid}`;
const D = `1791700300-${process.pid}`;
const VALUE = `sk_live_rowsStayCanary_${process.pid}_000000`;

function readTurn(path: string): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_rs_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_rs_0", name: "Read", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ file_path: path }) } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

test("the product page's session lists keep the rows that did not change when the poll draws a new or ended session, on the real stack, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rows-stay-"));
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
    const text = body.toString("utf8");
    seen.push(text);
    const sse = seen.length === 1 ? readTurn(env) : buildTextSse("Done.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  // One proxy per session, as each launch starts its own.
  const proxies = new Map<string, AnthropicProxy>();
  const ports = new Map<string, number>();
  for (const id of [A, B, C, D]) {
    const p = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: id, log: () => {} });
    proxies.set(id, p);
    ports.set(id, await p.listen(0));
  }
  // Through pageFetch, a socket of its own, as every request in a file
  // that runs a served page (served-page-fetch.test.ts).
  const ask = async (session: string, messages: unknown[]) => {
    const res = await pageFetch(`http://127.0.0.1:${ports.get(session)}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
  };
  const exit = async (session: string) =>
    assert.ok(await emitLauncherEvent(sock, sessionExitEvent({ scopeId: session, code: 0, durationMs: 4_000 }), humanSock), "the launcher's emit lands");
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the secret value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  /** The server's History once `done` holds for it (emission is asynchronous). */
  const history = async (done: (h: HistoryVM) => boolean): Promise<HistoryVM> => {
    let text = "";
    let h: HistoryVM = { total: 0, rows: [], next: null };
    for (let i = 0; i < 400; i++) {
      text = await (await pageFetch(`${base}/api/home/history`)).text();
      h = JSON.parse(text) as HistoryVM;
      if (done(h)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(done(h), text.slice(0, 600));
    noValue(text, "/api/home/history");
    return h;
  };
  const running = (h: HistoryVM, id: string) => h.rows.some((r) => r.id === id && r.state !== "idle");
  const ended = (h: HistoryVM, id: string) => h.rows.some((r) => r.id === id && r.state === "idle");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rows = (doc: any, list: string) => [...doc.querySelectorAll(`#${list} .row.agent`)] as any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ids = (doc: any, list: string) => rows(doc, list).map((r) => r.dataset.session);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rowOf = (doc: any, list: string, id: string) => rows(doc, list).find((r) => r.dataset.session === id);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const poll = (doc: any) => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  try {
    // K1: A reads the .env (the model gets a placeholder); B asks once.
    const q = "Read the .env file.";
    await ask(A, [{ role: "user", content: q }]);
    await ask(A, [
      { role: "user", content: q },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_rs_0", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_rs_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
    ]);
    await ask(B, [{ role: "user", content: "What changed today?" }]);
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    await history((h) => running(h, A) && running(h, B) && h.rows.some((r) => r.id === A && r.secrets.masked === 1));

    await servedProductPage(base, "/history", (doc) => ids(doc, "history-list").length === 2, async (doc) => {
      assert.deepEqual(ids(doc, "history-list"), [B, A]);
      const b = rowOf(doc, "history-list", B);
      const a = rowOf(doc, "history-list", A);
      assert.match(a.textContent, /running now, started/);
      assert.match(a.textContent, /1 secret masked/);

      // K2: C starts and A exits; the page's own poll draws them.
      await ask(C, [{ role: "user", content: "Summarize the README." }]);
      await exit(A);
      const h = await history((x) => x.rows[0]?.id === C && ended(x, A) && running(x, B));
      poll(doc);
      await waitWhile(() => ids(doc, "history-list")[0] !== C || !/ended/.test(rowOf(doc, "history-list", A)?.textContent ?? ""));
      assert.deepEqual(ids(doc, "history-list"), h.rows.map((r) => r.id), "the server's order, C on top");
      assert.equal(ids(doc, "history-list")[0], C);
      assert.equal(rowOf(doc, "history-list", B), b, "B, unchanged, is the row already there");
      assert.notEqual(rowOf(doc, "history-list", A), a, "A, ended, is drawn anew");
      assert.match(rowOf(doc, "history-list", A).textContent, /1 secret masked/, "its count kept");
      // The three rows under their day heading (§4.25ae *Sessions sit under their day*).
      assert.equal(doc.querySelectorAll("#history-list > :not(.history-day)").length, 3, "no row twice");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const days = [...doc.querySelectorAll("#history-list > .history-day time")].map((t: any) => t.getAttribute("datetime"));
      assert.ok(days.length >= 1 && new Set(days).size === days.length, `no day heading twice: ${days.join(" ")}`);
      noValue(doc.body.textContent, "the rendered History page");
    });

    await servedProductPage(base, "/", (doc) => ids(doc, "home-agents").length === 2 && ids(doc, "home-earlier").length === 1, async (doc) => {
      assert.deepEqual(ids(doc, "home-agents"), [C, B]);
      assert.deepEqual(ids(doc, "home-earlier"), [A]);
      const c = rowOf(doc, "home-agents", C);
      const a = rowOf(doc, "home-earlier", A);

      // K3: D starts and B exits.
      await ask(D, [{ role: "user", content: "List the open issues." }]);
      await exit(B);
      await history((h) => h.rows[0]?.id === D && ended(h, B));
      poll(doc);
      await waitWhile(() => !ids(doc, "home-agents").includes(D) || ids(doc, "home-earlier")[0] !== B);
      assert.deepEqual([...ids(doc, "home-agents")].sort(), [C, D].sort(), "D comes in, B leaves Running now");
      assert.equal(rowOf(doc, "home-agents", C), c, "C, unchanged, is the row already there");
      assert.deepEqual(ids(doc, "home-earlier"), [B, A], "B, ended, over A in Earlier");
      assert.equal(rowOf(doc, "home-earlier", A), a, "A, unchanged, is the row already there");
      noValue(doc.body.textContent, "the rendered Home page");
    });
  } finally {
    for (const p of proxies.values()) await p.close();
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
