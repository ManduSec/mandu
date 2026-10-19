/**
 * history-follows-poll.test — the product page's History follows the poll,
 * across the REAL components (dashboard.md §4.25ae *History follows the
 * poll*). Mandu-new.
 *
 * History was read once, when the page opened: an agent that exited still
 * read "running now", and a session started after never came in, until the
 * person opened the page again. Here a real ArbiterServer runs at the
 * `secrets` axes, the REAL anthropic-proxy on its production client
 * (`new ArbiterClientAdapter(data, human)`) carries the sessions, and a
 * product-only DashboardServer reads them over a real ArbiterEventSource,
 * signed out; the served `/history` (its own index.html and home.js in
 * jsdom) stays open throughout:
 *
 *   H1  session A reads a `.env` through the proxy (the model gets a
 *       placeholder): History draws its row, running now, its secret masked;
 *   H2  the launcher's REAL `session_exit` for A, then session B's first
 *       model call: the server's History lists B on top and A ended;
 *   H3  the page's poll (a return to the tab): the open page draws B on top,
 *       running now, and A ended, its count kept, with no page change;
 *   H4  the oracle: the model never got the value, and neither the History
 *       answer nor the drawn page carries it or a token.
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

const A = `1791600000-${process.pid}`;
const B = `1791600100-${process.pid}`;
const VALUE = `sk_live_historyPollCanary_${process.pid}_000000`;

function readTurn(path: string): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_hp_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_hp_0", name: "Read", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ file_path: path }) } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

test("History follows the poll on the real stack: an agent that exited reads ended and a new session comes in on top, without reopening the page, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-history-poll-"));
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
  // One proxy per session, as each launch starts its own.
  const proxyA = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: A, log: () => {} });
  const proxyB = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: B, log: () => {} });
  const portA = await proxyA.listen(0);
  const portB = await proxyB.listen(0);
  // Through pageFetch, a socket of its own, as every request in a file
  // that runs a served page (served-page-fetch.test.ts).
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
  /** The server's History once `done` holds for it (emission is asynchronous). */
  const history = async (done: (h: HistoryVM) => boolean): Promise<{ h: HistoryVM; text: string }> => {
    let text = "";
    let h: HistoryVM = { total: 0, rows: [], next: null };
    for (let i = 0; i < 400; i++) {
      text = await (await pageFetch(`${base}/api/home/history`)).text();
      h = JSON.parse(text) as HistoryVM;
      if (done(h)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(done(h), text.slice(0, 600));
    return { h, text };
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rows = (doc: any) => [...doc.querySelectorAll("#history-list .row.agent")] as any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rowOf = (doc: any, id: string) => rows(doc).find((r) => r.dataset.session === id);
  try {
    // H1: A reads the .env; the model gets a placeholder.
    const q = "Read the .env file.";
    await ask(portA, A, [{ role: "user", content: q }]);
    await ask(portA, A, [
      { role: "user", content: q },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_hp_0", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_hp_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
    ]);
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    await history((h) => h.rows.some((r) => r.id === A && r.secrets.masked === 1 && r.state !== "idle"));

    await servedProductPage(base, "/history", (doc) => rowOf(doc, A) !== undefined, async (doc) => {
      assert.equal(doc.getElementById("page-history").hidden, false);
      assert.match(rowOf(doc, A).textContent, /running now, started/, "A runs");
      assert.match(rowOf(doc, A).textContent, /1 secret masked/);
      assert.equal(rowOf(doc, B), undefined);
      const heading = doc.querySelector("#page-history h1");

      // H2: A's launcher records its exit; B starts.
      assert.ok(await emitLauncherEvent(sock, sessionExitEvent({ scopeId: A, code: 0, durationMs: 4_000 }), humanSock), "the launcher's emit lands");
      await ask(portB, B, [{ role: "user", content: "What changed today?" }]);
      const served = await history((h) => h.rows[0]?.id === B && h.rows.some((r) => r.id === A && r.state === "idle"));
      noValue(served.text, "/api/home/history");
      assert.match(rowOf(doc, A).textContent, /running now/, "the open page has not read it yet");

      // H3: the page's poll (a return to the tab) draws it, no page change.
      doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      await waitWhile(() => rows(doc)[0]?.dataset.session !== B || !/ended/.test(rowOf(doc, A)?.textContent ?? ""));
      assert.deepEqual(rows(doc).map((r) => r.dataset.session), [B, A], "B on top, A under it");
      assert.match(rowOf(doc, B).textContent, /running now, started/);
      assert.match(rowOf(doc, A).textContent, /ended/, "the agent that exited reads ended");
      assert.doesNotMatch(rowOf(doc, A).textContent, /running now/);
      assert.match(rowOf(doc, A).textContent, /1 secret masked/, "its count kept");
      assert.equal(doc.querySelector("#page-history h1"), heading, "the same page, not opened again");
      assert.equal(doc.getElementById("page-history").hidden, false);

      // H4: the drawn page carries no value.
      noValue(doc.body.textContent, "the rendered History page");
    });
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
