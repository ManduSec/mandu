/**
 * history-back-restores.test — Back from a session returns the product
 * page's History to the row you opened, with the rows you had loaded, across
 * the REAL components (dashboard.md §4.25ae *Back returns to the row you
 * opened*, §4.25ad *The back link names where you came from*). Mandu-new.
 *
 * Until 2026-10-18 every page change read History again from nothing: after
 * Show more twice and a row's Details, Back showed the first 25 rows at the
 * top, and the session page's link always went Home. Here a real
 * ArbiterServer runs at the `secrets` axes, the REAL anthropic-proxy on its
 * production client carries one session that reads a `.env`, the launcher's
 * real `session_exit` records 59 more, and a product-only DashboardServer
 * reads them over a real ArbiterEventSource, signed out. The served
 * `/history` (its own index.html and home.js in jsdom, which has no layout:
 * the unit suite home-js-back-restores reads the scroll) stays open:
 *
 *   R1  Show more twice draws the 60 rows; row 55's Details opens its page,
 *       whose back link reads "Back to History";
 *   R2  the browser's Back: History holds at least 55 rows, row 55 among
 *       them with the keyboard focus, with no page of 25 drawn on the way;
 *   R3  the same through the session page's "Back to History";
 *   R4  the oracle: the model never got the value, and no drawn page carries
 *       it or a token.
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

const VALUE = `sk_live_historyBackCanary_${process.pid}_000000`;
/** The session that reads the `.env`, the oldest; the launcher records 59 after it. */
const FIRST = `1791800000-${process.pid}`;
const LATER = Array.from({ length: 59 }, (_, i) => `${1791800100 + i}-${process.pid}`);

function readTurn(path: string): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_hb_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_hb_0", name: "Read", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ file_path: path }) } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const historyRows = (doc: any) => [...doc.querySelectorAll("#history-list .row.agent")] as any[];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rowOf = (doc: any, id: string) => historyRows(doc).find((r) => r.dataset.session === id);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const showMore = (doc: any) => doc.querySelector("#history-list .history-more button") as any;

test("Back from a session returns History to the row you opened, with the rows you had loaded, by the browser's Back and by Back to History (real arbiter, proxy, launcher events, dashboard, served page; secrets axes, explicit)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-history-back-"));
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
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: FIRST, log: () => {} });
  const port = await proxy.listen(0);
  // Through pageFetch, a socket of its own, as every request in a file
  // that runs a served page (served-page-fetch.test.ts).
  const ask = async (messages: unknown[]) => {
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": FIRST, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
  };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the secret value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  /** The server's History once `done` holds for it (emission is asynchronous). */
  const history = async (done: (h: HistoryVM) => boolean): Promise<HistoryVM> => {
    let h: HistoryVM = { total: 0, rows: [], next: null };
    let text = "";
    for (let i = 0; i < 400; i++) {
      text = await (await pageFetch(`${base}/api/home/history`)).text();
      h = JSON.parse(text) as HistoryVM;
      if (done(h)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(done(h), text.slice(0, 600));
    return h;
  };
  try {
    const q = "Read the .env file.";
    await ask([{ role: "user", content: q }]);
    await ask([
      { role: "user", content: q },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_hb_0", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_hb_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
    ]);
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    await history((h) => h.rows.some((r) => r.id === FIRST && r.secrets.masked === 1));
    for (const id of LATER) {
      assert.ok(await emitLauncherEvent(sock, sessionExitEvent({ scopeId: id, code: 0, durationMs: 1_000 }), humanSock), "the launcher's emit lands");
    }
    await history((h) => h.total === 60);

    await servedProductPage(base, "/history", (doc) => historyRows(doc).length === 25 && !!showMore(doc), async (doc) => {
      const w = doc.defaultView;
      // R1: Show more twice, then row 55's Details.
      showMore(doc).click();
      await waitWhile(() => historyRows(doc).length < 50);
      showMore(doc).click();
      await waitWhile(() => historyRows(doc).length < 60);
      assert.equal(historyRows(doc).length, 60);
      const opened: string = historyRows(doc)[54].dataset.session;
      noValue(doc.body.textContent, "the rendered History page");
      const openRow = () => {
        const details = rowOf(doc, opened).querySelector('a[data-page-link="agent"]');
        details.focus();
        details.click();
      };
      openRow();
      await waitWhile(() => doc.getElementById("page-agent").hidden);
      assert.equal(doc.getElementById("page-agent").hidden, false);
      assert.equal(w.location.pathname, `/agents/${encodeURIComponent(opened)}`);
      const back = doc.getElementById("agent-back");
      assert.equal(back.textContent, "Back to History", "the back link names the page it was opened from");

      // R2: the browser's Back. Every draw on the way is watched: none is
      // the first page of 25 alone.
      let drawnShort = false;
      const watch = new w.MutationObserver(() => {
        const n = historyRows(doc).length;
        if (!doc.getElementById("page-history").hidden && n > 0 && n < 55) drawnShort = true;
      });
      watch.observe(doc.getElementById("history-list"), { childList: true });
      w.history.back();
      await waitWhile(() => w.location.pathname !== "/history" || doc.activeElement !== rowOf(doc, opened));
      assert.equal(w.location.pathname, "/history");
      assert.ok(historyRows(doc).length >= 55, `at least 55 rows, got ${historyRows(doc).length}`);
      assert.equal(doc.activeElement, rowOf(doc, opened), "row 55 has the keyboard focus");
      assert.equal(historyRows(doc).indexOf(rowOf(doc, opened)), 54, "in its place");
      assert.equal(drawnShort, false, "never a page of 25 on the way back");
      noValue(doc.body.textContent, "the History page returned to");

      // R3: the same through the session page's Back to History.
      openRow();
      await waitWhile(() => doc.getElementById("page-agent").hidden);
      assert.equal(back.textContent, "Back to History");
      back.focus();
      back.click();
      await waitWhile(() => w.location.pathname !== "/history" || doc.activeElement !== rowOf(doc, opened));
      watch.disconnect();
      assert.ok(historyRows(doc).length >= 55);
      assert.equal(doc.activeElement, rowOf(doc, opened), "row 55 has the keyboard focus again");
      assert.equal(drawnShort, false);
      // R4: no drawn page carries the value.
      noValue(doc.body.textContent, "the History page returned to by its link");
    });
  } finally {
    await proxy.close();
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
