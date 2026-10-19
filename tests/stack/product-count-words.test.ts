/**
 * product-count-words.test — on the product page a count never breaks from
 * its word, across the REAL components and the served styles (dashboard.md
 * §4.25u *A count keeps its word*). Mandu-new.
 *
 * Until 2026-10-15 a count in the page's own words could end a line with its
 * number: headless Chromium drew a Home or History row's counts as "1" over
 * "action blocked" at 980 px and "1" over "send with a real value filled
 * in" at 320 px, and a session page's Your secrets card as "… in 2" over
 * "requests.". Here a real ArbiterServer runs at the `secrets` axes, and the
 * REAL anthropic-proxy on its production client (`new
 * ArbiterClientAdapter(data, human)`) carries two sessions that each read a
 * `.env` whose key the proxy masks: A then ends through the launcher's REAL
 * `session_exit`, B runs on. A product-only DashboardServer reads them over a
 * real ArbiterEventSource. Each served page is opened with its served
 * stylesheets as a 980 px screen and a 320 px phone apply them:
 *
 *   C1  Home (B under Running now, A under Earlier) and History (both): each
 *       row's counts read "1 secret masked", the "1 secret" one
 *       `.count-word` that computes `white-space: nowrap`, in a line that
 *       wraps;
 *   C2  A's session page: its Your secrets card says the requests the
 *       placeholder went in ("… in 1 request."), the number and its word one
 *       `.count-word` that never wraps, in a line that does; every
 *       `.count-word` on the page is a number and its word;
 *   C3  the oracle: the model never got the value, and no page or answer
 *       carries it or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the served page and styles; the stack supplies the real
 * sessions and the server's own sentences they draw.
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
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const A = `1791810000-${process.pid}`;
const B = `1791810100-${process.pid}`;
const VALUE = `sk_live_countWordsCanary_${process.pid}_000000`;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

function readTurn(path: string): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_cw_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_cw_0", name: "Read", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ file_path: path }) } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

/** A `.count-word`: a number and its word, one text, never wrapping, in a
 *  block that does. Gives its words. */
function keptCount(span: El, w: El, where: string): string {
  assert.equal(span.childNodes.length, 1, `${where}: the count is one text`);
  assert.match(span.textContent, /^\d+ [A-Za-z]+$/, `${where}: a number and its word`);
  assert.equal(w.getComputedStyle(span).whiteSpace, "nowrap", `${where}: "${span.textContent}" stays on one line`);
  assert.notEqual(w.getComputedStyle(span.parentElement).whiteSpace, "nowrap", `${where}: the line around it wraps`);
  return span.textContent;
}

/** Each row's counts line under `list`: "1 secret masked" with "1 secret"
 *  kept together. */
function rowCounts(doc: El, list: string, ids: string[], where: string): void {
  for (const id of ids) {
    const line = doc.querySelector(`#${list} .row.agent[data-session="${id}"] .agent-counts`);
    assert.ok(line, `${where}: ${id === A ? "A" : "B"}'s row has its counts`);
    assert.equal(line.textContent, "1 secret masked", `${where}: ${JSON.stringify(line.textContent)}`);
    const spans = [...line.querySelectorAll(".count-word")] as El[];
    assert.deepEqual(spans.map((s) => keptCount(s, doc.defaultView, where)), ["1 secret"]);
  }
}

test("a count on the product page never breaks from its word, on Home, History and the session page, on the real stack with its served styles, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-count-words-"));
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
  const proxies: AnthropicProxy[] = [];
  const ports = new Map<string, number>();
  for (const id of [A, B]) {
    // Each session: the first request reads the .env, the next one answers.
    let n = 0;
    const upstream: UpstreamFetcher = async ({ body }) => {
      seen.push(body.toString("utf8"));
      const sse = n++ === 0 ? readTurn(env) : buildTextSse("Done.", { deltas: 1 });
      return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
    };
    const p = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: id, log: () => {} });
    proxies.push(p);
    ports.set(id, await p.listen(0));
  }
  const ask = async (session: string, messages: unknown[]) => {
    const res = await pageFetch(`http://127.0.0.1:${ports.get(session)}/v1/messages`, {
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
  const served = async (f: string): Promise<string> => {
    const r = await pageFetch(base + f);
    assert.equal(r.status, 200, `${f} is served`);
    return r.text();
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rowIds = (doc: any, list: string) => [...doc.querySelectorAll(`#${list} .row.agent`)].map((r: any) => r.dataset.session);
  try {
    // A and B each read the .env (the model gets a placeholder); A ends, B runs on.
    const q = "Read the .env file.";
    for (const id of [A, B]) {
      await ask(id, [{ role: "user", content: q }]);
      await ask(id, [
        { role: "user", content: q },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_cw_0", name: "Read", input: { file_path: env } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_cw_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
      ]);
    }
    assert.ok(await emitLauncherEvent(sock, sessionExitEvent({ scopeId: A, code: 0, durationMs: 4_000 }), humanSock), "the launcher's emit lands");
    assert.equal(seen.length, 4, "each session made its two requests");
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    let text = "";
    for (let i = 0; i < 400; i++) {
      text = await (await pageFetch(`${base}/api/home/history`)).text();
      const h = JSON.parse(text) as HistoryVM;
      if (h.rows.some((r) => r.id === A && r.state === "idle" && r.secrets.masked === 1) && h.rows.some((r) => r.id === B && r.state !== "idle" && r.secrets.masked === 1)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    noValue(text, "/api/home/history");
    const agentJson = await (await pageFetch(`${base}/api/home/agent?session=${A}`)).text();
    noValue(agentJson, "/api/home/agent");
    const sheets = `${await served("/mandu.css")}\n${await served("/app.css")}`;

    for (const width of [980, 320]) {
      const opts = { css: resolveCssVars(stylesAt(sheets, width)) };

      // ── C1: Home and History ──
      await servedProductPage(base, "/", (doc) => rowIds(doc, "home-agents").length === 1 && rowIds(doc, "home-earlier").length === 1, (doc) => {
        rowCounts(doc, "home-agents", [B], `Home's Running now at ${width}`);
        rowCounts(doc, "home-earlier", [A], `Home's Earlier at ${width}`);
        noValue(doc.body.textContent, "the rendered Home page");
      }, opts);
      await servedProductPage(base, "/history", (doc) => rowIds(doc, "history-list").length === 2, (doc) => {
        rowCounts(doc, "history-list", [A, B], `History at ${width}`);
        noValue(doc.body.textContent, "the rendered History page");
      }, opts);

      // ── C2: A's session page ──
      await servedProductPage(base, `/agents/${A}`, (doc) => !!doc.querySelector("#agent-secrets .secret-line"), (doc) => {
        const where = `A's session page at ${width}`;
        const lines = [...doc.querySelectorAll("#agent-secrets .secret-line")] as El[];
        const line = lines.find((l) => /in \d+ requests?\.$/.test(l.textContent));
        assert.ok(line, `${where}: the card says the requests the placeholder went in: ${JSON.stringify(lines.map((l) => l.textContent))}`);
        const said = /in (\d+ requests?)\.$/.exec(line.textContent)![1];
        const spans = [...line.querySelectorAll(".count-word")] as El[];
        assert.deepEqual(spans.map((s) => keptCount(s, doc.defaultView, where)), [said]);
        for (const s of [...doc.querySelectorAll(".count-word")] as El[]) keptCount(s, doc.defaultView, where);
        noValue(doc.body.textContent, "the rendered session page");
      }, opts);
    }
  } finally {
    for (const p of proxies) await p.close();
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
