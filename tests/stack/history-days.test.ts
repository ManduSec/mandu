/**
 * history-days.test — the product page's History puts its sessions under
 * day headings, across the REAL components and the served styles
 * (dashboard.md §4.25ae *Sessions sit under their day*). Mandu-new.
 *
 * History gave each row its moment only as relative words ("ended 99 days
 * ago"), the clock time on hover: two sessions ten hours apart on two days
 * read alike. Here a real ArbiterServer runs at the `secrets` axes, the REAL
 * anthropic-proxy on its production client (`new ArbiterClientAdapter(data,
 * human)`) carries two sessions, and a product-only DashboardServer reads
 * them over a real ArbiterEventSource, signed out:
 *
 *   A   reads a `.env` through the proxy (the model gets a placeholder),
 *       then the launcher's REAL `session_exit` ends it;
 *   B   asks once, then runs past midnight: its launcher's `session_exit`
 *       lands a day later (the event's own time, as the launcher stamps it),
 *       so B ended on the next day.
 *
 * Each served `/history` is opened with its served stylesheets as a 1280 px
 * screen and a 390 px phone apply them, its clock a minute past B's end, in
 * Seoul (TZ pinned, no daylight saving time):
 *
 *   Y1  two h2 headings, "Today" before B and "Yesterday" before A, each
 *       with its day as <time datetime>, B ending on the day after A;
 *   Y2  each heading a slim line that wraps: no margin, 13 px, padding 8 px
 *       24 px, no fixed width, never `nowrap`, so it never runs past a
 *       390 px phone; the rows keep their moments;
 *   Y3  the oracle: the model never got the value, and neither the History
 *       answer, `/api/home` nor the drawn page carries it or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the served page and styles; the stack supplies the real
 * sessions they draw.
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
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const A = `1791900000-${process.pid}`;
const B = `1791900100-${process.pid}`;
const VALUE = `sk_live_historyDaysCanary_${process.pid}_000000`;
const DAY_MS = 86_400_000;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

function readTurn(path: string): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_hd_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_hd_0", name: "Read", input: {} } })
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

test("History puts real sessions under day headings, Today and Yesterday, each before its rows, a slim line at 1280 and 390 px, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-history-days-"));
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
  const served = async (f: string): Promise<string> => {
    const r = await pageFetch(base + f);
    assert.equal(r.status, 200, `${f} is served`);
    return r.text();
  };
  let pageNow = 0;
  const clock = (w: El) => { const real = w.Date.now.bind(w.Date); const opened = real(); w.Date.now = () => pageNow + (real() - opened); };
  const list = (doc: El) => doc.getElementById("history-list");
  /** The list in page order: a heading by its words, a row by its id. */
  const order = (doc: El) => ([...list(doc).children] as El[]).map((x) => x.matches(".history-day") ? `# ${x.textContent}` : x.dataset.session);
  try {
    // A reads the .env (the model gets a placeholder) and ends.
    const q = "Read the .env file.";
    await ask(portA, A, [{ role: "user", content: q }]);
    await ask(portA, A, [
      { role: "user", content: q },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_hd_0", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_hd_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
    ]);
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    assert.ok(await emitLauncherEvent(sock, sessionExitEvent({ scopeId: A, code: 0, durationMs: 4_000 }), humanSock), "A's exit lands");
    // B asks, runs past midnight and ends a day later.
    await ask(portB, B, [{ role: "user", content: "What changed today?" }]);
    const bEnd = Date.now() + DAY_MS;
    assert.ok(await emitLauncherEvent(sock, { ...sessionExitEvent({ scopeId: B, code: 0, durationMs: DAY_MS }), ts: new Date(bEnd).toISOString() }, humanSock), "B's exit lands");
    let text = "";
    let h: HistoryVM = { total: 0, rows: [], next: null };
    const done = (x: HistoryVM) => x.rows[0]?.id === B && x.rows[0]?.state === "idle" && x.rows.some((r) => r.id === A && r.state === "idle" && r.secrets.masked === 1);
    for (let i = 0; i < 400; i++) {
      text = await (await pageFetch(`${base}/api/home/history`)).text();
      h = JSON.parse(text) as HistoryVM;
      if (done(h)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(done(h), text.slice(0, 600));
    noValue(text, "/api/home/history");
    noValue(await served("/api/home"), "/api/home");
    const aEnd = Date.parse(h.rows.find((r) => r.id === A)!.lastAt!);
    assert.equal(h.rows[0]!.lastAt, new Date(bEnd).toISOString(), "B ended when its exit says");
    assert.notEqual(dayKey(aEnd), dayKey(bEnd), "A and B ended on two days");
    pageNow = bEnd + 60_000;
    const sheets = `${await served("/mandu.css")}\n${await served("/app.css")}`;

    for (const width of [1280, 390]) {
      const css = resolveCssVars(stylesAt(sheets, width));
      await servedProductPage(base, "/history", (doc) => list(doc).querySelectorAll(".row.agent").length === 2, (doc) => {
        // Y1: the headings, each before its rows.
        assert.deepEqual(order(doc), ["# Today", B, "# Yesterday", A], `History at ${width}`);
        const heads = [...list(doc).querySelectorAll(".history-day")] as El[];
        assert.deepEqual(heads.map((x) => x.tagName), ["H2", "H2"], "a real heading under the page h1");
        assert.deepEqual(heads.map((x) => x.querySelector("time").getAttribute("datetime")), [dayKey(bEnd), dayKey(aEnd)]);
        // Y2: a slim line that wraps; the rows keep their moments.
        const win = doc.defaultView;
        for (const x of heads) {
          const s = win.getComputedStyle(x);
          assert.equal(s.marginTop, "0px", `at ${width}: no margin of an h2`);
          assert.equal(s.fontSize, "13px", `at ${width}: small`);
          assert.equal(s.paddingLeft, "24px", `at ${width}: inset as a row`);
          assert.notEqual(s.whiteSpace, "nowrap", `at ${width}: the words wrap`);
          for (const p of ["width", "minWidth"]) assert.ok(["", "auto", "0px"].includes(s[p]), `at ${width}: no fixed ${p} (${s[p]})`);
        }
        for (const id of [A, B]) {
          const row = [...list(doc).querySelectorAll(".row.agent")].find((r: El) => r.dataset.session === id) as El;
          assert.match(row.textContent, /ended/, `${id} keeps its moment`);
        }
        // Y3: the drawn page carries no value.
        noValue(doc.body.textContent, `the rendered History page at ${width}`);
      }, { css, beforeScripts: clock });
    }
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
