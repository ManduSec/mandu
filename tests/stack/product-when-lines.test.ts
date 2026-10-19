/**
 * product-when-lines.test — on the product page a moment never breaks
 * between a number and its word, across the REAL components and the served
 * styles (dashboard.md §4.25u *A moment keeps its number with its word*).
 * Mandu-new.
 *
 * Until 2026-10-15 a moment's words wrapped anywhere: headless Chromium drew
 * History's running row at 1280 px as "running now, started 1" over "minute
 * ago" (its 150 px time column), and the session page's header at 390 px as
 * "… ended Oct 15, 15:31 · 2" over "minutes ago". Here a real ArbiterServer
 * runs at the `secrets` axes, the REAL anthropic-proxy on its production
 * client (`new ArbiterClientAdapter(data, human)`) carries two sessions, A
 * reading a `.env` whose key the proxy masks, then ending through
 * the launcher's REAL `session_exit`, B still running; a product-only
 * DashboardServer reads them over a real ArbiterEventSource. Each served
 * page is opened with its served stylesheets as a 1280 px screen and a
 * 390 px phone apply them, its clock set from the sessions' own moments so
 * every moment says "2 minutes ago" (`ahead`):
 *
 *   L1  History and Home: each row's relative words ("2 minutes ago") are
 *       one `time.ago` that computes `white-space: nowrap`, after "running
 *       now, started " or "ended ", which wrap; the verb's last word and the
 *       moment are one `.when-phrase` computing an inline box no wider than
 *       its line, so History's running row breaks after "running now,", not
 *       after "started" (§4.25u *A row's moment keeps its verb*, 2026-10-17:
 *       Chromium drew it as "running now, started" over "1 minute ago");
 *   L2  the session pages of A (ended) and B (running): the header's moment
 *       is "Oct 15, 15:31 ·" and "2 minutes ago", each part computing
 *       `nowrap`, the <time> around them wrapping between them;
 *   L3  the oracle: the model never got the value, and no page or answer
 *       carries it or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the served page and styles; the stack supplies the real
 * sessions they draw.
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

const A = `1791800000-${process.pid}`;
const B = `1791800100-${process.pid}`;
const VALUE = `sk_live_whenLinesCanary_${process.pid}_000000`;
/** The page's clock, from when each page opens: this far past the time the
 *  sessions' moments were all in (`atMoments`), so each moment says "2
 *  minutes ago" (`ago` rounds: 90 s to 149 s) however long the run took to
 *  get there. Until 2026-10-15 it ran 2 min 5 s ahead of the real clock,
 *  and the session pages, drawn last, read "3 minutes ago" once the run was
 *  25 s in (31 s on the CI guest: master pipeline 10839). */
const AHEAD_MS = 95_000;
const CLOCK = String.raw`[A-Z][a-z]{2} \d{1,2}(?:, \d{4})?, \d{2}:\d{2}`;
const RELATIVE = /^\d+ (?:minute|hour|day)s? ago$/;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

function readTurn(path: string): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_wl_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_wl_0", name: "Read", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ file_path: path }) } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

/** A row's relative words under `root`: one `time.ago`, a text alone, that
 *  never wraps, in a `.when-phrase` with the verb's last word, an inline box
 *  no wider than its line, after words that wrap. Gives each line's text and
 *  its phrase's, as "<line> | <phrase>". */
function rowMoments(root: El, w: El, where: string): string[] {
  const lines: string[] = [];
  for (const t of [...root.querySelectorAll("time.ago")] as El[]) {
    assert.equal(t.children.length, 0, `${where}: the relative words are one text`);
    assert.match(t.textContent, RELATIVE, `${where}: a number and its word`);
    assert.equal(w.getComputedStyle(t).whiteSpace, "nowrap", `${where}: "${t.textContent}" stays on one line`);
    const phrase = t.parentElement;
    assert.equal(phrase.className, "when-phrase", `${where}: the moment is in its phrase: ${phrase.outerHTML}`);
    const ps = w.getComputedStyle(phrase);
    assert.equal(ps.display, "inline-block", `${where}: the phrase is an inline box, so the line breaks before it`);
    assert.equal(ps.maxWidth, "100%", `${where}: the phrase is no wider than its line`);
    assert.notEqual(ps.whiteSpace, "nowrap", `${where}: the phrase wraps inside when it alone is wider than its line`);
    const line = phrase.parentElement;
    assert.notEqual(w.getComputedStyle(line).whiteSpace, "nowrap", `${where}: the line breaks before the moment if it must`);
    assert.notEqual(w.getComputedStyle(line.closest(".agent-when")).whiteSpace, "nowrap", `${where}: the time column wraps`);
    lines.push(`${line.textContent} | ${phrase.textContent}`);
  }
  return lines;
}

/** A whenNode moment: its two parts, each never wrapping, one space between,
 *  the <time> itself wrapping between them. Gives the relative words. */
function twoParts(t: El, w: El, where: string): string {
  assert.ok(t, `${where}: the moment is drawn`);
  const kids = [...t.childNodes] as El[];
  assert.deepEqual(kids.map((k) => (k.nodeType === 1 ? k.className : k.textContent)), ["when-at", " ", "when-ago"], `${where}: ${t.outerHTML}`);
  assert.match(kids[0].textContent, new RegExp(`^${CLOCK} ·$`), `${where}: the clock time with its dot`);
  assert.match(kids[2].textContent, RELATIVE, `${where}: a number and its word`);
  for (const part of [kids[0], kids[2]]) assert.equal(w.getComputedStyle(part).whiteSpace, "nowrap", `${where}: "${part.textContent}" stays on one line`);
  assert.notEqual(w.getComputedStyle(t).whiteSpace, "nowrap", `${where}: the line may break between the parts`);
  return kids[2].textContent;
}

test("a moment on the product page never breaks between a number and its word, on History, Home and the session pages, on the real stack with its served styles, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-when-lines-"));
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
  const proxies: AnthropicProxy[] = [];
  const ports = new Map<string, number>();
  for (const id of [A, B]) {
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
  let atMoments = 0;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ahead = (w: any) => { const real = w.Date.now.bind(w.Date); const opened = real(); w.Date.now = () => atMoments + AHEAD_MS + (real() - opened); };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rowIds = (doc: any, list: string) => [...doc.querySelectorAll(`#${list} .row.agent`)].map((r: any) => r.dataset.session);
  try {
    // A reads the .env (the model gets a placeholder) and ends; B asks once and runs on.
    const q = "Read the .env file.";
    await ask(A, [{ role: "user", content: q }]);
    await ask(A, [
      { role: "user", content: q },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_wl_0", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_wl_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
    ]);
    await ask(B, [{ role: "user", content: "What changed today?" }]);
    assert.ok(await emitLauncherEvent(sock, sessionExitEvent({ scopeId: A, code: 0, durationMs: 4_000 }), humanSock), "the launcher's emit lands");
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    let text = "";
    for (let i = 0; i < 400; i++) {
      text = await (await pageFetch(`${base}/api/home/history`)).text();
      const h = JSON.parse(text) as HistoryVM;
      if (h.rows.some((r) => r.id === A && r.state === "idle" && r.secrets.masked === 1) && h.rows.some((r) => r.id === B && r.state !== "idle")) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    // Every moment the pages show is in: A's start and end, B's start.
    atMoments = Date.now();
    noValue(text, "/api/home/history");
    const sheets = `${await served("/mandu.css")}\n${await served("/app.css")}`;

    for (const width of [1280, 390]) {
      const css = resolveCssVars(stylesAt(sheets, width));
      const opts = { css, beforeScripts: ahead };

      // ── L1: History and Home ──
      await servedProductPage(base, "/history", (doc) => rowIds(doc, "history-list").length === 2, (doc) => {
        const lines = rowMoments(doc.getElementById("history-list"), doc.defaultView, `History at ${width}`);
        assert.deepEqual(lines.map((l) => l.replace(/\d+/g, "N")).sort(), ["ended N minutes ago | ended N minutes ago", "running now, started N minutes ago | started N minutes ago"], `History at ${width}: ${JSON.stringify(lines)}`);
        noValue(doc.body.textContent, "the rendered History page");
      }, opts);
      await servedProductPage(base, "/", (doc) => rowIds(doc, "home-agents").length === 1 && rowIds(doc, "home-earlier").length === 1, (doc) => {
        const lines = [...rowMoments(doc.getElementById("home-agents"), doc.defaultView, `Home's Running now at ${width}`),
          ...rowMoments(doc.getElementById("home-earlier"), doc.defaultView, `Home's Earlier at ${width}`)];
        assert.deepEqual(lines.map((l) => l.replace(/\d+/g, "N")), ["started N minutes ago | started N minutes ago", "ended N minutes ago | ended N minutes ago"], `Home at ${width}: ${JSON.stringify(lines)}`);
        noValue(doc.body.textContent, "the rendered Home page");
      }, opts);

      // ── L2: the session pages ──
      for (const [id, lead] of [[A, /^(?:ran .+, )?ended $/], [B, /^running now, started $/]] as const) {
        await servedProductPage(base, `/agents/${id}`, (doc) => !!doc.querySelector("#agent-sub .agent-when time.when"), (doc) => {
          const line = doc.querySelector("#agent-sub .agent-when");
          const t = line.querySelector("time.when");
          const words = twoParts(t, doc.defaultView, `the session page of ${id === A ? "A" : "B"} at ${width}`);
          const before = line.textContent.slice(0, line.textContent.indexOf(t.textContent));
          assert.match(before, lead, `the words before the moment: ${JSON.stringify(line.textContent)}`);
          assert.match(words, /^2 minutes ago$/);
          noValue(doc.body.textContent, "the rendered session page");
        }, opts);
      }
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
