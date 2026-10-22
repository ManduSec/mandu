/**
 * product-command-whole.test — on the product page a command the page names
 * stays on one line, across the REAL components and the served styles
 * (dashboard.md §4.25u *A command keeps its words*). Mandu-new.
 *
 * Until 2026-10-15 a command in the page's own words wrapped at its space:
 * headless Chromium drew Settings › Protection's "Start it with `mandu`" over
 * "`dashboard` to manage the protection service here." at 1280, 720, 390 and
 * 320 px, and Home › Where your data lives' "run `mandu`" over "`paths`." at
 * 320 px; History's empty state named `mandu claude or mandu codex` as plain
 * text. Here a real ArbiterServer runs at the `secrets` axes and a
 * product-only DashboardServer, started without the service controls as
 * `mandu dashboard` is not, reads it over a real ArbiterEventSource. Each
 * served page is opened with its served stylesheets as a 1280 px screen, a
 * 390 px phone and a 320 px one apply them:
 *
 *   P1  before any session: History's empty state and Home's Running now
 *       name `mandu claude` and `mandu codex` as code, each a `.code-whole`
 *       that computes `white-space: nowrap`, in a line that wraps;
 *   P2  then the REAL anthropic-proxy on its production client (`new
 *       ArbiterClientAdapter(data, human)`) carries a session that reads a
 *       `.env` whose key it masks; Settings keeps `mandu dashboard` whole
 *       in its service line and in the sign-in words the gate's refusal of
 *       Prompt filters brings (the page is signed out), and Home's Where
 *       your data lives keeps `mandu paths` whole, beside the session's row;
 *   P3  the oracle: the model never got the value, and no page or answer
 *       carries it or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the served page and styles; the stack supplies the real
 * session and the server the page reads.
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
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HistoryVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const S = `1791820000-${process.pid}`;
const VALUE = `sk_live_commandWholeCanary_${process.pid}_000000`;
const WIDTHS = [1280, 390, 320];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

function readTurn(path: string): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_cmd_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_cmd_0", name: "Read", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ file_path: path }) } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

/** The commands under `line`, each a `.code-whole` of one text that never
 *  wraps, in a line that does. Gives their words. */
function keptWhole(line: El, where: string): string[] {
  const w = line.ownerDocument.defaultView;
  assert.notEqual(w.getComputedStyle(line).whiteSpace, "nowrap", `${where}: the line around the command wraps`);
  return ([...line.querySelectorAll("code.code-whole")] as El[]).map((c) => {
    assert.equal(c.childNodes.length, 1, `${where}: the command is one text`);
    assert.match(c.textContent, /^\S+(?: \S+)+$/, `${where}: a command with a space`);
    assert.ok(c.textContent.length <= 24, `${where}: "${c.textContent}" fits the narrowest column`);
    assert.equal(w.getComputedStyle(c).whiteSpace, "nowrap", `${where}: "${c.textContent}" stays on one line`);
    return c.textContent;
  });
}

test("a command the product page names stays on one line, in History, Settings and Home, on the real stack with its served styles, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-command-whole-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  // No `extensions` and no `services`: the product page only, without the
  // service controls (Settings then names `mandu dashboard`).
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }), configEnv: { MANDU_HOME: join(tmp, "home") }, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const seen: string[] = [];
  let n = 0;
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = n++ === 0 ? readTurn(env) : buildTextSse("Done.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: S, log: () => {} });
  const port = await proxy.listen(0);
  const ask = async (messages: unknown[]) => {
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": S, "anthropic-version": "2023-06-01" },
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
  try {
    const sheets = `${await served("/mandu.css")}\n${await served("/app.css")}`;

    // ── P1: History before any session ──
    const none = JSON.parse(await (await pageFetch(`${base}/api/home/history`)).text()) as HistoryVM;
    assert.equal(none.rows.length, 0, "no session yet");
    for (const width of WIDTHS) {
      const opts = { css: resolveCssVars(stylesAt(sheets, width)) };
      await servedProductPage(base, "/history", (doc) => !!doc.querySelector("#history-list .empty"), (doc) => {
        const empty = doc.querySelector("#history-list .empty");
        assert.equal(empty.textContent, "No session has been recorded yet. Start your agent through Mandu, mandu claude or mandu codex, and it shows up here.");
        assert.deepEqual(keptWhole(empty, `History's empty state at ${width}`), ["mandu claude", "mandu codex"]);
      }, opts);
      await servedProductPage(base, "/", (doc) => !!doc.querySelector("#home-agents .empty"), (doc) => {
        const empty = doc.querySelector("#home-agents .empty");
        assert.equal(empty.textContent, "No agent is running right now. Start one with mandu claude or mandu codex.");
        assert.deepEqual(keptWhole(empty, `Home's Running now at ${width}`), ["mandu claude", "mandu codex"]);
      }, opts);
    }

    // ── P2: a real session reads the .env (the model gets a placeholder) ──
    const q = "Read the .env file.";
    await ask([{ role: "user", content: q }]);
    await ask([
      { role: "user", content: q },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_cmd_0", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_cmd_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
    ]);
    assert.equal(seen.length, 2, "the session made its two requests");
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    let text = "";
    for (let i = 0; i < 400; i++) {
      text = await (await pageFetch(`${base}/api/home/history`)).text();
      if ((JSON.parse(text) as HistoryVM).rows.some((r) => r.id === S && r.secrets.masked === 1)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok((JSON.parse(text) as HistoryVM).rows.some((r) => r.id === S && r.secrets.masked === 1), "the session's masked read is on record");
    noValue(text, "/api/home/history");
    noValue(await (await pageFetch(`${base}/api/home`)).text(), "/api/home");

    for (const width of WIDTHS) {
      const opts = { css: resolveCssVars(stylesAt(sheets, width)) };
      const signIn = (doc: El) => /^Sign in first:/.test(doc.getElementById("settings-prompt-kinds").textContent);
      await servedProductPage(base, "/settings", (doc) => !!doc.querySelector("#settings-services .service-none") && signIn(doc), (doc) => {
        const line = doc.querySelector("#settings-services .service-none");
        assert.equal(line.textContent, "This dashboard was started without the service controls. Start it with mandu dashboard to manage the protection service here.");
        assert.deepEqual(keptWhole(line, `Settings at ${width}`), ["mandu dashboard"]);
        const kinds = doc.getElementById("settings-prompt-kinds");
        assert.match(kinds.textContent, /^Sign in first: reload this page and sign in with your dashboard account/);
        // `mandu dashboard --set-password` is longer than the narrowest column
        // keeps whole (24): a plain code that may wrap at its spaces.
        assert.deepEqual(keptWhole(kinds.firstElementChild, `Settings' sign-in words at ${width}`), []);
        noValue(doc.body.textContent, "the rendered Settings page");
      }, opts);
      await servedProductPage(base, "/", (doc) => !!doc.querySelector(`#home-agents .row.agent[data-session="${S}"]`), (doc) => {
        const about = doc.getElementById("home-data-about");
        assert.match(about.textContent, /To see every place, including the ones only Mandu's developers use, run mandu paths\.$/);
        assert.deepEqual(keptWhole(about, `Home's Where your data lives at ${width}`), ["mandu paths"]);
        // The session's own row draws no command of the page's.
        assert.equal(doc.querySelector(`#home-agents .row.agent[data-session="${S}"] .code-whole`), null);
        noValue(doc.body.textContent, "the rendered Home page");
      }, opts);
    }
  } finally {
    await proxy.close();
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
