/**
 * home-last-stepped-in.test — Home with nothing in the last 24 hours says
 * when Mandu last stepped in, and links that session, across the REAL
 * components (dashboard.md §4.25 *An empty window says when Mandu last
 * stepped in*). Mandu-new.
 *
 * Home's counts cover the last 24 hours, so a person back on Monday after
 * Mandu masked a key on Friday saw only "Nothing to count in the last 24
 * hours.". Here a real ArbiterServer runs at the `secrets` axes, the REAL
 * anthropic-proxy on its production client (`new ArbiterClientAdapter(data,
 * human)`) carries two sessions, and a product-only DashboardServer reads
 * them over a real ArbiterEventSource, signed out:
 *
 *   - OLD reads a `.env` through the proxy: the model gets a placeholder;
 *   - PLAIN asks a question and gets an answer: Mandu did nothing.
 *
 * Each record is then moved back in time as a session that ran then leaves
 * it (every event's `ts`, nothing else: OLD 30 hours, PLAIN 2 hours), a new
 * file the arbiter's listing reads afresh.
 *
 *   L1  `/api/home` counts nothing in the window (PLAIN alone) and names OLD
 *       in `lastSteppedIn`: its id, agent, the time of its last event, and
 *       its History row's numbers (`counts`: 1 secret masked);
 *   L2  the served Home draws "Nothing to count in the last 24 hours. Mandu
 *       last stepped in …: 1 secret masked.", linking OLD's page, then "See
 *       every one in History" with its switch on;
 *   L3  the oracle for the new field: the model never got the value, and
 *       neither `/api/home` nor the drawn hero carries it or a `$MDU:` token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HistoryVM, HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HOUR = 3_600_000;
const T0 = Math.floor(Date.now() / 1000);
const OLD = `${T0}-${process.pid}-old`;
const PLAIN = `${T0 + 1}-${process.pid}-plain`;
const VALUE = `sk_live_lastSteppedInCanary_${process.pid}_000000`;
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";

/** The record of `id` as a session that ran `ms` earlier leaves it: every
 *  event's `ts` moved back, written as a new file (a new inode, so the
 *  arbiter's listing reads it afresh). */
function moveBack(eventDir: string, id: string, ms: number): string {
  const file = join(eventDir, `${id}.ndjson`);
  const lines = readFileSync(file, "utf8").split("\n").filter((l) => l.trim() !== "");
  let last = "";
  const moved = lines.map((l) => {
    const e = JSON.parse(l) as { ts?: string };
    if (typeof e.ts === "string") e.ts = last = new Date(Date.parse(e.ts) - ms).toISOString();
    return JSON.stringify(e);
  });
  writeFileSync(`${file}.moved`, moved.join("\n") + "\n");
  renameSync(`${file}.moved`, file);
  return last;
}

test("Home with nothing in the last 24 hours names the session where Mandu last stepped in, and links it, with no value (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-home-last-stepped-in-"));
  const env = join(tmp, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const eventDir = join(tmp, "events");
  const arbiter = new ArbiterServer({ socketPath: sock, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir, log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  // No `extensions`: the product page only, as the shipped package.
  const source = new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock });
  const dashboard = new DashboardServer({ source, configEnv: { MANDU_HOME: join(tmp, "home") }, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const seen: string[] = [];
  let script: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = script.shift() ?? buildTextSse("Done.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxies: AnthropicProxy[] = [];
  type Msg = { role: string; content: unknown };
  /** One proxy per session, as each launch starts its own; each call is one turn's request. */
  const session = async (sid: string, turns: Msg[][]): Promise<string[]> => {
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: sid, log: () => {} });
    proxies.push(proxy);
    const p = await proxy.listen(0);
    const sent: string[] = [];
    for (const messages of turns) {
      const res = await pageFetch(`http://127.0.0.1:${p}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": sid, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
      });
      assert.equal(res.status, 200, await res.text());
      sent.push(seen.at(-1)!);
    }
    await proxy.close();
    return sent;
  };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the .env value`);
    assert.doesNotMatch(text, /\$MDU:/, `${where} carries no token`);
  };
  const json = async <T>(path: string): Promise<{ vm: T; text: string }> => {
    const res = await pageFetch(`${base}${path}`);
    const text = await res.text();
    assert.equal(res.status, 200, text.slice(0, 200));
    return { vm: JSON.parse(text) as T, text };
  };
  try {
    // OLD reads the .env: the proxy masks the value on its way to the model.
    script = [buildToolUseSse({ id: "toolu_ls_env", name: "Read", input: { file_path: env } })];
    const ask: Msg[] = [{ role: "user", content: "What is in .env?" }];
    const old = await session(OLD, [ask, [
      ...ask,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_ls_env", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_ls_env", content: render(`STRIPE_KEY=${VALUE}\n`) }] },
    ]]);
    assert.ok(!old.at(-1)!.includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    assert.match(old.at(-1)!, /\$MDU:/, "the model got its placeholder");
    // PLAIN asks and is answered: Mandu does nothing.
    await session(PLAIN, [[{ role: "user", content: "Rename the parser helper." }]]);

    // Emission is asynchronous: wait until both are listed and OLD is counted.
    const settled = async () => {
      const { vm } = await json<HistoryVM>("/api/home/history");
      return vm.total === 2 && vm.rows.some((r) => r.id === OLD && r.secrets.masked === 1);
    };
    for (let i = 0; i < 400 && !(await settled()); i++) await new Promise((r) => setTimeout(r, 25));
    assert.ok(await settled(), "both sessions recorded, OLD's secret masked");

    // The records as sessions that ran 30 and 2 hours ago leave them.
    const oldAt = moveBack(eventDir, OLD, 30 * HOUR);
    moveBack(eventDir, PLAIN, 2 * HOUR);

    // ── L1: the server's answer ──
    let home = await json<HomeVM>("/api/home");
    for (let i = 0; i < 200 && home.vm.lastSteppedIn?.id !== OLD; i++) {
      await new Promise((r) => setTimeout(r, 25));
      home = await json<HomeVM>("/api/home");
    }
    const w = home.vm.window;
    assert.deepEqual([w.sessions, w.counted, w.secretsMasked, w.secretsEarly, w.untrusted, w.blocked, w.sent], [1, 1, 0, 0, 0, 0, 0], `the window holds PLAIN alone, counting nothing (${JSON.stringify(w)})`);
    assert.equal(home.vm.verdict, "secrets-only");
    assert.ok(home.vm.lastSteppedIn, "named");
    assert.deepEqual({ ...home.vm.lastSteppedIn, cwd: null }, {
      id: OLD, agent: "Claude Code", cwd: null, at: oldAt,
      counts: { secrets: { masked: 1, early: 0 }, untrusted: 0, blocked: 0, sent: 0, waiting: 0, holds: true, protectionOff: false },
    }, JSON.stringify(home.vm.lastSteppedIn));
    assert.deepEqual(Object.keys(home.vm.lastSteppedIn!).sort(), ["agent", "at", "counts", "cwd", "id"], "metadata only");
    assert.deepEqual(Object.keys(home.vm.lastSteppedIn!.counts!).sort(), ["blocked", "holds", "protectionOff", "secrets", "sent", "untrusted", "waiting"], "its row's numbers only");
    // ── L3 (the answer): no value, no token ──
    noValue(home.text, "/api/home");

    // ── L2: the served Home ──
    const empty = /^Nothing to count in the last 24 hours\. Mandu last stepped in /;
    await servedProductPage(base, "/", (doc) => empty.test(doc.getElementById("hero-facts")?.textContent ?? ""), (doc) => {
      const facts = doc.getElementById("hero-facts");
      assert.match(facts.textContent, /^Nothing to count in the last 24 hours\. Mandu last stepped in [A-Z][a-z]{2}, [A-Z][a-z]{2} \d{1,2}(?:, \d{4})?, \d{2}:\d{2}, in Claude Code(?: in .+)?: 1 secret masked\. See every one in History\.$/);
      const [toSession, toHistory] = [...facts.querySelectorAll("a")];
      assert.equal(toSession.dataset.session, OLD, "the words link OLD's page");
      assert.equal(toSession.getAttribute("href"), `/agents/${encodeURIComponent(OLD)}`);
      assert.equal(toSession.querySelector("time").getAttribute("datetime"), oldAt);
      assert.equal(toHistory.getAttribute("href"), "/history?only=stepped-in", "History with its switch on");
      // ── L3 (the page): no value, no token ──
      noValue(doc.getElementById("hero").textContent, "the drawn hero");
    });
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
