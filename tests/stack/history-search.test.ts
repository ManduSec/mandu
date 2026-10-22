/**
 * history-search.test — History's search finds a past session by what was
 * asked or by agent, across the REAL components (dashboard.md §4.25ae
 * *Finding a session*). Mandu-new.
 *
 * History listed every session 25 at a time and nothing found one. Here a
 * real ArbiterServer runs at the `secrets` axes with a registered key (as the
 * launcher registers the environment), the REAL anthropic-proxy on its
 * production client (`new ArbiterClientAdapter(data, human)`) carries 33
 * sessions, and a product-only DashboardServer reads them over a real
 * ArbiterEventSource, signed out (the History read is open):
 *
 *   S1  two sessions asked about `staging`, then 31 newer ones: the first
 *       unfiltered page does not reach them, `?q=staging` returns exactly
 *       those two, `total` 2, no next page, and `query.all` every session;
 *   S2  the served `/history?q=staging` draws exactly those two rows, the
 *       box holding the search and the count "2 of 33 sessions";
 *   S3  the oracle for this new read: a session whose prompt pasted the
 *       registered key (the proxy masks it on the way to the model) is
 *       found by its other words, but a signed-out search for the key's
 *       value, or a piece of it, returns no row; no answer and no drawn
 *       page carries the value, and the model never got it;
 *   S4  *An empty History has nothing to find*: over an empty event store
 *       the served `/history` hides the form and says how to start a
 *       session; a session's model call (its prompt pasting the key), then
 *       the page's poll, lists the row and shows the form again on the same
 *       page; the model, the answer and the page never carry the value;
 *   S5  *by its folder* (2026-10-22): two sessions whose agent worked in
 *       `~/projects/shop` (the agent's own environment block), neither prompt
 *       saying "shop", then 31 newer ones elsewhere: `?q=shop` returns
 *       exactly those two, past the first page, the `~` form and the full
 *       path alike, "shop login" the one whose prompt also says it; signed
 *       out the answer is the one signed in gets, and none carries the key
 *       one of them pasted; the served page draws the two with the new
 *       placeholder.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HistoryVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const KEY = `sk_live_51HistSearch${process.pid}Qz8vKp3mWx7RtYb2NcLd`;
const T0 = 1791700000;
const id = (i: number) => `${T0 + i}-${process.pid}`;
const STAGING = [id(0), id(1)];
const SECRET = id(2);
const OTHERS = Array.from({ length: 30 }, (_, i) => id(3 + i));
const ALL = 33;

test("History's search finds a session past the first page by what was asked, and never by a secret's value (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-history-search-"));
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const reg = await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
  assert.match(reg.vars[0]!.symbol ?? "", /^\$MDU:/, JSON.stringify(reg));
  // No `extensions`: the product page only, as the shipped package; signed out.
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }), configEnv: { MANDU_HOME: join(tmp, "home") }, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(buildTextSse("Done.", { deltas: 1 }), "utf8")]) };
  };
  const proxies: AnthropicProxy[] = [];
  // One proxy per session, as each launch starts its own; one prompt each.
  const session = async (sid: string, prompt: string) => {
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: sid, log: () => {} });
    proxies.push(proxy);
    const port = await proxy.listen(0);
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": sid, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }], messages: [{ role: "user", content: prompt }] }),
    });
    assert.equal(res.status, 200, await res.text());
    await proxy.close();
  };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(KEY), `CONFIDENTIALITY VIOLATION: ${where} carries the key's value`);
    assert.ok(!text.includes(KEY.slice(0, 20)), `CONFIDENTIALITY VIOLATION: ${where} carries a piece of the key`);
  };
  const read = async (query: string): Promise<{ h: HistoryVM; text: string }> => {
    const res = await pageFetch(`${base}/api/home/history${query}`);
    const text = await res.text();
    assert.equal(res.status, 200, `signed out, the History read is open: ${text.slice(0, 200)}`);
    noValue(text, `/api/home/history${query}`);
    return { h: JSON.parse(text) as HistoryVM, text };
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rows = (doc: any) => ([...doc.querySelectorAll("#history-list .row.agent")] as any[]).map((r) => r.dataset.session);
  try {
    await session(STAGING[0]!, "Fix deploy/staging.conf before Friday");
    await session(STAGING[1]!, "Why does the staging build fail?");
    await session(SECRET, `Is ${KEY} still valid for payments?`);
    for (const [i, sid] of OTHERS.entries()) await session(sid, `Refactor module ${i} of the parser`);
    assert.ok(!seen.join("\n").includes(KEY), "CONFIDENTIALITY VIOLATION: the model got the key");
    // Emission is asynchronous: wait until every session is listed with its label.
    let first: HistoryVM | null = null;
    for (let i = 0; i < 400; i++) {
      const { h } = await read("");
      first = h;
      const found = (await read("?q=parser")).h;
      if (h.total === ALL && found.total === OTHERS.length && (await read("?q=staging")).h.total === 2) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(first!.total, ALL, JSON.stringify(first).slice(0, 400));

    // ── S1: the matches past the first page ──
    assert.equal(first!.rows.length, 25);
    for (const sid of STAGING) assert.ok(!first!.rows.some((r) => r.id === sid), `${sid} is past the first page`);
    const { h: staging } = await read("?q=staging");
    assert.deepEqual(staging.rows.map((r) => r.id).sort(), [...STAGING].sort(), "exactly the two");
    assert.equal(staging.total, 2, "total counts the matches");
    assert.equal(staging.next, null, "no next page");
    assert.deepEqual(staging.query, { text: "staging", all: ALL });
    assert.deepEqual((await read("?q=STAGING%20friday")).h.rows.map((r) => r.id), [STAGING[0]], "every word, case aside");
    assert.equal((await read("?q=Claude%20Code")).h.total, ALL, "by agent");
    // The matches page as the list does: Show more's cursor is a match.
    const p1 = (await read("?q=parser&limit=20")).h;
    assert.equal(p1.rows.length, 20);
    assert.equal(p1.total, OTHERS.length);
    const p2 = (await read(`?q=parser&after=${encodeURIComponent(p1.next!)}`)).h;
    assert.equal(p2.rows.length, OTHERS.length - 20);
    assert.ok(p2.rows.every((r) => OTHERS.includes(r.id)));

    // ── S2: the served page ──
    await servedProductPage(base, "/history?q=staging", (doc) => rows(doc).length === 2, (doc) => {
      assert.equal(doc.getElementById("page-history").hidden, false);
      assert.deepEqual(rows(doc).sort(), [...STAGING].sort());
      assert.equal(doc.getElementById("history-q").value, "staging");
      assert.equal(doc.getElementById("history-count").textContent, `2 of ${ALL} sessions`);
      assert.equal(doc.querySelector("#history-list .history-more"), null);
    });

    // ── S3: the oracle ──
    const control = (await read("?q=still%20valid%20payments")).h;
    assert.deepEqual(control.rows.map((r) => r.id), [SECRET], "the session is found by its other words");
    assert.match(control.rows[0]!.title ?? "", /\$MDU:/, "its label holds the key masked, as the AI saw it: what the search must not see through");
    for (const q of [KEY, KEY.slice(0, 20), KEY.slice(8, 30), `${KEY} still`]) {
      const { h } = await read(`?q=${encodeURIComponent(q)}`);
      assert.equal(h.total, 0, `CONFIDENTIALITY VIOLATION: a signed-out search for the key's value (${q.length} chars) found a session`);
      assert.deepEqual(h.rows, []);
    }
    await servedProductPage(base, `/history?q=${encodeURIComponent(KEY)}`, (doc) => /No session matches/.test(doc.getElementById("history-list").textContent), (doc) => {
      assert.deepEqual(rows(doc), []);
      // The box holds what was typed (the reader's own words); the list never draws a row's value.
      noValue(doc.getElementById("history-list").textContent.replace(KEY, ""), "the drawn list");
      assert.match(doc.getElementById("history-list").textContent, /No session matches/);
    });
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("History with no session on record hides its search and says how to start one; the poll that brings the first session brings the search back (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-history-empty-"));
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const reg = await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
  assert.match(reg.vars[0]!.symbol ?? "", /^\$MDU:/, JSON.stringify(reg));
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }), configEnv: { MANDU_HOME: join(tmp, "home") }, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(buildTextSse("Done.", { deltas: 1 }), "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: SECRET, log: () => {} });
  const port = await proxy.listen(0);
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(KEY), `CONFIDENTIALITY VIOLATION: ${where} carries the key's value`);
    assert.ok(!text.includes(KEY.slice(0, 20)), `CONFIDENTIALITY VIOLATION: ${where} carries a piece of the key`);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rows = (doc: any) => ([...doc.querySelectorAll("#history-list .row.agent")] as any[]).map((r) => r.dataset.session);
  try {
    const none = JSON.parse(await (await pageFetch(`${base}/api/home/history`)).text()) as HistoryVM;
    assert.equal(none.total, 0, "no session on record");
    await servedProductPage(base, "/history", (doc) => !!doc.querySelector("#history-list .empty"), async (doc) => {
      const form = doc.getElementById("history-search");
      assert.equal(doc.getElementById("page-history").hidden, false);
      assert.equal(form.hidden, true, "nothing to find: no search form");
      assert.equal(doc.getElementById("history-list").textContent, "No session has been recorded yet. Start your agent through Mandu, mandu claude or mandu codex, and it shows up here.");
      const heading = doc.querySelector("#page-history h1");

      // The first session: one model call through the proxy, its prompt
      // pasting the key (masked on the way to the model).
      const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": SECRET, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }], messages: [{ role: "user", content: `Is ${KEY} still valid for payments?` }] }),
      });
      assert.equal(res.status, 200, await res.text());
      assert.ok(!seen.join("\n").includes(KEY), "CONFIDENTIALITY VIOLATION: the model got the key");
      let served = "";
      for (let i = 0; i < 400; i++) {
        served = await (await pageFetch(`${base}/api/home/history`)).text();
        if ((JSON.parse(served) as HistoryVM).total === 1) break;
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal((JSON.parse(served) as HistoryVM).total, 1, served.slice(0, 400));
      noValue(served, "/api/home/history");
      assert.equal(form.hidden, true, "the open page has not read it yet");

      // The page's poll (a return to the tab) lists it and brings the form back.
      doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      await waitWhile(() => rows(doc).length === 0);
      assert.deepEqual(rows(doc), [SECRET], "the row is listed");
      assert.equal(form.hidden, false, "the form is back");
      assert.equal(doc.querySelector("#page-history h1"), heading, "the same page, not opened again");
      noValue(doc.body.textContent, "the drawn History page");
    });
  } finally {
    await proxy.close().catch(() => {});
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("History's search finds the sessions an agent ran in a folder by the folder's name, signed out as signed in, never a value (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-history-folder-"));
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const reg = await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
  assert.match(reg.vars[0]!.symbol ?? "", /^\$MDU:/, JSON.stringify(reg));
  // `~` is this home, as the served page's `home-dir` says.
  const home = join(tmp, "u");
  const shop = join(home, "projects", "shop");
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }), configEnv: { MANDU_HOME: join(tmp, "home") }, fileBrowserHome: home, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { Cookie: dashboard.adminCookie() };
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(buildTextSse("Done.", { deltas: 1 }), "utf8")]) };
  };
  const proxies: AnthropicProxy[] = [];
  // One proxy per session; Claude Code's system prompt names its folder.
  const session = async (sid: string, cwd: string, prompt: string) => {
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: sid, log: () => {} });
    proxies.push(proxy);
    const port = await proxy.listen(0);
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": sid, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-opus-4", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }],
        system: [{ type: "text", text: `You are Claude Code.\n\n# Environment\n - Primary working directory: ${cwd}\n - Platform: linux` }],
        messages: [{ role: "user", content: prompt }],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    await proxy.close();
  };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(KEY), `CONFIDENTIALITY VIOLATION: ${where} carries the key's value`);
    assert.ok(!text.includes(KEY.slice(0, 20)), `CONFIDENTIALITY VIOLATION: ${where} carries a piece of the key`);
  };
  const read = async (query: string, headers: Record<string, string> = {}): Promise<{ h: HistoryVM; text: string }> => {
    const res = await pageFetch(`${base}/api/home/history${query}`, { headers });
    const text = await res.text();
    assert.equal(res.status, 200, text.slice(0, 200));
    noValue(text, `/api/home/history${query}`);
    return { h: JSON.parse(text) as HistoryVM, text };
  };
  const ids = (h: HistoryVM) => h.rows.map((r) => r.id).sort();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rows = (doc: any) => ([...doc.querySelectorAll("#history-list .row.agent")] as any[]).map((r) => r.dataset.session);
  const SHOP = [id(0), id(1)];
  try {
    await session(SHOP[0]!, shop, "fix the flaky test");
    await session(SHOP[1]!, shop, `Is ${KEY} still valid on the login page?`);
    await session(id(2), join(home, "projects", "payments"), "Add a login page");
    for (const [i, sid] of OTHERS.entries()) await session(sid, join(home, "projects", "blog"), `Refactor module ${i} of the parser`);
    assert.ok(!seen.join("\n").includes(KEY), "CONFIDENTIALITY VIOLATION: the model got the key");
    let found: HistoryVM | null = null;
    for (let i = 0; i < 400; i++) {
      found = (await read("?q=shop")).h;
      if ((await read("")).h.total === ALL && found.total === 2 && (await read("?q=blog")).h.total === OTHERS.length) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    const first = (await read("")).h;
    assert.equal(first.total, ALL);
    for (const sid of SHOP) assert.ok(!first.rows.some((r) => r.id === sid), `${sid} is past the first page`);
    assert.ok(first.rows.every((r) => r.cwd === join(home, "projects", "blog")), "each row names its folder");

    // Signed out (the read is open): exactly the two, counted, no next page.
    assert.deepEqual(ids(found!), [...SHOP].sort(), "exactly the sessions in ~/projects/shop");
    assert.equal(found!.total, 2, "total counts the matches");
    assert.equal(found!.next, null);
    assert.deepEqual(found!.query, { text: "shop", all: ALL });
    assert.deepEqual(ids((await read("?q=~%2Fprojects%2Fshop")).h), [...SHOP].sort(), "the folder as the row draws it");
    assert.deepEqual(ids((await read(`?q=${encodeURIComponent(shop)}`)).h), [...SHOP].sort(), "the full path, as its title shows it");
    assert.deepEqual(ids((await read("?q=SHOP%20login")).h), [SHOP[1]!], "every word across the folder and the prompt, case aside");
    assert.deepEqual(ids((await read("?q=payments")).h), [id(2)]);
    // Signed in, the same answer: the match reads only what a row shows.
    const inside = await read("?q=shop", signedIn);
    assert.equal(inside.text, (await read("?q=shop")).text, "signed out reads what signed in reads");
    for (const q of [KEY, KEY.slice(0, 20), `shop ${KEY}`]) {
      for (const headers of [{}, signedIn]) {
        const { h } = await read(`?q=${encodeURIComponent(q)}`, headers);
        assert.equal(h.total, 0, `CONFIDENTIALITY VIOLATION: a search for the key's value (${q.length} chars) found a session`);
      }
    }

    // The served page: the box's new words, the two rows, each "in ~/projects/shop".
    await servedProductPage(base, "/history?q=shop", (doc) => rows(doc).length === 2, (doc) => {
      assert.equal(doc.getElementById("history-q").getAttribute("placeholder"), "What you asked, the agent or the folder");
      assert.deepEqual(rows(doc).sort(), [...SHOP].sort());
      assert.equal(doc.getElementById("history-count").textContent, `2 of ${ALL} sessions`);
      assert.match(doc.getElementById("history-list").textContent, /~\/projects\/shop/);
      noValue(doc.getElementById("history-list").textContent, "the drawn list");
    });
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
