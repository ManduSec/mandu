/**
 * history-says-waiting.test — History says what waits for you, across the
 * REAL components (dashboard.md §4.25ae *History says what waits for you*).
 * Mandu-new.
 *
 * History drew no row's waiting question: the route never read the queue, so
 * a running agent that waited for your OK read "running now" with the green
 * dot, where Home's Running now said it waited for your OK, and an ended
 * session's question still waiting was said nowhere on History. Here a real
 * ArbiterServer runs at the `secrets` axes; the REAL anthropic-proxy on its
 * production client carries two sessions, A and B; each asks the arbiter's
 * egress gate (from the human socket, as the real proxies ask) to send a
 * registered key to a host no rule binds it to; B's launcher records its
 * REAL `session_exit`. A product-only DashboardServer reads them over a real
 * ArbiterEventSource, its approvals through the production adapter
 * (`makeApprovalsArbiter`), and serves `/history` (its own index.html and
 * home.js in jsdom), signed out:
 *
 *   W1  the server's History: A is waiting with 1 question, B ended with 1;
 *       Home's rows of the same sessions say the same, and the served Home
 *       draws them with History's first line (A keeps what you asked under
 *       Running now, B under Earlier);
 *   W2  the drawn page: A's row has the amber dot and "1 question waiting
 *       for you", B's says it and "ended";
 *   W3  A's question answered (Block, over the real route): the page's poll
 *       draws A without it and with the green dot; B's is unchanged;
 *   W4  the oracle: the model never got the value, and neither History's
 *       answers nor the drawn page carries it or a token.
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
import { buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { emitLauncherEvent, sessionExitEvent } from "../../launcher/src/services/observe.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import type { HistoryVM, HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { humanSockIn } from "../lib/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const A = `1791700000-${process.pid}`;
const B = `1791700100-${process.pid}`;
const VALUE = `sk_live_historyWaitingCanary_${process.pid}_000000`;

test("History says what waits for you on the real stack: a running agent's question and an ended one's, as Home says them, and an answer clears it on the poll; no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-history-waiting-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const data = await open(sock);
  const human = await open(humanSock);
  const guard = await open(humanSock);
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production approvals adapter");
  // No `extensions`: the product page only, as the shipped package.
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(buildTextSse("Done.", { deltas: 1 }), "utf8")]) };
  };
  // One proxy per session, as each launch starts its own.
  const proxyA = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: A, log: () => {} });
  const proxyB = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: B, log: () => {} });
  const portA = await proxyA.listen(0);
  const portB = await proxyB.listen(0);
  const ask = async (port: number, session: string, prompt: string) => {
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, messages: [{ role: "user", content: prompt }] }),
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
  const rowIn = (h: { rows?: HistoryVM["rows"]; agents?: HomeVM["agents"] }, id: string) => (h.rows ?? h.agents ?? []).find((r) => r.id === id);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rowOf = (doc: any, id: string) => [...doc.querySelectorAll("#history-list .row.agent")].find((r: any) => r.dataset.session === id) as any;
  try {
    // Both sessions talk to the model; B's launcher records its exit.
    await ask(portA, A, "Deploy the billing service.");
    await ask(portB, B, "Send the weekly report.");
    assert.ok(await emitLauncherEvent(sock, sessionExitEvent({ scopeId: B, code: 0, durationMs: 4_000 }), humanSock), "the launcher's emit lands");
    // A key each agent's next step would send to a host no rule binds it to.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
    const reg = await data.registerSecret({ path: env, sessionKey: A });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const send = (session: string, destination: string) => guard.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination, sessionKey: session, scheme: "https" });
    const fromA = await send(A, "api.stripe.com");
    const fromB = await send(B, "hooks.example.com");
    assert.equal(fromA.allow, false);
    assert.equal(fromB.allow, false);
    const askA = String((fromA as { approvalId?: string }).approvalId);

    // W1: the server's History, and Home's rows of the same sessions.
    const w1 = await history((h) => rowIn(h, A)?.waiting === 1 && rowIn(h, B)?.waiting === 1 && rowIn(h, B)?.state === "idle");
    assert.equal(rowIn(w1.h, A)!.state, "waiting", "A runs and waits for your OK");
    noValue(w1.text, "/api/home/history");
    const homeText = await (await pageFetch(`${base}/api/home`)).text();
    const homeVm = JSON.parse(homeText) as HomeVM;
    for (const id of [A, B]) {
      assert.deepEqual({ state: rowIn(homeVm, id)!.state, waiting: rowIn(homeVm, id)!.waiting }, { state: rowIn(w1.h, id)!.state, waiting: rowIn(w1.h, id)!.waiting }, `Home and History agree on ${id}`);
    }

    // Home's rows of the same sessions, drawn: A under Running now keeps
    // what you asked, its counts leading with the question; B is under
    // Earlier (dashboard.md §4.25 *Agents, not sessions*).
    const homeLine: Record<string, string> = {};
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const homeRow = (doc: any, host: string, id: string) => doc.querySelector(`#${host} .row.agent[data-session="${id}"]`);
    await servedProductPage(base, "/", (doc) => homeRow(doc, "home-agents", A) !== null && homeRow(doc, "home-earlier", B) !== null, async (doc) => {
      const a = homeRow(doc, "home-agents", A);
      assert.equal(a.querySelector(".dot").className, "dot warn", "the amber dot says it waits");
      assert.match(a.querySelector(".agent-counts").textContent, /^1 question waiting for you/);
      assert.doesNotMatch(a.textContent, /Waiting for your OK/, "the state is not put in the prompt's place");
      homeLine[A] = a.querySelector(".agent-what .sub").textContent;
      homeLine[B] = homeRow(doc, "home-earlier", B).querySelector(".agent-what .sub").textContent;
      noValue(doc.body.textContent, "the rendered Home page");
    });
    assert.match(homeLine[A]!, /^Deploy the billing service\./, "Home's waiting row keeps its prompt");
    assert.match(homeLine[B]!, /^Send the weekly report\./);

    await servedProductPage(base, "/history", (doc) => rowOf(doc, A) !== undefined && rowOf(doc, B) !== undefined, async (doc) => {
      // W2: the drawn rows, each with the first line Home drew for it.
      for (const id of [A, B]) assert.equal(rowOf(doc, id).querySelector(".agent-what .sub").textContent, homeLine[id], `Home and History describe ${id} alike`);
      assert.equal(doc.getElementById("page-history").hidden, false);
      assert.equal(rowOf(doc, A).querySelector(".dot").className, "dot warn", "Running now's dot for an agent waiting for your OK");
      assert.match(rowOf(doc, A).querySelector(".agent-counts").textContent, /1 question waiting for you/);
      assert.match(rowOf(doc, A).textContent, /Deploy the billing service\./, "the row keeps its prompt");
      assert.match(rowOf(doc, A).textContent, /running now, started/);
      assert.match(rowOf(doc, B).querySelector(".agent-counts").textContent, /1 question waiting for you/);
      assert.match(rowOf(doc, B).textContent, /ended/);

      // W3: A's question answered (Block, over the real route); the poll draws it.
      const blocked = await pageFetch(`${base}/api/egress/approvals/${encodeURIComponent(askA)}/deny`, { method: "POST", headers: CSRF_ADMIN });
      assert.equal(blocked.status, 200, await blocked.text());
      await history((h) => rowIn(h, A)?.waiting === 0 && rowIn(h, A)?.state === "running");
      doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      await waitWhile(() => /waiting for you/.test(rowOf(doc, A)?.textContent ?? ""));
      assert.doesNotMatch(rowOf(doc, A).textContent, /waiting for you/, "the answered question is no longer counted");
      assert.equal(rowOf(doc, A).querySelector(".dot").className, "dot ok");
      assert.match(rowOf(doc, B).querySelector(".agent-counts").textContent, /1 question waiting for you/, "B's question still waits");

      // W4: the drawn page carries no value.
      noValue(doc.body.textContent, "the rendered History page");
    });
    noValue(homeText, "/api/home");
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the value");
  } finally {
    await proxyA.close();
    await proxyB.close();
    await dashboard.close();
    wired?.close();
    for (const c of clients) c.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
