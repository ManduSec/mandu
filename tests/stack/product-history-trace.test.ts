/**
 * product-history-trace.test — a product-only dashboard is a whole trace,
 * across the REAL components (dashboard.md §4.25ae). Mandu-new.
 *
 * The developer view leaves the shipped package (the design note in the
 * private tree, step 2), so a user with the product page alone must still
 * see, for every session, what the AI saw against what really happened.
 * Here a real ArbiterServer runs at the `secrets` axes, the REAL
 * anthropic-proxy on its production client carries one turn in which a
 * scripted model reads a `.env`, and a DashboardServer built with no
 * extensions (the product page only) reads it over a real
 * ArbiterEventSource, signed out:
 *
 *   T1  `/api/home/history` lists the session, counted as its Home row is
 *       (its secret masked), with no value; the served `/history` page draws
 *       its row, whose link is that session's agent page, and a click on
 *       the row's prompt opens that page in place (§4.25 *A click on a
 *       session's row opens it*), with no value or token on it;
 *   T2  the served agent page (its own index.html and home.js in jsdom) shows
 *       the Read as two halves, "What the AI saw" (a placeholder) and "What
 *       really happened" (the secret by its name), and Your secrets says the
 *       AI got only a placeholder; the leak check found nothing, so no
 *       finding block; no link into `/dev/`, no word naming the trace;
 *   T3  the oracle: the model never got the value, and no answer or page
 *       carries it or a token; the whole-original route is refused signed out;
 *   T4  a session whose Read result the leak check flagged (its record over
 *       the arbiter's IPC, `violatedInvariant`, as the fixtures record one):
 *       the served agent page, signed in and out, shows *What the leak check
 *       found* and then *What to do now*, which names the secret by its name
 *       and links Report a problem; no rendered text carries the value or a
 *       token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
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
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import type { HistoryVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { ISSUES_URL } from "../../dashboard/src/agent-versions.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = `1791500000-${process.pid}`;
const VALUE = `sk_live_historyTraceCanary_${process.pid}_000000`;

function readTurn(path: string): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_ht_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_ht_0", name: "Read", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ file_path: path }) } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

function post(port: number, messages: unknown[], session = SESSION): Promise<number> {
  const body = JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages });
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
    r.on("error", reject);
    r.end(body);
  });
}

test("a product-only dashboard shows a session's trace: History lists it, its agent page shows what the AI saw against what happened, signed out, with no value (secrets axes, explicit)", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-history-trace-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const gate = new ArbiterClient(sock); await gate.connect();
  const humanClient = new ArbiterClient(human); await humanClient.connect();
  // No `extensions`: the product page only, as the shipped package.
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: human }), log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? readTurn(env) : buildTextSse("I read it; the key is hidden from me.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(gate, humanClient), upstream, sessionKey: SESSION, log: () => {} });
  const proxyPort = await proxy.listen(0);
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the secret value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  try {
    const ask = "Read the .env file.";
    assert.equal(await post(proxyPort, [{ role: "user", content: ask }]), 200);
    assert.equal(await post(proxyPort, [
      { role: "user", content: ask },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_ht_0", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_ht_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
    ]), 200);
    // T3 on the model's side.
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");

    // T1: History lists the session, counted, with no value.
    let historyText = "";
    let history: HistoryVM | null = null;
    for (let i = 0; i < 200; i++) {
      historyText = await (await pageFetch(`${base}/api/home/history`)).text();
      history = JSON.parse(historyText) as HistoryVM;
      const row = history.rows.find((r) => r.id === SESSION);
      if (row && row.secrets.masked === 1) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    const row = history?.rows.find((r) => r.id === SESSION);
    assert.ok(row, historyText.slice(0, 400));
    assert.equal(row.secrets.masked, 1, "counted as its Home row is");
    assert.equal(row.holds, true);
    noValue(historyText, "/api/home/history");
    await servedProductPage(base, "/history", (doc) => doc.querySelector("#history-list .row.agent") !== null, async (doc) => {
      assert.equal(doc.getElementById("page-history").hidden, false);
      const drawn = [...doc.querySelectorAll("#history-list .row.agent")].find((r) => (r as { dataset: { session: string } }).dataset.session === SESSION) as { querySelector(s: string): { getAttribute(a: string): string } } | undefined;
      assert.ok(drawn, "the session's row");
      assert.equal(drawn.querySelector("a").getAttribute("href"), `/agents/${encodeURIComponent(SESSION)}`);
      assert.equal(doc.getElementById("home-history").hidden, false, "Home's link to it is shown in a product-only build");
      noValue(doc.body.textContent, "the rendered History page");
      // A click on the row's prompt, not its Details, opens the session.
      const prompt = (drawn as unknown as { querySelector(s: string): { dispatchEvent(e: unknown): boolean } }).querySelector(".agent-what .sub");
      prompt.dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true, cancelable: true }));
      await waitWhile(() => doc.querySelector("#agent-story .step.split") === null);
      assert.equal(doc.defaultView.location.pathname, `/agents/${encodeURIComponent(SESSION)}`, "the row's session");
      assert.equal(doc.getElementById("page-agent").hidden, false);
      assert.equal(doc.getElementById("page-history").hidden, true);
      assert.ok(doc.querySelector("#agent-story .step.split"), "its trace drawn");
      noValue(doc.body.textContent, "the agent page a row click opened");
    });

    // T2: the agent page, signed out: what the AI saw against what happened.
    const pageText = await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`)).text();
    const page = JSON.parse(pageText) as AgentPageVM;
    assert.equal(page.found, true);
    assert.equal(page.valuesShown, false);
    assert.equal(page.finding, null, "the leak check found nothing");
    noValue(pageText, "/api/home/agent");
    assert.doesNotMatch(pageText, /detailed trace|developer view|"trace":/i);
    await servedProductPage(base, `/agents/${encodeURIComponent(SESSION)}`, (doc) => doc.querySelector("#agent-story .step.split") !== null, (doc) => {
      const split = doc.querySelector("#agent-story .step.split");
      assert.equal(split.querySelector(".half.saw .half-label").textContent, "What the AI saw");
      assert.equal(split.querySelector(".half.real .half-label").textContent, "What really happened");
      assert.ok(split.querySelector(".half.saw .chip, .half.saw [class*=chip]") || /secret/.test(split.querySelector(".half.saw").textContent), "the AI saw a placeholder");
      assert.match(split.querySelector(".half.real").textContent, /The result held your secret \.env\./, "what happened names the secret");
      assert.match(doc.getElementById("agent-secrets").textContent, /The AI got only a placeholder, never the real value\./);
      assert.equal(doc.getElementById("agent-finding-block").hidden, true);
      assert.equal(doc.getElementById("agent-trace").hidden, true, "no Detailed trace button");
      const devLinks = [...doc.querySelectorAll("a")].filter((a) => /\/dev\//.test((a as { href: string }).href) && !(a as { closest(s: string): unknown }).closest("[hidden]"));
      assert.deepEqual(devLinks, []);
      noValue(doc.body.textContent, "the rendered agent page");
    });

    // T3: the whole-original route is the signed-in reader's.
    const whole = await pageFetch(`${base}/api/home/original?session=${SESSION}&step=${encodeURIComponent("tool:toolu_ht_0")}`);
    assert.equal(whole.status, 403);
    noValue(await whole.text(), "/api/home/original signed out");
  } finally {
    await proxy.close();
    await dashboard.close();
    gate.close();
    humanClient.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("a session the leak check flagged: its agent page says what to do now, naming the secret by its name and linking Report a problem, signed in and out, with no value (secrets axes, explicit)", { timeout: 60_000 }, async () => {
  const FLAGGED = `${SESSION}-flagged`;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-history-todo-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const gate = new ArbiterClient(sock); await gate.connect();
  const humanClient = new ArbiterClient(human); await humanClient.connect();
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: human }), log: () => {}, ...ADMIN_OPTS });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? readTurn(env) : buildTextSse("Done.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(gate, humanClient), upstream, sessionKey: FLAGGED, log: () => {} });
  const proxyPort = await proxy.listen(0);
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the secret value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  try {
    const ask = "Read the .env file.";
    assert.equal(await post(proxyPort, [{ role: "user", content: ask }], FLAGGED), 200);
    assert.equal(await post(proxyPort, [
      { role: "user", content: ask },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_ht_0", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_ht_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
    ], FLAGGED), 200);
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    // Wait for the proxy's record of the Read, then flag that result as
    // the leak check records one (the detail quotes what it found).
    let pageText = "";
    for (let i = 0; i < 200; i++) {
      pageText = await (await pageFetch(`${base}/api/home/agent?session=${FLAGGED}`)).text();
      if (pageText.includes("toolu_ht_0") && /The result held your secret/.test(pageText)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    await gate.emit({
      id: `leak-${process.pid}`, sessionId: FLAGGED, turn: 1, ts: new Date().toISOString(), seq: 0, callId: "toolu_ht_0", parentId: null,
      kind: "tool_result", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
      input: null, output: null, invariant: { violatedInvariant: true, detail: `un-symbolized span survived: STRIPE_KEY=${VALUE}` },
    } as never);
    const read = async (signedIn: boolean): Promise<string> =>
      (await pageFetch(`${base}/api/home/agent?session=${FLAGGED}`, signedIn ? { headers: CSRF_ADMIN } : {})).text();
    let page: AgentPageVM | null = null;
    for (let i = 0; i < 200; i++) {
      page = JSON.parse(await read(false)) as AgentPageVM;
      if (page.finding) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(page?.finding, "the leak check's finding");
    for (const signedIn of [true, false]) {
      const who = signedIn ? "signed in" : "signed out";
      const text = await read(signedIn);
      const vm = JSON.parse(text) as AgentPageVM;
      assert.equal(vm.valuesShown, signedIn, who);
      const todo = vm.finding!.todo.map((l) => l.map((p) => p.text).join(""));
      assert.equal(todo[0], "Change .env where it was issued, and turn the old one off: the AI's provider received it as it was.", `${who}: ${JSON.stringify(todo)}`);
      noValue(text, `${who}: /api/home/agent`);
      await servedProductPage(base, `/agents/${encodeURIComponent(FLAGGED)}`, (doc) => doc.querySelector("#agent-finding-todo li") !== null, (doc) => {
        assert.equal(doc.getElementById("agent-finding-block").hidden, false, who);
        assert.equal(doc.getElementById("agent-finding-todo-title").textContent, "What to do now");
        const lines = [...doc.querySelectorAll("#agent-finding-todo li")].map((li) => (li as { textContent: string }).textContent);
        assert.match(lines[0]!, /^Change \.env where it was issued/, who);
        assert.equal(lines[lines.length - 1], "This is a fault in Mandu, not in your rules. Report a problem, with this session's time. Never paste the key itself.");
        const link = doc.querySelector("#agent-finding-todo a") as { getAttribute(a: string): string };
        assert.equal(link.getAttribute("href"), ISSUES_URL);
        assert.equal(link.getAttribute("target"), "_blank");
        noValue(doc.body.textContent, `${who}: the rendered agent page`);
      }, signedIn ? { headers: CSRF_ADMIN } : {});
    }
  } finally {
    await proxy.close();
    await dashboard.close();
    gate.close();
    humanClient.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
