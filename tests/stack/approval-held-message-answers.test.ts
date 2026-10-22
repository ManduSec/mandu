/**
 * approval-held-message-answers — Approvals › Answered earlier says what a
 * held message's answer sent, and offers only a reversal that does what it
 * says, over the PRODUCTION wiring (dashboard.md §4.34 "A held message's
 * answer"). Found 2026-10-11 on an audit of Approvals: a message answered
 * Send masked was listed as "Blocked" with **Allow instead**, and that
 * button (the generic approve, an Always) filed a standing "send as
 * written" for the whole session (prompt-filter holds.ts `afterResolve`),
 * which its words never said.
 *
 * A real ArbiterServer with a file-backed law and a prompt pack, the REAL
 * anthropic-proxy on its production clients, a scripted fake model, and the
 * real DashboardServer over `makeApprovalsArbiter` and `ArbiterEventSource`:
 *
 *   H1  a held message answered Send masked: its answered row reads
 *       `masked` and offers no reversal; the message went masked;
 *   H2  a held message answered Send as written for the session: the
 *       message's own row offers no reversal, the session's row reads
 *       `sent-session` and offers "Send masked instead"; the next message
 *       goes as written without a hold;
 *   H3  "Send masked instead" over the real route: the session's row reads
 *       `masked-session`, and the next message goes masked;
 *   H4  /api/home never carries the found text.
 *
 * And a held message nobody answers (dashboard.md §4.34 *A held message's
 * deadline*), over an arbiter holding 4 s, on the served Approvals page:
 *
 *   H5  the card first says the request waits "N more seconds";
 *   H6  after the deadline, the page's own tick says the message went
 *       masked, announced once (`role="status"`);
 *   H7  the model got the message masked, never the code name.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { startScriptedAnthropic } from "../lib/fake-anthropic.js";
import { humanSockIn } from "../lib/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the confidentiality axis the prompt filter serves; integrity off

const dirs: string[] = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const CODENAME = "heronvaleproject";

function post(port: number, body: unknown, session: string): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": session } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

async function waitFor<T>(what: string, f: () => Promise<T | undefined>, ms = 10_000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await f();
    if (v !== undefined) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** The production wiring: a real ArbiterServer (secrets axes, a prompt pack
 *  asking about CODENAME after `up`), the REAL anthropic-proxy on its
 *  production clients, a scripted fake model, and the real DashboardServer;
 *  `holdMs` is the arbiter's hold deadline. */
async function rig(holdMs: number) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-held-answers-"));
  dirs.push(dir);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const humanSock = humanSockIn(dir);
  const packs = join(dir, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), `pack: acme-dlp\nversion: 1\nkeywords:\n  - category: acme.codename\n    words: [${CODENAME}]\n    level: local-model\n`);
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, "version: 1\nprompt_filters:\n  filters:\n    acme-dlp: on\n");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: null, packDir: null, packKeysDir: join(dir, "keys"), promptHoldMs: holdMs,
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  const session = `held-answers-${process.pid}`;
  await data.setSessionSpec({ sessionKey: session, spec: "claude-code" });
  const fake = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const proxyPort = await proxy.listen(0);
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  const source = new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock });
  const server = new DashboardServer({ source, policyDocArbiter: wired.policyDoc, approvalsArbiter: wired.arbiter, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const call = async (method: "GET" | "POST", path: string, body?: unknown, headers: Record<string, string> = { ...CSRF_ADMIN, "Content-Type": "application/json" }) => {
    const r = await pageFetch(`http://127.0.0.1:${port}/api/${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: r.status, body: (await r.json().catch(() => ({}))) as Record<string, any> };
  };
  const ask = (text: string) => post(proxyPort, {
    model: "claude-sonnet-4-5", stream: true, max_tokens: 64,
    tools: [{ name: "Read", input_schema: { type: "object" } }],
    messages: [{ role: "user", content: [{ type: "text", text }] }],
  }, session);
  const sent = () => fake.requests.filter((q) => q.url.includes("/v1/messages") && q.body.includes('"tools"')).map((q) => q.body);
  const seen = new Set<string>();
  const held = async (text: string) => {
    const pending = ask(text);
    const hold = await waitFor(`the hold of "${text}"`, async () => {
      const h = await call("GET", "prompt-filters/holds");
      return (h.body["holds"] as Array<{ approvalId: string }> | undefined)?.find((x) => !seen.has(x.approvalId));
    });
    seen.add(hold.approvalId);
    return { pending, id: hold.approvalId };
  };
  const up = async () => {
    const r = await call("POST", "policy/prompt-filters/change", { edit: { op: "set-prompt-action", category: "acme.codename", action: "ask" } });
    assert.equal(r.status, 200, JSON.stringify(r.body));
  };
  const close = async () => {
    await server.close?.();
    wired.close();
    await proxy.close();
    await fake.close();
    data.close();
    human.close();
    await arbiter.close();
  };
  return { base: `http://127.0.0.1:${port}`, call, ask, sent, held, up, close };
}

test("a held message's answer reads as what went to the AI, and its only reversal does what it says (secrets axes)", { timeout: 60_000 }, async () => {
  const { call, ask, sent, held, up, close } = await rig(20_000);
  const homeVm = async () => (await call("GET", "home", undefined, {})).body as unknown as HomeVM;
  try {
    await up();

    // H1: Send masked. The row says the message went masked; no reversal.
    const h1 = await held(`plan for ${CODENAME} one`);
    assert.equal((await call("POST", "prompt-filters/holds/answer", { approvalId: h1.id, answer: "mask", scope: "once" })).status, 200);
    assert.equal((await h1.pending).status, 200);
    assert.ok(!sent().at(-1)!.includes(CODENAME), "the message went masked");
    let vm = await homeVm();
    const r1 = vm.answered.find((a) => a.id === h1.id)!;
    assert.equal(r1.outcome, "masked", "never Blocked for a message that went masked");
    assert.deepEqual(r1.actions, [], "no Allow instead: the message went, and the generic Allow would answer for the session");

    // H2: Send as written for the session.
    const h2 = await held(`plan for ${CODENAME} two`);
    assert.equal((await call("POST", "prompt-filters/holds/answer", { approvalId: h2.id, answer: "send", scope: "session" })).status, 200);
    assert.equal((await h2.pending).status, 200);
    assert.ok(sent().at(-1)!.includes(`${CODENAME} two`), "sent as written");
    vm = await homeVm();
    const r2 = vm.answered.find((a) => a.id === h2.id)!;
    assert.equal(r2.outcome, "sent-session");
    assert.deepEqual(r2.actions, [], "the message's own row: no reversal");
    const sessionRow = vm.answered.find((a) => a.id !== h1.id && a.id !== h2.id && a.outcome === "sent-session");
    assert.ok(sessionRow, `the session's answer is listed: ${JSON.stringify(vm.answered)}`);
    assert.deepEqual(sessionRow!.actions.map((a) => [a.approve, a.label]), [[false, "Send masked instead"]]);
    assert.equal((await ask(`plan for ${CODENAME} three`)).status, 200);
    assert.ok(sent().at(-1)!.includes(`${CODENAME} three`), "the session's answer covers the next message, no hold");

    // H3: Send masked instead, over the real route the page uses.
    const flip = await call("POST", `egress/approvals/${sessionRow!.id}/deny`, undefined, CSRF_ADMIN);
    assert.equal(flip.status, 200, JSON.stringify(flip.body));
    vm = await homeVm();
    const flipped = vm.answered.find((a) => a.id === sessionRow!.id)!;
    assert.equal(flipped.outcome, "masked-session");
    assert.deepEqual(flipped.actions.map((a) => [a.approve, a.label]), [[true, "Send as written instead"]]);
    assert.equal((await ask(`plan for ${CODENAME} four`)).status, 200);
    assert.ok(!sent().at(-1)!.includes(CODENAME), "the next message goes masked");

    // H4: the found text never on the open route.
    assert.ok(!JSON.stringify(await homeVm()).includes(CODENAME), "/api/home never carries the found text");
  } finally {
    await close();
  }
});

test("a held message's Approvals card counts down its deadline, then says the message went masked; the model got it masked (secrets axes)", { timeout: 90_000 }, async () => {
  const HOLD_MS = 4000;
  const { base, held, sent, up, close } = await rig(HOLD_MS);
  try {
    await up();
    // The page is opened before the message is sent, so the deadline is
    // not spent on loading it; a poll then draws the card.
    await servedProductPage(base, "/approvals", (doc: any) => !!doc.querySelector('#approvals-waiting [data-empty="questions"], #approvals-waiting .empty'), async (doc: any) => {
      const h5 = await held(`plan for ${CODENAME} five`);
      Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
      doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      const lineOf = () => doc.querySelector(`#approvals-waiting .ask[data-id="${h5.id}"] .ask-hold`);
      const say = () => String(lineOf()?.textContent ?? "");
      // H5: first it says it waits, and how long, from the route's time left.
      await waitFor("the counting line", async () => (/waits \d+ more seconds?/.test(say()) || /^No answer/.test(say()) ? true : undefined));
      assert.match(say(), /^The request to the AI waits [1-4] more seconds? for your answer, then goes with that part masked\.$/);
      assert.equal(doc.querySelector(`#approvals-waiting .ask[data-id="${h5.id}"] .ask-found`).textContent, `It found: ${CODENAME}`);
      // H6: after the deadline the page's own tick says it went, and when.
      await waitFor("the past line", async () => (/^No answer/.test(say()) ? true : undefined), 15_000);
      assert.match(say(), /^No answer came within 4 seconds, so your message went to the AI with that part masked at .+\. Your answer applies the next time the agent sends it\.$/);
      assert.equal(lineOf().getAttribute("role"), "status", "the change is announced once");
      // H7: the oracle, unchanged: the request went masked, never the span.
      assert.equal((await h5.pending).status, 200);
    }, { headers: { Cookie: ADMIN_COOKIE } });
    assert.ok(sent().length > 0, "the request reached the model");
    assert.ok(!sent().at(-1)!.includes(CODENAME), "CONFIDENTIALITY VIOLATION: the held message reached the model unmasked");
  } finally {
    await close();
  }
});
