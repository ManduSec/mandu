/**
 * dashboard-answer-line.test — an answer says what it did, across the REAL
 * components (dashboard.md §4.25 *An answer says what it did*). Mandu-new.
 *
 * Until 2026-10-22 Allow once on Home's card "Claude Code wants to send your
 * secret STRIPE_KEY to api.stripe.com" drew Home as "Nothing is waiting for
 * you.": nothing said the answer was recorded, nor that Mandu had refused
 * the send and only the agent's next try goes. Here a real ArbiterServer
 * runs at the `secrets` axes, a Claude Code session is on record (its
 * anthropic-proxy events), the net-proxy in its production wiring stops the
 * session's send of a registered key, and a real DashboardServer over the
 * production approvals adapter serves the product page (its own index.html
 * and home.js in jsdom):
 *
 *   W1  the send is stopped and never forwarded: one question waits, its
 *       card on Home names the agent, the key and the host;
 *   W2  Allow once on Home's card, over the real route and resolve op:
 *       Home shows "Allowed once: send your secret STRIPE_KEY to
 *       api.stripe.com. Tell Claude Code to try again." where the card was,
 *       as a status with the focus; the arbiter has the answer, once;
 *   W3  its Change your answer opens Approvals at the answered row
 *       (`/approvals/<id>`), which offers Block instead;
 *   W4  the oracle: neither the line, its link, `/api/home`, nor any page
 *       drawn carries the key's value or a token; nothing was forwarded.
 *
 * And an answer its row on Approvals cannot change (2026-10-28): the REAL
 * anthropic-proxy holds a message under a prompt filter set to ask (as
 * approval-held-message-answers.test.ts holds one), on a real arbiter at
 * the `secrets` axes, and the served Home answers it:
 *
 *   W5  Send masked on Home's card: the line reads "Sent masked: … It
 *       applied to that message only. See your answer";
 *   W6  its link opens Approvals at that row, which offers no change;
 *   W7  the oracle: the line names nothing past what the card named (not
 *       the found text) and no token; the model got the message masked.
 *
 * Axes: secrets (stated; both arbiters' confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as ProxyArbiterAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { startScriptedAnthropic } from "../lib/fake-anthropic.js";

stateAxes("secrets");

const KEY_VALUE = "sk_" + "live_answerLineStackCanary0000000001";
const SESSION = "1791400000-0559";
const CSRF = { "X-Mandu-Control": "1" };
const LINE = "Allowed once: send your secret STRIPE_KEY to api.stripe.com. Tell Claude Code to try again. Change your answer";

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

/** Enter on a button: it has the focus, the click answers, and the browser
 *  drops the focus of the button the answer turned off to <body>. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function press(btn: any): void {
  assert.ok(btn, "the button is there");
  btn.focus();
  btn.click();
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
}
const said = (parts: { text: string }[]) => parts.map((p) => p.text).join("");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const words = (x: any) => String(x.textContent).replace(/\s+/g, " ").trim();

test("Allow once on Home leaves a line that says what was allowed and to tell Claude Code to try again; its link opens the answered row (real arbiter, net-proxy, dashboard, served page); no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-answer-line-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();

  // Production wiring of the net-proxy's arbiter (net-proxy/src/server-main.ts).
  const netClient = new ArbiterClient(socketPath);
  await netClient.connect();
  const netHuman = new ArbiterClient(humanPath);
  const forwarded: string[] = [];
  const proxy = new NetProxy({
    arbiter: new ArbiterClientAdapter(netClient as unknown as RealArbiterClient, netHuman),
    sessionId: SESSION,
    forwarder: async ({ url }) => {
      forwarded.push(url);
      throw new Error("a stopped send must never be forwarded");
    },
    log: () => {},
  });
  const proxyPort = await proxy.listen(0);

  const gate = new ArbiterClient(socketPath); await gate.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const approvalsArbiter: ApprovalsArbiter = {
    egressApprovals: (status) => admin.egressApprovals(status),
    resolveEgressApproval: (approvalId, approve, scope) => admin.resolveEgressApproval(approvalId, approve, scope),
  };
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { Cookie: dashboard.adminCookie() };
  const rendered: [string, string][] = [];
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  try {
    // ── W1: a Claude Code session's send of a registered key is stopped ─────
    await human.emit({
      id: "al-call-1", ts: new Date(Date.now() - 30_000).toISOString(), kind: "tllm_call", sessionId: SESSION,
      view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
      input: { symbolized: "Charge the test card.", original: null, differs: false, symbols: [] },
    } as never);
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const res = await viaProxy(proxyPort, "http://api.stripe.com/v1/charges", `key=${keySym}`);
    assert.equal(res.status, 403, `the send is stopped: ${res.body}`);
    assert.ok(!res.body.includes(KEY_VALUE), "the agent's answer carries no value");
    assert.deepEqual(forwarded, []);
    const pending = (await admin.egressApprovals("pending")).filter((a) => a.symbol === keySym);
    assert.equal(pending.length, 1, "one question waits");
    const id = String(pending[0]!.id);
    // The session is listed as Claude Code's (emission is asynchronous).
    const homeVm = async () => (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    let card = (await homeVm()).waiting.find((a) => a.id === id);
    for (const end = Date.now() + 20_000; !(card && said(card.sentence).startsWith("Claude Code ")) && Date.now() < end;) {
      await new Promise((r) => setTimeout(r, 100));
      card = (await homeVm()).waiting.find((a) => a.id === id);
    }
    assert.ok(card, "the question is on Home");
    assert.equal(said(card.sentence), "Claude Code wants to send your secret STRIPE_KEY to api.stripe.com");
    assert.equal(card.afterAllow, "Tell Claude Code to try again.");

    // ── W2: Allow once on Home; the line where the card was ─────────────────
    // ── W3: its link opens Approvals at the answered row ────────────────────
    const cardIn = (doc: any) => doc.querySelector(`#home-waiting > .ask[data-id="${id}"]`); // eslint-disable-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, "/", (doc) => cardIn(doc) !== null, async (doc) => {
      const allow = [...cardIn(doc).querySelectorAll("button")].find((b: any) => b.textContent === "Allow once"); // eslint-disable-line @typescript-eslint/no-explicit-any
      press(allow);
      const line = () => doc.querySelector("#home-waiting > .answer-line");
      await waitWhile(() => line() === null, 20_000);
      assert.equal(cardIn(doc), null, "the card went");
      assert.equal(words(line()), LINE);
      assert.equal(line().getAttribute("role"), "status");
      assert.equal(doc.activeElement, line(), "the line has the focus");
      const link = line().querySelector("a");
      assert.equal(link.getAttribute("href"), `/approvals/${encodeURIComponent(id)}`);
      assert.equal(link.textContent, "Change your answer");
      rendered.push(["Home after the answer", doc.documentElement.outerHTML]);
      link.click();
      const row = () => doc.querySelector(`#approvals-answered > [data-id="${id}"]`);
      await waitWhile(() => row() === null, 20_000);
      assert.equal(doc.defaultView.location.pathname, `/approvals/${encodeURIComponent(id)}`);
      assert.ok([...row().querySelectorAll("button")].some((b: any) => b.textContent === "Block instead"), "the answered row offers its change"); // eslint-disable-line @typescript-eslint/no-explicit-any
      assert.match(words(row()), /Allowed once, unused/);
      rendered.push(["Approvals from the line's link", doc.documentElement.outerHTML]);
    }, { headers: signedIn });
    const answered = (await admin.egressApprovals("approved")).filter((a) => a.id === id);
    assert.equal(answered.length, 1, "the arbiter has the answer");
    assert.equal(answered[0]!.scope, "once");

    // ── W4: the oracle ───────────────────────────────────────────────────────
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");
    assert.deepEqual(forwarded, [], "nothing was forwarded");
    const bodies: [string, string][] = [
      ["/api/home", await (await pageFetch(`${base}/api/home`)).text()],
      ["/api/home signed in", await (await pageFetch(`${base}/api/home`, { headers: { ...CSRF, ...signedIn } })).text()],
      ...rendered,
    ];
    for (const [where, body] of bodies) {
      assert.ok(!body.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: the key's value is in ${where}`);
      assert.doesNotMatch(body, /\$MDU/, `${where} carries no token`);
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    await proxy.close();
    netClient.close(); netHuman.close();
    gate.close(); admin.close(); human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

const CODENAME = "heronvaleanswerline";

test("Send masked on a held message leaves a line that ends See your answer; its link opens a row with no change (real arbiter, anthropic-proxy, dashboard, served page)", { timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-answer-line-held-"));
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
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {}, // the `secrets` axes, stated
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: null, packDir: null, packKeysDir: join(dir, "keys"), promptHoldMs: 20_000,
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const session = `answer-line-held-${process.pid}`;
  await data.setSessionSpec({ sessionKey: session, spec: "claude-code" });
  const fake = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const proxy = new AnthropicProxy({ arbiter: new ProxyArbiterAdapter(data, human), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const proxyPort = await proxy.listen(0);
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock }), policyDocArbiter: wired.policyDoc, approvalsArbiter: wired.arbiter, log: () => {}, ...ADMIN_OPTS });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await pageFetch(`${base}/api/${path}`, { method, headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: r.status, body: (await r.json().catch(() => ({}))) as Record<string, unknown> };
  };
  const sent = () => fake.requests.filter((q) => q.url.includes("/v1/messages") && q.body.includes('"tools"')).map((q) => q.body);
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  try {
    const up = await call("POST", "policy/prompt-filters/change", { edit: { op: "set-prompt-action", category: "acme.codename", action: "ask" } });
    assert.equal(up.status, 200, JSON.stringify(up.body));
    // The agent sends the person's message; the arbiter holds it.
    const body = Buffer.from(JSON.stringify({
      model: "claude-sonnet-4-5", stream: true, max_tokens: 64, tools: [{ name: "Read", input_schema: { type: "object" } }],
      messages: [{ role: "user", content: [{ type: "text", text: `plan for ${CODENAME} next week` }] }],
    }));
    const pending = new Promise<number>((resolve, reject) => {
      const req = httpRequest({ host: "127.0.0.1", port: proxyPort, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "content-length": String(body.length), "x-mandu-session-id": session } },
        (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
      req.on("error", reject);
      req.end(body);
    });
    let id = "";
    for (const end = Date.now() + 10_000; !id && Date.now() < end;) {
      const holds = (await call("GET", "prompt-filters/holds")).body["holds"] as Array<{ approvalId: string }> | undefined;
      id = holds?.[0]?.approvalId ?? "";
      if (!id) await new Promise((r) => setTimeout(r, 50));
    }
    assert.ok(id, "the message is held");

    // ── W5: Send masked on Home; the line where the card was ────────────────
    // ── W6: its link opens Approvals at that row, which offers no change ────
    const cardIn = (doc: any) => doc.querySelector(`#home-waiting > .ask[data-id="${id}"]`); // eslint-disable-line @typescript-eslint/no-explicit-any
    let lineSaid = "";
    await servedProductPage(base, "/", (doc) => cardIn(doc) !== null, async (doc) => {
      const mask = [...cardIn(doc).querySelectorAll("button")].find((b: any) => b.textContent === "Send masked"); // eslint-disable-line @typescript-eslint/no-explicit-any
      press(mask);
      const line = () => doc.querySelector("#home-waiting > .answer-line");
      await waitWhile(() => line() === null, 20_000);
      assert.equal(cardIn(doc), null, "the card went");
      lineSaid = words(line());
      assert.equal(lineSaid, "Sent masked: the AI reads your message with that part masked. It applied to that message only. See your answer");
      const link = line().querySelector("a");
      assert.equal(link.textContent, "See your answer");
      assert.equal(link.getAttribute("href"), `/approvals/${encodeURIComponent(id)}`);
      link.click();
      const row = () => doc.querySelector(`#approvals-answered > [data-id="${id}"]`);
      await waitWhile(() => row() === null, 20_000);
      assert.equal(doc.defaultView.location.pathname, `/approvals/${encodeURIComponent(id)}`);
      assert.match(words(row()), /Sent masked, or cancelled/);
      assert.deepEqual([...row().querySelectorAll("button")].map((b: any) => b.textContent).filter((t: string) => /instead$/.test(t)), [], "the row offers no change"); // eslint-disable-line @typescript-eslint/no-explicit-any
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // ── W7: the oracle ───────────────────────────────────────────────────────
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");
    assert.ok(!lineSaid.includes(CODENAME), "the line names nothing past what the card named");
    assert.doesNotMatch(lineSaid, /\$MDU/, "the line carries no token");
    assert.equal(await pending, 200, "the held request went on");
    assert.ok(sent().length > 0 && !sent().at(-1)!.includes(CODENAME), "the model got the message masked");
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    wired.close();
    await proxy.close();
    await fake.close();
    data.close(); human.close();
    await arbiter.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
