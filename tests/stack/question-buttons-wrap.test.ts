/**
 * question-buttons-wrap — on a phone, a question card's answers wrap inside
 * the card, for a held message's answers and a send's, across the REAL
 * arbiter, anthropic-proxy, server and served pages and styles
 * (dashboard.md §4.25 *A question's buttons wrap inside its card*).
 * Mandu-new.
 *
 * Until 2026-10-14 the answers' row (`.ask-actions`) never shrank and had
 * no bound, so it was as wide as its buttons on one line: a headless
 * Chromium measured a held message's four answers on Approvals 365 px past
 * the card at 390 px, the page scrolling sideways to 714 px, and a send's
 * Block cut at the screen's edge at 320 px.
 *
 *   a real ArbiterServer (`secrets` axes) with a prompt pack whose codename
 *   the person set to ask, the REAL anthropic-proxy on its production
 *   clients holding a message that names it (a scripted fake model), and
 *   the real egress gate asking about a registered `.env`'s key at a host
 *   no rule binds it to; a real DashboardServer over the production
 *   adapter; the served pages with their served stylesheets as a 390 px
 *   phone applies them:
 *
 *   Q1  the served Home, signed out: the held message's card offers Send as
 *       written, Send masked, Cancel the message, the send's Allow once,
 *       Always allow, Send without it, Block, each in a row that wraps, never shrinks and is
 *       never wider than its own row (`max-width: 100%`), no inline style;
 *   Q2  the served Approvals, signed out: the held message's four answers
 *       (Send as written for this session too) and the send's, the same;
 *   Q3  the oracle: no page or answer the signed-out reader got carries
 *       the key, the held message's found text, the admin token or the
 *       session secret.
 *
 * Axes: `secrets` stated (the confidentiality axis the prompt filter and the
 * egress gate serve). What is under test is the served styles on the served
 * cards; the stack supplies real questions for them to draw.
 */
import { test } from "node:test";
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
import { ADMIN_OPTS, ADMIN_TOKEN, CSRF_ADMIN, SESSION_SECRET } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { startScriptedAnthropic } from "../lib/fake-anthropic.js";
import { humanSockIn } from "../lib/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const KEY_VALUE = `sk_live_questionButtonsWrapCanary_${process.pid}_5e2a`;
const CODENAME = "marlowbrookproject";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

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

/** Each card's answers under `root`, keyed by the card's first words: in
 *  one `.ask-actions` with no inline style, computing a row that wraps
 *  inside the card. */
function answersOf(root: El, w: El, page: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const card of [...root.querySelectorAll(".ask")] as El[]) {
    const rows = [...card.querySelectorAll(".ask-actions")] as El[];
    assert.equal(rows.length, 1, `${page}: one row of answers per card`);
    const row = rows[0];
    assert.equal(row.getAttribute("style"), null, `${page}: no inline style, the served stylesheet decides`);
    const cs = w.getComputedStyle(row);
    assert.deepEqual([cs.display, cs.flexWrap, cs.flexShrink], ["flex", "wrap", "0"], `${page}: a row that wraps and never shrinks`);
    assert.equal(cs.maxWidth, "100%", `${page}: never wider than its own row, so on a phone the buttons wrap inside the card`);
    const sentence = card.querySelector(".ask-sentence").textContent as string;
    out.set(sentence.includes("wants to send your message to the AI") ? "held" : sentence.includes("STRIPE_KEY") ? "send" : sentence,
      [...row.querySelectorAll("button")].map((b: El) => b.textContent));
  }
  return out;
}

test("a held message's and a send's answers wrap inside their cards on a phone, on Home and Approvals (secrets axes)", { timeout: 90_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-question-buttons-wrap-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const dataSock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const packs = join(tmp, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), `pack: acme-dlp\nversion: 1\nkeywords:\n  - category: acme.codename\n    words: [${CODENAME}]\n    level: local-model\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\nprompt_filters:\n  filters:\n    acme-dlp: on\n");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: null, packDir: null, packKeysDir: join(tmp, "keys"), promptHoldMs: 30_000,
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  const session = `question-buttons-${process.pid}`;
  await data.setSessionSpec({ sessionKey: session, spec: "claude-code" });
  const fake = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const proxyPort = await proxy.listen(0);
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter is wired");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home"), HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const admin = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await pageFetch(`${base}/api/${path}`, { method, headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: r.status, body: (await r.json().catch(() => ({}))) as Record<string, unknown> };
  };
  const out = { "Sec-Fetch-Site": "same-origin" };
  const signedOutReads: string[] = [];
  let held: { pending: Promise<{ status: number }>; id: string } | null = null;
  try {
    // One message waits: it names the codename, which the person set to ask.
    const up = await admin("POST", "policy/prompt-filters/change", { edit: { op: "set-prompt-action", category: "acme.codename", action: "ask" } });
    assert.equal(up.status, 200, JSON.stringify(up.body));
    const pending = post(proxyPort, {
      model: "claude-sonnet-4-5", stream: true, max_tokens: 64,
      tools: [{ name: "Read", input_schema: { type: "object" } }],
      messages: [{ role: "user", content: [{ type: "text", text: `plan for ${CODENAME} next week` }] }],
    }, session);
    const hold = await waitFor("the message's hold", async () =>
      ((await admin("GET", "prompt-filters/holds")).body["holds"] as Array<{ approvalId: string }> | undefined)?.[0]);
    held = { pending, id: hold.approvalId };

    // One send waits: the key of a registered `.env`, at a host no rule binds it to.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await data.registerSecret({ path: env, sessionKey: session });
    const symbol = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(symbol, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const d = await data.desymbolizationDecision({ symbol, boundary: "network", destination: "api.stripe.com", sessionKey: session, scheme: "https" });
    assert.equal(d.allow, false);
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "the gate asks");
    signedOutReads.push(await (await pageFetch(`${base}/api/home`, { headers: out })).text());

    const served = async (f: string): Promise<string> => {
      const r = await pageFetch(base + f, { headers: out });
      assert.equal(r.status, 200, `${f} is served`);
      return r.text();
    };
    const css = resolveCssVars(stylesAt(`${await served("/mandu.css")}\n${await served("/app.css")}`, 390));

    // ── Q1: Home ──
    await servedProductPage(base, "/", (doc) => doc.querySelectorAll("#home-waiting .ask").length === 2, (doc) => {
      const answers = answersOf(doc.getElementById("home-waiting"), doc.defaultView, "Home");
      assert.deepEqual(answers.get("held"), ["Send as written", "Send masked", "Cancel the message"], `the held message's answers: ${JSON.stringify([...answers])}`);
      assert.deepEqual(answers.get("send"), ["Allow once", "Always allow", "Send without it", "Block"], `the send's answers: ${JSON.stringify([...answers])}`);
      signedOutReads.push(doc.documentElement.outerHTML);
    }, { headers: out, css });

    // ── Q2: Approvals ──
    await servedProductPage(base, "/approvals", (doc) => doc.querySelectorAll("#approvals-waiting .ask.expanded").length === 2, (doc) => {
      const answers = answersOf(doc.getElementById("approvals-waiting"), doc.defaultView, "Approvals");
      assert.deepEqual(answers.get("held"), ["Send as written", "Send as written for this session", "Send masked", "Cancel the message"],
        `the held message's four answers: ${JSON.stringify([...answers])}`);
      assert.deepEqual(answers.get("send"), ["Allow once", "Always allow", "Send without it", "Block"], `the send's answers: ${JSON.stringify([...answers])}`);
      signedOutReads.push(doc.documentElement.outerHTML);
    }, { headers: out, css });

    // ── Q3: the oracle ──
    assert.equal(signedOutReads.length, 3);
    for (const body of signedOutReads) {
      assert.equal(body.includes(KEY_VALUE), false, "no page or answer the signed-out reader got carries the key");
      assert.equal(body.includes(CODENAME), false, "nor the held message's found text");
      assert.equal(body.includes(ADMIN_TOKEN), false, "the admin token is never served");
      assert.equal(body.includes(SESSION_SECRET), false, "the session secret is never served");
    }
  } finally {
    // The held request answers (cancelled) before the stack goes.
    if (held) {
      await admin("POST", "prompt-filters/holds/answer", { approvalId: held.id, answer: "cancel", scope: "once" }).catch(() => undefined);
      await held.pending.catch(() => undefined);
    }
    await dashboard.close();
    wired.close();
    await proxy.close();
    await fake.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
