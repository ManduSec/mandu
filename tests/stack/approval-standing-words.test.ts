/**
 * approval-standing-words.test — a send question says what Always allow and
 * Block keep doing, and the words hold to the code (dashboard.md §4.34, *A
 * send question says what its standing answers keep doing*). Mandu-new.
 *
 * The card says a standing answer is kept for this secret and this host
 * only, that Always allow then lets ANY agent's request that sends it there
 * go with the real secret filled in without asking, that Block refuses those
 * requests without asking, and that it covers no other secret or host. This
 * suite proves each claim across the real components, no mocks: a real
 * ArbiterServer (`secrets` axes) with a registered `.env`, two net-proxies
 * for two sessions wired as production wires them
 * (`new ArbiterClientAdapter(new ArbiterClient(dataSock), new
 * ArbiterClient(humanSock))`, only the last hop captured), and a real
 * DashboardServer whose approval routes reach the admin socket:
 *
 *   W1  session A's send of `STRIPE_KEY` to pay.example is stopped; the
 *       served card (`/api/home`, and the served Approvals page) says the
 *       line under Send without it, its Rules a link to Your rules;
 *   W2  Always allow over the real route: session B (another session, its
 *       own proxy) sends the same secret to the same host and it goes, with
 *       the real value on the wire, and no question is filed;
 *   W3  the same secret to another host, and another secret to the same
 *       host, are stopped and asked about (not covered);
 *   W4  Block over the real route for `SLACK_TOKEN` to pay.example: either
 *       session's send of it is refused with no new question; the same
 *       secret to another host, and another secret to that host, ask;
 *   W5  the oracle: no proxy answer to the agent, no dashboard route and no
 *       served page carries a secret value, and the product's home and page
 *       no token (the agent's 403 may name the placeholder it sent, and the
 *       answer routes the row they answered, as before).
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
import { ArbiterClientAdapter } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const VALUES = {
  STRIPE_KEY: "sk_" + "live_standingWordsStackCanary0000000001",
  SLACK_TOKEN: "xoxb-" + "standingWordsStackCanary0000000000002",
  DB_PASSWORD: "standingWordsStackCanaryDbPassword0003",
};
type Key = keyof typeof VALUES;
const SESSION_A = "1791300000-144";
const SESSION_B = "1791300100-145";
const CSRF = { "X-Mandu-Control": "1" };

/** One absolute-form request through a forward proxy. */
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

const said = (parts: { text: string }[]) => parts.map((p) => p.text).join("");

test("a send question's standing answers: the card says this secret, this host, any agent, and the real gate does exactly that (real arbiter, two net-proxies, dashboard)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-standing-words-"));
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

  // Two sessions, each with the net-proxy's production wiring.
  const wire: Array<{ session: string; url: string; body: string }> = [];
  const clients: ArbiterClient[] = [];
  const proxies: NetProxy[] = [];
  const proxyFor = async (session: string): Promise<number> => {
    const data = new ArbiterClient(socketPath);
    await data.connect();
    const human = new ArbiterClient(humanPath);
    clients.push(data, human);
    const proxy = new NetProxy({
      arbiter: new ArbiterClientAdapter(data, human),
      sessionId: session,
      forwarder: async ({ url, body }) => {
        wire.push({ session, url, body: body.toString("utf8") });
        return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
      },
      log: () => {},
    });
    proxies.push(proxy);
    return proxy.listen(0);
  };
  const portA = await proxyFor(SESSION_A);
  const portB = await proxyFor(SESSION_B);

  const gate = new ArbiterClient(socketPath); await gate.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
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
  // What the agent got back from its proxy, and what the answer routes said.
  const answers: string[] = [];
  const routeAnswers: string[] = [];
  try {
    // A registered `.env`: each key gets its own symbol (the structured twin).
    const env = join(home, "proj", ".env");
    writeFileSync(env, Object.entries(VALUES).map(([k, v]) => `${k}=${v}`).join("\n") + "\n");
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION_A });
    const sym = {} as Record<Key, string>;
    for (const k of Object.keys(VALUES) as Key[]) {
      const s = new RegExp(`\\$MDU:nomodel_Read\\[[0-9a-f]+\\]\\.${k}`).exec(reg.twin ?? "")?.[0];
      assert.ok(s, `${k} has its own symbol: ${JSON.stringify(reg)}`);
      sym[k] = s;
    }

    /** A send of one secret through a session's proxy, the agent's answer kept for the oracle. */
    const send = async (port: number, key: Key, host: string) => {
      const res = await viaProxy(port, `http://${host}/v1/send`, `token=${sym[key]}`);
      answers.push(res.body);
      return res;
    };
    const pending = async () => (await admin.egressApprovals("pending")).map((a) => ({ id: a.id, symbol: a.symbol, destination: a.destination }));
    /** The waiting question for {key, host}, if one is filed. */
    const askFor = async (key: Key, host: string) => (await pending()).find((a) => a.symbol === sym[key] && a.destination === host);
    const answer = async (id: string, verb: "approve" | "deny") => {
      const r = await pageFetch(`${base}/api/egress/approvals/${id}/${verb}`, { method: "POST", headers: { ...CSRF, Cookie: dashboard.adminCookie() } });
      routeAnswers.push(await r.text());
      assert.equal(r.status, 200, `${verb} ${id}`);
    };
    const homeVm = async () => (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;

    // ── W1: stopped, asked, and the card says what the standing answers do ──
    const first = await send(portA, "STRIPE_KEY", "pay.example");
    assert.equal(first.status, 403, `the send is stopped: ${first.body}`);
    assert.equal(wire.length, 0, "nothing on the wire");
    const stripeAsk = await askFor("STRIPE_KEY", "pay.example");
    assert.ok(stripeAsk, `the stop filed a question: ${JSON.stringify(await pending())}`);
    const card = (await homeVm()).waiting.find((a) => a.id === stripeAsk!.id);
    assert.ok(card, "the product page lists it");
    assert.equal(said(card!.sentence), "The agent wants to send your secret STRIPE_KEY to pay.example");
    const LINE = "Mandu remembers it for STRIPE_KEY and pay.example only. Always allow: from now on, any agent's request that sends it to pay.example goes with the real secret filled in, without asking. Block: those requests are refused without asking. Your answer does not cover other secrets or other hosts. You can change it under Rules.";
    assert.equal(card!.ifStanding, LINE);
    assert.equal(said(card!.ifStandingParts!), LINE);
    assert.deepEqual(card!.ifStandingParts!.at(-2), { kind: "link", text: "Rules", to: "your-rules" });
    assert.ok(card!.actions.some((a) => a.approve && a.scope !== "once") && card!.actions.some((a) => !a.approve && a.scope !== "once" && !a.strip), "the card offers both standing answers");
    const cardSel = `#approvals-waiting .ask[data-id="${stripeAsk!.id}"]`;
    await servedProductPage(base, "/approvals", (doc) => doc.querySelector(`${cardSel} .ask-standing`) !== null, (doc) => {
      const line = doc.querySelector(`${cardSel} .ask-standing`);
      assert.equal(line.textContent, `If you click Always allow or Block: ${LINE}`);
      assert.equal(line.previousElementSibling?.classList.contains("ask-without"), true, "under Send without it");
      assert.match(line.querySelector("a").getAttribute("href"), /\/rules#your-rules$/);
      const page = doc.body.textContent ?? "";
      for (const v of Object.values(VALUES)) assert.ok(!page.includes(v), "the served page carries no secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    });

    // ── W2: Always allow; another session's send of it goes, with no question ──
    await answer(stripeAsk!.id, "approve");
    const other = await send(portB, "STRIPE_KEY", "pay.example");
    assert.equal(other.status, 200, `another session's send goes without asking: ${other.body}`);
    assert.equal(wire.length, 1);
    assert.equal(wire[0]!.session, SESSION_B);
    assert.ok(wire[0]!.body.includes(VALUES.STRIPE_KEY), "with the real secret filled in");
    assert.equal(await askFor("STRIPE_KEY", "pay.example"), undefined, "no question filed");
    assert.equal((await send(portA, "STRIPE_KEY", "pay.example")).status, 200, "and from the session that asked, again");
    assert.equal(wire.length, 2);

    // ── W3: not covered: the same secret to another host, another secret here ──
    assert.equal((await send(portB, "STRIPE_KEY", "other.example")).status, 403);
    assert.ok(await askFor("STRIPE_KEY", "other.example"), "the same secret to another host asks");
    assert.equal((await send(portB, "SLACK_TOKEN", "pay.example")).status, 403);
    const slackAsk = await askFor("SLACK_TOKEN", "pay.example");
    assert.ok(slackAsk, "another secret to the same host asks");
    assert.equal(wire.length, 2, "neither went");

    // ── W4: Block; refused without a question, from either session ──────────
    const slackCard = (await homeVm()).waiting.find((a) => a.id === slackAsk!.id);
    assert.equal(slackCard?.ifStanding, LINE.replaceAll("STRIPE_KEY", "SLACK_TOKEN"), "its card says the same of its own secret");
    await answer(slackAsk!.id, "deny");
    for (const port of [portA, portB]) {
      assert.equal((await send(port, "SLACK_TOKEN", "pay.example")).status, 403, "refused");
      assert.equal(await askFor("SLACK_TOKEN", "pay.example"), undefined, "without asking");
    }
    assert.equal(wire.length, 2, "nothing went");
    assert.equal((await send(portA, "SLACK_TOKEN", "third.example")).status, 403);
    assert.ok(await askFor("SLACK_TOKEN", "third.example"), "the same secret to another host asks");
    assert.equal((await send(portA, "DB_PASSWORD", "pay.example")).status, 403);
    assert.ok(await askFor("DB_PASSWORD", "pay.example"), "another secret to the same host asks");
    assert.equal(wire.length, 2);

    // ── W5: the oracle ────────────────────────────────────────────────────────
    const bodies = {
      home: await (await pageFetch(`${base}/api/home`)).text(),
      panel: await (await pageFetch(`${base}/api/policy/panel`)).text(),
      agentA: await (await pageFetch(`${base}/api/home/agent?session=${SESSION_A}`)).text(),
      agentB: await (await pageFetch(`${base}/api/home/agent?session=${SESSION_B}`)).text(),
    };
    for (const [route, body] of [...Object.entries(bodies), ...answers.map((b, i) => [`the agent's answer ${i}`, b] as const), ...routeAnswers.map((b, i) => [`answer route ${i}`, b] as const)]) {
      for (const v of Object.values(VALUES)) assert.ok(!body.includes(v), `${route} carries no secret value`);
    }
    assert.doesNotMatch(bodies.home, /\$MDU/, "the product's home carries no token");
  } finally {
    await dashboard.close();
    for (const p of proxies) await p.close();
    for (const c of [...clients, gate, admin]) c.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
