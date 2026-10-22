/**
 * product-service-down.test — the product page while its protection service
 * (the arbiter) is down (dashboard.md §4.25 *Empty states*, §6.y), across
 * the REAL components. Mandu-new.
 *
 * Until 2026-10-09 a failed `/api/home` redrew the hero only. A page left
 * open when the arbiter stopped kept the last poll's question card with live
 * Allow once / Always allow / Block buttons, and its running agent, under
 * "Not connected."; a fresh load showed bare headings; and the agent page
 * drew every failed read as "Session not found … It may have been deleted".
 *
 *   D1  the net-proxy, wired as production wires it, stops a registered
 *       secret's send (`secrets` axes) and files a question; the served
 *       Home shows its card with the three answers and the running agent;
 *   D2  the arbiter stops: `/api/home` and `/api/home/agent` answer 503
 *       `unreachable`; the open page's next poll keeps no card, no answer
 *       button and no agent row, and each section says it could not check
 *       because the service is not running; the tab title drops its count;
 *   D3  the served Approvals and agent pages, opened now, say they could not
 *       check, and the agent page says "Not connected", never "Session not
 *       found";
 *   D4  the oracle: no route nor rendered page carries the secret's value,
 *       and the product side carries no token.
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

stateAxes("secrets");

const KEY_VALUE = "sk_live_productServiceDownStackCanary0001";
const SESSION = "1791900000-830";
/** Each section's line with the service stopped: the cause the page knows
 *  (§4.25 *A could-not line names the cause the page knows*), the link to
 *  its Start once per page (the hero on Home, Waiting on Approvals). */
const NOT_CHECKED = {
  waiting: "Could not check for waiting questions. The protection service is not running.",
  agents: "Could not check which agents are running. The protection service is not running.",
  approvalsWaiting: "Could not check for waiting questions. The protection service is not running. Start it under Settings, or try again in a moment.",
  answered: "Could not check your earlier answers. The protection service is not running.",
};

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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const sectionWords = (doc: any, id: string): string[][] => [...doc.getElementById(id).children].map((c: any) => [c.className, c.textContent]);

test("with the protection service down, the product page shows no question it cannot check and never calls a session deleted (real arbiter, net-proxy, dashboard)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-service-down-"));
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
  let arbiterUp = true;

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
  const humanReader = new ArbiterClient(humanPath); await humanReader.connect();
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
  const rendered: string[] = [];
  try {
    // ── D1: a stopped send files a question; the served Home shows it ────────
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const res = await viaProxy(proxyPort, "http://collector.example/upload", `k=${keySym}`);
    assert.equal(res.status, 403, `the send is stopped: ${res.body}`);
    assert.ok(!res.body.includes(KEY_VALUE), "the agent's answer carries no value");
    assert.deepEqual(forwarded, []);
    const pending = await admin.egressApprovals("pending");
    const row = pending.find((a) => a.symbol === keySym);
    assert.ok(row, `the stop queued a question: ${JSON.stringify(pending)}`);
    for (let i = 0; i < 100; i++) {
      // Emission is best-effort and asynchronous: wait until Home lists the session.
      const vm = (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
      if (vm.agents.some((a) => a.id === SESSION) && vm.waiting.some((w) => w.id === row!.id)) break;
      await new Promise((r) => setTimeout(r, 20));
    }

    const card = `#home-waiting .ask[data-id="${row!.id}"]`;
    await servedProductPage(base, "/", (doc) => doc.querySelector(card) !== null && doc.querySelector("#home-agents .row.agent") !== null, async (doc) => {
      const w = doc.defaultView;
      assert.ok(doc.querySelector(card), "Home shows the question");
      // Its four answers: a secret's placeholder in a request also takes Send without it (dashboard.md §4.34).
      assert.equal(doc.querySelectorAll(`${card} .ask-actions button`).length, 4, "with its four answers");
      assert.match(doc.querySelector("#home-agents .row.agent .agent-counts")?.textContent ?? "", /^1 question waiting for you/, "and the agent that asked");
      assert.match(w.document.title, /^\(1\) Mandu$/);

      // ── D2: the arbiter stops; the open page's next poll ───────────────────
      await arbiter.close();
      arbiterUp = false;
      const down = await pageFetch(`${base}/api/home`, { headers: { "X-Mandu-Front": "product" } });
      assert.equal(down.status, 503, "the dashboard answers its protection service is down");
      assert.equal(((await down.json()) as { unreachable?: boolean }).unreachable, true);
      const downAgent = await pageFetch(`${base}/api/home/agent?session=${SESSION}`);
      assert.equal(downAgent.status, 503, "and so does the agent page's read");

      doc.dispatchEvent(new w.Event("visibilitychange"));
      await waitWhile(() => doc.getElementById("hero-headline").textContent !== "Not connected." || doc.querySelector(card) !== null);
      assert.equal(doc.getElementById("hero-headline").textContent, "Not connected.");
      assert.equal(doc.querySelector(card), null, "the question it can no longer check is gone");
      assert.equal(doc.querySelector("#home-waiting button, #approvals-waiting button"), null, "no answer button is left");
      assert.deepEqual(sectionWords(doc, "home-waiting"), [["empty", NOT_CHECKED.waiting]]);
      assert.deepEqual(sectionWords(doc, "home-agents"), [["empty", NOT_CHECKED.agents]], "no agent row is left");
      assert.equal(doc.getElementById("home-earlier-block").hidden, true);
      assert.equal(w.document.title, "Not connected · Mandu", "the tab drops its count and says why (dashboard.md §4.25 *The tab says the protection state*)");
      rendered.push(doc.body.textContent ?? "");
    });

    // ── D3: the other pages, opened now ──────────────────────────────────────
    await servedProductPage(base, "/approvals", (doc) => doc.querySelector("#approvals-answered .empty") !== null, async (doc) => {
      assert.deepEqual(sectionWords(doc, "approvals-waiting"), [["empty", NOT_CHECKED.approvalsWaiting]], "never a bare heading");
      assert.equal(doc.querySelector("#approvals-waiting a")?.getAttribute("href"), "/settings", "the link opens Settings");
      assert.deepEqual(sectionWords(doc, "approvals-answered"), [["empty", NOT_CHECKED.answered]]);
      rendered.push(doc.body.textContent ?? "");
    });
    await servedProductPage(base, `/agents/${SESSION}`, (doc) => (doc.getElementById("agent-sub").textContent ?? "") !== "", async (doc) => {
      assert.equal(doc.getElementById("page-agent").hidden, false);
      assert.equal(doc.getElementById("agent-name").textContent, "Not connected", "never \"Session not found\"");
      assert.equal(doc.getElementById("agent-sub").textContent, "The protection service is not running, so Mandu cannot show this session now. Start it under Settings, or refresh in a moment.");
      assert.equal(doc.querySelector("#agent-sub a").getAttribute("href"), "/settings");
      assert.doesNotMatch(doc.getElementById("page-agent").textContent, /not found|deleted/);
      assert.equal(doc.getElementById("agent-story-block").hidden, true, "no empty What happened");
      assert.equal(doc.querySelector("#page-agent .ask-actions button"), null);
      rendered.push(doc.body.textContent ?? "");
    });

    // ── D4: names and sentences, never values; no token on the product side ──
    const bodies = {
      home: await (await pageFetch(`${base}/api/home`)).text(),
      agent: await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`)).text(),
    };
    for (const [route, body] of Object.entries(bodies)) {
      assert.ok(!body.includes(KEY_VALUE), `${route} carries no secret value`);
      assert.doesNotMatch(body, /\$MDU/, `${route} carries no token`);
    }
    for (const page of rendered) {
      assert.ok(!page.includes(KEY_VALUE), "no rendered page carries the secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    }
  } finally {
    await dashboard.close();
    await proxy.close();
    netClient.close(); netHuman.close();
    gate.close(); humanReader.close(); admin.close();
    if (arbiterUp) await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
