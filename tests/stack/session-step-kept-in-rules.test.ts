/**
 * session-step-kept-in-rules.test — on the session page, a step answered
 * Always allow or Block links where Rules keeps that answer (dashboard.md
 * §4.25b *A stop says Mandu asked you*; §4.25 *A remembered answer opens
 * where Rules keeps it*), across the REAL components. Mandu-new.
 *
 * The session page is where a person reads what happened and notices "that
 * should not have been allowed". Until 2026-10-23 its step said "Your
 * answer: Always allowed." and led only to Approvals, whose row then led to
 * Rules: two pages for what the step already knows. This suite pins the
 * whole path with no mocks:
 *
 *   K1  the net-proxy, wired as production wires it
 *       (`new ArbiterClientAdapter(new ArbiterClient(sock))`), stops a
 *       registered secret's send to a host no rule binds it to (`secrets`
 *       axes), and its `net_action` names the queue row; Always allow over
 *       the real route, and the same send goes;
 *   K2  the served session page (its own index.html and home.js in jsdom,
 *       signed in): the stop's line reads "Mandu asked for your OK in
 *       Approvals. Your answer: Always allowed. Kept in Rules", the link
 *       addressed to `/rules#answer-<id>`; a click opens Rules with that
 *       answer's row open, Remove in it, the focus on its ⋯;
 *   K3  Remove, pressed there, forgets the answer through the production
 *       approvals adapter: the same send is stopped again and waits;
 *   K4  the oracle: neither rendered page nor the routes it read carry the
 *       secret's value, and the product side carries no token.
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
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const KEY_VALUE = "sk_" + "live_sessionStepKeptRulesCanary0000001";
const SESSION = "1791400000-101";
const URL_OUT = "http://collector.example/upload";

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

test("a session step answered Always allow ends with Kept in Rules, which opens its row on Rules, and Remove there makes the same send wait again (real arbiter, net-proxy, dashboard)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-step-kept-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const adminPath = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminPath, humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();

  // Production wiring of the net-proxy's arbiter (net-proxy/src/server-main.ts).
  const netClient = new ArbiterClient(socketPath);
  await netClient.connect();
  const netHuman = new ArbiterClient(humanPath);
  const wire: string[] = [];
  const proxy = new NetProxy({
    arbiter: new ArbiterClientAdapter(netClient as unknown as RealArbiterClient, netHuman),
    sessionId: SESSION,
    forwarder: async ({ url }) => {
      wire.push(url);
      return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
    },
    log: () => {},
  });
  const proxyPort = await proxy.listen(0);

  const gate = new ArbiterClient(socketPath); await gate.connect();
  const humanReader = new ArbiterClient(humanPath); await humanReader.connect();
  const admin = new ArbiterClient(adminPath); await admin.connect();
  // The dashboard's production approvals adapter (forget included).
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminPath }));
  assert.ok(wired?.arbiter.forgetEgressApproval, "the production adapter forwards forgetEgressApproval");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  try {
    // ── K1: stopped, then Always allow; the same send goes ─────────────────
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const first = await viaProxy(proxyPort, URL_OUT, `k=${keySym}`);
    assert.equal(first.status, 403, `the send is stopped: ${first.body}`);
    assert.ok(!first.body.includes(KEY_VALUE));
    assert.deepEqual(wire, [], "nothing went out");
    const row = (await admin.egressApprovals("pending")).find((a) => a.symbol === keySym);
    assert.ok(row, "the stop queued a question");
    const id = row!.id;
    let stamped: string | undefined;
    for (let i = 0; i < 100 && !stamped; i++) {
      // Emission is best-effort and asynchronous.
      const events = (await humanReader.events(SESSION)) as unknown as { kind: string; action?: string; policy?: { approvalId?: string } }[];
      stamped = events.find((e) => e.kind === "net_action" && e.action === "blocked")?.policy?.approvalId;
      if (!stamped) await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(stamped, id, "the stop's net_action carries the queue id");
    const allow = await pageFetch(`${base}/api/egress/approvals/${id}/approve`, { method: "POST", headers: CSRF_ADMIN });
    assert.equal(allow.status, 200);
    const allowed = await viaProxy(proxyPort, URL_OUT, `k=${keySym}`);
    assert.equal(allowed.status, 200, "the answer is remembered: the same send goes");
    assert.deepEqual(wire, [URL_OUT]);
    const page = (await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`)).json()) as AgentPageVM;
    const stopped = page.story.flatMap((t) => t.steps).find((x) => x.kind === "action" && x.askId === id);
    assert.ok(stopped && stopped.kind === "action", "the stopped send is a step that asked");
    assert.equal(stopped.answer, "allowed", "the route carries the row's answer");

    // ── K2 + K3: the step's Kept in Rules opens the row; Remove forgets it ──
    const askedLine = (doc: any) => ([...doc.querySelectorAll("#agent-story .step .note.asked")] as any[]).find((n) => n.querySelector("a.kept-link")); // eslint-disable-line @typescript-eslint/no-explicit-any
    const ruleRow = (doc: any) => ([...doc.querySelectorAll("#rules-list .row[data-rule]")] as any[]).find((r) => r.getAttribute("data-rule") === "answer:" + id); // eslint-disable-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, `/agents/${SESSION}`, (doc) => askedLine(doc) !== undefined, async (doc) => {
      const line = askedLine(doc);
      assert.equal(line.textContent, "Mandu asked for your OK in Approvals. Your answer: Always allowed. Kept in Rules");
      assert.match(line.closest("[data-step-id]").textContent, /collector\.example/, "on the stopped send");
      assert.equal(line.querySelector("a").getAttribute("href"), `/approvals/${id}`, "the Approvals word still opens the row");
      const link = line.querySelector("a.kept-link");
      assert.equal(link.getAttribute("href"), `/rules#answer-${encodeURIComponent(id)}`, "the address names the row");
      assert.equal(doc.querySelectorAll("#agent-story a.kept-link").length, 1, "only the step that asked");
      const sessionPage = doc.body.textContent ?? "";
      assert.ok(!sessionPage.includes(KEY_VALUE), "the session page carries no secret value");
      assert.doesNotMatch(sessionPage, /\$MDU/, "nor a token");

      link.click();
      await waitWhile(() => !ruleRow(doc)?.classList.contains("open"));
      assert.equal(doc.getElementById("page-rules").hidden, false, "Rules opened");
      assert.equal(doc.defaultView.location.pathname, "/rules");
      const opened = ruleRow(doc);
      assert.ok(opened && opened.classList.contains("open"), "the answer's row is open");
      assert.match(opened.textContent, /collector\.example/, "the answered send");
      assert.equal(doc.activeElement, opened.querySelector(".file-more"), "the focus on its ⋯");
      const remove = opened.nextElementSibling.querySelector(".rule-remove");
      assert.ok(remove, "Remove is there");
      assert.equal(remove.textContent, "Remove");
      assert.equal(doc.getElementById("rules-answer-note").hidden, true);
      const rules = doc.body.textContent ?? "";
      assert.ok(!rules.includes(KEY_VALUE), "the Rules page carries no secret value");
      assert.doesNotMatch(rules, /\$MDU/, "nor a token");

      remove.click();
      await waitWhile(() => ruleRow(doc) !== undefined);
      assert.equal(ruleRow(doc), undefined, "the answer is gone from Rules");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    const again = await viaProxy(proxyPort, URL_OUT, `k=${keySym}`);
    assert.equal(again.status, 403, "the same send is stopped again");
    assert.deepEqual(wire, [URL_OUT], "and did not go out");
    const waiting = (await admin.egressApprovals("pending")).filter((a) => a.symbol === keySym);
    assert.equal(waiting.length, 1, `it waits for an answer again: ${JSON.stringify(waiting)}`);

    // ── K4: names and links, never values; no token on the product side ────
    const bodies = {
      home: await (await pageFetch(`${base}/api/home`)).text(),
      agent: await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`)).text(),
      panel: await (await pageFetch(`${base}/api/policy/panel`)).text(),
    };
    for (const [route, body] of Object.entries(bodies)) assert.ok(!body.includes(KEY_VALUE), `${route} carries no secret value`);
    assert.doesNotMatch(bodies.home, /\$MDU/, "the product's home carries no token");
    assert.doesNotMatch(bodies.agent, /\$MDU/, "nor its session page");
  } finally {
    await dashboard.close();
    await proxy.close();
    netClient.close(); netHuman.close();
    gate.close(); humanReader.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
