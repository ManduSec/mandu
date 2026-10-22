/**
 * answered-opens-rule.test — a remembered answer under Approvals › Answered
 * earlier opens where Rules keeps it (dashboard.md §4.25 *A remembered
 * answer opens where Rules keeps it*, §4.25h), across the REAL components.
 * Mandu-new.
 *
 * Approvals says "Always allow and Block are remembered under Rules", and
 * until 2026-10-22 no answered row led there: someone who pressed Always
 * allow by mistake, and wanted to be asked again, had to find the row among
 * every rule by hand. This suite pins the whole path with no mocks:
 *
 *   R1  the net-proxy, wired as production wires it
 *       (`new ArbiterClientAdapter(new ArbiterClient(sock))`), stops a
 *       registered secret's send to a host no rule binds it to (`secrets`
 *       axes); Always allow over the real route, and the same send goes;
 *   R2  the served Approvals page (its own index.html and home.js in jsdom,
 *       signed in): the row's when line ends with "Kept in Rules", addressed
 *       to `/rules#answer-<id>`; a click opens Rules with that answer's row
 *       open, Remove in it, the focus on its ⋯;
 *   R3  Remove, pressed there, forgets the answer through the production
 *       approvals adapter: the same send is stopped again, and the arbiter's
 *       queue holds it pending;
 *   R4  the oracle: neither rendered page nor the routes it read carry the
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
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const KEY_VALUE = "sk_" + "live_answeredOpensRuleStackCanary000001";
const SESSION = "1791300000-467";
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

test("Kept in Rules on an Always allowed answer opens its row on Rules, and Remove there makes the same send wait again (real arbiter, net-proxy, dashboard)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-answered-rule-"));
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
    // ── R1: stopped, then Always allow; the same send goes ─────────────────
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
    const allow = await pageFetch(`${base}/api/egress/approvals/${id}/approve`, { method: "POST", headers: CSRF_ADMIN });
    assert.equal(allow.status, 200);
    const vm = (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    assert.equal(vm.answered.find((a) => a.id === id)?.outcome, "allowed", "Always allowed under Answered earlier");
    const allowed = await viaProxy(proxyPort, URL_OUT, `k=${keySym}`);
    assert.equal(allowed.status, 200, "the answer is remembered: the same send goes");
    assert.deepEqual(wire, [URL_OUT]);

    // ── R2 + R3: Kept in Rules opens the row; Remove forgets it ────────────
    const rowSel = `#approvals-answered .row.answered[data-id="${id}"]`;
    const ruleRow = (doc: any) => ([...doc.querySelectorAll("#rules-list .row[data-rule]")] as any[]).find((r) => r.getAttribute("data-rule") === "answer:" + id); // eslint-disable-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, "/approvals", (doc) => doc.querySelector(`${rowSel} a.kept-link`) !== null, async (doc) => {
      const line = doc.querySelector(`${rowSel} .answered-when`);
      assert.match(line.textContent, /\. See what the agent was doing\. Kept in Rules$/);
      const link = line.querySelector("a.kept-link");
      assert.equal(link.getAttribute("href"), `/rules#answer-${encodeURIComponent(id)}`, "the address names the row");
      assert.equal(doc.querySelector(`${rowSel} .outcome`).textContent, "Always allowed");
      const approvals = doc.body.textContent ?? "";
      assert.ok(!approvals.includes(KEY_VALUE), "the Approvals page carries no secret value");
      assert.doesNotMatch(approvals, /\$MDU/, "nor a token");

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

    // ── R4: names and links, never values; no token on the product side ────
    for (const route of ["/api/home", "/api/policy/panel"]) {
      const body = await (await pageFetch(base + route)).text();
      assert.ok(!body.includes(KEY_VALUE), `${route} carries no secret value`);
    }
    assert.doesNotMatch(await (await pageFetch(`${base}/api/home`)).text(), /\$MDU/, "the product's home carries no token");
  } finally {
    await dashboard.close();
    await proxy.close();
    netClient.close(); netHuman.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
