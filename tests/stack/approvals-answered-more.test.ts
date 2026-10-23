/**
 * approvals-answered-more.test — Approvals › Answered earlier goes back
 * past its newest 20, across the REAL components (dashboard.md §4.25 *Past
 * the newest 20*). Mandu-new.
 *
 * Until 2026-10-18 the list stopped at the 20 answers `/api/home` carried,
 * with nothing after the last: the 21st answer's reversal was gone from the
 * page. Here a real ArbiterServer runs at the `secrets` axes, the net-proxy
 * on its production client (`new ArbiterClientAdapter(new ArbiterClient(sock))`)
 * stops a registered secret's send to 45 hosts no rule names, each answered
 * Always allow over the real route, and a product-only DashboardServer
 * serves Approvals (its own index.html and home.js in jsdom):
 *
 *   M1  `/api/home` carries the newest 20 and `answeredTotal` 45; the new
 *       route's next page starts after the 20th;
 *   M2  the served page draws 20 and says "Showing 20 of 45 answers.";
 *       Show more brings 21-40, each with its Block instead;
 *   M3  the 30th's Block instead changes that answer over the real route:
 *       the arbiter's row is denied, and the page says Blocked;
 *   M4  the oracle: the secret never left, and neither `/api/home`, the new
 *       route signed out nor the drawn page carries its value or a token;
 *       the new route carries no more than `/api/home` does for the same
 *       rows.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
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
import type { HomeAnswered, HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const KEY_VALUE = "sk_" + "live_answeredMoreStackCanary0000000001";
const SESSION = "1791300000-745";
const CSRF = { "X-Mandu-Control": "1" };
const HOSTS = 45;

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

test("Answered earlier goes past its newest 20 with Show more, and the 30th answer's Block instead works over the real route, no value shown (real arbiter, net-proxy, dashboard; secrets axes, explicit)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-answered-more-"));
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
  const signedIn = { ...CSRF, Cookie: dashboard.adminCookie() };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the secret value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rows = (doc: any) => [...doc.querySelectorAll("#approvals-answered .row.answered")] as any[];
  try {
    // ── 45 stopped sends, each answered Always allow ─────────────────────────
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    for (let i = 0; i < HOSTS; i++) {
      const res = await viaProxy(proxyPort, `http://collector${i}.example/upload`, `k=${keySym}`);
      assert.equal(res.status, 403, `send ${i} is stopped: ${res.body}`);
      assert.ok(!res.body.includes(KEY_VALUE));
    }
    assert.deepEqual(forwarded, [], "nothing left the machine");
    const pending = (await admin.egressApprovals("pending")).filter((a) => a.symbol === keySym);
    assert.equal(pending.length, HOSTS, "one question per host");
    for (const a of pending) {
      const r = await pageFetch(`${base}/api/egress/approvals/${a.id}/approve`, { method: "POST", headers: signedIn });
      assert.equal(r.status, 200);
    }

    // ── M1: Home's newest 20 and the route's next page ───────────────────────
    const homeText = await (await pageFetch(`${base}/api/home`)).text();
    const vm = JSON.parse(homeText) as HomeVM;
    assert.equal(vm.answered.length, 20);
    assert.equal(vm.answeredTotal, HOSTS);
    const nextText = await (await pageFetch(`${base}/api/home/answered?after=${encodeURIComponent(vm.answered[19]!.id)}&limit=20`)).text();
    const next = JSON.parse(nextText) as { rows: HomeAnswered[]; total: number; next: string | null };
    assert.equal(next.total, HOSTS);
    assert.equal(next.rows.length, 20);
    assert.ok(next.rows.every((r) => !vm.answered.some((a) => a.id === r.id)), "no answer twice");
    // The whole list over the route: the first page is Home's, field for field.
    const whole = (await (await pageFetch(`${base}/api/home/answered?limit=500`)).json()) as { rows: HomeAnswered[] };
    assert.deepEqual(whole.rows.slice(0, 20), vm.answered, "the route builds its rows as /api/home does");
    assert.deepEqual(whole.rows.slice(20, 40), next.rows);

    // ── M2, M3: the served page ──────────────────────────────────────────────
    let thirtieth = "";
    await servedProductPage(base, "/approvals", (doc) => rows(doc).length === 20, async (doc) => {
      const words = () => doc.querySelector("#approvals-answered .answered-more span")?.textContent;
      assert.equal(words(), "Showing 20 of 45 answers.");
      doc.querySelector("#approvals-answered .answered-more button").click();
      await waitWhile(() => rows(doc).length < 40);
      assert.equal(rows(doc).length, 40, "Show more brought 21-40");
      assert.deepEqual(rows(doc).slice(20).map((r) => r.dataset.id), next.rows.map((r) => r.id));
      for (const r of rows(doc).slice(20)) assert.equal(r.querySelector("button")?.textContent, "Block instead", "each with its reversal");
      assert.equal(doc.activeElement, rows(doc)[20], "the first new row has the focus");
      assert.equal(words(), "Showing 40 of 45 answers.");

      const row30 = rows(doc)[29];
      thirtieth = row30.dataset.id;
      row30.querySelector("button").click();
      const of = () => rows(doc).find((r) => r.dataset.id === thirtieth);
      await waitWhile(() => of()?.dataset.state !== "blocked");
      assert.equal(of()?.dataset.state, "blocked", "the page says the new answer");
      assert.match(of()!.textContent, /Blocked/);
      assert.ok(rows(doc).length >= 40, "the rows brought stay");
      noValue(doc.body.textContent ?? "", "the drawn Approvals page");
    }, { headers: { Cookie: dashboard.adminCookie() } });
    const denied = (await admin.egressApprovals("denied")).find((a) => a.id === thirtieth);
    assert.ok(denied, "the arbiter's row is now denied");

    // ── M4: the oracle ───────────────────────────────────────────────────────
    noValue(homeText, "/api/home");
    noValue(nextText, "/api/home/answered");
    const signedOut = await pageFetch(`${base}/api/home/answered?limit=500`);
    assert.equal(signedOut.status, 200, "open signed out, as /api/home");
    const outText = await signedOut.text();
    noValue(outText, "/api/home/answered signed out");
    const homeOut = JSON.parse(await (await pageFetch(`${base}/api/home`)).text()) as HomeVM;
    const out = JSON.parse(outText) as { rows: HomeAnswered[] };
    assert.deepEqual(out.rows.slice(0, 20), homeOut.answered, "no more than /api/home carries for the same rows");
    const keys = new Set(out.rows.flatMap((r) => Object.keys(r)));
    for (const k of keys) assert.ok(["id", "sentence", "outcome", "decidedAt", "sessions", "actions", "staleNote"].includes(k), `a field /api/home's answers carry: ${k}`);
  } finally {
    await dashboard.close();
    await proxy.close();
    netClient.close(); netHuman.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
