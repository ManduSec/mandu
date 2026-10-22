/**
 * approvals-answered-find.test — Approvals › Answered earlier finds a past
 * answer by its secret, host or agent, across the REAL components
 * (dashboard.md §4.25 *Finding an answer*). Mandu-new.
 *
 * Until 2026-10-22 the list could only be paged: the answer to undo was
 * found by pressing Show more and reading every row. Here a real
 * ArbiterServer runs at the `secrets` axes, the net-proxy on its production
 * client (`new ArbiterClientAdapter(new ArbiterClient(sock))`) stops 25 sends
 * of a registered file's keys, 13 to one host and 12 to another, each
 * answered Block over the real route, and a product-only DashboardServer
 * serves Approvals (its own index.html and home.js in jsdom):
 *
 *   F1  `/api/home/answered?q=<host>` lists that host's 12 answers only,
 *       `total` 12 and `query.all` 25; two words narrow it to one key;
 *   F2  the served page at `/approvals?q=<host>` shows the search in its
 *       box, draws the 12 and says "12 of 25 answers match";
 *   F3  *Allow instead* on a found row changes that answer over the real
 *       route: the arbiter's row is approved and the row says so;
 *   F4  the oracle: nothing left the machine; a search for the secret's
 *       value finds nothing; neither the route signed out nor the drawn
 *       page carries a value or a token.
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
import type { AnsweredPage } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const SESSION = "1791300000-861";
const CSRF = { "X-Mandu-Control": "1" };
const KEYS = 25;
const name = (i: number) => `KEY_${String(i).padStart(2, "0")}`;
const value = (i: number) => "sk_" + `live_answeredFindStackCanary${String(i).padStart(4, "0")}`;
/** Even keys go to the shop's host, odd ones to the paste site. */
const hostOf = (i: number) => (i % 2 === 0 ? "api.shop.example" : "paste.example");

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

test("Find an answer lists one host's answers, and Allow instead on a found row works over the real route, no value shown (real arbiter, net-proxy, dashboard; secrets axes, explicit)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-answered-find-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "shop"), { recursive: true });
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
    for (let i = 0; i < KEYS; i++) assert.ok(!text.includes(value(i)), `CONFIDENTIALITY VIOLATION: ${where} carries ${name(i)}'s value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  const find = async (q: string, headers: Record<string, string> = {}) => {
    const res = await pageFetch(`${base}/api/home/answered?limit=20&q=${encodeURIComponent(q)}`, { headers });
    assert.equal(res.status, 200, "open, as /api/home");
    const text = await res.text();
    return { text, page: JSON.parse(text) as AnsweredPage };
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rows = (doc: any) => [...doc.querySelectorAll("#approvals-answered .row.answered")] as any[];
  try {
    // ── 25 stopped sends, each answered Block ────────────────────────────────
    const env = join(home, "shop", ".env");
    writeFileSync(env, Array.from({ length: KEYS }, (_, i) => `${name(i)}=${value(i)}\n`).join(""));
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    for (let i = 0; i < KEYS; i++) {
      const sym = new RegExp(`\\$MDU:nomodel_Read\\[[0-9a-f]+\\]\\.${name(i)}`).exec(reg.twin ?? "")?.[0];
      assert.ok(sym, `${name(i)} has its own symbol`);
      const res = await viaProxy(proxyPort, `http://${hostOf(i)}/upload`, `k=${sym}`);
      assert.equal(res.status, 403, `send ${i} is stopped: ${res.body}`);
      assert.ok(!res.body.includes(value(i)));
    }
    assert.deepEqual(forwarded, [], "nothing left the machine");
    const pending = await admin.egressApprovals("pending");
    assert.equal(pending.length, KEYS, "one question per send");
    for (const a of pending) {
      const r = await pageFetch(`${base}/api/egress/approvals/${a.id}/deny`, { method: "POST", headers: signedIn });
      assert.equal(r.status, 200);
    }

    // ── F1: the route finds one host's answers ───────────────────────────────
    const paste = await find("paste.example");
    assert.equal(paste.page.total, 12, "the paste site's 12 answers");
    assert.deepEqual(paste.page.query, { text: "paste.example", all: KEYS });
    assert.equal(paste.page.rows.length, 12);
    assert.equal(paste.page.next, null);
    for (const r of paste.page.rows) {
      const words = r.sentence.map((p) => p.text).join("");
      assert.match(words, /paste\.example/, "each found row is the host's");
      assert.doesNotMatch(words, /api\.shop\.example/);
      assert.equal(r.outcome, "blocked");
    }
    const one = await find("KEY_07 paste");
    assert.equal(one.page.total, 1, "two words: one key's answer");
    assert.match(one.page.rows[0]!.sentence.map((p) => p.text).join(""), /KEY_07/);
    assert.equal((await find("KEY_07 api.shop")).page.total, 0, "KEY_07 never went to the shop's host");
    assert.equal((await find("blocked")).page.total, KEYS, "the answer's words");

    // ── F2, F3: the served page with the search in its address ───────────────
    let allowed = "";
    await servedProductPage(base, "/approvals?q=paste.example", (doc) => rows(doc).length === 12, async (doc) => {
      assert.equal(doc.getElementById("answered-q").value, "paste.example", "the box shows the search");
      assert.equal(doc.getElementById("answered-count").textContent, "12 of 25 answers match");
      for (const r of rows(doc)) assert.match(r.textContent, /paste\.example/);
      const row = rows(doc)[3];
      allowed = row.dataset.id;
      const button = row.querySelector("button");
      assert.equal(button.textContent, "Allow instead");
      button.click();
      const of = () => rows(doc).find((r) => r.dataset.id === allowed);
      await waitWhile(() => of()?.dataset.state === "blocked");
      assert.notEqual(of()?.dataset.state, "blocked", "the page says the new answer");
      assert.match(of()!.textContent, /allowed/i);
      noValue(doc.body.textContent ?? "", "the drawn Approvals page");
    }, { headers: { Cookie: dashboard.adminCookie() } });
    const approved = (await admin.egressApprovals("approved")).find((a) => a.id === allowed);
    assert.ok(approved, "the arbiter's row is now approved");
    assert.equal((await find("paste.example blocked")).page.total, 11, "the row found now says it was allowed");

    // ── F4: the oracle ───────────────────────────────────────────────────────
    assert.deepEqual(forwarded, [], "nothing left the machine");
    for (const probe of [value(7), "sk_live", "answeredFindStackCanary", "$MDU", "nomodel_Read"]) {
      const r = await find(probe);
      assert.equal(r.page.total, 0, `a search for ${probe} finds nothing`);
    }
    noValue(paste.text, "/api/home/answered?q= signed out");
    noValue((await find("KEY", signedIn)).text, "/api/home/answered?q= signed in");
  } finally {
    await dashboard.close();
    await proxy.close();
    netClient.close(); netHuman.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
