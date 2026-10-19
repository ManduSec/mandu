/**
 * product-page-focus.test — a page change of the product page gives the
 * keyboard focus to the page shown, across the REAL components (dashboard.md
 * §4.25 *A page change moves the focus*). Mandu-new.
 *
 * Until 2026-10-10 nothing moved the focus on a page change. Enter on a
 * link inside a page left it on the link the change hid (on <body> in a
 * browser), and a screen reader said nothing of the new page. A Tab from a
 * link to an earlier page left the document. Here a real ArbiterServer
 * runs at the `secrets` axes, the net-proxy runs in its production wiring,
 * and a real DashboardServer serves the product page (its own index.html
 * and home.js in jsdom, signed in). Each link is focused before its click,
 * as Enter does:
 *
 *   F1  the net-proxy stops a registered key's send to a host no rule binds
 *       it to: a real question waits;
 *   F2  Home's "Details in Approvals" opens Approvals with the question's
 *       card marked and focused, the link's page hidden;
 *   F3  the card's "See what the agent was doing" opens the agent page:
 *       its heading has the focus while it is read, then the step where
 *       Mandu stopped and asked takes it once drawn;
 *   F4  Back gives the marked Approvals card the focus again; the nav's
 *       Rules and Settings focus their headings, and its Home the verdict;
 *   F5  nothing rejects unhandled; the oracle: neither `/api/home` nor any
 *       rendered page carries the key's value, and none carries a token.
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
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets");

const KEY_VALUE = "sk_live_productPageFocusStackCanary00001";
const SESSION = "1791300000-2130";
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

/** Enter on a link: it has the focus, then the click. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function press(link: any): void {
  assert.ok(link, "the link is there");
  link.focus();
  link.click();
}
/** The h1 of the one page shown. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function shownHeading(doc: any) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const shown = [...doc.querySelectorAll("#main > section[data-page]")].filter((s: any) => !s.hidden) as any[];
  assert.equal(shown.length, 1, "one page is shown");
  return shown[0].querySelector("h1");
}

test("a page change gives the keyboard focus to the page shown: its heading, or the card or step it marks (real arbiter, net-proxy, dashboard, served page)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-page-focus-"));
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
  const signedIn = { Cookie: dashboard.adminCookie() };
  const rendered: [string, string][] = [];
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  try {
    // ── F1: a registered key bound for a host no rule names is stopped ───────
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
    // The stop's step is on the agent page once its event is stored
    // (emission is best-effort and asynchronous).
    const agentRoute = `${base}/api/home/agent?session=${SESSION}&ask=${encodeURIComponent(row!.id)}`;
    let located: string | null | undefined = null;
    for (let i = 0; i < 100 && !located; i++) {
      const vm = (await (await pageFetch(agentRoute, { headers: { ...CSRF, ...signedIn } })).json()) as { focus?: { turnId?: string | null } };
      located = vm.focus?.turnId;
      if (!located) await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(located, "the agent page finds the step where Mandu asked");

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const card = (doc: any) => [...doc.querySelectorAll("#approvals-waiting .ask")].find((c: any) => c.dataset.id === row!.id) as any;
    await servedProductPage(base, "/", (doc) => doc.querySelector("#home-waiting .ask-details") !== null, async (doc) => {
      const w = doc.defaultView;
      assert.equal(doc.activeElement, doc.body, "the first load leaves the focus where the browser puts it");

      // ── F2: Details opens Approvals at the question, focused ──────────────
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const details = [...doc.querySelectorAll("#home-waiting .ask-details")].find((a: any) => a.getAttribute("href").endsWith("/approvals/" + encodeURIComponent(row!.id)));
      press(details);
      await waitWhile(() => !card(doc) || doc.activeElement !== card(doc));
      assert.equal(doc.getElementById("page-approvals").hidden, false, "Approvals is shown");
      assert.equal(details.closest("section[data-page]").hidden, true, "the link's page is hidden");
      assert.ok(card(doc).classList.contains("focus"), "the question's card is marked");
      assert.equal(doc.activeElement, card(doc), "and has the focus, never the hidden link");

      // ── F3: the agent page, its heading, then the step where Mandu asked ──
      const agentLink = card(doc).querySelector("a.ask-link");
      assert.equal(agentLink?.dataset.session, SESSION, "the card links its agent");
      press(agentLink);
      assert.equal(doc.activeElement, doc.getElementById("agent-name"), "the agent's heading while its page is read");
      await waitWhile(() => doc.querySelector("#agent-story .focus-tag") === null);
      const marked = doc.querySelector("#agent-story .focus-tag")?.closest(".step, .turn");
      assert.ok(marked, "the step where Mandu asked is marked");
      assert.equal(doc.activeElement, marked, "and has the focus");
      rendered.push(["the agent page", doc.documentElement.outerHTML]);

      // ── F4: Back, then the nav ─────────────────────────────────────────────
      w.history.back();
      await waitWhile(() => doc.getElementById("page-approvals").hidden || doc.activeElement !== card(doc));
      assert.equal(w.location.pathname, "/approvals/" + encodeURIComponent(row!.id));
      assert.equal(doc.activeElement, card(doc), "Back: the marked card has the focus again");
      rendered.push(["the Approvals page", doc.documentElement.outerHTML]);
      for (const [page, words] of [["rules", "Rules"], ["settings", "Settings"]]) {
        press(doc.querySelector(`#nav [data-page-link="${page}"]`));
        assert.equal(doc.activeElement, shownHeading(doc), `${page}: its heading`);
        assert.equal(doc.activeElement.textContent, words);
      }
      press(doc.querySelector('#nav [data-page-link="home"]'));
      assert.equal(doc.activeElement, doc.getElementById("hero-headline"), "Home: the verdict");
      rendered.push(["the Home page", doc.documentElement.outerHTML]);
    }, { headers: signedIn });

    // ── F5: nothing rejected unhandled; the oracle ───────────────────────────
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");
    const bodies: [string, string][] = [
      ["/api/home", await (await pageFetch(`${base}/api/home`)).text()],
      ["/api/home signed in", await (await pageFetch(`${base}/api/home`, { headers: { ...CSRF, ...signedIn } })).text()],
      ["/api/home/agent", await (await pageFetch(agentRoute, { headers: { ...CSRF, ...signedIn } })).text()],
      ...rendered,
    ];
    for (const [where, body] of bodies) {
      assert.ok(!body.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: the key's value is in ${where}`);
      assert.doesNotMatch(body, /\$MDU/, `${where} carries no token`);
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    await proxy.close();
    netClient.close(); netHuman.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
