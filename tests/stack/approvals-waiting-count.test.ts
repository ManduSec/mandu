/**
 * approvals-waiting-count.test — Approvals' *Waiting for your answer* says
 * how many questions wait, "(2)", across the REAL components (dashboard.md
 * §4.25 *Waiting for your answer counts its questions*). Mandu-new.
 *
 * Until 2026-10-31 the heading gave no number: Home's block said
 * "Approvals waiting (5)" and drew three, then linked here, where a person
 * answering a backlog counted the cards to know how much was left.
 *
 * A real ArbiterServer (`secrets` axes) labels a key's file `no-model`,
 * bound to api.stripe.com; its egress gate asks twice for the key, at two
 * hosts no rule binds it to. A real DashboardServer over the production
 * approvals adapter (makeApprovalsArbiter) serves `/approvals` signed in:
 *
 *   C1  the heading reads "Waiting for your answer (2)", the count in its
 *       muted span, over two cards;
 *   C2  Block on one card, over the real route and resolve op: the redraw
 *       after it reads "(1)", one card left; the arbiter has the denial;
 *   C3  the oracle: no rendered page nor `/api/home` carries the key's
 *       value or a `$MDU` token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const KEY_VALUE = "sk_" + "live_waitingCountStackCanary0000000001";
const SESSION = "1791500000-0208";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

test("Approvals' Waiting for your answer counts its questions, (2) then (1) after a Block (real arbiter, production adapter, served page); no secret anywhere", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-waiting-count-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath); await gate.connect();
  const admin = new ArbiterClient(adminSock); await admin.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production adapter");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const rendered: [string, string][] = [];
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  try {
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: ["api.stripe.com"], recursive: false });
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const sym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(sym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const ids: string[] = [];
    for (const host of ["evil.example", "other.example"]) {
      const asked = await gate.desymbolizationDecision({ symbol: sym!, boundary: "network", destination: host, sessionKey: SESSION, scheme: "https" });
      assert.equal((asked as { requiresApproval?: boolean }).requiresApproval, true, `${host} asks`);
      ids.push(String((asked as { approvalId?: string }).approvalId));
    }
    assert.notEqual(ids[0], ids[1], "two questions");

    const cards = (doc: El) => doc.querySelectorAll("#approvals-waiting .ask");
    await servedProductPage(base, "/approvals", (doc) => cards(doc).length === 2, async (doc) => {
      // C1: the heading counts both.
      const h2 = doc.querySelector("#approvals-waiting-block h2");
      const count = doc.getElementById("approvals-waiting-count");
      assert.equal(h2.textContent, "Waiting for your answer (2)");
      assert.equal(count.textContent, "(2)");
      assert.ok(count.classList.contains("muted"));
      rendered.push(["Approvals with two questions", doc.documentElement.outerHTML]);

      // C2: Block on one card; the redraw after it reads (1).
      const card = doc.querySelector(`#approvals-waiting .ask[data-id="${ids[0]}"]`);
      const block = [...card.querySelectorAll(".ask-actions button")].find((b: El) => b.textContent === "Block");
      assert.ok(block, "the card's Block");
      block.click();
      await waitWhile(() => count.textContent !== "(1)", 20_000);
      assert.equal(count.textContent, "(1)", "the count follows the answer");
      assert.equal(h2.textContent, "Waiting for your answer (1)");
      assert.equal(cards(doc).length, 1, "one card left");
      assert.equal(doc.querySelector(`#approvals-waiting .ask[data-id="${ids[0]}"]`), null, "the answered one went");
      rendered.push(["Approvals after the Block", doc.documentElement.outerHTML]);
    }, { headers: { Cookie: ADMIN_COOKIE } });
    const denied = (await admin.egressApprovals("denied")).filter((a) => a.id === ids[0]);
    assert.equal(denied.length, 1, "the arbiter has the Block");
    assert.equal((await admin.egressApprovals("pending")).filter((a) => ids.includes(String(a.id))).length, 1, "one still waits");

    // C3: the oracle.
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");
    const bodies: [string, string][] = [
      ["/api/home", await (await pageFetch(`${base}/api/home`)).text()],
      ["/api/home signed in", await (await pageFetch(`${base}/api/home`, { headers: CSRF_ADMIN })).text()],
      ...rendered,
    ];
    for (const [where, body] of bodies) {
      assert.ok(!body.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: the key's value is in ${where}`);
      assert.doesNotMatch(body, /\$MDU/, `${where} carries no token`);
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    wired.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
