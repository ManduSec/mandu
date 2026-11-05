/**
 * ask-card-headings.test — a waiting question's headline is a heading on
 * the served product page, across the REAL components (dashboard.md §4.25u
 * *Each question and rule change is a heading*). Mandu-new.
 *
 * A real ArbiterServer (`secrets` axes) registers a secret file, and its
 * real egress gate asks about the file's key at a host no rule binds it to.
 * A real DashboardServer over a real ArbiterEventSource, with the real
 * admin-socket client behind its approval routes, serves the queue:
 *
 *   K1  the served Approvals page lists the question's headline among its
 *       headings, an h3 right under the h2 "Waiting for your answer", and
 *       the card is named by it;
 *   K2  the served Home lists it as an h3 right under "Approvals waiting";
 *   K3  after an answer (Block, over the real route and the real resolve
 *       op) the heading is gone with its card, on both pages;
 *   K4  neither page carries the secret's value or a `$MDU` token.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets");

const KEY_VALUE = "sk_" + "live_askCardHeadingsStackCanary00000001";
const SESSION = "1791200000-177";
const CSRF = { "X-Mandu-Control": "1" };
const HEADLINE = "The agent wants to send your secret STRIPE_KEY to api.stripe.com";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const said = (e: El) => String(e.textContent).replace(/\s+/g, " ").trim();
/** The headings a screen reader lists on one page: none in a hidden part. */
const listed = (doc: El, page: string) => ([...doc.querySelectorAll(`#page-${page} :is(h1, h2, h3, h4, h5, h6)`)] as El[])
  .filter((h) => !h.closest("[hidden]"));
const noLeak = (doc: El) => {
  const page = doc.body.textContent ?? "";
  assert.ok(!page.includes(KEY_VALUE), "the served page carries no secret value");
  assert.doesNotMatch(page, /\$MDU/, "nor a token");
};

test("a waiting question's headline is a heading on the served Approvals and Home, gone with its card once answered", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-ask-headings-"));
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
  try {
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\nDEBUG=1\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const d = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: "api.stripe.com", sessionKey: SESSION, scheme: "https" });
    assert.equal(d.allow, false);
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true);
    const id = String((d as { approvalId?: string }).approvalId);

    // K1: Approvals.
    const approvalsCard = `#approvals-waiting .ask[data-id="${id}"]`;
    await servedProductPage(base, "/approvals", (doc) => doc.querySelector(approvalsCard) !== null, (doc) => {
      const card = doc.querySelector(approvalsCard);
      const heads = [...card.querySelectorAll("h1, h2, h3, h4, h5, h6")] as El[];
      assert.equal(heads.length, 1, "one heading in the card");
      assert.equal(heads[0].tagName, "H3");
      assert.equal(said(heads[0]), HEADLINE);
      assert.equal(doc.getElementById(card.getAttribute("aria-labelledby")), heads[0], "the card is named by its heading");
      const list = listed(doc, "approvals");
      const at = list.indexOf(heads[0]);
      assert.ok(at > 0, "the question is in the page's heading list");
      assert.equal(`${list[at - 1].tagName} ${said(list[at - 1])}`, "H2 Waiting for your answer (1)", "right under its section's h2, which counts its one question");
      noLeak(doc);
    });

    // K2: Home's short card.
    const homeCard = `#home-waiting .ask[data-id="${id}"]`;
    await servedProductPage(base, "/", (doc) => doc.querySelector(homeCard) !== null, (doc) => {
      const h = doc.querySelector(`${homeCard} h3.ask-sentence`);
      assert.ok(h, "Home's card has its h3");
      assert.equal(said(h), HEADLINE);
      const list = listed(doc, "home");
      const at = list.indexOf(h);
      assert.ok(at > 0, "the question is in Home's heading list");
      assert.match(`${list[at - 1].tagName} ${said(list[at - 1])}`, /^H2 Approvals waiting/, "right under Approvals waiting");
      noLeak(doc);
    });

    // K3: Block over the real route; the heading leaves with its card.
    const res = await pageFetch(`${base}/api/egress/approvals/${id}/deny`, { method: "POST", headers: { ...CSRF, Cookie: dashboard.adminCookie() } });
    assert.equal(res.status, 200, await res.clone().text());
    const answeredRow = `#approvals-answered .row.answered[data-id="${id}"]`;
    await servedProductPage(base, "/approvals", (doc) => doc.querySelector(answeredRow) !== null, (doc) => {
      assert.equal(doc.querySelector(approvalsCard), null, "the card is gone");
      assert.ok(!listed(doc, "approvals").some((h) => said(h) === HEADLINE), "and its heading with it");
      noLeak(doc);
    });
    await servedProductPage(base, "/", (doc) => doc.querySelector('#home-waiting [data-empty="questions"], #home-waiting .empty') !== null, (doc) => {
      assert.equal(doc.querySelector(homeCard), null, "Home's card is gone");
      assert.ok(!listed(doc, "home").some((h) => said(h) === HEADLINE), "and its heading with it");
    });
  } finally {
    await dashboard.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
