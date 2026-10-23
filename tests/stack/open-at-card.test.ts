/**
 * open-at-card.test — a link on the product page to a card on another of
 * its pages opens that page at the card once the page has drawn what sits
 * above it, across the REAL components (dashboard.md §4.25r *A link opens at
 * its card*). Mandu-new.
 *
 * Until 2026-10-08 the page scrolled at the click, before the page's reads
 * answered, and what they drew above the card then pushed it down: with ten
 * rules, Settings › Sensitivity labels' **Keys Mandu found** left the card
 * fully below a 900 px window (its top at 997 px), the screen showing Your
 * rules and no Scan for keys; so did Approvals' **Review them**.
 *
 * Here a real ArbiterServer (secrets) with six file rules in policy.yaml, and
 * a real DashboardServer over the production adapter (`makeApprovalsArbiter`).
 * ~/docs holds a document whose label no mapping names and a script holding
 * a key no rule covers. Each served page is its own index.html and home.js
 * in jsdom, signed in, and each scroll is recorded with what the page had
 * drawn by then:
 *
 *   C1  before any scan, Settings' note link **Keys Mandu found** opens Rules
 *       scrolled to that card once the six rules are drawn above it;
 *   C2  after a real scan of ~/docs, Rules' scan line link **Settings,
 *       Sensitivity labels** opens Settings scrolled to that card once Models
 *       above it and the card's own label are drawn;
 *   C3  Approvals' **Review them** (the scan's key waits there) opens Rules
 *       scrolled to Keys Mandu found once the rules are drawn;
 *   C4  the oracle: neither the answers nor the rendered pages carry the
 *       registered key, the key the scan found, the document's text, or a
 *       token.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NO_ADMIN_LAYER, setAdminLayer } from "../../arbiter/policy/admin-layer.js";
import { buildOfficeFile } from "../../arbiter/test/helpers/office-zip.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => setAdminLayer(NO_ADMIN_LAYER));

const KEY = "sk_" + "live_openAtCardRegisteredCanary00000001";
const FOUND = "sk_" + "live_51HopenAtCardFound0AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
const BODY = "OPENATCARDDOCUMENTBODY6631";
const UNMAPPED = "2a2a0000-0000-4000-8000-000000000002";
const TENANT = "4c1d0000-0000-4000-8000-0000000000aa";
const RULES = 6;

test("a link to a card on another page opens it there once the page has drawn above it, over the real arbiter; no value on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-open-at-card-"));
  const home = join(tmp, "home");
  const docs = join(home, "docs");
  mkdirSync(docs, { recursive: true });
  writeFileSync(join(docs, "plan.docx"), buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: BODY, stored: true }));
  writeFileSync(join(docs, "deploy.sh"), `export STRIPE_KEY=${FOUND}\n`);
  const rules = Array.from({ length: RULES }, (_, i) => `  - { path: "${join(home, `proj${i}`, "secret.txt")}", level: no-model }`).join("\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n${rules}\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null, workspaceScan: { env: {}, discovery: { installEnv: {}, selfDir: null } },
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home") }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const pages: string[] = [];
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await pageFetch(base + path, { method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) };
  };
  /** The served page at `path`; `fn` gets it and `scrolled`, each scroll as
   *  [the card's id, what `drawn` says the page had drawn by then]. */
  const served = (path: string, ready: (doc: any) => boolean, drawn: (doc: any) => unknown, fn: (doc: any, scrolled: unknown[][]) => Promise<void>) =>
    servedProductPage(base, path, ready, async (doc) => {
      const scrolled: unknown[][] = [];
      doc.defaultView.HTMLElement.prototype.scrollIntoView = function (this: any) { scrolled.push([this.id, drawn(doc)]); };
      await fn(doc, scrolled);
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });
  const page = (doc: any, name: string) => doc.querySelector(`#main > section[data-page="${name}"]`);
  // The six rules, as Rules draws them above Keys Mandu found.
  const rulesDrawn = (doc: any) => [...doc.querySelectorAll("#files-tree .row.file-rule")].filter((r: any) => /proj\d/.test(r.getAttribute("data-path") ?? "")).length;
  try {
    // A registered key, for the oracle: nothing below may carry it.
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });

    // C1: Settings › Sensitivity labels' note, before any scan.
    const noteLink = (doc: any) => doc.querySelector("#settings-labels .labels-note a");
    await served("/settings", (doc) => noteLink(doc) != null, rulesDrawn, async (doc, scrolled) => {
      assert.equal(noteLink(doc).textContent, "Keys Mandu found");
      assert.equal(rulesDrawn(doc), 0, "Rules has not been drawn in this page yet");
      noteLink(doc).click();
      await waitWhile(() => page(doc, "rules").hidden || scrolled.length === 0);
      assert.equal(doc.defaultView.location.pathname, "/rules");
      assert.deepEqual(scrolled, [["suggested-block", RULES]], "one scroll, to Keys Mandu found, once the six rules above it are drawn");
      assert.equal(doc.getElementById("files-suggested-view").hidden, false, "Keys Mandu found is open");
      assert.equal(doc.getElementById("suggest-scan").textContent, "Scan for keys");
    });

    // A real scan of ~/docs: the document's label and the script's key.
    const started = await call("POST", "/api/suggestions/scan", { root: "~/docs" });
    assert.equal(started.status, 200, JSON.stringify(started.body));
    let scan: any = started.body.scan;
    for (const end = Date.now() + 60_000; scan.running && Date.now() < end; await new Promise((res) => setTimeout(res, 50))) {
      scan = (await call("GET", "/api/suggestions")).body.scan;
    }
    assert.equal(scan.running, false, "the scan ended");
    assert.equal(scan.error, null);
    assert.match(scan.summary, /1 file carries a sensitivity label you have not chosen a level for/);
    const listing = (await call("GET", "/api/suggestions")).body;
    assert.ok(listing.count >= 1, `the scan's key waits in Keys Mandu found: ${JSON.stringify(listing.suggestions.map((s: any) => s.sentence))}`);

    // C2: Rules' scan line links Settings › Sensitivity labels.
    const scanLink = (doc: any) => doc.querySelector("#suggest-status a");
    const settingsDrawn = (doc: any) => [doc.getElementById("settings-models").childElementCount > 0, doc.querySelector("#settings-labels .label-row.label-unmapped") != null];
    await served("/rules", (doc) => doc.getElementById("suggest-open") != null && rulesDrawn(doc) === RULES, settingsDrawn, async (doc, scrolled) => {
      if (doc.getElementById("files-suggested-view").hidden) doc.getElementById("suggest-open").click();
      await waitWhile(() => scanLink(doc) == null);
      assert.equal(scanLink(doc).textContent, "Settings › Sensitivity labels");
      assert.deepEqual(settingsDrawn(doc), [false, false], "Settings has not been drawn in this page yet");
      scanLink(doc).click();
      await waitWhile(() => page(doc, "settings").hidden || scrolled.length === 0);
      assert.equal(doc.defaultView.location.pathname, "/settings");
      assert.deepEqual(scrolled, [["settings-labels-block", [true, true]]], "one scroll, once Models above the card and the card's own label are drawn");
    });

    // C3: Approvals' Review them.
    const review = (doc: any) => doc.getElementById("approvals-suggestions-open");
    await served("/approvals", (doc) => !doc.getElementById("approvals-suggestions-block").hidden, rulesDrawn, async (doc, scrolled) => {
      assert.match(doc.getElementById("approvals-suggestions-block").textContent, /Mandu found 1 possible key/);
      assert.equal(rulesDrawn(doc), 0, "Rules has not been drawn in this page yet");
      review(doc).click();
      await waitWhile(() => page(doc, "rules").hidden || scrolled.length === 0);
      assert.equal(doc.defaultView.location.pathname, "/rules");
      assert.deepEqual(scrolled, [["suggested-block", RULES]], "one scroll, to Keys Mandu found, once the rules are drawn");
      await waitWhile(() => doc.querySelector("#files-suggested-list .row.suggested") == null);
      assert.match(doc.getElementById("files-suggested-list").textContent, /deploy\.sh/, "the key the scan found is listed there");
    });

    // C4: the oracle.
    assert.equal(pages.length, 3, "every page was read");
    for (const b of [...bodies, ...pages]) {
      assert.ok(!b.includes(KEY), "no answer or page carries the registered key");
      assert.ok(!b.includes(FOUND), "nor the key the scan found");
      assert.ok(!b.includes(BODY), "nor the document's text");
    }
    for (const p of pages) assert.doesNotMatch(p, /\$MDU/, "no page carries a token");
  } finally {
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
