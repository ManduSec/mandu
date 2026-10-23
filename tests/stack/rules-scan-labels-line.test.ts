/**
 * rules-scan-labels-line.test — Rules › Keys Mandu found: the line under
 * Scan for keys counts the documents whose sensitivity labels the scan read,
 * and links Settings › Sensitivity labels where it says to set a level,
 * across the REAL components (dashboard.md §4.25r *Scan for keys*).
 * Mandu-new.
 *
 * Until 2026-10-08 a scan of a folder of Office documents read "Scanned 0
 * files in ~/docs. … 1 file carries a sensitivity label you have not chosen
 * a level for: set it in Settings › Sensitivity labels.": the arbiter counts
 * a document's label read apart from its text reads, and the line counted
 * only the text reads. The place it named was plain text.
 *
 * Here a real ArbiterServer (secrets) and a real DashboardServer over the
 * production adapter (`makeApprovalsArbiter`). ~/docs holds a text file, a
 * document whose label no mapping names, and a document a rule covers:
 *
 *   S1  a real scan of ~/docs: the line counts the text file and the
 *       document it opened ("Scanned 2 files"), and says the covered one
 *       was not opened; `summaryParts` names Settings › Sensitivity labels
 *       as a link part, never an address, in the scan answer and in the
 *       listing;
 *   S2  the served Rules page (its own index.html and home.js in jsdom,
 *       signed in) shows that line with the link; a click opens Settings
 *       scrolled to the Sensitivity labels card, which lists the label, once
 *       the card and Models above it are drawn;
 *   S3  the oracle: neither the answers nor the rendered pages carry the
 *       registered key, a document's text, or a token.
 *
 * And the documents the label read left unchecked (2026-10-08): until then
 * the line never named the label read's own caps nor the documents it could
 * not read, which the arbiter names for the terminal. With the label read's
 * file cap lowered to 2 (standing in for a folder past the real 2,000), a
 * malformed `.docx` and three labelled documents:
 *
 *   S4  the scan answer, the listing and the served Rules page end the line
 *       with "Not checked for a sensitivity label: 2 documents past the 2 it
 *       looks at and 1 document it could not read."; the S3 oracle again.
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

const KEY = "sk_" + "live_rulesScanLabelsLineCanary000000001";
const BODY = "RULESSCANLABELSLINEDOCUMENTBODY7781";
const LOCKED_BODY = "RULESSCANLABELSLINELOCKEDBODY7782";
const UNMAPPED = "2a2a0000-0000-4000-8000-000000000002";
const TENANT = "4c1d0000-0000-4000-8000-0000000000aa";
const LINK = { kind: "link", text: "Settings › Sensitivity labels", to: "labels" };
const LINE =
  "Scanned 2 files in ~/docs. Nothing new to review. No git history was found in ~/docs. " +
  "1 file your rules already protect was not opened. " +
  "1 file carries a sensitivity label you have not chosen a level for: set it in Settings › Sensitivity labels.";

/** A real arbiter (secrets) and a real signed-in dashboard over the
 *  production adapter; `fill` writes ~/docs and returns the policy's
 *  `paths:` lines; `labelLimits` lowers the label read's budgets. */
async function withStack(
  fill: (docs: string) => string,
  labelLimits: { maxFiles?: number; totalMaxBytes?: number } | null,
  body: (t: { call: (method: "GET" | "POST", path: string, body?: unknown) => Promise<{ status: number; body: any }>; base: string; bodies: string[]; scan: () => Promise<any> }) => Promise<void>,
): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-scan-labels-line-"));
  const home = join(tmp, "home");
  const docs = join(home, "docs");
  mkdirSync(docs, { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\n${fill(docs)}`);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    workspaceScan: { env: {}, discovery: { installEnv: {}, selfDir: null }, ...(labelLimits ? { labelLimits } : {}) },
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
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await pageFetch(base + path, { method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) };
  };
  // A real scan of ~/docs, read back until it ends.
  const scan = async () => {
    const started = await call("POST", "/api/suggestions/scan", { root: "~/docs" });
    assert.equal(started.status, 200, JSON.stringify(started.body));
    let s: any = started.body.scan;
    for (const end = Date.now() + 60_000; s.running && Date.now() < end; await new Promise((res) => setTimeout(res, 50))) {
      s = (await call("GET", "/api/suggestions")).body.scan;
    }
    assert.equal(s.running, false, "the scan ended");
    assert.equal(s.error, null);
    return s;
  };
  try {
    // A registered key, for the oracle: nothing below may carry it.
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    await body({ call, base, bodies, scan });
  } finally {
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
}

const status = (doc: any) => doc.getElementById("suggest-status");

test("Rules' scan line over the real arbiter: it counts the documents it read and links Settings › Sensitivity labels; no value on the page", { timeout: 180_000 }, async () => {
  const fill = (docs: string) => {
    writeFileSync(join(docs, "notes.txt"), "meeting notes, nothing secret\n");
    writeFileSync(join(docs, "plan.docx"), buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: BODY, stored: true }));
    writeFileSync(join(docs, "locked.docx"), buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: LOCKED_BODY, stored: true }));
    return `paths:\n  - { path: "${join(docs, "locked.docx")}", level: no-model }\n`;
  };
  await withStack(fill, null, async ({ call, base, bodies, scan: runScan }) => {
    const pages: string[] = [];
    // S1: a real scan of ~/docs, read back until it ends.
    const scan = await runScan();
    assert.equal(scan.summary, LINE, "the text file and the document it opened are counted; the covered one was not opened");
    assert.doesNotMatch(scan.summary, /Scanned 0 files/);
    assert.deepEqual(scan.summaryParts.filter((p: any) => p.kind !== "text"), [LINK], "the place is a link part, never an address");
    assert.equal(scan.summaryParts.map((p: any) => p.text).join(""), scan.summary, "summary is the parts joined");
    const listed = (await call("GET", "/api/suggestions")).body.scan;
    assert.deepEqual([listed.summary, listed.summaryParts], [scan.summary, scan.summaryParts], "the listing keeps the line and its parts");

    // S2: the served Rules page, signed in.
    await servedProductPage(base, "/rules", (doc) => doc.getElementById("suggest-open") != null, async (doc) => {
      if (doc.getElementById("files-suggested-view").hidden) doc.getElementById("suggest-open").click();
      await waitWhile(() => status(doc).querySelector("a") == null);
      assert.equal(status(doc).textContent, LINE);
      const links = [...status(doc).querySelectorAll("a")] as any[];
      assert.deepEqual(links.map((a) => [a.textContent, a.getAttribute("href")]), [["Settings › Sensitivity labels", "/settings#sensitivity-labels"]]);
      pages.push(doc.body.textContent ?? "");
      // Each scroll with whether the card's own list and Models above it
      // were drawn by then: it comes once Settings has drawn (§4.25r *A link
      // opens at its card*).
      const scrolled: unknown[][] = [];
      const drawn = () => [doc.querySelector("#settings-labels .label-row.label-unmapped") != null, doc.getElementById("settings-models").childElementCount > 0];
      doc.defaultView.HTMLElement.prototype.scrollIntoView = function (this: any) { scrolled.push([this.id, drawn()]); };
      links[0].click();
      const settings = () => doc.querySelector('#main > section[data-page="settings"]');
      await waitWhile(() => settings().hidden || scrolled.length === 0);
      assert.equal(doc.defaultView.location.pathname, "/settings", "Settings");
      assert.equal(doc.querySelector('#main > section[data-page="rules"]').hidden, true);
      assert.deepEqual(scrolled, [["settings-labels-block", [true, true]]], "scrolled to the Sensitivity labels card, once it and Models are drawn");
      const row = doc.querySelector("#settings-labels .label-row.label-unmapped");
      assert.equal(row.dataset.id, UNMAPPED, "where the label waits for a level");
      assert.ok(doc.getElementById("settings-labels-block").contains(row));
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // S3: the oracle.
    assert.ok(pages.length === 2, "both pages were read");
    for (const b of [...bodies, ...pages]) {
      assert.ok(!b.includes(KEY), "no answer or page carries the registered key");
      assert.ok(!b.includes(BODY) && !b.includes(LOCKED_BODY), "nor a document's text");
    }
    for (const p of pages) assert.doesNotMatch(p, /\$MDU/, "no page carries a token");
  });
});

const GAPS_LINE =
  "Scanned 3 files in ~/docs. Nothing new to review. No git history was found in ~/docs. " +
  "1 file carries a sensitivity label you have not chosen a level for: set it in Settings › Sensitivity labels. " +
  "Not checked for a sensitivity label: 2 documents past the 2 it looks at and 1 document it could not read.";

test("Rules' scan line over the real arbiter: it names the documents the label read left unchecked, past its own cap or unreadable; no value on the page", { timeout: 180_000 }, async () => {
  // Walked in name order: the malformed document and the first labelled one
  // are examined (the cap is 2), the other two are past it.
  const fill = (docs: string) => {
    writeFileSync(join(docs, "notes.txt"), "meeting notes, nothing secret\n");
    writeFileSync(join(docs, "0-broken.docx"), "not an Office file at all\n");
    writeFileSync(join(docs, "a-plan.docx"), buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: BODY, stored: true }));
    writeFileSync(join(docs, "b-budget.xlsx"), buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: LOCKED_BODY, stored: true }));
    writeFileSync(join(docs, "c-deck.pptx"), buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: LOCKED_BODY, stored: true }));
    return "";
  };
  await withStack(fill, { maxFiles: 2 }, async ({ call, base, bodies, scan: runScan }) => {
    const pages: string[] = [];
    // S4: the scan answer and the listing.
    const scan = await runScan();
    assert.equal(scan.summary, GAPS_LINE, "the label read's cap and the document it could not read are named");
    assert.equal(scan.summaryParts.map((p: any) => p.text).join(""), scan.summary, "summary is the parts joined");
    assert.deepEqual(scan.summaryParts.filter((p: any) => p.kind !== "text"), [LINK], "no new link");
    const listed = (await call("GET", "/api/suggestions")).body.scan;
    assert.equal(listed.summary, GAPS_LINE, "the listing keeps the line");

    // The served Rules page, signed in.
    await servedProductPage(base, "/rules", (doc) => doc.getElementById("suggest-open") != null, async (doc) => {
      if (doc.getElementById("files-suggested-view").hidden) doc.getElementById("suggest-open").click();
      await waitWhile(() => status(doc).querySelector("a") == null);
      assert.equal(status(doc).textContent, GAPS_LINE);
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // The oracle.
    assert.ok(pages.length === 1, "the page was read");
    for (const b of [...bodies, ...pages]) {
      assert.ok(!b.includes(KEY), "no answer or page carries the registered key");
      assert.ok(!b.includes(BODY) && !b.includes(LOCKED_BODY), "nor a document's text");
    }
    for (const p of pages) assert.doesNotMatch(p, /\$MDU/, "no page carries a token");
  });
});
