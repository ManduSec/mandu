/**
 * settings-labels-scan-link.test — Settings › Sensitivity labels' note links
 * to where Scan for keys is, and says what the last scan found, across the
 * REAL components (dashboard.md §4.25s *The note links where Scan for keys
 * is*). Mandu-new.
 *
 * Until 2026-10-08 the note before any scan said "Press Scan for keys in
 * Rules › Keys Mandu found, to look for them." with no link, and Rules shows
 * that button only once Keys Mandu found is opened (Review). After a scan
 * that found no document with a label, it said "Every sensitivity label the
 * last scan found has a level." over an empty list.
 *
 * Here a real ArbiterServer (secrets) and a real DashboardServer over the
 * production adapter (`makeApprovalsArbiter`), with a project holding no
 * Office file and a folder holding a document whose label no mapping names:
 *
 *   L1  before any scan, the listing's note names Keys Mandu found as a link
 *       part; on the served Settings page (its own index.html and home.js in
 *       jsdom, signed in) it is a link, and a click on it shows Rules with
 *       Keys Mandu found open and its Scan for keys button;
 *   L2  after a real scan of the project, the note says the scan found no
 *       sensitivity label, with the same link, on the listing and the page;
 *   L3  after a real scan of the folder, the label is listed with no note;
 *   L4  the oracle: neither the answers nor the rendered pages carry the
 *       registered key, the document's text, or a token.
 *
 * And what the label read left unchecked (2026-10-08, §4.25s *The note says
 * what the scan left unchecked*): until then a scan that never checked some
 * documents still read "found no sensitivity label on your documents",
 * while Rules' scan line named them. With the label read's file cap lowered
 * to 2 (standing in for a folder past the real 2,000):
 *
 *   L5  a real scan of a folder of unlabelled documents and a malformed
 *       `.docx`: the listing and the served page say "on the documents it
 *       checked" and which documents it did not, in the scan line's words,
 *       with the same link;
 *   L6  a real scan of three labelled documents: the label waits for a
 *       level, and the note says the one document past the cap; once the
 *       label is given a level (a real change through the route), "Every
 *       sensitivity label the last scan found has a level." and the same;
 *   L7  the L4 oracle again.
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
import { ALL_MAPPED_NOTE, NO_LABELS_NOTE, NO_SCAN_NOTE } from "../../dashboard/src/view-model/sensitivity-labels.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => setAdminLayer(NO_ADMIN_LAYER));

const KEY = "sk_live_settingsLabelsScanLinkCanary0000001";
const BODY = "SETTINGSLABELSSCANLINKDOCUMENTBODY5521";
const UNMAPPED = "2a2a0000-0000-4000-8000-000000000002";
const TENANT = "4c1d0000-0000-4000-8000-0000000000aa";
const LINK = { kind: "link", text: "Keys Mandu found", to: "suggested" };

type Stack = {
  call: (method: "GET" | "POST", path: string, body?: unknown) => Promise<{ status: number; body: any }>;
  labels: () => Promise<any>;
  scan: (root: string, done: (l: any) => boolean) => Promise<any>;
  settings: (ready: (doc: any) => boolean, fn: (doc: any) => void | Promise<void>) => Promise<void>;
  bodies: string[];
  pages: string[];
};

/** A real arbiter (secrets) and a real signed-in dashboard over the
 *  production adapter, with a registered key for the oracle; `fill` writes
 *  the home folder; `labelLimits` lowers the label read's budgets. */
async function withStack(fill: (home: string) => void, labelLimits: { maxFiles?: number } | null, body: (t: Stack) => Promise<void>): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-settings-labels-scan-link-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  fill(home);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
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
  const pages: string[] = [];
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await pageFetch(base + path, { method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) };
  };
  const labels = async () => (await call("GET", "/api/policy/sensitivity-labels")).body.labels;
  /** Scan `root`, then read the listing until that scan's labels are in it. */
  const scan = async (root: string, done: (l: any) => boolean) => {
    const before = (await labels()).scannedAt;
    const r = await call("POST", "/api/suggestions/scan", { root });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    let l: any = null;
    for (const end = Date.now() + 60_000; Date.now() < end; await new Promise((res) => setTimeout(res, 50))) {
      l = await labels();
      if (typeof l.scannedAt === "number" && l.scannedAt !== before && done(l)) break;
    }
    assert.ok(typeof l.scannedAt === "number" && l.scannedAt !== before, `the scan of ${root} ended: ${JSON.stringify(l)}`);
    return l;
  };
  const settings = (ready: (doc: any) => boolean, fn: (doc: any) => void | Promise<void>) =>
    servedProductPage(base, "/settings", ready, async (doc) => {
      await fn(doc);
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });
  try {
    // A registered key, for the oracle: nothing below may carry it.
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    await body({ call, labels, scan, settings, bodies, pages });
  } finally {
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
}

const note = (doc: any) => doc.querySelector("#settings-labels .labels-note");

/** The oracle: no answer or rendered page carries the registered key, a
 *  document's text, or a token. */
function oracle({ bodies, pages }: Stack, n: number): void {
  assert.equal(pages.length, n, "every page was read");
  for (const b of [...bodies, ...pages]) {
    assert.ok(!b.includes(KEY), "no answer or page carries the registered key");
    assert.ok(!b.includes(BODY), "nor a document's text");
  }
  for (const p of pages) assert.doesNotMatch(p, /\$MDU/, "no page carries a token");
}

test("Settings › Sensitivity labels over the real arbiter: the note links Keys Mandu found, open with Scan for keys; a scan that found no label says so; no value on the page", { timeout: 180_000 }, async () => {
  const fill = (home: string) => {
    mkdirSync(join(home, "proj"));
    writeFileSync(join(home, "proj", "README.md"), "a project with no Office file\n");
    mkdirSync(join(home, "docs"));
    writeFileSync(join(home, "docs", "plan.docx"), buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: BODY, stored: true }));
  };
  await withStack(fill, null, async (t) => {
    const { labels, scan, settings } = t;
    // L1: before any scan.
    const first = await labels();
    assert.equal(first.scannedAt, null, "no scan yet");
    assert.equal(first.note, NO_SCAN_NOTE);
    assert.deepEqual(first.noteParts.filter((p: any) => p.kind === "link"), [LINK], "the place is a link part, never an address");
    await settings((doc) => note(doc)?.querySelector("a") != null, async (doc) => {
      const n = note(doc);
      assert.equal(n.textContent, "Mandu lists here the sensitivity labels it finds on your documents. To look for them, open Keys Mandu found in Rules and press Scan for keys.");
      const a = n.querySelector("a");
      assert.equal(a.textContent, "Keys Mandu found");
      assert.equal(a.getAttribute("href"), "/rules#keys-found");
      assert.equal(doc.getElementById("files-suggested-view").hidden, true, "Rules keeps Scan for keys behind Review until opened");
      a.click();
      const view = () => doc.getElementById("files-suggested-view");
      await waitWhile(() => view().hidden || doc.querySelector('#main > section[data-page="rules"]').hidden);
      assert.equal(doc.defaultView.location.pathname, "/rules", "Rules");
      assert.equal(doc.querySelector('#main > section[data-page="rules"]').hidden, false);
      assert.equal(view().hidden, false, "with Keys Mandu found open");
      assert.equal(doc.getElementById("suggest-open").getAttribute("aria-expanded"), "true");
      const btn = doc.getElementById("suggest-scan");
      assert.ok(btn && view().contains(btn), "its Scan for keys button inside it");
      assert.equal(btn.textContent, "Scan for keys");
    });

    // L2: a real scan of a project with no Office file.
    const none = await scan("~/proj", () => true);
    assert.deepEqual(none.unmapped, []);
    assert.equal(none.note, NO_LABELS_NOTE, "it found no label, and says so");
    assert.notEqual(none.note, ALL_MAPPED_NOTE);
    assert.deepEqual(none.noteParts.filter((p: any) => p.kind === "link"), [LINK]);
    await settings((doc) => /found no sensitivity label/.test(note(doc)?.textContent ?? ""), (doc) => {
      assert.equal(note(doc).textContent, "The last scan found no sensitivity label on your documents. To look in another folder, open Keys Mandu found in Rules.");
      assert.doesNotMatch(note(doc).textContent, /Every sensitivity label/);
      assert.equal(note(doc).querySelector("a").getAttribute("href"), "/rules#keys-found");
      assert.equal(doc.querySelector("#settings-labels .label-row"), null, "no label listed");
    });

    // L3: a real scan of the folder with a labelled document.
    const found = await scan("~/docs", (l) => (l.unmapped ?? []).some((u: any) => u.id === UNMAPPED));
    assert.deepEqual(found.unmapped.map((u: any) => [u.id, u.site, u.files]), [[UNMAPPED, TENANT, 1]]);
    assert.equal(found.note, null, "a label to give a level: no note");
    assert.equal(found.noteParts, null);
    await settings((doc) => doc.querySelector("#settings-labels .label-row.label-unmapped") != null, (doc) => {
      assert.equal(doc.querySelector("#settings-labels .label-row.label-unmapped").dataset.id, UNMAPPED);
      assert.equal(note(doc), null);
    });

    // L4: the oracle.
    oracle(t, 3);
  });
});

const GAPS = "Not checked for a sensitivity label: 2 documents past the 2 it looks at and 1 document it could not read.";
const PAST_CAP = "Not checked for a sensitivity label: 1 document past the 2 it looks at.";

test("Settings › Sensitivity labels over the real arbiter: after a scan whose label read left documents unchecked, the note says which, as Rules' scan line does; no value on the page", { timeout: 180_000 }, async () => {
  // Walked in name order with the cap at 2: in ~/plain the malformed
  // document and the first unlabelled one are examined, the other two are
  // past the cap; in ~/labelled the third labelled document is.
  const fill = (home: string) => {
    mkdirSync(join(home, "plain"));
    writeFileSync(join(home, "plain", "notes.txt"), "meeting notes, nothing secret\n");
    writeFileSync(join(home, "plain", "0-broken.docx"), "not an Office file at all\n");
    for (const n of ["a-plan.docx", "b-budget.xlsx", "c-deck.pptx"]) writeFileSync(join(home, "plain", n), buildOfficeFile({ body: BODY, stored: true }));
    mkdirSync(join(home, "labelled"));
    for (const n of ["a-plan.docx", "b-budget.xlsx", "c-deck.pptx"]) writeFileSync(join(home, "labelled", n), buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: BODY, stored: true }));
  };
  await withStack(fill, { maxFiles: 2 }, async (t) => {
    const { call, labels, scan, settings } = t;
    // L5: no labelled document, two past the cap and one it could not read.
    const plain = await scan("~/plain", () => true);
    const rulesLine = (await call("GET", "/api/suggestions")).body.scan.summary as string;
    assert.ok(rulesLine.endsWith(GAPS), `Rules' scan line names them: ${rulesLine}`);
    const NOTE = `The last scan found no sensitivity label on the documents it checked. ${GAPS} To look in another folder, open Keys Mandu found in Rules.`;
    assert.deepEqual(plain.unmapped, []);
    assert.equal(plain.note, NOTE, "the same words as the scan line, and only about what it checked");
    assert.notEqual(plain.note, NO_LABELS_NOTE);
    assert.deepEqual(plain.noteParts.filter((p: any) => p.kind === "link"), [LINK]);
    await settings((doc) => /documents it checked/.test(note(doc)?.textContent ?? ""), (doc) => {
      assert.equal(note(doc).textContent, NOTE);
      assert.doesNotMatch(note(doc).textContent, /on your documents/);
      assert.equal(note(doc).querySelector("a").getAttribute("href"), "/rules#keys-found");
    });

    // L6: a label waiting for a level, with one document past the cap.
    const found = await scan("~/labelled", (l) => (l.unmapped ?? []).some((u: any) => u.id === UNMAPPED));
    assert.deepEqual(found.unmapped.map((u: any) => [u.id, u.site, u.files]), [[UNMAPPED, TENANT, 2]], "the two documents it checked");
    assert.equal(found.note, PAST_CAP, "the note says the one past the cap, alone");
    assert.deepEqual(found.noteParts, [{ kind: "text", text: PAST_CAP }]);
    await settings((doc) => doc.querySelector("#settings-labels .label-row.label-unmapped") != null && note(doc) != null, (doc) => {
      assert.equal(doc.querySelector("#settings-labels .label-row.label-unmapped").dataset.id, UNMAPPED);
      assert.equal(note(doc).textContent, PAST_CAP);
      assert.equal(note(doc).querySelector("a"), null);
    });
    // Given a level through the real route: every label found has one, and
    // the note still says what was left unchecked.
    const mapped = await call("POST", "/api/policy/sensitivity-labels/change", { action: "map", id: UNMAPPED, site: TENANT, name: "Confidential", level: "no-model", version: found.unmapped[0].version });
    assert.equal(mapped.status, 200, JSON.stringify(mapped.body));
    assert.equal(mapped.body.applied, true);
    const after = await labels();
    assert.deepEqual(after.unmapped, []);
    assert.equal(after.note, `${ALL_MAPPED_NOTE} ${PAST_CAP}`);
    await settings((doc) => /Every sensitivity label/.test(note(doc)?.textContent ?? ""), (doc) => {
      assert.equal(note(doc).textContent, `${ALL_MAPPED_NOTE} ${PAST_CAP}`);
      assert.equal(doc.querySelector("#settings-labels .label-row").dataset.id, UNMAPPED, "listed with its level");
    });

    // L7: the oracle.
    oracle(t, 3);
  });
});
