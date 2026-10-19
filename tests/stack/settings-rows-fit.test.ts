/**
 * settings-rows-fit.test — Settings rows whose last cell is a choice and its
 * buttons fit them, across the REAL components (dashboard.md §4.25s *A row's
 * controls fit it*). Mandu-new.
 *
 * Until 2026-10-08 Settings › Sensitivity labels and Settings › Prompt
 * filters put their controls in the plain service row's 120px third column,
 * with no layout of their own: in a browser a label's level picker read
 * "Secret, hidden from th" past the row's border, Save and Remove stacked,
 * every prompt filter choice ran past the row and lost its arrow, and the
 * hint under a label with no level filled the 180px name column.
 *
 * Here a real ArbiterServer (secrets) holds a policy file with the person's
 * label mapping and own prompt filter choice, and an administrator's file
 * with a label and a lock. A real DashboardServer over the production
 * adapter (`makeApprovalsArbiter`) runs a real scan that finds a document's
 * label with no level. The served Settings page (its own index.html and
 * home.js in jsdom, signed in, with the served mandu.css and app.css applied)
 * then shows:
 *
 *   F1  every label row and prompt filter row (yours, your administrator's,
 *       the one the scan found; your own kind, the default, a locked one)
 *       has a third column sized to its controls, up to half the row, and
 *       the controls laid out as one wrapping line;
 *   F2  the notes under a row ("Set by your administrator.", the hint under
 *       a label with no level) span the row;
 *   F3  the oracle: neither the listings nor the rendered page carry the
 *       registered key, the document's text, or a token;
 *   F4  every prompt filter exception (yours, your administrator's, one on
 *       an organization's kind with a long name, one a lock keeps out of
 *       force) reads as one sentence in the row's widest cell, who added it
 *       on the line under it, Remove at the end, and a chip in a name breaks
 *       inside it (§4.25y *An exception reads as a sentence*). Until
 *       2026-10-08 the sentence filled the 180px name column, three to five
 *       lines tall, and a long pattern ran over the words beside it.
 *
 * jsdom does no layout: it reads the declared values the served styles give
 * the served rows, which is what failed (the class names in the page and
 * the rules in the stylesheet did not meet). Axes: secrets (stated).
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
import { resolveCssVars } from "../../dashboard/test/unit/ui/css-flatten.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => setAdminLayer(NO_ADMIN_LAYER));

const KEY = "sk_live_settingsRowsFitStackCanary000000001";
const BODY = "SETTINGSROWSFITDOCUMENTBODYCANARY7741";
const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const GEN = "1e4f0000-0000-4000-8000-000000000001";
const UNMAPPED = "2a2a0000-0000-4000-8000-000000000002";
const TENANT = "4c1d0000-0000-4000-8000-0000000000aa";
const FIT = "180px minmax(0, 1fr) fit-content(50%)";
const LONG_KIND = "acme.customeraccountnumber";
const LONG_MATCH = "build-notifications-and-release-announcements@very-long-subdomain.example.org";

test("Settings over the real arbiter: every label and prompt filter row's controls share one cell sized to them, its notes span the row; each exception reads as one sentence; no value on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-settings-rows-fit-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  // A document whose label no mapping names: the scan counts it.
  writeFileSync(join(proj, "plan.docx"), buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: BODY, stored: true }));
  writeFileSync(join(proj, "README.md"), "a project\n");
  // An organization's prompt filter pack, whose kind has a long name.
  const packs = join(tmp, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), `pack: acme-dlp\nversion: 1\npatterns:\n  - id: account\n    category: ${LONG_KIND}\n    regex: 'CUST\\d{8}'\n`);
  const adminDir = join(tmp, "policy.d");
  mkdirSync(adminDir);
  writeFileSync(join(adminDir, "10-org.yaml"), [
    "sensitivity_labels:",
    `  - { id: ${GEN}, name: General, level: any-model }`,
    "prompt_filters:",
    "  actions:",
    "    secret.shape: { action: redact, locked: true }",
    "  exceptions:",
    "    - { category: pii.email, match: '*@corp.example.com' }",
    "",
  ].join("\n"));
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "sensitivity_labels:",
    `  - { id: ${HC}, name: Highly Confidential, level: no-model }`,
    "prompt_filters:",
    "  filters:",
    "    acme-dlp: on",
    "  actions:",
    "    pii.email: mask",
    "  exceptions:",
    `    - { category: pii.email, match: '${LONG_MATCH}' }`,
    `    - { category: ${LONG_KIND}, match: 'CUST0000*' }`,
    "    - { category: secret.shape, match: 'pk_*' }",
    "",
  ].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: adminDir, promptPackDir: packs, adminPromptPackDir: null, workspaceScan: { env: {}, discovery: { installEnv: {}, selfDir: null } },
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
  try {
    // A registered key, for the oracle: nothing below may carry it.
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });

    // The scan finds the document's label, which no mapping names.
    const scan = await call("POST", "/api/suggestions/scan", { root: "~/proj" });
    assert.equal(scan.status, 200, JSON.stringify(scan.body));
    let labels: any = null;
    for (const end = Date.now() + 60_000; Date.now() < end; await new Promise((r) => setTimeout(r, 50))) {
      labels = (await call("GET", "/api/policy/sensitivity-labels")).body.labels;
      if ((labels?.unmapped ?? []).some((u: any) => u.id === UNMAPPED)) break;
    }
    assert.ok(labels.unmapped.some((u: any) => u.id === UNMAPPED), `the scan found the label with no level: ${JSON.stringify(labels)}`);
    const prompts = await call("GET", "/api/policy/prompt-filters");
    assert.equal(prompts.status, 200);
    const cats = prompts.body.settings.kinds.map((k: any) => k.category);
    for (const c of ["pii.email", "secret.registered", "secret.shape", LONG_KIND]) assert.ok(cats.includes(c), `${c} is listed (${cats.join(", ")})`);
    assert.equal(prompts.body.settings.exceptions.length, 4, `yours and your administrator's exceptions: ${JSON.stringify(prompts.body.settings.exceptions)}`);

    // The served page, signed in, with its served styles.
    const css = async (f: string) => {
      const r = await pageFetch(`${base}/${f}`);
      assert.equal(r.status, 200, `${f} is served`);
      return r.text();
    };
    const styles = resolveCssVars((await css("mandu.css")) + "\n" + (await css("app.css")));
    await servedProductPage(base, "/settings",
      (doc) => doc.querySelector("#settings-labels .label-row.label-unmapped") !== null && doc.querySelector('#settings-prompt-kinds .prompt-kind[data-category="secret.shape"]') !== null
        && doc.querySelectorAll("#settings-prompt-exceptions .row.prompt-exception").length === 4,
      (doc) => {
        const style = (e: Element) => doc.defaultView.getComputedStyle(e);
        // F1: the label rows.
        const labelRows = [...doc.querySelectorAll("#settings-labels .row.label-row")] as HTMLElement[];
        const byId = (id: string) => labelRows.find((r) => r.dataset.id === id);
        const mine = byId(HC), admin = byId(GEN), open = byId(UNMAPPED);
        assert.ok(mine && admin && open, `yours, your administrator's and the one the scan found: ${labelRows.map((r) => r.dataset.id).join(", ")}`);
        for (const row of labelRows) assert.equal(style(row).gridTemplateColumns, FIT, `label ${row.dataset.id}: the third column fits its controls`);
        for (const row of [mine, open]) {
          const acts = row.children[2] as HTMLElement;
          assert.equal(acts.className, "model-actions", "the controls are the row's third cell");
          assert.ok(acts.querySelector("select.label-level") && acts.querySelector(".label-save-btn"), "the picker and Save are in it");
          assert.equal(style(acts).display, "flex", "laid out as one line");
          assert.equal(style(acts).flexWrap, "wrap");
        }
        assert.ok(mine.querySelector(".model-actions .label-remove-btn"), "Remove beside Save");
        assert.equal((mine.querySelector("select.label-level") as HTMLSelectElement).value, "no-model");
        // F2: the notes under a row span it.
        const adminNote = admin.querySelector(".model-admin") as HTMLElement;
        assert.equal(adminNote.textContent, "Set by your administrator.");
        assert.equal(style(adminNote).gridColumn, "1 / -1");
        const hint = open.querySelector(".field-hint") as HTMLElement;
        assert.match(hint.textContent ?? "", /Mandu cannot read your organization's settings, so you choose\./);
        assert.equal(style(hint).gridColumn, "1 / -1", "the hint spans the row, not the name column");
        // F1: the prompt filter rows.
        const kinds = [...doc.querySelectorAll("#settings-prompt-kinds .row.prompt-kind")] as HTMLElement[];
        assert.ok(kinds.length >= 3);
        for (const row of kinds) {
          assert.equal(style(row).gridTemplateColumns, FIT, `${row.dataset.category}: the third column fits its choice`);
          const acts = row.children[2] as HTMLElement;
          assert.equal(acts.className, "model-actions");
          assert.equal(style(acts).display, "flex");
        }
        const own = kinds.find((r) => r.dataset.category === "pii.email")!;
        assert.deepEqual([...own.querySelector(".model-actions")!.children].map((c) => c.className), ["prompt-action", "btn small prompt-reset-btn"], "your own choice, then Use the default, in one cell");
        assert.equal((own.querySelector("select.prompt-action") as HTMLSelectElement).value, "mask");
        assert.match(kinds.find((r) => r.dataset.category === "secret.shape")!.querySelector(".prompt-who")!.textContent ?? "", /Locked by your administrator \(10-org\.yaml\)/);
        const longKind = kinds.find((r) => r.dataset.category === LONG_KIND)!.querySelector(".name code") as HTMLElement;
        assert.equal(longKind.textContent, LONG_KIND, "an organization's kind as code");
        assert.equal(style(longKind).overflowWrap, "anywhere", "its chip breaks inside the name column, never over the words beside it");
        // F4: the exceptions.
        const exRows = [...doc.querySelectorAll("#settings-prompt-exceptions .row.prompt-exception")] as HTMLElement[];
        const sentence = (r: HTMLElement) => r.querySelector(".prompt-exception-what > .name")?.textContent ?? "";
        const ex = (words: string) => exRows.find((r) => sentence(r) === words);
        for (const row of exRows) {
          assert.equal(style(row).gridTemplateColumns, "minmax(0, 1fr) auto", `${sentence(row)}: the sentence takes the row's width`);
          const what = row.children[0] as HTMLElement;
          assert.equal(what.className, "prompt-exception-what", "the sentence and who added it share the first cell");
          assert.deepEqual([...what.children].map((c) => c.className), ["name", "sub"], "who added it on the line under the sentence");
          assert.equal(style(what).flexDirection, "column");
          assert.equal(style(what.children[0] as HTMLElement).display, "block", "the sentence wraps as words");
          for (const code of what.querySelectorAll("code")) assert.equal(style(code as HTMLElement).overflowWrap, "anywhere", `${code.textContent}: breaks inside its chip`);
        }
        const adminEx = ex("An email address matching *@corp.example.com");
        assert.ok(adminEx, `your administrator's exception: ${exRows.map(sentence).join(" | ")}`);
        assert.equal(adminEx.querySelector(".sub")!.textContent, "Set by your administrator (10-org.yaml).");
        assert.equal(adminEx.querySelector("button"), null, "read only");
        const longEx = ex("An email address matching " + LONG_MATCH)!;
        assert.deepEqual([...longEx.children].map((c) => c.className), ["prompt-exception-what", "btn small right prompt-exception-remove"], "Remove is the row's last cell");
        assert.equal(longEx.querySelector(".sub")!.textContent, "Added by you.");
        assert.ok(ex(LONG_KIND + " matching CUST0000*"), "an organization's kind, then its pattern");
        assert.equal(ex("Something shaped like a key or password matching pk_*")!.querySelector(".sub")!.textContent,
          "Added by you. Not in force: your administrator locked this kind.");
        // F3 on the rendered page.
        const page = doc.body.textContent ?? "";
        assert.ok(!page.includes(KEY), "the rendered page carries no registered key");
        assert.ok(!page.includes(BODY), "nor the document's text");
        assert.doesNotMatch(page, /\$MDU/, "nor a token");
      },
      { headers: { Cookie: ADMIN_COOKIE }, css: styles },
    );
    // F3 on every answer read here.
    for (const b of bodies) {
      assert.ok(!b.includes(KEY), "no answer carries the registered key");
      assert.ok(!b.includes(BODY), "nor the document's text");
    }
  } finally {
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
