/**
 * notice-undo-names.test — on the product page, a notice's Undo says which
 * change it undoes, across the REAL components (dashboard.md §4.25 *A
 * notice's Undo says which change it undoes*). Mandu-new.
 *
 * A change made in Rules › Your rules or in a Settings card shows a notice
 * with an Undo, and a notice stays until its card's next change. Until
 * 2026-10-11 three changes on Settings (a model removed, a label saved, a
 * kind's choice changed) left three buttons all named "Undo", with no word
 * of what each undoes.
 *
 * Here a real ArbiterServer (secrets) holds a policy.yaml with two models of
 * the person's own, a sensitivity label level, a prompt filter choice and a
 * sending rule, and a registered key. A real DashboardServer over the
 * production adapter (`makeApprovalsArbiter`) serves the product page (its
 * own index.html and home.js in jsdom), signed in:
 *
 *   U1  Settings: a model removed (asked first), a label saved and a kind's
 *       choice changed give three notices whose Undo is named by its card
 *       ("Undo the change in Models", "… in Sensitivity labels", "… in
 *       Prompt filters"), still reads "Undo", is described by its notice's
 *       words, and no two controls on Settings share a name;
 *   U2  Undo in Sensitivity labels puts the label's level back in
 *       policy.yaml, read back through the arbiter; the model stays removed,
 *       the kind keeps its choice, the other two notices and their Undo are
 *       as they were, and the focus is on the card's heading;
 *   U3  Rules: a rule's menu gives a notice whose Undo is named "Undo the
 *       change in Your rules", described by "Now always blocked."; its Undo
 *       makes the rule allow again;
 *   U4  the oracle: neither the rendered pages nor the answers read here
 *       carry the registered key.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { PolicyPanelVM } from "../../dashboard/src/view-model/policy-panel.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { controlName, nameFaults } from "../../dashboard/test/unit/ui/control-names.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_" + "live_noticeUndoNamesStackCanary00000000001";
const CONF = "2b2b0000-0000-4000-8000-000000000003";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const rowBy = (doc: Doc, sel: string, key: string, value: string) => [...doc.querySelectorAll(sel)].find((r: Doc) => r.dataset[key] === value);
const labelRow = (doc: Doc, id: string) => rowBy(doc, "#settings-labels .label-row", "id", id);
const modelRow = (doc: Doc, name: string) => rowBy(doc, "#settings-models .model-row", "name", name);
const kindRow = (doc: Doc, cat: string) => rowBy(doc, "#settings-prompt-kinds .prompt-kind", "category", cat);
const undoIn = (doc: Doc, notice: string) => [...doc.querySelectorAll(`#${notice} button`)];
/** The words a button is described by, as a browser reads them. */
const description = (b: Doc) => (b.getAttribute("aria-describedby") ?? "").split(/\s+/).filter(Boolean)
  .map((id: string) => b.ownerDocument.getElementById(id)?.textContent ?? "").join(" ");
/** A pick in a menu, as the keyboard makes it. */
function pick(sel: Doc, value: string): void {
  sel.focus();
  sel.value = value;
  sel.dispatchEvent(new sel.ownerDocument.defaultView.Event("change", { bubbles: true }));
}

test("The product page over the real arbiter: each notice's Undo is named by its card and described by its notice; Undo in one card undoes its change alone; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-notice-undo-names-"));
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "models:",
    "  - { name: ollama, url: 'http://127.0.0.1:11434', wire: openai-chat, model: llama3.2, local: true, helper: true }",
    "  - { name: lab, url: 'https://lab.example/v1', wire: openai-chat, model: mistral, local: true }",
    "sensitivity_labels:",
    `  - { id: ${CONF}, name: Confidential, level: local-model }`,
    "prompt_filters:",
    "  actions:",
    "    pii.email: mask",
    "user_rules:",
    "  - { id: r-0001, kind: release, to: { host: api.example.com }, mode: allow }",
    "",
  ].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
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
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const read = async (path: string) => {
    const text = await (await pageFetch(base + path, { headers: CSRF_ADMIN })).text();
    bodies.push(text);
    return JSON.parse(text);
  };
  const level = async () => (await read("/api/policy/sensitivity-labels")).labels.mappings.find((m: { id: string }) => m.id === CONF)?.level;
  const pages: string[] = [];
  try {
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const ready = (doc: Doc) => doc.querySelectorAll("#settings-models .model-row").length === 2
      && !!labelRow(doc, CONF) && !!kindRow(doc, "pii.email");

    await servedProductPage(base, "/settings", ready, async (doc) => {
      doc.defaultView.confirm = () => true;
      // U1: three changes, one per card.
      modelRow(doc, "lab").querySelector(".model-remove-btn").click();
      await waitWhile(() => modelRow(doc, "lab") !== undefined);
      const label = labelRow(doc, CONF);
      label.querySelector("select.label-level").value = "no-model";
      label.querySelector(".label-save-btn").click();
      await waitWhile(() => labelRow(doc, CONF) === label);
      pick(kindRow(doc, "pii.email").querySelector("select"), "block");
      await waitWhile(() => doc.getElementById("prompt-notice").hidden);

      const cards = [
        { notice: "models-notice", name: "Undo the change in Models", words: /^Removed lab\./ },
        { notice: "labels-notice", name: "Undo the change in Sensitivity labels", words: /^Saved Confidential\./ },
        { notice: "prompt-notice", name: "Undo the change in Prompt filters", words: /It applies to your next message\.$/ },
      ];
      for (const card of cards) {
        const buttons = undoIn(doc, card.notice);
        assert.equal(buttons.length, 1, `${card.notice} has its Undo`);
        const [b] = buttons;
        assert.equal(b.textContent, "Undo", "a sighted reader still sees Undo");
        assert.equal(controlName(b), card.name);
        assert.match(description(b), card.words, "described by its notice's words");
        assert.equal(doc.getElementById(card.notice).textContent, description(b) + "Undo", "the whole notice, nothing more");
      }
      assert.deepEqual(nameFaults(doc.getElementById("page-settings")), { shared: [], unnamed: [] }, "no two controls on Settings share a name");
      assert.equal(await level(), "no-model", "the label was saved");
      assert.match(readFileSync(policyPath, "utf8"), /pii\.email: block/, "the kind's choice was saved");

      // U2: Undo in Sensitivity labels alone.
      const others = ["models-notice", "prompt-notice"].map((id) => [id, doc.getElementById(id).textContent, undoIn(doc, id)[0]] as const);
      const undo = undoIn(doc, "labels-notice")[0];
      undo.focus();
      undo.click();
      await waitWhile(() => doc.getElementById("labels-notice").textContent !== "Undone.");
      await waitWhile(() => labelRow(doc, CONF)?.querySelector("select.label-level")?.value !== "local-model");
      assert.equal(await level(), "local-model", "the label's level is back in policy.yaml, read through the arbiter");
      assert.deepEqual((await data.modelEndpoints()).map((m: { name: string }) => m.name), ["ollama"], "the model stays removed");
      assert.match(readFileSync(policyPath, "utf8"), /pii\.email: block/, "the kind keeps its choice");
      for (const [id, text, b] of others) {
        assert.equal(doc.getElementById(id).textContent, text, `${id} is as it was`);
        assert.equal(undoIn(doc, id)[0], b, `${id}'s Undo is the same button`);
      }
      assert.equal(undoIn(doc, "labels-notice").length, 0, "an undone notice has no button");
      assert.equal(doc.activeElement, doc.getElementById("settings-labels-title"), "the card's heading");
      assert.deepEqual(nameFaults(doc.getElementById("page-settings")), { shared: [], unnamed: [] });
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // U3: Rules.
    const kind = async () => ((await read("/api/policy/panel")).panel as PolicyPanelVM).yourRules?.find((r) => r.id === "r-0001")?.kind;
    const menu = (doc: Doc) => rowBy(doc, "#rules-list .row.rule", "rule", "r-0001")?.querySelector("select.effect-select");
    assert.equal(await kind(), "release-allow");
    await servedProductPage(base, "/rules", (doc) => !!menu(doc), async (doc) => {
      const old = menu(doc);
      pick(old, "flip");
      await waitWhile(() => menu(doc) === old);
      const [b] = undoIn(doc, "rules-notice");
      assert.equal(b.textContent, "Undo");
      assert.equal(controlName(b), "Undo the change in Your rules");
      assert.equal(description(b), "Now always blocked.");
      assert.equal(await kind(), "release-block", "the arbiter's panel has the rule blocking");
      b.focus();
      b.click();
      await waitWhile(() => doc.getElementById("rules-notice").textContent !== "Undone.");
      assert.equal(await kind(), "release-allow", "Undo made the rule allow again");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // U4: the oracle.
    for (const path of ["/api/policy/panel", "/api/policy/sensitivity-labels", "/api/policy/prompt-filters"]) await read(path);
    for (const text of [...pages, ...bodies]) assert.ok(!text.includes(KEY), "no page or answer carries the registered key");
  } finally {
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
