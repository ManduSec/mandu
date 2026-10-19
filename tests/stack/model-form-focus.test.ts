/**
 * model-form-focus.test — on the product page's Settings, the Models form
 * keeps the keyboard focus across the REAL components (dashboard.md §4.25
 * *The Models form keeps the focus*). Mandu-new.
 *
 * Until 2026-10-11 a headless Chromium left the focus on <body> after every
 * Cancel of the form, every Save that worked, and every refused Save, which
 * its error line did not describe; the token field was named with its hint.
 *
 * Here a real ArbiterServer (secrets) holds a policy.yaml with two models
 * (ollama, your own; lab, an outside model) and a registered key. A real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`)
 * serves the Settings page (its own index.html and home.js in jsdom):
 *
 *   F1  signed in, Edit on lab, then Cancel: the focus is on lab's Edit;
 *   F2  Edit on lab, a new model, Save (asked first): the focus is on lab's
 *       Edit, drawn again, and the arbiter's list has the new model;
 *   F3  Add a model with a bad address: the refusal gives the focus back to
 *       Save, described by the validator's words; the form stays open; a
 *       fixed address then saves, the focus on Add a model, and the arbiter
 *       lists the model;
 *   F4  the token field is named "Token variable name (optional)" and
 *       described by its hint;
 *   F5  signed out, a refused Save gives the focus back to Save, described
 *       by "Sign in first…", and policy.yaml is unchanged;
 *   F6  the oracle: neither the rendered pages nor the answers read here
 *       carry the registered key.
 *
 * jsdom keeps the focus of a button turned off, so `press` drops it to
 * <body> after the click, as Chromium does. Axes: secrets (stated).
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
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { controlName } from "../../dashboard/test/unit/ui/control-names.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_live_modelFormFocusStackCanary00000000001";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** Enter on Save: it has the focus, the click submits, and the browser
 *  drops the focus of the button the change turned off to <body>. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "Save goes off while the change is on its way");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
}
/** Enter on a button that only opens or closes the form. */
function enter(btn: Doc): void {
  btn.focus();
  btn.click();
}
const modelRow = (doc: Doc, name: string) => [...doc.querySelectorAll("#settings-models .model-row")].find((r: Doc) => r.dataset.name === name);
const editOf = (doc: Doc, name: string) => modelRow(doc, name)?.querySelector(".model-edit-btn");
const byId = (doc: Doc, id: string) => doc.getElementById(id);

test("Settings over the real arbiter: the Models form's Cancel and Save give the focus back to what opened it, a refusal gives it to Save described; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-model-form-focus-"));
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "models:",
    "  - { name: ollama, url: 'http://127.0.0.1:11434', wire: openai-chat, model: llama3.2, local: true }",
    "  - { name: lab, url: 'https://lab.example/v1', wire: openai-chat, model: mistral }",
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
  const pages: string[] = [];
  const endpoint = async (name: string) => (await data.modelEndpoints()).find((m: { name: string }) => m.name === name);
  try {
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const ready = (doc: Doc) => doc.querySelectorAll("#settings-models .model-row").length === 2;

    await servedProductPage(base, "/settings", ready, async (doc) => {
      doc.defaultView.confirm = () => true;
      // F1: Edit, then Cancel.
      enter(editOf(doc, "lab"));
      assert.equal(byId(doc, "model-form").hidden, false);
      assert.equal(byId(doc, "model-name").value, "lab");
      enter(byId(doc, "model-cancel"));
      assert.equal(byId(doc, "model-form").hidden, true);
      assert.equal(doc.activeElement, editOf(doc, "lab"), "lab's Edit, which opened the form");
      assert.equal(controlName(doc.activeElement), "Edit the model lab");

      // F2: Edit, then a Save that works (asked first).
      const old = editOf(doc, "lab");
      enter(old);
      byId(doc, "model-model").value = "mistral-large";
      press(byId(doc, "model-save"));
      await waitWhile(() => editOf(doc, "lab") === old);
      assert.match(byId(doc, "models-notice").textContent, /^Saved lab\./);
      assert.equal(doc.activeElement, editOf(doc, "lab"), "lab's Edit, drawn again");
      assert.equal((await endpoint("lab"))?.model, "mistral-large", "the arbiter's list has the new model");

      // F3: Add with a bad address, refused; then fixed.
      enter(byId(doc, "model-open"));
      byId(doc, "model-name").value = "zdr";
      byId(doc, "model-url").value = "ftp://zdr.example";
      const save = byId(doc, "model-save");
      press(save);
      await waitWhile(() => !byId(doc, "model-error").textContent);
      assert.match(byId(doc, "model-error").textContent, /^This model entry is not valid\./);
      assert.equal(byId(doc, "model-form").hidden, false, "the form stays open to fix");
      assert.equal(doc.activeElement, save, "Save, on again");
      assert.equal(save.getAttribute("aria-describedby"), "model-error", "described by the validator's words");
      byId(doc, "model-url").value = "https://zdr.example/v1";
      press(save);
      await waitWhile(() => modelRow(doc, "zdr") === undefined);
      assert.equal(byId(doc, "model-form").hidden, true);
      assert.equal(doc.activeElement, byId(doc, "model-open"), "Add a model, which opened the form");
      assert.equal((await endpoint("zdr"))?.url, "https://zdr.example/v1", "the arbiter lists the model added");

      // F4: the token field's name and description.
      const token = byId(doc, "model-token-env");
      assert.equal(controlName(token), "Token variable name (optional)");
      assert.match(byId(doc, token.getAttribute("aria-describedby")).textContent, /^An environment variable's name\./);
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // F5: signed out, a refusal.
    const before = readFileSync(policyPath, "utf8");
    await servedProductPage(base, "/settings", (doc) => editOf(doc, "lab") !== undefined, async (doc) => {
      doc.defaultView.confirm = () => true;
      enter(editOf(doc, "lab"));
      byId(doc, "model-model").value = "other";
      const save = byId(doc, "model-save");
      press(save);
      await waitWhile(() => !byId(doc, "model-error").textContent);
      assert.match(byId(doc, "model-error").textContent, /^Sign in first/);
      assert.equal(doc.activeElement, save, "Save, on again");
      assert.equal(save.disabled, false);
      assert.equal(save.getAttribute("aria-describedby"), "model-error");
      pages.push(doc.body.textContent ?? "");
    });
    assert.equal(readFileSync(policyPath, "utf8"), before, "nothing changed signed out");

    // F6: the oracle.
    for (const path of ["/api/policy/panel", "/api/home"]) await read(path);
    for (const text of [...pages, ...bodies]) assert.ok(!text.includes(KEY), "no page or answer carries the registered key");
  } finally {
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
