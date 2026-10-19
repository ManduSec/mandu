/**
 * model-form-escape.test — on the product page's Settings, Escape closes
 * the Models form as Cancel does, across the REAL components (dashboard.md
 * §4.25 *The Models form keeps the focus*, *Escape closes it*). Mandu-new.
 *
 * Until 2026-10-11 only Cancel closed the form; Escape did nothing in it.
 *
 * Here a real ArbiterServer (secrets) holds a policy.yaml with two models
 * (ollama, your own; lab, an outside model) and a registered key. A real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`)
 * serves the Settings page (its own index.html and home.js in jsdom),
 * signed in:
 *
 *   X1  Edit on lab, a new address typed, Escape in the field: the form
 *       closes with the focus on lab's Edit; policy.yaml and the arbiter's
 *       list are unchanged;
 *   X2  Add a model, a name and address typed, Escape on a tick box: the
 *       focus is on Add a model, the form opens again empty, and the
 *       arbiter lists no such model;
 *   X3  an open note in the form takes the first Escape alone;
 *   X4  Enter in a field sends a change, and an Escape while it is on its
 *       way closes nothing: the change lands (the arbiter lists the new
 *       model) and the focus goes to lab's Edit, drawn again;
 *   X5  the oracle: neither the rendered page nor the answers read here
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
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { controlName } from "../../dashboard/test/unit/ui/control-names.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_live_modelFormEscapeStackCanary0000000001";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** Enter on a button that opens or closes something. */
function enter(btn: Doc): void {
  btn.focus();
  btn.click();
}
/** Escape where the focus is, as a browser sends it. */
function escape(doc: Doc): Doc {
  const ev = new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
  doc.activeElement.dispatchEvent(ev);
  return ev;
}
const modelRow = (doc: Doc, name: string) => [...doc.querySelectorAll("#settings-models .model-row")].find((r: Doc) => r.dataset.name === name);
const editOf = (doc: Doc, name: string) => modelRow(doc, name)?.querySelector(".model-edit-btn");
const byId = (doc: Doc, id: string) => doc.getElementById(id);
const formOpen = (doc: Doc) => !byId(doc, "model-form").hidden;

test("Settings over the real arbiter: Escape closes the Models form as Cancel does, with the focus back on what opened it and nothing saved; not while a Save is on its way; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-model-form-escape-"));
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
    const before = readFileSync(policyPath, "utf8");

    await servedProductPage(base, "/settings", ready, async (doc) => {
      doc.defaultView.confirm = () => true;
      // X1: Edit lab, a new address, Escape in the field.
      enter(editOf(doc, "lab"));
      assert.ok(formOpen(doc));
      byId(doc, "model-url").value = "https://other.example/v1";
      byId(doc, "model-url").focus();
      assert.equal(escape(doc).defaultPrevented, true, "the form takes the Escape");
      assert.equal(formOpen(doc), false, "Escape closes the form");
      assert.equal(doc.activeElement, editOf(doc, "lab"), "lab's Edit, which opened it");
      assert.equal(controlName(doc.activeElement), "Edit the model lab");

      // X2: Add a model, typed, Escape on a tick box.
      enter(byId(doc, "model-open"));
      byId(doc, "model-name").value = "zdr";
      byId(doc, "model-url").value = "https://zdr.example/v1";
      byId(doc, "model-local").focus();
      escape(doc);
      assert.equal(formOpen(doc), false);
      assert.equal(doc.activeElement, byId(doc, "model-open"), "Add a model, which opened it");
      assert.equal(byId(doc, "model-open").getAttribute("aria-expanded"), "false");
      enter(byId(doc, "model-open"));
      assert.equal(byId(doc, "model-name").value, "", "the form opens again empty");

      // X3: an open note takes the first Escape alone.
      const help = byId(doc, "model-form").querySelector(".help-btn");
      enter(help);
      assert.equal(help.getAttribute("aria-expanded"), "true");
      escape(doc);
      assert.equal(help.getAttribute("aria-expanded"), "false", "the note closes");
      assert.ok(formOpen(doc), "the form stays open");
      escape(doc);
      assert.equal(formOpen(doc), false, "the next Escape closes the form");
      assert.equal(doc.activeElement, byId(doc, "model-open"));

      assert.equal(readFileSync(policyPath, "utf8"), before, "nothing was saved: policy.yaml is unchanged");
      assert.equal((await endpoint("lab"))?.url, "https://lab.example/v1", "the arbiter's lab is unchanged");
      assert.equal(await endpoint("zdr"), undefined, "the arbiter lists no model the Escape dropped");

      // X4: Enter in a field sends the change; Escape while it is on its way.
      const old = editOf(doc, "lab");
      enter(old);
      const field = byId(doc, "model-model");
      field.value = "mistral-large";
      field.focus();
      byId(doc, "model-form").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
      assert.equal(byId(doc, "model-save").disabled, true, "the change is on its way");
      assert.equal(escape(doc).defaultPrevented, false, "not taken");
      assert.ok(formOpen(doc), "the form stays open: the change cannot be called back");
      await waitWhile(() => editOf(doc, "lab") === old);
      assert.equal(formOpen(doc), false, "the answer closes it");
      assert.match(byId(doc, "models-notice").textContent, /^Saved lab\./);
      assert.equal(doc.activeElement, editOf(doc, "lab"), "lab's Edit, drawn again");
      assert.equal((await endpoint("lab"))?.model, "mistral-large", "the change landed");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // X5: the oracle.
    for (const path of ["/api/policy/panel", "/api/home"]) await read(path);
    for (const text of [...pages, ...bodies]) assert.ok(!text.includes(KEY), "no page or answer carries the registered key");
  } finally {
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
