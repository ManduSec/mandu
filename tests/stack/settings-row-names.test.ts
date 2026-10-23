/**
 * settings-row-names.test — on the product page's Settings, each row's
 * button names its row, and a change made there keeps the keyboard focus,
 * across the REAL components (dashboard.md §4.25 *A Settings row's button
 * names its row; a change keeps the focus*). Mandu-new.
 *
 * Until 2026-10-11 a headless Chromium read 27 controls on Settings, 16 of
 * them sharing a name ("Remove" ×7, "Test connection" ×3, "Edit", "Save",
 * "Use the default" ×2), and every change there (a label's Save, a model's
 * Remove, Use the default, Test connection) left the focus on <body>.
 *
 * Here a real ArbiterServer (secrets) holds a policy.yaml with two models of
 * the person's own, two sensitivity label levels, a prompt filter choice and
 * three exceptions (two of one kind), and a registered key. A loopback model
 * server answers Test connection. A real DashboardServer over the production
 * adapter (`makeApprovalsArbiter`) serves the Settings page (its own
 * index.html and home.js in jsdom):
 *
 *   N1  signed in, every row's button is named by its row, its own words
 *       first, and no two controls share a name;
 *   N2  Save on a label, drawn again, keeps the focus on that label's Save,
 *       and policy.yaml has the new level;
 *   N3  Remove on one of two exceptions of a kind gives the focus to the
 *       card's heading, never to the other's Remove, and policy.yaml loses
 *       exactly that one;
 *   N4  Remove on a model (asked first) gives the focus to the Models
 *       heading, and the arbiter no longer lists it;
 *   N5  Test connection gives the focus back to the same button, the
 *       result under it;
 *   N6  signed out, a refused Remove gives the focus back to the button,
 *       described by "Sign in first…", and nothing changed;
 *   N7  the oracle: neither the rendered pages nor the answers read here
 *       carry the registered key.
 *
 * jsdom keeps the focus of a button turned off, so `press` drops it to
 * <body> after the click, as Chromium does. Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
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
import { controlName, nameFaults } from "../../dashboard/test/unit/ui/control-names.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_" + "live_settingsRowNamesStackCanary0000000001";
const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const CONF = "2b2b0000-0000-4000-8000-000000000003";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** Enter on a button: it has the focus, the click acts, and the browser
 *  drops the focus of the button the change turned off to <body>. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the change turns its button off while it is on its way");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
}
const rowBy = (doc: Doc, sel: string, key: string, value: string) => [...doc.querySelectorAll(sel)].find((r: Doc) => r.dataset[key] === value);
const labelRow = (doc: Doc, id: string) => rowBy(doc, "#settings-labels .label-row", "id", id);
const modelRow = (doc: Doc, name: string) => rowBy(doc, "#settings-models .model-row", "name", name);
const exceptionRow = (doc: Doc, match: string) => rowBy(doc, "#settings-prompt-exceptions .prompt-exception", "match", match);

test("Settings over the real arbiter: each row's button names its row; a Save, a Remove and Test connection keep the focus, a refusal gives it back described; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-settings-row-names-"));
  // A loopback model server: Test connection reads its model list.
  const modelServer = createServer((req, res) => {
    res.writeHead(req.url === "/v1/models" ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify({ data: [{ id: "llama3.2:latest" }] }));
  });
  await new Promise<void>((r) => modelServer.listen(0, "127.0.0.1", () => r()));
  const modelUrl = `http://127.0.0.1:${(modelServer.address() as { port: number }).port}`;
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "models:",
    `  - { name: ollama, url: '${modelUrl}', wire: openai-chat, model: llama3.2, local: true, helper: true }`,
    "  - { name: lab, url: 'https://lab.example/v1', wire: openai-chat, model: mistral, local: true }",
    "sensitivity_labels:",
    `  - { id: ${HC}, name: Highly Confidential, level: no-model }`,
    `  - { id: ${CONF}, name: Confidential, level: local-model }`,
    "prompt_filters:",
    "  actions:",
    "    pii.email: mask",
    "  exceptions:",
    "    - { category: pii.email, match: '*@example.com' }",
    "    - { category: pii.email, match: '*@corp.example' }",
    "    - { category: secret.shape, match: 'pk_test_*' }",
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
  try {
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const ready = (doc: Doc) => doc.querySelectorAll("#settings-models .model-row").length === 2
      && doc.querySelectorAll("#settings-labels .label-row").length === 2
      && doc.querySelectorAll("#settings-prompt-exceptions .prompt-exception").length === 3;

    await servedProductPage(base, "/settings", ready, async (doc) => {
      doc.defaultView.confirm = () => true;
      // N1: the names.
      const names = (sel: string) => [...doc.querySelectorAll(sel)].map((b: Doc) => controlName(b));
      assert.deepEqual(names("#settings-models .model-row button"), [
        "Test connection to ollama", "Edit the model ollama", "Remove the model ollama",
        "Test connection to lab", "Edit the model lab", "Remove the model lab",
      ]);
      assert.deepEqual(names("#settings-labels button"), [
        "Save the level for Highly Confidential", "Remove the level for Highly Confidential",
        "Save the level for Confidential", "Remove the level for Confidential",
      ]);
      assert.deepEqual(names("#settings-prompt-kinds button"), ["Use the default for an email address"]);
      assert.deepEqual(names("#settings-prompt-exceptions button"), [
        "Remove the exception for an email address matching *@example.com",
        "Remove the exception for an email address matching *@corp.example",
        "Remove the exception for something shaped like a key or password matching pk_test_*",
      ]);
      for (const b of doc.querySelectorAll("#page-settings .table button")) {
        assert.ok(controlName(b).startsWith(b.textContent), `"${controlName(b)}" starts with its words "${b.textContent}"`);
      }
      assert.deepEqual(nameFaults(doc.getElementById("page-settings")), { shared: [], unnamed: [] });

      // N2: a label's Save. The focus is given back in the same task as the
      // list's draw, so waiting for the draw is enough.
      const conf = labelRow(doc, CONF);
      conf.querySelector("select.label-level").value = "no-model";
      const save = conf.querySelector(".label-save-btn");
      press(save);
      await waitWhile(() => labelRow(doc, CONF) === conf);
      assert.match(doc.getElementById("labels-notice").textContent, /^Saved Confidential\./);
      assert.equal(doc.activeElement, labelRow(doc, CONF).querySelector(".label-save-btn"), "Save on the same label, drawn again");
      assert.notEqual(doc.activeElement, save);
      const mapped = (await read("/api/policy/sensitivity-labels")).labels.mappings.find((m: { id: string }) => m.id === CONF);
      assert.equal(mapped?.level, "no-model", "the new level is in policy.yaml, read back through the arbiter");

      // N3: one of two exceptions of a kind.
      press(exceptionRow(doc, "*@example.com").querySelector("button"));
      await waitWhile(() => exceptionRow(doc, "*@example.com") !== undefined);
      assert.equal(doc.activeElement, doc.getElementById("settings-prompt-title"), "the card's heading");
      assert.notEqual(doc.activeElement, exceptionRow(doc, "*@corp.example").querySelector("button"), "never the other exception's Remove");
      const yaml = readFileSync(policyPath, "utf8");
      assert.doesNotMatch(yaml, /\*@example\.com/, "that exception is gone from policy.yaml");
      assert.match(yaml, /\*@corp\.example/, "the other stays");

      // N4: a model, asked first.
      press(modelRow(doc, "lab").querySelector(".model-remove-btn"));
      await waitWhile(() => modelRow(doc, "lab") !== undefined);
      assert.equal(doc.activeElement, doc.getElementById("settings-models-title"), "the Models heading, not ollama's buttons");
      assert.deepEqual((await data.modelEndpoints()).map((m: { name: string }) => m.name), ["ollama"], "the arbiter no longer lists lab");

      // N5: Test connection.
      const testBtn = modelRow(doc, "ollama").querySelector(".model-test-btn");
      press(testBtn);
      await waitWhile(() => /Testing/.test(modelRow(doc, "ollama").querySelector(".model-test")?.textContent ?? "Testing"));
      assert.equal(doc.activeElement, testBtn, "the same button");
      assert.match(modelRow(doc, "ollama").querySelector(".model-test").textContent, /Connected to 127\.0\.0\.1/);
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // N6: signed out, a refusal.
    const before = readFileSync(policyPath, "utf8");
    await servedProductPage(base, "/settings", (doc) => modelRow(doc, "ollama") !== undefined, async (doc) => {
      doc.defaultView.confirm = () => true;
      const b = modelRow(doc, "ollama").querySelector(".model-remove-btn");
      press(b);
      await waitWhile(() => !modelRow(doc, "ollama").querySelector(".ask-error"));
      const words = modelRow(doc, "ollama").querySelector(".ask-error");
      assert.match(words.textContent, /^Sign in first/);
      assert.equal(doc.activeElement, b, "the button pressed, on again");
      assert.equal(b.disabled, false);
      assert.equal(b.getAttribute("aria-describedby"), words.id, "described by the refusal's words");
      pages.push(doc.body.textContent ?? "");
    });
    assert.equal(readFileSync(policyPath, "utf8"), before, "nothing changed signed out");

    // N7: the oracle.
    for (const path of ["/api/policy/panel", "/api/policy/sensitivity-labels", "/api/policy/prompt-filters"]) await read(path);
    for (const text of [...pages, ...bodies]) assert.ok(!text.includes(KEY), "no page or answer carries the registered key");
  } finally {
    await dashboard.close();
    data.close();
    await arbiter.close();
    await new Promise<void>((r) => modelServer.close(() => r()));
    rmSync(tmp, { recursive: true, force: true });
  }
});
