/**
 * home-js-models.test — plan 11/12, "Your own AI only" and the
 * declared models: the own-model choice in All files, Settings › Models (list,
 * add, edit, remove, test, the administrator's lock, unencrypted http), the
 * own-model rule warning, a proposal's warnings, and the agent page's main
 * model line.
 *
 * Split out of home-js.test.ts, which drove the PRODUCT page script
 * (public/js/home.js) in jsdom over a fetch stub (dashboard.md §4.25); the
 * shared harness and fixtures are in home-js-fixtures.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  HTML, JS, AGENT, load, tick, FILES_ROUTES, rowFor, tickRow, optionOf, pressed,
  opened, chooseTicked, treeRows,
} from "./home-js-fixtures.js";

// ── plan 11 D6: "Your own AI only" and the declared models ────────

const OLLAMA = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", wireWords: "OpenAI chat", model: "llama3.2", local: true, where: "Your own model", tokenEnv: null, placement: "host", placementWords: "On this computer", allowPlainHttp: false, notEncrypted: false };
const V_ZDR = "f".repeat(32);
const ZDR = { name: "zdr", url: "https://zdr.example", wire: "anthropic", wireWords: "Anthropic Messages", model: null, local: false, where: "Outside model", tokenEnv: "ZDR_KEY", version: V_ZDR };
const panelWith = (models: unknown) => ({ panel: { available: true, verdictsKnown: true, queue: [], yourRules: [], ...(models === undefined ? {} : { models }) } });
// The own-model choice in README's label menu, in Add a rule.
const ownChoice = (doc: any) => optionOf(rowFor(doc, /README/), "local-model");
async function pickReadme(doc: any) {
  doc.getElementById("rules-add").click();
  await tick();
}

test("plan 11: the own-model choice is enabled only when a local model is declared; otherwise disabled with the hint", async () => {
  for (const [models, on] of [[[OLLAMA, ZDR], true], [[ZDR], false], [[], false], [undefined, false], [null, false]] as const) {
    const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": panelWith(models), ...FILES_ROUTES } });
    await tick();
    await pickReadme(doc);
    assert.equal(ownChoice(doc).disabled, !on, `models=${JSON.stringify(models)}`);
    assert.equal(ownChoice(doc).textContent, on ? "Your own AI only" : "Your own AI only (none listed)", "the choice says why it is off");
    assert.equal((doc.querySelector('#files-selected .level-btn[data-level="local-model"]') ?? { disabled: !on }).disabled, !on);
  }
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": panelWith([ZDR]), ...FILES_ROUTES } });
  await tick();
  await pickReadme(doc);
  assert.equal(ownChoice(doc).textContent, "Your own AI only (none listed)");
  assert.match(ownChoice(doc).title, /^Your own AI only\. Only your own AI may read it, when it asks: one you or your organization run, on this computer or your organization's network/);
});

test("plan 11: an unreadable panel leaves the own-model choice off (the page never offers what it cannot confirm)", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": { status: 502, body: { error: "down" } }, ...FILES_ROUTES } });
  await tick();
  await pickReadme(doc);
  assert.equal(ownChoice(doc).disabled, true);
});

test("plan 11: picking the own-model choice queues local-model", async () => {
  const saves: any[] = [];
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": panelWith([OLLAMA]), ...FILES_ROUTES, "POST files/labels": (b: any) => (saves.push(b), { applied: true, changeId: null, page: 0 }) } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  tickRow(doc, /README/);
  chooseTicked(doc, "local-model");
  doc.getElementById("files-save").click();
  await tick();
  assert.equal(saves[0].changes[0].level, "local-model");
});

test("plan 11: a label made on this page at local-model reads in the page's term", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: {
    "GET secrets": { panel: { labels: [{ path: "/home/u/contracts", levelClass: "local-only", modelOk: false, scope: "subtree", pattern: false, bindings: [], source: "user" }] } },
  } });
  await tick();
  const row = doc.querySelector("#files-tree .row.file-rule");
  assert.match(row.textContent, /contracts/);
  assert.deepEqual(pressed(row), ["local-model"]);
  row.querySelector(".file-more").click();
  assert.match(opened(doc).textContent, /Your own AI only/);
});

test("plan 11: Settings lists the declared models, own vs outside, a key by its setting's name only, each with Test, Edit and Remove", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: { "GET policy/panel": panelWith([OLLAMA, { ...ZDR, token: "sk-SECRET" }]) } });
  await tick();
  const rows = [...doc.querySelectorAll("#settings-models .model-row")] as any[];
  assert.equal(rows.length, 2);
  assert.equal(rows[0].querySelector(".name").textContent, "ollama");
  assert.equal(rows[0].querySelector(".sub").textContent, "http://127.0.0.1:11434, OpenAI chat, model llama3.2");
  assert.equal(rows[0].querySelector(".model-where").textContent, "Your own model, on this computer");
  assert.equal(rows[1].querySelector(".sub").textContent, "https://zdr.example, Anthropic Messages, key from ZDR_KEY");
  assert.equal(rows[1].querySelector(".model-where").textContent, "Outside model");
  assert.doesNotMatch(doc.getElementById("settings-models").textContent, /sk-SECRET/);
  assert.deepEqual([...rows[0].querySelectorAll("button")].map((b: any) => b.textContent), ["Test connection", "Edit", "Remove"]);
  assert.match(doc.getElementById("settings-models").closest("section").querySelector("details.more .note").textContent, /Changes are saved to models: in policy\.yaml/);
});

test("plan 12 D5: an administrator's model says so and has no Edit; under the lock a note says what is allowed and the form cannot add your own model", async () => {
  const corp = { ...OLLAMA, name: "corp", url: "https://llm.corp.example/v1", placement: "network", placementWords: "On your organization's network (llm.corp.example)", admin: true, locked: true };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: {
    "GET policy/panel": { panel: { ...panelWith([corp, ZDR]).panel, modelsAdmin: { files: ["/etc/mandu/policy.d/10-corp.yaml"], locked: true } } },
  } });
  await tick();
  const rows = [...doc.querySelectorAll("#settings-models .model-row")] as any[];
  assert.equal(rows[0].querySelector(".model-admin").textContent, "Set by your administrator. You can remove it, not change it.");
  // The buttons keep the row's last column; the note spans the row below them (hand check 2026-09-28).
  const order = [...rows[0].children].map((c: any) => c.className);
  assert.ok(order.indexOf("model-actions") < order.indexOf("model-admin"), order.join(" "));
  assert.deepEqual([...rows[0].querySelectorAll("button")].map((b: any) => b.textContent), ["Test connection", "Remove"]);
  assert.deepEqual([...rows[1].querySelectorAll("button")].map((b: any) => b.textContent), ["Test connection", "Edit", "Remove"]);
  assert.equal(rows[1].querySelector(".model-admin"), null);
  assert.match(doc.querySelector("#settings-models .model-admin-lock").textContent, /^Your administrator has locked your own models\. You can remove one of theirs or add an outside model/);
  doc.getElementById("model-open").click();
  await tick();
  assert.equal(doc.getElementById("model-local").disabled, true);
  assert.equal(doc.getElementById("model-local").checked, false);
});

test("plan 12 D4/D5: Settings names the lines of policy.yaml the administrator's settings keep out of use, a refused re-read, the perimeter and who set it, and brings back a removed administrator's model", async () => {
  const { doc, window, calls } = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: {
    "GET policy/panel": { panel: {
      ...panelWith([ZDR]).panel,
      modelsAdmin: {
        files: ["/etc/mandu/policy.d/10-corp.yaml"], locked: true,
        conflicts: ["models[0]: 'mine' is local: true, and your own models are set by your administrator (/etc/mandu/policy.d/10-corp.yaml): you can add outside models only (local: true is refused)"],
        refused: ["/etc/mandu/policy.d/20-bad.yaml: 'paths' cannot be set here"],
        removed: [{ name: "corp", file: "/etc/mandu/policy.d/10-corp.yaml" }],
      },
      perimeter: { networks: ["10.0.0.0/8"], domains: ["corp.example"], by: "administrator" },
    } },
    "POST policy/models/change": { applied: true, changeId: "pc-9", note: "New sessions use this. Restart a running agent to use it there." },
  } });
  window.confirm = () => true;
  await tick();
  const host = doc.getElementById("settings-models");
  assert.match(host.querySelector(".model-admin-conflicts").textContent, /^Not in use, because your administrator's settings take priority\. Change policy\.yaml to match:.*'mine' is local: true/);
  assert.match(host.querySelector(".model-admin-refused").textContent, /could not be used, so the ones read before still apply: .*20-bad\.yaml/);
  assert.equal(host.querySelector(".model-perimeter").textContent, "Your own models on another computer are used only at addresses in 10.0.0.0/8 (set by your administrator).");
  const removed = host.querySelector(".model-removed");
  assert.equal(removed.querySelector(".name").textContent, "corp");
  assert.deepEqual([...removed.querySelectorAll("button")].map((b: any) => b.textContent), ["Bring back"]);
  removed.querySelector(".model-restore-btn").click();
  await tick();
  assert.deepEqual(calls.find((c) => c.url.endsWith("/api/policy/models/change"))!.body, { action: "restore", name: "corp" });
});

test("plan 11: Settings says when no model is listed, and when the list cannot be read", async () => {
  const none = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: { "GET policy/panel": panelWith([]) } });
  await tick();
  assert.match(none.doc.getElementById("settings-models").textContent, /^No models listed\. Until you add one of your own, no model reads files marked "Your own AI only"\./);
  // An error the dashboard server answered with says so, with its status
  // (until 2026-10-10: "The protection service may be unreachable.").
  const unknown = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: { "GET policy/panel": { status: 502, body: {} } } });
  await tick();
  assert.equal(unknown.doc.getElementById("settings-models").textContent, "The model list could not be read. The dashboard server answered with an error (502). Refresh in a moment.");
  assert.equal(unknown.doc.getElementById("model-open").hidden, true, "no Add while the list cannot be read");
  // A service that answered but sent no list (an older one): no reason given.
  const old = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: { "GET policy/panel": panelWith(undefined) } });
  await tick();
  assert.equal(old.doc.getElementById("settings-models").textContent, "The model list could not be read.");
  assert.equal(old.doc.getElementById("model-open").hidden, true);
});

// ── Settings › Models: add, edit, remove, test (dashboard.md §4.25l) ─────────

const CONFIRM = {
  applied: false, confirm: true, expected: ["models\u0000lab"],
  rows: [[{ kind: "text", text: "Add the model " }, { kind: "code", text: "lab" }, { kind: "text", text: " at " }, { kind: "code", text: "http://203.0.113.9:8000" }, { kind: "text", text: ", as your own model" }]],
  wouldLet: [[{ kind: "text", text: "The models Mandu knows would change for " }, { kind: "code", text: "lab" }]],
  warnings: [[{ kind: "code", text: "lab" }, { kind: "text", text: " would count as your own model, but it is far" }]],
};

function fillModelForm(doc: any, f: Record<string, string | boolean>): void {
  for (const [id, v] of Object.entries(f)) {
    const input = doc.getElementById(id);
    if (typeof v === "boolean") input.checked = v;
    else input.value = v;
  }
}

test("Settings › Models: Add posts the form's fields, asks with the server's rows and warning, then sends what was shown; the restart note and Undo follow", async () => {
  let posts = 0;
  const confirms: string[] = [];
  const { doc, window, calls } = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: {
    "GET policy/panel": panelWith([]),
  } });
  window.confirm = (msg: string) => { confirms.push(msg); return true; };
  const realFetch = window.fetch;
  window.fetch = (url: string, init: any = {}) => {
    if (url.endsWith("/api/policy/models/change")) {
      calls.push({ url, method: init.method, headers: init.headers, body: JSON.parse(init.body) });
      posts++;
      const body = posts === 1 ? CONFIRM : { applied: true, changeId: "pc-000009", note: "New sessions use this. Restart a running agent to use it there." };
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
    }
    return realFetch(url, init);
  };
  await tick();
  assert.equal(doc.getElementById("model-form").hidden, true);
  doc.getElementById("model-open").click();
  assert.equal(doc.getElementById("model-form").hidden, false);
  fillModelForm(doc, { "model-name": " lab ", "model-url": "http://203.0.113.9:8000", "model-wire": "openai-chat", "model-model": "qwen2.5", "model-local": true, "model-token-env": "LAB_TOKEN" });
  doc.getElementById("model-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick(20);
  const sent = calls.filter((c) => c.url.endsWith("/api/policy/models/change"));
  assert.equal(sent.length, 2);
  assert.equal(sent[0]!.headers["X-Mandu-Control"], "1", "CSRF header");
  assert.deepEqual(sent[0]!.body, { action: "add", model: { name: "lab", url: "http://203.0.113.9:8000", wire: "openai-chat", model: "qwen2.5", local: true, helper: false, allowPlainHttp: false, tokenEnv: "LAB_TOKEN" } });
  assert.deepEqual((sent[1]!.body as { expected: string[] }).expected, ["models\u0000lab"], "the second send carries exactly what the person was shown");
  assert.equal(confirms.length, 1);
  assert.match(confirms[0]!, /Add the model lab at http:\/\/203\.0\.113\.9:8000, as your own model/);
  assert.match(confirms[0]!, /Warning: lab would count as your own model/);
  assert.equal(doc.getElementById("model-form").hidden, true, "the form closes");
  const notice = doc.getElementById("models-notice");
  assert.match(notice.textContent, /Added lab\. New sessions use this\. Restart a running agent to use it there\./);
  assert.ok([...notice.querySelectorAll("button")].some((b: any) => b.textContent === "Undo"));
});

test("Settings › Models: Cancel at the question sends nothing more; a refusal shows the validator's lines in the form", async () => {
  const { doc, window, calls } = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: {
    "GET policy/panel": panelWith([]),
    "POST policy/models/change": { status: 422, body: { error: "This model entry is not valid.", problems: ["url: must be an http(s) URL with no credentials in it"] } },
  } });
  await tick();
  doc.getElementById("model-open").click();
  fillModelForm(doc, { "model-name": "x", "model-url": "ftp://x" });
  doc.getElementById("model-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick();
  assert.equal(doc.getElementById("model-error").textContent, "This model entry is not valid. url: must be an http(s) URL with no credentials in it");
  assert.equal(doc.getElementById("model-form").hidden, false, "the form stays open to fix");

  const second = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: { "GET policy/panel": panelWith([OLLAMA]), "POST policy/models/change": CONFIRM } });
  second.window.confirm = () => false;
  await tick();
  (second.doc.querySelector("#settings-models .model-remove-btn") as any).click();
  await tick();
  assert.equal(second.calls.filter((c) => c.url.endsWith("/api/policy/models/change")).length, 1, "no second send after Cancel");
  assert.deepEqual(second.calls.find((c) => c.url.endsWith("/api/policy/models/change"))!.body, { action: "remove", name: "ollama" });
  void calls;
});

test("Settings › Models: Edit fills the form from the row and sends an update naming the entry it started from", async () => {
  const { doc, window, calls } = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: {
    "GET policy/panel": panelWith([OLLAMA, ZDR]),
    "POST policy/models/change": { applied: true, changeId: "pc-1", note: "New sessions use this. Restart a running agent to use it there." },
  } });
  await tick();
  (doc.querySelectorAll("#settings-models .model-edit-btn")[1] as any).click();
  assert.equal((doc.getElementById("model-name") as any).value, "zdr");
  assert.equal((doc.getElementById("model-url") as any).value, "https://zdr.example");
  assert.equal((doc.getElementById("model-wire") as any).value, "anthropic");
  assert.equal((doc.getElementById("model-local") as any).checked, false);
  assert.equal((doc.getElementById("model-token-env") as any).value, "ZDR_KEY");
  assert.equal(doc.getElementById("model-save").textContent, "Save changes");
  fillModelForm(doc, { "model-name": "zdr2" });
  doc.getElementById("model-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick();
  const sent = calls.find((c) => c.url.endsWith("/api/policy/models/change"))!;
  assert.deepEqual(sent.body, { action: "update", name: "zdr", model: { name: "zdr2", url: "https://zdr.example", wire: "anthropic", model: "", local: false, helper: false, allowPlainHttp: false, tokenEnv: "ZDR_KEY" }, version: V_ZDR },
    "the update names the version of the entry the form was filled from");
  assert.match(doc.getElementById("models-notice").textContent, /^Saved zdr2\. New sessions use this/);
});

test("Settings › Models: a save refused because the model changed meanwhile says so, keeps what was typed, reads the list again and saves against the model as it is now", async () => {
  const V2 = "0".repeat(32);
  let panelReads = 0;
  const saves: any[] = [];
  const words = "zdr was changed somewhere else while you were editing it, so nothing was saved. What you typed is still in the form: compare it with zdr as it is now, then save again.";
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: {
    // The second read finds the entry changed by someone else (a new address, a new version).
    "GET policy/panel": () => (++panelReads === 1 ? panelWith([OLLAMA, ZDR]) : panelWith([OLLAMA, { ...ZDR, url: "https://zdr2.example", version: V2 }])),
    "POST policy/models/change": (b: any) => {
      saves.push(b);
      return saves.length === 1
        ? { status: 409, body: { error: words, stale: true, changed: ["models zdr"] } }
        : { applied: true, changeId: "pc-3", note: "New sessions use this. Restart a running agent to use it there." };
    },
  } });
  await tick();
  (doc.querySelectorAll("#settings-models .model-edit-btn")[1] as any).click();
  fillModelForm(doc, { "model-model": "zdr-large" });
  doc.getElementById("model-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick();
  assert.equal(saves[0].version, V_ZDR);
  assert.equal(doc.getElementById("model-error").textContent, words, "said plainly, in the page's words");
  assert.equal(doc.getElementById("model-form").hidden, false, "the form stays open");
  assert.equal((doc.getElementById("model-model") as any).value, "zdr-large", "what was typed is kept");
  assert.equal((doc.getElementById("model-url") as any).value, "https://zdr.example", "the form is not refilled over what the person typed");
  assert.equal(panelReads, 2, "the list is read again");
  assert.equal(doc.querySelectorAll("#settings-models .model-row")[1]!.querySelector(".sub")!.textContent, "https://zdr2.example, Anthropic Messages, key from ZDR_KEY", "the row shows the model as it is now");
  assert.equal(doc.getElementById("models-notice").hidden, true, "nothing reads as saved");

  doc.getElementById("model-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick();
  assert.equal(saves[1].version, V2, "the next save names the model as it is now");
  assert.equal(doc.getElementById("model-form").hidden, true);
});

test("Settings › Models: a model removed while its form was open says so after a stale refusal", async () => {
  let panelReads = 0;
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: {
    "GET policy/panel": () => (++panelReads === 1 ? panelWith([OLLAMA, ZDR]) : panelWith([OLLAMA])),
    "POST policy/models/change": { status: 409, body: { error: "zdr was changed somewhere else while you were editing it, so nothing was saved.", stale: true, changed: ["models zdr"] } },
  } });
  await tick();
  (doc.querySelectorAll("#settings-models .model-edit-btn")[1] as any).click();
  doc.getElementById("model-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick();
  assert.equal(doc.getElementById("model-error").textContent, "Nothing was saved: zdr is no longer in your list.");
});

test("Settings › Models: the helper choice is offered for your own model only, names the reading row, and is sent with the form", async () => {
  const LAB = { ...OLLAMA, name: "lab", url: "https://10.0.0.5:8443", helperMarked: true, helper: true, placement: "network", placementWords: "On your network (10.0.0.5)" };
  const { doc, window, calls } = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: {
    "GET policy/panel": panelWith([{ ...OLLAMA, helperMarked: false, helper: false }, LAB, ZDR]),
    "POST policy/models/change": { applied: true, changeId: "pc-2", note: "New sessions use this. Restart a running agent to use it there." },
  } });
  await tick();
  const where = [...doc.querySelectorAll("#settings-models .model-where")].map((n: any) => n.textContent);
  assert.deepEqual(where, ["Your own model, on this computer", "Your own model, on your network (10.0.0.5), reads your own-model files", "Outside model"]);

  const box = doc.getElementById("model-helper") as any;
  (doc.querySelectorAll("#settings-models .model-edit-btn")[2] as any).click();
  assert.equal(box.disabled, true, "an outside model cannot read your own-model files");
  assert.equal(box.checked, false);
  (doc.querySelectorAll("#settings-models .model-edit-btn")[1] as any).click();
  assert.equal(box.disabled, false);
  assert.equal(box.checked, true, "the row's own mark, as written");
  const local = doc.getElementById("model-local") as any;
  local.checked = false;
  local.dispatchEvent(new window.Event("change"));
  assert.equal(box.disabled, true);
  assert.equal(box.checked, false, "unticking 'my own model' clears the choice");

  (doc.querySelectorAll("#settings-models .model-edit-btn")[0] as any).click();
  assert.equal(box.checked, false);
  box.checked = true;
  doc.getElementById("model-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick();
  const sent = calls.find((c) => c.url.endsWith("/api/policy/models/change"))!;
  assert.equal((sent.body as { model: { helper: boolean } }).model.helper, true);
});

test("plan 12 D2: 'Send without encryption' is offered only for your own model at an http address, fills from the row, and is sent; the row says Not encrypted", async () => {
  const LAB = { ...OLLAMA, name: "lab", url: "http://10.0.3.7:8000", placement: "network", placementWords: "On your network (10.0.3.7)", allowPlainHttp: true, notEncrypted: true };
  const CORP = { ...OLLAMA, name: "corp", url: "https://llm.corp.example/v1", placement: "network", placementWords: "On your network (llm.corp.example)" };
  const { doc, window, calls } = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: {
    "GET policy/panel": panelWith([LAB, CORP, ZDR]),
    "POST policy/models/change": { applied: true, changeId: "pc-3", note: "New sessions use this. Restart a running agent to use it there." },
  } });
  await tick();
  const rows = [...doc.querySelectorAll("#settings-models .model-row")] as any[];
  assert.match(rows[0].querySelector(".model-plain-http").textContent, /^Not encrypted: files marked "Your own AI only" cross the network in the clear/);
  assert.equal(rows[1].querySelector(".model-plain-http"), null, "an https model is not flagged");
  assert.equal(rows[1].querySelector(".model-where").textContent, "Your own model, on your network (llm.corp.example)");
  const plain = doc.getElementById("model-plain-http") as any;
  (doc.querySelectorAll("#settings-models .model-edit-btn")[1] as any).click();
  assert.equal(plain.disabled, true, "an https address: nothing to allow");
  (doc.querySelectorAll("#settings-models .model-edit-btn")[2] as any).click();
  assert.equal(plain.disabled, true, "an outside model: never");
  (doc.querySelectorAll("#settings-models .model-edit-btn")[0] as any).click();
  assert.equal(plain.disabled, false);
  assert.equal(plain.checked, true, "the row's opt-out, as written");
  doc.getElementById("model-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick();
  const sent = calls.find((c) => c.url.endsWith("/api/policy/models/change"))!;
  assert.equal((sent.body as { model: { allowPlainHttp: boolean } }).model.allowPlainHttp, true, "kept on an edit");
  // Typing an https address clears and disables it.
  (doc.querySelectorAll("#settings-models .model-edit-btn")[0] as any).click();
  const url = doc.getElementById("model-url") as any;
  url.value = "https://10.0.3.7:8443";
  url.dispatchEvent(new window.Event("input"));
  assert.equal(plain.disabled, true);
  assert.equal(plain.checked, false);
});

test("plan 12 D6: the product copy no longer says 'you run yourself' or 'computer you control'", () => {
  const html = HTML + JS;
  assert.doesNotMatch(html, /you run yourself/i);
  assert.doesNotMatch(html, /computer you control/i);
});

test("Settings › Models: Test connection posts the name only and shows the server's lines as text", async () => {
  const { doc, calls } = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: {
    "GET policy/panel": panelWith([OLLAMA]),
    "POST policy/models/test": { result: { name: "ollama", ok: false, lines: [{ tone: "ok", text: "Connected to 127.0.0.1:11434." }, { tone: "bad", text: "<b>llama3.2</b> is not in the server's model list." }] } },
  } });
  await tick();
  (doc.querySelector("#settings-models .model-test-btn") as any).click();
  await tick();
  const sent = calls.find((c) => c.url.endsWith("/api/policy/models/test"))!;
  assert.deepEqual(sent.body, { name: "ollama" });
  assert.equal(sent.headers["X-Mandu-Control"], "1");
  const lines = [...doc.querySelectorAll("#settings-models .model-test li")] as any[];
  assert.deepEqual(lines.map((l) => [l.className, l.textContent]), [["ok", "Connected to 127.0.0.1:11434."], ["bad", "<b>llama3.2</b> is not in the server's model list."]]);
  assert.equal(doc.querySelector("#settings-models .model-test b"), null, "server text is never markup");
});

test("Rules: a your-own-model rule warns when no model of your own is listed (a rules-file row, and a label made on the page)", async () => {
  const rule = { id: "lock:/home/u/contracts", kind: "lock", subject: "/home/u/contracts", level: "local-model", bindings: [], plain: { subject: "/home/u/contracts", reach: "and everything inside", effect: "Your own AI only" }, actions: { remove: true, flip: null }, warning: "No AI of your own is listed, so no AI reads this file. Add one in Settings › Models." };
  const label = { path: "/home/u/memo", levelClass: "local-only", modelOk: false, scope: "exact", pattern: false, bindings: [], source: "user" };
  const warnings = (doc: any) => treeRows(doc).map((_, i) => {
    const r = treeRows(doc)[i];
    // Marked on the row itself, and said in full when it is opened.
    const mark = r.querySelector(".file-warn-mark");
    r.click();
    const w = doc.querySelector("#files-tree .file-detail .rule-warn");
    if (w) assert.equal(mark && mark.getAttribute("aria-label"), w.textContent);
    return w ? w.textContent : null;
  });
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: {
    "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [rule], models: [] } },
    "GET secrets": { panel: { labels: [label] } },
  } });
  await tick();
  assert.deepEqual(warnings(doc), [rule.warning, rule.warning]);
  const own = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: {
    "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [{ ...rule, warning: undefined }], models: [OLLAMA] } },
    "GET secrets": { panel: { labels: [label] } },
  } });
  await tick();
  assert.deepEqual(warnings(own.doc), [null, null], "with a model of your own listed, no warning");
});

test("Approvals: a proposal's warnings show before the agent's words, and the typed confirmation says why", async () => {
  const card = {
    id: "pp-000007", status: "pending", requester: "Your agent",
    rows: CONFIRM.rows, wouldLet: CONFIRM.wouldLet, capped: false, overBroad: true, warnings: CONFIRM.warnings,
    reason: "use my model", createdAt: Date.now() - 1000,
  };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { "GET policy/proposals?status=pending": { proposals: [card] } } });
  await tick();
  const el = doc.querySelector("#approvals-proposals .proposal");
  const warn = el.querySelector(".proposal-warn");
  assert.equal(warn.textContent, "Warning: lab would count as your own model, but it is far");
  const order = [...el.children].map((c: any) => c.className);
  assert.ok(order.indexOf("proposal-warn") < order.indexOf("agent-says"), "the warning comes before the agent's words");
  assert.match(el.textContent, /Read the warning above before you allow this\./);
  assert.equal((el.querySelector("button") as any).disabled, true, "Allow waits for the typed ALLOW");
});

test("the agent page names the main model when the session is bound to a declared one", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": { ...AGENT, mainModel: { words: "Main model: your own model (ollama)", local: true } } } });
  await tick();
  const line = doc.querySelector("#agent-sub .agent-main-model");
  assert.equal(line.textContent, "Main model: your own model (ollama)");
  assert.equal(line.getAttribute("data-local"), "true");
  const plain = load({ url: "http://127.0.0.1:4500/mandu/agents/s1" });
  await tick();
  assert.equal(plain.doc.querySelector("#agent-sub .agent-main-model"), null, "no binding, no line");
});
