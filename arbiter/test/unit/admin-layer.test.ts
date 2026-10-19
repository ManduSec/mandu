/**
 * admin-layer.test — the administrator's `models:` / `perimeter:` layer
 * (confidentiality plan 12 D5, admin-layer.ts): reading /etc/mandu/policy.d
 * (here a temp directory), the merge under the user's policy.yaml, the lock
 * (`models_locked: true`) as every writer meets it (validatePolicyDocument,
 * the edit grammar), what compiles, and the arbiter serving it.
 *
 * With no layer, today's behaviour is unchanged: the same document validates
 * and compiles to the same entries, with no administrator fields.
 *
 * The administrator wins a conflict with a user file written before the layer
 * changed: the user's side is not in force, the arbiter names it, a start is
 * never refused over it, and a write is refused only for a conflict it adds.
 */
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AdminLayerError, adminLockProblems, effectiveModels, NO_ADMIN_LAYER, setAdminLayer, type AdminLayer,
} from "../../policy/admin-layer.js";
import { installAdminLayer, layerProblems, loadPolicyFileStrict, validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { compilePolicy } from "../../policy/compiled-policy.js";
import { applyEdits } from "../../policy/policy-edit.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // local-model is a confidentiality level; the layer reads no axis

const dirs: string[] = [];
/** The law in force's version: a whole-document apply names it. */
const lawOf = async (c: ArbiterClient): Promise<string> => (await c.policyDocument()).lawHash!;
function layerDir(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "mandu-policy-d-"));
  dirs.push(d);
  for (const [n, text] of Object.entries(files)) writeFileSync(join(d, n), text);
  return d;
}
afterEach(() => { setAdminLayer(NO_ADMIN_LAYER); });
process.on("exit", () => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const CORP = `models:
  - name: corp
    url: https://llm.corp.example/v1
    wire: openai-chat
    model: qwen
    local: true
    helper: true
perimeter:
  networks: [ 10.0.0.0/8 ]
  domains: [ corp.example ]
`;
const LOCKED = CORP + "models_locked: true\n";

test("reading the layer: a missing directory is no layer; files in name order; every problem named with its file; a bad layer refuses", () => {
  assert.equal(installAdminLayer(join(tmpdir(), "mandu-no-such-policy-d")).files.length, 0);
  const d = layerDir({ "20-gw.yaml": "models:\n  - name: gw\n    url: https://gw.corp.example\n", "10-corp.yaml": LOCKED, "notes.txt": "ignored" });
  const l = installAdminLayer(d);
  assert.deepEqual(l.files.map((f) => f.slice(d.length + 1)), ["10-corp.yaml", "20-gw.yaml"]);
  assert.deepEqual(l.models.map((m) => [m.entry.name, m.file.slice(d.length + 1)]), [["corp", "10-corp.yaml"], ["gw", "20-gw.yaml"]]);
  assert.equal(l.locked, true);
  assert.deepEqual(l.perimeter, { networks: ["10.0.0.0/8"], domains: ["corp.example"] });

  const bad = layerDir({
    "a.yaml": "paths:\n  - path: /x\n    level: public\nmodels:\n  - name: lab\n    url: http://10.0.3.7:8000\n    local: true\n",
    "b.yaml": "models:\n  - name: lab\n    url: https://lab.example\n  - name: off\n    disabled: true\nperimeter:\n  networks: [ 10.0.0.0/33 ]\n",
    "c.yaml": "perimeter:\n  domains: [ corp.example ]\nmodels_locked: yes-please\n",
    "d.yaml": "models: [ {",
  });
  assert.throws(() => installAdminLayer(bad), (e: unknown) => {
    assert.ok(e instanceof AdminLayerError);
    const all = e.problems.join("\n");
    assert.match(all, /a\.yaml: 'paths' cannot be set here/);
    assert.match(all, /a\.yaml: .*'lab' is on another machine and would receive local-model files in the clear/);
    assert.match(all, /b\.yaml: models: 'lab' is already set in .*a\.yaml/);
    assert.match(all, /b\.yaml: models: 'off': disabled is for the user's file/);
    assert.match(all, /b\.yaml: perimeter\.networks\[0\]: not a network/);
    assert.match(all, /c\.yaml: perimeter is already set in .*b\.yaml/);
    assert.match(all, /c\.yaml: models_locked must be true or false/);
    assert.match(all, /d\.yaml: /);
    return true;
  });
});

test("bwrap_path (rootless-confinement-ubuntu-2404.md §0.7): an administrator may set it; a value src/bwrap-path.ts would read differently refuses the layer", () => {
  // Accepted: plain, quoted, commented. The arbiter itself does not use it.
  for (const v of ["/opt/bubblewrap/bin/bwrap", '"/opt/bubblewrap/bin/bwrap"', "/opt/bubblewrap/bin/bwrap   # 0.12.0"]) {
    const l = installAdminLayer(layerDir({ "10-corp.yaml": `${LOCKED}bwrap_path: ${v}\n` }));
    assert.equal(l.files.length, 1, v);
  }
  // Refused, naming the file: a relative path, a block scalar (the line
  // reader would not see it), a `..`, a non-string.
  for (const bad of ["bwrap_path: bwrap\n", "bwrap_path: >-\n  /opt/bubblewrap/bin/bwrap\n", "bwrap_path: /opt/../tmp/bwrap\n", "bwrap_path: 12\n"]) {
    assert.throws(() => installAdminLayer(layerDir({ "10-corp.yaml": bad })), (e: unknown) => {
      assert.ok(e instanceof AdminLayerError);
      assert.match(e.problems.join("\n"), /10-corp\.yaml: bwrap_path must be one absolute path on its own line/, bad);
      return true;
    });
  }
});

const load = (files: Record<string, string>): AdminLayer => installAdminLayer(layerDir(files));

test("no layer: today's behaviour: a document validates and compiles the same, no administrator fields; disabled refers to nothing", () => {
  const doc: PolicyFileConfig = { models: [{ name: "ollama", url: "http://127.0.0.1:11434", local: true }] };
  assert.deepEqual(validatePolicyDocument(doc), []);
  const c = compilePolicy({ specId: "claude-code", document: doc });
  assert.deepEqual(c.models, [{ name: "ollama", url: "http://127.0.0.1:11434", wire: "anthropic", local: true }]);
  assert.equal(c.admin, null);
  assert.match(validatePolicyDocument({ models: [{ name: "corp", disabled: true }] } as unknown as PolicyFileConfig).join("\n"), /'corp' is not set by your administrator, so disabled: true turns nothing off/);
  assert.match(validatePolicyDocument({ models_locked: true } as unknown as PolicyFileConfig).join("\n"), /only your administrator's files \(\/etc\/mandu\/policy\.d\) can lock the models/);
});

test("unlocked: the administrator's entries come first with their file; the user may change or remove them and add their own", () => {
  const l = load({ "10-corp.yaml": CORP });
  const doc: PolicyFileConfig = { models: [{ name: "corp", url: "https://other.corp.example/v1", local: true }, { name: "mine", url: "http://127.0.0.1:11434", local: true }] };
  assert.deepEqual(adminLockProblems(doc, l), []);
  assert.deepEqual(validatePolicyDocument(doc), []);
  const eff = effectiveModels(doc, l);
  assert.deepEqual(eff.models.map((m) => [m.name, m.url, m.adminFile !== undefined]), [["corp", "https://other.corp.example/v1", false], ["mine", "http://127.0.0.1:11434", false]]);
  assert.deepEqual(effectiveModels({ models: [{ name: "corp", disabled: true }] } as unknown as PolicyFileConfig, l).models, []);
  const c = compilePolicy({ specId: "claude-code", document: null });
  assert.deepEqual(c.models.map((m) => [m.name, m.adminFile?.endsWith("10-corp.yaml"), m.locked ?? false, m.perimeter]), [["corp", true, false, ["10.0.0.0/8"]]]);
  assert.equal(c.admin?.locked, false);
});

test("locked: remove and add an outside model pass; add local, or change url / tls / local / helper / allow_plain_http, is refused naming the file", () => {
  const l = load({ "10-corp.yaml": LOCKED });
  const file = l.files[0]!;
  const pass = (doc: PolicyFileConfig): void => assert.deepEqual(validatePolicyDocument(doc), [], JSON.stringify(doc));
  const refused = (doc: PolicyFileConfig, re: RegExp): void => assert.match(validatePolicyDocument(doc).join("\n"), re, JSON.stringify(doc));
  pass({ models: [{ name: "corp", disabled: true }] } as unknown as PolicyFileConfig);
  pass({ models: [{ name: "gw", url: "https://api.example.com" }] });
  pass({ models: [{ name: "corp", url: "https://llm.corp.example/v1", wire: "openai-chat", model: "qwen3", local: true, helper: true }] }); // the model name is not locked
  const setBy = new RegExp(`set by your administrator \\(${file.replace(/[.]/g, "\\.")}\\)`);
  refused({ models: [{ name: "mine", url: "http://127.0.0.1:11434", local: true }] }, /you can add outside models only \(local: true is refused\)/);
  refused({ models: [{ name: "mine", url: "http://127.0.0.1:11434", local: true }] }, setBy);
  refused({ models: [{ name: "corp", url: "https://evil.example/v1", wire: "openai-chat", model: "qwen", local: true, helper: true }] }, /'corp' is set by your administrator .*, and its url cannot be changed here; you can remove it \(disabled: true\)/);
  refused({ models: [{ name: "corp", url: "https://llm.corp.example/v1", local: false, helper: false }] }, /its local, helper cannot be changed/);
  refused({ models: [{ name: "corp", url: "https://llm.corp.example/v1", local: true, helper: true, tls: { pin_sha256: [Buffer.alloc(32, 1).toString("base64")] } }] }, /its tls cannot be changed/);
  // The perimeter: narrowing passes, widening is refused.
  pass({ perimeter: { networks: ["10.1.0.0/16"] } });
  refused({ perimeter: { networks: ["10.0.0.0/8", "192.168.0.0/16"] } }, /perimeter\.networks: set by your administrator .* as 10\.0\.0\.0\/8; you can narrow it here, not widen it/);
  // The effective perimeter under the lock: the user's narrower networks, both domain lists.
  const eff = effectiveModels({ perimeter: { networks: ["10.1.0.0/16"], domains: ["lab.example"] } }, l);
  assert.deepEqual(eff.perimeter, { networks: ["10.1.0.0/16"], domains: ["corp.example", "lab.example"] });
  const c = compilePolicy({ specId: "claude-code", document: { models: [{ name: "gw", url: "https://api.example.com" }] } });
  assert.deepEqual(c.models.map((m) => [m.name, m.locked ?? false]), [["corp", true], ["gw", false]]);
});

test("the edit grammar under the layer: remove-model writes the marker; add-model of an administrator's name is refused; update-model is judged by the lock", () => {
  const l = load({ "10-corp.yaml": LOCKED });
  const r = applyEdits(null, [{ op: "remove-model", name: "corp" }]);
  assert.equal(r.ok, true, r.ok ? "" : r.problems.join("; "));
  if (r.ok) assert.deepEqual(r.document.models, [{ name: "corp", disabled: true }]);
  if (r.ok) {
    const again = applyEdits(r.document, [{ op: "remove-model", name: "corp" }]);
    assert.equal(again.ok, false);
    if (!again.ok) assert.match(again.problems.join("\n"), /already removed/);
  }
  const add = applyEdits(null, [{ op: "add-model", name: "corp", url: "https://llm.corp.example/v1", local: true }]);
  assert.equal(add.ok, false);
  if (!add.ok) assert.match(add.problems.join("\n"), new RegExp(`set by your administrator \\(${l.files[0]!.replace(/[.]/g, "\\.")}\\); change it with update-model`));
  const upd = applyEdits(null, [{ op: "update-model", name: "corp", url: "https://evil.example/v1", wire: "openai-chat", model: "qwen", local: true, helper: true }]);
  assert.equal(upd.ok, false);
  if (!upd.ok) assert.match(upd.problems.join("\n"), /'corp' is set by your administrator .*its url cannot be changed here/);
  const local = applyEdits(null, [{ op: "add-model", name: "mine", url: "http://127.0.0.1:11434", local: true }]);
  assert.equal(local.ok, false);
  if (!local.ok) assert.match(local.problems.join("\n"), /you can add outside models only/);
  assert.equal(applyEdits(null, [{ op: "add-model", name: "gw", url: "https://api.example.com" }]).ok, true);
});

test("the arbiter: modelEndpoints marks the administrator's entries and names the files; policyDocument carries the layer; a hand-edited file that breaks the lock is refused", async () => {
  const d = layerDir({ "10-corp.yaml": LOCKED });
  const tmp = mkdtempSync(join(tmpdir(), "mandu-admin-arbiter-"));
  dirs.push(tmp);
  const sock = join(tmp, "a.sock");
  const adminSock = join(tmp, "admin.sock");
  writeFileSync(join(tmp, "policy.yaml"), "models:\n  - name: gw\n    url: https://api.example.com\n");
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, dbPath: join(tmp, "s.sqlite"), eventDir: join(tmp, "events"), log: () => {}, policyPollMs: 0,
    confidentiality: true, integrity: false, adminPolicyDir: d, policyPath: join(tmp, "policy.yaml"),
  });
  await arbiter.listen();
  const c = new ArbiterClient(sock);
  await c.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  try {
    const raw = c as unknown as { request<T>(op: string, args: object): Promise<T> };
    const r = await raw.request<{ endpoints: Array<Record<string, unknown>>; admin?: { files: string[]; locked: boolean } }>("modelEndpoints", {});
    assert.deepEqual(r.endpoints.map((e) => [e["name"], e["adminFile"] === join(d, "10-corp.yaml"), e["locked"] ?? false]), [["corp", true, true], ["gw", false, false]]);
    assert.deepEqual(r.admin, { files: [join(d, "10-corp.yaml")], locked: true, conflicts: [], refused: [] });
    const pd = await admin.policyDocument();
    assert.equal(pd.admin?.locked, true);
    assert.deepEqual(pd.admin?.models.map((m) => [m["name"], m["url"], m["file"]]), [["corp", "https://llm.corp.example/v1", join(d, "10-corp.yaml")]]);
    // The dashboard's raw apply of a document that breaks the lock is refused
    // and the law in force is kept.
    await assert.rejects(
      admin.applyPolicyDocument({ models: [{ name: "mine", url: "http://127.0.0.1:11434", local: true }] }, "test", pd.lawHash!),
      /local: true is refused/,
    );
    assert.deepEqual((await c.modelEndpoints()).map((e) => e.name), ["corp", "gw"]);
  } finally {
    c.close();
    admin.close();
    await arbiter.close();
  }
});

test("the administrator wins: under the lock a user's local entry, a changed locked field and a widened perimeter are not in force; start tolerates them, a write only keeps the ones it had", () => {
  const l = load({ "10-corp.yaml": LOCKED });
  const doc: PolicyFileConfig = {
    models: [
      { name: "corp", url: "https://evil.example/v1", wire: "openai-chat", model: "qwen", local: true, helper: true },
      { name: "mine", url: "http://127.0.0.1:11434", local: true },
      { name: "gw", url: "https://api.example.com" },
    ],
    perimeter: { networks: ["0.0.0.0/0"] },
  };
  const eff = effectiveModels(doc, l);
  assert.deepEqual(eff.models.map((m) => [m.name, m.url, m.adminFile !== undefined]), [["corp", "https://llm.corp.example/v1", true], ["gw", "https://api.example.com", false]]);
  assert.deepEqual(eff.perimeter?.networks, ["10.0.0.0/8"], "a widening is replaced by the administrator's networks");
  const c = compilePolicy({ specId: "claude-code", document: doc });
  assert.deepEqual(c.models.map((m) => [m.name, m.url]), [["corp", "https://llm.corp.example/v1"], ["gw", "https://api.example.com"]]);

  // Every conflict is named; strict validation refuses, the start does not.
  const conflicts = layerProblems(doc, l);
  assert.equal(conflicts.length, 3, conflicts.join("\n"));
  assert.equal(validatePolicyDocument(doc).length, 3);
  assert.deepEqual(validatePolicyDocument(doc, l, { tolerate: "all" }), []);
  const tmp = mkdtempSync(join(tmpdir(), "mandu-admin-start-"));
  dirs.push(tmp);
  writeFileSync(join(tmp, "policy.yaml"), "models:\n  - name: mine\n    url: http://127.0.0.1:11434\n    local: true\n");
  assert.equal(loadPolicyFileStrict(join(tmp, "policy.yaml")).found, true, "a conflict never refuses the start");

  // A write keeps the conflicts the document in force had (even when an edit
  // moves the entry in the list) and is refused for one it adds.
  const moved: PolicyFileConfig = { ...doc, models: [{ name: "extra", url: "https://api2.example.com" }, ...doc.models!] };
  assert.deepEqual(validatePolicyDocument(moved, l, { tolerate: doc }), []);
  const added: PolicyFileConfig = { ...doc, models: [...doc.models!, { name: "mine2", url: "http://127.0.0.1:8080", local: true }] };
  const refused = validatePolicyDocument(added, l, { tolerate: doc });
  assert.equal(refused.length, 1);
  assert.match(refused[0]!, /you can add outside models only/);
  // The edit grammar judges the same way.
  assert.equal(applyEdits(doc, [{ op: "add-model", name: "gw2", url: "https://api3.example.com" }]).ok, true);
  assert.equal(applyEdits(doc, [{ op: "add-model", name: "mine3", url: "http://127.0.0.1:9090", local: true }]).ok, false);
});

test("the administrator's perimeter holds without the lock: a user may narrow it, never widen or drop it; a second helper loses to the administrator's", () => {
  const l = load({ "10-corp.yaml": CORP });
  assert.equal(l.locked, false);
  assert.deepEqual(validatePolicyDocument({ perimeter: { networks: ["10.2.0.0/16"] } }), []);
  assert.deepEqual(effectiveModels({ perimeter: { networks: ["10.2.0.0/16"] } }, l).perimeter?.networks, ["10.2.0.0/16"]);
  assert.match(validatePolicyDocument({ perimeter: { networks: ["192.168.0.0/16"] } }).join("\n"), /perimeter\.networks: set by your administrator .* as 10\.0\.0\.0\/8; you can narrow it here, not widen it/);
  assert.deepEqual(effectiveModels({ perimeter: { networks: ["192.168.0.0/16"] } }, l).perimeter?.networks, ["10.0.0.0/8"]);
  assert.deepEqual(effectiveModels({ perimeter: { domains: ["lab.example"] } }, l).perimeter, { networks: ["10.0.0.0/8"], domains: ["corp.example", "lab.example"] }, "a user perimeter with no networks keeps the administrator's");

  const doc: PolicyFileConfig = { models: [{ name: "mine", url: "http://127.0.0.1:11434", wire: "openai-chat", local: true, helper: true }] };
  assert.match(validatePolicyDocument(doc).join("\n"), /only one model can be the helper's \('corp' in .*10-corp\.yaml, 'mine' are\)/);
  assert.deepEqual(effectiveModels(doc, l).models.map((m) => [m.name, m.helper ?? false]), [["corp", true], ["mine", false]]);
  // Removing the administrator's helper, or overriding it without the mark, frees the choice.
  assert.deepEqual(validatePolicyDocument({ models: [{ name: "corp", disabled: true }, ...doc.models!] } as unknown as PolicyFileConfig), []);
});

test("restore-model brings back an administrator's entry the user removed; nothing else", () => {
  load({ "10-corp.yaml": LOCKED });
  const removed = applyEdits(null, [{ op: "remove-model", name: "corp" }]);
  assert.ok(removed.ok);
  const back = applyEdits(removed.document, [{ op: "restore-model", name: "corp" }]);
  assert.equal(back.ok, true, back.ok ? "" : back.problems.join("; "));
  if (back.ok) assert.equal(back.document.models, undefined);
  const notRemoved = applyEdits(null, [{ op: "restore-model", name: "corp" }]);
  assert.ok(!notRemoved.ok && /is not removed/.test(notRemoved.problems.join("\n")));
  const notAdmin = applyEdits(null, [{ op: "restore-model", name: "gw" }]);
  assert.ok(!notAdmin.ok && /no model named "gw" is set by your administrator/.test(notAdmin.problems.join("\n")));
});

test("the arbiter re-reads the layer when a file changes: a lock that arrives wins over the user's file and is named; a broken file keeps the layer in force; a removed layer gives the list back", async () => {
  const d = layerDir({ "10-corp.yaml": CORP });
  const tmp = mkdtempSync(join(tmpdir(), "mandu-admin-reload-"));
  dirs.push(tmp);
  const sock = join(tmp, "a.sock");
  const adminSock = join(tmp, "admin.sock");
  writeFileSync(join(tmp, "policy.yaml"), "models:\n  - name: mine\n    url: http://127.0.0.1:11434\n    local: true\n");
  const logs: string[] = [];
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, dbPath: join(tmp, "s.sqlite"), eventDir: join(tmp, "events"), log: (m) => logs.push(m), policyPollMs: 50,
    confidentiality: true, integrity: false, adminPolicyDir: d, policyPath: join(tmp, "policy.yaml"),
  });
  await arbiter.listen();
  const c = new ArbiterClient(sock);
  await c.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const names = async (): Promise<string[]> => (await c.modelEndpoints()).map((e) => e.name);
  const until = async (what: string, ok: () => Promise<boolean>): Promise<void> => {
    for (let i = 0; i < 100; i++) { if (await ok()) return; await new Promise((r) => setTimeout(r, 50)); }
    assert.fail(`timed out waiting for ${what}`);
  };
  try {
    assert.deepEqual(await names(), ["corp", "mine"]);
    // The administrator locks the models: the poll picks it up.
    writeFileSync(join(d, "10-corp.yaml"), LOCKED);
    await until("the lock", async () => (await names()).join() === "corp");
    const pd = await admin.policyDocument();
    assert.equal(pd.admin?.locked, true);
    assert.equal(pd.admin?.conflicts.length, 1);
    assert.match(pd.admin!.conflicts[0]!, /'mine' is local: true, and your own models are set by your administrator/);
    assert.ok(logs.some((l) => /\[admin\] your administrator's policy was read again: .*\(models locked\)/.test(l)));
    assert.ok(logs.some((l) => /\[admin\] not in force, your administrator's policy wins: .*local: true is refused/.test(l)));
    // Settings' view: the conflict, and the perimeter the administrator set.
    const snap = (await admin.policySnapshot()).document;
    assert.equal(snap?.modelsAdmin?.conflicts.length, 1);
    assert.deepEqual(snap?.modelsAdmin?.removed, []);
    assert.deepEqual(snap?.perimeter, { networks: ["10.0.0.0/8"], domains: ["corp.example"], by: "administrator" });
    // A write that keeps the conflict passes; one that adds a conflict is refused.
    await admin.applyPolicyDocument({ models: [{ name: "mine", url: "http://127.0.0.1:11434", local: true }, { name: "gw", url: "https://api.example.com" }] }, "test", await lawOf(admin));
    assert.deepEqual(await names(), ["corp", "gw"]);
    await assert.rejects(
      admin.applyPolicyDocument({ models: [{ name: "mine", url: "http://127.0.0.1:11434", local: true }, { name: "mine2", url: "http://127.0.0.1:8080", local: true }] }, "test", await lawOf(admin)),
      /local: true is refused/,
    );
    // Removing the administrator's entry, then bringing it back; a narrower
    // perimeter of the user's own.
    await admin.applyPolicyDocument({ models: [{ name: "corp", disabled: true }, { name: "mine", url: "http://127.0.0.1:11434", local: true }, { name: "gw", url: "https://api.example.com" }], perimeter: { networks: ["10.9.0.0/16"] } }, "test", await lawOf(admin));
    const snap2 = (await admin.policySnapshot()).document;
    assert.deepEqual(snap2?.modelsAdmin?.removed, [{ name: "corp", file: join(d, "10-corp.yaml") }]);
    assert.deepEqual(snap2?.perimeter?.networks, ["10.9.0.0/16"]);
    assert.equal(snap2?.perimeter?.by, "narrowed");
    assert.deepEqual(await names(), ["gw"]);
    await admin.applyPolicyDocument({ models: [{ name: "mine", url: "http://127.0.0.1:11434", local: true }, { name: "gw", url: "https://api.example.com" }] }, "test", await lawOf(admin));
    assert.deepEqual(await names(), ["corp", "gw"]);
    // A broken file: the layer in force stays, the problem is answered.
    writeFileSync(join(d, "20-bad.yaml"), "paths: []\n");
    const refused = arbiter.reloadAdminLayer();
    assert.equal(refused.ok, false);
    const pd2 = await admin.policyDocument();
    assert.equal(pd2.admin?.locked, true);
    assert.match(pd2.admin!.refused.join("\n"), /20-bad\.yaml: 'paths' cannot be set here/);
    assert.deepEqual(await names(), ["corp", "gw"]);
    // The layer is removed: the user's own list is the whole list again.
    unlinkSync(join(d, "20-bad.yaml"));
    unlinkSync(join(d, "10-corp.yaml"));
    await until("the layer to go", async () => (await names()).join() === "mine,gw");
    const pd3 = await admin.policyDocument();
    assert.equal(pd3.admin, undefined);
  } finally {
    c.close();
    admin.close();
    await arbiter.close();
  }
});
