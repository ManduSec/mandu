/**
 * file-rule-weaker-words.test — across the REAL components, the question
 * the Rules page asks before a weaker change words a rule that reaches
 * everything inside a path that is a FILE as that file, and a folder rule
 * as a folder (dashboard.md §4.25f *A rule on a file reads as a file*).
 * Mandu-new.
 *
 * A `paths:` entry with no `recursive:` key reaches everything inside its
 * path, folder or not, and a saved Keys Mandu found suggestion writes
 * exactly that on a file. Since 2026-10-11 the tree, the opened row and
 * Changes to save word it as the file; the question asked before a weaker
 * Save still said "This covers everything inside it that has no rule of its
 * own" (and ", and so does everything inside it" for a rule kept in the
 * page's own store), of a file.
 *
 * Here a real ArbiterServer (secrets) holds a policy.yaml with a folder
 * rule; the real workspace scan files a key in a project and its
 * suggestion is saved through the dashboard; a label is made on a file
 * through the inspector's route (the page's own store). A real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`)
 * serves the Rules page (its own index.html and home.js in jsdom, signed
 * in):
 *
 *   Q1  the saved suggestion is a policy.yaml entry with no `recursive:` key
 *       (the arbiter reaches everything inside it, `covers: subtree`);
 *   Q2  Any AI chosen for the two file rules and the folder rule, Save asks
 *       first, and the question words each file as that file and the folder
 *       with everything inside it; nothing is changed yet;
 *   Q3  Save anyway applies all three: policy.yaml has the new levels and
 *       still no `recursive:` key on the file, the page-store label has its
 *       new level, and the arbiter still reaches everything inside the file;
 *   Q4  the oracle: neither the rendered pages nor the answers read here
 *       carry the key, or an 8-character run of it.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { randomSecretBody } from "../../arbiter/test/helpers/random-secret.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

// Assembled at run time: this file holds no key-shaped literal.
const BODY = randomSecretBody(36);
const TOKEN = "gh" + "p_" + BODY;
const RUNS = Array.from({ length: BODY.length - 7 }, (_, i) => BODY.slice(i, i + 8));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const treeRow = (doc: Doc, path: string) => [...doc.querySelectorAll("#files-tree .row.file-rule")].find((r: Doc) => r.getAttribute("data-path") === path);
const menuIn = (row: Doc) => row?.querySelector("select.label-select:not(.send-select)");
function choose(sel: Doc, value: string): void {
  sel.focus();
  sel.value = value;
  sel.dispatchEvent(new sel.ownerDocument.defaultView.Event("change", { bubbles: true }));
}
/** policy.yaml's entry for `path`: its lines up to the next entry. */
function entryOf(yaml: string, path: string): string {
  const at = yaml.indexOf(`- path: ${path}\n`);
  assert.ok(at >= 0, `policy.yaml has ${path}:\n${yaml}`);
  const rest = yaml.slice(at + 2);
  const end = rest.search(/\n\s*- |\n\S/);
  return end < 0 ? rest : rest.slice(0, end);
}

test("Rules over the real arbiter: the question before a weaker Save words a rule reaching everything inside a file as that file, a folder as a folder; Save anyway applies it; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-file-rule-weaker-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(join(proj, "secrets"), { recursive: true });
  mkdirSync(join(proj, "deploy"), { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]) => execFileSync("git", a, { cwd: proj, env: gitEnv, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(proj, "README.md"), "# app\n");
  git("add", "."); git("commit", "-qm", "init");
  const staging = join(proj, "deploy", "staging.conf");
  writeFileSync(staging, `[api]\nAPI_TOKEN=${TOKEN}\n`);
  const inspector = join(proj, "inspector.token");
  writeFileSync(inspector, "nothing secret here\n");
  const folder = join(proj, "secrets");
  writeFileSync(join(folder, "a.txt"), "nothing secret here\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, ["version: 1", "paths:", `  - path: ${folder}`, "    level: no-model", ""].join("\n"));
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
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const panelRow = async (path: string): Promise<any> => ((await call("GET", "/api/policy/panel")).body.panel.yourRules as Array<{ id: string }>).find((r) => r.id === `lock:${path}`);
  const pageLabel = async (path: string) => ((await call("GET", "/api/secrets")).body.panel.labels as Array<{ path: string; level: string; scope: string; source?: string }>).find((l) => l.path === path);
  try {
    // Q1: the real scan files the key; its suggestion is saved. A label is
    // made on a file in the inspector (the page's own store).
    const scan = await call("POST", "/api/suggestions/scan", { root: "~/proj" });
    assert.equal(scan.status, 200);
    const ids = (scan.body.suggestions as Array<{ id: string; path: string }>).filter((s) => s.path === staging).map((s) => s.id);
    assert.equal(ids.length, 1, "the scan files the key in deploy/staging.conf");
    assert.equal((await call("POST", "/api/suggestions/apply", { ids })).body.applied.length, 1);
    assert.doesNotMatch(entryOf(readFileSync(policyPath, "utf8"), staging), /recursive/, "saved with no recursive: key");
    assert.equal((await panelRow(staging)).covers, "subtree", "the arbiter reaches everything inside it");
    assert.equal((await call("POST", "/api/secrets/label", { path: inspector, confidentiality: "no-model" })).status, 200);
    assert.equal((await pageLabel(inspector))?.scope, "subtree", "the inspector's label reaches everything inside the file too");

    const ready = (doc: Doc) => !!menuIn(treeRow(doc, staging)) && !!menuIn(treeRow(doc, inspector)) && !!menuIn(treeRow(doc, folder));
    await servedProductPage(base, "/rules", ready, async (doc) => {
      doc.defaultView.confirm = () => true;
      // Q2: a weaker level for the two file rules and the folder rule.
      for (const p of [staging, inspector, folder]) choose(menuIn(treeRow(doc, p)), "any-model");
      assert.equal(doc.querySelectorAll("#files-pending-list li").length, 3, "three changes wait");
      doc.getElementById("files-save").click();
      await waitWhile(() => doc.getElementById("files-confirm").hidden);
      assert.equal(doc.getElementById("files-confirm").hidden, false, "Save asks first");
      const asked = Object.fromEntries([...doc.querySelectorAll("#files-confirm-list li")].map((li: Doc) => [li.querySelector("code").textContent, (li.textContent as string).slice(li.querySelector("code").textContent.length + 1)]));
      assert.deepEqual(asked, {
        "~/proj/deploy/staging.conf": "Becomes Any AI, when it asks, which lets more reach an AI or leave this computer than now.",
        "~/proj/inspector.token": "Becomes Any AI, when it asks.",
        "~/proj/secrets": "Becomes Any AI, when it asks, which lets more reach an AI or leave this computer than now. This covers everything inside it that has no rule of its own.",
      });
      assert.match(entryOf(readFileSync(policyPath, "utf8"), staging), /level: no-model/, "asking changes nothing");
      assert.equal(doc.getElementById("files-save").textContent, "Save anyway");
      pages.push(doc.body.textContent ?? "");
      // Q3: Save anyway.
      doc.getElementById("files-save").click();
      await waitWhile(() => !doc.getElementById("files-pending").hidden);
      assert.equal(doc.getElementById("files-pending").hidden, true, "saved");
      await waitWhile(() => menuIn(treeRow(doc, staging))?.value !== "any-model");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    const yaml = readFileSync(policyPath, "utf8");
    assert.match(entryOf(yaml, staging), /level: any-model/);
    assert.doesNotMatch(entryOf(yaml, staging), /recursive/, "the file's entry keeps its reach: no recursive: false");
    assert.match(entryOf(yaml, folder), /level: any-model/);
    assert.equal((await pageLabel(inspector))?.level, "any-model", "the page-store label is changed in place");
    const after = await panelRow(staging);
    assert.deepEqual([after.level, after.covers, after.pathIsFile], ["any-model", "subtree", true], "the arbiter still reaches everything inside");

    // Q4: the oracle.
    for (const path of ["/api/home", "/api/files/list?path=" + encodeURIComponent(join(proj, "deploy"))]) await call("GET", path);
    for (const text of [...pages, ...bodies]) {
      assert.ok(!text.includes(TOKEN), "no page or answer carries the key");
      assert.equal(RUNS.find((r) => text.includes(r)), undefined, "no page or answer carries an 8-character run of the key");
    }
  } finally {
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
