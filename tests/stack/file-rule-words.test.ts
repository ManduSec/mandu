/**
 * file-rule-words.test — across the REAL components, a rule that reaches
 * everything inside a path that is a FILE reads as that file on the product
 * page's Rules, and a change made there keeps the rule as written
 * (dashboard.md §4.25f *A rule on a file reads as a file*). Mandu-new.
 *
 * A `paths:` entry with no `recursive:` key reaches everything inside its
 * path, folder or not, and the arbiter's Keys Mandu found suggestion writes
 * exactly that on a file. Until 2026-10-11 the page drew it as a folder:
 * "deploy/staging.conf and everything inside", a folder icon, "A folder
 * label covers everything inside it…", and the same in Who may get your
 * secrets.
 *
 * Here a real ArbiterServer (secrets) holds a policy.yaml with a hand-written
 * rule on a file and one on a folder; the real workspace scan files a key in
 * a project and its suggestion is saved through the dashboard; a label is
 * made on a file through the inspector's route. A real DashboardServer over
 * the production adapter (`makeApprovalsArbiter`) serves the Rules page (its
 * own index.html and home.js in jsdom):
 *
 *   W1  the saved suggestion is a policy.yaml entry with no `recursive:` key
 *       (the arbiter reaches everything inside it);
 *   W2  /api/policy/panel words it and the hand-written file rule "this
 *       file only" with `pathIsFile`, keeping `covers: subtree`; the folder
 *       rule "and everything inside"; /api/secrets marks the label made on
 *       a file; /api/policy/by-who lists the files alone, the folder with
 *       its reach;
 *   W3  the served page, signed out and in: the tree's words and icons, and
 *       the opened row with no folder note (the folder's keeps it);
 *   W4  a tighter level chosen on the hand-written file rule waits as a
 *       change to the file and is saved: policy.yaml gets the new level and
 *       still no `recursive:` key, and the arbiter still reaches everything
 *       inside (the panel's `covers`);
 *   W5  the oracle: neither the rendered pages nor the answers read here
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
const words = (row: Doc) => (row.querySelector(".file-name").textContent as string).trim();
const icon = (row: Doc) => row.querySelector(".row-icon").innerHTML as string;
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

test("Rules over the real arbiter: a rule reaching everything inside a file reads as that file, signed out and in, and a change made there keeps the rule; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-file-rule-words-"));
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
  const token = join(proj, "deploy.token");
  writeFileSync(token, "nothing secret here\n");
  const inspector = join(proj, "inspector.token");
  writeFileSync(inspector, "nothing secret here\n");
  const folder = join(proj, "secrets");
  writeFileSync(join(folder, "a.txt"), "nothing secret here\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "paths:",
    `  - path: ${token}`,
    "    level: any-model",
    `  - path: ${folder}`,
    "    level: no-model",
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
  try {
    // W1: the real scan files the key; its suggestion is saved.
    const scan = await call("POST", "/api/suggestions/scan", { root: "~/proj" });
    assert.equal(scan.status, 200);
    const ids = (scan.body.suggestions as Array<{ id: string; path: string }>).filter((s) => s.path === staging).map((s) => s.id);
    assert.equal(ids.length, 1, "the scan files the key in deploy/staging.conf");
    const applied = await call("POST", "/api/suggestions/apply", { ids });
    assert.equal(applied.status, 200);
    assert.equal(applied.body.applied.length, 1);
    assert.doesNotMatch(entryOf(readFileSync(policyPath, "utf8"), staging), /recursive/, "saved with no recursive: key");
    // A label made in the inspector (Lock it) on a file sends no `recursive`.
    assert.equal((await call("POST", "/api/secrets/label", { path: inspector, confidentiality: "no-model" })).status, 200);

    // W2: the answers.
    const savedRow = await panelRow(staging);
    assert.equal(savedRow.covers, "subtree", "the arbiter reaches everything inside it");
    assert.equal(savedRow.pathIsFile, true);
    assert.equal(savedRow.plain.reach, "this file only");
    assert.equal((await panelRow(token)).plain.reach, "this file only", "the hand-written file rule");
    assert.equal((await panelRow(folder)).plain.reach, "and everything inside", "the folder rule");
    assert.equal((await panelRow(folder)).pathIsFile, undefined);
    const label = ((await call("GET", "/api/secrets")).body.panel.labels as Array<{ path: string; scope: string; pathIsFile?: boolean }>).find((l) => l.path === inspector);
    assert.deepEqual([label?.scope, label?.pathIsFile], ["subtree", true]);
    const byWho = (await call("GET", "/api/policy/by-who")).body.byWho;
    const any = (byWho.programs.rows as Array<{ name: string; groups: Array<{ items: Array<{ path: string; reach: string | null }> }> }>).find((r) => r.name === "Any other program")!;
    const reach = Object.fromEntries(any.groups.flatMap((g) => g.items).map((i) => [i.path, i.reach]));
    assert.deepEqual(reach, {
      "~/proj/deploy.token": null,
      "~/proj/deploy/staging.conf": null,
      "~/proj/inspector.token": null,
      "~/proj/secrets": "and everything inside",
    });

    // W3: the served page, signed out (an expired session) and in.
    const ready = (doc: Doc) => !!menuIn(treeRow(doc, staging)) && !!menuIn(treeRow(doc, inspector)) && !!menuIn(treeRow(doc, folder));
    const tree = (doc: Doc) => {
      assert.equal(words(treeRow(doc, staging)), "deploy/staging.conf this file only");
      assert.equal(words(treeRow(doc, token)), "deploy.token this file only");
      assert.equal(words(treeRow(doc, inspector)), "inspector.token this file only");
      assert.equal(words(treeRow(doc, folder)), "secrets and everything inside");
      assert.equal(icon(treeRow(doc, staging)), icon(treeRow(doc, token)));
      assert.equal(icon(treeRow(doc, inspector)), icon(treeRow(doc, token)));
      assert.notEqual(icon(treeRow(doc, staging)), icon(treeRow(doc, folder)), "never the folder's icon");
      treeRow(doc, staging).querySelector(".file-more").click();
      const box = doc.querySelector("#files-tree .file-detail");
      assert.match(box.textContent, /Your rule, this file only/);
      assert.doesNotMatch(box.textContent, /everything inside/, "no folder note");
      treeRow(doc, folder).querySelector(".file-more").click();
      assert.match(doc.querySelector("#files-tree .file-detail").textContent, /A folder's rule covers everything inside it/);
      pages.push(doc.body.textContent ?? "");
    };
    await servedProductPage(base, "/rules", ready, async (doc) => tree(doc));
    await servedProductPage(base, "/rules", ready, async (doc) => {
      tree(doc);
      // W4: a tighter level on the hand-written file rule, saved.
      doc.defaultView.confirm = () => true;
      choose(menuIn(treeRow(doc, token)), "no-model");
      const line = [...doc.querySelectorAll("#files-pending-list li")].map((li: Doc) => li.textContent as string).find((l) => l.includes("deploy.token"));
      assert.match(line ?? "", /^~\/proj\/deploy\.token Any AI, when it asks → No AI/);
      assert.doesNotMatch(line ?? "", /everything inside/, "a change to the file");
      doc.getElementById("files-save").click();
      await waitWhile(() => !doc.getElementById("files-pending").hidden);
      assert.equal(doc.getElementById("files-pending").hidden, true, "saved, with no question");
      // The save reads Your rules again and draws the tree: wait for it.
      await waitWhile(() => menuIn(treeRow(doc, token))?.value !== "no-model");
      assert.equal(words(treeRow(doc, token)), "deploy.token this file only");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    const entry = entryOf(readFileSync(policyPath, "utf8"), token);
    assert.match(entry, /level: no-model/, "the new level is in policy.yaml");
    assert.doesNotMatch(entry, /recursive/, "the entry keeps its reach: no recursive: false");
    const after = await panelRow(token);
    assert.deepEqual([after.level, after.covers, after.pathIsFile], ["no-model", "subtree", true], "the arbiter still reaches everything inside");

    // W5: the oracle.
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
