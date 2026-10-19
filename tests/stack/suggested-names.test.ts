/**
 * suggested-names.test — on the product page's Rules, two keys in files of
 * the same name are named apart across the REAL components (dashboard.md
 * §4.25 *Keys in files of the same name are named apart*). Mandu-new.
 *
 * Until 2026-10-11 two keys in services/api/app.conf and services/web/app.conf
 * gave two tick boxes "Save app.conf", two ⋯ "More about app.conf", two Skips
 * "Skip the suggestion for app.conf", and a Not a secret that asked "Mark
 * app.conf as not a secret?" of either file.
 *
 * Here a real ArbiterServer (secrets) has an empty policy.yaml and a project
 * whose work tree holds three keys no rule covers, two in files named
 * app.conf, which the real workspace scan files. A real DashboardServer over
 * the production adapter (`makeApprovalsArbiter`) serves the Rules page (its
 * own index.html and home.js in jsdom), signed in, with Keys Mandu found
 * opened:
 *
 *   N1  each app.conf row's tick box and ⋯, and its Skip in Changes to save,
 *       name it by its path; ci.conf keeps its name; no two controls of the
 *       list or of Changes to save share a name;
 *   N2  the web app.conf opened: Show in policy.yaml and Not a secret name
 *       its path, and the lines are that file's;
 *   N3  Not a secret asks of that path and says that path when done; the
 *       arbiter no longer lists that file and still lists the other
 *       app.conf, which then has its name to itself;
 *   N4  the oracle: neither the rendered pages nor the answers read here
 *       carry any key, or an 8-character run of one.
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
import { controlName, nameFaults } from "../../dashboard/test/unit/ui/control-names.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { randomSecretBody } from "../../arbiter/test/helpers/random-secret.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

// Assembled at run time: this file holds no key-shaped literal.
const BODIES = [randomSecretBody(36), randomSecretBody(36), randomSecretBody(36)];
const TOKENS = BODIES.map((b) => "gh" + "p_" + b);
const RUNS = BODIES.flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));
const FILES = ["services/api/app.conf", "services/web/app.conf", "tools/ci.conf"];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** Enter or Space on a control that keeps working. */
function enter(c: Doc): void {
  c.focus();
  c.click();
}
const rows = (doc: Doc) => [...doc.querySelectorAll("#files-suggested-list .row.suggested")] as Doc[];
const rowAt = (doc: Doc, rel: string) => rows(doc).find((r) => r.dataset.path.endsWith("/" + rel));
const tickAt = (doc: Doc, rel: string) => rowAt(doc, rel).querySelector("input.file-tick");
const moreAt = (doc: Doc, rel: string) => rowAt(doc, rel).querySelector(".file-more");
const skipAt = (doc: Doc, rel: string) => byId(doc, "files-pending-list").querySelector(`li[data-id="${rowAt(doc, rel).dataset.id}"] button`);
const detail = (doc: Doc) => doc.querySelector("#files-suggested-list .file-detail");
const button = (box: Doc, words: string) => [...box.querySelectorAll("button")].find((b: Doc) => b.textContent === words);
const byId = (doc: Doc, id: string) => doc.getElementById(id);

test("Rules over the real arbiter: two keys in files named app.conf are named apart by their paths, on every control and in Not a secret's words; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-suggested-names-"));
  const home = join(tmp, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]) => execFileSync("git", a, { cwd: repo, env: gitEnv, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(repo, "README.md"), "# app\n");
  git("add", "."); git("commit", "-qm", "init");
  FILES.forEach((rel, i) => {
    mkdirSync(join(repo, rel, ".."), { recursive: true });
    writeFileSync(join(repo, rel), `[api]\nAPI_TOKEN=${TOKENS[i]}\n`);
  });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
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
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await pageFetch(base + path, { method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) };
  };
  const listed = async () => ((await call("GET", "/api/suggestions")).body.suggestions as Array<{ path: string }>).map((s) => s.path.slice(repo.length + 1)).sort();
  const pages: string[] = [];
  try {
    const first = await call("POST", "/api/suggestions/scan", { root: "~/proj" });
    assert.equal(first.status, 200);
    assert.deepEqual(await listed(), [...FILES].sort(), "the real workspace scan files the three keys");

    const asked: string[] = [];
    const ready = (doc: Doc) => !!byId(doc, "suggest-open");
    await servedProductPage(base, "/rules", ready, async (doc) => {
      doc.defaultView.confirm = (q: string) => (asked.push(q), true);
      byId(doc, "suggest-open").click();
      await waitWhile(() => rows(doc).length !== 3);
      assert.equal(rows(doc).length, 3, "Keys Mandu found lists the three");

      // N1: each control names its row apart.
      assert.equal(controlName(tickAt(doc, "services/api/app.conf")), "Skip ~/proj/services/api/app.conf");
      assert.equal(controlName(tickAt(doc, "services/web/app.conf")), "Skip ~/proj/services/web/app.conf");
      assert.equal(controlName(moreAt(doc, "services/api/app.conf")), "More about ~/proj/services/api/app.conf");
      assert.equal(controlName(moreAt(doc, "services/web/app.conf")), "More about ~/proj/services/web/app.conf");
      assert.equal(controlName(tickAt(doc, "tools/ci.conf")), "Skip ci.conf", "a name of its own stays short");
      assert.equal(controlName(skipAt(doc, "services/web/app.conf")), "Skip the suggestion for ~/proj/services/web/app.conf");
      assert.equal(controlName(skipAt(doc, "tools/ci.conf")), "Skip the suggestion for ci.conf");
      assert.deepEqual(nameFaults(byId(doc, "files-suggested-list")), { shared: [], unnamed: [] });
      assert.deepEqual(nameFaults(byId(doc, "files-pending-list")), { shared: [], unnamed: [] });

      // N2: the web app.conf opened.
      enter(moreAt(doc, "services/web/app.conf"));
      assert.equal(controlName(doc.activeElement), "Close ~/proj/services/web/app.conf");
      const show = button(detail(doc), "Show in policy.yaml");
      assert.equal(controlName(show), "Show in policy.yaml: ~/proj/services/web/app.conf");
      enter(show);
      assert.equal(detail(doc).querySelector(".suggestion-yaml").textContent, `paths:\n  - path: ${join(repo, "services/web/app.conf")}\n    level: no-model`);
      const not = button(detail(doc), "Not a secret");
      assert.equal(controlName(not), "Not a secret: ~/proj/services/web/app.conf");
      assert.deepEqual(nameFaults(byId(doc, "files-suggested-list")), { shared: [], unnamed: [] });

      // N3: Not a secret, of that file only.
      enter(not);
      // Its own answer writes the notice. A read of the suggestions the page
      // made meanwhile (its first Home poll's, late on a loaded host) can
      // take the row away first (master pipeline 10542): the wait is on both.
      await waitWhile(() => rowAt(doc, "services/web/app.conf") !== undefined || byId(doc, "rules-notice").textContent === "");
      assert.deepEqual(asked, ["Mark ~/proj/services/web/app.conf as not a secret? Mandu will not suggest it again, and the AI can still read it."]);
      assert.equal(rowAt(doc, "services/web/app.conf"), undefined, "the row is gone");
      assert.equal(byId(doc, "rules-notice").textContent, "~/proj/services/web/app.conf is marked as not a secret. Mandu will not suggest it again.");
      assert.equal(controlName(tickAt(doc, "services/api/app.conf")), "Skip app.conf", "the other app.conf has its name to itself");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    assert.deepEqual(await listed(), ["services/api/app.conf", "tools/ci.conf"], "the arbiter no longer lists that file, and still lists the other app.conf");
    assert.equal(readFileSync(policyPath, "utf8"), "version: 1\n", "no rule was written");

    // N4: the oracle.
    for (const path of ["/api/policy/panel", "/api/home"]) await call("GET", path);
    for (const text of [...pages, ...bodies]) {
      for (const t of TOKENS) assert.ok(!text.includes(t), "no page or answer carries a key");
      assert.equal(RUNS.find((r) => text.includes(r)), undefined, "no page or answer carries an 8-character run of a key");
    }
  } finally {
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
