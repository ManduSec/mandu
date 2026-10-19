/**
 * suggestions-order.test — on the product page's Rules, a read of Keys
 * Mandu found asked before a change's answer never draws over it, across
 * the REAL components (dashboard.md §4.25 *A read asked before a change
 * never draws over it*). Mandu-new.
 *
 * The page reads the suggestions on every Home poll, when the card opens,
 * and every 3 s while a scan runs; Not a secret, Save, Scan for keys and a
 * model run each answer with the server's new list. Until 2026-10-12 a read
 * asked before the change that answered after it was taken too: on a slow
 * network the key marked Not a secret came back on the next draw, ticked,
 * and the next Save sent it again; and a poll made after the change waited
 * on that older read.
 *
 * Here a real ArbiterServer (secrets) has an empty policy.yaml and a project
 * whose work tree holds keys no rule covers, which the real workspace scan
 * files. A real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves the Rules page (its own index.html and
 * home.js in jsdom), signed in, through a relay that holds one
 * `/api/suggestions` answer back (tests/lib/holding-relay.ts):
 *
 *   R1  Keys Mandu found lists the three keys; a poll's read of them is
 *       answered (the three) and held;
 *   R2  Not a secret on staging.conf: the row is gone and the notice says
 *       so; the arbiter no longer lists it;
 *   R3  another scan files a fourth key; the next poll reads again rather
 *       than wait on the held read, and draws it;
 *   R4  the held read (the three, staging.conf with them) comes: it is
 *       dropped; a tick draws the list again without staging.conf, and
 *       Changes to save does not list it;
 *   R5  Save saves the three still waiting, refuses none, and policy.yaml
 *       never names staging.conf;
 *   R6  the oracle: neither the rendered pages nor the answers read here
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
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { randomSecretBody } from "../../arbiter/test/helpers/random-secret.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { holdingRelay } from "../lib/holding-relay.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

// Assembled at run time: this file holds no key-shaped literal.
const BODIES = [randomSecretBody(36), randomSecretBody(36), randomSecretBody(36), randomSecretBody(36)];
const TOKENS = BODIES.map((b) => "gh" + "p_" + b);
const RUNS = BODIES.flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));
const FILES = ["deploy/prod.conf", "deploy/staging.conf", "tools/ci.conf"];
const LATER = "deploy/new.conf";
/** How long a page is given to draw a held answer it must drop: a page
 *  that draws it changes the list within this, a page that drops it never
 *  does. */
const SETTLE_MS = 1500;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const rows = (doc: Doc) => [...doc.querySelectorAll("#files-suggested-list .row.suggested")] as Doc[];
const shown = (doc: Doc, repo: string) => rows(doc).map((r) => r.dataset.path.slice(repo.length + 1)).sort();
const rowAt = (doc: Doc, rel: string) => rows(doc).find((r) => r.dataset.path.endsWith("/" + rel));
const byId = (doc: Doc, id: string) => doc.getElementById(id);
const button = (box: Doc, words: string) => [...box.querySelectorAll("button")].find((b: Doc) => b.textContent === words);
/** Enter or Space on a control that keeps working. */
function enter(c: Doc): void {
  c.focus();
  c.click();
}

test("Rules over the real arbiter: a read of the suggestions asked before Not a secret never brings the key back, and a poll after it reads again; Save never sends it; no key on the page", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-suggestions-order-"));
  const home = join(tmp, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]) => execFileSync("git", a, { cwd: repo, env: gitEnv, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(repo, "README.md"), "# app\n");
  git("add", "."); git("commit", "-qm", "init");
  const plant = (rel: string, i: number) => {
    mkdirSync(join(repo, rel, ".."), { recursive: true });
    writeFileSync(join(repo, rel), `[api]\nAPI_TOKEN=${TOKENS[i]}\n`);
  };
  FILES.forEach(plant);
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
  const port = await dashboard.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const relay = await holdingRelay(port);
  const bodies: string[] = [];
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await pageFetch(base + path, { method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) };
  };
  const listed = async () => ((await call("GET", "/api/suggestions")).body.suggestions as Array<{ path: string }>).map((s) => s.path.slice(repo.length + 1)).sort();
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const pages: string[] = [];
  try {
    assert.equal((await call("POST", "/api/suggestions/scan", { root: "~/proj" })).status, 200);
    assert.deepEqual(await listed(), FILES, "the real workspace scan files the three keys");

    const ready = (doc: Doc) => !!byId(doc, "suggest-open");
    await servedProductPage(relay.base, "/rules", ready, async (doc) => {
      doc.defaultView.confirm = () => true;
      // The page reads again when it is shown (its 10 s poll is inert here).
      const poll = () => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      const keep = () => pages.push(doc.body.textContent ?? "");

      // R1: the list, then a poll's read of it held.
      byId(doc, "suggest-open").click();
      await waitWhile(() => rows(doc).length !== 3);
      assert.deepEqual(shown(doc, repo), FILES, "Keys Mandu found lists the three");
      const before = relay.holdNext("/api/suggestions");
      poll();
      assert.equal(await before.asked, 200, "answered while staging.conf still waited, and held");
      keep();

      // R2: Not a secret on staging.conf.
      enter(rowAt(doc, "deploy/staging.conf").querySelector(".file-more"));
      enter(button(doc.querySelector("#files-suggested-list .file-detail"), "Not a secret"));
      await waitWhile(() => rowAt(doc, "deploy/staging.conf") !== undefined || byId(doc, "rules-notice").textContent === "");
      assert.equal(rowAt(doc, "deploy/staging.conf"), undefined, "the row is gone");
      assert.equal(byId(doc, "rules-notice").textContent, "staging.conf is marked as not a secret. Mandu will not suggest it again.");
      assert.deepEqual(await listed(), ["deploy/prod.conf", "tools/ci.conf"], "the arbiter no longer lists it");

      // R3: another scan files a fourth key; the next poll reads again
      // rather than wait on the held read, and draws it.
      plant(LATER, 3);
      assert.equal((await call("POST", "/api/suggestions/scan", { root: "~/proj" })).status, 200);
      assert.deepEqual(await listed(), ["deploy/new.conf", "deploy/prod.conf", "tools/ci.conf"]);
      poll();
      await waitWhile(() => !rowAt(doc, LATER));
      assert.deepEqual(shown(doc, repo), ["deploy/new.conf", "deploy/prod.conf", "tools/ci.conf"], "a read of its own, drawn while the older one is still held");
      keep();

      // R4: the held read comes, staging.conf in it: dropped.
      await before.release();
      await waitWhile(() => !rowAt(doc, "deploy/staging.conf"), SETTLE_MS);
      enter(rowAt(doc, "tools/ci.conf").querySelector("input.file-tick"));
      enter(rowAt(doc, "tools/ci.conf").querySelector("input.file-tick"));
      assert.deepEqual(shown(doc, repo), ["deploy/new.conf", "deploy/prod.conf", "tools/ci.conf"], "never drawn again, also after a tick");
      assert.equal(byId(doc, "files-suggested-count").textContent, "3");
      assert.doesNotMatch(byId(doc, "files-pending-list").textContent, /staging\.conf/, "nor waiting in Changes to save");
      keep();

      // R5: Save sends only what still waits.
      byId(doc, "files-save").click();
      await waitWhile(() => rows(doc).length > 0 || byId(doc, "rules-notice").textContent === "");
      assert.equal(byId(doc, "lock-error").textContent, "", "nothing refused");
      assert.match(byId(doc, "rules-notice").textContent, /^3 suggestions saved\./);
      assert.equal(rows(doc).length, 0);
      keep();
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");
    assert.deepEqual(await listed(), [], "nothing waits");
    const yaml = readFileSync(policyPath, "utf8");
    for (const rel of ["deploy/new.conf", "deploy/prod.conf", "tools/ci.conf"]) assert.ok(yaml.includes(join(repo, rel)), `${rel} is a rule`);
    assert.ok(!yaml.includes("staging.conf"), "never the key marked as not a secret");

    // R6: the oracle.
    assert.equal(pages.length, 4);
    for (const path of ["/api/policy/panel", "/api/home"]) await call("GET", path);
    for (const text of [...pages, ...bodies]) {
      for (const t of TOKENS) assert.ok(!text.includes(t), "no page or answer carries a key");
      assert.equal(RUNS.find((r) => text.includes(r)), undefined, "no page or answer carries an 8-character run of a key");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await relay.close();
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
