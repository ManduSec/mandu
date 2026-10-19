/**
 * suggested-focus.test — on the product page's Rules › Keys Mandu found keeps
 * the keyboard focus across the REAL components, and an opened row's buttons
 * name their row (dashboard.md §4.25 *Keys Mandu found keeps the focus*).
 * Mandu-new.
 *
 * Until 2026-10-11 a headless Chromium left the focus on <body> after a
 * row's ⋯, its tick box, Not a secret and Scan for keys; Show in policy.yaml
 * and Not a secret named no row. Until 2026-10-13 the focus of a pressed
 * Scan for keys stayed on <body> while the scan ran.
 *
 * Here a real ArbiterServer (secrets) has an empty policy.yaml and a project
 * whose work tree holds three keys no rule covers, which the real workspace
 * scan files. A real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves the Rules page (its own index.html and
 * home.js in jsdom), with Keys Mandu found opened:
 *
 *   K1  signed in, Enter on a row's ⋯ opens it and the focus is on that
 *       row's ⋯, drawn again; Space on a tick box keeps the focus, and
 *       Changes to save follows;
 *   K2  Show in policy.yaml is named by its row, reads Hide with the lines
 *       shown, and keeps the focus;
 *   K3  Not a secret (named by its row): the row is gone, the focus is on
 *       the card's heading, and the arbiter no longer lists it;
 *   K4  Scan for keys over the typed folder: while it runs the focus waits
 *       on the card's heading, never <body>; it is back on Scan for keys
 *       once the scan is done, and the scan says the key marked as not a
 *       secret was left out (the arbiter's own count);
 *   K5  signed out on the open page (an expired session): a refused Not a
 *       secret and a refused Scan each keep the focus (the Scan's waits on
 *       the heading until the refusal), described by "Sign in first…", and
 *       the arbiter still lists the key;
 *   K6  the oracle: neither the rendered pages nor the answers read here
 *       carry any key, or an 8-character run of one.
 *
 * jsdom keeps the focus of a button turned off, so `press` drops it to
 * <body> after the click, as Chromium does; `pressOff` drops it only if the
 * button still has it (Scan for keys hands it on first). Axes: secrets
 * (stated).
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
import { controlName } from "../../dashboard/test/unit/ui/control-names.js";
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
const FILES = ["tools/ci.conf", "deploy/staging.conf", "deploy/prod.conf"];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** Enter on a button that goes off while it acts: the browser drops its
 *  focus to <body>. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the button goes off while it acts");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
}
/** Enter on Scan for keys: the browser drops the focus of a button turned
 *  off, but only while the button still has it. */
function pressOff(btn: Doc): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the button goes off while it acts");
  if (btn.ownerDocument.activeElement !== btn) return;
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
}
/** Enter or Space on a control that keeps working. */
function enter(c: Doc): void {
  c.focus();
  c.click();
}
const rows = (doc: Doc) => [...doc.querySelectorAll("#files-suggested-list .row.suggested")] as Doc[];
const rowAt = (doc: Doc, rel: string) => rows(doc).find((r) => r.dataset.path.endsWith("/" + rel));
const detail = (doc: Doc) => doc.querySelector("#files-suggested-list .file-detail");
const button = (box: Doc, words: string) => [...box.querySelectorAll("button")].find((b: Doc) => b.textContent === words);
const byId = (doc: Doc, id: string) => doc.getElementById(id);

test("Rules over the real arbiter: Keys Mandu found keeps the focus through ⋯, a tick, Show in policy.yaml, Not a secret and Scan for keys, signed in and out; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-suggested-focus-"));
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

    // The page signed in; `headers` goes with every request it makes, so
    // dropping the cookie signs it out (a session that expired).
    const headers: Record<string, string> = { Cookie: ADMIN_COOKIE };
    const ready = (doc: Doc) => !!byId(doc, "suggest-open");
    await servedProductPage(base, "/rules", ready, async (doc) => {
      doc.defaultView.confirm = () => true;
      byId(doc, "suggest-open").click();
      await waitWhile(() => rows(doc).length !== 3);
      assert.equal(rows(doc).length, 3, "Keys Mandu found lists the three");

      // K1: the row's ⋯, then a tick box.
      const more = rowAt(doc, "deploy/staging.conf").querySelector(".file-more");
      enter(more);
      assert.ok(detail(doc), "opened");
      assert.notEqual(rowAt(doc, "deploy/staging.conf").querySelector(".file-more"), more, "drawn again");
      assert.equal(doc.activeElement, rowAt(doc, "deploy/staging.conf").querySelector(".file-more"), "the same row's ⋯");
      assert.equal(controlName(doc.activeElement), "Close staging.conf");
      enter(rowAt(doc, "tools/ci.conf").querySelector("input.file-tick"));
      assert.equal(doc.activeElement, rowAt(doc, "tools/ci.conf").querySelector("input.file-tick"), "the same row's tick box");
      assert.equal(doc.activeElement.checked, false);
      assert.doesNotMatch(byId(doc, "files-pending-list").textContent, /ci\.conf/, "skipped");
      enter(rowAt(doc, "tools/ci.conf").querySelector("input.file-tick"));
      assert.equal(doc.activeElement, rowAt(doc, "tools/ci.conf").querySelector("input.file-tick"));
      assert.match(byId(doc, "files-pending-list").textContent, /~\/proj\/tools\/ci\.conf/);

      // K2: Show in policy.yaml.
      const show = button(detail(doc), "Show in policy.yaml");
      assert.equal(controlName(show), "Show in policy.yaml: staging.conf");
      enter(show);
      assert.equal(controlName(show), "Hide policy.yaml: staging.conf");
      assert.equal(doc.activeElement, show);
      assert.equal(detail(doc).querySelector(".suggestion-yaml").textContent, `paths:\n  - path: ${join(repo, "deploy/staging.conf")}\n    level: no-model`);

      // K3: Not a secret.
      const not = button(detail(doc), "Not a secret");
      assert.equal(controlName(not), "Not a secret: staging.conf");
      press(not);
      // Its own answer writes the notice and gives the focus its place. A
      // read of the suggestions the page made meanwhile (its first Home
      // poll's, late on a loaded host) can take the row away first (master
      // pipeline 10542, suggested-names): the wait is on both.
      await waitWhile(() => rowAt(doc, "deploy/staging.conf") !== undefined || byId(doc, "rules-notice").textContent === "");
      assert.equal(rowAt(doc, "deploy/staging.conf"), undefined, "the row is gone");
      assert.equal(doc.activeElement, byId(doc, "suggested-title"), "the card's heading, never <body>");
      assert.deepEqual(await listed(), ["deploy/prod.conf", "tools/ci.conf"], "the arbiter no longer lists it");

      // K4: Scan for keys over the typed folder.
      byId(doc, "suggest-root").value = "~/proj";
      const scan = byId(doc, "suggest-scan");
      pressOff(scan);
      assert.equal(doc.activeElement, byId(doc, "suggested-title"), "while it runs, the card's heading, never <body>");
      await waitWhile(() => scan.disabled);
      assert.equal(scan.disabled, false, "the scan is done");
      assert.equal(doc.activeElement, scan, "Scan for keys, on again");
      assert.match(byId(doc, "suggest-status").textContent, /1 finding you marked as not a secret was left out/, "the arbiter's own count");
      assert.equal(rows(doc).length, 2);

      // K5: signed out on the open page.
      delete headers.Cookie;
      enter(rowAt(doc, "deploy/prod.conf").querySelector(".file-more"));
      const refused = button(detail(doc), "Not a secret");
      press(refused);
      await waitWhile(() => !byId(doc, "suggest-error").textContent);
      assert.match(byId(doc, "suggest-error").textContent, /^Sign in first/);
      assert.equal(doc.activeElement, refused, "the button pressed, on again");
      assert.equal(refused.getAttribute("aria-describedby"), "suggest-error");
      assert.ok(rowAt(doc, "deploy/prod.conf"), "still waiting");
      byId(doc, "suggest-error").textContent = "";
      pressOff(scan);
      assert.equal(doc.activeElement, byId(doc, "suggested-title"), "the heading, until the refusal");
      await waitWhile(() => scan.disabled);
      assert.match(byId(doc, "suggest-error").textContent, /^Sign in first/);
      assert.equal(doc.activeElement, scan, "Scan for keys, on again");
      assert.equal(scan.getAttribute("aria-describedby"), "suggest-error");
      pages.push(doc.body.textContent ?? "");
    }, { headers });
    assert.deepEqual(await listed(), ["deploy/prod.conf", "tools/ci.conf"], "nothing changed signed out");
    assert.equal(readFileSync(policyPath, "utf8"), "version: 1\n", "no rule was written");

    // K6: the oracle.
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
