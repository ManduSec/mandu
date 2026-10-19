/**
 * rules-warning-once — on the product page's Rules, an opened rule's row
 * says the rule's warning once, across the REAL components (dashboard.md
 * §4.25p *A warning is said once*). Mandu-new.
 *
 * An opened rule says its warning in full in its left column (`.rule-warn`,
 * the policy panel's `warning`), and *What the rules say* draws the why
 * route's lines, one of which is the same warning (`Warning`, the same
 * judgment of the same readers). Until 2026-10-16 the row said it twice; a
 * headless Chromium found the 51-word printer warning in both halves of the
 * row at every width, and three sentences for a your-own-AI rule's two.
 *
 * A real ArbiterServer (secrets) holds a policy.yaml with four rules over
 * real files holding a value: `.env` (no AI, two hosts, readers psql, ssh
 * from git and cat), `notes.env` (your own AI with none listed, reader cat),
 * the folder `deploy` (reader cat) and its `prod.env` (reader ssh). A real
 * DashboardServer over the production adapter serves Rules, signed in, and
 * each rule's row is opened:
 *
 *   W1  `.env`: the row says the route's Warning once, in its left column;
 *       the box draws the route's other lines, in order;
 *   W2  `notes.env`: the left column says the no-own-model sentence and
 *       the readers' warning; the box leaves out the line it holds; each
 *       sentence once;
 *   W3  the folder (a folder's box names no readers) and `prod.env` (no
 *       warning): the box draws every line of the route, as before;
 *   W4  Add a rule's browser (Show in its folder): `.env`'s row there has
 *       no rule of its own, so its box keeps the Warning, said once;
 *   W5  the oracle: no page or answer read here carries a file's value or
 *       a minted token, and policy.yaml is as it was.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
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
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const VALUES = [`sk_live_warningOnceCanary_${process.pid}_0`, `warningOnceCanary${process.pid}x1`, `warningOnceCanary${process.pid}x2`, `warningOnceCanary${process.pid}x3`];
/** A minted token (the panel's own help text names the `$MDU:` form). */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;
const NO_OWN = "No AI of your own is listed, so no AI reads this file.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
type Line = { term: string; text: string };

test("Rules over the real arbiter: an opened rule says its warning once, in its left column, and What the rules say draws the route's other lines; the browser's row keeps it in the box; no value on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-warning-once-"));
  const home = join(tmp, "home");
  const deploy = join(home, "mandu-try", "deploy");
  mkdirSync(deploy, { recursive: true });
  const env = join(home, "mandu-try", ".env");
  const notes = join(home, "mandu-try", "notes.env");
  const prod = join(deploy, "prod.env");
  writeFileSync(env, `STRIPE_KEY=${VALUES[0]}\n`);
  writeFileSync(notes, `NOTES_TOKEN=${VALUES[1]}\n`);
  writeFileSync(prod, `DB_PASSWORD=${VALUES[2]}\n`);
  writeFileSync(join(deploy, "staging.conf"), `token = ${VALUES[3]}\n`);
  const policyPath = join(tmp, "policy.yaml");
  const policy = [
    "version: 1",
    "paths:",
    `  - { path: "${env}", level: no-model, bindings: [api.stripe.com, "db.internal:5432"], readers: [psql, { app: ssh, from: git }, cat] }`,
    `  - { path: "${notes}", level: local-model, readers: [cat] }`,
    `  - { path: "${deploy}", level: no-model, readers: [cat] }`,
    `  - { path: "${prod}", level: no-model, readers: [ssh] }`,
    "",
  ].join("\n");
  writeFileSync(policyPath, policy);
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
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { Cookie: ADMIN_COOKIE };
  const noValue = (body: string, where: string) => {
    for (const v of VALUES) assert.ok(!body.includes(v), `CONFIDENTIALITY VIOLATION: ${where} carries a file's value`);
    assert.doesNotMatch(body, TOKEN, `${where} carries no token`);
  };
  const read = async (path: string, headers: Record<string, string>): Promise<string> => {
    const r = await pageFetch(base + path, { headers });
    const body = await r.text();
    assert.equal(r.status, 200, `${path}: ${body.slice(0, 200)}`);
    noValue(body, path);
    return body;
  };
  try {
    // The arbiter's answers, as the route gives them.
    const route: Record<string, Line[]> = {};
    for (const path of [env, notes, deploy, prod]) {
      route[path] = (JSON.parse(await read(`/api/files/why?path=${encodeURIComponent(path)}`, CSRF_ADMIN)) as { why: { lines: Line[] } }).why.lines;
    }
    const warningOf = (path: string) => route[path]!.find((l) => l.term === "Warning")?.text ?? null;
    const envWarning = warningOf(env);
    const notesWarning = warningOf(notes);
    assert.match(envWarning ?? "", /^psql, cat print or copy what they read/, "the route warns about .env's printers");
    assert.match(notesWarning ?? "", /^cat prints or copies what it reads/, "and notes.env's");
    assert.equal(warningOf(deploy), null, "a folder's box names no readers");
    assert.equal(warningOf(prod), null, "ssh earns no warning");
    const lines = (path: string, keepWarning: boolean) => route[path]!.filter((l) => keepWarning || l.term !== "Warning").map((l) => `${l.term}: ${l.text}`);

    const ruleRow = (doc: Doc, path: string) => doc.querySelector(`#files-tree .row.file-rule[data-path="${path}"]`);
    const shown = (detail: Doc) => ({
      left: ([...detail.querySelectorAll(".file-detail-main .rule-warn")] as Doc[]).map((w) => w.textContent),
      box: ([...detail.querySelectorAll(".file-why dt")] as Doc[]).map((dt) => `${dt.textContent}: ${dt.nextElementSibling.textContent}`),
      text: detail.textContent as string,
    });
    const times = (text: string, sentence: string) => text.split(sentence).length - 1;
    await servedProductPage(base, "/rules", (doc: Doc) => [env, notes, deploy, prod].every((p) => ruleRow(doc, p)), async (doc: Doc) => {
      const open = async (path: string) => {
        ruleRow(doc, path).querySelector(".file-more").click();
        const boxOf = () => doc.querySelector(`#files-tree .file-detail .file-why[data-path="${path}"]`);
        await waitWhile(() => !boxOf()?.querySelector("dl"));
        assert.ok(boxOf()?.querySelector("dl"), `${path}: What the rules say is read and drawn`);
        return boxOf().closest(".file-detail");
      };
      const close = async (path: string) => {
        ruleRow(doc, path).querySelector(".file-more").click();
        await waitWhile(() => !!doc.querySelector("#files-tree .file-detail"));
      };

      // ── W1 ──
      let s = shown(await open(env));
      assert.deepEqual(s.left, [envWarning], ".env: the left column says the warning in full");
      assert.deepEqual(s.box, lines(env, false), ".env: the box draws the route's other lines, in order");
      assert.equal(times(s.text, envWarning!), 1, ".env: the opened row says it once");
      await close(env);

      // ── W2 ──
      s = shown(await open(notes));
      assert.equal(s.left.length, 1);
      assert.ok(s.left[0].startsWith(NO_OWN) && s.left[0].endsWith(notesWarning!), `notes.env: the no-own-model sentence, then the readers' warning: ${s.left[0]}`);
      assert.deepEqual(s.box, lines(notes, false), "notes.env: the box leaves out the line the row holds");
      assert.equal(times(s.text, notesWarning!), 1);
      assert.equal(times(s.text, NO_OWN), 1);
      await close(notes);

      // ── W3 ──
      s = shown(await open(deploy));
      assert.equal(s.left.length, 1, "the folder: its rule's warning, in its left column");
      assert.match(s.left[0], /^cat prints or copies what it reads/);
      assert.deepEqual(s.box, lines(deploy, true), "the folder: the box as the route says it");
      await close(deploy);
      s = shown(await open(prod));
      assert.deepEqual(s.left, [], "prod.env: no warning");
      assert.deepEqual(s.box, lines(prod, true), "prod.env: the box as the route says it");
      await close(prod);

      // ── W4: the same file in Add a rule's browser ──
      const detail = await open(env);
      ([...detail.querySelectorAll(".detail-links button")] as Doc[]).find((b) => b.textContent === "Show in its folder").click();
      const browserBox = () => doc.querySelector(`#files-list .file-detail .file-why[data-path="${env}"]`);
      await waitWhile(() => !browserBox()?.querySelector("dl"));
      assert.ok(browserBox()?.querySelector("dl"), "the browser opens .env's row and reads what the rules say");
      s = shown(browserBox().closest(".file-detail"));
      assert.deepEqual(s.left, [], "the browser's row has no rule of its own");
      assert.deepEqual(s.box, lines(env, true), "so its box keeps the Warning");
      assert.equal(times(s.text, envWarning!), 1, "said once there too");
      noValue(doc.body.textContent, "the rendered Rules page");
    }, { headers: signedIn });

    // ── W5: the oracle ──
    for (const r of ["/api/home", "/api/policy/panel", "/api/secrets", "/rules", "/"]) await read(r, signedIn);
    assert.equal(readFileSync(policyPath, "utf8"), policy, "nothing was saved");
  } finally {
    await dashboard.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
