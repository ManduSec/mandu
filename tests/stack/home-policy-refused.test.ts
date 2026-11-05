/**
 * home-policy-refused — Home says when Mandu refused your last edit to
 * policy.yaml, across the REAL components and the served page (dashboard.md
 * §4.25 *An edit to policy.yaml Mandu refused*). Mandu-new.
 *
 * Rules has said so since 2026-10-25 (its refused line), but after saving
 * the file people look at Home, and Home kept saying "Protection on" while
 * the edit, perhaps a new lock, was not in force. Here a real ArbiterServer
 * runs at the `secrets` axes with `~/.mandu/policy.yaml` (polled every
 * 30 ms) under the dashboard's home, behind a real DashboardServer over the
 * production adapter (`makeApprovalsArbiter`):
 *
 *   H1  the file holds a valid lock: `/api/home` carries `policyFile` with
 *       `valid: true`, and the served Home draws no card;
 *   H2  the file is overwritten with a level that does not exist: once the
 *       arbiter has refused the reload, `/api/home` carries `policyFile`
 *       with `valid: false`, the path, the problem count and the time, and
 *       none of the problems' words; the served Home draws the card, naming
 *       the file with `~` and linking Rules;
 *       The served Approvals page's top bar marks the Rules link "!", named
 *       "Rules, Mandu did not take your last edit to policy.yaml" (#215,
 *       *The top bar says so on every page*), and so does Home's;
 *   H3  the file is fixed: on the next poll of the same page the card goes,
 *       and on the next poll of the Approvals page the mark goes;
 *   H4  the oracle: no page or answer read here carries the locked file's
 *       value, and none a minted token (`$MDU:NAME[hex]`); nor does the
 *       Rules link's name or title, which carries no problem's words.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the words the served page draws; the stack supplies the
 * file state, as the arbiter's reload decides it, that the words are about.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const ENV_VALUE = `sk_live_homePolicyRefusedCanary_${process.pid}_000000`;
/** A minted token (the panel's own help text names the `$MDU:` form). */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;

type HomePolicyFile = { valid: boolean; path: string; problemCount: number; refusedAt: number | null };

test("Home says when Mandu refused your last edit to policy.yaml, with the count and a link to Rules but never the problems, the top bar's Rules link says so on Approvals, and both go on the next poll once fixed, on the real stack with its served page; no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-home-policy-refused-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  mkdirSync(join(home, ".mandu"), { recursive: true });
  const env = join(home, "proj", ".env");
  writeFileSync(env, `STRIPE_KEY=${ENV_VALUE}\n`);
  const policyPath = join(home, ".mandu", "policy.yaml");
  const VALID = ["version: 1", "paths:", `  - { path: "${env}", level: no-model }`, ""].join("\n");
  writeFileSync(policyPath, VALID);
  const dataSock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 30, adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    secretsArbiter: wired.secrets,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(home, ".mandu"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const noValue = (body: string, where: string) => {
    assert.ok(!body.includes(ENV_VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the file's value`);
    assert.doesNotMatch(body, TOKEN, `${where} carries no token`);
  };
  const read = async (path: string): Promise<string> => {
    const r = await pageFetch(base + path, { headers: { Cookie: ADMIN_COOKIE } });
    const body = await r.text();
    assert.equal(r.status, 200, `${path}: ${body}`);
    noValue(body, path);
    return body;
  };
  const homeAnswer = async (): Promise<{ body: string; policyFile: HomePolicyFile | undefined }> => {
    const body = await read("/api/home");
    return { body, policyFile: (JSON.parse(body) as { policyFile?: HomePolicyFile }).policyFile };
  };
  const until = async (ok: () => Promise<boolean>, what: string): Promise<void> => {
    for (let i = 0; i < 400; i++) { if (await ok()) return; await new Promise((r) => setTimeout(r, 25)); }
    assert.fail(`never ${what}`);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  type Doc = any;
  const card = (doc: Doc) => doc.getElementById("home-policy-refused");
  const heroDrawn = (doc: Doc) => doc.getElementById("hero-headline").textContent !== "";
  const REFUSED_NAME = "Rules, Mandu did not take your last edit to policy.yaml";
  /** The top bar's Rules mark: its text (null while hidden), the link's name and title. */
  const rulesMark = (doc: Doc) => {
    const m = doc.getElementById("nav-rules-unsaved");
    const link = m.parentElement;
    for (const said of [link.getAttribute("aria-label") ?? "", link.getAttribute("title") ?? ""]) {
      noValue(said, "the Rules link's name and title");
      assert.ok(!said.includes("no-modle"), "the Rules link's name carries no problem's words");
    }
    return { text: m.hidden ? null : m.textContent, name: link.getAttribute("aria-label"), title: link.getAttribute("title") };
  };
  const poll = async (doc: Doc) => {
    doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); // a poll, as on coming back to the tab
    await new Promise((res) => setTimeout(res, 50));
  };
  try {
    // ── H1: a valid file ──
    const first = (await homeAnswer()).policyFile;
    assert.deepEqual(first && { valid: first.valid, path: first.path, problemCount: first.problemCount }, { valid: true, path: policyPath, problemCount: 0 }, "Home carries the file as the arbiter reads it");
    await servedProductPage(base, "/", heroDrawn, (doc: Doc) => {
      assert.equal(card(doc).hidden, true, "nothing refused: no card");
      assert.deepEqual(rulesMark(doc), { text: null, name: null, title: null }, "nothing refused: a plain Rules link");
      noValue(doc.body.textContent, "the rendered Home");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // ── H2: a hand edit with a mistake, refused by the arbiter ──
    writeFileSync(policyPath, ["version: 1", "paths:", `  - { path: "${env}", level: no-modle }`, ""].join("\n"));
    let refused: { body: string; policyFile: HomePolicyFile | undefined } | null = null;
    await until(async () => { const a = await homeAnswer(); if (a.policyFile?.valid === false) refused = a; return refused !== null; }, "saw the arbiter refuse the broken file on /api/home");
    const r = refused as unknown as { body: string; policyFile: HomePolicyFile };
    assert.equal(r.policyFile.path, policyPath);
    assert.ok(r.policyFile.problemCount > 0, "the arbiter found a problem, and Home counts it");
    assert.equal(typeof r.policyFile.refusedAt, "number");
    assert.deepEqual(Object.keys(r.policyFile).sort(), ["path", "problemCount", "refusedAt", "valid"], "the count, never the problems");
    assert.ok(!r.body.includes("no-modle"), "no problem text (it echoes the file) reaches /api/home");
    // The Approvals page, open meanwhile: its Rules link is marked.
    const marked = (doc: Doc) => !doc.getElementById("nav-rules-unsaved").hidden;
    await servedProductPage(base, "/approvals", marked, async (approvals: Doc) => {
      assert.equal(approvals.querySelector('#nav a[aria-current="page"]').getAttribute("data-page-link"), "approvals", "on Approvals");
      assert.deepEqual(rulesMark(approvals), { text: "!", name: REFUSED_NAME, title: REFUSED_NAME }, "the Approvals page's Rules link says the edit was refused");
      assert.equal(approvals.getElementById("nav-rules-unsaved").className, "unsaved-mark refused");
      assert.match(approvals.getElementById("nav-rules-unsaved").parentElement.getAttribute("href"), /\/rules$/, "the link opens Rules, whose refused line lists the problems");
      noValue(approvals.body.textContent, "the rendered Approvals");
      await servedProductPage(base, "/", (doc: Doc) => heroDrawn(doc) && !card(doc).hidden, async (doc: Doc) => {
        assert.deepEqual(rulesMark(doc), { text: "!", name: REFUSED_NAME, title: REFUSED_NAME }, "Home's top bar too");
        assert.equal(doc.getElementById("policy-refused-headline").textContent, "Mandu did not take your last edit to policy.yaml");
        const sentence = doc.getElementById("policy-refused-sentence").textContent as string;
        assert.match(sentence, /^~\/\.mandu\/policy\.yaml has a mistake, so Mandu is still using the last version that worked \(since [A-Z][a-z]{2} \d{1,2}, \d{2}:\d{2}\)\. The file has \d+ problems?\./);
        assert.ok(sentence.includes(`The file has ${r.policyFile.problemCount} problem`), sentence);
        assert.equal(doc.getElementById("policy-refused-fix").textContent, "See what is wrong in Rules, then save the file again.");
        assert.match(doc.querySelector("#policy-refused-fix a").getAttribute("href"), /\/rules$/);
        assert.ok(!doc.body.textContent.includes("no-modle"), "Home draws no problem text");
        noValue(doc.body.textContent, "the rendered Home");

        // ── H3: fixed; the next poll of this page takes the card away ──
        writeFileSync(policyPath, VALID.replace("level: no-model", "level: no-model, bindings: [api.stripe.com]"));
        await until(async () => (await homeAnswer()).policyFile?.valid === true, "saw the arbiter take the fixed file");
        await until(async () => { await poll(doc); return card(doc).hidden === true; }, "hid the card on a poll after the fix");
        assert.deepEqual(rulesMark(doc), { text: null, name: null, title: null }, "and Home's Rules mark");
        // The Approvals page's next poll takes the mark away too.
        await until(async () => { await poll(approvals); return rulesMark(approvals).text === null; }, "hid the Rules mark on Approvals on a poll after the fix");
        assert.deepEqual(rulesMark(approvals), { text: null, name: null, title: null }, "a plain Rules link again");
      }, { headers: { Cookie: ADMIN_COOKIE } });
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // ── H4: the oracle ──
    for (const route of ["/api/home", "/api/policy/panel", "/rules", "/approvals", "/"]) await read(route);
  } finally {
    await dashboard.close();
    wired?.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
