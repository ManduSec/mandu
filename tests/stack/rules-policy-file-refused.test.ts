/**
 * rules-policy-file-refused — the Rules page says where your rules file is,
 * and when Mandu refused your last edit to it, across the REAL components
 * and the served page (dashboard.md §4.25 *Rules says where your rules file
 * is*; the banner of policy-surface.md §2.1). Mandu-new.
 *
 * Until 2026-10-25 a hand edit of policy.yaml the arbiter found not valid
 * was refused, the last version that worked stayed in force, and the
 * product page looked as before: a person who typed a lock with a mistake
 * believed the file protected. Here a real ArbiterServer runs at the
 * `secrets` axes with `~/.mandu/policy.yaml` (polled every 30 ms) under the
 * dashboard's home, behind a real DashboardServer over the production
 * adapter (`makeApprovalsArbiter`):
 *
 *   P1  the file holds a valid lock: the served Rules page says "Saved in
 *       ~/.mandu/policy.yaml. Mandu also reads your hand edits to it." and
 *       draws no refused line;
 *   P2  the file is overwritten with a level that does not exist: once the
 *       arbiter has refused the reload, the served Rules page shows the
 *       refused line naming the file, each problem the arbiter reported in
 *       the words of the page, and Your rules still lists the lock in force;
 *   P3  the file is fixed: the refused line goes and the note is back;
 *   P4  the oracle: no page or answer read here carries the locked file's
 *       value, and none a minted token (`$MDU:NAME[hex]`).
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

const ENV_VALUE = `sk_live_rulesPolicyFileCanary_${process.pid}_000000`;
/** A minted token (the panel's own help text names the `$MDU:` form). */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;

type PolicyFile = { path: string | null; found: boolean; valid: boolean; problems: string[]; refusedAt: number | null };

test("the Rules page names your rules file, says when Mandu refused an edit to it and that the rules in force stay, and takes the line away once fixed, on the real stack with its served page; no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-policy-file-"));
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
  const policyFile = async (): Promise<PolicyFile> => (JSON.parse(await read("/api/policy/panel")) as { panel: { policyFile: PolicyFile } }).panel.policyFile;
  const until = async (ok: () => Promise<boolean>, what: string): Promise<void> => {
    for (let i = 0; i < 400; i++) { if (await ok()) return; await new Promise((r) => setTimeout(r, 25)); }
    assert.fail(`the arbiter never ${what}`);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  type Doc = any;
  const ruleRow = (doc: Doc) => doc.querySelector(`#files-tree .row.file-rule[data-path="${env}"]`);
  const SAVED = "Saved in ~/.mandu/policy.yaml. Mandu also reads your hand edits to it.";
  try {
    // ── P1: a valid file ──
    const first = await policyFile();
    assert.equal(first.path, policyPath, "the panel names the file");
    assert.equal(first.valid, true);
    await servedProductPage(base, "/rules", (doc: Doc) => !!ruleRow(doc) && !doc.getElementById("rules-file").hidden, (doc: Doc) => {
      const note = doc.getElementById("rules-file");
      assert.equal(note.textContent, SAVED);
      assert.equal(note.querySelector("code").textContent, "~/.mandu/policy.yaml", "the file under the dashboard's home, with ~");
      assert.equal(doc.getElementById("rules-refused").hidden, true, "nothing refused");
      noValue(doc.body.textContent, "the rendered Rules page");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // ── P2: a hand edit with a mistake, refused by the arbiter ──
    writeFileSync(policyPath, ["version: 1", "paths:", `  - { path: "${env}", level: no-modle }`, ""].join("\n"));
    let refused: PolicyFile | null = null;
    await until(async () => { const f = await policyFile(); if (f.valid === false) refused = f; return refused !== null; }, "refused the broken file");
    const r = refused as unknown as PolicyFile;
    assert.ok(r.problems.length > 0, "the arbiter names the problem");
    assert.equal(typeof r.refusedAt, "number");
    await servedProductPage(base, "/rules", (doc: Doc) => !!ruleRow(doc) && !doc.getElementById("rules-refused").hidden, (doc: Doc) => {
      const box = doc.getElementById("rules-refused");
      assert.equal(box.getAttribute("role"), "status");
      assert.match(box.textContent, /^Your last edit to ~\/\.mandu\/policy\.yaml has a mistake, so Mandu is still using the last version that worked \(since [A-Z][a-z]{2} \d{1,2}, \d{2}:\d{2}\)\. Your rules below are the ones in force\. Fix the file and save it; Mandu reads it again within seconds\./);
      const items = [...box.querySelectorAll("li")].map((li: Doc) => li.textContent as string);
      assert.equal(items.length, Math.min(r.problems.length, 5), `each problem the arbiter reported: ${JSON.stringify(r.problems)}`);
      // Each in the words of the page: the problem without its place in the file.
      r.problems.slice(0, 5).forEach((p, i) => assert.ok(p.endsWith(items[i].replace(/, and \d+ more$/, "")), `${items[i]} is ${p} in the words of the page`));
      assert.ok(items.some((t) => t.includes("no-modle")), `the problem names the mistake: ${JSON.stringify(items)}`);
      assert.equal(doc.getElementById("rules-file").hidden, true, "no Saved in note while the edit is refused");
      assert.ok(ruleRow(doc), "Your rules still lists the lock in force");
      noValue(doc.body.textContent, "the rendered Rules page");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // ── P3: fixed ──
    writeFileSync(policyPath, VALID.replace("level: no-model", "level: no-model, bindings: [api.stripe.com]"));
    await until(async () => (await policyFile()).valid === true, "took the fixed file");
    await servedProductPage(base, "/rules", (doc: Doc) => !!ruleRow(doc) && !doc.getElementById("rules-file").hidden, (doc: Doc) => {
      assert.equal(doc.getElementById("rules-refused").hidden, true, "fixed: the refused line goes");
      assert.equal(doc.getElementById("rules-file").textContent, SAVED);
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // ── P4: the oracle ──
    for (const route of ["/api/home", "/api/policy/panel", "/rules", "/"]) await read(route);
  } finally {
    await dashboard.close();
    wired?.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
