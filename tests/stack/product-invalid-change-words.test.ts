/**
 * product-invalid-change-words.test — on the product page's Rules, a change
 * the REAL arbiter finds not valid says why, across the real components
 * (dashboard.md §4.25 "Refusals", *A change that is not valid says why*).
 * Mandu-new.
 *
 * The arbiter previews every change of the rules before anything changes,
 * and the dashboard answers one it finds not valid 422 with the arbiter's
 * problems. Until 2026-10-15 the page showed only "this change is not
 * valid": a pattern typed in Add a rule that the arbiter cannot use (an
 * unclosed `[`, a pattern matching every path) was refused with no reason,
 * and Changes to save said it in the arbiter's own terms ("withEdits:
 * paths[6].path: pattern "/home/…": …").
 * This file pins home.js's reading of the problems to the real arbiter's
 * lines: were the arbiter's words to change shape, the page would show them
 * as written, and V1 and V2 fail.
 *
 *   a real ArbiterServer (`secrets` axes) labelling a `.env` no-model; a
 *   real DashboardServer over the production adapter (`makeApprovalsArbiter`),
 *   its home a temp folder; the served Rules page (its own index.html and
 *   home.js in jsdom), signed in:
 *
 *   V1  `~/notes/[draft` typed and chosen No AI: Changes to save says
 *       "What this changes could not be worked out: ~/notes/[draft: '[' in
 *       '[draft' is never closed (a literal '[' is '\[')."; Save: "Not
 *       saved: ~/notes/[draft: …" in the same words; the change stays to be
 *       saved; policy.yaml unchanged;
 *   V2  `/**` typed as well: both lines name both problems, one after the
 *       other, the second's own "; " kept; policy.yaml unchanged;
 *   V3  the typed path made valid (`~/notes/draft`), Save: saved, and
 *       policy.yaml has the rule (the refusal left nothing behind);
 *   V4  the oracle: no rendered page or answer carries the labelled value,
 *       the admin token or the session secret.
 *
 * Axes: secrets (stated). What is under test is the served script.
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
import { ADMIN_COOKIE, ADMIN_OPTS, ADMIN_TOKEN, SESSION_SECRET } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const CANARY = `PRODUCT_INVALID_CHANGE_WORDS_CANARY_${process.pid}_7d2a`;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

test("the served Rules page says why the real arbiter refuses a typed pattern, the path as the page shows it, and saves once it is valid (real arbiter, adapter and server; secrets axes)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-invalid-change-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "notes"), { recursive: true });
  const env = join(home, ".env");
  writeFileSync(env, `API_TOKEN=${CANARY}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
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
  const pages: string[] = [];
  const answers: string[] = [];
  const unhandled: unknown[] = [];
  const onUnhandled = (e: unknown) => { unhandled.push(e); };
  process.on("unhandledRejection", onUnhandled);
  try {
    const policyBefore = readFileSync(policyPath, "utf8");
    await servedProductPage(base, "/rules", (doc: Doc) => !!doc.getElementById("rules-add") && doc.querySelectorAll("#files-tree .row.file-rule").length > 0, async (doc: Doc) => {
      const w = doc.defaultView;
      // Every answer the page reads, kept for the oracle.
      const fetch0 = w.fetch;
      w.fetch = async (url: string, init?: RequestInit) => {
        const r = await fetch0(url, init);
        return { ...r, json: async () => { const v = await r.json(); answers.push(JSON.stringify(v)); return v; } };
      };
      w.confirm = () => true;
      doc.getElementById("rules-add").click();
      await waitWhile(() => doc.getElementById("lock-form").hidden || doc.querySelectorAll("#files-list .row.file").length === 0);
      const typeAndChoose = async (path: string) => {
        doc.getElementById("lock-path").value = path;
        doc.getElementById("files-go").dispatchEvent(new w.Event("submit", { cancelable: true }));
        await waitWhile(() => !([...doc.querySelectorAll("#files-list .row.file:not(.up)")] as Doc[]).some((r) => (r.querySelector(".file-name")?.textContent ?? "").includes(path.replace(/^~\//, ""))));
        const row = ([...doc.querySelectorAll("#files-list .row.file:not(.up)")] as Doc[]).find((r) => (r.querySelector(".file-name")?.textContent ?? "").includes(path.replace(/^~\//, "")));
        const sel = row.querySelector("select.label-select");
        sel.value = "no-model";
        sel.dispatchEvent(new w.Event("change", { bubbles: true }));
      };
      const save = async () => {
        const err = doc.getElementById("lock-error");
        err.textContent = "…";
        doc.getElementById("files-save").click();
        await waitWhile(() => err.textContent === "…" || err.textContent === "");
        return err.textContent as string;
      };

      const impact = async () => {
        const box = doc.getElementById("files-impact");
        await waitWhile(() => box.hidden || /^Working out|^$/.test(box.textContent));
        return box.textContent as string;
      };

      // V1: an unclosed '['. Changes to save says why first, then Save.
      await typeAndChoose("~/notes/[draft");
      assert.equal(await impact(), "What this changes could not be worked out: ~/notes/[draft: '[' in '[draft' is never closed (a literal '[' is '\\[').", "the arbiter's reason before Save, in the same words");
      const v1 = await save();
      assert.equal(v1, "Not saved: ~/notes/[draft: '[' in '[draft' is never closed (a literal '[' is '\\[').", "the arbiter's reason, the path as the page shows it");
      assert.equal(doc.getElementById("files-pending").hidden, false, "the change stays to be saved");
      assert.equal(readFileSync(policyPath, "utf8"), policyBefore, "policy.yaml unchanged");

      // V2: a pattern matching every path, as well: both problems.
      await typeAndChoose("/**");
      await waitWhile(() => !doc.getElementById("files-impact").textContent.includes("/**"));
      assert.equal(await impact(), "What this changes could not be worked out: ~/notes/[draft: '[' in '[draft' is never closed (a literal '[' is '\\['); /**: the pattern matches every path on the machine; label a directory instead.", "the line is cut at each problem, never at the '; ' inside one");
      const v2 = await save();
      assert.equal(v2, "Not saved: ~/notes/[draft: '[' in '[draft' is never closed (a literal '[' is '\\['); /**: the pattern matches every path on the machine; label a directory instead.");
      assert.equal(readFileSync(policyPath, "utf8"), policyBefore, "policy.yaml unchanged");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // V3: the same page, once the typed paths are valid, saves.
    await servedProductPage(base, "/rules", (doc: Doc) => !!doc.getElementById("rules-add") && doc.querySelectorAll("#files-tree .row.file-rule").length > 0, async (doc: Doc) => {
      const w = doc.defaultView;
      w.confirm = () => true;
      doc.getElementById("rules-add").click();
      await waitWhile(() => doc.getElementById("lock-form").hidden || doc.querySelectorAll("#files-list .row.file").length === 0);
      doc.getElementById("lock-path").value = "~/notes/draft";
      doc.getElementById("files-go").dispatchEvent(new w.Event("submit", { cancelable: true }));
      const rowOf = () => ([...doc.querySelectorAll("#files-list .row.file:not(.up)")] as Doc[]).find((r) => /notes\/draft/.test(r.querySelector(".file-name")?.textContent ?? ""));
      await waitWhile(() => !rowOf());
      const sel = rowOf().querySelector("select.label-select");
      sel.value = "no-model";
      sel.dispatchEvent(new w.Event("change", { bubbles: true }));
      doc.getElementById("files-save").click();
      await waitWhile(() => !doc.getElementById("files-pending").hidden);
      assert.equal(doc.getElementById("lock-error").textContent, "", "no refusal");
      assert.match(readFileSync(policyPath, "utf8"), new RegExp(`- path: ${join(home, "notes", "draft").replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}\\n\\s+level: no-model`), "policy.yaml has the rule");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // V4: no unhandled rejection; the oracle.
    assert.deepEqual(unhandled, [], "no unhandled rejection");
    for (const [what, text] of [["a rendered page", pages.join("\n")], ["an answer", answers.join("\n")], ["policy.yaml", readFileSync(policyPath, "utf8")]] as const) {
      assert.ok(!text.includes(CANARY), `${what} carries the labelled value`);
      assert.ok(!text.includes(ADMIN_TOKEN), `${what} carries the admin token`);
      assert.ok(!text.includes(SESSION_SECRET), `${what} carries the session secret`);
    }
    assert.ok(answers.length > 0, "(the answers were read)");
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
