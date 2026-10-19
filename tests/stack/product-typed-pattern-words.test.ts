/**
 * product-typed-pattern-words.test — on the product page's Rules › Add a
 * rule, a typed pattern the REAL arbiter cannot use says why on its own row,
 * across the real components (dashboard.md §4.25 "Refusals", *A typed
 * pattern says why on its row*). Mandu-new.
 *
 * A typed pattern's row asks the dashboard which files it would decide
 * (POST /api/files/impact), which asks the arbiter with the pattern as an
 * edit (`pathLevels` withEdits). The arbiter refuses a pattern it cannot use
 * with its reason, and until 2026-10-15 the row said only "Which files it
 * matches could not be worked out.": the reason came only after a label was
 * chosen or Save pressed (product-invalid-change-words.test.ts). This file
 * pins home.js's reading of the arbiter's lines for the row: were their
 * shape to change, the row would show the hedge or the arbiter's terms, and
 * P1 to P3 fail.
 *
 *   a real ArbiterServer (`secrets` axes) labelling a `.env` no-model; a
 *   real DashboardServer over the production adapter (`makeApprovalsArbiter`),
 *   its home a temp folder with ~/notes/plan.md; the served Rules page (its
 *   own index.html and home.js in jsdom), signed in:
 *
 *   P1  `~/notes/[draft` typed: its row says "Mandu cannot use this pattern:
 *       '[' in '[draft' is never closed (a literal '[' is '\[')." and so
 *       does the opened row; never the arbiter's place or terms;
 *   P2  `/**`: "… the pattern matches every path on the machine; label a
 *       directory instead.";
 *   P3  `~/notes/a**b`: "… '**' must be a whole path segment (got 'a**b');
 *       inside a segment use a single '*'.";
 *   P4  `~/notes/*.md`, which the arbiter can use: "Matches 1 file under …:
 *       ~/notes/plan.md", as before;
 *   P5  typing wrote nothing (policy.yaml unchanged); the oracle: no
 *       rendered page or answer carries the labelled value, the admin token
 *       or the session secret.
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

const CANARY = `PRODUCT_TYPED_PATTERN_WORDS_CANARY_${process.pid}_3c9e`;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

test("the served Rules page says on a typed pattern's row why the real arbiter cannot use it, and what a usable one matches (real arbiter, adapter and server; secrets axes)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-typed-pattern-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "notes"), { recursive: true });
  writeFileSync(join(home, "notes", "plan.md"), "a plan\n");
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
      doc.getElementById("rules-add").click();
      await waitWhile(() => doc.getElementById("lock-form").hidden || doc.querySelectorAll("#files-list .row.file").length === 0);
      /** Type `path` and go; the line the typed row says under "Every file
       *  that matches" once its matches are worked out, and the opened row's. */
      const typed = async (path: string): Promise<{ row: string; opened: string }> => {
        doc.getElementById("lock-path").value = path;
        doc.getElementById("files-go").dispatchEvent(new w.Event("submit", { cancelable: true }));
        const rowOf = () => ([...doc.querySelectorAll("#files-list .row.file:not(.up)")] as Doc[]).find((r) => r.querySelector(".file-name")?.textContent === path);
        await waitWhile(() => !rowOf() || rowOf().querySelectorAll(".file-from").length < 2);
        const line = rowOf().querySelectorAll(".file-from")[1].textContent as string;
        const note = doc.querySelector("#files-list .file-detail .detail-note");
        pages.push(doc.body.textContent ?? "");
        return { row: line, opened: note ? note.textContent : "(no opened row)" };
      };

      // P1: an unclosed '['.
      const p1 = await typed("~/notes/[draft");
      assert.equal(p1.row, "Mandu cannot use this pattern: '[' in '[draft' is never closed (a literal '[' is '\\[').", "the arbiter's reason on the row, alone");
      assert.equal(p1.opened, p1.row, "the opened row says the same");
      // P2: a pattern matching every path.
      const p2 = await typed("/**");
      assert.equal(p2.row, "Mandu cannot use this pattern: the pattern matches every path on the machine; label a directory instead.");
      // P3: '**' inside a segment.
      const p3 = await typed("~/notes/a**b");
      assert.equal(p3.row, "Mandu cannot use this pattern: '**' must be a whole path segment (got 'a**b'); inside a segment use a single '*'.");
      for (const p of [p1, p2, p3]) assert.doesNotMatch(p.row, /paths\[|withEdits|pattern "|could not be worked out/, "never the arbiter's place or terms, never the hedge");
      // P4: a pattern the arbiter can use, as before.
      const p4 = await typed("~/notes/*.md");
      assert.match(p4.row, /^Matches 1 file under .+: ~\/notes\/plan\.md$/, "what a usable pattern matches");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // P5: typing wrote nothing; no unhandled rejection; the oracle.
    assert.equal(readFileSync(policyPath, "utf8"), policyBefore, "policy.yaml unchanged");
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
