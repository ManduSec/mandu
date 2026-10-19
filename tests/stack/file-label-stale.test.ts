/**
 * file-label-stale e2e — a label chosen on the Rules page names the file
 * rule as the page read it, and a change to that same rule landing in
 * between is never overwritten (policy-surface.md §8.4.6 "An item-level
 * version"; dashboard.md §4.25m *A save names the rules as they were
 * read*). Mandu-new.
 *
 * Across the real components: a REAL ArbiterServer (secrets) with a
 * file-backed policy.yaml holding two file rules (a `.env` at No AI that
 * may go to api.stripe.com, a notes file at Any AI), a real DashboardServer
 * over the production adapter (`makeApprovalsArbiter`) serving the Rules
 * page (its own index.html and home.js in jsdom, every request through
 * pageFetch):
 *
 *   F1  the page reads Your rules; on the `.env` the person chooses Any AI
 *       (its hosts carried over from the row); meanwhile ANOTHER rule (the
 *       notes file) changes: Save asks, Save anyway applies — another
 *       rule's change does not refuse it, and that change is kept;
 *   F2  the person chooses Not secret on the `.env`; meanwhile a change to
 *       that same rule lands (back to No AI with no host, as a second
 *       window or a hand edit would): Save is refused in the page's words,
 *       the choice still waits in Changes to save, Your rules is read again;
 *   F3  THE INVARIANT: nothing was written — policy.yaml and the law keep
 *       the stricter, newer rule, nothing waits in Approvals; the route's
 *       own answer to the same stale change is 409 `stale`;
 *   F4  the person saves again: asked again, then applied against the rule
 *       as it is now;
 *   F5  the oracle: no page or answer carries the file's value or a token.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../arbiter/policy/load-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const VALUE = `sk_live_fileLabelStaleCanary_${process.pid}_00001`;
/** A minted token (the panel's own help text names the `$MDU:` form). */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

test("the Rules page over the real arbiter: a label chosen on a rule read before another change to that rule is refused, nothing overwritten; another rule's change does not refuse it", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-file-label-stale-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const env = join(home, "proj", ".env");
  const notes = join(home, "proj", "notes.md");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  writeFileSync(notes, "notes\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "paths:",
    `  - { path: "${env}", level: no-model, bindings: [api.stripe.com], recursive: false }`,
    `  - { path: "${notes}", level: any-model, recursive: false }`,
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
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const call = async (method: string, path: string, body?: unknown) => {
    const r = await pageFetch(base + path, { method, headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) as Record<string, unknown> };
  };
  /** Another window, or a hand edit the arbiter loaded: a change on the admin channel. */
  const elsewhere = async (edits: unknown[]) => {
    const r = await admin.policyPropose({ edits, requestedBy: "rules-page" });
    if (r.applied) return;
    assert.ok("proposalId" in r, JSON.stringify(r));
    const done = await admin.resolvePolicyProposal(r.proposalId, "approved", "human:rules-page");
    assert.ok(done.changeId, JSON.stringify(done));
  };
  const ruleOf = async (path: string) => ((await admin.policyDocument()).inForce as PolicyFileConfig | null)?.paths?.find((p) => p.path === path);
  const pages: string[] = [];
  try {
    const ruleRow = (doc: Doc, path: string) => doc.querySelector(`#files-tree .row.file-rule[data-path="${path}"]`);
    const choose = (doc: Doc, path: string, level: string) => {
      const m = ruleRow(doc, path).querySelector("select.label-select");
      m.value = level;
      m.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
    };
    const saveAndConfirm = async (doc: Doc) => {
      doc.getElementById("files-save").click();
      await waitWhile(() => doc.getElementById("files-confirm").hidden !== false && (doc.getElementById("lock-error").textContent ?? "") === "");
    };

    await servedProductPage(base, "/rules", (doc: Doc) => !!ruleRow(doc, env) && !!ruleRow(doc, notes), async (doc: Doc) => {
      // F1: the notes rule changes meanwhile; the save on the .env applies.
      choose(doc, env, "any-model");
      await waitWhile(() => !doc.querySelector("#files-pending-list li"));
      await elsewhere([{ op: "lock-path", path: notes, level: "no-model", recursive: false }]);
      await saveAndConfirm(doc);
      assert.equal(doc.getElementById("files-confirm").hidden, false, `a weaker change asks first: ${doc.getElementById("lock-error").textContent}`);
      doc.getElementById("files-save").click();
      await waitWhile(() => doc.getElementById("files-pending").hidden !== true);
      assert.deepEqual(await ruleOf(env), { path: env, level: "any-model", bindings: ["api.stripe.com"], recursive: false }, "another rule's change does not refuse the save; the hosts carried over");
      assert.equal((await ruleOf(notes))?.level, "no-model", "and that change is kept");

      // F2: the same rule changes meanwhile; Save is refused.
      // Your rules read again after the save: the row shows the rule as saved, nothing waiting.
      const drawn = (level: string) => {
        const pick = ruleRow(doc, env)?.querySelector(".label-pick");
        return !!pick && !pick.classList.contains("waiting") && pick.getAttribute("data-level") === level;
      };
      await waitWhile(() => !drawn("any-model"));
      choose(doc, env, "public");
      await waitWhile(() => !doc.querySelector("#files-pending-list li"));
      await elsewhere([{ op: "lock-path", path: env, level: "no-model", recursive: false }]);
      const bytes = readFileSync(policyPath, "utf8");
      doc.getElementById("files-save").click();
      await waitWhile(() => (doc.getElementById("lock-error").textContent ?? "") === "");
      assert.equal(doc.getElementById("lock-error").textContent,
        "~/proj/.env was changed somewhere else while you were choosing, so nothing was saved. Your choice still waits in Changes to save: look at the label as it is now, then save again.");
      assert.equal(doc.getElementById("files-pending").hidden, false, "the choice still waits");
      assert.equal(doc.querySelectorAll("#files-pending-list li").length, 1);
      await waitWhile(() => !/^~\/proj\/\.env No AI → /.test(doc.querySelector("#files-pending-list li")?.textContent ?? ""));
      assert.match(doc.querySelector("#files-pending-list li").textContent, /^~\/proj\/\.env No AI → Not secret/, "Changes to save says what it changes from now");
      assert.equal(ruleRow(doc, env).querySelector(".label-pick").getAttribute("data-level"), "public", "the choice still shows as waiting on its row");

      // F3: the invariant — nothing was written; the stricter, newer rule stands.
      assert.equal(readFileSync(policyPath, "utf8"), bytes, "policy.yaml is unchanged");
      assert.deepEqual(await ruleOf(env), { path: env, level: "no-model", recursive: false }, "the stricter rule stays in force");
      assert.deepEqual((await admin.policyProposals("pending")).proposals, [], "nothing waits in Approvals");
      const raw = await call("POST", "/api/files/labels", { changes: [{ path: env, level: "public", recursive: false, version: "0".repeat(32) }], expected: [] });
      assert.equal(raw.status, 409, JSON.stringify(raw.body));
      assert.equal(raw.body["stale"], true);
      assert.equal(readFileSync(policyPath, "utf8"), bytes, "the route wrote nothing either");

      // F4: saved again: asked again, then applied against the rule as it is now.
      await saveAndConfirm(doc);
      assert.equal(doc.getElementById("files-confirm").hidden, false, `asked again: ${doc.getElementById("lock-error").textContent}`);
      doc.getElementById("files-save").click();
      await waitWhile(() => doc.getElementById("files-pending").hidden !== true);
      assert.equal((await ruleOf(env))?.level, "public");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // F5: the oracle.
    assert.equal((await call("GET", "/api/files/list?path=~/proj")).status, 200);
    for (const text of [...pages, ...bodies]) {
      assert.ok(!text.includes(VALUE), "CONFIDENTIALITY VIOLATION: a page or an answer carries the file's value");
      assert.doesNotMatch(text, TOKEN, "no page or answer carries a token");
    }
  } finally {
    await dashboard.close();
    wired.close();
    admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
