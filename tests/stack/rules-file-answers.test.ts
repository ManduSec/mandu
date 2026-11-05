/**
 * rules-file-answers — a file's row under Rules › Your rules names your
 * answers about sending it, across the REAL components (dashboard.md §4.25n
 * *A file's row names your answers about it*, 2026-10-30). Mandu-new.
 *
 * A real ArbiterServer reading a policy FILE (`secrets` axes) labels a
 * `.env` `no-model` with no hosts; its real egress gate asks about the
 * file's key at two hosts; one is answered Always allow and one Block
 * through the real admin client. A real DashboardServer over the production
 * adapter (`makeApprovalsArbiter`) serves the panel and the page:
 *
 *   F1  /api/policy/panel: each answer carries the file it came from as
 *       `origin`, the absolute path, from the arbiter's read-time provenance;
 *   F2  the served Rules page: the `.env` row's second menu still reads
 *       *Needs your OK*, and the line under it names both hosts with their
 *       effects, newest first as Sending data lists them, each a link to
 *       its answer's row there, the menu described by the line;
 *   F3  the oracle: neither the panel nor the drawn page carries the key's
 *       value, nor a `$MDU` token on the page.
 *
 * And the sends of it that wait (the same section, *And the sends of it that
 * wait*): the real gate asks about the key at a host and nobody answers.
 *
 *   W1  /api/policy/panel: the waiting question carries the file as
 *       `origin`, under the id Approvals uses;
 *   W2  the served Rules page names that host under *Waiting for your
 *       answer*, a link to `/approvals/<id>`, and no answers line;
 *   W3  after a Block through the admin client, a new Rules read names it
 *       under *Your answers* as Always blocked and the waiting line is gone;
 *   W4  the oracle: no read carries the key's value, nor a `$MDU` token on
 *       the page.
 *
 * And it follows the questions waiting while Rules stays open (queue item
 * #284): the served page is open on Rules with nothing waiting.
 *
 *   P1  the real gate asks about the key at a host: one Home poll later the
 *       row names it, without a reload, with no "Your rules changed" line;
 *   P2  answered Allow once through the admin client: one poll later the
 *       line is gone, and no answers line (a once answer is not a standing
 *       one);
 *   P3  the oracle: the page carries neither the key's value nor a token.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { PolicyPanelVM } from "../../dashboard/src/view-model/policy-panel.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const KEY_VALUE = `sk_live_rulesFileAnswersCanary${process.pid}00000000`;
const SESSION = "1791300000-186";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
interface Stack { env: string; base: string; gate: ArbiterClient; admin: ArbiterClient; keySym: string }

/** A real arbiter reading a policy file that labels `~/proj/.env` `no-model`
 *  with no hosts, the key's symbol registered, and a real dashboard over the
 *  production adapter; `fn` runs against them, then all of it closes. */
async function withStack(fn: (s: Stack) => Promise<void>): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-file-answers-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const env = join(home, "proj", ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\nDEBUG=1\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - { path: "${env}", level: no-model }\n`);
  const dataSock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock); await gate.connect();
  const admin = new ArbiterClient(adminSock); await admin.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  try {
    // The registered `.env`: its key gets its own symbol.
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    await fn({ env, base, gate, admin, keySym: keySym! });
  } finally {
    await dashboard.close();
    wired?.close();
    gate.close(); admin.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** The real gate asks about the key at `dest`, a host no rule binds it to; the question's id. */
async function ask(s: Stack, dest: string): Promise<string> {
  const d = await s.gate.desymbolizationDecision({ symbol: s.keySym, boundary: "network", destination: dest, sessionKey: SESSION, scheme: "https" });
  assert.equal(d.allow, false, dest);
  assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, dest);
  return String((d as { approvalId?: string }).approvalId);
}
/** `/api/policy/panel` as the page reads it, checked for the key's value (the oracle). */
async function readPanel(s: Stack): Promise<PolicyPanelVM> {
  const res = await pageFetch(`${s.base}/api/policy/panel`, { headers: { Cookie: ADMIN_COOKIE } });
  const body = await res.text();
  assert.equal(res.status, 200, body);
  assert.ok(!body.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: /api/policy/panel carries the key's value");
  return (JSON.parse(body) as { panel: PolicyPanelVM }).panel;
}
const fileRowOf = (doc: Doc, env: string) => ([...doc.querySelectorAll("#files-tree .row.file-rule")] as Doc[]).find((r) => r.getAttribute("data-path") === env);
/** The drawn page carries neither the key's value nor a token (the oracle). */
function noValueOn(doc: Doc): void {
  const page = doc.body.textContent ?? "";
  assert.ok(!page.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: the rendered page carries the key's value");
  assert.doesNotMatch(page, /\$MDU/, "the page carries no token");
}

test("a file's row names the hosts your answers allowed and blocked for it, under its unchanged menu, and carries no value (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  await withStack(async ({ env, base, gate, admin, keySym }) => {
    // The real gate asks at two hosts no rule binds it to; one answer each.
    const asked: Record<string, string> = {};
    for (const dest of ["api.stripe.com", "hooks.zapier.com"]) {
      const d = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: dest, sessionKey: SESSION, scheme: "https" });
      assert.equal(d.allow, false, dest);
      assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, dest);
      asked[dest] = String((d as { approvalId?: string }).approvalId);
    }
    await admin.resolveEgressApproval(asked["api.stripe.com"]!, true);
    await admin.resolveEgressApproval(asked["hooks.zapier.com"]!, false);

    // F1: each answer names the file it came from, absolute.
    const panelRes = await pageFetch(`${base}/api/policy/panel`, { headers: { Cookie: ADMIN_COOKIE } });
    const panelBody = await panelRes.text();
    assert.equal(panelRes.status, 200, panelBody);
    const panel = (JSON.parse(panelBody) as { panel: PolicyPanelVM }).panel;
    for (const [dest, status] of [["api.stripe.com", "approved"], ["hooks.zapier.com", "denied"]] as const) {
      const row = panel.queue.find((r) => r.id === asked[dest]);
      assert.ok(row, `${dest}: the answer is in the panel`);
      assert.equal(row!.status, status);
      assert.equal(row!.scope, "always");
      assert.equal(row!.where, "network");
      assert.equal(row!.origin, env, `${dest}: its origin is the file`);
    }
    // F3: names, never the value.
    assert.ok(!panelBody.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: /api/policy/panel carries the key's value");

    // F2: the served Rules page.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    const fileRow = (doc: Doc) => ([...doc.querySelectorAll("#files-tree .row.file-rule")] as Doc[]).find((r) => r.getAttribute("data-path") === env);
    await servedProductPage(base, "/rules", (doc: Doc) => !!fileRow(doc)?.querySelector(".file-answers"), (doc: Doc) => {
      const row = fileRow(doc);
      assert.ok(row, "the .env row is drawn under Files and folders");
      const sel = row.querySelector("select.send-select");
      assert.equal(sel.value, "ask");
      assert.equal(sel.selectedOptions[0].textContent, "Needs your OK", "the menu is unchanged: no host is bound");
      const line = row.querySelector(".file-answers");
      assert.ok(line, "the row names your answers");
      // Newest answer first, as Sending data lists them (the Block was last).
      assert.equal(line.textContent.replace(/\s+/g, " "), "Your answers: hooks.zapier.com Always blocked · api.stripe.com Always allowed");
      assert.deepEqual([...line.querySelectorAll(".outcome")].map((e: Doc) => e.className), ["outcome bad", "outcome ok"]);
      assert.deepEqual([...line.querySelectorAll("a")].map((a: Doc) => a.getAttribute("href")),
        [`/rules#answer-${encodeURIComponent(asked["hooks.zapier.com"]!)}`, `/rules#answer-${encodeURIComponent(asked["api.stripe.com"]!)}`]);
      assert.equal(sel.getAttribute("aria-describedby"), line.id, "a screen reader hears the answers with the menu");
      // Each answer keeps its row under Sending data, where the link goes.
      for (const id of Object.values(asked)) {
        assert.ok(([...doc.querySelectorAll("#rules-list .row[data-rule]")] as Doc[]).some((r) => r.getAttribute("data-rule") === `answer:${id}`), `${id}: listed under Sending data`);
      }
      // F3: the drawn page.
      const page = doc.body.textContent ?? "";
      assert.ok(!page.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: the rendered page carries the key's value");
      assert.doesNotMatch(page, /\$MDU/, "the page carries no token");
    }, { headers: { Cookie: ADMIN_COOKIE } });
  });
});


test("a file's row names the send of it that waits for your answer, a link to Approvals, until a Block moves it to your answers; no value (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  await withStack(async (s) => {
    const id = await ask(s, "evil.example");

    // W1: the waiting question names the file, under the id Approvals uses.
    const waitingRow = (await readPanel(s)).queue.find((r) => r.id === id);
    assert.ok(waitingRow, "the waiting question is in the panel");
    assert.equal(waitingRow!.status, "pending");
    assert.equal(waitingRow!.where, "network");
    assert.equal(waitingRow!.target, "evil.example");
    assert.equal(waitingRow!.origin, s.env, "its origin is the file");

    // W2: the served Rules page names it, a link to its question.
    await servedProductPage(s.base, "/rules", (doc: Doc) => !!fileRowOf(doc, s.env)?.querySelector(".file-waiting"), (doc: Doc) => {
      const row = fileRowOf(doc, s.env);
      assert.ok(row, "the .env row is drawn under Files and folders");
      const sel = row.querySelector("select.send-select");
      assert.equal(sel.selectedOptions[0].textContent, "Needs your OK", "the menu is unchanged");
      const line = row.querySelector(".file-waiting");
      assert.ok(line, "the row names the send that waits");
      assert.equal(line.textContent.replace(/\s+/g, " "), "Waiting for your answer: evil.example");
      assert.deepEqual([...line.querySelectorAll("a")].map((a: Doc) => [a.getAttribute("href"), a.getAttribute("data-ask")]),
        [[`/approvals/${encodeURIComponent(id)}`, id]]);
      assert.equal(row.querySelector(".file-answers"), null, "nothing answered yet");
      assert.equal(sel.getAttribute("aria-describedby"), line.id);
      noValueOn(doc);
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // W3: Blocked; the next Rules read names the answer, and nothing waits.
    await s.admin.resolveEgressApproval(id, false);
    const answered = (await readPanel(s)).queue.find((r) => r.id === id);
    assert.equal(answered?.status, "denied");
    await servedProductPage(s.base, "/rules", (doc: Doc) => !!fileRowOf(doc, s.env)?.querySelector(".file-answers"), (doc: Doc) => {
      const row = fileRowOf(doc, s.env);
      assert.ok(row);
      assert.equal(row.querySelector(".file-answers")?.textContent.replace(/\s+/g, " "), "Your answers: evil.example Always blocked");
      assert.equal(row.querySelector(".file-waiting"), null, "the waiting line is gone");
      noValueOn(doc);
    }, { headers: { Cookie: ADMIN_COOKIE } });
  });
});

test("a file's row follows a send of it that starts waiting, then one answered Allow once, at the next Home poll without a reload; no value (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  await withStack(async (s) => {
    let homes = 0;
    let out = 0; // the page's reads still out
    const waitLine = (doc: Doc) => fileRowOf(doc, s.env)?.querySelector(".file-waiting") ?? null;
    // The page polls only when told (setInterval is off): a return to the
    // tab is one Home poll.
    const pollOnce = async (doc: Doc, until: () => boolean) => {
      const was = homes;
      doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      await waitWhile(() => homes === was || !until());
      assert.equal(homes, was + 1, "one Home poll");
    };
    await servedProductPage(s.base, "/rules", (doc: Doc) => !!fileRowOf(doc, s.env) && homes > 0, async (doc: Doc) => {
      // A poll already compared, as a page left open has.
      await pollOnce(doc, () => true);
      // Its answer drawn and compared, and no read of the page's opening
      // still out (one answered after the send would show it unpolled).
      await waitWhile(() => out > 0);
      assert.equal(waitLine(doc), null, "nothing waits yet");

      // P1: a send of it starts waiting.
      const id = await ask(s, "evil.example");
      await pollOnce(doc, () => !!waitLine(doc));
      const line = waitLine(doc);
      assert.ok(line, "the row names the send that waits, without a reload");
      assert.equal(line.textContent.replace(/\s+/g, " "), "Waiting for your answer: evil.example");
      assert.equal(line.querySelector("a")?.getAttribute("href"), `/approvals/${encodeURIComponent(id)}`);
      assert.equal(fileRowOf(doc, s.env).querySelector("select.send-select").getAttribute("aria-describedby"), line.id);
      assert.equal(doc.getElementById("rules-changed").hidden, true, "your rules did not change: no line says so");
      noValueOn(doc);

      // P2: answered Allow once elsewhere.
      await s.admin.resolveEgressApproval(id, true, "once");
      await pollOnce(doc, () => !waitLine(doc));
      assert.equal(waitLine(doc), null, "the line is gone");
      assert.equal(fileRowOf(doc, s.env).querySelector(".file-answers"), null, "a once answer is not a standing one");
      assert.equal(doc.getElementById("rules-changed").hidden, true);
      // P3: the oracle.
      noValueOn(doc);
    }, {
      headers: { Cookie: ADMIN_COOKIE },
      beforeScripts: (w) => {
        const f = w.fetch;
        w.fetch = (url: string, init?: RequestInit) => {
          if (/\/api\/home(?:\?|$)/.test(url)) homes++;
          out++;
          return f(url, init).finally(() => { out--; });
        };
      },
    });
  });
});
