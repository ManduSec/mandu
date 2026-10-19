/**
 * no-word-alone — the served product page balances its headings and labels
 * and lets its prose move a word down, so a line of words does not end with
 * one word alone, across the REAL components (dashboard.md §4.25u *No word
 * alone on a last line*). Mandu-new.
 *
 * Until 2026-10-17 headless Chromium drew Approvals' cell label "If you
 * click Allow once or Always allow" with "Allow" alone on its second line at
 * 1280 px, and at 390 px ten notes and rows (Settings' notes, History's
 * lede, a rule-change row, a glossary entry) ended on one word. Here a real
 * ArbiterServer runs at the `secrets` axes with a policy.yaml on disk; it
 * registers `~/mandu-try/.env`, its real egress gate refuses the key's send
 * to `api.stripe.com` and asks for an OK, and the agent (data plane) asks to
 * loosen a rule (it waits). A real DashboardServer over the production
 * adapter (`makeApprovalsArbiter`) serves, signed in, under its served
 * styles at 390 px:
 *
 *   N1  Approvals: the page's heading, the send card's three cell labels
 *       (the third "If you click Allow once or Always allow") and the rule
 *       change's *This would let* label are `balance`; the card's cells and
 *       the change's rows are `pretty`; a kept-whole code in them stays
 *       `nowrap`;
 *   N2  Rules, History and Settings: their notes, lede and glossary
 *       entries are `pretty`, their headings `balance`;
 *   N3  the oracle: no page or answer read here carries the key's value,
 *       and none a token (`$MDU`).
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is how the served page wraps its words; the stack supplies the
 * real requests the page draws.
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
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = `1791880000-${process.pid}`;
const VALUE = `sk_live_noWordAloneCanary_${process.pid}_000000`;
const LABELS = ["Why it stopped", "What the AI has now", "If you click Allow once or Always allow"];

test("the served pages balance their headings and labels and let their prose move a word down, on the real stack, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-no-word-alone-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try"), { recursive: true });
  const env = join(home, "mandu-try", ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(sock);
  await gate.connect();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { Cookie: ADMIN_COOKIE };
  const noValue = (body: string, where: string) => {
    assert.ok(!body.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the value`);
    assert.doesNotMatch(body, /\$MDU/, `${where} carries no token`);
  };
  const read = async (path: string): Promise<string> => {
    const r = await pageFetch(base + path, { headers: signedIn });
    const body = await r.text();
    assert.equal(r.status, 200, `${path}: ${body}`);
    noValue(body, path);
    return body;
  };
  try {
    // The key's send waits for an OK; the agent's loosening waits too.
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const d = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: "api.stripe.com", sessionKey: SESSION, scheme: "https" });
    assert.equal(d.allow, false, "the real gate refuses api.stripe.com");
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "and asks for an OK");
    const p = await gate.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.stripe.com", "deploy-hooks.example.com"] }], sessionKey: SESSION, reason: "deploy needs it" });
    assert.ok("proposalId" in p && p.proposalId, `the change waits for the human: ${JSON.stringify(p)}`);

    const sheets = `${await read("/mandu.css")}\n${await read("/app.css")}`;
    const css = resolveCssVars(stylesAt(sheets, 390));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type El = any;
    const wrapOf = (el: El): string => el.ownerDocument.defaultView.getComputedStyle(el).getPropertyValue("text-wrap-style");
    const all = (els: El[], want: string, what: string) => {
      assert.ok(els.length > 0, `${what}: drawn`);
      for (const el of els) assert.equal(wrapOf(el), want, `${what} "${el.textContent.trim().slice(0, 60)}": ${want}`);
    };

    // ── N1: Approvals ──
    const ready = (doc: El) => doc.querySelectorAll("#approvals-waiting .ask .ask-detail .k").length === 3
      && !!doc.querySelector(`#approvals-proposals .proposal[data-id="${p.proposalId}"] .proposal-rows li`);
    await servedProductPage(base, "/approvals", ready, (doc: El) => {
      const card = doc.querySelector("#approvals-waiting .ask");
      const labels = [...card.querySelectorAll(".ask-detail .k")];
      assert.deepEqual(labels.map((k: El) => k.firstChild.textContent), LABELS, "the card's three labels");
      all(labels, "balance", "a cell's label");
      all([...card.querySelectorAll(".ask-detail .v")], "pretty", "a cell");
      const change = doc.querySelector(`#approvals-proposals .proposal[data-id="${p.proposalId}"]`);
      all([...change.querySelectorAll(".proposal-k")], "balance", "the change's label");
      all([...change.querySelectorAll(".proposal-rows li")], "pretty", "the change's row");
      all([...doc.querySelectorAll("#page-approvals h1, #page-approvals h2")].filter((h: El) => !h.closest("[hidden]")), "balance", "a heading");
      const whole = [...doc.querySelectorAll("#page-approvals code.code-whole")];
      assert.ok(whole.length > 0, "a kept-whole code is drawn");
      for (const c of whole) assert.equal(doc.defaultView.getComputedStyle(c).whiteSpace, "nowrap", `${c.textContent}: still on one line`);
      noValue(doc.body.textContent, "the rendered Approvals page");
    }, { headers: signedIn, css });

    // ── N2: Rules, History and Settings ──
    for (const [path, view] of [["/rules", "#page-rules"], ["/history", "#page-history"], ["/settings", "#page-settings"]] as const) {
      await servedProductPage(base, path, (doc: El) => !!doc.querySelector(view), (doc: El) => {
        const v = doc.querySelector(view);
        all([...v.querySelectorAll("p")], "pretty", `${path}: a note`);
        all([...v.querySelectorAll("h1, h2")], "balance", `${path}: a heading`);
        if (path === "/rules") all([...v.querySelectorAll("#rules-glossary dd")], "pretty", "a glossary entry");
        noValue(doc.body.textContent, `the rendered ${path} page`);
      }, { headers: signedIn, css });
    }

    // ── N3: the oracle ──
    for (const route of ["/api/home", "/api/policy/proposals?status=pending", "/approvals", "/rules", "/settings", "/history", "/"]) await read(route);
  } finally {
    await dashboard.close();
    wired?.close();
    gate.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
