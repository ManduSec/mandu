/**
 * approvals-answered-scope.test — Approvals › Answered earlier and Rules ›
 * Your answers name an allow by the scope the arbiter keeps it as, across
 * the REAL components
 * (dashboard.md §4.25 *The allow that reverses a Block names its scope*).
 * Mandu-new.
 *
 * Until 2026-10-28 every reversal of a Block read *Always allow instead*,
 * and a program's send allowed for its session read "Always allowed",
 * though the arbiter keeps those allows for one session or one use. The
 * dashboard mirrors the arbiter's rule (policy-panel.ts `allowKeptAs`);
 * this pins the mirror against the arbiter's real scoping. A real
 * ArbiterServer runs at the `secrets` axes; the guard's production client
 * (the human socket) files three questions through the arbiter's own flow:
 *
 *   - a program in a session that read `.env` sends to hooks.slack.com
 *     (`holder-send:` keyed to that session);
 *   - a program with no session that read it sends to paste.example
 *     (`holder-send:` keyed to none);
 *   - git, handed code on its command line, changes a protected file
 *     (`write:…#run:`, one run of a program).
 *
 * A product-only DashboardServer on the production admin client serves
 * Approvals (its own index.html and home.js in jsdom):
 *
 *   S1  each answered Block over the real route reads *Allow this session
 *       instead*, *Allow once instead*, *Allow once instead*;
 *   S2  pressed over the real route, the arbiter records `always` on the
 *       session's row and `once` on the other two, and the rows read
 *       "Allowed for this session" (kept in Rules, *Block instead*) and
 *       "Allowed once, unused": what each button said;
 *   S3  Rules › Your answers (the third place that draws them, 2026-10-31):
 *       the allowed session row reads "Allowed for this session", a second
 *       send of that session, blocked, "Blocked for this session", and the
 *       two once answers are not listed (Rules keeps standing answers);
 *       its effect menu offers "Allowed for this session", and turned
 *       around over the real route the notice says "Now allowed for this
 *       session." and the arbiter records `always` on the session's row;
 *   S4  the oracle: neither /api/home nor a drawn page carries the
 *       file's value or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const SESSION = "1791300000-862";
const CSRF = { "X-Mandu-Control": "1" };
const VALUE = "sk_" + "live_answeredScopeStackCanary0001";
const SHA = "a".repeat(64);
const GIT = "/usr/bin/git";

test("Answered earlier and Rules › Your answers name each allow by what the arbiter keeps it as: this session, once, over the real route, no value shown (real arbiter, dashboard; secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-answered-scope-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "shop"), { recursive: true });
  const env = join(home, "shop", ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", readers: ["ssh-add"] }] },
  });
  await arbiter.listen();
  // The guard's channel (the human plane) and the dashboard's (admin), both production clients.
  const guard = new ArbiterClient(humanPath); await guard.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const approvalsArbiter: ApprovalsArbiter = {
    egressApprovals: (status) => admin.egressApprovals(status),
    resolveEgressApproval: (approvalId, approve, scope) => admin.resolveEgressApproval(approvalId, approve, scope),
  };
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { ...CSRF, Cookie: dashboard.adminCookie() };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the file's value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rowOf = (doc: any, id: string) => doc.querySelector(`#approvals-answered .row.answered[data-id="${id}"]`);
  try {
    // ── three questions, filed through the arbiter's own flow ────────────────
    for (const [procKey, session] of [["a-1", SESSION], ["b-1", undefined]] as const) {
      const d = await guard.decideSecretOpen({ path: env, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey, ...(session ? { session } : {}) });
      assert.equal(d.verdict, "raw", JSON.stringify(d));
    }
    const holderSession = (await guard.taintedProcessBindings({ procKey: "a-1", session: SESSION, destination: "hooks.slack.com" })).ask!.approvalId;
    const holderNone = (await guard.taintedProcessBindings({ procKey: "b-1", destination: "paste.example" })).ask!.approvalId;
    const holderBlocked = (await guard.taintedProcessBindings({ procKey: "a-1", session: SESSION, destination: "chat.example" })).ask!.approvalId;
    assert.notEqual(holderBlocked, holderSession, "a second send of the session is its own question");
    const w = await guard.decideProtectedWrite({ path: join(home, ".bashrc"), exe: GIT, sha256: SHA, exeSystem: true, openerEnv: ["args:git -c core.editor"], procKey: "gw-1", label: "a shell startup file", session: SESSION });
    assert.equal(w.verdict, "ask", JSON.stringify(w));
    const pending = await admin.egressApprovals("pending");
    const run = pending.find((a) => a.symbol === `write:${GIT}#${SHA}#run:gw-1`)!.id;
    assert.match(pending.find((a) => a.id === holderSession)!.symbol, new RegExp(`^holder-send:.*"session":"${SESSION}"`));
    assert.match(pending.find((a) => a.id === holderNone)!.symbol, /^holder-send:\{"session":null,/, "keyed to no session");
    for (const id of [holderSession, holderNone, run, holderBlocked]) {
      const r = await pageFetch(`${base}/api/egress/approvals/${id}/deny`, { method: "POST", headers: signedIn });
      assert.equal(r.status, 200);
    }

    // ── S1, S2: the served page, each reversal pressed over the real route ───
    const vmText = await (await pageFetch(`${base}/api/home`)).text();
    const vm = JSON.parse(vmText) as HomeVM;
    const answered = (id: string) => vm.answered.find((a) => a.id === id)!;
    assert.equal(answered(holderSession).allowKeptAs, "session");
    assert.equal(answered(holderNone).allowKeptAs, "once");
    assert.equal(answered(run).allowKeptAs, "once");
    noValue(vmText, "/api/home");
    const expect: Array<[string, string, string]> = [
      [holderSession, "Allow this session instead", "allowed-session"],
      [holderNone, "Allow once instead", "allowed-once"],
      [run, "Allow once instead", "allowed-once"],
    ];
    await servedProductPage(base, "/approvals", (doc) => expect.every(([id]) => rowOf(doc, id)), async (doc) => {
      for (const [id, label, state] of expect) {
        const button = rowOf(doc, id).querySelector("button");
        assert.equal(button.textContent, label, `${id}: the allow names what the arbiter keeps it as`);
        button.click();
        await waitWhile(() => rowOf(doc, id)?.dataset.state === "blocked");
        assert.equal(rowOf(doc, id).dataset.state, state, `${id}: the page says the new answer`);
      }
      const session = rowOf(doc, holderSession);
      assert.equal(session.querySelector(".outcome").textContent, "Allowed for this session", "never Always allowed");
      assert.match(session.querySelector(".answered-when").textContent, /Kept in Rules$/);
      assert.equal(session.querySelector("button").textContent, "Block instead");
      for (const id of [holderNone, run]) assert.equal(rowOf(doc, id).querySelector(".outcome").textContent, "Allowed once, unused", `${id}: what the button said`);
      assert.doesNotMatch(doc.getElementById("approvals-answered").textContent, /Always/, "no Always on any of the three");
      noValue(doc.body.textContent ?? "", "the drawn Approvals page");
    }, { headers: { Cookie: dashboard.adminCookie() } });
    // What the arbiter recorded: the mirror agrees with it.
    const approved = new Map((await admin.egressApprovals("approved")).map((a) => [a.id, a.scope]));
    assert.equal(approved.get(holderSession), "always", "a standing answer on the session's row");
    assert.equal(approved.get(holderNone), "once");
    assert.equal(approved.get(run), "once");

    // ── S3: Rules › Your answers, and its flip over the real route ───────────
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ruleRow = (doc: any, id: string) => doc.querySelector(`#rules-list .row[data-rule="answer:${id}"]`);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const menu = (doc: any, id: string) => ruleRow(doc, id).querySelector("select.effect-select");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const options = (doc: any, id: string) => ([...menu(doc, id).options] as any[]).map((o) => o.textContent);
    await servedProductPage(base, "/rules", (doc) => ruleRow(doc, holderSession) && ruleRow(doc, holderBlocked), async (doc) => {
      assert.match(ruleRow(doc, holderBlocked).textContent, /one session/, "its reach says one session");
      assert.deepEqual(options(doc, holderSession), ["Allowed for this session", "Blocked for this session"]);
      assert.deepEqual(options(doc, holderBlocked), ["Blocked for this session", "Allowed for this session"], "never Always under a one-session reach");
      for (const id of [holderNone, run]) assert.equal(ruleRow(doc, id), null, `${id}: a once answer is not a rule`);
      assert.doesNotMatch(doc.getElementById("rules-list").textContent, /Always/, "no Always on any of them");
      const m = menu(doc, holderBlocked);
      m.value = "flip";
      m.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
      await waitWhile(() => !/^Now /.test(doc.getElementById("rules-notice").textContent ?? ""));
      assert.equal(doc.getElementById("rules-notice").textContent, "Now allowed for this session.");
      await waitWhile(() => options(doc, holderBlocked)[0] !== "Allowed for this session");
      assert.deepEqual(options(doc, holderBlocked), ["Allowed for this session", "Blocked for this session"], "the row says the new answer");
      noValue(doc.body.textContent ?? "", "the drawn Rules page");
    }, { headers: { Cookie: dashboard.adminCookie() } });
    const kept = (await admin.egressApprovals("approved")).find((a) => a.id === holderBlocked);
    assert.equal(kept?.scope, "always", "the arbiter keeps it on the session's row, as the notice said");
    assert.match(kept!.symbol, new RegExp(`"session":"${SESSION}"`));

    // ── S4: the oracle ───────────────────────────────────────────────────────
    noValue(await (await pageFetch(`${base}/api/home`)).text(), "/api/home after the answers");
    noValue(await (await pageFetch(`${base}/api/home`, { headers: signedIn })).text(), "/api/home signed in");
  } finally {
    await dashboard.close();
    guard.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
