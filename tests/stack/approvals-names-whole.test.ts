/**
 * approvals-names-whole — every name Approvals draws is kept whole, as a
 * waiting card's are, and a program's send names its files and the hosts
 * they may go to in code, across the REAL components and the served page
 * (dashboard.md §4.25u *Approvals names things whole*). Mandu-new.
 *
 * Until 2026-10-16 only a waiting card's headline and cells kept a short
 * name on one line. Headless Chromium over the served page (a real program
 * holding two registered files, its send refused) drew *What the program
 * holds* with each file a plain code and the hosts it may go to as text,
 * and *Answered earlier* broke a host at its hyphen at 980 px. Here a real
 * ArbiterServer runs at the `secrets` axes with a policy.yaml on disk; a
 * program (`ssh-add`, a reader of both) reads `~/ws/app/.env` and
 * `~/data/customers.csv` raw, and the net-proxy's own verdict over its
 * production adapter refuses its sends to two hosts. One question is
 * answered Block over the real route; on the other, an *Always* adds the
 * host to `.env`'s rule (a rule change), leaving `customers.csv` in the
 * way. A real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves:
 *
 *   N1  `/api/home`: each file's `nameParts` / `mayGoParts` and the
 *       question's `sourcesLeftParts`, each joined to its string, the files
 *       and hosts as code;
 *   N2  the served Approvals page in jsdom under its served styles at
 *       320 px: *What the program holds* draws each file, each host and the
 *       files left as code kept on one line (`white-space: nowrap`); the
 *       *Answered earlier* row and the *Rule changes* row keep their names
 *       whole too, the rule change each host its own code; the words read
 *       as the strings;
 *   N3  the oracle: no page or answer read here carries a file's value,
 *       and none a token (`$MDU`).
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the words the served page draws; the stack supplies the
 * real questions and the real rule change they are about.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { ArbiterClientAdapter } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { secretTaintVerdict } from "../../interceptors/net-proxy/src/egress.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM, HomeTextPart } from "../../dashboard/src/view-model/home.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = `1791860000-${process.pid}`;
const ENV_VALUE = `sk_live_namesWholeCanary_${process.pid}_000000`;
const CARD_VALUE = "4111111111111111";
const H = "hooks.slack.com";
const ASKED = "paste.names.example";

const text = (parts: HomeTextPart[]): string => parts.map((p) => p.text).join("");
const codes = (parts: HomeTextPart[]): string[] => parts.filter((p) => p.kind === "code").map((p) => p.text);

test("Approvals keeps every short name whole and names a program's files and hosts in code, on the real stack with its served page, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-names-whole-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "ws", "app"), { recursive: true });
  mkdirSync(join(home, "data"), { recursive: true });
  const env = join(home, "ws", "app", ".env");
  const csv = join(home, "data", "customers.csv");
  writeFileSync(env, `STRIPE_KEY=${ENV_VALUE}\n`);
  writeFileSync(csv, `name,card\nAda,${CARD_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1
paths:
  - { path: "${env}", level: no-model, readers: [ssh-add], bindings: [api.stripe.com, "db.internal:5432"] }
  - { path: "${csv}", level: any-model, readers: [ssh-add] }
`);
  const dataSock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock);
  // The net-proxy's production adapter: data socket + the human socket it asks on.
  const proxyArbiter = new ArbiterClientAdapter(await open(dataSock), await open(humanSock));
  const send = (host: string) => secretTaintVerdict({ arbiter: proxyArbiter, holders: [{ procKey: "py-1", ancestors: [] }], destinationHost: host, sessionKey: SESSION });
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const noValue = (body: string, where: string) => {
    assert.ok(!body.includes(ENV_VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the .env value`);
    assert.ok(!body.includes(CARD_VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the card number`);
  };
  const post = async (path: string, body?: unknown) => {
    const r = await pageFetch(base + path, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: r.status, body: await r.text() };
  };
  const served = async (f: string): Promise<string> => {
    const r = await pageFetch(base + f, { headers: { Cookie: ADMIN_COOKIE } });
    assert.equal(r.status, 200, `${f} is served`);
    return r.text();
  };
  try {
    // The program reads both files raw, then sends to two hosts no rule
    // lets both go to: two questions.
    for (const path of [env, csv]) {
      const d = await guard.decideSecretOpen({ path, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "py-1", session: SESSION });
      assert.equal(d.verdict, "raw", `${path}: ${JSON.stringify(d)}`);
    }
    const askOf = async (host: string): Promise<string> => {
      const v = await send(host);
      assert.equal(v.action, "block", `${host}: refused`);
      const id = v.action === "block" ? v.withheld[0]!.approvalId : undefined;
      assert.ok(id, `${host}: the question's id rides on the block: ${JSON.stringify(v)}`);
      return id!;
    };
    const waitingId = await askOf(H);
    const answeredId = await askOf(ASKED);
    assert.notEqual(waitingId, answeredId, "one question per host");
    // One answered Block over the real route: it moves to Answered earlier.
    const blocked = await post(`/api/egress/approvals/${answeredId}/deny`);
    assert.equal(blocked.status, 200, blocked.body);
    // An Always on .env alone: a rule change, and customers.csv still in the way.
    const always = await post(`/api/egress/approvals/${waitingId}/always-source`, { path: env });
    assert.equal(always.status, 200, always.body);
    assert.equal((JSON.parse(always.body) as { released: boolean }).released, false);

    // ── N1: the answer the page reads ──
    const homeText = await served("/api/home");
    noValue(homeText, "/api/home");
    const vm = JSON.parse(homeText) as HomeVM;
    const ask = vm.waiting.find((a) => a.id === waitingId);
    assert.ok(ask?.sources, "the question waits, with its files");
    const byName = new Map(ask!.sources!.map((s) => [s.name, s]));
    const envSrc = byName.get("~/ws/app/.env")!;
    const csvSrc = byName.get("~/data/customers.csv")!;
    assert.ok(envSrc && csvSrc, `both files are named: ${[...byName.keys()].join(", ")}`);
    for (const s of ask!.sources!) {
      assert.equal(text(s.nameParts), s.name, `${s.name}: its parts are its name`);
      assert.equal(text(s.mayGoParts), s.mayGo, `${s.name}: its parts are its places`);
      assert.deepEqual(codes(s.nameParts), [s.name], `${s.name}: the file is the code`);
    }
    assert.deepEqual(codes(envSrc.mayGoParts).sort(), ["api.stripe.com", "db.internal:5432", H].sort(), "the hosts .env may go to, the Always's among them, as code");
    assert.deepEqual(csvSrc.mayGoParts, [{ kind: "text", text: "may go nowhere" }]);
    assert.equal(text(ask!.sourcesLeftParts!), ask!.sourcesLeft);
    assert.deepEqual(codes(ask!.sourcesLeftParts!), [H, "~/data/customers.csv"], "the line names the place and the file left");
    const answered = vm.answered.find((a) => a.id === answeredId);
    assert.ok(answered, "the Block is under Answered earlier");
    assert.deepEqual(codes(answered!.sentence).sort(), ["~/data/customers.csv", "~/ws/app/.env", ASKED].sort());

    // ── N2: the served Approvals page under its served styles, a 320 px phone ──
    const sheets = `${await served("/mandu.css")}\n${await served("/app.css")}`;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    const drawn = (doc: Doc) => doc.querySelectorAll(".ask-source-what").length === 2
      && !!doc.querySelector("#approvals-answered .row.answered .answered-sentence code")
      && !!doc.querySelector("#approvals-rule-history .row code");
    await servedProductPage(base, "/approvals", drawn, (doc: Doc) => {
      const win = doc.defaultView;
      const whole = (node: Doc): string[] => [...node.querySelectorAll("code")].map((c: Doc) => {
        assert.equal(c.className, "code-whole", `${c.textContent} is kept whole`);
        assert.equal(win.getComputedStyle(c).whiteSpace, "nowrap", `${c.textContent} stays on one line`);
        return c.textContent;
      });
      const card = [...doc.querySelectorAll("#approvals-waiting .ask")].find((c: Doc) => c.dataset.id === waitingId);
      assert.ok(card, "the waiting card is drawn");
      const what = new Map<string, Doc>([...card.querySelectorAll(".ask-source-what")].map((x: Doc) => [x.querySelector("code").textContent, x]));
      assert.equal(what.get("~/ws/app/.env").textContent, `~/ws/app/.env ${envSrc.mayGo}`, "the words as the strings");
      assert.deepEqual(whole(what.get("~/ws/app/.env")), ["~/ws/app/.env", ...codes(envSrc.mayGoParts)], ".env and its hosts, as code, whole");
      assert.equal(what.get("~/data/customers.csv").textContent, "~/data/customers.csv may go nowhere Not to this place.");
      assert.deepEqual(whole(what.get("~/data/customers.csv")), ["~/data/customers.csv"]);
      const left = card.querySelector(".ask-sources-left");
      assert.equal(left.textContent, ask!.sourcesLeft);
      assert.deepEqual(whole(left), [H, "~/data/customers.csv"]);
      const row = [...doc.querySelectorAll("#approvals-answered .row.answered")].find((r: Doc) => r.dataset.id === answeredId);
      assert.ok(row, "the answered row is drawn");
      assert.equal(row.querySelector(".answered-sentence").textContent, text(answered!.sentence));
      assert.deepEqual(whole(row.querySelector(".answered-sentence")).sort(), codes(answered!.sentence).sort(), "its names, kept whole");
      // The rule change names .env and each host its rule now lists, every
      // one its own code, kept whole (§4.25u *A rule change names each
      // host*; before, the hosts were one 47-character code that wrapped).
      const change = doc.querySelector("#approvals-rule-history .row");
      const changeCodes = [...change.querySelectorAll(".proposal-let code")] as Doc[];
      assert.ok(changeCodes.some((c) => c.textContent === "~/ws/app/.env"), `the rule change names .env: ${changeCodes.map((c) => c.textContent).join(" | ")}`);
      const changeHosts = changeCodes.map((c) => c.textContent).filter((s: string) => s !== "~/ws/app/.env");
      assert.deepEqual([...changeHosts].sort(), ["api.stripe.com", "db.internal:5432", H].sort(), "each host its own code");
      for (const c of changeCodes) {
        assert.equal(c.className, "code-whole", `${c.textContent}: whole`);
        assert.equal(win.getComputedStyle(c).whiteSpace, "nowrap", `${c.textContent}: on one line`);
      }
      noValue(doc.body.textContent, "the rendered Approvals page");
      assert.doesNotMatch(doc.body.textContent, /\$MDU/, "the rendered page carries no token");
    }, { headers: { Cookie: ADMIN_COOKIE }, css: resolveCssVars(stylesAt(sheets, 320)) });

    // ── N3: the oracle ──
    for (const route of ["/api/home", "/api/policy/changes?limit=20", "/api/egress/approvals", "/approvals", "/"]) {
      const r = await pageFetch(base + route, { headers: { Cookie: ADMIN_COOKIE } });
      const body = await r.text();
      noValue(body, route);
      assert.doesNotMatch(body, /\$MDU/, `${route} carries no token`);
    }
  } finally {
    await dashboard.close();
    wired?.close();
    for (const c of clients) c.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
