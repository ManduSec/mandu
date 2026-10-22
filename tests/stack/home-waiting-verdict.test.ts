/**
 * home-waiting-verdict.test — Home's waiting state claims only what holds,
 * across the REAL components (dashboard.md §4.25, the verdict ladder's
 * `waiting`; §4.25d). Mandu-new.
 *
 * Until 2026-10-07, while any question waited, Home's hero said "Protection
 * is holding while you decide. Nothing leaves your machine until you
 * answer." Here the real gate shows why that was false: a real ArbiterServer
 * (`secrets` axes) holds a question about a labelled secret at a host no rule
 * names, and while it waits the same gate lets that secret go to the host its
 * label binds it to, with no question. At Secrets the waiting sentence also
 * replaced the level's "Untrusted content is not masked" (CONTRIBUTING.md,
 * protection modes: the product says so).
 *
 *   W1  the gate: the unbound send asks; the bound send is allowed while the
 *       question waits (the counterexample, from the real policy);
 *   W2  /api/home from a real DashboardServer over a real
 *       ArbiterEventSource: the waiting verdict says what is asked happens
 *       only if you allow it, keeps the Secrets disclosure, and never says
 *       nothing leaves;
 *   W3  the oracle: no answer on the product side, nor the inspector's
 *       panel, carries the secret's value, and Home carries no token;
 *   W4  the served product page (its own index.html and home.js in jsdom,
 *       fetching from that server) says how many questions wait once, in
 *       the headline: the facts line under it does not say "1 waiting for
 *       you" again (2026-10-08, §4.25 *Said once*), the question is listed
 *       under the hero, and the rendered page carries neither the secret's
 *       value nor a token.
 *
 * A second test (dashboard.md §4.25 *A question from a session that has
 * ended*, 2026-10-22): the asking session's launcher records its REAL
 * `session_exit`, and the hero stops saying that protection is holding:
 *
 *   E1  /api/home's headline names the ended session, its sentence says no
 *       agent waits on it, and the verdict is still `waiting`, the question
 *       still counted;
 *   E2  the served page draws those words, the Approvals badge and Home's
 *       Approvals waiting (1) unchanged, and the card says the agent ended;
 *   E3  the oracle kept: the bound send still goes to its host, and no
 *       answer nor the page carries the value or a token.
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
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { emitLauncherEvent, sessionExitEvent } from "../../launcher/src/services/observe.js";

stateAxes("secrets");

const KEY_VALUE = "sk_live_homeWaitingStackCanary0000000000001";
const SESSION = "1791200000-417";

test("while a question waits, a rule still sends the secret to its bound host, and Home says only what holds", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-home-waiting-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath); await gate.connect();
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
  try {
    // A secret file whose label lets it go to one host: the Rules row reads
    // "No AI; may be sent to api.stripe.com".
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: ["api.stripe.com"], recursive: false });
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);

    // W1: the send to a host no rule names asks ...
    const asked = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: "evil.example", sessionKey: SESSION, scheme: "https" });
    assert.equal(asked.allow, false);
    assert.equal((asked as { requiresApproval?: boolean }).requiresApproval, true);
    const askId = String((asked as { approvalId?: string }).approvalId);
    // ... and while it waits, the rule sends the same secret to its own host,
    // with no question: something leaves before anyone answers.
    const bound = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: "api.stripe.com", sessionKey: SESSION, scheme: "https" });
    assert.equal(bound.allow, true, `the bound host gets the real value with no question: ${JSON.stringify(bound)}`);
    assert.notEqual((bound as { requiresApproval?: boolean }).requiresApproval, true);

    // W2: Home over the real arbiter.
    const vm = (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    assert.equal(vm.protection.level, "secrets");
    assert.deepEqual(vm.waiting.map((a) => a.id), [askId], "the one question is waiting");
    assert.equal(vm.verdict, "waiting");
    assert.equal(vm.headline, "One question is waiting for you.");
    assert.equal(vm.sentence,
      "Protection is holding while you decide: what it asks for happens only if you allow it. Untrusted content is not masked in this mode.");
    assert.doesNotMatch(vm.sentence, /[Nn]othing leaves|until you answer/);

    // W3: the oracle on the product side and the inspector's panel.
    const bodies = {
      home: await (await pageFetch(`${base}/api/home`)).text(),
      panel: await (await pageFetch(`${base}/api/policy/panel`)).text(),
    };
    for (const [route, body] of Object.entries(bodies)) {
      assert.ok(!body.includes(KEY_VALUE), `${route} carries no secret value`);
    }
    assert.doesNotMatch(bodies.home, /\$MDU/, "the product's home carries no token");

    // W4: the served page says the count once, in the headline.
    assert.equal(vm.window.waiting, 1, "the payload still counts the question");
    await servedProductPage(base, "/", (doc) => doc.getElementById("hero").dataset.verdict === "waiting" && doc.querySelectorAll("#home-waiting .ask").length > 0, (doc) => {
      assert.equal(doc.getElementById("hero-headline").textContent, "One question is waiting for you.");
      const facts = doc.getElementById("hero-facts");
      assert.ok(facts.textContent.length > 0, "the facts line still says what the window holds");
      assert.doesNotMatch(facts.textContent, /waiting/, `the count is not said again under the headline: "${facts.textContent}"`);
      assert.equal(doc.querySelectorAll("#home-waiting .ask").length, 1, "the question is listed under the hero");
      assert.equal(doc.getElementById("home-waiting-title").textContent, "Approvals waiting (1)");
      const page = doc.body.textContent;
      assert.ok(!page.includes(KEY_VALUE), "the rendered page carries no secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    });
  } finally {
    await dashboard.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("a question from a session that has ended: Home's headline says so, the verdict, the count and the badge stay, and the bound send still goes (secrets axes, explicit)", { timeout: 60_000 }, async () => {
  const ENDED = "1791200100-418";
  const tmp = mkdtempSync(join(tmpdir(), "mandu-home-waiting-ended-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath); await gate.connect();
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
  const HEADLINE = "One question from a session that has ended is waiting for you.";
  const SENTENCE = "No agent is waiting on it now. Your answer decides what happens the next time an agent asks the same. Untrusted content is not masked in this mode.";
  try {
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: ["api.stripe.com"], recursive: false });
    const reg = await gate.registerSecret({ path: env, sessionKey: ENDED });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const asked = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: "evil.example", sessionKey: ENDED, scheme: "https" });
    assert.equal((asked as { requiresApproval?: boolean }).requiresApproval, true);
    const askId = String((asked as { approvalId?: string }).approvalId);

    // While the session runs, the hero is as it was.
    const before = (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    assert.deepEqual(before.waiting.map((a) => a.id), [askId]);
    assert.equal(before.headline, "One question is waiting for you.");

    // The session's launcher records its exit.
    assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: ENDED, code: 0, durationMs: 4_000 }), humanPath), "the launcher's emit lands");

    // E1: the served headline names the ended session; nothing else moves.
    let vm = before;
    for (let i = 0; i < 400 && vm.headline !== HEADLINE; i++) {
      await new Promise((r) => setTimeout(r, 25));
      vm = (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    }
    assert.equal(vm.protection.level, "secrets");
    assert.equal(vm.headline, HEADLINE);
    assert.equal(vm.sentence, SENTENCE);
    assert.doesNotMatch(vm.sentence, /Protection is holding/);
    assert.equal(vm.verdict, "waiting", "the verdict stays: the question still needs an answer");
    assert.deepEqual(vm.waiting.map((a) => a.id), [askId], "the question is still listed");
    assert.equal(vm.waiting[0]!.askerEnded, true);
    assert.equal(vm.window.waiting, 1, "and still counted");

    // E3: the bound send still goes to its host, with no question.
    const bound = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: "api.stripe.com", sessionKey: ENDED, scheme: "https" });
    assert.equal(bound.allow, true, `the bound host gets the real value with no question: ${JSON.stringify(bound)}`);
    const bodies = {
      home: await (await pageFetch(`${base}/api/home`)).text(),
      panel: await (await pageFetch(`${base}/api/policy/panel`)).text(),
    };
    for (const [route, body] of Object.entries(bodies)) assert.ok(!body.includes(KEY_VALUE), `${route} carries no secret value`);
    assert.doesNotMatch(bodies.home, /\$MDU/, "the product's home carries no token");

    // E2: the served page draws the words; the badge and the count are the same.
    await servedProductPage(base, "/", (doc) => doc.getElementById("hero").dataset.verdict === "waiting" && doc.querySelectorAll("#home-waiting .ask").length > 0, (doc) => {
      assert.equal(doc.getElementById("hero-headline").textContent, HEADLINE);
      assert.equal(doc.getElementById("hero").dataset.verdict, "waiting");
      const badge = doc.getElementById("nav-approvals-count");
      assert.equal(badge.textContent, "1", "the Approvals badge still counts the question");
      assert.equal(badge.hidden, false);
      assert.equal(doc.getElementById("home-waiting-title").textContent, "Approvals waiting (1)");
      assert.match(doc.getElementById("home-waiting").textContent, /The agent that asked has ended/, "the card says the same");
      const page = doc.body.textContent;
      assert.ok(page.includes(SENTENCE), "the hero's sentence is drawn");
      assert.ok(!page.includes(KEY_VALUE), "the rendered page carries no secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    });
  } finally {
    await dashboard.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
