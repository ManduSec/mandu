/**
 * approval-after-answer.test — the Approvals card says what an answer does
 * to the stopped action, and the real arbiter does just that (dashboard.md
 * §4.34 "After you answer"). Mandu-new.
 *
 * A real ArbiterServer (`secrets` axes) behind a real DashboardServer over a
 * real ArbiterEventSource, with the real admin-socket client behind its
 * approval routes:
 *
 *   A1  the real egress gate refuses a registered secret's send to a host no
 *       rule binds it to; the served card says the next request goes with
 *       the value, that this one was refused, and to tell the agent;
 *   A2  Allow once over the real route: the gate's NEXT decision for that
 *       send allows it, and the one after asks again (the words "next
 *       request", one request);
 *   A3  the guard holds a change to a file that runs later (the human
 *       socket's `decideProtectedWrite`): while it asks, the card says the
 *       program is waiting now and goes on at once, with no count of the
 *       re-asks; once it stops asking, the card says it stopped waiting and
 *       that the next try is the one an answer covers; the guard's answer
 *       after an Allow once is `allow` (no new question);
 *   A4  no route carries the secret's value; the product side no token.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { HELD_FRESH_MS, type HomeVM } from "../../dashboard/src/view-model/home.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const KEY_VALUE = "sk_live_afterAnswerStackCanary0000000001";
const SESSION = "1791300000-321";
const SHA = "d".repeat(64);
const CSRF = { "X-Mandu-Control": "1" };

test("the card says what an answer does to the stopped action, and the real arbiter does it", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-approval-after-answer-"));
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
  const guard = new ArbiterClient(humanPath); await guard.connect();
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
  const homeVm = async (): Promise<HomeVM> => (await (await fetch(`${base}/api/home`)).json()) as HomeVM;
  try {
    // A1: a registered key's send to a host no rule binds it to.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    // From the human socket, as the real proxies ask: only an attested ask
    // spends an Allow once (plan 13 D9).
    const send = () => guard.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: "api.stripe.com", sessionKey: SESSION, scheme: "https" });
    const first = await send();
    assert.equal(first.allow, false);
    const askId = String((first as { approvalId?: string }).approvalId);
    const sendCard = (await homeVm()).waiting.find((a) => a.id === askId)!;
    assert.equal(sendCard.ifAllowed, "The AI's next request goes to api.stripe.com with the real secret filled in. Mandu refused this one, so nothing was sent. After you answer, tell the agent to try again.");

    // A2: Allow once, over the real route; then the next try goes, once.
    const once = await fetch(`${base}/api/egress/approvals/${askId}/approve-once`, { method: "POST", headers: { ...CSRF, Cookie: dashboard.adminCookie() } });
    assert.equal(once.status, 200, await once.text());
    assert.equal((await send()).allow, true, "the agent's next request goes");
    const third = await send();
    assert.equal(third.allow, false, "Allow once covered one request");
    assert.equal((third as { requiresApproval?: boolean }).requiresApproval, true, "and the next one asks again");

    // A3: the guard holds a change to a file that runs later, asking again
    // every half second as it does while it holds.
    const rc = join(home, ".bashrc");
    const write = () => guard.decideProtectedWrite({ path: rc, exe: "/usr/bin/nano", procKey: "nano-aa-1", label: "a shell startup file", sha256: SHA, exeSystem: true, openerEnv: [], session: SESSION });
    let held = await write();
    assert.equal(held.verdict, "ask", JSON.stringify(held));
    const writeId = String(held.approvalId);
    for (let i = 0; i < 3; i++) { await sleep(500); held = await write(); }
    const waitingNow = (await homeVm()).waiting.find((a) => a.id === writeId)!;
    assert.equal(waitingNow.held, true);
    assert.ok(waitingNow.count >= 4, "the re-asks counted by the arbiter");
    assert.equal(waitingNow.ifAllowed, "The AI's program /usr/bin/nano is waiting for your answer now, and goes on at once: it changes the file. What it wrote runs the next time the file is used.");
    // The guard stops asking (its ceiling); the card says so.
    await sleep(HELD_FRESH_MS + 500);
    const gone = (await homeVm()).waiting.find((a) => a.id === writeId)!;
    assert.equal(gone.held, false);
    assert.match(gone.why, /Mandu held the change for a while, then refused it\.$/);
    assert.equal(gone.ifAllowed, "The AI's program /usr/bin/nano stopped waiting and could not change the file. If you allow it, it changes the file the next time the AI runs it. After you answer, tell the agent to try again. What it wrote runs the next time the file is used.");
    // Allow once: the next try is allowed, with no new question.
    const ok = await fetch(`${base}/api/egress/approvals/${writeId}/approve-once`, { method: "POST", headers: { ...CSRF, Cookie: dashboard.adminCookie() } });
    assert.equal(ok.status, 200, await ok.text());
    assert.equal((await write()).verdict, "allow", "the next try is the one the answer covers");

    // A4: never the value; the product side never a token.
    const bodies = {
      home: await (await fetch(`${base}/api/home`)).text(),
      panel: await (await fetch(`${base}/api/policy/panel`)).text(),
    };
    for (const [route, body] of Object.entries(bodies)) assert.ok(!body.includes(KEY_VALUE), `${route} carries no secret value`);
    assert.doesNotMatch(bodies.home, /\$MDU/, "the product's home carries no token");
  } finally {
    await dashboard.close();
    gate.close(); admin.close(); guard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
