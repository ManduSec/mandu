/**
 * announce-new-asks.test — a question or rule change that arrives while the
 * product page is open is said to a screen reader in the top bar's hidden
 * live region, across the REAL components (dashboard.md §4.25 *A new
 * question is announced on the page*). Mandu-new.
 *
 * Until 2026-10-22 the only signal was a desktop notification, which needs
 * the browser's permission: with it blocked, a screen-reader user was never
 * told that the agent was held on a question.
 *
 * A real ArbiterServer runs at the `secrets` axes with a policy file; a real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`)
 * serves the page, signed in, in jsdom (served-page.ts), with notification
 * permission DENIED:
 *
 *   A1  the first poll says nothing (nothing waits);
 *   A2  the real egress gate asks about a masked environment variable at a
 *       host no rule binds it to; the next poll writes "<agent> needs your
 *       OK. 1 waiting in Approvals." (the agent as the card names it);
 *   A3  the agent asks for a loosening rule change over the data socket;
 *       the next poll writes "Your agent asks to change a rule. 2 waiting
 *       in Approvals.";
 *   A4  the oracle: the region never holds a `$MDU` token, the secret's
 *       name or value, the host, nor the agent's reason.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests());

const VALUE = `ghp_announceNewAsksCanary_${process.pid}_000000000`;
const NAME = "ANNOUNCE_TOKEN";
const HOST = "exfil-announce.example.net";
const RULE_HOST = "rule-announce.example.net";
const REASON = `the deploy step posts ${VALUE} to ${RULE_HOST}`;
const SESSION = `1791400000-${process.pid}`;

/** A page with notifications blocked: the region must speak anyway. */
const DENIED = `(() => {
  function N() { throw new Error("blocked"); }
  N.permission = "denied";
  N.requestPermission = () => Promise.resolve("denied");
  Object.defineProperty(window, "Notification", { value: N, configurable: true, writable: true });
})();`;

test("served page: a new send question, then a rule change the agent asks for, are each said in the top bar's live region, naming no secret, host or token (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-announce-new-asks-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
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
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  try {
    const region = (doc: any) => doc.getElementById("top-announce");
    const drawn = (doc: any) => doc.getElementById("top-status").children.length > 0;
    await servedProductPage(base, "/", drawn, async (doc) => {
      const w = doc.defaultView;
      const poll = () => {
        Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
        doc.dispatchEvent(new w.Event("visibilitychange"));
      };
      const lines: string[] = [];
      // A1
      assert.equal(region(doc).getAttribute("aria-live"), "polite");
      assert.equal(region(doc).textContent, "", "nothing waits, nothing said");

      // A2: the real gate asks about a masked variable at an unbound host.
      const vars = await gate.registerEnvSecrets({ vars: [{ name: NAME, value: VALUE }], sessionKey: SESSION });
      const sym = String(vars.vars[0]?.symbol);
      assert.match(sym, /^\$MDU:nomodel_Env\[/);
      const d = await gate.desymbolizationDecision({ symbol: sym, boundary: "network", destination: HOST, sessionKey: SESSION, scheme: "https" });
      assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "the send waits for the person");
      const vm = (await (await pageFetch(`${base}/api/home`, { headers: { Cookie: ADMIN_COOKIE } })).json()) as HomeVM;
      const card = vm.waiting.find((a) => a.id === String((d as { approvalId?: string }).approvalId));
      assert.ok(card, "Home lists the question");
      const sentence = card!.sentence.map((p) => p.text).join("");
      assert.ok(sentence.includes(NAME) && sentence.includes(HOST), `the card names the secret and host: ${sentence}`);
      poll();
      await waitWhile(() => region(doc).textContent === "");
      lines.push(region(doc).textContent);
      assert.equal(lines[0], `${card!.agents[0] || "An agent"} needs your OK. 1 waiting in Approvals.`);

      // A3: the agent asks for a loosening rule change.
      const r = await gate.policyPropose({ edits: [{ op: "allow-connect", host: RULE_HOST }], reason: REASON, sessionKey: SESSION });
      assert.ok("proposalId" in r && r.proposalId, `it waits for the person: ${JSON.stringify(r)}`);
      poll();
      await waitWhile(() => region(doc).textContent === lines[0]);
      lines.push(region(doc).textContent);
      assert.equal(lines[1], "Your agent asks to change a rule. 2 waiting in Approvals.");

      // A4
      for (const line of lines) {
        assert.ok(!line.includes(VALUE), `CONFIDENTIALITY VIOLATION: the region carries the value: ${line}`);
        assert.doesNotMatch(line, /\$MDU/, "no token");
        for (const word of [NAME, HOST, RULE_HOST, "deploy step"]) assert.ok(!line.includes(word), `the region names ${word}: ${line}`);
      }
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: (w) => w.eval(DENIED) });
  } finally {
    await dashboard.close();
    wired.close();
    gate.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
