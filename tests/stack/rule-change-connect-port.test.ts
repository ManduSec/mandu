/**
 * rule-change-connect-port — a rule change that lets the agent's programs
 * connect somewhere names the port, on both of its lines, across the REAL
 * components and the served page (dashboard.md §4.25u *A rule change names
 * its port*). Mandu-new.
 *
 * Until 2026-10-16 the rule-change grammar (policy-proposals.ts
 * `editWords`) read a host of `*` as "any address" and dropped the edit's
 * port, while the *This would let* line under it said `*:22`; a removal of
 * the same rule read as the raw code `*:2222`, and a port of `*` as a `:*`
 * suffix. Here a real ArbiterServer runs at the `secrets` axes with a
 * policy.yaml on disk that registers `.env` and already lets programs
 * connect to any address on port 2222. The agent (data plane) asks to let
 * them connect to any address on port 22, to stop the 2222 one, and to let
 * them reach `*.example.org` on any port (it waits); and, apart, to let them
 * connect to any address (the human allows it over the dashboard's real
 * route). A real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves:
 *
 *   P1  the listings (`/api/policy/proposals`, `/api/policy/changes`),
 *       signed in and signed out: each row and each *This would let* line
 *       names the port ("any address on port 22", "on any port"), never a
 *       bare `*` or a `:*` as a name; the allowed change reads "any address";
 *   P2  the served Approvals page in jsdom under its served styles: the
 *       waiting card's rows and *This would let* lines and the *Rule
 *       changes* row read as the listing's, each port its own code;
 *   P3  the oracle: no page or answer read here carries the registered
 *       value, and none a token (`$MDU`); policy.yaml holds the allowed
 *       change and none of the waiting one's.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the words the served page draws; the stack supplies the
 * real requests, the arbiter's own *This would let* subjects and the real
 * change they are about.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = `1791880000-${process.pid}`;
const ENV_VALUE = `sk_live_connectPortCanary_${process.pid}_000000`;
const LET = "Let your agent's programs connect to ";
const STOP = "Stop letting your agent's programs connect to ";
const COULD = "Your agent's programs could connect to ";
const WAIT_ROWS = [`${LET}any address on port 22`, `${STOP}any address on port 2222`, `${LET}*.example.org on any port`];
const WAIT_CODES = [["22"], ["2222"], ["*.example.org"]];
const WAIT_LETS = [`${COULD}*.example.org on any port`, `${COULD}any address on port 22`];
const MADE_ROW = `${LET}any address`;

type Part = { kind: string; text: string };
const text = (parts: Part[]): string => parts.map((p) => p.text).join("");
const codes = (parts: Part[]): string[] => parts.filter((p) => p.kind === "code").map((p) => p.text);
/** No connection target is named by a bare `*` or a `:*` port. */
const noRawStar = (parts: Part[], where: string) => {
  for (const c of codes(parts)) assert.ok(c !== "*" && !c.startsWith("*:") && !c.endsWith(":*"), `${where}: ${c} is a raw target`);
};

test("a rule change that lets programs connect names the port on both of its lines, on the real stack with its served page, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-connect-port-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try"), { recursive: true });
  const env = join(home, "mandu-try", ".env");
  writeFileSync(env, `STRIPE_KEY=${ENV_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1
paths:
  - { path: "${env}", level: no-model, bindings: [api.stripe.com] }
destinations:
  - { host: "*", port: 2222, connect: allow }
`);
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
  const data = new ArbiterClient(dataSock);
  await data.connect();
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
  const noValue = (body: string, where: string) => {
    assert.ok(!body.includes(ENV_VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the .env value`);
    assert.doesNotMatch(body, /\$MDU/, `${where} carries no token`);
  };
  const read = async (path: string, headers: Record<string, string>): Promise<string> => {
    const r = await pageFetch(base + path, { headers });
    const body = await r.text();
    assert.equal(r.status, 200, `${path}: ${body}`);
    noValue(body, path);
    return body;
  };
  try {
    // The agent asks for both; loosening, so each waits for the human.
    const ask = async (edits: Array<Record<string, unknown>>, reason: string): Promise<string> => {
      const r = await data.policyPropose({ edits, sessionKey: SESSION, reason });
      assert.ok("proposalId" in r && r.proposalId, `it waits for the human: ${JSON.stringify(r)}`);
      return String(r.proposalId);
    };
    const waitingId = await ask([
      { op: "allow-connect", host: "*", port: 22 },
      { op: "remove-connect", host: "*", port: 2222 },
      { op: "allow-connect", host: "*.example.org", port: "*" },
    ], "ssh to the build boxes");
    const allowedId = await ask([{ op: "allow-connect", host: "*" }], "fetch packages");
    // The human allows the second over the dashboard's real route.
    const ok = await pageFetch(`${base}/api/policy/proposals/${allowedId}`, { method: "POST", body: JSON.stringify({ verdict: "approved" }), headers: { ...CSRF_ADMIN, "content-type": "application/json" } });
    assert.equal(ok.status, 200, await ok.text());

    // ── P1: the listings, signed in and signed out ──
    for (const headers of [CSRF_ADMIN, {}]) {
      const who = Object.keys(headers).length ? "signed in" : "signed out";
      const pending = (JSON.parse(await read("/api/policy/proposals?status=pending", headers)) as { proposals: Array<{ id: string; rows: Part[][]; wouldLet: Part[][]; overBroad: boolean }> }).proposals;
      const card = pending.find((p) => p.id === waitingId);
      assert.ok(card, `${who}: the request waits`);
      assert.deepEqual(card!.rows.map(text), WAIT_ROWS, `${who}: each row names its port`);
      assert.deepEqual(card!.rows.map(codes), WAIT_CODES, `${who}: each port, or a named host, its own code`);
      assert.deepEqual(card!.wouldLet.map(text).sort(), WAIT_LETS, `${who}: the arbiter's subjects in the same words`);
      for (const r of [...card!.rows, ...card!.wouldLet]) noRawStar(r, who);
      assert.equal(card!.overBroad, true, `${who}: the typed ALLOW is still asked`);
      const changes = (JSON.parse(await read("/api/policy/changes?limit=20", headers)) as { changes: Array<{ rows: Part[][] }> }).changes;
      assert.ok(changes.some((c) => c.rows.length === 1 && text(c.rows[0]!) === MADE_ROW && codes(c.rows[0]!).length === 0),
        `${who}: the allowed change reads "any address": ${JSON.stringify(changes.map((c) => c.rows.map(text)))}`);
    }

    // ── P2: the served Approvals page under its served styles ──
    const sheets = `${await read("/mandu.css", { Cookie: ADMIN_COOKIE })}\n${await read("/app.css", { Cookie: ADMIN_COOKIE })}`;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    const cardSel = `#approvals-proposals .proposal[data-id="${waitingId}"]`;
    const drawn = (doc: Doc) => !!doc.querySelector(`${cardSel} .proposal-rows li code`)
      && [...doc.querySelectorAll("#approvals-rule-history .proposal-let li")].some((li: Doc) => li.textContent === MADE_ROW);
    await servedProductPage(base, "/approvals", drawn, (doc: Doc) => {
      const lines = (sel: string): string[] => [...doc.querySelectorAll(sel)].map((li: Doc) => li.textContent);
      assert.deepEqual(lines(`${cardSel} .proposal-rows li`), WAIT_ROWS, "the waiting card's rows as the listing's");
      assert.deepEqual([...doc.querySelectorAll(`${cardSel} .proposal-rows li`)].map((li: Doc) => [...li.querySelectorAll("code")].map((c: Doc) => c.textContent)), WAIT_CODES, "each port its own code");
      assert.deepEqual(lines(`${cardSel} .proposal-let li`).sort(), WAIT_LETS, "This would let, in the same words");
      assert.ok(lines("#approvals-rule-history .proposal-let li").includes(MADE_ROW), "the Rule changes row");
      for (const c of doc.querySelectorAll(`${cardSel} code, #approvals-rule-history code`)) {
        const s = c.textContent;
        assert.ok(s !== "*" && !s.startsWith("*:") && !s.endsWith(":*"), `the page draws ${s} as a target`);
      }
      noValue(doc.body.textContent, "the rendered Approvals page");
    }, { headers: { Cookie: ADMIN_COOKIE }, css: resolveCssVars(stylesAt(sheets, 390)) });

    // ── P3: the oracle ──
    for (const route of ["/api/home", "/api/policy/proposals?status=pending", "/api/policy/changes?limit=20", "/approvals", "/"]) {
      await read(route, { Cookie: ADMIN_COOKIE });
    }
    const onDisk = readFileSync(policyPath, "utf8");
    assert.match(onDisk, /2222/, "the waiting removal is not applied");
    assert.doesNotMatch(onDisk, /example\.org|port: 22\b/, "the waiting change is not applied");
    assert.equal(onDisk.match(/connect: allow/g)?.length, 2, `the allowed change is written beside the 2222 one: ${onDisk}`);
    noValue(onDisk, "policy.yaml");
  } finally {
    await dashboard.close();
    wired?.close();
    data.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
