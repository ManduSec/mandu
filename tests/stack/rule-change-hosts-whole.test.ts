/**
 * rule-change-hosts-whole — a rule change names each host a file may be
 * sent to as its own code, so Approvals keeps each short one whole, across
 * the REAL components and the served page (dashboard.md §4.25u *A rule
 * change names each host*). Mandu-new.
 *
 * Until 2026-10-16 the rule-change grammar (policy-proposals.ts
 * `editWords`) joined a rule's hosts into ONE code ("`api.github.com,
 * deploy-hooks.example.com`"), past the 24 characters a name is kept whole
 * at, so headless Chromium broke "deploy-" / "hooks.example.com" in a
 * *Rule changes* row at 390 px. Here a real ArbiterServer runs at the
 * `secrets` axes with a policy.yaml on disk; the agent (data plane) asks to
 * let `~/mandu-try/.env` go to four hosts (it waits) and `deploy.token` to
 * two (the human allows it over the dashboard's real route). A real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`)
 * serves:
 *
 *   W1  the listings (`/api/policy/proposals`, `/api/policy/changes`): each
 *       row names the file and each host as its own code, and its words
 *       are the sentence one code made, signed in and signed out;
 *   W2  the served Approvals page in jsdom under its served styles at
 *       320 px: the waiting card's row and the *Rule changes* row draw each
 *       host as its own code, one of at most 24 characters kept on one line
 *       (`.code-whole`, `white-space: nowrap`), the 27-character one a
 *       plain code; the words read as the listing's;
 *   W3  the oracle: no page or answer read here carries a file's value,
 *       and none a token (`$MDU`).
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the words the served page draws; the stack supplies the
 * real requests and the real change they are about.
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
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = `1791870000-${process.pid}`;
const ENV_VALUE = `sk_live_hostsWholeCanary_${process.pid}_000000`;
const TOKEN_VALUE = `ghp_hostsWholeCanary${process.pid}000000`;
/** 24 characters (kept whole) and 27 (past the bound, wraps). */
const HOOKS = "deploy-hooks.example.com";
const UPLOADS = "uploads.example-storage.net";
const ENV_HOSTS = ["api.stripe.com", "db.internal:5432", HOOKS, UPLOADS];
const TOKEN_HOSTS = ["api.github.com", HOOKS];
const ENV_ROW = `Make ~/mandu-try/.env a secret no AI may read, may be sent to ${ENV_HOSTS.join(", ")}`;
const TOKEN_ROW = `Make ~/mandu-try/deploy.token a secret no AI may read, may be sent to ${TOKEN_HOSTS.join(", ")}`;

type Part = { kind: string; text: string };
const text = (parts: Part[]): string => parts.map((p) => p.text).join("");
const codes = (parts: Part[]): string[] => parts.filter((p) => p.kind === "code").map((p) => p.text);

test("a rule change names each host as its own code, and Approvals keeps each short one whole, on the real stack with its served page, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-hosts-whole-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try"), { recursive: true });
  const env = join(home, "mandu-try", ".env");
  const token = join(home, "mandu-try", "deploy.token");
  writeFileSync(env, `STRIPE_KEY=${ENV_VALUE}\n`);
  writeFileSync(token, `${TOKEN_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1
paths:
  - { path: "${env}", level: no-model, bindings: [api.stripe.com, "db.internal:5432"] }
  - { path: "${token}", level: no-model }
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
    assert.ok(!body.includes(TOKEN_VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the token`);
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
    const ask = async (edit: Record<string, unknown>, reason: string): Promise<string> => {
      const r = await data.policyPropose({ edits: [edit], sessionKey: SESSION, reason });
      assert.ok("proposalId" in r && r.proposalId, `it waits for the human: ${JSON.stringify(r)}`);
      return String(r.proposalId);
    };
    const waitingId = await ask({ op: "lock-path", path: env, level: "no-model", bindings: ENV_HOSTS }, "deploy needs it");
    const allowedId = await ask({ op: "lock-path", path: token, level: "no-model", bindings: TOKEN_HOSTS }, "ci needs it");
    // The human allows the token's over the dashboard's real route.
    const ok = await pageFetch(`${base}/api/policy/proposals/${allowedId}`, { method: "POST", body: JSON.stringify({ verdict: "approved" }), headers: { ...CSRF_ADMIN, "content-type": "application/json" } });
    assert.equal(ok.status, 200, await ok.text());

    // ── W1: the listings, signed in and signed out ──
    for (const headers of [CSRF_ADMIN, {}]) {
      const who = Object.keys(headers).length ? "signed in" : "signed out";
      const pending = (JSON.parse(await read("/api/policy/proposals?status=pending", headers)) as { proposals: Array<{ id: string; rows: Part[][] }> }).proposals;
      const card: { id: string; rows: Part[][] } | undefined = pending.find((p) => p.id === waitingId);
      assert.ok(card, `${who}: the request waits`);
      assert.equal(card!.rows.length, 1);
      assert.equal(text(card!.rows[0]!), ENV_ROW, `${who}: the words as one code said them`);
      assert.deepEqual(codes(card!.rows[0]!), ["~/mandu-try/.env", ...ENV_HOSTS], `${who}: the file and each host its own code`);
      const changes = (JSON.parse(await read("/api/policy/changes?limit=20", headers)) as { changes: Array<{ rows: Part[][] }> }).changes;
      const made = changes.find((c) => c.rows.some((r) => text(r) === TOKEN_ROW));
      assert.ok(made, `${who}: the allowed change is listed: ${JSON.stringify(changes.map((c) => c.rows.map(text)))}`);
      assert.deepEqual(codes(made!.rows.find((r) => text(r) === TOKEN_ROW)!), ["~/mandu-try/deploy.token", ...TOKEN_HOSTS], `${who}: each host its own code`);
    }

    // ── W2: the served Approvals page under its served styles, a 320 px phone ──
    const sheets = `${await read("/mandu.css", { Cookie: ADMIN_COOKIE })}\n${await read("/app.css", { Cookie: ADMIN_COOKIE })}`;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    const drawn = (doc: Doc) => !!doc.querySelector(`#approvals-proposals .proposal[data-id="${waitingId}"] .proposal-rows li code`)
      && [...doc.querySelectorAll("#approvals-rule-history .proposal-let li")].some((li: Doc) => li.textContent === TOKEN_ROW);
    await servedProductPage(base, "/approvals", drawn, (doc: Doc) => {
      const win = doc.defaultView;
      const drawnCodes = (li: Doc): string[] => [...li.querySelectorAll("code")].map((c: Doc) => {
        const short = c.textContent.length <= 24;
        assert.equal(c.className, short ? "code-whole" : "", `${c.textContent}: ${short ? "kept whole" : "past the bound, a plain code"}`);
        assert.equal(win.getComputedStyle(c).whiteSpace === "nowrap", short, `${c.textContent}: ${short ? "on one line" : "may wrap"}`);
        return c.textContent;
      });
      const row = doc.querySelector(`#approvals-proposals .proposal[data-id="${waitingId}"] .proposal-rows li`);
      assert.equal(row.textContent, ENV_ROW, "the waiting card's words as the listing's");
      assert.deepEqual(drawnCodes(row), ["~/mandu-try/.env", ...ENV_HOSTS], "the file and each host its own code");
      const change = [...doc.querySelectorAll("#approvals-rule-history .proposal-let li")].find((li: Doc) => li.textContent === TOKEN_ROW);
      assert.deepEqual(drawnCodes(change), ["~/mandu-try/deploy.token", ...TOKEN_HOSTS], "the Rule changes row: each host its own code, all whole");
      noValue(doc.body.textContent, "the rendered Approvals page");
    }, { headers: { Cookie: ADMIN_COOKIE }, css: resolveCssVars(stylesAt(sheets, 320)) });

    // ── W3: the oracle ──
    for (const route of ["/api/home", "/api/policy/proposals?status=pending", "/api/policy/changes?limit=20", "/approvals", "/"]) {
      await read(route, { Cookie: ADMIN_COOKIE });
    }
  } finally {
    await dashboard.close();
    wired?.close();
    data.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
