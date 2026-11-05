/**
 * rule-its-sessions.test — a file's rule on Rules and a secret's card on
 * its session page each open History searched for that file, across the
 * REAL components (dashboard.md §4.25f *A rule finds its sessions*, §4.25b
 * *A card finds its other sessions*, queue #250). Mandu-new.
 *
 * History's Find a session finds the sessions where a secret came up by its
 * card's name or its file (#249), but the two places where a person looks
 * at one file had no way there: the opened rule's links ended with *Show in
 * its folder*, the card's with *Show its steps* (this session only). Here a
 * real ArbiterServer at the `secrets` axes whose event store holds the
 * recorded first-session tour (dashboard/test/fixtures/
 * tour-1791164083-1418381.ndjson, fake secrets: `STRIPE_KEY` in
 * `~/mandu-try/.env` masked) and two newer plain sessions, a `no-model`
 * rule on the tour's `.env` in policy.yaml, and a DashboardServer over the
 * production adapter (`makeApprovalsArbiter`), signed in:
 *
 *   S1  the served Rules page: the `.env` rule's opened row links *Its
 *       sessions on History* to `/history?q=~%2Fmandu-try%2F.env`, named
 *       "Its sessions on History: ~/mandu-try/.env"; following it lands on
 *       History with the box holding the path and the tour listed, alone,
 *       with its Found line;
 *   S2  the served session page: the `.env` card links *Its other
 *       sessions* to the same search; following it lands the same way;
 *   S3  the oracle: no page, address or History answer along the way holds
 *       one of the tour's fake values or a `$MDU:` token, and following the
 *       links changed no rule.
 *
 * Every request goes through `pageFetch` (a socket of its own), as a stack
 * test that runs a served page must (served-page-fetch).
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HistoryVM } from "../../dashboard/src/view-model/home.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

after(() => resetCurrentPolicyForTests("claude-code"));

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ID = "1791164083-1418381";
const FIXTURE = join(REPO, "dashboard", "test", "fixtures", `tour-${ID}.ndjson`);
/** The tour's fake secrets (scripts/tour-screenshots.mjs FAKE_VALUES). */
const FAKE_VALUES = ["sk_live_fake_123456", "FAKE-STAGING-TOKEN-0000", "FAKE-STRIPE-KEY-0000"];
const PLAIN = [`${1791200000}-${process.pid}`, `${1791200001}-${process.pid}`];
/** The tour recorded its folder under /home/user. */
const HOME = "/home/user";
const ENV = `${HOME}/mandu-try/.env`;
const FILE = "~/mandu-try/.env";
const HREF = `/history?q=${encodeURIComponent(FILE)}`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const historyRows = (doc: Doc) => [...doc.querySelectorAll("#history-list .row.agent")].map((r: Doc) => r.dataset.session);
const ruleRow = (doc: Doc) => [...doc.querySelectorAll("#files-tree .row.file-rule")].find((r: Doc) => r.getAttribute("data-path") === ENV);
const ruleLink = (doc: Doc) => doc.querySelector("#files-tree .file-detail a.rule-sessions-link");
const cardLink = (doc: Doc) => [...doc.querySelectorAll("#agent-secrets a.secret-sessions-link")].find((a: Doc) => a.getAttribute("data-land") === `q:${FILE}`);

test("a file's rule and a secret's card open History searched for the file, and it lists the session; no value anywhere (secrets axes, explicit)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rule-its-sessions-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const eventDir = join(tmp, "events");
  mkdirSync(eventDir, { recursive: true });
  // The tour, its times moved so it ended an hour ago; plain sessions after it.
  const events = readFileSync(FIXTURE, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { ts: string });
  const shift = Date.now() - 3_600_000 - Date.parse(events.at(-1)!.ts);
  writeFileSync(join(eventDir, `${ID}.ndjson`), events.map((e) => JSON.stringify({ ...e, ts: new Date(Date.parse(e.ts) + shift).toISOString() })).join("\n") + "\n");
  for (const [i, sid] of PLAIN.entries()) {
    const ts = new Date(Date.now() - 1_800_000 + i * 60_000).toISOString();
    writeFileSync(join(eventDir, `${sid}.ndjson`), JSON.stringify({
      id: `ev_plain_${i}`, sessionId: sid, turn: 0, ts, seq: 0, callId: null, parentId: null,
      kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
      input: { symbolized: `▸ user\nRename the parser helper ${i}.`, original: null, differs: false, symbols: [] },
      output: { symbolized: "Done.", original: null, differs: false, symbols: [] },
      invariant: { violatedInvariant: false }, model: { id: "claude-opus-4-8", inputTokens: 10, outputTokens: 2 },
    }) + "\n");
  }
  // The person's rule on the tour's .env (the tour's file is under /home/user,
  // which this host need not have: the rule is drawn all the same).
  const policyPath = join(tmp, "policy.yaml");
  const policyText = `version: 1\npaths:\n  - path: ${ENV}\n    level: no-model\n`;
  writeFileSync(policyPath, policyText);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir, policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter is wired");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, secretsArbiter: wired.secrets,
    postureArbiter: wired.posture, auditArbiter: wired.audit,
    fileBrowserHome: HOME, configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const seen: string[] = [];
  const signedIn = { headers: { Cookie: ADMIN_COOKIE } };
  /** History, landed: the box holds the path and the tour is listed alone. */
  const landed = (doc: Doc, from: string) => {
    const w = doc.defaultView;
    assert.equal(w.location.pathname + w.location.search, HREF, `${from}: the address holds the search`);
    assert.equal(doc.getElementById("page-history").hidden, false, `${from}: History`);
    assert.equal(doc.getElementById("history-q").value, FILE, `${from}: the box holds the path`);
    assert.deepEqual(historyRows(doc), [ID], `${from}: the tour, and only it`);
    assert.equal(doc.querySelector("#history-list .history-found")?.textContent, `Found here: STRIPE_KEY in ${FILE}`);
    seen.push(w.location.href, doc.documentElement.outerHTML);
  };
  try {
    // The search the links carry finds the tour (#249), on the open read too.
    const answer = await pageFetch(`${base}/api/home/history?q=${encodeURIComponent(FILE)}`);
    assert.equal(answer.status, 200);
    const text = await answer.text();
    seen.push(text);
    assert.deepEqual((JSON.parse(text) as HistoryVM).rows.map((r) => r.id), [ID]);

    // ── S1: the opened rule on Rules ──
    await servedProductPage(base, "/rules", (doc: Doc) => !!ruleRow(doc), async (doc: Doc) => {
      ruleRow(doc).querySelector(".file-more").click();
      await waitWhile(() => !ruleLink(doc), 5_000);
      const a = ruleLink(doc);
      assert.equal(a.textContent, "Its sessions on History");
      assert.equal(a.getAttribute("href"), HREF, "a plain link, the path searched");
      assert.equal(a.getAttribute("aria-label"), `Its sessions on History: ${FILE}`);
      seen.push(doc.documentElement.outerHTML);
      a.click();
      await waitWhile(() => historyRows(doc).length !== 1, 20_000);
      landed(doc, "from Rules");
    }, signedIn);

    // ── S2: the secret's card on the session page ──
    await servedProductPage(base, `/agents/${ID}`, (doc: Doc) => !!cardLink(doc), async (doc: Doc) => {
      const a = cardLink(doc);
      assert.equal(a.textContent, "Its other sessions");
      assert.equal(a.getAttribute("href"), HREF);
      assert.equal(a.getAttribute("aria-label"), `Its other sessions: ${FILE}`);
      assert.match(a.closest(".secret-card").querySelector(".secret-what").textContent, /STRIPE_KEY in ~\/mandu-try\/\.env/, "on the .env key's card");
      seen.push(doc.documentElement.outerHTML);
      a.click();
      await waitWhile(() => historyRows(doc).length !== 1, 20_000);
      landed(doc, "from the card");
    }, signedIn);

    // ── S3: the oracle ──
    assert.ok(seen.length >= 7);
    for (const t of seen) {
      for (const v of FAKE_VALUES) assert.ok(!t.includes(v), `CONFIDENTIALITY VIOLATION: a page, an address or an answer carries the tour's value ${v}`);
      assert.doesNotMatch(t, /\$MDU:/, "nor a token");
    }
    assert.equal(readFileSync(policyPath, "utf8"), policyText, "following the links changed no rule");
  } finally {
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
