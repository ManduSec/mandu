/**
 * agent-neighbours.test — a session's page links the sessions History lists
 * just above and below it, across the REAL components (dashboard.md §4.25b
 * *Newer and older sessions*, #253). Mandu-new.
 *
 * Until then, reading sessions one after another cost a round trip through
 * History each: the page had no way to the session before or after it. Here
 * a real ArbiterServer at the `secrets` axes whose event store holds the
 * recorded first-session tour (dashboard/test/fixtures/
 * tour-1791164083-1418381.ndjson, fake secrets: `STRIPE_KEY` masked, a
 * send to `api.stripe.com`) and one newer plain session, and a
 * DashboardServer over the production adapter (`makeApprovalsArbiter`) and
 * a real ArbiterEventSource, signed out:
 *
 *   N1  `/api/home/agent?session=<tour>` has `neighbours.newer` = the plain
 *       session, named as its `/api/home/history` row, and no `older`; the
 *       plain session's page has the tour as `older` and no `newer`;
 *   N2  the served page of the tour draws "← Newer: Claude Code · Rename
 *       the parser helper. · <time>" under What happened; a click opens the
 *       plain session's page (its address, its prompt), whose line has
 *       "Older: …" back to the tour, and whose back link reads "Back to home"
 *       (the first page was opened by its address, no page before it);
 *   N2b (#291) opened from History instead: the plain session's row, then
 *       Older to the tour; its back link still reads "Back to History",
 *       and a click goes back the whole chain to History (no entry added),
 *       the row you opened in view with the focus;
 *   N3  the oracle: neither page's neighbours, nor the drawn line, holds one
 *       of the tour's fake values or a `$MDU:` token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HistoryVM } from "../../dashboard/src/view-model/home.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page-types.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ID = "1791164083-1418381";
const FIXTURE = join(REPO, "dashboard", "test", "fixtures", `tour-${ID}.ndjson`);
/** The tour's fake secrets (scripts/tour-screenshots.mjs FAKE_VALUES). */
const FAKE_VALUES = ["sk_live_fake_123456", "FAKE-STAGING-TOKEN-0000", "FAKE-STRIPE-KEY-0000"];
const PLAIN = `${1791200000}-${process.pid}`;

test("a session's page links the newer and older sessions History lists beside it, and a click opens one (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-agent-neighbours-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const eventDir = join(tmp, "events");
  mkdirSync(eventDir, { recursive: true });
  // The tour, its times moved so it ended an hour ago; a plain session after it.
  const events = readFileSync(FIXTURE, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { ts: string });
  const shift = Date.now() - 3_600_000 - Date.parse(events.at(-1)!.ts);
  writeFileSync(join(eventDir, `${ID}.ndjson`), events.map((e) => JSON.stringify({ ...e, ts: new Date(Date.parse(e.ts) + shift).toISOString() })).join("\n") + "\n");
  writeFileSync(join(eventDir, `${PLAIN}.ndjson`), JSON.stringify({
    id: "ev_plain_0", sessionId: PLAIN, turn: 0, ts: new Date(Date.now() - 1_800_000).toISOString(), seq: 0, callId: null, parentId: null,
    kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: { symbolized: "▸ user\nRename the parser helper.", original: null, differs: false, symbols: [] },
    output: { symbolized: "Done.", original: null, differs: false, symbols: [] },
    invariant: { violatedInvariant: false }, model: { id: "claude-opus-4-8", inputTokens: 10, outputTokens: 2 },
  }) + "\n");
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir, policyPath: join(tmp, "policy.yaml"), policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production adapter is wired");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, secretsArbiter: wired.secrets,
    postureArbiter: wired.posture, auditArbiter: wired.audit,
    fileBrowserHome: "/home/user", configEnv: { MANDU_HOME: join(tmp, "mandu-home"), HOME: home },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const agent = async (id: string): Promise<AgentPageVM> => {
    const res = await pageFetch(`${base}/api/home/agent?session=${encodeURIComponent(id)}`);
    assert.equal(res.status, 200, "signed out, the page is a projection");
    return await res.json() as AgentPageVM;
  };
  const served: string[] = [];
  try {
    // ── N1: the neighbours, as History lists them ──
    const rows = (await (await pageFetch(`${base}/api/home/history`)).json() as HistoryVM).rows;
    assert.deepEqual(rows.map((r) => r.id), [PLAIN, ID], "the tour is the older of two");
    const tour = await agent(ID);
    const plain = await agent(PLAIN);
    assert.deepEqual(tour.neighbours, { newer: { id: PLAIN, agent: rows[0]!.agent, title: "Rename the parser helper.", at: rows[0]!.lastAt }, older: null });
    assert.deepEqual(plain.neighbours, { newer: null, older: { id: ID, agent: rows[1]!.agent, title: rows[1]!.title, at: rows[1]!.lastAt } });
    served.push(JSON.stringify(tour.neighbours), JSON.stringify(plain.neighbours));

    // ── N2: the served page, and a click ──
    await servedProductPage(base, `/agents/${ID}`, (doc) => doc.querySelectorAll("#agent-neighbours a").length === 1, async (doc) => {
      const nav = doc.getElementById("agent-neighbours");
      assert.equal(nav.hidden, false);
      const link = nav.querySelector("a");
      const words = String(link.textContent).replace(/\s+/g, " ").trim();
      assert.match(words, /^← Newer: Claude Code · Rename the parser helper\. · (?:\d{2}:\d{2}|yesterday \d{2}:\d{2})$/);
      assert.equal(link.dataset.session, PLAIN);
      served.push(nav.outerHTML);
      link.click();
      const win = doc.defaultView;
      await waitWhile(() => !win.location.pathname.endsWith(`/agents/${PLAIN}`));
      await waitWhile(() => !(doc.querySelector("#agent-neighbours a")?.dataset.session === ID));
      assert.match(doc.getElementById("agent-sub").textContent, /Rename the parser helper\./, "the plain session's page");
      assert.match(String(nav.querySelector("a").textContent).replace(/\s+/g, " ").trim(), /^Older: .+ →$/);
      assert.equal(doc.getElementById("agent-back").textContent, "Back to home");
      served.push(nav.outerHTML);
    });

    // ── N2b: a chain opened from History keeps its way back ──
    const rowLink = (doc: any, id: string) => doc.querySelector(`#history-list .row.agent[data-session="${id}"]`); // eslint-disable-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, "/history", (doc) => !!rowLink(doc, PLAIN), async (doc) => {
      const win = doc.defaultView;
      const back = () => doc.getElementById("agent-back");
      rowLink(doc, PLAIN).querySelector("a").click();
      await waitWhile(() => !win.location.pathname.endsWith(`/agents/${PLAIN}`));
      assert.equal(back().textContent, "Back to History");
      await waitWhile(() => !(doc.querySelector("#agent-neighbours a.older")?.dataset.session === ID));
      doc.querySelector("#agent-neighbours a.older").click();
      await waitWhile(() => !win.location.pathname.endsWith(`/agents/${ID}`));
      await waitWhile(() => !(doc.querySelector("#agent-neighbours a")?.dataset.session === PLAIN));
      assert.equal(back().textContent, "Back to History", "one Older on, still the page the chain started from");
      assert.equal(new URL(back().href).pathname, "/history");
      served.push(doc.getElementById("agent-neighbours").outerHTML);
      const length = win.history.length;
      back().click();
      await waitWhile(() => !win.location.pathname.endsWith("/history"));
      await waitWhile(() => doc.activeElement !== rowLink(doc, PLAIN));
      assert.equal(doc.getElementById("page-history").hidden, false, "History is shown");
      assert.equal(win.history.length, length, "Back, not a new page");
      assert.equal(doc.activeElement, rowLink(doc, PLAIN), "the row you opened has the focus");
    });

    // ── N3: the oracle ──
    for (const text of served) {
      for (const v of FAKE_VALUES) assert.ok(!text.includes(v), `CONFIDENTIALITY VIOLATION: the neighbours carried the tour's value ${v}`);
      assert.doesNotMatch(text, /\$MDU:/, "nor a token");
    }
  } finally {
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
