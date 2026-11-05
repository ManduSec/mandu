/**
 * history-find-secret.test — History's Find a session also finds where a
 * secret came up or a send went, across the REAL components (dashboard.md
 * §4.25ae *By a secret or a host*, #249). Mandu-new.
 *
 * Until then the search read only each row's agent, first prompt and
 * folder: after a scare, "which session touched STRIPE_KEY?" or "what went
 * to api.stripe.com?" found nothing, though the session's page answers it.
 * Here a real ArbiterServer at the `secrets` axes whose event store holds
 * the recorded first-session tour (dashboard/test/fixtures/
 * tour-1791164083-1418381.ndjson, fake secrets: `STRIPE_KEY` in
 * `~/mandu-try/.env` masked, `~/mandu-try/deploy/staging.conf` read before
 * it was marked, a send to `api.stripe.com` blocked and one let through) and
 * three newer plain sessions, and a DashboardServer over the production
 * adapter (`makeApprovalsArbiter`) and a real ArbiterEventSource, signed out
 * (the History read is open):
 *
 *   E1  `?q=STRIPE_KEY`, `?q=staging.conf` and `?q=api.stripe.com` each list
 *       the tour, and only it, with `found` naming why; `?q=zzz` lists none;
 *   E2  the served `/history?q=STRIPE_KEY` draws the tour's row with
 *       "Found here: STRIPE_KEY in ~/mandu-try/.env", the count "1 of 4
 *       sessions"; `?q=api.stripe.com` draws "Found here: a send to
 *       api.stripe.com";
 *   E3  the oracle: a search for one of the tour's fake values, or a piece
 *       of one, or `$MDU`, finds nothing (matching stays on names, never
 *       originals); no History answer (but its echo of what was typed) and no
 *       drawn page holds a value or a `$MDU:` token;
 *   E4  a host Mandu blocked every send to (the tour holds one more blocked
 *       request, to `pastebin.com`): `?q=pastebin` draws "Found here: a
 *       blocked send to pastebin.com", never "a send to", and that name is a
 *       link to `/agents/<id>?go=blocked`; pressed, it opens the session
 *       with its blocked step focused and marked; "STRIPE_KEY" links Your
 *       secrets; no value or token on either page (#301).
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
const PLAIN = [`${1791200000}-${process.pid}`, `${1791200001}-${process.pid}`, `${1791200002}-${process.pid}`];

test("History's search finds where a secret came up or a send went, by name, and never by a value (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-history-find-secret-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const eventDir = join(tmp, "events");
  mkdirSync(eventDir, { recursive: true });
  // The tour, its times moved so it ended an hour ago; three plain
  // sessions after it, newest first in the list.
  const events = readFileSync(FIXTURE, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { ts: string });
  // One more request Mandu blocked, to pastebin.com, just after the tour's
  // blocked send to api.stripe.com (a copy of it): a host only blocked.
  const at = events.findIndex((e) => (e as { kind?: string; action?: string }).kind === "net_action" && (e as { action?: string }).action === "blocked");
  assert.ok(at >= 0, "the tour has a blocked send");
  const blocked = events[at] as { id: string; ts: string };
  events.splice(at + 1, 0, JSON.parse(JSON.stringify({ ...blocked, id: `${blocked.id}:pastebin`, ts: new Date(Date.parse(blocked.ts) + 50).toISOString() })
    .split("api.stripe.com").join("pastebin.com").split("egr-1").join("egr-pb")) as { ts: string });
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
    // The tour recorded its folder under /home/user: names are `~/…`.
    fileBrowserHome: "/home/user", configEnv: { MANDU_HOME: join(tmp, "mandu-home"), HOME: home },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const served: string[] = [];
  /** A signed-out History read; `served` keeps the answer but its echo of the search. */
  const read = async (q: string): Promise<HistoryVM> => {
    const res = await pageFetch(`${base}/api/home/history?q=${encodeURIComponent(q)}`);
    assert.equal(res.status, 200, "signed out, the History read is open");
    const vm = await res.json() as HistoryVM;
    served.push(JSON.stringify({ ...vm, query: vm.query ? { ...vm.query, text: undefined } : undefined }));
    return vm;
  };
  const rows = (doc: Document) => [...doc.querySelectorAll("#history-list .row.agent")].map((r) => (r as HTMLElement).dataset.session);
  try {
    // ── E1: by a secret's name, a file, a host ──
    const all = await (await pageFetch(`${base}/api/home/history`)).json() as HistoryVM;
    assert.deepEqual(all.rows.map((r) => r.id), [...[...PLAIN].reverse(), ID], "the tour is the oldest of four");
    const cases: Array<[string, string]> = [
      ["STRIPE_KEY", "STRIPE_KEY in ~/mandu-try/.env"],
      ["staging.conf", "the file ~/mandu-try/deploy/staging.conf"],
      ["api.stripe.com", "a send to api.stripe.com"],
    ];
    for (const [q, why] of cases) {
      const vm = await read(q);
      assert.deepEqual(vm.rows.map((r) => r.id), [ID], `${q}: the tour, and only it`);
      assert.deepEqual(vm.rows[0]!.found?.map((n) => n.name), [why], `${q}: why it is listed`);
      assert.equal(vm.total, 1);
      assert.equal(vm.query?.through, undefined, "it looked through every session");
    }
    const none = await read("zzz");
    assert.deepEqual(none.rows, []);
    assert.equal(none.total, 0);

    // ── E2: the served page ──
    const pages: string[] = [];
    await servedProductPage(base, "/history?q=STRIPE_KEY", (doc) => rows(doc).length === 1, (doc) => {
      assert.deepEqual(rows(doc), [ID]);
      assert.equal(doc.querySelector("#history-list .history-found")?.textContent, "Found here: STRIPE_KEY in ~/mandu-try/.env");
      assert.equal(doc.getElementById("history-count")!.textContent, "1 of 4 sessions");
      assert.equal(doc.getElementById("history-q")!.getAttribute("placeholder"), "What you asked, a folder, secret or host");
      pages.push(doc.documentElement.outerHTML);
    });
    await servedProductPage(base, "/history?q=api.stripe.com", (doc) => rows(doc).length === 1, (doc) => {
      assert.equal(doc.querySelector("#history-list .history-found")?.textContent, "Found here: a send to api.stripe.com");
      pages.push(doc.documentElement.outerHTML);
    });

    // ── E4: a host only blocked: "a blocked send to", a link to the blocked steps (#301) ──
    const pb = await read("pastebin");
    assert.deepEqual(pb.rows.map((r) => r.id), [ID]);
    assert.deepEqual(pb.rows[0]!.found, [{ name: "a blocked send to pastebin.com", go: "blocked" }]);
    await servedProductPage(base, "/history?q=pastebin", (doc) => rows(doc).length === 1, async (doc) => {
      const line = doc.querySelector("#history-list .history-found");
      assert.equal(line?.textContent, "Found here: a blocked send to pastebin.com");
      assert.doesNotMatch(doc.getElementById("history-list")!.textContent!, /a send to pastebin/, "never read as sent");
      const a = line.querySelector("a");
      assert.equal(a.getAttribute("href"), `/agents/${ID}?go=blocked`);
      pages.push(doc.documentElement.outerHTML);
      a.click();
      const w = doc.defaultView;
      await waitWhile(() => !doc.activeElement?.dataset?.stepId);
      const step = doc.activeElement;
      assert.equal(w.location.pathname, `/agents/${ID}`, "the session's page");
      assert.equal(step.dataset.outcome, "blocked", "a blocked step has the focus");
      assert.ok(step.classList.contains("shown"), "marked");
      assert.equal(step.closest("[hidden]"), null, "in sight");
      assert.match(doc.getElementById("agent-story").textContent, /Mandu blocked a request to pastebin\.com/, "the page says blocked too");
      pages.push(doc.documentElement.outerHTML);
    });
    await servedProductPage(base, "/history?q=STRIPE_KEY", (doc) => rows(doc).length === 1, async (doc) => {
      const a = doc.querySelector("#history-list .history-found a");
      assert.equal(a.textContent, "STRIPE_KEY in ~/mandu-try/.env");
      assert.equal(a.getAttribute("href"), `/agents/${ID}?go=secrets`);
      a.click();
      await waitWhile(() => doc.activeElement?.tagName !== "H2");
      assert.equal(doc.activeElement, doc.getElementById("agent-secrets-block").querySelector("h2"), "Your secrets' heading has the focus");
      pages.push(doc.documentElement.outerHTML);
    });

    // ── E3: the oracle ──
    for (const q of [...FAKE_VALUES, FAKE_VALUES[0]!.slice(0, 12), FAKE_VALUES[2]!.slice(5), "$MDU", "$MDU:"]) {
      const vm = await read(q);
      assert.deepEqual(vm.rows, [], `${q}: a search for a value or a token finds nothing`);
      assert.equal(vm.total, 0);
    }
    for (const text of [...served, ...pages]) {
      for (const v of FAKE_VALUES) assert.ok(!text.includes(v), `CONFIDENTIALITY VIOLATION: History served the tour's value ${v}`);
      assert.doesNotMatch(text, /\$MDU:/, "nor a token");
    }
  } finally {
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
