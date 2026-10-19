/**
 * approvals-read-first.test — a waiting send of a secret the AI read as it
 * was before its label never says "the AI never read it" (dashboard.md §4.34
 * "Read before it was marked"), end to end over the served pages. Found
 * 2026-10-07: every send card said "Mandu masked it, so the AI never read
 * it" and "It has never read the real one", also for the tour's
 * `staging.conf`, which the AI read at 10:41 and which was labelled at 10:42.
 *
 * The REAL DashboardServer over a FileEventSource holding the first-session
 * tour (test/fixtures/tour-1791164083-1418381.ndjson, moved to the last
 * minute so Home's window holds it), whose policy snapshot serves the queue
 * the arbiter would: a send of the file and a send of `STRIPE_KEY` (masked
 * from the start), each raised by the tour session, and a send of the file
 * raised by a session not on record; and a program's read of the file
 * (`open:`, `trust:`) and of `.env`, the guard's held opens. The served product page (index.html,
 * home.js) runs in jsdom with its fetch bridged to that server, at
 * /approvals, at / and on the session's page; the inspector's words are read
 * off /api/policy/panel. The real-arbiter version is
 * tests/stack/approval-read-first.test.ts.
 * Axes: the store serves the Secrets posture; display only, no arbiter runs.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import type { PolicySnapshot, VerdictEntry } from "../../src/policy-model.js";
import type { PolicyPanelVM } from "../../src/view-model/policy-panel.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { waitWhile } from "../unit/page-wait.js";
import { pageFetch } from "../unit/page-fetch.js";

const ID = "1791164083-1418381";
const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", `tour-${ID}.ndjson`);
const HOME = "/home/user";
/** The first Read of deploy/staging.conf (10:41), as recorded. */
const DELIVERED = "2026-10-05T01:41:29.686Z";
const NOW = Date.now();

const READ_FIRST_WHY = "Mandu masks it now, but the AI read its real value before it was marked a secret. Sending it would show the real secret to paste.example.";
const READ_FIRST_NOW = "The AI read the real value before it was marked a secret. Since then it gets the masked version, but Mandu does not mask what the AI wrote itself.";
/** A program's read of the file the AI read first (§4.34). */
const FILE_READ_FIRST_NOW = (program: string) => `The AI read the file as it was before it was marked a secret, and its program ${program} has not read it. Since then the AI gets the masked version, but Mandu does not mask what the AI wrote itself.`;
const H = "c".repeat(64);

const ask = (over: Partial<VerdictEntry>): VerdictEntry => ({
  id: "egr-0", symbol: "", destination: "paste.example", status: "pending", reason: "secret symbol (no-model) at unbound destination",
  count: 1, firstSeen: NOW - 120_000, lastSeen: NOW - 60_000, resolvedAt: null, sessions: [ID],
  ...over,
} as VerdictEntry);

const VERDICTS: VerdictEntry[] = [
  ask({ id: "egr-1", symbol: "$MDU:nomodel_Read[1131]", lastSeen: NOW - 5_000, source: { tool: "Read", origin: `${HOME}/mandu-try/deploy/staging.conf` } }),
  ask({ id: "egr-2", symbol: "$MDU:nomodel_Read[5c6e].STRIPE_KEY", destination: "api.stripe.com", lastSeen: NOW - 10_000, source: { tool: "Read", origin: `${HOME}/mandu-try/.env` } }),
  ask({ id: "egr-3", symbol: "$MDU:nomodel_Read[1131]", destination: "gist.github.com", lastSeen: NOW - 20_000, sessions: ["1791000000-1"] }),
  // A program's read of a secret file (the guard's held open): its
  // destination is the file. Of the file read first, as a known reader and
  // as the warning question, and of .env, masked from the start.
  ask({ id: "egr-4", symbol: `open:/usr/bin/cat#${H}`, destination: `${HOME}/mandu-try/deploy/staging.conf`, lastSeen: NOW - 25_000, reason: "held for the human" }),
  ask({ id: "egr-5", symbol: `trust:/usr/local/bin/deploy#${H}`, destination: `${HOME}/mandu-try/deploy/staging.conf`, lastSeen: NOW - 30_000, reason: "held for the human" }),
  ask({ id: "egr-6", symbol: `open:/usr/bin/cat#${H}`, destination: `${HOME}/mandu-try/.env`, lastSeen: NOW - 35_000, reason: "held for the human" }),
];

/** A file source behind which the arbiter serves the Secrets posture and
 *  the queue above. */
class QueueSource extends FileEventSource {
  override async policySnapshot(): Promise<PolicySnapshot | null> {
    return {
      specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
      posture: { integrity: false, confidentiality: true },
      usage: { rules: [], sensitivePaths: [] },
      verdicts: VERDICTS,
    } as unknown as PolicySnapshot;
  }
}

let server: DashboardServer;
let base: string;
let events: string;
let mHome: string;
/** The recorded moments, moved with the session. */
let shift = 0;
const moved = (iso: string) => new Date(Date.parse(iso) + shift).toISOString();

before(async () => {
  events = tmpDir("mandu-approvals-read-first-");
  mHome = tmpDir("mandu-approvals-read-first-home-");
  const recorded = readFileSync(FIXTURE, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { ts: string });
  shift = NOW - 30_000 - Date.parse(recorded[recorded.length - 1]!.ts);
  writeFileSync(join(events, `${ID}.ndjson`), recorded.map((e) => JSON.stringify({ ...e, ts: moved(e.ts) })).join("\n") + "\n");
  server = new DashboardServer({ source: new QueueSource(events), configEnv: { MANDU_HOME: mHome }, fileBrowserHome: HOME, log: () => {} });
  base = `http://127.0.0.1:${await server.listen(0)}`;
});

after(async () => {
  await server.close();
  for (const d of [events, mHome]) rmSync(d, { recursive: true, force: true });
});

/** The served page at `path`, running against the server. */
async function openPage(path: string) {
  const html = await (await pageFetch(`${base}${path}`)).text();
  const js = await (await pageFetch(`${base}/js/home.js`)).text();
  const dom = new JSDOM(html.replace(/<script type="module"[^>]*><\/script>/, ""), {
    url: `${base}${path}`, runScripts: "outside-only", pretendToBeVisual: true,
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const w = dom.window as any;
  let closed = false;
  const gate = <T>(p: Promise<T>): Promise<T> =>
    p.then((v) => (closed ? new Promise<T>(() => {}) : v), (e) => (closed ? new Promise<T>(() => {}) : Promise.reject(e)));
  w.fetch = (url: string, { signal: _signal, ...init }: RequestInit = {}) =>
    gate(pageFetch(new URL(url, base).href, init).then(async (res) => {
      const body = await res.text();
      return { ok: res.ok, status: res.status, json: () => gate(Promise.resolve().then(() => JSON.parse(body))) };
    }));
  w.setInterval = () => 0;
  w.scrollTo = () => {};
  w.eval(js);
  return { doc: w.document as Document, close: () => { closed = true; w.close(); } };
}

async function until(check: () => boolean, what: string): Promise<void> {
  await waitWhile(() => !check());
  assert.ok(check(), what);
}

const squash = (s: string | null | undefined) => (s ?? "").replace(/\s+/g, " ").trim();

/** A card's detail cells by their labels. */
function cells(card: Element): Record<string, string> {
  const out: Record<string, string> = {};
  // The label is the cell's first text (a help button may follow it).
  for (const k of card.querySelectorAll(".ask-detail .k")) out[squash(k.firstChild?.textContent)] = squash(k.nextElementSibling?.textContent);
  return out;
}

test("Approvals: the file the AI read before its label says so in Why it stopped and What the AI has now; STRIPE_KEY's card keeps its claim", async () => {
  const { doc, close } = await openPage("/approvals");
  try {
    const cards = () => [...doc.querySelectorAll("#approvals-waiting .ask")] as Element[];
    await until(() => cards().length === 6, `six waiting cards (got ${cards().length})`);
    const card = (id: string) => cards().find((c) => c.getAttribute("data-id") === id)!;
    assert.equal(squash(card("egr-1").querySelector(".ask-sentence")?.textContent), "Claude Code wants to send a secret from ~/mandu-try/deploy/staging.conf to paste.example");
    const file = cells(card("egr-1"));
    assert.equal(file["Why it stopped"], READ_FIRST_WHY);
    assert.equal(file["What the AI has now"], READ_FIRST_NOW);
    // (The help beside "What the AI has now" explains masking in general.)
    assert.doesNotMatch(squash(card("egr-1").textContent), /never read it|never read the real/);
    // Masked from the start: the claim holds.
    const key = cells(card("egr-2"));
    assert.equal(key["Why it stopped"], "STRIPE_KEY comes from ~/mandu-try/.env. Mandu masked it, so the AI never read it. Sending it would show the real secret to api.stripe.com.");
    assert.equal(key["What the AI has now"], "The AI has only the masked version. It has never read the real one.");
    // Raised by a session Mandu has no record of: nothing known, as before.
    assert.match(cells(card("egr-3"))["Why it stopped"] ?? "", /^Mandu masked it, so the AI never read it\./);
    assert.doesNotMatch(doc.body.textContent ?? "", /\$MDU|FAKE-STAGING-TOKEN-0000/);
  } finally {
    close();
  }
});

test("Approvals: a program's read of the file the AI read before its label never says the AI has not seen it; a read of .env keeps its words", async () => {
  const { doc, close } = await openPage("/approvals");
  try {
    const cards = () => [...doc.querySelectorAll("#approvals-waiting .ask")] as Element[];
    await until(() => cards().length === 6, `six waiting cards (got ${cards().length})`);
    const card = (id: string) => cards().find((c) => c.getAttribute("data-id") === id)!;
    assert.equal(squash(card("egr-4").querySelector(".ask-sentence")?.textContent), "Claude Code's program /usr/bin/cat wants to read a secret file: staging.conf");
    assert.equal(cells(card("egr-4"))["What the AI has now"], FILE_READ_FIRST_NOW("/usr/bin/cat"));
    assert.equal(cells(card("egr-5"))["What the AI has now"], FILE_READ_FIRST_NOW("/usr/local/bin/deploy"));
    for (const id of ["egr-4", "egr-5"]) assert.doesNotMatch(squash(card(id).textContent), /has not seen the real file/, id);
    // .env was masked from its first read: the claim holds.
    assert.equal(cells(card("egr-6"))["What the AI has now"], "The AI has not seen the real file, and its program /usr/bin/cat has not read it.");
    assert.doesNotMatch(doc.body.textContent ?? "", /\$MDU|FAKE-STAGING-TOKEN-0000|FAKE-STRIPE-KEY-0000/);
  } finally {
    close();
  }
  // The inspector's row carries the raw delivery's time and the same words.
  const panel = ((await (await pageFetch(`${base}/api/policy/panel`)).json()) as { panel: PolicyPanelVM }).panel;
  const row = (id: string) => panel.queue.find((r) => r.id === id)!;
  for (const id of ["egr-4", "egr-5"]) assert.equal(row(id).readFirst, moved(DELIVERED), id);
  assert.equal(row("egr-4").words.aiNow, FILE_READ_FIRST_NOW("/usr/bin/cat"));
  assert.ok(!("readFirst" in row("egr-6")));
});

test("Home and the session's page: the waiting card about the file says the AI read it first", async () => {
  const home = await openPage("/");
  try {
    const card = () => home.doc.querySelector('#home-waiting .ask[data-id="egr-1"]');
    await until(() => card() !== null, "the staging.conf card is on Home");
    assert.ok(squash(card()!.querySelector(".ask-sub")?.textContent).startsWith(READ_FIRST_WHY + " "), "the why, then when it was asked");
  } finally {
    home.close();
  }
  // The session's page lists what waits on it from the same words.
  const agent = await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).text();
  assert.ok(agent.includes(READ_FIRST_WHY), "the session page's waiting card");
  assert.ok(!agent.includes("Mandu masked it, so the AI never read it. Sending it would show the real secret to paste.example."));
});

test("the served queue: the inspector's row carries the time and the same words; /api/home carries words, never the time or a token", async () => {
  const panel = ((await (await pageFetch(`${base}/api/policy/panel`)).json()) as { panel: PolicyPanelVM }).panel;
  const row = (id: string) => panel.queue.find((r) => r.id === id)!;
  assert.equal(row("egr-1").readFirst, moved(DELIVERED));
  assert.equal(row("egr-1").words.why, READ_FIRST_WHY);
  assert.equal(row("egr-1").words.aiNow, READ_FIRST_NOW);
  for (const id of ["egr-2", "egr-3"]) assert.ok(!("readFirst" in row(id)), id);
  const home = await (await pageFetch(`${base}/api/home`)).text();
  assert.ok(home.includes(READ_FIRST_WHY));
  // (`stats.readFirst` is the session's count of such items, as before.)
  assert.doesNotMatch(home, /\$MDU|"readFirst":"|FAKE-STAGING-TOKEN-0000/);
});
