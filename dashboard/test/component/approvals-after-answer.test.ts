/**
 * approvals-after-answer.test — what happens after an answer, said on the
 * served product page (dashboard.md §4.34 "After you answer"). Found
 * 2026-10-11 on an audit of Approvals with a row of each kind:
 *
 *   - a send's card said "The AI's request goes to … with the real secret
 *     filled in", but the gate had refused that request: only a new try
 *     goes, and the agent was told to wait for the person, so nothing
 *     tries again until the person says so;
 *   - a program's held read said "asked 121 times" (the guard asks again
 *     every half second) and "reads the real file" an hour after the
 *     program stopped waiting;
 *   - an agent that ended hours ago stayed under Running now, waiting for
 *     your OK, while its question waited;
 *   - a card offering no Always allow named it in its third cell.
 *
 * The REAL DashboardServer over a FileEventSource whose policy snapshot
 * serves the queue the arbiter would, beside two recorded sessions (one
 * running, one that ended 3 hours ago). The served page (index.html,
 * home.js) runs in jsdom with its fetch bridged to that server. The
 * real-arbiter version is tests/stack/approval-after-answer.test.ts.
 * Axes: the store serves the Secrets posture; display only, no arbiter runs.
 */

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { JSDOM } from "jsdom";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import type { PolicySnapshot, VerdictEntry } from "../../src/policy-model.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { waitWhile } from "../unit/page-wait.js";
import { pageFetch } from "../unit/page-fetch.js";
import { walkthroughEvents } from "../unit/view-model/walkthrough-fixture.js";

const HOME = "/home/u";
const NOW = Date.now();
const H = "a".repeat(64);

const ask = (over: Partial<VerdictEntry>): VerdictEntry => ({
  id: "egr-0", symbol: "", destination: "", status: "pending", reason: "r",
  count: 1, firstSeen: NOW - 120_000, lastSeen: NOW - 60_000, resolvedAt: null, sessions: ["live"],
  ...over,
} as VerdictEntry);

const VERDICTS: VerdictEntry[] = [
  ask({ id: "egr-1", symbol: "$MDU:nomodel_Read[9bbd].STRIPE_KEY", destination: "api.stripe.com", source: { tool: "Read", origin: `${HOME}/proj/.env` } }),
  // The guard asked about this read 240 times while it held it, and gave up a minute ago.
  ask({ id: "egr-2", symbol: `open:/usr/bin/psql#${H}`, destination: `${HOME}/.pgpass`, count: 240, lastSeen: NOW - 60_000 }),
  // One run's change, no Always allow (plan 13 §8 (c)).
  ask({ id: "egr-3", symbol: `write:/usr/bin/bash#${H}#run:12-34`, destination: `${HOME}/.bashrc`, lastSeen: NOW - 60_000 }),
  // Asked by an agent that ended 3 hours ago.
  ask({ id: "egr-4", symbol: "fs:Read:read", destination: `${HOME}/.ssh/id_rsa`, reason: "sensitive path (~/.ssh): read by 'Read' requires approval", sessions: ["ended"], count: 2 }),
  // Answered held messages (dashboard.md §4.34 "A held message's answer"):
  // one sent masked, and a session's standing "as written".
  ask({ id: "egr-5", symbol: `prompt:acme.codename#${"b".repeat(32)}`, destination: `model:live#turn:${"c".repeat(32)}`, status: "denied", scope: "once", resolvedAt: NOW - 30_000 } as Partial<VerdictEntry>),
  ask({ id: "egr-6", symbol: `prompt:acme.codename#${"b".repeat(32)}`, destination: "model:live", status: "approved", scope: "always", resolvedAt: NOW - 20_000 } as Partial<VerdictEntry>),
  // An answer the arbiter marks as applying to nothing (§4.34 "Answers that no longer apply").
  ask({ id: "egr-7", symbol: "write:tee", destination: `${HOME}/.bashrc`, status: "approved", scope: "always", resolvedAt: NOW - 10_000, noLongerApplies: "name-only" } as Partial<VerdictEntry>),
];

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

const events = tmpDir("mandu-approvals-after-answer-");
for (const [session, ago] of [["live", 60_000], ["ended", 3 * 3_600_000]] as const) {
  writeFileSync(join(events, `${session}.ndjson`), walkthroughEvents({ session, startMs: NOW - ago, noNetwork: true }).map((e) => JSON.stringify(e)).join("\n") + "\n");
}
const mHome = tmpDir("mandu-approvals-after-answer-home-");
const server = new DashboardServer({ source: new QueueSource(events), configEnv: { MANDU_HOME: mHome }, fileBrowserHome: HOME, log: () => {} });
const base = `http://127.0.0.1:${await server.listen(0)}`;

after(async () => {
  await server.close();
  for (const d of [events, mHome]) rmSync(d, { recursive: true, force: true });
});

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

test("Approvals: each card says what happens after an answer, and that the person tells the agent to try again", async () => {
  const { doc, close } = await openPage("/approvals");
  try {
    const cards = () => [...doc.querySelectorAll("#approvals-waiting .ask")] as Element[];
    await until(() => cards().length === 4, `four waiting cards (got ${cards().length})`);
    const card = (id: string) => cards().find((c) => c.getAttribute("data-id") === id)!;
    const cells = (id: string) => [...card(id).querySelectorAll(".ask-detail > div")].map((c) => [squash(c.querySelector(".k")?.textContent), squash(c.querySelector(".v")?.textContent)]);
    const sub = (id: string) => squash(card(id).querySelector(".ask-sub")?.textContent);

    // A send: refused, so only a new try goes.
    assert.deepEqual(cells("egr-1")[2], ["If you click Allow once or Always allow",
      "The AI's next request goes to api.stripe.com with the real secret filled in. Mandu refused this one, so nothing was sent. After you answer, tell the agent to try again."]);
    // A program that stopped waiting: no re-ask count, the next run reads the file.
    assert.doesNotMatch(sub("egr-2"), /times/, "the guard's half-second re-asks are no count");
    assert.equal(squash(card("egr-2").querySelector(".ask-sentence")?.textContent), "Claude Code's program /usr/bin/psql wants to read a secret file: .pgpass");
    assert.equal(cells("egr-2")[2]![1], "The AI's program /usr/bin/psql stopped waiting and could not read the file. If you allow it, it reads the real file the next time the AI runs it. After you answer, tell the agent to try again. What it prints still reaches the AI masked.");
    // One run's change: no Always allow, none named; the run is over.
    assert.equal(cells("egr-3")[2]![0], "If you click Allow once");
    assert.equal(cells("egr-3")[2]![1], "The AI's program /usr/bin/bash running its own code stopped waiting and its change was refused. Your answer covers that run only, so a new try asks again.");
    assert.match(cells("egr-3")[0]![1]!, /Mandu held the change for a while, then refused it\./);
    // An ended agent's question: nothing waits on it now. With questions a
    // running agent waits on, it is listed after them, under a heading that
    // says so once (dashboard.md §4.25 *A question from a session that has
    // ended*), so the card leaves its own sentence out.
    const list = doc.getElementById("approvals-waiting")!;
    const kids = [...list.children].map((c) => c.getAttribute("data-id") ?? c.className);
    assert.equal(kids.at(-1), "egr-4", "the ended one last");
    assert.equal(kids.at(-2), "ask-group-head");
    assert.equal(squash(list.querySelector(".ask-group-head h3")?.textContent), "From sessions that have ended");
    assert.equal(squash(list.querySelector(".ask-group-head p")?.textContent), "No agent is waiting on these now. Your answer decides what happens the next time an agent asks the same.");
    // Short under the heading (§4.25 *An ended question is short on
    // Approvals*): what each answer does is one press away.
    assert.match(sub("egr-4"), /, 2 times\. What each answer does$/);
    assert.equal(card("egr-4").querySelector(".ask-detail"), null, "no cells until pressed");
    (card("egr-4").querySelector(".ask-more") as HTMLButtonElement).click();
    assert.equal(cells("egr-4")[2]![0], "If you click Allow once or Always allow");
    assert.equal(card("egr-1").querySelector(".ask-more"), null, "a running agent's card is full");
    assert.doesNotMatch(sub("egr-1"), /has ended/, "a running agent's question");
    assert.doesNotMatch(doc.body.textContent ?? "", /\$MDU|model_context/);
  } finally {
    close();
  }
});

test("Home: an agent that ended with a question waiting is under Earlier, counting it, not under Running now", async () => {
  const { doc, close } = await openPage("/");
  try {
    const rows = (host: string) => [...doc.querySelectorAll(`#${host} .row.agent`)] as Element[];
    await until(() => rows("home-agents").length === 1 && rows("home-earlier").length === 1, "one running, one earlier");
    // The running one waits for your OK: the amber dot, its counts leading
    // with the question, and its prompt kept (dashboard.md §4.25 *Agents,
    // not sessions*): it reads as the ended one of the same task does.
    const live = rows("home-agents")[0]!;
    const ended = rows("home-earlier")[0]!;
    const first = (row: Element) => squash(row.querySelector(".agent-what .sub")!.textContent);
    assert.equal(live.querySelector(".dot")!.className, "dot warn");
    assert.match(squash(live.querySelector(".agent-counts")!.textContent), /^3 questions waiting for you, /, "its three questions lead its counts");
    assert.ok(first(live).length > 0);
    assert.equal(first(live), first(ended), "the same task's prompt on both rows");
    assert.doesNotMatch(squash(live.textContent), /Waiting for your OK/);
    const earlier = squash(ended.textContent);
    assert.match(earlier, /1 question waiting for you/);
    assert.doesNotMatch(earlier, /Waiting for your OK/);
  } finally {
    close();
  }
});

test("Approvals › Answered earlier: a held message's answer says what went to the AI; one message's has no reversal, the session's flips as itself", async () => {
  const { doc, close } = await openPage("/approvals");
  try {
    const row = (id: string) => doc.querySelector(`#approvals-answered .row.answered[data-id="${id}"]`);
    await until(() => !!row("egr-5") && !!row("egr-6"), "both answered held messages");
    const cells = (id: string) => [...row(id)!.children].slice(1).map((c) => squash(c.textContent));
    assert.deepEqual(cells("egr-5"), ["Sent masked, or cancelled", ""], "never Blocked, and no Allow instead");
    assert.deepEqual(cells("egr-6"), ["Sent as written for the session", "Send masked instead"]);
    assert.equal(squash(row("egr-5")!.querySelector(".answered-sentence")?.textContent), "Claude Code wants to send your message to the AI. It holds acme.codename.");
  } finally {
    close();
  }
});

test("Approvals › Answered earlier: an answer that applies to nothing any more says why and offers no change", async () => {
  const { doc, close } = await openPage("/approvals");
  try {
    const row = () => doc.querySelector('#approvals-answered .row.answered[data-id="egr-7"]');
    await until(() => !!row(), "the stale answer");
    assert.match(squash(row()!.querySelector(".answered-stale")?.textContent), /^This answer no longer applies: it names the program by its name only/);
    assert.equal(squash(row()!.querySelector(".outcome")?.textContent), "No longer applies");
    assert.equal(row()!.querySelectorAll("button").length, 0);
  } finally {
    close();
  }
});

test("Approvals › Answered earlier: the answers sit under the day they were given, Today, as History's sessions do (§4.34 *Answers sit under their day*)", async () => {
  const { doc, close } = await openPage("/approvals");
  try {
    const list = () => doc.getElementById("approvals-answered")!;
    await until(() => list().querySelectorAll(".row.answered").length === 3, "the three answers");
    // The local day of each answer, as the page keys it; the run starting
    // just past midnight puts an answer 30 s old under Yesterday, so the
    // words follow the clock rather than assume one day.
    const pad = (k: number) => String(k).padStart(2, "0");
    const day = (ms: number) => { const d = new Date(ms); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; };
    const today = day(Date.now());
    const words = (key: string) => (key === today ? "Today" : "Yesterday");
    // Newest first: egr-7, egr-6, egr-5 (answered 10, 20 and 30 s before NOW).
    const expected: string[] = [];
    let last = "";
    for (const [id, ms] of [["egr-7", NOW - 10_000], ["egr-6", NOW - 20_000], ["egr-5", NOW - 30_000]] as const) {
      if (day(ms) !== last) expected.push(`# ${words(day(ms))}`);
      last = day(ms);
      expected.push(id);
    }
    const order = [...list().children].map((x) => x.matches(".history-day") ? `# ${squash(x.textContent)}` : (x as HTMLElement).dataset.id ?? x.className);
    assert.deepEqual(order, expected);
    for (const h of list().querySelectorAll(".history-day")) {
      assert.equal(h.tagName, "H3", "a heading under Answered earlier's h2");
      assert.equal(h.getAttribute("data-id"), null, "never taken for an answer");
    }
  } finally {
    close();
  }
});
