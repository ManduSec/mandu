/**
 * home-js-home.test — Home (the product page's first screen): the hero,
 * the capped asks and the three verbs' routes + CSRF header, the running and
 * earlier agents with their version notices, the tab title count and nav
 * badge, the notification priming rule, and the first-run card.
 *
 * Split out of home-js.test.ts, which drove the PRODUCT page script
 * (public/js/home.js) in jsdom over a fetch stub (dashboard.md §4.25); the
 * shared harness and fixtures are in home-js-fixtures.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { ASK, CLOCK, home, load, tick, PUB } from "./home-js-fixtures.js";
import { declValue, flattenCss, mentions, stripComments } from "./css-flatten.js";

test("boots on Home: hero, capped asks, running + earlier agents, title count and nav badge", async () => {
  const { doc, err, window } = load();
  assert.equal(err, null);
  await tick();
  assert.equal(doc.getElementById("hero-headline").textContent, "One question is waiting for you.");
  assert.equal(doc.querySelectorAll("#home-waiting .ask").length, 1);
  assert.equal(doc.getElementById("nav-approvals-count").textContent, "1");
  assert.equal(doc.getElementById("nav-approvals-count").hidden, false);
  assert.match(doc.getElementById("home-agents").textContent, /Claude Code/);
  assert.doesNotMatch(doc.getElementById("home-agents").textContent, /Codex CLI/, "idle sessions are not 'running'");
  // An agent with a question waiting keeps what you asked and where, as
  // History draws it; its counts lead with the question (dashboard.md §4.25
  // *Agents, not sessions*). Never "Paused": a refused send or command does
  // not stop it.
  const waitingRow = doc.querySelector('#home-agents .row.agent[data-session="s1"]');
  assert.equal(waitingRow.querySelector(".dot").className, "dot warn", "the amber dot says it waits");
  assert.equal(waitingRow.querySelector(".agent-what .sub").textContent, "Fix the test in ~/ws");
  assert.equal(waitingRow.querySelector(".agent-what .sub").title, "Fix the test — /home/u/ws", "the folder whole on hover");
  assert.match(waitingRow.querySelector(".agent-counts").textContent, /^1 question waiting for you, /);
  assert.doesNotMatch(doc.getElementById("home-agents").textContent, /Paused|Waiting for your OK/);
  assert.equal(doc.getElementById("home-earlier-block").hidden, false);
  assert.match(doc.getElementById("home-earlier").textContent, /Codex CLI.*Old task/);
  assert.match(window.document.title, /^\(1\) Mandu$/);
  assert.match(doc.getElementById("favicon").href, /^data:image\/svg\+xml,/);
});

// ── Earlier: the window, not "today" (dashboard.md §4.25, Home) ─────────────

/** An idle (ended) Home agent row that last acted `hoursAgo` hours ago;
 *  `secrets` = its page's secret tiles (masked, read before marked). */
function idleAgent(id: string, hoursAgo: number, stats: Record<string, number> = {}, blocked = 0, secrets = { masked: 0, early: 0 }, untrusted = 0) {
  const at = new Date(Date.now() - hoursAgo * 3_600_000).toISOString();
  return {
    id, agent: "Claude Code", title: `Task ${id}`, cwd: null, startedAt: at, lastAt: at, state: "idle",
    stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0, ...stats }, secrets, untrusted, blocked, holds: true, waiting: 0,
  };
}

test("Earlier is headed by the server's window, never 'today', and each row says when it ended, counts or not", async () => {
  // 22 hours ago is yesterday for most of the day: the rolling window holds it.
  const vm = home({ agents: [idleAgent("e1", 3, { flows: 2, secret: 2, egressBlocked: 1 }, 1, { masked: 2, early: 0 }), idleAgent("e2", 22)] });
  const { doc, err } = load({ homeVm: vm });
  assert.equal(err, null);
  await tick();
  assert.equal(doc.getElementById("home-earlier-title").textContent, "Earlier in the last 24 hours");
  assert.doesNotMatch(doc.getElementById("home-earlier-block").textContent, /today/i);
  const [counted, quiet] = [...doc.querySelectorAll("#home-earlier .row.agent")] as any[];
  assert.equal(counted.querySelector(".agent-counts").textContent, "2 secrets masked, 1 action blocked");
  assert.equal(counted.querySelector(".agent-ended").textContent, "ended 3 hours ago", "a row with counts also says when");
  const time = counted.querySelector(".agent-ended time");
  assert.equal(time.getAttribute("datetime"), (vm.agents as any[])[0].lastAt);
  assert.match(time.getAttribute("title"), new RegExp(`^${CLOCK}$`), "the clock time on hover");
  assert.equal(quiet.querySelector(".agent-counts"), null);
  assert.equal(quiet.querySelector(".agent-ended").textContent, "ended 22 hours ago");
});

test("an Earlier row names its folder, as Running now and History do; a row without one names none", async () => {
  // A session lost its folder on its way from Running now to Earlier
  // (dashboard.md §4.25 *Agents, not sessions*).
  const shop = { ...idleAgent("e1", 3), title: "Fix the deploy script", cwd: "/home/u/projects/shop" };
  const { doc, err } = load({ homeVm: home({ waiting: [], agents: [shop, idleAgent("e2", 5)] }) });
  assert.equal(err, null);
  await tick();
  const first = (id: string) => doc.querySelector(`#home-earlier .row.agent[data-session="${id}"] .agent-what .sub`);
  assert.equal(first("e1").textContent, "Fix the deploy script in ~/projects/shop");
  assert.equal(first("e1").querySelector("code").textContent, "~/projects/shop", "the folder kept whole, as code");
  assert.equal(first("e1").title, "Fix the deploy script — /home/u/projects/shop", "the full path on hover");
  assert.equal(first("e2").textContent, "Task e2", "no folder recorded: no \" in \"");
  assert.equal(first("e2").querySelector("code"), null);
  const details = doc.querySelector('#home-earlier a[data-session="e1"]');
  assert.equal(details.getAttribute("aria-label"), "Details: Claude Code, Fix the deploy script in ~/projects/shop");
});

test("Earlier follows the window it is given; when its length is not known it makes no time claim", async () => {
  const many = Array.from({ length: 12 }, (_, i) => idleAgent(`m${i}`, 1 + i));
  const counts = { sessions: 12, masked: 0, secretsMasked: 0, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0 };
  const twelve = load({ homeVm: home({ window: { hours: 12, ...counts }, agents: many }) });
  await tick();
  assert.equal(twelve.doc.getElementById("home-earlier-title").textContent, "Earlier in the last 12 hours");
  assert.equal(twelve.doc.querySelectorAll("#home-earlier .row.agent").length, 10);
  assert.equal(twelve.doc.querySelector("#home-earlier > .row.dim").textContent, "2 more sessions in the last 12 hours. Show them");
  // "Show them" draws the rest in place, and the first of them takes the
  // focus (dashboard.md §4.25ad); the line goes.
  (twelve.doc.querySelector("#home-earlier > .row.dim button.show-rest") as any).click();
  const rows = [...twelve.doc.querySelectorAll("#home-earlier .row.agent")] as any[];
  assert.equal(rows.length, 12);
  assert.equal(twelve.doc.activeElement, rows[10], "the first row it brought");
  assert.equal(twelve.doc.querySelector("#home-earlier > .row.dim"), null);
  const unknown = load({ homeVm: home({ window: { hours: null, ...counts }, agents: many }) });
  await tick();
  assert.equal(unknown.err, null);
  assert.equal(unknown.doc.getElementById("home-earlier-title").textContent, "Earlier");
  assert.equal(unknown.doc.querySelector("#home-earlier > .row.dim").textContent, "2 more sessions. Show them");
  // A row whose last moment is not known says nothing about when, not "ended ".
  const noTime = load({ homeVm: home({ agents: [{ ...idleAgent("n1", 1), lastAt: null }] }) });
  await tick();
  assert.equal(noTime.doc.querySelector("#home-earlier .agent-ended"), null);
  assert.doesNotMatch(noTime.doc.getElementById("home-earlier").textContent, /ended/);
});

// ── A row's layout: counts under the prompt, the time alone (§4.25) ──────────

test("a row reads its counts under its prompt, and when it started or ended alone in the next column (§4.25)", async () => {
  // The tour's counts wrapped to four lines in a 220px third column beside a
  // mostly empty prompt column, and a running row with counts never said
  // when it started.
  const started = new Date(Date.now() - 3 * 60_000).toISOString();
  const running = { ...idleAgent("r1", 0), state: "running", startedAt: started, cwd: "/home/u/ws", secrets: { masked: 1, early: 0 }, blocked: 1, waiting: 1 };
  const tour = { ...idleAgent("t1", 3, {}, 1, { masked: 1, early: 1 }), sent: 1 };
  const { doc, err } = load({ homeVm: home({ waiting: [], agents: [running, tour] }) });
  assert.equal(err, null);
  await tick();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const classes = (node: any): string[] => [...node.children].map((c: any) => c.className);
  const rows = [...doc.querySelectorAll("#home-agents .row.agent, #home-earlier .row.agent")] as any[];
  assert.equal(rows.length, 2);
  for (const row of rows) assert.deepEqual(classes(row), ["name", "agent-what", "dim agent-when", "right"]);

  const [run, ended] = rows;
  const what = run.querySelector(".agent-what");
  assert.deepEqual(classes(what), ["sub ellipsis", "sub agent-counts"], "the prompt, then its counts under it");
  assert.equal(what.children[0].textContent, "Task r1 in ~/ws");
  assert.equal(what.children[1].textContent, "1 question waiting for you, 1 secret masked, 1 action blocked");
  const when = run.querySelector(".agent-when");
  assert.equal(when.textContent, "started 3 minutes ago", "counts do not hide when it started");
  assert.equal(when.querySelector(".agent-started time").getAttribute("datetime"), started);
  assert.match(when.querySelector("time").getAttribute("title"), new RegExp(`^${CLOCK}$`), "the clock time on hover");

  assert.deepEqual(classes(ended.querySelector(".agent-what")), ["sub ellipsis", "dim agent-counts"]);
  assert.equal(ended.querySelector(".agent-what > .agent-counts").textContent,
    "1 secret masked, 1 secret read before it was marked, 1 action blocked, 1 send with a real value filled in");
  assert.equal(ended.querySelector(".agent-when").textContent, "ended 3 hours ago", "the time column holds only the time");
});

test("a running row with nothing counted has no counts line; with no recorded start it makes no time claim, not 'started '", async () => {
  const quiet = { ...idleAgent("q1", 0.05), state: "running" };
  const unknown = { ...idleAgent("u1", 0), state: "running", startedAt: null, secrets: { masked: 1, early: 0 } };
  const { doc, err } = load({ homeVm: home({ waiting: [], agents: [quiet, unknown] }) });
  assert.equal(err, null);
  await tick();
  const [q, u] = [...doc.querySelectorAll("#home-agents .row.agent")] as any[];
  assert.equal(q.querySelector(".agent-counts"), null);
  assert.equal(q.querySelector(".agent-when").textContent, "started 3 minutes ago");
  assert.equal(u.querySelector(".agent-counts").textContent, "1 secret masked");
  assert.equal(u.querySelector(".agent-when").textContent, "");
  assert.doesNotMatch(u.textContent, /started/);
});

test("app.css: a Home row's counts sit in its widest column and wrap, never cut; its prompt keeps one line (§4.25)", () => {
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  const agentRow = rules.filter((r) => r.selectors.includes(".row.agent"));
  const wide = agentRow.find((r) => r.media === null)!;
  const cols = declValue(wide.block, "grid-template-columns")!.match(/minmax\([^)]*\)|\S+/g)!;
  assert.equal(cols.length, 4, "name, prompt and counts, when, Details");
  assert.equal(cols[1], "minmax(0, 1fr)", "the prompt's column takes the room left");
  for (const i of [0, 2, 3]) assert.match(cols[i]!, /^\d+px$/, "the others are fixed, so the rows line up");
  assert.ok(parseInt(cols[2]!, 10) <= 160, `the time's column is narrow (${cols[2]}): the counts are no longer in it`);
  assert.ok(agentRow.some((r) => r.media?.includes("max-width: 760px") && declValue(r.block, "grid-template-columns") === "1fr"), "a narrow screen stacks the row");
  const what = rules.find((r) => r.selectors.includes(".agent-what") && r.media === null)!;
  assert.ok(what, "the prompt's cell has its rule");
  assert.equal(declValue(what.block, "flex-direction"), "column", "the counts go under the prompt");
  assert.equal(declValue(what.block, "min-width"), "0", "so the prompt can ellipsize inside the grid cell");
  for (const r of rules.filter((x) => x.selectors.some((s) => mentions(s, ".agent-counts") || mentions(s, ".agent-what")))) {
    const where = `"${r.selectors.join(", ")}"${r.media ? ` in ${r.media}` : ""}`;
    assert.notEqual(declValue(r.block, "white-space"), "nowrap", `${where} keeps the counts on one line`);
    assert.notEqual(declValue(r.block, "text-overflow"), "ellipsis", `${where} cuts the counts`);
    assert.ok(!/^(hidden|clip)/.test(declValue(r.block, "overflow") ?? ""), `${where} clips the counts`);
  }
});

// ── Counts: the words and numbers of the session's own page (§4.25) ──────────

test("a row counts blocked actions as its page's tile does, from `blocked`, never 'send blocked' from the lineage", async () => {
  // The lineage's item count (egressBlocked) says 1; the page blocked 2 steps.
  const running = { ...idleAgent("r1", 0), state: "running", stats: { ...idleAgent("r1", 0).stats, flows: 1, secret: 1, egressBlocked: 1 }, secrets: { masked: 1, early: 0 }, blocked: 2 };
  const vm = home({ waiting: [], window: { hours: 24, sessions: 3, masked: 4, secretsMasked: 4, secretsEarly: 0, untrusted: 0, blocked: 3, sent: 0, waiting: 0 }, agents: [
    running,
    idleAgent("e1", 3, { flows: 2, secret: 2, egressBlocked: 1 }, 1, { masked: 2, early: 0 }),
    idleAgent("e2", 4, { flows: 1, secret: 1, egressBlocked: 1 }, 0, { masked: 1, early: 0 }),
  ] });
  const { doc, err } = load({ homeVm: vm });
  assert.equal(err, null);
  await tick();
  assert.match(doc.getElementById("home-agents").textContent, /1 secret masked, 2 actions blocked/);
  const rows = [...doc.querySelectorAll("#home-earlier .row.agent")] as any[];
  assert.deepEqual(rows.map((r) => r.querySelector(".agent-counts")?.textContent ?? null), ["2 secrets masked, 1 action blocked", "1 secret masked"]);
  assert.doesNotMatch(doc.getElementById("page-home").textContent, /sends? blocked/);
});

test("a row says its sends with a real value filled in, the words and count of its page's tile, after the blocked count (§4.25)", async () => {
  // The tour: its page's tiles say a send left with STRIPE_KEY filled in;
  // a row that left it out read as if Mandu only masked and blocked.
  const running = { ...idleAgent("r1", 0), state: "running", secrets: { masked: 2, early: 0 }, sent: 2 };
  const tour = { ...idleAgent("t1", 3, {}, 1, { masked: 1, early: 1 }), sent: 1 };
  const noSends = { ...idleAgent("t2", 4, {}, 2, { masked: 1, early: 0 }), sent: 0 };
  const { doc, err } = load({ homeVm: home({ waiting: [], agents: [running, tour, noSends] }) });
  assert.equal(err, null);
  await tick();
  assert.match(doc.getElementById("home-agents").textContent, /2 secrets masked, 2 sends with a real value filled in/);
  const rows = [...doc.querySelectorAll("#home-earlier .row.agent")].map((r: any) => r.querySelector(".agent-counts")?.textContent ?? null);
  assert.deepEqual(rows, [
    "1 secret masked, 1 secret read before it was marked, 1 action blocked, 1 send with a real value filled in",
    "1 secret masked, 2 actions blocked",
  ]);
  // Only a send: the row still has its counts line.
  const only = load({ homeVm: home({ waiting: [], agents: [{ ...idleAgent("s1", 2), sent: 1 }] }) });
  await tick();
  assert.equal(only.doc.querySelector("#home-earlier .agent-counts").textContent, "1 send with a real value filled in");
});

test("the hero's facts: actions blocked and sends with a real value filled in, each where allowed (§4.25)", async () => {
  const facts = async (w: Record<string, number>) => {
    const { doc, err } = load({ homeVm: home({ verdict: "secrets-only", headline: "Your secrets are guarded.", sentence: "No agent is running right now.", waiting: [], window: { hours: 24, sessions: 2, masked: 0, secretsMasked: 0, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0, ...w } }) });
    assert.equal(err, null);
    await tick();
    return doc.getElementById("hero-facts");
  };
  const many = await facts({ masked: 3, secretsMasked: 3, blocked: 2, sent: 3 });
  assert.match(many.textContent, /3 secrets masked before the AI saw them .*2 actions blocked.*3 sends with a real value filled in/);
  const sent = [...many.children].find((s: any) => /^\d+ sends? with a real value filled in$/.test(s.textContent)) as any;
  assert.equal(sent.title, "Each went to a destination allowed to receive it. A session's page shows where.");
  assert.doesNotMatch(many.textContent, /allowed by you|sends? blocked/);
  const one = await facts({ masked: 1, secretsMasked: 1, blocked: 1, sent: 1 });
  assert.match(one.textContent, /1 action blocked.*1 send with a real value filled in/);
  // One send is "It", not "Each".
  const oneSent = [...one.children].find((s: any) => /^1 send with a real value filled in$/.test(s.textContent)) as any;
  assert.equal(oneSent.title, "It went to a destination allowed to receive it. A session's page shows where.");
  const none = await facts({ masked: 1, secretsMasked: 1 });
  assert.doesNotMatch(none.textContent, /\d+ actions? blocked|with a real value filled in/, "a zero count is left out");
});

test("the hero and the rows count secrets as each session's page does: masked, read before marked (amber), untrusted only where masked; never 'items masked' or 'secrets guarded' (§4.25)", async () => {
  // The tour: three masked tokens, two secrets, one read before it was
  // marked. The lineage's `masked` / `stats.flows` are never drawn.
  const tour = idleAgent("t1", 3, { flows: 3, secret: 3, egressBlocked: 1 }, 1, { masked: 1, early: 1 });
  const twoEarly = idleAgent("t2", 4, { flows: 2, secret: 2 }, 0, { masked: 0, early: 2 });
  const frozen = idleAgent("t3", 5, { flows: 4, secret: 1 }, 0, { masked: 1, early: 0 }, 3);
  const window = { hours: 24, sessions: 3, masked: 9, secretsMasked: 2, secretsEarly: 3, untrusted: 3, blocked: 1, sent: 1, waiting: 0 };
  const { doc, err } = load({ homeVm: home({ verdict: "secrets-only", headline: "Your secrets are guarded.", sentence: "No agent is running right now.", waiting: [], window, agents: [tour, twoEarly, frozen] }) });
  assert.equal(err, null);
  await tick();
  const facts = doc.getElementById("hero-facts");
  // Each fact's own words (the window's lead, the "?" and its note are beside the first).
  const items = [...facts.children].map((f: any) => (f.querySelector(":scope > span:not(.help):not(.facts-when)") ?? f).textContent);
  assert.deepEqual(items, [
    "2 secrets masked before the AI saw them",
    "3 untrusted items masked before the AI saw them",
    "3 secrets the AI read before they were marked secrets",
    "1 action blocked",
    "1 send with a real value filled in",
  ]);
  // The first masked count carries the "?"; the early count is amber, with what it means.
  assert.equal(facts.querySelectorAll(".help-btn").length, 1);
  assert.ok(facts.children[0].querySelector(".help-btn"));
  assert.match(facts.children[0].textContent, /^In the last 24 hours: 2 secrets masked before the AI saw them \?/, "the window's lead, then the first count and its \"?\"");
  const early = [...facts.children].find((f: any) => /read before/.test(f.textContent)) as any;
  assert.ok(early.querySelector("strong.warn"), "amber, as the page's tile");
  assert.equal(early.title, "The AI read the real value as it was, before it was marked a secret. A session's page says when.");
  assert.doesNotMatch(facts.textContent, /items masked(?! before)|secrets? guarded|\b9\b/);
  const rows = [...doc.querySelectorAll("#home-earlier .row.agent")].map((r: any) => r.querySelector(".agent-counts")?.textContent ?? null);
  assert.deepEqual(rows, [
    "1 secret masked, 1 secret read before it was marked, 1 action blocked",
    "2 secrets read before they were marked",
    "1 secret masked, 3 untrusted items masked",
  ]);
  // Only untrusted items masked: the "?" moves to that count; one secret read early reads singular.
  const solo = load({ homeVm: home({ verdict: "protected", waiting: [], window: { ...window, secretsMasked: 0, secretsEarly: 1, untrusted: 1, blocked: 0, sent: 0 } }) });
  await tick();
  const soloFacts = solo.doc.getElementById("hero-facts");
  assert.match(soloFacts.children[0].textContent, /^In the last 24 hours: 1 untrusted item masked before the AI saw it/);
  assert.ok(soloFacts.children[0].querySelector(".help-btn"));
  assert.match(soloFacts.textContent, /1 secret the AI read before it was marked a secret/);
});

test("the hero's counts name their window: 'In the last 24 hours:' leads the first of them, whichever it is; a question waiting now comes first, outside it; an unknown window makes no time claim (§4.25)", async () => {
  const zero = { sessions: 2, masked: 0, secretsMasked: 0, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0 };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const facts = async (w: Record<string, number | null>): Promise<any> => {
    const { doc, err } = load({ homeVm: home({ verdict: "secrets-only", headline: "Your secrets are guarded.", sentence: "No agent is running right now.", protection: { level: "secrets", configured: "secrets", connected: true }, waiting: [], window: { hours: 24, ...zero, ...w } }) });
    assert.equal(err, null);
    await tick();
    return doc.getElementById("hero-facts");
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const texts = (f: any) => [...f.children].map((c: any) => c.textContent.replace(/\?.*$/s, "?"));

  // The masked count first: one item holds the lead, the count and its "?".
  const masked = await facts({ secretsMasked: 1, blocked: 2, sent: 1 });
  assert.deepEqual(texts(masked), [
    "In the last 24 hours: 1 secret masked before the AI saw it ?",
    "2 actions blocked",
    "1 send with a real value filled in",
  ]);
  const leads = masked.querySelectorAll(".facts-when");
  assert.equal(leads.length, 1, "one lead for the line");
  assert.equal(leads[0].textContent, "In the last 24 hours:");
  assert.equal(leads[0].title, "Each session active in the last 24 hours counts whole, including its steps before then.");
  assert.ok(masked.children[0].querySelector(".help-btn"), "the \"?\" stays beside the masked count");
  assert.equal(masked.children[0].querySelector("strong").textContent, "1");

  // Another count first: the lead goes on it, and its own title stays on the count.
  const early = await facts({ secretsEarly: 1, blocked: 1 });
  assert.deepEqual(texts(early), ["In the last 24 hours: 1 secret the AI read before it was marked a secret", "1 action blocked"]);
  const earlyFact = early.children[0].querySelector(":scope > span:not(.facts-when)");
  assert.match(earlyFact.title, /^The AI read the real value as it was/);
  assert.ok(earlyFact.querySelector("strong.warn"), "still amber");
  const blocked = await facts({ blocked: 1, sent: 2 });
  assert.deepEqual(texts(blocked), ["In the last 24 hours: 1 action blocked", "2 sends with a real value filled in"]);

  // A question waiting is about now (every pending one, of any age): first, never under the lead.
  const waiting = await facts({ secretsMasked: 4, blocked: 5, waiting: 2 });
  assert.deepEqual(texts(waiting), [
    "2 waiting for you",
    "In the last 24 hours: 4 secrets masked before the AI saw them ?",
    "5 actions blocked",
  ]);
  assert.equal(waiting.children[0].querySelector(".facts-when"), null);
  assert.ok(waiting.children[0].querySelector("strong.warn"), "amber, as before");
  const onlyWaiting = await facts({ waiting: 1 });
  assert.deepEqual(texts(onlyWaiting), ["1 waiting for you"]);
  assert.equal(onlyWaiting.querySelector(".facts-when"), null, "no window, no lead");

  // Nothing counted: the window is named once, in the empty line.
  assert.equal((await facts({})).textContent, "Nothing to count in the last 24 hours.");
  // The window the server says, never a fixed one.
  assert.match((await facts({ hours: 12, blocked: 1 })).textContent, /^In the last 12 hours: 1 action blocked$/);
  // Its length not known: the counts as they are, with no time claim.
  const unknown = await facts({ hours: null, secretsMasked: 1, blocked: 1 });
  assert.deepEqual(texts(unknown), ["1 secret masked before the AI saw it ?", "1 action blocked"]);
  assert.equal(unknown.querySelector(".facts-when"), null);
  assert.equal((await facts({ hours: null })).textContent, "Nothing to count.");
});

test("said once: while questions wait, the headline counts them, so the facts line does not say it again; a failed headline, which does not, still puts the count first (§4.25)", async () => {
  const zero = { sessions: 2, masked: 0, secretsMasked: 0, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0 };
  const secrets = { level: "secrets", configured: "secrets", connected: true };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const hero = async (over: Record<string, unknown>, w: Record<string, number>): Promise<any> => {
    const { doc, err } = load({ homeVm: home({ protection: secrets, ...over, window: { hours: 24, ...zero, ...w } }) });
    assert.equal(err, null);
    await tick();
    return doc;
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const texts = (f: any) => [...f.children].map((c: any) => c.textContent.replace(/\?.*$/s, "?"));
  const two = [ASK, { ...ASK, id: "egr-2" }];

  // Two questions waiting: the headline says so, and the line starts with the window's counts.
  const waiting = await hero({ verdict: "waiting", headline: "2 questions are waiting for you.", waiting: two }, { secretsMasked: 4, blocked: 5, waiting: 2 });
  assert.equal(waiting.getElementById("hero-headline").textContent, "2 questions are waiting for you.");
  const facts = waiting.getElementById("hero-facts");
  assert.deepEqual(texts(facts), ["In the last 24 hours: 4 secrets masked before the AI saw them ?", "5 actions blocked"]);
  assert.doesNotMatch(facts.textContent, /waiting/, "the count is said once, in the headline");
  assert.ok(facts.children[0].querySelector(".help-btn"), "the \"?\" stays beside the first count");
  assert.equal(waiting.querySelectorAll("#home-waiting .ask").length, 2, "the questions are still listed under the hero");
  // Nothing else in the window: its own empty line, never the count again.
  const only = await hero({ verdict: "waiting", headline: "One question is waiting for you." }, { waiting: 1 });
  assert.equal(only.getElementById("hero-facts").textContent, "Nothing to count in the last 24 hours.");

  // Protection failed while a question waits: that headline does not count it, so the line does, first and unled.
  const failed = await hero({ verdict: "failed", headline: "Protection failed.", sentence: "One item reached the AI unmasked in the last 24 hours." }, { blocked: 1, waiting: 1 });
  const failedFacts = failed.getElementById("hero-facts");
  assert.deepEqual(texts(failedFacts), ["1 waiting for you", "In the last 24 hours: 1 action blocked"]);
  assert.ok(failedFacts.children[0].querySelector("strong.warn"), "amber, as before");
  assert.equal(failedFacts.children[0].querySelector(".facts-when"), null);
});

test("on a busy day the lead says how many of the window's sessions the counts add up ('In 26 of the 31 sessions in the last 24 hours:'), and its title that the totals may be higher; all counted, or an older server, reads as before (§4.25)", async () => {
  const zero = { sessions: 31, masked: 0, secretsMasked: 0, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0 };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const facts = async (w: Record<string, number | null>): Promise<any> => {
    const { doc, err } = load({ homeVm: home({ verdict: "secrets-only", headline: "Your secrets are guarded.", sentence: "No agent is running right now.", protection: { level: "secrets", configured: "secrets", connected: true }, waiting: [], window: { hours: 24, ...zero, ...w } }) });
    assert.equal(err, null);
    await tick();
    return doc.getElementById("hero-facts");
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const texts = (f: any) => [...f.children].map((c: any) => c.textContent.replace(/\?.*$/s, "?"));

  const busy = await facts({ counted: 26, secretsMasked: 3, blocked: 2, waiting: 1 });
  assert.deepEqual(texts(busy), [
    "1 waiting for you",
    "In 26 of the 31 sessions in the last 24 hours: 3 secrets masked before the AI saw them ?",
    "2 actions blocked",
  ]);
  const lead = busy.querySelector(".facts-when");
  assert.equal(lead.textContent, "In 26 of the 31 sessions in the last 24 hours:");
  assert.equal(lead.title, "Only 26 of the 31 sessions active in the last 24 hours are added up (the newest, and any where protection failed), so the totals may be higher. History lists every session with its own counts. Each counts whole, including its steps before then.");
  // Without the developer view too, the title points at History (§4.25ae).
  const bare = load({ extensions: "", homeVm: home({ verdict: "secrets-only", headline: "Your secrets are guarded.", sentence: "No agent is running right now.", protection: { level: "secrets", configured: "secrets", connected: true }, waiting: [], window: { hours: 24, ...zero, counted: 26, secretsMasked: 3 } }) });
  await tick();
  assert.equal(bare.doc.querySelector("#hero-facts .facts-when").title, "Only 26 of the 31 sessions active in the last 24 hours are added up (the newest, and any where protection failed), so the totals may be higher. History lists every session with its own counts. Each counts whole, including its steps before then.");
  assert.ok(busy.children[1].querySelector(".help-btn"), "the \"?\" stays beside the first count");
  assert.equal(busy.querySelectorAll(".facts-when").length, 1);

  // Nothing in the counted sessions: never "nothing" over the window as a whole.
  assert.equal((await facts({ counted: 25 })).textContent, "Nothing to count in 25 of the 31 sessions in the last 24 hours.");
  // None could be counted: said, never "Nothing to count".
  assert.equal((await facts({ counted: 0 })).textContent, "None of the 31 sessions in the last 24 hours could be counted.");
  assert.equal((await facts({ sessions: 1, counted: 0 })).textContent, "The one session in the last 24 hours could not be counted.");
  // The window's length unknown: how many, with no time claim.
  const unknown = await facts({ hours: null, counted: 1, sessions: 2, blocked: 1 });
  assert.deepEqual(texts(unknown), ["In 1 of the 2 sessions: 1 action blocked"]);
  assert.doesNotMatch(unknown.querySelector(".facts-when").title, /hours|Each counts whole/);

  // Every session counted: the window's lead and title, as before.
  const all = await facts({ counted: 31, blocked: 1 });
  assert.deepEqual(texts(all), ["In the last 24 hours: 1 action blocked"]);
  assert.equal(all.querySelector(".facts-when").title, "Each session active in the last 24 hours counts whole, including its steps before then.");
  // A payload without `counted` (an older server): all of them, as before.
  assert.deepEqual(texts(await facts({ blocked: 1 })), ["In the last 24 hours: 1 action blocked"]);
  assert.equal((await facts({})).textContent, "Nothing to count in the last 24 hours.");
});

test("server strings are text: a code part carrying markup is not parsed", async () => {
  const { doc } = load();
  await tick();
  const code = doc.querySelector("#home-waiting .ask-sentence code");
  assert.equal(code.textContent, "<img src=x onerror=alert(1)>");
  assert.equal(doc.querySelector("#home-waiting img"), null);
});

test("the three verbs hit the approval routes with the CSRF header", async () => {
  for (const [label, verb] of [["Allow once", "approve-once"], ["Always allow", "approve"], ["Block", "deny"]] as const) {
    const { doc, calls } = load();
    await tick();
    const btn = [...doc.querySelectorAll("#home-waiting .ask button")].find((b: any) => b.textContent === label) as any;
    btn.click();
    await tick();
    const post = calls.find((c) => c.method === "POST");
    assert.ok(post, label);
    assert.equal(post!.url, `/mandu/api/egress/approvals/egr-1/${verb}`);
    assert.equal(post!.headers["X-Mandu-Control"], "1");
  }
});

test("notifications: the first visit primes silently, a later new ask notifies once", async () => {
  const first = load();
  await tick();
  assert.equal(first.notes.length, 0, "the backlog at first visit never floods");
  const stored = {
    "mandu.home.notifyPrimed": first.window.localStorage.getItem("mandu.home.notifyPrimed"),
    "mandu.home.seenAsks": first.window.localStorage.getItem("mandu.home.seenAsks"),
  };
  assert.equal(stored["mandu.home.notifyPrimed"], "1");
  const next = load({ storage: stored as Record<string, string>, homeVm: home({ waiting: [ASK, { ...ASK, id: "egr-2" }] }) });
  await tick();
  assert.equal(next.notes.length, 1);
  assert.equal(next.notes[0]!.title, "Mandu: Claude Code needs your OK");
  assert.match(next.notes[0]!.body, /wants to send text from a file/);
});

test("notifications: without permission nothing is shown and the page offers to turn them on", async () => {
  const { doc, notes } = load({ permission: "default", storage: { "mandu.home.notifyPrimed": "1" } });
  await tick();
  assert.equal(notes.length, 0);
  assert.equal(doc.getElementById("notify-offer").hidden, false);
});

// ── Rule changes notify too (dashboard.md §4.25 *Notifications*) ────────────

const PENDING = "GET policy/proposals?status=pending";
const REASON = "need it for deploy, key sk_live_reasonCanary0000 at exfil.example.net";
/** A rule change your agent asked for, its reason and rows naming a host and a file. */
const AGENT_RULE = {
  id: "pp-7", status: "pending", requester: "Your agent", byAgent: true, reason: REASON,
  headline: "Your agent wants to change a rule",
  rows: [[{ kind: "text", text: "Allow connecting to " }, { kind: "code", text: "exfil.example.net" }], [{ kind: "text", text: "Lock " }, { kind: "code", text: "~/app/.env" }]],
  createdAt: Date.now() - 60_000,
};
const DISK_RULE = { ...AGENT_RULE, id: "pp-8", requester: "policy.yaml", byAgent: false, onDisk: true, reason: undefined };
const YOURS = { ...AGENT_RULE, id: "pp-9", requester: "You", byAgent: false };
/** A browser primed for both kinds, its ask egr-1 already seen. */
const PRIMED_BOTH = { "mandu.home.notifyPrimed": "1", "mandu.home.seenAsks": "[\"egr-1\"]", "mandu.home.seenProposals": "[]" };

test("notifications: a rule change your agent asks for notifies once, in fixed words that hold no reason, row, host or file", async () => {
  let pending: unknown[] = [AGENT_RULE];
  const page = load({ storage: PRIMED_BOTH, routes: { [PENDING]: () => ({ proposals: pending }) } });
  await tick();
  assert.equal(page.notes.length, 1, page.notes.map((x) => x.title).join(" | "));
  const [note] = page.notes;
  assert.equal(note!.title, "Mandu: your agent asks to change a rule");
  assert.equal(note!.body, "Open Approvals to answer it.");
  for (const w of [note!.title, note!.body]) {
    assert.doesNotMatch(w, /sk_live|exfil|example\.net|\.env|deploy|Allow connecting/, w);
  }
  assert.deepEqual(JSON.parse(page.window.localStorage.getItem("mandu.home.seenProposals")!), ["pp-7"]);
  // The same rule change on the next poll: nothing more.
  page.doc.dispatchEvent(new page.window.Event("visibilitychange"));
  await tick();
  assert.equal(page.notes.length, 1, "seen: no second notification");
  // Its click opens Approvals with that card marked.
  note!.note.onclick();
  await tick();
  assert.equal(page.window.location.pathname, "/mandu/approvals/pp-7", "the address names the card");
  const card = page.doc.querySelector('#approvals-proposals .proposal[data-id="pp-7"]');
  assert.ok(card, "the card is drawn");
  assert.ok(card.classList.contains("focus"), "and marked");
  assert.equal(page.doc.getElementById("approvals-focus-note").hidden, true);
  // A later one notifies; the answered one is gone from the list.
  pending = [{ ...AGENT_RULE, id: "pp-10" }];
  page.doc.dispatchEvent(new page.window.Event("visibilitychange"));
  await tick();
  assert.equal(page.notes.length, 2);
});

test("notifications: the address a rule change's notification opened marks its card on a fresh load too", async () => {
  const page = load({ url: "http://127.0.0.1:4500/mandu/approvals/pp-7", storage: PRIMED_BOTH, routes: { [PENDING]: { proposals: [AGENT_RULE] } } });
  await tick();
  const card = page.doc.querySelector('#approvals-proposals .proposal[data-id="pp-7"]');
  assert.ok(card && card.classList.contains("focus"), "marked once its read drew it");
  assert.equal(page.doc.getElementById("approvals-focus-note").hidden, true);
});

test("notifications: a held policy.yaml change has its own words; one you asked for yourself says nothing", async () => {
  const page = load({ storage: PRIMED_BOTH, routes: { [PENDING]: { proposals: [DISK_RULE, YOURS] } } });
  await tick();
  assert.deepEqual(page.notes.map((x) => [x.title, x.body]), [["Mandu: a change to policy.yaml waits for your OK", "Open Approvals to answer it."]]);
  assert.deepEqual(JSON.parse(page.window.localStorage.getItem("mandu.home.seenProposals")!).sort(), ["pp-8", "pp-9"], "both recorded");
});

test("notifications: the first visit records the waiting rule changes silently, also in a browser already primed for asks", async () => {
  const routes = { [PENDING]: { proposals: [AGENT_RULE] } };
  const askPrimed: Record<string, string> = { "mandu.home.notifyPrimed": "1", "mandu.home.seenAsks": "[\"egr-1\"]" };
  for (const storage of [{}, askPrimed]) {
    const first = load({ storage, routes });
    await tick();
    assert.equal(first.notes.length, 0, JSON.stringify(storage));
    assert.deepEqual(JSON.parse(first.window.localStorage.getItem("mandu.home.seenProposals")!), ["pp-7"]);
  }
  // Turned off, or no permission: still recorded, so a later On brings no backlog.
  for (const opts of [{ permission: "default" }, { storage: { ...PRIMED_BOTH, "mandu.home.notifyOff": "1" } }]) {
    const quiet = load({ storage: PRIMED_BOTH, ...opts, routes });
    await tick();
    assert.equal(quiet.notes.length, 0);
    assert.deepEqual(JSON.parse(quiet.window.localStorage.getItem("mandu.home.seenProposals")!), ["pp-7"]);
  }
});

test("notifications: a refused rule-change read (no admin session) neither notifies nor records", async () => {
  const page = load({ storage: { ...PRIMED_BOTH, "mandu.home.seenProposals": "[\"pp-1\"]" },
    routes: { [PENDING]: { status: 403, body: { error: "admin session required" } } } });
  await tick();
  assert.equal(page.notes.length, 0);
  assert.equal(page.window.localStorage.getItem("mandu.home.seenProposals"), "[\"pp-1\"]", "untouched");
});

test("notifications: five new asks show three and then '2 more need your OK', which opens Approvals", async () => {
  const many = Array.from({ length: 5 }, (_, i) => ({ ...ASK, id: `egr-n${i}` }));
  const page = load({ storage: PRIMED_BOTH, homeVm: home({ waiting: many }) });
  await tick();
  assert.deepEqual(page.notes.map((x) => x.title), [
    "Mandu: Claude Code needs your OK", "Mandu: Claude Code needs your OK", "Mandu: Claude Code needs your OK",
    "Mandu: 2 more need your OK",
  ]);
  assert.equal(page.notes[3]!.body, "Open Approvals to see them.");
  page.notes[3]!.note.onclick();
  await tick();
  assert.equal(page.window.location.pathname, "/mandu/approvals");
  // Asks and rule changes count together: three asks and one rule change.
  const mixed = load({ storage: PRIMED_BOTH, homeVm: home({ waiting: many.slice(0, 3) }), routes: { [PENDING]: { proposals: [AGENT_RULE] } } });
  await tick();
  assert.deepEqual(mixed.notes.map((x) => x.title).slice(3), ["Mandu: 1 more needs your OK"]);
});

// ── The alarms: protection failed, the service stopped (dashboard.md §4.25
// *Notifications*) ─────────────────────────────────────────────────────────

/** Home with its waiting agent s1 shown failed (`holds: false`), nothing waiting. */
function failedHome() {
  const vm = home({ waiting: [], verdict: "failed", headline: "Protection failed." });
  (vm.agents as any[])[0] = { ...(vm.agents as any[])[0], state: "running", waiting: 0, holds: false };
  return vm;
}
const PRIMED = { "mandu.home.notifyPrimed": "1", "mandu.home.seenAsks": "[\"egr-1\"]", "mandu.home.seenFailed": "[]" };
const DOWN_HOME = { status: 503, body: { error: "the arbiter is not reachable", tenant: "live", unreachable: true } };
/** Home answered by `answer()` each poll; `readAgain` makes the page poll. */
function polled(answer: () => unknown, opts: { storage?: Record<string, string>; permission?: string; homeVm?: unknown } = {}) {
  const page = load({ ...opts, routes: { "GET home": () => answer() } });
  const readAgain = () => page.doc.dispatchEvent(new page.window.Event("visibilitychange"));
  return { ...page, readAgain };
}

test("alarms: a session newly failed notifies once, naming only its agent, and its click opens that session's page", async () => {
  const { notes, window, readAgain } = polled(() => failedHome(), { storage: PRIMED });
  await tick();
  assert.equal(notes.length, 1, notes.map((n) => n.title).join(" | "));
  assert.equal(notes[0]!.title, "Mandu: protection failed in Claude Code");
  assert.equal(notes[0]!.body, "Something reached the AI unmasked. Open its page to see what.");
  for (const w of [notes[0]!.title, notes[0]!.body]) {
    assert.doesNotMatch(w, /Fix the test|\/home\/u|~\/ws/, "never the session's prompt or folder");
  }
  assert.match(window.localStorage.getItem("mandu.home.seenFailed"), /"s1"/);
  readAgain();
  await tick();
  assert.equal(notes.length, 1, "the same session again: no second notification");
  notes[0]!.note.onclick();
  await tick();
  assert.equal(window.location.pathname, "/mandu/agents/s1");
});

test("alarms: the first visit records sessions already failed silently, and turned off or without permission none is shown", async () => {
  const first = load({ homeVm: failedHome() });
  await tick();
  assert.equal(first.notes.length, 0, "the first visit primes silently");
  assert.match(first.window.localStorage.getItem("mandu.home.seenFailed"), /"s1"/);
  for (const permission of ["default", "denied"]) {
    const { notes } = load({ homeVm: failedHome(), permission, storage: PRIMED });
    await tick();
    assert.equal(notes.length, 0, permission);
  }
  const off = load({ homeVm: failedHome(), storage: { ...PRIMED, "mandu.home.notifyOff": "1" } });
  await tick();
  assert.equal(off.notes.length, 0, "turned off in Settings");
  assert.match(off.window.localStorage.getItem("mandu.home.seenFailed"), /"s1"/, "still recorded, so turning on brings no backlog");
});

test("alarms: the service stopping right after a read with a running agent notifies once; a stop with none running says nothing", async () => {
  let answer: unknown = home({ waiting: [] });
  const page = polled(() => answer, { storage: PRIMED });
  await tick();
  assert.equal(page.notes.length, 0);
  answer = DOWN_HOME;
  page.readAgain();
  await tick();
  assert.equal(page.notes.length, 1, page.notes.map((n) => n.title).join(" | "));
  assert.equal(page.notes[0]!.title, "Mandu: the protection service stopped");
  assert.equal(page.notes[0]!.body, "Your agent's requests are blocked until it runs again. Open Settings to start it.");
  page.readAgain();
  await tick();
  assert.equal(page.notes.length, 1, "the next failed poll says nothing");
  page.notes[0]!.note.onclick();
  await tick();
  assert.equal(page.window.location.pathname, "/mandu/settings");
  // It answers again, an agent runs, it stops again: a new stop, told once.
  answer = home({ waiting: [] });
  page.readAgain();
  await tick();
  answer = DOWN_HOME;
  page.readAgain();
  await tick();
  assert.equal(page.notes.length, 2, "a later stop is told again");

  // No agent running (only an ended one): the stop is a normal state between agents.
  const idle = home({ waiting: [] });
  (idle.agents as any[])[0] = { ...(idle.agents as any[])[0], state: "idle", waiting: 0 };
  let quiet: unknown = idle;
  const between = polled(() => quiet, { storage: PRIMED });
  await tick();
  quiet = DOWN_HOME;
  between.readAgain();
  await tick();
  assert.equal(between.notes.length, 0, "a stop with no agent running says nothing");
  // Without permission, a stop under a running agent says nothing either.
  let denied: unknown = home({ waiting: [] });
  const blocked = polled(() => denied, { storage: PRIMED, permission: "denied" });
  await tick();
  denied = DOWN_HOME;
  blocked.readAgain();
  await tick();
  assert.equal(blocked.notes.length, 0);
});

test("alarms: Settings › Notifications' On line names all three", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/settings" });
  await tick();
  assert.equal(doc.getElementById("notify-state").textContent,
    "On. You get a notification when an agent needs your OK, when protection fails, and when the protection service stops under a running agent.");
});

test("an agent outside the tested versions shows a warning mark that opens its notice, as text (supported-agents.md)", async () => {
  const vm = home();
  const notice = "Claude Code 9.0.0 is newer than the versions Mandu was tested with (2.1.273 to 2.1.295). <b>x</b>";
  (vm.agents as any[])[0].notice = notice;
  (vm.agents as any[])[1].notice = "Codex 0.1.0 is older than the versions Mandu was tested with (0.136.0 to 0.162.0). Upgrade it if anything misbehaves.";
  const { doc, err } = load({ homeVm: vm });
  assert.equal(err, null);
  await tick();
  const btn = doc.querySelector("#home-agents .row.agent .name .notice-btn");
  assert.ok(btn, "a warning mark by the name");
  assert.ok(btn.querySelector("svg"), "drawn as an icon");
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  const pop = doc.getElementById(btn.getAttribute("aria-controls"));
  assert.equal(pop.hidden, true, "closed until clicked");
  const shown = doc.getElementById("home-agents").cloneNode(true);
  for (const p of shown.querySelectorAll(".help-pop")) p.remove();
  assert.doesNotMatch(shown.textContent, /newer than the versions/, "the row holds the mark, not the sentence");
  assert.equal(pop.textContent, notice, "rendered as text, never markup");
  assert.equal(pop.querySelector("b"), null);
  btn.click();
  assert.equal(btn.getAttribute("aria-expanded"), "true");
  assert.equal(pop.hidden, false, "a click opens it");
  btn.click();
  assert.equal(pop.hidden, true, "a second click closes it");
  const earlier = doc.querySelector("#home-earlier .notice-btn");
  assert.match(doc.getElementById(earlier.getAttribute("aria-controls")).textContent, /older than the versions Mandu was tested with/);
  assert.equal(doc.querySelector(".agent-notice"), null, "no sentence under any row");
  // A row without a notice gets no mark.
  const { doc: plain } = load();
  await tick();
  assert.equal(plain.querySelector("#home-agents .notice-btn"), null);
});

const PREVIEW = (label: string) => ({
  label,
  sentence: `${label} support is a preview: Mandu was tested less with it than with Claude Code and Codex.`,
  issues: "https://github.com/mandusec/mandu/issues",
});

test("a preview agent shows a Preview tag by its name that opens what that means and a link to report a problem (supported-agents.md §2.0)", async () => {
  const vm = home();
  (vm.agents as any[])[0].preview = PREVIEW("Goose");
  (vm.agents as any[])[0].notice = "Goose 1.55.0 is newer than the versions Mandu was tested with (1.53.0 to 1.54.0). It may not work as expected with Mandu.";
  (vm.agents as any[])[1].preview = { ...PREVIEW("OpenCode 2"), sentence: "<b>x</b> support is a preview." };
  const { doc, err } = load({ homeVm: vm });
  assert.equal(err, null);
  await tick();
  const name = doc.querySelector("#home-agents .row.agent .name");
  const tag = name.querySelector(".preview-btn");
  assert.ok(tag, "a tag by the name");
  assert.equal(tag.textContent, "Preview");
  assert.equal(tag.getAttribute("aria-label"), "Goose support is a preview");
  assert.equal(tag.getAttribute("aria-expanded"), "false");
  assert.ok(name.querySelector(".notice-btn"), "the version's warning mark stays, after the tag");
  assert.ok(tag.compareDocumentPosition(name.querySelector(".notice-btn")) & 4, "the tag comes first");
  const pop = doc.getElementById(tag.getAttribute("aria-controls"));
  assert.equal(pop.hidden, true, "closed until clicked");
  tag.click();
  assert.equal(pop.hidden, false, "a click opens it");
  assert.equal(pop.textContent, "Goose support is a preview: Mandu was tested less with it than with Claude Code and Codex. Report a problem.");
  const link = pop.querySelector("a");
  assert.equal(link.textContent, "Report a problem");
  assert.equal(link.getAttribute("href"), "https://github.com/mandusec/mandu/issues");
  assert.equal(link.getAttribute("target"), "_blank");
  assert.equal(link.getAttribute("rel"), "noopener noreferrer", "no referrer: the page's address names the session");
  link.dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true }));
  assert.equal(pop.hidden, false, "a click on its link keeps it open");
  doc.body.click();
  assert.equal(pop.hidden, true, "a click elsewhere closes it");
  // The earlier row's sentence is text, never markup.
  const earlier = doc.querySelector("#home-earlier .preview-btn");
  const earlierPop = doc.getElementById(earlier.getAttribute("aria-controls"));
  assert.match(earlierPop.textContent, /^<b>x<\/b> support is a preview\. Report a problem\.$/);
  assert.equal(earlierPop.querySelector("b"), null);
  // A supported agent's row gets no tag.
  const { doc: plain } = load();
  await tick();
  assert.equal(plain.querySelector(".preview-btn"), null);
});

test("an open note that would run past the window's right edge moves left inside it, never past the left margin", async () => {
  const vm = home();
  (vm.agents as any[])[0].preview = PREVIEW("Goose");
  const { doc } = load({ homeVm: vm });
  await tick();
  Object.defineProperty(doc.documentElement, "clientWidth", { value: 390, configurable: true });
  const tag = doc.querySelector("#home-agents .preview-btn");
  const pop = doc.getElementById(tag.getAttribute("aria-controls"));
  let rect = { left: 136, right: 456 };
  pop.getBoundingClientRect = () => ({ ...rect, top: 0, bottom: 60, width: rect.right - rect.left, height: 60 });
  tag.click();
  assert.equal(pop.style.left, "-82px", "456 - (390 - 16): it ends 16 px inside the window");
  tag.click();
  rect = { left: 20, right: 340 };
  tag.click();
  assert.equal(pop.style.left, "", "a note inside the window stays where it opens");
  tag.click();
  rect = { left: 30, right: 456 };
  tag.click();
  assert.equal(pop.style.left, "-14px", "never past the 16 px left margin");
});

// ── The first-run card (dashboard.md §4.25, "First-run card") ─────────────────

const FIRST_RUN = {
  mode: "secrets", saved: false, headline: "Get started with Mandu",
  protects: "Mandu is running in the Secrets mode. Untrusted content is not masked in this mode.",
  steps: [
    { id: "start", title: "Start your agent through Mandu", text: "Put mandu in front.", link: null,
      commands: [{ command: "mandu claude", does: "Claude Code" }, { command: "<img src=x onerror=alert(1)>", does: "<b>Codex CLI</b>" }] },
    { id: "secrets", title: "Mark what is secret", text: "Choose \"No AI\".",
      commands: [{ command: "mandu doctor --secrets", does: "lists them" }], link: { page: "rules", text: "Open Files and folders" } },
    { id: "check", title: "Check this computer", text: "Run mandu doctor.", commands: [{ command: "mandu doctor", does: "what it enforces" }], link: null },
  ],
};
const FRESH = () => home({
  verdict: "secrets-only", headline: "Your secrets are guarded.", sentence: "No agent is running right now.",
  protection: { level: "secrets", configured: "secrets", connected: true },
  window: { hours: 24, sessions: 0, masked: 0, secret: 0, blocked: 0, sent: 0, waiting: 0 },
  waiting: [], agents: [], history: { total: 0 }, firstRun: FIRST_RUN,
});

test("first run: the setup card renders the server's steps, commands as code, all as text", async () => {
  const { doc, err } = load({ homeVm: FRESH() });
  assert.equal(err, null);
  await tick();
  const card = doc.getElementById("home-first-run");
  assert.equal(card.hidden, false);
  assert.equal(card.dataset.mode, "secrets");
  assert.equal(doc.getElementById("first-run-headline").textContent, "Get started with Mandu");
  assert.match(doc.getElementById("first-run-protects").textContent, /not masked in this mode/);
  const steps = [...card.querySelectorAll(".first-run-step")] as any[];
  assert.deepEqual(steps.map((s) => s.dataset.step), ["start", "secrets", "check"]);
  assert.deepEqual([...steps[0].querySelectorAll("code")].map((c: any) => c.textContent), ["mandu claude", "<img src=x onerror=alert(1)>"]);
  assert.equal(card.querySelector("img"), null, "a command carrying markup stays text");
  assert.equal(card.querySelector("b"), null);
  assert.match(steps[2].textContent, /mandu doctor/);
  // The card sits above "Waiting for you", right under the hero.
  assert.equal(doc.getElementById("hero").nextElementSibling.id, "home-first-run");
});

test("first run: a step's sentence sent as parts draws each code part as code, all as text; a step without parts shows its text", async () => {
  // dashboard.md §4.25 "First-run card" (2026-10-08): the card's own
  // sentences name `mandu doctor`, `paths:` and the policy file as code, as
  // every other sentence the page writes does.
  const parts = (...xs: Array<string | [string]>) => xs.map((x) => (Array.isArray(x) ? { kind: "code", text: x[0] } : { kind: "text", text: x }));
  const check = parts("Run ", ["mandu doctor"], " in a terminal at any time.");
  const secrets = parts("Or add it under ", ["paths:"], " in ", ["~/.mandu/policy.yaml"], ", or ", ["<img src=x onerror=alert(1)>"], ".");
  const firstRun = {
    ...FIRST_RUN,
    steps: [
      FIRST_RUN.steps[0]!, // no parts: its text, as an older server sent it
      { ...FIRST_RUN.steps[1]!, text: secrets.map((p) => p.text).join(""), parts: secrets },
      { ...FIRST_RUN.steps[2]!, text: "Run mandu doctor in a terminal at any time.", parts: check },
    ],
  };
  const { doc, err } = load({ homeVm: { ...FRESH(), firstRun } });
  assert.equal(err, null);
  await tick();
  const sentence = (id: string) => doc.querySelector(`#home-first-run .first-run-step[data-step="${id}"] > p.note`) as any;
  assert.equal(sentence("check").textContent, "Run mandu doctor in a terminal at any time.", "the same words");
  assert.deepEqual([...sentence("check").querySelectorAll("code")].map((c: any) => c.textContent), ["mandu doctor"]);
  assert.equal(sentence("check").firstChild.nodeType, 3, "the text around the code is text");
  assert.deepEqual([...sentence("secrets").querySelectorAll("code")].map((c: any) => c.textContent), ["paths:", "~/.mandu/policy.yaml", "<img src=x onerror=alert(1)>"]);
  assert.equal(doc.querySelector("#home-first-run img"), null, "a part carrying markup stays text");
  assert.equal(sentence("start").textContent, "Put mandu in front.");
  assert.equal(sentence("start").querySelector("code"), null, "no parts: the text as written, one text node");
});

test("first run: the step's link opens the Rules page in place", async () => {
  const { doc, window } = load({ homeVm: FRESH() });
  await tick();
  const link = doc.querySelector('#home-first-run a[data-page-link="rules"]') as any;
  assert.equal(link.textContent, "Open Files and folders");
  link.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true }));
  await tick();
  assert.equal(doc.getElementById("page-rules").hidden, false);
  assert.equal(window.location.pathname, "/mandu/rules");
});

test("first run: the card goes away once a session exists (the next poll), and on a failed load", async () => {
  const { doc, window, setHome } = load({ homeVm: FRESH() });
  await tick();
  assert.equal(doc.getElementById("home-first-run").hidden, false);
  setHome(home()); // a session now exists: the server sends no firstRun
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick();
  assert.equal(doc.getElementById("home-first-run").hidden, true);
  assert.equal(doc.querySelectorAll("#first-run-steps li").length, 0);
  assert.match(doc.getElementById("home-agents").textContent, /Claude Code/);

  const failed = load({ homeVm: FRESH(), routes: { "GET home": { status: 500, body: {} } } });
  await tick();
  assert.equal(failed.doc.getElementById("home-first-run").hidden, true, "no card when the page could not load /api/home");
});

// ── Another agent can reach Mandu's own controls (dashboard.md §4.25x) ────────

const EXPOSURE = {
  headline: "Another agent can reach Mandu's own controls.",
  sentence: "An agent was started without the file guard.",
  fix: "Stop that agent, or start it again with the file guard on.",
  since: Date.now() - 120_000,
  causes: [{ pid: 4242, session: "claude-x1", words: "process 4242, session claude-x1, protection off, <b>no file guard</b>" }],
};

test("exposure: the notice names each agent and the fix while the server sends it, as text; it goes away when the next poll has none", async () => {
  const quiet = load();
  await tick();
  assert.equal(quiet.doc.getElementById("home-exposure").hidden, true, "no `exposure`: no notice");
  const { doc, err, window, setHome } = load({ homeVm: home({ exposure: EXPOSURE }) });
  assert.equal(err, null);
  await tick();
  const card = doc.getElementById("home-exposure");
  assert.equal(card.hidden, false);
  assert.equal(card.getAttribute("role"), "alert");
  assert.equal(doc.getElementById("exposure-headline").textContent, EXPOSURE.headline);
  assert.match(doc.getElementById("exposure-sentence").textContent, new RegExp(`^An agent was started without the file guard\\. Since ${CLOCK}`));
  const causes = [...card.querySelectorAll("#exposure-causes li")] as any[];
  assert.deepEqual(causes.map((c) => [c.dataset.pid, c.textContent]), [["4242", EXPOSURE.causes[0]!.words]]);
  assert.equal(card.querySelector("b"), null, "server words stay text");
  assert.equal(doc.getElementById("exposure-fix").textContent, EXPOSURE.fix);
  setHome(home()); // the other agent stopped: the server sends no exposure
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick();
  assert.equal(card.hidden, true);
  assert.equal(card.querySelectorAll("#exposure-causes li").length, 0);
});

test("exposure: the fix sent as parts draws its launch flags as code, the same words, as text (§4.25x)", async () => {
  const fixParts = [
    { kind: "text", text: "Stop that agent, or start it again with the file guard on (without " },
    { kind: "code", text: "--mode off" },
    { kind: "text", text: " or " },
    { kind: "code", text: "<b>--no-net-guard</b>" },
    { kind: "text", text: ")." },
  ];
  const fix = fixParts.map((p) => p.text).join("");
  const { doc, err } = load({ homeVm: home({ exposure: { ...EXPOSURE, fix, fixParts } }) });
  assert.equal(err, null);
  await tick();
  const el = doc.getElementById("exposure-fix");
  assert.equal(el.textContent, fix);
  assert.deepEqual([...el.querySelectorAll("code")].map((c: any) => c.textContent), ["--mode off", "<b>--no-net-guard</b>"]);
  assert.equal(el.querySelector("b"), null, "server parts stay text");
});

test("exposure: a cause sent as parts names its agent as a link to its page, an unnamed session as code; the link opens that page in place (§4.25x)", async () => {
  const known = [{ kind: "link", text: "Claude Code", to: "agent", session: "claude-x1" }, { kind: "text", text: ", process 4242, protection off, no file guard" }];
  const unnamed = [{ kind: "text", text: "process 4343, session " }, { kind: "code", text: "<b>codex-y2</b>" }, { kind: "text", text: ", secrets protection, no file guard" }];
  // A link part with no session, or to a place the page does not know: text.
  const odd = [{ kind: "link", text: "Goose", to: "agent", session: "" }, { kind: "link", text: " <i>x</i>", to: "elsewhere" }];
  const joined = (parts: Array<{ text: string }>) => parts.map((p) => p.text).join("");
  const causes = [
    { pid: 4242, session: "claude-x1", words: joined(known), parts: known },
    { pid: 4343, session: "<b>codex-y2</b>", words: joined(unnamed), parts: unnamed },
    { pid: 4444, session: null, words: joined(odd), parts: odd },
  ];
  const { doc, err, window, calls } = load({ homeVm: home({ exposure: { ...EXPOSURE, causes } }) });
  assert.equal(err, null);
  await tick();
  const items = [...doc.querySelectorAll("#exposure-causes li")] as any[];
  assert.deepEqual(items.map((li) => [li.dataset.pid, li.textContent]), causes.map((c) => [String(c.pid), c.words]), "the same words");
  assert.deepEqual(items.map((li) => [...li.querySelectorAll("code")].map((c: any) => c.textContent)), [[], ["<b>codex-y2</b>"], []]);
  const links = items.map((li) => [...li.querySelectorAll("a")]) as any[][];
  assert.deepEqual(links.map((l) => l.length), [1, 0, 0], "only the agent Home knows is a link");
  const a = links[0]![0];
  assert.equal(a.textContent, "Claude Code");
  assert.equal(a.getAttribute("href"), "/mandu/agents/claude-x1");
  assert.equal(a.dataset.pageLink, "agent");
  assert.equal(a.dataset.session, "claude-x1");
  assert.equal(doc.querySelector("#exposure-causes b, #exposure-causes i"), null, "server parts stay text");
  // Its page, in place.
  a.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true }));
  await tick();
  assert.equal(window.location.pathname, "/mandu/agents/claude-x1");
  assert.equal(doc.getElementById("page-agent").hidden, false);
  assert.equal(doc.getElementById("page-home").hidden, true);
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/agent?session=claude-x1"));
});

// ── Where your data lives (on-disk-layout.md §9.2) ────────────────────────────

const LOCATIONS = {
  home: "~/.mandu",
  locations: [
    { name: "mandu-home", path: "~/.mandu", where: "home", holds: "Mandu's folder: your settings at the top", developer: false, exists: true, mode: "0700", ownerOnly: true },
    { name: "events", path: "~/.mandu/events", where: "home", holds: "session history, kept 90 days", developer: false, exists: true, mode: "0755", ownerOnly: false },
    { name: "runs-root", path: "~/.mandu/runs", where: "home", holds: "test and evaluation results (developers)", developer: true, exists: false, brokenLink: false, mode: null, ownerOnly: null },
    { name: "packs", path: "~/.mandu/packs", where: "home", holds: "rule packs you installed", developer: false, exists: false, brokenLink: false, mode: null, ownerOnly: null },
    { name: "dev-root", path: "~/.mandu/dev", where: "home", holds: "files for Mandu's developers", developer: true, exists: true, mode: "0700", ownerOnly: true },
    { name: "cache-root", path: "~/.mandu/cache", where: "home", holds: "files Mandu can rebuild", developer: false, exists: true, brokenLink: true, mode: null, ownerOnly: null },
    { name: "ci-cache", path: "~/.mandu/cache/ci", where: "home", holds: "virtual machine images for Mandu's CI (developers)", developer: true, exists: false, brokenLink: false, mode: null, ownerOnly: null },
    { name: "runtime-dir", path: "/run/user/1000/mandu", where: "outside", holds: "running services <b>x</b>", developer: false, exists: true, mode: "0700", ownerOnly: null },
  ],
};

function openDataWhere(doc: any, window: any): void {
  const d = doc.getElementById("home-data");
  d.open = true;
  d.dispatchEvent(new window.Event("toggle"));
}

test("Where your data lives: closed and not fetched until opened; low on the Home page", async () => {
  const { doc, calls } = load({ routes: { "GET data-locations": LOCATIONS } });
  await tick();
  const block = doc.getElementById("home-data-block");
  assert.equal(block.closest("section[data-page]").id, "page-home");
  assert.equal(block.nextElementSibling, null, "the last section on the Home page");
  assert.equal(doc.getElementById("home-data").open, false, "closed by default");
  assert.equal(doc.querySelector("#home-data summary").textContent, "Where your data lives");
  assert.ok(!calls.some((c) => c.url.includes("data-locations")), "nothing fetched while closed");
  const about = doc.getElementById("home-data-about").textContent;
  assert.match(about, /one folder, ~\/\.mandu/);
  assert.match(about, /The AI cannot open it/);
  assert.match(about, /mandu paths/);
  assert.match(about, /To see every place, including the ones only Mandu's developers use, run mandu paths\.$/, "the terminal has the full list");
  assert.doesNotMatch(about, /\bagent\b/i, "the page says the AI");
});

test("Where your data lives: one line per location, only-you / open-to-others badges for Mandu's folder, a note for the open ones", async () => {
  const { doc, window, calls } = load({ routes: { "GET data-locations": LOCATIONS } });
  await tick();
  openDataWhere(doc, window);
  await tick();
  assert.ok(calls.some((c) => c.url === "/mandu/api/data-locations" && c.method === "GET"));
  const rows = [...doc.querySelectorAll("#home-data-list .data-where-row")] as any[];
  assert.equal(rows.length, 6, "the two developer places that are not there are left out");
  const row = (name: string) => rows.find((r) => r.dataset.name === name);
  assert.equal(row("mandu-home").querySelector(".sub").textContent, "Mandu's folder: your settings at the top");
  assert.equal(row("mandu-home").querySelector("code").textContent, "~/.mandu");
  assert.equal(row("mandu-home").querySelector(".tag").textContent, "only you");
  assert.equal(row("events").querySelector(".tag").textContent, "open to others");
  assert.equal(row("events").querySelector(".sub").textContent, "Session history, kept 90 days", "sentence case");
  assert.ok(row("packs").classList.contains("missing"));
  assert.equal(row("packs").querySelector(".tag"), null);
  assert.match(row("packs").textContent, /not there yet/);
  // A dangling symlink is there but broken (on-disk-layout.md §5), as in `mandu paths`.
  assert.ok(!row("cache-root").classList.contains("missing"));
  assert.equal(row("cache-root").querySelector(".tag").textContent, "broken link");
  assert.doesNotMatch(row("cache-root").textContent, /not there yet/);
  assert.equal(row("runtime-dir").querySelector(".tag"), null, "no badge outside Mandu's folder");
  assert.equal(row("runtime-dir").querySelector("b"), null, "server strings are text");
  assert.match(doc.getElementById("home-data-list").textContent, /Outside Mandu's folder/);
  const open = doc.getElementById("home-data-open");
  assert.equal(open.hidden, false);
  assert.match(open.textContent, /Other people on this computer can open 1 place in Mandu's folder/);
});

/** The list's lines in order: a row's name, or a group line's words. */
function dataLines(doc: any): string[] {
  return ([...doc.querySelectorAll("#home-data-list > .row")] as any[]).map((r) => (r.classList.contains("data-where-group") ? `[${r.textContent}]` : r.dataset.name));
}

test("Where your data lives: a developer place that is not there is left out; one that is there is listed under For Mandu's developers, after Mandu's folder", async () => {
  const { doc, window } = load({ routes: { "GET data-locations": LOCATIONS } });
  await tick();
  openDataWhere(doc, window);
  await tick();
  assert.deepEqual(dataLines(doc), ["mandu-home", "events", "packs", "cache-root", "[For Mandu's developers]", "dev-root", "[Outside Mandu's folder]", "runtime-dir"]);
  const dev = doc.querySelector('#home-data-list .data-where-row[data-name="dev-root"]');
  assert.equal(dev.querySelector(".tag").textContent, "only you", "keeps its badge");
  assert.ok(dev.previousElementSibling.classList.contains("data-where-group"), "the same group line as Outside Mandu's folder");
  assert.doesNotMatch(doc.getElementById("home-data-list").textContent, /CI \(developers\)|evaluation results/);

  // None there (a user's machine): no developers' line at all.
  const user = load({ routes: { "GET data-locations": { ...LOCATIONS, locations: LOCATIONS.locations.filter((l) => l.name !== "dev-root") } } });
  await tick();
  openDataWhere(user.doc, user.window);
  await tick();
  assert.deepEqual(dataLines(user.doc), ["mandu-home", "events", "packs", "cache-root", "[Outside Mandu's folder]", "runtime-dir"]);
});

test("Where your data lives: a developer place that is there and open to others is counted in the note", async () => {
  const locations = LOCATIONS.locations.map((l) => (l.name === "dev-root" ? { ...l, mode: "0755", ownerOnly: false } : l));
  const { doc, window } = load({ routes: { "GET data-locations": { ...LOCATIONS, locations } } });
  await tick();
  openDataWhere(doc, window);
  await tick();
  assert.equal(doc.querySelector('#home-data-list .data-where-row[data-name="dev-root"] .tag').textContent, "open to others");
  const open = doc.getElementById("home-data-open");
  assert.equal(open.hidden, false);
  assert.match(open.textContent, /Other people on this computer can open 2 places in Mandu's folder/);
});

test("Where your data lives: an older server's rows (no developer field) are all drawn, as before", async () => {
  const locations = LOCATIONS.locations.map(({ developer: _d, ...l }) => l);
  const { doc, window } = load({ routes: { "GET data-locations": { ...LOCATIONS, locations } } });
  await tick();
  openDataWhere(doc, window);
  await tick();
  assert.deepEqual(dataLines(doc), ["mandu-home", "events", "runs-root", "packs", "dev-root", "cache-root", "ci-cache", "[Outside Mandu's folder]", "runtime-dir"]);
  assert.doesNotMatch(doc.getElementById("home-data-list").textContent, /For Mandu's developers/);
});

test("Where your data lives: all owner-only → no warning; a failed load says so and points at mandu paths", async () => {
  const tight = { ...LOCATIONS, locations: LOCATIONS.locations.filter((l) => l.ownerOnly !== false) };
  const ok = load({ routes: { "GET data-locations": tight } });
  await tick();
  openDataWhere(ok.doc, ok.window);
  await tick();
  assert.equal(ok.doc.getElementById("home-data-open").hidden, true);

  const bad = load({ routes: { "GET data-locations": { status: 500, body: {} } } });
  await tick();
  openDataWhere(bad.doc, bad.window);
  await tick();
  assert.match(bad.doc.getElementById("home-data-list").textContent, /could not be loaded.*mandu paths/);
});

test("plan 15 §7: a held message's card shows the found text as text and answers the hold with the CSRF header", async () => {
  const PROMPT_ASK = {
    ...ASK, id: "egr-5", family: "prompt",
    sentence: [{ kind: "text", text: "Claude Code wants to send your message to the AI. It holds " }, { kind: "code", text: "acme.codename" }, { kind: "text", text: "." }],
    actions: [{ approve: true, scope: "once", prompt: "send", label: "Send as written" }],
  };
  for (const [label, answer] of [["Send as written", "send"], ["Send masked", "mask"], ["Cancel the message", "cancel"]] as const) {
    const { doc, calls } = load({
      homeVm: home({ waiting: [PROMPT_ASK] }),
      routes: { "GET prompt-filters/holds": { holds: [{ approvalId: "egr-5", span: "<img src=x onerror=alert(1)>falcon" }] } },
    });
    await tick();
    const found = doc.querySelector("#home-waiting .ask-found");
    assert.equal(found.textContent, "It found: <img src=x onerror=alert(1)>falcon");
    assert.equal(found.querySelector("img"), null, "the found text is text");
    const get = calls.find((c) => c.url.endsWith("/api/prompt-filters/holds"));
    assert.equal(get?.headers["X-Mandu-Control"], "1", "fetched with the CSRF header");
    const btn = [...doc.querySelectorAll("#home-waiting .ask button")].find((b: any) => b.textContent === label) as any;
    assert.ok(btn, label);
    btn.click();
    await tick();
    const post = calls.find((c) => c.method === "POST");
    assert.equal(post!.url, "/mandu/api/prompt-filters/holds/answer");
    assert.deepEqual(post!.body, { approvalId: "egr-5", answer, scope: "once" });
    assert.equal(post!.headers["X-Mandu-Control"], "1");
  }
});

test("plan 15 §12 (2026-10-04): under a locked ask row the Approvals card offers no session answer and says why", async () => {
  const NOTE = "Your administrator set this to ask every time, so your answer covers this message only. Mandu asks again the next time a message holds it.";
  const PROMPT_ASK = {
    ...ASK, id: "egr-6", family: "prompt",
    sentence: [{ kind: "text", text: "Claude Code wants to send your message to the AI. It holds " }, { kind: "code", text: "acme.codename" }, { kind: "text", text: "." }],
    actions: [{ approve: true, scope: "once", prompt: "send", label: "Send as written" }],
  };
  const url = "http://127.0.0.1:4500/mandu/approvals";
  const locked = load({ url, homeVm: home({ waiting: [{ ...PROMPT_ASK, onlyThisMessage: NOTE }] }), routes: { "GET prompt-filters/holds": { holds: [] } } });
  await tick();
  const card = locked.doc.querySelector('#approvals-waiting .ask[data-id="egr-6"]');
  assert.deepEqual([...card.querySelectorAll(".ask-actions button")].map((b: any) => b.textContent), ["Send as written", "Send masked", "Cancel the message"]);
  assert.equal(card.querySelector(".ask-once-only").textContent, NOTE);
  const open = load({ url, homeVm: home({ waiting: [PROMPT_ASK] }), routes: { "GET prompt-filters/holds": { holds: [] } } });
  await tick();
  const card2 = open.doc.querySelector('#approvals-waiting .ask[data-id="egr-6"]');
  assert.deepEqual([...card2.querySelectorAll(".ask-actions button")].map((b: any) => b.textContent), ["Send as written", "Send as written for this session", "Send masked", "Cancel the message"]);
  assert.equal(card2.querySelector(".ask-once-only"), null);
});

// ── the product names itself to the server (dashboard.md §6.y) ───────────────

test("every request the product makes carries X-Mandu-Front: product, so the inspector's Tests cookie never steers it", async () => {
  const { calls, doc } = load();
  await tick();
  // open the other pages too, so their reads are made
  for (const page of ["approvals", "rules", "settings"]) {
    (doc.querySelector(`[data-page-link="${page}"]`) as any).click();
    await tick();
  }
  const api = calls.filter((c) => c.url.includes("/api/"));
  const paths = new Set(api.map((c) => c.url.split("?")[0]));
  assert.ok(paths.size >= 5, `requests made: ${[...paths].join(", ")}`);
  for (const c of api) assert.equal(c.headers["X-Mandu-Front"], "product", `${c.method} ${c.url}`);
});

test("a home answered 503 unreachable says the protection service is not running, not that the server is unreachable", async () => {
  const { doc } = load({ routes: { "GET home": { status: 503, body: { error: "the arbiter is not reachable", tenant: "live", unreachable: true } } } });
  await tick();
  assert.equal(doc.getElementById("hero-headline").textContent, "Not connected.");
  const sentence = doc.getElementById("hero-sentence").textContent;
  // In words alone (§4.25, *The hero says why in words*): never the request
  // and its status, "(home → 503)", as until 2026-10-10.
  assert.equal(sentence, "The protection service is not running, so nothing can be checked. Start it under Settings, or refresh in a moment.");
  assert.doesNotMatch(sentence, /→|503|home/, "no request, no status");
  assert.doesNotMatch(sentence, /arbiter/, "the server's inspector words are not shown");
  // Settings has the service's Start, and the words link there (§4.25, *The
  // hero links where it points*).
  const start = [...doc.querySelectorAll("#hero-sentence a")] as any[];
  assert.deepEqual(start.map((a) => [a.textContent, a.getAttribute("href"), a.dataset.pageLink]), [["Start it under Settings", "/mandu/settings", "settings"]]);
  // A server that answered with an error says it answered, with its status,
  // never that it could not be reached; nothing to open.
  const plain = load({ routes: { "GET home": { status: 500, body: null } } });
  await tick();
  assert.equal(plain.doc.getElementById("hero-headline").textContent, "Not connected.");
  assert.equal(plain.doc.getElementById("hero-sentence").textContent, "The dashboard server answered with an error (500). Refresh in a moment.");
  assert.equal(plain.doc.querySelector("#hero-sentence a"), null);
  // A 503 that is not the service's `unreachable` is an error like any other.
  const other = load({ routes: { "GET home": { status: 503, body: { error: "busy" } } } });
  await tick();
  assert.equal(other.doc.getElementById("hero-sentence").textContent, "The dashboard server answered with an error (503). Refresh in a moment.");
});

test("a home whose request never got an answer says the dashboard could not reach its server, never the browser's own words", async () => {
  // The dashboard server is gone: fetch throws, in each browser's words
  // (Chrome "Failed to fetch", Firefox "NetworkError when attempting to
  // fetch resource.", Safari "Load failed", Node "fetch failed").
  for (const thrown of ["Failed to fetch", "NetworkError when attempting to fetch resource.", "Load failed", "fetch failed"]) {
    const { doc } = load({ routes: { "GET home": () => { throw new TypeError(thrown); } } });
    await tick();
    assert.equal(doc.getElementById("hero-headline").textContent, "Not connected.", thrown);
    assert.equal(doc.getElementById("hero-sentence").textContent, "The dashboard could not reach its own server. Refresh in a moment.", thrown);
    assert.equal(doc.querySelector("#hero-sentence a"), null, thrown);
    assert.equal(doc.getElementById("top-status").textContent, "Not connected", thrown);
  }
});

// ── A home that cannot be read: every section says so (§4.25 Empty states) ──

const DOWN = { status: 503, body: { error: "the arbiter is not reachable", tenant: "live", unreachable: true } };
const LEADS = {
  waiting: "Could not check for waiting questions.",
  agents: "Could not check which agents are running.",
  answered: "Could not check your earlier answers.",
};
/** The words after each lead, by the cause the failed read tells (§4.25
 *  *Empty states*, *A could-not line names the cause the page knows*): on
 *  Home and under the line above (`plain`), and on Approvals › Waiting for
 *  your answer (`linked`), the one line there whose words for a stopped
 *  service link to Settings. Until 2026-10-10 every cause read "The
 *  protection service may be unreachable.", also under a hero that said
 *  the dashboard itself could not be reached. */
const CAUSE = {
  down: { plain: "The protection service is not running.", linked: "The protection service is not running. Start it under Settings, or try again in a moment." },
  error500: { plain: "The dashboard server answered with an error (500). Refresh in a moment.", linked: "The dashboard server answered with an error (500). Refresh in a moment." },
  gone: { plain: "The dashboard could not reach its own server. Refresh in a moment.", linked: "The dashboard could not reach its own server. Refresh in a moment." },
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const emptyText = (doc: any, id: string) => [...doc.getElementById(id).children].map((c: any) => [c.className, c.textContent]);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const linksIn = (doc: any, id: string) => [...doc.getElementById(id).querySelectorAll("a")].map((a: any) => [a.textContent, a.getAttribute("href"), a.dataset.pageLink]);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function assertNotChecked(doc: any, why: string, cause: { plain: string; linked: string }) {
  assert.deepEqual(emptyText(doc, "home-waiting"), [["empty", `${LEADS.waiting} ${cause.plain}`]], `Home › Approvals waiting (${why})`);
  assert.deepEqual(emptyText(doc, "home-agents"), [["empty", `${LEADS.agents} ${cause.plain}`]], `Home › Running now (${why})`);
  assert.equal(doc.getElementById("home-history").textContent, "", `no session count (${why})`);
  assert.equal(doc.getElementById("home-earlier-block").hidden, true, `no Earlier (${why})`);
  assert.deepEqual(emptyText(doc, "approvals-waiting"), [["empty", `${LEADS.waiting} ${cause.linked}`]], `Approvals › Waiting for your answer (${why})`);
  assert.deepEqual(emptyText(doc, "approvals-answered"), [["empty", `${LEADS.answered} ${cause.plain}`]], `Approvals › Answered earlier (${why})`);
  for (const id of ["home-waiting", "home-agents", "approvals-waiting", "approvals-answered"]) {
    assert.equal(doc.getElementById(id).querySelector("button, .ask, .row"), null, `no question, answer or agent row in #${id} (${why})`);
  }
  // One link to the Start of the service per page: the hero has it on Home,
  // Waiting for your answer on Approvals; nothing else to open.
  const start = cause === CAUSE.down ? [["Start it under Settings", "/mandu/settings", "settings"]] : [];
  assert.deepEqual(linksIn(doc, "approvals-waiting"), start, `the link on Approvals (${why})`);
  for (const id of ["home-waiting", "home-agents", "approvals-answered"]) assert.deepEqual(linksIn(doc, id), [], `no link in #${id} (${why})`);
}

test("a home that cannot be read says each section could not be checked, with the cause the read tells, never a bare heading (§4.25 Empty states)", async () => {
  // Until 2026-10-09 a failed /api/home drew the hero only: Home's Approvals
  // waiting and Running now, and both Approvals sections, stood as bare
  // headings.
  const down = load({ routes: { "GET home": DOWN } });
  assert.equal(down.err, null);
  await tick();
  assert.equal(down.doc.getElementById("hero-headline").textContent, "Not connected.");
  assertNotChecked(down.doc, "503 unreachable", CAUSE.down);
  assert.equal(down.window.document.title, "Mandu");
  // The page's own server failing says it answered, with its status.
  const failed = load({ routes: { "GET home": { status: 500, body: null } } });
  await tick();
  assertNotChecked(failed.doc, "500", CAUSE.error500);
  // No answer at all: the dashboard is gone, never "the protection service".
  const gone = load({ routes: { "GET home": () => { throw new TypeError("Failed to fetch"); } } });
  await tick();
  assert.equal(gone.doc.getElementById("hero-sentence").textContent, CAUSE.gone.plain, "the hero says the same");
  assertNotChecked(gone.doc, "no answer", CAUSE.gone);
  assert.doesNotMatch(gone.doc.body.textContent, /Failed to fetch|may be unreachable/);
});

test("a page left open when the protection service stops keeps none of the last poll's questions, agents or count; the next good poll draws them again", async () => {
  let up = true;
  let gone = false;
  const { doc, window, err } = load({ routes: { "GET home": () => {
    if (gone) throw new TypeError("Failed to fetch");
    return up ? home() : DOWN;
  } } });
  assert.equal(err, null);
  await tick();
  const poll = async () => { doc.dispatchEvent(new window.Event("visibilitychange")); await tick(); };
  assert.equal(doc.querySelectorAll("#home-waiting .ask").length, 1);
  assert.equal(doc.querySelectorAll("#approvals-waiting .ask .ask-actions button").length, 3);
  assert.match(doc.getElementById("home-agents").textContent, /Claude Code/);
  assert.equal(window.document.title, "(1) Mandu");
  // The tab's icon draws the count as text over the shield.
  assert.match(doc.getElementById("favicon").href, /%3Ctext[^]*%3E1%3C\/text%3E/);

  up = false;
  await poll();
  // Until 2026-10-09 the card stayed with live Allow once / Always allow /
  // Block buttons, the agent stayed "Waiting for your OK" and the tab said
  // (1), under "Not connected." and a nav badge of 0.
  assert.equal(doc.getElementById("hero-headline").textContent, "Not connected.");
  assertNotChecked(doc, "after the service stopped", CAUSE.down);
  assert.equal(doc.getElementById("nav-approvals-count").hidden, true);
  assert.equal(window.document.title, "Mandu", "the tab no longer counts a question it cannot check");
  assert.doesNotMatch(doc.getElementById("favicon").href, /%3Ctext/, "nor does its icon");
  // The same cause again leaves each line as it is; another cause draws it again.
  const line = doc.querySelector("#approvals-waiting .empty");
  await poll();
  assert.equal(doc.querySelector("#approvals-waiting .empty"), line, "an unchanged cause is not drawn again");
  gone = true;
  await poll();
  assertNotChecked(doc, "after the dashboard went too", CAUSE.gone);
  gone = false;

  up = true;
  await poll();
  assert.equal(doc.querySelectorAll("#home-waiting .ask").length, 1, "back: the question again");
  assert.equal(doc.querySelectorAll("#approvals-waiting .ask .ask-actions button").length, 3);
  assert.match(doc.getElementById("home-agents").textContent, /Claude Code/);
  assert.equal(doc.getElementById("home-history").textContent, "History: 9 sessions");
  assert.equal(doc.getElementById("home-earlier-block").hidden, false);
  assert.equal(window.document.title, "(1) Mandu");
});

// ── The hero links where it points (dashboard.md §4.25) ──────────────────────

const OFF_PARTS = [
  { kind: "text", text: "The AI can read untrusted content as-is, and your secrets are not guarded. " },
  { kind: "link", text: "Turn it back on in Settings", to: "settings" },
  { kind: "text", text: "." },
];
const joined = (parts: { text: string }[]) => parts.map((p) => p.text).join("");
const QUIET_WINDOW = { hours: 24, sessions: 1, counted: 1, masked: 0, secretsMasked: 0, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0 };

test("Protection is off: \"Turn it back on in Settings\" is a link that opens Settings, where the switch is, and a repaint draws it once", async () => {
  const vm = home({
    verdict: "off", headline: "Protection is off.", sentence: joined(OFF_PARTS), sentenceParts: OFF_PARTS,
    protection: { level: "off", configured: "off", connected: true }, window: QUIET_WINDOW, waiting: [],
  });
  const { doc, err, window } = load({ homeVm: vm });
  assert.equal(err, null);
  await tick();
  const sentence = doc.getElementById("hero-sentence");
  assert.equal(sentence.textContent, "The AI can read untrusted content as-is, and your secrets are not guarded. Turn it back on in Settings.");
  doc.dispatchEvent(new window.Event("visibilitychange")); // the poll's repaint
  await tick();
  assert.equal(sentence.textContent, "The AI can read untrusted content as-is, and your secrets are not guarded. Turn it back on in Settings.", "repainted, not appended");
  const links = [...sentence.querySelectorAll("a")] as any[];
  assert.equal(links.length, 1);
  assert.equal(links[0].textContent, "Turn it back on in Settings");
  assert.equal(links[0].getAttribute("href"), "/mandu/settings");
  assert.equal(links[0].dataset.pageLink, "settings");
  links[0].click();
  await tick();
  assert.equal(window.location.pathname, "/mandu/settings");
  assert.equal(doc.getElementById("page-settings").hidden, false);
  assert.equal(doc.getElementById("page-home").hidden, true);
  assert.equal(doc.getElementById("settings-protection-title").textContent, "Protection", "the switch's card");
  assert.ok(doc.getElementById("switch-protection"));
});

test("Protection failed: \"Open the detailed trace\" opens the failed session's trace in a new tab, or the trace's list when several failed", async () => {
  const parts = (session: string | null) => [
    { kind: "text", text: "One item reached the AI unmasked in the last 24 hours. " },
    { kind: "link", text: "Open the detailed trace", to: "trace", session },
    { kind: "text", text: " to see which." },
  ];
  const cases: [string | null, string][] = [
    ["s1", "/mandu/dev/sessions/s1"],
    [null, "/mandu/dev/sessions"],
    ["1791200000-417/../x y", "/mandu/dev/sessions/1791200000-417%2F..%2Fx%20y"],
  ];
  for (const [session, href] of cases) {
    const p = parts(session);
    const { doc } = load({ homeVm: home({ verdict: "failed", headline: "Protection failed.", sentence: joined(p), sentenceParts: p }) });
    await tick();
    const sentence = doc.getElementById("hero-sentence");
    assert.equal(sentence.textContent, "One item reached the AI unmasked in the last 24 hours. Open the detailed trace to see which.");
    const links = [...sentence.querySelectorAll("a")] as any[];
    assert.equal(links.length, 1);
    assert.equal(links[0].textContent, "Open the detailed trace");
    assert.equal(links[0].getAttribute("href"), href, String(session));
    assert.equal(links[0].getAttribute("target"), "_blank");
    assert.equal(links[0].getAttribute("rel"), "noopener");
    assert.equal(links[0].dataset.pageLink, undefined, "the developer view, not a page of this one");
  }
});

test("the hero builds every link itself: a place it does not know, or an address in the payload, is never a link; a payload without parts reads its sentence", async () => {
  const parts = [
    { kind: "text", text: "Go " },
    { kind: "link", text: "<img src=x onerror=alert(1)>", to: "https://evil.example/" },
    { kind: "text", text: " or " },
    { kind: "link", text: "here", to: "settings", href: "javascript:alert(1)" },
  ];
  const { doc } = load({ homeVm: home({ verdict: "off", headline: "Protection is off.", sentence: joined(parts), sentenceParts: parts, waiting: [] }) });
  await tick();
  const sentence = doc.getElementById("hero-sentence");
  assert.equal(sentence.textContent, "Go <img src=x onerror=alert(1)> or here");
  assert.equal(sentence.querySelector("img"), null, "text, never markup");
  const links = [...sentence.querySelectorAll("a")] as any[];
  assert.deepEqual(links.map((a) => [a.textContent, a.getAttribute("href")]), [["here", "/mandu/settings"]], "the page's own address, never the payload's");
  // An older server: the plain sentence, no link.
  const old = load({ homeVm: home({ sentence: "Protection is holding." }) });
  await tick();
  assert.equal(old.doc.getElementById("hero-sentence").textContent, "Protection is holding.");
  assert.equal(old.doc.querySelector("#hero-sentence a"), null);
});

// ── The hero counts the rule changes waiting, as the badge does (§4.25, the
// verdict ladder; 2026-10-18). Until then one rule change alone left the
// hero green, "Your secrets are guarded.", over "Approvals waiting (1)". ────

const RULE_CHANGE = {
  id: "pp-000001", status: "pending", requester: "Your agent", createdAt: Date.now() - 60_000,
  rows: [[{ kind: "text", text: "Trust content from " }, { kind: "code", text: "https://pypi.org/" }]],
  wouldLet: [], capped: false, overBroad: false, reason: "widen it",
};

test("one rule change waiting and no question: the hero reads amber, and the number it says is the badge's", async () => {
  const vm = home({
    verdict: "waiting", headline: "A rule change is waiting for you.",
    sentence: "Your rules stay as they are until you answer. Untrusted content is not masked in this mode.",
    sentenceParts: [{ kind: "text", text: "Your rules stay as they are until you answer. Untrusted content is not masked in this mode." }],
    protection: { level: "secrets", configured: "secrets", connected: true },
    window: { hours: 24, sessions: 2, masked: 0, secretsMasked: 1, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0 },
    waiting: [], ruleChangesWaiting: 1,
  });
  const { doc, err } = load({ homeVm: vm, routes: { "GET policy/proposals?status=pending": { proposals: [RULE_CHANGE] } } });
  assert.equal(err, null);
  await tick();
  const hero = doc.getElementById("hero");
  assert.equal(hero.dataset.verdict, "waiting", "amber, never the green 'guarded'");
  assert.equal(doc.getElementById("hero-headline").textContent, "A rule change is waiting for you.");
  assert.equal(doc.getElementById("hero-sentence").textContent, "Your rules stay as they are until you answer. Untrusted content is not masked in this mode.");
  const badge = doc.getElementById("nav-approvals-count");
  assert.equal(badge.textContent, "1");
  assert.equal(badge.hidden, false);
  assert.equal(doc.getElementById("home-waiting-title").textContent, "Approvals waiting (1)");
  // "A rule change" is one: the hero's count equals the badge's.
  assert.equal(1 + vm.waiting.length, Number(badge.textContent));
  // Said once: the waiting headline counts it, so the facts line does not.
  assert.doesNotMatch(doc.getElementById("hero-facts").textContent, /waiting/);
});

test("under Protection failed, the facts line's waiting count adds the rule changes to the questions, as the badge does", async () => {
  const vm = home({
    verdict: "failed", headline: "Protection failed.",
    sentence: "1 item reached the AI unmasked in the last 24 hours.", sentenceParts: [{ kind: "text", text: "1 item reached the AI unmasked in the last 24 hours." }],
    ruleChangesWaiting: 1,
  });
  const { doc } = load({ homeVm: vm, routes: { "GET policy/proposals?status=pending": { proposals: [RULE_CHANGE] } } });
  await tick();
  assert.equal(doc.getElementById("hero").dataset.verdict, "failed");
  assert.match(doc.getElementById("hero-facts").textContent, /^2 waiting for you/, "one question and one rule change");
  assert.equal(doc.getElementById("nav-approvals-count").textContent, "2");
});

// ── A click on a session's row opens it (dashboard.md §4.25) ────────────────

/** A plain or modified pointer click on `target`, bubbling as a browser's does. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const clickOn = (target: any, init: Record<string, unknown> = {}, type = "click") =>
  target.dispatchEvent(new target.ownerDocument.defaultView.MouseEvent(type, { bubbles: true, cancelable: true, ...init }));

test("a click anywhere on a Home row opens its session, as its Details does: a running row's prompt, an Earlier row's moment", async () => {
  const running = load();
  await tick();
  const row = running.doc.querySelector('#home-agents .row.agent[data-session="s1"]');
  clickOn(row.querySelector(".agent-what .sub"));
  await tick();
  assert.equal(running.window.location.pathname, "/mandu/agents/s1");
  assert.equal(running.doc.getElementById("page-agent").hidden, false);
  assert.equal(running.doc.getElementById("page-home").hidden, true);
  assert.ok(running.calls.some((c) => c.url === "/mandu/api/home/agent?session=s1"));
  const earlier = load();
  await tick();
  clickOn(earlier.doc.querySelector('#home-earlier .row.agent[data-session="s2"] .agent-when'));
  await tick();
  assert.equal(earlier.window.location.pathname, "/mandu/agents/s2");
  assert.equal(earlier.doc.getElementById("page-agent").hidden, false);
});

test("a row click leaves its controls theirs, a text selection and a modified or middle click: Preview opens its note, Ctrl opens a new tab", async () => {
  const vm = home();
  (vm.agents as any[])[0].preview = PREVIEW("Goose");
  const opened: unknown[][] = [];
  const { doc, window } = load({ homeVm: vm, before: (w) => { w.open = (...a: unknown[]) => { opened.push(a); return null; }; } });
  await tick();
  const row = doc.querySelector('#home-agents .row.agent[data-session="s1"]');
  const stays = (why: string) => {
    assert.equal(window.location.pathname, "/mandu/", why);
    assert.equal(doc.getElementById("page-home").hidden, false, why);
  };
  // The Preview tag opens its note, and a click inside the note and on its link stay there.
  const tag = row.querySelector(".preview-btn");
  tag.click();
  await tick();
  const pop = doc.getElementById(tag.getAttribute("aria-controls"));
  assert.equal(pop.hidden, false, "the tag opens its note");
  stays("a click on Preview is the tag's");
  clickOn(pop);
  clickOn(pop.querySelector("a"));
  await tick();
  stays("a click in the open note, or on its link, is the note's");
  doc.body.click();
  // A click that ends a selection of the prompt opens nothing.
  const prompt = row.querySelector(".agent-what .sub");
  const range = doc.createRange();
  range.selectNodeContents(prompt);
  window.getSelection().addRange(range);
  clickOn(prompt);
  await tick();
  stays("a drag across the prompt selects it");
  window.getSelection().removeAllRanges();
  // Ctrl, ⌘ and Shift, and a middle click: the link's address in a new tab, this page unchanged.
  clickOn(prompt, { ctrlKey: true });
  clickOn(prompt, { metaKey: true });
  clickOn(prompt, { shiftKey: true });
  clickOn(prompt, { button: 1 }, "auxclick");
  clickOn(prompt, { button: 2 }, "auxclick");
  await tick();
  stays("a modified click leaves this tab");
  assert.deepEqual(opened, Array.from({ length: 4 }, () => ["http://127.0.0.1:4500/mandu/agents/s1", "_blank", "noopener"]), "four new tabs at the link's address; a right click opens none");
  // The row stays no control: Details is its one tab stop, with its name.
  for (const r of doc.querySelectorAll(".row.agent") as any) {
    assert.equal(r.getAttribute("tabindex"), null);
    assert.equal(r.getAttribute("role"), null);
    assert.equal(r.getAttribute("aria-label"), null);
  }
  assert.equal(row.querySelector('a[data-page-link="agent"]').getAttribute("aria-label"), "Details: Claude Code, Fix the test in ~/ws");
  // And a plain click still opens it.
  clickOn(prompt);
  await tick();
  assert.equal(window.location.pathname, "/mandu/agents/s1");
});

test("app.css: a session row shows it opens on a click: the pointer, and the page's row hover", () => {
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  const plain = rules.filter((r) => r.media === null);
  assert.ok(plain.some((r) => r.selectors.includes(".row.agent") && declValue(r.block, "cursor") === "pointer"), "the pointer");
  const hover = plain.find((r) => r.selectors.includes(".row.agent:hover"));
  assert.ok(hover, "a hover rule");
  assert.equal(declValue(hover.block, "background"), "var(--bg)", "the page's row hover, as a file row's");
  assert.ok(plain.some((r) => r.selectors.includes(".row.file-rule:hover") && declValue(r.block, "background") === "var(--bg)"), "the same as the Rules rows'");
});
