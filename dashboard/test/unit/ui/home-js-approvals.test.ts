/**
 * home-js-approvals.test — the Approvals wording of the product page
 * (dashboard.md §4.25u): the page is "Approvals" wherever a person reads its
 * name (nav, heading, tab title, the Home summary and its count), every
 * moment reads absolute and relative in a <time> element, the "?" help next
 * to "masked" is a real toggle button, and an Approvals card's three cells
 * have the AI as their subject. Its Answered earlier and Rule changes rows
 * read whole, with when under them (§4.25, Approvals, *Read in full*), and
 * an answer's when line links to where it was asked (§4.25h). The
 * page keys and links (`/approvals`, `data-page="approvals"`, dashboard.md
 * §4.25v) are not this suite's business.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AGENT, ASK, CLOCK, home, load, tick, PUB } from "./home-js-fixtures.js";
import { declValue, flattenCss, mentions, stripComments } from "./css-flatten.js";

const APPROVALS_URL = "http://127.0.0.1:4500/mandu/approvals";
const DAY = 86_400_000;

test("the page is called Approvals: nav label, heading, tab title", async () => {
  const { doc, window } = load({ url: APPROVALS_URL });
  await tick();
  const nav = doc.querySelector('#nav [data-page-link="approvals"]');
  assert.match(nav.textContent, /^Approvals\b/);
  assert.equal(doc.querySelector("#page-approvals h1").textContent, "Approvals");
  assert.match(window.document.title, /^\(1\) Mandu · Approvals$/);
  // The block on the page itself is not a second "Approvals".
  const heads = [...doc.querySelectorAll("#page-approvals h2")].map((h: any) => h.textContent);
  // Its heading now carries the count of its questions (§4.25 *Waiting for
  // your answer counts its questions*).
  assert.ok(heads.some((h) => h.startsWith("Waiting for your answer")), heads.join(" | "));
});

test("Home: 'Approvals waiting (N)' counts what the nav badge counts, with an explicit link", async () => {
  const proposal = { id: "prop-1", headline: "Your agent wants to change a rule", rows: [], createdAt: Date.now() - 60_000 };
  const { doc } = load({ routes: { "GET policy/proposals?status=pending": { proposals: [proposal] } } });
  await tick();
  const badge = doc.getElementById("nav-approvals-count").textContent;
  assert.equal(badge, "2", "one ask + one rule change");
  assert.equal(doc.getElementById("home-waiting-title").textContent, `Approvals waiting (${badge})`);
  const link = doc.querySelector("#home-waiting-block .block-head a");
  assert.equal(link.textContent, "Open Approvals →");
  assert.match(doc.getElementById("home-waiting").textContent, /1 rule change your agent asked for is in Approvals/);
});

test("Home: nothing waiting → no count in the heading; the cap line says 'in Approvals'", async () => {
  const none = load({ homeVm: home({ waiting: [] }) });
  await tick();
  assert.equal(none.doc.getElementById("home-waiting-title").textContent, "Approvals waiting");
  const many = Array.from({ length: 5 }, (_, i) => ({ ...ASK, id: `egr-${i}` }));
  const capped = load({ homeVm: home({ waiting: many }) });
  await tick();
  assert.equal(capped.doc.getElementById("home-waiting-title").textContent, "Approvals waiting (5)");
  assert.equal(capped.doc.querySelector("#home-waiting .more").textContent, "2 more questions in Approvals");
});

test("a moment reads absolute and relative, in a <time> with its ISO datetime; the year only when it is not this year", async () => {
  const thisYear = Date.now() - 2 * 60_000;
  const lastYear = new Date(new Date().getFullYear() - 1, 5, 15, 9, 5).getTime();
  const { doc } = load({
    url: APPROVALS_URL,
    homeVm: home({
      waiting: [{ ...ASK, askedAt: thisYear, count: 3 }],
      answered: [{ id: "old", sentence: [{ kind: "text", text: "An old send" }], outcome: "blocked", decidedAt: lastYear, actions: [] }],
    }),
  });
  await tick();
  const sub = doc.querySelector("#approvals-waiting .ask-sub");
  const time = sub.querySelector("time");
  assert.ok(time, "a <time> element");
  assert.equal(time.getAttribute("datetime"), new Date(thisYear).toISOString());
  assert.match(time.textContent, new RegExp(`^${CLOCK} · 2 minutes ago$`));
  assert.doesNotMatch(time.textContent, /, \d{4},/, "no year for this year");
  assert.match(sub.textContent, new RegExp(`^${CLOCK} · 2 minutes ago, 3 times$`), "no 'Asked' prefix; the count stays, and no period with nothing after it");
  const old = doc.querySelector('#approvals-answered .row.answered[data-id="old"] time');
  assert.equal(old.textContent.split(" · ")[0], `Jun 15, ${new Date(lastYear).getFullYear()}, 09:05`);
  // Jun 15 of last year is 6 to 18 months back, by today's date: whole
  // months, or past a year (§4.25u *Every moment reads absolute and relative*).
  assert.match(old.textContent, / · (?:\d+ months|over a year) ago$/);
  // Text only: the moment is built from text nodes, never markup. Its only
  // elements are the two parts app.css keeps each on one line (§4.25u *A
  // moment keeps its number with its word*), each holding one text node.
  assert.deepEqual([...time.querySelectorAll("*")].map((e: any) => e.className), ["when-at", "when-ago"]);
  for (const part of [...time.children] as any[]) assert.deepEqual([...part.childNodes].map((x: any) => x.nodeType), [3]);
});

test("an Approvals card: Why it stopped / What the AI has now / If you click Allow once or Always allow", async () => {
  const ask = { ...ASK, why: "Mandu masked it.", aiNow: "The AI has only the masked version.", ifAllowed: "The AI's next request goes to x with the real text filled in. Mandu refused this one, so nothing was sent. After you answer, tell the agent to try again." };
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [ask] }) });
  await tick();
  const cells = [...doc.querySelectorAll("#approvals-waiting .ask-detail > div")];
  const label = (c: any) => c.querySelector(".k").childNodes[0].textContent;
  assert.deepEqual(cells.map(label), ["Why it stopped", "What the AI has now", "If you click Allow once or Always allow"]);
  assert.deepEqual(cells.map((c: any) => c.querySelector(".v").textContent), [ask.why, ask.aiNow, ask.ifAllowed]);
  assert.doesNotMatch(doc.getElementById("approvals-waiting").textContent, /placeholder|What the AI saw|If you allow\b/);
  // The buttons the third label names are the card's buttons.
  const verbs = [...doc.querySelectorAll("#approvals-waiting .ask-actions button")].map((b: any) => b.textContent);
  assert.ok(verbs.includes("Allow once") && verbs.includes("Always allow"), verbs.join(", "));
});

test("the masked help: a button with aria-expanded/aria-controls that opens and closes its note (click, Escape, a click elsewhere)", async () => {
  const { doc, window } = load({ url: APPROVALS_URL, homeVm: home({ protection: { level: "secrets", configured: "secrets", connected: true } }) });
  await tick();
  const btn = doc.querySelector("#approvals-waiting .ask-detail .help-btn");
  assert.ok(btn, "the help sits next to 'What the AI has now'");
  assert.equal(btn.tagName, "BUTTON");
  assert.equal(btn.getAttribute("type"), "button");
  assert.equal(btn.getAttribute("aria-label"), "What masked means");
  const pop = doc.getElementById(btn.getAttribute("aria-controls"));
  assert.ok(pop, "aria-controls names the note");
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  assert.equal(pop.hidden, true);
  btn.click();
  assert.equal(btn.getAttribute("aria-expanded"), "true");
  assert.equal(pop.hidden, false);
  assert.match(pop.textContent, /^Masked: before the AI saw it, Mandu replaced the real value with a short code that stands for it\./);
  // Secrets mode: untrusted text is NOT masked, and the note says so.
  assert.match(pop.textContent, /only secrets are masked; untrusted content reaches the AI as-is/);
  btn.click();
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  assert.equal(pop.hidden, true);
  // Escape closes it from the keyboard.
  btn.click();
  btn.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  // A click elsewhere closes it.
  btn.click();
  doc.body.click();
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  assert.equal(pop.hidden, true);
});

test("the masked help follows the level: where untrusted text is masked too, it says so; the hero's first masked count has one", async () => {
  const { doc } = load({ homeVm: home({ protection: { level: "full", configured: "full", connected: true } }) });
  await tick();
  const btn = doc.querySelector("#hero-facts .help-btn");
  assert.ok(btn, "the hero's masked count carries the help");
  btn.click();
  const pop = doc.getElementById(btn.getAttribute("aria-controls"));
  assert.match(pop.textContent, /In this mode, untrusted content, such as a web page, is masked too/);
  assert.doesNotMatch(pop.textContent, /only secrets are masked/);
});

test("each help has its own note (ids do not collide)", async () => {
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [ASK, { ...ASK, id: "egr-2" }] }) });
  await tick();
  const ids = [...doc.querySelectorAll(".help-btn")].map((b: any) => b.getAttribute("aria-controls"));
  assert.ok(ids.length >= 2);
  assert.equal(new Set(ids).size, ids.length);
});

// ── Read in full (dashboard.md §4.25, Approvals) ─────────────────────────────

/** A sentence as the server words it (ask-words.ts `describeAsk`). */
const SEND_WORDS = [
  { kind: "text", text: "The agent wants to send your secret " }, { kind: "code", text: "GITHUB_TOKEN" },
  { kind: "text", text: " to " }, { kind: "code", text: "gist.github.com" },
];

test("Answered earlier: a row says what was asked whole, when on the line under it, then the answer and the button that reverses it", async () => {
  const decidedAt = Date.now() - 60_000;
  const answered = [{ id: "a1", sentence: SEND_WORDS, outcome: "allowed-once", decidedAt, actions: [{ approve: false, scope: "always" }] }];
  const { doc } = load({
    url: APPROVALS_URL,
    homeVm: home({ answered }),
    routes: { "POST egress/approvals/a1/deny": { status: 409, body: { error: "approval a1 is already resolved" } } },
  });
  await tick();
  const row = doc.querySelector('#approvals-answered .row.answered[data-id="a1"]');
  assert.ok(row, "the answered row");
  // Until 2026-10-08 the question kept one ellipsized line: "…to gist.github.c…"
  // at 1280px, "…your secret GITHUB_…" on a phone, above Block instead.
  assert.equal(row.querySelector(".ellipsis"), null, "nothing in the row is cut to one line");
  const cells = [...row.children] as any[];
  assert.deepEqual(cells.map((c) => c.className), ["answered-what", "outcome dim", "btn small right"], "words, answer, button: three cells");
  const [what, outcome, button] = cells;
  assert.equal(what.querySelector(".answered-sentence").textContent, "The agent wants to send your secret GITHUB_TOKEN to gist.github.com");
  assert.deepEqual([...what.querySelectorAll(".answered-sentence code")].map((c: any) => c.textContent), ["GITHUB_TOKEN", "gist.github.com"]);
  // When: the row's one moment, under the words, absolute and relative.
  const times = [...row.querySelectorAll("time")] as any[];
  assert.equal(times.length, 1);
  assert.equal(times[0].parentElement, what.querySelector(".answered-when"), "the time is on the line under the words");
  assert.equal(what.lastElementChild, what.querySelector(".answered-when"));
  assert.equal(times[0].getAttribute("datetime"), new Date(decidedAt).toISOString());
  assert.match(times[0].textContent, new RegExp(`^${CLOCK} · 1 minute ago$`));
  assert.equal(outcome.textContent, "Allowed once, unused");
  assert.equal(button.textContent, "Block instead");
  // A refusal spans the row under it (app.css `.row.answered > .ask-error`).
  button.click();
  await tick();
  const error = row.querySelector(".ask-error");
  assert.ok(error, "the server's words are shown");
  assert.equal(error.parentElement, row);
  assert.match(error.textContent, /already resolved/);
});

test("Answered earlier: an answer with no recorded time has no empty time line", async () => {
  const answered = [
    { id: "a2", sentence: SEND_WORDS, outcome: "allowed-once", decidedAt: null, actions: [] },
    // A standing answer's line is its Kept in Rules link alone (§4.25 *A
    // remembered answer opens where Rules keeps it*).
    { id: "a3", sentence: SEND_WORDS, outcome: "blocked", decidedAt: null, actions: [] },
  ];
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ answered }) });
  await tick();
  const row = doc.querySelector('#approvals-answered .row.answered[data-id="a2"]');
  assert.equal(row.querySelector(".answered-when"), null);
  assert.equal(row.querySelector(".answered-what").textContent, "The agent wants to send your secret GITHUB_TOKEN to gist.github.com");
  assert.equal(row.children.length, 3, "words, answer, and the empty cell where a reversal would be");
  const kept = doc.querySelector('#approvals-answered .row.answered[data-id="a3"] .answered-when');
  assert.equal(kept.textContent, "Kept in Rules");
  assert.equal(kept.querySelector("time"), null);
});

test("Answered earlier: the when line links to where it was asked, the latest session, as its waiting card did (§4.25h)", async () => {
  // Until 2026-10-08 an answered row led nowhere: the waiting card's "See
  // what the agent was doing" went when it was answered, and an Allowed
  // once answer, which Rules does not list, had no way to its moment.
  const decidedAt = Date.now() - 60_000;
  const row = (id: string, over: Record<string, unknown>) => ({ id, sentence: SEND_WORDS, outcome: "allowed-once", decidedAt, actions: [], ...over });
  const answered = [
    row("egr-7", { sessions: ["s3", "s9"] }),
    row("egr-8", { sessions: ["s1"], outcome: "blocked" }),
    row("egr-9", { sessions: ["s1"], decidedAt: null }),
    row("egr-10", { sessions: [] }),
  ];
  const { doc, calls, window } = load({
    url: APPROVALS_URL,
    homeVm: home({ answered }),
    routes: { "GET home/agent?session=s9&ask=egr-7": { ...AGENT, id: "s9" } },
  });
  await tick();
  const line = (id: string) => doc.querySelector(`#approvals-answered .row.answered[data-id="${id}"] .answered-what`).lastElementChild;

  // Several sessions: the latest, said as the Rules page says it.
  const shared = line("egr-7");
  assert.equal(shared.className, "dim answered-when", "the link is on the line under the words, after when");
  assert.match(shared.textContent, new RegExp(`^${CLOCK} · 1 minute ago\\. See what the agent was doing \\(asked in 2 sessions, this shows the latest\\)$`));
  assert.equal(shared.querySelectorAll("time").length, 1);
  const link = shared.querySelector("a");
  assert.equal(link.className, "ask-link");
  assert.equal(link.getAttribute("href"), "/mandu/agents/s9?ask=egr-7", "the agent page at the step where it was asked");
  assert.equal(link.dataset.pageLink, "agent");
  assert.equal(link.dataset.session, "s9");
  assert.equal(link.dataset.ask, "egr-7");
  assert.doesNotMatch(link.getAttribute("href"), /dev\//, "the product's agent page, not the inspector");

  // One session: no count.
  // A standing answer (Blocked) adds Kept in Rules after it (§4.25).
  assert.match(line("egr-8").textContent, new RegExp(`^${CLOCK} · 1 minute ago\\. See what the agent was doing\\. Kept in Rules$`));
  assert.equal(line("egr-8").querySelector("a").getAttribute("href"), "/mandu/agents/s1?ask=egr-8");
  // No recorded time: the line is the link alone.
  assert.equal(line("egr-9").className, "dim answered-when");
  assert.equal(line("egr-9").textContent, "See what the agent was doing");
  assert.equal(line("egr-9").querySelector("time"), null);
  // No session recorded: no link, nothing guessed.
  assert.equal(line("egr-10").querySelector("a"), null);
  assert.match(line("egr-10").textContent, new RegExp(`^${CLOCK} · 1 minute ago$`));

  // The link opens the product's agent page at that ask.
  link.click();
  await tick();
  assert.equal(doc.getElementById("page-agent").hidden, false);
  assert.equal(window.location.pathname + window.location.search, "/mandu/agents/s9?ask=egr-7");
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/agent?session=s9&ask=egr-7"));
});

test("app.css: an Approvals row's words take its widest column and wrap, a long path breaking in its chip; never cut (§4.25)", () => {
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  const row = rules.filter((r) => r.selectors.includes(".row.answered"));
  const wide = row.find((r) => r.media === null)!;
  const cols = gridColumns(declValue(wide.block, "grid-template-columns")!);
  assert.equal(cols.length, 3, `words and when, the answer, the button (got ${cols.join(" ")})`);
  assert.equal(cols[0], "minmax(0, 1fr)", "the words' column takes the room left");
  assert.match(cols[1]!, /^\d+px$/, "the answer's is fixed, so the rows line up");
  // The button's: a floor the rows line up at, and room for a wider label
  // (*One line in its button*, the test below).
  assert.match(cols[2]!, /^minmax\(.+, max-content\)$/, "the button's has a floor and grows to its button");
  assert.ok(row.some((r) => r.media?.includes("max-width: 760px") && declValue(r.block, "grid-template-columns") === "1fr"), "a narrow screen stacks the row");
  const what = rules.find((r) => r.selectors.includes(".answered-what") && r.media === null)!;
  assert.ok(what, "the words' cell has its rule");
  assert.equal(declValue(what.block, "flex-direction"), "column", "when goes under the words");
  assert.equal(declValue(what.block, "min-width"), "0", "so the cell can shrink inside the grid and wrap");
  const code = rules.find((r) => r.selectors.includes(".answered-what code"));
  assert.equal(code && declValue(code.block, "overflow-wrap"), "anywhere", "a long path breaks inside its chip");
  const error = rules.find((r) => r.selectors.includes(".row.answered > .ask-error"));
  assert.equal(error && declValue(error.block, "grid-column"), "1 / -1", "a refusal spans the row");
  for (const r of rules.filter((x) => x.selectors.some((s) => mentions(s, ".answered-what") || mentions(s, ".answered-sentence") || mentions(s, ".answered-when")))) {
    const where = `"${r.selectors.join(", ")}"${r.media ? ` in ${r.media}` : ""}`;
    assert.notEqual(declValue(r.block, "white-space"), "nowrap", `${where} keeps the words on one line`);
    assert.notEqual(declValue(r.block, "text-overflow"), "ellipsis", `${where} cuts the words`);
    assert.ok(!/^(hidden|clip)/.test(declValue(r.block, "overflow") ?? ""), `${where} clips the words`);
  }
});

/** A `grid-template-columns` value's tracks, a function's commas and
 *  nested parentheses kept inside its track. */
function gridColumns(value: string): string[] {
  const out: string[] = [];
  let depth = 0, cur = "";
  for (const ch of value.trim()) {
    if (ch === "(") depth += 1;
    if (ch === ")") depth -= 1;
    if (/\s/.test(ch) && depth === 0) { if (cur) out.push(cur); cur = ""; } else cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

test("app.css: Answered earlier's reversal is one line inside its button, its column no fixed 110 px but at least the longest label; Rule changes keeps 110 px for Undo (§4.25 *One line in its button*)", () => {
  const css = stripComments(readFileSync(join(PUB, "app.css"), "utf8"));
  const rules = flattenCss(css);
  const wide = rules.find((r) => r.selectors.includes(".row.answered") && r.media === null)!;
  const third = gridColumns(declValue(wide.block, "grid-template-columns")!)[2]!;
  assert.notEqual(third, "110px", "a fixed 110 px wraps 'Always allow instead' to two lines (#258)");
  const m = /^minmax\(var\(--reversal-floor, (\d+)px\), max-content\)$/.exec(third);
  assert.ok(m, `the column is its floor, or its button where that is wider: ${third}`);
  assert.equal(Number(m![1]), 110, "a list that sets no floor (Rule changes, its Undo) keeps 110 px");
  const floor = rules.find((r) => r.selectors.includes("#approvals-answered") && r.media === null && declValue(r.block, "--reversal-floor") !== null);
  assert.ok(floor, "Answered earlier sets its own floor");
  // 178 px: "Allow this session instead" in the page's 13 px Plex Sans 500,
  // padding and border included (measured in headless Chromium; the stack
  // test answered-reversal-fits measures it each run).
  assert.ok(parseFloat(declValue(floor!.block, "--reversal-floor")!) >= 178, "the floor fits the longest label, so the rows line up");
  const nowrap = rules.find((r) => r.selectors.includes(".row.answered > .btn") && r.media === null);
  assert.equal(nowrap && declValue(nowrap.block, "white-space"), "nowrap", "a later, longer label widens the column, never wraps");
  // A phone stacks the row: the floor never reaches it.
  const phone = rules.find((r) => r.selectors.includes(".row.answered") && r.media?.includes("max-width: 760px"))!;
  assert.equal(declValue(phone.block, "grid-template-columns"), "1fr");
  assert.ok(!rules.some((r) => r.selectors.some((s) => /#approvals-answered\b.*\.row/.test(s)) && declValue(r.block, "grid-template-columns") !== null), "no rule outranks the phone's one column");
});

test("§4.34 After you answer: a held program's card shows no re-ask count, an ended agent's card says nothing waits on it now, and the third cell is named for the buttons offered", async () => {
  const askedAt = Date.now() - 2 * 60_000;
  const run = {
    ...ASK, id: "run-1", family: "other", askedAt, count: 240, held: false,
    actions: [{ approve: true, scope: "once", label: "Allow once" }, { approve: false, label: "Block" }],
  };
  const ended = { ...ASK, id: "ended-1", askedAt, count: 3, askerEnded: true };
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [run, ended] }) });
  await tick();
  const card = (id: string) => [...doc.querySelectorAll("#approvals-waiting .ask")].find((c: any) => c.getAttribute("data-id") === id) as any;
  const sub = (id: string) => card(id).querySelector(".ask-sub").textContent;
  assert.match(sub("run-1"), new RegExp(`^${CLOCK} · 2 minutes ago$`), "a held program's half-second re-asks are no count of tries");
  // Under From sessions that have ended, which says it once (§4.25 *A
  // question from a session that has ended*); alone, the card says it.
  // Short there (§4.25 *An ended question is short on Approvals*): its why
  // inline, as on Home, and What each answer does where Home's link is.
  assert.match(sub("ended-1"), new RegExp(`^The text was masked\\. ${CLOCK} · 2 minutes ago, 3 times\\. What each answer does$`), "under the heading: no sentence of its own");
  const alone = load({ url: APPROVALS_URL, homeVm: home({ waiting: [ended] }) });
  await tick();
  assert.match(alone.doc.querySelector('#approvals-waiting .ask[data-id="ended-1"] .ask-sub').textContent, new RegExp(`^${CLOCK} · 2 minutes ago, 3 times\\. The agent that asked has ended, so nothing is waiting on this now\\. Your answer counts the next time an agent asks\\.$`));
  const label = (id: string) => [...card(id).querySelectorAll(".ask-detail .k")].map((k: any) => k.textContent.trim())[2];
  assert.equal(label("run-1"), "If you click Allow once", "no Always allow offered, none named");
  card("ended-1").querySelector(".ask-more").click();
  assert.equal(label("ended-1"), "If you click Allow once or Always allow");
  assert.deepEqual([...card("run-1").querySelectorAll("button")].map((b: any) => b.textContent).filter((t: string) => /Allow|Block/.test(t)), ["Allow once", "Block"]);
});

test("§4.25u A moment line ends where it ends: a card's moment with nothing after it has no period; one a sentence or a link follows keeps it, as an Answered earlier row does", async () => {
  const askedAt = Date.now() - 2 * 60_000;
  const once = { ...ASK, id: "once-1", askedAt, count: 1 };
  const many = { ...ASK, id: "many-1", askedAt, count: 3 };
  const ended = { ...ASK, id: "ended-1", askedAt, count: 3, askerEnded: true };
  const unknown = { ...ASK, id: "unknown-1", askedAt: null, count: 1 };
  const agent = { id: "pp-1", status: "pending", requester: "Your agent", headline: "Your agent wants to change a rule", rows: [], createdAt: askedAt };
  const disk = { ...agent, id: "pp-2", requester: "policy.yaml", onDisk: true, headline: "policy.yaml was changed on disk and would loosen 1 rule. Nothing changes until you approve" };
  const untimed = { ...disk, id: "pp-3", createdAt: null };
  const routes = { "GET policy/proposals?status=pending": { proposals: [agent, disk, untimed] } };
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [once, many, ended, unknown] }), routes });
  await tick();
  const sub = (sel: string) => doc.querySelector(`${sel} .ask-sub`).textContent;
  const card = (id: string) => `#approvals-waiting .ask[data-id="${id}"]`;
  assert.match(sub(card("once-1")), new RegExp(`^${CLOCK} · 2 minutes ago$`), "the moment alone");
  assert.match(sub(card("many-1")), new RegExp(`^${CLOCK} · 2 minutes ago, 3 times$`), "the moment and its count");
  assert.match(sub(card("ended-1")), new RegExp(`^The text was masked\\. ${CLOCK} · 2 minutes ago, 3 times\\. What each answer does$`), "under From sessions that have ended, What each answer does follows: the period stays");
  assert.equal(sub(card("unknown-1")), "", "no moment recorded: no lone period");
  const prop = (id: string) => `#approvals-proposals .proposal[data-id="${id}"]`;
  assert.match(sub(prop("pp-1")), new RegExp(`^${CLOCK} · 2 minutes ago$`), "a rule change your agent asked for");
  assert.match(sub(prop("pp-2")), new RegExp(`^Seen ${CLOCK} · 2 minutes ago$`), "a change seen on disk");
  assert.equal(sub(prop("pp-3")), "", "no moment recorded: no bare Seen");
  // The same moments elsewhere on the page: Answered earlier puts the period
  // only before its link, as before.
  const answered = load({ url: APPROVALS_URL, homeVm: home({ waiting: [], answered: [
    { id: "a1", sentence: [{ kind: "text", text: "A send" }], outcome: "blocked", decidedAt: askedAt, sessions: [], actions: [] },
  ] }) });
  await tick();
  const row = answered.doc.querySelector('#approvals-answered .row.answered[data-id="a1"] .answered-when');
  assert.match(row.textContent, new RegExp(`^${CLOCK} · 2 minutes ago\\. Kept in Rules$`));
  // Home's short card: its link follows the moment, so the period stays.
  const short = load({ homeVm: home({ waiting: [once] }) });
  await tick();
  assert.match(short.doc.querySelector("#home-waiting .ask .ask-sub").textContent, new RegExp(`${CLOCK} · 2 minutes ago\\. Details in Approvals$`));
});

test("§4.34 A held message's answer: Answered earlier says what went to the AI, with no reversal for one message and the session's own for a session", async () => {
  const s = [{ kind: "text", text: "Claude Code wants to send your message to the AI. It holds " }, { kind: "code", text: "acme.codename" }, { kind: "text", text: "." }];
  const at = Date.now() - 60_000;
  const { doc } = load({
    url: APPROVALS_URL,
    homeVm: home({ answered: [
      { id: "m", sentence: s, outcome: "masked", decidedAt: at, sessions: [], actions: [] },
      { id: "w", sentence: s, outcome: "sent", decidedAt: at, sessions: [], actions: [] },
      { id: "ss", sentence: s, outcome: "sent-session", decidedAt: at, sessions: [], actions: [{ approve: false, label: "Send masked instead" }] },
      { id: "ms", sentence: s, outcome: "masked-session", decidedAt: at, sessions: [], actions: [{ approve: true, label: "Send as written instead" }] },
    ] }),
  });
  await tick();
  const row = (id: string) => doc.querySelector(`#approvals-answered .row.answered[data-id="${id}"]`);
  const cells = (id: string) => [...row(id).children].slice(1).map((c: any) => c.textContent.trim());
  assert.deepEqual(cells("m"), ["Sent masked, or cancelled", ""], "never Blocked, no Allow instead");
  assert.deepEqual(cells("w"), ["Sent as written", ""]);
  assert.deepEqual(cells("ss"), ["Sent as written for the session", "Send masked instead"]);
  assert.deepEqual(cells("ms"), ["Masked for the session", "Send as written instead"]);
});

test("§4.25 Answered earlier: the reversal of a Block names its scope, Always allow instead, and posts …/approve; Block instead posts …/deny; a held message keeps its own", async () => {
  const s = [{ kind: "text", text: "Claude Code wanted to send your secret " }, { kind: "code", text: "STRIPE_KEY" }, { kind: "text", text: " to api.example.com" }];
  const at = Date.now() - 60_000;
  // The server's label (the developer view's words) is never drawn: the page names the reversal itself.
  const { doc, calls } = load({
    url: APPROVALS_URL,
    homeVm: home({ answered: [
      { id: "b", sentence: s, outcome: "blocked", decidedAt: at, sessions: [], actions: [{ approve: true, label: "Allow instead" }] },
      { id: "a", sentence: s, outcome: "allowed", decidedAt: at, sessions: [], actions: [{ approve: false, label: "Block instead" }] },
      { id: "ms", sentence: s, outcome: "masked-session", decidedAt: at, sessions: [], actions: [{ approve: true, label: "Send as written instead" }] },
      { id: "ss", sentence: s, outcome: "sent-session", decidedAt: at, sessions: [], actions: [{ approve: false, label: "Send masked instead" }] },
    ] }),
  });
  await tick();
  const button = (id: string) => doc.querySelector(`#approvals-answered .row.answered[data-id="${id}"] button`);
  assert.equal(button("b").textContent, "Always allow instead", "the allow says it stands, as the card's Always allow");
  assert.equal(button("a").textContent, "Block instead");
  assert.equal(button("ms").textContent, "Send as written instead");
  assert.equal(button("ss").textContent, "Send masked instead");
  const posts = () => calls.filter((c) => c.method === "POST").map((c) => c.url);
  button("b").click();
  await tick();
  assert.deepEqual(posts(), ["/mandu/api/egress/approvals/b/approve"], "a standing allow, not approve-once");
  button("a").click();
  await tick();
  assert.deepEqual(posts().slice(1), ["/mandu/api/egress/approvals/a/deny"]);
});

test("§4.34 Answers that no longer apply: Answered earlier says why under the words, reads No longer applies, and offers no change", async () => {
  const s = [{ kind: "text", text: "Claude Code's program " }, { kind: "code", text: "tee" }, { kind: "text", text: " wants to change a file that runs later: " }, { kind: "code", text: ".bashrc" }];
  const note = "This answer no longer applies: it names the program by its name only, as Mandu asked before October 2, 2026. Mandu now asks about the program's file, so it asks again.";
  const { doc } = load({
    url: APPROVALS_URL,
    homeVm: home({ answered: [{ id: "old", sentence: s, outcome: "allowed", decidedAt: Date.now() - 9 * DAY, sessions: [], actions: [], staleNote: note }] }),
  });
  await tick();
  const row = doc.querySelector('#approvals-answered .row.answered[data-id="old"]');
  assert.equal(row.querySelector(".answered-stale").textContent, note);
  const cells = [...row.children].slice(1).map((c: any) => c.textContent.trim());
  assert.deepEqual(cells, ["No longer applies", ""], "never Always allowed, and no Block instead");
  assert.equal(row.querySelector(".outcome").getAttribute("title"), "Always allowed", "what was answered, on hover");
});

test("§4.25 A question from a session that has ended: Approvals lists the questions an agent waits on, then From sessions that have ended with its line and those cards, which leave their own sentence out", async () => {
  const at = (min: number) => Date.now() - min * 60_000;
  const e1 = { ...ASK, id: "ended-1", askedAt: at(1), count: 3, askerEnded: true };
  const e2 = { ...ASK, id: "ended-2", askedAt: at(5), askerEnded: true };
  const l1 = { ...ASK, id: "live-1", askedAt: at(2) };
  const l2 = { ...ASK, id: "live-2", askedAt: at(3) };
  const page = load({ url: APPROVALS_URL, homeVm: home({ waiting: [e1, l1, l2, e2] }) });
  const { doc } = page;
  await tick();
  const list = doc.getElementById("approvals-waiting");
  const kids = () => [...list.children].map((c: any) => c.getAttribute("data-id") ?? c.className);
  assert.deepEqual(kids(), ["live-1", "live-2", "ask-group-head", "ended-1", "ended-2"], "live first, then the heading, then the ended ones; each kind newest first");
  const head = list.querySelector(".ask-group-head");
  assert.equal(head.querySelector("h3").textContent, "From sessions that have ended");
  assert.equal(head.querySelector("p").textContent, "No agent is waiting on these now. Your answer decides what happens the next time an agent asks the same.");
  assert.equal(head.dataset.id, undefined, "the heading is no card");
  const card = (id: string) => list.querySelector(`.ask[data-id="${id}"]`);
  for (const id of ["ended-1", "ended-2", "live-1"]) assert.equal(card(id).querySelector(".ask-ended"), null, `${id}: no per-card sentence`);
  assert.match(card("ended-1").querySelector(".ask-sub").textContent, new RegExp(`^The text was masked\\. ${CLOCK} · 1 minute ago, 3 times\\. What each answer does$`), "short: What each answer does follows the moment");
  assert.equal(doc.getElementById("nav-approvals-count").textContent, "4", "the badge counts every question");
  // A poll with the same questions leaves the list as drawn.
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
  assert.equal(list.querySelector(".ask-group-head"), head, "not drawn again");
  // A session that ends changes what the list is drawn from: drawn again.
  page.setHome(home({ waiting: [e1, l1, { ...l2, askerEnded: true }, e2] }));
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
  assert.deepEqual(kids(), ["live-1", "ask-group-head", "ended-1", "live-2", "ended-2"]);

  // All of one kind: no heading; all ended keep their sentence.
  for (const [waiting, said] of [[[l1, l2], false], [[e1, e2], true]] as const) {
    const one = load({ url: APPROVALS_URL, homeVm: home({ waiting }) });
    await tick();
    const l = one.doc.getElementById("approvals-waiting");
    assert.equal(l.querySelector(".ask-group-head"), null, "no heading over a list of one kind");
    assert.deepEqual([...l.children].map((c: any) => c.getAttribute("data-id")), waiting.map((a) => a.id));
    for (const c of l.querySelectorAll(".ask")) assert.equal(!!c.querySelector(".ask-ended"), said);
  }
});

test("§4.25 Waiting for your answer counts its questions: '(5)' with 2 from ended sessions, none when empty or unread; it follows a poll and an answer", async () => {
  const at = (min: number) => Date.now() - min * 60_000;
  const live = [1, 2, 3].map((i) => ({ ...ASK, id: `live-${i}`, askedAt: at(i) }));
  const ended = [4, 5].map((i) => ({ ...ASK, id: `ended-${i}`, askedAt: at(i), askerEnded: true }));
  // eslint-disable-next-line prefer-const
  let page: ReturnType<typeof load>;
  page = load({ url: APPROVALS_URL, homeVm: home({ waiting: [...live, ...ended] }), routes: {
    "POST egress/approvals/live-1/deny": () => (page.setHome(home({ waiting: [...live.slice(1), ...ended], answered: [] })), {}),
  } });
  const { doc } = page;
  await tick();
  const h2 = doc.querySelector("#approvals-waiting-block h2");
  const count = doc.getElementById("approvals-waiting-count");
  assert.equal(h2.textContent, "Waiting for your answer (5)", "every question, those from ended sessions too");
  assert.equal(count.textContent, "(5)");
  assert.ok(count.classList.contains("muted"), "muted, as the Rules headings' counts");
  assert.equal(count.parentElement, h2);
  assert.equal(doc.getElementById("approvals-waiting").querySelectorAll(".ask").length, 5, "the count is the cards drawn");
  assert.equal(doc.querySelector("#approvals-waiting .ask-group-head h3").textContent, "From sessions that have ended", "the sub-heading stays");
  assert.equal(doc.getElementById("home-waiting-title").textContent, "Approvals waiting (5)", "Home's heading as before");

  // A poll with the same questions leaves the count as written: not written again.
  const text = count.firstChild;
  await poll(doc);
  assert.equal(count.textContent, "(5)");
  assert.equal(count.firstChild, text, "written only when it changes");

  // A poll that adds one question: the count and the new card.
  const added = { ...ASK, id: "live-0", askedAt: at(0) };
  page.setHome(home({ waiting: [added, ...live, ...ended] }));
  await poll(doc);
  assert.equal(count.textContent, "(6)");
  assert.equal(h2.textContent, "Waiting for your answer (6)", "the heading's words stay");
  assert.ok(doc.querySelector('#approvals-waiting .ask[data-id="live-0"]'), "the new card");

  // An answer that takes a card off lowers it with that redraw.
  page.setHome(home({ waiting: [...live, ...ended] }));
  await poll(doc);
  assert.equal(count.textContent, "(5)");
  const block = [...doc.querySelectorAll('#approvals-waiting .ask[data-id="live-1"] .ask-actions button')].find((b: any) => b.textContent === "Block");
  assert.ok(block, "the card's Block");
  block.click();
  await tick(40);
  assert.equal(doc.querySelector('#approvals-waiting .ask[data-id="live-1"]'), null, "the card went");
  assert.equal(count.textContent, "(4)");

  // None waiting, or the queue not read: no count, the list's line says so.
  for (const vm of [home({ waiting: [] }), home({ waiting: [ASK], waitingKnown: false })]) {
    const other = load({ url: APPROVALS_URL, homeVm: vm });
    await tick();
    assert.equal(other.doc.getElementById("approvals-waiting-count").textContent, "");
    assert.equal(other.doc.querySelector("#approvals-waiting-block h2").textContent.trim(), "Waiting for your answer");
    assert.ok(other.doc.querySelector("#approvals-waiting .empty"), "the list's own line");
  }
  // A poll that empties the list takes the count away.
  page.setHome(home({ waiting: [] }));
  await poll(doc);
  assert.equal(count.textContent, "");
});

test("§4.25 A question from a session that has ended: the session page's Needs your OK keeps the server's order, with no heading; the heading is styled", async () => {
  const ended = { ...ASK, id: "ended-1", askedAt: Date.now() - 60_000, askerEnded: true };
  const live = { ...ASK, id: "live-1", askedAt: Date.now() - 120_000 };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: {
    "GET home/agent?session=s1": { ...AGENT, waiting: [ended, live] },
  } });
  await tick(30);
  const list = doc.getElementById("agent-waiting");
  assert.deepEqual([...list.children].map((c: any) => c.getAttribute("data-id") ?? c.className), ["ended-1", "live-1"]);
  assert.match(list.querySelector('.ask[data-id="ended-1"] .ask-ended').textContent, /The agent that asked has ended/);
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  const head = rules.find((r) => r.selectors.includes(".ask-group-head h3"));
  assert.ok(head, "the heading is styled");
  assert.equal(declValue(head!.block, "font-size"), "15px");
});

test("§4.34 A send question says what its standing answers keep doing: the line under Send without it, its Rules a link; only the halves offered, only on the expanded card", async () => {
  const T = (text: string) => ({ kind: "text", text });
  const C = (text: string) => ({ kind: "code", text });
  const RULES = { kind: "link", text: "Rules", to: "your-rules" };
  const bothParts = [
    T("Mandu remembers it for "), C("STRIPE_KEY"), T(" and "), C("api.stripe.com"), T(" only. Always allow: from now on, any agent's request that sends it to "), C("api.stripe.com"),
    T(" goes with the real secret filled in, without asking. Block: those requests are refused without asking. Your answer does not cover other secrets or other hosts. You can change it under "), RULES, T("."),
  ];
  const said = (parts: Array<{ text: string }>) => parts.map((p) => p.text).join("");
  const both = {
    ...ASK, id: "egr-21", ifStandingParts: bothParts, ifStanding: said(bothParts),
    actions: [
      { approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Always allow" },
      { approve: false, label: "Send without it", scope: "once", strip: true }, { approve: false, label: "Block" },
    ],
  };
  const blockParts = [T("Mandu remembers it for "), C("STRIPE_KEY"), T(" and "), C("api.stripe.com"), T(" only. Block: from now on, any agent's request that sends it to "), C("api.stripe.com"), T(" is refused without asking. Your answer does not cover other secrets or other hosts. You can change it under "), RULES, T(".")];
  const blockOnly = { ...ASK, id: "egr-22", ifStandingParts: blockParts, ifStanding: said(blockParts), actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: false, label: "Block" }] };
  // A card offering no standing answer draws no line, whatever it is sent.
  const onceOnly = { ...ASK, id: "egr-23", ifStandingParts: bothParts, ifStanding: said(bothParts), actions: [{ approve: true, label: "Allow once", scope: "once" }] };
  const other = { ...ASK, id: "egr-24", family: "run", ifStandingParts: bothParts, ifStanding: said(bothParts) };
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [both, blockOnly, onceOnly, other] }) });
  await tick();
  const card = (id: string) => doc.querySelector(`#approvals-waiting .ask[data-id="${id}"]`) as any;
  const line = card("egr-21").querySelector(".ask-standing");
  assert.ok(line, "the card says what Always allow and Block keep doing");
  assert.equal(line.textContent, "If you click Always allow or Block: " + both.ifStanding);
  assert.deepEqual([...line.querySelectorAll("code")].map((c: any) => c.textContent), ["STRIPE_KEY", "api.stripe.com", "api.stripe.com"], "the names as code");
  assert.equal(line.previousElementSibling, card("egr-21").querySelector(".ask-without"), "under Send without it");
  assert.ok(line.nextElementSibling.contains(card("egr-21").querySelector(".ask-actions")), "above the buttons");
  const rules = line.querySelector("a");
  assert.equal(rules.textContent, "Rules");
  assert.match(rules.getAttribute("href"), /\/rules#your-rules$/, "Rules, where a remembered answer is kept: no row exists yet");
  assert.equal(card("egr-22").querySelector(".ask-standing").textContent, "If you click Block: " + blockOnly.ifStanding, "only the Block half");
  assert.equal(card("egr-23").querySelector(".ask-standing"), null, "Allow once alone: no line");
  assert.equal(card("egr-24").querySelector(".ask-standing"), null, "another family: no line");
  // Home's short card leaves it out, as it leaves the cells out.
  const home1 = load({ homeVm: home({ waiting: [both] }) });
  await tick();
  assert.ok(home1.doc.querySelector('#home-waiting .ask[data-id="egr-21"]'), "Home draws the card");
  assert.equal(home1.doc.querySelector('#home-waiting .ask[data-id="egr-21"] .ask-standing'), null);
  // No print rule hides it (#91): the page prints the card as drawn.
  const css = stripComments(readFileSync(join(PUB, "app.css"), "utf8"));
  assert.ok(!css.includes("ask-standing"), "no rule of its own, on screen or in print: it is a note like Send without it");
});

test("§4.25 Answered earlier: the reversal names what the arbiter keeps its allow as, Allow this session instead or Allow once instead, still …/approve; a program's send allowed for its session reads Allowed for this session, kept in Rules", async () => {
  const s = [{ kind: "text", text: "Claude Code's program wanted to send data from " }, { kind: "code", text: "~/shop/.env" }, { kind: "text", text: " to hooks.slack.com" }];
  const at = Date.now() - 60_000;
  const { doc, calls } = load({
    url: APPROVALS_URL,
    homeVm: home({ answered: [
      { id: "hs", sentence: s, outcome: "blocked", decidedAt: at, sessions: [], actions: [{ approve: true, label: "Allow instead" }], allowKeptAs: "session" },
      { id: "ho", sentence: s, outcome: "blocked", decidedAt: at, sessions: [], actions: [{ approve: true, label: "Allow instead" }], allowKeptAs: "once" },
      { id: "ha", sentence: s, outcome: "allowed-session", decidedAt: at, sessions: [], actions: [{ approve: false, label: "Block instead" }] },
      { id: "b", sentence: s, outcome: "blocked", decidedAt: at, sessions: [], actions: [{ approve: true, label: "Allow instead" }] },
    ] }),
  });
  await tick();
  const row = (id: string) => doc.querySelector(`#approvals-answered .row.answered[data-id="${id}"]`);
  const button = (id: string) => row(id).querySelector("button");
  assert.equal(button("hs").textContent, "Allow this session instead");
  assert.equal(button("ho").textContent, "Allow once instead");
  assert.equal(button("b").textContent, "Always allow instead", "absent: a standing allow, as before");
  assert.equal(button("ha").textContent, "Block instead");
  const out = row("ha").querySelector(".outcome");
  assert.equal(out.textContent, "Allowed for this session", "never Always allowed");
  assert.ok(out.classList.contains("ok"), "an allow's tone");
  assert.ok(out.querySelector("svg"), "an allow's mark");
  assert.equal(row("ha").dataset.state, "allowed-session");
  assert.match(row("ha").querySelector(".answered-when").textContent, /Kept in Rules$/, "Rules keeps it");
  assert.doesNotMatch(row("hs").querySelector(".answered-when").textContent, /Always/);
  const posts = () => calls.filter((c) => c.method === "POST").map((c) => c.url);
  button("hs").click();
  await tick();
  button("ho").click();
  await tick();
  assert.deepEqual(posts(), ["/mandu/api/egress/approvals/hs/approve", "/mandu/api/egress/approvals/ho/approve"], "the same route and body: only the words change");
});

// ── An ended question is short on Approvals (dashboard.md §4.25) ────────────
// Under *From sessions that have ended* a card is Home's short card, with
// What each answer does in place of Details in Approvals; pressed, it opens
// the full card's cells, notes and agent link in place and reads Hide. Kept
// open by question id over a poll that draws the list again. Full: a live
// card, every card of an all-ended list, the card `/approvals/<id>` names, a
// held message and a program's send of the files it holds.

const ENDED_SEND = {
  ...ASK, id: "ended-1", askerEnded: true,
  answersShortParts: [{ kind: "text", text: "Allow once and Send without it cover the next request; Always allow and Block are kept under Rules." }],
  answersShort: "Allow once and Send without it cover the next request; Always allow and Block are kept under Rules.",
};
const ENDED_2 = { ...ASK, id: "ended-2", askerEnded: true };
const LIVE = { ...ASK, id: "live-1" };
const endedCard = (doc: any, id: string) => doc.querySelector(`#approvals-waiting .ask[data-id="${id}"]`);
const poll = async (doc: any) => {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
};

test("§4.25 An ended question is short on Approvals: under the heading a card has no cells and a What each answer does button where Home's link is; the live card keeps its cells", async () => {
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [LIVE, ENDED_SEND, ENDED_2] }) });
  await tick();
  const live = endedCard(doc, "live-1");
  assert.equal(live.querySelectorAll(".ask-detail .k").length, 3, "the live card keeps its three cells");
  assert.equal(live.querySelector(".ask-more"), null);
  assert.ok(live.classList.contains("expanded"));
  for (const id of ["ended-1", "ended-2"]) {
    const card = endedCard(doc, id);
    assert.equal(card.querySelector(".ask-detail"), null, `${id}: no cells`);
    assert.equal(card.querySelector(".ask-without, .ask-standing, .ask-link"), null, `${id}: no notes, no agent link`);
    assert.equal(card.querySelector(".ask-details"), null, `${id}: no link to the page it is on`);
    assert.ok(!card.classList.contains("expanded"), id);
    const more = card.querySelector(".ask-sub .ask-more");
    assert.equal(more.tagName, "BUTTON");
    assert.equal(more.getAttribute("type"), "button");
    assert.equal(more.textContent, "What each answer does");
    assert.equal(more.getAttribute("aria-expanded"), "false");
    assert.equal(more.dataset.askMore, id, "keyed by its question, for the focus over a poll");
    assert.equal(card.querySelector("h4.ask-sentence") !== null, true, "its heading stays an h4 under the h3");
    // The same buttons as the full card, beside the words as on Home.
    assert.deepEqual([...card.querySelectorAll(".ask-actions button")].map((b: any) => b.textContent), ["Allow once", "Always allow", "Block"]);
    assert.equal(card.querySelector(".ask-top > .ask-actions") !== null, true);
  }
  // Which answers last stays in sight on the short card (§4.34 *Home's card
  // says which answers last*).
  assert.equal(endedCard(doc, "ended-1").querySelector(".ask-answers").textContent, ENDED_SEND.answersShort);
  // The toggle is styled where Home's link is.
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  assert.ok(rules.find((r) => r.selectors.includes(".ask-sub .ask-more")), "the toggle has a rule");
  const open = rules.find((r) => r.selectors.includes(".ask.ask-open"));
  assert.equal(declValue(open!.block, "flex-direction"), "column", "an open card stacks its cells under its line");
});

test("§4.25 An ended question is short on Approvals: What each answer does opens the cells, notes and agent link in place and reads Hide; a poll keeps it open, and so does one that adds a question, with the focus on it", async () => {
  const page = load({ url: APPROVALS_URL, homeVm: home({ waiting: [LIVE, ENDED_SEND, ENDED_2] }) });
  const { doc } = page;
  await tick();
  const more = () => endedCard(doc, "ended-1").querySelector(".ask-more");
  more().focus();
  more().click();
  const card = endedCard(doc, "ended-1");
  assert.equal(more().getAttribute("aria-expanded"), "true");
  assert.equal(more().textContent, "Hide");
  assert.ok(card.classList.contains("ask-open"));
  assert.deepEqual([...card.querySelectorAll(".ask-detail .k")].map((k: any) => k.firstChild.textContent), ["Why it stopped", "What the AI has now", "If you click Allow once or Always allow"]);
  assert.equal(card.querySelector(".ask-link").textContent, "See what the agent was doing");
  assert.match(card.querySelector(".ask-link").getAttribute("href"), /\/agents\/s1/);
  // In place: under the card's line and buttons, which stay as they were.
  assert.equal(card.querySelector(".ask-top").nextElementSibling, card.querySelector(".ask-more-box"));
  assert.ok(card.querySelector(".ask-top > .ask-actions"));
  assert.equal(endedCard(doc, "ended-2").querySelector(".ask-detail"), null, "only the card pressed opens");
  // A poll with the same questions draws nothing again.
  await poll(doc);
  assert.equal(endedCard(doc, "ended-1"), card, "not drawn again");
  // A poll that adds a question draws the list again: the card stays open,
  // and the focus stays on its button.
  page.setHome(home({ waiting: [LIVE, { ...ASK, id: "live-2" }, ENDED_SEND, ENDED_2] }));
  await poll(doc);
  assert.notEqual(endedCard(doc, "ended-1"), card, "drawn again");
  assert.equal(endedCard(doc, "ended-1").querySelectorAll(".ask-detail .k").length, 3, "still open");
  assert.equal(more().getAttribute("aria-expanded"), "true");
  assert.equal(more().textContent, "Hide");
  assert.equal(doc.activeElement, more(), "the focus is on the toggle again");
  assert.equal(endedCard(doc, "ended-2").querySelector(".ask-detail"), null);
  // Hide folds it, and the next draw keeps it folded.
  more().click();
  assert.equal(endedCard(doc, "ended-1").querySelector(".ask-detail, .ask-more-box"), null);
  assert.equal(more().getAttribute("aria-expanded"), "false");
  assert.equal(more().textContent, "What each answer does");
  page.setHome(home({ waiting: [LIVE, ENDED_SEND, ENDED_2] }));
  await poll(doc);
  assert.equal(endedCard(doc, "ended-1").querySelector(".ask-detail"), null);
});

test("§4.25 An ended question is short on Approvals: the card /approvals/<id> names is full, marked; once the mark goes it stays open", async () => {
  const { doc } = load({ url: APPROVALS_URL + "/ended-2", homeVm: home({ waiting: [LIVE, ENDED_SEND, ENDED_2] }) });
  await tick(30);
  const card = endedCard(doc, "ended-2");
  assert.ok(card.classList.contains("focus"), "marked");
  assert.ok(card.classList.contains("expanded"), "full");
  assert.equal(card.querySelectorAll(".ask-detail .k").length, 3);
  assert.equal(card.querySelector(".ask-more"), null);
  assert.ok(card.querySelector(".ask-link"));
  assert.equal(endedCard(doc, "ended-1").querySelector(".ask-detail"), null, "the other ended card is short");
  // Following a link to it from Approvals itself draws it full too.
  const other = load({ url: APPROVALS_URL, homeVm: home({ waiting: [LIVE, ENDED_SEND, ENDED_2] }) });
  await tick();
  assert.equal(endedCard(other.doc, "ended-2").querySelector(".ask-detail"), null);
  const a = other.doc.createElement("a");
  a.setAttribute("href", "/mandu/approvals/ended-2");
  a.setAttribute("data-page-link", "approvals");
  a.setAttribute("data-ask", "ended-2");
  other.doc.body.append(a);
  a.click();
  await tick(30);
  assert.ok(endedCard(other.doc, "ended-2").classList.contains("expanded"), "full once the page is opened for it");
  assert.ok(endedCard(other.doc, "ended-2").classList.contains("focus"));
  // A search of Answered earlier ends the mark: the card is not folded
  // under the reader, it stays open.
  (other.doc.getElementById("answered-q") as any).value = "stripe";
  other.doc.getElementById("answered-search").dispatchEvent(new other.doc.defaultView.Event("submit", { cancelable: true }));
  await tick(30);
  const c = endedCard(other.doc, "ended-2");
  assert.ok(!c.classList.contains("focus"), "no longer marked");
  assert.ok(!c.classList.contains("expanded"), "drawn short again");
  assert.equal(c.querySelectorAll(".ask-detail .k").length, 3, "its cells stay in sight");
  assert.equal(c.querySelector(".ask-more").textContent, "Hide");
});

test("§4.25 An ended question is short on Approvals: an all-ended list is full, and so are a held message and a program's send of the files it holds under the heading", async () => {
  const all = load({ url: APPROVALS_URL, homeVm: home({ waiting: [ENDED_SEND, ENDED_2] }) });
  await tick();
  for (const id of ["ended-1", "ended-2"]) {
    const c = endedCard(all.doc, id);
    assert.ok(c.classList.contains("expanded"), `${id}: full with no heading`);
    assert.equal(c.querySelector(".ask-more"), null);
  }
  const prompt = {
    ...ASK, id: "prompt-1", family: "prompt", askerEnded: true,
    sentence: [{ kind: "text", text: "Claude Code wants to send your message to the AI." }],
    actions: [{ approve: true, scope: "once", prompt: "send", label: "Send as written" }],
  };
  const holder = {
    ...ASK, id: "holder-1", askerEnded: true,
    sentence: [{ kind: "text", text: "Claude Code's program wants to send data from .env to hooks.slack.com" }],
    actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Allow this session" }, { approve: false, label: "Block" }],
    sources: [{ path: "/home/u/ws/.env", name: "~/ws/.env", mayGo: "may go nowhere", blocks: true, always: "Always: add hooks.slack.com to .env" }],
  };
  const { doc } = load({
    url: APPROVALS_URL, homeVm: home({ waiting: [LIVE, prompt, holder, ENDED_2] }),
    routes: { "GET prompt-filters/holds": { holds: [] } },
  });
  await tick();
  assert.ok(doc.querySelector("#approvals-waiting .ask-group-head"), "under the heading");
  for (const id of ["prompt-1", "holder-1"]) {
    const c = endedCard(doc, id);
    assert.ok(c.classList.contains("expanded"), `${id}: full`);
    assert.equal(c.querySelector(".ask-more"), null, id);
    assert.ok(c.querySelector(".ask-detail"), id);
  }
  assert.ok(endedCard(doc, "holder-1").querySelector(".ask-source-always"), "its per-file Always");
  assert.ok([...endedCard(doc, "prompt-1").querySelectorAll("button")].some((b: any) => b.textContent === "Send as written for this session"), "a held message's answers, all of them");
  assert.ok(endedCard(doc, "ended-2").querySelector(".ask-more"), "the plain send beside them is short");
});

// ── A waiting question is short on a phone (dashboard.md §4.25) ─────────────
// At the page's phone breakpoint (`max-width: 760px`) every card of
// Approvals is the short card an ended question gets, its answers right
// under its line; a held message, a program's send of the files it holds
// and the card `/approvals/<id>` names stay full. Wide, nothing changes. A
// flip of the query draws the list again, open cards kept open, the focus
// kept. jsdom has no matchMedia: `phone` stubs one the test can flip.

/** A stubbed `(max-width: 760px)` query: `flip(matches)` fires its change. */
function phone(matches: boolean) {
  const q: any = { media: "(max-width: 760px)", matches, listeners: [] as Array<(e: unknown) => void> };
  q.addEventListener = (type: string, fn: (e: unknown) => void) => { if (type === "change") q.listeners.push(fn); };
  q.removeEventListener = () => {};
  const asked: string[] = [];
  return {
    asked,
    before: (w: any) => { w.matchMedia = (m: string) => { asked.push(m); return q; }; },
    flip: (to: boolean) => { q.matches = to; for (const fn of q.listeners) fn({ matches: to, media: q.media }); },
  };
}
const ANSWERS_SHORT = "Allow once and Send without it cover the next request; Always allow and Block are kept under Rules.";
const STANDING = "Mandu remembers it for STRIPE_KEY and api.stripe.com only.";
/** A live send of a secret that offers all four answers. */
const LIVE_SEND = {
  ...ASK, id: "live-send",
  answersShortParts: [{ kind: "text", text: ANSWERS_SHORT }], answersShort: ANSWERS_SHORT,
  ifStandingParts: [{ kind: "text", text: STANDING }], ifStanding: STANDING,
  actions: [
    { approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Always allow" },
    { approve: false, label: "Send without it", scope: "once", strip: true }, { approve: false, label: "Block" },
  ],
};
const LIVE_2 = { ...ASK, id: "live-2" };
const PROMPT_LIVE = {
  ...ASK, id: "prompt-1", family: "prompt",
  sentence: [{ kind: "text", text: "Claude Code wants to send your message to the AI." }],
  actions: [{ approve: true, scope: "once", prompt: "send", label: "Send as written" }],
};
const HOLDER_LIVE = {
  ...ASK, id: "holder-1",
  sentence: [{ kind: "text", text: "Claude Code's program wants to send data from .env to hooks.slack.com" }],
  actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Allow this session" }, { approve: false, label: "Block" }],
  sources: [{ path: "/home/u/ws/.env", name: "~/ws/.env", mayGo: "may go nowhere", blocks: true, always: "Always: add hooks.slack.com to .env" }],
};

test("§4.25 A waiting question is short on a phone: a live send card is short, its answers-last line and four buttons beside its line; What each answer does opens the three cells and both If you click notes", async () => {
  const media = phone(true);
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [LIVE_SEND, LIVE_2] }), before: media.before });
  await tick();
  assert.ok(media.asked.includes("(max-width: 760px)"), "the page's phone breakpoint");
  for (const id of ["live-send", "live-2"]) {
    const card = endedCard(doc, id);
    assert.ok(!card.classList.contains("expanded"), `${id}: short`);
    assert.equal(card.querySelector(".ask-detail, .ask-without, .ask-standing, .ask-link"), null, `${id}: no cells, notes nor agent link`);
    assert.equal(card.querySelector(".ask-details"), null, `${id}: no link to the page it is on`);
    assert.ok(card.querySelector("h3.ask-sentence"), `${id}: still an h3 under the h2, not under the ended heading`);
    assert.equal(card.querySelector(".ask-ended"), null, `${id}: a live card says nothing about an ended agent`);
    const more = card.querySelector(".ask-sub .ask-more");
    assert.equal(more.textContent, "What each answer does");
    assert.equal(more.getAttribute("aria-expanded"), "false");
    assert.equal(more.dataset.askMore, id);
    assert.ok(card.querySelector(".ask-top > .ask-actions"), `${id}: the buttons beside the line, as on Home`);
  }
  const card = endedCard(doc, "live-send");
  assert.match(card.querySelector(".ask-sub").textContent, new RegExp(`^The text was masked\\. ${CLOCK} · 1 minute ago\\. ${ANSWERS_SHORT} What each answer does$`), "the why, the moment, which answers last, the toggle");
  assert.equal(card.querySelector(".ask-answers").textContent, ANSWERS_SHORT, "which answers last stays in sight");
  assert.deepEqual([...card.querySelectorAll(".ask-actions button")].map((b: any) => b.textContent), ["Allow once", "Always allow", "Send without it", "Block"]);
  card.querySelector(".ask-more").click();
  const open = endedCard(doc, "live-send");
  assert.equal(open.querySelector(".ask-more").textContent, "Hide");
  assert.deepEqual([...open.querySelectorAll(".ask-detail .k")].map((k: any) => k.firstChild.textContent), ["Why it stopped", "What the AI has now", "If you click Allow once or Always allow"]);
  assert.equal(open.querySelector(".ask-without strong").textContent, "If you click Send without it: ");
  assert.equal(open.querySelector(".ask-standing").textContent, "If you click Always allow or Block: " + STANDING);
  assert.ok(open.querySelector(".ask-detail").textContent.includes(ASK.ifAllowed), "the live card's own cells");
  assert.ok(open.querySelector(".ask-link"), "with the agent link");
  assert.equal(endedCard(doc, "live-2").querySelector(".ask-detail"), null, "only the card pressed opens");
});

test("§4.25 A waiting question is short on a phone: a held message, a program's send of the files it holds and the card /approvals/<id> names stay full", async () => {
  const media = phone(true);
  const { doc } = load({
    url: APPROVALS_URL + "/live-2", homeVm: home({ waiting: [PROMPT_LIVE, HOLDER_LIVE, LIVE_SEND, LIVE_2] }), before: media.before,
    routes: { "GET prompt-filters/holds": { holds: [] } },
  });
  await tick(30);
  for (const id of ["prompt-1", "holder-1", "live-2"]) {
    const c = endedCard(doc, id);
    assert.ok(c.classList.contains("expanded"), `${id}: full`);
    assert.equal(c.querySelector(".ask-more"), null, id);
    assert.ok(c.querySelector(".ask-detail"), id);
  }
  assert.ok(endedCard(doc, "live-2").classList.contains("focus"), "the named card is marked");
  assert.ok(endedCard(doc, "holder-1").querySelector(".ask-source-always"), "its per-file Always");
  assert.ok([...endedCard(doc, "prompt-1").querySelectorAll("button")].some((b: any) => b.textContent === "Send as written for this session"), "a held message's answers, all of them");
  assert.ok(endedCard(doc, "live-send").querySelector(".ask-more"), "the plain send beside them is short");
  // Once the mark goes, the named card is short with its cells open, never
  // folded under the reader.
  (doc.getElementById("answered-q") as any).value = "stripe";
  doc.getElementById("answered-search").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick(30);
  const c = endedCard(doc, "live-2");
  assert.ok(!c.classList.contains("expanded"), "short once no longer marked");
  assert.equal(c.querySelectorAll(".ask-detail .k").length, 3, "its cells stay in sight");
  assert.equal(c.querySelector(".ask-more").textContent, "Hide");
});

test("§4.25 A waiting question is short on a phone: on a wide screen, or with no matchMedia, a live card is full as before", async () => {
  for (const before of [phone(false).before, undefined]) {
    const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [LIVE_SEND, LIVE_2] }), before });
    await tick();
    for (const id of ["live-send", "live-2"]) {
      const c = endedCard(doc, id);
      assert.ok(c.classList.contains("expanded"), `${id}: full (${before ? "wide" : "no matchMedia"})`);
      assert.equal(c.querySelectorAll(".ask-detail .k").length, 3);
      assert.equal(c.querySelector(".ask-more"), null);
    }
    assert.ok(endedCard(doc, "live-send").querySelector(".ask-standing"), "its If you click Always allow or Block");
  }
});

test("§4.25 A waiting question is short on a phone: a flip of the query draws the list again in the other form, an opened card kept open and the focus kept on its button", async () => {
  const media = phone(true);
  const page = load({ url: APPROVALS_URL, homeVm: home({ waiting: [LIVE_SEND, LIVE_2, ENDED_SEND] }), before: media.before });
  const { doc } = page;
  await tick();
  endedCard(doc, "live-send").querySelector(".ask-more").click();
  const allowOnce = () => [...endedCard(doc, "live-2").querySelectorAll(".ask-actions button")].find((b: any) => b.textContent === "Allow once") as any;
  allowOnce().focus();
  const before = endedCard(doc, "live-2");
  // Wide: the live cards full, the ended one short as ever.
  media.flip(false);
  assert.notEqual(endedCard(doc, "live-2"), before, "drawn again at once");
  for (const id of ["live-send", "live-2"]) assert.ok(endedCard(doc, id).classList.contains("expanded"), `${id}: full when wide`);
  assert.ok(!endedCard(doc, "ended-1").classList.contains("expanded"), "the ended card stays short");
  assert.equal(doc.activeElement, allowOnce(), "the focus stays on Allow once");
  // A poll that brings the same leaves it as drawn.
  const wide = endedCard(doc, "live-2");
  await poll(doc);
  assert.equal(endedCard(doc, "live-2"), wide, "a poll does not draw it again");
  // Back to a phone: short again, the card opened before still open.
  media.flip(true);
  assert.ok(!endedCard(doc, "live-2").classList.contains("expanded"), "short on a phone again");
  const open = endedCard(doc, "live-send");
  assert.equal(open.querySelectorAll(".ask-detail .k").length, 3, "the opened card is still open");
  assert.equal(open.querySelector(".ask-more").textContent, "Hide");
  assert.equal(doc.activeElement, allowOnce(), "the focus is on Allow once again");
});
