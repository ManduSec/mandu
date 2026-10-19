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
  assert.ok(heads.includes("Waiting for your answer"), heads.join(" | "));
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
  assert.match(old.textContent, / · \d+ days ago$/);
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
  const answered = [{ id: "a2", sentence: SEND_WORDS, outcome: "blocked", decidedAt: null, actions: [] }];
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ answered }) });
  await tick();
  const row = doc.querySelector('#approvals-answered .row.answered[data-id="a2"]');
  assert.equal(row.querySelector(".answered-when"), null);
  assert.equal(row.querySelector(".answered-what").textContent, "The agent wants to send your secret GITHUB_TOKEN to gist.github.com");
  assert.equal(row.children.length, 3, "words, answer, and the empty cell where a reversal would be");
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
  assert.match(line("egr-8").textContent, new RegExp(`^${CLOCK} · 1 minute ago\\. See what the agent was doing$`));
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
  const cols = declValue(wide.block, "grid-template-columns")!.match(/minmax\([^)]*\)|\S+/g)!;
  assert.equal(cols.length, 3, `words and when, the answer, the button (got ${cols.join(" ")})`);
  assert.equal(cols[0], "minmax(0, 1fr)", "the words' column takes the room left");
  for (const c of cols.slice(1)) assert.match(c, /^\d+px$/, "the others are fixed, so the rows line up");
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
  assert.match(sub("ended-1"), new RegExp(`^${CLOCK} · 2 minutes ago, 3 times\\. The agent that asked has ended, so nothing is waiting on this now\\. Your answer counts the next time an agent asks\\.$`));
  const label = (id: string) => [...card(id).querySelectorAll(".ask-detail .k")].map((k: any) => k.textContent.trim())[2];
  assert.equal(label("run-1"), "If you click Allow once", "no Always allow offered, none named");
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
  assert.match(sub(card("ended-1")), new RegExp(`^${CLOCK} · 2 minutes ago, 3 times\\. The agent that asked has ended`), "a sentence follows: the period stays");
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
  assert.match(row.textContent, new RegExp(`^${CLOCK} · 2 minutes ago$`));
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
