/**
 * home-js-agent-headings.test — dashboard.md §4.25, the per-agent page,
 * *Each turn and each secret card is a heading*. A session page holds up
 * to 60 turns, each several steps long, and a screen-reader user moves
 * through a long page by its headings; until 2026-10-27 it had none below
 * its h2s: a turn's "You asked" line and a secret card's name were plain
 * divs (WCAG 2.1 SC 1.3.1, 2.4.6).
 *
 *   H1  every turn card (and a message Mandu stopped) has exactly one h3,
 *       which names the card (`aria-labelledby`): "You asked at 10:24",
 *       "You ran at …", "Before your first question at …", "A message you
 *       wrote at …"; the visible line is unchanged ("You asked", the time
 *       said only to a screen reader); a card with no time says none;
 *   H2  over two days the heading names the day too, in the day line's
 *       words ("You asked at 00:10 on Saturday, Oct 17");
 *   H3  every Your secrets card has one h3, its name, with the level tag
 *       beside it, never in it;
 *   H4  the page's heading levels never skip (h1 → h2 → h3);
 *   H5  under the page's own styles, light and dark, the h3s look as the
 *       lines they replace did: the same font size, weight and colour, and
 *       never a heading's balanced wrap;
 *   H6  with "Only where Mandu stepped in" on (§4.25ae), the folded turns'
 *       headings are hidden with them: the headings left are the turns
 *       where Mandu stepped in.
 *
 * Over the real dashboard and a recorded session:
 * test/component/agent-page-headings.test.ts.
 * Axes: none (display only).
 */
process.env.TZ = "Asia/Seoul"; // UTC+9, no daylight saving time

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AGENT, PUB, T, load, tick } from "./home-js-fixtures.js";
import { perSelector, resolveCssVars, stylesAt } from "./css-flatten.js";

const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
/** The year words a day of 2026 gets: none while it is 2026. */
const YEAR = new Date().getFullYear() === 2026 ? "" : ", 2026";
const step = (id: string, ts: string, outcome = "plain") => ({ kind: "action", id, ts, icon: "run", sentence: [T(`Ran ${id}`)], outcome, note: null, split: null });
const turn = (id: string, ts: string | null, outcome = "plain", over: Record<string, unknown> = {}) => ({
  ...AGENT.story[1], id, ts, prompt: `Question ${id}`, promptParts: null, shell: null, routine: null, reply: null, moreSteps: 0, promptNote: null,
  summary: outcome === "plain" ? "Nothing here needed guarding." : `Mandu did ${outcome}.`, summaryParts: null, tone: outcome,
  steps: [step(`${id}-a`, ts ?? "2026-10-16T01:00:01.000Z", outcome)], ...over,
});
const UNSENT = { lines: ["Your message was not sent to the AI: it holds a card number."], items: [], ts: "2026-10-16T02:00:00.000Z" };
/** One day in Seoul: 09:50 before any question, 10:24 a question, 11:00 a
 *  message Mandu stopped, 12:05 a shell escape, then a turn with no time. */
const ONE_DAY = { ...AGENT, waiting: [], earlier: 0, unplacedNotes: [UNSENT], story: [
  turn("t:pre", "2026-10-16T00:50:00.000Z", "plain", { prompt: null }),
  turn("t:ask", "2026-10-16T01:24:00.000Z", "blocked"),
  turn("t:sh", "2026-10-16T03:05:00.000Z", "plain", { prompt: "!ls", shell: { command: "ls", output: [] } }),
  turn("t:none", null),
] };
// 23:50 on Friday Oct 16 and 00:10 on Saturday Oct 17 in Seoul.
const NIGHT = { ...AGENT, waiting: [], earlier: 0, unplacedNotes: [], story: [
  turn("t:1", "2026-10-16T14:50:00.000Z"), turn("t:2", "2026-10-16T15:10:00.000Z", "blocked"),
] };
const SECRETS = {
  mode: "secrets", flagged: false, more: 0,
  secrets: [
    { what: [{ kind: "code", text: "STRIPE_KEY" }, T(" in "), { kind: "code", text: "~/mandu-try/.env" }], level: "No AI", lines: [
      { tone: "good", parts: [T("The AI got only its masked version, never the real value.")] },
    ] },
    { what: [T("The file "), { kind: "code", text: "~/mandu-try/deploy/staging.tfvars" }], level: "No AI", lines: [
      { tone: "good", parts: [T("The AI got only its masked version, never the real value.")] },
    ] },
  ],
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const cards = (doc: El) => [...doc.querySelectorAll("#agent-story article.turn")] as El[];
/** What a screen reader hears of an element: its words, hidden ones too. */
const said = (e: El) => String(e.textContent).replace(/\s+/g, " ").trim();
/** The headings a screen reader lists: none inside a hidden fold. */
const listed = (doc: El) => ([...doc.querySelectorAll("#page-agent h1, #page-agent h2, #page-agent h3, #page-agent h4, #page-agent h5, #page-agent h6")] as El[])
  .filter((h) => !h.closest("[hidden]"));

async function page(vm: unknown): Promise<El> {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": vm } });
  await tick();
  return doc;
}

test("H1: every turn card has one h3 that names it, its line and its time: 'You asked at 10:24'", async () => {
  const doc = await page(ONE_DAY);
  const all = cards(doc);
  assert.equal(all.length, 5, "four turns and the message Mandu stopped");
  const heads = all.map((c) => {
    const h3s = [...c.querySelectorAll("h3")] as El[];
    assert.equal(h3s.length, 1, `${c.dataset.turnId ?? "unsent"}: one heading`);
    const id = c.getAttribute("aria-labelledby");
    assert.ok(id, "the card is named");
    assert.equal(doc.getElementById(id), h3s[0], "by its own heading");
    assert.ok(h3s[0].closest(".turn-head"), "the heading is the card's head line");
    return said(h3s[0]);
  });
  assert.deepEqual(heads, [
    "Before your first question at 09:50",
    "You asked at 10:24",
    "A message you wrote at 11:00",
    "You ran at 12:05",
    "You asked",
  ], "in page order; a turn with no time says none");
  // The line a sighted reader sees is unchanged: the time is said once,
  // in its column, and only a screen reader hears it in the heading.
  const asked = all[1].querySelector("h3");
  assert.equal(asked.querySelector(".note").textContent, "You asked");
  assert.ok(asked.querySelector(".turn-when").classList.contains("sr-only"), "the heading's time is not drawn again");
  assert.equal(all[1].querySelector(".turn-head > time.time").textContent, "10:24");
  const ids = all.map((c) => c.getAttribute("aria-labelledby"));
  assert.equal(new Set(ids).size, ids.length, "each card its own heading id");
});

test("H2: over two days a turn's heading names its day, as the day line above it does", async () => {
  const doc = await page(NIGHT);
  assert.deepEqual(cards(doc).map((c) => said(c.querySelector("h3"))), [
    `You asked at 23:50 on Friday, Oct 16${YEAR}`,
    `You asked at 00:10 on Saturday, Oct 17${YEAR}`,
  ]);
  assert.deepEqual([...doc.querySelectorAll("#agent-story .story-day")].map((d: El) => d.textContent), [`Friday, Oct 16${YEAR}`, `Saturday, Oct 17${YEAR}`]);
});

test("H3: every secret card has one h3, its name, with the level tag beside it and not in it", async () => {
  const doc = await page({ ...ONE_DAY, secrets: SECRETS });
  const secretCards = [...doc.querySelectorAll("#agent-secrets .secret-card")] as El[];
  assert.equal(secretCards.length, 2);
  assert.deepEqual(secretCards.map((c) => {
    const h3s = [...c.querySelectorAll("h3")] as El[];
    assert.equal(h3s.length, 1, "one heading a card");
    assert.ok(h3s[0].classList.contains("secret-what"), "the name line is the heading");
    assert.equal(h3s[0].querySelector(".tag"), null, "the level tag is not in the heading");
    assert.equal(h3s[0].parentElement.querySelector(":scope > .tag").textContent, "No AI", "it sits beside it");
    assert.equal(h3s[0].querySelector("div, p"), null, "the heading holds only words and code");
    return said(h3s[0]);
  }), ["STRIPE_KEY in ~/mandu-try/.env", "The file ~/mandu-try/deploy/staging.tfvars"]);
  assert.equal(secretCards[0].querySelector("h3 code").textContent, "STRIPE_KEY", "its name still reads as code");
});

test("H4: the page's heading levels never skip (h1, then h2, then h3)", async () => {
  const doc = await page({ ...ONE_DAY, waiting: AGENT.waiting, secrets: SECRETS });
  const levels = listed(doc).map((h) => Number(h.tagName[1]));
  assert.equal(levels[0], 1, "the page starts with its h1");
  assert.ok(levels.filter((l) => l === 3).length >= 7, "the five turn cards and the two secret cards");
  levels.forEach((l, i) => {
    if (i) assert.ok(l <= levels[i - 1]! + 1, `heading ${i} (h${l}) after h${levels[i - 1]}: no level skipped`);
  });
  // Every h3 sits under an h2: Your secrets', or What happened's.
  for (const h of listed(doc).filter((x) => x.tagName === "H3" && (x.matches(".turn-title, .secret-what")))) {
    const section = h.closest("section.block");
    assert.ok(section && section.querySelector(":scope h2"), `"${said(h)}" under its section's h2`);
  }
});

// ── The look (H5) ───────────────────────────────────────────────────────────

/** The product page's own styles, as index.html links them, after the
 *  browser's own heading rule (jsdom has none), so a heading not reset
 *  would read large and bold here as it would on screen. */
const UA = "h3 { display: block; font-size: 1.17em; font-weight: bold; }";
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
function styled(doc: El, theme: "light" | "dark"): void {
  let sheet = doc.getElementById("headings-styles");
  if (!sheet) {
    sheet = doc.createElement("style");
    sheet.id = "headings-styles";
    doc.head.append(sheet);
  }
  sheet.textContent = perSelector(resolveCssVars(`${UA}\n${stylesAt(CSS, 1280)}`, theme));
}
const look = (doc: El, e: El) => {
  const cs = doc.defaultView.getComputedStyle(e);
  return { size: cs.fontSize, weight: cs.fontWeight, color: cs.color };
};

test("H5: under the page's styles, light and dark, the h3s look as the lines they replace did, and are not balanced", async () => {
  const doc = await page({ ...ONE_DAY, secrets: SECRETS });
  const head = cards(doc)[1].querySelector(".turn-q");
  const h3 = head.querySelector("h3.turn-title");
  // The line as it was before 2026-10-27, beside it: a div.note in .turn-q.
  const oldNote = doc.createElement("div");
  oldNote.className = "note";
  oldNote.textContent = "You asked";
  head.append(oldNote);
  const secretHead = doc.querySelector("#agent-secrets .secret-head");
  const name = secretHead.querySelector("h3.secret-what");
  const oldName = doc.createElement("div");
  oldName.className = "secret-what";
  oldName.textContent = "STRIPE_KEY in ~/mandu-try/.env";
  secretHead.append(oldName);
  for (const theme of ["light", "dark"] as const) {
    styled(doc, theme);
    const was = look(doc, oldNote);
    assert.equal(was.size, "13px", `${theme}: the line was 13 px`);
    assert.deepEqual(look(doc, h3), was, `${theme}: the turn's heading looks as its line did`);
    assert.deepEqual(look(doc, h3.querySelector(".note")), was, `${theme}: and so do its words`);
    const wasName = look(doc, oldName);
    assert.equal(wasName.weight, "600", `${theme}: the name was 600`);
    assert.deepEqual(look(doc, name), wasName, `${theme}: the secret's heading looks as its name did`);
    // A heading is balanced (app.css, §4.25u); these two are not, so a
    // secret's long name wraps where it did.
    for (const e of [h3, name]) assert.notEqual(doc.defaultView.getComputedStyle(e).getPropertyValue("text-wrap-style"), "balance", `${theme}: ${e.className} keeps its wrap`);
  }
  // The heading rule still balances the page's other headings.
  assert.equal(doc.defaultView.getComputedStyle(doc.querySelector("#agent-story-block h2")).getPropertyValue("text-wrap-style"), "balance");
});

test("H6: with 'Only where Mandu stepped in' on, a folded turn's heading is hidden with it", async () => {
  const doc = await page(ONE_DAY);
  const turnHeads = () => listed(doc).filter((h) => h.matches(".turn-title")).map(said);
  assert.equal(turnHeads().length, 5, "off: every turn");
  doc.getElementById("agent-only").click();
  assert.equal(doc.getElementById("agent-only").getAttribute("aria-checked"), "true");
  assert.deepEqual(turnHeads(), ["You asked at 10:24", "A message you wrote at 11:00"], "on: the turns where Mandu stepped in");
  const folded = cards(doc).find((c) => c.dataset.turnId === "t:sh");
  assert.ok(folded.querySelector("h3").closest("[hidden]"), "the quiet turn's heading is folded with it");
});
