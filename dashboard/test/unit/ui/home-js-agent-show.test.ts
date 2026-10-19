/**
 * home-js-agent-show.test — dashboard.md §4.25ad: the agent page shows what
 * it leaves out, in place. Each line under a capped list (earlier turns,
 * the steps past a turn's cap, the secrets past Your secrets' cap) has a
 * "Show them" that reads the page again asking for them (`turns=all`,
 * `steps=<turn id>`, `secrets=all`), and the first thing it brought takes
 * the focus, unfolded if a fold held it. The polls of that visit keep asking;
 * a new visit asks for the caps again. A list the page already asked for
 * says the rest is past what it shows, with no button.
 *
 * In both builds: with the developer view the line also names the detailed
 * trace (a link); without it, no word on the page points there.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, T, load, tick } from "./home-js-fixtures.js";

const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
const step = (id: string, over: Record<string, unknown> = {}) => ({ kind: "action", id, ts: "2026-09-25T10:00:01.000Z", icon: "run", sentence: [T(`Ran ${id}`)], outcome: "plain", note: null, split: null, ...over });
const turn = (id: string, steps: unknown[], over: Record<string, unknown> = {}) => ({ ...AGENT.story[1], id, prompt: `Question ${id}`, routine: null, reply: null, steps, moreSteps: 0, ...over });
const card = (name: string) => ({ what: [T("The environment variable "), { kind: "code", text: name }], level: "No AI", saw: "masked", lines: [{ tone: "good", parts: [T("The AI got only a placeholder, never the real value.")] }] });
const secrets = (cards: unknown[], more: number) => ({ mode: "secrets", flagged: false, more, counts: { masked: cards.length + more, early: 0 }, secrets: cards });

/** The page as first read: 2 earlier turns, a turn with 3 more steps, 1
 *  more secret. */
const CAPPED = {
  ...AGENT, waiting: [], earlier: 2,
  story: [turn("turn:x", [step("a0")], { moreSteps: 3, moreFrom: "b0" })],
  secrets: secrets([card("A")], 1),
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function poll(doc: any): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}
/** The words a reader can reach: no hidden element's ([hidden] hides a
 *  subtree, mandu.css). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function shownText(x: any): string {
  const copy = x.cloneNode(true);
  for (const h of copy.querySelectorAll("[hidden]")) h.remove();
  return copy.textContent;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const lines = (doc: any, host: string) => [...doc.querySelectorAll(`${host} .story-more`)] as any[];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const showIn = (line: any) => line.querySelector("button.show-rest");

test("earlier turns: Show them asks for every turn; the oldest turn takes the focus; the polls keep asking", async () => {
  const all = { ...CAPPED, earlier: 0, allTurns: true, story: [turn("turn:o1", [step("o")]), turn("turn:o2", [step("p")]), ...CAPPED.story] };
  const { doc, calls, window } = load({ url: URL1, routes: { "GET home/agent?session=s1": CAPPED, "GET home/agent?session=s1&turns=all": all } });
  await tick();
  const [earlier] = lines(doc, "#agent-story");
  assert.equal(earlier.textContent, "2 earlier turns are not shown here. The detailed trace has them. Show them");
  const btn = showIn(earlier);
  assert.equal(btn.getAttribute("aria-describedby") && doc.getElementById(btn.getAttribute("aria-describedby")).textContent, "2 earlier turns are not shown here.", "the button is described by its line");
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "pressed once");
  await tick();
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/agent?session=s1&turns=all"));
  const turns = [...doc.querySelectorAll("#agent-story article.turn")] as any[];
  assert.deepEqual(turns.map((t) => t.dataset.turnId), ["turn:o1", "turn:o2", "turn:x"]);
  assert.equal(doc.activeElement, turns[0], "the first turn it brought");
  assert.equal(turns[0].getAttribute("tabindex"), "-1", "a card, not a Tab stop");
  assert.ok(!lines(doc, "#agent-story").some((l) => /earlier turn/.test(l.textContent)), "the line goes");

  // The next poll asks the same, and the focus stays; another visit of the
  // page asks for the caps again.
  const agentReads = () => calls.filter((c) => c.url.startsWith("/mandu/api/home/agent?")).map((c) => c.url);
  const before = agentReads().length;
  await poll(doc);
  assert.ok(agentReads().length > before, "the poll read the page");
  assert.equal(agentReads().at(-1), "/mandu/api/home/agent?session=s1&turns=all");
  assert.equal(doc.activeElement, doc.querySelector("#agent-story article.turn"));
  (doc.querySelector('#nav a[data-page-link="home"]') as any).click();
  await tick();
  (doc.querySelector('#home-agents a[data-page-link="agent"]') as any).click();
  await tick();
  assert.equal(window.location.pathname, "/mandu/agents/s1");
  assert.equal(agentReads().at(-1), "/mandu/api/home/agent?session=s1");
  assert.equal(lines(doc, "#agent-story")[0].textContent, "2 earlier turns are not shown here. The detailed trace has them. Show them");
});

test("a turn's more steps: Show them asks for that turn's every step; the first of them is unfolded and takes the focus", async () => {
  // Six steps in sight, then a run of plain ones that fold: b0 is in it.
  const shown = Array.from({ length: 6 }, (_, i) => step(`a${i}`));
  const capped = { ...CAPPED, earlier: 0, secrets: secrets([], 0), story: [turn("turn:x y", shown, { moreSteps: 3, moreFrom: "b0" })] };
  const lifted = { ...capped, story: [turn("turn:x y", [...shown, step("b0"), step("b1"), step("b2")], { allSteps: true })] };
  const { doc, calls } = load({ url: URL1, routes: { "GET home/agent?session=s1": capped, "GET home/agent?session=s1&steps=turn%3Ax%20y": lifted } });
  await tick();
  const [more] = lines(doc, "#agent-story");
  assert.equal(more.textContent, "3 more steps are not shown here. The detailed trace has them. Show them");
  assert.equal(more.querySelector("a").getAttribute("href"), "/mandu/dev/sessions/s1?step=b0", "the trace at the first of them");
  showIn(more).click();
  await tick();
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/agent?session=s1&steps=turn%3Ax%20y"));
  const b0 = doc.querySelector('#agent-story [data-step-id="b0"]');
  assert.ok(b0);
  assert.equal(b0.closest(".steps-more").hidden, false, "its fold opened");
  assert.equal(doc.activeElement, b0);
  assert.equal(lines(doc, "#agent-story").length, 0);
});

test("more secrets: Show them asks for every secret; the first new card takes the focus", async () => {
  const all = { ...CAPPED, earlier: 0, story: [], allSecrets: true, secrets: secrets([card("A"), card("B")], 0) };
  const { doc, calls } = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...CAPPED, earlier: 0, story: [] }, "GET home/agent?session=s1&secrets=all": all } });
  await tick();
  const [more] = lines(doc, "#agent-secrets");
  assert.equal(more.textContent, "1 more secret is not shown here. The detailed trace has it. Show it");
  showIn(more).click();
  await tick();
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/agent?session=s1&secrets=all"));
  const cards = [...doc.querySelectorAll("#agent-secrets .secret-card")] as any[];
  assert.equal(cards.length, 2);
  assert.equal(doc.activeElement, cards[1]);
});

test("asked for already: the rest is past what the page shows, and no button", async () => {
  const past = {
    ...CAPPED, earlier: 3, allTurns: true, allSecrets: true,
    story: [turn("turn:x", [step("a0")], { moreSteps: 4, moreFrom: "b0", allSteps: true })],
    secrets: secrets([card("A")], 2),
  };
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": past }, extensions: "" });
  await tick();
  assert.deepEqual([...lines(doc, "#agent-story"), ...lines(doc, "#agent-secrets")].map((l) => l.textContent), [
    "3 earlier turns are past what this page shows.",
    "4 more steps are past what this page shows.",
    "2 more secrets are past what this page shows.",
  ]);
  assert.equal(doc.querySelector("#page-agent button.show-rest"), null);
});

test("without the developer view: each line has its Show them and names no trace; no word on the agent page points there", async () => {
  const agent = {
    ...CAPPED, holds: false, violations: 1,
    story: [turn("turn:x", [
      step("u1", { outcome: "unmasked", note: "This reached the AI without a mask." }),
      step("h1", { outcome: "masked", split: { ai: [T("Got "), { kind: "masked", text: "masked" }, T(".")], real: [T("The real result:")], hidden: { text: null, secret: false, truncated: false } } }),
    ], { moreSteps: 3, moreFrom: "b0", routine: { count: 2, hosts: [] } })],
  };
  const bare = load({ url: URL1, routes: { "GET home/agent?session=s1": agent }, extensions: "" });
  await tick();
  const doc = bare.doc;
  assert.deepEqual([...lines(doc, "#agent-story"), ...lines(doc, "#agent-secrets")].map((l) => l.textContent), [
    "2 earlier turns are not shown here. Show them",
    "3 more steps are not shown here. Show them",
    "1 more secret is not shown here. Show it",
  ]);
  assert.equal(doc.querySelector("#agent-facts .tile.bad .lbl").textContent, "reached the AI unmasked.");
  assert.equal(doc.querySelector('#agent-story [data-step-id="h1"] .hidden-note').textContent, "The original was not recorded here.");
  assert.equal(doc.querySelector("#agent-story .routine").title, "Steps that needed nothing from you.");
  assert.doesNotMatch(shownText(doc.getElementById("page-agent")), /detailed trace|developer view/i);
  // A moment the page could not find: said, with nowhere to send you.
  const ask = "egr-7";
  const lost = load({ url: `${URL1}?ask=${ask}`, routes: { [`GET home/agent?session=s1&ask=${ask}`]: { ...AGENT, focus: { ask, turnId: null, stepId: null, match: null } } }, extensions: "" });
  await tick();
  assert.equal(lost.doc.querySelector(".focus-note.missing").textContent, "Mandu could not find the moment it asked in this session.");
});
