/**
 * home-js-agent-tiles-go.test — dashboard.md §4.25 *A tile takes you to
 * what it counts*. A session's page opens with count tiles ("3 actions
 * blocked", "1 send with a real value filled in", "1 waiting for you")
 * whose tooltips said "What happened, below, shows it": on a long story
 * the reader then hunted for the one row among the turns. Now:
 *
 *   G1  the blocked, sent and waiting tiles are buttons only when their
 *       count is non-zero (with steps to go to); at 0, or for the secrets'
 *       tiles, a plain tile;
 *   G2  a press goes to the first such step: opened, marked (`.shown`),
 *       focused; the next press the next ("Showing 2 of 3"), after the last
 *       the first again; the sent tile alike;
 *   G3  "waiting for you" focuses the first card in Needs your OK;
 *   G4  a counted step in a turn before those drawn: the press asks for
 *       every turn (`turns=all`, the Show them read) and lands on it; past
 *       what the page can show, it never lands on nothing;
 *   G5  a poll redraw keeps where the tile is (the next press goes on from
 *       there), the mark, the focus and the story's toggles.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, ASK, T, home, load, tick } from "./home-js-fixtures.js";

const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
const step = (id: string, outcome = "plain") => ({ kind: "action", id, ts: "2026-09-25T10:00:01.000Z", icon: "run", sentence: [T(`Ran ${id}`)], outcome, note: null, split: null });
const turn = (id: string, steps: unknown[], tone = "plain") => ({
  ...AGENT.story[1], id, prompt: `Question ${id}`, routine: null, reply: null, moreSteps: 0, promptNote: null,
  summary: tone === "plain" ? "Nothing here needed guarding." : `Mandu did ${tone}.`, summaryParts: null, tone, steps,
});
/** Eight plain steps: the turn folds some behind "Show N more steps". */
const plain8 = (id: string) => Array.from({ length: 8 }, (_, i) => step(`${id}-p${i}`));
const STORY = [
  turn("t:a", [step("a1"), step("b1", "blocked")], "blocked"),
  turn("t:q", plain8("q")),
  turn("t:b", [step("s1", "sent"), step("b2", "blocked"), step("a2")], "blocked"),
  turn("t:c", [step("b3", "blocked")], "blocked"),
];
const PAGE = { ...AGENT, earlier: 0, blocked: 3, sent: 1, waiting: [ASK, { ...ASK, id: "egr-2" }], story: STORY };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const tileOf = (doc: El, goes: string) => [...doc.querySelectorAll("#agent-facts .tile")].find((t: El) => t.dataset.goes === goes) as El;
const tiles = (doc: El) => [...doc.querySelectorAll("#agent-facts .tile")] as El[];
/** A tile's name: its words without the hover word (aria-hidden). */
const nameOf = (t: El) => [...t.childNodes].filter((x: El) => !x.classList?.contains("go")).map((x: El) => x.textContent).join("").trim();
const shown = (doc: El) => [...doc.querySelectorAll("#agent-story .step.shown")].map((x: El) => x.dataset.stepId);
async function poll(doc: El): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("G1: the blocked, sent and waiting tiles are buttons only when their count is non-zero; the others stay plain", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  const all = tiles(doc);
  assert.deepEqual(all.map((t) => [t.tagName, t.dataset.goes ?? null]), [
    ["DIV", null], ["BUTTON", "blocked"], ["BUTTON", "sent"], ["BUTTON", "waiting"],
  ], "the secrets' tile is plain; the three that count steps or asks go to them");
  for (const b of all.slice(1)) {
    assert.equal(b.getAttribute("type"), "button");
    assert.equal(b.querySelector(".go").textContent, "Show", "the hover word");
    assert.equal(b.querySelector(".go").getAttribute("aria-hidden"), "true", "not part of its name");
    assert.equal(b.querySelector("div"), null, "a button holds no div");
  }
  assert.equal(nameOf(tileOf(doc, "blocked")), "3 actions blocked", "its name reads as the tile");
  assert.match(tileOf(doc, "blocked").title, /Press to go to each in turn under What happened\.$/);
  assert.equal(tileOf(doc, "sent").title, "It went to a destination allowed to receive it. Press to go to it under What happened.");
  assert.equal(tileOf(doc, "waiting").title, "Press to go to Needs your OK, below.");

  // Nothing to go to: a plain tile, and no sent or waiting tile at all.
  const zero = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...PAGE, blocked: 0, sent: 0, waiting: [], story: [turn("t:q", plain8("q"))] } } });
  await tick();
  const z = tiles(zero.doc);
  assert.deepEqual(z.map((t) => t.tagName), ["DIV", "DIV"]);
  assert.equal(z[1].textContent, "0 actions blocked");
  assert.equal(z[1].title, "Each is a step Mandu stopped: a command, a file or a send. What happened, below, shows it.", "at 0 the tooltip says what it counts, no press");
  // Counted, but past every turn the page can show (no Show them lifts it)
  // and none drawn: nothing to land on, so no button.
  const past = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...PAGE, blocked: 1, sent: 0, waiting: [], earlier: 4, allTurns: true, story: [turn("t:q", plain8("q"))] } } });
  await tick();
  assert.equal(tiles(past.doc)[1].tagName, "DIV");
});

test("G2: a press goes to the first blocked step, the next press to the next with where it is, and after the last to the first", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  const b = tileOf(doc, "blocked");
  assert.equal(b.querySelector(".at").textContent, "", "no place before a press");
  b.focus();
  b.click();
  assert.equal(doc.activeElement.dataset.stepId, "b1", "the focus is on the first blocked step");
  assert.equal(doc.activeElement.dataset.outcome, "blocked");
  assert.deepEqual(shown(doc), ["b1"], "marked");
  assert.equal(b.querySelector(".at").textContent, "Showing 1 of 3");
  b.click();
  assert.equal(doc.activeElement.dataset.stepId, "b2");
  assert.deepEqual(shown(doc), ["b2"], "one mark at a time");
  assert.equal(b.querySelector(".at").textContent, "Showing 2 of 3");
  assert.equal(nameOf(b), "3 actions blocked Showing 2 of 3", "its name says where it is");
  b.click();
  assert.equal(doc.activeElement.dataset.stepId, "b3");
  assert.equal(b.querySelector(".at").textContent, "Showing 3 of 3");
  b.click();
  assert.equal(doc.activeElement.dataset.stepId, "b1", "after the last, the first");
  assert.equal(b.querySelector(".at").textContent, "Showing 1 of 3");

  // The sent tile: one send, no "1 of 1".
  const s = tileOf(doc, "sent");
  s.click();
  assert.equal(doc.activeElement.dataset.stepId, "s1");
  assert.deepEqual(shown(doc), ["s1"]);
  assert.equal(s.querySelector(".at").textContent, "", "one step: nothing to count");
  assert.equal(b.querySelector(".at").textContent, "Showing 1 of 3", "the blocked tile keeps its own place");

  // Only where Mandu stepped in (#2): a blocked turn never folds, and a
  // press with the switch on still lands.
  doc.getElementById("agent-only").click();
  b.click();
  assert.equal(doc.activeElement.dataset.stepId, "b2");
  assert.equal(doc.activeElement.closest("[hidden]"), null);
});

test("G3: the waiting tile focuses the first card in Needs your OK", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  tileOf(doc, "waiting").click();
  const a = doc.activeElement;
  assert.ok(a.classList.contains("ask"), `a card has the focus: ${a.className}`);
  assert.equal(a.dataset.id, "egr-1", "the first card");
  assert.equal(a.parentElement.id, "agent-waiting");
  assert.equal(a.getAttribute("tabindex"), "-1", "not a Tab stop");
});

test("G4: a blocked step in a turn before those drawn: the press asks for every turn, then lands on it", async () => {
  const older = turn("t:old", [step("b0", "blocked")], "blocked");
  const capped = { ...PAGE, blocked: 4, earlier: 1, story: STORY };
  const all = { ...PAGE, blocked: 4, earlier: 0, allTurns: true, story: [older, ...STORY] };
  const { doc, calls } = load({ url: URL1, routes: { "GET home/agent?session=s1": capped, "GET home/agent?session=s1&turns=all": all } });
  await tick();
  const b = tileOf(doc, "blocked");
  b.focus();
  b.click();
  await tick(40);
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/agent?session=s1&turns=all"), "the Show them read");
  assert.equal(doc.activeElement.dataset.stepId, "b0", "the first blocked step, in the turn that was not drawn");
  assert.deepEqual(shown(doc), ["b0"]);
  assert.equal(tileOf(doc, "blocked").querySelector(".at").textContent, "Showing 1 of 4");
  tileOf(doc, "blocked").click();
  assert.equal(doc.activeElement.dataset.stepId, "b1", "then on, with every turn drawn");
  assert.equal(calls.filter((c) => c.url.endsWith("&turns=all")).length, 1, "no second ask");

  // Past what the page can show: the presses go round the steps it has.
  const past = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...capped, earlier: 3, allTurns: true } } });
  await tick();
  const p = tileOf(past.doc, "blocked");
  p.click();
  assert.equal(past.doc.activeElement.dataset.stepId, "b1");
  assert.equal(p.querySelector(".at").textContent, "Showing 1 of 4", "of what the tile counts");
  assert.ok(!past.calls.some((c) => c.url.endsWith("&turns=all")), "nothing to ask for");
});

test("G5: a poll redraw keeps where the tile is, its mark, the focus and the story's toggles", async () => {
  let page: unknown = PAGE;
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": () => page } });
  await tick();
  const q = () => [...doc.querySelectorAll("#agent-story article.turn")].find((t: El) => t.dataset.turnId === "t:q") as El;
  q().querySelector(".steps-toggle").click();
  assert.equal(q().querySelector(".steps-toggle").getAttribute("aria-expanded"), "true");
  tileOf(doc, "blocked").click();
  tileOf(doc, "blocked").click();
  assert.equal(doc.activeElement.dataset.stepId, "b2");
  // The agent did more: a new turn; the page is drawn again.
  page = { ...PAGE, story: [...STORY, turn("t:d", [step("d1")])] };
  const before = tileOf(doc, "blocked");
  await poll(doc);
  assert.notEqual(tileOf(doc, "blocked"), before, "drawn again");
  assert.equal(tileOf(doc, "blocked").querySelector(".at").textContent, "Showing 2 of 3", "the place is kept");
  assert.deepEqual(shown(doc), ["b2"], "the mark is kept");
  assert.equal(doc.activeElement.dataset.stepId, "b2", "the focus is kept, not sent to the top");
  assert.equal(q().querySelector(".steps-toggle").getAttribute("aria-expanded"), "true", "the fold you opened stays open");
  tileOf(doc, "blocked").click();
  assert.equal(doc.activeElement.dataset.stepId, "b3", "the next press goes on from there");

  // The focus on the tile itself stays there across a redraw.
  tileOf(doc, "blocked").focus();
  page = { ...PAGE, story: [...STORY, turn("t:d", [step("d1")]), turn("t:e", [step("e1")])] };
  await poll(doc);
  assert.equal(doc.activeElement, tileOf(doc, "blocked"));
  // A new visit starts over.
  doc.defaultView.eval(`setPage('home', true)`);
  await tick();
  doc.defaultView.eval(`setPage('agent', true, 's1')`);
  await tick();
  assert.equal(tileOf(doc, "blocked").querySelector(".at").textContent, "");
  tileOf(doc, "blocked").click();
  assert.equal(doc.activeElement.dataset.stepId, "b1");
});

// ── A Home count's link: `?go=` (§4.25 *The counts link where they point*) ──

test("G6: /agents/<id>?go=blocked presses the blocked tile once the page is first drawn, then drops `go` from the address; a poll does not land again", async () => {
  let page: unknown = PAGE;
  const { doc } = load({ url: `${URL1}?go=blocked`, routes: { "GET home/agent?session=s1": () => page } });
  await tick();
  assert.equal(doc.defaultView.location.pathname + doc.defaultView.location.search, "/mandu/agents/s1", "used once: Back and a reload do not jump again");
  assert.equal(doc.activeElement.dataset.stepId, "b1", "the first blocked step has the focus");
  assert.deepEqual(shown(doc), ["b1"], "marked, as the tile's press marks it");
  assert.equal(tileOf(doc, "blocked").querySelector(".at").textContent, "Showing 1 of 3", "the tile says where it is");
  // The person moves on; the agent does more and the page is drawn again: no second landing.
  tileOf(doc, "waiting").click();
  const card = doc.activeElement;
  page = { ...PAGE, story: [...STORY, turn("t:d", [step("d1")])] };
  await poll(doc);
  assert.equal(doc.activeElement.dataset.id, card.dataset.id, "the focus stays where the person put it");
  assert.deepEqual(shown(doc), ["b1"]);

  // `?go=sent` presses the sent tile.
  const sent = load({ url: `${URL1}?go=sent`, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  assert.equal(sent.doc.activeElement.dataset.stepId, "s1");
});

test("G7: ?go=blocked for a step in a turn before those drawn asks for every turn first, as a press does, and lands on it", async () => {
  const older = turn("t:old", [step("b0", "blocked")], "blocked");
  const capped = { ...PAGE, blocked: 4, earlier: 1, story: STORY };
  const all = { ...PAGE, blocked: 4, earlier: 0, allTurns: true, story: [older, ...STORY] };
  const { doc, calls } = load({ url: `${URL1}?go=blocked`, routes: { "GET home/agent?session=s1": capped, "GET home/agent?session=s1&turns=all": all } });
  await tick(60);
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/agent?session=s1&turns=all"), "the Show them read");
  assert.equal(doc.activeElement.dataset.stepId, "b0");
  assert.deepEqual(shown(doc), ["b0"], "marked once: the reads that follow (Home's poll asks for every turn too) do not land again");
});

test("G8: ?go=secrets focuses Your secrets; ?go=nonsense, or a tile with nothing to go to, leaves the page as a plain link opens it", async () => {
  const withSecrets = { ...PAGE, secrets: { mode: "secrets", flagged: false, more: 0, counts: { masked: 0, early: 0 }, secrets: [] } };
  const secrets = load({ url: `${URL1}?go=secrets`, routes: { "GET home/agent?session=s1": withSecrets } });
  await tick();
  const block = secrets.doc.getElementById("agent-secrets-block");
  assert.equal(block.hidden, false);
  assert.equal(secrets.doc.activeElement, block.querySelector("h2"), "Your secrets' heading has the focus");
  assert.equal(secrets.doc.defaultView.location.search, "");

  for (const url of [`${URL1}?go=nonsense`, `${URL1}?go=blocked`]) {
    const story = url.endsWith("nonsense") ? STORY : [turn("t:q", plain8("q"))];
    const { doc } = load({ url, routes: { "GET home/agent?session=s1": { ...PAGE, blocked: url.endsWith("nonsense") ? 3 : 0, story } } });
    await tick();
    assert.equal(doc.activeElement.dataset?.stepId, undefined, `${url}: no step has the focus`);
    assert.deepEqual(shown(doc), [], `${url}: nothing marked`);
    assert.equal(doc.defaultView.location.search, "", `${url}: the address is the page's own`);
  }
});

test("G9: Home's \"1 action blocked\", pressed, opens that session's page at the blocked step", async () => {
  const w = { hours: 24, sessions: 1, counted: 1, masked: 0, secretsMasked: 0, secretsEarly: 0, untrusted: 0, blocked: 3, sent: 0, waiting: 0, only: { secretsMasked: null, secretsEarly: null, blocked: "s1", sent: null } };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/", routes: { "GET home": home({ verdict: "secrets-only", headline: "Your secrets are guarded.", waiting: [], window: w }), "GET home/agent?session=s1": PAGE } });
  await tick();
  const a = [...doc.querySelectorAll("#hero-facts a")].find((x: El) => /actions blocked/.test(x.textContent)) as El;
  a.click();
  await tick(40);
  assert.equal(doc.defaultView.location.pathname + doc.defaultView.location.search, "/mandu/agents/s1");
  assert.equal(doc.activeElement.dataset.stepId, "b1");
  assert.deepEqual(shown(doc), ["b1"]);
  // The session again by a plain link: a new visit, no landing.
  doc.defaultView.eval(`setPage('agent', true, 's1')`);
  await tick();
  assert.deepEqual(shown(doc), []);
});
