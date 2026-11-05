/**
 * home-js-count-meanings.test — dashboard.md §4.25 *What the counts mean*.
 * Home's counts and a session page's tiles said what they count only in a
 * `title`: a tooltip a mouse shows and nothing else, never on a phone nor
 * from the keyboard. Only the masked count had a "?". Now:
 *
 *   C1  on Home, each count other than masked (read before it was marked,
 *       blocked, sent, a session with protection off) has its own "?"
 *       after its link, never inside it, kept with it in one span: a real
 *       button that opens its meaning and closes with Escape; the masked
 *       count keeps its one help; "waiting for you" gets none;
 *   C2  under a session's tiles, *What the counts mean* (closed) lists a
 *       term and meaning for each tile drawn, a blocked tile at 0 too, and
 *       no "Press to go"; a tile not drawn is not listed;
 *   C3  one list of meanings: a fold entry is its tile's tooltip less the
 *       press sentence, and a Home "?" note is the tooltip's meaning;
 *   C4  printing opens the fold, and afterprint folds it again; a page not
 *       found hides it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, T, home, load, tick } from "./home-js-fixtures.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
const owners = { secretsMasked: "s1", secretsEarly: "s1", blocked: "s1", sent: "s1", off: "s2" };
const WINDOW = { hours: 24, sessions: 2, counted: 2, masked: 2, secretsMasked: 2, secretsEarly: 1, untrusted: 0, blocked: 3, sent: 1, off: 1, waiting: 1, only: owners };
const HOME = home({ verdict: "secrets-only", headline: "Your secrets are guarded.", sentence: "No agent is running right now.", protection: { level: "secrets", configured: "secrets", connected: true }, ruleChangesWaiting: 0, waiting: [], window: WINDOW });

const factOf = (doc: El, re: RegExp): El => [...doc.getElementById("hero-facts").children].find((f: El) => re.test((f.querySelector("a") ?? f).textContent));

test("C1: on Home each count but masked has its own \"?\" after its link: it opens its meaning, Escape closes it; the masked count keeps its one", async () => {
  const { doc, err } = load({ homeVm: { ...HOME, verdict: "failed", headline: "Protection failed.", sentence: "One item reached the AI unmasked.", waiting: [] } });
  assert.equal(err, null);
  await tick();
  const facts = doc.getElementById("hero-facts");
  const helps = [...facts.querySelectorAll(".help-btn")].map((b: El) => b.getAttribute("aria-label"));
  assert.deepEqual(helps, ["What protection off means", "What masked means", "What read before it was marked means", "What blocked means", "What a send with a real value means"],
    "one \"?\" per count, the masked count's own first among the secrets");
  const waiting = factOf(doc, /waiting for you/);
  assert.ok(waiting, "the waiting count is drawn");
  assert.equal(waiting.querySelector(".help-btn"), null, "\"waiting for you\" needs none");

  const cases: [RegExp, string][] = [
    [/^1 session ran with protection off$/, "Mandu only watched in it: nothing was masked or blocked."],
    [/^1 secret the AI read before it was marked a secret$/, "The AI read the real value as it was, before it was marked a secret."],
    [/^3 actions blocked$/, "Each is a step Mandu stopped: a command, a file or a send."],
    [/^1 send with a real value filled in$/, "It went to a destination allowed to receive it."],
  ];
  for (const [re, means] of cases) {
    const fact = factOf(doc, re);
    assert.ok(fact, `the count ${re}`);
    const link = fact.querySelector("a");
    const btn = fact.querySelector(".help-btn");
    assert.equal(link.querySelector("button"), null, "the \"?\" is never inside the link");
    assert.equal(btn.closest("a"), null);
    assert.ok(link.compareDocumentPosition(btn) & doc.defaultView.Node.DOCUMENT_POSITION_FOLLOWING, "it comes after the link");
    assert.equal(btn.parentElement.parentElement, fact, "count and \"?\" in one span: never a \"?\" alone at a row's start");
    assert.equal(btn.tagName, "BUTTON");
    assert.equal(btn.getAttribute("type"), "button");
    assert.equal(btn.getAttribute("aria-expanded"), "false");
    const pop = doc.getElementById(btn.getAttribute("aria-controls"));
    assert.equal(pop.hidden, true, "closed until pressed");
    btn.click();
    assert.equal(btn.getAttribute("aria-expanded"), "true");
    assert.equal(pop.hidden, false);
    assert.equal(pop.textContent, means, "it says what the count means");
    btn.focus();
    btn.dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    assert.equal(btn.getAttribute("aria-expanded"), "false", "Escape closes it");
    assert.equal(pop.hidden, true);
    assert.equal(doc.activeElement, btn, "and the focus stays on the \"?\"");
    // C3: the note is the tooltip's meaning (the link's title adds where it
    // goes). The blocked count's tooltip only ever said where it goes, and
    // stays so (the tooltips stay as they are).
    if (/blocked/.test(re.source)) assert.equal(link.title, "Opens the session where it happened.");
    else assert.ok(link.title.startsWith(means + " Opens "), `the tooltip says the same: ${link.title}`);
  }

  // The masked count keeps its one help, What masked means.
  const masked = factOf(doc, /secrets masked before the AI saw them/);
  assert.deepEqual([...masked.querySelectorAll(".help-btn")].map((b: El) => b.getAttribute("aria-label")), ["What masked means"]);
});

test("C1: one count alone keeps its \"?\" with it; a window with only masked secrets draws the masked one only", async () => {
  const solo = load({ homeVm: { ...HOME, window: { ...WINDOW, secretsMasked: 0, masked: 0, secretsEarly: 0, blocked: 0, off: 0, sent: 2, waiting: 0 } } });
  await tick();
  const facts = solo.doc.getElementById("hero-facts");
  assert.equal(facts.children.length, 1);
  assert.match(facts.children[0].textContent, /^In the last 24 hours: 2 sends with a real value filled in \?Each went to a destination allowed to receive it\.$/);
  const masked = load({ homeVm: { ...HOME, window: { ...WINDOW, secretsEarly: 0, blocked: 0, off: 0, sent: 0, waiting: 0 } } });
  await tick();
  assert.deepEqual([...masked.doc.querySelectorAll("#hero-facts .help-btn")].map((b: El) => b.getAttribute("aria-label")), ["What masked means"]);
});

const sentStep = { kind: "action", id: "s1", ts: "2026-09-25T10:00:05.000Z", icon: "web", sentence: [T("Sent to "), { kind: "code", text: "api.example" }], outcome: "sent", note: null, split: null };
const SECRETS = (masked: number, early = 0) => ({ mode: "secrets", flagged: false, more: 0, counts: { masked, early }, secrets: [] });
const PAGE = {
  ...AGENT, earlier: 0, blocked: 0, sent: 1, waiting: [], secrets: SECRETS(2),
  story: [{ ...AGENT.story[0], steps: [...AGENT.story[0].steps.filter((s) => s.outcome !== "blocked"), sentStep] }, AGENT.story[1]],
};
const fold = (doc: El) => doc.getElementById("agent-count-meanings");
const entries = (doc: El) => {
  const dts = [...fold(doc).querySelectorAll("dt")].map((d: El) => d.textContent);
  const dds = [...fold(doc).querySelectorAll("dd")].map((d: El) => d.textContent);
  return dts.map((t, i) => [t, dds[i]]);
};
const tileTitles = (doc: El) => [...doc.querySelectorAll("#agent-facts .tile")].map((t: El) => t.title).filter(Boolean);

test("C2, C3: under a session's tiles, What the counts mean lists each tile drawn (blocked at 0 too) with its tooltip less the press; closed", async () => {
  const { doc, err } = load({ url: URL1, routes: { "GET home/agent?session=s1": PAGE } });
  assert.equal(err, null);
  await tick();
  const f = fold(doc);
  assert.equal(f.tagName, "DETAILS");
  assert.equal(f.hidden, false);
  assert.equal(f.open, false, "closed by default: one line");
  assert.equal(f.querySelector("summary").textContent, "What the counts mean");
  assert.equal(f.parentElement, doc.getElementById("agent-facts").parentElement, "under the tiles, not among them");
  assert.equal(doc.getElementById("agent-facts").nextElementSibling, f);
  assert.deepEqual(entries(doc), [
    ["Secrets masked before the AI saw them", "The AI got only the masked version of each, from the first time it could see it. Your secrets, below, names them."],
    ["Actions blocked", "Each is a step Mandu stopped: a command, a file or a send. What happened, below, shows it."],
    ["Sends with a real value filled in", "It went to a destination allowed to receive it."],
  ]);
  assert.doesNotMatch(f.textContent, /Press/, "never the press: the fold is no button");
  // C3: each entry is its tile's tooltip, less the "Press …" sentence.
  assert.deepEqual(tileTitles(doc).map((t: string) => t.replace(/ Press .*$/, "")), entries(doc).map(([, says]) => says));
  assert.match(doc.querySelector('#agent-facts .tile[data-goes="sent"]').title, / Press to go to it under What happened\.$/, "the sent tile is a button, its tooltip keeps the press");
});

test("C2: a tile not drawn is not listed; the read-before-marked tile is; a waiting tile adds nothing", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...PAGE, sent: 0, blocked: 2, secrets: SECRETS(1, 1), waiting: [{ id: "egr-9" }], story: AGENT.story } } });
  await tick();
  assert.deepEqual(entries(doc).map(([t]) => t), ["Secrets masked before the AI saw them", "Secrets the AI read before they were marked secrets", "Actions blocked"]);
  assert.doesNotMatch(fold(doc).textContent, /Sends with a real value|waiting/i, "no sent entry without a sent tile");
  assert.equal(entries(doc)[1][1], "The AI read the real value as it was, before it was marked a secret. Your secrets, below, says when.");
  assert.equal(entries(doc)[2][1], "Each is a step Mandu stopped: a command, a file or a send.", "a blocked tile that is a button: its meaning, no press");
});

test("C4: printing opens the fold and afterprint folds it again; one you opened stays open; a page not found hides it", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  const print = (kind: string) => doc.defaultView.dispatchEvent(new doc.defaultView.Event(kind));
  print("beforeprint");
  assert.equal(fold(doc).open, true, "printed open");
  print("afterprint");
  assert.equal(fold(doc).open, false, "and folded again after");
  fold(doc).open = true;
  print("beforeprint");
  print("afterprint");
  assert.equal(fold(doc).open, true, "one you opened stays open");

  const gone = load({ url: URL1, routes: { "GET home/agent?session=s1": { found: false } } });
  await tick();
  assert.equal(fold(gone.doc).hidden, true, "no tiles, no fold");
});
