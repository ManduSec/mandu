/**
 * home-js-reveal-names.test — every "Show the real value" on the agent page
 * says which secret it shows, and so does its "Hide it again"
 * (public/js/home.js `secretValueBox`, `renderAgentSecrets`, `hiddenNode`;
 * dashboard.md §4.25b *Show the real value names its secret*).
 *
 * The agent page draws the button on each Your secrets card and on each
 * masked step whose result held a secret. Until 2026-10-12 a button was
 * named by its secret only when one step held several; a session that
 * read two secret files drew four buttons named "Show the real value", and
 * a pressed one read "Hide it again" with no word of whose value it shows.
 * Now each is named by the words the page draws for its secret, its own
 * words first (WCAG 2.5.3), as the rows' controls are (`rowControlName`):
 *
 *   - a Your secrets card's by the card's heading ("The file ~/ws/.env");
 *   - a step that held one secret by its name (".env");
 *   - a step that held several keeps its visible "Show the real value of
 *     NAME", and its "Hide it again" is named by NAME;
 *   - a secret with no name keeps the bare words, as before;
 *   - never by the value; the visible words, the box's group name, what is
 *     posted and the value as text are as before.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter, proxy and dashboard,
 * tests/stack/reveal-names.test.ts. Axes: none (display only). Mandu-new
 * test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, M, T, load, tick } from "./home-js-fixtures.js";

const PAGE = "http://127.0.0.1:4500/mandu/agents/s1";
const SHOW = "Show the real value";
const HIDE = "Hide it again";
const VALUES: Record<string, string> = {
  "aaaaaaaaaaaaaaaaaaaaaaa1": "sk-env-VALUE-one",
  "aaaaaaaaaaaaaaaaaaaaaaa2": "pw-creds-VALUE-two",
  "bbbbbbbbbbbbbbbbbbbbbbb1": "sk-card-env",
  "bbbbbbbbbbbbbbbbbbbbbbb2": "pw-card-creds",
  "ccccccccccccccccccccccc1": "sk-api-key",
  "ccccccccccccccccccccccc2": "pw-db",
  "ddddddddddddddddddddddd1": "nameless-value",
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const code = (text: string) => ({ kind: "code", text });
const secretStep = (id: string, file: string, secrets: Array<{ ref: string; name: string | null }>) => ({
  kind: "action", id, ts: "2026-09-25T10:00:02.000Z", icon: "file", sentence: [T("Read "), code(file)], outcome: "secret", note: null,
  split: { ai: [T("Got "), M("secret"), T(" in place of the result.")], real: [T("The result held your secret "), code(file), T(".")],
    hidden: { text: null, secret: true, truncated: false, secrets } },
});
const card = (what: unknown[], ref: string) => ({ what, level: "No AI", saw: "masked", lines: [{ tone: "good", parts: [T("The AI got only a placeholder, never the real value.")] }], ref });
const ENV_CARD = card([T("The file "), code("~/ws/.env")], "bbbbbbbbbbbbbbbbbbbbbbb1");
const CREDS_CARD = card([T("The file "), code("~/ws/creds.json")], "bbbbbbbbbbbbbbbbbbbbbbb2");
const TWO_FILES = [
  secretStep("t1", ".env", [{ ref: "aaaaaaaaaaaaaaaaaaaaaaa1", name: ".env" }]),
  secretStep("t2", "creds.json", [{ ref: "aaaaaaaaaaaaaaaaaaaaaaa2", name: "creds.json" }]),
];

/** The agent page of s1 with these steps in its first turn and these Your
 *  secrets cards. */
function agentPage(steps: unknown[], cards: unknown[]): unknown {
  const page = JSON.parse(JSON.stringify(AGENT));
  page.story = [{ ...page.story[0], steps }];
  page.secrets = { mode: "secrets", flagged: false, more: 0, counts: { masked: cards.length, early: 0 }, secrets: cards };
  return page;
}
function open(steps: unknown[], cards: unknown[]) {
  const posted: Array<{ ref: string }> = [];
  const loaded = load({
    url: PAGE,
    routes: {
      "GET home/agent?session=s1": agentPage(steps, cards),
      "POST home/reveal": (b: { ref: string }) => { posted.push(b); return { status: 200, body: { value: VALUES[b.ref] ?? "unknown" } }; },
    },
  });
  return { ...loaded, posted };
}
const cardButtons = (doc: Doc) => [...doc.querySelectorAll("#agent-secrets .secret-card button.secret-reveal")] as Doc[];
const stepButtons = (doc: Doc) => [...doc.querySelectorAll("#agent-story .step.split button.secret-reveal")] as Doc[];
/** What a screen reader reads for a button: its aria-label, else its words. */
const nameOf = (b: Doc): string => b.getAttribute("aria-label") ?? b.textContent;
/** Every aria-label on the page, and every name a reveal button has. */
const allNames = (doc: Doc): string[] => [
  ...[...doc.querySelectorAll("[aria-label]")].map((x: Doc) => x.getAttribute("aria-label")),
  ...[...doc.querySelectorAll("button.secret-reveal")].map(nameOf),
];

test("two secrets: each card's and each step's Show the real value is named by its secret, its words first; no two share a name", async () => {
  const { doc, err } = open(TWO_FILES, [ENV_CARD, CREDS_CARD]);
  assert.equal(err, null);
  await tick(40);
  const cards = cardButtons(doc);
  const steps = stepButtons(doc);
  assert.equal(cards.length, 2);
  assert.equal(steps.length, 2);
  assert.deepEqual(cards.map(nameOf), [`${SHOW}: The file ~/ws/.env`, `${SHOW}: The file ~/ws/creds.json`]);
  assert.deepEqual(steps.map(nameOf), [`${SHOW}: .env`, `${SHOW}: creds.json`]);
  for (const b of [...cards, ...steps]) {
    assert.equal(b.textContent, SHOW, "the eye still reads the same words");
    assert.equal(b.getAttribute("aria-expanded"), "false");
  }
  const names = [...cards, ...steps].map(nameOf);
  assert.equal(new Set(names).size, names.length, `no two share a name (${JSON.stringify(names)})`);
});

test("Hide it again says whose value it hides; a second click gives the name back; the value lands as text and is never in a name", async () => {
  const { doc, posted } = open(TWO_FILES, [ENV_CARD, CREDS_CARD]);
  await tick(40);
  const creds = cardButtons(doc)[1];
  const box = creds.closest(".secret-card").querySelector("pre.secret-value");
  creds.click();
  await tick(40);
  assert.deepEqual(posted, [{ session: "s1", ref: "bbbbbbbbbbbbbbbbbbbbbbb2" }], "the card's own ref, as before");
  assert.equal(box.hidden, false);
  assert.equal(box.textContent, "pw-card-creds");
  assert.equal(creds.textContent, HIDE);
  assert.equal(nameOf(creds), `${HIDE}: The file ~/ws/creds.json`);
  assert.equal(box.getAttribute("aria-label"), "The real value", "the box keeps its group name");
  assert.equal(nameOf(cardButtons(doc)[0]), `${SHOW}: The file ~/ws/.env`, "the other card is untouched");
  // A step's button too.
  const env = stepButtons(doc)[0];
  env.click();
  await tick(40);
  assert.equal(nameOf(env), `${HIDE}: .env`);
  for (const name of allNames(doc)) {
    for (const value of Object.values(VALUES)) assert.ok(!name.includes(value), `no name carries a value (${name})`);
  }
  creds.click();
  assert.equal(box.hidden, true);
  assert.equal(box.textContent, "", "hidden again, the value leaves the page");
  assert.equal(creds.textContent, SHOW);
  assert.equal(nameOf(creds), `${SHOW}: The file ~/ws/creds.json`);
  assert.equal(creds.getAttribute("aria-expanded"), "false");
});

test("a step that held several secrets keeps its visible names, and each Hide it again is named by its secret", async () => {
  const { doc } = open([secretStep("t1", ".env", [{ ref: "ccccccccccccccccccccccc1", name: "API_KEY" }, { ref: "ccccccccccccccccccccccc2", name: "DB_PASSWORD" }])], []);
  await tick(40);
  const [api, db] = stepButtons(doc);
  assert.equal(api.textContent, `${SHOW} of API_KEY`);
  assert.equal(api.getAttribute("aria-label"), null, "its words already say the secret");
  assert.equal(db.textContent, `${SHOW} of DB_PASSWORD`);
  db.click();
  await tick(40);
  assert.equal(db.textContent, HIDE);
  assert.equal(nameOf(db), `${HIDE}: DB_PASSWORD`);
  assert.equal(nameOf(api), `${SHOW} of API_KEY`);
  assert.equal(db.closest(".secret-value-box").querySelector("pre.secret-value").getAttribute("aria-label"), "The real value of DB_PASSWORD");
  db.click();
  assert.equal(db.textContent, `${SHOW} of DB_PASSWORD`);
  assert.equal(db.getAttribute("aria-label"), null);
});

test("a secret the page has no name for keeps the bare words, shown and hidden (as before)", async () => {
  const { doc } = open([secretStep("t1", ".env", [{ ref: "ddddddddddddddddddddddd1", name: null }])], []);
  await tick(40);
  const [b] = stepButtons(doc);
  assert.equal(b.textContent, SHOW);
  assert.equal(b.getAttribute("aria-label"), null);
  b.click();
  await tick(40);
  assert.equal(b.textContent, HIDE);
  assert.equal(b.getAttribute("aria-label"), null);
});

test("a card heading with markup in it names the button as text, never markup", async () => {
  const { doc } = open([], [card([T("The file "), code("~/ws/<b>x</b>.env")], "bbbbbbbbbbbbbbbbbbbbbbb1")]);
  await tick(40);
  const [b] = cardButtons(doc);
  assert.equal(nameOf(b), `${SHOW}: The file ~/ws/<b>x</b>.env`);
  assert.equal(doc.querySelector("#agent-secrets b"), null);
});
