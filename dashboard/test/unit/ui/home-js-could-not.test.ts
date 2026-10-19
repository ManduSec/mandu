/**
 * home-js-could-not.test — the PRODUCT page's could-not lines name the cause
 * the page knows (public/js/home.js; dashboard.md §4.25 *Empty states*, *A
 * could-not line names the cause the page knows*).
 *
 * Until 2026-10-10 every list that could not be read guessed one cause, "The
 * protection service may be unreachable.", also with the dashboard server
 * itself gone, under a hero that said so; Rules then offered "You can still
 * add a rule", whose file browser opened empty over an unhandled `fetch
 * failed`. Now:
 *
 * - Rules › Your rules and Settings › Models say the cause their read tells:
 *   the service not running (with the link to its Start), the status the
 *   dashboard server answered with, or no answer at all. A panel that
 *   answered `available: false` takes the cause of the latest Home poll
 *   when that one knows the service is not running or the dashboard is
 *   gone, and keeps the hedge otherwise; a Home poll that ends after their
 *   read draws the line again, only when the cause changed.
 * - With no answer, Your rules offers no "add a rule", and the file
 *   browser, opened from Add a rule, says so in its note.
 * - "Show in policy.yaml" says the cause in the page's words, never the
 *   server's own error.
 * - A control read with no answer (`apiGetControl`, status 0) is worded by
 *   refusalText, as Settings › Sensitivity labels shows.
 * - When the service comes back (a Home poll answers after one that failed),
 *   Rules and Settings read again what they could not read: Your rules,
 *   Settings › Protection, Models, Sensitivity labels and Prompt filters,
 *   only those, once, and never draw the hedge on the way (*What could not
 *   be read is read again when the service comes back*).
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts);
 * across the real arbiter and dashboard, tests/stack/
 * product-could-not-check-words.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, rulesPage, treeRow, opened, FILES_ROUTES, list, RULES_PANEL } from "./home-js-fixtures.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import { labelSettingsVM } from "../../../src/view-model/sensitivity-labels.js";
import { promptSettingsVM } from "../../../src/view-model/prompt-settings.js";

const DOWN = { status: 503, body: { error: "the arbiter is not reachable", tenant: "live", unreachable: true } };
/** What /api/policy/panel answers with no protection service behind it. */
const UNREAD_PANEL = { panel: toPolicyPanelViewModel(null) };
const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const RULES_URL = "http://127.0.0.1:4500/mandu/rules";
const noAnswer = () => { throw new TypeError("Failed to fetch"); };

const WORDS = {
  downLinked: "The protection service is not running. Start it under Settings, or try again in a moment.",
  gone: "The dashboard could not reach its own server. Refresh in a moment.",
  error: (n: number) => `The dashboard server answered with an error (${n}). Refresh in a moment.`,
  hedge: "The protection service may be unreachable.",
};
const START = [["Start it under Settings", "/mandu/settings", "settings"]];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const links = (node: any) => [...node.querySelectorAll("a")].map((a: any) => [a.textContent, a.getAttribute("href"), a.dataset.pageLink]);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const buttons = (node: any) => [...node.querySelectorAll("button")].map((b: any) => b.textContent);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const yourRules = (doc: any) => doc.querySelector("#files-tree .empty-row");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };

test("Rules › Your rules says the cause its read tells: the service not running (linked), an error with its status, or no answer (and then no add)", async () => {
  // The panel answered `available: false` while Home knows the service is down.
  const down = load({ url: RULES_URL, routes: { "GET home": DOWN, "GET policy/panel": UNREAD_PANEL, "GET secrets": { panel: { labels: [] } } } });
  await tick();
  assert.equal(yourRules(down.doc).textContent, `Your rules could not be read. ${WORDS.downLinked} You can still add a rule.`);
  assert.deepEqual(links(yourRules(down.doc)), START);
  assert.deepEqual(buttons(yourRules(down.doc)), ["add a rule"], "the file browser works without the service");
  assert.equal(down.doc.getElementById("rules-list").hidden, true, "said once for all of Your rules");

  // The read itself answered an error: its status, and add a rule stays.
  const failed = rulesPage({ "GET policy/panel": { status: 500, body: null } });
  await tick();
  assert.equal(yourRules(failed.doc).textContent, `Your rules could not be read. ${WORDS.error(500)} You can still add a rule.`);
  assert.deepEqual(links(yourRules(failed.doc)), []);

  // No answer: the dashboard is gone, so nothing that needs it is offered.
  const gone = rulesPage({ "GET policy/panel": noAnswer });
  await tick();
  assert.equal(yourRules(gone.doc).textContent, `Your rules could not be read. ${WORDS.gone}`);
  assert.deepEqual(buttons(yourRules(gone.doc)), [], "no add a rule without the dashboard");
  assert.doesNotMatch(gone.doc.getElementById("page-rules").textContent, /may be unreachable|Failed to fetch/);

  // Not known (`available: false` with a good Home, as a dashboard with no
  // service configured answers): the hedge as before.
  const unknown = rulesPage({ "GET policy/panel": UNREAD_PANEL, "GET secrets": { panel: { labels: [] } } });
  await tick();
  assert.equal(yourRules(unknown.doc).textContent, `Your rules could not be read. ${WORDS.hedge} You can still add a rule.`);
});

test("Rules › Your rules follows the Home poll: a cause learned after its read draws the line again, an unchanged one leaves it (and its focus) as it is", async () => {
  let homeDown = false;
  const { doc, calls } = load({ url: RULES_URL, routes: {
    "GET home": () => (homeDown ? DOWN : undefined),
    "GET policy/panel": UNREAD_PANEL, "GET secrets": { panel: { labels: [] } },
  } });
  await tick();
  assert.equal(yourRules(doc).textContent, `Your rules could not be read. ${WORDS.hedge} You can still add a rule.`);
  homeDown = true;
  await poll(doc);
  assert.equal(yourRules(doc).textContent, `Your rules could not be read. ${WORDS.downLinked} You can still add a rule.`);
  // The same cause again: the line is not drawn again, and the focus stays.
  const line = yourRules(doc);
  line.querySelector("button").focus();
  await poll(doc);
  assert.equal(yourRules(doc), line, "not drawn again");
  assert.equal(doc.activeElement?.textContent, "add a rule", "the focus stays");
  // The service answers again: Your rules is read again; this panel still
  // answers `available: false`, so the page does not know why.
  const reads = () => calls.filter((c) => c.url === "/mandu/api/policy/panel").length;
  const before = reads();
  homeDown = false;
  await poll(doc);
  assert.equal(reads(), before + 1, "read again once the service answers");
  assert.equal(yourRules(doc).textContent, `Your rules could not be read. ${WORDS.hedge} You can still add a rule.`);
  await poll(doc);
  assert.equal(reads(), before + 1, "a poll after one that answered reads nothing again");
});

test("Add a rule with no answer: the file browser says the dashboard could not be reached in its note, never an empty panel over an unhandled fetch failure", async () => {
  const unhandled: unknown[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(e);
  process.on("unhandledRejection", onUnhandled);
  try {
    let gone = false;
    const { doc } = load({ url: RULES_URL, storage: { "mandu.files.folder": "/home/u/ws" }, routes: {
      ...FILES_ROUTES,
      [list("/home/u/ws")]: () => (gone ? noAnswer() : FILES_ROUTES[list("/home/u/ws")]),
      [list("~")]: noAnswer,
    } });
    await tick();
    gone = true;
    doc.getElementById("rules-add").click();
    await tick(20);
    assert.equal(doc.getElementById("lock-form").hidden, false, "the panel opens");
    const note = doc.getElementById("files-note");
    assert.equal(note.hidden, false, "its note says why the list is empty");
    assert.equal(note.textContent, WORDS.gone);
    assert.equal(doc.querySelector("#files-list .row.file"), null);
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(unhandled.map(String), [], "no unhandled rejection in the page");
  } finally {
    process.off("unhandledRejection", onUnhandled);
  }
});

test("Settings › Models says the cause its read tells, and follows the Home poll as Rules does", async () => {
  const models = (doc: any) => doc.getElementById("settings-models");
  const lead = "The model list could not be read.";
  // The service's own 503 `unreachable` on the read, and `available: false`
  // while Home knows the service is down: not running, with the link.
  for (const [why, routes] of [
    ["503 unreachable", { "GET policy/panel": DOWN }],
    ["available: false, Home down", { "GET home": DOWN, "GET policy/panel": UNREAD_PANEL }],
  ] as const) {
    const { doc } = load({ url: SETTINGS_URL, routes });
    await tick();
    assert.equal(models(doc).textContent, `${lead} ${WORDS.downLinked}`, why);
    assert.deepEqual(links(models(doc)), START, why);
    assert.equal(doc.getElementById("model-open").hidden, true, `no Add (${why})`);
  }
  const gone = load({ url: SETTINGS_URL, routes: { "GET policy/panel": noAnswer } });
  await tick();
  assert.equal(models(gone.doc).textContent, `${lead} ${WORDS.gone}`);

  // Read before Home knew: the hedge, then the cause once the poll tells it.
  let homeDown = false;
  const { doc } = load({ url: SETTINGS_URL, routes: { "GET home": () => (homeDown ? DOWN : undefined), "GET policy/panel": UNREAD_PANEL } });
  await tick();
  assert.equal(models(doc).textContent, `${lead} ${WORDS.hedge}`);
  homeDown = true;
  await poll(doc);
  assert.equal(models(doc).textContent, `${lead} ${WORDS.downLinked}`);
  const line = models(doc).firstElementChild;
  await poll(doc);
  assert.equal(models(doc).firstElementChild, line, "an unchanged cause is not drawn again");
});

test("Show in policy.yaml that cannot be read says the cause in the page's words, never the server's own error", async () => {
  const ROUTE = "GET policy/rules/source?id=lock%3A**%2Fws-*%2Fmemo%2F**";
  const cases: [string, unknown, string][] = [
    ["the failed dial", { status: 502, body: { error: "connect ENOENT /run/user/1000/mandu/arbiter.sock" } }, WORDS.downLinked],
    ["no answer", noAnswer, WORDS.gone],
    ["no service behind the route", { status: 404, body: { error: "arbiter not connected" } }, "The protection service is not connected."],
    ["another error", { status: 503, body: { error: "admin channel unavailable: connect ECONNREFUSED 127.0.0.1:1 (adopted instance)" } }, WORDS.error(503)],
  ];
  for (const [why, answer, words] of cases) {
    const { doc } = rulesPage({ [ROUTE]: answer });
    await tick();
    treeRow(doc, /ws-\*\/memo/).click();
    const detail = opened(doc);
    ([...detail.querySelectorAll("button")] as any[]).find((b) => b.textContent === "Show in policy.yaml").click();
    await tick();
    const panel = detail.querySelector(".rule-source");
    assert.equal(panel.textContent, `policy.yaml could not be read. ${words}`, why);
    assert.deepEqual(links(panel), words === WORDS.downLinked ? START : [], why);
    assert.doesNotMatch(panel.textContent, /admin channel|ENOENT|arbiter|may be unreachable/, why);
  }
});

test("a control read with no answer says the dashboard could not be reached (Settings › Sensitivity labels)", async () => {
  const { doc } = load({ url: SETTINGS_URL, routes: { "GET policy/sensitivity-labels": noAnswer } });
  await tick();
  assert.equal(doc.getElementById("settings-labels").textContent, WORDS.gone);
});

test("Settings › Protection says the cause its read of config.toml tells: an error with its status, or no answer; the sentence alone when none is known", async () => {
  // Until 2026-10-10 it said "The protection settings could not be read."
  // alone, with the dashboard gone too, under a Models block that said so.
  const lead = "The protection settings could not be read.";
  const protect = (doc: any) => doc.getElementById("settings-protect-text");
  for (const [why, answer, words] of [
    ["an error", { status: 500, body: null }, `${lead} ${WORDS.error(500)}`],
    ["no answer", noAnswer, `${lead} ${WORDS.gone}`],
    // It answered, but with no settings in it: the page knows no cause, and
    // config.toml is the dashboard's own read, so never the service's hedge.
    ["an answer without settings", { ok: false }, lead],
  ] as const) {
    const { doc } = load({ url: SETTINGS_URL, routes: { "GET config/axes": answer } });
    await tick();
    assert.equal(protect(doc).textContent, words, why);
    assert.deepEqual(links(protect(doc)), [], `no link (${why})`);
    assert.equal(doc.getElementById("switch-protection").disabled, true, `the switch is off limits (${why})`);
    assert.equal(doc.querySelector("#settings-protect-row .name").textContent, "Unknown", why);
  }
});

const PROMPT_DIAL = { status: 502, body: { error: "The protection service did not answer." } };
const LABELS_DIAL = { status: 502, body: { error: "the protection service did not answer (connect ENOENT /run/user/1000/mandu/current/arbiter.sock)" } };

test("Settings › Prompt filters with the service stopped says what Models and Sensitivity labels beside it say, with the link; any other refusal keeps its words", async () => {
  // Until 2026-10-10 it said "The protection service did not answer." (its
  // route words the failed dial so) where its two siblings said the service
  // is not running.
  const prompt = (doc: any) => doc.getElementById("settings-prompt-kinds");
  const down = load({ url: SETTINGS_URL, routes: { "GET home": DOWN, "GET policy/panel": UNREAD_PANEL, "GET policy/sensitivity-labels": LABELS_DIAL, "GET policy/prompt-filters": PROMPT_DIAL } });
  await tick();
  assert.equal(down.doc.getElementById("settings-models").textContent, `The model list could not be read. ${WORDS.downLinked}`);
  assert.equal(down.doc.getElementById("settings-labels").textContent, WORDS.downLinked);
  assert.equal(prompt(down.doc).textContent, WORDS.downLinked, "the same words as its siblings");
  assert.deepEqual(links(prompt(down.doc)), START);
  assert.equal(down.doc.getElementById("prompt-exception-form").hidden, true);
  assert.equal(down.doc.getElementById("settings-prompt-exceptions-head").hidden, true, "still its refusal alone");

  // The service answers Home: a 502 is its own (a service that hangs), in its words.
  const hung = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": PROMPT_DIAL } });
  await tick();
  assert.equal(prompt(hung.doc).textContent, "The protection service did not answer.");
  assert.deepEqual(links(prompt(hung.doc)), []);

  // Any other refusal keeps the words it had, the service down or not.
  for (const [why, answer, words] of [
    ["signed out", { status: 403, body: { error: "admin session required: open the dashboard's sign-in link" } }, /^Sign in first: in your own terminal, run mandu dashboard/],
    ["no service behind the route", { status: 404, body: { error: "The protection service is not connected." } }, /^The protection service is not connected\.$/],
    ["no answer", noAnswer, new RegExp(`^${WORDS.gone.replace(/\./g, "\\.")}$`)],
  ] as const) {
    const { doc } = load({ url: SETTINGS_URL, routes: { "GET home": DOWN, "GET policy/prompt-filters": answer } });
    await tick();
    assert.match(prompt(doc).textContent, words, why);
  }
});

test("Settings › Prompt filters follows the Home poll: a stopped service learned after its read draws its line again, an unchanged one leaves it as it is", async () => {
  let homeDown = false;
  const { doc, calls } = load({ url: SETTINGS_URL, routes: {
    "GET home": () => (homeDown ? DOWN : undefined),
    "GET policy/prompt-filters": PROMPT_DIAL,
  } });
  await tick();
  const prompt = () => doc.getElementById("settings-prompt-kinds");
  assert.equal(prompt().textContent, "The protection service did not answer.", "read before Home knew");
  const reads = () => calls.filter((c) => c.url === "/mandu/api/policy/prompt-filters").length;
  const before = reads();
  homeDown = true;
  await poll(doc);
  assert.equal(prompt().textContent, WORDS.downLinked);
  assert.deepEqual(links(prompt()), START);
  assert.equal(reads(), before, "drawn again, not read again");
  const link = prompt().querySelector("a");
  await poll(doc);
  assert.equal(prompt().querySelector("a"), link, "an unchanged cause is not drawn again");
});

// ── When the service comes back (*What could not be read is read again*) ──────

/** What `#id` showed at each change while `fn` ran. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function shown(doc: any, ids: string[], fn: () => Promise<void>): Promise<string[]> {
  const seen: string[] = [];
  const watch = new doc.defaultView.MutationObserver(() => { for (const id of ids) seen.push(doc.getElementById(id).textContent); });
  for (const id of ids) watch.observe(doc.getElementById(id), { childList: true, subtree: true, characterData: true });
  await fn();
  watch.disconnect();
  return seen;
}
const reads = (calls: { url: string }[], route: string) => calls.filter((c) => c.url === `/mandu/api/${route}`).length;

test("the service comes back: Rules reads Your rules again and lists them, never the hedge on the way, and a poll after that reads nothing again", async () => {
  let up = false;
  const { doc, calls } = load({ url: RULES_URL, routes: {
    "GET home": () => (up ? undefined : DOWN),
    "GET policy/panel": () => (up ? RULES_PANEL : UNREAD_PANEL),
    "GET secrets": { panel: { labels: [] } },
  } });
  await tick();
  assert.equal(yourRules(doc).textContent, `Your rules could not be read. ${WORDS.downLinked} You can still add a rule.`);
  const before = reads(calls, "policy/panel");
  up = true;
  const seen = await shown(doc, ["files-tree"], () => poll(doc));
  assert.equal(reads(calls, "policy/panel"), before + 1, "Your rules is read again once");
  assert.equal(yourRules(doc), null, "no could-not line");
  assert.ok(treeRow(doc, /ws-\*\/memo/), "the rule is listed");
  assert.ok(seen.length > 0 && !seen.some((t) => /may be unreachable/.test(t)), `never the hedge on the way: ${JSON.stringify(seen)}`);
  await poll(doc);
  assert.equal(reads(calls, "policy/panel"), before + 1, "a poll after one that answered reads nothing again");
});

const MODELS_PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [], models: [] } };
const LABELS = { labels: labelSettingsVM({ sensitivity_labels: [{ id: "9fbde396-1a24-4c79-8edf-9254a0f35055", name: "Highly Confidential", level: "no-model" }] }, undefined, null) };
const PROMPT = { settings: promptSettingsVM({
  filters: [{ id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] }],
  actions: [{ category: "secret.registered", action: "mask", setBy: "default", locked: false }],
  fallback: "redact", exceptions: [], enforcing: true, editable: true,
}) };
const PROMPT_UNREAD = { settings: { available: false, note: "The protection service did not answer." } };
const SETTINGS_BLOCKS = ["settings-protect-text", "settings-models", "settings-labels", "settings-prompt-kinds"];

test("the service comes back: Settings reads again the blocks that could not be read (Models, Prompt filters), never one that was read (Sensitivity labels, Protection), nor the hedge on the way", async () => {
  let up = false;
  const { doc, calls } = load({ url: SETTINGS_URL, routes: {
    "GET home": () => (up ? undefined : DOWN),
    "GET policy/panel": () => (up ? MODELS_PANEL : UNREAD_PANEL),
    "GET policy/sensitivity-labels": LABELS,
    "GET policy/prompt-filters": () => (up ? PROMPT : PROMPT_UNREAD),
  } });
  await tick();
  assert.equal(doc.getElementById("settings-models").textContent, `The model list could not be read. ${WORDS.downLinked}`);
  assert.equal(doc.getElementById("settings-prompt-kinds").textContent, "The protection service did not answer.");
  assert.match(doc.getElementById("settings-labels").textContent, /Highly Confidential/, "read while the service was down");
  const routes = ["policy/panel", "policy/prompt-filters", "policy/sensitivity-labels", "config/axes"];
  const before = routes.map((r) => reads(calls, r));
  up = true;
  const seen = await shown(doc, SETTINGS_BLOCKS, () => poll(doc));
  assert.deepEqual(routes.map((r) => reads(calls, r)), [before[0]! + 1, before[1]! + 1, before[2], before[3]], "only the unread blocks, once each");
  assert.match(doc.getElementById("settings-models").textContent, /^No models listed\./);
  assert.equal(doc.getElementById("model-open").hidden, false, "Add a model is offered again");
  assert.ok(doc.querySelector('#settings-prompt-kinds .prompt-kind[data-category="secret.registered"]'), "the filters are listed");
  assert.equal(doc.getElementById("settings-prompt-exceptions-head").hidden, false, "with their Exceptions");
  assert.ok(seen.length > 0 && !seen.some((t) => /may be unreachable/.test(t)), `never the hedge on the way: ${JSON.stringify(seen)}`);
  await poll(doc);
  assert.deepEqual(routes.map((r) => reads(calls, r)), [before[0]! + 1, before[1]! + 1, before[2], before[3]], "a poll after one that answered reads nothing again");
});

test("the dashboard comes back: every Settings block that got no answer is read again (Protection, Models, Sensitivity labels, Prompt filters)", async () => {
  let up = false;
  const gone = (answer?: unknown) => () => (up ? answer : noAnswer());
  const { doc, calls } = load({ url: SETTINGS_URL, routes: {
    "GET home": gone(),
    "GET config/axes": gone(),
    "GET policy/panel": gone(MODELS_PANEL),
    "GET policy/sensitivity-labels": gone(LABELS),
    "GET policy/prompt-filters": gone(PROMPT),
  } });
  await tick();
  assert.equal(doc.getElementById("settings-protect-text").textContent, `The protection settings could not be read. ${WORDS.gone}`);
  assert.equal(doc.getElementById("settings-models").textContent, `The model list could not be read. ${WORDS.gone}`);
  assert.equal(doc.getElementById("settings-labels").textContent, WORDS.gone);
  assert.equal(doc.getElementById("settings-prompt-kinds").textContent, WORDS.gone);
  const routes = ["config/axes", "policy/panel", "policy/sensitivity-labels", "policy/prompt-filters"];
  const before = routes.map((r) => reads(calls, r));
  up = true;
  await poll(doc);
  assert.deepEqual(routes.map((r) => reads(calls, r)), before.map((k) => k + 1), "each read again once");
  assert.doesNotMatch(doc.getElementById("settings-protect-text").textContent, /could not be read/);
  assert.equal(doc.getElementById("switch-protection").disabled, false, "the switch works again");
  assert.match(doc.getElementById("settings-models").textContent, /^No models listed\./);
  assert.match(doc.getElementById("settings-labels").textContent, /Highly Confidential/);
  assert.ok(doc.querySelector('#settings-prompt-kinds .prompt-kind[data-category="secret.registered"]'));
  assert.doesNotMatch(doc.getElementById("page-settings").textContent, /could not reach its own server|may be unreachable/);
});

test("off Rules and Settings, a return reads none of their lists", async () => {
  let up = false;
  const { doc, calls } = load({ routes: { "GET home": () => (up ? undefined : DOWN) } });
  await tick();
  const routes = ["policy/panel", "policy/sensitivity-labels", "policy/prompt-filters", "config/axes"];
  const before = routes.map((r) => reads(calls, r));
  up = true;
  await poll(doc);
  assert.deepEqual(routes.map((r) => reads(calls, r)), before);
});
