/**
 * home-js-follows-running.test — the lines that say whether protection runs
 * follow a restart on or off without a reload (public/js/home.js
 * followRunningAnswers; dashboard.md §4.25 *The on/off says what runs*,
 * §4.25y *The answer follows the card*; queue item #294).
 *
 * Until 2026-11-03 Settings › Protection and the line above the rules
 * followed what runs, but the Prompt filters card under it ("Protection is
 * off, so Mandu only notes what it finds"), a drawn Try a message answer
 * ("Mandu would only note these"), an opened file's "What the rules say"
 * and Find a rule's answer ("Protection is off, so none of this is enforced
 * now") kept the on/off of their first read: after a restart to off they
 * still read as enforced. Pins:
 *
 * - Settings: a Home poll whose protection turns on (or off) reads the
 *   Prompt filters card once and asks the drawn Try answer again once; the
 *   off lines go (or come back); a poll with the same on/off reads nothing;
 *   a poll that cannot say ("not connected", mid-restart) reads nothing;
 *   with the focus in the card or an exception being written nothing is
 *   read, and the first poll after reads.
 * - Rules: an opened file's "What the rules say" and a Find a rule answer
 *   are asked again once when what runs changes, and their off line goes;
 *   the hosts typed in the opened row stay; a poll with the same on/off
 *   asks nothing. A restart followed on Settings is still followed on
 *   returning to Rules.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts);
 * across the real server, tests/stack/protection-switch-follows.test.ts.
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, home, FILES_URL, WS_LIST, RULES_PANEL, list, openRow, opened } from "./home-js-fixtures.js";
import { promptSettingsVM, type PromptFiltersProjection } from "../../../src/view-model/prompt-settings.js";

const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const RULES_URL = "http://127.0.0.1:4500/mandu/rules";
const ON = home({ protection: { level: "secrets", configured: "secrets", connected: true } });
const OFF = home({ protection: { level: "off", configured: "off", connected: true } });
const RESTARTING = home({ protection: { level: "unknown", configured: "secrets", connected: false } });

const PROJ = (enforcing: boolean): PromptFiltersProjection => ({
  filters: [{ id: "pii", on: true, categories: [{ category: "pii.email", action: "redact" }] }],
  actions: [{ category: "pii.email", action: "redact", setBy: "you", locked: false }],
  fallback: "redact",
  exceptions: [],
  enforcing,
  editable: true,
});
const OFF_NOTE = "Protection is off, so Mandu only notes what it finds. These choices apply when it is on.";
const TRY_OFF = "Protection is off, so Mandu would only note these.";
const OFF_LINE = "Protection is off, so none of this is enforced now.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };
const count = (calls: { url: string }[], part: string) => calls.filter((c) => c.url.includes(part)).length;
const cardReads = (calls: { url: string }[]) => calls.filter((c) => c.url === "/mandu/api/policy/prompt-filters").length;

/** Settings over a protection service whose on/off is `running.on`: the
 *  card and the try route answer with it. */
function settings(start: "on" | "off") {
  const running = { on: start === "on" };
  const page = load({ url: SETTINGS_URL, homeVm: running.on ? ON : OFF, routes: {
    "GET policy/prompt-filters": () => ({ settings: promptSettingsVM(PROJ(running.on)) }),
    "POST policy/prompt-filters/try": () => ({
      enforcing: running.on, action: running.on ? "rewrite" : "pass",
      findings: [{ start: 5, end: 18, category: "pii.email", name: "An email address", named: false, action: running.on ? "redact" : "log" }],
    }),
  } });
  /** The service restarted on or off: Home and both routes say so. */
  const restart = (on: boolean) => { running.on = on; page.setHome(on ? ON : OFF); };
  return { ...page, restart };
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function tryMessage(page: any, text: string): Promise<void> {
  page.doc.getElementById("prompt-try-text").value = text;
  page.doc.getElementById("prompt-try-form").dispatchEvent(new page.window.Event("submit", { cancelable: true }));
  await tick();
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const offNote = (doc: any) => doc.querySelector("#settings-prompt-kinds .prompt-off")?.textContent ?? null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const tryOff = (doc: any) => doc.querySelector("#prompt-try-answer .prompt-try-off")?.textContent ?? null;

test("F1 Settings: a restart on reads Prompt filters and asks the Try answer again, once; the off lines go; the same on/off reads nothing", async () => {
  const page = settings("off");
  await tick();
  await poll(page.doc);
  await tryMessage(page, "mail ann@corp.test");
  assert.equal(offNote(page.doc), OFF_NOTE);
  assert.equal(tryOff(page.doc), TRY_OFF);
  const reads = cardReads(page.calls);
  const tries = count(page.calls, "/prompt-filters/try");

  await poll(page.doc);
  assert.equal(cardReads(page.calls), reads, "a poll whose on/off is the one drawn reads nothing");
  assert.equal(count(page.calls, "/prompt-filters/try"), tries);

  page.restart(true);
  await poll(page.doc);
  assert.equal(cardReads(page.calls), reads + 1, "one read of the card");
  assert.equal(count(page.calls, "/prompt-filters/try"), tries + 1, "one re-ask of the drawn answer");
  assert.equal(offNote(page.doc), null, "the card's off note is gone");
  assert.equal(tryOff(page.doc), null, "the answer's off line is gone");
  assert.match(page.doc.getElementById("prompt-try-answer").textContent, /An email address: removed/);
  assert.equal(page.doc.getElementById("prompt-try-go").disabled, false, "no busy button for the re-ask");

  await poll(page.doc);
  assert.equal(cardReads(page.calls), reads + 1, "the next poll reads nothing more");
  assert.equal(count(page.calls, "/prompt-filters/try"), tries + 1);
});

test("F2 Settings: a restart off brings the off lines back; a poll mid-restart ('not connected') reads nothing", async () => {
  const page = settings("on");
  await tick();
  await poll(page.doc);
  await tryMessage(page, "mail ann@corp.test");
  assert.equal(offNote(page.doc), null);
  assert.equal(tryOff(page.doc), null);
  const reads = cardReads(page.calls);

  page.setHome(RESTARTING);
  await poll(page.doc);
  assert.equal(cardReads(page.calls), reads, "an unknown on/off is no change");
  assert.equal(offNote(page.doc), null);

  page.restart(false);
  await poll(page.doc);
  assert.equal(cardReads(page.calls), reads + 1);
  assert.equal(offNote(page.doc), OFF_NOTE, "it says protection is off again");
  assert.equal(tryOff(page.doc), TRY_OFF, "and so does the answer");
});

test("F3 Settings: never under the person's hands; the focus in the exception form, or an exception being written, holds the read to the first poll after", async () => {
  const page = settings("off");
  await tick();
  await poll(page.doc);
  const reads = cardReads(page.calls);
  const match = page.doc.getElementById("prompt-exception-match");
  match.focus();
  page.restart(true);
  await poll(page.doc);
  assert.equal(cardReads(page.calls), reads, "nothing read while the focus is in the card");
  assert.equal(offNote(page.doc), OFF_NOTE);
  assert.equal(page.doc.activeElement, match, "the focus stays");

  match.value = "*@corp.test";
  match.blur();
  await poll(page.doc);
  assert.equal(cardReads(page.calls), reads, "nor while an exception is being written");

  match.value = "";
  await poll(page.doc);
  assert.equal(cardReads(page.calls), reads + 1, "the first poll after reads");
  assert.equal(offNote(page.doc), null);
});

/** The Rules page with the browser open at ~/ws, .env opened, over a
 *  service whose on/off is `running.on`; a full path typed in Find asks
 *  files/why at once (the 400 ms wait after typing made 0). */
function rules(start: "on" | "off") {
  const running = { on: start === "on" };
  const why = (path: string) => () => ({ why: { path, display: path, label: { level: "no-model", levelClass: "strict", words: "No AI", source: "builtin", from: "Built in: environment files", via: "builtin:env", bindings: [], removable: false }, off: !running.on,
    lines: [{ term: "Where the label comes from", text: "Built in: environment files" }] } });
  const page = load({ url: RULES_URL, homeVm: running.on ? ON : OFF, storage: { "mandu.files.folder": "/home/u/ws" }, routes: {
    "GET policy/panel": RULES_PANEL,
    [list("/home/u/ws")]: WS_LIST,
    [`GET files/why?path=${encodeURIComponent("/home/u/ws/.env")}`]: why("/home/u/ws/.env"),
    [`GET files/why?path=${encodeURIComponent("~/.aws/credentials")}`]: why("/home/u/.aws/credentials"),
  }, before: (w: any) => { // eslint-disable-line @typescript-eslint/no-explicit-any
    const st = w.setTimeout;
    w.setTimeout = (fn: () => void, ms?: number, ...a: unknown[]) => st(fn, ms === 400 ? 0 : ms, ...a);
  } });
  const restart = (on: boolean) => { running.on = on; page.setHome(on ? ON : OFF); };
  return { ...page, restart };
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function openEnv(doc: any) {
  doc.getElementById("rules-add").click();
  await tick();
  openRow(doc, /^\.env/);
  await tick();
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const whyText = (doc: any) => opened(doc).querySelector(".file-why").textContent as string;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const findText = (doc: any) => doc.getElementById("rules-find-none").textContent as string;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function find(doc: any, text: string) {
  const box = doc.getElementById("rules-find");
  box.focus();
  box.value = text;
  box.dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
  await tick(20);
}

test("F4 Rules: an opened file's 'What the rules say' is asked again once when protection restarts on; its off line goes; hosts typed in the row stay", async () => {
  const page = rules("off");
  await tick();
  await poll(page.doc);
  await openEnv(page.doc);
  assert.ok(whyText(page.doc).includes(OFF_LINE), whyText(page.doc));
  const asked = count(page.calls, "/api/files/why");
  const typed = page.doc.querySelector("#files-list .file-detail input[type=text]");
  assert.ok(typed, "the opened row takes hosts");
  typed.value = "api.example.com";
  typed.focus();

  await poll(page.doc);
  assert.equal(count(page.calls, "/api/files/why"), asked, "the same on/off asks nothing");

  page.restart(true);
  await poll(page.doc);
  assert.equal(count(page.calls, "/api/files/why"), asked + 1, "asked again once");
  assert.ok(!whyText(page.doc).includes(OFF_LINE), whyText(page.doc));
  assert.match(whyText(page.doc), /Where the label comes fromBuilt in: environment files/);
  assert.equal(typed.isConnected, true, "only the box was redrawn");
  assert.equal(typed.value, "api.example.com");
  assert.equal(page.doc.activeElement, typed);

  await poll(page.doc);
  assert.equal(count(page.calls, "/api/files/why"), asked + 1, "the next poll asks nothing more");

  page.restart(false);
  await poll(page.doc);
  assert.equal(count(page.calls, "/api/files/why"), asked + 2);
  assert.ok(whyText(page.doc).includes(OFF_LINE), "a restart off says so again");
});

test("F5 Rules: Find a rule's answer for a typed path is asked again when what runs changes, and its off line goes", async () => {
  const page = rules("off");
  await tick();
  await poll(page.doc);
  await find(page.doc, "~/.aws/credentials");
  assert.ok(findText(page.doc).includes(OFF_LINE), findText(page.doc));
  const asked = count(page.calls, "/api/files/why");

  page.restart(true);
  await poll(page.doc);
  assert.equal(count(page.calls, "/api/files/why"), asked + 1, "asked again once");
  assert.ok(!findText(page.doc).includes(OFF_LINE), findText(page.doc));
  assert.match(findText(page.doc), /Mandu keeps it secret without a rule/);
  assert.equal(page.doc.activeElement, page.doc.getElementById("rules-find"), "the focus stays in the box");
});

test("F6 a restart followed on Settings is still followed on returning to Rules", async () => {
  const page = rules("off");
  await tick();
  await poll(page.doc);
  await openEnv(page.doc);
  assert.ok(whyText(page.doc).includes(OFF_LINE));
  const asked = count(page.calls, "/api/files/why");
  page.doc.querySelector('[data-page-link="settings"]').click();
  await tick();
  assert.equal(page.doc.getElementById("page-settings").hidden, false);
  page.restart(true);
  await poll(page.doc);
  assert.equal(count(page.calls, "/api/files/why"), asked, "off Rules, nothing is asked");
  page.doc.querySelector('[data-page-link="rules"]').click();
  await tick();
  await poll(page.doc);
  assert.equal(count(page.calls, "/api/files/why"), asked + 1, "asked again once, on Rules");
  assert.ok(!whyText(page.doc).includes(OFF_LINE), whyText(page.doc));
});
