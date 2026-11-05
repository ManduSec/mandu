/**
 * home-js-not-running-lines.test — before Mandu runs, every line that could
 * not read something says Mandu is not running yet, never a fault
 * (dashboard.md §4.25 *Protection is off when nothing runs*, *Rule changes
 * says when it could not be read*).
 *
 * Until 2026-10-31 the hero, the top bar and Settings › Protection said so,
 * and every other line read the same state as a fault: "may be
 * unreachable", "not connected", and Rule changes "The dashboard server
 * answered with an error (404). Refresh in a moment.". Now, while the latest
 * Home poll says `protection.notRunning`:
 *
 *   R1  Home's waiting card, where Mandu never ran (`firstRun`): none waits,
 *       and how Mandu starts, the commands as code;
 *   R2  Approvals: Waiting, Answered earlier and Rule changes say so, with
 *       no "(404)"; where Mandu ran before, Waiting never says none waits
 *       (the questions of an earlier run are kept);
 *   R3  Rules: Your rules says so and keeps "You can still add a rule";
 *       Built-in protections says "not running", the server's words or,
 *       from an older server with none, the page's own;
 *   R4  Settings: Models, Sensitivity labels and Prompt filters say so;
 *   R5  History: where Mandu never ran, the empty record's line, its Find
 *       box hidden; where it ran before, that its sessions show here;
 *   R6  Find a change, and a link to a rule change, say so too;
 *   R7  a fault (`connected: false` without `notRunning`) keeps the words
 *       of a fault; Rule changes' 404 says it in the words of the page;
 *   R8  a poll that turns `notRunning` off draws the lines again and reads
 *       again what could not be read;
 *   R9  Rules › Add a rule: the file browser's note over labels no service
 *       answered for (no service, its failed dial) says where the levels
 *       show, and keeps "You can still choose rules."; a fault, and any other
 *       cause the route wrote, keep their words; a poll redraws it;
 *   R10 Keys Mandu found, opened with Review: a read no service answered
 *       (404 not connected, 503 unreachable) says where the keys show; a
 *       fault keeps the words of the page; a refusal of the sign-in keeps its
 *       own; the Approvals card stays hidden; a poll redraws it.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts); across the real launcher and
 * dashboard, tests/stack/not-running-lines.test.ts. Axes: none (display
 * only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick, list, WS_LIST } from "./home-js-fixtures.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import { builtInProtections } from "../../../src/view-model/home.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const BASE = "http://127.0.0.1:4500/mandu/";
const FIRST_RUN = { steps: [] };
/** What `/api/home` answers where Mandu is not running at all: `firstRun`
 *  where it never ran here, none where it ran before. */
const offHome = (ranBefore = false, over: Record<string, unknown> = {}) => home({
  verdict: "off", headline: "Protection is off: no agent runs with Mandu.", sentence: "",
  protection: { level: "unknown", configured: "secrets", connected: false, notRunning: true },
  waitingKnown: false, waiting: [], answered: [], agents: [], history: { total: ranBefore ? 3 : 0 },
  start: ["mandu claude", "mandu codex"], firstRun: ranBefore ? null : FIRST_RUN,
  builtIn: builtInProtections("unknown", undefined, "secrets", true),
  ...over,
});
/** The same with a fault: the service does not answer, Mandu is not known
 *  to be stopped. */
const faultHome = () => home({
  verdict: "unknown", headline: "Not connected.", sentence: "",
  protection: { level: "unknown", configured: "secrets", connected: false },
  waitingKnown: false, waiting: [], answered: [], agents: [], history: { total: 3 }, firstRun: null,
  builtIn: builtInProtections("unknown", undefined, "secrets"),
});
/** What each read answers with no protection service behind the dashboard,
 *  as the real routes answer it (tests/stack/not-running-lines.test.ts). */
const DOWN = { status: 503, body: { error: "the arbiter is not reachable", tenant: "live", unreachable: true } };
const NO_SERVICE = {
  "GET policy/changes?limit=21": { status: 404, body: { error: "arbiter not connected" } },
  "GET policy/panel": { panel: toPolicyPanelViewModel(null) },
  "GET policy/sensitivity-labels": { status: 404, body: { error: "arbiter not connected" } },
  "GET policy/prompt-filters": { status: 404, body: { error: "The protection service is not connected." } },
  "GET home/history": DOWN,
  "GET home/answered": DOWN,
  "GET suggestions": { status: 404, body: { error: "arbiter not connected" } },
};
/** The words of a fault, which this state never is. */
const FAULT = /may be unreachable|not connected|not reachable|error \(|\(404\)|Refresh in a moment|try again in a moment|Could not|could not be read/i;
const OFF = (what: string) => `Mandu is not running now; ${what} once it starts with your first agent: mandu claude or mandu codex.`;

const text = (doc: Doc, id: string): string => doc.getElementById(id).textContent;
const codes = (doc: Doc, id: string): string[] => [...doc.getElementById(id).querySelectorAll("code")].map((c: Doc) => c.textContent);
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(60);
}
function noFault(doc: Doc, ids: string[]): void {
  for (const id of ids) assert.doesNotMatch(text(doc, id), FAULT, `${id}: ${text(doc, id)}`);
}

test("R1: Home's waiting card, where Mandu never ran: none waits, and how it starts, the commands as code", async () => {
  const { doc } = load({ url: BASE, homeVm: offHome(), routes: NO_SERVICE });
  await tick(60);
  assert.equal(text(doc, "home-waiting"), "No agent runs with Mandu now, so none is waiting for your answer. Mandu starts with your first agent: mandu claude or mandu codex.");
  assert.deepEqual(codes(doc, "home-waiting"), ["mandu claude", "mandu codex"]);
  noFault(doc, ["home-waiting"]);
});

test("R2: Approvals says Mandu is not running in its three sections, no (404); where it ran before, Waiting never says none waits", async () => {
  const { doc } = load({ url: BASE + "approvals", homeVm: offHome(), routes: NO_SERVICE });
  await tick(60);
  assert.match(text(doc, "approvals-waiting"), /^No agent runs with Mandu now, so none is waiting for your answer\./);
  assert.equal(text(doc, "approvals-answered"), OFF("your earlier answers show here"));
  assert.equal(text(doc, "approvals-rule-history"), OFF("your rule changes show here"));
  for (const id of ["approvals-waiting", "approvals-answered", "approvals-rule-history"]) assert.deepEqual(codes(doc, id), ["mandu claude", "mandu codex"], id);
  noFault(doc, ["approvals-waiting", "approvals-answered", "approvals-rule-history"]);
  assert.doesNotMatch(text(doc, "page-approvals"), /\(404\)/);

  const before = load({ url: BASE + "approvals", homeVm: offHome(true), routes: NO_SERVICE });
  await tick(60);
  assert.equal(text(before.doc, "approvals-waiting"), OFF("questions waiting for your answer show here"));
  assert.doesNotMatch(text(before.doc, "approvals-waiting"), /none is waiting/, "the questions of an earlier run come back");
  assert.equal(text(before.doc, "approvals-answered"), OFF("your earlier answers show here"));
});

test("R3: Rules: Your rules says so and keeps its add a rule; Built-in protections says not running (the server's words, or the page's own)", async () => {
  const { doc } = load({ url: BASE + "rules", homeVm: offHome(), routes: NO_SERVICE });
  await tick(60);
  assert.equal(text(doc, "files-tree"), OFF("your rules show here") + " You can still add a rule.");
  assert.ok([...doc.querySelectorAll("#files-tree button")].some((b: Doc) => b.textContent === "add a rule"));
  assert.equal(text(doc, "builtin-note"), "not running");
  assert.equal(text(doc, "builtin-list"), "Mandu is not running now, so none of these is on. They turn on with your first agent.");
  noFault(doc, ["files-tree", "builtin-note", "builtin-list"]);

  const older = load({ url: BASE + "rules", homeVm: offHome(false, { builtIn: undefined }), routes: NO_SERVICE });
  await tick(60);
  assert.equal(text(older.doc, "builtin-note"), "not running");
  assert.equal(text(older.doc, "builtin-list"), "Mandu is not running now, so none of these is on. They turn on with your first agent.");
});

test("R4: Settings: Models, Sensitivity labels and Prompt filters say Mandu is not running, the commands as code", async () => {
  const { doc } = load({ url: BASE + "settings", homeVm: offHome(), routes: NO_SERVICE });
  await tick(60);
  assert.equal(text(doc, "settings-models"), OFF("the model list shows here"));
  assert.equal(text(doc, "settings-labels"), OFF("your sensitivity labels show here"));
  assert.equal(text(doc, "settings-prompt-kinds"), OFF("your prompt filter settings show here"));
  for (const id of ["settings-models", "settings-labels", "settings-prompt-kinds"]) assert.deepEqual(codes(doc, id), ["mandu claude", "mandu codex"], id);
  noFault(doc, ["settings-models", "settings-labels", "settings-prompt-kinds"]);
});

test("R5: History: where Mandu never ran, the empty record's line with no Find box; where it ran before, its sessions show here once it starts", async () => {
  const { doc } = load({ url: BASE + "history", homeVm: offHome(), routes: NO_SERVICE });
  await tick(60);
  assert.equal(text(doc, "history-list"), "No session has been recorded yet. Start your agent through Mandu, mandu claude or mandu codex, and it shows up here.");
  assert.equal(doc.getElementById("history-search").hidden, true, "no box over an empty record");
  noFault(doc, ["history-list"]);

  const before = load({ url: BASE + "history", homeVm: offHome(true), routes: NO_SERVICE });
  await tick(60);
  assert.equal(text(before.doc, "history-list"), OFF("your sessions show here"));
  assert.deepEqual(codes(before.doc, "history-list"), ["mandu claude", "mandu codex"]);
});

const change = (i: number) => ({
  id: "pc-" + String(10 - i).padStart(6, "0"), sentence: "You changed a rule on the Rules page", session: null,
  createdAt: Date.now() - (i + 1) * 60_000, undone: false, undoable: true,
  rows: [[{ kind: "text", text: "Make " }, { kind: "code", text: `/w/f${i}.pem` }, { kind: "text", text: " a secret no AI may read" }]],
});

test("R6: Find a change whose read fails once Mandu stopped, and a link to a rule change, say Mandu is not running", async () => {
  // Read while Mandu ran; then Mandu stops and a search is typed.
  const changes: { now: unknown } = { now: { changes: [change(0), change(1)] } };
  const { doc, setHome } = load({ url: BASE + "approvals", homeVm: home(), routes: { ...NO_SERVICE, "GET policy/changes?limit=21": () => changes.now, "GET policy/changes?limit=500": () => changes.now } });
  await tick(60);
  const box = doc.getElementById("changes-q");
  box.focus();
  box.value = "f0";
  box.dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 300));
  await tick(40);
  changes.now = NO_SERVICE["GET policy/changes?limit=21"];
  setHome(offHome(true));
  await poll(doc);
  const line = doc.querySelector("#approvals-rule-history .empty");
  assert.equal(line.textContent, OFF("your rule changes show here") + " Clear");
  noFault(doc, ["approvals-rule-history"]);

  const link = load({ url: BASE + "approvals/pc-000003", homeVm: offHome(), routes: NO_SERVICE });
  await tick(60);
  const note = link.doc.getElementById("approvals-focus-note");
  assert.equal(note.textContent, "Mandu is not running now, so this rule change cannot be shown. It is still kept, and shows here once Mandu starts with your first agent: mandu claude (or mandu codex).");
});

test("R7: a fault keeps the words of a fault, and Rule changes' 404 is said in the words of the page, never its status", async () => {
  const routes = { ...NO_SERVICE };
  const approvals = load({ url: BASE + "approvals", homeVm: faultHome(), routes });
  await tick(60);
  assert.equal(text(approvals.doc, "approvals-waiting"), "Could not check for waiting questions. The protection service may be unreachable.");
  assert.equal(text(approvals.doc, "approvals-answered"), "Could not check your earlier answers. The protection service may be unreachable.");
  assert.equal(text(approvals.doc, "approvals-rule-history"), "Could not read your rule changes. The protection service is not connected.");
  const history = load({ url: BASE + "history", homeVm: faultHome(), routes });
  await tick(60);
  assert.equal(text(history.doc, "history-list"), "Could not read the history. The protection service is not running.");
  const rules = load({ url: BASE + "rules", homeVm: faultHome(), routes });
  await tick(60);
  assert.match(text(rules.doc, "files-tree"), /^Your rules could not be read\. The protection service may be unreachable\./);
  assert.equal(text(rules.doc, "builtin-note"), "not connected");
  const settings = load({ url: BASE + "settings", homeVm: faultHome(), routes });
  await tick(60);
  assert.equal(text(settings.doc, "settings-models"), "The model list could not be read. The protection service may be unreachable.");
  assert.equal(text(settings.doc, "settings-labels"), "The protection service is not connected.");
  assert.equal(text(settings.doc, "settings-prompt-kinds"), "The protection service is not connected.");
});

test("R8: a poll that turns not running off draws the lines again, and Settings reads again what it could not read", async () => {
  const approvals = load({ url: BASE + "approvals", homeVm: offHome(true), routes: NO_SERVICE });
  await tick(60);
  assert.equal(text(approvals.doc, "approvals-answered"), OFF("your earlier answers show here"));
  approvals.setHome(faultHome());
  await poll(approvals.doc);
  assert.equal(text(approvals.doc, "approvals-waiting"), "Could not check for waiting questions. The protection service may be unreachable.");
  assert.equal(text(approvals.doc, "approvals-answered"), "Could not check your earlier answers. The protection service may be unreachable.");
  assert.equal(text(approvals.doc, "approvals-rule-history"), "Could not read your rule changes. The protection service is not connected.");

  const settings = load({ url: BASE + "settings", homeVm: offHome(), routes: NO_SERVICE });
  await tick(60);
  const reads = (route: string) => settings.calls.filter((c) => c.url === `/mandu/api/${route}`).length;
  const before = ["policy/panel", "policy/sensitivity-labels", "policy/prompt-filters"].map(reads);
  settings.setHome(faultHome());
  await poll(settings.doc);
  assert.deepEqual(["policy/panel", "policy/sensitivity-labels", "policy/prompt-filters"].map(reads), before.map((n) => n + 1), "each unread block read again once");
  assert.equal(text(settings.doc, "settings-models"), "The model list could not be read. The protection service may be unreachable.");
  assert.equal(text(settings.doc, "settings-labels"), "The protection service is not connected.");

  const history = load({ url: BASE + "history", homeVm: offHome(true), routes: NO_SERVICE });
  await tick(60);
  history.setHome(faultHome());
  await poll(history.doc);
  assert.equal(text(history.doc, "history-list"), "Could not read the history. The protection service is not running.");
});

// ── Rules › Add a rule's note and Keys Mandu found (2026-11-03) ─────────────

/** A listing of /home/u/ws whose labels the route could not read, `labelError` its words. */
const unknownLabels = (labelError?: string) => ({
  ...WS_LIST, labels: "unknown", axis: null, self: null, entries: WS_LIST.entries.map((e) => ({ ...e, label: null })),
  ...(labelError === undefined ? {} : { labelError }),
});
const AT_WS = { "mandu.files.folder": "/home/u/ws" };
async function openBrowser(homeVm: unknown, labelError?: string) {
  const page = load({ url: BASE + "rules", homeVm, storage: AT_WS, routes: { ...NO_SERVICE, [list("/home/u/ws")]: unknownLabels(labelError) } });
  await tick(60);
  page.doc.getElementById("rules-add").click();
  await tick(60);
  return page;
}
const NOTE_OFF = OFF("the levels of your files show here") + " You can still choose rules.";
/** The route's words for no service behind it, and for a dial that failed. */
const NOT_CONNECTED = "the protection service is not connected";
const DIAL = "the protection service did not answer (connect ENOENT /run/user/1000/mandu/arbiter.sock)";

test("R9: Add a rule's note, while Mandu is not running, says where the levels show, the commands as code, with no fault and no Settings link", async () => {
  for (const labelError of [NOT_CONNECTED, DIAL, undefined]) {
    const { doc } = await openBrowser(offHome(), labelError);
    const note = doc.getElementById("files-note");
    assert.equal(note.hidden, false, String(labelError));
    assert.equal(text(doc, "files-note"), NOTE_OFF, String(labelError));
    assert.deepEqual(codes(doc, "files-note"), ["mandu claude", "mandu codex"], String(labelError));
    assert.equal(note.querySelector("a"), null, "no link to a Start under Settings");
    assert.doesNotMatch(text(doc, "files-note"), /could not|Start it under Settings/i);
    noFault(doc, ["files-note"]);
  }
});

test("R9: Add a rule's note keeps the words of a fault while Mandu runs, and any cause the route wrote while it does not", async () => {
  const dial = await openBrowser(faultHome(), DIAL);
  assert.equal(text(dial.doc, "files-note"), "Labels could not be read. The protection service is not running. Start it under Settings, or try again in a moment. You can still choose rules.");
  const none = await openBrowser(faultHome(), NOT_CONNECTED);
  assert.equal(text(none.doc, "files-note"), "Labels could not be read: the protection service is not connected. You can still choose rules.");
  // An older service, or the admin boundary: a fault whatever the state.
  const old = "this Mandu service cannot read labels for the file browser; restart the Mandu stack on the current build";
  const stale = await openBrowser(offHome(), old);
  assert.equal(text(stale.doc, "files-note"), `Labels could not be read: ${old}. You can still choose rules.`);
  const admin = await openBrowser(offHome(), "admin channel unavailable: no admin socket");
  assert.equal(text(admin.doc, "files-note"), "Labels could not be read: admin channel unavailable: no admin socket. You can still choose rules.");
});

test("R9: a poll that turns not running on or off draws Add a rule's note again, the list as it was", async () => {
  const { doc, setHome } = await openBrowser(faultHome(), DIAL);
  assert.match(text(doc, "files-note"), /^Labels could not be read\. /);
  const rows = doc.querySelectorAll("#files-list .row.file").length;
  setHome(offHome());
  await poll(doc);
  assert.equal(text(doc, "files-note"), NOTE_OFF);
  assert.equal(doc.querySelectorAll("#files-list .row.file").length, rows);
  setHome(faultHome());
  await poll(doc);
  assert.match(text(doc, "files-note"), /^Labels could not be read\. The protection service is not running\./);
});

async function openKeys(homeVm: unknown, answer: unknown) {
  const page = load({ url: BASE + "rules", homeVm, routes: { ...NO_SERVICE, "GET suggestions": answer } });
  await tick(60);
  page.doc.getElementById("suggest-open").click();
  await tick(60);
  return page;
}
const NOT_CONNECTED_404 = { status: 404, body: { error: "arbiter not connected" } };
const KEYS_OFF = OFF("the keys it finds show here");

test("R10: Keys Mandu found, while Mandu is not running, says where the keys show where its error was; the Approvals card stays hidden", async () => {
  for (const answer of [NOT_CONNECTED_404, DOWN]) {
    const { doc } = await openKeys(offHome(), answer);
    assert.equal(doc.getElementById("files-suggested-view").hidden, false);
    assert.equal(text(doc, "suggest-error"), KEYS_OFF, JSON.stringify(answer));
    assert.deepEqual(codes(doc, "suggest-error"), ["mandu claude", "mandu codex"]);
    assert.equal(doc.getElementById("suggest-scan").disabled, false, "Scan for keys stays as it is");
    noFault(doc, ["suggest-error", "suggested-line"]);
  }
  const approvals = load({ url: BASE + "approvals", homeVm: offHome(), routes: NO_SERVICE });
  await tick(60);
  assert.equal(approvals.doc.getElementById("approvals-suggestions-block").hidden, true, "no keys wait: no card");
});

test("R10: Keys Mandu found keeps the words of a fault while Mandu runs, and a refusal of the sign-in whatever the state", async () => {
  const none = await openKeys(faultHome(), NOT_CONNECTED_404);
  assert.equal(text(none.doc, "suggest-error"), "The protection service is not connected.");
  const down = await openKeys(faultHome(), DOWN);
  assert.equal(text(down.doc, "suggest-error"), "The protection service is not running. Start it under Settings, or try again in a moment.");
  const signIn = await openKeys(offHome(), { status: 403, body: { error: "admin session required" } });
  assert.match(text(signIn.doc, "suggest-error"), /^Sign in first: /);
  const broken = await openKeys(offHome(), { status: 500, body: { error: "the suggestion store is damaged" } });
  assert.equal(text(broken.doc, "suggest-error"), "the suggestion store is damaged");
});

test("R10: a poll that turns not running on or off draws Keys Mandu found's line again", async () => {
  const { doc, setHome } = await openKeys(faultHome(), NOT_CONNECTED_404);
  assert.equal(text(doc, "suggest-error"), "The protection service is not connected.");
  setHome(offHome());
  await poll(doc);
  assert.equal(text(doc, "suggest-error"), KEYS_OFF);
  setHome(faultHome());
  await poll(doc);
  assert.equal(text(doc, "suggest-error"), "The protection service is not connected.");
});
