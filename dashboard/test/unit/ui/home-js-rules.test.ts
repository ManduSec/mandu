/**
 * home-js-rules.test — the Rules page: no switch (it is in Settings) and the
 * line while protection is off, the grouped rule rows and their Remove / Undo flows, §4.25g "Show in
 * policy.yaml", §4.25i who put each rule there, and §4.25c a subject chip as
 * wide as its words (the page's own styles applied).
 *
 * Split out of home-js.test.ts, which drove the PRODUCT page script
 * (public/js/home.js) in jsdom over a fetch stub (dashboard.md §4.25); the
 * shared harness and fixtures are in home-js-fixtures.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { tick, pressed, opened, treeRow, treeRows, rulesPage, rowOf, openRule, CLOCK, home, load, HTML, RULES_PANEL, PUB } from "./home-js-fixtures.js";
import { ISSUER_TABLE, issuerItem } from "../../../src/view-model/issuer-words.js";
import { BUILTIN_FILE_KINDS, BUILTIN_HOME_PLACES, builtinFiles } from "../../../src/view-model/builtin-files.js";
import { declValue, flattenCss, resolveCssVars, stripComments, stylesAt } from "./css-flatten.js";

const button = (row: any, label: string) => ([...row.querySelectorAll("button")] as any[]).find((b) => b.textContent === label);
/** A rule's effect menu: its options, and turning it around as a person does. */
const effectMenu = (row: any) => row.querySelector("select.effect-select") as any;
const effects = (row: any) => ([...effectMenu(row).options] as any[]).map((o) => o.textContent);
const flip = (row: any) => {
  const m = effectMenu(row);
  m.value = "flip";
  m.dispatchEvent(new m.ownerDocument.defaultView.Event("change", { bubbles: true }));
};

const axesGet = (integrity: boolean, confidentiality: boolean) => ({
  ok: true, effective: { integrity, confidentiality },
  effectiveMode: confidentiality ? (integrity ? "full" : "secrets") : (integrity ? "injection" : "off"),
});

/** Home's answer with the protection service running `level` (or none). */
const runs = (level: string, connected = true) => home({ protection: { level, configured: "secrets", connected } });

test("Rules: no switch on the page; while protection is off a line says so and points to Settings", async () => {
  const on = rulesPage({ "GET config/axes": axesGet(false, true) });
  await tick();
  assert.equal(on.doc.querySelector("#page-rules [role=switch]"), null, "the on/off lives in Settings");
  assert.equal(on.doc.getElementById("rules-off").hidden, true);
  const off = rulesPage({ "GET config/axes": axesGet(false, false), "GET home": runs("off") });
  await tick();
  const line = off.doc.getElementById("rules-off");
  assert.equal(line.hidden, false);
  assert.equal(line.textContent, "Protection is off, so these rules are kept but not enforced. Turn it on in Settings.");
  assert.equal(line.querySelector("a").getAttribute("data-page-link"), "settings");
});

test("Rules: the line says what runs now, beside what is saved (§4.25 \"The on/off says what runs\")", async () => {
  const SAVED_OFF = "Protection is saved as off: once the protection service restarts, these rules are kept but not enforced. Turn it on in Settings.";
  const cases: [string, boolean, unknown, string | null][] = [
    ["on, running", true, runs("secrets"), null],
    ["on, no protection service", true, runs("unknown", false), null],
    ["on saved, off still running", true, runs("off"), "Protection is still off until the protection service restarts, so these rules are kept but not enforced."],
    ["off saved, on still running", false, runs("secrets"), SAVED_OFF],
    ["off saved, no protection service", false, runs("unknown", false), SAVED_OFF],
  ];
  for (const [what, savedOn, homeAnswer, want] of cases) {
    const { doc } = rulesPage({ "GET config/axes": axesGet(false, savedOn), "GET home": homeAnswer });
    await tick();
    const line = doc.getElementById("rules-off");
    assert.equal(line.hidden, want === null, `${what}: shown`);
    assert.equal(line.textContent, want ?? "", what);
  }
  // Home answers after the rules: the line follows it.
  let answer: (v: unknown) => void = () => {};
  const late = new Promise((r) => { answer = r; });
  const { doc } = rulesPage({ "GET config/axes": axesGet(false, true), "GET home": () => late });
  await tick();
  assert.equal(doc.getElementById("rules-off").hidden, true, "nothing known of what runs: on is saved, no line");
  answer(runs("off"));
  await tick();
  assert.equal(doc.getElementById("rules-off").hidden, false);
  assert.match(doc.getElementById("rules-off").textContent, /^Protection is still off until the protection service restarts/);
});

test("Rules: grouped rows, every button acts on the page, and nothing links to the developer view", async () => {
  const { doc } = rulesPage();
  await tick();
  const groups = [...doc.querySelectorAll("#rules-list .rules-group")].map((g: any) => g.firstChild.textContent);
  assert.deepEqual(groups, ["Sending data", "Programs and connections"], "a per-program rule sits with programs, not files; file rules are the explorer's");
  assert.equal(doc.querySelectorAll("#page-rules a[href*='dev/']").length, 0, "no link from the Rules page to /dev/");
  // The one link a row carries is an answer's "See what the agent was doing"
  // under its ⋯, to the product's agent page (§4.25h); rules act through
  // menus and buttons.
  assert.deepEqual(([...doc.querySelectorAll("#rules-list a")] as any[]).map((a) => a.textContent), [], "closed rows carry no link");
  assert.deepEqual(([...openRule(doc, /paste\.example/).querySelectorAll("a")] as any[]).map((a) => a.textContent), ["See what the agent was doing"]);
  // A file rule from the rules file sits in the explorer's Labeled tree, once.
  assert.equal(rowOf(doc, /ws-\*\/memo/), undefined);
  const pats = ([...doc.querySelectorAll("#files-tree .row.file-rule")] as any[]).filter((r) => /ws-\*\/memo/.test(r.textContent));
  assert.equal(pats.length, 1, "listed once, not again as a label");
  assert.deepEqual(pressed(pats[0]), ["any-model"], "a rules-file lock, chosen in its menu");
  assert.deepEqual(([...pats[0].querySelectorAll(".host-chip")] as any[]).map((c) => c.textContent), ["example.com"]);
  pats[0].click();
  assert.ok(doc.getElementById("files-unset"), "a pattern lock from the rules file can be removed from its opened row");
  // A row: what it covers, ONE effect menu, and a ⋯ for the rest.
  const send = rowOf(doc, /api\.example\.com/);
  assert.deepEqual(effects(send), ["sending allowed", "Always blocked"], "the effect in force, and the one it can turn into");
  assert.deepEqual([...send.querySelectorAll("button")].map((b: any) => b.getAttribute("aria-label")), ["More about api.example.com"], "Remove waits under ⋯");
  assert.deepEqual([...openRule(doc, /api\.example\.com/).querySelectorAll("button")].map((b: any) => b.textContent), ["Show in policy.yaml", "Remove"]);
  const app = rowOf(doc, /psql/);
  assert.equal(effectMenu(app), null, "a rule set in the rules file has no menu");
  assert.match(openRule(doc, /psql/).textContent, /Set in policy.yaml/);
  assert.equal(openRule(doc, /psql/).querySelector(".rule-remove"), null);
  const answer = rowOf(doc, /paste\.example/);
  assert.deepEqual(effects(answer), ["Always allowed", "Always blocked"]);
  assert.match(answer.textContent, /paste\.example\s*sending only the file ~\/ws\/notes\.md/, "an answer names the one piece of data it covers (§4.25e)");
  assert.match(openRule(doc, /paste\.example/).textContent, /Your answer, asked 3 times/);
  // Every group says what its rules decide, beside its title.
  const abouts = [...doc.querySelectorAll("#rules-list .rules-group .muted")].map((g: any) => g.textContent);
  assert.equal(abouts.length, 2);
  assert.match(abouts[0], /^where masked data and secrets may go, or are blocked from going, without asking you$/, "the line says what the group blocks too (§4.25e)");
  for (const a of abouts) assert.doesNotMatch(a, /—|policy|egress|symbol/i);
  assert.equal(rowOf(doc, /later\.example/), undefined, "a pending ask is not a rule");
});

test("Rules: Remove that loosens asks first, sends back what it was told, then offers Undo", async () => {
  const { doc, calls, window } = rulesPage({
    "POST policy/rules/change": { applied: false, confirm: true, expected: ["release\u0000api.example.com"] },
  });
  await tick();
  // The question is asked on the page (dashboard.md §4.25n *Rules asks on
  // the page, not in a browser dialog*), never in one a browser can block.
  window.confirm = () => { throw new Error("window.confirm called"); };
  // The second POST (with expected) answers applied.
  let n = 0;
  const f = window.fetch;
  window.fetch = (url: string, init: any = {}) => {
    if (url.endsWith("/policy/rules/change") && ++n === 2) {
      calls.push({ url, method: "POST", headers: init.headers, body: JSON.parse(init.body) });
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ applied: true, changeId: "pc-000004" }) });
    }
    return f(url, init);
  };
  const remove = button(openRule(doc, /api\.example\.com/), "Remove");
  remove.focus();
  remove.click();
  await tick();
  assert.equal(calls.filter((c) => c.url.endsWith("/policy/rules/change")).length, 1, "asked first: nothing changed yet");
  const ask = doc.querySelector("#rules-list .ask-in-place");
  assert.ok(ask, "the question is under the row");
  assert.equal(ask.previousElementSibling.classList.contains("rule-detail"), true, "under the opened row, its Remove above it");
  assert.equal(ask.querySelector(".ask-in-place-words").textContent, "Removing this rule makes protection weaker for api.example.com.");
  assert.equal(ask.querySelector("code").textContent, "api.example.com");
  assert.deepEqual([...ask.querySelectorAll("button")].map((b: any) => b.textContent), ["Remove anyway", "Cancel"]);
  assert.equal(doc.activeElement, ask.querySelector(".ask-in-place-words"), "its sentence has the focus, never the button");
  button(ask, "Remove anyway").click();
  await tick();
  const posts = calls.filter((c) => c.url.endsWith("/policy/rules/change"));
  assert.equal(posts.length, 2);
  assert.equal(doc.querySelector(".ask-in-place"), null, "the question is gone");
  assert.deepEqual(posts[0]!.body, { id: "r-0001", action: "remove" }, "the page names a row and an action, never an edit");
  assert.deepEqual(posts[1]!.body, { id: "r-0001", action: "remove", expected: ["release\u0000api.example.com"] });
  assert.equal(posts[0]!.headers["X-Mandu-Control"], "1");
  const notice = doc.getElementById("rules-notice");
  assert.equal(notice.hidden, false);
  assert.match(notice.textContent, /Rule removed\./);
  button(notice, "Undo").click();
  await tick();
  assert.ok(calls.some((c) => c.method === "POST" && c.url === "/mandu/api/policy/changes/pc-000004/undo"));
});

test("Rules: Cancel or Escape on the question changes nothing; a refusal shows the server's words on the row", async () => {
  const a = rulesPage({ "POST policy/rules/change": { applied: false, confirm: true, expected: ["k"] } });
  await tick();
  a.window.confirm = () => { throw new Error("window.confirm called"); };
  button(openRule(a.doc, /api\.example\.com/), "Remove").click();
  await tick();
  button(a.doc.querySelector(".ask-in-place"), "Cancel").click();
  await tick();
  assert.equal(a.calls.filter((c) => c.url.endsWith("/policy/rules/change")).length, 1, "no second request");
  assert.equal(a.doc.querySelector(".ask-in-place"), null, "Cancel closes the question");
  button(openRule(a.doc, /api\.example\.com/), "Remove").click();
  await tick();
  const words = a.doc.querySelector(".ask-in-place .ask-in-place-words");
  words.dispatchEvent(new a.window.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
  await tick();
  assert.equal(a.doc.querySelector(".ask-in-place"), null, "Escape closes it too");
  assert.equal(a.calls.filter((c) => c.url.endsWith("/policy/rules/change")).length, 2, "each Remove asks the server once; neither answer posts");
  assert.ok(a.calls.filter((c) => c.url.endsWith("/policy/rules/change")).every((c) => !(c.body as { expected?: unknown }).expected));
  const b = rulesPage({ "POST policy/rules/change": { status: 409, body: { error: "This rule is no longer in your rules. Reload the page." } } });
  await tick();
  const row = rowOf(b.doc, /api\.example\.com/);
  flip(row);
  await tick();
  assert.deepEqual(b.calls.find((c) => c.url.endsWith("/policy/rules/change"))!.body, { id: "r-0001", action: "block" });
  assert.match(row.querySelector(".ask-error").textContent, /no longer in your rules/);
  assert.equal(effectMenu(row).value, "", "the menu shows the effect in force again");
  assert.equal(effectMenu(row).disabled, false);
});

test("Rules: a lock made on this page is removed from the explorer, as a change to save; Remove on an answer forgets it", async () => {
  const saves: any[] = [];
  const { doc, calls } = rulesPage({ "POST egress/approvals/egr-7/forget": { approval: { id: "egr-7" } }, "POST files/labels": (b: any) => (saves.push(b), { applied: true, changeId: null, page: 1 }) });
  await tick();
  treeRow(doc, /\.env/).click();
  assert.match(opened(doc).textContent, /Added here/);
  doc.getElementById("files-unset").click();
  assert.equal(treeRow(doc, /\.env/).querySelector("select.label-select").value, "", "the menu shows Remove my rule, waiting");
  assert.match(doc.getElementById("files-pending-list").textContent, /~\/ws\/\.env.*No rule of its own/);
  assert.match(doc.getElementById("files-tree").textContent, /~\/ws\/\.env.*Will be: No rule of its own \(not saved\)/);
  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual(saves[0].changes, [{ path: "/home/u/ws/.env", level: null, recursive: false }]);
  assert.equal(calls.filter((c) => c.method === "DELETE").length, 0, "no longer the old label route");
  button(openRule(doc, /paste\.example/), "Remove").click();
  await tick();
  assert.ok(calls.some((c) => c.method === "POST" && c.url === "/mandu/api/egress/approvals/egr-7/forget"));
  assert.match(doc.getElementById("rules-notice").textContent, /asked again next time/);
});

test("Rules › Your answers names an answer by what the arbiter keeps it as: for this session on a program's send keyed to one, once on a flip of a once kind, Always elsewhere (§4.25 *Kept for one session or one use*)", async () => {
  const SHA = "a".repeat(64);
  const REACH = "a program in one session sending data from ~/app/.env";
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const answerRow = (id: string, approved: boolean, extra: Record<string, unknown>): any => ({
    id, status: approved ? "approved" : "denied", scope: "always", where: "network", count: 1,
    actions: [{ approve: !approved, label: approved ? "Block instead" : "Allow instead" }], sessions: [], resolvedAt: null, ...extra,
  });
  const holder = (id: string, host: string, approved: boolean) => answerRow(id, approved, {
    subject: 'holder-send:{"session":"s1","files":["/home/u/app/.env"]}', target: host, allowKeptAs: "session",
    plain: { subject: host, reach: REACH, effect: "Always allowed" },
  });
  // A once kind kept standing (stored before plan 13 §8 decision (c)): the
  // arbiter now keeps an answer on it as once, so it reaches Rules only so.
  const run = answerRow("egr-r1", false, {
    where: "file", subject: `open:/usr/bin/python3#${SHA}#run:py-1`, target: "/home/u/app/.env", allowKeptAs: "once",
    plain: { subject: "/home/u/app/.env", reach: "one run of python3 reading it", effect: "Always blocked" },
  });
  const plain = answerRow("egr-6", false, { subject: "$MDU:x", target: "old.example", plain: { subject: "old.example", reach: null, effect: "Always blocked" } });
  let queue = [holder("egr-h1", "hooks.slack.com", false), holder("egr-h2", "chat.example", true), run, plain];
  const answered = (id: string, approve: boolean, scope: "always" | "once") => {
    queue = queue.map((v) => v.id !== id ? v : { ...v, status: approve ? "approved" : "denied", scope, actions: [{ approve: !approve, label: "x" }] });
    return { approval: { id } };
  };
  const { doc, calls } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: {
    "GET policy/panel": () => ({ panel: { available: true, verdictsKnown: true, yourRules: [], queue } }),
    "POST egress/approvals/egr-h1/approve": () => answered("egr-h1", true, "always"),
    "POST egress/approvals/egr-r1/approve": () => answered("egr-r1", true, "once"),
    "POST egress/approvals/egr-6/approve": () => answered("egr-6", true, "always"),
  } });
  await tick();
  const notice = () => doc.getElementById("rules-notice");
  // The effect, and the one it turns into, under the row's own reach line.
  const blocked = rowOf(doc, /hooks\.slack\.com/);
  assert.match(blocked.textContent, /a program in one session sending data/);
  assert.deepEqual(effects(blocked), ["Blocked for this session", "Allowed for this session"], "never Always under a one-session reach");
  assert.deepEqual(effects(rowOf(doc, /chat\.example/)), ["Allowed for this session", "Blocked for this session"]);
  assert.deepEqual(effects(rowOf(doc, /old\.example/)), ["Always blocked", "Always allowed"], "a plain answer keeps its words");
  assert.deepEqual(effects(rowOf(doc, /one run of python3/)), ["Always blocked", "Allowed once"], "kept standing, it reads Always; its allow is kept once");
  // Find a rule finds it by the new words.
  const find = doc.getElementById("rules-find");
  find.value = "this session";
  find.dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
  await tick();
  assert.ok(rowOf(doc, /hooks\.slack\.com/) && rowOf(doc, /chat\.example/), "found by their effect (the reach says one session)");
  assert.equal(rowOf(doc, /old\.example/), undefined);
  find.value = "";
  find.dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
  await tick();
  // Flipped: same route, no body; the notice says what the arbiter keeps.
  flip(rowOf(doc, /hooks\.slack\.com/));
  await tick(30);
  assert.ok(calls.some((c) => c.method === "POST" && c.url === "/mandu/api/egress/approvals/egr-h1/approve"));
  assert.equal(notice().firstChild.textContent, "Now allowed for this session.");
  assert.deepEqual(effects(rowOf(doc, /hooks\.slack\.com/)), ["Allowed for this session", "Blocked for this session"]);
  // A once answer leaves Rules: the notice says so and links where it is listed.
  flip(rowOf(doc, /one run of python3/));
  await tick(30);
  assert.equal(notice().firstChild.textContent, "Now allowed once: your agent's next try goes through, then Mandu asks again. It is listed under Approvals › Answered earlier.");
  const link = notice().querySelector("a");
  assert.equal(link.textContent, "Approvals › Answered earlier");
  assert.equal(link.getAttribute("data-page-link"), "approvals");
  assert.equal(link.getAttribute("data-ask"), "egr-r1", "the link marks the row of the answer");
  assert.equal(rowOf(doc, /one run of python3/), undefined, "Rules lists standing answers only");
  // A plain answer still says Always.
  flip(rowOf(doc, /old\.example/));
  await tick(30);
  assert.equal(notice().firstChild.textContent, "Now always allowed.");
  assert.doesNotMatch(doc.getElementById("rules-list").textContent, /Always allowed.{0,40}one session/, "no Always beside a one-session reach");
});

// ── dashboard.md §4.25g: "Show in policy.yaml" ───────────────────────────────

test("§4.25g: a rules-file row opens its policy.yaml lines under it (read-only); a row kept elsewhere says where", async () => {
  const { doc, calls } = rulesPage({
    "GET policy/rules/source?id=lock%3A**%2Fws-*%2Fmemo%2F**": {
      found: true, path: "/home/u/.config/mandu/policy.yaml", start: 8,
      lines: ["  # drill workspaces", "  - { path: \"**/ws-*/memo/**\", level: any-model }"], mark: [9],
    },
    "GET policy/rules/source?id=r-0001": { found: false, path: "/home/u/.config/mandu/policy.yaml", reason: "This rule is not written in policy.yaml. It comes from Mandu's built-in settings." },
  });
  await tick();
  // A file rule: its lines open in its opened row.
  treeRow(doc, /ws-\*\/memo/).click();
  const detail = opened(doc);
  const show = ([...detail.querySelectorAll("button")] as any[]).find((b) => b.textContent === "Show in policy.yaml");
  assert.ok(show, "every rule from the rules file has the button");
  show.click();
  await tick();
  const panel = detail.querySelector(".rule-source");
  assert.ok(panel, "the lines open in the opened row");
  assert.match(panel.querySelector(".rule-source-head").textContent, /^Line 9 of ~\/\.config\/mandu\/policy\.yaml$/);
  const lines = ([...panel.querySelectorAll(".ln")] as any[]).map((l) => `${l.classList.contains("mark") ? "*" : " "}${l.querySelector(".ln-no").textContent} ${l.querySelector(".ln-text").textContent}`);
  assert.deepEqual(lines, [" 8   # drill workspaces", "*9   - { path: \"**/ws-*/memo/**\", level: any-model }"]);
  assert.equal(panel.querySelectorAll("button, textarea, input, a").length, 0, "read-only: nothing to edit or follow");
  assert.equal(show.textContent, "Hide policy.yaml");
  assert.equal(show.getAttribute("aria-expanded"), "true");
  show.click();
  await tick();
  assert.equal(detail.querySelector(".rule-source"), null, "closes again");
  assert.equal(show.textContent, "Show in policy.yaml");
  assert.ok(calls.every((c) => !c.url.includes("rules/source") || c.method === "GET"));

  // A rule the file does not hold says so in place of the lines, under ⋯.
  const send = openRule(doc, /api\.example\.com/);
  ([...send.querySelectorAll("button")] as any[]).find((b) => b.textContent === "Show in policy.yaml").click();
  await tick();
  assert.match(send.querySelector(".detail-source").textContent, /not written in policy\.yaml/);

  // Rows kept elsewhere: a lock made on this page, and a past answer.
  treeRow(doc, /\.env/).click();
  assert.equal(([...opened(doc).querySelectorAll("button")] as any[]).some((b) => /policy\.yaml/.test(b.textContent)), false);
  assert.match(opened(doc).textContent, /Saved by Mandu, not in policy\.yaml/);
  const answer = openRule(doc, /paste\.example/);
  assert.match(answer.querySelector(".rule-source-note").textContent, /^Saved when you answered, not in policy\.yaml$/);
});

// ── §4.25i: who put each rule there ───────────────────────────────────────────

test("§4.25i: a rules-file row says who put it there and when; an agent's rule links to its session; no record only when the record is whole", async () => {
  const origins = {
    origins: {
      "r-0001": { recorded: true, sentence: "Your agent asked for this and you approved it", at: Date.now() - 2 * 3_600_000, session: "sess-9", changedSince: false },
      "lock:**/ws-*/memo/**": { recorded: true, sentence: "You added this on the Rules page", at: Date.now() - 86_400_000, session: null, changedSince: true },
    },
    complete: true,
    unrecorded: { recorded: false, sentence: "No record of who added this. It was written in policy.yaml directly", at: null, session: null, changedSince: false },
  };
  const { doc, calls, window } = rulesPage({ "GET policy/rules/origins": origins });
  await tick();
  const send = openRule(doc, /api\.example\.com/);
  assert.match(send.querySelector(".rule-origin").textContent, new RegExp(`^Your agent asked for this and you approved it, ${CLOCK} · 2 hours ago\\. See what the agent was doing$`));
  const link = send.querySelector(".rule-origin a");
  assert.equal(link.getAttribute("href"), "/mandu/agents/sess-9", "the session's top: a rule change has no ask to mark");
  treeRow(doc, /ws-\*\/memo/).click();
  const memo = opened(doc);
  assert.match(memo.querySelector(".rule-origin").textContent, new RegExp(`^You added this on the Rules page, ${CLOCK} · yesterday\\. It was changed in policy\\.yaml after that, while Mandu was not running\\.$`));
  assert.equal(memo.querySelector(".rule-origin a"), null, "a person's change has no agent session");
  const app = openRule(doc, /psql/);
  assert.equal(app.querySelector(".rule-origin").textContent, "No record of who added this. It was written in policy.yaml directly.");
  // Answers and page-made locks keep their own lines, not an origin line.
  assert.equal(openRule(doc, /paste\.example/).querySelector(".rule-origin"), null);
  treeRow(doc, /\.env/).click();
  assert.equal(opened(doc).querySelector(".rule-origin"), null);
  openRule(doc, /api\.example\.com/).querySelector(".rule-origin a").click();
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/agents/sess-9");
  assert.equal(calls.filter((c) => c.url.startsWith("/mandu/api/home/agent")).pop()!.url, "/mandu/api/home/agent?session=sess-9");

  // A partial record: rows it does not name say nothing, never "no record".
  const part = rulesPage({ "GET policy/rules/origins": { ...origins, complete: false } });
  await tick();
  assert.equal(openRule(part.doc, /psql/).querySelector(".rule-origin"), null);
  // Unreadable: no origin lines at all, the page still works.
  const down = rulesPage({ "GET policy/rules/origins": { status: 501, body: { error: "old arbiter" } } });
  await tick();
  assert.equal(down.doc.querySelectorAll(".rule-origin").length, 0);
  assert.ok(rowOf(down.doc, /api\.example\.com/));
});

test("§4.25i: a recorded origin ends with a link to its change in Approvals, named by its rule; no record has none; the agent link stays", async () => {
  const origins = {
    origins: {
      "r-0001": { recorded: true, sentence: "Your agent asked for this and you approved it", at: Date.now() - 2 * 3_600_000, session: "sess-9", changedSince: false, changeId: "pc-000007" },
      "lock:**/ws-*/memo/**": { recorded: true, sentence: "You added this on the Rules page", at: Date.now() - 86_400_000, session: null, changedSince: false, changeId: "pc-000003" },
    },
    complete: true,
    unrecorded: { recorded: false, sentence: "No record of who added this", at: null, session: null, changedSince: false, changeId: null },
  };
  const { doc, window } = rulesPage({ "GET policy/rules/origins": origins });
  await tick();
  const send = openRule(doc, /api\.example\.com/);
  const line = send.querySelector(".rule-origin");
  assert.match(line.textContent, new RegExp(`^Your agent asked for this and you approved it, ${CLOCK} · 2 hours ago\\. See what the agent was doing · See this change in Approvals · Find its changes$`), "the words as before, the change link, then a send rule's Find its changes (home-js-rule-changes-find F12)");
  const [agent, change] = [...line.querySelectorAll("a")] as any[];
  assert.equal(agent.getAttribute("href"), "/mandu/agents/sess-9", "the agent link stays");
  assert.equal(change.getAttribute("href"), "/mandu/approvals/pc-000007", "a plain link: a new tab, a bookmark and Back work");
  assert.equal(change.dataset.pageLink, "approvals");
  assert.equal(change.getAttribute("aria-label"), "See this change in Approvals: api.example.com", "named by its rule");
  treeRow(doc, /ws-\*\/memo/).click();
  const memo = opened(doc).querySelector(".rule-origin");
  assert.match(memo.textContent, new RegExp(`^You added this on the Rules page, ${CLOCK} · yesterday\\. See this change in Approvals · Find its changes$`), "a person's change: the change link, then a file rule's Find its changes (home-js-rule-changes-find)");
  assert.equal(memo.querySelector("a").getAttribute("href"), "/mandu/approvals/pc-000003");
  assert.match(memo.querySelector("a").getAttribute("aria-label"), /^See this change in Approvals: .*memo/);
  const app = openRule(doc, /psql/).querySelector(".rule-origin");
  assert.equal(app.textContent, "No record of who added this.");
  assert.equal(app.querySelector("a"), null, "no record: nothing to link");
  // An origin from an older dashboard (no changeId) keeps the line as it was.
  const old = rulesPage({ "GET policy/rules/origins": { ...origins, origins: { "r-0001": { ...origins.origins["r-0001"], changeId: undefined } } } });
  await tick();
  assert.equal(openRule(old.doc, /api\.example\.com/).querySelectorAll(".rule-origin a").length, 1);
  // Pressed: Approvals, at that change.
  (openRule(doc, /api\.example\.com/).querySelector(".rule-origin .change-link") as any).click();
  await tick();
  assert.equal(window.location.pathname, "/mandu/approvals/pc-000007");
  assert.equal(doc.getElementById("page-approvals").hidden, false);
});

// ── Built-in protections follow the running mode (dashboard.md §4.25z) ───────

const RULES_URL = "http://127.0.0.1:4500/mandu/rules";
const builtIn = (doc: any) => ({
  note: doc.getElementById("builtin-note").textContent as string,
  items: ([...doc.querySelectorAll("#builtin-list li")] as any[]).map((li) => li.textContent as string),
});

test("built-in protections: the Secrets mode does not claim masking and says untrusted content is not masked", async () => {
  const vm = home({
    protection: { level: "secrets", configured: "secrets", connected: true },
    builtIn: { note: "always on in the Secrets mode", items: ["Keys and secret files reach the AI masked, unless a rule lets the AI read them.", "Untrusted content is not masked in this mode: the AI reads it as-is."] },
  });
  const { doc } = load({ url: RULES_URL, homeVm: vm });
  await tick();
  const b = builtIn(doc);
  assert.equal(b.note, "always on in the Secrets mode");
  assert.ok(!b.items.some((t) => /is masked before the AI reads it/.test(t)), b.items.join(" | "));
  assert.ok(b.items.some((t) => /Untrusted content is not masked in this mode/.test(t)));
});

test("built-in protections: with masking on the masking sentence is shown; before the home and without it nothing is claimed", async () => {
  const vm = home({ builtIn: { note: "always on in the Full mode", items: ["Untrusted content is masked before the AI reads it.", "Keys and secret files leave this computer only where a rule or your OK allows."] } });
  const on = load({ url: RULES_URL, homeVm: vm });
  await tick();
  assert.deepEqual(builtIn(on.doc).items, ["Untrusted content is masked before the AI reads it.", "Keys and secret files leave this computer only where a rule or your OK allows."]);
  assert.match(HTML, /<ul class="plain-list" id="builtin-list"><\/ul>/, "the static page lists nothing");
  const down = load({ url: RULES_URL, routes: { "GET home": { status: 503, body: { unreachable: true } } } });
  await tick();
  const b = builtIn(down.doc);
  assert.equal(b.note, "not connected");
  assert.ok(!b.items.some((t) => /masked/.test(t)), b.items.join(" | "));
});

test("built-in protections: the issuer item lists each company with its hosts as code under a fold; off and unknown draw their words (§4.25z)", async () => {
  const SECRETS = { note: "always on in the Secrets mode", items: ["Keys and secret files leave this computer only where a rule or your OK allows."] };
  const draw = async (issuers: unknown) => {
    const { doc } = load({ url: RULES_URL, homeVm: home({ protection: { level: "secrets", configured: "secrets", connected: true }, builtIn: { ...SECRETS, issuers } }) });
    await tick();
    const items = [...doc.querySelectorAll("#builtin-list > li")] as any[];
    return { items, li: doc.querySelector("#builtin-list > li.builtin-issuers") as any };
  };
  // on, Stripe asking
  const partly = await draw(issuerItem({ read: true, raw: { issuers_off: ["stripe"] } }));
  assert.equal(partly.items.length, 2, "the sentence beside it stays, the item is one more");
  assert.equal(partly.items[0].textContent, "Keys and secret files leave this computer only where a rule or your OK allows.");
  const li = partly.li;
  assert.equal(li.dataset.state, "partly");
  assert.match(li.querySelector("span").textContent, /without asking\. Off for: Stripe\.$/);
  const fold = li.querySelector("details.more");
  assert.ok(fold, "the list is folded");
  assert.equal(fold.open, false);
  assert.equal(fold.querySelector("summary").textContent, "Which companies");
  const rows = [...fold.querySelectorAll(".issuer-list > li")] as any[];
  assert.deepEqual(rows.map((r) => r.textContent), ISSUER_TABLE.map((i) => `${i.name}${i.id === "stripe" ? " (asks)" : ""}: ${i.hosts.join(", ")}`));
  for (const [n, r] of rows.entries()) {
    assert.deepEqual([...r.querySelectorAll("code")].map((c: any) => c.textContent), [...ISSUER_TABLE[n]!.hosts], "each host is code");
  }
  const change = li.querySelector(".issuer-change");
  assert.deepEqual([...change.querySelectorAll("code")].map((c: any) => c.textContent), ["issuer_bindings: false", "policy.yaml", "issuer_bindings: { issuers_off: [stripe] }"]);
  assert.equal(li.querySelector("button, input, [role=switch]"), null, "no switch: policy.yaml text only");
  // off
  const off = (await draw(issuerItem({ read: true, raw: false }))).li;
  assert.equal(off.dataset.state, "off");
  assert.equal(off.querySelector("span").textContent, "Every key asks before it goes to its company's API (issuer_bindings is off in policy.yaml).");
  assert.equal(off.querySelector("details"), null, "no company list when it is off");
  assert.equal(off.querySelector(".issuer-change").textContent, "To turn it back on, remove issuer_bindings from policy.yaml.");
  // not read
  const unknown = (await draw(issuerItem({ read: false }))).li;
  assert.equal(unknown.dataset.state, "unknown");
  assert.match(unknown.textContent, /^Mandu could not read whether/);
  assert.equal(unknown.querySelector("details, .issuer-change"), null);
  // an older server sends no item: none is drawn
  assert.equal((await draw(undefined)).li, null);
});

test("built-in protections: a closed Which files fold under the masking item names the kinds and the places, each name as code, and links Your rules (§4.25z)", async () => {
  const MASKED = "Keys and secret files reach the AI masked, unless a rule lets the AI read them.";
  const KEPT = "Keys and secret files leave this computer only where a rule or your OK allows.";
  const SECRETS = { note: "always on in the Secrets mode", items: [MASKED, KEPT], issuers: null };
  const draw = async (builtIn: unknown, files: unknown = { ...home(), builtIn: { ...(builtIn as object), files: builtinFiles() } }) => {
    const vm = home({ protection: { level: "secrets", configured: "secrets", connected: true }, builtIn });
    const r = load({ url: RULES_URL, homeVm: vm, routes: { "GET home?files=1": files } });
    await tick();
    return { ...r, items: [...r.doc.querySelectorAll("#builtin-list > li")] as any[] };
  };
  const { doc, window, items, calls } = await draw({ ...SECRETS, filesAt: 0 });
  assert.equal(calls.filter((c: any) => c.url.endsWith("/api/home?files=1")).length, 1, "the lists are read once");
  assert.equal(items.length, 2, "the fold is inside the item, not one more");
  const li = items[0];
  assert.ok(li.classList.contains("builtin-files"));
  assert.ok(li.textContent.startsWith(MASKED));
  assert.equal(items[1].querySelector("details"), null, "the other item has no fold");
  const fold = li.querySelector("details.more");
  assert.equal(fold.open, false, "closed by default");
  assert.equal(fold.querySelector("summary").textContent, "Which files");
  const kinds = [...fold.querySelectorAll(".builtin-kinds > li")] as any[];
  assert.deepEqual(kinds.map((k) => [...k.querySelectorAll("code")].map((c: any) => c.textContent)), BUILTIN_FILE_KINDS.map((k) => [...k.names]), "each kind's names, as code");
  assert.equal(kinds[0].textContent, "Environment files: .env, .env.*, *.env, .envrc");
  assert.match(kinds.find((k) => /^A tool's saved sign-in/.test(k.textContent)).textContent, /\(in a tool's own folder\)$/);
  const heads = [...fold.querySelectorAll(".builtin-files-head")].map((h: any) => h.textContent);
  assert.deepEqual(heads, ["Named like this, in any folder:", `These places in your home folder (${BUILTIN_HOME_PLACES.length} places):`]);
  const runs = [...fold.querySelectorAll(".builtin-places")] as any[];
  assert.deepEqual([...runs[0].querySelectorAll("code")].map((c: any) => c.textContent), [...BUILTIN_HOME_PLACES], "every place, as code, in one run");
  assert.equal(runs[0].children.length, BUILTIN_HOME_PLACES.length, "one run of chips, not a row each");
  assert.match(runs[1].textContent, /^And these system files: \/etc\/shadow, /);
  assert.ok(!fold.textContent.includes("AppData"), "the Windows places are one line");
  assert.match(fold.textContent, /And the same stores in a Windows profile, under WSL\./);
  assert.match(fold.textContent, /And OpenCode's and Goose's own data, wherever it is kept\./);
  assert.match(fold.textContent, /Templates are left out: \.env\.example, secrets\.example\.json/);
  assert.equal(fold.querySelector("button, input, [role=switch]"), null, "no switch");
  const change = fold.querySelector(".builtin-files-change");
  assert.equal(change.textContent, "To make one of these readable by the AI, give it a rule of your own under Your rules: your rules are checked first.");
  const link = change.querySelector("a");
  assert.equal(link.textContent, "Your rules");
  assert.equal(link.getAttribute("href"), "/mandu/rules#your-rules");
  link.click();
  await tick();
  assert.equal(window.location.hash, "#your-rules");
  assert.equal(doc.activeElement, doc.querySelector("#rules-block h2"), "the click goes to the Your rules card (#rules-block)");
  // An older server sends no filesAt: the card is drawn as before, nothing read.
  const old = await draw(SECRETS);
  assert.deepEqual(old.items.map((i: any) => i.textContent), [MASKED, KEPT]);
  assert.equal(old.doc.querySelector("#builtin-list details"), null);
  assert.equal(old.calls.filter((c: any) => c.url.includes("files=1")).length, 0);
  // The lists cannot be read: the card as before, no empty fold.
  const failed = await draw({ ...SECRETS, filesAt: 0 }, { status: 503, body: { unreachable: true } });
  assert.deepEqual(failed.items.map((i: any) => i.textContent), [MASKED, KEPT]);
  assert.equal(failed.doc.querySelector("#builtin-list details"), null);
  // Full: the fold goes under the item `filesAt` names.
  const full = await draw({ note: "always on in the Full mode", items: ["Untrusted content is masked before the AI reads it.", MASKED], issuers: null, filesAt: 1 });
  assert.equal(full.items[0].querySelector("details"), null);
  assert.ok(full.items[1].querySelector("details.more"));
});

test("built-in protections is one column at every width, read top to bottom; the folds' lists of kinds and companies keep two columns (§4.25z)", async () => {
  // Until 2026-10-29 the list was a two-column `.plain-list` wider than
  // 760 px: the Secrets mode's sentences sat side by side, and its third one
  // beside an empty cell. jsdom lays out nothing, so this reads the columns
  // the served styles give the drawn card at each width (css-flatten.ts
  // stylesAt); the browser stack rules-builtin-one-column measures the boxes.
  const MASKED = "Keys and secret files reach the AI masked, unless a rule lets the AI read them.";
  const KEPT = "Keys and secret files leave this computer only where a rule or your OK allows.";
  const AS_IS = "Untrusted content is not masked in this mode: the AI reads it as-is.";
  const builtIn = { note: "always on in the Secrets mode", items: [MASKED, KEPT, AS_IS], filesAt: 0, issuers: issuerItem({ read: true, raw: undefined }) };
  const vm = home({ protection: { level: "secrets", configured: "secrets", connected: true }, builtIn });
  const { doc } = load({ url: RULES_URL, homeVm: vm, routes: { "GET home?files=1": { ...home(), builtIn: { ...builtIn, files: builtinFiles() } } } });
  await tick();
  const list = doc.getElementById("builtin-list");
  assert.deepEqual(([...list.children] as any[]).map((li) => li.className), ["builtin-files", "", "", "builtin-issuers"], "the three sentences, then the companies");
  const sheet = doc.createElement("style");
  doc.head.append(sheet);
  const cols = (e: any) => doc.defaultView.getComputedStyle(e).gridTemplateColumns;
  const raw = readFileSync(join(PUB, "mandu.css"), "utf8") + "\n" + readFileSync(join(PUB, "app.css"), "utf8");
  for (const width of [1280, 1000, 761, 760, 390]) {
    sheet.textContent = resolveCssVars(stylesAt(raw, width));
    assert.equal(cols(list), "minmax(0, 1fr)", `${width}px: one column`);
    const two = width > 760 ? "repeat(2, minmax(0, 1fr))" : "1fr";
    assert.equal(cols(list.querySelector(".builtin-kinds")), two, `${width}px: Which files' kinds as every other plain list`);
    assert.equal(cols(list.querySelector(".issuer-list")), two, `${width}px: Which companies as every other plain list`);
  }
});

// ── dashboard.md §4.34 "`~` is the dashboard's home" ─────────────────────────

test("§4.34 `~` is the dashboard's home: the page writes `~/…` only under the home folder it was served with; another account's home, or none, stays as recorded", async () => {
  const label = (path: string) => ({ path, levelClass: "strict", modelOk: false, scope: "exact", pattern: false, bindings: [], source: "user" });
  const labels = { panel: { labels: [label("/home/u/ws/.env"), label("/home/alice/ws/.env"), label("/Users/u/ws/.env")] } };
  const answered = { id: "egr-9", status: "approved", scope: "always", where: "file", target: "/home/u/.pgpass", count: 1, actions: [{ approve: false, label: "Block instead" }],
    plain: { subject: "/home/u/.pgpass", reach: "opening this file", effect: "Always allowed" }, sessions: [], resolvedAt: null };
  const panel = { panel: { ...RULES_PANEL.panel, queue: [...RULES_PANEL.panel.queue, answered] } };
  const agent = (cwd: string) => ({ id: "r1", agent: "Claude Code", title: "Task r1", cwd, startedAt: new Date().toISOString(), lastAt: new Date().toISOString(), state: "running",
    stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, holds: true, waiting: 0 });
  const shown = async (homeDir: string | null, cwd: string) => {
    const routes = { "GET policy/panel": panel, "GET secrets": labels, "GET home": home({ waiting: [], agents: [agent(cwd)] }) };
    const rules = load({ url: "http://127.0.0.1:4500/mandu/rules", homeDir, routes });
    const front = load({ homeDir, routes });
    await tick();
    assert.equal(rules.err, null);
    return {
      // The file rules (the panel's pattern rule is not a path).
      labels: treeRows(rules.doc).map((r) => r.querySelector(".file-name code").textContent).filter((t: string) => !t.includes("*")).sort(),
      answer: rowOf(rules.doc, /pgpass/).querySelector("code").textContent,
      agent: front.doc.querySelector("#home-agents .row.agent .agent-what").children[0].textContent,
    };
  };
  // Served from /home/u: its own files read `~/…`; alice's is hers, as recorded.
  const linux = await shown("/home/u", "/home/alice/ws");
  assert.deepEqual(linux.labels, ["/Users/u/ws/.env", "/home/alice/ws/.env", "~/ws/.env"]);
  assert.equal(linux.answer, "~/.pgpass", "an answer about one file names it as the file rules do");
  assert.equal(linux.agent, "Task r1 in /home/alice/ws", "an agent working in another account's folder is never in `~`");
  assert.equal((await shown("/home/u/", "/home/u/ws")).agent, "Task r1 in ~/ws", "a trailing slash on the served home changes nothing");
  // A macOS home folder is `~` too, and /home/u is then someone else's.
  const mac = await shown("/Users/u", "/Users/u/ws");
  // (the two /home ones share a folder heading, so each reads under it)
  assert.deepEqual(mac.labels, ["alice/ws/.env", "u/ws/.env", "~/ws/.env"]);
  assert.equal(mac.answer, "/home/u/.pgpass");
  assert.equal(mac.agent, "Task r1 in ~/ws");
  // A page served without a home folder writes every path as recorded.
  const none = await shown(null, "/home/u/ws");
  assert.deepEqual(none.labels, ["/Users/u/ws/.env", "alice/ws/.env", "u/ws/.env"], "no `~`: both /home ones under a /home heading");
  assert.equal(none.agent, "Task r1 in /home/u/ws");
});

// ── dashboard.md §4.25c "The subject's chip fits it" ─────────────────────────

// The product page's two stylesheets, in its own order, with the theme's
// tokens resolved (jsdom reads a shorthand holding a `var()` as nothing).
const STYLES = resolveCssVars(readFileSync(join(PUB, "mandu.css"), "utf8") + "\n" + readFileSync(join(PUB, "app.css"), "utf8"));

test("§4.25c a rule's subject chip is as wide as its words, never stretched across the column; its reach line and warning still span it", async () => {
  // Until 2026-10-08 `.rule-text` (a flex column) stretched the subject's
  // `<code>`, which has a background: in a browser `api.example.com` was a
  // grey bar across the row, like an empty field. jsdom does no layout, so
  // this reads the declared values the page's styles give the rendered rows.
  const warned = { id: "app:psql", kind: "lock", subject: "psql", effect: "program rule", reach: null, hits: null, actions: { remove: false, flip: null }, warning: "This program-wide rule no longer applies." };
  const panel = { panel: { ...RULES_PANEL.panel, yourRules: RULES_PANEL.panel.yourRules.map((r) => (r.id === "app:psql" ? warned : r)) } };
  const { doc } = rulesPage({ "GET policy/panel": panel });
  const s = doc.createElement("style");
  s.textContent = STYLES;
  doc.head.append(s);
  await tick();
  const css = (e: any) => doc.defaultView.getComputedStyle(e);
  const subjects = [...doc.querySelectorAll("#rules-list .row.rule .rule-text")] as any[];
  assert.deepEqual(subjects.map((t) => t.firstElementChild.textContent), ["api.example.com", "paste.example", "old.example", "psql"], "a host rule, two answers, a program rule");
  for (const text of subjects) {
    const chip = text.firstElementChild;
    assert.equal(chip.tagName, "CODE", "the subject is a chip");
    assert.equal(css(text).display, "flex");
    assert.equal(css(text).flexDirection, "column");
    assert.equal(css(chip).alignSelf, "flex-start", `${chip.textContent}: the chip keeps its own width, not the column's`);
    assert.equal(css(chip).overflowWrap, "anywhere", `${chip.textContent}: a long host still breaks inside its chip`);
  }
  const reach = rowOf(doc, /api\.example\.com/).querySelector(".rule-text > .dim");
  assert.equal(reach.textContent, "from any source to api.example.com");
  assert.notEqual(css(reach).alignSelf, "flex-start", "the reach line under it still spans the column");
  const warn = rowOf(doc, /psql/).querySelector(".rule-text > .rule-warn");
  assert.equal(warn.textContent, "This program-wide rule no longer applies.");
  assert.notEqual(css(warn).alignSelf, "flex-start", "and so does a warning");
});

test("§4.25c app.css: the chip in a rule's subject column keeps its own width", () => {
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  const text = rules.filter((r) => r.media === null && r.selectors.includes(".rule-text"));
  assert.ok(text.some((r) => declValue(r.block, "flex-direction") === "column"), "the subject column is a flex column");
  const chip = rules.filter((r) => r.media === null && r.selectors.includes(".rule-text code"));
  assert.deepEqual(chip.map((r) => declValue(r.block, "align-self")).filter(Boolean), ["flex-start"], "so its chip must not stretch");
  assert.ok(!rules.some((r) => r.selectors.some((sel) => /\.rule-text\b/.test(sel)) && declValue(r.block, "align-items") === "stretch"), "nothing stretches it back");
});

// ── §4.25p: the use line says when a rule last decided something ─────────────

test("§4.25p an opened rule says how often it decided something and when it last did, the clock time on hover; Never used, no moment, answers and page labels stay as they were", async () => {
  const yesterday = Date.now() - 86_400_000;
  const hoursAgo = Date.now() - 3 * 3_600_000;
  const uses: Record<string, { hits: number | null; lastHit: number | null }> = {
    "r-0001": { hits: 12, lastHit: yesterday },
    "lock:**/ws-*/memo/**": { hits: 1, lastHit: hoursAgo },
    "app:psql": { hits: 3, lastHit: null },
  };
  const never = { id: "r-0002", kind: "release-block", subject: "b.example", effect: "sending blocked", reach: "from any source to b.example", hits: 0, lastHit: null, actions: { remove: true, flip: "allow" } };
  const panel = { panel: { ...RULES_PANEL.panel, yourRules: [...RULES_PANEL.panel.yourRules.map((r) => ({ ...r, ...uses[r.id] })), never] } };
  const { doc } = rulesPage({ "GET policy/panel": panel });
  await tick();
  const useLine = (detail: any) => ([...detail.querySelectorAll(".dim")] as any[]).find((d) => /\buses?\b|^Never used$|^Your answer|^Added here$/.test(d.textContent));
  const iso = (ms: number) => new Date(ms).toISOString();

  const send = useLine(openRule(doc, /api\.example\.com/));
  assert.equal(send.textContent, "12 uses, the last yesterday");
  const at = send.querySelector("time.ago");
  assert.ok(at, "a time.ago, so the poll keeps it current (refreshWhen)");
  assert.equal(at.getAttribute("datetime"), iso(yesterday), "the moment of the last use");
  assert.match(at.getAttribute("title"), new RegExp(`^${CLOCK}$`), "the clock time on hover");

  assert.equal(useLine(openRule(doc, /b\.example/)).textContent, "Never used");
  assert.equal(useLine(openRule(doc, /b\.example/)).querySelector("time"), null);
  const app = useLine(openRule(doc, /psql/));
  assert.equal(app.textContent, "3 uses", "counted without a moment: the count alone");
  assert.equal(app.querySelector("time"), null);
  assert.equal(useLine(openRule(doc, /paste\.example/)).textContent, "Your answer, asked 3 times", "an answer has no use moment");

  // The file rule, opened in the Labeled tree, says the same words.
  treeRow(doc, /ws-\*\/memo/).click();
  const memo = useLine(opened(doc));
  assert.equal(memo.textContent, "1 use, 3 hours ago", "one use: no “the last”");
  assert.equal(memo.querySelector("time.ago").getAttribute("datetime"), iso(hoursAgo));
  treeRow(doc, /\.env/).click();
  assert.equal(useLine(opened(doc)).textContent, "Added here");
  assert.equal(useLine(opened(doc)).querySelector("time"), null);
});

// ── A send rule says when the mode leaves it nothing to decide (§4.25e) ──
// In the Secrets mode the gate never asks a rule for a host about a secret,
// and only secrets are masked: a host's send rule decides nothing, and says so.
const IDLE_WORDS = "Decides nothing in the Secrets mode: a rule for a host never covers your secrets, and this mode masks only secrets.";
const MODE_PANEL = { panel: { available: true, verdictsKnown: true,
  yourRules: [
    { id: "r-0031", kind: "release-block", subject: "paste.example", effect: "sending blocked", reach: null, hits: 0, actions: { remove: true, flip: "allow" },
      plain: { subject: "paste.example", reach: "sending any masked data", effect: "Always blocked" } },
    { id: "r-0032", kind: "release-allow", subject: "api.example.com", effect: "sending allowed", reach: null, hits: 0, actions: { remove: true, flip: "block" },
      plain: { subject: "api.example.com", reach: "sending any masked data", effect: "Always allowed" } },
    { id: "r-0033", kind: "release-block", subject: "old.example", effect: "sending blocked", reach: null, hits: 0, expired: true, actions: { remove: true, flip: null },
      plain: { subject: "old.example", reach: "sending any masked data", effect: "Expired, no longer used" } },
    { id: "connect:tcp:*:2222", kind: "connect-allow", subject: "*:2222", reach: null, hits: null, effect: "the agent may connect there", actions: { remove: true, flip: null },
      plain: { subject: "*:2222", reach: "your agent's programs connecting", effect: "Always allowed, from the agent's next start" } },
  ],
  queue: [
    { id: "egr-31", status: "denied", scope: "always", where: "network", target: "hooks.example", count: 1, actions: [{ approve: true, label: "Allow instead" }],
      plain: { subject: "hooks.example", reach: "sending only the file ~/app/.env", effect: "Always blocked" }, sessions: [], resolvedAt: null },
  ] } };
const modeLine = (row: any) => row.querySelector(".rule-mode-note");
const dotOf = (row: any) => row.querySelector(".label-pick")?.getAttribute("data-effect") ?? null;
const modeRows = (doc: any) => ({
  block: rowOf(doc, /paste\.example/), allow: rowOf(doc, /api\.example\.com/),
  connect: rowOf(doc, /2222/), answer: rowOf(doc, /hooks\.example/),
});

test("Rules: in the Secrets mode a host's send rule says it decides nothing, with a grey dot; answers and connection rules are unchanged", async () => {
  const { doc } = rulesPage({ "GET policy/panel": MODE_PANEL, "GET config/axes": axesGet(false, true) });
  await tick();
  const r = modeRows(doc);
  for (const [name, row] of [["block rule", r.block], ["allow rule", r.allow]] as const) {
    assert.equal(modeLine(row)?.textContent, IDLE_WORDS, `${name}: the line`);
    assert.ok(modeLine(row).classList.contains("dim"), `${name}: a muted note, as the row's others`);
    assert.equal(modeLine(row).previousElementSibling.textContent, "sending any masked data", `${name}: under its reach`);
    assert.equal(dotOf(row), "none", `${name}: a grey dot`);
  }
  assert.deepEqual(effects(r.block), ["Always blocked", "Always allowed"], "the menu's words are unchanged");
  assert.equal(modeLine(r.answer), null, "an answer about a file decides in this mode: no line");
  assert.equal(dotOf(r.answer), "block", "and keeps its red dot");
  assert.equal(modeLine(r.connect), null, "a connection rule: no line");
  assert.ok(r.connect.querySelector(".outcome.ok"), "and keeps its ✓");
  assert.equal(modeLine(rowOf(doc, /old\.example/)), null, "an expired rule already says it is no longer used: no line");
  assert.equal(doc.querySelectorAll("#rules-list .rule-mode-note").length, 2, "only the two send rules in force");
  // The opened row says it too.
  const detail = openRule(doc, /paste\.example/);
  assert.equal(detail.querySelector(".rule-mode-note")?.textContent, IDLE_WORDS, "the opened row's detail has the line");
});

test("Rules: with the integrity axis on, the axes unread, or protection off, send rules are drawn as before (no line, red and green)", async () => {
  for (const [what, axes] of [["full", axesGet(true, true)], ["unread", { status: 500, body: { error: "down" } }]] as const) {
    const { doc } = rulesPage({ "GET policy/panel": MODE_PANEL, "GET config/axes": axes });
    await tick();
    const r = modeRows(doc);
    assert.equal(doc.querySelectorAll("#rules-list .rule-mode-note").length, 0, `${what}: no line`);
    assert.equal(dotOf(r.block), "block", `${what}: the block rule's dot is red`);
    assert.equal(dotOf(r.allow), "allow", `${what}: the allow rule's dot is green`);
    assert.equal(openRule(doc, /paste\.example/).querySelector(".rule-mode-note"), null, `${what}: nor in the opened row`);
  }
  const off = rulesPage({ "GET policy/panel": MODE_PANEL, "GET config/axes": axesGet(false, false), "GET home": runs("off") });
  await tick();
  assert.equal(off.doc.querySelectorAll("#rules-list .rule-mode-note").length, 0, "off: no line, its own banner stands");
  assert.equal(off.doc.getElementById("rules-off").hidden, false);
});

test("Rules: in the Secrets mode the menu still turns a send rule around (the same change as before)", async () => {
  const { doc, calls } = rulesPage({
    "GET policy/panel": MODE_PANEL, "GET config/axes": axesGet(false, true),
    "POST policy/rules/change": { applied: true, changeId: "pc-000031" },
  });
  await tick();
  flip(rowOf(doc, /paste\.example/));
  await tick();
  assert.deepEqual(calls.find((c) => c.url.endsWith("/policy/rules/change"))!.body, { id: "r-0031", action: "allow" });
});
