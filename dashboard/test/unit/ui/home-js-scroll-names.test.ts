/**
 * home-js-scroll-names.test — a box on the product page that scrolls by
 * itself says what it holds (dashboard.md §4.25 *A box that scrolls says what
 * it holds*). Mandu-new.
 *
 * Chromium (since 130, as Firefox) makes a box that overflows and holds
 * nothing to focus a Tab stop of its own, so a keyboard can scroll it. A
 * screen reader reads that stop by its role and name. Until 2026-10-12 none
 * of the product page's had a name: a headless Chromium read the model
 * preview's list as every name in it run together, and a `<pre>` as a
 * "generic" named by all its text.
 *
 * jsdom has no layout, so "may scroll" is read off the page's own styles
 * (mandu.css + app.css applied, tokens resolved): an element whose computed
 * overflow is auto or scroll. Pins:
 *   - every rule of the product page's styles that scrolls is listed below,
 *     as holding controls (never a stop of its own) or as named, so a new one
 *     is a decision;
 *   - on each surface drawn (the agent page: a reply's fenced block, What was
 *     hidden, the real value, the note under your message; Rules: the model
 *     preview's list, a suggestion's policy.yaml lines, Changes to save's
 *     impact, the weaker-change question's two lists), every element that may
 *     scroll and holds something but nothing to focus has a role, never a
 *     bare generic, and a name; each box named here is one of them;
 *   - a name is the box's own words, never what it holds: the real value's
 *     box names the secret, never the value.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AGENT, FILES_ROUTES, FILES_URL, M, PUB, T, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, resolveCssVars, stripComments } from "./css-flatten.js";
import { boxRole, controlName, scrollFaults as faults, scrollStops } from "./control-names.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";
import { modelPickerVM, modelPreviewVM, type ModelPreviewWire } from "../../../src/view-model/suggestion-model.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
const STYLES = resolveCssVars(CSS);

/** The page's own styles, applied (jsdom cascades them). */
function styled(doc: El): void {
  const sheet = doc.createElement("style");
  sheet.textContent = STYLES;
  doc.head.append(sheet);
}

/** `box` is one of the stops under `root`, with this role and name. */
function named(root: El, box: El, role: string, name: string): void {
  assert.ok(box, `the box named "${name}" is drawn`);
  assert.ok(scrollStops(root).includes(box), `"${name}": it may scroll and holds nothing to focus`);
  assert.equal(boxRole(box), role, `"${name}": its role`);
  assert.equal(controlName(box), name);
}

// Every rule of the product page's styles that scrolls, and why it is no
// unnamed stop: it holds controls (Chromium never makes it a stop), or the
// page names it (drawn below).
const SCROLL_RULES: Record<string, string> = {
  "#nav": "holds links",
  ".files-list": "holds a row's buttons",
  ".files-pending": "holds Save and Discard",
  ".files-pending > .files-pending-list": "holds Drop and Skip",
  ".code-block": "named: Code",
  ".hidden-text": "named: What was hidden, The real value",
  ".files-pending > .files-impact": "named: What this changes",
  "#files-confirm-list": "named: These changes make protection weaker.",
  ".files-confirm-files ul": "named: Files that become less protected",
  ".suggest-model-list": "named: its caption's words",
  ".suggestion-yaml": "named: Save adds these lines to policy.yaml:",
};

test("every rule of the product page's styles that scrolls is listed: it holds controls, or the page names it", () => {
  const found: string[] = [];
  for (const r of flattenCss(stripComments(CSS))) {
    if (["overflow", "overflow-x", "overflow-y"].some((p) => /\b(auto|scroll)\b/.test(declValue(r.block, p) ?? ""))) found.push(...r.selectors);
  }
  assert.deepEqual(found.sort(), Object.keys(SCROLL_RULES).sort(), "a new box that scrolls: name it (or say what it holds), here and in dashboard.md §4.25");
});

test("the agent page: a reply's fenced block, What was hidden and the real value are named groups; a name never holds the value", async () => {
  const two = { ...AGENT.story[0].steps[1], id: "t2b", split: { ...AGENT.story[0].steps[1].split, hidden: { text: null, secret: true, truncated: false,
    secrets: [{ ref: "aaaaaaaaaaaaaaaaaaaaaaaa", name: "API_KEY" }, { ref: "bbbbbbbbbbbbbbbbbbbbbbbb", name: "DB_PASS" }] } } };
  const agent = { ...AGENT, waiting: [], earlier: 0, story: [
    { ...AGENT.story[0], steps: [...AGENT.story[0].steps, two],
      reply: { ts: "2026-09-25T10:00:04.000Z", parts: [T("Run it:\n```bash\nnpm test -- --reporter=spec --grep 'a very long pattern that a narrow window cuts'\n```\nwith "), M("secret"), T(".")], ai: null } },
  ] };
  const value = (ref: string) => (ref.startsWith("a") ? "sk-live-scrollNamesValue1" : ref.startsWith("b") ? "db-pass-scrollNamesValue2" : "sk-live-scrollNamesValue0");
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": agent, "POST home/reveal": (b: El) => ({ value: value(b.ref) }) } });
  styled(doc);
  await tick();
  const story = doc.getElementById("agent-story");
  assert.deepEqual(faults(story), [], "before any reveal");
  named(story, story.querySelector("pre.code-block"), "group", "Code");
  assert.match(story.querySelector("pre.code-block").textContent, /^npm test/, "the block holds the code");

  // What was hidden, shown.
  const masked = story.querySelector(".step.split");
  masked.querySelector("button.reveal").click();
  named(story, masked.querySelector("pre.hidden-text"), "group", "What was hidden");

  // The real value of one secret, and of each of two.
  for (const b of [...story.querySelectorAll("button.secret-reveal")] as El[]) b.click();
  await tick();
  const boxes = [...story.querySelectorAll("pre.secret-value")] as El[];
  assert.equal(boxes.length, 3);
  named(story, boxes[0], "group", "The real value");
  named(story, boxes[1], "group", "The real value of API_KEY");
  named(story, boxes[2], "group", "The real value of DB_PASS");
  assert.deepEqual(boxes.map((b) => b.textContent), ["sk-live-scrollNamesValue0", "sk-live-scrollNamesValue1", "db-pass-scrollNamesValue2"], "each box holds its value");
  for (const b of boxes) assert.doesNotMatch(controlName(b), /scrollNamesValue/, "a name never holds the value");
  assert.deepEqual(faults(story), [], "with every box shown");
});

test("the note under your message: What was hidden, shown, is a named group", async () => {
  const note = {
    lines: ["One value in your prompt was hidden from the AI (an email address)."],
    items: [{ eventId: "ev-1", index: 0, category: "pii.email", words: "an email address", state: "hidden", canLetOnce: false, canLetSession: false, canShow: true }],
    ts: "2026-09-25T10:00:00.000Z",
  };
  const agent = { ...AGENT, story: [{ ...AGENT.story[0], promptNote: note }, { ...AGENT.story[1], promptNote: null }] };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: {
    "GET home/agent?session=s1": agent,
    "POST prompt-filters/reveal": { original: "me@corp.example, written out in a line long enough to scroll" },
  } });
  styled(doc);
  await tick();
  doc.querySelector("#agent-story .prompt-reveal").click();
  await tick();
  const story = doc.getElementById("agent-story");
  named(story, story.querySelector("pre.prompt-hidden-text"), "group", "What was hidden");
  assert.deepEqual(faults(story), []);
});

const HOME = "/home/u";
const preview = (over: Partial<ModelPreviewWire>): ModelPreviewWire => ({
  axis: true, tier: "contents", digest: "b".repeat(64),
  destination: { kind: "declared", name: "ollama", location: "local", placement: "host", vendor: "127.0.0.1" },
  roots: [{ index: 1, root: `${HOME}/proj`, files: 40 }], items: 40, bytes: 40_000, requests: 1, names: [],
  files: Array.from({ length: 40 }, (_, i) => ({ root: 1, name: `notes/meeting-notes-${i}.md`, bytes: 1000, truncated: false })),
  left: { covered: 0, labelled: 0, tooLong: 0, personal: 0, overCap: 0, detector: 0, registered: 0, flagged: 0, unread: 0 },
  promptVersion: "contents-1", confine: { live: true }, expiresAt: 1, walk: { examined: 40, covered: 0, capped: [] },
  ...over,
});

test("Rules › Ask a model too: the preview's list is named by its caption's words, not the capitals drawn; an empty preview names nothing", async () => {
  let next = preview({});
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES,
    "GET suggestions": { suggestions: [], count: 0, scan: null, model: modelPickerVM(true, [{ name: "ollama", local: true }]) },
    "POST suggestions/model/preview": () => ({ preview: modelPreviewVM(next, HOME) }),
  } });
  styled(doc);
  await tick();
  doc.getElementById("suggest-open").click();
  await tick();
  const sel = doc.getElementById("suggest-model-tier");
  sel.value = "contents";
  sel.dispatchEvent(new doc.defaultView.Event("change"));
  doc.getElementById("suggest-model-run").click();
  await tick();
  const box = doc.getElementById("suggest-model-preview");
  const list = doc.getElementById("suggest-model-list");
  assert.equal(box.hidden, false);
  assert.equal(list.children.length, 40);
  assert.equal(doc.getElementById("suggest-model-caption").textContent, "The files it reads (their text is not shown here)");
  named(box, list, "list", "The files it reads (their text is not shown here)");
  assert.equal(list.getAttribute("aria-labelledby"), null, "the caption's words, never the caption: it is drawn in capitals");
  assert.deepEqual(faults(box), []);

  // Nothing to send: an empty list, no name left from the last preview.
  doc.getElementById("suggest-model-cancel").click();
  next = preview({ digest: "", items: 0, files: [], roots: [] });
  doc.getElementById("suggest-model-run").click();
  await tick();
  assert.equal(box.hidden, false);
  assert.equal(list.children.length, 0);
  assert.equal(list.getAttribute("aria-label"), null, "an empty list keeps no name");
});

const SUGGESTION: SuggestionWire = {
  id: "pp-000001", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "k1", source: "workspace-scan", repoRoot: `${HOME}/proj`,
  edits: [{ op: "lock-path", path: `${HOME}/proj/services/payments/settlement/config/production/app.conf`, level: "no-model" }],
  sentence: "Make ~/proj/services/payments/settlement/config/production/app.conf a secret no AI may read",
  evidence: { paths: ["services/payments/settlement/config/production/app.conf"], blobs: [], historyOnly: false,
    findings: [{ blob: "a".repeat(40), paths: ["services/payments/settlement/config/production/app.conf"], firstCommit: null, lastCommit: null, inHead: true, inIndex: false, stillPresent: true,
      detectors: [{ kind: "content-shape", rule: "stripe-key", mask: "sk_live_…", words: "Stripe key", line: 2 }] }] },
  impact: { historicalVersions: 0, workingTreeChanges: true, files: ["services/payments/settlement/config/production/app.conf"] },
  historyOnly: false, rotate: false, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
} as unknown as SuggestionWire;

test("Rules › Keys Mandu found: a suggestion's policy.yaml lines are a group named by the words above them", async () => {
  const { doc, window } = load({ url: FILES_URL, routes: { ...FILES_ROUTES,
    "GET suggestions": { suggestions: suggestionRows([SUGGESTION], HOME, "linux"), count: 1, scan: null },
  } });
  styled(doc);
  await tick();
  doc.getElementById("suggest-open").click();
  await tick();
  doc.querySelector("#files-suggested-list .row.suggested .file-name").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  const detail = doc.querySelector("#files-suggested-list .file-detail");
  ([...detail.querySelectorAll("button")] as El[]).find((b) => b.textContent === "Show in policy.yaml").click();
  const pre = detail.querySelector("pre.suggestion-yaml");
  named(detail, pre, "group", "Save adds these lines to policy.yaml:");
  assert.equal(pre.previousElementSibling.textContent, "Save adds these lines to policy.yaml:", "the words just above it");
  assert.match(pre.textContent, /^paths:\n {2}- path: \/home\/u\/proj\/services\/payments/);
  assert.deepEqual(faults(doc.getElementById("suggested-block")), []);
});

test("Rules › Changes to save: what this changes and the weaker-change question's two lists are named", async () => {
  const pending = Array.from({ length: 6 }, (_, i) => ({
    path: `/home/u/ws/p${i}/config.yaml`, display: `~/ws/p${i}/config.yaml`, level: "public",
    bindings: [], recursive: false, before: "No AI", target: null,
  }));
  const weaker = pending.map((p) => ({ path: p.path, display: p.display, before: "No AI", after: "Not secret", weaker: true }));
  const impact = { scanned: 6, truncated: false, changed: 6, weaker: 6, files: weaker, decidedBy: {} };
  let checked: unknown = { impact: { scanned: 6, truncated: false, changed: 0, weaker: 0, files: [], decidedBy: {} }, page: 0 };
  const { doc } = load({ url: FILES_URL, storage: { "mandu.files.pending": JSON.stringify(pending) }, routes: { ...FILES_ROUTES,
    "POST files/impact": () => checked,
    "POST files/labels": { applied: false, confirm: true, expected: ["k"], impact, loosens: weaker.map((f) => ({ subject: f.display, detail: "Becomes Not secret." })) },
  } });
  styled(doc);
  await tick();
  const bar = doc.getElementById("files-pending");
  const what = doc.getElementById("files-impact");
  assert.equal(bar.hidden, false);
  assert.equal(what.textContent, "No file under these changes gets a different label.");
  named(bar, what, "status", "What this changes");

  // With the files listed under its fold, it holds a control: no stop of its own.
  checked = { impact, page: 0 };
  doc.querySelector("#files-pending-list button").click(); // Drop one: the impact is worked out again
  await tick();
  assert.ok(what.querySelector("details summary"));
  assert.equal(scrollStops(bar).includes(what), false, "the fold's summary takes the focus");
  assert.equal(controlName(what), "What this changes", "and it keeps its name");

  // The question.
  doc.getElementById("files-save").click();
  await tick();
  assert.equal(doc.getElementById("files-confirm").hidden, false);
  named(bar, doc.getElementById("files-confirm-list"), "list", "These changes make protection weaker.");
  named(bar, doc.querySelector("#files-confirm-files ul"), "list", "Files that become less protected:");
  assert.deepEqual(faults(bar), []);
});
