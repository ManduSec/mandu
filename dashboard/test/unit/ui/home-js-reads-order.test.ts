/**
 * home-js-reads-order.test — on the agent page, Rules and Settings, a read
 * asked before your change never draws over it (public/js/home.js
 * `readsInOrder`: `AGENT_READS`, `RULES_READS`, `MODEL_READS`, `LABEL_READS`,
 * `PROMPT_READS`, `AXES_READS`; dashboard.md §4.25 *A read asked before your
 * change never draws over it*).
 *
 * The agent page is read by every Home poll and after an answer; Your rules
 * on opening Rules and after each change made there; each Settings card on
 * opening Settings and after each change made in it; the protection switch's
 * saved setting by Settings and by Rules, and answered by a flip. Until
 * 2026-10-12 the answer that came LAST drew, even when its read was asked
 * first, so on a slow network:
 *
 *   - a question you answered on the agent page came back as waiting, with
 *     live Allow once, Always allow and Block, until the next poll;
 *   - after two changes in Your rules, the read after the first, answered
 *     last, drew the second rule with its old effect under the notice
 *     "Now always allowed.", and a removed rule or model came back;
 *   - protection turned off drew On again, with the words that promise it
 *     guards your secrets, while config.toml said off (and the same the
 *     other way).
 *
 * Now an answer to a read asked before the latest one taken, or before a
 * change of yours to that list answered, is dropped: every change that
 * worked marks its list (`wrote()`), a refused one marks nothing, and reads
 * answered in the order they were asked are each drawn. Each read here is
 * answered with what the stub server holds at the moment it is read, as a
 * server answers, and a held one is sent when the test releases it; each
 * read of a list also carries a marker row of its own (`read-<n>`), so the
 * test sees which read drew. Drives home.js in jsdom over the shared fetch
 * stub (home-js-fixtures.ts); across the real arbiter, net-proxy and
 * dashboard, tests/stack/product-reads-order.test.ts and (the switch)
 * protection-switch-order.test.ts. Axes: none (display only). Mandu-new
 * test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, ASK, FILES_ROUTES, home, load, tick } from "./home-js-fixtures.js";
import { labelSettingsVM } from "../../../src/view-model/sensitivity-labels.js";
import { promptSettingsVM } from "../../../src/view-model/prompt-settings.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** A GET answered with what `now(n)` says when the n-th read reaches it, as
 *  a server answers; `hold()` keeps the next read's answer until released
 *  (or failed: no answer, as with the dashboard gone). */
function gated(now: (n: number) => unknown) {
  let n = 0;
  const armed: Array<{ gate: Promise<void> }> = [];
  return {
    route: () => {
      const v = now(++n);
      const h = armed.shift();
      return h ? h.gate.then(() => v) : v;
    },
    hold() {
      let release!: () => void;
      let fail!: (e: unknown) => void;
      const gate = new Promise<void>((a, b) => { release = a; fail = b; });
      armed.push({ gate });
      return { release, fail: () => fail(new TypeError("Failed to fetch")) };
    },
    get reads() { return n; },
  };
}
/** The marker rows a page drew: which reads it took. */
const markers = (root: Doc): string[] => [...new Set((root.textContent.match(/read-\d+/g) ?? []) as string[])];
const button = (root: Doc, label: string) => root && [...root.querySelectorAll("button")].find((b: Doc) => b.textContent === label);
const go = async (doc: Doc, page: string) => { doc.querySelector(`#nav [data-page-link="${page}"]`).click(); await tick(30); };
/** A poll, as a return to the tab makes one. */
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}
/** A pick in a menu, as a person makes it. */
function pick(sel: Doc, value: string): void {
  sel.focus();
  sel.value = value;
  sel.dispatchEvent(new sel.ownerDocument.defaultView.Event("change", { bubbles: true }));
}

// ── The agent page ───────────────────────────────────────────────────────────

const AGENT_URL = "http://127.0.0.1:4500/mandu/agents/s1";
const AGENT_PATH = "GET home/agent?session=s1";
/** The agent page as the stub server holds it, with its read marked. */
const agentAt = (waiting: unknown[]) => (n: number) => ({ ...AGENT, title: `Fix the test read-${n}`, waiting });
const waitingCards = (doc: Doc): Doc[] => [...doc.querySelectorAll("#agent-waiting .ask")];
const liveAnswers = (doc: Doc): Doc[] => [...doc.querySelectorAll("#agent-waiting button")].filter((b: Doc) => !b.disabled && b.textContent !== "?");
const agentTitle = (doc: Doc): string[] => markers(doc.getElementById("agent-sub"));

/** The agent page with ASK waiting; Allow once answers it. */
function agentPage(ask: Record<string, unknown> = ASK, routes: Record<string, unknown> = {}) {
  let waiting: unknown[] = [ask];
  const reads = gated((n) => agentAt(waiting)(n));
  const answered = () => { waiting = []; return {}; };
  const page = load({ url: AGENT_URL, routes: {
    [AGENT_PATH]: reads.route,
    "POST egress/approvals/egr-1/approve-once": answered,
    "POST egress/approvals/egr-1/always-source": () => (answered(), { released: true, left: [] }),
    ...routes,
  } });
  // The Home poll answers that nothing waits once it was answered.
  return { ...page, reads, answered: () => page.setHome(home({ waiting, waitingKnown: true })) };
}

test("the agent page: a poll's read asked before your answer, answered after the read that follows it, never draws the question again", async () => {
  const { doc, reads } = agentPage();
  await tick(40);
  assert.equal(waitingCards(doc).length, 1, "the question waits");
  const before = reads.hold();
  await poll(doc); // its read of the page is held
  const allow = button(waitingCards(doc)[0], "Allow once");
  allow.focus();
  allow.click();
  await tick(40);
  assert.equal(waitingCards(doc).length, 0, "the read after the answer draws none");
  assert.match(doc.getElementById("agent-waiting").textContent, /Nothing is waiting/);
  const drawn = agentTitle(doc);
  const focused = doc.activeElement;
  before.release();
  await tick(40);
  assert.equal(waitingCards(doc).length, 0, "never drawn as waiting again");
  assert.deepEqual(liveAnswers(doc), [], "no live Allow once, Always allow or Block");
  assert.deepEqual(agentTitle(doc), drawn, "the older read drew nothing");
  assert.equal(doc.activeElement, focused, "the focus stays");
  await poll(doc);
  assert.equal(waitingCards(doc).length, 0, "the next poll still draws: the page did not stop taking answers");
  assert.deepEqual(agentTitle(doc), [`read-${reads.reads}`]);
});

test("the agent page: an older read that answers before the read after your answer never draws the question either", async () => {
  const { doc, reads } = agentPage();
  await tick(40);
  const before = reads.hold();
  await poll(doc);
  const after = reads.hold();
  button(waitingCards(doc)[0], "Allow once").click();
  await tick(40);
  const drawn = agentTitle(doc);
  before.release();
  await tick(40);
  assert.deepEqual(liveAnswers(doc), [], "no live Allow once, Always allow or Block from the older read");
  assert.deepEqual(agentTitle(doc), drawn, "the older read drew nothing");
  after.release();
  await tick(40);
  assert.deepEqual(agentTitle(doc), [`read-${reads.reads}`], "the read after the answer is drawn");
  assert.equal(waitingCards(doc).length, 0);
});

test("the agent page: Always for one file (a program's send) marks the page's reads as an answer does", async () => {
  const sources = { ...ASK, sources: [{ name: "~/proj/.env", path: "/home/u/proj/.env", via: null, mayGo: "may go to api.stripe.com.", blocks: true, always: "Always: add collector.example to ~/proj/.env" }] };
  const { doc, reads } = agentPage(sources);
  await tick(40);
  const before = reads.hold();
  await poll(doc);
  const after = reads.hold();
  const always = button(waitingCards(doc)[0], "Always: add collector.example to ~/proj/.env");
  assert.ok(always, "the card offers Always for the file");
  always.click();
  await tick(40);
  const drawn = agentTitle(doc);
  before.release();
  await tick(40);
  assert.deepEqual(liveAnswers(doc), [], "no live Always from the older read");
  assert.deepEqual(agentTitle(doc), drawn, "the older read drew nothing");
  after.release();
  await tick(40);
  assert.equal(waitingCards(doc).length, 0, "the read after it is drawn");
});

test("the agent page: a refused answer marks nothing, so a read asked before it is still drawn", async () => {
  const { doc, reads } = agentPage(ASK, { "POST egress/approvals/egr-1/approve-once": { status: 403, body: { error: "admin session required" } } });
  await tick(40);
  const before = reads.hold();
  await poll(doc);
  button(waitingCards(doc)[0], "Allow once").click();
  await tick(40);
  assert.match(waitingCards(doc)[0].querySelector(".ask-error").textContent, /^Sign in first/);
  before.release();
  await tick(40);
  assert.deepEqual(agentTitle(doc), [`read-${reads.reads}`], "newer than anything the page knows: drawn");
  assert.match(waitingCards(doc)[0].querySelector(".ask-error").textContent, /^Sign in first/, "the refusal's words stay");
});

test("the agent page: reads answered in the order they were asked are each drawn, an older one after a newer is dropped, a failure too", async () => {
  const { doc, reads } = agentPage();
  await tick(40);
  const a = reads.hold();
  await poll(doc);
  const b = reads.hold();
  await poll(doc);
  const na = reads.reads - 1;
  a.release();
  await tick(40);
  assert.deepEqual(agentTitle(doc), [`read-${na}`], "the older read, first in, is drawn");
  b.release();
  await tick(40);
  assert.deepEqual(agentTitle(doc), [`read-${na + 1}`], "then the newer");
  const c = reads.hold();
  await poll(doc);
  const d = reads.hold();
  await poll(doc);
  d.release();
  await tick(40);
  const newest = agentTitle(doc);
  c.fail();
  await tick(40);
  assert.deepEqual(agentTitle(doc), newest, "an older read that fails after a newer one never draws \"could not be loaded\"");
  assert.notEqual(doc.getElementById("agent-name").textContent, "Session not loaded");
});

// ── Rules › Your rules ───────────────────────────────────────────────────────

const RULES_URL = "http://127.0.0.1:4500/mandu/rules";
const sendRule = (id: string, host: string, mode: "allow" | "block") => ({
  id, kind: `release-${mode}`, subject: host, effect: mode === "allow" ? "sending allowed" : "sending blocked",
  reach: `from any source to ${host}`, hits: 1, actions: { remove: true, flip: mode === "allow" ? "block" : "allow" },
});
const answerRow = (id: string, host: string, approved: boolean) => ({
  id, status: approved ? "approved" : "denied", scope: "always", where: "network", target: host, count: 1,
  actions: [{ approve: !approved, label: approved ? "Block instead" : "Allow instead" }],
  plain: { subject: host, reach: null, effect: approved ? "Always allowed" : "Always blocked" },
  sessions: [], resolvedAt: null,
});
const ruleRow = (doc: Doc, host: string) => [...doc.querySelectorAll("#rules-list .row.rule")].find((r: Doc) => r.querySelector(".rule-text code")?.textContent === host);
const menuOf = (doc: Doc, host: string) => ruleRow(doc, host)?.querySelector("select.effect-select");
const effectOf = (doc: Doc, host: string): string => menuOf(doc, host).options[0].textContent;
const openedUnder = (doc: Doc, host: string) => {
  const more = ruleRow(doc, host).querySelector(".file-more");
  if (more.getAttribute("aria-expanded") !== "true") more.click();
  return ruleRow(doc, host).nextElementSibling;
};
const rulesMarkers = (doc: Doc) => markers(doc.getElementById("rules-list"));

/** The Rules page over a stub server that follows the changes posted. */
function rulesPage(routes: Record<string, unknown> = {}, labels: unknown[] = []) {
  let yourRules: unknown[] = [sendRule("r-0001", "api.example.com", "allow"), sendRule("r-0002", "b.example", "block")];
  let queue: unknown[] = [answerRow("egr-7", "paste.example", true), answerRow("egr-6", "old.example", false)];
  const panel = gated((n) => ({ panel: { available: true, verdictsKnown: true, queue, yourRules: [...yourRules, sendRule(`rk-${n}`, `read-${n}.example`, "block")] } }));
  const added = (host: string) => { yourRules = [...yourRules, sendRule(`r-${host}`, host, "block")]; };
  const page = load({ url: RULES_URL, routes: {
    ...FILES_ROUTES,
    "GET policy/panel": panel.route,
    "GET secrets": { panel: { labels } },
    "POST policy/rules/change": (b: { id: string; action: string }) => {
      if (b.action === "remove") yourRules = yourRules.filter((r) => (r as { id: string }).id !== b.id);
      else yourRules = yourRules.map((r) => ((r as { id: string }).id === b.id ? sendRule(b.id, (r as { subject: string }).subject, b.action as "allow" | "block") : r));
      return { applied: true, changeId: "pc-0007" };
    },
    "POST egress/approvals/egr-7/deny": () => { queue = queue.map((q) => ((q as { id: string }).id === "egr-7" ? answerRow("egr-7", "paste.example", false) : q)); return { approval: { id: "egr-7" } }; },
    "POST egress/approvals/egr-6/forget": () => { queue = queue.filter((q) => (q as { id: string }).id !== "egr-6"); return { approval: { id: "egr-6" } }; },
    "POST policy/changes/pc-0007/undo": () => { yourRules = [sendRule("r-0001", "api.example.com", "allow"), sendRule("r-0002", "b.example", "block")]; return { ok: true }; },
    "POST files/labels": () => (added("labelled.example"), { applied: true, changeId: "pc-0008" }),
    "POST files/move-page-rules": () => (added("moved.example"), { moved: 1, changeId: "pc-0009" }),
    "POST policy/assistant": { model: "m", note: "", rows: [{ parts: [{ kind: "text", text: "Lock ~/.ssh" }], loosens: false, overBroad: false }], loosens: [], edits: [{ op: "lock-path", path: "~/.ssh", level: "no-model" }], expected: [] },
    "POST policy/assistant/apply": () => (added("applied.example"), { applied: true, changeId: "pc-0010" }),
    ...routes,
  } });
  return { ...page, panel, added };
}

test("Your rules: after two changes, the read after the first, answered last, never draws the second rule with its old effect", async () => {
  const { doc, panel } = rulesPage();
  await tick(30);
  assert.equal(effectOf(doc, "b.example"), "sending blocked");
  const first = panel.hold();
  pick(menuOf(doc, "api.example.com"), "flip"); // its read is held
  await tick(30);
  pick(menuOf(doc, "b.example"), "flip");
  await tick(30);
  assert.equal(effectOf(doc, "b.example"), "sending allowed", "the read after the second change is drawn");
  assert.equal(effectOf(doc, "api.example.com"), "sending blocked");
  assert.equal(doc.getElementById("rules-notice").firstChild.textContent, "Now always allowed.");
  const drawn = rulesMarkers(doc);
  const menu = menuOf(doc, "b.example");
  assert.equal(doc.activeElement, menu, "the focus is on the changed rule's menu");
  first.release();
  await tick(30);
  assert.equal(effectOf(doc, "b.example"), "sending allowed", "never \"sending blocked\" under \"Now always allowed.\"");
  assert.deepEqual(rulesMarkers(doc), drawn, "the older read drew nothing");
  assert.equal(doc.activeElement, menu, "the focus stays");
});

test("Your rules: a refused change marks nothing, so the read after an earlier change is still drawn", async () => {
  const { doc, panel } = rulesPage({ "POST egress/approvals/egr-7/deny": { status: 403, body: { error: "admin session required" } } });
  await tick(30);
  const first = panel.hold();
  pick(menuOf(doc, "api.example.com"), "flip");
  await tick(30);
  pick(menuOf(doc, "paste.example"), "flip");
  await tick(30);
  assert.match(ruleRow(doc, "paste.example").querySelector(".ask-error").textContent, /^Sign in first/);
  first.release();
  await tick(30);
  assert.equal(effectOf(doc, "api.example.com"), "sending blocked", "the read after the first change is drawn");
  assert.deepEqual(rulesMarkers(doc), [`read-${panel.reads}`]);
});

test("Your rules: reads answered in the order they were asked are each drawn, an older one after a newer is dropped", async () => {
  const { doc, panel } = rulesPage();
  await tick(30);
  const a = panel.hold();
  await go(doc, "home");
  await go(doc, "rules");
  const b = panel.hold();
  await go(doc, "home");
  await go(doc, "rules");
  const na = panel.reads - 1;
  a.release();
  await tick(30);
  assert.deepEqual(rulesMarkers(doc), [`read-${na}`], "the older read, first in, is drawn");
  b.release();
  await tick(30);
  assert.deepEqual(rulesMarkers(doc), [`read-${na + 1}`], "then the newer");
  const c = panel.hold();
  await go(doc, "home");
  await go(doc, "rules");
  const d = panel.hold();
  await go(doc, "home");
  await go(doc, "rules");
  d.release();
  await tick(30);
  c.release();
  await tick(30);
  assert.deepEqual(rulesMarkers(doc), [`read-${panel.reads}`], "an older read that answers after a newer one is dropped");
});

/** Each change made on Rules: what it does, once the page is drawn. A read
 *  asked before it (Rules opened again) is held across it, and so is the
 *  read after it; the older one, sent first, must draw nothing. */
const RULES_CHANGES: Array<{ name: string; act: (doc: Doc, window: Doc) => Promise<void> | void; labels?: unknown[]; routes?: Record<string, unknown>; open?: (doc: Doc) => Promise<void> | void; done: (doc: Doc) => boolean }> = [
  { name: "a rule's menu", act: (doc) => pick(menuOf(doc, "b.example"), "flip"), done: (doc) => effectOf(doc, "b.example") === "sending allowed" },
  { name: "Remove under a rule", act: (doc) => button(openedUnder(doc, "b.example"), "Remove").click(), done: (doc) => !ruleRow(doc, "b.example") },
  { name: "an answer's menu", act: (doc) => pick(menuOf(doc, "paste.example"), "flip"), done: (doc) => effectOf(doc, "paste.example") === "Always blocked" },
  { name: "Remove under an answer", act: (doc) => button(openedUnder(doc, "old.example"), "Remove").click(), done: (doc) => !ruleRow(doc, "old.example") },
  {
    name: "the notice's Undo",
    open: async (doc) => { pick(menuOf(doc, "api.example.com"), "flip"); await tick(30); },
    act: (doc) => button(doc.getElementById("rules-notice"), "Undo").click(),
    done: (doc) => effectOf(doc, "api.example.com") === "sending allowed",
  },
  {
    name: "Save under Changes to save",
    open: async (doc) => { doc.getElementById("rules-add").click(); await tick(30); },
    act: (doc) => {
      const row = [...doc.querySelectorAll("#files-list .row.file:not(.up)")].find((r: Doc) => /^README\.md/.test(r.querySelector(".file-name").textContent));
      pick(row.querySelector("select.label-select"), "no-model");
      doc.getElementById("files-save").click();
    },
    done: (doc) => !!ruleRow(doc, "labelled.example"),
  },
  {
    name: "Move them into policy.yaml",
    labels: [{ path: "/home/u/ws/.env", levelClass: "strict", modelOk: false, scope: "exact", pattern: false, bindings: [], source: "user" }],
    act: (doc) => doc.querySelector("#files-move button").click(),
    done: (doc) => !!ruleRow(doc, "moved.example"),
  },
  {
    name: "Apply under Describe what you want",
    open: async (doc) => {
      doc.getElementById("describe-text").value = "Keep ~/.ssh secret.";
      doc.getElementById("describe-form").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
      await tick(30);
    },
    act: (doc) => button(doc.getElementById("describe-result"), "Apply").click(),
    done: (doc) => !!ruleRow(doc, "applied.example"),
  },
  {
    name: "Save of a key Mandu found",
    routes: {
      "GET suggestions": { suggestions: suggestionRows([{
        id: "pp-000001", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "k-1", source: "git-history", repoRoot: "/home/u/proj",
        edits: [{ op: "lock-path", path: "/home/u/proj/deploy/id_rsa", level: "no-model" }],
        sentence: "Make ~/proj/deploy/id_rsa a secret no AI may read (only in git history)",
        evidence: { paths: ["deploy/id_rsa"], blobs: ["a".repeat(40)], historyOnly: true, findings: [] },
        impact: { historicalVersions: 2, workingTreeChanges: false, files: [] },
        historyOnly: true, rotate: true, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
      } as SuggestionWire], "/home/u", "linux"), count: 1, scan: null },
    },
    open: async (doc) => { doc.getElementById("suggest-open").click(); await tick(30); },
    act: (doc) => doc.getElementById("files-save").click(),
    done: (doc) => !!ruleRow(doc, "suggested.example"),
  },
];

for (const change of RULES_CHANGES) {
  test(`Your rules, ${change.name}: a read asked before it, answered after it, never draws the rules as they were`, async () => {
    const routes = { ...change.routes };
    let page!: ReturnType<typeof rulesPage>;
    if (change.name === "Save of a key Mandu found") {
      routes["POST suggestions/apply"] = (b: { ids: string[] }) => (page.added("suggested.example"), { applied: b.ids.map((id) => ({ id, changeId: "pc-0011" })), refused: [], suggestions: [], count: 0, scan: null });
    }
    page = rulesPage(routes, change.labels);
    const { doc, window, panel } = page;
    await tick(30);
    await change.open?.(doc);
    const shown = rulesMarkers(doc);
    const before = panel.hold();
    await go(doc, "home");
    await go(doc, "rules"); // Rules opened again: its read is held
    const after = panel.hold();
    await change.act(doc, window);
    await tick(30);
    assert.equal(change.done(doc), false, "the read after the change is held");
    before.release();
    await tick(30);
    assert.deepEqual(rulesMarkers(doc), shown, "the read asked before the change drew nothing");
    after.release();
    await tick(30);
    assert.ok(change.done(doc), "the read after the change is drawn");
    assert.deepEqual(rulesMarkers(doc), [`read-${panel.reads}`]);
  });
}

// ── Settings: Models, Sensitivity labels, Prompt filters ────────────────────

const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const CONF = "2b2b0000-0000-4000-8000-000000000003";
const OLLAMA = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", wireWords: "OpenAI chat", model: "llama3.2", local: true, placementWords: "On this computer" };
const LAB = { name: "lab", url: "https://lab.example/v1", wire: "openai-chat", wireWords: "OpenAI chat", model: "mistral", local: true, placementWords: "On your network" };
const CORP = { name: "corp", url: "https://llm.corp.example/v1", wire: "openai-chat", wireWords: "OpenAI chat", local: true, admin: true, locked: false };
const modelNamed = (name: string) => ({ ...LAB, name, url: `https://${name}.example/v1` });
const modelRow = (doc: Doc, name: string) => [...doc.querySelectorAll("#settings-models .model-row:not(.model-removed)")].find((r: Doc) => r.dataset.name === name);
const labelRow = (doc: Doc, id: string) => [...doc.querySelectorAll("#settings-labels .label-row")].find((r: Doc) => r.dataset.id === id);
const kindRow = (doc: Doc, cat: string) => [...doc.querySelectorAll("#settings-prompt-kinds .prompt-kind")].find((r: Doc) => r.dataset.category === cat);
const exceptionRow = (doc: Doc, match: string) => [...doc.querySelectorAll("#settings-prompt-exceptions .prompt-exception")].find((r: Doc) => r.querySelector("code:last-of-type")?.textContent === match);

/** Settings over a stub server that follows the changes posted; each card's
 *  read carries its marker (a model, a label, an exception named read-<n>). */
function settingsPage(routes: Record<string, unknown> = {}) {
  let models: unknown[] = [CORP, OLLAMA, LAB];
  let removed = ["corp-big"];
  let labels = [{ id: HC, name: "Highly Confidential", level: "no-model" }, { id: CONF, name: "Confidential", level: "local-model" }];
  let emailAction: { category: string; action: string; setBy: string; locked: boolean } = { category: "pii.email", action: "mask", setBy: "you", locked: false };
  let exceptions = [{ category: "pii.email", match: "*@example.com", setBy: "you", inForce: true }];
  const modelReads = gated((n) => ({ panel: {
    available: true, verdictsKnown: true, queue: [], yourRules: [], models: [...models, modelNamed(`read-${n}`)],
    modelsAdmin: { files: ["/etc/mandu/policy.d/10-org.yaml"], locked: false, removed: removed.map((name) => ({ name })) },
  } }));
  const labelReads = gated((n) => ({ labels: labelSettingsVM({ sensitivity_labels: [...labels, { id: `a0000000-0000-4000-8000-${String(n).padStart(12, "0")}`, name: `read-${n}`, level: "no-model" }] }, { sensitivityLabels: [] }, { labels: { unmapped: [], unmappedMore: 0 }, at: 1 }) }));
  const promptReads = gated((n) => ({ settings: promptSettingsVM({
    filters: [{ id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] }],
    actions: [{ category: "secret.registered", action: "mask", setBy: "default", locked: false }, emailAction],
    fallback: "redact",
    exceptions: [...exceptions, { category: "pii.email", match: `read-${n}@example.com`, setBy: "you", inForce: true }],
    enforcing: true, editable: true,
  }) }));
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/panel": modelReads.route,
    "GET policy/sensitivity-labels": labelReads.route,
    "GET policy/prompt-filters": promptReads.route,
    "POST policy/models/change": (b: { action: string; name: string; model?: { name: string } }) => {
      if (b.action === "remove") models = models.filter((m) => (m as { name: string }).name !== b.name);
      if (b.action === "restore") { removed = []; models = [...models, { ...CORP, name: "corp-big" }]; }
      if (b.action === "update") models = models.map((m) => ((m as { name: string }).name === b.name ? { ...LAB, ...b.model, wireWords: "OpenAI chat", placementWords: "On your network" } : m));
      return { applied: true, changeId: "pc-2", note: "" };
    },
    "POST policy/sensitivity-labels/change": (b: { action: string; id: string }) => {
      if (b.action === "unmap") labels = labels.filter((l) => l.id !== b.id);
      return { applied: true, changeId: "pc-4", note: "" };
    },
    "POST policy/prompt-filters/change": (b: { edit: { op: string } }) => {
      if (b.edit.op === "remove-prompt-action") emailAction = { ...emailAction, action: "redact", setBy: "default" };
      if (b.edit.op === "remove-prompt-exception") exceptions = [];
      return { applied: true, changeId: "pc-3" };
    },
    "POST policy/changes/pc-2/undo": () => { models = [CORP, OLLAMA, LAB]; return { ok: true }; },
    "POST policy/changes/pc-4/undo": () => { labels = [{ id: HC, name: "Highly Confidential", level: "no-model" }, { id: CONF, name: "Confidential", level: "local-model" }]; return { ok: true }; },
    "POST policy/changes/pc-3/undo": () => { exceptions = [{ category: "pii.email", match: "*@example.com", setBy: "you", inForce: true }]; return { ok: true }; },
    ...routes,
  } });
  return { ...page, modelReads, labelReads, promptReads };
}

test("Settings › Models: after two Removes, the read after the first, answered last, never brings the second model back", async () => {
  const { doc, modelReads } = settingsPage();
  await tick(30);
  const first = modelReads.hold();
  modelRow(doc, "ollama").querySelector(".model-remove-btn").click();
  await tick(30);
  modelRow(doc, "lab").querySelector(".model-remove-btn").click();
  await tick(30);
  assert.equal(modelRow(doc, "lab"), undefined, "the read after the second Remove is drawn");
  assert.equal(modelRow(doc, "ollama"), undefined);
  assert.match(doc.getElementById("models-notice").textContent, /^Removed lab\./);
  const drawn = markers(doc.getElementById("settings-models"));
  first.release();
  await tick(30);
  assert.equal(modelRow(doc, "lab"), undefined, "never drawn again under \"Removed lab.\"");
  assert.deepEqual(markers(doc.getElementById("settings-models")), drawn, "the older read drew nothing");
});

test("Settings: a refused change marks nothing, so a read asked before it is still drawn", async () => {
  const { doc, labelReads } = settingsPage({ "POST policy/sensitivity-labels/change": { status: 403, body: { error: "admin session required" } } });
  await tick(30);
  const before = labelReads.hold();
  await go(doc, "home");
  await go(doc, "settings");
  labelRow(doc, HC).querySelector(".label-remove-btn").click();
  await tick(30);
  assert.match(labelRow(doc, HC).querySelector(".ask-error").textContent, /^Sign in first/);
  before.release();
  await tick(30);
  assert.deepEqual(markers(doc.getElementById("settings-labels")), [`read-${labelReads.reads}`], "the read asked before the refusal is drawn");
});

test("Settings: reads of a card answered in the order they were asked are each drawn, an older one after a newer is dropped", async () => {
  const { doc, promptReads } = settingsPage();
  await tick(30);
  const card = () => markers(doc.getElementById("settings-prompt-exceptions"));
  const a = promptReads.hold();
  await go(doc, "home");
  await go(doc, "settings");
  const b = promptReads.hold();
  await go(doc, "home");
  await go(doc, "settings");
  const na = promptReads.reads - 1;
  a.release();
  await tick(30);
  assert.deepEqual(card(), [`read-${na}`], "the older read, first in, is drawn");
  b.release();
  await tick(30);
  assert.deepEqual(card(), [`read-${na + 1}`], "then the newer");
  const c = promptReads.hold();
  await go(doc, "home");
  await go(doc, "settings");
  const d = promptReads.hold();
  await go(doc, "home");
  await go(doc, "settings");
  d.release();
  await tick(30);
  c.release();
  await tick(30);
  assert.deepEqual(card(), [`read-${promptReads.reads}`], "an older read that answers after a newer one is dropped");
});

type SettingsPage = ReturnType<typeof settingsPage>;
/** Each change made in a Settings card: its card, its reads, what it does
 *  once the page is drawn, and what the read after it shows. */
const SETTINGS_CHANGES: Array<{ name: string; card: string; reads: (p: SettingsPage) => ReturnType<typeof gated>; open?: (doc: Doc) => Promise<void> | void; act: (doc: Doc) => void; done: (doc: Doc) => boolean }> = [
  { name: "Models, Remove", card: "settings-models", reads: (p) => p.modelReads, act: (doc) => modelRow(doc, "ollama").querySelector(".model-remove-btn").click(), done: (doc) => !modelRow(doc, "ollama") },
  { name: "Models, Bring back", card: "settings-models", reads: (p) => p.modelReads, act: (doc) => doc.querySelector("#settings-models .model-restore-btn").click(), done: (doc) => !!modelRow(doc, "corp-big") },
  {
    name: "Models, Save in the form", card: "settings-models", reads: (p) => p.modelReads,
    open: async (doc) => { button(modelRow(doc, "lab"), "Edit").click(); await tick(30); },
    act: (doc) => { doc.getElementById("model-model").value = "mixtral"; doc.getElementById("model-save").click(); },
    done: (doc) => /mixtral/.test(modelRow(doc, "lab")?.textContent ?? ""),
  },
  {
    name: "Models, the notice's Undo", card: "settings-models", reads: (p) => p.modelReads,
    open: async (doc) => { modelRow(doc, "ollama").querySelector(".model-remove-btn").click(); await tick(30); },
    act: (doc) => button(doc.getElementById("models-notice"), "Undo").click(),
    done: (doc) => !!modelRow(doc, "ollama"),
  },
  { name: "Sensitivity labels, Remove", card: "settings-labels", reads: (p) => p.labelReads, act: (doc) => labelRow(doc, CONF).querySelector(".label-remove-btn").click(), done: (doc) => !labelRow(doc, CONF) },
  {
    name: "Sensitivity labels, the notice's Undo", card: "settings-labels", reads: (p) => p.labelReads,
    open: async (doc) => { labelRow(doc, CONF).querySelector(".label-remove-btn").click(); await tick(30); },
    act: (doc) => button(doc.getElementById("labels-notice"), "Undo").click(),
    done: (doc) => !!labelRow(doc, CONF),
  },
  { name: "Prompt filters, Use the default", card: "settings-prompt-exceptions", reads: (p) => p.promptReads, act: (doc) => kindRow(doc, "pii.email").querySelector(".prompt-reset-btn").click(), done: (doc) => !kindRow(doc, "pii.email").querySelector(".prompt-reset-btn") },
  {
    name: "Prompt filters, the notice's Undo", card: "settings-prompt-exceptions", reads: (p) => p.promptReads,
    open: async (doc) => { exceptionRow(doc, "*@example.com").querySelector("button").click(); await tick(30); },
    act: (doc) => button(doc.getElementById("prompt-notice"), "Undo").click(),
    done: (doc) => !!exceptionRow(doc, "*@example.com"),
  },
];

for (const change of SETTINGS_CHANGES) {
  test(`Settings › ${change.name}: a read asked before it, answered after it, never draws the card as it was`, async () => {
    const page = settingsPage();
    const { doc } = page;
    const reads = change.reads(page);
    await tick(30);
    await change.open?.(doc);
    const card = () => markers(doc.getElementById(change.card));
    const shown = card();
    const before = reads.hold();
    await go(doc, "home");
    await go(doc, "settings"); // Settings opened again: the card's read is held
    const after = reads.hold();
    change.act(doc);
    await tick(30);
    assert.equal(change.done(doc), false, "the read after the change is held");
    before.release();
    await tick(30);
    assert.deepEqual(card(), shown, "the read asked before the change drew nothing");
    after.release();
    await tick(30);
    assert.ok(change.done(doc), "the read after the change is drawn");
    assert.deepEqual(card(), [`read-${reads.reads}`]);
  });
}

// ── Settings › Protection: the one switch, read by Settings and by Rules ────

/** The setting config.toml holds, as GET and POST config/axes answer it. */
const savedAs = (on: boolean) => ({ ok: true, effective: { integrity: false, confidentiality: on }, effectiveMode: on ? "secrets" : "off" });
const protectSwitch = (doc: Doc) => doc.getElementById("switch-protection");
/** The Protection row as drawn: the switch, its name, the sentence under it. */
const protectRow = (doc: Doc) => ({
  checked: protectSwitch(doc).getAttribute("aria-checked"),
  name: doc.querySelector("#settings-protect-row .name").textContent,
  text: doc.getElementById("settings-protect-text").textContent,
});
const ON_WORDS = "Keys and secret files leave this computer only where a rule or your OK allows.";
const OFF_WORDS = "Mandu only watches. Your secrets are not masked, and nothing is stopped.";
const STILL_ON = "Still on until the protection service restarts: keys and secret files leave this computer only where a rule or your OK allows.";

/** A page over a stub config.toml that a flip writes and a terminal (`mandu
 *  mode`) can change: each read of it answers what it holds when read. The
 *  fixture's protection service runs Full, so on is what runs. */
function protectionPage(url = SETTINGS_URL, routes: Record<string, unknown> = {}, on = true) {
  let saved = on;
  const reads = gated(() => savedAs(saved));
  const page = load({ url, routes: {
    ...FILES_ROUTES,
    "GET config/axes": reads.route,
    "POST config/axes": (b: { mode: string }) => { saved = b.mode === "secrets"; return savedAs(saved); },
    ...routes,
  } });
  page.window.prompt = () => "OFF";
  return { ...page, reads, set: (v: boolean) => { saved = v; } };
}

for (const flip of [
  { name: "turning it off", from: true, drawn: { checked: "false", name: "Off", text: STILL_ON }, runs: "off", restarted: { checked: "false", name: "Off", text: OFF_WORDS } },
  { name: "turning it on", from: false, drawn: { checked: "true", name: "On", text: ON_WORDS }, runs: "secrets", restarted: { checked: "true", name: "On", text: ON_WORDS } },
]) {
  test(`Settings › Protection, ${flip.name}: a read asked before it, answered after it, never draws the switch as it was`, async () => {
    const { doc, reads, calls, setHome } = protectionPage(SETTINGS_URL, {}, flip.from);
    await tick(30);
    assert.equal(protectRow(doc).checked, String(flip.from));
    const before = reads.hold();
    await go(doc, "home");
    await go(doc, "settings"); // Settings opened again: its read of the setting is held
    protectSwitch(doc).focus();
    protectSwitch(doc).click();
    await tick(30);
    assert.deepEqual(calls.filter((c: Doc) => c.method === "POST" && c.url.endsWith("/config/axes")).map((c: Doc) => c.body), [{ mode: flip.from ? "off" : "secrets" }]);
    assert.deepEqual(protectRow(doc), flip.drawn, "the flip's answer is drawn");
    const note = doc.getElementById("settings-protect-note").textContent;
    before.release();
    await tick(30);
    assert.deepEqual(protectRow(doc), flip.drawn, "never drawn as it was before the flip");
    assert.equal(doc.getElementById("settings-protect-note").textContent, note);
    assert.equal(doc.activeElement, protectSwitch(doc), "the focus stays on the switch");
    // The protection service restarts and runs what is saved: the next Home
    // poll draws the row again, from the setting the page holds.
    setHome(home({ protection: { level: flip.runs, configured: flip.runs, connected: true } }));
    await poll(doc);
    assert.deepEqual(protectRow(doc), flip.restarted, "the page holds the setting you saved, not the older read's");
    await go(doc, "home");
    await go(doc, "settings");
    assert.deepEqual(protectRow(doc), flip.restarted, "a read asked after the flip is drawn");
  });
}

test("Settings › Protection: a refused flip marks nothing, so a read asked before it is still drawn", async () => {
  const { doc, reads, set } = protectionPage(SETTINGS_URL, { "POST config/axes": { status: 403, body: { error: "admin session required" } } });
  await tick(30);
  set(false); // turned off from a terminal
  const before = reads.hold();
  await go(doc, "home");
  await go(doc, "settings"); // its read (off) is held; the switch still says On
  assert.equal(protectRow(doc).checked, "true");
  protectSwitch(doc).click();
  await tick(30);
  assert.match(doc.getElementById("settings-protect-note").textContent, /^Sign in first/);
  before.release();
  await tick(30);
  assert.deepEqual(protectRow(doc), { checked: "false", name: "Off", text: STILL_ON }, "the read asked before the refusal is drawn");
});

test("Settings › Protection: Rules' read of the setting, answered after Settings read a newer one, never draws the switch as it was", async () => {
  const { doc, reads, set, setHome } = protectionPage(RULES_URL);
  await tick(30);
  const rules = reads.hold();
  await go(doc, "home");
  await go(doc, "rules"); // Rules opened again: its read of the setting (on) is held
  set(false); // turned off from a terminal
  await go(doc, "settings");
  assert.deepEqual(protectRow(doc), { checked: "false", name: "Off", text: STILL_ON }, "Settings reads the newer setting");
  rules.release();
  await tick(30);
  // The protection service restarts and runs what is saved: the next Home
  // poll draws the row again, from the setting the page holds.
  setHome(home({ protection: { level: "off", configured: "off", connected: true } }));
  await poll(doc);
  assert.deepEqual(protectRow(doc), { checked: "false", name: "Off", text: OFF_WORDS }, "never On over a newer read, nor \"Still off until the protection service restarts\" after it did");
});

test("Settings › Protection: reads answered in the order they were asked are each drawn, an older one after a newer is dropped, a failure too", async () => {
  const { doc, reads, set, setHome } = protectionPage();
  await tick(30);
  const again = async () => { await go(doc, "home"); await go(doc, "settings"); };
  const a = reads.hold();
  await again(); // reads on
  set(false);
  const b = reads.hold();
  await again(); // reads off
  a.release();
  await tick(30);
  assert.equal(protectRow(doc).checked, "true", "the older read, first in, is drawn");
  b.release();
  await tick(30);
  assert.equal(protectRow(doc).checked, "false", "then the newer");
  const c = reads.hold();
  await again(); // reads off
  set(true);
  const d = reads.hold();
  await again(); // reads on
  d.release();
  await tick(30);
  assert.deepEqual(protectRow(doc), { checked: "true", name: "On", text: ON_WORDS });
  c.release();
  await tick(30);
  assert.deepEqual(protectRow(doc), { checked: "true", name: "On", text: ON_WORDS }, "an older read that answers after a newer one is dropped");
  const e = reads.hold();
  await again();
  const f = reads.hold();
  await again();
  f.release();
  await tick(30);
  e.fail();
  await tick(30);
  assert.deepEqual(protectRow(doc), { checked: "true", name: "On", text: ON_WORDS }, "an older read that fails after a newer one never draws \"could not be read\"");
  assert.equal(protectSwitch(doc).disabled, false);
  // The protection service restarts: the next Home poll draws the row again,
  // from the setting the page holds (the newest read's).
  setHome(home({ protection: { level: "secrets", configured: "secrets", connected: true } }));
  await poll(doc);
  assert.deepEqual(protectRow(doc), { checked: "true", name: "On", text: ON_WORDS }, "the page holds the newest read's setting");
  assert.equal(protectSwitch(doc).disabled, false);
});
