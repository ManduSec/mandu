/**
 * home-js-count-keeps-word.test — dashboard.md §4.25u *A count keeps its
 * word*. Until 2026-10-15 a count in the page's own words could end a line
 * with its number: headless Chromium drew a Home or History row's counts as
 * "1" over "action blocked" at 980 px and "1" over "send with a real value
 * filled in" at 320 px, a session page's Your secrets card as "… in 2" over
 * "requests." (720 to 1280 px; "11" at 390), and its background line as
 * "In the background: 4" over "updates to your screen …" at 320 px. Now
 * home.js `countWords` puts each number and the word after it in a
 * `.count-word` that app.css keeps on one line. The text is the same.
 *
 *   K1  countWords alone: each number and its word in one span, the text
 *       as before; a number inside a word, a path or a clock time, a word
 *       past 24 letters, or no number at all is left as one text node;
 *   K2  the row counts on Home's Running now and Earlier and on History;
 *   K3  the session page's sentences (sentenceNode): a Your secrets card,
 *       a turn's summary, its background line, server-built or not;
 *   K4  the hero's sentence (textParts), with parts and without;
 *   K5  data stays as written: the AI's reply, the person's prompt and the
 *       output of a command they ran carry no span;
 *   K6  app.css: `.count-word` never wraps, at every width; the lines that
 *       hold one still do.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AGENT, PUB, T, home, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, mentions, stripComments } from "./css-flatten.js";

const HISTORY_URL = "http://127.0.0.1:4500/mandu/history";
const AGENT_URL = "http://127.0.0.1:4500/mandu/agents/s1";

/** A node's children as `[count-word]` for a count span and the text of a
 *  text node, so a test reads the split it pins. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function pieces(node: any): string[] {
  return ([...node.childNodes] as { nodeType: number; className?: string; textContent: string; childNodes: unknown[] }[]).map((x) => {
    if (x.nodeType === 3) return x.textContent;
    assert.equal(x.className, "count-word", `only count spans are added: ${x.className}`);
    assert.equal(x.childNodes.length, 1, "a count span holds one text node");
    return `[${x.textContent}]`;
  });
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const counts = (node: any): string[] => [...node.querySelectorAll(".count-word")].map((x: any) => x.textContent);

test("K1: countWords keeps each number with the word after it, and leaves everything else one text (§4.25u)", () => {
  const { window, doc } = load();
  const host = doc.createElement("div");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const split = (text: unknown): any => { host.textContent = ""; host.append(window.countWords(text)); return host; };
  const cases: [string, string[]][] = [
    ["1 secret masked, 1 action blocked", ["[1 secret]", " masked, ", "[1 action]", " blocked"]],
    ["It went to the AI that way in 11 requests.", ["It went to the AI that way in ", "[11 requests]", "."]],
    ["ran 9 minutes 7 seconds", ["ran ", "[9 minutes]", " ", "[7 seconds]"]],
    ["(3 items) and 1,234 requests in 1.5 seconds", ["(", "[3 items]", ") and ", "[1,234 requests]", " in ", "[1.5 seconds]"]],
    ["In the background: 4 updates to your screen", ["In the background: ", "[4 updates]", " to your screen"]],
    ["2 " + "a".repeat(24), [`[2 ${"a".repeat(24)}]`]],
  ];
  for (const [text, want] of cases) {
    assert.deepEqual(pieces(split(text)), want, text);
    assert.equal(host.textContent, text, "the text is the same");
  }
  // Not a count: one text node, as before (a text with no number draws as it did).
  for (const text of ["Protection is holding.", "v2 build", "at 15:31 on", "in ~/a/2 b", "x2 y", "2 " + "a".repeat(25), "2  two spaces", "", null, undefined]) {
    const node = window.countWords(text);
    assert.equal(node.nodeType, 3, `${JSON.stringify(text)} stays one text node`);
    assert.equal(node.textContent, text == null ? "" : text);
  }
});

test("K2: the row counts on Home and History keep each number with its word (§4.25u)", async () => {
  const NOW = Date.now();
  const iso = (ms: number) => new Date(ms).toISOString();
  const row = (id: string, state: string) => ({
    id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", state, startedAt: iso(NOW - 3_600_000), lastAt: iso(NOW - 60_000),
    stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 },
    secrets: { masked: 1, early: 1 }, untrusted: 2, blocked: 1, sent: 1, holds: true, waiting: 1, notice: null, preview: null,
  });
  const WORDS = "1 secret masked, 1 secret read before it was marked, 2 untrusted items masked, 1 action blocked, 1 send with a real value filled in";
  const SPANS = ["1 secret", "1 secret", "2 untrusted", "1 action", "1 send"];
  const { doc } = load({ homeVm: home({ waiting: [], agents: [row("r1", "running"), row("e1", "idle")] }) });
  await tick();
  const running = doc.querySelector('#home-agents .row.agent[data-session="r1"] .agent-counts');
  assert.ok(running, "Running now drew the row's counts");
  assert.equal(running.textContent, "1 question waiting for you, " + WORDS);
  assert.deepEqual(counts(running), ["1 question", ...SPANS]);
  const earlier = doc.querySelector('#home-earlier .row.agent[data-session="e1"] .agent-counts');
  assert.ok(earlier, "Earlier drew the row's counts");
  assert.equal(earlier.textContent, WORDS + ", 1 question waiting for you");
  assert.deepEqual(counts(earlier), [...SPANS, "1 question"]);
  assert.deepEqual(pieces(earlier).slice(0, 4), ["[1 secret]", " masked, ", "[1 secret]", " read before it was marked, "]);

  const hist = load({ extensions: "", url: HISTORY_URL, homeVm: home(), routes: { "GET home/history": { total: 2, rows: [row("r1", "running"), row("e1", "idle")], next: null } } });
  await tick();
  for (const id of ["r1", "e1"]) {
    const line = hist.doc.querySelector(`#history-list .row.agent[data-session="${id}"] .agent-counts`);
    assert.ok(line, `History drew ${id}'s counts`);
    // Its question waiting too, in Earlier's words (§4.25ae *History says
    // what waits for you*).
    assert.equal(line.textContent, WORDS + ", 1 question waiting for you");
    assert.deepEqual(counts(line), [...SPANS, "1 question"]);
  }
  // A row with nothing to count draws no line, as before.
  const quiet = load({ homeVm: home({ waiting: [], agents: [{ ...row("q1", "running"), secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, waiting: 0 }] }) });
  await tick();
  assert.ok(quiet.doc.querySelector('.row.agent[data-session="q1"]'), "the row is drawn");
  assert.equal(quiet.doc.querySelector('.row.agent[data-session="q1"] .agent-counts'), null);
});

test("K3: the session page's own sentences keep each number with its word (§4.25u)", async () => {
  const agent = {
    ...AGENT, waiting: [], earlier: 0,
    secrets: { mode: "secrets", flagged: false, more: 0, counts: { masked: 1, early: 0 }, secrets: [
      { what: [T("The file "), { kind: "code", text: "~/ws/deploy/staging.conf" }], level: "No AI", lines: [
        { tone: "good", parts: [T("The AI got only a placeholder, never the real value. It went to the AI that way in 11 requests.")] },
      ] },
    ] },
    story: [
      { ...AGENT.story[0], routine: { count: 4, hosts: [], parts: [T("In the background: 4 updates to your screen with the real text in place of masked items.")] } },
      // A server without the background words: the page says the count itself.
      { ...AGENT.story[1], routine: { count: 2, hosts: [] } },
    ],
  };
  const { doc } = load({ url: AGENT_URL, routes: { "GET home/agent?session=s1": agent } });
  await tick();
  const line = doc.querySelector("#agent-secrets .secret-line");
  assert.ok(line, "the Your secrets card is drawn");
  assert.equal(line.textContent, "The AI got only a placeholder, never the real value. It went to the AI that way in 11 requests.");
  assert.deepEqual(counts(line), ["11 requests"]);
  const [first, second] = [...doc.querySelectorAll("#agent-story .turn")] as any[];
  const summary = first.querySelector(".turn-summary");
  assert.equal(summary.textContent, "Mandu blocked 1 action, masked 1 item and hid your secret API_KEY from the AI.");
  assert.deepEqual(counts(summary), ["1 action", "1 item"]);
  assert.equal(summary.querySelector("code").textContent, "API_KEY", "a code part stays code");
  const routine = first.querySelector(".routine");
  assert.match(routine.textContent, /^In the background: 4 updates to your screen with the real text in place of masked items\./);
  assert.deepEqual(counts(routine), ["4 updates"]);
  assert.deepEqual(counts(second.querySelector(".routine")), ["2 steps"]);
  assert.match(second.querySelector(".routine").textContent, /^In the background: 2 steps\./);
});

test("K4: the hero's sentence keeps each number with its word, with its parts and without (§4.25u)", async () => {
  const parts = [T("Mandu masked 3 secrets in 2 sessions. "), { kind: "link", to: "settings", text: "Settings" }, T(" says how.")];
  const { doc } = load({ homeVm: home({ sentence: "Mandu masked 3 secrets in 2 sessions. Settings says how.", sentenceParts: parts }) });
  await tick();
  const s = doc.getElementById("hero-sentence");
  assert.equal(s.textContent, "Mandu masked 3 secrets in 2 sessions. Settings says how.");
  assert.deepEqual(counts(s), ["3 secrets", "2 sessions"]);
  assert.equal(s.querySelector("a").textContent, "Settings", "a link part stays a link");
  // An older server: the plain sentence, the same way.
  const old = load({ homeVm: home({ sentence: "Mandu masked 3 secrets." }) });
  await tick();
  const o = old.doc.getElementById("hero-sentence");
  assert.equal(o.textContent, "Mandu masked 3 secrets.");
  assert.deepEqual(pieces(o), ["Mandu masked ", "[3 secrets]", "."]);
  // No number: one text node, as before.
  const plain = load({ homeVm: home() });
  await tick();
  assert.deepEqual(pieces(plain.doc.getElementById("hero-sentence")), ["Protection is holding."]);
});

test("K5: the AI's reply, the person's prompt and a command's output stay as written (§4.25u)", async () => {
  const agent = { ...AGENT, waiting: [], earlier: 0, story: [
    { ...AGENT.story[1], id: "turn:q", prompt: "Run 2 tests twice", promptParts: [T("Run 2 tests twice")], shell: null, steps: [],
      reply: { ts: "2026-09-25T10:01:09.000Z", parts: [T("All 2 tests passed.")], ai: null } },
    { ...AGENT.story[1], id: "turn:sh", prompt: "!git status", promptParts: null, shell: { command: "git status", output: [T("2 files **changed**, 3 insertions")] }, steps: [], reply: null },
  ] };
  const { doc } = load({ url: AGENT_URL, routes: { "GET home/agent?session=s1": agent } });
  await tick();
  const [q, sh] = [...doc.querySelectorAll("#agent-story .turn")] as any[];
  assert.match(q.querySelector(".q-text").textContent, /Run 2 tests twice/);
  assert.match(q.querySelector(".reply-text").textContent, /All 2 tests passed\./);
  const out = sh.querySelector(".q-out");
  assert.ok(out, "the command's output is drawn");
  // As written: no count span, and no markdown either (its ** stay).
  assert.equal(out.textContent, "2 files **changed**, 3 insertions");
  assert.equal(out.querySelector("strong"), null, "the output is not read as markdown");
  for (const node of [q.querySelector(".q-text"), q.querySelector(".reply-text"), out]) {
    assert.equal(node.querySelector(".count-word"), null, `${node.className} is drawn as written`);
  }
});

test("K6: app.css keeps a count on one line at every width, and lets the lines around it wrap (§4.25u)", () => {
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  const own = rules.filter((r) => r.media === null && r.selectors.includes(".count-word"));
  assert.ok(own.some((r) => declValue(r.block, "white-space") === "nowrap"), ".count-word stays on one line");
  for (const r of rules.filter((x) => x.selectors.some((s) => mentions(s, ".count-word")) && declValue(x.block, "white-space") !== null)) {
    assert.equal(declValue(r.block, "white-space"), "nowrap", `"${r.selectors.join(", ")}"${r.media ? ` in ${r.media}` : ""} lets a count wrap`);
  }
  // The lines that hold a count wrap between words: only the pair is kept.
  for (const sel of [".agent-counts", ".routine", ".secret-line", ".turn-summary", "#hero-sentence"]) {
    for (const r of rules.filter((x) => x.selectors.some((s) => mentions(s, sel)))) {
      assert.notEqual(declValue(r.block, "white-space"), "nowrap", `"${r.selectors.join(", ")}"${r.media ? ` in ${r.media}` : ""} keeps the whole of ${sel} on one line`);
    }
  }
});
