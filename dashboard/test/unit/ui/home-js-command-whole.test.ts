/**
 * home-js-command-whole.test — dashboard.md §4.25u *A command keeps its
 * words*. Until 2026-10-15 a command in the page's own words wrapped at its
 * space like any text: headless Chromium drew Settings › Protection's "Start
 * it with `mandu`" over "`dashboard` to manage …" at 1280, 720, 390 and
 * 320 px, and Home › Where your data lives' "run `mandu`" over "`paths`." at
 * 320 px; History's empty state named `mandu claude or mandu codex` as plain
 * text. Now home.js `ownCode` marks a code of the page's own words with a
 * space in it, at most WHOLE_MAX (24) characters, as `code.code-whole`, which
 * app.css keeps on one line. The text is the same.
 *
 *   W1  ownCode alone: a short code with a space is whole; one with no
 *       space, or past 24 characters, is a plain code; its text as given;
 *   W2  the ownWords sentences (`words()`): the sign-in refusal's
 *       `mandu dashboard`;
 *   W3  `textParts` code parts: the exposure notice's flags, the hero's;
 *   W4  the page's literal commands: Settings' service line, Home's and
 *       History's empty states (History's now as code), Where your data
 *       lives (index.html's line, the open note, the failed load); every
 *       literal command in home.js goes through ownCode and is whole;
 *   W5  data stays as written: a command the AI ran (short or long), the
 *       AI's reply and a command the person ran carry no class;
 *   W6  app.css: `code.code-whole` never wraps, at every width; the lines
 *       that hold one still do.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AGENT, JS, PUB, T, home, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, mentions, stripComments } from "./css-flatten.js";

const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const HISTORY_URL = "http://127.0.0.1:4500/mandu/history";
const AGENT_URL = "http://127.0.0.1:4500/mandu/agents/s1";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
/** Each code under `node` as `[text]` when kept whole, `text` when not. */
const codes = (node: El): string[] => [...node.querySelectorAll("code")].map((c: El) => {
  assert.ok(c.className === "" || c.className === "code-whole", `only .code-whole is added: ${c.className}`);
  assert.equal(c.children.length, 0, "a code holds its text only");
  return c.className === "code-whole" ? `[${c.textContent}]` : c.textContent;
});

test("W1: ownCode keeps a short code with a space whole, and leaves every other code plain (§4.25u)", () => {
  const { window } = load();
  const whole = ["mandu dashboard", "mandu claude", "mandu doctor --secrets", "--mode off", "a".repeat(11) + " " + "b".repeat(12), "<b>x y</b>"];
  for (const text of whole) {
    const c = window.ownCode(text);
    assert.equal(c.tagName, "CODE");
    assert.equal(c.className, "code-whole", `${JSON.stringify(text)} is kept whole`);
    assert.equal(c.textContent, text, "the text as given");
    assert.equal(c.children.length, 0, "never markup");
  }
  const plain = ["mandu", "--no-net-guard", "~/.aws/credentials", "a".repeat(12) + " " + "b".repeat(12), "curl -sS https://api.example.com/v1 -d x=1", ""];
  for (const text of plain) {
    const c = window.ownCode(text);
    assert.equal(c.tagName, "CODE");
    assert.equal(c.className, "", `${JSON.stringify(text)} stays a plain code`);
    assert.equal(c.textContent, text);
  }
  for (const text of [null, undefined]) assert.equal(window.ownCode(text).textContent, "");
});

test("W2: the page's own sentences (words) keep their command whole: the sign-in refusal (§4.25u)", async () => {
  const { doc } = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { status: 403, body: { error: "admin session required: open the login link" } } } });
  await tick();
  const kinds = doc.getElementById("settings-prompt-kinds");
  assert.equal(kinds.textContent, "Sign in first: reload this page and sign in with your dashboard account (if there isn't one yet, run mandu dashboard --set-password in your own terminal).");
  // Longer than WHOLE_MAX: a plain code, which may wrap at its spaces in
  // the narrowest column (dashboard.md §4.25u, §6.z).
  assert.deepEqual(codes(kinds), ["mandu dashboard --set-password"]);
});

test("W3: textParts keeps a short command whole and leaves a file or a flag plain: the exposure notice, the hero (§4.25u)", async () => {
  const fixParts = [
    T("Stop that agent, or start it again with the file guard on (without "),
    { kind: "code", text: "--mode off" },
    T(" or "),
    { kind: "code", text: "--no-net-guard" },
    T(")."),
  ];
  const fix = fixParts.map((p) => p.text).join("");
  const exposure = { headline: "Another agent can reach Mandu's own controls.", sentence: "An agent was started without the file guard.", fix, fixParts, causes: [] };
  const sentenceParts = [T("Run "), { kind: "code", text: "mandu doctor" }, T(" to check "), { kind: "code", text: "~/.mandu/policy.yaml" }, T(".")];
  const { doc } = load({ homeVm: home({ exposure, sentence: "Run mandu doctor to check ~/.mandu/policy.yaml.", sentenceParts }) });
  await tick();
  const f = doc.getElementById("exposure-fix");
  assert.equal(f.textContent, fix, "the same words");
  assert.deepEqual(codes(f), ["[--mode off]", "--no-net-guard"]);
  const hero = doc.getElementById("hero-sentence");
  assert.equal(hero.textContent, "Run mandu doctor to check ~/.mandu/policy.yaml.");
  assert.deepEqual(codes(hero), ["[mandu doctor]", "~/.mandu/policy.yaml"]);
});

const LOCATIONS = {
  home: "~/.mandu",
  locations: [{ name: "events", path: "~/.mandu/events", where: "home", holds: "session history", exists: true, mode: "0755", ownerOnly: false }],
};
function openDataWhere(doc: El, window: El): void {
  const d = doc.getElementById("home-data");
  d.open = true;
  d.dispatchEvent(new window.Event("toggle"));
}

test("W4: every command the page writes itself is code and kept whole, History's empty state too (§4.25u)", async () => {
  // Settings › Protection with no service controls.
  const settings = load({ url: SETTINGS_URL, routes: { "GET control/summary": { summary: null } } });
  await tick();
  const service = settings.doc.querySelector("#settings-services .service-none");
  assert.equal(service.textContent, "This dashboard was started without the service controls. Start it with mandu dashboard to manage the protection service here.");
  assert.deepEqual(codes(service), ["[mandu dashboard]"]);

  // Home: Running now with no agent, and Where your data lives (the page's
  // own line in index.html, then the note on open places).
  const idle = home().agents.filter((a) => a.state === "idle");
  const h = load({ homeVm: home({ verdict: "quiet", waiting: [], agents: idle }), routes: { "GET data-locations": LOCATIONS } });
  await tick();
  const running = h.doc.querySelector("#home-agents .empty");
  assert.equal(running.textContent, "No agent is running right now. Start one with mandu claude or mandu codex.");
  assert.deepEqual(codes(running), ["[mandu claude]", "[mandu codex]"]);
  assert.deepEqual(codes(h.doc.getElementById("home-data-about")), ["~/.mandu", "[mandu paths]"]);
  openDataWhere(h.doc, h.window);
  await tick();
  const open = h.doc.getElementById("home-data-open");
  assert.equal(open.textContent, "Other people on this computer can open 1 place in Mandu's folder. Run mandu paths in a terminal for the command that makes them yours only.");
  assert.deepEqual(codes(open), ["[mandu paths]"]);
  const bad = load({ routes: { "GET data-locations": { status: 500, body: {} } } });
  await tick();
  openDataWhere(bad.doc, bad.window);
  await tick();
  const failed = bad.doc.querySelector("#home-data-list .empty");
  assert.equal(failed.textContent, "The list could not be loaded. Run mandu paths in a terminal to see it.");
  assert.deepEqual(codes(failed), ["[mandu paths]"]);

  // History with no session: Home's Get started step, its commands code.
  const hist = load({ extensions: "", url: HISTORY_URL, homeVm: home(), routes: { "GET home/history": { total: 0, rows: [], next: null } } });
  await tick();
  const empty = hist.doc.querySelector("#history-list .empty");
  assert.ok(empty, "History draws its empty state");
  assert.equal(empty.textContent, "No session has been recorded yet. Start your agent through Mandu, mandu claude or mandu codex, and it shows up here.");
  assert.deepEqual(codes(empty), ["[mandu claude]", "[mandu codex]"]);

  // Every literal command in home.js goes through ownCode, and each is whole.
  assert.deepEqual(JS.match(/el\('code', \{ text: '[^']*\s[^']*' \}\)/g) ?? [], [], "a literal command drawn past ownCode");
  const literals = [...JS.matchAll(/ownCode\('([^']*)'\)/g)].map((m) => m[1]!);
  const owned = [...JS.matchAll(/ownWords\([^;]*?\['([^']*)'\]/g)].map((m) => m[1]!);
  assert.ok(literals.length >= 7 && owned.length >= 2, `found the page's commands: ${JSON.stringify([...literals, ...owned])}`);
  // Each one that fits the narrowest column (WHOLE_MAX, 24) is whole; the
  // one longer command, `mandu dashboard --set-password`, wraps as a plain code.
  for (const text of [...literals, ...owned]) {
    assert.equal(h.window.ownCode(text).className, text.length <= 24 ? "code-whole" : "", `${text} is kept whole only when it fits`);
  }
});

test("W5: data is drawn as written: the AI's commands, its reply and the person's command carry no class (§4.25u)", async () => {
  const agent = {
    ...AGENT, waiting: [], earlier: 0,
    story: [
      { ...AGENT.story[1], id: "turn:run",
        steps: [
          { kind: "action", id: "c1", ts: "2026-09-25T10:01:01.000Z", icon: "run", sentence: [T("Ran "), { kind: "code", text: "git status" }], outcome: "plain", note: null, split: null },
          { kind: "action", id: "c2", ts: "2026-09-25T10:01:02.000Z", icon: "run", sentence: [T("Ran "), { kind: "code", text: "curl -sS https://api.example.com/v1/customers -d limit=1" }], outcome: "plain", note: null, split: null },
        ],
        reply: { ts: "2026-09-25T10:01:09.000Z", parts: [T("I ran `git status` and `npm test`.")], ai: null } },
      { ...AGENT.story[1], id: "turn:sh", prompt: "!git status", promptParts: null, shell: { command: "git status", output: [T("nothing to commit")] }, steps: [], reply: null },
    ],
  };
  const { doc } = load({ url: AGENT_URL, routes: { "GET home/agent?session=s1": agent } });
  await tick();
  const story = doc.getElementById("agent-story");
  const texts = [...story.querySelectorAll("code")].map((c: El) => c.textContent);
  for (const t of ["git status", "curl -sS https://api.example.com/v1/customers -d limit=1", "npm test"]) assert.ok(texts.includes(t), `${t} is drawn as code: ${JSON.stringify(texts)}`);
  assert.equal(story.querySelector(".code-whole"), null, "the AI's and the person's commands wrap as written");
});

test("W6: app.css keeps a .code-whole on one line at every width, and lets the lines around it wrap (§4.25u)", () => {
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  const own = rules.filter((r) => r.media === null && r.selectors.includes("code.code-whole"));
  assert.ok(own.some((r) => declValue(r.block, "white-space") === "nowrap"), "code.code-whole stays on one line");
  for (const r of rules.filter((x) => x.selectors.some((s) => mentions(s, ".code-whole")) && declValue(x.block, "white-space") !== null)) {
    assert.equal(declValue(r.block, "white-space"), "nowrap", `"${r.selectors.join(", ")}"${r.media ? ` in ${r.media}` : ""} lets a command wrap`);
  }
  // The lines that hold one wrap between words: only the command is kept.
  for (const sel of [".service-none", ".service-line", "#home-data-about", ".note", ".empty", "#exposure-fix", "#hero-sentence", ".ask-error"]) {
    for (const r of rules.filter((x) => x.selectors.some((s) => mentions(s, sel)))) {
      assert.notEqual(declValue(r.block, "white-space"), "nowrap", `"${r.selectors.join(", ")}"${r.media ? ` in ${r.media}` : ""} keeps the whole of ${sel} on one line`);
    }
  }
  // The 24 the page measures against is home.js's WHOLE_MAX.
  assert.match(JS, /^const WHOLE_MAX = 24;$/m);
});
