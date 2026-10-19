/**
 * home-js-long-names.test — dashboard.md §4.25u *A long name breaks at its
 * slashes*. A name of at most WHOLE_MAX (24) characters is kept whole
 * (`nameCode`, `fitName`, `keepNamesWhole`); a longer one was a plain code
 * the browser broke where it could. Headless Chromium at 390 px drew the
 * session page's Your secrets card as "token in ~/mandu-" over
 * "try/deploy/staging.conf", and Rules › *Who may get your secrets* at
 * 320 px each long file the same way: the hyphen inside a folder name was
 * the line's only break. Now `longName` cuts such a name after each `/`
 * (a host with no `/`: after each `.`) into `.name-part`s, which app.css
 * draws as boxes no wider than their line, so a line breaks between the
 * parts:
 *
 *   L1  the cut: a path after each slash, a host after each dot; a short
 *       name, one with a space (a command), one with one part, unchanged;
 *       the text always the same;
 *   L2  the session page's Your secrets card heading and line;
 *   L3  Rules › Who may get your secrets: each file of a list;
 *   L4  Approvals: a waiting card's cells and an *Answered earlier* row;
 *   L5  a name holding markup is text in its parts;
 *   L6  the app.css contract: a .name-part is an inline box no wider than
 *       its line, wrapping inside only when alone too wide;
 *   L7  (2026-10-17, *A rule's long name breaks as elsewhere*) Rules ›
 *       *Sending data*: a row whose subject is one long host (its chip) is
 *       cut at its dots; a short one stays one piece; the row's title and
 *       buttons keep the whole name;
 *   L8  Rules › Who may get your secrets › Hosts: a long host's name is
 *       cut at its dots, a short one is one piece;
 *   L9  (2026-10-17, *The session's folder breaks as elsewhere*) the
 *       session page's line under its title: a long folder ("in
 *       ~/projects/…") is cut at its slashes, a short one stays one piece,
 *       the line reads as before.
 *   L10 (2026-10-17, *A name in a reply breaks as elsewhere*) the agent's
 *       reply and the person's question (their markdown): an inline code
 *       with no space is a name; a long one is cut at its slashes (a host:
 *       its dots), a short one is one `.name-fit` box; a command with a
 *       space, a code holding a chip and a fenced block are as written; the
 *       text is the same.
 *   L11 (2026-10-17, *A command's code keeps to its column*) the app.css
 *       contract: the reply's and the question's inline codes are
 *       `break-spaces`, so a space at the end of a line takes its room
 *       instead of hanging past the column under the text's `pre-wrap`
 *       (Chromium at 320 px: a `! curl …` code 6 px past it); a
 *       `.code-whole` stays `nowrap`.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/long-name-breaks.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { JSDOM } from "jsdom";
import { join } from "node:path";

import { AGENT, ASK, home, load, M, PUB, RULES_PANEL, T, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, stripComments } from "./css-flatten.js";
import { byWhoRules, toByWhoVM } from "../../../src/view-model/rules-by-who.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const C = (text: string) => ({ kind: "code", text });
/** A code as a person would read where it may break: its parts joined by
 *  " | ", or its text when it is one piece. */
const cut = (c: El): string => {
  const parts = [...c.querySelectorAll(".name-part")] as El[];
  if (!parts.length) return c.textContent;
  assert.equal([...c.childNodes].every((n: El) => n.nodeType === 1 && n.classList.contains("name-part")), true, "only parts inside");
  assert.equal(parts.map((p) => p.textContent).join(""), c.textContent, "the text is the same");
  return parts.map((p) => p.textContent).join(" | ");
};
const cuts = (node: El): string[] => [...node.querySelectorAll("code")].map(cut);

const PATH = "~/mandu-try/deploy/staging.conf";
const HOST = "uploads.example-storage.net";

test("L1: a long path is cut after each slash, a long host after each dot; shorter names, commands and one-part names stay one piece", async () => {
  const sentence = [
    T("Claude Code wants to send "), C(PATH), T(" and "), C("/srv//shared/projects/acme/"), T(" to "), C(HOST),
    T(" by "), C("curl -T ./deploy/staging.conf https://x"), T(" or "), C("~/mandu-try/.env"), T(" or "),
    C("AWS_SECRET_ACCESS_KEY_PRODUCTION"), T("."),
  ];
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", homeVm: home({ answered: [{ id: "a1", sentence, outcome: "blocked", decidedAt: Date.now() - 60_000, actions: [] }] }) });
  await tick();
  const said = doc.querySelector('#approvals-answered .row.answered[data-id="a1"] .answered-sentence');
  assert.ok(said, "the row is drawn");
  assert.deepEqual(cuts(said), [
    "~/ | mandu-try/ | deploy/ | staging.conf",
    "/ | srv// | shared/ | projects/ | acme/",
    "uploads. | example-storage. | net",
    "curl -T ./deploy/staging.conf https://x",
    "~/mandu-try/.env",
    "AWS_SECRET_ACCESS_KEY_PRODUCTION",
  ]);
  assert.equal(said.textContent, sentence.map((p) => p.text).join(""), "the sentence reads as before");
});

test("L2: the session page's Your secrets card cuts its long file name at the slashes, in its heading and its lines", async () => {
  const secrets = {
    mode: "secrets", flagged: false, more: 0,
    secrets: [{
      what: [C("token"), T(" in "), C(PATH)], level: "No AI",
      lines: [{ tone: "good", parts: [T("Mandu sent it only to "), C(HOST), T(".")] }],
    }],
  };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": { ...AGENT, secrets } } });
  await tick();
  const card = doc.querySelector("#agent-secrets .secret-card");
  assert.ok(card, "the card is drawn");
  assert.deepEqual(cuts(card.querySelector(".secret-what")), ["token", "~/ | mandu-try/ | deploy/ | staging.conf"]);
  assert.deepEqual(cuts(card.querySelector(".secret-line")), ["uploads. | example-storage. | net"]);
  assert.equal(card.querySelector(".secret-what").textContent, "token in " + PATH);
});

test("L3: Rules › Who may get your secrets cuts each long file of a list at its slashes", async () => {
  const vm = toByWhoVM(byWhoRules([
    { path: "/home/u/mandu-try/deploy/staging.conf", level: "no-model", bindings: [], recursive: false, readers: ["deploy"] },
    { path: "/home/u/.env", level: "no-model", bindings: [], recursive: false, readers: ["deploy"] },
  ], []), [], { home: "/home/u" });
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": RULES_PANEL, "GET policy/by-who": { byWho: vm } } });
  await tick();
  const items = [...doc.querySelectorAll("#by-who-list .by-who-items code")].map(cut);
  assert.ok(items.includes("~/ | mandu-try/ | deploy/ | staging.conf"), `the long file is cut: ${JSON.stringify(items)}`);
  assert.ok(items.includes("~/.env"), "a short one is one piece");
});

test("L4: a waiting card's cells cut a long name; its short names stay whole", async () => {
  const card = {
    ...ASK, id: "egr-9",
    sentence: [T("Claude Code wants to send your secret "), C("STRIPE_KEY"), T(" to "), C(HOST)],
    whyParts: [C("STRIPE_KEY"), T(" comes from "), C(PATH), T(".")],
  };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", homeVm: home({ waiting: [card] }) });
  await tick();
  const ask = doc.querySelector('#approvals-waiting .ask[data-id="egr-9"]');
  assert.ok(ask, "the card is drawn");
  const all = cuts(ask);
  assert.ok(all.includes("uploads. | example-storage. | net"), `the headline's host is cut: ${JSON.stringify(all)}`);
  assert.ok(all.includes("~/ | mandu-try/ | deploy/ | staging.conf"), `the cell's file is cut: ${JSON.stringify(all)}`);
  const key = [...ask.querySelectorAll("code")].find((c: El) => c.textContent === "STRIPE_KEY");
  assert.equal(key.className, "code-whole", "a short name is still kept whole");
});

test("L5: a long name holding markup is text in its parts, never markup", async () => {
  const evil = "~/mandu-try/<b>bold</b>/<img/src=x>.conf";
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", homeVm: home({ answered: [{ id: "a1", sentence: [T("Send "), C(evil)], outcome: "blocked", decidedAt: Date.now() - 60_000, actions: [] }] }) });
  await tick();
  const said = doc.querySelector('#approvals-answered .row.answered[data-id="a1"] .answered-sentence');
  assert.equal(said.querySelectorAll("img, b").length, 0);
  assert.equal(said.querySelector("code").textContent, evil);
  assert.ok(said.querySelectorAll(".name-part").length > 1, "it is cut");
});

test("L6: app.css draws a .name-part as an inline box no wider than its line that wraps inside only when alone too wide", () => {
  const css = stripComments(readFileSync(join(PUB, "app.css"), "utf8"));
  const rule = flattenCss(css).find((r) => r.selectors.includes(".name-part"));
  assert.ok(rule, "a .name-part rule");
  assert.equal(declValue(rule!.block, "display"), "inline-block");
  assert.equal(declValue(rule!.block, "max-width"), "100%");
  assert.equal(declValue(rule!.block, "overflow-wrap"), "anywhere");
  assert.ok(!flattenCss(css).some((r) => r.selectors.some((s) => /\.name-part/.test(s)) && /white-space\s*:\s*nowrap/.test(r.block)), "never nowrap: a part wider than its line wraps inside");
});

const LONG_HOST = "uploads.a-very-long-subdomain-name.example.com";

test("L7: Rules › Sending data cuts a rule's long host at its dots; a short one stays one chip", async () => {
  const rule = (id: string, subject: string) => ({
    id, kind: "release-allow", subject, effect: "sending allowed", reach: `from any source to ${subject}`, hits: 1,
    actions: { remove: true, flip: "block" },
  });
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: {
    "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [rule("r-0001", LONG_HOST), rule("r-0002", "b.example")] } },
  } });
  await tick();
  const chips = [...doc.querySelectorAll("#rules-list .row.rule .rule-text > code")] as El[];
  assert.deepEqual(chips.map(cut), ["uploads. | a-very-long-subdomain-name. | example. | com", "b.example"]);
  const row = chips[0].closest(".row.rule");
  assert.equal(row.querySelector(".rule-text").title, LONG_HOST, "the row's title is the whole name");
  assert.ok((row.querySelector(".file-more").getAttribute("aria-label") || "").includes(LONG_HOST), "⋯ names the whole host");
});

test("L8: Who may get your secrets › Hosts cuts a long host's name at its dots", async () => {
  const vm = toByWhoVM(byWhoRules([
    { path: "/home/u/.env", level: "no-model", bindings: [LONG_HOST, "api.stripe.com"], recursive: false, readers: [] },
  ], []), [], { home: "/home/u" });
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": RULES_PANEL, "GET policy/by-who": { byWho: vm } } });
  await tick();
  (doc.querySelectorAll('.by-who-tabs [role="tab"]')[1] as El).click();
  await tick();
  const names = [...doc.querySelectorAll("#by-who-list .by-who-subject")].map(cut);
  assert.ok(names.includes("uploads. | a-very-long-subdomain-name. | example. | com"), `the long host is cut: ${JSON.stringify(names)}`);
  assert.ok(names.includes("api.stripe.com"), "a short one is one piece");
});

test("L9: the session page's folder line cuts a long folder at its slashes; a short one stays one piece", async () => {
  const meta = async (cwd: string) => {
    const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": { ...AGENT, cwd } } });
    await tick();
    const line = doc.querySelector("#agent-sub .agent-when");
    assert.ok(line, "the line is drawn");
    return line;
  };
  const long = await meta("/home/u/projects/mandu-try/customer-portal-backend/services");
  assert.deepEqual(cuts(long), ["~/ | projects/ | mandu-try/ | customer-portal-backend/ | services"]);
  assert.match(long.textContent, /in ~\/projects\/mandu-try\/customer-portal-backend\/services$/, "the line reads as before");
  const short = await meta("/home/u/ws");
  assert.deepEqual(cuts(short), ["~/ws"]);
  assert.equal(short.querySelectorAll(".name-part").length, 0, "a short folder is one piece");
});

test("L10: a name in the agent's reply or the person's question breaks as elsewhere; commands, chips and code blocks as written", async () => {
  const reply = [T("At `no-model`, so `egress:secret-unbound` refused `https://api.stripe.com/v1/customers` and `" + HOST + "`. Run `git status`, `cat "), M("secret"), T("`.\n```\n" + PATH + "\n```\nAlso `<b>~/a-very-long-folder/x</b>`.")];
  const agent = { ...AGENT, waiting: [], earlier: 0, story: [
    { ...AGENT.story[1], id: "turn:names", prompt: "Why did `" + PATH + "` fail?", promptParts: null, steps: [], reply: { ts: "2026-09-25T10:01:09.000Z", parts: reply, ai: null } },
  ] };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": agent } });
  await tick();
  const text = doc.querySelector("#agent-story .reply-text");
  assert.ok(text, "the reply is drawn");
  const code = (t: string): El => [...text.querySelectorAll("code")].find((c: El) => c.textContent === t);
  for (const short of ["no-model", "egress:secret-unbound"]) {
    assert.equal(code(short).className, "name-fit", `${short} is one box`);
    assert.equal(code(short).children.length, 0, `${short} is one piece`);
  }
  assert.equal(cut(code("https://api.stripe.com/v1/customers")), "https:// | api.stripe.com/ | v1/ | customers");
  assert.equal(cut(code(HOST)), "uploads. | example-storage. | net");
  assert.equal(code("git status").className, "", "a command with a space is as written");
  const withChip = [...text.querySelectorAll("code")].find((c: El) => c.querySelector(".mask-chip")) as El;
  assert.ok(withChip, "the chip stays in its code");
  assert.equal(withChip.className, "", "a code holding a chip is as written");
  assert.equal(withChip.querySelector(".name-part"), null);
  const block = text.querySelector("pre.code-block");
  assert.equal(block.textContent, PATH, "a fenced block is as written");
  assert.equal(block.querySelector("code, .name-part"), null);
  const markup = code("<b>~/a-very-long-folder/x</b>");
  assert.equal(cut(markup), "<b>~/ | a-very-long-folder/ | x</ | b>", "markup is text in its parts");
  assert.equal(text.querySelector("b"), null);
  assert.match(text.textContent, /^At no-model, so egress:secret-unbound refused https:\/\/api\.stripe\.com\/v1\/customers and uploads\.example-storage\.net\. Run git status, cat secret\./, "the reply reads as written");
  const q = doc.querySelector("#agent-story .q-text");
  assert.equal(cut([...q.querySelectorAll("code")][0]), "~/ | mandu-try/ | deploy/ | staging.conf", "the question cuts its long name too");
  assert.equal(q.textContent, "Why did " + PATH + " fail?");
});

test("L11: the reply's and the question's codes break after a space inside their column, never hang it past; a .code-whole stays on one line", () => {
  const css = stripComments(readFileSync(join(PUB, "app.css"), "utf8"));
  const rules = flattenCss(css);
  const at = rules.findIndex((r) => r.selectors.includes(".reply-text code") && r.selectors.includes(".q-text code"));
  assert.ok(at >= 0, "a rule for the reply's and the question's codes");
  assert.equal(declValue(rules[at].block, "white-space"), "break-spaces");
  for (const box of [".reply-text", ".q-text"]) {
    const text = rules.filter((r) => r.selectors.some((s) => s.endsWith(box)) && declValue(r.block, "white-space"));
    assert.ok(text.length > 0 && text.every((r) => declValue(r.block, "white-space") === "pre-wrap"), `${box} itself keeps its spaces (pre-wrap): the case the codes' rule is for`);
  }
  const whole = rules.findIndex((r) => r.selectors.includes("code.code-whole"));
  assert.ok(whole > at && declValue(rules[whole].block, "white-space") === "nowrap", "a .code-whole's nowrap comes after and wins");
  const dom = new JSDOM(`<!doctype html><style>${css}</style><div id="agent-story"><div class="reply-text">Ran <code>! curl https://api.stripe.com/v1/customers -G -d limit=100 -u x</code>, see <code class="code-whole">mandu dashboard</code>.</div><div class="turn-q"><div class="q-text"><code>! ls -la</code></div></div></div>`);
  const win = dom.window;
  const [cmd, own, shell] = [...win.document.querySelectorAll("code")];
  assert.equal(win.getComputedStyle(cmd).whiteSpace, "break-spaces", "a reply's command");
  assert.equal(win.getComputedStyle(shell).whiteSpace, "break-spaces", "the question's command");
  assert.equal(win.getComputedStyle(own).whiteSpace, "nowrap", "a .code-whole");
  assert.equal(win.getComputedStyle(cmd).overflowWrap, "anywhere", "a word alone wider than the line still wraps inside");
});
