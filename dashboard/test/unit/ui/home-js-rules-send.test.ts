/**
 * home-js-rules-send.test — dashboard.md §4.25u *Rules names what a send
 * covers*. Until 2026-10-16 Rules › *Sending data* drew the line under a
 * row as one text ("sending only the file ~/mandu-try/.env", "sending any
 * masked data from docs.python.org"), while the Approvals card that made the
 * answer names the same file as code, and drew a send rule to `*` as the
 * chip `anywhere`, a word in the code font. Now the panel sends the line's
 * names as parts (`plain.reachParts`), the word as words (`subjectParts`):
 *
 *   S1  an answer's reach line names its file, address or command as code
 *       (each in a `.name-fit`, fitWords), its text exactly `plain.reach`;
 *       a command keeps its quotes, as text around the code;
 *   S2  a send rule to anywhere says "anywhere" as a word, not a chip, and
 *       names its source as code; the buttons say "anywhere"; a send rule
 *       to a host keeps the host's chip;
 *   S3  an older server (no parts) draws the line as one text and
 *       "anywhere" as the chip, as before; a reach naming nothing is text;
 *   S4  data is never markup: a file name holding tags is text in its code;
 *   S5  under the served styles the line wraps between its words and a name
 *       wraps inside only when the column is narrower than it;
 *   S6  (2026-10-17, *A send rule's dot is its answer's*) a send rule's menu
 *       has the dot of an answer with the same words: red for Always
 *       blocked, green for Always allowed, read from the rule's kind; an
 *       expired, audit or off rule keeps the grey ring;
 *   S7  under the served styles the two "Always blocked" dots are one
 *       colour, and an expired rule's is not filled.
 *   S8  (2026-10-23, *A rule with an end date says when*) a send rule with
 *       an end still to come (`plain.until`) reads "Always allowed until
 *       Dec 1, 09:00", the moment a <time> whose datetime is the ISO, in
 *       the reader's clock, the full date on hover; the opened row says
 *       it again with how long is left; Find finds it by those words;
 *       a rule without `until` draws no such line;
 *   S9  an Approvals row with a time part draws a <time>, not a code; a
 *       part kind this page does not know still draws its text.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/rules-send-names.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { PUB, load, tick } from "./home-js-fixtures.js";
import { resolveCssVars } from "./css-flatten.js";

const RULES = "http://127.0.0.1:4500/mandu/rules";
const STYLES = resolveCssVars(readFileSync(join(PUB, "mandu.css"), "utf8") + "\n" + readFileSync(join(PUB, "app.css"), "utf8"));

type Part = { kind: "text" | "code"; text: string };
const t = (text: string): Part => ({ kind: "text", text });
const c = (text: string): Part => ({ kind: "code", text });
const words = (parts: Part[]) => parts.map((p) => p.text).join("");

/** A send rule as `/api/policy/panel` sends it (policy-panel.ts). */
function sendRule(id: string, to: string, from: string | null, parts: boolean, mode = "allow", expired = false) {
  const subject = to === "*" ? "anywhere" : to;
  const reachParts = from ? [t("sending any masked data from "), c(from)] : null;
  return {
    id, kind: `release-${mode}`, subject, effect: "sending allowed — no ask", reach: `from ${from ?? "any source"} to ${to === "*" ? "any destination" : to}`, hits: null,
    expired, actions: { remove: true, flip: mode === "block" ? "allow" : "block" },
    plain: {
      subject,
      ...(parts && to === "*" ? { subjectParts: [t("anywhere")] } : {}),
      reach: reachParts ? words(reachParts) : "sending any masked data",
      ...(parts && reachParts ? { reachParts } : {}),
      effect: expired ? "Expired, no longer used" : mode === "allow" ? "Always allowed" : mode === "block" ? "Always blocked" : mode === "audit" ? "Only counted, still needs your OK" : "Turned off",
    },
  };
}

/** An answered send as the panel's queue sends it. */
function answer(id: string, target: string, reachParts: Part[], parts: boolean) {
  return {
    id, status: "denied", scope: "always", where: "network", target, count: 1, sessions: [], resolvedAt: null,
    actions: [{ approve: true, label: "Allow instead" }],
    plain: { subject: target, reach: words(reachParts), ...(parts ? { reachParts } : {}), effect: "Always blocked" },
  };
}

const ANSWERS = (parts = true) => [
  answer("egr-1", "uploads.example-storage.net", [t("sending only the file "), c("~/mandu-try/.env")], parts),
  answer("egr-2", "paste.example", [t("sending only what was fetched from "), c("httpbin.org/get")], parts),
  answer("egr-3", "paste.example", [t("sending only the output of “"), c("cat notes.md"), t("”")], parts),
  answer("egr-4", "hooks.slack.com", [t("a program in one session sending data from "), c("~/a.csv"), t(", "), c("~/.env"), t(" and 2 more")], parts),
];
const RULES_ROWS = (parts = true) => [
  sendRule("r-0004", "*", "docs.python.org", parts),
  sendRule("r-0005", "api.github.com", "*.internal.example", parts),
  sendRule("r-0002", "b.example", null, parts),
];

function page(yourRules: unknown[], queue: unknown[]) {
  return load({ url: RULES, routes: {
    "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue, yourRules } },
  } });
}

const rows = (doc: any) => [...doc.querySelectorAll("#rules-list .row.rule")] as any[];
const rowOf = (doc: any, title: string) => rows(doc).find((r) => r.querySelector(".rule-text").title === title);
const subjectOf = (row: any) => row.querySelector(".rule-text").firstElementChild;
const reachOf = (row: any) => row.querySelector(".rule-text > .dim");
/** The line's names and words in order: codes as `[name]`. */
function drawn(node: any): string {
  if (node.tagName === "CODE") return `[${node.textContent}]`;
  let out = "";
  const walk = (n: any) => {
    for (const k of n.childNodes) {
      if (k.nodeType === 3) out += k.textContent;
      else if (k.tagName === "CODE") out += `[${k.textContent}]`;
      else walk(k);
    }
  };
  walk(node);
  return out;
}

test("S1: an answer's reach line names its file, address or command as code, the text exactly plain.reach", async () => {
  const { doc } = page([], ANSWERS());
  await tick();
  const lines = rows(doc).map((r) => reachOf(r));
  assert.deepEqual(lines.map((l) => [l.className, drawn(l)]).sort((a, b) => a[1]!.localeCompare(b[1]!)), [
    ["dim rule-reach", "a program in one session sending data from [~/a.csv], [~/.env] and 2 more"],
    ["dim rule-reach", "sending only the file [~/mandu-try/.env]"],
    ["dim rule-reach", "sending only the output of “[cat notes.md]”"],
    ["dim rule-reach", "sending only what was fetched from [httpbin.org/get]"],
  ]);
  const byText = new Map(ANSWERS().map((a) => [a.plain.reach, a]));
  for (const l of lines) {
    assert.ok(byText.has(l.textContent), `${l.textContent}: the line's text is plain.reach, byte for byte`);
    for (const code of l.querySelectorAll("code")) assert.equal(code.parentElement.className, "name-fit", `${code.textContent}: kept whole where the column holds it`);
  }
  // The subject is the host's chip, as before.
  assert.deepEqual(rows(doc).map((r) => subjectOf(r).tagName), ["CODE", "CODE", "CODE", "CODE"]);
});

test("S2: a send rule to anywhere says \"anywhere\" as a word and its source as code; one to a host keeps the chip", async () => {
  const { doc } = page(RULES_ROWS(), []);
  await tick();
  const any = rowOf(doc, "anywhere");
  assert.equal(subjectOf(any).tagName, "SPAN");
  assert.equal(subjectOf(any).className, "rule-subject");
  assert.equal(drawn(subjectOf(any)), "anywhere", "a word, no code");
  assert.equal(subjectOf(any).querySelector("code"), null);
  assert.equal(drawn(reachOf(any)), "sending any masked data from [docs.python.org]");
  assert.equal(any.querySelector(".file-more").getAttribute("aria-label"), "More about anywhere");
  const gh = rowOf(doc, "api.github.com");
  assert.deepEqual([subjectOf(gh).tagName, subjectOf(gh).textContent], ["CODE", "api.github.com"]);
  assert.equal(drawn(reachOf(gh)), "sending any masked data from [*.internal.example]");
  const b = rowOf(doc, "b.example");
  assert.deepEqual([drawn(reachOf(b)), reachOf(b).childNodes.length, reachOf(b).firstChild.nodeType], ["sending any masked data", 1, 3], "a reach that names nothing is one text, as before");
});

test("S3: an older server without parts draws each line as one text and \"anywhere\" as the chip, as before", async () => {
  const { doc } = page(RULES_ROWS(false), ANSWERS(false));
  await tick();
  for (const r of rows(doc)) {
    const l = reachOf(r);
    assert.equal(l.querySelector("code"), null, `${l.textContent}: no code without parts`);
    assert.equal(l.childNodes.length, 1);
  }
  assert.deepEqual([subjectOf(rowOf(doc, "anywhere")).tagName, subjectOf(rowOf(doc, "anywhere")).textContent], ["CODE", "anywhere"]);
  assert.equal(doc.querySelector("#rules-list .rule-subject"), null);
});

test("S4: a file name holding tags is drawn as text inside its code, never as markup", async () => {
  const evil = "~/<img src=x onerror=alert(1)>.env";
  const { doc } = page([], [answer("egr-9", "x.example", [t("sending only the file "), c(evil), t(" <b>now</b>")], true)]);
  await tick();
  const l = reachOf(rows(doc)[0]);
  assert.equal(l.querySelector("img, b"), null, "no markup");
  assert.equal(drawn(l), `sending only the file [${evil}] <b>now</b>`);
});

test("S5: under the served styles the reach line wraps between its words, and a name wraps inside only when it must", async () => {
  const { doc } = page(RULES_ROWS(), ANSWERS());
  const s = doc.createElement("style");
  s.textContent = STYLES;
  doc.head.append(s);
  await tick();
  const css = (e: any) => doc.defaultView.getComputedStyle(e);
  for (const r of rows(doc)) {
    const l = reachOf(r);
    assert.notEqual(css(l).whiteSpace, "nowrap", `${l.textContent}: the words wrap`);
    for (const box of l.querySelectorAll(".name-fit") as any) {
      assert.equal(css(box).display, "inline-block", "the name moves whole to the next line");
      assert.equal(css(box).maxWidth, "100%", "never wider than its line");
      assert.equal(css(box.firstElementChild).overflowWrap, "anywhere", "and wraps inside only when the column is narrower");
    }
  }
  // The probe can tell the fonts apart: a host's chip is in the code font.
  assert.match(css(subjectOf(rowOf(doc, "api.github.com"))).fontFamily, /Mono/, "a host's chip is in the code font");
  assert.doesNotMatch(css(subjectOf(rowOf(doc, "anywhere"))).fontFamily, /Mono/, "\"anywhere\" is in the page's font, not the code font");
});

/** The menus' colours, by row title: `data-effect` on each `.label-pick`. */
const MIXED = () => [
  sendRule("r-0010", "b.example", null, true, "block"),
  sendRule("r-0011", "api.github.com", null, true, "allow"),
  sendRule("r-0012", "old.example", null, true, "block", true),
  sendRule("r-0013", "audit.example", null, true, "audit"),
  sendRule("r-0014", "off.example", null, true, "off"),
];
const toneOf = (row: any) => row.querySelector(".label-pick").getAttribute("data-effect");

test("S6: a send rule's menu has the dot of an answer with the same words, read from its kind; expired, audit and off stay grey", async () => {
  const { doc } = page(MIXED(), [answer("egr-1", "uploads.example-storage.net", [t("sending only the file "), c("~/mandu-try/.env")], true)]);
  await tick();
  const seen = rows(doc).map((r) => [r.querySelector(".rule-text").title, r.querySelector("select").options[0].textContent, toneOf(r)]);
  assert.deepEqual(seen.sort((a, b) => a[0]!.localeCompare(b[0]!)), [
    ["api.github.com", "Always allowed", "allow"],
    ["audit.example", "Only counted, still needs your OK", "none"],
    ["b.example", "Always blocked", "block"],
    ["off.example", "Turned off", "none"],
    ["old.example", "Expired, no longer used", "none"],
    ["uploads.example-storage.net", "Always blocked", "block"],
  ]);
  // Every menu that says the same words has the same colour.
  const byWords = new Map<string, Set<string>>();
  for (const [, w, tone] of seen) byWords.set(w!, (byWords.get(w!) ?? new Set()).add(tone!));
  for (const [w, tones] of byWords) assert.equal(tones.size, 1, `${w}: one colour`);
  // The colour comes from the kind, not the words: a rule whose words a
  // server changed keeps its kind's colour.
  const { doc: d2 } = page([{ ...sendRule("r-0020", "c.example", null, true, "block"), plain: { subject: "c.example", reach: "sending any masked data", effect: "Blocked, no ask" } }], []);
  await tick();
  assert.equal(toneOf(rows(d2)[0]), "block");
});

test("S7: under the served styles both \"Always blocked\" dots are the same red, and an expired rule's dot is not filled", async () => {
  const { doc } = page(MIXED(), [answer("egr-1", "uploads.example-storage.net", [t("sending only the file "), c("~/mandu-try/.env")], true)]);
  const s = doc.createElement("style");
  s.textContent = STYLES;
  doc.head.append(s);
  await tick();
  const dot = (title: string) => doc.defaultView.getComputedStyle(rowOf(doc, title).querySelector(".label-dot"));
  const rule = dot("b.example"), ans = dot("uploads.example-storage.net"), allowed = dot("api.github.com"), old = dot("old.example");
  assert.equal(rule.backgroundColor, ans.backgroundColor, "the rule's dot is the answer's");
  assert.notEqual(rule.backgroundColor, old.backgroundColor, "a filled dot, not the ring");
  assert.notEqual(allowed.backgroundColor, rule.backgroundColor, "allowed is not blocked's colour");
  assert.notEqual(allowed.backgroundColor, old.backgroundColor, "allowed is filled too");
});

/** "Dec 1, 09:00" in this process's own clock, with the year when it is not
 *  this year, as the page says it. */
function clock(iso: string): string {
  const d = new Date(iso);
  const pad = (k: number) => String(k).padStart(2, "0");
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const year = d.getFullYear() === new Date().getFullYear() ? "" : `, ${d.getFullYear()}`;
  return `${months[d.getMonth()]} ${d.getDate()}${year}, ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

test("S8: a send rule with an end still to come reads \"Always allowed until <moment>\", again with how long is left when opened", async () => {
  const until = new Date(Date.now() + 9 * 86_400_000 + 3_600_000).toISOString();
  const later = sendRule("r-0007", "pastebin.com", null, true);
  const ends = { ...later, plain: { ...later.plain, until } };
  const { doc, window: win } = page([ends, sendRule("r-0002", "b.example", null, true)], []);
  await tick();
  const row = rowOf(doc, "pastebin.com");
  const line = row.querySelector(".rule-effect .rule-until");
  assert.ok(line, "the end is drawn under the effect");
  assert.equal(row.querySelector(".rule-effect select").options[0].textContent, "Always allowed", "the menu keeps its words");
  assert.equal(line.textContent, `until ${clock(until)}`);
  assert.match(line.textContent, /^until [A-Z][a-z]{2} \d{1,2}(, \d{4})?, \d{2}:\d{2}$/, "clock words, never the ISO");
  const time = line.querySelector("time");
  assert.equal(time.getAttribute("datetime"), until);
  assert.match(time.title, /^[A-Z][a-z]+day, [A-Z][a-z]{2} \d{1,2}, \d{4}, \d{2}:\d{2}$/, "the full date on hover");
  assert.doesNotMatch(row.textContent, /T\d{2}:\d{2}/, "no ISO on the row");
  // A rule without an end: no line, the effect where it was.
  assert.equal(rowOf(doc, "b.example").querySelector(".rule-until, .rule-effect"), null);
  // Opened: the row's words again, and how long is left.
  row.querySelector(".file-more").click();
  await tick();
  const ends9 = doc.querySelector("#rules-list .rule-detail .rule-ends");
  assert.equal(ends9.textContent, `Always allowed until ${clock(until)}, ends in 9 days.`);
  assert.equal(ends9.querySelector("time").getAttribute("datetime"), until);
  // Find reads the words the row draws.
  const find = doc.getElementById("rules-find");
  {
    find.value = clock(until).split(",")[0];
    find.dispatchEvent(new win.Event("input"));
    await tick();
    assert.deepEqual(rows(doc).map((r) => r.querySelector(".rule-text").title), ["pastebin.com"], "Find matches the end's words");
  }
});

test("S9: an Approvals row with a time part draws a <time>, not code; an unknown part kind draws its text", async () => {
  const until = "2026-12-01T00:00:00Z";
  const proposal = {
    id: "pp-000031", status: "pending", requester: "Your agent", createdAt: Date.now() - 60_000,
    rows: [[t("Always allow sending masked data from anywhere to "), c("pastebin.com"), t(" until "), { kind: "time", text: until }, { kind: "sparkle", text: " (soon)" }]],
    wouldLet: [], capped: false, overBroad: false, reason: "share",
  };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { "GET policy/proposals?status=pending": { proposals: [proposal] } } });
  await tick();
  const li = doc.querySelector('#approvals-proposals [data-id="pp-000031"] .proposal-rows li');
  assert.ok(li, "the row is drawn");
  assert.deepEqual([...li.querySelectorAll("code")].map((x: any) => x.textContent), ["pastebin.com"], "the end is no code");
  const time = li.querySelector("time");
  assert.equal(time.getAttribute("datetime"), until);
  assert.equal(time.textContent, clock(until));
  assert.equal(li.textContent, `Always allow sending masked data from anywhere to pastebin.com until ${clock(until)} (soon)`);
});
