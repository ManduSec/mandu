/**
 * home-js-rules-connect.test — dashboard.md §4.25u *Rules names a connection
 * in words*. Until 2026-10-16 Rules › *Programs and connections* drew a
 * connection rule as one raw code (`*:2222`, `*.example.org:*`,
 * `10.0.0.0/8:53 (udp)`, the "(udp)" inside the code), while the Approvals
 * card that asked for the same rule says "any address on port `2222`". Now
 * the panel sends the row's words as parts (`plain.subjectParts`) and:
 *
 *   R1  words around names are one line (`.rule-subject`): its text exactly
 *       `plain.subject`, each name a code in a `.name-fit` (fitWords), the
 *       words as text; the reach line under it as before;
 *   R2  the row's buttons say the same words (⋯, Show in policy.yaml,
 *       Remove), and Remove posts the row's id, unchanged;
 *   R3  a subject that is one name stays the one `<code>` chip (`pypi.org:443`),
 *       and an older server (no parts) draws its subject as that chip;
 *   R4  data is never markup: a host holding tags is text in its code;
 *   R5  under the served styles, a name in the line wraps inside only when
 *       the column is narrower than it (`.name-fit`), and nothing in the
 *       line is kept from wrapping;
 *   R6  (2026-10-17, *A connection rule is coloured as its answer*) a
 *       connection rule says "Always allowed, from the agent's next start"
 *       in green with a ✓, and a built-in protection set to Block says
 *       "Always blocked, instead of asking you" in red with a ✗, as the
 *       answers about commands beside them are coloured; the colour comes
 *       from the rule's kind, not its words; a program rule stays grey;
 *   R7  under the served styles the connection's green is the allowed
 *       answer's dot, and the built-in's red is the blocked answer's.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/rules-connect-words.test.ts. Axes: none (display only).
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

/** A connection row as `/api/policy/panel` sends it (policy-panel.ts). */
function connectRow(spec: string, subject: string, parts: Part[] | null) {
  return {
    id: `connect:${spec}`, kind: "connect-allow", subject, reach: null, hits: null,
    effect: "the agent may connect there — from the next launch, in every posture",
    actions: { remove: true, flip: null },
    plain: {
      subject: parts ? parts.map((p) => p.text).join("") : subject,
      ...(parts ? { subjectParts: parts } : {}),
      reach: "your agent's programs connecting", effect: "Always allowed, from the agent's next start",
    },
  };
}

const ROWS = [
  connectRow("tcp:*:2222", "*:2222", [t("any address on port "), c("2222")]),
  connectRow("tcp:*.example.org:*", "*.example.org:*", [c("*.example.org"), t(" on any port")]),
  connectRow("udp:10.0.0.0/8:53", "10.0.0.0/8:53 (udp)", [c("10.0.0.0/8:53"), t(" over UDP")]),
  connectRow("tcp:pypi.org:443", "pypi.org:443", [c("pypi.org:443")]),
];

function page(rows: unknown[], routes: Record<string, unknown> = {}) {
  const posted: unknown[] = [];
  const loaded = load({ url: RULES, routes: {
    "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: [], yourRules: rows } },
    "POST policy/rules/change": (b: unknown) => { posted.push(b); return { applied: true, changeId: "pc-0001" }; },
    ...routes,
  } });
  return { ...loaded, posted };
}

const rows = (doc: any) => [...doc.querySelectorAll("#rules-list .row.rule")] as any[];
const subjectOf = (row: any) => row.querySelector(".rule-text").firstElementChild;
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

test("R1: a connection rule's words around its names are one line, each name a code, the words exactly plain.subject", async () => {
  const { doc } = page(ROWS);
  await tick();
  const got = rows(doc).map((r) => {
    const s = subjectOf(r);
    return [s.tagName, s.className, drawn(s), s.textContent];
  });
  assert.deepEqual(got, [
    ["SPAN", "rule-subject", "any address on port [2222]", "any address on port 2222"],
    ["SPAN", "rule-subject", "[*.example.org] on any port", "*.example.org on any port"],
    ["SPAN", "rule-subject", "[10.0.0.0/8:53] over UDP", "10.0.0.0/8:53 over UDP"],
    ["CODE", "", "[pypi.org:443]", "pypi.org:443"],
  ]);
  for (const r of rows(doc).slice(0, 3)) {
    for (const code of subjectOf(r).querySelectorAll("code")) {
      assert.equal(code.parentElement.className, "name-fit", `${code.textContent}: kept whole where the column holds it`);
    }
    assert.equal(r.querySelector(".rule-text > .dim").textContent, "your agent's programs connecting", "the reach line under it, as before");
  }
  assert.ok(!doc.querySelector("#rules-list").textContent.includes("(udp)"), "no protocol code left on the page");
});

test("R2: the row's buttons say the same words, and Remove posts the row's id as before", async () => {
  const { doc, posted } = page(ROWS);
  await tick();
  const row = rows(doc)[0];
  const more = row.querySelector(".file-more");
  assert.equal(more.getAttribute("aria-label"), "More about any address on port 2222");
  assert.equal(row.querySelector(".rule-text").title, "*:2222", "the tooltip keeps the rule as written in force");
  more.click();
  await tick();
  const box = rows(doc)[0].nextElementSibling;
  assert.equal(box.getAttribute("aria-label"), "About any address on port 2222");
  const remove = [...box.querySelectorAll("button")].find((b: any) => b.textContent === "Remove") as any;
  assert.equal(remove.getAttribute("aria-label"), "Remove the rule for any address on port 2222");
  const source = box.querySelector(".rule-source-btn");
  assert.match(source.getAttribute("aria-label") ?? source.textContent, /any address on port 2222/);
  remove.click();
  await tick();
  assert.deepEqual(posted, [{ id: "connect:tcp:*:2222", action: "remove" }], "the same id and action as before");
});

test("R3: one name stays its chip; an older server without parts draws the subject as that chip", async () => {
  const old = ROWS.map((r) => ({ ...r, plain: { subject: r.subject, reach: r.plain.reach, effect: r.plain.effect } }));
  const { doc } = page(old);
  await tick();
  assert.deepEqual(rows(doc).map((r) => [subjectOf(r).tagName, subjectOf(r).textContent]), [
    ["CODE", "*:2222"], ["CODE", "*.example.org:*"], ["CODE", "10.0.0.0/8:53 (udp)"], ["CODE", "pypi.org:443"],
  ], "an older server's subject, one chip each, as before");
  assert.equal(doc.querySelector("#rules-list .rule-subject"), null);
});

test("R4: a host holding tags is drawn as text inside its code, never as markup", async () => {
  const evil = "<img src=x onerror=alert(1)>";
  const { doc } = page([connectRow(`tcp:${evil}:*`, `${evil}:*`, [c(evil), t(" on any port <b>now</b>")])]);
  await tick();
  const s = subjectOf(rows(doc)[0]);
  assert.equal(s.querySelector("img, b"), null, "no markup");
  assert.equal(drawn(s), `[${evil}] on any port <b>now</b>`);
});

test("R5: under the served styles a name in the line wraps inside only when it must, and nothing in the line is kept from wrapping", async () => {
  const { doc } = page(ROWS);
  const s = doc.createElement("style");
  s.textContent = STYLES;
  doc.head.append(s);
  await tick();
  const css = (e: any) => doc.defaultView.getComputedStyle(e);
  for (const r of rows(doc).slice(0, 3)) {
    const line = subjectOf(r);
    assert.equal(line.className, "rule-subject", "words around names are one line");
    assert.notEqual(css(line).whiteSpace, "nowrap", "the words wrap between them");
    const boxes = [...line.querySelectorAll(".name-fit")];
    assert.equal(boxes.length, 1, `${line.textContent}: its name in a box`);
    for (const box of boxes as any[]) {
      assert.equal(css(box).display, "inline-block", "the name moves whole to the next line");
      assert.equal(css(box).maxWidth, "100%", "never wider than its line");
      assert.equal(css(box.firstElementChild).overflowWrap, "anywhere", "and wraps inside only when the column is narrower");
      assert.notEqual(css(box.firstElementChild).whiteSpace, "nowrap");
    }
  }
  const chip = subjectOf(rows(doc)[3]);
  assert.equal(css(chip).alignSelf, "flex-start", "a one-name subject keeps its own chip width (§4.25c)");
});

/** A built-in protection set to Block, as the panel sends it. */
function dispositionRow(ruleId: string, name: string) {
  return {
    id: `disposition:${ruleId}`, kind: "disposition", subject: ruleId, reach: null, hits: null,
    effect: "set to Block — the built-in ask is denied without asking",
    actions: { remove: true, flip: null },
    plain: { subject: name, reach: "a built-in protection", effect: "Always blocked, instead of asking you" },
  };
}
/** A program rule (kept for its warning), as the panel sends it. */
const PROGRAM = {
  id: "app:jq", kind: "lock", subject: "jq", reach: null, hits: null, effect: "program rule",
  actions: { remove: false, flip: null },
  plain: { subject: "jq", reach: "a program", effect: "Its output is masked after it reads a secret file" },
};
/** An answer about a command, in the same group, as the queue sends it. */
function execAnswer(id: string, command: string, approved: boolean) {
  return {
    id, status: approved ? "approved" : "denied", scope: "always", where: "exec", target: command, count: 1, sessions: [], resolvedAt: null,
    actions: [{ approve: !approved, label: approved ? "Block instead" : "Allow instead" }],
    plain: { subject: command, reach: "running this command", effect: approved ? "Always allowed" : "Always blocked" },
  };
}
const RUN_ROWS = [ROWS[0], ROWS[3], dispositionRow("net.untrusted-destination", "untrusted destination"), PROGRAM];
const RUN_ANSWERS = [execAnswer("ex-1", "make test", true), execAnswer("ex-2", "curl evil.example", false)];

function runPage() {
  return load({ url: RULES, routes: {
    "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: RUN_ANSWERS, yourRules: RUN_ROWS } },
  } });
}
/** A row's effect as drawn: its class, its mark (✓ check / ✗ x / none) and its words. */
function effectOf(row: any): [string, string, string] {
  const pick = row.querySelector(".label-pick");
  if (pick) return [`menu ${pick.getAttribute("data-effect")}`, "dot", pick.querySelector("select").options[0].textContent];
  const cell = row.querySelector(".rule-text").nextElementSibling;
  const mark = cell.querySelector("svg") ? (cell.className === "outcome ok" ? "check" : "x") : "none";
  return [cell.className, mark, cell.textContent];
}

test("R6: a connection rule is green with a check and a built-in set to Block red with an x, as the answers beside them; a program rule stays grey", async () => {
  const { doc } = runPage();
  await tick();
  const seen = rows(doc).map((r) => [r.querySelector(".rule-text").title, ...effectOf(r)]);
  assert.deepEqual(seen, [
    ["*:2222", "outcome ok", "check", "Always allowed, from the agent's next start"],
    ["pypi.org:443", "outcome ok", "check", "Always allowed, from the agent's next start"],
    ["net.untrusted-destination", "outcome bad", "x", "Always blocked, instead of asking you"],
    ["jq", "sub", "none", "Its output is masked after it reads a secret file"],
    ["make test", "menu allow", "dot", "Always allowed"],
    ["curl evil.example", "menu block", "dot", "Always blocked"],
  ]);
  for (const r of rows(doc).slice(0, 3)) {
    const cell = r.querySelector(".rule-text").nextElementSibling;
    assert.equal(cell.querySelector("svg").getAttribute("aria-hidden"), "true", "the mark is not read out: the words say it");
  }
  // The colour comes from the kind, not the words: a server that words them
  // differently keeps the kind's colour.
  const reworded = [{ ...ROWS[0], plain: { ...ROWS[0].plain, effect: "May connect" } }, { ...dispositionRow("exec.x", "x"), plain: { subject: "x", reach: "a built-in protection", effect: "Denied" } }];
  const { doc: d2 } = load({ url: RULES, routes: { "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: [], yourRules: reworded } } } });
  await tick();
  assert.deepEqual(rows(d2).map((r) => effectOf(r).slice(0, 2)), [["outcome ok", "check"], ["outcome bad", "x"]]);
});

test("R7: under the served styles the connection's green is the allowed answer's dot, and the built-in's red the blocked answer's", async () => {
  const { doc } = runPage();
  const s = doc.createElement("style");
  s.textContent = STYLES;
  doc.head.append(s);
  await tick();
  const css = (e: any) => doc.defaultView.getComputedStyle(e);
  const byTitle = (title: string) => rows(doc).find((r) => r.querySelector(".rule-text").title === title);
  const cell = (title: string) => byTitle(title).querySelector(".rule-text").nextElementSibling;
  const dot = (title: string) => css(byTitle(title).querySelector(".label-dot")).backgroundColor;
  const green = dot("make test"), red = dot("curl evil.example");
  assert.notEqual(green, red);
  assert.equal(css(cell("*:2222")).color, green, "the connection's words are the allowed answer's green");
  assert.equal(css(cell("net.untrusted-destination")).color, red, "the built-in's words are the blocked answer's red");
  const grey = css(cell("jq")).color;
  assert.notEqual(grey, green);
  assert.notEqual(grey, red);
});
