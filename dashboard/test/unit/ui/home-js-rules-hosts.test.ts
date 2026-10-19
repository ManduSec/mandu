/**
 * home-js-rules-hosts.test — dashboard.md §4.25u *Rules names each host*.
 * Until 2026-10-16 the Rules page named a file's hosts as plain text in its
 * own sentences: an opened row's *What the rules say › May be sent to* and
 * the *Per value* sentence under a row's second menu. Headless Chromium
 * broke "deploy-" / "hooks.example.com" in the first at 390 px and
 * "payments-" / "eu.example.com" in the second at 320 px, while Approvals
 * draws each host as its own code, kept whole up to 24 characters. Now:
 *
 *   H1  *Per value*: each value's key and each host a code (`sendParts`
 *       through nameCode), one of at most 24 characters `.code-whole`, a
 *       longer one plain; the words exactly the sentence;
 *   H2  *What the rules say*: a line with parts draws each host as a code
 *       the same way; a line without parts is its text, as before;
 *   H3  an older server (no `sendParts`, no parts): the sentence and the
 *       line as text, no code;
 *   H4  data is never markup: a host holding tags is text in a code;
 *   H5  app.css: `.file-why dd` and `.file-values` wrap a long name
 *       anywhere, and `code.code-whole` never wraps.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/rules-hosts-whole.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { PUB, load, tick, treeRow } from "./home-js-fixtures.js";
import { declValue, flattenCss, stripComments } from "./css-flatten.js";

const RULES = "http://127.0.0.1:4500/mandu/rules";
/** 24 characters (kept whole) and 29 (past the bound, wraps). */
const HOOKS = "deploy-hooks.example.com";
const S3 = "s3.eu-central-1.amazonaws.com";

type Part = { kind: "text" | "code"; text: string };
const t = (text: string): Part => ({ kind: "text", text });
const c = (text: string): Part => ({ kind: "code", text });
const SEND_PARTS: Part[] = [
  c("STRIPE_KEY"), t(" may be sent only to "), c("api.stripe.com"), t(", "), c(HOOKS),
  t("; "), c("AWS_*"), t(" only to "), c(S3),
  t("; a program holding the whole file may send it nowhere without asking."),
];
const SEND = SEND_PARTS.map((p) => p.text).join("");
const VALUES = [{ key: "STRIPE_KEY", bindings: ["api.stripe.com", HOOKS] }, { key: "AWS_*", bindings: [S3] }];

function panelWith(rule: Record<string, unknown>) {
  return { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [{
    kind: "lock", reach: null, hits: null, covers: "exact", level: "no-model", effect: "x",
    actions: { remove: true, flip: null }, ...rule,
  }] } };
}

/** Each code under `node`: its text, and `[whole]` when kept on one line. */
function drawnCodes(node: any): string[] {
  return [...node.querySelectorAll("code")].map((x: any) => {
    const short = x.textContent.length <= 24;
    assert.equal(x.classList.contains("code-whole"), short, `${x.textContent}: ${short ? "kept whole" : "past the bound, a plain code"}`);
    return x.textContent;
  });
}

test("H1: the Per value sentence names each value's key and each host as code, short ones kept whole, its words the sentence", async () => {
  const { doc } = load({ url: RULES, routes: { "GET policy/panel": panelWith({
    id: "lock:/home/u/ws/app/.env", subject: "/home/u/ws/app/.env", bindings: [], values: VALUES,
    plain: { subject: "/home/u/ws/app/.env", reach: "this file only", effect: "No AI", opens: "Programs get a masked copy.", send: SEND, sendParts: SEND_PARTS },
  }) } });
  await tick();
  const line = treeRow(doc, /app\/\.env/).querySelector(".file-values");
  assert.equal(line.textContent, SEND, "the words exactly the sentence");
  assert.deepEqual(drawnCodes(line), ["STRIPE_KEY", "api.stripe.com", HOOKS, "AWS_*", S3], "each key and each host its own code");
});

test("H2: an opened rule's What the rules say draws May be sent to with each host as code; a line without parts stays text", async () => {
  const path = "/home/u/ws/.env";
  const hosts = ["api.stripe.com", "db.internal:5432", HOOKS, S3];
  const why = { why: { path, display: "~/ws/.env", label: { level: "no-model", words: "No AI", source: "yours", from: "Your rule", bindings: hosts }, off: false, lines: [
    { term: "Where the label comes from", text: "Your rule (~/ws/.env)" },
    { term: "May be sent to", text: hosts.join(", "), parts: hosts.flatMap((h, i) => (i ? [t(", "), c(h)] : [c(h)])) },
  ] } };
  const { doc } = load({ url: RULES, routes: {
    "GET policy/panel": panelWith({ id: `lock:${path}`, subject: path, bindings: hosts, plain: { subject: path, reach: "this file only", effect: `No AI; may be sent to ${hosts.join(", ")}` } }),
    [`GET files/why?path=${encodeURIComponent(path)}`]: why,
  } });
  await tick();
  treeRow(doc, /ws\/\.env$/).querySelector(".file-more").click();
  await tick();
  const box = doc.querySelector("#files-tree .file-detail .file-why");
  assert.ok(box, "the opened row says what the rules say");
  const dds = [...box.querySelectorAll("dd")] as any[];
  assert.equal(dds.length, 2);
  assert.equal(dds[0].textContent, "Your rule (~/ws/.env)");
  assert.equal(dds[0].querySelector("code"), null, "a line without parts is its text, as before");
  assert.equal(dds[1].textContent, hosts.join(", "), "the words as the text");
  assert.deepEqual(drawnCodes(dds[1]), hosts, "each host its own code");
});

test("H3: from an older server (no sendParts, no parts) the sentence and the line are text, as before", async () => {
  const path = "/home/u/ws/app/.env";
  const why = { why: { path, display: "~/ws/app/.env", label: { level: "no-model", words: "No AI", source: "yours", from: "Your rule", bindings: [] }, off: false, lines: [
    { term: "May be sent to", text: "Nowhere without your OK." },
  ] } };
  const { doc } = load({ url: RULES, routes: {
    "GET policy/panel": panelWith({ id: `lock:${path}`, subject: path, bindings: [], values: VALUES, plain: { subject: path, reach: "this file only", effect: "No AI", send: SEND } }),
    [`GET files/why?path=${encodeURIComponent(path)}`]: why,
  } });
  await tick();
  const row = treeRow(doc, /app\/\.env/);
  assert.equal(row.querySelector(".file-values").textContent, SEND);
  assert.equal(row.querySelector(".file-values code"), null, "no parts: one text");
  row.querySelector(".file-more").click();
  await tick();
  const dd = doc.querySelector("#files-tree .file-why dd");
  assert.equal(dd.textContent, "Nowhere without your OK.");
  assert.equal(dd.querySelector("code"), null);
});

test("H4: a host holding tags is drawn as text inside its code, never as markup", async () => {
  const evil = "<img src=x onerror=alert(1)>";
  const path = "/home/u/ws/.env";
  const why = { why: { path, display: "~/ws/.env", label: { level: "no-model", words: "No AI", source: "yours", from: "Your rule", bindings: [evil] }, off: false, lines: [
    { term: "May be sent to", text: evil, parts: [c(evil)] },
  ] } };
  const sendParts = [c("<b>K</b>"), t(" may be sent only to "), c(evil), t("; a program holding the whole file may send it nowhere without asking.")];
  const { doc } = load({ url: RULES, routes: {
    "GET policy/panel": panelWith({ id: `lock:${path}`, subject: path, bindings: [], values: [{ key: "<b>K</b>", bindings: [evil] }], plain: { subject: path, reach: "this file only", effect: "No AI", send: sendParts.map((p) => p.text).join(""), sendParts } }),
    [`GET files/why?path=${encodeURIComponent(path)}`]: why,
  } });
  await tick();
  const row = treeRow(doc, /ws\/\.env$/);
  row.querySelector(".file-more").click();
  await tick();
  const values = treeRow(doc, /ws\/\.env$/).querySelector(".file-values");
  assert.equal(values.querySelector("img, b"), null, "the sentence holds no markup");
  assert.deepEqual([...values.querySelectorAll("code")].map((x: any) => x.textContent), ["<b>K</b>", evil]);
  const dd = doc.querySelector("#files-tree .file-why dd");
  assert.equal(dd.querySelector("img"), null, "the line holds no markup");
  assert.equal(dd.querySelector("code").textContent, evil);
});

test("H5: app.css lets a long name in a Rules line wrap anywhere, and never wraps a .code-whole", () => {
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  for (const sel of [".file-why dd", ".file-values"]) {
    const own = rules.filter((r) => r.media === null && r.selectors.includes(sel));
    assert.ok(own.some((r) => declValue(r.block, "overflow-wrap") === "anywhere"), `${sel} wraps a long name where it must`);
  }
  const whole = rules.filter((r) => r.media === null && r.selectors.includes("code.code-whole"));
  assert.ok(whole.some((r) => declValue(r.block, "white-space") === "nowrap"), "code.code-whole stays on one line");
});
