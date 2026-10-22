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
 *   H5  app.css: `.file-why dd`, `.file-values` and `.file-values-how`
 *       wrap a long name anywhere, and `code.code-whole` never wraps;
 *   H6  *Per value* says on the page how to change it (§4.25p): a line
 *       under the sentence names `values:` and the policy file as the
 *       panel reports it (else `policy.yaml`), and the disabled menu,
 *       which Tab skips and a touch screen cannot hover, is described by
 *       it (`aria-describedby`); an inherited row gets the line too;
 *   H7  a row without `values:` has no such line.
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

import { FILES_ROUTES, PUB, WS_LIST, chip, list, load, rowFor, tick, treeRow } from "./home-js-fixtures.js";
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

function panelWith(rule: Record<string, unknown>, more: Record<string, unknown> = {}) {
  return { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [{
    kind: "lock", reach: null, hits: null, covers: "exact", level: "no-model", effect: "x",
    actions: { remove: true, flip: null }, ...rule,
  }], ...more } };
}
/** The panel's policy file (policy-panel-types.ts `PolicyFileVM`). */
const POLICY_FILE = { path: "/home/u/.mandu/policy.yaml", found: true, valid: true, problems: [], loadedAt: 1, refusedAt: null };

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
  for (const sel of [".file-why dd", ".file-values", ".file-values-how"]) {
    const own = rules.filter((r) => r.media === null && r.selectors.includes(sel));
    assert.ok(own.some((r) => declValue(r.block, "overflow-wrap") === "anywhere"), `${sel} wraps a long name where it must`);
  }
  const whole = rules.filter((r) => r.media === null && r.selectors.includes("code.code-whole"));
  assert.ok(whole.some((r) => declValue(r.block, "white-space") === "nowrap"), "code.code-whole stays on one line");
});

const PER_VALUE_RULE = {
  id: "lock:/home/u/ws/app/.env", subject: "/home/u/ws/app/.env", bindings: [], values: VALUES,
  plain: { subject: "/home/u/ws/app/.env", reach: "this file only", effect: "No AI", opens: "Programs get a masked copy.", send: SEND, sendParts: SEND_PARTS },
};

test("H6: a Per value row says on the page where its hosts change: values: in the policy file the panel names, and its disabled menu is described by that line", async () => {
  const { doc } = load({ url: RULES, routes: { "GET policy/panel": panelWith(PER_VALUE_RULE, { policyFile: POLICY_FILE }) } });
  await tick();
  const row = treeRow(doc, /app\/\.env/);
  const how = row.querySelector(".file-values-how");
  assert.ok(how, "the row has the line");
  assert.equal(how.textContent, "Each value has its own hosts, so this menu cannot change them. Edit values: for this file in ~/.mandu/policy.yaml.");
  assert.ok(how.classList.contains("dim"), "in the row's secondary ink");
  assert.deepEqual([...how.querySelectorAll("code")].map((x: any) => x.textContent), ["values:", "~/.mandu/policy.yaml"], "the key and the file as code");
  assert.equal(how.previousElementSibling, row.querySelector(".file-values"), "right under the Per value sentence");
  assert.equal(row.querySelector(".file-values").textContent, SEND, "the sentence is unchanged");
  const sel = row.querySelector("select.send-select");
  assert.equal(sel.disabled, true, "the menu keeps its state");
  assert.deepEqual([...sel.options].map((o: any) => o.textContent), ["Per value"]);
  assert.ok(how.id, "the line has an id");
  assert.equal(sel.getAttribute("aria-describedby"), how.id, "a screen reader on the menu hears the line");
  assert.equal(doc.querySelectorAll(`[id="${how.id}"]`).length, 1, "the id is the page's only one");
  assert.equal(sel.title, how.textContent, "the tooltip says the same as the line");

  // A panel with no policy file known: its bare name.
  const bare = load({ url: RULES, routes: { "GET policy/panel": panelWith(PER_VALUE_RULE) } });
  await tick();
  assert.match(treeRow(bare.doc, /app\/\.env/).querySelector(".file-values-how").textContent, /Edit values: for this file in policy\.yaml\.$/);
});

test("H6: an inherited Per value row gets the same line, pointing at the rule it inherits", async () => {
  const notes = {
    ...WS_LIST, path: "/home/u/ws/notes", display: "~/ws/notes", parent: "/home/u/ws",
    crumbs: [...WS_LIST.crumbs, { name: "notes", path: "/home/u/ws/notes" }],
    self: chip("no-model", "No AI", "yours", "Your rule", true),
    entries: [{
      name: "app.env", path: "/home/u/ws/notes/app.env", display: "~/ws/notes/app.env", kind: "file", link: null, inside: 0,
      label: { ...chip("no-model", "No AI", "inherited", "From your rule on ~/ws/notes"), values: VALUES, send: SEND, sendParts: SEND_PARTS },
    }],
    total: 1,
  };
  const { doc } = load({ url: RULES, routes: { ...FILES_ROUTES, [list("~/ws/notes")]: notes, "GET policy/panel": panelWith(PER_VALUE_RULE, { policyFile: POLICY_FILE }) } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  (doc.getElementById("lock-path") as any).value = "~/ws/notes";
  doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick();
  const row = rowFor(doc, /^app\.env/);
  const sel = row.querySelector("select.send-select");
  assert.equal(row.querySelector(".send-pick").getAttribute("data-from"), "values", "inherited");
  const how = row.querySelector(".file-values-how");
  assert.equal(how.textContent, "Each value has its own hosts, so this menu cannot change them. Edit values: in the rule it inherits, in ~/.mandu/policy.yaml.");
  assert.equal(sel.getAttribute("aria-describedby"), how.id);
  assert.equal(sel.disabled, true);
});

test("H7: a row without values: has no such line, and its menu no description", async () => {
  const path = "/home/u/ws/.env";
  const { doc } = load({ url: RULES, routes: { "GET policy/panel": panelWith(
    { id: `lock:${path}`, subject: path, bindings: ["api.stripe.com"], plain: { subject: path, reach: "this file only", effect: "No AI; may be sent to api.stripe.com" } },
    { policyFile: POLICY_FILE },
  ) } });
  await tick();
  const row = treeRow(doc, /ws\/\.env$/);
  assert.ok(row.querySelector("select.send-select"), "the row has its second menu");
  assert.equal(row.querySelector(".file-values-how"), null, "no line");
  assert.equal(row.querySelector("select.send-select").hasAttribute("aria-describedby"), false);
  assert.equal(doc.querySelector("#files-tree .file-values-how"), null);
});
