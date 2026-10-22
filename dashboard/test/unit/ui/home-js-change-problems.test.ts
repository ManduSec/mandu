/**
 * home-js-change-problems.test — on the PRODUCT page's Rules, a change the
 * protection service finds not valid says why (dashboard.md §4.25
 * "Refusals", *A change that is not valid says why*).
 *
 * The service checks a change before anything changes, and refuses one it
 * finds not valid with 422 and its `problems`, each a line in the terms of
 * policy.yaml (`paths[1].path: pattern "<path>": <why>`, `edits[0]
 * (<op>): <why>`). Until 2026-10-15 Your rules' Save, a rule's menu and
 * Describe's Apply showed only the route's error ("this change is not
 * valid"), so a typed pattern the service cannot use was refused with no
 * reason. Pins, in jsdom over the shared fetch stub (home-js-fixtures.ts):
 *
 *   - Save: "Not saved: ~/notes/[draft: '[' in '[draft' is never closed
 *     …", the path as the page shows it, the file's place for it left out;
 *     the change stays to be saved, Save described by the words;
 *   - Changes to save's line before Save (files/impact's "withEdits: …"
 *     refusal) in the same words, cut at each problem's place, never at a
 *     "; " inside one; another refusal there as before;
 *   - several problems, one after the other; a pattern with a quote in it;
 *     a path outside the home folder as written;
 *   - a rule's menu: "Not changed: …", a problem of another shape without
 *     its place, a path in it shortened; a line of no known shape as written;
 *   - Describe's Apply: "Not applied: …" and Describe it again;
 *   - a refusal with no problems keeps its words: the route's error, the
 *     sign-in words, and a non-422 answer's error even with problems.
 *
 * tests/stack/product-invalid-change-words.test.ts pins the match to the
 * real arbiter's lines. Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES, fileRows, choose, rulesPage, rowOf } from "./home-js-fixtures.js";
import { ADMIN_SESSION_REQUIRED } from "../../../src/server.js";

/** A 422 as the routes answer one the service found not valid. */
const notValid = (error: string, problems: unknown) => ({ status: 422, body: { error, problems } });

/** Rules › Add a rule: type each of `typed` in the path box, choose No AI
 *  for it, then Save (unless `save` is false). */
async function saveTyped(routes: Record<string, unknown>, typed: string[], opts: { homeDir?: string | null; save?: boolean } = {}) {
  const { save = true, ...more } = opts;
  const page = load({ url: FILES_URL, routes: { ...FILES_ROUTES, ...routes }, ...more });
  const { doc } = page;
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  for (const t of typed) {
    (doc.getElementById("lock-path") as any).value = t;
    doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
    await tick();
    choose(fileRows(doc)[0], "no-model");
  }
  if (!save) { await tick(); return page; }
  doc.getElementById("files-save").click();
  await tick();
  return page;
}

test("Save: a typed pattern the service cannot use says why, the path as the page shows it; the change stays to be saved", async () => {
  const sent: any[] = [];
  const { doc } = await saveTyped({
    "POST files/labels": (b: any) => (sent.push(b), notValid("this change is not valid", [
      `paths[1].path: pattern "/home/u/notes/[draft": '[' in '[draft' is never closed (a literal '[' is '\\[')`,
    ])),
  }, ["~/notes/[draft"]);
  assert.equal(sent.length, 1);
  const err = doc.getElementById("lock-error");
  assert.equal(err.textContent, "Not saved: ~/notes/[draft: '[' in '[draft' is never closed (a literal '[' is '\\[').");
  assert.doesNotMatch(err.textContent, /paths\[|this change is not valid/, "never the file's place, never the bare error");
  assert.equal(doc.getElementById("files-save").getAttribute("aria-describedby"), "lock-error", "Save is described by the words");
  assert.equal(doc.getElementById("files-pending").hidden, false, "the change stays to be saved");
  assert.equal(doc.getElementById("files-save").disabled, false);
});

test("Save: several problems one after the other; a pattern with a quote in it; a path outside the home folder as written", async () => {
  const { doc } = await saveTyped({
    "POST files/labels": notValid("this change is not valid", [
      `paths[1].path: pattern ${JSON.stringify('/srv/say "hi"/[x')}: '[' in '[x' is never closed (a literal '[' is '\\[')`,
      `paths[2].path: pattern "/**": the pattern matches every path on the machine; label a directory instead`,
    ]),
  }, ['/srv/say "hi"/[x', "/**"]);
  assert.equal(doc.getElementById("lock-error").textContent,
    `Not saved: /srv/say "hi"/[x: '[' in '[x' is never closed (a literal '[' is '\\['); /**: the pattern matches every path on the machine; label a directory instead.`);
});

test("Changes to save: what the change would do, refused, says why as Save does; the line is cut at each problem's place, never inside a problem; another refusal keeps its words", async () => {
  const impact = (error: string, status = 422) => ({ status, body: { error } });
  const { doc } = await saveTyped({
    "POST files/impact": impact(`withEdits: paths[1].path: pattern "/home/u/notes/[draft": '[' in '[draft' is never closed (a literal '[' is '\\['); paths[2].path: pattern "/**": the pattern matches every path on the machine; label a directory instead`),
    "POST files/labels": notValid("this change is not valid", []),
  }, ["~/notes/[draft", "/**"]);
  await tick();
  assert.equal(doc.getElementById("files-impact").textContent,
    "What this changes could not be worked out: ~/notes/[draft: '[' in '[draft' is never closed (a literal '[' is '\\['); /**: the pattern matches every path on the machine; label a directory instead.");
  const down = await saveTyped({ "POST files/impact": impact("the protection service did not answer", 502) }, ["~/notes/[draft"], { save: false });
  await tick();
  assert.equal(down.doc.getElementById("files-impact").textContent, "What this changes could not be worked out: the protection service did not answer.", "any other refusal as before");
  const not422 = await saveTyped({ "POST files/impact": impact(`withEdits: paths[1].path: pattern "/home/u/x": y`, 502) }, ["~/notes/[draft"], { save: false });
  await tick();
  assert.equal(not422.doc.getElementById("files-impact").textContent, `What this changes could not be worked out: withEdits: paths[1].path: pattern "/home/u/x": y.`, "only a 422 is read as the service's problems");
  const edits = await saveTyped({ "POST files/impact": impact("withEdits: edits[0] (unlock-path): no lock on /home/u/notes/x") }, ["~/notes/[draft"], { save: false });
  await tick();
  assert.equal(edits.doc.getElementById("files-impact").textContent, "What this changes could not be worked out: no lock on ~/notes/x.");
});

test("Save: a page served with no home folder shows the path as recorded", async () => {
  const { doc } = await saveTyped({
    "POST files/labels": notValid("this change is not valid", [
      `paths[1].path: pattern "/home/u/a**b": '**' must be a whole path segment (got 'a**b'); inside a segment use a single '*'`,
    ]),
  }, ["/home/u/a**b"], { homeDir: null });
  assert.equal(doc.getElementById("lock-error").textContent,
    "Not saved: /home/u/a**b: '**' must be a whole path segment (got 'a**b'); inside a segment use a single '*'.");
});

test("a rule's menu: a problem of another shape without its place, its path shortened; a line of no known shape as written", async () => {
  let answer: unknown = notValid("this change is not valid", ["edits[0] (unlock-path): no lock on /home/u/ws/gone.txt"]);
  const { doc } = rulesPage({ "POST policy/rules/change": () => answer });
  await tick();
  const flip = async () => {
    const menu = rowOf(doc, /api\.example\.com/).querySelector("select.effect-select");
    menu.value = "flip";
    menu.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
    await tick();
    return rowOf(doc, /api\.example\.com/).querySelector(".ask-error")?.textContent;
  };
  assert.equal(await flip(), "Not changed: no lock on ~/ws/gone.txt.");
  answer = notValid("this change is not valid", ["user_rules[0].to.host: something new happened."]);
  assert.equal(await flip(), "Not changed: user_rules[0].to.host: something new happened.", "a line the page does not know keeps its words and its full stop");
});

test("Describe's Apply: the problems after Not applied, and Describe it again", async () => {
  const SUGGESTION = {
    model: "m", note: "",
    rows: [{ parts: [{ kind: "text", text: "Stop protecting " }, { kind: "code", text: "~/x" }], loosens: true, overBroad: false }],
    loosens: [], edits: [{ op: "unlock-path", path: "/home/u/x" }], expected: [],
  };
  const { doc, window, calls } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: {
    "POST policy/assistant": SUGGESTION,
    "POST policy/assistant/apply": notValid("this is not a valid rule change any more", ["edits[0] (unlock-path): no lock on /home/u/x"]),
  } });
  await tick();
  (doc.getElementById("describe-text") as any).value = "Stop protecting ~/x";
  doc.getElementById("describe-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick();
  ([...doc.querySelectorAll("#describe-result button")].find((b: any) => b.textContent === "Apply") as any).click();
  await tick();
  assert.equal(doc.querySelector("#describe-result .ask-error").textContent, "Not applied: no lock on ~/x.");
  const again = doc.querySelector("#describe-result .describe-again") as any;
  assert.equal(again?.textContent, "Describe it again", "a change that no longer fits is described again");
  again.click();
  await tick();
  assert.equal(calls.filter((c) => c.method === "POST" && c.url === "/mandu/api/policy/assistant").length, 2);
});

test("a refusal with no problems keeps its words: the route's error, the sign-in words, a non-422 answer's error", async () => {
  const bare = await saveTyped({ "POST files/labels": notValid("this change is not valid", []) }, ["~/notes/[draft"]);
  assert.equal(bare.doc.getElementById("lock-error").textContent, "this change is not valid");
  const odd = await saveTyped({ "POST files/labels": notValid("this change is not valid", [null, 7, ""]) }, ["~/notes/[draft"]);
  assert.equal(odd.doc.getElementById("lock-error").textContent, "this change is not valid", "problems that are not lines are not shown");
  const out = await saveTyped({ "POST files/labels": { status: 403, body: { error: ADMIN_SESSION_REQUIRED } } }, ["~/notes/[draft"]);
  assert.match(out.doc.getElementById("lock-error").textContent, /^Sign in first: reload this page and sign in with your dashboard account/);
  const other = await saveTyped({ "POST files/labels": { status: 502, body: { error: "the protection service did not answer", problems: ["paths[1].path: pattern \"/x\": y"] } } }, ["~/notes/[draft"]);
  assert.equal(other.doc.getElementById("lock-error").textContent, "the protection service did not answer", "only a 422 names problems");
});
