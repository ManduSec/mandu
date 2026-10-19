/**
 * home-js-rules-prompt.test — dashboard.md §4.25u *Rules names a held
 * message's answer*. Until 2026-10-16 Rules knew a past answer only as a
 * send, a command or else a file, so an answer to a held message (prompt
 * filter, plan 15 §7: `prompt:<category>#<ref>` × `model:<session>`) was
 * listed under *Your answers about files* with the file icon, its tooltip
 * the key `model:<session>`, its ⋯ offering "Show in the file browser" on
 * that key, and its subject one code chip ("acme.codename in your message
 * to the AI") while the Approvals card that made it names only the
 * category as code. Now:
 *
 *   P1  a session's and a message's answer are under *Sending data*, with
 *       the Approvals card's icon; no *Your answers about files* group;
 *       the subject is the category as code and the words as words; the
 *       tooltip is the row's words; the reach is the server's;
 *   P2  opened, the row offers Remove and no "Show in the file browser";
 *       an answer about a file still offers it, under its own group;
 *   P3  an older server (no parts) draws the subject as one chip, still
 *       under *Sending data*;
 *   P4  a category holding tags is text inside its code, never markup;
 *   P5  its effect says what went to the AI, in Approvals' words: "Sent as
 *       written" / "Sent masked", never *Always allowed* / *Always blocked*
 *       (a masked message was not stopped, which the glossary's *Always
 *       blocked* says); the session's menu offers the other one, and
 *       choosing it posts the reversal and says what goes now; an answer
 *       about a file keeps *Always allowed* / *Always blocked*
 *       (§4.25u *A held message's answer says what was sent*).
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter, proxy and dashboard,
 * tests/stack/rules-held-message-answer.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";

const RULES = "http://127.0.0.1:4500/mandu/rules";

type Part = { kind: "text" | "code"; text: string };
const IN_MESSAGE = " in your message to the AI";

/** A held message's answer as the panel's queue sends it (policy-panel.ts,
 *  rule-words.ts `promptAnswerWords`). */
function promptAnswer(id: string, category: string, turn: string | null, status: "approved" | "denied", parts = true) {
  const subjectParts: Part[] = [{ kind: "code", text: category }, { kind: "text", text: IN_MESSAGE }];
  return {
    id, status, scope: "always", where: "prompt", subject: `prompt:${category}#3f2a9c`,
    target: `model:1791210000-777${turn ? `#turn:${turn}` : ""}`, count: 1, sessions: ["1791210000-777"], resolvedAt: 20,
    actions: turn ? [] : [{ approve: status !== "approved", label: status === "approved" ? "Send masked instead" : "Send as written instead" }],
    plain: {
      subject: category + IN_MESSAGE,
      ...(parts ? { subjectParts } : {}),
      reach: status === "denied" ? (turn ? "masked in that one message" : "masked for that session") : (turn ? "as you wrote it, in that one message" : "as you wrote it, for that session"),
      effect: status === "approved" ? "Sent as written" : "Sent masked",
    },
  };
}

/** An answer about one file, as the queue sends it. */
const FILE_ANSWER = {
  id: "egr-9", status: "approved", scope: "always", where: "file", subject: "fs:Read:read", target: "/home/u/ws/notes.md", count: 1, sessions: [], resolvedAt: 20,
  actions: [{ approve: false, label: "Block instead" }],
  plain: { subject: "/home/u/ws/notes.md", reach: "opening this file", effect: "Always allowed" },
};

function page(queue: unknown[]) {
  return load({ url: RULES, routes: {
    "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue, yourRules: [] } },
  } });
}

const rows = (doc: any) => [...doc.querySelectorAll("#rules-list .row.rule")] as any[];
const rowOf = (doc: any, id: string) => rows(doc).find((r) => r.getAttribute("data-rule") === `answer:${id}`);
const subjectOf = (row: any) => row.querySelector(".rule-text").firstElementChild;
const groupOf = (row: any) => row.parentElement.previousElementSibling.firstChild.textContent;
const groups = (doc: any) => [...doc.querySelectorAll("#rules-list .rules-group")].map((g: any) => g.firstChild.textContent);
/** home.js `ICON.eye`'s first path (`FAMILY_ICON.prompt`) and `ICON.file`'s. */
const EYE = "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z";
const FILE = "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z";
const iconOf = (row: any) => row.querySelector(".row-icon path").getAttribute("d");
/** A node's words and names in order: codes as `[name]`. */
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
const opened = async (doc: any, row: any) => {
  row.querySelector(".file-more").click();
  await tick();
  const box = doc.querySelector("#rules-list .rule-detail");
  assert.ok(box, "the row opens");
  return [...box.querySelectorAll("button")].map((b: any) => b.textContent);
};

test("P1: a held message's answer is under Sending data with the card's icon, the category as code, its words as the tooltip", async () => {
  const { doc } = page([promptAnswer("egr-1", "acme.codename", null, "approved"), promptAnswer("egr-2", "acme.codename", "01d1706f", "approved"), promptAnswer("egr-3", "secret.card", null, "denied")]);
  await tick();
  assert.deepEqual(groups(doc), ["Sending data"], "no Your answers about files for a message");
  const want = [
    ["egr-1", "[acme.codename] in your message to the AI", "as you wrote it, for that session"],
    ["egr-2", "[acme.codename] in your message to the AI", "as you wrote it, in that one message"],
    ["egr-3", "[secret.card] in your message to the AI", "masked for that session"],
  ];
  for (const [id, subject, reach] of want) {
    const row = rowOf(doc, id!);
    assert.equal(groupOf(row), "Sending data", `${id}: its group`);
    assert.equal(iconOf(row), EYE, `${id}: the Approvals card's icon, not the file's`);
    assert.equal(subjectOf(row).className, "rule-subject", `${id}: words around a name, not one chip`);
    assert.equal(drawn(subjectOf(row)), subject, `${id}: the category as code`);
    assert.equal(subjectOf(row).textContent, subject!.replace(/[[\]]/g, ""), `${id}: the text is plain.subject, byte for byte`);
    assert.equal(drawn(row.querySelector(".rule-reach")), reach);
    assert.equal(row.querySelector(".rule-text").title, subject!.replace(/[[\]]/g, ""), `${id}: the tooltip is the row's words, never model:<session>`);
    assert.equal(row.querySelector(".file-more").getAttribute("aria-label"), `More about ${subject!.replace(/[[\]]/g, "")}`);
  }
  for (const code of doc.querySelectorAll("#rules-list .rule-subject code")) assert.equal(code.parentElement.className, "name-fit", "the category kept whole where the column holds it");
});

test("P2: opened, a held message's answer offers Remove and no file browser; an answer about a file still offers it", async () => {
  const { doc } = page([promptAnswer("egr-1", "acme.codename", null, "approved"), FILE_ANSWER]);
  await tick();
  assert.deepEqual(groups(doc), ["Your answers about files", "Sending data"]);
  const buttons = await opened(doc, rowOf(doc, "egr-1"));
  assert.ok(buttons.includes("Remove"), `Remove: ${JSON.stringify(buttons)}`);
  assert.ok(!buttons.includes("Show in the file browser"), `no file browser for a message: ${JSON.stringify(buttons)}`);
  // Close it; the file's answer keeps its group, icon and link.
  rowOf(doc, "egr-1").querySelector(".file-more").click();
  await tick();
  const file = rowOf(doc, "egr-9");
  assert.equal(groupOf(file), "Your answers about files");
  assert.equal(iconOf(file), FILE);
  assert.ok((await opened(doc, file)).includes("Show in the file browser"), "a file's answer keeps its link");
});

test("P3: an older server without parts draws the subject as one chip, still under Sending data", async () => {
  const { doc } = page([promptAnswer("egr-1", "acme.codename", null, "approved", false)]);
  await tick();
  const row = rowOf(doc, "egr-1");
  assert.deepEqual([subjectOf(row).tagName, subjectOf(row).textContent], ["CODE", "acme.codename in your message to the AI"]);
  assert.equal(groupOf(row), "Sending data");
  assert.equal(row.querySelector(".rule-text").title, "acme.codename in your message to the AI");
});

test("P4: a category holding tags is drawn as text inside its code, never as markup", async () => {
  const evil = "<img src=x onerror=alert(1)>";
  const { doc } = page([promptAnswer("egr-1", evil, null, "approved")]);
  await tick();
  const row = rowOf(doc, "egr-1");
  assert.equal(row.querySelector(".rule-text img"), null, "no markup");
  assert.equal(drawn(subjectOf(row)), `[${evil}] in your message to the AI`);
});

test("P5: a held message's answer says Sent as written / Sent masked; its menu offers the other and says what goes now; a file's answer keeps Always allowed", async () => {
  const { doc, calls } = load({ url: RULES, routes: {
    "GET policy/panel": { panel: { available: true, verdictsKnown: true, yourRules: [], queue: [
      promptAnswer("egr-1", "acme.codename", null, "approved"),
      promptAnswer("egr-2", "acme.codename", "01d1706f", "approved"),
      promptAnswer("egr-3", "secret.card", null, "denied"),
      promptAnswer("egr-4", "secret.card", "77aa01bb", "denied"),
      FILE_ANSWER,
    ] } },
    "POST egress/approvals/egr-1/deny": { ok: true },
  } });
  await tick();
  const menu = (id: string) => rowOf(doc, id).querySelector("select.effect-select");
  const options = (id: string) => [...menu(id).options].map((o: any) => o.textContent);
  // A session's answer turns around in its own words.
  assert.deepEqual(options("egr-1"), ["Sent as written", "Sent masked"]);
  assert.deepEqual(options("egr-3"), ["Sent masked", "Sent as written"]);
  assert.equal(menu("egr-1").closest(".label-pick").getAttribute("data-effect"), "allow");
  assert.equal(menu("egr-3").closest(".label-pick").getAttribute("data-effect"), "block");
  // One message's answer has no menu (the message went): its words alone.
  for (const [id, words] of [["egr-2", "Sent as written"], ["egr-4", "Sent masked"]] as const) {
    assert.equal(menu(id), null, `${id}: no menu`);
    assert.equal(rowOf(doc, id).querySelector(".outcome").textContent, words, id);
  }
  const page = doc.getElementById("rules-list").textContent;
  assert.doesNotMatch(rowOf(doc, "egr-1").textContent + rowOf(doc, "egr-2").textContent + rowOf(doc, "egr-3").textContent + rowOf(doc, "egr-4").textContent, /Always (allowed|blocked)/, "no Always words on a message's answer");
  // A file's answer keeps the rule words.
  assert.deepEqual([...menu("egr-9").options].map((o: any) => o.textContent), ["Always allowed", "Always blocked"]);
  assert.ok(page.includes("Sent masked"));
  // Choosing the other posts the reversal and says what goes now.
  const sel = menu("egr-1");
  sel.value = "flip";
  sel.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
  await tick(30);
  assert.ok(calls.some((c) => c.method === "POST" && c.url.endsWith("/api/egress/approvals/egr-1/deny")), "the reversal is the same deny");
  assert.equal(doc.getElementById("rules-notice").textContent, "Now sent masked for that session.");
});
