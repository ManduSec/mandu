/**
 * home-js-no-dev.test — the product page in a build without the developer
 * view (dashboard.md §4.25ac): the server's `extensions` meta names no
 * `inspector`, so nothing on the page links into `/dev/`: the elements that
 * only link there are hidden, and the words that name the detailed trace are
 * text. With the meta naming it, the same page keeps every link.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, T, load, tick } from "./home-js-fixtures.js";

/** The links into the developer view a reader could reach: in no hidden
 *  element (`[hidden]` hides a subtree, mandu.css). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function reachableDevLinks(doc: any): string[] {
  return ([...doc.querySelectorAll("a")] as any[])
    .filter((a) => /\/dev\//.test(a.href) && !a.closest("[hidden]"))
    .map((a) => a.id || a.textContent);
}

test("without the developer view, Home and Settings show no link into it; with it, they do", async () => {
  const bare = load({ extensions: "" });
  await tick();
  assert.deepEqual(reachableDevLinks(bare.doc), [], "Home");
  // History is the product's own page in both builds (§4.25ae).
  assert.equal(bare.doc.getElementById("home-history").hidden, false, "History");
  assert.equal(bare.doc.getElementById("home-history").getAttribute("href"), "/mandu/history");
  assert.equal(bare.doc.querySelector('#nav a[data-page-link="history"]').getAttribute("href"), "/mandu/history", "the top bar's History link");
  assert.equal(bare.doc.querySelector('#nav a[data-page-link="history"]').closest("[hidden]"), null);
  assert.equal(bare.doc.querySelector('[aria-labelledby="settings-dev-title"]').hidden, true, "the Developer view card");
  assert.equal(bare.doc.getElementById("settings-prompt-dev").closest("[hidden]") !== null, true, "the prompt checks' pointer");
  assert.match(bare.doc.getElementById("settings-prompt-about").textContent, /next message\./, "the note keeps its own sentence");

  const full = load();
  await tick();
  assert.equal(full.doc.getElementById("home-history").hidden, false);
  assert.equal(full.doc.getElementById("home-history").getAttribute("href"), "/mandu/history");
  assert.equal(full.doc.querySelector('#nav a[data-page-link="history"]').getAttribute("href"), "/mandu/history");
  assert.equal(full.doc.querySelector('[aria-labelledby="settings-dev-title"]').hidden, false);
  assert.equal(full.doc.getElementById("settings-dev-link").getAttribute("href"), "/mandu/dev/");
});

test("without the developer view, the agent page has no Detailed trace button and its trace words are text", async () => {
  const id = "s1";
  const agent = {
    ...AGENT, id, waiting: [], holds: false, violations: 1, earlier: 2,
    story: [{
      ...AGENT.story[1], id: "turn:x", moreSteps: 3, moreFrom: "tool:m", routine: null, reply: null,
      steps: [{
        kind: "action", id: "tool:u1", ts: "2026-09-25T10:00:01.000Z", icon: "run", sentence: [T("Ran a step")], outcome: "unmasked", split: null,
        note: "This reached the AI without a mask. Open the detailed trace.",
        noteParts: [T("This reached the AI without a mask. "), { kind: "text", text: "Open the detailed trace", trace: "trace" }, T(".")],
      }],
    }],
  };
  const routes = { [`GET home/agent?session=${id}`]: agent };
  const bare = load({ url: `http://127.0.0.1:4500/mandu/agents/${id}`, routes, extensions: "" });
  await tick();
  assert.equal(bare.doc.getElementById("agent-trace").hidden, true, "the button");
  assert.deepEqual(reachableDevLinks(bare.doc), []);
  assert.match(bare.doc.getElementById("agent-story").textContent, /Open the detailed trace/, "the words stay, as text");

  const full = load({ url: `http://127.0.0.1:4500/mandu/agents/${id}`, routes });
  await tick();
  assert.equal(full.doc.getElementById("agent-trace").hidden, false);
  assert.ok(reachableDevLinks(full.doc).includes("Open the detailed trace"), "a link with the developer view");
});
