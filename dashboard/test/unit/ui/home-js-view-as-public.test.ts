/**
 * home-js-view-as-public.test — View as public (dashboard.md §4.25ac): in a
 * build that serves the developer view, the Settings card's button keeps the
 * choice in this browser and reloads; the page then reads as a build without
 * the developer view (every `data-dev-only` element hidden, the trace words
 * text, no reachable link into `/dev/`) under a bar whose button turns it
 * off. A build without the developer view ignores the choice: nothing to
 * show again, so no bar.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, T, load, tick } from "./home-js-fixtures.js";

const KEY = "mandu.home.viewAsPublic";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function reachableDevLinks(doc: any): string[] {
  return ([...doc.querySelectorAll("a")] as any[])
    .filter((a) => /\/dev\//.test(a.href) && !a.closest("[hidden]"))
    .map((a) => a.id || a.textContent);
}

/** A page whose reload is counted (jsdom does not navigate). */
function counted(opts: Parameters<typeof load>[0] = {}): ReturnType<typeof load> & { reloads: () => number } {
  let n = 0;
  const page = load({
    ...opts,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    before: (w: any) => {
      const loc = w.location;
      // jsdom's Location is unforgeable: count on its implementation object.
      const impl = Object.getOwnPropertySymbols(loc).map((s) => loc[s]).find((v) => v && typeof v.reload === "function");
      if (impl) impl.reload = () => { n++; };
    },
  });
  return Object.assign(page, { reloads: () => n });
}

test("the Settings button keeps View as public in this browser and reloads; the bar is hidden until then", async () => {
  const page = counted({ url: "http://127.0.0.1:4500/mandu/settings" });
  await tick();
  assert.equal(page.err, null);
  const { doc, window } = page;
  assert.equal(doc.getElementById("as-public").hidden, true, "no bar before the choice");
  const btn = doc.getElementById("settings-view-public");
  assert.equal(btn.closest("[hidden]"), null, "the button is on the Developer view card");
  btn.click();
  assert.equal(window.localStorage.getItem(KEY), "1");
  assert.equal(page.reloads(), 1, "the page draws again");
});

test("viewing as public: no reachable link into /dev/, the dev-only parts hidden, the bar shown; its button turns it off", async () => {
  const page = counted({ storage: { [KEY]: "1" } });
  await tick();
  assert.equal(page.err, null);
  const { doc, window } = page;
  assert.deepEqual(reachableDevLinks(doc), [], "Home");
  assert.equal(doc.querySelector('[aria-labelledby="settings-dev-title"]').hidden, true, "the Developer view card");
  assert.equal(doc.getElementById("settings-prompt-dev").closest("[hidden]") !== null, true, "the prompt checks' pointer");
  assert.equal(doc.getElementById("home-history").hidden, false, "History is the product's own page");
  const bar = doc.getElementById("as-public");
  assert.equal(bar.hidden, false, "the bar");
  assert.match(bar.textContent, /Viewing as public/);
  doc.getElementById("as-public-off").click();
  assert.equal(window.localStorage.getItem(KEY), null, "the choice is gone");
  assert.equal(page.reloads(), 1);
});

test("viewing as public, the agent page reads as the public version: no Detailed trace button, its trace words text", async () => {
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
  const url = `http://127.0.0.1:4500/mandu/agents/${id}`;
  const pub = load({ url, routes, storage: { [KEY]: "1" } });
  await tick();
  assert.equal(pub.doc.getElementById("agent-trace").hidden, true, "the button");
  assert.deepEqual(reachableDevLinks(pub.doc), []);
  assert.match(pub.doc.getElementById("agent-story").textContent, /Open the detailed trace/, "the words stay, as text");
  assert.equal(pub.doc.getElementById("as-public").hidden, false);

  const full = load({ url, routes });
  await tick();
  assert.equal(full.doc.getElementById("agent-trace").hidden, false);
  assert.ok(reachableDevLinks(full.doc).includes("Open the detailed trace"));
});

test("a build without the developer view ignores the choice: no bar, nothing to turn back on", async () => {
  const page = load({ extensions: "", storage: { [KEY]: "1" } });
  await tick();
  assert.equal(page.err, null);
  assert.equal(page.doc.getElementById("as-public").hidden, true);
  assert.deepEqual(reachableDevLinks(page.doc), []);
});
