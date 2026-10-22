/**
 * home-js-agent-launch-time — dashboard.md §4.25ag: the session page says,
 * under its title, how long Mandu took to start the session and to clean up
 * after it, in the server's words (view-model/launch-time.ts); a session
 * whose launch recorded no times has no such line, and a redraw draws it
 * once.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, load, tick } from "./home-js-fixtures.js";

const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
const LAUNCH = {
  total: "1.7 s", totalMs: 1712,
  slowest: [{ words: "checking git history for secrets", time: "0.38 s", ms: 378 }],
  sentence: "Mandu took 1.7 s to start this session: checking git history for secrets 0.38 s.",
  cleanup: "After the AI stopped, Mandu took 0.20 s to clean up.",
};

test("the start's line under the title: the sentence, then the clean-up", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...AGENT, launchTime: LAUNCH } } });
  await tick();
  const lines = doc.querySelectorAll("#agent-sub .agent-launch-time");
  assert.equal(lines.length, 1);
  assert.equal(lines[0].textContent, "Mandu took 1.7 s to start this session: checking git history for secrets 0.38 s. After the AI stopped, Mandu took 0.20 s to clean up.");
  assert.ok(lines[0].classList.contains("dim"), "a quiet line, as the folder and the main model");
});

test("a session still running: the start alone; no times recorded: no line", async () => {
  const running = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...AGENT, launchTime: { ...LAUNCH, cleanup: null } } } });
  await tick();
  assert.equal(running.doc.querySelector("#agent-sub .agent-launch-time").textContent, LAUNCH.sentence);
  const none = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...AGENT, launchTime: null } } });
  await tick();
  assert.equal(none.doc.querySelector("#agent-sub .agent-launch-time"), null);
  const older = load({ url: URL1 });
  await tick();
  assert.equal(older.doc.querySelector("#agent-sub .agent-launch-time"), null, "a page from a server without the field");
});

test("a redraw (the poll) draws the line once", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...AGENT, launchTime: LAUNCH } } });
  await tick();
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
  assert.equal(doc.querySelectorAll("#agent-sub .agent-launch-time").length, 1);
});
