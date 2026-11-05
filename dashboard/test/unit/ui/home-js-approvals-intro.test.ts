/**
 * home-js-approvals-intro.test — the sentence under Approvals' title says
 * only what is true of every card (dashboard.md §4.25 *A remembered answer
 * opens where Rules keeps it*, 2026-10-27). Until then it said "Allow once
 * lets just this one through", while the send card right under it said
 * "Mandu refused this one, so nothing was sent": a send is refused before
 * it is asked about, so Allow once covers the agent's next try, and each
 * card says which request it covers.
 *
 *   I1  the served index.html's Approvals head: no "this one"; it names
 *       Allow once, Always allow and Block, and Allow once's next try;
 *   I2  its Rules link keeps `data-page-link="rules"`, and a click opens
 *       Rules;
 *   I3  its words pass the product vocabulary sweep.
 *
 * Across the real arbiter and dashboard: tests/stack/approval-names-secret
 * (the served intro beside a served, refused send card).
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";

const APPROVALS_URL = "http://127.0.0.1:4500/mandu/approvals";
const intro = (doc: any) => doc.querySelector("#page-approvals .page-head > p");
const words = (doc: any) => (intro(doc).textContent as string).replace(/\s+/g, " ").trim();

test("I1: Approvals' intro does not say Allow once lets this one through; it names the three answers and the next try", async () => {
  const { doc, err } = load({ url: APPROVALS_URL });
  assert.equal(err, null);
  await tick();
  const said = words(doc);
  assert.doesNotMatch(said, /just this one|this one/i, said);
  assert.equal(said, "Each question says what its answers do. Allow once covers one request. When Mandu has already refused the one asked about, that is the agent's next try. Answers that last, such as Always allow and Block, are kept under Rules, where you can change them.");
  for (const answer of ["Allow once", "Always allow", "Block"]) assert.ok(said.includes(answer), `names ${answer}`);
});

test("I2: the intro's Rules link is the page link it was, and opens Rules", async () => {
  const { doc, window } = load({ url: APPROVALS_URL });
  await tick();
  const links = [...intro(doc).querySelectorAll("a")] as any[];
  assert.equal(links.length, 1, "one link");
  assert.equal(links[0].textContent, "Rules");
  assert.equal(links[0].getAttribute("data-page-link"), "rules");
  assert.equal(links[0].getAttribute("href"), "/mandu/rules", "under the base path");
  links[0].dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true, button: 0 }));
  await tick();
  assert.equal(doc.getElementById("page-rules").hidden, false, "Rules is shown");
  assert.equal(doc.getElementById("page-approvals").hidden, true, "Approvals is not");
});

test("I3: the intro passes the product vocabulary sweep", async () => {
  const { doc } = load({ url: APPROVALS_URL });
  await tick();
  const FORBIDDEN = /\b(symbol\w*|symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter)\b|\$MDU:|placeholder|binding/i;
  assert.doesNotMatch(words(doc), FORBIDDEN);
});
