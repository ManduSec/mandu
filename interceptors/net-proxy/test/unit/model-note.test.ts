/**
 * model-note — the pure rules of the handling note in a browser agent's own
 * model calls (src/model-note.ts; devtools-relay.md §6.5): the switch, the
 * Chat Completions call, and the body with the note as its first system
 * message, or why it leaves as written. Mandu-new (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { BROWSER_NOTE_CAPABILITIES, addModelNote, isChatCompletionsCall, modelNoteFromEnv } from "../../src/model-note.js";

const NOTE = "## Web pages\nfill the placeholder itself";

test("the switch: only `browser` turns it on", () => {
  assert.equal(modelNoteFromEnv("browser"), "browser");
  for (const v of [undefined, "", "1", "Browser", "on"]) assert.equal(modelNoteFromEnv(v), null, String(v));
});

test("a browser agent's capabilities: no inspect, exec, policy tools or view map; the Web pages section", () => {
  assert.deepEqual({ ...BROWSER_NOTE_CAPABILITIES }, { inspect: false, policyTools: false, exec: false, fsView: false, browser: true });
});

test("a Chat Completions call is a POST to a path ending in /chat/completions, a query or a trailing slash allowed", () => {
  for (const p of ["/api/v1/chat/completions", "/v1/chat/completions", "/chat/completions", "/api/v1/chat/completions?x=1", "/api/v1/chat/completions/"]) {
    assert.equal(isChatCompletionsCall("POST", p), true, p);
  }
  assert.equal(isChatCompletionsCall("post", "/api/v1/chat/completions"), true);
  for (const [m, p] of [["GET", "/api/v1/chat/completions"], ["POST", "/api/v1/responses"], ["POST", "/api/v1/chat/completions/x"], ["POST", "/v1/systemone"], ["POST", "/chat/completionsx"]] as const) {
    assert.equal(isChatCompletionsCall(m, p), false, `${m} ${p}`);
  }
});

test("the note goes in as the first system message; the rest of the request is unchanged", () => {
  const body = { model: "google/gemini-2.5-flash", messages: [{ role: "system", content: "You are a browser agent." }, { role: "user", content: "Fill $MDU:nomodel_Read[ab12].KEY" }], temperature: 0 };
  const r = addModelNote(JSON.stringify(body), { "content-type": "application/json" }, NOTE);
  assert.equal(r.kind, "added");
  const out = JSON.parse((r as { bodyText: string }).bodyText);
  assert.deepEqual(out.messages[0], { role: "system", content: NOTE });
  assert.deepEqual(out.messages.slice(1), body.messages, "the agent's own messages, in order, the placeholder as written");
  assert.equal(out.model, body.model);
  assert.equal(out.temperature, 0);
});

test("a request the note step cannot read, or one that has it already, leaves as written (with the reason)", () => {
  const ok = JSON.stringify({ messages: [{ role: "user", content: "hi" }] });
  const cases: Array<[string, string, NodeJS.Dict<string | string[]>, string, RegExp]> = [
    ["not JSON", "model=x", {}, NOTE, /not a JSON body/],
    ["an array", "[1]", {}, NOTE, /not a JSON object/],
    ["no messages", JSON.stringify({ input: "hi" }), {}, NOTE, /no messages array/],
    ["gzip", ok, { "Content-Encoding": "gzip" }, NOTE, /a gzip body/],
    ["empty note (both axes off)", ok, {}, "", /no note/],
    ["already there", JSON.stringify({ messages: [{ role: "system", content: NOTE }, { role: "user", content: "hi" }] }), {}, NOTE, /already there/],
  ];
  for (const [name, body, headers, note, why] of cases) {
    const r = addModelNote(body, headers, note);
    assert.equal(r.kind, "skipped", name);
    assert.match((r as { reason: string }).reason, why, name);
  }
  assert.equal(addModelNote(ok, { "content-encoding": "identity" }, NOTE).kind, "added", "identity is no encoding");
});
