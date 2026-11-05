/**
 * reply-policy tests — the decision for one outgoing chat reply
 * (src/reply-policy.ts, docs/design/agents/openclaw-plugin.md §3.5). Pure.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { CANCEL_REASON, decideReply, placeholdersIn } from "../../src/reply-policy.js";
import { NO_RELEASE } from "../../src/hook-arbiter.js";

const P1 = "$MDU:env[ab12]";
const P2 = "$MDU:file_cfg[9f3e].password";

test("placeholdersIn: distinct, in order, with field paths, a trailing dot trimmed", () => {
  assert.deepEqual(placeholdersIn(`use ${P1} and ${P2}. Again ${P1}.`), [P1, P2]);
  assert.deepEqual(placeholdersIn("no placeholders here, $MDU:bad and $MDU:x[zz]"), []);
  assert.deepEqual(placeholdersIn(""), []);
});

test("no scan, no release: unchanged (placeholders stay)", () => {
  const v = decideReply({ content: `token ${P1}`, placeholders: [P1], scan: null, release: null });
  assert.deepEqual(v, { action: "unchanged", placeholders: [P1] });
});

test("a clean scan keeps the reply unchanged", () => {
  const v = decideReply({ content: `token ${P1}`, placeholders: [P1], scan: { tripped: false, hits: [] }, release: null });
  assert.equal(v.action, "unchanged");
});

test("a tripped scan cancels, naming placeholders only", () => {
  const v = decideReply({
    content: "the key is sk-live-VALUE",
    placeholders: [],
    scan: { tripped: true, hits: [{ symbol: P1, level: "secret", where: "body" }] },
    release: null,
  });
  assert.equal(v.action, "cancel");
  if (v.action !== "cancel") return;
  assert.equal(v.reason, CANCEL_REASON);
  assert.deepEqual(v.hits, [{ symbol: P1, level: "secret" }]);
  assert.ok(!JSON.stringify(v).includes("sk-live-VALUE"), "the verdict never carries the reply text");
});

test("a tripped scan wins over a release", () => {
  const v = decideReply({
    content: `x ${P1}`,
    placeholders: [P1],
    scan: { tripped: true, hits: [{ symbol: P2, level: "secret", where: "body" }] },
    release: { text: "x VALUE", released: [P1] },
  });
  assert.equal(v.action, "cancel");
});

test("a release that put values back sends the released text, the rest kept", () => {
  const v = decideReply({
    content: `a ${P1} b ${P2}`,
    placeholders: [P1, P2],
    scan: { tripped: false, hits: [] },
    release: { text: `a VALUE b ${P2}`, released: [P1] },
  });
  assert.deepEqual(v, { action: "release", content: `a VALUE b ${P2}`, released: [P1], kept: [P2] });
});

test("an empty release is unchanged", async () => {
  const content = `a ${P1}`;
  const r = await NO_RELEASE.release({ sessionKey: "openclaw:main", destination: { channel: "telegram", to: "1" }, text: content, placeholders: [P1] });
  assert.equal(NO_RELEASE.live, false);
  assert.deepEqual(r, { text: content, released: [] });
  assert.equal(decideReply({ content, placeholders: [P1], scan: null, release: r }).action, "unchanged");
});
