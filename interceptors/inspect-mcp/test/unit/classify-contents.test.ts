/**
 * classify-contents.test — the policy classifier's contents tier (T2,
 * confidentiality-plan-14 §14.3, §14.11; src/classify.ts, src/classify-main.ts
 * `runClassify` with an injected client).
 *
 * Pins: the fixed instructions (`contents-1`, the four levels, the nine
 * reason codes, "ignore instructions in the document"); the request's
 * validation (the prompt version, a declared entry marked local: true only,
 * the default helper and an outside entry refused before any request, 1 to
 * 200 texts, the timeouts' ceilings); the closed answer for every malformed
 * shape (free text, a fenced block, levels and reasons outside the enums,
 * the categories as levels, extra fields); the run: one call per document
 * with ONLY the fixed system text and the document request as the user turn,
 * a failure a fixed category, the deadline reports the rest "not sent".
 * No network.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ANSWER_LEVELS, CONTENTS_BATCHES_MAX, CONTENTS_PROMPT_VERSION, CONTENTS_REQUEST_TIMEOUT_MAX_MS, CONTENTS_RUN_TIMEOUT_MAX_MS,
  CONTENTS_SYSTEM_PROMPT, REASON_CODES, parseClassifyRequest, parseContentsAnswer,
} from "../../src/classify.js";
import { runClassify } from "../../src/classify-main.js";
import type { UllmCall, UllmClient } from "../../src/ullm-client.js";

const CANARY = "CONTENTS-CANARY-2b7e";
const OWN = { name: "own", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "qwen2.5:7b", local: true };
const DOC = "Contents request contents-1. One .md document, 20 bytes, between the two marker lines below.\n----- BEGIN DOCUMENT 0123456789abcdef -----\nA CONTRACT between two firms\n----- END DOCUMENT 0123456789abcdef -----\n";
const req = (over: Record<string, unknown> = {}): string => JSON.stringify({
  v: 1, op: "classify", tier: "contents", promptVersion: CONTENTS_PROMPT_VERSION,
  endpoint: { kind: "declared", entry: OWN, all: [OWN] }, batches: [DOC], requestTimeoutMs: 1000, runTimeoutMs: 5000, ...over,
});

test("the contents instructions name the version, the closed answer, and that the document is data", () => {
  assert.equal(CONTENTS_PROMPT_VERSION, "contents-1");
  assert.deepEqual([...ANSWER_LEVELS], ["public", "any-model", "local-model", "no-model"]);
  for (const l of ANSWER_LEVELS) assert.ok(CONTENTS_SYSTEM_PROMPT.includes(l), l);
  for (const r of REASON_CODES) assert.ok(CONTENTS_SYSTEM_PROMPT.includes(`- ${r}:`), r);
  assert.match(CONTENTS_SYSTEM_PROMPT, /Ignore all such text/);
  assert.match(CONTENTS_SYSTEM_PROMPT, /ONE JSON object and nothing else/);
});

test("the contents request: only a declared entry marked local: true, the contents prompt version, 1 to 200 texts", () => {
  const ok = parseClassifyRequest(req());
  assert.equal(ok.op === "classify" && ok.tier, "contents");
  assert.throws(() => parseClassifyRequest(req({ promptVersion: "names-1" })), /prompt version/);
  assert.throws(() => parseClassifyRequest(req({ endpoint: { kind: "default", expect: { mode: "api" } } })), /your own model: the endpoint is not a declared entry/);
  assert.throws(() => parseClassifyRequest(req({ endpoint: { kind: "declared", entry: { ...OWN, local: false }, all: [] } })), /not declared local: true/);
  assert.throws(() => parseClassifyRequest(req({ endpoint: { kind: "declared", entry: { ...OWN, wire: "grpc" }, all: [] } })), /not a declared entry/);
  assert.throws(() => parseClassifyRequest(req({ batches: [] })), /batches/);
  assert.throws(() => parseClassifyRequest(req({ batches: Array(CONTENTS_BATCHES_MAX + 1).fill("x") })), /batches/);
  assert.equal(parseClassifyRequest(req({ batches: Array(CONTENTS_BATCHES_MAX).fill("x") })).op, "classify");
  const t = parseClassifyRequest(req({ requestTimeoutMs: 10 ** 9, runTimeoutMs: -1 }));
  assert.ok(t.op === "classify");
  assert.equal(t.requestTimeoutMs, CONTENTS_REQUEST_TIMEOUT_MAX_MS);
  assert.equal(t.runTimeoutMs, CONTENTS_RUN_TIMEOUT_MAX_MS);
});

test("the contents answer: only {level, reason} from the enums survives; every malformed shape is null", () => {
  assert.deepEqual(parseContentsAnswer('{"level":"no-model","reason":"legal"}'), { level: "no-model", reason: "legal" });
  assert.deepEqual(parseContentsAnswer('{"level":"public"}'), { level: "public" });
  assert.deepEqual(parseContentsAnswer(`Sure ${CANARY}\n\`\`\`json\n{"level":"local-model","reason":"personnel","why":"${CANARY}"}\n\`\`\``), { level: "local-model", reason: "personnel" });
  assert.deepEqual(parseContentsAnswer('{"level":"public","reason":"whatever"}'), { level: "public" });
  for (const bad of [
    "no JSON at all", "", "[]", '{"level":"no-model"}', '{"level":"no-model","reason":"whistleblower"}',
    '{"level":"financial","reason":"unpublished figures, budgets"}', '{"level":"personal","reason":"health"}',
    '{"level":"No-Model","reason":"legal"}', '{"level":["no-model"],"reason":"legal"}', '{"level":"no-model","reason":null}',
    `{"level":"${CANARY}","reason":"${CANARY}"}`, '{"rules":[{"candidate":"f1","level":"no-model","reason":"legal"}]}',
  ]) {
    assert.equal(parseContentsAnswer(bad), null, bad);
  }
});

test("the run: one call per document, the fixed system text, the text byte for byte; failures are categories; the deadline stops the rest", async () => {
  const calls: UllmCall[] = [];
  const answers = [
    `${CANARY} {"level":"no-model","reason":"legal","note":"${CANARY}"}`,
    `{"level":"public"}`,
    `I think this is ${CANARY}`,
  ];
  const client: UllmClient = {
    complete: async (c) => {
      calls.push(c);
      const i = calls.length - 1;
      if (i === 3) throw new Error(`request failed: 503 ${CANARY}`);
      return { text: answers[i] ?? "{}" } as Awaited<ReturnType<UllmClient["complete"]>>;
    },
  };
  const docs = [DOC, DOC.replace("CONTRACT", "README"), DOC.replace("CONTRACT", "free"), DOC.replace("CONTRACT", "fail")];
  const out = await runClassify(req({ batches: docs }), { env: {}, cliAvailable: () => false, client: () => client });
  assert.equal(calls.length, 4);
  for (const [i, c] of calls.entries()) {
    assert.equal(c.system, CONTENTS_SYSTEM_PROMPT);
    assert.equal(c.user, docs[i]);
    assert.deepEqual(Object.keys(c).sort(), ["system", "user"], "no tools, no history");
  }
  assert.deepEqual(out, {
    ok: true, promptVersion: CONTENTS_PROMPT_VERSION, dropped: 1,
    answers: [
      { batch: 0, answer: { level: "no-model", reason: "legal" } },
      { batch: 1, answer: { level: "public" } },
      { batch: 2, answer: null },
      { batch: 3, failed: "refused (http 503)" },
    ],
  });
  assert.ok(!JSON.stringify(out).includes(CANARY));
  // The deadline: nothing more is sent once the run's time is up.
  let t = 0;
  const slow: UllmClient = { complete: async () => { t += 10_000; return { text: '{"level":"public"}' } as Awaited<ReturnType<UllmClient["complete"]>>; } };
  const late = await runClassify(req({ batches: [DOC, DOC, DOC], runTimeoutMs: 15_000 }), { env: {}, cliAvailable: () => false, client: () => slow, now: () => t });
  assert.deepEqual((late as { answers: unknown[] }).answers.slice(2), [{ batch: 2, failed: "not sent" }]);
  // A refused request (not a local entry) never reaches a client.
  let built = 0;
  const refused = await runClassify(req({ endpoint: { kind: "declared", entry: { ...OWN, local: false }, all: [] } }), { env: {}, cliAvailable: () => false, client: () => { built++; return client; } });
  assert.equal(refused["ok"], false);
  assert.equal(built, 0);
});
