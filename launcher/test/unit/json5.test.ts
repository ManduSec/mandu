/**
 * json5.test — the launcher's JSON5 reader (services/json5.ts), which reads
 * the agents' own config files (OpenClaw's openclaw.json is JSON5; OpenCode's
 * JSONC is a subset). Cases follow the JSON5 spec (https://spec.json5.org);
 * the same set matched the `json5` package (2.2.3) case for case when the
 * reader was written.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Json5Error, parseJson5 } from "../../src/services/json5.js";

test("json5: plain JSON reads as JSON.parse reads it", () => {
  const text = JSON.stringify({ a: [1, 2.5, -3e2, true, false, null, "x\n\"y\"\u00e9"], b: { c: {} } });
  assert.deepEqual(parseJson5(text), JSON.parse(text));
});

test("json5: comments, trailing commas, identifier keys, single quotes", () => {
  const text = `// OpenClaw config
{
  /* the model */
  agents: { defaults: { model: { primary: 'anthropic/claude-sonnet-4-6', fallbacks: ['anthropic/claude-opus-4-6',], }, }, },
  $include_not: "k", _x1: 1,
  'quoted key': "it's",
}`;
  assert.deepEqual(parseJson5(text), {
    agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6", fallbacks: ["anthropic/claude-opus-4-6"] } } },
    $include_not: "k", _x1: 1, "quoted key": "it's",
  });
});

test("json5: numbers and string escapes beyond JSON", () => {
  assert.deepEqual(parseJson5("[0x1F, -0x10, .5, 5., +1, 1e3, Infinity, -Infinity]"), [31, -16, 0.5, 5, 1, 1000, Infinity, -Infinity]);
  assert.ok(Number.isNaN(parseJson5("NaN")));
  assert.equal(parseJson5("'\\x41\\u0042\\v\\0'"), "AB\v\0");
  assert.equal(parseJson5("'line \\\nnext'"), "line next");
  assert.equal(parseJson5("'\\q'"), "q");
});

test("json5: __proto__ stays an own key, as JSON.parse keeps it", () => {
  const got = parseJson5("{__proto__: {polluted: 1}}") as Record<string, unknown>;
  assert.ok(Object.prototype.hasOwnProperty.call(got, "__proto__"));
  assert.equal(({} as Record<string, unknown>)["polluted"], undefined);
});

test("json5: what the grammar rejects throws, with a line and column", () => {
  for (const bad of ["{a:1", "{a:1}}", "[1 2]", "{a:01}", "{a:'x\ny'}", "{1a:1}", "{a:1,,}", "[,]", "{a:0x}", "{a:'\\1'}", "{a:tru}", "/* open", "{a:\"\\u12\"}", "", "{'a' 1}", "trueish"]) {
    assert.throws(() => parseJson5(bad), Json5Error, JSON.stringify(bad));
  }
  assert.throws(() => parseJson5("{\n  a: 1\n  b: 2\n}"), /line 3 column 3/);
});

test("json5: deep nesting is refused, not a stack overflow", () => {
  assert.throws(() => parseJson5("[".repeat(10_000)), /nesting too deep/);
});
