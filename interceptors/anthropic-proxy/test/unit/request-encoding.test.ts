/**
 * request-encoding — a compressed request body read as the bytes it carries
 * (model-wires.md §9.3): OpenClaw's ChatGPT transport sends zstd. Every
 * coding Node can undo is decoded, an unknown one or a body that does not
 * decode is refused, and a body that decodes past the limit is refused.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as zlib from "node:zlib";

import { decodeRequestBody } from "../../src/request-encoding.js";

const JSON_BODY = Buffer.from(JSON.stringify({ model: "gpt-5.5", input: [{ type: "function_call_output", call_id: "c1", output: "x".repeat(2000) }] }));
const z = zlib as unknown as Record<string, ((b: Buffer) => Buffer) | undefined>;

test("no content-encoding, or identity: the body as it came, not decoded", () => {
  for (const h of [undefined, "", "identity", " Identity "]) {
    const r = decodeRequestBody(h, JSON_BODY, 1 << 20);
    assert.ok(r.ok && !r.decoded && r.body === JSON_BODY, String(h));
  }
});

test("gzip, deflate, br and zstd (where Node has it) decode to the same JSON", () => {
  const cases: Array<[string, Buffer]> = [
    ["gzip", zlib.gzipSync(JSON_BODY)],
    ["x-gzip", zlib.gzipSync(JSON_BODY)],
    ["deflate", zlib.deflateSync(JSON_BODY)],
    ["br", zlib.brotliCompressSync(JSON_BODY)],
  ];
  const zc = z["zstdCompressSync"];
  if (zc) cases.push(["zstd", zc(JSON_BODY)], ["ZSTD", zc(JSON_BODY)]);
  for (const [coding, body] of cases) {
    const r = decodeRequestBody(coding, body, 1 << 20);
    assert.ok(r.ok, coding);
    assert.ok(r.ok && r.decoded, coding);
    assert.deepEqual(r.ok ? r.body : null, JSON_BODY, coding);
  }
  // Two codings: undone last-applied first.
  const r = decodeRequestBody("deflate, gzip", zlib.gzipSync(zlib.deflateSync(JSON_BODY)), 1 << 20);
  assert.ok(r.ok && r.decoded);
  assert.deepEqual(r.ok ? r.body : null, JSON_BODY);
});

test("fail-closed: an unknown coding (415), a body that does not decode (400), one past the limit (413)", () => {
  const unknown = decodeRequestBody("compress", JSON_BODY, 1 << 20);
  assert.ok(!unknown.ok && unknown.status === 415, "compress");
  const bad = decodeRequestBody("gzip", JSON_BODY, 1 << 20);
  assert.ok(!bad.ok && bad.status === 400, "plain bytes labelled gzip");
  const big = decodeRequestBody("gzip", zlib.gzipSync(Buffer.alloc(4 << 20)), 1 << 20);
  assert.ok(!big.ok && big.status === 413, "a body that decodes past the limit");
  const zc = z["zstdCompressSync"];
  if (zc) {
    const zbig = decodeRequestBody("zstd", zc(Buffer.alloc(4 << 20)), 1 << 20);
    assert.ok(!zbig.ok && zbig.status === 413, "zstd past the limit");
  }
});
