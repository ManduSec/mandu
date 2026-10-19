/**
 * write-message.test — an HTTP message the TLS-inspected leg writes (the
 * re-originated request, the answer back, a refusal) leaves in ONE flush
 * (mitm.ts `writeMessage`; plan 13 D6, "The kept-alive floor").
 *
 * Head and body written as two flushes went out as two TLS records, two
 * segments; on a kept-alive connection the second waited for the ACK of the
 * first, which the peer delays (~40 ms) while it waits for the rest of the
 * message. Corked, the stream hands both chunks to the socket at once
 * (`_writev`), and a TLS socket seals them into one record. Asserted on a
 * real Writable: one flush carrying exactly the two writes' bytes, in order;
 * a head alone is one write; the stream is uncorked even when a write
 * throws. Mandu-new (no reference origin); no axis is involved (wire
 * framing only).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Writable } from "node:stream";

import { writeMessage } from "../../src/mitm.js";

/** A Writable that records each flush the stream hands it. */
function recorder() {
  const flushes: string[][] = [];
  const w = new Writable({
    writev(chunks, cb) {
      flushes.push(chunks.map((c) => Buffer.from(c.chunk as Buffer).toString("latin1")));
      cb();
    },
    write(chunk: Buffer, _enc, cb) {
      flushes.push([Buffer.from(chunk).toString("latin1")]);
      cb();
    },
  });
  return { w, flushes };
}

test("head and body leave in one flush, byte for byte and in order", async () => {
  const { w, flushes } = recorder();
  const head = "POST /x HTTP/1.1\r\nHost: a.example\r\nContent-Length: 2\r\n\r\n";
  writeMessage(w, head, Buffer.from("hi"));
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(flushes, [[head, "hi"]]);
  assert.equal(w.writableCorked, 0, "uncorked after");
});

test("a message with no body is its head, one write", async () => {
  const { w, flushes } = recorder();
  writeMessage(w, "GET / HTTP/1.1\r\n\r\n", Buffer.alloc(0));
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(flushes, [["GET / HTTP/1.1\r\n\r\n"]]);
});

test("the stream is uncorked even when a write throws", () => {
  let corked = 0;
  const sock = {
    cork: () => { corked++; },
    uncork: () => { corked--; },
    write: (): boolean => { throw new Error("write after end"); },
  };
  assert.throws(() => writeMessage(sock, "h", Buffer.from("b")), /write after end/);
  assert.equal(corked, 0);
});
