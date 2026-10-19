/**
 * ws-server — the relay's WebSocket server half (RFC 6455): the handshake
 * key, masked client frames in one piece or split, fragmentation, ping,
 * and the refusals (unmasked, binary, too large) (secrets axes, explicit:
 * stated for the manifest, though no arbiter runs here).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { stateAxes } from "../axes.js";
import { acceptKey, frame, WsConnection } from "../../src/ws-server.js";

stateAxes("secrets");

/** A client frame: masked, with `fin` and `opcode`. */
function clientFrame(opcode: number, text: string | Buffer, fin = true): Buffer {
  const payload = typeof text === "string" ? Buffer.from(text) : text;
  const mask = Buffer.from([1, 2, 3, 4]);
  const masked = Buffer.from(payload.map((b, i) => b ^ mask[i & 3]!));
  const len = payload.length;
  const head = len < 126 ? Buffer.from([(fin ? 0x80 : 0) | opcode, 0x80 | len])
    : Buffer.concat([Buffer.from([(fin ? 0x80 : 0) | opcode, 0x80 | 126]), Buffer.from([len >> 8, len & 0xff])]);
  return Buffer.concat([head, mask, masked]);
}

function conn(maxPayload = 1024) {
  const sock = new PassThrough();
  const written: Buffer[] = [];
  sock.write = ((chunk: Buffer) => { written.push(Buffer.from(chunk)); return true; }) as typeof sock.write;
  const c = new WsConnection(sock, { maxPayload });
  const got: string[] = [];
  c.onMessage((t) => got.push(t));
  return { c, sock, got, written };
}

test("the accept key of RFC 6455's example", () => {
  assert.equal(acceptKey("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
});

test("text in one frame, split across chunks, and fragmented", () => {
  const { sock, got } = conn();
  sock.emit("data", clientFrame(1, "hello"));
  const f = clientFrame(1, "split across chunks");
  sock.emit("data", f.subarray(0, 3));
  sock.emit("data", f.subarray(3));
  sock.emit("data", Buffer.concat([clientFrame(1, "frag", false), clientFrame(0, "mented")]));
  const long = "x".repeat(300);
  sock.emit("data", clientFrame(1, long));
  assert.deepEqual(got, ["hello", "split across chunks", "fragmented", long]);
});

test("a ping is answered with a pong; a server frame is unmasked", () => {
  const { sock, written } = conn();
  sock.emit("data", clientFrame(9, "p"));
  assert.deepEqual(written[0], frame(0xa, Buffer.from("p")));
  assert.deepEqual(frame(1, Buffer.from("hi")), Buffer.from([0x81, 2, 0x68, 0x69]));
});

test("unmasked, binary or oversized frames close the connection", () => {
  for (const [name, bytes] of [
    ["unmasked", Buffer.from([0x81, 2, 0x68, 0x69])],
    ["binary", clientFrame(2, "bin")],
    ["too large", clientFrame(1, "y".repeat(200))],
  ] as const) {
    const { c, sock, got } = conn(100);
    sock.emit("data", bytes);
    assert.equal(c.isOpen, false, name);
    assert.deepEqual(got, [], name);
  }
});
