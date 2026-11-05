/**
 * mysql-wire — the MySQL login pieces the database login release uses
 * (db-relay.ts, db-login-release.md §8): framing, the handshakes, and the
 * password methods (native, caching_sha2's fast scramble and its RSA answer).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";

import {
  CACHING_SHA2, CAP, MyReader, NATIVE, authSwitch, cachingSha2Password, cleartextOf, clientResponse, errPacket, errText,
  lenencInt, lenencIntAt, nativePassword, packet, parseAuthSwitch, parseClientResponse, parseServerHandshake, rsaPassword,
  rsaPasswordOf, serverHandshake, sslRequest,
} from "../../src/mysql-wire.js";

const SCRAMBLE = Buffer.from("0123456789abcdefghij");

test("packets: 3-byte length and a sequence id, cut across chunks; an oversized one refused", () => {
  const r = new MyReader();
  const all = Buffer.concat([packet(0, Buffer.from("hello")), packet(1, Buffer.from("x"))]);
  r.feed(all.subarray(0, 6));
  assert.equal(r.take(), null);
  r.feed(all.subarray(6));
  assert.deepEqual(r.take(), { seq: 0, payload: Buffer.from("hello") });
  assert.deepEqual(r.take(), { seq: 1, payload: Buffer.from("x") });
  const big = Buffer.alloc(4);
  big.writeUIntLE(1 << 20, 0, 3);
  r.feed(big);
  assert.throws(() => r.take(), /a packet of/);
  for (const n of [0, 250, 251, 65535, 65536, 16_777_216]) assert.deepEqual(lenencIntAt(lenencInt(n), 0)?.value, n);
});

test("the server handshake round-trips: version, id, scramble, capabilities, plugin", () => {
  const h = { serverVersion: "8.4.3", connectionId: 77, scramble: SCRAMBLE, capabilities: (CAP.PROTOCOL_41 | CAP.SECURE_CONNECTION | CAP.PLUGIN_AUTH | CAP.SSL | CAP.CONNECT_ATTRS) >>> 0, charset: 255, status: 2, plugin: CACHING_SHA2 };
  assert.deepEqual(parseServerHandshake(serverHandshake(h)), h);
  assert.equal(parseServerHandshake(Buffer.from([9, 0])), null, "protocol 9");
});

test("the client's response round-trips (lenenc auth data, database, plugin, attrs); a 32-byte SSLRequest is told apart", () => {
  const caps = (CAP.PROTOCOL_41 | CAP.SECURE_CONNECTION | CAP.PLUGIN_AUTH | CAP.PLUGIN_AUTH_LENENC_CLIENT_DATA | CAP.CONNECT_WITH_DB | CAP.CONNECT_ATTRS) >>> 0;
  const attrs = Buffer.concat([lenencInt(9), Buffer.from([4]), Buffer.from("_pid"), Buffer.from([3]), Buffer.from("123")]);
  const r = { capabilities: caps, maxPacket: 1 << 24, charset: 45, user: "alice", authResponse: Buffer.from([1, 2, 3]), database: "app", plugin: NATIVE, attrs };
  assert.deepEqual(parseClientResponse(clientResponse(r)), { ...r, ssl: false });
  const ssl = parseClientResponse(sslRequest(caps, 1 << 24, 45));
  assert.equal(ssl?.ssl, true);
  assert.equal(parseClientResponse(Buffer.alloc(40)), null, "no PROTOCOL_41");
});

test("native: SHA1(pw) XOR SHA1(scramble || SHA1(SHA1(pw))); caching_sha2's fast scramble likewise with SHA256", () => {
  const sha1 = (b: Buffer) => createHash("sha1").update(b).digest();
  const sha256 = (b: Buffer) => createHash("sha256").update(b).digest();
  const s1 = sha1(Buffer.from("s3cret"));
  const want = Buffer.from(s1.map((b, i) => b ^ sha1(Buffer.concat([SCRAMBLE, sha1(s1)]))[i]!));
  assert.deepEqual(nativePassword("s3cret", SCRAMBLE), want);
  const m1 = sha256(Buffer.from("s3cret"));
  const want2 = Buffer.from(m1.map((b, i) => b ^ sha256(Buffer.concat([sha256(m1), SCRAMBLE]))[i]!));
  assert.deepEqual(cachingSha2Password("s3cret", SCRAMBLE), want2);
  assert.equal(nativePassword("", SCRAMBLE).length, 0);
});

test("caching_sha2's full path: the RSA answer decrypts back to the password; cleartext answers end in one NUL", () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  const enc = rsaPassword("$MDU:nomodel_Read[ab12].client.password", SCRAMBLE, publicKey);
  assert.equal(rsaPasswordOf(enc, SCRAMBLE, privateKey), "$MDU:nomodel_Read[ab12].client.password");
  assert.equal(rsaPasswordOf(Buffer.alloc(256), SCRAMBLE, privateKey), null);
  assert.equal(cleartextOf(Buffer.from("pw\0")), "pw");
  assert.equal(cleartextOf(Buffer.from("pw")), null);
  assert.equal(cleartextOf(Buffer.from("p\0w\0")), null);
});

test("auth switch and error packets", () => {
  assert.deepEqual(parseAuthSwitch(authSwitch(CACHING_SHA2, Buffer.concat([SCRAMBLE, Buffer.from([0])]))), { plugin: CACHING_SHA2, data: SCRAMBLE });
  assert.equal(errText(errPacket("mandu: refused")), "mandu: refused");
});
