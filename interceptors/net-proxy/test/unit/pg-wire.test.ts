/**
 * pg-wire — the Postgres login pieces the database login release uses
 * (db-relay.ts): startup packets, framing, md5, and the SCRAM-SHA-256 client
 * against RFC 7677's own test vector.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  AUTH, MAX_STARTUP_BYTES, PgReader, ScramClient, authRequest, errorResponse, errorText, md5Password, message, parseAuth,
  parseStartupPacket, passwordMessage, passwordOf, saslMechanisms, saslPrep, sslRequest, SSL_REQUEST_CODE,
} from "../../src/pg-wire.js";

function startup(params: Record<string, string>, version = 196608): Buffer {
  const kv = Buffer.from(Object.entries(params).map(([k, v]) => `${k}\0${v}\0`).join("") + "\0");
  const head = Buffer.alloc(8);
  head.writeInt32BE(8 + kv.length, 0);
  head.writeInt32BE(version, 4);
  return Buffer.concat([head, kv]);
}

test("startup packets: SSLRequest, a 3.0 startup with its parameters, and what is refused", () => {
  assert.deepEqual(parseStartupPacket(sslRequest()), { kind: "ssl" });
  assert.equal(sslRequest().readInt32BE(4), SSL_REQUEST_CODE);
  const p = parseStartupPacket(startup({ user: "alice", database: "app" }));
  assert.equal(p.kind, "startup");
  if (p.kind === "startup") {
    assert.deepEqual([p.major, p.minor, p.params.get("user"), p.params.get("database")], [3, 0, "alice", "app"]);
  }
  // 3.2 (Postgres 18) is passed on; the server negotiates.
  assert.equal(parseStartupPacket(startup({ user: "a" }, (3 << 16) | 2)).kind, "startup");
  assert.equal(parseStartupPacket(startup({ user: "a" }, 2 << 16)).kind, "invalid", "protocol 2");
  assert.equal(parseStartupPacket(startup({ database: "x" })).kind, "invalid", "no user");
  const short = startup({ user: "a" }).subarray(0, 12);
  assert.equal(parseStartupPacket(short).kind, "invalid", "length word mismatch");
});

test("PgReader cuts messages across chunk boundaries and refuses lengths out of bounds", () => {
  const r = new PgReader();
  const m1 = authRequest(AUTH.md5, Buffer.from([1, 2, 3, 4]));
  const m2 = message("Z", Buffer.from("I"));
  const all = Buffer.concat([m1, m2]);
  r.feed(all.subarray(0, 3));
  assert.equal(r.takeMessage(), null);
  r.feed(all.subarray(3, 13));
  const a = r.takeMessage()!;
  assert.equal(a.type, "R");
  assert.deepEqual(parseAuth(a.body), { code: AUTH.md5, data: Buffer.from([1, 2, 3, 4]) });
  assert.equal(r.takeMessage(), null);
  r.feed(all.subarray(13));
  assert.equal(r.takeMessage()!.type, "Z");
  assert.equal(r.rest().length, 0);

  const big = Buffer.alloc(5);
  big.write("R", 0);
  big.writeInt32BE(10_000_000, 1);
  r.feed(big);
  assert.throws(() => r.takeMessage(), /a message of 10000000 bytes/);
  const s = new PgReader();
  const head = Buffer.alloc(4);
  head.writeInt32BE(MAX_STARTUP_BYTES + 1, 0);
  s.feed(head);
  assert.throws(() => s.takeStartup(), /startup packet/);
});

test("password and error messages round-trip; SASL mechanisms are listed", () => {
  const pm = passwordMessage("$MDU:nomodel_Read[ab12].alice.password");
  assert.equal(pm.subarray(0, 1).toString(), "p");
  assert.equal(passwordOf(pm.subarray(5)), "$MDU:nomodel_Read[ab12].alice.password");
  assert.equal(passwordOf(Buffer.from("no-nul")), null);
  const e = errorResponse("28000", "mandu: refused");
  assert.equal(errorText(e.subarray(5)), "mandu: refused");
  assert.deepEqual(saslMechanisms(Buffer.from("SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0")), ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]);
});

test("md5: md5(md5(password || user) || salt), prefixed md5", () => {
  const salt = Buffer.from([0x93, 0x0f, 0x1c, 0x6a]);
  const inner = createHash("md5").update("s3cretalice").digest("hex");
  const want = "md5" + createHash("md5").update(Buffer.concat([Buffer.from(inner), salt])).digest("hex");
  assert.equal(md5Password("alice", "s3cret", salt), want);
});

test("SCRAM-SHA-256: RFC 7677 §3's exchange, byte for byte, and the server signature checked", () => {
  const c = new ScramClient("pencil", { nonce: "rOprNGfwEbeRWgbNEkqO", user: "user" });
  assert.equal(c.first(), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
  const serverFirst = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
  assert.equal(c.final(serverFirst), "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");
  assert.equal(c.verify("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="), true);
  assert.equal(c.verify("v=AAAATRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="), false, "a wrong signature");
  assert.equal(c.verify("e=invalid-proof"), false);
});

test("SCRAM refuses a server nonce that does not extend the client's, and absurd iteration counts", () => {
  const c = new ScramClient("pw", { nonce: "abc" });
  c.first();
  assert.throws(() => c.final("r=xyz123,s=c2FsdA==,i=4096"), /nonce/);
  assert.throws(() => c.final("r=abc,s=c2FsdA==,i=4096"), /nonce/, "the bare client nonce");
  assert.throws(() => c.final("r=abcdef,s=c2FsdA==,i=999999999"), /iteration/);
  assert.throws(() => c.final("r=abcdef,s=c2FsdA==,i=4095"), /iteration count of 4095/, "below Postgres's own default");
  assert.throws(() => c.final("e=other-error"), /refused SCRAM/);
  assert.equal(new ScramClient("pw").verify("v=AAAA"), false, "verify before final");
});

test("saslPrep: ASCII as is, non-ASCII spaces mapped, NFKC applied", () => {
  assert.equal(saslPrep("p@ss word!"), "p@ss word!");
  assert.equal(saslPrep("a b"), "a b");
  assert.equal(saslPrep("Ⅸ"), "IX");
  assert.equal(saslPrep("x­y"), "xy");
});
