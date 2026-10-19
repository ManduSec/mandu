/**
 * send-without.test — which cards take "Send without it", and how the
 * approval store keeps the answer (confidentiality.md §4 "Send without it", "Send without
 * it", 2026-10-17). Mandu-new.
 *
 *   - `sendWithoutRefusal` (pure): a secret's whole `$MDU:` symbol × a
 *     network host, with the confidentiality axis on, takes it; every
 *     content-agnostic card (a program holding a secret, a HIGH session's
 *     request or command, a file open or change, a held message, a masked
 *     value asked into the model's context) is refused, since its request
 *     may hold the raw value;
 *   - the store: the answer is a ONCE DENIAL carrying `strip`, spent like
 *     an Allow once, cleared by a fresh pending cycle and by any other
 *     answer, and kept across a restart (the `strip` column, added to an
 *     older table in place).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import Database from "../../db/sqlite.js";
import { EgressApprovalStore } from "../../policy/egress-approvals.js";
import { isNetworkDestination, isSymbolSubject, sendWithoutRefusal } from "../../policy/send-without.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SYM = "$MDU:nomodel_Read[ab12cd34]";
const ON = { confidentiality: true, secretSymbol: true };

test("a secret's symbol in a request to a network host takes Send without it", () => {
  assert.equal(sendWithoutRefusal({ symbol: SYM, destination: "api.github.com" }, ON), null);
  assert.equal(sendWithoutRefusal({ symbol: `${SYM}.password`, destination: "api.github.com:443" }, ON), null, "a field path and a port");
  assert.equal(sendWithoutRefusal({ symbol: SYM, destination: "127.0.0.1:8080" }, ON), null);
  assert.equal(sendWithoutRefusal({ symbol: SYM, destination: "[::1]:8080" }, ON), null);
});

test("every content-agnostic card is refused: its request may hold the raw value, with no placeholder to take out", () => {
  const subjects = [
    "holder-send:{\"files\":[\"/home/u/.env\"],\"session\":\"s1\"}",
    "session-net:s1",
    "session-exec:s1",
    "<taint:pid:1→evil.example>",
    "<secret-taint:pid:1→evil.example>",
    "<secret-taint:unattributed→evil.example>",
    "open:cat#/usr/bin/cat",
    "write:/home/u/.bashrc",
    "trust:/usr/bin/python3",
    "prompt:api-key#f1",
    "exec-program:abc",
    `${SYM} trailing`,
    `x${SYM}`,
    "",
  ];
  for (const symbol of subjects) {
    const why = sendWithoutRefusal({ symbol, destination: "evil.example" }, ON);
    assert.ok(why !== null, `refused: ${symbol}`);
  }
});

test("a symbol card is refused when it is not a network send, not a secret, or the axis is off", () => {
  assert.ok(sendWithoutRefusal({ symbol: SYM, destination: "model_context:in-context-read" }, ON), "a masked value asked into the model's context");
  assert.ok(sendWithoutRefusal({ symbol: SYM, destination: "model:s1#turn:3" }, ON));
  assert.ok(sendWithoutRefusal({ symbol: SYM, destination: "/home/u/.env" }, ON));
  assert.ok(sendWithoutRefusal({ symbol: SYM, destination: "https://evil.example/x" }, ON), "a URL is not a host");
  assert.ok(sendWithoutRefusal({ symbol: SYM, destination: "evil.example" }, { confidentiality: true, secretSymbol: false }), "not a secret the table holds");
  assert.ok(sendWithoutRefusal({ symbol: SYM, destination: "evil.example" }, { confidentiality: false, secretSymbol: true }), "the axis off");
});

test("the subject and destination grammars", () => {
  assert.equal(isSymbolSubject(SYM), true);
  assert.equal(isSymbolSubject("$MDU:x[zz]"), false);
  assert.equal(isNetworkDestination("a.b-c.example"), true);
  assert.equal(isNetworkDestination("a b"), false);
  assert.equal(isNetworkDestination("fs:Read:open"), false);
  assert.equal(isNetworkDestination(""), false);
});

test("the store: Send without it is a once DENIAL carrying strip; spent like a once; a fresh cycle and any other answer clear it", () => {
  let t = 1000;
  const store = new EgressApprovalStore({ now: () => ++t });
  const row = store.recordPending(SYM, "api.github.com", "secret at unbound destination", "s1");
  const answered = store.resolve(row.id, true, "always", { strip: true })!;
  assert.equal(answered.status, "denied", "never an approval, whatever approve said");
  assert.equal(answered.scope, "once", "one-shot, whatever scope said");
  assert.equal(answered.strip, true);
  assert.equal(store.lookupEntry(SYM, "api.github.com")!.strip, true);

  // spent by its one decision; the next attempt is a fresh question
  assert.ok(store.consumeOnce(row.id));
  const again = store.recordPending(SYM, "api.github.com", "secret at unbound destination", "s1");
  assert.equal(again.status, "pending");
  assert.equal(again.strip, undefined, "a fresh cycle is no strip");

  // any other answer clears it
  store.resolve(row.id, false, "always", { strip: true });
  const blocked = store.resolve(row.id, false, "always")!;
  assert.equal(blocked.strip, undefined);
  assert.equal(blocked.scope, "always");
});

test("the store: the answer survives a restart; an older table gains the column in place; a stray cell on another row is ignored", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-send-without-"));
  try {
    const dbPath = join(dir, "db.sqlite");
    // a table from before the column
    const old = new Database(dbPath);
    old.exec(`CREATE TABLE egress_approvals (id TEXT PRIMARY KEY, symbol TEXT NOT NULL, destination TEXT NOT NULL, status TEXT NOT NULL,
      reason TEXT NOT NULL, count INTEGER NOT NULL, firstSeen INTEGER NOT NULL, lastSeen INTEGER NOT NULL, resolvedAt INTEGER,
      sessions TEXT, scope TEXT NOT NULL, consumedAt INTEGER);
      CREATE UNIQUE INDEX idx_egress_approvals_key ON egress_approvals(symbol, destination);
      INSERT INTO egress_approvals VALUES ('egr-1', '${SYM}', 'old.example', 'denied', 'r', 1, 1, 1, 1, '[]', 'always', NULL);`);
    old.close();

    const a = new EgressApprovalStore({ dbPath });
    assert.equal(a.lookupEntry(SYM, "old.example")!.strip, undefined, "an older row reads as no strip");
    const row = a.recordPending(SYM, "api.github.com", "r", "s1");
    a.resolve(row.id, false, "once", { strip: true });
    a.close();

    const b = new EgressApprovalStore({ dbPath });
    const back = b.lookupEntry(SYM, "api.github.com")!;
    assert.equal(back.strip, true, "kept across a restart");
    assert.equal(back.status, "denied");
    assert.equal(back.scope, "once");
    b.close();

    // a strip cell on a row that is not a once denial is never read as one
    const raw = new Database(dbPath);
    raw.prepare("UPDATE egress_approvals SET strip = 1 WHERE id = 'egr-1'").run();
    raw.close();
    const c = new EgressApprovalStore({ dbPath });
    assert.equal(c.lookupEntry(SYM, "old.example")!.strip, undefined);
    c.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
