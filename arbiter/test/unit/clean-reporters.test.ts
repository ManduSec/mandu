/**
 * clean-reporters.test — who may vouch for a clean-box run
 * (exec-routing.md §8.5.3, sandbox-security-review finding 4). Pure.
 *
 * Axes: none. The store sits below the axis switches: it only says which
 * session a reporter token speaks for.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { CleanReporters } from "../../policy/clean-reporters.js";

test("a session nobody offered has no reporter to claim", () => {
  const r = new CleanReporters();
  const c = r.claim("s1");
  assert.equal(c.ok, false);
  assert.equal(r.offered("s1"), false);
});

test("the first claim gets a 256-bit token that maps back to its session", () => {
  const r = new CleanReporters();
  r.allow("s1");
  assert.equal(r.offered("s1"), true);
  const c = r.claim("s1");
  assert.ok(c.ok);
  assert.match(c.token, /^[0-9a-f]{64}$/);
  assert.equal(r.sessionFor(c.token), "s1");
  assert.equal(r.sessionFor("f".repeat(64)), undefined);
  assert.equal(r.sessionFor(undefined), undefined);
  assert.equal(r.sessionFor("not-hex"), undefined);
});

test("a second claim revokes the reporter for good: the first token stops counting", () => {
  const r = new CleanReporters();
  r.allow("s1");
  const first = r.claim("s1");
  assert.ok(first.ok);
  const second = r.claim("s1");
  assert.equal(second.ok, false);
  assert.equal(r.sessionFor(first.token), undefined);
  assert.equal(r.offered("s1"), false);
  // allow() cannot reopen a revoked or claimed slot.
  r.allow("s1");
  assert.equal(r.claim("s1").ok, false);
});

test("tokens are per session", () => {
  const r = new CleanReporters();
  r.allow("s1");
  r.allow("s2");
  const a = r.claim("s1");
  const b = r.claim("s2");
  assert.ok(a.ok && b.ok);
  assert.notEqual(a.token, b.token);
  assert.equal(r.sessionFor(a.token), "s1");
  assert.equal(r.sessionFor(b.token), "s2");
});
