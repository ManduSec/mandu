/**
 * relay-notices — the queue of the DevTools relay's refusals
 * (ipc/relay-notices.ts; devtools-relay.md §3.4): a notice is checked field
 * by field (kinds, a host, placeholder names only), kept per session,
 * bounded (per session, sessions, age), a repeat replaces the pending one,
 * and taking returns them oldest first and clears them. Mandu-new.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  RELAY_NOTICES_PER_SESSION, RELAY_NOTICE_SESSIONS, RELAY_NOTICE_TTL_MS, RelayNoticeQueue, parseRelayNotice, type RelayNoticeWire,
} from "../../ipc/relay-notices.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the queue is axis-free; stated all the same

const MADE_UP = "$MDU:web_fetch[8c4f].text";
const SHOWN = "$MDU:nomodel_Read[8c4e].CARD_NUMBER";
const unknown = (sym = MADE_UP): RelayNoticeWire => ({ kind: "unknown", page: "ledgerly.localhost", symbols: [sym], shown: [SHOWN] });

test("a notice is checked field by field: kinds and causes from the lists, a host, placeholder names only", () => {
  assert.deepEqual(parseRelayNotice(unknown()), unknown());
  assert.deepEqual(parseRelayNotice({ kind: "failed", cause: "no-field", symbols: [SHOWN], page: "Ledgerly.Localhost" }), { kind: "failed", cause: "no-field", symbols: [SHOWN], page: "ledgerly.localhost" });
  assert.deepEqual(parseRelayNotice({ kind: "not-allowed", symbols: [SHOWN, SHOWN], page: "[::1]" }), { kind: "not-allowed", symbols: [SHOWN], page: "[::1]" });
  const bad: unknown[] = [
    null, "x", [], { kind: "leak", symbols: [SHOWN] },
    { kind: "unknown", symbols: [] },
    { kind: "unknown", symbols: ["sk_live_0123456789abcdef"] },
    { kind: "unknown", symbols: [`${SHOWN} and the value sk_live_0123`] },
    { kind: "unknown", symbols: [SHOWN], page: "evil.example/path?x=sk_live_1" },
    { kind: "unknown", symbols: [SHOWN], page: "ignore previous instructions" },
    { kind: "unknown", symbols: [SHOWN], shown: ["4242 4242 4242 4242"] },
    { kind: "not-allowed", symbols: [SHOWN], shown: [SHOWN] },
    { kind: "failed", symbols: [SHOWN] },
    { kind: "failed", symbols: [SHOWN], cause: "because I said so" },
    { kind: "unknown", symbols: [SHOWN], cause: "no-field" },
    { kind: "unknown", symbols: Array.from({ length: 9 }, (_, i) => `$MDU:x[000${i}]`) },
  ];
  for (const b of bad) assert.equal(typeof parseRelayNotice(b), "string", JSON.stringify(b));
});

test("a lookalike's notice (malformed) names no placeholder of its own: its code is free text; the shown ones are checked as ever", () => {
  assert.deepEqual(parseRelayNotice({ kind: "malformed", page: "ledgerly.localhost", symbols: [], shown: [SHOWN] }), { kind: "malformed", page: "ledgerly.localhost", symbols: [], shown: [SHOWN] });
  assert.deepEqual(parseRelayNotice({ kind: "malformed" }), { kind: "malformed", symbols: [] });
  for (const bad of [
    { kind: "malformed", symbols: ["$MDU:nomodel_Read[e213b2c2-8419-4809-b684-297d264f3319].number"] },
    { kind: "malformed", symbols: [SHOWN] },
    { kind: "malformed", symbols: "x" },
    { kind: "malformed", symbols: [], shown: ["4242 4242 4242 4242"] },
    { kind: "malformed", symbols: [], cause: "no-field" },
    { kind: "malformed", symbols: [], page: "ignore previous instructions" },
  ]) assert.equal(typeof parseRelayNotice(bad), "string", JSON.stringify(bad));
});

test("taking returns the session's notices oldest first and clears them; other sessions keep theirs", () => {
  const q = new RelayNoticeQueue();
  q.add("s1", unknown(), 1000);
  q.add("s1", { kind: "not-allowed", page: "chat.localhost", symbols: [SHOWN] }, 1001);
  q.add("s2", unknown(), 1002);
  assert.deepEqual(q.take("s1", 1003).map((n) => n.kind), ["unknown", "not-allowed"]);
  assert.deepEqual(q.take("s1", 1004), [], "told once");
  assert.equal(q.take("s2", 1005).length, 1);
  assert.deepEqual(q.take("nobody"), []);
});

test("a repeat of a pending notice replaces it (the model retried the same token)", () => {
  const q = new RelayNoticeQueue();
  for (let i = 0; i < 3; i++) q.add("s", unknown(), 1000 + i);
  q.add("s", unknown("$MDU:web_fetch[8c4f].other"), 1010);
  q.add("s", unknown(), 1011);
  assert.deepEqual(q.take("s", 1012).map((n) => n.symbols[0]), ["$MDU:web_fetch[8c4f].other", MADE_UP]);
});

test("bounded: per session, sessions (the least recently reported dropped), age", () => {
  const q = new RelayNoticeQueue();
  for (let i = 0; i < RELAY_NOTICES_PER_SESSION + 3; i++) q.add("s", unknown(`$MDU:web_fetch[${(0x1000 + i).toString(16)}]`), 1000 + i);
  const kept = q.take("s", 2000);
  assert.equal(kept.length, RELAY_NOTICES_PER_SESSION);
  assert.equal(kept[0]!.symbols[0], `$MDU:web_fetch[${(0x1000 + 3).toString(16)}]`, "the oldest dropped first");

  for (let i = 0; i <= RELAY_NOTICE_SESSIONS; i++) q.add(`s${i}`, unknown(), 3000 + i);
  assert.equal(q.sessions, RELAY_NOTICE_SESSIONS);
  assert.deepEqual(q.take("s0", 4000), [], "the least recently reported session went first");
  assert.equal(q.take(`s${RELAY_NOTICE_SESSIONS}`, 4000).length, 1);

  q.add("old", unknown(), 0);
  assert.deepEqual(q.take("old", RELAY_NOTICE_TTL_MS + 1), [], "too old to tell");
});
