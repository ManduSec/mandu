/**
 * rate-limit.test.ts — an upstream throttle read off its headers
 * (src/rate-limit.ts): which limit, until when, and whether it is a plan's
 * quota the proxy must relay at once instead of retrying.
 *
 * The headers below are the ones a subscription at its weekly limit got on
 * 2026-10-28 (live, the nightly VM), minus the request id.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { HARD_LIMIT_S, describeUpstreamLimit, isHardLimit, parseUpstreamLimit, retryAfterSeconds } from "../../src/rate-limit.js";

const NOW = Date.parse("2026-10-28T08:27:28Z");
const WEEKLY: Record<string, string> = {
  "content-type": "application/json",
  "x-should-retry": "true",
  "retry-after": "45151",
  "anthropic-ratelimit-unified-status": "rejected",
  "anthropic-ratelimit-unified-representative-claim": "seven_day",
  "anthropic-ratelimit-unified-reset": "1793221200",
  "anthropic-ratelimit-unified-7d-status": "rejected",
  "anthropic-ratelimit-unified-7d-utilization": "1.0",
  "anthropic-ratelimit-unified-7d-reset": "1793221200",
  "anthropic-ratelimit-unified-7d-surpassed-threshold": "1.0",
  "anthropic-ratelimit-unified-5h-status": "allowed",
  "anthropic-ratelimit-unified-5h-utilization": "0.0",
  "anthropic-ratelimit-unified-5h-reset": "1793193600",
  "anthropic-ratelimit-unified-overage-status": "rejected",
  "anthropic-ratelimit-unified-overage-disabled-reason": "org_level_disabled",
  "anthropic-ratelimit-unified-upgrade-paths": "overage",
};

test("a weekly limit: the claim, both windows, the reset and Retry-After, and it is hard", () => {
  const l = parseUpstreamLimit(429, WEEKLY, NOW)!;
  assert.deepEqual(l, {
    status: 429,
    unifiedStatus: "rejected",
    claim: "seven_day",
    fiveHour: { status: "allowed", utilization: 0, resetsAt: "2026-10-28T13:20:00.000Z" },
    sevenDay: { status: "rejected", utilization: 1, resetsAt: "2026-10-28T21:00:00.000Z" },
    overageStatus: "rejected",
    resetsAt: "2026-10-28T21:00:00.000Z",
    retryAfterS: 45151,
    hard: true,
  });
  assert.equal(describeUpstreamLimit(l), "rate-limited until 2026-10-28 21:00 UTC (seven-day limit)");
});

test("a short throttle (Retry-After of seconds, the plan's limits allowed) is not hard: the proxy keeps absorbing it", () => {
  const l = parseUpstreamLimit(429, { "retry-after": "2", "anthropic-ratelimit-unified-status": "allowed" }, NOW)!;
  assert.equal(l.hard, false);
  assert.equal(l.retryAfterS, 2);
  assert.equal(parseUpstreamLimit(429, {}, NOW)!.hard, false, "no headers at all: a plain throttle");
  assert.equal(describeUpstreamLimit(parseUpstreamLimit(429, {}, NOW)!), "rate-limited");
  // a 529 is an overload
  const o = parseUpstreamLimit(529, { "retry-after": "5" }, NOW)!;
  assert.equal(o.hard, false);
  assert.equal(describeUpstreamLimit(o), "overloaded (retry after 5s)");
});

test("hard: a Retry-After of minutes, or the quota refused with its reset minutes away", () => {
  assert.equal(parseUpstreamLimit(429, { "retry-after": String(HARD_LIMIT_S) }, NOW)!.hard, true);
  assert.equal(parseUpstreamLimit(429, { "retry-after": String(HARD_LIMIT_S - 1) }, NOW)!.hard, false);
  const soon = String(Math.floor(NOW / 1000) + 60);
  assert.equal(parseUpstreamLimit(429, { "anthropic-ratelimit-unified-status": "rejected", "anthropic-ratelimit-unified-reset": soon }, NOW)!.hard, false, "a reset a minute away: retried");
  assert.equal(parseUpstreamLimit(429, { "anthropic-ratelimit-unified-status": "rejected" }, NOW)!.hard, true, "refused, with no reset and no Retry-After: not a spike");
  assert.equal(isHardLimit({ status: 429, unifiedStatus: "allowed" }, NOW), false);
});

test("only 429 and 529 are limits", () => {
  for (const s of [200, 400, 401, 403, 500, 502]) assert.equal(parseUpstreamLimit(s, WEEKLY, NOW), null, String(s));
});

test("each value is held to its shape; anything else of the answer is never read", () => {
  const l = parseUpstreamLimit(429, {
    "anthropic-ratelimit-unified-status": "rejected; token=sk-ant-oat01-SECRET",
    "anthropic-ratelimit-unified-representative-claim": "Seven Day <b>",
    "anthropic-ratelimit-unified-7d-utilization": "lots",
    "anthropic-ratelimit-unified-reset": "tomorrow",
    "retry-after": "-5",
    authorization: "Bearer sk-ant-oat01-SECRET",
    "x-api-key": "sk-ant-api03-SECRET",
    "set-cookie": "session=SECRET",
  }, NOW)!;
  assert.deepEqual(l, { status: 429, hard: false }, "malformed values are dropped, not passed on");
  assert.ok(!JSON.stringify(l).includes("SECRET"));
  // header names in any case; an array value takes its first
  const m = parseUpstreamLimit(429, { "Anthropic-Ratelimit-Unified-Status": ["rejected", "allowed"], "Retry-After": "600" }, NOW)!;
  assert.equal(m.unifiedStatus, "rejected");
  assert.equal(m.retryAfterS, 600);
});

test("Retry-After as an HTTP date", () => {
  assert.equal(retryAfterSeconds({ "retry-after": new Date(NOW + 90_000).toUTCString() }, NOW), 90);
  assert.equal(retryAfterSeconds({ "retry-after": "not a date" }, NOW), undefined);
});
