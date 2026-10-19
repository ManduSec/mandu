/**
 * exec-clean-verdicts.test — unit tests for the per-invocation CLEAN-verdict
 * store (exec-routing.md §8.4 rung 2 / §5, the arbiter half).
 *
 * The store IS the §5 gate chain: every absent/failing input must resolve
 * UNCLEAN with the failing gate named (fail-closed — a miss is a utility miss,
 * never a leak), the arbiter re-checks lineage taint itself, and unclean is
 * monotonic downward. Pure + deterministic (no daemon, no kernel).
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ExecCleanVerdictStore,
  type ExecCleanVerdictReport,
} from "../../policy/exec-clean-verdicts.js";

const SHA = "a".repeat(64);
/** The session guard's channel (exec-routing.md §8.5.3): a report carrying
 *  the token the guard of session s1 claimed. */
const AUTH = { via: "authenticated-supervisor", sessionKey: "s1" } as const;

/** A report that passes every gate against a never-tainted oracle. */
function cleanReport(overrides: Partial<ExecCleanVerdictReport> = {}): ExecCleanVerdictReport {
  return {
    callId: "toolu_clean_01",
    clean: true,
    boxed: true,
    shell: "AgentShell",
    procKey: "boot42:1234",
    outputSha256: SHA,
    reason: "landlock read-allow: 12 paths",
    sessionKey: "s1",
    ...overrides,
  };
}

function store(opts: { tainted?: Set<string>; capacity?: number; noOracle?: boolean } = {}) {
  return new ExecCleanVerdictStore({
    ...(opts.capacity !== undefined ? { capacity: opts.capacity } : {}),
    ...(opts.noOracle ? {} : { isProcessTainted: (k) => opts.tainted?.has(k) ?? false }),
  });
}

test("a report passing every §5 gate resolves CLEAN and is retrievable by callId", () => {
  const s = store();
  const v = s.report(cleanReport(), AUTH);
  assert.equal(v.clean, true);
  assert.match(v.reason, /clean \(boxed AgentShell, lineage untainted\)/);
  assert.match(v.reason, /landlock read-allow/);
  assert.equal(v.outputSha256, SHA);
  assert.equal(s.lookup("toolu_clean_01")?.clean, true);
  assert.equal(s.size(), 1);
});

test("a report over the data socket is never honored, whatever it claims (finding 4)", () => {
  // The reporter runs inside the agent's process tree; a claim that passes
  // every other gate still resolves UNCLEAN, and nothing upgrades on it.
  const s = store();
  const v = s.report(cleanReport(), "data-socket");
  assert.equal(v.clean, false);
  assert.match(v.reason, /data socket/);
  assert.match(v.reason, /cannot be authenticated/);
  assert.equal("outputSha256" in v, false);
  assert.equal(s.lookup("toolu_clean_01")?.clean, false);
  // Monotonic downward still holds: a later authenticated report cannot flip
  // a callId the data socket already resolved unclean.
  assert.equal(s.report(cleanReport(), AUTH).clean, false);
});

test("every §5 gate fails closed, naming itself", () => {
  const cases: Array<[Partial<ExecCleanVerdictReport>, RegExp]> = [
    [{ clean: false }, /supervisor reported unclean/],
    [{ boxed: undefined }, /did not run inside the exec box/],
    [{ boxed: false }, /did not run inside the exec box/],
    [{ shell: "HumanShell" }, /only AgentShell qualifies/],
    [{ shell: undefined }, /only AgentShell qualifies/],
    [{ procKey: undefined }, /no procKey/],
    [{ outputSha256: undefined }, /no output sha256/],
    [{ outputSha256: "not-hex" }, /no output sha256/],
    [{ outputSha256: SHA.slice(0, 63) }, /no output sha256/],
  ];
  for (const [override, re] of cases) {
    const v = store().report(cleanReport({ ...override, callId: "toolu_gate" }), AUTH);
    assert.equal(v.clean, false, `gate must fail for ${JSON.stringify(override)}`);
    assert.match(v.reason, re);
    assert.equal("outputSha256" in v, false, "an unclean verdict must not carry a hash");
  }
});

test("the ARBITER's own taint oracle gates the verdict (§5: a tainted parent poisons the invocation)", () => {
  const s = store({ tainted: new Set(["boot42:1234"]) });
  const v = s.report(cleanReport(), AUTH);
  assert.equal(v.clean, false);
  assert.match(v.reason, /lineage-tainted/);
});

test("no taint oracle wired ⇒ every verdict resolves UNCLEAN (a store that cannot check must not upgrade)", () => {
  const s = store({ noOracle: true });
  const v = s.report(cleanReport(), AUTH);
  assert.equal(v.clean, false);
  assert.match(v.reason, /no taint oracle/);
});

test("empty callId resolves UNCLEAN and records nothing", () => {
  const s = store();
  const v = s.report(cleanReport({ callId: "" }), AUTH);
  assert.equal(v.clean, false);
  assert.equal(s.size(), 0);
  assert.equal(s.lookup(""), undefined);
});

test("monotonic downward: unclean is never flipped clean by a later report; clean CAN downgrade", () => {
  const s = store();
  // unclean first → a later clean report must not resurrect it.
  s.report(cleanReport({ callId: "toolu_m", clean: false }), AUTH);
  const after = s.report(cleanReport({ callId: "toolu_m" }), AUTH);
  assert.equal(after.clean, false, "the standing unclean verdict wins");
  assert.equal(s.lookup("toolu_m")?.clean, false);
  // clean first → a later unclean report downgrades it.
  s.report(cleanReport({ callId: "toolu_n" }), AUTH);
  s.report(cleanReport({ callId: "toolu_n", clean: false, reason: "late re-report" }), AUTH);
  assert.equal(s.lookup("toolu_n")?.clean, false);
});

test("bounded: overflow evicts oldest-first, like the exec-decision sibling", () => {
  const s = store({ capacity: 2 });
  s.report(cleanReport({ callId: "a" }), AUTH);
  s.report(cleanReport({ callId: "b" }), AUTH);
  s.report(cleanReport({ callId: "c" }), AUTH);
  assert.equal(s.size(), 2);
  assert.equal(s.lookup("a"), undefined, "oldest evicted");
  assert.equal(s.lookup("b")?.clean, true);
  assert.equal(s.lookup("c")?.clean, true);
});

test("an authenticated verdict names the token's session, never the one the report claims (§5.3)", () => {
  // Axes: none (the store is below the axis switches). A guard of session s2
  // reporting a callId with sessionKey "s1" records a verdict for s2: classify
  // in s1 then misses it (claude-code-inbound.test pins that half).
  const s = store();
  const v = s.report(cleanReport({ sessionKey: "s1" }), { via: "authenticated-supervisor", sessionKey: "s2" });
  assert.equal(v.clean, true);
  assert.equal(v.sessionKey, "s2");
  assert.equal(s.lookup("toolu_clean_01")?.sessionKey, "s2");
});
