/**
 * assertion-verdicts.test — unit tests for the pure SessionRef verdict deriver
 * (event-source.ts assertionVerdicts): the sidebar's per-session ✓/✗ from the
 * session's LAST `assertion` event — `checksVerdict` ("fail" iff any check is a
 * BLOCKING fail; warn/skip count as pass, matching the §4.13 panel),
 * `checksFailed` (WHICH groups failed — security refined by aspect) and
 * `historyFidelity` (the same rule over just the HISTORY_FIDELITY_ASSERTS
 * oracle checks, omitted when none ran) — plus the FileEventSource.listSessions
 * integration that spreads the verdicts onto each SessionRef from NDJSON.
 *
 * Mandu-new test. Runs under `node --test`, no DOM.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";

import type { ManduEvent, AssertionCheck } from "../../src/event-model.js";
import { assertionVerdicts, FileEventSource } from "../../src/event-source.js";
import { tmpDir } from "./tmp-dir.js";

function base(partial: Partial<ManduEvent>): ManduEvent {
  return {
    id: "e", sessionId: "s", turn: 0, ts: "2026-07-07T00:00:00.000Z", seq: 1,
    callId: null, parentId: null, kind: "tllm_call", view: "AgentView",
    boundary: "model_context", emitter: "anthropic-proxy",
    input: null, output: null, invariant: { violatedInvariant: false },
    ...partial,
  } as ManduEvent;
}

function assertionEvent(checks: AssertionCheck[], id = "a1"): ManduEvent {
  return base({
    id, kind: "assertion", view: "HumanView", emitter: "test-harness",
    ts: "2026-07-07T00:01:00.000Z", assertions: checks,
  });
}

const chk = (over: Partial<AssertionCheck>): AssertionCheck => ({
  label: "c", category: "security", status: "pass", reason: "ok", ...over,
});

test("returns {} when the session has no assertion event", () => {
  assert.deepEqual(assertionVerdicts([]), {});
  assert.deepEqual(assertionVerdicts([base({ kind: "tllm_call" })]), {});
});

test("all checks pass → checksVerdict pass, and NO historyFidelity without history_* asserts", () => {
  const v = assertionVerdicts([
    assertionEvent([
      chk({ label: "sym", category: "security", status: "pass" }),
      chk({ label: "exit", category: "utility", status: "pass" }),
    ]),
  ]);
  assert.deepEqual(v, { checksVerdict: "pass" }, "fidelity key omitted when the oracle didn't run");
});

test("warn and skip are NON-blocking — the verdict stays pass (matches the §4.13 panel)", () => {
  const v = assertionVerdicts([
    assertionEvent([
      chk({ label: "sym", category: "security", status: "pass" }),
      chk({ label: "stdout", category: "utility", status: "warn" }),
      chk({ label: "flagged", category: "security", status: "skip" }),
    ]),
  ]);
  assert.deepEqual(v, { checksVerdict: "pass" });
});

test("any check with status fail → checksVerdict fail", () => {
  const v = assertionVerdicts([
    assertionEvent([
      chk({ label: "sym", status: "pass" }),
      chk({ label: "raw", status: "fail", reason: "leaked" }),
    ]),
  ]);
  assert.equal(v.checksVerdict, "fail");
  assert.deepEqual(v.checksFailed, ["security"], "an aspect-less security fail names the legacy group");
});

test("checksFailed names the failing groups — security refined by aspect, deduped, blocking-first", () => {
  const v = assertionVerdicts([
    assertionEvent([
      chk({ label: "sym", aspect: "integrity", status: "pass" }),
      chk({ label: "exit", category: "utility", status: "fail", reason: "exit 1" }),
      chk({ label: "conf-wire", aspect: "confidentiality", status: "fail", reason: "LEAKED" }),
      chk({ label: "conf-catalog", aspect: "confidentiality", status: "fail", reason: "LEAKED too" }),
    ]),
  ]);
  assert.equal(v.checksVerdict, "fail");
  assert.deepEqual(v.checksFailed, ["security-confidentiality", "utility"],
    "aspect refines the group name; duplicates collapse; security groups order first");
});

test("checksFailed is OMITTED when everything passes (nothing to name)", () => {
  const v = assertionVerdicts([
    assertionEvent([chk({ label: "sym", aspect: "integrity", status: "pass" })]),
  ]);
  assert.equal(v.checksVerdict, "pass");
  assert.equal("checksFailed" in v, false);
});

test("the LAST assertion event wins when a session re-ran", () => {
  const v = assertionVerdicts([
    assertionEvent([chk({ status: "fail", reason: "old failure" })], "old"),
    assertionEvent([chk({ status: "pass" })], "new"),
  ]);
  assert.deepEqual(v, { checksVerdict: "pass" }, "the re-run's all-pass event overwrites the old verdict");
});

test("history-fidelity checks all passing while another check fails → fail overall, fidelity pass", () => {
  const fid = (a: string): AssertionCheck =>
    chk({ label: a, category: "fidelity", status: "pass", assert: a });
  const v = assertionVerdicts([
    assertionEvent([
      fid("history_prompts"), fid("no_bogus_input"), fid("final_reply_matches"), fid("history_tools"),
      chk({ label: "raw", category: "security", status: "fail", reason: "leaked" }),
    ]),
  ]);
  assert.equal(v.checksVerdict, "fail", "the non-oracle fail makes the overall verdict fail");
  assert.equal(v.historyFidelity, "pass", "the oracle's own checks all passed");
});

test("a failing history_tools check fails BOTH the fidelity verdict and the overall one", () => {
  const v = assertionVerdicts([
    assertionEvent([
      chk({ label: "sym", category: "security", status: "pass" }),
      chk({
        label: "history-tools", category: "fidelity", status: "fail",
        assert: "history_tools", reason: "tool_use drift vs the transcript",
      }),
    ]),
  ]);
  assert.equal(v.historyFidelity, "fail");
  assert.equal(v.checksVerdict, "fail");
});

test("an assertion event whose assertions is missing or not an array → {}", () => {
  assert.deepEqual(assertionVerdicts([base({ kind: "assertion" })]), {});
  assert.deepEqual(
    assertionVerdicts([base({ kind: "assertion", assertions: "bogus" as never })]),
    {},
  );
});

// ── FileEventSource integration: the verdicts land on each SessionRef ─────────

/** One canonical NDJSON event line (coerceEvent-clean — same field set as the
 *  test-sections e2e's eventLine, adapted per kind). */
function line(
  sessionId: string,
  kind: "tllm_call" | "assertion",
  seq: number,
  extra: Record<string, unknown> = {},
): string {
  return JSON.stringify({
    id: `${sessionId}-${seq}`,
    sessionId,
    turn: 0,
    ts: "2026-07-07T00:00:00.000Z",
    seq,
    callId: null,
    parentId: null,
    kind,
    view: kind === "assertion" ? "HumanView" : "AgentView",
    boundary: "model_context",
    emitter: kind === "assertion" ? "test-harness" : "anthropic-proxy",
    input: kind === "tllm_call"
      ? { symbolized: `▸ user\ntask for ${sessionId}`, original: null, differs: false, symbols: [] }
      : null,
    output: null,
    invariant: { violatedInvariant: false },
    ...extra,
  });
}

test("FileEventSource.listSessions spreads the assertion verdicts onto each SessionRef", async () => {
  const dir = tmpDir("mandu-evsrc-verdicts-");
  try {
    // A passing e2e session: a security check + a history_prompts oracle check.
    writeFileSync(
      join(dir, "claude-e2e-foo-1750000000000.ndjson"),
      line("claude-e2e-foo-1750000000000", "tllm_call", 0) + "\n" +
        line("claude-e2e-foo-1750000000000", "assertion", 1, {
          assertions: [
            chk({ label: "raw-injection-absent", category: "security", status: "pass", assert: "raw_absent" }),
            chk({ label: "history-prompts", category: "fidelity", status: "pass", assert: "history_prompts" }),
          ],
        }) + "\n",
    );
    // A failing e2e session, with no history_* oracle checks.
    writeFileSync(
      join(dir, "claude-e2e-bar-1750000001000.ndjson"),
      line("claude-e2e-bar-1750000001000", "tllm_call", 0) + "\n" +
        line("claude-e2e-bar-1750000001000", "assertion", 1, {
          assertions: [
            chk({ label: "raw-injection-absent", category: "security", status: "fail", reason: "leaked" }),
          ],
        }) + "\n",
    );

    const src = new FileEventSource(dir);
    const refs = await src.listSessions();
    src.close();

    const foo = refs.find((r) => r.id === "claude-e2e-foo-1750000000000");
    assert.equal(foo?.checksVerdict, "pass");
    assert.equal(foo?.historyFidelity, "pass");
    const bar = refs.find((r) => r.id === "claude-e2e-bar-1750000001000");
    assert.equal(bar?.checksVerdict, "fail");
    assert.equal(bar?.historyFidelity, undefined, "no history_* checks → fidelity omitted");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
