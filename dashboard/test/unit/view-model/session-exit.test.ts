/**
 * session-exit.test — the one rule for "the session's agent exited"
 * (src/view-model/session-exit.ts, dashboard.md §4.10.4, §4.25): a recorded
 * `session_exit` with no agent activity after it. The product pages read it
 * through agent-page.ts; the event sources spread `withExited` into each
 * SessionRef, so the developer view's list uses the same rule.
 *
 * Axes: none (pure; no arbiter, no policy).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import type { ManduEvent } from "../../../src/event-model.js";
import { sessionExited, withExited } from "../../../src/view-model/session-exit.js";
import { sessionExited as pageSessionExited } from "../../../src/view-model/agent-page.js";

const ev = (kind: string, ts: string): ManduEvent => ({ kind, ts: `2026-10-05T01:${ts}.000Z` }) as unknown as ManduEvent;

test("sessionExited: a recorded exit after the last model call or tool step; none, or activity after it, is not an exit", () => {
  const ran = [ev("user_prompt", "34:48"), ev("tllm_call", "35:00"), ev("tool_use", "35:01"), ev("tool_result", "35:02")];
  assert.equal(sessionExited(ran), false, "no session_exit: not known to have exited");
  assert.equal(sessionExited([...ran, ev("session_exit", "43:56")]), true);
  assert.equal(sessionExited([ev("session_exit", "35:02"), ...ran]), true, "an exit at the last activity's moment counts, in any order");
  assert.equal(sessionExited([...ran, ev("session_exit", "36:00"), ev("tllm_call", "40:00")]), false, "a model call after the exit: the session resumed");
  assert.equal(sessionExited([...ran, ev("session_exit", "36:00"), ev("tllm_call", "40:00"), ev("session_exit", "41:00")]), true, "the later exit ends it again");
  assert.equal(sessionExited([...ran, ev("session_exit", "36:00"), ev("delivery", "36:05")]), true, "bookkeeping after the exit is not activity");
  assert.equal(sessionExited([ev("session_exit", "36:00")]), true, "an agent that exited before any activity");
  assert.equal(sessionExited([]), false);
});

test("withExited: the SessionRef field, present only when the agent exited; the page builder's sessionExited is the same rule", () => {
  assert.deepEqual(withExited([ev("tllm_call", "35:00"), ev("session_exit", "36:00")]), { exited: true });
  assert.deepEqual(withExited([ev("tllm_call", "35:00")]), {}, "no exit: no field at all");
  assert.equal(pageSessionExited, sessionExited, "agent-page.ts re-exports the one rule");
});
