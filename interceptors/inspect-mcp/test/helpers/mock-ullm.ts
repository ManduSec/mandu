/**
 * mock-ullm — an in-memory quarantined-model client for the test suite.
 *
 * Mandu M4 (interceptors/inspect-mcp) test helper. Implements the `UllmClient`
 * seam (src/ullm-client.ts) so the suite makes NO network call and needs NO API
 * key. Records every call so tests can assert the quarantined call carries the
 * raw value + instruction and NO T-LLM history/system prompt.
 *
 * `fail` injects a U-LLM error to exercise the core's FAIL-CLOSED path.
 *
 * The mock is triage-aware: inspect_symbol makes TWO quarantined calls per
 * inspect (the main instruction call + the fixed content_kind triage call,
 * symbol-quality.md §4.2), distinguished by their system prompt. `triageReply`
 * / `failTriage` steer the triage call independently; `mainCalls` /
 * `triageCalls` split the recording for assertions.
 */

import type { UllmCall, UllmClient, UllmResult } from "../../src/ullm-client.js";
import { TRIAGE_SYSTEM_PROMPT, TRIAGE_SYSTEM_PROMPT_REQUEST } from "../../src/inspect-symbol.js";

/** Both fixed triage prompt variants (provenance-free + §4.1 v2 request-aware). */
const TRIAGE_SYSTEMS = new Set([TRIAGE_SYSTEM_PROMPT, TRIAGE_SYSTEM_PROMPT_REQUEST]);

export interface MockUllmOptions {
  /** The text the quarantined model returns (main instruction call). */
  reply?: string;
  /** Sequential replies for SUCCESSIVE main calls (the contradiction-retry
   *  tests: refusal first, compliance second). Takes precedence over `reply`;
   *  the last entry repeats once exhausted. */
  mainReplies?: string[];
  /** The text the TRIAGE call returns (defaults to "substantive"). */
  triageReply?: string;
  /** The model id reported. */
  model?: string;
  /** Throw on complete() to exercise fail-closed (BOTH call kinds). */
  fail?: boolean;
  /** Throw ONLY for the triage call (main call succeeds). */
  failTriage?: boolean;
}

export class MockUllm implements UllmClient {
  /** Every quarantined call, for assertions (NO T-LLM context should appear). */
  readonly calls: UllmCall[] = [];

  constructor(private readonly opts: MockUllmOptions = {}) {}

  /** The main instruction calls (system = quarantine prompt). */
  get mainCalls(): UllmCall[] {
    return this.calls.filter((c) => !TRIAGE_SYSTEMS.has(c.system));
  }

  /** The content_kind triage calls (either fixed triage prompt variant). */
  get triageCalls(): UllmCall[] {
    return this.calls.filter((c) => TRIAGE_SYSTEMS.has(c.system));
  }

  async complete(call: UllmCall): Promise<UllmResult> {
    this.calls.push(call);
    if (this.opts.fail) throw new Error("mock U-LLM: failure (injected)");
    if (TRIAGE_SYSTEMS.has(call.system)) {
      if (this.opts.failTriage) throw new Error("mock U-LLM: triage failure (injected)");
      return {
        text: this.opts.triageReply ?? "substantive",
        model: this.opts.model ?? "claude-mock",
      };
    }
    if (this.opts.mainReplies && this.opts.mainReplies.length > 0) {
      const i = Math.min(this.mainCalls.length - 1, this.opts.mainReplies.length - 1);
      return { text: this.opts.mainReplies[i]!, model: this.opts.model ?? "claude-mock" };
    }
    return {
      text: this.opts.reply ?? "QUARANTINED_RESULT",
      model: this.opts.model ?? "claude-mock",
    };
  }
}
