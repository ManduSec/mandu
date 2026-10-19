/**
 * agent-fake-script.ts — the scripted model of the shared Anthropic-wire live
 * runner's FAKE tier (OpenClaw · OpenCode): the LAST_TOOL_RESULT sentinel, the
 * symbolization-invariant turn counter, and the scripted fake upstream built
 * from one scenario's `fake` script.
 *
 * Mandu (tests/). Design: docs/design/testing/agent-e2e-harness.md §7.4.
 * Extracted verbatim from anthropic-agent-runner.ts, which re-exports the
 * suite-facing names (LAST_TOOL_RESULT, countToolResults).
 */

import assert from "node:assert/strict";

import {
  startScriptedAnthropic, textTurn, toolUseTurn, extractToolResultText,
  type FakeAnthropic, type ParsedRequest,
} from "./fake-anthropic.js";
import type { AgentScenario, FakeToolInput, RunnerContext } from "./agent-scenario.js";
import { withoutPathDerivedNote } from "./conf-exfil.js";

/** The last tool_result's text as a model would carry it on: without the
 *  proxy's path-derived note (a shell read of a secret file, conf-exfil.ts
 *  PATH_DERIVED_NOTE_RE), which is proxy text after the symbol, never data. */
function lastToolResultText(r: ParsedRequest): string | null {
  const t = extractToolResultText(r);
  return t === null ? null : withoutPathDerivedNote(t);
}

/**
 * Sentinel for a scripted tool input: any top-level string value exactly equal
 * to this is replaced, at request time, with the text of the LAST tool_result
 * in that request.
 *
 * This exists because a step cannot know the symbol a previous step's result
 * was replaced with — and that is precisely the value a realistic follow-up
 * carries (the model writes back / sends on what it was given). On the defended
 * path the substituted text is the `$MDU:` token; if symbolization ever stopped
 * happening, the same script would carry RAW bytes, which the oracles then
 * catch. So the sentinel keeps the script honest rather than assuming an
 * outcome.
 */
export const LAST_TOOL_RESULT = "\u0000MDU_LAST_TOOL_RESULT\u0000";

/** Substitute LAST_TOOL_RESULT in a scripted tool input. Top-level string
 *  values only — no tool input needs deeper reach, and a shallow walk keeps the
 *  substitution auditable. */
function fillLastToolResult(
  input: FakeToolInput,
  lastToolResult: string | null,
): Record<string, unknown> {
  if (typeof input === "function") return input(lastToolResult);
  let touched = false;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(input)) {
    if (v === LAST_TOOL_RESULT) {
      touched = true;
      out[k] = lastToolResult ?? "";
    } else {
      out[k] = v;
    }
  }
  return touched ? out : input;
}

/** How many tool_result blocks a request body carries — the scripted model's
 *  turn counter. STRUCTURAL, not content-based (see startFakeUpstream). */
export function countToolResults(body: string): number {
  return body.split('"tool_result"').length - 1;
}

/** Build the scripted fake upstream for one scenario.
 *
 *  MATCHING IS MARKER/STRUCTURE-BASED, never content-based: on the wrapped side
 *  a tool_result arrives SYMBOLIZED, so matching on its content would make the
 *  script behave differently exactly when the defense is working. The turn
 *  counter is the NUMBER of tool_result blocks in the request, which is
 *  symbolization-invariant.
 *
 *  Step i fires when the request carries exactly i tool_results, so a scenario
 *  can drive a real multi-turn loop (read → send). Steps are NOT `once`: the
 *  count-based predicate is idempotent, so an agent retrying a request gets the
 *  same instruction instead of falling through to the terminator.
 *
 *  Step 0 additionally requires its tool to be ADVERTISED in the request's
 *  tools[] — the discriminator against OpenCode's title-generation side call,
 *  which carries neither tool_results nor the agent tool battery. */
export async function startFakeUpstream(
  s: AgentScenario,
  ctx: RunnerContext,
  workspaceFile: string,
  sinkOrigin: string,
): Promise<FakeAnthropic> {
  const finalText = s.fake?.finalText ?? "MDU_LIVE_DONE";
  assert.ok(
    !(s.fake?.toolUse && s.fake?.toolUses),
    `[${s.name}] fake.toolUse and fake.toolUses are mutually exclusive`,
  );
  const stepFns = s.fake?.toolUses ?? (s.fake?.toolUse ? [s.fake.toolUse] : []);
  const steps = stepFns
    .map((fn) => fn({ workspaceFile, provisioner: ctx.provisioner, sinkOrigin }))
    .filter((t): t is { name: string; input: FakeToolInput } => t !== null);

  return startScriptedAnthropic({
    script: [
      ...steps.map((tool, i) => ({
        match: (r: { hasToolResult: boolean; body: string }) =>
          countToolResults(r.body) === i &&
          // Only step 0 needs the advertised-tool discriminator; later steps are
          // already discriminated by the tool_result count.
          (i > 0 || r.body.includes(`"name":"${tool.name}"`)),
        respond: (r: ParsedRequest) =>
          toolUseTurn(
            `toolu_mdu_agent_${i + 1}`,
            tool.name,
            fillLastToolResult(tool.input, lastToolResultText(r)),
          ),
      })),
      // Every scripted step has run (or there were none) → end the turn.
      {
        match: (r: { hasToolResult: boolean; body: string }) =>
          steps.length === 0 ? !r.hasToolResult : countToolResults(r.body) >= steps.length,
        respond: (r: ParsedRequest) =>
          textTurn(typeof finalText === "function" ? finalText(lastToolResultText(r)) : finalText),
      },
    ],
    // Side calls (OpenCode's title generation) get a short ack.
    fallbackText: "MDU_LIVE_ACK",
  });
}
