/**
 * agentdojo-policy.test.ts — unit tests for the AgentDojo inbound trust spec.
 *
 * Mandu-new test (no reference origin). Exercises arbiter/policy/agentdojo-
 * inbound.ts — the re-map of the inbound trust vocabulary onto AgentDojo's tool
 * names (docs/design/testing/evaluation.md §2.4) — through the arbiter's classify()
 * contract, for each of the four suites:
 *   - third-party-influenceable outputs (received mail, reviews, transaction
 *     subjects, slack messages, webpages) → UNTRUSTED (symbolized before T-LLM)
 *   - user-owned state + action metadata (balance, IBAN, sent mail, send
 *     confirmations) → TRUSTED
 *   - the "fail-closed" spec symbolizes EVERY tool (the conservative bound)
 *   - the eval spec does NOT change the live default ("claude-code")
 *
 * A guard before/after restores the default so this suite can't leak its spec
 * switch into a sibling suite.
 *
 * Run: npm run test:integrity
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";

import { createEngineBackedPolicy } from "../../policy/policy-interface.js";
import {
  setActiveInboundSpec,
  getActiveInboundSpecId,
} from "../../policy/tool-inbound.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

before(() => setActiveInboundSpec("agentdojo"));
after(() => setActiveInboundSpec("claude-code"));

function policy() {
  return createEngineBackedPolicy();
}

/** classify a whole-result tool output. AgentDojo tool results are a single
 *  content blob, so — like the proxy's whole-result path — we classify with NO
 *  field (summarizeToolTrust resolves the literal root schema). */
function trustOf(tool: string): "TRUSTED" | "UNTRUSTED" {
  return policy().classify({
    tool,
    value: "some tool output",
    boundary: "model_context",
  }).trust;
}

test("selecting the agentdojo spec does not disturb the claude-code default id logic", () => {
  assert.equal(getActiveInboundSpecId(), "agentdojo");
});

// ── the untrusted-origin tools (the injection vectors) ─────────────────────

const UNTRUSTED_TOOLS = [
  // workspace — inbound mail / calendar / shared drive
  "get_unread_emails",
  "get_received_emails",
  "search_emails",
  "get_day_calendar_events",
  "search_calendar_events",
  "get_file_by_id",
  "list_files",
  "search_files",
  "search_files_by_filename",
  // workspace — echo-back action tools: return a PRE-EXISTING object (event/file
  // a third party may have authored), so the injection rides in the echoed object.
  // add_calendar_event_participants + delete_file are trust-gap-audit-proven
  // (eval/agentdojo/trust_gap_audit.py); reschedule_calendar_event + share_file
  // are the same echo-of-pre-existing-object class.
  "add_calendar_event_participants",
  "reschedule_calendar_event",
  "delete_file",
  "share_file",
  // travel — third-party reviews
  "get_rating_reviews_for_hotels",
  "get_rating_reviews_for_restaurants",
  "get_rating_reviews_for_car_rental",
  // banking — attacker-set transaction subjects + file content
  "get_most_recent_transactions",
  "get_scheduled_transactions",
  "read_file",
  // slack — messages from others + fetched webpages + attacker-set channel names
  "read_channel_messages",
  "read_inbox",
  "get_webpage",
  "get_channels", // AgentDojo plants the injection in a channel name (audit-proven)
];

for (const tool of UNTRUSTED_TOOLS) {
  test(`agentdojo: ${tool} output is UNTRUSTED (symbolized before T-LLM)`, () => {
    assert.equal(trustOf(tool), "UNTRUSTED");
  });
}

// ── the trusted tools (user-owned state / action metadata) ─────────────────

const TRUSTED_TOOLS = [
  // workspace
  "get_sent_emails",
  "get_draft_emails",
  "get_current_day",
  "search_contacts_by_name",
  "search_contacts_by_email",
  "send_email",
  "create_calendar_event",
  "create_file", // NEW user-authored object
  "cancel_calendar_event", // bare "Event <id> canceled" — echoes no fields
  "delete_email", // bare "Email <id> deleted" — echoes no fields
  // travel
  "get_user_information",
  "get_hotels_prices",
  "get_flight_information",
  "reserve_hotel",
  // banking
  "get_iban",
  "get_balance",
  "get_user_info",
  "send_money",
  // slack
  "get_users_in_channel",
  "send_direct_message",
  "post_webpage",
];

for (const tool of TRUSTED_TOOLS) {
  test(`agentdojo: ${tool} output is TRUSTED (user-owned / metadata)`, () => {
    assert.equal(trustOf(tool), "TRUSTED");
  });
}

// ── the fail-closed bound ──────────────────────────────────────────────────

test("fail-closed spec: every tool output — even a trusted-looking one — is UNTRUSTED", () => {
  setActiveInboundSpec("fail-closed");
  try {
    // A tool the calibrated spec marks TRUSTED must still be UNTRUSTED here.
    assert.equal(trustOf("get_balance"), "UNTRUSTED");
    assert.equal(trustOf("get_iban"), "UNTRUSTED");
    // And the always-untrusted vectors stay UNTRUSTED.
    assert.equal(trustOf("get_webpage"), "UNTRUSTED");
  } finally {
    setActiveInboundSpec("agentdojo");
  }
});

// ── the invariant: an UNLISTED tool fails closed ───────────────────────────

test("agentdojo: an unlisted tool fails closed to UNTRUSTED", () => {
  assert.equal(trustOf("some_tool_not_in_the_suite"), "UNTRUSTED");
});
