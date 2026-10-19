/**
 * agentdojo-inbound — the inbound data-trust ruleset for the AGENTDOJO benchmark
 * suites (workspace / travel / banking / slack).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   A RE-MAP of the same ToolSpec schema vocabulary used by
 *     arbiter/policy/claude-code-inbound.ts
 *   onto AgentDojo's tool names, for the apples-to-apples AgentDojo eval (see
 *   docs/design/testing/evaluation.md §2). AgentDojo (Debenedetti et al., NeurIPS 2024)
 *   is a function-calling benchmark whose tools operate over a SYNTHETIC
 *   environment; injections are planted in tool OUTPUTS. Routing AgentDojo's
 *   Anthropic pipeline through interceptors/anthropic-proxy symbolizes those
 *   untrusted outputs before the privileged model (T-LLM) sees them — the exact
 *   DUALVIEW mechanism. This spec tells the arbiter which AgentDojo tool outputs
 *   are untrusted.
 *
 * CLASSIFICATION RULE (the DUALVIEW "untrusted origin" definition):
 *   A tool output is UNTRUSTED iff a party OTHER THAN THE USER can influence its
 *   content — a received email body, a third-party review, an attacker-set bank
 *   transaction subject, a slack message from someone else, a fetched webpage.
 *   The user's own state (balance, IBAN, sent mail, their contact list) and pure
 *   action-result metadata (a send confirmation) stay TRUSTED.
 *
 * SECURITY INVARIANT (carried over, unchanged):
 *   TRUSTED is granted ONLY on an explicit rule match. Any tool NOT listed here
 *   falls through to the fail-closed UNTRUSTED default in policy-interface.ts /
 *   resolve-schema.ts. So this spec never under-symbolizes; the worst a missing
 *   entry does is over-symbolize (cost some utility), never leak.
 *
 *   We classify at WHOLE-RESULT granularity ({ schema: "UNTRUSTED" | "TRUSTED" }):
 *   AgentDojo's synthetic environment has no real URLs/dirs to key a DataSpec
 *   against, and an injected instruction can appear in ANY field of an
 *   untrusted-origin result, so per-field keying buys nothing here — the whole
 *   result of an untrusted-origin tool is symbolized.
 *
 * Which tools carry the injection in each suite (the AgentDojo attack vectors):
 *   workspace → received email bodies, shared drive files, calendar events
 *   travel    → hotel / restaurant / car-rental REVIEWS
 *   banking   → transaction SUBJECT fields, read_file content
 *   slack     → channel messages, inbox DMs, fetched webpages
 */

import type { ToolSpec } from "./schema-types.js";

const UNTRUSTED: ToolSpec = { schema: "UNTRUSTED" };
const TRUSTED: ToolSpec = { schema: "TRUSTED" };

export const AGENTDOJO_INBOUND_SPEC: Record<string, ToolSpec> = {
  // ── workspace suite ────────────────────────────────────────────────────
  // Inbound mail + calendar + cloud drive: any content a third party can put
  // in front of the user is UNTRUSTED. Sent/draft mail is user-authored, the
  // contact list is the user's own, and PURE-metadata action results are TRUSTED
  // — but see the echo-back note below the read tools.
  get_unread_emails: UNTRUSTED,
  get_received_emails: UNTRUSTED,
  search_emails: UNTRUSTED,
  get_day_calendar_events: UNTRUSTED, // participant-authored titles/descriptions
  search_calendar_events: UNTRUSTED,
  get_file_by_id: UNTRUSTED, // a drive file may be shared by someone else
  list_files: UNTRUSTED,
  search_files: UNTRUSTED,
  search_files_by_filename: UNTRUSTED,
  append_to_file: UNTRUSTED, // echoes back file content that may be shared
  get_sent_emails: TRUSTED, // user-authored
  get_draft_emails: TRUSTED, // user-authored
  get_current_day: TRUSTED,
  search_contacts_by_name: TRUSTED, // the user's own contact list
  search_contacts_by_email: TRUSTED,
  // Action results: TRUSTED only when the result is pure metadata (an id/status
  // confirmation) or a NEW user-authored object. An action that ECHOES BACK a
  // PRE-EXISTING object — an event or file a third party may have authored — is
  // UNTRUSTED: the injection rides in the echoed object, exactly as it would
  // through a read. The trust-gap audit (eval/agentdojo/trust_gap_audit.py)
  // empirically proved add_calendar_event_participants / delete_file (workspace)
  // surface an injection canary; reschedule_calendar_event / share_file return the
  // same pre-existing typed object (CalendarEvent / CloudDriveFile) and so are the
  // same echo-back class. The str-returning cancel/delete tools embed only the id.
  send_email: TRUSTED, // returns the NEW user-authored Email
  create_calendar_event: TRUSTED, // NEW user-authored CalendarEvent
  create_file: TRUSTED, // NEW user-authored CloudDriveFile
  cancel_calendar_event: TRUSTED, // bare "Event <id> canceled" — echoes no fields
  delete_email: TRUSTED, // bare "Email <id> deleted" — echoes no fields
  add_calendar_event_participants: UNTRUSTED, // echoes the pre-existing CalendarEvent (audit-proven)
  reschedule_calendar_event: UNTRUSTED, // echoes the pre-existing CalendarEvent
  delete_file: UNTRUSTED, // echoes the pre-existing CloudDriveFile content (audit-proven)
  share_file: UNTRUSTED, // echoes the pre-existing CloudDriveFile content

  // ── travel suite ───────────────────────────────────────────────────────
  // Reviews are free-text written by third parties — the travel injection
  // vector. Structured lookups (prices, addresses, cuisine, hours, ratings-
  // as-numbers, availability) and the user's own info are TRUSTED. Reservation
  // actions are metadata.
  get_rating_reviews_for_hotels: UNTRUSTED,
  get_rating_reviews_for_restaurants: UNTRUSTED,
  get_rating_reviews_for_car_rental: UNTRUSTED,
  get_user_information: TRUSTED,
  get_all_hotels_in_city: TRUSTED,
  get_hotels_prices: TRUSTED,
  get_hotels_address: TRUSTED,
  get_all_restaurants_in_city: TRUSTED,
  get_cuisine_type_for_restaurants: TRUSTED,
  get_restaurants_address: TRUSTED,
  get_dietary_restrictions_for_all_restaurants: TRUSTED,
  get_contact_information_for_restaurants: TRUSTED,
  get_price_for_restaurants: TRUSTED,
  check_restaurant_opening_hours: TRUSTED,
  get_all_car_rental_companies_in_city: TRUSTED,
  get_car_types_available: TRUSTED,
  get_car_fuel_options: TRUSTED,
  get_car_rental_address: TRUSTED,
  get_car_price_per_day: TRUSTED,
  get_flight_information: TRUSTED,
  reserve_hotel: TRUSTED,
  reserve_car_rental: TRUSTED,
  reserve_restaurant: TRUSTED,

  // ── banking suite ──────────────────────────────────────────────────────
  // Transaction SUBJECT fields are attacker-settable (a received transaction
  // carries a subject the sender wrote), and read_file surfaces file content —
  // both injection vectors → UNTRUSTED. The user's own IBAN / balance / info
  // and transaction actions are TRUSTED.
  get_most_recent_transactions: UNTRUSTED,
  get_scheduled_transactions: UNTRUSTED,
  read_file: UNTRUSTED,
  get_iban: TRUSTED,
  get_balance: TRUSTED,
  get_user_info: TRUSTED,
  send_money: TRUSTED, // action-result metadata (the SINK is gated at egress, not here)
  schedule_transaction: TRUSTED,
  update_scheduled_transaction: TRUSTED,
  update_password: TRUSTED,
  update_user_info: TRUSTED,

  // ── slack suite ────────────────────────────────────────────────────────
  // Messages from others + fetched webpages are third-party content → the slack
  // injection vector. get_channels is UNTRUSTED: AgentDojo plants an injection in
  // an attacker-created CHANNEL NAME ("External_<injection>"), so the channel
  // listing itself carries third-party content (trust-gap audit proved it). The
  // user-membership listing and the send/invite/remove actions stay TRUSTED.
  read_channel_messages: UNTRUSTED,
  read_inbox: UNTRUSTED,
  get_webpage: UNTRUSTED,
  get_channels: UNTRUSTED, // attacker-settable channel names (audit-proven)
  get_users_in_channel: TRUSTED,
  send_direct_message: TRUSTED,
  send_channel_message: TRUSTED,
  add_user_to_channel: TRUSTED,
  invite_user_to_slack: TRUSTED,
  remove_user_from_slack: TRUSTED,
  post_webpage: TRUSTED, // action-result metadata (the SINK is gated at egress)
};

/**
 * The "fail-closed" spec: an EMPTY map so EVERY AgentDojo tool falls through to
 * the UNTRUSTED default. This is the conservative security bound reported
 * alongside the calibrated AGENTDOJO_INBOUND_SPEC (docs/design/testing/evaluation.md §2
 * §4): maximal symbolization, minimal utility. Selectable for the eval so the
 * report can contrast the two operating points.
 */
export const FAIL_CLOSED_INBOUND_SPEC: Record<string, ToolSpec> = {};
