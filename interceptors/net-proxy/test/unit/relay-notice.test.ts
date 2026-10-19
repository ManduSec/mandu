/**
 * relay-notice — the DevTools relay's refusals told to the browser agent's
 * model (src/relay-notice.ts, src/model-note.ts `editModelCall`;
 * devtools-relay.md §3.4): the wording per kind and cause, names and hosts
 * only (a field that fails the check is dropped, never quoted), one
 * message after the latest one, the note untouched, and a body the step
 * cannot read left as written with its refusals still pending.
 * Mandu-new (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { LEAVE_IT_OUT, NOTICE_ROLE, NOTICE_SPEAKER, appendRelayNotice, noticeReason, relayNoticeText, type RelayNotice } from "../../src/relay-notice.js";
import { editModelCall } from "../../src/model-note.js";

const MADE_UP = "$MDU:web_fetch[8c4f].text";
const SHOWN = "$MDU:nomodel_Read[8c4e].CARD_NUMBER";
const CARD = "4242424242424242";
const NOTE = "## Web pages\nfill the placeholder itself";
const JSON_HEADERS = { "content-type": "application/json" };
const unknown: RelayNotice = { kind: "unknown", page: "ledgerly.localhost", symbols: [MADE_UP], shown: [SHOWN] };

test("an unknown placeholder: the model is told it names nothing, to copy it from the page, and which ones the pages showed", () => {
  assert.equal(
    relayNoticeText([unknown]),
    `${NOTICE_SPEAKER}: your last attempt to type into a field on ledgerly.localhost typed nothing: ${MADE_UP} is not a placeholder Mandu knows. ` +
      `Copy the placeholder character for character from the page that shows the secret (the pages showed ${SHOWN}).`,
  );
});

test("a lookalike (malformed): the model is told what it typed is not a placeholder and which ones the pages showed, never quoting it", () => {
  const WALLET = "$MDU:nomodel_Read[5958].extract_1";
  assert.equal(
    relayNoticeText([{ kind: "malformed", page: "ledgerly.localhost", symbols: [], shown: [WALLET] }]),
    `${NOTICE_SPEAKER}: your last attempt to type into a field on ledgerly.localhost typed nothing: the text typed looks like a placeholder but is not one Mandu made. ` +
      `Copy the placeholder character for character from the page that shows the secret, never make one up (the pages showed ${WALLET}).`,
  );
  assert.match(noticeReason({ kind: "malformed", symbols: [] })!, /never make one up\.$/, "no shown ones, no list");
  // A forged one carrying free text in its fields: none of it is quoted.
  const forged = { kind: "malformed", page: `x/${CARD}`, symbols: [`$MDU:k[${CARD}]`], shown: [CARD, WALLET] } as unknown as RelayNotice;
  const text = relayNoticeText([forged])!;
  assert.ok(!text.includes(CARD), text);
  assert.match(text, /into a field typed nothing: .*\(the pages showed \$MDU:nomodel_Read\[5958\]\.extract_1\)\.$/);
});

test("a site that may not have the secret: leave it out, name it in words, go on; tell or ask the user only if they asked for it there", () => {
  // Live 2026-10-19 (the expense-report demo): the summary for the team
  // chat held the card's placeholder; told to ask the user, the model
  // stopped and never posted. The task never needed the card there.
  const r = (kind: RelayNotice["kind"], page?: string) => noticeReason({ symbols: [SHOWN], kind, ...(page !== undefined ? { page } : {}) });
  assert.equal(
    r("needs-approval", "huddle.localhost"),
    `huddle.localhost may not have the secret ${SHOWN} without the user's approval in Mandu. ` +
      "Unless the user asked for that secret to go to huddle.localhost, do not ask them: leave it out, write the rest without it " +
      '(name the secret in plain words if the text needs it, such as "the card" or "the API key", never its placeholder), and go on with the task. ' +
      "If they did ask for it there, ask them to approve it in Mandu, then type it again.",
  );
  assert.equal(
    r("not-allowed", "chat.localhost"),
    `chat.localhost may not have the secret ${SHOWN}. Do not type it there again: ${LEAVE_IT_OUT} ` +
      "Only if the user asked for that secret to go to chat.localhost, tell them Mandu does not let that site have it.",
  );
  assert.ok(r("needs-approval", "huddle.localhost")!.includes(LEAVE_IT_OUT));
  assert.match(r("needs-approval")!, /^this site may not have the secret .* to go to this site, do not ask them: leave it out/, "no host: this site");
  assert.match(r("not-allowed")!, /^this site may not have the secret /);
  // In the one message, after who speaks and where.
  assert.ok(relayNoticeText([{ kind: "needs-approval", page: "huddle.localhost", symbols: [SHOWN] }])!.startsWith(
    `${NOTICE_SPEAKER}: your last attempt to type into a field on huddle.localhost typed nothing: huddle.localhost may not have the secret ${SHOWN} without`));
});

test("each kind and cause in plain words", () => {
  const r = (n: Partial<RelayNotice>) => noticeReason({ symbols: [SHOWN], page: "chat.localhost", kind: "failed", ...n } as RelayNotice);
  assert.match(r({ kind: "not-allowed" })!, /^chat\.localhost may not have the secret \$MDU:.*leave it out.*tell them Mandu does not let that site have it\.$/);
  assert.match(r({ kind: "needs-approval" })!, /without the user's approval in Mandu.*leave it out.*then type it again\.$/);
  assert.match(r({ kind: "declined" })!, /the user chose to go on without .*finish the task without it/);
  for (const cause of ["no-field", "page-moved", "frame", "no-page", "page-refused", "unavailable"] as const) {
    assert.ok((r({ cause }) ?? "").length > 20, cause);
  }
  assert.match(r({ cause: "unavailable" })!, /Mandu could not check the placeholder just then/);
  assert.equal(r({ cause: undefined }), null, "a failed notice needs its cause");
  assert.equal(r({ kind: "nonsense" as never }), null);
  assert.match(noticeReason({ kind: "unknown", symbols: [MADE_UP, `${MADE_UP}x`] })!, / and \$MDU:\S+ are not placeholders Mandu knows\. Copy /);
});

test("names and hosts only: anything that is not one is dropped, never quoted", () => {
  const forged = [
    { kind: "unknown", symbols: [CARD], page: "ledgerly.localhost" },
    { kind: "unknown", symbols: [MADE_UP], shown: [CARD], page: `ledgerly.localhost/${CARD}` },
    { kind: "not-allowed", symbols: [`${SHOWN} ${CARD}`] },
    null,
  ] as unknown as RelayNotice[];
  const text = relayNoticeText(forged);
  assert.ok(text !== null && !text.includes(CARD), text ?? "");
  assert.match(text!, /your last attempt to type into a field typed nothing: \$MDU:web_fetch\[8c4f\]\.text is not a placeholder Mandu knows\. Copy .* the secret\.$/, "the bad host and the bad shown name dropped");
  assert.equal(relayNoticeText([forged[0]!]), null);
  assert.equal(relayNoticeText([]), null);
});

test("several refusals: one message, one line each", () => {
  const text = relayNoticeText([unknown, { kind: "not-allowed", page: "chat.localhost", symbols: [SHOWN] }])!;
  assert.ok(text.startsWith(`${NOTICE_SPEAKER}: your last 2 attempts to type a placeholder typed nothing:\n- into a field on ledgerly.localhost: `));
  assert.equal(text.split("\n").length, 3);
  assert.deepEqual(appendRelayNotice([{ role: "user", content: "x" }], text).at(-1), { role: NOTICE_ROLE, content: text });
});

const request = (extra: Record<string, unknown> = {}) => JSON.stringify({
  model: "google/gemini-2.5-flash",
  messages: [{ role: "system", content: "You are a browser agent." }, { role: "user", content: "Step 7: the page shows the form" }],
  ...extra,
});

test("editModelCall: the note first, the refusals last, everything else as written", async () => {
  let takes = 0;
  const r = await editModelCall(request({ temperature: 0 }), JSON_HEADERS, { note: async () => NOTE, relayNotices: async () => { takes++; return [unknown]; } });
  assert.equal(r.note, "added");
  assert.equal(r.relayNotices, 1);
  const out = JSON.parse(r.bodyText!);
  assert.deepEqual(out.messages[0], { role: "system", content: NOTE }, "the note, byte for byte, first");
  assert.deepEqual(out.messages.slice(1, 3), JSON.parse(request()).messages);
  assert.equal(out.messages.length, 4);
  assert.deepEqual(out.messages[3], { role: "user", content: relayNoticeText([unknown]) }, "after the latest message");
  assert.equal(out.temperature, 0);
  assert.equal(takes, 1);
});

test("editModelCall: no refusals pending, the body is the note's alone; the note gone, the refusals still go", async () => {
  const none = await editModelCall(request(), JSON_HEADERS, { note: async () => NOTE, relayNotices: async () => [] });
  assert.equal(none.relayNotices, 0);
  assert.equal(JSON.parse(none.bodyText!).messages.length, 3);

  const noNote = await editModelCall(request(), JSON_HEADERS, { note: async () => { throw new Error("down"); }, relayNotices: async () => [unknown] });
  assert.match(noNote.note, /^not added: the protection service did not give the note \(down\)/);
  assert.equal(noNote.relayNotices, 1);
  const msgs = JSON.parse(noNote.bodyText!).messages;
  assert.equal(msgs.length, 3);
  assert.equal(msgs[2].role, "user");

  const axesOff = await editModelCall(request(), JSON_HEADERS, { note: async () => "" });
  assert.deepEqual(axesOff, { note: "not added: no note (both protection axes off)", relayNotices: 0 }, "nothing changed: no body");
});

test("editModelCall: the arbiter failing to give the refusals sends the call without them (utility, not a gate)", async () => {
  const r = await editModelCall(request(), JSON_HEADERS, { note: async () => NOTE, relayNotices: async () => { throw new Error("connect ENOENT"); } });
  assert.equal(r.note, "added");
  assert.equal(r.relayNotices, 0);
  assert.equal(JSON.parse(r.bodyText!).messages.length, 3);
});

test("editModelCall: a body the step cannot read is left as written and its refusals are not taken", async () => {
  for (const [body, headers, why] of [
    [request(), { "content-encoding": "gzip" }, /a gzip body/],
    ["not json", JSON_HEADERS, /not a JSON body/],
    ["[1,2]", JSON_HEADERS, /not a JSON object/],
    [JSON.stringify({ input: "hi" }), JSON_HEADERS, /no messages array/],
  ] as const) {
    let takes = 0;
    const r = await editModelCall(body, headers, { note: async () => NOTE, relayNotices: async () => { takes++; return [unknown]; } });
    assert.equal(r.bodyText, undefined, String(why));
    assert.match(r.note, why);
    assert.equal(r.relayNotices, 0);
    assert.equal(takes, 0, "left pending for a call the step can read");
  }
});
