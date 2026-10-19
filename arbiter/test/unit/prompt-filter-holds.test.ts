/**
 * prompt-filter-holds.test — `ask` with the Inbox hold, and the per-finding
 * "let it through" (confidentiality-plan-15-prompt-filter.md §7, phase 3;
 * §13.6). Mandu-new.
 *
 * Proves, over the real engine, filters and approval store (in memory, a
 * fake clock):
 *   - the engine answers an `ask` with its DEFAULT applied: `mask` when a
 *     finding carries a level, `redact` otherwise; on harness text `ask` is a
 *     redaction (never held);
 *   - an attested caller that can wait gets `hold` (no text), one Inbox row
 *     per message whose reason never names the span; asking again keeps the
 *     row; past the deadline (or on the caller's last ask) the default goes
 *     and the row stays pending;
 *   - the answers: send (as written, this message only, or the session),
 *     mask (the default), cancel (refused once, then the default);
 *   - fail-closed: an unattested caller (the data socket), a request that
 *     cannot wait, no session, a span holding a registered value, and a
 *     segment that blocks anyway all take the default, file no row and (for
 *     the unattested caller) consult no verdict;
 *   - "let it through": a redacted or blocked finding goes as written once
 *     or for the session; never a registered value, never under a locked
 *     administrator's row;
 *   - under a LOCKED administrator's `ask` row (any row that covers the
 *     category) the human answers for this message only (§12, 2026-10-04):
 *     a session answer, a session let-through and an Always on the generic
 *     route are refused with the reason, never downgraded; a stored session
 *     verdict is not consulted; the listing says `onceOnly`; an unlocked
 *     administrator's `ask` keeps the session answer;
 *   - the references are keyed (not a plain hash of the span), stable per
 *     mandu.db;
 *   - NOTED MESSAGES (§13.7 item 10): a message answered an attested caller
 *     with a referenced finding is named by its turn on a later answer with
 *     none, its text unchanged; per session, human text only, the exact
 *     text (a look-alike or a reference written into the text matches
 *     nothing); never made or answered on the data socket or a dry run;
 *     kept in mandu.db across an arbiter restart, keyed (no session, text or
 *     turn in the file), bounded, oldest out (an evicted mark names no
 *     turn: the note is kept).
 *
 * Axes: secrets (stated).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PromptFilterEngine, type FilterPromptOutcome, type PromptPolicyInput, type PromptSegmentIn } from "../../prompt-filter/engine.js";
import { CANCEL_REASON, ONCE_ONLY_PHRASE, PromptHolds, parsePromptRow, sessionRefusal, type HoldContext } from "../../prompt-filter/holds.js";
import { RegisteredValueFilter } from "../../prompt-filter/registered-value-filter.js";
import { RegisteredValueIndex } from "../../prompt-filter/registered-values.js";
import { KeyShapesFilter } from "../../prompt-filter/key-shapes-filter.js";
import { PackFilter, parsePackText } from "../../prompt-filter/packs.js";
import { effectivePromptConfig, lockedAction, lockedAsk, type AdminPromptFilters, type PromptFiltersConfig } from "../../prompt-filter/policy.js";
import { EgressApprovalStore } from "../../policy/egress-approvals.js";
import { allocateSymbol, type SymbolMap } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const KEY = "Pw-Zq81Hc0vNw3PpL6tYbQ"; // registered
const CARD = "4111 1111 1111 1111";

const PACK = parsePackText(`pack: acme-dlp
version: 1
patterns:
  - id: card
    category: pii.payment-card
    regex: '\\b(?:\\d[ -]?){13,19}\\b'
    check: luhn
  - id: email
    category: pii.email
    regex: '[a-z0-9.]+@[a-z0-9.-]+\\.[a-z]{2,}'
  - id: token
    category: acme.token
    regex: 'token=\\S+'
keywords:
  - category: acme.codename
    words: [falcon, falconridgeproject]
    level: local-model
`);
if (!("doc" in PACK)) throw new Error(JSON.stringify(PACK));
const packFilter = new PackFilter({ doc: PACK.doc, source: "user", file: "/x/acme.yaml", signedBy: null, digest: "d1" });

const ON = { filters: { "acme-dlp": "on" as const } };

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function setup(cfg: PromptFiltersConfig, opts: { admin?: AdminPromptFilters[]; timeoutMs?: number } = {}) {
  const map: SymbolMap = { symbols: new Map() };
  const key = allocateSymbol(map, { tool: "env", value: KEY, confidentiality: "no-model" });
  const index = new RegisteredValueIndex();
  const policy: PromptPolicyInput = { config: effectivePromptConfig(cfg, opts.admin ?? []), packs: new Map([["acme-dlp", packFilter]]), packsDigest: "p1" };
  const engine = new PromptFilterEngine({
    filters: [new RegisteredValueFilter({
      index: () => { index.sync(map); return index; },
      rowLevel: (s) => {
        const e = map.symbols.get(s);
        return e && e.obsoleted_at === null && e.confidentiality !== "public" ? e.confidentiality : null;
      },
    }), new KeyShapesFilter()],
    policy: () => policy,
    enforcing: () => true,
    mint: (value, level) => allocateSymbol(map, { tool: "prompt_filter", value, confidentiality: level }),
    values: () => { index.sync(map); return { version: index.contentVersion, digest: index.digest }; },
  });
  let clock = 1_000_000;
  const now = () => clock;
  const approvals = new EgressApprovalStore({ now });
  const holds = new PromptHolds({ approvals, now, timeoutMs: opts.timeoutMs ?? 30_000 });
  const own = (s: string): boolean => map.symbols.get(s)?.tool === "prompt_filter";
  const run = async (segs: PromptSegmentIn[], ctx: Partial<HoldContext> = {}) =>
    holds.apply(await engine.run(segs, { session: "s1" }), segs, {
      session: "s1", live: true, attested: true, holds: true,
      config: engine.config(),
      // As the server: the filter's own masks are not registered secrets.
      holdsRegisteredValue: (t) => engine.holdsRegisteredValue(t, own),
      enforcedRegisteredIn: (t) => engine.enforcedRegisteredIn(t, "human", own),
      ...ctx,
    });
  return { engine, holds, approvals, key, run, advance: (ms: number) => { clock += ms; } };
}

const human = (text: string, id = "h"): PromptSegmentIn => ({ id, origin: "human", text });

test("the engine answers ask with its default: mask with a level, redact without; harness text is redacted", async () => {
  const { engine } = setup({ ...ON, actions: { "acme.codename": "ask", "pii.email": "ask" } });
  const out = await engine.run([human("ship falcon to bob@example.com"), { id: "r", origin: "harness", text: "<system-reminder>falcon</system-reminder>" }], { session: "s1" });
  const [h, r] = out.segments;
  assert.equal(h!.action, "rewrite");
  const codename = h!.findings.find((f) => f.category === "acme.codename")!;
  assert.equal(codename.action, "ask");
  assert.match(codename.symbol ?? "", /^\$MDU:/, "a finding with a level masks by default");
  const email = h!.findings.find((f) => f.category === "pii.email")!;
  assert.equal(email.action, "ask");
  assert.equal(email.symbol, undefined);
  assert.equal(h!.text, `ship ${codename.symbol} to [redacted: pii.email]`);
  assert.equal(r!.text, "<system-reminder>[redacted: acme.codename]</system-reminder>", "harness text is never held");
});

test("hold: one row per message, no span in it; asking again keeps it; past the deadline the default goes", async () => {
  const t = setup({ ...ON, actions: { "acme.codename": "ask" } });
  const msg = [human("ship falcon today")];
  const a = (await t.run(msg)).segments[0]!;
  assert.equal(a.action, "hold");
  assert.equal(a.text, undefined, "nothing of a held segment goes");
  assert.equal(a.hold!.timeoutMs, 30_000);
  const id = a.hold!.approvalId;
  assert.equal(a.findings[0]!.hold?.state, "pending");
  assert.match(a.findings[0]!.ref ?? "", /^[0-9a-f]{32}$/);
  assert.match(a.turn ?? "", /^[0-9a-f]{32}$/);
  const rows = t.approvals.list();
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.status, "pending");
  assert.ok(!rows[0]!.reason.includes("falcon") && !rows[0]!.symbol.includes("falcon") && !rows[0]!.destination.includes("falcon"), "the row (data plane) never names the span");
  assert.match(rows[0]!.reason, /acme\.codename/);
  const p = t.holds.pending(t.engine.config());
  assert.equal(p.length, 1);
  assert.equal(p[0]!.span, "falcon", "the Inbox card (human plane) shows the human's own text");
  assert.equal(p[0]!.fallback, "mask");
  t.advance(10_000);
  const b = (await t.run(msg)).segments[0]!;
  assert.equal(b.action, "hold");
  assert.equal(b.hold!.approvalId, id);
  assert.equal(b.hold!.timeoutMs, 20_000);
  assert.equal(t.approvals.list()[0]!.count, 1, "asking again files no new attempt");
  t.advance(20_000);
  const c = (await t.run(msg)).segments[0]!;
  assert.equal(c.action, "rewrite");
  assert.match(c.text!, /^ship \$MDU:\S+ today$/, "the default (mask) on timeout");
  assert.equal(c.findings[0]!.hold?.state, "timed-out");
  assert.equal(t.approvals.list()[0]!.status, "pending", "the row waits for an answer that applies to the next resend");
  // The caller's last ask (heldMs) never holds, even inside the deadline.
  const fresh = setup({ ...ON, actions: { "acme.codename": "ask" } });
  (await fresh.run(msg));
  const last = (await fresh.run(msg, { heldMs: 30_000 })).segments[0]!;
  assert.equal(last.action, "rewrite");
  assert.equal(last.findings[0]!.hold?.state, "timed-out");
});

test("send as written, once: this message (on every resend) goes raw; another message with the span asks again", async () => {
  const t = setup({ ...ON, actions: { "acme.codename": "ask" } });
  const msg = [human("ship falcon today")];
  const id = (await t.run(msg)).segments[0]!.hold!.approvalId;
  t.holds.answer(id, "send", "once", t.engine.config());
  for (let i = 0; i < 2; i++) {
    const s = (await t.run(msg)).segments[0]!;
    assert.equal(s.action, "pass", "as written");
    assert.equal(s.text, undefined);
    assert.equal(s.findings[0]!.let, "once");
    assert.equal(s.findings[0]!.hold?.state, "sent");
  }
  const other = (await t.run([human("and falcon again")])).segments[0]!;
  assert.equal(other.action, "hold", "a new message asks again");
});

test("send as written for the session: the span in a later message goes as written with no hold", async () => {
  const t = setup({ ...ON, actions: { "acme.codename": "ask" } });
  const id = (await t.run([human("ship falcon today")])).segments[0]!.hold!.approvalId;
  t.holds.answer(id, "send", "session", t.engine.config());
  const later = (await t.run([human("falcon status?")])).segments[0]!;
  assert.equal(later.action, "pass");
  assert.equal(later.findings[0]!.let, "session");
  const rows = t.approvals.list();
  assert.equal(rows.length, 2, "the message's row and the session's");
  assert.ok(rows.every((r) => r.status === "approved"));
  assert.ok(rows.some((r) => parsePromptRow(r)?.turn === undefined), "a session row");
});

test("send masked: the default; cancel: the waiting request is refused once, then the default", async () => {
  const t = setup({ ...ON, actions: { "acme.codename": "ask" } });
  const msg = [human("ship falcon today")];
  t.holds.answer((await t.run(msg)).segments[0]!.hold!.approvalId, "mask", "once", t.engine.config());
  const m = (await t.run(msg)).segments[0]!;
  assert.equal(m.action, "rewrite");
  assert.ok(!m.text!.includes("falcon"));
  assert.equal(m.findings[0]!.hold?.state, "masked");

  const c = setup({ ...ON, actions: { "acme.codename": "ask" } });
  c.holds.answer((await c.run(msg)).segments[0]!.hold!.approvalId, "cancel", "session", c.engine.config());
  const first = (await c.run(msg)).segments[0]!;
  assert.equal(first.action, "block");
  assert.equal(first.reason, CANCEL_REASON);
  assert.ok(!first.text!.includes("falcon"), "a cancelled segment's safe text carries the default");
  assert.equal(first.findings[0]!.hold?.state, "cancelled");
  const second = (await c.run(msg)).segments[0]!;
  assert.equal(second.action, "rewrite", "the resend carries the message with the default");
  assert.equal(c.approvals.list().length, 1, "a cancel covers this message only, never the session");
});

test("fail-closed: the data socket, a request that cannot wait, no session, a registered value inside, a blocking segment", async () => {
  const t = setup({ ...ON, actions: { "acme.codename": "ask", "acme.token": "ask", "pii.payment-card": "block" } });
  const msg = [human("ship falcon today")];
  // An approved verdict exists; the data socket consults none and files none.
  const id = (await t.run(msg)).segments[0]!.hold!.approvalId;
  t.holds.answer(id, "send", "session", t.engine.config());
  const data = (await t.run(msg, { attested: false })).segments[0]!;
  assert.equal(data.action, "rewrite");
  assert.ok(!data.text!.includes("falcon"), "an unattested caller never gets the span as written");
  assert.equal(data.findings[0]!.hold?.state, "default");
  const before = t.approvals.list().length;
  const other = (await t.run([human("falcon two")], { attested: false })).segments[0]!;
  assert.equal(other.action, "rewrite");
  assert.equal(t.approvals.list().length, before, "no row from the data socket");
  // Cannot wait; no session.
  const u = setup({ ...ON, actions: { "acme.codename": "ask" } });
  assert.equal((await u.run(msg, { holds: false })).segments[0]!.action, "rewrite");
  assert.equal((await u.run(msg, { session: undefined })).segments[0]!.action, "rewrite");
  assert.equal(u.approvals.list().length, 0);
  // A registered value inside the asked span: never held, never as written.
  const tok = (await t.run([human(`use token=${KEY} now`)])).segments[0]!;
  assert.equal(tok.action, "rewrite");
  assert.ok(!tok.text!.includes(KEY));
  assert.match(tok.findings.find((f) => f.action === "ask")!.hold?.why ?? "", /protects as a secret/);
  // The segment blocks anyway: the ask takes its default, no hold.
  const blk = (await t.run([human(`falcon and ${CARD}`)])).segments[0]!;
  assert.equal(blk.action, "block");
});

test("let it through: a redacted finding once or for the session; never a registered value; never under a lock", async () => {
  const t = setup({ ...ON, actions: { "pii.email": "redact", "pii.payment-card": "block" } });
  const msg = [human("mail bob@example.com")];
  const s = (await t.run(msg)).segments[0]!;
  assert.equal(s.text, "mail [redacted: pii.email]");
  const f = s.findings[0]!;
  t.holds.letThrough({ session: "s1", category: f.category, ref: f.ref, turn: s.turn, scope: "once" }, t.engine.config());
  const again = (await t.run(msg)).segments[0]!;
  assert.equal(again.action, "pass");
  assert.equal(again.findings[0]!.let, "once");
  assert.equal((await t.run([human("cc bob@example.com")])).segments[0]!.action, "rewrite", "once covers that message only");
  t.holds.letThrough({ session: "s1", category: f.category, ref: f.ref, scope: "session" }, t.engine.config());
  assert.equal((await t.run([human("cc bob@example.com")])).segments[0]!.action, "pass");
  assert.equal((await t.run([human("cc bob@example.com")], { session: "s2" })).segments[0]!.action, "rewrite", "a session verdict is that session's");
  // A blocked finding let through: the segment no longer blocks.
  const card = (await t.run([human(`pay ${CARD}`)])).segments[0]!;
  assert.equal(card.action, "block");
  t.holds.letThrough({ session: "s1", category: "pii.payment-card", ref: card.findings[0]!.ref, scope: "session" }, t.engine.config());
  const paid = (await t.run([human(`pay ${CARD}`)])).segments[0]!;
  assert.equal(paid.action, "pass");
  // Refusals.
  assert.throws(() => t.holds.letThrough({ session: "s1", category: "secret.registered", ref: "0".repeat(32), scope: "session" }, t.engine.config()), /registered secret/);
  assert.throws(() => t.holds.letThrough({ session: "s1", category: "pii.email", ref: "0".repeat(32), scope: "once" }, t.engine.config()), /once needs/);
  assert.throws(() => t.holds.letThrough({ session: "s1", category: "pii.email", ref: "not-a-ref", scope: "session" }, t.engine.config()), /reference/);
  const admin: AdminPromptFilters[] = [{ file: "/etc/mandu/policy.d/10-org.yaml", config: { actions: { "pii.payment-card": { action: "block", locked: true } } } }];
  const l = setup({ ...ON }, { admin });
  assert.deepEqual(lockedAction(l.engine.config(), "pii.payment-card"), { action: "block", file: "/etc/mandu/policy.d/10-org.yaml" });
  assert.throws(() => l.holds.letThrough({ session: "s1", category: "pii.payment-card", ref: "0".repeat(32), scope: "session" }, l.engine.config()), /set by your administrator/);
  // A verdict filed before the lock is not honoured under it.
  const lc = (await l.run([human(`pay ${CARD}`)])).segments[0]!;
  l.approvals.resolve(l.approvals.recordPending(`prompt:pii.payment-card#${lc.findings[0]!.ref}`, "model:s1", "x", "s1").id, true, "always");
  assert.equal((await l.run([human(`pay ${CARD}`)])).segments[0]!.action, "block");
});

const ORG = "/etc/mandu/policy.d/10-org.yaml";
const lockedAskAdmin = (category: string, locked = true): AdminPromptFilters[] => [{ file: ORG, config: { actions: { [category]: { action: "ask", locked } } } }];

test("a locked ask row: the hold takes this message only; every session answer is refused, the next message asks again", async () => {
  const t = setup({ ...ON }, { admin: lockedAskAdmin("acme.codename") });
  assert.deepEqual(lockedAsk(t.engine.config(), "acme.codename"), { file: ORG });
  const msg = [human("ship falcon today")];
  const id = (await t.run(msg)).segments[0]!.hold!.approvalId;
  const listed = t.holds.pending(t.engine.config());
  assert.equal(listed[0]!.onceOnly, true, "the Inbox listing says this message only");
  for (const answer of ["send", "mask", "cancel"] as const) {
    assert.throws(() => t.holds.answer(id, answer, "session", t.engine.config()), (e: Error) => e.message.includes("set acme.codename to ask every time") && e.message.includes(ORG) && e.message.endsWith(ONCE_ONLY_PHRASE));
  }
  assert.equal(t.approvals.list().length, 1, "a refused answer files nothing");
  assert.equal(t.approvals.list()[0]!.status, "pending", "a refused answer is not downgraded to once");
  // The generic route's Always would be a session answer: refused; its Allow once is not.
  assert.match(t.holds.genericRefusal(t.approvals.list()[0], "always", t.engine.config()) ?? "", /this message only/);
  assert.equal(t.holds.genericRefusal(t.approvals.list()[0], "once", t.engine.config()), null);
  // This message, as written: allowed, and only this message.
  t.holds.answer(id, "send", "once", t.engine.config());
  assert.equal((await t.run(msg)).segments[0]!.action, "pass");
  assert.equal((await t.run([human("falcon status?")])).segments[0]!.action, "hold", "the next message is held again");
  // Defensive: a resolve that slipped past the ops files no session verdict.
  const next = t.approvals.list().find((r) => r.status === "pending")!;
  const resolved = t.approvals.resolve(next.id, true, "always")!;
  t.holds.afterResolve(resolved, t.engine.config());
  assert.ok(!t.approvals.list().some((r) => parsePromptRow(r)?.turn === undefined), "no session row under a locked ask");
});

test("a locked ask row: a session verdict stored before the lock is not consulted; let it through once only", async () => {
  // Before the lock: the person answered for the session.
  const before = setup({ ...ON, actions: { "acme.codename": "ask" } });
  const id = (await before.run([human("ship falcon today")])).segments[0]!.hold!.approvalId;
  before.holds.answer(id, "send", "session", before.engine.config());
  assert.equal((await before.run([human("falcon status?")])).segments[0]!.action, "pass");
  // The same holds and store, the administrator's lock now in force.
  const t = setup({ ...ON }, { admin: lockedAskAdmin("acme.codename") });
  const holds = before.holds;
  const later = await holds.apply(await t.engine.run([human("falcon status?")], { session: "s1" }), [human("falcon status?")], {
    session: "s1", live: true, attested: true, holds: true, config: t.engine.config(),
    holdsRegisteredValue: async () => false, enforcedRegisteredIn: async () => false,
  });
  assert.equal(later.segments[0]!.action, "hold", "the stored session verdict is not honoured under the lock");
  assert.equal(later.segments[0]!.findings[0]!.let, undefined);
  // Let it through: once is allowed, the session is refused.
  const f = later.segments[0]!.findings[0]!;
  assert.throws(() => holds.letThrough({ session: "s1", category: f.category, ref: f.ref, scope: "session" }, t.engine.config()), new RegExp(ONCE_ONLY_PHRASE));
  holds.letThrough({ session: "s1", category: f.category, ref: f.ref, turn: later.segments[0]!.turn, scope: "once" }, t.engine.config());
});

test("mixed rows: a locked ask on a parent category counts under the person's own ask; an unlocked administrator's ask keeps the session answer", async () => {
  // The person's own `acme.codename: ask` decides the action; the locked
  // `acme: ask` above it still makes the hold this-message-only.
  const t = setup({ ...ON, actions: { "acme.codename": "ask" } }, { admin: lockedAskAdmin("acme") });
  const id = (await t.run([human("ship falcon today")])).segments[0]!.hold!.approvalId;
  assert.equal(t.holds.pending(t.engine.config())[0]!.onceOnly, true);
  assert.throws(() => t.holds.answer(id, "send", "session", t.engine.config()), new RegExp(ONCE_ONLY_PHRASE));
  assert.notEqual(sessionRefusal(t.engine.config(), "acme.token"), null, "the whole locked prefix");
  assert.equal(sessionRefusal(t.engine.config(), "pii.email"), null, "another category is not covered");
  // The administrator's ask, unlocked: a default the session answer may settle.
  const u = setup({ ...ON }, { admin: lockedAskAdmin("acme.codename", false) });
  const uid = (await u.run([human("ship falcon today")])).segments[0]!.hold!.approvalId;
  assert.equal(u.holds.pending(u.engine.config())[0]!.onceOnly, undefined);
  u.holds.answer(uid, "send", "session", u.engine.config());
  assert.equal((await u.run([human("falcon status?")])).segments[0]!.action, "pass");
  // A plain ask (no administrator): unchanged.
  assert.equal(sessionRefusal(effectivePromptConfig({ actions: { "acme.codename": "ask" } }, []), "acme.codename"), null);
});

test("a locked ask row: every referenced finding of the answer says onceOnly (held, answered, let through once, or masked by a narrower row); none otherwise", async () => {
  // Held: the finding the proxy records carries the lock next to its reference.
  const t = setup({ ...ON }, { admin: lockedAskAdmin("acme.codename") });
  const msg = [human("ship falcon today")];
  const held = (await t.run(msg)).segments[0]!;
  assert.equal(held.action, "hold");
  assert.match(held.findings[0]!.ref ?? "", /^[0-9a-f]{32}$/);
  assert.equal(held.findings[0]!.onceOnly, true, "the held finding says this message only");
  // Answered once: still flagged on the answer the proxy records next.
  t.holds.answer(held.hold!.approvalId, "send", "once", t.engine.config());
  const sent = (await t.run(msg)).segments[0]!;
  assert.equal(sent.findings[0]!.hold?.state, "sent");
  assert.equal(sent.findings[0]!.onceOnly, true);
  // A narrower row the person set (a tightening to block) decides the
  // action; the locked `acme: ask` above it still makes it this-message-only.
  const b = setup({ ...ON, actions: { "acme.codename": "block" } }, { admin: lockedAskAdmin("acme") });
  const blocked = (await b.run(msg)).segments[0]!;
  assert.equal(blocked.findings[0]!.action, "block");
  assert.equal(blocked.findings[0]!.onceOnly, true, "a block under a locked ask: let through once only");
  // No lock: no flag (an unlocked administrator's ask, the person's own ask, a mask).
  for (const u of [setup({ ...ON }, { admin: lockedAskAdmin("acme.codename", false) }), setup({ ...ON, actions: { "acme.codename": "ask" } }), setup({ ...ON, actions: { "acme.codename": "mask" } })]) {
    const f = (await u.run(msg)).segments[0]!.findings[0]!;
    assert.match(f.ref ?? "", /^[0-9a-f]{32}$/);
    assert.equal(f.onceOnly, undefined);
  }
});

test("a long span the filter masked by default (its own row) is still held and can go as written", async () => {
  const t = setup({ ...ON, actions: { "acme.codename": "ask" } });
  const msg = [human("ship falconridgeproject today")];
  const first = (await t.run(msg)).segments[0]!;
  assert.equal(first.action, "hold");
  assert.equal(first.findings[0]!.category, "acme.codename", "the pack's category leads the cluster, not its own mint's");
  const again = (await t.run(msg)).segments[0]!;
  assert.equal(again.action, "hold", "the default's own row does not count as a registered secret");
  t.holds.answer(first.hold!.approvalId, "send", "once", t.engine.config());
  const sent = (await t.run(msg)).segments[0]!;
  assert.equal(sent.action, "pass");
  assert.equal(sent.findings[0]!.let, "once");
  // The same with the default's row in place for a mask let through later.
  const m = setup({ ...ON, actions: { "acme.codename": "mask" } });
  const s1 = (await m.run([human("about falconridgeproject")])).segments[0]!;
  assert.equal(s1.action, "rewrite");
  const s2 = (await m.run([human("about falconridgeproject")])).segments[0]!;
  assert.equal(s2.findings[0]!.category, "acme.codename");
  m.holds.letThrough({ session: "s1", category: "acme.codename", ref: s2.findings[0]!.ref, scope: "session" }, m.engine.config());
  assert.equal((await m.run([human("about falconridgeproject")])).segments[0]!.action, "pass");
});

test("a registered value's own finding takes no reference and no verdict", async () => {
  const t = setup({ ...ON });
  const s = (await t.run([human(`the key is ${KEY}`)])).segments[0]!;
  assert.equal(s.action, "rewrite");
  assert.equal(s.findings[0]!.ref, undefined);
  assert.equal(s.turn, undefined);
});

test("references are keyed per mandu.db, never a plain hash of the span", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-prompt-holds-"));
  dirs.push(dir);
  const db = join(dir, "mandu.db");
  const a = new PromptHolds({ approvals: new EgressApprovalStore(), dbPath: db });
  const b = new PromptHolds({ approvals: new EgressApprovalStore(), dbPath: db });
  const c = new PromptHolds({ approvals: new EgressApprovalStore(), dbPath: join(dir, "other.db") });
  assert.equal(a.ref("falcon"), b.ref("falcon"), "stable across restarts");
  assert.notEqual(a.ref("falcon"), c.ref("falcon"));
  assert.ok(!createHash("sha256").update("falcon").digest("hex").startsWith(a.ref("falcon")));
  assert.notEqual(a.ref("falcon"), a.turn("falcon"));
});

// ── Noted messages (plan 15 §13.7 item 10, 2026-10-17) ──────────────────────
// The hold layer remembers, per session, each message it answered an
// attested caller with a referenced finding, and names that message's turn
// on a later answer with none, so a proxy that never saw the message (a
// restarted one) files the cleared outcome under the message's note.

const TICKET = "ACME-20417";
const SEEN = `see ${TICKET} today`;
const outcomeOf = (segs: PromptSegmentIn[], found: boolean): FilterPromptOutcome => ({
  enforcing: true, dryRun: false, digest: { policy: "p", packs: "k", values: "v" },
  segments: segs.map((s) => {
    const at = s.text.indexOf(TICKET);
    return found && at >= 0
      ? { id: s.id, origin: s.origin, action: "rewrite" as const, text: s.text.replace(TICKET, "[redacted: acme.ticket]"), findings: [{ start: at, end: at + TICKET.length, category: "acme.ticket", filterId: "acme-dlp", action: "redact" as const }], skipped: 0, cached: false }
      : { id: s.id, origin: s.origin, action: "pass" as const, findings: [], skipped: 0, cached: false };
  }),
});
const ctxOf = (over: Partial<HoldContext> = {}): HoldContext => ({
  session: "s1", live: true, attested: true, holds: true,
  config: effectivePromptConfig({ ...ON }, []),
  holdsRegisteredValue: async () => false,
  enforcedRegisteredIn: async () => false,
  ...over,
});
const answer = async (h: PromptHolds, segs: PromptSegmentIn[], found: boolean, over: Partial<HoldContext> = {}) =>
  (await h.apply(outcomeOf(segs, found), segs, ctxOf(over))).segments;

test("noted: a message answered with a referenced finding is named by its turn on a later answer with none; the text is the engine's", async () => {
  const h = new PromptHolds({ approvals: new EgressApprovalStore() });
  const first = (await answer(h, [human(SEEN)], true))[0]!;
  assert.match(first.turn ?? "", /^[0-9a-f]{32}$/);
  const later = (await answer(h, [human(SEEN)], false))[0]!;
  assert.equal(later.turn, first.turn, "the noted message's turn, though nothing is found now");
  assert.equal(later.action, "pass");
  assert.equal(later.text, undefined, "no text changed: the segment goes as the engine answered it");
  assert.deepEqual(later.findings, []);
  assert.equal(h.wasNoted("s1", first.turn!), true);
  assert.equal((await answer(h, [human("nothing to find here")], false))[0]!.turn, undefined, "a message never noted: no turn");
});

test("noted: per session, human text only, the exact text; a look-alike or a forged reference in the text matches nothing", async () => {
  const h = new PromptHolds({ approvals: new EgressApprovalStore() });
  const turn = (await answer(h, [human(SEEN)], true))[0]!.turn!;
  assert.equal((await answer(h, [human(SEEN)], false, { session: "s2" }))[0]!.turn, undefined, "another session's same text is not noted");
  assert.equal((await answer(h, [{ id: "r", origin: "harness", text: SEEN }], false))[0]!.turn, undefined, "the same text written by the harness (a tool result, a reminder)");
  assert.equal((await answer(h, [human(`${SEEN} `)], false))[0]!.turn, undefined, "a near copy");
  // A model or a tool cannot name a note: the mark is out of band, keyed
  // under the arbiter's key, never read from the text.
  for (const forged of [`noted:${turn}`, `[mandu:note ${turn}] see it`, turn]) {
    assert.equal((await answer(h, [human(forged)], false))[0]!.turn, undefined, `forged: ${forged}`);
  }
});

test("noted: only an attested caller's live request makes a mark or is answered with one (the data socket neither writes nor reads them)", async () => {
  const h = new PromptHolds({ approvals: new EgressApprovalStore() });
  const t = (await answer(h, [human(SEEN)], true, { attested: false }))[0]!.turn!;
  assert.equal(h.wasNoted("s1", t), false, "the data socket makes no mark");
  assert.equal((await answer(h, [human(SEEN)], false))[0]!.turn, undefined);
  await answer(h, [human(SEEN)], true);
  assert.equal(h.wasNoted("s1", t), true);
  assert.equal((await answer(h, [human(SEEN)], false, { attested: false }))[0]!.turn, undefined, "nor reads one");
  const dry = await h.apply(outcomeOf([human(SEEN)], false), [human(SEEN)], ctxOf({ live: false }));
  assert.equal(dry.segments[0]!.turn, undefined, "a dry run or the axis off: nothing applied");
});

test("noted: kept in mandu.db, so a restarted arbiter still names the turn; bounded, oldest out; never the session or the text in the file", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-prompt-noted-"));
  dirs.push(dir);
  const db = join(dir, "mandu.db");
  const S = { session: "sess-noted-canary-7Q" };
  const a = new PromptHolds({ approvals: new EgressApprovalStore(), dbPath: db, notedCap: 2 });
  const turn = (await answer(a, [human(SEEN)], true, S))[0]!.turn!;
  const b = new PromptHolds({ approvals: new EgressApprovalStore(), dbPath: db, notedCap: 2 });
  assert.equal((await answer(b, [human(SEEN)], false, S))[0]!.turn, turn, "the arbiter restarted: the mark survives");
  await answer(b, [human(`one ${TICKET}`)], true, S);
  await answer(b, [human(`two ${TICKET}`)], true, S);
  assert.equal((await answer(b, [human(SEEN)], false, S))[0]!.turn, undefined, "evicted (cap 2): the note is kept, never text dropped");
  const c = new PromptHolds({ approvals: new EgressApprovalStore(), dbPath: db, notedCap: 2 });
  assert.equal((await answer(c, [human(SEEN)], false, S))[0]!.turn, undefined, "the eviction reached the file");
  assert.ok((await answer(c, [human(`two ${TICKET}`)], false, S))[0]!.turn, "the newer marks are kept");
  const files = [db, `${db}-wal`].filter((f) => existsSync(f));
  const raw = files.map((f) => readFileSync(f).toString("latin1")).join("");
  assert.ok(!raw.includes(S.session) && !raw.includes(TICKET) && !raw.includes(turn), "the rows are keyed: no session, no text, no turn");
});
