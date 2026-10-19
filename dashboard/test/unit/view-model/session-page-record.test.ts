/**
 * session-page-record.test — the product's session page (`/agents/<id>`,
 * dashboard.md §4.25b) tells each turn as it happened, over a recorded live
 * session (test/fixtures/tour-1791164083-1418381.ndjson, the first-session tour
 * of 2026-10-05; its secrets are fake and respelled). Turns:
 *   10:35 "What is in .env?"                 Read .env, STRIPE_KEY masked
 *   10:36 "Show me the lines of .env …"      no tool call
 *   10:38 "Use the Stripe key … with curl."  curl, its send blocked
 *   10:39 "I allowed it once … again."       curl, its send let out
 *   10:41 "What is in deploy/staging.conf?"  Read, returned AS IT WAS
 *   10:42 "Use Mandu's policy tools to mark deploy/staging.conf …"
 *                                            the label, then a Read, masked
 *   10:43 /exit
 *
 * Contracts:
 *   - a tool call sits under the question that caused it: the reply-filter's
 *     terminal repaints (turn-unaware, like the net side's records) never
 *     strand the next question behind the previous turn's call;
 *   - a result the AI read as it was says so at its own turn, with the moment
 *     later requests began carrying it masked; never "masked before the AI
 *     read it" (the history re-send after the label is not that turn's);
 *   - "Your secrets" says the AI read the file's real value before the label,
 *     both moments as times, and lists the file ONCE (two tokens, one file);
 *     never "only a placeholder" after the label: the AI's 10:41 reply quoted
 *     the file, and the next line says the AI's own words are not masked;
 *     under the person's home folder it names it `~/mandu-try/…`, as the
 *     tour's screenshot shows it, never with the account name;
 *   - each time on a "Your secrets" card opens the step it tells of (the
 *     10:38 block, the 10:39 send, the 10:41 Read), by the step's id; "from
 *     10:42 on", a model request, opens none, and without the page's steps
 *     (Home) no time does, in the same words;
 *   - the tiles count those two secrets by the same lines (1 masked from
 *     the start, 1 read before its label), the blocked send and the sent one;
 *   - Home's facts for the session (home-routes.ts `HomeFacts`, its row)
 *     count the same secrets, never the lineage's three masked tokens;
 *   - a session whose agent exited is not "running now", whatever the
 *     listing's recent-activity rule says;
 *   - the 10:38 curl's result, Mandu's refusal naming the placeholder the
 *     AI sent, is not "Secret hidden", and its turn says only what Mandu
 *     blocked, never "hid your secret";
 *   - the turns say of the file what its card says: the 10:41 summary names
 *     it, and at 10:42 (where the AI's reply says it never saw the file) the
 *     reply's line and every chip of the file say the AI read its real
 *     value at 10:41, never "never"; STRIPE_KEY's chips keep their claim,
 *     and a session whose leak check fired says neither.
 *
 * Axes: none (a pure projection; the mode is the session's recorded one).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import type { ManduEvent } from "../../../src/event-model.js";
import type { SessionRef } from "../../../src/event-source/contract.js";
import { toSessionViewModel } from "../../../src/view-model.js";
import { toDualLanes, type DualToolStep } from "../../../src/view-model/dual-lanes.js";
import { buildAgentPage, sessionExited, type StoryPart, type StoryTurn } from "../../../src/view-model/agent-page.js";
import { HomeFacts, readFirstLookup } from "../../../src/server/home-routes.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import { buildHomeViewModel } from "../../../src/view-model/home.js";
import type { PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";
import { earlyReads, secretsStory } from "../../../src/view-model/secret-story.js";
import type { EventSource } from "../../../src/event-source.js";

const ID = "1791164083-1418381";
const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "fixtures", `tour-${ID}.ndjson`);
const EVENTS = readFileSync(FIXTURE, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as ManduEvent);

/** The first Read of deploy/staging.conf (10:41), the label (10:42). */
const RAW_READ = "tool:toolu_01TsLEVYKVQrwjEgsbrZ1vEf";
const DELIVERED = "2026-10-05T01:41:29.686Z";
const MASKED_FROM = "2026-10-05T01:42:05.942Z";

const words = (parts: readonly StoryPart[] | null | undefined) =>
  (parts ?? []).map((p) => (p.kind === "masked" ? `[${p.name ?? p.text}]` : p.kind === "time" ? `<${p.text}>` : p.text)).join("");

function page(events: ManduEvent[] = EVENTS, session: SessionRef | null = null, home?: string) {
  const vm = toSessionViewModel(ID, events);
  return buildAgentPage({ session, id: ID, vm, cwd: null, waiting: [], events, believedVm: vm, ...(home !== undefined ? { home } : {}) });
}

function turn(story: StoryTurn[], prompt: RegExp): StoryTurn {
  const t = story.find((x) => x.prompt !== null && prompt.test(x.prompt));
  assert.ok(t, `a turn for ${prompt}: ${story.map((x) => x.prompt).join(" | ")}`);
  return t;
}

const actions = (t: StoryTurn) => t.steps.flatMap((s) => (s.kind === "action" ? [s] : []));

test("each tool call sits under the question that caused it, not the turn before", () => {
  const { story } = page();
  assert.deepEqual(story.map((t) => t.prompt?.slice(0, 24)), [
    "What is in .env?",
    "Show me the lines of .en",
    "Use the Stripe key in .e",
    "I allowed it once on the",
    "What is in deploy/stagin",
    "Use Mandu's policy tools",
  ]);
  // 10:36: answered from history, no tool call.
  assert.deepEqual(actions(turn(story, /^Show me the lines/)), []);
  // 10:38: the first curl and the block of its send.
  const ask = actions(turn(story, /^Use the Stripe key/));
  assert.deepEqual(ask.map((s) => s.id), ["tool:toolu_01P6KYMYqXT3w6qfrvV1aZfL", ask[1]!.id]);
  assert.match(words(ask[0]!.sentence), /^Ran curl -sS https:\/\/api\.stripe\.com\/v1\/customers -u '\[STRIPE_KEY\]:'/);
  assert.equal(ask[1]!.outcome, "blocked");
  // 10:39: the second curl and the send it let out.
  const again = actions(turn(story, /^I allowed it once/));
  assert.deepEqual(again.map((s) => s.id), ["tool:toolu_01Y4C8xBRgh4FkkEEQe9zRZ1", again[1]!.id]);
  assert.equal(again[1]!.outcome, "sent");
});

test("10:38: the curl got back Mandu's refusal naming the placeholder it sent; nothing in it was hidden from the AI", () => {
  const { story, blocked } = page();
  const t = turn(story, /^Use the Stripe key/);
  const [curl, block] = actions(t);
  // Its result: Mandu's fail-closed refusal, the placeholder in what the
  // tool returned as well as in what the AI got, and a refusal note.
  assert.equal(curl!.outcome, "plain", "not \"Secret hidden\"");
  assert.equal(curl!.split, null, "no halves: the AI got back what it sent");
  assert.equal(curl!.note, "The AI used the masked version of your secret, not its real value.");
  assert.equal(block!.outcome, "blocked");
  assert.equal(t.summary, "Mandu blocked 1 request that carried your secret STRIPE_KEY.");
  assert.equal(t.tone, "blocked");
  assert.equal(blocked, 1, "the tile counts the block once, as before");
  // 10:35's Read of .env did keep the value from the AI, and says so.
  const env = turn(story, /^What is in \.env\?/);
  const [read] = actions(env);
  assert.equal(read!.outcome, "secret");
  assert.equal(words(read!.split!.real), "The result held your secret STRIPE_KEY.");
  assert.equal(env.summary, "Mandu hid your secret STRIPE_KEY from the AI.");
});

test("the dual lanes record a result read as it was and masked only in later requests", () => {
  const steps = toDualLanes(EVENTS).steps;
  const read = steps.find((s) => s.id === RAW_READ) as DualToolStep;
  // What the AI received at its turn stays the record: no token.
  assert.doesNotMatch(read.resultAgent ?? "", /\$MDU:/);
  assert.deepEqual(read.maskedLater, { ts: MASKED_FROM, deliveredTs: DELIVERED, symbols: ["$MDU:nomodel_Read[1131]"] });
  // Masked from the start: never "masked later".
  const env = steps.find((s) => s.id === "tool:toolu_016AV1Ux6U1K1iPi9E7Mk554") as DualToolStep;
  assert.equal(env.maskedLater, undefined);
  const reread = steps.find((s) => s.id === "tool:toolu_01S67cvquU4VLUJG9ScHFyo6") as DualToolStep;
  assert.equal(reread.maskedLater, undefined);
});

test("10:41: the AI read the file as it was; masked from 10:42 on, after it was marked a secret", () => {
  const { story } = page();
  const t = turn(story, /^What is in deploy\/staging\.conf/);
  const [read] = actions(t);
  assert.equal(read!.id, RAW_READ);
  assert.equal(read!.outcome, "raw");
  assert.equal(read!.split, null, "nothing was kept from the AI at this turn");
  assert.equal(read!.note, "The AI got this as it was: nothing marked it a secret when it read it.");
  assert.equal(words(read!.later), `Masked from <${MASKED_FROM}> on, after it was marked a secret.`);
  assert.equal(t.tone, "raw");
  assert.equal(t.summary, "The AI read your secret staging.conf as it was: it was marked secret only later.");
  assert.deepEqual(t.summaryParts!.filter((p) => p.kind === "code").map((p) => p.text), ["staging.conf"], "named as code, as the steps name it");
  assert.doesNotMatch(t.summary ?? "", /masked 1 item|before the AI read it/);
  // 10:42: the Read after the label is masked, as it was.
  const after = actions(turn(story, /^Use Mandu's policy tools/));
  assert.equal(after.find((s) => s.id === "tool:toolu_01S67cvquU4VLUJG9ScHFyo6")!.outcome, "secret");
});

/** Every chip in a turn: its steps' sentences and halves, and its reply. */
function chipsOf(t: StoryTurn): StoryPart[] {
  const parts = t.steps.flatMap((s) => (s.kind === "action" ? [...s.sentence, ...(s.split ? [...s.split.ai, ...s.split.real] : [])] : s.kind === "said" ? s.parts : []));
  return [...parts, ...(t.reply ? [...t.reply.parts, ...(t.reply.ai ?? [])] : [])].filter((p) => p.kind === "masked");
}

test("10:42: the reply and every chip of the file say the AI read its real value at 10:41, as its card does; STRIPE_KEY's never", () => {
  const { story } = page();
  const t = turn(story, /^Use Mandu's policy tools/);
  // The AI's own words say it never saw the file; the page's line under them does not agree.
  assert.match(t.reply!.parts.map((p) => p.text).join(""), /Nothing from the file entered this conversation/);
  assert.equal(words(t.reply!.kept),
    `The reply held your secret staging.conf. The AI wrote it masked, and this page keeps it masked. The AI read its real value at <${DELIVERED}>, before it was marked a secret.`);
  const chips = chipsOf(t);
  assert.equal(chips.length, 3, "the Read's result and the two placeholders the reply names");
  assert.deepEqual(chips.map((p) => [p.text, p.early]), [["secret", DELIVERED], ["secret", DELIVERED], ["secret", DELIVERED]]);
  // STRIPE_KEY was masked from the start: its chips carry no early read, and its reply's line is as before.
  const stripe = story.filter((x) => x !== t).flatMap(chipsOf);
  assert.ok(stripe.length >= 4, stripe.length.toString());
  assert.ok(stripe.every((p) => p.early === undefined), JSON.stringify(stripe));
  assert.equal(words(turn(story, /^Show me the lines/).reply!.kept), "The reply held your secret STRIPE_KEY. The AI wrote it masked, and this page keeps it masked.");
});

test("earlyReads: the file's two tokens read at 10:41, STRIPE_KEY's none; where the card makes no such claim, none", () => {
  const vm = toSessionViewModel(ID, EVENTS);
  assert.deepEqual([...earlyReads(vm, false, "secrets")].sort(), [["$MDU:nomodel_Read[1131]", DELIVERED], ["$MDU:nomodel_Read[aa74]", DELIVERED]]);
  // The card's first line decides: a fired leak check, Off, no record.
  assert.equal(earlyReads(vm, true, "secrets").size, 0);
  assert.equal(earlyReads({ ...vm, invariant: { ...vm.invariant, holds: false } }, false, "secrets").size, 0);
  assert.equal(earlyReads(vm, false, "off").size, 0);
  assert.equal(earlyReads(null, false, "secrets").size, 0);
  // And it agrees with the cards it follows, in every mode.
  for (const mode of ["secrets", "off", null] as const) {
    const early = secretsStory(vm, EVENTS, false, mode).counts.early;
    assert.equal(earlyReads(vm, false, mode).size > 0, early > 0, String(mode));
  }
});

test("a session whose leak check fired: the card makes no claim about what the AI saw, and neither do the turns", () => {
  const vm = toSessionViewModel(ID, EVENTS);
  const flagged = { ...vm, invariant: { ...vm.invariant, holds: false } };
  const p = buildAgentPage({ session: null, id: ID, vm: flagged, cwd: null, waiting: [], events: EVENTS, believedVm: flagged });
  assert.ok(p.secrets.flagged);
  const t = turn(p.story, /^Use Mandu's policy tools/);
  assert.equal(words(t.reply!.kept), "The reply held your secret staging.conf. The AI wrote it masked, and this page keeps it masked.");
  assert.ok(p.story.flatMap(chipsOf).every((x) => x.early === undefined));
});

test("Your secrets: the file once, read as it was at 10:41, a placeholder from 10:42 on, and the AI's own words not masked", () => {
  const { secrets } = page();
  const names = secrets.secrets.map((s) => words(s.what));
  assert.deepEqual(names, ["STRIPE_KEY in /home/user/mandu-try/.env", "The file /home/user/mandu-try/deploy/staging.conf"]);
  const conf = secrets.secrets[1]!;
  const lines = conf.lines.map((l) => `${l.tone}: ${words(l.parts)}`);
  assert.equal(lines[0], `warn: The AI read its real value at <${DELIVERED}>, before it was marked a secret. From <${MASKED_FROM}> on it got a placeholder in its place, in 2 requests.`);
  // The AI's 10:41 reply quoted the file ("host = staging.example.com",
  // "token = \"FAKE-…\""), and the proxies forward its own replies as
  // written: never "only a placeholder" after the label.
  assert.equal(lines[1], "warn: Anything the AI wrote from its real value went back to the AI as written with each later request: Mandu does not mask the AI's own words.");
  assert.ok(!lines.some((l) => /never the real value|only a placeholder/.test(l)), lines.join("\n"));
  // The secret masked from the start keeps its claim, and no own-words line.
  assert.match(words(secrets.secrets[0]!.lines[0]!.parts), /^The AI got only a placeholder, never the real value\./);
  assert.ok(!secrets.secrets[0]!.lines.some((l) => /own words/.test(words(l.parts))));
});

test("Your secrets: each time opens its step under What happened: 10:38 the block, 10:39 the send, 10:41 the Read; \"from 10:42 on\" is a request, no step", () => {
  const p = page();
  const steps = new Map(p.story.flatMap((t) => t.steps.map((s) => [s.id, s] as const)));
  const times = p.secrets.secrets.flatMap((s) => s.lines.flatMap((l) => l.parts.filter((x) => x.kind === "time")));
  const opened = times.map((x) => {
    const s = x.step ? steps.get(x.step) : undefined;
    return `${x.text} -> ${s && s.kind === "action" ? `${s.outcome}: ${words(s.sentence)}` : "-"}`;
  });
  assert.deepEqual(opened, [
    "2026-10-05T01:38:07.123Z -> blocked: Mandu blocked a request to api.stripe.com that carried your secret STRIPE_KEY",
    "2026-10-05T01:39:24.292Z -> sent: Sent a request to api.stripe.com with your secret STRIPE_KEY filled in",
    `${DELIVERED} -> raw: Read staging.conf`,
    `${MASKED_FROM} -> -`,
  ]);
  assert.equal(times[2]!.step, RAW_READ, "the Read the AI got as it was");
  // The lines' words are the same as without steps (Home's call).
  const plain = secretsStory(toSessionViewModel(ID, EVENTS), EVENTS, false, "secrets");
  assert.deepEqual(p.secrets.secrets.map((s) => s.lines.map((l) => words(l.parts))), plain.secrets.map((s) => s.lines.map((l) => words(l.parts))));
  assert.ok(plain.secrets.every((s) => s.lines.every((l) => l.parts.every((x) => x.step === undefined))), "no steps given, no time opens one");
});

test("Your secrets: under the person's home folder the files read ~/mandu-try/.env and ~/mandu-try/deploy/staging.conf, counted the same", () => {
  const { secrets } = page(EVENTS, null, "/home/user");
  assert.deepEqual(secrets.secrets.map((s) => words(s.what)), ["STRIPE_KEY in ~/mandu-try/.env", "The file ~/mandu-try/deploy/staging.conf"]);
  assert.doesNotMatch(JSON.stringify(secrets), /\/home\/user/);
  assert.deepEqual(secrets.counts, page().secrets.counts);
});

test("the tiles count what the page shows: 1 secret masked from the start, 1 read before its label, 1 block, 1 send", () => {
  const vm = page();
  // The lineage has three flows (the file masked to two tokens); the page
  // tells two secrets, one of them read as it was before its label.
  assert.equal(vm.stats.flows, 3);
  assert.deepEqual(vm.secrets.counts, { masked: 1, early: 1 });
  assert.equal(vm.blocked, 1, "the first curl's send");
  assert.equal(vm.sent, 1, "the second curl's send, let out once");
});

test("Home's facts count the session's secrets as its page's tiles do: 1 masked, 1 read before its label, never 3", async () => {
  const source = { readEvents: async () => EVENTS } as unknown as EventSource;
  const listed = { id: ID, eventCount: EVENTS.length, firstTs: EVENTS[0]!.ts, lastTs: EVENTS[EVENTS.length - 1]!.ts } as SessionRef;
  const facts = await new HomeFacts(source).of(listed);
  assert.equal(facts.stats.flows, 3, "the lineage's three masked tokens");
  assert.deepEqual(facts.secrets, page().secrets.counts);
  assert.deepEqual(facts.secrets, { masked: 1, early: 1 });
  assert.equal(facts.untrusted, 0, "the Secrets mode masks no untrusted text");
  assert.deepEqual([facts.blocked, facts.sent], [page().blocked, page().sent]);
  // Under the page's home folder, the row still counts what the page shows.
  const homed = await new HomeFacts(source, "/home/user").of(listed);
  assert.deepEqual(homed.secrets, page(EVENTS, null, "/home/user").secrets.counts);
});

test("a waiting send of staging.conf, read at 10:41 before its label, never says the AI never read it; STRIPE_KEY's card keeps its claim (§4.34)", async () => {
  const source = { readEvents: async () => EVENTS } as unknown as EventSource;
  const listed = { id: ID, eventCount: EVENTS.length, firstTs: EVENTS[0]!.ts, lastTs: EVENTS[EVENTS.length - 1]!.ts, agent: "claude" } as SessionRef;
  const facts = new HomeFacts(source, "/home/user");
  assert.deepEqual([...(await facts.of(listed)).readFirst!], [["$MDU:nomodel_Read[1131]", DELIVERED]], "the 10:41 Read only");
  // The queue the arbiter would serve: a send of each secret this session
  // raised, one raised by a session not on record, and an answered one.
  const ask = (id: string, symbol: string, over: Partial<VerdictEntry> = {}): VerdictEntry => ({
    id, symbol, destination: "paste.example", status: "pending", reason: "secret symbol (no-model) at unbound destination",
    count: 1, firstSeen: 0, lastSeen: 0, resolvedAt: null, sessions: [ID], ...over,
  } as VerdictEntry);
  const verdicts = [
    ask("egr-file", "$MDU:nomodel_Read[1131]", { source: { tool: "Read", origin: "/home/user/mandu-try/deploy/staging.conf" } }),
    ask("egr-key", "$MDU:nomodel_Read[5c6e].STRIPE_KEY", { source: { tool: "Read", origin: "/home/user/mandu-try/.env" } }),
    ask("egr-gone", "$MDU:nomodel_Read[1131]", { sessions: ["1791000000-1"] }),
    ask("egr-done", "$MDU:nomodel_Read[1131]", { status: "denied", resolvedAt: 5 }),
  ];
  const early = await readFirstLookup(facts, async () => [listed])(verdicts);
  assert.deepEqual([...early], [["egr-file", DELIVERED]]);
  const snapshot = {
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] }, verdicts,
  } as PolicySnapshot;
  const panel = toPolicyPanelViewModel(snapshot, early);
  const row = (id: string) => panel.queue.find((r) => r.id === id)!;
  // The inspector's card (full path).
  assert.equal(row("egr-file").words.why, "Mandu masks it now, but the AI read its real value before it was marked a secret. Sending it would show the real secret to paste.example.");
  assert.match(row("egr-key").words.why ?? "", /^STRIPE_KEY comes from \/home\/user\/mandu-try\/\.env\. Mandu masked it, so the AI never read it\./);
  assert.match(row("egr-gone").words.aiNow ?? "", /never read the real one/, "a session not on record claims as before");
  // The product's card, over the same row.
  const home = buildHomeViewModel({
    sessions: [listed], facts: new Map([[ID, await facts.of(listed)]]), panel, configuredMode: "secrets",
    nowMs: Date.parse(listed.lastTs!), windowHours: 24, historyTotal: 1, home: "/home/user",
  });
  const card = home.waiting.find((a) => a.id === "egr-file")!;
  assert.equal(card.sentence.map((p) => p.text).join(""), "Claude Code wants to send a secret from ~/mandu-try/deploy/staging.conf to paste.example");
  assert.equal(card.aiNow, "The AI read the real value before it was marked a secret. Since then it gets the masked version, but Mandu does not mask what the AI wrote itself.");
  assert.doesNotMatch(JSON.stringify(home), /\$MDU:|FAKE-STAGING-TOKEN-0000|FAKE-STRIPE-KEY-0000/);
});

test("a program's waiting read of staging.conf, read at 10:41 before its label, never says the AI has not seen the file; one of .env keeps its words (§4.34)", async () => {
  const source = { readEvents: async () => EVENTS } as unknown as EventSource;
  const listed = { id: ID, eventCount: EVENTS.length, firstTs: EVENTS[0]!.ts, lastTs: EVENTS[EVENTS.length - 1]!.ts, agent: "claude" } as SessionRef;
  const facts = new HomeFacts(source, "/home/user");
  const conf = "/home/user/mandu-try/deploy/staging.conf";
  assert.deepEqual([...(await facts.of(listed)).readFirstFiles!], [[conf, DELIVERED]], "the 10:41 Read's file only, by its token's origin");
  // The queue the arbiter would serve: a program's read of each secret file
  // this session raised (the guard's held open, `open:`/`trust:`, its
  // destination the file), one raised by a session not on record, an
  // answered one, and a change to the file (not a read).
  const h = "c".repeat(64);
  const ask = (id: string, symbol: string, over: Partial<VerdictEntry> = {}): VerdictEntry => ({
    id, symbol, destination: conf, status: "pending", reason: "held for the human",
    count: 1, firstSeen: 0, lastSeen: 0, resolvedAt: null, sessions: [ID], ...over,
  } as VerdictEntry);
  const verdicts = [
    ask("open-conf", `open:/usr/bin/cat#${h}`),
    ask("trust-conf", `trust:/usr/local/bin/deploy#${h}`),
    ask("open-env", `open:/usr/bin/cat#${h}`, { destination: "/home/user/mandu-try/.env" }),
    ask("open-gone", `open:/usr/bin/cat#${h}`, { sessions: ["1791000000-1"] }),
    ask("open-done", `open:/usr/bin/cat#${h}`, { status: "approved", resolvedAt: 5 }),
    ask("write-conf", `write:/usr/bin/bash#${h}`),
  ];
  const early = await readFirstLookup(facts, async () => [listed])(verdicts);
  assert.deepEqual([...early].sort(), [["open-conf", DELIVERED], ["trust-conf", DELIVERED]]);
  const snapshot = {
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] }, verdicts,
  } as PolicySnapshot;
  const panel = toPolicyPanelViewModel(snapshot, early);
  const row = (id: string) => panel.queue.find((r) => r.id === id)!;
  assert.equal(row("open-conf").words.aiNow, "The AI read the file as it was before it was marked a secret, and its program /usr/bin/cat has not read it. Since then the AI gets the masked version, but Mandu does not mask what the AI wrote itself.");
  assert.match(row("trust-conf").words.aiNow ?? "", /^The AI read the file as it was before it was marked a secret, and its program \/usr\/local\/bin\/deploy has not read it\./);
  for (const id of ["open-env", "open-gone"]) assert.equal(row(id).words.aiNow, "The AI has not seen the real file, and its program /usr/bin/cat has not read it.", id);
  // The product's card, over the same row.
  const home = buildHomeViewModel({
    sessions: [listed], facts: new Map([[ID, await facts.of(listed)]]), panel, configuredMode: "secrets",
    nowMs: Date.parse(listed.lastTs!), windowHours: 24, historyTotal: 1, home: "/home/user",
  });
  const card = home.waiting.find((a) => a.id === "open-conf")!;
  assert.equal(card.sentence.map((p) => p.text).join(""), "Claude Code's program /usr/bin/cat wants to read a secret file: staging.conf");
  assert.equal(card.aiNow, row("open-conf").words.aiNow);
  assert.doesNotMatch(JSON.stringify(home), /\$MDU:|FAKE-STAGING-TOKEN-0000|FAKE-STRIPE-KEY-0000/);
});

test("the page never ships a token or a fake secret's value", () => {
  const json = JSON.stringify(page());
  assert.doesNotMatch(json, /\$MDU:/);
  assert.doesNotMatch(json, /FAKE-STAGING-TOKEN-0000|FAKE-STRIPE-KEY-0000/);
});

test("an exited session is not running now, whatever the listing says", () => {
  const listed: SessionRef = { id: ID, eventCount: EVENTS.length, firstTs: EVENTS[0]!.ts, lastTs: EVENTS[EVENTS.length - 1]!.ts, status: "running" } as SessionRef;
  assert.equal(sessionExited(EVENTS), true);
  assert.equal(page(EVENTS, listed).running, false);
  // Without the exit record, recent activity still reads as running.
  const live = EVENTS.filter((e) => e.kind !== "session_exit");
  assert.equal(sessionExited(live), false);
  assert.equal(page(live, listed).running, true);
  // Activity after an exit (a resumed session on the same log): running.
  const exit = EVENTS.find((e) => e.kind === "session_exit")!;
  const resumed = [...EVENTS, { ...EVENTS.find((e) => e.kind === "tllm_call")!, id: "ev_resumed", seq: 999, ts: "2026-10-05T01:50:00.000Z" }];
  assert.ok(exit.ts < "2026-10-05T01:50:00.000Z");
  assert.equal(sessionExited(resumed), false);
});
