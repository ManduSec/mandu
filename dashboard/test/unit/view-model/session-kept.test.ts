/**
 * session-kept — what Mandu kept from the AI in one session, and the line
 * the launcher prints when the session ends (dashboard.md §4.25ah,
 * view-model/session-kept.ts): the SAME counts Home counts the session by
 * (home-routes.ts `HomeFacts`, derived in the same call), Home's words and
 * plurals, the names behind them (at most three, "and N more"), the hosts
 * of the sends, the leak check and `off` saying no more than the record
 * holds, one short line when nothing came up, no control character from a
 * name, no inspector word, and never a value: a real value planted in the
 * record's originals appears in neither the facts nor the line. A record
 * Mandu could not check (every event a claim, or a launch that says its
 * agent was not walled off from Mandu's controls) never says "no secret came
 * up", and a claim never raises a count.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { ManduEvent } from "../../../src/event-model.js";
import { HomeFacts } from "../../../src/server/home-routes.js";
import { keptLine, keptName, nameList, plainName, sentHosts, KEPT_NAME_MAX, KEPT_UNCHECKED_LINE, type SessionKept } from "../../../src/view-model/session-kept.js";
import { recordUnchecked } from "../../../src/event-model.js";
import type { StoryTurn } from "../../../src/view-model/agent-page.js";
import { walkthroughEvents, PK, SESSION, type WalkOptions } from "./walkthrough-fixture.js";

const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|symbol|twin|placeholder|teardown|posture|discovery|token)\b|\$MDU/i;

/** A real-looking value planted in the record's human-side originals. */
const VALUE = "sk_" + "live_PLANTEDsessionKept0123456789";

/** The walkthrough with VALUE as the .env read's original (the human plane
 *  holds it there) and as its symbol's recorded value. */
function planted(o: WalkOptions = {}): ManduEvent[] {
  return walkthroughEvents(o).map((e) => {
    const out = (e as { output?: { symbols?: Array<{ name: string; value?: string | null }>; original?: string | null } }).output;
    if (e.kind !== "tool_result" || !out?.symbols?.some((s) => s.name === PK)) return e;
    return { ...e, output: { ...out, original: `PASTE_KEY=${VALUE}\nDEBUG=1`, symbols: out.symbols.map((s) => ({ ...s, value: VALUE })) } } as unknown as ManduEvent;
  });
}

async function factsOf(events: ManduEvent[], home = "/home/dev") {
  const facts = new HomeFacts({ readEvents: async () => events } as never, home);
  const f = await facts.ofId(SESSION);
  assert.ok(f && f.kept, "facts with what was kept");
  return f;
}

const kept = (p: Partial<SessionKept>): SessionKept => ({
  mode: "secrets", flagged: false,
  masked: { count: 0, names: [] }, early: { count: 0, names: [] }, unmasked: { count: 0, names: [] },
  blocked: 0, sent: { count: 0, names: [] }, unchecked: false, ...p,
});

test("the walkthrough: Home's counts, the names behind them, the hosts; one line in Home's words", async () => {
  const f = await factsOf(walkthroughEvents());
  const k = f.kept!;
  assert.equal(k.masked.count, f.secrets!.masked, "the masked count is the page's tile Home counts");
  assert.equal(k.early.count, f.secrets!.early);
  assert.equal(k.sent.count, f.sent, "the sends are Home's");
  assert.equal(k.blocked, f.blocked, "the blocks are Home's");
  assert.deepEqual(k.masked.names, ["the environment variable GITHUB_TOKEN", "PASTE_KEY in ~/app/.env"], "a file under the home folder as ~/…");
  assert.deepEqual(k.sent.names, ["api.github.com", "paste.example"]);
  assert.equal(
    keptLine(k),
    "mandu: in this session: 2 secrets masked before the AI saw them (the environment variable GITHUB_TOKEN and PASTE_KEY in ~/app/.env)" +
      " · 1 action blocked · 2 sends with a real value filled in (api.github.com and paste.example) · details: `mandu dashboard`",
  );
});

test("never a value: a real value planted in the record's originals is in neither the facts nor the line", async () => {
  for (const o of [{}, { mode: "off" as const }, { flagged: true }, { replyReveal: true }]) {
    const f = await factsOf(planted(o));
    const said = JSON.stringify(f.kept) + "\n" + keptLine(f.kept!);
    assert.ok(!said.includes(VALUE), `the planted value leaked (${JSON.stringify(o)}): ${said}`);
    assert.ok(!said.includes("PLANTED"), "not even a piece of it");
    assert.doesNotMatch(said, /\$MDU/, "nor a token");
  }
});

test("plurals: one of each in the singular; more than three names end with 'and N more'", () => {
  assert.equal(
    keptLine(kept({ masked: { count: 1, names: ["DB_PASSWORD in ~/proj/.env"] }, early: { count: 1, names: ["the file ~/notes.txt"] }, blocked: 1, sent: { count: 1, names: ["api.stripe.com"] } })),
    "mandu: in this session: 1 secret masked before the AI saw it (DB_PASSWORD in ~/proj/.env) · 1 secret the AI read before it was marked a secret (the file ~/notes.txt)" +
      " · 1 action blocked · 1 send with a real value filled in (api.stripe.com) · details: `mandu dashboard`",
  );
  assert.equal(
    keptLine(kept({ masked: { count: 14, names: ["A", "B", "C", "D"] }, early: { count: 2, names: [] }, blocked: 3, sent: { count: 5, names: ["a.example", "b.example"] } })),
    "mandu: in this session: 14 secrets masked before the AI saw them (A, B, C and 11 more) · 2 secrets the AI read before they were marked secrets" +
      " · 3 actions blocked · 5 sends with a real value filled in (a.example and b.example) · details: `mandu dashboard`",
    "a count past the names listed says how many more; a fact with no name known lists none; a send's hosts each once",
  );
  assert.equal(nameList(["a"], 1), " (a)");
  assert.equal(nameList(["a", "b"], 2), " (a and b)");
  assert.equal(nameList(["a", "b", "c"], 3), " (a, b and c)");
  assert.equal(nameList(["a", "b", "c"], 4), " (a, b, c and 1 more)");
  assert.equal(nameList([], 4), "");
});

test("nothing came up: one short line, not silence (a missing line means the line was off or could not be read)", async () => {
  assert.equal(keptLine(kept({})), "mandu: no secret came up in this session, so Mandu had nothing to mask");
  const quiet: ManduEvent[] = [{
    id: "q-0", sessionId: SESSION, turn: 0, ts: "2026-10-21T01:00:00.000Z", seq: 0, callId: null, parentId: null, kind: "launch_posture",
    view: "HumanView", boundary: "shell", emitter: "launcher", invariant: { violatedInvariant: false }, input: null, output: null,
    protection: { mode: "secrets", integrity: false, reported: true },
  } as unknown as ManduEvent];
  assert.equal(keptLine((await factsOf(quiet)).kept!), "mandu: no secret came up in this session, so Mandu had nothing to mask");
});

test("off (observe only): masked nothing; the secrets the record holds are named, never claimed as masked", async () => {
  const f = await factsOf(walkthroughEvents({ mode: "off", noNetwork: true }));
  assert.equal(f.secrets!.masked, 0, "Home counts none masked under off");
  assert.equal(f.kept!.masked.count, 0);
  assert.equal(
    keptLine(f.kept!),
    "mandu: protection was off this session (observe only), so Mandu did not mask 2 secrets (the environment variable GITHUB_TOKEN and PASTE_KEY in ~/app/.env)" +
      " · `mandu mode secrets` turns it on · details: `mandu dashboard`",
  );
  assert.equal(
    keptLine(kept({ mode: "off" })),
    "mandu: protection was off this session (observe only), so Mandu masked nothing · `mandu mode secrets` turns it on · details: `mandu dashboard`",
    "no secret on record: nothing claimed about what Secrets mode would have masked",
  );
});

test("a fired leak check claims nothing about what the AI saw", async () => {
  const f = await factsOf(walkthroughEvents({ flagged: true }));
  assert.equal(f.kept!.flagged, true);
  assert.equal(keptLine(f.kept!), "mandu: Mandu's leak check flagged this session, so Mandu cannot say what the AI saw · details: `mandu dashboard`");
});

test("a name is plain text: control characters cannot drive the terminal; a long one is cut", () => {
  assert.equal(plainName("evil\u001b[31m.env\r\nx\u0007"), "evil?[31m.env??x?");
  assert.equal(plainName("a b\u009bc"), "a?b?c");
  const long = plainName("x".repeat(300));
  assert.equal(long.length, KEPT_NAME_MAX);
  assert.ok(long.endsWith("…"));
  assert.equal(keptName([{ kind: "text", text: "The file " }, { kind: "code", text: "~/.aws/credentials" }]), "the file ~/.aws/credentials");
  assert.equal(keptName([{ kind: "code", text: "DB_PASSWORD" }, { kind: "text", text: " in " }, { kind: "code", text: "~/proj/.env" }]), "DB_PASSWORD in ~/proj/.env");
  assert.equal(keptName([{ kind: "code", text: "Token\u001b]0;pwn\u0007" }]), "Token?]0;pwn?", "a name that starts with code keeps its case");
  const turns = [{ steps: [
    { kind: "action", outcome: "sent", sentence: [{ kind: "text", text: "Sent a request to " }, { kind: "code", text: "api.example\u001b[2J" }] },
    { kind: "action", outcome: "blocked", sentence: [{ kind: "code", text: "evil.example" }] },
  ] }] as unknown as StoryTurn[];
  assert.deepEqual(sentHosts(turns), ["api.example?[2J"], "only sends, and their host as plain text");
});

/** `events` with every one stored as a claim (a launch with no wall,
 *  arbiter-human-plane.md §10.1). */
const allClaimed = (events: ManduEvent[]): ManduEvent[] => events.map((e) => ({ ...e, claimed: true }) as ManduEvent);
/** `events` whose launch says its agent was (`walled`) or was not walled off
 *  from the human plane (launch_posture.humanPlaneWalled). */
const walled = (events: ManduEvent[], w: boolean): ManduEvent[] =>
  events.map((e) => (e.kind === "launch_posture" ? ({ ...e, humanPlaneWalled: w }) as unknown as ManduEvent : e));

test("a record Mandu could not check, all claims: the line says so and where to read why, and counts nothing (dashboard.md §4.25ah)", async () => {
  assert.equal(
    KEPT_UNCHECKED_LINE,
    "mandu: Mandu could not check this session's record (on this computer the agent could reach Mandu's own controls), so it shows no count · why: `mandu doctor` and `mandu log`",
  );
  for (const o of [{}, { flagged: false }, { noNetwork: true }]) {
    const f = await factsOf(allClaimed(planted(o)));
    const k = f.kept!;
    assert.equal(k.unchecked, true, "every event a claim: unchecked");
    assert.deepEqual([k.masked.count, k.early.count, k.blocked, k.sent.count], [0, 0, 0, 0], "a claim never raises a count");
    assert.deepEqual(f.secrets, { masked: 0, early: 0 }, "Home's tiles count no claim either");
    const line = keptLine(k);
    assert.equal(line, KEPT_UNCHECKED_LINE);
    assert.doesNotMatch(line, /no secret came up|nothing to mask/, "never 'nothing came up' over a record Mandu could not check");
    assert.ok(!line.includes(VALUE) && !JSON.stringify(k).includes(VALUE), "never a value");
  }
});

test("mixed claims and believed events: the believed counts, unchanged words; a claim only takes a count away", async () => {
  const whole = (await factsOf(walkthroughEvents())).kept!;
  const mixed = (await factsOf(walkthroughEvents({ claimedBlock: true }))).kept!;
  assert.equal(mixed.unchecked, false, "some events believed, a walled launch: checked");
  assert.equal(whole.blocked, 1);
  assert.equal(mixed.blocked, 0, "the claimed block is not counted in the line");
  assert.equal(mixed.masked.count, whole.masked.count);
  assert.match(keptLine(mixed), /^mandu: in this session: 2 secrets masked before the AI saw them .* · details: `mandu dashboard`$/);
  assert.doesNotMatch(keptLine(mixed), /could not check/);
});

test("none claimed: the line is unchanged; a launch that says it was walled changes nothing", async () => {
  const plain = (await factsOf(walkthroughEvents())).kept!;
  const said = (await factsOf(walled(walkthroughEvents(), true))).kept!;
  assert.equal(plain.unchecked, false);
  assert.equal(said.unchecked, false);
  assert.equal(keptLine(said), keptLine(plain));
  assert.match(keptLine(plain), /^mandu: in this session: /);
});

test("a launch that says its agent was not walled off: no 'nothing came up'; believed counts still said, with the note", async () => {
  const quiet = walled(walkthroughEvents({ noNetwork: true }), false).filter((e) => e.kind === "launch_posture");
  assert.equal(quiet.length, 1);
  const q = (await factsOf(quiet)).kept!;
  assert.equal(q.unchecked, true);
  assert.equal(keptLine(q), KEPT_UNCHECKED_LINE);
  const f = (await factsOf(walled(walkthroughEvents(), false))).kept!;
  assert.equal(f.unchecked, true);
  assert.equal(f.masked.count, 2, "believed events still count");
  assert.equal(
    keptLine(f),
    "mandu: in this session: 2 secrets masked before the AI saw them (the environment variable GITHUB_TOKEN and PASTE_KEY in ~/app/.env)" +
      " · 1 action blocked · 2 sends with a real value filled in (api.github.com and paste.example)" +
      " · Mandu could not check the rest of this session's record (on this computer the agent could reach Mandu's own controls)" +
      " · why: `mandu doctor` and `mandu log` · details: `mandu dashboard`",
  );
  // The precedence stays: a fired leak check, then off.
  assert.match(keptLine(kept({ unchecked: true, flagged: true })), /leak check flagged/);
  assert.match(keptLine(kept({ unchecked: true, mode: "off" })), /protection was off/);
});

test("recordUnchecked: every event a claim, or a launch not walled off; never an empty record", () => {
  const ev = (o: Record<string, unknown>) => o as { claimed?: unknown; kind?: unknown };
  assert.equal(recordUnchecked([]), false, "no record: nothing to say about it");
  assert.equal(recordUnchecked([ev({ kind: "tllm_call" })]), false);
  assert.equal(recordUnchecked([ev({ kind: "tllm_call", claimed: true })]), true);
  assert.equal(recordUnchecked([ev({ kind: "tllm_call", claimed: true }), ev({ kind: "tool_result" })]), false, "mixed");
  assert.equal(recordUnchecked([ev({ kind: "launch_posture", humanPlaneWalled: false }), ev({ kind: "tllm_call" })]), true);
  assert.equal(recordUnchecked([ev({ kind: "launch_posture", humanPlaneWalled: true }), ev({ kind: "tllm_call" })]), false);
  assert.equal(recordUnchecked([ev({ kind: "launch_posture" }), ev({ kind: "tllm_call" })]), false, "an older launcher says nothing");
  assert.equal(recordUnchecked([ev({ kind: "tllm_call", humanPlaneWalled: false })]), false, "only the launch's own posture says it");
});

test("the words: none is an inspector term", () => {
  const lines = [
    KEPT_UNCHECKED_LINE,
    keptLine(kept({ unchecked: true, blocked: 1 })),
    keptLine(kept({ masked: { count: 2, names: ["a", "b"] }, early: { count: 1, names: ["c"] }, blocked: 1, sent: { count: 1, names: ["h"] } })),
    keptLine(kept({ masked: { count: 1, names: ["a"] } })),
    keptLine(kept({})),
    keptLine(kept({ mode: "off" })),
    keptLine(kept({ mode: "off", unmasked: { count: 1, names: ["a"] } })),
    keptLine(kept({ flagged: true })),
  ];
  for (const l of lines) {
    assert.doesNotMatch(l, FORBIDDEN, l);
    assert.match(l, /^mandu: /, "a launcher line");
    assert.ok(!l.includes("\n"), "one line");
  }
});
