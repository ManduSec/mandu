/**
 * session-kept — what Mandu kept from the AI in one session, and the line
 * the launcher prints when the session ends (dashboard.md §4.25ah,
 * view-model/session-kept.ts): the SAME counts Home counts the session by
 * (home-routes.ts `HomeFacts`, derived in the same call), Home's words and
 * plurals, the names behind them (at most three, "and N more"), the hosts
 * of the sends, the leak check and `off` saying no more than the record
 * holds, one short line when nothing came up, no control character from a
 * name, no inspector word, and never a value: a real value planted in the
 * record's originals appears in neither the facts nor the line.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { ManduEvent } from "../../../src/event-model.js";
import { HomeFacts } from "../../../src/server/home-routes.js";
import { keptLine, keptName, nameList, plainName, sentHosts, KEPT_NAME_MAX, type SessionKept } from "../../../src/view-model/session-kept.js";
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
  blocked: 0, sent: { count: 0, names: [] }, ...p,
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

test("the words: none is an inspector term", () => {
  const lines = [
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
