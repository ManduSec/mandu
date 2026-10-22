/**
 * secret-story.test — "Your secrets in this session" on the product's agent
 * page (dashboard.md §4.25b *Your secrets*). Contracts:
 *   - one entry per recorded secret, named by its variable or file, never by
 *     its token or its value;
 *   - each line follows from a recorded event: the AI's placeholder, the
 *     destinations Mandu filled the real value in for ("only" when nothing
 *     else was released), each blocked send, the reply that showed it;
 *   - the send line and each block line say when (the first, for more than
 *     one) and run in the order they happened, so a block and a later send
 *     to one host do not read as "allowed" above "blocked"; a time the
 *     record does not hold is not said, and then no order is guessed;
 *   - a time opens its step: the send's and each host's first block's time
 *     carry the id of the page's step that shows the event the time comes
 *     from (`tool:<call>` when the event names a call the page shows, else
 *     `os:<event>`), only when the page shows it; the words do not change;
 *   - a block or a stopped action whose own recorded event names the
 *     Approvals row it filed (`policy.approvalId`, the queue's id shape)
 *     says Mandu asked for your OK, the word a link to the earliest row
 *     ("for N of them" when only some did); a send never claims an ask or
 *     an answer;
 *   - a secret the AI read before its label (a tool step's `maskedLater`)
 *     says later requests carried a placeholder in its place, never "only a
 *     placeholder", and, when later requests went, that anything the AI
 *     wrote from the real value went back to it as written (the proxies do
 *     not mask the AI's own words); no other card says either;
 *   - no claim where the record cannot back one: a fired leak check says so,
 *     a claimed event makes no "blocked" line, a level that lets a model read
 *     it says that instead of "placeholder only", Off says nothing was masked;
 *   - the tag agrees with the card: each card carries its first line's
 *     answer (`saw`, the page colours the level's tag by it), and a read
 *     before the label carries since when the AI got a placeholder
 *     (`since`, the card's "From … on" moment); no other card has `since`;
 *   - the page's tiles count the secrets by the same first line (`counts`,
 *     every secret, listed or past the cap), never a secret read before its
 *     label as masked;
 *   - a file under the person's home folder is named `~/…`, never with the
 *     account name; one outside it (another account's too) as recorded.
 *
 * Axes: none (a pure projection; the mode is read from the recorded events).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildAgentPage } from "../../../src/view-model/agent-page.js";
import { aiSaw, FINDING_POINTER, releaseWhere, RELEASES_SHOWN, secretFile, secretsStory, secretShortName, secretWhat, SECRET_ALL_CAP, SECRET_CAP, type SecretsStory } from "../../../src/view-model/secret-story.js";
import { believedEvents, type ManduEvent } from "../../../src/event-model.js";
import { toSessionViewModel } from "../../../src/view-model.js";
import type { SymbolLineage } from "../../../src/view-model/lineage.js";
import type { DualStep } from "../../../src/view-model/dual-lanes.js";
import { walkthroughEvents, SESSION } from "./walkthrough-fixture.js";

const words = (parts: { text: string }[]) => parts.map((p) => p.text).join("");
const linesOf = (story: SecretsStory, i: number) => story.secrets[i]!.lines.map((l) => `${l.tone}: ${words(l.parts)}`);

function pageOf(events = walkthroughEvents(), home?: string) {
  const vm = toSessionViewModel(SESSION, events);
  const believed = believedEvents(events);
  return buildAgentPage({ session: null, id: SESSION, vm, cwd: null, waiting: [], events: believed, believedVm: toSessionViewModel(SESSION, believed), ...(home !== undefined ? { home } : {}) });
}

test("each secret by name, with where its real value went and what Mandu blocked", () => {
  const { secrets } = pageOf();
  assert.equal(secrets.mode, "secrets");
  assert.equal(secrets.flagged, false);
  assert.equal(secrets.secrets.length, 2);
  const [gh, pk] = secrets.secrets;
  assert.equal(words(gh!.what), "The environment variable GITHUB_TOKEN");
  assert.equal(gh!.level, "No AI");
  assert.deepEqual(linesOf(secrets, 0), [
    "good: The AI got only a placeholder, never the real value. It went to the AI that way in 5 requests.",
    // Each says when (a time part, the page draws the clock), in the order
    // they happened: the bound send, then the blocked exfiltration.
    "plain: Mandu sent its real value only to api.github.com (1 request, at 2026-10-04T13:10:06.000Z), where it was allowed to go.",
    "good: Mandu blocked 1 attempt to send it to collector.evil.example, at 2026-10-04T13:10:22.500Z. The request never left this machine.",
  ]);
  assert.deepEqual(gh!.lines[1]!.parts.filter((p) => p.kind === "time").map((p) => p.text), ["2026-10-04T13:10:06.000Z"]);
  assert.equal(words(pk!.what), "PASTE_KEY in /home/dev/app/.env");
  assert.match(linesOf(secrets, 1).join("\n"), /only to paste\.example \(1 request, at [0-9T:.Z-]+\)/);
  // Destinations and names are code, so the page draws them as code.
  assert.deepEqual(gh!.lines[1]!.parts.filter((p) => p.kind === "code").map((p) => p.text), ["api.github.com"]);
});

test("never a token or a value in the page's data", () => {
  const page = pageOf(walkthroughEvents({ replyReveal: true }));
  const json = JSON.stringify(page.secrets);
  assert.doesNotMatch(json, /\$MDU:/);
  assert.doesNotMatch(json, /f8d2|3fa9/, "not even the token's hash");
});

test("a secret Mandu never filled in says so; the reply that showed it to you is named", () => {
  const { secrets } = pageOf(walkthroughEvents({ noNetwork: true, replyReveal: true }));
  const gh = linesOf(secrets, 0);
  assert.ok(gh.includes("good: Mandu did not fill in its real value for any request off this machine."), gh.join("\n"));
  assert.ok(gh.includes("plain: You saw its real value in the agent's reply. The AI kept the placeholder."), gh.join("\n"));
  assert.ok(!gh.some((l) => /blocked/.test(l)));
});

test("a fired leak check: no claim about what the AI saw, for any secret", () => {
  const { secrets } = pageOf(walkthroughEvents({ flagged: true }));
  assert.equal(secrets.flagged, true);
  for (const s of secrets.secrets) {
    assert.equal(s.lines[0]!.tone, "bad");
    assert.match(words(s.lines[0]!.parts), /leak check flagged this session/);
    assert.ok(!s.lines.some((l) => /placeholder, never/.test(words(l.parts))));
  }
});

test("the lines that name the detailed trace carry it as a link part, a tab name and never an address (§4.25, *The page links the trace it names*)", () => {
  // A fired leak check: "Open the detailed trace" opens it.
  const { secrets } = pageOf(walkthroughEvents({ flagged: true }));
  for (const s of secrets.secrets) {
    assert.equal(words(s.lines[0]!.parts), "Mandu's leak check flagged this session, so this page cannot say what the AI saw. Open the detailed trace.");
    assert.deepEqual(s.lines[0]!.parts.filter((p) => p.trace), [{ kind: "text", text: "Open the detailed trace", trace: "trace" }]);
  }
  // A release after a check names where it went in every build (§4.25ae),
  // so no line links the trace for it; nothing names an address.
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const root = "$MDU:nomodel_Read[aaaa].STRIPE_KEY";
  const flow: SymbolLineage = {
    root, nodes: [],
    edges: [1, 2].map((i) => ({ from: `sym:${root}`, to: `snk:fs:/w/out-${i}.txt`, kind: "egress" as const, verdict: "approved" as const, eventId: `ev${i}`, seq: i })),
    summary: { root, originLabel: null, minted: true, contextTurns: 0, echoed: false, terminal: "context-only" },
  };
  const story = secretsStory({ ...vm, lineage: { ...vm.lineage, flows: [flow] } }, [], false, "secrets");
  const released = story.secrets[0]!.lines.find((l) => /released it/.test(words(l.parts)))!;
  assert.equal(words(released.parts), "Mandu released it 2 more times after a check: to a place its record does not name (2 times).");
  assert.equal(story.secrets[0]!.lines.flatMap((l) => l.parts).some((p) => p.trace), false);
  assert.doesNotMatch(JSON.stringify(story), /\/dev\//);
});

test("§4.25ae: each release after a check says where it went and when, in time order, its time opening the step that shows it; past RELEASES_SHOWN, how many more", () => {
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const root = "$MDU:nomodel_Read[aaaa].STRIPE_KEY";
  const ev = (id: string, ts: string, extra: Partial<ManduEvent> & Record<string, unknown>): ManduEvent =>
    ({ id, seq: 1, ts, turn: 2, kind: "egress_request", view: "HumanView", emitter: "arbiter", boundary: "network", sessionId: SESSION, callId: null, parentId: null, input: null, output: null, invariant: { violatedInvariant: false }, ...extra } as unknown as ManduEvent);
  const events = [
    ev("e2", "2026-09-25T10:05:00.000Z", { boundary: "shell", input: { symbolized: `run ${root}`, original: null, differs: true, symbols: [] } }),
    ev("e1", "2026-09-25T10:04:00.000Z", { input: { symbolized: `send ${root} to api.example.com:443`, original: null, differs: true, symbols: [] } }),
    ev("e3", "2026-09-25T10:06:00.000Z", { destination: "hooks.example.org" }),
  ];
  const flow = (ids: string[]): SymbolLineage => ({
    root, nodes: [],
    edges: ids.map((id, i) => ({ from: `sym:${root}`, to: `snk:egress:${id}`, kind: "egress" as const, verdict: "approved" as const, eventId: id, seq: i })),
    summary: { root, originLabel: null, minted: true, contextTurns: 0, echoed: false, terminal: "approved" },
  });
  const story = secretsStory({ ...vm, lineage: { ...vm.lineage, flows: [flow(["e2", "e1", "e3"])] } }, events, false, "secrets", "", new Set(["os:e1"]), undefined, { dev: false });
  const released = story.secrets[0]!.lines.find((l) => /released it/.test(words(l.parts)))!;
  assert.equal(words(released.parts),
    "Mandu released it 3 more times after a check: to api.example.com at 2026-09-25T10:04:00.000Z; in a command at 2026-09-25T10:05:00.000Z; to hooks.example.org at 2026-09-25T10:06:00.000Z.");
  // The host is code, each time a time part; the step the page shows opens.
  assert.deepEqual(released.parts.filter((p) => p.kind === "code").map((p) => p.text), ["api.example.com", "hooks.example.org"]);
  assert.deepEqual(released.parts.filter((p) => p.kind === "time").map((p) => p.step ?? null), ["os:e1", null, null]);
  // Never a token: the masked form names the host, not the item.
  assert.doesNotMatch(JSON.stringify(released), /\$MDU:/);

  // Past RELEASES_SHOWN: "; and N more".
  const many = Array.from({ length: RELEASES_SHOWN + 2 }, (_, i) => ev(`m${i}`, `2026-09-25T10:${String(10 + i).padStart(2, "0")}:00.000Z`, { destination: `h${i}.example.com` }));
  const long = secretsStory({ ...vm, lineage: { ...vm.lineage, flows: [flow(many.map((e) => e.id))] } }, many, false, "secrets", "", undefined, undefined, { dev: false });
  const line = words(long.secrets[0]!.lines.find((l) => /released it/.test(words(l.parts)))!.parts);
  assert.match(line, /^Mandu released it 7 more times after a check: to h0\.example\.com at /);
  assert.match(line, /; and 2 more\.$/);
  assert.equal(releaseWhere(undefined).map((p) => p.text).join(""), "to a place its record does not name");
});

test("without the developer view (§4.25ad, §4.25ae), no line names the detailed trace: a flagged session points at the page's own finding, and a release after a check says where", () => {
  const vm = toSessionViewModel(SESSION, walkthroughEvents({ flagged: true }));
  const flagged = secretsStory(vm, [], true, "secrets", "", undefined, undefined, { dev: false });
  assert.ok(flagged.secrets.length > 0);
  for (const s of flagged.secrets) {
    assert.deepEqual(s.lines[0], { tone: "bad", parts: [{ kind: "text", text: `Mandu's leak check flagged this session, so this page cannot say what the AI saw. ${FINDING_POINTER}` }] });
  }
  const plain = toSessionViewModel(SESSION, walkthroughEvents());
  const root = "$MDU:nomodel_Read[aaaa].STRIPE_KEY";
  const flow: SymbolLineage = {
    root, nodes: [],
    edges: [1, 2].map((i) => ({ from: `sym:${root}`, to: `snk:fs:/w/out-${i}.txt`, kind: "egress" as const, verdict: "approved" as const, eventId: `ev${i}`, seq: i })),
    summary: { root, originLabel: null, minted: true, contextTurns: 0, echoed: false, terminal: "context-only" },
  };
  const story = secretsStory({ ...plain, lineage: { ...plain.lineage, flows: [flow] } }, [], false, "secrets", "", undefined, undefined, { dev: false });
  assert.ok(story.secrets[0]!.lines.some((l) => words(l.parts) === "Mandu released it 2 more times after a check: to a place its record does not name (2 times)."));
  for (const x of [flagged, story]) {
    assert.equal(x.secrets.flatMap((s) => s.lines).flatMap((l) => l.parts).some((p) => p.trace), false);
    assert.doesNotMatch(JSON.stringify(x), /detailed trace|developer view/i);
  }
  // The page passes its build's answer down (buildAgentPage `dev`).
  const page = buildAgentPage({ session: null, id: SESSION, vm, cwd: null, waiting: [], dev: false });
  assert.doesNotMatch(JSON.stringify(page.secrets), /detailed trace/);
  assert.match(JSON.stringify(buildAgentPage({ session: null, id: SESSION, vm, cwd: null, waiting: [] }).secrets), /detailed trace/);
});

test("the page that asked for every secret (§4.25ad) lists them all, up to SECRET_ALL_CAP, and counts the same", () => {
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const flow = (i: number): SymbolLineage => {
    const root = `$MDU:nomodel_Env[${(0xa000 + i).toString(16)}].V${i}`;
    return { root, nodes: [], edges: [], summary: { root, originLabel: null, minted: true, contextTurns: 0, echoed: false, terminal: "dormant" } };
  };
  const many = { ...vm, lineage: { ...vm.lineage, flows: Array.from({ length: SECRET_CAP + 2 }, (_, i) => flow(i)) } };
  const capped = buildAgentPage({ session: null, id: SESSION, vm: many, cwd: null, waiting: [] });
  assert.equal(capped.secrets.secrets.length, SECRET_CAP);
  assert.equal(capped.secrets.more, 2);
  assert.equal("allSecrets" in capped, false);
  const all = buildAgentPage({ session: null, id: SESSION, vm: many, cwd: null, waiting: [], show: { secrets: true } });
  assert.equal(all.secrets.secrets.length, SECRET_CAP + 2);
  assert.equal(all.secrets.more, 0);
  assert.equal(all.allSecrets, true);
  assert.deepEqual(all.secrets.counts, capped.secrets.counts, "the tiles count every secret either way");
  // Past the ALL cap, the rest are counted.
  const huge = { ...vm, lineage: { ...vm.lineage, flows: Array.from({ length: SECRET_ALL_CAP + 1 }, (_, i) => flow(i)) } };
  const top = secretsStory(huge, [], false, "secrets", "", undefined, undefined, { cap: SECRET_ALL_CAP });
  assert.equal(top.secrets.length, SECRET_ALL_CAP);
  assert.equal(top.more, 1);
});

test("a claimed block (arbiter-human-plane.md §10.2) makes no \"blocked\" line", () => {
  const { secrets } = pageOf(walkthroughEvents({ claimedBlock: true }));
  const gh = linesOf(secrets, 0).join("\n");
  assert.doesNotMatch(gh, /blocked/);
  // Without the believed view-model (pure use) the full one is read.
  const events = walkthroughEvents({ claimedBlock: true });
  const vm = toSessionViewModel(SESSION, events);
  const believed = believedEvents(events);
  assert.equal(believed.length, events.length - 1);
  assert.doesNotMatch(linesOf(secretsStory(toSessionViewModel(SESSION, believed), believed, false, "secrets"), 0).join("\n"), /blocked/);
  assert.match(linesOf(secretsStory(vm, events, false, "secrets"), 0).join("\n"), /blocked/);
});

test("Off: nothing was masked, and no \"never filled in\" claim", () => {
  const { secrets } = pageOf(walkthroughEvents({ mode: "off", noNetwork: true }));
  assert.equal(secrets.mode, "off");
  const gh = linesOf(secrets, 0);
  assert.equal(gh[0], "warn: Protection was off, so Mandu did not mask it.");
  assert.ok(!gh.some((l) => /did not fill in/.test(l)));
});

test("a level that lets a model read it says so, not \"placeholder only\"", () => {
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const flow = (root: string): SymbolLineage => ({ root, nodes: [], edges: [], summary: { root, originLabel: null, minted: true, contextTurns: 2, echoed: false, terminal: "context-only" } });
  const story = secretsStory({ ...vm, lineage: { ...vm.lineage, flows: [flow("$MDU:anymodel_Env[aaaa].A"), flow("$MDU:localmodel_Env[bbbb].B")] } }, [], false, "secrets");
  assert.equal(story.secrets[0]!.level, "Any AI, when it asks");
  assert.deepEqual(linesOf(story, 0).slice(0, 1), ["plain: Its level lets the AI read it."]);
  assert.equal(story.secrets[1]!.level, "Your own AI only");
  assert.match(linesOf(story, 1)[0]!, /only your own model/);
});

/** One file the AI read as it was at `DELIVERED`, masked from `MASKED` on in
 *  `requests` later requests (a dual-lanes tool step's `maskedLater`, as the
 *  tour's `deploy/staging.conf`), at `prefix`'s level. */
const DELIVERED = "2026-10-05T01:41:29.686Z";
const MASKED = "2026-10-05T01:42:05.942Z";
function earlyStory(requests: number, opts: { prefix?: "nomodel" | "localmodel" | "anymodel"; flagged?: boolean; mode?: "secrets" | "off" | null; root?: string; origin?: string | null } = {}): SecretsStory {
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const root = opts.root ?? `$MDU:${opts.prefix ?? "nomodel"}_Read[cccc]`;
  const flow: SymbolLineage = { root, nodes: [], edges: [], summary: { root, originLabel: opts.origin === undefined ? "/srv/app/deploy/staging.conf" : opts.origin, minted: true, contextTurns: requests, echoed: false, terminal: "context-only" } };
  const read = { id: "tool:c-read", step: "tool", callId: "c-read", ts: DELIVERED, turn: 5, maskedLater: { ts: MASKED, deliveredTs: DELIVERED, symbols: [root] } } as unknown as DualStep;
  return secretsStory({ ...vm, dualLanes: { ...vm.dualLanes, steps: [read] }, lineage: { ...vm.lineage, flows: [flow] } }, [], opts.flagged ?? false, opts.mode === undefined ? "secrets" : opts.mode);
}
const OWN_WORDS = "warn: Anything the AI wrote from its real value went back to the AI as written with each later request: Mandu does not mask the AI's own words.";
const CHANGE_FILE = "warn: If it holds a key or a password, change it: the AI saw it as it was.";
const CHANGE_KEY = "warn: Change this key: the AI saw its real value, and marking it a secret does not take that back.";

test("a secret the AI read before its label: a placeholder in its place after, never \"only\", and the AI's own words are not masked (§4.25b)", () => {
  // The proxies forward the AI's own replies as written (confidentiality.md
  // §7.1, the residual): the tour's 10:41 reply quoted the file, and every
  // later request carried that reply beside the placeholder.
  assert.deepEqual(linesOf(earlyStory(2), 0), [
    `warn: The AI read its real value at ${DELIVERED}, before it was marked a secret. From ${MASKED} on it got a placeholder in its place, in 2 requests.`,
    OWN_WORDS,
    CHANGE_FILE,
    "good: Mandu did not fill in its real value for any request off this machine.",
  ]);
  assert.deepEqual(earlyStory(2).counts, { masked: 0, early: 1 }, "the tiles count it as read before its label");
  // No later request carried it: nothing went back to the AI, and the advice
  // follows the first line.
  assert.deepEqual(linesOf(earlyStory(0), 0).slice(0, 3), [
    `warn: The AI read its real value at ${DELIVERED}, before it was marked a secret. From ${MASKED} on it got a placeholder in its place.`,
    CHANGE_FILE,
    "good: Mandu did not fill in its real value for any request off this machine.",
  ]);
  // Your own model's level: its line after the advice.
  assert.deepEqual(linesOf(earlyStory(1, { prefix: "localmodel" }), 0).slice(1, 4), [
    OWN_WORDS,
    CHANGE_FILE,
    "plain: Its level lets only your own model read it. An outside AI gets a placeholder.",
  ]);
});

test("a secret the AI read before its label says to change it: a named key \"Change this key\", anything else \"If it holds a key or a password\" (§4.25b)", () => {
  // The kind comes from how the card names it (secretWhat's branch), never
  // from its words: a file's key and an environment variable are keys.
  const cases: [string, string, string | null, string, string][] = [
    ["a file", "$MDU:nomodel_Read[cccc]", "/srv/app/deploy/staging.conf", "The file /srv/app/deploy/staging.conf", CHANGE_FILE],
    ["a file's key", "$MDU:nomodel_Read[cccc].STRIPE_KEY", "/srv/app/.env", "STRIPE_KEY in /srv/app/.env", CHANGE_KEY],
    ["a key in a file not placed", "$MDU:nomodel_Read[cccc].STRIPE_KEY", null, "STRIPE_KEY in a file", CHANGE_KEY],
    ["an environment variable", "$MDU:nomodel_Env[cccc].GITHUB_TOKEN", null, "The environment variable GITHUB_TOKEN", CHANGE_KEY],
    ["a step's output", "$MDU:nomodel_Bash[cccc]", null, "Output of a Bash step that held a secret", CHANGE_FILE],
  ];
  for (const [what, root, origin, named, advice] of cases) {
    for (const requests of [0, 2]) {
      const story = earlyStory(requests, { root, origin });
      assert.equal(words(story.secrets[0]!.what), named, what);
      const lines = linesOf(story, 0);
      assert.equal(lines[requests > 0 ? 2 : 1], advice, `${what}, ${requests} requests: ${lines.join(" | ")}`);
      assert.equal(lines.filter((l) => l === CHANGE_FILE || l === CHANGE_KEY).length, 1, `${what}: one advice line`);
      assert.deepEqual(story.counts, { masked: 0, early: 1 }, `${what}: wording only, the tiles count the same`);
    }
  }
});

test("only a card that says the AI read the real value before its label says to change it", () => {
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const own: SymbolLineage = { root: "$MDU:localmodel_Env[bbbb].B", nodes: [], edges: [], summary: { root: "$MDU:localmodel_Env[bbbb].B", originLabel: null, minted: true, contextTurns: 2, echoed: false, terminal: "context-only" } };
  const cases: [string, SecretsStory][] = [
    ["a level that lets the AI read it", earlyStory(2, { prefix: "anymodel" })],
    ["a fired leak check", earlyStory(2, { flagged: true })],
    ["Off", earlyStory(2, { mode: "off" })],
    ["a key, a fired leak check", earlyStory(2, { flagged: true, root: "$MDU:nomodel_Read[cccc].STRIPE_KEY", origin: "/srv/app/.env" })],
    ["a key, Off", earlyStory(2, { mode: "off", root: "$MDU:nomodel_Read[cccc].STRIPE_KEY", origin: "/srv/app/.env" })],
    ["masked from the start", pageOf().secrets],
    ["your own model's level, masked from the start", secretsStory({ ...vm, lineage: { ...vm.lineage, flows: [own] } }, [], false, "secrets")],
  ];
  for (const [what, story] of cases) {
    assert.ok(story.secrets.length > 0, what);
    for (let i = 0; i < story.secrets.length; i++) {
      assert.ok(story.secrets[i]!.saw !== "early", what);
      assert.ok(!linesOf(story, i).some((l) => /change it|Change this key/.test(l)), `${what}: ${linesOf(story, i).join(" | ")}`);
    }
  }
});

test("the AI's own words line only on a card that says the AI read the real value before its label", () => {
  const cases: [string, SecretsStory][] = [
    ["a level that lets the AI read it", earlyStory(2, { prefix: "anymodel" })],
    ["a fired leak check", earlyStory(2, { flagged: true })],
    ["Off", earlyStory(2, { mode: "off" })],
    ["masked from the start", pageOf().secrets],
  ];
  for (const [what, story] of cases) {
    for (let i = 0; i < story.secrets.length; i++) {
      assert.ok(!linesOf(story, i).some((l) => /own words|before it was marked/.test(l)), `${what}: ${linesOf(story, i).join(" | ")}`);
    }
  }
});

test("the tag agrees with the card: each card carries its first line's answer, and a read before the label says since when (§4.25b)", () => {
  // The tour's staging.conf: a level's green tag above "The AI read its real
  // value" read as the opposite of the line under it.
  const early = earlyStory(2).secrets[0]!;
  assert.equal(early.saw, "early");
  assert.equal(early.since, MASKED, "the card's own \"From … on\" moment");
  assert.ok(linesOf(earlyStory(2), 0)[0]!.includes(`From ${MASKED} on`));
  assert.equal(earlyStory(0).secrets[0]!.since, MASKED, "no later request: still the moment it was masked from");
  // Your own model's level, read before its label: still early.
  assert.equal(earlyStory(1, { prefix: "localmodel" }).secrets[0]!.saw, "early");
  // Every other answer: the first line's, and never a `since`.
  const cases: [string, SecretsStory, string][] = [
    ["a level that lets the AI read it", earlyStory(2, { prefix: "anymodel" }), "readable"],
    ["a fired leak check", earlyStory(2, { flagged: true }), "flagged"],
    ["Off", earlyStory(2, { mode: "off" }), "off"],
    ["a fired leak check over the walkthrough", pageOf(walkthroughEvents({ flagged: true })).secrets, "flagged"],
    ["Off over the walkthrough", pageOf(walkthroughEvents({ mode: "off", noNetwork: true })).secrets, "off"],
    ["masked from the start", pageOf().secrets, "masked"],
  ];
  for (const [what, story, saw] of cases) {
    assert.ok(story.secrets.length > 0, what);
    for (const s of story.secrets) {
      assert.equal(s.saw, saw, what);
      assert.equal("since" in s, false, `${what}: no since`);
    }
  }
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const flow = (root: string): SymbolLineage => ({ root, nodes: [], edges: [], summary: { root, originLabel: null, minted: true, contextTurns: 2, echoed: false, terminal: "context-only" } });
  const levels = secretsStory({ ...vm, lineage: { ...vm.lineage, flows: [flow("$MDU:anymodel_Env[aaaa].A"), flow("$MDU:localmodel_Env[bbbb].B"), flow("$MDU:nomodel_Env[cccc].C")] } }, [], false, "secrets");
  assert.deepEqual(levels.secrets.map((s) => s.saw), ["readable", "own-model", "masked"]);
});

/** One secret whose sends and blocks are `edges`, each proved by an event
 *  (`ev<i>`) at its time (no time: no event recorded one) that names `ask`
 *  as its Approvals row and `callId` as its tool call; `gate`: an OS gate
 *  that decided a call using it, not a send. `steps`: the ids of the steps
 *  the page shows (absent: none, as on Home). */
function egressStory(edges: { host: string; verdict: "allowed" | "blocked"; ts?: string; ask?: unknown; gate?: boolean; callId?: string }[], steps?: ReadonlySet<string>): SecretsStory {
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const root = "$MDU:nomodel_Read[aaaa].STRIPE_KEY";
  const flow: SymbolLineage = {
    root,
    nodes: [],
    edges: edges.map((e, i) => e.gate
      ? { from: `sym:${root}`, to: `snk:exec:ev${i}`, kind: "gated" as const, verdict: e.verdict, eventId: `ev${i}`, seq: i + 1 }
      : { from: `sym:${root}`, to: `snk:net:${e.host}`, kind: "egress" as const, verdict: e.verdict, eventId: `ev${i}`, seq: i + 1 }),
    summary: { root, originLabel: null, minted: true, contextTurns: 0, echoed: false, terminal: "blocked" },
  };
  const events = edges.flatMap((e, i) => (e.ts ? [{ id: `ev${i}`, ts: e.ts, callId: e.callId ?? null, ...("ask" in e ? { policy: { usage: "deny", approvalId: e.ask } } : {}) } as unknown as ManduEvent] : []));
  return secretsStory({ ...vm, lineage: { ...vm.lineage, flows: [flow] } }, events, false, "secrets", "", steps);
}

/** Each time part of a card's lines, with the step it opens ("-": none). */
const timeSteps = (story: SecretsStory, i = 0) =>
  story.secrets[i]!.lines.flatMap((l) => l.parts.flatMap((p) => (p.kind === "time" ? [`${p.text} -> ${p.step ?? "-"}`] : [])));

test("a block and a later send to the same place read in the order they happened, each with its time", () => {
  // The tour: blocked at 10:38 (no rule let it go there), sent at 10:39
  // after the person allowed it once. Listed send-first, the card read
  // "allowed to go" above "blocked" for the same host.
  const story = egressStory([
    { host: "api.stripe.com", verdict: "allowed", ts: "2026-10-05T01:39:24.292Z" },
    { host: "api.stripe.com", verdict: "blocked", ts: "2026-10-05T01:38:07.123Z" },
  ]);
  assert.deepEqual(linesOf(story, 0), [
    "good: The AI got only a placeholder, never the real value.",
    "good: Mandu blocked 1 attempt to send it to api.stripe.com, at 2026-10-05T01:38:07.123Z. The request never left this machine.",
    "plain: Mandu sent its real value only to api.stripe.com (1 request, at 2026-10-05T01:39:24.292Z), where it was allowed to go.",
  ]);
  // The moments are time parts (the page draws the viewer's clock), the
  // hosts code.
  const [, block, send] = story.secrets[0]!.lines;
  assert.deepEqual(block!.parts.filter((p) => p.kind !== "text").map((p) => `${p.kind}:${p.text}`), ["code:api.stripe.com", "time:2026-10-05T01:38:07.123Z"]);
  assert.deepEqual(send!.parts.filter((p) => p.kind !== "text").map((p) => `${p.kind}:${p.text}`), ["code:api.stripe.com", "time:2026-10-05T01:39:24.292Z"]);
});

test("more than one send or block: the first time, and \"None of them left\"", () => {
  const story = egressStory([
    { host: "x.example", verdict: "blocked", ts: "2026-10-05T01:05:00.000Z" },
    { host: "a.example", verdict: "allowed", ts: "2026-10-05T01:03:00.000Z" },
    { host: "b.example", verdict: "allowed", ts: "2026-10-05T01:02:00.000Z" },
    { host: "x.example", verdict: "blocked", ts: "2026-10-05T01:01:00.000Z" },
    { host: "a.example", verdict: "allowed", ts: "2026-10-05T01:04:00.000Z" },
  ]);
  assert.deepEqual(linesOf(story, 0).slice(1), [
    "good: Mandu blocked 2 attempts to send it to x.example, the first at 2026-10-05T01:01:00.000Z. None of them left this machine.",
    "plain: Mandu sent its real value only to a.example and b.example (3 requests, the first at 2026-10-05T01:02:00.000Z), where it was allowed to go.",
  ]);
  // Blocks only: after "did not fill in", as before, in their own order.
  const blocks = egressStory([
    { host: "late.example", verdict: "blocked", ts: "2026-10-05T01:09:00.000Z" },
    { host: "early.example", verdict: "blocked", ts: "2026-10-05T01:01:00.000Z" },
  ]);
  assert.deepEqual(linesOf(blocks, 0).slice(1), [
    "good: Mandu did not fill in its real value for any request off this machine.",
    "good: Mandu blocked 1 attempt to send it to early.example, at 2026-10-05T01:01:00.000Z. The request never left this machine.",
    "good: Mandu blocked 1 attempt to send it to late.example, at 2026-10-05T01:09:00.000Z. The request never left this machine.",
  ]);
});

test("a time the record does not hold is not said, and no order is guessed", () => {
  // The block's event is not in the record: its line has no time, and the
  // lines keep the order they always had (the send first).
  const story = egressStory([
    { host: "api.stripe.com", verdict: "blocked" },
    { host: "api.stripe.com", verdict: "allowed", ts: "2026-10-05T01:39:24.292Z" },
  ]);
  assert.deepEqual(linesOf(story, 0).slice(1), [
    "plain: Mandu sent its real value only to api.stripe.com (1 request, at 2026-10-05T01:39:24.292Z), where it was allowed to go.",
    "good: Mandu blocked 1 attempt to send it to api.stripe.com. The request never left this machine.",
  ]);
  // One send of two without a time: "the first at" would guess, so no time.
  const sends = egressStory([
    { host: "a.example", verdict: "allowed", ts: "2026-10-05T01:03:00.000Z" },
    { host: "a.example", verdict: "allowed" },
  ]);
  assert.equal(linesOf(sends, 0)[1], "plain: Mandu sent its real value only to a.example (2 requests), where it was allowed to go.");
  // An unreadable time is no time.
  const bad = egressStory([{ host: "a.example", verdict: "blocked", ts: "not a time" }]);
  assert.equal(linesOf(bad, 0).at(-1), "good: Mandu blocked 1 attempt to send it to a.example. The request never left this machine.");
});

test("a block whose event names the Approvals row it filed says Mandu asked for your OK, linking that row; a send never does (§4.25b)", () => {
  // The tour: the 10:38 block queued egr-1, and the person allowed it once.
  // The 10:39 send's event records no answer, so its line claims none.
  const story = egressStory([
    { host: "api.stripe.com", verdict: "blocked", ts: "2026-10-05T01:38:07.123Z", ask: "egr-1" },
    { host: "api.stripe.com", verdict: "allowed", ts: "2026-10-05T01:39:24.292Z", ask: "egr-2" },
  ]);
  assert.deepEqual(linesOf(story, 0).slice(1), [
    "good: Mandu blocked 1 attempt to send it to api.stripe.com, at 2026-10-05T01:38:07.123Z, and asked for your OK in Approvals. The request never left this machine.",
    "plain: Mandu sent its real value only to api.stripe.com (1 request, at 2026-10-05T01:39:24.292Z), where it was allowed to go.",
  ]);
  const [, block, send] = story.secrets[0]!.lines;
  assert.deepEqual(block!.parts.filter((p) => p.ask), [{ kind: "text", text: "Approvals", ask: "egr-1" }], "the word links the row");
  assert.equal(send!.parts.some((p) => p.ask), false, "a send claims no ask, and no answer");
});

test("a send claims no standing permission: \"where it was allowed to go\", never \"is allowed\", and it names no OK (§4.25b)", () => {
  // The tour: the 10:38 block queued egr-1, and the 10:39 send went out on
  // the person's one-time OK. The present tense ("where it is allowed to
  // go") told that OK as a permission that still held; the send's event
  // records neither a rule nor an answer, so the line claims neither.
  const once = egressStory([
    { host: "api.stripe.com", verdict: "blocked", ts: "2026-10-05T01:38:07.123Z", ask: "egr-1" },
    { host: "api.stripe.com", verdict: "allowed", ts: "2026-10-05T01:39:24.292Z" },
  ]);
  // A send under a rule alone (a binding), with no block: the same words.
  const bound = egressStory([{ host: "api.github.com", verdict: "allowed", ts: "2026-10-04T13:10:06.000Z" }]);
  const sendOf = (story: SecretsStory) => linesOf(story, 0).filter((l) => / sent its real value /.test(l));
  assert.deepEqual(sendOf(once), ["plain: Mandu sent its real value only to api.stripe.com (1 request, at 2026-10-05T01:39:24.292Z), where it was allowed to go."]);
  assert.deepEqual(sendOf(bound), ["plain: Mandu sent its real value only to api.github.com (1 request, at 2026-10-04T13:10:06.000Z), where it was allowed to go."]);
  for (const l of [...sendOf(once), ...sendOf(bound)]) assert.doesNotMatch(l, /is allowed|still|OK|Approvals|answer/);
});

test("several blocks: \"asked\" when each filed a row, \"for N of them\" when some did; the link is the earliest row", () => {
  const all = egressStory([
    { host: "x.example", verdict: "blocked", ts: "2026-10-05T01:05:00.000Z", ask: "egr-2" },
    { host: "x.example", verdict: "blocked", ts: "2026-10-05T01:01:00.000Z", ask: "egr-1" },
  ]);
  assert.equal(linesOf(all, 0).at(-1), "good: Mandu blocked 2 attempts to send it to x.example, the first at 2026-10-05T01:01:00.000Z, and asked for your OK in Approvals. None of them left this machine.");
  assert.deepEqual(all.secrets[0]!.lines.at(-1)!.parts.flatMap((p) => (p.ask ? [p.ask] : [])), ["egr-1"], "the earliest row");
  const some = egressStory([
    { host: "x.example", verdict: "blocked", ts: "2026-10-05T01:01:00.000Z" },
    { host: "x.example", verdict: "blocked", ts: "2026-10-05T01:09:00.000Z", ask: "egr-4" },
    { host: "x.example", verdict: "blocked", ts: "2026-10-05T01:05:00.000Z", ask: "egr-3" },
    { host: "y.example", verdict: "blocked", ts: "2026-10-05T01:07:00.000Z" },
  ]);
  assert.deepEqual(linesOf(some, 0).slice(2), [
    "good: Mandu blocked 3 attempts to send it to x.example, the first at 2026-10-05T01:01:00.000Z, and asked for your OK in Approvals for 2 of them. None of them left this machine.",
    "good: Mandu blocked 1 attempt to send it to y.example, at 2026-10-05T01:07:00.000Z. The request never left this machine.",
  ], "each host by its own blocks");
  assert.deepEqual(some.secrets[0]!.lines[2]!.parts.flatMap((p) => (p.ask ? [p.ask] : [])), ["egr-3"]);
  // No time can be read: the first recorded row, and no time said.
  const untimed = egressStory([
    { host: "z.example", verdict: "blocked", ts: "not a time", ask: "egr-5" },
    { host: "z.example", verdict: "blocked", ts: "nor this", ask: "egr-6" },
  ]);
  assert.equal(linesOf(untimed, 0).at(-1), "good: Mandu blocked 2 attempts to send it to z.example, and asked for your OK in Approvals. None of them left this machine.");
  assert.deepEqual(untimed.secrets[0]!.lines.at(-1)!.parts.flatMap((p) => (p.ask ? [p.ask] : [])), ["egr-5"]);
});

test("no ask is said without a row of the queue's shape on the block's own recorded event", () => {
  for (const ask of ["egr 1; x", "", 42, null, "a".repeat(65), { id: "egr-1" }]) {
    const story = egressStory([{ host: "a.example", verdict: "blocked", ts: "2026-10-05T01:01:00.000Z", ask }]);
    assert.equal(linesOf(story, 0).at(-1), "good: Mandu blocked 1 attempt to send it to a.example, at 2026-10-05T01:01:00.000Z. The request never left this machine.", JSON.stringify(ask));
  }
  // The block's event is not in the record: no time, and no ask.
  const gone = egressStory([{ host: "a.example", verdict: "blocked", ask: "egr-1" }]);
  assert.equal(linesOf(gone, 0).at(-1), "good: Mandu blocked 1 attempt to send it to a.example. The request never left this machine.");
});

test("an OS gate that stopped an action using it and filed a row says Mandu asked too", () => {
  const one = egressStory([{ host: "", gate: true, verdict: "blocked", ts: "2026-10-05T01:01:00.000Z", ask: "egr-7" }]);
  assert.equal(linesOf(one, 0).at(-1), "good: Mandu stopped 1 action that used it, and asked for your OK in Approvals.");
  assert.deepEqual(one.secrets[0]!.lines.at(-1)!.parts.flatMap((p) => (p.ask ? [p.ask] : [])), ["egr-7"]);
  const some = egressStory([
    { host: "", gate: true, verdict: "blocked", ts: "2026-10-05T01:01:00.000Z", ask: "egr-7" },
    { host: "", gate: true, verdict: "blocked", ts: "2026-10-05T01:02:00.000Z" },
  ]);
  assert.equal(linesOf(some, 0).at(-1), "good: Mandu stopped 2 actions that used it, and asked for your OK in Approvals for 1 of them.");
  const none = egressStory([{ host: "", gate: true, verdict: "blocked", ts: "2026-10-05T01:01:00.000Z" }]);
  assert.equal(linesOf(none, 0).at(-1), "good: Mandu stopped 1 action that used it.");
});

test("through the session's own lineage: the block's net_action names its row, so the card says Mandu asked; claimed, no line at all", () => {
  const withAsk = (events: ManduEvent[]) => events.map((e) =>
    e.kind === "net_action" && (e as unknown as { action?: string }).action === "blocked" ? ({ ...e, policy: { ...e.policy!, approvalId: "egr-3" } }) : e);
  const { secrets } = pageOf(withAsk(walkthroughEvents()));
  assert.equal(linesOf(secrets, 0).at(-1), "good: Mandu blocked 1 attempt to send it to collector.evil.example, at 2026-10-04T13:10:22.500Z, and asked for your OK in Approvals. The request never left this machine.");
  assert.deepEqual(secrets.secrets.flatMap((s) => s.lines.flatMap((l) => l.parts.flatMap((p) => (p.ask ? [p.ask] : [])))), ["egr-3"]);
  // A claimed block (arbiter-human-plane.md §10.2) is no line, so no ask.
  const claimed = pageOf(withAsk(walkthroughEvents({ claimedBlock: true }))).secrets;
  assert.doesNotMatch(linesOf(claimed, 0).join("\n"), /blocked|asked/);
});

test("a time opens its step: the send's and each block's time carry the page's step that shows the event they come from (§4.25b)", () => {
  // The tour: blocked at 10:38, sent at 10:39, each a connection card
  // under What happened (`os:<event id>`, the trace's own id).
  const edges = [
    { host: "api.stripe.com", verdict: "blocked" as const, ts: "2026-10-05T01:38:07.123Z" },
    { host: "api.stripe.com", verdict: "allowed" as const, ts: "2026-10-05T01:39:24.292Z" },
  ];
  assert.deepEqual(timeSteps(egressStory(edges, new Set(["os:ev0", "os:ev1", "tool:other"]))), [
    "2026-10-05T01:38:07.123Z -> os:ev0",
    "2026-10-05T01:39:24.292Z -> os:ev1",
  ]);
  // Words and order are unchanged by it.
  assert.deepEqual(linesOf(egressStory(edges, new Set(["os:ev0", "os:ev1"])), 0), linesOf(egressStory(edges), 0));
  // A step the page does not show (a turn past the cap, a step only the
  // detailed trace lists) is no link; Home passes no steps at all.
  assert.deepEqual(timeSteps(egressStory(edges, new Set(["os:ev1"]))), ["2026-10-05T01:38:07.123Z -> -", "2026-10-05T01:39:24.292Z -> os:ev1"]);
  assert.deepEqual(timeSteps(egressStory(edges)), ["2026-10-05T01:38:07.123Z -> -", "2026-10-05T01:39:24.292Z -> -"]);
});

test("a time opens the step of the FIRST of several, by time; a check folded onto its tool call opens that call's step", () => {
  const story = egressStory([
    { host: "x.example", verdict: "blocked", ts: "2026-10-05T01:05:00.000Z" },
    { host: "a.example", verdict: "allowed", ts: "2026-10-05T01:03:00.000Z" },
    { host: "a.example", verdict: "allowed", ts: "2026-10-05T01:02:00.000Z" },
    { host: "x.example", verdict: "blocked", ts: "2026-10-05T01:01:00.000Z" },
  ], new Set(["os:ev0", "os:ev1", "os:ev2", "os:ev3"]));
  assert.deepEqual(timeSteps(story), ["2026-10-05T01:01:00.000Z -> os:ev3", "2026-10-05T01:02:00.000Z -> os:ev2"]);
  // Two at the same moment: the first recorded, as the time is.
  const tie = egressStory([
    { host: "x.example", verdict: "blocked", ts: "2026-10-05T01:01:00.000Z" },
    { host: "x.example", verdict: "blocked", ts: "2026-10-05T01:01:00.000Z" },
  ], new Set(["os:ev0", "os:ev1"]));
  assert.deepEqual(timeSteps(tie), ["2026-10-05T01:01:00.000Z -> os:ev0"]);
  // The event names its tool call and the page shows that call: its step,
  // as the Approvals link finds one (agent-page.ts `locateAsk`).
  const folded = egressStory([{ host: "api.stripe.com", verdict: "blocked", ts: "2026-10-05T01:38:07.123Z", callId: "toolu_1" }], new Set(["tool:toolu_1", "os:ev0"]));
  assert.deepEqual(timeSteps(folded), ["2026-10-05T01:38:07.123Z -> tool:toolu_1"]);
  // A time not said opens nothing: the event is not in the record, or one
  // of several has no readable time.
  assert.deepEqual(timeSteps(egressStory([{ host: "a.example", verdict: "blocked" }], new Set(["os:ev0"]))), []);
  assert.deepEqual(timeSteps(egressStory([
    { host: "a.example", verdict: "allowed", ts: "2026-10-05T01:03:00.000Z" },
    { host: "a.example", verdict: "allowed", ts: "not a time" },
  ], new Set(["os:ev0", "os:ev1"]))), []);
});

test("through the session's own lineage: the card's block time opens the block's step on the page", () => {
  const page = pageOf();
  const shown = new Set(page.story.flatMap((t) => t.steps.filter((s) => s.kind === "action").map((s) => s.id)));
  const parts = page.secrets.secrets.flatMap((s) => s.lines.flatMap((l) => l.parts.filter((p) => p.kind === "time")));
  assert.ok(parts.length >= 2, "the walkthrough's cards say when");
  for (const p of parts) assert.ok(p.step && shown.has(p.step), `${p.text} opens a step the page shows`);
  const block = page.secrets.secrets[0]!.lines.find((l) => words(l.parts).startsWith("Mandu blocked"))!;
  const step = page.story.flatMap((t) => t.steps).find((s) => s.id === block.parts.find((p) => p.kind === "time")!.step);
  assert.ok(step && step.kind === "action" && step.outcome === "blocked", "the block line opens the block");
  assert.match(step.kind === "action" ? words(step.sentence) : "", /collector\.evil\.example/);
});

test("names: a variable, a file's key, a whole file, a command's output", () => {
  const f = (root: string, originLabel: string | null = null): SymbolLineage => ({ root, nodes: [], edges: [], summary: { root, originLabel, minted: true, contextTurns: 0, echoed: false, terminal: "dormant" } });
  assert.equal(words(secretWhat(f("$MDU:nomodel_Env[aaaa].NPM_TOKEN"))), "The environment variable NPM_TOKEN");
  assert.equal(words(secretWhat(f("$MDU:nomodel_Read[aaaa].KEY", "/w/.env"))), "KEY in /w/.env");
  assert.equal(words(secretWhat(f("$MDU:nomodel_Read[aaaa]", "/w/id_rsa"))), "The file /w/id_rsa");
  assert.equal(words(secretWhat(f("$MDU:nomodel_Bash[aaaa]"))), "Output of a Bash step that held a secret");
});

test("names: every agent's file read names its file, as Claude Code's Read does (OpenCode's and OpenClaw's read, Codex's read_file; §4.25b)", () => {
  const f = (root: string, originLabel: string | null = null): SymbolLineage => ({ root, nodes: [], edges: [], summary: { root, originLabel, minted: true, contextTurns: 0, echoed: false, terminal: "dormant" } });
  const home = "/home/user";
  // OpenCode's `read` of a labelled file is masked whole as one token
  // (tests/stack/opencode-read-value): it read "Output of a read step that
  // held a secret".
  for (const tool of ["read", "read_file", "Read"]) {
    assert.equal(words(secretWhat(f(`$MDU:nomodel_${tool}[aaaa]`, "/home/user/ws/vault/partner-token.md"), home)), "The file ~/ws/vault/partner-token.md", tool);
    assert.equal(words(secretWhat(f(`$MDU:nomodel_${tool}[aaaa].KEY`, "/w/.env"), home)), "KEY in /w/.env", tool);
  }
  // A whole-output mask's reason never renames a file read.
  assert.equal(words(secretWhat(f("$MDU:nomodel_read[aaaa]", "/w/.env"), "", { kind: "names", paths: [".env"] })), "The file /w/.env");
  // A search or a listing names a folder, and a command or a web tool a
  // command or an address: never "The file …".
  for (const tool of ["grep", "glob", "Grep", "ls", "bash", "shell", "webfetch", "web_fetch"]) {
    assert.equal(words(secretWhat(f(`$MDU:nomodel_${tool}[aaaa]`, "/w/src"))), `Output of a ${tool} step that held a secret`, tool);
  }
});

test("names: a command's output masked whole says why, from its note's reason; a twin or a variable keeps its name (§4.25b)", () => {
  const f = (root: string, originLabel: string | null = null): SymbolLineage => ({ root, nodes: [], edges: [], summary: { root, originLabel, minted: true, contextTurns: 0, echoed: false, terminal: "dormant" } });
  const home = "/home/user";
  const bash = f("$MDU:nomodel_Bash[aaaa]", 'set -a && . ./.env && curl -u "$STRIPE_KEY:" https://api.stripe.com/v1/customers');
  // The command names the file (the path-derived note): the output is not
  // known to hold a secret, so the card does not say it "held" one.
  assert.equal(words(secretWhat(bash, home, { kind: "names", paths: ["./.env"] })), "Output of a Bash step whose command named your secret file ./.env");
  assert.deepEqual(secretWhat(bash, home, { kind: "names", paths: ["./.env"] }).filter((p) => p.kind === "code").map((p) => p.text), ["Bash", "./.env"]);
  assert.equal(
    words(secretWhat(bash, home, { kind: "names", paths: ["./.env", "/home/user/.aws/credentials", "/srv/a.pem", "/srv/b.pem"] })),
    "Output of a Bash step whose command named your secret files ./.env, ~/.aws/credentials, /srv/a.pem and 1 more",
  );
  assert.equal(words(secretWhat(bash, home, { kind: "names", paths: [] })), "Output of a Bash step whose command named one of your secret files");
  // A program under it read the file (the guard's taint): by base name;
  // another account's home stays as recorded.
  assert.equal(words(secretWhat(bash, home, { kind: "read", apps: ["/usr/bin/psql"], files: ["/home/user/.pgpass"] })), "Output of a Bash step in which psql read your secret file ~/.pgpass");
  assert.equal(words(secretWhat(bash, home, { kind: "read", apps: ["sh", "node"], files: ["/srv/a.env", "/home/bob/.env"] })), "Output of a Bash step in which sh and node read your secret files /srv/a.env and /home/bob/.env");
  assert.equal(words(secretWhat(bash, home, { kind: "read", apps: [], files: ["/srv/a.env"] })), "Output of a Bash step in which a program read your secret file /srv/a.env");
  assert.equal(words(secretWhat(f("$MDU:nomodel_exec_command[aaaa]", "cat .env"), "", { kind: "names", paths: [".env"] })), "Output of a exec_command step whose command named your secret file .env");
  // No reason: the words of before.
  assert.equal(words(secretWhat(bash, home, null)), "Output of a Bash step that held a secret");
  // A twin or a variable is named by itself, whatever the note says.
  assert.equal(words(secretWhat(f("$MDU:nomodel_Read[aaaa].KEY", "/home/user/.env"), home, { kind: "names", paths: [".env"] })), "KEY in ~/.env");
  assert.equal(words(secretWhat(f("$MDU:nomodel_Env[aaaa].NPM_TOKEN"), home, { kind: "read", apps: ["node"], files: ["/srv/a.env"] })), "The environment variable NPM_TOKEN");
});

/** The proxies' two `masked:` note forms (rewrite-request.ts; the stack
 *  test `dashboard-command-output-name` pins them to the proxies). */
const namesNote = (named: string): string => `[mandu:secret] masked: the command names ${named}, so its whole output is hidden from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Everything else it printed is hidden with it: to read another file, a listing or a log, run that part again as a command of its own that names no secret file. Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.`;
const readNote = (apps: string, files: string): string => `[mandu:secret] masked: ${apps} read ${files}; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Say so rather than retrying.`;

/** A session whose tool steps returned `results` (each the AI's result and
 *  the note it carried), with one lineage flow per token. */
function causeStory(results: Array<{ token: string; note: string | null; origin?: string; echo?: boolean }>, home = ""): SecretsStory {
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  // `echo`: the AI's own call sent the token and the tool printed it back.
  const steps = results.map((r, i) => ({
    id: `tool:c${i}`, step: "tool", callId: `c${i}`, tool: "Bash", ts: `2026-10-07T01:0${i}:00.000Z`, turn: i + 1, resultAgent: r.token, secretNote: r.note,
    ...(r.echo ? { input: JSON.stringify({ command: `echo ${r.token}` }), resultHuman: r.token } : {}),
  } as unknown as DualStep));
  const flows = [...new Set(results.map((r) => r.token))].map((root): SymbolLineage => ({ root, nodes: [], edges: [], summary: { root, originLabel: results.find((r) => r.token === root)!.origin ?? "a command", minted: true, contextTurns: 1, echoed: false, terminal: "context-only" } }));
  return secretsStory({ ...vm, dualLanes: { ...vm.dualLanes, steps }, lineage: { ...vm.lineage, flows } }, [], false, "secrets", home);
}

test("Your secrets: a masked command output's card says why, from the note of the step that minted it; different reasons are different cards (§4.25b)", () => {
  const home = "/home/user";
  const story = causeStory([
    { token: "$MDU:nomodel_Bash[a001]", note: namesNote("a secret file (./.env)") },
    { token: "$MDU:nomodel_Bash[a002]", note: readNote("psql", "/home/user/.pgpass") },
    // The same reason again: the same thing, one card.
    { token: "$MDU:nomodel_Bash[a003]", note: namesNote("a secret file (./.env)") },
    // A note this rule does not know, and none: the words of before, one card.
    { token: "$MDU:nomodel_Bash[a004]", note: "[mandu:secret] masked: the process taint could not be read: masked (fail-closed). The user does not see this output unless your reply quotes the symbol (they then see its real value)." },
    { token: "$MDU:nomodel_Bash[a005]", note: null },
  ], home);
  assert.deepEqual(story.secrets.map((x) => words(x.what)), [
    "Output of a Bash step whose command named your secret file ./.env",
    "Output of a Bash step in which psql read your secret file ~/.pgpass",
    "Output of a Bash step that held a secret",
  ]);
  assert.deepEqual(story.counts, { masked: 3, early: 0 }, "the tiles count the cards");
  // The step that minted the token says why, not a later step that echoed it.
  const echoed = causeStory([
    { token: "$MDU:nomodel_Bash[b001]", note: null },
    { token: "$MDU:nomodel_Bash[b001]", note: namesNote("a secret file (.env)") },
  ]);
  assert.deepEqual(echoed.secrets.map((x) => words(x.what)), ["Output of a Bash step that held a secret"]);
  // A result that only printed back the placeholder the AI's own call sent
  // did not mask it: that step's note is not its reason.
  const printedBack = causeStory([{ token: "$MDU:nomodel_Bash[b002]", note: namesNote("a secret file (.env)"), echo: true }]);
  assert.deepEqual(printedBack.secrets.map((x) => words(x.what)), ["Output of a Bash step that held a secret"]);
  // Names and paths only, never a token or a value.
  assert.doesNotMatch(JSON.stringify(story.secrets), /\$MDU:|a00[1-5]/);
});

test("Home's count of a session follows the cards: one card per reason (pageSecrets, §4.25b)", () => {
  // Two outputs, one reason: still one secret; two reasons: two.
  const one = causeStory([{ token: "$MDU:nomodel_Bash[c001]", note: namesNote("a secret file (./.env)") }, { token: "$MDU:nomodel_Bash[c002]", note: namesNote("a secret file (./.env)") }]);
  assert.deepEqual(one.counts, { masked: 1, early: 0 });
  const two = causeStory([{ token: "$MDU:nomodel_Bash[c001]", note: namesNote("a secret file (./.env)") }, { token: "$MDU:nomodel_Bash[c002]", note: namesNote("secret files (./.env, ./prod.env)") }]);
  assert.deepEqual(two.secrets.map((x) => words(x.what)), [
    "Output of a Bash step whose command named your secret file ./.env",
    "Output of a Bash step whose command named your secret files ./.env and ./prod.env",
  ]);
  assert.deepEqual(two.counts, { masked: 2, early: 0 });
});

/** A session whose tool steps returned `steps` (each its tool, arguments,
 *  the AI's result and recorded origin), with one lineage flow per root
 *  `roots` names (`origin`: the flow's recorded origin, none by default). */
function mintedStory(steps: Array<{ tool: string; args: Record<string, unknown>; result: string; origin?: string }>, roots: Array<{ root: string; origin?: string }>, cwd: string | null, home = ""): SecretsStory {
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const dual = steps.map((r, i) => ({
    id: `tool:m${i}`, step: "tool", callId: `m${i}`, tool: r.tool, ts: `2026-10-07T02:0${i}:00.000Z`, turn: i + 1,
    input: JSON.stringify(r.args), resultAgent: r.result, secretNote: null, origin: r.origin ?? null,
  } as unknown as DualStep));
  const flows = roots.map(({ root, origin }): SymbolLineage => ({ root, nodes: [], edges: [], summary: { root, originLabel: origin ?? null, minted: true, contextTurns: 1, echoed: false, terminal: "context-only" } }));
  return secretsStory({ ...vm, dualLanes: { ...vm.dualLanes, steps: dual }, lineage: { ...vm.lineage, flows } }, [], false, "secrets", home, undefined, { labels: [], cwd });
}

test("Your secrets: a read token with no recorded origin is named by the read step that minted it, placed as a Read's path is (§4.25b)", () => {
  const home = "/home/user";
  const key = "$MDU:nomodel_Read[d001].STRIPE_KEY";
  const named = (args: Record<string, unknown>, cwd: string | null, tool = "Read") =>
    words(mintedStory([{ tool, args, result: `STRIPE_KEY=${key}\n` }], [{ root: key }], cwd, home).secrets[0]!.what);
  // The first-session tour: the Read's absolute path, under the home folder.
  assert.equal(named({ file_path: "/home/user/mandu-try/.env" }, null), "STRIPE_KEY in ~/mandu-try/.env");
  // Every agent's file read (tool-family.ts), by its own argument.
  assert.equal(named({ path: "/srv/app/.env" }, null, "read_file"), "STRIPE_KEY in /srv/app/.env");
  assert.equal(named({ filePath: "~/app/.env" }, null, "read"), "STRIPE_KEY in ~/app/.env");
  // A relative path is placed in the session's folder.
  assert.equal(named({ file_path: "app/.env" }, "/home/user/proj"), "STRIPE_KEY in ~/proj/app/.env");
  assert.equal(named({ file_path: "../other/.env" }, "/home/user/proj"), "STRIPE_KEY in ~/other/.env");
  // Where it cannot be placed, the words of before: a relative path and no
  // folder recorded, a path holding a token, no path at all.
  assert.equal(named({ file_path: "app/.env" }, null), "STRIPE_KEY in a file");
  assert.equal(named({ file_path: "$MDU:nomodel_Env[e001].APP_DIR/.env" }, "/home/user/proj"), "STRIPE_KEY in a file");
  assert.equal(named({}, "/home/user/proj"), "STRIPE_KEY in a file");
  // A whole file masked to one token: "The file …", as with an origin.
  const whole = mintedStory([{ tool: "Read", args: { file_path: "/home/user/.ssh/id_ed25519" }, result: "$MDU:nomodel_Read[d002]" }], [{ root: "$MDU:nomodel_Read[d002]" }], null, home);
  assert.equal(words(whole.secrets[0]!.what), "The file ~/.ssh/id_ed25519");
  // The step's recorded origin, when absolute, is its file (as plainReads).
  const byOrigin = mintedStory([{ tool: "Read", args: { file_path: "app/.env" }, result: key, origin: "/srv/real/.env" }], [{ root: key }], null, home);
  assert.equal(words(byOrigin.secrets[0]!.what), "STRIPE_KEY in /srv/real/.env");
});

test("Your secrets: a read step names a key's file only when it minted it; a recorded origin always wins (§4.25b)", () => {
  const home = "/home/user";
  const key = "$MDU:nomodel_Read[d003].API_KEY";
  // The token's own recorded origin outranks the step's path.
  const recorded = mintedStory([{ tool: "Read", args: { file_path: "/home/user/x/.env" }, result: key }], [{ root: key, origin: "/home/user/real/.env" }], null, home);
  assert.equal(words(recorded.secrets[0]!.what), "API_KEY in ~/real/.env");
  // First held by a command, then by a Read of some file: the Read did not
  // mint it, so it is not named by that file.
  const later = mintedStory([
    { tool: "Bash", args: { command: "env" }, result: key },
    { tool: "Read", args: { file_path: "/home/user/notes.md" }, result: key },
  ], [{ root: key }], null, home);
  assert.equal(words(later.secrets[0]!.what), "API_KEY in a file");
  // A search's result is not a file read: never "in" the folder it searched.
  const grep = mintedStory([{ tool: "Grep", args: { path: "/home/user/x" }, result: key }], [{ root: key }], null, home);
  assert.equal(words(grep.secrets[0]!.what), "API_KEY in a file");
  // Another field of the same file is the same file.
  const two = mintedStory([{ tool: "Read", args: { file_path: "/home/user/x/.env" }, result: `${key}\n$MDU:nomodel_Read[d003].DB_URL` }], [{ root: key }, { root: "$MDU:nomodel_Read[d003].DB_URL" }], null, home);
  assert.deepEqual(two.secrets.map((x) => words(x.what)), ["API_KEY in ~/x/.env", "DB_URL in ~/x/.env"]);
  // Paths only, never a token.
  assert.doesNotMatch(JSON.stringify([recorded, later, grep, two].map((x) => x.secrets)), /\$MDU:/);
});

test("Your secrets: two flows of one key, one naming its file and one not, are one card, and the tiles count one (§4.25b)", () => {
  const home = "/home/user";
  const key = "$MDU:nomodel_Read[d004].STRIPE_KEY";
  // Before, the flow with an origin read "STRIPE_KEY in ~/app/.env" and the
  // one without "STRIPE_KEY in a file": two cards for one key.
  const story = mintedStory([{ tool: "Read", args: { file_path: "/home/user/app/.env" }, result: key }], [{ root: key, origin: "/home/user/app/.env" }, { root: key }], null, home);
  assert.deepEqual(story.secrets.map((x) => words(x.what)), ["STRIPE_KEY in ~/app/.env"]);
  assert.deepEqual(story.counts, { masked: 1, early: 0 });
});

test("a card's file, which it links to Rules: a key's file, a whole file, a minted read's; ~/… under home, else absolute; none where no file is named (§4.25b)", () => {
  const f = (root: string, originLabel: string | null = null): SymbolLineage => ({ root, nodes: [], edges: [], summary: { root, originLabel, minted: true, contextTurns: 0, echoed: false, terminal: "dormant" } });
  const home = "/home/user";
  // A recorded origin: the key's file, the whole file; under home as ~/….
  assert.equal(secretFile(f("$MDU:nomodel_Read[aaaa].KEY", "/home/user/app/.env"), home), "~/app/.env");
  assert.equal(secretFile(f("$MDU:nomodel_read_file[aaaa]", "/home/user/.ssh/id_ed25519"), home), "~/.ssh/id_ed25519");
  // Outside home, another account's home, or no home known: absolute.
  assert.equal(secretFile(f("$MDU:nomodel_Read[aaaa].KEY", "/srv/app/.env"), home), "/srv/app/.env");
  assert.equal(secretFile(f("$MDU:nomodel_Read[aaaa].KEY", "/home/bob/.env"), home), "/home/bob/.env");
  assert.equal(secretFile(f("$MDU:nomodel_Read[aaaa].KEY", "/home/user/app/.env")), "/home/user/app/.env");
  // A relative origin is placed in the session's folder, else not linked.
  assert.equal(secretFile(f("$MDU:nomodel_Read[aaaa].KEY", "app/.env"), home, null, "/home/user/proj"), "~/proj/app/.env");
  assert.equal(secretFile(f("$MDU:nomodel_Read[aaaa].KEY", "app/.env"), home), null);
  assert.equal(secretFile(f("$MDU:nomodel_Read[aaaa].KEY", "~/app/.env"), "", null, "/w"), null, "~ with no home known is never the session's folder");
  // The file of the read that minted it, when no origin was recorded; a recorded one wins.
  assert.equal(secretFile(f("$MDU:nomodel_Read[aaaa].KEY"), home, "/home/user/mandu-try/.env"), "~/mandu-try/.env");
  assert.equal(secretFile(f("$MDU:nomodel_Read[aaaa].KEY", "/srv/real/.env"), home, "/home/user/x/.env"), "/srv/real/.env");
  // No file named: a variable, a command's output, a search, a secret item, an unknown read.
  assert.equal(secretFile(f("$MDU:nomodel_Env[aaaa].NPM_TOKEN"), home), null);
  assert.equal(secretFile(f("$MDU:nomodel_Read[aaaa].KEY", "env:NPM_TOKEN"), home), null);
  assert.equal(secretFile(f("$MDU:nomodel_Bash[aaaa]", "/home/user/app/.env"), home, "/home/user/app/.env"), null);
  assert.equal(secretFile(f("$MDU:nomodel_Grep[aaaa]", "/home/user/app"), home), null);
  assert.equal(secretFile(f("$MDU:nomodel_Read[aaaa].KEY"), home), null);
  assert.equal(secretFile(f("$MDU:secret[aaaa]"), home), null);
  // A token with no tool tag names a file only by an absolute or ~/ origin.
  assert.equal(secretFile(f("$MDU:secret[aaaa]", "/home/user/notes/plan.md"), home), "~/notes/plan.md");
  assert.equal(secretFile(f("$MDU:secret[aaaa]", "plan.md"), home, null, "/home/user"), null);
  assert.equal(secretFile(f("$MDU:secret[aaaa]", "https://example.com/x"), home, null, "/home/user"), null);
});

test("Your secrets: a card that names a file carries it, a minted read's too; a variable's and a command output's carry none (§4.25b)", () => {
  const home = "/home/user";
  const key = "$MDU:nomodel_Read[d005].STRIPE_KEY";
  const minted = mintedStory([{ tool: "Read", args: { file_path: "/home/user/mandu-try/.env" }, result: key }], [{ root: key }], null, home);
  assert.equal(minted.secrets[0]!.file, "~/mandu-try/.env");
  const unplaced = mintedStory([{ tool: "Read", args: { file_path: "app/.env" }, result: key }], [{ root: key }], null, home);
  assert.equal(words(unplaced.secrets[0]!.what), "STRIPE_KEY in a file");
  assert.equal("file" in unplaced.secrets[0]!, false, "a path that could not be placed: no link");
  const { secrets } = pageOf(walkthroughEvents(), "/home/dev");
  const byName = new Map(secrets.secrets.map((s) => [words(s.what), s.file]));
  assert.equal(byName.get("PASTE_KEY in ~/app/.env"), "~/app/.env");
  assert.equal(byName.get("The environment variable GITHUB_TOKEN"), undefined);
  const outputs = causeStory([{ token: "$MDU:nomodel_Bash[a001]", note: namesNote("a secret file (./.env)") }], home);
  assert.equal("file" in outputs.secrets[0]!, false, "a command's output names no file of its own");
});

test("short names: a variable, a file's key, a file; never a piece of a command or a web address (§4.25b)", () => {
  // The names the page's sentences use, as Your secrets names the same items.
  assert.equal(secretShortName("$MDU:nomodel_Env[aaaa].NPM_TOKEN", null), "NPM_TOKEN");
  assert.equal(secretShortName("$MDU:nomodel_Read[aaaa].KEY", "/w/.env"), "KEY");
  assert.equal(secretShortName("$MDU:nomodel_Env[aaaa]", "env:NPM_TOKEN"), "NPM_TOKEN");
  assert.equal(secretShortName("$MDU:nomodel_Read[aaaa]", "/w/deploy/staging.conf"), "staging.conf");
  assert.equal(secretShortName("$MDU:nomodel_Read[aaaa]", "/w/keys/"), "keys", "a folder by its own name");
  assert.equal(secretShortName("$MDU:nomodel_Read[aaaa]", null), null);
  // Another agent's file tools keep their file's name (OpenCode's read, Goose's text editor).
  assert.equal(secretShortName("$MDU:nomodel_read[aaaa]", "/w/deploy/staging.conf"), "staging.conf");
  assert.equal(secretShortName("$MDU:localmodel_text_editor[aaaa]", "/w/notes.md"), "notes.md");
  // A command's output: its recorded origin is the command (the proxies'
  // `originFor`). The tour's once read "your secret `customers -u "$STRIPE_KEY:"`".
  const tour = 'set -a && . ./.env && set +a && curl -sS https://api.stripe.com/v1/customers -u "$STRIPE_KEY:"';
  for (const tag of ["Bash", "BashOutput", "TaskOutput", "Monitor", "exec_command", "shell_command", "local_shell", "bash", "exec", "process", "shell"]) {
    assert.equal(secretShortName(`$MDU:nomodel_${tag}[aaaa]`, tour), null, tag);
  }
  assert.equal(secretShortName("$MDU:anymodel_Bash[aaaa]", "cat ~/.ssh/id_rsa | head -3"), null);
  assert.equal(secretShortName("$MDU:nomodel_exec_command[aaaa]", "cat .env"), null);
  // A twin's field still names it, whatever tool read it.
  assert.equal(secretShortName("$MDU:nomodel_exec_command[aaaa].STRIPE_KEY", tour), "STRIPE_KEY");
  // A web address or a query: not a file either.
  assert.equal(secretShortName("$MDU:nomodel_WebFetch[aaaa]", "https://api.example.com/v1/customers"), null);
  assert.equal(secretShortName("$MDU:nomodel_WebSearch[aaaa]", "stripe api key format"), null);
  assert.equal(secretShortName("$MDU:nomodel_fetch_page[aaaa]", "https://intranet.example/wiki/keys"), null, "an MCP tool's URL origin");
});

test("names: a file under the home folder reads ~/…; anywhere else, as recorded", () => {
  const f = (root: string, originLabel: string | null = null): SymbolLineage => ({ root, nodes: [], edges: [], summary: { root, originLabel, minted: true, contextTurns: 0, echoed: false, terminal: "dormant" } });
  const home = "/home/user";
  assert.equal(words(secretWhat(f("$MDU:nomodel_Read[aaaa].KEY", "/home/user/proj/.env"), home)), "KEY in ~/proj/.env");
  assert.equal(words(secretWhat(f("$MDU:nomodel_Read[aaaa]", "/home/user/mandu-try/deploy/staging.conf"), home)), "The file ~/mandu-try/deploy/staging.conf");
  // Still code, so the page draws the path as code.
  assert.deepEqual(secretWhat(f("$MDU:nomodel_Read[aaaa]", "/home/user/.ssh/id_rsa"), home), [{ kind: "text", text: "The file " }, { kind: "code", text: "~/.ssh/id_rsa" }]);
  // Another account's home, a sibling that shares the prefix, a system path:
  // as recorded, never a `~` that would name the wrong folder.
  assert.equal(words(secretWhat(f("$MDU:nomodel_Read[aaaa]", "/home/bob/.env"), home)), "The file /home/bob/.env");
  assert.equal(words(secretWhat(f("$MDU:nomodel_Read[aaaa]", "/home/user2/.env"), home)), "The file /home/user2/.env");
  assert.equal(words(secretWhat(f("$MDU:nomodel_Read[aaaa]", "/etc/app/key.pem"), home)), "The file /etc/app/key.pem");
  // A variable's name is not a path; no home leaves the path as recorded.
  assert.equal(words(secretWhat(f("$MDU:nomodel_Env[aaaa].HOME_TOKEN", "env:HOME_TOKEN"), home)), "The environment variable HOME_TOKEN");
  assert.equal(words(secretWhat(f("$MDU:nomodel_Read[aaaa]", "/home/user/.env"))), "The file /home/user/.env");
});

test("the page names the walkthrough's .env under its home ~/app/.env, and counts the same", () => {
  const plain = pageOf().secrets;
  const page = pageOf(walkthroughEvents(), "/home/dev").secrets;
  assert.equal(words(page.secrets[1]!.what), "PASTE_KEY in ~/app/.env");
  assert.doesNotMatch(JSON.stringify(page), /\/home\/dev/);
  assert.deepEqual(page.counts, plain.counts);
  assert.deepEqual(page.secrets.map((x) => x.lines), plain.secrets.map((x) => x.lines));
  assert.equal(words(pageOf(walkthroughEvents(), "/home/other").secrets.secrets[1]!.what), "PASTE_KEY in /home/dev/app/.env");
});

test("no secret: an empty list; past the cap, a count", () => {
  assert.deepEqual(pageOf(walkthroughEvents().filter((e) => !JSON.stringify(e).includes("$MDU:"))).secrets.secrets, []);
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const many = Array.from({ length: SECRET_CAP + 2 }, (_, i): SymbolLineage => {
    const root = `$MDU:nomodel_Env[${(0xa000 + i).toString(16)}].V${i}`;
    return { root, nodes: [], edges: [], summary: { root, originLabel: null, minted: true, contextTurns: 0, echoed: false, terminal: "dormant" } };
  });
  const story = secretsStory({ ...vm, lineage: { ...vm.lineage, flows: many } }, [], false, "secrets");
  assert.equal(story.secrets.length, SECRET_CAP);
  assert.equal(story.more, 2);
});

test("the tiles' counts follow each card's first line, over every secret (past the cap too)", () => {
  // Masked from the start: both secrets.
  assert.deepEqual(pageOf().secrets.counts, { masked: 2, early: 0 });
  // A fired leak check and Off make no claim: neither tile counts them.
  assert.deepEqual(pageOf(walkthroughEvents({ flagged: true })).secrets.counts, { masked: 0, early: 0 });
  assert.deepEqual(pageOf(walkthroughEvents({ mode: "off", noNetwork: true })).secrets.counts, { masked: 0, early: 0 });
  // A level that lets a model read it is not "masked before the AI saw it".
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const flow = (root: string): SymbolLineage => ({ root, nodes: [], edges: [], summary: { root, originLabel: null, minted: true, contextTurns: 2, echoed: false, terminal: "context-only" } });
  const levels = secretsStory({ ...vm, lineage: { ...vm.lineage, flows: [flow("$MDU:anymodel_Env[aaaa].A"), flow("$MDU:localmodel_Env[bbbb].B"), flow("$MDU:nomodel_Env[cccc].C")] } }, [], false, "secrets");
  assert.deepEqual(levels.secrets.map((s) => s.lines[0]!.tone), ["plain", "plain", "good"]);
  assert.deepEqual(levels.counts, { masked: 1, early: 0 }, "only the card that says 'never the real value'");
  // Past the cap: listed or not, every secret counts.
  const many = Array.from({ length: SECRET_CAP + 2 }, (_, i): SymbolLineage => flow(`$MDU:nomodel_Env[${(0xa000 + i).toString(16)}].V${i}`));
  const capped = secretsStory({ ...vm, lineage: { ...vm.lineage, flows: many } }, [], false, "secrets");
  assert.equal(capped.secrets.length, SECRET_CAP);
  assert.deepEqual(capped.counts, { masked: SECRET_CAP + 2, early: 0 });
});

test("aiSaw: the card's first line, weighed in order", () => {
  assert.equal(aiSaw("no-model", true, true, "secrets"), "flagged", "a fired leak check outranks all");
  assert.equal(aiSaw("no-model", true, false, "off"), "off");
  assert.equal(aiSaw("any-model", true, false, "secrets"), "readable");
  assert.equal(aiSaw("local-model", true, false, "secrets"), "early", "a read before the label outranks the level's placeholder");
  assert.equal(aiSaw("local-model", false, false, "secrets"), "own-model");
  assert.equal(aiSaw("no-model", false, false, "secrets"), "masked");
  assert.equal(aiSaw("no-model", true, false, null), "early");
});
