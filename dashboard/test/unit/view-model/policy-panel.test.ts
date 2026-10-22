/**
 * policy-panel.test — the Policy panel view-model (policy-surface.md §9.4, §9.8).
 *
 * The invariants under test (view-model/policy-panel.ts):
 *   1. unknown-is-not-off: a snapshot without the standing-state extension
 *      (old arbiter) renders posture "unknown", never "off"; an absent
 *      egressPosture renders "unknown", never "normal"; an absent lawSource
 *      renders NO line, never invented provenance.
 *   2. every queue row is visible in ONE merged list (pending + approved +
 *      denied), newest activity first, each with its status-appropriate
 *      actions, session attribution, outcome chip, and (when resolved) the
 *      verdict:<id> join key.
 *   3. rules group by GATE in catalog order (§8) — never re-interleaved by
 *      boundary; gate citations come only from the arbiter's gate catalog
 *      (absent ⇒ omitted, not reconstructed).
 *   4. one row grammar: both row kinds carry the shared where/outcome/detail
 *      vocabulary; sensitive paths render as detail of fs:sensitive-path.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  SPENT_HISTORY_LIMIT,
  toPolicyPanelViewModel,
  verdictDetailOf,
  verdictFamily,
  whereLabel,
} from "../../../src/view-model/policy-panel.js";
import type { PolicySnapshot, UsageGateRow, VerdictEntry } from "../../../src/policy-model.js";
import { NO_OWN_MODEL_WARNING, NO_OWN_MODEL_WARNING_PARTS } from "../../../src/view-model/model-endpoints.js";
import { describeAsk } from "../../../src/view-model/ask-words.js";
import { describeAsk as homeDescribeAsk } from "../../../src/view-model/home.js";

test("§4.34 the queue rows carry the product's words: a waiting row the card's sentence and three cells, an answered row its sentence only", () => {
  const h = "a".repeat(64);
  const vm = toPolicyPanelViewModel({
    ...BARE,
    ...EXT,
    verdicts: [
      verdict({ id: "w-open", symbol: `open:/usr/bin/ssh-add#${h}`, destination: "/home/u/.pgpass", status: "pending", reason: "ssh-add wants to read it", lastSeen: 90 }),
      verdict({ id: "w-net", symbol: "$MDU:WebFetch[bb].body", destination: "evil.example", status: "pending", lastSeen: 80 }),
      verdict({ id: "a-net", symbol: "$MDU:Read[cc].x", destination: "api.github.com", status: "approved", resolvedAt: 70 }),
    ],
  });
  const row = (id: string) => vm.queue.find((r) => r.id === id)!;
  // The same describeAsk the product home uses, with "The agent" asking.
  for (const id of ["w-open", "w-net"]) {
    const r = row(id);
    assert.deepEqual(r.words, describeAsk(r, "The agent"), `${id}: the product's words`);
  }
  assert.equal(homeDescribeAsk, describeAsk, "home.ts re-exports the one describeAsk");
  assert.deepEqual(row("w-open").words.sentence, [
    { kind: "text", text: "The agent's program " }, { kind: "code", text: "/usr/bin/ssh-add" },
    { kind: "text", text: " wants to read a secret file: " }, { kind: "code", text: ".pgpass" },
  ]);
  assert.equal(row("w-open").words.why, ".pgpass is a secret file, and Mandu keeps secret files from the AI. If you want /usr/bin/ssh-add to read it, click Allow once or Always allow.");
  // An answered row: the sentence for "Answered earlier", nothing more (the
  // bytes an answer adds stay small, §4.30).
  assert.deepEqual(Object.keys(row("a-net").words).sort(), ["family", "sentence"]);
  assert.equal(row("a-net").words.family, "send");
  assert.equal(row("a-net").words.sentence.map((p) => p.text).join(""), "The agent wants to send text from a file to api.github.com");
});

test("§4.34 a send names its secret: the row keeps a file or variable origin, and its words name the secret with the full path", () => {
  const vm = toPolicyPanelViewModel({
    ...BARE,
    ...EXT,
    verdicts: [
      verdict({ id: "key", symbol: "$MDU:nomodel_Read[9bbd].STRIPE_KEY", destination: "api.stripe.com", status: "pending", source: { tool: "Read", origin: "/home/u/proj/.env" } }),
      verdict({ id: "env", symbol: "$MDU:nomodel_Env[e5b9].GITHUB_TOKEN", destination: "gist.github.com", status: "approved", resolvedAt: 30, source: { tool: "Env", origin: "env:GITHUB_TOKEN" } }),
      verdict({ id: "web", symbol: "$MDU:WebFetch[bb].body", destination: "evil.example", status: "pending", source: { tool: "WebFetch", origin: "https://docs.example/x?token=t" } }),
      verdict({ id: "cmd", symbol: "$MDU:nomodel_Bash[cc]", destination: "evil.example", status: "pending", source: { tool: "Bash", origin: "cat ~/.env" } }),
      verdict({ id: "old", symbol: "$MDU:nomodel_Read[9bbd].STRIPE_KEY", destination: "evil.example", status: "pending" }),
    ],
  });
  const row = (id: string) => vm.queue.find((r) => r.id === id)!;
  const said = (id: string) => row(id).words.sentence.map((p) => p.text).join("");
  assert.equal(row("key").origin, "/home/u/proj/.env");
  assert.equal(said("key"), "The agent wants to send your secret STRIPE_KEY to api.stripe.com");
  // The inspector keeps the full path (no home is passed here).
  assert.equal(row("key").words.why, "STRIPE_KEY comes from /home/u/proj/.env. Mandu masked it, so the AI never read it. Sending it would show the real secret to api.stripe.com.");
  assert.deepEqual(row("key").words, describeAsk(row("key"), "The agent"), "the same words the product home builds");
  // An answered row names it too ("Answered earlier").
  assert.equal(row("env").origin, "env:GITHUB_TOKEN");
  assert.equal(said("env"), "The agent wants to send your secret GITHUB_TOKEN to gist.github.com");
  // A web address or a command is not kept on the row (no bytes, no new data),
  // and an arbiter that did not say where it came from leaves the words as before.
  for (const id of ["web", "cmd", "old"]) assert.ok(!("origin" in row(id)), id);
  assert.equal(said("cmd"), "The agent wants to send a secret to evil.example");
  assert.equal(said("old"), "The agent wants to send a secret to evil.example");
  assert.equal(said("web"), "The agent wants to send text from a web page to evil.example");
});

test("§4.34 read before it was marked: a waiting row the AI read first carries the time and never says never read; an answer or another row is unchanged", () => {
  const TS = "2026-10-05T01:41:29.686Z";
  const vm = toPolicyPanelViewModel({
    ...BARE,
    ...EXT,
    verdicts: [
      verdict({ id: "early", symbol: "$MDU:nomodel_Read[1131]", destination: "paste.example", status: "pending", source: { tool: "Read", origin: "/home/u/deploy/staging.conf" } }),
      verdict({ id: "done", symbol: "$MDU:nomodel_Read[1131]", destination: "gist.github.com", status: "denied", resolvedAt: 30 }),
      verdict({ id: "other", symbol: "$MDU:nomodel_Read[9bbd].STRIPE_KEY", destination: "api.stripe.com", status: "pending", source: { tool: "Read", origin: "/home/u/proj/.env" } }),
    ],
  }, new Map([["early", TS], ["done", TS]]));
  const row = (id: string) => vm.queue.find((r) => r.id === id)!;
  assert.equal(row("early").readFirst, TS);
  assert.equal(row("early").words.why, "Mandu masks it now, but the AI read its real value before it was marked a secret. Sending it would show the real secret to paste.example.");
  assert.equal(row("early").words.aiNow, "The AI read the real value before it was marked a secret. Since then it gets the masked version, but Mandu does not mask what the AI wrote itself.");
  assert.deepEqual(row("early").words, describeAsk(row("early"), "The agent"), "the same words the product home builds");
  // An answered row has no card to correct: no time, its sentence only.
  assert.ok(!("readFirst" in row("done")));
  assert.deepEqual(Object.keys(row("done").words).sort(), ["family", "sentence"]);
  // A row the lookup did not name keeps its claim.
  assert.ok(!("readFirst" in row("other")));
  assert.match(row("other").words.why ?? "", /Mandu masked it, so the AI never read it\./);
  // No lookup at all: as before.
  const bare = toPolicyPanelViewModel({ ...BARE, ...EXT, verdicts: [verdict({ id: "early", symbol: "$MDU:nomodel_Read[1131]", destination: "paste.example", status: "pending" })] });
  assert.match(bare.queue[0]!.words.why ?? "", /^Mandu masked it, so the AI never read it\./);
});

test("§4.34 read before it was marked, a program's read: a waiting open:/trust: row about a file the AI read first carries the time and never says the AI has not seen the file", () => {
  const TS = "2026-10-05T01:41:29.686Z";
  const h = "c".repeat(64);
  const conf = "/home/u/deploy/staging.conf";
  const vm = toPolicyPanelViewModel({
    ...BARE,
    ...EXT,
    verdicts: [
      verdict({ id: "open", symbol: `open:/usr/bin/cat#${h}`, destination: conf, status: "pending" }),
      verdict({ id: "trust", symbol: `trust:/usr/local/bin/deploy#${h}`, destination: conf, status: "pending" }),
      verdict({ id: "done", symbol: `open:/usr/bin/cat#${h}`, destination: conf, status: "approved", resolvedAt: 30 }),
      verdict({ id: "env", symbol: `open:/usr/bin/cat#${h}`, destination: "/home/u/proj/.env", status: "pending" }),
    ],
  }, new Map([["open", TS], ["trust", TS], ["done", TS]]));
  const row = (id: string) => vm.queue.find((r) => r.id === id)!;
  for (const [id, program] of [["open", "/usr/bin/cat"], ["trust", "/usr/local/bin/deploy"]] as const) {
    assert.equal(row(id).readFirst, TS, id);
    assert.equal(row(id).words.aiNow, `The AI read the file as it was before it was marked a secret, and its program ${program} has not read it. Since then the AI gets the masked version, but Mandu does not mask what the AI wrote itself.`, id);
    assert.deepEqual(row(id).words, describeAsk(row(id), "The agent"), "the same words the product home builds");
  }
  // An answered row has no card to correct; a file the lookup did not name keeps its words.
  assert.ok(!("readFirst" in row("done")));
  assert.deepEqual(Object.keys(row("done").words).sort(), ["family", "sentence"]);
  assert.ok(!("readFirst" in row("env")));
  assert.equal(row("env").words.aiNow, "The AI has not seen the real file, and its program /usr/bin/cat has not read it.");
});

const BARE: PolicySnapshot = {
  specId: "claude-code",
  origins: [],
  tools: {},
  fallbackTrust: "UNTRUSTED",
  mcpPrefix: "mcp__",
};

const EXT = {
  posture: { integrity: true, confidentiality: false },
  usage: { rules: [], sensitivePaths: [] },
  verdicts: [] as VerdictEntry[],
};

function verdict(over: Partial<VerdictEntry>): VerdictEntry {
  return {
    id: "egr-1", symbol: "$MDU:Read[aaaa].x", destination: "evil.test",
    status: "approved", reason: "r", count: 1, firstSeen: 10, lastSeen: 20,
    ...over,
  };
}

function sectionOf(detail: { label: string; items: { text: string; ms?: number | null }[] }[], label: string) {
  const s = detail.find((d) => d.label === label);
  assert.ok(s, `expected a '${label}' detail section`);
  return s!;
}

test("no snapshot → unavailable; old arbiter → unknown posture/lockdown, no law source", () => {
  const none = toPolicyPanelViewModel(null);
  assert.equal(none.available, false);
  assert.equal(none.posture.integrity.state, "unknown");
  assert.equal(none.posture.egress.state, "unknown");
  assert.equal(none.verdictsKnown, false);
  assert.equal(none.lawSource, null);

  const old = toPolicyPanelViewModel(BARE); // live but pre-extension
  assert.equal(old.available, true);
  assert.equal(old.extended, false);
  assert.equal(old.posture.integrity.state, "unknown");
  assert.equal(old.posture.confidentiality.state, "unknown");
  // Absent egressPosture is UNKNOWN, never "normal" (the posture-guard rule
  // applied to the lockdown field — a lockdown hidden behind "normal" is the
  // display twin of the posture-nobody-reads bug class).
  assert.equal(old.posture.egress.state, "unknown");
  assert.equal(old.lawSource, null, "no invented provenance on an old arbiter");
  assert.deepEqual(old.queue, []);
  // No verdicts field at all ⇒ we could not learn the queue: the panel must
  // say so, never render an unfetched queue as an empty one.
  assert.equal(old.verdictsKnown, false);
});

test("route fallback shape: queue WITHOUT the extension → rows render, posture stays unknown", () => {
  const vm = toPolicyPanelViewModel({
    ...BARE,
    verdicts: [verdict({ id: "egr-2", status: "denied" })],
  });
  assert.equal(vm.extended, false);
  assert.equal(vm.verdictsKnown, true);
  assert.equal(vm.queue.length, 1);
  assert.equal(vm.queue[0]!.id, "egr-2");
  assert.equal(vm.posture.integrity.state, "unknown");
  assert.deepEqual(vm.gateGroups, []);
});

test("posture chips carry state + a non-empty explanation; lockdown renders as itself", () => {
  const vm = toPolicyPanelViewModel({ ...BARE, ...EXT, egressPosture: "normal" });
  assert.equal(vm.extended, true);
  assert.equal(vm.posture.integrity.state, "on");
  assert.equal(vm.posture.confidentiality.state, "off");
  assert.equal(vm.posture.egress.state, "normal");
  for (const chip of [vm.posture.integrity, vm.posture.confidentiality, vm.posture.egress]) {
    assert.ok(chip.detail.length > 0 && chip.detail[0]!.items[0]!.text.length > 0);
  }

  const locked = toPolicyPanelViewModel({ ...BARE, ...EXT, egressPosture: "lockdown" });
  assert.equal(locked.posture.egress.state, "lockdown");
  assert.match(locked.posture.egress.detail[0]!.items[0]!.text, /EVERY network egress/);
});

test("ONE merged queue: every status, newest first, shared outcome/where grammar, ⓘ detail", () => {
  const snap: PolicySnapshot = {
    ...BARE,
    ...EXT,
    verdicts: [
      verdict({ id: "egr-1", status: "approved", lastSeen: 20 }),
      verdict({
        id: "egr-2", symbol: "fs:Glob:read", destination: "/opt/probe",
        status: "denied", lastSeen: 25, resolvedAt: 30, sessions: ["sess-A", "sess-B"],
      }),
      verdict({ id: "egr-3", status: "pending", lastSeen: 40, reason: "untrusted destination" }),
    ],
  };
  const vm = toPolicyPanelViewModel(snap);
  const det = (id: string) => verdictDetailOf(snap, id)!;
  // The rows carry no drawer: it is built when the drawer opens (§4.30).
  for (const r of vm.queue) assert.equal("detail" in r, false, `${r.id} ships no drawer`);
  assert.deepEqual(vm.queue.map((r) => r.id), ["egr-3", "egr-2", "egr-1"]);

  const pending = vm.queue[0]!;
  assert.equal(pending.status, "pending");
  assert.equal(pending.outcome, "pending");
  assert.equal(pending.family, "network");
  assert.equal(pending.where, "network");
  assert.deepEqual(
    pending.actions,
    [
      { approve: true, scope: "once", label: "Allow once" },
      { approve: true, label: "Always allow" },
      { approve: false, label: "Block" },
    ],
    "pending → Allow once + Always allow + Block, the product's words and order (§4.34; the scope discriminant marks the single-use verb, §8.7)",
  );
  assert.equal(pending.ruleRefId, null, "a pending row has decided nothing");
  assert.equal(pending.resolvedAt, null);
  assert.deepEqual(pending.sessions, [], "no attribution recorded → honest empty");
  // The reason left the table (§8) but must survive in the drawer.
  assert.match(sectionOf(det("egr-3"), "Where it came from").items[0]!.text, /untrusted destination/);
  assert.match(sectionOf(det("egr-3"), "Resolution").items[0]!.text, /Awaiting a human/);

  const denied = vm.queue[1]!;
  assert.equal(denied.family, "filesystem");
  assert.equal(denied.where, "file");
  assert.equal(denied.outcome, "deny");
  assert.deepEqual(denied.actions, [{ approve: true, label: "Allow instead" }], "a denied row flips to approve");
  assert.equal(denied.ruleRefId, "verdict:egr-2");
  assert.equal(denied.resolvedAt, 30, "the audit column rides the row");
  assert.deepEqual(denied.sessions, ["sess-A", "sess-B"]);
  // Detail: precedence claim + attribution + the epoch-typed resolution time.
  assert.match(sectionOf(det("egr-2"), "What this is").items[1]!.text, /BEFORE every built-in rule/);
  assert.match(
    sectionOf(det("egr-2"), "Where it came from").items[3]!.text,
    /sess-B, sess-A/,
    "sessions render most-recent-first",
  );
  assert.deepEqual(
    sectionOf(det("egr-2"), "Resolution").items[0],
    { text: "denied by a human", ms: 30 },
  );

  const approved = vm.queue[2]!;
  assert.equal(approved.outcome, "allow");
  assert.deepEqual(approved.actions, [{ approve: false, label: "Block instead" }]);
  assert.equal(approved.resolvedAt, null, "a pre-column row stays honestly unknown");
  // Pre-audit-column row: the drawer says unknown via ms:null, never a guess.
  assert.deepEqual(
    sectionOf(det("egr-1"), "Resolution").items[0],
    { text: "approved by a human", ms: null },
  );
});

test("verdict scope (§8.7): once rows project scope + consumedAt; the drawer says what one use is worth", () => {
  const snap: PolicySnapshot = {
    ...BARE,
    ...EXT,
    verdicts: [
      verdict({ id: "egr-once", status: "approved", scope: "once", resolvedAt: 30 }),
      verdict({
        id: "egr-spent", symbol: "$MDU:Read[bbbb].y", status: "approved",
        scope: "once", resolvedAt: 30, consumedAt: 40, lastSeen: 40,
      }),
      verdict({ id: "egr-standing", symbol: "$MDU:Read[cccc].z", status: "approved", resolvedAt: 30, lastSeen: 50 }),
    ],
  };
  const vm = toPolicyPanelViewModel(snap);
  const det = (id: string) => verdictDetailOf(snap, id)!;
  const byId = new Map(vm.queue.map((r) => [r.id, r]));

  const once = byId.get("egr-once")!;
  assert.equal(once.scope, "once");
  assert.equal(once.consumedAt, null);
  assert.match(sectionOf(det("egr-once"), "What this is").items[0]!.text, /single-use human decision/);
  assert.match(sectionOf(det("egr-once"), "What it decides").items[2]!.text, /The NEXT request .* after that one use, asking resumes/);
  assert.deepEqual(sectionOf(det("egr-once"), "Resolution").items[0], { text: "approved by a human (once)", ms: 30 });

  const spent = byId.get("egr-spent")!;
  assert.equal(spent.consumedAt, 40);
  assert.match(sectionOf(det("egr-spent"), "What it decides").items[2]!.text, /Nothing anymore .* spent/);
  assert.deepEqual(sectionOf(det("egr-spent"), "Resolution").items[1], { text: "spent by its one use", ms: 40 });

  // A pre-scope arbiter's rows (scope absent) read as standing — the honest
  // default, and the ONLY thing they ever were.
  const standing = byId.get("egr-standing")!;
  assert.equal(standing.scope, "always");
  assert.equal(standing.consumedAt, null);
  assert.match(sectionOf(det("egr-standing"), "What this is").items[1]!.text, /never expires/);
});

test("the history window (§4.30): only spent single-use answers past the newest are left out, and they are counted", () => {
  const extra = 30;
  const spent = Array.from({ length: SPENT_HISTORY_LIMIT + extra }, (_, i) => verdict({
    id: `spent-${i}`, status: i % 2 ? "approved" : "denied", scope: "once",
    resolvedAt: 10_000 - i, consumedAt: 10_001 - i, lastSeen: 10_000 - i,
  }));
  // Rows that still decide something, all OLDER than every spent one: a
  // window over the whole queue would drop them first.
  const live = [
    verdict({ id: "ask", status: "pending", lastSeen: 5 }),
    verdict({ id: "standing", status: "approved", resolvedAt: 4, lastSeen: 4 }),
    verdict({ id: "unspent-once", status: "denied", scope: "once", resolvedAt: 3, lastSeen: 3 }),
  ];
  const snap: PolicySnapshot = { ...BARE, ...EXT, verdicts: [...live, ...spent] };
  const vm = toPolicyPanelViewModel(snap);
  const ids = vm.queue.map((r) => r.id);
  for (const id of ["ask", "standing", "unspent-once"]) assert.ok(ids.includes(id), `${id} decides something: always listed`);
  const listedSpent = ids.filter((id) => id.startsWith("spent-"));
  assert.equal(listedSpent.length, SPENT_HISTORY_LIMIT);
  assert.deepEqual(listedSpent, spent.slice(0, SPENT_HISTORY_LIMIT).map((v) => v.id), "the newest spent answers are the ones kept");
  assert.equal(vm.queueOmitted, extra);
  // The counts cover every verdict, the omitted ones included.
  const all = [...live, ...spent];
  assert.deepEqual(vm.queueCounts, {
    pending: all.filter((v) => v.status === "pending").length,
    approved: all.filter((v) => v.status === "approved").length,
    denied: all.filter((v) => v.status === "denied").length,
  });
  // An omitted row's drawer is still there to open.
  assert.ok(verdictDetailOf(snap, `spent-${SPENT_HISTORY_LIMIT + extra - 1}`));

  // Under the window nothing is left out.
  const small = toPolicyPanelViewModel({ ...BARE, ...EXT, verdicts: [...live, ...spent.slice(0, 5)] });
  assert.equal(small.queue.length, 8);
  assert.equal(small.queueOmitted, 0);
  assert.deepEqual(toPolicyPanelViewModel(null).queueCounts, { pending: 0, approved: 0, denied: 0 });
});

test("verdictDetailOf: the drawer of one verdict; null for an unknown id, an unshown status, or no snapshot", () => {
  const snap: PolicySnapshot = {
    ...BARE, ...EXT,
    verdicts: [verdict({ id: "egr-1", status: "pending", reason: "fs gate denied" }), verdict({ id: "egr-x", status: "expired" as VerdictEntry["status"] })],
  };
  const d = verdictDetailOf(snap, "egr-1")!;
  assert.deepEqual(d.map((s) => s.label), ["What this is", "What it decides", "Where it came from", "Resolution"]);
  assert.match(sectionOf(d, "Where it came from").items[0]!.text, /fs gate denied/);
  // the requesting sessions, newest first; one is "session", never "session(s)"
  const from = (sessions: string[]) => sectionOf(verdictDetailOf({ ...snap, verdicts: [verdict({ id: "egr-1", status: "pending", sessions })] }, "egr-1")!, "Where it came from").items.at(-1)!.text;
  assert.equal(from(["s1"]), "requesting session: s1");
  assert.equal(from(["s1", "s2"]), "requesting sessions: s2, s1");
  assert.equal(verdictDetailOf(snap, "egr-404"), null);
  assert.equal(verdictDetailOf(snap, "egr-x"), null, "a status the queue does not show has no drawer either");
  assert.equal(verdictDetailOf(null, "egr-1"), null);
  assert.equal(verdictDetailOf({ ...BARE }, "egr-1"), null, "an arbiter that reports no verdicts");
});

test("§8.8 inbound trust: tool rows off the spec objects, fail-closed fallback line, origins; null only with no snapshot", () => {
  const vm = toPolicyPanelViewModel({
    ...BARE,
    origins: [
      { id: "URL", mode: "allowlist", listSize: 3, defaultTrust: "UNTRUSTED" },
    ],
    tools: {
      WebFetch: {
        tool: "WebFetch",
        inbound: {
          kind: "structured",
          summary: "2 fields — 1 trusted, 0 conditional, 1 untrusted",
          fields: [
            { field: "url", trust: "TRUSTED", category: "URL", detail: "TRUSTED (key)" },
            { field: "text", trust: "UNTRUSTED", category: null, detail: "UNTRUSTED (literal)" },
          ],
        },
        outbound: { toolResolve: false, destination: "AgentView", summary: "no resolve", fields: [] },
      },
      TodoWrite: {
        tool: "TodoWrite",
        inbound: null,
        outbound: { toolResolve: false, destination: "AgentView", summary: "no resolve", fields: [] },
      },
      Grep: {
        tool: "Grep",
        inbound: {
          kind: "structured",
          summary: "1 field — 0 trusted, 1 conditional, 0 untrusted",
          fields: [
            { field: "matches", trust: "conditional", category: "DIR", detail: "conditional on DIR" },
          ],
        },
        outbound: { toolResolve: false, destination: "AgentView", summary: "no resolve", fields: [] },
      },
    },
  });
  assert.ok(vm.inbound, "the base snapshot fields are enough — no standing-state extension needed");
  assert.equal(vm.inbound!.specId, "claude-code");
  assert.match(vm.inbound!.fallbackLine, /tools not described .* UNTRUSTED \(fail-closed\)/);
  assert.match(vm.inbound!.fallbackLine, /mcp__\* MCP tools/);
  assert.deepEqual(vm.inbound!.originLines, [
    "URL: allowlist of 3 — anything else defaults UNTRUSTED",
  ]);

  const byTool = new Map(vm.inbound!.tools.map((t) => [t.tool, t]));
  const wf = byTool.get("WebFetch")!;
  assert.equal(wf.summary, "2 fields — 1 trusted, 0 conditional, 1 untrusted");
  assert.equal(wf.trustedFields, 1);
  assert.equal(wf.untrustedFields, 1);
  const fieldSec = wf.detail.find((s) => s.label === "Field trust")!;
  assert.match(fieldSec.items[0]!.text, /url: TRUSTED \(URL key\)/);
  assert.match(fieldSec.items[1]!.text, /text: UNTRUSTED — UNTRUSTED \(literal\)/);

  // No inbound spec → the fail-closed consequence is the summary, not silence.
  const todo = byTool.get("TodoWrite")!;
  assert.match(todo.summary, /no inbound spec — results fail closed to UNTRUSTED/);
  assert.equal(todo.trustedFields, 0);
  assert.equal(todo.untrustedFields, 0);

  // Conditional (origin-keyed) counts as untrusted — UNTRUSTED unless proven.
  const grep = byTool.get("Grep")!;
  assert.equal(grep.untrustedFields, 1);
  assert.match(
    grep.detail.find((s) => s.label === "Field trust")!.items[0]!.text,
    /matches: UNTRUSTED unless DIR is trusted/,
  );

  // Null only when there is no snapshot at all.
  assert.equal(toPolicyPanelViewModel(null).inbound, null);
});

test("verdictFamily parses all three queue-key families; whereLabel is the one vocabulary", () => {
  assert.equal(verdictFamily("$MDU:Read[aaaa].x"), "network");
  assert.equal(verdictFamily("fs:Read:write"), "filesystem");
  assert.equal(verdictFamily("exec-escalate:network"), "exec");
  assert.equal(verdictFamily("exec-program:get.evil.example"), "exec", "§7a net-fetched program text is the exec chokepoint");
  assert.equal(verdictFamily("something-else"), "unknown");
  // shell (rule boundary) and exec (queue family) are ONE chokepoint label.
  assert.equal(whereLabel("shell"), "exec");
  assert.equal(whereLabel("exec"), "exec");
  assert.equal(whereLabel("filesystem"), "file");
  assert.equal(whereLabel("nonsense"), "?");
});

const GATE_FS: UsageGateRow = {
  id: "fs", title: "filesystem path gate",
  definedIn: "arbiter/policy/fs-outbound.ts (decideFsPath)",
  doc: "docs/design/integrity/fs-sync.md §1.4.1",
  evaluation: "checked top to bottom; first match wins",
};

test("rules group by GATE in catalog order; boundary no longer re-interleaves gates", () => {
  const mk = (id: string, boundary: "filesystem" | "network", gate: string) => ({
    id, source: "rule" as const, boundary, outcome: "allow" as const, summary: "s", gate,
  });
  const vm = toPolicyPanelViewModel({
    ...BARE,
    ...EXT,
    usage: {
      // Catalog order: fs, fs, egress — with an egress rule whose BOUNDARY is
      // filesystem (the interleave case the boundary grouping got wrong).
      rules: [
        mk("fs:a", "filesystem", "fs"),
        mk("fs:b", "filesystem", "fs"),
        { ...mk("egress:secret-filesystem", "filesystem", "egress"), outcome: "deny+approval" as const },
      ],
      sensitivePaths: [],
      gates: [GATE_FS],
    },
  });
  assert.deepEqual(vm.gateGroups.map((g) => g.id), ["fs", "egress"]);
  assert.deepEqual(vm.gateGroups[0]!.rules.map((r) => r.id), ["fs:a", "fs:b"], "catalog order kept");
  assert.equal(vm.gateGroups[0]!.title, "filesystem path gate");
  assert.equal(vm.gateGroups[0]!.evaluation, GATE_FS.evaluation);
  // The egress gate has no catalog entry in this fixture: honest fallback —
  // prefix title, NO evaluation caption, NO citation lines in the drawer.
  const eg = vm.gateGroups[1]!;
  assert.equal(eg.title, "egress gate");
  assert.equal(eg.evaluation, null);
  const cite = sectionOf(eg.rules[0]!.detail, "Where it's specified");
  assert.deepEqual(cite.items.map((i) => i.text), ["rule id: egress:secret-filesystem"]);
  // Shared grammar: outcome chip mapping + where label on rule rows.
  assert.equal(eg.rules[0]!.outcome, "needs-approval");
  assert.equal(eg.rules[0]!.where, "file");
  // Cited group: the drawer carries the enforcing-code citation.
  const fsCite = sectionOf(vm.gateGroups[0]!.rules[0]!.detail, "Where it's specified");
  assert.ok(fsCite.items.some((i) => i.text.includes("fs-outbound.ts")));
});

test("gate derives from the id prefix when an older arbiter omits the field", () => {
  const vm = toPolicyPanelViewModel({
    ...BARE,
    ...EXT,
    usage: {
      rules: [
        { id: "session:not-high", source: "rule", boundary: "any", outcome: "allow", summary: "s" },
      ],
      sensitivePaths: [],
    },
  });
  assert.equal(vm.gateGroups.length, 1);
  assert.equal(vm.gateGroups[0]!.id, "session");
  assert.equal(vm.gateGroups[0]!.evaluation, null, "no gate catalog → no invented caption");
});

test("sensitive paths render as detail of fs:sensitive-path, and ride the VM for cross-checks", () => {
  const vm = toPolicyPanelViewModel({
    ...BARE,
    ...EXT,
    usage: {
      rules: [
        { id: "fs:sensitive-path", source: "rule", boundary: "filesystem", outcome: "deny+approval", summary: "s", gate: "fs" },
        { id: "fs:default-deny", source: "fail-closed", boundary: "filesystem", outcome: "deny+approval", summary: "s", gate: "fs" },
      ],
      sensitivePaths: ["~/.ssh", "/etc/shadow"],
      gates: [GATE_FS],
    },
  });
  assert.deepEqual(vm.sensitivePaths, ["~/.ssh", "/etc/shadow"]);
  const rule = vm.gateGroups[0]!.rules.find((r) => r.id === "fs:sensitive-path")!;
  const cfg = sectionOf(rule.detail, "Configured sensitive prefixes");
  assert.deepEqual(cfg.items.map((i) => i.text), ["~/.ssh", "/etc/shadow"]);
  // Only that rule carries the list — it is the rule's config, not boilerplate.
  const other = vm.gateGroups[0]!.rules.find((r) => r.id === "fs:default-deny")!;
  assert.ok(!other.detail.some((d) => d.label === "Configured sensitive prefixes"));
  // A fail-closed row says so in its drawer.
  assert.match(sectionOf(other.detail, "What this is").items[0]!.text, /fail-closed default/);
});

test("law source: builtin / missing-file / file-with-sections / custom", () => {
  const builtin = toPolicyPanelViewModel({
    ...BARE, ...EXT, lawSource: { kind: "builtin" },
  });
  assert.equal(builtin.lawSource?.text, "law source: built-in claude-code spec — no policy file");

  const missing = toPolicyPanelViewModel({
    ...BARE, ...EXT,
    lawSource: { kind: "builtin", configuredPath: "p.yaml", resolvedPath: "/etc/p.yaml", found: false },
  });
  assert.match(missing.lawSource!.text, /NOT loaded: \/etc\/p\.yaml/);

  const file = toPolicyPanelViewModel({
    ...BARE, ...EXT,
    lawSource: {
      kind: "file", configuredPath: "p.yaml", resolvedPath: "/etc/p.yaml", found: true,
      sections: { url: true, channel: false, dir: false, commandEntries: 1, toolOverrides: 2 },
    },
  });
  assert.equal(file.lawSource?.text, "law source: built-in claude-code spec + policy file /etc/p.yaml");
  assert.match(
    file.lawSource!.detail[0]!.items[1]!.text,
    /URL origin list, 2 tool overrides, 1 per-command entry/,
  );

  const custom = toPolicyPanelViewModel({ ...BARE, ...EXT, lawSource: { kind: "custom" } });
  assert.match(custom.lawSource!.text, /custom policy engine/);
});

// ── policy-surface.md §4 / stage 5b: the operator's law as rows ─────

const DOC_EXT = {
  document: {
    lists: { docs: ["https://docs.python.org/"] },
    paths: [
      { path: "/home/u/.aws", level: "no-model", bindings: [], recursive: true },
      { path: "/home/u/pub.txt", level: "public", bindings: [], recursive: false },
    ],
    rules: { "egress:untrusted-destination": { mode: "block" } },
    userRules: [
      { id: "ur-1", kind: "release", from: ["docs.python.org"], to: ["api.github.com"], mode: "allow", reason: "ci", added: "2026-09-04T00:00:00Z", expires: null },
      { id: "ur-2", kind: "release", from: null, to: ["*"], mode: "block", expires: "2020-01-01T00:00:00Z" },
    ],
  },
  relaxations: [
    { kind: "trusted-origin", subject: "URL:https://docs.python.org/", detail: "TRUSTED as-is" },
    { kind: "release-allow", subject: "docs.python.org → api.github.com", detail: "no ask" },
    { kind: "public-path", subject: "/home/u/pub.txt", detail: "declassified" },
  ],
  hits: { "user:ur-1": { hits: 3, auditHits: 0, lastHit: 40 }, "egress:untrusted-destination": { hits: 7, auditHits: 0, lastHit: 41 } },
  policyFile: { path: "/home/u/.config/mandu/policy.yaml", found: true, valid: true, problems: [], loadedAt: 1, refusedAt: null },
};

test("§4.25u a send rule with an end still to come carries plain.until; a past one says Expired, with none; no end, neither", () => {
  const soon = new Date(Date.now() + 9 * 86_400_000).toISOString();
  const doc = {
    ...DOC_EXT.document,
    userRules: [
      { id: "ur-a", kind: "release", from: null, to: ["pastebin.com"], mode: "allow", expires: soon },
      { id: "ur-b", kind: "release", from: ["docs.python.org"], to: ["*"], mode: "block", expires: soon },
      { id: "ur-c", kind: "release", from: null, to: ["x.example"], mode: "allow", expires: "2020-01-01T00:00:00Z" },
      { id: "ur-d", kind: "release", from: null, to: ["y.example"], mode: "allow", expires: null },
      // An audit or off rule keeps its own words: it never decides, so
      // "until" would misread.
      { id: "ur-e", kind: "release", from: null, to: ["z.example"], mode: "audit", expires: soon },
    ],
  };
  const vm = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT, document: doc } as PolicySnapshot);
  const plain = (id: string) => vm.yourRules!.find((r) => r.id === id)!.plain!;
  assert.deepEqual([plain("ur-a").effect, plain("ur-a").until], ["Always allowed", soon]);
  assert.deepEqual([plain("ur-b").effect, plain("ur-b").until], ["Always blocked", soon]);
  assert.equal(plain("ur-c").effect, "Expired, no longer used");
  assert.equal("until" in plain("ur-c"), false, "an expired rule has no until");
  assert.equal(plain("ur-d").effect, "Always allowed");
  assert.equal("until" in plain("ur-d"), false, "a rule with no end has no until");
  assert.equal("until" in plain("ur-e"), false, "an audit rule has no until");
});

test("stage 5b: yourRules projects locks, trusted origins, user rules and dispositions in ONE row grammar", () => {
  const vm = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT } as PolicySnapshot);
  assert.ok(vm.yourRules, "present when the snapshot carries a document");
  const kinds = vm.yourRules!.map((r) => r.kind);
  assert.deepEqual(kinds, ["lock", "lock", "trusted-origin", "release-allow", "release-block", "disposition"]);
  // A disposition that restates the default (mode: ask) is NOT a row.
  const withAsk = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT, document: { ...DOC_EXT.document, rules: { "egress:untrusted-destination": { mode: "ask" } } } } as PolicySnapshot);
  assert.equal(withAsk.yourRules!.filter((r) => r.kind === "disposition").length, 0);
  // Every row names its source; only the relaxing ones say so.
  assert.ok(vm.yourRules!.every((r) => r.source === "policy.yaml"));
  assert.deepEqual(vm.yourRules!.filter((r) => r.relaxes).map((r) => r.id), ["lock:/home/u/pub.txt", "trusted-origin:url:https://docs.python.org/", "ur-1"]);
  // Hits ride the `user:<id>` key for user rules and the rule id for dispositions.
  const ur1 = vm.yourRules!.find((r) => r.id === "ur-1")!;
  assert.equal(ur1.hits, 3);
  assert.equal(ur1.reach, "from docs.python.org to api.github.com");
  const disp = vm.yourRules!.find((r) => r.kind === "disposition")!;
  assert.equal(disp.hits, 7);
  assert.match(disp.effect, /set to Block/);
  // An expired rule is kept, marked, and does NOT count as a relaxation.
  const ur2 = vm.yourRules!.find((r) => r.id === "ur-2")!;
  assert.equal(ur2.expired, true);
  assert.equal(ur2.subject, "anywhere");
  // Relaxations pass through verbatim; the file status rides along.
  assert.equal(vm.relaxations!.length, 3);
  assert.equal(vm.policyFile!.valid, true);
});

test("stage 5b: an arbiter predating the document reports yourRules/relaxations/policyFile as null (unknown, not empty)", () => {
  const vm = toPolicyPanelViewModel({ ...BARE, ...EXT });
  assert.equal(vm.yourRules, null);
  assert.equal(vm.relaxations, null);
  assert.equal(vm.policyFile, null);
  // Rule rows say "not tracked" (null), never 0.
  const withRule = toPolicyPanelViewModel({ ...BARE, ...EXT, usage: { rules: [{ id: "egress:untrusted-destination", source: "rule", boundary: "network", outcome: "deny+approval", summary: "s", gate: "egress" }], sensitivePaths: [] } });
  const row = withRule.gateGroups.flatMap((g: any) => g.rules).find((r) => r.id === "egress:untrusted-destination")!;
  assert.equal(row.hits, null);
  assert.equal(row.disposition, null);
});

test("stage 5b: built-in rule rows carry hits + the operator disposition; pending network asks are mintable", () => {
  const vm = toPolicyPanelViewModel({
    ...BARE, ...EXT, ...DOC_EXT,
    usage: { rules: [{ id: "egress:untrusted-destination", source: "rule", boundary: "network", outcome: "deny+approval", summary: "s", gate: "egress" }], sensitivePaths: [] },
    verdicts: [
      verdict({ id: "p-net", status: "pending", destination: "https://api.github.com/repos", originHost: "docs.python.org" }),
      verdict({ id: "p-fs", status: "pending", symbol: "fs:Read:read", destination: "/etc/passwd", originHost: null }),
      verdict({ id: "p-anon", status: "pending", destination: "https://api.github.com/x", originHost: null }),
      verdict({ id: "done", status: "approved", destination: "https://api.github.com/repos", originHost: "docs.python.org" }),
    ],
  } as PolicySnapshot);
  const row = vm.gateGroups.flatMap((g: any) => g.rules).find((r) => r.id === "egress:untrusted-destination")!;
  assert.equal(row.hits, 7);
  assert.equal(row.disposition, "block");
  const byId = Object.fromEntries(vm.queue.map((q) => [q.id, q]));
  assert.deepEqual(byId["p-net"].mintable, { from: "docs.python.org", to: "https://api.github.com/repos" });
  assert.equal(byId["p-net"].originHost, "docs.python.org");
  assert.equal(byId["p-fs"].mintable, null, "a filesystem ask has no release-rule shape");
  assert.equal(byId["p-anon"].mintable, null, "no known origin → no one-click rule (too broad)");
  assert.equal(byId["done"].mintable, null, "only a PENDING ask is mintable");
});

test("stage 4b: destinations (connect: allow) render as 🔌 rows — a relaxation, next-launch wording; a pre-4b arbiter (no key) adds none", () => {
  const vm = toPolicyPanelViewModel({
    ...BARE, ...EXT, ...DOC_EXT,
    document: { ...DOC_EXT.document, userRules: [], paths: [], rules: {}, destinations: [
      { host: "registry.npmjs.org", port: 443, proto: "tcp", connect: "allow", reason: "installs" },
      { host: "10.0.0.0/8", port: "*", proto: "udp", connect: "allow" },
    ] },
    relaxations: [],
  } as PolicySnapshot);
  const rows = vm.yourRules!.filter((r) => r.kind === "connect-allow");
  assert.deepEqual(rows.map((r) => [r.id, r.subject, r.relaxes]), [
    ["connect:tcp:registry.npmjs.org:443", "registry.npmjs.org:443", true],
    ["connect:udp:10.0.0.0/8:*", "10.0.0.0/8:* (udp)", true],
  ]);
  assert.match(rows[0]!.effect, /from the next launch/);
  assert.ok(rows[0]!.detail.some((s) => s.items.some((i) => /reason: installs/.test(i.text))));
  assert.ok(rows[0]!.detail.some((s) => s.label === "What it does NOT do"), "sending stays a separate decision");
  const old = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT } as PolicySnapshot);
  assert.equal(old.yourRules!.filter((r) => r.kind === "connect-allow").length, 0);
});

test("§4.25u Rules names a connection in words: a connection row's plain subject is the rule-change card's words, its names as code parts", () => {
  const vm = toPolicyPanelViewModel({
    ...BARE, ...EXT, ...DOC_EXT,
    document: { ...DOC_EXT.document, userRules: [], paths: [], rules: {}, destinations: [
      { host: "*", port: 2222, proto: "tcp", connect: "allow" },
      { host: "*", port: "*", proto: "tcp", connect: "allow" },
      { host: "*.example.org", port: "*", proto: "tcp", connect: "allow" },
      { host: "10.0.0.0/8", port: 53, proto: "udp", connect: "allow" },
      { host: "*", port: 443, proto: "udp", connect: "allow" },
      { host: "registry.npmjs.org", port: 443, proto: "tcp", connect: "allow" },
      { host: "db.internal", port: 5432, proto: "tcp", connect: "deny" },
    ] },
    relaxations: [],
  } as PolicySnapshot);
  const rows = vm.yourRules!.filter((r) => r.kind === "connect-allow");
  const shown = (parts: Array<{ kind: string; text: string }>) => parts.map((p) => (p.kind === "code" ? `[${p.text}]` : p.text)).join("");
  assert.deepEqual(rows.map((r) => [r.id, r.plain.subject, shown(r.plain.subjectParts!)]), [
    ["connect:tcp:*:2222", "any address on port 2222", "any address on port [2222]"],
    ["connect:tcp:*:*", "any address on any port", "any address on any port"],
    ["connect:tcp:*.example.org:*", "*.example.org on any port", "[*.example.org] on any port"],
    ["connect:udp:10.0.0.0/8:53", "10.0.0.0/8:53 over UDP", "[10.0.0.0/8:53] over UDP"],
    ["connect:udp:*:443", "any address on port 443 over UDP", "any address on port [443] over UDP"],
    ["connect:tcp:registry.npmjs.org:443", "registry.npmjs.org:443", "[registry.npmjs.org:443]"],
  ], "the Approvals card's words (connectTarget); a deny entry is no row");
  for (const r of rows) {
    assert.equal(r.plain.subjectParts!.map((p) => p.text).join(""), r.plain.subject, `${r.id}: the parts are the subject, byte for byte`);
    assert.doesNotMatch(r.plain.subject, /\(udp\)|:\*/, `${r.id}: no protocol or wildcard code left in the words`);
  }
  // The rest of the row is what it was: the compiled subject, the id
  // Remove posts, a relaxation, the next-launch words.
  assert.deepEqual(rows.map((r) => r.subject), ["*:2222", "*:*", "*.example.org:*", "10.0.0.0/8:53 (udp)", "*:443 (udp)", "registry.npmjs.org:443"]);
  assert.ok(rows.every((r) => r.relaxes && r.plain.reach === "your agent's programs connecting" && r.plain.effect === "Always allowed, from the agent's next start"));
  // Every row's parts are its own: a page that edits one never changes another.
  const all = rows.flatMap((r) => r.plain.subjectParts!);
  assert.equal(new Set(all).size, all.length, "no part object shared between rows");
  // Every other kind sends no parts.
  const others = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT } as PolicySnapshot).yourRules!;
  // Every other kind sends no parts, but for the send rule to anywhere,
  // whose subject is a word (§4.25u, *Rules names what a send covers*).
  assert.ok(others.length > 0 && others.every((r) => r.plain.subjectParts === undefined || r.id === "ur-2"), "only a connection row has subject parts, and the send rule to anywhere");
  assert.deepEqual(others.find((r) => r.id === "ur-2")!.plain.subjectParts, [{ kind: "text", text: "anywhere" }]);
});

// ── plan 10: readers / apps on the law's rows; the held-open queue family ────
test("plan 10: a lock with readers says who reads raw and what the rest get; an apps: entry is a program-rule row; open:<app> is a filesystem verdict", () => {
  const doc = {
    ...DOC_EXT.document,
    paths: [
      { path: "/home/u/.pgpass", level: "no-model", bindings: ["db.internal:5432"], recursive: false, readers: ["ssh-add", { app: "ssh", path: "/usr/bin/ssh", sha256: "a".repeat(64) }] },
      { path: "/home/u/.netrc", level: "no-model", bindings: [], recursive: false, readers: [], others: "twin" as const },
      { path: "/home/u/pub.txt", level: "public", bindings: [], recursive: false },
    ],
    apps: [{ app: "ssh-add", output: "clear" as const }, { app: "aws", output: "mask" as const, mask: ["AKIA[0-9A-Z]{16}"] }],
  };
  const vm = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT, document: doc } as PolicySnapshot);
  const rows = vm.yourRules!;
  const pg = rows.find((r) => r.id === "lock:/home/u/.pgpass")!;
  assert.match(pg.effect, /raw readers: ssh-add, ssh \(pinned\) \(others are refused\)/);
  assert.ok(pg.detail.some((d) => d.label === "Raw readers (plan 10)" && d.items.some((i) => /ssh \(pinned\) may open the real file/.test(i.text))));
  const netrc = rows.find((r) => r.id === "lock:/home/u/.netrc")!;
  assert.match(netrc.effect, /raw readers: none \(others get the twin\)/);
  const pub = rows.find((r) => r.id === "lock:/home/u/pub.txt")!;
  assert.ok(!/raw readers/.test(pub.effect), "no reader list: nothing said");
  // Plan 13 D3: the program-wide rule is deprecated and clears nothing; the
  // row says the output is masked and where the rule belongs now.
  const sshAdd = rows.find((r) => r.id === "app:ssh-add")!;
  assert.equal(sshAdd.kind, "lock");
  assert.match(sshAdd.effect, /program rule: its whole output is masked for the AI/);
  assert.equal(sshAdd.relaxes, false, "a deprecated rule releases nothing");
  assert.match(sshAdd.warning ?? "", /no longer applies: it covered every file ssh-add reads.*output: clear.*readers:/);
  const aws = rows.find((r) => r.id === "app:aws")!;
  assert.match(aws.warning ?? "", /only spans matching AKIA\[0-9A-Z\]\{16\} masked/);
  assert.equal(verdictFamily("open:ssh-add"), "filesystem");
  assert.equal(verdictFamily(`open:/usr/bin/ssh-add#${"a".repeat(64)}`), "filesystem", "the row names the binary since Plan 13 D8");
  assert.equal(verdictFamily("write:bash"), "filesystem", "a held change to a file that runs later (finding 6)");
  assert.equal(pg.warning, undefined, "ssh-add and ssh are leaf programs: no warning");
});

test("plan 13 §8 decision (c): a held change by a program running code no pin names (a #run: row) offers no standing answer; a script's row does", () => {
  const h = "a".repeat(64);
  const vm = toPolicyPanelViewModel({
    ...BARE,
    ...EXT,
    verdicts: [
      verdict({ id: "run-1", symbol: `write:/usr/bin/bash#${h}#run:123-456`, destination: "/home/u/.bashrc", status: "pending", lastSeen: 50 }),
      verdict({ id: "scr-1", symbol: `write:/usr/bin/python3.12#${h}#script:%2Fopt%2Fa.py#${h}`, destination: "/home/u/.bashrc", status: "pending", lastSeen: 40 }),
    ],
  });
  const run = vm.queue.find((r) => r.id === "run-1")!;
  assert.deepEqual(run.actions, [{ approve: true, scope: "once", label: "Allow once" }, { approve: false, label: "Block" }], "no Always allow for one run");
  assert.equal(run.family, "filesystem");
  const scr = vm.queue.find((r) => r.id === "scr-1")!;
  assert.deepEqual(scr.actions.map((a) => a.label), ["Allow once", "Always allow", "Block"]);
});

test("Plan 13 D8, printers admit nothing (2026-10-03): a printer reader, pinned or cleared, is marked on the rule row and warned about", () => {
  const doc = {
    ...DOC_EXT.document,
    paths: [
      { path: "/home/u/ws/.env", level: "no-model", bindings: [], recursive: false, readers: [{ app: "cat", output: "clear" as const }, { app: "base64", path: "/usr/bin/base64", sha256: "a".repeat(64) }, "ssh-add"] },
    ],
  };
  const rows = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT, document: doc } as PolicySnapshot).yourRules!;
  const env = rows.find((r) => r.id === "lock:/home/u/ws/.env")!;
  assert.match(env.effect, /raw readers: cat \(admits nothing\), base64 \(admits nothing\), ssh-add \(others are refused\)/);
  assert.match(env.warning ?? "", /^cat, base64 print or copy what they read to whatever reads their output/);
  assert.doesNotMatch(env.effect, /output shown to the AI/);
});

test("Plan 13 D8 (13), P0 item 14: the rule row shows the arbiter's judgment of each reader entry, not the names it mirrors", () => {
  // A pin the name rule calls a leaf reader is, by the arbiter's host
  // hashes, a renamed copy of python3.12; a pin the human vouched for is
  // judged by the arbiter to read the twin; the newer arbiter's word wins.
  const pin = { app: "mytool", path: "/home/u/bin/mytool", sha256: "b".repeat(64), prints: "nothing" as const };
  const doc = {
    ...DOC_EXT.document,
    paths: [
      { path: "/home/u/ws/.env", level: "no-model", bindings: [], recursive: false, readers: [pin, "ssh-add", { app: "deploy", prints: "nothing" as const }],
        readersAdmitNothing: [true, false, false], readersReadTwin: [false, false, true], readersCopyOf: ["python3.12", null, null] },
      // an older arbiter: no judgment, the name rule
      { path: "/home/u/.pgpass", level: "no-model", bindings: [], recursive: false, readers: [pin, "nu"] },
    ],
  };
  const rows = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT, document: doc } as PolicySnapshot).yourRules!;
  const env = rows.find((r) => r.id === "lock:/home/u/ws/.env")!;
  assert.match(env.effect, /raw readers: mytool \(a copy of python3\.12\) \(admits nothing\), ssh-add, deploy \(reads the placeholder copy\) \(others are refused\)/);
  assert.match(env.warning ?? "", /mytool \(a copy of python3\.12\)/);
  const pg = rows.find((r) => r.id === "lock:/home/u/.pgpass")!;
  assert.match(pg.effect, /raw readers: mytool \(pinned\), nu \(admits nothing\) \(others are refused\)/, "nushell's binary runs code by name");
});

test("Plan 13 D3: a reader entry's own output rule shows beside it, for that file only; a shell's is not claimed", () => {
  const doc = {
    ...DOC_EXT.document,
    paths: [
      { path: "/home/u/.pgpass", level: "no-model", bindings: [], recursive: false, readers: [{ app: "ssh-add", output: "clear" as const }, { app: "aws", output: "mask" as const, mask: ["x"] }, "ssh", { app: "bash", output: "clear" as const }] },
    ],
  };
  const rows = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT, document: doc } as PolicySnapshot).yourRules!;
  const pg = rows.find((r) => r.id === "lock:/home/u/.pgpass")!;
  // plan 13 §8 decision (b): the shell admits nothing, and the row says so
  // plan 13 D8 (12): aws is no vetted reader, so it reads the placeholder copy
  assert.match(pg.effect, /raw readers: ssh-add \(output shown to the AI\), aws \(output partly masked\) \(reads the placeholder copy\), ssh, bash \(admits nothing\) \(others are refused\)/);
  assert.ok(pg.detail.some((d) => d.items.some((i) => /for this file only; a process holding another secret stays masked/.test(i.text))));
});

test("Plan 13 D8: a lock whose readers include a shell or an interpreter carries a warning naming them", () => {
  const doc = {
    ...DOC_EXT.document,
    paths: [
      { path: "/home/u/ws/.env", level: "no-model", bindings: [], recursive: false, readers: ["bash", "ssh-add", { app: "node", from: "make" }], others: "twin" as const },
      { path: "/home/u/.pgpass", level: "no-model", bindings: [], recursive: false, readers: ["ssh-add"] },
    ],
  };
  const rows = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT, document: doc } as PolicySnapshot).yourRules!;
  const env = rows.find((r) => r.id === "lock:/home/u/ws/.env")!;
  // plan 13 §8 decision (b): the entries admit nothing; the warning names the script pin
  assert.match(env.warning ?? "", /^bash, node run any code they are given, so they read nothing here: none of them gets the real file through these entries, inline code included/);
  assert.match(env.warning ?? "", /\{ app: bash, script: \/absolute\/path\/of\/the\/script \}/);
  assert.match(env.effect, /raw readers: bash \(admits nothing\), ssh-add, node \(admits nothing\)/);
  assert.equal(rows.find((r) => r.id === "lock:/home/u/.pgpass")!.warning, undefined);
});

test("Plan 13 R5: an interpreter pinned with its script is that program: named with the script, its output rule shown, no warning", () => {
  const doc = {
    ...DOC_EXT.document,
    paths: [
      { path: "/home/u/.pgpass", level: "no-model", bindings: [], recursive: false, readers: [{ app: "python3", script: "/opt/tools/report.py", output: "clear" as const, prints: "nothing" as const }] },
      { path: "/home/u/.env", level: "no-model", bindings: [], recursive: false, readers: [{ app: "python3", script: "/opt/tools/report.py" }, "python3"] },
    ],
  };
  const rows = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT, document: doc } as PolicySnapshot).yourRules!;
  const pg = rows.find((r) => r.id === "lock:/home/u/.pgpass")!;
  assert.match(pg.effect, /raw readers: python3 running \/opt\/tools\/report\.py \(output shown to the AI\) \(others are refused\)/);
  assert.equal(pg.warning, undefined, "the script pin is no code-running reader");
  const env = rows.find((r) => r.id === "lock:/home/u/.env")!;
  assert.match(env.warning ?? "", /^python3 runs any code it is given/, "a bare interpreter beside it still warns");
});

// ── dashboard.md §4.25d: the product page's words for each row ──────────────

test("§4.25p: a file rule's row says which programs may open the real file (plan 13 §5.3, Openers)", async () => {
  const { opensWords } = await import("../../../src/view-model/rule-words.js");
  const doc = {
    ...DOC_EXT.document,
    paths: [
      { path: "/home/u/.ssh/id_ed25519", level: "no-model", bindings: [], recursive: false, readers: [{ app: "ssh", from: "git" }] },
      { path: "/home/u/proj/.env", level: "no-model", bindings: ["api.stripe.com"], recursive: false, readers: [{ app: "deploy", prints: "nothing" }], others: "twin" },
      { path: "/home/u/.pgpass", level: "no-model", bindings: [], recursive: false, readers: ["psql"] },
      { path: "/home/u/notes", level: "any-model", bindings: [], recursive: true },
      { path: "/home/u/pub.txt", level: "public", bindings: [], recursive: false },
    ],
  };
  const vm = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT, document: doc } as PolicySnapshot);
  const opens = Object.fromEntries(vm.yourRules!.map((r) => [r.id, r.plain?.opens]));
  assert.equal(opens["lock:/home/u/.ssh/id_ed25519"], "ssh (checked by Mandu) may open the real file. Other programs are refused.");
  assert.equal(opens["lock:/home/u/proj/.env"], "deploy (your word) may open the real file. Other programs get a masked copy.");
  assert.match(opens["lock:/home/u/.pgpass"] ?? "", /^No program opens the real file\. psql never gets the real file: it prints or runs what it reads\./, "a database shell is never a reader");
  assert.equal(opens["lock:/home/u/notes"], "Programs get a masked copy.", "no readers: list");
  assert.equal(opens["lock:/home/u/pub.txt"], undefined, "Not secret has nothing to open");
  // The words alone: several of a kind, and a listed program that is neither vetted nor vouched for.
  assert.equal(opensWords([{ name: "ssh", how: "checked" }, { name: "ssh-add", how: "checked" }, { name: "aws", how: "masked" }]),
    "ssh (checked by Mandu) and ssh-add (checked by Mandu) may open the real file. aws gets a masked copy. Other programs are refused.");
  for (const r of vm.yourRules!) {
    if (r.plain?.opens) assert.doesNotMatch(r.plain.opens, /policy\.yaml|twin|taint|placeholder|reader/i, r.id);
  }
});

test("§4.25d: every row's plain words use the glossary's terms; the page's glossary is the same list", async () => {
  const { TERMS, GLOSSARY } = await import("../../../src/view-model/rule-words.js");
  const doc = {
    ...DOC_EXT.document,
    paths: [
      ...DOC_EXT.document.paths,
      { path: "/home/u/notes", level: "any-model", bindings: ["api.example.com"], recursive: true },
      { path: "**/ws-*/memo/**", level: "any-model", bindings: [], recursive: true, glob: true },
      { path: "/home/u/contracts", level: "local-model", bindings: [], recursive: true },
    ],
    userRules: [...DOC_EXT.document.userRules, { id: "ur-3", kind: "release", from: null, to: ["x.example"], mode: "audit", expires: null }],
    apps: [{ app: "ssh-add", output: "clear" }],
    destinations: [{ host: "registry.example", port: 443, proto: "tcp", connect: "allow" }],
  };
  const vm = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT, document: doc } as PolicySnapshot);
  const words = Object.fromEntries(vm.yourRules!.map((r) => [r.id, r.plain]));
  assert.deepEqual(words["lock:/home/u/.aws"], { subject: "/home/u/.aws", reach: "and everything inside", effect: "No AI", opens: "Programs get a masked copy." });
  assert.deepEqual(words["lock:/home/u/pub.txt"], { subject: "/home/u/pub.txt", reach: "this file only", effect: "Not secret" });
  assert.equal(words["lock:/home/u/notes"]!.effect, "Any AI, when it asks; may be sent to api.example.com");
  assert.equal(words["lock:**/ws-*/memo/**"]!.reach, "every matching file");
  assert.equal(words["lock:/home/u/contracts"]!.effect, "Your own AI only", "plan 11 D6: the third secret term");
  // §4.25f: a file rule says how far it reaches, for the page's folder tree.
  const covers = Object.fromEntries(vm.yourRules!.map((r) => [r.id, r.covers]));
  assert.equal(covers["lock:/home/u/.aws"], "subtree");
  assert.equal(covers["lock:/home/u/pub.txt"], "exact");
  assert.equal(covers["lock:**/ws-*/memo/**"], "pattern");
  assert.equal(covers["app:ssh-add"], undefined, "only file rules carry it");
  // §4.25n: the explorer's label buttons press the level in force and fill in its hosts.
  const byId = Object.fromEntries(vm.yourRules!.map((r) => [r.id, r]));
  assert.equal(byId["lock:/home/u/notes"]!.level, "any-model");
  assert.deepEqual(byId["lock:/home/u/notes"]!.bindings, ["api.example.com"]);
  assert.equal(byId["lock:/home/u/contracts"]!.level, "local-model");
  assert.equal(byId["app:ssh-add"]!.level, undefined, "only file rules carry it");
  assert.deepEqual(words["trusted-origin:url:https://docs.python.org/"], { subject: "https://docs.python.org/", reach: "a website", effect: "Trusted source, reaches the AI unmasked" });
  assert.deepEqual(words["ur-1"], { subject: "api.github.com", reach: "sending any masked data from docs.python.org", reachParts: [{ kind: "text", text: "sending any masked data from " }, { kind: "code", text: "docs.python.org" }], effect: "Always allowed" });
  assert.equal(words["ur-2"]!.effect, "Expired, no longer used");
  assert.equal(words["ur-3"]!.effect, "Only counted, still needs your OK");
  assert.deepEqual(words["disposition:egress:untrusted-destination"], { subject: "untrusted destination", reach: "a built-in protection", effect: "Always blocked, instead of asking you" });
  assert.deepEqual(words["app:ssh-add"], { subject: "ssh-add", reach: "a program", effect: "Its output is masked after it reads a secret file" }, "plan 13 D3: the program-wide clear is deprecated");
  assert.equal(words["connect:tcp:registry.example:443"]!.effect, "Always allowed, from the agent's next start");

  // One vocabulary: every effect is a glossary term, or says masked/unmasked,
  // expired or off, all of which the page explains or needs no explaining.
  const terms = Object.values(TERMS) as string[];
  for (const r of vm.yourRules!) {
    assert.ok(terms.some((t) => r.plain.effect.startsWith(t)) || /masked|Expired|Turned off|Only counted/.test(r.plain.effect), `${r.id}: ${r.plain.effect}`);
    assert.doesNotMatch(`${r.plain.subject} ${r.plain.reach} ${r.plain.effect}`, /policy\.yaml|release|disposition|egress|origin|taint|twin|—/i, r.id);
  }

  // The page's "What the words mean" list is exactly GLOSSARY, in order.
  const { readFileSync } = await import("node:fs");
  const { join, dirname } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const html = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "public", "index.html"), "utf8");
  const block = html.slice(html.indexOf('id="rules-glossary"'), html.indexOf("</details>", html.indexOf('id="rules-glossary"')));
  const pairs = [...block.matchAll(/<dt>(.*?)<\/dt><dd>(.*?)<\/dd>/g)].map((m) => ({ term: m[1], meaning: m[2] }));
  assert.deepEqual(pairs, GLOSSARY);
  // The explorer's label buttons (§4.25n) carry the same four levels with the
  // same meanings, in their tooltips.
  const js = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "public", "js", "home.js"), "utf8");
  for (const t of [TERMS.hidden, TERMS.ownModel, TERMS.readable, TERMS.notSecret]) {
    const meaning = GLOSSARY.find((g) => g.term === t)!.meaning;
    assert.ok(js.includes(`term: '${t}', meaning: '${meaning.replaceAll("'", "\\'")}'`), `label button: ${t}`);
  }
});

// ── dashboard.md §4.25f *A rule on a file reads as a file* ─────────────────────
test("§4.25f a rule on a file reads as a file: a subtree rule whose path is a file says \"this file only\" and keeps its reach for the page's edits", () => {
  const doc = {
    ...DOC_EXT.document,
    paths: [
      // As a saved Keys Mandu found suggestion writes it: no `recursive:` key.
      { path: "/home/u/proj/deploy.token", level: "no-model", bindings: [], recursive: true },
      { path: "/home/u/proj/secrets", level: "no-model", bindings: [], recursive: true },
      { path: "/home/u/proj/exact.token", level: "no-model", bindings: [], recursive: false },
      { path: "/home/u/proj/*.key", level: "no-model", bindings: [], recursive: true, glob: true },
    ],
  };
  // What server/path-kinds.ts found on disk (a pattern is never looked up,
  // so one in the set changes nothing).
  const files = new Set(["/home/u/proj/deploy.token", "/home/u/proj/exact.token", "/home/u/proj/*.key"]);
  const snap = { ...BARE, ...EXT, ...DOC_EXT, document: doc } as PolicySnapshot;
  const rows = Object.fromEntries(toPolicyPanelViewModel(snap, undefined, "", files).yourRules!.map((r) => [r.id, r]));
  const file = rows["lock:/home/u/proj/deploy.token"]!;
  assert.equal(file.plain.reach, "this file only", "never \"and everything inside\"");
  assert.equal(file.pathIsFile, true, "the page draws a file");
  assert.equal(file.covers, "subtree", "what the rule says: an edit on the page keeps it");
  const does = (r: typeof file) => r.detail.find((d) => d.label === "What it does")!.items[0]!.text;
  assert.equal(does(file), "/home/u/proj/deploy.token: the AI can't read it.");
  const folder = rows["lock:/home/u/proj/secrets"]!;
  assert.equal(folder.plain.reach, "and everything inside");
  assert.equal(folder.pathIsFile, undefined);
  assert.match(does(folder), /^\/home\/u\/proj\/secrets and everything under it: /);
  assert.equal(rows["lock:/home/u/proj/exact.token"]!.pathIsFile, undefined, "an exact rule is a file rule already");
  assert.equal(rows["lock:/home/u/proj/exact.token"]!.plain.reach, "this file only");
  assert.equal(rows["lock:/home/u/proj/*.key"]!.pathIsFile, undefined, "a pattern is never one file");
  assert.equal(rows["lock:/home/u/proj/*.key"]!.plain.reach, "every matching file");
  // Not looked at (no set): the words the rule says, as before.
  const unknown = toPolicyPanelViewModel(snap).yourRules!.find((r) => r.id === "lock:/home/u/proj/deploy.token")!;
  assert.equal(unknown.plain.reach, "and everything inside");
  assert.equal(unknown.pathIsFile, undefined);
});

test("§4.25d: a secret level's meaning promises no OK that its own row's \"may be sent to\" skips", async () => {
  const { TERMS, GLOSSARY, levelWords } = await import("../../../src/view-model/rule-words.js");
  // The row that made "It is not sent anywhere without your OK" false on the
  // same page: a bound file is sent to its host with no question asked.
  assert.equal(levelWords("any-model", ["api.example.com"]), "Any AI, when it asks; may be sent to api.example.com");
  for (const t of [TERMS.hidden, TERMS.ownModel, TERMS.readable]) {
    const meaning = GLOSSARY.find((g) => g.term === t)!.meaning;
    assert.match(meaning, /[Ii]t is sent only where a rule or your OK allows\.$/, t);
    assert.doesNotMatch(meaning, /without your OK|cannot leave|can't leave/, t);
  }
});

// ── dashboard.md §4.25e: a sending answer names the ONE piece of data it covers ─

test("§4.25e: an answer row says which data it covers, from the arbiter's read-time source; two answers to one host read differently", async () => {
  const { dataWords } = await import("../../../src/view-model/rule-words.js");
  const vm = toPolicyPanelViewModel({
    ...BARE,
    verdicts: [
      verdict({ id: "egr-5", symbol: "$MDU:Read[7d70].notes.md", destination: "notes-sink.test", source: { tool: "Read", origin: "/home/u/.local/state/mandu/watches/run-a/ws-i16/notes.md" } }),
      verdict({ id: "egr-9", symbol: "$MDU:Read[727f].notes.md", destination: "notes-sink.test", source: { tool: "Read", origin: "/home/u/ws/notes.md" } }),
      verdict({ id: "egr-8", symbol: "$MDU:anymodel_Read[d31e].x", destination: "httpbin.org", status: "denied", source: null }),
      verdict({ id: "egr-3", symbol: "fs:Read:read", destination: "/etc/shadow" }),
      verdict({ id: "egr-4", symbol: "exec-escalate:net", destination: "curl evil.test", status: "pending" }),
    ],
  } as PolicySnapshot, undefined, "/home/u");
  const plain = Object.fromEntries(vm.queue.map((q) => [q.id, q.plain]));
  assert.deepEqual(plain["egr-5"], { subject: "notes-sink.test", reach: "sending only the file \u2026/run-a/ws-i16/notes.md", reachParts: [{ kind: "text", text: "sending only the file " }, { kind: "code", text: "\u2026/run-a/ws-i16/notes.md" }], effect: "Always allowed" });
  assert.deepEqual(plain["egr-9"], { subject: "notes-sink.test", reach: "sending only the file ~/ws/notes.md", reachParts: [{ kind: "text", text: "sending only the file " }, { kind: "code", text: "~/ws/notes.md" }], effect: "Always allowed" });
  assert.notEqual(plain["egr-5"]!.reach, plain["egr-9"]!.reach, "two answers to one host are told apart");
  assert.deepEqual(plain["egr-8"], { subject: "httpbin.org", reach: "sending only the data you were asked about", effect: "Always blocked" }, "an older arbiter (no source) still says it is one piece");
  assert.deepEqual(plain["egr-3"], { subject: "/etc/shadow", reach: "opening this file", effect: "Always allowed" });
  assert.deepEqual(plain["egr-4"], { subject: "curl evil.test", reach: "running this command", effect: "Needs your OK" });

  // Each source shape in words; never the value, never a symbol token.
  assert.equal(dataWords({ tool: "WebFetch", origin: "https://httpbin.org/get?note=hello" }), "what was fetched from httpbin.org/get");
  assert.equal(dataWords({ tool: "WebFetch", origin: "https://example.com/" }), "what was fetched from example.com");
  assert.equal(dataWords({ tool: "Bash", origin: "cat   notes.md\n| head" }), "the output of \u201ccat notes.md | head\u201d");
  // Every agent's shell (tool-family.ts): OpenCode's bash and shell, OpenClaw's
  // exec, Goose's shell, Codex's shell_command, Claude Code's Monitor.
  for (const tool of ["bash", "shell", "exec", "shell_command", "exec_command", "Monitor"]) {
    assert.equal(dataWords({ tool, origin: "cat notes.md" }), "the output of \u201ccat notes.md\u201d", tool);
  }
  assert.equal(dataWords({ tool: "mcp__srv__get", origin: null }), "what the mcp__srv__get tool returned");
  assert.equal(dataWords({ tool: "Read", origin: "~/x.md" }), "the file ~/x.md");
  for (const q of vm.queue) assert.doesNotMatch(`${q.plain.subject} ${q.plain.reach}`, /\$MDU:|egress|verdict|—/);
});

test("§4.25u Rules names what a send covers: an answer's file, address or command, a program's files and a send rule's sources are code parts; \"anywhere\" is a word", async () => {
  const { dataParts, dataWords, holderAnswerWords } = await import("../../../src/view-model/rule-words.js");
  const shown = (parts: ReadonlyArray<{ kind: string; text: string }> | undefined) => parts?.map((p) => (p.kind === "code" ? `[${p.text}]` : p.text)).join("");
  const vm = toPolicyPanelViewModel({
    ...BARE,
    verdicts: [
      verdict({ id: "egr-1", symbol: "$MDU:nomodel_Read[9bbd].STRIPE_KEY", destination: "uploads.example-storage.net", status: "denied", source: { tool: "Read", origin: "/home/u/mandu-try/.env" } }),
      verdict({ id: "egr-2", symbol: "$MDU:WebFetch[1a2b].body", destination: "paste.example", source: { tool: "WebFetch", origin: "https://httpbin.org/get?x=1" } }),
      verdict({ id: "egr-3", symbol: "$MDU:Bash[3c4d].out", destination: "paste.example", source: { tool: "Bash", origin: "cat  notes.md" } }),
      verdict({ id: "egr-4", symbol: "$MDU:mcp[5e6f].x", destination: "paste.example", source: { tool: "mcp__srv__get", origin: null } }),
      verdict({ id: "egr-5", symbol: "$MDU:anymodel_Read[d31e].x", destination: "httpbin.org", source: null }),
      verdict({ id: "egr-6", symbol: "fs:Read:read", destination: "/etc/shadow" }),
      verdict({ id: "egr-7", symbol: "exec-escalate:net", destination: "curl evil.test" }),
    ],
    document: { ...DOC_EXT.document, paths: [], rules: {}, destinations: [], userRules: [
      { id: "ur-1", kind: "release", from: ["docs.python.org"], to: ["*"], mode: "allow", expires: null },
      { id: "ur-2", kind: "release", from: ["*.internal.example"], to: ["api.github.com"], mode: "block", expires: null },
      { id: "ur-3", kind: "release", from: null, to: ["b.example"], mode: "block", expires: null },
      { id: "ur-4", kind: "release", from: null, to: ["*"], mode: "block", expires: null },
      { id: "ur-5", kind: "release", from: [], to: ["c.example"], mode: "block", expires: null },
    ] },
    relaxations: [],
  } as PolicySnapshot, undefined, "/home/u");
  const plain = Object.fromEntries([...vm.queue.map((q) => [q.id, q.plain] as const), ...vm.yourRules!.map((r) => [r.id, r.plain] as const)]);
  assert.deepEqual(Object.fromEntries(Object.entries(plain).map(([id, p]) => [id, [p.reach, shown(p.reachParts) ?? null]])), {
    "egr-1": ["sending only the file ~/mandu-try/.env", "sending only the file [~/mandu-try/.env]"],
    "egr-2": ["sending only what was fetched from httpbin.org/get", "sending only what was fetched from [httpbin.org/get]"],
    "egr-3": ["sending only the output of \u201ccat notes.md\u201d", "sending only the output of \u201c[cat notes.md]\u201d"],
    "egr-4": ["sending only what the mcp__srv__get tool returned", null],
    "egr-5": ["sending only the data you were asked about", null],
    "egr-6": ["opening this file", null],
    "egr-7": ["running this command", null],
    "ur-1": ["sending any masked data from docs.python.org", "sending any masked data from [docs.python.org]"],
    "ur-2": ["sending any masked data from *.internal.example", "sending any masked data from [*.internal.example]"],
    "ur-3": ["sending any masked data", null],
    "ur-4": ["sending any masked data", null],
    "ur-5": ["sending any masked data", null],
  }, "a reach names its file, address, command or sources as code; one that names nothing has no parts");
  for (const [id, p] of Object.entries(plain)) {
    if (p.reachParts) assert.equal(p.reachParts.map((x) => x.text).join(""), p.reach, `${id}: the parts are the reach, byte for byte`);
    if (p.reachParts) assert.ok(p.reachParts.every((x, i) => i === 0 || x.kind !== "text" || p.reachParts![i - 1]!.kind !== "text"), `${id}: no two text parts in a row`);
  }
  // A send rule to `*` says "anywhere" as a word; to a host, the host's chip.
  assert.deepEqual([plain["ur-1"]!.subject, plain["ur-1"]!.subjectParts], ["anywhere", [{ kind: "text", text: "anywhere" }]]);
  assert.deepEqual([plain["ur-4"]!.subject, plain["ur-4"]!.subjectParts], ["anywhere", [{ kind: "text", text: "anywhere" }]]);
  assert.deepEqual([plain["ur-2"]!.subject, plain["ur-2"]!.subjectParts], ["api.github.com", undefined]);
  // The inspector's words are the old ones: each row's `subject` and `reach`.
  const rows = Object.fromEntries(vm.yourRules!.map((r) => [r.id, r]));
  assert.deepEqual([rows["ur-1"]!.subject, rows["ur-1"]!.reach], ["anywhere", "from docs.python.org to any destination"]);
  // Every row's parts are its own.
  const all = Object.values(plain).flatMap((p) => [...(p.reachParts ?? []), ...(p.subjectParts ?? [])]);
  assert.equal(new Set(all).size, all.length, "no part object shared between rows");

  // dataWords is dataParts' text, for every source shape.
  for (const src of [null, { tool: "Read", origin: "/home/u/x.md" }, { tool: "Read", origin: "/home/u/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/very-long-name.md" }, { tool: "WebFetch", origin: "https://example.com/" }, { tool: "WebFetch", origin: "https://exa mple" }, { tool: "bash", origin: "ls" }, { tool: "Grep", origin: "pattern" }]) {
    assert.equal(dataParts(src, "/home/u").map((p) => p.text).join(""), dataWords(src, "/home/u"), JSON.stringify(src));
  }
  // A program's files: each a code, the rest counted in words.
  const five = ["/home/u/a.csv", "/home/u/.env", "/srv/b.key", "/home/u/c", "/home/u/d"];
  const h = holderAnswerWords(five, "hooks.slack.com", "approved", "/home/u");
  assert.equal(h.reach, "a program in one session sending data from ~/a.csv, ~/.env, /srv/b.key and 2 more");
  assert.equal(shown(h.reachParts), "a program in one session sending data from [~/a.csv], [~/.env], [/srv/b.key] and 2 more");
  assert.equal(holderAnswerWords([], "hooks.slack.com", "approved").reachParts, undefined, "no file named: no parts");
});

test("§4.25u Rules names a held message's answer: the category is a code part, the words text; the reach names no part", async () => {
  const { promptAnswerWords } = await import("../../../src/view-model/rule-words.js");
  const shown = (parts: ReadonlyArray<{ kind: string; text: string }> | undefined) => parts?.map((p) => (p.kind === "code" ? `[${p.text}]` : p.text)).join("");
  const vm = toPolicyPanelViewModel({
    ...BARE,
    verdicts: [
      verdict({ id: "egr-1", symbol: "prompt:acme.codename#3f2a9c", destination: "model:1791210000-777", status: "approved", scope: "always" }),
      verdict({ id: "egr-2", symbol: "prompt:acme.codename#3f2a9c", destination: "model:1791210000-777#turn:01d1706f", status: "approved", scope: "always" }),
      verdict({ id: "egr-3", symbol: "prompt:secret.card#77aa01", destination: "model:1791210000-777", status: "denied", scope: "always" }),
    ],
  } as PolicySnapshot);
  const rows = Object.fromEntries(vm.queue.map((q) => [q.id, q]));
  assert.deepEqual(["egr-1", "egr-2", "egr-3"].map((id) => [rows[id]!.where, rows[id]!.plain.subject, shown(rows[id]!.plain.subjectParts), rows[id]!.plain.reach, rows[id]!.plain.reachParts]), [
    ["prompt", "acme.codename in your message to the AI", "[acme.codename] in your message to the AI", "as you wrote it, for that session", undefined],
    ["prompt", "acme.codename in your message to the AI", "[acme.codename] in your message to the AI", "as you wrote it, in that one message", undefined],
    ["prompt", "secret.card in your message to the AI", "[secret.card] in your message to the AI", "masked for that session", undefined],
  ], "the category as code, as the Approvals card names it; the words as text");
  for (const q of vm.queue) {
    assert.equal(q.plain.subjectParts!.map((x) => x.text).join(""), q.plain.subject, `${q.id}: the parts are the subject, byte for byte`);
  }
  const all = vm.queue.flatMap((q) => q.plain.subjectParts ?? []);
  assert.equal(new Set(all).size, all.length, "no part object shared between rows");
  // A key the row cannot read names no category: its words alone, no parts.
  assert.deepEqual(promptAnswerWords("prompt:", "model:s", "approved"), { subject: "a found part in your message to the AI", reach: "as you wrote it, for that session", effect: "Sent as written" });
});

test("§4.25u a held message's answer says what was sent: Sent as written / Sent masked, never Always allowed / Always blocked", async () => {
  const { promptAnswerWords, TERMS, GLOSSARY } = await import("../../../src/view-model/rule-words.js");
  const vm = toPolicyPanelViewModel({
    ...BARE,
    verdicts: [
      verdict({ id: "egr-1", symbol: "prompt:acme.codename#3f2a9c", destination: "model:1791210000-777", status: "approved", scope: "always" }),
      verdict({ id: "egr-2", symbol: "prompt:acme.codename#3f2a9c", destination: "model:1791210000-777#turn:01d1706f", status: "approved", scope: "always" }),
      verdict({ id: "egr-3", symbol: "prompt:secret.card#77aa01", destination: "model:1791210000-777", status: "denied", scope: "always" }),
      verdict({ id: "egr-4", symbol: "prompt:secret.card#77aa01", destination: "model:1791210000-777#turn:9c0d", status: "denied", scope: "always" }),
      verdict({ id: "egr-5", symbol: "fs:Read:read", destination: "/home/u/ws/notes.md", status: "denied", scope: "always" }),
    ],
  } as PolicySnapshot);
  const effect = Object.fromEntries(vm.queue.map((q) => [q.id, q.plain.effect]));
  assert.deepEqual(effect, { "egr-1": "Sent as written", "egr-2": "Sent as written", "egr-3": "Sent masked", "egr-4": "Sent masked", "egr-5": TERMS.blocked });
  // The glossary's *Always blocked* is "Stopped without asking you": a masked
  // message went, so its answer never borrows the term.
  assert.equal(GLOSSARY.find((g) => g.term === TERMS.blocked)!.meaning, "Stopped without asking you.");
  // Still waiting: the shared word.
  assert.equal(promptAnswerWords("prompt:acme.codename#3f2a9c", "model:s", "pending").effect, TERMS.ask);
});

test("§4.34 `~` is the dashboard's home: an answer's file is `~/…` under the page's home only; another account's home, or no home, stays as recorded", () => {
  const snap = {
    ...BARE,
    verdicts: [
      verdict({ id: "egr-1", symbol: "$MDU:Read[727f].notes.md", destination: "notes-sink.test", source: { tool: "Read", origin: "/home/u/ws/notes.md" } }),
      verdict({ id: "egr-2", symbol: "$MDU:Read[727e].notes.md", destination: "notes-sink.test", source: { tool: "Read", origin: "/home/alice/ws/notes.md" } }),
      verdict({ id: "egr-3", symbol: "$MDU:Read[727d].notes.md", destination: "notes-sink.test", source: { tool: "Read", origin: "/Users/u/ws/notes.md" } }),
      verdict({ id: "egr-4", symbol: "$MDU:Read[727c].notes.md", destination: "notes-sink.test", source: { tool: "Read", origin: "/home/user/ws/notes.md" } }),
    ],
  } as PolicySnapshot;
  const reach = (home?: string) => Object.fromEntries(toPolicyPanelViewModel(snap, undefined, home).queue.map((q) => [q.id, q.plain.reach]));
  const linux = reach("/home/u");
  assert.equal(linux["egr-1"], "sending only the file ~/ws/notes.md");
  assert.equal(linux["egr-2"], "sending only the file /home/alice/ws/notes.md", "another account's home folder is never `~`");
  assert.equal(linux["egr-4"], "sending only the file /home/user/ws/notes.md", "a home folder that only starts like the page's is another folder");
  assert.equal(reach("/Users/u")["egr-3"], "sending only the file ~/ws/notes.md", "a macOS home folder is `~` too");
  assert.equal(reach()["egr-1"], "sending only the file /home/u/ws/notes.md", "no home known: as recorded");
});

// ── plan 11 D2/D6: the declared models, read-only ───────────────────────────

test("plan 11: models are projected from document.models; [] with a document that declares none; null with no document", () => {
  const withModels = toPolicyPanelViewModel({
    ...BARE, ...EXT,
    document: { ...DOC_EXT.document, models: [
      { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
      { name: "zdr", url: "https://zdr.example", wire: "anthropic", local: false, tokenEnv: "ZDR_KEY" },
    ] },
  } as PolicySnapshot);
  assert.deepEqual(withModels.models!.map((m) => [m.name, m.where, m.wireWords, m.model, m.tokenEnv]), [
    ["ollama", "Your own model", "OpenAI chat", "llama3.2", null],
    ["zdr", "Outside model", "Anthropic Messages", null, "ZDR_KEY"],
  ]);
  const olderArbiter = toPolicyPanelViewModel({ ...BARE, ...EXT, ...DOC_EXT } as PolicySnapshot);
  assert.deepEqual(olderArbiter.models, [], "an arbiter predating plan 11 sends a document without models: none declared");
  assert.equal(toPolicyPanelViewModel({ ...BARE, ...EXT } as PolicySnapshot).models, null, "no document: unknown, not empty");
  assert.equal(toPolicyPanelViewModel(null).models, null);
});

test("plan 12 D4/D5: the administrator's layer and the perimeter are copied field by field; an older arbiter's files-and-lock shape still reads", () => {
  const vm = toPolicyPanelViewModel({
    ...BARE, ...EXT,
    document: { ...DOC_EXT.document, models: [],
      modelsAdmin: { files: ["/etc/mandu/policy.d/10-corp.yaml"], locked: true, conflicts: ["models[0]: 'mine' is local: true", 3], refused: [], removed: [{ name: "corp", file: "/etc/mandu/policy.d/10-corp.yaml" }, { name: 7 }], extra: "dropped" },
      perimeter: { networks: ["10.0.0.0/8"], domains: ["corp.example"], by: "administrator" } },
  } as unknown as PolicySnapshot);
  assert.deepEqual(vm.modelsAdmin, { files: ["/etc/mandu/policy.d/10-corp.yaml"], locked: true, conflicts: ["models[0]: 'mine' is local: true"], refused: [], removed: [{ name: "corp", file: "/etc/mandu/policy.d/10-corp.yaml" }] });
  assert.deepEqual(vm.perimeter, { networks: ["10.0.0.0/8"], domains: ["corp.example"], by: "administrator" });
  const older = toPolicyPanelViewModel({ ...BARE, ...EXT, document: { ...DOC_EXT.document, modelsAdmin: { files: ["/etc/mandu/policy.d/a.yaml"], locked: false } } } as unknown as PolicySnapshot);
  assert.deepEqual(older.modelsAdmin, { files: ["/etc/mandu/policy.d/a.yaml"], locked: false, conflicts: [], refused: [], removed: [] });
  assert.equal(older.perimeter, null);
});

test("plan 11: a local-model lock row says only your own model may read it, in both registers", () => {
  const vm = toPolicyPanelViewModel({
    ...BARE, ...EXT,
    document: { ...DOC_EXT.document, paths: [{ path: "/srv/contract.md", level: "local-model", bindings: ["api.example.com"], recursive: false }] },
  } as PolicySnapshot);
  const row = vm.yourRules!.find((r) => r.id === "lock:/srv/contract.md")!;
  assert.equal(row.plain!.effect, "Your own AI only; may be sent to api.example.com");
  assert.match(row.effect, /^only your own model may read it/);
});

test("§4.25d: the inspector's lock row for a file that may go to a host never says it can't leave, in the row or its detail", () => {
  const vm = toPolicyPanelViewModel({
    ...BARE, ...EXT,
    document: { ...DOC_EXT.document, paths: [
      { path: "/srv/acme/notes", level: "any-model", bindings: ["api.example.com"], recursive: true },
      { path: "/srv/contract.md", level: "local-model", bindings: ["api.example.com"], recursive: false },
    ] },
  } as PolicySnapshot);
  const rows = vm.yourRules!;
  const row = (id: string) => rows.find((r) => r.id === id)!;
  assert.equal(row("lock:/srv/acme/notes").effect, "the AI may read it — sent only where a rule or your OK allows · may go to api.example.com");
  assert.equal(row("lock:/srv/contract.md").effect,
    "only your own model may read it; sent only where a rule or your OK allows (this file only) · may go to api.example.com");
  const does = (id: string) => row(id).detail.find((d) => d.label === "What it does")!.items[0]!.text;
  assert.equal(does("lock:/srv/acme/notes"), "/srv/acme/notes and everything under it: the AI may read it — sent only where a rule or your OK allows.");
  for (const r of rows) {
    const all = [r.effect, ...r.detail.flatMap((d) => d.items.map((i) => i.text))].join("\n");
    assert.doesNotMatch(all, /can't leave|cannot leave|without your OK/, r.id);
  }
});

test("§4.25l: a local-model lock row warns while no model of your own is declared, and only then", () => {
  const lock = { path: "/srv/contract.md", level: "local-model", bindings: [], recursive: false };
  const strict = { path: "/srv/.env", level: "no-model", bindings: [], recursive: false };
  const rowsWith = (models: unknown) => toPolicyPanelViewModel({
    ...BARE, ...EXT,
    document: { ...DOC_EXT.document, paths: [lock, strict], ...(models === undefined ? {} : { models }) },
  } as PolicySnapshot).yourRules!;
  for (const models of [undefined, [], [{ name: "gw", url: "https://llm.example.com", wire: "anthropic", local: false }]]) {
    const rows = rowsWith(models);
    assert.equal(rows.find((r) => r.id === "lock:/srv/contract.md")!.warning, NO_OWN_MODEL_WARNING, JSON.stringify(models));
    assert.equal(rows.find((r) => r.id === "lock:/srv/.env")!.warning, undefined, "a strict lock needs no warning");
  }
  const own = rowsWith([{ name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", local: true }]);
  assert.equal(own.find((r) => r.id === "lock:/srv/contract.md")!.warning, undefined, "with a model of your own, no warning");
  assert.doesNotMatch(NO_OWN_MODEL_WARNING, /\b(egress|arbiter|symboliz|T-LLM|U-LLM)\b|—/);
});

test("§4.25p: a rule's warning comes as parts too, Settings › Models a link part; joined, the same words", () => {
  const joined = (parts: ReadonlyArray<{ text: string }>) => parts.map((x) => x.text).join("");
  const links = (parts: ReadonlyArray<{ kind: string }>) => parts.filter((x) => x.kind === "link");
  assert.equal(joined(NO_OWN_MODEL_WARNING_PARTS), NO_OWN_MODEL_WARNING, "the plain words are unchanged");
  assert.deepEqual(links(NO_OWN_MODEL_WARNING_PARTS), [{ kind: "link", text: "Settings › Models", to: "models" }]);
  const vm = toPolicyPanelViewModel({
    ...BARE, ...EXT,
    document: { ...DOC_EXT.document, paths: [
      { path: "/srv/contract.md", level: "local-model", bindings: [], recursive: false },
      { path: "/srv/db.md", level: "local-model", bindings: [], recursive: false, readers: ["psql"] },
      { path: "/srv/.pgpass", level: "no-model", bindings: [], recursive: false, readers: ["psql"] },
      { path: "/srv/.env", level: "no-model", bindings: [], recursive: false },
    ] },
  } as PolicySnapshot);
  const row = (id: string) => vm.yourRules!.find((r) => r.id === id)!;
  for (const r of vm.yourRules!) {
    if (r.warning) assert.equal(joined(r.warningParts!), r.warning, r.id);
    else assert.equal(r.warningParts, undefined, r.id);
  }
  assert.deepEqual(row("lock:/srv/contract.md").warningParts, [...NO_OWN_MODEL_WARNING_PARTS]);
  // Two warnings joined: the place still a link, the readers' words text.
  const db = row("lock:/srv/db.md");
  assert.ok(db.warning!.startsWith(NO_OWN_MODEL_WARNING + " "), db.warning);
  assert.equal(links(db.warningParts!).length, 1);
  // The readers' warning alone names no place: one text part, no link.
  const pg = row("lock:/srv/.pgpass");
  assert.ok(pg.warning, "psql runs what it reads: a warning");
  assert.deepEqual(pg.warningParts, [{ kind: "text", text: pg.warning }]);
  assert.equal(row("lock:/srv/.env").warning, undefined);
});
