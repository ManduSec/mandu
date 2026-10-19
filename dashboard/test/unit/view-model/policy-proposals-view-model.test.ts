/**
 * policy-proposals-view-model.test — the "Your agent wants to change a rule"
 * card grammar (policy-surface.md §8.6, dashboard.md §4.25).
 *
 * Pins:
 *   - every PolicyEdit op renders to a plain sentence (none falls to the
 *     "cannot describe" row), and an unknown op says it cannot be described;
 *   - the agent's reason is NEVER part of a row or a "This would let" line,
 *     even when the reason is word-for-word a row-like sentence;
 *   - every delta facet has plain "This would let" copy of its own (the
 *     arbiter's inspector-prose `detail` is not used);
 *   - over-broad rows (no limit on one side) are flagged for the typed ALLOW;
 *   - the change history words, Undo availability;
 *   - a file under the dashboard's home folder reads `~/…` in a row, a
 *     would-let line and a history row, as on the Rules page; any other path
 *     as recorded, another account's home folder included (§4.34 "`~` is
 *     the dashboard's home");
 *   - no inspector vocabulary in any of it (the §4.18 sweep).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  changeWarnings,
  editRow,
  editWords,
  isOverBroad,
  relaxLine,
  relaxWords,
  toChangeRow,
  changeWho,
  ruleOrigins,
  UNRECORDED_ORIGIN,
  type PolicyChangeRow,
  toProposalCard,
  type Part,
  type PolicyProposalRow,
} from "../../../src/view-model/policy-proposals.js";

const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter)\b|\$MDU:/i;
const text = (parts: Part[]) => parts.map((p) => p.text).join("");

const EVERY_OP: Array<[Record<string, unknown>, RegExp]> = [
  [{ op: "lock-path", path: "/srv/app/.env", level: "no-model" }, /^Make \/srv\/app\/\.env a secret no AI may read$/],
  [{ op: "lock-path", path: "/srv/app/notes", level: "any-model", bindings: ["api.example.com"], recursive: false }, /^Make \/srv\/app\/notes a secret any AI may read when it asks, may be sent to api\.example\.com \(this item only/],
  [{ op: "lock-path", path: "/srv/contract.md", level: "local-model" }, /^Make \/srv\/contract\.md a secret only your own AI may read$/],
  [{ op: "lock-path", path: "/srv/fixtures/.env", level: "public" }, /^Mark \/srv\/fixtures\/\.env not secret$/],
  [{ op: "unlock-path", path: "/srv/app/.env" }, /^Remove the rule for \/srv\/app\/\.env$/],
  [{ op: "lock-blob", blob: "sha1:3b18e512dba79e4c8300dd08aeb37f8e728b8dad", level: "no-model", note: "found in history: deploy/config.py" }, /^Hide the old file version sha1:3b18e512dba79e4c8300dd08aeb37f8e728b8dad from the AI in every project's history \(found in history: deploy\/config\.py\)$/],
  [{ op: "lock-blob", blob: "sha1:3b18e512dba79e4c8300dd08aeb37f8e728b8dad", level: "public" }, /^Mark the old file version sha1:3b18e512dba79e4c8300dd08aeb37f8e728b8dad not secret$/],
  [{ op: "unlock-blob", blob: "sha1:3b18e512dba79e4c8300dd08aeb37f8e728b8dad" }, /^Stop hiding the old file version sha1:3b18e512dba79e4c8300dd08aeb37f8e728b8dad$/],
  [{ op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }, /^Trust content from https:\/\/pypi\.org\/, so it reaches the AI unmasked$/],
  [{ op: "trust-origin", kind: "dir", pattern: "/srv/docs" }, /^Trust files under \/srv\/docs/],
  [{ op: "distrust-origin", kind: "channel", pattern: "C123" }, /^Always mask messages from C123$/],
  [{ op: "release", from: { host: "docs.python.org" }, to: { host: "api.example.com" }, mode: "allow" }, /^Always allow sending masked data from docs\.python\.org to api\.example\.com$/],
  [{ op: "release", to: { host: "pastebin.com" }, mode: "block", expires: "2026-12-01T00:00:00Z" }, /^Always block sending masked data from anywhere to pastebin\.com until 2026-12-01/],
  [{ op: "release", id: "r-0001", to: { host: "*" }, mode: "audit" }, /^Change rule r-0001: only count masked data sent from anywhere to anywhere, which still needs your OK$/],
  [{ op: "retire-rule", id: "r-0002" }, /^Remove rule r-0002$/],
  [{ op: "set-disposition", rule: "egress:untrusted-destination", mode: "block" }, /^Always block, without asking, what the built-in rule untrusted destination stops$/],
  [{ op: "set-disposition", rule: "egress:untrusted-destination", mode: "ask" }, /^Ask you again before the built-in rule untrusted destination/],
  [{ op: "allow-connect", host: "db.internal", port: 5432 }, /^Let your agent's programs connect to db\.internal:5432$/],
  [{ op: "remove-connect", host: "db.internal" }, /^Stop letting your agent's programs connect to db\.internal$/],
  [{ op: "trust-command", id: "git", trustHelp: true }, /^Show the AI the help text of git unmasked$/],
  [{ op: "trust-command", id: "git", trustHelp: false }, /^Mask the help text of git again$/],
  [{ op: "tool-inbound", tool: "WebFetch", trust: "TRUSTED" }, /^Show the AI results from the tool WebFetch unmasked$/],
  [{ op: "tool-inbound", tool: "WebFetch", trust: "UNTRUSTED" }, /^Mask results from the tool WebFetch$/],
  [{ op: "list", name: "svc", add: ["a.example"], remove: ["b.example"] }, /^Add a\.example to the list svc, and remove b\.example from it$/],
  [{ op: "add-model", name: "ollama", url: "http://127.0.0.1:11434/v1", wire: "openai-chat", model: "llama3.2", local: true, token_env: "OLLAMA_TOKEN" },
    /^Add the model ollama at http:\/\/127\.0\.0\.1:11434\/v1, as your own model, using llama3\.2, key from OLLAMA_TOKEN$/],
  [{ op: "update-model", name: "gw", url: "https://llm.example.com" }, /^Change the model gw to https:\/\/llm\.example\.com, as an outside model$/],
  [{ op: "remove-model", name: "gw" }, /^Remove the model gw$/],
  [{ op: "set-prompt-filter", filter: "key-shapes", on: true }, /^Turn on the prompt check key-shapes$/],
  [{ op: "set-prompt-filter", filter: "acme-dlp", on: false, on_error: "pass" }, /^Turn off the prompt check acme-dlp, and send the prompt unchecked when it cannot run$/],
  [{ op: "set-prompt-filter", filter: "cls", on: true, endpoint: "ollama" }, /^Turn on the prompt check cls, reading your prompts with your model ollama$/],
  [{ op: "set-prompt-filter", filter: "cls", on: true, endpoint: null }, /^Turn on the prompt check cls, with no model named \(it cannot run\)$/],
  [{ op: "set-prompt-action", category: "pii.payment-card", action: "block" }, /^In your prompts, pii\.payment-card stops the prompt from being sent$/],
  [{ op: "remove-prompt-action", category: "pii" }, /^Remove your own rule for pii in your prompts$/],
  [{ op: "add-prompt-exception", category: "pii.email", match: "*@example.com" }, /^Let pii\.email in your prompts through when it matches \*@example\.com$/],
  [{ op: "remove-prompt-exception", category: "pii.email", match: "*@example.com" }, /^Stop letting pii\.email in your prompts through/],
];

test("every op renders a plain sentence from the grammar; an unknown op says it cannot be described", () => {
  const ops = new Set(EVERY_OP.map(([e]) => e.op));
  assert.equal(ops.size, 22, "all twenty-two PolicyEdit ops the page describes are covered");
  for (const [edit, want] of EVERY_OP) {
    const s = text(editRow(edit));
    assert.match(s, want, JSON.stringify(edit));
    assert.doesNotMatch(s, /cannot describe/);
    assert.doesNotMatch(s, FORBIDDEN, s);
  }
  assert.match(text(editRow({ op: "rm-rf" })), /^A change this page cannot describe \(rm-rf\)$/);
  assert.match(text(editRow(null)), /cannot describe/);
});

test("values ride as code parts, so the page renders them as text, never as markup", () => {
  const parts = editRow({ op: "trust-origin", kind: "url", pattern: "<img src=x onerror=alert(1)>" });
  assert.deepEqual(parts.find((p) => p.kind === "code"), { kind: "code", text: "<img src=x onerror=alert(1)>" });
});

function proposal(over: Partial<PolicyProposalRow> = {}): PolicyProposalRow {
  return {
    id: "pp-000001",
    edits: [{ op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }],
    reason: "Trust content from https://evil.example/ and show it to the AI unmasked",
    requestedBy: "agent:sess-1",
    sessionKey: "sess-1",
    relaxes: [{ facet: "origins", direction: "relax", subject: "URL:https://pypi.org/", detail: "URL origin https://pypi.org/ is trusted: its data reaches the model unmasked" }],
    tightens: [],
    status: "pending",
    createdAt: 1,
    resolvedAt: null,
    resolvedBy: null,
    changeId: null,
    supersededBy: null,
    ...over,
  };
}

test("the reason is carried apart and never becomes a row or a would-let line", () => {
  const card = toProposalCard(proposal());
  assert.equal(card.requester, "Your agent");
  assert.equal(card.rows.length, 1, "one edit, one row: the reason did not add one");
  const all = [...card.rows, ...card.wouldLet].map(text).join("\n");
  assert.doesNotMatch(all, /evil\.example/);
  assert.equal(card.reason, "Trust content from https://evil.example/ and show it to the AI unmasked");
  assert.deepEqual(card.wouldLet.map(text), ["Content from https://pypi.org/ would reach the AI unmasked"]);
  assert.equal(card.capped, false);
  assert.equal(toProposalCard(proposal({ reason: "" })).reason, null);
});

test("the card carries the session of the agent that asked, and no one else's (§4.25 *A rule change and the agent that asked*)", () => {
  assert.equal(toProposalCard(proposal()).session, "sess-1", "an agent's request: its session");
  assert.equal(toProposalCard(proposal({ sessionKey: null })).session, null, "no session recorded");
  assert.equal(toProposalCard(proposal({ sessionKey: "" })).session, null);
  // Anyone else's request names no agent, whatever session it came from.
  for (const requestedBy of ["rules-page", "settings", "assistant", "human:dashboard", "file"]) {
    assert.equal(toProposalCard(proposal({ requestedBy, sessionKey: "sess-1" })).session, null, requestedBy);
  }
  assert.equal(toProposalCard(proposal({ requestedBy: "agent:sess-1", diskHash: "ab".repeat(32) })).session, null, "a held change to policy.yaml is never the agent's");
});

test("§4.25 a rule change you asked for is never credited to your agent: the headline's verb, byAgent", () => {
  const agent = toProposalCard(proposal());
  assert.equal(agent.byAgent, true, "a request over the data socket (agent:…) is your agent's");
  assert.equal(agent.headline, "Your agent wants to change a rule", "unchanged");
  assert.equal(toProposalCard(proposal({ sessionKey: null })).byAgent, true, "with no session recorded too");
  // Every name the product page writes as (applyAsHuman's requestedBy),
  // and the admin channel's default.
  for (const requestedBy of ["rules-page", "settings", "approvals-page", "dashboard", "human", "human:dashboard"]) {
    const card = toProposalCard(proposal({ requestedBy, sessionKey: null, reason: "Changed on the Rules page (remove)" }));
    assert.equal(card.requester, "You", requestedBy);
    assert.equal(card.headline, "You want to change a rule", requestedBy);
    assert.equal(card.byAgent, false, requestedBy);
    assert.equal(card.reason, "Changed on the Rules page (remove)", "the note is still carried, as text");
  }
  const assistant = toProposalCard(proposal({ requestedBy: "assistant", sessionKey: null }));
  assert.equal(assistant.headline, "The setup assistant wants to change a rule");
  assert.equal(assistant.byAgent, false);
  const disk = toProposalCard(proposal({ edits: [], reason: null, requestedBy: "file", sessionKey: null, diskHash: "ab".repeat(32) }));
  assert.equal(disk.byAgent, false, "a held change to policy.yaml");
  assert.equal(toProposalCard(proposal({ requestedBy: "agent:sess-1", diskHash: "ab".repeat(32) })).byAgent, false, "held on disk, whoever is named");
});

test("every delta facet has its own plain would-let copy (the arbiter's detail prose is not shown)", () => {
  const cases: Array<[string, string, RegExp]> = [
    ["paths", "/home/u/.ssh", /^\/home\/u\/\.ssh would be protected less$/],
    ["origins", "DIR:/srv/docs", /^Files under \/srv\/docs would reach the AI unmasked$/],
    ["origins", "CHANNEL:C1", /^Messages from C1 would reach/],
    ["origins", "URL:default", /unlisted places/],
    ["command-output", "git", /^Output of git would reach the AI unmasked$/],
    ["tools", "my_tool:resolve", /^The tool my_tool would send the real data out$/],
    ["tools", "my_tool.body", /^my_tool\.body would send the real data out$/],
    ["tools", "WebFetch", /^Results from the tool WebFetch would reach/],
    ["dispositions", "egress:untrusted-destination", /^The built-in rule untrusted destination would ask you instead of blocking$/],
    ["user-rules", "r-0001", /^Rule r-0001 would let more data leave without asking$/],
    ["destinations", "tcp:db.internal:5432", /^Your agent's programs could connect to db\.internal:5432$/],
    ["apps", "jq", /^jq's output would stay readable after it read a secret$/],
    ["env", "GITHUB_TOKEN", /^The environment variable GITHUB_TOKEN would be shown to the AI in the clear$/],
    ["models", "ollama", /^The models Mandu knows would change for ollama\. They decide which model counts as your own/],
    ["perimeter", "networks", /^Your own models on other computers would no longer be held to your organization's networks$/],
    ["perimeter", "10.0.0.0/8", /^A model at an address in 10\.0\.0\.0\/8 could count as on your organization's network$/],
    ["blob-lock", "sha1:3b18e512dba79e4c8300dd08aeb37f8e728b8dad", /^The old file version sha1:3b18e512dba79e4c8300dd08aeb37f8e728b8dad could be read by the AI again$/],
    ["prompt-filters", "prompt filter acme-dlp", /^Less of what you type would be checked before the AI reads it: prompt filter acme-dlp$/],
    ["prompt-filters", "prompt filter model local-classifier", /^Another model of your own would read what you type for the check local-classifier$/],
    ["law", "future_key", /^A change Mandu cannot check for you: future_key$/],
  ];
  for (const [facet, subject, want] of cases) {
    const s = text(relaxLine({ facet, subject }));
    assert.match(s, want, `${facet} ${subject}`);
    assert.doesNotMatch(s, FORBIDDEN, s);
  }
});

test("over-broad: an allow with no from or to *, a wildcard origin, a connect to any address", () => {
  assert.equal(isOverBroad([{ op: "release", to: { host: "api.example.com" }, mode: "allow" }]), true);
  assert.equal(isOverBroad([{ op: "release", from: { host: "docs.python.org" }, to: { host: "*" }, mode: "allow" }]), true);
  assert.equal(isOverBroad([{ op: "release", from: { host: "docs.python.org" }, to: { host: "api.example.com" }, mode: "allow" }]), false);
  assert.equal(isOverBroad([{ op: "release", to: { host: "*" }, mode: "block" }]), false, "a wide block is not a risk");
  assert.equal(isOverBroad([{ op: "trust-origin", kind: "url", pattern: "https://*.example.com/" }]), true);
  assert.equal(isOverBroad([{ op: "allow-connect", host: "*" }]), true);
  assert.equal(isOverBroad([{ op: "lock-path", path: "/x", level: "no-model" }]), false);
});

test("a proposal waiting only because of the tightening cap says so", () => {
  const card = toProposalCard(proposal({ relaxes: [], edits: [{ op: "lock-path", path: "/x.pem", level: "no-model" }] }));
  assert.equal(card.capped, true);
  assert.deepEqual(card.wouldLet, []);
});

test("history rows: who did it in plain words; Undo only where the arbiter says so; an undo lists what it moved", () => {
  const base = { requestedBy: "agent:s1", sessionKey: "s1", proposalId: null, createdAt: 5, undoneAt: null, undoneBy: null };
  const tight = toChangeRow({ ...base, id: "pc-000001", via: "agent-tighten", edits: [{ op: "lock-path", path: "/x.pem", level: "no-model" }], delta: [], undoable: true });
  assert.equal(tight.sentence, "Your agent tightened your rules");
  assert.equal(text(tight.rows[0]!), "Make /x.pem a secret no AI may read");
  assert.equal(tight.undoable, true);
  const approved = toChangeRow({ ...base, id: "pc-000002", via: "proposal", edits: [], delta: [{ facet: "origins", direction: "relax", subject: "URL:https://pypi.org/", detail: "" }], undoable: false, undoneAt: 9, undoneBy: "pc-000003" });
  assert.equal(approved.sentence, "You approved a change your agent asked for");
  assert.equal(approved.undone, true);
  const undo = toChangeRow({ ...base, id: "pc-000003", via: "undo", edits: [], delta: [{ facet: "paths", direction: "relax", subject: "/x.pem", detail: "" }], undoable: false });
  assert.equal(undo.sentence, "You undid an earlier change");
  assert.equal(text(undo.rows[0]!), "Loosened: /x.pem");
  for (const r of [tight, approved, undo]) assert.doesNotMatch([r.sentence, ...r.rows.map(text)].join("\n"), FORBIDDEN);
});

// ── dashboard.md §4.34: `~` is the dashboard's home ──────────────────────────

const HOME = "/home/alice";

test("§4.34 a file a rule names under the dashboard's home reads ~/…, as its Rules row does; any other path as recorded", () => {
  const cases: Array<[Record<string, unknown>, string, string]> = [
    [{ op: "lock-path", path: "/home/alice/proj/.env", level: "no-model" }, "Make ~/proj/.env a secret no AI may read", "~/proj/.env"],
    [{ op: "lock-path", path: "/home/alice/proj/notes", level: "any-model", bindings: ["api.example.com"], recursive: false }, "Make ~/proj/notes a secret any AI may read when it asks, may be sent to api.example.com (this item only, not what is inside it)", "~/proj/notes"],
    [{ op: "lock-path", path: "/home/alice/contract.md", level: "local-model" }, "Make ~/contract.md a secret only your own AI may read", "~/contract.md"],
    [{ op: "lock-path", path: "/home/alice/proj/fixtures/.env", level: "public" }, "Mark ~/proj/fixtures/.env not secret", "~/proj/fixtures/.env"],
    [{ op: "lock-path", path: "/home/alice/x", level: "weird" }, "Set ~/x to an unknown level", "~/x"],
    [{ op: "unlock-path", path: "/home/alice/proj/.env" }, "Remove the rule for ~/proj/.env", "~/proj/.env"],
    [{ op: "lock-path", path: "/home/alice", level: "no-model" }, "Make ~ a secret no AI may read", "~"],
    // Not under this home: as recorded, so `~` never names the wrong folder.
    [{ op: "lock-path", path: "/home/bob/proj/.env", level: "no-model" }, "Make /home/bob/proj/.env a secret no AI may read", "/home/bob/proj/.env"],
    [{ op: "lock-path", path: "/home/alice2/.env", level: "no-model" }, "Make /home/alice2/.env a secret no AI may read", "/home/alice2/.env"],
    [{ op: "lock-path", path: "/srv/app/.env", level: "no-model" }, "Make /srv/app/.env a secret no AI may read", "/srv/app/.env"],
    [{ op: "lock-path", path: "**/*.pem", level: "no-model" }, "Make **/*.pem a secret no AI may read", "**/*.pem"],
    [{ op: "lock-path", path: "~/already.env", level: "no-model" }, "Make ~/already.env a secret no AI may read", "~/already.env"],
    [{ op: "lock-path", path: "/home/alice/../bob/.env", level: "public" }, "Mark ~/../bob/.env not secret", "~/../bob/.env"],
  ];
  for (const [edit, want, path] of cases) {
    const parts = editWords(edit, HOME);
    assert.equal(text(parts), want, JSON.stringify(edit));
    assert.equal(parts.find((p) => p.kind === "code")?.text, path, "the path is a code part");
    // No home, or the root: every path as recorded, the sentence otherwise the same.
    for (const home of ["", "/"]) assert.equal(text(editWords(edit, home)), text(editRow(edit)), `${home || "no home"}: ${JSON.stringify(edit)}`);
    assert.equal(text(editRow(edit)), want.replace(path, String(edit.path)), "editRow writes the path as recorded");
  }
  // Only a rule's file: a value of another kind stays as written, even one
  // that starts with the home folder.
  for (const [edit] of EVERY_OP.filter(([e]) => e.op !== "lock-path" && e.op !== "unlock-path")) {
    assert.equal(text(editWords(edit, HOME)), text(editRow(edit)), JSON.stringify(edit));
  }
  const list = { op: "list", name: "svc", add: ["/home/alice/x"] };
  assert.equal(text(editWords(list, HOME)), "Add /home/alice/x to the list svc");
});

test("§4.34 a would-let line and a history row name a file under the home as ~/…; other facets and paths as recorded", () => {
  assert.equal(text(relaxWords({ facet: "paths", subject: "/home/alice/proj/.env" }, HOME)), "~/proj/.env would be protected less");
  assert.equal(text(relaxWords({ facet: "paths", subject: "/home/bob/.env" }, HOME)), "/home/bob/.env would be protected less");
  assert.equal(text(relaxWords({ facet: "paths", subject: "**/*.pem" }, HOME)), "**/*.pem would be protected less");
  assert.equal(text(relaxWords({ facet: "paths", subject: "/home/alice/proj/.env" }, "")), text(relaxLine({ facet: "paths", subject: "/home/alice/proj/.env" })));
  assert.equal(text(relaxLine({ facet: "paths", subject: "/home/alice/proj/.env" })), "/home/alice/proj/.env would be protected less");
  for (const facet of ["blob-lock", "command-output", "tools", "apps", "env", "destinations", "user-rules"]) {
    const r = { facet, subject: "/home/alice/bin/tool" };
    assert.equal(text(relaxWords(r, HOME)), text(relaxLine(r)), facet);
  }

  const card = toProposalCard(proposal({
    edits: [{ op: "lock-path", path: "/home/alice/proj/.env", level: "public" }, { op: "lock-path", path: "/home/bob/.env", level: "public" }],
    relaxes: [{ facet: "paths", direction: "relax", subject: "/home/alice/proj/.env", detail: "" }, { facet: "paths", direction: "relax", subject: "/home/bob/.env", detail: "" }],
  }), { home: HOME });
  assert.deepEqual(card.rows.map(text), ["Mark ~/proj/.env not secret", "Mark /home/bob/.env not secret"]);
  assert.deepEqual(card.wouldLet.map(text), ["~/proj/.env would be protected less", "/home/bob/.env would be protected less"]);
  const bare = toProposalCard(proposal({ edits: [{ op: "lock-path", path: "/home/alice/proj/.env", level: "public" }], relaxes: [{ facet: "paths", direction: "relax", subject: "/home/alice/proj/.env", detail: "" }] }));
  assert.deepEqual([...bare.rows, ...bare.wouldLet].map(text), ["Mark /home/alice/proj/.env not secret", "/home/alice/proj/.env would be protected less"], "no home: as recorded");

  const tight = toChangeRow(change({ via: "agent-tighten", requestedBy: "agent:s1", edits: [{ op: "lock-path", path: "/home/alice/proj/.env", level: "no-model" }] }), { home: HOME });
  assert.equal(text(tight.rows[0]!), "Make ~/proj/.env a secret no AI may read");
  const undo = toChangeRow(change({ via: "undo", delta: [
    { facet: "paths", direction: "relax", subject: "/home/alice/proj/.env", detail: "" },
    { facet: "paths", direction: "tighten", subject: "/home/bob/.env", detail: "" },
    { facet: "destinations", direction: "relax", subject: "/home/alice/odd", detail: "" },
  ] }), { home: HOME });
  assert.deepEqual(undo.rows.map(text), ["Loosened: ~/proj/.env", "Tightened: /home/bob/.env", "Loosened: /home/alice/odd"], "only a file is shortened");
  const disk = toChangeRow(change({ via: "disk", edits: [], delta: [{ facet: "paths", direction: "tighten", subject: "/home/alice/a.pem", detail: "" }] }), { home: HOME, patterns: false });
  assert.equal(text(disk.rows[0]!), "Tightened: ~/a.pem");
  assert.equal(text(toChangeRow(change({ via: "undo", delta: [{ facet: "paths", direction: "relax", subject: "/home/alice/proj/.env", detail: "" }] })).rows[0]!), "Loosened: /home/alice/proj/.env", "no home: as recorded");
});

// ── dashboard.md §4.25i: who put each rule there ──────────────────────────────

function change(over: Partial<PolicyChangeRow>): PolicyChangeRow {
  return {
    id: "pc-000001", via: "tighten", requestedBy: "rules-page", sessionKey: null, edits: [], delta: [], proposalId: null,
    createdAt: 1, undoneAt: null, undoneBy: null, undoable: true, proposedBy: null, rules: [], ...over,
  };
}

test("changeWho: the one who ASKED, from proposedBy; an older arbiter is read by the approver's name", () => {
  assert.equal(changeWho(change({ via: "agent-tighten", requestedBy: "agent:s1" })), "agent");
  assert.equal(changeWho(change({ via: "proposal", requestedBy: "dashboard", proposedBy: "agent:s1" })), "agent-approved");
  assert.equal(changeWho(change({ via: "proposal", requestedBy: "human:rules-page", proposedBy: "rules-page" })), "rules-page");
  assert.equal(changeWho(change({ via: "tighten", requestedBy: "rules-page" })), "rules-page");
  assert.equal(changeWho(change({ via: "proposal", requestedBy: "human:dashboard", proposedBy: "assistant" })), "describe");
  assert.equal(changeWho(change({ via: "tighten", requestedBy: "assistant" })), "describe");
  assert.equal(changeWho(change({ via: "tighten", requestedBy: "human" })), "you");
  assert.equal(changeWho(change({ via: "undo", requestedBy: "dashboard" })), "undo");
  // No proposedBy field at all (an arbiter predating it).
  const old = (requestedBy: string) => changeWho({ via: "proposal", requestedBy });
  assert.equal(old("human:rules-page"), "rules-page");
  assert.equal(old("human:dashboard"), "describe");
  assert.equal(old("dashboard"), "agent-approved");
});

test("history: a loosening made with Describe a rule is yours, not 'a change your agent asked for'", () => {
  assert.equal(toChangeRow(change({ via: "proposal", requestedBy: "human:dashboard", proposedBy: "assistant" })).sentence, "You changed your rules with Describe a rule");
  assert.equal(toChangeRow(change({ via: "proposal", requestedBy: "dashboard", proposedBy: "agent:s1" })).sentence, "You approved a change your agent asked for");
  assert.equal(toChangeRow(change({ via: "tighten", requestedBy: "rules-page" })).sentence, "You changed a rule on the Rules page");
  assert.equal(toChangeRow(change({ via: "tighten", requestedBy: "human" })).sentence, "You tightened your rules");
});

test("history: a change your agent made or asked for carries its session, and no one else's (§4.25 *A rule change and the agent that asked*)", () => {
  assert.equal(toChangeRow(change({ via: "agent-tighten", requestedBy: "agent:s1", sessionKey: "s1" })).session, "s1", "its own tightening");
  assert.equal(toChangeRow(change({ via: "proposal", requestedBy: "dashboard", proposedBy: "agent:s1", sessionKey: "s1" })).session, "s1", "its request, approved");
  assert.equal(toChangeRow({ ...change({ via: "proposal", requestedBy: "dashboard", sessionKey: "s1" }), proposedBy: undefined }).session, "s1", "an arbiter predating proposedBy");
  assert.equal(toChangeRow(change({ via: "agent-tighten", requestedBy: "agent:s1", sessionKey: null })).session, null, "no session recorded");
  assert.equal(toChangeRow(change({ via: "agent-tighten", requestedBy: "agent:s1", sessionKey: "" })).session, null);
  // Anyone else's change names no agent, whatever session it carries.
  for (const over of [
    { via: "tighten", requestedBy: "rules-page" },
    { via: "proposal", requestedBy: "human:settings", proposedBy: "settings" },
    { via: "proposal", requestedBy: "human:dashboard", proposedBy: "assistant" },
    { via: "tighten", requestedBy: "human" },
    { via: "undo", requestedBy: "dashboard" },
    { via: "disk", requestedBy: "file" },
    { via: "proposal", requestedBy: "dashboard", proposedBy: "file" },
    { via: "apply", requestedBy: "dashboard" },
    { via: "pin-reader", requestedBy: "mandu" },
    { via: "move-labels", requestedBy: "rules-page" },
  ] as const) {
    assert.equal(toChangeRow(change({ ...over, sessionKey: "s1" })).session, null, JSON.stringify(over));
  }
});

test("ruleOrigins: the newest change per row; the agent's session only for the agent; changed since; a removal reads as no record", () => {
  const origins = ruleOrigins([
    change({ id: "pc-000001", createdAt: 10, via: "proposal", requestedBy: "dashboard", proposedBy: "agent:sess-9", sessionKey: "sess-9",
      rules: [{ rowIds: ["r-0001"], added: true, removed: false, current: true }, { rowIds: ["lock:/w/.env"], added: true, removed: false, current: false }] }),
    change({ id: "pc-000003", createdAt: 30, via: "tighten", requestedBy: "rules-page",
      rules: [{ rowIds: ["r-0002"], added: false, removed: false, current: true }, { rowIds: ["connect:tcp:a.example:443"], added: false, removed: true, current: true }] }),
    change({ id: "pc-000002", createdAt: 20, via: "agent-tighten", requestedBy: "agent:sess-4", sessionKey: "sess-4",
      rules: [{ rowIds: ["r-0002"], added: true, removed: false, current: false }, { rowIds: ["connect:tcp:a.example:443"], added: true, removed: false, current: false }] }),
  ]);
  assert.deepEqual(origins["r-0001"], { recorded: true, sentence: "Your agent asked for this and you approved it", at: 10, session: "sess-9", changedSince: false });
  assert.equal(origins["lock:/w/.env"]!.changedSince, true);
  assert.deepEqual(origins["r-0002"], { recorded: true, sentence: "You changed this on the Rules page", at: 30, session: null, changedSince: false }, "the newest change wins, whatever the list order");
  assert.deepEqual(origins["connect:tcp:a.example:443"], UNRECORDED_ORIGIN, "removed by the newest change, yet the row exists: re-added by an unrecorded edit");
  assert.equal("r-0404" in origins, false);
  assert.deepEqual(ruleOrigins([change({ rules: undefined })]), {}, "an older arbiter names no rows");
  for (const o of Object.values(origins)) assert.doesNotMatch(o.sentence, FORBIDDEN);
  assert.match(ruleOrigins([change({ via: "agent-tighten", requestedBy: "agent:s", sessionKey: "s", rules: [{ rowIds: ["x"], added: true, removed: false, current: true }] })])["x"]!.sentence,
    /^Your agent added this\. It only makes your rules stricter, so it did not need your OK$/);
});

test("a suggestion of Mandu's scan applied on the agent's channel: never 'you', never a session (agent-tighten; an older arbiter's tighten by data-plane)", () => {
  const scan = { proposalId: "pp-000001", proposedBy: "mandu:scan", sessionKey: null, rules: [{ rowIds: ["lock:/w/id_rsa"], added: true, removed: false, current: true }] };
  for (const over of [{ via: "agent-tighten", requestedBy: "data-plane" }, { via: "tighten", requestedBy: "data-plane" }] as const) {
    const ch = change({ ...scan, ...over });
    assert.equal(changeWho(ch), "scan-applied", JSON.stringify(over));
    const row = toChangeRow(ch);
    assert.equal(row.sentence, "A rule Mandu suggested was applied from the terminal or by your agent");
    assert.equal(row.session, null);
    assert.doesNotMatch(row.sentence, FORBIDDEN);
    const origin = ruleOrigins([ch])["lock:/w/id_rsa"]!;
    assert.equal(origin.sentence, "Mandu suggested this, and it was applied from the terminal or by your agent. It only makes your rules stricter, so it did not need your OK");
    assert.equal(origin.session, null);
    assert.doesNotMatch(origin.sentence, FORBIDDEN);
  }
  // A person on the admin channel: applySuggestion names them (tighten), Approvals approves it (proposal): yours.
  assert.equal(changeWho(change({ ...scan, via: "tighten", requestedBy: "human:e2e" })), "you");
  assert.equal(changeWho(change({ ...scan, via: "proposal", requestedBy: "human:dashboard" })), "you");
  // The agent's own tightening (no suggestion) stays the agent's.
  assert.equal(changeWho(change({ via: "agent-tighten", requestedBy: "agent:s1", proposedBy: null })), "agent");
});

test("§4.25j: writes outside the policy surface: a hand edit (never 'you'), the developer view, Mandu pinning a program", () => {
  assert.equal(changeWho(change({ via: "disk", requestedBy: "file" })), "file");
  for (const via of ["apply", "mint-rule", "export-labels"] as const) assert.equal(changeWho(change({ via, requestedBy: "dashboard add-rule" })), "developer");
  assert.equal(changeWho(change({ via: "pin-reader", requestedBy: "arbiter" })), "mandu");
  assert.equal(toChangeRow(change({ via: "disk", requestedBy: "file", undoable: false })).sentence, "policy.yaml was edited directly, not through Mandu");
  assert.equal(toChangeRow(change({ via: "disk", requestedBy: "file", undoable: false })).undoable, false);
  // The inspector's mint names its area: "dashboard approvals" since the
  // Inbox → Approvals rename (2026-10-02); a record from before reads the same.
  for (const requestedBy of ["dashboard approvals", "dashboard inbox"]) {
    assert.equal(toChangeRow(change({ via: "mint-rule", requestedBy })).sentence, "You changed your rules in the developer view", requestedBy);
  }
  const o = ruleOrigins([
    change({ id: "pc-000001", createdAt: 1, via: "disk", requestedBy: "file", rules: [{ rowIds: ["lock:/a"], added: true, removed: false, current: true }, { rowIds: ["r-0001"], added: false, removed: false, current: true }] }),
    change({ id: "pc-000002", createdAt: 2, via: "mint-rule", requestedBy: "dashboard", rules: [{ rowIds: ["r-0002"], added: true, removed: false, current: true }] }),
    change({ id: "pc-000003", createdAt: 3, via: "pin-reader", requestedBy: "arbiter", rules: [{ rowIds: ["lock:/b"], added: false, removed: false, current: true }] }),
  ]);
  assert.equal(o["lock:/a"]!.sentence, "Added to policy.yaml directly, not through Mandu");
  assert.equal(o["r-0001"]!.sentence, "Changed in policy.yaml directly, not through Mandu");
  assert.equal(o["r-0002"]!.sentence, "You added this in the developer view");
  assert.equal(o["lock:/b"]!.sentence, "Mandu updated this when you let a program read the file");
  for (const v of Object.values(o)) {
    assert.equal(v.session, null, "no agent session for these");
    assert.doesNotMatch(v.sentence, FORBIDDEN);
  }
  assert.doesNotMatch(o["lock:/a"]!.sentence, /\byou\b/i, "who edited the file is unknown: never 'you'");
  assert.match(UNRECORDED_ORIGIN.sentence, /before Mandu kept a record, or was written while Mandu was not running$/);
});

test("§4.25m: the move of the page's older rules into policy.yaml reads as the person's, unchanged, and is not undoable", () => {
  const ch = change({ via: "move-labels", requestedBy: "human:rules-page", undoable: false, rules: [{ rowIds: ["lock:/a"], added: true, removed: false, current: true }] });
  assert.equal(changeWho(ch), "moved");
  const row = toChangeRow(ch);
  assert.equal(row.sentence, "You moved rules made on the Rules page into policy.yaml, unchanged");
  assert.equal(row.undoable, false);
  const o = ruleOrigins([ch]);
  assert.equal(o["lock:/a"]!.sentence, "You made this on the Rules page, and it was later moved into policy.yaml unchanged");
  assert.doesNotMatch(o["lock:/a"]!.sentence, FORBIDDEN);
});

test("plan 12 D2: a model change with allow_plain_http to another computer warns that files cross the network unencrypted", () => {
  const lan = { op: "add-model", name: "lab", url: "http://10.0.3.7:8000", local: true, allow_plain_http: true };
  const tunnel = { op: "add-model", name: "t", url: "http://127.0.0.1:18000", local: true, allow_plain_http: true };
  const w = changeWarnings([lan, tunnel, { ...lan, name: "no", allow_plain_http: undefined }]).map(text);
  assert.equal(w.length, 1, w.join("\n"));
  assert.match(w[0]!, /^lab is at a plain http address on another computer \(http:\/\/10\.0\.3\.7:8000\)\. Files marked .Your own AI only. would cross the network unencrypted\.$/);
  assert.doesNotMatch(w[0]!, FORBIDDEN);
});

test("a model change: the address in full; a warning and the typed confirmation for your own model off this machine", () => {
  const far = { op: "add-model", name: "lab", url: "http://203.0.113.9:8000", local: true };
  const near = { op: "add-model", name: "ollama", url: "http://127.0.0.1:11434", local: true };
  const lan = { op: "update-model", name: "box", url: "http://192.168.1.20:8000", local: true };
  const named = { op: "update-model", name: "box", url: "http://gpu-box:8000", local: true };
  const outside = { op: "add-model", name: "gw", url: "https://llm.example.com" };
  assert.deepEqual(changeWarnings([near, lan, outside, { op: "remove-model", name: "x" }]), [], "no warning on this machine, a local network, or for an outside model");
  const w = changeWarnings([far, named]).map(text);
  assert.equal(w.length, 2);
  assert.match(w[0]!, /^lab would count as your own model, but http:\/\/203\.0\.113\.9:8000 is not on this machine or a private network address\. Files marked .Your own AI only. could then be sent there\. Allow it only if you or your organization control that server\.$/);
  for (const line of w) assert.doesNotMatch(line, FORBIDDEN, line);
  assert.equal(isOverBroad([far]), true, "your own model off this machine needs the typed ALLOW");
  assert.equal(isOverBroad([near, outside]), false);
  const card = toProposalCard({
    id: "pp-000001", edits: [far], reason: null, requestedBy: "agent:s1", sessionKey: "s1",
    relaxes: [{ facet: "models", direction: "relax", subject: "lab", detail: "prose" }], tightens: [],
    status: "pending", createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
  });
  assert.equal(card.warnings.length, 1);
  assert.equal(card.overBroad, true);
  assert.match(text(card.rows[0]!), /http:\/\/203\.0\.113\.9:8000/, "the url is shown in full");
});

test("history: a change made in Settings says so, as the asker or (older arbiter) as the approver", () => {
  const base = { id: "pc-1", sessionKey: null, edits: [{ op: "remove-model", name: "gw" }], delta: [], proposalId: "pp-1", createdAt: 1, undoneAt: null, undoneBy: null, undoable: true };
  assert.equal(changeWho({ via: "proposal", requestedBy: "human:settings", proposedBy: "settings" }), "settings");
  assert.equal(changeWho({ via: "proposal", requestedBy: "human:settings" }), "settings");
  assert.equal(toChangeRow({ ...base, via: "proposal", requestedBy: "human:settings", proposedBy: "settings" }).sentence, "You changed your models in Settings");
});

test("§4.6 a held change to policy.yaml: its own headline, no rows, what it would let; never called 'you' or the agent", () => {
  const vm = toProposalCard(proposal({
    edits: [], reason: null, requestedBy: "file", sessionKey: null, diskHash: "ab".repeat(32),
    relaxes: [
      { facet: "user-rules", direction: "relax", subject: "hand", detail: "" },
      { facet: "destinations", direction: "relax", subject: "tcp:attacker.example:443", detail: "" },
    ],
  }));
  assert.equal(vm.onDisk, true);
  assert.equal(vm.requester, "policy.yaml");
  assert.equal(vm.headline, "policy.yaml was changed on disk and would loosen 2 rules. Nothing changes until you approve");
  assert.deepEqual(vm.rows, []);
  assert.equal(vm.wouldLet.length, 2);
  assert.equal(vm.capped, false);
  assert.equal(vm.reason, null);
  assert.doesNotMatch(vm.headline, FORBIDDEN);
  const one = toProposalCard(proposal({ edits: [], requestedBy: "file", diskHash: "cd".repeat(32) }));
  assert.match(one.headline, /would loosen 1 rule\. Nothing changes/);
  // An edit proposal is unchanged.
  const agent = toProposalCard(proposal());
  assert.equal(agent.onDisk, false);
  assert.equal(agent.headline, "Your agent wants to change a rule");
});

test("§4.6 history: a held change to policy.yaml you approved says so, as a row origin too", () => {
  const ch = change({ via: "proposal", requestedBy: "dashboard", proposedBy: "file", edits: [], delta: [{ facet: "user-rules", direction: "relax", subject: "hand", detail: "" }] });
  assert.equal(changeWho(ch), "file-approved");
  assert.equal(toChangeRow(ch).sentence, "You approved a change made to policy.yaml directly");
  const origins = ruleOrigins([{ ...ch, rules: [{ rowIds: ["hand"], added: true, removed: false, current: true }] }]);
  assert.equal(origins.hand!.sentence, "Added to policy.yaml directly, and you approved it");
  assert.equal(origins.hand!.session, null);
});

// ── dashboard.md §4.25u: *A rule change names each host* ─────────────────────

test("§4.25u a rule's hosts and a list's entries are one code each, \", \" between; the words are as one code said them", () => {
  const T = (s: string): Part => ({ kind: "text", text: s });
  const C = (s: string): Part => ({ kind: "code", text: s });
  const hosts = ["api.stripe.com", "db.internal:5432", "deploy-hooks.example.com"];
  const lock = editWords({ op: "lock-path", path: "/home/alice/proj/.env", level: "no-model", bindings: hosts, recursive: false }, HOME);
  assert.deepEqual(lock, [
    T("Make "), C("~/proj/.env"), T(" a secret no AI may read"),
    T(", may be sent to "), C("api.stripe.com"), T(", "), C("db.internal:5432"), T(", "), C("deploy-hooks.example.com"),
    T(" (this item only, not what is inside it)"),
  ]);
  assert.equal(text(lock), `Make ~/proj/.env a secret no AI may read, may be sent to ${hosts.join(", ")} (this item only, not what is inside it)`, "the words as before");
  // One host is one code, as before; no host, no list.
  assert.deepEqual(editRow({ op: "lock-path", path: "/p/k", level: "any-model", bindings: ["api.github.com"] }).slice(-2), [T(", may be sent to "), C("api.github.com")]);
  assert.deepEqual(editRow({ op: "lock-path", path: "/p/k", level: "no-model", bindings: [] }), [T("Make "), C("/p/k"), T(" a secret no AI may read")]);
  // Every level's sentence lists its hosts the same way.
  for (const level of ["no-model", "any-model", "local-model", "public", "weird"]) {
    const row = editRow({ op: "lock-path", path: "/p/k", level, bindings: ["a.example", "b.example"] });
    assert.deepEqual(row.slice(-4), [T(", may be sent to "), C("a.example"), T(", "), C("b.example")], level);
  }

  const list = editRow({ op: "list", name: "svc", add: ["a.example", "b.example"], remove: ["c.example", "d-e.example", "f.example"] });
  assert.deepEqual(list, [
    T("Add "), C("a.example"), T(", "), C("b.example"), T(" to the list "), C("svc"),
    T(", and remove "), C("c.example"), T(", "), C("d-e.example"), T(", "), C("f.example"), T(" from it"),
  ]);
  assert.equal(text(list), "Add a.example, b.example to the list svc, and remove c.example, d-e.example, f.example from it");
  assert.deepEqual(editRow({ op: "list", name: "svc", remove: ["x.example", "y.example"] }), [T("Remove "), C("x.example"), T(", "), C("y.example"), T(" from it")]);

  // A waiting card's rows and a Rule changes row carry the same parts.
  const edit = { op: "lock-path", path: "/home/alice/proj/.env", level: "no-model", bindings: hosts };
  const card = toProposalCard(proposal({ edits: [edit], relaxes: [{ facet: "paths", direction: "relax", subject: "/home/alice/proj/.env", detail: "" }] }), { home: HOME });
  const made = toChangeRow(change({ via: "proposal", edits: [edit] }), { home: HOME });
  for (const row of [card.rows[0]!, made.rows[0]!]) {
    assert.deepEqual(row.filter((p) => p.kind === "code").map((p) => p.text), ["~/proj/.env", ...hosts]);
    assert.ok(row.every((p) => p.kind !== "code" || !p.text.includes(", ")), "no code holds two names");
  }
  // Parts are never shared: drawing one row cannot change another.
  const twice = [editRow(edit), editRow(edit)];
  assert.ok(twice[0]!.every((p, i) => p !== twice[1]![i]));
});

test("§4.25u a connection rule names its port: any address, any port, a named host's code; UDP says so", () => {
  const T = (s: string): Part => ({ kind: "text", text: s });
  const C = (s: string): Part => ({ kind: "code", text: s });
  const LET = "Let your agent's programs connect to ";
  const STOP = "Stop letting your agent's programs connect to ";
  // [host, port, the words after "connect to "]: host `*` is "any address",
  // port `*` "any port"; a named host (a pattern, a list) keeps its code.
  const shapes: Array<[string, unknown, Part[]]> = [
    ["*", undefined, [T("any address")]],
    ["*", 22, [T("any address on port "), C("22")]],
    ["*", 443, [T("any address on port "), C("443")]],
    ["*", "*", [T("any address"), T(" on any port")]],
    ["*.example.org", "*", [C("*.example.org"), T(" on any port")]],
    ["db.internal", 5432, [C("db.internal:5432")]],
    ["pypi.org", undefined, [C("pypi.org")]],
    ["@registries", 443, [C("@registries:443")]],
  ];
  for (const [host, port, after] of shapes) {
    const edit = port === undefined ? { host } : { host, port };
    for (const [op, lead] of [["allow-connect", LET], ["remove-connect", STOP]] as const) {
      const row = editRow({ op, ...edit });
      assert.deepEqual(row, [T(lead), ...after], `${op} ${host}:${String(port)}`);
      // Never a bare `*` as a name, never a port dropped or written `:*`.
      assert.ok(row.every((p) => p.kind !== "code" || (p.text !== "*" && !p.text.startsWith("*:") && !p.text.endsWith(":*"))), text(row));
      if (typeof port === "number") assert.match(text(row), new RegExp(`\\b${port}$`), "the port is named");
    }
  }
  assert.equal(text(editRow({ op: "allow-connect", host: "*", port: 22 })), "Let your agent's programs connect to any address on port 22");
  assert.equal(text(editRow({ op: "remove-connect", host: "*", port: 2222 })), "Stop letting your agent's programs connect to any address on port 2222");

  // The would-let line reads the arbiter's `proto:host:port` the same way.
  const COULD = "Your agent's programs could connect to ";
  const specs: Array<[string, Part[]]> = [
    ["tcp:*:22", [T("any address on port "), C("22")]],
    ["tcp:*:443", [T("any address on port "), C("443")]],
    ["tcp:*:*", [T("any address"), T(" on any port")]],
    ["tcp:*.example.org:*", [C("*.example.org"), T(" on any port")]],
    ["udp:*:53", [T("any address on port "), C("53"), T(" over UDP")]],
    ["udp:dns.internal:53", [C("dns.internal:53"), T(" over UDP")]],
    ["tcp:db.internal:5432", [C("db.internal:5432")]],
    ["tcp:::1:8080", [C("::1:8080")]],
    // Not a subject the arbiter writes: shown as recorded, as before.
    ["tcp:pypi.org", [C("pypi.org")]],
    ["odd-subject", [C("odd-subject")]],
  ];
  for (const [subject, after] of specs) {
    const line = relaxLine({ facet: "destinations", subject });
    assert.deepEqual(line, [T(COULD), ...after], subject);
    assert.doesNotMatch(text(line), FORBIDDEN);
  }

  // A waiting card says one thing on both lines: what the agent asked, and
  // what that would let, port and all.
  const card = toProposalCard(proposal({
    edits: [{ op: "allow-connect", host: "*", port: 22 }, { op: "allow-connect", host: "*" }],
    relaxes: [
      { facet: "destinations", direction: "relax", subject: "tcp:*:22", detail: "the agent's processes may connect to tcp:*:22" },
      { facet: "destinations", direction: "relax", subject: "tcp:*:443", detail: "the agent's processes may connect to tcp:*:443" },
    ],
  }));
  assert.deepEqual(card.rows.map(text), [`${LET}any address on port 22`, `${LET}any address`]);
  assert.deepEqual(card.wouldLet.map(text), [`${COULD}any address on port 22`, `${COULD}any address on port 443`]);
  assert.equal(card.overBroad, true, "the typed ALLOW is asked as before");
  // A change made reads the same as the card that asked for it.
  const made = toChangeRow(change({ via: "proposal", edits: [{ op: "allow-connect", host: "*", port: "*" }] }));
  assert.deepEqual(made.rows.map(text), [`${LET}any address on any port`]);
});
