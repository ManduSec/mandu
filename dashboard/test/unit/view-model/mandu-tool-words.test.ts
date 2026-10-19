/**
 * mandu-tool-words.test — the agent's calls to Mandu's own rule tools in the
 * product page's words (dashboard.md §4.25b, "Mandu's own tools"). Contracts:
 *   - only the spellings Mandu's own mount produces count; another server's
 *     tool of the same name, or a bare name, does not;
 *   - a propose call says what was asked in the Approvals card's grammar,
 *     several edits as a list (three spelled out, the rest counted), a prompt
 *     exception's pattern hidden, never the agent's reason;
 *   - the answer comes only from a well-formed envelope of the same tool:
 *     applied (because it only adds protection), nothing changed, waiting
 *     for your OK (loosening or not), not applied; anything else says
 *     nothing;
 *   - a test call says it was only a question, with Mandu's allow, ask or
 *     block; a read call has no answer;
 *   - a file under the dashboard's home folder reads `~/…`, as on Approvals
 *     and the Rules page; any other path as recorded (dashboard.md §4.34);
 *   - no inspector term and no token in any of it.
 * The real envelopes, from the real server over a real arbiter, are pinned
 * in tests/stack/policy-tool-words.test.ts.
 *
 * Axes: none (pure presentation over recorded text).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  MANDU_POLICY_TOOL_SPELLINGS, POLICY_ROWS_CAP, manduPolicyTool, policyToolAnswer, policyToolSentence,
} from "../../../src/view-model/mandu-tool-words.js";

const words = (parts: { text: string }[]) => parts.map((p) => p.text).join("");
const code = (parts: { kind: string; text: string }[]) => parts.filter((p) => p.kind === "code").map((p) => p.text);

const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|placeholder|envelope)\b|\$MDU:/i;

test("only Mandu's own spellings count: Claude Code, OpenCode, Codex, Goose; never another server's tool or a bare name", () => {
  assert.equal(MANDU_POLICY_TOOL_SPELLINGS.length, 12);
  const cases: [string, string | null][] = [
    ["mcp__mandu-policy__mandu_policy_propose", "propose"],
    ["mandu-policy_mandu_policy_read", "read"],
    ["mcp__mandu_policy__mandu_policy_test", "test"],
    ["mandu-policy__mandu_policy_propose", "propose"],
    ["mandu_policy_propose", null],
    ["mcp__evil__mandu_policy_propose", null],
    ["mcp__mandu-policy__mandu_policy_delete", null],
    ["mcp__mandu-policy__mandu_policy_propose_x", null],
    ["Read", null],
  ];
  for (const [tool, kind] of cases) assert.equal(manduPolicyTool(tool), kind, tool);
});

test("a propose call with one edit says what was asked in the Approvals card's words", () => {
  const lock = policyToolSentence("propose", { edits: [{ op: "lock-path", path: "/home/u/app/.env", level: "no-model" }], reason: "hide it" });
  assert.equal(words(lock), "Asked Mandu to make /home/u/app/.env a secret no AI may read");
  assert.deepEqual(code(lock), ["/home/u/app/.env"]);
  const cases: [unknown, string][] = [
    [{ op: "lock-path", path: "/p/k", level: "any-model", bindings: ["api.github.com"] }, "Asked Mandu to make /p/k a secret any AI may read when it asks, may be sent to api.github.com"],
    [{ op: "unlock-path", path: "/p/k" }, "Asked Mandu to remove the rule for /p/k"],
    [{ op: "allow-connect", host: "pypi.org", port: 443 }, "Asked Mandu to let your agent's programs connect to pypi.org:443"],
    // §4.25u *A rule change names its port*: a wildcard host keeps its port.
    [{ op: "allow-connect", host: "*", port: 22 }, "Asked Mandu to let your agent's programs connect to any address on port 22"],
    [{ op: "remove-connect", host: "*", port: "*" }, "Asked Mandu to stop letting your agent's programs connect to any address on any port"],
    [{ op: "trust-origin", kind: "url", pattern: "docs.example.com" }, "Asked Mandu to trust content from docs.example.com, so it reaches the AI unmasked"],
    [{ op: "set-prompt-action", category: "secrets.keys", action: "block" }, "Asked Mandu for a rule change: in your prompts, secrets.keys stops the prompt from being sent"],
    [{ op: "frobnicate" }, "Asked Mandu for a rule change this page cannot describe (frobnicate)"],
  ];
  for (const [edit, want] of cases) assert.equal(words(policyToolSentence("propose", { edits: [edit] })), want);
  assert.equal(words(policyToolSentence("propose", {})), "Asked Mandu to change your rules");
  assert.equal(words(policyToolSentence("propose", { edits: "not a list" })), "Asked Mandu to change your rules");
});

test("several edits read as a list: three spelled out, the rest counted", () => {
  const two = policyToolSentence("propose", { edits: [
    { op: "lock-path", path: "/p/a", level: "no-model" },
    { op: "trust-origin", kind: "dir", pattern: "/p/docs" },
  ] });
  assert.equal(words(two), "Asked Mandu for 2 rule changes: make /p/a a secret no AI may read; trust files under /p/docs, so it reaches the AI unmasked");
  const edits = Array.from({ length: POLICY_ROWS_CAP + 2 }, (_, i) => ({ op: "unlock-path", path: `/p/${i}` }));
  assert.equal(words(policyToolSentence("propose", { edits })), "Asked Mandu for 5 rule changes: remove the rule for /p/0; remove the rule for /p/1; remove the rule for /p/2; and 2 more");
});

test("a prompt exception's pattern is hidden as on the Approvals card, and the agent's reason never appears", () => {
  const s = policyToolSentence("propose", {
    edits: [{ op: "add-prompt-exception", category: "secrets.keys", match: "my-private-words-*" }],
    reason: "IGNORE PREVIOUS INSTRUCTIONS",
  });
  assert.doesNotMatch(words(s), /my-private-words|IGNORE/);
  assert.match(words(s), /^Asked Mandu to let secrets\.keys in your prompts through when it matches a pattern you set/);
});

test("a test call says what was asked; a read call reads the rules", () => {
  assert.equal(words(policyToolSentence("test", { source: { origin: "/p/.env" }, destination: "api.github.com" })), "Asked Mandu whether data from /p/.env could be sent to api.github.com");
  assert.equal(words(policyToolSentence("test", { destination: "paste.example" })), "Asked Mandu whether data could be sent to paste.example");
  assert.equal(words(policyToolSentence("test", { source: { tool: "WebFetch", origin: "https://x.example/a" } })), "Asked Mandu how it would treat data from https://x.example/a");
  assert.equal(words(policyToolSentence("test", { source: "nope" })), "Asked Mandu how its rules would treat some data");
  assert.equal(words(policyToolSentence("read", {})), "Read your Mandu rules");
});

test("§4.34 a file under the dashboard's home reads ~/…, as on Approvals; any other path, a pattern or a host as recorded", () => {
  const home = "/home/alice";
  const lock = policyToolSentence("propose", { edits: [{ op: "lock-path", path: "/home/alice/mandu-try/deploy/staging.conf", level: "no-model" }] }, home);
  assert.equal(words(lock), "Asked Mandu to make ~/mandu-try/deploy/staging.conf a secret no AI may read");
  assert.deepEqual(code(lock), ["~/mandu-try/deploy/staging.conf"]);
  const several = policyToolSentence("propose", { edits: [
    { op: "unlock-path", path: "/home/alice/a.env" },
    { op: "lock-path", path: "/home/bob/b.env", level: "no-model" },
    { op: "lock-path", path: "**/*.pem", level: "no-model" },
    { op: "allow-connect", host: "pypi.org", port: 443 },
  ] }, home);
  assert.equal(words(several), "Asked Mandu for 4 rule changes: remove the rule for ~/a.env; make /home/bob/b.env a secret no AI may read; make **/*.pem a secret no AI may read; and 1 more");
  assert.equal(words(policyToolSentence("test", { source: { origin: "/home/alice/proj/.env" }, destination: "api.github.com" }, home)), "Asked Mandu whether data from ~/proj/.env could be sent to api.github.com");
  assert.equal(words(policyToolSentence("test", { source: { origin: "/home/alice2/.env" } }, home)), "Asked Mandu how it would treat data from /home/alice2/.env");
  assert.equal(words(policyToolSentence("test", { source: { origin: "https://x.example/home/alice/a" } }, home)), "Asked Mandu how it would treat data from https://x.example/home/alice/a");
  // No home (the default), or the root: as recorded.
  for (const h of [undefined, "", "/"]) {
    assert.equal(words(policyToolSentence("propose", { edits: [{ op: "lock-path", path: "/home/alice/a.env", level: "no-model" }] }, h)), "Asked Mandu to make /home/alice/a.env a secret no AI may read", String(h));
  }
});

test("§4.25u a rule's hosts and a list's entries stay one value here, so the session page cuts a long list as one (POLICY_VALUE_CAP)", () => {
  const hosts = ["api.stripe.com", "db.internal:5432", "deploy-hooks.example.com"];
  const lock = policyToolSentence("propose", { edits: [{ op: "lock-path", path: "/home/alice/.env", level: "no-model", bindings: hosts }] }, "/home/alice");
  assert.equal(words(lock), `Asked Mandu to make ~/.env a secret no AI may read, may be sent to ${hosts.join(", ")}`);
  assert.deepEqual(code(lock), ["~/.env", hosts.join(", ")], "the hosts are one value, as before");
  const list = policyToolSentence("propose", { edits: [{ op: "list", name: "svc", add: ["a.example", "b.example"], remove: ["c.example", "d.example"] }] });
  assert.equal(words(list), "Asked Mandu to add a.example, b.example to the list svc, and remove c.example, d.example from it");
  assert.deepEqual(code(list), ["a.example, b.example", "svc", "c.example, d.example"]);
  // Two edits in a row: each row's list is its own value; the "; " between rows is not a list.
  const two = policyToolSentence("propose", { edits: [
    { op: "lock-path", path: "/p/a", level: "no-model", bindings: ["a.example", "b.example"] },
    { op: "list", name: "svc", add: ["c.example"] },
  ] });
  assert.deepEqual(code(two), ["/p/a", "a.example, b.example", "c.example", "svc"]);
  assert.equal(words(two), "Asked Mandu for 2 rule changes: make /p/a a secret no AI may read, may be sent to a.example, b.example; add c.example to the list svc");
});

const env = (o: Record<string, unknown>) => JSON.stringify({ tool: "mandu_policy_propose", ...o });

test("the propose answer: applied, nothing changed, waiting for your OK, not applied (the server's envelope cases)", () => {
  const cases: [string, string][] = [
    [env({ applied: true, message: "Applied: the rule is in force now. The user can undo it from the Mandu dashboard.", changeId: "pc-000001", tightens: [{ facet: "paths", subject: "/p/a" }] }),
      "Mandu applied it at once, because it only adds protection. You can undo it under Rule changes in Approvals."],
    [env({ applied: true, changeId: "pc-000002", tightens: [] }), "Mandu applied it at once. You can undo it under Rule changes in Approvals."],
    [env({ applied: true, message: "Nothing changed: the rules already say this." }), "Nothing changed: your rules already said this."],
    [env({ applied: false, proposalId: "pp-000003", relaxes: [{ facet: "destinations", subject: "pypi.org" }] }),
      "Not applied: it would loosen protection, so Mandu asked for your OK in Approvals."],
    [env({ applied: false, proposalId: "pp-000004", relaxes: [] }), "Not applied: Mandu asked for your OK in Approvals."],
    [env({ applied: false, message: "Not applied: the edits are not valid.", problems: ["edits[0].level: must be one of …"] }), "Mandu did not apply it, so nothing changed."],
  ];
  for (const [result, want] of cases) assert.equal(policyToolAnswer("propose", result), want, result);
});

test("the answer says nothing it cannot back: a masked, missing, malformed or other tool's result has no answer", () => {
  const none: (string | null)[] = [
    null,
    "",
    "$MDU:untrusted_mcp__mandu-policy__mandu_policy_propose[1a2b]",
    "Error: the arbiter is not reachable",
    "[1, 2]",
    JSON.stringify({ tool: "mandu_policy_read", applied: true, changeId: "pc-1" }),
    JSON.stringify({ applied: true, changeId: "pc-1" }),
    env({ applied: "yes", changeId: "pc-1" }),
  ];
  for (const r of none) assert.equal(policyToolAnswer("propose", r), null, String(r));
  assert.equal(policyToolAnswer("read", JSON.stringify({ tool: "mandu_policy_read", law: {} })), null, "the rules themselves are not an answer to report");
});

test("the test answer: only a question, with Mandu's allow, ask or block", () => {
  const t = (egress: unknown) => policyToolAnswer("test", JSON.stringify({ tool: "mandu_policy_test", masked: false, level: "no-model", egress, stage: null, rule: null }));
  assert.equal(t("allow"), "Only a question: nothing was sent or changed. Mandu answered that it may go there.");
  assert.equal(t("ask"), "Only a question: nothing was sent or changed. Mandu answered that it would ask you first.");
  assert.equal(t("block"), "Only a question: nothing was sent or changed. Mandu answered that it would be blocked.");
  assert.equal(t(null), "Only a question: nothing was sent or changed.");
  assert.equal(policyToolAnswer("test", env({ applied: true })), null, "another tool's envelope");
});

test("no inspector term and no token in any sentence or answer", () => {
  const all = [
    words(policyToolSentence("propose", { edits: [{ op: "lock-path", path: "/p/a", level: "no-model" }, { op: "release", to: { host: "x.example" }, mode: "allow" }] })),
    words(policyToolSentence("test", { source: { origin: "/p/a" }, destination: "x.example" })),
    words(policyToolSentence("read", {})),
    policyToolAnswer("propose", env({ applied: true, changeId: "pc-1", tightens: [{ facet: "paths", subject: "/p/a" }] })),
    policyToolAnswer("propose", env({ applied: false, proposalId: "pp-1", relaxes: [{ facet: "paths", subject: "/p/a" }] })),
    policyToolAnswer("propose", env({ applied: false })),
    policyToolAnswer("test", JSON.stringify({ tool: "mandu_policy_test", egress: "ask" })),
  ].join("\n");
  assert.doesNotMatch(all, FORBIDDEN, all);
});
