// The job summary: names and hosts only, never a value, from the run's events
// and the doctor's report. Design: docs/design/distribution/github-action.md §6.
import { test } from "node:test";
import assert from "node:assert/strict";

import { blockedAnnotations, code, collectReport, displayPath, renderSummary, symbolLabel } from "../lib/summary.mjs";

const RAW = "dep_Zq81xkW3vB7nM2pL5tR9_unit";
const RAW_FILE = "pw-Hq7wE2rT9yU4iO6pA1sD-unit";
const ENV_SYM = "$MDU:nomodel_Env[833c].DEPLOY_TOKEN";

/** Events shaped as a real run writes them (the e2e's run, trimmed), with
 *  raw values planted wherever the event model carries originals. */
const EVENTS = [
  {
    kind: "launch_posture", emitter: "launcher", sessionId: "s1",
    secrets: { posture: "confined" }, protection: { mode: "secrets" },
    agentVersion: { name: "Claude Code", version: "2.1.295", verdict: "tested" },
    notes: [
      "mandu: environment: 2 secret variables masked (ANTHROPIC_API_KEY, DEPLOY_TOKEN)",
      `mandu: some other line naming ${RAW}`,
    ],
  },
  {
    kind: "symbolize", emitter: "anthropic-proxy", view: "AgentView", sessionId: "s1", callId: "toolu_0",
    input: { symbolized: "$MDU:nomodel_Bash[ce78]", original: `DB_PASSWORD=${RAW_FILE}`, differs: true },
    output: { symbolized: "$MDU:nomodel_Bash[ce78]", original: `DB_PASSWORD=${RAW_FILE}`, differs: true, symbols: [{ name: "$MDU:nomodel_Bash[ce78]", origin: `echo ${RAW}`, value: RAW }] },
  },
  // The same tool result masked again on a later turn: one call.
  { kind: "symbolize", emitter: "anthropic-proxy", view: "AgentView", sessionId: "s1", callId: "toolu_0", output: { differs: true } },
  { kind: "net_action", action: "forwarded", destination: "deploy.example", resolved: [ENV_SYM], status: 200 },
  { kind: "net_action", action: "forwarded", destination: "pypi.org", resolved: [] },
  {
    kind: "net_action", action: "blocked", destination: "paste.example", withheld: [ENV_SYM, RAW],
    reason: `egress withheld ${RAW}`, policy: { usage: "deny", ruleRef: { source: "rule", id: "egress:secret-unbound" }, approvalId: "egr-1" },
  },
  { kind: "net_action", action: "blocked", destination: "paste.example", withheld: [ENV_SYM] },
  { kind: "net_action", action: "blocked", destination: `evil.example/${RAW}`, withheld: [ENV_SYM] },
  { kind: "session_exit", emitter: "launcher", code: 0 },
];
const DOCTOR = {
  files: [
    { path: "/home/runner/work/app/app/.env", level: "no-model" },
    { path: "/home/runner/.aws/credentials", level: "no-model" },
    { path: "/home/runner/x\ny", level: "no-model" },
  ],
  env: { masked: ["CLAUDE_CODE_MESSAGING_TOKEN", "DEPLOY_TOKEN"] },
};
const WHERE = { home: "/home/runner", workspace: "/home/runner/work/app/app" };

test("symbolLabel reads a placeholder's name, and nothing that is not a placeholder", () => {
  assert.deepEqual(symbolLabel(ENV_SYM), { name: "DEPLOY_TOKEN", kind: "environment variable" });
  assert.deepEqual(symbolLabel("$MDU:nomodel_Read[c0aa].DB_PASSWORD"), { name: "DB_PASSWORD", kind: "a value in a secret file" });
  assert.equal(symbolLabel("$MDU:nomodel_Read[c0aa]").name, "a secret file");
  assert.equal(symbolLabel(RAW), null);
  assert.equal(symbolLabel(`$MDU:nomodel_Env[833c].X ${RAW}`), null);
  assert.equal(symbolLabel(42), null);
});

test("collectReport: the launch's facts, the masked names, each host once with its count", () => {
  const r = collectReport(EVENTS, DOCTOR, WHERE);
  assert.equal(r.agent, "Claude Code 2.1.295");
  assert.equal(r.mode, "secrets");
  assert.equal(r.posture, "confined");
  assert.equal(r.exitCode, 0);
  assert.deepEqual(r.envMasked, ["ANTHROPIC_API_KEY", "DEPLOY_TOKEN"], "the launch's own line wins over the doctor's");
  assert.deepEqual(r.files, [{ path: ".env", level: "no-model" }, { path: "~/.aws/credentials", level: "no-model" }]);
  assert.equal(r.maskedResults, 1);
  assert.deepEqual(r.blocked, [{ host: "paste.example", names: ["DEPLOY_TOKEN"], rule: "egress:secret-unbound", count: 2 }]);
  assert.deepEqual(r.sent, [{ host: "deploy.example", names: ["DEPLOY_TOKEN"], count: 1 }], "a forward that put nothing back is no send of a secret");
});

test("no raw value survives into the report, the summary or the annotations", () => {
  const r = collectReport(EVENTS, DOCTOR, WHERE);
  const all = JSON.stringify(r) + renderSummary(r, { failOnBlocked: true, policyFrom: "none" }) + blockedAnnotations(r).join("\n");
  assert.ok(!all.includes(RAW), "the env value");
  assert.ok(!all.includes(RAW_FILE), "the file value");
  assert.ok(!all.includes("$MDU:"), "not even a placeholder: names only");
});

test("without the launch's line the doctor's variable names are used", () => {
  const r = collectReport(EVENTS.filter((e) => e.kind !== "launch_posture"), DOCTOR, WHERE);
  assert.deepEqual(r.envMasked, ["CLAUDE_CODE_MESSAGING_TOKEN", "DEPLOY_TOKEN"]);
  assert.equal(r.agent, null);
});

test("renderSummary: the tables, the blocked send's way out, the fail-on-blocked line", () => {
  const md = renderSummary(collectReport(EVENTS, DOCTOR, WHERE), { failOnBlocked: true, policyFrom: ".github/mandu/policy.yaml" });
  assert.match(md, /^## Mandu: what the AI did not see$/m);
  assert.match(md, /\*\*Claude Code 2\.1\.295\*\* · mode `secrets` · secrets `confined` · exit 0 · policy: \.github\/mandu\/policy\.yaml/);
  assert.match(md, /\| `DEPLOY_TOKEN` \| environment variable \| sent only where a binding allows \|/);
  assert.match(md, /\| `\.env` \| file \| no AI may read it \|/);
  assert.match(md, /\| `~\/\.aws\/credentials` \| file \|/);
  assert.match(md, /1 tool result reached the model with a secret replaced/);
  assert.match(md, /\| blocked \| `paste\.example` \| `DEPLOY_TOKEN` \| 2 \|/);
  assert.match(md, /\| sent with the real value \(bound\) \| `deploy\.example` \| `DEPLOY_TOKEN` \| 1 \|/);
  assert.match(md, /bind the secret to it \(the `bindings` input/);
  assert.match(md, /This step fails because of it/);
  assert.doesNotMatch(renderSummary(collectReport(EVENTS, DOCTOR, WHERE), { failOnBlocked: false, policyFrom: "none" }), /This step fails/);
});

test("renderSummary: a quiet run says so", () => {
  const md = renderSummary(collectReport([], null), { failOnBlocked: true, policyFrom: "none" });
  assert.match(md, /Nothing secret was found/);
  assert.match(md, /No request carried a secret/);
  assert.match(md, /the agent did not report an exit/);
});

test("blockedAnnotations: one ::error per host", () => {
  assert.deepEqual(blockedAnnotations(collectReport(EVENTS, DOCTOR, WHERE)), [
    "::error title=Mandu blocked a send::DEPLOY_TOKEN to paste.example (2 requests): no binding allows it, and nobody approves in CI",
  ]);
});

test("displayPath and code: relative paths; a code span markdown cannot break out of", () => {
  assert.equal(displayPath("/w/a/.env", { workspace: "/w/a" }), ".env");
  assert.equal(displayPath("/h/.npmrc", { home: "/h/" }), "~/.npmrc");
  assert.equal(displayPath("/etc/x", WHERE), "/etc/x");
  assert.equal(code("a`b|c"), "`a'b\\|c`");
});
