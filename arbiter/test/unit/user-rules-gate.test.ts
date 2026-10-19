/**
 * user-rules-gate.test — the operator's law inside the egress gate, over the
 * real IPC (policy-surface.md §2.4, §2.5, stage 4).
 *
 * An ArbiterServer compiled from an in-memory policy DOCUMENT (`policyDocument`)
 * with user release rules, a disposition and a locked-file label. Pins:
 *   - a user `allow` rule releases an untrusted symbol from a matching origin
 *     to a matching destination with NO pending row and the user-rule ruleRef;
 *   - a user `block` rule denies without asking (nothing queued), and beats an
 *     allow for the same destination;
 *   - a disposition `block` on the built-in ask denies with nothing queued;
 *   - an `audit` rule never decides but counts (auditHits), the built-in ask
 *     still queues;
 *   - a SECRET symbol never yields to a user allow rule (the bound-destination
 *     path stays authoritative);
 *   - a document `paths:` label is effective at symbolize time (the symbol's
 *     level) and is listed by the labels ops with source `policy-file`;
 *   - `policySnapshot` carries the document, the relaxations and the hits.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const SECRET_DIR = "/tmp/mandu-user-rules-gate-secret";

const DOC: PolicyFileConfig = {
  version: 1,
  lists: { "my-services": ["api.github.com", "*.internal.example"] },
  paths: [{ path: SECRET_DIR, level: "no-model" }],
  rules: { "egress:untrusted-destination": { mode: "block" } },
  user_rules: [
    { id: "docs-to-api", kind: "release", from: { host: "docs.python.org" }, to: { host: "@my-services" }, mode: "allow", reason: "my own api" },
    { id: "no-paste", kind: "release", to: { host: "*.pastebin.com" }, mode: "block" },
    { id: "paste-ok-from-docs", kind: "release", from: { host: "docs.python.org" }, to: { host: "pastebin.com" }, mode: "allow" },
    { id: "watch-everything", kind: "release", to: { host: "*" }, mode: "audit" },
  ],
};

async function up(doc: PolicyFileConfig, confidentiality = false) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-user-rules-"));
  const socketPath = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath,
    adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.db"),
    eventDir: join(dir, "events"),
    log: () => {},
    policyDocument: doc,
    confidentiality,
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "admin.sock")); // admin path: pathLabels reads + decisions in one client
  await client.connect();
  return {
    client,
    close: async () => {
      client.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
      resetCurrentPolicyForTests("claude-code");
    },
  };
}

test("user rules decide untrusted egress: allow releases with no pending row; block denies without asking and beats allow", async () => {
  const h = await up(DOC);
  try {
    const sym = await h.client.symbolize({ tool: "WebFetch", field: "text", value: "fetched-from-docs", origin: "https://docs.python.org/3/library/os.html" });
    const allowed = await h.client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "api.github.com" });
    assert.equal(allowed.allow, true);
    assert.equal(allowed.ruleRef?.id, "egress:user-rule-allow");
    assert.match(allowed.reason, /docs-to-api/);
    const viaList = await h.client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "db.internal.example:5432" });
    assert.equal(viaList.allow, true, "a @list suffix entry matches, host:port is reduced to the host");

    const blocked = await h.client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "pastebin.com" });
    assert.equal(blocked.allow, false);
    assert.equal(blocked.allow === false && blocked.requiresApproval, false, "a user block never asks");
    assert.equal(blocked.ruleRef?.id, "egress:user-rule-block");
    assert.match(blocked.reason, /no-paste/, "Block beats the narrower Allow for the same destination");

    assert.deepEqual(await h.client.egressApprovals(), [], "nothing was queued by any user-rule decision");
  } finally {
    await h.close();
  }
});

test("an approval carries its data's source (tool + origin) at read time, never the value (dashboard.md §4.25e)", async () => {
  const h = await up({ ...DOC, rules: {} });
  try {
    const sym = await h.client.symbolize({ tool: "Read", field: "notes.md", value: "the private body", origin: "/ws/run-1/notes.md" });
    await h.client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "evil.example" });
    const [queued] = await h.client.egressApprovals("pending");
    assert.deepEqual(queued?.source, { tool: "Read", origin: "/ws/run-1/notes.md" });
    assert.equal(queued?.originHost, null, "a file path has no origin host");
    const snap = await h.client.policySnapshot();
    const verdict = snap.verdicts?.find((v) => v.id === queued!.id);
    assert.deepEqual(verdict?.source, { tool: "Read", origin: "/ws/run-1/notes.md" }, "the panel's snapshot carries it too");
    assert.doesNotMatch(JSON.stringify(await h.client.egressApprovals()), /the private body/, "provenance only");
  } finally {
    await h.close();
  }
});

test("a disposition `block` on the built-in ask denies with nothing queued; an audit rule counts but the built-in still decides", async () => {
  const h = await up({ ...DOC, rules: {} }); // no disposition first: the audit rule + the built-in ask
  try {
    const sym = await h.client.symbolize({ tool: "WebFetch", field: "text", value: "x", origin: "https://unknown.example/page" });
    const asked = await h.client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "evil.example" });
    assert.equal(asked.allow, false);
    assert.equal(asked.allow === false && asked.requiresApproval, true, "no user rule applies (the origin is not docs) → the built-in asks");
    assert.equal(asked.ruleRef?.id, "egress:untrusted-destination");
    assert.equal((await h.client.egressApprovals("pending")).length, 1, "the ask was queued");
    const snap = await h.client.policySnapshot();
    assert.equal(snap.hits?.["user:watch-everything"]?.auditHits, 1, "the audit rule matched and counted");
    assert.equal(snap.hits?.["user:watch-everything"]?.hits ?? 0, 0, "…but never decided");
    assert.equal(snap.hits?.["egress:untrusted-destination"]?.hits, 1);
  } finally {
    await h.close();
  }
  const d = await up(DOC); // with the disposition
  try {
    const sym = await d.client.symbolize({ tool: "WebFetch", field: "text", value: "y", origin: "https://unknown.example/page" });
    const denied = await d.client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "evil.example" });
    assert.equal(denied.allow, false);
    assert.equal(denied.allow === false && denied.requiresApproval, false, "the operator set the ask to Block");
    assert.equal(denied.ruleRef?.id, "egress:disposition-block");
    assert.match(denied.reason, /set to Block by the operator/);
    assert.deepEqual(await d.client.egressApprovals(), [], "nothing queued");
    const snap = await d.client.policySnapshot();
    assert.equal(snap.hits?.["egress:disposition-block"]?.hits, 1);
    assert.deepEqual(snap.document?.rules, { "egress:untrusted-destination": { mode: "block" } });
    assert.deepEqual(snap.document?.userRules.map((r) => r.id), ["docs-to-api", "no-paste", "paste-ok-from-docs", "watch-everything"]);
    assert.deepEqual(snap.document?.userRules[0]?.to, ["api.github.com", "*.internal.example"], "lists expanded in the snapshot");
    assert.ok(snap.relaxations?.some((r) => r.kind === "user-rule-allow" && r.subject === "docs-to-api"));
  } finally {
    await d.close();
  }
});

test("a SECRET symbol never yields to a user allow rule; a document `paths:` label is effective and listed as policy-file", async () => {
  const h = await up(DOC, true);
  try {
    const labels = await h.client.pathLabels();
    const doc = labels.find((l) => l.path === SECRET_DIR) as { path: string; level: string; source?: string } | undefined;
    assert.ok(doc, "the document label is listed by the labels op");
    assert.equal(doc.level, "no-model");
    assert.equal(doc.source, "policy-file");

    // A file under the labeled dir symbolizes as no-model → the model-context
    // branch denies (the label took effect at symbolize time, from the document).
    const sym = await h.client.symbolize({ tool: "Read", field: "content", value: "BEGIN PRIVATE KEY", origin: join(SECRET_DIR, "id_ed25519") });
    const ctx = await h.client.desymbolizationDecision({ symbol: sym, boundary: "model_context" });
    assert.equal(ctx.allow, false);
    assert.equal(ctx.ruleRef?.id, "egress:secret-model-context");

    // Even with an allow rule that would match (any origin → api.github.com via
    // a docs-origin rule cannot match a path origin; use a wide allow instead).
    const wide = await up({ ...DOC, user_rules: [{ id: "wide", kind: "release", to: { host: "*" }, mode: "allow" }] }, true);
    try {
      const s2 = await wide.client.symbolize({ tool: "Read", field: "content", value: "BEGIN PRIVATE KEY 2", origin: join(SECRET_DIR, "id_rsa") });
      const net = await wide.client.desymbolizationDecision({ symbol: s2, boundary: "network", destination: "api.github.com" });
      assert.equal(net.allow, false, "a secret keeps the bound-destination path — the user rule is not consulted");
      assert.match(net.ruleRef?.id ?? "", /^egress:secret-/);
      // …while an UNTRUSTED symbol IS released by the same wide rule.
      const s3 = await wide.client.symbolize({ tool: "WebFetch", field: "text", value: "public page", origin: "https://example.org/" });
      const ok = await wide.client.desymbolizationDecision({ symbol: s3, boundary: "network", destination: "api.github.com" });
      assert.equal(ok.allow, true);
      assert.equal(ok.ruleRef?.id, "egress:user-rule-allow");
    } finally {
      await wide.close();
    }
  } finally {
    await h.close();
  }
});
