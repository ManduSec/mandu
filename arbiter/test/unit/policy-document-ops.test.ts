/**
 * policy-document-ops.test — the arbiter as the single writer of policy.yaml
 * (policy-surface.md §2.1, stage 5a), over the real IPC.
 *
 * Pins:
 *   - the three writers are ADMIN-ONLY (refused on the data socket);
 *   - `applyPolicyDocument` validates strictly, writes the file atomically,
 *     swaps the law in force (a user rule takes effect on the next decision)
 *     and lands one `config_change` audit line on the arbiter-admin stream;
 *   - an INVALID apply is refused with every problem, the file and the law are
 *     untouched, and the status records the refusal;
 *   - `mintUserRule` appends with a fresh `r-000n` id; `exportDbLabels` copies
 *     DB-only labels into `paths:` without duplicating declared ones;
 *   - a HAND EDIT on disk is picked up by the poll (valid → reload + audit;
 *     invalid → last-known-good kept, `policyFile.valid:false` + problems on the
 *     snapshot; fixed → reload again);
 *   - an in-memory-law arbiter (policyDocument) reads fine and refuses writes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer, ADMIN_SESSION_ID } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

/** The law in force's version: a whole-document apply names it. */
const lawOf = async (c: ArbiterClient): Promise<string> => (await c.policyDocument()).lawHash!;

async function up(opts: { policyText?: string; inMemory?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-policy-doc-"));
  const policyPath = join(dir, "policy.yaml");
  if (opts.policyText !== undefined) writeFileSync(policyPath, opts.policyText);
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.db"),
    eventDir: join(dir, "events"),
    log: () => {},
    ...(opts.inMemory ? { policyDocument: { user_rules: [] } } : { policyPath }),
    policyPollMs: 0, // tests drive the poll by hand
  });
  await server.listen();
  const admin = new ArbiterClient(join(dir, "admin.sock"));
  const data = new ArbiterClient(join(dir, "arbiter.sock"));
  await admin.connect();
  await data.connect();
  return {
    dir, policyPath, server, admin, data,
    poll: () => (server as unknown as { policyDocs: { pollDisk(): void } }).policyDocs.pollDisk(),
    close: async () => {
      admin.close();
      data.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
      resetCurrentPolicyForTests("claude-code");
    },
  };
}

const RULE_DOC = {
  version: 1,
  user_rules: [{ id: "r-0001", kind: "release", from: { host: "docs.python.org" }, to: { host: "api.github.com" }, mode: "allow" }],
};

test("the writers are admin-only; apply writes the file, swaps the law, and audits", async () => {
  const h = await up();
  try {
    await assert.rejects(() => h.data.applyPolicyDocument(RULE_DOC, undefined, "any"), /admin-only/);
    await assert.rejects(() => h.data.mintUserRule({ kind: "release", to: { host: "*" }, mode: "block" }), /admin-only/);
    await assert.rejects(() => h.data.exportDbLabels(), /admin-only/);

    const before = await h.data.policyDocument();
    assert.equal(before.status.found, false, "no file yet");
    assert.equal(before.inForce, null);

    const sym = await h.data.symbolize({ tool: "WebFetch", field: "text", value: "x", origin: "https://docs.python.org/a" });
    const pre = await h.data.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "api.github.com" });
    assert.equal(pre.allow, false, "before the apply the built-in asks");

    const applied = await h.admin.applyPolicyDocument(RULE_DOC, "test-operator", before.lawHash!);
    assert.equal(applied.path, h.policyPath);
    assert.equal(applied.status.valid, true);
    assert.equal(applied.status.found, true);
    const text = readFileSync(h.policyPath, "utf8");
    assert.match(text, /^# Mandu policy/);
    assert.match(text, /id: r-0001/);

    const post = await h.data.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "api.github.com" });
    assert.equal(post.allow, true, "the applied rule is the law in force");
    assert.equal(post.ruleRef?.id, "egress:user-rule-allow");

    const after = await h.data.policyDocument();
    assert.deepEqual((after.inForce as { user_rules: unknown[] }).user_rules.length, 1);
    assert.deepEqual(after.onDisk.problems, []);
    assert.match(after.onDisk.text ?? "", /r-0001/);

    const audit = await h.admin.events(ADMIN_SESSION_ID);
    const change = audit.find((e) => e.kind === "config_change") as { output?: { symbolized: string }; policyChange?: { via: string; requestedBy: string } } | undefined;
    assert.ok(change, "one config_change audit line on the arbiter-admin stream");
    assert.equal(change.policyChange?.via, "apply");
    assert.equal(change.policyChange?.requestedBy, "test-operator");
    assert.match(change.output?.symbolized ?? "", /applied/);

    const snap = await h.data.policySnapshot();
    assert.equal(snap.policyFile?.valid, true);
    assert.equal(snap.policyFile?.path, h.policyPath);
    assert.equal(snap.lawSource?.kind, "file", "the law source follows the file once it exists");
  } finally {
    await h.close();
  }
});

test("an invalid apply is refused with every problem; file and law untouched; the refusal is recorded", async () => {
  const h = await up({ policyText: "version: 1\nuser_rules: []\n" });
  try {
    const original = readFileSync(h.policyPath, "utf8");
    await assert.rejects(
      async () => h.admin.applyPolicyDocument({ version: 2, user_rules: [{ id: "x", kind: "release", to: { host: "*" }, mode: "sometimes" }] }, undefined, await lawOf(h.admin)),
      (err: Error) => /policy\.version: must be 1/.test(err.message) && /user_rules\[0\]\.mode/.test(err.message) && /refuses/.test(err.message),
    );
    assert.equal(readFileSync(h.policyPath, "utf8"), original, "the file was not written");
    const snap = await h.data.policySnapshot();
    assert.equal(snap.policyFile?.valid, false);
    assert.ok((snap.policyFile?.problems.length ?? 0) >= 2);
    assert.ok(snap.policyFile?.refusedAt);
    assert.deepEqual(snap.document?.userRules, [], "the law in force is the last-known-good");
  } finally {
    await h.close();
  }
});

test("mintUserRule appends with a fresh id; exportDbLabels copies DB-only labels into paths: without duplicates", async () => {
  const h = await up({ policyText: "version: 1\npaths:\n  - { path: /srv/declared, level: no-model }\n" });
  try {
    const a = await h.admin.mintUserRule({ kind: "release", to: { host: "*.pastebin.com" }, mode: "block", reason: "never paste" }, "dash");
    assert.equal(a.id, "r-0001");
    const b = await h.admin.mintUserRule({ kind: "release", from: { host: "docs.python.org" }, to: { host: "api.github.com" }, mode: "allow" });
    assert.equal(b.id, "r-0002");
    let doc = (await h.data.policyDocument()).inForce as { user_rules: { id: string; added?: string; reason?: string }[]; paths: { path: string }[] };
    assert.deepEqual(doc.user_rules.map((r) => r.id), ["r-0001", "r-0002"]);
    assert.ok(doc.user_rules[0]!.added, "the mint stamps `added`");
    assert.equal(doc.user_rules[0]!.reason, "never paste");

    // DB labels: one new, one already declared in the file.
    await h.admin.setPathLabel({ path: "/srv/declared", confidentiality: "no-model" });
    await h.admin.setPathLabel({ path: "/srv/dbonly", confidentiality: "any-model", bindings: ["api.anthropic.com"] });
    const ex = await h.admin.exportDbLabels("dash");
    assert.equal(ex.added, 1, "only the DB-only label is exported");
    doc = (await h.data.policyDocument()).inForce as typeof doc;
    assert.deepEqual(doc.paths.map((p) => p.path).sort(), ["/srv/dbonly", "/srv/declared"]);
    const text = readFileSync(h.policyPath, "utf8");
    assert.match(text, /\/srv\/dbonly/);
    assert.match(text, /api\.anthropic\.com/);
    const audit = (await h.admin.events(ADMIN_SESSION_ID)).filter((e) => e.kind === "config_change");
    assert.equal(audit.length, 3, "one audit line per applied change (two mints + one export)");
  } finally {
    await h.close();
  }
});

test("a hand edit on disk is picked up: valid → reload + audit; invalid → last-known-good kept and flagged; fixed → reload", async () => {
  const h = await up({ policyText: "version: 1\nuser_rules: []\n" });
  try {
    const sym = await h.data.symbolize({ tool: "WebFetch", field: "text", value: "x", origin: "https://docs.python.org/a" });
    assert.equal((await h.data.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "api.github.com" })).allow, false);

    // valid edit
    writeFileSync(h.policyPath, "version: 1\nuser_rules:\n  - { id: hand, kind: release, to: { host: api.github.com }, mode: allow }\n");
    h.poll();
    // An allow rule relaxes the law: held, the law unchanged, until approved (§4.6).
    assert.equal((await h.data.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "api.github.com" })).allow, false, "held: not the law yet");
    const [held] = (await h.admin.policyProposals("pending")).proposals;
    assert.equal(held?.requestedBy, "file");
    await h.admin.resolvePolicyProposal(held!.id, "approved");
    assert.equal((await h.data.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "api.github.com" })).allow, true, "the hand-written rule is the law");
    let snap = await h.data.policySnapshot();
    assert.equal(snap.policyFile?.valid, true);
    assert.deepEqual(snap.document?.userRules.map((r) => r.id), ["hand"]);
    const audit = (await h.admin.events(ADMIN_SESSION_ID)).filter((e) => e.kind === "config_change") as { policyChange?: { via: string } }[];
    assert.equal(audit.length, 1);
    assert.equal(audit[0]!.policyChange?.via, "proposal", "an approved held change is audited as an approved proposal");

    // invalid edit → last-known-good stays, flagged
    writeFileSync(h.policyPath, "version: 1\nuser_rules:\n  - { id: broken, kind: release, to: { host: '*' }, mode: maybe }\n");
    h.poll();
    assert.equal((await h.data.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "api.github.com" })).allow, true, "the previous law is still in force");
    snap = await h.data.policySnapshot();
    assert.equal(snap.policyFile?.valid, false);
    assert.ok(snap.policyFile?.problems.some((p) => /user_rules\[0\]\.mode/.test(p)));
    assert.deepEqual(snap.document?.userRules.map((r) => r.id), ["hand"]);

    // fixed → reload
    writeFileSync(h.policyPath, "version: 1\nuser_rules:\n  - { id: fixed, kind: release, to: { host: '*' }, mode: block }\n");
    h.poll();
    snap = await h.data.policySnapshot();
    assert.equal(snap.policyFile?.valid, true);
    assert.deepEqual(snap.document?.userRules.map((r) => r.id), ["fixed"]);
    assert.equal((await h.data.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "api.github.com" })).allow, false, "block is the law now");
  } finally {
    await h.close();
  }
});

test("an in-memory law reads fine and refuses writes (there is no file to write)", async () => {
  const h = await up({ inMemory: true });
  try {
    const d = await h.data.policyDocument();
    assert.equal(d.status.path, null);
    assert.deepEqual(d.inForce, { user_rules: [] });
    await assert.rejects(() => h.admin.applyPolicyDocument({ version: 1 }, undefined, d.lawHash!), /in-memory document/);
    await assert.rejects(() => h.admin.mintUserRule({ kind: "release", to: { host: "*" }, mode: "block" }), /in-memory document/);
  } finally {
    await h.close();
  }
});

test("stage 4b: destinations: (connect: allow) compile into netConnectAllow specs from the law IN FORCE; deny is refused; the snapshot carries them", async () => {
  const h = await up();
  try {
    assert.deepEqual(await h.data.netConnectAllow(), { specs: [] }, "built-ins alone export nothing");
    await h.admin.applyPolicyDocument({
      version: 1,
      lists: { registries: ["registry.npmjs.org", "pypi.org"] },
      destinations: [
        { host: "@registries", connect: "allow", reason: "installs" },
        { host: "10.0.0.0/8", port: "*", proto: "udp", connect: "allow" },
      ],
    }, "test-operator", await lawOf(h.admin));
    assert.deepEqual(await h.data.netConnectAllow(), { specs: ["tcp:registry.npmjs.org:443", "tcp:pypi.org:443", "udp:10.0.0.0/8:*"] });
    const snap = await h.data.policySnapshot();
    assert.deepEqual(snap.document?.destinations?.map((d) => [d.host, d.port, d.proto, d.connect]), [
      ["registry.npmjs.org", 443, "tcp", "allow"], ["pypi.org", 443, "tcp", "allow"], ["10.0.0.0/8", "*", "udp", "allow"],
    ]);
    assert.ok(snap.relaxations?.some((r) => r.kind === "connect-allow" && r.subject === "tcp:pypi.org:443"), "each allowance is a listed relaxation");
    // deny: refused with the alternative; the law in force is untouched.
    await assert.rejects(
      async () => h.admin.applyPolicyDocument({ version: 1, destinations: [{ host: "evil.example", connect: "deny" }] }, undefined, await lawOf(h.admin)),
      /connect: "deny" is not enforceable yet.*user_rules \(kind: release, mode: block\)/,
    );
    assert.deepEqual(await h.data.netConnectAllow(), { specs: ["tcp:registry.npmjs.org:443", "tcp:pypi.org:443", "udp:10.0.0.0/8:*"] });
  } finally {
    await h.close();
  }
});

test("testFlow (§4/§5 Tester ≡ gates): the probe's answer equals the live gate's, names the deciding layer, and records nothing", async () => {
  const h = await up();
  try {
    // Built-ins only: an untrusted origin is masked; sending to an unknown host asks.
    const before = await h.data.testFlow({ source: { tool: "WebFetch", field: "content", origin: "https://docs.python.org/3/" }, destination: "api.github.com" });
    assert.equal(before.inbound.trust, "UNTRUSTED");
    assert.equal(before.probe.integrity, "untrusted");
    assert.ok(before.egress && before.egress.decision.allow === false && before.egress.decision.requiresApproval === true);
    assert.equal(before.egress!.stage, "built-in");
    const builtinRule = before.egress!.decision.ruleRef!.id;
    // NOTHING recorded: no pending ask, no hit.
    const snap0 = await h.data.policySnapshot();
    assert.equal((snap0.verdicts ?? []).length, 0, "a probe never queues an ask");
    assert.equal(snap0.hits?.[builtinRule], undefined, "a probe never counts a hit");

    // The law: a release rule + a trusted origin + a disposition.
    await h.admin.applyPolicyDocument({
      version: 1,
      inbound: { url: { default: "UNTRUSTED", trustedList: ["trusted.example"] } }, // host[/path-prefix] or *.suffix — never a full URL
      user_rules: [{ id: "r-0001", kind: "release", from: { host: "docs.python.org" }, to: { host: "api.github.com" }, mode: "allow" }],
      rules: { [builtinRule]: { mode: "block" } },
    }, "test-operator", await lawOf(h.admin));

    const viaRule = await h.data.testFlow({ source: { tool: "WebFetch", field: "content", origin: "https://docs.python.org/3/" }, destination: "api.github.com" });
    assert.equal(viaRule.egress!.stage, "user-rule");
    assert.equal(viaRule.egress!.decision.allow, true);
    assert.equal(viaRule.egress!.decision.ruleRef?.id, "egress:user-rule-allow");

    const viaDisposition = await h.data.testFlow({ source: { tool: "WebFetch", field: "content", origin: "https://docs.python.org/3/" }, destination: "evil.example" });
    assert.equal(viaDisposition.egress!.stage, "disposition");
    assert.equal(viaDisposition.egress!.decision.allow, false);
    assert.equal((viaDisposition.egress!.decision as { requiresApproval: boolean }).requiresApproval, false, "Block: nothing would be queued");

    const trusted = await h.data.testFlow({ source: { tool: "WebFetch", field: "content", origin: "https://trusted.example/page" } });
    assert.equal(trusted.inbound.trust, "TRUSTED");
    assert.equal(trusted.probe.integrity, "trusted");
    assert.equal(trusted.egress, null, "no destination → inbound only");

    // Tester ≡ gates: a REAL symbol from the same origin gets the same verdict.
    const sym = await h.data.symbolize({ tool: "WebFetch", field: "content", value: "x", origin: "https://docs.python.org/3/" });
    const live = await h.data.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "api.github.com" });
    assert.equal(live.allow, viaRule.egress!.decision.allow);
    assert.equal(live.ruleRef?.id, viaRule.egress!.decision.ruleRef?.id);
    const liveBlocked = await h.data.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "evil.example" });
    assert.equal(liveBlocked.allow, false);
    assert.equal(liveBlocked.ruleRef?.id, viaDisposition.egress!.decision.ruleRef?.id);
    // …and the LIVE calls are what counted: the probe rows never did.
    const snap1 = await h.data.policySnapshot();
    assert.equal(snap1.hits?.["user:r-0001"]?.hits, 1);
    assert.equal(snap1.hits?.["egress:disposition-block"]?.hits, 1);
  } finally {
    await h.close();
  }
});

test("testFlow result shape: a filesystem-path source carries `pathLabel` (pathLevel's derivation + outranked); a URL source does not", async () => {
  const h = await up();
  try {
    await h.admin.setPathLabel({ path: "/srv/tf-notes", confidentiality: "any-model", bindings: ["example.com"] });
    const lvl = await h.data.pathLevel("/srv/tf-notes/a.txt");
    const r = await h.data.testFlow({ source: { tool: "Read", field: "content", origin: "/srv/tf-notes/a.txt" } });
    assert.deepEqual(Object.keys(r.pathLabel ?? {}).sort(), ["axis", "bindings", "level", "outranked", "path", "rule"]);
    assert.deepEqual(r.pathLabel, { path: "/srv/tf-notes/a.txt", ...lvl, outranked: [] });
    if (lvl.axis) {
      assert.equal(r.pathLabel!.rule, "label:/srv/tf-notes");
      assert.deepEqual(r.pathLabel!.bindings, ["example.com"]);
    } else {
      assert.equal(r.pathLabel!.rule, null, "axis off: no rule is claimed");
    }
    const url = await h.data.testFlow({ source: { tool: "WebFetch", field: "content", origin: "https://docs.python.org/3/" } });
    assert.equal("pathLabel" in url, false);
    const rel = await h.data.testFlow({ source: { tool: "Read", origin: "relative/file.txt" } });
    assert.equal("pathLabel" in rel, false, "a relative path has no stable identity: no derivation is claimed");
  } finally {
    await h.close();
  }
});
