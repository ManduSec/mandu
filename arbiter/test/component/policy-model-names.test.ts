/**
 * policy-model-names e2e — the names-only model (confidentiality plan 14
 * §14.2-§14.4, step 4b) through the REAL arbiter: an in-process ArbiterServer
 * with a file-backed law, the production `ArbiterClient` on its data socket
 * (the client's parity for `modelSuggestPreview` / `modelSuggest`), the real
 * workspace walk over a fixture work tree, and a FAKE classifier process
 * (test/helpers/fake-classifier.mjs: the classify-main.ts contract, no
 * model) started from `policyClassifier` exactly as `--classifier` starts the
 * real one:
 *
 *   - no classifier: both ops answer "not available in this install";
 *   - `tier: "contents"` with no local model declared: refused; an undeclared endpoint:
 *     refused;
 *   - the preview: every name relative to its root (`root 1`), the folders
 *     above a file numbered `d<n>`, the files `f<n>`; left out: the catalog's
 *     `.env`, every name under the labelled folder (and the folder's own
 *     name), a file whose NAME is a token (the gate's detector); the home
 *     path never; `bytes` is the request texts' size;
 *   - the send: the classifier gets exactly the kept texts (the bytes the
 *     preview counted); the valid folder rule over `clients/` is filed as a
 *     `model-names` suggestion at `no-model` (the model's own level kept in
 *     its facts), grouping the pending workspace suggestion under it; the
 *     rule over `src/` is too broad; a second call with the same digest
 *     sends nothing again; an unknown digest, and one past 15 minutes, are
 *     refused ("look again");
 *   - applying the folder rule closes the grouped suggestion `superseded`
 *     by it;
 *   - a HOSTILE classifier (every malformed shape, a canary in every free
 *     field) files only the valid rule, and no canary reaches a reply, the
 *     event store, the proposals table, the log or policy.yaml;
 *   - one `policy_model_call` event per run, counts only;
 *   - the classifier's environment is the allowlist (no arbiter socket).
 *
 * Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Database from "../../db/sqlite.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import type { ModelSuggestPreviewResult, ModelSuggestResult } from "../../ipc/protocol.js";
import { stateAxes } from "../axes.js";
import { randomSecretBody } from "../helpers/random-secret.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE = join(HERE, "..", "helpers", "fake-classifier.mjs");
const CANARY = "CLASSIFIER-CANARY-7f3a9c";
const LABELLED = "hr-canary-q7k2";

const alnum = (n: number): string => {
  let s = "";
  while (s.length < n) s += randomBytes(64).toString("base64").replace(/[^A-Za-z0-9]/g, "");
  return s.slice(0, n);
};

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

interface Rig {
  dir: string; home: string; repo: string; policy: string; record: string; logs: string[];
  server: ArbiterServer; client: ArbiterClient; clock: { t: number };
  close: () => Promise<void>;
}

async function rig(mode: "ok" | "hostile" | "refuse" | null): Promise<Rig> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-model-names-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const repo = join(home, "proj");
  const put = (rel: string, body = "ordinary text\n"): void => { mkdirSync(dirname(join(repo, rel)), { recursive: true }); writeFileSync(join(repo, rel), body); };
  mkdirSync(join(repo, ".git"), { recursive: true });
  put("README.md", "a project\n");
  put("package.json", "{}\n");
  put("docs/guide.md");
  put("docs/design.md");
  for (let i = 0; i < 14; i++) put(`src/mod${i}.ts`, `export const x${i} = ${i};\n`);
  put("clients/acme/contract.docx");
  put("clients/acme/invoice-2026.xlsx");
  put("clients/beta/nda.pdf");
  put("clients/beta/api.conf", `[api]\nTOKEN=${"gh" + "p_" + randomSecretBody(36)}\n`);
  put(".env", `KEY=${alnum(20)}\n`);
  put(`${LABELLED}/salaries-canary.txt`);
  put(`${LABELLED}/carved-out-canary.txt`);
  put(`notes/${"gh" + "p_" + randomSecretBody(36)}.txt`);
  const policy = join(dir, "policy.yaml");
  // The folder is labelled; one file in it is carved out `public`: its name
  // still sits under a labelled folder, so it is not sent either.
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(repo, LABELLED)}\n    level: no-model\n  - path: ${join(repo, LABELLED, "carved-out-canary.txt")}\n    level: public\n`);
  const record = join(dir, "record.jsonl");
  const logs: string[] = [];
  const clock = { t: Date.now() };
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock,
    dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, policyPollMs: 0, confidentiality: true, integrity: false,
    log: (m) => logs.push(m),
    policyClassifier: mode === null ? null : { argv: [process.execPath, FAKE, mode, record] },
    policyModel: { env: { PATH: process.env["PATH"], HOME: home, ARBITER_SOCKET_SHOULD_NOT_PASS: "x", MANDU_ARBITER_SOCK: sock }, userName: "nobody-here", now: () => clock.t },
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  return {
    dir, home, repo, policy, record, logs, server, client, clock,
    close: async () => { client.close(); await server.close(); },
  };
}

function everything(r: Rig, replies: unknown[]): string {
  const parts = [JSON.stringify(replies), r.logs.join("\n"), readFileSync(r.policy, "utf8")];
  const ev = join(r.dir, "events");
  if (existsSync(ev)) for (const f of readdirSync(ev, { recursive: true }) as string[]) {
    const p = join(ev, f);
    try { parts.push(readFileSync(p, "utf8")); } catch { /* a folder */ }
  }
  const db = new Database(join(r.dir, "mandu.db"));
  try { parts.push(JSON.stringify(db.prepare("SELECT * FROM policy_proposals").all())); } finally { db.close(); }
  return parts.join("\n");
}

test("without a classifier both model ops answer 'not available in this install'", async () => {
  const r = await rig(null);
  try {
    await assert.rejects(r.client.modelSuggestPreview([r.repo], { home: r.home }), /not available in this install/);
    await assert.rejects(r.client.modelSuggest("0".repeat(64)), /no longer held.*look again/);
  } finally { await r.close(); }
});

test("preview → send over the real arbiter: names only, the gate, the bytes consent binds, the closed answer, grouping and superseding, the stale digest, one event", async () => {
  const r = await rig("ok");
  const replies: unknown[] = [];
  try {
    // The scans first (§14.4: their suggestions are filed before the model's).
    const scanned = await r.client.suggestPolicy([r.repo], { home: r.home, sources: ["workspace"] });
    replies.push(scanned);
    const ws = scanned.suggestions.find((s) => s.edits.some((e) => e.op === "lock-path" && e.path === join(r.repo, "clients/beta/api.conf")));
    assert.ok(ws, "the workspace scan filed the token file under clients/");

    await assert.rejects(r.client.modelSuggestPreview([r.repo], { tier: "contents", home: r.home }), /no model of your own is declared/);
    await assert.rejects(r.client.modelSuggestPreview([r.repo], { endpoint: "nope", home: r.home }), /no model named 'nope'/);

    const p: ModelSuggestPreviewResult = await r.client.modelSuggestPreview([r.repo], { home: r.home });
    replies.push(p);
    assert.match(p.digest, /^[0-9a-f]{64}$/);
    assert.deepEqual(p.destination, { kind: "default", name: "Claude (fake)", location: "external", placement: "network", vendor: "Anthropic" });
    assert.deepEqual(p.roots.map((x) => [x.index, x.root]), [[1, r.repo]]);
    const lines = p.names.join("\n");
    assert.match(lines, /^d\d+ root 1 "clients\/"$/m);
    assert.match(lines, /^d\d+ root 1 "clients\/acme\/"$/m);
    assert.match(lines, /^f\d+ root 1 "clients\/acme\/contract\.docx" size=under1KB ext=docx$/m);
    assert.match(lines, /^f\d+ root 1 "clients\/beta\/api\.conf" size=under1KB ext=conf holds=github-token$/m);
    assert.ok(!lines.includes(LABELLED), "no name under the labelled folder, nor the folder's own");
    assert.ok(!lines.includes(".env"), "the catalog's .env is covered: not sent");
    assert.ok(!/gh[p]_/.test(lines), "a token-shaped NAME is dropped by the gate");
    assert.ok(!lines.includes(r.home) && !lines.includes(r.dir), "no absolute path");
    assert.equal(p.left.labelled, 1, "the public carve-out under the labelled folder");
    assert.equal(p.left.covered, 2, "the catalog's .env and the labelled file");
    assert.equal(p.left.detector, 1);
    assert.equal(p.items, p.names.length);
    assert.equal(p.confine.live, false, "no applier was passed");
    assert.equal(p.expiresAt, r.clock.t + 15 * 60_000);

    // An unknown digest: refused, nothing sent.
    await assert.rejects(r.client.modelSuggest("f".repeat(64)), /look again/);
    assert.equal(existsSync(r.record), false, "no classifier run for an unknown digest");

    const s: ModelSuggestResult = await r.client.modelSuggest(p.digest);
    replies.push(s);
    assert.equal(s.running, false);
    assert.equal(s.error, null, s.error ?? "");
    const runs = readFileSync(r.record, "utf8").trim().split("\n").map((l) => JSON.parse(l) as { req: { batches: string[] }; env: string[] });
    assert.equal(runs.length, 1);
    const sent = runs[0]!.req.batches;
    assert.equal(sent.reduce((n, b) => n + Buffer.byteLength(b), 0), p.bytes, "the bytes sent are the preview's");
    for (const l of p.names) assert.ok(sent.some((b) => b.split("\n").includes(l)), `sent: ${l}`);
    assert.deepEqual(runs[0]!.env.filter((k) => /ARBITER/.test(k)), [], "no arbiter socket in the classifier's environment");
    assert.equal(s.sent.bytes, p.bytes);
    assert.equal(s.counts.tooBroad, 1, "src/ is more than half the root's files");
    assert.equal(s.filed.length, 1);
    const m = s.suggestions.find((v) => v.id === s.filed[0])!;
    assert.equal(m.source, "model-names");
    assert.equal(m.requestedBy, "mandu:scan");
    assert.deepEqual(m.edits, [{ op: "lock-path", path: join(r.repo, "clients"), level: "no-model" }]);
    assert.equal(m.sentence, "Make ~/proj/clients a secret no AI may read: covers 1 suggestion below");
    assert.deepEqual(m.model, { endpoint: "Claude (fake)", level: "local-model", reason: "customer-data", reasonWords: "looks like customer data", candidate: "folder", files: 4, covers: [ws!.id] });
    assert.equal(m.rotate, false);

    // Once per digest: a second call answers the same run.
    const again = await r.client.modelSuggest(p.digest);
    assert.deepEqual(again.filed, s.filed);
    assert.equal(readFileSync(r.record, "utf8").trim().split("\n").length, 1, "nothing is sent twice");

    // Applying the folder rule closes the grouped workspace suggestion.
    const applied = await r.client.applySuggestion(m.id);
    replies.push(applied);
    assert.equal(applied.applied, true);
    const all = (await r.client.policySuggestions()).suggestions;
    const closed = all.find((v) => v.id === ws!.id)!;
    assert.equal(closed.status, "superseded");
    assert.equal(closed.supersededBy, m.id);

    // A preview past 15 minutes is forgotten.
    const p2 = await r.client.modelSuggestPreview([r.repo], { home: r.home });
    r.clock.t += 15 * 60_000 + 1;
    await assert.rejects(r.client.modelSuggest(p2.digest), /look again/);
    assert.equal(readFileSync(r.record, "utf8").trim().split("\n").length, 1, "a stale digest sends nothing");

    // One event per run, counts only.
    const text = everything(r, replies);
    const events = text.split("\n").filter((l) => l.includes('"policy_model_call"'));
    assert.equal(events.length, 1, "one policy_model_call event");
    const e = JSON.parse(events[0]!) as { policyModelCall: Record<string, unknown> };
    assert.deepEqual(Object.keys(e.policyModelCall).sort(), ["bytes", "dropped", "endpoint", "failed", "filed", "items", "kept", "location", "ms", "placement", "requests", "tier"]);
    assert.equal(e.policyModelCall["bytes"], p.bytes);
    assert.ok(!events[0]!.includes("clients"), "no name in the event");
  } finally { await r.close(); }
});

test("a hostile classifier files only the valid rule; no canary anywhere", async () => {
  const r = await rig("hostile");
  const replies: unknown[] = [];
  try {
    const p = await r.client.modelSuggestPreview([r.repo], { home: r.home });
    replies.push(p);
    const s = await r.client.modelSuggest(p.digest);
    replies.push(s);
    assert.equal(s.filed.length, 1, JSON.stringify(s.suggestions.map((v) => [v.edits, v.model])));
    assert.deepEqual(s.suggestions.map((v) => v.edits), [[{ op: "lock-path", path: join(r.repo, "clients"), level: "no-model" }]]);
    assert.ok(s.counts.dropped >= 5, JSON.stringify(s.counts));
    replies.push(await r.client.policySuggestions());
    const text = everything(r, replies);
    assert.ok(!text.includes(CANARY), "no canary in the replies, the events, the proposals, the log or policy.yaml");
  } finally { await r.close(); }
});

test("a classifier that refuses or answers garbage files nothing and says why in the arbiter's words", async () => {
  const r = await rig("refuse");
  try {
    const p = await r.client.modelSuggestPreview([r.repo], { home: r.home });
    const s = await r.client.modelSuggest(p.digest, { waitMs: 10_000 });
    assert.equal(s.filed.length, 0);
    assert.equal(s.error, "no model is configured");
  } finally { await r.close(); }
});
