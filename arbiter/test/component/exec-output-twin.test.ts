/**
 * exec-output-twin.test.ts — plan 10 §11.8 over the real IPC: `callTaint`
 * answers `twinOf` for a shell result that is a piece of one registered
 * file's structured twin, and ONLY on evidence (the guard recorded the
 * call's tree and nothing in it read a secret raw). Every other shape keeps
 * the answer without `twinOf`, so the proxies keep the whole-result mask.
 * And "A document's own twin" (2026-10-12): a result that is exactly a
 * labelled document's whole-file twin answers `twinOf` with `twinWhole`.
 *
 * Mandu-new test. A real ArbiterServer on a temp socket, the real client.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const RAW = "PORT=3000\nSTRIPE_KEY=sk_live_abcdef1234567890\nAPI_TOKEN=tok_0123456789abcdef\n";

async function stack(confidentiality: boolean) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-exec-twin-"));
  const env = join(dir, ".env");
  writeFileSync(env, RAW);
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality, integrity: false });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxy's channel (plan 13 D9)
  await c.connect();
  return { dir, env, s, c, done: async () => { c.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("the guard saw `cat .env` read the twin: callTaint names the file; the twin carries keys and field symbols only", async () => {
  const k = await stack(true);
  try {
    const reg = await k.c.registerSecret({ path: k.env });
    assert.ok(reg.symbol && typeof reg.twin === "string", JSON.stringify(reg));
    const twin = reg.twin as string;
    assert.ok(!twin.includes("sk_live_abcdef1234567890") && twin.includes("STRIPE_KEY="), twin);
    // the guard saw the exec; `cat` got the twin, so no secret taint
    await k.c.recordExecRoot({ procKey: "t-sh-1", argv: ["/bin/sh", "-c", "cat .env"], session: "st" });
    const t = await k.c.callTaint("call_twin_1", { command: "cat .env", session: "st", output: twin });
    assert.equal(t.root, "t-sh-1");
    assert.equal(t.level, null);
    assert.deepEqual(t.twinOf, [k.env]);
    // one line of it (grep STRIPE_KEY .env) through a Codex envelope
    const line = twin.split("\n").find((l) => l.startsWith("STRIPE_KEY="))!;
    const env = "Chunk ID: 9a\nWall time: 0.01 seconds\nProcess exited with code 0\nOutput:\n";
    await k.c.recordExecRoot({ procKey: "t-sh-2", argv: ["/bin/sh", "-c", "grep STRIPE_KEY .env"], session: "st" });
    assert.deepEqual((await k.c.callTaint("call_twin_2", { command: "grep STRIPE_KEY .env", session: "st", output: `${env}${line}\n`, codexHead: true })).twinOf, [k.env]);
    // review of !1604: the same head on a call the proxy did not mark as a
    // Codex result is the program's own text, never looked through
    assert.equal((await k.c.callTaint("call_twin_2", { command: "grep STRIPE_KEY .env", session: "st", output: `${env}${line}\n` })).twinOf, undefined);
    assert.equal((await k.c.callTaint("call_twin_2", { command: "grep STRIPE_KEY .env", session: "st", output: `${env}${env}${line}\n`, codexHead: true })).twinOf, undefined, "a second head");
    // a script cell that printed the whole exec result object (live GPT-5 wire)
    const cell = `Script completed\nWall time 0.2 seconds\nOutput:\n${JSON.stringify({ chunk_id: "3ec25a", wall_time_seconds: 0.01, exit_code: 0, original_token_count: 52, output: twin })}`;
    await k.c.recordExecRoot({ procKey: "t-sh-3", argv: ["/bin/sh", "-c", "cat .env"], session: "st3" });
    assert.deepEqual((await k.c.callTaint("call_twin_3", { command: "cat .env", session: "st3", output: cell, codexHead: true })).twinOf, [k.env]);
  } finally { await k.done(); }
});

test("no evidence, a tainted tree, raw bytes or no output: no twinOf (the mask stands)", async () => {
  const k = await stack(true);
  try {
    const twin = (await k.c.registerSecret({ path: k.env })).twin as string;
    // no root recorded for the call (no guard): the text alone is not evidence
    const none = await k.c.callTaint("call_noroot", { command: "cat .env", session: "sn", output: twin });
    assert.equal(none.root, null);
    assert.equal(none.twinOf, undefined);
    // a process in the tree read the file RAW (a listed reader): rule (i) owns it
    await k.c.recordExecRoot({ procKey: "r-sh-1", argv: ["/bin/sh", "-c", "cat .env"], session: "sr" });
    await k.c.processLineage({ childKey: "r-cat-2", parentKey: "r-sh-1" });
    await k.c.taintProcessSecret({ procKey: "r-cat-2", path: k.env, level: "no-model", app: "cat" });
    const tainted = await k.c.callTaint("call_raw", { command: "cat .env", session: "sr", output: twin });
    assert.equal(tainted.level, "no-model");
    assert.equal(tainted.twinOf, undefined);
    // evidence, but the output is the raw file
    await k.c.recordExecRoot({ procKey: "w-sh-1", argv: ["/bin/sh", "-c", "cat .env"], session: "sw" });
    assert.equal((await k.c.callTaint("call_rawtext", { command: "cat .env", session: "sw", output: RAW })).twinOf, undefined);
    // evidence, no output sent
    assert.equal((await k.c.callTaint("call_rawtext", { command: "cat .env", session: "sw" })).twinOf, undefined);
  } finally { await k.done(); }
});

test("confidentiality axis OFF: callTaint never answers twinOf", async () => {
  const k = await stack(false);
  try {
    const reg = await k.c.registerSecret({ path: k.env });
    await k.c.recordExecRoot({ procKey: "o-sh-1", argv: ["/bin/sh", "-c", "cat .env"], session: "so" });
    const t = await k.c.callTaint("call_off", { command: "cat .env", session: "so", output: typeof reg.twin === "string" ? reg.twin : RAW });
    assert.equal(t.twinOf, undefined);
  } finally { await k.done(); }
});

test("a read of the twin masked whole is no fingerprint: later renderings of the twin pass the value backstop; a raw row still hits", async () => {
  const k = await stack(true);
  try {
    const reg = await k.c.registerSecret({ path: k.env });
    const twin = reg.twin as string;
    // OpenClaw's `read` of the file got the twin and was masked whole at the
    // path-derived level (VM run 2026-09-28): a secret row whose value is the twin.
    const masked = await k.c.symbolizeFull({ tool: "read", value: twin, origin: k.env, sessionKey: "sr", callId: "toolu_read_1" });
    assert.ok(masked.confidentiality && masked.confidentiality !== "public", JSON.stringify(masked));
    // Before: every later rendering of the twin (a Read, a `cat`) matched that row.
    assert.deepEqual((await k.c.scanSecretValues(twin)).hits, [], "the twin itself is no registered value");
    const line = twin.split("\n").find((l) => l.startsWith("STRIPE_KEY="))!;
    assert.deepEqual((await k.c.scanSecretValues(`${line}\n`)).hits, [], "nor is a line of it");
    // and the release it blocked now happens
    await k.c.recordExecRoot({ procKey: "t-sh-r", argv: ["/bin/sh", "-c", "cat .env"], session: "sr" });
    assert.deepEqual((await k.c.callTaint("call_after_read", { command: "cat .env", session: "sr", output: twin })).twinOf, [k.env]);
    // NEGATIVE: a row holding raw bytes (a masked raw read) still fingerprints
    const raw = await k.c.symbolizeFull({ tool: "read", value: RAW, origin: k.env, sessionKey: "sr", callId: "toolu_read_2" });
    const hits = (await k.c.scanSecretValues(`leaked: ${RAW}`)).hits.map((h) => h.symbol);
    assert.ok(hits.includes(raw.symbol), JSON.stringify(hits));
  } finally { await k.done(); }
});

// ── "A document's own twin" (plan 10 §11.8, 2026-10-12) ──────────────────────

const DOC_CANARY = "DOC_TWIN_CANARY_5150";

async function docStack() {
  const dir = mkdtempSync(join(tmpdir(), "mandu-doc-twin-"));
  const doc = join(dir, "brief.md");
  const doc2 = join(dir, "plan.md");
  const env = join(dir, ".env");
  writeFileSync(doc, `Deal brief. Reference code: ${DOC_CANARY}.\n`);
  writeFileSync(doc2, "Second plan, also internal.\n");
  writeFileSync(env, RAW);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${doc}`, "    level: any-model", "    bindings: [example.com]", `  - path: ${doc2}`, "    level: no-model", ""].join("\n"));
  const s = new ArbiterServer({ socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0 });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock"));
  await c.connect();
  return { dir, doc, doc2, env, s, c, done: async () => { c.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("a document's whole-file twin, in a tree the guard saw read no secret: callTaint names the file and says twinWhole", async () => {
  const k = await docStack();
  try {
    const reg = await k.c.registerSecret({ path: k.doc });
    assert.match(String(reg.symbol), /^\$MDU:anymodel_Read\[[0-9a-f]{4,8}\]$/);
    assert.equal(reg.twin, undefined, "a document: the whole-file twin");
    assert.equal(reg.terminator, "\n");
    const tok = String(reg.symbol);
    const head = "Chunk ID: 9a\nWall time: 0.01 seconds\nProcess exited with code 0\nOutput:\n";
    await k.c.recordExecRoot({ procKey: "d-sh-1", argv: ["/bin/sh", "-c", "cat brief.md"], session: "sd" });
    const t = await k.c.callTaint("call_doc_1", { command: "cat brief.md", session: "sd", output: `${head}${tok}\n`, codexHead: true });
    assert.equal(t.level, null);
    assert.deepEqual(t.twinOf, [k.doc]);
    assert.equal(t.twinWhole, true);
    // the token alone (a runtime that trimmed the newline)
    const bare = await k.c.callTaint("call_doc_1", { command: "cat brief.md", session: "sd", output: tok });
    assert.deepEqual(bare.twinOf, [k.doc]);
    // the structured rule is unchanged: its answer carries no twinWhole
    const envTwin = (await k.c.registerSecret({ path: k.env })).twin as string;
    await k.c.recordExecRoot({ procKey: "d-sh-2", argv: ["/bin/sh", "-c", "cat .env"], session: "se" });
    const st = await k.c.callTaint("call_env_1", { command: "cat .env", session: "se", output: envTwin });
    assert.deepEqual(st.twinOf, [k.env]);
    assert.equal(st.twinWhole, undefined);
  } finally { await k.done(); }
});

test("a document's twin: no evidence, a tainted tree, another byte, two files, a structured file's base token: no twinOf", async () => {
  const k = await docStack();
  try {
    const tok = String((await k.c.registerSecret({ path: k.doc })).symbol);
    const tok2 = String((await k.c.registerSecret({ path: k.doc2 })).symbol);
    const envBase = String((await k.c.registerSecret({ path: k.env })).symbol);
    // no root recorded: the text alone is not evidence
    const none = await k.c.callTaint("call_d_none", { command: "cat brief.md", session: "sn", output: `${tok}\n` });
    assert.equal(none.root, null);
    assert.equal(none.twinOf, undefined);
    // a process in the tree read the document raw: rule (i) owns it
    await k.c.recordExecRoot({ procKey: "dr-sh-1", argv: ["/bin/sh", "-c", "cat brief.md"], session: "sr" });
    await k.c.processLineage({ childKey: "dr-cat-2", parentKey: "dr-sh-1" });
    await k.c.taintProcessSecret({ procKey: "dr-cat-2", path: k.doc, level: "any-model", app: "cat" });
    const tainted = await k.c.callTaint("call_d_raw", { command: "cat brief.md", session: "sr", output: `${tok}\n` });
    assert.equal(tainted.level, "any-model");
    assert.equal(tainted.twinOf, undefined);
    // evidence, but not exactly the twin
    await k.c.recordExecRoot({ procKey: "dw-sh-1", argv: ["/bin/sh", "-c", "cat brief.md"], session: "sw" });
    for (const output of [
      `     1\t${tok}\n`, // cat -n
      `${tok}\ndone\n`, // a second command's output
      `${tok}\n${tok2}\n`, // two files
      `${tok}\r\n`, // not the file's terminator
      tok.slice(0, 12), // head -c 12
      `${envBase}\n`, // a structured file's base token: its twin is never the token alone
      `Deal brief. Reference code: ${DOC_CANARY}.\n`, // the raw document
    ]) {
      const r = await k.c.callTaint("call_d_shape", { command: "cat brief.md", session: "sw", output });
      assert.equal(r.twinOf, undefined, JSON.stringify(output));
      assert.equal(r.twinWhole, undefined);
    }
  } finally { await k.done(); }
});
