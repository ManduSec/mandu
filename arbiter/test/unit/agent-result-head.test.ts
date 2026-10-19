/**
 * agent-result-head.test — plan 10 §11.14: a Codex result masked whole
 * registers its value and its long lines, but not the lines of the head
 * Codex's runtime wrote in front of the command's output. The head is
 * matched by exact structure at offset 0 of a value the symbolize request
 * names as Codex's whole result (`resultHead: "codex"`); a line that merely
 * reads like a head line anywhere else stays registered.
 *
 * Confidentiality axis: what the value backstop serves.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { codexResultHeadLength, isWholeWriteNotice, parseResultHead, resultHeadLength, writeNoticeHeadLength } from "../../policy/agent-result-head.js";
import { ResultHeadStore } from "../../symbol-table/result-heads.js";
import { lineFingerprints } from "../../policy/egress-fingerprint.js";
import { RegisteredValueIndex } from "../../prompt-filter/registered-values.js";
import type { SymbolEntry, SymbolMap } from "../../symbol-table/symbol-table.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const EXEC_HEAD = "Chunk ID: 9a3f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 11\nOutput:\n";
const SECRET_LINE = "db:5432:*:app:hunter2-very-secret-password";

test("codexResultHeadLength: the exact Codex head forms at offset 0", () => {
  const forms = [
    EXEC_HEAD,
    "Chunk ID: 1\nWall time: 0.5 seconds\nProcess running with session ID 12\nOriginal token count: 3\nOutput:\n",
    "Chunk ID: ba993e\nProcess exited with code 2\nOutput:\n", // the older three-line form
    "Script completed\nWall time 0.2 seconds\nOutput:\n",
    "Script failed (exit code 1)\nWall time 0.2 seconds\nProcess exited with code 1\nOriginal token count: 4\nOutput:\n",
    "Script running with cell ID 1\nWall time 0.2 seconds\nOutput:\n",
  ];
  for (const h of forms) {
    assert.equal(codexResultHeadLength(`${h}${SECRET_LINE}\n`), h.length, JSON.stringify(h));
    assert.equal(codexResultHeadLength(h), h.length, "a head-only result");
  }
});

test("codexResultHeadLength: anything that is not exactly the grammar at offset 0 is no head", () => {
  for (const v of [
    `x\n${EXEC_HEAD}${SECRET_LINE}`, // not at offset 0
    ` ${EXEC_HEAD}`,
    "Chunk ID: 9a3f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 11\n", // no Output: line
    "Chunk ID: 9a3f\nProcess exited with code 0\nProcess running with session ID 3\nOutput:\n", // both status lines
    "Chunk ID: XYZ\nProcess exited with code 0\nOutput:\n", // chunk id not hex
    `Chunk ID: ${"a".repeat(33)}\nProcess exited with code 0\nOutput:\n`, // chunk id too long
    "Chunk ID: 9a\nProcess exited with code 0 hunter2\nOutput:\n", // a payload past the digits
    "Chunk ID: 9a\nWall time: 0.1 seconds\nOutput:\n", // no status line
    "Wall time: 0.1 seconds\nOutput:\n", // the MCP header is not an exec head
    "Script finished\nOutput:\n", // a status word off the closed set
    "Process exited with code 0\nOutput:\n",
    "",
  ]) assert.equal(codexResultHeadLength(v), 0, JSON.stringify(v));
  assert.equal(parseResultHead("codex"), "codex");
  for (const v of [undefined, "", "Codex", "claude", 1, null]) assert.equal(parseResultHead(v), null);
});

test("lineFingerprints(value, head): the head's lines are skipped, the body keeps every line, a header-looking body line included", () => {
  const body = `${SECRET_LINE}\nProcess exited with code 0\nOriginal token count: 11\n`;
  const value = `${EXEC_HEAD}${body}`;
  const head = codexResultHeadLength(value);
  assert.deepEqual(lineFingerprints(value), [
    "Wall time: 0.0123 seconds", "Process exited with code 0", "Original token count: 11", SECRET_LINE,
  ], "control: without the head, every long line is registered");
  // the command printed lines identical in text to head lines: in the BODY they stay registered
  assert.deepEqual(lineFingerprints(value, head), [SECRET_LINE, "Process exited with code 0", "Original token count: 11"]);
  // a one-line output after the head keeps its line (the value is still multi-line)
  assert.deepEqual(lineFingerprints(`${EXEC_HEAD}${SECRET_LINE}`, codexResultHeadLength(`${EXEC_HEAD}${SECRET_LINE}`)), [SECRET_LINE]);
  // a head-only value registers no line
  assert.deepEqual(lineFingerprints(EXEC_HEAD, EXEC_HEAD.length), []);
});

function row(value: string, tool = "exec_command"): SymbolEntry {
  return {
    value, tool, field: null, origin: null, session_key: "s", call_id: "c", created_at: 0,
    obsoleted_at: null, obsoleted_by: null, derived_from: null, line_range: null,
    confidentiality: "no-model", bindings: null, integrity: "untrusted",
  };
}

test("RegisteredValueIndex: a headed row's head lines are no hit, its body lines are (header-looking ones too); an unnamed row keeps every line", () => {
  const headed = `${EXEC_HEAD}${SECRET_LINE}\n`;
  const forged = `${EXEC_HEAD}${SECRET_LINE}\nChunk ID: 0123456789abcdef0123456789abcdef\nProcess exited with code 0\n`;
  const map: SymbolMap = { symbols: new Map([["$MDU:a[0001]", row(headed)], ["$MDU:a[0002]", row(forged)]]) };
  const idx = new RegisteredValueIndex();
  idx.sync(map); // no head named: the pre-§11.14 behaviour
  assert.deepEqual(idx.hits("Process exited with code 0").map((h) => h.symbol), ["$MDU:a[0001]", "$MDU:a[0002]"]);
  const named = new Set(["$MDU:a[0001]", "$MDU:a[0002]"]);
  idx.sync(map, (name, e) => (named.has(name) ? codexResultHeadLength(e.value) : 0), 1);
  assert.deepEqual(idx.hits(`${EXEC_HEAD}hi\n`).map((h) => h.symbol), ["$MDU:a[0002]"],
    "a later clean result carrying only Codex's head lines is no hit on the headed row (the other row's command printed one of them)");
  assert.deepEqual(idx.hits("Wall time: 0.0123 seconds\nOriginal token count: 11"), [], "head lines are no hit");
  assert.deepEqual(idx.hits("Process exited with code 0").map((h) => h.symbol), ["$MDU:a[0002]"],
    "the line the command printed in its output (identical to a head line) is still registered");
  assert.deepEqual(idx.hits("Chunk ID: 0123456789abcdef0123456789abcdef").map((h) => h.symbol), ["$MDU:a[0002]"]);
  assert.deepEqual(idx.hits(`later: ${SECRET_LINE}`).map((h) => h.symbol), ["$MDU:a[0001]", "$MDU:a[0002]"], "the secret line stays registered");
  assert.deepEqual(idx.hits(headed).map((h) => ({ ...h })), [{ symbol: "$MDU:a[0001]", how: "value" }, { symbol: "$MDU:a[0002]", how: "line" }], "the whole value stays a fingerprint");
});

test("the arbiter learns the head only from a symbolize that names it AND a value that starts with it; the body's header-looking line stays registered (real server)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-result-head-"));
  const s = new ArbiterServer({ socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock"));
  await c.connect();
  try {
    // an evidential exec-output row: its call's tree read a secret raw (plan 10 rule (i))
    const evidence = async (callId: string, procKey: string): Promise<void> => {
      await c.recordExecRoot({ procKey, argv: ["/bin/sh", "-c", "cat creds"], session: "rh" });
      await c.taintProcessSecret({ procKey, path: join(dir, "creds"), level: "no-model", app: "cat", session: "rh" });
      await c.recordCallRoot({ callId, procKey, session: "rh" });
    };
    const hitBy = async (text: string): Promise<string[]> => (await c.scanSecretValues(text)).hits.map((h) => h.symbol);

    // 1. named and headed: the head's lines are not registered, the body's are
    await evidence("call_h1", "rh-sh-1");
    const v1 = `${EXEC_HEAD}${SECRET_LINE}\nProcess running with session ID 4242\n`;
    const s1 = await c.symbolize({ tool: "exec_command", value: v1, origin: "cat creds", confidentiality: "no-model", sessionKey: "rh", callId: "call_h1", resultHead: "codex" });
    assert.deepEqual(await hitBy(`${EXEC_HEAD}hi\n`), [], "Codex's head lines are not registered values");
    assert.deepEqual(await hitBy(`x\n${SECRET_LINE}\n`), [s1]);
    assert.deepEqual(await hitBy("Process running with session ID 4242"), [s1],
      "a line the command printed is registered even though it reads like a head line");

    // 2. the same value NOT named (the split path's body, a pre-§11.14 proxy): every line counts
    await evidence("call_h2", "rh-sh-2");
    const s2 = await c.symbolize({ tool: "exec_command", value: `${EXEC_HEAD}other-secret-line-0123456789abcdef\n`, origin: "cat creds", confidentiality: "no-model", sessionKey: "rh", callId: "call_h2" });
    assert.deepEqual(await hitBy("Process exited with code 0"), [s2], "an unnamed row keeps its head-looking lines");

    // 3. named, but the value does not start with exactly the grammar: every line counts
    await evidence("call_h3", "rh-sh-3");
    const v3 = `Chunk ID: 9a3f\nProcess exited with code 0 and more\nOriginal token count: 77\nOutput:\nthird-secret-line-0123456789abcdef\n`;
    const s3 = await c.symbolize({ tool: "exec_command", value: v3, origin: "cat creds", confidentiality: "no-model", sessionKey: "rh", callId: "call_h3", resultHead: "codex" });
    assert.ok((await hitBy("Original token count: 77")).includes(s3), "no exact head: the hint is ignored");
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── 2026-10-09: Codex's MCP head, Claude Code's poll tags, durable marks ──

const MCP_HEAD = "Wall time: 0.0055 seconds\nOutput:";
const TASK_HEAD = "<retrieval_status>success</retrieval_status>\n\n<task_id>b1x9</task_id>\n\n<task_type>local_bash</task_type>\n\n<status>completed</status>\n\n<exit_code>0</exit_code>\n\n<output>\n";
const BASHOUTPUT_HEAD = "<status>running</status>\n\n<exit_code>0</exit_code>\n\n<stdout>\n";

test("resultHeadLength: Codex's MCP head and Claude Code's poll tags at offset 0, each only under its own kind", () => {
  // the MCP head: the parts form runs straight on into the server's text; the string form has one \n
  assert.equal(resultHeadLength("codex-mcp", `${MCP_HEAD}${SECRET_LINE}`), MCP_HEAD.length);
  assert.equal(resultHeadLength("codex-mcp", `${MCP_HEAD}\n${SECRET_LINE}`), MCP_HEAD.length + 1);
  assert.equal(resultHeadLength("codex-mcp", "Wall time: 9 seconds\nOutput:"), "Wall time: 9 seconds\nOutput:".length);
  // the poll tags: TaskOutput's and BashOutput's, a head-only poll
  assert.equal(resultHeadLength("claude-task", `${TASK_HEAD}${SECRET_LINE}\n</output>`), TASK_HEAD.length);
  assert.equal(resultHeadLength("claude-task", `${BASHOUTPUT_HEAD}${SECRET_LINE}\n</stdout>`), BASHOUTPUT_HEAD.length);
  const pending = "<retrieval_status>not_ready</retrieval_status>\n\n<task_id>b1</task_id>\n\n<status>running</status>";
  assert.equal(resultHeadLength("claude-task", pending), pending.length);
  // the codex kind is the exec grammar, unchanged
  assert.equal(resultHeadLength("codex", `${EXEC_HEAD}${SECRET_LINE}`), EXEC_HEAD.length);
  // a head of another kind is no head
  assert.equal(resultHeadLength("codex", `${MCP_HEAD}\n${SECRET_LINE}`), 0);
  assert.equal(resultHeadLength("codex-mcp", `${EXEC_HEAD}${SECRET_LINE}`), 0);
  assert.equal(resultHeadLength("claude-task", `${EXEC_HEAD}${SECRET_LINE}`), 0);
  assert.equal(resultHeadLength("codex-mcp", `${TASK_HEAD}${SECRET_LINE}`), 0);
  for (const k of ["codex", "codex-mcp", "claude-task"] as const) assert.equal(parseResultHead(k), k);
});

test("resultHeadLength: anything off the exact MCP and poll grammars is no head; no head ever spans a byte past its grammar", () => {
  for (const v of [
    `x${MCP_HEAD}`, ` ${MCP_HEAD}`,
    "Wall time: 0.1 seconds hunter2\nOutput:",
    "Wall time 0.1 seconds\nOutput:", // the script cell's spelling is not the MCP head
    "Wall time: 0.1 seconds\n",
  ]) assert.equal(resultHeadLength("codex-mcp", v), 0, JSON.stringify(v));
  // `Output:` runs on into the server's text in the parts form: the head ends at the colon, the rest is body
  assert.equal(resultHeadLength("codex-mcp", "Wall time: 0.1 seconds\nOutput: hunter2"), "Wall time: 0.1 seconds\nOutput:".length);
  for (const v of [
    `x\n${TASK_HEAD}`, ` ${TASK_HEAD}`,
    "<status>done</status>\n<output>\n", // a status off the closed set
    "<status>completed</status> hunter2\n", // a payload past the tag
    `<task_id>${"k".repeat(65)}</task_id>\n`, // an id over 64
    "<task_id>a b</task_id>\n", "<exit_code>0x1</exit_code>\n",
    "<retrieval_status>maybe</retrieval_status>\n", "<task_type>Local Bash</task_type>\n",
    "<output>\nsecret\n", // no status tag at all
    "<stdout>\n",
    "",
  ]) assert.equal(resultHeadLength("claude-task", v), 0, JSON.stringify(v));
  // a tag line with a payload past it ends the head before that line
  const v = "<status>completed</status>\n<exit_code>0</exit_code> hunter2\n";
  assert.equal(resultHeadLength("claude-task", v), "<status>completed</status>\n".length);
});

test("lineFingerprints after the MCP and poll heads: the head's lines are skipped, a body line reading like a head line is registered", () => {
  const status = "<retrieval_status>success</retrieval_status>";
  const body = `${SECRET_LINE}\n${status}\n</output>`;
  const value = `${TASK_HEAD}${body}`;
  assert.ok(lineFingerprints(value).includes("<task_type>local_bash</task_type>"), "control: the tags are lines of 24+");
  assert.deepEqual(lineFingerprints(value, resultHeadLength("claude-task", value)), [SECRET_LINE, status],
    "the task printed a status tag: in the body it stays registered");
  const wall = "Wall time: 0.0055 seconds";
  const mcp = `${MCP_HEAD}${SECRET_LINE}\n${wall}`;
  assert.deepEqual(lineFingerprints(mcp), [wall, `Output:${SECRET_LINE}`], "control");
  assert.deepEqual(lineFingerprints(mcp, resultHeadLength("codex-mcp", mcp)), [SECRET_LINE, wall]);
});

test("ResultHeadStore: a mark is bound to its row's value; a gone row or a changed value is not loaded", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-result-head-store-"));
  try {
    const dbPath = join(dir, "db.sqlite");
    const store = new ResultHeadStore({ dbPath });
    store.record("$MDU:a[0001]", "codex", `${EXEC_HEAD}${SECRET_LINE}`);
    store.record("$MDU:a[0002]", "claude-task", `${TASK_HEAD}x`);
    store.record("$MDU:a[0003]", "codex-mcp", `${MCP_HEAD}y`);
    store.close();
    const again = new ResultHeadStore({ dbPath });
    const map: SymbolMap = {
      symbols: new Map([
        ["$MDU:a[0001]", row(`${EXEC_HEAD}${SECRET_LINE}`)],
        ["$MDU:a[0002]", row(`${TASK_HEAD}another value`)], // another value under the name
      ]),
    };
    assert.deepEqual([...again.load(map)], [["$MDU:a[0001]", "codex"]]);
    again.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an arbiter restart keeps every result-head mark: the head lines stay unregistered, the secret line and the whole value stay registered (real server)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-result-head-restart-"));
  const opts = { socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false };
  const boot = async (): Promise<{ s: ArbiterServer; c: ArbiterClient }> => {
    const s = new ArbiterServer(opts);
    await s.listen();
    const c = new ArbiterClient(join(dir, "human", "h.sock"));
    await c.connect();
    return { s, c };
  };
  let { s, c } = await boot();
  try {
    const evidence = async (callId: string, procKey: string): Promise<void> => {
      await c.recordExecRoot({ procKey, argv: ["/bin/sh", "-c", "cat creds"], session: "rr" });
      await c.taintProcessSecret({ procKey, path: join(dir, "creds"), level: "no-model", app: "cat", session: "rr" });
      await c.recordCallRoot({ callId, procKey, session: "rr" });
    };
    const values: Array<[string, string, string]> = [
      ["codex", "exec_command", `${EXEC_HEAD}${SECRET_LINE}\n`],
      ["codex-mcp", "mcp__box__run", `${MCP_HEAD}mcp-row:9921:kV3pQ8sZ-another-secret-line\n`],
      ["claude-task", "TaskOutput", `${TASK_HEAD}task-row:7710:Lm4xT2wR-third-secret-line\n</output>`],
    ];
    const minted: string[] = [];
    for (const [i, [kind, tool, value]] of values.entries()) {
      await evidence(`call_r${i}`, `rr-sh-${i}`);
      minted.push(await c.symbolize({ tool, value, origin: "cat creds", confidentiality: "no-model", sessionKey: "rr", callId: `call_r${i}`, resultHead: kind }));
    }
    const headLines = "Process exited with code 0\nOriginal token count: 11\nWall time: 0.0055 seconds\n<retrieval_status>success</retrieval_status>\n<task_type>local_bash</task_type>\n<status>completed</status>";
    const check = async (when: string): Promise<void> => {
      assert.deepEqual((await c.scanSecretValues(headLines)).hits, [], `${when}: no head line is a registered value`);
      for (const [i, [kind, , value]] of values.entries()) {
        const line = value.split("\n").find((l) => /secret/.test(l))!.replace(/^Output:/, "");
        assert.deepEqual((await c.scanSecretValues(`later: ${line}`)).hits.map((h) => h.symbol), [minted[i]], `${when}: ${kind}'s secret line stays registered`);
        assert.ok((await c.scanSecretValues(value)).hits.some((h) => h.symbol === minted[i] && (h as { how?: string }).how === "value"), `${when}: ${kind}'s whole value stays registered`);
      }
    };
    await check("before the restart");
    c.close();
    await s.close();
    ({ s, c } = await boot());
    await check("after the restart, with no re-send");
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── 2026-10-11: the write notice (plan 15 §13.10, "The notice is no piece") ──

const P = "/ws/deploy/app.env";
const OC1 = "Wrote file successfully.";
const DIAG_LINE = `ERROR [1:11] ${SECRET_LINE}`;
const DIAG = `\n\nLSP errors detected in this file, please fix:\n<diagnostics file="${P}">\n${DIAG_LINE}\n</diagnostics>`;
const CC_CURRENT = " (file state is current in your context — no need to Read it back)";
const NOTICES: Array<[string, string]> = [
  ["claude-code created", `File created successfully at: ${P}`],
  ["claude-code created, suffixes", `File created successfully at: ${P} The user modified your proposed content before accepting it.${CC_CURRENT}`],
  ["claude-code updated", `The file ${P} has been updated successfully.${CC_CURRENT}`],
  ["opencode 2", `Created file successfully: ${P}`],
  ["opencode 1", OC1],
  ["goose", `Created ${P} (12 lines)`],
  ["openclaw", `Successfully wrote 22 bytes to ${P}`],
];

test("writeNoticeHeadLength: each pinned notice on the first line, its path the row's own origin; the line break after it is head", () => {
  for (const [what, n] of NOTICES) {
    assert.equal(writeNoticeHeadLength(n, P), n.length, what);
    assert.equal(writeNoticeHeadLength(`${n}${DIAG}`, P), n.length + 1, `${what}: diagnostics after it are body`);
    assert.equal(resultHeadLength("write-notice", `${n}\n${SECRET_LINE}`, P), n.length + 1, `${what}: by kind`);
    assert.ok(isWholeWriteNotice("write", null, n, P) && isWholeWriteNotice("Write", null, `${n}\n`, P), `${what}: whole`);
  }
  // a relative path the arbiter placed at the launch directory
  const rel = "Successfully wrote 5 bytes to deploy/app.env";
  assert.equal(writeNoticeHeadLength(rel, P), rel.length);
  assert.equal(writeNoticeHeadLength("Created file successfully: app.env", P), "Created file successfully: app.env".length);
  // OpenCode 1's sentence names no path: no origin needed
  assert.equal(writeNoticeHeadLength(OC1, null), OC1.length);
  assert.equal(parseResultHead("write-notice"), "write-notice");
});

test("writeNoticeHeadLength: another path, no origin, not at offset 0, a payload past the sentence, a lookalike: no head", () => {
  for (const [what, n] of NOTICES.filter(([w]) => w !== "opencode 1")) {
    assert.equal(writeNoticeHeadLength(n, "/ws/other.env"), 0, `${what}: another path`);
    assert.equal(writeNoticeHeadLength(n, null), 0, `${what}: no origin to check the path against`);
    assert.equal(writeNoticeHeadLength(n.replace(P, `${P} ${SECRET_LINE}`), P), 0, `${what}: a payload in the path span`);
  }
  for (const v of [
    `x${OC1}`, ` ${OC1}`, `\n${OC1}`, `${OC1} ${SECRET_LINE}`, "Wrote file successfully", "wrote file successfully.",
    `${SECRET_LINE}\n${OC1}`, // the notice on a later line is body
    `Created ${P} (twelve lines)`, `Created ${P} (1234567890123 lines)`, `Successfully wrote 1e3 bytes to ${P}`,
    `Successfully wrote 22 bytes to ${P.slice(1)}x`, // not the origin, nor a suffix of it after a "/"
    "Created file successfully: p.env", // a partial name is no relative path
    "",
  ]) assert.equal(writeNoticeHeadLength(v, P), 0, JSON.stringify(v));
  // whole: only a write tool's own row, one line
  assert.equal(isWholeWriteNotice("Bash", null, OC1, P), false, "another tool");
  assert.equal(isWholeWriteNotice("mcp__fs__write", null, OC1, P), false, "an MCP tool");
  assert.equal(isWholeWriteNotice("write", "content", OC1, P), false, "a field row");
  assert.equal(isWholeWriteNotice("write", null, `${OC1}${DIAG}`, P), false, "the notice and more");
  assert.equal(isWholeWriteNotice("write", null, `Created file successfully: ${P}`, "/ws/other.env"), false, "another path");
});

test("RegisteredValueIndex: a whole-notice row has no pattern; a notice-headed row keeps its body lines and its whole value; an unnamed row keeps the notice line", () => {
  const w = (value: string): SymbolEntry => ({ ...row(value, "write"), origin: P });
  const map: SymbolMap = {
    symbols: new Map([
      ["$MDU:w[0001]", w(OC1)], // the notice alone (a no-content call, a row from before the mark)
      ["$MDU:w[0002]", w(`${OC1}${DIAG}`)], // the diagnostics form, named by the proxy
      ["$MDU:w[0003]", w(`${OC1}${DIAG}`)], // the same, not named (fail-closed)
    ]),
  };
  const idx = new RegisteredValueIndex();
  const named = new Set(["$MDU:w[0002]"]);
  idx.sync(map, (name, e) => (isWholeWriteNotice(e.tool, e.field, e.value, e.origin) ? e.value.length : named.has(name) ? writeNoticeHeadLength(e.value, e.origin) : 0), 1);
  assert.deepEqual(idx.hits(OC1).map((h) => h.symbol), ["$MDU:w[0003]"], "only the unnamed row's notice line is a hit");
  assert.deepEqual(idx.hits(`later: ${DIAG_LINE}`).map((h) => h.symbol), ["$MDU:w[0002]", "$MDU:w[0003]"], "the diagnostics' line stays registered");
  assert.ok(idx.hits(`${OC1}${DIAG}`).some((h) => h.symbol === "$MDU:w[0002]" && h.how === "value"), "the headed row's whole value stays a fingerprint");
  // a path-bearing notice (Goose's) is no hit once named; the line after it is
  const g = `Created ${P} (1 lines)`;
  const gmap: SymbolMap = { symbols: new Map([["$MDU:w[0004]", w(`${g}\nwarning: ${SECRET_LINE}`)]]) };
  idx.sync(gmap, (_n, e) => writeNoticeHeadLength(e.value, e.origin), 2);
  assert.deepEqual(idx.hits(g), []);
  assert.deepEqual(idx.hits(`warning: ${SECRET_LINE}`).map((h) => h.symbol), ["$MDU:w[0004]"]);
});

test("the arbiter learns a write-notice head only for a write tool's own row whose first line is its notice; a whole-notice row needs no mark; marks survive a restart (real server)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-write-notice-head-"));
  const opts = { socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false };
  const boot = async (): Promise<{ s: ArbiterServer; c: ArbiterClient }> => {
    const s = new ArbiterServer(opts);
    await s.listen();
    const c = new ArbiterClient(join(dir, "human", "h.sock"));
    await c.connect();
    return { s, c };
  };
  let { s, c } = await boot();
  try {
    const hitBy = async (text: string): Promise<string[]> => (await c.scanSecretValues(text)).hits.map((h) => h.symbol);
    const sym = (args: { tool: string; value: string; origin: string; callId: string; resultHead?: string; field?: string }) =>
      c.symbolize({ ...args, confidentiality: "no-model", sessionKey: "wn" });
    // 1. named, its own path: the notice line is no piece, the diagnostics' line is
    const s1 = await sym({ tool: "write", value: `${OC1}${DIAG}`, origin: P, callId: "w1", resultHead: "write-notice" });
    const oc2 = `Created file successfully: ${P}`;
    const s2 = await sym({ tool: "write", value: `${oc2}\n\nLSP errors detected in this file, please fix:\n${DIAG_LINE}-2`, origin: P, callId: "w2", resultHead: "write-notice" });
    // 2. a whole-notice row (Claude Code's body once the proxy split its reminder tail off), no mark
    const cc = `File created successfully at: ${P}${CC_CURRENT}`;
    await sym({ tool: "Write", value: cc, origin: P, callId: "w3" });
    const check = async (when: string): Promise<void> => {
      assert.deepEqual(await hitBy(OC1), [], `${when}: OpenCode 1's notice is no registered value`);
      assert.deepEqual(await hitBy(oc2), [], `${when}: OpenCode 2's notice line is no registered value`);
      assert.deepEqual(await hitBy(`${cc}\n\n<system-reminder>\n<total_tokens>9 tokens left</total_tokens>\n</system-reminder>`), [], `${when}: Claude Code's notice is no registered value`);
      assert.ok((await hitBy(`later: ${DIAG_LINE}\n`)).includes(s1), `${when}: the diagnostics' line stays registered`);
      assert.ok((await hitBy(`later: ${DIAG_LINE}-2\n`)).includes(s2), `${when}: OpenCode 2's diagnostics' line stays registered`);
    };
    await check("before the restart");
    c.close();
    await s.close();
    ({ s, c } = await boot());
    await check("after the restart, with no re-send");

    // 3. fail-closed: the kind named where it does not hold keeps the notice line a piece
    const s4 = await sym({ tool: "Edit", value: `${OC1}\nfourth-secret-line-0123456789abcdef`, origin: P, callId: "w4", resultHead: "write-notice" });
    const s5 = await sym({ tool: "write", value: `${OC1}\nfifth-secret-line-0123456789abcdef`, origin: P, callId: "w5", field: "output", resultHead: "write-notice" });
    const s6 = await sym({ tool: "write", value: `Created file successfully: /ws/elsewhere.env\n${SECRET_LINE}-6`, origin: P, callId: "w6", resultHead: "write-notice" });
    const s7 = await sym({ tool: "write", value: `${OC1}\n${SECRET_LINE}-7`, origin: P, callId: "w7" }); // not named
    const hits = await hitBy(OC1);
    for (const [why, name] of [["another tool (Edit)", s4], ["a field row", s5], ["an unnamed row", s7]] as const) {
      assert.ok(hits.includes(name), `${why} keeps the notice line`);
    }
    assert.ok(!hits.includes(s1) && !hits.includes(s2), "the named rows still hold no notice piece");
    assert.ok((await hitBy("Created file successfully: /ws/elsewhere.env")).includes(s6), "a notice for another path than the row's is no head");
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
