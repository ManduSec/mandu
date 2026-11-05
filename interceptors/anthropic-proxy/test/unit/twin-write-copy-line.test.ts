/**
 * twin-write-copy-line.test.ts — the `copy:` line on a Claude Code call that
 * writes a protected file (plan 10 §4.1, "The model is told at the call",
 * 2026-10-27).
 *
 * demo-orders-sync-debug, live 2026-10-27: Edit's save of `orders-app/.env`
 * was refused (EACCES on the rename), `sed -i` too, and `cat >
 * orders-app/.env << 'EOF'` landed in the placeholder copy (its output masked
 * whole, path-derived); the sync run in the session read the copy and
 * succeeded, and the model told the person "Fixed!" while their real .env was
 * unchanged. The arbiter now answers `twinWrites` on such a call's classify
 * (only for a session the file guard confines: arbiter
 * `twin-writes-classify.test.ts`); this proxy adds the `copy:` line, after the
 * masked line on a masked result and after the program's own text on a
 * released one. Never for a token the call did not write itself, never
 * without the answer, and never a byte of the output.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { rewriteRequest } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { twinWriteLine } from "../../src/twin-write-note.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const ENV = "orders-app/.env";
const ABS = "/w/orders-app/.env";
const HEREDOC = `cat > ${ENV} << 'EOF'\nORDERHUB_URL=https://api.orderhub.test\nORDERHUB_PASSWORD='$MDU:nomodel_Read[a169].ORDERHUB_PASSPHRASE'\nEOF\n`;
const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;
const COPY = `[mandu:secret] ${twinWriteLine([ENV])}`;
const EDIT_REFUSED = `EACCES: permission denied, rename '${ABS}.tmp.2.5f8d4674dd18' -> '${ABS}'`;

/** The classify of the heredoc: masked by its path (the command names the
 *  .env), and the arbiter's answer of what it writes. */
const heredocVerdict = (twinWrites: string[] = [ENV]): ClassifyResult => ({
  trust: "TRUSTED", category: null, reason: "mock", confidentiality: "no-model",
  namedPaths: [ENV], twinWrites,
});
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

function call(name: string, input: Record<string, unknown>, content: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "Our order sync stopped working. Fix it." },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_1", name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_1", content }] },
    ],
  } as MessagesRequest;
}
const text = (out: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);

test("the drill's heredoc into the .env, answered: one symbol, the masked line, then the copy: line naming the .env; no output byte", async () => {
  const arbiter = new MockArbiter({ classifyFn: () => heredocVerdict(), callTaintFn: () => wire({}) });
  const out = await rewriteRequest(call("Bash", { command: HEREDOC, description: "Write the corrected .env file" }, "(Bash completed with no output)"), { arbiter });
  const [symbol, note, ...rest] = text(out).split("\n\n");
  assert.match(symbol!, SYM_RE);
  assert.deepEqual(rest, []);
  const lines = note!.split("\n");
  assert.equal(lines.length, 2, note);
  assert.match(lines[0]!, /^\[mandu:secret\] masked: the command names a secret file \(orders-app\/\.env\)/);
  assert.equal(lines[1], COPY);
  assert.ok(!text(out).includes("Bash completed"), "no byte of the output");
  assert.deepEqual(out.rewrites[0]!.secretTaint?.twinWrites, [ENV]);
});

test("no answer, no line: the arbiter's verdict without twinWrites (a session the guard does not confine) keeps the masked line alone", async () => {
  const arbiter = new MockArbiter({ classifyFn: () => { const { twinWrites: _none, ...v } = heredocVerdict(); return v; }, callTaintFn: () => wire({}) });
  const t = text(await rewriteRequest(call("Bash", { command: HEREDOC }, "(Bash completed with no output)"), { arbiter }));
  assert.ok(!t.includes("copy:"), t);
  assert.match(t, /\[mandu:secret\] masked: the command names/, "the masked line stays");
});

test("a token the call did not write itself (a resolved spelling) gets no line; the mask is unchanged", async () => {
  const arbiter = new MockArbiter({ classifyFn: () => heredocVerdict(["/home/u/w/orders-app/.env"]), callTaintFn: () => wire({}) });
  const t = text(await rewriteRequest(call("Bash", { command: HEREDOC }, "(Bash completed with no output)"), { arbiter }));
  assert.match(t, SYM_RE);
  assert.ok(!t.includes("copy:") && !t.includes("/home/u"), t);
});

test("Edit's refused save of the .env (released as the tool's own error): the error as written, then the copy: line naming the path", async () => {
  const arbiter = new MockArbiter({ classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public", twinWrites: [ABS] }) });
  const input = { file_path: ABS, old_string: "ORDERHUB_PASSPHRASE=", new_string: "ORDERHUB_PASSWORD=" };
  const t = text(await rewriteRequest(call("Edit", input, EDIT_REFUSED), { arbiter }));
  assert.equal(t, `${EDIT_REFUSED}\n\n[mandu:secret] ${twinWriteLine([ABS])}`);
});

test("a call that writes no protected file: nothing added, released or masked", async () => {
  const pub = new MockArbiter({ classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" }), callTaintFn: () => wire({}) });
  assert.equal(text(await rewriteRequest(call("Bash", { command: "echo x > notes.txt" }, ""), { arbiter: pub })), "");
  const masked = new MockArbiter({ classifyFn: () => heredocVerdict([]), callTaintFn: () => wire({}) });
  const t = text(await rewriteRequest(call("Bash", { command: `cat ${ENV}` }, "x"), { arbiter: masked }));
  assert.ok(!t.includes("copy:"), t);
});
