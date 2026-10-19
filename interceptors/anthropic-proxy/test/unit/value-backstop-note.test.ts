/**
 * value-backstop-note.test.ts — confidentiality.md §7.1, "the value-backstop
 * note" (2026-10-17). A result the arbiter's value backstop raised (a
 * registered secret's value printed in an old log, a file the path rules
 * call public) is masked whole like a path-derived one, but the call names
 * no secret path. It used to get the path-derived note ("the command names a
 * secret file … run that part again as a command of its own that names no
 * secret file"), which is false there and sent the model in circles: a
 * scripted probe of demo-api-401-debug's old payments log got it on `cat`
 * and `grep` of the log. Such a result now gets its own static line, on any
 * tool (a Read is masked whole the same way), and never the path-derived one.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildSecretNote, rewriteRequest } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const KEY = "sk_test_NOTEPROBE_2718281828";
const LOG = `[08:00:01] check (DEBUG=1)\nDEBUG: Authorization: Bearer ${KEY}\n[08:00:02] ok: HTTP 200\n[20:00:01] warning: STRIPE_KEY is empty\n`;
const CMD = "cat shop-app/logs/payments.log";
const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;
const NOTE = "[mandu:secret] masked: this output contains the value of a registered secret, so the whole output is withheld from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). It is withheld for that value, not for the file it came from. To read the rest, run a command that prints it with the value left out (for example without the lines that hold it); do not print the value in any other form. Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.";

/** classify: the path rules call the log public; the value backstop raised it. */
const backstopVerdict = (): ClassifyResult => ({
  trust: "TRUSTED", category: null, reason: "mock; a registered secret appears verbatim", confidentiality: "no-model",
  raisedBy: "value-backstop",
});
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

function call(name: string, input: Record<string, unknown>, content: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "payments broke last night; here is the log" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_1", name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_1", content }] },
    ],
  } as MessagesRequest;
}
const text = (out: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);

test("buildSecretNote: the value-backstop line, static, and never beside a listed reader's release line", () => {
  const base = { level: "public", files: [], apps: [], rule: "secret" as const, maskWhole: false, denied: [], deniedOnly: false, why: "" };
  assert.equal(buildSecretNote({ ...base, valueBackstop: true }), NOTE);
  // a listed reader's release that the backstop overruled: no "released by the program's rule" line
  const t = buildSecretNote({ ...base, files: ["/w/.env"], apps: ["psql"], valueBackstop: true })!;
  assert.equal(t, NOTE);
});

test("a Bash `cat` of a public log the value backstop raised: the symbol, then the value-backstop note; no path-derived advice, no output byte", async () => {
  const arbiter = new MockArbiter({ classifyFn: backstopVerdict, callTaintFn: () => wire({}) });
  const out = await rewriteRequest(call("Bash", { command: CMD }, LOG), { arbiter });
  const t = text(out);
  const [symbol, note, ...rest] = t.split("\n\n");
  assert.match(symbol!, SYM_RE);
  assert.equal(note, NOTE);
  assert.deepEqual(rest, []);
  assert.ok(!t.includes("the command names"), "no path-derived line: the command names no secret file");
  assert.ok(!t.includes("names no secret file"), "no path-derived advice");
  // THE ORACLE: nothing of the output reaches the model.
  for (const piece of [KEY, "NOTEPROBE", "Authorization", "STRIPE_KEY is empty", "HTTP 200"]) {
    assert.ok(!t.includes(piece), `output byte(s) reached the model: ${piece}`);
  }
  assert.equal(out.rewrites[0]!.secretTaint?.valueBackstop, true);
  assert.equal(out.rewrites[0]!.secretTaint?.pathDerived, undefined);
});

test("no taint answer at all (an arbiter without callTaint): the same note", async () => {
  const arbiter = new MockArbiter({ classifyFn: backstopVerdict });
  const t = text(await rewriteRequest(call("Bash", { command: CMD }, LOG), { arbiter }));
  assert.ok(t.endsWith(`\n\n${NOTE}`), t);
});

test("a Read of the same log: masked whole, and the value-backstop note says why", async () => {
  const arbiter = new MockArbiter({ classifyFn: backstopVerdict });
  const t = text(await rewriteRequest(call("Read", { file_path: "/w/shop-app/logs/payments.log" }, LOG), { arbiter }));
  const [symbol, note] = t.split("\n\n");
  assert.match(symbol!, SYM_RE);
  assert.equal(note, NOTE);
  assert.ok(!t.includes(KEY), t);
});

test("only the backstop case: a path-derived mask keeps the path-derived note, a taint mask its own line", async () => {
  const path = new MockArbiter({
    classifyFn: (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "no-model", namedPaths: [".env"] }),
    callTaintFn: () => wire({}),
  });
  const p = text(await rewriteRequest(call("Bash", { command: "cat .env" }, "K=v"), { arbiter: path }));
  assert.match(p, /\[mandu:secret\] masked: the command names a secret file \(\.env\)/);
  assert.ok(!p.includes("registered secret"), p);

  const taint = new MockArbiter({ classifyFn: backstopVerdict, callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["cat"] }) });
  const tt = text(await rewriteRequest(call("Bash", { command: "cat .env logs/payments.log" }, LOG), { arbiter: taint }));
  assert.match(tt, /\[mandu:secret\] masked: cat read \/w\/\.env/);
  assert.ok(!tt.includes("registered secret"), "a taint-masked result keeps its own reason");
});
