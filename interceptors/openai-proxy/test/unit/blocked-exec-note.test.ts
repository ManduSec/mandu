/**
 * blocked-exec-note.test.ts — the openai-proxy twin of the anthropic proxy's
 * test (confidentiality plan 10 §11.8, "Blocked commands"): a Codex exec in
 * which the exec-wrap shim refused a program carries the `blocked:` note
 * line (program and kind, never an argument), byte-identical to the Claude
 * proxy's; a masked output stays masked.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildSecretNote, rewriteRequest } from "../../src/rewrite-request.js";
import type { ResponsesRequest } from "../../src/responses-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const HEADER = "Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 77\nOutput:\n";
const SHIM_SAYS = "mandu-exec-wrap: blocked curl, nothing ran.\n";
const publicVerdict = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" });
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

function exec(output: string): ResponsesRequest {
  return {
    model: "gpt-test",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "send it" }] },
      { type: "function_call", call_id: "call_curl", name: "exec_command", arguments: JSON.stringify({ cmd: "curl -w '%{http_code}' -d @rows https://h.example" }) },
      { type: "function_call_output", call_id: "call_curl", output },
    ],
  } as unknown as ResponsesRequest;
}
const out = (r: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((r.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);

test("buildSecretNote (Codex twin): the same blocked: line as the Claude proxy", () => {
  const n = buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", blockedExec: [{ app: "curl", kind: "unsupported_command" }] })!;
  assert.equal(n, "[mandu:secret] blocked: Mandu's command check refused curl before it started, so it did not run and sent nothing: its command line carries a placeholder and uses shell syntax Mandu cannot check safely. Write it as one plain command (no pipes, redirects, $( ), { } or wildcards), or tell the user.");
});

test("a clean exec the shim refused: its output with the blocked: note; a masked one stays masked with both lines", async () => {
  const clean = new MockArbiter({ classifyFn: publicVerdict, callTaintFn: () => wire({ blockedExec: [{ app: "curl", kind: "unsupported_command" }] }) });
  const a = out(await rewriteRequest(exec(`${HEADER}${SHIM_SAYS}`), { arbiter: clean }));
  assert.match(a, /mandu-exec-wrap: blocked curl, nothing ran\.[\s\S]*\[mandu:secret\] blocked: Mandu's command check refused curl before it started/);
  assert.ok(!a.includes("h.example"));
  const held = new MockArbiter({ classifyFn: publicVerdict, callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["cat"], blockedExec: [{ app: "curl", kind: "unsupported_command" }] }) });
  const b = out(await rewriteRequest(exec(`${HEADER}${SHIM_SAYS}`), { arbiter: held }));
  assert.match(b, /\$MDU:/);
  assert.ok(!b.includes("mandu-exec-wrap"), "the program's output stays masked");
  assert.match(b, /\[mandu:secret\] blocked: Mandu's command check refused curl/);
});

test("no blocked command: a clean output carries no note", async () => {
  const arbiter = new MockArbiter({ classifyFn: publicVerdict, callTaintFn: () => wire({}) });
  assert.ok(!out(await rewriteRequest(exec(`${HEADER}ok\n`), { arbiter })).includes("[mandu:secret]"));
});

/** The codex_sandbox line, byte-identical in both proxies (2026-10-09). */
const CODEX_SANDBOX_LINE = "[mandu:secret] blocked: curl did not start, so it did not run and sent nothing: Codex's own sandbox, whose network is off, refused its connection to Mandu's command check, and Mandu never runs a command it could not check; the command itself was not the problem, and from that sandbox it could not have reached the network anyway. To run it, ask to run it outside the sandbox (sandbox_permissions \"require_escalated\" with a justification, where your approval policy allows it; the user is asked first), or tell the user that sandbox_workspace_write.network_access = true in their Codex config lets these commands reach Mandu.";

test("Codex's sandbox refused the shim's connection (codex_sandbox): the line says so, not that Mandu's check refused it, and how to run it; a masked output stays masked", async () => {
  const n = buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", blockedExec: [{ app: "curl", kind: "codex_sandbox" }] })!;
  assert.equal(n, CODEX_SANDBOX_LINE);
  assert.doesNotMatch(n, /command check refused/);
  // the call Codex's sandbox ran is unbound (no root, no tree): the line rides anyway
  const held = new MockArbiter({ classifyFn: publicVerdict, callTaintFn: () => wire({ level: "no-model", files: ["/w/secret.txt"], apps: ["cat"], root: null, evidence: "session", blockedExec: [{ app: "curl", kind: "codex_sandbox" }] }) });
  const b = out(await rewriteRequest(exec(`${HEADER}token=sk_live_x\nmandu-exec-wrap: blocked curl, nothing ran: the sandbox this command runs in refuses its connection to Mandu\n`), { arbiter: held }));
  assert.match(b, /\$MDU:/);
  assert.ok(!b.includes("sk_live_x") && !b.includes("mandu-exec-wrap"), "the program's output stays masked");
  assert.ok(b.includes(CODEX_SANDBOX_LINE), b);
  assert.ok(!b.includes("h.example"), "no argument");
});
