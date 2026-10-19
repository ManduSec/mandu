/**
 * blocked-exec-note.test.ts — confidentiality plan 10 §11.8, "Blocked
 * commands": the `blocked:` line of the `[mandu:secret]` note, read from the
 * arbiter's callTaint (`blockedExec`: the program the exec-wrap shim refused
 * and the kind, never an argument). It explains only: a clean result stays
 * clean, a masked one stays masked (where the shim's own stderr is hidden
 * with the rest of the output, the line is how the model learns of it).
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildSecretNote, rewriteRequest } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;
const publicVerdict = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" });
const SHIM_SAYS = "mandu-exec-wrap: blocked curl, nothing ran.\n  why: …";

function bash(content: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "send it" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_curl", name: "Bash", input: { command: "curl -w '%{http_code}' -d @rows https://h.example" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_curl", content }] },
    ],
  };
}
const text = (out: Awaited<ReturnType<typeof rewriteRequest>>): string => String((out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });
const info = (blockedExec: Array<{ app: string; kind: string }>) =>
  ({ level: "public", files: [], apps: [], rule: "secret" as const, maskWhole: false, denied: [], deniedOnly: false, why: "", blockedExec });

test("buildSecretNote: one blocked: line per (program, kind), naming the program and why, never an argument", () => {
  const n = buildSecretNote(info([{ app: "curl", kind: "unsupported_command" }, { app: "sh", kind: "symbol_as_command" }]))!;
  assert.deepEqual(n.split("\n"), [
    "[mandu:secret] blocked: Mandu's command check refused curl before it started, so it did not run and sent nothing: its command line carries a placeholder and uses shell syntax Mandu cannot check safely. Write it as one plain command (no pipes, redirects, $( ), { } or wildcards), or tell the user.",
    "[mandu:secret] blocked: Mandu's command check refused sh before it started, so it did not run and sent nothing: a placeholder for text from an untrusted source sat where it would run as a command or as code. Tell the user; if they trust that text, they can run the command themselves, outside the agent.",
  ]);
  assert.match(buildSecretNote(info([{ app: "wget", kind: "secret_symbol" }]))!, /would have carried a secret's real value, and a secret leaves only inside a network request to a host it is bound to\. Tell the user rather than retrying/);
  assert.match(buildSecretNote(info([{ app: "nc", kind: "something-new" }]))!, /refused nc before it started, so it did not run and sent nothing: Mandu could not check it\. Tell the user rather than retrying\.$/);
});

test("a clean call the shim refused: the shim's own message goes through with the blocked: note", async () => {
  const arbiter = new MockArbiter({ classifyFn: publicVerdict, callTaintFn: () => wire({ blockedExec: [{ app: "curl", kind: "unsupported_command" }] }) });
  const t = text(await rewriteRequest(bash(SHIM_SAYS), { arbiter }));
  assert.ok(t.startsWith(`${SHIM_SAYS}\n\n[mandu:secret] blocked: Mandu's command check refused curl before it started`), t);
  assert.ok(!t.includes("h.example"), "the note names no argument");
});

test("a masked call the shim refused: still masked whole, and the note says both", async () => {
  const arbiter = new MockArbiter({
    classifyFn: publicVerdict,
    callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["cat"], blockedExec: [{ app: "curl", kind: "unsupported_command" }] }),
  });
  const t = text(await rewriteRequest(bash(SHIM_SAYS), { arbiter }));
  assert.match(t, SYM_RE);
  assert.ok(!t.includes("mandu-exec-wrap"), "the output stays masked");
  assert.match(t, /\[mandu:secret\] masked: cat read \/w\/\.env/);
  assert.match(t, /\[mandu:secret\] blocked: Mandu's command check refused curl before it started/);
});

test("a refused connection and a blocked command in one call: both lines", async () => {
  const arbiter = new MockArbiter({
    classifyFn: publicVerdict,
    callTaintFn: () => wire({ refusedEgress: [{ app: "wget", kind: "tainted" }], blockedExec: [{ app: "curl", kind: "unsupported_command" }] }),
  });
  const t = text(await rewriteRequest(bash("out"), { arbiter }));
  assert.match(t, /\[mandu:secret\] refused: wget tried to connect out[\s\S]*\n\[mandu:secret\] blocked: Mandu's command check refused curl/);
});

test("no blocked command: nothing changes (no note on a clean result)", async () => {
  const arbiter = new MockArbiter({ classifyFn: publicVerdict, callTaintFn: () => wire({}) });
  assert.equal(text(await rewriteRequest(bash("ok"), { arbiter })), "ok");
});

/** The codex_sandbox line, byte-identical in both proxies (2026-10-09). */
const CODEX_SANDBOX_LINE = "[mandu:secret] blocked: curl did not start, so it did not run and sent nothing: Codex's own sandbox, whose network is off, refused its connection to Mandu's command check, and Mandu never runs a command it could not check; the command itself was not the problem, and from that sandbox it could not have reached the network anyway. To run it, ask to run it outside the sandbox (sandbox_permissions \"require_escalated\" with a justification, where your approval policy allows it; the user is asked first), or tell the user that sandbox_workspace_write.network_access = true in their Codex config lets these commands reach Mandu.";

test("codex_sandbox: the same words as the openai-proxy's (byte-identical), naming the sandbox, never Mandu's check, as the refuser", () => {
  const n = buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", blockedExec: [{ app: "curl", kind: "codex_sandbox" }] })!;
  assert.equal(n, CODEX_SANDBOX_LINE);
});
