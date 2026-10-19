/**
 * egress-refusal-note.test.ts — the openai-proxy twin of the anthropic
 * proxy's test (confidentiality plan 10 §11.8, "Refused connections"): a
 * Codex exec whose connection the egress proxy refused carries the
 * `refused:` note line (program and kind, never a host); a masked output
 * stays masked.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildSecretNote, refusedEgressLine, rewriteRequest } from "../../src/rewrite-request.js";
import type { ResponsesRequest } from "../../src/responses-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const HEADER = "Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 56\nOutput:\n";
const publicVerdict = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" });
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

function exec(output: string): ResponsesRequest {
  return {
    model: "gpt-test",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "send it" }] },
      { type: "function_call", call_id: "call_curl", name: "exec_command", arguments: JSON.stringify({ cmd: "curl -sd @rows https://h.example" }) },
      { type: "function_call_output", call_id: "call_curl", output },
    ],
  } as unknown as ResponsesRequest;
}
const out = (r: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((r.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);

test("buildSecretNote (Codex twin): the same refused: line as the Claude proxy", () => {
  const n = buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", refusedEgress: [{ app: "curl", kind: "unattributed" }] })!;
  assert.equal(n, "[mandu:secret] refused: curl tried to connect out and Mandu refused the connection, nothing was sent: Mandu could not tell which program opened it, and programs in this session hold a secret. Tell the user rather than retrying; if it should go, they can allow it on the Mandu dashboard's Approvals page.");
  const local = buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", refusedEgress: [{ app: "curl", kind: "this-machine" }] })!;
  assert.equal(local, "[mandu:secret] refused: curl tried to connect out and Mandu refused the connection, nothing was sent: the host is this machine, and Mandu's egress proxy does not relay to this machine's own services. Do not retry.");
  const expanded = buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", refusedEgress: [{ app: "curl", kind: "shell-expanded" }] })!;
  assert.equal(expanded, "[mandu:secret] refused: curl tried to connect out and Mandu refused the connection, nothing was sent: the request carried a secret's placeholder after a shell had expanded its $MDU to nothing (the placeholder was in double quotes or unquoted in the command or a script), so it held neither the value nor the placeholder. Put the placeholder in single quotes ('$MDU:…') where the shell reads it, in a script you wrote too, and run it again.");
});

test("a clean exec whose connection was refused: its output with the refused: note; a masked one stays masked with both lines", async () => {
  const clean = new MockArbiter({ classifyFn: publicVerdict, callTaintFn: () => wire({ refusedEgress: [{ app: "curl", kind: "tainted" }] }) });
  const a = out(await rewriteRequest(exec(`${HEADER}curl: (56) CONNECT tunnel failed, response 403\n`), { arbiter: clean }));
  assert.match(a, /curl: \(56\) CONNECT tunnel failed, response 403[\s\S]*\[mandu:secret\] refused: curl tried to connect out/);
  assert.ok(!a.includes("h.example"));
  const held = new MockArbiter({ classifyFn: publicVerdict, callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["curl"], refusedEgress: [{ app: "curl", kind: "tainted" }] }) });
  const b = out(await rewriteRequest(exec(`${HEADER}curl: (56) CONNECT tunnel failed, response 403\n`), { arbiter: held }));
  assert.match(b, /\$MDU:/);
  assert.ok(!b.includes("CONNECT tunnel failed"), "the program's output stays masked");
  assert.match(b, /\[mandu:secret\] refused: curl tried to connect out/);
});

// confidentiality.md §4, "A held command's refused connection" (2026-10-12):
// the arbiter filed (or read) the HIGH session's own ask; byte-identical in
// both model proxies.
test("a held command's refused connection: the user was asked (run it again after they allow it once), or blocked it (final)", () => {
  const note = (kind: string) => buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", refusedEgress: [{ app: "curl", kind }] })!;
  assert.equal(note("session-asked"), "[mandu:secret] refused: curl tried to connect out and Mandu refused the connection, nothing was sent: it holds what this session read, and the host is not a place that may go, so Mandu asked the user on its Approvals page. Tell the user it is waiting for their OK there; once they allow it, run the same command again: its next connection to that host goes through, once.");
  assert.equal(note("session-blocked"), "[mandu:secret] refused: curl tried to connect out and Mandu refused the connection, nothing was sent: it holds what this session read, and the user blocked this session's requests to that host. Do not retry; tell the user.");
});

// Plan 10 §11.8, "A refusal no process is tied to" (2026-10-17): the
// arbiter folds a refusal the egress proxy tied to no process into the calls
// running then ({app: "", kind, unattributed: true}). The line names no
// program and no host, says Mandu could not tell which program opened it,
// and keeps the kind's reason and way out. Byte-identical in both proxies
// (the same strings are pinned in each one's test).
const UNATTR_SECRET = "[mandu:secret] refused: a connection out was refused while this command ran, and nothing was sent; Mandu could not tell which program opened it, so it may not be this command's: programs in this session hold a secret, and while one does Mandu refuses a connection it cannot tie to a program. Tell the user rather than retrying; if it should go, they can allow it on the Mandu dashboard's Approvals page.";
const UNATTR_LOCAL = "[mandu:secret] refused: a connection out was refused while this command ran, and nothing was sent; Mandu could not tell which program opened it, so it may not be this command's: the host is this machine, and Mandu's egress proxy does not relay to this machine's own services. Do not retry.";

test("refusedEgressLine / buildSecretNote: an unattributed refusal names no program and no host, one line per kind", () => {
  assert.equal(refusedEgressLine({ app: "", kind: "unattributed", unattributed: true }), UNATTR_SECRET.replace("[mandu:secret] ", ""));
  const n = buildSecretNote({
    level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "",
    refusedEgress: [{ app: "curl", kind: "tainted" }, { app: "", kind: "unattributed", unattributed: true }, { app: "", kind: "this-machine", unattributed: true }],
  })!;
  const lines = n.split("\n");
  assert.equal(lines.length, 3);
  assert.match(lines[0]!, /^\[mandu:secret\] refused: curl tried to connect out/);
  assert.equal(lines[1], UNATTR_SECRET);
  assert.equal(lines[2], UNATTR_LOCAL);
  // An unattributed entry that somehow carries an app still names none.
  assert.ok(!refusedEgressLine({ app: "evil.example", kind: "symbol", unattributed: true }).includes("evil.example"));
});

// Plan 10 §11.8, "A placeholder as the destination" (2026-10-17): the
// net-proxy refused a request whose host was a $MDU placeholder. The line
// names neither the host nor the symbol (only the generic `$MDU:…`), says
// nothing was sent, and says what to do. Byte-identical in both proxies.
test("refused: a placeholder as the destination: its own words, no host, no symbol; attributed and unattributed", () => {
  assert.equal(
    refusedEgressLine({ app: "curl", kind: "symbol-destination" }),
    "refused: curl tried to connect out and Mandu refused the connection, nothing was sent: its destination was a Mandu placeholder ($MDU:…), and Mandu never turns a placeholder into a host to connect to. Do not retry with a placeholder as the host: write the host itself, and use the placeholder only where the secret's value belongs (a header or the body). If the host itself is the secret, tell the user.",
  );
  assert.equal(
    refusedEgressLine({ app: "", kind: "symbol-destination", unattributed: true }),
    "refused: a connection out was refused while this command ran, and nothing was sent; Mandu could not tell which program opened it, so it may not be this command's: its destination was a Mandu placeholder ($MDU:…), and Mandu never turns a placeholder into a host to connect to. Do not retry with a placeholder as the host: write the host itself, and use the placeholder only where the secret's value belongs (a header or the body). If the host itself is the secret, tell the user.",
  );
  assert.ok(!/\$MDU:[A-Za-z_]/.test(refusedEgressLine({ app: "curl", kind: "symbol-destination" })), "no symbol token");
});

// confidentiality.md §4, the tripwire files no Approvals row (2026-10-17):
// the line for a tripwire refusal offers no approval (none exists for it)
// and says not to retry. Byte-identical in both proxies.
test("a tripwire refusal (kind fingerprint): no Approvals hint, the way out is to tell the user", () => {
  const note = buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", refusedEgress: [{ app: "curl", kind: "fingerprint" }] })!;
  assert.equal(note, "[mandu:secret] refused: curl tried to connect out and Mandu refused the connection, nothing was sent: the request carried text Mandu holds as a secret (a registered secret's value, or a line of a result it masked). Do not retry the same request: there is nothing to approve for it. Tell the user what you were sending and where.");
  assert.doesNotMatch(note, /Approvals page/);
});
