/**
 * secret-hold-timeout — plan 10 §12.2 / §11.8 over the REAL components: a
 * held secret open whose ceiling passes unanswered, then the tool result the
 * model reads for it, through the production proxy wiring
 * (`new ArbiterClientAdapter(new ArbiterClient(sock))`, no test bridge).
 *
 * Drill S7 (2026-09-24) found the hold path silent at both ends: the guard
 * denied on its own when its ceiling passed, so the arbiter had no denial to
 * report and the tool result carried no note, while the "Permission denied"
 * text the program printed was masked as `$MDU:nomodel_Bash` by the classify
 * verdict's path-derived level (the command names `.env`). This suite pins
 * the closed shape end to end:
 *   1. the guard's last ask (`heldMs`) is answered `deny` and RECORDED;
 *   2. the row stays pending (a later answer needs no new prompt);
 *   3. the proxy renders the §11.8 "held:" form and RELEASES the program's own
 *      failure text (denied-only tree, value backstop clean);
 *   4. the same result with NO recorded denial is still masked (the release
 *      rests on the arbiter's record, never on the text looking harmless);
 *   5. a tree that DID read the secret stays masked whatever else was refused.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";

function bashResult(command: string, content: string, toolUseId: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "read the env file" },
      { role: "assistant", content: [{ type: "tool_use", id: toolUseId, name: "Bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: toolUseId, content }] },
    ],
  };
}

test("a held open past its ceiling: recorded denial, pending row, the 'held:' note and the released failure text over the real arbiter + production proxy adapter (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-hold-e2e-"));
  const ws = join(tmp, "ws"); mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, "API_KEY=sk_live_e2e_0123456789\n");
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath,
    adminSocketPath: join(tmp, "admin.sock"),
    humanSocketPath: join(tmp, "human", "h.sock"),
    dbPath: join(tmp, "symbols.sqlite"),
    eventDir: join(tmp, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
    // a reader list exists (sh) and mytool is not on it: with ask=always the open is HELD
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", readers: ["sh"] }] },
  });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect(); // the guard reports on the human socket (plan 13 D9)
  const realHuman = new ArbiterClient(join(tmp, "human", "h.sock")); await realHuman.connect(); // the proxy's second client (server-main)
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const real: RealArbiterClient = new ArbiterClient(socketPath); await real.connect();
  const proxy = new ArbiterClientAdapter(real, realHuman);
  const session = "s-hold-e2e";
  const command = `mytool ${env}`;
  const output = `mytool: ${env}: Permission denied\n`;
  // The agent's own shell for one Bash call, as the guard reports it, with
  // the opener under it: plan 13 D7's call-root recorder binds the call to it
  // by command text (a call it cannot bind is masked while the session holds
  // a raw read, so the releases below need the binding).
  // Plan 13 D9 follow-up: the call binds by the command the proxy recorded
  // when it relayed the call (its response side), recorded here first.
  const shellFor = async (root: string, cmd: string, child: string, callId: string): Promise<void> => {
    await proxy.recordCallCommand!({ callId, command: cmd, sessionKey: session });
    await guard.recordExecRoot({ procKey: root, ancestors: ["agent-e2e-0"], argv: ["/bin/bash", "-c", cmd], session, callRoot: true });
    if (child !== root) await guard.processLineage({ childKey: child, parentKey: root, session });
  };
  try {
    // 1. The guard's hold, then its last ask once the ceiling passed.
    const open = { path: env, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "mytool-e2e-1", session, ask: "always" };
    const held = await guard.decideSecretOpen(open);
    assert.equal(held.verdict, "ask");
    assert.ok(held.approvalId);
    const expired = await guard.decideSecretOpen({ ...open, heldMs: 60_000 });
    assert.equal(expired.verdict, "deny");
    assert.match(expired.reason, /^held for 60 s, nobody answered/);
    await shellFor("sh-e2e-1", command, "mytool-e2e-1", "toolu_held");

    // 2. The row is still pending.
    const row = (await admin.egressApprovals("pending")).find((a) => a.id === held.approvalId);
    assert.equal(row?.status, "pending");
    assert.equal(row?.symbol, "trust:/usr/bin/mytool", "the row names the binary (Plan 13 D8), as the warning question (D8 (12): mytool is no vetted reader); no hash was reported");

    // 3. The tool result the model reads: released text + the held form.
    const after = await rewriteRequest(bashResult(command, output, "toolu_held"), { arbiter: proxy, sessionKey: session });
    const r = after.rewrites[0]!;
    assert.equal(r.symbolized, false, "denied-only tree, backstop clean: the program's failure text is released");
    assert.equal(r.secretTaint?.deniedOnly, true);
    const fwd = (after.request.messages[2].content as Array<{ content: string }>)[0]!.content;
    assert.ok(fwd.startsWith(output), fwd);
    assert.match(fwd, /\[mandu:secret\] held: mytool waited for the user to allow it to read .*\.env \(held for 60 s, nobody answered; the approval is still waiting in the dashboard\)/);
    assert.doesNotMatch(fwd, /sk_live_e2e/, "the value never rides along");

    // 5. A tree that DID read the secret: rule (i) masks, the denial only adds its line.
    await guard.taintProcessSecret({ procKey: "sh-e2e-2", path: env, level: "no-model", app: "sh", session });
    await guard.processLineage({ childKey: "mytool-e2e-3", parentKey: "sh-e2e-2", session });
    await guard.decideSecretOpen({ ...open, procKey: "mytool-e2e-3", parentKey: "sh-e2e-2", heldMs: 60_000 });
    await shellFor("sh-e2e-2", `sh -c 'mytool ${env}'`, "sh-e2e-2", "toolu_mixed");
    const mixed = await rewriteRequest(bashResult(`sh -c 'mytool ${env}'`, "API_KEY=sk_live_e2e_0123456789\n", "toolu_mixed"), { arbiter: proxy, sessionKey: session });
    assert.equal(mixed.rewrites[0]!.symbolized, true);
    assert.match(mixed.rewrites[0]!.reason ?? "", /rule \(i\)/);
    const fwdMixed = (mixed.request.messages[2].content as Array<{ content: string }>)[0]!.content;
    assert.ok(!fwdMixed.includes("sk_live_e2e"), "the secret never reaches the model");
    assert.match(fwdMixed, /\[mandu:secret\] masked: sh read/);
    assert.match(fwdMixed, /\[mandu:secret\] held: mytool/);

    // 4. No record for this call: the path-derived level masks the failure
    //    text. The mask mints a secret-level `nomodel_Bash` symbol of that text as
    //    a PRECAUTION (no taint on record).
    const other = `head: ${env}: Permission denied\n`;
    const norec = await rewriteRequest(bashResult(`head -1 ${env}`, other, "toolu_norecord"), { arbiter: proxy, sessionKey: session });
    assert.equal(norec.rewrites[0]!.symbolized, true, "no denial on record: the mask stands");
    assert.match(norec.rewrites[0]!.confidentiality ?? "", /^(?:no|any)-model$/);
    const fwdNorec = (norec.request.messages[2].content as Array<{ content: string }>)[0]!.content;
    assert.ok(!fwdNorec.includes("Permission denied"), fwdNorec);

    // 6. The retry, with the denial on record this time and the SAME text:
    //    the precautionary row of step 4 does not fingerprint its own text,
    //    so the §11.8 release fires (the S7 rerun of 2026-09-24 saw it silent).
    await guard.decideSecretOpen({ ...open, exe: "/usr/bin/head", procKey: "head-e2e-4", heldMs: 60_000 });
    await shellFor("sh-e2e-4", `head -1 ${env}`, "head-e2e-4", "toolu_retry");
    const retry = await rewriteRequest(bashResult(`head -1 ${env}`, other, "toolu_retry"), { arbiter: proxy, sessionKey: session });
    assert.equal(retry.rewrites[0]!.symbolized, false, "the text masked once as a precaution does not silence the release");
    assert.equal(retry.rewrites[0]!.secretTaint?.deniedOnly, true);
    assert.ok(((retry.request.messages[2].content as Array<{ content: string }>)[0]!.content).startsWith(other));

    // 7. The bytes step 5 masked on EVIDENCE (rule (i): sh read .env and
    //    printed it) reach a later denied-only tree by some route the guard
    //    never saw: the evidential `nomodel_Bash` row fingerprints them, so the
    //    release does not fire and the value never reaches the model. (.env is
    //    labeled by path, never registered: the row is the only copy the
    //    arbiter holds.)
    await guard.decideSecretOpen({ ...open, procKey: "mytool-e2e-5", heldMs: 60_000 });
    await shellFor("sh-e2e-5", `mytool ${env}`, "mytool-e2e-5", "toolu_leak");
    const leak = await rewriteRequest(bashResult(`mytool ${env}`, "API_KEY=sk_live_e2e_0123456789\n", "toolu_leak"), { arbiter: proxy, sessionKey: session });
    assert.equal(leak.rewrites[0]!.symbolized, true, "a denied-only tree whose output carries the bytes a reader once printed stays masked");
    assert.equal(leak.rewrites[0]!.secretTaint?.deniedOnly, false);
    assert.match(leak.rewrites[0]!.secretTaint?.why ?? "", /a registered secret value appears verbatim/);
    const fwdLeak = (leak.request.messages[2].content as Array<{ content: string }>)[0]!.content;
    assert.ok(!fwdLeak.includes("sk_live_e2e"), fwdLeak);
  } finally {
    guard.close(); admin.close(); real.close(); realHuman.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
