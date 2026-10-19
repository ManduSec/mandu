/**
 * call-binding-clock — plan 13 D7's call windows over the REAL arbiter and
 * the anthropic-proxy's production adapter (`new ArbiterClientAdapter(new
 * ArbiterClient(sock), new ArbiterClient(humanSock))`), on a wall clock that
 * never moves and on one that steps back (CI pipeline #8378).
 *
 * A call is bound to the agent's shell for it only if that shell was reported
 * between the proxy's relay of the call and its first ask. Those bounds were
 * compared on the raw millisecond clock: everything the arbiter handled in
 * one millisecond counted as simultaneous. config-twin-fidelity then failed
 * once under load: `cat ~/.npmrc` twice in a row (the twin, then the raw
 * read), the second call's shell reported in the millisecond of the first
 * call's first ask, so both calls "owned" it, and the lost-record rule left
 * the second call unbound: its output was masked whole (D7 note) instead of
 * one symbol. The same tie let a shell reported AFTER a call's first ask,
 * in that millisecond, bind a call already masked as unbound.
 *
 * The arbiter's provenance store now stamps on its own strictly increasing
 * clock. Here Date.now is frozen (then made to step back) while the guard's
 * records and the proxy's asks go through the real sockets:
 *   - two same-text calls in a row each bind their own shell: the twin is
 *     released as the twin, the raw read is one symbol (no D7 note);
 *   - a call whose shell was never reported is masked with the D7 note, and a
 *     same-text shell reported after its first ask does not unmask it on a
 *     resend (no canary at any point).
 * Axes stated: `secrets` (confidentiality ON, integrity OFF), pinned on the
 * server too.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const GIT_PW = "gitpw_CLOCK_CANARY_4e1a7c";
const AWS_PW = "awsCLOCKCANARY7d2e1bQx9Lm4Pz";
const NPM_PW = "npmpwCLOCKCANARY9b3d2f";
const CANARIES = [GIT_PW, AWS_PW, NPM_PW, Buffer.from(NPM_PW).toString("base64")];
const FILES: Record<string, string> = {
  ".git-credentials": `https://builder:${GIT_PW}@git.example.com\n`,
  ".aws/credentials": `[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = ${AWS_PW}\n`,
  ".npmrc": `//r.ex/:username=me\n//r.ex/:_password=${Buffer.from(NPM_PW).toString("base64")}\n`,
};

function bash(command: string, content: string, id: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "check my configuration" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  };
}
const forwarded = (r: MessagesRequest): string => ((r.messages[2]!.content as any[])[0].content as string);

/** One symbol, and at most the path-derived note the proxy writes from the
 *  command (confidentiality.md §7.1, 2026-10-05): never an output byte. */
const ONE_SYMBOL = /^\$MDU:nomodel_Bash\[[0-9a-f]{4,8}\](?:\n\n\[mandu:secret\] masked: (?:the command names|this output contains the value of a registered secret)[^\n]*)?$/;

for (const [clockName, makeClock] of [
  ["frozen", () => { const t = Date.now(); return () => t; }],
  ["stepping back", () => { let t = Date.now(); return () => (t -= 3); }],
] as Array<[string, () => () => number]>) {
  test(`D7 call windows on a wall clock ${clockName}: same-text calls in a row bind their own shells; a shell after a call's first ask never unmasks it (secrets axes, explicit)`, async () => {
    const tmp = mkdtempSync(join(tmpdir(), "mandu-call-clock-"));
    const home = join(tmp, "home");
    for (const [rel, content] of Object.entries(FILES)) {
      mkdirSync(dirname(join(home, rel)), { recursive: true });
      writeFileSync(join(home, rel), content);
    }
    const p = (rel: string): string => join(home, rel);
    const socketPath = join(tmp, "arbiter.sock");
    const server = new ArbiterServer({
      socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
      confidentiality: true, integrity: false, // the `secrets` mode axes, stated
      // plan 13 D8 (11): git and every credential helper print (git-credential-*,
      // 2026-10-07), so the store's raw reader is a deploy tool the human vouches for
      policyDocument: { version: 1, paths: [{ path: p(".git-credentials"), level: "no-model", readers: [{ app: "acme-deploy", prints: "nothing" }], others: "twin" }] },
    });
    await server.listen();
    const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect(); // the guard reports on the human socket (plan 13 D9)
    const realHuman = new ArbiterClient(join(tmp, "human", "h.sock")); await realHuman.connect();
    const real: RealArbiterClient = new ArbiterClient(socketPath); await real.connect();
    const claude = new ArbiterClientAdapter(real, realHuman);
    const session = "s-call-clock";
    const realNow = Date.now;
    try {
      const reg: Record<string, Awaited<ReturnType<ArbiterClient["registerSecret"]>>> = {};
      for (const rel of Object.keys(FILES)) reg[rel] = await guard.registerSecret({ path: p(rel), home, sessionKey: session });
      assert.equal(typeof reg[".npmrc"]!.twin, "string", reg[".npmrc"]!.reason);
      // The session holds a raw read: a deploy tool the human vouches for read the real store.
      const gitOpen = await guard.decideSecretOpen({ path: p(".git-credentials"), exe: "/usr/bin/acme-deploy", isAgent: false, exeSystem: true, openerEnv: [], procKey: "git-1", session, ask: "known" });
      assert.equal(gitOpen.verdict, "raw", gitOpen.reason);

      Date.now = makeClock();
      let roots = 0;
      const shellFor = async (command: string, child: string, callId: string, o: { lost?: boolean } = {}): Promise<void> => {
        await claude.recordCallCommand!({ callId, command, sessionKey: session });
        if (o.lost === true) return; // the shell's report never reached the arbiter
        const root = `sh-${++roots}`;
        await guard.recordExecRoot({ procKey: root, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true });
        await guard.processLineage({ childKey: child, parentKey: root, session });
      };
      const cat = `cat ${p(".npmrc")}`;
      // 1. The twin, then the raw read, the same command, in a row.
      await shellFor(cat, "cat-1", "toolu_clock_twin");
      const twin = await rewriteRequest(bash(cat, reg[".npmrc"]!.twin!, "toolu_clock_twin"), { arbiter: claude, sessionKey: session });
      assert.equal(forwarded(twin.request), reg[".npmrc"]!.twin!, `the twin is released as the twin: ${JSON.stringify(twin.rewrites)}`);
      await shellFor(cat, "cat-1", "toolu_clock_raw");
      const raw = await rewriteRequest(bash(cat, FILES[".npmrc"]!, "toolu_clock_raw"), { arbiter: claude, sessionKey: session });
      assert.match(forwarded(raw.request), ONE_SYMBOL, "the raw read is one symbol, bound to its own shell (no D7 note)");
      // 2. A call whose shell was never reported: masked whole, with the note.
      await shellFor(cat, "cat-1", "toolu_clock_lost", { lost: true });
      const lostReq = bash(cat, FILES[".npmrc"]!, "toolu_clock_lost");
      const lost = await rewriteRequest(lostReq, { arbiter: claude, sessionKey: session });
      assert.match(forwarded(lost.request), /plan 13 D7: Mandu could not tie this Bash call/);
      // A same-text shell reported after that first ask (a stray or a later
      // call's) does not bind it: the resend is masked the same way.
      await guard.recordExecRoot({ procKey: `sh-${++roots}`, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", cat], session, callRoot: true });
      const resend = await rewriteRequest(lostReq, { arbiter: claude, sessionKey: session });
      assert.match(forwarded(resend.request), /plan 13 D7: Mandu could not tie this Bash call/, "a shell after the first ask never unmasks the call");
      for (const r of [twin, raw, lost, resend]) {
        for (const c of CANARIES) assert.ok(!forwarded(r.request).includes(c), `the model got ${c}`);
      }
    } finally {
      Date.now = realNow;
      guard.close(); realHuman.close(); real.close();
      await server.close();
      rmSync(tmp, { recursive: true, force: true });
    }
  });
}
