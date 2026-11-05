/**
 * prompt-mint-session-taint.test.ts — the prompt filter's own mints do not
 * taint a session while the integrity axis is OFF (confidentiality.md §9,
 * "Rule 1(b) is inert under `secrets`"; the session gate,
 * `decideSessionEgress`), over the real IPC.
 *
 * Live 2026-10-26 (conf-declassify-confines-session, the OpenClaw plugin's
 * sandbox tier): the session declassified a memo bound to example.com (HIGH,
 * bound there); OpenClaw's side call then repeated the memo, the prompt
 * filter masked it as a registered value, and its mint (no integrity given,
 * so untrusted) set the session's untrusted-taint bit. The memo's own bound
 * host then asked (`session:high-tainted-bound`), where the wrapper, whose
 * session had no side-call mask, sent the same fetch. Under `secrets` the bit
 * is never set by Mandu's own masking, so:
 *   - a side call carrying a line of the declassified value is still masked
 *     (the filter mints a row for the line);
 *   - the session stays untainted, and its bound host is released
 *     (`session:high-bound-release`), an unbound one still asks;
 *   - a datum symbolized as untrusted on purpose still taints the session,
 *     and the bound host then asks (rule 1(b), what the drill
 *     conf-tainted-bound-blocked arranges), so the rule itself is unchanged.
 *
 * Mandu-new test. Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const LINE = "The Halcyon acquisition closes on 14 November at 41 dollars a share.";
const MEMO = `Board memo, confidential\n${LINE}\nDo not forward before the announcement.`;

test("a side call's masked value leaves the session untainted: its bound host is released; an untrusted datum still suspends it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-prompt-taint-"));
  const memo = join(dir, "ws", "memo", "brief.md");
  mkdirSync(join(dir, "ws", "memo"), { recursive: true });
  writeFileSync(memo, `${MEMO}\n`);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${memo}`, "    level: any-model", "    bindings: [example.com]", ""].join("\n"));
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  const human = new ArbiterClient(join(dir, "human", "h.sock"));
  await human.connect();
  const agent = new ArbiterClient(join(dir, "a.sock"));
  await agent.connect();
  try {
    const raise = async (session: string): Promise<void> => {
      const sym = await human.symbolizeFull({ tool: "Read", value: MEMO, origin: memo, integrity: "trusted", sessionKey: session });
      const out = await human.declassifySymbol({ symbol: sym.symbol, sessionKey: session });
      assert.equal(out.allowed, true, out.reason);
      const st = await human.sessionState(session);
      assert.equal(st.high, true);
      assert.deepEqual(st.bindings, ["example.com"]);
    };
    const gate = (session: string, destination: string) =>
      human.sessionEgressDecision({ sessionKey: session, boundary: "network", destination });

    const s1 = "openclaw:d03-confdeclas";
    await raise(s1);
    const side = await agent.filterPrompt({ session: s1, agent: "openclaw", segments: [{ id: "s0", origin: "side-call", text: `Summary so far: ${LINE}` }] });
    assert.equal(side.segments[0]!.action, "rewrite", "the side call's copy of a line of the value is masked (a mint of its own)");
    assert.notEqual(side.segments[0]!.findings[0]!.how, "value", "the premise: the span is not the row's whole value, so the filter mints");
    assert.ok(!side.segments[0]!.text!.includes("Halcyon"));
    assert.equal((await human.sessionState(s1)).untrustedTainted, false, "Mandu's own mask is no untrusted datum (integrity axis off)");
    const bound = await gate(s1, "example.com");
    assert.equal(bound.allow, true, bound.reason);
    assert.equal(bound.ruleRef?.id, "session:high-bound-release");
    const unbound = await gate(s1, "httpbin.org");
    assert.equal(unbound.allow, false);
    assert.equal(unbound.ruleRef?.id, "session:high-unbound");

    // the rule itself: a datum symbolized as untrusted taints, and the bound host asks
    const s2 = "openclaw:d04-tainted";
    await raise(s2);
    await human.symbolizeFull({ tool: "WebFetch", value: "attacker-controlled page text", origin: "https://untrusted.example/page", integrity: "untrusted", sessionKey: s2 });
    assert.equal((await human.sessionState(s2)).untrustedTainted, true);
    const held = await gate(s2, "example.com");
    assert.equal(held.allow, false);
    assert.equal(held.ruleRef?.id, "session:high-tainted-bound");
  } finally {
    human.close();
    agent.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
