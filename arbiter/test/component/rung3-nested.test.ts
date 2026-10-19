/**
 * component — rung 3 (`declassify_symbol`) releases the CONTENT, not the next
 * wrapper (model-endpoints.md §1.6, the confidentiality-axis twin, found by the
 * live drill conf-derived-label-next-session, 2026-10-03).
 *
 * The live shape: the agent Reads a labeled file through its AgentView twin,
 * whose bytes are the registered row's token, and the proxy symbolizes that
 * result again, so the symbol the model holds stands for another symbol. A
 * one-level resolve handed the model that inner token: a granted read gave
 * nothing. The release now resolves nested symbols, each by ITS OWN rung-3
 * decision (nesting follows admission, as for rung 2, plan 11 D3).
 *
 * The invariant half: a nested `no-model` token, or a nested untrusted one,
 * stays opaque inside a granted read; every nested symbol opened raises the
 * watermark (level and bindings); another session gets nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF (the product default)

const MEMO = "Deal memo: the reference code is NESTED_RUNG3_CANARY.";
const KEY = "NOMODEL_NESTED_CANARY_VALUE";
const LAW: PolicyFileConfig = {
  version: 1,
  paths: [
    { path: "/h/notes/memo.md", level: "any-model", bindings: ["example.com"] },
    { path: "/h/notes/other.md", level: "any-model", bindings: ["example.org"] },
    { path: "/h/keys/key.txt", level: "no-model" },
  ],
};

async function withStack(fn: (data: ArbiterClient) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-rung3-nested-"));
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyDocument: LAW, policyPollMs: 0,
  });
  await server.listen();
  const data = new ArbiterClient(join(dir, "a.sock"));
  try {
    await data.connect();
    await fn(data);
  } finally {
    data.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The registered row (the launcher's registerSecret: trusted, session-less)
 *  and the Read result over its AgentView twin, symbolized again. */
async function doubleWrapped(data: ArbiterClient, sessionKey: string): Promise<{ inner: string; outer: string }> {
  const inner = (await data.symbolizeFull({ tool: "Read", value: MEMO, origin: "/h/notes/memo.md", integrity: "trusted" })).symbol;
  const outer = (await data.symbolizeFull({ tool: "Read", value: `${inner}\n`, origin: "/h/notes/memo.md", integrity: "trusted", sessionKey })).symbol;
  return { inner, outer };
}

test("a granted read of a double-wrapped file releases the file's bytes, not the inner token", async () => {
  await withStack(async (data) => {
    const { inner, outer } = await doubleWrapped(data, "s");
    assert.match(outer, /anymodel_/);
    const r = await data.declassifySymbol({ symbol: outer, sessionKey: "s" });
    assert.equal(r.allowed, true, r.reason);
    assert.equal(r.value, `${MEMO}\n`, "the content reaches the cleared model");
    assert.ok(!r.value!.includes(inner), "not the inner wrapper");
    assert.equal(r.watermark, "any-model");
    const st = await data.sessionState("s");
    assert.equal(st.high, true, "the session is HIGH");
    assert.deepEqual(st.bindings, ["example.com"], "the release surface is the file's bindings");
    // Confinement after the read: a host the file is not bound to asks.
    const away = await data.sessionEgressDecision({ sessionKey: "s", boundary: "network", destination: "attacker.invalid" });
    assert.equal(away.allow, false, away.reason);
    // Another session holds nothing and was never raised.
    assert.equal((await data.sessionState("other")).high, false);
  });
});

test("nesting follows admission: a no-model or untrusted token stays opaque inside a granted read", async () => {
  await withStack(async (data) => {
    const key = (await data.symbolizeFull({ tool: "Read", value: KEY, origin: "/h/keys/key.txt", integrity: "trusted" })).symbol;
    assert.match(key, /nomodel_/);
    // Minted in another session: an untrusted mint here would taint "n" (§9 rule 2).
    const untrusted = (await data.symbolizeFull({ tool: "Read", value: "UNTRUSTED_NESTED_CANARY", origin: "/h/notes/memo.md", sessionKey: "elsewhere" })).symbol;
    const outer = (await data.symbolizeFull({
      tool: "Read", value: `${MEMO}\nkey: ${key}\nquote: ${untrusted}\n`, origin: "/h/notes/memo.md", integrity: "trusted", sessionKey: "n",
    })).symbol;
    const r = await data.declassifySymbol({ symbol: outer, sessionKey: "n" });
    assert.equal(r.allowed, true, r.reason);
    assert.ok(r.value!.includes(MEMO), "the cleared text is released");
    assert.ok(r.value!.includes(key), "the no-model token stays a token");
    assert.ok(!r.value!.includes(KEY), "no model reads no-model data, nested or not");
    assert.ok(r.value!.includes(untrusted), "the untrusted token stays a token");
    assert.ok(!r.value!.includes("UNTRUSTED_NESTED_CANARY"), "untrusted data never enters context raw");
    assert.equal((await data.sessionState("n")).confidentiality, "any-model", "a token left opaque does not float the session");
  });
});

test("every nested symbol opened raises the watermark with its own bindings", async () => {
  await withStack(async (data) => {
    const other = (await data.symbolizeFull({ tool: "Read", value: "Other memo: OTHER_NESTED_CANARY", origin: "/h/notes/other.md", integrity: "trusted" })).symbol;
    const outer = (await data.symbolizeFull({
      tool: "Read", value: `${MEMO}\nsee also: ${other}\n`, origin: "/h/notes/memo.md", integrity: "trusted", sessionKey: "b",
    })).symbol;
    const r = await data.declassifySymbol({ symbol: outer, sessionKey: "b" });
    assert.equal(r.allowed, true, r.reason);
    assert.ok(r.value!.includes("OTHER_NESTED_CANARY"), "a cleared nested datum opens");
    const st = await data.sessionState("b");
    assert.deepEqual(st.bindings, [], "example.com ∩ example.org: the session's egress asks everywhere");
    for (const host of ["example.com", "example.org"]) {
      const d = await data.sessionEgressDecision({ sessionKey: "b", boundary: "network", destination: host });
      assert.equal(d.allow, false, `${host}: ${d.reason}`);
    }
  });
});

// Nightly 11551 (2026-10-17): the model's `reason` names the file it is
// declassifying ("…loading content from notes/memo.md"). declassify_symbol is
// a tool no session spec maps, so every string of its input is read for a
// labelled path (plan 10 §11.11), and since the label-root text scan
// (2026-10-17) a RELATIVE mention matches too: the result of the granted read
// was raised to the file's level and masked again, a fresh token where the
// content belongs. The exact grant is the release; anything else keeps the
// raise.
test("a granted read's result is released though its input names the labelled file; nothing else is", async () => {
  await withStack(async (data) => {
    const TOOL = "mcp__mandu-inspect__declassify_symbol";
    const { outer } = await doubleWrapped(data, "r");
    const r = await data.declassifySymbol({ symbol: outer, sessionKey: "r" });
    assert.equal(r.allowed, true, r.reason);
    const notice = "[DECLASSIFIED — this session is now HIGH (any-model).]";
    for (const reason of ["User explicitly authorized loading content from notes/memo.md", "load /h/notes/memo.md here"]) {
      const classify = (over: Record<string, unknown>) => data.classify({
        tool: TOOL, value: `${notice}\n\n${r.value!}`, boundary: "model_context", sessionKey: "r",
        params: { symbol: outer, reason }, ...over,
      } as never);
      // the precondition: the input names a labelled path, so a result that
      // is NOT the grant is raised to that path's level
      const other = await classify({ value: "not what was released" });
      assert.equal(other.confidentiality, "any-model", `${reason}: the input names the label (${other.reason})`);

      const granted = await classify({});
      assert.equal(granted.confidentiality, "public", `${reason}: the released value reaches the cleared model (${granted.reason})`);
      assert.equal(granted.trust, "TRUSTED");
      assert.equal(granted.bindings, undefined, "no row is minted, so no bindings");
      assert.equal((await classify({ value: r.value! })).confidentiality, "public", `${reason}: the bare value`);
      // Claude Code appends its token-budget reminder to every tool_result
      const budget = "<system-reminder>\n<total_tokens>14999989 tokens left</total_tokens>\n</system-reminder>";
      assert.equal((await classify({ value: `${notice}\n\n${r.value!}\n\n${budget}` })).confidentiality, "public", `${reason}: past the harness's budget tail`);
      assert.equal((await classify({ value: `${notice}\n\n${r.value!}\n\n<system-reminder>\nmore\n</system-reminder>` })).confidentiality, "any-model", `${reason}: any other tail keeps the raise`);

      for (const [over, why] of [
        [{ sessionKey: "other" }, "another session"],
        [{ params: { symbol: "$MDU:anymodel_Read[0000]", reason } }, "another symbol"],
        [{ params: { reason } }, "no symbol in the input"],
        [{ value: `${notice}\n\n${r.value!}\nand the next file` }, "text appended after the value"],
        [{ value: `before\n${notice}\n\n${r.value!}` }, "text before the notice"],
        [{ tool: "mcp__other__declassify_symbol" }, "another server's tool of the same name"],
      ] as const) {
        assert.equal((await classify(over as Record<string, unknown>)).confidentiality, "any-model", `${reason}: ${why} keeps the raise`);
      }
    }
    // the release does not lower the session: it stays HIGH, bound as the file
    const st = await data.sessionState("r");
    assert.equal(st.confidentiality, "any-model");
    assert.deepEqual(st.bindings, ["example.com"]);
  });
});
