/**
 * policy, symbols and the adapter: the method tables, the placeholder
 * pattern, and the production adapter's shape over a stand-in client
 * (devtools-relay.md §4, §5; secrets axes, explicit).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { stateAxes } from "../axes.js";
import { refusedBecause, refusalMessage } from "../../src/policy.js";
import { findSymbols, substituteSymbols } from "../../src/symbols.js";
import { ArbiterClientAdapter, RELAY_AGENT, humanSockFromEnv } from "../../src/arbiter-client.js";

stateAxes("secrets");

test("pixels, the cookie jar, nested sessions and unknown domains are refused", () => {
  for (const m of ["Page.captureScreenshot", "Page.startScreencast", "Page.printToPDF", "Tracing.start", "HeadlessExperimental.beginFrame"]) {
    assert.equal(refusedBecause(m), "pixels", m);
  }
  for (const m of ["Network.getCookies", "Network.getAllCookies", "Storage.getCookies"]) assert.equal(refusedBecause(m), "cookies", m);
  assert.equal(refusedBecause("Target.sendMessageToTarget"), "protocol");
  assert.equal(refusedBecause("Target.exposeDevToolsProtocol"), "protocol");
  assert.equal(refusedBecause("WebAuthn.enable"), "domain");
  for (const m of ["Runtime.evaluate", "DOM.getDocument", "Accessibility.getFullAXTree", "Input.insertText", "Page.navigate", "Target.setAutoAttach"]) {
    assert.equal(refusedBecause(m), null, m);
  }
  assert.match(refusalMessage("Page.captureScreenshot", "pixels"), /not pixels/);
});

test("placeholders are found once each and substituted only with a decision", () => {
  const a = "$MDU:nomodel_A[1a2b]";
  const b = "$MDU:nomodel_B[3c4d]";
  assert.deepEqual(findSymbols(`${a} and ${b} and ${a}`), [a, b]);
  assert.deepEqual(findSymbols("no placeholder"), []);
  assert.equal(substituteSymbols(`x=${a};y=${a}`, new Map([[a, "1"]])), "x=1;y=1");
  assert.throws(() => substituteSymbols(`${a}${b}`, new Map([[a, "1"]])), /no decision/);
});

test("the adapter sends harness segments as the browser agent, and asks the human client for releases", async () => {
  const calls: unknown[] = [];
  const emitted: unknown[] = [];
  const adapter = new ArbiterClientAdapter(
    {
      filterPrompt: async (args) => { calls.push(args); return { segments: args.segments.map((s) => ({ id: s.id, action: "pass" as const })) }; },
      emit: async (e) => { emitted.push(e); return 1; },
    },
    {
      desymbolizationDecision: async () => ({ allow: true, reason: "ok" }), resolve: async () => "v",
      placeholderKnown: async (args) => { calls.push(args); return { known: args.base === "$MDU:x[1a2b]" }; },
    },
  );
  await adapter.filterText([{ id: "s0", text: "hello world" }], "sess");
  assert.deepEqual(calls[0], { session: "sess", agent: RELAY_AGENT, segments: [{ id: "s0", origin: "harness", text: "hello world" }] });
  assert.equal(await adapter.resolve("$MDU:x[1a2b]"), "v");
  assert.equal(await adapter.placeholderKnown("$MDU:x[1a2b]"), true);
  assert.equal(await adapter.placeholderKnown("$MDU:x[1a2c]"), false);
  assert.deepEqual(calls[1], { base: "$MDU:x[1a2b]" }, "the lookup goes to the human client as one object");
  const odd = new ArbiterClientAdapter(
    { filterPrompt: async () => ({ segments: [] }), emit: async () => 1 },
    { desymbolizationDecision: async () => ({ allow: true, reason: "ok" }), resolve: async () => null, placeholderKnown: async () => ({ known: "yes" as unknown as boolean }) },
  );
  assert.equal(await odd.placeholderKnown("$MDU:x[1a2b]"), false, "only a literal true is known");
  await adapter.emit({ kind: "browser_action" });
  assert.deepEqual(emitted, [{ kind: "browser_action" }], "events go to the data client");
  const noHuman = new ArbiterClientAdapter({ filterPrompt: async () => ({ segments: [] }), emit: async () => 1 }, null);
  await assert.rejects(noHuman.resolve("$MDU:x[1a2b]"), /MANDU_ARBITER_HUMAN_SOCK/);
  await assert.rejects(noHuman.placeholderKnown("$MDU:x[1a2b]"), /MANDU_ARBITER_HUMAN_SOCK/, "no human plane: the lookup throws, the relay refuses");
  await assert.rejects(noHuman.desymbolizationDecision({ symbol: "$MDU:x[1a2b]", boundary: "network", destination: "a.com", asCommand: false }), /MANDU_ARBITER_HUMAN_SOCK/);
  assert.equal(humanSockFromEnv({}), null);
  assert.equal(humanSockFromEnv({ MANDU_ARBITER_HUMAN_SOCK: "/h.sock" }), "/h.sock");
});
