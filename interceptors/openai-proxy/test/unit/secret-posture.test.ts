/**
 * secret-posture.test.ts — MANDU_SECRET_POSTURE → the openai-proxy's session
 * fact (src/secret-posture.ts; docs/design/agents/handling-prompt.md §2): parity with
 * the launcher's posture names and the anthropic-proxy's copy, the capability
 * fact, and the real proxy reporting it on every handlingPrompt request.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { SECRET_POSTURES, secretPostureFromEnv } from "../../src/secret-posture.js";
import { detectCapabilities, rewriteRequest } from "../../src/rewrite-request.js";
import { OpenAiProxy } from "../../src/proxy.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";

test("secretPostureFromEnv: known names pass; unset/empty is nothing; unknown is logged and dropped", () => {
  for (const p of ["confined", "read-blocked", "gated"]) assert.equal(secretPostureFromEnv(p), p);
  assert.equal(secretPostureFromEnv(undefined), undefined);
  assert.equal(secretPostureFromEnv(""), undefined);
  const logged: string[] = [];
  assert.equal(secretPostureFromEnv("readblocked", (m) => logged.push(m)), undefined);
  assert.equal(logged.length, 1);
});

test("parity: the posture names are the launcher's POSTURES and the anthropic-proxy's copy is this file", async () => {
  const launcher = "../../../../launcher/src/confinement-posture.ts";
  const { POSTURES } = await import(launcher) as { POSTURES: readonly string[] };
  assert.deepEqual([...SECRET_POSTURES], [...POSTURES]);
  const twin = "../../../anthropic-proxy/src/secret-posture.ts";
  const other = await import(twin) as { SECRET_POSTURES: readonly string[] };
  assert.deepEqual([...other.SECRET_POSTURES], [...SECRET_POSTURES]);
});

test("detectCapabilities: the posture fact is added only when set (older facts stay byte-identical)", () => {
  assert.deepEqual(detectCapabilities([{ type: "local_shell" }]), { inspect: false, policyTools: false, manduPolicy: false, exec: true });
  assert.deepEqual(detectCapabilities([{ type: "local_shell" }], {}), { inspect: false, policyTools: false, manduPolicy: false, exec: true });
  assert.equal(detectCapabilities([], { secretPosture: "read-blocked" }).secretPosture, "read-blocked");
  assert.equal(detectCapabilities(null, { secretPosture: "read-blocked" }).secretPosture, "read-blocked", "not a tool fact");
});

test("rewriteRequest: opts.secretPosture rides the handlingPrompt request; absent reports no key", async () => {
  const arbiter = new MockArbiter();
  const req = (): Parameters<typeof rewriteRequest>[0] => ({ model: "gpt-5", input: [{ role: "user", content: [{ type: "input_text", text: "hi" }] }] } as Parameters<typeof rewriteRequest>[0]);
  await rewriteRequest(req(), { arbiter, secretPosture: "read-blocked" });
  assert.equal(arbiter.handlingPromptArgs[0]?.capabilities?.secretPosture, "read-blocked");
  await rewriteRequest(req(), { arbiter });
  assert.ok(!("secretPosture" in (arbiter.handlingPromptArgs[1]?.capabilities ?? {})));
});

test("the proxy reports its posture on every request; a proxy with none reports no key", async () => {
  for (const secretPosture of ["read-blocked", undefined]) {
    const arbiter = new MockArbiter();
    const upstream = new MockUpstream({ json: { id: "r", status: "completed", output: [] } });
    const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, ...(secretPosture ? { secretPosture } : {}) });
    const port = await proxy.listen(0);
    try {
      const r = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "gpt-5", input: "hi", stream: false }),
      });
      assert.equal(r.status, 200);
      await r.text();
      assert.equal(arbiter.handlingPromptArgs.length, 1);
      const caps = arbiter.handlingPromptArgs[0]?.capabilities ?? {};
      if (secretPosture) assert.equal(caps.secretPosture, secretPosture);
      else assert.ok(!("secretPosture" in caps));
    } finally {
      await proxy.close();
    }
  }
});
