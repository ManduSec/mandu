/**
 * secret-posture.test.ts — MANDU_SECRET_POSTURE → the proxy's session fact
 * (src/secret-posture.ts; docs/design/agents/handling-prompt.md §2), and its
 * parity with the launcher's posture names. Through the real proxy: the
 * fact rides every handlingPrompt request, and only when set.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { SECRET_POSTURES, secretPostureFromEnv } from "../../src/secret-posture.js";
import { AnthropicProxy } from "../../src/proxy.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";

test("secretPostureFromEnv: the three posture names pass; unset/empty is nothing; an unknown value is logged and dropped", () => {
  for (const p of ["confined", "read-blocked", "gated"]) assert.equal(secretPostureFromEnv(p), p);
  assert.equal(secretPostureFromEnv(undefined), undefined);
  assert.equal(secretPostureFromEnv(""), undefined);
  const logged: string[] = [];
  assert.equal(secretPostureFromEnv("Read-Blocked", (m) => logged.push(m)), undefined);
  assert.equal(secretPostureFromEnv("off", (m) => logged.push(m)), undefined);
  assert.equal(logged.length, 2);
  assert.match(logged[0]!, /MANDU_SECRET_POSTURE="Read-Blocked" is not a posture this proxy knows \(confined \| read-blocked \| gated\)/);
});

test("parity: the proxy's posture names are the launcher's POSTURES", async () => {
  const path = "../../../../launcher/src/confinement-posture.ts";
  const { POSTURES } = await import(path) as { POSTURES: readonly string[] };
  assert.deepEqual([...SECRET_POSTURES], [...POSTURES]);
});

test("the proxy reports its posture on every handlingPrompt request; a proxy with none reports no key", async () => {
  for (const secretPosture of ["read-blocked", undefined]) {
    const arbiter = new MockArbiter();
    const upstream = new MockUpstream({ json: { type: "message", role: "assistant", content: [] } });
    const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, ...(secretPosture ? { secretPosture } : {}) });
    const port = await proxy.listen(0);
    try {
      for (let i = 0; i < 2; i++) {
        const r = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ model: "claude-haiku-4-5", max_tokens: 8, messages: [{ role: "user", content: `turn ${i}` }] }),
        });
        assert.equal(r.status, 200);
        await r.text();
      }
      assert.equal(arbiter.handlingPromptArgs.length, 2);
      for (const a of arbiter.handlingPromptArgs) {
        if (secretPosture) assert.equal(a?.capabilities?.secretPosture, secretPosture);
        else assert.ok(!("secretPosture" in (a?.capabilities ?? {})));
      }
    } finally {
      await proxy.close();
    }
  }
});
