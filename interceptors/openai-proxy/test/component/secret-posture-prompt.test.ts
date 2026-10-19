/**
 * secret-posture-prompt.test.ts — E2E: Codex's model is told about a
 * `read-blocked` session through the REAL openai-proxy data path
 * (docs/design/agents/handling-prompt.md §2; macOS, 2026-09-29).
 *
 * MANDU_SECRET_POSTURE → ProxyOptions.secretPosture → every handlingPrompt
 * request's `capabilities.secretPosture` → the arbiter's own prompt builder
 * (imported from the sibling package, the `secrets` mode: integrity OFF,
 * confidentiality ON) → the Responses `instructions` string on the upstream
 * wire. No posture, or a Linux one, leaves the instructions byte-identical.
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { OpenAiProxy } from "../../src/proxy.js";
import type { HandlingPromptArgs } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";

type Build = (fmt: unknown, opts: Record<string, unknown>) => string;

async function arbiterPromptBuilder(): Promise<(caps: unknown) => string> {
  const hp = "../../../../arbiter/symbol-table/handling-prompt.ts";
  const sf = "../../../../arbiter/symbol-table/symbol-format.ts";
  const { buildSymbolSystemPrompt } = await import(hp) as { buildSymbolSystemPrompt: Build };
  const { getActiveFormat } = await import(sf) as { getActiveFormat: () => unknown };
  return (caps) => buildSymbolSystemPrompt(getActiveFormat(), { integrity: false, confidentiality: true, capabilities: caps });
}

class PromptArbiter extends MockArbiter {
  constructor(private readonly build: (caps: unknown) => string) { super(); }
  override async handlingPrompt(args?: HandlingPromptArgs): Promise<{ prompt: string }> {
    await super.handlingPrompt(args);
    return { prompt: this.build(args?.capabilities) };
  }
}

async function forwardedInstructions(secretPosture: string | undefined): Promise<string> {
  const arbiter = new PromptArbiter(await arbiterPromptBuilder());
  const upstream = new MockUpstream({ json: { id: "r", status: "completed", output: [] } });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, ...(secretPosture ? { secretPosture } : {}) });
  const port = await proxy.listen(0);
  try {
    const r = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "gpt-5", stream: false, instructions: "You are Codex.",
        tools: [{ type: "function", name: "exec_command", parameters: { type: "object" } }],
        input: [{ role: "user", content: [{ type: "input_text", text: "deploy with my AWS credentials" }] }],
      }),
    });
    assert.equal(r.status, 200);
    await r.text();
    const sent = upstream.requests[0]!.json() as { instructions?: unknown };
    assert.equal(typeof sent.instructions, "string");
    return sent.instructions as string;
  } finally {
    await proxy.close();
  }
}

test("a read-blocked Codex session: the instructions say reads of credential files fail by design and name the placeholders", async () => {
  const text = await forwardedInstructions("read-blocked");
  assert.match(text, /## Blocked credential files/);
  assert.match(text, /"Operation not\npermitted"/);
  assert.match(text, /Do not try to read, copy, move, rename, or otherwise work around a blocked/);
  assert.match(text, /\$MDU:nomodel_Env\[e1e1\]\.GITHUB_TOKEN/);
  assert.match(text, /You are Codex\./, "the agent's own instructions are kept");
});

test("no posture, or a Linux posture: the instructions are byte-identical to before", async () => {
  const none = await forwardedInstructions(undefined);
  assert.doesNotMatch(none, /Blocked credential files/);
  for (const posture of ["confined", "gated"]) assert.equal(await forwardedInstructions(posture), none, posture);
});
