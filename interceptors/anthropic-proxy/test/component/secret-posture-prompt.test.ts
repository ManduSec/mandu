/**
 * secret-posture-prompt.test.ts — E2E: the session's secret posture reaches
 * the model through the REAL proxy data path (docs/design/agents/handling-prompt.md
 * §2; macOS, 2026-09-29).
 *
 * The launcher hands the proxy its launch's posture (MANDU_SECRET_POSTURE →
 * ProxyOptions.secretPosture); the proxy reports it on every handlingPrompt
 * request; the arbiter renders the "blocked credential files" section for a
 * `read-blocked` session with the confidentiality axis ON. Here the arbiter
 * side is the arbiter's OWN prompt builder (imported from the sibling package
 * the way the launcher's parity tests import theirs), so the bytes asserted
 * on the upstream wire are the bytes a real session sends, in the `secrets`
 * mode (integrity OFF, confidentiality ON). A session with no posture, or a
 * Linux posture, sends exactly the prompt it sent before.
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy } from "../../src/proxy.js";
import type { HandlingPromptArgs } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";

type Build = (fmt: unknown, opts: Record<string, unknown>) => string;

/** The arbiter's real prompt builder (sibling package, loaded at run time so
 *  this package still typechecks standalone). */
async function arbiterPromptBuilder(): Promise<(caps: unknown) => string> {
  const hp = "../../../../arbiter/symbol-table/handling-prompt.ts";
  const sf = "../../../../arbiter/symbol-table/symbol-format.ts";
  const { buildSymbolSystemPrompt } = await import(hp) as { buildSymbolSystemPrompt: Build };
  const { getActiveFormat } = await import(sf) as { getActiveFormat: () => unknown };
  // The `secrets` mode, stated (protection-modes.md §4).
  return (caps) => buildSymbolSystemPrompt(getActiveFormat(), { integrity: false, confidentiality: true, capabilities: caps });
}

/** A mock arbiter whose handlingPrompt is the arbiter's own assembly. */
class PromptArbiter extends MockArbiter {
  constructor(private readonly build: (caps: unknown) => string) { super(); }
  override async handlingPrompt(args?: HandlingPromptArgs): Promise<{ prompt: string }> {
    await super.handlingPrompt(args);
    return { prompt: this.build(args?.capabilities) };
  }
}

function call(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

const BODY = JSON.stringify({
  model: "claude-haiku-4-5", stream: false, max_tokens: 64,
  tools: [{ name: "Bash", input_schema: { type: "object", properties: { command: { type: "string" } } } }],
  messages: [{ role: "user", content: "deploy with my AWS credentials" }],
});

async function forwardedSystem(secretPosture: string | undefined): Promise<{ system: string; reported: unknown }> {
  const arbiter = new PromptArbiter(await arbiterPromptBuilder());
  const upstream = new MockUpstream({ json: { type: "message", role: "assistant", content: [] } });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, ...(secretPosture ? { secretPosture } : {}) });
  const port = await proxy.listen(0);
  try {
    const r = await call(port, BODY);
    assert.equal(r.status, 200);
    const sent = upstream.requests[0]!.json() as { system?: unknown };
    const system = typeof sent.system === "string" ? sent.system : JSON.stringify(sent.system ?? "");
    return { system, reported: arbiter.handlingPromptArgs[0]?.capabilities?.secretPosture };
  } finally {
    await proxy.close();
  }
}

test("a read-blocked session: the model is told reads of credential files fail by design, not to work around them, and where its secrets are", async () => {
  const { system, reported } = await forwardedSystem("read-blocked");
  assert.equal(reported, "read-blocked", "the proxy reported the posture on the handlingPrompt request");
  assert.match(system, /## Blocked credential files/);
  assert.match(system, /Operation not\\npermitted/);
  assert.match(system, /Do not try to read, copy, move, rename, or otherwise work around a blocked/);
  assert.match(system, /\$MDU:nomodel_Env\[e1e1\]\.GITHUB_TOKEN/);
  assert.equal(system.split("## Blocked credential files").length, 2, "exactly once");
});

test("no posture, or a Linux posture: nothing reported, and the prompt on the wire is exactly the one before", async () => {
  const none = await forwardedSystem(undefined);
  assert.equal(none.reported, undefined);
  assert.doesNotMatch(none.system, /Blocked credential files/);
  for (const posture of ["confined", "gated"]) {
    const other = await forwardedSystem(posture);
    assert.equal(other.reported, posture, "the fact is reported as is");
    assert.equal(other.system, none.system, `${posture}: byte-identical prompt`);
  }
});
