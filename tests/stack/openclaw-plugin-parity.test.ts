/**
 * openclaw-plugin-parity — the PRODUCTION wiring of the Mandu OpenClaw
 * plugin's hook arbiter, `new HookArbiterAdapter(new ArbiterClient(sock))`,
 * over a real ArbiterServer, with no test bridge in between
 * (docs/design/agents/openclaw-plugin.md §3.3, §3.5; the arbiter-client
 * pattern, CONTRIBUTING.md).
 *
 * The plugin's component tests drive its hooks against a mock; only this
 * proves the two ops it forwards reach the real arbiter in the shape the
 * arbiter answers, ON THE DATA SOCKET (the only socket the plugin is given):
 *   - egressFingerprintScan: a registered secret value in a reply trips with
 *     its placeholder (never the value), a reply with only the placeholder
 *     does not, and the "" destination (a chat is no host) admits no binding;
 *   - emit: stored as a CLAIM (the data socket) under `openclaw:<agentId>`.
 * Type level: the real client class satisfies the adapter's interface.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import {
  HookArbiterAdapter,
  type RealHookArbiterClient,
} from "../../interceptors/openclaw-inspect-plugin/src/hook-arbiter.js";
import { attachmentSession as pluginSession } from "../../interceptors/openclaw-inspect-plugin/src/attachment-session.js";
import { replyEvent } from "../../interceptors/openclaw-inspect-plugin/src/plugin-events.js";
import { humanSockIn } from "../lib/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the tripwire is a confidentiality-axis op (inert with the axis OFF)

// Type-level parity: the real client must satisfy the adapter's interface.
const _typeCheck: (c: ArbiterClient) => RealHookArbiterClient = (c) => c;
void _typeCheck;

const KEY = "sk-live-7d3c9e1f5a2b8c4d6e0f";

test("the production HookArbiterAdapter over a real ArbiterClient on the DATA socket: tripwire + emit", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-ocp-parity-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSockIn(tmp), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const setup = new ArbiterClient(socketPath);
  await setup.connect();
  const client = new ArbiterClient(socketPath);
  await client.connect();
  try {
    const reg = await setup.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const sym = reg.vars[0]!.symbol!;
    assert.match(sym, /^\$MDU:/);

    const adapter = new HookArbiterAdapter(client);
    const leak = await adapter.egressFingerprintScan([{ where: "body", text: `the key is ${KEY}` }], "");
    assert.equal(leak.tripped, true);
    assert.equal(leak.hits[0]!.symbol, sym);
    assert.ok(!JSON.stringify(leak).includes(KEY), "the answer names the placeholder, never the value");

    const kept = await adapter.egressFingerprintScan([{ where: "body", text: `the key is ${sym}` }], "");
    assert.deepEqual(kept, { tripped: false, hits: [] }, "a placeholder is no leak");

    const session = pluginSession("main");
    const seq = await adapter.emit(replyEvent({
      sessionId: session, sessionKey: "agent:main:telegram:1", agentId: "main",
      destination: { channel: "telegram", to: "1" }, outcome: "kept", placeholders: [sym], checked: true,
    }));
    assert.ok(seq >= 1, `stored with a seq (${seq})`);
    const human = new ArbiterClient(humanSockIn(tmp));
    await human.connect();
    try {
      const evs = await human.events(session, 0);
      assert.equal(evs.length, 1);
      const ev = evs[0] as unknown as Record<string, any>;
      assert.equal(ev.claimed, true, "an event from the data socket is a claim");
      assert.equal(ev.emitter, "openclaw-plugin");
      assert.equal(ev.openclaw.sessionKey, "agent:main:telegram:1");
    } finally {
      human.close();
    }
  } finally {
    client.close();
    setup.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
