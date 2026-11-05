/**
 * attachment-hooks tests — the plugin's hooks registered through the real
 * registrar (src/register.ts) on a FAKE OpenClaw api, against a mock arbiter
 * (docs/design/agents/openclaw-plugin.md §3.5, §3.6).
 *
 * No OpenClaw, no socket. What is pinned:
 *   - the attachment registers exactly before_tool_call and message_sending,
 *     no conversation-access hook, no tool-result middleware; the per-run
 *     config (no `attachment`) registers no hook at all;
 *   - before_tool_call blocks a tamper call with a reason, passes ordinary
 *     calls, and needs no arbiter (it decides with the arbiter down);
 *   - message_sending leaves a reply with placeholders UNCHANGED (no release
 *     op exists), cancels a reply that carries a secret value, and on any
 *     arbiter failure or hang sends the reply unchanged (its placeholders);
 *   - events go to `openclaw:<agentId>` with the Gateway's sessionKey, and
 *     carry no reply text and no tool arguments;
 *   - an attachment without a U-LLM transport keeps its hooks (inspect_symbol
 *     is dropped with an error), and a host without api.on fails the load.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { registerInspectPlugin, tamperContextFrom, type RegisterOptions } from "../../src/register.js";
import type { OpenClawPluginApiLike, PluginAgentTool, PluginToolFactory } from "../../src/openclaw-api.js";
import type { ReplyReleaser } from "../../src/hook-arbiter.js";
import { MockArbiter } from "../../../inspect-mcp/test/helpers/mock-arbiter.js";
import { MockUllm } from "../../../inspect-mcp/test/helpers/mock-ullm.js";
import { MockHookArbiter } from "../helpers/mock-hook-arbiter.js";

const SOCK = "/run/user/1000/mandu/instances/ab12/arbiter.sock";
const P1 = "$MDU:env[ab12]";
const SECRET = "sk-live-4f9b2c7d1e8a6b3f";

type Handler = (event: unknown, ctx: unknown) => unknown;

function fakeApi(pluginConfig: Record<string, unknown>, withOn = true) {
  const hooks = new Map<string, Handler>();
  const tools: Array<PluginAgentTool | PluginToolFactory> = [];
  const logs: string[] = [];
  const api: OpenClawPluginApiLike = {
    id: "mandu-inspect",
    pluginConfig,
    logger: { info: (m) => logs.push(`info:${m}`), warn: (m) => logs.push(`warn:${m}`), error: (m) => logs.push(`error:${m}`) },
    registerTool: (t) => tools.push(t),
    ...(withOn ? { on: (name: string, h: (e: never, c: never) => unknown) => { hooks.set(name, h as Handler); } } : {}),
  };
  return { api, hooks, tools, logs };
}

const ATTACH = { arbiterSock: SOCK, attachment: true, agentId: "main", scopeId: "openclaw:main", manduPaths: ["/home/u/.mandu", "/run/user/1000/mandu"] };
const ENV = { HOME: "/home/u" };

function opts(hookArbiter: MockHookArbiter | null, over: Partial<RegisterOptions> = {}): RegisterOptions {
  return {
    env: ENV,
    cliAvailable: () => true,
    connectArbiter: async () => new MockArbiter(),
    buildUllm: () => new MockUllm(),
    connectHookArbiter: async () => {
      if (hookArbiter === null) throw new Error("ECONNREFUSED");
      return hookArbiter;
    },
    ...over,
  };
}

/** Wait for the fire-and-forget emits to land. */
const settle = () => new Promise((r) => setTimeout(r, 10));

test("the attachment registers exactly before_tool_call and message_sending; the per-run config registers none", () => {
  const a = fakeApi(ATTACH);
  registerInspectPlugin(a.api, opts(new MockHookArbiter()));
  assert.deepEqual([...a.hooks.keys()].sort(), ["before_tool_call", "message_sending"]);
  assert.equal(a.tools.length, 2, "inspect_symbol + declassify_symbol still registered");

  const b = fakeApi({ arbiterSock: SOCK, ullmMode: "cli" });
  registerInspectPlugin(b.api, opts(new MockHookArbiter()));
  assert.equal(b.hooks.size, 0, "mandu openclaw's per-run config: tools only, as before");
});

test("before_tool_call blocks a tamper call, passes an ordinary one, and needs no arbiter", async () => {
  const a = fakeApi(ATTACH);
  registerInspectPlugin(a.api, opts(null)); // the arbiter is down
  const h = a.hooks.get("before_tool_call")!;
  const ctx = { agentId: "main", sessionKey: "agent:main:telegram:42", toolName: "exec" };

  const r = h({ toolName: "exec", params: { command: "mandu serve stop" }, toolCallId: "t1" }, ctx) as { block?: boolean; blockReason?: string };
  assert.equal(r.block, true);
  assert.match(r.blockReason!, /Mandu refused this exec call/);

  assert.equal(h({ toolName: "exec", params: { command: "ls -la" } }, ctx), undefined);
  assert.equal(h({ toolName: "read", params: { path: "/home/u/.openclaw/workspace/a.md" } }, ctx), undefined);

  const w = h({ toolName: "write", params: { path: "/home/u/.openclaw/openclaw.json", content: "{}" } }, ctx) as { block?: boolean };
  assert.equal(w.block, true);
  assert.ok(a.logs.some((l) => l.startsWith("warn:[mandu] refused write")));
});

test("before_tool_call's event: openclaw:<agentId>, the sessionKey, the rule, no arguments", async () => {
  const arb = new MockHookArbiter();
  const a = fakeApi(ATTACH);
  registerInspectPlugin(a.api, opts(arb));
  a.hooks.get("before_tool_call")!(
    { toolName: "exec", params: { command: "cat ~/.mandu/state/mandu.db" }, toolCallId: "t9" },
    { agentId: "Work", sessionKey: "agent:work:discord:7" },
  );
  await settle();
  assert.equal(arb.events.length, 1);
  const ev = arb.events[0] as Record<string, any>;
  assert.equal(ev.sessionId, "openclaw:work");
  assert.equal(ev.emitter, "openclaw-plugin");
  assert.equal(ev.kind, "tool_use");
  assert.equal(ev.callId, "t9");
  assert.equal(ev.policy.usage, "deny");
  assert.equal(ev.policy.ruleRef.id, "openclaw:tamper:mandu-state");
  assert.equal(ev.openclaw.sessionKey, "agent:work:discord:7");
  assert.ok(!JSON.stringify(ev).includes("mandu.db"), "no tool arguments in the event");
});

test("message_sending: a reply with a placeholder to an unbound chat is sent UNCHANGED", async () => {
  const arb = new MockHookArbiter([{ symbol: P1, value: SECRET }]);
  const a = fakeApi(ATTACH);
  registerInspectPlugin(a.api, opts(arb));
  const h = a.hooks.get("message_sending")!;
  const content = `Your key is ${P1}, kept by Mandu.`;
  const r = await h({ to: "12345", content }, { channelId: "telegram", accountId: "bot1", conversationId: "12345", sessionKey: "agent:main:telegram:12345" });
  assert.equal(r, undefined, "no rewrite: the placeholder goes out as is");
  assert.equal(arb.scans.length, 1);
  assert.equal(arb.scans[0]!.destination, "", "a chat is no host: no host binding admits it");
  assert.equal(arb.scans[0]!.scope, "reply", "a reply the model wrote: a whole-masked output counts only by its secrets");
  await settle();
  const ev = arb.events[0] as Record<string, any>;
  assert.equal(ev.sessionId, "openclaw:main");
  assert.equal(ev.kind, "egress_decision");
  assert.equal(ev.policy.ruleRef.id, "openclaw:reply:unbound");
  assert.deepEqual(ev.openclaw.placeholders, [P1]);
  assert.deepEqual(ev.openclaw.destination, { channel: "telegram", to: "12345", accountId: "bot1", conversationId: "12345" });
  assert.equal(ev.openclaw.sessionKey, "agent:main:telegram:12345");
  assert.ok(!JSON.stringify(ev).includes("Your key"), "no reply text in the event");
});

test("message_sending: a reply carrying the secret VALUE is cancelled, the value in no event", async () => {
  const arb = new MockHookArbiter([{ symbol: P1, value: SECRET }]);
  const a = fakeApi(ATTACH);
  registerInspectPlugin(a.api, opts(arb));
  const r = await a.hooks.get("message_sending")!({ to: "9", content: `here: ${SECRET}` }, { channelId: "whatsapp", sessionKey: "agent:main:whatsapp:9" }) as { cancel?: boolean; cancelReason?: string };
  assert.equal(r.cancel, true);
  assert.match(r.cancelReason!, /Mandu cancelled this reply/);
  assert.ok(!r.cancelReason!.includes(SECRET));
  await settle();
  const ev = arb.events[0] as Record<string, any>;
  assert.equal(ev.policy.usage, "deny");
  assert.deepEqual(ev.openclaw.hits, [{ symbol: P1, level: "secret" }]);
  assert.ok(!JSON.stringify(ev).includes(SECRET));
  assert.ok(!a.logs.some((l) => l.includes(SECRET)), "no log line carries the value");
});

test("message_sending fails safe: arbiter down, refusing, or hanging → the reply goes out unchanged", async () => {
  const content = `token ${P1}`;
  const ctx = { channelId: "telegram", sessionKey: "agent:main:telegram:1" };

  const down = fakeApi(ATTACH);
  registerInspectPlugin(down.api, opts(null));
  assert.equal(await down.hooks.get("message_sending")!({ to: "1", content }, ctx), undefined);
  assert.ok(down.logs.some((l) => /reply not checked/.test(l)));

  const refusing = new MockHookArbiter();
  refusing.failScan = new Error("refused on data channel");
  const r = fakeApi(ATTACH);
  registerInspectPlugin(r.api, opts(refusing));
  assert.equal(await r.hooks.get("message_sending")!({ to: "1", content }, ctx), undefined);

  const hanging = new MockHookArbiter();
  hanging.hangScan = true;
  const g = fakeApi(ATTACH);
  registerInspectPlugin(g.api, opts(hanging, { replyTimeoutMs: 50 }));
  // The hook's timer is unref'd (a guest must not hold its host's event loop
  // open), so the test holds the loop itself while it waits.
  const hold = setTimeout(() => {}, 5000);
  const t0 = Date.now();
  const out = await g.hooks.get("message_sending")!({ to: "1", content }, ctx);
  clearTimeout(hold);
  assert.equal(out, undefined);
  assert.ok(Date.now() - t0 < 2000);
  assert.ok(g.logs.some((l) => /no answer within 50 ms/.test(l)));
});

test("message_sending: a reply with no placeholder and no value is unchanged and leaves no event", async () => {
  const arb = new MockHookArbiter([{ symbol: P1, value: SECRET }]);
  const a = fakeApi(ATTACH);
  registerInspectPlugin(a.api, opts(arb));
  assert.equal(await a.hooks.get("message_sending")!({ to: "1", content: "hello" }, { channelId: "telegram" }), undefined);
  assert.equal(await a.hooks.get("message_sending")!({ to: "1", content: "" }, { channelId: "telegram" }), undefined);
  await settle();
  assert.equal(arb.events.length, 0);
});

test("the release seam: a live releaser's answer is sent; the default sends nothing back", async () => {
  const arb = new MockHookArbiter();
  const live: ReplyReleaser = {
    live: true,
    async release({ text, destination }) {
      return destination.channel === "telegram" ? { text: text.replace(P1, "BOUND-VALUE"), released: [P1] } : { text, released: [] };
    },
  };
  const a = fakeApi(ATTACH);
  registerInspectPlugin(a.api, opts(arb, { releaser: live }));
  const r = await a.hooks.get("message_sending")!({ to: "1", content: `v=${P1}` }, { channelId: "telegram", sessionKey: "agent:main:telegram:1" }) as { content?: string };
  assert.equal(r.content, "v=BOUND-VALUE");
  assert.equal(await a.hooks.get("message_sending")!({ to: "1", content: `v=${P1}` }, { channelId: "slack" }), undefined);

  const failing: ReplyReleaser = { live: true, async release() { throw new Error("boom"); } };
  const b = fakeApi(ATTACH);
  registerInspectPlugin(b.api, opts(arb, { releaser: failing }));
  assert.equal(await b.hooks.get("message_sending")!({ to: "1", content: `v=${P1}` }, { channelId: "telegram" }), undefined, "a failed release keeps the placeholders");
});

test("an attachment without a U-LLM keeps its hooks; inspect_symbol is dropped with an error", () => {
  const a = fakeApi(ATTACH);
  registerInspectPlugin(a.api, opts(new MockHookArbiter(), { cliAvailable: () => false }));
  assert.deepEqual([...a.hooks.keys()].sort(), ["before_tool_call", "message_sending"]);
  assert.equal(a.tools.length, 1, "declassify_symbol only");
  assert.ok(a.logs.some((l) => l.startsWith("error:[mandu-inspect] inspect_symbol not registered")));
  // The per-run config keeps failing loudly, as before.
  const b = fakeApi({ arbiterSock: SOCK });
  assert.throws(() => registerInspectPlugin(b.api, opts(new MockHookArbiter(), { cliAvailable: () => false })));
});

test("a host without api.on fails the attachment load loudly", () => {
  const a = fakeApi(ATTACH, false);
  assert.throws(() => registerInspectPlugin(a.api, opts(new MockHookArbiter())), /no plugin hook API/);
});

test("tamperContextFrom: the Gateway's env and the config's paths", () => {
  const c = tamperContextFrom({ arbiterSock: SOCK, manduPaths: ["/opt/mandu-home", "relative"] }, {
    HOME: "/home/u", OPENCLAW_STATE_DIR: "/srv/oc", XDG_RUNTIME_DIR: "/run/user/1000",
  });
  assert.equal(c.home, "/home/u");
  assert.equal(c.openclawStateDir, "/srv/oc");
  assert.equal(c.openclawConfigPath, "/srv/oc/openclaw.json");
  assert.deepEqual(c.manduPaths, ["/home/u/.mandu", "/run/user/1000/mandu", "/opt/mandu-home", SOCK]);
  const d = tamperContextFrom({ arbiterSock: SOCK, manduPaths: [] }, { HOME: "/home/u", OPENCLAW_CONFIG_PATH: "/etc/oc.json", MANDU_HOME: "/m" });
  assert.equal(d.openclawConfigPath, "/etc/oc.json");
  assert.equal(d.openclawStateDir, "/home/u/.openclaw");
  assert.ok(d.manduPaths.includes("/m"));
});
