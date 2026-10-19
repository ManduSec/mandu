/**
 * filter-prompt-op.test — the `filterPrompt` and `promptFilters` ops over
 * the arbiter's real sockets (confidentiality-plan-15-prompt-filter.md §3.2,
 * §8.1, phase 1). Mandu-new.
 *
 * Proves, through ArbiterClient over the data and human sockets of a
 * listening ArbiterServer:
 *   - a registered environment value pasted into a human segment comes back
 *     as the value's OWN symbol (the one `registerEnvSecrets` minted), and
 *     `desymbolize` on the human plane restores the original;
 *   - `postgres` (registered, below the prompt floor) passes in a human
 *     segment and is masked in a harness segment;
 *   - a DRY RUN is refused on the data socket (the agent's world) and served
 *     on the human socket, where it mints nothing;
 *   - `promptFilters` names the one filter, who set it, and the digest;
 *   - the value backstop (`scanSecretValues`) answers as before over the
 *     one-pass index.
 *
 * Axes: secrets (stated; the server's confidentiality option pinned ON).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer, humanPlaneOnlyError } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const KEY = "sk-live-Zq81Hc0vNw3PpL6tYb4R";
const WEAK = "postgres";

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

async function rig(confidentiality = true) {
  const dir = mkdtempSync(join(tmpdir(), "mdu-filter-prompt-"));
  dirs.push(dir);
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality, integrity: false, policyPollMs: 0, packDir: null,
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  const human = new ArbiterClient(humanSock);
  return { server, data, human, close: async () => { data.close(); human.close(); await server.close(); } };
}

test("a registered value in the human's prompt becomes its own symbol; the human plane restores it", async () => {
  const r = await rig();
  try {
    const reg = await r.data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }, { name: "DB_PASSWORD", value: WEAK }], sessionKey: "s1" });
    assert.ok(reg);
    const out = await r.data.filterPrompt({
      session: "s1", agent: "claude-code",
      segments: [
        { id: "h", origin: "human", text: `my key is ${KEY}, the db password is ${WEAK}` },
        { id: "r", origin: "harness", text: `<system-reminder>DB_PASSWORD=${WEAK}</system-reminder>` },
      ],
    });
    assert.equal(out.enforcing, true);
    const [h, hr] = out.segments;
    assert.equal(h!.action, "rewrite");
    assert.ok(!h!.text!.includes(KEY), "the key never reaches the model raw");
    assert.ok(h!.text!.includes(WEAK), "postgres in the human's text passes (prompt floor)");
    assert.equal(h!.skipped, 1);
    const sym = h!.findings[0]!.symbol!;
    assert.match(sym, /^\$MDU:/);
    assert.equal(hr!.action, "rewrite");
    assert.ok(!hr!.text!.includes(WEAK), "postgres in harness text is masked");
    // The human still sees the original.
    const back = await r.human.desymbolize(h!.text!);
    assert.equal(back, `my key is ${KEY}, the db password is ${WEAK}`);
    // Resend: the same symbol, from the cache.
    const again = await r.data.filterPrompt({ session: "s1", agent: "claude-code", segments: [{ id: "h", origin: "human", text: `my key is ${KEY}, the db password is ${WEAK}` }] });
    assert.equal(again.segments[0]!.text, h!.text);
    assert.equal(again.segments[0]!.cached, true);
  } finally {
    await r.close();
  }
});

test("a dry run is refused on the data socket and served on the human socket, minting nothing", async () => {
  const r = await rig();
  try {
    await r.data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const req = { agent: "dashboard", dryRun: true, segments: [{ id: "t", origin: "human" as const, text: `try ${KEY}` }] };
    await assert.rejects(() => r.data.filterPrompt(req), (e: Error) => e.message.includes(humanPlaneOnlyError("filterPrompt")));
    // A truthy non-boolean is a dry run too: refused, never run live.
    await assert.rejects(() => r.data.filterPrompt({ ...req, dryRun: 1 as unknown as boolean }), /human-plane/);
    const before = (await r.data.promptFilters()).registeredValues;
    const out = await r.human.filterPrompt(req);
    assert.equal(out.dryRun, true);
    assert.ok(!out.segments[0]!.text!.includes(KEY));
    assert.equal((await r.data.promptFilters()).registeredValues, before, "nothing minted");
  } finally {
    await r.close();
  }
});

test("promptFilters names the filter and who set it; scanSecretValues answers as before", async () => {
  const r = await rig();
  try {
    await r.data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const pf = await r.data.promptFilters();
    // Phase 2: the two built-ins, registered-value on and key-shapes off, both by default.
    assert.deepEqual(pf.filters.map((f) => [f.id, f.kind, f.on, f.setBy]), [["registered-value", "built-in", true, "default"], ["key-shapes", "built-in", false, "default"]]);
    assert.deepEqual(pf.filters[0]!.categories, [{ category: "secret.registered", action: "mask" }]);
    assert.deepEqual(pf.actions, [{ category: "secret.registered", action: "mask", setBy: "default", locked: false }]);
    assert.equal(pf.fallback, "redact");
    assert.ok(pf.registeredValues >= 1);
    assert.match(pf.digest.policy, /^[0-9a-f]{16}$/);
    assert.ok(!JSON.stringify(pf).includes(KEY), "no value in the panel's projection");
    const hits = await r.data.scanSecretValues(`a ${KEY} b`);
    assert.equal(hits.hits.length, 1);
    assert.deepEqual((await r.data.scanSecretValues("nothing")).hits, []);
  } finally {
    await r.close();
  }
});

test("confidentiality axis OFF: findings are log only and nothing is rewritten", async () => {
  const r = await rig(false);
  try {
    await r.data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const out = await r.data.filterPrompt({ agent: "codex", segments: [{ id: "h", origin: "harness", text: `k=${KEY}` }] });
    assert.equal(out.enforcing, false);
    assert.equal(out.segments[0]!.action, "pass");
    assert.equal(out.segments[0]!.text, undefined);
  } finally {
    await r.close();
  }
});

test("phase 3 seam: filterPrompt is asynchronous; concurrent requests on one socket each get their answer; the channel check stays first", async () => {
  const r = await rig();
  try {
    await r.data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }], sessionKey: "s1" });
    // The synchronous dispatch points at the asynchronous op.
    const sync = r.server.dispatch({ id: 1, op: "filterPrompt", agent: "codex", segments: [] } as never) as { ok: boolean; error?: string };
    assert.equal(sync.ok, false);
    assert.match(sync.error!, /asynchronous/);
    // In process: the op itself, and its channel check (a dry run is human-plane).
    const inproc = await r.server.filterPromptOp({ id: 2, op: "filterPrompt", agent: "codex", segments: [{ id: "h", origin: "human", text: `k ${KEY}` }] } as never) as { ok: boolean; result: { segments: Array<{ text?: string }> } };
    assert.equal(inproc.ok, true);
    assert.ok(!inproc.result.segments[0]!.text!.includes(KEY));
    const refused = await r.server.filterPromptOp({ id: 3, op: "filterPrompt", agent: "codex", dryRun: true, segments: [] } as never, { channel: "data" }) as { ok: boolean; error?: string };
    assert.equal(refused.ok, false);
    assert.equal(refused.error, humanPlaneOnlyError("filterPrompt"));
    // Over the socket, many at once.
    const many = await Promise.all(Array.from({ length: 8 }, (_, i) =>
      r.data.filterPrompt({ session: "s1", agent: "claude-code", segments: [{ id: `h${i}`, origin: "human", text: `turn ${i}: ${KEY}` }] })));
    many.forEach((m, i) => {
      assert.equal(m.segments[0]!.id, `h${i}`);
      assert.equal(m.segments[0]!.action, "rewrite");
      assert.ok(!m.segments[0]!.text!.includes(KEY));
    });
  } finally {
    await r.close();
  }
});
