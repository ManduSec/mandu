/**
 * stripped-placeholders — the `strippedPlaceholders` op over the wire
 * (confidentiality.md §7, "A placeholder the agent's shell would expand").
 *
 * The net-proxy rebuilds `$MDU:` names from text a shell left of a
 * placeholder (`:nomodel_Read[h].KEY`) and asks which are real. Pinned: only
 * a secret-labelled ROW is found (the row's level, not the name's marker),
 * look-alikes and malformed names are not, the answer carries names and the
 * rule only (never a value), an oversized ask is refused, the data socket
 * answers it (existence is what `desymbolizationDecision` already tells
 * there), and with the confidentiality axis off nothing is found. A
 * `shell-expanded` refusal is a kind `recordEgressRefusal` accepts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { STRIPPED_PLACEHOLDERS_MAX } from "../../ipc/protocol.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

async function arbiter(dir: string, confidentiality: boolean) {
  mkdirSync(join(dir, "human"), { mode: 0o700, recursive: true });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, adminPolicyDir: null, packDir: null, confidentiality, integrity: false,
  });
  await s.listen();
  const data = new ArbiterClient(join(dir, "a.sock")); await data.connect();
  return { s, data, close: async () => { data.close(); await s.close(); } };
}

test("strippedPlaceholders: a secret row's name is found, look-alikes and public rows are not, never a value", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-stripped-"));
  const KEY = "sk_live_stripped_0123456789abcdef";
  const env = join(dir, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\nPORT=3000\n`);
  const a = await arbiter(dir, true);
  try {
    const reg = await a.data.registerSecret({ path: env });
    assert.ok(reg.twin, reg.reason);
    const P = /STRIPE_KEY='?(\$MDU:[^'\s]+)/.exec(reg.twin!)![1]!;
    const pub = await a.data.symbolizeFull({ tool: "web_fetch", value: "hello world page", field: "text", origin: "https://x.example", integrity: "trusted", sessionKey: "s" });
    const hash = /\[([0-9a-f]+)\]/.exec(P)![1]!;
    const other = hash === "0000" ? "1111" : "0000";
    const r = await a.data.strippedPlaceholders({
      candidates: [P, P.replace(`[${hash}]`, `[${other}]`), pub.symbol, "$MDU:nomodel_Read", "not a name", `${P}.`],
      sessionKey: "s",
    });
    assert.deepEqual(r.found, [P, `${P}.`], "the row, and the same row with a glued dot (the egress lookup)");
    assert.deepEqual(r.ruleRef, { source: "rule", id: "egress:shell-expanded-placeholder" });
    assert.ok(!JSON.stringify(r).includes(KEY), "never a value");
    const none = await a.data.strippedPlaceholders({ candidates: [pub.symbol] });
    assert.deepEqual(none, { found: [] });
    await assert.rejects(a.data.strippedPlaceholders({ candidates: Array.from({ length: STRIPPED_PLACEHOLDERS_MAX + 1 }, () => P) }));
    // the net-proxy's refusal kind is one the arbiter records
    const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
    try {
      assert.deepEqual(await guard.recordEgressRefusal({ procKeys: ["curl-1"], kind: "shell-expanded", sessionKey: "s" }), { recorded: true });
    } finally { guard.close(); }
  } finally {
    await a.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("strippedPlaceholders: with the confidentiality axis off nothing is found", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-stripped-off-"));
  const a = await arbiter(dir, false);
  try {
    assert.deepEqual(await a.data.strippedPlaceholders({ candidates: ["$MDU:nomodel_Read[de31].STRIPE_KEY"] }), { found: [] });
  } finally {
    await a.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
