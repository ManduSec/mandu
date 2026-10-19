/**
 * agent-read-twin.test.ts — plan 10 §11.8 over the real IPC: OpenClaw's and
 * OpenCode's `read` of a registered secret file shows the structured twin
 * (keys raw, one symbol per value) exactly as Claude Code's `Read` does,
 * and every other shape of the result keeps the file's label, so the proxy
 * masks it whole.
 *
 * Mandu-new test. A real ArbiterServer on a temp socket, the real client.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const RAW = "PORT=3000\nSTRIPE_KEY=sk_live_abcdef1234567890\nAPI_TOKEN=tok_0123456789abcdef\n";

async function stack() {
  const dir = mkdtempSync(join(tmpdir(), "mandu-read-twin-"));
  const env = join(dir, ".env");
  writeFileSync(env, RAW);
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false });
  await s.listen();
  const c = new ArbiterClient(sock);
  await c.connect();
  await c.setSessionSpec({ sessionKey: "oc", spec: "openclaw-agent", requestedBy: "agent-read-twin e2e" });
  await c.setSessionSpec({ sessionKey: "od", spec: "opencode", requestedBy: "agent-read-twin e2e" });
  return { dir, env, s, c, done: async () => { c.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("OpenClaw and OpenCode `read` of the twin: public (no mask); the raw file or a tampered twin: the file's label", async () => {
  const k = await stack();
  try {
    const reg = await k.c.registerSecret({ path: k.env });
    const twin = reg.twin as string;
    assert.ok(twin.includes("STRIPE_KEY='$MDU:") && !twin.includes("sk_live_abcdef1234567890"), twin);
    const lines = twin.replace(/\n$/, "").split("\n");
    const oc = (value: string) => k.c.classify({ tool: "read", value, boundary: "model_context", origin: k.env, params: { path: k.env }, sessionKey: "oc" });
    const od = (value: string) => k.c.classify({ tool: "read", value, boundary: "model_context", origin: k.env, params: { filePath: k.env }, sessionKey: "od" });
    const odRender = (ls: string[]) =>
      [`<path>${k.env}</path>`, "<type>file</type>", "<content>", ...ls.map((l, i) => `${i + 1}: ${l}`), "", `(End of file - total ${ls.length} lines)`, "</content>"].join("\n");

    assert.equal((await oc(twin)).confidentiality, "public");
    assert.equal((await oc(`${lines[1]}\n\n[1 more line in file. Use offset=3 to continue.]`)).confidentiality, "public");
    assert.equal((await od(odRender(lines))).confidentiality, "public");

    for (const v of [RAW, twin.replace(/\$MDU:[^\s']+\.STRIPE_KEY/, "sk_live_abcdef1234567890")]) {
      assert.equal((await oc(v)).confidentiality, "no-model", v);
      assert.notEqual((await od(odRender(v.replace(/\n$/, "").split("\n")))).confidentiality, "public", v);
    }
  } finally { await k.done(); }
});
