/**
 * twin-writes-classify.test.ts — the classify op's `twinWrites` over the real
 * IPC (plan 10 §4.1, "The model is told at the call", 2026-10-27): the path
 * tokens a call writes that name a registered secret file Mandu serves a twin
 * of, as the model wrote them, on a masked answer and a public one alike, for
 * a session the file guard confines (an attested `confined` launch record).
 * None for a read, a file no registration covers, a new file, a session with
 * no launch record or a `gated` one, or with the confidentiality axis off; the
 * level is never changed by it.
 *
 * Mandu-new test. A real ArbiterServer on a temp socket, the real client.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const RAW = "ORDERHUB_URL=https://api.orderhub.test\nORDERHUB_USER=bakery-shop\nORDERHUB_PASSPHRASE='Juniper-Harbor-TWINWRITE-6038'\n";
const SESSION = "tw-confined";

async function stack(confidentiality: boolean) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-twin-writes-"));
  const app = join(dir, "orders-app");
  mkdirSync(app);
  const env = join(app, ".env");
  writeFileSync(env, RAW);
  writeFileSync(join(app, "notes.txt"), "plain\n");
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality, integrity: false });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the launcher's and the proxy's channel (plan 13 D9)
  await c.connect();
  // The launcher's record of a Linux launch with the file guard (cache-epoch.ts).
  await c.beginLaunch({ pid: process.pid, mode: "secrets", posture: "confined", writeProtect: true, humanPlaneWalled: true, sessionId: SESSION });
  return { dir, app, env, c, done: async () => { c.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

const HEREDOC = (path: string) => `cat > ${path} << 'EOF'\nORDERHUB_PASSWORD='$MDU:nomodel_Read[a169].ORDERHUB_PASSPHRASE'\nEOF\n`;
const classify = (c: ArbiterClient, tool: string, params: Record<string, unknown>, value = "", sessionKey = SESSION) =>
  c.classify({ tool, value, boundary: "model_context", params, sessionKey });

test("a write into the registered .env in a guarded session: twinWrites names the token as written, on the masked answer; the level is the path's", async () => {
  const k = await stack(true);
  try {
    assert.ok((await k.c.registerSecret({ path: k.env })).symbol);
    const abs = await classify(k.c, "Bash", { command: HEREDOC(k.env) }, "(Bash completed with no output)");
    assert.equal(abs.confidentiality, "no-model", abs.reason);
    assert.deepEqual(abs.twinWrites, [k.env]);
    // relative under the command's leading cd; the sed script is no file
    const rel = await classify(k.c, "Bash", { command: `cd ${k.dir} && sed -i 's/PASSPHRASE/PASSWORD/' orders-app/.env` });
    assert.deepEqual(rel.twinWrites, ["orders-app/.env"]);
    // Codex's exec_command (`cmd`) reads the same way
    assert.deepEqual((await classify(k.c, "exec_command", { cmd: `echo X=1 >> ${k.env}` })).twinWrites, [k.env]);
    // Edit's refused save: a public answer (the tool's own error), with the path
    const refused = `EACCES: permission denied, rename '${k.env}.tmp.2.5f8d4674dd18' -> '${k.env}'`;
    const edit = await classify(k.c, "Edit", { file_path: k.env, old_string: "a", new_string: "b" }, refused);
    assert.notEqual(edit.confidentiality, "no-model", edit.reason);
    assert.deepEqual(edit.twinWrites, [k.env]);
  } finally { await k.done(); }
});

test("no twinWrites: a read of the .env, a write of a plain or new file, an unregistered secret, a non-shell tool, a relative Edit", async () => {
  const k = await stack(true);
  try {
    const none = async (tool: string, params: Record<string, unknown>): Promise<void> => {
      const r = await classify(k.c, tool, params);
      assert.equal(r.twinWrites, undefined, `${tool} ${JSON.stringify(params)}: ${JSON.stringify(r.twinWrites)}`);
    };
    // before registration: the catalog calls it secret, but Mandu serves no twin of it
    await none("Bash", { command: HEREDOC(k.env) });
    assert.ok((await k.c.registerSecret({ path: k.env })).symbol);
    await none("Bash", { command: `cat ${k.env}` });
    await none("Bash", { command: `grep KEY < ${k.env} > ${join(k.app, "notes.txt")}` });
    await none("Bash", { command: `echo hi > ${join(k.app, "new.txt")}` });
    await none("Read", { file_path: k.env });
    await none("mcp__x__run", { command: HEREDOC(k.env) });
    await none("Edit", { file_path: "orders-app/.env", old_string: "a", new_string: "b" });
  } finally { await k.done(); }
});

test("only a session the file guard confines: no launch record, a gated launch, or no session key answer nothing", async () => {
  const k = await stack(true);
  try {
    assert.ok((await k.c.registerSecret({ path: k.env })).symbol);
    await k.c.beginLaunch({ pid: process.pid, mode: "secrets", posture: "gated", writeProtect: true, humanPlaneWalled: true, sessionId: "tw-gated" });
    for (const sessionKey of ["tw-unlaunched", "tw-gated", ""]) {
      const r = await classify(k.c, "Bash", { command: HEREDOC(k.env) }, "", sessionKey);
      assert.equal(r.confidentiality, "no-model", "the mask is the path's, whatever the session");
      assert.equal(r.twinWrites, undefined, `${sessionKey}: ${JSON.stringify(r.twinWrites)}`);
    }
    assert.deepEqual((await classify(k.c, "Bash", { command: HEREDOC(k.env) })).twinWrites, [k.env], "the guarded session still does");
  } finally { await k.done(); }
});

test("confidentiality axis OFF: classify never answers twinWrites", async () => {
  const k = await stack(false);
  try {
    const r = await classify(k.c, "Bash", { command: HEREDOC(k.env) });
    assert.equal(r.twinWrites, undefined);
  } finally { await k.done(); }
});
