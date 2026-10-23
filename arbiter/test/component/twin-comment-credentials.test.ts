/**
 * twin-comment-credentials.test.ts — the structured twin's credential belt
 * and glued-secret lines (plan 10 §2.4, §11.8, 2026-10-17) over the real
 * IPC: a real ArbiterServer on a temp socket, the real client.
 *
 *   - a `.env` whose comment holds an old key (`# OLD_STRIPE_KEY=sk_live_…`):
 *     the twin `registerSecret` serves holds it as a field token, in none of
 *     the reviewer's encodings; Claude's Read of the twin is per key
 *     (public), the old key's field row is a registered value (the backstop
 *     and the egress tripwire hold it), `cat` of the twin is the structured
 *     exec-twin rule's, and a key listing of it names the file;
 *   - a `.env` with a short value glued inside another line's word
 *     (`DB_PASS2=owl`, `MODE=owlish`): the twin's release rules refuse a
 *     Read or `cat` of the whole twin (the path rule masks it), while a Read
 *     of other lines and the key listing (`MODE` alone) pass; and that line
 *     is no piece of the file, so an unrelated package.json or Dockerfile
 *     holding it is not masked (review of !1621);
 *   - a `.env` with `DATABASE_PORT=5432` keeps a per-key Read of its twin.
 *
 * Mandu-new test.
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

const OLD = "sk_" + "live_51OldKeyAbCdEfGhIjKlMnOpQrStUv";
const NEW = "sk_" + "live_51NewKeyZyXwVuTsRqPoNmLkJiHg";
const COMMENTED = `# OLD_STRIPE_KEY=${OLD}\nSTRIPE_SECRET_KEY=${NEW}\nPORT=3000\n`;
const GLUED = `STRIPE_SECRET_KEY=${NEW}\nDB_PASS2=owl\nMODE=owlish\nPORT=3000\n`;

/** Claude Code's Read rendering: a right-aligned line number and a tab. */
const claudeRead = (text: string) => text.replace(/\n$/, "").split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");

/** The reviewer's encodings of `secret` (verbatim, minus its prefix,
 *  reversed, base64 at each alignment, a 12-character window of its body). */
function encodings(secret: string): string[] {
  const body = secret.replace(/^sk_live_/, "");
  const out = [secret, body, [...secret].reverse().join(""), body.slice(2, 14)];
  for (let k = 0; k < 3; k++) out.push(Buffer.from("x".repeat(k) + secret).toString("base64").slice(4, -4));
  return out;
}

async function stack() {
  const dir = mkdtempSync(join(tmpdir(), "mandu-twin-belt-"));
  const s = new ArbiterServer({ socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxy's channel
  await c.connect();
  return { dir, s, c, done: async () => { c.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("a commented-out old key: the served twin holds its token (no encoding of the key), Read and `cat` of the twin pass, the key itself is a registered value", async () => {
  const k = await stack();
  try {
    const env = join(k.dir, ".env");
    writeFileSync(env, COMMENTED);
    const reg = await k.c.registerSecret({ path: env, sessionKey: "tc" });
    const twin = reg.twin as string;
    assert.ok(typeof twin === "string", JSON.stringify(reg));
    for (const e of encodings(OLD)) assert.ok(!twin.includes(e), `the twin holds ${e}:\n${twin}`);
    assert.match(twin, /^# OLD_STRIPE_KEY=\$MDU:nomodel_Read\[[0-9a-f]+\]\.cred\.OLD_STRIPE_KEY\n/);
    assert.equal(reg.fields, 2);

    // Claude Code's Read of the twin: the structured read-twin rule, unraised.
    const read = await k.c.classify({ tool: "Read", value: claudeRead(twin), boundary: "model_context", origin: env, params: { file_path: env }, sessionKey: "tc" });
    assert.equal(read.confidentiality, "public", read.reason);
    assert.doesNotMatch(read.reason, /appears verbatim/);
    assert.deepEqual((await k.c.scanSecretValues(twin)).hits, [], "the twin is no registered value");

    // The old key is a registered value of its own: the backstop and the
    // egress tripwire hold it (a copy the model got another way is caught).
    assert.ok((await k.c.scanSecretValues(`echo ${OLD}`)).hits.length > 0);
    assert.equal((await k.c.egressFingerprintScan({ surfaces: [{ where: "body", text: `{"k":"${OLD}"}` }], destination: "api.stripe.com" })).tripped, true, "bound nowhere: not even the vendor's own host");

    // `cat .env` in a clean tree: the structured exec-twin rule names the file.
    await k.c.recordExecRoot({ procKey: "tc-sh-1", argv: ["/bin/sh", "-c", "cat .env"], session: "tc" });
    const cat = await k.c.callTaint("call_tc_cat", { command: "cat .env", session: "tc", output: twin });
    assert.deepEqual(cat.twinOf, [env]);
    // the key listing (!1604): the comment line holds a token now, so it is a
    // token-bearing line, standing as its key part (`# OLD_STRIPE_KEY`)
    await k.c.recordExecRoot({ procKey: "tc-sh-2", argv: ["/bin/sh", "-c", "cut -d= -f1 .env"], session: "tc2" });
    const keys = await k.c.callTaint("call_tc_keys", { command: "cut -d= -f1 .env", session: "tc2", output: "# OLD_STRIPE_KEY\nSTRIPE_SECRET_KEY\nPORT\n" });
    assert.deepEqual(keys.twinOf, [env]);
    assert.equal(keys.twinKeys, true);
  } finally { await k.done(); }
});

test("a short value glued inside another line's word: the twin's release rules refuse a Read or `cat` carrying it (masked by the path rule), ordinary lines and the key names still pass", async () => {
  const k = await stack();
  try {
    const env = join(k.dir, ".env");
    writeFileSync(env, GLUED);
    const reg = await k.c.registerSecret({ path: env, sessionKey: "tg" });
    const twin = reg.twin as string;
    assert.ok(twin.includes("\nMODE=owlish\n"), "the twin programs read keeps MODE as written");

    // Read of the whole twin: no structured read-twin release; the path rule masks it.
    const read = await k.c.classify({ tool: "Read", value: claudeRead(twin), boundary: "model_context", origin: env, params: { file_path: env }, sessionKey: "tg" });
    assert.equal(read.confidentiality, "no-model", read.reason);
    assert.doesNotMatch(read.reason, /structured read-twin/);
    // `cat .env` in a clean tree: no structured exec-twin answer.
    await k.c.recordExecRoot({ procKey: "tg-sh-0", argv: ["/bin/sh", "-c", "cat .env"], session: "tg0" });
    const cat = await k.c.callTaint("call_tg_cat", { command: "cat .env", session: "tg0", output: twin });
    assert.equal(cat.twinOf, undefined);

    // A Read of the lines around it (offset/limit) is per key as before.
    const part = twin.split("\n").slice(0, 2).join("\n");
    const partRead = await k.c.classify({ tool: "Read", value: claudeRead(part), boundary: "model_context", origin: env, params: { file_path: env }, sessionKey: "tg" });
    assert.equal(partRead.confidentiality, "public", partRead.reason);

    // The key listing: `MODE` (no secret text in the name) stands for the glued line.
    await k.c.recordExecRoot({ procKey: "tg-sh-1", argv: ["/bin/sh", "-c", "cut -d= -f1 .env"], session: "tg" });
    const keys = await k.c.callTaint("call_tg_keys", { command: "cut -d= -f1 .env", session: "tg", output: "STRIPE_SECRET_KEY\nDB_PASS2\nMODE\nPORT\n" });
    assert.deepEqual(keys.twinOf, [env]);
    assert.equal(keys.twinKeys, true);
    await k.c.recordExecRoot({ procKey: "tg-sh-2", argv: ["/bin/sh", "-c", "sed 's/=.*//;/MODE/s/$/=owlish/' .env"], session: "tg2" });
    const val = await k.c.callTaint("call_tg_val", { command: "sed 's/=.*//;/MODE/s/$/=owlish/' .env", session: "tg2", output: "STRIPE_SECRET_KEY\nDB_PASS2\nMODE=owlish\nPORT\n" });
    assert.equal(val.twinKeys, undefined, "the glued line verbatim is no key listing");
  } finally { await k.done(); }
});

test("review of !1621: a glued twin line is no piece of the file, so an unrelated package.json or Dockerfile carrying the same line is not masked", async () => {
  const k = await stack();
  try {
    const env = join(k.dir, ".env");
    writeFileSync(env, `STRIPE_SECRET_KEY=${NEW}\nDB_PASS=dev\nDB_PASSWORD=1\nNODE_ENV=development\nPORT=4100\n`);
    await k.c.registerSecret({ path: env, sessionKey: "tr" });
    const pkg = join(k.dir, "package.json");
    const pkgText = `{\n  "scripts": {\n    "dev": "NODE_ENV=development next dev"\n  }\n}\n`;
    writeFileSync(pkg, pkgText);
    const docker = join(k.dir, "Dockerfile");
    const dockerText = "FROM node:22\nENV NODE_ENV=development\nENV PORT=4100\n";
    writeFileSync(docker, dockerText);
    for (const [path, text] of [[pkg, pkgText], [docker, dockerText]] as const) {
      assert.deepEqual((await k.c.scanSecretValues(text)).hits, [], path);
      const r = await k.c.classify({ tool: "Read", value: claudeRead(text), boundary: "model_context", origin: path, params: { file_path: path }, sessionKey: "tr" });
      assert.equal(r.confidentiality, "public", `${path}: ${r.reason}`);
    }
    assert.equal((await k.c.egressFingerprintScan({ surfaces: [{ where: "body", text: dockerText }], destination: "registry.example" })).tripped, false);
  } finally { await k.done(); }
});

test("review of !1621: a .env with `DATABASE_PORT=5432` (one bare token) keeps a per-key Read of its twin", async () => {
  const k = await stack();
  try {
    const env = join(k.dir, ".env");
    writeFileSync(env, `STRIPE_SECRET_KEY=${NEW}\nDATABASE_PORT=5432\nDB_POOL_SIZE_MAX=10\n`);
    const reg = await k.c.registerSecret({ path: env, sessionKey: "td" });
    const twin = reg.twin as string;
    assert.deepEqual((await k.c.scanSecretValues(twin)).hits, [], "the twin is no registered value");
    const read = await k.c.classify({ tool: "Read", value: claudeRead(twin), boundary: "model_context", origin: env, params: { file_path: env }, sessionKey: "td" });
    assert.equal(read.confidentiality, "public", read.reason);
    assert.ok((await k.c.scanSecretValues(`x ${NEW}`)).hits.length > 0, "the secret itself still hits");
  } finally { await k.done(); }
});
