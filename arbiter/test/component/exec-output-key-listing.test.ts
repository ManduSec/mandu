/**
 * exec-output-key-listing.test.ts — "A key listing" (plan 10 §11.8,
 * 2026-10-16) over the real IPC: `callTaint` answers `twinOf` with
 * `twinKeys` for a token-free shell result that is the keys of ONE
 * registered file's structured twin, in order, and ONLY on the evidence the
 * other twin rules need (the guard recorded the call's tree and nothing in it
 * read a secret raw). No record, a raw read in the tree, a value, a
 * reordered listing or the axis off: no `twinOf`.
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

const KEY = "sk_test_51KeyListingE2E0123456789";
const RAW = `# fake values, made up by mandu demo\nSTRIPE_SECRET_KEY=${KEY}\nPORT=4242\n`;
const LISTING = "# fake values, made up by mandu demo\nSTRIPE_SECRET_KEY\nPORT";
const COMMAND = "sed 's/=.*//' .env";

async function stack(confidentiality: boolean) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-key-listing-"));
  const env = join(dir, ".env");
  writeFileSync(env, RAW);
  const other = join(dir, "other.env");
  writeFileSync(other, "API_TOKEN=tok_0123456789abcdef0123\nDEBUG=1\n");
  const s = new ArbiterServer({ socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality, integrity: false });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxy's channel (plan 13 D9)
  await c.connect();
  return { dir, env, other, s, c, done: async () => { c.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("the guard saw `sed 's/=.*//' .env` read the twin: callTaint names the file with twinKeys; a second registered file is not confused for it", async () => {
  const k = await stack(true);
  try {
    const reg = await k.c.registerSecret({ path: k.env });
    assert.ok(typeof reg.twin === "string" && !(reg.twin as string).includes(KEY), JSON.stringify(reg));
    await k.c.registerSecret({ path: k.other });
    await k.c.recordExecRoot({ procKey: "kl-sh-1", argv: ["/bin/sh", "-c", COMMAND], session: "kl" });
    const t = await k.c.callTaint("call_kl_1", { command: COMMAND, session: "kl", output: LISTING });
    assert.equal(t.root, "kl-sh-1");
    assert.equal(t.level, null);
    assert.deepEqual(t.twinOf, [k.env]);
    assert.equal(t.twinKeys, true);
    assert.equal(t.twinWhole, undefined);
    // the other file's keys name the other file
    await k.c.recordExecRoot({ procKey: "kl-sh-2", argv: ["/bin/sh", "-c", "cut -d= -f1 other.env"], session: "kl2" });
    const o = await k.c.callTaint("call_kl_2", { command: "cut -d= -f1 other.env", session: "kl2", output: "API_TOKEN\nDEBUG\n" });
    assert.deepEqual(o.twinOf, [k.other]);
    assert.equal(o.twinKeys, true);
    // the twin itself (a token) is the structured rule's answer, no twinKeys
    await k.c.recordExecRoot({ procKey: "kl-sh-3", argv: ["/bin/sh", "-c", "cat .env"], session: "kl3" });
    const w = await k.c.callTaint("call_kl_3", { command: "cat .env", session: "kl3", output: reg.twin as string });
    assert.deepEqual(w.twinOf, [k.env]);
    assert.equal(w.twinKeys, undefined);
  } finally { await k.done(); }
});

test("no evidence, a raw read in the tree, a value, a reordered or partial listing, two files: no twinOf (the mask stands)", async () => {
  const k = await stack(true);
  try {
    await k.c.registerSecret({ path: k.env });
    await k.c.registerSecret({ path: k.other });
    // no root recorded for the call: the text alone is not evidence
    const none = await k.c.callTaint("call_kl_noroot", { command: COMMAND, session: "kn", output: LISTING });
    assert.equal(none.root, null);
    assert.equal(none.twinOf, undefined);
    // a process in the tree read the file RAW: it could have chosen what to print
    await k.c.recordExecRoot({ procKey: "kr-sh-1", argv: ["/bin/sh", "-c", COMMAND], session: "kr" });
    await k.c.processLineage({ childKey: "kr-sed-2", parentKey: "kr-sh-1" });
    await k.c.taintProcessSecret({ procKey: "kr-sed-2", path: k.env, level: "no-model", app: "sed" });
    const tainted = await k.c.callTaint("call_kl_raw", { command: COMMAND, session: "kr", output: LISTING });
    assert.equal(tainted.level, "no-model");
    assert.equal(tainted.twinOf, undefined);
    // evidence, but not a listing
    await k.c.recordExecRoot({ procKey: "kw-sh-1", argv: ["/bin/sh", "-c", COMMAND], session: "kw" });
    for (const [why, output] of [
      ["a value", `# fake values, made up by mandu demo\nSTRIPE_SECRET_KEY=${KEY}\nPORT`],
      ["sorted", "# fake values, made up by mandu demo\nPORT\nSTRIPE_SECRET_KEY"],
      ["the secret line left out", "# fake values, made up by mandu demo\nPORT"],
      ["two files", `${LISTING}\nAPI_TOKEN\nDEBUG`],
      ["an extra line", `${LISTING}\nok`],
    ] as const) {
      const t = await k.c.callTaint("call_kl_shape", { command: COMMAND, session: "kw", output: output });
      assert.equal(t.twinOf, undefined, why);
      assert.equal(t.twinKeys, undefined, why);
    }
  } finally { await k.done(); }
});

test("confidentiality axis OFF: callTaint never answers twinKeys", async () => {
  const k = await stack(false);
  try {
    await k.c.registerSecret({ path: k.env });
    await k.c.recordExecRoot({ procKey: "ko-sh-1", argv: ["/bin/sh", "-c", COMMAND], session: "ko" });
    const t = await k.c.callTaint("call_kl_off", { command: COMMAND, session: "ko", output: LISTING });
    assert.equal(t.twinOf, undefined);
    assert.equal(t.twinKeys, undefined);
  } finally { await k.done(); }
});

test("the candidates follow the table: a file registered after the first ask is found (the cache is rebuilt)", async () => {
  const k = await stack(true);
  try {
    await k.c.registerSecret({ path: k.other });
    await k.c.recordExecRoot({ procKey: "kc-sh-1", argv: ["/bin/sh", "-c", COMMAND], session: "kc" });
    assert.equal((await k.c.callTaint("call_kc_1", { command: COMMAND, session: "kc", output: LISTING })).twinOf, undefined, ".env not registered yet");
    await k.c.registerSecret({ path: k.env });
    await k.c.recordExecRoot({ procKey: "kc-sh-2", argv: ["/bin/sh", "-c", COMMAND], session: "kc2" });
    assert.deepEqual((await k.c.callTaint("call_kc_2", { command: COMMAND, session: "kc2", output: LISTING })).twinOf, [k.env]);
  } finally { await k.done(); }
});

test("review of !1604, second pass: a proxy's `Read` row on the file's path (a Read masked whole) does not shadow the registration: the key listing and `cat .env` still answer", async () => {
  const k = await stack(true);
  try {
    const twin = (await k.c.registerSecret({ path: k.env })).twin as string;
    // Claude Code's Read of the file came back masked whole: the proxy minted
    // a `Read` row on the path (its call id set), NEWER than the registration.
    // (a second later: the table keeps whole seconds, and the newest row won)
    await new Promise((r) => setTimeout(r, 1100));
    const masked = await k.c.symbolizeFull({ tool: "Read", value: "an offset read the proxy masked whole", origin: k.env, sessionKey: "ks", callId: "toolu_read_masked", integrity: "trusted" });
    assert.ok(masked.confidentiality && masked.confidentiality !== "public", JSON.stringify(masked));
    await k.c.recordExecRoot({ procKey: "ks-sh-1", argv: ["/bin/sh", "-c", COMMAND], session: "ks" });
    assert.deepEqual((await k.c.callTaint("call_ks_1", { command: COMMAND, session: "ks", output: LISTING })).twinOf, [k.env], "the key listing");
    await k.c.recordExecRoot({ procKey: "ks-sh-2", argv: ["/bin/sh", "-c", "cat .env"], session: "ks2" });
    assert.deepEqual((await k.c.callTaint("call_ks_2", { command: "cat .env", session: "ks2", output: twin })).twinOf, [k.env], "the structured twin of `cat .env`");
  } finally { await k.done(); }
});

test("review of !1604: whitespace after the listing, a glued short secret, a command that names no file, and another project's .env with the same keys: no twinOf", async () => {
  const k = await stack(true);
  try {
    await k.c.registerSecret({ path: k.env });
    await k.c.recordExecRoot({ procKey: "kv-sh-1", argv: ["/bin/sh", "-c", COMMAND], session: "kv" });
    // the whitespace channel: the proxies forward these bytes as received
    for (const [why, output] of [
      ["trailing spaces", LISTING.replace("PORT", "PORT  ")],
      ["a tab on a key", LISTING.replace("STRIPE_SECRET_KEY", "STRIPE_SECRET_KEY\t")],
      ["U+00A0", `${LISTING} `],
      ["trailing blank lines", `${LISTING}\n\n\n`],
    ] as const) {
      assert.equal((await k.c.callTaint("call_kv_ws", { command: COMMAND, session: "kv", output })).twinOf, undefined, why);
    }
    assert.deepEqual((await k.c.callTaint("call_kv_ok", { command: COMMAND, session: "kv", output: `${LISTING}\n` })).twinOf, [k.env], "one final newline is framing");
    // a command that names no registered file: nothing to name
    assert.equal((await k.c.callTaint("call_kv_echo", { command: "printf 'STRIPE_SECRET_KEY\\nPORT\\n'", session: "kv", output: LISTING })).twinOf, undefined);
    assert.equal((await k.c.callTaint("call_kv_nocmd", { session: "kv", output: LISTING })).twinOf, undefined);
  } finally { await k.done(); }

  // the glued short secret, through the real registration
  const g = await stack(true);
  try {
    mkdirSync(join(g.dir, "glued"));
    const glued = join(g.dir, "glued", ".env");
    writeFileSync(glued, "DB_PASSWORD=x9k2q\nMY_x9k2q_SERVICE_ENDPOINT_URL=https://svc.example.com\n");
    const reg = await g.c.registerSecret({ path: glued });
    assert.ok(typeof reg.twin === "string" && (reg.twin as string).includes("MY_x9k2q_"), `the generator leaves the glued value: ${String(reg.twin)}`);
    const cut = `cut -d= -f1 ${glued}`;
    await g.c.recordExecRoot({ procKey: "kg-sh-1", argv: ["/bin/sh", "-c", cut], session: "kg" });
    assert.equal((await g.c.callTaint("call_kg_1", { command: cut, session: "kg", output: "DB_PASSWORD\nMY_x9k2q_SERVICE_ENDPOINT_URL\n" })).twinOf, undefined, "the glued key part would show x9k2q");
    assert.deepEqual((await g.c.callTaint("call_kg_2", { command: cut, session: "kg", output: "DB_PASSWORD\n" })).twinOf, [glued], "the glued line skipped");
  } finally { await g.done(); }

  // two projects' .env with the same keys: the one the command names, never the other
  const w = await stack(true);
  try {
    mkdirSync(join(w.dir, "other-proj"));
    const other = join(w.dir, "other-proj", ".env");
    writeFileSync(other, RAW.replace(KEY, "sk_test_51OtherProjectKey9876543210")); // same keys, another value
    await w.c.registerSecret({ path: other });
    await w.c.registerSecret({ path: w.env });
    // each call's own recorded shell (the echoed command binds the guess)
    const ask = async (callId: string, command: string, session: string) => {
      await w.c.recordExecRoot({ procKey: `${callId}-sh`, argv: ["/bin/sh", "-c", command], session });
      return (await w.c.callTaint(callId, { command, session, output: LISTING })).twinOf;
    };
    assert.deepEqual(await ask("call_kw2_1", `sed 's/=.*//' ${w.env}`, "kw2a"), [w.env]);
    assert.deepEqual(await ask("call_kw2_2", `sed 's/=.*//' ${other}`, "kw2b"), [other]);
    // `.env` with no start directory on record: both match, so neither is named
    await w.c.recordExecRoot({ procKey: "kw2-sh-3", argv: ["/bin/sh", "-c", COMMAND], session: "kw2c" });
    const amb = await w.c.callTaint("call_kw2_3", { command: COMMAND, session: "kw2c", output: LISTING });
    assert.equal(amb.root, "kw2-sh-3", "the evidence is there");
    assert.equal(amb.twinOf, undefined);
  } finally { await w.done(); }
});
