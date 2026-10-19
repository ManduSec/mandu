// Unit tests for scripts/set-api-key.mjs: the key lands in the Mandu home's
// secrets.json (mode 0600, other fields kept) where secrets-to-env.mjs finds
// it; a wrong-shaped key, an OAuth token or a vendor-rejected key changes
// nothing; the key is never printed. Run: node --test <this file>.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { writeFileSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { tmpDir } from "./lib/tmp-dir.mjs";
import { mergeKey, masked } from "../set-api-key.mjs";

const SCRIPTS = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(SCRIPTS, "set-api-key.mjs");
const LOADER = join(SCRIPTS, "secrets-to-env.mjs");
const KEY = "sk-ant-api03-" + "A".repeat(40) + "tailXYZ9";
const OPENAI = "sk-proj-" + "B".repeat(40);

// The checkout's own secrets.local.json is read first by the loader; the
// load-through test skips when one exists.
const skipRepoLocal = existsSync(join(SCRIPTS, "..", "secrets.local.json")) ? "the checkout has a secrets.local.json" : false;

/** Run the CLI with `input` on a (non-TTY) stdin; async so an in-process
 *  verify server can answer. */
function run(args, input, env = {}) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [SCRIPT, ...args], { env: { PATH: process.env.PATH, ...env } });
    let stderr = "", stdout = "";
    c.stderr.on("data", (d) => { stderr += d; });
    c.stdout.on("data", (d) => { stdout += d; });
    c.on("close", (status) => resolve({ status, stderr, stdout }));
    c.stdin.end(input);
  });
}

async function vendor(status) {
  const seen = [];
  const s = createServer((req, res) => { seen.push({ url: req.url, key: req.headers["x-api-key"] ?? req.headers.authorization }); res.writeHead(status); res.end("{}"); });
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  return { base: `http://127.0.0.1:${s.address().port}`, seen, close: () => new Promise((r) => s.close(r)) };
}

test("mergeKey sets the field and keeps every other one", () => {
  const r = mergeKey(JSON.stringify({ openai_api_key: OPENAI, env: { A: "1" } }), "anthropic", KEY);
  assert.ok(r.ok);
  assert.deepEqual(JSON.parse(r.text), { openai_api_key: OPENAI, env: { A: "1" }, anthropic_api_key: KEY });
  assert.deepEqual(JSON.parse(mergeKey(null, "openai", OPENAI).text), { openai_api_key: OPENAI });
});

test("mergeKey refuses an OAuth token, an admin key, a wrong shape and a non-JSON file", () => {
  assert.match(mergeKey(null, "anthropic", "sk-ant-oat01-" + "x".repeat(40)).reason, /OAuth/);
  assert.match(mergeKey(null, "anthropic", "sk-ant-admin01-" + "x".repeat(40)).reason, /admin/);
  assert.match(mergeKey(null, "anthropic", "hello").reason, /not an Anthropic API key/);
  assert.match(mergeKey(null, "openai", KEY).reason, /Anthropic key/);
  assert.match(mergeKey("{oops", "anthropic", KEY).reason, /not JSON/);
  assert.match(mergeKey("[1]", "anthropic", KEY).reason, /not a JSON object/);
});

test("masked shows the kind and length only", () => {
  assert.equal(masked(KEY), `sk-… (${KEY.length} chars)`);
});

test("the CLI verifies, then writes the Mandu home's secrets.json 0600, never printing the key", async () => {
  const home = tmpDir("mandu-setkey-");
  writeFileSync(join(home, "secrets.json"), JSON.stringify({ ullm_model: "haiku" }));
  const v = await vendor(200);
  try {
    const r = await run(["anthropic"], KEY + "\n", { HOME: home, MANDU_HOME: home, MANDU_SET_KEY_VERIFY_BASE: v.base });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(v.seen, [{ url: "/v1/models", key: KEY }], "one model-list GET with the key, no inference call");
    const file = join(home, "secrets.json");
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), { ullm_model: "haiku", anthropic_api_key: KEY });
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.match(r.stderr, /check: usable/);
    assert.ok(!r.stderr.includes("XYZ9") && !r.stdout.includes("XYZ9"), "no part of the key's tail is printed");
  } finally { await v.close(); }
});

test("a key the vendor rejects changes nothing", async () => {
  const home = tmpDir("mandu-setkey-");
  const before = JSON.stringify({ anthropic_api_key: "sk-ant-api03-" + "G".repeat(40) });
  writeFileSync(join(home, "secrets.json"), before);
  const v = await vendor(401);
  try {
    const r = await run(["anthropic"], KEY + "\n", { HOME: home, MANDU_HOME: home, MANDU_SET_KEY_VERIFY_BASE: v.base });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /rejected \(HTTP 401\)/);
    assert.equal(readFileSync(join(home, "secrets.json"), "utf8"), before);
  } finally { await v.close(); }
});

test("an unreachable vendor still saves; --no-verify makes no request", async () => {
  const home = tmpDir("mandu-setkey-");
  const r = await run(["openai"], OPENAI + "\n", { HOME: home, MANDU_HOME: home, MANDU_SET_KEY_VERIFY_BASE: "http://127.0.0.1:1" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /not verified/);
  assert.equal(JSON.parse(readFileSync(join(home, "secrets.json"), "utf8")).openai_api_key, OPENAI);
  const home2 = tmpDir("mandu-setkey-");
  const v = await vendor(200);
  try {
    const r2 = await run(["anthropic", "--no-verify"], KEY + "\n", { HOME: home2, MANDU_HOME: home2, MANDU_SET_KEY_VERIFY_BASE: v.base });
    assert.equal(r2.status, 0, r2.stderr);
    assert.equal(v.seen.length, 0);
  } finally { await v.close(); }
});

test("a wrong-shaped key, an empty line or no provider off a terminal is refused", async () => {
  const home = tmpDir("mandu-setkey-");
  const env = { HOME: home, MANDU_HOME: home };
  const bad = await run(["anthropic", "--no-verify"], "sk-ant-oat01-" + "x".repeat(40) + "\n", env);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /OAuth token.*nothing changed/);
  assert.equal((await run(["anthropic", "--no-verify"], "\n", env)).status, 1);
  assert.equal((await run([], KEY + "\n", env)).status, 2, "the provider menu needs a terminal");
  assert.equal((await run(["gemini"], KEY + "\n", env)).status, 2);
  assert.ok(!existsSync(join(home, "secrets.json")));
});

test("secrets-to-env loads the key the script wrote", { skip: skipRepoLocal }, async () => {
  const home = tmpDir("mandu-setkey-");
  const env = { HOME: home, MANDU_HOME: home };
  assert.equal((await run(["anthropic", "--no-verify"], KEY + "\n", env)).status, 0);
  const l = spawnSync(process.execPath, [LOADER], { env: { PATH: process.env.PATH, ...env }, encoding: "utf8" });
  assert.equal(l.status, 0);
  assert.match(l.stdout, /export ANTHROPIC_API_KEY=/);
  assert.ok(l.stdout.includes(KEY));
});
