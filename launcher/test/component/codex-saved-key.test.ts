/**
 * codex-saved-key.test — Codex's saved key (`auth.json` in API-key mode, the
 * `codex login --with-api-key` file) twinned, and the key put back at the
 * openai-proxy (agent-sign-in.md §3.9), through the REAL launcher (`main()`),
 * a real arbiter daemon and the autostarted openai-proxy, against a scripted
 * Responses upstream on loopback that records each request's
 * `authorization`. Made-up keys only; no network; no model. No guard
 * (MANDU_NO_KERNEL=1: the twin bind alone).
 *
 *   stand-in   a node script NAMED `codex` with Codex's wire: it reads its
 *              `auth.json` from the agent's world, sends that key as
 *              `Bearer` to the provider base URL the launcher spliced in, and
 *              puts what it read in its prompt. The agent's world holds the
 *              twin; the upstream receives the REAL key; no body carries it;
 *   opt-out    MANDU_AUTH_SUBSTITUTION=0: `auth.json` stays Codex's raw login;
 *   ChatGPT    an `auth.json` with ChatGPT tokens: never granted, never
 *              twinned (Codex refreshes it itself, §3.6);
 *   REAL codex `codex exec` (self-skipped without the binary) authenticating
 *              with the placeholder it reads.
 */
import { test, before, after } from "node:test";
import "../lib/private-home.js"; // the Mandu home, npm cache and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { main } from "../lib/launch-in-dir.js";
import { sourceArbiterArgs, waitForPaths } from "../lib/arbiter-ready.js";
import { stopGroup } from "../lib/tmp-dir.js";
import { openaiTextSse } from "../../src/demo/stand-in-model.js";
import { probeUserns } from "../../src/userns.js";
import { systemBwrapBin } from "../../src/bwrap-path.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the shipped default: the file is twinned only with confidentiality on

const HERE = dirname(fileURLToPath(import.meta.url));
const ARBITER_DIR = resolve(HERE, "..", "..", "..", "arbiter");
/** A made-up OpenAI-shaped key, never a real one. */
const FAKE_KEY = "sk-proj-MANDUFAKEcodexSAVEDkey0123456789abcdefABCDEF";
const SKIP = process.platform !== "linux" ? "Linux only (macOS read-blocks a confined file)" : false;
// These two cases deliberately disable the kernel guard and prove the mount
// binding itself. The other cases (including env keys) need no namespace.
const BIND_SKIP = SKIP || (systemBwrapBin() === null || !probeUserns()
  ? "saved-file twin bind requires bubblewrap and working unprivileged user namespaces" : false);

interface Seen { path: string; auth: string | undefined; body: string }

let tmp: string;
let sock: string;
let arbiter: ChildProcess;
let upstream: Server;
let origin: string;
const seen: Seen[] = [];

before(async () => {
  if (SKIP) return;
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-codex-key-")));
  sock = join(tmp, "arbiter.sock");
  const logFd = openSync(join(tmp, "arbiter.log"), "a");
  arbiter = spawn(process.execPath, sourceArbiterArgs(sock), {
    cwd: ARBITER_DIR,
    env: { ...process.env, MANDU_ARBITER_SOCK: sock, MANDU_HOME: join(tmp, "mandu-home"), MANDU_RUNTIME_DIR: join(tmp, "mandu") },
    stdio: ["ignore", logFd, logFd], detached: true,
  });
  closeSync(logFd);
  await waitForPaths(sock, { what: "the arbiter", child: arbiter, logPath: join(tmp, "arbiter.log") });
  upstream = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const a = req.headers["authorization"];
      seen.push({ path: req.url ?? "", auth: Array.isArray(a) ? a[0] : a, body: b });
      if (req.method === "GET") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ models: [] }));
        return;
      }
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(openaiTextSse("MANDU_CODEX_DONE"));
    });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  // Plain HTTP to a literal loopback address: the openai-proxy's stand-in rule.
  origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(async () => {
  if (SKIP) return;
  upstream?.close();
  await stopGroup(arbiter);
  rmSync(tmp, { recursive: true, force: true });
});

/** A home whose `~/.codex/auth.json` holds `auth`. */
function codexHome(name: string, auth: Record<string, unknown>): { home: string; file: string } {
  const home = join(tmp, name);
  mkdirSync(join(home, ".codex"), { recursive: true });
  mkdirSync(join(home, "work"), { recursive: true });
  const file = join(home, ".codex", "auth.json");
  writeFileSync(file, JSON.stringify(auth, null, 2), { mode: 0o600 });
  return { home, file };
}

/** The stand-in agent: a node script named `codex`, Codex's wire. */
function standInCodex(name: string, out: string): string {
  const dir = join(tmp, `${name}-bin`);
  mkdirSync(dir, { recursive: true });
  const p = join(dir, "codex");
  writeFileSync(p, `#!${process.execPath}
const fs = require("node:fs");
const argv = process.argv.slice(2);
const kv = argv.find((a) => a.startsWith("model_providers.")) || "";
const base = (/base_url="([^"]+)"/.exec(kv) || [])[1];
const home = process.env.CODEX_HOME || (process.env.HOME + "/.codex");
let auth = "";
try { auth = fs.readFileSync(home + "/auth.json", "utf8"); } catch (e) { auth = "unreadable: " + e.message; }
let key = "";
try { key = JSON.parse(auth).OPENAI_API_KEY || ""; } catch {}
(async () => {
  const r = await fetch(base.replace(/\\/+$/, "") + "/responses", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + key },
    body: JSON.stringify({ model: "gpt-5.4", stream: true, input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "my auth.json: " + auth }] }] }),
  });
  await r.text();
  fs.writeFileSync(${JSON.stringify(out)}, JSON.stringify({ auth, status: r.status }));
})().catch((e) => { fs.writeFileSync(${JSON.stringify(out)}, JSON.stringify({ error: String(e) })); process.exit(1); });
`, { mode: 0o755 });
  return p;
}

async function launch(home: string, argv: string[], extraEnv: Record<string, string> = {}): Promise<{ code: number; lines: string[] }> {
  const lines: string[] = [];
  const orig = console.error;
  const savedHome = process.env["HOME"];
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  process.env["HOME"] = home;
  process.env["MANDU_UPSTREAM"] = origin;
  try {
    const code = await main(
      ["--target", "codex", "--no-scope", "--no-mcp", "--", ...argv],
      {
        HOME: home, PATH: process.env["PATH"], PWD: join(home, "work"),
        MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: tmp,
        MANDU_ARBITER_SOCK: sock, MANDU_OPENAI_PROXY_PORT: "0", MANDU_MODE: "secrets", MANDU_VERBOSE: "1",
        MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_FS_SYNC: "0", MANDU_NO_KERNEL: "1",
        ...extraEnv,
      },
    );
    return { code, lines };
  } finally {
    console.error = orig;
    delete process.env["MANDU_UPSTREAM"];
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
  }
}

test("stand-in codex: the agent's world reads the twin, the upstream gets the real key as Bearer, no body carries it", { skip: BIND_SKIP, timeout: 300_000 }, async () => {
  const { home, file } = codexHome("h-key", { OPENAI_API_KEY: FAKE_KEY, tokens: null, last_refresh: null });
  const out = join(tmp, "key-out.json");
  seen.length = 0;
  const { code, lines } = await launch(home, [standInCodex("key", out), "exec", "--skip-git-repo-check", "say hi"]);
  const got = JSON.parse(readFileSync(out, "utf8")) as { auth?: string; status?: number; error?: string };
  assert.equal(code, 0, `${JSON.stringify(got)}\n${lines.join("\n")}`);
  assert.equal(got.status, 200, JSON.stringify(got));
  assert.ok(got.auth && !got.auth.includes(FAKE_KEY), `the agent's world holds no key: ${got.auth}`);
  assert.match(got.auth!, /"OPENAI_API_KEY": "\$MDU:nomodel_Read\[[0-9a-f]+\]\.OPENAI_API_KEY"/, "the twin's placeholder");
  const turns = seen.filter((q) => /\/responses/.test(q.path));
  assert.ok(turns.length >= 1, `the turn reached the upstream: ${seen.map((q) => q.path).join(", ")}`);
  for (const q of turns) assert.equal(q.auth, `Bearer ${FAKE_KEY}`, "the REAL key, put back by the openai-proxy");
  for (const q of seen) assert.ok(!q.body.includes(FAKE_KEY) && !q.body.includes("MANDUFAKEcodexSAVED"), "INVARIANT: no request body carries the key");
  assert.equal(JSON.parse(readFileSync(file, "utf8")).OPENAI_API_KEY, FAKE_KEY, "the human's file is untouched");
  assert.ok(lines.some((l) => l.includes(file) && /placeholder in Codex's world/.test(l)), lines.join("\n"));
});

test("opt-out (MANDU_AUTH_SUBSTITUTION=0): auth.json stays Codex's raw login, and the key reaches the upstream", { skip: SKIP, timeout: 300_000 }, async () => {
  const { home } = codexHome("h-opt", { OPENAI_API_KEY: FAKE_KEY, tokens: null });
  const out = join(tmp, "opt-out.json");
  seen.length = 0;
  const { code, lines } = await launch(home, [standInCodex("opt", out), "exec", "--skip-git-repo-check", "say hi"], { MANDU_AUTH_SUBSTITUTION: "0" });
  const got = JSON.parse(readFileSync(out, "utf8")) as { auth?: string; status?: number };
  assert.equal(code, 0, lines.join("\n"));
  assert.ok(got.auth?.includes(FAKE_KEY), "raw, as before");
  assert.ok(seen.some((q) => q.auth === `Bearer ${FAKE_KEY}`));
  assert.ok(!lines.some((l) => /placeholder in Codex's world/.test(l)));
});

test("a ChatGPT sign-in in auth.json is never granted nor twinned (Codex refreshes it itself)", { skip: SKIP, timeout: 300_000 }, async () => {
  const tokens = { id_token: "eyJ.dummy.id", access_token: "eyJ.dummy.access", refresh_token: "rt-dummy", account_id: "acct-dummy" };
  const { home } = codexHome("h-chatgpt", { OPENAI_API_KEY: null, tokens, last_refresh: "2026-10-01T00:00:00Z" });
  const out = join(tmp, "chatgpt-out.json");
  seen.length = 0;
  const { lines } = await launch(home, [standInCodex("chatgpt", out), "exec", "--skip-git-repo-check", "say hi"]);
  const got = JSON.parse(readFileSync(out, "utf8")) as { auth?: string };
  assert.ok(got.auth?.includes("rt-dummy"), "Codex's own sign-in stays raw for it");
  assert.ok(!lines.some((l) => /placeholder in Codex's world/.test(l)));
});

/** The codex binary (MANDU_CODEX_BIN, else PATH), or null. */
function findCodex(): string | null {
  const pinned = process.env["MANDU_CODEX_BIN"];
  if (pinned) return existsSync(pinned) ? pinned : null;
  for (const d of (process.env["PATH"] ?? "").split(delimiter)) {
    if (d && existsSync(join(d, "codex"))) return join(d, "codex");
  }
  return null;
}
const CODEX = findCodex();

test("the REAL codex exec: it sends the placeholder it reads, the upstream gets the real key as Bearer, no request body carries it", { skip: BIND_SKIP || (CODEX === null ? "no codex binary: set MANDU_CODEX_BIN or put codex on PATH" : false), timeout: 300_000 }, async () => {
  const { home, file } = codexHome("h-real", { OPENAI_API_KEY: FAKE_KEY, tokens: null, last_refresh: null });
  // `codex exec` reads more input from a stdin that is not a terminal; a
  // wrapper NAMED codex (so the launcher routes it as Codex) closes it.
  const bin = join(tmp, "real-bin");
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, "codex"), `#!/bin/sh\nexec ${JSON.stringify(CODEX!)} "$@" </dev/null\n`, { mode: 0o755 });
  seen.length = 0;
  const { code, lines } = await launch(home, [join(bin, "codex"), "exec", "--skip-git-repo-check", "say hi"]);
  assert.equal(code, 0, lines.join("\n"));
  const turns = seen.filter((q) => /\/responses/.test(q.path));
  assert.ok(turns.length >= 1, `codex's turns reached the upstream: ${seen.map((q) => q.path).join(", ")}\n${lines.join("\n")}`);
  for (const q of turns) assert.equal(q.auth, `Bearer ${FAKE_KEY}`, `the REAL key, put back by the openai-proxy (${q.auth?.slice(0, 20)}…)`);
  for (const q of seen) assert.ok(!q.body.includes(FAKE_KEY) && !q.body.includes("MANDUFAKEcodexSAVED"), "INVARIANT: no request body carries the key");
  assert.equal(JSON.parse(readFileSync(file, "utf8")).OPENAI_API_KEY, FAKE_KEY, "the human's file is untouched");
  assert.ok(lines.some((l) => /placeholder in Codex's world/.test(l)), lines.join("\n"));
});

// ── Codex's key variables (§3.11) ────────────────────────────────────────────

/** A stand-in `codex` on a key variable: it sends `$OPENAI_API_KEY` as Bearer
 *  (the provider's env_key) and reports what its environment held. */
function standInKeyCodex(name: string, out: string): string {
  const dir = join(tmp, `${name}-bin`);
  mkdirSync(dir, { recursive: true });
  const p = join(dir, "codex");
  writeFileSync(p, `#!${process.execPath}
const fs = require("node:fs");
const argv = process.argv.slice(2);
const kv = argv.find((a) => a.startsWith("model_providers.")) || "";
const base = (/base_url="([^"]+)"/.exec(kv) || [])[1];
const envKey = (/env_key="([^"]+)"/.exec(kv) || [])[1] || "";
const key = process.env[envKey] || "";
(async () => {
  const r = await fetch(base.replace(/\\/+$/, "") + "/responses", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + key },
    body: JSON.stringify({ model: "gpt-5.4", stream: true, input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "my key: " + key }] }] }),
  });
  await r.text();
  fs.writeFileSync(${JSON.stringify(out)}, JSON.stringify({ envKey, key, codexKey: process.env.CODEX_API_KEY || null, status: r.status }));
})().catch((e) => { fs.writeFileSync(${JSON.stringify(out)}, JSON.stringify({ error: String(e) })); process.exit(1); });
`, { mode: 0o755 });
  return p;
}

test("key variables (§3.11): OPENAI_API_KEY and CODEX_API_KEY are placeholders in Codex's environment; the upstream gets the real key as Bearer", { skip: SKIP, timeout: 300_000 }, async () => {
  const home = join(tmp, "h-env");
  mkdirSync(join(home, "work"), { recursive: true });
  const out = join(tmp, "env-out.json");
  seen.length = 0;
  const { code, lines } = await launch(home, [standInKeyCodex("env", out), "exec", "--skip-git-repo-check", "say hi"], { OPENAI_API_KEY: FAKE_KEY, CODEX_API_KEY: `${FAKE_KEY}-2` });
  const got = JSON.parse(readFileSync(out, "utf8")) as { envKey?: string; key?: string; codexKey?: string; status?: number; error?: string };
  assert.equal(code, 0, `${JSON.stringify(got)}\n${lines.join("\n")}`);
  assert.equal(got.envKey, "OPENAI_API_KEY");
  assert.match(got.key ?? "", /^\$MDU:nomodel_Env\[[0-9a-f]+\]\.OPENAI_API_KEY$/, "the agent's environment holds the placeholder");
  assert.match(got.codexKey ?? "", /^\$MDU:nomodel_Env\[[0-9a-f]+\]\.CODEX_API_KEY$/);
  assert.equal(got.status, 200);
  const turns = seen.filter((q) => /\/responses/.test(q.path));
  assert.ok(turns.length >= 1);
  for (const q of turns) assert.equal(q.auth, `Bearer ${FAKE_KEY}`, "the REAL key, put back by the openai-proxy");
  for (const q of seen) assert.ok(!q.body.includes("MANDUFAKEcodexSAVED"), "INVARIANT: no request body carries the key");
  assert.ok(lines.some((l) => /OPENAI_API_KEY is a placeholder in Codex's environment/.test(l)), lines.join("\n"));
});

test("the REAL codex exec on OPENAI_API_KEY: it sends the placeholder from its environment, the upstream gets the real key", { skip: SKIP || (CODEX === null ? "no codex binary: set MANDU_CODEX_BIN or put codex on PATH" : false), timeout: 300_000 }, async () => {
  const home = join(tmp, "h-real-env");
  mkdirSync(join(home, ".codex"), { recursive: true });
  mkdirSync(join(home, "work"), { recursive: true });
  const bin = join(tmp, "real-env-bin");
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, "codex"), `#!/bin/sh\nexec ${JSON.stringify(CODEX!)} "$@" </dev/null\n`, { mode: 0o755 });
  seen.length = 0;
  const { code, lines } = await launch(home, [join(bin, "codex"), "exec", "--skip-git-repo-check", "say hi"], { OPENAI_API_KEY: FAKE_KEY });
  assert.equal(code, 0, lines.join("\n"));
  const turns = seen.filter((q) => /\/responses/.test(q.path));
  assert.ok(turns.length >= 1, `codex's turns reached the upstream: ${seen.map((q) => q.path).join(", ")}\n${lines.join("\n")}`);
  for (const q of turns) assert.equal(q.auth, `Bearer ${FAKE_KEY}`, `the REAL key, put back by the openai-proxy (${q.auth?.slice(0, 20)}…)`);
  for (const q of seen) assert.ok(!q.body.includes("MANDUFAKEcodexSAVED"), "INVARIANT: no request body carries the key");
});
