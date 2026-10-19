/**
 * A CATALOG file the launch did not register (a `.env`, a key), read by a
 * recursive or indirect read (confidentiality.md §6 "Read by a program the
 * launch did not see", 2026-10-17), across the REAL components in `secrets`
 * mode: the launcher's main(), a REAL ArbiterServer, the REAL
 * mandu-net-guard, and the production model proxy (`new ProxyAdapter(new
 * ArbiterClient(sock))`) in front of a mock upstream. The "agent" is
 * /bin/sh; policy.yaml labels nothing.
 *
 * The session CREATES a `.env` deeper than the discovery walk reaches
 * (MAX_DEPTH) and a key file, after the launch (no walk can have registered
 * them), then reads them by `cat`, `grep -r`, `tar` and a python `os.walk`.
 * Before the change the guard gated the registered, derived and labelled
 * files only, so each read printed them raw and the model received them in
 * clear. Now the guard learns the catalog (`labelRootsSince`: its prefixes as
 * roots, its basename shapes as name anchors), asks the arbiter about a
 * candidate (`labelledLevel`, the walk's own rule and prunes) and serves its
 * twin, made from `registerSecret` (which registers the file, so the value
 * backstop knows its values too).
 *
 *   C1 guard only (`--no-secret-bind`): every read of the new files yields
 *      the placeholder; a `.env.example` (no catalog secret by the walk's
 *      rule) and a `.env` inside `node_modules` (never walked) read raw, as
 *      does a plain file; no request to the model holds a secret value.
 *      Source files named like a credential (2026-10-17: `credentials.ts`
 *      at the launch, a `credentials.py` python imports, deeper than the
 *      walk) read raw; the `credentials.json` beside them is gated.
 *   C2 the same with the twin bind (the default posture).
 *
 * Self-SKIPs where the guard is not built (scripts/build-native.sh).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as ProxyAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets");

const PICK = pickGuard(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "interceptors", "target"));
const GUARD = PICK.path;
const skip = process.platform !== "linux" || !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;

/** The values, assembled at run time. */
const DEEP = ["q7Vt", "Rz2m", "CATALOG", "Kp9x", "Lw4c"].join("");
const KEY = ["kEy", "CATALOG", "OPENS", "9d3e", "Zx".repeat(8)].join("-");
/** A credentials.json beside the source file below: data, so still gated. */
const CRED = ["cRed", "CATALOG", "Json", "7e1f", "Yw".repeat(6)].join("-");
/** The text of the source files named like a credential: no secret. */
const SOURCE = ["SOURCE", "CONTROL", "c0de"].join("-");
/** One registered secret, so the launch is a real one's shape. */
const ENV_KEY = ["sk", "proj", "CATALOG", "OPENS", "4410", "Qz".repeat(12)].join("-");

interface Stack { dir: string; home: string; ws: string; sock: string; close: () => Promise<void> }

async function stack(prefix: string): Promise<Stack> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const home = join(dir, "home");
  const ws = join(dir, "ws");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  writeFileSync(join(ws, ".env"), `OPENAI_API_KEY=${ENV_KEY}\n`);
  writeFileSync(join(ws, "readme.md"), "README-CONTROL\n");
  // A source file named like a credential, present at the launch and within
  // the walk's depth (2026-10-17): no catalog shape, so not twinned.
  mkdirSync(join(ws, "src", "auth"), { recursive: true });
  writeFileSync(join(ws, "src", "auth", "credentials.ts"), `export const PROVIDER = "${SOURCE}-launch";\n`);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  return { dir, home, ws, sock, close: async () => { await server.close(); rmSync(dir, { recursive: true, force: true }); } };
}

/** One launch of /bin/sh running `reads` in order; each output and status. */
async function launch(s: Stack, reads: Record<string, string>, flags: string[]): Promise<{ log: string; out: Record<string, { text: string; status: number }> }> {
  const outDir = mkdtempSync(join(s.dir, "out-"));
  const script = [`cd '${s.ws}'`, ...Object.entries(reads).map(([name, cmd]) => `( ${cmd} ) > '${outDir}/${name}' 2>&1; echo $? > '${outDir}/${name}.status'`)].join("\n");
  const lines: string[] = [];
  const orig = console.error;
  const saved = { HOME: process.env["HOME"], MANDU_HOME: process.env["MANDU_HOME"], MANDU_NET_GUARD_BIN: process.env["MANDU_NET_GUARD_BIN"] };
  const cwd = process.cwd();
  let code: number | null = null;
  let err: Error | null = null;
  try {
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["HOME"] = s.home;
    process.env["MANDU_HOME"] = join(s.home, ".mandu");
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.chdir(s.ws);
    try {
      code = await main(
        ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", ...flags, "--", "/bin/sh", "-c", script],
        {
          HOME: s.home, PWD: s.ws, MANDU_ARBITER_SOCK: s.sock, PATH: process.env["PATH"],
          MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(s.home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: s.dir, MANDU_VERBOSE: "1",
        },
      );
    } catch (e) {
      err = e as Error;
    }
  } finally {
    console.error = orig;
    process.chdir(cwd);
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
  const log = lines.join("\n");
  assert.equal(err, null, `${err?.message}\n${log}`);
  assert.equal(code, 0, log);
  const out: Record<string, { text: string; status: number }> = {};
  for (const name of Object.keys(reads)) {
    const f = join(outDir, name);
    assert.ok(existsSync(f), `the confined launch ran ${name}\n${log}`);
    out[name] = { text: readFileSync(f, "utf8"), status: Number(readFileSync(`${f}.status`, "utf8").trim()) };
  }
  return { log, out };
}

/** Every output as a Bash tool result through the production model proxy;
 *  the bodies the upstream (the model) received. */
async function toModel(s: Stack, outputs: Record<string, { text: string }>): Promise<string[]> {
  const real = new ArbiterClient(s.sock);
  await real.connect();
  const up = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ProxyAdapter(real), upstream: up.fetcher, sessionKey: `catalog-${Date.now()}`, log: () => {} });
  const port = await proxy.listen(0);
  try {
    let n = 0;
    for (const [name, o] of Object.entries(outputs)) {
      const id = `tu_${n++}`;
      const body = JSON.stringify({
        model: "claude-opus-4", stream: true,
        messages: [
          { role: "user", content: "Search the project." },
          { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command: name } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: o.text }] },
        ],
      });
      const status = await new Promise<number>((resolve, reject) => {
        const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } },
          (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
        r.on("error", reject);
        r.end(body);
      });
      assert.equal(status, 200);
    }
    return up.requests.map((r) => r.bodyText);
  } finally {
    await proxy.close();
    real.close();
  }
}

const show = (out: Record<string, { text: string; status: number }>): string => Object.entries(out).map(([k, v]) => `--- ${k} (exit ${v.status})\n${v.text}`).join("\n");
const raw = (t: string): boolean => t.includes(DEEP) || t.includes(KEY) || t.includes(ENV_KEY) || t.includes(CRED);

/** The reads: the files are created by the session, then read every way. */
const READS = {
  create: [
    "mkdir -p a/b/c/d/e/f/src/auth/providers node_modules/pkg keys",
    `printf 'VALUE = "%s"\\n' '${SOURCE}-deep' > a/b/c/d/e/f/src/auth/providers/credentials.py`,
    `printf '{"token": "%s"}\\n' '${CRED}' > a/b/c/d/e/f/src/auth/providers/credentials.json`,
    `printf 'DB_PASSWORD=%s\\n' '${DEEP}' > a/b/c/d/e/f/.env`,
    `printf 'token %s\\n' '${KEY}' > keys/deploy.key`,
    "printf 'DB_PASSWORD=SAMPLE-CONTROL\\n' > .env.example",
    "printf 'FIXTURE=DEP-CONTROL\\n' > node_modules/pkg/.env",
    "echo created",
  ].join(" && "),
  cat: "cat a/b/c/d/e/f/.env keys/deploy.key",
  grepR: "grep -r DB_PASSWORD a",
  grepAll: "grep -r '' a keys",
  tar: "tar cf - a keys | tar xOf -",
  walk: `python3 -c "import os
for d,_,fs in os.walk('.'):
  for f in fs:
    p=os.path.join(d,f)
    try: print(p, open(p, errors='replace').read())
    except OSError as e: print(p, e)"`,
  example: "cat .env.example",
  // A program loads the source files named like a credential: raw.
  srcLaunch: "cat src/auth/credentials.ts",
  srcImport: `python3 -c "import sys; sys.path.insert(0, 'a/b/c/d/e/f/src/auth/providers'); import credentials; print(credentials.VALUE)"`,
  credJson: "cat a/b/c/d/e/f/src/auth/providers/credentials.json",
  dep: "cat node_modules/pkg/.env",
  control: "cat readme.md",
};

async function check(prefix: string, flags: string[]): Promise<void> {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack(prefix);
  try {
    const run = await launch(s, READS, flags);
    const all = show(run.out);
    assert.equal(run.out.create!.text.trim(), "created", all);
    assert.ok(readFileSync(join(s.ws, "a", "b", "c", "d", "e", "f", ".env"), "utf8").includes(DEEP), "host truth: the file holds the value");
    for (const [name, o] of Object.entries(run.out)) assert.ok(!raw(o.text), `${name}: no raw byte of a catalog file\n${all}`);
    assert.equal((run.out.cat!.text.match(/\$MDU:/g) ?? []).length >= 2, true, `cat: both placeholders\n${all}`);
    // A .env's twin keeps its names (a structured twin): the search finds
    // the line, with the placeholder for its value.
    assert.match(run.out.grepR!.text, /a\/b\/c\/d\/e\/f\/\.env:DB_PASSWORD='?\$MDU:/, `grep -r: the placeholder's line\n${all}`);
    assert.match(run.out.grepAll!.text, /keys\/deploy\.key:\$MDU:/, `grep -r '': the key's placeholder\n${all}`);
    assert.match(run.out.walk!.text, /\.env DB_PASSWORD='?\$MDU:/, `os.walk: the placeholder\n${all}`);
    assert.equal(run.out.example!.text, "DB_PASSWORD=SAMPLE-CONTROL\n", `a template is no catalog secret: raw\n${all}`);
    assert.equal(run.out.dep!.text, "FIXTURE=DEP-CONTROL\n", `a .env in node_modules reads raw\n${all}`);
    assert.match(run.out.walk!.text, /SAMPLE-CONTROL/, `os.walk reads the template raw\n${all}`);
    assert.equal(run.out.control!.text, "README-CONTROL\n", `a plain file reads raw\n${all}`);
    assert.equal(run.out.srcLaunch!.text, `export const PROVIDER = "${SOURCE}-launch";\n`, `a source file named like a credential, walked at the launch, reads raw\n${all}`);
    assert.equal(run.out.srcImport!.text, `${SOURCE}-deep\n`, `python imports a source file named like a credential, deeper than the walk, raw\n${all}`);
    assert.match(run.out.credJson!.text, /\$MDU:/, `its credentials.json sibling is gated\n${all}`);
    for (const b of await toModel(s, run.out)) assert.ok(!raw(b), "no request to the model holds a catalog file's value");
  } finally {
    await s.close();
  }
}

test("C1 (guard only): a .env deeper than the walk and a key file, created mid-session, read as their placeholders through cat, grep -r, tar and os.walk; a template, a node_modules .env and a plain file read raw", { skip, timeout: 300_000 }, async () => {
  await check("mandu-catalog-guard-", ["--no-secret-bind"]);
});

test("C2 (with the twin bind): the same", { skip, timeout: 300_000 }, async () => {
  await check("mandu-catalog-bind-", []);
});
