/**
 * A labelled file the launch did not register, read by a recursive or
 * indirect read (confidentiality.md §6 "Read by a program the launch did not
 * see", 2026-10-17), across the REAL components in `secrets` mode: the
 * launcher's main(), a REAL ArbiterServer, the REAL mandu-net-guard, and the
 * production model proxy (`new ProxyAdapter(new ArbiterClient(sock))`) in
 * front of a mock upstream. The "agent" is /bin/sh; policy.yaml labels the
 * workspace's `vault/` `no-model`.
 *
 * The file is CREATED during the session under the labelled folder (no
 * launch walk can have registered it), then read by `cat`, `grep -r`, `tar`
 * and a python `os.walk`. Before the change the guard knew only the launch's
 * registered list and the derived labels, so each of them printed the file
 * raw and the model received it in clear. Now the guard learns where the
 * labels lie (`labelRootsSince`), asks the arbiter about a file under one
 * (`labelledLevel`), and serves its twin, made from `registerSecret` (which
 * registers the file, so the value backstop knows its values too).
 *
 *   L1 guard only (`--no-secret-bind`): every read yields the placeholder, a
 *      file outside the label reads raw, and no request to the model holds
 *      the file's text. Then programs write the file (2026-10-17): an append
 *      (`echo >>`) and an in-place write (python "r+") land in the
 *      placeholder copy, `sed -i`'s rename over it is refused, the real file
 *      keeps its bytes, and the session's end names the file in the same
 *      notice a registered file's write gets (and its `session_exit` event
 *      lists it). Before that change the append reached the real file, and a
 *      write that did land in the copy was dropped with no word.
 *   L2 the same with the twin bind (the default posture).
 *
 * Self-SKIPs where the guard is not built (scripts/build-native.sh).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
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

/** The plan's text, assembled at run time. */
const PLAN = ["PLAN", "LABELLED", "OPEN", "MID", "SESSION", "73c1"].join("-");
/** One registered secret, so the launch is a real one's shape. */
const ENV_KEY = ["sk", "proj", "LABELLED", "OPENS", "4410", "Qz".repeat(12)].join("-");

interface Stack { dir: string; home: string; ws: string; sock: string; close: () => Promise<void> }

async function stack(prefix: string): Promise<Stack> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const home = join(dir, "home");
  const ws = join(dir, "ws");
  mkdirSync(home, { recursive: true });
  mkdirSync(join(ws, "vault"), { recursive: true });
  writeFileSync(join(ws, ".env"), `OPENAI_API_KEY=${ENV_KEY}\n`);
  writeFileSync(join(ws, "readme.md"), "README-CONTROL\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(ws, "vault")}\n    level: no-model\n`);
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
  const proxy = new AnthropicProxy({ arbiter: new ProxyAdapter(real), upstream: up.fetcher, sessionKey: `labelled-${Date.now()}`, log: () => {} });
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
const raw = (t: string): boolean => t.includes(PLAN) || t.includes(ENV_KEY);

/** The reads: the file is created by the session, then read every way. */
const READS = {
  // The pause: the guard's first look then lies past the timestamp slack
  // (twin-writes.ts REAL_TIME_SLACK_NS), so the notice may say the real
  // file is unchanged rather than that Mandu could not check.
  create: `mkdir -p vault/sub && printf 'password: %s\\n' '${PLAN}' > vault/sub/new.md && sleep 2.5 && echo created`,
  cat: "cat vault/sub/new.md",
  grepR: "grep -r password .",
  grepAll: "grep -r '' vault",
  tar: "tar cf - vault | tar xOf -",
  walk: `python3 -c "import os
for d,_,fs in os.walk('.'):
  for f in fs:
    p=os.path.join(d,f)
    try: print(p, open(p, errors='replace').read())
    except OSError as e: print(p, e)"`,
  control: "cat readme.md",
};

/** Then programs write it (2026-10-17): each lands in the placeholder copy. */
const APPENDED = ["APPENDED", "IN", "SESSION", "5d2e"].join("-");
const WRITES = {
  append: `echo '${APPENDED}' >> vault/sub/new.md && echo appended`,
  inplace: `python3 -c "f=open('vault/sub/new.md','r+'); f.write('X'); f.close(); print('inplace')"`,
  sedI: "sed -i 's/MDU/EDITED/' vault/sub/new.md; echo sed=$?",
  after: "cat vault/sub/new.md",
};

/** The notice line naming `path`, worded as for a registered file. */
const noticeOf = (path: string): RegExp => new RegExp(`^mandu: during this session the agent changed ${path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}; Mandu kept the change in its placeholder copy and discarded it, and the real file is unchanged\\. Apply the change yourself if you want it\\.$`, "m");

/** The `session_exit` events the arbiter recorded. */
function sessionExits(dir: string): Array<Record<string, unknown>> {
  const events = join(dir, "events");
  if (!existsSync(events)) return [];
  const out: Array<Record<string, unknown>> = [];
  for (const f of readdirSync(events, { recursive: true }) as string[]) {
    if (!f.endsWith(".ndjson")) continue;
    for (const l of readFileSync(join(events, f), "utf8").split("\n")) if (l.includes('"session_exit"')) out.push(JSON.parse(l) as Record<string, unknown>);
  }
  return out;
}

async function check(prefix: string, flags: string[]): Promise<void> {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack(prefix);
  try {
    const run = await launch(s, { ...READS, ...WRITES }, flags);
    const all = show(run.out);
    assert.equal(run.out.create!.text.trim(), "created", all);
    assert.ok(readFileSync(join(s.ws, "vault", "sub", "new.md"), "utf8").includes(PLAN), "host truth: the file holds the plan");
    for (const [name, o] of Object.entries(run.out)) assert.ok(!raw(o.text), `${name}: no raw byte of the labelled file or the key\n${all}`);
    assert.match(run.out.cat!.text, /\$MDU:/, `cat: the placeholder\n${all}`);
    // The placeholder holds no "password": the repro's search finds nothing
    // there; a search for every line shows the placeholder's.
    assert.ok(!/vault\/sub\/new\.md/.test(run.out.grepR!.text), `grep -r password: no hit in the labelled file\n${all}`);
    assert.match(run.out.grepAll!.text, /vault\/sub\/new\.md:\$MDU:/, `grep -r '': the placeholder's line\n${all}`);
    assert.match(run.out.walk!.text, /new\.md \$MDU:/, `os.walk: the placeholder\n${all}`);
    assert.equal(run.out.control!.text, "README-CONTROL\n", `a file outside the label reads raw\n${all}`);
    for (const b of await toModel(s, run.out)) assert.ok(!raw(b), "no request to the model holds the labelled file's text");
    // The writes: in the copy, never in the real file, and named at the end.
    const file = join(realpathSync(s.ws), "vault", "sub", "new.md");
    assert.equal(run.out.append!.text.trim(), "appended", all);
    assert.equal(run.out.inplace!.text.trim(), "inplace", all);
    assert.match(run.out.sedI!.text, /sed=[1-9]/, `sed -i: its rename over the labelled file is refused\n${all}`);
    assert.ok(run.out.after!.text.includes(APPENDED), `the append reads back from the copy\n${all}`);
    assert.equal(readFileSync(file, "utf8"), `password: ${PLAN}\n`, `host truth: the real file keeps its bytes\n${all}`);
    assert.match(run.log, noticeOf(file), `the session's end names the file\n${run.log.slice(-4000)}`);
    for (const l of run.log.split("\n").filter((x) => x.startsWith("mandu: during this session"))) {
      for (const v of [PLAN, ENV_KEY, APPENDED, "$MDU:"]) assert.ok(!l.includes(v), `a notice carries ${v}: ${l}`);
    }
    const exits = sessionExits(s.dir);
    assert.equal(exits.length, 1, JSON.stringify(exits));
    assert.ok(((exits[0]!["discardedWrites"] as string[] | undefined) ?? []).includes(file), `the session_exit event lists it: ${JSON.stringify(exits[0])}`);
  } finally {
    await s.close();
  }
}

test("L1 (guard only): a file created mid-session under a labelled folder reads as its placeholder through cat, grep -r, tar and os.walk; a file outside reads raw", { skip, timeout: 300_000 }, async () => {
  await check("mandu-labelled-guard-", ["--no-secret-bind"]);
});

test("L2 (with the twin bind): the same", { skip, timeout: 300_000 }, async () => {
  await check("mandu-labelled-bind-", []);
});
