/** leg-work.ts: only results go under a run's output dir. Everything the agent
 * under test touches (workspace, HOME, CLAUDE_CONFIG_DIR, its MANDU_HOME,
 * sockets) lives in a short per-leg work dir outside every Mandu home, so a
 * default output dir (<MANDU_HOME>/runs/eval/<run id>, eval-out.ts) neither
 * puts the agent inside the Mandu home nor pushes a socket past 107 bytes. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MAX_SOCKET_PATH, insideAny, legSocketPaths, legSocketProblem, legWorkBase, manduHomes, openLegWork } from "./leg-work.js";
import { launchSpec } from "./paired-config.js";
import { PAID_MODEL } from "./paired-budget.js";
import { resolveEvalOut } from "../eval-out.js";

const bytes = (p: string): number => Buffer.byteLength(p, "utf8");
const listen = (path: string): Promise<Server> => new Promise((ok, fail) => {
  const s = createServer();
  s.once("error", fail);
  s.listen(path, () => ok(s));
});
const close = (s: Server): Promise<void> => new Promise((ok) => s.close(() => ok()));
/** Every env var of a launch that names a path the agent (or its launcher) uses. */
const AGENT_PATH_VARS = ["HOME", "PWD", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "CLAUDE_CONFIG_DIR",
  "MANDU_HOME", "MANDU_ARBITER_SOCK", "MANDU_RUNTIME_DIR"];

test("the work base is TMPDIR when it is short and outside every Mandu home, else /tmp", () => {
  const env = { MANDU_HOME: "/data/mh" };
  assert.equal(legWorkBase({ ...env, TMPDIR: "/var/tmp" }, "/home/u", 1001), "/var/tmp");
  assert.equal(legWorkBase(env, "/home/u", 1001), "/tmp");
  assert.equal(legWorkBase({ ...env, TMPDIR: "/data/mh/tmp" }, "/home/u", 1001), "/tmp", "inside MANDU_HOME");
  assert.equal(legWorkBase({ ...env, TMPDIR: "/home/u/.mandu/tmp" }, "/home/u", 1001), "/tmp", "inside the default ~/.mandu");
  assert.equal(legWorkBase({ ...env, TMPDIR: "/" + "d".repeat(80) }, "/home/u", 1001), "/tmp", "too deep for the sockets");
  assert.equal(legWorkBase({ ...env, TMPDIR: "/data/mhx" }, "/home/u", 1001), "/data/mhx", "a sibling prefix is not inside");
  assert.deepEqual(manduHomes(env, "/home/u"), ["/data/mh", "/home/u/.mandu"]);
  assert.match(legSocketProblem("/" + "d".repeat(80), 1001)!, /over the 107-byte Unix socket limit/);
  assert.throws(() => legWorkBase({ MANDU_HOME: "/" }, "/", 1001), /inside a Mandu home/);
});

test("a default run dir: no agent-facing path is inside <MANDU_HOME>, results are, and every socket path is valid", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-leg-work-"));
  const base = mkdtempSync(join("/tmp", "mdu-lw-"));
  const servers: Server[] = [];
  try {
    // A long home and the real default: <MANDU_HOME>/runs/eval/<run id>/<leg>.
    const home = join(tmp, "home", "a-fairly-long-user-name-for-this-test");
    const manduHome = join(home, ".mandu");
    const env = { TMPDIR: base, MANDU_HOME: manduHome };
    const out = resolveEvalOut(undefined, "utility", { env, home });
    const legRoot = join(out.dir, "BU-07", "trial-03", "wrapped-default");
    // In place, the old layout would overflow: the socket half of the test is live.
    assert.ok(legSocketPaths(legRoot).some((p) => bytes(p) > MAX_SOCKET_PATH), "fixture must be deep enough to overflow in place");

    const work = openLegWork(legRoot, env, home);
    const { paths } = work;
    assert.equal(paths.root, legRoot);
    assert.ok(insideAny(paths.root, [manduHome]), "results live in the Mandu home");
    assert.equal(statSync(legRoot).mode & 0o777, 0o700);
    assert.ok(paths.work.startsWith(base + "/mdu-e-"));
    assert.equal(statSync(paths.work).mode & 0o777, 0o700);
    for (const p of [paths.work, paths.workspace, paths.home, paths.manduHome, paths.runtime, paths.tmp, paths.sock]) {
      assert.ok(!insideAny(p, [manduHome, join(home, ".mandu")]), `${p} must be outside the Mandu home`);
      assert.ok(!p.startsWith(out.dir), `${p} must be outside the output dir`);
    }
    for (const p of legSocketPaths(paths.work)) assert.ok(bytes(p) <= MAX_SOCKET_PATH, `${p} (${bytes(p)} bytes)`);

    // What each leg actually launches with (both sides; the utility runner
    // holds its own legs to the same rule in utility-config.test.ts).
    const config = { model: PAID_MODEL, inspectionModel: PAID_MODEL, agentBinary: "claude", repoRoot: "/repo", timeoutMs: 1 };
    const endpoints = { model: "https://127.0.0.1:1", inspection: "https://127.0.0.1:2", arbiterSock: paths.sock };
    const specs = (["unwrapped", "wrapped-default"] as const).map((side) => launchSpec(config, side, paths, "task", endpoints, {}));
    for (const spec of specs) {
      for (const key of AGENT_PATH_VARS) {
        const v = spec.env[key];
        if (v === undefined) continue;
        assert.ok(!insideAny(v, [manduHome]), `${key}=${v} must be outside <MANDU_HOME>`);
        assert.ok(v.startsWith(paths.work + "/"), `${key}=${v} must be in the leg's work dir`);
      }
    }
    const wrapped = launchSpec(config, "wrapped-default", paths, "task", endpoints, {});
    assert.equal(wrapped.env.MANDU_HOME, paths.manduHome);
    assert.equal(wrapped.env.CLAUDE_CONFIG_DIR, join(paths.home, ".claude"));

    // The kernel takes the sockets: bind the arbiter's and the deepest launcher one.
    const scopeSock = legSocketPaths(paths.work)[1];
    mkdirSync(join(scopeSock, ".."), { recursive: true });
    servers.push(await listen(paths.sock), await listen(scopeSock));
    writeFileSync(join(scopeSock, "..", "launch.log"), "posture\n");
    writeFileSync(join(paths.workspace, "result.json"), "{}\n");
    mkdirSync(join(paths.home, ".claude", "projects"), { recursive: true });
    writeFileSync(join(paths.home, ".claude", "projects", "t.jsonl"), "transcript\n");
    mkdirSync(paths.manduHome, { mode: 0o700 });
    writeFileSync(join(paths.manduHome, "config.toml"), "");

    // close(): the evidence comes back under the results dir, the sockets do not, the work dir goes.
    assert.deepEqual(work.close(), []);
    const scopeBack = join(legRoot, "runtime", "registry", "9999999999-4194304");
    assert.equal(readFileSync(join(scopeBack, "launch.log"), "utf8"), "posture\n");
    assert.equal(readFileSync(join(legRoot, "workspace", "result.json"), "utf8"), "{}\n");
    assert.equal(readFileSync(join(legRoot, "home", ".claude", "projects", "t.jsonl"), "utf8"), "transcript\n");
    assert.ok(existsSync(join(legRoot, "mandu-home", "config.toml")));
    assert.equal(existsSync(join(scopeBack, "clean.sock")), false);
    assert.equal(existsSync(join(legRoot, "a.sock")), false);
    assert.equal(statSync(join(legRoot, "workspace")).mode & 0o777, 0o700);
    assert.equal(existsSync(paths.work), false);
    assert.deepEqual(work.close(), [], "close is idempotent");
  } finally {
    for (const s of servers) await close(s);
    rmSync(tmp, { recursive: true, force: true });
    rmSync(base, { recursive: true, force: true });
  }
});

test("an unusable TMPDIR falls back to /tmp; MANDU_EVAL_KEEP_WORK=1 keeps the work dir", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-leg-work-"));
  try {
    const env = { MANDU_HOME: join(tmp, "mh") };
    const a = openLegWork(join(tmp, "a"), { ...env, TMPDIR: "/definitely/missing/tmp" }, tmp);
    assert.ok(a.paths.work.startsWith("/tmp/mdu-e-"));
    a.close();
    assert.equal(existsSync(a.paths.work), false);
    const b = openLegWork(join(tmp, "b"), { ...env, MANDU_EVAL_KEEP_WORK: "1" }, tmp);
    b.close();
    assert.ok(existsSync(b.paths.work));
    rmSync(b.paths.work, { recursive: true, force: true });
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});
