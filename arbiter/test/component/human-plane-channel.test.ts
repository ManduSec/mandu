/**
 * human-plane-channel.test — the arbiter's human-plane socket, live
 * (docs/design/architecture/arbiter-human-plane.md; Mandu-new, no reference origin).
 *
 * A REAL ArbiterServer serving both the data socket and the human socket, and
 * the REAL daemon entrypoint (server-main) binding
 * `${runtime}/human/<instanceId>.sock`:
 *   - over the data socket the original-returning ops are refused (subscribe
 *     included, at the connection layer); over the human socket they return
 *     the original;
 *   - `hello` names the human socket for discovery;
 *   - the human dir is 0700 and ours — a wider or symlinked dir refuses the
 *     start (fail closed);
 *   - close() / SIGTERM unlink the human socket; the manifest records it and
 *     resolveArbiterHumanSock finds the promoted instance's.
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import {
  CURRENT_LINK, INSTANCES_DIR, humanSockPath, readManifest, resolveArbiterHumanSock,
} from "../../ipc/instance.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");
const SECRET = "sk-live-HUMAN-PLANE-E2E-7f3a9c";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function waitFor(pred: () => boolean | Promise<boolean>, what: string, ms = 90_000): Promise<void> {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (await pred()) return;
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${what}`);
}

function rig(dir: string): ArbiterServer {
  return new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "symbols.db"),
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
  });
}

test("data refuses the original-returning ops; the human socket answers them with the original", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-hp-e2e-"));
  const server = rig(dir);
  await server.listen();
  const data = new ArbiterClient(join(dir, "arbiter.sock"));
  const human = new ArbiterClient(join(dir, "human", "h.sock"));
  try {
    // The interceptor side: symbolize a secret and emit an event carrying it
    // (the DualRepr.original of a reply-filter / proxy event), over DATA.
    const r = await data.symbolizeFull({ tool: "Read", field: "content", value: SECRET, origin: "/h/.env", confidentiality: "no-model" });
    const sym = r.symbol;
    assert.equal(r.confidentiality, "no-model");
    await data.emit({ sessionId: "s-hp", id: "e1", output: { symbolized: sym, original: SECRET } } as never);

    // The agent world holds only the data socket: every original-returning op refused.
    await assert.rejects(() => data.desymbolize(`k=${sym}`), /human-plane: 'desymbolize'/);
    await assert.rejects(() => data.resolve(sym), /human-plane: 'resolve'/);
    await assert.rejects(() => data.events("s-hp"), /human-plane: 'events'/);
    await assert.rejects(() => data.sessions(), /human-plane: 'sessions'/);
    await assert.rejects(() => data.verifyEvents("s-hp"), /human-plane: 'verifyEvents'/);
    const subRefusal = await new Promise<string>((resolve) => {
      data.subscribe("s-hp", 0, () => resolve("EVENT DELIVERED"), (e) => resolve(e.message)).catch((e: Error) => resolve(e.message));
    });
    assert.match(subRefusal, /human-plane: 'subscribe'/);
    // Deep resolve stays on data, and the level gate refuses the no-model row.
    assert.equal(await data.resolve(sym, { deep: true }), null);

    // The human plane: originals for the human-facing consumers.
    assert.equal(await human.desymbolize(`k=${sym}`), `k=${SECRET}`);
    assert.equal(await human.resolve(sym), SECRET);
    const events = await human.events("s-hp");
    assert.equal(events.length, 1);
    assert.equal((events[0] as unknown as { output: { original: string } }).output.original, SECRET);
    assert.deepEqual((await human.sessions()).map((s) => s.sessionId), ["s-hp"]);
    assert.equal((await human.verifyEvents("s-hp")).ok, true);
    const got: unknown[] = [];
    const handle = await human.subscribe("s-hp", 0, (e) => got.push(e.id));
    await waitFor(() => got.length === 1, "the human-plane backlog", 5000);
    handle.close();

    // Discovery, and the directory the boundary is anchored on.
    assert.equal((await data.hello()).humanSock, join(dir, "human", "h.sock"));
    assert.equal(statSync(join(dir, "human")).mode & 0o777, 0o700, "human dir is 0700");
    assert.equal(statSync(join(dir, "human")).uid, process.getuid!(), "human dir is ours");
  } finally {
    data.close();
    human.close();
    await server.close();
  }
  assert.ok(!existsSync(join(dir, "human", "h.sock")), "close() unlinks the human socket");
  rmSync(dir, { recursive: true, force: true });
});

test("a human dir that is group/other-accessible or a symlink refuses the start (fail closed)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-hp-e2e-perm-"));
  try {
    mkdirSync(join(dir, "human"));
    chmodSync(join(dir, "human"), 0o755);
    const wide = rig(dir);
    await assert.rejects(() => wide.listen(), /mode 755, not 700/);
    await wide.close();
    assert.ok(!existsSync(join(dir, "human", "h.sock")), "nothing was bound in the wide dir");

    rmSync(join(dir, "human"), { recursive: true, force: true });
    mkdirSync(join(dir, "elsewhere"), { mode: 0o700 });
    symlinkSync(join(dir, "elsewhere"), join(dir, "human"));
    const linked = rig(dir);
    await assert.rejects(() => linked.listen(), /not a real directory/);
    await linked.close();
    assert.deepEqual(readdirSync(join(dir, "elsewhere")), [], "nothing was bound through the symlink");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("server-main binds <runtime>/human/<id>.sock, records it in the manifest, and removes it on SIGTERM", async () => {
  // A short prefix: the instance sockets must fit the 103-byte macOS / 107-byte Linux sun_path under a
  // suite's TMPDIR, longer than /tmp (test-organization.md §8.5).
  const root = mkdtempSync(join(tmpdir(), "mdu-"));
  const base = join(root, "mandu");
  const child: ChildProcess = spawn(process.execPath, [
    "--import", "tsx", SERVER_MAIN, "--symbol-db", join(root, "symbols.db"), "--event-dir", join(root, "events"),
  ], {
    cwd: ARBITER_DIR,
    env: {
      ...process.env,
      MANDU_RUNTIME_DIR: base,
      MANDU_HOME: join(root, "home"),
      MANDU_ARBITER_SOCK: "",
      MANDU_ARBITER_HUMAN_SOCK: "",
      MANDU_PROMOTE: "1",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr!.setEncoding("utf8");
  child.stderr!.on("data", (c: string) => { stderr += c; });
  try {
    const currentSock = join(base, CURRENT_LINK, "arbiter.sock");
    await waitFor(() => existsSync(currentSock), `promotion (stderr: ${stderr})`);
    const id = readdirSync(join(base, INSTANCES_DIR))[0]!;
    await waitFor(() => readManifest(join(base, INSTANCES_DIR, id)) !== null, "the manifest");
    const m = readManifest(join(base, INSTANCES_DIR, id))!;
    const expected = humanSockPath(base, id);
    assert.equal(m.humanSockPath, expected, "the manifest records <base>/human/<id>.sock");
    assert.ok(!expected.startsWith(join(base, INSTANCES_DIR) + "/"), "outside the instance dir");
    assert.ok(existsSync(expected), "the human socket is bound");
    assert.equal(statSync(join(base, "human")).mode & 0o777, 0o700);

    const data = new ArbiterClient(currentSock);
    const hello = await data.hello();
    assert.equal(hello.humanSock, expected, "hello names the human socket");
    await assert.rejects(() => data.sessions(), /human-plane/);
    data.close();
    const human = new ArbiterClient(expected);
    assert.deepEqual(await human.sessions(), [], "the human socket is live");
    human.close();
    assert.equal(
      resolveArbiterHumanSock({ MANDU_RUNTIME_DIR: base, HOME: join(root, "home") } as NodeJS.ProcessEnv),
      expected, "published with `current`",
    );

    await new Promise<void>((resolve) => {
      const kill = setTimeout(() => child.kill("SIGKILL"), 60_000);
      kill.unref();
      child.once("exit", () => { clearTimeout(kill); resolve(); });
      child.kill("SIGTERM");
    });
    assert.ok(!existsSync(expected), "a graceful shutdown unlinks the human socket");
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    rmSync(root, { recursive: true, force: true });
  }
});
