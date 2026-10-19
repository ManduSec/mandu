/**
 * human-plane-rediscovery.test — a human-plane client follows the arbiter
 * across a restart (docs/design/architecture/arbiter-human-plane.md §5.1;
 * Mandu-new, no reference origin).
 *
 * An arbiter restarted under a live session binds a NEW human socket (the
 * path carries the instance id) at the same data-socket spelling. Before
 * this, every human-facing consumer kept dialling the dead path: the reply
 * filter showed raw placeholders, and the proxies' and net-proxy's
 * enforcement ops failed closed, until the session was relaunched.
 *
 * A REAL ArbiterServer is stopped and a second one started on the same data
 * socket and symbol DB, with its human socket at another path:
 *   - `ArbiterClient.humanPlane(human, data)` re-learns the human socket
 *     from the data socket's `hello`, confirms it answers as the `human`
 *     channel, and desymbolize resolves again (symbols survive the restart);
 *   - without a data socket the client stays on the dead path (fails, as
 *     before);
 *   - a `hello` naming any path outside the stale socket's directory, or the
 *     data socket itself, is never adopted: desymbolize is never sent to the
 *     data socket (the arbiter logs no data-channel refusal);
 *   - the rediscovery runs with backoff, not on every failing request.
 *
 * Run: npm run test:component
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient, REDISCOVER_MIN_MS, acceptableHumanSock, humanPlaneRediscovery } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const VALUE = "mdu-digest sha256=REDISCOVER-CANARY-41c7 .env";

function rig(dir: string, human: string, log: string[] = []): ArbiterServer {
  return new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    humanSocketPath: join(dir, "human", human),
    dbPath: join(dir, "symbols.db"),
    eventDir: join(dir, "events"),
    log: (l: string) => log.push(l),
    confidentiality: true,
    integrity: false,
  });
}

async function mint(dir: string): Promise<string> {
  const data = new ArbiterClient(join(dir, "arbiter.sock"));
  try {
    return await data.symbolize({ tool: "Bash", value: VALUE, confidentiality: "no-model" });
  } finally {
    data.close();
  }
}

test("a restart on a new human socket: the human-plane client re-learns it from the data socket and resolves again", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-hp-rediscover-"));
  let a: ArbiterServer | null = rig(dir, "a.sock");
  let b: ArbiterServer | null = null;
  const blog: string[] = [];
  const client = ArbiterClient.humanPlane(join(dir, "human", "a.sock"), join(dir, "arbiter.sock"));
  const plain = new ArbiterClient(join(dir, "human", "a.sock"));
  try {
    await a.listen();
    const token = await mint(dir);
    assert.match(token, /^\$MDU:nomodel_Bash\[/);
    assert.equal(await client.desymbolize(`x ${token}`), `x ${VALUE}`);
    assert.equal(await plain.desymbolize(token), VALUE);

    await a.close();
    a = null;
    // A real restart takes seconds; the clients hear the old connection close
    // first (a request written into the dying connection fails like any
    // request the old arbiter never answered: no retry of an op here).
    await new Promise((r) => setTimeout(r, 200));
    b = rig(dir, "b.sock", blog);
    await b.listen();

    assert.equal(await client.desymbolize(`y ${token}`), `y ${VALUE}`, "the symbol table survived; the client found the new socket");
    assert.equal(client.path, join(dir, "human", "b.sock"));
    assert.equal(client.rediscoveries, 1);
    // A client given no data socket stays where it was: it fails, as before.
    await assert.rejects(() => plain.desymbolize(token), /ENOENT|ECONNREFUSED|closed/);
    assert.equal(plain.path, join(dir, "human", "a.sock"));
    assert.ok(!blog.some((l) => /refused on data channel/.test(l)), `nothing asked the data socket: ${blog.join("\n")}`);
  } finally {
    client.close();
    plain.close();
    await a?.close().catch(() => {});
    await b?.close().catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  }
});

/** A fake data socket: answers every `hello` with `humanSock` (and the
 *  channel `data`), counts requests by op. */
function fakeData(path: string, humanSock: string): { server: Server; ops: string[] } {
  const ops: string[] = [];
  const server = createServer((c) => {
    c.on("error", () => {});
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        const req = JSON.parse(line) as { id: number; op: string };
        ops.push(req.op);
        const result = req.op === "hello" ? { humanSock, channel: "data", instanceId: "fake" } : { text: "LEAK-IF-SEEN" };
        c.write(JSON.stringify({ id: req.id, ok: true, result }) + "\n");
      }
    });
  });
  server.listen(path);
  return { server, ops };
}

test("a hello naming the data socket, or a path outside the human directory, is never adopted", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-hp-rediscover-"));
  const dataSock = join(dir, "arbiter.sock");
  const stale = join(dir, "human", "gone.sock");
  for (const named of [dataSock, join(dir, "elsewhere.sock"), "relative.sock", ""]) {
    const fake = fakeData(dataSock, named);
    await new Promise((r) => fake.server.once("listening", r));
    const client = ArbiterClient.humanPlane(stale, dataSock);
    try {
      await assert.rejects(() => client.desymbolize("$MDU:nomodel_Bash[abcd]"), /ENOENT/, `named ${JSON.stringify(named)}`);
      assert.equal(client.path, stale);
      assert.deepEqual(fake.ops, ["hello"], `only the discovery hello reached the data socket (named ${JSON.stringify(named)})`);
    } finally {
      client.close();
      await new Promise((r) => fake.server.close(r));
    }
  }
  rmSync(dir, { recursive: true, force: true });
});

test("a candidate in the human directory that answers as the DATA channel is refused", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-hp-rediscover-"));
  const dataSock = join(dir, "arbiter.sock");
  const { mkdirSync } = await import("node:fs");
  mkdirSync(join(dir, "human"));
  const impostor = join(dir, "human", "impostor.sock");
  const fake = fakeData(dataSock, impostor);
  const fakeHuman = fakeData(impostor, impostor); // answers hello with channel "data"
  await Promise.all([new Promise((r) => fake.server.once("listening", r)), new Promise((r) => fakeHuman.server.once("listening", r))]);
  try {
    const found = await humanPlaneRediscovery(dataSock)(join(dir, "human", "gone.sock"));
    assert.equal(found, null);
    assert.ok(!fakeHuman.ops.includes("desymbolize"));
  } finally {
    await new Promise((r) => fake.server.close(r));
    await new Promise((r) => fakeHuman.server.close(r));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rediscovery backs off: failing requests inside the window do not ask again", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-hp-rediscover-"));
  let asked = 0;
  const client = new ArbiterClient(join(dir, "nothing.sock"), {
    rediscoverPath: async () => { asked += 1; return null; },
  });
  try {
    for (let i = 0; i < 5; i++) await assert.rejects(() => client.ping());
    assert.equal(asked, 1, "one rediscovery inside the first window");
    await new Promise((r) => setTimeout(r, REDISCOVER_MIN_MS + 50));
    await assert.rejects(() => client.ping());
    assert.equal(asked, 2, "the window passed: asked again");
    await assert.rejects(() => client.ping());
    assert.equal(asked, 2, "the next window is longer");
  } finally {
    client.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an arbiter that is down grows no backoff: the first dial after it is back re-learns at once", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-hp-rediscover-"));
  const dataSock = join(dir, "arbiter.sock");
  let b: ArbiterServer | null = null;
  const client = ArbiterClient.humanPlane(join(dir, "human", "gone.sock"), dataSock);
  try {
    // Nothing on the data socket: each failing request asks once more, cheaply.
    for (let i = 0; i < 4; i++) await assert.rejects(() => client.ping(), /ENOENT/);
    b = rig(dir, "b.sock");
    await b.listen();
    assert.equal((await client.ping()).pong, true, "re-learned on the first dial after the restart");
    assert.equal(client.path, join(dir, "human", "b.sock"));
  } finally {
    client.close();
    await b?.close().catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  }
});

test("acceptableHumanSock: absolute, .sock, the stale path's directory, never the data socket", () => {
  const stale = "/run/user/1/mandu/human/i1.sock";
  const data = "/run/user/1/mandu/current/arbiter.sock";
  assert.equal(acceptableHumanSock("/run/user/1/mandu/human/i2.sock", stale, data), true);
  assert.equal(acceptableHumanSock("/run/user/1/mandu/human/../current/arbiter.sock", stale, data), false);
  assert.equal(acceptableHumanSock(data, stale, data), false);
  assert.equal(acceptableHumanSock("/tmp/x/i2.sock", stale, data), false);
  assert.equal(acceptableHumanSock("human/i2.sock", stale, data), false);
  assert.equal(acceptableHumanSock("/run/user/1/mandu/human/i2", stale, data), false);
  assert.equal(acceptableHumanSock("/run/user/1/mandu/human/i1.sock", "/run/user/1/mandu/human/i1.sock", "/run/user/1/mandu/human/i1.sock"), false, "the data socket in the human dir is still the data socket");
  assert.equal(acceptableHumanSock(`/run/user/1/mandu/human/${"x".repeat(200)}.sock`, stale, data), false, "too long to dial as written");
});
