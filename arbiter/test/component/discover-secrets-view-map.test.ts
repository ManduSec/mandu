/**
 * discover-secrets-view-map.test — the `discoverSecrets` op over the REAL
 * ArbiterServer + ArbiterClient with the launch's `stateBase`
 * (secret-discovery.md §1.9): Mandu's own state base is pruned
 * from the walk and the AgentView worktree of the workspace root is found
 * through fs-sync's persisted view map. The wire carries `stateBase`; the
 * default (`<home>/.mandu/state`, inside the pruned Mandu home) applies when
 * it is absent.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { connect, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4): confidentiality ON

const TOKEN = "$MDU:nomodel_Read[9bbd1234].env";

test("discoverSecrets over the wire: stateBase prunes the state dir and names the AgentView copies through the view map; absent, the default base under the launch's HOME does the same", async () => {
  // realpath: on macOS /tmp and /var are symlinks, and discovery answers canonical paths.
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-disc-e2e-")));
  const home = join(dir, "home");
  const ws = join(home, "proj");
  mkdirSync(join(ws, "sub"), { recursive: true });
  writeFileSync(join(ws, ".env"), "A=AKIA_HUMAN_E2E\n");
  const plant = (base: string): string => {
    const wsd = join(base, "workspaces", "proj-cafecafecafe");
    mkdirSync(join(wsd, "agentview", "deep", "er"), { recursive: true });
    mkdirSync(join(wsd, "repo.git", "objects", "ab", "cd", "ef"), { recursive: true });
    writeFileSync(join(wsd, "workspace.json"), JSON.stringify({ schemaVersion: 1, workspacePath: ws, workspaceId: "proj-cafecafecafe" }));
    writeFileSync(join(wsd, "agentview", ".env"), `${TOKEN}\n`);
    writeFileSync(join(wsd, "agentview", "deep", "er", ".env"), "B=AKIA_RAW_COPY_E2E\n");
    return join(wsd, "agentview");
  };
  const explicit = plant(join(dir, "state", "x", "y", "z", "view-state"));
  const dflt = plant(join(home, ".mandu", "state"));
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, policyPollMs: 0,
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "a.sock"));
  try {
    await client.connect();
    const r = await client.discoverSecretsReport([home, join(ws, "sub")], home, { stateBase: join(dir, "state", "x", "y", "z", "view-state") });
    const paths = r.files.map((f) => f.path);
    assert.ok(paths.includes(join(ws, ".env")));
    assert.ok(paths.includes(join(explicit, "deep", "er", ".env")), `the raw copy through the view map: ${paths}`);
    assert.ok(!paths.includes(join(explicit, ".env")), "fs-sync's mask is not re-masked");
    assert.equal(r.counts["agentview-symbolized"], 1);
    assert.equal(r.counts["depth"], 0, "the shadow repos are pruned with the bases");
    // the conventional ~/.mandu is pruned too when the launch names another base (one record: the
    // named base lies outside every root and is never met by the walk)
    assert.equal(r.counts["mandu-state"], 1);
    assert.ok(!paths.some((p) => p.startsWith(dflt)), "nothing under the left-behind default base, raw copy included: not this launch's view map");
    // no stateBase on the wire: the default `<home>/.mandu/state`, pruned with its home
    const d = await client.discoverSecretsReport([home, ws], home);
    const dp = d.files.map((f) => f.path);
    assert.equal(d.counts["mandu-state"], 1);
    assert.deepEqual(d.skipped.filter((s) => s.reason === "mandu-state").map((s) => s.path), [join(home, ".mandu")]);
    assert.ok(dp.includes(join(dflt, "deep", "er", ".env")), `the raw copy under the default base: ${dp}`);
    assert.ok(!dp.includes(join(dflt, ".env")));
    assert.equal(d.counts["agentview-symbolized"], 1);
    assert.ok(!dp.some((p) => p.startsWith(join(dir, "state"))), "the other base is out of every root now");
    assert.ok(!JSON.stringify(r).includes("AKIA_") && !JSON.stringify(d).includes("AKIA_"), "no contents on the wire");
    // the files-only op takes the same option
    const files = await client.discoverSecrets([home, ws], home, { stateBase: join(dir, "state", "x", "y", "z", "view-state") });
    assert.ok(files.some((f) => f.path === join(explicit, "deep", "er", ".env")));
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("discoverSecrets over the wire: package caches below the depth cap arrive as `package-cache`, the ssh-agent socket as `special-file`, a workspace under HOME is not a `depth` miss; a deep directory elsewhere and an unreadable key are still the consequential `depth` / `unreadable` (secret-discovery.md §1.9 F)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-disc-noise-"));
  const home = join(dir, "home");
  const ws = join(home, "proj");
  mkdirSync(join(ws, "a", "b", "c", "d"), { recursive: true }); // depth 5 from HOME, 4 from the workspace
  writeFileSync(join(ws, "a", "b", "c", "d", ".env"), "A=AKIA_WS_DEEP\n");
  const crate = join(home, ".cargo", "registry", "src", "index.crates.io-x", "serde-1.0.0");
  mkdirSync(join(crate, "src"), { recursive: true });
  const elsewhere = join(home, "notes", "a", "b", "c", "d");
  mkdirSync(elsewhere, { recursive: true });
  mkdirSync(join(home, ".ssh", "agent"), { recursive: true });
  const locked = join(home, ".ssh", "id_locked");
  writeFileSync(locked, "-----BEGIN OPENSSH PRIVATE KEY-----\nAKIA_LOCKED\n");
  chmodSync(locked, 0o000);
  const agentSock = createServer();
  await new Promise<void>((resolve, reject) => { agentSock.once("error", reject); agentSock.listen(join(home, ".ssh", "agent", "s.x"), resolve); });
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, policyPollMs: 0,
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "a.sock"));
  try {
    await client.connect();
    const r = await client.discoverSecretsReport([home, ws], home);
    const by = (reason: string): string[] => r.skipped.filter((s) => s.reason === reason).map((s) => s.path);
    assert.deepEqual(by("package-cache"), [crate]);
    assert.deepEqual(by("special-file"), [join(home, ".ssh", "agent", "s.x")]);
    assert.deepEqual(by("depth"), [elsewhere], "only the directory NO root reaches");
    assert.ok(r.files.some((f) => f.path === join(ws, "a", "b", "c", "d", ".env")), "the workspace walk reaches it");
    if (process.getuid && process.getuid() !== 0) assert.deepEqual(by("unreadable"), [locked]);
    assert.ok(!JSON.stringify(r).includes("AKIA_"), "no contents on the wire");
  } finally {
    client.close();
    await server.close();
    await new Promise<void>((resolve) => agentSock.close(() => resolve()));
    chmodSync(locked, 0o600);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("discoverSecrets over the wire: a workspace that IS HOME is walked once, and the launch's `cacheEnv` turns a cache moved by CARGO_HOME / GOMODCACHE into `package-cache`; unknown names and junk on the wire are dropped (secret-discovery.md §1.9 G)", async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-disc-moved-")));
  const home = join(dir, "home");
  const cargo = join(dir, "home", "dev", "cargo");
  const crate = join(cargo, "registry", "src", "idx"); // depth 5 from HOME
  mkdirSync(join(crate, "serde"), { recursive: true });
  const gomod = join(home, "dev", "gomod");
  const mod = join(gomod, "github.com", "x", "y@v1"); // depth 5 from HOME
  mkdirSync(mod, { recursive: true });
  const elsewhere = join(home, "notes", "a", "b", "c", "d");
  mkdirSync(elsewhere, { recursive: true });
  writeFileSync(join(home, ".env"), "A=AKIA_HOME_ENV\n");
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, policyPollMs: 0,
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "a.sock"));
  try {
    await client.connect();
    const plain = await client.discoverSecretsReport([home], home);
    assert.equal(plain.counts["depth"], 3);
    // the workspace IS HOME: the same answer, nothing counted twice
    const twice = await client.discoverSecretsReport([home, home], home);
    assert.deepEqual(twice.counts, plain.counts);
    assert.deepEqual(twice.files, plain.files);
    // the moved caches, through the production client
    const moved = await client.discoverSecretsReport([home, home], home, { cacheEnv: { CARGO_HOME: cargo, GOMODCACHE: gomod } });
    const by = (r: typeof moved, reason: string): string[] => r.skipped.filter((s) => s.reason === reason).map((s) => s.path).sort();
    assert.deepEqual(by(moved, "package-cache"), [crate, mod].sort());
    assert.deepEqual(by(moved, "depth"), [elsewhere]);
    assert.deepEqual(moved.files, plain.files, "the walk is unchanged");
    // a raw line with junk: an unknown name, a non-string and a HOME-wide value change nothing
    const raw = await new Promise<{ ok: boolean; result: typeof plain }>((resolve, reject) => {
      const c = connect(join(dir, "a.sock"));
      let buf = "";
      c.setEncoding("utf8");
      c.on("error", reject);
      c.on("data", (d: string) => { buf += d; const nl = buf.indexOf("\n"); if (nl >= 0) { c.destroy(); resolve(JSON.parse(buf.slice(0, nl))); } });
      c.write(JSON.stringify({ id: 1, op: "discoverSecrets", roots: [home], home, cacheEnv: { LD_PRELOAD: cargo, CARGO_HOME: 7, GOMODCACHE: home } }) + "\n");
    });
    assert.equal(raw.ok, true);
    assert.deepEqual(raw.result.counts, plain.counts);
    assert.ok(!JSON.stringify([plain, moved, raw]).includes("AKIA_"), "no contents on the wire");
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
