/**
 * discover-secrets-off-thread.test — `discoverSecrets` over the REAL
 * ArbiterServer + ArbiterClient runs on a worker thread (runtime-instances.md §14.2
 * item 7): it answers exactly what the in-process walk (`dispatch`) answers,
 * human labels from the DB included; a call made while it walks is answered
 * first (the walk no longer holds the event loop); and a closing arbiter stops
 * an in-flight walk, the client failing closed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4): confidentiality ON

function rig(warm = false): { dir: string; home: string; server: ArbiterServer; logs: string[] } {
  const dir = mkdtempSync(join(tmpdir(), "mdu-disc-thread-e2e-"));
  const home = join(dir, "home");
  mkdirSync(join(home, "proj", "fixtures"), { recursive: true });
  mkdirSync(join(home, ".aws"), { recursive: true });
  writeFileSync(join(home, ".aws", "credentials"), "[default]\naws_secret_access_key=AKIA_OFFTHREAD\n");
  writeFileSync(join(home, "proj", ".env"), "A=AKIA_OFFTHREAD_ENV\n");
  writeFileSync(join(home, "proj", "fixtures", ".env"), "FAKE=1\n");
  writeFileSync(join(home, "proj", "contract.txt"), "terms\n");
  // Enough directories that the walk is real work.
  for (let i = 0; i < 40; i++) {
    mkdirSync(join(home, "src", `m${i}`, "a"), { recursive: true });
    for (let j = 0; j < 10; j++) writeFileSync(join(home, "src", `m${i}`, "a", `f${j}.ts`), "x\n");
  }
  const logs: string[] = [];
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: (m: string) => logs.push(m), confidentiality: true, policyPollMs: 0,
    warmDiscoveryWorker: warm,
  });
  return { dir, home, server, logs };
}

test("discoverSecrets on the worker (warmed at listen, as the daemon does) answers what the in-process walk answers, DB labels included, and never blocks a concurrent call", async () => {
  const { dir, home, server, logs } = rig(true);
  await server.listen();
  const client = new ArbiterClient(join(dir, "a.sock"));
  try {
    await client.connect();
    for (const [path, confidentiality] of [[join(home, "proj", "fixtures"), "public"], [join(home, "proj", "contract.txt"), "local-model"]]) {
      const r = server.dispatch({ id: 1, op: "setPathLabel", path, confidentiality } as never) as { ok: boolean; error?: string };
      assert.ok(r.ok, r.error);
    }
    const order: string[] = [];
    const walk = client.discoverSecretsReport([home], home).then((r) => { order.push("discover"); return r; });
    const ping = client.ping().then(() => { order.push("ping"); });
    const [report] = await Promise.all([walk, ping]);
    assert.deepEqual(order, ["ping", "discover"], "the call made while the walk ran was answered first");
    assert.ok(!logs.some((l) => l.includes("walking in-process")), `the worker ran: ${logs.join("\n")}`);

    const direct = server.dispatch({ id: 2, op: "discoverSecrets", roots: [home], home }) as { ok: true; result: unknown };
    assert.deepEqual(report, direct.result, "the worker's answer is the in-process one");
    const paths = report.files.map((f) => f.path);
    assert.ok(paths.includes(join(home, ".aws", "credentials")));
    assert.ok(paths.includes(join(home, "proj", ".env")));
    assert.ok(paths.includes(join(home, "proj", "contract.txt")), "a DB label reaches the worker's snapshot");
    assert.ok(!paths.includes(join(home, "proj", "fixtures", ".env")), "a public DB label reaches it too");
    assert.ok(!JSON.stringify(report).includes("AKIA_"), "no contents on the wire");
    // A later walk sees a later label act; it runs on the same thread.
    const r = server.dispatch({ id: 3, op: "setPathLabel", path: join(home, "proj", "fixtures"), confidentiality: "no-model" } as never) as { ok: boolean };
    assert.ok(r.ok);
    const again = await client.discoverSecretsReport([home], home);
    assert.ok(again.files.some((f) => f.path === join(home, "proj", "fixtures", ".env")), "the next walk's snapshot has the new label");
    assert.ok(!logs.some((l) => l.includes("walking in-process")), `the worker ran: ${logs.join("\n")}`);
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a closing arbiter stops an in-flight walk; the client's request fails closed", async () => {
  const { dir, home, server, logs } = rig();
  await server.listen();
  const client = new ArbiterClient(join(dir, "a.sock"));
  try {
    await client.connect();
    const walk = client.discoverSecretsReport([home], home);
    await client.ping(); // the request has reached the server
    await server.close();
    await assert.rejects(walk);
    assert.ok(!logs.some((l) => l.includes("walking in-process")), "no fallback walk on close");
  } finally {
    client.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
