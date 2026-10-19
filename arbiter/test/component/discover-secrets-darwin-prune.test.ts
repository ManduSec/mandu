/**
 * discover-secrets-darwin-prune.test — the `discoverSecrets` op over the REAL
 * ArbiterServer + ArbiterClient on macOS: the HOME walk prunes the app-data
 * and media folders (secret-discovery.ts DARWIN_HOME_SKIP), but never over a
 * label. A file the human labeled deep inside ~/Library is still discovered,
 * so the launch's Seatbelt profile still blocks it (confidentiality.md §7.2,
 * §7.3); the arbiter hands the walk the label paths in force for that.
 *
 * darwin only: the prune keys on the arbiter's own platform.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4): confidentiality ON

test("macOS HOME prune: a labeled file inside ~/Library is still discovered; an unlabeled one there is pruned", { skip: process.platform !== "darwin" && "the HOME prune is macOS only" }, async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-disc-darwin-")));
  const home = join(dir, "home");
  const appDir = join(home, "Library", "Application Support", "acme");
  mkdirSync(appDir, { recursive: true });
  const labeled = join(appDir, "token.txt");
  const unlabeled = join(appDir, ".env");
  writeFileSync(labeled, "ACME_TOKEN=AKIA_DARWIN_LABELED\n");
  writeFileSync(unlabeled, "B=AKIA_DARWIN_PRUNED\n");
  mkdirSync(join(home, "proj"), { recursive: true });
  writeFileSync(join(home, "proj", ".env"), "C=AKIA_DARWIN_WS\n");
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, policyPollMs: 0,
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "a.sock"));
  try {
    await client.connect();
    const r = server.dispatch({ id: 1, op: "setPathLabel", path: labeled, confidentiality: "no-model", recursive: false } as never) as { ok: boolean; error?: string };
    assert.ok(r.ok, r.error);
    const report = await client.discoverSecretsReport([home], home);
    const paths = report.files.map((f) => f.path);
    assert.ok(paths.includes(join(home, "proj", ".env")), `the workspace secret: ${paths}`);
    assert.ok(paths.includes(labeled), `the labeled file under the pruned ~/Library is visited: ${paths}`);
    assert.ok(!paths.includes(unlabeled), "an unlabeled file under ~/Library is pruned (no catalog entry there)");
    assert.ok(!JSON.stringify(report).includes("AKIA_"), "no contents on the wire");
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
