/**
 * discovery-prefetch parity e2e — the launcher starts the secret discovery
 * walk early (run.ts, `prefetchDiscovery` once the AgentView is seeded) and
 * the secret setup picks its answer up (`withPrefetchedDiscovery`). Over the
 * PRODUCTION wiring (the launcher's socket adapter, no test bridge) against a
 * real ArbiterServer: a prefetched launch confines exactly what a plain one
 * does, every twin holds a placeholder and no secret byte, a prefetch asked
 * with other arguments is not used, and a prefetch that failed still refuses
 * the launch fail-closed (never an unhandled rejection, never a raw launch).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import {
  applySecretTwins, launchDiscoverOptions, prefetchDiscovery, socketSecretArbiter, withPrefetchedDiscovery,
  type SecretArbiter,
} from "../../launcher/src/secret-setup.js";
import { emptyMutation } from "../../launcher/src/backend/types.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { manduPath } from "../../launcher/src/generated/mandu-paths.js";
import { stateAxes } from "../../arbiter/test/axes.js";

stateAxes("secrets"); // confidentiality ON: discovery and the twins exist only on this axis

const AWS_RAW = "aws_secret_access_key=PREFETCH_AWS_RAW_4417";
const ENV_RAW = "STRIPE_KEY=sk_live_PREFETCH_ENV_RAW_9921";

test("a prefetched discovery confines exactly what a plain one does, over the real arbiter; other arguments are not served from it; a failed prefetch refuses", async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-prefetch-")));
  const home = join(dir, "home");
  const ws = join(home, "proj");
  mkdirSync(join(home, ".aws"), { recursive: true });
  mkdirSync(ws, { recursive: true });
  writeFileSync(join(home, ".aws", "credentials"), `[default]\n${AWS_RAW}\n`, { mode: 0o600 });
  writeFileSync(join(ws, ".env"), `${ENV_RAW}\n`);
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const unhandled: unknown[] = [];
  const onUnhandled = (e: unknown) => { unhandled.push(e); };
  process.on("unhandledRejection", onUnhandled);
  // The launch's Mandu home: the state base both the prefetch (run.ts) and the
  // setup name is its `state/` (the path table's `view-state`).
  const savedManduHome = process.env["MANDU_HOME"];
  process.env["MANDU_HOME"] = join(dir, "mandu-home");
  try {
    const plan = { confidentiality: true, bestEffort: false } as LaunchPlan;
    // As run.ts builds them (the state base and the moved caches, secret-discovery.md §1.9 G).
    const opts = launchDiscoverOptions(process.env, home);
    assert.equal(opts.stateBase, manduPath("view-state", process.env, home));
    let n = 0;
    const launch = async (arbiter: SecretArbiter) => {
      const runDir = join(dir, `run-${n++}`);
      mkdirSync(runDir);
      const mut = emptyMutation();
      const logs: string[] = [];
      const res = await applySecretTwins(plan, runDir, mut, {
        arbiter, commandExists: () => true, usernsOk: () => true, platform: "linux", log: (m) => logs.push(m),
        home, workspaceRoots: [ws], onWsl: false, nestingOk: () => true, wrapBwrap: "bwrap",
        symlinkProbe: (bwrap) => ({ bwrap, verdict: "unknown" }),
      });
      return { res, logs, runDir };
    };
    const paths = (r: Awaited<ReturnType<typeof launch>>) => r.res.confined.map((c) => c.path).sort();

    const plain = await launch(socketSecretArbiter(sock));
    assert.deepEqual(paths(plain), [join(home, ".aws", "credentials"), join(ws, ".env")].sort(), plain.logs.join("\n"));

    // A wrapper that counts the discovery calls that reach the arbiter live.
    let live = 0;
    const inner = socketSecretArbiter(sock);
    const counting = Object.assign(Object.create(inner) as SecretArbiter, {
      discoverSecrets: (...a: Parameters<SecretArbiter["discoverSecrets"]>) => { live++; return inner.discoverSecrets(...a); },
    });

    // The production wiring, exactly as run.ts builds it; the setup is
    // served from it (asks nothing live), so run.ts and the setup agree on
    // every argument, the state base included.
    const prefetch = prefetchDiscovery(socketSecretArbiter(sock), [home, ws], home, opts);
    const pre = await launch(withPrefetchedDiscovery(counting, prefetch));
    assert.equal(live, 0, "the prefetch was served: run.ts asks exactly what the setup asks");
    assert.equal(pre.res.posture, plain.res.posture, "and reports the same posture");
    assert.deepEqual(paths(pre), paths(plain), "the prefetched launch confines the same files");
    for (const c of pre.res.confined) {
      const twin = c.twin ?? c.symbol; // a structured twin, or the whole-file symbol
      assert.match(twin, /\$MDU:nomodel_/, `${c.path}: the twin holds a placeholder`);
      assert.ok(!twin.includes("PREFETCH_AWS_RAW") && !twin.includes("PREFETCH_ENV_RAW"), `${c.path}: no secret byte in the twin`);
    }

    // A prefetch asked with other roots is never served: the setup asks live.
    const other = prefetchDiscovery(inner, [home], home, opts);
    const mismatched = await launch(withPrefetchedDiscovery(counting, other));
    assert.equal(live, 1, "the mismatched prefetch was not used");
    assert.deepEqual(paths(mismatched), paths(plain));

    // A prefetch that failed (the arbiter unreachable when it ran) refuses.
    const dead = prefetchDiscovery(socketSecretArbiter(join(dir, "nobody.sock")), [home, ws], home, opts);
    await new Promise((r) => setTimeout(r, 50)); // it has failed before anyone awaits it
    await assert.rejects(
      launch(withPrefetchedDiscovery(socketSecretArbiter(sock), dead)),
      /could not discover secrets/,
    );
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(unhandled, [], "the early failure never surfaced as an unhandled rejection");
  } finally {
    process.off("unhandledRejection", onUnhandled);
    if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
