/**
 * instance-autostart.test — E2E: a bare launch (no MANDU_ARBITER_SOCK)
 * autostarts a REAL arbiter in INSTANCE mode under the plan's runtime base:
 * it binds instances/<id>/arbiter.sock, promotes `current`, writes a
 * manifest — and the launched agent sees the `current` SPELLING
 * (runtime-instances.md §5; the pre-fix launcher pinned the legacy fixed
 * path here, planting a second resident arbiter beside a promoted stack).
 *
 * The autostarted arbiter deliberately has NO lifeline (it is the shared
 * attach-or-start daemon) — this test is its owner and SIGTERMs it via the
 * manifest pid in finally, which also exercises the graceful instance-dir
 * self-cleanup; test/lib/runtime-sweep.ts then stops anything else still
 * running under the test's runtime base.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, chmodSync, readdirSync, readFileSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../axes.js";
import { sweepRuntimeProcesses } from "../lib/runtime-sweep.js";

stateAxes("off"); // this suite states its axes (protection-modes.md §4); the wiring it proves is axis-independent

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE = join(HERE, "..", "fixtures", "fake-agent.sh");

/** Every instance manifest under `base` (a torn one is skipped). */
function manifestsOf(base: string): { pid: number; sockPath: string }[] {
  const dir = join(base, "instances");
  if (!existsSync(dir)) return [];
  const out: { pid: number; sockPath: string }[] = [];
  for (const id of readdirSync(dir)) {
    const m = join(dir, id, "manifest.json");
    try { if (existsSync(m)) out.push(JSON.parse(readFileSync(m, "utf8"))); } catch { /* torn */ }
  }
  return out;
}

function manifestOf(base: string): { pid: number; sockPath: string } | null {
  return manifestsOf(base)[0] ?? null;
}

/** Pids of the dashboards registered under this runtime base (registry.ts). */
function dashboardPidsOf(base: string): number[] {
  const dir = join(base, "dashboards");
  if (!existsSync(dir)) return [];
  const pids: number[] = [];
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".json"))) {
    try {
      const m = JSON.parse(readFileSync(join(dir, f), "utf8")) as { pid?: unknown };
      if (typeof m.pid === "number") pids.push(m.pid);
    } catch { /* torn / unreadable entry */ }
  }
  return pids;
}

// The timeout covers the launcher's own load-aware deadlines (the supervisor's
// and the arbiter socket's, each up to 120 s on a saturated host;
// runtime-instances.md §10 "Autostart deadlines under load"): a test that
// timed out first would hide which one missed.
test("bare launch: instance-mode autostart promotes current; agent gets the spelling", { timeout: 300_000 }, async () => {
  chmodSync(FAKE, 0o755);
  // realpath: on macOS-style TMPDIR symlinks the arbiter's own runtimeBase()
  // resolution must land on the same dir the test polls. SHORT: the arbiter
  // binds <base>/instances/<id>/arbiter.sock, and macOS allows 103 bytes
  // (runtime-instances.md §3b) — its per-user TMPDIR alone is 49, so the base
  // lives under /tmp (/private/tmp/mdu-ia-XXXXXX/mandu: 32 bytes), and the
  // launcher refuses up front any base an instance socket might not fit under.
  const tmp = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "mdu-ia-")));
  const base = join(tmp, "mandu");
  const outFile = join(tmp, "out.json");
  // The autostart spawns the arbiter from process.env (main()'s env param
  // feeds parse/ensure decisions only) — so the durable-store isolation must
  // live in the REAL env for the duration. Never touch the host's shared
  // Mandu home (symbol DB, events) from a test.
  const manduHome = join(tmp, "mandu-home");
  const saved = {
    MANDU_HOME: process.env["MANDU_HOME"],
    MANDU_ARBITER_SOCK: process.env["MANDU_ARBITER_SOCK"],
  };
  process.env["MANDU_HOME"] = manduHome;
  delete process.env["MANDU_ARBITER_SOCK"];
  try {
    const code = await main(
      ["--target", "claude", "--no-scope", "--", "bash", "-c", `${FAKE} > ${outFile} 2>&1`],
      {
        HOME: process.env["HOME"], PWD: tmp, PATH: process.env["PATH"],
        // Hermetic: the developer's real ~/.mandu/config.toml must never leak in.
        MANDU_HOME: manduHome,
        MANDU_NO_CONTEXT_PROXY: "1",
        // Isolate the WHOLE runtime base — never touch the host's instances.
        MANDU_RUNTIME_DIR: base,
        // …and the scope run dir, whose root is the DEFAULT base (it ignores
        // MANDU_RUNTIME_DIR): a short TMPDIR keeps it at <tmp>/mandu, never the
        // host's /tmp/mandu-<uid> fallback.
        TMPDIR: tmp,
      },
    );
    assert.equal(code, 0);

    // The rendezvous the agent received is the current SPELLING, resolving live.
    const got = JSON.parse(readFileSync(outFile, "utf8"));
    assert.equal(got.arbiter, join(base, "current", "arbiter.sock"));
    assert.ok(existsSync(join(base, "current", "arbiter.sock")), "promoted socket resolves");

    // Instance registered: exactly one instances/<id>/ with a manifest naming
    // a live pid and the in-instance socket path.
    const manifest = manifestOf(base);
    assert.ok(manifest, "manifest.json written");
    assert.ok(manifest!.sockPath.includes(`${base}/instances/`), "socket bound INSIDE the instance dir");
    assert.doesNotThrow(() => process.kill(manifest!.pid, 0), "arbiter pid is live");

    // d4: the resident stack has NO owner, so `mandu reap` never stops it
    // once this launcher exits; and its entry records the base path (none).
    const entries = readdirSync(join(base, "dashboards")).filter((n) => n.endsWith(".json"));
    assert.equal(entries.length, 1, "the supervisor dashboard registered");
    const entry = JSON.parse(readFileSync(join(base, "dashboards", entries[0]!), "utf8")) as { ownerPid?: unknown; basePath?: unknown };
    assert.equal(entry.ownerPid, null, "ownerless: resident");
    assert.equal(entry.basePath, "", "served at the root by default");
    const { planReap, realReapDeps } = await import("../../src/reap.js");
    const plan = await planReap(base, { ...realReapDeps, pidAlive: (p) => p !== process.pid && realReapDeps.pidAlive(p) });
    assert.ok(!plan.some((a) => a.kind === "kill-orphan-dashboard" || a.kind === "kill-orphan-arbiter"),
      "with the launcher gone, reap plans no stop of the resident stack: " + JSON.stringify(plan));
  } finally {
    // The autostart starts the SUPERVISOR first (the dashboard with
    // DASHBOARD_AUTOSTART=arbiter), on a FREE port since 2026-09-26 (release
    // checklist a1) — so it binds even where a dashboard already holds 4500
    // and would outlive this test. It registers under <base>/dashboards/
    // after listen(); give it a moment, then stop it (its supervised arbiter
    // goes down with it).
    for (let i = 0; i < 50; i++) {
      const pids = dashboardPidsOf(base);
      if (pids.length > 0) {
        for (const pid of pids) { try { process.kill(pid, "SIGTERM"); } catch { /* already gone */ } }
        break;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    // We own these daemons: graceful stop (also removes each instance dir).
    // EVERY manifest, not the first: a second instance is exactly the leak.
    const manifests = manifestsOf(base);
    for (const m of manifests) { try { process.kill(m.pid, "SIGTERM"); } catch { /* already gone */ } }
    // Give the graceful shutdown a moment before the sweep.
    if (manifests.length > 0) await new Promise((r) => setTimeout(r, 500));
    // Last resort (2026-09-29, a 3-hour orphan of this test): anything still
    // carrying this base in its env, registered or not yet (a daemon still
    // starting is in no registry and would come up after the wipe below),
    // goes down with its whole process group.
    await sweepRuntimeProcesses(base);
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    rmSync(tmp, { recursive: true, force: true });
  }
});
