/**
 * scope-dir-planted.test — E2E: the real launcher never adopts a scope dir
 * someone prepared, and never takes a scope id that names one of Mandu's own
 * runtime entries (src/scope-dir.ts, src/runtime-registry.ts;
 * runtime-instances.md §2 "planted paths").
 *
 * The runtime base stays writable to the agent, and a minted scope id is
 * predictable (`<epochSec>-<pid>`): an agent could make a FUTURE launch's
 * scope dir in advance, with links in it, for the launcher and its services
 * (which run outside any confinement) to write through. Here a wrapper plants
 * exactly that for its own pid over the next seconds, then runs the real
 * main() in the same process, so the id the launcher mints is one it planted.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { once } from "node:events";
import { createServer, type Server } from "node:net";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";
import { axesEnv, stateAxes } from "../axes.js";

stateAxes("off"); // the refusals come before any service starts or any axis is read

const LAUNCHER_ROOT = resolve(fileURLToPath(import.meta.url), "..", "..", "..");
const RUN_TS = pathToFileURL(join(LAUNCHER_ROOT, "src", "run.ts")).href;
const TSX_LOADER = pathToFileURL(join(LAUNCHER_ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;

/** The wrapper: plant `<base>/<sec>-<own pid>` for the next seconds (a link
 *  to the victim folder, or a real dir holding `launch.log` -> the victim
 *  file), then run the launcher's main() in this very process. */
const WRAPPER = `
import { mkdirSync, symlinkSync } from "node:fs";
const base = process.env.PLANT_BASE, victim = process.env.PLANT_VICTIM, how = process.env.PLANT_HOW;
mkdirSync(base, { recursive: true, mode: 0o700 });
const now = Math.floor(Date.now() / 1000);
for (let s = now - 1; s <= now + 60; s++) {
  const d = base + "/" + s + "-" + process.pid;
  if (how === "link") symlinkSync(victim, d);
  else { mkdirSync(d); symlinkSync(victim + "/notes.txt", d + "/launch.log"); }
}
const { main } = await import(process.env.RUN_TS);
main(process.argv.slice(2)).then((c) => process.exit(c), (e) => { console.error(e instanceof Error ? e.message : String(e)); process.exit(2); });
`;

interface Run { code: number | null; stderr: string }

async function run(argv: string[], env: Record<string, string | undefined>, entry: string[]): Promise<Run> {
  // In the launch's folder (env.PWD), as a shell starts it: the launcher
  // launches for its real cwd (launch-cwd.ts), so tsx is imported by path.
  const child = spawn(process.execPath, ["--import", TSX_LOADER, ...entry, ...argv], {
    cwd: env["PWD"] ?? LAUNCHER_ROOT, stdio: ["ignore", "ignore", "pipe"], env: env as NodeJS.ProcessEnv,
  });
  let stderr = "";
  child.stderr!.on("data", (d) => { stderr += String(d); });
  const [code] = await once(child, "exit") as [number | null];
  return { code, stderr };
}

/** A scratch runtime dir, a victim folder, and a mock arbiter to attach to
 *  (the launch makes its scope dir once the arbiter is up). */
async function fixture(): Promise<{ dir: string; base: string; victim: string; env: Record<string, string | undefined>; cleanup: () => Promise<void> }> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-scope-planted-"));
  const victim = join(dir, "victim");
  mkdirSync(victim);
  writeFileSync(join(victim, "notes.txt"), "keep me\n");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(join(dir, "arbiter.sock"));
  await once(srv, "listening");
  const env = {
    HOME: process.env["HOME"], PATH: process.env["PATH"], PWD: dir, XDG_RUNTIME_DIR: dir,
    MANDU_ARBITER_SOCK: join(dir, "arbiter.sock"), MANDU_NO_ARBITER_AUTOSTART: "1", MANDU_HOME: join(dir, "mandu-home"),
    ...axesEnv("off"),
  };
  const cleanup = async (): Promise<void> => {
    srv.close();
    rmSync(dir, { recursive: true, force: true });
  };
  return { dir, base: join(dir, "mandu"), victim, env, cleanup };
}

const LAUNCH = ["--target", "claude", "--no-net-proxy", "--no-scope", "--no-reply-filter", "--", "bash", "-c", "exit 0"];

for (const how of ["link", "dir"] as const) {
  test(`a minted scope dir made in advance (${how === "link" ? "a link to someone's folder" : "a real dir with a link planted inside"}) REFUSES the launch; nothing is written through it`, { timeout: 120_000 }, async () => {
    const f = await fixture();
    try {
      const wrapper = join(f.dir, "plant-then-launch.mjs");
      writeFileSync(wrapper, WRAPPER);
      const r = await run(LAUNCH, { ...f.env, PLANT_BASE: f.base, PLANT_VICTIM: f.victim, PLANT_HOW: how, RUN_TS }, [wrapper]);
      assert.equal(r.code, 2, r.stderr);
      assert.match(r.stderr, /refusing to launch: the session folder .* already exists, and this launch did not make it/, r.stderr);
      assert.deepEqual(readdirSync(f.victim), ["notes.txt"], "nothing was created in the linked folder");
      assert.equal(readFileSync(join(f.victim, "notes.txt"), "utf8"), "keep me\n", "nothing was written through the planted launch.log");
    } finally {
      await f.cleanup();
    }
  });
}

test("a scope id that names one of Mandu's runtime entries, or is not one folder name, is refused before anything is made", { timeout: 120_000 }, async () => {
  const f = await fixture();
  try {
    for (const id of ["instances", "logs", "dashboard.log", "instances/x", ".."]) {
      const r = await run(["--id", id, ...LAUNCH], f.env, [join(LAUNCHER_ROOT, "src", "run.ts")]);
      assert.equal(r.code, 2, `${id}: ${r.stderr}`);
      assert.match(r.stderr, /cannot name a session/, `${id}: ${r.stderr}`);
    }
    assert.equal(existsSync(f.base), false, "no runtime dir, registry or scope dir was made");
    // Through the environment too (a harness's MANDU_SCOPE_ID).
    const env = await run(LAUNCH, { ...f.env, MANDU_SCOPE_ID: "current" }, [join(LAUNCHER_ROOT, "src", "run.ts")]);
    assert.equal(env.code, 2, env.stderr);
    assert.match(env.stderr, /"current" cannot name a session: `current` is one of Mandu's own entries in the runtime folder/);
  } finally {
    await f.cleanup();
  }
});

test("a named scope whose folder is a link is refused; nothing is written through it", { timeout: 120_000 }, async () => {
  const f = await fixture();
  try {
    mkdirSync(f.base, { recursive: true, mode: 0o700 });
    symlinkSync(f.victim, join(f.base, "named-scope"));
    const r = await run(["--id", "named-scope", ...LAUNCH], f.env, [join(LAUNCHER_ROOT, "src", "run.ts")]);
    assert.equal(r.code, 2, r.stderr);
    assert.match(r.stderr, /the session folder .*named-scope is not a real directory \(a link or a file\)/);
    assert.deepEqual(readdirSync(f.victim), ["notes.txt"]);
  } finally {
    await f.cleanup();
  }
});
