/**
 * e2e: the REAL daemon entrypoint (server-main) refuses to start while
 * Mandu's state directory is a symlink to a directory outside the home
 * (confidentiality-plan-14 §11.2 residual (c), db/store-links.ts).
 *
 * An unconfined process (an `off` session, a `gated` launch with no wall)
 * swaps `~/.mandu/state` for a symlink to a directory of its own. Every
 * layer that keeps a confined agent out of the stores names the home, so
 * the symbol DB the daemon then opens through the link (every original
 * behind a `$MDU:` placeholder, from every later launch) is readable and
 * writable by every later confined agent. On master `746331a9` the daemon
 * started and created `mandu.db` in the planted directory. Now it refuses
 * and writes nothing there; with the layout sound it starts.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CURRENT_LINK } from "../../ipc/instance.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");
const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

/** Start the daemon with the home's default stores; resolve when it is up
 *  (its socket exists) or exited. */
async function start(root: string): Promise<{ code: number | null; stderr: string; stop: () => Promise<void> }> {
  const base = join(root, "rt");
  const child = spawn(process.execPath, ["--import", "tsx", SERVER_MAIN], {
    cwd: ARBITER_DIR,
    env: {
      ...process.env, HOME: join(root, "home"), MANDU_HOME: join(root, "home", ".mandu"), MANDU_RUNTIME_DIR: base,
      MANDU_ARBITER_SOCK: "", MANDU_ARBITER_HUMAN_SOCK: "", MANDU_PROMOTE: "1", MANDU_MODE: "secrets",
      MANDU_POLICY_FILE: join(root, "policy.yaml"),
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr!.setEncoding("utf8");
  child.stderr!.on("data", (c: string) => { stderr += c; });
  const sock = join(base, CURRENT_LINK, "arbiter.sock");
  const t0 = Date.now();
  while (Date.now() - t0 < 90_000 && !existsSync(sock) && child.exitCode === null) await new Promise((r) => setTimeout(r, 100));
  return {
    code: child.exitCode,
    stderr,
    stop: () => new Promise<void>((resolve) => {
      if (child.exitCode !== null) return resolve();
      child.once("exit", () => resolve());
      child.kill("SIGTERM");
    }),
  };
}

test("e2e: the daemon refuses to start with ~/.mandu/state swapped for a symlink outside the home, and writes nothing there; a sound home starts", { timeout: 240_000 }, async () => {
  // A short prefix: the instance socket lands deep under it (rt/instances/<id>/
  // arbiter.sock, 107-byte sun_path) and a suite's TMPDIR is longer than /tmp
  // (test-organization.md §8.5).
  const root = mkdtempSync(join(tmpdir(), "mdu-sld-"));
  dirs.push(root);
  writeFileSync(join(root, "policy.yaml"), "version: 1\n");
  const mh = join(root, "home", ".mandu");
  mkdirSync(mh, { recursive: true, mode: 0o700 });
  const planted = join(root, "planted");
  mkdirSync(planted, { mode: 0o700 });
  symlinkSync(planted, join(mh, "state"));

  const refused = await start(root);
  await refused.stop();
  // MASTER: the daemon came up and created planted/mandu.db
  assert.equal(refused.code, 1, `the daemon must refuse (stderr: ${refused.stderr})`);
  assert.match(refused.stderr, /refusing to start: Mandu's stores must lie inside its home/);
  assert.match(refused.stderr, /state resolves to .*planted/);
  assert.ok(!existsSync(join(planted, "mandu.db")), "no store was written into the planted directory");

  // The fix the message names: the state back inside the home.
  rmSync(join(mh, "state"));
  const ok = await start(root);
  try {
    assert.equal(ok.code, null, `a sound home starts (stderr: ${ok.stderr})`);
  } finally { await ok.stop(); }
});
