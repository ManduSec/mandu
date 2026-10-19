/**
 * log-dir-planted.test — E2E with the real spawners: a log's DIRECTORY that
 * is a link gets no log (runtime-instances.md §2, "planted paths",
 * 2026-10-17). Until then only the log's last component was checked: the
 * agent (same uid, where no write-protect list applies) could swap
 * `<runtime base>/logs` for a link to any folder, and the next launch's
 * arbiter autostart created `arbiter-autostart.log` there and appended the
 * daemon's output to it; a dangling link had its target folder made by the
 * `mkdir -p` before the open.
 *
 *   - `startArbiterInstance` (the launch's autostart, the real dev-layout
 *     spawner over stand-in services) with `<base>/logs` a link to a folder:
 *     the start is refused before anything is spawned, the folder gets
 *     nothing;
 *   - the same with a dangling link: its target is not made;
 *   - `startDetachedCmd` (every session service) with the scope dir reached
 *     through a link of this user's: refused, nothing written there.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // the children's caches go to temp, not the real HOME (test-organization.md §8.4)
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pollSocket, startArbiterInstance } from "../../src/arbiter.js";
import { Layout } from "../../src/services/layout.js";
import { startDetachedCmd } from "../../src/services/primitives.js";
import { stateAxes } from "../axes.js";
import { standInService } from "../lib/stand-in-service.js";
import { sweepRuntimeProcesses } from "../lib/runtime-sweep.js";

stateAxes("off"); // file handling at a service's start: no arbiter decides anything here

/** A stand-in that records it ran, then exits. */
const RAN = `
import { writeFileSync } from "node:fs";
writeFileSync(process.env.FAKE_DIR + "/" + process.env.FAKE_NAME + ".ran", "");
`;

function setup(): { tmp: string; repo: string; base: string; victim: string; fake: string } {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-logdir-")));
  const repo = join(tmp, "repo");
  standInService(repo, "dashboard", "dashboard", RAN.replace("process.env.FAKE_NAME", '"dashboard"'));
  standInService(repo, "arbiter", "arbiter", RAN.replace("process.env.FAKE_NAME", '"arbiter"'));
  const base = join(tmp, "mandu");
  mkdirSync(base, { mode: 0o700 });
  const victim = join(tmp, "victim");
  mkdirSync(victim);
  writeFileSync(join(victim, "keep"), "keep\n");
  const fake = join(tmp, "fake");
  mkdirSync(fake);
  return { tmp, repo, base, victim, fake };
}

async function autostart(s: ReturnType<typeof setup>): Promise<{ error: Error | null }> {
  const start = startArbiterInstance(Layout.dev(s.repo), s.base, join(s.base, "logs", "arbiter-autostart.log"), {}, {
    env: { ...process.env, FAKE_DIR: s.fake, MANDU_RUNTIME_DIR: s.base },
    runtimeEnv: { ...process.env, MANDU_RUNTIME_DIR: s.base },
    account: null,
    waitForSocket: (sock, tries, delay) => pollSocket(sock, Math.min(tries, 5), delay),
    supervisorGraceMs: 500,
    log: () => {},
    info: () => {},
  });
  try {
    await start();
    return { error: null };
  } catch (e) {
    return { error: e as Error };
  }
}

test("the arbiter's autostart log: a <base>/logs that is a link to a folder refuses the start, the folder gets nothing", { timeout: 60_000 }, async () => {
  const s = setup();
  try {
    symlinkSync(s.victim, join(s.base, "logs"));
    const r = await autostart(s);
    assert.match(String(r.error?.message), /logs is a symbolic link on the way to the log/, String(r.error?.stack));
    assert.deepEqual(readdirSync(s.victim), ["keep"], "no arbiter-autostart.log in the linked-to folder");
    assert.deepEqual(readdirSync(s.fake), [], "nothing was spawned");
  } finally {
    await sweepRuntimeProcesses(s.base);
    rmSync(s.tmp, { recursive: true, force: true });
  }
});

test("the arbiter's autostart log: a dangling <base>/logs link has no folder made at its target", { timeout: 60_000 }, async () => {
  const s = setup();
  try {
    const target = join(s.tmp, "elsewhere", "deeper");
    symlinkSync(target, join(s.base, "logs"));
    const r = await autostart(s);
    assert.match(String(r.error?.message), /symbolic link on the way/, String(r.error?.stack));
    assert.equal(existsSync(join(s.tmp, "elsewhere")), false, "the link's target folder was not made");
  } finally {
    await sweepRuntimeProcesses(s.base);
    rmSync(s.tmp, { recursive: true, force: true });
  }
});

test("a session service's log: a scope dir reached through a link of this user's is refused, nothing written there", { timeout: 60_000 }, () => {
  const s = setup();
  try {
    symlinkSync(s.victim, join(s.base, "123-456"));
    assert.throws(
      () => startDetachedCmd(process.execPath, ["-e", "0"], { cwd: s.tmp, env: process.env }, join(s.base, "123-456", "net-proxy.log")),
      /123-456 is a symbolic link on the way to the log/,
    );
    assert.deepEqual(readdirSync(s.victim), ["keep"]);
  } finally {
    rmSync(s.tmp, { recursive: true, force: true });
  }
});
