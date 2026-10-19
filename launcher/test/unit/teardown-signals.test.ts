/**
 * teardown-signals.test — the launcher's signal policy for its teardown
 * window (src/teardown-signals.ts; portable-wrapper.md §2.1 "Teardown
 * signals"; differential-interactive.md §21):
 *   - SIGINT is ignored every time, the first press explains itself once;
 *   - SIGTERM / SIGHUP / SIGQUIT keep the default action (no handler);
 *   - the guard installs exactly one SIGINT listener and removes it, unless it
 *     holds until the process exits (the CLI entry's hand-off).
 * The last two tests run the guard in a real node process and signal it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createTeardownGuard,
  teardownSignalAction,
  teardownSigintNote,
  type SignalHost,
} from "../../src/teardown-signals.js";

const MODULE = resolve(fileURLToPath(import.meta.url), "..", "..", "..", "src", "teardown-signals.ts");

test("policy: SIGINT is ignored; SIGTERM, SIGHUP and SIGQUIT keep their default action", () => {
  assert.equal(teardownSignalAction("SIGINT"), "ignore");
  assert.equal(teardownSignalAction("SIGTERM"), "default");
  assert.equal(teardownSignalAction("SIGHUP"), "default");
  assert.equal(teardownSignalAction("SIGQUIT"), "default");
});

test("note: only the first ^C prints, and it names the pid to kill to end it now", () => {
  const first = teardownSigintNote(1, 4242);
  assert.ok(first);
  assert.match(first!, /\^C is ignored until that is done/);
  assert.match(first!, /kill 4242/);
  for (const n of [2, 3, 10]) assert.equal(teardownSigintNote(n, 4242), null, `press ${n} stays quiet`);
});

/** A fake `process`: an emitter with a pid. */
function fakeHost(): EventEmitter & SignalHost {
  const e = new EventEmitter() as EventEmitter & { pid: number };
  e.pid = 99;
  return e as EventEmitter & SignalHost;
}

test("guard: arm installs ONE SIGINT listener and nothing for SIGTERM/SIGHUP; disarm removes it; both idempotent", () => {
  const host = fakeHost();
  const g = createTeardownGuard({ note: () => {}, host });
  assert.equal(g.armed, false);
  g.arm();
  g.arm();
  assert.equal(g.armed, true);
  assert.equal(host.listenerCount("SIGINT"), 1);
  assert.equal(host.listenerCount("SIGTERM"), 0);
  assert.equal(host.listenerCount("SIGHUP"), 0);
  g.disarm();
  g.disarm();
  assert.equal(g.armed, false);
  assert.equal(host.listenerCount("SIGINT"), 0);
});

test("guard: every ^C is counted and swallowed; the note prints once; a throwing note sink is contained", () => {
  const host = fakeHost();
  const notes: string[] = [];
  const g = createTeardownGuard({ note: (l) => { notes.push(l); throw new Error("EIO"); }, host });
  g.arm();
  for (let i = 0; i < 5; i++) host.emit("SIGINT");
  assert.equal(g.presses, 5);
  assert.equal(notes.length, 1);
  assert.match(notes[0]!, /kill 99/);
  g.disarm();
  host.emit("SIGINT"); // no listener: nothing counted
  assert.equal(g.presses, 5);
});

test("guard: holdUntilExit keeps the handler past disarm (armed stays true, ^Cs still swallowed)", () => {
  const host = fakeHost();
  const g = createTeardownGuard({ note: () => {}, host, holdUntilExit: true });
  g.arm();
  g.disarm();
  assert.equal(g.armed, true);
  assert.equal(host.listenerCount("SIGINT"), 1, "removing it would give SIGINT its default action before the exit");
  host.emit("SIGINT");
  assert.equal(g.presses, 1);
});

/** Run the guard in a real node process: arm, then report ready and wait. */
function guardedChild(): ReturnType<typeof spawn> {
  const src = `
    import { createTeardownGuard } from ${JSON.stringify(MODULE)};
    const g = createTeardownGuard({ note: (l) => process.stderr.write(l + "\\n") });
    g.arm();
    process.stdout.write("armed\\n");
    // A teardown that takes a while: end on its own after 1.5 s with the
    // number of presses it swallowed as the exit code.
    setTimeout(() => { g.disarm(); process.exit(g.presses); }, 1500);
  `;
  return spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", src], {
    cwd: resolve(MODULE, "..", ".."),
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function waitArmed(child: ReturnType<typeof spawn>): Promise<void> {
  await new Promise<void>((res, rej) => {
    let out = "";
    child.stdout!.on("data", (d) => { out += String(d); if (out.includes("armed")) res(); });
    child.on("exit", () => rej(new Error("child exited before arming")));
  });
}

test("a real process with the guard armed survives three SIGINTs and finishes its teardown", { timeout: 20_000 }, async () => {
  const child = guardedChild();
  let stderr = "";
  child.stderr!.on("data", (d) => { stderr += String(d); });
  await waitArmed(child);
  for (let i = 0; i < 3; i++) {
    child.kill("SIGINT");
    await new Promise((r) => setTimeout(r, 50));
  }
  const [code, sig] = await new Promise<[number | null, NodeJS.Signals | null]>((r) => child.on("exit", (c, s) => r([c, s])));
  assert.equal(sig, null, "not killed by the SIGINTs");
  assert.equal(code, 3, "ran to its end and counted three presses");
  assert.equal(stderr.match(/\^C is ignored/g)?.length, 1, `one note, got: ${stderr}`);
});

/** The CLI entry's shape: hand off to the exit, arm, disarm, then a slow
 *  exit (an 'exit' handler that busy-waits 1 s stands in for process.exit's
 *  own shutdown, which is where a ^C used to kill the launcher 130). */
function exitingChild(hold: boolean): ReturnType<typeof spawn> {
  const src = `
    import { createTeardownGuard, holdTeardownGuardsUntilExit } from ${JSON.stringify(MODULE)};
    if (${hold}) holdTeardownGuardsUntilExit();
    const g = createTeardownGuard({ note: () => {} });
    g.arm();
    g.disarm();
    process.on("exit", () => { const end = Date.now() + 1000; while (Date.now() < end) { /* the exit's shutdown */ } });
    process.stdout.write("armed\\n");
    setTimeout(() => process.exit(0), 200);
  `;
  return spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", src], {
    cwd: resolve(MODULE, "..", ".."),
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function sigintDuringExit(hold: boolean): Promise<[number | null, NodeJS.Signals | null]> {
  const child = exitingChild(hold);
  const exited = new Promise<[number | null, NodeJS.Signals | null]>((r) => child.on("exit", (c, s) => r([c, s])));
  await waitArmed(child);
  await new Promise((r) => setTimeout(r, 600)); // inside the exit's 1 s shutdown
  child.kill("SIGINT");
  return exited;
}

test("held until exit: a SIGINT during process.exit's own shutdown is swallowed, the exit code stands", { timeout: 20_000 }, async () => {
  assert.deepEqual(await sigintDuringExit(true), [0, null]);
});

test("control: a guard disarmed before the exit leaves that shutdown to SIGINT's default action", { timeout: 20_000 }, async () => {
  assert.deepEqual(await sigintDuringExit(false), [null, "SIGINT"]);
});

test("a real process with the guard armed still ends at once on SIGTERM", { timeout: 20_000 }, async () => {
  const child = guardedChild();
  await waitArmed(child);
  const t0 = Date.now();
  child.kill("SIGTERM");
  const [code, sig] = await new Promise<[number | null, NodeJS.Signals | null]>((r) => child.on("exit", (c, s) => r([c, s])));
  assert.equal(sig, "SIGTERM", `ended by the signal, not by finishing (code ${code})`);
  assert.ok(Date.now() - t0 < 1000, "promptly, not after the 1.5 s teardown");
});
