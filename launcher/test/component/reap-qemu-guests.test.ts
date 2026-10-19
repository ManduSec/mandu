/**
 * reap-qemu-guests (e2e) — a qemu guest leaked by a killed VM test run is
 * collected by `mandu reap`, and nothing else is (os-test-matrix.md §10.5,
 * runtime-instances.md §10).
 *
 * The real pieces: scripts/lib/guest-registry.sh (the registration every VM
 * harness makes) sourced by a stand-in harness, and the real `mandu` CLI. The
 * "guest" is a long-running process whose argv[0] is qemu-system-x86_64 and
 * which writes its own pidfile, as qemu's -pidfile does: no VM, no KVM. The
 * registry is scoped to a throwaway MANDU_RUNTIME_DIR.
 *
 *   1. owner alive: `mandu reap` (and --dry-run) leaves the guest and its dir;
 *   2. owner SIGKILLed: --dry-run lists it and touches nothing; `mandu reap`
 *      stops the guest and removes its work dir and entry;
 *   3. --keep: the guest is stopped, the work dir stays, the credential copy
 *      (alsoRemove) goes;
 *   4. an unregistered qemu-named process, and an entry whose pid now belongs
 *      to another process (start time differs), are never signalled.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runCli } from "../lib/run-cli.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
/** The registry reads /proc (a guest's start time, the boot id), and the qemu
 *  VM harnesses that register guests are Linux-only (fresh-install-testing.md
 *  §5): elsewhere a registration never completes. */
const SKIP = process.platform === "linux" ? false : "the guest registry is Linux-only (it reads /proc)";
const LIB = join(REPO, "scripts", "lib", "guest-registry.sh");

const HARNESS = `#!/usr/bin/env bash
set -uo pipefail
. "$GUEST_LIB"
W="$1" KEEP="$2"
mkdir -p "$W/artifacts/ephemeral"
echo disk > "$W/overlay.qcow2"; echo cred > "$W/artifacts/ephemeral/cred.json"
bash -c 'echo $$ > "$1"; exec -a qemu-system-x86_64 sleep 600' _ "$W/qemu.pid" </dev/null &
q=$!
guest_register "$q" "$W/qemu.pid" e2e "$W" "$KEEP" "$W/artifacts/ephemeral"
echo "READY $GUEST_REG_PID"
wait "$q"
`;

function alive(pid: number): boolean {
  try {
    const state = readFileSync(`/proc/${pid}/stat`, "utf8").split(") ")[1]!.split(" ")[0];
    return state !== "Z" && state !== "X";
  } catch {
    return false;
  }
}

async function until(cond: () => boolean, ms = 10_000): Promise<boolean> {
  for (const end = Date.now() + ms; Date.now() < end; ) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return cond();
}

interface Harness { proc: ChildProcess; guest: number; work: string; entry: string }

async function startHarness(root: string, env: Record<string, string>, name: string, keep: 0 | 1): Promise<Harness> {
  const script = join(root, "harness.sh");
  writeFileSync(script, HARNESS, { mode: 0o755 });
  const work = join(root, "work", name);
  const proc = spawn("bash", [script, work, String(keep)], {
    env: { ...env, PATH: process.env["PATH"] ?? "/usr/bin:/bin", GUEST_LIB: LIB },
    stdio: ["ignore", "pipe", "inherit"],
  });
  let out = "";
  proc.stdout!.setEncoding("utf8").on("data", (c: string) => { out += c; });
  assert.ok(await until(() => /READY \d+/.test(out)), `harness never registered its guest: ${out}`);
  const guest = Number(/READY (\d+)/.exec(out)![1]);
  return { proc, guest, work, entry: join(env["MANDU_RUNTIME_DIR"]!, "vm-guests", `e2e-${guest}.json`) };
}

async function killHarness(h: Harness): Promise<void> {
  const exited = new Promise((r) => h.proc.once("exit", r));
  h.proc.kill("SIGKILL"); // the leak: no EXIT trap, no guest_release
  await exited;
}

function withRoot(fn: (root: string, env: Record<string, string>, spawned: number[]) => Promise<void>): () => Promise<void> {
  return async () => {
    const root = mkdtempSync(join(tmpdir(), "mandu-reap-guests-e2e-"));
    const env = { MANDU_RUNTIME_DIR: join(root, "rt"), HOME: join(root, "home") };
    mkdirSync(env.HOME, { recursive: true });
    const spawned: number[] = [];
    try {
      await fn(root, env, spawned);
    } finally {
      for (const p of spawned) try { process.kill(p, "SIGKILL"); } catch { /* gone */ }
      rmSync(root, { recursive: true, force: true });
    }
  };
}

test("a live owner protects its guest; once the owner is killed, reap --dry-run lists it and reap stops and cleans it", { skip: SKIP }, withRoot(async (root, env, spawned) => {
  const h = await startHarness(root, env, "run", 0);
  spawned.push(h.guest, h.proc.pid!);
  assert.ok(alive(h.guest) && existsSync(h.entry));
  const entry = JSON.parse(readFileSync(h.entry, "utf8"));
  assert.equal(entry.ownerPid, h.proc.pid, "the owner is the harness process");

  for (const argv of [["reap", "--dry-run"], ["reap"]]) {
    const r = await runCli(argv, env);
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /nothing to reap/, `owner alive: ${argv.join(" ")} plans nothing for the guest`);
  }
  assert.ok(alive(h.guest) && existsSync(h.work) && existsSync(h.entry), "owner alive: guest, dir and entry untouched");

  await killHarness(h);
  assert.ok(alive(h.guest), "the killed harness leaked its guest");

  const dry = await runCli(["reap", "--dry-run"], env);
  assert.equal(dry.code, 0, dry.stderr);
  assert.match(dry.stdout, new RegExp(`would kill-orphan-guest: e2e e2e-${h.guest}: owner ${h.proc.pid} is gone; stop qemu pid ${h.guest}; remove ${h.work}`));
  assert.ok(alive(h.guest) && existsSync(h.work) && existsSync(h.entry), "--dry-run touches nothing");

  const status = await runCli(["status"], env);
  assert.match(status.stdout, /1 test VM from ended runs/);

  const r = await runCli(["reap"], env);
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /kill-orphan-guest: e2e /);
  assert.ok(await until(() => !alive(h.guest)), "the leaked guest is stopped");
  assert.ok(!existsSync(h.work), "its work dir (overlay, credential copy) is removed");
  assert.ok(!existsSync(h.entry), "and its entry");
  assert.match((await runCli(["reap", "--dry-run"], env)).stdout, /nothing to reap/);
}));

test("--keep: the leaked guest is stopped, its work dir kept, the credential copy removed", { skip: SKIP }, withRoot(async (root, env, spawned) => {
  const h = await startHarness(root, env, "kept", 1);
  spawned.push(h.guest, h.proc.pid!);
  await killHarness(h);
  const r = await runCli(["reap"], env);
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.ok(await until(() => !alive(h.guest)));
  assert.ok(existsSync(join(h.work, "overlay.qcow2")), "the kept overlay stays for a post-mortem");
  assert.ok(!existsSync(join(h.work, "artifacts", "ephemeral")), "the credential copy never outlives its guest");
  assert.ok(!existsSync(h.entry));
}));

test("an unregistered qemu and a registered pid now owned by another process are never signalled", { skip: SKIP }, withRoot(async (root, env, spawned) => {
  // An unregistered process that looks exactly like a guest.
  const stray = spawn("bash", ["-c", "exec -a qemu-system-x86_64 sleep 600"], { stdio: "ignore" });
  // A bystander holding a pid an entry names, with another start time (a reused pid).
  const bystander = spawn("bash", ["-c", "exec -a qemu-system-x86_64 sleep 600"], { stdio: "ignore" });
  spawned.push(stray.pid!, bystander.pid!);
  const deadOwner = spawnSync("bash", ["-c", "echo $$"], { encoding: "utf8" }).stdout.trim();
  const work = join(root, "work", "stale");
  mkdirSync(work, { recursive: true });
  const dir = join(env.MANDU_RUNTIME_DIR, "vm-guests");
  mkdirSync(dir, { recursive: true });
  const entry = join(dir, `e2e-${bystander.pid}.json`);
  await until(() => alive(stray.pid!) && alive(bystander.pid!));
  writeFileSync(entry, JSON.stringify({ kind: "qemu-guest", harness: "e2e", pid: bystander.pid, pidStart: 1, ownerPid: Number(deadOwner), ownerStart: 1, workDir: work }));

  const r = await runCli(["reap"], env);
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.match(r.stdout, new RegExp(`rm-dead-guest: e2e e2e-${bystander.pid}: owner ${deadOwner} is gone, guest pid ${bystander.pid} stopped`));
  await new Promise((res) => setTimeout(res, 300));
  assert.ok(alive(stray.pid!), "the unregistered qemu is untouched");
  assert.ok(alive(bystander.pid!), "the reused pid is never signalled");
  assert.ok(!existsSync(entry) && !existsSync(work), "the stale entry and its dir go");
  assert.deepEqual(readdirSync(dir), []);
}));
