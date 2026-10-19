/**
 * ssh-config-write-protect (sandbox) — P0 (D), 2026-10-07: a file ssh reads
 * as configuration waits for the human, under the REAL guard
 * (write-protection.md §2; confidentiality plan 13 §3 D8, "a configuration
 * file the reader reads").
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around a
 *   bash, with the write-protect list the launcher builds in production
 *   (`writeProtectList`, real file reads) for a throwaway HOME whose
 *   `~/.ssh/config` says `Include config.d/*`, and a real ArbiterServer that
 *   answers the guard's `decideProtectedWrite` (nobody answers the Inbox: a
 *   held change is refused at the ceiling).
 *
 * ssh reads a key raw (a vetted reader, plan 13 D8 (12)); a configuration
 * file the agent writes decides what ssh opens. The oracle: the agent cannot
 * add a file to the included directory, change one there, move `~/.ssh`
 * aside, or put a planted directory in its place; an ordinary file
 * elsewhere in the HOME is written at once (the control).
 * Red before: only `~/.ssh/config` itself was on the list (the include
 * directory was writable), and a rename at an ancestor of an entry was not
 * judged at all.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { writeProtectList } from "../../../launcher/src/write-protect.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode, whose guard enforces the list

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
/** The human's ssh config: a directory of includes, and OrbStack's file. */
const CONFIG = "Include config.d/*\nHost *.orb\n  Include ~/.orbstack/ssh/config\n";
const skip = process.platform !== "linux" ? "Linux only" : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;

function runGuarded(script: string, env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((ok) => {
    const child = spawn(GUARD.path!, ["--allow", "127.0.0.0/8:*", "--", "bash", "-c", script], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += String(c)));
    child.stderr.on("data", (c) => (stderr += String(c)));
    const timer = setTimeout(() => child.kill("SIGKILL"), 120_000);
    child.on("close", (status) => { clearTimeout(timer); ok({ stdout, stderr, status }); });
  });
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("a file ssh includes, and the directory above it, wait for the human under the REAL guard; an ordinary file does not (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-ssh-wp-"));
  const home = join(tmp, "home");
  const ssh = join(home, ".ssh");
  mkdirSync(join(ssh, "config.d"), { recursive: true });
  writeFileSync(join(ssh, "config"), CONFIG);
  writeFileSync(join(ssh, "config.d", "work.conf"), "Host work\n  HostName work.example.com\n");
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const sock = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  try {
    // The production list for this HOME (the account's real home left out:
    // only the fixture is under test), as the launcher hands it to the guard.
    const list = writeProtectList({ HOME: home }, tmp, undefined, sock, undefined, () => {}, [], "linux", null);
    assert.ok(list.some((e) => e.path === join(ssh, "config.d") && e.answer === "ask" && e.label === "an ssh setting"), "the included directory is on the list");
    const secretPolicy = join(tmp, "secret-policy.json");
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: "", ask: "never", session: `ssh-wp-${process.pid}`, askTimeoutMs: 1000, secrets: [], writeProtect: list }));
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy, MANDU_NET_GUARD_PROTECT: "1" };
    const script = [
      `cd "$HOME"`,
      `echo "Host x" > .ssh/config.d/new.conf 2>/dev/null && echo new:ok || echo new:refused`,
      `echo "Host y" >> .ssh/config.d/work.conf 2>/dev/null && echo append:ok || echo append:refused`,
      `mkdir -p planted/config.d && mv .ssh .ssh.old 2>/dev/null && echo aside:ok || echo aside:refused`,
      // An included file whose directory does not exist yet: a planted
      // directory renamed into the place of its missing parent.
      `mkdir -p planted2/ssh && echo "Host z" > planted2/ssh/config && mv -T planted2 .orbstack 2>/dev/null && echo replace:ok || echo replace:refused`,
      `echo notes > notes.txt 2>/dev/null && echo control:ok || echo control:refused`,
    ].join("\n");
    const run = await runGuarded(script, env);
    if (!/control:/.test(run.stdout) && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr)) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    const got = Object.fromEntries(run.stdout.trim().split("\n").filter((l) => l.includes(":")).map((l) => l.split(":") as [string, string]));
    assert.equal(got["control"], "ok", `the control write: ${run.stdout}\n${run.stderr}`);
    assert.deepEqual({ new: got["new"], append: got["append"], aside: got["aside"], replace: got["replace"] },
      { new: "refused", append: "refused", aside: "refused", replace: "refused" }, `${run.stdout}\n${run.stderr}`);
    // And on disk: ssh's configuration is as the human left it.
    assert.deepEqual(readdirSync(join(ssh, "config.d")).sort(), ["work.conf"]);
    assert.equal(readFileSync(join(ssh, "config.d", "work.conf"), "utf8"), "Host work\n  HostName work.example.com\n");
    assert.equal(readFileSync(join(ssh, "config"), "utf8"), CONFIG);
    assert.ok(!existsSync(join(home, ".ssh.old")), "~/.ssh was not moved aside");
    assert.ok(!existsSync(join(home, ".orbstack")), "no planted directory took the place of an included file's missing parent");
  } finally {
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
