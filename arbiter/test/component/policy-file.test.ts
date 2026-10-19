/**
 * policy-file e2e — the daemon's boot contract for the data-law document
 * (policy-surface.md §2.1, stage 2), through the REAL
 * `ipc/server-main.ts`:
 *   - an INVALID file (unparseable or malformed) → the arbiter refuses to
 *     start, exits non-zero, and names the file and every problem;
 *   - a VALID file → boots, the engine consumes it, and `policySnapshot`
 *     reports `lawSource.kind === "file"` with the sections it set;
 *   - NO file at the resolved path → boots on the built-ins and the law
 *     source says so, naming the path it looked for (`found:false`).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function daemon(dir: string, policyFile: string): { child: ChildProcess; sock: string; stderr: () => string } {
  const sock = join(dir, "arbiter.sock");
  let err = "";
  const child = spawn(process.execPath, ["--import", "tsx", "ipc/server-main.ts"], {
    cwd: ARBITER_DIR,
    env: {
      ...process.env,
      MANDU_ARBITER_SOCK: sock,
      MANDU_RUNTIME_DIR: join(dir, "rt"),
      MANDU_HOME: join(dir, "home"),
      MANDU_POLICY_FILE: policyFile,
      MANDU_INBOUND_SPEC: "",
      MANDU_TENANT: "",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stderr!.on("data", (d: Buffer) => (err += d.toString()));
  return { child, sock, stderr: () => err };
}

async function waitFor(pred: () => boolean, ms: number, what: () => string): Promise<void> {
  const deadline = Date.now() + ms;
  while (!pred()) {
    if (Date.now() > deadline) assert.fail(`timed out: ${what()}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

/**
 * A client connected to the daemon's socket. The socket file appears when
 * the daemon binds, a moment before it listens; on a loaded host a connect in
 * between is refused (ECONNREFUSED, seen in CI), so a refusal is retried until
 * the deadline, or until the daemon exits.
 */
async function connected(d: { child: ChildProcess; sock: string; stderr: () => string }, ms: number): Promise<ArbiterClient> {
  const deadline = Date.now() + ms;
  for (;;) {
    const client = new ArbiterClient(d.sock);
    try {
      await client.connect();
      return client;
    } catch (e) {
      client.close();
      if (d.child.exitCode !== null) assert.fail(`daemon exited:\n${d.stderr()}`);
      if (Date.now() > deadline) assert.fail(`no connection to ${d.sock}: ${(e as Error).message}\n${d.stderr()}`);
      await new Promise((r) => setTimeout(r, 100));
    }
  }
}

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await new Promise<void>((r) => child.once("exit", () => r()));
}

test("an invalid policy file → the daemon refuses to start and names the file + problems", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-"));
  try {
    const bad = join(dir, "policy.yaml");
    writeFileSync(bad, "inbound:\n  url:\n    default: SOMETIMES\n    trustedList: 3\n");
    const d = daemon(dir, bad);
    await waitFor(() => d.child.exitCode !== null, 30_000, () => `daemon still running; stderr:\n${d.stderr()}`);
    assert.notEqual(d.child.exitCode, 0, "a refused start exits non-zero");
    assert.match(d.stderr(), /policy file .*policy\.yaml is invalid/);
    assert.match(d.stderr(), /inbound\.url\.default: must be TRUSTED or UNTRUSTED/);
    assert.match(d.stderr(), /inbound\.url\.trustedList: must be a list of strings/);
    assert.ok(!existsSync(join(dir, "arbiter.sock")), "no socket was ever bound");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a valid policy file → boots; policySnapshot.lawSource is 'file' with the sections it set", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-"));
  const good = join(dir, "policy.yaml");
  writeFileSync(
    good,
    [
      "inbound:",
      "  url:",
      "    default: UNTRUSTED",
      '    trustedList: ["https://docs.python.org/"]',
      "  command:",
      "    - id: git",
      "tools:",
      "  Read:",
      "    outbound: not_resolve",
      "",
    ].join("\n"),
  );
  const d = daemon(dir, good);
  t.after(async () => {
    await stop(d.child);
    rmSync(dir, { recursive: true, force: true });
  });
  await waitFor(() => existsSync(d.sock) || d.child.exitCode !== null, 30_000, () => d.stderr());
  assert.equal(d.child.exitCode, null, `daemon exited early:\n${d.stderr()}`);
  const client = await connected(d, 30_000);
  try {
    const snap = (await client.policySnapshot()) as { lawSource?: { kind: string; found?: boolean; resolvedPath?: string; sections?: Record<string, unknown> } };
    assert.equal(snap.lawSource?.kind, "file");
    assert.equal(snap.lawSource?.found, true);
    assert.equal(snap.lawSource?.resolvedPath, good);
    assert.deepEqual(snap.lawSource?.sections, { url: true, channel: false, dir: false, commandEntries: 1, toolOverrides: 1 });
    assert.match(d.stderr(), /policy file: .*policy\.yaml \(url:set channel:- dir:- commands:1 tools:1\)/);
  } finally {
    client.close();
  }
});

test("no file at the resolved path → boots on the built-ins; the law source names the path it looked for", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-"));
  const missing = join(dir, "nowhere", "policy.yaml");
  const d = daemon(dir, missing);
  t.after(async () => {
    await stop(d.child);
    rmSync(dir, { recursive: true, force: true });
  });
  await waitFor(() => existsSync(d.sock) || d.child.exitCode !== null, 30_000, () => d.stderr());
  assert.equal(d.child.exitCode, null, `daemon exited early:\n${d.stderr()}`);
  const client = await connected(d, 30_000);
  try {
    const snap = (await client.policySnapshot()) as { lawSource?: { kind: string; found?: boolean; configuredPath?: string } };
    assert.equal(snap.lawSource?.kind, "builtin");
    assert.equal(snap.lawSource?.found, false);
    assert.equal(snap.lawSource?.configuredPath, missing);
    assert.match(d.stderr(), /policy file: none at .*nowhere\/policy\.yaml — the built-in policy is the whole law/);
  } finally {
    client.close();
  }
});
