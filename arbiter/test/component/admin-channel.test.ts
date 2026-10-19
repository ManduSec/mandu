/**
 * admin-channel e2e — the human/agent boundary on the arbiter IPC
 * (docs/design/ui/policy-surface.md §2.6, finding F5).
 *
 * WHAT IS PROVEN, over the real wire:
 *   1. every op in ADMIN_ONLY_OPS is refused on the DATA socket with the
 *      catalog's exact error, and the data plane (hello / classify /
 *      declassifySymbol …) is untouched;
 *   2. the same ops succeed on an admin channel;
 *   3. the PRODUCTION admin channel — an fd the daemon inherits at spawn
 *      (`MANDU_ADMIN_FD`) — works end to end through the real
 *      `ipc/server-main.ts`, and the daemon's own data socket still refuses;
 *   4. `setSessionSpec` is bind-once: a bound session cannot be moved to a
 *      different spec, and a session that has classified cannot be bound.
 *
 * Why the daemon is spawned as `node --import tsx …` and not `npm run serve`:
 * measured 2026-09-05 — an extra stdio fd survives `sh → node`, but neither
 * the `tsx` CLI nor `npm exec` pass it through (both replace/close inherited
 * fds when they spawn the real node). The dashboard supervisor spawns the
 * arbiter the same way for the same reason (supervisor-defs.ts).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { connect, type Socket } from "node:net";

import { ArbiterServer, ADMIN_ONLY_OPS, adminOnlyError } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const dirs: string[] = [];
function tmp(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** One raw NDJSON request over a fresh connection — independent of the typed
 *  client, so the WIRE shape of a refusal is what is asserted. */
function rawRequest(socketPath: string, req: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const sock = connect(socketPath);
    let buf = "";
    sock.setEncoding("utf8");
    sock.once("connect", () => sock.write(JSON.stringify(req) + "\n"));
    sock.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl >= 0) {
        sock.end();
        resolve(JSON.parse(buf.slice(0, nl)) as Record<string, unknown>);
      }
    });
    sock.once("error", reject);
  });
}

async function inProcessServer(): Promise<{ server: ArbiterServer; dataSock: string; adminSock: string }> {
  const dir = tmp("mandu-admin-chan-");
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const server = new ArbiterServer({
    socketPath: dataSock,
    adminSocketPath: adminSock,
    dbPath: join(dir, "symbols.db"),
    eventDir: join(dir, "events"),
    log: () => {},
  });
  await server.listen();
  return { server, dataSock, adminSock };
}

// ── 1 + 2: the catalog is refused on data, accepted on admin ─────────────────

test("every ADMIN_ONLY_OPS op is refused on the data socket with the catalog error; the data plane is untouched", async () => {
  const { server, dataSock } = await inProcessServer();
  try {
    assert.ok(ADMIN_ONLY_OPS.size >= 6, "the catalog names the human-decision ops");
    for (const op of ADMIN_ONLY_OPS) {
      const r = await rawRequest(dataSock, { id: `d-${op}`, op });
      assert.equal(r.ok, false, `${op} must be refused on the data socket`);
      assert.equal(r.error, adminOnlyError(op), `${op}: refusal names the boundary, not a validation detail`);
    }
    // Data plane stays open: hello answers, declassifySymbol reaches its own
    // validation (any error but the admin refusal), classify answers.
    const hello = await rawRequest(dataSock, { id: "h", op: "hello" });
    assert.equal(hello.ok, true);
    const decl = await rawRequest(dataSock, { id: "x", op: "declassifySymbol", symbol: "$MDU:nope[0000]" });
    assert.notEqual(decl.error, adminOnlyError("declassifySymbol"), "declassifySymbol is the MCP child's quarantined read — data plane");
    const cls = await rawRequest(dataSock, {
      id: "c",
      op: "classify",
      request: { tool: "Bash", value: "ls", boundary: "model_context", params: {} },
    });
    assert.equal(cls.ok, true);
  } finally {
    await server.close();
  }
});

test("the typed client sees the refusal as a rejected promise; the admin channel enacts the same ops", async () => {
  const { server, dataSock, adminSock } = await inProcessServer();
  const data = new ArbiterClient(dataSock);
  const admin = new ArbiterClient(adminSock);
  try {
    await data.connect();
    await admin.connect();
    await assert.rejects(
      () => data.setPathLabel({ path: "/tmp/mandu-admin-chan-probe", confidentiality: "no-model" }),
      /admin-only/,
    );
    await assert.rejects(() => data.setSessionPosture({ posture: "lockdown", requestedBy: "test" }), /admin-only/);
    await assert.rejects(() => data.deleteSession("no-such-session"), /admin-only/);
    await assert.rejects(() => data.resolveEgressApproval("no-such-id", true), /admin-only/);
    // Nothing was enacted by the refused calls:
    assert.equal((await admin.pathLabels()).length, 0, "the refused label was never stored");

    const lbl = await admin.setPathLabel({ path: "/tmp/mandu-admin-chan-probe", confidentiality: "no-model" });
    assert.equal(lbl.level, "no-model");
    const posture = await admin.setSessionPosture({ posture: "lockdown", requestedBy: "admin-channel e2e" });
    assert.equal(posture.applied, true);
    // The data plane READS the state the admin channel set — one arbiter, two doors.
    assert.equal((await data.pathLabels()).length, 1);
  } finally {
    data.close();
    admin.close();
    await server.close();
  }
});

// ── 3: the production channel — an inherited fd through the real daemon ─────

test("inherited fd (MANDU_ADMIN_FD): admin op succeeds over the fd; the daemon's data socket refuses it", async (t) => {
  const dir = tmp("mandu-admin-fd-");
  const sock = join(dir, "arbiter.sock");
  const env = {
    ...process.env,
    MANDU_ARBITER_SOCK: sock, // pinned mode — no registry promotion
    MANDU_RUNTIME_DIR: join(dir, "rt"), // the instance registry stays in the temp dir
    MANDU_HOME: join(dir, "home"),
    MANDU_ADMIN_FD: "3",
    MANDU_INBOUND_SPEC: "",
  };
  const child: ChildProcess = spawn(process.execPath, ["--import", "tsx", "ipc/server-main.ts"], {
    cwd: ARBITER_DIR,
    env,
    stdio: ["ignore", "pipe", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr!.on("data", (d: Buffer) => (stderr += d.toString()));
  t.after(async () => {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await new Promise<void>((r) => child.once("exit", () => r()));
    }
  });

  // Wait for the daemon's data socket (tsx cold start is a few seconds).
  const deadline = Date.now() + 30_000;
  while (!existsSync(sock)) {
    if (child.exitCode !== null) assert.fail(`daemon exited early (code ${child.exitCode}):\n${stderr}`);
    if (Date.now() > deadline) assert.fail(`daemon did not listen within 30s:\n${stderr}`);
    await new Promise((r) => setTimeout(r, 100));
  }

  const admin = ArbiterClient.overSocket(child.stdio[3] as Socket);
  const data = new ArbiterClient(sock);
  try {
    await admin.connect();
    await data.connect();
    const hello = await admin.hello();
    assert.equal(typeof hello.eventDir, "string", "hello answers over the inherited fd");
    const r = await admin.setSessionPosture({ posture: "lockdown", requestedBy: "admin-channel e2e (fd)" });
    assert.equal(r.applied, true, "a human-decision op is enacted over the inherited fd");
    await assert.rejects(
      () => data.setSessionPosture({ posture: "normal", allowRelax: true, requestedBy: "agent?" }),
      /admin-only/,
      "the same op on the daemon's own data socket is refused",
    );
    assert.match(stderr, /admin channel: inherited fd 3/, "the daemon logged the channel it attached");
  } finally {
    data.close();
    admin.close();
  }
});

// ── 4: setSessionSpec is bind-once ───────────────────────────────────────────

test("setSessionSpec is bind-once: no re-bind to a different spec, no bind after the first classify", async () => {
  const { server, dataSock } = await inProcessServer();
  const client = new ArbiterClient(dataSock);
  try {
    await client.connect();
    const a = await client.setSessionSpec({ sessionKey: "bo-1", spec: "opencode" });
    assert.equal(a.bound, "opencode");
    const again = await client.setSessionSpec({ sessionKey: "bo-1", spec: "opencode" });
    assert.equal(again.bound, "opencode", "re-binding to the SAME spec is an idempotent no-op");
    await assert.rejects(
      () => client.setSessionSpec({ sessionKey: "bo-1", spec: "openclaw-agent" }),
      /bind-once/,
      "a bound session cannot be moved to another spec",
    );
    // A session that has already classified cannot be bound at all.
    await client.classify({ tool: "Bash", value: "ls", boundary: "model_context", params: {}, sessionKey: "bo-2" });
    await assert.rejects(
      () => client.setSessionSpec({ sessionKey: "bo-2", spec: "opencode" }),
      /already classified/,
    );
    // An unbound, never-classified session still binds (the proxy's boot path).
    const c = await client.setSessionSpec({ sessionKey: "bo-3", spec: "claude-code" });
    assert.equal(c.applied, true);
  } finally {
    client.close();
    await server.close();
  }
});
