/**
 * fs-path-decision.test.ts — the sensitive-path gate over a real Unix socket
 * (P3, fs-sync.md §1.4.1): the `fsPathDecision` op wrapped by the SAME
 * interactive approval queue as the network egress gate.
 *
 * Exercises end to end over an actual socket:
 *   - inside a workspace root → allow (no queue entry);
 *   - out-of-workspace → deny + requiresApproval, ONE pending entry keyed
 *     `fs:<tool>:<mode>` × path; a repeat increments count;
 *   - resolveEgressApproval(id, true) → the SAME request then allows
 *     (human-approved); (id, false) → deny WITHOUT re-queueing (human-denied);
 *   - sensitive built-ins (~/.ssh) deny even when workspace-rooted at ~.
 *
 * Run: npm run test:unit
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

let workdir: string;
let server: ArbiterServer;
let client: ArbiterClient;

const WS = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";
const ROOTS = [WS, AGENT];

before(async () => {
  workdir = mkdtempSync(join(tmpdir(), "mandu-fsgate-"));
  const socketPath = join(workdir, "arbiter.sock");
  server = new ArbiterServer({
    socketPath,
    dbPath: join(workdir, "symbols.db"),
    adminSocketPath: join(workdir, "admin.sock"),
    eventDir: join(workdir, "events"),
    log: () => {},
  });
  await server.listen();
  client = new ArbiterClient(join(workdir, "admin.sock"));
  await client.connect();
});

after(async () => {
  client.close();
  await server.close();
  rmSync(workdir, { recursive: true, force: true });
});

test("inside a workspace root → allow, and nothing is queued", async () => {
  const d = await client.fsPathDecision({
    tool: "Read", path: `${WS}/src/a.ts`, mode: "read", workspaceRoots: ROOTS,
  });
  assert.equal(d.allow, true);
  const queued = (await client.egressApprovals()).filter((a) => a.destination === `${WS}/src/a.ts`);
  assert.equal(queued.length, 0);
});

test("out-of-workspace → deny/approve, ONE pending entry keyed fs:<tool>:<mode>; repeat increments", async () => {
  const p = "/var/log/syslog";
  const d1 = await client.fsPathDecision({ tool: "Read", path: p, mode: "read", workspaceRoots: ROOTS });
  assert.equal(d1.allow, false);
  assert.equal((d1 as { requiresApproval: boolean }).requiresApproval, true);

  const after1 = (await client.egressApprovals()).filter((a) => a.symbol === "fs:Read:read" && a.destination === p);
  assert.equal(after1.length, 1);
  assert.equal(after1[0].status, "pending");
  assert.equal(after1[0].count, 1);

  await client.fsPathDecision({ tool: "Read", path: p, mode: "read", workspaceRoots: ROOTS });
  const after2 = (await client.egressApprovals()).filter((a) => a.symbol === "fs:Read:read" && a.destination === p);
  assert.equal(after2.length, 1, "idempotent upsert");
  assert.equal(after2[0].count, 2);
});

test("human approve flips the next identical request to allow", async () => {
  const p = "/opt/data/report.csv";
  await client.fsPathDecision({ tool: "Read", path: p, mode: "read", workspaceRoots: ROOTS });
  const entry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === "fs:Read:read" && a.destination === p,
  );
  assert.ok(entry);
  await client.resolveEgressApproval(entry!.id, true);

  const d = await client.fsPathDecision({ tool: "Read", path: p, mode: "read", workspaceRoots: ROOTS });
  assert.equal(d.allow, true);
  assert.equal((d as { reason: string }).reason, "human-approved");
  // Approval is per {tool, mode, path}: a WRITE of the same path is separate.
  const w = await client.fsPathDecision({ tool: "Write", path: p, mode: "write", workspaceRoots: ROOTS });
  assert.equal(w.allow, false);
});

test("human deny pins the verdict: denied WITHOUT re-approval prompting", async () => {
  const p = "/opt/data/secrets.env";
  await client.fsPathDecision({ tool: "Read", path: p, mode: "read", workspaceRoots: ROOTS });
  const entry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === "fs:Read:read" && a.destination === p,
  );
  assert.ok(entry);
  await client.resolveEgressApproval(entry!.id, false);

  const d = await client.fsPathDecision({ tool: "Read", path: p, mode: "read", workspaceRoots: ROOTS });
  assert.equal(d.allow, false);
  assert.equal((d as { requiresApproval: boolean }).requiresApproval, false);
  assert.equal((d as { reason: string }).reason, "human-denied");
});

test("a human deny pins the TARGET, not the spelling: alternate spellings stay denied and do not re-queue", async () => {
  const p = "/opt/data/pinned.env";
  await client.fsPathDecision({ tool: "Read", path: p, mode: "read", workspaceRoots: ROOTS });
  const entry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === "fs:Read:read" && a.destination === p,
  );
  assert.ok(entry);
  await client.resolveEgressApproval(entry!.id, false);

  // Alternate spellings of the SAME target must inherit the human deny — not
  // slip past it and mint fresh pending entries.
  for (const alt of ["/opt/data//pinned.env", "/opt/data/./pinned.env", "/opt/extra/../data/pinned.env"]) {
    const d = await client.fsPathDecision({ tool: "Read", path: alt, mode: "read", workspaceRoots: ROOTS });
    assert.equal(d.allow, false, alt);
    assert.equal((d as { requiresApproval: boolean }).requiresApproval, false, alt);
    assert.equal((d as { reason: string }).reason, "human-denied", alt);
  }
  // The queue still holds exactly ONE entry for this target (no per-spelling fragments).
  const entries = (await client.egressApprovals()).filter((a) => a.symbol === "fs:Read:read" && a.destination === p);
  assert.equal(entries.length, 1);
});

test("sensitive built-ins deny even under a workspace rooted at ~ (deny-precedence)", async () => {
  const home = homedir();
  const d = await client.fsPathDecision({
    tool: "Read", path: join(home, ".ssh", "id_rsa"), mode: "read", workspaceRoots: [home],
  });
  assert.equal(d.allow, false);
  assert.match((d as { reason: string }).reason, /sensitive path/);
});
