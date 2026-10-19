/**
 * batch-member.test — MANDU_BATCH_MEMBER end to end: a real `main()` launch
 * against a recording arbiter puts what the session is within its batch (the
 * watch runner's `scenario:<key>` or `posture:<key>`) on its `launch_posture`
 * event, beside the batch stamp, so the dashboard badges a watch row by it
 * instead of reading the session id (dashboard.md §4.22). A malformed value
 * costs the field, never the launch.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { answerUnavailable } from "../lib/unanswered-arbiter.js";

async function withRecordingArbiter(fn: (sock: string, dir: string, received: () => string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-e2e-member-"));
  const sock = join(dir, "arbiter.sock");
  let buf = "";
  const srv: Server = createServer(answerUnavailable((l) => { buf += `${l}\n`; }));
  srv.listen(sock);
  await once(srv, "listening");
  try { await fn(sock, dir, () => buf); } finally {
    srv.close(); rmSync(dir, { recursive: true, force: true });
  }
}

function fakeAgent(dir: string): { bin: string; ran: string } {
  const binDir = join(dir, "bin");
  mkdirSync(binDir, { recursive: true });
  const bin = join(binDir, "claude");
  const ran = join(binDir, "ran");
  writeFileSync(bin, `#!/bin/sh\nif [ "$1" = --version ]; then echo '0.0.0 (Claude Code)'; exit 0; fi\ntouch '${ran}'\n`);
  chmodSync(bin, 0o755);
  return { bin, ran };
}

async function postureOf(member: string | undefined): Promise<{ code: number; ran: boolean; posture: Record<string, unknown> }> {
  let out: { code: number; ran: boolean; posture: Record<string, unknown> } | undefined;
  await withRecordingArbiter(async (sock, dir, received) => {
    const { bin, ran } = fakeAgent(dir);
    const env = {
      HOME: dir, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], ANTHROPIC_API_KEY: "sk-e2e-unused",
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dir,
      MANDU_BATCH_ID: "watch-20260930T010203",
      ...(member !== undefined ? { MANDU_BATCH_MEMBER: member } : {}),
    };
    const orig = console.error;
    console.error = () => {};
    let code: number;
    try { code = await main(["--no-scope", "--no-reply-filter", "--", bin], env); } finally { console.error = orig; }
    const line = received().split("\n").find((l) => l.includes("\"launch_posture\""));
    assert.ok(line, "the launch_posture event reached the arbiter");
    const frame = JSON.parse(line!) as { args?: { event?: Record<string, unknown> }; event?: Record<string, unknown> };
    out = { code, ran: existsSync(ran), posture: (frame.args?.event ?? frame.event)! };
  });
  return out!;
}

test("a watch scenario's pane: launch_posture carries batchMember {scenario, key} beside the batch stamp", async () => {
  const r = await postureOf("scenario:S3@haiku#2");
  assert.equal(r.code, 0);
  assert.ok(r.ran, "the agent ran");
  assert.equal(r.posture["batchId"], "watch-20260930T010203");
  assert.deepEqual(r.posture["batchMember"], { kind: "scenario", key: "S3@haiku#2" });
});

test("a --shared-session pane: the member is the posture group, never read as a scenario", async () => {
  const r = await postureOf("posture:S1");
  assert.deepEqual(r.posture["batchMember"], { kind: "posture", key: "S1" });
});

test("no member, or a malformed one: no field, and the launch goes on", async () => {
  for (const bad of [undefined, "", "S1", "group:S1", "scenario:", "scenario:a b", "scenario:../x"]) {
    const r = await postureOf(bad);
    assert.equal(r.code, 0, String(bad));
    assert.ok(r.ran, `${String(bad)}: the agent ran`);
    assert.equal(r.posture["batchMember"], undefined, String(bad));
  }
});
