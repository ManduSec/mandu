/**
 * observe.test — the launch banners → `launch_posture` event (services/observe.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { emitLauncherEvent, launchPostureEvent, liveRungNames, postureFindings, sessionExitEvent } from "../../src/services/observe.js";
import { createServer, type Server } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const FULL = [
  "mandu: fs rung ACTIVE: cooperative — CWD→AgentView worktree + prefix map (workspace /w)",
  "mandu: net-proxy LIVE — cooperative egress gate on http://127.0.0.1:35939",
  "mandu: exec-wrap LIVE — PATH-shadowing [curl, wget, nc] through the arbiter",
  "mandu: exec-box LIVE — boxing [cat, grep] in the net-off AgentShell",
  "mandu: landlock-net LIVE — whole-agent TCP confined to CONNECT ports [22, 443] (deny all other TCP; --skip-unsupported degrades on kernel < 6.7)",
  "mandu: net-guard LIVE — whole-agent connect(2) confined by DESTINATION",
  "mandu: confidentiality — 17 secret(s) confined via symbolized twins",
  "reply-filter LIVE — the agent's stdout is desymbolized for the human",
  "Running scope as unit: mandu-1788559448-986903.scope",
];

test("postureFindings: a full posture has only live lines; the informational skip-unsupported clause is not a drop", () => {
  const f = postureFindings(FULL);
  assert.deepEqual(f.dropped, []);
  assert.deepEqual(liveRungNames(f.live), ["fs", "net-proxy", "exec-wrap", "exec-box", "landlock-net", "net-guard", "reply-filter"]);
});

test("postureFindings: the dropped/degraded phrases the CI posture oracle uses are findings", () => {
  const f = postureFindings([
    ...FULL,
    "mandu: service 'net-proxy' is on by default but failed to start: mandu: 127.0.0.1:8790 is occupied by another Mandu net-proxy — proceeding WITHOUT it",
    "mandu: secrets are GATED, not confined, on this host.\n  Ubuntu restricts unprivileged user namespaces (AppArmor).\n  Programs the agent runs can still read your credential files.\n  One-time upgrade:  mandu setup   (asks for sudo once)\n  Details:           mandu doctor",
    "mandu: fs rung DEGRADED: workspace and its AgentView nest — no usable pair",
    "mandu: exec-box OFF for codex by default — codex boxes each command in its own sandbox",
  ]);
  assert.equal(f.dropped.length, 3, "the designed codex OFF posture is informational, not a drop");
  assert.match(f.dropped[0]!, /net-proxy/);
  assert.match(f.dropped[1]!, /secrets are GATED/);
  assert.match(f.dropped[2]!, /DEGRADED/);
});

test("launchPostureEvent: a valid event with the live rungs, the dropped lines, and a capped notes copy", () => {
  const notes = [...FULL, ...Array.from({ length: 60 }, (_, i) => `mandu: note ${i}`)];
  const ev = launchPostureEvent({ scopeId: "sid-1", tenant: "live", target: "claude", argv0: "claude", notes, launcherVersion: "abc123" });
  assert.equal(ev["kind"], "launch_posture");
  assert.equal(ev["sessionId"], "sid-1");
  assert.equal(ev["emitter"], "launcher");
  assert.equal(ev["tenant"], "live");
  assert.deepEqual(ev["dropped"], []);
  assert.deepEqual(ev["live"], ["fs", "net-proxy", "exec-wrap", "exec-box", "landlock-net", "net-guard", "reply-filter"]);
  assert.equal((ev["notes"] as string[]).length, 40, "notes capped");
  assert.match((ev["input"] as { symbolized: string }).symbolized, /7 rung\(s\) live/);
  assert.match((ev["input"] as { symbolized: string }).symbolized, /full posture/);
  const dropped = launchPostureEvent({ scopeId: "s", target: "claude", argv0: "claude", notes: ["mandu: service 'x' is on by default but failed to start: y"] });
  assert.match((dropped["input"] as { symbolized: string }).symbolized, /1 DROPPED/);
  assert.equal(dropped["tenant"], undefined, "no tenant stamp without one");
  assert.equal(dropped["batchId"], undefined, "no batch stamp without one");
});

test("launcher events carry the MANDU_BATCH_ID stamp, so a session with no model call still groups with its run", () => {
  const posture = launchPostureEvent({ scopeId: "watch-9-s4", tenant: "test", batchId: "watch-9", target: "claude", argv0: "claude", notes: [] });
  assert.equal(posture["batchId"], "watch-9");
  const exit = sessionExitEvent({ scopeId: "watch-9-s4", batchId: "watch-9", code: 0, durationMs: 1 });
  assert.equal(exit["batchId"], "watch-9");
  assert.equal(sessionExitEvent({ scopeId: "s", code: 0, durationMs: 1 })["batchId"], undefined);
});

test("launch_posture carries batchMember when the launch has one (the watch runner's scenario / posture group), nothing otherwise", () => {
  const scn = launchPostureEvent({ scopeId: "watch-9-s1", batchId: "watch-9", batchMember: { kind: "scenario", key: "S1" }, target: "claude", argv0: "claude", notes: [] });
  assert.deepEqual(scn["batchMember"], { kind: "scenario", key: "S1" });
  const grp = launchPostureEvent({ scopeId: "watch-9-s1", batchId: "watch-9", batchMember: { kind: "posture", key: "S1" }, target: "claude", argv0: "claude", notes: [] });
  assert.deepEqual(grp["batchMember"], { kind: "posture", key: "S1" });
  assert.equal("batchMember" in launchPostureEvent({ scopeId: "s", target: "claude", argv0: "claude", notes: [] }), false);
});

test("sessionExitEvent: code + duration on the record", () => {
  const ev = sessionExitEvent({ scopeId: "sid-1", code: 130, durationMs: 65_000 });
  assert.equal(ev["kind"], "session_exit");
  assert.equal(ev["code"], 130);
  assert.match((ev["input"] as { symbolized: string }).symbolized, /exited 130 after 65s/);
});

test("sessionExitEvent: the protected files whose placeholder copy the session changed ride by path, only when there is one (plan 10 §4.1)", () => {
  const ev = sessionExitEvent({ scopeId: "sid-1", code: 0, durationMs: 1000, discardedWrites: ["/w/.env", "/h/.npmrc"] });
  assert.deepEqual(ev["discardedWrites"], ["/w/.env", "/h/.npmrc"]);
  assert.match((ev["input"] as { symbolized: string }).symbolized, /exited 0 after 1s; the agent changed 2 protected files \(\/w\/\.env, \/h\/\.npmrc\): the change stayed in the placeholder copy and never reached the real file$/);
  assert.equal("discardedWrites" in sessionExitEvent({ scopeId: "s", code: 0, durationMs: 1, discardedWrites: [] }), false);
  assert.equal("discardedWrites" in sessionExitEvent({ scopeId: "s", code: 0, durationMs: 1 }), false);
  assert.match((sessionExitEvent({ scopeId: "s", code: 0, durationMs: 1, discardedWrites: ["/w/.env"] })["input"] as { symbolized: string }).symbolized, /changed 1 protected file \(/);
  // The summary text shows a path's control and format characters as `?`
  // (a bidi override in a directory name cannot reorder it in the
  // inspector); the field keeps the path as it is.
  const odd = "/w/\u202Eevil\n/.env";
  const ev2 = sessionExitEvent({ scopeId: "s", code: 0, durationMs: 1, discardedWrites: [odd] });
  assert.deepEqual(ev2["discardedWrites"], [odd]);
  assert.match((ev2["input"] as { symbolized: string }).symbolized, /\(\/w\/\?evil\?\/\.env\)/);
});

test("launchPostureEvent: the protection mode rides first-class when given, absent otherwise", () => {
  const protection = { mode: "secrets", integrity: false, confidentiality: true, reported: true };
  const ev = launchPostureEvent({ scopeId: "s", target: "claude", argv0: "claude", notes: [], protection });
  assert.deepEqual(ev["protection"], protection);
  assert.equal(launchPostureEvent({ scopeId: "s", target: "claude", argv0: "claude", notes: [] })["protection"], undefined);
});

test("launchPostureEvent: whether the human plane was walled rides as given, either way; absent when no claim was made", () => {
  assert.equal(launchPostureEvent({ scopeId: "s", target: "claude", argv0: "claude", notes: [], humanPlaneWalled: false })["humanPlaneWalled"], false);
  assert.equal(launchPostureEvent({ scopeId: "s", target: "claude", argv0: "claude", notes: [], humanPlaneWalled: true })["humanPlaneWalled"], true);
  assert.equal("humanPlaneWalled" in launchPostureEvent({ scopeId: "s", target: "claude", argv0: "claude", notes: [] }), false);
});

/** A one-op NDJSON server that answers `emit` (or refuses it) and records it. */
async function emitServer(path: string, name: string, ok: boolean, got: string[]): Promise<Server> {
  const srv = createServer((c) => {
    let buf = "";
    c.on("data", (d) => {
      buf += d.toString();
      const i = buf.indexOf("\n");
      if (i === -1) return;
      const req = JSON.parse(buf.slice(0, i)) as { id: string; op: string };
      got.push(`${name}:${req.op}`);
      c.end(JSON.stringify(ok ? { id: req.id, ok: true, result: { seq: 1 } } : { id: req.id, ok: false, error: "refused" }) + "\n");
    });
  });
  await new Promise<void>((r) => srv.listen(path, () => r()));
  return srv;
}

test("emitLauncherEvent: the human socket first (believed there, arbiter-human-plane.md §10.2), the data socket only when it has none or it fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-observe-emit-"));
  const got: string[] = [];
  const data = await emitServer(join(dir, "d.sock"), "data", true, got);
  const human = await emitServer(join(dir, "h.sock"), "human", true, got);
  const broken = await emitServer(join(dir, "bh.sock"), "broken", false, got);
  try {
    assert.equal(await emitLauncherEvent(join(dir, "d.sock"), { id: "e" }, join(dir, "h.sock")), true);
    assert.deepEqual(got, ["human:emit"], "only the human socket");
    got.length = 0;
    assert.equal(await emitLauncherEvent(join(dir, "d.sock"), { id: "e" }, null), true);
    assert.deepEqual(got, ["data:emit"], "no human socket: the data socket (a claim there)");
    got.length = 0;
    assert.equal(await emitLauncherEvent(join(dir, "d.sock"), { id: "e" }, join(dir, "bh.sock")), true);
    assert.deepEqual(got, ["broken:emit", "data:emit"], "a human socket that refuses: the data socket after it");
    assert.equal(await emitLauncherEvent(undefined, { id: "e" }, null), false);
  } finally {
    data.close(); human.close(); broken.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
