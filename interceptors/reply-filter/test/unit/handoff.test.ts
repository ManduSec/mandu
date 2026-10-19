/**
 * handoff.test — the early-start protocol's pure half and its channel reader
 * (src/handoff.ts, packaging.md §5.3): what a valid hand-off is, how it is
 * applied, and that the reader answers only a valid one, closes the channel
 * either way, and reads an end of file as "the launch stopped".
 * Mandu-new (no reference origin). No arbiter is built here.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, connect, type Socket } from "node:net";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  HANDOFF_ACK, HANDOFF_FLAG, applyHandoff, handoffArgv, parseHandoff, receiveHandoff, type Handoff,
} from "../../src/handoff.js";
import { parseReplyInvocation } from "../../src/output-format.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // pure protocol logic; states its axes (protection-modes.md §4)

const good = {
  v: 1,
  cmd: ["net-guard", "--", "claude", "-p", "hi"],
  outer: ["systemd-run", "--user", "--scope", "--"],
  env: { PATH: "/usr/bin", MANDU_ARBITER_HUMAN_SOCK: "/run/h.sock" },
  cwd: "/",
  outputFormat: "stream-json",
};

test("the flag and the answer", () => {
  assert.equal(HANDOFF_FLAG, "--mandu-handoff-fd=3");
  assert.equal(HANDOFF_ACK, "ok\n");
});

test("parseHandoff: a valid line, and the serial form's argv from it", () => {
  const h = parseHandoff(JSON.stringify(good));
  assert.deepEqual(h, { cmd: good.cmd, outer: good.outer, env: good.env, cwd: "/", outputFormat: "stream-json" });
  const argv = handoffArgv(h);
  assert.deepEqual(argv, ["--mandu-output-format=stream-json", "--", ...good.cmd]);
  assert.deepEqual(parseReplyInvocation(argv), { cmd: good.cmd, outputFormat: "stream-json" }, "read exactly as the serial form");
  assert.deepEqual(parseHandoff(JSON.stringify({ ...good, outer: [] })).outer, [], "no scope prefix is fine");
});

test("parseHandoff: everything else is refused, by name", () => {
  const bad: Array<[unknown, RegExp]> = [
    ["{", /not JSON/],
    [[], /no command|not an object|version/],
    [{ ...good, v: 2 }, /version/],
    [{ ...good, cmd: [] }, /no command/],
    [{ ...good, cmd: ["a", 1] }, /no command/],
    [{ ...good, outer: "systemd-run" }, /scope prefix/],
    [{ ...good, env: { A: 1 } }, /environment/],
    [{ ...good, env: ["A=1"] }, /environment/],
    [{ ...good, cwd: "" }, /directory/],
    [{ ...good, outputFormat: "yaml" }, /output format/],
  ];
  for (const [m, why] of bad) {
    assert.throws(() => parseHandoff(typeof m === "string" ? m : JSON.stringify(m)), why, JSON.stringify(m));
  }
});

test("applyHandoff: exactly the hand-off's environment (nothing of the old one), in its directory", () => {
  const env: NodeJS.ProcessEnv = { OLD: "x", PATH: "/old" };
  let dir = "";
  applyHandoff(parseHandoff(JSON.stringify(good)), { env, chdir: (d) => { dir = d; } });
  assert.deepEqual({ ...env }, good.env);
  assert.equal(dir, "/");
});

/** A connected socket pair over a temp Unix socket: [the filter's end, the launcher's end]. */
async function pair(): Promise<{ filter: Socket; launcher: Socket; done: () => void }> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-handoff-"));
  const path = join(dir, "s");
  const server = createServer();
  server.listen(path);
  await once(server, "listening");
  const accepted = once(server, "connection");
  const launcher = connect(path);
  const [filter] = (await accepted) as [Socket];
  return { filter, launcher, done: () => { launcher.destroy(); server.close(); rmSync(dir, { recursive: true, force: true }); } };
}

const readAll = (s: Socket): Promise<string> => new Promise((resolve) => {
  let got = "";
  s.setEncoding("utf8");
  s.on("data", (c: string) => (got += c));
  s.on("close", () => resolve(got));
  s.on("end", () => resolve(got));
});

test("receiveHandoff: a valid line (in pieces) is applied, answered, and the channel closed", async () => {
  const { filter, launcher, done } = await pair();
  try {
    const answer = readAll(launcher);
    let applied: Handoff | null = null;
    const wait = receiveHandoff(filter, (h) => { applied = h; });
    const line = JSON.stringify(good) + "\n";
    launcher.write(line.slice(0, 10));
    await new Promise((r) => setTimeout(r, 20));
    launcher.write(line.slice(10));
    const w = await wait;
    assert.equal(w.kind, "handoff");
    assert.ok(applied !== null);
    assert.equal(await answer, HANDOFF_ACK);
    assert.equal(filter.destroyed, true, "the channel is closed before anything is spawned");
  } finally { done(); }
});

test("receiveHandoff: an end of file first is an abort (no answer)", async () => {
  const { filter, launcher, done } = await pair();
  try {
    const wait = receiveHandoff(filter);
    launcher.write(JSON.stringify(good).slice(0, 20)); // an incomplete line, then the end
    launcher.end();
    assert.deepEqual(await wait, { kind: "aborted" });
  } finally { done(); }
});

test("receiveHandoff: a malformed line, or one that cannot be applied, gets no answer", async () => {
  for (const [line, apply] of [
    ["not json\n", () => {}],
    [JSON.stringify(good) + "\n", () => { throw new Error("ENOENT: no such directory"); }],
  ] as Array<[string, (h: Handoff) => void]>) {
    const { filter, launcher, done } = await pair();
    try {
      const answer = readAll(launcher);
      const wait = receiveHandoff(filter, apply);
      launcher.write(line);
      const w = await wait;
      assert.equal(w.kind, "invalid");
      assert.equal(await answer, "", "no answer: the launcher falls back");
    } finally { done(); }
  }
});
