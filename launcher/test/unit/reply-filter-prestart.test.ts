/**
 * reply-filter-prestart.test — the reply filter's early start (packaging.md
 * §5.2, reply-filter.ts): the start, the hand-off, the abort, the fallbacks,
 * and the parity of the hand-off line with the filter's own reader
 * (interceptors/reply-filter/src/handoff.ts).
 *
 * The filter here is a stand-in (a small node script speaking the fd-3
 * protocol), so each path is driven deterministically; the REAL filter is
 * started early and handed an agent in
 * test/component/reply-filter-prestart.test.ts and through the launcher in
 * test/reply-filter-live.test.sh. Mandu-new (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  ABORT_GRACE_MS, HANDOFF_ACK, HANDOFF_FLAG, ReplyFilterSlot, applyReplyFilter, handOffReplyFilter,
  handoffLine, prestartReplyFilter, wantsPrestart, type PrestartedReplyFilter, type ReplyFilterHandoff,
} from "../../src/reply-filter.js";
import { runAgent } from "../../src/spawn.js";
import { Layout } from "../../src/services/layout.js";
import { emptyMutation } from "../../src/backend/types.js";
import type { LaunchPlan } from "../../src/types.js";
import { tmpDir } from "../lib/tmp-dir.js";

const dir = tmpDir("mdu-rf-prestart-");
const standIn = join(dir, "stand-in.cjs");
// The stand-in filter: STANDIN_MODE picks its behavior; it records the
// hand-off it got (and the env it was STARTED with) in STANDIN_OUT.
writeFileSync(standIn, `
const net = require('node:net');
const fs = require('node:fs');
const mode = process.env.STANDIN_MODE || 'ok';
if (process.argv.slice(2).join(' ') !== ${JSON.stringify(HANDOFF_FLAG)}) process.exit(40);
if (mode === 'die') process.exit(9);
const startedWith = { RF_ENV: process.env.RF_ENV, AMBIENT: process.env.AMBIENT };
const s = new net.Socket({ fd: 3, readable: true, writable: true });
let buf = '';
s.setEncoding('utf8');
s.on('data', (c) => {
  buf += c;
  const nl = buf.indexOf('\\n');
  if (nl < 0) return;
  const h = JSON.parse(buf.slice(0, nl));
  fs.writeFileSync(process.env.STANDIN_OUT, JSON.stringify({ h, startedWith, cwd: process.cwd() }));
  if (mode === 'noack') process.exit(3);
  s.end('ok\\n', () => { s.destroy(); setTimeout(() => process.exit(Number(h.env.EXIT_CODE || 0)), 50); });
});
s.on('end', () => { if (mode !== 'ignore-eof') process.exit(0); });
if (mode === 'ignore-eof') setInterval(() => {}, 1000);
`);

const standInLayout = (): Layout => ({
  replyFilter: () => ({ tokens: [process.execPath, standIn], env: { RF_ENV: "from-layout" }, requiredFile: standIn }),
} as unknown as Layout);

let n = 0;
function start(mode: string, extra: Partial<Parameters<typeof prestartReplyFilter>[1]> = {}): { pre: PrestartedReplyFilter; out: string } {
  const out = join(dir, `out-${++n}.json`);
  const pre = prestartReplyFilter(standInLayout(), {
    detached: true, cwd: dir,
    env: { ...process.env, STANDIN_MODE: mode, STANDIN_OUT: out, AMBIENT: "launcher-env" },
    ...extra,
  });
  assert.ok(pre !== null, "the stand-in spawns");
  return { pre, out };
}

const handoff = (over: Partial<ReplyFilterHandoff> = {}): ReplyFilterHandoff => ({
  cmd: ["net-guard", "--", "claude", "-p", "hi"],
  outer: ["systemd-run", "--user", "--scope", "--"],
  env: { PATH: "/usr/bin", MANDU_ARBITER_HUMAN_SOCK: "/run/h.sock", UNSET: undefined },
  cwd: "/",
  outputFormat: "text",
  ...over,
});

const gone = (pid: number | undefined): boolean => {
  if (pid === undefined) return true;
  try { process.kill(pid, 0); return false; } catch { return true; }
};

// ── the hand-off line ───────────────────────────────────────────────────────

test("handoffLine: one JSON line, version 1, unset variables dropped", () => {
  const line = handoffLine(handoff());
  assert.ok(line.endsWith("\n") && line.indexOf("\n") === line.length - 1, "exactly one line");
  const m = JSON.parse(line);
  assert.equal(m.v, 1);
  assert.deepEqual(m.cmd, ["net-guard", "--", "claude", "-p", "hi"]);
  assert.deepEqual(m.outer, ["systemd-run", "--user", "--scope", "--"]);
  assert.deepEqual(m.env, { PATH: "/usr/bin", MANDU_ARBITER_HUMAN_SOCK: "/run/h.sock" });
  assert.equal(m.outputFormat, "text");
});

test("parity: the filter's reader takes the launcher's line, and the flag and answer match", async () => {
  // A runtime specifier: the launcher typechecks standalone (tsconfig rootDir).
  const path = "../../../interceptors/reply-filter/src/handoff.ts";
  const rf = await import(path) as {
    HANDOFF_FLAG: string;
    HANDOFF_ACK: string;
    parseHandoff: (line: string) => unknown;
    handoffArgv: (h: unknown) => string[];
  };
  assert.equal(rf.HANDOFF_FLAG, HANDOFF_FLAG);
  assert.equal(rf.HANDOFF_ACK, HANDOFF_ACK);
  for (const outputFormat of ["text", "json", "stream-json", "passthrough"] as const) {
    const h = handoff({ outputFormat, outer: [] });
    const got = rf.parseHandoff(handoffLine(h).trimEnd());
    assert.deepEqual(got, { cmd: h.cmd, outer: [], env: { PATH: "/usr/bin", MANDU_ARBITER_HUMAN_SOCK: "/run/h.sock" }, cwd: "/", outputFormat });
    assert.deepEqual(rf.handoffArgv(got), [`--mandu-output-format=${outputFormat}`, "--", ...h.cmd], "the serial form's argv");
  }
});

// ── when it starts early ────────────────────────────────────────────────────

test("wantsPrestart: on with the filter and its runtime; off by flag, by MANDU_REPLY_FILTER_PRESTART=0, or with no runtime", () => {
  const layout = Layout.dev("/repo");
  const yes = (): boolean => true;
  assert.equal(wantsPrestart({ replyFilter: true }, layout, {}, yes), true);
  assert.equal(wantsPrestart({ replyFilter: true }, layout, { MANDU_REPLY_FILTER_PRESTART: "1" }, yes), true);
  assert.equal(wantsPrestart({ replyFilter: false }, layout, {}, yes), false);
  assert.equal(wantsPrestart({ replyFilter: true }, layout, { MANDU_REPLY_FILTER_PRESTART: "0" }, yes), false);
  assert.equal(wantsPrestart({ replyFilter: true }, layout, {}, () => false), false);
});

test("applyReplyFilter, hand-off form: nothing prepended, the human socket only in the filter's own env", () => {
  const plan = { replyFilter: true, argv: ["claude", "--output-format", "json", "-p", "x"], arbiterHumanSock: "/run/h.sock" } as unknown as LaunchPlan;
  const mut = emptyMutation();
  mut.launchPrefix = ["net-guard", "--"];
  const lines: string[] = [];
  const w = applyReplyFilter(plan, Layout.installed("/opt/mandu"), mut, () => true, (m) => lines.push(m), { handOff: true });
  assert.deepEqual(mut.launchPrefix, ["net-guard", "--"], "the chain is the serial form's command, untouched");
  assert.equal(mut.env["MANDU_ARBITER_HUMAN_SOCK"], undefined, "neither the agent's env nor the scope's --setenv carries it");
  assert.equal(mut.env["MANDU_ARBITER_CLIENT_MODULE"], "/opt/mandu/dist/arbiter-client.mjs", "the agent's env is as before");
  assert.deepEqual(w, { outputFormat: "json", filterEnv: { MANDU_ARBITER_HUMAN_SOCK: "/run/h.sock" } });
  assert.ok(lines.some((l) => /reply-filter LIVE/.test(l)));
  // The serial form is unchanged: prefix + the socket in mut.env.
  const serial = emptyMutation();
  const ws = applyReplyFilter(plan, Layout.installed("/opt/mandu"), serial, () => true, () => {});
  assert.equal(serial.env["MANDU_ARBITER_HUMAN_SOCK"], "/run/h.sock");
  assert.ok(serial.launchPrefix.includes("--mandu-output-format=json"));
  assert.deepEqual(ws?.filterEnv, { MANDU_ARBITER_HUMAN_SOCK: "/run/h.sock" });
  assert.equal(applyReplyFilter({ ...plan, replyFilter: false } as LaunchPlan, Layout.dev("/repo"), emptyMutation(), () => true, () => {}, { handOff: true }), null);
});

// ── start, hand-off, abort ──────────────────────────────────────────────────

test("start + hand-off: the filter gets the line on fd 3, answers, and its exit status is the chain's", async () => {
  const { pre, out } = start("ok");
  assert.equal(pre.detached, true);
  const ok = await pre.handOff(handoff({ env: { EXIT_CODE: "7", MANDU_ARBITER_HUMAN_SOCK: "/run/h.sock" }, cwd: "/" }));
  assert.equal(ok, true);
  assert.equal(await pre.exit, 7);
  const got = JSON.parse(readFileSync(out, "utf8"));
  assert.deepEqual(got.h.cmd, ["net-guard", "--", "claude", "-p", "hi"]);
  assert.deepEqual(got.h.outer, ["systemd-run", "--user", "--scope", "--"]);
  assert.equal(got.h.env.MANDU_ARBITER_HUMAN_SOCK, "/run/h.sock");
  assert.deepEqual(got.startedWith, { RF_ENV: "from-layout", AMBIENT: "launcher-env" }, "started with the launcher's env plus the runtime's");
  assert.equal(got.cwd, dir);
});

test("runAgent adopts the handed-off filter: no second spawn, its exit code returned, postExit run", async () => {
  const { pre } = start("ok");
  assert.equal(await pre.handOff(handoff({ env: { EXIT_CODE: "5" } })), true);
  let posted = false;
  const code = await runAgent({
    argv: ["/nonexistent/never-spawned"], adopted: { child: pre.child, exit: pre.exit },
    env: {}, cwd: dir, detached: true, postExit: async () => { posted = true; },
  });
  assert.equal(code, 5);
  assert.equal(posted, true);
});

test("abort: the end of file ends a waiting filter at once, silently (exit 0), and nothing is left", async () => {
  const { pre, out } = start("ok");
  const t0 = Date.now();
  await pre.abort();
  assert.equal(await pre.exit, 0);
  assert.ok(Date.now() - t0 < ABORT_GRACE_MS, "ended by the end of file, not the SIGKILL");
  assert.ok(gone(pre.child.pid), "no process left");
  assert.equal(existsSync(out), false, "it was never handed anything");
  await pre.abort(); // idempotent
});

test("abort: a filter that ignores the end of file is SIGKILLed after the grace", async () => {
  const { pre } = start("ignore-eof", { abortGraceMs: 200 });
  await new Promise((r) => setTimeout(r, 300)); // let it reach its wait
  await pre.abort();
  assert.equal(await pre.exit, 128 + 9);
  assert.ok(gone(pre.child.pid));
});

test("hand-off to a filter that died first: false, and it is reaped", async () => {
  const { pre } = start("die");
  assert.equal(await pre.exit, 9);
  assert.equal(await pre.handOff(handoff()), false);
  await assert.rejects(pre.handOff(handoff()), /handed off twice/);
});

test("hand-off that gets no answer: false, and the process is ended", async () => {
  const { pre } = start("noack");
  assert.equal(await pre.handOff(handoff()), false);
  await pre.exit;
  assert.ok(gone(pre.child.pid));
});

test("hand-off that gets no answer in time: false after the timeout, and the process is ended", async () => {
  const { pre } = start("ignore-eof", { ackTimeoutMs: 300, abortGraceMs: 200 });
  // ignore-eof still answers a valid line; send it to a stand-in that is
  // stopped, so nothing can answer.
  process.kill(pre.child.pid!, "SIGSTOP");
  try {
    assert.equal(await pre.handOff(handoff()), false);
  } finally {
    try { process.kill(pre.child.pid!, "SIGCONT"); } catch { /* gone */ }
  }
  await pre.exit;
  assert.ok(gone(pre.child.pid));
});

// ── the fallbacks (utility-only) ────────────────────────────────────────────

test("handOffReplyFilter: the early filter when it answers, with its spawn time (the agent tree's age floor)", async () => {
  const before = Date.now();
  const { pre } = start("ok");
  assert.ok(pre.spawnedAtMs >= before && pre.spawnedAtMs <= Date.now(), "stamped at the spawn");
  let fresh = 0;
  const chain = await handOffReplyFilter(pre, handoff(), true, () => { fresh++; return null; }, () => {});
  assert.equal(chain?.child, pre.child);
  assert.equal(chain?.spawnedAtMs, pre.spawnedAtMs, "the adopted chain carries the early spawn time");
  assert.equal(fresh, 0);
  await chain!.exit;
});

test("handOffReplyFilter: a dead early filter is replaced by a fresh one", async () => {
  const { pre } = start("die");
  await pre.exit;
  const box: { fresh: PrestartedReplyFilter | null } = { fresh: null };
  const chain = await handOffReplyFilter(pre, handoff(), true, () => (box.fresh = start("ok").pre), () => {});
  assert.ok(box.fresh !== null);
  assert.equal(chain?.child, box.fresh.child);
  await chain!.exit;
});

test("handOffReplyFilter: one spawned with another `detached` than the scope plan's is ended and replaced", async () => {
  const { pre } = start("ok", { detached: false });
  const box: { fresh: PrestartedReplyFilter | null } = { fresh: null };
  const chain = await handOffReplyFilter(pre, handoff(), true, () => (box.fresh = start("ok").pre), () => {});
  assert.equal(chain?.child, box.fresh?.child);
  assert.equal(await pre.exit, 0, "the mismatched one got the end of file");
  await chain!.exit;
});

test("handOffReplyFilter: nothing starts ⇒ null and a WARNING (the chain runs without a filter)", async () => {
  const warned: string[] = [];
  assert.equal(await handOffReplyFilter(null, handoff(), true, () => null, (m) => warned.push(m)), null);
  assert.equal(warned.length, 1);
  assert.match(warned[0]!, /^WARNING: mandu: the reply filter could not be started — running WITHOUT it/);
  const { pre } = start("die");
  await pre.exit;
  assert.equal(await handOffReplyFilter(pre, handoff(), true, () => start("noack").pre, () => {}), null);
});

// ── the slot: a launch that stops ends its filter ───────────────────────────

test("ReplyFilterSlot: abort ends a filter nobody took; a taken one is the taker's", async () => {
  const slot = new ReplyFilterSlot();
  assert.equal(slot.started, false);
  await slot.abort(); // nothing to do
  const a = start("ok").pre;
  slot.set(a);
  assert.equal(slot.started, true);
  await slot.abort();
  assert.equal(await a.exit, 0);
  assert.ok(gone(a.child.pid));
  assert.equal(slot.started, false);

  const b = start("ok").pre;
  slot.set(b);
  assert.equal(slot.take(), b);
  await slot.abort(); // no longer the slot's
  assert.equal(b.child.exitCode, null, "the taken filter still waits");
  await b.abort();
});
