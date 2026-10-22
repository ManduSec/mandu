/**
 * session-kept-line.test — the launcher's half of the session's last line
 * (src/session-kept-line.ts; packaging.md §5 *The session's last line*):
 * the answer's line printed only when it is one `mandu: ` line, with every
 * control character replaced and an overlong one cut; the dashboards asked
 * newest first, at most two, each only through a socket in this runtime's
 * human-plane directory, the next one after a failure, none past the
 * deadline; nothing ever thrown. The words and counts are the dashboard's
 * (its session-kept unit test); here only what the launcher does with them.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keptLineOf, sessionKeptLine, SESSION_KEPT_DASHBOARDS, SESSION_KEPT_LINE_MAX, SESSION_KEPT_OP } from "../../src/session-kept-line.js";

const BASE = "/run/user/1000/mandu";
const dash = (pid: number, sock = `${BASE}/human/dashboard-${pid}.sock`) => ({ host: "127.0.0.1", port: 4500, signInSock: sock });
const LINE = "mandu: in this session: 1 secret masked before the AI saw it (DB_PASSWORD in ~/proj/.env) · details: `mandu dashboard`";
const found = (line = LINE) => ({ ok: true, found: true, line, kept: {} });

test("keptLineOf: one `mandu: ` line, printable; anything else is nothing", () => {
  assert.equal(keptLineOf(found()), LINE);
  assert.equal(keptLineOf(found("mandu: kept \u001b[2J\u001b]0;x\u0007 (‮evil)")), "mandu: kept ?[2J?]0;x? (?evil)", "no escape reaches the terminal");
  for (const bad of [
    null, undefined, "x", 7, {}, { ok: true, found: false }, { ok: false, reason: "unknown", error: "e" },
    { ok: true, found: true, line: 5 }, found("two\nlines"), found("mandu: a\rb"), found("not a mandu line"),
  ]) assert.equal(keptLineOf(bad), null, JSON.stringify(bad));
  const long = keptLineOf(found("mandu: " + "x".repeat(2000)))!;
  assert.equal(long.length, SESSION_KEPT_LINE_MAX);
  assert.ok(long.endsWith("…"));
});

test("sessionKeptLine: the newest dashboard first, with the op and the session; the first that knows it wins", async () => {
  const asked: Array<{ sock: string; req: Record<string, unknown> }> = [];
  const line = await sessionKeptLine({
    session: "1791-42", runtimeBase: BASE, dashboards: [dash(2), dash(1)],
    call: async (sock, req) => { asked.push({ sock, req }); return sock.endsWith("-2.sock") ? { ok: true, found: false } : found(); },
  });
  assert.equal(line, LINE);
  assert.deepEqual(asked.map((a) => a.sock), [`${BASE}/human/dashboard-2.sock`, `${BASE}/human/dashboard-1.sock`]);
  assert.deepEqual(asked[0]!.req, { op: SESSION_KEPT_OP, session: "1791-42" });
});

test("sessionKeptLine: a socket outside the human-plane directory (or none) is never asked; a failing one is skipped; at most two", async () => {
  const asked: string[] = [];
  const call = async (sock: string) => {
    asked.push(sock);
    if (sock.endsWith("-3.sock")) throw new Error("ECONNREFUSED");
    return found();
  };
  const line = await sessionKeptLine({
    session: "s", runtimeBase: BASE, call,
    dashboards: [dash(9, "/tmp/planted/dashboard-9.sock"), { host: "127.0.0.1", port: 1 }, dash(3), dash(4), dash(5)],
  });
  assert.equal(line, null, `only the first ${SESSION_KEPT_DASHBOARDS} entries are considered, and neither of them may be asked`);
  assert.deepEqual(asked, []);
  const second = await sessionKeptLine({ session: "s", runtimeBase: BASE, call, dashboards: [dash(3), dash(4)] });
  assert.equal(second, LINE, "the next dashboard after one that failed");
  assert.deepEqual(asked, [`${BASE}/human/dashboard-3.sock`, `${BASE}/human/dashboard-4.sock`]);
});

test("sessionKeptLine: the deadline is the whole wait; nothing past it; no dashboard, nothing; never throws", async () => {
  let t = 0;
  const timeouts: number[] = [];
  const slow = async (_s: string, _r: Record<string, unknown>, timeoutMs: number) => { timeouts.push(timeoutMs); t += 3_000; throw new Error("timed out"); };
  assert.equal(await sessionKeptLine({ session: "s", runtimeBase: BASE, dashboards: [dash(1), dash(2)], call: slow, timeoutMs: 4_000, now: () => t }), null);
  assert.deepEqual(timeouts, [4_000, 1_000], "the second gets what is left");
  t = 0;
  timeouts.length = 0;
  const slower = async (_s: string, _r: Record<string, unknown>, timeoutMs: number) => { timeouts.push(timeoutMs); t += 5_000; throw new Error("timed out"); };
  assert.equal(await sessionKeptLine({ session: "s", runtimeBase: BASE, dashboards: [dash(1), dash(2)], call: slower, timeoutMs: 4_000, now: () => t }), null);
  assert.deepEqual(timeouts, [4_000], "none asked past the deadline");
  assert.equal(await sessionKeptLine({ session: "s", runtimeBase: BASE, dashboards: [] }), null);
});

test("sessionKeptLine over a real Unix socket: the dashboard's protocol, one line each way", async () => {
  const base = mkdtempSync(join(tmpdir(), "mdu-kept-line-"));
  mkdirSync(join(base, "human"), { mode: 0o700 });
  const sock = join(base, "human", "dashboard-77.sock");
  let got = "";
  const srv = createServer((c) => {
    c.setEncoding("utf8");
    c.on("data", (d: string) => { got += d; if (got.includes("\n")) c.end(JSON.stringify(found()) + "\n"); });
  });
  await new Promise<void>((r) => srv.listen(sock, r));
  try {
    assert.equal(await sessionKeptLine({ session: "1791-7", runtimeBase: base, dashboards: [dash(77, sock)] }), LINE);
    assert.deepEqual(JSON.parse(got.trim()), { op: SESSION_KEPT_OP, session: "1791-7" });
  } finally {
    srv.close();
    rmSync(base, { recursive: true, force: true });
  }
});
