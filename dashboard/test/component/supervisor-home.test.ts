/**
 * supervisor-home e2e — the supervisor starts the REAL arbiter twice (the live
 * tenant and the test tenant) under a temp MANDU_HOME, and each tenant's
 * stores land where the path table says (on-disk-layout.md §3, §5):
 *
 *   live  → <home>/state/mandu.db       + <home>/events/        (no flags: the
 *                                                                 arbiter's defaults)
 *   test  → <home>/state/mandu-test.db  + <home>/events/test/   (--symbol-db /
 *                                                                 --event-dir flags)
 *
 * Proven three ways per tenant: the arbiter's own `hello` names the paths,
 * the DB file exists there, and an emitted event is written there. The
 * retired MANDU_SYMBOL_DB / MANDU_EVENT_DIR are set to a decoy dir in the
 * supervisor's own env for the whole run: nothing may land in it.
 *
 * Axes (protection-modes.md §4): the live arbiter is pinned to `secrets`
 * through the supervisor's axis seam; the test arbiter states its own
 * (`injection`, supervisor-defs.ts). Mandu-new test (NO reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { connect } from "node:net";
import { existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Supervisor } from "../../src/supervisor/supervisor.js";
import { testTenantPaths } from "../../src/supervisor/supervisor-defs.js";
import { helloProbe } from "../../src/net-probes.js";
import { START_DEADLINE_MS, SERVER_TEST_TIMEOUT_MS } from "./server-up.js";
import { tmpDir } from "../unit/tmp-dir.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

/** One NDJSON request/response over the arbiter socket (no arbiter import:
 *  the dashboard stays standalone). */
function rpc(sock: string, req: Record<string, unknown>): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  return new Promise((resolve, reject) => {
    const s = connect({ path: sock });
    let buf = "";
    s.setTimeout(10_000, () => { s.destroy(); reject(new Error(`rpc ${String(req.op)} timed out`)); });
    s.once("error", reject);
    s.once("connect", () => s.write(JSON.stringify({ id: 1, ...req }) + "\n"));
    s.on("data", (c) => {
      buf += c.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      s.destroy();
      resolve(JSON.parse(buf.slice(0, nl)));
    });
  });
}

/** helloProbe gives up after 1.5 s of silence and answers null. A just-started
 *  arbiter under a loaded host (the full suite runs its files in parallel)
 *  can take longer to answer, and one null failed this test once
 *  (2026-09-30, full dashboard suite on the shared host; alone it passed).
 *  The supervisor retries a null identity itself (refreshAdoptedIdentity), so
 *  the test retries too, up to the start deadline, and reports how long the
 *  answer took if it never comes. */
async function helloWithin(sock: string, deadlineMs: number): Promise<{ id: Awaited<ReturnType<typeof helloProbe>>; tries: number; ms: number }> {
  const t0 = Date.now();
  let tries = 0;
  for (;;) {
    tries++;
    const id = await helloProbe(sock);
    if (id || Date.now() - t0 >= deadlineMs) return { id, tries, ms: Date.now() - t0 };
    await new Promise((r) => setTimeout(r, 200));
  }
}

const SAVED_KEYS =["MANDU_HOME", "MANDU_RUNTIME_DIR", "MANDU_SYMBOL_DB", "MANDU_EVENT_DIR"] as const;

test("supervisor under a temp MANDU_HOME: live stores at state/mandu.db + events/, the test tenant's at state/mandu-test.db + events/test; the retired variables move nothing",
  { timeout: SERVER_TEST_TIMEOUT_MS * 2 }, async () => {
  const dir = tmpDir("mandu-sup-home-");
  const home = join(dir, "home");
  const decoy = join(dir, "decoy");
  const saved = Object.fromEntries(SAVED_KEYS.map((k) => [k, process.env[k]]));
  // The supervisor builds its definitions and spawns from process.env, so the
  // isolation goes there (restored in finally).
  process.env.MANDU_HOME = home;
  process.env.MANDU_RUNTIME_DIR = join(dir, "rt");
  process.env.MANDU_SYMBOL_DB = join(decoy, "sym.db");
  process.env.MANDU_EVENT_DIR = join(decoy, "events");
  const liveSock = join(dir, "run", "arbiter.sock");
  const logs: string[] = [];
  const sup = new Supervisor({
    repoRoot: REPO,
    arbiterSock: liveSock,
    startTimeoutMs: START_DEADLINE_MS,
    axisEnv: () => ({ MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "1" }), // `secrets`, stated
    log: (m) => logs.push(m),
  });
  try {
    await sup.start("arbiter");
    await sup.start("test-arbiter");
    const tt = testTenantPaths({ arbiterSock: liveSock });
    assert.equal(tt.symbolDb, join(home, "state", "mandu-test.db"));
    assert.equal(tt.eventDir, join(home, "events", "test"));

    const cases = [
      { tenant: "live", sock: liveSock, db: join(home, "state", "mandu.db"), events: join(home, "events") },
      { tenant: "test", sock: tt.sock, db: tt.symbolDb, events: tt.eventDir },
    ];
    for (const c of cases) {
      const { id, tries, ms } = await helloWithin(c.sock, START_DEADLINE_MS);
      assert.ok(id, `${c.tenant} arbiter answers hello (${tries} tries over ${ms} ms; logs: ${logs.join("\n")})`);
      assert.equal(id!.symbolDb, c.db, `${c.tenant} arbiter's own symbol DB`);
      assert.equal(id!.eventDir, c.events, `${c.tenant} arbiter's own event dir`);
      assert.ok(existsSync(c.db), `${c.tenant} DB created at ${c.db}`);
      const sessionId = `e2e-home-${c.tenant}`;
      const r = await rpc(c.sock, { op: "emit", event: { id: `${sessionId}-1`, sessionId, ts: new Date().toISOString(), kind: "probe" } });
      assert.equal(r.ok, true, `${c.tenant} emit: ${r.error ?? ""}`);
      const file = join(c.events, `${sessionId}.ndjson`);
      assert.ok(existsSync(file), `${c.tenant} event written under ${c.events}`);
      assert.match(readFileSync(file, "utf8"), new RegExp(`"tenant":"${c.tenant}"`), `${c.tenant} arbiter stamped its tenant`);
    }
    assert.ok(!existsSync(join(home, "events", "e2e-home-test.ndjson")), "the test tenant's event never reaches the live dir");
    assert.ok(!existsSync(decoy), `the retired variables placed nothing (${existsSync(decoy) ? readdirSync(decoy).join(", ") : ""})`);
  } finally {
    await sup.shutdownAll();
    for (const k of SAVED_KEYS) {
      if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
