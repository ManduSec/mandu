/**
 * store-flags.test — the daemon's store paths come from its flags, live
 * (ipc/server-args.ts, on-disk-layout.md §5): spawns the REAL daemon
 * entrypoint with `--symbol-db` / `--event-dir` and asserts
 *   - the symbol DB (with the secret's original in it) and the session's
 *     event log land at the flagged paths, and the manifest names them;
 *   - the retired MANDU_SYMBOL_DB / MANDU_EVENT_DIR, set in the daemon's
 *     environment, move nothing: no file appears at either, and nothing
 *     lands in the (temp) home's defaults either;
 *   - a flag with no value refuses the start before any instance registers.
 *
 * The DB holds every original behind a `$MDU:` symbol, so where it lands is
 * a confidentiality property: a session that could set its own environment
 * must not be able to point the arbiter's originals somewhere else.
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterClient } from "../../ipc/client.js";
import { INSTANCES_DIR } from "../../ipc/instance.js";
import { openSymbolDb } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");
const SECRET = "ghp_" + "Q7x".repeat(12);

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

interface Scratch {
  root: string;
  home: string;
  base: string;
  sock: string;
  cleanup: () => void;
}

function scratch(): Scratch {
  const root = mkdtempSync(join(tmpdir(), "mdu-"));
  return {
    root,
    home: join(root, "home"),
    base: join(root, "rt"),
    sock: join(root, "a.sock"),
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

/** `node --import tsx` so the signalled process IS the daemon (see
 *  instance-mode.test.ts). A temp MANDU_HOME: the defaults stay in the test's
 *  tree, and the test can see that nothing reached them. */
function spawnDaemon(s: Scratch, args: string[], extraEnv: Record<string, string> = {}): { child: ChildProcess; stderr: () => string } {
  let err = "";
  const child = spawn(process.execPath, ["--import", "tsx", SERVER_MAIN, ...args], {
    cwd: ARBITER_DIR,
    env: {
      ...process.env,
      MANDU_HOME: s.home,
      MANDU_RUNTIME_DIR: s.base,
      MANDU_ARBITER_SOCK: s.sock,
      MANDU_INBOUND_SPEC: "",
      MANDU_TENANT: "",
      MANDU_LIFELINE: "",
      ...extraEnv,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  child.stderr!.setEncoding("utf8");
  child.stderr!.on("data", (c: string) => { err += c; });
  return { child, stderr: () => err };
}

async function waitFor(pred: () => boolean, what: string, ms = 90_000): Promise<void> {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (pred()) return;
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    const kill = setTimeout(() => { child.kill("SIGKILL"); }, 60_000);
    kill.unref();
    child.once("exit", () => { clearTimeout(kill); resolve(); });
    child.kill("SIGTERM");
  });
}

function manifestOf(s: Scratch): { eventDir: string; symbolDb: string } | null {
  const dir = join(s.base, INSTANCES_DIR);
  if (!existsSync(dir)) return null;
  for (const id of readdirSync(dir)) {
    const p = join(dir, id, "manifest.json");
    if (!existsSync(p)) continue;
    // An unparsable manifest (another writer's, or a torn read) is "not yet":
    // waitFor keeps polling; the assertions below stay strict on what it holds.
    try {
      return JSON.parse(readFileSync(p, "utf8")) as { eventDir: string; symbolDb: string };
    } catch {
      continue;
    }
  }
  return null;
}

test("--symbol-db / --event-dir place the stores; the retired MANDU_SYMBOL_DB / MANDU_EVENT_DIR move nothing", async () => {
  const s = scratch();
  const db = join(s.root, "flag", "arb.db");
  const events = join(s.root, "flag", "events");
  const retiredDb = join(s.root, "retired", "x.db");
  const retiredEvents = join(s.root, "retired", "events");
  const d = spawnDaemon(s, ["--symbol-db", db, `--event-dir=${events}`], {
    MANDU_SYMBOL_DB: retiredDb,
    MANDU_EVENT_DIR: retiredEvents,
  });
  try {
    await waitFor(() => manifestOf(s) !== null && existsSync(s.sock), `the daemon (stderr: ${d.stderr()})`);
    assert.deepEqual(
      { eventDir: manifestOf(s)!.eventDir, symbolDb: manifestOf(s)!.symbolDb },
      { eventDir: events, symbolDb: db },
      "the manifest names the flagged stores",
    );
    assert.match(d.stderr(), new RegExp(`symbol DB: ${db.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    const client = new ArbiterClient(s.sock);
    try {
      const r = await client.registerEnvSecrets({ vars: [{ name: "GITHUB_TOKEN", value: SECRET }], sessionKey: "sf" });
      assert.ok(r.vars[0]?.symbol, `the secret is symbolized (${JSON.stringify(r.vars)})`);
      assert.ok(!r.vars[0]!.symbol!.includes(SECRET), "the symbol is opaque");
      await client.emit({ sessionId: "sf", id: "e1" });
    } finally {
      await client.close();
    }
  } finally {
    await stop(d.child);
  }
  try {
    assert.ok(existsSync(join(events, "sf.ndjson")), "the session's events are in --event-dir");
    const conn = openSymbolDb(db, { HOME: s.home, MANDU_HOME: s.home });
    try {
      const row = conn.prepare("SELECT count(*) AS n FROM symbols WHERE value = ?").get(SECRET) as { n: number };
      assert.equal(row.n, 1, "the original is in the --symbol-db DB");
    } finally {
      conn.close();
    }
    assert.ok(!existsSync(join(s.root, "retired")), "nothing at the retired variables' paths");
    assert.ok(!existsSync(join(s.home, "state", "mandu.db")), "nothing at the home's default DB");
    assert.ok(!existsSync(join(s.home, "events")), "nothing at the home's default events");
  } finally {
    s.cleanup();
  }
});

test("without flags the stores are the home's defaults, whatever the retired variables say", async () => {
  const s = scratch();
  const retired = join(s.root, "retired");
  const d = spawnDaemon(s, [], {
    MANDU_SYMBOL_DB: join(retired, "x.db"),
    MANDU_EVENT_DIR: join(retired, "events"),
  });
  try {
    await waitFor(() => manifestOf(s) !== null && existsSync(s.sock), `the daemon (stderr: ${d.stderr()})`);
    assert.equal(manifestOf(s)!.symbolDb, join(s.home, "state", "mandu.db"));
    assert.equal(manifestOf(s)!.eventDir, join(s.home, "events"));
    const client = new ArbiterClient(s.sock);
    try {
      await client.emit({ sessionId: "sd", id: "e1" });
    } finally {
      await client.close();
    }
  } finally {
    await stop(d.child);
  }
  try {
    assert.ok(existsSync(join(s.home, "events", "sd.ndjson")));
    assert.ok(existsSync(join(s.home, "state", "mandu.db")));
    assert.ok(!existsSync(retired), "the retired variables are not read");
  } finally {
    s.cleanup();
  }
});

test("a store flag without a value refuses the start, before any instance registers", async () => {
  const s = scratch();
  try {
    const d = spawnDaemon(s, ["--event-dir", join(s.root, "ev"), "--symbol-db"]);
    const code = await new Promise<number | null>((r) => d.child.once("exit", (c) => r(c)));
    assert.equal(code, 1, `refused; stderr:\n${d.stderr()}`);
    assert.match(d.stderr(), /--symbol-db needs a path/);
    assert.equal(manifestOf(s), null, "no instance registered");
    assert.ok(!existsSync(join(s.root, "ev")) && !existsSync(s.home), "no store created");
  } finally {
    s.cleanup();
  }
});
