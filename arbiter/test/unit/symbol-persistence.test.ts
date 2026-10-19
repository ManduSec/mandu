/**
 * symbol-persistence.test.ts — the symbolize op PERSISTS across an arbiter
 * restart (the server.ts "Hydrate the symbol table from disk so a restart
 * keeps prior symbols" contract, exercised end-to-end over IPC).
 *
 * Regression (found 2026-07-10): the daemon constructed with a resolved-by-
 * default dbPath handed the RAW `this.dbPath` (undefined) to allocateSymbol,
 * whose undefined-dbPath branch is "in-memory only" (the unit-fixture mode) —
 * so every minted symbol silently died with the process while loadSymbolMap
 * dutifully re-read an empty file at each start. An arbiter restart therefore
 * lost every historical session's symbol table: the dashboard's delivered-
 * reply deep reveal and the U-LLM's `resolve` had nothing left to resolve.
 *
 * Run: npm run test:unit
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

let workdir: string;

before(() => {
  workdir = mkdtempSync(join(tmpdir(), "mandu-sympersist-"));
});

after(() => {
  rmSync(workdir, { recursive: true, force: true });
});

test("a symbol minted via the symbolize op survives an arbiter restart (deep desymbolize still resolves)", async () => {
  const dbPath = join(workdir, "symbols.db");

  // Life 1: mint a NESTED chain (the fs-sync twin-Read double-symbolization
  // shape the dashboard's delivery reveal depends on).
  const sockA = join(workdir, "a.sock");
  const serverA = new ArbiterServer({ socketPath: sockA, dbPath, eventDir: join(workdir, "events"), log: () => {} });
  await serverA.listen();
  const clientA = new ArbiterClient(sockA);
  await clientA.connect();
  const inner = await clientA.symbolize({
    tool: "Read", value: "RAW ORIGINAL NOTES", origin: "/ws/notes.md",
    sessionKey: "persist-s1", callId: "c-inner",
  });
  const outer = await clientA.symbolize({
    tool: "Read", value: `1\t${inner}\n2\t`, origin: "/agentview/notes.md",
    sessionKey: "persist-s1", callId: "c-outer",
  });
  clientA.close();
  await serverA.close();

  // Life 2: a FRESH server over the same dbPath — the restart. The chain must
  // hydrate from disk and the deep desymbolize must collapse it to the original.
  const sockB = join(workdir, "b.sock");
  // desymbolize is human-plane only (arbiter-human-plane.md).
  const serverB = new ArbiterServer({ socketPath: sockB, humanSocketPath: join(workdir, "human", "b.sock"), dbPath, eventDir: join(workdir, "events"), log: () => {} });
  await serverB.listen();
  const clientB = new ArbiterClient(join(workdir, "human", "b.sock"));
  await clientB.connect();
  try {
    const resolved = await clientB.desymbolize(`reply: ${outer}`);
    assert.equal(resolved, "reply: 1\tRAW ORIGINAL NOTES\n2\t",
      "the nested chain minted in life 1 fully resolves after the restart");
  } finally {
    clientB.close();
    await serverB.close();
  }
});

test("the DAEMON default (no explicit dbPath) also persists — regression for the in-memory fallthrough", async () => {
  // Without opts.dbPath the server resolves getSymbolDbPath(), the home's
  // state/mandu.db. Constructing WITHOUT opts.dbPath must still persist
  // (the broken path handed allocateSymbol an undefined dbPath = in-memory).
  const home = join(workdir, "daemon-default-home");
  const dbPath = join(home, "state", "mandu.db");
  const prev = process.env.MANDU_HOME;
  process.env.MANDU_HOME = home;
  try {
    const sockA = join(workdir, "da.sock");
    const serverA = new ArbiterServer({ socketPath: sockA, eventDir: join(workdir, "events"), log: () => {} });
    await serverA.listen();
    const clientA = new ArbiterClient(sockA);
    await clientA.connect();
    const sym = await clientA.symbolize({
      tool: "WebFetch", value: "DAEMON PERSISTED VALUE", sessionKey: "persist-s2", callId: "c1",
    });
    clientA.close();
    await serverA.close();

    const sockB = join(workdir, "db.sock");
    const serverB = new ArbiterServer({ socketPath: sockB, humanSocketPath: join(workdir, "human", "db.sock"), eventDir: join(workdir, "events"), log: () => {} });
    await serverB.listen();
    const clientB = new ArbiterClient(join(workdir, "human", "db.sock"));
    await clientB.connect();
    try {
      const resolved = await clientB.desymbolize(sym);
      assert.equal(resolved, "DAEMON PERSISTED VALUE",
        "a daemon-default (home-resolved) DB path persists across restarts");
      assert.ok(existsSync(dbPath), "the default DB is the home's state/mandu.db");
    } finally {
      clientB.close();
      await serverB.close();
    }
  } finally {
    if (prev === undefined) delete process.env.MANDU_HOME;
    else process.env.MANDU_HOME = prev;
  }
});
