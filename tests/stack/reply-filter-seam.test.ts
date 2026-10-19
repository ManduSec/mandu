/**
 * reply-filter-seam.test.ts — the base↔field SSE seam, pinned against the REAL
 * arbiter (integration e2e; deterministic, no model, no network).
 *
 * THE SEAM (third live hit 2026-07-19, pipeline 6420 / session
 * claude-e2e-interactive-inspect-extract-1784425815738; earlier
 * 1783831380-3877123 and pipeline 6414): a model streams a symbol-terminal
 * reply's base (`$MDU:inspect[c72f]`) and its `.result` field tail in SEPARATE
 * SSE deltas. When TUI frame control lands between them, the reply-filter's
 * candidate hold breaks by design (the narrow glue set — filter.ts header) and
 * the bare base goes to the arbiter, which had only minted the field-ful name:
 * the base came back unchanged and the HUMAN TERMINAL showed a raw token for
 * the whole session (0 desymbolize events + a raw $MDU: token in the stream —
 * the exact red triple of the live incident).
 *
 * THE FIX lives in the ARBITER's shared lookup walk, not the filter: a token
 * whose shortening candidates all miss resolves to the ONE allocated name
 * extending it at a `.` field boundary (symbol-format uniqueFieldExtension).
 * This file proves the fix END-TO-END across the real components — the real
 * ArbiterServer minting via the real symbolize op, the real reply-filter
 * stream core resolving over the real IPC client — for both stream shapes the
 * seam takes:
 *
 *   (a) INTERPOSED: base mid-frame, followed by TUI footer control in the same
 *       chunk (the candidate hold never engages), `.result` arriving later via
 *       an Ink diff-skip CHA. Before the fix the base emitted RAW.
 *   (b) TAIL-HELD: base is the chunk tail (the hold engages), the idle drain
 *       fires before the field arrives. Before the fix the drain re-held and,
 *       past its budget, emitted RAW.
 *
 * Accepted residual, asserted-as-documented here: the value splices where the
 * BASE stood, so the later `.result` glyphs print as a brief stray until the
 * TUI's next full repaint (which carries the complete token and resolves
 * exactly). The stray contains no `$MDU:` bytes — nothing symbol-shaped ever
 * reaches the human. Mid-hash splits (`$MDU:inspect[c7` / `2f].result`)
 * remain the documented unfixable-by-alias residual (never observed live).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ── REAL components under test (imported across package boundaries) ───────────
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ReplyStreamFilter } from "../../interceptors/reply-filter/src/filter.js";
import { ArbiterClientAdapter } from "../../interceptors/reply-filter/src/arbiter-client.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const ADVISORY_ID = "SA-2026-0777";
/** The raw-token leak detector — same surface evalTerminalEgressClean guards. */
const RAW_TOKEN_RE = /\$MDU:/;

interface SeamRig {
  client: ArbiterClient;
  /** The allocated field-ful name (`$MDU:inspect[hash].result`). */
  full: string;
  /** Its stranded base (`$MDU:inspect[hash]`) — never allocated. */
  base: string;
  close: () => Promise<void>;
}

async function startRig(): Promise<SeamRig> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-seam-e2e-"));
  const socketPath = join(dir, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath,
    humanSocketPath: humanSockIn(dir),
    dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"),
    log: () => {},
  });
  await arbiter.listen();
  // The reply filter is a human-plane consumer (arbiter-human-plane.md): its
  // adapter rides the human socket; minting below uses it too (human ⊇ data).
  const client = new ArbiterClient(humanSockIn(dir));
  await client.connect();
  // Mint exactly what inspect-mcp mints (inspect-symbol.ts step 3): the U-LLM
  // result under tool inspect_symbol with field "result" — the allocated name
  // is field-ful; the bare base exists nowhere in the table.
  const full = await client.symbolize({
    tool: "mcp__mandu-inspect__inspect_symbol",
    value: ADVISORY_ID,
    field: "result",
    sessionKey: "reply-filter-seam-e2e",
  });
  assert.match(full, /^\$MDU:inspect\[[0-9a-f]{4,8}\]\.result$/, "the minted name is field-ful");
  const base = full.replace(/\.result$/, "");
  return {
    client,
    full,
    base,
    close: async () => {
      client.close();
      await arbiter.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function eagerFilter(rig: SeamRig): { filter: ReplyStreamFilter; resolves: Array<{ before: string; after: string }> } {
  const resolves: Array<{ before: string; after: string }> = [];
  const filter = new ReplyStreamFilter(new ArbiterClientAdapter(rig.client), {
    eager: true,
    onResolve: (before, after) => {
      resolves.push({ before, after });
    },
  });
  return { filter, resolves };
}

test("seam (a) INTERPOSED: a mid-frame stranded base resolves via the arbiter alias — no raw token reaches the human", async () => {
  const rig = await startRig();
  try {
    const { filter, resolves } = eagerFilter(rig);
    let out = "";
    // Frame A: the reply text with the BASE, then TUI footer control in the
    // SAME chunk (cursor-show + CUP) — the shape that breaks the candidate
    // hold, so the base goes to the arbiter immediately.
    out += await filter.write(`advisory:${rig.base}[?25h[2;1H`);
    // Frame B: the field tail via the Ink diff-skip idiom (CHA + `.result`).
    out += await filter.write(`[30G.result`);
    out += await filter.flush();

    assert.ok(out.includes(ADVISORY_ID), "the human stream carries the resolved value");
    assert.ok(!RAW_TOKEN_RE.test(out), `no raw $MDU: token in the human stream: ${JSON.stringify(out)}`);
    assert.ok(
      resolves.some((r) => r.after.includes(ADVISORY_ID)),
      "the desymbolize observability seam fired with the resolved value",
    );
  } finally {
    await rig.close();
  }
});

test("seam (b) TAIL-HELD: the idle drain resolves a held base via the alias instead of re-holding to a raw emit", async () => {
  const rig = await startRig();
  try {
    const { filter, resolves } = eagerFilter(rig);
    let out = "";
    // The base is the chunk TAIL — the candidate hold engages.
    out += await filter.write(`advisory:${rig.base}`);
    assert.ok(!out.includes(rig.base), "the candidate base is held, not emitted");
    // The relay's quiet-period drain fires before the field delta arrives.
    out += await filter.flush(false);
    assert.ok(out.includes(ADVISORY_ID), "the first idle drain resolves the base (alias) — no re-hold needed");
    // The straggling field tail arrives afterwards: a brief glyph stray the
    // next repaint clears — but never anything token-shaped.
    out += await filter.write(`.result`);
    out += await filter.flush();

    assert.ok(!RAW_TOKEN_RE.test(out), `no raw $MDU: token in the human stream: ${JSON.stringify(out)}`);
    assert.ok(resolves.some((r) => r.after.includes(ADVISORY_ID)));
  } finally {
    await rig.close();
  }
});

test("control: a token whole in one frame resolves exactly as before (the alias tier never engages)", async () => {
  const rig = await startRig();
  try {
    const { filter } = eagerFilter(rig);
    let out = "";
    out += await filter.write(`advisory:${rig.full}\r\n`);
    out += await filter.flush();
    assert.ok(out.includes(ADVISORY_ID));
    assert.ok(!RAW_TOKEN_RE.test(out));
  } finally {
    await rig.close();
  }
});
