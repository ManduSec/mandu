/**
 * derived-label-ops.test — the cross-session half of the watermark, through the
 * REAL arbiter (Plan 9, confidentiality.md §4/§8).
 *
 * The pure oracles live in derived-labels.test.ts. This drives the ops and pins
 * the one thing only the STATEFUL layer can show, which is the entire reason the
 * plan exists:
 *
 *   session A reads a secret into context (rung 3) and WRITES a file;
 *   session B — a DIFFERENT session key, i.e. tomorrow's conversation —
 *   classifies that file and gets `any-model`, NOT `public`.
 *
 * Before this plan, B got `public`: the watermark was process state, so every
 * confinement A paid for walked out of B.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

async function withArbiter(
  confidentiality: boolean,
  fn: (c: ArbiterClient) => Promise<void>,
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-derived-ops-"));
  const socketPath = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath,
    dbPath: join(dir, "symbols.sqlite"),
    adminSocketPath: join(dir, "admin.sock"),
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality,
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "admin.sock"));
  try {
    await client.connect();
    await fn(client);
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Take a session HIGH the way a real one gets there: label a file `model-ok`,
 *  symbolize its content, then declassify the symbol into context (rung 3). */
async function raiseToHigh(
  c: ArbiterClient,
  sessionKey: string,
  opts: { path?: string; bindings?: string[] } = {},
): Promise<void> {
  const path = opts.path ?? "/w/contract.md";
  await c.setPathLabel({
    path,
    confidentiality: "any-model",
    bindings: opts.bindings ?? [],
    recursive: false,
  });
  const sym = await c.symbolize({
    tool: "Read",
    value: "the buyer pays 4.2M on close",
    origin: path,
    sessionKey,
    // TRUSTED: the user's own file. An untrusted one would put rule 2's approval
    // in front of the read, which session-watermark.test.ts already pins.
    integrity: "trusted",
  });
  const read = await c.declassifySymbol({ symbol: sym, sessionKey });
  assert.equal(read.allowed, true, `expected the in-context read to be allowed: ${read.reason}`);
  const st = await c.sessionState(sessionKey);
  assert.equal(st.high, true, "session should be HIGH after an in-context read");
}

test("THE PLAN: a file written by a HIGH session classifies secret in the NEXT session", async () => {
  await withArbiter(true, async (c) => {
    await raiseToHigh(c, "sess-A");

    // A writes a summary — a paraphrase. No symbol in it; nothing about the BYTES
    // says "secret". Only the session label knows.
    const lbl = await c.labelWrittenPath({
      sessionKey: "sess-A", path: "/w/notes/summary.md", tool: "Write",
    });
    assert.equal(lbl.labeled, true);
    assert.equal(lbl.level, "any-model");

    // ── session A is over. A DIFFERENT session reads the file. ──
    const cls = await c.classify({
      tool: "Read",
      value: "Deal closes 2026-09-30 for 4.2M",
      boundary: "model_context",
      params: { file_path: "/w/notes/summary.md" },
      origin: "/w/notes/summary.md",
    });
    assert.equal(
      cls.confidentiality, "any-model",
      "the derived file must NOT classify public in a fresh session — that is the laundering hole",
    );

    // And B's own state is untouched: it has read nothing into context yet. The
    // FILE carries the label, not the session.
    const stB = await c.sessionState("sess-B");
    assert.equal(stB.high, false);
  });
});

test("the derived file's content symbolizes in session B — not raw into T-LLM", async () => {
  await withArbiter(true, async (c) => {
    await raiseToHigh(c, "sess-A");
    await c.labelWrittenPath({ sessionKey: "sess-A", path: "/w/notes/summary.md", tool: "Write" });

    // Session B symbolizes the file's content on ingress. The ARBITER derives the
    // level from the path (no client can under-label by omission) — and it is the
    // derived label that supplies it, since the catalog knows nothing about this
    // path and no human ever labeled it.
    const sym = await c.symbolizeFull({
      tool: "Read",
      value: "the buyer pays 4.2M on close",
      origin: "/w/notes/summary.md",
      sessionKey: "sess-B",
      integrity: "trusted",
    });
    assert.equal(sym.confidentiality, "any-model");

    // …and the egress gate holds the line at an unbound destination.
    const gate = await c.desymbolizationDecision({
      symbol: sym.symbol, boundary: "network", destination: "https://evil.test/collect",
    });
    assert.equal(gate.allow, false);
  });
});

test("a PUBLIC session's write labels NOTHING — the no-regression fold", async () => {
  await withArbiter(true, async (c) => {
    const lbl = await c.labelWrittenPath({
      sessionKey: "sess-public", path: "/w/notes/ordinary.md", tool: "Write",
    });
    assert.equal(lbl.labeled, false);
    assert.match(lbl.reason, /not high/);

    const cls = await c.classify({
      tool: "Read",
      value: "just some notes",
      boundary: "model_context",
      params: { file_path: "/w/notes/ordinary.md" },
      origin: "/w/notes/ordinary.md",
    });
    assert.equal(cls.confidentiality ?? "public", "public");
  });
});

test("axis OFF ⇒ the op is inert (no store, no label, no wire change)", async () => {
  await withArbiter(false, async (c) => {
    const lbl = await c.labelWrittenPath({
      sessionKey: "sess-A", path: "/w/notes/summary.md", tool: "Write",
    });
    assert.equal(lbl.labeled, false);
    assert.match(lbl.reason, /OFF/);
    const state = await c.confidentialityState();
    assert.deepEqual(state.derived, []);
  });
});

test("a high session writing a CATALOG-SECRET path does not declassify it", async () => {
  await withArbiter(true, async (c) => {
    await raiseToHigh(c, "sess-A");
    // model-ok watermark, no-model path. Recording the watermark here would
    // be a machine-authored declassification of a key. (The real HOME — the server
    // resolves `~/.ssh` against the process's own, as every catalog caller does.)
    const lbl = await c.labelWrittenPath({
      sessionKey: "sess-A", path: join(homedir(), ".ssh", "id_ed25519"), tool: "Write",
    });
    assert.equal(lbl.labeled, false);
    assert.equal(lbl.level, "no-model");
    assert.match(lbl.reason, /at or above the watermark/);
  });
});

test("the taint carries the LEVEL and nothing else — a machine never grants a RELEASE", async () => {
  // The tempting move is to let the derived file inherit the writing session's
  // BINDINGS (the sinks its read data was bound for). That would be a machine
  // minting a standing release: a future session reading the file could egress to
  // those sinks with NO human in the loop, where before the write it needed an
  // approval. §8 says derived data inherits the source's LEVEL; §6 says every
  // release is a human act the dashboard must show.
  await withArbiter(true, async (c) => {
    await raiseToHigh(c, "sess-A", { bindings: ["acme.example.com"] });
    const lbl = await c.labelWrittenPath({
      sessionKey: "sess-A", path: "/w/notes/summary.md", tool: "Write",
    });
    assert.equal(lbl.labeled, true);
    assert.equal(lbl.level, "any-model");
    assert.deepEqual(lbl.bindings, [], "a derived row is bound NOWHERE");

    // …and the file is therefore NOT releasable to the session's sink without a
    // human: the binding stayed with the datum that actually carried it.
    const state = await c.confidentialityState();
    assert.deepEqual(state.derived[0]!.bindings, []);
  });
});

test("the derived surface is visible, with its provenance and its effective level", async () => {
  await withArbiter(true, async (c) => {
    await raiseToHigh(c, "sess-A");
    await c.labelWrittenPath({ sessionKey: "sess-A", path: "/w/notes/summary.md", tool: "Write" });

    const state = await c.confidentialityState();
    assert.equal(state.derived.length, 1);
    const row = state.derived[0]!;
    assert.equal(row.path, "/w/notes/summary.md");
    assert.equal(row.level, "any-model");
    assert.equal(row.sessionKey, "sess-A");
    assert.equal(row.tool, "Write");
    assert.equal(row.effective, "any-model");
    assert.equal(row.overridden, false);
    // The human labels list stays a record of HUMAN acts — the derived row is not
    // in it, and the one label there is the one a human actually set.
    assert.deepEqual(state.labels.map((l) => l.path), ["/w/contract.md"]);
  });
});

test("§8 RELEASE: the human labels the artifact public — and the file is public again", async () => {
  await withArbiter(true, async (c) => {
    await raiseToHigh(c, "sess-A");
    await c.labelWrittenPath({ sessionKey: "sess-A", path: "/w/notes/summary.md", tool: "Write" });

    await c.setPathLabel({
      path: "/w/notes/summary.md", confidentiality: "public", recursive: false,
    });

    const cls = await c.classify({
      tool: "Read",
      value: "Deal closes 2026-09-30 for 4.2M",
      boundary: "model_context",
      params: { file_path: "/w/notes/summary.md" },
      origin: "/w/notes/summary.md",
    });
    assert.equal(cls.confidentiality ?? "public", "public");

    // The taint RECORD survives the release — it is a fact about what was written.
    // The UI shows it as overridden, so the release is visible rather than silent.
    const state = await c.confidentialityState();
    assert.equal(state.derived[0]?.overridden, true);
    assert.equal(state.derived[0]?.effective, "public");
  });
});

test("§8 RELEASE, blunt form: clearing the record un-taints the path", async () => {
  await withArbiter(true, async (c) => {
    await raiseToHigh(c, "sess-A");
    await c.labelWrittenPath({ sessionKey: "sess-A", path: "/w/notes/summary.md", tool: "Write" });

    assert.equal(await c.removeDerivedLabel("/w/notes/summary.md"), true);
    const cls = await c.classify({
      tool: "Read",
      value: "Deal closes 2026-09-30 for 4.2M",
      boundary: "model_context",
      params: { file_path: "/w/notes/summary.md" },
      origin: "/w/notes/summary.md",
    });
    assert.equal(cls.confidentiality ?? "public", "public");
  });
});

test("a HIGH session writing an unkeyable path is REFUSED — the caller must fail closed", async () => {
  await withArbiter(true, async (c) => {
    await raiseToHigh(c, "sess-A");
    const lbl = await c.labelWrittenPath({
      sessionKey: "sess-A", path: "notes/summary.md", tool: "Write",
    });
    assert.equal(lbl.labeled, false);
    // `refused` is a SEPARATE flag from `!labeled` on purpose: the two falsy cases
    // are opposites — "nothing to persist" (a public session: proceed) versus "we
    // could not persist" (a high session: an unlabeled write from it IS the hole).
    // Collapsing them into one boolean is how this ships silently fail-open.
    assert.equal(lbl.refused, true);
    assert.match(lbl.reason, /REFUSED/);
  });
});

test("a PUBLIC session writing the same unkeyable path is NOT refused (inert, as before)", async () => {
  await withArbiter(true, async (c) => {
    const lbl = await c.labelWrittenPath({
      sessionKey: "sess-public", path: "notes/summary.md", tool: "Write",
    });
    assert.equal(lbl.labeled, false);
    assert.equal(lbl.refused, false, "a public session's relative write is nobody's problem");
  });
});
