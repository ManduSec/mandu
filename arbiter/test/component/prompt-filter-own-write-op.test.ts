/**
 * prompt-filter-own-write-op.test — which rows a HIGH session's own writes
 * exempt in its human text (confidentiality-plan-15-prompt-filter.md
 * §13.10), through the real ArbiterServer's ops: `declassifySymbol` (the
 * session goes HIGH), `recordToolCall` (the model proxy's record of the
 * Write, with its content), `labelWrittenPath` (the Plan 9 derived label),
 * `registerSecret` (the file's row), `filterPrompt`. Mandu-new.
 *
 * Proves:
 *   - a file the HIGH session created with `Write` does not mask the
 *     session's own human text, and is masked for every other session and
 *     in the session's harness text;
 *   - the prompt filter's own mask of the same sentence, minted by another
 *     session first, does not mask it in the writer session either;
 *   - NOT exempt: a file written with `Edit` (bytes the model may not have
 *     read), a file whose human label is above the session's watermark, a
 *     file whose bytes changed since the session wrote them, a Write only
 *     CLAIMED on the data socket (the agent's programs reach it), and a
 *     session that is not HIGH.
 *
 * Axes: secrets (stated; the server's confidentiality option pinned ON).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const SENTENCE = "The deal closes in the third quarter.";
const MARK = "third quarter";
const ASK = `Write a file named summary.md containing the sentence: ${SENTENCE}`;

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

async function rig() {
  const dir = mkdtempSync(join(tmpdir(), "mdu-own-write-op-"));
  dirs.push(dir);
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, packDir: null,
  });
  await server.listen();
  const c = new ArbiterClient(join(dir, "admin.sock"));
  const data = new ArbiterClient(join(dir, "a.sock"));
  await Promise.all([c.connect(), data.connect()]);
  return { dir, c, data, close: async () => { c.close(); data.close(); await server.close(); } };
}

/** Take `session` HIGH at any-model: a labelled file read into context (rung 3). */
async function raiseToHigh(c: ArbiterClient, dir: string, session: string): Promise<void> {
  const path = join(dir, `brief-${session}.md`);
  await c.setPathLabel({ path, confidentiality: "any-model", bindings: [], recursive: false });
  const sym = await c.symbolize({ tool: "Read", value: `brief for ${session}: the buyer pays 4.2M`, origin: path, sessionKey: session, integrity: "trusted" });
  const read = await c.declassifySymbol({ symbol: sym, sessionKey: session });
  assert.equal(read.allowed, true, read.reason);
  assert.equal((await c.sessionState(session)).confidentiality, "any-model");
}

let calls = 0;
/** `session`'s model writes `text` to `name` with `tool`, as the model proxy
 *  reports it (the label at the tool_use, the call's record), then the
 *  agent writes the bytes and its next open registers the file. */
async function write(
  c: ArbiterClient, dir: string, session: string, name: string, tool: string,
  text = `${SENTENCE}\n`, opts: { recorder?: ArbiterClient; onDisk?: string } = {},
): Promise<string> {
  const path = join(dir, name);
  await c.labelWrittenPath({ sessionKey: session, path, tool });
  const input = tool === "Edit" ? { file_path: path, old_string: "x", new_string: text } : { file_path: path, content: text };
  await (opts.recorder ?? c).recordToolCall({ toolUseId: `tu_${++calls}`, name: tool, input, sessionKey: session });
  writeFileSync(path, opts.onDisk ?? text);
  const reg = await c.registerSecret({ path, sessionKey: session });
  assert.ok(reg.symbol, reg.reason);
  return path;
}

async function filter(c: ArbiterClient, session: string, text: string, origin: "human" | "harness" = "human") {
  const out = await c.filterPrompt({ session, agent: "claude-code", segments: [{ id: "h", origin, text }] });
  return out.segments[0]!;
}

test("the writer session's own Write: its human text goes as typed; other sessions and its harness text are masked", async () => {
  const r = await rig();
  try {
    await raiseToHigh(r.c, r.dir, "A");
    await write(r.c, r.dir, "A", "summary.md", "Write");
    const a = await filter(r.c, "A", ASK);
    assert.equal(a.action, "pass", JSON.stringify(a));
    assert.deepEqual(a.findings.map((f) => [f.category, f.action]), [["secret.registered", "log"]]);
    const b = await filter(r.c, "B", ASK);
    assert.equal(b.action, "rewrite");
    assert.ok(!b.text!.includes(MARK), "another session's human text is masked");
    const harness = await filter(r.c, "A", `<system-reminder>${SENTENCE}</system-reminder>`, "harness");
    assert.ok(!harness.text!.includes(MARK), "the writer's harness text keeps the floor");
    // A HIGH session that did not write it: still masked.
    await raiseToHigh(r.c, r.dir, "C");
    assert.equal((await filter(r.c, "C", ASK)).action, "rewrite");
  } finally {
    await r.close();
  }
});

test("the prompt filter's own mask of the sentence, minted by another session first, does not mask it for the writer", async () => {
  const r = await rig();
  try {
    await raiseToHigh(r.c, r.dir, "A");
    await write(r.c, r.dir, "A", "summary.md", "Write");
    // B types the sentence with another lead: a prompt_filter row is minted for the line.
    const b = await filter(r.c, "B", `Remember: ${SENTENCE}`);
    assert.match(b.text ?? "", /\$MDU:anymodel_prompt_filter\[/);
    const a = await filter(r.c, "A", ASK);
    assert.equal(a.action, "pass", JSON.stringify(a));
    assert.ok(a.findings.every((f) => f.action === "log"));
  } finally {
    await r.close();
  }
});

test("not exempt: an Edit, a label above the watermark, bytes changed since, a claimed Write, a session that is not HIGH", async () => {
  const r = await rig();
  try {
    await raiseToHigh(r.c, r.dir, "A");
    // Edit: the file may hold bytes the model never read raw.
    const EDITED = "An edited line that is long enough to register.";
    await write(r.c, r.dir, "A", "edited.md", "Edit", `${EDITED}\n`);
    assert.equal((await filter(r.c, "A", `Please keep: ${EDITED}`)).action, "rewrite");
    // A human label above the watermark (no-model) on the written file.
    const STRICT = "A strictly labelled sentence the session wrote.";
    await r.c.setPathLabel({ path: join(r.dir, "strict.md"), confidentiality: "no-model", bindings: [], recursive: false });
    await write(r.c, r.dir, "A", "strict.md", "Write", `${STRICT}\n`);
    assert.equal((await filter(r.c, "A", `Note: ${STRICT}`)).action, "rewrite");
    // The bytes on disk are not what the model wrote (a program or the human changed them).
    const CHANGED = "A line someone else put into the session's file.";
    await write(r.c, r.dir, "A", "changed.md", "Write", `${SENTENCE}\n`, { onDisk: `${CHANGED}\n` });
    assert.equal((await filter(r.c, "A", `Note: ${CHANGED}`)).action, "rewrite");
    // A Write only claimed on the data socket is not evidence.
    const CLAIMED = "A sentence a program claims the model wrote.";
    await write(r.c, r.dir, "A", "claimed.md", "Write", `${CLAIMED}\n`, { recorder: r.data });
    assert.equal((await filter(r.c, "A", `Note: ${CLAIMED}`)).action, "rewrite");
    // A session that is not HIGH writes a file into a labelled folder: its own
    // write, but no watermark holds the level.
    const LOW = "A public session's sentence in a labelled folder.";
    mkdirSync(join(r.dir, "vault"));
    await r.c.setPathLabel({ path: join(r.dir, "vault"), confidentiality: "any-model", bindings: [], recursive: true });
    await r.c.recordToolCall({ toolUseId: "tu_low", name: "Write", input: { file_path: join(r.dir, "vault", "low.md"), content: `${LOW}\n` }, sessionKey: "P" });
    writeFileSync(join(r.dir, "vault", "low.md"), `${LOW}\n`);
    assert.ok((await r.c.registerSecret({ path: join(r.dir, "vault", "low.md"), sessionKey: "P" })).symbol);
    assert.equal((await filter(r.c, "P", `Note: ${LOW}`)).action, "rewrite");
  } finally {
    await r.close();
  }
});
