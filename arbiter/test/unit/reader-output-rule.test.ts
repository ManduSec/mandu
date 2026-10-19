/**
 * reader-output-rule.test.ts — confidentiality plan 13 D3: the output
 * declassifier is keyed by the (file, program) pair, not by the program.
 *
 * Before 2026-10-02 the fold of a tool call's tree looked a reader's output
 * rule up in the law's global `apps:` table by program name alone
 * (`outputRuleFor(app, apps)`): an `apps: [{app: ssh-add, output: clear}]`
 * written for `~/.pgpass` also cleared ssh-add's output when ssh-add printed
 * another labelled document it is a reader of. Now the rule sits on the
 * reader entry of ONE file (`readers: [{app: ssh-add, output: clear}]`), a
 * process's output is released only when EVERY file in its taint clears
 * that program (the intersection, as D1 does for destinations), and the
 * legacy global `apps:` rule clears nothing (deprecated, plan 13 §8).
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { foldRules, readerOutputRule, withPinnedReader, type ReaderEntry } from "../../policy/flow-taint.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: what the model sees of a reader's output

const PSQL = "/usr/bin/ssh-add";
const H = "a".repeat(64);

// ── the pure rule ───────────────────────────────────────────────────────────

test("readerOutputRule: the rule is the file's reader entry for that binary; any other file, or none, is secret", () => {
  const pgpass: ReaderEntry[] = [{ app: "ssh-add", output: "clear" }];
  const doc: ReaderEntry[] = ["ssh-add"];
  const row = (path: string) => ({ path, app: "ssh-add", exe: PSQL, sha256: H, via: "reader" as const });
  assert.equal(readerOutputRule(row("/h/.pgpass"), pgpass).output, "clear", "the pair the human cleared");
  assert.equal(readerOutputRule(row("/h/doc.md"), doc).output, "secret", "ssh-add on another file: that file's entry says nothing, so secret");
  assert.equal(readerOutputRule(row("/h/x"), undefined).output, "secret", "no reader list at all");
  // The intersection: one process holding both files is masked.
  assert.equal(foldRules([readerOutputRule(row("/h/.pgpass"), pgpass), readerOutputRule(row("/h/doc.md"), doc)]).output, "secret");
  // Two files that both clear ssh-add: clear.
  assert.equal(foldRules([readerOutputRule(row("/h/.pgpass"), pgpass), readerOutputRule(row("/h/b"), pgpass)]).output, "clear");
});

test("readerOutputRule: the entry must name the binary that opened the file (a pin by path and hash)", () => {
  const pinned: ReaderEntry[] = [{ app: "ssh-add", path: PSQL, sha256: H, output: "clear" }];
  const at = (exe: string | undefined, sha256?: string) =>
    readerOutputRule({ path: "/h/.pgpass", app: "ssh-add", ...(exe ? { exe } : {}), ...(sha256 ? { sha256 } : {}), via: "reader" }, pinned).output;
  assert.equal(at(PSQL, H), "clear");
  assert.equal(at("/tmp/w/psql", H), "secret", "another binary named ssh-add");
  assert.equal(at(PSQL, "b".repeat(64)), "secret", "a rebuilt ssh-add");
  assert.equal(at(undefined), "secret", "a row that does not say which binary");
});

test("readerOutputRule: a row the human let in (a verdict), or one with no grant recorded, is secret whatever the entry says", () => {
  const bare: ReaderEntry[] = [{ app: "ssh-add", output: "clear" }];
  // The human approved the agent's /tmp/w/psql once; the Inbox said its output stays masked.
  assert.equal(readerOutputRule({ path: "/h/.pgpass", app: "ssh-add", exe: "/tmp/w/psql", via: "verdict" }, bare).output, "secret");
  assert.equal(readerOutputRule({ path: "/h/.pgpass", app: "ssh-add" }, bare).output, "secret");
});

test("readerOutputRule: two entries name the binary → the strictest; a shell, interpreter or launcher is never clear; mask carries its spans", () => {
  const two: ReaderEntry[] = [{ app: "ssh-add", output: "clear" }, { app: "ssh-add", path: PSQL, sha256: H }];
  assert.equal(readerOutputRule({ path: "/h/.pgpass", app: "ssh-add", exe: PSQL, sha256: H, via: "reader" }, two).output, "secret");
  for (const app of ["python3", "bash", "awk", "find", "env"]) {
    const r = readerOutputRule({ path: "/h/x", app, exe: `/usr/bin/${app}`, via: "reader" }, [{ app, output: "clear" }]);
    assert.equal(r.output, "secret", `${app} runs code: the runtime refuses its clear`);
  }
  const m = readerOutputRule({ path: "/h/.aws/credentials", app: "aws", exe: "/usr/bin/aws", via: "reader" },
    [{ app: "aws", output: "mask", mask: ["AKIA[0-9A-Z]{16}"] }]);
  assert.equal(m.output, "mask");
  assert.deepEqual(m.mask, ["AKIA[0-9A-Z]{16}"]);
});

test("withPinnedReader: a first-use pin of a system binary keeps the entry's output; a pin the agent could have written does not take it", () => {
  const readers: ReaderEntry[] = [{ app: "ssh-add", output: "clear" }, "cat"];
  const sys = withPinnedReader(readers, { app: "ssh-add", path: PSQL, sha256: H }, { system: true });
  assert.deepEqual(sys, [{ app: "ssh-add", path: PSQL, sha256: H, output: "clear" }, "cat"]);
  // A human-approved binary in a place the agent can write: the bare entry
  // (and its output) stays for the system copy, the pin is appended without it.
  const ws = withPinnedReader(readers, { app: "ssh-add", path: "/tmp/w/psql", sha256: H }, { system: false });
  assert.deepEqual(ws, [{ app: "ssh-add", output: "clear" }, "cat", { app: "ssh-add", path: "/tmp/w/psql", sha256: H }]);
  // A bare entry with no output is replaced, as before.
  assert.deepEqual(withPinnedReader(["cat"], { app: "cat", path: "/usr/bin/cat", sha256: H }, { system: false }), [{ app: "cat", path: "/usr/bin/cat", sha256: H }]);
  // Already pinned: nothing to write.
  assert.equal(withPinnedReader(sys!, { app: "ssh-add", path: PSQL, sha256: H }, { system: true }), null);
});

// ── over the real arbiter: callTaint's fold ─────────────────────────────────

async function withArbiter(
  policy: (pgpass: string, doc: string) => Record<string, unknown>,
  fn: (c: ArbiterClient, pgpass: string, doc: string) => Promise<void>,
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d3-"));
  const pgpass = join(dir, ".pgpass");
  const doc = join(dir, "board-minutes.md");
  writeFileSync(pgpass, "db.internal:5432:prod:app:d3pgpasscanary000000001\n");
  writeFileSync(doc, "# Board minutes\nacquisition target: d3doccanary0000000000001\n");
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: policy(pgpass, doc) as never,
  });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxy's channel (plan 13 D9)
  await c.connect();
  try {
    await fn(c, pgpass, doc);
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The guard's open of `path` by the system ssh-add in process `proc`, under call `callId`. */
async function psqlOpens(c: ArbiterClient, path: string, proc: string, callId: string, exe = PSQL): Promise<string> {
  // the proxy's gate of the call, which records its command (plan 13 D9
  // follow-up: the call is bound by it, not by the text echoed back)
  await c.execGate({ command: commandOf(callId), sessionKey: "d3", callId });
  const d = await c.decideSecretOpen({ path, exe, sha256: H, isAgent: false, procKey: proc, parentKey: `${callId}-sh`, exeSystem: exe.startsWith("/usr/"), openerEnv: [], session: "d3" });
  // the call's shell, as the guard reports it: the agent's own child, the
  // call-root recorder's candidate (plan 13 D7)
  await c.recordExecRoot({ procKey: `${callId}-sh`, ancestors: ["d3-agent"], argv: ["/bin/bash", "-c", commandOf(callId)], session: "d3", callRoot: true });
  return d.verdict;
}

const commandOf = (callId: string): string => `psql -c 'select ${callId.replace(/\W/g, "_")}'`;

/** The proxy's question for the call's result: by callId and command text. */
function fold(c: ArbiterClient, callId: string): ReturnType<ArbiterClient["callTaint"]> {
  return c.callTaint(callId, { command: commandOf(callId), session: "d3" });
}

test("callTaint: ssh-add cleared for ~/.pgpass prints its rows; ssh-add printing another labelled document stays masked", async () => {
  await withArbiter((pgpass, doc) => ({
    version: 1,
    paths: [
      { path: pgpass, level: "no-model", readers: [{ app: "ssh-add", output: "clear" }] },
      { path: doc, level: "no-model", readers: ["ssh-add"] },
    ],
  }), async (c, pgpass, doc) => {
    assert.equal(await psqlOpens(c, pgpass, "p1", "call-1"), "raw");
    const t1 = await fold(c, "call-1");
    assert.equal(t1.level, "no-model");
    assert.equal(t1.rule, "clear", "the pair the human cleared: ssh-add's rows reach the model");

    assert.equal(await psqlOpens(c, doc, "p2", "call-2"), "raw");
    const t2 = await fold(c, "call-2");
    assert.equal(t2.rule, "secret", "ssh-add printing the board minutes: no entry clears that pair");
  });
});

test("callTaint: one process holding two files, one cleared and one not, stays masked (the intersection)", async () => {
  await withArbiter((pgpass, doc) => ({
    version: 1,
    paths: [
      { path: pgpass, level: "no-model", readers: [{ app: "ssh-add", output: "clear" }] },
      { path: doc, level: "no-model", readers: ["ssh-add"] },
    ],
  }), async (c, pgpass, doc) => {
    assert.equal(await psqlOpens(c, pgpass, "p1", "call-1"), "raw");
    assert.equal(await psqlOpens(c, doc, "p1", "call-1"), "raw");
    const t = await fold(c, "call-1");
    assert.deepEqual([...t.files].sort(), [doc, pgpass].sort());
    assert.equal(t.rule, "secret");
    // control: another ssh-add holding .pgpass alone is cleared, so the mask
    // above comes from the second file, not from a rule that never clears.
    assert.equal(await psqlOpens(c, pgpass, "p2", "call-2"), "raw");
    assert.equal((await fold(c, "call-2")).rule, "clear");
  });
});

test("callTaint: the legacy global apps: rule clears nothing (deprecated): ssh-add on a document it reads stays masked, and so does .pgpass", async () => {
  await withArbiter((pgpass, doc) => ({
    version: 1,
    paths: [
      { path: pgpass, level: "no-model", readers: ["ssh-add"] },
      { path: doc, level: "no-model", readers: ["ssh-add"] },
    ],
    apps: [{ app: "ssh-add", output: "clear" }],
  }), async (c, pgpass, doc) => {
    assert.equal(await psqlOpens(c, doc, "p1", "call-1"), "raw");
    assert.equal((await fold(c, "call-1")).rule, "secret", "the D3 leak: a program-wide clear written for .pgpass released the document");
    assert.equal(await psqlOpens(c, pgpass, "p2", "call-2"), "raw");
    assert.equal((await fold(c, "call-2")).rule, "secret", "mask by default until the rule moves onto the reader entry");
  });
});

test("callTaint: a cleared pair does not clear a binary of the same name the agent could have written", async () => {
  await withArbiter((pgpass) => ({
    version: 1,
    paths: [{ path: pgpass, level: "no-model", readers: [{ app: "ssh-add", output: "clear" }, { app: "ssh-add", path: "/tmp/w/ssh-add", sha256: H }] }],
  }), async (c, pgpass) => {
    // The human pinned the workspace ssh-add as a reader (its Inbox row said
    // its output stays masked); the bare entry's clear is not its.
    assert.equal(await psqlOpens(c, pgpass, "p1", "call-1", "/tmp/w/ssh-add"), "raw");
    assert.equal((await fold(c, "call-1")).rule, "secret");
  });
});
