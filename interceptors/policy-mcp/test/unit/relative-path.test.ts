/**
 * relative-path — the policy MCP reads the paths of a proposed edit the way
 * the user means them (2026-10-04, policy-surface.md §8.5.1).
 *
 * Pins (tools.ts `resolveEditPaths`, `runPropose`; server-main.ts `envDeps`):
 *   - a relative `lock-path` / `unlock-path` path is read in the project
 *     directory; the arbiter gets the absolute path and the envelope states
 *     it back under `resolved` (and passes the gate's grammar);
 *   - one that climbs out of the project is refused, nothing sent;
 *   - with no project directory, a relative path is refused with a problem
 *     saying how to write it, nothing sent;
 *   - a lock on a path that does not exist is refused, nothing sent: `/.env`
 *     (an absolute path at the root, seen live) names the project's `.env`
 *     ("did you mean"); otherwise the problem says to write an existing
 *     file or a `**`-pattern; a pattern and an unlock are not checked;
 *   - absolute, `~/` and `**` paths that exist go as written, no `resolved`.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { handleRpc, type JsonRpcResponse, type ServerDeps } from "../../src/mcp-server.js";
import { FIXED_MESSAGES, satisfiesGrammar } from "../../src/envelope.js";
import { resolveEditPaths } from "../../src/tools.js";
import { envDeps } from "../../src/server-main.js";
import { MockPolicyArbiter } from "../helpers/mock-arbiter.js";

const PROJECT = "/home/me/proj";
const FILES = new Set([PROJECT, `${PROJECT}/.env`, `${PROJECT}/config`, `${PROJECT}/config/keys`, "/home/me/.aws/credentials", "/srv/app/.env"]);
const exists = (p: string): boolean => FILES.has(p);

async function propose(edits: unknown[], extra: Partial<ServerDeps> = {}): Promise<{ envelope: Record<string, unknown>; text: string; arbiter: MockPolicyArbiter }> {
  const arbiter = new MockPolicyArbiter();
  const deps: ServerDeps = { arbiter, sessionKey: "sess-1", projectDir: PROJECT, exists, home: "/home/me", ...extra };
  const r = (await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "mandu_policy_propose", arguments: { edits, reason: "r" } } }, deps)) as JsonRpcResponse;
  const text = (r.result as { content: Array<{ text: string }> }).content[0]!.text;
  assert.ok(satisfiesGrammar(text, "mandu_policy_propose"), text);
  return { envelope: JSON.parse(text) as Record<string, unknown>, text, arbiter };
}

test("a relative path is read in the project directory: the arbiter gets the absolute path, and the result states it", async () => {
  const { envelope, arbiter } = await propose([
    { op: "lock-path", path: ".env", level: "no-model" },
    { op: "lock-path", path: "./config/keys", level: "no-model" },
    { op: "unlock-path", path: "old/token" },
  ]);
  assert.deepEqual(arbiter.calls[0]!.args, {
    edits: [
      { op: "lock-path", path: `${PROJECT}/.env`, level: "no-model" },
      { op: "lock-path", path: `${PROJECT}/config/keys`, level: "no-model" },
      { op: "unlock-path", path: `${PROJECT}/old/token` },
    ],
    reason: "r", sessionKey: "sess-1",
  });
  assert.equal(envelope.message, FIXED_MESSAGES.applied);
  assert.deepEqual(envelope.resolved, [
    { from: ".env", path: `${PROJECT}/.env` },
    { from: "./config/keys", path: `${PROJECT}/config/keys` },
    { from: "old/token", path: `${PROJECT}/old/token` },
  ]);
});

test("a relative pattern is anchored at the project directory and not checked for existence", async () => {
  const { arbiter, envelope } = await propose([{ op: "lock-path", path: "config/*.pem", level: "no-model" }]);
  assert.deepEqual((arbiter.calls[0]!.args as { edits: unknown[] }).edits, [{ op: "lock-path", path: `${PROJECT}/config/*.pem`, level: "no-model" }]);
  assert.deepEqual(envelope.resolved, [{ from: "config/*.pem", path: `${PROJECT}/config/*.pem` }]);
});

test("a relative path that leaves the project directory is refused; nothing reaches the arbiter", async () => {
  for (const path of ["../other/.env", "config/../../x"]) {
    const { envelope, arbiter } = await propose([{ op: "lock-path", path, level: "no-model" }]);
    assert.equal(arbiter.calls.length, 0, path);
    assert.equal(envelope.applied, false);
    assert.equal(envelope.message, FIXED_MESSAGES.invalid);
    assert.match(String((envelope.problems as string[])[0]), /leaves the project directory \/home\/me\/proj; write the full path/);
  }
  // `config/../.env` stays inside: read as the project's .env
  const ok = await propose([{ op: "lock-path", path: "config/../.env", level: "no-model" }]);
  assert.deepEqual(ok.envelope.resolved, [{ from: "config/../.env", path: `${PROJECT}/.env` }]);
});

test("no project directory known: a relative path is refused with how to write it", async () => {
  const { envelope, arbiter } = await propose([{ op: "lock-path", path: ".env", level: "no-model" }], { projectDir: undefined });
  assert.equal(arbiter.calls.length, 0);
  assert.match(String((envelope.problems as string[])[0]), /relative path .* write the file's full path/);
});

test("`/.env` is not the project's .env: a lock on a path that does not exist is refused, naming the file meant", async () => {
  const { envelope, arbiter } = await propose([{ op: "lock-path", path: "/.env", level: "no-model" }]);
  assert.equal(arbiter.calls.length, 0, "nothing labelled");
  assert.equal(envelope.message, FIXED_MESSAGES.invalid);
  const p = String((envelope.problems as string[])[0]);
  assert.match(p, /\/\.env does not exist; did you mean \/home\/me\/proj\/\.env\?/);
  assert.match(p, /read from the root of the machine, not the project/);
  // no file of that name in the project either: say how to write it
  const none = await propose([{ op: "lock-path", path: "/home/me/proj/secrets.yml", level: "no-model" }]);
  assert.equal(none.arbiter.calls.length, 0);
  assert.match(String((none.envelope.problems as string[])[0]), /does not exist \(the project directory is \/home\/me\/proj\); write the full path of an existing file, or a pattern such as \*\*\/secrets\.yml/);
  // a relative path that names nothing
  const rel = await propose([{ op: "lock-path", path: "nope/.env", level: "no-model" }]);
  assert.match(String((rel.envelope.problems as string[])[0]), /\/home\/me\/proj\/nope\/\.env does not exist/);
  // one bad edit refuses the call whole
  const mixed = await propose([{ op: "lock-path", path: ".env", level: "no-model" }, { op: "lock-path", path: "/.env", level: "no-model" }]);
  assert.equal(mixed.arbiter.calls.length, 0);
  assert.equal((mixed.envelope.problems as string[]).length, 1);
  assert.match(String((mixed.envelope.problems as string[])[0]), /^edits\[1\]\.path/);
});

test("what goes as written: existing absolute and ~/ paths, patterns, an unlock of a path that is gone, other ops", async () => {
  const edits = [
    { op: "lock-path", path: "/srv/app/.env", level: "no-model" },
    { op: "lock-path", path: "~/.aws/credentials", level: "no-model" },
    { op: "lock-path", path: "**/*.pem", level: "no-model" },
    { op: "lock-path", path: "/home/me/proj/**/id_*", level: "no-model" },
    { op: "unlock-path", path: "/gone/token" },
    { op: "trust-origin", kind: "dir", pattern: "vendor" },
  ];
  const { envelope, arbiter } = await propose(edits);
  assert.deepEqual((arbiter.calls[0]!.args as { edits: unknown[] }).edits, edits);
  assert.equal("resolved" in envelope, false);
  // not an array: the arbiter's validator answers it
  assert.deepEqual(resolveEditPaths("nope", { projectDir: PROJECT, exists }), { edits: "nope", resolved: [], problems: [] });
});

test("envDeps: the session key and an absolute project directory from the launcher's environment", () => {
  assert.deepEqual(envDeps({ MANDU_SCOPE_ID: "s", MANDU_PROJECT_DIR: "/w/p" }), { sessionKey: "s", projectDir: "/w/p" });
  assert.deepEqual(envDeps({ MANDU_PROJECT_DIR: "p" }), {}, "a relative project directory is none");
  assert.deepEqual(envDeps({}), {});
});
