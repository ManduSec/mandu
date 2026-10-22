/**
 * sign-in.test — the dashboard's human-plane socket (src/sign-in.ts;
 * policy-surface.md §2.6 "Signing in", dashboard.md §6.z).
 *
 * Pins:
 *   - `signInLink` never mints a link now: it answers how the dashboard
 *     signs a person in (the account, no account yet, an account that
 *     cannot be used, an in-memory username and password); an unknown op
 *     is refused;
 *   - the socket: one NDJSON answer per connection over a real Unix socket,
 *     created 0600 in a 0700 directory; a directory with group/other bits or
 *     a symlinked one refuses to serve; dead dashboards' sockets are swept,
 *     the arbiter's are not;
 *   - `sessionKept` (dashboard.md §4.25ah): a session id or a refusal; no
 *     source, an unknown session: `found: false`; a failure to read:
 *     `unknown`; the answer's line and facts over the same socket.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";

import {
  answerSignIn,
  serveSignInChannel,
  signInDepsFor,
  signInSockPath,
  sweepDeadSignInSocks,
  SIGN_IN_OP,
  SESSION_KEPT_OP,
  answerSessionKept,
  type SignInDeps,
  type SignInMode,
} from "../../src/sign-in.js";
import type { SessionKept } from "../../src/view-model/session-kept.js";

function deps(over: Partial<SignInDeps> = {}): SignInDeps {
  return { mode: () => "account", ...over };
}

test("signInLink answers how the dashboard signs a person in; never a link", async () => {
  const cases: Array<[SignInMode, string, RegExp]> = [
    ["account", "account", /your Mandu dashboard account/],
    ["no-account", "no-account", /no account yet; run `mandu dashboard --set-password`/],
    ["none", "no-account", /no account yet/],
    ["account-unusable", "account-unusable", /cannot be used; run `mandu dashboard --set-password`/],
    ["basic-auth", "basic-auth", /username and password/],
  ];
  for (const [mode, reason, words] of cases) {
    const a = await answerSignIn({ op: SIGN_IN_OP }, deps({ mode: () => mode }));
    assert.equal(a.ok, false, mode);
    assert.equal(a.reason, reason, mode);
    assert.match(a.error, words, mode);
    assert.ok(!("path" in a), `${mode}: no link`);
  }
  const bad = await answerSignIn({ op: "mint" }, deps());
  assert.equal(bad.reason, "bad-request");
  assert.equal((await answerSignIn(null, deps())).reason, "bad-request");
});

test("signInDepsFor: the server's mode, read at each ask, and its sessionKept", async () => {
  let mode: SignInMode = "no-account";
  const d = signInDepsFor({ signInMode: () => mode });
  assert.equal((await answerSignIn({ op: SIGN_IN_OP }, d)).reason, "no-account");
  mode = "account"; // `mandu dashboard --set-password` while it runs
  assert.equal((await answerSignIn({ op: SIGN_IN_OP }, d)).reason, "account");
  assert.equal(d.sessionKept, undefined);
});

function ask(path: string, line: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const c = connect(path);
    let buf = "";
    c.setEncoding("utf8");
    c.on("error", reject);
    c.on("connect", () => c.write(line));
    c.on("data", (d: string) => { buf += d; });
    c.on("close", () => resolve(buf));
  });
}

test("the socket: one answer per connection, 0600 in a 0700 directory, removed on close", async () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-signin-"));
  try {
    const path = signInSockPath(base, 777);
    assert.equal(path, join(base, "human", "dashboard-777.sock"));
    const ch = await serveSignInChannel(path, deps());
    assert.equal(statSync(join(base, "human")).mode & 0o777, 0o700);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    const a1 = JSON.parse(await ask(path, JSON.stringify({ op: SIGN_IN_OP }) + "\n"));
    assert.deepEqual([a1.ok, a1.reason], [false, "account"]);
    const bad = JSON.parse(await ask(path, "not json\n"));
    assert.equal(bad.ok, false);
    await ch.close();
    assert.equal(existsSync(path), false);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

const KEPT: SessionKept = {
  mode: "secrets", flagged: false, masked: { count: 1, names: ["DB_PASSWORD in ~/proj/.env"] }, early: { count: 0, names: [] },
  unmasked: { count: 0, names: [] }, blocked: 0, sent: { count: 0, names: [] },
};

test("answerSessionKept: a session id or a refusal; nothing known is found: false; a failed read is unknown", async () => {
  const known = deps({ sessionKept: async (id) => (id === "1791-1" ? { kept: KEPT, line: "mandu: in this session: …" } : null) });
  assert.deepEqual(await answerSessionKept({ op: SESSION_KEPT_OP, session: "1791-1" }, known), { ok: true, found: true, line: "mandu: in this session: …", kept: KEPT });
  assert.deepEqual(await answerSessionKept({ op: SESSION_KEPT_OP, session: "other" }, known), { ok: true, found: false });
  assert.deepEqual(await answerSessionKept({ op: SESSION_KEPT_OP, session: "1791-1" }, deps()), { ok: true, found: false }, "no source wired");
  for (const session of [undefined, "", 7, "a b", "../x\n", "x".repeat(201)]) {
    const a = await answerSessionKept({ op: SESSION_KEPT_OP, session }, known);
    assert.deepEqual([a.ok, !a.ok && a.reason], [false, "bad-request"], JSON.stringify(session));
  }
  const failing = await answerSessionKept({ op: SESSION_KEPT_OP, session: "1791-1" }, deps({ sessionKept: async () => { throw new Error("arbiter gone"); } }));
  assert.deepEqual([failing.ok, !failing.ok && failing.reason], [false, "unknown"]);
  const server = { signInMode: () => "account" as const, sessionKept: async () => ({ kept: KEPT, line: "L" }) };
  assert.deepEqual(await answerSessionKept({ session: "s" }, signInDepsFor(server)), { ok: true, found: true, line: "L", kept: KEPT }, "signInDepsFor wires the server's sessionKept");
});

test("the socket answers sessionKept beside signInLink", async () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-signin-kept-"));
  try {
    const path = signInSockPath(base, 778);
    const ch = await serveSignInChannel(path, deps({
      sessionKept: async (id) => (id === "s-1" ? { kept: KEPT, line: "mandu: in this session: 1 secret masked before the AI saw it (DB_PASSWORD in ~/proj/.env)" } : null),
    }));
    const a = JSON.parse(await ask(path, JSON.stringify({ op: SESSION_KEPT_OP, session: "s-1" }) + "\n"));
    assert.deepEqual([a.ok, a.found, a.kept.masked.count], [true, true, 1]);
    assert.match(a.line, /1 secret masked before the AI saw it/);
    assert.deepEqual(JSON.parse(await ask(path, JSON.stringify({ op: SESSION_KEPT_OP, session: "s-2" }) + "\n")), { ok: true, found: false });
    const how = JSON.parse(await ask(path, JSON.stringify({ op: SIGN_IN_OP }) + "\n"));
    assert.deepEqual([how.ok, how.reason], [false, "account"]);
    await ch.close();
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("the socket is not served from a directory with group/other bits, or a symlink", async () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-signin-"));
  try {
    mkdirSync(join(base, "human"), { mode: 0o700 });
    chmodSync(join(base, "human"), 0o755);
    await assert.rejects(serveSignInChannel(signInSockPath(base, 1), deps()), /not 700/);
    const other = mkdtempSync(join(tmpdir(), "mandu-signin-real-"));
    const base2 = mkdtempSync(join(tmpdir(), "mandu-signin-"));
    symlinkSync(other, join(base2, "human"));
    await assert.rejects(serveSignInChannel(signInSockPath(base2, 1), deps()), /not a real directory/);
    rmSync(other, { recursive: true, force: true });
    rmSync(base2, { recursive: true, force: true });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("sweepDeadSignInSocks removes dead dashboards' sockets only", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-signin-sweep-"));
  try {
    for (const n of ["dashboard-1.sock", "dashboard-2.sock", "20261005-1200-abc-p1.sock", "h.sock"]) writeFileSync(join(dir, n), "");
    const removed = sweepDeadSignInSocks(dir, (pid) => pid === 2);
    assert.deepEqual(removed, ["dashboard-1.sock"]);
    assert.equal(existsSync(join(dir, "dashboard-2.sock")), true);
    assert.equal(existsSync(join(dir, "20261005-1200-abc-p1.sock")), true, "the arbiter's are never touched");
    assert.deepEqual(sweepDeadSignInSocks(join(dir, "absent"), () => false), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sweepDeadSignInSocks refuses a planted directory link or a shared directory before deleting anything", () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-signin-sweep-planted-"));
  const target = join(base, "target");
  const linked = join(base, "human");
  try {
    mkdirSync(target, { mode: 0o700 });
    const victim = join(target, "dashboard-1.sock");
    writeFileSync(victim, "not a dashboard socket\n");
    symlinkSync(target, linked);
    assert.throws(() => sweepDeadSignInSocks(linked, () => false), /not a real directory/);
    assert.equal(readFileSync(victim, "utf8"), "not a dashboard socket\n", "cleanup did not follow the link");
    chmodSync(target, 0o755);
    assert.throws(() => sweepDeadSignInSocks(target, () => false), /not 700/);
    assert.equal(readFileSync(victim, "utf8"), "not a dashboard socket\n", "cleanup did not trust a shared directory");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
