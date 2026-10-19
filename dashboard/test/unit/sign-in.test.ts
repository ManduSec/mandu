/**
 * sign-in.test — the dashboard's one-time sign-in links (src/sign-in.ts;
 * policy-surface.md §2.6 "Signing in").
 *
 * Pins:
 *   - a ticket signs in ONCE, only before it expires; a guess, an empty or
 *     oversized value signs nobody in; the outstanding set is capped;
 *   - the decision: an unknown op is refused; a password or Basic-auth
 *     dashboard mints nothing; no exposure answer (absent, throwing,
 *     malformed) mints nothing (fail closed); a live launch with no wall
 *     mints nothing and names it; otherwise a path under the base path;
 *   - the socket: one NDJSON answer per connection over a real Unix socket,
 *     created 0600 in a 0700 directory; a directory with group/other bits or
 *     a symlinked one refuses to serve; dead dashboards' sockets are swept,
 *     the arbiter's are not.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect, createServer } from "node:net";

import {
  SignInTickets,
  answerSignIn,
  arbiterHumanSocks,
  askHumanPlaneStatus,
  combinedHumanPlaneStatus,
  serveSignInChannel,
  signInDepsFor,
  signInSockPath,
  sweepDeadSignInSocks,
  SIGN_IN_OP,
  type SignInDeps,
} from "../../src/sign-in.js";
import type { HumanPlaneStatus } from "../../src/event-source/contract.js";

const WALLED: HumanPlaneStatus = { exposed: false, since: null, launches: [] };
const EXPOSED: HumanPlaneStatus = {
  exposed: true, since: 1, launches: [{ pid: 4242, mode: "secrets", posture: "gated", session: "abc123" }],
};

function deps(over: Partial<SignInDeps> = {}): SignInDeps {
  let n = 0;
  return {
    mode: () => "tickets",
    mintPath: () => ({ path: `/login?ticket=t${++n}`, expiresAt: 99 }),
    humanPlaneStatus: async () => WALLED,
    ...over,
  };
}

test("a ticket signs in once, and only before it expires", () => {
  let now = 1_000;
  const t = new SignInTickets({ ttlMs: 100, now: () => now });
  const a = t.mint();
  assert.equal(a.expiresAt, 1_100);
  assert.match(a.ticket, /^[0-9a-f]{32}$/, "128 random bits");
  assert.equal(t.redeem(a.ticket), true);
  assert.equal(t.redeem(a.ticket), false, "spent on first use");
  const b = t.mint();
  now = 1_200;
  assert.equal(t.redeem(b.ticket), false, "expired");
  const c = t.mint();
  assert.equal(t.redeem(c.ticket + "0"), false, "a near-guess");
  assert.equal(t.redeem(""), false);
  assert.equal(t.redeem("x".repeat(300)), false);
  assert.equal(t.redeem(c.ticket), true, "a failed guess does not spend the real one");
});

test("tickets are distinct and the outstanding set is capped (oldest dropped)", () => {
  const t = new SignInTickets({ max: 3 });
  const minted = [t.mint(), t.mint(), t.mint(), t.mint()];
  assert.equal(new Set(minted.map((m) => m.ticket)).size, 4);
  assert.equal(t.size(), 3);
  assert.equal(t.redeem(minted[0]!.ticket), false, "the oldest was dropped");
  assert.equal(t.redeem(minted[3]!.ticket), true);
});

test("answerSignIn: unknown op, password, Basic auth: no link", async () => {
  assert.equal((await answerSignIn({ op: "nope" }, deps())).ok, false);
  assert.equal((await answerSignIn(null, deps())).ok, false);
  const pw = await answerSignIn({ op: SIGN_IN_OP }, deps({ mode: () => "password" }));
  assert.deepEqual([pw.ok, !pw.ok && pw.reason], [false, "password"]);
  const ba = await answerSignIn({ op: SIGN_IN_OP }, deps({ mode: () => "basic-auth" }));
  assert.deepEqual([ba.ok, !ba.ok && ba.reason], [false, "basic-auth"]);
});

test("answerSignIn fails closed when the exposure cannot be read", async () => {
  let minted = 0;
  const count = { mintPath: () => { minted++; return { path: "/login?ticket=x", expiresAt: 1 }; } };
  for (const humanPlaneStatus of [
    undefined,
    async (): Promise<HumanPlaneStatus> => { throw new Error("no human socket"); },
    async () => ({}) as unknown as HumanPlaneStatus,
  ]) {
    const d = deps({ ...count });
    if (humanPlaneStatus) d.humanPlaneStatus = humanPlaneStatus; else delete d.humanPlaneStatus;
    const a = await answerSignIn({ op: SIGN_IN_OP }, d);
    assert.equal(a.ok, false);
    assert.equal(!a.ok && a.reason, "unknown");
    assert.match(!a.ok ? a.error : "", /no sign-in link/);
  }
  assert.equal(minted, 0, "nothing minted");
});

test("answerSignIn mints nothing while a launch with no wall is live, and names it", async () => {
  let minted = 0;
  const a = await answerSignIn({ op: SIGN_IN_OP }, deps({
    humanPlaneStatus: async () => EXPOSED,
    mintPath: () => { minted++; return { path: "/login?ticket=x", expiresAt: 1 }; },
  }));
  assert.equal(a.ok, false);
  assert.equal(!a.ok && a.reason, "exposed");
  assert.match(!a.ok ? a.error : "", /pid 4242 \(session abc123\)/);
  assert.match(!a.ok ? a.error : "", /DASHBOARD_PASSWORD/);
  assert.equal(minted, 0);
});

test("answerSignIn: walled → a login path", async () => {
  const a = await answerSignIn({ op: SIGN_IN_OP }, deps());
  assert.deepEqual(a, { ok: true, path: "/login?ticket=t1", expiresAt: 99 });
});

test("signInDepsFor: the server's mode and mint, the source's exposure read (none → no link)", async () => {
  const server = { signInMode: () => "tickets" as const, mintSignInPath: () => ({ path: "/m/login?ticket=z", expiresAt: 5 }) };
  const withStatus = signInDepsFor(server, { humanPlaneStatus: async () => WALLED });
  assert.deepEqual(await answerSignIn({ op: SIGN_IN_OP }, withStatus), { ok: true, path: "/m/login?ticket=z", expiresAt: 5 });
  const fileSource = signInDepsFor(server, {});
  assert.equal((await answerSignIn({ op: SIGN_IN_OP }, fileSource)).ok, false);
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
    const a2 = JSON.parse(await ask(path, JSON.stringify({ op: SIGN_IN_OP }) + "\n"));
    assert.deepEqual([a1.ok, a1.path, a2.path], [true, "/login?ticket=t1", "/login?ticket=t2"]);
    const bad = JSON.parse(await ask(path, "not json\n"));
    assert.equal(bad.ok, false);
    await ch.close();
    assert.equal(existsSync(path), false);
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

test("combinedHumanPlaneStatus: every arbiter in the directory is asked; exposed if any is; a dead socket is skipped; any other failure or nothing answering is unknown", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-signin-hp-"));
  try {
    for (const n of ["a.sock", "b.sock", "dashboard-12.sock", "notes.txt"]) writeFileSync(join(dir, n), "");
    const asked: string[] = [];
    const answers: Record<string, HumanPlaneStatus | Error> = {};
    const ask = async (s: string): Promise<HumanPlaneStatus> => {
      asked.push(s.slice(dir.length + 1));
      const a = answers[s.slice(dir.length + 1)];
      if (a instanceof Error) throw a;
      return a!;
    };
    answers["a.sock"] = WALLED; answers["b.sock"] = WALLED;
    assert.deepEqual(await combinedHumanPlaneStatus(null, dir, ask), WALLED);
    assert.deepEqual(asked.sort(), ["a.sock", "b.sock"], "never a dashboard's own sign-in socket");

    // One of them (the test tenant's arbiter, say) holds an unwalled launch.
    answers["b.sock"] = EXPOSED;
    const both = await combinedHumanPlaneStatus(async () => EXPOSED, dir, ask);
    assert.equal(both.exposed, true);
    assert.deepEqual(both.launches.map((l) => l.pid), [4242], "the same launch named once");

    // A dead arbiter's leftover socket is skipped; a live one that fails is unknown.
    answers["b.sock"] = Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
    assert.equal((await combinedHumanPlaneStatus(null, dir, ask)).exposed, false);
    answers["b.sock"] = new Error("unknown op 'humanPlaneStatus'");
    await assert.rejects(combinedHumanPlaneStatus(null, dir, ask), /unknown op/);
    await assert.rejects(combinedHumanPlaneStatus(async () => { throw new Error("own source down"); }, dir, async () => WALLED), /own source down/);

    // Nothing answering is unknown, not walled.
    await assert.rejects(combinedHumanPlaneStatus(null, join(dir, "empty"), ask), /no protection service answered/);
    answers["a.sock"] = Object.assign(new Error("gone"), { code: "ENOENT" });
    answers["b.sock"] = Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
    await assert.rejects(combinedHumanPlaneStatus(null, dir, ask), /no protection service answered/);
    assert.deepEqual(arbiterHumanSocks(dir).map((p) => p.slice(dir.length + 1)), ["a.sock", "b.sock"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("askHumanPlaneStatus: the arbiter's NDJSON protocol over a real socket; a file that is not a socket is ECONNREFUSED", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-signin-ask-"));
  const sock = join(dir, "x.sock");
  const seen: string[] = [];
  const srv = createServer((c) => {
    c.setEncoding("utf8");
    c.on("data", (d: string) => { seen.push(d); c.end(JSON.stringify({ id: 1, ok: true, result: EXPOSED }) + "\n"); });
  });
  await new Promise<void>((r) => srv.listen(sock, r));
  try {
    assert.deepEqual(await askHumanPlaneStatus(sock), EXPOSED);
    assert.deepEqual(JSON.parse(seen[0]!), { id: 1, op: "humanPlaneStatus" });
    writeFileSync(join(dir, "plain.sock"), "");
    await assert.rejects(askHumanPlaneStatus(join(dir, "plain.sock")), (e: NodeJS.ErrnoException) => e.code === "ECONNREFUSED");
  } finally {
    await new Promise<void>((r) => srv.close(() => r()));
    rmSync(dir, { recursive: true, force: true });
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
