/**
 * dashboard-sign-in.test — the launcher's half of the dashboard's one-time
 * sign-in links (src/dashboard-sign-in.ts; policy-surface.md §2.6
 * "Signing in").
 *
 * Pins:
 *   - a link is asked for only when a person reads the output (a terminal, or
 *     MANDU_PRINT_SIGNIN_LINK=1);
 *   - the socket must lie in this runtime's human-plane directory (a planted
 *     registry entry naming a socket elsewhere is never dialled), and an
 *     older dashboard (no socket) says how to get one;
 *   - each answer becomes the right outcome, and the terminal line carries
 *     the link while the KEPT line never does;
 *   - `mandu dashboard` prints a link on a terminal, nothing on a pipe, and
 *     the refusal (with the remedy) when its sign-in channel is out of reach,
 *     as inside an agent's sandbox;
 *   - a real round trip on a Unix socket.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  bannerDashboard,
  requestSignInLink,
  signInCall,
  terminalDashboardLines,
  wantsSignInLink,
  SIGN_IN_OP,
  type SignInOutcome,
} from "../../src/dashboard-sign-in.js";
import { dashboardLine } from "../../src/launch-banner.js";
import { hermetic } from "../lib/test-runtime.js";
import { runDashboard as runDashboardIn, type DashboardDeps, type LiveDashboard } from "../../src/subcommands.js";
import { Layout } from "../../src/services/layout.js";

/** runDashboard with this file's own runtime dir when the env names none (test-runtime.ts). */
const runDashboard = hermetic(runDashboardIn, 1);

const BASE = "/run/user/1000/mandu";
const SOCK = `${BASE}/human/dashboard-77.sock`;
const DASH = { host: "127.0.0.1", port: 4501, signInSock: SOCK };

test("wantsSignInLink: a terminal, or an explicit MANDU_PRINT_SIGNIN_LINK=1; never a log by default", () => {
  assert.equal(wantsSignInLink(true, {}), true);
  assert.equal(wantsSignInLink(false, {}), false);
  assert.equal(wantsSignInLink(undefined, {}), false);
  assert.equal(wantsSignInLink(false, { MANDU_PRINT_SIGNIN_LINK: "1" }), true);
  assert.equal(wantsSignInLink(false, { MANDU_PRINT_SIGNIN_LINK: "yes" }), false);
});

test("requestSignInLink: a socket outside the human-plane directory is never dialled", async () => {
  const dialled: string[] = [];
  const call = async (s: string): Promise<unknown> => { dialled.push(s); return { ok: true, path: "/login?ticket=x" }; };
  for (const signInSock of [
    "/tmp/evil.sock",
    `${BASE}/human`,
    `${BASE}/human/../evil.sock`,
    `${BASE}/human/sub/dashboard-1.sock`,
    `${BASE}/humanx/dashboard-1.sock`,
    "human/dashboard-1.sock",
  ]) {
    const o = await requestSignInLink({ ...DASH, signInSock }, BASE, call);
    assert.equal(o.kind, "unavailable", signInSock);
  }
  assert.deepEqual(dialled, []);
});

test("requestSignInLink: an older dashboard (no socket) says how to get one", async () => {
  const o = await requestSignInLink({ host: "127.0.0.1", port: 4501 }, BASE, async () => { throw new Error("unreachable"); });
  assert.equal(o.kind, "unavailable");
  assert.match((o as { why: string }).why, /predates sign-in links.*mandu stop/);
});

test("requestSignInLink: each answer becomes its outcome", async () => {
  const at = (answer: unknown) => requestSignInLink(DASH, BASE, async (s) => { assert.equal(s, SOCK); return answer; });
  assert.deepEqual(await at({ ok: true, path: "/login?ticket=abc", expiresAt: 1 }), { kind: "link", url: "http://127.0.0.1:4501/login?ticket=abc" });
  assert.deepEqual(
    await requestSignInLink({ ...DASH, host: "0.0.0.0" }, BASE, async () => ({ ok: true, path: "/m/login?ticket=abc" })),
    { kind: "link", url: "http://127.0.0.1:4501/m/login?ticket=abc" },
    "a wildcard bind is reached over loopback",
  );
  assert.deepEqual(await at({ ok: false, reason: "password", error: "x" }), { kind: "password" });
  assert.deepEqual(await at({ ok: false, reason: "basic-auth", error: "x" }), { kind: "password" });
  assert.deepEqual(await at({ ok: false, reason: "exposed", error: "an agent … runs" }), { kind: "refused", why: "an agent … runs" });
  assert.equal((await at({ ok: true, path: "http://elsewhere/login" })).kind, "refused", "only a path, never another origin");
  assert.equal((await at(null)).kind, "refused");
  const down = await requestSignInLink(DASH, BASE, async () => { throw Object.assign(new Error("connect EACCES"), { code: "EACCES" }); });
  assert.equal(down.kind, "unavailable");
  assert.match((down as { why: string }).why, /did not answer \(connect EACCES\)/);
});

test("terminalDashboardLines: the link rides the terminal line; the kept line never has it", () => {
  const plain = dashboardLine("http://127.0.0.1:4501/");
  const link: SignInOutcome = { kind: "link", url: "http://127.0.0.1:4501/login?ticket=abc" };
  assert.deepEqual(terminalDashboardLines(plain, link), [
    "mandu: dashboard http://127.0.0.1:4501/login?ticket=abc (approve requests, see what was protected; the link signs this browser in, once)",
  ]);
  assert.doesNotMatch(plain, /ticket/);
  assert.deepEqual(terminalDashboardLines(plain, null), [plain]);
  assert.deepEqual(terminalDashboardLines(plain, { kind: "not-asked" }), [plain]);
  assert.deepEqual(terminalDashboardLines(plain, { kind: "password" }), [
    "mandu: dashboard http://127.0.0.1:4501/ (approve requests, see what was protected; sign in with its password)",
  ]);
  const refused = terminalDashboardLines(plain, { kind: "refused", why: "an agent that can reach Mandu's own controls is running (pid 9)" });
  assert.deepEqual(refused, [plain, "mandu: ! no dashboard sign-in link: an agent that can reach Mandu's own controls is running (pid 9)"]);
  const gone = terminalDashboardLines(plain, { kind: "unavailable", why: "no answer" });
  assert.equal(gone[0], plain);
  assert.match(gone[1]!, /^mandu: ! no dashboard sign-in link: no answer; to sign in later, run `mandu dashboard` in your own terminal/);
});

test("bannerDashboard: the default banner's dashboard part carries the link in place of the URL (terminal only); a link that could not be made is a notice", () => {
  const url = "http://127.0.0.1:4501/";
  assert.deepEqual(bannerDashboard(url, { kind: "link", url: `${url}login?ticket=abc` }), {
    part: "dashboard http://127.0.0.1:4501/login?ticket=abc (the link signs this browser in, once)", notes: [],
  });
  assert.deepEqual(bannerDashboard(url, null), { part: `dashboard ${url}`, notes: [] });
  assert.deepEqual(bannerDashboard(url, { kind: "not-asked" }), { part: `dashboard ${url}`, notes: [] });
  assert.deepEqual(bannerDashboard(url, { kind: "password" }), { part: `dashboard ${url} (sign in with its password)`, notes: [] });
  assert.deepEqual(bannerDashboard(null, null), { part: "no dashboard (start one: `mandu dashboard`)", notes: [] });
  // The notes are what --verbose prints on a line of its own, and never carry a link.
  const plain = dashboardLine(url);
  for (const o of [{ kind: "refused", why: "pid 9" }, { kind: "unavailable", why: "no answer" }] as SignInOutcome[]) {
    const b = bannerDashboard(url, o);
    assert.equal(b.part, `dashboard ${url}`);
    assert.deepEqual(b.notes, terminalDashboardLines(plain, o).slice(1));
    assert.ok(b.notes.every((n) => !/ticket/.test(n)));
  }
});

// ── `mandu dashboard` ────────────────────────────────────────────────────────

function harness(over: Partial<DashboardDeps> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const asked: LiveDashboard[] = [];
  const live: LiveDashboard = { id: "x", pid: 9, host: "127.0.0.1", port: 4501, basePath: "", signInSock: SOCK };
  const deps: DashboardDeps = {
    registered: () => [live],
    pidAlive: () => true,
    probePort: async (_h, p) => p === 4501,
    start: () => ({ stop: () => {} }),
    waitFor: async (pred) => Boolean(await pred()),
    readPortFile: () => 4501,
    sockExists: () => true,
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    isTTY: true,
    signIn: async (d) => { asked.push(d); return { kind: "link", url: "http://127.0.0.1:4501/login?ticket=abc" }; },
    ...over,
  };
  return { deps, out, err, asked };
}
const LAYOUT = Layout.dev("/repo");

test("mandu dashboard on a terminal: the URL, then a one-time sign-in link for that dashboard", async () => {
  const h = harness();
  assert.equal(await runDashboard([], {}, LAYOUT, h.deps), 0);
  assert.deepEqual(h.out, [
    "dashboard already up — http://127.0.0.1:4501/\n",
    "sign in (this link works once): http://127.0.0.1:4501/login?ticket=abc\n",
  ]);
  assert.equal(h.asked[0]?.signInSock, SOCK);
});

test("mandu dashboard on a pipe: the URL only, no link asked", async () => {
  const h = harness({ isTTY: false });
  assert.equal(await runDashboard([], {}, LAYOUT, h.deps), 0);
  assert.deepEqual(h.out, ["dashboard already up — http://127.0.0.1:4501/\n"]);
  assert.equal(h.asked.length, 0);
});

test("mandu dashboard where the sign-in channel is walled off (inside an agent's sandbox): no link, the remedy", async () => {
  const h = harness({ signIn: async () => ({ kind: "unavailable", why: "the dashboard's sign-in channel did not answer (connect EACCES)" }) });
  assert.equal(await runDashboard([], {}, LAYOUT, h.deps), 0);
  assert.deepEqual(h.out, ["dashboard already up — http://127.0.0.1:4501/\n"]);
  assert.match(h.err.join(""), /no sign-in link: .*EACCES.*run `mandu dashboard` in your own terminal/);
});

test("mandu dashboard while an agent with no wall runs: the dashboard's refusal, verbatim", async () => {
  const h = harness({ signIn: async () => ({ kind: "refused", why: "an agent that can reach Mandu's own controls is running (pid 9)" }) });
  assert.equal(await runDashboard([], {}, LAYOUT, h.deps), 0);
  assert.match(h.err.join(""), /^mandu: no sign-in link: an agent that can reach Mandu's own controls is running \(pid 9\)/);
});

test("mandu dashboard that STARTS one: the link is asked of the new dashboard's registry entry", async () => {
  let registered: LiveDashboard[] = [];
  const h = harness({
    registered: () => registered,
    probePort: async () => true,
    readPortFile: () => { registered = [{ id: "n", pid: 10, host: "127.0.0.1", port: 40123, signInSock: SOCK }]; return 40123; },
  });
  const rt = mkdtempSync(join(tmpdir(), "mandu-signin-rt-"));
  try {
    assert.equal(await runDashboard([], { XDG_RUNTIME_DIR: rt }, LAYOUT, h.deps), 0);
  } finally {
    rmSync(rt, { recursive: true, force: true });
  }
  assert.equal(h.out[0], "dashboard up — http://127.0.0.1:40123/\n");
  assert.equal(h.asked[0]?.port, 40123);
  assert.match(h.out[1]!, /^sign in \(this link works once\): /);
});

test("signInCall: one NDJSON round trip on a real Unix socket", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-signin-call-"));
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const sock = join(dir, "human", "dashboard-1.sock");
  const seen: string[] = [];
  const server = createServer((c) => {
    c.setEncoding("utf8");
    c.on("data", (d: string) => {
      seen.push(d);
      c.end(JSON.stringify({ ok: true, path: "/login?ticket=r", expiresAt: 1 }) + "\n");
    });
  });
  await new Promise<void>((r) => server.listen(sock, r));
  try {
    assert.deepEqual(await signInCall(sock), { ok: true, path: "/login?ticket=r", expiresAt: 1 });
    assert.deepEqual(JSON.parse(seen[0]!), { op: SIGN_IN_OP });
    const o = await requestSignInLink({ host: "127.0.0.1", port: 9, signInSock: sock }, dir);
    assert.deepEqual(o, { kind: "link", url: "http://127.0.0.1:9/login?ticket=r" });
    await assert.rejects(signInCall(join(dir, "human", "absent.sock")), /ENOENT/);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    rmSync(dir, { recursive: true, force: true });
  }
});
