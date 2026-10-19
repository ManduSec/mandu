/**
 * why-cli e2e — `mandu why` (launcher/src/why.ts) over its PRODUCTION call
 * path (the launcher's ndjsonCall, the op names it sends) against a REAL
 * ArbiterServer holding a law: a reader-listed, bound `.env` and a connect
 * allowance. Only the arbiter lookup is injected (the resident-or-throwaway
 * choice is doctor --secrets', covered there). comparisons.md §3.2.
 *
 * The second test is tour 1: a remembered Always allow for a file at a host
 * makes `--to` say released by that answer, as the live gate does, and only
 * for that file and host (policy-surface.md §4 "Test a flow").
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { loadPolicyFileStrict } from "../../arbiter/policy/policy-file-validate.js";
import { runWhy, realWhyDeps } from "../../launcher/src/why.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../../arbiter/test/axes.js";

stateAxes("secrets"); // confidentiality ON

/** stdout through runWhy's `out` sink: patching process.stdout.write across
 *  the arbiter round trips would swallow the test runner's report. */
async function capture(fn: (out: (s: string) => void) => Promise<number>): Promise<{ code: number; out: string }> {
  const chunks: string[] = [];
  const code = await fn((s) => { chunks.push(s); });
  return { code, out: chunks.join("") };
}

test("mandu why <path> / <path> --to <host> / <host> answer from the real arbiter", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-why-cli-"));
  const home = join(dir, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  const env = join(proj, ".env");
  writeFileSync(env, "STRIPE_KEY=sk_live_WHYCLI\n");
  const file = join(dir, "policy.yaml");
  writeFileSync(file, `version: 1
paths:
  - path: ${env}
    level: no-model
    bindings: [api.stripe.com]
    readers: [deploy-tool]
destinations:
  - host: db.internal
    port: 5432
    connect: allow
`);
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, policyDocument: loadPolicyFileStrict(file).config,
  });
  await server.listen();
  const deps = { ...realWhyDeps(), arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }), cwd: () => proj };
  const layout = {} as Layout;
  const envVars = { HOME: home };
  try {
    const p = await capture((out) => runWhy([".env"], envVars, layout, { ...deps, out }));
    assert.equal(p.code, 0, p.out);
    assert.match(p.out, /~\/proj\/\.env/);
    assert.match(p.out, /your label/);
    assert.match(p.out, /readers +deploy-tool/);
    assert.match(p.out, /may go to +api\.stripe\.com/);
    assert.doesNotMatch(p.out, /sk_live_WHYCLI/, "never a value");

    const bound = await capture((out) => runWhy([".env", "--to", "api.stripe.com"], envVars, layout, { ...deps, out }));
    assert.match(bound.out, /send to api\.stripe\.com: released/);
    const unbound = await capture((out) => runWhy([".env", "--to", "pastebin.com"], envVars, layout, { ...deps, out }));
    assert.match(unbound.out, /send to pastebin\.com: (held for your OK|blocked)/);

    const h = await capture((out) => runWhy(["api.stripe.com"], envVars, layout, { ...deps, out }));
    assert.equal(h.code, 0, h.out);
    assert.match(h.out, /bound +~\/proj\/\.env/);
    assert.match(h.out, /yes on :443/);

    const db = await capture((out) => runWhy(["db.internal", "--json"], envVars, layout, { ...deps, out }));
    const j = JSON.parse(db.out) as { destinations: Array<{ host: string; connect: string }>; bound: unknown[] };
    assert.deepEqual(j.destinations.map((d) => [d.host, d.connect]), [["db.internal", "allow"]]);
    assert.deepEqual(j.bound, []);
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mandu why <file> --to <host> follows a remembered Always allow, and only that (tour 1)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-why-ans-"));
  const home = join(dir, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const env = join(proj, ".env");
  const other = join(proj, "other.env");
  writeFileSync(env, "STRIPE_KEY=sk_live_WHYANS_aaaaaaaa\n");
  writeFileSync(other, "STRIPE_KEY=sk_live_WHYANS_bbbbbbbb\n");
  const file = join(dir, "policy.yaml");
  writeFileSync(file, `version: 1
paths:
  - path: ${env}
    level: no-model
  - path: ${other}
    level: no-model
`);
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, policyDocument: loadPolicyFileStrict(file).config,
  });
  await server.listen();
  const human = new ArbiterClient(join(dir, "human", "h.sock")); await human.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  const deps = { ...realWhyDeps(), arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }), cwd: () => proj };
  const layout = {} as Layout;
  const envVars = { HOME: home };
  const why = (args: string[]) => capture((out) => runWhy(args, envVars, layout, { ...deps, out }));
  try {
    // A launch registers both files; the twin carries one placeholder each.
    const data = new ArbiterClient(sock); await data.connect();
    const twin = (await data.registerSecret({ path: env })).twin ?? "";
    await data.registerSecret({ path: other });
    data.close();
    const field = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\]\.STRIPE_KEY/.exec(twin)?.[0];
    assert.ok(field, "the .env twin carries its field placeholder");

    const before = await why([".env", "--to", "collector.example"]);
    assert.match(before.out, /send to collector\.example: held for your OK/);

    // The real send asks the gate (as the net-proxy does, on the human
    // socket); the human answers Always allow on the dashboard's channel.
    const ask = await human.desymbolizationDecision({ symbol: field, boundary: "network", destination: "collector.example", sessionKey: "s-why-ans" });
    assert.equal(ask.allow, false);
    const id = (ask as { approvalId?: string }).approvalId!;
    await admin.resolveEgressApproval(id, true, "always");
    assert.equal((await human.desymbolizationDecision({ symbol: field, boundary: "network", destination: "collector.example" })).allow, true, "real sends go out");
    const rows = await admin.egressApprovals();

    const after = await why([".env", "--to", "Collector.Example:443"]);
    assert.equal(after.code, 0, after.out);
    assert.match(after.out, new RegExp(`send to collector\\.example: released by your remembered answer \\(verdict:${id}\\)`));
    assert.doesNotMatch(after.out, /sk_live_WHYANS/, "never a value");
    const j = JSON.parse((await why([".env", "--to", "collector.example", "--json"])).out) as { send: { egress: { stage: string } } };
    assert.equal(j.send.egress.stage, "verdict");

    // Only that file, only that host.
    assert.match((await why(["other.env", "--to", "collector.example"])).out, /send to collector\.example: held for your OK/);
    assert.match((await why([".env", "--to", "pastebin.example"])).out, /send to pastebin\.example: held for your OK/);
    assert.deepEqual(await admin.egressApprovals(), rows, "mandu why created, spent and changed no answer");

    // Removed on the Rules page: why says held again.
    await admin.forgetEgressApproval(id);
    assert.match((await why([".env", "--to", "collector.example"])).out, /send to collector\.example: held for your OK/);
  } finally {
    human.close(); admin.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mandu why on an AI agent's files, over the production call path (secret-discovery.md §1.10): a store is raw everywhere, a login raw only where its agent runs, a moved login named as one", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-why-agent-"));
  const home = join(dir, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  const put = (p: string, body: string): string => { mkdirSync(join(p, ".."), { recursive: true }); writeFileSync(p, body); return p; };
  const codexAuth = put(join(home, ".codex", "auth.json"), '{"OPENAI_API_KEY":"sk-proj-WHYAGENTFILE0123456789"}');
  const transcript = put(join(home, ".claude", "projects", "p", "s.jsonl"), '{"tool_result":"x"}\n');
  const movedDir = join(dir, "codex-elsewhere");
  const moved = put(join(movedDir, "auth.json"), '{"OPENAI_API_KEY":"sk-proj-WHYMOVED0123456789"}');
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const deps = { ...realWhyDeps(), arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }), cwd: () => proj };
  const layout = {} as Layout;
  const why = (args: string[], env: Record<string, string>) => capture((out) => runWhy(args, env, layout, { ...deps, out }));
  try {
    // An agent's own data: raw in every session; no placeholder copy, no readers.
    const s = await why([transcript], { HOME: home });
    assert.equal(s.code, 0, s.out);
    assert.match(s.out, /left raw +Claude Code's own data \(its sessions, settings, tool outputs\): left raw in every session/);
    assert.ok(!/placeholder copy|readers +|gets the placeholder/.test(s.out), `no promise of a placeholder copy for a file left raw:\n${s.out}`);

    // Codex's login at its default place: raw only where Codex runs, the opt-out named.
    const c = await why([codexAuth], { HOME: home });
    assert.match(c.out, /login +Codex's login\. Left raw in a session that runs Codex \(mandu codex and mandu openclaw\)/);
    assert.match(c.out, /MANDU_OTHER_AGENT_LOGINS=raw leaves/);
    assert.match(c.out, /the AI +sees a placeholder copy that keeps the file's structure/, "elsewhere, a placeholder copy");
    assert.doesNotMatch(c.out, /sk-proj-WHYAGENTFILE/, "never a value");

    // A login CODEX_HOME moved: the launcher sends the variable, the arbiter
    // names the file Codex's login, a secret where no catalog rule names it.
    const before = await why([moved], { HOME: home });
    assert.match(before.out, /Not secret \(public\): the AI reads it as is/, "without the variable it is no login");
    const m = await why([moved], { HOME: home, CODEX_HOME: movedDir });
    assert.equal(m.code, 0, m.out);
    assert.match(m.out, /level +No AI \(no-model\)/);
    assert.match(m.out, /because +Codex's login file, where your environment moved it \(agent-login:codex\)/);
    assert.match(m.out, /Codex's login\. Left raw in a session that runs Codex/);
    assert.doesNotMatch(m.out, /sk-proj-WHYMOVED/, "never a value");
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

const reEscape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

test("mandu why <file> under a launch HOME the arbiter does not share (plan 10 §11.13, 2026-10-17): judged under the running session's HOME on the human plane, the twin the guard serves; --session names another; the data plane names no session's HOME", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-why-launch-home-"));
  // Neither HOME is the arbiter's own (this process's): the catalog's `~`
  // places under the arbiter's HOME name none of these files.
  const homeA = join(dir, "home-a"); // the HOME `mandu why` runs with
  const homeB = join(dir, "home-b"); // the HOME session B was started with
  mkdirSync(homeA, { recursive: true });
  mkdirSync(join(homeB, ".ssh"), { recursive: true });
  const cfg = join(homeB, ".ssh", "config");
  writeFileSync(cfg, "Host build\n  HostName 10.1.2.3\n  User deployer\n  Port 2222\n");
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: humanSock, dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const launcher = new ArbiterClient(humanSock); await launcher.connect(); // the launcher: the human plane
  // The production lookup: the resident arbiter's data socket, and the human
  // socket its `hello` reports (realWhyDeps' humanSock).
  const deps = { ...realWhyDeps(), arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }), cwd: () => homeA };
  const layout = {} as Layout;
  const why = (args: string[], d: Partial<typeof deps> = {}) => capture((out) => runWhy(args, { HOME: homeA }, layout, { ...deps, ...d, out }));
  const launch = (sessionId: string, home: string) =>
    launcher.beginLaunch({ pid: process.pid, mode: "secrets", posture: "confined", writeProtect: true, humanPlaneWalled: true, sessionId, home });
  try {
    // The launcher registers the config under its HOME: the twin is its text.
    const reg = await launcher.registerSecret({ path: cfg, home: homeB });
    assert.ok(reg.symbol, reg.reason);
    // No session running: judged by your HOME and the arbiter's, as the
    // guard judges an open outside a session.
    const none = await why([cfg]);
    assert.equal(none.code, 0, none.out);
    assert.match(none.out, /Not secret \(public\)/);
    assert.doesNotMatch(none.out, /also judged under/);

    const b = await launch("sess-b", homeB);
    // Before the fix: "Not secret (public)" here (your HOME's catalog names
    // no such file), while session B's programs got the file's twin.
    const inB = await why([cfg]);
    assert.equal(inB.code, 0, inB.out);
    assert.match(inB.out, /level +No AI \(no-model\)/, inB.out);
    assert.match(inB.out, /because +the built-in catalog \(prefix:~\/\.ssh/);
    assert.match(inB.out, new RegExp(`home +also judged under ${reEscape(homeB)}, the HOME session sess-b was started with \\(the newest running session; for another, ask again with --session <id>\\)`));
    // The twin the guard serves under B's HOME: the file's own text.
    assert.match(inB.out, /the AI +sees the file as it is \(ssh-config\): it holds no secret value Mandu recognizes/);
    const j = await why([cfg, "--json"]);
    const a = JSON.parse(j.out) as { level: string; twin?: { form: string }; launch?: { session: string; home: string | null; newest: boolean } };
    assert.equal(a.level, "no-model");
    assert.equal(a.twin?.form, "own-text");
    assert.deepEqual(a.launch, { session: "sess-b", home: homeB, newest: true });

    // A newer launch under your own HOME: the newest one's HOME is yours,
    // so nothing is added; --session sess-b names B's.
    const aLaunch = await launch("sess-a", homeA);
    const newest = await why([cfg]);
    assert.match(newest.out, /Not secret \(public\)/, "the newest running session's HOME names no such file");
    const named = await why([cfg, "--session", "sess-b"]);
    assert.match(named.out, /level +No AI \(no-model\)/, named.out);
    assert.match(named.out, /also judged under .*, the HOME session sess-b was started with\n/, "no `newest` words for a named session");
    const gone = await why([cfg, "--session", "gone"]);
    assert.match(gone.out, /session gone is not running on this Mandu service, so only your HOME \(.*\) was used/);

    // Inside the agent's world (no human socket reachable): the data plane
    // names no session's HOME, whatever --session says.
    const errs: string[] = [];
    const ew = process.stderr.write.bind(process.stderr);
    (process.stderr as unknown as { write: (s: string) => boolean }).write = (s) => { errs.push(s); return true; };
    let walled: { code: number; out: string };
    try {
      walled = await why([cfg, "--session", "sess-b"], { humanSock: async () => null });
    } finally {
      (process.stderr as unknown as { write: typeof ew }).write = ew;
    }
    assert.equal(walled.code, 0, walled.out);
    assert.match(walled.out, /Not secret \(public\)/);
    assert.match(errs.join(""), /--session for a file is answered only outside the agent/);

    // B's launch ends: its HOME with it.
    await launcher.endLaunch(b.token);
    assert.match((await why([cfg, "--session", "sess-b"])).out, /session sess-b is not running/);
    await launcher.endLaunch(aLaunch.token);
  } finally {
    launcher.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
