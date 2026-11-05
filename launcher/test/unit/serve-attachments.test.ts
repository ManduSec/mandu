/**
 * serve-attachments + serve-secrets — the launcher's side of `mandu serve`'s
 * proxy pool (docs/design/agents/openclaw-plugin.md §3.2): `attach|detach`
 * over a temp Mandu home, the facts `status` and `doctor` show (proxy, port,
 * registration, posture, secret count, the "weaken + warn" lines), and the
 * secret registration the service runs for a session no launch ever covered,
 * against a mock arbiter. The pool itself: dashboard/test/unit/
 * attachment-pool.test.ts; the whole service: test/component/serve-pool.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  attachmentExposureLines,
  attachmentPosture,
  declaredFilePath,
  gatherAttachments,
  liveAttachmentSessions,
  parseAttachArgs,
  poolRecordSecrets,
  readDeclaredList,
  runServeAttach,
  runServeDetach,
  type AttachmentProxy,
} from "../../src/serve-attachments.js";
import { attachmentSecretRoots, openclawWorkspace, registerAttachmentSecrets, runRegisterSecrets } from "../../src/serve-secrets.js";
import { attachmentLine, statusProblems } from "../../src/serve-command.js";
import { serveAttachmentRows } from "../../src/doctor.js";
import { anthropicProxyPortFile, attachmentDir } from "../../src/attachment-contract.js";
import type { SecretArbiter } from "../../src/secret-setup.js";
import { tmpDir } from "../lib/tmp-dir.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

function world(): { root: string; env: Record<string, string>; run: string; home: string } {
  const root = tmpDir("mandu-serve-att-");
  const home = join(root, "home");
  const run = join(root, "run");
  mkdirSync(home, { recursive: true });
  mkdirSync(run, { mode: 0o700 });
  chmodSync(run, 0o700);
  return { root, home, run, env: { HOME: home, MANDU_HOME: join(root, "mandu"), MANDU_RUNTIME_DIR: run } };
}

const OURS = (session: string) => ({ mandu: true, service: "anthropic-proxy", sessionKey: session, arbiterSock: "/run/u/mandu/current/arbiter.sock" });

test("parseAttachArgs: openclaw only, --agent normalized, --port bounded", () => {
  assert.deepEqual(parseAttachArgs(["openclaw"]), { kind: "openclaw", agent: "main", port: null });
  assert.deepEqual(parseAttachArgs(["openclaw", "--agent", "Ops Team", "--port=41234"]), { kind: "openclaw", agent: "ops-team", port: 41234 });
  assert.match((parseAttachArgs([]) as { error: string }).error, /only openclaw/);
  assert.match((parseAttachArgs(["openclaw", "--port", "80"]) as { error: string }).error, /1024 to 65535/);
  assert.match((parseAttachArgs(["openclaw", "--agent"]) as { error: string }).error, /--agent needs/);
  assert.match((parseAttachArgs(["openclaw", "--bogus"]) as { error: string }).error, /unknown option '--bogus'/);
});

test("attach / detach: the declared file under the Mandu home, 0600; a stopped service says so (exit 3); the warn lines", async () => {
  const w = world();
  let out = "";
  const deps = {
    uid: process.getuid?.(), probe: async () => null, serviceActive: () => false,
    sleep: async () => {}, now: () => Date.now(), waitMs: 0,
    out: (s: string) => { out += s; }, err: (s: string) => { out += s; },
  };
  assert.equal(await runServeAttach(["openclaw", "--port", "41234"], w.env, deps), 3);
  assert.equal(declaredFilePath(w.env), join(w.env["MANDU_HOME"]!, "state", "serve-attachments.json"));
  const d = readDeclaredList(w.env);
  assert.deepEqual(d.attachments, [{ kind: "openclaw-plugin", agent: "main", session: "openclaw:main", port: 41234 }]);
  assert.equal(statSync(d.path).mode & 0o777, 0o600);
  assert.match(out, /attached openclaw:main \(OpenClaw agent main, port 41234\)/);
  assert.match(out, /a plugin session is running .*confined launches on this machine have lost their guard's attestation/);
  assert.match(out, /mandu openclaw gateway.*mandu serve stop/);
  assert.match(out, /the service is not running.*mandu serve start/);
  // a second attach with no port keeps it; a new agent gets a free port
  out = "";
  assert.equal(await runServeAttach(["openclaw"], w.env, deps), 3);
  assert.match(out, /already attached: openclaw:main/);
  assert.equal(await runServeAttach(["openclaw", "--agent", "ops"], w.env, deps), 3);
  const ops = readDeclaredList(w.env).attachments.find((a) => a.session === "openclaw:ops")!;
  assert.ok(ops.port !== null && ops.port >= 1024, "a free port picked at declaration");
  // detach
  out = "";
  assert.equal(runServeDetach(["openclaw", "--agent", "ops"], w.env, deps), 0);
  assert.match(out, /detached openclaw:ops: .*guard's attestation back/);
  assert.equal(runServeDetach(["openclaw", "--agent", "ops"], w.env, deps), 0);
  assert.match(out, /openclaw:ops is not attached/);
  assert.deepEqual(readDeclaredList(w.env).attachments.map((a) => a.session), ["openclaw:main"]);
});

test("attach while the service runs: waits for the pool's proxy, then names the next step", async () => {
  const w = world();
  let out = "";
  let t = 0;
  let calls = 0;
  const deps = {
    uid: process.getuid?.(),
    probe: async () => OURS("openclaw:main"),
    serviceActive: () => true,
    // The pool publishes the port file on the third look.
    sleep: async () => {
      if (++calls === 2) {
        mkdirSync(attachmentDir(w.run, "openclaw:main"), { recursive: true, mode: 0o700 });
        writeFileSync(anthropicProxyPortFile(w.run, "openclaw:main"), "41234\n", { mode: 0o600 });
      }
    },
    now: () => (t += 100), waitMs: 5_000,
    out: (s: string) => { out += s; }, err: (s: string) => { out += s; },
  };
  assert.equal(await runServeAttach(["openclaw"], w.env, deps), 0, out);
  assert.match(out, /serving at http:\/\/127\.0\.0\.1:41234; next: mandu openclaw install routes the Gateway through it/);
});

test("gatherAttachments: port file, identity, registration, posture and the secret count; an undeclared live lease too", async () => {
  const w = world();
  await runServeAttach(["openclaw", "--port", "41234"], w.env, {
    uid: undefined, probe: async () => null, serviceActive: () => false, sleep: async () => {}, now: () => 0, waitMs: 0, out: () => {}, err: () => {},
  });
  const status = { exposed: true, since: 1, launches: [
    { pid: 0, mode: "secrets", posture: "gated", session: "openclaw:main", attachment: "openclaw-plugin" },
    { pid: 0, mode: "secrets", posture: "gated", session: "openclaw:old", attachment: "openclaw-plugin" },
    { pid: 77, mode: "off", posture: "off", session: "claude-1" },
  ] };
  const deps = { uid: process.getuid?.(), probe: async (p: number) => (p === 41234 ? OURS("openclaw:main") : null), humanPlaneStatus: async () => status };
  // No port file yet: not healthy, says why.
  let list = await gatherAttachments(w.env, deps);
  assert.equal(list.length, 2);
  assert.equal(list[0]!.session, "openclaw:main");
  assert.equal(list[0]!.healthy, false);
  assert.match(list[0]!.problem!, /is absent/);
  assert.equal(list[0]!.registered, true);
  assert.equal(list[0]!.secrets, null);
  assert.deepEqual({ posture: list[0]!.posture, gap: list[0]!.gap }, { posture: "gated", gap: "openclaw-plugin" });
  assert.match(list[0]!.sentence, /The AI sees your secrets masked/);
  assert.equal(list[1]!.session, "openclaw:old");
  assert.equal(list[1]!.declared, false);
  // The pool's files: a port file, its record with the secret count.
  const dir = attachmentDir(w.run, "openclaw:main");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(anthropicProxyPortFile(w.run, "openclaw:main"), "41234\n", { mode: 0o600 });
  writeFileSync(join(dir, "pool.json"), JSON.stringify({ pid: 5, proxyPid: 6, session: "openclaw:main", startedAt: "t", secrets: { found: 3, registered: 2, at: "t" } }));
  list = await gatherAttachments(w.env, deps);
  assert.equal(list[0]!.healthy, true);
  assert.equal(list[0]!.port, 41234);
  assert.deepEqual(list[0]!.secrets, { found: 3, registered: 2, at: "t" });
  // A port file others can write is not trusted.
  chmodSync(anthropicProxyPortFile(w.run, "openclaw:main"), 0o666);
  assert.match((await gatherAttachments(w.env, deps))[0]!.problem!, /can be written by others/);
  // The arbiter not answering: registration unknown, never "registered".
  chmodSync(anthropicProxyPortFile(w.run, "openclaw:main"), 0o600);
  const silent = await gatherAttachments(w.env, { ...deps, humanPlaneStatus: async () => null });
  assert.equal(silent.length, 1);
  assert.equal(silent[0]!.registered, null);
  assert.equal(liveAttachmentSessions({ nope: 1 }), null);
  assert.equal(poolRecordSecrets("{"), null);
});

function proxy(over: Partial<AttachmentProxy> = {}): AttachmentProxy {
  return {
    session: "openclaw:main", declared: true, declaredPort: 41234, port: 41234, healthy: true, problem: null, registered: true,
    secrets: { found: 2, registered: 2, at: "t" }, route: null, ...attachmentPosture(), ...over,
  };
}

test("status: the attachment line, its problems, and the exposure warning only while one is registered", () => {
  assert.match(attachmentLine(proxy()), /^openclaw:main: proxy on 127\.0\.0\.1:41234, answering, registered, 2 secret files registered, posture gated \(gap openclaw-plugin\)$/);
  assert.match(attachmentLine(proxy({ port: 50000 })), /not on its port 41234: mandu openclaw install moves the Gateway's route/);
  assert.match(attachmentLine(proxy({ secrets: null })), /secret files not registered yet/);
  assert.match(attachmentLine(proxy({ secrets: { found: 3, registered: 1, at: "t" } })), /1 secret file registered of 3 found/);
  const st = {
    host: "ok" as const,
    unitFile: { path: "/u", state: "ours" as const, current: true, runs: null },
    unit: { load: "loaded", active: "active", sub: "running", enabled: "enabled", mainPid: 1, since: null, restarts: 0 },
    stack: { base: "/b", sock: "/b/current/arbiter.sock", arbiter: { running: true, version: "1", pid: 2, verdict: "match" as const, insideUnit: true } },
    thisMandu: { version: "1", install: "checkout" as const, root: "/r" },
    dashboard: { url: "http://x/", pid: 3, answering: true, insideUnit: true },
    sessions: [], linger: true,
  };
  assert.deepEqual(statusProblems({ ...st, attachments: [proxy()] }), []);
  const down = statusProblems({ ...st, attachments: [proxy({ healthy: false, port: null, problem: "no service proxy for openclaw:main (x is absent)" })] });
  assert.equal(down.length, 1);
  assert.match(down[0]!, /openclaw:main has no proxy serving \(no service proxy .*\): the Gateway's model calls fail/);
  assert.match(statusProblems({ ...st, attachments: [proxy({ registered: false })] })[0]!, /does not hold its attachment/);
  assert.deepEqual(statusProblems({ ...st, attachments: [proxy({ declared: false, healthy: false })] }), [], "an undeclared lease is no problem");
  assert.deepEqual(attachmentExposureLines([]), []);
  const lines = attachmentExposureLines(["openclaw:main"]);
  assert.equal(lines.length, 2);
  assert.match(lines[0]!, /plugin session is running \(Mandu's plugin in an OpenClaw Gateway, session openclaw:main\)/);
  assert.match(lines[1]!, /mandu openclaw gateway.*mandu serve stop.*mandu openclaw uninstall/);
});

test("doctor: the service's attachment rows say the proxy, the secrets, the posture, and the lost attestation", () => {
  assert.deepEqual(serveAttachmentRows(null), []);
  assert.deepEqual(serveAttachmentRows([]), []);
  const rows = serveAttachmentRows([proxy()]).join("\n");
  assert.match(rows, /✓ openclaw:main: the service's proxy answers on 127\.0\.0\.1:41234/);
  assert.match(rows, /✓ the service registered 2 secret files for it/);
  assert.match(rows, /posture gated \(gap openclaw-plugin\): The AI sees your secrets masked/);
  assert.match(rows, /✗ a plugin session is running .*lost their guard's attestation/);
  assert.match(rows, /to avoid it: run the Gateway under Mandu instead \(mandu openclaw gateway\), or .*mandu serve stop/);
  const down = serveAttachmentRows([proxy({ healthy: false, port: null, problem: "absent", registered: false, secrets: null })]).join("\n");
  assert.match(down, /✗ openclaw:main: no service proxy serves it \(absent\)/);
  assert.match(down, /fix: mandu serve start/);
  assert.match(down, /not registered with the arbiter/);
  assert.match(down, /has not registered its secret files yet/);
  assert.doesNotMatch(down, /lost their guard's attestation/, "nothing registered: no exposure claimed");
});

// ── The secret registration (serve-secrets.ts) ──────────────────────────────

test("the agent's workspace: its own, else the defaults', else OpenClaw's default; walked beside HOME only when outside it", () => {
  const ctx = { configPath: "/h/.openclaw/openclaw.json", stateDir: "/h/.openclaw" };
  assert.equal(openclawWorkspace(null, "main", ctx), "/h/.openclaw/workspace");
  assert.equal(openclawWorkspace({ agents: { defaults: { workspace: "/srv/ws" } } }, "main", ctx), "/srv/ws");
  assert.equal(openclawWorkspace({ agents: { defaults: { workspace: "/srv/ws" }, list: [{ id: "Ops", workspace: "ops-ws" }] } }, "ops", ctx), "/h/.openclaw/ops-ws");
  const w = world();
  const ws = join(w.root, "elsewhere-ws");
  mkdirSync(ws);
  mkdirSync(join(w.home, ".openclaw"), { recursive: true });
  writeFileSync(join(w.home, ".openclaw", "openclaw.json"), `{ agents: { defaults: { workspace: ${JSON.stringify(ws)} } } }`);
  assert.deepEqual(attachmentSecretRoots(w.env, "main"), { home: w.home, roots: [w.home, ws], workspace: ws });
  writeFileSync(join(w.home, ".openclaw", "openclaw.json"), "{ not json");
  assert.deepEqual(attachmentSecretRoots(w.env, "main").roots, [w.home], "an unreadable config walks HOME alone");
});

function mockArbiter(o: { discoverFails?: boolean; registerFails?: string } = {}): SecretArbiter & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async discoverSecrets(roots, home, opts) {
      calls.push(`discover ${roots.join(",")} home=${home} target=${opts?.target}`);
      if (o.discoverFails) throw new Error("walk failed");
      return { files: [{ path: "/h/.aws/credentials" }, { path: "/h/empty.env" }, { path: "/h/.codex/auth.json", agentLogin: "codex" }] };
    },
    async registerSecret(path) {
      calls.push(`register ${path}`);
      if (path === o.registerFails) throw new Error("arbiter down");
      return path === "/h/empty.env" ? { symbol: null, reason: "empty" } : { symbol: "$MDU:nomodel_X", reason: "ok" };
    },
  };
}

test("registerAttachmentSecrets: the launch's walk (target openclaw) and one registration per file; any failure is ok:false", async () => {
  const w = world();
  const a = mockArbiter();
  const r = await registerAttachmentSecrets(w.env, "main", a);
  assert.equal(r.ok, true);
  assert.equal(r.found, 3);
  assert.equal(r.registered, 2);
  assert.deepEqual(r.notRegistered, [{ path: "/h/empty.env", reason: "empty" }]);
  assert.match(a.calls[0]!, new RegExp(`^discover ${w.home} home=${w.home} target=openclaw$`));
  assert.deepEqual(a.calls.slice(1), ["register /h/.aws/credentials", "register /h/empty.env", "register /h/.codex/auth.json"]);
  // the agent's workspace rides along (the pool's MANDU_AGENT_CWD for the proxy), or null when there is none
  assert.equal(r.workspace, attachmentSecretRoots(w.env, "main").workspace);
  const f1 = await registerAttachmentSecrets(w.env, "main", mockArbiter({ discoverFails: true }));
  assert.equal(f1.ok, false);
  assert.match(f1.error!, /could not discover secrets \(walk failed\)/);
  const f2 = await registerAttachmentSecrets(w.env, "main", mockArbiter({ registerFails: "/h/.aws/credentials" }));
  assert.equal(f2.ok, false);
  assert.match(f2.error!, /could not register \/h\/\.aws\/credentials/);
});

test("mandu serve register-secrets --json: the pool's answer, exit 1 on a failure, 2 on usage", async () => {
  const w = world();
  let out = "";
  let err = "";
  const io = { out: (s: string) => { out += s; }, err: (s: string) => { err += s; } };
  assert.equal(await runRegisterSecrets(["--agent", "main", "--json"], w.env, { ...io, arbiter: async () => mockArbiter() }), 0);
  const ans = JSON.parse(out.trim()) as { ok: boolean; registered: number; found: number };
  assert.deepEqual([ans.ok, ans.registered, ans.found], [true, 2, 3]);
  out = "";
  assert.equal(await runRegisterSecrets(["--agent=main"], w.env, { ...io, arbiter: async () => { throw new Error("no arbiter answers at /x"); } }), 1);
  assert.match(err, /secrets not registered: no arbiter answers at \/x/);
  assert.equal(await runRegisterSecrets(["--bogus"], w.env, io), 2);
});
