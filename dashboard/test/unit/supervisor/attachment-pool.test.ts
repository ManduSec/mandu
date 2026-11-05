/**
 * attachment-pool.test — `mandu serve`'s proxy pool (src/supervisor/
 * attachment-pool.ts; docs/design/agents/openclaw-plugin.md §3.2): the pure
 * decisions (the proxy's environment, the backoff, the reconcile, the port,
 * the arbiter's and the launcher's answers), and the pool's order over fake
 * effects: secrets registered, then the attachment, then the proxy, then the
 * port file; nothing serves when the secrets or the registration fail; a
 * proxy that exits loses its port file; a lost lease stops it; an undeclared
 * session ends its attachment. The route check (§3.6) over real temp config
 * files: a route lost is recorded with the arbiter (the admin channel, else
 * the human socket) as the coverage it loses and said in the pool record; a
 * route back records the full coverage; a service that starts with the route
 * lost registers it lost; a session no install armed stays pending. No axis
 * is read (the pool runs in `secrets`; the real proxy and arbiter:
 * tests/stack/serve-pool-invariant.test.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  AttachmentPool,
  nextRouteRecord,
  routeCoverage,
  routeReport,
  watchConfigFiles,
  backoffMs,
  BOUND_PORT_FILE,
  parseRegistration,
  parseSecretsRun,
  pickPort,
  POOL_UPSTREAM_KEYS,
  poolProxyEnv,
  declaredUpstreamEnv,
  reconcilePlan,
  type PoolChild,
  type PoolDeps,
  type SecretsRun,
} from "../../../src/supervisor/attachment-pool.js";
import { anthropicProxyPortFile, attachmentDir, poolMarkerFile, providersKey, renderDeclared, type DeclaredAttachment, type DeclaredProvider, type RouteRecord } from "../../../src/attachment-contract.js";
import { ATTACHMENT_COVERAGE } from "../../../src/confinement-posture.js";
import { readOpenclawConfig } from "../../../src/openclaw/openclaw-config-read.js";
import { tmpDir } from "../tmp-dir.js";

const MAIN: DeclaredAttachment = { kind: "openclaw-plugin", agent: "main", session: "openclaw:main", port: 41234 };

test("poolProxyEnv: the session's keys set, every plan-derived key of a launch unset whatever the ambient env says", () => {
  const env = poolProxyEnv({
    service: { PATH: "/bin", MANDU_VIEW_MAP: "[{}]", MANDU_AGENT_CWD: "/x", MANDU_NET_TLS_INSPECTED: "1", MANDU_VERTEX_UPSTREAMS: '{"google-vertex":null}' },
    form: { MANDU_ARBITER_CLIENT_MODULE: "/pkg/dist/arbiter-client.mjs", MANDU_UPSTREAM: "https://api.anthropic.com", MANDU_PROXY_PORT: "8788" },
    arbiterSock: "/run/m/current/arbiter.sock", humanSock: "/run/m/human/h.sock", session: "openclaw:main", port: 41234,
    boundFile: "/run/m/attachments/openclaw:main/anthropic-proxy.bound", ownerPid: 4242,
  });
  assert.equal(env["MANDU_SESSION_KEY"], "openclaw:main");
  assert.equal(env["MANDU_INBOUND_SPEC"], "openclaw-agent");
  assert.equal(env["MANDU_TENANT"], "live");
  assert.equal(env["MANDU_SECRET_POSTURE"], "gated");
  assert.equal(env["MANDU_ARBITER_SOCK"], "/run/m/current/arbiter.sock");
  assert.equal(env["MANDU_ARBITER_HUMAN_SOCK"], "/run/m/human/h.sock");
  assert.equal(env["MANDU_ARBITER_CLIENT_MODULE"], "/pkg/dist/arbiter-client.mjs", "the spawn form's env rides along");
  assert.equal(env["MANDU_PROXY_HOST"], "127.0.0.1");
  assert.equal(env["MANDU_PROXY_PORT"], "41234", "the pool's port, not the shared proxy's");
  assert.equal(env["MANDU_LIFELINE"], "stdin");
  assert.equal(env["MANDU_OWNER_PID"], "4242");
  assert.equal(env["MANDU_UPSTREAM"], "https://api.anthropic.com", "no upstream configured: the form's default");
  // MANDU_VERTEX_UPSTREAMS: Route 1 routes no Vertex AI provider (openclaw-plugin.md §8.1).
  for (const k of ["MANDU_VIEW_MAP", "MANDU_AGENT_CWD", "MANDU_NET_TLS_INSPECTED", "MANDU_UPSTREAM_TLS", "MANDU_UPSTREAM_LOCAL", "MANDU_OPENAI_UPSTREAMS", "MANDU_VERTEX_UPSTREAMS"]) {
    assert.ok(k in env && env[k] === undefined, `${k} explicitly unset`);
  }
  assert.equal(poolProxyEnv({ service: {}, arbiterSock: "/a", humanSock: null, session: "s", port: 0, boundFile: "/b", ownerPid: 1, upstream: "http://u" })["MANDU_UPSTREAM"], "http://u");
});

test("poolProxyEnv: the agent's workspace is the proxy's MANDU_AGENT_CWD (an absolute one only; never the service's own)", () => {
  const base = { service: { MANDU_AGENT_CWD: "/service" }, arbiterSock: "/a", humanSock: null, session: "openclaw:main", port: 1, boundFile: "/b", ownerPid: 1 };
  assert.equal(poolProxyEnv({ ...base, agentCwd: "/home/u/projects" })["MANDU_AGENT_CWD"], "/home/u/projects");
  assert.equal(poolProxyEnv({ ...base, agentCwd: "projects" })["MANDU_AGENT_CWD"], undefined);
  assert.equal(poolProxyEnv(base)["MANDU_AGENT_CWD"], undefined);
});

test("poolProxyEnv: the service's upstream keys win over the supervisor's default (the fresh-VM leg's 401, 2026-10-25)", () => {
  const service = {
    MANDU_UPSTREAM: "http://127.0.0.1:9999", MANDU_UPSTREAM_LOCAL: "1", MANDU_UPSTREAM_TLS: '{"ca":"/etc/ca.pem"}',
    MANDU_UPSTREAM_IS_BASE_URL: "1", MANDU_OPENAI_UPSTREAMS: '{"ollama":"http://127.0.0.1:11434/v1"}', MANDU_OPENAI_TEXT_CALLS: '["ollama"]',
    MANDU_GOOGLE_UPSTREAMS: '{"google":"http://127.0.0.1:9998/v1beta"}',
    MANDU_OLLAMA_UPSTREAMS: '{"ollama":"http://127.0.0.1:11434"}',
  };
  const env = poolProxyEnv({
    service, form: { MANDU_UPSTREAM: "https://api.anthropic.com" },
    arbiterSock: "/a", humanSock: null, session: "openclaw:main", port: 1, boundFile: "/b", ownerPid: 1,
  });
  for (const k of POOL_UPSTREAM_KEYS) assert.equal(env[k], service[k], k);
  // An empty value in the service is no value: the default stands.
  assert.equal(poolProxyEnv({ service: { MANDU_UPSTREAM: "" }, form: { MANDU_UPSTREAM: "https://api.anthropic.com" }, arbiterSock: "/a", humanSock: null, session: "s", port: 1, boundFile: "/b", ownerPid: 1 })["MANDU_UPSTREAM"], "https://api.anthropic.com");
});

test("Route 1: the declared providers' own addresses win over the service environment; a built-in one takes the environment's, else its own", () => {
  const providers: DeclaredProvider[] = [
    { id: "anthropic", wire: "anthropic-messages", upstream: "https://gw.corp.example/anthropic", original: { existed: true, headers: false } },
    { id: "openai", wire: "openai-responses", upstream: null, original: { existed: false, headers: false } },
    { id: "openrouter", wire: "openai-completions", upstream: "https://openrouter.ai/api/v1", original: { existed: true, headers: false } },
  ];
  const service = {
    MANDU_UPSTREAM: "http://127.0.0.1:9", MANDU_UPSTREAM_LOCAL: "1", MANDU_UPSTREAM_TLS: '{"ca":"/c.pem"}',
    MANDU_OPENAI_UPSTREAMS: '{"openrouter":"http://127.0.0.1:9/wrong","openai":"http://127.0.0.1:7/v1"}',
  };
  const env = poolProxyEnv({ service, form: { MANDU_UPSTREAM: "https://api.anthropic.com" }, arbiterSock: "/a", humanSock: null, session: "openclaw:main", port: 1, boundFile: "/b", ownerPid: 1, providers });
  assert.equal(env["MANDU_UPSTREAM"], "https://gw.corp.example/anthropic", "the Anthropic-wire provider's own address");
  assert.equal(env["MANDU_UPSTREAM_LOCAL"], undefined, "the environment's claims about ITS upstream go with it");
  assert.equal(env["MANDU_UPSTREAM_TLS"], undefined);
  assert.deepEqual(JSON.parse(env["MANDU_OPENAI_UPSTREAMS"]!), { openai: "http://127.0.0.1:7/v1", openrouter: "https://openrouter.ai/api/v1" });
  // Built-ins only (null upstreams): the environment's Messages upstream and
  // keys stand (a test's stand-in model, an operator's gateway), and openai
  // goes to its own address when the environment names none.
  const builtins = providers.map((p) => ({ ...p, upstream: null }));
  assert.deepEqual(declaredUpstreamEnv(builtins.slice(0, 2), {}), { MANDU_OPENAI_UPSTREAMS: '{"openai":"https://api.openai.com/v1"}' });
  const e2 = poolProxyEnv({ service, form: {}, arbiterSock: "/a", humanSock: null, session: "s", port: 1, boundFile: "/b", ownerPid: 1, providers: builtins.slice(0, 1) });
  assert.equal(e2["MANDU_UPSTREAM"], "http://127.0.0.1:9");
  assert.equal(e2["MANDU_UPSTREAM_LOCAL"], "1");
  assert.equal(e2["MANDU_OPENAI_UPSTREAMS"], service.MANDU_OPENAI_UPSTREAMS, "no OpenAI-wire provider declared: the environment's");
  // Nothing declared (a `mandu serve attach` before any install): all from the environment.
  assert.deepEqual(declaredUpstreamEnv(undefined, service), {});
  // A changed provider list restarts the proxy; the same one does not.
  const withP: DeclaredAttachment = { ...MAIN, providers };
  assert.deepEqual(reconcilePlan([withP], new Map([["openclaw:main", MAIN]])).stop, ["openclaw:main"]);
  assert.deepEqual(reconcilePlan([withP], new Map([["openclaw:main", { ...withP, providers: [...providers] }]])).stop, []);
  assert.deepEqual(reconcilePlan([{ ...withP, unprotected: ["google"] }], new Map([["openclaw:main", withP]])).stop, [], "an unprotected list is checked, not forwarded");
});

test("Route 1, Gemini (model-wires.md §5): a google-generative-ai provider's address goes in MANDU_GOOGLE_UPSTREAMS, apart from the OpenAI table; the built-in google goes to the environment's, else Google's", () => {
  const providers: DeclaredProvider[] = [
    { id: "openai", wire: "openai-responses", upstream: null, original: { existed: false, headers: false } },
    { id: "google", wire: "google-generative-ai", upstream: null, original: { existed: false, headers: false } },
    { id: "corpgem", wire: "google-generative-ai", upstream: "https://gemini.corp.example/v1beta", original: { existed: true, headers: false } },
  ];
  const env = declaredUpstreamEnv(providers, {});
  assert.deepEqual(JSON.parse(env["MANDU_OPENAI_UPSTREAMS"]!), { openai: "https://api.openai.com/v1" }, "no Gemini provider in the OpenAI table");
  assert.deepEqual(JSON.parse(env["MANDU_GOOGLE_UPSTREAMS"]!), { google: "https://generativelanguage.googleapis.com/v1beta", corpgem: "https://gemini.corp.example/v1beta" });
  const fromEnv = declaredUpstreamEnv(providers.slice(1, 2), { MANDU_GOOGLE_UPSTREAMS: '{"google":"http://127.0.0.1:8/v1beta"}' });
  assert.deepEqual(fromEnv, { MANDU_GOOGLE_UPSTREAMS: '{"google":"http://127.0.0.1:8/v1beta"}' }, "the built-in at the environment's address (a test's stand-in model)");
  const pool = poolProxyEnv({ service: { MANDU_GOOGLE_UPSTREAMS: '{"x":"http://127.0.0.1:1"}' }, form: {}, arbiterSock: "/a", humanSock: null, session: "s", port: 1, boundFile: "/b", ownerPid: 1 });
  assert.equal(pool["MANDU_GOOGLE_UPSTREAMS"], '{"x":"http://127.0.0.1:1"}', "nothing declared: the environment's");
  assert.ok("MANDU_GOOGLE_UPSTREAMS" in poolProxyEnv({ service: {}, arbiterSock: "/a", humanSock: null, session: "s", port: 0, boundFile: "/b", ownerPid: 1 }), "explicitly unset otherwise");
});

test("backoff, reconcile, port, and the answers", () => {
  assert.deepEqual([0, 1, 2, 3, 10].map((n) => backoffMs(n)), [1000, 2000, 4000, 8000, 30_000]);
  const running = new Map([["openclaw:main", MAIN], ["openclaw:old", { ...MAIN, agent: "old", session: "openclaw:old" }]]);
  const plan = reconcilePlan([{ ...MAIN, port: 42000 }, { ...MAIN, agent: "ops", session: "openclaw:ops" }], running);
  assert.deepEqual(plan.stop.sort(), ["openclaw:main", "openclaw:old"], "undeclared, or its port moved");
  assert.deepEqual(plan.start.map((d) => d.session).sort(), ["openclaw:main", "openclaw:ops"]);
  assert.deepEqual(reconcilePlan([MAIN], new Map([["openclaw:main", MAIN]])), { start: [], stop: [] });
  assert.equal(pickPort(41234, false), 41234);
  assert.equal(pickPort(41234, true), 0);
  assert.equal(pickPort(null, false), 0);
  assert.deepEqual(parseRegistration({ token: "t", expiresAt: 5, leaseMs: 60_000 }), { token: "t", expiresAt: 5, leaseMs: 60_000 });
  assert.ok("error" in parseRegistration({ expiresAt: 5 }));
  assert.deepEqual(parseSecretsRun('noise\n{"ok":true,"found":3,"registered":2}\n', 0), { ok: true, found: 3, registered: 2 });
  assert.deepEqual(parseSecretsRun('{"ok":false,"error":"walk failed"}', 1), { ok: false, error: "walk failed" });
  // the agent's workspace (2026-10-26): kept when absolute, dropped otherwise
  assert.deepEqual(parseSecretsRun('{"ok":true,"found":1,"registered":1,"workspace":"/w/agent"}', 0), { ok: true, found: 1, registered: 1, workspace: "/w/agent" });
  assert.deepEqual(parseSecretsRun('{"ok":true,"workspace":"rel/agent"}', 0), { ok: true });
  assert.deepEqual(parseSecretsRun('{"ok":true,"workspace":null}', 0), { ok: true });
  assert.equal(parseSecretsRun('{"ok":true}', 1).ok, false, "a non-zero exit is a failure whatever it printed");
  assert.match(parseSecretsRun("", 1).error!, /without an answer/);
});

// ── The pool over fake effects ──────────────────────────────────────────────

interface Fake {
  deps: PoolDeps;
  base: string;
  calls: string[];
  children: Array<PoolChild & { die(code: number): void; env: NodeJS.ProcessEnv }>;
  setDeclared(list: DeclaredAttachment[]): void;
  /** Every beginAttachment's / updateAttachment's arguments, by channel. */
  begins: Array<Record<string, unknown>>;
  updates: Array<{ via: "admin" | "human"; args: Record<string, unknown> }>;
  secrets: { next: SecretsRun };
  arbiter: { begin: "ok" | "refuse"; renewed: boolean };
}

function fake(): Fake {
  const root = tmpDir("mandu-pool-");
  const base = join(root, "run");
  mkdirSync(base, { mode: 0o700 });
  let declared = "";
  const calls: string[] = [];
  const children: Fake["children"] = [];
  const secrets = { next: { ok: true, found: 2, registered: 2 } as SecretsRun };
  const arbiter = { begin: "ok" as "ok" | "refuse", renewed: true };
  const begins: Fake["begins"] = [];
  const updates: Fake["updates"] = [];
  let tok = 0;
  const deps: PoolDeps = {
    runtimeBase: base,
    arbiterSock: "/run/m/current/arbiter.sock",
    readDeclared: () => declared,
    proxySpawn: async () => ({ command: "node", args: ["proxy.js"], cwd: "/", env: { FROM_FORM: "1" } }),
    spawn: (_form, env) => {
      let exited = false;
      const cbs: Array<(c: number | null, s: NodeJS.Signals | null) => void> = [];
      const port = Number(env["MANDU_PROXY_PORT"]) || 45000 + children.length;
      // The proxy publishes its bound port, as server-main does.
      writeFileSync(String(env["MANDU_PORT_FILE"]), String(port));
      const c = {
        pid: 9000 + children.length, env,
        onExit: (cb: (c: number | null, s: NodeJS.Signals | null) => void) => { cbs.push(cb); },
        kill: () => { if (!exited) { exited = true; queueMicrotask(() => cbs.forEach((cb) => cb(null, "SIGTERM"))); } },
        exited: () => exited,
        die: (code: number) => { exited = true; cbs.forEach((cb) => cb(code, null)); },
      };
      calls.push(`spawn ${env["MANDU_SESSION_KEY"]} port=${env["MANDU_PROXY_PORT"]}`);
      children.push(c);
      return c;
    },
    humanSock: async () => "/run/m/human/h.sock",
    call: async (_sock, op, args) => {
      calls.push(op);
      if (op === "beginAttachment") {
        if (arbiter.begin === "refuse") throw new Error("refused");
        assert.equal(args["kind"], "openclaw-plugin");
        begins.push(args);
        return { token: `tok${++tok}`, expiresAt: Date.now() + 60_000, leaseMs: 60_000, posture: "gated", gap: "openclaw-plugin" };
      }
      if (op === "updateAttachment") { updates.push({ via: "human", args }); return { posture: "gated", gap: "x", believed: false }; }
      if (op === "renewAttachment") return { renewed: arbiter.renewed, expiresAt: arbiter.renewed ? Date.now() + 60_000 : null };
      return { ended: true };
    },
    probeIdentity: async () => ({ mandu: true, service: "anthropic-proxy", sessionKey: "openclaw:main", arbiterSock: "/run/m/current/arbiter.sock" }),
    portBusy: async () => false,
    registerSecrets: async (d) => { calls.push(`secrets ${d.agent}`); return secrets.next; },
    logDir: root,
    env: { PATH: "/bin" },
    ownerPid: process.pid,
    uid: process.getuid?.(),
    now: () => Date.now(),
    log: () => {},
    timing: { secretsMs: 60_000, reconcileMs: 20, renewMs: 40, readyMs: 2_000, stopGraceMs: 50, backoffBaseMs: 20, backoffMaxMs: 40, stableMs: 60_000, routeMs: 60_000, routeDebounceMs: 10 },
  };
  return { deps, base, calls, children, secrets, arbiter, begins, updates, setDeclared: (l) => { declared = renderDeclared(l); } };
}

async function until(pred: () => boolean, ms = 3_000): Promise<void> {
  const end = Date.now() + ms;
  while (!pred()) {
    if (Date.now() > end) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 10));
  }
}

test("the order: secrets, the attachment, the proxy, then the port file (0600 in a 0700 directory); stop undoes it in reverse", async () => {
  const f = fake();
  f.setDeclared([MAIN]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  const portFile = anthropicProxyPortFile(f.base, "openclaw:main");
  await until(() => existsSync(portFile));
  assert.deepEqual(f.calls.slice(0, 3), ["secrets main", "beginAttachment", "spawn openclaw:main port=41234"]);
  assert.deepEqual(f.begins[0]!["coverage"], { modelContext: "proxy", files: { by: "none", why: "openclaw-plugin" }, exec: "policy", egress: "none", replies: "chat", ownState: "readable" });
  assert.equal(f.begins[0]!["route"], undefined, "no route check in this pool: nothing claimed about one");
  assert.equal(readFileSync(portFile, "utf8"), "41234\n");
  assert.equal(statSync(portFile).mode & 0o777, 0o600);
  assert.equal(statSync(attachmentDir(f.base, "openclaw:main")).mode & 0o777, 0o700);
  assert.ok(existsSync(join(attachmentDir(f.base, "openclaw:main"), BOUND_PORT_FILE)));
  assert.equal(f.children[0]!.env["FROM_FORM"], "1", "the supervisor's spawn form's env rides along");
  const rec = JSON.parse(readFileSync(join(attachmentDir(f.base, "openclaw:main"), "pool.json"), "utf8"));
  assert.deepEqual([rec.pid, rec.proxyPid, rec.secrets.registered], [process.pid, 9000, 2]);
  assert.ok(existsSync(poolMarkerFile(f.base)));
  const e = pool.list()[0]!;
  assert.deepEqual([e.state, e.registered, e.port, e.secrets?.registered], ["serving", true, 41234, 2]);
  await until(() => f.calls.includes("renewAttachment"));
  await pool.stop();
  assert.equal(f.calls.at(-1), "endAttachment");
  assert.ok(!existsSync(portFile) && !existsSync(attachmentDir(f.base, "openclaw:main")));
  assert.ok(f.children[0]!.exited());
  assert.ok(!existsSync(poolMarkerFile(f.base)));
});

test("the agent's workspace the registration resolved is the proxy's MANDU_AGENT_CWD (relative tool paths start there, 2026-10-26)", async () => {
  const f = fake();
  f.secrets.next = { ok: true, found: 1, registered: 1, workspace: "/home/u/projects" };
  f.setDeclared([MAIN]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  await until(() => existsSync(anthropicProxyPortFile(f.base, "openclaw:main")));
  assert.equal(f.children[0]!.env["MANDU_AGENT_CWD"], "/home/u/projects");
  await pool.stop();
});

test("fail closed: failed secret registration, or a refused attachment, and nothing is spawned nor published", async () => {
  const f = fake();
  f.secrets.next = { ok: false, error: "walk failed" };
  f.setDeclared([MAIN]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  await until(() => f.calls.filter((c) => c === "secrets main").length >= 2);
  assert.ok(!f.calls.includes("beginAttachment") && f.children.length === 0, "neither registered nor served");
  assert.match(pool.list()[0]!.lastError!, /not registered \(walk failed\)/);
  // the secrets succeed; the arbiter refuses the attachment
  f.arbiter.begin = "refuse";
  f.secrets.next = { ok: true, found: 0, registered: 0 };
  await until(() => f.calls.filter((c) => c === "beginAttachment").length >= 2);
  assert.equal(f.children.length, 0);
  assert.ok(!existsSync(anthropicProxyPortFile(f.base, "openclaw:main")));
  f.arbiter.begin = "ok";
  await until(() => existsSync(anthropicProxyPortFile(f.base, "openclaw:main")));
  await pool.stop();
});

test("a proxy that exits loses its port file at once and is started again; the registration stays", async () => {
  const f = fake();
  f.setDeclared([MAIN]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  const portFile = anthropicProxyPortFile(f.base, "openclaw:main");
  await until(() => existsSync(portFile));
  f.children[0]!.die(1);
  assert.ok(!existsSync(portFile), "removed synchronously with the exit");
  await until(() => f.children.length === 2 && existsSync(portFile));
  assert.equal(f.calls.filter((c) => c === "beginAttachment").length, 1, "not registered again");
  assert.equal(pool.list()[0]!.restarts, 1);
  await pool.stop();
});

test("a lost lease that cannot be taken again stops the proxy (fail closed) and starts over", async () => {
  const f = fake();
  f.setDeclared([MAIN]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  const portFile = anthropicProxyPortFile(f.base, "openclaw:main");
  await until(() => existsSync(portFile));
  f.arbiter.renewed = false;
  f.arbiter.begin = "refuse";
  await until(() => !existsSync(portFile) && f.children[0]!.exited());
  f.arbiter.begin = "ok";
  f.arbiter.renewed = true;
  await until(() => existsSync(portFile) && f.children.length === 2);
  await pool.stop();
});

test("a failed secret rerun stops the proxy until a rerun succeeds", async () => {
  const f = fake();
  f.deps.timing.secretsMs = 50;
  f.setDeclared([MAIN]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  const portFile = anthropicProxyPortFile(f.base, "openclaw:main");
  await until(() => existsSync(portFile));
  f.secrets.next = { ok: false, error: "arbiter down" };
  await until(() => !existsSync(portFile));
  assert.ok(f.children[0]!.exited());
  f.secrets.next = { ok: true, found: 1, registered: 1 };
  await until(() => existsSync(portFile));
  assert.equal(pool.list()[0]!.secrets?.registered, 1);
  await pool.stop();
});

test("undeclared: its proxy stops, its port file goes, its attachment ends; a declared port in use falls back to any", async () => {
  const f = fake();
  f.deps.portBusy = async () => true;
  f.setDeclared([MAIN]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  const portFile = anthropicProxyPortFile(f.base, "openclaw:main");
  await until(() => existsSync(portFile));
  assert.match(f.calls.find((c) => c.startsWith("spawn"))!, /port=0$/);
  f.setDeclared([]);
  await until(() => f.calls.includes("endAttachment"));
  assert.ok(!existsSync(portFile));
  assert.deepEqual(pool.list(), []);
  await pool.stop();
});

// ── The route check (openclaw-plugin.md §3.6) ───────────────────────────────

const FULL = ATTACHMENT_COVERAGE["openclaw-plugin"];
const ROUTED = {
  plugins: {
    load: { paths: ["/src/mandu/interceptors/openclaw-inspect-plugin"] },
    entries: { "mandu-inspect": { enabled: true, config: { attachment: true, scopeId: "openclaw:main", agentId: "main" } } },
  },
  models: { providers: { anthropic: { baseUrl: "http://127.0.0.1:41234", api: "anthropic-messages", headers: { "x-mandu-session-id": "openclaw:main" } } } },
};

/** A fake pool with the route check on over a real config in a temp folder:
 *  the real reader and the real folder watch. */
function routeFake(doc: unknown, o: { admin?: "ok" | "fail" } = {}): Fake & { cfg: string; write(doc: unknown): void } {
  const f = fake();
  const dir = tmpDir("mandu-route-");
  const cfg = join(dir, "openclaw.json");
  const write = (d: unknown): void => { writeFileSync(`${cfg}.tmp`, typeof d === "string" ? d : JSON.stringify(d)); renameSync(`${cfg}.tmp`, cfg); };
  write(doc);
  f.deps.readRouteConfig = (p) => readOpenclawConfig(p, {}, dir);
  f.deps.routeConfigPath = join(dir, "never-named.json");
  f.deps.watchFiles = watchConfigFiles;
  f.deps.timing.routeMs = 60_000; // the watch, not the timer, finds each edit here
  if (o.admin !== undefined) {
    f.deps.updateAttachmentAdmin = async (args) => {
      if (o.admin === "fail") throw new Error("no admin channel");
      f.updates.push({ via: "admin", args });
      return { posture: "gated", gap: "x", believed: true };
    };
  }
  return { ...f, cfg, write };
}

function recordOf(f: Fake): { route?: RouteRecord } {
  return JSON.parse(readFileSync(join(attachmentDir(f.base, "openclaw:main"), "pool.json"), "utf8")) as { route?: RouteRecord };
}

test("route check: routed, then an edit that sends Anthropic calls elsewhere is recorded lost over the admin channel, then back after a re-install", async () => {
  const f = routeFake(ROUTED, { admin: "ok" });
  f.setDeclared([{ ...MAIN, config: f.cfg }]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  await until(() => existsSync(anthropicProxyPortFile(f.base, "openclaw:main")) && pool.list()[0]?.route?.state === "routed");
  assert.deepEqual(f.begins[0]!["coverage"], FULL);
  assert.deepEqual(f.begins[0]!["route"], { state: "routed", problems: [], config: f.cfg });
  assert.equal(f.updates.length, 0, "nothing to update: the registration carried the route");
  assert.equal(recordOf(f).route?.state, "routed");

  // The agent's programs point the provider elsewhere.
  const bypass = JSON.parse(JSON.stringify(ROUTED));
  bypass.models.providers.anthropic.baseUrl = "https://evil.example";
  f.write(bypass);
  await until(() => f.updates.length === 1);
  const u = f.updates[0]!;
  assert.equal(u.via, "admin", "the admin channel: believed while the attachment holds the human plane exposed");
  assert.equal(u.args["token"], "tok1");
  assert.deepEqual(u.args["coverage"], { ...FULL, modelContext: "none" });
  const route = u.args["route"] as { state: string; problems: Array<{ code: string; detail: string }>; config: string };
  assert.equal(route.state, "lost");
  assert.deepEqual(route.problems.map((p) => p.code), ["route-elsewhere"]);
  assert.match(route.problems[0]!.detail, /https:\/\/evil\.example, not Mandu's service proxy \(http:\/\/127\.0\.0\.1:41234\)/);
  assert.equal(route.config, f.cfg);
  const lost = pool.list()[0]!.route!;
  assert.equal(lost.state, "lost");
  assert.equal(recordOf(f).route?.state, "lost", "the pool record says so (status and doctor read it)");
  assert.ok(existsSync(anthropicProxyPortFile(f.base, "openclaw:main")), "the proxy keeps serving: the user's config is never rewritten, nothing is stopped");
  assert.equal(readFileSync(f.cfg, "utf8"), JSON.stringify(bypass), "the config is left as the user (or the agent) wrote it");

  // The same state again sends nothing; the plugin also disabled adds the policy loss.
  const both = JSON.parse(JSON.stringify(bypass));
  both.plugins.entries["mandu-inspect"].enabled = false;
  f.write(both);
  await until(() => f.updates.length === 2);
  assert.deepEqual(f.updates[1]!.args["coverage"], { ...FULL, modelContext: "none", exec: "none", replies: "none" });

  // Re-installed: the full coverage again, the route routed.
  f.write(ROUTED);
  await until(() => f.updates.length === 3);
  assert.deepEqual(f.updates[2]!.args["coverage"], FULL);
  assert.equal((f.updates[2]!.args["route"] as { state: string }).state, "routed");
  assert.equal(pool.list()[0]!.route!.state, "routed");
  await pool.stop();
});

test("route check, the confined-commands tier (openclaw-plugin.md §10.6): held, then lost (sandbox off, another plugin's `mandu`), said and recorded; the coverage untouched", async () => {
  const tier = {
    ...JSON.parse(JSON.stringify(ROUTED)),
    agents: { defaults: { sandbox: { mode: "all", backend: "mandu", workspaceAccess: "rw" } } },
    tools: { elevated: { enabled: false }, sandbox: { tools: { alsoAllow: ["message", "group:web", "group:plugins"] } } },
  };
  const f = routeFake(tier, { admin: "ok" });
  const logs: string[] = [];
  f.deps.log = (m) => logs.push(m);
  let status: string | null = null;
  f.deps.readText = () => status;
  f.setDeclared([{ ...MAIN, config: f.cfg, sandbox: { original: { sandbox: null, alsoAllow: null, elevated: null, execHost: null } } }]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  const rec = (): { sandbox?: { state: string; problems: Array<{ kind: string }> } } =>
    JSON.parse(readFileSync(join(attachmentDir(f.base, "openclaw:main"), "pool.json"), "utf8"));
  await until(() => existsSync(join(attachmentDir(f.base, "openclaw:main"), "pool.json")) && rec().sandbox?.state === "held");

  // The agent's programs (or a person) switch the sandbox off.
  const off = JSON.parse(JSON.stringify(tier));
  off.agents.defaults.sandbox.mode = "non-main";
  f.write(off);
  await until(() => rec().sandbox?.state === "lost");
  assert.deepEqual(rec().sandbox!.problems.map((p) => p.kind), ["sandbox-mode"]);
  assert.ok(logs.some((l) => /SANDBOX LOST: commands may run outside Mandu's box.*not "all".*mandu openclaw install --sandbox/.test(l)), logs.join("\n"));
  assert.equal(f.updates.length, 0, "the tier is no part of the declared coverage: nothing sent to the arbiter");

  // Back; then the plugin reports another plugin took `mandu`.
  f.write(tier);
  await until(() => rec().sandbox?.state === "held");
  assert.ok(logs.some((l) => /confined-commands tier is back/.test(l)));
  status = JSON.stringify({ version: 1, pid: process.pid, checkedAt: new Date().toISOString(), sdk: true, registered: true, ours: false });
  f.write({ ...tier, gateway: { port: 1 } });
  await until(() => rec().sandbox?.state === "lost");
  assert.deepEqual(rec().sandbox!.problems.map((p) => p.kind), ["backend-replaced"]);
  await pool.stop();
});

test("route check: the plugin removed alone loses the policy rows, not the model context; an unreadable config loses both", async () => {
  const f = routeFake(ROUTED, { admin: "ok" });
  f.setDeclared([{ ...MAIN, config: f.cfg }]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  await until(() => pool.list()[0]?.route?.state === "routed" && pool.list()[0]?.state === "serving");
  const noPlugin = JSON.parse(JSON.stringify(ROUTED));
  delete noPlugin.plugins.entries["mandu-inspect"];
  f.write(noPlugin);
  await until(() => f.updates.length === 1);
  assert.deepEqual(f.updates[0]!.args["coverage"], { ...FULL, exec: "none", replies: "none" });
  f.write("{ plugins: ");
  await until(() => f.updates.length === 2);
  assert.deepEqual(f.updates[1]!.args["coverage"], { ...FULL, modelContext: "none", exec: "none", replies: "none" });
  assert.deepEqual(((f.updates[1]!.args["route"]) as { problems: Array<{ code: string }> }).problems.map((p) => p.code), ["unreadable"]);
  await pool.stop();
});

test("route check: a service that starts with the route already lost registers it lost; no admin channel records over the human socket", async () => {
  const bypass = JSON.parse(JSON.stringify(ROUTED));
  delete bypass.models.providers.anthropic.baseUrl;
  const f = routeFake(bypass, { admin: "fail" });
  f.setDeclared([{ ...MAIN, config: f.cfg }]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  await until(() => f.begins.length === 1 && pool.list()[0]?.state === "serving");
  assert.deepEqual(f.begins[0]!["coverage"], { ...FULL, modelContext: "none" }, "never registered as covered");
  assert.equal((f.begins[0]!["route"] as { state: string }).state, "lost");
  f.write(ROUTED);
  await until(() => f.updates.length === 1);
  assert.equal(f.updates[0]!.via, "human", "the admin channel failed: the human socket (a claim)");
  assert.deepEqual(f.updates[0]!.args["coverage"], FULL);
  await pool.stop();
});

test("route check: a session no install armed stays pending (no alarm) until it is seen routed; armed after that", async () => {
  const f = routeFake({ tools: { profile: "coding" } }, { admin: "ok" });
  // Declared by `mandu serve attach` alone: no config recorded; the
  // service's own path is the file.
  f.deps.routeConfigPath = f.cfg;
  f.setDeclared([MAIN]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  await until(() => pool.list()[0]?.state === "serving" && pool.list()[0]?.route !== null);
  assert.equal(pool.list()[0]!.route!.state, "pending");
  assert.deepEqual(f.begins[0]!["coverage"], FULL, "nothing attached yet to lose");
  assert.equal(f.begins[0]!["route"], undefined);
  f.write(ROUTED);
  await until(() => pool.list()[0]?.route?.state === "routed");
  await until(() => f.updates.length === 1);
  assert.equal((f.updates[0]!.args["route"] as { state: string }).state, "routed");
  f.write({ tools: { profile: "coding" } });
  await until(() => pool.list()[0]?.route?.state === "lost");
  await until(() => f.updates.length === 2);
  assert.equal((f.updates[1]!.args["route"] as { state: string }).state, "lost");
  await pool.stop();
});

test("route check: the declaration's config, recorded by an install, is picked up in place", async () => {
  const f = routeFake(ROUTED, { admin: "ok" });
  f.deps.routeConfigPath = join(f.cfg, "..", "absent.json");
  f.setDeclared([MAIN]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  await until(() => pool.list()[0]?.state === "serving" && pool.list()[0]?.route !== null);
  assert.equal(pool.list()[0]!.route!.state, "pending", "the service's own path names no config");
  f.setDeclared([{ ...MAIN, config: f.cfg }]);
  await until(() => pool.list()[0]?.route?.state === "routed");
  assert.equal(pool.list()[0]!.route!.config, f.cfg);
  assert.equal(f.children.length, 1, "the slot kept running");
  await pool.stop();
});

test("route check, pure: the coverage and report a record gives, and since kept while nothing changes", () => {
  const rec = (state: RouteRecord["state"], codes: string[] = []): RouteRecord => ({ state, problems: codes.map((code) => ({ code: code as never, detail: code })), config: "/c", since: "s", checkedAt: "c" });
  assert.deepEqual(routeCoverage(MAIN, null), FULL);
  assert.deepEqual(routeCoverage(MAIN, rec("pending", ["route-direct"])), FULL);
  assert.deepEqual(routeCoverage(MAIN, rec("lost", ["route-direct"])), { ...FULL, modelContext: "none" });
  assert.equal(routeReport(rec("pending")), undefined);
  assert.deepEqual(routeReport(rec("lost", ["model-bypass"])), { state: "lost", problems: [{ code: "model-bypass", detail: "model-bypass" }], config: "/c" });
  const a = nextRouteRecord(null, { state: "routed", problems: [], config: "/c", now: "t1" });
  assert.ok(a.changed);
  const b = nextRouteRecord(a.record, { state: "routed", problems: [], config: "/c", now: "t2" });
  assert.deepEqual([b.changed, b.record.since, b.record.checkedAt], [false, "t1", "t2"]);
  assert.ok(nextRouteRecord(b.record, { state: "lost", problems: [{ code: "route-direct", detail: "x" }], config: "/c", now: "t3" }).changed);
});

test("Route 1: a declared OpenAI-compatible provider: its proxy forwards it to its own address, the record names the providers, and the route check judges its route too", async () => {
  const OR: DeclaredProvider = { id: "openrouter", wire: "openai-completions", upstream: "https://openrouter.ai/api/v1", original: { existed: true, headers: false } };
  const providers: DeclaredProvider[] = [
    { id: "anthropic", wire: "anthropic-messages", upstream: null, original: { existed: false, headers: false } },
    OR,
  ];
  const routed = JSON.parse(JSON.stringify(ROUTED));
  routed.models.providers.openrouter = { baseUrl: "http://127.0.0.1:41234/_mandu/openai/openrouter", api: "openai-completions", headers: { "x-mandu-session-id": "openclaw:main" }, models: [] };
  const f = routeFake(routed, { admin: "ok" });
  f.setDeclared([{ ...MAIN, config: f.cfg, providers, unprotected: ["openai"] }]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  await until(() => existsSync(anthropicProxyPortFile(f.base, "openclaw:main")) && pool.list()[0]?.route?.state === "routed");
  assert.equal(f.children[0]!.env["MANDU_OPENAI_UPSTREAMS"], JSON.stringify({ openrouter: "https://openrouter.ai/api/v1" }), "the provider's own address, from the declaration");
  assert.equal((JSON.parse(readFileSync(join(attachmentDir(f.base, "openclaw:main"), "pool.json"), "utf8")) as { providers?: string }).providers, providersKey(providers));

  // The provider pointed back at its own endpoint: a lost route naming it.
  const direct = JSON.parse(JSON.stringify(routed));
  direct.models.providers.openrouter.baseUrl = "https://openrouter.ai/api/v1";
  f.write(direct);
  await until(() => f.updates.length === 1);
  const route = f.updates[0]!.args["route"] as { state: string; problems: Array<{ code: string; detail: string }> };
  assert.equal(route.state, "lost");
  assert.match(route.problems[0]!.detail, /calls of provider openrouter go to https:\/\/openrouter\.ai, not Mandu's service proxy/);
  assert.equal((f.updates[0]!.args["coverage"] as { modelContext: string }).modelContext, "none");

  // The install records another address: the proxy restarts with it.
  f.write(routed);
  await until(() => f.updates.length === 2);
  f.setDeclared([{ ...MAIN, config: f.cfg, providers: [providers[0]!, { ...OR, upstream: "https://litellm.corp.example/v1" }], unprotected: ["openai"] }]);
  await until(() => f.children.length === 2 && existsSync(anthropicProxyPortFile(f.base, "openclaw:main")), 10_000);
  assert.equal(f.children[1]!.env["MANDU_OPENAI_UPSTREAMS"], JSON.stringify({ openrouter: "https://litellm.corp.example/v1" }));
  await pool.stop();
});

test("the model fence: the allowlist the install recorded, removed or widened, is a lost model context over the admin channel; put back, the route is back; a fence recorded again is judged at once", async () => {
  const providers: DeclaredProvider[] = [
    { id: "anthropic", wire: "anthropic-messages", upstream: null, original: { existed: false, headers: false } },
    { id: "openai", wire: "openai-responses", upstream: null, original: { existed: false, headers: false } },
  ];
  const fenced = JSON.parse(JSON.stringify(ROUTED));
  fenced.models.providers.openai = { baseUrl: "http://127.0.0.1:41234/_mandu/openai/openai", api: "openai-responses", headers: { "x-mandu-session-id": "openclaw:main" }, models: [] };
  fenced.agents = { defaults: { models: { "anthropic/*": {}, "openai/*": {} } } };
  const f = routeFake(fenced, { admin: "ok" });
  f.setDeclared([{ ...MAIN, config: f.cfg, providers, allowlist: ["anthropic/*", "openai/*"] }]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  await until(() => existsSync(anthropicProxyPortFile(f.base, "openclaw:main")) && pool.list()[0]?.route?.state === "routed");

  // The allowlist deleted: any model is one switch away.
  const gone = JSON.parse(JSON.stringify(fenced));
  delete gone.agents;
  f.write(gone);
  await until(() => f.updates.length === 1);
  let route = f.updates[0]!.args["route"] as { state: string; problems: Array<{ code: string; detail: string }> };
  assert.equal(route.state, "lost");
  assert.deepEqual(route.problems.map((p) => p.code), ["model-fence"]);
  assert.match(route.problems[0]!.detail, /the model allowlist \(agents\.defaults\.models\) Mandu wrote at the install is gone/);
  assert.equal((f.updates[0]!.args["coverage"] as { modelContext: string }).modelContext, "none");

  // Put back: routed again.
  f.write(fenced);
  await until(() => f.updates.length === 2);
  assert.equal((f.updates[1]!.args["route"] as { state: string }).state, "routed");

  // Widened: a key of a provider Mandu does not route.
  const wide = JSON.parse(JSON.stringify(fenced));
  wide.agents.defaults.models["mistral/*"] = {};
  f.write(wide);
  await until(() => f.updates.length === 3);
  route = f.updates[2]!.args["route"] as typeof route;
  assert.equal(route.state, "lost");
  assert.match(route.problems[0]!.detail, /names mistral\/\*, so a model switch can reach provider mistral/);

  // The declaration records the provider left on purpose (an install with
  // --leave-unprotected mistral): the change in place is judged at once.
  f.setDeclared([{ ...MAIN, config: f.cfg, providers, unprotected: ["mistral"], allowlist: ["anthropic/*", "openai/*", "mistral/*"] }]);
  await until(() => f.updates.length === 4);
  assert.equal((f.updates[3]!.args["route"] as { state: string }).state, "routed");
  // Only the fence recorded again (the same routes otherwise): judged too.
  f.write(gone);
  await until(() => f.updates.length === 5);
  f.setDeclared([{ ...MAIN, config: f.cfg, providers, unprotected: ["mistral"] }]);
  await until(() => f.updates.length === 6);
  assert.equal((f.updates[5]!.args["route"] as { state: string }).state, "routed", "an install before the fence: its absence is not judged");
  await pool.stop();
});

test("Route 1, Ollama: a declared Ollama-wire provider goes in MANDU_OLLAMA_UPSTREAMS at its own address; a built-in one at the environment's, else its own (a local Ollama, Ollama Cloud)", () => {
  const providers: DeclaredProvider[] = [
    { id: "ollama", wire: "ollama", upstream: null, original: { existed: false, headers: false } },
    { id: "ollama-cloud", wire: "ollama", upstream: null, original: { existed: false, headers: false } },
    { id: "gpu-box", wire: "ollama", upstream: "https://ollama.gpu.example", original: { existed: true, headers: false } },
  ];
  const env = poolProxyEnv({ service: {}, form: {}, arbiterSock: "/a", humanSock: null, session: "openclaw:main", port: 1, boundFile: "/b", ownerPid: 1, providers });
  assert.deepEqual(JSON.parse(env["MANDU_OLLAMA_UPSTREAMS"]!), { ollama: "http://127.0.0.1:11434", "ollama-cloud": "https://ollama.com", "gpu-box": "https://ollama.gpu.example" });
  assert.equal(env["MANDU_OPENAI_UPSTREAMS"], undefined, "an Ollama provider is not an OpenAI-wire route");
  const env2 = poolProxyEnv({ service: { MANDU_OLLAMA_UPSTREAMS: '{"ollama":"http://127.0.0.1:21434"}' }, form: {}, arbiterSock: "/a", humanSock: null, session: "openclaw:main", port: 1, boundFile: "/b", ownerPid: 1, providers: providers.slice(0, 1) });
  assert.deepEqual(JSON.parse(env2["MANDU_OLLAMA_UPSTREAMS"]!), { ollama: "http://127.0.0.1:21434" }, "the environment's address for a built-in");
});

test("route check, Azure OpenAI (model-wires.md §9.1): the Gateway's environment setting AZURE_OPENAI_BASE_URL loses the route; not readable is not verified (lost); nothing set is routed", async () => {
  const azure: DeclaredProvider = { id: "azure", wire: "azure-openai-responses", upstream: "https://r.openai.azure.com/openai/v1", original: { existed: true, headers: false } };
  const anthropic: DeclaredProvider = { id: "anthropic", wire: "anthropic-messages", upstream: null, original: { existed: false, headers: false } };
  const doc = JSON.parse(JSON.stringify(ROUTED));
  doc.models.providers.azure = { baseUrl: "http://127.0.0.1:41234/_mandu/openai/azure", api: "azure-openai-responses", headers: { "x-mandu-session-id": "openclaw:main" }, models: [] };
  doc.agents = { defaults: { model: { primary: "azure/gpt-5" }, models: { "azure/*": {}, "anthropic/*": {}, "openai/*": {} } } };
  const f = routeFake(doc);
  let facts: { verified: boolean; why?: string; set: string[] } = { verified: true, set: ["AZURE_OPENAI_BASE_URL (the running Gateway's environment, pid 4242)"] };
  const asked: string[] = [];
  f.deps.readGatewayEnv = (p) => { asked.push(p); return facts; };
  f.setDeclared([{ ...MAIN, config: f.cfg, providers: [anthropic, azure], unprotected: ["openai"], allowlist: [] }]);
  const pool = new AttachmentPool(f.deps);
  pool.start();
  await until(() => pool.list()[0]?.route?.state === "lost");
  assert.deepEqual(asked.slice(0, 1), [f.cfg], "the Gateway of the session's own config");
  let r = pool.list()[0]!.route!;
  assert.deepEqual(r.problems.map((p) => p.code), ["route-direct"]);
  assert.match(r.problems[0]!.detail, /Azure OpenAI provider azure go to AZURE_OPENAI_BASE_URL \(the running Gateway's environment, pid 4242\) instead of the route/);
  assert.equal(recordOf(f).route?.state, "lost", "status and the doctor read it");

  facts = { verified: true, set: [] };
  f.write(doc);
  await until(() => pool.list()[0]?.route?.state === "routed");

  facts = { verified: false, why: "Mandu cannot read a running OpenClaw Gateway's environment on this system (no /proc)", set: [] };
  f.write(doc);
  await until(() => pool.list()[0]?.route?.state === "lost");
  r = pool.list()[0]!.route!;
  assert.deepEqual(r.problems.map((p) => p.code), ["route-unverified"]);
  assert.match(r.problems[0]!.detail, /not verified: Mandu cannot read a running OpenClaw Gateway's environment/);
  await pool.stop();
});
