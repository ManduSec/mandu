/**
 * agent-world-originals-refused — the security-invariant oracle for the
 * arbiter's HUMAN PLANE (docs/design/architecture/arbiter-human-plane.md), across real
 * components and real process boundaries.
 *
 * THE CLASS: a process the agent's tools start (python3 / node / bash — not
 * boxed by default) can reach the arbiter's DATA socket ($MANDU_ARBITER_SOCK
 * is on the unix allow-list: every interceptor needs it). Before the human
 * plane, the ops that hand back ORIGINALS — deep `desymbolize`, shallow
 * `resolve`, and the observability store (`events` / `subscribe` / `sessions`
 * / `verifyEvents`, whose DualRepr.original fields carry originals) — answered
 * there too, label-unrestricted: a same-uid read of every secret the symbol
 * table holds, `no-model` ones included. The verbatim-value classify backstop
 * only catches originals printed as-is, so an encoded one reached the model.
 *
 * PINNED HERE (real ArbiterServer on the `secrets` axes; the secret registered
 * through the launcher's own registerSecret; event originals persisted):
 *   (1) a CHILD PROCESS given only $MANDU_ARBITER_SOCK — through the real
 *       arbiter client AND through a raw NDJSON socket — asks desymbolize,
 *       shallow resolve, events, sessions, verifyEvents and subscribe: every
 *       one is refused with the human-plane error, and the original never
 *       appears anywhere in its output; the deep resolve (the U-LLM's
 *       data-plane read) refuses the no-model row;
 *   (2) the human-facing consumers keep working over the human socket:
 *       fs-sync's syncToHuman writes the ORIGINAL into the HumanView through
 *       the production adapter over the human socket, and the same sync over
 *       the DATA socket fails closed (no original written). The reply-filter
 *       CLI side is pinned in reply-filter-secret-render.test.ts (e)/(f).
 *
 * Mandu-new test code (no reference origin). Offline, unprivileged.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ViewSync } from "../../fs-sync/src/view-sync.js";
import { ArbiterClientAdapter as FsSyncAdapter } from "../../fs-sync/src/arbiter-client.js";
import { makeTempRepo } from "../../fs-sync/test/helpers/temp-repo.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..");
const TSX = join(REPO, "tests", "node_modules", ".bin", "tsx");
const CLIENT_TS = join(REPO, "arbiter", "ipc", "client.ts");

const SESSION = "agent-world-oracle";
const API_KEY = "sk-oracle-no-model-7c1e9a0b5d";
const DB_PASSWORD = "oracle-db-pass-Q4v8";
const ORIGINALS = [API_KEY, DB_PASSWORD];

interface Rig {
  dir: string;
  dataSock: string;
  humanSock: string;
  /** A no-model token the arbiter minted for the .env's API_KEY. */
  token: string;
  data: ArbiterClient;
  human: ArbiterClient;
  close: () => Promise<void>;
}

async function startRig(): Promise<Rig> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-world-"));
  const home = join(dir, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const envPath = join(home, "proj", ".env");
  writeFileSync(envPath, `API_KEY=${API_KEY}\nDB_PASSWORD=${DB_PASSWORD}\n`);

  const dataSock = join(dir, "arbiter.sock");
  const humanSock = humanSockIn(dir);
  const server = new ArbiterServer({
    socketPath: dataSock,
    humanSocketPath: humanSock,
    dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"),
    integrity: false,
    confidentiality: true,
    adminPolicyDir: null,
    packDir: null,
    log: () => {},
  });
  await server.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();

  // The launcher's own registration call (secret-setup.ts): a structured twin
  // whose fields are no-model tokens.
  const reg = await data.registerSecret({ path: envPath, home });
  assert.ok(reg.twin, `.env gets a structured twin: ${reg.reason}`);
  const tokens = [...reg.twin!.matchAll(/\$MDU:nomodel_[^\s'"]+/g)].map((m) => m[0]);
  assert.ok(tokens.length >= 2, `the twin carries no-model tokens: ${reg.twin}`);
  const token = tokens.find((t) => /API_KEY|\.API_KEY/i.test(t)) ?? tokens[0]!;
  assert.ok(ORIGINALS.includes(await human.resolve(token) as string), "sanity: the human plane resolves the token");

  // Persist events whose DualRepr.original carries the secret (what the reply
  // filter's desymbolize event and the proxies record).
  await data.emit({
    id: "o1", sessionId: SESSION, ts: new Date().toISOString(), kind: "desymbolize",
    view: "HumanView", boundary: "user_reply", emitter: "reply-filter",
    output: { symbolized: token, original: API_KEY, differs: true, symbols: [] },
  } as never);
  assert.ok((await human.events(SESSION)).some((e) => JSON.stringify(e).includes(API_KEY)), "sanity: the stored event carries the original");

  return {
    dir, dataSock, humanSock, token, data, human,
    close: async () => {
      data.close();
      human.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** The agent world's env: ONLY the data socket (what net-guard and the Claude
 *  sandbox allow), never the human socket's name. */
function agentEnv(rig: Rig): NodeJS.ProcessEnv {
  return { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: rig.dir, MANDU_ARBITER_SOCK: rig.dataSock };
}

async function runChild(cmd: string, args: string[], env: NodeJS.ProcessEnv, cwd: string): Promise<string> {
  const child = spawn(cmd, args, { env, cwd, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (c: string) => (out += c));
  child.stderr.on("data", (c: string) => (out += c));
  const [code] = (await once(child, "close")) as [number | null];
  assert.equal(code, 0, `child exited 0: ${out}`);
  return out;
}

/** A child that uses the REAL arbiter client over $MANDU_ARBITER_SOCK. */
const CLIENT_SCRIPT = (clientTs: string, session: string) => `
import { ArbiterClient } from ${JSON.stringify(clientTs)};
const token = process.argv[2];
const c = new ArbiterClient(process.env.MANDU_ARBITER_SOCK);
const out = { humanEnv: process.env.MANDU_ARBITER_HUMAN_SOCK ?? null };
const attempt = async (name, fn) => {
  try { out[name] = { ok: true, value: await fn() }; } catch (e) { out[name] = { ok: false, error: e.message }; }
};
await attempt("desymbolize", () => c.desymbolize("x " + token + " y"));
await attempt("resolve", () => c.resolve(token));
await attempt("resolveFullShallow", () => c.resolveFull(token, { deep: false }));
await attempt("events", () => c.events(${JSON.stringify(session)}));
await attempt("sessions", () => c.sessions());
await attempt("verifyEvents", () => c.verifyEvents(${JSON.stringify(session)}));
await attempt("deepResolve", () => c.resolve(token, { deep: true }));
await attempt("subscribe", () => new Promise((res, rej) => {
  const frames = [];
  c.subscribe(${JSON.stringify(session)}, 0, (e) => frames.push(e), (err) => rej(err))
    .then(() => setTimeout(() => res(frames), 1500), rej);
}));
c.close();
process.stdout.write(JSON.stringify(out) + "\\n");
`;

/** A child speaking RAW NDJSON over the data socket (no client library). */
const RAW_SCRIPT = (session: string) => `
const net = require('net');
const token = process.argv[1];
const reqs = [
  { id: 1, op: 'desymbolize', text: token },
  { id: 2, op: 'resolve', symbol: token },
  { id: 3, op: 'events', sessionId: ${JSON.stringify(session)} },
  { id: 4, op: 'sessions' },
  { id: 5, op: 'verifyEvents', sessionId: ${JSON.stringify(session)} },
  { id: 6, op: 'resolve', symbol: token, deep: true },
];
const results = {};
const one = (req) => new Promise((res) => {
  const s = net.connect(process.env.MANDU_ARBITER_SOCK);
  let buf = '';
  s.on('connect', () => s.write(JSON.stringify(req) + '\\n'));
  s.on('data', (d) => { buf += d; });
  s.on('close', () => res(buf));
  s.on('error', (e) => res('ERR ' + e.message));
  setTimeout(() => s.end(), req.op === 'subscribe' ? 1500 : 800);
});
(async () => {
  for (const r of reqs) results[r.op + (r.deep ? ':deep' : '')] = await one(r);
  results.subscribe = await one({ id: 7, op: 'subscribe', sessionId: ${JSON.stringify(session)}, sinceSeq: 0 });
  process.stdout.write(JSON.stringify(results) + '\\n');
})();
`;

test("(1a) a child given only $MANDU_ARBITER_SOCK (the real client): every originals-returning op is refused; deep resolve refuses no-model", async () => {
  const rig = await startRig();
  try {
    const script = join(rig.dir, "probe.mts");
    writeFileSync(script, CLIENT_SCRIPT(CLIENT_TS, SESSION));
    const raw = await runChild(TSX, [script, rig.token], agentEnv(rig), rig.dir);
    for (const v of ORIGINALS) assert.ok(!raw.includes(v), `no original in the child's output (${v.slice(0, 8)}…): ${raw}`);
    const out = JSON.parse(raw.trim().split("\n").at(-1)!) as Record<string, { ok: boolean; error?: string; value?: unknown }> & { humanEnv: string | null };
    assert.equal(out.humanEnv, null, "the agent world is not told the human socket");
    for (const op of ["desymbolize", "resolve", "resolveFullShallow", "events", "sessions", "verifyEvents", "subscribe"]) {
      assert.equal(out[op]!.ok, false, `${op} is refused on the data socket: ${JSON.stringify(out[op])}`);
      assert.match(String(out[op]!.error), /human-plane/, `${op} names the human plane`);
    }
    assert.deepEqual(out["deepResolve"], { ok: true, value: null }, "deep resolve (data plane) refuses the no-model row");
  } finally {
    await rig.close();
  }
});

test("(1b) the same child over a RAW NDJSON socket: refused frames only, no original, subscribe ends with one error frame", async () => {
  const rig = await startRig();
  try {
    const raw = await runChild(process.execPath, ["-e", RAW_SCRIPT(SESSION), rig.token], agentEnv(rig), rig.dir);
    for (const v of ORIGINALS) assert.ok(!raw.includes(v), `no original on the raw wire (${v.slice(0, 8)}…): ${raw}`);
    const results = JSON.parse(raw.trim()) as Record<string, string>;
    for (const op of ["desymbolize", "resolve", "events", "sessions", "verifyEvents", "subscribe"]) {
      const frames = results[op]!.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { ok: boolean; error?: string; result?: unknown });
      assert.equal(frames.length, 1, `${op}: exactly one frame: ${results[op]}`);
      assert.equal(frames[0]!.ok, false, `${op}: refused`);
      assert.match(String(frames[0]!.error), /^human-plane:/, `${op}: the human-plane refusal`);
    }
    const deep = JSON.parse(results["resolve:deep"]!.trim()) as { ok: boolean; result: { value: unknown } };
    assert.equal(deep.ok, true);
    assert.equal(deep.result.value, null, "deep resolve refuses the no-model row");
  } finally {
    await rig.close();
  }
});

test("(2) fs-sync over the human socket still writes the ORIGINAL into the HumanView; over the data socket it fails closed", async () => {
  const rig = await startRig();
  const human = makeTempRepo({ "README.md": "hello\n" });
  const dataOnly = makeTempRepo({ "README.md": "hello\n" });
  try {
    // Production wiring: fs-sync's adapter over a client of the HUMAN socket.
    const views = new ViewSync({ workspacePath: human.workspacePath, stateBase: human.stateBase, arbiter: new FsSyncAdapter(rig.human) });
    await views.initialize();
    writeFileSync(join(views.agentViewPath, "config.txt"), `key=${rig.token}\n`);
    const synced = await views.syncToHuman({ toolName: "Write", callId: "oracle-write" });
    assert.ok(synced.includes("config.txt"), `synced: ${synced.join(",")}`);
    const written = readFileSync(join(human.workspacePath, "config.txt"), "utf8");
    assert.ok(ORIGINALS.some((v) => written.includes(v)), `the HumanView gets the original: ${written}`);
    assert.ok(!written.includes("$MDU:"), "no token left in the HumanView");

    // The same sync over the DATA socket: every desymbolize is refused, so the
    // original is never written (fail closed — never raw from an unresolved token).
    const viewsData = new ViewSync({ workspacePath: dataOnly.workspacePath, stateBase: dataOnly.stateBase, arbiter: new FsSyncAdapter(rig.data) });
    await viewsData.initialize();
    writeFileSync(join(viewsData.agentViewPath, "config.txt"), `key=${rig.token}\n`);
    const dataOutcome = await viewsData.syncToHuman({ toolName: "Write", callId: "oracle-write-data" }).then((r) => `synced ${r.join(",")}`, (e: Error) => `rejected: ${e.message}`);
    assert.match(dataOutcome, /^rejected: human-plane:/, "the data socket refuses the sync's desymbolize, and the sync fails");
    const target = join(dataOnly.workspacePath, "config.txt");
    if (existsSync(target)) {
      const got = readFileSync(target, "utf8");
      for (const v of ORIGINALS) assert.ok(!got.includes(v), `no original via the data socket: ${got}`);
    }
  } finally {
    human.cleanup();
    dataOnly.cleanup();
    await rig.close();
  }
});
