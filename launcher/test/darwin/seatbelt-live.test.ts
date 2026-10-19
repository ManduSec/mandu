/**
 * seatbelt-live.test — the macOS whole-agent Seatbelt profile, run for REAL
 * under `sandbox-exec` (confidentiality.md §7.3; seatbelt-profile.ts).
 *
 * Part 1 renders the profile a launch would render — the secret setup's deny
 * set (a mock arbiter registers a scratch canary), Mandu's state, the macOS
 * write-protect list, the network port set and the Unix-socket list — over a
 * scratch HOME, runtime dir and workspace, and runs each attack and each
 * everyday command under it, the attacks on the history caches' stores the
 * profile's `homeSealed` vouches for included (plan 14 §11.2, §11.3), each
 * store and the credential file tried by every other spelling of its path
 * (`otherSpellings`: letter case, the Data-volume firmlink, `..`, the /tmp
 * link, /.vol by inode). Part 2 is the
 * launch e2e: the real CLI (`mandu --target shell`) against a real arbiter, a
 * canary ~/.aws/credentials, the read failing inside while the launch says
 * `read-blocked`, and a cache seal recorded before the launch still standing
 * after it (the arbiter counted the sealed launch confined).
 *
 * darwin only; SKIPs elsewhere and without /usr/bin/sandbox-exec. Scratch
 * dirs live under /tmp (short: a Unix socket path must fit 104 bytes) and
 * every server and child is stopped in `after`.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile, execFileSync, spawn, type ChildProcess } from "node:child_process";
import {
  closeSync, existsSync, lstatSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, readlinkSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync, type Stats,
} from "node:fs";
import { createServer, type Server } from "node:net";
import { lookup } from "node:dns/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { applySecretTwins, ndjsonCall, type SecretArbiter } from "../../src/secret-setup.js";
import { applySeatbelt } from "../../src/seatbelt-setup.js";
import { RUNTIME_REGISTRY } from "../../src/runtime-registry.js";
import { planSeatbeltNet } from "../../src/landlock-net-setup.js";
import { writeProtectList } from "../../src/write-protect.js";
import { unixPolicy } from "../../src/unix-policy.js";
import { emptyMutation } from "../../src/backend/types.js";
import type { LaunchPlan } from "../../src/types.js";
import { axesEnv, stateAxes } from "../axes.js";

stateAxes("secrets"); // the profile is the secrets-mode enactment; part 2's arbiter runs secrets too

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = resolve(HERE, "..", "..");
const REPO = resolve(PKG, "..");
const SANDBOX_EXEC = "/usr/bin/sandbox-exec";
const SKIP = process.platform !== "darwin" ? "darwin only" : !existsSync(SANDBOX_EXEC) ? "no /usr/bin/sandbox-exec" : false;

const CANARY = "aws_secret_access_key = CANARY-SEATBELT-7f3e";
const DB_CANARY = "SYMBOL-DB-CANARY-91c2";
const MANIFEST = `${JSON.stringify({ instanceId: "i1", role: "arbiter", pid: process.pid })}\n`;

let S = "";
let home = "";
let ws = "";
let rt = "";
let sid = "";
/** A second runtime base: the account's default one, where the user's
 *  resident stack lives when a launch has a MANDU_RUNTIME_DIR of its own. */
let rt2 = "";
/** The rendered profile's TEXT: the launch hands it to sandbox-exec inline
 *  (`-p`), and so does every probe here. */
let profileText = "";
let allowedPort = 0;
let deniedPort = 0;
const servers: Server[] = [];
const children: ChildProcess[] = [];

function listen(srv: Server, where: string | number): Promise<number> {
  servers.push(srv);
  return new Promise((res, rej) => {
    srv.once("error", rej);
    if (typeof where === "string") srv.listen(where, () => res(0));
    else srv.listen(where, "127.0.0.1", () => res((srv.address() as { port: number }).port));
  });
}
const hello = (): Server => createServer((c) => { c.end("hello\n"); });

/** Run `sh -c cmd` under the rendered profile, passed inline as a launch
 *  passes it, the event loop kept free (the servers above live in this
 *  process). */
function sandboxed(cmd: string, env: Record<string, string> = {}, profile: string = profileText): Promise<{ code: number; out: string; err: string }> {
  return new Promise((res) => {
    execFile(SANDBOX_EXEC, ["-p", profile, "/bin/sh", "-c", cmd], {
      env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: home, ...env }, cwd: ws, timeout: 30_000,
    }, (e, out, err) => res({ code: e ? (typeof (e as { code?: unknown }).code === "number" ? (e as { code: number }).code : 1) : 0, out: String(out), err: String(err) }));
  });
}
const EPERM = /Operation not permitted|EPERM/;

/** The other spellings of an existing path under the scratch dir that name
 *  the same file, which a path rule must hold for (SBPL matches the path the
 *  kernel resolves): other letter cases (the default APFS volume ignores
 *  case; only where this one does), the `/System/Volumes/Data` firmlink
 *  spelling (where it exists), `..` components (absolute and relative to
 *  the workspace, the sandboxed cwd), the `/tmp` link spelling, and
 *  `/.vol/<device>/<inode>` (volfs, open by inode). */
function otherSpellings(p: string): string[] {
  const out: string[] = [];
  const rel = relative(S, p);
  const parts = rel.split("/");
  if (existsSync(S.toUpperCase())) {
    out.push(join(S, ...parts.slice(0, -1), parts.at(-1)!.toUpperCase()));
    out.push(join(S, ...parts.map((c, i) => (i === parts.length - 2 ? c.toUpperCase() : c))));
    out.push(`${S.toUpperCase()}/${rel}`);
  }
  if (existsSync(`/System/Volumes/Data${S}`)) out.push(`/System/Volumes/Data${p}`);
  out.push(`${ws}/../${rel}`, `${dirname(p)}/../${parts.at(-2)}/${parts.at(-1)}`, relative(ws, p));
  if (p.startsWith("/private/tmp/")) out.push(p.slice("/private".length));
  const st = statSync(p);
  out.push(`/.vol/${st.dev}/${st.ino}`);
  return out;
}
const NODE = process.execPath;
const nodeConnect = (target: string): string =>
  `${NODE} -e 'const s=require("net").connect(${target});s.on("data",d=>{process.stdout.write("OK "+d);s.destroy()});s.on("error",e=>{console.log("ERR "+e.code);})'`;

before(async () => {
  if (SKIP) return;
  S = realpathSync(mkdtempSync("/tmp/mdu-sb."));
  home = join(S, "h");
  ws = join(S, "ws");
  rt = join(S, "rt");
  sid = join(S, "sid");
  rt2 = join(S, "rt2");
  for (const d of [
    join(home, ".aws"), join(home, ".mandu"), join(home, "Library"), join(home, ".docker", "run"), ws, join(rt, "instances", "i1", "logs"), join(rt, "human"),
    join(rt, "dashboards"), join(rt, "logs"), sid, join(S, "else"), join(rt2, "instances", "r1"), join(rt2, "human"),
  ]) {
    mkdirSync(d, { recursive: true });
  }
  writeFileSync(join(home, ".aws", "credentials"), `[default]\n${CANARY}\n`);
  writeFileSync(join(home, ".mandu", "mandu.db"), `${DB_CANARY}\n`);
  writeFileSync(join(home, ".zshrc"), "# rc\n");
  writeFileSync(join(rt, "instances", "i1", "manifest.json"), MANIFEST);
  writeFileSync(join(rt, "dashboard.log"), "[dashboard] up\n");
  symlinkSync("instances/i1", join(rt, "current"));
  symlinkSync("instances/r1", join(rt2, "current"));
  await listen(hello(), join(rt, "instances", "i1", "arbiter.sock"));
  await listen(hello(), join(rt, "human", "i1.sock"));
  // The account's default base's human plane (the resident stack's), which
  // a launch with its own MANDU_RUNTIME_DIR must not reach either.
  await listen(hello(), join(rt2, "human", "r1.sock"));
  await listen(hello(), join(S, "else", "b.sock"));
  await listen(hello(), join(home, ".docker", "run", "docker.sock"));
  allowedPort = await listen(hello(), 0);
  deniedPort = await listen(hello(), 0);

  // The profile a secrets-mode launch in `ws` would render (run.ts wiring).
  const arbiterSock = join(rt, "current", "arbiter.sock");
  const env = { HOME: home, PATH: process.env["PATH"] ?? "" };
  const plan = {
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "test", arbiterSock, arbiterSockMode: "pinned" as const,
    arbiterRuntimeBase: rt, eventDir: join(sid, "events"), cwd: ws, humanCwd: ws, noContextProxy: true, fsSync: false,
    proxy: { host: "127.0.0.1", port: allowedPort }, openaiProxy: { host: "127.0.0.1", port: 0 },
    openaiProviderName: "mandu", noProxyExtra: [], requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: true, writeMcp: false, bestEffort: false, replyFilter: false, confidentiality: true,
    effectiveAxes: { integrity: false, confidentiality: true }, landlockNetStrict: true,
  } as unknown as LaunchPlan;
  const arbiter: SecretArbiter = {
    discoverSecrets: async () => [{ path: join(home, ".aws", "credentials") }],
    registerSecret: async () => ({ symbol: "$MDU:nomodel_Read[5eat]", reason: "registered" }),
  };
  const mut = emptyMutation();
  const secrets = await applySecretTwins(plan, sid, mut, {
    arbiter, commandExists: (c) => c === SANDBOX_EXEC, usernsOk: () => false, platform: "darwin", log: () => {}, home, workspaceRoots: [ws],
  });
  assert.equal(secrets.posture, "read-blocked");
  const r = applySeatbelt({
    plan, env, scopeRunDir: sid, secrets: secrets.seatbelt, sealState: true,
    writeProtect: writeProtectList(env, ws, undefined, arbiterSock, undefined, () => {}, [], "darwin"),
    // Strict: only the loopback model-proxy port (the listener above).
    net: planSeatbeltNet(plan),
    unix: unixPolicy(env, { platform: "darwin", arbiterSock, scopeRunDir: sid, runtimeBase: rt, cwd: ws, humanDirs: [join(rt, "human")] }),
    humanDirs: [join(rt, "human")],
    runtimeRegistry: true,
    registryBases: [rt2],
    available: true,
  }, mut, { log: () => {} });
  assert.ok(r, "a profile was rendered");
  assert.ok(r!.components.includes("human plane"), r!.components.join(", "));
  assert.equal(r!.humanPlaneWalled, true, "the applied profile claims the human-directory wall tested against the live sockets below");
  // Plan 14 §11.2: this profile is what the launch record's homeSealed
  // claim rests on; test 2b below attacks the stores it vouches for.
  assert.equal(r!.homeSealed, true, r!.components.join(", "));
  assert.ok(r!.components.includes("runtime registry"), r!.components.join(", "));
  profileText = r!.profile;
  // By absolute path: a `sandbox-exec` on the agent's PATH never stands in
  // for it (seatbelt-profile.ts SANDBOX_EXEC). And the TEXT, never a path
  // read back later (review 2026-09-30); the copy is for reading only.
  assert.deepEqual(mut.launchPrefix, [SANDBOX_EXEC, "-p", profileText]);
  assert.equal(readFileSync(r!.profilePath, "utf8"), profileText);
});

after(async () => {
  for (const s of servers) s.close();
  for (const c of children) { try { c.kill("SIGKILL"); } catch { /* gone */ } }
  // A child's last compile-cache write can race the removal: retry.
  await new Promise((r) => setTimeout(r, 300));
  if (S) rmSync(S, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
});

test("1. the credential file: read, rename (file and every folder above), link, clone, truncate, replace — each refused", { skip: SKIP }, async () => {
  const cred = join(home, ".aws", "credentials");
  const r = await sandboxed(`cat ${cred}`);
  assert.notEqual(r.code, 0);
  assert.match(r.err, EPERM);
  assert.ok(!r.out.includes("CANARY"), "the raw bytes never appear");
  for (const cmd of [
    `mv ${cred} ${join(home, "moved")}`,
    `mv ${join(home, ".aws")} ${join(home, ".a2")}`,
    `mv ${home} ${join(S, "h2")}`,
    `ln ${cred} ${join(ws, "hl")}`,
    `cp -c ${cred} ${join(ws, "cl")}`,
    `truncate -s 0 ${cred}`,
    `echo x > ${join(ws, "o")} && mv ${join(ws, "o")} ${cred}`,
    `rm ${cred}`,
  ]) {
    const x = await sandboxed(cmd);
    assert.notEqual(x.code, 0, cmd);
    assert.match(x.err, EPERM, cmd);
  }
  // A symlink the agent makes to it does not help either (the check is on the file).
  const sl = await sandboxed(`ln -s ${cred} ${join(ws, "sl")} && cat ${join(ws, "sl")}`);
  assert.match(sl.err, EPERM);
  // Nor does any other spelling of it: another case, the Data-volume
  // firmlink, `..`, the /tmp link, its inode through /.vol.
  const spellings = otherSpellings(cred);
  assert.ok(spellings.length >= 5, spellings.join(" "));
  for (const v of spellings) {
    const rd = await sandboxed(`cat '${v}'`);
    assert.notEqual(rd.code, 0, v);
    assert.match(rd.err, EPERM, `${v}: ${rd.err}`);
    assert.ok(!rd.out.includes("CANARY"), v);
    const wr = await sandboxed(`echo x >> '${v}'`);
    assert.match(wr.err, EPERM, `${v}: ${wr.err}`);
  }
  if (existsSync(S.toUpperCase())) {
    const mvCase = await sandboxed(`mv ${join(home, ".AWS")} ${join(home, ".a3")}`);
    assert.match(mvCase.err, EPERM, `the folder above it, in another case: ${mvCase.err}`);
  }
  assert.ok(readFileSync(cred, "utf8").includes(CANARY), "the file is untouched");
  assert.ok(!readFileSync(cred, "utf8").includes("\nx\n"), "no spelling wrote to it");
  assert.ok(!existsSync(join(home, "moved")) && !existsSync(join(home, ".a2")) && !existsSync(join(S, "h2")));
  // The folder stays usable: a sibling can still be written and renamed.
  const sib = await sandboxed(`echo y > ${join(home, ".aws", "config")} && mv ${join(home, ".aws", "config")} ${join(home, ".aws", "config2")} && echo done`);
  assert.equal(sib.code, 0, sib.err);
});

test("2. Mandu's own state: the symbol DB is unreadable", { skip: SKIP }, async () => {
  const r = await sandboxed(`cat ${join(home, ".mandu", "mandu.db")}`);
  assert.match(r.err, EPERM);
  assert.ok(!r.out.includes(DB_CANARY));
  const ls = await sandboxed(`ls ${join(home, ".mandu")}`);
  assert.match(ls.err, EPERM);
});

test("2b. the history caches' stores (plan 14 §11.2): nothing under the Mandu home can be read, written, created, replaced, linked or renamed, by any path", { skip: SKIP }, async () => {
  // What the seals vouch for: the sanitized packs, the history walks, the
  // history-scan cache and mandu.db. A launch claims homeSealed only because
  // the agent can change none of them (seatbelt-setup.ts profileSealsHome).
  const mh = join(home, ".mandu");
  const pack = join(mh, "cache", "object-twins", "k", "pack-1.pack");
  const walk = join(mh, "state", "object-walks", "w.json");
  const scan = join(mh, "state", "object-walks", "history-scan", "s.json");
  const db = join(mh, "state", "mandu.db");
  for (const [p, body] of [[pack, "PACK-BYTES"], [walk, "{}"], [scan, "{}"], [db, "DB"]] as const) {
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, body);
  }
  writeFileSync(join(ws, "planted"), "PLANTED\n");
  for (const cmd of [
    `cat ${pack}`, `cat ${walk}`, `ls ${join(mh, "state", "object-walks")}`,
    `echo x > ${pack}`, `echo '{}' >> ${walk}`, `truncate -s 0 ${db}`,
    `echo '{}' > ${join(mh, "state", "object-walks", "history-scan", "new.json")}`,
    `mkdir -p ${join(mh, "cache", "object-twins", "planted")}`,
    `cp ${join(ws, "planted")} ${pack}`,
    `mv ${join(ws, "planted")} ${scan}`,
    `ln ${db} ${join(ws, "db-link")}`,
    `rm ${walk}`,
    `mv ${mh} ${join(home, ".mandu-moved")}`,
    `mv ${join(mh, "state")} ${join(mh, "state2")}`,
  ]) {
    const x = await sandboxed(cmd);
    assert.notEqual(x.code, 0, cmd);
    assert.match(x.err, EPERM, `${cmd}: ${x.err}`);
  }
  // A symlink the agent makes into the home does not reach it either (the
  // rules match the path the kernel resolves).
  const via = await sandboxed(`ln -s ${join(mh, "state")} ${join(ws, "st")} && echo x > ${join(ws, "st", "object-walks", "w.json")}`);
  assert.match(via.err, EPERM, via.err);
  const viaRead = await sandboxed(`cat ${join(ws, "st", "object-walks", "w.json")}`);
  assert.match(viaRead.err, EPERM, viaRead.err);
  // Every other spelling of every store: another case (`.MANDU`, `Cache`,
  // `STATE`, the file name), the Data-volume firmlink, `..` components, the
  // /tmp link, the inode through /.vol. Read, append, and create beside it.
  const ci = existsSync(S.toUpperCase());
  for (const [p, body] of [[pack, "PACK-BYTES"], [walk, "{}"], [scan, "{}"], [db, "DB"]] as const) {
    const vs = otherSpellings(p);
    if (ci) vs.push(p.replace("/.mandu/", "/.MANDU/"), p.replace("/.mandu/cache/", "/.mandu/Cache/").replace("/.mandu/state/", "/.mandu/State/"));
    for (const v of vs) {
      const rd = await sandboxed(`cat '${v}'`);
      assert.notEqual(rd.code, 0, v);
      assert.match(rd.err, EPERM, `${v}: ${rd.err}`);
      assert.ok(!rd.out.includes(body === "{}" ? "{" : body), v);
      const wr = await sandboxed(`echo x >> '${v}'`);
      assert.match(wr.err, EPERM, `${v}: ${wr.err}`);
      if (!v.startsWith("/.vol/")) {
        const mk = await sandboxed(`echo '{}' > '${dirname(v)}/planted-by-spelling.json'`);
        assert.match(mk.err, EPERM, `${dirname(v)}: ${mk.err}`);
      }
    }
    assert.equal(readFileSync(p, "utf8"), body, `${p}: no spelling changed it`);
    assert.ok(!existsSync(join(dirname(p), "planted-by-spelling.json")), dirname(p));
  }
  if (ci) {
    for (const cmd of [`mv ${join(home, ".MANDU")} ${join(home, ".m2")}`, `mv ${join(S, "H")} ${join(S, "h3")}`, `mv ${join(mh, "STATE")} ${join(mh, "s3")}`]) {
      const x = await sandboxed(cmd);
      assert.match(x.err, EPERM, `${cmd}: ${x.err}`);
    }
  }
  assert.equal(readFileSync(pack, "utf8"), "PACK-BYTES");
  assert.equal(readFileSync(walk, "utf8"), "{}");
  assert.equal(readFileSync(scan, "utf8"), "{}");
  assert.equal(readFileSync(db, "utf8"), "DB");
  assert.ok(!existsSync(join(mh, "state", "object-walks", "history-scan", "new.json")) && !existsSync(join(mh, "cache", "object-twins", "planted")));
  assert.ok(existsSync(join(ws, "planted")), "the planted file never moved in");
  assert.ok(!existsSync(join(home, ".mandu-moved")) && !existsSync(join(ws, "db-link")));
});

test("3. write-protect: a shell startup file and a launchd agent cannot be written (refused on macOS)", { skip: SKIP }, async () => {
  const rc = await sandboxed(`echo 'curl evil' >> ${join(home, ".zshrc")}`);
  assert.match(rc.err, EPERM);
  const la = await sandboxed(`mkdir -p ${join(home, "Library", "LaunchAgents")} && echo '<plist/>' > ${join(home, "Library", "LaunchAgents", "x.plist")}`);
  assert.notEqual(la.code, 0);
  assert.match(la.err, EPERM);
  assert.ok(!existsSync(join(home, "Library", "LaunchAgents", "x.plist")));
  assert.equal(readFileSync(join(home, ".zshrc"), "utf8"), "# rc\n");
  // The xcrun shim's cache (it picks the git /usr/bin/git runs, for the user
  // and for Mandu): refused. Probed with `touch` only, which could change
  // nothing but a timestamp if the rule failed; the real cache is never
  // written by this test.
  const tmpT = execFileSync("getconf", ["DARWIN_USER_TEMP_DIR"], { encoding: "utf8" }).trim();
  const xcrunDb = join(tmpT, "xcrun_db");
  if (existsSync(xcrunDb)) {
    const x = await sandboxed(`touch ${xcrunDb}`);
    assert.match(x.err, EPERM, `the xcrun cache is write-protected: ${x.err}`);
  }
});

test("4. network: TCP to an allowed loopback port works, to any other port it is refused; bind refused", { skip: SKIP }, async () => {
  const ok = await sandboxed(nodeConnect(`${allowedPort},"127.0.0.1"`));
  assert.match(ok.out, /^OK hello/, `${ok.out}${ok.err}\nport ${allowedPort}; the profile:\n${profileText}`);
  const no = await sandboxed(nodeConnect(`${deniedPort},"127.0.0.1"`));
  assert.match(no.out, /ERR EPERM/, no.out + no.err);
  const bind = await sandboxed(`${NODE} -e 'require("net").createServer().listen(0,"127.0.0.1",()=>console.log("LISTENING")).on("error",e=>console.log("ERR "+e.code))'`);
  assert.match(bind.out, /ERR EPERM/, bind.out + bind.err);
});

test("4. network, across ports: the rendered order never misfires on an allowed port and never admits another (a Seatbelt quirk)", { skip: SKIP }, async () => {
  // With the TCP rules BEFORE the Unix-socket rules, a bare unix-socket deny
  // misfired on ~6% of allowed ports (seatbelt-profile.ts). The rendered
  // order must hold for any port: a port nobody listens on answers
  // ECONNREFUSED when the profile allows it and EPERM when it denies it.
  const dir = join(S, "ports");
  mkdirSync(dir, { recursive: true });
  const env = { HOME: home };
  const unix = unixPolicy(env, { platform: "darwin", arbiterSock: join(rt, "current", "arbiter.sock"), scopeRunDir: sid, runtimeBase: rt, cwd: ws });
  const misfires: string[] = [];
  for (let i = 0; i < 24; i++) {
    const port = 20000 + Math.floor(Math.random() * 40000);
    const r = applySeatbelt({
      plan: { eventDir: join(sid, "events"), arbiterSock: join(rt, "current", "arbiter.sock"), arbiterRuntimeBase: rt, humanCwd: ws, cwd: ws },
      env, scopeRunDir: join(dir, String(i)), sealState: false, writeProtect: null, runtimeRegistry: true,
      net: { connect: [{ host: "localhost", port }], bind: [] }, unix, available: true,
    }, emptyMutation(), { log: () => {} })!;
    const probe = (p: number): Promise<string> => new Promise((res) => {
      execFile(SANDBOX_EXEC, ["-p", r.profile, NODE, "-e", `require("net").connect(${p},"127.0.0.1").on("connect",()=>{console.log("OPEN");process.exit(0)}).on("error",e=>{console.log(e.code);process.exit(0)})`], { timeout: 20_000 }, (_e, out) => res(String(out).trim()));
    });
    const allowed = await probe(port);
    if (allowed === "EPERM") misfires.push(`allowed ${port} denied`);
    const other = await probe(port === 59999 ? 59998 : port + 1);
    if (other !== "EPERM") misfires.push(`other ${port + 1} → ${other}`);
  }
  assert.deepEqual(misfires, []);
});

test("5. Unix sockets: the arbiter under the runtime dir works; a socket elsewhere and docker are refused", { skip: SKIP }, async () => {
  const arb = await sandboxed(nodeConnect(JSON.stringify(join(rt, "current", "arbiter.sock"))));
  assert.match(arb.out, /^OK hello/, arb.out + arb.err);
  const elsewhere = await sandboxed(nodeConnect(JSON.stringify(join(S, "else", "b.sock"))));
  assert.match(elsewhere.out, /ERR EPERM/, elsewhere.out + elsewhere.err);
  const docker = await sandboxed(nodeConnect(JSON.stringify(join(home, ".docker", "run", "docker.sock"))));
  assert.match(docker.out, /ERR EPERM/, docker.out + docker.err);
  // A server the agent starts in its workspace is its own to reach.
  const own = await sandboxed(`${NODE} -e 'const n=require("net");const p=${JSON.stringify(join(ws, "own.sock"))};n.createServer(c=>c.end("mine")).listen(p,()=>{n.connect(p).on("data",d=>{console.log("OK "+d);process.exit(0)}).on("error",e=>{console.log("ERR "+e.code);process.exit(0)})})'`);
  assert.match(own.out, /OK mine/, own.out + own.err);
});

test("the human plane: no connect (direct, a symlink, a directory symlink), no hard link, no rename of it or of the runtime dir; the data socket still works", { skip: SKIP }, async () => {
  const human = join(rt, "human", "i1.sock");
  const direct = await sandboxed(nodeConnect(JSON.stringify(human)));
  assert.match(direct.out, /ERR EPERM/, direct.out + direct.err);
  const viaLink = await sandboxed(`ln -s ${human} ${join(ws, "h.sock")} && ${nodeConnect(JSON.stringify(join(ws, "h.sock")))}`);
  assert.match(viaLink.out, /ERR EPERM/, viaLink.out + viaLink.err);
  const viaDir = await sandboxed(`ln -s ${join(rt, "human")} ${join(ws, "hdir")} && ${nodeConnect(JSON.stringify(join(ws, "hdir", "i1.sock")))}`);
  assert.match(viaDir.out, /ERR EPERM/, viaDir.out + viaDir.err);
  const hard = await sandboxed(`ln ${human} ${join(ws, "hard.sock")}; echo rc=$?`);
  assert.match(hard.err + hard.out, EPERM, "no hard link to the socket");
  // Renaming the runtime dir would put the socket at a path no rule names.
  for (const [from, to] of [[join(rt, "human"), join(rt, "moved")], [rt, join(S, "rt-moved")]] as const) {
    const mv = await sandboxed(`mv ${from} ${to}; echo rc=$?`);
    assert.match(mv.err, EPERM, `${from}: ${mv.out} ${mv.err}`);
    assert.ok(existsSync(from) && !existsSync(to), `${from} still in place`);
  }
  const ls = await sandboxed(`ls ${join(rt, "human")}`);
  assert.match(ls.err, EPERM, "its listing is unreadable too");
  const arb = await sandboxed(nodeConnect(JSON.stringify(join(rt, "current", "arbiter.sock"))));
  assert.match(arb.out, /^OK hello/, "the data socket beside it still answers: " + arb.out + arb.err);
  // The same wall under the account's default base (registryBases): the
  // resident stack's human/ is walled off from a launch with its own base.
  const other = join(rt2, "human", "r1.sock");
  const c2 = await sandboxed(nodeConnect(JSON.stringify(other)));
  assert.match(c2.out, /ERR EPERM/, `${other}: ${c2.out}${c2.err}`);
  for (const cmd of [`rm ${other}`, `mkdir ${join(rt2, "human", "x")}`, `mv ${join(rt2, "human")} ${join(rt2, "human.moved")}`]) {
    const x = await sandboxed(cmd);
    assert.match(x.err, EPERM, `${cmd}: ${x.err}`);
  }
  assert.ok(existsSync(other), "the resident stack's human socket is untouched");
});

/** What the runtime registry entries of `base` hold (runtime-registry.ts): each
 *  entry's kind (a link names its target, a dir its listing, a file its
 *  bytes), and every name the registry's prefixes cover. Only these: a probe
 *  elsewhere in the base (a nested launch's scope dir) is not the registry's. */
function registrySnapshot(base: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const n of [...RUNTIME_REGISTRY.dirs, ...RUNTIME_REGISTRY.names]) {
    const p = join(base, n);
    let st: Stats;
    try { st = lstatSync(p); } catch { out[n] = "absent"; continue; }
    out[n] = st.isSymbolicLink() ? `link -> ${readlinkSync(p)}` : st.isDirectory() ? `dir [${readdirSync(p).sort().join(",")}]` : `file ${readFileSync(p, "utf8")}`;
  }
  out["<prefixed>"] = readdirSync(base).filter((n) => RUNTIME_REGISTRY.prefixes.some((x) => n.startsWith(x))).sort().join(",");
  return out;
}

test("the runtime registries: nothing planted under instances/ (a link at the manifest's temp name, a pre-made instance dir, a forged manifest, a socket), no `current` swap, no registry or log entry, no link at `mandu dashboard`'s log or port files; the same under the account's default base; the arbiter still answers; the session's dir, the bases and the names beside the entries stay writable", { skip: SKIP }, async () => {
  const inst = join(rt, "instances", "i1");
  const victim = join(S, "else", "victim.txt");
  writeFileSync(victim, "untouched\n");
  const before = { rt: registrySnapshot(rt), rt2: registrySnapshot(rt2), inst: readdirSync(inst).sort() };
  // The /tmp spelling of the same runtime dir: the profile names both.
  const rtTmp = rt.startsWith("/private/tmp/") ? rt.slice("/private".length) : rt;
  const attempts = [
    `ln -s ${victim} ${join(inst, ".manifest.json.99999.tmp")}`,
    `mkdir ${join(rt, "instances", "20260930-0000-abc1234-p99999")}`,
    `mkdir ${join(rtTmp, "instances", "20260930-0001-abc1234-p99999")}`,
    `echo '{"pid":1073741824}' > ${join(ws, "m.json")} && mv ${join(ws, "m.json")} ${join(inst, "manifest.json")}`,
    `echo x > ${join(inst, "manifest.json")}`,
    `rm ${join(inst, "manifest.json")}`,
    `ln -s ${victim} ${join(inst, "logs", "x.log")}`,
    `mv ${join(rt, "instances")} ${join(rt, "instances.old")}`,
    `rm ${join(rt, "current")}`,
    `ln -sfn ${ws} ${join(rt, "current")}`,
    `ln -s instances/evil ${join(rt, ".current.tmp-99999")}`,
    `echo '{"pid":1}' > ${join(rt, "dashboards", "x.json")}`,
    `ln -s ${victim} ${join(rt, "dashboards", "y.json.tmp")}`,
    `mkdir ${join(rt, "vm-guests")}`,
    `ln -s ${victim} ${join(rt, "logs", "arbiter-autostart.log")}`,
    `mkdir ${join(rt, "test")}`,
    // `mandu dashboard`'s own files at the top of the base (review
    // 2026-09-30): its log (appended to), and the port file's temp name the
    // dashboard writes (the CLI's pid: every name up to 99999 can be planted).
    `rm ${join(rt, "dashboard.log")}`,
    `ln -sf ${victim} ${join(rt, "dashboard.log")}`,
    `echo x >> ${join(rt, "dashboard.log")}`,
    `ln -s ${victim} ${join(rt, "dashboard-99999.port.tmp")}`,
    `ln -s ${victim} ${join(rtTmp, "dashboard-99998.port.tmp")}`,
    `echo 4242 > ${join(rt, "dashboard-99999.port")}`,
    // The account's default base, where the user's resident stack lives.
    `mkdir ${join(rt2, "instances", "20260930-0002-abc1234-p99999")}`,
    `ln -sfn ${ws} ${join(rt2, "current")}`,
    `mkdir ${join(rt2, "dashboards")}`,
    `ln -s ${victim} ${join(rt2, "dashboard.log")}`,
    `mv ${join(rt2, "instances")} ${join(rt2, "instances.old")}`,
    `mv ${rt2} ${join(S, "rt2-moved")}`,
  ];
  for (const cmd of attempts) {
    const x = await sandboxed(cmd);
    assert.notEqual(x.code, 0, cmd);
    assert.match(x.err, EPERM, `${cmd}: ${x.err}`);
  }
  // No impostor socket can be bound there, nor at the legacy fixed path.
  const bindAt = (p: string): string =>
    `${NODE} -e 'require("net").createServer().listen(${JSON.stringify(p)},()=>{console.log("BOUND");process.exit(0)}).on("error",e=>console.log("ERR "+e.code))'`;
  for (const p of [join(inst, "evil.sock"), join(rt, "arbiter.sock"), join(rt2, "instances", "r1", "evil.sock")]) {
    const b = await sandboxed(bindAt(p));
    assert.match(b.out, /ERR EPERM/, `${p}: ${b.out}${b.err}`);
  }
  // Every registry entry is as the arbiter and the dashboard left it.
  assert.equal(readFileSync(join(inst, "manifest.json"), "utf8"), MANIFEST);
  assert.equal(readlinkSync(join(rt, "current")), "instances/i1");
  assert.equal(readFileSync(victim, "utf8"), "untouched\n");
  assert.deepEqual({ rt: registrySnapshot(rt), rt2: registrySnapshot(rt2), inst: readdirSync(inst).sort() }, before);
  // The data socket answers by its path and through `current` (connect(2) is
  // not a write), and the registry stays readable (`mandu status` inside).
  for (const p of [join(inst, "arbiter.sock"), join(rt, "current", "arbiter.sock")]) {
    const c = await sandboxed(nodeConnect(JSON.stringify(p)));
    assert.match(c.out, /^OK hello/, `${p}: ${c.out}${c.err}`);
  }
  const cat = await sandboxed(`cat ${join(rt, "current", "manifest.json")}`);
  assert.equal(cat.out, MANIFEST, cat.err);
  // The session's own dir and a new dir in either base (a nested launch's
  // scope) stay writable, and so do the names beside the entries: `(prefix
  // "P")` is a name prefix, so `.current.tmpX` (no dash) and `dashboardX` are
  // outside `.current.tmp-` and `dashboard-` (seatbelt-profile.ts, SBPL facts).
  const own = await sandboxed(
    `mkdir -p ${join(sid, "x")} && echo ok > ${join(sid, "x", "f")} && mkdir ${join(rt, "1-2")} && echo ok > ${join(rt, "1-2", "f")} && ` +
      `mkdir ${join(rt2, "1-2")} && ln -s x ${join(rt, ".current.tmpX")} && echo ok > ${join(rt, "dashboardX")} && echo done`,
  );
  assert.equal(own.out.trim(), "done", own.err);
  assert.equal(readlinkSync(join(rt, ".current.tmpX")), "x");
  const tidy = await sandboxed(`rm ${join(rt, ".current.tmpX")} ${join(rt, "dashboardX")} && echo done`);
  assert.equal(tidy.out.trim(), "done", tidy.err);
  assert.ok(!existsSync(join(rt, "dashboardX")) && !readdirSync(rt).includes(".current.tmpX"));
  for (const d of [join(rt, "1-2"), join(rt2, "1-2")]) rmSync(d, { recursive: true, force: true });
});

test("5. Unix sockets, a launch from HOME: every socket under HOME is admitted except the refused control sockets (WezTerm, iTerm2, Emacs, docker)", { skip: SKIP }, async () => {
  // Review 2026-09-29 (seatbelt-7): the workspace allow is a subpath, so a
  // launch from HOME reaches every socket under it; the refusal list is what
  // keeps a terminal's or editor's control socket (it types into a window or
  // evaluates code outside the profile) out of reach.
  const refused = [
    join(home, ".local", "share", "wezterm", "gui-sock-1"),
    join(home, "Library", "Application Support", "iTerm2", "private", "socket"),
    join(home, ".emacs.d", "server", "server"),
    join(home, ".docker", "run", "docker.sock"),
  ];
  const admitted = join(home, "proj", "app.sock");
  for (const p of [...refused, admitted]) {
    mkdirSync(dirname(p), { recursive: true });
    if (!existsSync(p)) await listen(hello(), p);
  }
  const env = { HOME: home, PATH: process.env["PATH"] ?? "" };
  const arbiterSock = join(rt, "current", "arbiter.sock");
  const homeSid = join(S, "sid-home");
  const r = applySeatbelt({
    plan: { eventDir: join(homeSid, "events"), arbiterSock, arbiterRuntimeBase: rt, humanCwd: home, cwd: home },
    env, scopeRunDir: homeSid, sealState: false, writeProtect: null, net: null, runtimeRegistry: true,
    unix: unixPolicy(env, { platform: "darwin", arbiterSock, scopeRunDir: homeSid, runtimeBase: rt, cwd: home }),
    available: true,
  }, emptyMutation(), { log: () => {} });
  assert.ok(r, "a profile was rendered");
  const ok = await sandboxed(nodeConnect(JSON.stringify(admitted)), {}, r!.profile);
  assert.match(ok.out, /^OK hello/, `an ordinary socket under HOME is admitted: ${ok.out}${ok.err}`);
  for (const p of refused) {
    const x = await sandboxed(nodeConnect(JSON.stringify(p)), {}, r!.profile);
    assert.match(x.out, /ERR EPERM/, `${p}: ${x.out}${x.err}`);
  }
});

test("the inline wrap (-p) applies what -f applies, with the same size limit (a compiled profile of at most 64 KiB)", { skip: SKIP }, async () => {
  // seatbelt-profile.ts, SBPL facts: a launch passes the profile's text, so
  // nothing is read back from the runtime dir (review 2026-09-30).
  const target = join(S, "else", "limit.txt");
  writeFileSync(target, "x\n");
  const file = join(S, "else", "p.sb");
  const run = (args: string[]): Promise<{ out: string; err: string }> => new Promise((res) => {
    execFile(SANDBOX_EXEC, [...args, "/bin/cat", target], { timeout: 20_000 }, (_e, out, err) => res({ out: String(out), err: String(err) }));
  });
  const small = `(version 1)\n(allow default)\n(deny file-read* (literal ${JSON.stringify(target)}))\n`;
  writeFileSync(file, small);
  for (const args of [["-p", small], ["-f", file]]) {
    const r = await run(args);
    assert.match(r.err, EPERM, `${args[0]}: ${r.out}${r.err}`);
  }
  const lines = Array.from({ length: 6000 }, (_, i) => `  (literal "/Users/nobody/a/long/path/to/credential/file/number/${String(i).padStart(5, "0")}/creds.json")`);
  const big = `(version 1)\n(allow default)\n(deny file-read*\n${lines.join("\n")})\n`;
  writeFileSync(file, big);
  for (const args of [["-p", big], ["-f", file]]) {
    const r = await run(args);
    assert.match(r.err, /exceeds maximum \(65535\)/, `${args[0]}: ${r.out}${r.err}`);
  }
});

test("6. host services: open and osascript cannot run", { skip: SKIP }, async () => {
  for (const cmd of ["/usr/bin/open -R /nonexistent-mandu", "/usr/bin/osascript -e 'return 1'", "/bin/launchctl version"]) {
    const r = await sandboxed(cmd);
    assert.notEqual(r.code, 0, cmd);
    assert.match(r.err, EPERM, cmd);
  }
});

test("everyday work still works: a workspace write, node, git, a name lookup", { skip: SKIP }, async () => {
  const w = await sandboxed(`echo hi > ${join(ws, "f")} && cat ${join(ws, "f")}`);
  assert.equal(w.out.trim(), "hi", w.err);
  const n = await sandboxed(`${NODE} -e 'console.log(6*7)'`);
  assert.equal(n.out.trim(), "42", n.err);
  const g = await sandboxed("git --version");
  assert.equal(g.code, 0, g.err);
  const local = await sandboxed(`${NODE} -e 'require("dns").lookup("localhost",(e,a)=>console.log(e?"ERR "+e.code:"ADDR "+a))'`);
  assert.match(local.out, /^ADDR /, local.out + local.err);
  // A real name only when this host resolves it outside (offline hosts skip).
  let online = false;
  try { await lookup("example.com"); online = true; } catch { /* offline */ }
  if (online) {
    const remote = await sandboxed(`${NODE} -e 'require("dns").lookup("example.com",(e,a)=>console.log(e?"ERR "+e.code:"ADDR "+a))'`);
    assert.match(remote.out, /^ADDR /, `name lookups go through mDNSResponder, which stays reachable: ${remote.out}${remote.err}`);
  }
});

// ── Part 2: the launch e2e ─────────────────────────────────────────────────

function waitFor(p: string, ms: number): Promise<void> {
  const start = Date.now();
  return new Promise((res, rej) => {
    const tick = (): void => {
      if (existsSync(p)) return res();
      if (Date.now() - start > ms) return rej(new Error(`${p} did not appear`));
      setTimeout(tick, 100);
    };
    tick();
  });
}

test("launch e2e: `mandu --target shell` in secrets mode — the canary read fails inside, the launch says read-blocked, the arbiter stays reachable, a PATH-planted sandbox-exec never runs", { skip: SKIP, timeout: 180_000 }, async () => {
  const E = join(S, "e2e");
  const h2 = join(E, "h");
  const w2 = join(E, "ws");
  for (const d of [join(h2, ".aws"), w2, join(E, "tmp"), join(E, "events"), join(E, "rt"), join(h2, ".local", "bin")]) mkdirSync(d, { recursive: true });
  writeFileSync(join(h2, ".aws", "credentials"), `[default]\n${CANARY}\n`);
  // What an agent could plant in one session for the next (review
  // 2026-09-29, docs-tests-11): a `sandbox-exec` and a `script` first on
  // PATH that run the rest WITHOUT the profile. The launch names both by
  // absolute path, so neither runs and the read stays blocked.
  const planted = join(E, "planted-ran");
  for (const name of ["sandbox-exec", "script"]) {
    writeFileSync(join(h2, ".local", "bin", name), `#!/bin/sh\necho ${name} >> '${planted}'\ncase "$1" in -f|-p) shift 2;; esac\nexec "$@"\n`, { mode: 0o755 });
  }
  writeFileSync(join(h2, ".gitconfig"), "[user]\n\tname = Mandu Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = master\n");
  const sock = join(E, "a.sock");
  const base: Record<string, string> = {
    PATH: `${join(h2, ".local", "bin")}:${process.env["PATH"] ?? "/usr/bin:/bin"}`, HOME: h2, TMPDIR: join(E, "tmp"), MANDU_RUNTIME_DIR: join(E, "rt"),
    MANDU_ARBITER_SOCK: sock, MANDU_HOME: join(E, "mandu-home"),
    MANDU_CONFIG: "/dev/null", MANDU_POLICY_FILE: "/dev/null/mandu-test-no-policy.yaml", ...axesEnv("secrets"),
  };
  const logFd = openSync(join(E, "arbiter.log"), "a");
  const arbiter = spawn(join(REPO, "arbiter", "node_modules", ".bin", "tsx"), [join(REPO, "arbiter", "ipc", "server-main.ts"), sock], {
    cwd: join(REPO, "arbiter"), env: base, stdio: ["ignore", logFd, logFd], detached: true,
  });
  closeSync(logFd);
  children.push(arbiter);
  try {
    await waitFor(sock, 60_000);
    // Plan 14 §11.2: a seal recorded before the launch. The launch's end
    // voids it if the arbiter counted the launch unconfined; a macOS launch
    // whose one profile seals the home (read-blocked + homeSealed) keeps it.
    const hello = await ndjsonCall<{ humanSock?: string }>(sock, "hello", {}, 5000);
    assert.ok(typeof hello.humanSock === "string", "the arbiter reports its human socket");
    const humanSock = hello.humanSock!;
    const SEAL = { kind: "history-walk", key: "darwin-e2e", sha256: "a".repeat(64), size: 1 };
    const sealedAt = await ndjsonCall<{ epoch: string }>(humanSock, "sealCacheEntries", { entries: [SEAL] }, 5000);
    // A pinned arbiter still registers under the runtime dir's instances/
    // (runtime-instances.md §10): the registry exists, so a refused plant
    // there is the profile's doing.
    const plantedDir = join(E, "rt", "instances", "planted");
    assert.ok(existsSync(join(E, "rt", "instances")), "the arbiter registered its instance");
    // And `mandu dashboard`'s port-file temp name at the top of the base (the
    // dashboard writes it from outside the profile), and a FUTURE launch's
    // minted scope dir, which the next launch refuses to adopt (scope-dir.ts).
    const plantedPort = join(E, "rt", "dashboard-99999.port.tmp");
    const futureScope = join(E, "rt", `${Math.floor(Date.now() / 1000) + 3600}-99999`);
    const script = `cat "$HOME/.aws/credentials"; echo "cat=$?"; echo made > ws-out; echo "write=$?"; curl --version >/dev/null 2>&1; echo "curl=$?"; ` +
      `mkdir '${plantedDir}' 2>/dev/null; echo "plant=$?"; ln -s "$HOME/.zshrc" '${plantedPort}' 2>/dev/null; echo "plantport=$?"; ` +
      `mkdir '${futureScope}' && echo "scope=$?"`;
    const res = await new Promise<{ code: number; out: string; err: string }>((done) => {
      const child = spawn(join(PKG, "node_modules", ".bin", "tsx"), [join(PKG, "src", "run.ts"), "--target", "shell", "--no-scope", "--", "sh", "-c", script], {
        cwd: w2, env: { ...base, PWD: w2, MANDU_MODE: "secrets", MANDU_NO_CONTEXT_PROXY: "1", MANDU_VERBOSE: "1", MANDU_TENANT: "test" },
        stdio: ["ignore", "pipe", "pipe"],
      });
      children.push(child);
      let out = "", err = "";
      child.stdout.setEncoding("utf8").on("data", (c: string) => { out += c; });
      child.stderr.setEncoding("utf8").on("data", (c: string) => { err += c; });
      child.on("close", (code) => done({ code: code ?? 1, out, err }));
    });
    const diag = `\n--- stdout\n${res.out}\n--- stderr\n${res.err}\n--- arbiter\n${readFileSync(join(E, "arbiter.log"), "utf8").slice(-2000)}`;
    assert.equal(res.code, 0, diag);
    assert.ok(!res.out.includes("CANARY") && !res.err.includes("CANARY"), `the raw bytes never appear${diag}`);
    assert.match(res.out, /cat=1/, diag);
    assert.equal(existsSync(planted), false, `a PATH-planted sandbox-exec or script ran: ${existsSync(planted) ? readFileSync(planted, "utf8") : ""}${diag}`);
    assert.match(res.out, /write=0/, diag);
    assert.equal(readFileSync(join(w2, "ws-out"), "utf8"), "made\n");
    assert.match(res.out, /curl=0/, `the exec-wrap shim reached the arbiter from inside the profile${diag}`);
    assert.match(res.err, /mandu: mode secrets \(1 credential file unreadable \(read-blocked\)/, diag);
    assert.match(res.err, /mandu: seatbelt LIVE — the macOS profile around the whole agent: credential files, Mandu's state, write-protect, network, unix sockets, host services, human plane, runtime registry/, diag);
    assert.match(res.out, /plant=1/, `nothing can be planted in the instance registry from inside${diag}`);
    assert.equal(existsSync(plantedDir), false);
    assert.match(res.out, /plantport=1/, `no link at the dashboard's port-file temp name${diag}`);
    assert.equal(existsSync(plantedPort), false);
    // The base itself stays writable: a scope dir can be made in advance
    // (the profile cannot tell it from a nested launch's), and it is the
    // launcher that refuses to adopt one (scope-dir.ts, the unit test).
    assert.match(res.out, /scope=0/, `the runtime base stays writable${diag}`);
    rmSync(futureScope, { recursive: true, force: true });
    assert.ok(!/not built|proceeding WITHOUT|cargo build/.test(res.err), `no Linux rung noise on macOS${diag}`);
    assert.ok(!/readers? pinned|masked\)/.test(res.err.split("\n").find((l) => l.startsWith("mandu: mode")) ?? ""), diag);
    // The launch was recorded as confined for the caches (homeSealed): its
    // end rotated no epoch, so the seal from before it still stands.
    assert.ok(!/could not record this unprotected launch/.test(res.err), `the arbiter recorded the launch${diag}`);
    const after = await ndjsonCall<{ epoch: string; honoured: boolean; seals: unknown[] }>(humanSock, "cacheSeals", { kind: SEAL.kind, keys: [SEAL.key] }, 5000);
    assert.equal(after.epoch, sealedAt.epoch, `the sealed macOS launch rotated no epoch${diag}`);
    assert.equal(after.honoured, true);
    assert.equal(after.seals.length, 1, "the seal from before the launch still stands");
  } finally {
    try { process.kill(-arbiter.pid!, "SIGTERM"); } catch { /* gone */ }
  }
});
