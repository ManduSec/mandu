/**
 * own-text-config-twin — plan 10 §11.13 (2026-10-17) over the REAL arbiter
 * (its sockets, the human plane) and the anthropic-proxy through its
 * production adapter (`new ArbiterClientAdapter(new ArbiterClient(sock),
 * new ArbiterClient(humanSock))`):
 *
 * 1. The launch's HOME. Two launches with different HOMEs on one arbiter,
 *    each recorded by its launcher on the human plane (`beginLaunch` with
 *    `home`): ssh, a known consumer of `~/.ssh/id_*`, reads a key under
 *    launch B's HOME raw in session B and gets its twin in session A (whose
 *    HOME is elsewhere). Before, every session was judged by the arbiter's
 *    own HOME, so ssh got the twin in both (fail-safe, no login). A HOME
 *    claimed on the data socket is not recorded, and a launch's HOME ends
 *    with it.
 *
 * 2. A config with no secret reaches the model as its text. A
 *    `~/.ssh/config` whose every place is public (its twin is its own text)
 *    reaches the model as it is through Claude Code's `Read` (the whole file
 *    or a piece) and through `cat` in a tree the guard saw read no secret.
 *    It used to come back as one handle. And the invariant holds:
 *      - a config with a credential the belt (!1621) finds is a structured
 *        twin: the model sees a symbol, never the token;
 *      - a config holding a REGISTERED value (an environment secret) in a
 *        public place reaches the model masked (the value backstop);
 *      - the file's text with a secret it did not have at registration (a
 *        read the guard did not serve) reaches the model masked;
 *      - `cat -n` (a gutter), and a `cat` in a tree that read a key raw,
 *        reach the model masked;
 *    and no canary reaches the model anywhere.
 * Axes stated: `secrets` (confidentiality ON, integrity OFF), pinned on the
 * server too.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const KEY_CANARY = "keyCANARY9d2c7e1a4b6f";
const GH_CANARY = "ghp_" + "Zq7vX2pL9kWm4Rt8Yb3Nc6Hd1Jf5Gs0Ae2Uo";
const REUSED_CANARY = "corp-deploy-pw-CANARY-77";
const ADDED_CANARY = "addedCANARY3f8e1b0c5d";
const CANARIES = [KEY_CANARY, GH_CANARY, REUSED_CANARY, ADDED_CANARY];

const PLAIN = "Host build\n  HostName 10.1.2.3\n  User deployer\n  IdentityFile ~/.ssh/id_work\n  Port 2222\n";
const KEY = `-----BEGIN OPENSSH PRIVATE KEY-----\n${KEY_CANARY}\n-----END OPENSSH PRIVATE KEY-----\n`;

interface Rig {
  tmp: string;
  server: ArbiterServer;
  guard: ArbiterClient;
  real: ArbiterClient;
  realHuman: ArbiterClient;
  claude: ArbiterClientAdapter;
  close: () => Promise<void>;
}

async function rig(name: string): Promise<Rig> {
  const tmp = mkdtempSync(join(tmpdir(), `mandu-owntext-${name}-`));
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
  });
  await server.listen();
  const guard = new ArbiterClient(humanSock); await guard.connect(); // the guard and the launcher: the human plane
  const realHuman = new ArbiterClient(humanSock); await realHuman.connect(); // the proxies' second client (server-main)
  const real = new ArbiterClient(socketPath); await real.connect(); // the data socket
  const claude = new ArbiterClientAdapter(real as unknown as RealArbiterClient, realHuman as unknown as RealArbiterClient);
  return {
    tmp, server, guard, real, realHuman, claude,
    close: async () => { guard.close(); realHuman.close(); real.close(); await server.close(); rmSync(tmp, { recursive: true, force: true }); },
  };
}

function put(home: string, rel: string, text: string): string {
  const p = join(home, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text);
  return p;
}

const launch = (r: Rig, client: ArbiterClient, sessionId: string, home: string) =>
  client.beginLaunch({ pid: process.pid, mode: "secrets", posture: "confined", writeProtect: true, humanPlaneWalled: true, sessionId, home });

test("decideSecretOpen judges a session's opens by its launch's HOME: ssh reads a key under launch B's HOME raw in session B, the twin in session A; a data-socket HOME is not recorded (secrets axes, explicit)", async () => {
  const r = await rig("home");
  try {
    const homeA = join(r.tmp, "home-a");
    const homeB = join(r.tmp, "home-b");
    mkdirSync(homeA, { recursive: true });
    // A custom-named key: `~/.ssh` is a HOME-anchored catalog place (no
    // basename shape covers `id_work`), and ssh is its known consumer.
    const key = put(homeB, ".ssh/id_work", KEY);
    const reg = await r.guard.registerSecret({ path: key, home: homeB });
    assert.ok(reg.symbol, reg.reason);
    const a = await launch(r, r.guard, "sess-a", homeA);
    const b = await launch(r, r.guard, "sess-b", homeB);
    const open = (session: string, procKey: string) => r.guard.decideSecretOpen({ path: key, exe: "/usr/bin/ssh", isAgent: false, exeSystem: true, openerEnv: [], procKey, session, ask: "never" });

    const inB = await open("sess-b", "ssh-b-1");
    assert.equal(inB.verdict, "raw", `ssh logs in with the key of its own launch's HOME: ${inB.reason}`);
    const inA = await open("sess-a", "ssh-a-1");
    assert.equal(inA.verdict, "twin", `another launch's HOME is not this session's: ${inA.reason}`);
    // The agent's own process never reads raw, whatever the HOME.
    const agent = await r.guard.decideSecretOpen({ path: key, exe: "/usr/bin/ssh", isAgent: true, exeSystem: true, openerEnv: [], procKey: "agent-b", session: "sess-b", ask: "never" });
    assert.equal(agent.verdict, "twin");
    // A HOME claimed on the data socket names nothing: the launch op there
    // is refused or recorded with no HOME.
    await launch(r, r.real, "sess-c", homeB).catch(() => null);
    assert.equal((await open("sess-c", "ssh-c-1")).verdict, "twin", "a data-socket HOME is not believed");
    // And a data-socket report of the open is a claim: the twin.
    assert.equal((await r.real.decideSecretOpen({ path: key, exe: "/usr/bin/ssh", isAgent: false, exeSystem: true, openerEnv: [], procKey: "ssh-b-2", session: "sess-b", ask: "never" })).verdict, "twin");
    // The launch ends: its HOME with it (fail-safe: the twin again).
    await r.guard.endLaunch(b.token);
    assert.equal((await open("sess-b", "ssh-b-3")).verdict, "twin", "an ended launch's HOME is not kept");
    await r.guard.endLaunch(a.token);
  } finally {
    await r.close();
  }
});

function readReq(path: string, content: string, id: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "show me my ssh config" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  };
}
function bashReq(command: string, content: string, id: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "show me my ssh config" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  };
}
const forwarded = (req: MessagesRequest): string => ((req.messages[2]!.content as any[])[0].content as string);
const claudeRead = (text: string, from = 1) => text.replace(/\n$/, "").split("\n").map((l, i) => `${String(i + from).padStart(6)}\t${l}`).join("\n");
const SYMBOL = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/;

test("a config with no secret reaches the model as its text (Read and cat); a credential, a registered value, an added secret, a gutter or a tainted tree keep it masked; no canary reaches the model (secrets axes, explicit)", async () => {
  const r = await rig("config");
  const session = "sess-own";
  try {
    const home = join(r.tmp, "home");
    const plain = put(home, ".ssh/config", PLAIN);
    const belt = put(home, ".ssh/config.d/github", `Host gh\n  HostName github.com\n  User ${GH_CANARY}\n`);
    const reused = put(home, ".ssh/config.d/corp", `Host corp\n  HostName corp.example\n  User ${REUSED_CANARY}\n`);
    const key = put(home, ".ssh/id_work", KEY);
    await launch(r, r.guard, session, home);
    assert.equal((await r.real.setSessionSpec({ sessionKey: session, spec: "claude-code", requestedBy: "own-text-config-twin e2e" })).bound, "claude-code");
    // The launcher: its environment's secret first, then the HOME's files.
    const env = await r.guard.registerEnvSecrets({ vars: [{ name: "CORP_DEPLOY_PASSWORD", value: REUSED_CANARY }] });
    assert.ok(env.vars[0]!.symbol, env.vars[0]!.reason);
    const reg: Record<string, Awaited<ReturnType<ArbiterClient["registerSecret"]>>> = {};
    for (const p of [plain, belt, reused, key]) reg[p] = await r.guard.registerSecret({ path: p, home, sessionKey: session });
    assert.equal(reg[plain]!.twin, PLAIN, `no secret: the twin is the file's own text (${reg[plain]!.reason})`);
    assert.match(reg[belt]!.twin ?? "", SYMBOL, "the belt masks a token in a public place: a structured twin");
    assert.ok(!(reg[belt]!.twin ?? "").includes(GH_CANARY));
    assert.equal(reg[reused]!.twin, `Host corp\n  HostName corp.example\n  User ${REUSED_CANARY}\n`, "by its format alone the corp config is its own text (the registered value is the backstop's)");

    const seen: string[] = [];
    const viaRead = async (path: string, content: string, id: string) => {
      const out = await rewriteRequest(readReq(path, content, id), { arbiter: r.claude, sessionKey: session });
      const f = forwarded(out.request);
      seen.push(f);
      return { f, rw: out.rewrites[0]! };
    };

    // ── the Read leg ───────────────────────────────────────────────────────
    const whole = await viaRead(plain, claudeRead(PLAIN), "toolu_read_1");
    assert.equal(whole.f, claudeRead(PLAIN), `the model reads the config as it is: ${whole.rw.reason}`);
    assert.equal(whole.rw.symbolized, false);
    const piece = await viaRead(plain, claudeRead("  HostName 10.1.2.3\n  User deployer\n", 2), "toolu_read_2");
    assert.ok(piece.f.includes("HostName 10.1.2.3"), `an offset/limit piece too: ${piece.f}`);
    // Again, after two released reads (no proxy row may shadow it).
    assert.equal((await viaRead(plain, claudeRead(PLAIN), "toolu_read_3")).f, claudeRead(PLAIN));
    // The real file with a secret it did not have at registration (a read
    // the guard did not serve): masked whole.
    const added = await viaRead(plain, claudeRead(`${PLAIN}  SetEnv TOKEN=${ADDED_CANARY}\n`), "toolu_read_4");
    assert.equal(added.rw.symbolized, true, added.rw.reason);
    assert.ok(!added.f.includes("HostName"), `masked whole: ${added.f}`);
    // The belt's config: its structured twin, the token a symbol.
    const gh = await viaRead(belt, claudeRead(reg[belt]!.twin!), "toolu_read_5");
    assert.match(gh.f, SYMBOL, gh.f);
    // A registered value in a public place: the value backstop masks it.
    const corp = await viaRead(reused, claudeRead(reg[reused]!.twin!), "toolu_read_6");
    assert.equal(corp.rw.symbolized, true, `a registered value masks the read: ${corp.rw.reason}`);

    // ── the cat leg ────────────────────────────────────────────────────────
    let roots = 0;
    const shellFor = async (command: string, child: string, callId: string): Promise<void> => {
      const root = `sh-${++roots}`;
      await r.claude.recordCallCommand!({ callId, command, sessionKey: session });
      await r.guard.recordExecRoot({ procKey: root, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true });
      await r.guard.processLineage({ childKey: child, parentKey: root, session });
    };
    const viaBash = async (command: string, child: string, content: string, id: string) => {
      await shellFor(command, child, id);
      const out = await rewriteRequest(bashReq(command, content, id), { arbiter: r.claude, sessionKey: session });
      const f = forwarded(out.request);
      seen.push(f);
      return { f, rw: out.rewrites[0]! };
    };
    const cat = await viaBash("cat ~/.ssh/config", "cat-1", PLAIN.replace(/\n$/, ""), "toolu_cat_1");
    assert.equal(cat.rw.symbolized, false, `${cat.rw.reason} ${JSON.stringify(cat.rw.secretTaint)}`);
    assert.ok(cat.f.startsWith(PLAIN.replace(/\n$/, "")), `the model reads cat's output as printed: ${cat.f}`);
    assert.match(cat.f, /\[mandu:secret\] twin: this is .*\/\.ssh\/config as it is: Mandu read every place in it that can hold a secret and found none, so you see its text\.$/);
    const grep = await viaBash(`grep User ${plain}`, "grep-1", "  User deployer", "toolu_cat_2");
    assert.ok(grep.f.startsWith("  User deployer"), `a grep of it too: ${grep.f}`);
    // `cat -n`: a gutter the twin does not hold, masked whole.
    const numbered = await viaBash("cat -n ~/.ssh/config", "cat-2", claudeRead(PLAIN), "toolu_cat_3");
    assert.equal(numbered.rw.symbolized, true, numbered.rw.reason);
    // A tree that read a key raw (ssh, the key's known consumer) could print
    // anything: masked whole, whatever its output looks like.
    const raw = await r.guard.decideSecretOpen({ path: key, exe: "/usr/bin/ssh", isAgent: false, exeSystem: true, openerEnv: [], procKey: "ssh-9", session, ask: "never" });
    assert.equal(raw.verdict, "raw", raw.reason);
    const tainted = await viaBash("ssh build cat ~/.ssh/config", "ssh-9", PLAIN, "toolu_cat_4");
    assert.equal(tainted.rw.symbolized, true, tainted.rw.reason);
    // The corp config printed by cat: the value backstop masks it.
    const corpCat = await viaBash(`cat ${reused}`, "cat-3", reg[reused]!.twin!, "toolu_cat_5");
    assert.equal(corpCat.rw.symbolized, true, corpCat.rw.reason);

    // THE ORACLE: no canary reached the model.
    for (const f of seen) for (const c of CANARIES) assert.ok(!f.includes(c), `the model got ${c}: ${f}`);
  } finally {
    await r.close();
  }
});
