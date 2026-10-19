/**
 * human-plane — fs-sync over the arbiter's HUMAN plane
 * (docs/design/architecture/arbiter-human-plane.md), against a REAL ArbiterServer.
 *
 *   (1) PARITY (CONTRIBUTING.md arbiter-client pattern): the PRODUCTION wiring —
 *       `new ArbiterClientAdapter(new ArbiterClient(humanSock))` and
 *       `new ArbiterEventStreamAdapter(…same…)`, no test bridge — with every
 *       forwarded op called. The same adapters over the DATA socket are
 *       refused on every original-returning op (desymbolize, resolve,
 *       events/subscribe) and still serve the data-plane ones.
 *   (2) The CLI: `sync` resolves a `no-model` token the agent wrote into the
 *       AgentView to the ORIGINAL in the HumanView when given the human
 *       socket; given ONLY the data socket it refuses to run (non-zero, names
 *       MANDU_ARBITER_HUMAN_SOCK) and the HumanView is not written.
 *
 * Mandu-new (no reference origin). Offline + unprivileged (tmpdir only).
 */

import { strict as assert } from "node:assert";
import { spawn, execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  ArbiterClientAdapter,
  ArbiterEventStreamAdapter,
  type RealArbiterClient,
} from "../../src/arbiter-client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis mints the no-model row

const HERE = dirname(fileURLToPath(import.meta.url));
const FS_SYNC_DIR = resolve(HERE, "..", "..");
const REPO = resolve(FS_SYNC_DIR, "..");
const CLI = join(FS_SYNC_DIR, "src", "fs-sync-cli.ts");
const TSX = join(FS_SYNC_DIR, "node_modules", ".bin", "tsx");
const SECRET = "ghp_FsSyncHumanPlane0123456789abcdefABCD";
const GIT_ENV = {
  GIT_AUTHOR_NAME: "fs-sync-test", GIT_AUTHOR_EMAIL: "fs-sync@test.local",
  GIT_COMMITTER_NAME: "fs-sync-test", GIT_COMMITTER_EMAIL: "fs-sync@test.local",
};

interface Srv { listen(): Promise<void>; close(): Promise<void> }
interface Cli extends RealArbiterClient {
  registerEnvSecrets(a: { vars: Array<{ name: string; value: string }>; sessionKey?: string }): Promise<{ vars: Array<{ symbol: string | null }> }>;
}

async function rig(): Promise<{ dir: string; dataSock: string; humanSock: string; server: Srv; mk: (p: string) => Cli }> {
  const { ArbiterServer } = (await import(join(REPO, "arbiter/ipc/server.ts"))) as {
    ArbiterServer: new (o: Record<string, unknown>) => Srv;
  };
  const { ArbiterClient } = (await import(join(REPO, "arbiter/ipc/client.ts"))) as {
    ArbiterClient: new (path: string) => Cli;
  };
  const dir = mkdtempSync(join(tmpdir(), "fs-sync-hp-"));
  const dataSock = join(dir, "arbiter.sock");
  const humanSock = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: dataSock, humanSocketPath: humanSock,
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    adminPolicyDir: null, packDir: null, log: () => {},
  });
  await server.listen();
  return { dir, dataSock, humanSock, server, mk: (p) => new ArbiterClient(p) };
}

test("(1) parity: the production adapters over the human socket serve every op; over the data socket the original-returning ops are refused", async () => {
  const r = await rig();
  const humanClient = r.mk(r.humanSock);
  const dataClient = r.mk(r.dataSock);
  const handles: Array<{ close(): void }> = [];
  try {
    const reg = await dataClient.registerEnvSecrets({ vars: [{ name: "GITHUB_TOKEN", value: SECRET }], sessionKey: "fs-hp" });
    const secretSym = reg.vars[0]!.symbol!;
    assert.ok(secretSym && !secretSym.includes(SECRET));

    const human = new ArbiterClientAdapter(humanClient);
    const minted = await human.symbolize({ tool: "Read", field: "content", value: "plain notes", origin: join(r.dir, "notes.txt") });
    assert.match(minted, /^\$MDU:/);
    assert.equal(await human.resolve(secretSym), SECRET, "shallow resolve over the human plane");
    assert.equal(await human.desymbolize(`k=${secretSym}`), `k=${SECRET}`, "deep desymbolize over the human plane");
    assert.ok((await human.symbolProvenance(minted)) !== null);
    assert.equal(typeof (await human.pathLevel(join(r.dir, "notes.txt"))).axis, "boolean");
    assert.equal(typeof (await human.fileTrust({ path: join(r.dir, "notes.txt") })).untrusted, "boolean");
    assert.ok((await human.emit({ sessionId: "fs-hp", id: "e0", kind: "tool_result" })) > 0);

    const stream = new ArbiterEventStreamAdapter(humanClient);
    await stream.ping();
    const got: unknown[] = [];
    handles.push(await stream.subscribeFromNow("fs-hp", (e) => got.push(e)));
    await human.emit({ sessionId: "fs-hp", id: "e1", kind: "tool_result" });
    const t0 = Date.now();
    while (!got.some((e) => (e as { id?: string }).id === "e1")) {
      if (Date.now() - t0 > 5000) throw new Error("no live event over the human-plane stream");
      await new Promise((res) => setTimeout(res, 20));
    }
    assert.ok(!got.some((e) => (e as { id?: string }).id === "e0"), "from NOW: history is not replayed");

    // The DATA socket: data-plane ops still work, the original-returning ones are refused.
    const data = new ArbiterClientAdapter(dataClient);
    assert.match(await data.symbolize({ tool: "Read", field: "content", value: "x" }), /^\$MDU:/);
    await assert.rejects(data.desymbolize(`k=${secretSym}`), /human-plane/);
    await assert.rejects(data.resolve(secretSym), /human-plane/);
    await assert.rejects(new ArbiterEventStreamAdapter(dataClient).subscribeFromNow("fs-hp", () => {}), /human-plane/);
  } finally {
    for (const h of handles) h.close();
    humanClient.close();
    dataClient.close();
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});

function runCli(args: string[], env: Record<string, string | undefined>): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((res) => {
    const child = spawn(TSX, [CLI, ...args], {
      cwd: FS_SYNC_DIR,
      env: { ...process.env, MANDU_ARBITER_SOCK: undefined, MANDU_ARBITER_HUMAN_SOCK: undefined, ...env },
    });
    let stdout = ""; let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("close", (code) => res({ code, stdout, stderr }));
  });
}

test("(2) CLI: sync writes the ORIGINAL through the human socket; with only the data socket it refuses and writes nothing", async () => {
  const r = await rig();
  const dataClient = r.mk(r.dataSock);
  try {
    const reg = await dataClient.registerEnvSecrets({ vars: [{ name: "GITHUB_TOKEN", value: SECRET }], sessionKey: "fs-hp-cli" });
    const secretSym = reg.vars[0]!.symbol!;

    const ws = join(r.dir, "workspace");
    mkdirSync(ws);
    const git = (args: string[]): void => { execFileSync("git", args, { cwd: ws, env: { ...process.env, ...GIT_ENV } }); };
    git(["init", "-q", "-b", "main"]);
    writeFileSync(join(ws, "README.md"), "# hello\n");
    git(["add", "-A"]);
    git(["commit", "-q", "-m", "seed"]);
    const stateBase = join(r.dir, "state");

    // Only the DATA socket: refused before any view is built.
    const refused = await runCli(["init", ws, "--state-base", stateBase], { MANDU_ARBITER_SOCK: r.dataSock });
    assert.notEqual(refused.code, 0, "no human socket → fail closed");
    assert.match(refused.stderr, /MANDU_ARBITER_HUMAN_SOCK is required/);

    const env = { MANDU_ARBITER_SOCK: r.dataSock, MANDU_ARBITER_HUMAN_SOCK: r.humanSock };
    const init = await runCli(["init", ws, "--state-base", stateBase], env);
    assert.equal(init.code, 0, init.stderr);
    const agentView = (JSON.parse(init.stdout.trim()) as { agentView: string }).agentView;

    // The agent writes a file holding the token.
    writeFileSync(join(agentView, "config.txt"), `token=${secretSym}\n`);

    // A sync with only the data socket: refused, the HumanView untouched.
    const noHuman = await runCli(["sync", ws, "--state-base", stateBase, "--tool", "Write"], { MANDU_ARBITER_SOCK: r.dataSock });
    assert.notEqual(noHuman.code, 0);
    assert.ok(!existsSync(join(ws, "config.txt")), "nothing written into the HumanView without the human plane");

    // Over the human socket: the human's copy holds the original.
    const synced = await runCli(["sync", ws, "--state-base", stateBase, "--tool", "Write"], env);
    assert.equal(synced.code, 0, synced.stderr);
    assert.equal(readFileSync(join(ws, "config.txt"), "utf8"), `token=${SECRET}\n`);
    assert.ok(!readFileSync(join(agentView, "config.txt"), "utf8").includes(SECRET), "the AgentView stays symbolic");
  } finally {
    dataClient.close();
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});
