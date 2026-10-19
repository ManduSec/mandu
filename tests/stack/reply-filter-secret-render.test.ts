/**
 * reply-filter-secret-render.test.ts — every secret SOURCE renders the same
 * way on the human's terminal (release checklist a3; confidentiality.md §7
 * "Secrets on the human's terminal: one rendering for every source").
 *
 * THE BUG (fresh-user run of the 0.1.0 tarball, 2026-09-26): a shell command
 * over a fake `.env`, `~/.aws/credentials` and `GITHUB_TOKEN` printed the
 * `.env` values as ORIGINALS while `aws_access_key_id` and `GITHUB_TOKEN` stayed
 * `$MDU:` tokens. All three are registered the same way (arbiter
 * secret-registry: file twin fields and the env mask, all resolvable by the
 * deep `desymbolize` op). The difference was purely the reply filter's wrap
 * reassembly: a token that ENDS a line glued to the next line's first word
 * (`\n` is also a wrap insertion), so the arbiter was asked for a name it never
 * allocated. The `.env` twin quotes its values (`KEY='$MDU:…'`), so the quote
 * ended the token and it resolved.
 *
 * THE CONTRACT pinned here, across the REAL components (real ArbiterServer on
 * the `secrets` axes, real registerSecret / registerEnvSecrets over the IPC,
 * the real reply-filter CLI spawned around a real bash):
 *
 *   (a) what the agent's own world holds (twin files + masked env) carries NO
 *       secret byte: this is what can reach the model, and the reply filter
 *       does not touch it;
 *   (b) the human's terminal (pipe mode, the real CLI) shows the ORIGINAL of
 *       every secret from every source, and no `$MDU:` token;
 *   (c) the same in EAGER (PTY-relay) mode over the real IPC client, modulo
 *       the frame-safe padding / wrap-off bracket;
 *   (d) with the arbiter unreachable, EVERY source degrades the same way:
 *       all tokens stay opaque (utility posture, nothing leaks);
 *   (e) the HUMAN PLANE (docs/design/architecture/arbiter-human-plane.md): the filter
 *       resolves over $MANDU_ARBITER_HUMAN_SOCK only. Given the data socket
 *       alone it passes every token through (it never asks the data socket,
 *       which refuses `desymbolize` anyway), and the wrapped child — the
 *       agent's world — is never told the human socket's name.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ReplyStreamFilter } from "../../interceptors/reply-filter/src/filter.js";
import { ArbiterClientAdapter } from "../../interceptors/reply-filter/src/arbiter-client.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // the built-in default mode; the confidentiality axis is what mints secret symbols

const HERE = dirname(fileURLToPath(import.meta.url));
const RF_ROOT = join(HERE, "..", "..", "interceptors", "reply-filter");
const RUN_TS = join(RF_ROOT, "src", "run.ts");
const TSX_BIN = join(RF_ROOT, "node_modules", ".bin", "tsx");

/** The originals, one per secret field, by source class. */
const ORIGINALS = {
  dotenv: { API_KEY: "sk-test-abcdef1234567890", DB_PASSWORD: "hunter2hunter2hunter2" },
  aws: {
    aws_access_key_id: "AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  },
  env: { GITHUB_TOKEN: "ghp_abcdefghijklmnopqrstuvwxyz0123456789" },
} as const;
const ALL_ORIGINALS = [
  ...Object.values(ORIGINALS.dotenv),
  ...Object.values(ORIGINALS.aws),
  ...Object.values(ORIGINALS.env),
];

interface Rig {
  sock: string;
  /** The arbiter's human-plane socket (arbiter-human-plane.md). */
  humanSock: string;
  /** The agent's world: twin files (what the bwrap bind shows) + masked env. */
  envTwinPath: string;
  awsTwinPath: string;
  maskedGithubToken: string;
  /** The shell command a new user runs inside the agent's world. */
  script: string;
  client: ArbiterClient;
  /** A client over the human-plane socket: the filter's production channel. */
  humanClient: ArbiterClient;
  close: () => Promise<void>;
}

async function startRig(): Promise<Rig> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-secret-render-"));
  const home = join(dir, "home");
  mkdirSync(join(home, ".aws"), { recursive: true });
  mkdirSync(join(home, "proj"), { recursive: true });
  const envPath = join(home, "proj", ".env");
  const awsPath = join(home, ".aws", "credentials");
  writeFileSync(envPath, `API_KEY=${ORIGINALS.dotenv.API_KEY}\nDB_PASSWORD=${ORIGINALS.dotenv.DB_PASSWORD}\n`);
  writeFileSync(
    awsPath,
    `[default]\naws_access_key_id = ${ORIGINALS.aws.aws_access_key_id}\n` +
      `aws_secret_access_key = ${ORIGINALS.aws.aws_secret_access_key}\n`,
  );

  const sock = join(dir, "arbiter.sock");
  const humanSock = humanSockIn(dir);
  const arbiter = new ArbiterServer({
    socketPath: sock,
    humanSocketPath: humanSock,
    dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"),
    log: () => {},
  });
  await arbiter.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const humanClient = new ArbiterClient(humanSock);
  await humanClient.connect();

  // Exactly the launcher's registration calls (secret-setup.ts).
  const env = await client.registerSecret({ path: envPath, home });
  const aws = await client.registerSecret({ path: awsPath, home });
  const gh = await client.registerEnvSecrets({ vars: [{ name: "GITHUB_TOKEN", value: ORIGINALS.env.GITHUB_TOKEN }] });
  assert.ok(env.twin, `.env gets a structured twin: ${env.reason}`);
  assert.ok(aws.twin, `~/.aws/credentials gets a structured twin: ${aws.reason}`);
  const ghTwin = gh.vars[0]?.twin;
  assert.ok(ghTwin, `GITHUB_TOKEN is masked: ${gh.vars[0]?.reason}`);

  const envTwinPath = join(dir, "twin-env");
  const awsTwinPath = join(dir, "twin-aws");
  writeFileSync(envTwinPath, env.twin!);
  writeFileSync(awsTwinPath, aws.twin!);
  return {
    sock,
    humanSock,
    envTwinPath,
    awsTwinPath,
    maskedGithubToken: ghTwin!,
    // The fresh-user command: two files, the env var, and one more line after
    // it (the line that glued GITHUB_TOKEN's token in the release run).
    script: `cat "$ENV_TWIN"; cat "$AWS_TWIN"; echo "GITHUB_TOKEN=$GITHUB_TOKEN"; echo done`,
    client,
    humanClient,
    close: async () => {
      client.close();
      humanClient.close();
      await arbiter.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function childEnv(rig: Rig, sock: string | undefined, humanSock?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    MANDU_ARBITER_SOCK: sock,
    MANDU_ARBITER_HUMAN_SOCK: humanSock,
    MANDU_SCOPE_ID: "secret-render-e2e",
    MANDU_REPLY_FILTER_PTY: "0",
    ENV_TWIN: rig.envTwinPath,
    AWS_TWIN: rig.awsTwinPath,
    GITHUB_TOKEN: rig.maskedGithubToken,
  };
  // An absent human socket is ABSENT, never inherited from this process.
  if (humanSock === undefined) delete env["MANDU_ARBITER_HUMAN_SOCK"];
  return env;
}

async function runCapture(cmd: string, args: string[], env: NodeJS.ProcessEnv): Promise<string> {
  const child = spawn(cmd, args, { env, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (c: string) => (out += c));
  child.stderr.resume();
  const [code] = (await once(child, "close")) as [number | null];
  assert.equal(code, 0, `exit code of ${cmd}`);
  return out;
}

/** The human-facing line for each secret, by source class. */
function assertEveryClassShowsOriginals(out: string, label: string): void {
  assert.ok(!out.includes("$MDU:"), `${label}: no opaque token reaches the human: ${JSON.stringify(out)}`);
  const lines = out.split(/\r?\n/);
  const lineOf = (prefix: string) => lines.find((l) => l.startsWith(prefix)) ?? "";
  for (const [k, v] of Object.entries(ORIGINALS.dotenv)) {
    assert.ok(lineOf(`${k}=`).includes(v), `${label}: .env ${k} shows its original`);
  }
  for (const [k, v] of Object.entries(ORIGINALS.aws)) {
    assert.ok(lineOf(`${k} = `).includes(v), `${label}: ~/.aws/credentials ${k} shows its original`);
  }
  assert.ok(lineOf("GITHUB_TOKEN=").includes(ORIGINALS.env.GITHUB_TOKEN), `${label}: GITHUB_TOKEN shows its original`);
  assert.ok(lines.includes("done"), `${label}: the line after the last token survives verbatim`);
}

test("(a)+(b) secrets mode: .env, ~/.aws/credentials and a masked env var ALL show originals through the real reply-filter CLI", async () => {
  const rig = await startRig();
  try {
    // (a) The agent's own world: no secret byte anywhere the model can read.
    const agentView = await runCapture("bash", ["-c", rig.script], childEnv(rig, undefined));
    for (const v of ALL_ORIGINALS) assert.ok(!agentView.includes(v), `the agent's world holds no original (${v.slice(0, 6)}…)`);
    assert.equal((agentView.match(/\$MDU:nomodel_/g) ?? []).length, 5, `five secret tokens in the agent's view: ${agentView}`);
    assert.ok(!readFileSync(rig.envTwinPath, "utf8").includes(ORIGINALS.dotenv.API_KEY));

    // (b) The human's terminal, through the real CLI in pipe mode.
    const human = await runCapture(TSX_BIN, [RUN_TS, "--", "bash", "-c", rig.script], childEnv(rig, rig.sock, rig.humanSock));
    assertEveryClassShowsOriginals(human, "pipe mode");
  } finally {
    await rig.close();
  }
});

test("(c) EAGER (PTY relay) stream core over the real IPC client: every source class renders its original", async () => {
  const rig = await startRig();
  try {
    const agentView = await runCapture("bash", ["-c", rig.script], childEnv(rig, undefined));
    // Production wiring: the adapter over a client of the HUMAN socket.
    const filter = new ReplyStreamFilter(new ArbiterClientAdapter(rig.humanClient), { eager: true });
    // A PTY delivers CRLF line ends; feed it line by line, as a relay would.
    const chunks = agentView.replace(/\n/g, "\r\n").split(/(?<=\n)/);
    let out = "";
    for (const c of chunks) out += await filter.write(c);
    out += await filter.flush();
    // Frame-safe rendering: a shorter value pads to the token's width, a
    // longer one is wrapped in ESC[?7l…?7h. Strip exactly that framing.
    const unframed = out.replace(/\x1b\[\?7[lh]/g, "").replace(/ +(?=['\r\n])/g, "");
    assertEveryClassShowsOriginals(unframed, "eager mode");
  } finally {
    await rig.close();
  }
});

test("(d) arbiter unreachable: every source degrades the SAME way (all tokens stay opaque, nothing leaks)", async () => {
  const rig = await startRig();
  try {
    const human = await runCapture(
      TSX_BIN,
      [RUN_TS, "--", "bash", "-c", rig.script],
      childEnv(
        rig,
        join(tmpdir(), `mandu-no-such-arbiter-${process.pid}.sock`),
        join(tmpdir(), `mandu-no-such-human-${process.pid}.sock`),
      ),
    );
    for (const v of ALL_ORIGINALS) assert.ok(!human.includes(v), "no original without the arbiter");
    assert.equal((human.match(/\$MDU:nomodel_/g) ?? []).length, 5, `all five tokens stay opaque: ${human}`);
  } finally {
    await rig.close();
  }
});

test("(e) human plane: given ONLY the data socket the real CLI passes every token through, and the agent's child is never told the human socket", async () => {
  const rig = await startRig();
  try {
    // Data socket only: the filter has no human plane → passthrough. It must
    // not ask the data socket (which would refuse), and nothing leaks.
    const dataOnly = await runCapture(TSX_BIN, [RUN_TS, "--", "bash", "-c", rig.script], childEnv(rig, rig.sock));
    for (const v of ALL_ORIGINALS) assert.ok(!dataOnly.includes(v), `no original over the data socket (${v.slice(0, 6)}…)`);
    assert.equal((dataOnly.match(/\$MDU:nomodel_/g) ?? []).length, 5, `all five tokens stay opaque: ${dataOnly}`);

    // The data socket itself refuses the op the filter needs (the reach this
    // plane closes), while the human socket answers it.
    const token = /\$MDU:nomodel_[^\s'"]+/.exec(dataOnly)![0];
    await assert.rejects(rig.client.desymbolize(token), /human-plane/, "desymbolize on the data socket is refused");
    assert.ok(ALL_ORIGINALS.includes(await rig.humanClient.desymbolize(token) as never), "the human socket resolves it");

    // Hygiene: the wrapped child (the agent's world) runs without the name.
    const probe = await runCapture(
      TSX_BIN,
      [RUN_TS, "--", "bash", "-c", 'echo "HUMAN=${MANDU_ARBITER_HUMAN_SOCK:-unset}"'],
      childEnv(rig, rig.sock, rig.humanSock),
    );
    assert.match(probe, /HUMAN=unset/, `the child env lacks MANDU_ARBITER_HUMAN_SOCK: ${probe}`);
    assert.ok(!probe.includes(rig.humanSock), "the human socket path never reaches the child's output");
  } finally {
    await rig.close();
  }
});

test("(f) the stream core over a DATA-socket client: every desymbolize is refused, so every token passes through", async () => {
  const rig = await startRig();
  try {
    const agentView = await runCapture("bash", ["-c", rig.script], childEnv(rig, undefined));
    const filter = new ReplyStreamFilter(new ArbiterClientAdapter(rig.client), { eager: true });
    let out = "";
    for (const c of agentView.split(/(?<=\n)/)) out += await filter.write(c);
    out += await filter.flush();
    for (const v of ALL_ORIGINALS) assert.ok(!out.includes(v), `no original via the data socket (${v.slice(0, 6)}…)`);
    assert.equal((out.match(/\$MDU:nomodel_/g) ?? []).length, 5, `all five tokens stay opaque: ${out}`);
  } finally {
    await rig.close();
  }
});
