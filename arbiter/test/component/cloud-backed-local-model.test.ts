/**
 * e2e — plan 11 §8 item 3 through the REAL arbiter: a policy file that
 * declares a cloud-backed model (Ollama's `:cloud` / `-cloud` tags) as
 * `local: true` never becomes the law.
 *
 *   - at boot, the daemon (`ipc/server-main.ts`) refuses to start and names
 *     the entry, and no socket is bound;
 *   - on a hand edit of a running arbiter's file, the reload is refused and
 *     the law in force (the previous `models:`) stays: `modelEndpoints` still
 *     answers the old entry and the file status says why;
 *   - an apply over the admin socket (the dashboard's write path) is refused
 *     and writes nothing.
 * Why it matters: the entry's `model` is what inspect-mcp sends `local-model`
 * bytes to (D5), and a cloud tag behind 127.0.0.1:11434 relays them to the
 * vendor.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // local-model is a confidentiality level (the default mode's axis)

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const GOOD = `version: 1
models:
  - name: ollama
    url: http://127.0.0.1:11434
    wire: openai-chat
    model: gpt-oss:20b
    local: true
`;
const CLOUD = GOOD.replace("gpt-oss:20b", "gpt-oss:120b-cloud");

async function waitFor(pred: () => boolean | Promise<boolean>, ms: number, what: () => string): Promise<void> {
  const deadline = Date.now() + ms;
  while (!(await pred())) {
    if (Date.now() > deadline) assert.fail(`timed out: ${what()}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

test("boot: a local: true entry with a cloud model → the daemon refuses to start and names the entry", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-cloud-model-e2e-"));
  let child: ChildProcess | null = null;
  try {
    const file = join(dir, "policy.yaml");
    writeFileSync(file, CLOUD);
    const sock = join(dir, "arbiter.sock");
    let err = "";
    child = spawn(process.execPath, ["--import", "tsx", "ipc/server-main.ts"], {
      cwd: ARBITER_DIR,
      env: {
        ...process.env,
        MANDU_ARBITER_SOCK: sock,
        MANDU_RUNTIME_DIR: join(dir, "rt"),
        MANDU_HOME: join(dir, "home"),
        MANDU_POLICY_FILE: file,
        MANDU_INBOUND_SPEC: "",
        MANDU_TENANT: "",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const c = child;
    c.stderr!.on("data", (d: Buffer) => (err += d.toString()));
    await waitFor(() => c.exitCode !== null, 30_000, () => `daemon still running; stderr:\n${err}`);
    assert.notEqual(c.exitCode, 0, "a refused start exits non-zero");
    assert.match(err, /policy file .*policy\.yaml is invalid/);
    assert.match(err, /models\[0\]\.model: 'gpt-oss:120b-cloud' runs on the vendor's servers \(a cloud model\), so 'ollama' cannot be local: true/);
    assert.ok(!existsSync(sock), "no socket was ever bound");
  } finally {
    // A daemon that started after all (the failure above) is stopped before
    // its dir goes: alive, it outlived the test and kept the dir's socket.
    if (child && child.exitCode === null && child.signalCode === null) {
      const gone = new Promise((r) => child!.once("exit", r));
      child.kill("SIGKILL");
      await gone;
    }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("reload and apply: the cloud entry is refused and the law in force keeps the previous local model", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-cloud-model-e2e-"));
  const file = join(dir, "policy.yaml");
  writeFileSync(file, GOOD);
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: file, policyPollMs: 40, log: () => {},
  });
  await server.listen();
  const data = new ArbiterClient(join(dir, "arbiter.sock"));
  const admin = new ArbiterClient(join(dir, "admin.sock"));
  try {
    await data.connect();
    await admin.connect();
    const models = async () => (await data.modelEndpoints()).map((e) => [e.name, e.model, e.local]);
    assert.deepEqual(await models(), [["ollama", "gpt-oss:20b", true]]);

    // A hand edit swaps in the cloud tag: refused, the old law stays.
    writeFileSync(file, CLOUD);
    const status = async () => ((await data.policySnapshot()) as { policyFile?: { valid: boolean; problems: string[] } }).policyFile;
    await waitFor(async () => (await status())?.valid === false, 10_000, () => "the reload was never refused");
    assert.ok((await status())!.problems.some((p) => /gpt-oss:120b-cloud' runs on the vendor's servers/.test(p)));
    assert.deepEqual(await models(), [["ollama", "gpt-oss:20b", true]], "the refused file did not replace models:");

    // The dashboard's write path refuses the same document and writes nothing.
    writeFileSync(file, GOOD);
    await waitFor(async () => (await status())?.valid === true, 10_000, () => "the good file was never reloaded");
    await assert.rejects(
      async () => admin.applyPolicyDocument({
        version: 1,
        models: [{ name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "qwen3-coder:480b-cloud", local: true }],
      }, "e2e", (await admin.policyDocument()).lawHash!),
      /qwen3-coder:480b-cloud' runs on the vendor's servers/,
    );
    assert.equal(readFileSync(file, "utf8"), GOOD, "the refused apply wrote nothing");
    assert.deepEqual(await models(), [["ollama", "gpt-oss:20b", true]]);

    // The same model on a non-local entry is fine.
    await admin.applyPolicyDocument({
      version: 1,
      models: [{ name: "ollama-cloud", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "gpt-oss:120b-cloud", local: false }],
    }, "e2e", (await admin.policyDocument()).lawHash!);
    assert.deepEqual(await models(), [["ollama-cloud", "gpt-oss:120b-cloud", false]]);
  } finally {
    data.close();
    admin.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
