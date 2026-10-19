/**
 * e2e — the level names retired on 2026-09-27 are REFUSED, never translated
 * and never silently dropped (confidentiality.md), through
 * the real arbiter:
 *   - the daemon (`ipc/server-main.ts`) refuses to start on a policy.yaml that
 *     uses one, naming the entry;
 *   - a hand edit that introduces one is rejected and the last good law stays;
 *   - an embedder that builds the server straight from the file is refused
 *     like the daemon (plan 14 §14.12: the server validates the file that is
 *     the law at start);
 *   - an engine handed such a document in memory (no validator) still locks
 *     the file at `no-model`: its content reaches the model only as an opaque
 *     token (the invariant half).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import yaml from "js-yaml";

import { ArbiterServer } from "../../ipc/server.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";
import { pollDiskApproving } from "../held-disk.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const OLD_STRICT = ["secret", "strict"].join("-");
const OLD_MODEL_OK = ["secret", "model-ok"].join("-");
const CANARY = "Acme pays 4,200,000 USD. RETIRED_LEVEL_CANARY";

test("the daemon refuses to start on a policy.yaml that uses a retired level name, naming the entry", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-"));
  const file = join(dir, "policy.yaml");
  writeFileSync(file, `version: 1\npaths:\n  - { path: /h/deal.md, level: ${OLD_MODEL_OK} }\n`);
  try {
    let err = "";
    const child = spawn(process.execPath, ["--import", "tsx", "ipc/server-main.ts"], {
      cwd: ARBITER_DIR,
      env: {
        ...process.env,
        MANDU_ARBITER_SOCK: join(dir, "a.sock"), MANDU_RUNTIME_DIR: join(dir, "rt"),
        MANDU_HOME: join(dir, "home"),
        MANDU_POLICY_FILE: file, MANDU_INBOUND_SPEC: "", MANDU_TENANT: "",
      },
      stdio: ["ignore", "ignore", "pipe"],
    });
    child.stderr!.on("data", (d: Buffer) => (err += d.toString()));
    const code = await new Promise<number | null>((r) => child.once("exit", (c) => r(c)));
    assert.notEqual(code, 0, "the start is refused");
    assert.match(err, /paths\[0\]\.level/);
    assert.match(err, /no-model/, "the error lists the levels it accepts");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a server built straight from an old-name file is refused; one handed the document locks at no-model; a hand edit with one is rejected", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-"));
  const file = join(dir, "policy.yaml");
  const oldNames = [
    "version: 1",
    "paths:",
    "  - path: /h/contract.md",
    `    level: ${OLD_STRICT}`,
    `  - { path: /h/deal.md, level: ${OLD_MODEL_OK}, bindings: [example.com] }`,
    "",
  ].join("\n");
  writeFileSync(file, oldNames);
  const opts = { dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true };
  assert.throws(
    () => new ArbiterServer({ ...opts, socketPath: join(dir, "x.sock"), policyPath: file, policyPollMs: 0 }),
    (e: Error) => e.name === "PolicyFileError" && /paths\[0\]\.level/.test(e.message) && /paths\[1\]\.level/.test(e.message),
    "the embedder refuses the file like the daemon",
  );
  const handed = new ArbiterServer({
    ...opts, dbPath: join(dir, "handed.sqlite"), socketPath: join(dir, "h.sock"),
    policyDocument: yaml.load(oldNames) as PolicyFileConfig,
  });
  await handed.listen();
  const inMemory = new ArbiterClient(join(dir, "h.sock"));
  try {
    await inMemory.connect();
    for (const p of ["/h/contract.md", "/h/deal.md"]) {
      assert.equal((await inMemory.pathLevel(p)).level, "no-model", `${p}: the strictest level, not the old meaning`);
    }
    const s = await inMemory.symbolizeFull({ tool: "Read", value: CANARY, field: "content", origin: "/h/deal.md" });
    assert.match(s.symbol, /^\$MDU:nomodel_Read\[/);
    assert.ok(!s.symbol.includes("RETIRED_LEVEL_CANARY"), "the token is opaque");
  } finally {
    inMemory.close();
    await handed.close();
  }

  writeFileSync(file, "version: 1\npaths:\n  - { path: /h/contract.md, level: no-model }\n");
  const server = new ArbiterServer({ ...opts, socketPath: join(dir, "a.sock"), policyPath: file, policyPollMs: 0 });
  await server.listen();
  const data = new ArbiterClient(join(dir, "a.sock"));
  try {
    await data.connect();
    // A valid edit is picked up; a later edit with a retired name is rejected
    // and the last good law stays in force.
    const touch = (text: string, ahead: number) => {
      writeFileSync(file, text);
      const t = new Date(Date.now() + ahead);
      utimesSync(file, t, t);
    };
    const docs = (server as unknown as { policyDocs: { pollDisk(): boolean; status: { valid: boolean; problems: string[] } } }).policyDocs;
    touch("version: 1\npaths:\n  - { path: /h/other.md, level: any-model }\n", 5_000);
    assert.equal(pollDiskApproving(server), true, "the valid edit was picked up (it relaxes, so it is approved, §4.6)");
    assert.equal((await data.pathLevel("/h/other.md")).level, "any-model");
    touch(`version: 1\npaths:\n  - { path: /h/other.md, level: ${OLD_MODEL_OK} }\n`, 10_000);
    docs.pollDisk();
    assert.equal(docs.status.valid, false, "the old-name edit is rejected");
    assert.match(docs.status.problems.join("\n"), /paths\[0\]\.level/);
    assert.equal((await data.pathLevel("/h/other.md")).level, "any-model", "the last good law stays");
  } finally {
    data.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
