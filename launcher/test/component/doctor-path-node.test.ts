/**
 * doctor-path-node e2e — `mandu doctor` through the real CLI entry (a child
 * process: run.ts → runSubcommand → runDoctor with the REAL host probes)
 * reads the `node` a session's programs would run, the first on PATH, and
 * warns when it is too old to honour the launcher's NODE_USE_ENV_PROXY
 * (confidentiality-plan-13-reader-set-labels.md §10.2): a Node program there
 * goes around Mandu's network proxy, so its secrets are never filled in.
 *
 * The oracle is a fake `node` first on PATH that prints a chosen version for
 * `--version` and hands everything else to the real Node, so the launcher
 * itself still runs on the real one (as when install.sh gives Mandu its own
 * Node and the user's PATH has an older one). No node on PATH at all: no
 * row. Doctor is a diagnostic: exit 0 in every case.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const TSX_CLI = join(PKG, "node_modules", "tsx", "dist", "cli.mjs");

/** `mandu doctor` run by THIS process's Node (never the PATH's), with `env`. */
function doctor(env: Record<string, string>): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [TSX_CLI, join(PKG, "src", "run.ts"), "doctor"], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.setEncoding("utf8").on("data", (c: string) => { stdout += c; });
    child.stderr.setEncoding("utf8").on("data", (c: string) => { stderr += c; });
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ code: code ?? (signal ? 128 : 127), stdout, stderr }));
  });
}

/** The "What Mandu needs" section of a doctor report. */
const needs = (out: string): string => out.slice(out.indexOf("What Mandu needs"), out.indexOf("\nInstalled"));

test("mandu doctor names the node on PATH: ✗ with the fix when it predates NODE_USE_ENV_PROXY, ✓ when it honours it, · when its version is unreadable, nothing without one", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-doctor-path-node-"));
  const home = join(dir, "home");
  const bin = join(dir, "bin");
  const bare = join(dir, "bare");
  for (const d of [home, bin, bare]) mkdirSync(d);
  const fakeNode = join(bin, "node");
  const fake = (version: string): void => {
    writeFileSync(fakeNode, `#!/bin/sh\nif [ "$1" = "--version" ]; then printf '%s\\n' '${version}'; exit 0; fi\nexec '${process.execPath}' "$@"\n`);
    chmodSync(fakeNode, 0o755);
  };
  const base = {
    HOME: home, MANDU_HOME: join(dir, "mandu-home"), XDG_RUNTIME_DIR: dir,
    MANDU_RUNTIME_DIR: join(dir, "rt"), MANDU_ARBITER_SOCK: join(dir, "absent.sock"), MANDU_UPDATE_CHECK: "0",
  };
  const withFake = { ...base, PATH: `${bin}:${process.env["PATH"] ?? ""}` };
  try {
    fake("v22.13.0");
    let r = await doctor(withFake);
    assert.equal(r.code, 0, `doctor is a diagnostic: always exits 0\n${r.stderr}`);
    let n = needs(r.stdout);
    assert.match(n, new RegExp(`✗ node on your PATH is v22\\.13\\.0 \\(${fakeNode.replace(/[.]/g, "\\.")}\\): Node programs in a Mandu session won't have your secrets filled in on their web requests`), r.stdout);
    assert.match(n, /fix: upgrade to Node 22\.21 or newer, or 24\.5 or newer \(nvm install 22\)/);
    assert.match(n, /✓ Node\.js \S+ \(22\.13\.0 or newer\)/, "Mandu's own Node (the real one) is a separate, passing row");

    fake("v24.2.0");
    n = needs((r = await doctor(withFake)).stdout);
    assert.match(n, /✗ node on your PATH is v24\.2\.0 .*on web requests made with http\/https \(fetch works\)/, r.stdout);
    assert.match(n, /fix: upgrade to Node 24\.5 or newer \(nvm install 24\)/);

    fake("v24.21.0");
    n = needs((r = await doctor(withFake)).stdout);
    assert.match(n, /✓ node on your PATH is v24\.21\.0 .*send their web requests through Mandu/, r.stdout);
    assert.doesNotMatch(n, /won't have your secrets filled in|fix: upgrade to Node/);

    fake("not-a-version");
    r = await doctor(withFake);
    assert.equal(r.code, 0, r.stderr);
    assert.match(needs(r.stdout), /· could not read the version of the node on your PATH \(.*: "not-a-version"\)/, r.stdout);

    // No node on PATH at all (the launcher runs on its own Node): no row.
    r = await doctor({ ...base, PATH: bare });
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /What Mandu needs/);
    assert.doesNotMatch(r.stdout, /node on your PATH/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
