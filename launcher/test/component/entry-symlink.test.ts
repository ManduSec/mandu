/**
 * entry-symlink e2e — the real CLI entry (src/run.ts through tsx) started
 * through a SYMLINKED checkout path still runs.
 *
 * The bootstrap `mandu` shim execs tsx on `$HERE/src/run.ts` with a logical
 * `pwd`, and on darwin /tmp and /var are symlinks: until the guard compared
 * realpaths (src/entrypoint.ts), any symlinked spelling exited 0 with no
 * output — `mandu` silently did nothing. demo.test.ts covers the bundle
 * (`node /tmp/…/dist/mandu.mjs`) on darwin; this file covers the source entry
 * on every host by making the symlink itself.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function run(entry: string, argv: string[], env: Record<string, string>): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(join(PKG, "node_modules", ".bin", "tsx"), [entry, ...argv], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.setEncoding("utf8").on("data", (c: string) => { stdout += c; });
    child.stderr.setEncoding("utf8").on("data", (c: string) => { stderr += c; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

test("`mandu --version` through a symlinked checkout prints the version (it used to exit 0 silently)", async () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-entry-link-"));
  try {
    const link = join(root, "launcher-link");
    symlinkSync(PKG, link);
    const version = (JSON.parse(readFileSync(join(PKG, "package.json"), "utf8")) as { version: string }).version;
    const env = { PATH: process.env["PATH"] ?? "", HOME: root, MANDU_CONFIG: "/dev/null" };

    const direct = await run(join(PKG, "src", "run.ts"), ["--version"], env);
    assert.equal(direct.code, 0, direct.stderr);
    assert.equal(direct.stdout.trim(), `mandu ${version}`, "precondition: the real path answers");

    const viaLink = await run(join(link, "src", "run.ts"), ["--version"], env);
    assert.equal(viaLink.code, 0, viaLink.stderr);
    assert.equal(viaLink.stdout.trim(), `mandu ${version}`, "the symlinked spelling is the same entry");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
