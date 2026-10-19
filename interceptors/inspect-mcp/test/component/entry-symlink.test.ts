/**
 * entry-symlink e2e — server-main.ts started through a SYMLINKED package path
 * reaches main(): with no MANDU_ARBITER_SOCK it refuses loudly (exit 1, the
 * fail-closed message) instead of exiting 0 before serving anything, which is
 * what the literal import.meta.url === argv[1] guard did under any symlinked
 * spelling (darwin's /tmp and /var are symlinks).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function run(entry: string, env: Record<string, string>): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(join(PKG, "node_modules", ".bin", "tsx"), [entry], { env, stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.setEncoding("utf8").on("data", (c: string) => { stderr += c; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, stderr }));
  });
}

test("inspect-mcp server-main through a symlinked package path runs main() (fails closed without an arbiter socket)", async () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-inspect-link-"));
  try {
    symlinkSync(PKG, join(root, "pkg-link"));
    const env = { PATH: process.env["PATH"] ?? "", HOME: root };
    for (const entry of [join(PKG, "src", "server-main.ts"), join(root, "pkg-link", "src", "server-main.ts")]) {
      const r = await run(entry, env);
      assert.equal(r.code, 1, `${entry}: main() ran and refused\n${r.stderr}`);
      assert.match(r.stderr, /\[inspect-mcp\] MANDU_ARBITER_SOCK is not set — cannot reach the arbiter \(fail closed\)/);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
