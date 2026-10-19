/**
 * entrypoint.test — the realpath-aware entry guard of server-main.ts
 * (src/entrypoint.ts, a copy of launcher/src/entrypoint.ts), pure and through
 * a spawned server (this package has no e2e directory; the spawn is quick).
 *
 * Node hands the main module its REAL path as import.meta.url while argv[1]
 * keeps the typed spelling; on darwin /tmp and /var are symlinks, so the old
 * literal comparison made a server started under a symlinked spelling exit 0
 * before serving anything.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isEntrypoint } from "../../src/entrypoint.js";

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("isEntrypoint: the literal path and a symlinked directory name the entry; another module, a missing path or no argv do not", () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-policy-entry-"));
  try {
    const real = join(root, "real");
    mkdirSync(real);
    const mod = join(real, "server-main.mjs");
    writeFileSync(mod, "");
    writeFileSync(join(real, "other.mjs"), "");
    symlinkSync(real, join(root, "link"));
    const url = pathToFileURL(mod).href;
    assert.equal(isEntrypoint(url, mod), true);
    assert.equal(isEntrypoint(url, join(root, "link", "server-main.mjs")), true, "through a symlinked directory (darwin /tmp → /private/tmp)");
    assert.equal(isEntrypoint(url, join(real, "other.mjs")), false);
    assert.equal(isEntrypoint(url, join(root, "missing.mjs")), false);
    assert.equal(isEntrypoint(url, undefined), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function run(entry: string, env: Record<string, string>): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(join(PKG, "node_modules", ".bin", "tsx"), [entry], { env, stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.setEncoding("utf8").on("data", (c: string) => { stderr += c; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, stderr }));
  });
}

test("policy-mcp server-main through a symlinked package path runs main() (fails closed without an arbiter socket)", async () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-policy-link-"));
  try {
    symlinkSync(PKG, join(root, "pkg-link"));
    const env = { PATH: process.env["PATH"] ?? "", HOME: root };
    for (const entry of [join(PKG, "src", "server-main.ts"), join(root, "pkg-link", "src", "server-main.ts")]) {
      const r = await run(entry, env);
      assert.equal(r.code, 1, `${entry}: main() ran and refused\n${r.stderr}`);
      assert.match(r.stderr, /\[policy-mcp\] MANDU_ARBITER_SOCK is not set; cannot reach the arbiter \(fail closed\)/);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
