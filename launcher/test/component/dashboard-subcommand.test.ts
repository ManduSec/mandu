/**
 * dashboard-subcommand.test — E2E for `mandu dashboard`'s port choice
 * (release checklist a1, runtime-instances.md §8) through the REAL CLI entry
 * (`main(["dashboard"])`), the real runtime registry on disk, the real pid
 * check and real TCP probes. Nothing is spawned: every case resolves before
 * the start path (the start path's port-file handshake is unit-tested with
 * injected deps in test/unit/subcommands.test.ts).
 *
 *   - a live dashboard registered in THIS user's runtime dir is reused, even
 *     on a port that is not 4500 (the registry, not a fixed port, is the
 *     rendezvous);
 *   - a pinned DASHBOARD_PORT held by a server that is NOT a registered
 *     dashboard (another user's, anything) is refused, never handed out.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type AddressInfo, type Server } from "node:net";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const PKG = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..");

async function listen(): Promise<{ srv: Server; port: number }> {
  const srv = createServer((s) => { s.on("error", () => {}); s.end(); });
  srv.listen(0, "127.0.0.1");
  await once(srv, "listening");
  return { srv, port: (srv.address() as AddressInfo).port };
}

/** Run the real CLI as a child (async: the test process keeps serving the
 *  stand-in dashboard's port while the child probes it). */
function cli(env: Record<string, string | undefined>): Promise<{ code: number; out: string; err: string }> {
  return new Promise((resolve) => {
    const child = spawn(join(PKG, "node_modules", ".bin", "tsx"), [join(PKG, "src", "run.ts"), "dashboard"], {
      cwd: PKG, env: env as NodeJS.ProcessEnv, stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => { out += String(d); });
    child.stderr.on("data", (d) => { err += String(d); });
    child.on("close", (code) => resolve({ code: code ?? -1, out, err }));
  });
}

test("mandu dashboard: a live REGISTERED dashboard of this user is reused on whatever port it bound", { timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dash-e2e-"));
  const { srv, port } = await listen();
  try {
    const reg = join(dir, "mandu", "dashboards");
    mkdirSync(reg, { recursive: true });
    // This process stands in for the dashboard: its pid is alive, its port answers.
    writeFileSync(join(reg, `20260926-0000-test-p${process.pid}.json`), JSON.stringify({ pid: process.pid, port, host: "0.0.0.0" }));
    const env = { HOME: process.env["HOME"], PATH: process.env["PATH"], XDG_RUNTIME_DIR: dir, MANDU_HOME: join(dir, "mandu-home") };
    const r = await cli(env);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out, `dashboard already up — http://127.0.0.1:${port}/mandu/\n`, "an entry without basePath predates 2026-09-26: /mandu");
    // A current entry records the prefix it serves under; the URL follows it.
    writeFileSync(join(reg, `20260926-0000-test-p${process.pid}.json`), JSON.stringify({ pid: process.pid, port, host: "0.0.0.0", basePath: "" }));
    const r2 = await cli(env);
    assert.equal(r2.out, `dashboard already up — http://127.0.0.1:${port}/\n`);
  } finally {
    srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mandu dashboard: a link planted at <runtime dir>/dashboard.log refuses the start; nothing is appended through it (runtime-instances.md §2)", { timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dash-e2e-"));
  // An arbiter socket to find (the start path is reached only with one).
  const arb = createServer((s) => { s.on("error", () => {}); s.end(); });
  arb.listen(join(dir, "a.sock"));
  await once(arb, "listening");
  try {
    const base = join(dir, "mandu");
    mkdirSync(base, { recursive: true, mode: 0o700 });
    const victim = join(dir, "victim.rc");
    writeFileSync(victim, "# rc\n");
    symlinkSync(victim, join(base, "dashboard.log"));
    const env = { HOME: process.env["HOME"], PATH: process.env["PATH"], XDG_RUNTIME_DIR: dir, MANDU_HOME: join(dir, "mandu-home"), MANDU_ARBITER_SOCK: join(dir, "a.sock") };
    const r = await cli(env);
    assert.notEqual(r.code, 0, r.out);
    assert.match(r.err, /the log .*dashboard\.log is a symbolic link; refusing to write through it/, r.err);
    assert.equal(readFileSync(victim, "utf8"), "# rc\n", "the linked file is untouched");
    assert.deepEqual(readdirSync(base).filter((n) => n.startsWith("dashboard-")), [], "no dashboard was started (no port file)");
  } finally {
    arb.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mandu dashboard: a PINNED port held by something that is not a registered dashboard is refused", { timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dash-e2e-"));
  const { srv, port } = await listen();
  try {
    const env = { HOME: process.env["HOME"], PATH: process.env["PATH"], XDG_RUNTIME_DIR: dir, MANDU_HOME: join(dir, "mandu-home"), DASHBOARD_PORT: String(port) };
    const r = await cli(env);
    assert.equal(r.code, 1);
    assert.equal(r.out, "", "never a stranger's URL");
    assert.match(r.err, new RegExp(`127\\.0\\.0\\.1:${port} is in use by something that is not one of your Mandu dashboards`));
  } finally {
    srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
