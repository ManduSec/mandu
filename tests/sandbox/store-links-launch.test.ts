/**
 * The store-link refusal e2e (confidentiality-plan-14 §11.2 residual (c)),
 * across the REAL launcher: main() in `secrets` mode with a REAL
 * ArbiterServer, the Mandu home's event log swapped for a symlink to a
 * directory outside the home (as something that ran unconfined could leave
 * it). Every layer that keeps the agent out of Mandu's stores names the
 * home, so the store behind that link would be readable and writable by the
 * agent. The launch is refused before the agent starts (its script never
 * runs), and the refusal names the store and the fix; with the link gone
 * the same launch runs. Self-SKIPs off Linux.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const skip = process.platform !== "linux" ? "linux only" : false;

test("a launch with Mandu's event log swapped for a symlink outside the home is refused before the agent starts; with the link gone it runs", { skip, timeout: 120_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-store-links-"));
  const home = join(dir, "home");
  const mh = join(home, ".mandu");
  const planted = join(dir, "planted");
  mkdirSync(mh, { recursive: true, mode: 0o700 });
  mkdirSync(planted, { mode: 0o700 });
  symlinkSync(planted, join(mh, "events"));
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "mandu", "human", "i.sock"),
    dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const lines: string[] = [];
  const orig = console.error;
  const saved = { home: process.env["HOME"], mh: process.env["MANDU_HOME"] };
  const ran = join(dir, "ran");
  const launch = (): Promise<number> => main(
    ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "bash", "-c", `touch ${ran}`],
    {
      HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], MANDU_NO_CONTEXT_PROXY: "1",
      MANDU_HOME: mh, MANDU_MODE: "secrets", XDG_RUNTIME_DIR: dir,
    },
  );
  try {
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["HOME"] = home;
    process.env["MANDU_HOME"] = mh;
    let code: number | null = null;
    let thrown = "";
    try { code = await launch(); } catch (e) { thrown = (e as Error).message; }
    const log = `${thrown}\n${lines.join("\n")}`;
    // MASTER: code 0, the agent ran
    assert.notEqual(code, 0, `refused: ${log}`);
    assert.match(log, /Mandu's stores must lie inside its home/);
    assert.match(log, /events resolves to .*planted/);
    assert.ok(!existsSync(ran), "the agent never started");

    rmSync(join(mh, "events"));
    lines.length = 0;
    assert.equal(await launch(), 0, lines.join("\n"));
    assert.ok(existsSync(ran), "with the link gone the launch runs");
  } finally {
    console.error = orig;
    for (const [k, v] of [["HOME", saved.home], ["MANDU_HOME", saved.mh]] as const) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
