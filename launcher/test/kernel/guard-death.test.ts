/**
 * guard-death e2e — a launch whose guard dies before its agent ends the
 * session and says so (src/guard-death.ts; rootless-confinement-ubuntu-2404.md
 * §12.2). Real components: main() on the no-scope path, the REAL
 * mandu-net-guard (its status file, its child's PR_SET_PDEATHSIG), a bash
 * "agent" that starts a background tool. The guard is SIGKILLed from outside
 * the session (the agent itself cannot: guard-death-live.test.sh); the
 * agent's top process dies with it, the launcher kills the leftover tool by
 * session and prints the note. A control launch whose agent exits normally
 * prints nothing. Self-SKIPs where the guard is not built.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { createServer, type Server } from "node:net";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { answerUnavailable } from "../lib/unanswered-arbiter.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const INTERCEPTORS = resolve(HERE, "..", "..", "..", "interceptors", "target");
const GUARD = ["release", "debug"].map((p) => join(INTERCEPTORS, p, "mandu-net-guard")).find(existsSync);
const skip = process.platform !== "linux" || !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;

async function launch(dir: string, sock: string, script: string): Promise<{ code: number; lines: string[] }> {
  const lines: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  const saved = process.env["MANDU_NET_GUARD_BIN"];
  process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
  try {
    const code = await main(
      ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "bash", "-c", script],
      {
        HOME: process.env["HOME"], PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dir,
      },
    );
    return { code, lines };
  } finally {
    console.error = orig;
    if (saved === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = saved;
  }
}

const alive = (pid: number): boolean => {
  try {
    // A zombie is dead for this purpose.
    return !/^\S+ \(.*\) Z/.test(readFileSync(`/proc/${pid}/stat`, "utf8"));
  } catch {
    return false;
  }
};

async function waitFor<T>(f: () => T | null, ms = 20_000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = f();
    if (v !== null) return v;
    if (Date.now() > end) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 50));
  }
}

test("the guard killed mid-session: the agent dies with it, the leftover tool is killed, and the launch says why", { skip }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-guard-death-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  try {
    const guardFile = join(dir, "guard.pid");
    const toolFile = join(dir, "tool.pid");
    // Find the guard up the parent chain, start a background tool, wait.
    const script =
      `p=$PPID; while [ "$p" -gt 1 ]; do read -r c < /proc/$p/comm; [ "$c" = mandu-net-guard ] && break; read -r -a s < /proc/$p/stat; p=\${s[3]}; done; ` +
      `sleep 60 & echo $! > ${toolFile}; echo $$ > ${join(dir, "agent.pid")}; echo $p > ${guardFile}; wait`;
    const run = launch(dir, sock, script);
    let failed: unknown = null;
    run.catch((e) => { failed = e; });
    const guard = await waitFor(() => {
      if (failed) throw failed;
      return existsSync(guardFile) ? Number(readFileSync(guardFile, "utf8")) || null : null;
    });
    const tool = Number(readFileSync(toolFile, "utf8"));
    const agent = Number(readFileSync(join(dir, "agent.pid"), "utf8"));
    assert.equal(readFileSync(`/proc/${guard}/comm`, "utf8").trim(), "mandu-net-guard");
    assert.ok(alive(tool) && alive(agent));
    process.kill(guard, "SIGKILL");
    const r = await run;
    assert.notEqual(r.code, 0, "the launch does not report success");
    assert.ok(r.lines.some((l) => /the guard \(mandu-net-guard, pid \d+\) stopped before the agent did/.test(l) && /ENOSYS/.test(l)), JSON.stringify(r.lines));
    assert.equal(alive(agent), false, "the agent's top process died with its guard (PR_SET_PDEATHSIG)");
    await waitFor(() => (alive(tool) ? null : true), 5_000);
    assert.equal(alive(tool), false, "the tool it left behind was killed with the session");
  } finally {
    srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("control: an agent that exits normally under the guard gets no note", { skip }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-guard-death-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  try {
    const r = await launch(dir, sock, "exit 3");
    assert.equal(r.code, 3);
    assert.ok(!r.lines.some((l) => /stopped before the agent did/.test(l)), JSON.stringify(r.lines));
  } finally {
    srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
