/**
 * guard-session-events (sandbox) — the guard's refusals are filed under the
 * session that launched it (exec-routing.md §7.5, "Whose session"; the
 * first-session tour, 2026-10-07).
 *
 *   the REAL launcher (`launcher/src/run.ts` in a child, `--id` naming the
 *   session) in `secrets` mode, the REAL mandu-net-guard as its whole-agent
 *   wrap (guard-only: no bind, no landlock-net, no command box, no proxies),
 *   and a real ArbiterServer whose event store the guard reports to. The
 *   agent is bash, which connects to 192.0.2.1:9 (TEST-NET-1: no allow rule
 *   in the default posture, so the guard refuses it in-kernel).
 *
 * The oracle: the connect is refused (EACCES), and its `net_action` deny is
 * in the session's own log, the id the launch was given; the sessionless
 * `net-guard` log and the session an outer launch left in the environment
 * (`MANDU_SESSION_ID=outer-…`) hold none of it. Red before: the launcher set
 * no session id for the guard, so the deny landed in the `net-guard` log
 * (or, nested, under the outer launch's id).
 *
 * Self-SKIPs off Linux, where the guard is not built, and where its seccomp
 * trap cannot be installed (the launcher then degrades with a banner).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { runLauncher } from "../../lib/launcher-live.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // the default mode: the guard wraps every launch

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const GUARD_ATTACHES = process.platform === "linux" && !!GUARD.path
  && spawnSync(GUARD.path, ["--allow", "tcp:127.0.0.1:1", "--", "true"], { stdio: "ignore", timeout: 15_000 }).status === 0;
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
    : !GUARD_ATTACHES ? "the guard's seccomp trap cannot be installed on this host"
      : false;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("a refused connect under a live launch is filed under the launch's session, not the sessionless net-guard log (secrets axes)", { skip, timeout: 300_000 }, async () => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-guard-session-")));
  const home = join(tmp, "home");
  const ws = join(tmp, "ws");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const sock = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"),
    eventDir: join(tmp, "events"), policyPath: policy, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  // `events` returns originals: the human socket only (arbiter-human-plane.md).
  const client = new ArbiterClient(join(tmp, "human", "h.sock"));
  const sid = `guard-session-${process.pid}`;
  const outer = `outer-${process.pid}`;
  try {
    const script = "timeout 20 bash -c 'exec 3<>/dev/tcp/192.0.2.1/9' 2>/dev/null && echo conn:ok || echo conn:refused";
    const r = await runLauncher(
      ["--target", "claude", "--id", sid, "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy",
        "--no-exec-box", "--no-exec-wrap", "--no-secret-bind", "--net-guard", "--", "/bin/bash", "-c", script],
      {
        HOME: home, PWD: ws, PATH: process.env["PATH"], XDG_RUNTIME_DIR: tmp,
        MANDU_HOME: join(home, ".mandu"), MANDU_ARBITER_SOCK: sock, MANDU_NO_CONTEXT_PROXY: "1", MANDU_MODE: "secrets", MANDU_VERBOSE: "1",
        MANDU_NET_GUARD_BIN: GUARD.path!,
        // An outer launch's id in the environment: this launch's must win.
        MANDU_SESSION_ID: outer,
      },
      ws,
    );
    assert.match(r.out, /net-guard LIVE/, `the guard wrapped the launch:\n${r.out.slice(-3000)}`);
    assert.match(r.out, /conn:refused/, `the connect to 192.0.2.1:9 was refused:\n${r.out.slice(-3000)}`);

    await client.connect();
    const isDeny = (stored: unknown): boolean => {
      const e = stored as { kind?: string; policy?: { usage?: string; reason?: string } };
      return e.kind === "net_action" && e.policy?.usage === "deny" && (e.policy.reason ?? "").includes("192.0.2.1:9");
    };
    // The emit is best-effort and asynchronous to the launch's exit: wait.
    let mine: Awaited<ReturnType<ArbiterClient["events"]>> = [];
    for (let i = 0; i < 50; i++) {
      mine = await client.events(sid);
      if (mine.some(isDeny)) break;
      await new Promise((ok) => setTimeout(ok, 100));
    }
    const elsewhere = [...await client.events("net-guard"), ...await client.events(outer)];
    assert.ok(mine.some(isDeny),
      `the deny is in the session's log (${mine.length} event(s) there; ${elsewhere.filter(isDeny).length} deny(ies) elsewhere)\n${r.out.slice(-2000)}`);
    assert.equal(elsewhere.filter(isDeny).length, 0, "neither the sessionless log nor the outer launch's holds it");
  } finally {
    client.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
