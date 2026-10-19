/**
 * services.test — E2E for the service-manager phase: the exec-shim + mcp
 * services actually run and their wiring reaches the spawned agent, and a
 * requested-but-unavailable hardening flag fails the wired launch closed.
 *
 * PROJECT INVARIANT (fail-closed): a requested gate that cannot be provided
 * must ABORT the launch, never launch the agent without it (spec §5).
 *
 * Robustness note: we assert on MANDU_EXECWRAP_SHIM_DIR and on the shim dir's
 * PRESENCE in PATH (not PATH[0]) because a dev shell's ~/.bashrc may re-prepend
 * its own entries when bash sources it under the test runner's pipe stdio — the
 * composer still put the shim dir on PATH, just not necessarily first. The exact
 * PATH-prepend is separately proven in test/unit/env-compose.test.ts.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import assert from "node:assert/strict";
import { createServer, connect, type Server, type AddressInfo } from "node:net";
import { mkdtempSync, mkdirSync, rmSync, existsSync, readFileSync, readdirSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { once } from "node:events";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { unavailableReply } from "../lib/unanswered-arbiter.js";
import { standInService, withClaudeShimAssets } from "../lib/stand-in-service.js";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { startServices } from "../../src/services/manager.js";
import { Layout } from "../../src/services/layout.js";
import { PROBE_CACHE_ENV, disableProbeCache, enableProbeCache, parseCacheFile, probeCacheHits } from "../../src/probe-cache.js";
import type { LaunchPlan } from "../../src/types.js";

async function withMockArbiter(
  fn: (sock: string, dir: string) => Promise<void>,
  // Optional per-NDJSON-line responder. The default answers every request with
  // the bare failure the launcher reads as "no answer" (test/lib/
  // unanswered-arbiter.ts): a mock that swallowed requests made each launch
  // wait out its readers' deadlines, about 20 s per launch.
  respondLine: (line: string) => string = unavailableReply,
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-svc-"));
  const sock = join(dir, "arbiter.sock");
  // Track accepted connections and destroy them on cleanup: srv.close() alone
  // waits for clients to hang up, so a leaked service still holding its arbiter
  // connection would keep this process's event loop alive (test hang, not fail).
  const conns = new Set<import("node:net").Socket>();
  const srv: Server = createServer((s) => {
    conns.add(s);
    s.on("close", () => conns.delete(s));
    let buf = "";
    s.on("error", () => { /* the launcher's readers hang up as soon as they have a line */ });
    s.on("data", (d) => {
      buf += String(d);
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!s.destroyed) s.write(respondLine(line) + "\n");
      }
    });
  });
  srv.listen(sock);
  await once(srv, "listening");
  try { await fn(sock, dir); } finally {
    srv.close();
    for (const s of conns) s.destroy();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("--exec-wrap: shims written + shim env reaches the agent; the inspect-mcp config lands in the scope run dir, NOT the cwd", async () => {
  await withMockArbiter(async (sock, dir) => {
    const outFile = join(dir, "out.json");
    const fake = join(dir, "fake.sh");
    // The agent reports the shim-dir env (untouched by ~/.bashrc) and whether the
    // shim dir is anywhere on PATH — both robust proofs the exec-wrap wiring landed.
    // It also looks for the shim and the MCP config WHILE it runs: a clean exit
    // removes the scope run dir they live in (runtime-instances.md §10.1).
    writeFileSync(
      fake,
      `#!/usr/bin/env bash\n` +
        `case ":$PATH:" in *":$MANDU_EXECWRAP_SHIM_DIR:"*) onpath=yes ;; *) onpath=no ;; esac\n` +
        `[ -x "$MANDU_EXECWRAP_SHIM_DIR/curl" ] && shim=yes || shim=no\n` +
        `[ -f "$(dirname "$MANDU_EXECWRAP_SHIM_DIR")/mcp.json" ] && mcp=yes || mcp=no\n` +
        `printf '{"shimDir":"%s","onpath":"%s","shim":"%s","mcp":"%s"}\\n' "\${MANDU_EXECWRAP_SHIM_DIR:-}" "$onpath" "$shim" "$mcp" > ${outFile}\n`,
    );
    chmodSync(fake, 0o755);

    // XDG_RUNTIME_DIR: contain the scope run dir (<runtimeDir>/mandu/<scopeId>,
    // exec-shims / service logs) in the tmp tree withMockArbiter rmSyncs — no
    // /tmp/mandu/* leak per run. Same for the other two tests below.
    const code = await main(
      ["--target", "claude", "--exec-wrap=curl", "--no-scope", "--", "bash", "-c", fake],
      // A temp MANDU_HOME with no config.toml keeps every e2e main() hermetic: the
      // developer's real ~/.mandu/config.toml must never leak in.
      { HOME: process.env["HOME"], PWD: dir, XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off" },
    );
    assert.equal(code, 0);
    const got = JSON.parse(readFileSync(outFile, "utf8"));
    assert.match(got.shimDir, /exec-shims$/);            // composer set the shim-dir env on the agent
    assert.equal(got.onpath, "yes");                     // shim dir reached the agent's PATH
    assert.equal(got.shim, "yes");                       // the service wrote the shim
    // The inspect-mcp config sits NEXT TO the shims in the scope run dir and is
    // delivered by --mcp-config; a project-scope <cwd>/.mcp.json would raise
    // Claude Code's "New MCP server found" approval dialog at the default
    // permission posture and litter the workspace (services/mcp.ts header).
    assert.equal(got.mcp, "yes", "mcp.json in the scope run dir");
    assert.equal(existsSync(dirname(got.shimDir)), false, "the clean exit removed the scope run dir");
    assert.ok(!existsSync(join(dir, ".mcp.json")), "no project-scope .mcp.json litter in the cwd");
  });
});

test("exec-wrap whose dependencies are missing: never reported LIVE; the default launch runs without its shims, an explicit --exec-wrap is refused", async () => {
  await withMockArbiter(async (sock, dir) => {
    // A checkout that never installed interceptors/exec-wrap: the shims the
    // launcher writes would crash on every call (portable-wrapper.md §5).
    const fakeRepo = join(dir, "repo-without-exec-wrap-deps");
    mkdirSync(join(fakeRepo, "interceptors", "exec-wrap", "src"), { recursive: true });
    withClaudeShimAssets(fakeRepo); // a real install ships the claude shim's preload (agent-sdks.md §3.5)
    const outFile = join(dir, "out.json");
    const fake = join(dir, "fake.sh");
    writeFileSync(
      fake,
      `#!/usr/bin/env bash\n` +
        `case ":$PATH:" in *exec-shims*) onpath=yes ;; *) onpath=no ;; esac\n` +
        `printf '{"shimDir":"%s","onpath":"%s"}\\n' "\${MANDU_EXECWRAP_SHIM_DIR:-}" "$onpath" > ${outFile}\n`,
    );
    chmodSync(fake, 0o755);
    const env = {
      HOME: process.env["HOME"], PWD: dir, XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", MANDU_DEV_REPO: fakeRepo, MANDU_VERBOSE: "1",
    };
    const stderr: string[] = [];
    const origErr = console.error;
    console.error = (...a: unknown[]) => { stderr.push(a.map(String).join(" ")); };
    let code: number;
    try {
      // Default-on exec-wrap (no flag): degraded, loudly; the agent still runs.
      code = await main(["--target", "claude", "--no-net-proxy", "--no-mcp", "--no-scope", "--", "bash", "-c", fake], env);
    } finally {
      console.error = origErr;
    }
    assert.equal(code, 0);
    const got = JSON.parse(readFileSync(outFile, "utf8"));
    assert.equal(got.shimDir, "", "no shim dir handed to the agent");
    assert.equal(got.onpath, "no", "no shim that cannot load shadows the agent's PATH");
    const log = stderr.join("\n");
    assert.doesNotMatch(log, /exec-wrap LIVE/, "never reported LIVE");
    assert.match(log, /exec-wrap' is on by default but failed to start: the exec-wrap shim cannot load/);

    // Explicit --exec-wrap: refused before the agent runs.
    rmSync(outFile, { force: true });
    await assert.rejects(
      main(["--target", "claude", "--exec-wrap=curl", "--no-net-proxy", "--no-mcp", "--no-scope", "--", "bash", "-c", fake], env),
      /service 'exec-wrap' was requested but failed to start: the exec-wrap shim cannot load/,
    );
    assert.equal(existsSync(outFile), false, "the agent never ran");
  });
});

test("fail-closed: a retired hardening flag (--unshare) refuses the wired launch", async () => {
  await withMockArbiter(async (sock, dir) => {
    // --unshare was retired 2026-07-14 (with fs-preload): requesting it must
    // refuse the launch with the retirement error — never launch the agent as
    // if the request had been honored. Deterministic (parse-time, no spawn).
    await assert.rejects(
      main(["--target", "claude", "--unshare", "--no-scope", "--", "bash", "-c", "echo SHOULD_NOT_RUN"], {
        HOME: process.env["HOME"], PWD: dir, XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off",
      }),
      /unshare was retired/,
    );
  });
});

/** The port a launch's context proxy published in its port file (port 0: the
 *  kernel picked it), found under the test's runtime dir. A picked-then-freed
 *  port could be taken by a suite running alongside (test-organization.md §8.4). */
function publishedProxyPort(dir: string): number | null {
  const walk = (d: string): string | null => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) { const hit = walk(p); if (hit) return hit; }
      else if (e.name === "anthropic-proxy.port") return p;
    }
    return null;
  };
  const f = walk(dir);
  if (!f) return null;
  const port = Number(readFileSync(f, "utf8").trim());
  return Number.isInteger(port) && port > 0 ? port : null;
}

/** Is something accepting TCP connections at 127.0.0.1:port right now? */
function portUp(port: number, timeoutMs = 500): Promise<boolean> {
  return new Promise((resolve) => {
    const s = connect({ host: "127.0.0.1", port });
    const done = (ok: boolean) => { s.destroy(); resolve(ok); };
    s.setTimeout(timeoutMs);
    s.once("connect", () => done(true));
    s.once("timeout", () => done(false));
    s.once("error", () => done(false));
  });
}

test("ephemeral proxy port (MANDU_PROXY_PORT=0): agent gets a real bound port; teardown after exit", { timeout: 60_000 }, async () => {
  await withMockArbiter(async (sock, dir) => {
    // Port 0 = the kernel picks. The REAL anthropic-proxy publishes the bound
    // port via the port file; the launcher adopts it into the composed
    // ANTHROPIC_BASE_URL. No fixed rendezvous → no stale daemon can ever
    // collide with this launch (the orphaned-run contention class).
    const outFile = join(dir, "base-url.txt");
    const fake = join(dir, "fake.sh");
    writeFileSync(fake, `#!/usr/bin/env bash\nprintf '%s' "\${ANTHROPIC_BASE_URL:-}" > ${outFile}\n`);
    chmodSync(fake, 0o755);
    const code = await main(
      ["--target", "claude", "--no-net-proxy", "--no-scope", "--", "bash", "-c", fake],
      { HOME: process.env["HOME"], PWD: dir, XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], MANDU_MCP_CONFIG: join(dir, ".mcp.json"), MANDU_PROXY_PORT: "0", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off" },
    );
    assert.equal(code, 0);
    const baseUrl = readFileSync(outFile, "utf8");
    const m = baseUrl.match(/^http:\/\/127\.0\.0\.1:(\d+)$/);
    assert.ok(m, `agent saw a composed base URL with a real port, got '${baseUrl}'`);
    const port = Number(m![1]);
    assert.ok(port > 0, "kernel-assigned port is nonzero");
    // postExit teardown: the proxy must be gone (SIGTERM + severed lifeline).
    let down = false;
    for (let i = 0; i < 50 && !down; i++) {
      down = !(await portUp(port));
      if (!down) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(down, `context proxy still listening on 127.0.0.1:${port} after agent exit (orphaned)`);
  });
});

test("DEFAULT ports (release checklist a1): with NO port env at all, the REAL context proxy AND the REAL egress proxy come up on kernel-assigned ports through the port-file handshake", { timeout: 90_000 }, async () => {
  await withMockArbiter(async (sock, dir) => {
    // The built-in default used to be 8788 (context) / 8790 (egress): a second
    // user or a resident stack on the host made this launch refuse (context) or
    // silently lose its egress gate (net-proxy). Now both default to 0. The
    // assertion below that neither proxy landed on its old port proves it;
    // the test no longer squats on 8788/8790 itself, which a suite running
    // alongside could need (test-organization.md §8.4).
    const outFile = join(dir, "env.txt");
    const fake = join(dir, "fake.sh");
    writeFileSync(fake, `#!/usr/bin/env bash\nprintf '%s\\n%s\\n' "\${ANTHROPIC_BASE_URL:-}" "\${HTTP_PROXY:-}" > ${outFile}\n`);
    chmodSync(fake, 0o755);
    const env: Record<string, string | undefined> = {
      HOME: process.env["HOME"], PWD: dir, XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
      MANDU_MCP_CONFIG: join(dir, ".mcp.json"), MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off",
      MANDU_NO_KERNEL: "1",
    };
    // Nothing port-shaped may leak in from the runner's env.
    for (const k of ["MANDU_PROXY_PORT", "MANDU_NET_PROXY_PORT", "MANDU_OPENAI_PROXY_PORT"]) delete env[k];
    const saved = process.env["MANDU_NET_PROXY_PORT"];
    delete process.env["MANDU_NET_PROXY_PORT"]; // the net-proxy service reads the PROCESS env
    let code: number;
    try {
      code = await main(["--target", "claude", "--no-scope", "--", "bash", "-c", fake], env);
    } finally {
      if (saved !== undefined) process.env["MANDU_NET_PROXY_PORT"] = saved;
    }
    assert.equal(code, 0);
    const [baseUrl, httpProxy] = readFileSync(outFile, "utf8").split("\n");
    const ctx = baseUrl!.match(/^http:\/\/127\.0\.0\.1:(\d+)$/);
    const egress = httpProxy!.match(/^http:\/\/127\.0\.0\.1:(\d+)\/?$/);
    assert.ok(ctx, `the agent saw a context-proxy base URL with a real port, got '${baseUrl}'`);
    assert.ok(egress, `the agent saw the egress gate (HTTP_PROXY) with a real port, got '${httpProxy}'`);
    for (const [name, m, wellKnown] of [["context", ctx, 8788], ["egress", egress, 8790]] as const) {
      const port = Number(m![1]);
      assert.ok(port > 0 && port !== wellKnown, `${name} proxy on a kernel-assigned port, got ${port}`);
    }
  });
});

test("a failed egress proxy REFUSES the launch (release checklist a1): the agent never runs; --no-net-proxy is the deliberate opt-out", { timeout: 90_000 }, async () => {
  await withMockArbiter(async (sock, dir) => {
    // A pinned net-proxy port held by a FOREIGN server: the conflict class the
    // old soft default turned into "proceeding WITHOUT it" after one warning.
    const foreign = createServer((s) => {
      s.on("error", () => { /* the probe hangs up first: not this test's concern */ });
      s.once("data", () => s.end("HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n"));
    });
    foreign.listen(0, "127.0.0.1");
    await once(foreign, "listening");
    const port = (foreign.address() as AddressInfo).port;
    const marker = join(dir, "ran");
    const env: Record<string, string | undefined> = {
      HOME: process.env["HOME"], PWD: dir, XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", MANDU_NO_KERNEL: "1",
    };
    const saved = process.env["MANDU_NET_PROXY_PORT"];
    process.env["MANDU_NET_PROXY_PORT"] = String(port);
    try {
      await assert.rejects(
        main(["--target", "claude", "--no-scope", "--", "bash", "-c", `touch ${marker}`], env),
        (e: Error) => /egress gate \(net-proxy\) could not start/.test(e.message) && /--no-net-proxy/.test(e.message),
      );
      assert.ok(!existsSync(marker), "the agent never ran without its egress gate");
      // The deliberate opt-out launches (no gate, by the user's choice).
      const code = await main(["--target", "claude", "--no-net-proxy", "--no-scope", "--", "bash", "-c", `touch ${marker}`], env);
      assert.equal(code, 0);
      assert.ok(existsSync(marker), "--no-net-proxy launches");
    } finally {
      if (saved === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = saved;
      foreign.close();
    }
  });
});

/**
 * A stand-in repo whose anthropic-proxy entry is `body`, so the launcher's
 * REAL detached spawner, readiness wait and teardown run against a proxy that
 * misbehaves on purpose (MANDU_DEV_REPO points the dev layout at it). The
 * script records its pid in `pidFile`.
 */
function standInProxyRepo(root: string, body: string): void {
  standInService(root, "anthropic-proxy", join("interceptors", "anthropic-proxy"), body);
}

const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };

test("readiness deadline (runtime-instances.md §14.6): a context proxy that NEVER becomes ready fails the launch CLOSED at the deadline; the agent never runs and the proxy is torn down", { timeout: 60_000 }, async () => {
  await withMockArbiter(async (sock, dir) => {
    const repo = join(dir, "repo");
    const pidFile = join(dir, "proxy.pid");
    // Alive, never publishes a port file, never listens: the saturated-host
    // shape seen from the launcher's side.
    standInProxyRepo(repo, `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(pidFile)}, String(process.pid));\nsetInterval(() => {}, 1e6);\n`);
    const marker = join(dir, "ran");
    const saved = process.env["MANDU_SERVICE_READY_TIMEOUT_MS"];
    process.env["MANDU_SERVICE_READY_TIMEOUT_MS"] = "2500"; // the services read the PROCESS env
    const t0 = Date.now();
    try {
      await assert.rejects(
        main(["--target", "claude", "--no-net-proxy", "--no-scope", "--", "bash", "-c", `touch ${marker}`], {
          HOME: process.env["HOME"], PWD: dir, XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
          MANDU_DEV_REPO: repo, MANDU_PROXY_PORT: "0", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", MANDU_NO_KERNEL: "1",
        }),
        (e: Error) => {
          assert.match(e.message, /service 'context-proxy' was requested but failed to start/);
          assert.match(e.message, /anthropic-proxy \(context proxy\) did not come up \(no port file at .*: not ready within 2500 ms; MANDU_SERVICE_READY_TIMEOUT_MS/);
          assert.match(e.message, /--best-effort/);
          return true;
        },
      );
    } finally {
      if (saved === undefined) delete process.env["MANDU_SERVICE_READY_TIMEOUT_MS"]; else process.env["MANDU_SERVICE_READY_TIMEOUT_MS"] = saved;
    }
    assert.ok(Date.now() - t0 >= 2000, "the launch waited for the deadline");
    assert.ok(!existsSync(marker), "the agent never ran without its context proxy");
    // The proxy that never came up is torn down, not orphaned.
    const pid = Number(readFileSync(pidFile, "utf8"));
    let gone = false;
    for (let i = 0; i < 50 && !gone; i++) {
      gone = !alive(pid);
      if (!gone) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(gone, `stand-in proxy ${pid} still running after the fail-closed abort`);
  });
});

test("readiness deadline: a context proxy that EXITS before it is ready fails the launch closed at once, naming the exit (no deadline wait)", { timeout: 60_000 }, async () => {
  await withMockArbiter(async (sock, dir) => {
    const repo = join(dir, "repo");
    standInProxyRepo(repo, `process.exit(3);\n`);
    const marker = join(dir, "ran");
    const saved = process.env["MANDU_SERVICE_READY_TIMEOUT_MS"];
    process.env["MANDU_SERVICE_READY_TIMEOUT_MS"] = "45000"; // long: the exit, not the deadline, must end the wait
    const t0 = Date.now();
    try {
      await assert.rejects(
        main(["--target", "claude", "--no-net-proxy", "--no-scope", "--", "bash", "-c", `touch ${marker}`], {
          HOME: process.env["HOME"], PWD: dir, XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
          MANDU_DEV_REPO: repo, MANDU_PROXY_PORT: "0", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", MANDU_NO_KERNEL: "1",
        }),
        /context proxy\) did not come up \(no port file at .*: it exited with code \d+ before becoming ready/,
      );
    } finally {
      if (saved === undefined) delete process.env["MANDU_SERVICE_READY_TIMEOUT_MS"]; else process.env["MANDU_SERVICE_READY_TIMEOUT_MS"] = saved;
    }
    assert.ok(Date.now() - t0 < 30_000, `ended on the exit, not the 45 s deadline (took ${Date.now() - t0} ms)`);
    assert.ok(!existsSync(marker), "the agent never ran");
  });
});

test("fail-closed abort AFTER services started tears the context proxy back down (no orphan)", { timeout: 60_000 }, async () => {
  await withMockArbiter(async (sock, dir) => {
    // No MANDU_NO_CONTEXT_PROXY: the manager autostarts the REAL
    // anthropic-proxy (its serve binds the port and only dials the arbiter
    // socket, which the mock provides). --confidentiality then asks for secret
    // confinement, whose discovery IPC the mock arbiter answers with an ERROR →
    // applySecretTwins REFUSES (fail-closed, secret-setup.ts) AFTER services
    // started — the abort path must tear the just-started proxy down instead of
    // orphaning it. (--unshare used to drive this via the deferred linux-userns
    // stub; it was retired 2026-07-14 and now fails at parse, before any
    // service starts.) --require-confinement makes the refusal independent of
    // the host: a host that cannot confine at all (no bwrap, no guard, e.g. a
    // fresh VM guest) only WARNS on an arbiter failure and launches gated, and
    // this test then passed nowhere but a developer box (os-test-matrix run
    // 2026-09-25). Strict, both postures refuse after services started.
    await assert.rejects(
      main(["--target", "claude", "--confidentiality", "--require-confinement", "--no-scope", "--", "bash", "-c", "echo SHOULD_NOT_RUN"], {
        HOME: process.env["HOME"], PWD: dir, XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
        MANDU_PROXY_PORT: "0", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off",
      }),
      (e: Error) => {
        assert.match(e.message, /protects your secrets|--require-confinement is set/);
        // The way out speaks the mode vocabulary (protection-modes.md §8),
        // whichever refusal this host's posture reached.
        assert.match(e.message, /turn secret protection off\s+for this launch(: | \()--mode off\b/);
        assert.doesNotMatch(e.message, /--(no-)?confidentiality/);
        return true;
      },
    );
    // The proxy came up (on the port its file names) before the abort.
    const port = publishedProxyPort(dir);
    assert.ok(port, "the context proxy published its kernel-assigned port before the abort");
    // Poll up to ~5s: SIGTERM delivery to the detached proxy group is async.
    let down = false;
    for (let i = 0; i < 50 && !down; i++) {
      down = !(await portUp(port));
      if (!down) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(down, `context proxy still listening on 127.0.0.1:${port} after the fail-closed abort (orphaned)`);
  }, () => JSON.stringify({ ok: false, error: "mock arbiter has no secrets API" }));
});

test("the exec-wrap shim's load probe is kept for the boot (portable-wrapper.md §5): the REAL bundle, shims, probe and cache file; a kept pass skips the node start, a rebuilt bundle and the bypass probe again, a shim that cannot load is never kept and still degrades or refuses", { timeout: 120_000 }, async () => {
  const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  const dir = mkdtempSync(join(tmpdir(), "mandu-shim-cache-"));
  const savedPath = process.env["PATH"];
  try {
    // An installed-form package: the real exec-wrap and arbiter client,
    // bundled the way build-bundle.mjs bundles them.
    const pkg = join(dir, "pkg");
    const dist = join(pkg, "dist");
    const bundle = async (entry: string, name: string): Promise<void> => {
      await build({ entryPoints: [join(repo, entry)], outfile: join(dist, `${name}.mjs`), bundle: true, platform: "node", format: "esm", target: "node22", logLevel: "warning" });
    };
    await bundle("interceptors/exec-wrap/src/wrap.ts", "exec-shim");
    await bundle("arbiter/ipc/client.ts", "arbiter-client");
    const layout = Layout.installed(pkg);
    // `node` on the probe's PATH is a stand-in that counts every start, then
    // runs the real node: the count is the number of real probes.
    const bin = join(dir, "bin");
    mkdirSync(bin);
    const starts = join(dir, "node-starts");
    writeFileSync(join(bin, "node"), `#!/bin/sh\necho start >> '${starts}'\nexec '${process.execPath}' "$@"\n`);
    chmodSync(join(bin, "node"), 0o755);
    process.env["PATH"] = `${bin}:${savedPath ?? ""}`;
    const nodeStarts = (): number => (existsSync(starts) ? readFileSync(starts, "utf8").split("\n").filter(Boolean).length : 0);
    const cacheDir = join(dir, "rt", "probe-cache");
    mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    const cacheFile = join(cacheDir, "kernel-probes.json");
    const kept = (): boolean => existsSync(cacheFile) && parseCacheFile(readFileSync(cacheFile, "utf8"))!.entries["exec-shim"] !== undefined;

    let n = 0;
    const launchOnce = async (o: { execWrap?: true; env?: Record<string, string> } = {}): Promise<{ plan: LaunchPlan; warnings: string[]; error: Error | null; hits: readonly string[] }> => {
      n++;
      const p: LaunchPlan = {
        target: "claude", argv: ["claude"], scopeId: `s${n}`, tenant: "live", arbiterSock: join(dir, `arbiter-${n}.sock`), arbiterSockMode: "pinned",
        arbiterRuntimeBase: dir, eventDir: dir, cwd: dir, humanCwd: dir, noContextProxy: true, fsSync: false, basePath: "/usr/bin",
        proxy: { host: "127.0.0.1", port: 1 }, openaiProxy: { host: "127.0.0.1", port: 1 }, openaiProviderName: "mandu", noProxyExtra: [],
        requested: { netProxy: false, netProxyMitm: false, execWrap: o.execWrap }, execWrapCmds: ["curl", "wget"],
        ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" }, landlockNet: false,
        noScope: true, writeMcp: false, bestEffort: false, replyFilter: false,
      };
      const warnings: string[] = [];
      enableProbeCache({ PATH: process.env["PATH"], ...o.env }, { file: cacheFile });
      try {
        // The production deps (undefined): the real writer, the real cached probe.
        const h = await startServices(p, layout, join(dir, `scope-${n}`), undefined, (m) => warnings.push(m));
        await h.stop();
        return { plan: p, warnings, error: null, hits: [...probeCacheHits()] };
      } catch (e) {
        return { plan: p, warnings, error: e as Error, hits: [...probeCacheHits()] };
      } finally {
        disableProbeCache();
      }
    };
    const live = (r: { warnings: string[] }): boolean => r.warnings.some((w) => /^exec-wrap LIVE/.test(w));

    // 1. The first launch of the boot probes (one node start) and keeps the pass.
    const a = await launchOnce();
    assert.equal(a.error, null);
    assert.ok(live(a), JSON.stringify(a.warnings));
    assert.equal(nodeStarts(), 1);
    assert.ok(kept(), "the pass is kept");

    // 2. The next launch (a new scope dir and socket): no node start, LIVE,
    //    and its own shim really loads.
    const b = await launchOnce();
    assert.equal(b.error, null);
    assert.ok(live(b));
    assert.equal(nodeStarts(), 1, "a kept pass skips the probe");
    assert.deepEqual(b.hits, ["exec-shim"]);
    assert.equal(b.plan.shimDir, join(dir, `scope-${n}`, "exec-shims"));

    // 3. A rebuilt bundle is a new question.
    writeFileSync(join(dist, "exec-shim.mjs"), readFileSync(join(dist, "exec-shim.mjs"), "utf8") + "\n// rebuilt\n");
    assert.ok(live(await launchOnce()));
    assert.equal(nodeStarts(), 2, "a rebuilt bundle probes again");
    assert.ok(live(await launchOnce()));
    assert.equal(nodeStarts(), 2);

    // 4. MANDU_PROBE_CACHE=0 probes afresh.
    assert.ok(live(await launchOnce({ env: { [PROBE_CACHE_ENV]: "0" } })));
    assert.equal(nodeStarts(), 3);

    // 5. The arbiter client module cannot load: every launch probes, default-on
    //    degrades exactly as before (never LIVE, no shim dir for the agent's
    //    PATH), an explicit --exec-wrap refuses, and nothing is kept.
    const client = join(dist, "arbiter-client.mjs");
    const good = readFileSync(client, "utf8");
    writeFileSync(client, "throw new Error('broken arbiter client');\n");
    const d1 = await launchOnce();
    assert.equal(d1.error, null);
    assert.ok(!live(d1), JSON.stringify(d1.warnings));
    assert.equal(d1.plan.shimDir, undefined, "no shim that cannot load shadows the agent's PATH");
    assert.ok(d1.warnings.some((w) => /service 'exec-wrap' is on by default but failed to start: the exec-wrap shim cannot load .*broken arbiter client.*proceeding WITHOUT it/.test(w)), JSON.stringify(d1.warnings));
    assert.equal(nodeStarts(), 4);
    assert.equal(kept(), false, "a failure is never kept");
    const d2 = await launchOnce({ execWrap: true });
    assert.match(String(d2.error?.message), /service 'exec-wrap' was requested but failed to start: the exec-wrap shim cannot load .*broken arbiter client/);
    assert.equal(d2.plan.shimDir, undefined);
    assert.equal(nodeStarts(), 5, "asked again: a failure is never answered from the cache");

    // 6. Fixed: the next launch probes, passes and keeps it again.
    writeFileSync(client, good);
    assert.ok(live(await launchOnce({ execWrap: true })));
    assert.equal(nodeStarts(), 6);
    assert.ok(kept());
  } finally {
    disableProbeCache();
    if (savedPath === undefined) delete process.env["PATH"]; else process.env["PATH"] = savedPath;
    rmSync(dir, { recursive: true, force: true });
  }
});
