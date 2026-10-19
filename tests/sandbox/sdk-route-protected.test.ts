/**
 * sdk-route-protected e2e (docs/design/agents/agent-sdks.md §3.6), across the
 * REAL components: the launcher's main() in `secrets` mode writes the SDK
 * route of `mandu --target claude -- node …` into the launch's own
 * `<scope run dir>/sdk-route/` (the route file beside the copies of the
 * preload and the Python hook that read it) and the PATH shims into
 * `sdk-shims/`, puts both folders on the Linux write-protect list, and the
 * REAL mandu-net-guard refuses the agent tree's changes there. The route
 * left the environment (MANDU_SDK_ROUTE, which a host could forge) for that
 * file; this suite proves the agent cannot forge the file instead.
 *
 *   - refused: a rewrite of the route, its removal, a new file beside it, a
 *     change to the preload copy or the Python hook copy, a rename of the
 *     route folder, a replaced or removed shim;
 *   - performed (the control): a new file elsewhere in the scope run dir.
 *   - the host's agent child is still routed by the launch's route after
 *     every attempt (the stand-in claude records the launch's base URL).
 *
 * Self-SKIPs where the guard is not built (scripts/build-native.sh) or the
 * kernel has no seccomp user notification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "interceptors", "target");
const PICK = pickGuard(TARGET);
const GUARD = PICK.path;
const skip = process.platform !== "linux" || !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});

/** The host program: finds the launch's route folder by the preload copy
 *  its NODE_OPTIONS loads, tries to change each protected entry, records
 *  each outcome (0, or the error code) in `out`, then starts the stand-in
 *  `claude` by full path, which the hook must still route. */
function probe(out: string, claude: string): string {
  return `"use strict";
const fs = require("fs"), path = require("path");
const m = /--require=(\\S+)/.exec(process.env.NODE_OPTIONS || "");
const dir = m ? path.dirname(m[1]) : "/nonexistent";
const scope = path.dirname(dir), shims = path.join(scope, "sdk-shims");
const got = { dir: path.basename(dir) };
const step = (k, f) => { try { f(); got[k] = 0; } catch (e) { got[k] = e.code || String(e); } };
step("route", () => fs.writeFileSync(path.join(dir, "route.json"), '{"v":1,"env":{}}'));
step("rmroute", () => fs.unlinkSync(path.join(dir, "route.json")));
step("beside", () => fs.writeFileSync(path.join(dir, "route2.json"), "{}"));
step("preload", () => fs.appendFileSync(path.join(dir, "sdk-route-preload.cjs"), "\\n// x"));
step("pyhook", () => fs.writeFileSync(path.join(dir, "python", "sitecustomize.py"), "x"));
step("mvdir", () => fs.renameSync(dir, dir + ".away"));
step("shim", () => fs.writeFileSync(path.join(shims, "codex"), "#!/bin/sh\\nexit 0\\n"));
step("rmshim", () => fs.unlinkSync(path.join(shims, "claude")));
step("free", () => fs.writeFileSync(path.join(scope, "free.txt"), "ok"));
got.routeIntact = (() => { try { return JSON.parse(fs.readFileSync(path.join(dir, "route.json"), "utf8")).launchRouting !== undefined; } catch { return false; } })();
fs.writeFileSync(${JSON.stringify(out)}, JSON.stringify(got));
require("child_process").execFileSync(${JSON.stringify(claude)}, ["-p", "hi"], { env: { PATH: "/usr/bin:/bin" }, stdio: "inherit" });
`;
}

test("the agent tree cannot change the SDK route's file, its hook copies or the PATH shims; the route still routes", { skip, timeout: 120_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-route-wp-e2e-"));
  const home = join(dir, "home");
  mkdirSync(home, { recursive: true });
  const out = join(dir, "out.json");
  const bin = join(dir, "bin");
  mkdirSync(bin);
  const record = join(dir, "claude.json");
  // The stand-in claude: records the base URL it was started with.
  writeFileSync(join(bin, "claude"), `#!${process.execPath}\nrequire("fs").writeFileSync(${JSON.stringify(record)}, JSON.stringify({ base: process.env.ANTHROPIC_BASE_URL || "", argv: process.argv.slice(2) }));\n`, { mode: 0o755 });
  const host = join(dir, "host.js");
  writeFileSync(host, probe(out, join(bin, "claude")));
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const lines: string[] = [];
  const orig = console.error;
  const savedBin = process.env["MANDU_NET_GUARD_BIN"];
  const savedHome = process.env["HOME"];
  const savedManduHome = process.env["MANDU_HOME"];
  try {
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.env["HOME"] = home;
    process.env["MANDU_HOME"] = join(home, ".mandu");
    const code = await main(
      ["--target", "claude", "--no-scope", "--no-mcp", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", process.execPath, host],
      {
        HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: `${bin}:${process.env["PATH"]}`,
        ANTHROPIC_BASE_URL: "http://127.0.0.1:8788",
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: dir,
      },
    );
    console.error = orig;
    const said = `\nlauncher said:\n${lines.join("\n")}`;
    assert.ok(existsSync(out), `the host ran${said}`);
    const got = JSON.parse(readFileSync(out, "utf8")) as Record<string, unknown>;
    const all = `${said}\nagent got: ${JSON.stringify(got)}`;
    assert.equal(code, 0, all);
    assert.equal(got["dir"], "sdk-route", `the host loads the launch's copy of the preload${all}`);
    for (const k of ["route", "rmroute", "beside", "preload", "pyhook", "mvdir", "shim", "rmshim"]) {
      assert.notEqual(got[k], 0, `${k}: the agent changed the SDK route's folder or a shim${all}`);
    }
    assert.equal(got["routeIntact"], true, `the route is the launch's${all}`);
    assert.equal(got["free"], 0, `the control: a new file elsewhere in the scope run dir${all}`);
    const started = JSON.parse(readFileSync(record, "utf8")) as { base: string; argv: string[] };
    assert.equal(started.base, "http://127.0.0.1:8788", `the claude the host started is routed by the launch's route${all}`);
    assert.ok(started.argv.includes("--settings"), `with the launch's overlay${all}`);
  } finally {
    console.error = orig;
    if (savedBin === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = savedBin;
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
    if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
