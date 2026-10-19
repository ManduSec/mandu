/**
 * opencode-project-plugins.test — E2E through main(): with confidentiality ON
 * an OpenCode 1 launch is REFUSED before the agent runs, naming the file and
 * the way out, when it would bring code OpenCode 1's own `OPENCODE_PURE`
 * switch does not leave out: a project's custom tool, the user's own custom
 * tool, a project's plugin with the user's own opted in, the user's own
 * plugins with only a project's opted in (the switch is all or none). A
 * plugin alone (a project's, the user's, a config document naming one) is
 * left out by the switch, not refused. MANDU_OPENCODE_PROJECT_PLUGINS=1 /
 * MANDU_OPENCODE_GLOBAL_PLUGINS=1 run them with a warning; mode `off` runs
 * them; a clean project launches as before (src/opencode-project-code.ts,
 * src/opencode-global-code.ts; supported-agents.md §2.3 items 11 and 12).
 *
 * WHY A TOOL IS REFUSED, NOT LEFT OUT: OpenCode 1 reads its project and
 * global directories itself (Mandu does not build its configuration as it
 * does OpenCode 2's), and `--pure` skips plugins only. A plugin or tool runs
 * inside OpenCode and writes the model request itself (measured: a project
 * plugin copied a pinned reader's raw output into the system prompt); the
 * real-binary form is tests/sandbox/guard/opencode-project-plugins.test.ts.
 *
 * Stand-ins NAMED `opencode` that print an OpenCode 1 version and otherwise
 * record that they ran; an arbiter that answers nothing (the requested mode
 * is then the effective one); the kernel rungs off (MANDU_NO_KERNEL=1).
 *
 * Axes: stated per launch, `secrets` (confidentiality ON, the rule applies)
 * and `off` (it does not).
 *
 * PROJECT INVARIANT: code that would run inside the agent never runs
 * unchecked unless the human said so.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { launchLogs } from "../lib/launch-log-read.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";
import { createServer, type Server } from "node:net";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)

interface Rig { dir: string; home: string; proj: string; sock: string; up: { url: string; hits: number; close: () => void } }

async function withRig(fn: (r: Rig) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-oc-projcode-"));
  const home = join(dir, "home");
  const proj = join(dir, "proj");
  mkdirSync(join(proj, ".git"), { recursive: true });
  mkdirSync(home, { recursive: true });
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  const counter = { hits: 0 };
  const http = createHttpServer((_req: IncomingMessage, res: ServerResponse) => { counter.hits++; res.writeHead(404); res.end("{}"); });
  http.listen(0, "127.0.0.1");
  await once(http, "listening");
  const up = { url: `http://127.0.0.1:${(http.address() as AddressInfo).port}`, get hits() { return counter.hits; }, close: () => { http.closeAllConnections(); http.close(); } };
  try { await fn({ dir, home, proj, sock, up }); } finally {
    srv.close(); up.close(); rmSync(dir, { recursive: true, force: true });
  }
}

const env = (r: Rig, extra: Record<string, string> = {}): Record<string, string | undefined> => ({
  HOME: r.home, PWD: r.proj, MANDU_ARBITER_SOCK: r.sock, PATH: process.env["PATH"], XDG_RUNTIME_DIR: r.dir,
  MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "secrets", MANDU_UPSTREAM: r.up.url,
  MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
  ...extra,
});

/** A stand-in named `opencode` reporting OpenCode 1; a run writes `ran`. */
function standIn(r: Rig): { bin: string; ran: string } {
  const d = mkdtempSync(join(r.dir, "bin-"));
  const bin = join(d, "opencode");
  const ran = join(d, "ran");
  writeFileSync(bin, `#!/usr/bin/env node
if (process.argv[2] === "--version") { console.log("1.18.13"); process.exit(0); }
require("fs").writeFileSync(${JSON.stringify(ran)}, "1");
`, { mode: 0o755 });
  return { bin, ran };
}

/** Run main(), returning the error it threw (or null) and the launch notes: stderr's lines, then its log's. */
async function launch(argv: string[], e: Record<string, string | undefined>): Promise<{ err: unknown; stderr: string }> {
  const lines: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  let err: unknown = null;
  const before = launchLogs(e);
  try { await main(argv, e); } catch (x) { err = x; } finally { console.error = orig; }
  // The launch's own log holds every note in full (the default display
  // prints a banner and one short line per warning; packaging.md §5).
  return { err, stderr: [...lines, ...before.newLinesIfAny()].join("\n") };
}

const REFUSED = /refusing OpenCode in mode/;

function plant(path: string, text = "export default {}\n"): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, text);
}

test("OpenCode 1, mode secrets: a project's custom tool refuses the launch before the agent runs; a project plugin or plugin-naming config is left out by the switch, not refused (axis: secrets)", async () => {
  await withRig(async (r) => {
    plant(join(r.proj, ".opencode", "tools", "t.js"));
    const s = standIn(r);
    const { err } = await launch(["--no-scope", "--no-mcp", "--", s.bin, "run", "hi"], env(r));
    assert.ok(err !== null, "a custom tool: refused");
    assert.match(String(err), /refusing OpenCode in mode secrets: this project brings OpenCode code/);
    assert.match(String(err), /MANDU_OPENCODE_PROJECT_PLUGINS=1/);
    assert.match(String(err), new RegExp(join(r.proj, ".opencode", "tools", "t.js").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), "the file is named");
    assert.equal(existsSync(s.ran), false, "INVARIANT: the agent never ran");
    assert.equal(r.up.hits, 0, "no model request");
  });
  const leftOut: Array<[string, (proj: string) => void]> = [
    ["a plugin", (p) => plant(join(p, ".opencode", "plugin", "leak.ts"))],
    ["a config naming a plugin", (p) => writeFileSync(join(p, "opencode.json"), JSON.stringify({ plugin: ["some-npm-plugin"] }))],
  ];
  for (const [what, put] of leftOut) {
    await withRig(async (r) => {
      put(r.proj);
      const { err } = await launch(["--no-scope", "--no-mcp", "--", standIn(r).bin, "run", "hi"], env(r));
      // Past the rule (whatever stops this rig's launch later, its
      // unanswering arbiter's missing secret discovery, is not this refusal).
      assert.doesNotMatch(String(err), REFUSED, `${what}: left out by OPENCODE_PURE, not refused`);
    });
  }
});

test("OpenCode 1, mode secrets: the user's own custom tool refuses the launch; the user's own plugins (a file, an npm plugin in the global opencode.json) do not (axis: secrets)", async () => {
  await withRig(async (r) => {
    plant(join(r.home, ".config", "opencode", "tool", "mytool.ts"));
    const s = standIn(r);
    const { err } = await launch(["--no-scope", "--no-mcp", "--", s.bin, "run", "hi"], env(r));
    assert.match(String(err), /refusing OpenCode in mode secrets: your OpenCode folders hold a custom tool.*mytool\.ts.*MANDU_OPENCODE_GLOBAL_PLUGINS=1/);
    assert.equal(existsSync(s.ran), false, "INVARIANT: the agent never ran");
    assert.equal(r.up.hits, 0, "no model request");
  });
  await withRig(async (r) => {
    for (const d of [join(r.home, ".config", "opencode", "plugin"), join(r.home, ".opencode", "plugins")]) plant(join(d, "mine.ts"));
    writeFileSync(join(r.home, ".config", "opencode", "opencode.json"), JSON.stringify({ plugin: ["oh-my-opencode"] }));
    const mine = await launch(["--no-scope", "--no-mcp", "--", standIn(r).bin, "run", "hi"], env(r));
    assert.doesNotMatch(String(mine.err), REFUSED, "the user's plugins are left out by OPENCODE_PURE, not refused");
    assert.doesNotMatch(mine.stderr, /WARNING: MANDU_OPENCODE/);
  });
});

test("OpenCode 1: the opt-ins — each runs its own with a warning; one alone refuses what OpenCode 1 cannot split; mode off runs everything (axes: secrets, off)", async () => {
  await withRig(async (r) => {
    plant(join(r.proj, ".opencode", "plugin", "leak.ts"));
    plant(join(r.home, ".config", "opencode", "plugin", "mine.ts"));
    // The project opt-in alone: the user's plugins would run too (all or none).
    const proj = await launch(["--no-scope", "--no-mcp", "--", standIn(r).bin, "run", "hi"], env(r, { MANDU_OPENCODE_PROJECT_PLUGINS: "1" }));
    assert.match(String(proj.err), /OpenCode 1 can only run every plugin or none.*mine\.ts.*MANDU_OPENCODE_GLOBAL_PLUGINS=1/);
    assert.match(proj.stderr, /WARNING: MANDU_OPENCODE_PROJECT_PLUGINS=1 .*not checked: .*leak\.ts/);
    // The global opt-in alone: the project's plugin refuses (item 11).
    const own = await launch(["--no-scope", "--no-mcp", "--", standIn(r).bin, "run", "hi"], env(r, { MANDU_OPENCODE_GLOBAL_PLUGINS: "1" }));
    assert.match(String(own.err), /this project brings OpenCode code.*leak\.ts/);
    assert.match(own.stderr, /WARNING: MANDU_OPENCODE_GLOBAL_PLUGINS=1 .*not checked: .*mine\.ts/);
    // Both: past the rule, with both warnings.
    const both = await launch(["--no-scope", "--no-mcp", "--", standIn(r).bin, "run", "hi"], env(r, { MANDU_OPENCODE_PROJECT_PLUGINS: "1", MANDU_OPENCODE_GLOBAL_PLUGINS: "1" }));
    assert.doesNotMatch(String(both.err), REFUSED);
    assert.match(both.stderr, /WARNING: MANDU_OPENCODE_PROJECT_PLUGINS=1/);
    assert.match(both.stderr, /WARNING: MANDU_OPENCODE_GLOBAL_PLUGINS=1/);
    // Mode off: nothing is kept from the model; the rule does not apply, and
    // the agent runs.
    plant(join(r.home, ".config", "opencode", "tool", "mytool.ts"));
    const s = standIn(r);
    const off = await launch(["--no-scope", "--no-mcp", "--", s.bin, "run", "hi"], env(r, { MANDU_MODE: "off" }));
    assert.equal(off.err, null, String(off.err));
    assert.ok(existsSync(s.ran), "mode off: the agent ran");
  });
});
