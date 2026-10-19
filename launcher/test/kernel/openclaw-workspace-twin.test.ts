/**
 * openclaw-workspace-twin.test — E2E (kernel tier): `mandu openclaw chat`
 * under the `secrets` axes and the REAL whole-agent secret-twins wrap
 * (bwrap), with OpenClaw's workspace pinned to the launch directory
 * (services/agent-config.ts fenceOpenclawWorkspace; supported-agents.md §5.5 item 5).
 *
 * WHY: OpenClaw loads its workspace's USER.md, AGENTS.md, MEMORY.md, … into
 * the model's context every session, not as a tool result. Pinning the
 * workspace to the project makes the project's files that ingress, so a
 * labelled file there must reach OpenClaw only as its twin: the wrap binds the
 * twin over the real path, and the workspace the run config names must be
 * that same path inside the wrap (the wrap is a mask over `/`, not a jail).
 *
 * Through main() against a mock arbiter answering the secret-registry ops
 * (the claude-sandbox.test.ts pattern), with a stand-in named `openclaw` that
 * reads `<workspace>/USER.md` the way OpenClaw would. Self-SKIPs where bwrap
 * or user namespaces are unavailable.
 *
 * PROJECT INVARIANT: a secret reaches a model only as an opaque symbol.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { createServer, type Server } from "node:net";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { spawnSync } from "node:child_process";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { probeUserns } from "../../src/userns.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode (protection-modes.md §4)

const commandExists = (cmd: string): boolean => spawnSync("sh", ["-c", `command -v ${cmd}`], { stdio: "ignore" }).status === 0;

const CANARY = "OC_WS_TWIN_CANARY_5521";
const SYM = "$MDU:nomodel_Read[5eed]";
const TWIN = `# About me\ntoken: ${SYM}.token\n`;

/** A mock arbiter for a secrets launch: the workspace's USER.md is the one
 *  discovered secret, registered with a twin. */
async function withSecretsArbiter(secretPath: string, fn: (sock: string, dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-ocws-e2e-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer((c) => {
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        let req: { id?: unknown; op?: string; vars?: Array<{ name: string }> };
        try { req = JSON.parse(line); } catch { continue; }
        let res: unknown;
        switch (req.op) {
          case "hello": res = { id: req.id, ok: true, result: { pid: 1, integrity: false, confidentiality: true } }; break;
          case "discoverSecrets": res = { id: req.id, ok: true, result: { files: [{ path: secretPath }] } }; break;
          case "registerSecret": res = { id: req.id, ok: true, result: { symbol: SYM, reason: "registered", twin: TWIN, fields: 1 } }; break;
          case "registerEnvSecrets":
            res = { id: req.id, ok: true, result: { vars: (req.vars ?? []).map((v) => ({ name: v.name, symbol: null, reason: "not a secret variable" })) } };
            break;
          case "emit": res = { id: req.id, ok: true, result: {} }; break;
          // Plan 14 §8.3: no blob lock, no label (the launch reads it fail-closed).
          case "gitHistoryLocks": res = { id: req.id, ok: true, result: { axis: true, blobs: [], labels: [] } }; break;
          default: res = { id: req.id, ok: false, error: `mock: ${req.op} not implemented` };
        }
        c.write(JSON.stringify(res) + "\n");
      }
    });
    c.on("error", () => {});
  });
  srv.listen(sock);
  await once(srv, "listening");
  try { await fn(sock, dir); } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
}

test("openclaw chat under the real twin wrap: the pinned workspace is the launch directory, and a labelled USER.md there reads as its twin", async (t) => {
  if (process.platform !== "linux" || !commandExists("bwrap") || !probeUserns()) { t.skip("bwrap with user namespaces unavailable"); return; }
  const home = realpathSync(mkdtempSync(join(tmpdir(), "mandu-ocws-home-")));
  const project = join(home, "project");
  mkdirSync(project, { recursive: true });
  const userMd = join(project, "USER.md");
  writeFileSync(userMd, `# About me\ntoken: ${CANARY}\n`, { mode: 0o600 });
  const userCfg = join(home, "openclaw.json");
  writeFileSync(userCfg, JSON.stringify({ agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" }, workspace: "~/.openclaw/workspace" } } }));
  // A stand-in named `openclaw`: answers --version, then reads USER.md from
  // the workspace its run config names, as OpenClaw loads it into the prompt.
  const bin = join(home, "bin");
  mkdirSync(bin);
  const out = join(home, "agent-out.json");
  writeFileSync(join(bin, "openclaw"), `#!/usr/bin/env node
const fs = require("fs");
if (process.argv[2] === "--version") { console.log("OpenClaw 2026.6.35 (c283867)"); process.exit(0); }
const cfg = JSON.parse(fs.readFileSync(process.env.OPENCLAW_CONFIG_PATH, "utf8"));
const ws = cfg.agents.defaults.workspace;
let seen = null;
try { seen = fs.readFileSync(ws + "/USER.md", "utf8"); } catch (e) { seen = "ERR " + e.code; }
fs.writeFileSync(${JSON.stringify(out)}, JSON.stringify({ workspace: ws, cwd: process.cwd(), seen }));
`, { mode: 0o755 });

  const prev = { home: process.env["HOME"], cfg: process.env["OPENCLAW_CONFIG_PATH"], cwd: process.cwd() };
  const lines: string[] = [];
  const origErr = console.error;
  try {
    await withSecretsArbiter(userMd, async (sock, dir) => {
      process.env["HOME"] = home;
      process.env["OPENCLAW_CONFIG_PATH"] = userCfg;
      process.chdir(project);
      console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
      let code: number;
      try {
        code = await main(["--target", "openclaw", "--no-scope", "--no-net-guard", "--no-exec-box", "--no-landlock-net", "--", join(bin, "openclaw"), "chat"], {
          HOME: home, PWD: project, PATH: process.env["PATH"], XDG_RUNTIME_DIR: dir,
          MANDU_ARBITER_SOCK: sock, MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "secrets",
          MANDU_NET_PROXY_PORT: "0", MANDU_REPLY_FILTER: "0", MANDU_VERBOSE: "1",
        });
      } finally {
        console.error = origErr;
      }
      assert.equal(code, 0, lines.join("\n"));
    });
    const text = lines.join("\n");
    assert.match(text, /1 secret\(s\) (confined via symbolized twins|behind placeholder copies by the mount layer only)/, `the twin wrap is up:\n${text}`);
    const got = JSON.parse(readFileSync(out, "utf8")) as { workspace: string; cwd: string; seen: string };
    assert.equal(got.workspace, project, "the run config names the launch directory");
    assert.equal(got.cwd, project, "and the agent runs there, inside the wrap");
    assert.ok(!got.seen.includes(CANARY), `the raw secret reached the workspace read: ${got.seen}`);
    assert.ok(got.seen.includes(SYM), `the workspace's USER.md reads as its twin: ${got.seen}`);
    assert.match(text, /OpenClaw works in .*\/project for this session/);
    assert.ok(readFileSync(userMd, "utf8").includes(CANARY), "the human's file is untouched");
  } finally {
    console.error = origErr;
    process.chdir(prev.cwd);
    if (prev.home === undefined) delete process.env["HOME"]; else process.env["HOME"] = prev.home;
    if (prev.cfg === undefined) delete process.env["OPENCLAW_CONFIG_PATH"]; else process.env["OPENCLAW_CONFIG_PATH"] = prev.cfg;
    rmSync(home, { recursive: true, force: true });
  }
});
