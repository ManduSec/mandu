/**
 * openclaw-gateway-env tests (src/services/openclaw-gateway-env.ts;
 * model-wires.md §9.1): where a Gateway's environment sets OpenClaw's Azure
 * endpoint variables, over a fake /proc, unit directory and dotenv files.
 * The running Gateway of THIS config only (other configs, other users and
 * other programs ignored), its systemd user unit running or not
 * (`Environment=`, `EnvironmentFile=`), the dotenv files; no /proc or an
 * unreadable environ is "not verified". Never a value in the answer.
 *
 * Axes: none. A reader; the verdict over it is openclaw-route-check's.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  gatewayAzureEnv, isGatewayArgv, parseEnvFile, parseEnviron, parseUnitEnvironment, type GatewayEnvIo,
} from "../../src/services/openclaw-gateway-env.js";

const HOME = "/home/u";
const CFG = "/home/u/.openclaw/openclaw.json";
const SECRET_URL = "https://elsewhere.openai.azure.com/openai/v1";

interface Proc { uid: number; cmd: string[]; env: Record<string, string> | null }

function io(o: { procs?: Record<number, Proc>; files?: Record<string, string>; noProc?: boolean }): GatewayEnvIo {
  const procs = o.procs ?? {};
  const files = o.files ?? {};
  return {
    listPids: () => (o.noProc ? null : Object.keys(procs).map(Number)),
    uidOf: (pid) => procs[pid]?.uid ?? null,
    readCmdline: (pid) => (procs[pid] ? procs[pid]!.cmd.join("\0") + "\0" : null),
    readEnviron: (pid) => {
      const e = procs[pid]?.env;
      return e ? Object.entries(e).map(([k, v]) => `${k}=${v}`).join("\0") : null;
    },
    readFile: (p) => files[p] ?? null,
    listDir: (p) => {
      const pre = p.endsWith("/") ? p : `${p}/`;
      const names = Object.keys(files).filter((f) => f.startsWith(pre) && !f.slice(pre.length).includes("/")).map((f) => f.slice(pre.length));
      return names.length > 0 ? names : null;
    },
    uid: 1000,
  };
}

const GW = ["node", "/opt/openclaw/node_modules/openclaw/openclaw.mjs", "gateway", "run", "--port", "18789"];

test("isGatewayArgv: OpenClaw's Gateway (its title, or `openclaw … gateway [run|start]`); its short-lived clients and other programs are not", () => {
  for (const a of [GW, ["openclaw-gateway"], ["openclaw", "gateway"], ["/usr/bin/openclaw-2026.9.9", "--profile", "x", "gateway", "start"], ["bash", "/usr/local/bin/openclaw-2026.7.1-2", "gateway", "run"]]) {
    assert.equal(isGatewayArgv(a), true, a.join(" "));
  }
  for (const a of [["openclaw", "gateway", "status"], ["openclaw", "gateway", "install"], ["openclaw", "agent", "-m", "gateway"], ["node", "server.js", "gateway", "run"], ["openclaw-node-worker"], []]) {
    assert.equal(isGatewayArgv(a), false, a.join(" "));
  }
});

test("parsers: environ, dotenv and a unit's Environment= / EnvironmentFile=", () => {
  assert.deepEqual(parseEnviron("A=1\0B=x=y\0\0junk\0"), { A: "1", B: "x=y" });
  assert.deepEqual(parseEnvFile("# c\nexport AZURE_OPENAI_BASE_URL=\"https://x\"\nAZURE_OPENAI_RESOURCE_NAME='r'\nE=\n"), { AZURE_OPENAI_BASE_URL: "https://x", AZURE_OPENAI_RESOURCE_NAME: "r", E: "" });
  const u = parseUnitEnvironment([
    "[Service]",
    "ExecStart=/usr/bin/node /opt/openclaw/openclaw.mjs gateway run",
    `Environment="HOME=/home/u" "AZURE_OPENAI_BASE_URL=${SECRET_URL}" PLAIN=1`,
    "Environment=OPENCLAW_STATE_DIR=%h/.openclaw \\",
    "  OTHER=2",
    "EnvironmentFile=-%h/.config/openclaw/svc.env",
  ].join("\n"), HOME);
  assert.deepEqual(u.env, { HOME: "/home/u", AZURE_OPENAI_BASE_URL: SECRET_URL, PLAIN: "1", OPENCLAW_STATE_DIR: "/home/u/.openclaw", OTHER: "2" });
  assert.deepEqual(u.files, ["/home/u/.config/openclaw/svc.env"]);
});

test("a running Gateway of this config with AZURE_OPENAI_BASE_URL set is found; one of another config, another user's, or another program is not; the value never appears", () => {
  const facts = gatewayAzureEnv(CFG, { HOME }, io({
    procs: {
      101: { uid: 1000, cmd: GW, env: { HOME, AZURE_OPENAI_BASE_URL: SECRET_URL } },
      102: { uid: 1000, cmd: GW, env: { HOME: "/tmp/other", AZURE_OPENAI_RESOURCE_NAME: "r" } }, // another config
      103: { uid: 0, cmd: GW, env: null }, // another user's: not looked at
      104: { uid: 1000, cmd: ["vim", "notes"], env: { AZURE_OPENAI_BASE_URL: SECRET_URL } },
    },
  }));
  assert.equal(facts.verified, true);
  assert.deepEqual(facts.set, ["AZURE_OPENAI_BASE_URL (the running Gateway's environment, pid 101)"]);
  assert.ok(!JSON.stringify(facts).includes(SECRET_URL), "names only, never a value");
  // The config named by the Gateway's own OPENCLAW_CONFIG_PATH or OPENCLAW_STATE_DIR.
  const byPath = gatewayAzureEnv("/srv/oc/gw.json", { HOME }, io({ procs: { 7: { uid: 1000, cmd: ["openclaw-gateway"], env: { HOME, OPENCLAW_CONFIG_PATH: "/srv/oc/gw.json", AZURE_OPENAI_RESOURCE_NAME: "r" } } } }));
  assert.deepEqual(byPath.set, ["AZURE_OPENAI_RESOURCE_NAME (the running Gateway's environment, pid 7)"]);
  const byState = gatewayAzureEnv("/srv/state/openclaw.json", { HOME }, io({ procs: { 8: { uid: 1000, cmd: GW, env: { HOME, OPENCLAW_STATE_DIR: "/srv/state", AZURE_OPENAI_BASE_URL: "x" } } } }));
  assert.equal(byState.set.length, 1);
  // Nothing set, no Gateway: verified, nothing.
  assert.deepEqual(gatewayAzureEnv(CFG, { HOME }, io({ procs: { 101: { uid: 1000, cmd: GW, env: { HOME, AZURE_OPENAI_BASE_URL: "" } } } })), { verified: true, set: [] });
  assert.deepEqual(gatewayAzureEnv(CFG, { HOME }, io({})), { verified: true, set: [] });
});

test("fail-closed: no /proc, or a Gateway whose environment cannot be read, is not verified", () => {
  const none = gatewayAzureEnv(CFG, { HOME }, io({ noProc: true }));
  assert.equal(none.verified, false);
  assert.match(none.why!, /no \/proc/);
  const hidden = gatewayAzureEnv(CFG, { HOME }, io({ procs: { 55: { uid: 1000, cmd: GW, env: null } } }));
  assert.equal(hidden.verified, false);
  assert.match(hidden.why!, /pid 55 cannot be read/);
});

test("the Gateway's systemd user unit, installed and not running: Environment= and EnvironmentFile=, only for a unit of this config", () => {
  const unitDir = "/home/u/.config/systemd/user";
  const facts = gatewayAzureEnv(CFG, { HOME }, io({
    files: {
      [`${unitDir}/openclaw-gateway.service`]: `[Service]\nExecStart=/usr/bin/openclaw gateway run\nEnvironment="AZURE_OPENAI_BASE_URL=${SECRET_URL}"\nEnvironmentFile=-%h/.config/openclaw/svc.env\n`,
      "/home/u/.config/openclaw/svc.env": "AZURE_OPENAI_RESOURCE_NAME=r\n",
      [`${unitDir}/openclaw-gateway-work.service`]: "[Service]\nEnvironment=OPENCLAW_STATE_DIR=/srv/work AZURE_OPENAI_BASE_URL=x\n", // another config
      [`${unitDir}/other.service`]: "[Service]\nEnvironment=AZURE_OPENAI_BASE_URL=x\n",
    },
  }));
  assert.equal(facts.verified, true);
  assert.deepEqual(facts.set, [
    `AZURE_OPENAI_BASE_URL (${unitDir}/openclaw-gateway.service, Environment=)`,
    "AZURE_OPENAI_RESOURCE_NAME (/home/u/.config/openclaw/svc.env, the EnvironmentFile of openclaw-gateway.service)",
  ]);
  // XDG_CONFIG_HOME moves the unit directory.
  const xdg = gatewayAzureEnv(CFG, { HOME, XDG_CONFIG_HOME: "/x" }, io({ files: { "/x/systemd/user/openclaw-gateway.service": "Environment=AZURE_OPENAI_BASE_URL=y\n" } }));
  assert.equal(xdg.set.length, 1);
});

test("OpenClaw's global dotenv files", () => {
  const facts = gatewayAzureEnv(CFG, { HOME, OPENCLAW_STATE_DIR: "/srv/s" }, io({
    files: {
      "/home/u/.openclaw/.env": "AZURE_OPENAI_BASE_URL=x\n",
      "/srv/s/.env": "AZURE_OPENAI_RESOURCE_NAME=r\n",
      "/home/u/.config/openclaw/gateway.env": "OTHER=1\n",
    },
  }));
  assert.deepEqual(facts.set, ["AZURE_OPENAI_BASE_URL (/home/u/.openclaw/.env)", "AZURE_OPENAI_RESOURCE_NAME (/srv/s/.env)"]);
});
