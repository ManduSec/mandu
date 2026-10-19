/**
 * claude-sandbox.test — E2E (plan 10 §12.3): a launch under the `secrets`
 * axes with Claude Code's OWN sandbox configured in the user's settings.
 * Through main() against a mock arbiter that answers the secret-registry
 * ops, with a fixture HOME. Asserts what the launch SAYS (the double-mask
 * warnings name the setting file) and what the agent RECEIVES (one
 * `--settings` carrying the arbiter socket in allowUnixSockets; the masked
 * env var as a symbol). Hermetic run under MANDU_NO_KERNEL (no bwrap); a
 * second run with real bwrap adds the file overlap, and self-SKIPs where
 * user namespaces are unavailable.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { createServer, type Server } from "node:net";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { probeUserns } from "../../src/userns.js";
import { spawnSync } from "node:child_process";

const commandExists = (cmd: string): boolean => spawnSync("sh", ["-c", `command -v ${cmd}`], { stdio: "ignore" }).status === 0;

const ENV_SYM = "$MDU:nomodel_Env[e1e1].GH_TOKEN";
const FILE_SYM = "$MDU:nomodel_Read[abcd]";

/** A mock arbiter speaking the NDJSON protocol for the ops a secrets launch needs. */
async function withSecretsArbiter(home: string, fn: (sock: string, dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-cs-e2e-"));
  const sock = join(dir, "arbiter.sock");
  const cred = join(home, ".aws", "credentials");
  const srv: Server = createServer((c) => {
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        let req: { id?: unknown; op?: string; vars?: Array<{ name: string; value: string }> };
        try { req = JSON.parse(line); } catch { continue; }
        let res: unknown;
        switch (req.op) {
          case "hello": res = { id: req.id, ok: true, result: { pid: 1, integrity: false, confidentiality: true } }; break;
          case "discoverSecrets": res = { id: req.id, ok: true, result: { files: [{ path: cred }] } }; break;
          case "registerSecret": res = { id: req.id, ok: true, result: { symbol: FILE_SYM, reason: "registered", twin: `[default]\naws_secret_access_key = ${FILE_SYM}.default.aws_secret_access_key\n`, fields: 1 } }; break;
          case "registerEnvSecrets":
            res = { id: req.id, ok: true, result: { vars: (req.vars ?? []).map((v) => v.name === "GH_TOKEN"
              ? { name: v.name, symbol: ENV_SYM, twin: ENV_SYM, reason: "registered (env:value)" }
              : { name: v.name, symbol: null, reason: "not a secret variable" }) } };
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

/** A fixture HOME: a credential file with a canary, and Claude Code's own
 *  sandbox ON with that file and GH_TOKEN masked by ITS credentials list. */
function fixtureHome(): { home: string; claude: string; out: string; cleanup: () => void } {
  const home = mkdtempSync(join(tmpdir(), "mandu-cs-home-"));
  mkdirSync(join(home, ".aws"), { recursive: true });
  writeFileSync(join(home, ".aws", "credentials"), "[default]\naws_secret_access_key = CS_E2E_CANARY_7731\n", { mode: 0o600 });
  mkdirSync(join(home, ".claude"), { recursive: true });
  writeFileSync(join(home, ".claude", "settings.json"), JSON.stringify({
    sandbox: {
      enabled: true,
      network: { allowUnixSockets: ["/run/user/1/other.sock"] },
      credentials: { files: [{ path: "~/.aws/credentials", mode: "mask" }], envVars: [{ name: "GH_TOKEN", mode: "mask" }] },
    },
  }));
  // A stand-in named `claude` (the launcher splices --settings only for that basename):
  // records its argv and the GH_TOKEN it received.
  const bin = join(home, "bin");
  mkdirSync(bin);
  const out = join(home, "agent-out.txt");
  const claude = join(bin, "claude");
  writeFileSync(claude, `#!/usr/bin/env bash\nprintf 'ARGV=%s\\nGH_TOKEN=%s\\n' "$*" "\${GH_TOKEN:-}" > '${out}'\n`);
  chmodSync(claude, 0o755);
  return { home, claude, out, cleanup: () => rmSync(home, { recursive: true, force: true }) };
}

async function run(argv: string[], env: Record<string, string | undefined>, home: string): Promise<{ code: number; lines: string[]; error?: Error }> {
  const lines: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  // os.homedir() (the discovery root the launch walks) reads process.env.HOME.
  const prevHome = process.env["HOME"];
  const prevCwd = process.cwd();
  process.env["HOME"] = home;
  process.chdir(home);
  try {
    return { code: await main(argv, env), lines };
  } catch (e) {
    return { code: -1, lines, error: e as Error };
  } finally {
    console.error = orig;
    process.env["HOME"] = prevHome;
    process.chdir(prevCwd);
  }
}

const baseEnv = (sock: string, dir: string, home: string): Record<string, string | undefined> => ({
  HOME: home, PWD: home, PATH: process.env["PATH"], XDG_RUNTIME_DIR: dir,
  MANDU_ARBITER_SOCK: sock, MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME,
  MANDU_MODE: "secrets", GH_TOKEN: "ghp_cs_e2e_canary_0042",
  // Never the resident stack's ports (a foreign net-proxy on 8790 is refused with a note).
  MANDU_NET_PROXY_PORT: "0",
  // The sandbox notes are informational rung lines: shown only under --verbose
  // (launch-banner.ts display policy) — this suite reads them off stderr.
  MANDU_VERBOSE: "1",
});

test("the launch names Claude Code's sandbox ONCE, warns about the env var masked twice, and hands the agent ONE --settings with the arbiter socket", async () => {
  const fx = fixtureHome();
  try {
    await withSecretsArbiter(fx.home, async (sock, dir) => {
      const r = await run(["--target", "claude", "--no-scope", "--", fx.claude], { ...baseEnv(sock, dir, fx.home), MANDU_NO_KERNEL: "1" }, fx.home);
      assert.equal(r.code, 0, r.error?.message ?? r.lines.join("\n"));
      const text = r.lines.join("\n");
      const on = /mandu: Claude Code's own sandbox is ON \(([^)]*)\)/.exec(text);
      assert.ok(on, text);
      assert.equal(on![1], join(fx.home, ".claude", "settings.json"), "the file named once, though the launch runs FROM home (project file = user file)");
      assert.match(text, /WARNING: mandu: 1 environment variable is masked TWICE — by Claude Code's sandbox\.credentials\.envVars in .*\/\.claude\/settings\.json \(GH_TOKEN\)/);
      // the file overlap follows the twin: warned iff this host put one over the file (confined, or the
      // bind-only gated posture of finding 7; gated without a bind ⇒ no twin ⇒ no double mask, no false warning)
      const twinned = /1 secret\(s\) (confined via symbolized twins|behind placeholder copies by the mount layer only)/.test(text);
      assert.equal(/credential file is masked TWICE/.test(text), twinned, text);
      const got = readFileSync(fx.out, "utf8");
      const argv = /ARGV=(.*)/.exec(got)![1]!;
      const settings = [...argv.matchAll(/--settings (\{.*?\})(?= --|$)/g)];
      assert.equal(settings.length, 1, argv);
      const parsed = JSON.parse(settings[0]![1]!) as { sandbox: { network: { allowUnixSockets: string[] } } };
      assert.deepEqual(parsed.sandbox.network.allowUnixSockets, ["/run/user/1/other.sock", sock], "the user's own entry kept, the arbiter socket added");
      assert.match(got, /GH_TOKEN=\$MDU:nomodel_Env\[e1e1\]\.GH_TOKEN/);
    });
  } finally {
    fx.cleanup();
  }
});

test("with real bwrap: the bind-covered credential file IS masked twice, and the warning names the setting file to edit", async (t) => {
  if (process.platform !== "linux" || !commandExists("bwrap") || !probeUserns()) { t.skip("bwrap with user namespaces unavailable"); return; }
  const fx = fixtureHome();
  try {
    await withSecretsArbiter(fx.home, async (sock, dir) => {
      const r = await run(["--target", "claude", "--no-scope", "--no-net-guard", "--no-exec-box", "--no-landlock-net", "--", fx.claude], baseEnv(sock, dir, fx.home), fx.home);
      assert.equal(r.code, 0, r.error?.message ?? r.lines.join("\n"));
      const text = r.lines.join("\n");
      // --no-net-guard: the bind alone, `gated` since sandbox-security-review finding 7, the twin still up
      assert.match(text, /1 secret\(s\) behind placeholder copies by the mount layer only/);
      assert.match(text, /Mandu's file guard is turned off/);
      assert.match(text, /WARNING: mandu: 1 credential file is masked TWICE — by Claude Code's sandbox\.credentials\.files in .*\/\.claude\/settings\.json \(~\/\.aws\/credentials\) and by Mandu's structured twin/);
      assert.match(text, /Remove that entry from .*\/\.claude\/settings\.json/);
      assert.match(readFileSync(fx.out, "utf8"), /--settings \{"sandbox"/);
    });
  } finally {
    fx.cleanup();
  }
});
