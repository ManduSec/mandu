/**
 * wsl-interop.test — E2E: the whole-agent secret-twin wrap on WSL hides the
 * Windows interop door (launcher/src/wsl.ts, exec-routing.md §4.1). The REAL
 * wrap argv (planSecretTwins + wslTwinWrapFlags) runs under real bwrap with
 * the WSL paths pointed at stand-ins, since this host is not WSL: a directory
 * holding a live Unix socket for `/run/WSL/<pid>_interop` and a file for
 * `/init`. A differential: without the WSL flags the probe reaches the socket,
 * sees `$WSL_INTEROP` and reads the stand-in `/init`; with them the socket
 * directory is empty, the variable is gone and `/init` is masked by /dev/null.
 * Self-SKIPs without bwrap + user namespaces or python3.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { once } from "node:events";
import { join } from "node:path";
import { planSecretTwins } from "../../src/secret-twins.js";
import { resolveWrapBwrap } from "../../src/bwrap-grant.js";
import { probeUserns } from "../../src/userns.js";
import { wslTwinWrapFlags } from "../../src/wsl.js";

const commandExists = (cmd: string): boolean => spawnSync("sh", ["-c", `command -v ${cmd}`], { stdio: "ignore" }).status === 0;

const PROBE = `
import os, socket, sys
sock, init = sys.argv[1], sys.argv[2]
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock); print("INTEROP-REACHED")
except OSError as e:
    print("INTEROP-BLOCKED", e.errno)
print("ENV=" + os.environ.get("WSL_INTEROP", "<unset>"))
try:
    print("INIT=" + repr(open(init, "rb").read()))
except OSError as e:
    print("INIT-DENIED", e.errno)
`;

test("the secret-twin wrap on WSL: interop socket, WSL_INTEROP and /init are hidden from the agent", async (t) => {
  if (process.platform !== "linux" || !commandExists("bwrap") || !probeUserns()) { t.skip("bwrap with user namespaces unavailable"); return; }
  if (!commandExists("python3")) { t.skip("python3 unavailable (the socket probe)"); return; }
  // A short fixed prefix under /tmp: a Unix socket path must stay under 108
  // bytes (so not tmpdir(), which a long TMPDIR can stretch), and the
  // secret-twin wrap does not remap /tmp, so the stand-ins are seen as they
  // are. Never under the real $HOME (test-organization.md §8.4).
  const root = mkdtempSync("/tmp/mdu-wsl-");
  const srv = createServer((c) => c.end());
  try {
    const runWsl = join(root, "run-WSL");
    mkdirSync(runWsl);
    const sock = join(runWsl, "8_interop");
    srv.listen(sock);
    await once(srv, "listening");
    const init = join(root, "init");
    writeFileSync(init, "WSL-INIT\n");
    const twinDir = join(root, "twins");
    mkdirSync(twinDir);
    const secret = join(root, "credentials");
    writeFileSync(secret, "RAW\n");

    const run = (flags: string[]): string => {
      // The bwrap the launcher's wrap really runs: Mandu's own copy where
      // `mandu setup` installed it (the system one may lack the grant then).
      const plan = planSecretTwins([{ path: secret, symbol: "$MDU:nomodel_Read[aaaa]" }], twinDir, resolveWrapBwrap() ?? "bwrap", { extraFlags: flags });
      for (const f of plan.files) writeFileSync(f.twinPath, f.content);
      const r = spawnSync(plan.wrapArgv[0]!, [...plan.wrapArgv.slice(1), "python3", "-c", PROBE, sock, init], {
        encoding: "utf8", env: { ...process.env, WSL_INTEROP: sock }, timeout: 30_000,
      });
      assert.equal(r.status, 0, `the wrapped probe must run: ${r.stderr}`);
      return r.stdout;
    };

    const off = run(wslTwinWrapFlags(false, existsSync, { interopDir: runWsl, init }));
    assert.match(off, /INTEROP-REACHED/, `control: the socket is reachable through the plain wrap: ${off}`);
    assert.match(off, new RegExp(`ENV=${sock.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    assert.match(off, /INIT=b'WSL-INIT\\n'/);

    const on = run(wslTwinWrapFlags(true, existsSync, { interopDir: runWsl, init }));
    assert.match(on, /INTEROP-BLOCKED 2\b/, `WSL: the interop socket directory must be empty inside the wrap: ${on}`);
    assert.match(on, /ENV=<unset>/);
    // /dev/null bound inside an unprivileged user namespace is a nodev mount:
    // the masked /init cannot even be opened (so cannot be exec'd).
    assert.match(on, /INIT=b''|INIT-DENIED 13\b/, `WSL: /init is masked inside the wrap: ${on}`);
    assert.doesNotMatch(on, /WSL-INIT/);
  } finally {
    srv.close();
    rmSync(root, { recursive: true, force: true });
  }
});
