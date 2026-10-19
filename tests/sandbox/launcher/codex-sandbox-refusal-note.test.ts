/**
 * codex-sandbox-refusal-note.test.ts — the model is told when Codex's own
 * command sandbox refused the exec-wrap shim's connection (confidentiality
 * plan 10 §11.8, "Blocked commands"; supported-agents.md §6.4).
 *
 * The real launcher (`secrets`, the guard, exec-wrap's curl shim, the egress
 * proxy) runs the REAL `codex exec` against a scripted Responses model (no
 * API key). The model asks for one shell call, `cat secret.txt; curl …`:
 * the command names a labelled file, so its whole output reaches the model
 * masked, the shim's own stderr with it.
 *
 *   (1) The user's Codex config keeps the sandbox's network off
 *       (`network_access = false`, which a launch respects): Codex's seccomp
 *       filter refuses the shim's connection to the arbiter, the shim fails
 *       closed (exit 77, nothing sent), and the masked result the model gets
 *       carries the `blocked:` line naming Codex's sandbox, saying the
 *       command was not the problem and how to run it. The arbiter found it
 *       from the guard's own record of Codex's sandbox helper, never from
 *       the command's output. No byte of the secret reaches the model.
 *   (2) Control, the config silent: the launch opens the sandbox's network
 *       (§6.5), the shim reaches the arbiter, curl runs and reaches the
 *       host, and the result carries no `blocked:` line.
 *
 * GATED on Linux + bwrap + an unprivileged userns + openssl + curl + the
 * built guard + a codex whose sandbox starts on this host (a host that bars
 * a sandbox nested in Mandu's skips with the reason). Zero API budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

import { withStack, runLauncher, startHttpsShim, probeKernelTier } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";
import { startScriptedResponses, responsesFnTurn, responsesTextTurn } from "../../lib/fake-responses.js";
import { functionCallOutputSpan } from "../../lib/conf-exfil.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../../interceptors/net-proxy/src/ca.js";

installExitGuard("codex-sandbox-refusal-note");

// This suite STATES its axes (protection-modes.md §4): `secrets`, the
// default mode, whose masked results carry the note.
stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const probe = process.platform === "linux" ? probeKernelTier() : null;
const which = (cmd: string): string | null => {
  const r = spawnSync("bash", ["-c", `command -v ${cmd}`], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
};
const REAL_CODEX = which("codex");
const WORKSPACE_WRITE = ["-c", 'sandbox_mode="workspace-write"', "-c", "sandbox_workspace_write.exclude_slash_tmp=true"];

function codexSandboxStarts(): boolean {
  const home = mkdtempSync(join(tmpdir(), "mdu-cxref-probe-"));
  try {
    return spawnSync(REAL_CODEX!, ["sandbox", ...WORKSPACE_WRITE, "--", "true"], {
      cwd: home, env: { ...process.env, CODEX_HOME: home, TMPDIR: home }, stdio: "ignore", timeout: 60_000,
    }).status === 0;
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

const GATE = process.platform !== "linux"
  ? "Linux only (the guard, Codex's Linux sandbox)"
  : !probe!.bwrap
    ? "`bwrap` not installed"
    : !probe!.userns
      ? "unprivileged user namespaces unavailable"
      : !GUARD.path
        ? "mandu-net-guard is not built (scripts/build-native.sh)"
        : !opensslAvailable()
          ? "openssl is not installed (the certificates)"
          : which("curl") === null
            ? "curl is not installed"
            : REAL_CODEX === null
              ? "codex is not installed"
              : !codexSandboxStarts()
                ? "Codex's own sandbox does not start on this host (launcher/src/codex-sandbox.ts)"
                : false;

const alnum = (n: number): string => [...randomBytes(n)].map((b) => "abcdefghijklmnopqrstuvwxyz0123456789"[b % 36]).join("");
const CANARY = `sk_live_fake${alnum(24)}`;
const CALL = "call_mdu_shim_refused";
const MARKER = "MDU_SHIM_REFUSAL";
const COMMAND = "cat secret.txt; curl -sS --max-time 20 https://collect.example/v1/ping";
const SANDBOX_LINE = "[mandu:secret] blocked: curl did not start, so it did not run and sent nothing: Codex's own sandbox, whose network is off, refused its connection to Mandu's command check";

interface Leg { out: string; code: number; span: string | null; requests: string[]; hits: string[] }

async function launch(networkSetting: "off" | "unset"): Promise<Leg> {
  const policyDir = mkdtempSync(join(tmpdir(), "mdu-cxref-policy-"));
  writeFileSync(join(policyDir, "policy.yaml"), [
    "version: 1", "paths:", "  - path: \"**/workspace/secret.txt\"", "    level: no-model", "",
  ].join("\n"));
  const leg: Leg = { out: "", code: -1, span: null, requests: [], hits: [] };
  try {
    await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
      writeFileSync(join(workspace, "secret.txt"), `token=${CANARY}\n`);
      // The host curl targets, behind the session proxy's host route.
      const ca = ensureCa(join(tmp, "ca-collect"));
      const leaf = leafForHost(ca, "collect.example");
      const sink = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
        leg.hits.push(`${req.method} ${req.url}`);
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("pong\n");
      });
      sink.listen(0, "127.0.0.1");
      await once(sink, "listening");
      const sites = join(tmp, "mock-sites.yaml");
      writeFileSync(sites, ["hosts:", "  - host: collect.example", `    tls_to: 127.0.0.1:${(sink.address() as AddressInfo).port}`, `    tls_ca: ${ca.certPath}`, ""].join("\n"));
      const fake = await startScriptedResponses({
        script: [
          { match: (r) => r.hasToolResult, respond: () => responsesTextTurn("MDU_DONE") },
          { match: (r) => !r.hasToolResult && r.body.includes(MARKER), respond: () => responsesFnTurn(CALL, "exec_command", { cmd: COMMAND }), once: true },
        ],
      });
      mkdirSync(join(tmp, "shim-cert"), { recursive: true });
      const shim = await startHttpsShim(fake.origin, join(tmp, "shim-cert"));
      try {
        const codexHome = join(tmp, "codex-home");
        mkdirSync(codexHome, { recursive: true });
        writeFileSync(join(codexHome, "config.toml"), [
          "check_for_update_on_startup = false",
          'approval_policy = "never"',
          'sandbox_mode = "workspace-write"',
          `[projects.${JSON.stringify(workspace)}]`, 'trust_level = "trusted"',
          "[sandbox_workspace_write]", "exclude_slash_tmp = true",
          // (1) the user's own choice, which a launch keeps (§6.5); (2) silent
          ...(networkSetting === "off" ? ["network_access = false"] : []),
          "[features]", "plugins = false",
          "",
        ].join("\n"));
        const env = {
          ...launcherEnv(shim.origin, 0),
          HOME: home,
          CODEX_HOME: codexHome,
          MANDU_NET_PROXY_MOCK_SITES: sites,
          OPENAI_API_KEY: "sk-mdu-dummy",
        };
        const r = await runLauncher(
          ["--no-scope", "--no-mcp", "--no-reply-filter", "--", REAL_CODEX!, "exec", "--skip-git-repo-check", `${MARKER}: run it`],
          env, workspace, 240_000,
        );
        leg.out = r.out;
        leg.code = r.code;
        leg.requests = fake.requests.map((q) => q.body);
        const follow = fake.requests.find((q) => q.body.includes('"function_call_output"'));
        leg.span = follow ? functionCallOutputSpan(follow.body, CALL) : null;
      } finally {
        await shim.close();
        await fake.close();
        sink.close();
      }
    }, { mode: "secrets", policyPath: join(policyDir, "policy.yaml") });
  } finally {
    rmSync(policyDir, { recursive: true, force: true });
  }
  return leg;
}

const diagOf = (leg: Leg): string =>
  `\n--- the result the model got ---\n${leg.span}\n--- sink ---\n${leg.hits.join("\n")}\n--- launch output (tail) ---\n${leg.out.slice(-5000)}`.split(CANARY).join("<CANARY>");
/** Codex's sandbox never started the command (bwrap refused inside Mandu's
 *  wrap): the one host shape this suite cannot judge. */
const nestedBarred = (leg: Leg): boolean => /bwrap/i.test(leg.out) && !leg.out.includes("exited ") && leg.span === null;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test(
  "§11.8 LIVE: Codex's sandbox, network off, refuses the shim's connection: nothing runs or is sent, and the masked result tells the model it was Codex's sandbox and how to run the command",
  { skip: GATE, timeout: 300_000 },
  async (t) => {
    const leg = await launch("off");
    const diag = diagOf(leg);
    if (nestedBarred(leg)) {
      t.skip(`Codex's sandbox cannot start nested in Mandu's on this host: ${leg.out.slice(-600)}`);
      return;
    }
    assert.equal(leg.code, 0, `the launch failed${diag}`);
    assert.ok(/net-guard LIVE/.test(leg.out), `the guard engaged${diag}`);
    // THE ORACLES first: no byte of the secret in any model request; nothing reached the host.
    for (const body of leg.requests) assert.ok(!body.includes(CANARY), `the secret reached the model${diag}`);
    assert.deepEqual(leg.hits, [], `curl reached the host past Codex's closed sandbox${diag}`);
    // (The shim's own stderr is not asserted here: `codex exec` prints the
    // command's output on 0.162 but not on 0.144, the CI guest's. Its wording
    // is pinned by codex-shell-network and codex-sandbox-exec-wrap.)
    // The model's result: masked whole, with the line from the arbiter's record.
    assert.ok(leg.span !== null, `the follow-up carries the call's result${diag}`);
    assert.match(leg.span!, /^\$MDU:nomodel_/, `the result is masked${diag}`);
    assert.ok(!leg.span!.includes("mandu-exec-wrap"), `the program's output stays masked${diag}`);
    const full = leg.requests.find((b) => b.includes(SANDBOX_LINE));
    assert.ok(full !== undefined, `the masked result carries the codex_sandbox blocked: line${diag}`);
    assert.ok(full!.includes("the command itself was not the problem"), `the line says the command was not the problem${diag}`);
    assert.ok(full!.includes('sandbox_permissions \\"require_escalated\\"'), `the line says how to run it${diag}`);
    console.error("codex-sandbox-refusal-note (network off): masked, with the codex_sandbox line; the host saw nothing");
  },
);

test(
  "§11.8 LIVE control: with the launch opening Codex's sandbox network, the shim reaches Mandu, curl runs, and the result carries no blocked: line",
  { skip: GATE, timeout: 300_000 },
  async (t) => {
    const leg = await launch("unset");
    const diag = diagOf(leg);
    if (nestedBarred(leg)) {
      t.skip(`Codex's sandbox cannot start nested in Mandu's on this host: ${leg.out.slice(-600)}`);
      return;
    }
    assert.equal(leg.code, 0, `the launch failed${diag}`);
    for (const body of leg.requests) assert.ok(!body.includes(CANARY), `the secret reached the model${diag}`);
    assert.ok(!/refuses its connection to Mandu/.test(leg.out), `Codex's sandbox still refused the shim${diag}`);
    assert.deepEqual(leg.hits, ["GET /v1/ping"], `curl ran and reached the host through the proxy${diag}`);
    assert.ok(leg.span !== null && /^\$MDU:nomodel_/.test(leg.span), `the result is masked (it names the labelled file)${diag}`);
    assert.ok(!leg.requests.some((b) => b.includes("[mandu:secret] blocked:")), `no blocked: line for a command that ran${diag}`);
    console.error("codex-sandbox-refusal-note (network on): curl ran, no blocked: line");
  },
);
