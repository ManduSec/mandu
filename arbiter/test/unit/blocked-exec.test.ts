/**
 * blocked-exec — plan 10 §11.8, "Blocked commands": the shim's run found in
 * the guard's argv record (`shimInvocationArgv`), the shim's verdict
 * recomputed over it (`blockedExecFold`), and the program name a note may
 * carry (`blockedProgramName`: never an argument, a placeholder or a
 * registered secret value). And Codex's own sandbox with its network off
 * (`codexSandboxNetworkOff`, read off the helper's argv the guard
 * recorded): a shim run under it is `codex_sandbox`, never recomputed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { blockedExecFold, blockedProgramName } from "../../policy/blocked-exec.js";
import { codexSandboxNetworkOff, shimInvocationArgv } from "../../provenance/provenance-store.js";
import type { SymbolEntry, SymbolMap } from "../../symbol-table/index.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the default mode: a secret placeholder stays as written and the command runs

const SECRET = "$MDU:nomodel_Read[de31].STRIPE_KEY";
const PUBLIC = "$MDU:WebFetch[cd34]";

function mapOf(entries: Record<string, Partial<SymbolEntry> & { value: string }>): SymbolMap {
  const symbols = new Map<string, SymbolEntry>();
  for (const [name, e] of Object.entries(entries)) {
    symbols.set(name, {
      tool: "Read", field: null, origin: null, session_key: null, call_id: null,
      created_at: 1, obsoleted_at: null, obsoleted_by: null, derived_from: null, line_range: null,
      confidentiality: "public", bindings: null, integrity: "untrusted", ...e,
    });
  }
  return { symbols };
}
const MAP = mapOf({ [SECRET]: { value: "sk_live_fake_123456", confidentiality: "no-model" }, [PUBLIC]: { value: "hello-data" } });

test("shimInvocationArgv: the command the shim stood in for, from the checkout's and the bundle's argv; null for anything else", () => {
  const dev = ["curl", "--import", "file:///r/interceptors/exec-wrap/node_modules/tsx/dist/esm/index.mjs", "/r/interceptors/exec-wrap/src/wrap.ts", "-s", "https://x.test/"];
  assert.deepEqual(shimInvocationArgv(dev), ["curl", "-s", "https://x.test/"]);
  const bundled = ["wget", "--no-warnings=ExperimentalWarning", "/usr/lib/node_modules/@mandusec/mandu/dist/exec-shim.mjs", "-q", "https://x.test/"];
  assert.deepEqual(shimInvocationArgv(bundled), ["wget", "-q", "https://x.test/"]);
  assert.deepEqual(shimInvocationArgv(["curl", "/r/interceptors/exec-wrap/src/wrap.ts"]), ["curl"], "no arguments");
  // the real program, and the shim script's own exec (before its `exec -a`)
  assert.equal(shimInvocationArgv(["/usr/bin/curl", "-s", "https://x.test/"]), null);
  assert.equal(shimInvocationArgv(["curl", "-s", "https://x.test/"]), null);
  // the entry after another operand is an argument, not a shim run
  assert.equal(shimInvocationArgv(["node", "x.js", "/r/interceptors/exec-wrap/src/wrap.ts"]), null);
  assert.equal(shimInvocationArgv(["curl", "-s", "https://x.test/", "/r/interceptors/exec-wrap/src/wrap.ts"]), null);
  // The argv alone cannot tell `cat <entry>` from the shim: it counts, and
  // the fold names it only if the shim would have refused its arguments
  // (an explanation, never a release).
  assert.deepEqual(shimInvocationArgv(["cat", "/r/interceptors/exec-wrap/src/wrap.ts"]), ["cat"]);
  assert.equal(shimInvocationArgv(["", "/r/interceptors/exec-wrap/src/wrap.ts"]), null);
  assert.equal(shimInvocationArgv(["curl"]), null);
  // a look-alike file name is not the entry
  assert.equal(shimInvocationArgv(["curl", "/r/my-wrap.ts"]), null);
});

test("blockedProgramName: a plain program name only; a path's basename; anything else is 'a program'", () => {
  assert.equal(blockedProgramName("curl"), "curl");
  assert.equal(blockedProgramName("/usr/bin/wget"), "wget");
  assert.equal(blockedProgramName("python3.12"), "python3.12");
  assert.equal(blockedProgramName(PUBLIC), "a program", "a placeholder");
  assert.equal(blockedProgramName("curl -s"), "a program");
  assert.equal(blockedProgramName("a\nb"), "a program");
  assert.equal(blockedProgramName("x".repeat(41)), "a program");
  assert.equal(blockedProgramName(""), "a program");
  // argv[0] is the agent's to choose: a registered value never names it
  assert.equal(blockedProgramName("sk_live_fake_123456", (t) => t.includes("sk_live_fake_123456")), "a program");
});

test("blockedExecFold: the shim's verdict, one entry per (program, kind); a command the shim runs is not named; never an argument", () => {
  const unsupported = ["curl", "-d", `note=${PUBLIC}`, "-w", "%{http_code}", "-u", `${SECRET}:`, "https://x.test/"];
  const codeFlow = ["sh", "-c", SECRET];
  const runs = ["curl", "-H", `Authorization: Bearer ${SECRET}`, "https://api.example/"];
  const clean = ["curl", "-s", "https://x.test/"];
  const out = blockedExecFold([unsupported, codeFlow, runs, clean, unsupported], MAP);
  assert.deepEqual(out, [{ app: "curl", kind: "unsupported_command" }, { app: "sh", kind: "symbol_as_command" }]);
  const s = JSON.stringify(out);
  for (const leak of ["x.test", "sk_live", "STRIPE", "hello-data", "$MDU"]) assert.ok(!s.includes(leak), `no argument: ${leak}`);
  assert.deepEqual(blockedExecFold([], MAP), []);
  assert.deepEqual(blockedExecFold([runs, clean], MAP), [], "a secret placeholder stays as written and the command runs (confidentiality.md §7.1)");
});

/** Codex's sandbox policy as its helper takes it (codex-cli 0.159.1 to 0.162.0). */
const profile = (network: string): string => JSON.stringify({
  type: "managed",
  file_system: { type: "restricted", entries: [{ path: { type: "special", value: { kind: "root" } }, access: "read" }] },
  network,
});
const HELPER = ["--sandbox-policy-cwd", "/w", "--command-cwd", "/w"];

test("codexSandboxNetworkOff: Codex's sandbox helper with the network restricted, in each spelling the guard records; nothing else", () => {
  // the helper's first exec, the helper itself, and its seccomp stage
  const setup = ["/proc/self/exe", "--codex-run-as-process-setup", "44", "260678", "pipe", "", "/w", "/opt/codex/bin/codex", "codex-linux-sandbox", ...HELPER, "--permission-profile", profile("restricted"), "--", "/usr/bin/zsh", "-c", "__CODEX_SNAPSHOT_OVERRIDE_SET_0=1"];
  assert.equal(codexSandboxNetworkOff(setup), true);
  assert.equal(codexSandboxNetworkOff(["codex-linux-sandbox", ...HELPER, "--permission-profile", profile("restricted"), "--", "bash", "-c", "x"]), true);
  assert.equal(codexSandboxNetworkOff(["codex-linux-sandbox", ...HELPER, "--permission-profile", profile("restricted"), "--apply-seccomp-then-exec", "--", "bash", "-c", "x"]), true);
  assert.equal(codexSandboxNetworkOff(["/x/codex-linux-sandbox", `--permission-profile=${profile("restricted")}`, "--", "true"]), true);
  // the network on, no helper, no policy, a policy that does not parse
  assert.equal(codexSandboxNetworkOff(["codex-linux-sandbox", ...HELPER, "--permission-profile", profile("enabled"), "--", "bash", "-c", "x"]), false);
  assert.equal(codexSandboxNetworkOff(["bash", "-c", `codex-linux-sandbox --permission-profile '${profile("restricted")}'`]), false, "the words inside a shell payload are not the helper");
  assert.equal(codexSandboxNetworkOff(["codex-linux-sandbox", ...HELPER, "--", "bash"]), false);
  assert.equal(codexSandboxNetworkOff(["codex-linux-sandbox", "--permission-profile", '{"network":"restr']), false, "cut short in the guard's record");
  // the policy belongs to the helper only: after `--` it is the command's
  assert.equal(codexSandboxNetworkOff(["codex-linux-sandbox", "--", "tool", "--permission-profile", profile("restricted")]), false);
  // an older Codex's `--sandbox-policy` form was not measured: not recognized
  assert.equal(codexSandboxNetworkOff(["codex-linux-sandbox", "--sandbox-policy", '{"type":"workspace-write","network_access":false}', "--", "bash"]), false);
  assert.equal(codexSandboxNetworkOff([]), false);
});

test("blockedExecFold: a run under Codex's network-off sandbox is codex_sandbox, without a verdict; another run of it outside keeps its own", () => {
  const plain = ["curl", "-s", "https://x.test/"];
  const unsupported = ["curl", "-d", `note=${PUBLIC}`, "-w", "%{http_code}", "https://x.test/"];
  // the shim lets a plain curl through, yet under Codex's sandbox it never asked
  assert.deepEqual(blockedExecFold([plain], MAP, { codexSandbox: [plain] }), [{ app: "curl", kind: "codex_sandbox" }]);
  assert.deepEqual(blockedExecFold([plain], MAP), [], "outside the sandbox the shim ran it");
  // a command the shim would refuse is still not judged under the sandbox
  assert.deepEqual(blockedExecFold([unsupported], MAP, { codexSandbox: [unsupported] }), [{ app: "curl", kind: "codex_sandbox" }]);
  assert.deepEqual(blockedExecFold([unsupported, plain], MAP, { codexSandbox: [plain] }), [{ app: "curl", kind: "unsupported_command" }, { app: "curl", kind: "codex_sandbox" }]);
  const s = JSON.stringify(blockedExecFold([unsupported], MAP, { codexSandbox: [unsupported] }));
  for (const leak of ["x.test", "hello-data", "$MDU"]) assert.ok(!s.includes(leak), `no argument: ${leak}`);
});
