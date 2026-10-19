/**
 * codex-sandbox-binding — plan 13 D7, a Codex call run under Codex's own
 * command sandbox binds to its process tree (2026-10-09).
 *
 * The agent's child for such a call is the sandbox helper
 * (`codex-linux-sandbox …`), whose argv the guard records cut inside the
 * shell-snapshot preamble, so before this no candidate root carried the
 * command's text: the call bound to nothing and, while the session held a
 * raw secret read, its result was masked at the session's level. The
 * helper is now a candidate for the ONE command shell its plumbing started.
 * The trees below are the ones read off real runs (codex-cli 0.144.1 and
 * 0.162.0 under `codex exec`, a scripted model, the host's process table).
 *
 * The binding decides what a result is masked by, so the other half of
 * every case is that a forged or ambiguous shell binds nothing new: the
 * call then stays unbound (masked at the session's level), never bound to a
 * tree that did not run it.
 *
 * Confidentiality axis (the call-root recorder serves the model exit).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  ProvenanceStore, isCodexSandboxHelperArgv, isCodexSandboxPlumbingArgv, isCodexSnapshotPreambleArgv,
} from "../../provenance/provenance-store.js";
import { execSignature, execSignatureForArgv, rootSignaturesOfArgv } from "../../policy/exec-signature.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const PROFILE = JSON.stringify({ type: "managed", file_system: { type: "restricted", entries: [] }, network: "restricted" });
/** The helper as the agent starts it, cut where the guard stopped reading (the preamble). */
const HELPER = ["codex-linux-sandbox", "--sandbox-policy-cwd", "/w", "--command-cwd", "/w", "--permission-profile", PROFILE, "--", "/usr/bin/zsh", "-c"];
const SETUP = ["/proc/self/exe", "--codex-run-as-process-setup", "codex-linux-sandbox", "--sandbox-policy-cwd", "/w"];
const BWRAP = ["bwrap", "--as-pid-1", "--new-session", "--die-with-parent", "--ro-bind", "/", "/", "--", "/usr/bin/codex", "--sandbox-policy-cwd", "/w"];
const INNER_162 = ["codex-linux-sandbox", "--sandbox-policy-cwd", "/w", "--command-cwd", "/w", "--permission-profile", PROFILE, "--", "/usr/bin/zsh", "-c"];
const INNER_144 = ["/usr/lib/codex/codex", "--sandbox-policy-cwd", "/w", "--permission-profile", PROFILE, "--apply-seccomp-then-exec", "--", "/usr/bin/zsh", "-c"];
const PREAMBLE_CUT = ["/usr/bin/zsh", "-c"];
const shellOf = (cmd: string): string[] => ["/usr/bin/zsh", "-c", cmd];

const READ = "cat ./x.txt | od -An -tx1";
const CLEAN = "echo clean-$((6*7))";

function withStore(fn: (s: ProvenanceStore) => void | Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-cxsb-"));
  const store = new ProvenanceStore({ dbPath: join(dir, "p.db") });
  return (async () => {
    try { await fn(store); } finally { store.close(); rmSync(dir, { recursive: true, force: true }); }
  })();
}

/** An exec as the server records it: signature from the argv, root signatures for an agent child. */
function exec(s: ProvenanceStore, procKey: string, ancestors: string[], argv: string[], callRoot = false): void {
  s.recordExecRoot({
    procKey, ancestors, argv, signature: execSignatureForArgv(argv), session: "s",
    ...(callRoot ? { callRoot: true, rootSignatures: rootSignaturesOfArgv(argv) } : {}),
  });
}

/** One sandboxed call's tree, 0.162.0 form: helper → bwrap → helper (pid 1) → shell. */
function tree162(s: ProvenanceStore, n: string, cmd: string, opts: { snapshot?: boolean; shellLost?: boolean } = {}): { helper: string; inner: string; shell: string } {
  const helper = `h${n}`, bw = `bw${n}`, inner = `in${n}`, shell = `sh${n}`;
  exec(s, helper, ["agent-0"], SETUP, true);
  exec(s, helper, ["agent-0"], HELPER, true);
  exec(s, bw, [helper, "agent-0"], BWRAP);
  exec(s, inner, [bw, helper, "agent-0"], INNER_162);
  if (opts.snapshot !== false) exec(s, shell, [inner, bw, helper, "agent-0"], PREAMBLE_CUT);
  if (opts.shellLost !== true) exec(s, shell, [inner, bw, helper, "agent-0"], shellOf(cmd));
  return { helper, inner, shell };
}

/** 0.144.1 form: helper → bwrap → bwrap (a fork, never exec'd) → one process: inner helper, preamble, shell. */
function tree144(s: ProvenanceStore, n: string, cmd: string): { helper: string; shell: string } {
  const helper = `h${n}`, bw = `bw${n}`, bwf = `bwf${n}`, shell = `sh${n}`;
  exec(s, helper, ["agent-0"], HELPER, true);
  exec(s, bw, [helper, "agent-0"], BWRAP);
  exec(s, shell, [bwf, bw, helper, "agent-0"], INNER_144);
  exec(s, shell, [bwf, bw, helper, "agent-0"], PREAMBLE_CUT);
  exec(s, shell, [bwf, bw, helper, "agent-0"], shellOf(cmd));
  return { helper, shell };
}

const sig = (cmd: string): string => execSignature(cmd);

test("the helper's argv forms: the agent's child, the plumbing, the preamble; nothing else", () => {
  assert.equal(isCodexSandboxHelperArgv(HELPER), true);
  assert.equal(isCodexSandboxHelperArgv(SETUP), true);
  assert.equal(isCodexSandboxHelperArgv(["/opt/codex/bin/codex-linux-sandbox", "--"]), true);
  for (const a of [["bash", "-lc", "codex-linux-sandbox --x"], ["zsh", "-c", READ], ["codex", "exec"], []]) assert.equal(isCodexSandboxHelperArgv(a), false, JSON.stringify(a));
  for (const a of [HELPER, BWRAP, INNER_162, INNER_144]) assert.equal(isCodexSandboxPlumbingArgv(a), true, JSON.stringify(a));
  for (const a of [shellOf(READ), PREAMBLE_CUT, ["cat", "x"], []]) assert.equal(isCodexSandboxPlumbingArgv(a), false, JSON.stringify(a));
  assert.equal(isCodexSnapshotPreambleArgv(PREAMBLE_CUT), true, "the payload the guard cut");
  assert.equal(isCodexSnapshotPreambleArgv(["/usr/bin/zsh", "-c", "__CODEX_SNAPSHOT_OVERRIDE_SET_0=x\nexec '/usr/bin/zsh' -c 'ls'"]), true, "a short preamble kept whole");
  for (const a of [shellOf(READ), ["/usr/bin/zsh", "-l"], ["cat", "-c"]]) assert.equal(isCodexSnapshotPreambleArgv(a), false, JSON.stringify(a));
});

test("0.162.0 and 0.144.1 forms, with and without the snapshot: each call binds EXACT to its own helper; the reading call's tree is folded, the clean call's result is clean", async () => {
  for (const form of ["162", "162-nosnap", "144"] as const) {
    await withStore((s) => {
      s.recordCallCommand("call_read", sig(READ), "delivered", "s");
      s.recordCallCommand("call_clean", sig(CLEAN), "delivered", "s");
      const read = form === "144" ? tree144(s, "1", READ) : tree162(s, "1", READ, { snapshot: form === "162" });
      const clean = form === "144" ? tree144(s, "2", CLEAN) : tree162(s, "2", CLEAN, { snapshot: form === "162" });
      // a reader under the reading call's shell reads the secret raw
      exec(s, "cat-1", [read.shell, "in1", "bw1", read.helper, "agent-0"], ["cat", "./x.txt"]);
      s.taintProcessSecret({ procKey: "cat-1", path: "/w/x.txt", level: "no-model", app: "cat", session: "s" });
      const r = s.callTree("call_read", { session: "s" });
      assert.equal(r.binding, "exact", form);
      assert.deepEqual(r.roots, [read.helper], `${form}: bound to the helper, so the whole sandbox tree folds`);
      assert.equal(r.level, "no-model", `${form}: the reader is in the reading call's tree`);
      const c = s.callTree("call_clean", { session: "s" });
      assert.equal(c.binding, "exact", form);
      assert.deepEqual(c.roots, [clean.helper], form);
      assert.equal(c.level, null, `${form}: utility, the clean call is clean (before: unbound, masked at the session's level)`);
    });
  }
});

test("forged or ambiguous shells bind nothing new: an orphan's shell makes the helper ambiguous; the command's own `exec` of a shell and its child shells are never read", async () => {
  // a) an orphan of the reading command, re-parented to the sandbox's pid 1,
  //    execs a shell with the clean call's text; the clean call's own shell
  //    record was lost. Neither call binds through the ambiguous helper.
  await withStore((s) => {
    s.recordCallCommand("call_read", sig(READ), "delivered", "s");
    s.recordCallCommand("call_clean", sig(CLEAN), "delivered", "s");
    const read = tree162(s, "1", READ);
    tree162(s, "2", CLEAN, { shellLost: true });
    exec(s, "cat-1", [read.shell, read.inner, "bw1", read.helper, "agent-0"], ["cat", "./x.txt"]);
    s.taintProcessSecret({ procKey: "cat-1", path: "/w/x.txt", level: "no-model", app: "cat", session: "s" });
    exec(s, "orphan-9", [read.inner, "bw1", read.helper, "agent-0"], shellOf(CLEAN));
    assert.equal(s.codexSandboxCommandShell(read.helper), "ambiguous");
    assert.equal(s.callTree("call_clean", { session: "s" }).binding, "none", "never bound to the tree that read the secret through a forged shell");
    assert.equal(s.callTree("call_read", { session: "s" }).binding, "none", "the reading call is unbound too: masked at the session's level (fail-closed)");
  });
  // b) the reading command `exec`s a shell with the clean call's text (a
  //    later exec of the command's own process), and a child of it runs one:
  //    neither is read; each call keeps its own helper.
  await withStore((s) => {
    s.recordCallCommand("call_read", sig(READ), "delivered", "s");
    s.recordCallCommand("call_clean", sig(CLEAN), "delivered", "s");
    const read = tree162(s, "1", READ);
    exec(s, read.shell, [read.inner, "bw1", read.helper, "agent-0"], shellOf(CLEAN));
    exec(s, "child-3", [read.shell, read.inner, "bw1", read.helper, "agent-0"], ["bash", "-c", CLEAN]);
    const clean = tree162(s, "2", CLEAN);
    const shell = s.codexSandboxCommandShell(read.helper);
    assert.ok(shell !== null && shell !== "ambiguous" && execSignatureForArgv(shell.argv) === sig(READ));
    assert.deepEqual(s.callTree("call_clean", { session: "s" }).roots, [clean.helper], "the clean call is bound to its own helper only");
    assert.deepEqual(s.callTree("call_read", { session: "s" }).roots, [read.helper]);
  });
  // c) the clean call's shell lost, the reading command's child execs its
  //    text: the clean call binds nothing (a child of the command is never
  //    a command shell).
  await withStore((s) => {
    s.recordCallCommand("call_clean", sig(CLEAN), "delivered", "s");
    s.recordCallCommand("call_read", sig(READ), "delivered", "s");
    const read = tree162(s, "1", READ);
    exec(s, "child-3", [read.shell, read.inner, "bw1", read.helper, "agent-0"], shellOf(CLEAN));
    tree162(s, "2", CLEAN, { shellLost: true });
    assert.equal(s.callTree("call_clean", { session: "s" }).binding, "none");
  });
});

test("only the agent's own child, on the guard's own edges, in the call's window: a helper that is no candidate root, a claimed edge, a shell exec'd after the first ask bind nothing", async () => {
  // a helper the guard did not report as the agent's child (no callRoot)
  await withStore((s) => {
    s.recordCallCommand("call_x", sig(CLEAN), "delivered", "s");
    exec(s, "hx", ["sh-other", "agent-0"], HELPER);
    exec(s, "shx", ["inx", "bwx", "hx", "sh-other", "agent-0"], shellOf(CLEAN));
    exec(s, "inx", ["bwx", "hx", "sh-other", "agent-0"], INNER_162);
    assert.equal(s.callTree("call_x", { session: "s" }).binding, "none");
  });
  // a shell under the helper only by a claimed (data-socket) edge
  await withStore((s) => {
    s.recordCallCommand("call_x", sig(CLEAN), "delivered", "s");
    exec(s, "hx", ["agent-0"], HELPER, true);
    s.recordLineageChain("shx", ["hx", "agent-0"], "s", { claimed: true });
    s.recordExecRoot({ procKey: "shx", argv: shellOf(CLEAN), signature: execSignatureForArgv(shellOf(CLEAN)), session: "s" });
    assert.equal(s.callTree("call_x", { session: "s" }).binding, "none", "a claimed edge is never walked");
  });
  // the command shell exec'd only after the call's result was first asked for
  await withStore((s) => {
    s.recordCallCommand("call_x", sig(CLEAN), "delivered", "s");
    tree162(s, "1", CLEAN, { shellLost: true });
    assert.equal(s.callTree("call_x", { session: "s" }).binding, "none");
    exec(s, "sh1", ["in1", "bw1", "h1", "agent-0"], shellOf(CLEAN));
    assert.equal(s.callTree("call_x", { session: "s" }).binding, "none", "a later exec never binds a call already answered");
  });
  // two same-text calls at once, each in its own helper: shared over both (as any same-text pair)
  await withStore((s) => {
    s.recordCallCommand("call_a", sig(CLEAN), "delivered", "s");
    s.recordCallCommand("call_b", sig(CLEAN), "delivered", "s");
    tree162(s, "1", CLEAN);
    tree162(s, "2", CLEAN);
    const a = s.callTree("call_a", { session: "s" });
    assert.equal(a.binding, "shared");
    assert.deepEqual([...a.roots].sort(), ["h1", "h2"]);
  });
});
