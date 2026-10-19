/**
 * code-runner-content — the leftovers of the renamed-copy fix (confidentiality
 * plan 13 §8 decision (b) and D8, 2026-10-03), each red on the code before:
 *
 *   (1) an interpreter NOT byte-identical to an installed program (a pyenv
 *       python, an nvm node, a static busybox) under a new name passed the
 *       code-running check: no name and no host hash said what it was. The
 *       guard now reads the executable's content for an interpreter's front
 *       end (reader_identity.rs `runtime_of`) and reports `runs:<family>`
 *       among the opener's findings; the arbiter treats it as code
 *       (`argsCodeProblem`, `runtimeOf`): no reader, never prompted for, no
 *       verdict but one keyed by its run.
 *   (2) the guard judged the ssh-agent socket's readers by name only; it
 *       now asks the arbiter (`readerProgram`) what the binary is, by name
 *       and by the host's program hashes, as every other list is judged.
 *   (3) the dashboard judged reader lists by name only; the arbiter now
 *       says, per entry, whether it admits nothing (`confidentialityState`'s
 *       `readersAdmitNothing`, beside `whyPath`'s), and the page uses it.
 *
 * Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  addCodeRunnerHashes, argsCodeProblem, clearHostProgramHashesForTest, decideOpen, inlineCodeProblem, loaderEnvProblem, matchReader, runtimeOf, verdictProgramOf,
} from "../../policy/flow-taint.js";
import { refreshProgramHashes } from "../../policy/program-hashes.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const sha = (b: string): string => createHash("sha256").update(b).digest("hex");
/** A python build no installed program's hash matches (pyenv's). */
const PYENV = sha("a pyenv-built CPython 3.11, renamed");
const ENV = "/w/.env";
// The human pinned the program by hand and vouches for it (plan 13 D8 (12)).
const PIN = { app: "mytool", path: "/home/u/bin/mytool", sha256: PYENV, prints: "nothing" as const };

// ── (1) an interpreter by its content ───────────────────────────────────────

test("(1) on the code before (no finding), a pinned renamed interpreter no hash knows read raw", () => {
  assert.equal(decideOpen(ENV, { readers: [PIN] }, { exe: PIN.path, sha256: PYENV, exeSystem: false, loaderEnv: [] }).verdict, "raw");
});

test("(1) the guard's runs: finding makes the opener no reader, in every form, and never a question", () => {
  const opener = { exe: PIN.path, sha256: PYENV, exeSystem: true, loaderEnv: ["runs:python"] };
  assert.equal(runtimeOf(opener), "python");
  assert.equal(loaderEnvProblem(opener), null, "not a loader variable");
  assert.match(argsCodeProblem(opener) ?? "", /by its content, a python interpreter/);
  assert.notEqual(inlineCodeProblem(opener), null);
  assert.equal(verdictProgramOf(opener), null, "no reusable verdict: an answer is keyed by its run");
  for (const ask of ["never", "known", "always"] as const) {
    // pinned by path and hash, listed by bare name, or as a known consumer
    const pinned = decideOpen(ENV, { readers: [PIN] }, opener, { ask });
    assert.equal(pinned.verdict, "deny", `${ask}: ${pinned.why}`);
    assert.match(pinned.why, /mytool is not the program a human could name: its executable is, by its content, a python interpreter/);
    assert.equal(decideOpen(ENV, { readers: ["mytool"] }, opener, { ask }).verdict, "deny", ask);
    assert.equal(decideOpen(ENV, { readers: [PIN], others: "twin" }, opener, { ask }).verdict, "twin", ask);
    assert.equal(decideOpen(ENV, {}, opener, { ask }).verdict, "twin", ask);
    assert.equal(decideOpen("/h/.pgpass", {}, { ...opener, exe: "/usr/local/bin/psql" }, { ask }).verdict, "twin", `${ask}: a known consumer's name buys nothing`);
  }
  // with an args: finding beside it, both are said
  assert.match(argsCodeProblem({ ...opener, loaderEnv: ["runs:node", "args:git -c"] }) ?? "", /node interpreter.*; its command line/);
  // the pin still names the binary (the refusal is decideOpen's, not a miss)
  assert.notEqual(matchReader([PIN], { ...opener, loaderEnv: [] }), null);
});

test("(1) the families !506 left out (2026-10-04) are refused alike, each named as what it is", () => {
  // The guard's RUNTIME_MARKERS families added for ksh93, mksh/lksh, posh,
  // yash, tcsh, BSD csh, fish, toybox, LuaJIT, guile, Racket CS, R and
  // littler, julia, bun (and every program `bun build --compile` makes),
  // deno and PowerShell's apphost. The arbiter takes any family the guard
  // names: none is a reader, none is asked about, none gets a reusable
  // verdict.
  for (const family of ["ksh", "mksh", "posh", "yash", "tcsh", "csh", "fish", "toybox", "luajit", "guile", "racket", "R", "julia", "bun", "deno", "pwsh"]) {
    const opener = { exe: PIN.path, sha256: PYENV, exeSystem: true, loaderEnv: [`runs:${family}`] };
    assert.equal(runtimeOf(opener), family);
    assert.equal(verdictProgramOf(opener), null, family);
    for (const ask of ["never", "known", "always"] as const) {
      const d = decideOpen(ENV, { readers: [PIN] }, opener, { ask });
      assert.equal(d.verdict, "deny", `${family} ${ask}: ${d.why}`);
      assert.match(d.why, new RegExp(`its executable is, by its content, a ${family} interpreter`));
      assert.equal(decideOpen(ENV, {}, opener, { ask }).verdict, "twin", `${family} ${ask}`);
    }
  }
});

test("(1) a byte-identical copy the guard also finds by content is refused as the copy it is (the hash names it)", () => {
  addCodeRunnerHashes([[COPY, "python3.12"]]);
  try {
    const d = decideOpen(ENV, { readers: [{ app: "mytool", path: PIN.path, sha256: COPY }] }, { exe: PIN.path, sha256: COPY, exeSystem: false, loaderEnv: ["runs:python"] });
    assert.equal(d.verdict, "deny");
    assert.match(d.why, /^mytool is a copy of python3\.12, a program that runs code it is given/);
  } finally {
    clearHostProgramHashesForTest();
    refreshProgramHashes({ minIntervalMs: 0 });
  }
});

test("(1) a clean leaf program is untouched: no finding, a reader as before", () => {
  const sshAdd = { exe: "/usr/bin/ssh-add", sha256: sha("ssh-add"), exeSystem: true, loaderEnv: [] as string[] };
  assert.equal(runtimeOf(sshAdd), null);
  assert.equal(argsCodeProblem(sshAdd), null);
  assert.equal(decideOpen("/h/.pgpass", { readers: ["ssh-add"] }, sshAdd).verdict, "raw");
});

// ── over a real server: (1) the open, (2) readerProgram, (3) the panel ──────

async function rig(policyOf: (dir: string, secret: string) => string, fn: (r: { guard: ArbiterClient; admin: ArbiterClient; dir: string; secret: string }) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-runner-content-"));
  const secret = join(dir, ".env");
  writeFileSync(secret, "API_KEY=runner_content_canary_01\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, policyOf(dir, secret));
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), policyPath: policy, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  try { await fn({ guard, admin, dir, secret }); } finally { guard.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); }
}

/** A copy of an installed interpreter by its hash, known to this process's
 *  flow-taint (the server runs in it) as the host scan would make it. */
const COPY = sha("byte for byte the host's python3.12");

test("(1) over a real server: the runs: opener, pinned by path and hash, is refused unprompted and holds nothing", async () => {
  await rig((_d, secret) => `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, path: ${PIN.path}, sha256: ${PYENV}, prints: nothing }, ssh-add]\n`, async ({ guard, secret }) => {
    const d = await guard.decideSecretOpen({ path: secret, exe: PIN.path, sha256: PYENV, isAgent: false, exeSystem: true, openerEnv: ["runs:python"], procKey: "rc-1", session: "rc", ask: "always" });
    assert.equal(d.verdict, "deny", d.reason);
    assert.match(d.reason, /by its content, a python interpreter/);
    assert.equal(d.approvalId, undefined, "never asked about");
    assert.equal((await guard.processSecretTaint("rc-1")).level, null, "no taint row");
    // the same binary with no finding (the code before) was the listed reader
    assert.equal((await guard.decideSecretOpen({ path: secret, exe: PIN.path, sha256: PYENV, isAgent: false, exeSystem: true, openerEnv: [], procKey: "rc-2", session: "rc" })).verdict, "raw");
  });
});

test("(2) readerProgram: the arbiter's identity of a binary, by name and by the host's program hashes", async () => {
  await rig((_d, secret) => `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n`, async ({ guard }) => {
    addCodeRunnerHashes([[COPY, "python3.12"]]);
    try {
      assert.deepEqual(await guard.readerProgram("/usr/bin/ssh-add", sha("ssh-add")), { prints: false, runsCode: false, copyOf: null });
      assert.deepEqual(await guard.readerProgram("/usr/local/bin/ssh-add", COPY), { prints: false, runsCode: true, copyOf: "python3.12" }, "a byte-identical copy under a leaf program's name");
      assert.deepEqual(await guard.readerProgram("/usr/bin/socat", sha("socat")), { prints: true, runsCode: true, copyOf: null }, "by name");
      assert.deepEqual(await guard.readerProgram("/usr/bin/python3.12"), { prints: false, runsCode: true, copyOf: null });
      await assert.rejects(guard.readerProgram("/usr/bin/ssh", "not-a-hash"), /sha256 must be 64 hex digits/);
      await assert.rejects(guard.readerProgram(""), /exe must be a non-empty string/);
    } finally {
      clearHostProgramHashesForTest();
      refreshProgramHashes({ minIntervalMs: 0 });
    }
  });
});

test("(3) confidentialityState says, per reader entry, whether it admits nothing as the arbiter judges it (a pin's hash, a script pin)", async () => {
  await rig((_d, secret) => `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, path: /home/u/bin/mytool, sha256: ${COPY} }, ssh-add, { app: python3, script: /opt/tools/report.py }, cat, bash]\n`, async ({ guard, admin, secret }) => {
    addCodeRunnerHashes([[COPY, "python3.12"]]);
    try {
      await guard.registerSecret({ path: secret });
      const st = await admin.confidentialityState();
      const row = st.secrets.find((e) => e.path === secret);
      assert.ok(row, JSON.stringify(st.secrets));
      assert.deepEqual(row.readers, ["mytool", "ssh-add", "python3", "cat", "bash"]);
      // mytool by its hash; python3 with a script pin admits its script;
      // cat and bash by name
      assert.deepEqual(row.readersAdmitNothing, [true, false, false, true, true]);
    } finally {
      clearHostProgramHashesForTest();
      refreshProgramHashes({ minIntervalMs: 0 });
    }
  });
});
