/**
 * args-code-reader — confidentiality plan 13 §3 D8, "code by argument"
 * (2026-10-02), as pure decisions (flow-taint.ts).
 *
 * A reader is pinned by its binary; some readers run code their command line
 * or environment hands them (`git -c alias.x='!sh'`, `ssh -o
 * ProxyCommand=…`, `psql -f`, `less +!cmd`, `sed s///e`, `tar
 * --to-command`, `rsync -e`). The guard reports such an invocation as an
 * `args:<program> <option>` finding (args_code.rs) beside D8's loader
 * findings. Asserted here, each marked NEW failing on the code before (an
 * `args:` finding was read as a loader variable named `args:…`: a refusal
 * for a writer, a "loader" message for an opener, and an opener the law did
 * not list was asked about):
 *   - such an opener is no reader of a listed file (deny), gets the twin of
 *     a file with no list even as a known consumer, and is never prompted
 *     for under any `ask` mode;
 *   - a verdict about it has no reusable key (decision (c)'s run key for a
 *     writer), and it is not a loader problem (a writer is asked per run,
 *     not refused);
 *   - an opener with no finding is unchanged (a pinned psql reads raw; git
 *     is a printer since 2026-10-04, plan 13 §4.9, and reads no secret raw
 *     with or without a finding);
 *   - the editors, debuggers and database shells added to the code-running
 *     list admit nothing as readers.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  argsCodeProblem, decideOpen, entryAdmitsNothing, inlineCodeProblem, loaderEnvProblem, readerOutputRefusal, readerRunsCode, verdictProgramOf,
  type OpenerFacts,
} from "../../policy/flow-taint.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const GIT = "/usr/bin/git";
const PSQL = "/usr/bin/psql";
const SSH = "/usr/bin/ssh";
const SHA = "a".repeat(64);
const CREDS = "/home/u/.git-credentials";
const ENV = "/home/u/proj/.env";

const git = (over: Partial<OpenerFacts> = {}): OpenerFacts => ({ exe: GIT, sha256: SHA, exeSystem: true, loaderEnv: [], ...over });
const byArgs = (finding: string, exe = GIT): OpenerFacts => ({ exe, sha256: SHA, exeSystem: true, loaderEnv: [`args:${finding}`] });

test("NEW: argsCodeProblem names the options, and only the args: findings; a loader problem ignores them", () => {
  const o = git({ loaderEnv: ["args:git -c alias.x", "args:git $GIT_SSH_COMMAND"] });
  assert.equal(argsCodeProblem(o), "its command line or environment hands it code to run (git -c alias.x, git $GIT_SSH_COMMAND)");
  assert.equal(loaderEnvProblem(o), null, "an argument is not a loader variable");
  assert.equal(argsCodeProblem(git()), null);
  const both = git({ loaderEnv: ["LD_PRELOAD", "args:git -c core.pager"] });
  assert.match(loaderEnvProblem(both) ?? "", /LD_PRELOAD/);
  assert.doesNotMatch(loaderEnvProblem(both) ?? "", /args:|core\.pager/);
  assert.equal(argsCodeProblem(git({ loaderEnv: undefined })), null, "unchecked is loaderEnvProblem's (unclean)");
  assert.match(loaderEnvProblem(git({ loaderEnv: undefined })) ?? "", /not checked/);
});

test("NEW: an invocation that is handed code is no reader of a listed file, never prompted, under every ask mode", () => {
  // (psql, the earlier carrier of these cases, is a printer since plan 13 D8
  // (12)'s correction; ssh, a vetted reader, carries them)
  const sshF = byArgs("ssh -o proxycommand", SSH);
  for (const ask of ["never", "known", "always"] as const) {
    const d = decideOpen(ENV, { readers: ["ssh"] }, sshF, { ask });
    assert.equal(d.verdict, "deny", `${ask}: ${d.why}`);
    assert.match(d.why, /hands it code to run \(ssh -o proxycommand\)/);
    const t = decideOpen(ENV, { readers: ["ssh"], others: "twin" }, sshF, { ask });
    assert.equal(t.verdict, "twin", `${ask}: others: twin`);
    // git, handed code or not, is a printer (plan 13 §4.9, 2026-10-04)
    const g = decideOpen(ENV, { readers: ["git"] }, byArgs("git -c alias.x"), { ask });
    assert.equal(g.verdict, "deny", `${ask}: ${g.why}`);
    assert.match(g.why, /prints or copies/);
  }
  // control: the same binary with a clean command line reads raw
  assert.equal(decideOpen(ENV, { readers: ["ssh"] }, git({ exe: SSH })).verdict, "raw");
  assert.equal(decideOpen(ENV, { readers: [{ app: "ssh", path: SSH, sha256: SHA, output: "clear" }] }, byArgs("ssh -o proxycommand", SSH)).verdict, "deny", "a full pin (path and hash) does not vouch for the code it is handed either");
  // psql is a printer (plan 13 D8 (12)'s correction): refused, word or not
  assert.equal(decideOpen(ENV, { readers: [{ app: "psql", prints: "nothing" }] }, git({ exe: PSQL })).verdict, "deny");
});

test("NEW: a known consumer handed code gets the twin of a file with no reader list (psql and .pgpass, ssh and its key; git and .git-credentials)", () => {
  for (const ask of ["never", "known", "always"] as const) {
    assert.equal(decideOpen("/home/u/.pgpass", {}, byArgs("psql -f", PSQL), { ask }).verdict, "twin", ask);
    assert.equal(decideOpen("/home/u/.pgpass", {}, byArgs("pg_dump --filter", "/usr/bin/pg_dump"), { ask }).verdict, "twin", ask);
    assert.equal(decideOpen("/home/u/.ssh/id_ed25519", {}, byArgs("ssh -o proxycommand", "/usr/bin/ssh"), { ask }).verdict, "twin", ask);
    assert.equal(decideOpen(CREDS, {}, byArgs("git $GIT_CONFIG_PARAMETERS credential.helper"), { ask }).verdict, "twin", ask);
  }
  // psql is a printer since plan 13 D8 (12)'s correction: its password
  // file's twin (Postgres has no wire release)
  assert.equal(decideOpen("/home/u/.pgpass", {}, git({ exe: PSQL })).verdict, "twin");
  assert.equal(decideOpen("/home/u/.ssh/id_ed25519", {}, git({ exe: "/usr/bin/ssh" })).verdict, "raw");
  // git is a printer since 2026-10-04 (plan 13 §4.9): its credential store's
  // twin even with a clean command line (the wire release puts it back)
  assert.equal(decideOpen(CREDS, {}, git()).verdict, "twin");
});

test("NEW: no reusable verdict for an invocation handed code; inlineCodeProblem says why (the prior-verdict gate)", () => {
  assert.equal(verdictProgramOf(byArgs("git -c alias.x")), null, "keyed by its run (decision (c)), never by the binary alone");
  assert.equal(verdictProgramOf(git()), undefined, "a clean leaf program: the binary alone, as before");
  assert.match(inlineCodeProblem(byArgs("psql -f", "/usr/bin/psql")) ?? "", /psql -f/);
  assert.equal(inlineCodeProblem(git()), null);
});

test("NEW: editors, debuggers and database shells run code they are given: listed alone they admit nothing, and their output is never cleared", () => {
  for (const app of ["vim", "vi", "nvim", "ex", "view", "emacs", "ed", "gdb", "strace", "sqlite3", "expect", "flock", "unshare", "bwrap", "su", "time"]) {
    assert.ok(readerRunsCode(app), app);
    assert.ok(entryAdmitsNothing(app), app);
    assert.notEqual(readerOutputRefusal(app, "clear"), null, app);
    const d = decideOpen(ENV, { readers: [app] }, { exe: `/usr/bin/${app}`, sha256: SHA, exeSystem: true, loaderEnv: [] }, { ask: "always" });
    assert.equal(d.verdict, "deny", `${app}: ${d.why}`);
  }
  // leaf programs are untouched
  for (const app of ["psql", "git", "ssh", "less", "tar", "sed", "rsync", "cat", "curl", "vimtutor-not", "exiftool"]) assert.equal(readerRunsCode(app), false, app);
});
