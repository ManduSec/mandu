/**
 * hardened-git-parity — ONE git hardening in four packages
 * (docs/design/architecture/write-protection.md §8.3).
 *
 * launcher, arbiter, dashboard and fs-sync ship standalone, so
 * src/hardened-git.ts is copied verbatim into each. A drift would leave one
 * package starting a program another one refuses. This file:
 *   - holds the four copies byte-identical (the drift check), the four of
 *     src/bwrap-path.ts it imports (which bubblewrap the git sandbox runs,
 *     rootless-confinement-ubuntu-2404.md §0.7), and the two
 *     copies of src/child-run.ts, the runner under the arbiter's and the
 *     launcher's git calls (§5.1);
 *   - runs every git subcommand those packages use, through EACH copy's
 *     arguments and environment, over a hostile repository
 *     (tests/lib/hostile-git-repo.ts) with the same poisoned `GIT_*` in the
 *     parent environment, and requires that no marker fires: the command
 *     forms the launcher, the arbiter, the dashboard and fs-sync issue,
 *     including fs-sync's commit (hooks, signing, auto gc and maintenance).
 *
 * The git sandbox is off (MANDU_GIT_SANDBOX=0): it would stop a marker from
 * writing; the hardening is under test here.
 *
 * docs-lane-exempt: the git calls (ls-files among them) run in temporary
 * hostile repositories, never over the docs.
 */
process.env["MANDU_GIT_SANDBOX"] = "0";

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { stateAxes } from "../lib/axes.js";
import { gitConfigHooksUnswitchable, gitRunsConfigHooks, gitVersion, hostileRepo, unhardenedFires, type HostileRepo } from "../lib/hostile-git-repo.js";
import * as launcher from "../../launcher/src/hardened-git.js";
import * as arbiter from "../../arbiter/src/hardened-git.js";
import * as dashboard from "../../dashboard/src/hardened-git.js";
import * as fsSync from "../../fs-sync/src/hardened-git.js";

stateAxes("secrets"); // no axis is read; the launch prep and the scans it hardens serve the confidentiality axis

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const PKGS: Array<[string, typeof launcher]> = [["launcher", launcher], ["arbiter", arbiter], ["dashboard", dashboard], ["fs-sync", fsSync]];

const repos: HostileRepo[] = [];
after(() => { for (const r of repos) r.cleanup(); });

test("the four copies of hardened-git.ts are byte-identical", () => {
  const master = readFileSync(join(ROOT, "launcher/src/hardened-git.ts"), "utf8");
  for (const p of ["arbiter", "dashboard", "fs-sync"]) {
    assert.equal(readFileSync(join(ROOT, `${p}/src/hardened-git.ts`), "utf8"), master,
      `${p}/src/hardened-git.ts drifted from launcher/src/hardened-git.ts; copy the launcher's file out again`);
  }
});

test("the four copies of bwrap-path.ts (which bubblewrap the git sandbox runs, never one inside the working directory) are byte-identical", () => {
  // rootless-confinement-ubuntu-2404.md §0.7: a drift would let one
  // package's git sandbox run a `bwrap` planted in the workspace, or ignore
  // an administrator's `bwrap_path`.
  const master = readFileSync(join(ROOT, "launcher/src/bwrap-path.ts"), "utf8");
  for (const p of ["arbiter", "dashboard", "fs-sync"]) {
    assert.equal(readFileSync(join(ROOT, `${p}/src/bwrap-path.ts`), "utf8"), master,
      `${p}/src/bwrap-path.ts drifted from launcher/src/bwrap-path.ts; copy the launcher's file out again`);
  }
});

test("the two copies of child-run.ts (the runner under the arbiter's and the launcher's git calls) are byte-identical", () => {
  // write-protection.md §8.5.1: a drift would leave one package's sandboxed git
  // killable only by its direct child, the orphan hang.
  const master = readFileSync(join(ROOT, "arbiter/src/child-run.ts"), "utf8");
  assert.equal(readFileSync(join(ROOT, "launcher/src/child-run.ts"), "utf8"), master,
    "launcher/src/child-run.ts drifted from arbiter/src/child-run.ts; copy the arbiter's file out again");
});

/** The command forms the four packages issue (their git runners prepend
 *  the hardening). `null` input: none. */
const FORMS: Array<{ what: string; args: string[]; input?: string; literal?: boolean; promisor?: boolean; settled?: boolean; runsHooks?: boolean }> = [
  { what: "the history walk (launcher, arbiter)", args: ["log", "--all", "--reflog", "-m", "--root", "--format=", "--raw", "-z", "--no-abbrev", "--no-renames", "--", "config.env"], literal: true },
  { what: "the scan's trace walk", args: ["log", "--all", "--reflog", "-m", "--root", "--no-renames", "--raw", "--no-abbrev", "--format=commit %H"], literal: true },
  { what: "the dashboard's commit list", args: ["log", "--format=COMMIT:%H%n%s%n%an%n%aI%n%D", "--name-only"] },
  { what: "the dashboard's commit detail", args: ["log", "-1", "--format=%H%n%s%n%an%n%aI%n%D%n%b", "HEAD~1"] },
  { what: "the dashboard's diff", args: ["diff-tree", "-p", "--root", "--no-ext-diff", "--no-textconv", "HEAD"] },
  { what: "the index read", args: ["ls-files", "-s", "-z"], literal: true },
  { what: "gitRevOf's reads", args: ["ls-files", "--debug"] },
  { what: "gitRevOf's staged check", args: ["diff-index", "--cached", "--quiet", "HEAD", "--"] },
  { what: "gitRevOf's untracked list", args: ["ls-files", "-o", "--exclude-standard", "-z"] },
  { what: "the working-copy hash", args: ["hash-object", "--no-filters", "--", "config.env", "crlf.txt"], literal: true },
  { what: "the history state", args: ["rev-list", "--all", "--reflog", "--no-walk"] },
  { what: "the scan's object list", args: ["rev-list", "--all", "--reflog", "--objects"] },
  { what: "the reflogs' names kept and peeled (launcher, arbiter)", args: ["rev-list", "--no-walk", "--ignore-missing", "--stdin"], input: "HEAD\n" },
  { what: "the scan's object list from the reflogs' names", args: ["rev-list", "--all", "--ignore-missing", "--stdin", "--objects"], input: "HEAD\n" },
  { what: "the scan's trace walk from the reflogs' names", args: ["log", "--all", "--ignore-missing", "--stdin", "-m", "--root", "--no-renames", "--raw", "--no-abbrev", "--format=commit %H"], input: "HEAD\n", literal: true },
  { what: "the ref storage (arbiter's history readers)", args: ["config", "-z", "--get-regexp", "^extensions\\.refstorage$"] },
  { what: "the repository facts", args: ["rev-parse", "--show-toplevel", "--show-object-format", "--git-path", "shallow", "--git-common-dir"] },
  { what: "replace refs", args: ["for-each-ref", "--format=%(objectname) %(refname)", "refs/replace/"] },
  { what: "the blob reader", args: ["cat-file", "--batch"], input: "HEAD:config.env\n" },
  { what: "the net guard's remotes", args: ["config", "--get-regexp", "^remote\\..*\\.url$"] },
  { what: "the dashboard's file browser", args: ["ls-tree", "-r", "-l", "-z", "HEAD"] },
  { what: "the self-status range", args: ["diff", "--no-ext-diff", "--no-textconv", "--name-only", "HEAD~1", "HEAD", "--", "."] },
  { what: "fs-sync's ignore check", args: ["check-ignore", "-z", "--stdin"], input: "node_modules/x\0" },
  { what: "fs-sync's commit (hooks, config hooks, signing, auto gc, maintenance)", args: ["commit", "-q", "--allow-empty", "-m", "sync"], settled: true, runsHooks: true },
  { what: "a lazy fetch (the blob reader on a partial clone)", args: ["cat-file", "--batch"], input: "0000000000000000000000000000000000000001\n", promisor: true },
  { what: "a fetch", args: ["fetch", "origin"] },
];

test("control: a stock commit in the settled repository runs its hooks and its signer", () => {
  const settled = hostileRepo({ settled: true });
  repos.push(settled);
  const fired = unhardenedFires(settled, ["commit", "-q", "--allow-empty", "-m", "sync"]);
  for (const m of ["hook-pre-commit", "hook-commit-msg", "gpg"]) assert.ok(fired.includes(m), `${m} fires under a stock git: ${fired.join(", ")}`);
  // Config-based hooks (git 2.54+), the included one too: the hooks
  // directory's override does not reach them. An older git has none to run.
  for (const m of ["cfghook-pre-commit", "cfghook-commit-msg", "cfghook-included"]) {
    assert.equal(fired.includes(m), gitRunsConfigHooks(), `${m} fires under a stock git ${gitVersion().join(".")} exactly when it runs config hooks: ${fired.join(", ")}`);
  }
  assert.equal(fired.some((m) => m.startsWith("filter-")), false, "no work-tree compare in a settled repository (the filter residual is fs-sync's, §6)");
});

const configHooksSkip = !gitRunsConfigHooks() ? `git ${gitVersion().join(".")} runs no config-based hooks (git 2.54 and later do)`
  : gitConfigHooksUnswitchable() ? "git 2.54 has no hook.<event>.enabled switch (write-protection.md §8.6)" : false;

test("config-based hooks: the hooks directory's override alone leaves them running; the forced event switches stop every one", { skip: configHooksSkip }, () => {
  const settled = hostileRepo({ settled: true });
  repos.push(settled);
  const commit = ["commit", "-q", "--allow-empty", "-m", "sync"];
  // Every forced key but the event switches: the hooks directory is
  // redirected, the commit's config hooks still run.
  const noSwitch = launcher.GIT_NO_PROGRAM_CONFIG.filter((kv) => !kv.startsWith("hook."));
  const without = unhardenedFires(settled, [...noSwitch.flatMap((kv) => ["-c", kv]), ...commit]);
  for (const m of ["cfghook-pre-commit", "cfghook-commit-msg", "cfghook-included"]) assert.ok(without.includes(m), `${m} runs without the event switches: ${without.join(", ")}`);
  assert.equal(without.some((m) => m.startsWith("hook-")), false, "no hook from a hooks directory");
  assert.deepEqual(unhardenedFires(settled, [...launcher.HARDENED_GIT_GLOBAL_ARGS, ...commit]), [], "the hardened commit runs no hook");
});

for (const [name, pkg] of PKGS) {
  test(`${name}: every command form, hardened by this copy, starts nothing the hostile repository names`, () => {
    const plain = hostileRepo();
    const promisor = hostileRepo({ promisor: true });
    const settled = hostileRepo({ settled: true });
    repos.push(plain, promisor, settled);
    // A parent environment an attacker would like to reach git.
    const poisoned: Record<string, string | undefined> = {
      ...process.env,
      GIT_CONFIG_PARAMETERS: `'core.fsmonitor'='${join(plain.dir, "bin", "fsmonitor")}'`,
      GIT_EXTERNAL_DIFF: join(plain.dir, "bin", "extdiff"),
      GIT_SSH_COMMAND: join(plain.dir, "bin", "ssh"),
      GIT_PAGER: join(plain.dir, "bin", "pager"),
      GIT_DIR: join(plain.root, ".git"),
      GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
    };
    for (const f of FORMS) {
      const r = f.promisor ? promisor : f.settled ? settled : plain;
      const env = pkg.hardenedGitEnv(poisoned, {
        LC_ALL: "C", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
      });
      const cmd = pkg.gitCommand(pkg.hardenedGitArgs(f.args, { literalPathspecs: f.literal === true }), pkg.gitSandbox());
      spawnSync(cmd.file, cmd.args, { cwd: r.root, env, input: f.input ?? "", stdio: ["pipe", "ignore", "ignore"], timeout: 30_000 });
      let fired = r.fired();
      if (f.runsHooks === true && gitConfigHooksUnswitchable()) {
        // git 2.54: config hooks with no switch by event (write-protection.md
        // §8.6). fs-sync's commit (frozen axis) runs them there. The residual
        // is pinned, not hidden: only the config hooks of a commit's events.
        const hooks = fired.filter((m) => m.startsWith("cfghook-"));
        const commitHooks = ["cfghook-commit-msg", "cfghook-included", "cfghook-post-commit", "cfghook-post-index-change", "cfghook-pre-commit", "cfghook-prepare-commit-msg", "cfghook-reference-transaction"];
        assert.deepEqual(hooks.filter((m) => !commitHooks.includes(m)), [], `git 2.54, ${name}: ${f.what}: only a commit's config hooks (${hooks.join(", ")})`);
        fired = fired.filter((m) => !m.startsWith("cfghook-"));
      }
      assert.deepEqual(fired, [], `${name}: ${f.what} (git ${f.args.join(" ")}) started a program`);
    }
  });
}
