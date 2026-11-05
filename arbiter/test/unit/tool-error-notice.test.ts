/**
 * tool-error-notice.test.ts — a tool's own error about a secret path
 * (confidentiality.md §7.1, "A tool's error about a secret path"): the exact
 * shapes pass public, and nothing that could carry a byte of a file does.
 *
 * Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { isGitNoContentReport, isReadMissingFileNotice, isShellPathErrorOutput, isWriteRefusalNotice, lockedObjectsIn, unlinkDeniedPathsIn } from "../../policy/tool-error-notice.js";
import { createEngineBackedPolicy } from "../../policy/policy-interface.js";
import { bindSessionSpec } from "../../policy/tool-inbound.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const SECRET = "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc";
const BUDGET = "\n\n<system-reminder>\n<total_tokens>14956073 tokens left</total_tokens>\n</system-reminder>";
const WS = "/tmp/ws-error-notice";
const MISSING = `${WS}/http-client.private.env.json`;
const nothingExists = () => false;
const everythingExists = () => true;

test("Read: the missing-file answer for an absolute path that is not there", () => {
  const v = `File does not exist. Note: your current working directory is ${WS}.`;
  for (const value of [v, v + BUDGET, `${v}\n`]) {
    assert.equal(isReadMissingFileNotice(value, { file_path: MISSING }, nothingExists), true, JSON.stringify(value));
  }
  // the file is there after all: no release (a Read of it is content)
  assert.equal(isReadMissingFileNotice(v, { file_path: MISSING }, everythingExists), false);
  // a relative or absent path: not checked, no release
  assert.equal(isReadMissingFileNotice(v, { file_path: "http-client.private.env.json" }, nothingExists), false);
  assert.equal(isReadMissingFileNotice(v, {}, nothingExists), false);
  for (const bad of [
    `${v} Did you mean ${WS}/api/http-client.private.env.json?`, // names another file
    `${v}\n${SECRET}`, // a byte after it
    `${v} ${SECRET}`,
    `File does not exist. Note: your current working directory is ${SECRET}`, // no final dot
    `File does not exist. Note: your current working directory is relative/${SECRET}.`, // not absolute
    `1\tFile does not exist. Note: your current working directory is ${WS}.`, // a file's rendering
    `File does not exist. Note: your current working directory is ${WS}.` + "\n\n<system-reminder>\n" + SECRET + "\n</system-reminder>",
    `No such file or directory\n${SECRET}`,
    "",
  ]) {
    assert.equal(isReadMissingFileNotice(bad, { file_path: MISSING }, nothingExists), false, JSON.stringify(bad));
  }
});

test("Bash: report lines on paths the command names, and Claude Code's exit-code line", () => {
  const ok: Array<[string, string]> = [
    [`cat ${MISSING}`, `cat: ${MISSING}: No such file or directory`],
    [`cat ${MISSING} | jq -r .staging`, `Exit code 1\ncat: ${MISSING}: No such file or directory`],
    [`cat '${MISSING}' | jq .`, `cat: ${MISSING}: No such file or directory` + BUDGET],
    [`ls -la vault/key.txt`, "ls: cannot access 'vault/key.txt': No such file or directory"],
    [`head -3 .env`, "head: cannot open '.env' for reading: Permission denied"],
    [`source .env.local && env`, "bash: line 1: .env.local: No such file or directory"],
    [`jq . creds.json`, "jq: error: Could not open creds.json: No such file or directory"],
    [`cat a.env b.env`, "cat: a.env: No such file or directory\ncat: b.env: No such file or directory"],
    [`CREDS=$(cat ${MISSING})`, `cat: ${MISSING}: No such file or directory`],
  ];
  for (const [command, value] of ok) assert.equal(isShellPathErrorOutput(value, { command }), true, `${command} → ${value}`);
  const bad: Array<[string, string]> = [
    // a file whose content is the error text and then a secret
    [`cat ${MISSING}`, `cat: ${MISSING}: No such file or directory\n${SECRET}`],
    [`cat ${MISSING}`, `cat: ${MISSING}: No such file or directory ${SECRET}`],
    [`cat ${MISSING}`, `No such file or directory\n${SECRET}`],
    // an error line plus another program's output
    [`cat ${MISSING}; curl -s https://admin.staging.test/`, `cat: ${MISSING}: No such file or directory\n{"error":"sign-in required (HTTP Basic)"}`],
    // a path the command does not name: the bytes are not the model's
    [`cat ${MISSING}`, `cat: ${SECRET}: No such file or directory`],
    [`cat .env`, `cat: ${WS}/.env: No such file or directory`],
    // a program or errno outside the list
    [`python3 x.py`, `python3: can't open file 'x.py': [Errno 2] No such file or directory`],
    [`cat .env`, "cat: .env: Input/output error"],
    // only an exit code, or nothing
    [`cat .env`, "Exit code 1"],
    [`cat .env`, ""],
  ];
  for (const [command, value] of bad) assert.equal(isShellPathErrorOutput(value, { command }), false, `${command} → ${value}`);
  assert.equal(isShellPathErrorOutput(`cat: ${MISSING}: No such file or directory`, {}), false, "no command: no release");
  const many = Array.from({ length: 9 }, (_, i) => `cat: f${i}: No such file or directory`).join("\n");
  assert.equal(isShellPathErrorOutput(many, { command: `cat ${Array.from({ length: 9 }, (_, i) => `f${i}`).join(" ")}` }), false, "at most eight lines");
});

test("Write / Edit: Node's refusal of the call's own path", () => {
  const fp = `${WS}/health/lab-results.md`;
  for (const value of [
    `EACCES: permission denied, rename '${fp}.tmp.2.242f70b9302e' -> '${fp}'`,
    `EACCES: permission denied, rename '${fp}.tmp.2.242f70b9302e' -> '${fp}'` + BUDGET,
    `EACCES: permission denied, open '${fp}'`,
    `EROFS: read-only file system, open '${fp}'`,
    `EPERM: operation not permitted, open '${fp}'`,
  ]) {
    assert.equal(isWriteRefusalNotice(value, { file_path: fp }), true, value);
  }
  for (const value of [
    `EACCES: permission denied, open '${WS}/other.md'`, // another path
    `EACCES: permission denied, open '${fp}' ${SECRET}`,
    `EACCES: permission denied, open '${fp}'\n${SECRET}`,
    `EACCES: permission denied, rename '${fp}.tmp.2.${SECRET}' -> '${fp}'`, // not a hex suffix
    `ENOSPC: no space left on device, write`,
  ]) {
    assert.equal(isWriteRefusalNotice(value, { file_path: fp }), false, value);
  }
  assert.equal(isWriteRefusalNotice(`EACCES: permission denied, open '${fp}'`, {}), false);
});

test("the policy: a labelled path's error passes public under Claude Code's own entries, content keeps the label", () => {
  bindSessionSpec("cc-err", "claude-code");
  const p = createEngineBackedPolicy({ policyFileOverride: { paths: [{ path: `${WS}/**`, level: "no-model" }] }, confidentiality: true, integrity: false });
  const classify = (tool: string, value: string, params: Record<string, unknown>, origin?: string) =>
    p.classify({ tool, value, boundary: "model_context", ...(origin ? { origin } : {}), params, sessionKey: "cc-err" });
  // a path no file sits at (this machine has no /tmp/ws-error-notice)
  assert.equal(classify("Read", `File does not exist. Note: your current working directory is ${WS}.` + BUDGET, { file_path: MISSING }, MISSING).confidentiality, "public");
  assert.equal(classify("Bash", `Exit code 1\ncat: ${MISSING}: No such file or directory` + BUDGET, { command: `cat ${MISSING} | jq .` }).confidentiality, "public");
  const fp = `${WS}/notes.md`;
  assert.equal(classify("Write", `EACCES: permission denied, open '${fp}'`, { file_path: fp, content: "x" }, fp).confidentiality, "public");
  // the same calls with a file's content keep the path's level
  assert.equal(classify("Read", `1\tAPI_KEY=${SECRET}`, { file_path: MISSING }, MISSING).confidentiality, "no-model");
  assert.equal(classify("Bash", `cat: ${MISSING}: No such file or directory\n${SECRET}`, { command: `cat ${MISSING}` }).confidentiality, "no-model");
  // another agent's tool of the same name is not Claude Code's entry
  bindSessionSpec("oc-err", "openclaw-agent");
  assert.equal(p.classify({ tool: "Read", value: `File does not exist. Note: your current working directory is ${WS}.`, boundary: "model_context", origin: MISSING, params: { file_path: MISSING }, sessionKey: "oc-err" }).confidentiality, "no-model");
});

// ── git's report on a history rewrite (2026-10-26) ──────────────────────────

const LOCKED = "7c72b0c959f112730dc47da675a590979839a25e";
const OTHER = "244c7bd48198edc9143a3b1932341bd589ad7a9d";
const isLocked = (id: string) => id === LOCKED;
const FB = "git filter-branch --force --index-filter 'git rm -q --cached --ignore-unmatch .env' -- --all";
const BANNER = [
  "WARNING: git-filter-branch has a glut of gotchas generating mangled history",
  "\t rewrites.  Hit Ctrl-C before proceeding to abort, then use an",
  "\t alternative filtering tool such as 'git filter-repo'",
  "\t (https://github.com/newren/git-filter-repo/) instead.  See the",
  "\t filter-branch manual page for more details; to squelch this warning,",
  "\t set FILTER_BRANCH_SQUELCH_WARNING=1.",
  "Proceeding with filter-branch...",
  "",
].join("\n");
const REWRITE = "\rRewrite fa868d24d68eb52abf9f84d66c4788482c6e7cb5 (1/2) (0 seconds passed, remaining 0 predicted)    \rRewrite e22e7d72bb160a7e544d3626502e4b62f0d4bee8 (2/2) (0 seconds passed, remaining 0 predicted)    ";

test("git: filter-branch's own report (banner, progress, rm of the path it names, refs) passes", () => {
  const ok: Array<[string, string]> = [
    [FB, `${BANNER}\n${REWRITE}\nRef 'refs/heads/main' was rewritten\nWARNING: Ref 'refs/remotes/origin/main' is unchanged`],
    [`git filter-branch --index-filter 'git rm --cached --ignore-unmatch .env' -- --all`, `${BANNER}\n\rRewrite 5cb5b56e8b842ae74079bfedeed233ed6c4d57cd (1/2) (0 seconds passed, remaining 0 predicted)    rm '.env'\nRef 'refs/heads/main' was rewritten` + BUDGET],
    [`${FB} && git push --force origin main`, `${REWRITE}\nRef 'refs/heads/main' was rewritten\nTo git://127.0.0.1:43941/ws-a0d0c6fff6-storefront.git\n + 42df800...5cb94c8 main -> main (forced update)`],
    [`git fetch origin && git reset --hard origin/main && git rm --cached .env`, `From git://127.0.0.1:43941/ws-a0d0c6fff6-storefront\n + 5cb94c8...42df800 main       -> origin/main  (forced update)\nrm '.env'`],
    [`git reflog expire --expire=now --all && git gc --prune=now`, "Enumerating objects: 15, done.\nCounting objects: 100% (15/15), done.\nDelta compression using up to 32 threads\nCompressing objects: 100% (9/9), done.\nWriting objects: 100% (15/15), done.\nTotal 15 (delta 2), reused 0 (delta 0), pack-reused 0"],
    [`git log -p --all`, `error: unable to open loose object ${LOCKED}: Permission denied\nfatal: unable to read ${LOCKED}`],
    [`git filter-repo --invert-paths --path .env --force`, "Parsed 4 commits\nNew history written in 0.03 seconds; now repacking/cleaning...\nRepacking your repo and cleaning out old unneeded objects\nCompletely finished after 0.10 seconds."],
    [FB, `Exit code 1\nCannot create a new backup.\nA previous backup already exists in refs/original/\nForce overwriting the backup with -f`],
  ];
  for (const [command, value] of ok) assert.equal(isGitNoContentReport(value, { command }, isLocked), true, `${command} → ${JSON.stringify(value)}`);
});

test("git: anything that could carry a file's bytes, or a byte the model did not write, keeps the mask", () => {
  const bad: Array<[string, string]> = [
    // a diff line after the progress: the file's content
    [FB, `${REWRITE}\n+STRIPE_SECRET_KEY=${SECRET}`],
    [FB, `${REWRITE}\nRef 'refs/heads/main' was rewritten\n${SECRET}`],
    // a commit subject (`HEAD is now at`), a remote's own text
    [`git reset --hard origin/main && git rm --cached .env`, `HEAD is now at 5cb94c8 rotate key ${SECRET}`],
    [`git push --force origin main`, `remote: ${SECRET}\nTo git://127.0.0.1/x.git\n + 1234567...89abcde main -> main (forced update)`],
    // a remote URL with a user part (it could hold a token)
    [`git push --force origin main`, `To https://x-access-token:${SECRET}@github.example/x.git\n + 1234567...89abcde main -> main (forced update)`],
    // rm of a path the command does not name
    [FB, `${REWRITE}    rm '${SECRET}'`],
    // an unreadable object Mandu did not lock, or no lookup at all
    [`git log -p --all`, `fatal: unable to read ${OTHER}`],
    // a ref name with bytes no ref holds
    [FB, `Ref 'refs/heads/main ${SECRET}' was rewritten`],
    // the progress line with text after it
    [FB, `Rewrite fa868d24d68eb52abf9f84d66c4788482c6e7cb5 (1/2) ${SECRET}`],
    // not a git command
    [`cat .env`, `Ref 'refs/heads/main' was rewritten`],
  ];
  for (const [command, value] of bad) assert.equal(isGitNoContentReport(value, { command }, isLocked), false, `${command} → ${JSON.stringify(value)}`);
  assert.equal(isGitNoContentReport(`fatal: unable to read ${LOCKED}`, { command: "git log -p" }, undefined), false, "no locked set: no release");
});

test("git: its EACCES on removing a work-tree file the command names passes; another path, extra text, a value after it keep the mask (2026-10-27)", () => {
  const live = "git filter-branch --index-filter \"git update-index --remove .env\" --prune-empty -- --all";
  const prog = "Rewrite 4630e26cf401e40a90b505fd594368e180e1f250 (1/4) (0 seconds passed, remaining 0 predicted)    \rRewrite 42df800adf4697eccba104d1be0c8114cb4a6b88 (4/4) (1 seconds passed, remaining 0 predicted)    ";
  // the live take's output (scrub-recheck-20261027-a), the budget tail and all
  assert.equal(isGitNoContentReport(`${prog}\nRef 'refs/heads/main' was rewritten\nRef 'refs/remotes/origin/main' was rewritten\nwarning: unable to unlink '.env': Permission denied${BUDGET}`, { command: live }, undefined), true);
  assert.equal(isGitNoContentReport("error: unable to unlink old '.env': Permission denied\nfatal: Could not reset index file to revision 'origin/main'.", { command: "git reset --hard origin/main -- .env" }, undefined), true);
  const bad: Array<[string, string]> = [
    // a path the command does not name
    [live, "warning: unable to unlink 'bank/statement.md': Permission denied"],
    ["git reset --hard origin/main", "error: unable to unlink old '.env': Permission denied"],
    // extra text, a value after it, another errno, a line break in the path
    [live, "warning: unable to unlink '.env': Permission denied (STRIPE_SECRET_KEY=sk_live_x)"],
    [live, `warning: unable to unlink '.env': Permission denied\n${SECRET}`],
    [live, "warning: unable to unlink '.env': Read-only file system"],
    [live, "warning: unable to unlink '.env\n': Permission denied"],
    // the reset line with more than a ref
    [live, `fatal: Could not reset index file to revision '${SECRET} x'.`],
  ];
  for (const [command, value] of bad) assert.equal(isGitNoContentReport(value, { command }, undefined), false, `${command} → ${JSON.stringify(value)}`);
});

test("git: the paths it could not remove, for the proxy's note (git's own line only, as the result shows it)", () => {
  assert.deepEqual(unlinkDeniedPathsIn("Ref 'refs/heads/main' was rewritten\nwarning: unable to unlink '.env': Permission denied"), [".env"]);
  assert.deepEqual(unlinkDeniedPathsIn("error: unable to unlink old 'storefront/.env': Permission denied\nfatal: Could not reset index file to revision 'origin/main'."), ["storefront/.env"]);
  assert.deepEqual(unlinkDeniedPathsIn("warning: unable to unlink '.env': Permission denied and more"), []);
  assert.deepEqual(unlinkDeniedPathsIn("rm: cannot remove '.env': Permission denied"), [], "only git's own line");
});

test("git: an object git cannot open for EACCES is evidence on its own (the object twins' mode-000 copy), whether or not the arbiter's locked set holds it", () => {
  // live 2026-10-26: the launcher locked a catalog file's versions itself, so the arbiter's set did not hold 7c72b0c
  const none = () => false;
  const repack = `error: unable to mmap .git/objects/7c/${LOCKED.slice(2)}: Permission denied\nerror: ${LOCKED}: object corrupt or missing: .git/objects/7c/${LOCKED.slice(2)}\nmissing blob ${LOCKED}\nfatal: unable to read ${LOCKED}`;
  assert.equal(isGitNoContentReport(repack, { command: "git gc --prune=now" }, none), true);
  const fb = `Rewrite 4630e26cf401e40a90b505fd594368e180e1f250 (1/4) (0 seconds passed, remaining 0 predicted)    Rewrite a473627446fe5422be9ef6b5d3a764a4c16f60cc (2/4) (1 seconds passed, remaining 1 predicted)    error: unable to open loose object ${LOCKED}: Permission denied\nfatal: unable to read ${LOCKED}`;
  assert.equal(isGitNoContentReport(fb, { command: FB }, none), true, "the error after the progress on one line");
  assert.deepEqual(lockedObjectsIn(repack, none), [LOCKED]);
  assert.deepEqual(lockedObjectsIn(fb, undefined), [LOCKED]);
  // a "could not read" with no EACCES and no lock is not one of ours
  assert.equal(isGitNoContentReport(`fatal: unable to read ${OTHER}`, { command: "git log -p" }, none), false);
  assert.equal(isGitNoContentReport(`error: ${OTHER}: object corrupt or missing: .git/objects/24/${OTHER.slice(2)}\n${SECRET}`, { command: "git log -p" }, none), false);
});

test("git: the locked objects a result reports, for the proxy's note", () => {
  assert.deepEqual(lockedObjectsIn(`commit a473627\n\nerror: unable to open loose object ${LOCKED}: Permission denied\nfatal: unable to read ${LOCKED}`, isLocked), [LOCKED]);
  assert.deepEqual(lockedObjectsIn(`fatal: unable to read ${OTHER}`, isLocked), [], "an object Mandu did not lock is not explained");
  assert.deepEqual(lockedObjectsIn(`fatal: unable to read ${LOCKED} and more`, isLocked), [], "only git's exact line");
  assert.deepEqual(lockedObjectsIn(`fatal: unable to read ${LOCKED}`, undefined), []);
});

test("the policy: filter-branch's report on .env passes public with the locked set wired; a diff of it keeps the label", () => {
  bindSessionSpec("cc-git", "claude-code");
  const p = createEngineBackedPolicy({ policyFileOverride: {}, confidentiality: true, integrity: false, lockedObject: isLocked });
  const classify = (command: string, value: string) => p.classify({ tool: "Bash", value, boundary: "model_context", params: { command }, sessionKey: "cc-git" });
  // `.env` names the catalog's secret shape: the command's output was masked whole
  assert.equal(classify(FB, `${REWRITE}\nRef 'refs/heads/main' was rewritten`).confidentiality, "public");
  assert.equal(classify(FB, `${REWRITE}\n+STRIPE_SECRET_KEY=${SECRET}`).confidentiality, "no-model");
  assert.equal(classify("git show a473627 -- .env", `error: unable to open loose object ${LOCKED}: Permission denied\nfatal: unable to read ${LOCKED}`).confidentiality, "public");
});
