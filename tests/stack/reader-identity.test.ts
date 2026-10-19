/**
 * reader-identity e2e — Plan 13 D8 (confidentiality-plan-13-reader-set-labels.md
 * §3, §7 step 8): a reader of a secret file is the BINARY the human named or
 * approved, over the production wiring.
 *
 *   - the code-running-reader rule is one table in the three places that ship
 *     it standalone (arbiter/policy/flow-taint.ts `readerRunsCode`, the
 *     validator's warning; dashboard/src/view-model/reader-runs-code.ts, the
 *     rule row's and the file page's warning; the guard's secret_open.rs,
 *     the ssh-agent socket's readers);
 *   - a REAL ArbiterServer with a file-backed law, the guard's question
 *     (`decideSecretOpen`) over the production ArbiterClient and the human's
 *     answer over the admin socket: after the human allows /usr/bin/ssh-add, a
 *     copy named ssh-add in the workspace gets no raw byte and no taint, nor does
 *     the allowed binary run with LD_PRELOAD, nor an opener whose guard
 *     reported no identity facts. The same properties under the real guard,
 *     with the canary checked at the program's output, are
 *     launcher/test/secret-readers-live.test.sh steps 12 to 16;
 *   - plan 13 §8 decision (b) (2026-10-02): a reader entry naming a shell or
 *     an interpreter alone admits nothing. Over the same wiring, with
 *     `readers: [bash, python3]` and a script pin beside them: `bash -c '.
 *     .env'` and `python3 -c` get no raw byte, no taint and no Inbox row
 *     (ask: always), and nothing is pinned; python3 running the pinned
 *     script still reads raw; and a standing *Always* the human gave
 *     python3 running a script admits no inline code of the same binary.
 *     Under the real guard: launcher/test/secret-readers-live.test.sh (6b),
 *     pipe-taint-live.test.sh and tests/sandbox/guard/script-reader-pin.test.ts;
 *   - plan 13 §8 decision (c): the Always names the script, so python3
 *     running another script of the same binary is asked under its own row;
 *   - plan 13 D8, printers admit nothing (the maintainer's decision of
 *     2026-10-03): one printer table in the arbiter, the dashboard and the
 *     guard (which judges the ssh-agent socket's readers with it, leftover
 *     (3b) of !437; the arbiter decides every file open); over
 *     the production wiring, `cat` listed for a file (bare, and pinned by
 *     path and hash) gets the twin under `others: twin` and the refusal
 *     without it, under `ask: always`, with no taint, no Inbox row and no
 *     pin; a standing *Always* the human gave /usr/bin/cat before the
 *     decision admits nothing; `ssh-add` listed beside it still reads raw;
 *   - the !437 leftovers (2026-10-03): `curl` and `wget` (programs that
 *     fetch a URL or a file, a local one included) listed admit nothing;
 *     the host's `cat` copied under another name and pinned by path and hash
 *     admits nothing (its hash is a printer's); a pending question an older
 *     arbiter filed about a printer is listed nowhere and its answer is
 *     refused; and, durably, such questions left in mandu.db are removed at
 *     the next start, a stale Allow grants nothing, the guard still holding
 *     the open gets the twin, and no id is reused across restarts. Under the real guard: launcher/test/pipe-taint-live.test.sh
 *     and secret-readers-live.test.sh (6d).
 *   - the code-running list by content (2026-10-03): the host's interpreter
 *     copied under another name and pinned by path and hash admits nothing
 *     (its hash is an installed interpreter's: no byte, no taint, no row, an
 *     old Always spent on nothing), and `whyPath` (`readersCopyOf`) and the
 *     warnings name what it is a copy of; tnftp's `ftp` and aria2c (its
 *     `--on-download-*` hooks) listed admit nothing. Under the real guard:
 *     secret-readers-live.test.sh (6e), a renamed, pinned copy of bash.
 *   - its leftovers (2026-10-03): an interpreter no installed program's
 *     hash matches (a pyenv build), pinned, is refused on the guard's
 *     content finding (`runs:python`) with no taint and no row; the guard's
 *     socket question (`readerProgram`) over the production client knows a
 *     renamed copy by the host scan; and the dashboard's secrets panel and
 *     file page, fed by the real arbiter, mark the pinned copy, which the
 *     name rule alone did not. Under the real guard:
 *     secret-readers-live.test.sh (6f) and (4c).
 *   - programs known by name only (P0 item 14, 2026-10-07; plan 13 D8
 *     (13)): the names nushell, the pdksh line and Racket install as are
 *     in the three copies; over the production wiring a GNU printer no
 *     hash knows (`pkg:coreutils`) and a nushell build (`runs:nushell`),
 *     pinned and vouched for, admit nothing, and the dashboard's rule list,
 *     fed by the real arbiter's snapshot, shows its per-entry judgment.
 *     Under the real guard: secret-readers-live.test.sh (6h) and (6i).
 *
 * Axes stated: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { CODE_RUNNING_READERS as ARBITER_LIST, PRINTER_READERS as ARBITER_PRINTERS, PRINTER_NAME_PREFIXES as ARBITER_PREFIXES, scriptPrints as arbiterScriptPrints, VETTED_READERS as ARBITER_VETTED, entryReadsTwin as arbiterReadsTwin, readerPrints as arbiterPrints, readerRunsCode as arbiterRule, readerVetted as arbiterVetted } from "../../arbiter/policy/flow-taint.js";
import { policyWarnings } from "../../arbiter/policy/policy-file-validate.js";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { EgressApprovalStore } from "../../arbiter/policy/egress-approvals.js";
import { CODE_RUNNING_READERS as DASHBOARD_LIST, PRINTER_READERS as DASHBOARD_PRINTERS, PRINTER_NAME_PREFIXES as DASHBOARD_PREFIXES, scriptPrints as dashboardScriptPrints, VETTED_READERS as DASHBOARD_VETTED, codeRunningReadersWarning, entryReadsTwin as dashboardReadsTwin, readerPrints as dashboardPrints, readerRunsCode as dashboardRule, readerVetted as dashboardVetted } from "../../dashboard/src/view-model/reader-runs-code.js";
import { toSecretsPanel } from "../../dashboard/src/view-model/secrets.js";
import { toPolicyPanelViewModel } from "../../dashboard/src/view-model/policy-panel.js";
import type { PolicySnapshot } from "../../dashboard/src/policy-model.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the confidentiality axis is what a reader's identity guards

/** A guard's copy of a list (secret_open.rs `pub const NAME: &[&str]`), read from source. */
function guardTable(name: string): string[] {
  const src = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "interceptors", "net-supervisor", "src", "secret_open.rs"), "utf8");
  const m = new RegExp(`pub const ${name}: &\\[&str\\] = &\\[([\\s\\S]*?)\\];`).exec(src);
  assert.ok(m, `secret_open.rs declares ${name}`);
  return [...m![1]!.replace(/\/\/[^\n]*/g, "").matchAll(/"([^"]+)"/g)].map((x) => x[1]!);
}
const guardList = (): string[] => guardTable("CODE_RUNNING_READERS");

test("one code-running-reader table in the arbiter, the dashboard and the guard; each package warns on the same names", () => {
  assert.deepEqual([...DASHBOARD_LIST].sort(), [...ARBITER_LIST].sort(), "the dashboard's mirror lists the arbiter's names");
  assert.deepEqual(guardList().sort(), [...ARBITER_LIST].sort(), "the guard's mirror (the ssh-agent socket's readers) lists the arbiter's names");
  // plan 13 D8 leftover (3a) of !437: a launcher under a distribution's
  // prefix, a multi-call binary, a relay
  const names = [...ARBITER_LIST, "python3.12", "nc.openbsd", "ssh-add", "aws", "ssh", "git", "cat", "pg_dump", "docker-compose", "bashful", "/usr/bin/node",
    "gnuenv", "gnutimeout", "gnunice", "gnustdbuf", "genv", "gmake", "uu-env", "uu_timeout", "toybox", "/usr/lib/cargo/bin/coreutils/env", "ncat", "gh", "g", "gnu",
    "ftp", "/usr/bin/tnftp", "ftp.tnftp", "aria2c", "sftp", "wget", "lynx", "vim.basic", "kak", "hx", "valgrind", "tmux", "curl", "scp", "xh",
    // 2026-10-04: build tools, versioned names
    "cmake", "ninja", "go", "cargo", "npm", "beam.smp", "pdftex", "php8.5", "/usr/bin/lua5.4", "tclsh8.6", "perl5.40.1", "guile-3.0", "psql16", "x86_64", "gofmt",
    // P0 item 14 (2026-10-07): the names nushell, the pdksh line and Racket install as
    "nu", "/usr/bin/nu", "oksh", "loksh", "racketbc", "racketcs", "numfmt", "uu-", "uu_"];
  for (const n of names) assert.equal(dashboardRule(n), arbiterRule(n), n);
  const readers = ["bash", "ssh-add", { app: "node", from: "make" }];
  const validator = policyWarnings({ version: 1, paths: [{ path: "/w/.env", level: "no-model", readers }] });
  assert.equal(validator.length, 2);
  assert.match(codeRunningReadersWarning(readers) ?? "", /^bash, node run any code/);
});

test("plan 13 D8 (12), the allow-list: one vetted-reader table in the arbiter, the dashboard and the guard; each judges the same entries as reading the placeholder", () => {
  assert.deepEqual([...DASHBOARD_VETTED].sort(), [...ARBITER_VETTED].sort(), "the dashboard's mirror lists the arbiter's vetted readers");
  assert.deepEqual(guardTable("VETTED_READERS").sort(), [...ARBITER_VETTED].sort(), "the guard's mirror (the ssh-agent socket's readers, secret_open.rs VETTED_READERS) lists the arbiter's");
  const names = [...ARBITER_VETTED, "/usr/bin/ssh-add", "ssh.openssh", "psql16", "sshd", "git", "git-credential-store", "aws", "gh", "kubectl", "cat", "bash", "deploy", "/usr/lib/cargo/bin/coreutils/wc"];
  for (const n of names) assert.equal(dashboardVetted(n), arbiterVetted(n), n);
  const entries: unknown[] = ["deploy", "ssh-add", { app: "deploy", prints: "nothing" }, { app: "deploy", path: "/opt/d", sha256: "a".repeat(64) }, { app: "python3", script: "/opt/a.py" }, { app: "python3", script: "/opt/a.py", prints: "nothing" }, "cat", { app: "cat", prints: "nothing" }, { app: "ssh", from: "git" }];
  for (const e of entries) assert.equal(dashboardReadsTwin(e), arbiterReadsTwin(e as never), JSON.stringify(e));
});

test("plan 13 D8, printers admit nothing: one printer table in the arbiter, the dashboard and the guard; each package warns on the same names", () => {
  assert.deepEqual([...DASHBOARD_PRINTERS].sort(), [...ARBITER_PRINTERS].sort(), "the dashboard's mirror lists the arbiter's printers");
  // leftover (3b) of !437: the guard judges the ssh-agent socket's readers
  // with the same table (secret_open.rs PRINTER_READERS); a printer added to
  // the arbiter's is added there in the same change
  assert.deepEqual(guardTable("PRINTER_READERS").sort(), [...ARBITER_PRINTERS].sort(), "the guard's mirror (the ssh-agent socket's readers, secret_open.rs PRINTER_READERS) lists the arbiter's printers");
  // 2026-10-07: git's separately built programs that read .netrc through
  // libcurl (git-http-fetch, -push, git-imap-send) or send a file named by
  // a request (git-http-backend) are in all three (red before: in none)
  // 2026-10-07: the git-credential- prefix class, one table in the three
  assert.deepEqual([...DASHBOARD_PREFIXES], [...ARBITER_PREFIXES], "the dashboard's printer prefixes");
  assert.deepEqual(guardTable("PRINTER_NAME_PREFIXES"), [...ARBITER_PREFIXES], "the guard's printer prefixes");
  for (const n of ["git-credential-libsecret", "/usr/local/bin/git-credential-manager", "git-credential-osxkeychain", "git-credential-", "mygit-credential-x"]) {
    assert.equal(dashboardPrints(n), arbiterPrints(n), n);
  }
  assert.ok(dashboardScriptPrints("/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc") && arbiterScriptPrints("/opt/git-credential-netrc"));
  assert.ok(!dashboardScriptPrints("/opt/tools/load.pl") && !arbiterScriptPrints("/opt/tools/load.pl"));
  for (const n of ["git-http-fetch", "git-http-push", "git-imap-send", "git-http-backend"]) {
    assert.ok(ARBITER_PRINTERS.has(n) && DASHBOARD_PRINTERS.has(n) && guardTable("PRINTER_READERS").includes(n), n);
    assert.ok(dashboardPrints(`/usr/lib/git-core/${n}`) && arbiterPrints(`/usr/libexec/git-core/${n}`), n);
  }
  const names = [...ARBITER_PRINTERS, "xz.alt", "category", "ssh-add", "aws", "git", "curl", "/usr/bin/cat", "/usr/lib/cargo/bin/coreutils/wc", "/usr/bin/wc", "python3", "gnucat", "uu-base64", "gpg-agent", "ssh-add",
    "gcc-15", "clang-18", "cpp-14", "sha256sum", "x86_64-linux-gnu-ld.bfd"];
  for (const n of names) assert.equal(dashboardPrints(n), arbiterPrints(n), n);
  const readers = ["cat", "ssh-add", { app: "base64", path: "/usr/bin/base64", sha256: "a".repeat(64) }];
  const validator = policyWarnings({ version: 1, paths: [{ path: "/w/.env", level: "no-model", readers }] });
  assert.equal(validator.length, 2, validator.join("\n"));
  assert.ok(validator.every((l) => /prints or copies/.test(l)));
  assert.match(codeRunningReadersWarning(readers) ?? "", /^cat, base64 print or copy what they read/);
});

test("plan 13 D8 e2e, printers admit nothing: cat listed for a file (bare or pinned) gets the twin, or the refusal without others: twin; no taint, no row, no pin; an old Always admits nothing; ssh-add beside it reads raw", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-printer-e2e-"));
  const home = join(tmp, "home"); mkdirSync(home, { recursive: true });
  const env = join(home, ".env"); writeFileSync(env, "API_KEY=sk_live_printer_e2e_123\n");
  const deny = join(home, "deny.key"); writeFileSync(deny, "KEY=printer_e2e_456\n");
  const CAT = "/usr/bin/cat", CAT_SHA = "d".repeat(64);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n    others: twin\n    readers:\n      - cat\n      - { app: cat, path: ${CAT}, sha256: ${CAT_SHA} }\n      - ssh-add\n  - path: ${deny}\n    level: no-model\n    readers: [cat]\n`);
  const server = new ArbiterServer({ socketPath: join(tmp, "a.sock"), adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect(); // the guard reports on the human socket (plan 13 D9)
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const session = "s-printer";
  const open = (path: string, exe: string, procKey: string) =>
    guard.decideSecretOpen({ path, exe, sha256: CAT_SHA, isAgent: false, exeSystem: true, openerEnv: [], procKey, session, ask: "always" });
  try {
    const before = readFileSync(policyPath, "utf8");
    const twin = await open(env, CAT, "cat-1");
    assert.equal(twin.verdict, "twin", `${twin.verdict}: ${twin.reason}`);
    assert.match(twin.reason, /prints or copies/);
    assert.equal(twin.approvalId, undefined, "never asked about");
    assert.equal((await guard.processSecretTaint("cat-1")).level, null, "no raw read recorded");
    const refused = await open(deny, CAT, "cat-2");
    assert.equal(refused.verdict, "deny", `${refused.verdict}: ${refused.reason}`);
    assert.equal((await guard.processSecretTaint("cat-2")).level, null);
    assert.deepEqual((await admin.egressApprovals("pending")).filter((a) => a.symbol.startsWith("open:")), [], "no Inbox row");
    assert.equal(readFileSync(policyPath, "utf8"), before, "nothing pinned");
    // a standing Always for /usr/bin/cat from before the decision: no raw byte
    const store = (server as unknown as { egressApprovals: { recordPending(sym: string, d: string, r: string): { id: string }; resolve(id: string, approve: boolean, scope: "once" | "always"): unknown } }).egressApprovals;
    const old = store.recordPending(`open:${CAT}#${CAT_SHA}`, deny, "cat wants to read it");
    store.resolve(old.id, true, "always"); // answered before the decision (an answer now is refused)
    const after = await open(deny, CAT, "cat-3");
    assert.equal(after.verdict, "deny", `the old Always admitted cat (${after.verdict}: ${after.reason})`);
    assert.equal((await guard.processSecretTaint("cat-3")).level, null);
    const why = await admin.whyPath(deny);
    assert.ok(why.verdicts.some((v) => v.exe === CAT && v.printer === true), JSON.stringify(why.verdicts));
    assert.deepEqual((await admin.whyPath(env)).readersPrint, [true, true, false]);
    // the leaf program beside it is unchanged
    const sshAdd = await guard.decideSecretOpen({ path: env, exe: "/usr/bin/ssh-add", sha256: "e".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "psql-1", session, ask: "always" });
    assert.equal(sshAdd.verdict, "raw", sshAdd.reason);
  } finally {
    guard.close(); admin.close(); await server.close(); rmSync(tmp, { recursive: true, force: true });
  }
});

test("Plan 13 D8 e2e: the human allows /usr/bin/pg_dump; a copy named pg_dump in the workspace (same bytes, another path) gets no raw byte and no taint", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-reader-identity-"));
  const home = join(tmp, "home"); mkdirSync(home, { recursive: true });
  const ws = join(tmp, "ws"); mkdirSync(join(ws, "bin"), { recursive: true });
  const pgpass = join(home, ".pgpass"); writeFileSync(pgpass, "db:5432:prod:app:pw_d8_123456\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${pgpass}\n    level: no-model\n    readers: [ssh-add]\n`);
  const socketPath = join(tmp, "a.sock");
  const server = new ArbiterServer({ socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect(); // the guard reports on the human socket (plan 13 D9)
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const session = "s-d8-e2e";
  const sha = "e".repeat(64);
  try {
    const open = (exe: string, procKey: string) =>
      guard.decideSecretOpen({ path: pgpass, exe, sha256: sha, isAgent: false, exeSystem: exe.startsWith("/usr/"), openerEnv: [], procKey, session, ask: "known" });
    // the human allows the system's pg_dump, standing
    const held = await open("/usr/bin/pg_dump", "psql-1");
    assert.equal(held.verdict, "ask");
    await admin.resolveEgressApproval(held.approvalId!, true, "always");
    assert.equal((await open("/usr/bin/pg_dump", "psql-2")).verdict, "raw");

    // the agent's copy: same bytes (a copy has the same hash), another path
    const copy = join(ws, "bin", "pg_dump");
    const v = await open(copy, "copy-1");
    assert.notEqual(v.verdict, "raw", `the copy is not the binary the human allowed (got ${v.verdict}: ${v.reason})`);
    assert.equal((await guard.processSecretTaint("copy-1")).level, null, "no raw read recorded for the copy");

    // the allowed binary run with LD_PRELOAD (the guard's openerEnv) is not
    // the binary the human allowed: no raw byte, no taint, no prompt
    const pre = await guard.decideSecretOpen({ path: pgpass, exe: "/usr/bin/pg_dump", sha256: sha, isAgent: false, exeSystem: true, openerEnv: ["LD_PRELOAD"], procKey: "pre-1", session, ask: "known" });
    assert.equal(pre.verdict, "deny", `${pre.verdict}: ${pre.reason}`);
    assert.equal((await guard.processSecretTaint("pre-1")).level, null);
    // an older guard that reports no identity facts gets no raw byte either
    const bare = await guard.decideSecretOpen({ path: pgpass, exe: "/usr/bin/pg_dump", sha256: sha, isAgent: false, procKey: "old-1", session, ask: "known" });
    assert.notEqual(bare.verdict, "raw", "unreported facts count against the opener");
  } finally {
    guard.close(); admin.close(); await server.close(); rmSync(tmp, { recursive: true, force: true });
  }
});

test("Plan 13 §8 decision (b) e2e: readers [bash, python3] admit no inline code (no byte, no taint, no row, no pin); the pinned script still reads; an Always for python3 running a script admits no inline python", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-decision-b-"));
  const home = join(tmp, "home"); mkdirSync(home, { recursive: true });
  const env = join(home, ".env"); writeFileSync(env, "API_KEY=sk_live_decision_b_123\n");
  const notes = join(home, "notes.key"); writeFileSync(notes, "NOTES=decision_b_456\n");
  const policyPath = join(tmp, "policy.yaml");
  const SCRIPT = "/opt/tools/report.py";
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n    readers:\n      - bash\n      - python3\n      - { app: python3, script: ${SCRIPT}, prints: nothing }\n  - path: ${notes}\n    level: no-model\n    readers: [ssh-add]\n`);
  const server = new ArbiterServer({ socketPath: join(tmp, "a.sock"), adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect(); // the guard reports on the human socket (plan 13 D9)
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const session = "s-decision-b";
  const PY = "/usr/bin/python3.12", PY_SHA = "a".repeat(64), BASH = "/usr/bin/bash", BASH_SHA = "b".repeat(64);
  const script = (path: string) => ({ path, sha256: "c".repeat(64), system: true, isolated: true, traced: false });
  const open = (path: string, exe: string, sha256: string, procKey: string, extra: Record<string, unknown>) =>
    guard.decideSecretOpen({ path, exe, sha256, isAgent: false, exeSystem: true, openerEnv: [], procKey, session, ask: "always", ...extra });
  try {
    // bash -c '. .env', with bash listed: no byte, no taint, no row, no pin
    for (const [exe, sha, problem, key] of [[BASH, BASH_SHA, "inline code (sh -c)", "bash-1"], [PY, PY_SHA, "inline code (python -c)", "py-1"]] as const) {
      const v = await open(env, exe, sha, key, { scriptProblem: problem });
      assert.equal(v.verdict, "deny", `${exe} ${problem}: ${v.reason}`);
      assert.match(v.reason, /reads a secret only as a pinned script/);
      assert.equal(v.approvalId, undefined, "never asked about, even with prompting on for every program");
      assert.equal((await guard.processSecretTaint(key)).level, null, "no raw read recorded");
    }
    assert.deepEqual((await admin.egressApprovals("pending")).filter((a) => a.destination === env), [], "no Inbox row for inline code");
    assert.doesNotMatch(readFileSync(policyPath, "utf8"), /path: \/usr\/bin\/bash/, "nothing pinned for the shell");
    // the pinned script still reads raw, and is pinned with its script
    const pinned = await open(env, PY, PY_SHA, "py-2", { script: script(SCRIPT) });
    assert.equal(pinned.verdict, "raw", pinned.reason);
    assert.match(readFileSync(policyPath, "utf8"), /script: \/opt\/tools\/report\.py/);
    // a script the law does not pin, run by the same listed python3: no reader (the bare entry is inert)
    const other = await open(env, PY, PY_SHA, "py-3", { script: script("/opt/tools/other.py") });
    assert.notEqual(other.verdict, "raw", other.reason);

    // An Always the human gave python3 running a script admits no inline python of that binary.
    const held = await open(notes, PY, PY_SHA, "py-4", { script: script(SCRIPT) });
    assert.equal(held.verdict, "ask", held.reason);
    await admin.resolveEgressApproval(held.approvalId!, true, "always");
    assert.equal((await open(notes, PY, PY_SHA, "py-5", { script: script(SCRIPT) })).verdict, "raw", "the answered pair reads");
    const law = readFileSync(policyPath, "utf8");
    assert.match(law, /script: \/opt\/tools\/report\.py\n\s+scriptSha256: c{64}/, "the Always pinned the interpreter WITH its script (a bare interpreter pin admits nothing)");
    const inline = await open(notes, PY, PY_SHA, "py-6", { scriptProblem: "inline code (python -c)" });
    assert.equal(inline.verdict, "deny", `the Always does not cover python3 -c: ${inline.reason}`);
    assert.equal((await guard.processSecretTaint("py-6")).level, null);
    // decision (c): nor another script of the same binary, asked under its own row
    const other2 = await open(notes, PY, PY_SHA, "py-7", { script: script("/opt/tools/other.py") });
    assert.equal(other2.verdict, "ask", `the Always for report.py covered other.py: ${other2.reason}`);
    assert.equal((await guard.processSecretTaint("py-7")).level, null);
    // plan 13 D8 (12): an interpreter's script is no vetted reader: the warning question
    const rows = (await admin.egressApprovals()).filter((a) => a.destination === notes).map((a) => a.symbol);
    assert.ok(rows.includes(`trust:${PY}#${PY_SHA}#script:${encodeURIComponent("/opt/tools/other.py")}#${"c".repeat(64)}`), rows.join(" | "));
  } finally {
    guard.close(); admin.close(); await server.close(); rmSync(tmp, { recursive: true, force: true });
  }
});

/** This host's `cat`, resolved (GNU's, or uutils' one binary), or null. */
function hostCat(): string | null {
  for (const c of ["/usr/bin/cat", "/bin/cat"]) if (existsSync(c)) return realpathSync(c);
  return null;
}

test("the !437 leftovers e2e: curl and wget listed admit nothing; the host's cat copied under another name and pinned by path and hash admits nothing; a pending question about a printer is listed nowhere and its answer refused", { skip: hostCat() === null ? "no cat on this host" : false }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-printer-left-e2e-"));
  const home = join(tmp, "home"); mkdirSync(home, { recursive: true });
  const env = join(home, ".env"); writeFileSync(env, "API_KEY=sk_live_leftover_e2e_789\n");
  // (2): the human copies the host's cat and pins the copy by path and hash
  const copy = join(tmp, "bin", "mdu-catcopy"); mkdirSync(dirname(copy), { recursive: true });
  copyFileSync(hostCat()!, copy); chmodSync(copy, 0o755);
  const COPY_SHA = createHash("sha256").update(readFileSync(copy)).digest("hex");
  const H = "e".repeat(64);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n    readers:\n      - curl\n      - { app: wget, path: /usr/bin/wget, sha256: ${H} }\n      - { app: mdu-catcopy, path: ${copy}, sha256: ${COPY_SHA} }\n      - ssh-add\n`);
  const server = new ArbiterServer({ socketPath: join(tmp, "a.sock"), adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const open = (exe: string, sha256: string, procKey: string, exeSystem = true) =>
    guard.decideSecretOpen({ path: env, exe, sha256, isAgent: false, exeSystem, openerEnv: [], procKey, session: "s-left", ask: "always" });
  try {
    for (const [exe, sha, key, sys, why] of [
      ["/usr/bin/curl", H, "curl-1", true, /curl prints or copies/],
      ["/usr/bin/wget", H, "wget-2", true, /wget prints or copies/],
      [copy, COPY_SHA, "copy-3", false, /mdu-catcopy is a copy of a program that prints or copies/],
    ] as const) {
      const d = await open(exe, sha, key, sys);
      assert.equal(d.verdict, "deny", `${exe}: ${d.verdict} ${d.reason}`);
      assert.match(d.reason, why);
      assert.equal(d.approvalId, undefined, "never asked about");
      assert.equal((await guard.processSecretTaint(key)).level, null, "no raw read recorded");
    }
    assert.equal((await open("/usr/bin/ssh-add", H, "psql-4")).verdict, "raw", "ssh-add beside them still reads raw");
    const why = await admin.whyPath(env);
    assert.deepEqual(why.readersPrint, [true, true, true, false]);
    assert.deepEqual(why.readersAdmitNothing, [true, true, true, false]);
    // (4): a question an older arbiter filed about a printer
    const store = (server as unknown as { egressApprovals: { recordPending(sym: string, d: string, r: string): { id: string } } }).egressApprovals;
    const old = store.recordPending(`open:/usr/bin/curl#${H}`, env, "curl (/usr/bin/curl) wants to read it as a program");
    assert.deepEqual((await admin.egressApprovals("pending")).filter((a) => a.destination === env), [], "listed nowhere");
    assert.ok(!(await admin.policySnapshot()).verdicts.some((v) => v.id === old.id), "not in the Approvals panel's queue");
    await assert.rejects(admin.resolveEgressApproval(old.id, true, "always"), /no longer applies: curl prints or copies/);
    assert.equal((await open("/usr/bin/curl", H, "curl-5")).verdict, "deny", "and no answer was spent on it");
    assert.ok(!(server as unknown as { egressApprovals: { list(): Array<{ id: string }> } }).egressApprovals.list().some((a) => a.id === old.id), "retired: removed from the store");
  } finally {
    guard.close(); admin.close(); await server.close(); rmSync(tmp, { recursive: true, force: true });
  }
});

/** An interpreter installed on this host (resolved), as the arbiter's scan
 *  finds it, or null. */
function hostInterpreter(): string | null {
  for (const c of ["/usr/bin/python3", "/usr/bin/perl", "/usr/bin/bash", "/bin/sh"]) if (existsSync(c)) return realpathSync(c);
  return null;
}

test("2026-10-03 e2e: the host's interpreter copied under another name and pinned by path and hash admits nothing (no byte, no taint, no row, an old Always spent on nothing); tnftp's ftp and aria2c listed admit nothing; whyPath and the warnings say what the copy is", { skip: hostInterpreter() === null ? "no interpreter on this host" : false }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-interp-copy-e2e-"));
  const home = join(tmp, "home"); mkdirSync(home, { recursive: true });
  const env = join(home, ".env"); writeFileSync(env, "API_KEY=sk_live_interp_copy_e2e_314\n");
  // The human copies the host's interpreter as mytool and pins the copy.
  const real = hostInterpreter()!;
  const copy = join(tmp, "bin", "mdu-mytool"); mkdirSync(dirname(copy), { recursive: true });
  copyFileSync(real, copy); chmodSync(copy, 0o755);
  const COPY_SHA = createHash("sha256").update(readFileSync(copy)).digest("hex");
  const H = "f".repeat(64);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n    readers:\n      - { app: mdu-mytool, path: ${copy}, sha256: ${COPY_SHA} }\n      - ftp\n      - { app: aria2c, path: /usr/bin/aria2c, sha256: ${H} }\n      - ssh-add\n`);
  const server = new ArbiterServer({ socketPath: join(tmp, "a.sock"), adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const open = (exe: string, sha256: string, procKey: string, exeSystem: boolean) =>
    guard.decideSecretOpen({ path: env, exe, sha256, isAgent: false, exeSystem, openerEnv: [], procKey, session: "s-copy", ask: "always" });
  try {
    const before = readFileSync(policyPath, "utf8");
    // A standing Always the human gave the copy before the fix: spent on nothing.
    const store = (server as unknown as { egressApprovals: { recordPending(sym: string, d: string, r: string): { id: string }; resolve(id: string, a: boolean, sc: "once" | "always"): unknown } }).egressApprovals;
    const old = store.recordPending(`open:${copy}#${COPY_SHA}`, env, "mdu-mytool wants to read it as a program");
    store.resolve(old.id, true, "always");
    for (const [exe, sha, key, sys, why] of [
      [copy, COPY_SHA, "copy-1", false, new RegExp(`mdu-mytool is a copy of ${basename(real).replace(/\./g, "\\.")}, a program that runs code it is given`)],
      ["/usr/bin/tnftp", H, "ftp-2", true, /tnftp runs code it is given/],
      ["/usr/bin/aria2c", H, "aria-3", true, /aria2c prints or copies/],
    ] as const) {
      const d = await open(exe, sha, key, sys);
      assert.equal(d.verdict, "deny", `${exe}: ${d.verdict} ${d.reason}`);
      assert.match(d.reason, why);
      assert.equal(d.approvalId, undefined, "never asked about");
      assert.equal((await guard.processSecretTaint(key)).level, null, "no raw read recorded");
    }
    assert.deepEqual((await admin.egressApprovals("pending")).filter((a) => a.symbol.startsWith("open:")), [], "no Inbox row");
    assert.equal(readFileSync(policyPath, "utf8"), before, "nothing pinned");
    assert.equal((await open("/usr/bin/ssh-add", H, "psql-4", true)).verdict, "raw", "ssh-add beside them still reads raw");
    const why = await admin.whyPath(env);
    assert.deepEqual(why.readersAdmitNothing, [true, true, true, false]);
    assert.deepEqual(why.readersPrint, [false, false, true, false]);
    assert.deepEqual(why.readersCopyOf, [basename(real), null, null, null]);
    const doc = await admin.policyDocument();
    assert.ok(doc.onDisk.warnings.some((l) => l.includes(`mdu-mytool is a copy of ${basename(real)}`) && /runs any code it is given/.test(l)), doc.onDisk.warnings.join("\n"));
  } finally {
    guard.close(); admin.close(); await server.close(); rmSync(tmp, { recursive: true, force: true });
  }
});

test("2026-10-03 leftovers e2e: an interpreter no hash knows, by the guard's content finding, admits nothing; the guard's socket question (readerProgram) knows a renamed copy; the dashboard's panels show the arbiter's judgment of a pinned copy", { skip: hostInterpreter() === null ? "no interpreter on this host" : false }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-leftovers-e2e-"));
  const home = join(tmp, "home"); mkdirSync(home, { recursive: true });
  const env = join(home, ".env"); writeFileSync(env, "API_KEY=sk_live_leftovers_e2e_271\n");
  const real = hostInterpreter()!;
  const copy = join(tmp, "bin", "mdu-mytool"); mkdirSync(dirname(copy), { recursive: true });
  copyFileSync(real, copy); chmodSync(copy, 0o755);
  const COPY_SHA = createHash("sha256").update(readFileSync(copy)).digest("hex");
  // (1) a pyenv-style build: no installed program's hash, pinned by the human
  const PYENV = "a9".repeat(32), BUILD = join(tmp, "bin", "mdu-pyenv");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n    readers:\n      - { app: mdu-pyenv, path: ${BUILD}, sha256: ${PYENV}, prints: nothing }\n      - { app: mdu-mytool, path: ${copy}, sha256: ${COPY_SHA}, prints: nothing }\n      - ssh-add\n`);
  const server = new ArbiterServer({ socketPath: join(tmp, "a.sock"), adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  try {
    // (1) the guard's content finding, as it reports it
    const d = await guard.decideSecretOpen({ path: env, exe: BUILD, sha256: PYENV, isAgent: false, exeSystem: true, openerEnv: ["runs:python"], procKey: "pyenv-1", session: "s-left", ask: "always" });
    assert.equal(d.verdict, "deny", d.reason);
    assert.match(d.reason, /by its content, a python interpreter/);
    assert.equal(d.approvalId, undefined, "never asked about");
    assert.equal((await guard.processSecretTaint("pyenv-1")).level, null, "no raw read recorded");
    // (2) the guard's socket question, over the production client: the
    // renamed copy is the interpreter by the host scan, a leaf is a leaf
    const asked = await guard.readerProgram(copy, COPY_SHA);
    assert.equal(asked.runsCode, true, JSON.stringify(asked));
    assert.equal(asked.copyOf, basename(real));
    assert.deepEqual(await guard.readerProgram("/usr/bin/ssh-add", "8".repeat(64)), { prints: false, runsCode: false, copyOf: null });
    // (3) the dashboard over the arbiter's answers: the secrets panel and
    // the file page mark the copy, which the name rule alone did not
    await guard.registerSecret({ path: env });
    const panel = toSecretsPanel(await admin.confidentialityState() as unknown as Parameters<typeof toSecretsPanel>[0]);
    const row = panel.secrets.find((s) => s.path === env)!;
    assert.deepEqual(row.readers, ["mdu-pyenv", "mdu-mytool (admits nothing)", "ssh-add"]);
    const why = await admin.whyPath(env);
    const warn = codeRunningReadersWarning(why.readers, { admitNothing: why.readersAdmitNothing!, print: why.readersPrint!, copyOf: why.readersCopyOf! }) ?? "";
    assert.match(warn, new RegExp(`^mdu-mytool \\(a copy of ${basename(real).replace(/\./g, "\\.")}\\) runs any code it is given`));
    assert.equal(codeRunningReadersWarning(why.readers), null, "the name rule alone saw nothing to warn about");
  } finally {
    guard.close(); admin.close(); await server.close(); rmSync(tmp, { recursive: true, force: true });
  }
});

test("P0 item 14 e2e: a printer's or launcher's package and the families known by name only, by the guard's content findings, admit nothing; the rule list, fed by the real arbiter, shows its judgment of each entry", { skip: hostInterpreter() === null ? "no interpreter on this host" : false }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-p0-14-e2e-"));
  const home = join(tmp, "home"); mkdirSync(home, { recursive: true });
  const env = join(home, ".env"); writeFileSync(env, "API_KEY=sk_live_p0_14_e2e_577\n");
  // a renamed, byte-identical copy of the host's interpreter (the host scan
  // knows it), a non-identical GNU env renamed (only its content says what
  // it is), and nushell by the name it installs as
  const real = hostInterpreter()!;
  const copy = join(tmp, "bin", "mdu-mytool"); mkdirSync(dirname(copy), { recursive: true });
  copyFileSync(real, copy); chmodSync(copy, 0o755);
  const COPY_SHA = createHash("sha256").update(readFileSync(copy)).digest("hex");
  const ENVCOPY = "e7".repeat(32), ENVBIN = join(tmp, "bin", "mdu-envcopy");
  const NU = "c4".repeat(32), NUBIN = join(tmp, "bin", "mdu-shell");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n    readers:\n      - { app: mdu-envcopy, path: ${ENVBIN}, sha256: ${ENVCOPY}, prints: nothing }\n      - { app: mdu-shell, path: ${NUBIN}, sha256: ${NU}, prints: nothing }\n      - { app: mdu-mytool, path: ${copy}, sha256: ${COPY_SHA}, prints: nothing }\n      - nu\n      - ssh-add\n`);
  const server = new ArbiterServer({ socketPath: join(tmp, "a.sock"), adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  try {
    for (const [exe, sha, finding, key, why] of [
      [ENVBIN, ENVCOPY, "pkg:coreutils", "env-1", /mdu-envcopy is, by its content, a program of GNU coreutils/],
      [NUBIN, NU, "runs:nushell", "nu-2", /by its content, a nushell interpreter/],
    ] as const) {
      const d = await guard.decideSecretOpen({ path: env, exe, sha256: sha, isAgent: false, exeSystem: true, openerEnv: [finding], procKey: key, session: "s-p0-14", ask: "always" });
      assert.equal(d.verdict, "deny", `${exe}: ${d.reason}`);
      assert.match(d.reason, why);
      assert.equal(d.approvalId, undefined, "never asked about");
      assert.equal((await guard.processSecretTaint(key)).level, null, "no raw read recorded");
      // the same binary without the finding (the code before) read raw
      assert.equal((await guard.decideSecretOpen({ path: env, exe, sha256: sha, isAgent: false, exeSystem: true, openerEnv: [], procKey: `${key}-before`, session: "s-p0-14" })).verdict, "raw", exe);
    }
    assert.deepEqual((await admin.egressApprovals("pending")).filter((a) => a.symbol.startsWith("open:") || a.symbol.startsWith("trust:")), [], "no Inbox row");
    // the rule list from the real arbiter's snapshot: the renamed copy and
    // `nu` admit nothing, which the names the page mirrors did not all say
    const snapshot = await admin.policySnapshot() as unknown as PolicySnapshot;
    const row = toPolicyPanelViewModel(snapshot).yourRules!.find((r) => r.id === `lock:${env}`)!;
    assert.match(row.effect, new RegExp(`raw readers: mdu-envcopy \\(pinned\\), mdu-shell \\(pinned\\), mdu-mytool \\(a copy of ${basename(real).replace(/\./g, "\\.")}\\) \\(admits nothing\\), nu \\(admits nothing\\), ssh-add \\(others are refused\\)`), row.effect);
  } finally {
    guard.close(); admin.close(); await server.close(); rmSync(tmp, { recursive: true, force: true });
  }
});

test("the !437 leftover (4) e2e, durable: moot questions an older arbiter left in mandu.db are removed at the next start; a stale Allow is refused and grants nothing; the waiting guard's re-ask gets the law's answer; no id is reused across restarts", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-moot-retire-e2e-"));
  const home = join(tmp, "home"); mkdirSync(home, { recursive: true });
  const env = join(home, ".env"); writeFileSync(env, "API_KEY=sk_live_moot_retire_e2e_246\n");
  const H = "f".repeat(64);
  const policyPath = join(tmp, "policy.yaml");
  // `cat` named a reader, as the live store's drill did before printers admitted nothing
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n    others: twin\n    readers: [cat, ssh-add]\n`);
  const dbPath = join(tmp, "db.sqlite");
  // An older arbiter's rows (the live store's `egr-1`, `egr-2`: a cat on a drill's .env)
  const older = new EgressApprovalStore({ dbPath });
  const moot = [
    older.recordPending(`open:/usr/bin/cat#${H}`, env, "cat (/usr/bin/cat) wants to read it as a program", "s-drill"),
    older.recordPending(`open:/usr/bin/cat#${"e".repeat(64)}`, env, "cat (/usr/bin/cat) wants to read it as a program", "s-drill"),
  ];
  older.close();
  const start = async () => {
    const server = new ArbiterServer({ socketPath: join(tmp, "a.sock"), adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath, eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
    await server.listen();
    const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect();
    const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
    return { server, guard, admin, stop: async () => { guard.close(); admin.close(); await server.close(); } };
  };
  const onDisk = (): string[] => { const s = new EgressApprovalStore({ dbPath }); try { return s.list().map((a) => a.id); } finally { s.close(); } };
  try {
    const a = await start();
    try {
      assert.deepEqual(onDisk(), [], "removed from mandu.db at start, before any listing");
      for (const q of moot) {
        await assert.rejects(a.admin.resolveEgressApproval(q.id, true, "always"), /no longer applies: cat prints or copies/, "a stale page's Always");
        await assert.rejects(a.admin.resolveEgressApproval(q.id, true, "once"), /no longer applies/, "a stale page's once");
      }
      assert.deepEqual(await a.admin.egressApprovals(), [], "nothing listed, nothing answered");
      // the guard still holding cat's open re-asks, under every ask mode: the twin, never raw, no new question
      for (const ask of ["always", "known", "never"] as const) {
        const d = await a.guard.decideSecretOpen({ path: env, exe: "/usr/bin/cat", sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: `cat-${ask}`, session: "s-drill", ask });
        assert.equal(d.verdict, "twin", `${ask}: ${d.verdict} ${d.reason}`);
        assert.equal(d.approvalId, undefined, "never asked again");
        assert.equal((await a.guard.processSecretTaint(`cat-${ask}`)).level, null, "no raw read recorded");
      }
      assert.equal((await a.guard.decideSecretOpen({ path: env, exe: "/usr/bin/ssh-add", sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: "psql-1", session: "s-drill" })).verdict, "raw", "the leaf reader beside it is unchanged");
    } finally { await a.stop(); }
    // a restart: the retired ids stay spent, so a stale answer cannot land on a new question
    const b = await start();
    try {
      const fresh = await b.guard.decideSecretOpen({ path: env, exe: "/opt/tools/loader", sha256: H, isAgent: false, exeSystem: false, openerEnv: [], procKey: "loader-1", session: "s-new", ask: "always" });
      assert.equal(fresh.verdict, "ask", fresh.reason);
      assert.ok(fresh.approvalId !== undefined && !moot.some((q) => q.id === fresh.approvalId), `a retired id reused: ${fresh.approvalId}`);
      for (const q of moot) await assert.rejects(b.admin.resolveEgressApproval(q.id, true, "always"), /unknown egress-approval id/);
      assert.deepEqual((await b.admin.egressApprovals("approved")), [], "no approval anywhere");
    } finally { await b.stop(); }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("2026-10-04 e2e: build tools (cmake, go, ninja) and a versioned interpreter (php8.5) listed admit nothing, never asked; cargo reads ~/.cargo/credentials only as a twin; ssh-add beside them still reads raw", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-build-tools-e2e-"));
  const home = join(tmp, "home"); mkdirSync(join(home, ".cargo"), { recursive: true });
  const env = join(home, ".env"); writeFileSync(env, "API_KEY=sk_live_build_tools_e2e_314\n");
  const cred = join(home, ".cargo", "credentials.toml"); writeFileSync(cred, '[registry]\ntoken = "cio_build_tools_e2e_271"\n');
  // A hash no installed program has: only the name can say what each is
  // (red before: php8.5's version suffix was no alternatives suffix).
  const H = "f".repeat(64);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n    readers: [cmake, go, ninja, php8.5, ssh-add]\n  - path: ${cred}\n    level: no-model\n`);
  const server = new ArbiterServer({ socketPath: join(tmp, "a.sock"), adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const open = (path: string, exe: string, procKey: string, ask = "always") =>
    guard.decideSecretOpen({ path, exe, sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey, session: "s-build", ask });
  try {
    for (const [exe, key] of [["/usr/bin/cmake", "cmake-1"], ["/usr/bin/go", "go-2"], ["/usr/bin/ninja", "ninja-3"], ["/usr/bin/php8.5", "php-4"]] as const) {
      const d = await open(env, exe, key);
      assert.equal(d.verdict, "deny", `${exe}: ${d.verdict} ${d.reason}`);
      assert.match(d.reason, /runs code it is given/);
      assert.equal(d.approvalId, undefined, "never asked about");
      assert.equal((await guard.processSecretTaint(key)).level, null, "no raw read recorded");
    }
    assert.equal((await open(env, "/usr/bin/ssh-add", "psql-5")).verdict, "raw", "ssh-add beside them still reads raw");
    const why = await admin.whyPath(env);
    assert.deepEqual(why.readersAdmitNothing, [true, true, true, true, false]);
    // cargo, the consumer-table reader of its credentials, runs the
    // package's build.rs: the twin, never the raw token, no taint
    for (const ask of ["never", "known"]) {
      const d = await open(cred, "/usr/bin/cargo", `cargo-${ask}`, ask);
      assert.equal(d.verdict, "twin", `cargo (${ask}): ${d.verdict} ${d.reason}`);
      assert.equal((await guard.processSecretTaint(`cargo-${ask}`)).level, null);
    }
  } finally {
    guard.close(); admin.close(); await server.close(); rmSync(tmp, { recursive: true, force: true });
  }
});
