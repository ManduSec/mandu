/**
 * reader-allow-list — confidentiality plan 13 §3 D8 (12), the maintainer's
 * decision of 2026-10-04: raw bytes go only to a vetted reader
 * (`VETTED_READERS`: ssh, ssh-add since the correction) or to a
 * program its reader entry vouches for (`prints: nothing`, the human's
 * word, independent of `output:`); every other program gets the twin, and
 * under `ask: always` is held with the warning question (`trust:`), whose
 * *Always allow* writes the word into the law. A printer or a program that
 * runs code is refused first, whatever the entry says. An answer given to
 * the old question (`open:`) about an unvetted program no longer counts.
 * `git` and `git-credential-store` are printers (§4.9 option (a)).
 *
 * Each `twin` / `ask` for an unvetted program here was `raw` on the code
 * before. Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  VETTED_READERS, binaryVetted, decideOpen, entryReadsTwin, entryVouches, mootQuestionReason, printerOpenVerdict, readerPrints, readerVetted,
  trustVerdictSubject, unvettedOpenVerdict, withPinnedReader, type ReaderEntry,
} from "../../policy/flow-taint.js";
import { policyWarnings, validatePolicyDocument } from "../../policy/policy-file-validate.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const H = "a".repeat(64);
const SYS = { exeSystem: true, loaderEnv: [] as string[] };
const ENV = "/w/.env";
const at = (exe: string) => ({ exe, sha256: H, ...SYS });

test("the vetted readers: only the programs probed not to print a file (ssh, ssh-add); no printer, no code runner, no unprobed consumer", () => {
  assert.deepEqual([...VETTED_READERS].sort(), ["ssh", "ssh-add"]);
  for (const n of ["ssh-add", "/usr/bin/ssh-add", "ssh", "ssh.openssh"]) assert.ok(readerVetted(n), n);
  for (const n of ["psql", "pg_dump", "pg_restore", "git", "git-credential-store", "aws", "gh", "docker", "kubectl", "helm", "curl", "scp", "npm", "node", "cargo", "twine", "cat", "python3", "mytool", "psql16", "sshd", "vault"]) {
    assert.equal(readerVetted(n), false, n);
  }
  // git prints (§4.9 option (a)); its credential helper prints what it
  // stores; psql and pg_restore print a file (probed, D8 (12)'s correction);
  // pg_dump does not, and is unvetted (its word lets it read)
  for (const n of ["git", "git-credential-store", "psql", "pg_restore"]) assert.ok(readerPrints(n), n);
  assert.equal(readerPrints("pg_dump"), false);
  // a renamed copy is judged by its name, and a printer's hash is never vetted
  assert.equal(binaryVetted({ exe: "/opt/x/mypsql", sha256: H }), false);
});

test("decideOpen: a listed program that is neither vetted nor vouched for reads the twin (never asked, whatever `others:`); under ask: always it is held with the warning", () => {
  for (const others of [undefined, "twin", "deny"] as const) {
    for (const ask of ["never", "known"] as const) {
      const d = decideOpen(ENV, { readers: ["deploy"], ...(others ? { others } : {}) }, at("/usr/bin/deploy"), { ask });
      assert.equal(d.verdict, "twin", `${others} ${ask}: ${d.why}`);
      assert.match(d.why, /deploy is not a program Mandu knows keeps a file's contents out of what it prints/);
      assert.match(d.why, /\{ app: deploy, prints: nothing \}/, "the way out");
    }
  }
  const held = decideOpen(ENV, { readers: ["deploy"] }, at("/usr/bin/deploy"), { ask: "always" });
  assert.equal(held.verdict, "ask");
  assert.equal(held.unvetted, true);
  // an unlisted unvetted program under ask: always: the warning question too
  const unlisted = decideOpen(ENV, { readers: ["ssh-add"] }, at("/usr/bin/other"), { ask: "always" });
  assert.equal(unlisted.verdict, "ask");
  assert.equal(unlisted.unvetted, true);
  // ...and a vetted one: the ordinary question
  assert.equal(decideOpen(ENV, { readers: [] }, at("/usr/bin/ssh"), { ask: "always" }).unvetted, undefined);
  assert.equal(decideOpen(ENV, { readers: [] }, at("/usr/bin/pg_dump"), { ask: "always" }).unvetted, true, "pg_dump: unprobed for a clean bill, so the warning question");
});

test("decideOpen: the human's word reads raw, in every form; a vetted reader needs none", () => {
  const forms: ReaderEntry[] = [
    { app: "deploy", prints: "nothing" },
    { app: "deploy", path: "/usr/bin/deploy", sha256: H, prints: "nothing" },
    { app: "deploy", path: "/usr/bin/deploy", sha256: H, prints: "nothing", output: "secret" },
  ];
  for (const e of forms) {
    assert.ok(entryVouches(e), JSON.stringify(e));
    assert.equal(entryReadsTwin(e), false);
    const d = decideOpen(ENV, { readers: [e] }, at("/usr/bin/deploy"), { ask: "always" });
    assert.equal(d.verdict, "raw", `${JSON.stringify(e)}: ${d.why}`);
    assert.match(d.why, /prints: nothing/);
  }
  // a pin without the word is no vouch: Mandu writes pins too
  const pin = { app: "deploy", path: "/usr/bin/deploy", sha256: H };
  assert.equal(entryVouches(pin), false);
  assert.ok(entryReadsTwin(pin));
  assert.equal(decideOpen(ENV, { readers: [pin] }, at("/usr/bin/deploy")).verdict, "twin");
  // vetted: raw, bare or pinned; default readers of their own files
  assert.equal(decideOpen(ENV, { readers: ["ssh-add"] }, at("/usr/bin/ssh-add")).verdict, "raw");
  assert.equal(decideOpen("/h/.pgpass", {}, at("/usr/bin/pg_dump")).verdict, "twin", "pg_dump, unvetted: its .pgpass twin");
  assert.equal(decideOpen("/h/.pgpass", { readers: [{ app: "pg_dump", prints: "nothing" }] }, at("/usr/bin/pg_dump")).verdict, "raw", "with the human's word");
  assert.equal(decideOpen("/h/.pgpass", { readers: [{ app: "psql", prints: "nothing" }] }, at("/usr/bin/psql")).verdict, "deny", "psql prints: no word lifts it");
  assert.equal(decideOpen("/h/.ssh/id_ed25519", {}, at("/usr/bin/ssh")).verdict, "raw");
  assert.equal(decideOpen("/h/.ssh/id_ed25519", {}, at("/usr/bin/ssh-add")).verdict, "raw");
  // the word's pin to an agent-writable binary still needs the human (D8 TOFU)
  const ws = { exe: "/w/bin/deploy", sha256: H, exeSystem: false, loaderEnv: [] as string[] };
  assert.equal(decideOpen(ENV, { readers: [{ app: "deploy", prints: "nothing" }] }, ws, { ask: "known" }).verdict, "ask");
  // an (interpreter, script) pair with the word reads raw
  const script = { path: "/opt/tools/load.py", sha256: H, system: true, isolated: true, traced: false };
  const py = { exe: "/usr/bin/python3.12", sha256: H, ...SYS, script };
  assert.equal(decideOpen(ENV, { readers: [{ app: "python3", script: script.path, prints: "nothing" }] }, py).verdict, "raw");
  assert.equal(decideOpen(ENV, { readers: [{ app: "python3", script: script.path }] }, py).verdict, "twin", "the pair without the word");
});

test("the refusals come first: the word lifts no printer and no program that runs code", () => {
  for (const [app, exe] of [["cat", "/usr/bin/cat"], ["git", "/usr/bin/git"], ["curl", "/usr/bin/curl"], ["bash", "/usr/bin/bash"], ["cmake", "/usr/bin/cmake"]] as const) {
    const e = { app, prints: "nothing" as const };
    assert.equal(entryVouches(e), false, app);
    for (const ask of ["never", "always"] as const) assert.equal(decideOpen(ENV, { readers: [e] }, at(exe), { ask }).verdict, "deny", `${app} ${ask}`);
  }
  const w = policyWarnings({ version: 1, paths: [{ path: ENV, level: "no-model", readers: [{ app: "cat", prints: "nothing" }, { app: "bash", prints: "nothing" }] }] });
  assert.ok(w.some((l) => l.startsWith("paths[0].readers[0]: cat prints or copies") && l.endsWith("prints: nothing cannot change that.")), w.join("\n"));
  assert.ok(w.some((l) => l.startsWith("paths[0].readers[1]: bash runs any code") && l.endsWith("prints: nothing cannot change that.")), w.join("\n"));
});

test("the default readers of the consumer table: only the vetted ones read raw; the others read the twin (the wire release's where it serves) or are asked with the warning", () => {
  for (const [path, exe] of [["/h/.aws/credentials", "/usr/bin/aws"], ["/h/.kube/config", "/usr/bin/kubectl"], ["/h/.docker/config.json", "/usr/bin/docker"], ["/h/.config/gh/hosts.yml", "/usr/bin/gh"], ["/h/.git-credentials", "/usr/bin/git"]] as const) {
    assert.equal(decideOpen(path, {}, at(exe), { ask: "never" }).verdict, "twin", exe);
  }
  const asked = decideOpen("/h/.aws/credentials", {}, at("/usr/bin/aws"), { ask: "known" });
  assert.equal(asked.verdict, "ask");
  assert.equal(asked.unvetted, true);
  // the human's entry lifts it
  assert.equal(decideOpen("/h/.aws/credentials", { readers: [{ app: "aws", prints: "nothing" }] }, at("/usr/bin/aws")).verdict, "raw");
});

test("the migration: the validator names every entry whose program now reads the placeholder, and the fix; the word is validated", () => {
  const doc = { version: 1, paths: [{ path: ENV, level: "no-model", readers: ["deploy", { app: "tool", path: "/opt/t/tool", sha256: H }, { app: "python3", script: "/opt/a.py" }, "ssh-add", { app: "x", prints: "nothing" }] }] };
  const w = policyWarnings(doc);
  assert.ok(w.some((l) => l === `paths[0].readers[0]: deploy is not a program Mandu knows keeps a file's contents out of what it prints, so it reads the placeholder copy of ${ENV}. If you are sure it does, write { app: deploy, prints: nothing }.`), w.join("\n"));
  assert.ok(w.some((l) => l.startsWith("paths[0].readers[1]: tool is not a program Mandu knows")), w.join("\n"));
  assert.ok(w.some((l) => l.includes("python3 running /opt/a.py is not a program") && l.includes("{ app: python3, script: /opt/a.py, prints: nothing }")), w.join("\n"));
  assert.ok(!w.some((l) => l.includes("readers[3]") || l.includes("readers[4]")), w.join("\n"));
  // the socket's list: the same, in its words
  const s = policyWarnings({ version: 1, ssh_agent: { readers: ["ssh-add", "my-signer"] } });
  assert.ok(s.some((l) => l.startsWith("ssh_agent.readers[1]: my-signer is not a program Mandu knows") && l.includes("does not reach your ssh-agent")), s.join("\n"));
  assert.ok(!s.some((l) => l.includes("readers[0]")), s.join("\n"));
  // the only value
  const bad = validatePolicyDocument({ version: 1, paths: [{ path: ENV, level: "no-model", readers: [{ app: "deploy", prints: "secrets" }] }] } as unknown as PolicyFileConfig);
  assert.ok(bad.some((l) => /readers\[0\]\.prints: the only value is nothing/.test(l)), bad.join("\n"));
  assert.deepEqual(validatePolicyDocument(doc as unknown as PolicyFileConfig), []);
});

test("pins keep the word: a first-use pin keeps the one the human wrote on the name; an Always on the warning question adds it", () => {
  const pin = { app: "deploy", path: "/usr/bin/deploy", sha256: H };
  assert.deepEqual(withPinnedReader([{ app: "deploy", prints: "nothing" }], pin, { system: true }), [{ ...pin, prints: "nothing" }]);
  assert.deepEqual(withPinnedReader(["deploy"], pin, { system: true }), [pin], "Mandu's own pin carries no word");
  assert.deepEqual(withPinnedReader([pin], { ...pin, prints: "nothing" }, { system: true }), [{ ...pin, prints: "nothing" }]);
  assert.equal(withPinnedReader([{ ...pin, prints: "nothing" }], { ...pin, prints: "nothing" }, { system: true }), null, "nothing to write");
});

test("the questions: an unvetted program's is `trust:`; an old `open:` one about it no longer applies (pending: retired); a vetted program's and a printer's are as before", () => {
  assert.equal(trustVerdictSubject("/usr/bin/deploy", H), `trust:/usr/bin/deploy#${H}`);
  assert.equal(unvettedOpenVerdict(`open:/usr/bin/deploy#${H}`), true);
  assert.equal(unvettedOpenVerdict(`open:/usr/bin/ssh-add#${H}`), false);
  assert.equal(unvettedOpenVerdict(`open:/usr/bin/cat#${H}`), false, "a printer's own reason");
  assert.match(mootQuestionReason(`open:/usr/bin/deploy#${H}`) ?? "", /did not say that deploy may print what it reads/);
  assert.equal(mootQuestionReason(`trust:/usr/bin/deploy#${H}`), null);
  assert.equal(mootQuestionReason(`open:/usr/bin/ssh-add#${H}`), null);
  assert.equal(printerOpenVerdict(`trust:/usr/bin/cat#${H}`), true);
});

test("over a real server: the warning question under ask: always, its Always writing `prints: nothing`, an old open answer not counted, the vetted reader untouched", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-allow-list-"));
  const secret = join(dir, ".env"); writeFileSync(secret, "API_KEY=allow_list_canary_0001\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [deploy, ssh-add]\n`);
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), policyPath: policy, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  const open = (exe: string, procKey: string, ask = "always") =>
    guard.decideSecretOpen({ path: secret, exe, sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey, session: "al", ask });
  try {
    // an Always the human gave the OLD question about deploy (before the change)
    const store = (s as unknown as { egressApprovals: { recordPending(sym: string, d: string, r: string): { id: string }; resolve(id: string, a: boolean, sc: "once" | "always"): unknown } }).egressApprovals;
    const old = store.recordPending(`open:/usr/bin/deploy#${H}`, secret, "deploy wants to read it as a program");
    store.resolve(old.id, true, "always");
    // without ask: the twin, no question, no taint
    const twin = await open("/usr/bin/deploy", "d-0", "never");
    assert.equal(twin.verdict, "twin", twin.reason);
    assert.equal((await guard.processSecretTaint("d-0")).level, null);
    // ask: always: held with the warning, the old Always not counted
    const held = await open("/usr/bin/deploy", "d-1");
    assert.equal(held.verdict, "ask", held.reason);
    const row = (await admin.egressApprovals("pending")).find((e) => e.id === held.approvalId)!;
    assert.equal(row.symbol, `trust:/usr/bin/deploy#${H}`);
    assert.match(row.reason, /Mandu does not know whether deploy keeps what it reads out of what it prints: if you allow it, the AI's other programs may be able to read the file through it\./);
    assert.equal((await guard.processSecretTaint("d-1")).level, null);
    const why = await admin.whyPath(secret);
    assert.deepEqual(why.readersReadTwin, [true, false]);
    assert.ok(why.verdicts.some((v) => v.kind === "open" && v.unvetted === true && v.exe === "/usr/bin/deploy"), JSON.stringify(why.verdicts));
    assert.ok(why.verdicts.some((v) => v.kind === "trust" && v.status === "pending"), JSON.stringify(why.verdicts));
    // Always allow: raw, and the law gets the human's word
    await admin.resolveEgressApproval(held.approvalId!, true, "always");
    const raw = await open("/usr/bin/deploy", "d-2");
    assert.equal(raw.verdict, "raw", raw.reason);
    assert.equal((await guard.processSecretTaint("d-2")).level, "no-model");
    const law = readFileSync(policy, "utf8");
    assert.match(law, /app: deploy[\s\S]{0,200}prints: nothing/, law);
    // the law alone now admits it (a fresh session, ask: never)
    assert.equal((await open("/usr/bin/deploy", "d-3", "never")).verdict, "raw");
    // the vetted reader beside it: raw, never asked
    assert.equal((await open("/usr/bin/ssh-add", "p-1", "never")).verdict, "raw");
  } finally {
    guard.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});

test("over a real server: a glob label's vouched entry stays vouched after its first-use pin, which lands in an entry of its own (red before: the second open read the twin)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-allow-list-glob-"));
  mkdirSync(join(dir, "w"));
  const secret = join(dir, "w", ".env"); writeFileSync(secret, "API_KEY=allow_list_glob_0002\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: "**/w/.env"\n    level: no-model\n    readers: [{ app: deploy, prints: nothing }]\n`);
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), policyPath: policy, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
  const open = (procKey: string) => guard.decideSecretOpen({ path: secret, exe: "/usr/bin/deploy", sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey, session: "glob", ask: "never" });
  try {
    assert.equal((await open("d-1")).verdict, "raw");
    assert.match(readFileSync(policy, "utf8"), /path: \/usr\/bin\/deploy[\s\S]{0,120}prints: nothing|prints: nothing[\s\S]{0,120}path: \/usr\/bin\/deploy/, "the pin carries the word");
    assert.equal((await open("d-2")).verdict, "raw", "the pinned entry still vouches");
  } finally {
    guard.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});

test("P0 (D), 2026-10-07: a reader that reads an agent-writable rc file which runs code (git's .git/config, psql's .psqlrc, less's lesskey, mysql's .my.cnf) admits nothing, whatever the word; the other SQL shells are printers like psql", () => {
  // Red before for the SQL shells: `{ app: mysql, prints: nothing }` read
  // ~/.my.cnf raw, and mysql runs `[mysql] pager=` / `\!` and prints a file
  // through `source` (the server's error quotes its lines).
  const shells = ["mysql", "mariadb", "mysqlsh", "duckdb", "usql", "sqlcmd", "sqlplus", "clickhouse", "clickhouse-client", "clickhouse-local", "mongosh", "mongo"];
  for (const n of shells) {
    assert.ok(readerPrints(n), n);
    assert.equal(readerVetted(n), false, n);
    const e = { app: n, prints: "nothing" as const };
    assert.equal(entryVouches(e), false, `${n}: the word lifts no printer`);
    for (const ask of ["never", "known", "always"] as const) {
      assert.equal(decideOpen("/h/.my.cnf", { readers: [e] }, at(`/usr/bin/${n}`), { ask }).verdict, "deny", `${n} ${ask}`);
    }
  }
  assert.ok(readerPrints("/usr/bin/mysql"), "by path");
  assert.ok(readerPrints("mysql8"), "under a trailing version");
  assert.equal(readerPrints("mysqldump"), false, "a dump tool that prints no file stays unvetted, like pg_dump");
  // The programs whose rc file the ledger named: none reads a byte raw, so a
  // planted rc file runs only in a process that holds placeholders.
  for (const [app, file] of [["git", "/w/.git/config"], ["psql", "/h/.psqlrc"], ["less", "/h/.lesskey"], ["mysql", "/h/.my.cnf"]] as const) {
    assert.equal(decideOpen(ENV, { readers: [{ app, prints: "nothing" }] }, at(`/usr/bin/${app}`)).verdict, "deny", `${app} (reads ${file})`);
  }
});
