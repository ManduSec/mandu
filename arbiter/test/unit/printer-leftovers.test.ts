/**
 * printer-leftovers — the three leftovers of !437 ("printers admit nothing as
 * secret readers", confidentiality plan 13 D8, 2026-10-03), each red on the
 * code before:
 *
 *   (1) a program that fetches or transfers a URL or a file, a local one
 *       included (`curl file:///…`, `wget -i <file>`, `scp a b`, …), is a
 *       printer: named in `readers:` it admitted the agent's code downstream
 *       of `curl file:///w/.env | python3 x.py` to the raw bytes. Now it
 *       admits nothing; the consumer table's curl keeps `.netrc`'s twin
 *       under the wire release.
 *   (2) a printer copied under another name and pinned by path and hash
 *       was that pin's program. Now a binary whose sha256 is a host
 *       printer's (`hashPrints`, `program-hashes.ts`, once `printer-hashes.ts`) is that printer.
 *   (4) a pending Inbox question filed before !437 about a printer (or
 *       about an interpreter alone, before plan 13 §8 decisions (b), (c))
 *       was listed and could be approved, with no effect. Now it is retired:
 *       removed from the store (the DB row included, at start and before
 *       every listing and answer), listed nowhere, and an answer to it is
 *       refused, saying why; retiring grants nothing and no id is reused
 *       (unit + the human plane over a real server's admin socket).
 *
 * Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  addPrinterHashes, clearPrinterHashesForTest, decideOpen, entryAdmitsNothing, hashPrints, matchReader, mootQuestionReason, printerOpenVerdict, readerPrints,
} from "../../policy/flow-taint.js";
import { refreshProgramHashes, scanPrinterHashes } from "../../policy/program-hashes.js";
import { policyWarnings } from "../../policy/policy-file-validate.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { EgressApprovalStore } from "../../policy/egress-approvals.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SYS = { exeSystem: true, loaderEnv: [] as string[] };
const H = "c".repeat(64);
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

// ── (1) programs that fetch or transfer a URL or a file ─────────────────────

const FETCHERS = ["curl", "curlie", "wget", "wget2", "aria2c", "http", "https", "xh", "xhs", "lftp", "rclone", "scp", "sftp", "gio", "gvfs-cat", "gvfs-copy", "kioclient5", "lynx", "w3m", "links", "links2", "elinks"];

test("(1) every fetcher or transfer tool is a printer: listed it admits nothing, deny or the twin, never asked", () => {
  for (const name of FETCHERS) {
    const opener = { exe: `/usr/bin/${name}`, sha256: H, ...SYS };
    assert.ok(readerPrints(name), name);
    assert.equal(entryAdmitsNothing(name), true, name);
    assert.equal(entryAdmitsNothing({ app: name, path: `/usr/bin/${name}`, sha256: H }), true, `${name} pinned`);
    assert.equal(matchReader([name], opener), null, name);
    for (const ask of ["never", "known", "always"] as const) {
      const d = decideOpen("/w/.env", { readers: [name] }, opener, { ask });
      assert.equal(d.verdict, "deny", `${name} under ${ask}: ${d.why}`);
      assert.match(d.why, /prints or copies/);
      assert.equal(decideOpen("/w/.env", { readers: [name], others: "twin" }, opener, { ask }).verdict, "twin");
    }
  }
});

test("(1) curl on .netrc: the consumer table's row still gets the twin the wire release serves, listed or not; raw no more", () => {
  const curl = { exe: "/usr/bin/curl", sha256: H, ...SYS };
  const wire = { wireTwin: { why: "the session proxy puts the password back" } };
  assert.equal(decideOpen("/h/.netrc", {}, curl, wire).verdict, "twin");
  assert.equal(decideOpen("/h/.netrc", { readers: ["curl"] }, curl, { ask: "known", ...wire }).verdict, "twin", "listed: the wire twin, as before");
  assert.equal(decideOpen("/h/.netrc", { readers: ["curl"] }, curl, { ask: "always", ...wire }).verdict, "twin");
  // Without the wire release (MANDU_WIRE_TWIN=0, or no TLS inspection) the
  // default reader read raw before; now it gets the twin (the utility cost).
  assert.equal(decideOpen("/h/.netrc", {}, curl, { ask: "known" }).verdict, "twin");
  assert.equal(decideOpen("/h/.netrc", { readers: ["curl"] }, curl, { ask: "known" }).verdict, "deny");
  // git, the other .netrc consumer, is a printer too since 2026-10-04 (plan
  // 13 §4.9 option (a)): the same twin, served or not
  const git = { exe: "/usr/bin/git", sha256: H, ...SYS };
  assert.equal(decideOpen("/h/.netrc", {}, git, { ask: "known" }).verdict, "twin");
  assert.equal(decideOpen("/h/.netrc", { readers: ["git"] }, git, { ask: "known", ...wire }).verdict, "twin");
  assert.equal(decideOpen("/h/.netrc", { readers: ["git"] }, git, { ask: "known" }).verdict, "deny");
});

test("(1) policyWarnings names curl and wget as printers; a leaf program earns none", () => {
  const w = policyWarnings({ version: 1, paths: [{ path: "/w/.env", level: "no-model", readers: ["curl", { app: "wget", path: "/usr/bin/wget", sha256: H }, "ssh-add"] }] });
  assert.ok(w.some((l) => l.startsWith("paths[0].readers[0]: curl prints or copies")), w.join("\n"));
  assert.ok(w.some((l) => l.startsWith("paths[0].readers[1]: wget prints or copies")), w.join("\n"));
  assert.ok(!w.some((l) => l.includes("readers[2]")), w.join("\n"));
});

// ── (2) a copy of a printer under another name ──────────────────────────────

test("(2) a pin whose hash is a host printer's admits nothing, whatever its name; another hash is that program", () => {
  const CAT = sha("pretend this is GNU cat");
  const OTHER = sha("a leaf program of the human's");
  clearPrinterHashesForTest();
  try {
    const pin = { app: "mdu-catcopy", path: "/opt/x/mdu-catcopy", sha256: CAT, prints: "nothing" as const };
    const opener = { exe: "/opt/x/mdu-catcopy", sha256: CAT, exeSystem: false, loaderEnv: [] as string[] };
    // before the host's printers are known (the code before the fix): admitted
    assert.equal(entryAdmitsNothing(pin), false);
    assert.equal(decideOpen("/w/.env", { readers: [pin] }, opener).verdict, "raw");
    addPrinterHashes([CAT.toUpperCase()]);
    assert.equal(hashPrints(CAT), true);
    assert.equal(entryAdmitsNothing(pin), true);
    assert.equal(matchReader([pin], opener), null);
    const d = decideOpen("/w/.env", { readers: [pin] }, opener, { ask: "always" });
    assert.equal(d.verdict, "deny", d.why);
    assert.match(d.why, /mdu-catcopy is a copy of a program that prints or copies/);
    assert.equal(decideOpen("/w/.env", { readers: [pin], others: "twin" }, opener).verdict, "twin");
    // a bare renamed entry: the opener's hash decides
    assert.equal(decideOpen("/w/.env", { readers: ["mdu-catcopy"] }, { ...opener, exeSystem: true }).verdict, "deny");
    // an old answer about the copy is a printer's
    assert.equal(printerOpenVerdict(`open:/opt/x/mdu-catcopy#${CAT}`), true);
    assert.ok(mootQuestionReason(`open:/opt/x/mdu-catcopy#${CAT}`));
    // the policy surface says so
    const w = policyWarnings({ version: 1, paths: [{ path: "/w/.env", level: "no-model", readers: [pin] }] });
    assert.ok(w.some((l) => l.startsWith("paths[0].readers[0]: mdu-catcopy is a copy of a program that prints")), w.join("\n"));
    // a binary with another hash is still the human's program
    const tool = { app: "acme-load", path: "/opt/acme/acme-load", sha256: OTHER, prints: "nothing" as const };
    assert.equal(entryAdmitsNothing(tool), false);
    assert.equal(decideOpen("/w/.env", { readers: [tool] }, { exe: tool.path, sha256: OTHER, exeSystem: false, loaderEnv: [] }).verdict, "raw");
  } finally {
    clearPrinterHashesForTest();
    refreshProgramHashes({ minIntervalMs: 0 });
  }
});

test("(2) scanPrinterHashes hashes the files a printer's name (or link) names, once per inode, and nothing else", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-printer-scan-"));
  try {
    const bin = join(dir, "bin"); const lib = join(dir, "lib");
    mkdirSync(bin); mkdirSync(lib);
    writeFileSync(join(bin, "cat"), "CAT-BYTES");
    linkSync(join(bin, "cat"), join(bin, "tac")); // one inode, two names
    writeFileSync(join(bin, "gnuhead"), "GNUHEAD-BYTES");
    writeFileSync(join(bin, "mytool"), "MYTOOL-BYTES");
    writeFileSync(join(lib, "pager-impl"), "LESS-BYTES");
    symlinkSync(join(lib, "pager-impl"), join(bin, "less"));
    mkdirSync(join(bin, "zcat")); // a directory named like a printer
    const got = scanPrinterHashes([bin, join(dir, "missing")]);
    assert.deepEqual([...got].sort(), [sha("CAT-BYTES"), sha("GNUHEAD-BYTES"), sha("LESS-BYTES")].sort());
    assert.ok(!got.has(sha("MYTOOL-BYTES")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** A real server over both sockets, the policy given; the host's printers
 *  are hashed at its start. */
async function rig(policyOf: (dir: string, secret: string) => string, fn: (r: { guard: ArbiterClient; admin: ArbiterClient; s: ArbiterServer; dir: string; secret: string }) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-printer-left-"));
  const secret = join(dir, ".env");
  writeFileSync(secret, "API_KEY=printer_leftover_canary_01\n");
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
  try { await fn({ guard, admin, s, dir, secret }); } finally { guard.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); }
}

/** This host's `cat`, as the server's scan finds it (GNU's, or uutils' one
 *  binary), or null. */
function hostCat(): string | null {
  for (const c of ["/usr/bin/cat", "/bin/cat"]) if (existsSync(c)) return realpathSync(c);
  return null;
}

test("(2) over a real server: the host's cat copied as mdu-catcopy and pinned by path and hash gets no raw byte, no taint; whyPath and the warnings say why", { skip: hostCat() === null ? "no cat on this host" : false }, async () => {
  const copyDir = mkdtempSync(join(tmpdir(), "mandu-catcopy-"));
  try {
    const copy = join(copyDir, "mdu-catcopy");
    copyFileSync(hostCat()!, copy); chmodSync(copy, 0o755);
    const H_CAT = sha(readFileSync(copy));
    await rig((_d, secret) => `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mdu-catcopy, path: ${copy}, sha256: ${H_CAT} }, ssh-add]\n`, async ({ guard, admin, secret }) => {
      const d = await guard.decideSecretOpen({ path: secret, exe: copy, sha256: H_CAT, isAgent: false, exeSystem: false, openerEnv: [], procKey: "cc-1", session: "pl", ask: "known" });
      assert.equal(d.verdict, "deny", d.reason);
      assert.match(d.reason, /copy of a program that prints or copies/);
      assert.equal(d.approvalId, undefined, "never asked about");
      assert.equal((await guard.processSecretTaint("cc-1")).level, null, "no taint row");
      // ssh-add beside it reads raw
      assert.equal((await guard.decideSecretOpen({ path: secret, exe: "/usr/bin/ssh-add", sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: "cc-2", session: "pl" })).verdict, "raw");
      const why = await admin.whyPath(secret);
      assert.deepEqual(why.readersPrint, [true, false]);
      assert.deepEqual(why.readersAdmitNothing, [true, false]);
      const doc = await admin.policyDocument();
      assert.ok(doc.onDisk.warnings.some((l) => /mdu-catcopy is a copy of a program that prints/.test(l)), doc.onDisk.warnings.join("\n"));
    });
  } finally {
    rmSync(copyDir, { recursive: true, force: true });
  }
});

// ── (4) a question that no longer applies ───────────────────────────────────

test("(4) mootQuestionReason: a printer's open, an interpreter named alone, and (plan 13 D8 (12)) an old open question about any unvetted program; a vetted program's question and the warning question are live", () => {
  assert.match(mootQuestionReason(`open:/usr/bin/cat#${H}`) ?? "", /prints or copies/);
  assert.match(mootQuestionReason(`open:/usr/bin/curl#${H}`) ?? "", /prints or copies/);
  assert.match(mootQuestionReason("open:head") ?? "", /prints or copies/);
  assert.match(mootQuestionReason(`open:/usr/bin/python3.12#${H}`) ?? "", /names python3\.12 alone/);
  assert.match(mootQuestionReason(`write:/usr/bin/bash#${H}`) ?? "", /names bash alone/);
  assert.equal(mootQuestionReason(`open:/usr/bin/ssh-add#${H}`), null);
  assert.match(mootQuestionReason(`open:/usr/bin/python3.12#${H}#script:%2Fopt%2Fa.py#${H}`) ?? "", /did not say that python3\.12 may print/);
  assert.match(mootQuestionReason(`open:/opt/tools/loader#${H}`) ?? "", /did not say that loader may print/);
  assert.equal(mootQuestionReason(`trust:/opt/tools/loader#${H}`), null, "the warning question is live");
  assert.equal(mootQuestionReason(`trust:/usr/bin/python3.12#${H}#script:%2Fopt%2Fa.py#${H}`), null);
  assert.equal(mootQuestionReason(`write:/usr/bin/tee#${H}`), null, "a held change to a protected file by tee is another question");
  assert.equal(mootQuestionReason("$MDU:nomodel_Read[0123abcd]"), null, "a symbol's question");
});

test("(4) over the human plane: a pending question filed before !437 about a printer or an interpreter alone is retired (listed nowhere, removed) and its answer is refused; a live one is listed and answered", async () => {
  await rig((_d, secret) => `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [ssh-add]\n`, async ({ admin, s, secret }) => {
    // Rows as an arbiter before the decisions wrote them.
    const store = (s as unknown as { egressApprovals: { recordPending(sym: string, d: string, r: string): { id: string }; list(f?: { status?: string }): Array<{ id: string; status: string }> } }).egressApprovals;
    const cat = store.recordPending(`open:/usr/bin/cat#${H}`, secret, "cat (/usr/bin/cat) wants to read it as a program");
    const py = store.recordPending(`open:/usr/bin/python3.12#${H}`, secret, "python3.12 wants to read it as a program");
    const live = store.recordPending(`open:/usr/bin/ssh-add#${H}`, secret, "ssh-add wants to read it as a program");
    const ids = (rows: Array<{ id: string }>) => rows.map((r) => r.id).sort();
    assert.deepEqual(ids(await admin.egressApprovals("pending")), [live.id], "only the live question is pending");
    assert.deepEqual(ids(await admin.egressApprovals()), [live.id], "nor listed among all rows");
    const snap = await admin.policySnapshot();
    assert.deepEqual(ids(snap.verdicts.filter((v) => v.status === "pending")), [live.id], "the Approvals panel's queue");
    const why = await admin.whyPath(secret);
    assert.equal(why.verdicts.length, 1, JSON.stringify(why.verdicts));
    for (const [row, re] of [[cat, /no longer applies: cat prints or copies/], [py, /no longer applies: this question names python3\.12 alone/]] as const) {
      await assert.rejects(admin.resolveEgressApproval(row.id, true, "always"), re);
      await assert.rejects(admin.resolveEgressApproval(row.id, false), re, "a denial too: it would change nothing");
      assert.equal(store.list().find((r) => r.id === row.id), undefined, "the row is retired (removed), never answered");
    }
    const ok = await admin.resolveEgressApproval(live.id, true, "once");
    assert.equal(ok.status, "approved");
  });
});

test("(4) durable: a moot pending question an older arbiter left in the DB is removed at the next start; retiring it grants nothing; the waiter's re-ask gets the law's answer; its id is never reused", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-moot-retire-"));
  const secret = join(dir, ".env");
  writeFileSync(secret, "API_KEY=moot_retire_canary_02\n");
  const policy = join(dir, "policy.yaml");
  // cat named a reader (before !437 that admitted it)
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [cat, ssh-add]\n`);
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const dbPath = join(dir, "db.sqlite");
  // The older arbiter's rows, as it wrote them to the DB.
  const old = new EgressApprovalStore({ dbPath });
  const cat = old.recordPending(`open:/usr/bin/cat#${H}`, secret, "cat (/usr/bin/cat) wants to read it as a program", "s-old");
  const bash = old.recordPending(`write:/usr/bin/bash#${H}`, join(dir, ".bashrc"), "bash wants to change it", "s-old");
  const live = old.recordPending(`open:/usr/bin/ssh-add#${H}`, secret, "ssh-add wants to read it as a program", "s-old");
  old.close();
  const logs: string[] = [];
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath, eventDir: join(dir, "events"), policyPath: policy, policyPollMs: 0, log: (m) => logs.push(m), confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  try {
    // Removed from the DB at start, before anyone listed anything.
    const onDisk = new EgressApprovalStore({ dbPath });
    assert.deepEqual(onDisk.list().map((r) => r.id), [live.id], "only the live question is left on disk");
    onDisk.close();
    assert.ok(logs.some((l) => l.startsWith(`retired ${cat.id} `)) && logs.some((l) => l.startsWith(`retired ${bash.id} `)), logs.join("\n"));
    // A stale page's Allow (Always or once) is refused with the reason, and grants nothing.
    await assert.rejects(admin.resolveEgressApproval(cat.id, true, "always"), /no longer applies: cat prints or copies/);
    await assert.rejects(admin.resolveEgressApproval(cat.id, true, "once"), /no longer applies/);
    await assert.rejects(admin.resolveEgressApproval(bash.id, true, "always"), /no longer applies: this question names bash alone/);
    assert.deepEqual((await admin.egressApprovals()).map((r) => r.id), [live.id]);
    // The guard still holding cat's open re-asks: the law's answer (a printer
    // gets what a non-reader gets: the refusal here), never raw, never a new question.
    for (const ask of ["always", "known", "never"] as const) {
      const d = await guard.decideSecretOpen({ path: secret, exe: "/usr/bin/cat", sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: `cat-${ask}`, session: "s-old", ask });
      assert.equal(d.verdict, "deny", `${ask}: ${d.verdict} ${d.reason}`);
      assert.equal(d.approvalId, undefined, "no question filed again");
      assert.equal((await guard.processSecretTaint(`cat-${ask}`)).level, null, "no raw read recorded");
    }
    // A new question takes a new id, never a retired one's.
    const fresh = await guard.decideSecretOpen({ path: secret, exe: "/opt/tools/other", sha256: H, isAgent: false, exeSystem: false, openerEnv: [], procKey: "other-1", session: "s-new", ask: "always" });
    assert.equal(fresh.verdict, "ask", fresh.reason);
    assert.ok(fresh.approvalId !== undefined && ![cat.id, bash.id, live.id].includes(fresh.approvalId), String(fresh.approvalId));
  } finally { guard.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("(4) an ANSWERED question about a printer stays listed (marked in whyPath), only a pending one is dropped", async () => {
  await rig((_d, secret) => `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [ssh-add]\n`, async ({ admin, s, secret }) => {
    const store = (s as unknown as { egressApprovals: { recordPending(sym: string, d: string, r: string): { id: string }; resolve(id: string, a: boolean, sc: "once" | "always"): unknown } }).egressApprovals;
    const old = store.recordPending(`open:/usr/bin/cat#${H}`, secret, "cat wants to read it");
    store.resolve(old.id, true, "always");
    assert.deepEqual((await admin.egressApprovals()).map((r) => r.id), [old.id]);
    const why = await admin.whyPath(secret);
    assert.ok(why.verdicts.length === 1 && why.verdicts[0]!.printer === true, JSON.stringify(why.verdicts));
  });
});
