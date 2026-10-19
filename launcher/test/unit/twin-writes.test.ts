/**
 * twin-writes.test — the end-of-session notice for writes the placeholder
 * copy absorbed (twin-writes.ts; confidentiality-plan-10-flow-taint.md §4.1).
 *
 * A write to a registered secret file lands in its twin and is discarded
 * with it; the launcher snapshots each twin as written and each real file
 * as found, and names, by path only, every registered file whose twin
 * changed, was removed or replaced, saying whether the real file changed
 * too. The twins' snapshots (never anything of the real file) are left
 * beside them, so `mandu reap` can still name the changes of a session
 * whose launcher died. These cases work on real files in a temporary
 * directory (the twin is a plain file the launcher owns), and check that
 * no line carries the twin's content.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, statSync,
  symlinkSync, unlinkSync, utimesSync, writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DERIVED_TWIN_DIR, LABELLED_TWIN_RECORDS, REAL_HASH_MAX, TWIN_SNAPSHOT_FILE, changedTwins, discardedWriteNotice, discardedWrites,
  REAL_TIME_SLACK_NS, forgetLabelledTwinRecords, forgetTwinWatch, labelledDiscardedWrites, markRealFile, mergeDiscardedWrites, parseLabelledTwinRecords,
  parseTwinSnapshots, printablePath, realFileState, realIdentityState, realTwinLook, reapDiscardedWriteNotice, scopeTwinDir, snapshotTwin,
  staleScopeDiscardedWrites, twinContentHash, watchTwins, type DiscardedWrite, type LookStat, type TwinLook,
} from "../../src/twin-writes.js";
import { publishFile } from "../../src/safe-file.js";
import { stateAxes } from "../axes.js";

// The twins exist only with the confidentiality axis on (`secrets`).
stateAxes("secrets");

const PLACEHOLDER = "STRIPE_SECRET_KEY='$MDU:nomodel_Read[72ae].STRIPE_SECRET_KEY'\nDB_HOST=localhost\n";
const REAL = "STRIPE_SECRET_KEY=sk_live_CANARYtwinwritesUNIT0123456789\nDB_HOST=localhost\n";
const FRESH = "ghp_FAKEfreshTOKENwrittenINsession0123456789";

function twinDir(): { dir: string; cleanup: () => void } {
  // realpath: the stale-scope lookup opens the base as a real directory.
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-twin-writes-")));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** A twin written as the launch writes it (publishFile), and its snapshot. */
function materialize(dir: string, name: string, target: string, content = PLACEHOLDER) {
  const twinPath = join(dir, name);
  publishFile(twinPath, content, { mode: 0o600 });
  return { twinPath, snap: snapshotTwin({ twinPath, targetPath: target, content }) };
}

/** The real look, counting the files it hashes. */
function countingLook(): { look: TwinLook; hashed: string[] } {
  const hashed: string[] = [];
  return { hashed, look: { stat: realTwinLook.stat, hash: (p) => { hashed.push(p); return realTwinLook.hash(p); } } };
}

const W = (path: string, real: DiscardedWrite["real"]): DiscardedWrite => ({ path, real });

test("snapshotTwin: the hash and size of the bytes as written, with the twin's inode", () => {
  const { dir, cleanup } = twinDir();
  try {
    const { twinPath, snap } = materialize(dir, "000-.env", "/w/.env");
    assert.equal(snap.targetPath, "/w/.env");
    assert.equal(snap.twinPath, twinPath);
    assert.equal(snap.sha256, createHash("sha256").update(readFileSync(twinPath)).digest("hex"));
    assert.equal(snap.sha256, twinContentHash(PLACEHOLDER), "publishFile writes the text as UTF-8");
    assert.equal(snap.size, Buffer.byteLength(PLACEHOLDER));
    assert.equal(snap.ino, String(statSync(twinPath).ino), "the identity is kept");
  } finally {
    cleanup();
  }
});

test("an untouched twin is not named; neither is one rewritten in place with the same bytes", () => {
  const { dir, cleanup } = twinDir();
  try {
    const { twinPath, snap } = materialize(dir, "000-.env", "/w/.env");
    assert.deepEqual(changedTwins([snap]), []);
    // `printf "$(cat .env)\n" > .env`: truncated and rewritten, same inode, same bytes
    writeFileSync(twinPath, PLACEHOLDER);
    assert.deepEqual(changedTwins([snap]), [], "no change was lost");
  } finally {
    cleanup();
  }
});

test("an append (>>), a truncating write (>) and a chmod that makes it unreadable each count as a change", () => {
  const { dir, cleanup } = twinDir();
  try {
    const a = materialize(dir, "000-.env", "/w/.env");
    appendFileSync(a.twinPath, "FEATURE_X=1\n");
    assert.deepEqual(changedTwins([a.snap]), ["/w/.env"]);

    const b = materialize(dir, "001-.npmrc", "/h/.npmrc");
    writeFileSync(b.twinPath, `//registry.npmjs.org/:_authToken=${FRESH}\n`);
    assert.deepEqual(changedTwins([b.snap]), ["/h/.npmrc"]);

    const c = materialize(dir, "002-credentials", "/h/.aws/credentials");
    chmodSync(c.twinPath, 0o000);
    // root reads a mode-0 file anyway (a CI container): then it is unchanged
    let readable = true;
    try { readFileSync(c.twinPath); } catch { readable = false; }
    assert.deepEqual(changedTwins([c.snap]), readable ? [] : ["/h/.aws/credentials"], "a twin it cannot read counts as changed");
  } finally {
    cleanup();
  }
});

test("a twin removed, replaced by another file with the same bytes, or by a symlink counts as changed", () => {
  const { dir, cleanup } = twinDir();
  try {
    const gone = materialize(dir, "000-.env", "/w/.env");
    unlinkSync(gone.twinPath);
    assert.deepEqual(changedTwins([gone.snap]), ["/w/.env"], "deleted");

    const swapped = materialize(dir, "001-.env", "/w/conf/.env");
    const other = join(dir, "other");
    writeFileSync(other, PLACEHOLDER);
    renameSync(other, swapped.twinPath);
    assert.deepEqual(changedTwins([swapped.snap]), ["/w/conf/.env"], "replaced: another inode, though the bytes are the same");

    const linked = materialize(dir, "002-.env", "/w/app/.env");
    const copy = join(dir, "copy");
    writeFileSync(copy, PLACEHOLDER);
    unlinkSync(linked.twinPath);
    symlinkSync(copy, linked.twinPath);
    assert.deepEqual(changedTwins([linked.snap]), ["/w/app/.env"], "a symlink in its place is never followed as the twin");
  } finally {
    cleanup();
  }
});

test("several twins: only the changed ones, each target once, sorted", () => {
  const { dir, cleanup } = twinDir();
  try {
    const z = materialize(dir, "000-z", "/w/z/.env");
    const a = materialize(dir, "001-a", "/w/a/.env");
    const m = materialize(dir, "002-m", "/w/m/.env");
    appendFileSync(z.twinPath, "X=1\n");
    appendFileSync(a.twinPath, "Y=1\n");
    assert.deepEqual(changedTwins([z.snap, a.snap, m.snap, a.snap]), ["/w/a/.env", "/w/z/.env"]);
  } finally {
    cleanup();
  }
});

test("the size is compared first: a grown twin is never read, an unchanged one is hashed once", () => {
  const { dir, cleanup } = twinDir();
  try {
    const grown = materialize(dir, "000-.env", "/w/.env");
    appendFileSync(grown.twinPath, "x".repeat(1 << 16));
    const same = materialize(dir, "001-.env", "/w/b/.env");
    const sameSize = materialize(dir, "002-.env", "/w/c/.env");
    writeFileSync(sameSize.twinPath, PLACEHOLDER.replace("localhost", "localhosT"));
    const { look, hashed } = countingLook();
    assert.deepEqual(changedTwins([grown.snap, same.snap, sameSize.snap], look), ["/w/.env", "/w/c/.env"]);
    assert.deepEqual(hashed.sort(), [same.twinPath, sameSize.twinPath].sort(), "only the twins whose size still matches are read");
  } finally {
    cleanup();
  }
});

test("a twin that could not be read back at launch is judged by the size and hash of its text alone", () => {
  const failing: TwinLook = { stat: () => { throw new Error("EACCES"); }, hash: () => { throw new Error("EACCES"); } };
  const snap = snapshotTwin({ twinPath: "/nowhere/000-.env", targetPath: "/w/.env", content: PLACEHOLDER }, failing);
  assert.deepEqual(snap, { targetPath: "/w/.env", twinPath: "/nowhere/000-.env", sha256: twinContentHash(PLACEHOLDER), size: Buffer.byteLength(PLACEHOLDER) });
  // No identity to compare: the same bytes are unchanged, other bytes changed.
  const at = (sha256: string, size = snap.size): TwinLook => ({ stat: () => ({ regular: true, size, dev: "9", ino: "9", mtimeNs: "1", ctimeNs: "1" }), hash: () => sha256 });
  assert.deepEqual(changedTwins([snap], at(twinContentHash(PLACEHOLDER))), []);
  assert.deepEqual(changedTwins([snap], at(twinContentHash("X=1\n"))), ["/w/.env"]);
  assert.deepEqual(changedTwins([snap], at(twinContentHash(PLACEHOLDER), snap.size + 1)), ["/w/.env"]);
  // A twin the end of the session cannot judge counts as changed (errs loud).
  assert.deepEqual(changedTwins([snap], failing), ["/w/.env"]);
});

test("the real file: unchanged only when its size and bytes are; changed when written, replaced or gone; unknown when unreadable", () => {
  const { dir, cleanup } = twinDir();
  try {
    const real = join(dir, ".env");
    writeFileSync(real, REAL, { mode: 0o600 });
    const mark = markRealFile(real);
    assert.ok(mark !== null);
    assert.equal(mark.size, Buffer.byteLength(REAL));
    assert.equal(mark.sha256, createHash("sha256").update(REAL).digest("hex"));
    // Untouched: the bytes are read and decide.
    const untouched = countingLook();
    assert.equal(realFileState(real, mark, untouched.look), "unchanged");
    assert.deepEqual(untouched.hashed, [real], "a hashed file is cleared by its bytes, never by its times");
    // Rewritten in place with the same bytes (an allow-listed reader that
    // rewrote it as it was): unchanged, whether or not its times moved.
    writeFileSync(real, REAL);
    const rewritten = countingLook();
    assert.equal(realFileState(real, mark, rewritten.look), "unchanged");
    assert.deepEqual(rewritten.hashed, [real], "the bytes decide");
    // Same size, other bytes (a raw writer the guard handed the real file),
    // with its times put back as they were at the mark, as a write in the
    // same clock tick leaves them: still a change.
    const before = statSync(real);
    writeFileSync(real, REAL.replace("localhost", "localhosT"));
    utimesSync(real, before.atime, before.mtime);
    assert.equal(realFileState(real, mark), "changed");
    const sameTimes: TwinLook = { stat: () => ({ regular: true, size: mark.size, dev: mark.dev, ino: mark.ino, mtimeNs: mark.mtimeNs, ctimeNs: mark.ctimeNs }), hash: () => "other bytes" };
    assert.equal(realFileState(real, mark, sameTimes), "changed", "the same identity never clears other bytes");
    writeFileSync(real, REAL);
    // Grown: judged by its size, never read.
    appendFileSync(real, "OUTSIDE=1\n");
    const { look, hashed } = countingLook();
    assert.equal(realFileState(real, mark, look), "changed");
    assert.deepEqual(hashed, [], "a size that differs is enough");
    // Gone, or a link in its place.
    unlinkSync(real);
    assert.equal(realFileState(real, mark), "changed");
    writeFileSync(join(dir, "elsewhere"), REAL);
    symlinkSync(join(dir, "elsewhere"), real);
    assert.equal(realFileState(real, mark), "changed", "a link at the path is not the real file");
    // Unknown: not readable at launch, or not now.
    assert.equal(markRealFile(join(dir, "absent")), null);
    assert.equal(realFileState(real, null), "unknown");
    const denied: TwinLook = { stat: () => { throw new Error("EACCES"); }, hash: () => { throw new Error("EACCES"); } };
    assert.equal(realFileState(real, mark, denied), "unknown");
  } finally {
    cleanup();
  }
});

test("a real file over REAL_HASH_MAX (a big labelled document) is never read: judged by its identity alone", () => {
  let hashes = 0;
  let stat: LookStat = { regular: true, size: REAL_HASH_MAX + 1, dev: "1", ino: "2", mtimeNs: "100", ctimeNs: "100" };
  const look: TwinLook = { stat: () => stat, hash: () => { hashes++; return "x"; } };
  const mark = markRealFile("/docs/big.csv", look);
  assert.deepEqual(mark, { size: REAL_HASH_MAX + 1, dev: "1", ino: "2", mtimeNs: "100", ctimeNs: "100" });
  assert.equal(realFileState("/docs/big.csv", mark, look), "unchanged");
  stat = { ...stat, mtimeNs: "200", ctimeNs: "200" };
  assert.equal(realFileState("/docs/big.csv", mark, look), "changed", "its times moved and there is no hash to clear it");
  assert.equal(hashes, 0, "never read");
  // At the cap it is still hashed.
  stat = { ...stat, size: REAL_HASH_MAX };
  assert.equal(markRealFile("/docs/big.csv", look)?.sha256, "x");
});

test("watchTwins: the twins' snapshots go beside them (0600), nothing of the real file does; discardedWrites says what became of each real file", () => {
  const { dir, cleanup } = twinDir();
  try {
    const twins = join(dir, "secret-twins");
    mkdirSync(twins, { mode: 0o700 });
    const envReal = join(dir, ".env");
    const confReal = join(dir, "conf.env");
    writeFileSync(envReal, REAL, { mode: 0o600 });
    writeFileSync(confReal, REAL.replace("UNIT", "CONF"), { mode: 0o600 });
    const files = [
      { twinPath: join(twins, "000-.env"), targetPath: envReal, content: PLACEHOLDER },
      { twinPath: join(twins, "001-conf.env"), targetPath: confReal, content: PLACEHOLDER },
    ];
    for (const f of files) publishFile(f.twinPath, f.content, { mode: 0o600 });
    const watch = watchTwins(files, twins);

    assert.equal(watch.file, join(twins, TWIN_SNAPSHOT_FILE));
    assert.equal(statSync(watch.file).mode & 0o777, 0o600);
    const onDisk = readFileSync(watch.file, "utf8");
    assert.deepEqual(parseTwinSnapshots(JSON.parse(onDisk)), watch.twins);
    // Nothing of the real file is written down: not its hash, not its size.
    for (const m of watch.real.values()) {
      assert.ok(m !== null && m.sha256 !== undefined);
      assert.ok(!onDisk.includes(m.sha256), "the real file's hash stays in memory");
    }
    assert.ok(!onDisk.includes("sk_live_"), "nor any of its bytes");
    for (const t of JSON.parse(onDisk).twins as object[]) {
      assert.deepEqual(Object.keys(t).sort(), ["dev", "ino", "sha256", "size", "targetPath", "twinPath"]);
    }

    assert.deepEqual(discardedWrites(watch), [], "nothing written yet");
    appendFileSync(files[0]!.twinPath, "FEATURE_X=1\n");
    writeFileSync(files[1]!.twinPath, `NEW_TOKEN=${FRESH}\n`);
    appendFileSync(envReal, "EDITED_OUTSIDE=1\n"); // the real .env changed meanwhile
    assert.deepEqual(discardedWrites(watch), [W(confReal, "unchanged"), W(envReal, "changed")].sort((a, b) => (a.path < b.path ? -1 : 1)));

    forgetTwinWatch(watch);
    assert.equal(existsSync(watch.file), false, "said at the end of the session: reap does not say it again");
    forgetTwinWatch(watch); // idempotent
  } finally {
    cleanup();
  }
});

test("watchTwins: a snapshot file that cannot be written costs only reap's notice", () => {
  const { dir, cleanup } = twinDir();
  try {
    const files = [{ twinPath: join(dir, "000-.env"), targetPath: join(dir, "absent-real"), content: PLACEHOLDER }];
    publishFile(files[0]!.twinPath, PLACEHOLDER, { mode: 0o600 });
    const watch = watchTwins(files, join(dir, "no-such-dir"));
    assert.equal(watch.file, null);
    assert.equal(watch.real.get(files[0]!.targetPath), null, "an unreadable real file is unknown, not unchanged");
    appendFileSync(files[0]!.twinPath, "X=1\n");
    assert.deepEqual(discardedWrites(watch), [W(files[0]!.targetPath, "unknown")]);
    forgetTwinWatch(watch);
  } finally {
    cleanup();
  }
});

test("the notice: one plain line per file, worded by what was checked, never the twin's content", () => {
  const p = "/home/u/proj/.env";
  const head = `mandu: during this session the agent changed ${p}; Mandu kept the change in its placeholder copy and `;
  const kept = "did not apply it (the copy stays in the session's scope dir until `mandu reap` removes it)";
  assert.deepEqual(discardedWriteNotice([W(p, "unchanged")]), [
    `${head}discarded it, and the real file is unchanged. Apply the change yourself if you want it.`,
  ]);
  assert.deepEqual(discardedWriteNotice([W(p, "changed")]), [
    `${head}discarded it. The real file also changed during the session, so check it before you apply the change yourself.`,
  ]);
  assert.deepEqual(discardedWriteNotice([W(p, "unknown")]), [
    `${head}discarded it. Mandu could not check whether the real file changed, so check it before you apply the change yourself.`,
  ]);
  assert.deepEqual(discardedWriteNotice([W(p, "unchanged")], { kept: true }), [
    `${head}${kept}, and the real file is unchanged. Apply the change yourself if you want it.`,
  ]);
  assert.deepEqual(discardedWriteNotice([W(p, "changed")], { kept: true }), [
    `${head}${kept}. The real file also changed during the session, so check it before you apply the change yourself.`,
  ]);
  assert.deepEqual(discardedWriteNotice([W(p, "unknown")], { kept: true }), [
    `${head}${kept}. Mandu could not check whether the real file changed, so check it before you apply the change yourself.`,
  ]);
  for (const real of ["unchanged", "changed", "unknown"] as const) {
    for (const k of [false, true]) {
      const [l] = discardedWriteNotice([W(p, real)], { kept: k });
      assert.ok(!l!.includes("\n"), "one line");
      assert.equal(/the real file is unchanged/.test(l!), real === "unchanged", "the claim only when checked");
    }
  }
  assert.equal(discardedWriteNotice([W("/a/.env", "unchanged"), W("/b/.env", "changed")]).length, 2, "one line per file");
  assert.deepEqual(discardedWriteNotice([]), [], "nothing changed: nothing printed");
});

test("the notice names the file, never what was written into the copy", () => {
  const { dir, cleanup } = twinDir();
  try {
    const t = materialize(dir, "000-.env", "/home/u/proj/.env");
    writeFileSync(t.twinPath, `NEW_TOKEN=${FRESH}\n`);
    const lines = discardedWriteNotice(changedTwins([t.snap]).map((path) => W(path, "unchanged")));
    assert.equal(lines.length, 1);
    for (const l of lines) {
      assert.ok(!l.includes(FRESH), "a value written into the copy is never printed");
      assert.ok(!l.includes("$MDU:"), "nor the placeholder text");
    }
  } finally {
    cleanup();
  }
});

test("a file name cannot forge a terminal line, send an escape sequence, or reorder the line (bidi and format controls)", () => {
  const [line] = discardedWriteNotice([W("/w/.env\nmandu: all good\u001b[2J\u009b", "unchanged")]);
  assert.ok(!/[\u0000-\u001f\u007f-\u009f]/.test(line!), JSON.stringify(line));
  assert.match(line!, /changed \/w\/\.env\?mandu: all good\?\[2J\?; Mandu kept/);
  // RLO/LRO/PDF, the isolates, LRM/RLM, zero-width space and joiner, a BOM,
  // the line and paragraph separators: each one `?`.
  const tricky = "/w/\u202Evne.\u202C/\u2066x\u2069/\u200E\u200F\u200B\u200D\uFEFF\u2028\u2029/.env";
  assert.equal(printablePath(tricky), "/w/?vne.?/?x?/???????/.env");
  const [bidi] = discardedWriteNotice([W(tricky, "changed")]);
  assert.ok(!/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u2028\u2029]/.test(bidi!), JSON.stringify(bidi));
  const [reaped] = reapDiscardedWriteNotice("1-2\u202E", [tricky]);
  assert.ok(!/[\u202A-\u202E\u2066-\u2069]/.test(reaped!), JSON.stringify(reaped));
  // Ordinary non-ASCII names are kept as they are.
  assert.equal(printablePath("/home/유저/프로젝트/.env"), "/home/유저/프로젝트/.env");
});

test("parseTwinSnapshots: only the shape the launch writes", () => {
  const ok = { targetPath: "/w/.env", twinPath: "/r/s/secret-twins/000-.env", sha256: "a".repeat(64), size: 3, dev: "1", ino: "2" };
  assert.deepEqual(parseTwinSnapshots({ version: 1, twins: [ok] }), [ok]);
  const noId = { targetPath: "/w/.env", twinPath: "/x", sha256: "b".repeat(64), size: 0 };
  assert.deepEqual(parseTwinSnapshots({ version: 1, twins: [noId] }), [noId]);
  for (const bad of [
    null, 3, "x", {}, { version: 2, twins: [] }, { version: 1, twins: {} }, { version: 1, twins: [null] },
    { version: 1, twins: [{ ...ok, sha256: "zz" }] }, { version: 1, twins: [{ ...ok, size: -1 }] },
    { version: 1, twins: [{ ...ok, size: 1.5 }] }, { version: 1, twins: [{ ...ok, targetPath: 7 }] },
    { version: 1, twins: [{ ...ok, ino: 9 }] },
  ]) assert.equal(parseTwinSnapshots(bad), null, JSON.stringify(bad));
});

/** A runtime base with one scope dir whose launch left its twins and the
 *  snapshot file, as a launcher killed mid-session does. */
function staleScope(): { base: string; scope: string; twins: string; files: Array<{ twinPath: string; targetPath: string; content: string }>; cleanup: () => void } {
  const { dir, cleanup } = twinDir();
  const base = join(dir, "mandu");
  const scope = "1790000000-4242";
  const twins = join(base, scope, "secret-twins");
  mkdirSync(twins, { recursive: true, mode: 0o700 });
  const files = [
    { twinPath: join(twins, "000-.env"), targetPath: "/w/.env", content: PLACEHOLDER },
    { twinPath: join(twins, "001-.env"), targetPath: "/w/conf/.env", content: PLACEHOLDER },
    { twinPath: join(twins, "002-credentials"), targetPath: "/h/.aws/credentials", content: PLACEHOLDER },
  ];
  for (const f of files) publishFile(f.twinPath, f.content, { mode: 0o600 });
  watchTwins(files, twins);
  return { base, scope, twins, files, cleanup };
}

test("staleScopeDiscardedWrites (mandu reap): the files whose copy the dead session changed, from what its launch left", () => {
  const s = staleScope();
  try {
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), [], "nothing changed");
    appendFileSync(s.files[0]!.twinPath, "FEATURE_X=1\n");
    writeFileSync(s.files[1]!.twinPath, `NEW_TOKEN=${FRESH}\n`);
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), ["/w/.env", "/w/conf/.env"]);
    const lines = reapDiscardedWriteNotice(s.scope, staleScopeDiscardedWrites(s.base, s.scope));
    assert.deepEqual(lines, ["/w/.env", "/w/conf/.env"].map((p) =>
      `  the session ${s.scope} ended before Mandu could say so: its agent changed ${p}; the change went to the file's placeholder copy, ` +
      "which goes with the scope dir, never to the real file. Apply it yourself if you want it."));
    for (const l of lines) assert.ok(!l.includes(FRESH) && !l.includes("$MDU:"), l);
    // A twin is looked up by its own name in the scope's twin directory,
    // whatever directory the file names (a moved runtime base, or an entry
    // someone rewrote): one that names another directory's file is judged by
    // the twin of that name here.
    const snap = JSON.parse(readFileSync(join(s.twins, TWIN_SNAPSHOT_FILE), "utf8"));
    snap.twins[2].twinPath = "/etc/../elsewhere/002-credentials";
    writeFileSync(join(s.twins, TWIN_SNAPSHOT_FILE), JSON.stringify(snap));
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), ["/w/.env", "/w/conf/.env"]);
    // An entry naming the snapshot file itself is no twin.
    snap.twins[2].twinPath = TWIN_SNAPSHOT_FILE;
    writeFileSync(join(s.twins, TWIN_SNAPSHOT_FILE), JSON.stringify(snap));
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), ["/w/.env", "/w/conf/.env"]);
  } finally {
    s.cleanup();
  }
});

test("staleScopeDiscardedWrites: nothing to say without a readable snapshot file, and nothing is read through a link", () => {
  const s = staleScope();
  try {
    appendFileSync(s.files[0]!.twinPath, "FEATURE_X=1\n");
    const snapFile = join(s.twins, TWIN_SNAPSHOT_FILE);
    const kept = readFileSync(snapFile);
    // The launcher said it itself and removed the file.
    unlinkSync(snapFile);
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), []);
    // Not JSON, or not the shape.
    writeFileSync(snapFile, "{");
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), []);
    writeFileSync(snapFile, JSON.stringify({ version: 1, twins: [{}] }));
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), []);
    // A link planted at the snapshot file's name is not read through.
    unlinkSync(snapFile);
    const decoy = join(s.base, "decoy.json");
    writeFileSync(decoy, kept);
    symlinkSync(decoy, snapFile);
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), []);
    unlinkSync(snapFile);
    writeFileSync(snapFile, kept);
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), ["/w/.env"], "the real file again");
    // The twin directory, or the scope dir, as a link: not walked.
    const moved = join(s.base, "moved-twins");
    renameSync(s.twins, moved);
    symlinkSync(moved, s.twins);
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), []);
    unlinkSync(s.twins);
    renameSync(moved, s.twins);
    const scopeDir = join(s.base, s.scope);
    renameSync(scopeDir, join(s.base, "real-scope"));
    symlinkSync(join(s.base, "real-scope"), scopeDir);
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), []);
    // No such scope, or a base that is not one.
    assert.deepEqual(staleScopeDiscardedWrites(s.base, "1-1"), []);
    assert.deepEqual(staleScopeDiscardedWrites("relative/base", s.scope), []);
  } finally {
    s.cleanup();
  }
});

// ── 2026-10-17: a labelled file the launch did not register ─────────────────
// The network guard makes its twin on demand in `derived-twins/` and records
// it (net-supervisor label_index.rs `twin_record_line`); these cases write
// the records as the guard does.

/** A guard-made twin of `target` (a real file) in `<twins>/derived-twins/`,
 *  and its record line appended as the guard appends it. `marked`: when the
 *  guard looked at the real file; by default well after its times (a file
 *  last changed long before the gate made its twin), `"now"` the look the
 *  guard makes right after a write (the same timestamp tick may follow). */
function guardTwin(twins: string, name: string, target: string, content = PLACEHOLDER, marked: "old-file" | "now" = "old-file"): string {
  const dir = join(twins, DERIVED_TWIN_DIR);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const twinPath = join(dir, name);
  writeFileSync(twinPath, content, { mode: 0o600 });
  const t = statSync(twinPath, { bigint: true });
  const r = statSync(target, { bigint: true });
  const line = {
    v: 1, targetPath: target, twinPath, sha256: twinContentHash(content), size: Buffer.byteLength(content), dev: String(t.dev), ino: String(t.ino),
    real: {
      dev: String(r.dev), ino: String(r.ino), mtimeNs: String(r.mtimeNs), ctimeNs: String(r.ctimeNs),
      markedNs: String(marked === "now" ? BigInt(Date.now()) * 1_000_000n : r.ctimeNs + 10n * REAL_TIME_SLACK_NS),
    },
  };
  appendFileSync(join(dir, LABELLED_TWIN_RECORDS), `${JSON.stringify(line)}\n`, { mode: 0o600 });
  return twinPath;
}

test("labelledDiscardedWrites: a labelled file whose guard-made twin a program changed is named, worded by the real file's identity", () => {
  const { dir, cleanup } = twinDir();
  try {
    const twins = scopeTwinDir(join(dir, "scope"));
    mkdirSync(twins, { recursive: true });
    assert.deepEqual(labelledDiscardedWrites(twins), [], "no guard twin, no record");
    const real = (n: string) => { const p = join(dir, n); writeFileSync(p, REAL); return p; };
    const [plan, notes, read, gone] = [real("plan.md"), real("notes.md"), real("read.md"), real("gone.md")];
    const tPlan = guardTwin(twins, "0123456789abcdef-plan.md", plan);
    const tNotes = guardTwin(twins, "1123456789abcdef-notes.md", notes);
    guardTwin(twins, "2123456789abcdef-read.md", read);
    const tGone = guardTwin(twins, "3123456789abcdef-gone.md", gone);
    assert.deepEqual(labelledDiscardedWrites(twins), [], "twins only read: nothing to say");
    appendFileSync(tPlan, "APPENDED\n");
    writeFileSync(tNotes, `NEW_TOKEN=${FRESH}\n`);
    // An editor's save (a new file renamed over it): another inode, a change
    // whatever the clock (an in-place write in the same tick is the slack's
    // case, `realIdentityState` below).
    writeFileSync(`${notes}.new`, "the agent edited the real file meanwhile\n");
    renameSync(`${notes}.new`, notes);
    appendFileSync(tGone, "x\n");
    unlinkSync(gone);
    assert.deepEqual(labelledDiscardedWrites(twins), [W(gone, "changed"), W(notes, "changed"), W(plan, "unchanged")]);
    // Said in the registered files' words, by path only.
    const lines = discardedWriteNotice(labelledDiscardedWrites(twins));
    assert.ok(lines.some((l) => l.includes(`changed ${plan}; Mandu kept the change in its placeholder copy and discarded it, and the real file is unchanged.`)), lines.join("\n"));
    for (const l of lines) assert.ok(!l.includes(FRESH) && !l.includes("$MDU:") && !l.includes("APPENDED"), l);
    // The end of the session removes the records: reap says nothing again.
    forgetLabelledTwinRecords(twins);
    assert.equal(existsSync(join(twins, DERIVED_TWIN_DIR, LABELLED_TWIN_RECORDS)), false);
    assert.deepEqual(labelledDiscardedWrites(twins), []);
  } finally {
    cleanup();
  }
});

test("labelledDiscardedWrites: a twin remade after the real file changed is its own record; the earlier one's write is still named", () => {
  const { dir, cleanup } = twinDir();
  try {
    const twins = scopeTwinDir(join(dir, "scope"));
    const plan = join(dir, "plan.md");
    writeFileSync(plan, REAL);
    // The guard looks right after the write; the next write may fall in
    // the same timestamp tick (CI pipeline 11426: same inode, same times).
    const first = guardTwin(twins, "0123456789abcdef-plan.md", plan, PLACEHOLDER, "now");
    appendFileSync(first, "WRITTEN-INTO-THE-FIRST\n");
    writeFileSync(plan, `${REAL}more\n`);
    // A filesystem with coarse timestamps (the CI guest's) can give the
    // rewrite the same mtime and ctime as the first write within one tick:
    // the change is made visible as a later edit would be.
    const at = statSync(plan);
    utimesSync(plan, at.atime, new Date(at.mtimeMs + 10_000));
    guardTwin(twins, "0123456789abcdef-plan.md.1", plan);
    const named = labelledDiscardedWrites(twins);
    assert.deepEqual(named.map((w) => w.path), [plan], "the first twin's write is named");
    assert.notEqual(named[0]!.real, "unchanged", "the real file changed since: never said to be unchanged");
  } finally {
    cleanup();
  }
});

test("parseLabelledTwinRecords: only the guard's shape, line by line; a twin is looked up by its own name in derived-twins/", () => {
  const ok = {
    v: 1, targetPath: "/w/vault/plan.md", twinPath: "/s/secret-twins/derived-twins/0123456789abcdef-plan.md", sha256: "a".repeat(64), size: 3, dev: "1", ino: "2",
    real: { dev: "3", ino: "4", mtimeNs: "5", ctimeNs: "6" },
  };
  const text = [JSON.stringify(ok), "{torn", JSON.stringify({ ...ok, v: 2 }), JSON.stringify({ ...ok, sha256: "x" }), JSON.stringify({ ...ok, real: { dev: "-1" } }), ""].join("\n");
  const recs = parseLabelledTwinRecords(text);
  assert.equal(recs.length, 2, "the good line, and the one whose real identity is malformed");
  assert.deepEqual(recs[0]!.real, ok.real);
  assert.equal(recs[1]!.real, null, "no identity: what became of the real file is unknown");
  assert.equal(realIdentityState("/nonexistent", null), "unknown");
  // The same identity clears the real file only when its times lie well
  // before the guard's look: a write in that timestamp tick keeps them.
  const id = { dev: "3", ino: "4", mtimeNs: "5000000000", ctimeNs: "6000000000" };
  const same: TwinLook = { stat: () => ({ regular: true, size: 1, dev: "3", ino: "4", mtimeNs: "5000000000", ctimeNs: "6000000000" }), hash: () => "" };
  assert.equal(realIdentityState("/r", { ...id, markedNs: String(6_000_000_000n + REAL_TIME_SLACK_NS + 1n) }, same), "unchanged");
  assert.equal(realIdentityState("/r", { ...id, markedNs: "6000000001" }, same), "unknown", "looked within the tick: a same-tick write cannot be ruled out");
  assert.equal(realIdentityState("/r", id, same), "unknown", "no look time: never cleared");
  assert.equal(realIdentityState("/r", { ...id, ctimeNs: "7000000000", markedNs: "99000000000" }, same), "changed");
  // A record naming a twin elsewhere is judged by the twin of that name here.
  const { dir, cleanup } = twinDir();
  try {
    const twins = scopeTwinDir(join(dir, "scope"));
    const plan = join(dir, "plan.md");
    writeFileSync(plan, REAL);
    const t = guardTwin(twins, "0123456789abcdef-plan.md", plan);
    const recFile = join(twins, DERIVED_TWIN_DIR, LABELLED_TWIN_RECORDS);
    const rec = JSON.parse(readFileSync(recFile, "utf8"));
    const elsewhere = join(dir, "0123456789abcdef-plan.md");
    writeFileSync(elsewhere, "an unrelated file of that name\n");
    writeFileSync(recFile, `${JSON.stringify({ ...rec, twinPath: elsewhere })}\n`);
    assert.deepEqual(labelledDiscardedWrites(twins), [], "the twin here is unchanged");
    appendFileSync(t, "x\n");
    assert.deepEqual(labelledDiscardedWrites(twins), [W(plan, "unchanged")]);
    // The records file as a link: not read through.
    const kept = readFileSync(recFile);
    unlinkSync(recFile);
    const decoy = join(dir, "decoy.ndjson");
    writeFileSync(decoy, kept);
    symlinkSync(decoy, recFile);
    assert.deepEqual(labelledDiscardedWrites(twins), []);
  } finally {
    cleanup();
  }
});

test("staleScopeDiscardedWrites (mandu reap) names a labelled file's changed guard-made twin too, with or without a launch snapshot", () => {
  const s = staleScope();
  try {
    const plan = join(s.base, "plan.md");
    writeFileSync(plan, REAL);
    const t = guardTwin(s.twins, "0123456789abcdef-plan.md", plan);
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), []);
    appendFileSync(t, "x\n");
    appendFileSync(s.files[0]!.twinPath, "FEATURE_X=1\n");
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), ["/w/.env", plan].sort());
    // A launch with no registered file left no snapshot: the guard's records alone.
    unlinkSync(join(s.twins, TWIN_SNAPSHOT_FILE));
    assert.deepEqual(staleScopeDiscardedWrites(s.base, s.scope), [plan]);
  } finally {
    s.cleanup();
  }
});

test("mergeDiscardedWrites: each path once, the more cautious word on the real file, sorted", () => {
  assert.deepEqual(
    mergeDiscardedWrites([W("/b", "unchanged"), W("/a", "unchanged")], [W("/b", "changed"), W("/c", "unknown")]),
    [W("/a", "unchanged"), W("/b", "changed"), W("/c", "unknown")],
  );
});
