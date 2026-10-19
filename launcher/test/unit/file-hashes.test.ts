/**
 * file-hashes — the seal check's file hashes on worker threads and ahead of
 * need (file-hashes.ts; confidentiality-plan-14-policy-suggestions.md §11.2,
 * confidentiality.md §7.2a "Cost on a relaunch"):
 *
 *   - the hash is the full sha256 of the file, the same on a worker and on
 *     the main thread, with the file's identity; a directory, a FIFO (never
 *     blocking) and a file that changed while it was read are refused;
 *   - a hash computed early is used only for the same unchanged file: a
 *     rewrite (same size), a rename over it (new inode) is hashed again;
 *   - a worker that dies or answers junk hands its jobs to the main thread
 *     (never a failed or skipped check); after close a hash is refused;
 *   - SealSession.verifyFiles hashes its files concurrently, starts them
 *     before the seal lookup answers, and judges every one before it
 *     answers (all or nothing).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { mkdtempSync, renameSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import * as crypto from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { FileHashes, hashFileHere, hashFileWith, hashWorkersFromEnv, sameFile, type FileHash } from "../../src/file-hashes.js";
import { SealSession, type CacheSealClient } from "../../src/cache-seals.js";
import { stateAxes } from "../axes.js";
import { memorySeals } from "../lib/memory-seals.js";

stateAxes("secrets"); // the seal check gates the confidentiality axis's git-object twins

const sha = (b: string | Buffer): string => createHash("sha256").update(b).digest("hex");

function tmp(): { dir: string; done: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-filehash-"));
  return { dir, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("hashFileWith: the full sha256 and the file's identity; a directory, a FIFO (without blocking) and a missing file are refused", () => {
  const t = tmp();
  try {
    const p = join(t.dir, "f.pack");
    const big = Buffer.alloc(9 * 1024 * 1024 + 7, 0x61); // over two 4 MiB reads
    writeFileSync(p, big);
    const h = hashFileHere(p);
    assert.equal(h.sha256, sha(big));
    assert.equal(h.size, big.length);
    assert.ok(sameFile(h, statSync(p, { bigint: true })));
    assert.throws(() => hashFileHere(t.dir), /not a regular file/);
    assert.throws(() => hashFileHere(join(t.dir, "missing")), /ENOENT/);
    const fifo = join(t.dir, "fifo");
    execFileSync("mkfifo", [fifo]);
    assert.throws(() => hashFileHere(fifo), /not a regular file/, "opened O_NONBLOCK: no writer never blocks the launch");
  } finally { t.done(); }
});

test("hashFileWith: a file that changes while it is read is refused (fstat before and after differ)", () => {
  const t = tmp();
  try {
    const p = join(t.dir, "f");
    writeFileSync(p, "bytes");
    let calls = 0;
    const shifting = {
      ...fs,
      fstatSync: ((fd: number, o: { bigint: true }) => {
        const st = fs.fstatSync(fd, o);
        calls++;
        return calls === 1 ? st : Object.assign(Object.create(Object.getPrototypeOf(st)), st, { ctimeNs: st.ctimeNs + 1n });
      }) as typeof fs.fstatSync,
    } as typeof fs;
    assert.throws(() => hashFileWith(shifting, crypto, p), /changed while it was hashed/);
  } finally { t.done(); }
});

test("FileHashes on workers: the same hashes as the main thread, several at once; an early hash is used only for the same unchanged file", async () => {
  const t = tmp();
  const hashes = new FileHashes({ workers: 2 });
  try {
    const files = [0, 1, 2, 3, 4].map((i) => {
      const p = join(t.dir, `f${i}`);
      writeFileSync(p, Buffer.alloc(1024 * 1024 * (i + 1), 0x30 + i));
      return p;
    });
    hashes.warm();
    hashes.prefetch(files);
    const got = await Promise.all(files.map((p) => hashes.current(p)));
    got.forEach((h, i) => assert.equal(h.sha256, hashFileHere(files[i]!).sha256));
    assert.equal(hashes.fellBack, 0, "hashed on the workers (the worker runs hashFileWith's own source)");

    // Counting hashes: a prefetched one is reused while the file is the
    // same, and recomputed after a same-size rewrite or a rename over it.
    let n = 0;
    const counting = new FileHashes({ hash: (p) => { n++; return hashFileHere(p); } });
    const p = files[0]!;
    counting.prefetch([p]);
    assert.equal((await counting.current(p)).sha256, got[0]!.sha256);
    assert.equal((await counting.current(p)).sha256, got[0]!.sha256);
    assert.equal(n, 1, "hashed once while unchanged");
    await sleep(50); // past the timestamp granularity
    const same = Buffer.alloc(1024 * 1024, 0x7a);
    writeFileSync(p, same); // the same size, other bytes
    assert.equal((await counting.current(p)).sha256, sha(same), "a rewrite is hashed again");
    assert.equal(n, 2);
    const other = join(t.dir, "other");
    writeFileSync(other, same);
    const st = statSync(p);
    utimesSync(other, st.atime, st.mtime);
    renameSync(other, p); // a new inode with the same size, bytes and mtime
    await counting.current(p);
    assert.equal(n, 3, "a file renamed over it is hashed again (its inode and ctime differ)");
  } finally {
    hashes.close();
    t.done();
  }
});

test("FileHashes: a worker that dies or answers junk hands its jobs to the main thread; after close a hash is refused", async () => {
  const t = tmp();
  try {
    const p = join(t.dir, "f");
    writeFileSync(p, "payload");
    const want = hashFileHere(p).sha256;
    const dying = new FileHashes({ workers: 1, workerSource: "process.exit(3);" });
    try {
      assert.equal((await dying.current(p)).sha256, want, "the check still completes, on the main thread");
      assert.equal(dying.fellBack, 1);
    } finally { dying.close(); }
    const junk = new FileHashes({
      workers: 1,
      workerSource: `require("node:worker_threads").parentPort.on("message", (m) => require("node:worker_threads").parentPort.postMessage({ id: m.id, ok: true, v: { sha256: "0".repeat(64), size: 1 } }));`,
    });
    try {
      assert.equal((await junk.current(p)).sha256, want, "an answer without the file's identity is not taken");
    } finally { junk.close(); }
    const closed = new FileHashes({ workers: 1 });
    closed.close();
    await assert.rejects(closed.current(p), /closed/);
  } finally { t.done(); }
});

test("hashWorkersFromEnv: up to four, one fewer than the CPUs, at least one; MANDU_HASH_WORKERS overrides (0: the main thread)", () => {
  assert.equal(hashWorkersFromEnv({}, 128), 4);
  assert.equal(hashWorkersFromEnv({}, 2), 1);
  assert.equal(hashWorkersFromEnv({}, 1), 1);
  assert.equal(hashWorkersFromEnv({ MANDU_HASH_WORKERS: "0" }, 64), 0);
  assert.equal(hashWorkersFromEnv({ MANDU_HASH_WORKERS: "2" }, 64), 2);
  assert.equal(hashWorkersFromEnv({ MANDU_HASH_WORKERS: "junk" }, 64), 4);
});

test("SealSession.verifyFiles: the files hash concurrently and start before the seal lookup answers; every file is judged before the answer, all or nothing", async () => {
  const t = tmp();
  try {
    const parts = ["a.pack", "a.idx", "a.rev"].map((n) => {
      const path = join(t.dir, n);
      writeFileSync(path, `content of ${n}`);
      return { key: `k/${n}`, path };
    });
    const seals = memorySeals();
    const writer = new SealSession(seals);
    for (const it of parts) await writer.sealFile("object-twin", it.key, it.path);
    await writer.flush();

    let inFlight = 0;
    let most = 0;
    let started = 0;
    const slow = async (p: string): Promise<FileHash> => {
      started++;
      inFlight++;
      most = Math.max(most, inFlight);
      await sleep(30);
      inFlight--;
      return hashFileHere(p);
    };
    let startedAtLookup = -1;
    const watching: CacheSealClient = {
      lookup: async (kind, keys) => { startedAtLookup = started; return seals.lookup(kind, keys); },
      record: seals.record,
    };
    const s = new SealSession(watching, undefined, new FileHashes({ hash: slow }));
    assert.equal(await s.verifyFiles("object-twin", parts), true);
    assert.equal(most, 3, "the three files hash at once");
    assert.equal(startedAtLookup, 3, "they started before the seal lookup was asked");
    assert.equal(s.entries.length, 3, "each one judged");

    // One file of the entry no longer matches: the entry is refused, the
    // others still judged (and the mismatch reported).
    writeFileSync(parts[1]!.path, "planted");
    const s2 = new SealSession(seals, undefined, new FileHashes({ hash: slow }));
    assert.equal(await s2.verifyFiles("object-twin", parts), false);
    assert.deepEqual(s2.rejected, [{ kind: "object-twin", key: "k/a.idx", reason: "mismatch" }]);
    assert.equal(s2.entries.length, 2);
    // A file that cannot be hashed refuses the entry too.
    rmSync(parts[2]!.path);
    assert.equal(await new SealSession(seals).verifyFiles("object-twin", parts), false);
    // Without a seal client nothing is hashed (nothing cached is trusted).
    started = 0;
    const none = new SealSession(undefined, undefined, new FileHashes({ hash: slow }));
    assert.equal(await none.verifyFiles("object-twin", parts.slice(0, 1)), false);
    none.prefetch([parts[0]!.path]);
    assert.equal(started, 0);
  } finally { t.done(); }
});
