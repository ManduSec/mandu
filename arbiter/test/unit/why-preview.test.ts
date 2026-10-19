/**
 * why-preview (2026-10-10, second review): `whyPath` (`mandu why`) reads a
 * labelled file and runs the extractor on the arbiter's one event loop, and
 * the agent reaches it on the data socket with files it can write. An
 * agent-written 7 MB YAML of `-u a:b` flow items took 3.5 s a call, so
 * repeated calls could keep every interceptor waiting.
 *
 * Now: the file is checked before it is opened (a FIFO or a device is never
 * opened); at most WHY_MAX_BYTES of it is read; an answer is remembered by
 * the hash of the text read; and texts not remembered spend a byte budget
 * per window. Whatever is not extracted gets no twin (the hedged words of
 * `mandu why`).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { WHY_MAX_BYTES, WhyPreview, whyFileStat, whyFileText } from "../../ipc/why-preview.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // what `mandu why` says of a twin is the confidentiality axis's

const LABEL = { rule: "label:test" };

test("whyFileStat: only a regular file within the limit, checked without opening it; a link is followed to a regular file only", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-why-preview-"));
  try {
    const env = join(dir, ".env");
    writeFileSync(env, "STRIPE_KEY=sk_live_WHYpreview1\n");
    const link = join(dir, "link.env");
    symlinkSync(env, link);
    const dev = join(dir, "zero.env");
    symlinkSync("/dev/zero", dev);
    assert.equal(whyFileStat(env)?.link, false);
    assert.equal(whyFileStat(link)?.link, true, "a link to a regular file is followed");
    assert.equal(whyFileStat(dev), null, "a link to a device is refused before any open");
    assert.equal(whyFileStat(dir), null, "a directory");
    assert.equal(whyFileStat(join(dir, "missing")), null);
    assert.equal(whyFileStat(env, 8), null, "over the limit");
    assert.equal(whyFileText(link), "STRIPE_KEY=sk_live_WHYpreview1\n");
    assert.equal(whyFileText(dev), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("WhyPreview: a file over WHY_MAX_BYTES is not read (the hedged answer); a file within it is", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-why-preview-"));
  try {
    const big = join(dir, "big.yaml");
    // The adversarial shape of the review, just over the limit.
    writeFileSync(big, `password: p\nargs: [${"-u, a:b, ".repeat(Math.ceil(WHY_MAX_BYTES / 9))}x]\n`);
    const small = join(dir, "small.yaml");
    writeFileSync(small, `password: p\nargs: [${"-u, a:b, ".repeat(1000)}x]\n`);
    const w = new WhyPreview();
    assert.deepEqual(w.facts(big, LABEL), {}, "no twin");
    assert.equal(w.reads, 0, "never read");
    // CPU time, not the wall clock (a loaded CI host stretches the wall clock).
    const c0 = process.cpuUsage();
    assert.equal(w.facts(small, LABEL).twin?.form, "structured");
    const c = process.cpuUsage(c0);
    assert.ok((c.user + c.system) / 1000 < 1000, `took ${Math.round((c.user + c.system) / 1000)} ms of CPU`);
    assert.equal(w.reads, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("WhyPreview: an unchanged file is answered from memory; a change (even to the same size, within one timestamp tick) is extracted again; the label's rule is part of the key", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-why-preview-"));
  try {
    const env = join(dir, ".env");
    writeFileSync(env, "STRIPE_KEY=sk_live_WHYpreview1\nPORT=3000\n");
    const w = new WhyPreview();
    const first = w.facts(env, LABEL);
    assert.deepEqual(first.twin, { form: "structured", shape: "dotenv", fields: 1 });
    for (let i = 0; i < 5; i++) assert.deepEqual(w.facts(env, LABEL), first);
    assert.equal(w.reads, 1, "asked six times, extracted once");
    // Same size, other content, written within the same kernel timestamp
    // tick (a stat-keyed memory gave the earlier answer here).
    writeFileSync(env, "STRIPE_KEY=sk_live_WHYpreview2\nPORT=Ab9z\n");
    assert.deepEqual(w.facts(env, LABEL).twin, { form: "structured", shape: "dotenv", fields: 2 });
    assert.equal(w.reads, 2);
    w.facts(env, { rule: "label:test", extract: "KEY=(\\w+)" });
    assert.equal(w.reads, 3, "another extract: another answer");
    // An ssh config's withheld commands come from the same read.
    mkdirSync(join(dir, ".ssh"));
    const sshPath = join(dir, ".ssh", "config");
    writeFileSync(sshPath, "Host x\n  ProxyCommand bash -c 'exec nc %h %p'\n");
    assert.deepEqual(w.facts(sshPath, LABEL, { withheld: true }).withheld, [{ line: 2, keyword: "ProxyCommand" }]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("WhyPreview: texts not remembered spend a byte budget per window; past it the answer is hedged until the window turns", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-why-preview-"));
  try {
    let now = 1_000_000;
    const w = new WhyPreview({ budgetBytes: 120, windowMs: 10_000, now: () => now });
    const files = [0, 1, 2].map((i) => {
      const p = join(dir, `${i}.env`);
      writeFileSync(p, `STRIPE_KEY=sk_live_${"x".repeat(20)}${i}\nPORT=3000\n`); // 51 bytes
      return p;
    });
    assert.ok(w.facts(files[0]!, LABEL).twin);
    assert.ok(w.facts(files[1]!, LABEL).twin);
    assert.deepEqual(w.facts(files[2]!, LABEL), {}, "the third would pass 120 bytes in the window");
    assert.ok(w.facts(files[0]!, LABEL).twin, "a remembered file costs nothing");
    now += 10_000;
    assert.ok(w.facts(files[2]!, LABEL).twin, "a new window");
    assert.equal(w.reads, 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
