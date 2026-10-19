#!/usr/bin/env node
// native-provenance.mjs — record what each native bin was built from
// (packaging.md §5.2), so another checkout of the same repository (a git
// worktree with no bins of its own) can use the bin only when it was built
// from exactly that checkout's sources (launcher/src/services/native-provenance.ts
// is the reader).
//
//   node scripts/native-provenance.mjs record <interceptors dir> <profile dir> <bin>...
//
// scripts/build-native.sh runs it after every host build. For each bin it
// writes `<bin>.provenance.json` beside it:
//
//   { "format": "mandu-native-provenance/1", "bin": "mandu-net-guard",
//     "profile": "release", "features": ["kernel"],
//     "sha256": "<the bin's>", "size": <bytes>,
//     "sources": { "<path under interceptors/>": "<sha256>" | null, ... } }
//
// `sources` is every file cargo says the bin was compiled from (its dep-info,
// `<bin>.d`), plus what shapes a build without appearing there: the workspace
// Cargo.toml and Cargo.lock, each crate's Cargo.toml and build.rs, and the
// cargo config and toolchain files (null: absent, which the reader requires
// too). A record is written only when it can be true: every source lies under
// the interceptors dir and no dep-info source changed after the bin was built
// (an edit made during or after the build would make it claim sources the bin
// was not built from; cargo would rebuild on the same mtime rule). Otherwise
// the old record is removed and the bin is simply not shared; the build
// itself never fails for it.
//
// Plain node, no dependencies. Mandu-new (no reference origin).
import { createHash } from "node:crypto";
import { existsSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const PROVENANCE_FORMAT = "mandu-native-provenance/1";
export const PROVENANCE_SUFFIX = ".provenance.json";
/** Build inputs under the interceptors dir that cargo's dep-info leaves out. */
export const WORKSPACE_INPUTS = ["Cargo.toml", "Cargo.lock", ".cargo/config.toml", ".cargo/config", "rust-toolchain", "rust-toolchain.toml"];
/** The same, per crate directory a source lies in. */
export const CRATE_INPUTS = ["Cargo.toml", "build.rs"];

const sha256File = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");

/** cargo dep-info: `<target>: <dep> <dep> …`, a space in a path escaped as
 *  `\ ` (the launcher's parseDepInfoSources reads the same). */
export function depInfoSources(text) {
  const line = text.split("\n").find((l) => l.includes(": ")) ?? "";
  const idx = line.indexOf(": ");
  if (idx < 0) return [];
  return line.slice(idx + 2).trim().split(/(?<!\\) /).map((t) => t.replace(/\\ /g, " ").trim()).filter(Boolean);
}

/**
 * The record for one bin, or `{ error }` when none can be true. Pure but for
 * reading the files it names.
 */
export function provenanceFor(interceptorsDir, profileDir, bin) {
  const root = resolve(interceptorsDir);
  const binPath = join(profileDir, bin);
  if (!existsSync(binPath)) return { error: `${binPath} is missing` };
  if (!existsSync(`${binPath}.d`)) return { error: `${binPath}.d (cargo's dep-info) is missing` };
  const binStat = statSync(binPath);
  const deps = depInfoSources(readFileSync(`${binPath}.d`, "utf8"));
  if (deps.length === 0) return { error: `${binPath}.d names no source` };
  const rels = new Set();
  for (const d of deps) {
    const abs = resolve(d);
    const rel = relative(root, abs);
    if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return { error: `${abs} lies outside ${root}` };
    if (!existsSync(abs)) return { error: `${abs} (a source of the bin) is gone` };
    if (statSync(abs).mtimeMs > binStat.mtimeMs) return { error: `${abs} changed after the bin was built` };
    rels.add(rel.split(sep).join("/"));
  }
  const crates = new Set([...rels].filter((r) => r.includes("/")).map((r) => r.split("/")[0]));
  // Recorded by content only: cargo judges these by what they resolve to, so
  // a manifest rewritten with no effect on this bin leaves it unrelinked and
  // older than the file, and the bin is still what the content builds.
  const extra = [...WORKSPACE_INPUTS, ...[...crates].flatMap((c) => CRATE_INPUTS.map((f) => `${c}/${f}`))].filter((e) => !rels.has(e));
  const sources = {};
  for (const r of [...rels, ...extra].sort()) {
    const abs = join(root, r);
    sources[r] = existsSync(abs) ? sha256File(abs) : null;
  }
  return {
    record: {
      format: PROVENANCE_FORMAT, bin, profile: basename(profileDir), features: ["kernel"],
      sha256: sha256File(binPath), size: binStat.size, sources,
    },
  };
}

/** Write (or remove) each bin's record. Returns the lines to print. */
export function record(interceptorsDir, profileDir, bins) {
  const out = [];
  for (const bin of bins) {
    const target = join(profileDir, `${bin}${PROVENANCE_SUFFIX}`);
    // Never leave an older record standing beside a rebuilt bin.
    rmSync(target, { force: true });
    const got = provenanceFor(interceptorsDir, profileDir, bin);
    if (got.error) {
      out.push(`  ${bin}: no provenance record (${got.error}); other checkouts will not use this bin`);
      continue;
    }
    const tmp = `${target}.tmp-${process.pid}`;
    writeFileSync(tmp, `${JSON.stringify(got.record, null, 1)}\n`, { mode: 0o644 });
    renameSync(tmp, target);
    out.push(`  ${bin}: provenance recorded (${Object.keys(got.record.sources).length} sources)`);
  }
  return out;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, interceptorsDir, profileDir, ...bins] = process.argv.slice(2);
  if (cmd !== "record" || !interceptorsDir || !profileDir || bins.length === 0) {
    console.error("usage: native-provenance.mjs record <interceptors dir> <profile dir> <bin>...");
    process.exit(2);
  }
  for (const l of record(interceptorsDir, profileDir, bins)) console.log(l);
}
