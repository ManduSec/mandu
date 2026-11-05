#!/usr/bin/env tsx
/**
 * check-issuers — run every check of the issuer catalog over the files in
 * `policy/issuers/` as they are on disk (confidentiality.md §2.3, "Where the
 * table lives, and what checks a file"; CONTRIBUTING.md, "Add a service").
 *
 *   cd arbiter && npm run check:issuers
 *
 * Exits 0 when every file passes and the directory and `issuers/index.ts`
 * name the same files; else prints each problem and exits 1. The checks
 * are issuer-catalog.ts's (the arbiter runs the same ones when it loads the
 * table); this adds what only the directory can show: a file that is not
 * valid JSON, and a file the index does not import (or an index line with
 * no file). test/unit/issuer-catalog.test.ts runs it too.
 *
 * Mandu-new (no reference origin).
 */
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { loadIssuerCatalog, type Issuer } from "../policy/issuer-catalog.js";
import { ISSUER_FILES } from "../policy/issuers/index.js";

/** The issuer directory beside the catalog module. */
export const ISSUER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "policy", "issuers");

/** Check the directory: every `*.json` file parsed and checked (in the
 *  index's order, then any file the index misses), and the index matched
 *  against the directory. */
export function checkIssuerDir(dir: string = ISSUER_DIR, index: readonly { file: string }[] = ISSUER_FILES): { issuers: readonly Issuer[]; problems: string[] } {
  const problems: string[] = [];
  const onDisk = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
  const listed = index.map((f) => f.file);
  for (const f of onDisk) if (!listed.includes(f)) problems.push(`${f}: not imported by issuers/index.ts (add its import and its line, at the end)`);
  for (const f of listed) if (!onDisk.includes(f)) problems.push(`issuers/index.ts: names ${f}, which is not in ${dir}`);
  const order = [...listed.filter((f) => onDisk.includes(f)), ...onDisk.filter((f) => !listed.includes(f))];
  const files: { file: string; data: unknown }[] = [];
  for (const file of order) {
    try {
      files.push({ file, data: JSON.parse(readFileSync(join(dir, file), "utf8")) });
    } catch (e) {
      problems.push(`${file}: is not valid JSON (${(e as Error).message})`);
    }
  }
  const catalog = loadIssuerCatalog(files);
  problems.push(...catalog.problems);
  return { issuers: catalog.issuers, problems };
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { issuers, problems } = checkIssuerDir();
  if (problems.length > 0) {
    for (const p of problems) console.error(`check-issuers: ${p}`);
    console.error(`check-issuers: ${problems.length} problem(s); an issuer whose file fails is left out of the table (its keys ask)`);
    process.exit(1);
  }
  console.log(`check-issuers: ${issuers.length} issuers, every check passes (${issuers.map((i) => i.id).join(", ")})`);
}
