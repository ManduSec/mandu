/**
 * batch-id.test — the per-process e2e batch id (`YYYYMMDD-HHMM-<4hex>`).
 *
 * The id doubles as the kept fsSync workspace dir name
 * (`<tmpdir>/mandu-e2e-fs-<uid>/<batch>/<scenario>/`), so the format is a small
 * contract: date-time readable in a path, zero-padded (lexicographic sort =
 * chronological sort), and a random suffix so same-minute batches on one host
 * (host + docker share the bind-mounted base) get distinct dirs.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { mintBatchId } from "../lib/batch-id.js";

const FORM = /^\d{8}-\d{4}-[0-9a-f]{4}$/;

test("mintBatchId: YYYYMMDD-HHMM-<4hex>, local time, zero-padded", () => {
  // 2026-01-05 09:04 local — every component below 10, so padding shows.
  const id = mintBatchId(new Date(2026, 0, 5, 9, 4, 33));
  assert.match(id, FORM);
  assert.ok(id.startsWith("20260105-0904-"), `date-time part is padded local time: ${id}`);
});

test("mintBatchId: the wall-clock default matches the format and is path/docker-name safe", () => {
  const id = mintBatchId();
  assert.match(id, FORM);
  // Dir-name + docker-container-name charset (the dashboard's mintRunId twin
  // feeds `mandu-e2e-<id>` container names): [A-Za-z0-9_.-] only.
  assert.match(id, /^[A-Za-z0-9_.-]+$/);
});

test("mintBatchId: the random suffix distinguishes same-minute batches", () => {
  const at = new Date(2026, 6, 16, 14, 39, 0);
  const draws = new Set(Array.from({ length: 64 }, () => mintBatchId(at)));
  // 64 draws of a 16-bit suffix: expecting ~63.97 distinct; >1 is the claim
  // (same minute must not mean same id), and even 2+ collisions leave >32.
  assert.ok(draws.size > 32, `same-minute ids vary by suffix (got ${draws.size} distinct of 64)`);
  for (const d of draws) assert.ok(d.startsWith("20260716-1439-"), d);
});
