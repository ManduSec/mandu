/**
 * batch-id — mint the per-process e2e batch id (the MANDU_BATCH_ID fallback).
 *
 * Format: `YYYYMMDD-HHMM-<4 hex>` (local time), e.g. `20260716-1439-4f2a`.
 * The batch id is a DIRECTORY NAME as well as a grouping key — claude-e2e keeps
 * fsSync workspaces at `<tmpdir>/mandu-e2e-fs-<uid>/<batch>/<scenario>/` so the
 * dashboard can read dual-view refs after the run — so the format is chosen for
 * the path a human ends up reading: sortable, the run time visible at a glance,
 * and short (the old `agent-<epoch-millis>` fallback was unreadable; the
 * dashboard's old runId was a 36-char UUID).
 *
 * Uniqueness contract: distinct per suite process for the lifetime of /tmp — a
 * later batch must never reuse an earlier batch's kept workspace dir (the
 * dashboard still resolves the old session's git view from it), and host +
 * docker batches share the bind-mounted base. Same-minute starts collide only
 * on a 1-in-65536 suffix match. Same-batch reruns reusing one id stay possible
 * via the MANDU_BATCH_ID env override — that path does not come through here.
 *
 * The dashboard test-runner's runId (which becomes MANDU_BATCH_ID for "Run
 * e2e" batches) mints the SAME format in the developer view's `test-runner.ts`
 * `mintRunId()` — a deliberate small twin, not an import: the packages install
 * and test independently (no repo-root workspace).
 */
import { randomBytes } from "node:crypto";

export function mintBatchId(now: Date = new Date()): string {
  const p = (n: number) => String(n).padStart(2, "0");
  const stamp =
    `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}` +
    `-${p(now.getHours())}${p(now.getMinutes())}`;
  return `${stamp}-${randomBytes(2).toString("hex")}`;
}
