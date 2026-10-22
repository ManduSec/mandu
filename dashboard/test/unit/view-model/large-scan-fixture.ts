/**
 * large-scan-fixture — a kept `mandu scan` record at about a real machine's
 * scale (dashboard.md §4.25ai *A long scan, in pages*), every value fake.
 *
 * Its shape is scaled from a real record of 834 sessions (counts and byte
 * sizes only, never a field's content): 918 findings (3 of your secrets,
 * 280 key-shaped values, 635 values named like a secret), about 1.5
 * examples each and as many again by way, commands near the 240-character
 * cap, 1.3 projects each, and 5 sends (3 to another host). About 1.3 MB on
 * disk, over 3 MB as one Scan page answer before the paging.
 *
 * `plant` goes into fields the record never has (the launcher keeps no
 * value), so a test can say no 8-character run of it reaches an answer.
 * Mandu-new test helper.
 */
import type { LastScanWire, ScanExampleWire, ScanFindingWire, ScanSendWire } from "../../../src/view-model/last-scan.js";

export interface LargeScanOpts {
  /** Your secrets (default 3). */
  known?: number;
  /** Key-shaped values (default 280). */
  looks?: number;
  /** Values named like a secret (default 635). */
  named?: number;
  /** A fake value planted in fields the record does not have. */
  plant?: string;
}

const HOWS = ["command-output", "read-file", "your-message", "tool-result", "ai-wrote"] as const;
const AGENTS = ["claude-code", "codex"] as const;

function day(i: number): string {
  return new Date(Date.UTC(2026, 8, 1) + (i % 50) * 86_400_000 + (i % 24) * 3_600_000).toISOString();
}

function example(i: number, k: number, how: string): ScanExampleWire {
  const project = `~/work/project-${(i + k) % 140}`;
  const e: ScanExampleWire = { at: day(i + k), agent: AGENTS[(i + k) % 7 === 0 ? 1 : 0]!, how, project, mandu: "without", provider: (i + k) % 7 === 0 ? "openai" : "anthropic" };
  if (how === "command-output" || how === "ai-wrote") {
    e.command = `cd ${project} && grep -rn "API_TOKEN\\|DB_PASSWORD" config/ services/api/src/settings/ --include='*.env*' | head -40 && docker compose -f deploy/compose.yml config | sed -n '1,80p' # run ${i}-${k}`.slice(0, 240);
    e.tool = "Bash";
  } else if (how === "read-file") {
    e.file = `${project}/services/api/config/settings.local.${k}.env`;
    e.tool = "Read";
  } else if (how === "tool-result") {
    e.url = `https://internal.example.test/project-${i % 140}/admin/settings?token=…&page=${k}`;
    e.tool = "WebFetch";
  }
  return e;
}

function finding(i: number, kind: string, preview: string, plant: string | undefined, source?: { path: string; name: string }): ScanFindingWire {
  const how1 = HOWS[i % HOWS.length]!;
  const how2 = HOWS[(i + 2) % HOWS.length]!;
  const n = 1 + (i % 3);
  const examples = Array.from({ length: i % 2 === 0 ? 2 : 1 }, (_, k) => example(i, k, k === 0 ? how1 : how2));
  const byHow: Record<string, ScanExampleWire[]> = { [how1]: Array.from({ length: i % 3 === 0 ? 2 : 1 }, (_, k) => example(i, k + 3, how1)) };
  if (i % 2 === 0) byHow[how2] = [example(i, 6, how2)];
  const f: ScanFindingWire = {
    kind, preview, sessions: n, agents: i % 7 === 0 ? ["claude-code", "codex"] : ["claude-code"],
    first: day(i), last: day(i + n), how: { [how1]: n, ...(i % 2 === 0 ? { [how2]: 1 } : {}) },
    projects: i % 3 === 0 ? [`~/work/project-${i % 140}`, `~/work/project-${(i + 1) % 140}`] : [`~/work/project-${i % 140}`],
    duringMandu: 0, sessionsUnderMandu: 0, sessionsByTime: 0, examples, examplesByHow: byHow,
  };
  if (source) f.source = source;
  // Not fields of the record: dropped when read.
  if (plant !== undefined) Object.assign(f, { raw: plant, value: plant });
  return f;
}

/** The record (as the launcher keeps it, plus the planted fields). */
export function largeScanRecord(opts: LargeScanOpts = {}): LastScanWire {
  const known = opts.known ?? 3;
  const looks = opts.looks ?? 280;
  const named = opts.named ?? 635;
  const plant = opts.plant;
  const findings: ScanFindingWire[] = [];
  let i = 0;
  for (let k = 0; k < known; k++, i++) {
    findings.push(finding(i, "known", `SERVICE_KEY_${k} in ~/work/project-${k}/.env`, plant, { path: `~/work/project-${k}/.env`, name: `SERVICE_KEY_${k}` }));
  }
  const shapes = ["github-token", "openai-key", "aws-access-key-id", "slack-token", "anthropic-key"];
  const masks = ["ghp_…", "sk-…", "AKIA…", "xoxb-…", "sk-ant-…"];
  for (let k = 0; k < looks; k++, i++) findings.push(finding(i, shapes[k % shapes.length]!, `${masks[k % masks.length]}${k.toString(36)}`, plant));
  for (let k = 0; k < named; k++, i++) findings.push(finding(i, k % 9 === 0 ? "url-password" : "credential-assignment", k % 9 === 0 ? `postgres://app:…@db-${k}.internal` : `DB_PASSWORD_${k}=…`, plant));
  const sends: ScanSendWire[] = Array.from({ length: 5 }, (_, k) => ({
    kind: "known", preview: `SERVICE_KEY_${k % 3} in ~/work/project-${k % 3}/.env`, source: { path: `~/work/project-${k % 3}/.env`, name: `SERVICE_KEY_${k % 3}` },
    to: k < 3 ? "other-host" as const : "own-service" as const, host: k < 3 ? `hooks-${k}.vendor.test` : `api-${k}.service.test`,
    sessions: 1 + k, ran: 1 + k, stoppedByMandu: 0, via: ["curl"], by: ["variable" as const], agents: ["claude-code"], last: day(k), duringMandu: 0,
    urls: [`https://${k < 3 ? `hooks-${k}.vendor.test` : `api-${k}.service.test`}/v1/events?key=…`],
  }));
  const rec: LastScanWire = {
    version: 1, ranAt: "2026-10-22T09:00:00.000Z", sessions: { "claude-code": 818, codex: 16 },
    from: "2026-09-01T00:00:00.000Z", to: "2026-10-22T00:00:00.000Z", duringMandu: 0, known: known + 4, findings,
    dropped: 0, capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 },
    risk: { skippedPrompts: 120, skippedWithSecret: 2, envDumps: 3 }, sends, sendsDropped: 0, suggestions: { pending: 2, filed: 0, covered: 1 },
  };
  if (plant !== undefined) Object.assign(rec, { secret: plant });
  return rec;
}
