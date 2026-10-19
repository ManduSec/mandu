/**
 * ci-live-fixtures — a live-drill store as scripts/ci/collect-results.mjs
 * collectLive writes a CI run's drill runs into it (continuous-integration.md
 * §6, "The live-drill records"): `<CI part>.<drill run>/` with the record
 * files, the `ci-run.json` marker and `events-<host session>.ndjson`, the
 * session ids namespaced (`<run>-<key>`), plus a host's own run beside it.
 * Shared by ci-live-source.test.ts and the ci-live-sessions component test.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { tmpDir } from "./tmp-dir.js";

export const GUEST_RUN = "watch-20261003T010203";
export const CI_RUN = `nightly-subscription-41-77.${GUEST_RUN}`;
export const CI_SID = `${CI_RUN}-util-reasoning`;
export const CI_SID2 = `${CI_RUN}-conf-env-catalog`;
/** A session the run names that has no log (its launch died). */
export const CI_SID_NOLOG = `${CI_RUN}-util-write-file`;
export const HOST_RUN = "watch-20261003T090000";
export const HOST_SID = `${HOST_RUN}-util-reasoning`;

/** One event as the guest's own arbiter logged it: the GUEST's ids. */
export function guestEvent(seq: number, kind: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const model = kind === "tllm_call";
  return {
    id: `ev_${seq}`, sessionId: `${GUEST_RUN}-util-reasoning`, batchId: GUEST_RUN, turn: 0, ts: `2026-10-03T01:02:0${seq}.000Z`, seq,
    callId: null, parentId: null, kind, view: model ? "AgentView" : "HumanView", boundary: model ? "model_context" : "shell",
    emitter: model ? "anthropic-proxy" : "launcher",
    input: { symbolized: "▸ user\nWhat is 17 * 23? $MDU:abc123", original: "▸ user\nWhat is 17 * 23? synthetic-canary-391", differs: true, symbols: [] },
    output: null, invariant: { violatedInvariant: false }, tenant: "test", ...extra,
  };
}
export const ndjson = (lines: Array<Record<string, unknown>>): string => lines.map((l) => JSON.stringify(l)).join("\n") + "\n";

function put(dir: string, files: Record<string, string | object>): void {
  mkdirSync(dir, { recursive: true });
  for (const [name, v] of Object.entries(files)) writeFileSync(join(dir, name), typeof v === "string" ? v : JSON.stringify(v));
}

/** The store: the CI run (two sessions with logs, one without, a log of a
 *  session it does not name) and the host's own run (no marker, a log beside
 *  it that must never be served from here). */
export function ciLiveStore(): string {
  const dir = tmpDir("ci-live-store-");
  put(join(dir, CI_RUN), {
    "meta.json": {
      runId: CI_RUN, startedAt: "2026-10-03T01:02:03Z", finishedAt: "2026-10-03T01:20:00Z", status: "done", pid: 0, ws: "/home/ci/x",
      ids: ["util-reasoning", "conf-env-catalog", "util-write-file"], settings: ["secrets"], model: "claude-haiku-4-5", attach: {},
      sessions: { "util-reasoning": CI_SID, "conf-env-catalog": CI_SID2, "util-write-file": CI_SID_NOLOG }, casts: {},
    },
    "chapters.json": [
      { id: "util-reasoning", scenarioId: "util-reasoning", title: "reasoning", setting: "secrets", scopeId: CI_SID, cast: "terminal-util-reasoning.cast", t: 0, verdict: "PASS", turns: [] },
      { id: "conf-env-catalog", scenarioId: "conf-env-catalog", title: "env", setting: "secrets", scopeId: CI_SID2, cast: "terminal-conf-env-catalog.cast", t: 0, verdict: "FAIL", turns: [] },
      { id: "util-write-file", scenarioId: "util-write-file", title: "write", setting: "secrets", scopeId: CI_SID_NOLOG, cast: "terminal-util-write-file.cast", t: 0, verdict: "TIMEOUT", turns: [] },
    ],
    "report.json": [],
    "terminal-util-reasoning.cast": '{"version":2,"width":80,"height":24}\n',
    "terminal-conf-env-catalog.cast": '{"version":2,"width":80,"height":24}\n',
    "terminal-util-write-file.cast": '{"version":2,"width":80,"height":24}\n',
    "ci-run.json":{ kind: "mandu-ci-live-run", ciRun: "nightly-subscription-41-77", guestRun: GUEST_RUN },
    [`events-${CI_SID}.ndjson`]: ndjson([
      guestEvent(1, "launch_posture", { target: "claude", argv0: "claude", live: ["net-proxy"], dropped: [], input: null }),
      guestEvent(2, "tllm_call"),
      guestEvent(3, "assertion", { emitter: "e2e-harness", input: null, assertions: [{ label: "answer", category: "utility", status: "pass", reason: "391" }] }),
    ]),
    [`events-${CI_SID2}.ndjson`]: ndjson([guestEvent(1, "tllm_call", { sessionId: `${GUEST_RUN}-conf-env-catalog`, ts: "2026-10-03T01:10:00.000Z" })]),
    [`events-${CI_RUN}-not-named.ndjson`]: ndjson([guestEvent(1, "tllm_call")]),
  });
  put(join(dir, HOST_RUN), {
    "meta.json": { runId: HOST_RUN, startedAt: "2026-10-03T09:00:00Z", status: "done", pid: 0, ws: "", ids: [], settings: [], attach: {}, sessions: { "util-reasoning": HOST_SID }, casts: {} },
    "chapters.json": [],
    [`events-${HOST_SID}.ndjson`]: ndjson([guestEvent(1, "tllm_call")]),
  });
  return dir;
}
