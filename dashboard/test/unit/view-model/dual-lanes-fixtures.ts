/**
 * dual-lanes-fixtures — the shared event-builder kit for the dual-lanes test
 * files (split from dual-lanes.test.ts 2026-07-16 so failures localize by
 * feature area). Not a .test.ts file, so the unit glob does not run it.
 */

import type { ManduEvent } from "../../../src/event-model.js";

let seq = 0;
export function ev(partial: Partial<ManduEvent> & { kind: ManduEvent["kind"] }): ManduEvent {
  seq += 1;
  return {
    id: `ev${seq}`,
    sessionId: "s",
    turn: 0,
    ts: new Date(Date.parse("2026-07-06T15:45:10.000Z") + seq * 1000).toISOString(),
    seq,
    callId: null,
    parentId: null,
    view: "AgentView",
    boundary: "model_context",
    emitter: "anthropic-proxy",
    input: null,
    output: null,
    invariant: { violatedInvariant: false },
    ...partial,
  } as ManduEvent;
}

export function repr(symbolized: string, original: string | null = null, symbols: ManduEvent["input"] extends null ? never : any[] = []) {
  return { symbolized, original, differs: original !== null && symbolized !== original, symbols };
}

export const READ_SYM = {
  name: "$MDU:Read[1a9f]", tool: "Read", field: null,
  origin: "/ws/notes.md", value: "RAW NOTES", derivedFrom: undefined, lineRange: undefined,
};
