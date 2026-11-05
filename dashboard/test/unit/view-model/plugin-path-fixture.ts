/**
 * plugin-path-fixture — one session shaped like the OpenClaw plugin demo
 * (dashboard.md §4.25b *Where it went*): the AI runs a script whose debug
 * output prints a registered secret, and the anthropic-proxy masks it to
 * the file's twin, whose recorded origin is the COMMAND (events.ts
 * `symbolize` / `tool_result` refs, `tool: "exec"`). Optionally an
 * unchecked record: every event a claim, the launch with no wall. The value
 * is a made-up one. Shared by secret-path.test.ts and the events route's
 * test.
 */

import type { ManduEvent } from "../../../src/event-model.js";

export const SESSION = "path-1";
export const HOME = "/home/dev";
export const TWIN = "$MDU:nomodel_Read[0404].ORDERHUB_PASSPHRASE";
export const BASE = "$MDU:nomodel_Read[0404]";
export const FILE = "/home/dev/app/.env";
export const CMD = "DEBUG=1 sh bin/sync-orders.sh";
export const VALUE = "Juniper-Harbor-6038-Wren";
export const SENT_HOST = "api.orderhub.example";
export const STOPPED_HOST = "paste.example";

/** A plugin-shaped session: the AI runs a script whose debug output prints
 *  a registered secret; the proxy masks it to the file's twin. `claimed`:
 *  every event a claim, the launch with no wall (an unchecked record).
 *  `sent`: then the net-proxy fills its real value in for `SENT_HOST` and
 *  holds it back from `STOPPED_HOST` (`net_action` resolved / withheld). */
export function events(o: { claimed?: boolean; sent?: boolean } = {}): ManduEvent[] {
  const out: ManduEvent[] = [];
  let seq = 0;
  const t0 = Date.parse("2026-10-28T09:11:30.000Z");
  const dr = (symbolized: string, original: string | null = null, symbols: unknown[] = []) =>
    ({ symbolized, original, differs: original !== null && original !== symbolized, symbols });
  const ev = (kind: string, f: Record<string, unknown> = {}): void => {
    out.push({
      id: `${SESSION}-${String(seq).padStart(3, "0")}`, sessionId: SESSION, turn: 0, ts: new Date(t0 + seq * 1000).toISOString(), seq,
      callId: null, parentId: null, kind, view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
      input: null, output: null, invariant: { violatedInvariant: false }, ...(o.claimed ? { claimed: true } : {}), ...f,
    } as unknown as ManduEvent);
    seq++;
  };
  const ref = { name: TWIN, tool: "exec", field: null, origin: CMD, value: null, confidentiality: "no-model" };
  const call = `exec(${JSON.stringify({ command: CMD })})`;
  ev("launch_posture", { view: "HumanView", boundary: "shell", emitter: "launcher", protection: { mode: "secrets", integrity: false, reported: true }, ...(o.claimed ? { humanPlaneWalled: false } : {}) });
  ev("tllm_call", { input: dr("▸ user\nRun the sync with debug output."), output: dr(`→ ${call}`) });
  ev("tool_use", { callId: "c1", input: dr(call) });
  ev("symbolize", { turn: 1, callId: "c1", output: dr(TWIN, VALUE, [ref]) });
  ev("tool_result", { turn: 1, callId: "c1", output: dr(`sync: pass=${TWIN}\nsync: 401`, `sync: pass=${VALUE}\nsync: 401`, [ref]), policy: { trust: "TRUSTED", confidentiality: "no-model" } });
  ev("tllm_call", { turn: 1, input: dr(`▸ tool_result\nsync: pass=${TWIN}`), output: dr("The script reads ORDERHUB_PASSWORD; the file has ORDERHUB_PASSPHRASE.") });
  if (o.sent) {
    const net = { turn: 1, view: "HumanView", boundary: "network", emitter: "net-proxy" };
    ev("net_action", { ...net, action: "forwarded", destination: SENT_HOST, resolved: [{ symbol: TWIN }] });
    ev("net_action", { ...net, action: "blocked", destination: STOPPED_HOST, withheld: [{ symbol: TWIN }] });
  }
  return out;
}

