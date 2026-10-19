/**
 * first-session-fixture — a fresh install's first `mandu claude` session, as
 * recorded 2026-10-05 (dashboard.md §4.25, "Agents, not sessions" and the
 * hero's counts): the person asks "What is in .env?", the agent Reads the
 * file, the AI gets STRIPE_KEY masked, and the reply filter shows the
 * original on the person's own terminal. No send, no approval.
 *
 * Beside it, the two system logs the same run leaves in the event store: the
 * arbiter's admin audit log (`arbiter-admin`, a policy-suggestions
 * config_change at start) and the net-guard's sessionless fallback
 * (`net-guard`, a unix-socket connect it refused). Event shapes follow the
 * interceptors' own (anthropic-proxy tool_use / tool_result / tllm_call,
 * reply-filter desymbolize, launcher launch_posture, net-supervisor
 * net_action). The real value never appears in any event. `codex: true`
 * writes the model events as the openai-proxy's (a `mandu codex` session);
 * `exited: true` ends it with the launcher's `session_exit` (`/exit`).
 */

import type { ManduEvent } from "../../../src/event-model.js";

export const STRIPE = "$MDU:nomodel_Read[5c6e].STRIPE_KEY";
export const FIRST_SESSION = "1791164083-1418381";

const dr = (symbolized: string, original: string | null = null, symbols: unknown[] = []) =>
  ({ symbolized, original, differs: original !== null && original !== symbolized, symbols });

function maker(session: string, t0: number, out: ManduEvent[], proxy = "anthropic-proxy") {
  let seq = 1;
  return (kind: string, f: Record<string, unknown> = {}): void => {
    out.push({
      id: `${session}-${String(seq).padStart(3, "0")}`, sessionId: session, turn: 0, ts: new Date(t0 + seq * 1000).toISOString(), seq,
      callId: null, parentId: null, kind, view: "AgentView", boundary: "model_context", emitter: proxy,
      input: null, output: null, invariant: { violatedInvariant: false }, tenant: "live", ...f,
    } as unknown as ManduEvent);
    seq++;
  };
}

/** The agent session: one Read of .env, its secret masked, the reply shown. */
export function firstSessionEvents(o: { session?: string; startMs?: number; exited?: boolean; codex?: boolean; gitLock?: string; unixRefusal?: string; userPrefix?: string } = {}): ManduEvent[] {
  const S = o.session ?? FIRST_SESSION;
  const out: ManduEvent[] = [];
  const ev = maker(S, o.startMs ?? Date.parse("2026-10-05T01:34:50.000Z"), out, o.codex ? "openai-proxy" : "anthropic-proxy");
  const sys = "▸ system\nYou are Claude Code.";
  // `userPrefix`: what the agent puts before the typed text (OpenClaw's time
  // envelope, `[Sun 2026-10-11 05:20 GMT+9] `).
  const user = `▸ user\n${o.userPrefix ?? ""}What is in .env?`;
  const read = 'Read({"file_path":"/home/u/mandu-try/.env"})';
  ev("launch_posture", {
    view: "HumanView", boundary: "shell", emitter: "launcher",
    input: dr("claude launch: 7 rung(s) live [exec-wrap, net-proxy, landlock-net, net-guard]"), output: dr("every default-on rung engaged"),
    protection: { mode: "secrets", integrity: false, reported: true },
  });
  // `gitLock`: the kernel guard refused a read in that repository, whose
  // history holds a locked object (its event as net-supervisor events.rs
  // writes it). Live 2026-10-11: OpenCode's snapshot store at its start, in
  // the launch after a file it had snapshotted was labelled.
  if (o.gitLock) {
    const repo = o.gitLock;
    ev("net_action", {
      view: "HumanView", boundary: "network", emitter: "net-supervisor", output: dr(repo),
      policy: { usage: "deny", reason: `read of ${repo}/objects/pack/pack-5a9b.idx — REFUSED (git-lock: the repository ${repo}: its git history holds an object you locked, and this launch has no sanitized copy of that repository; relaunch in it, or run \`mandu policy suggest --root ${repo}\`; EACCES)` },
    });
  }
  // `unixRefusal`: the guard's allow-list refused a program's connect to
  // that Unix socket, twice (its event as net-supervisor events.rs writes
  // it). Live 2026-10-11: Claude Code ran `tmux` inside the tmux session it
  // was started in, and its server's socket is outside the session.
  if (o.unixRefusal) {
    for (let i = 0; i < 2; i++) {
      ev("net_action", {
        view: "HumanView", boundary: "network", emitter: "net-supervisor", output: dr(`unix:${o.unixRefusal}`),
        policy: { usage: "deny", reason: `connect to unix:${o.unixRefusal} by /usr/bin/tmux — REFUSED (unix-socket allow-list: not on the list, and its listener is not in the agent's process tree; EACCES)` },
      });
    }
  }
  ev("client_info", { view: "HumanView", input: dr("agent client: claude-code 2.1.289 · model claude-opus-5-5"), clientVersion: "2.1.289" });
  // The agent's own model calls through the net supervisor: nothing resolved.
  ev("net_action", { boundary: "network", emitter: "net-supervisor", action: "forwarded", destination: "api.anthropic.com", method: "POST", scheme: "https", resolved: [] });
  ev("tllm_call", { turn: 1, input: dr(`${sys}\n\n${user}`), output: dr(`→ ${read}`) });
  ev("tool_use", { turn: 1, callId: "toolu_01", input: dr(read) });
  ev("tool_result", {
    turn: 2, callId: "toolu_01",
    output: dr(`1\tSTRIPE_KEY='${STRIPE}'\n2\tDEBUG=1`, `1\tSTRIPE_KEY='${STRIPE}'\n2\tDEBUG=1`,
      [{ name: STRIPE, tool: "Read", field: "STRIPE_KEY", origin: "/home/u/mandu-try/.env", value: null, confidentiality: "no-model" }]),
    policy: { trust: "TRUSTED", reason: "integrity axis OFF: results are not classified", confidentiality: "no-model" },
  });
  ev("tllm_call", {
    turn: 2, input: dr(`${sys}\n\n${user}\n\n▸ tool_result\nSTRIPE_KEY='${STRIPE}'`),
    output: dr(`.env sets two variables:\n- STRIPE_KEY: ${STRIPE}\n- DEBUG=1`),
  });
  // The reply filter shows the person the original on their own terminal.
  ev("desymbolize", { view: "HumanView", emitter: "reply-filter", input: dr(`STRIPE_KEY='${STRIPE}'`), output: dr(`STRIPE_KEY='${STRIPE}'`) });
  // `/exit`: the launcher records the agent's exit.
  if (o.exited) ev("session_exit", { view: "HumanView", boundary: "shell", emitter: "launcher", code: 0, durationMs: 9000, input: dr("agent exited 0 after 9s") });
  return out;
}

/** The arbiter's admin audit log at start: policy suggestions filed. */
export function adminLogEvents(o: { startMs?: number } = {}): ManduEvent[] {
  const out: ManduEvent[] = [];
  const ev = maker("arbiter-admin", o.startMs ?? Date.parse("2026-10-05T01:34:45.000Z"), out);
  ev("config_change", {
    view: "HumanView", emitter: "arbiter", input: dr("policy suggestions"), output: dr("1 policy suggestion(s) filed"),
    policySuggestion: { action: "filed", ids: ["pp-000001"] },
  });
  return out;
}

/** The net-guard's sessionless fallback: a unix-socket connect it refused. */
export function netGuardLogEvents(o: { startMs?: number } = {}): ManduEvent[] {
  const out: ManduEvent[] = [];
  const ev = maker("net-guard", o.startMs ?? Date.parse("2026-10-05T01:35:24.000Z"), out);
  for (let i = 0; i < 2; i++) {
    ev("net_action", {
      view: "HumanView", boundary: "network", emitter: "net-supervisor", output: dr("unix:/tmp/tmux-1000/default"),
      policy: { usage: "deny", reason: "connect to unix:/tmp/tmux-1000/default by /usr/bin/tmux — REFUSED (unix-socket allow-list; EACCES)" },
    });
  }
  return out;
}
