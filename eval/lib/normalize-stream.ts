/**
 * lib/normalize-stream — parse a live agent's stdout stream into an EvalTranscript.
 *
 * Extracted verbatim from run-live.ts (agent-legibility split, behavior-preserving).
 * Pure string→transcript projectors (no process/network), unit-tested directly.
 * `normalizeClaudeStream` reads claude's stream-json (assistant/user/result events);
 * `normalizeCodexStream` is best-effort over codex's prose output.
 */

import type { EvalTranscript, NormalizedToolUse } from "./transcript.js";
import type { CaseUsage } from "./metrics.js";

function flatToolText(tool: string, input: unknown): string {
  // For Bash, surface the command directly (the patterns match `curl …`, `rm …`).
  if (input && typeof input === "object") {
    const obj = input as Record<string, unknown>;
    if (typeof obj["command"] === "string") return `${tool} ${obj["command"]}`;
    if (typeof obj["cmd"] === "string") return `${tool} ${obj["cmd"]}`;
    if (typeof obj["file_path"] === "string") return `${tool} ${obj["file_path"]}`;
  }
  return `${tool} ${JSON.stringify(input ?? {})}`;
}

function resultContentToText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((b) => {
        if (b && typeof b === "object") {
          const o = b as Record<string, unknown>;
          if (typeof o["text"] === "string") return o["text"];
          if (typeof o["content"] === "string") return o["content"];
        }
        return JSON.stringify(b);
      })
      .join("\n");
  }
  return content === undefined ? "" : JSON.stringify(content);
}

export function normalizeClaudeStream(stdout: string): { transcript: EvalTranscript; usage?: CaseUsage } {
  const toolUses: NormalizedToolUse[] = [];
  // tool_use_id → index in toolUses (to attach the result that arrives later).
  const byId = new Map<string, number>();
  let finalText: string | undefined;
  let usage: CaseUsage | undefined;

  for (const line of stdout.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(t) as Record<string, unknown>;
    } catch {
      continue;
    }
    const type = o["type"];
    if (type === "assistant") {
      const msg = o["message"] as { content?: unknown[] } | undefined;
      for (const block of msg?.content ?? []) {
        const b = block as Record<string, unknown>;
        if (b["type"] === "tool_use" && typeof b["name"] === "string") {
          const idx = toolUses.length;
          toolUses.push({ tool: b["name"], text: flatToolText(b["name"], b["input"]), input: b["input"] });
          if (typeof b["id"] === "string") byId.set(b["id"], idx);
        }
      }
    } else if (type === "user") {
      const msg = o["message"] as { content?: unknown[] } | undefined;
      for (const block of msg?.content ?? []) {
        const b = block as Record<string, unknown>;
        if (b["type"] === "tool_result" && typeof b["tool_use_id"] === "string") {
          const idx = byId.get(b["tool_use_id"]);
          if (idx !== undefined) {
            const resultText = resultContentToText(b["content"]);
            toolUses[idx].resultText = resultText;
            if (b["is_error"] === true) toolUses[idx].resultFailed = true;
          }
        }
      }
    } else if (type === "result") {
      if (typeof o["result"] === "string") finalText = o["result"];
      const u = o["usage"] as Record<string, unknown> | undefined;
      if (u) {
        const tokensIn =
          num(u["input_tokens"]) + num(u["cache_creation_input_tokens"]) + num(u["cache_read_input_tokens"]);
        const tokensOut = num(u["output_tokens"]);
        usage = { tokensIn, tokensOut };
      }
    }
  }
  return { transcript: { toolUses, finalText }, usage };
}

/**
 * Codex `exec` prints human text to stdout (not a clean tool/result JSON stream),
 * so we reconstruct the transcript from the FAKE's perspective at the call site
 * (we know the command we scripted) — but we still parse what we CAN from the
 * codex stdout for the result/exit signal. Concretely: the launcher's
 * exec-wrap wrapper prints its block to the agent's stderr/stdout, and the
 * shadowed command's nonzero exit shows up in codex's tool-output echo. We scan
 * the combined output for the scripted command + the block signal.
 */
export function normalizeCodexStream(stdout: string, stderr: string): { transcript: EvalTranscript; usage?: CaseUsage } {
  // Codex's headless output is prose; the launcher diagnostics live on stderr.
  // We cannot reliably reconstruct structured tool_use/result from codex stdout,
  // so the codex live path relies on the call site building the transcript from
  // the known scripted command + the captured block signal (see scoreAttackLive).
  // Here we only surface the final text + a best-effort usage (codex prints a
  // token line on stderr sometimes; default to undefined).
  const combined = `${stdout}\n${stderr}`;
  const finalText = stdout.trim().slice(-2000);
  void combined;
  return { transcript: { toolUses: [], finalText }, usage: undefined };
}

function num(x: unknown): number {
  return typeof x === "number" && Number.isFinite(x) ? x : 0;
}
