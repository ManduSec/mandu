/**
 * mock-prompt-filter — an in-test `filterPrompt` that behaves like the
 * arbiter's phase-1 registered-value filter (arbiter/prompt-filter/), for the
 * proxy's unit tests: a registered value becomes its symbol; in a `human`
 * segment a value under 12 characters or 3.0 bits/char is skipped and
 * counted. The real op is pinned by the arbiter's own tests and the stack
 * tests through the production client.
 */
import type { FilterPromptRequest, FilterPromptResult } from "../../src/arbiter-client.js";

function entropy(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

/** `values`: registered value → its symbol. */
export function registeredValueFilter(values: Record<string, string>, opts: { enforcing?: boolean } = {}) {
  const enforcing = opts.enforcing ?? true;
  return (req: FilterPromptRequest): FilterPromptResult => ({
    enforcing, dryRun: false, digest: { policy: "p", packs: "k", values: "v" },
    segments: req.segments.map((s) => {
      const findings: FilterPromptResult["segments"][number]["findings"] = [];
      let skipped = 0;
      let text = s.text;
      for (const [value, symbol] of Object.entries(values)) {
        if (!s.text.includes(value)) continue;
        if (s.origin === "human" && (value.length < 12 || entropy(value) < 3)) { skipped++; continue; }
        const start = s.text.indexOf(value);
        findings.push({ start, end: start + value.length, category: "secret.registered", filterId: "registered-value", action: enforcing ? "mask" : "log", symbol, how: "value" });
        if (enforcing) text = text.split(value).join(symbol);
      }
      const rewrite = enforcing && findings.length > 0;
      return { id: s.id, origin: s.origin, action: rewrite ? "rewrite" as const : "pass" as const, ...(rewrite ? { text } : {}), findings, skipped, cached: false };
    }),
  });
}

/**
 * A phase-2 policy in miniature (plan 15 §7, §13.3): each rule finds
 * `needle` in a segment and answers its action as the arbiter does:
 * `redact` → `[redacted: <category>]`, `block` → the segment `block` with a
 * reason and the safe text (`[blocked: <category>]`), or no text at all with
 * `noText` (a filter that could not run). In harness and side-call text a
 * `block` acts as `redact` (never a refusal).
 */
export function policyFilter(rules: Array<{ needle: string; category: string; action: "redact" | "block" | "log" }>, opts: { noText?: boolean } = {}) {
  return (req: FilterPromptRequest): FilterPromptResult => ({
    enforcing: true, dryRun: false, digest: { policy: "p2", packs: "k2", values: "v" },
    segments: req.segments.map((s) => {
      const findings: FilterPromptResult["segments"][number]["findings"] = [];
      let text = s.text;
      for (const r of rules) {
        const start = s.text.indexOf(r.needle);
        if (start < 0) continue;
        const action = r.action === "block" && s.origin !== "human" ? "redact" as const : r.action;
        findings.push({ start, end: start + r.needle.length, category: r.category, filterId: "acme-dlp", action });
        if (action !== "log") text = text.split(r.needle).join(action === "redact" ? `[redacted: ${r.category}]` : `[blocked: ${r.category}]`);
      }
      const blocked = findings.filter((f) => f.action === "block");
      const changed = findings.some((f) => f.action !== "log");
      if (blocked.length > 0) {
        return {
          id: s.id, origin: s.origin, action: "block" as const, ...(opts.noText ? {} : { text }),
          reason: `Mandu blocked this prompt: it contains ${blocked.map((f) => `${f.category} (${f.filterId})`).join(", ")}.`,
          findings, skipped: 0, cached: false,
        };
      }
      return { id: s.id, origin: s.origin, action: changed ? "rewrite" as const : "pass" as const, ...(changed ? { text } : {}), findings, skipped: 0, cached: false };
    }),
  });
}
