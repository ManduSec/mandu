/**
 * plan10-drift — the §7.2 drift spike of confidentiality-plan-10-flow-taint.md,
 * measured OFFLINE from recorded session events (no prototype needed).
 *
 * Question: under plan 10's rule (i), how many tool results would the model
 * see MASKED if every catalog consumer were a listed reader? A Bash command
 * whose text references a catalog secret path, or a Read of one, is counted
 * as "would open a secret" (the wrapper-layer approximation the arbiter's
 * text scan already uses: arbiter/policy/secret-catalog.ts). This over-counts
 * (a `git status` that names `.env` in its output does not open it) and
 * under-counts (a script that reads `.env` internally), which is why it is a
 * spike and not the design's oracle.
 *
 * Run from `arbiter/`:  npx tsx ../scripts/spikes/plan10-drift.ts <events.ndjson…>
 */
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { findSecretPathsInText, pathConfidentiality } from "../../arbiter/policy/secret-catalog.js";

interface Ev { kind: string; callId?: string; input?: { symbolized?: string | null; original?: string | null } | null; output?: { symbolized?: string | null } | null; ts?: number }

function analyze(file: string) {
  const uses = new Map<string, { tool: string; text: string }>();
  let results = 0, masked = 0, bashTotal = 0, readTotal = 0, bashMasked = 0, readMasked = 0;
  const files = new Map<string, number>();
  for (const line of readFileSync(file, "utf8").split("\n")) {
    if (!line) continue;
    let e: Ev; try { e = JSON.parse(line); } catch { continue; }
    if (e.kind === "tool_use" && e.callId) {
      const t = e.input?.symbolized ?? "";
      const m = /^([A-Za-z_]+)\((.*)\)$/s.exec(t);
      if (m) uses.set(e.callId, { tool: m[1]!, text: m[2]! });
    } else if (e.kind === "tool_result" && e.callId) {
      const u = uses.get(e.callId);
      if (!u || (u.tool !== "Bash" && u.tool !== "Read")) continue;
      results++;
      if (u.tool === "Bash") bashTotal++; else readTotal++;
      let hits: string[] = [];
      try {
        const args = JSON.parse(u.text) as Record<string, string>;
        if (u.tool === "Read" && args["file_path"]) {
          if (pathConfidentiality(args["file_path"]).rule) hits = [args["file_path"]];
        } else if (u.tool === "Bash" && args["command"]) {
          hits = findSecretPathsInText(args["command"]).map((h) => h.token);
        }
      } catch { /* unparsable input: not a hit */ }
      if (hits.length > 0) {
        masked++;
        if (u.tool === "Bash") bashMasked++; else readMasked++;
        for (const h of hits) files.set(h, (files.get(h) ?? 0) + 1);
      }
    }
  }
  return { file: basename(file), results, masked, bashTotal, bashMasked, readTotal, readMasked, files };
}

const rows = process.argv.slice(2).map(analyze);
console.log("| session | Bash+Read results | would be masked (rule i) | Bash masked/total | Read masked/total | files behind the masks |");
console.log("|---|---|---|---|---|---|");
let T = 0, M = 0;
for (const r of rows) {
  T += r.results; M += r.masked;
  const top = [...r.files.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4).map(([f, n]) => `${f} ×${n}`).join(", ");
  console.log(`| ${r.file} | ${r.results} | ${r.masked} (${r.results ? Math.round(100 * r.masked / r.results) : 0}%) | ${r.bashMasked}/${r.bashTotal} | ${r.readMasked}/${r.readTotal} | ${top} |`);
}
console.log(`| **all** | ${T} | ${M} (${T ? Math.round(100 * M / T) : 0}%) | | | |`);
