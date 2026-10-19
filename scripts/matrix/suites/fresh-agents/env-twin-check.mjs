#!/usr/bin/env node
// env-twin-check.mjs — the live exec-twin oracle (docs/design/testing/os-test-matrix.md §10
// §14.1 item 7; confidentiality-plan-10-flow-taint.md §11.8). A real model was
// asked to run `cat .env` with its shell tool; this reads what the MODEL was
// given, not what it answered: the `tool_result` events the context proxies
// (anthropic-proxy for Claude Code's Bash, openai-proxy for Codex) emitted
// during the run, whose `output.symbolized` is the text that landed in the
// model's input.
//
// Usage: node env-twin-check.mjs --label <name> --since <ISO time> \
//          --secret-keys K1,K2 --plain-keys K3,K4 --canary <regex> <event dir>...
//
// Prints PASS/FAIL/NOTE lines for the suite's forward(); exit 0 iff no FAIL.
//   1. a tool result carrying the file reached the model (fail-closed: none =
//      the agent never ran the command, and the checks below are vacuous);
//   2. the canary is in NO event text the model was given during the run;
//   3. the twin was released, not masked whole: every key name is visible,
//      each secret key's line holds exactly ONE $MDU: symbol, and the
//      `[mandu:secret] twin:` note names the file.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const argv = process.argv.slice(2);
const opt = {}; const dirs = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i].startsWith("--")) opt[argv[i].slice(2)] = argv[++i];
  else dirs.push(argv[i]);
}
const label = opt.label ?? "live";
const since = Date.parse(opt.since ?? "1970-01-01T00:00:00Z");
const secretKeys = (opt["secret-keys"] ?? "").split(",").filter(Boolean);
const plainKeys = (opt["plain-keys"] ?? "").split(",").filter(Boolean);
const canary = new RegExp(opt.canary ?? "FRESHENVCANARY");
let fails = 0;
const pass = (m) => console.log(`PASS ${label}: ${m}`);
const fail = (m) => { console.log(`FAIL ${label}: ${m}`); fails++; };
const note = (m) => console.log(`NOTE ${label}: ${m}`);

function* ndjsonFiles(d, depth = 0) {
  let ents = [];
  try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    const p = join(d, e.name);
    if (e.isDirectory() && depth < 4) yield* ndjsonFiles(p, depth + 1);
    else if (e.isFile() && e.name.endsWith(".ndjson")) {
      try { if (statSync(p).mtimeMs >= since - 60_000) yield p; } catch { /* vanished */ }
    }
  }
}
const events = [];
for (const d of dirs) for (const f of ndjsonFiles(d)) {
  for (const line of readFileSync(f, "utf8").split("\n")) {
    if (!line.trim()) continue;
    let e; try { e = JSON.parse(line); } catch { continue; }
    if (Date.parse(e.ts ?? "") >= since) events.push(e);
  }
}
const seen = (e) => (typeof e?.output?.symbolized === "string" ? e.output.symbolized : "");

// 2. no canary in anything the model was given during the run
const leaked = events.filter((e) => e.view === "AgentView" && canary.test(seen(e)));
if (leaked.length) fail(`the canary reached the model in ${leaked.length} event(s): ${leaked.map((e) => e.kind).join(",")}`);
else pass(`the canary is in none of the ${events.length} events of the run`);

// 1. the result of the read
// Found by what the agent sent (output.original, the privileged side) as well
// as what the model saw: a result masked whole shows the model no key at all.
const sent = (e) => (typeof e?.output?.original === "string" ? e.output.original : "");
const results = events.filter((e) => e.kind === "tool_result" &&
  (secretKeys.some((k) => seen(e).includes(k) || sent(e).includes(k)) || /\.env\b/.test(e.secretNote ?? "") || (e.secretTaint?.files ?? []).some((f) => f.endsWith("/.env"))));
const uses = events.filter((e) => e.kind === "tool_use").map((e) => JSON.stringify(e.input?.original ?? e.input?.symbolized ?? "").slice(0, 160));
if (results.length === 0) {
  fail("no tool result of the .env read reached the model (the agent never ran the command, so the checks are vacuous)");
  if (uses.length) note(`tool calls of the run: ${uses.join(" | ")}`);
  process.exit(1);
}
pass(`${results.length} tool result(s) of the .env read reached the model`);

// 3. released as the twin: keys visible, one symbol per secret value
const SYM = /\$MDU:[A-Za-z0-9_]+\[[0-9a-f]{4,8}\](?:\.[A-Za-z0-9_.-]+)?/g;
function verdict(text) {
  const t = text.replace(/\\n/g, "\n");
  const why = [];
  for (const k of [...secretKeys, ...plainKeys]) if (!new RegExp(`(^|[^A-Za-z0-9_])${k}=`, "m").test(t)) why.push(`key ${k} not visible`);
  for (const k of secretKeys) {
    const line = t.split("\n").find((l) => new RegExp(`(^|[^A-Za-z0-9_])${k}=`).test(l));
    if (line === undefined) continue;
    const n = (line.match(SYM) ?? []).length;
    if (n !== 1) why.push(`${k}'s value holds ${n} symbols, not 1`);
  }
  if (!/\[mandu:secret\] twin:/.test(t)) why.push("no `[mandu:secret] twin:` note");
  return why;
}
const verdicts = results.map((e) => ({ e, why: verdict(seen(e)) }));
const good = verdicts.find((v) => v.why.length === 0);
if (good) {
  pass(`released as the twin: every key visible, one symbol per secret value (${(seen(good.e).match(SYM) ?? []).join(" ")})`);
} else {
  const v = verdicts[verdicts.length - 1];
  fail(`not released as the twin: ${v.why.join("; ")}`);
  if (v.e.policy?.reason) note(`the proxy's reason: ${String(v.e.policy.reason).slice(0, 300)}`);
  if (uses.length) note(`tool calls of the run: ${uses.join(" | ")}`);
}
console.log("  what the model saw:");
for (const l of seen((good ?? verdicts[verdicts.length - 1]).e).split("\n").slice(0, 14)) console.log(`        | ${l}`);
process.exit(fails === 0 ? 0 : 1);
