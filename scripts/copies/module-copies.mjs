#!/usr/bin/env node
// scripts/copies/module-copies.mjs — THE table of the TypeScript modules that
// ship byte-identical in more than one package, and the copier that keeps
// them so (docs/development.md §3, "Every shared module has one source").
//
// The packages stay standalone (no workspace, no cross-package import), so a
// module two packages need is copied VERBATIM, never imported. Each group
// below names its SOURCE, the one copy a change is made in, and the copies
// written from it. A copy is the source's bytes: no generated header, so the
// copies stay what each package's own tests, typecheck and parity tests read.
//
//   node scripts/copies/module-copies.mjs generate   write every copy from its source
//   node scripts/copies/module-copies.mjs check      exit 1 when a copy differs
//
// scripts/test/module-copies.test.mjs runs `check`. The tests/stack parity
// tests still run each group's behavior through every package
// (text-repack-parity, reserve-layout-parity, safe-file-parity, ...).
//
// First the model proxies' verbatim modules (the shared proxy core, step 1 of
// making Mandu pluggable): a module both model proxies carry, with every other
// package that carries it too, and the unit suites copied with them.

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const AP = "interceptors/anthropic-proxy";
const OP = "interceptors/openai-proxy";
const NP = "interceptors/net-proxy";
const RF = "interceptors/reply-filter";

function g(name, source, copies, extra = {}) {
  return { name, source, copies, ...extra };
}

/** One row per shared file: its source (where a change is made) and the
 *  copies written from it. A module's header names the same source. */
export const GROUPS = [
  // Upstream TLS for every package that dials a model or the arbiter's endpoint.
  g("endpoint-tls", "interceptors/inspect-mcp/src/endpoint-tls.ts",
    [`${AP}/src/endpoint-tls.ts`, `${OP}/src/endpoint-tls.ts`, "launcher/src/endpoint-tls.ts", "dashboard/src/endpoint-tls.ts"]),
  // Kernel-bound service lifetime (runtime-instances.md §8).
  g("lifeline", "arbiter/ipc/lifeline.ts",
    [`${AP}/src/lifeline.ts`, `${OP}/src/lifeline.ts`, `${NP}/src/lifeline.ts`, "fs-sync/src/lifeline.ts"]),
  g("lifeline unit suite", `${AP}/test/unit/lifeline.test.ts`,
    [`${OP}/test/unit/lifeline.test.ts`, `${NP}/test/unit/lifeline.test.ts`, "fs-sync/test/unit/lifeline.test.ts"]),
  // The secret posture's names, sentences and decision over a coverage
  // (openclaw-plugin.md §3.4): the dashboard shows them, the arbiter decides
  // an attachment's posture by them. Not a proxy module (`proxies: false`).
  g("confinement-posture", "launcher/src/confinement-posture.ts",
    ["dashboard/src/confinement-posture.ts", "arbiter/policy/confinement-posture.ts"], { proxies: false }),
  // A private file written whole, never through a link (the dashboard: the
  // proxy pool's port files, openclaw-plugin.md §3.2).
  g("safe-file", "launcher/src/safe-file.ts",
    [`${AP}/src/safe-file.ts`, `${OP}/src/safe-file.ts`, `${NP}/src/safe-file.ts`, "dashboard/src/safe-file.ts"]),
  // What `mandu serve`'s proxy pool and its readers agree on (openclaw-plugin.md
  // §3.2, §8): the session, the port-file contract, the declared attachments.
  // The pool runs in the dashboard; the launcher declares, installs, reports.
  g("attachment-contract", "launcher/src/attachment-contract.ts",
    ["dashboard/src/attachment-contract.ts"], { proxies: false }),
  // The models an OpenClaw config names and its openrouter bypass: the
  // route check (attachment-contract.ts, its relative import) judges the
  // model fence by them (openclaw-plugin.md §3.6).
  g("openclaw-model-refs", "launcher/src/openclaw-model-refs.ts",
    ["dashboard/src/openclaw-model-refs.ts"], { proxies: false }),
  // The OpenClaw config as OpenClaw reads it (JSON5, `$include`s resolved):
  // `mandu openclaw install` and its doctor check read it in the launcher, the
  // service's route check in the dashboard (openclaw-plugin.md §3.6). The
  // three keep their relative imports, so the copies sit together.
  g("json5", "launcher/src/services/json5.ts", ["dashboard/src/openclaw/json5.ts"], { proxies: false }),
  g("openclaw-include", "launcher/src/services/openclaw-include.ts", ["dashboard/src/openclaw/openclaw-include.ts"], { proxies: false }),
  g("openclaw-config-read", "launcher/src/services/openclaw-config-read.ts", ["dashboard/src/openclaw/openclaw-config-read.ts"], { proxies: false }),
  // Where an OpenClaw Gateway's environment sets the Azure endpoint
  // variables (model-wires.md §8.1): install and the doctor in the launcher,
  // the service's route check in the dashboard.
  g("openclaw-gateway-env", "launcher/src/services/openclaw-gateway-env.ts", ["dashboard/src/openclaw/openclaw-gateway-env.ts"], { proxies: false }),
  // Reply-row reservation (reply-row-reservation.md): the layout rule the
  // arbiter, both proxies and the reply filter count rows by.
  g("reserve-layout", `${RF}/src/reserve-layout.ts`,
    [`${AP}/src/reserve-layout.ts`, `${OP}/src/reserve-layout.ts`, "arbiter/ipc/reserve-layout.ts"]),
  g("reserve-layout unit suite", `${RF}/test/unit/reserve-layout.test.ts`, [`${OP}/test/unit/reserve-layout.test.ts`]),
  g("reserve-block", `${AP}/src/reserve-block.ts`, [`${OP}/src/reserve-block.ts`]),
  g("reserve-block unit suite", `${AP}/test/unit/reserve-block.test.ts`, [`${OP}/test/unit/reserve-block.test.ts`]),
  g("reserve-context", `${AP}/src/reserve-context.ts`, [`${OP}/src/reserve-context.ts`]),
  g("reserve-context unit suite", `${AP}/test/unit/reserve-context.test.ts`, [`${OP}/test/unit/reserve-context.test.ts`]),
  // The OpenAI wire's text-delta repacker and response id.
  g("text-repack", `${AP}/src/text-repack.ts`, [`${OP}/src/text-repack.ts`]),
  g("text-repack unit suite", `${AP}/test/unit/text-repack.test.ts`, [`${OP}/test/unit/text-repack.test.ts`]),
  g("response-id", `${AP}/src/response-id.ts`, [`${OP}/src/response-id.ts`]),
  g("response-id unit suite", `${AP}/test/unit/response-id.test.ts`, [`${OP}/test/unit/response-id.test.ts`]),
  // The prompt filter's protocol-neutral half (each proxy keeps its own
  // segmenter in prompt-filter.ts).
  g("prompt-filter-core", `${AP}/src/prompt-filter-core.ts`, [`${OP}/src/prompt-filter-core.ts`]),
  g("prompt-filter-core unit suite", `${AP}/test/unit/prompt-filter-core.test.ts`, [`${OP}/test/unit/prompt-filter-core.test.ts`]),
  // The secret posture a proxy reports, and its upstream TLS options.
  g("secret-posture", `${AP}/src/secret-posture.ts`, [`${OP}/src/secret-posture.ts`]),
  g("upstream-tls", `${AP}/src/upstream-tls.ts`, [`${OP}/src/upstream-tls.ts`]),
  // The `copy:` line of the secret note: a write stays in a protected file's
  // placeholder copy (plan 10 §4.1, "The model is told at the call").
  g("twin-write-note", `${AP}/src/twin-write-note.ts`, [`${OP}/src/twin-write-note.ts`]),
  g("twin-write-note unit suite", `${AP}/test/unit/twin-write-note.test.ts`, [`${OP}/test/unit/twin-write-note.test.ts`]),
  // The `[mandu:locked]` note: git could not read a locked object, or remove
  // a protected file's read-only copy (confidentiality.md §7.1, "git's report
  // on a history rewrite"). Each proxy's own suite drives its wire.
  g("locked-object-note", `${AP}/src/locked-object-note.ts`, [`${OP}/src/locked-object-note.ts`]),
  g("locked-object-note unit suite", `${AP}/test/unit/locked-object-note-text.test.ts`, [`${OP}/test/unit/locked-object-note-text.test.ts`]),
  // Once copies whose headers alone had drifted (step 0.2 of the shared
  // proxy core); their unit suites differ, each driving its own wire.
  g("after-the-fact", `${AP}/src/after-the-fact.ts`, [`${OP}/src/after-the-fact.ts`]),
  g("auth-substitution", `${AP}/src/auth-substitution.ts`, [`${OP}/src/auth-substitution.ts`]),
  g("cloud-model", `${AP}/src/cloud-model.ts`, [`${OP}/src/cloud-model.ts`]),
  g("unmapped-exec", `${AP}/src/unmapped-exec.ts`, [`${OP}/src/unmapped-exec.ts`]),
  g("unmapped-upload-core", `${AP}/src/unmapped-upload-core.ts`, [`${OP}/src/unmapped-upload-core.ts`]),
];

/** Every (copy, source) pair. */
export function expectedCopies() {
  return GROUPS.flatMap((grp) => grp.copies.map((path) => ({ path, source: grp.source, group: grp.name })));
}

/** What is wrong with the table itself: a file named twice, a source that is
 *  also a copy, a group with no copy, a source missing under `root`. */
export function tableProblems(root = ROOT) {
  const out = [];
  const seen = new Map();
  for (const grp of GROUPS) {
    if (grp.copies.length === 0) out.push(`${grp.name}: no copies`);
    for (const p of [grp.source, ...grp.copies]) {
      if (seen.has(p)) out.push(`${p}: named by ${seen.get(p)} and ${grp.name}`);
      seen.set(p, grp.name);
    }
    if (!existsSync(join(root, grp.source))) out.push(`${grp.name}: source ${grp.source} missing`);
  }
  return out;
}

/** The copies under `root` that are missing or differ from their source. */
export function staleCopies(root = ROOT) {
  const stale = [];
  for (const c of expectedCopies()) {
    const src = readFileSync(join(root, c.source));
    const dst = join(root, c.path);
    if (!existsSync(dst) || !readFileSync(dst).equals(src)) stale.push(c.path);
  }
  return stale;
}

/** Write every copy from its source; returns the paths written. */
export function generate(root = ROOT) {
  const written = [];
  for (const c of expectedCopies()) {
    const src = readFileSync(join(root, c.source));
    const dst = join(root, c.path);
    if (existsSync(dst) && readFileSync(dst).equals(src)) continue;
    mkdirSync(dirname(dst), { recursive: true });
    writeFileSync(dst, src);
    written.push(c.path);
  }
  return written;
}

function main(argv) {
  const cmd = argv[0];
  const problems = tableProblems();
  if (problems.length > 0) {
    for (const p of problems) process.stderr.write(`module-copies: ${p}\n`);
    return 2;
  }
  if (cmd === "generate") {
    for (const p of generate()) process.stdout.write(`module-copies: wrote ${p}\n`);
    return 0;
  }
  if (cmd === "check") {
    const stale = staleCopies();
    if (stale.length === 0) return 0;
    const source = new Map(expectedCopies().map((c) => [c.path, c.source]));
    for (const p of stale) {
      process.stderr.write(`module-copies: ${p} differs from its source ${source.get(p)}\n`);
    }
    process.stderr.write("module-copies: change the source, then run `node scripts/copies/module-copies.mjs generate`\n");
    return 1;
  }
  process.stderr.write("usage: module-copies.mjs generate|check\n");
  return 2;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(main(process.argv.slice(2)));
}
