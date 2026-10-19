/**
 * runtime-registry-parity.test — the macOS profile write-denies every runtime
 * registry entry the packages actually use (runtime-instances.md §2;
 * confidentiality.md §7.3, 2026-09-30).
 *
 * launcher/src/runtime-registry.ts names the entries directly under the
 * runtime base that Mandu processes OUTSIDE the agent's Seatbelt profile
 * read, write through or delete from, so the agent may not write them (and
 * no scope id may name them). The names are owned elsewhere, each package
 * standalone:
 *
 *   instances/, current, arbiter.sock,   arbiter/ipc/instance.ts
 *   .current.tmp-<pid>                   (INSTANCES_DIR, CURRENT_LINK,
 *                                        ARBITER_SOCK, CURRENT_TMP_PREFIX)
 *   dashboards/                          dashboard/src/registry.ts DASHBOARDS_DIR
 *   dashboard.log, dashboard-<pid>.port  launcher/src/subcommands.ts (`mandu
 *   and its .tmp                         dashboard`), dashboard/src/port-file.ts
 *   test/                                dashboard supervisor-defs.ts testTenantPaths
 *   logs/                                dashboard supervisor.ts (its logDir under
 *                                        the base) and launcher run.ts (the
 *                                        autostart log)
 *   vm-guests/                           scripts/lib/guest-registry.sh
 *   release-check/                       launcher/src/release-gate.ts GATE_DIR (the
 *                                        release check's pending markers and lock)
 *
 * Two oracles. The first pins each owner's name to the list. The second is
 * the completeness check: it scans every package's sources for a path joined
 * DIRECTLY onto a runtime base (`join(base, …)`, `` `${base}/…` ``) and fails
 * on any first component that is neither on the list, nor the human plane's
 * `human/` (its own component denies it), nor a scope dir. A new entry
 * written from outside the profile therefore fails here until it is either
 * denied or shown not to need it.
 *
 * Run: npm test  (tests/)
 */

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ARBITER_SOCK, CURRENT_LINK, CURRENT_TMP_PREFIX, HUMAN_DIR, INSTANCES_DIR, instancePaths, resolveArbiterSock,
} from "../../arbiter/ipc/instance.js";
import { DASHBOARDS_DIR } from "../../dashboard/src/registry.js";
import { testTenantPaths } from "../../dashboard/src/supervisor/supervisor-defs.js";
import { RUNTIME_REGISTRY, runtimeRegistryPaths } from "../../launcher/src/runtime-registry.js";
import { GATE_DIR } from "../../launcher/src/release-gate.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // no arbiter runs here; the profile is the secrets-mode enactment on macOS

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// A fresh base of its own (review 2026-09-30): the host's real base may hold a
// live promoted stack, whose `current` the legacy-path oracle below must never see.
const SCRATCH = mkdtempSync(join(tmpdir(), "mandu-registry-parity-"));
const BASE = join(SCRATCH, "mandu");
after(() => rmSync(SCRATCH, { recursive: true, force: true }));

const src = (...p: string[]): string => readFileSync(join(REPO, ...p), "utf8");
/** Is `name` (one component) covered by the list? */
const listed = (name: string): boolean =>
  [...RUNTIME_REGISTRY.dirs, ...RUNTIME_REGISTRY.names].includes(name) || RUNTIME_REGISTRY.prefixes.some((x) => name.startsWith(x));

test("every registry the arbiter uses under the base is write-denied: instances/, current, the legacy socket, the promotion's temp link", () => {
  const r = runtimeRegistryPaths(BASE);
  assert.ok(r.dirs.includes(join(BASE, INSTANCES_DIR)), "the instance registry");
  assert.equal(dirname(instancePaths(BASE, "20260930-0000-abc-p1").dir), join(BASE, INSTANCES_DIR));
  assert.ok(r.names.includes(join(BASE, CURRENT_LINK)), "the rendezvous link");
  // Client resolution step 3, the legacy fixed path, over a base where
  // nothing is promoted (it never exists, so no `current` can answer).
  const legacy = resolveArbiterSock({ MANDU_RUNTIME_DIR: BASE } as NodeJS.ProcessEnv);
  assert.equal(legacy, join(BASE, ARBITER_SOCK));
  assert.ok(r.names.includes(legacy), "the legacy socket path");
  assert.ok(r.prefixes.includes(join(BASE, CURRENT_TMP_PREFIX)), "the promotion's temporary link");
  // promoteInstance's own test (arbiter instance.test.ts) proves it uses the
  // name; this pins that the name is built from the exported prefix.
  assert.match(src("arbiter", "ipc", "instance.ts"), /join\(base, `\$\{CURRENT_TMP_PREFIX\}\$\{process\.pid\}`\)/,
    "promoteInstance names its temp link with the exported prefix");
  assert.equal(HUMAN_DIR, "human", "the human plane's dir, which a scope id may not name either");
});

test("and the dashboard's, `mandu dashboard`'s, the supervisor's, the launcher's and the VM harness's", () => {
  const r = runtimeRegistryPaths(BASE);
  assert.ok(r.dirs.includes(join(BASE, DASHBOARDS_DIR)), "the dashboards registry");
  assert.ok(r.dirs.includes(dirname(testTenantPaths({ arbiterSock: join(BASE, "current", "arbiter.sock"), arbiterInstanceBase: BASE }, {}).sock)), "the test tenant's socket dir");
  // `mandu dashboard` (review 2026-09-30): its log at the top of the base,
  // opened for append from outside the profile, and the port rendezvous the
  // dashboard writes through `<file>.tmp` (port-file.ts).
  const sub = src("launcher", "src", "subcommands.ts");
  assert.match(sub, /const logPath = `\$\{base\}\/dashboard\.log`;/, "mandu dashboard's log is <base>/dashboard.log");
  assert.match(sub, /`\$\{base\}\/dashboard-\$\{process\.pid\}\.port`/, "its port file is <base>/dashboard-<pid>.port");
  assert.ok(r.names.includes(join(BASE, "dashboard.log")));
  for (const n of [`dashboard-${process.pid}.port`, `dashboard-${process.pid}.port.tmp`, "dashboard-99999.port.tmp"]) {
    assert.ok(r.prefixes.some((p) => join(BASE, n).startsWith(p)), `${n} is under a denied prefix`);
  }
  assert.match(src("dashboard", "src", "port-file.ts"), /const tmp = `\$\{portFile\}\.tmp`;/, "the dashboard writes <port file>.tmp");
  assert.match(src("dashboard", "src", "server-main.ts"), /if \(portFile\) publishPortFile\(portFile, port\);/, "through port-file.ts");
  const supervisor = src("dashboard", "src", "supervisor", "supervisor.ts");
  assert.match(supervisor, /join\(opts\.arbiterInstanceBase, "logs"\)/, "the supervisor's logs live in <base>/logs");
  assert.match(src("launcher", "src", "run.ts"), /\$\{plan\.arbiterRuntimeBase\}\/logs\/arbiter-autostart\.log/, "the autostart log lives in <base>/logs");
  assert.ok(r.dirs.includes(join(BASE, "logs")));
  const guests = src("scripts", "lib", "guest-registry.sh");
  assert.match(guests, /guest_registry_dir\(\) \{ printf '%s\/vm-guests\\n' "\$\(mandu_runtime_base\)"; \}/, "the VM guests' registry is <base>/vm-guests (the launcher's rule, scripts/lib/runtime-base.sh)");
  assert.ok(r.dirs.includes(join(BASE, "vm-guests")));
  // The release check's gate (runtime-instances.md §4.1): a forged pending
  // marker would take a real session out of a launch's session scan.
  assert.ok(r.dirs.includes(join(BASE, GATE_DIR)), "the release check's gate");
});

// ── the completeness oracle ────────────────────────────────────────────────

/** The package sources that run outside the agent's profile (tests and
 *  generated tables excluded). */
const ROOTS = ["arbiter/ipc", "arbiter/src", "arbiter/policy", "dashboard/src", "launcher/src", "fs-sync/src", "interceptors"];
/** An expression that names a base: an identifier (or member, or call)
 *  ending in `base`/`Base`/`BASE`. */
const BASE_EXPR = "((?:[A-Za-z_$][\\w$.]*)?(?:[Bb]ase|BASE)[\\w$]*(?:\\([^()]*\\))?)";
const JOIN_RE = new RegExp(`join\\(\\s*${BASE_EXPR}\\s*,\\s*([^,)]+)`, "g");
const TPL_RE = new RegExp("`\\$\\{" + BASE_EXPR + "\\}/([^`/]*)", "g");
/** Bases that are not the runtime base, by name. */
const NOT_RUNTIME_NAME = /(^|\.)(basePath|baseUrl|stateBase|relativeBase|baseDir|tmpBase)$|^endpointApiBase\(/;
/** Plain `base` that is not the runtime base, per file (each with what it is). */
const NOT_RUNTIME_FILE: Record<string, string> = {
  "launcher/src/codex-sandbox.ts": "Codex's own home (CODEX_HOME)",
  "launcher/src/wsl.ts": "a Windows profile folder",
  "interceptors/anthropic-proxy/src/fs-gate.ts": "a relative path's base folder",
};
/** Per file, the one entry expression that stands for a scope dir `<scope
 *  id>` (parse.ts refuses a scope id that names a registry entry). */
const SCOPE_EXPR: Record<string, string> = {
  "launcher/src/parse.ts": "`${scopeId}`",
  "launcher/src/scope-dir-cleanup.ts": "i.scopeId",
  "launcher/src/reap.ts": "name", // the scope-dir walk, `^\d+-\d+$` only
};
const CONSTS: Record<string, string> = {
  HUMAN_DIR, INSTANCES_DIR, CURRENT_LINK, ARBITER_SOCK, DASHBOARDS_DIR, CURRENT_TMP_PREFIX, GATE_DIR,
};

function sources(): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const n of readdirSync(d)) {
      if (["node_modules", "test", "generated", "target", "dist"].includes(n)) continue;
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(ts|mjs)$/.test(n) && !n.endsWith(".d.ts")) out.push(p);
    }
  };
  for (const r of ROOTS) walk(join(REPO, r));
  return out;
}

/** The first path component an argument names: a string literal, a template
 *  (constants filled in, anything else `<x>`), a known constant, or a scope. */
function firstComponent(file: string, arg: string): string | null {
  const a = arg.trim();
  if (SCOPE_EXPR[file] === a) return "<scope>";
  const lit = a.match(/^"([^"]*)"$/) ?? a.match(/^'([^']*)'$/);
  if (lit) return lit[1]!.split("/")[0]!;
  const tpl = a.match(/^`([^`]*)`$/);
  const body = tpl ? tpl[1]! : null;
  if (body !== null) return body.replace(/\$\{([^}]*)\}/g, (_m, e: string) => CONSTS[e.trim()] ?? "<x>").split("/")[0]!;
  if (a in CONSTS) return CONSTS[a]!;
  return null;
}

test("completeness: every entry joined directly onto a runtime base anywhere in the sources is denied, the human plane's, or a scope dir", () => {
  const found: string[] = [];
  const unknown: string[] = [];
  for (const file of sources()) {
    const rel = relative(REPO, file);
    const lines = readFileSync(file, "utf8").split("\n");
    lines.forEach((line, i) => {
      const t = line.trim();
      if (t.startsWith("*") || t.startsWith("/*") || t.startsWith("//")) return;
      const hits = [
        ...[...line.matchAll(JOIN_RE)].map((m) => ({ base: m[1]!, arg: m[2]! })),
        ...[...line.matchAll(TPL_RE)].map((m) => ({ base: m[1]!, arg: "`" + m[2]! + "`" })),
      ];
      for (const h of hits) {
        if (NOT_RUNTIME_NAME.test(h.base)) continue;
        if (h.base === "base" && rel in NOT_RUNTIME_FILE) continue;
        const name = firstComponent(rel, h.arg);
        const where = `${rel}:${i + 1} ${h.base} / ${h.arg.trim()}`;
        if (name === null) { unknown.push(`${where} (an entry this oracle cannot read: spell it as a literal or a known constant)`); continue; }
        found.push(`${rel} ${name}`);
        if (name === "<scope>" || name === "human" || listed(name)) continue;
        unknown.push(`${where} → "${name}" is not on runtime-registry.ts's list`);
      }
    });
  }
  assert.deepEqual(unknown, [], "an entry under the runtime base that the macOS profile does not deny");
  // Not vacuous: the scan sees the owners named above.
  for (const want of [
    "arbiter/ipc/instance.ts instances", "arbiter/ipc/instance.ts current", "arbiter/ipc/instance.ts .current.tmp-<x>", "arbiter/ipc/instance.ts arbiter.sock",
    "arbiter/ipc/instance.ts human", "dashboard/src/registry.ts dashboards", "dashboard/src/supervisor/supervisor-defs.ts test",
    "dashboard/src/supervisor/supervisor.ts logs", "launcher/src/run.ts logs", "launcher/src/subcommands.ts dashboard.log",
    "launcher/src/subcommands.ts dashboard-<x>.port", "launcher/src/reap.ts vm-guests", "launcher/src/parse.ts <scope>",
    "launcher/src/release-gate.ts release-check",
  ]) assert.ok(found.includes(want), `the scan found ${want}\n${found.join("\n")}`);
});

test("nothing else: the base itself and every session dir stay writable", () => {
  const r = runtimeRegistryPaths(BASE);
  for (const p of [...r.dirs, ...r.names, ...r.prefixes]) assert.equal(dirname(p), BASE, `${p} is one entry directly in the base`);
  assert.ok(![...r.dirs, ...r.names].includes(BASE));
  assert.ok(!r.dirs.some((d) => /\/\d+-\d+$/.test(d)), "no scope dir (`<epoch>-<pid>`)");
  assert.ok(!listed("1790000000-4242") && !listed("named-scope"), "a scope dir is never covered by a prefix");
});
