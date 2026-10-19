/**
 * version-report — `mandu version` (packaging.md §11.7): which Mandu this is,
 * where it is, which commit it came from, and what else on this machine could
 * make it behave like another one. For triage and bug reports; `--json` gives
 * the same report. `mandu --version` stays the one line `mandu <version>`.
 *
 * What it says:
 *   - this mandu: the file the shell ran and the file it resolves to, how it
 *     is installed (an npm package, or a source checkout running its own
 *     build or its TypeScript), its release, and its commits: the source
 *     repository's and the public repository's. An installed package reads
 *     them from `dist/build-info.json` (scripts/build-info.mjs; written when
 *     the package was built, since an install has no git); a checkout asks
 *     git now, so a pull never leaves it naming an old commit;
 *   - every `mandu` on PATH, in order, what each is, and which one runs;
 *   - the running Mandu services: the arbiter's release and build against
 *     this mandu's (arbiter-version.ts, the same comparison a launch makes),
 *     where its code is, and the systemd service that keeps it alive, if one
 *     does (stack-supervisor.ts);
 *   - the environment variables that change which code runs (MANDU_DEV_REPO,
 *     MANDU_LAYOUT, MANDU_FROM_SOURCE) or which services it uses;
 *   - the globally installed npm package, when it is not this one;
 *   - the problems among those, each with its fix.
 * Read-only: it starts nothing and stops nothing. Every effect is injected.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { accessSync, constants, existsSync, readFileSync, readlinkSync, realpathSync } from "node:fs";
import { basename, delimiter, dirname, join, resolve } from "node:path";
import { gitFacts, readBuildInfo, type BuildInfo, type GitRun } from "../scripts/build-info.mjs";
import { arbiterRevOf, arbiterTreesMatch } from "./arbiter.js";
import { resolveArbiterSock } from "./arbiter-sock.js";
import { describeBuild, ownArbiterBuild, parseBuild, versionVerdict, type BuildIdentity, type VersionVerdict } from "./arbiter-version.js";
import { NODE_FLOOR, nodeMeetsFloor } from "./node-floor.js";
import { ndjsonCall } from "./secret-setup.js";
import { Layout } from "./services/layout.js";
import { describeSupervisor, disableCommand, OWN_STACK_NOTE, ownStackCommand, stackSupervisor, type StackSupervisor } from "./stack-supervisor.js";
// A cycle (subcommands dispatches here), used only at call time.
import { residentPidsOn } from "./subcommands.js";
import { launcherVersion } from "./update-check.js";

type Env = Record<string, string | undefined>;

/** The npm package's name. */
const PACKAGE = "@mandusec/mandu";

/** How a `mandu` is installed. */
export type InstallKind =
  | "npm"            // an npm package (or one unpacked by install.sh / Homebrew)
  | "checkout-build" // a source checkout running its own launcher/dist
  | "checkout-source"// a source checkout running its TypeScript through tsx
  | "checkout-shim"  // launcher/mandu-run.sh of a source checkout (on PATH)
  | "other";         // something else named mandu

export interface SelfFacts {
  /** The path the shell ran (argv[1]), or null. */
  invoked: string | null;
  /** That path with every symlink resolved. */
  realPath: string | null;
  kind: InstallKind;
  /** The package root (npm) or the repository root (checkout). */
  root: string;
  version: string;
  /** Where the commits below came from. */
  commitsFrom: "build-info" | "git" | "none";
  sourceCommit: string | null;
  publicCommit: string | null;
  publicAhead: number;
  dirty: boolean | null;
}

export interface PathEntry {
  /** `<dir>/mandu` as PATH spells it. */
  path: string;
  realPath: string | null;
  kind: InstallKind;
  /** Its package or repository root, when known. */
  root: string | null;
  version: string | null;
  /** This is the mandu that is running. */
  running: boolean;
}

export interface ServiceFacts {
  sock: string;
  /** How the socket was chosen (arbiter-sock.ts): `pinned` = MANDU_ARBITER_SOCK. */
  sockMode: string;
  /** The stack's runtime folder (`mandu stop --stack` takes it). */
  base: string;
  /** The arbiter answered `hello`. */
  running: boolean;
  version: string | null;
  build: BuildIdentity | null;
  pid: number | null;
  startedAt: string | null;
  /** The directory its code runs from (its working directory), or null. */
  codeDir: string | null;
  /** Its release and build against this mandu's. */
  verdict: VersionVerdict["kind"] | null;
  /** This mandu's arbiter build, for the message. */
  ourBuild: BuildIdentity | null;
  supervisor: StackSupervisor | null;
}

export interface Problem {
  id: string;
  /** What is wrong, in a sentence. */
  problem: string;
  /** What to run or change. */
  fix: string;
}

export interface VersionReport {
  self: SelfFacts;
  node: { version: string; path: string; meetsFloor: boolean; floor: string };
  path: PathEntry[];
  services: ServiceFacts | null;
  /** The MANDU_* variables that change which code or services run, as set. */
  env: Record<string, string>;
  /** The globally installed npm package, when npm answers. */
  npmGlobal: { root: string; version: string | null; installed: boolean } | null;
  /** This mandu's layout was forced by the environment (MANDU_DEV_REPO,
   *  MANDU_LAYOUT): the services it starts come from `effectiveRoot`. */
  forcedLayout: { mode: "installed" | "dev"; effectiveRoot: string } | null;
  problems: Problem[];
}

/** The variables that change which code or which services a mandu uses. */
export const STEERING_VARS = ["MANDU_DEV_REPO", "MANDU_LAYOUT", "MANDU_FROM_SOURCE", "MANDU_ARBITER_SOCK", "MANDU_ARBITER_SOCKET", "MANDU_RUNTIME_DIR", "MANDU_HOME"] as const;

/** The effects the report needs, injectable for tests. */
export interface VersionDeps {
  env: Env;
  /** argv[1] of this process. */
  argv1: string | undefined;
  /** import.meta.url of the running launcher module. */
  moduleUrl: string;
  /** The layout the launch would use (env-forced or not). */
  layout: Layout;
  realpath: (p: string) => string | null;
  isExecutable: (p: string) => boolean;
  exists: (p: string) => boolean;
  readFile: (p: string) => string | null;
  git: GitRun;
  /** One `hello` on `sock`; undefined (or a rejection) when nothing answers. */
  hello: (sock: string) => Promise<unknown>;
  /** The socket the next launch would use, or null when that cannot be said. */
  arbiterSock: (env: Env) => { sock: string; mode: string; base: string } | null;
  /** The systemd service keeping the stack at `base` alive, or null. */
  supervisor: (base: string, arbiterPid: number | null) => StackSupervisor | null;
  /** A process's working directory, or null. */
  cwdOf: (pid: number) => string | null;
  /** Where `npm install -g` puts packages (globalNpmRoot), or null. */
  npmRoot: () => string | null;
  /** The arbiter build this mandu would start, and the tree check. */
  ownBuild: () => BuildIdentity | null;
  sameArbiterTree: (a: string, b: string) => boolean | null;
  node: { version: string; path: string };
}

/** What a `mandu` file is, from its resolved path. Pure but for `exists`/`readFile`. */
export function classifyMandu(realPath: string, deps: Pick<VersionDeps, "exists" | "readFile">): { kind: InstallKind; root: string | null; version: string | null } {
  const versionAt = (pkgJson: string): string | null => {
    const raw = deps.readFile(pkgJson);
    if (raw === null) return null;
    try {
      const v = (JSON.parse(raw) as { version?: unknown }).version;
      return typeof v === "string" ? v : null;
    } catch {
      return null;
    }
  };
  if (basename(realPath) === "mandu-run.sh" && basename(dirname(realPath)) === "launcher") {
    return { kind: "checkout-shim", root: dirname(dirname(realPath)), version: versionAt(join(dirname(realPath), "package.json")) };
  }
  if (basename(realPath) === "mandu.mjs" && basename(dirname(realPath)) === "bin") {
    const pkg = dirname(dirname(realPath));
    const version = versionAt(join(pkg, "package.json"));
    if (deps.exists(join(pkg, "src", "run.ts"))) return { kind: "checkout-build", root: dirname(pkg), version };
    return { kind: "npm", root: pkg, version };
  }
  // The shim scripts/bootstrap.sh writes (the from-source install): a script
  // that names its checkout in REPO_ROOT and runs launcher/mandu-run.sh.
  const text = deps.readFile(realPath);
  if (text !== null && text.length < 16_384 && text.includes("generated by scripts/bootstrap.sh")) {
    const m = /^REPO_ROOT="([^"\n]+)"$/m.exec(text);
    if (m) return { kind: "checkout-shim", root: m[1]!, version: versionAt(join(m[1]!, "launcher", "package.json")) };
  }
  return { kind: "other", root: null, version: null };
}

/** This mandu: where it is, what it is, its commits. */
export function selfFacts(deps: VersionDeps): SelfFacts {
  // How it runs, from where the module is (the environment cannot change it).
  const own = Layout.detect(deps.moduleUrl, {}, deps.exists);
  const kind: InstallKind = own.mode === "installed" ? "npm" : own.bundled ? "checkout-build" : "checkout-source";
  const root = own.mode === "installed" ? own.pkgRoot : own.repoRoot;
  const invoked = deps.argv1 ? resolve(deps.argv1) : null;
  const base = { invoked, realPath: invoked ? deps.realpath(invoked) : null, kind, root, version: launcherVersion() };
  if (kind === "npm") {
    const info: BuildInfo | null = readBuildInfo(join(own.pkgRoot, "dist"), (p) => {
      const s = deps.readFile(p);
      if (s === null) throw new Error("absent");
      return s;
    });
    return {
      ...base,
      commitsFrom: info ? "build-info" : "none",
      sourceCommit: info?.sourceCommit ?? null,
      publicCommit: info?.publicCommit ?? null,
      publicAhead: info?.publicAhead ?? 0,
      dirty: info?.dirty ?? null,
    };
  }
  const g = gitFacts(root, deps.git);
  return {
    ...base,
    commitsFrom: g ? "git" : "none",
    sourceCommit: g?.sourceCommit ?? null,
    publicCommit: g?.publicCommit ?? null,
    publicAhead: g?.publicAhead ?? 0,
    dirty: g?.dirty ?? null,
  };
}

/** Every `mandu` on PATH, first first (the one the shell runs). */
export function pathEntries(self: SelfFacts, deps: VersionDeps): PathEntry[] {
  const out: PathEntry[] = [];
  const seen = new Set<string>();
  const selfReal = self.realPath;
  for (const dir of (deps.env["PATH"] ?? "").split(delimiter)) {
    if (!dir) continue;
    const p = join(dir, "mandu");
    if (seen.has(p) || !deps.isExecutable(p)) continue;
    seen.add(p);
    const real = deps.realpath(p);
    const c = real ? classifyMandu(real, deps) : { kind: "other" as const, root: null, version: null };
    // A checkout's shim runs that checkout's bin: it is this mandu when the
    // checkout is this one.
    const running = (real !== null && real === selfReal) ||
      (c.kind === "checkout-shim" && self.kind !== "npm" && c.root !== null && deps.realpath(c.root) === deps.realpath(self.root));
    out.push({ path: p, realPath: real, ...c, running });
  }
  return out;
}

/** The running arbiter on the socket a launch would use, against this mandu. */
export async function serviceFacts(self: SelfFacts, deps: VersionDeps): Promise<ServiceFacts | null> {
  let where: { sock: string; mode: string; base: string } | null;
  try {
    where = deps.arbiterSock(deps.env);
  } catch {
    where = null;
  }
  if (where === null) return null;
  let hello: unknown;
  try {
    hello = await deps.hello(where.sock);
  } catch {
    hello = undefined;
  }
  const h = hello && typeof hello === "object" ? (hello as Record<string, unknown>) : null;
  const pid = typeof h?.["pid"] === "number" && Number.isInteger(h["pid"]) && (h["pid"] as number) > 0 ? (h["pid"] as number) : null;
  const running = h !== null && typeof h["protocolVersion"] === "number";
  if (!running) {
    return {
      sock: where.sock, sockMode: where.mode, base: where.base, running: false, version: null, build: null, pid: null,
      startedAt: null, codeDir: null, verdict: null, ourBuild: null, supervisor: null,
    };
  }
  const verdict = versionVerdict(self.version, hello, { own: deps.ownBuild, sameArbiterTree: deps.sameArbiterTree });
  let supervisor: StackSupervisor | null = null;
  // A pinned socket is the caller's own, not the resident stack a launch
  // would stop (arbiter-version.ts): no supervisor is looked for there.
  if (where.mode !== "pinned") {
    try { supervisor = deps.supervisor(where.base, pid); } catch { supervisor = null; }
  }
  return {
    sock: where.sock,
    sockMode: where.mode,
    base: where.base,
    running: true,
    version: typeof h["version"] === "string" ? h["version"] : null,
    build: parseBuild(hello),
    pid,
    startedAt: typeof h["startedAt"] === "string" ? h["startedAt"] : null,
    codeDir: pid !== null ? deps.cwdOf(pid) : null,
    verdict: verdict.kind,
    ourBuild: deps.ownBuild(),
    supervisor,
  };
}

/** The problems a report shows, each with its fix. Pure. */
export function problemsOf(r: Omit<VersionReport, "problems">): Problem[] {
  const out: Problem[] = [];
  const self = r.self;

  // 1. The environment forces another layout: the services come from elsewhere.
  if (r.forcedLayout !== null) {
    const vars = ["MANDU_DEV_REPO", "MANDU_LAYOUT"].filter((k) => r.env[k] !== undefined).map((k) => `${k}=${r.env[k]}`);
    if (r.forcedLayout.mode === "dev" && self.kind === "npm") {
      out.push({
        id: "forced-dev-layout",
        problem: `${vars.join(" and ")} makes this npm mandu start its services from the source tree at ${r.forcedLayout.effectiveRoot}, not from this package.`,
        fix: `unset ${vars.map((v) => v.split("=")[0]).join(" ")} (look in your shell's startup files and ~/.mandu/config.toml)`,
      });
    } else if (r.forcedLayout.mode !== (self.kind === "npm" ? "installed" : "dev")) {
      out.push({
        id: "forced-layout",
        problem: `${vars.join(" and ")} makes this mandu run its services as ${r.forcedLayout.mode === "dev" ? "a source checkout's" : "an installed package's"} from ${r.forcedLayout.effectiveRoot}.`,
        fix: `unset ${vars.map((v) => v.split("=")[0]).join(" ")} unless you meant it`,
      });
    }
  }

  // 2. Typing `mandu` runs another one, or another one waits behind it.
  const first = r.path[0];
  if (first !== undefined && !first.running) {
    out.push({
      id: "path-runs-another",
      problem: `typing \`mandu\` runs ${first.path} (${kindWords(first)}), not this one (${self.invoked ?? self.root}).`,
      fix: `if this is the mandu you want, remove or rename ${first.path}` +
        (self.invoked !== null && basename(self.invoked) === "mandu" ? `, or put ${dirname(self.invoked)} before ${dirname(first.path)} on PATH` : "") +
        "; then run `hash -r` in open shells",
    });
  }
  for (const e of r.path.slice(1)) {
    if (e.running || (first !== undefined && e.realPath !== null && e.realPath === first.realPath)) continue;
    out.push({
      id: "path-shadowed",
      problem: `another mandu is on PATH: ${e.path} (${kindWords(e)}). It does not run while ${first?.path} comes first, but a shell with another PATH, or one that remembered it, runs it.`,
      fix: `remove it if you no longer use it: rm ${e.path}; then run \`hash -r\` in open shells`,
    });
  }

  // 3. The running services are another release or build.
  const s = r.services;
  if (s?.running && s.verdict !== null && s.verdict !== "match" && s.verdict !== "unknown") {
    const theirs = s.version ? `Mandu ${s.version}` : "an older Mandu (one that does not report its version)";
    const what = s.verdict === "build"
      ? `another build of Mandu ${s.version} (${describeBuild(s.build ?? { bundle: null, rev: null })}; this mandu's is ${describeBuild(s.ourBuild ?? { bundle: null, rev: null })})`
      : theirs;
    const from = s.codeDir ? `, running from ${s.codeDir}` : "";
    if (s.supervisor) {
      out.push({
        id: "services-supervised-other-build",
        problem: `the Mandu services running for you (arbiter pid ${s.pid ?? "?"}${from}) are ${what}, and ${describeSupervisor(s.supervisor)} starts them again whenever they stop. A launch of this mandu refuses to use them and cannot replace them.`,
        fix: `${disableCommand(s.supervisor)}${s.supervisor.fragmentPath ? ` (its unit file: ${s.supervisor.fragmentPath})` : ""}; or, to keep that service, run this mandu on its own stack: ${ownStackCommand(s.base)} (${OWN_STACK_NOTE})`,
      });
    } else if (s.sockMode === "pinned") {
      out.push({
        id: "services-pinned-other-build",
        problem: `MANDU_ARBITER_SOCK points this mandu at an arbiter that runs ${what}${from}; a launch refuses it.`,
        fix: "unset MANDU_ARBITER_SOCK, or restart that arbiter from this mandu's install",
      });
    } else {
      out.push({
        id: "services-other-build",
        problem: `the Mandu services running for you (arbiter pid ${s.pid ?? "?"}${from}) are ${what}. The next launch replaces them when no other mandu session uses them, and refuses otherwise.`,
        fix: `end the other sessions, or stop the services now: mandu stop --stack ${s.base}`,
      });
    }
  }

  // 4. The global npm package is not the one running.
  if (r.npmGlobal?.installed && self.kind !== "npm" && r.npmGlobal.version !== null) {
    out.push({
      id: "npm-not-running",
      problem: `${PACKAGE} ${r.npmGlobal.version} is installed globally (${join(r.npmGlobal.root, PACKAGE)}), but the mandu running is ${kindWords({ kind: self.kind, root: self.root, version: self.version })}.`,
      fix: "remove the other mandu from PATH (see above), or uninstall the one you do not use",
    });
  } else if (r.npmGlobal?.installed && self.kind === "npm" && self.realPath !== null
    && r.npmGlobal.version !== null && r.npmGlobal.version !== self.version
    && !self.realPath.startsWith(join(r.npmGlobal.root, PACKAGE) + "/")) {
    out.push({
      id: "npm-two-installs",
      problem: `two npm installs: this one (${self.version}, ${self.root}) and the global one (${r.npmGlobal.version}, ${join(r.npmGlobal.root, PACKAGE)}).`,
      fix: "keep one: npm uninstall -g @mandusec/mandu, or remove this one",
    });
  }

  // 5. Node below the floor (a checkout run through tsx can get this far).
  if (!r.node.meetsFloor) {
    out.push({
      id: "node-too-old",
      problem: `Node ${r.node.version} (${r.node.path}) is older than Mandu needs (${r.node.floor}).`,
      fix: "install Node 22.13 or newer (nvm install 22)",
    });
  }
  return out;
}

/** "npm package 0.2.0-beta.6 at /…", "source checkout /… (0.2.0-beta.5)". */
function kindWords(e: { kind: InstallKind; root: string | null; version: string | null }): string {
  const v = e.version ? ` ${e.version}` : "";
  switch (e.kind) {
    case "npm": return `npm package${v}${e.root ? ` at ${e.root}` : ""}`;
    case "checkout-shim": return `the source checkout ${e.root ?? "?"}${e.version ? ` (${e.version})` : ""}, through its mandu-run.sh`;
    case "checkout-build": return `the source checkout ${e.root ?? "?"}${e.version ? ` (${e.version})` : ""}, its own build`;
    case "checkout-source": return `the source checkout ${e.root ?? "?"}${e.version ? ` (${e.version})` : ""}, from TypeScript`;
    default: return "not a Mandu install this can read";
  }
}

/** Gather the whole report. */
export async function gatherVersionReport(deps: VersionDeps): Promise<VersionReport> {
  const self = selfFacts(deps);
  const env: Record<string, string> = {};
  for (const k of STEERING_VARS) {
    const v = deps.env[k];
    if (v !== undefined && v !== "") env[k] = v;
  }
  const own = Layout.detect(deps.moduleUrl, {}, deps.exists);
  const forced = deps.layout.mode !== own.mode || (deps.layout.mode === "dev" && deps.layout.repoRoot !== own.repoRoot)
    ? { mode: deps.layout.mode, effectiveRoot: deps.layout.mode === "dev" ? deps.layout.repoRoot : deps.layout.pkgRoot }
    : null;
  let npmGlobal: VersionReport["npmGlobal"] = null;
  const root = deps.npmRoot();
  if (root !== null) {
    const pj = deps.readFile(join(root, PACKAGE, "package.json"));
    let version: string | null = null;
    if (pj !== null) {
      try {
        const v = (JSON.parse(pj) as { version?: unknown }).version;
        version = typeof v === "string" ? v : null;
      } catch { /* unreadable: null */ }
    }
    npmGlobal = { root, version, installed: pj !== null };
  }
  const partial = {
    self,
    node: { ...deps.node, meetsFloor: nodeMeetsFloor(deps.node.version, NODE_FLOOR), floor: NODE_FLOOR },
    path: pathEntries(self, deps),
    services: await serviceFacts(self, deps),
    env,
    npmGlobal,
    forcedLayout: forced,
  };
  return { ...partial, problems: problemsOf(partial) };
}

const short = (c: string | null): string => (c ? c.slice(0, 12) : "not recorded");

/** "source 1c322e3c55b5, public 9a8b7c6d5e4f + 2 commits + uncommitted
 *  changes", or why there is none. Pure. */
export function commitWords(s: SelfFacts): string {
  if (s.commitsFrom === "none") {
    return s.kind === "npm"
      ? "not recorded (this package was built before Mandu recorded its commit)"
      : "unknown (no git here)";
  }
  const ahead = s.publicCommit !== null && s.publicAhead > 0 ? ` + ${s.publicAhead} commit${s.publicAhead === 1 ? "" : "s"}` : "";
  const dirty = s.dirty ? " + uncommitted changes" : "";
  return `source ${short(s.sourceCommit)}, public ${short(s.publicCommit)}${ahead}${dirty}`;
}

/** The human-readable report. Pure. */
export function renderVersionReport(r: VersionReport): string {
  const s = r.self;
  const L: string[] = [];
  L.push(`mandu ${s.version}`);
  const col = (k: string, v: string): string => `  ${k.padEnd(15)}${v}`;
  L.push(col("this mandu:", s.invoked ?? "(unknown)"));
  if (s.realPath && s.realPath !== s.invoked) L.push(col("", `→ ${s.realPath}`));
  L.push(col("installed as:", kindWords({ kind: s.kind, root: s.root, version: null })));
  L.push(col("commit:", commitWords(s)));
  L.push(col("node:", `${r.node.version} (${r.node.path})`));
  L.push("");

  L.push("mandu on PATH (the first one runs):");
  if (r.path.length === 0) L.push("  none: this mandu was run by its path");
  for (const e of r.path) {
    L.push(`  ${e.running ? "*" : " "} ${e.path}`);
    L.push(`      ${kindWords(e)}${e.running ? "  ← this one" : ""}`);
  }
  L.push("");

  L.push("running Mandu services:");
  const sv = r.services;
  if (sv === null) {
    L.push("  could not tell (the runtime folder is not usable)");
  } else if (!sv.running) {
    L.push(`  none (the next launch starts them; socket ${sv.sock})`);
  } else {
    const verdict = sv.verdict === "match" ? "same as this mandu"
      : sv.verdict === "build" ? "ANOTHER BUILD than this mandu"
        : sv.verdict === "unknown" ? "cannot compare"
          : "ANOTHER RELEASE than this mandu";
    L.push(col("arbiter:", `${sv.version ? `Mandu ${sv.version}` : "a release that does not report its version"}${sv.build ? ` (${describeBuild(sv.build)})` : ""}: ${verdict}`));
    L.push(col("", `pid ${sv.pid ?? "?"}${sv.startedAt ? `, since ${sv.startedAt}` : ""}${sv.codeDir ? `, from ${sv.codeDir}` : ""}`));
    L.push(col("", `socket ${sv.sock}${sv.sockMode === "pinned" ? " (MANDU_ARBITER_SOCK)" : ""}`));
    if (sv.supervisor) L.push(col("kept alive by:", describeSupervisor(sv.supervisor)));
  }
  L.push("");

  const envKeys = Object.keys(r.env);
  if (envKeys.length > 0) {
    L.push("environment that changes what runs:");
    for (const k of envKeys) L.push(`  ${k}=${r.env[k]}`);
    L.push("");
  }
  if (r.npmGlobal?.installed) {
    L.push(`global npm package: ${PACKAGE} ${r.npmGlobal.version ?? "?"} at ${join(r.npmGlobal.root, PACKAGE)}`);
    L.push("");
  }

  if (r.problems.length === 0) {
    L.push("No install problems found.");
  } else {
    L.push(`${r.problems.length} problem${r.problems.length === 1 ? "" : "s"}:`);
    for (const p of r.problems) {
      L.push(`  ! ${p.problem}`);
      L.push(`    fix: ${p.fix}`);
    }
  }
  L.push("More checks (prerequisites, protection, updates): mandu doctor");
  return L.join("\n") + "\n";
}

/**
 * Where `npm install -g` puts packages, worked out without running npm
 * (`npm root -g` writes a debug log and an update-notifier stamp under
 * ~/.npm, and this report only looks): `npm_config_prefix`, else the
 * `prefix=` of ~/.npmrc, else the prefix of the node running Mandu (its
 * `bin/`'s parent: nvm's, or /usr). Then `<prefix>/lib/node_modules`
 * (`<prefix>/node_modules` on Windows). Pure but for `readFile`.
 */
export function globalNpmRoot(env: Env, execPath: string, readFile: (p: string) => string | null): string | null {
  const home = env["HOME"];
  const expand = (p: string): string => (home ? p.replace(/^~(?=\/|$)/, home).replace(/\$\{HOME\}|\$HOME\b/g, home) : p);
  let prefix = env["npm_config_prefix"] || env["NPM_CONFIG_PREFIX"] || null;
  if (!prefix && home) {
    const rc = readFile(join(home, ".npmrc"));
    const m = rc === null ? null : /^\s*prefix\s*=\s*(.+?)\s*$/m.exec(rc);
    if (m) prefix = m[1]!.replace(/^["']|["']$/g, "");
  }
  if (!prefix) prefix = dirname(dirname(execPath));
  prefix = expand(prefix);
  return process.platform === "win32" ? join(prefix, "node_modules") : join(prefix, "lib", "node_modules");
}

/** The real effects. */
export function realVersionDeps(env: Env, layout: Layout): VersionDeps {
  return {
    env,
    argv1: process.argv[1],
    moduleUrl: import.meta.url,
    layout,
    realpath: (p) => { try { return realpathSync(p); } catch { return null; } },
    isExecutable: (p) => { try { accessSync(p, constants.X_OK); return true; } catch { return false; } },
    exists: existsSync,
    readFile: (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } },
    git: (dir, args) => {
      const r = spawnSync("git", ["-C", dir, ...args], {
        encoding: "utf8", timeout: 5_000, stdio: ["ignore", "pipe", "ignore"],
        env: { ...process.env, GIT_DIR: undefined, GIT_WORK_TREE: undefined, GIT_OPTIONAL_LOCKS: "0" },
      });
      return r.status === 0 && typeof r.stdout === "string" ? r.stdout : null;
    },
    hello: (sock) => ndjsonCall<unknown>(sock, "hello", {}, 3_000),
    arbiterSock: (e) => resolveArbiterSock(e),
    supervisor: (base, arbiterPid) => stackSupervisor([...(arbiterPid !== null ? [arbiterPid] : []), ...residentPidsOn(base)]),
    cwdOf: (pid) => { try { return readlinkSync(`/proc/${pid}/cwd`); } catch { return null; } },
    npmRoot: () => globalNpmRoot(env, process.execPath, (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } }),
    ownBuild: () => ownArbiterBuild(layout, { revOf: arbiterRevOf }),
    sameArbiterTree: (a, b) => arbiterTreesMatch(layout.repoRoot, a, b),
    node: { version: process.versions.node, path: process.execPath },
  };
}

/** `mandu version [--json]`. */
export async function runVersion(args: string[], env: Env, layout: Layout, deps?: VersionDeps): Promise<number> {
  const report = await gatherVersionReport(deps ?? realVersionDeps(env, layout));
  process.stdout.write(args.includes("--json") ? JSON.stringify(report, null, 2) + "\n" : renderVersionReport(report));
  return 0;
}
