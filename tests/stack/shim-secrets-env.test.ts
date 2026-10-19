/**
 * shim-secrets-env e2e — the secrets file reaches the launcher's environment
 * from the launcher's own node exactly as it did from the shell
 * (packaging.md §5.1, 2026-10-16).
 *
 * A checkout's `mandu` (launcher/mandu-run.sh) no longer sources
 * scripts/mandu-env.sh, which ran `node secrets-to-env.mjs` and eval'd its
 * exports into the shell before it exec'd the launcher; bin/mandu.mjs's
 * checkout prelude (launcher/scripts/checkout-launch.mjs) applies the same
 * load in process. The env-masking step later in the launch
 * (applyEnvSecrets) reads that environment, so it must see exactly the
 * variables it saw before, with the same values: else a key from the file
 * could reach the agent raw, or a variable the human set could be replaced.
 *
 * In a stand-in checkout (the real shim, bin, prelude, mandu-env.sh,
 * secrets-to-env.mjs and path table; a built launcher whose main() dumps its
 * process.env), each case runs the shim and a reference shell that is the
 * old shim's secrets block verbatim, then compares the two environments
 * whole: variables the file sets, ones already set (kept), ones set empty
 * (filled), a value with quotes, `$`, backticks, a backslash, a newline and
 * non-ASCII, a name the shell refuses, no file, MANDU_SECRETS_FILE=0. The
 * `[mandu-secrets]` lines match too (verbose, quiet, a group-readable file).
 * Then both environments go through the real applyEnvSecrets and socket
 * adapter against a real ArbiterServer: the same variables are masked, and a
 * token from the file reaches the agent only as a placeholder.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, readFileSync, utimesSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { applyEnvSecrets, socketSecretArbiter } from "../../launcher/src/secret-setup.js";
import { emptyMutation } from "../../launcher/src/backend/types.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { fsClockMs, writeStamp } from "../../launcher/scripts/bundle-stamp.mjs";
import { stateAxes } from "../lib/axes.js";
import { tmpDir } from "../lib/tmp-dir.js";

stateAxes("secrets"); // the masking half runs with confidentiality ON, the product default

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

const ANTH = ["sk-ant-api03", "SHIMENV", "e2e", "Q".repeat(40)].join("-");
const OPENAI_ENV = ["sk-proj", "FROMENV", "W".repeat(30)].join("-");
const OPENAI_FILE = ["sk-proj", "FROMFILE", "Z".repeat(30)].join("-");
const GH = ["ghp", "SHIMENVe2e", "x".repeat(26)].join("_");
const TRICKY = `it's "q" $HOME \`id\` \\ ü\nline2`;

/** The old shim's secrets block (launcher/mandu-run.sh before 2026-10-16),
 *  verbatim, then the exec of a node that dumps its environment. */
const REFERENCE = `#!/usr/bin/env bash
set -uo pipefail
REPO_ROOT="$1"; DUMPER="$2"; shift 2
if [[ -f "$REPO_ROOT/scripts/mandu-env.sh" ]]; then
  _mandu_quiet=1
  case "\${MANDU_VERBOSE:-}" in ""|0|false|FALSE|False) ;; *) _mandu_quiet=0 ;; esac
  for _a in "$@"; do [[ "$_a" == "--verbose" ]] && _mandu_quiet=0; [[ "$_a" == "--" ]] && break; done
  # shellcheck source=/dev/null
  MANDU_SECRETS_QUIET=$_mandu_quiet source "$REPO_ROOT/scripts/mandu-env.sh" || true
  unset _mandu_quiet _a
fi
exec node "$DUMPER" "$@"
`;

const DUMPER = `import { writeFileSync } from "node:fs";
writeFileSync(process.env.DUMP_ENV, JSON.stringify(process.env));
`;

/** The built launcher stub: main() dumps the environment it was given. */
const BUNDLE = `import { writeFileSync } from "node:fs";
export async function main() { writeFileSync(process.env.DUMP_ENV, JSON.stringify(process.env)); return 0; }
`;

function standIn() {
  const root = tmpDir("mdu-shimenv-");
  const pkg = join(root, "launcher");
  for (const d of ["launcher/bin", "launcher/scripts", "launcher/dist", "launcher/src", "launcher/node_modules/.bin", "scripts/paths", "home"]) {
    mkdirSync(join(root, d), { recursive: true });
  }
  for (const f of ["mandu-run.sh", "bin/mandu.mjs", "scripts/checkout-launch.mjs", "scripts/bundle-stamp.mjs"]) {
    copyFileSync(join(REPO, "launcher", f), join(pkg, f));
  }
  for (const f of ["mandu-env.sh", "secrets-to-env.mjs", "paths/mandu-paths.mjs"]) {
    copyFileSync(join(REPO, "scripts", f), join(root, "scripts", f));
  }
  writeFileSync(join(pkg, "dist", "mandu.mjs"), BUNDLE);
  writeFileSync(join(pkg, "src", "run.ts"), "export {};\n");
  writeFileSync(join(pkg, "node_modules", ".bin", "tsx"), "#!/bin/sh\necho 'the stand-in bundle was judged stale' >&2\nexit 99\n");
  chmodSync(join(pkg, "node_modules", ".bin", "tsx"), 0o755);
  writeFileSync(join(root, "ref.sh"), REFERENCE);
  writeFileSync(join(root, "dump.mjs"), DUMPER);
  // A clean build record over the one input, so the launch runs the bundle.
  const dist = join(pkg, "dist");
  const past = new Date(Date.now() - 60_000);
  utimesSync(join(pkg, "src", "run.ts"), past, past);
  assert.equal(writeStamp(dist, { repoRoot: root, inputs: ["launcher/src/run.ts"], outputs: ["mandu.mjs"], startMs: fsClockMs(dist) }), null);
  return { root, home: join(root, "home") };
}

const C = standIn();

/** Put (or remove) the checkout's secrets.local.json. */
function secretsFile(data: object | null, mode = 0o600): void {
  const p = join(C.root, "secrets.local.json");
  if (data === null) { spawnSync("rm", ["-f", p]); return; }
  writeFileSync(p, JSON.stringify(data));
  chmodSync(p, mode);
}

interface Run { env: Record<string, string>; stderr: string; status: number | null }

/** Run the new shim and the reference with the same environment and argv. */
function both(extraEnv: Record<string, string>, argv: string[] = ["claude", "--version"]): { now: Run; ref: Run } {
  const go = (cmd: string[], tag: string): Run => {
    const dump = join(C.root, `env-${tag}.json`);
    const r = spawnSync("bash", cmd, {
      cwd: C.root, encoding: "utf8", timeout: 60_000,
      env: { PATH: process.env["PATH"], HOME: C.home, DUMP_ENV: dump, ...extraEnv },
    });
    assert.equal(r.status, 0, `${tag}: ${r.stderr}`);
    const env = JSON.parse(readFileSync(dump, "utf8")) as Record<string, string>;
    delete env["_"]; // the path of the last command bash ran: not part of the comparison
    delete env["DUMP_ENV"];
    return { env, stderr: r.stderr, status: r.status };
  };
  return {
    now: go([join(C.root, "launcher", "mandu-run.sh"), ...argv], "now"),
    ref: go([join(C.root, "ref.sh"), C.root, join(C.root, "dump.mjs"), ...argv], "ref"),
  };
}

const secretLines = (s: string) => s.split("\n").filter((l) => l.startsWith("[mandu-secrets]"));

const FILE = {
  anthropic_api_key: ANTH,
  openai_api_key: OPENAI_FILE,
  openai_base_url: "https://file.example/v1",
  ullm_model: "file-model",
  env: {
    GITHUB_TOKEN: GH,
    MANDU_SHIMTEST_TRICKY: TRICKY,
    MANDU_SHIMTEST_PRESET: "from-file",
    MANDU_SHIMTEST_EMPTY: "from-file",
    MANDU_SHIMTEST_BLANK: "   ",
    "bad-name": "refused",
  },
};

test("the launcher's environment is the old shell path's: set, unset, pre-set and pre-set-empty variables, a tricky value, a refused name", () => {
  secretsFile(FILE);
  for (const argv of [["claude", "--version"], ["--verbose", "claude"]]) {
    const { now, ref } = both({ OPENAI_API_KEY: OPENAI_ENV, MANDU_SHIMTEST_PRESET: "from-env", MANDU_SHIMTEST_EMPTY: "" }, argv);
    assert.deepEqual(now.env, ref.env, argv.join(" "));
    assert.equal(now.env["ANTHROPIC_API_KEY"], ANTH, "unset: filled from the file");
    assert.equal(now.env["MANDU_ULLM_API_KEY"], ANTH, "the U-LLM key falls back to the Anthropic key");
    assert.equal(now.env["OPENAI_API_KEY"], OPENAI_ENV, "already set: the environment wins");
    assert.equal(now.env["MANDU_SHIMTEST_PRESET"], "from-env");
    assert.equal(now.env["MANDU_SHIMTEST_EMPTY"], "from-file", "set but empty: the file fills it");
    assert.equal(now.env["MANDU_SHIMTEST_TRICKY"], TRICKY, "the value byte for byte");
    assert.equal(now.env["GITHUB_TOKEN"], GH);
    assert.equal(now.env["MANDU_SHIMTEST_BLANK"], undefined, "a blank value is not loaded");
    assert.equal(now.env["bad-name"], undefined, "a name the shell refuses is not set");
    assert.equal(now.env["MANDU_SHIM_CHECKOUT"], undefined);
    assert.equal(now.env["MANDU_SECRETS_QUIET"], undefined, "the quiet switch stays the load's own");
  }
});

test("no secrets file, and MANDU_SECRETS_FILE=0 over one: nothing is loaded, the environment is the old path's", () => {
  secretsFile(null);
  let r = both({ OPENAI_API_KEY: OPENAI_ENV });
  assert.deepEqual(r.now.env, r.ref.env);
  assert.equal(r.now.env["ANTHROPIC_API_KEY"], undefined);
  secretsFile(FILE);
  r = both({ MANDU_SECRETS_FILE: "0" });
  assert.deepEqual(r.now.env, r.ref.env);
  assert.equal(r.now.env["ANTHROPIC_API_KEY"], undefined, "the switch keeps the file out");
  assert.equal(r.now.env["GITHUB_TOKEN"], undefined);
});

test("the [mandu-secrets] lines are the old path's: none for a quiet launch, the load lines for a verbose one, the permissions warning always", () => {
  const { env: _drop, ...clean } = FILE;
  secretsFile({ ...clean, env: { GITHUB_TOKEN: GH } });
  const quiet = both({});
  assert.deepEqual(secretLines(quiet.now.stderr), []);
  assert.deepEqual(secretLines(quiet.ref.stderr), []);
  for (const [env, argv] of [[{}, ["--verbose", "claude"]], [{ MANDU_VERBOSE: "1" }, ["claude"]]] as const) {
    const v = both({ ...env, OPENAI_API_KEY: OPENAI_ENV }, [...argv]);
    const lines = secretLines(v.now.stderr);
    assert.deepEqual(lines, secretLines(v.ref.stderr));
    assert.ok(lines.some((l) => /loaded .*secrets\.local\.json/.test(l)), lines.join("\n"));
    assert.ok(lines.some((l) => /kept existing OPENAI_API_KEY/.test(l)), lines.join("\n"));
    assert.ok(!lines.join("\n").includes(GH.slice(4)), "no key on stderr");
  }
  // `--verbose` after `--` is the agent's, not the launch's.
  const agents = both({}, ["claude", "--", "--verbose"]);
  assert.deepEqual(secretLines(agents.now.stderr), []);
  assert.deepEqual(secretLines(agents.ref.stderr), []);
  secretsFile({ env: { GITHUB_TOKEN: GH } }, 0o644);
  const loose = both({});
  assert.deepEqual(secretLines(loose.now.stderr), secretLines(loose.ref.stderr));
  assert.ok(secretLines(loose.now.stderr).some((l) => /WARNING: .* is group\/other-readable/.test(l)));
});

const arbDir = tmpDir("mdu-shimenv-arb-");
const sock = join(arbDir, "a.sock");
const server = new ArbiterServer({
  socketPath: sock, adminSocketPath: join(arbDir, "admin.sock"), dbPath: join(arbDir, "symbols.sqlite"), eventDir: join(arbDir, "events"),
  log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
});
after(async () => { await server.close(); });

test("the env-masking step masks the same variables from either path, and a token from the secrets file reaches the agent only as a placeholder", async () => {
  await server.listen();
  secretsFile(FILE);
  const { now, ref } = both({ OPENAI_API_KEY: OPENAI_ENV, MANDU_SHIMTEST_PRESET: "from-env" });
  const mask = async (env: Record<string, string>) => {
    const mut = emptyMutation();
    const logs: string[] = [];
    const res = await applyEnvSecrets({ confidentiality: true } as LaunchPlan, env, mut, {
      arbiter: socketSecretArbiter(sock), log: (m) => logs.push(m),
    });
    return { res, mut, logs };
  };
  const a = await mask(now.env);
  const b = await mask(ref.env);
  assert.deepEqual(a.res.masked, b.res.masked, "the same variables are masked");
  const shape = (e: Record<string, string>) => JSON.stringify(Object.entries(e).sort()).replace(/\[[0-9a-f]+\]/g, "[h]");
  assert.equal(shape(a.mut.env), shape(b.mut.env), "the agent's environment carries the same placeholders");
  assert.ok(a.res.masked.includes("GITHUB_TOKEN"), `${a.res.masked.join(",")} (${a.logs.join(" | ")})`);
  assert.match(a.mut.env["GITHUB_TOKEN"] ?? "", /^\$MDU:nomodel_Env\[[0-9a-f]+\]\.GITHUB_TOKEN$/);
  assert.ok(!JSON.stringify(a.mut.env).includes(GH), "the file's token never enters the agent's environment raw");
});
