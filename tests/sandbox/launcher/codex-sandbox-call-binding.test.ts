/**
 * codex-sandbox-call-binding.test.ts — plan 13 D7: a Codex call run under
 * Codex's own command sandbox binds to its process tree (2026-10-09).
 *
 * The real launcher (`secrets`, the guard) runs the REAL `codex exec` in its
 * `workspace-write` sandbox against a scripted Responses model (no API key).
 * The model asks for two shell calls, one turn each:
 *
 *   (1) `/usr/bin/python3 -I <base64.py> ./secret.tx?`: the pinned reader
 *       reads the labelled file RAW and prints it base64-encoded (past the
 *       value scan; the glob names no labelled path). Only its call's tree
 *       can mask it.
 *   (2) `echo clean-$((6*7))`: a clean call in a session that now holds a
 *       raw secret read.
 *
 * Codex runs each through its sandbox helper (`codex-linux-sandbox`), whose
 * argv the guard records cut inside the shell-snapshot preamble. Before the
 * fix neither call bound to a tree, and while the session held the raw read
 * both were masked at the session's level: (2) reached the model as a
 * symbol. Now each binds to its own helper: (1) is masked by its tree (the
 * reader in it), (2) reaches the model as `clean-42`. The oracle: no request
 * to the model carries the secret, raw or base64.
 *
 * GATED on Linux + bwrap + an unprivileged userns + the built guard + a
 * python3 with the stdlib's base64.py + a codex whose sandbox starts on this
 * host (three tries: one failed start under load decides nothing). A host
 * that bars a sandbox nested in Mandu's skips with the reason, and only on
 * positive evidence: the reading call's own result is bubblewrap's refusal
 * (`nestedBarred`). Any other broken run fails: on 2026-10-09 (GitLab
 * pipelines 9916 and 9918) the npm wrapper's race (the second leg's note)
 * lost the model connection after the read and was taken for this skip.
 * Zero API budget.
 *
 * Two legs (2026-10-09): `codex` as found on PATH (npm's wrapper script
 * in the CI guest, which runs the native binary as its child) and, when it
 * is that wrapper, the native binary launched directly. Through the wrapper
 * the native Codex used to be no agent to the guard, so the reader's raw
 * read made it a holder and the session lost its model connection.
 * (confidentiality-plan-13 §4.5.1, "The agent is never made a holder").
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

import { withStack, runLauncher, startHttpsShim, probeKernelTier } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stdlibBase64 } from "../../lib/holder-reader.js";
import { stateAxes } from "../../lib/axes.js";
import { startScriptedResponses, responsesFnTurn, responsesTextTurn } from "../../lib/fake-responses.js";
import { functionCallOutputSpan } from "../../lib/conf-exfil.js";
import { npmWrappedNative } from "../../../launcher/src/secret-setup.js";

installExitGuard("codex-sandbox-call-binding");

// This suite STATES its axes (protection-modes.md §4): `secrets`, whose
// model exit the call-root recorder serves.
stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const probe = process.platform === "linux" ? probeKernelTier() : null;
const which = (cmd: string): string | null => {
  const r = spawnSync("bash", ["-c", `command -v ${cmd}`], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
};
/** `codex` on PATH: npm's wrapper script in the CI guest (and for most
 *  users), the standalone binary elsewhere. */
const CODEX = process.platform === "linux" ? which("codex") : null;
/** When `codex` is npm's wrapper, the native binary it runs, launched
 *  directly as the second leg (the launcher's own lookup). */
const NATIVE = CODEX !== null ? ((): string | null => {
  try {
    const real = realpathSync(CODEX);
    const nat = npmWrappedNative(real);
    return nat !== null && nat !== real ? nat : null;
  } catch { return null; }
})() : null;
const REAL_CODEX = CODEX;
const B64 = process.platform === "linux" ? stdlibBase64() : null;
const WORKSPACE_WRITE = ["-c", 'sandbox_mode="workspace-write"', "-c", "sandbox_workspace_write.exclude_slash_tmp=true"];

/** Does Codex's own sandbox start here (outside Mandu)? Up to three tries:
 *  the gate skips the suite only when every one fails. */
function codexSandboxStarts(): boolean {
  for (let i = 0; i < 3; i++) if (codexSandboxStartsOnce()) return true;
  return false;
}

function codexSandboxStartsOnce(): boolean {
  const home = mkdtempSync(join(tmpdir(), "mdu-cxbind-probe-"));
  try {
    return spawnSync(REAL_CODEX!, ["sandbox", ...WORKSPACE_WRITE, "--", "true"], {
      cwd: home, env: { ...process.env, CODEX_HOME: home, TMPDIR: home }, stdio: "ignore", timeout: 60_000,
    }).status === 0;
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

const GATE = process.platform !== "linux"
  ? "Linux only (the guard, Codex's Linux sandbox)"
  : !probe!.bwrap
    ? "`bwrap` not installed"
    : !probe!.userns
      ? "unprivileged user namespaces unavailable"
      : !GUARD.path
        ? "mandu-net-guard is not built (scripts/build-native.sh)"
        : !B64
          ? "python3 has no stdlib base64.py (the pinned reader)"
          : REAL_CODEX === null
            ? "codex is not installed"
            : !codexSandboxStarts()
              ? "Codex's own sandbox does not start on this host (launcher/src/codex-sandbox.ts)"
              : false;

const alnum = (n: number): string => [...randomBytes(n)].map((b) => "abcdefghijklmnopqrstuvwxyz0123456789"[b % 36]).join("");
const CANARY = `sk_live_fake${alnum(24)}`;
const FILE = `token=${CANARY}\n`;
const FILE_B64 = Buffer.from(FILE).toString("base64");
const MARKER = "MDU_SANDBOX_BINDING";
const READ_CALL = "call_mdu_sandbox_read";
const CLEAN_CALL = "call_mdu_sandbox_clean";
const READ = `/usr/bin/python3 -I ${B64 ?? "base64.py"} ./secret.tx?`;
const CLEAN = "echo clean-$((6*7))";

interface Run { out: string; code: number; requests: string[]; read: string | null; clean: string | null; proxyLog: string; records: string; cleanMs: number | null }

/** Does a Responses request body carry the output of call `id`? */
const hasOutput = (body: string, id: string): boolean => functionCallOutputSpan(body, id) !== null;

async function run(codexBin: string): Promise<Run> {
  const policyDir = mkdtempSync(join(tmpdir(), "mdu-cxbind-policy-"));
  writeFileSync(join(policyDir, "policy.yaml"), [
    "version: 1", "paths:", "  - path: \"**/workspace/secret.txt\"", "    level: no-model",
    `    readers: [{ app: python3, script: ${B64}, prints: nothing }]`, "",
  ].join("\n"));
  const res: Run = { out: "", code: -1, requests: [], read: null, clean: null, proxyLog: "", records: "", cleanMs: null };
  try {
    await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
      writeFileSync(join(workspace, "secret.txt"), FILE);
      const fake = await startScriptedResponses({
        script: [
          { match: (r) => hasOutput(r.body, CLEAN_CALL), respond: () => responsesTextTurn("MDU_DONE") },
          { match: (r) => hasOutput(r.body, READ_CALL), respond: () => responsesFnTurn(CLEAN_CALL, "exec_command", { cmd: CLEAN }), once: true },
          { match: (r) => !r.hasToolResult && r.body.includes(MARKER), respond: () => responsesFnTurn(READ_CALL, "exec_command", { cmd: READ }), once: true },
        ],
      });
      mkdirSync(join(tmp, "shim-cert"), { recursive: true });
      const shim = await startHttpsShim(fake.origin, join(tmp, "shim-cert"));
      try {
        const codexHome = join(tmp, "codex-home");
        mkdirSync(codexHome, { recursive: true });
        writeFileSync(join(codexHome, "config.toml"), [
          "check_for_update_on_startup = false",
          'approval_policy = "never"',
          'sandbox_mode = "workspace-write"',
          `[projects.${JSON.stringify(workspace)}]`, 'trust_level = "trusted"',
          "[sandbox_workspace_write]", "exclude_slash_tmp = true",
          "[features]", "plugins = false",
          "",
        ].join("\n"));
        const env = { ...launcherEnv(shim.origin, 0), HOME: home, CODEX_HOME: codexHome, OPENAI_API_KEY: "sk-mdu-dummy" };
        const r = await runLauncher(
          ["--no-scope", "--no-mcp", "--no-reply-filter", "--", codexBin, "exec", "--skip-git-repo-check", `${MARKER}: run them`],
          env, workspace, 240_000,
        );
        res.out = r.out;
        res.code = r.code;
        try {
          for (const d of readdirSync(join(tmp, "mandu"))) {
            const p = join(tmp, "mandu", d, "openai-proxy.log");
            if (existsSync(p)) res.proxyLog += readFileSync(p, "utf8").split("\n").slice(-60).join("\n");
          }
        } catch { /* no log */ }
        res.records = bindingRecords(join(tmp, "symbols.sqlite"));
        res.cleanMs = callMs(join(tmp, "symbols.sqlite"), CLEAN_CALL);
        res.requests = fake.requests.map((q) => q.body);
        for (const q of fake.requests) {
          res.read = functionCallOutputSpan(q.body, READ_CALL) ?? res.read;
          res.clean = functionCallOutputSpan(q.body, CLEAN_CALL) ?? res.clean;
        }
      } finally {
        await shim.close();
        await fake.close();
      }
    }, { mode: "secrets", policyPath: join(policyDir, "policy.yaml") });
  } finally {
    rmSync(policyDir, { recursive: true, force: true });
  }
  return res;
}

/** The arbiter's call-binding records of the run (plan 13 D7: the guard's
 *  candidate roots and execs, the proxy's calls, the bindings, the holders),
 *  read from its store while it still runs, so a failed binding says why
 *  (2026-10-09: the clean call masked at the session's level on GitLab
 *  pipelines 9916 and 9940, with only the launch output to read). */
function bindingRecords(db: string): string {
  const tables: Array<[string, string]> = [
    ["call_pending", "call_id, created_at"], ["call_commands", "call_id, source, signature, created_at"],
    ["call_asked", "call_id, created_at"], ["call_answered", "*"], ["call_bindings", "call_id, proc_key, kind, created_at"],
    ["call_roots", "call_id, proc_key, created_at"], ["call_root_candidates", "proc_key, signature, created_at"],
    ["orphan_roots", "*"], ["exec_roots", "*"], ["process_secret_taint", "*"], ["process_flows", "*"], ["agent_flows", "*"],
    ["process_lineage", "*"], ["exec_argv", "proc_key, substr(argv, 1, 240) AS argv, created_at"],
  ];
  let d: InstanceType<typeof DatabaseSync> | null = null;
  try {
    d = new DatabaseSync(db, { readOnly: true });
    return tables.map(([t, cols]) => {
      try {
        const rows = d!.prepare(`SELECT ${cols} FROM ${t} ORDER BY rowid`).all();
        return `[${t}] ${rows.length} row(s)\n${rows.map((r) => `  ${JSON.stringify(r)}`).join("\n")}`;
      } catch (e) { return `[${t}] (${(e as Error).message})`; }
    }).join("\n");
  } catch (e) {
    return `(no store at ${db}: ${(e as Error).message})`;
  } finally {
    d?.close();
  }
}

/** How long call `id` took as the arbiter saw it: from the proxy's gate of
 *  it (`call_pending`) to the proxy's first ask for its result
 *  (`call_asked`), in ms; null when either is missing. */
function callMs(db: string, id: string): number | null {
  let d: InstanceType<typeof DatabaseSync> | null = null;
  try {
    d = new DatabaseSync(db, { readOnly: true });
    const row = d.prepare("SELECT p.created_at AS p, a.created_at AS a FROM call_pending p JOIN call_asked a ON a.call_id = p.call_id WHERE p.call_id = ?").get(id) as { p: number; a: number } | undefined;
    return row ? Math.round(row.a - row.p) : null;
  } catch {
    return null;
  } finally {
    d?.close();
  }
}

const diagOf = (r: Run): string =>
  `\n--- the arbiter's call-binding records ---\n${r.records}\n--- read call ---\n${r.read}\n--- clean call ---\n${r.clean}\n--- launch output (tail) ---\n${r.out.slice(-5000)}\n--- openai-proxy log (tail) ---\n${r.proxyLog}`.split(CANARY).join("<CANARY>").split(FILE_B64).join("<FILE_B64>");
/** Codex's sandbox could not start nested in Mandu's: the reading call's own
 *  result, as the model got it, is bubblewrap's refusal (`bwrap: …`, Codex
 *  hands a command's failure to the model), unmasked and without the
 *  reader's output. Positive evidence only. A run with no result for the
 *  call (the session broke), a masked one or the reader's output is no
 *  skip but a failure: the check this replaces matched `bwrap` anywhere in
 *  the launch output, whose banner always names it, and took a lost model
 *  connection for this skip (job 15323 of pipeline 9918, 2026-10-09). */
function nestedBarred(read: string | null): boolean {
  return read !== null && /^bwrap: /m.test(read) && !read.includes("$MDU:") && !read.includes(FILE_B64.slice(0, 16));
}

test("the nested-sandbox skip needs bubblewrap's refusal in the reading call's own result", () => {
  const refused = "Chunk ID: 1\nWall time: 0 seconds\nProcess exited with code 1\nOutput:\nbwrap: loopback: Failed to create NETLINK_ROUTE socket: Operation not permitted\n";
  assert.equal(nestedBarred(refused), true, "Codex's sandbox refused: skip with the reason");
  assert.equal(nestedBarred(null), false, "no result for the call: the session broke (the model connection lost after the read), a failure");
  assert.equal(nestedBarred("Output:\n$MDU:nomodel_exec_command[802d]\n\n[mandu:secret] masked: python3.12 read secret.txt"), false, "a masked result: the reader ran");
  assert.equal(nestedBarred(`Output:\n${FILE_B64}\nbwrap: x\n`), false, "the reader's output: it ran");
  assert.equal(nestedBarred("Output:\nclean-42\n"), false);
  assert.equal(nestedBarred("Output:\nmandu: bwrap on this host follows symlinks (bwrap 0.9.0)\n"), false, "a mention of bwrap is no refusal");
});

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

/** The clean call's fork-exec wait bound (see `assertRun`'s timing note). */
const CLEAN_MS = 1900;

/**
 * One leg: the run, then every assertion (`label` names the leg). The
 * clean call's speed is the one wall-clock check: a sweep that took its
 * tree for a holder's waited the whole 2 s FORK_EXEC_WAIT on every run (the
 * decision itself is net-supervisor's `not_yet_execd` unit test), while a
 * loaded host slows one run now and then (3.5 s once in 106 CI runs,
 * 2026-10-18). So a slow clean call runs the leg once more, every
 * assertion again, and fails only when that run is slow too.
 */
async function leg(t: { skip: (m: string) => void }, codexBin: string, label: string): Promise<void> {
  const r = await run(codexBin);
  if (nestedBarred(r.read)) {
    console.error(`codex-sandbox-call-binding: skipped; requests: ${r.requests.length}${diagOf(r)}`);
    t.skip(`Codex's sandbox cannot start nested in Mandu's on this host: ${r.out.slice(-600)}`);
    return;
  }
  assertRun(r);
  if (r.cleanMs !== null && r.cleanMs < CLEAN_MS) {
    console.error(`codex-sandbox-call-binding (${label}): the reader's call masked by its tree, the clean call raw`);
    return;
  }
  console.error(`codex-sandbox-call-binding (${label}): the clean call took ${r.cleanMs} ms; once more, to tell the wait from load`);
  const again = await run(codexBin);
  assertRun(again);
  assert.ok(again.cleanMs !== null && again.cleanMs < CLEAN_MS,
    `the clean call took ${r.cleanMs} ms, then ${again.cleanMs} ms, gate to result (the 2 s fork-exec wait signature is 2.2 s)${diagOf(again)}`);
  console.error(`codex-sandbox-call-binding (${label}): the reader's call masked by its tree, the clean call raw (${again.cleanMs} ms the second time)`);
}

/** Every assertion of one run but the clean call's speed. */
function assertRun(r: Run): void {
  const diag = diagOf(r);
  assert.equal(r.code, 0, `the launch failed${diag}`);
  assert.ok(/net-guard LIVE/.test(r.out), `the guard engaged${diag}`);
  // THE ORACLE first: no byte of the secret, raw or base64, in any model request.
  for (const body of r.requests) {
    assert.ok(!body.includes(CANARY), `CONFIDENTIALITY VIOLATION: the secret reached the model${diag}`);
    assert.ok(!body.includes(FILE_B64.slice(0, 16)), `CONFIDENTIALITY VIOLATION: the reader's output reached the model${diag}`);
  }
  // (1) the reading call: masked, by its own tree (the reader in it)
  assert.ok(r.read !== null, `the follow-up carries the reading call's result${diag}`);
  assert.match(r.read!, /\$MDU:nomodel_/, `the reading call's result is masked${diag}`);
  // (2) the clean call: bound to its own helper, clean, forwarded as it is
  assert.ok(r.clean !== null, `the follow-up carries the clean call's result${diag}`);
  assert.ok(r.clean!.includes("clean-42"), `utility: the clean call reaches the model as it is (before: masked at the session's level)${diag}`);
  assert.ok(!r.clean!.includes("$MDU:"), `the clean call is not masked${diag}`);
  assert.ok(!/plan 13 D7: Mandu could not tie/.test(r.requests.join("\n")), `no call was left untied${diag}`);
  // 2026-10-09 (plan 13 §4.5.1): the clean call runs at its own speed. When
  // a sweep took its tree for a holder's, the guard waited the whole 2 s
  // FORK_EXEC_WAIT on Codex's helper (the agent's image, exec'd long ago):
  // every failing run's clean call took about 2.2 s. Timed by the arbiter
  // (the proxy's gate of the call to its first ask for the result; Codex's
  // own `succeeded in` line is not always printed) and checked by `leg`.
}

test(
  "D7 LIVE, Codex under its own sandbox, launched as `codex` on PATH (npm's wrapper script in CI): each call binds to its own helper; the reader's call is masked by its tree, the clean call after it reaches the model as it is",
  { skip: GATE, timeout: 300_000 },
  async (t) => { await leg(t, CODEX!, "codex on PATH"); },
);

// 2026-10-09: npm's wrapper used to leave the native Codex no agent (the
// guard's agent set was fixed before the script had started it), so the
// reader's raw read made Codex a holder and the session broke. The second
// leg launches the native binary the wrapper runs, directly.
test(
  "D7 LIVE, the same with the native binary npm's wrapper runs, launched directly",
  { skip: GATE || (NATIVE === null ? "`codex` on PATH is no npm wrapper (the first leg already ran the binary)" : false), timeout: 300_000 },
  async (t) => { await leg(t, NATIVE!, "npm's native binary"); },
);
