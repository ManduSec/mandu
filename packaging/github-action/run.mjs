#!/usr/bin/env node
// @ts-check
/**
 * run — the Mandu GitHub Action's one step after the installs: check the
 * inputs and the checkout, write the run's policy, launch the agent under
 * `mandu`, then write the job summary from the run's own event log and stop
 * Mandu's services.
 *
 * Exit status: the agent's, when it failed; else 1 when a send was blocked
 * and `fail-on-blocked` is on; else 0. A refusal before the launch is 2.
 *
 * Every decision is in lib/ (pure, unit-tested); this file only runs things.
 * Design: docs/design/distribution/github-action.md. Mandu-new (no reference
 * origin).
 */
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { appendFileSync, createWriteStream, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { parseInputs } from "./lib/inputs.mjs";
import { assemblePolicy, policySource } from "./lib/policy.mjs";
import { blockedAnnotations, collectReport, renderSummary } from "./lib/summary.mjs";
import { launchArgv, launchEnv, runtimeDirProblem, runtimeDirTemplate, setupDecision, stepStatus } from "./lib/command.mjs";

const env = process.env;
const MANDU = "mandu";
const log = (/** @type {string} */ s) => process.stderr.write(`mandu-action: ${s}\n`);

/** Append `key=value` to a GitHub file command ($GITHUB_OUTPUT, …), if set. */
function fileCommand(name, key, value) {
  const f = env[name];
  if (f) appendFileSync(f, `${key}=${value}\n`);
}

function refuse(problems) {
  for (const p of problems) process.stdout.write(`::error title=Mandu::${p}\n`);
  if (env.GITHUB_STEP_SUMMARY) {
    appendFileSync(env.GITHUB_STEP_SUMMARY, `## Mandu: the run did not start\n\n${problems.map((p) => `- ${p.replace(/\n/g, " ")}`).join("\n")}\n`);
  }
  fileCommand("GITHUB_OUTPUT", "exit-code", "2");
  process.exit(2);
}

/** git in `cwd`, its stdout, or null. Never prints a value. */
function git(cwd, args) {
  const r = spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  return r.status === 0 ? r.stdout : null;
}

const root = resolve(env.GITHUB_WORKSPACE || process.cwd());
const { config, problems } = parseInputs(env, (p) => {
  try { return readFileSync(resolve(root, p), "utf8"); } catch { return null; }
});
if (problems.length) refuse(problems);
const workspace = resolve(root, config.workingDirectory);
if (!existsSync(workspace)) refuse([`working-directory: ${config.workingDirectory} does not exist`]);

// A checkout that left its token in the git config (actions/checkout's
// default) hands it to any program that reads the config, and from there
// to the model: Mandu does not know that file. Names only, never the value.
const persisted = (git(workspace, ["config", "--includes", "--name-only", "--get-regexp", "^http\\..*\\.extraheader$"]) ?? "").split("\n").filter(Boolean);
if (persisted.length && !config.allowPersistedCredentials) {
  refuse([
    `the checkout left a credential in the git config (${persisted.join(", ")}), where the agent's programs can read it and pass it to the model. ` +
      "Check out with `persist-credentials: false` (give the agent a token through the job's env and the `bindings` input instead), or set allow-persisted-credentials: true.",
  ]);
}

// The policy: the trusted text plus the action's own inputs.
const githubSha = env.GITHUB_SHA ?? "";
const headSha = (git(root, ["rev-parse", "HEAD"]) ?? "").trim() || null;
const source = policySource({
  inline: config.policyInline,
  file: config.policyFile,
  fileExplicit: config.policyFileExplicit,
  trustWorkspace: config.trustWorkspacePolicy,
  githubSha,
  headSha,
  readWorkspace: (rel) => { try { return readFileSync(resolve(root, rel), "utf8"); } catch { return null; } },
  readAtCommit: (sha, rel) => git(root, ["show", `${sha}:./${rel}`]),
});
if (!source.ok) refuse([source.problem]);
const policy = assemblePolicy(source.ok ? source.text : "", config.bindings, config.maskEnv);
if (!policy.ok) refuse([policy.problem]);

const base = mkdtempSync(join(env.RUNNER_TEMP || tmpdir(), "mandu-"));
const manduHome = join(base, "home");
mkdirSync(manduHome, { recursive: true, mode: 0o700 });
// The services' sockets: a short dir of the run's own (mkdtemp makes it
// 0700), whatever the length of $RUNNER_TEMP; removed at the end.
const runtimeDir = mkdtempSync(runtimeDirTemplate(env));
{
  const problem = runtimeDirProblem(runtimeDir);
  if (problem) { rmSync(runtimeDir, { recursive: true, force: true }); refuse([problem]); }
}
writeFileSync(join(manduHome, "policy.yaml"), policy.ok ? policy.text : "", { mode: 0o600 });
const runEnv = launchEnv(env, { manduHome, runtimeDir });
const policyFrom = source.ok ? source.from : "none";
log(`policy: ${policyFrom}${config.bindings.length ? `; bindings: ${config.bindings.map((b) => `${b.name} -> ${b.hosts.join(" ")}`).join(", ")}` : ""}`);

// `mandu setup`: Mandu's own bubblewrap (the bind layer; Codex's sandbox).
const sudo = process.platform === "linux" && spawnSync("sudo", ["-n", "true"], { stdio: "ignore" }).status === 0;
const setup = setupDecision(config.setup, { agent: config.agent, platform: process.platform, sudo });
if (setup.problem) { rmSync(runtimeDir, { recursive: true, force: true }); refuse([setup.problem]); }
if (setup.note) log(setup.note);
if (setup.run) {
  if (spawnSync("sh", ["-c", "command -v bwrap"], { stdio: "ignore" }).status !== 0) {
    log("installing bubblewrap (apt) for mandu setup");
    spawnSync("sudo", ["-n", "apt-get", "update", "-qq"], { stdio: ["ignore", "inherit", "inherit"] });
    spawnSync("sudo", ["-n", "apt-get", "install", "-y", "-qq", "bubblewrap"], { stdio: ["ignore", "inherit", "inherit"] });
  }
  const r = spawnSync(MANDU, ["setup", "--yes"], { env: runEnv, cwd: workspace, stdio: ["ignore", "inherit", "inherit"] });
  if (r.status !== 0) log(`mandu setup exited ${r.status}; the launch says which layer is missing`);
}

// The launch. The agent's stdout goes to the log (placeholders: the reply
// filter is off) and to result.txt. Its output can carry text from a pull
// request, so the runner reads no workflow command (`::…::`) in it.
const resultFile = join(base, "result.txt");
const argv = launchArgv(config);
log(`running: mandu ${argv.slice(0, argv.indexOf(config.agent) + (config.agent === "codex" ? 2 : 1)).join(" ")} …`);
const stopToken = `mandu-${randomBytes(16).toString("hex")}`;
process.stdout.write(`::stop-commands::${stopToken}\n`);
const exitCode = await new Promise((done) => {
  const child = spawn(MANDU, argv, { env: runEnv, cwd: workspace, stdio: ["ignore", "pipe", "inherit"] });
  const out = createWriteStream(resultFile, { mode: 0o600 });
  child.stdout.on("data", (d) => { process.stdout.write(d); out.write(d); });
  child.on("error", (e) => { log(`could not start mandu: ${e.message}`); out.end(); done(127); });
  child.on("close", (code, signal) => { out.end(); done(code ?? (signal ? 128 : 1)); });
});
process.stdout.write(`\n::${stopToken}::\n`);

// What the launch masked (names only): the doctor's dry run against the same
// workspace and environment, while the run's services still answer.
let doctor = null;
{
  const r = spawnSync(MANDU, ["doctor", "--secrets", "--json", "--no-history", "--target", config.agent], {
    env: runEnv, cwd: workspace, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 120_000, maxBuffer: 16 << 20,
  });
  try { doctor = JSON.parse(r.stdout ?? ""); } catch { log("mandu doctor gave no report; the summary lists the environment only"); }
}

// Stop this run's stack only (never another Mandu's on a self-hosted
// runner), and wait for its arbiter to exit: it appends its last events
// while it shuts down.
{
  const stack = runtimeDir;
  let arbiterPid = 0;
  try { arbiterPid = Number(JSON.parse(readFileSync(join(stack, "current", "manifest.json"), "utf8")).pid) || 0; } catch { /* no stack came up */ }
  spawnSync(MANDU, ["stop", "--all", "--stack", stack], { env: runEnv, cwd: workspace, stdio: "ignore", timeout: 60_000 });
  const alive = (/** @type {number} */ pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
  const until = Date.now() + 15_000;
  while (arbiterPid > 0 && alive(arbiterPid) && Date.now() < until) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
  try {
    // A twin store the guard made read-only would refuse the removal.
    spawnSync("chmod", ["-R", "u+rwx", runtimeDir], { stdio: "ignore" });
    rmSync(runtimeDir, { recursive: true, force: true });
  } catch (e) { log(`could not remove ${runtimeDir}: ${/** @type {Error} */ (e).message}`); }
}

// Every session's events of this run (its own MANDU_HOME), never the
// arbiter's admin stream.
const events = [];
const eventDir = join(manduHome, "events");
for (const f of existsSync(eventDir) ? readdirSync(eventDir) : []) {
  if (!f.endsWith(".ndjson") || f.startsWith("arbiter-admin")) continue;
  for (const line of readFileSync(join(eventDir, f), "utf8").split("\n")) {
    if (!line.trim()) continue;
    try { events.push(JSON.parse(line)); } catch { /* a torn line */ }
  }
}

const report = collectReport(events, doctor, { home: runEnv.HOME ?? homedir(), workspace });
writeFileSync(join(base, "report.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
for (const line of blockedAnnotations(report)) process.stdout.write(`${line}\n`);
log(`masked: ${report.envMasked.length} variable(s), ${report.files.length} file(s); sends: ${report.blocked.reduce((n, b) => n + b.count, 0)} blocked, ${report.sent.reduce((n, s) => n + s.count, 0)} sent to a bound host`);
if (config.summary && env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, renderSummary(report, { failOnBlocked: config.failOnBlocked, policyFrom }));

const blockedSends = report.blocked.reduce((n, b) => n + b.count, 0);
const status = stepStatus(exitCode, blockedSends, config.failOnBlocked);
fileCommand("GITHUB_OUTPUT", "exit-code", String(exitCode));
fileCommand("GITHUB_OUTPUT", "masked", String(report.envMasked.length + report.files.length));
fileCommand("GITHUB_OUTPUT", "blocked", String(blockedSends));
fileCommand("GITHUB_OUTPUT", "sent", String(report.sent.reduce((n, s) => n + s.count, 0)));
fileCommand("GITHUB_OUTPUT", "result-file", resultFile);
fileCommand("GITHUB_OUTPUT", "report-file", join(base, "report.json"));
if (exitCode === 0 && blockedSends > 0 && config.failOnBlocked) log("failing the step: a send was blocked (fail-on-blocked)");
process.exit(status);
