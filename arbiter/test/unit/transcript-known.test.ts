/**
 * transcript-known.test — where `mandu scan`'s known values come from
 * (arbiter/policy/transcript-known.ts;
 * docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md
 * §3 item 5), found by a hand check of the scan on 2026-10-22, where a
 * GitHub CLI token and a GitLab CLI token that reached the model were
 * reported by their shape, not as the person's own:
 *
 * - the extractor's values of the GitHub CLI's `hosts.yml` in both layouts
 *   (gh 2.x with `users:`, the older flat one) and of a two-host glab
 *   `config.yml` written the way glab writes it (comments, a template host
 *   with an empty token, a quoted `use_keyring`, a proxy URL with a
 *   password), each a credential to the scan;
 * - `knownIsCredential` by the detector's stand-in test: a live key whose
 *   random body holds `xxxx` counts, a person's stand-in still does not;
 * - a systemd user unit's `Environment=` values, a URL password in its
 *   `ExecStart=`, the `EnvironmentFile=` it names, and that file's values;
 * - the file list over a temp home: the walk's files, every catalog store
 *   and agent login read by its own place when the walk listed nothing
 *   (its caps), a store folder's cap, an agent's store never walked, a
 *   transcript never read, a `public` verdict honoured; and the values
 *   with their places;
 * - the scanner: a known value counted in every session that carried it.
 *
 * Every credential below is built by concatenation and fake.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extractSecretSpans } from "../../policy/secret-extract.js";
import {
  envFileValues, knownSecretsOf, STORE_MAX_FILES, storeFiles, systemdUnitFiles, systemdUnitValues, transcriptKnownFiles,
} from "../../policy/transcript-known.js";
import { knownIsCredential, TranscriptScanner } from "../../policy/transcript-scan.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

const GHO = `${"gh" + "o_"}Qm7Lz2Xw4Rt9Yv6Nb1Cs5Hf0Gp2Ae7WqK3Jd`;
const GHO_USER = `${"gh" + "o_"}Zt5Kp8Lm2Xw4Rt9Yv6Nb1Cs5Hf0Gp2Ae7Wq`;
const GHO_ENT = `${"gh" + "o_"}Yv6Nb1Cs5Hf0Gp2Ae7WqK3JdQm7Lz2Xw4Rt9`;
const GL_COM = `${"gl" + "pat-"}Ab3Cd4Ef5Gh6Ij7Kl8Mn`;
const GL_CORP = `${"gl" + "pat-"}Zy9Xw8Vu7Ts6Rq5Po4Nm`;
const PROXY_PW = `Pr0xy${"Pass"}-77qz`;
const UNIT_PW = `Un1t${"Pass"}-42kq`;
const ENVFILE_PW = `Env${"File"}-9Rt2Lm`;

/** gh 2.x: per-host, the active user's token at the host and under `users:`. */
const GH_HOSTS_V2 = [
  "github.com:",
  "    users:",
  "        alice:",
  `            oauth_token: ${GHO_USER}`,
  "    git_protocol: https",
  "    user: alice",
  `    oauth_token: ${GHO_USER}`,
  "ghe.corp.example:",
  "    users:",
  "        alice-corp:",
  `            oauth_token: ${GHO_ENT}`,
  "    git_protocol: ssh",
  "    user: alice-corp",
  `    oauth_token: ${GHO_ENT}`,
  "",
].join("\n");

/** The layout before gh 2.40: a host, its token, its user. */
const GH_HOSTS_FLAT = ["github.com:", `    oauth_token: ${GHO}`, "    user: alice", "    git_protocol: https", ""].join("\n");

/** glab's config as glab writes it: comments over each key, the default
 *  host's template with an empty token, a second host with its own. */
const GLAB_CONFIG = [
  "# What protocol to use when performing Git operations. Supported values: ssh, https.",
  "git_protocol: ssh",
  "# What editor glab should run when creating issues, merge requests, etc.",
  "editor:",
  "# Set your desired Markdown renderer style. Available options are [dark, light, notty].",
  "glamour_style: dark",
  "# Default GitLab hostname to use.",
  "host: gitlab.com",
  "# Configuration specific for GitLab instances.",
  "hosts:",
  "    gitlab.com:",
  "        # What protocol to use to access the API endpoint. Supported values: http, https.",
  "        api_protocol: https",
  "        api_host: gitlab.com",
  "        # Your GitLab access token. To get one, read https://docs.gitlab.com/user/profile/personal_access_tokens/",
  `        token: ${GL_COM}`,
  "        # The proxy to use for this host.",
  `        proxy: http://alice:${PROXY_PW}@127.0.0.1:3128`,
  "        custom_headers: []",
  "    gitlab.corp.example:",
  '        use_keyring: "false"',
  `        token: ${GL_CORP}`,
  "        api_host: gitlab.corp.example",
  "        api_protocol: https",
  "        git_protocol: ssh",
  "        user: alice",
  "    gitlab.template.example:",
  "        token:",
  "        job_token:",
  "        user:",
  "",
].join("\n");

const valuesOf = (path: string, text: string): Map<string, string> =>
  new Map(extractSecretSpans(path, text).spans.map((s) => [s.key, s.value]));

test("gh hosts.yml, gh 2.x layout: every host's token, under users: too, each a credential", () => {
  const v = valuesOf("/home/u/.config/gh/hosts.yml", GH_HOSTS_V2);
  assert.equal(v.get("github.com.users.alice.oauth_token"), GHO_USER);
  assert.equal(v.get("github.com.oauth_token"), GHO_USER);
  assert.equal(v.get("ghe.corp.example.users.alice-corp.oauth_token"), GHO_ENT);
  assert.equal(v.get("ghe.corp.example.oauth_token"), GHO_ENT);
  for (const [name, value] of v) assert.equal(knownIsCredential({ value, path: "~/.config/gh/hosts.yml", name }), true, name);
});

test("gh hosts.yml, the flat layout before gh 2.40: the host's token", () => {
  const v = valuesOf("/home/u/.config/gh/hosts.yml", GH_HOSTS_FLAT);
  assert.deepEqual([...v], [["github.com.oauth_token", GHO]]);
  assert.equal(knownIsCredential({ value: GHO, path: "~/.config/gh/hosts.yml", name: "github.com.oauth_token" }), true);
});

test("glab config.yml: each host's token and a proxy URL's password, as glab writes the file", () => {
  const v = valuesOf("/home/u/.config/glab-cli/config.yml", GLAB_CONFIG);
  assert.equal(v.get("hosts.gitlab.com.token"), GL_COM);
  assert.equal(v.get("hosts.gitlab.corp.example.token"), GL_CORP);
  assert.equal(v.get("hosts.gitlab.com.proxy.password"), PROXY_PW);
  assert.ok(![...v.values()].includes(""), "a template's empty token is no value");
  for (const name of ["hosts.gitlab.com.token", "hosts.gitlab.corp.example.token", "hosts.gitlab.com.proxy.password"]) {
    assert.equal(knownIsCredential({ value: v.get(name)!, path: "~/.config/glab-cli/config.yml", name }), true, name);
  }
});

test("knownIsCredential: a live key whose random body holds xxxx or dummy counts; a stand-in still does not", () => {
  const xxxx = `${"gl" + "pat-"}Ab3Kd9xxxxQm7Lz2Wq5R`;
  const dummy = `${"gh" + "o_"}Qm7Lz2Xw4Rt9dummyYv6Nb1Cs5Hf0Gp2Ae7W`;
  assert.equal(knownIsCredential({ value: xxxx, path: "~/.config/glab-cli/config.yml", name: "hosts.gitlab.com.token" }), true);
  assert.equal(knownIsCredential({ value: dummy, path: "~/.config/gh/hosts.yml", name: "github.com.oauth_token" }), true);
  for (const stand of ["changeme-please", "xxxx-xxxx-xxxx", "<your-token-here>", "${GITLAB_TOKEN}", "my-dummy-token", "your_api_key_here"]) {
    assert.equal(knownIsCredential({ value: stand, path: "~/.env", name: "API_TOKEN" }), false, stand);
  }
});

const UNIT = [
  "[Unit]",
  "Description=a local service",
  "# Environment=OLD_TOKEN=not-read-in-a-comment-1234",
  "[Service]",
  `Environment=HTTPS_PROXY=http://alice:${PROXY_PW}@127.0.0.1:3128 "NO_PROXY=localhost,127.0.0.1"`,
  `Environment="SERVICE_API_TOKEN=${GL_CORP}" PORT=8080`,
  "Environment=LOG_LEVEL=debug",
  `ExecStart=/usr/bin/relay --upstream https://relay:${UNIT_PW}@relay.corp.example/v1 --port 8080`,
  "EnvironmentFile=-%h/.config/relay/relay.env",
  "EnvironmentFile=/etc/relay/outside.env",
  "",
].join("\n");

test("systemdUnitValues: Environment= credentials, a URL password elsewhere, the EnvironmentFile= paths; no comment", () => {
  const u = systemdUnitValues(UNIT, "/home/u");
  const by = new Map(u.values.map((v) => [v.value, v.name]));
  assert.equal(by.get(PROXY_PW), "HTTPS_PROXY.password");
  assert.equal(by.get(GL_CORP), "SERVICE_API_TOKEN");
  assert.equal(by.get(UNIT_PW), "url.password");
  assert.ok(![...by.keys()].some((v) => v.includes("not-read") || v === "8080" || v === "debug" || v.startsWith("localhost")));
  assert.deepEqual(u.environmentFiles, ["/home/u/.config/relay/relay.env", "/etc/relay/outside.env"]);
  for (const v of u.values.filter((x) => x.value !== GL_CORP || x.name === "SERVICE_API_TOKEN")) {
    assert.equal(knownIsCredential({ value: v.value, path: "~/.config/systemd/user/relay.service", name: v.name }), true, v.name);
  }
});

test("envFileValues: NAME=value lines, export and quotes, comments skipped", () => {
  const v = envFileValues(`# relay\nexport RELAY_PASSWORD="${ENVFILE_PW}"\nRELAY_PORT=8080\n; DB_PASSWORD=not-this-one-9x\n`);
  assert.deepEqual(v, [{ name: "RELAY_PASSWORD", value: ENVFILE_PW }]);
});

/** A temp home holding the stores this suite reads. */
function fixtureHome(): string {
  const home = mkdtempSync(join(tmpdir(), "mdu-tk-"));
  mkdirSync(join(home, ".config", "gh"), { recursive: true });
  writeFileSync(join(home, ".config", "gh", "hosts.yml"), GH_HOSTS_V2);
  mkdirSync(join(home, ".config", "glab-cli"), { recursive: true });
  writeFileSync(join(home, ".config", "glab-cli", "config.yml"), GLAB_CONFIG);
  mkdirSync(join(home, ".config", "systemd", "user", "default.target.wants"), { recursive: true });
  writeFileSync(join(home, ".config", "systemd", "user", "relay.service"), UNIT);
  symlinkSync(join(home, ".config", "systemd", "user", "relay.service"), join(home, ".config", "systemd", "user", "default.target.wants", "relay.service"));
  writeFileSync(join(home, ".config", "systemd", "user", "notes.txt"), `TOKEN=${GHO}\n`);
  mkdirSync(join(home, ".config", "relay"), { recursive: true });
  writeFileSync(join(home, ".config", "relay", "relay.env"), `RELAY_PASSWORD=${ENVFILE_PW}\n`);
  mkdirSync(join(home, ".claude", "projects", "-p"), { recursive: true });
  writeFileSync(join(home, ".claude", ".credentials.json"), JSON.stringify({ claudeAiOauth: { accessToken: `${"sk-ant-" + "oat01-"}Qm7Lz2Xw4Rt9Yv6Nb1Cs5Hf0Gp2Ae7WqK3Jd` } }));
  writeFileSync(join(home, ".claude", "projects", "-p", "s1.jsonl"), `{"token":"${GHO}"}\n`);
  return home;
}

test("transcriptKnownFiles: the stores by their places when the walk listed none; units; never an agent's store or a transcript", () => {
  const home = fixtureHome();
  try {
    const files = transcriptKnownFiles({ home, discovered: [], isSecretPath: () => true, isTranscript: (p) => p.endsWith(".jsonl") });
    const at = new Map(files.map((f) => [f.path.slice(home.length), f.kind]));
    assert.equal(at.get("/.config/gh/hosts.yml"), "extract");
    assert.equal(at.get("/.config/glab-cli/config.yml"), "extract");
    assert.equal(at.get("/.claude/.credentials.json"), "extract", "an agent's login, whatever the walk's capped records kept");
    assert.equal(at.get("/.config/systemd/user/relay.service"), "unit");
    assert.equal([...at.keys()].filter((p) => p.endsWith("relay.service")).length, 1, "a .wants link is the unit itself");
    assert.ok(!at.has("/.config/systemd/user/notes.txt"), "not a unit");
    assert.ok(![...at.keys()].some((p) => p.startsWith("/.claude/projects")), "an agent's store is not walked");

    // The walk's own files come first and keep their place; a `public`
    // verdict (a label of the person's) keeps a store's file out.
    const walked = join(home, "proj.env");
    const f2 = transcriptKnownFiles({ home, discovered: [walked], isSecretPath: (p) => !p.endsWith("/glab-cli/config.yml"), isTranscript: () => false });
    assert.deepEqual(f2[0], { path: walked, kind: "extract", walked: true });
    assert.ok(!f2.some((f) => f.path.endsWith("/glab-cli/config.yml")), "a file the labels call public is not read");
    assert.ok(f2.some((f) => f.path.endsWith("/gh/hosts.yml")));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("knownSecretsOf: every token of both CLIs, the unit's and its EnvironmentFile's under the home, with their places", () => {
  const home = fixtureHome();
  try {
    const isTranscript = (p: string): boolean => p.endsWith(".jsonl");
    const known = knownSecretsOf(transcriptKnownFiles({ home, discovered: [], isSecretPath: () => true, isTranscript }), { home, isTranscript });
    const where = (v: string): string[] => known.filter((k) => k.value === v).map((k) => `${k.name} in ${k.path}`);
    assert.deepEqual(where(GHO_USER), ["github.com.users.alice.oauth_token in ~/.config/gh/hosts.yml", "github.com.oauth_token in ~/.config/gh/hosts.yml"]);
    assert.ok(where(GHO_ENT).includes("ghe.corp.example.oauth_token in ~/.config/gh/hosts.yml"));
    assert.deepEqual(where(GL_COM), ["hosts.gitlab.com.token in ~/.config/glab-cli/config.yml"]);
    assert.ok(where(GL_CORP).includes("hosts.gitlab.corp.example.token in ~/.config/glab-cli/config.yml"));
    assert.ok(where(GL_CORP).includes("SERVICE_API_TOKEN in ~/.config/systemd/user/relay.service"));
    assert.ok(where(PROXY_PW).includes("HTTPS_PROXY.password in ~/.config/systemd/user/relay.service"));
    assert.deepEqual(where(ENVFILE_PW), ["RELAY_PASSWORD in ~/.config/relay/relay.env"]);
    assert.ok(!known.some((k) => k.path.includes("/.claude/projects")), "a transcript's values are what is looked at");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("knownSecretsOf: the walk's own files do not use up the budget of the stores read by their places (step 0, 2026-10-22)", () => {
  const home = fixtureHome();
  try {
    const isTranscript = (p: string): boolean => p.endsWith(".jsonl");
    // A walk that listed more bytes than the budget, ahead of the stores.
    const big = join(home, "walked.env");
    writeFileSync(big, `NOTES=${"n".repeat(4000)}\n`);
    const files = transcriptKnownFiles({ home, discovered: [big], isSecretPath: () => true, isTranscript });
    assert.equal(files[0]!.path, big, "the walk's files come first");
    const known = knownSecretsOf(files, { home, isTranscript, maxTotalBytes: 3000 });
    assert.ok(known.some((k) => k.value === GHO_USER), "gh's token is read after a walk larger than the budget");
    assert.ok(known.some((k) => k.value === GL_CORP), "glab's too");
    // The budget still bounds the stores themselves.
    const none = knownSecretsOf(files, { home, isTranscript, maxTotalBytes: 1 });
    assert.ok(!none.some((k) => k.value === GHO_USER), "a store past the budget is not read");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("storeFiles: shallowest first, at most STORE_MAX_FILES, never into an agent's store", () => {
  const home = mkdtempSync(join(tmpdir(), "mdu-tk-"));
  try {
    const kube = join(home, ".kube");
    mkdirSync(join(kube, "cache", "discovery", "x"), { recursive: true });
    writeFileSync(join(kube, "config"), "apiVersion: v1\n");
    for (let i = 0; i < STORE_MAX_FILES + 20; i++) writeFileSync(join(kube, "cache", "discovery", "x", `f${String(i).padStart(3, "0")}.json`), "{}");
    const got = storeFiles(kube, home);
    assert.equal(got[0], join(kube, "config"), "the store's top file first");
    assert.equal(got.length, STORE_MAX_FILES);
    mkdirSync(join(home, ".claude", "projects"), { recursive: true });
    writeFileSync(join(home, ".claude", "projects", "s.jsonl"), "{}");
    assert.deepEqual(storeFiles(join(home, ".claude"), home).filter((p) => p.includes("projects")), []);
    assert.deepEqual(systemdUnitFiles(join(home, "none")), []);
    // A store folder kept elsewhere and linked (dotfiles): read through the link.
    mkdirSync(join(home, "dotfiles", "gh"), { recursive: true });
    writeFileSync(join(home, "dotfiles", "gh", "hosts.yml"), GH_HOSTS_FLAT);
    mkdirSync(join(home, ".config"), { recursive: true });
    symlinkSync(join(home, "dotfiles", "gh"), join(home, ".config", "gh"));
    assert.deepEqual(storeFiles(join(home, ".config", "gh"), home), [join(home, ".config", "gh", "hosts.yml")]);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("scanner: a known value is counted in every session that carried it, however each carried it", () => {
  const s = new TranscriptScanner({ home: "/home/u", known: [{ value: GL_CORP, path: "~/.config/glab-cli/config.yml", name: "hosts.gitlab.corp.example.token" }] });
  s.addSession("claude-code", "/p/s1.jsonl", [{ how: "command-output", tool: "Bash", text: `hosts:\n    gitlab.corp.example:\n        token: ${GL_CORP}\n` }]);
  s.addSession("claude-code", "/p/s2.jsonl", [{ how: "read-file", tool: "Read", text: `   125→        token: ${GL_CORP}` }]);
  s.addSession("claude-code", "/p/s3.jsonl", [{ how: "ai-wrote", tool: "Bash", text: `GITLAB_TOKEN=${GL_CORP} glab mr list` }]);
  s.addSession("codex", "/c/r1.jsonl", [{ how: "command-output", text: `git remote -v\norigin https://oauth2:${GL_CORP}@gitlab.corp.example/x.git (fetch)` }]);
  const r = s.result();
  const known = r.findings.filter((f) => f.kind === "known");
  assert.equal(known.length, 1);
  assert.equal(known[0]!.sessions, 4);
  assert.deepEqual(known[0]!.how, { "command-output": 2, "read-file": 1, "ai-wrote": 1 });
  assert.deepEqual(r.findings.filter((f) => f.kind !== "known").map((f) => f.kind), [], "never again by its shape");
});
