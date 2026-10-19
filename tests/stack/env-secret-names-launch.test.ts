/**
 * env-secret-names-launch e2e (plan 10 §11.4, 2026-10-09) — the secret
 * environment variables a launch used to hand the agent raw, through the REAL
 * launcher (`main()`, in process, a `--target shell` launch in `secrets` mode)
 * against a real ArbiterServer.
 *
 * Before the fix PGPASSWORD (libpq), MYSQL_PWD, GITHUB_PAT, Terraform's
 * TF_TOKEN_<host> and a Slack webhook URL reached the agent's programs as
 * they were (the name list wanted `_PASSWORD` and had no `_PWD`, `_PAT`,
 * `TF_TOKEN_` or webhook rule), and so did a GitHub token under a name no
 * shape matches. Now the shell the launch runs sees a placeholder for each,
 * the arbiter holds each original behind its placeholder, and the everyday
 * variables beside them (PGHOST, a passwordless Sentry DSN, OLDPWD) stay as
 * they are.
 *
 * 2026-10-10 (review follow-up): a webhook under a name with no `_URL`
 * (SLACK_WEBHOOK), a private key inside a JSON string's `\n` escapes (a
 * service-account key in GCP_SA_KEY) and a key inside a one-line value over
 * the detector's 10,000-character line (APP_CONFIG_JSON) reached the agent
 * raw too; and a `*_PWD` holding a directory (HOST_PWD, CALLER_PWD) stays
 * raw, as a script that cd's there needs.
 *
 * Fake values only, built at run time (no token-shaped literal in the file).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crc32 } from "node:zlib";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { humanSockIn } from "../lib/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the product default: the env mask is the confidentiality axis's

/** A GitHub classic token whose checksum holds (GitHub's CRC-32 in base62). */
function githubClassic(random30: string): string {
  const b62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  let n = crc32(random30);
  let sum = "";
  for (let i = 0; i < 6; i++) { sum = b62[n % 62]! + sum; n = Math.floor(n / 62); }
  return "gh" + "p_" + random30 + sum;
}

const SECRETS: Record<string, string> = {
  PGPASSWORD: "fakePgPw_Q7x91_envnames",
  MYSQL_PWD: "fakeMyPw_R2k44_envnames",
  GITHUB_PAT: "fake-pat-envnames-5521",
  TF_TOKEN_app_terraform_io: "fake.atlasv1.envnames-7730",
  SLACK_WEBHOOK_URL: "https://hooks." + "slack.com/services/T0FAKE000/B0FAKE000/envnamesFakeHook4417",
  // A name no shape matches, holding a key in GitHub's format.
  BUILD_HELPER_CONFIG: githubClassic("Fk3sQ9xZ7LmPq2RtW8vYbN4cJh6DgA"),
  SLACK_WEBHOOK: "https://hooks." + "slack.com/services/T0FAKE000/B0FAKE000/envnamesFakeHook5518",
  // A service-account key file's JSON: the key block sits in `\n` escapes.
  GCP_SA_KEY: JSON.stringify({
    type: "service_account", project_id: "envnames-demo",
    private_key: "-----BEGIN " + "PRIVATE KEY-----\n" + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCenvnamesFAKE0" +
      "\n" + "Qk7Lp3Xr9Tz2Vb8Nm4Jc6Hd1Gf5Sa0Wq7Ey3Ru9Ti2Yo8Up4Ia6Os1Pd5Fg3Hj7Kl\n-----END PRIVATE KEY-----\n",
    client_email: "svc@envnames-demo.iam.gserviceaccount.com",
  }),
  // One line over 10,000 characters with a key in it (a config blob).
  APP_CONFIG_JSON: JSON.stringify({
    banner: "lorem ipsum dolor ".repeat(700), helper: githubClassic("Zq8wE4rT6yU2iO0pA9sD7fG5hJ3kL1"), footer: "sit amet ".repeat(200),
  }),
};
const RAW: Record<string, string> = {
  PGHOST: "db.envnames.internal",
  PGUSER: "envnames_app",
  SENTRY_DSN: "https://0123456789abcdef0123456789abcdef@o0.ingest.sentry.io/42",
  OLDPWD: "/srv/envnames-previous",
  HOST_PWD: "/srv/envnames-host/project",
  CALLER_PWD: "/home/envnames/caller dir",
};

/** `NAME=value` lines of an `env` dump. */
function parseEnv(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of text.split("\n")) {
    const eq = line.indexOf("=");
    if (eq > 0) out.set(line.slice(0, eq), line.slice(eq + 1));
  }
  return out;
}

test("a shell launch hands PGPASSWORD, MYSQL_PWD, GITHUB_PAT, TF_TOKEN_<host>, webhooks, a JSON-escaped private key and keys in known formats (in a long one-line value too) to its programs only as placeholders", { timeout: 120_000 }, async () => {
  const long = SECRETS["APP_CONFIG_JSON"]!;
  assert.ok(long.length > 10_000 && !long.includes("\n"), "APP_CONFIG_JSON is one line over the detector's line limit");
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-envnames-")));
  const home = join(dir, "home");
  const ws = join(dir, "ws");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const sock = join(dir, "arbiter.sock");
  const humanSock = humanSockIn(dir);
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  const human = new ArbiterClient(humanSock);
  const lines: string[] = [];
  const orig = console.error;
  try {
    await data.connect();
    await human.connect();
    const out = join(dir, "child-env.txt");
    let code: number | undefined;
    let err: Error | undefined;
    // The launcher reads parts of its process's own environment too (the
    // Mandu home's caches, the home it walks): the rig's, never the runner's.
    const saved = { HOME: process.env["HOME"], MANDU_HOME: process.env["MANDU_HOME"] };
    process.env["HOME"] = home;
    process.env["MANDU_HOME"] = join(dir, "mandu-home");
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    try {
      code = await main(
        ["--target", "shell", "--no-scope", "--no-reply-filter", "--no-net-proxy", "--no-kernel", "--no-exec-box", "--no-exec-wrap",
          "--", "/bin/sh", "-c", `env > '${out}'`],
        {
          HOME: home, PWD: ws, PATH: process.env["PATH"], TMPDIR: dir, XDG_RUNTIME_DIR: dir, MANDU_RUNTIME_DIR: join(dir, "rt"),
          MANDU_HOME: join(dir, "mandu-home"), MANDU_ARBITER_SOCK: sock, MANDU_NO_CONTEXT_PROXY: "1", MANDU_MODE: "secrets",
          ...SECRETS, ...RAW,
        },
      );
    } catch (e) {
      err = e as Error;
    } finally {
      console.error = orig;
      for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
    const log = lines.join("\n");
    assert.equal(err, undefined, `${err?.message}\n${log}`);
    assert.equal(code, 0, log);
    assert.ok(existsSync(out), `the shell ran\n${log}`);
    const dump = readFileSync(out, "utf8");
    const env = parseEnv(dump);

    for (const [name, value] of Object.entries(SECRETS)) {
      const seen = env.get(name);
      assert.ok(seen !== undefined, `${name} reaches the shell\n${log}`);
      assert.match(seen!, new RegExp(`^\\$MDU:nomodel_Env\\[[0-9a-f]+\\]\\.${name}$`), `${name} is a placeholder in the agent's world`);
      assert.ok(!dump.includes(value), `${name}'s value is nowhere in the agent's environment`);
      // The arbiter holds the original behind it, as an environment secret.
      const prov = await data.symbolProvenance(seen!);
      assert.equal(prov.tool, "Env", `${name}: registered from the environment`);
      assert.equal(prov.field, name);
      assert.equal(await human.desymbolize(seen!), value, `${name}: the human plane resolves it to the original`);
    }
    for (const [name, value] of Object.entries(RAW)) assert.equal(env.get(name), value, `${name} stays as it is`);
    // The default banner counts them (packaging.md §5; the names go to the logs).
    const mode = lines.find((l) => l.startsWith("mandu: secrets mode · "));
    assert.match(mode ?? "", new RegExp(`(, | \\u00b7 )${Object.keys(SECRETS).length} env vars masked \\u00b7 `), log);
  } finally {
    console.error = orig;
    data.close();
    human.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
