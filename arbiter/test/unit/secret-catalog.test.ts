import { test } from "node:test";
import assert from "node:assert/strict";
import {
  normalizedPrefixes,
  secretPathConfidentiality,
  findSecretPathsInText,
  confidentialityForOrigin,
  SOURCE_EXTS,
} from "../../policy/secret-catalog.js";
import { createEngineBackedPolicy } from "../../policy/policy-interface.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const HOME = "/home/u";

test("catalog prefixes classify no-model (fs-outbound reuse + keyrings)", () => {
  for (const p of [
    "~/.ssh/id_rsa", "/home/u/.ssh/config", "~/.aws/credentials",
    "~/.config/gcloud/foo.json", "/etc/shadow", "~/.claude.json",
    "~/.local/share/keyrings/login.keyring", "~/.password-store/x.gpg",
  ]) {
    const m = secretPathConfidentiality(p, HOME);
    assert.equal(m.level, "no-model", p);
    assert.notEqual(m.rule, null, p);
  }
});

test("basename shapes classify no-model anywhere they live", () => {
  for (const p of [
    "/work/app/.env", "/work/app/.env.production", "./credentials.json",
    "/repo/secrets.local.json", "/tmp/backup/id_ed25519", "/srv/svc.keytab",
  ]) {
    assert.equal(secretPathConfidentiality(p, HOME).level, "no-model", p);
  }
});

test("a CLI's login file in its own directory, and an HTTP client's private environment, are secrets (2026-10-19, secret-discovery.md §2.6)", () => {
  for (const [p, rule] of [
    ["/work/shop/.launchdeck/auth.json", "shape:tool-login-file"],          // a platform CLI's project login
    ["/home/u/.now/auth.json", "shape:tool-login-file"],                    // Vercel's old CLI
    ["/home/u/.gemini/oauth_creds.json", "shape:tool-login-file"],          // Gemini CLI, Qwen Code
    ["/home/u/.config/planetscale/access-token", "shape:tool-login-file"],  // a token file in ~/.config/<tool>
    ["/home/u/.config/cursor/auth.json", "shape:tool-login-file"],
    ["/work/x/.deploy/auth.yml", "shape:tool-login-file"],
    [".launchdeck/auth.json", "shape:tool-login-file"],                     // relative, as a command names it
    ["/work/api/http-client.private.env.json", "shape:*.private.env.json"], // JetBrains HTTP Client
    ["/work/api/rest.private.env.json", "shape:*.private.env.json"],
  ] as const) {
    assert.deepEqual(secretPathConfidentiality(p, HOME), { level: "no-model", bindings: [], rule }, p);
  }
  for (const p of [
    "/work/web/public/locales/en/auth.json",   // an app's strings: not in a tool's directory
    "/work/app/src/auth.json", "auth.json", "/work/app/auth.ts", "/work/x/.cache/tool/auth.json",
    "/work/api/http-client.env.json",          // the shared, committed environment
    "/work/x/../auth.json",
  ]) {
    assert.equal(secretPathConfidentiality(p, HOME).rule, null, p);
  }
  // the text scan reads them in a command
  assert.equal(confidentialityForOrigin("cat .launchdeck/auth.json", HOME).level, "no-model");
  assert.equal(confidentialityForOrigin("jq .staging api/http-client.private.env.json", HOME).level, "no-model");
});

test("the *credentials* shape skips documentation pages; every other spelling still matches", () => {
  for (const p of [
    "/src/linux/Documentation/security/credentials.rst", "/work/docs/credentials.md", "/work/docs/Credentials.MD",
    "/work/site/credentials.html", "/work/site/aws-credentials.htm", "/work/docs/credentials.markdown",
  ]) {
    const m = secretPathConfidentiality(p, HOME);
    assert.equal(m.level, "public", p);
    assert.equal(m.rule, null, p);
  }
  for (const p of [
    "/work/credentials", "/work/credentials.json", "/work/credentials.txt", "/work/Credentials.xml",
    "/work/credentials.md.bak", "/work/credentials.html.json", "/work/.terraform.d/credentials.tfrc.json",
  ]) {
    assert.equal(secretPathConfidentiality(p, HOME).rule, "shape:*credentials*", p);
  }
  // A catalog PREFIX still covers a doc-named file under it.
  assert.equal(secretPathConfidentiality("~/.aws/credentials.md", HOME).level, "no-model");
});

test("the *credentials* shape skips program source (2026-10-17): a module named after what it handles is no credential file; data, config and shell files still match", () => {
  for (const p of [
    "/work/src/auth/providers/credentials.ts", "/work/src/auth/credentials.tsx", "/work/src/credentials.test.ts",
    "/work/types/credentials.d.ts", "/work/lib/credentials.mjs", "/work/lib/credentials.cjs", "/work/lib/Credentials.JS",
    "/venv/lib/python3.12/site-packages/botocore/credentials.py", "/work/app/credentials.rb", "/work/pkg/auth/credentials.go",
    "/work/pkg/auth/credentials_test.go", "/work/src/credentials.rs", "/work/src/main/java/CredentialsProvider.java",
    "/work/app/Credentials.kt", "/work/ios/Credentials.swift", "/work/src/credentials.h", "/work/src/credentials.cpp",
    "/work/src/Credentials.cs", "/work/www/credentials.php", "/work/ui/Credentials.vue",
  ]) {
    const m = secretPathConfidentiality(p, HOME);
    assert.deepEqual([m.level, m.rule], ["public", null], p);
  }
  for (const p of [
    "/work/credentials", "/work/.credentials", "/work/credentials.json", "/work/credentials.yaml", "/work/credentials.yml",
    "/work/credentials.toml", "/work/credentials.ini", "/work/credentials.conf", "/work/credentials.env", "/work/credentials.txt",
    "/work/credentials.xml", "/work/credentials.properties", "/work/credentials.sh", "/work/credentials.bash",
    "/work/config/credentials.yml.enc", "/work/credentials.ts.bak", "/work/credentials.py.orig", "/work/credentials.csv",
  ]) {
    assert.equal(secretPathConfidentiality(p, HOME).rule, "shape:*credentials*", p);
  }
  // A catalog PREFIX still covers a source-named file under it.
  assert.equal(secretPathConfidentiality("~/.aws/credentials.py", HOME).level, "no-model");
  assert.equal(secretPathConfidentiality("~/.config/gcloud/credentials.ts", HOME).level, "no-model");
});

test("SOURCE_EXTS holds no data, configuration or shell extension, and no other basename shape matches a source-named file (the audit)", () => {
  const DATA = ["json", "yaml", "yml", "toml", "ini", "conf", "cfg", "env", "properties", "xml", "txt", "tfvars", "plist", "csv", "enc", "gpg", "age", "pem", "key", "sh", "bash", "zsh", "fish", "ps1", "bat", "cmd"];
  for (const x of DATA) assert.ok(!(SOURCE_EXTS as readonly string[]).includes(x), `.${x} holds data: never exempt`);
  // Every other shape keys on a data extension or an exact name: a source file
  // whatever its stem never matches one (secret.ts, client_secret.py, …).
  for (const stem of ["secret", "secrets", "client_secret", "service-account", "sa-key", "keyfile", "id_rsa", "privkey", "server-key", "token", "password", "terraform.tfstate", "prod.env", "app.keytab"]) {
    for (const x of SOURCE_EXTS) {
      const m = secretPathConfidentiality(`/work/src/${stem}.${x}`, HOME);
      assert.equal(m.rule, null, `${stem}.${x}: ${m.rule}`);
    }
  }
  // The one exception, kept on purpose: a dotfile `.env.<ext>` is an env
  // store whatever its extension (env-cmd reads `.env.js`, which exports the
  // variables), so `.env*` still matches it.
  for (const x of ["js", "ts", "mjs"]) assert.equal(secretPathConfidentiality(`/work/.env.${x}`, HOME).rule, "shape:.env*", `.env.${x}`);
});

test("templates and ordinary files are public", () => {
  for (const p of [
    "/work/app/.env.example", "/work/app/.env.template", "/work/app/.env.sample",
    "/repo/secrets.example.json", "/work/README.md", "~/notes/todo.txt",
    "/work/.envrc-doc.md",
  ]) {
    assert.equal(secretPathConfidentiality(p, HOME).level, "public", p);
  }
});

test("catalog matches carry empty bindings in Phase A", () => {
  assert.deepEqual(secretPathConfidentiality("~/.aws/credentials", HOME).bindings, []);
});

test("findSecretPathsInText: conservative scan of a Bash command", () => {
  const hits = findSecretPathsInText("cat ~/.aws/credentials | base64", HOME);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].level, "no-model");

  assert.equal(findSecretPathsInText("grep -r TODO src/ && npm test", HOME).length, 0);
  // quoted + relative shapes still hit
  assert.equal(findSecretPathsInText("head '.env.local'", HOME).length, 1);
});

// ── the engine-backed classify wrapper (Task 7) ──────────────────────────────

test("classify ON carries confidentiality derived from origin/params", () => {
  const policy = createEngineBackedPolicy({ confidentiality: true });

  const read = policy.classify({
    tool: "Read", value: "AKIA...", boundary: "model_context",
    origin: `${process.env.HOME}/.aws/credentials`,
  });
  assert.equal(read.confidentiality, "no-model");

  const bash = policy.classify({
    tool: "Bash", value: "SECRET=1", boundary: "model_context",
    origin: "cat .env",
  });
  assert.equal(bash.confidentiality, "no-model");

  const web = policy.classify({
    tool: "web_fetch", value: "page text", boundary: "model_context",
    origin: "https://example.com/docs/credentials",
  });
  assert.equal(web.confidentiality, "public");

  const params = policy.classify({
    tool: "Read", value: "x", boundary: "model_context",
    params: { file_path: "/work/app/.env" },
  });
  assert.equal(params.confidentiality, "no-model");

  // the trust axis is untouched by the wrapper
  assert.equal(typeof read.trust, "string");
});

test("classify OFF (inertness): result carries NO confidentiality field", () => {
  const policy = createEngineBackedPolicy({ confidentiality: false });
  const r = policy.classify({
    tool: "Read", value: "AKIA...", boundary: "model_context",
    origin: `${process.env.HOME}/.aws/credentials`,
  });
  assert.equal("confidentiality" in r, false);
});

test("confidentialityForOrigin: path origin, command origin, URL exemption", () => {
  assert.equal(confidentialityForOrigin("~/.ssh/id_rsa", HOME).level, "no-model");
  assert.equal(confidentialityForOrigin("cat .env", HOME).level, "no-model");
  // A remote URL is not a local secret path — never strict-label web content
  // (it would make the fetched page uninspectable by the U-LLM for nothing).
  assert.equal(
    confidentialityForOrigin("https://example.com/docs/credentials", HOME).level,
    "public",
  );
  assert.equal(confidentialityForOrigin(undefined, HOME).level, "public");
  assert.equal(confidentialityForOrigin(null, HOME).level, "public");
});

test("the prefix memo is keyed per HOME: two homes classify independently and exactly", () => {
  // A memo that ignored `home` would let the first caller's expansion leak
  // into the second (a `/home/u/.ssh` hit for `/home/v/...`, or vice versa).
  assert.equal(secretPathConfidentiality("/home/u/.ssh/id_rsa", "/home/u").rule, "prefix:~/.ssh");
  assert.equal(secretPathConfidentiality("/home/v/.ssh/id_rsa", "/home/v").rule, "prefix:~/.ssh");
  assert.equal(secretPathConfidentiality("/home/v/.ssh/config", "/home/u").rule, null, "the other home's ~/.ssh is not a prefix hit");
  assert.equal(secretPathConfidentiality("/home/u/.aws/credentials", "/home/v").rule, "shape:*credentials*", "falls through to the shape rule");
});

test("the per-home prefix memo: one normalized prefix list per home, reused for every path of a walk", () => {
  // The discovery walk calls secretPathConfidentiality once per entry of HOME
  // (140k entries at depth 4 on a developer host). Re-normalizing the catalog
  // prefixes per path cost 35 us a path, ~5 s of every launch, until the
  // per-home memo (f37de4c3). This pins the memo itself. A timing ratio used to
  // stand in for it (10x a plain string pass; the pre-memo shape ~17x, the memo
  // ~4.5x idle), but in the loaded CI guest an unchanged matcher measured 11x
  // in wall time, sequential or interleaved, and 11x in process CPU time even
  // idle (V8's GC helper threads count there), so no ratio told load from a
  // regression (continuous-integration.md §11, 2026-09-29).
  const a = normalizedPrefixes(HOME);
  assert.equal(normalizedPrefixes(HOME), a, "the same list object for the same home: computed once");
  for (let i = 0; i < 1000; i++) secretPathConfidentiality(`/home/u/project/repo${i % 50}/src/file${i}.ts`, HOME);
  assert.equal(normalizedPrefixes(HOME), a, "classifying paths reuses the home's list, never recomputes it");
  const other = normalizedPrefixes("/home/v");
  assert.notEqual(other, a, "keyed on the home string: another home gets its own list");
  assert.deepEqual([...a].sort(), [...normalizedPrefixes(HOME)].sort());
  assert.ok(a.every((p) => !p.includes("~")), "the list is normalized (no ~ left)");
});

test("plan 10 §11.13: the public material directly in ~/.ssh is not a catalog secret; the keys, config and anything else there are", () => {
  for (const p of [
    "~/.ssh/known_hosts", "~/.ssh/known_hosts2", "~/.ssh/known_hosts.old", "~/.ssh/authorized_keys",
    "~/.ssh/authorized_keys2", "~/.ssh/allowed_signers", "~/.ssh/id_ed25519.pub", "/home/u/.ssh/deploy.pub",
  ]) {
    assert.equal(secretPathConfidentiality(p, HOME).rule, null, p);
  }
  for (const p of [
    "~/.ssh/id_ed25519", "~/.ssh/deploy_prod", "~/.ssh/config", "~/.ssh/config.d/work", "~/.ssh/environment",
    "~/.ssh/rc", "~/.ssh/keys/known_hosts", "~/.ssh/known_hosts.d/x", "~/.ssh/id_rsa.pub.bak",
  ]) {
    assert.equal(secretPathConfidentiality(p, HOME).rule, "prefix:~/.ssh", p);
  }
  // Exempt only under the home's own ~/.ssh.
  assert.equal(secretPathConfidentiality("/home/v/.ssh/known_hosts", "/home/v").rule, null);
  assert.equal(confidentialityForOrigin("cat ~/.ssh/known_hosts ~/.ssh/id_rsa", HOME).rule, "prefix:~/.ssh", "a command naming a key still labels");
});
