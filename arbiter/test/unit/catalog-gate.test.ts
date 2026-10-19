/**
 * The guard's gate of a CATALOG file the launch did not register (2026-10-17,
 * confidentiality.md §6 "Read by a program the launch did not see",
 * secret-discovery.md §1.12): the prefilter the arbiter ships the guard
 * (`catalogNameAnchors`, `catalogGateRoots`) and the verdict it gives on one
 * file (`gateVerdict`, the `labelledLevel` op).
 *
 * Before, a `.env` or a key the walk did not reach (created mid-session,
 * deeper than MAX_DEPTH, past MAX_FILES, outside HOME and the workspace) was
 * opened raw by every program. The gate must apply the WALK's rule (no
 * content check: a `.env.example` stays raw), never miss a file the walk
 * would register (the prefilter is a superset), and keep the walk's prunes
 * (an agent's own files, Mandu's state, `node_modules`, package caches).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { CREDENTIAL_CORPUS } from "../fixtures/credential-corpus.js";
import { catalogNameAnchors, nameAnchorAdmits, unanchoredShapes, type LabelLookup } from "../../policy/secret-catalog.js";
import { CATALOG_GATE_SKIP_DIRS, catalogGateRoots, discoverSecretsReport, gateVerdict, MAX_DEPTH, SKIP_DIRS } from "../../policy/secret-discovery.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // pure policy functions; the axis is the confidentiality one by name

function tmpHome(): { dir: string; home: string; close: () => void } {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-catalog-gate-")));
  const home = join(dir, "home");
  mkdirSync(home, { recursive: true });
  return { dir, home, close: () => rmSync(dir, { recursive: true, force: true }) };
}

function put(p: string, text = "x\n"): string {
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text);
  return p;
}

/** The guard's prefilter, as label_index applies it: under a root (a
 *  catalog prefix), or a name an anchor admits with no skipped directory
 *  below the deepest home holding the file (below `/` outside every one). */
function prefilterAdmits(p: string, homes: string[]): boolean {
  const roots = catalogGateRoots(homes);
  const under = (r: string): boolean => p === r || p.startsWith(r + "/");
  const skip = new Set([...SKIP_DIRS, ...CATALOG_GATE_SKIP_DIRS]);
  const root = roots.filter(under).sort((a, b) => b.length - a.length)[0];
  if (root !== undefined) {
    const dirs = p.slice(root.length + 1).split("/").slice(0, -1);
    if (!dirs.some((d) => SKIP_DIRS.has(d))) return true;
  }
  if (!catalogNameAnchors().some((a) => nameAnchorAdmits(a, basename(p)))) return false;
  let base = "/";
  for (const h of homes) if (under(h) && h.length > base.length) base = h;
  const dirs = (base === "/" ? p.slice(1) : p.slice(base.length + 1)).split("/").slice(0, -1);
  return !dirs.some((d) => skip.has(d));
}

test("the name anchors are sound: every name a basename shape matches meets one of that shape's anchors", () => {
  const heads = ["", ".", "x", "my-", "prod_", "Secrets", "SECRET", "secrets", "id_", "service-account", "serviceAccount", "Service_Account", "privkey", "server", ".env", "aws_", "client_"];
  const mids = ["", "credentials", "Credentials", "CREDENTIALS", "secret", "Secret", "secrets", "key", "-key", "_key", ".key", "account", ".env", "tfstate", "rsa", "ed25519", "rc"];
  const tails = ["", ".json", ".JSON", ".yaml", ".yml", ".toml", ".env", ".key", ".KEY", ".pem", ".PEM", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".kdbx", ".tfstate", ".tfstate.backup", ".keytab", ".txt", ".md", ".py", ".ts", "rc", ".local", ".production", ".properties", ".xml", ".tfvars"];
  const names = new Set<string>(["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".envrc", "keyfile.json", ...CREDENTIAL_CORPUS.map((e) => basename(e.path))]);
  for (const h of heads) for (const m of mids) for (const t of tails) names.add(`${h}${m}${t}`);
  const bad: string[] = [];
  let matched = 0;
  for (const n of names) {
    const u = unanchoredShapes(n);
    if (u.length > 0) bad.push(`${n}: ${u.join(",")}`);
    if (catalogNameAnchors().some((a) => nameAnchorAdmits(a, n))) matched++;
  }
  assert.deepEqual(bad, [], "a shape matched a name none of its anchors admits");
  assert.ok(matched > 0 && matched < names.size, "the anchors admit some names and not others");
  // The anchors spare the names an ordinary tree is made of.
  for (const n of ["index.js", "README.md", "main.rs", "package.json", "Cargo.toml", "secrets.ts", "secret_manager.py", "known_hosts", "ca-certificates.crt", "id_rsa.pub", "server.crt", "notes.txt"]) {
    assert.ok(!catalogNameAnchors().some((a) => nameAnchorAdmits(a, n)), `${n} costs no round trip`);
  }
});

test("nameAnchorAdmits: every condition given must hold; ci folds ASCII only", () => {
  assert.ok(nameAnchorAdmits({ contains: "secret", suffix: ".json", ci: true }, "My-SECRETS.JSON"));
  assert.ok(!nameAnchorAdmits({ contains: "secret", suffix: ".json", ci: true }, "secrets.yaml"));
  assert.ok(!nameAnchorAdmits({ prefix: "secrets", suffix: ".json" }, "Secrets.json"), "case-sensitive without ci");
  assert.ok(nameAnchorAdmits({ exact: ".env" }, ".env") && !nameAnchorAdmits({ exact: ".env" }, ".env.local"));
  assert.ok(!nameAnchorAdmits({ contains: "secret", ci: true }, "ſecret"), "a non-ASCII letter never folds to an ASCII one (as /secret/i)");
  assert.equal(/secret/i.test("ſecret"), false, "the catalog's own regex agrees");
});

test("parity with the walk: every corpus credential the walk registers is admitted by the prefilter and gated, and the same name deeper than the walk is gated too", () => {
  const t = tmpHome();
  try {
    for (const e of CREDENTIAL_CORPUS) put(join(t.home, e.path), e.content);
    const report = discoverSecretsReport([t.home], t.home, undefined, { selfDir: null, installEnv: {} });
    assert.ok(report.files.length > 20, `the walk registered the corpus: ${report.files.length}`);
    // A file the content tier found (secret-discovery.md §2.6) is gated by
    // its found label's own root (label-lookup.ts guardLabelRoots,
    // found-labels.test.ts), not by the catalog's names: the parity here is
    // the path rules'.
    assert.ok(report.files.some((f) => f.rule === "content:secret-key"), "the content tier found the corpus' tool configs");
    for (const f of report.files.filter((x) => x.rule !== "content:secret-key")) {
      assert.ok(prefilterAdmits(f.path, [t.home]), `the prefilter admits ${f.path} (${f.rule})`);
      const v = gateVerdict(f.path, [t.home]);
      assert.equal(v.level, f.level, `the gate classifies ${f.path} as the walk did (${f.rule}): ${JSON.stringify(v)}`);
    }
    // Every basename-shaped corpus file, deeper than the walk reaches.
    const deep = join(t.home, "proj", "a", "b", "c", "d", "e");
    let shaped = 0;
    for (const f of report.files.filter((x) => x.rule.startsWith("shape:"))) {
      // under its own two directories' names (a shape may read them:
      // `shape:tool-login-file`, a CLI's login in `.<tool>/` or
      // `.config/<tool>/`)
      const p = put(join(deep, basename(dirname(dirname(f.path))), basename(dirname(f.path)), basename(f.path)));
      shaped++;
      assert.ok(prefilterAdmits(p, [t.home]), `the prefilter admits ${p}`);
      assert.equal(gateVerdict(p, [t.home]).level, "no-model", p);
    }
    assert.ok(shaped > 3);
    const again = discoverSecretsReport([t.home], t.home, undefined, { selfDir: null, installEnv: {} });
    assert.ok(!again.files.some((f) => f.path.startsWith(deep + "/")), `below MAX_DEPTH=${MAX_DEPTH} the walk registers none of them (the gap the gate closes)`);
    // A file deeper than the walk under a catalog prefix (gcloud's per-account dirs).
    const prefixed = put(join(t.home, ".config", "gcloud", "a", "b", "c", "d", "token.db"));
    assert.ok(prefilterAdmits(prefixed, [t.home]));
    assert.equal(gateVerdict(prefixed, [t.home]).level, "no-model");
  } finally {
    t.close();
  }
});

test("a source file named like a credential (2026-10-17): the walk does not twin it above MAX_DEPTH, the gate does not gate it below, and the prefilter spares it the round trip; its data siblings stay", () => {
  const t = tmpHome();
  try {
    const h = t.home;
    const shallow = join(h, "proj", "src", "auth");
    const deep = join(h, "proj", "src", "auth", "providers", "a", "b", "c");
    const sources = ["credentials.ts", "credentials.py", "Credentials.java", "credentials.go", "credentials.rs", "credentials.test.ts"];
    const data = [".env", "credentials", "credentials.json", "credentials.yaml", "credentials.sh"];
    for (const d of [shallow, deep]) for (const n of [...sources, ...data]) put(join(d, n), "x=1\n");
    const report = discoverSecretsReport([h], h, undefined, { selfDir: null, installEnv: {} });
    const walked = new Set(report.files.map((f) => f.path));
    for (const n of sources) {
      assert.ok(!walked.has(join(shallow, n)), `the walk does not twin ${n}`);
      for (const d of [shallow, deep]) {
        const p = join(d, n);
        assert.equal(gateVerdict(p, [h]).level, "public", `the gate does not gate ${p}`);
        assert.ok(!prefilterAdmits(p, [h]), `the prefilter spares ${p} the round trip`);
      }
    }
    for (const n of data) {
      assert.ok(walked.has(join(shallow, n)), `the walk still registers ${n}`);
      for (const d of [shallow, deep]) {
        const p = join(d, n);
        assert.equal(gateVerdict(p, [h]).level, "no-model", `the gate still gates ${p}`);
        assert.ok(prefilterAdmits(p, [h]), `the prefilter admits ${p}`);
      }
    }
    // A human label still wins over the exception (fail-closed for a real secret).
    const labelled = join(deep, "credentials.ts");
    const lookup: LabelLookup = (p) => (p === labelled ? { level: "no-model", bindings: [], via: labelled, origin: "human" } as never : null);
    assert.equal(gateVerdict(labelled, [h], lookup).level, "no-model", "a labelled source file is gated");
  } finally {
    t.close();
  }
});

test("the walk's rule, not the content: a template name stays public, and the walk's prunes hold", () => {
  const t = tmpHome();
  try {
    const h = t.home;
    const v = (p: string): string => `${gateVerdict(put(p), [h]).level}/${gateVerdict(p, [h]).pruned ?? "-"}`;
    assert.equal(v(join(h, "proj", ".env")), "no-model/-");
    assert.equal(v(join(h, "proj", ".env.example")), "public/-", "a template is no shape (the walk never reads content)");
    assert.equal(v(join(h, "proj", "config", "secrets.example.yaml")), "public/-");
    assert.equal(v(join(h, "proj", "node_modules", "pkg", ".env")), "public/skipped-dir");
    assert.equal(v(join(h, "proj", ".git", "credentials")), "public/skipped-dir");
    assert.equal(v(join(h, "venv-x", "lib", "python3.12", "site-packages", "botocore", "data", "credentials.json")), "public/skipped-dir", "a library's own file");
    assert.equal(v(join(h, ".cargo", "registry", "src", "idx", "aws-creds-1.0", "tests", "credentials.json")), "public/package-cache");
    assert.equal(v(join(h, "venv-x", "lib", "python3.12", "site-packages", "botocore", "credentials.py")), "public/-", "a library's source: no shape at all (SOURCE_EXTS)");
    assert.equal(v(join(h, ".claude", "projects", "p", "credentials.json")), "public/agent-auth", "an agent's own store");
    assert.equal(v(join(h, ".claude", ".credentials.json")), "public/agent-auth", "an agent's login");
    assert.equal(v(join(h, ".codex", "auth.json")), "public/agent-auth");
    assert.equal(v(join(h, ".mandu", "state", "workspaces", "w", "shadow", ".env")), "public/mandu-state", "Mandu's own state");
    assert.equal(v(join(h, ".mandu", "state", "workspaces", "w", "agentview", ".env")), "no-model/-", "a raw AgentView copy is judged");
    // ~/.cache is skipped, but a credential the catalog names inside it is not.
    assert.equal(v(join(h, ".cache", "huggingface", "token")), "no-model/-");
    assert.equal(v(join(h, ".ssh", "known_hosts")), "public/-", "a public file under a prefix");
    assert.equal(v(join(h, ".ssh", "config.d", "work")), "no-model/-", "any depth under a prefix");
  } finally {
    t.close();
  }
});

test("outside every home: the user's own file is gated, another account's is not; an unreadable owner is gated", () => {
  const t = tmpHome();
  try {
    const p = put(join(t.dir, "srv", "app", ".env"));
    const me = process.getuid!();
    assert.equal(gateVerdict(p, [t.home], undefined, { uid: me }).level, "no-model", "a .env outside HOME the user owns");
    const other = gateVerdict(p, [t.home], undefined, { uid: me + 1 });
    assert.deepEqual([other.level, other.pruned], ["public", "other-owner"], "a file another account owns (a system package's)");
    assert.equal(gateVerdict(join(t.dir, "gone", ".env"), [t.home], undefined, { uid: me + 1 }).level, "no-model", "an owner that cannot be read: judged as named");
    assert.equal(gateVerdict(join(t.dir, "srv", "build", "x", ".env"), [t.home]).pruned, "skipped-dir", "outside every home, every directory counts");
  } finally {
    t.close();
  }
});

test("a label decides wherever the file lies; two homes: the stricter, and either home's agent files pruned", () => {
  const t = tmpHome();
  try {
    const h = t.home;
    const launch = join(t.dir, "launch-home");
    const pub = put(join(h, "proj", ".env"));
    const dep = put(join(h, "proj", "node_modules", "pkg", "plan.md"));
    const lookup: LabelLookup = (p) =>
      p === pub ? { level: "public", bindings: [], via: pub, origin: "human" } as never
        : p === dep ? { level: "no-model", bindings: [], via: dep, origin: "human" } as never
          : null;
    assert.equal(gateVerdict(pub, [h], lookup).level, "public", "a human public label declassifies the .env");
    assert.equal(gateVerdict(dep, [h], lookup).level, "no-model", "a human label speaks inside node_modules too");
    const key = put(join(launch, ".aws", "sso", "cache", "a", "b", "tok.json"));
    assert.equal(gateVerdict(key, [h]).level, "public", "not a catalog place under the arbiter's HOME alone");
    assert.equal(gateVerdict(key, [h, launch]).level, "no-model", "the launch HOME's catalog place");
    assert.equal(gateVerdict(put(join(launch, ".claude", ".credentials.json")), [h, launch]).pruned, "agent-auth", "the launch HOME's agent login, though its name matches a shape");
    const roots = catalogGateRoots([h, launch]);
    for (const r of [join(h, ".ssh"), join(launch, ".ssh"), join(h, ".aws"), join(launch, ".config", "gcloud"), "/etc/shadow"]) assert.ok(roots.includes(r), `${r} in ${roots.join(" ")}`);
    for (const r of [join(h, ".claude"), join(launch, ".codex"), join(h, ".claude.json"), join(h, ".local", "share", "opencode")]) assert.ok(!roots.includes(r), `an agent's own place is no root: ${r}`);
  } finally {
    t.close();
  }
});
