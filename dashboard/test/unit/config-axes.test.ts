/**
 * config-axes.test — offline unit tests for src/config-axes.ts (the Protection
 * drawer's durable axis surface, dashboard.md §4.19 ②): config-path resolution
 * (the launcher's `<MANDU_HOME or ~/.mandu>/config.toml`), the read side (launcher
 * parseToml-subset semantics: bool coercion, last-wins, inline comments), the
 * SURGICAL writer (in-place replacement, provenance-comment append added once,
 * every other byte preserved VERBATIM), file/dir creation, and the arbiter
 * spawn-env fill's precedence (explicit process env wins; config fills only
 * unset keys; both absent → nothing).
 *
 * Mandu-new test (NO reference origin). Pure functions + a temp dir; no
 * server, no arbiter, no process.env mutation (env is always passed in).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

import {
  AXIS_DEFAULTS,
  applyAxesEdit,
  arbiterAxisSpawnEnv,
  configuredAxes,
  PROVENANCE_COMMENT,
  readAxesState,
  resolveConfigPath,
  writeAxes,
} from "../../src/config-axes.js";
import { manduPath } from "../../src/generated/mandu-paths.js";
import { tmpDir } from "./tmp-dir.js";

// ── resolveConfigPath (the launcher's rule, launcher/src/config.ts) ───────────

test("resolveConfigPath: the retired MANDU_CONFIG moves nothing", () => {
  assert.equal(resolveConfigPath({ MANDU_CONFIG: "/pinned/config.toml", MANDU_HOME: "/mh", HOME: "/home/u" }), "/mh/config.toml");
  assert.equal(resolveConfigPath({ MANDU_CONFIG: "/pinned/config.toml", HOME: "/home/u" }), "/home/u/.mandu/config.toml");
  assert.equal(resolveConfigPath({ MANDU_CONFIG: "/pinned/config.toml" }), null, "it alone resolves no path");
});

test("resolveConfigPath: MANDU_HOME beats HOME; HOME is the fallback; XDG_CONFIG_HOME places nothing; none → null", () => {
  assert.equal(resolveConfigPath({ MANDU_HOME: "/mh", HOME: "/home/u" }), join("/mh", "config.toml"));
  assert.equal(resolveConfigPath({ HOME: "/home/u" }), join("/home/u", ".mandu", "config.toml"));
  assert.equal(resolveConfigPath({ XDG_CONFIG_HOME: "/xdg", HOME: "/home/u" }), join("/home/u", ".mandu", "config.toml"));
  assert.equal(resolveConfigPath({ XDG_CONFIG_HOME: "/xdg" }), null);
  assert.equal(resolveConfigPath({}), null);
});

test("resolveConfigPath: the path table's config-toml whenever a path resolves; empty values count as unset", () => {
  assert.equal(resolveConfigPath({ MANDU_HOME: "/mh" }), "/mh/config.toml", "no HOME needed under MANDU_HOME");
  assert.equal(resolveConfigPath({ MANDU_HOME: "", HOME: "" }), null);
  for (const env of [
    { HOME: "/home/u" },
    { HOME: "/home/u", MANDU_HOME: "/mh" },
    { HOME: "/home/u", XDG_CONFIG_HOME: "/xdg" },
    { HOME: "/home/u", MANDU_HOME: "" },
    { HOME: "/home/u", MANDU_HOME: "/dev/null/mandu-test-home" },
  ]) {
    assert.equal(resolveConfigPath(env), manduPath("config-toml", env, "/home/u"));
  }
});

// ── read side (launcher parseToml-subset semantics) ───────────────────────────

test("configuredAxes: absent keys → null; bare booleans parse; string \"true\" coerces on", () => {
  assert.deepEqual(configuredAxes(""), { integrity: null, confidentiality: null });
  assert.deepEqual(configuredAxes("integrity = false\nconfidentiality = true\n"), {
    integrity: false,
    confidentiality: true,
  });
  // The launcher's bool coercion: `true`/"true" → on, any other present value → off.
  assert.deepEqual(configuredAxes('integrity = "true"\nconfidentiality = "yes"\n'), {
    integrity: true,
    confidentiality: false,
  });
});

test("configuredAxes: commented lines don't count; inline comments strip; duplicates → LAST wins", () => {
  const text = [
    "# integrity = false", // a comment is not a configuration
    "integrity = true # keep the defense on",
    "confidentiality = false",
    "confidentiality = true", // last wins (launcher parseToml overwrites)
  ].join("\n");
  assert.deepEqual(configuredAxes(text), { integrity: true, confidentiality: true });
});

test("readAxesState: missing file → exists:false, all-null configured, effective = arbiter defaults", () => {
  const dir = tmpDir("mandu-config-axes-");
  try {
    const env = { MANDU_HOME: join(dir, "nope") };
    const st = readAxesState(env);
    assert.equal(st.ok, true);
    assert.equal(st.path, join(dir, "nope", "config.toml"));
    assert.equal(st.exists, false);
    assert.deepEqual(st.configured, { integrity: null, confidentiality: null });
    // Derived, never hardcoded: DEFAULT_MODE is the one constant naming it.
    assert.deepEqual(st.defaults, AXIS_DEFAULTS);
    assert.deepEqual(st.effective, AXIS_DEFAULTS);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("readAxesState: effective = configured ?? default, per axis independently", () => {
  const dir = tmpDir("mandu-config-axes-");
  try {
    const path = join(dir, "config.toml");
    writeFileSync(path, "confidentiality = true\n");
    const st = readAxesState({ MANDU_HOME: dir });
    assert.equal(st.exists, true);
    assert.deepEqual(st.configured, { integrity: null, confidentiality: true });
    assert.deepEqual(st.effective, { integrity: AXIS_DEFAULTS.integrity, confidentiality: true });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── the surgical editor (pure text transform) ────────────────────────────────

test("applyAxesEdit: replaces an existing line in place, preserving indent + inline comment", () => {
  const text = "# my config\nintegrity = true # the defense\nproxy-port = 0\n";
  const out = applyAxesEdit(text, { integrity: false });
  assert.equal(out, "# my config\nintegrity = false  # the defense\nproxy-port = 0\n");
});

test("applyAxesEdit: EVERY unrelated byte preserved verbatim (comments, spacing, unknown keys, CRLF-free run)", () => {
  const text = [
    "# hand-written header — do not touch",
    "",
    "reply-filter = true   # weird   spacing",
    "net-allow = \"10.0.0.0/8:*\"",
    "confidentiality = false",
    "",
    "# trailing note",
    "",
  ].join("\n");
  const out = applyAxesEdit(text, { confidentiality: true });
  const expected = text.replace("confidentiality = false", "confidentiality = true");
  assert.equal(out, expected, "only the managed line changed; every other byte identical");
});

test("applyAxesEdit: replaces EVERY duplicate managed line (last-wins read stays coherent)", () => {
  const text = "integrity = true\nintegrity = false\n";
  const out = applyAxesEdit(text, { integrity: true });
  assert.equal(out, "integrity = true\nintegrity = true\n");
  assert.equal(configuredAxes(out).integrity, true);
});

test("applyAxesEdit: never touches a commented-out or longer-key line", () => {
  const text = "# integrity = false\nfs-integrity = false\n";
  const out = applyAxesEdit(text, { integrity: true });
  assert.ok(out.startsWith("# integrity = false\nfs-integrity = false\n"), "untouched");
  assert.match(out, new RegExp(`^integrity = true$`, "m"), "the real key was appended");
});

test("applyAxesEdit: absent key appends as a bare TOML boolean under the provenance comment", () => {
  const out = applyAxesEdit("proxy-port = 0\n", { confidentiality: true });
  assert.equal(out, `proxy-port = 0\n\n${PROVENANCE_COMMENT}\nconfidentiality = true\n`);
});

test("applyAxesEdit: the provenance comment is added ONCE across sequential appends", () => {
  const first = applyAxesEdit("", { integrity: false });
  assert.equal(first, `${PROVENANCE_COMMENT}\nintegrity = false\n`);
  const second = applyAxesEdit(first, { confidentiality: true });
  const comments = second.split("\n").filter((l) => l === PROVENANCE_COMMENT);
  assert.equal(comments.length, 1, "comment not duplicated");
  assert.equal(second, `${PROVENANCE_COMMENT}\nintegrity = false\nconfidentiality = true\n`);
});

test("applyAxesEdit: appending to a file without a trailing newline first completes the line", () => {
  const out = applyAxesEdit("proxy-port = 0", { integrity: true });
  assert.equal(out, `proxy-port = 0\n\n${PROVENANCE_COMMENT}\nintegrity = true\n`);
});

test("applyAxesEdit: both keys in one update — replace one, append the other", () => {
  const out = applyAxesEdit("integrity = false\n", { integrity: true, confidentiality: true });
  assert.equal(out, `integrity = true\n\n${PROVENANCE_COMMENT}\nconfidentiality = true\n`);
});

// ── writeAxes (the FS wrapper) ────────────────────────────────────────────────

test("writeAxes: creates the parent dir + file when absent, returns the post-write state", () => {
  const dir = tmpDir("mandu-config-axes-");
  try {
    const path = join(dir, "deep", "nested", "config.toml");
    const env = { MANDU_HOME: join(dir, "deep", "nested") };
    const st = writeAxes(env, { confidentiality: true });
    assert.equal(existsSync(path), true, "file created");
    assert.equal(st.exists, true);
    assert.deepEqual(st.configured, { integrity: null, confidentiality: true });
    assert.deepEqual(st.effective, { integrity: AXIS_DEFAULTS.integrity, confidentiality: true });
    assert.equal(readFileSync(path, "utf8"), `${PROVENANCE_COMMENT}\nconfidentiality = true\n`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeAxes: round-trip on a hand-written file — unrelated bytes byte-identical", () => {
  const dir = tmpDir("mandu-config-axes-");
  try {
    const path = join(dir, "config.toml");
    const hand = "# mine\nnet-guard = true\nintegrity = true\n# tail\n";
    writeFileSync(path, hand);
    const st = writeAxes({ MANDU_HOME: dir }, { integrity: false });
    assert.equal(readFileSync(path, "utf8"), "# mine\nnet-guard = true\nintegrity = false\n# tail\n");
    assert.equal(st.configured.integrity, false);
    // Flip it back — byte-identical to the original hand-written file.
    writeAxes({ MANDU_HOME: dir }, { integrity: true });
    assert.equal(readFileSync(path, "utf8"), hand, "round-trip restored the exact original bytes");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeAxes: writes <MANDU_HOME>/config.toml, never the HOME-derived default; the retired MANDU_CONFIG moves nothing", () => {
  const dir = tmpDir("mandu-config-axes-");
  try {
    const home = join(dir, "mh");
    const retired = join(dir, "pinned.toml");
    writeAxes({ MANDU_HOME: home, HOME: dir, MANDU_CONFIG: retired }, { integrity: false });
    assert.equal(existsSync(join(home, "config.toml")), true, "wrote the home's config.toml");
    assert.equal(existsSync(retired), false, "never the retired MANDU_CONFIG path");
    assert.equal(existsSync(join(dir, ".mandu", "config.toml")), false, "never touched the HOME-derived default");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeAxes: no resolvable path (neither MANDU_HOME nor HOME) → throws, writes nothing", () => {
  assert.throws(() => writeAxes({}, { integrity: false }), /cannot resolve the config path/);
});

test("a home under a non-directory (the test scripts' MANDU_HOME=/dev/null/...) reads as no config; a write fails loudly", () => {
  const env = { MANDU_HOME: "/dev/null/mandu-test-home" };
  const st = readAxesState(env);
  assert.equal(st.path, "/dev/null/mandu-test-home/config.toml");
  assert.equal(st.exists, false, "ENOTDIR reads like ENOENT");
  assert.deepEqual(st.configured, { integrity: null, confidentiality: null });
  assert.deepEqual(arbiterAxisSpawnEnv(env), {});
  assert.throws(() => writeAxes(env, { integrity: false }), /ENOTDIR|EEXIST|not a directory/i);
});

// ── arbiterAxisSpawnEnv (the supervisor's spawn-time fill; launcher precedence) ─

test("arbiterAxisSpawnEnv: config fills only UNSET env keys (explicit process env wins)", () => {
  const dir = tmpDir("mandu-config-axes-");
  try {
    const path = join(dir, "config.toml");
    writeFileSync(path, "integrity = false\nconfidentiality = true\n");
    // Both unset → both filled, launcher "1"/"0" spellings.
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir }), {
      MANDU_INTEGRITY: "0",
      MANDU_CONFIDENTIALITY: "1",
    });
    // An explicitly-set env var wins — the config never overrides it.
    assert.deepEqual(
      arbiterAxisSpawnEnv({ MANDU_HOME: dir, MANDU_INTEGRITY: "1" }),
      { MANDU_CONFIDENTIALITY: "1" },
    );
    // The launcher's exact rule: only `undefined` is unset — an EMPTY-string
    // export is still "set" (applyConfigDefaults fills `=== undefined` only).
    assert.deepEqual(
      arbiterAxisSpawnEnv({ MANDU_HOME: dir, MANDU_INTEGRITY: "", MANDU_CONFIDENTIALITY: "" }),
      {},
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("arbiterAxisSpawnEnv: unconfigured keys / missing file / no path → nothing set (arbiter defaults rule)", () => {
  const dir = tmpDir("mandu-config-axes-");
  try {
    const path = join(dir, "config.toml");
    writeFileSync(path, "proxy-port = 0\n"); // neither axis key configured
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir }), {});
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: join(dir, "absent") }), {});
    assert.deepEqual(arbiterAxisSpawnEnv({}), {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("arbiterAxisSpawnEnv: a home with no config.toml fills nothing (the test isolation stays inert)", () => {
  const dir = tmpDir("mandu-config-axes-");
  try {
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir }), {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("arbiterAxisSpawnEnv: a `policy-file` key seeds MANDU_POLICY_FILE for the spawned arbiter (env wins; §2.1)", () => {
  const dir = tmpDir("mandu-config-axes-");
  try {
    const path = join(dir, "config.toml");
    writeFileSync(path, 'integrity = true\npolicy-file = "~/law/policy.yaml"   # the data law\n');
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir }), {
      MANDU_INTEGRITY: "1",
      MANDU_POLICY_FILE: "~/law/policy.yaml",
    });
    assert.deepEqual(
      arbiterAxisSpawnEnv({ MANDU_HOME: dir, MANDU_POLICY_FILE: "/explicit.yaml" }),
      { MANDU_INTEGRITY: "1" },
      "an explicit env var wins — the config never overrides it",
    );
    writeFileSync(path, "integrity = true\n");
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir }), { MANDU_INTEGRITY: "1" }, "no key → nothing seeded");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
