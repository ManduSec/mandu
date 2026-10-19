/**
 * guard-settings.test — policy.yaml `unix_sockets:` and `write_protect:`
 * (guard-settings.ts; sandbox-security-review-2026-09-28 findings 1, 2, 6):
 *   - validation: the shapes, unknown sub-keys refused, `@*` / `/` refused,
 *     and an `unprotect` value that names Mandu's own files refused in every
 *     spelling we know (config / state / install dirs, the symbol DB, the
 *     arbiter socket, a directory above them);
 *   - the relax / tighten proof: a unix allow entry and an `unprotect` entry
 *     RELAX, a deny / ask addition TIGHTENS (ask → deny tightens, deny → ask
 *     relaxes), and the keys are not "unknown" to the delta;
 *   - a disk edit adding an `unprotect` entry is HELD; one adding a deny
 *     applies at once;
 *   - no edit op of the policy agent's grammar reaches these keys: an edit
 *     list naming them is refused on the data plane and from the Describe
 *     box, and the schema a model is offered does not mention them.
 *
 * No privilege. The keys are axis-independent in the arbiter (the launcher
 * decides when each list is enforced); the suite states `full`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";

import { compareGuardSettings, guardSettingsOf, namesManduOwnFiles } from "../../policy/guard-settings.js";
import { validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { policyDelta } from "../../policy/policy-delta.js";
import { compilePolicy, getCurrentPolicy, resetCurrentPolicyForTests, swapCurrentPolicy } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { PolicyDocumentStore } from "../../policy/policy-document-store.js";
import { PolicyProposalStore } from "../../policy/policy-proposals.js";
import { PolicyAgentOps } from "../../ipc/policy-agent-ops.js";
import { AGENT_EDIT_OPS } from "../../policy/policy-edit.js";
import { policyAgentEditSchema, policyEditSchema } from "../../policy/policy-edit-schema.js";
import { stateAxes } from "../axes.js";

stateAxes("full");

const problems = (doc: unknown): string[] => validatePolicyDocument(doc);

test("valid shapes pass; guardSettingsOf compiles them (trailing / trimmed, @names kept)", () => {
  const doc = {
    version: 1,
    unix_sockets: { allow: ["~/.local/run/helper.sock", "/run/user/1000/app/", "@my-helper", "@/tmp/prefix*"] },
    write_protect: { deny: ["~/bin/"], ask: ["~/.config/nvim/init.lua"], unprotect: ["~/.gitconfig", "/home/u/repo/.git/hooks"] },
  };
  assert.deepEqual(problems(doc), []);
  assert.deepEqual(guardSettingsOf(doc as PolicyFileConfig), {
    unixAllow: ["~/.local/run/helper.sock", "/run/user/1000/app", "@my-helper", "@/tmp/prefix*"],
    writeDeny: ["~/bin"],
    writeAsk: ["~/.config/nvim/init.lua"],
    writeUnprotect: ["~/.gitconfig", "/home/u/repo/.git/hooks"],
    trustLookups: [],
  });
  assert.deepEqual(guardSettingsOf(null), { unixAllow: [], writeDeny: [], writeAsk: [], writeUnprotect: [], trustLookups: [] });
});

test("remote_mounts.trust_lookups: valid entries compile (trailing / trimmed, a repeat by point and type once); bad shapes are refused", () => {
  const doc = { version: 1, remote_mounts: { trust_lookups: [{ mount: "/home/", type: "nfs4" }, { mount: "~/remote", type: "fuse.sshfs" }, { mount: "/home", type: "NFS4" }, { mount: "/", type: "nfs" }] } };
  assert.deepEqual(problems(doc), []);
  assert.deepEqual(guardSettingsOf(doc as PolicyFileConfig).trustLookups, [
    { mount: "/home", type: "nfs4" }, { mount: "~/remote", type: "fuse.sshfs" }, { mount: "/", type: "nfs" },
  ]);
  const cases: Array<[unknown, RegExp]> = [
    [{ remote_mounts: [] }, /remote_mounts: must be a mapping with 'trust_lookups'/],
    [{ remote_mounts: { hide: [] } }, /remote_mounts: unknown key 'hide'/],
    [{ remote_mounts: { trust_lookups: "/home" } }, /remote_mounts\.trust_lookups: must be a list/],
    [{ remote_mounts: { trust_lookups: ["/home"] } }, /remote_mounts\.trust_lookups\[0\]: must be \{ mount/],
    [{ remote_mounts: { trust_lookups: [{ mount: "home", type: "nfs4" }] } }, /trust_lookups\[0\]\.mount: must be the mount point/],
    [{ remote_mounts: { trust_lookups: [{ mount: "/home" }] } }, /trust_lookups\[0\]\.type: must be the file-system type/],
    [{ remote_mounts: { trust_lookups: [{ mount: "/home", type: "nfs 4" }] } }, /trust_lookups\[0\]\.type: must be the file-system type/],
    [{ remote_mounts: { trust_lookups: [{ mount: "/home", type: "nfs4", source: "nas:/x" }] } }, /trust_lookups\[0\]: unknown key 'source'/],
  ];
  for (const [d, re] of cases) {
    const p = problems(d);
    assert.ok(p.some((x) => re.test(x)), `${JSON.stringify(d)} → ${JSON.stringify(p)}`);
  }
});

test("the delta: trusting a mount for lookups RELAXES, dropping it TIGHTENS; the key is known; the type is case-folded", () => {
  const base = { version: 1 };
  const add = delta(base, { version: 1, remote_mounts: { trust_lookups: [{ mount: "/home", type: "nfs4" }] } });
  assert.deepEqual(add.tightenings, []);
  assert.deepEqual(add.relaxations.map((r) => [r.facet, r.subject]), [["env", "remote_mounts.trust_lookups /home (nfs4)"]]);
  assert.match(add.relaxations[0]!.detail, /its server sees every name/);
  assert.ok(!add.relaxations.some((r) => r.facet === "law"), "not an unknown key");
  const back = delta({ remote_mounts: { trust_lookups: [{ mount: "/home", type: "nfs4" }] } }, base);
  assert.deepEqual([back.relaxations.length, back.tightenings.length], [0, 1]);
  const same = delta({ remote_mounts: { trust_lookups: [{ mount: "/home", type: "nfs4" }] } }, { remote_mounts: { trust_lookups: [{ mount: "/home/", type: "NFS4" }] } });
  assert.deepEqual([same.relaxations.length, same.tightenings.length], [0, 0]);
  const other = delta({ remote_mounts: { trust_lookups: [{ mount: "/home", type: "nfs4" }] } }, { remote_mounts: { trust_lookups: [{ mount: "/home", type: "fuse.sshfs" }] } });
  assert.deepEqual([other.relaxations.length, other.tightenings.length], [1, 1], "another type at the same point is another mount");
});

test("bad shapes and unknown sub-keys are refused", () => {
  const cases: Array<[unknown, RegExp]> = [
    [{ unix_sockets: ["/x.sock"] }, /unix_sockets: must be a mapping/],
    [{ unix_sockets: { allow: "/x.sock" } }, /unix_sockets\.allow: must be a list/],
    [{ unix_sockets: { allow: ["/x.sock"], deny: [] } }, /unix_sockets: unknown key 'deny'/],
    [{ unix_sockets: { allow: ["relative.sock"] } }, /unix_sockets\.allow\[0\]: must be a socket path/],
    [{ unix_sockets: { allow: ["/"] } }, /would allow every socket/],
    [{ unix_sockets: { allow: ["~"] } }, /would allow every socket/],
    [{ unix_sockets: { allow: ["@"] } }, /names every abstract socket/],
    [{ unix_sockets: { allow: ["@*"] } }, /names every abstract socket/],
    [{ unix_sockets: { allow: ["@a*b"] } }, /only at the end/],
    [{ unix_sockets: { allow: [" /x.sock"] } }, /must be a socket path/],
    [{ write_protect: [] }, /write_protect: must be a mapping/],
    [{ write_protect: { allow: ["/x"] } }, /write_protect: unknown key 'allow'/],
    [{ write_protect: { deny: "/x" } }, /write_protect\.deny: must be a list/],
    [{ write_protect: { ask: ["x"] } }, /write_protect\.ask\[0\]: must be an absolute or ~\/ path/],
    [{ write_protect: { deny: ["/"] } }, /would stop the agent from changing any file/],
    [{ write_protect: { ask: ["~"] } }, /would stop the agent from changing any file/],
    [{ sandbox: {} }, /policy: unknown key 'sandbox'/],
  ];
  for (const [doc, re] of cases) {
    const p = problems(doc);
    assert.ok(p.some((x) => re.test(x)), `${JSON.stringify(doc)} → ${JSON.stringify(p)}`);
  }
});

test("Mandu's own files can NOT be unprotected, in any spelling the validator knows", () => {
  const own = [
    "~/.mandu", "~/.mandu/policy.yaml", "/home/u/.mandu/config.toml", "~/.mandu/state/mandu.db",
    "~/.local/share/mandu", "~/.local/share/mandu/bin", "/srv/x/mandu.db-wal", "/tmp/elsewhere/mandu-test.db",
    "/run/user/1000/mandu", "/run/user/1000/mandu/current/arbiter.sock", "/tmp/dev/arbiter.sock",
    "/usr/lib/mandu", "/usr/lib/mandu/bin/bwrap", "/opt/mandu",
    "~", "/", "~/.local", "~/.local/share", "/home/u/.local/share", "/run/user/1000", "/usr/lib",
    "~/.mandu/./state", "~/x/../.mandu", "~/.mandu/", "~/.local/share/./mandu", "~/.local/share/x/../mandu",
  ];
  for (const p of own) {
    assert.equal(namesManduOwnFiles(p), true, p);
    const found = problems({ write_protect: { unprotect: [p] } });
    assert.ok(found.some((x) => /Mandu.s own files \(the Mandu home,/.test(x) && /cannot be unprotected/.test(x)), `${p} → ${JSON.stringify(found)}`);
  }
  for (const p of ["~/.gitconfig", "~/.bashrc", "~/.config/systemd/user", "/home/u/src/mandu/.git/hooks", "~/.config/fish", "~/.ssh/config", "~/.config"]) {
    assert.equal(namesManduOwnFiles(p), false, p);
    assert.deepEqual(problems({ write_protect: { unprotect: [p] } }), [], p);
  }
  // deny / ask may name them (a no-op beside the built-in refusal, never a loosening).
  assert.deepEqual(problems({ write_protect: { deny: ["~/.mandu/policy.yaml"], ask: ["~/.mandu"] } }), []);
});

test("Mandu's own files: the whole one home, and no older layout's location (on-disk-layout.md §3, §6)", () => {
  const env = { HOME: "/home/u" };
  const oneHome = [
    "~/.mandu/config.toml", "~/.mandu/policy.yaml", "~/.mandu/packs", "~/.mandu/secrets.json",
    "~/.mandu/state", "~/.mandu/state/mandu.db", "~/.mandu/state/mandu-test.db-wal", "~/.mandu/state/workspaces/x/repo.git",
    "~/.mandu/state/object-walks", "~/.mandu/events", "~/.mandu/events/test", "~/.mandu/runs/ci", "~/.mandu/dev/docker-e2e-home",
    "~/.mandu/cache", "~/.mandu/cache/object-twins", "~/.mandu/cache/exec-box", "/home/u/.mandu/cache/ci",
    // A stray file at the top of the home (the pre-one-home DB) or one not yet made: the home is one rule (§4).
    "~/.mandu/mandu.db", "~/.mandu/anything-new", "~/.mandu/state/anything-new",
  ];
  for (const p of oneHome) assert.equal(namesManduOwnFiles(p, env), true, p);
  // A clean start: the XDG config / state / cache dirs hold nothing of Mandu's.
  const olderLayouts = [
    "~/.local/state/mandu/object-walks", "~/.config/mandu/docker-e2e-home", "~/.cache/mandu/exec-box",
    "~/.config", "~/.local/state", "~/.cache",
  ];
  for (const p of [...olderLayouts, "~/.cache/pip", "~/.cache/mandu-other", "~/src/mandu/cache", "/srv/cache/object-twins"]) {
    assert.equal(namesManduOwnFiles(p, env), false, p);
  }
});

test("Mandu's own files: a relocated MANDU_HOME, anything in it, and the directories above it", () => {
  const env = { HOME: "/home/u", MANDU_HOME: "/data/mh/" };
  for (const p of ["/data/mh", "/data/mh/cache/object-twins", "/data/mh/state/mandu.db", "/data", "/data/mh/"]) {
    assert.equal(namesManduOwnFiles(p, env), true, p);
  }
  assert.equal(namesManduOwnFiles("~/mh/events", { HOME: "/home/u", MANDU_HOME: "/home/u/mh" }), true, "spelled with ~");
  assert.equal(namesManduOwnFiles("~/mh2", { HOME: "/home/u", MANDU_HOME: "/home/u/mh" }), false, "a sibling is not it");
  for (const p of ["/data/other", "/data/mhx", "~/.gitconfig"]) assert.equal(namesManduOwnFiles(p, env), false, p);
  assert.equal(namesManduOwnFiles("/data/mh/state", { HOME: "/home/u" }), false, "without MANDU_HOME the path is nobody's");
});

function delta(before: unknown, after: unknown) {
  const c = (d: unknown) => compilePolicy({ specId: "claude-code", document: d as PolicyFileConfig });
  return policyDelta(c(before), c(after));
}

test("the delta: unix allow and unprotect entries relax; deny / ask additions tighten; the keys are known", () => {
  const base = { version: 1 };
  const u = delta(base, { version: 1, unix_sockets: { allow: ["/run/x.sock"] } });
  assert.deepEqual(u.tightenings, []);
  assert.equal(u.relaxations.length, 1);
  assert.equal(u.relaxations[0]!.facet, "env");
  assert.equal(u.relaxations[0]!.subject, "unix_sockets /run/x.sock");
  assert.ok(!u.relaxations.some((r) => r.facet === "law"), "not an unknown key");
  const uBack = delta({ version: 1, unix_sockets: { allow: ["/run/x.sock"] } }, base);
  assert.deepEqual([uBack.relaxations.length, uBack.tightenings.length], [0, 1]);

  const d = delta(base, { version: 1, write_protect: { deny: ["~/bin"], ask: ["~/notes"] } });
  assert.deepEqual(d.relaxations, []);
  assert.deepEqual(d.tightenings.map((t) => t.subject).sort(), ["write_protect ~/bin", "write_protect ~/notes"]);
  const askToDeny = delta({ write_protect: { ask: ["~/bin"] } }, { write_protect: { deny: ["~/bin"] } });
  assert.deepEqual([askToDeny.relaxations.length, askToDeny.tightenings.length], [0, 1]);
  const denyToAsk = delta({ write_protect: { deny: ["~/bin"] } }, { write_protect: { ask: ["~/bin"] } });
  assert.deepEqual([denyToAsk.relaxations.length, denyToAsk.tightenings.length], [1, 0]);
  const both = delta({ write_protect: { deny: ["~/bin"] } }, { write_protect: { deny: ["~/bin"], ask: ["~/bin"] } });
  assert.deepEqual([both.relaxations.length, both.tightenings.length], [0, 0], "deny still wins for the path: no change");
  const removed = delta({ write_protect: { deny: ["~/bin"] } }, base);
  assert.deepEqual([removed.relaxations.length, removed.tightenings.length], [1, 0]);

  const un = delta(base, { version: 1, write_protect: { unprotect: ["~/.gitconfig"] } });
  assert.deepEqual(un.tightenings, []);
  assert.deepEqual(un.relaxations.map((r) => r.subject), ["write_protect.unprotect ~/.gitconfig"]);
  const unBack = delta({ write_protect: { unprotect: ["~/.gitconfig"] } }, base);
  assert.deepEqual([unBack.relaxations.length, unBack.tightenings.length], [0, 1]);

  const same = delta({ unix_sockets: { allow: ["/a"] }, write_protect: { unprotect: ["~/.x"] } }, { unix_sockets: { allow: ["/a/"] }, write_protect: { unprotect: ["~/.x"] } });
  assert.deepEqual([same.relaxations.length, same.tightenings.length], [0, 0], "a trailing / is the same entry");
});

test("compareGuardSettings is pure over the raw documents", () => {
  const r: string[] = [], t: string[] = [];
  compareGuardSettings(null, { unix_sockets: { allow: ["@x"] }, write_protect: { ask: ["/a"] } }, (s) => r.push(s), (s) => t.push(s));
  assert.deepEqual(r, ["unix_sockets @x"]);
  assert.deepEqual(t, ["write_protect /a"]);
});

test("a disk edit adding an unprotect entry is HELD; one adding a deny path applies at once", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-guard-settings-"));
  const file = join(dir, "policy.yaml");
  const initial: PolicyFileConfig = { version: 1 };
  writeFileSync(file, yaml.dump(initial));
  const rebuild = (d: PolicyFileConfig | null) => swapCurrentPolicy(compilePolicy({ specId: "claude-code", document: d }));
  rebuild(initial);
  const proposals = new PolicyProposalStore();
  const docs = new PolicyDocumentStore({ path: file, rebuild, pollMs: 0 }, { document: initial, found: true });
  const ops = new PolicyAgentOps({ docs, proposals, pendingAsks: () => [], dbLabels: () => [], ruleHits: () => ({}), hostOf: (h) => h });
  let bump = 0;
  const write = (text: string) => {
    writeFileSync(file, text);
    const t = new Date(Date.now() + 5_000 + ++bump * 1_000);
    utimesSync(file, t, t);
  };
  try {
    write("version: 1\nwrite_protect:\n  unprotect: [~/.gitconfig]\n");
    assert.equal(docs.pollDisk(), true);
    const [p] = ops.proposalsList("pending").proposals;
    assert.ok(p, "the opt-out waits for a human");
    assert.ok(p.relaxes.some((r) => r.subject === "write_protect.unprotect ~/.gitconfig"));
    assert.equal(getCurrentPolicy().document?.write_protect, undefined, "not the law");
    ops.resolve(p.id, "denied", "dashboard");
    write("version: 1\nwrite_protect:\n  deny: [~/bin]\nunix_sockets:\n  allow: []\n");
    assert.equal(docs.pollDisk(), true);
    assert.equal(ops.proposalsList("pending").proposals.length, 0);
    assert.deepEqual(getCurrentPolicy().document?.write_protect, { deny: ["~/bin"] }, "a tightening is the law at once");
    write("version: 1\nwrite_protect:\n  deny: [~/bin]\nunix_sockets:\n  allow: [\"@helper\"]\n");
    docs.pollDisk();
    assert.equal(ops.proposalsList("pending").proposals.length, 1, "a unix allow entry is held too");
  } finally {
    docs.close();
    rmSync(dir, { recursive: true, force: true });
    resetCurrentPolicyForTests("claude-code");
  }
});

test("no model can propose these keys: no edit op names them, and the schema a model is offered does not mention them", () => {
  const schema = JSON.stringify([policyAgentEditSchema(), policyEditSchema()]);
  assert.ok(!/unix_sockets|write_protect|unprotect/.test(schema), "the offered grammar has no way to write them");
  assert.ok(!(AGENT_EDIT_OPS as readonly string[]).some((op) => /unix|protect|socket/.test(op)));
  const proposals = new PolicyProposalStore();
  const docs = new PolicyDocumentStore({ path: null, rebuild: () => {}, pollMs: 0 }, { document: null, found: false });
  const ops = new PolicyAgentOps({ docs, proposals, pendingAsks: () => [], dbLabels: () => [], ruleHits: () => ({}), hostOf: (h) => h });
  for (const edits of [
    [{ op: "write-protect", unprotect: ["~/.gitconfig"] }],
    [{ op: "unprotect", path: "~/.gitconfig" }],
    [{ op: "allow-unix-socket", path: "/run/docker.sock" }],
    [{ op: "list", name: "x", add: ["y"], write_protect: { unprotect: ["~/.gitconfig"] } }],
  ]) {
    for (const [channel, requestedBy] of [["data", undefined], ["admin", "assistant"]] as const) {
      const r = ops.propose({ id: "1", op: "policyPropose", edits, sessionKey: "s1", ...(requestedBy ? { requestedBy } : {}) }, channel);
      assert.equal(r.applied, false, `${channel}: ${JSON.stringify(edits)}`);
      assert.ok("refused" in r && r.refused === "invalid", `${channel}: refused fail-closed, never filed: ${JSON.stringify(r)}`);
    }
  }
  assert.equal(proposals.listProposals().length, 0, "nothing was filed");
});
