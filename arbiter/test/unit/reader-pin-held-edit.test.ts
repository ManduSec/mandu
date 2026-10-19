/**
 * reader-pin-held-edit — the arbiter's reader pin (plan 10 §11.2: a bare
 * reader name becomes `{app, path, sha256}` on its first raw open) is written
 * like every other policy.yaml write (policy-surface.md §8.4.6; first-session
 * tour item 17 after !1095):
 *
 *   - into the person's text: every comment and the layout stay;
 *   - while a relaxing hand edit waits in Approvals, made to that held edit
 *     as well (layered): the law gets the pin, the file keeps the hand edit
 *     with the pin, its card is filed again for the new bytes showing no
 *     more than before, and nothing the hand edit relaxes takes effect.
 *     Before, the pin wrote the law over the file: the hand edit was gone
 *     from it and its card superseded (restrictive, never a loosening);
 *   - a hand edit that landed inside the poll window is seen first (held,
 *     here) and the pin made once more over the law it left;
 *   - refused, the file untouched and the same card waiting, when the held
 *     edit changes the file's own rule, or when the file has no rule of its
 *     own yet and the held edit changes any `paths:` rule (the new entry
 *     copies the label the law gives the file). The open itself is still
 *     answered raw (the reader is listed); only the pin waits.
 *
 * A real ArbiterServer over a file-backed law, the guard's own channel (the
 * human socket, plan 13 D9) and the admin channel. The `secrets` axes,
 * stated (the pin is a confidentiality decision); no privilege.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: pinned on the server below

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const SHA = "a".repeat(64);

interface Rig {
  home: string;
  pgpass: string;
  billing: string;
  token: string;
  policy: string;
  guard: ArbiterClient;
  admin: ArbiterClient;
  close: () => Promise<void>;
}

/** The person's file: a comment at every level, each must survive. */
function law(r: { pgpass: string; billing: string; home: string }): string {
  return [
    "# Team policy. Ask Dana before you loosen anything.",
    "version: 1",
    "",
    "paths:",
    "  # the database password",
    `  - path: ${r.pgpass}   # prod`,
    "    level: no-model",
    "    readers: [ssh-add]   # the backup job",
    "  # the billing key",
    `  - path: ${r.billing}`,
    "    level: no-model",
    "  # tokens the deploy tool reads",
    `  - path: "${r.home}/sec/*"`,
    "    level: no-model",
    "    readers: [ssh-add]",
    "",
  ].join("\n");
}
const COMMENTS = ["# Team policy. Ask Dana before you loosen anything.", "  # the database password", "# prod", "# the backup job", "  # the billing key", "  # tokens the deploy tool reads"];

async function rig(): Promise<Rig> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-pin-held-"));
  dirs.push(dir);
  const home = join(dir, "home");
  mkdirSync(join(home, "billing"), { recursive: true });
  mkdirSync(join(home, "sec"), { recursive: true });
  const pgpass = join(home, ".pgpass");
  const billing = join(home, "billing", ".env");
  const token = join(home, "sec", "token");
  writeFileSync(pgpass, "db:5432:prod:app:pinHeldEditCanary01\n");
  writeFileSync(billing, "STRIPE_KEY=pinHeldEditCanary02\n");
  writeFileSync(token, "TOKEN=pinHeldEditCanary03\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, law({ pgpass, billing, home }));
  // No poll timer: a hand edit is seen only when a write looks (the pin's
  // own guarded write), so the window a hand edit can land in is the test's.
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock"));
  await guard.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock"));
  await admin.connect();
  return {
    home, pgpass, billing, token, policy, guard, admin,
    close: async () => { guard.close(); admin.close(); await s.close(); },
  };
}

const open = (r: Rig, path: string, exe: string, procKey: string) =>
  r.guard.decideSecretOpen({ path, exe, sha256: SHA, isAgent: false, exeSystem: true, openerEnv: [], procKey });

/** The reader entries the law in force gives `path` (its own entry). */
async function readersInForce(r: Rig, path: string): Promise<unknown[]> {
  const doc = (await r.admin.policyDocument()).inForce as PolicyFileConfig | null;
  return (doc?.paths?.find((p) => p.path === path)?.readers ?? []) as unknown[];
}
const isPin = (exe: string) => (x: unknown): boolean => typeof x === "object" && x !== null && (x as { path?: string }).path === exe && (x as { sha256?: string }).sha256 === SHA;
const onDisk = (r: Rig): PolicyFileConfig => yaml.load(readFileSync(r.policy, "utf8")) as PolicyFileConfig;
function keepsComments(text: string): void {
  for (const c of COMMENTS) assert.ok(text.includes(c), `the file keeps "${c}":\n${text}`);
}

test("a reader pin with nothing held is written into the person's text: every comment stays", async () => {
  const r = await rig();
  try {
    const d = await open(r, r.pgpass, "/usr/bin/ssh-add", "p-1");
    assert.equal(d.verdict, "raw", JSON.stringify(d));
    assert.equal(d.pinNeeded, true);
    assert.ok((await readersInForce(r, r.pgpass)).some(isPin("/usr/bin/ssh-add")), "the pin is the law");
    const text = readFileSync(r.policy, "utf8");
    keepsComments(text);
    assert.ok(text.startsWith("# Team policy. Ask Dana before you loosen anything.\nversion: 1\n\npaths:\n  # the database password\n"), text);
    // A file labelled by the pattern gets its own entry, also spliced in.
    assert.equal((await open(r, r.token, "/usr/bin/ssh-add", "t-1")).verdict, "raw");
    assert.ok((await readersInForce(r, r.token)).some(isPin("/usr/bin/ssh-add")));
    keepsComments(readFileSync(r.policy, "utf8"));
  } finally {
    await r.close();
  }
});

test("a reader pin while a relaxing hand edit is held is layered: the law gets the pin, the file keeps the hand edit, one card, nothing released", async () => {
  const r = await rig();
  try {
    // The hand edit binds the billing key to Stripe (a relaxation), with its
    // own comment. It lands unseen: the pin's write sees it first (held), and
    // the pin is made once more over the law it left.
    const hand = readFileSync(r.policy, "utf8").replace(
      `  - path: ${r.billing}\n    level: no-model\n`,
      `  - path: ${r.billing}\n    level: no-model\n    bindings: [api.stripe.com]   # billing goes to Stripe\n`,
    );
    writeFileSync(r.policy, hand);
    const released = async (): Promise<boolean> =>
      (await r.admin.testFlow({ source: { tool: "Read", origin: r.billing }, destination: "api.stripe.com" })).egress?.decision.allow === true;

    const d = await open(r, r.pgpass, "/usr/bin/ssh-add", "p-1");
    assert.equal(d.verdict, "raw", JSON.stringify(d));
    assert.ok((await readersInForce(r, r.pgpass)).some(isPin("/usr/bin/ssh-add")), "the pin is the law");
    assert.equal(await released(), false, "the held binding is not the law");
    const text = readFileSync(r.policy, "utf8");
    keepsComments(text);
    assert.ok(text.includes("bindings: [api.stripe.com]   # billing goes to Stripe"), `the file keeps the hand edit as written:\n${text}`);
    const file = onDisk(r);
    assert.ok((file.paths!.find((p) => p.path === r.pgpass)!.readers as unknown[]).some(isPin("/usr/bin/ssh-add")), "with the pin");
    const pending = (await r.admin.policyProposals("pending")).proposals;
    assert.equal(pending.length, 1, "one card");
    assert.equal(pending[0]!.requestedBy, "file");
    assert.deepEqual(pending[0]!.relaxes.map((x) => x.subject).every((s) => s.includes("billing") || s.includes("stripe")), true, `the card shows the hand edit's relaxation only: ${JSON.stringify(pending[0]!.relaxes)}`);
    const superseded = (await r.admin.policyProposals("superseded")).proposals.filter((p) => p.requestedBy === "file");
    assert.equal(superseded.length, 1, "the card first filed for the hand edit was filed again for the new bytes");
    assert.equal(superseded[0]!.supersededBy, pending[0]!.id);

    // The file has no rule of its own for the token, and the held edit
    // changes a `paths:` rule: the pin waits, the open is still answered.
    const before = readFileSync(r.policy, "utf8");
    assert.equal((await open(r, r.token, "/usr/bin/ssh-add", "t-1")).verdict, "raw", "the listed reader is still let in");
    assert.equal(readFileSync(r.policy, "utf8"), before, "the held edit is untouched");
    assert.deepEqual(await readersInForce(r, r.token), [], "no own entry was made in the law");
    assert.deepEqual((await r.admin.policyProposals("pending")).proposals.map((p) => p.id), [pending[0]!.id], "the same card waits");

    // The human approves: the hand edit and the pin are both the law.
    const ok = await r.admin.resolvePolicyProposal(pending[0]!.id, "approved", "human:test");
    assert.equal(ok.proposal.status, "approved");
    assert.equal(await released(), true, "approved: the binding is the law");
    assert.ok((await readersInForce(r, r.pgpass)).some(isPin("/usr/bin/ssh-add")), "and the pin stays");
    assert.equal(readFileSync(r.policy, "utf8"), before, "the approval wrote nothing over the person's file");
    // Nothing held now: the token's pin is written at its next open.
    assert.equal((await open(r, r.token, "/usr/bin/ssh-add", "t-2")).verdict, "raw");
    assert.ok((await readersInForce(r, r.token)).some(isPin("/usr/bin/ssh-add")));
    keepsComments(readFileSync(r.policy, "utf8"));
  } finally {
    await r.close();
  }
});

test("a reader pin on a file whose own rule the held edit changes too waits: the file untouched, the same card, the law without the edit", async () => {
  const r = await rig();
  try {
    // The hand edit binds the pgpass file itself to a host: a relaxation of
    // the very rule the pin would change.
    const hand = readFileSync(r.policy, "utf8").replace(
      "    readers: [ssh-add]   # the backup job\n",
      "    readers: [ssh-add]   # the backup job\n    bindings: [db.example.com]\n",
    );
    writeFileSync(r.policy, hand);
    // The first open sees the hand edit (held) and the pin is refused.
    assert.equal((await open(r, r.pgpass, "/usr/bin/ssh-add", "p-1")).verdict, "raw", "the listed reader is let in");
    assert.equal(readFileSync(r.policy, "utf8"), hand, "the held edit is untouched");
    assert.ok(!(await readersInForce(r, r.pgpass)).some(isPin("/usr/bin/ssh-add")), "the pin waits");
    const pending = (await r.admin.policyProposals("pending")).proposals;
    assert.equal(pending.length, 1);
    const doc = (await r.admin.policyDocument()).inForce as PolicyFileConfig;
    assert.equal(doc.paths!.find((p) => p.path === r.pgpass)!.bindings, undefined, "the held binding is not the law");
    // Again: still nothing written, still the same card.
    assert.equal((await open(r, r.pgpass, "/usr/bin/ssh-add", "p-2")).verdict, "raw");
    assert.equal(readFileSync(r.policy, "utf8"), hand);
    assert.deepEqual((await r.admin.policyProposals("pending")).proposals.map((p) => p.id), [pending[0]!.id]);
    // Declined: the law is written back (comments kept) and the next open pins.
    const no = await r.admin.resolvePolicyProposal(pending[0]!.id, "denied", "human:test");
    assert.equal(no.proposal.status, "denied");
    assert.equal((await open(r, r.pgpass, "/usr/bin/ssh-add", "p-3")).verdict, "raw");
    assert.ok((await readersInForce(r, r.pgpass)).some(isPin("/usr/bin/ssh-add")));
    const text = readFileSync(r.policy, "utf8");
    keepsComments(text);
    assert.ok(!text.includes("db.example.com"), "the declined binding is not in the file");
  } finally {
    await r.close();
  }
});
