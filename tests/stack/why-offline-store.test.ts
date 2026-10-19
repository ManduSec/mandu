/**
 * why-offline-store e2e — `mandu why` with NO Mandu running reads what the
 * stopped arbiter kept (comparisons.md §3.2; arbiter/db/store-seed.ts;
 * launcher/src/why.ts `whyArbiter`), over the production path end to end:
 * the launcher's `realWhyDeps()` finds no resident arbiter, spawns its
 * temporary arbiter from the source tree with `--seed-from` the store a REAL
 * ArbiterServer wrote and closed, and asks it.
 *
 *   - the answer is the one the running arbiter gave, byte for byte: the
 *     remembered Always allow decides `--to` ("released by your remembered
 *     answer"), the hand edit still waiting in Approvals is named, and the
 *     law in force (not the held edit) is what the file reads as;
 *   - the store is only read: its bytes and policy.yaml are unchanged,
 *     nothing is created beside it (on a Node whose SQLite takes no URI,
 *     22.13, only the empty WAL and index any SQLite reader creates), and
 *     no value appears in any answer;
 *   - policy.yaml holding bytes the human DECLINED (written back while Mandu
 *     was stopped) is answered as the law in force, and `mandu why` does not
 *     write the file back (the next start does);
 *   - with no store at all the answer is the one of before: the remembered
 *     answers were not consulted, and it says so.
 *
 * Secrets axes (confidentiality ON, integrity OFF), stated below; the
 * temporary arbiter pins them itself.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { runWhy, realWhyDeps, residentStorePath, SEEDED_NOTE, THROWAWAY_NOTE } from "../../launcher/src/why.js";
import { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the servers pin them below

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VALUE = "sk_live_WHYOFFLINE_0123456789";

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function waitFor<T>(what: string, probe: () => Promise<T | undefined>): Promise<T> {
  for (let i = 0; i < 300; i++) {
    const v = await probe();
    if (v !== undefined) return v;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`timed out waiting for ${what}`);
}

/** The law: .env a secret, bound to Stripe or nowhere. */
const law = (env: string, bound: boolean): string => `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n${bound ? "    bindings: [api.stripe.com]\n" : ""}`;

interface Home { dir: string; home: string; proj: string; env: string; store: string; policy: string; rt: string }

function setup(): Home {
  const dir = mkdtempSync(join(tmpdir(), "mdu-why-offline-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  mkdirSync(join(home, ".mandu", "state"), { recursive: true, mode: 0o700 });
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const rt = join(dir, "rt");
  mkdirSync(rt, { mode: 0o700 });
  const env = join(proj, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const policy = join(home, ".mandu", "policy.yaml");
  writeFileSync(policy, law(env, false));
  return { dir, home, proj, env, store: join(home, ".mandu", "state", "mandu.db"), policy, rt };
}

/** The resident arbiter as the stack runs it: its store and policy file
 *  where `mandu why` looks for them, the hand-edit poll on. */
async function resident(h: Home) {
  const sock = join(h.dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(h.dir, "human", "h.sock"), adminSocketPath: join(h.dir, "admin.sock"),
    dbPath: h.store, eventDir: join(h.dir, "events"), policyPath: h.policy, policyPollMs: 30,
    confidentiality: true, integrity: false, log: () => {},
  });
  await server.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(join(h.dir, "human", "h.sock")); await human.connect();
  const admin = new ArbiterClient(join(h.dir, "admin.sock")); await admin.connect();
  return {
    sock, data, human, admin,
    close: async () => { data.close(); human.close(); admin.close(); await server.close(); },
  };
}

/** `mandu why` over the production deps; `sock` pins a running arbiter
 *  (the live answer), else none runs and the CLI finds its own. stdout
 *  through runWhy's sink; stderr collected (the notes). */
async function why(h: Home, args: string[], sock?: string): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const deps = {
    ...realWhyDeps(), cwd: () => h.proj, out: (s: string) => { out.push(s); },
    ...(sock !== undefined ? { arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }) } : {}),
  };
  const env = {
    HOME: h.home, PATH: process.env["PATH"] ?? "/usr/bin:/bin", TMPDIR: h.dir, MANDU_RUNTIME_DIR: h.rt,
    // Nothing answers here: the CLI's own lookup finds no resident arbiter.
    MANDU_ARBITER_SOCK: join(h.dir, "nobody.sock"),
  };
  const ew = process.stderr.write.bind(process.stderr);
  (process.stderr as unknown as { write: (s: string) => boolean }).write = (s) => { err.push(String(s)); return true; };
  try {
    const code = await runWhy(args, env, Layout.dev(REPO), deps);
    return { code, out: out.join(""), err: err.join("") };
  } finally {
    (process.stderr as unknown as { write: typeof ew }).write = ew;
  }
}

const sha = (p: string): string => createHash("sha256").update(readFileSync(p)).digest("hex");

/** Does this node's SQLite open a URI filename? Probed on the closed store
 *  itself, immutable and read-only: the probe creates nothing either way. */
function sqliteTakesUris(store: string): boolean {
  try {
    new DatabaseSync(`${pathToFileURL(store).href}?mode=ro&immutable=1`, { readOnly: true }).close();
    return true;
  } catch {
    return false;
  }
}

test("no Mandu running [secrets]: mandu why answers from the stopped arbiter's store, as the running one did, and only reads it", async () => {
  const h = setup();
  assert.equal(residentStorePath({ HOME: h.home }), h.store, "where the resident arbiter keeps its store");
  const a = await resident(h);
  const live: Record<string, string> = {};
  const asks = [[".env"], [".env", "--to", "collector.example"], ["api.stripe.com"], ["collector.example"]];
  let cardId = "";
  try {
    // A launch registers .env; a real send asks the gate; the human answers
    // Always allow on the dashboard's channel.
    const twin = (await a.data.registerSecret({ path: h.env })).twin ?? "";
    const field = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\]\.STRIPE_KEY/.exec(twin)?.[0];
    assert.ok(field, "the .env twin carries its field placeholder");
    const ask = await a.human.desymbolizationDecision({ symbol: field, boundary: "network", destination: "collector.example", sessionKey: "s-offline" });
    await a.admin.resolveEgressApproval((ask as { approvalId?: string }).approvalId!, true, "always");
    // The human (or anything that can write the file) binds .env to Stripe
    // by hand: the edit waits in Approvals.
    writeFileSync(h.policy, law(h.env, true));
    const card = await waitFor("the held card", async () => {
      const r = await a.admin.policyProposals("pending");
      return r.proposals.length ? r.proposals[0] : undefined;
    });
    cardId = card!.id;
    for (const args of asks) {
      const r = await why(h, args, a.sock);
      assert.equal(r.code, 0, r.out + r.err);
      live[args.join(" ")] = r.out;
    }
    assert.match(live[".env --to collector.example"]!, /send to collector\.example: released by your remembered answer/);
  } finally {
    await a.close();
  }

  // Mandu is stopped. What is beside the store, and its bytes, stay as they are.
  const beside = readdirSync(dirname(h.store)).sort();
  const storeBytes = sha(h.store);
  const policyBytes = readFileSync(h.policy, "utf8");

  for (const args of asks) {
    const r = await why(h, args);
    assert.equal(r.code, 0, r.out + r.err);
    assert.equal(r.out, live[args.join(" ")], `the answer the running arbiter gave (${args.join(" ")})`);
    assert.equal(r.err, SEEDED_NOTE, "it says where the answer came from");
    assert.doesNotMatch(r.out + r.err, new RegExp(VALUE), "never a value");
  }
  const file = live[".env"]!;
  assert.match(file, /may go to +no host/, "the law in force, not the held edit");
  assert.match(file, new RegExp(`waiting +a change to this file's rule waits for your OK in Approvals \\(${cardId}: policy\\.yaml was changed on disk\\)`));
  const to = live[".env --to collector.example"]!;
  assert.match(to, /send to collector\.example: released by your remembered answer \(verdict:/);
  assert.doesNotMatch(to, /not consulted/);
  assert.match(live["collector.example"]!, /decided +\$MDU:[A-Za-z_]+\[[0-9a-f]+\]\.STRIPE_KEY: approved \(always\)/, "the remembered answer, listed for its host");

  assert.equal(sha(h.store), storeBytes, "the store's bytes are unchanged");
  // Nothing new beside it where this SQLite takes a URI (the temporary
  // arbiter runs on this same node); else only the empty WAL and the index
  // any SQLite reader of a WAL database creates (Node 22.13).
  const now = readdirSync(dirname(h.store)).sort();
  if (sqliteTakesUris(h.store)) assert.deepEqual(now, beside, "nothing created or left beside the store");
  for (const f of now.filter((n) => !beside.includes(n))) {
    assert.ok(/^mandu\.db-(wal|shm)$/.test(f), `only a reader's WAL companions: ${f}`);
    assert.equal(statSync(join(dirname(h.store), f)).mode & 0o077, 0, `${f} is owner-only`);
    if (f.endsWith("-wal")) assert.equal(statSync(join(dirname(h.store), f)).size, 0, "an empty WAL: nothing written");
  }
  assert.equal(readFileSync(h.policy, "utf8"), policyBytes, "policy.yaml is unchanged");
});

test("no Mandu running [secrets]: declined bytes back in policy.yaml read as the law in force, and mandu why leaves the file as it is; with no store, the answer of before", async () => {
  const h = setup();
  const a = await resident(h);
  try {
    writeFileSync(h.policy, law(h.env, true));
    const card = await waitFor("the held card", async () => {
      const r = await a.admin.policyProposals("pending");
      return r.proposals.length ? r.proposals[0] : undefined;
    });
    await a.admin.resolvePolicyProposal(card!.id, "denied");
    await waitFor("the file restored", async () => (readFileSync(h.policy, "utf8") === law(h.env, false) ? true : undefined));
  } finally {
    await a.close();
  }
  // While Mandu is stopped the declined bytes come back (an editor's undo).
  writeFileSync(h.policy, law(h.env, true));
  const r = await why(h, [".env"]);
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /may go to +no host/, "the declined binding is not the law");
  assert.doesNotMatch(r.out, /waiting/, "a declined change waits for nothing");
  assert.equal(r.err, SEEDED_NOTE);
  assert.equal(readFileSync(h.policy, "utf8"), law(h.env, true), "mandu why changes nothing: the next start restores the file, not it");

  // No store: the temporary arbiter of before, and its notes.
  const bare = setup();
  const b = await why(bare, [".env", "--to", "collector.example"]);
  assert.equal(b.code, 0, b.out + b.err);
  assert.match(b.out, /your remembered answers were not consulted/);
  assert.equal(b.err, THROWAWAY_NOTE);
  assert.deepEqual(readdirSync(join(bare.home, ".mandu", "state")), [], "and no store is created");
});
