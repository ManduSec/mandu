/**
 * e2e — the value backstop's value-only release
 * (docs/design/confidentiality/backstop-value-only.md), through the
 * PRODUCTION wiring: the model proxy's adapter over the data and human
 * sockets of a real ArbiterServer, `secrets` axes, the guard's reports on the
 * human socket.
 *
 * The shape (demo-api-401-debug's old payments log): a `no-model` .env
 * holding a Stripe key is registered; the agent reads an UNLABELLED log in
 * which old debug lines printed the same key. Before, the whole log reached
 * the model as one symbol; now, when the call read no secret, the log
 * reaches it with the key as the .env's own field symbol.
 *
 * Proves:
 *   1. a clean `cat` and a Read of the log: the log as it is, each copy of
 *      the key replaced by the field symbol the .env's twin shows;
 *   2. fail closed, masked whole: the log also carrying the key base64'd, a
 *      12-character prefix of it, or a `$MDU` token; a call whose tree read a
 *      labelled file raw; a `cat` that names the .env itself;
 *   3. THE ORACLE: no request to the model carries the key in any form this
 *      test knows (verbatim, base64 at each alignment, hex, reversed, rot13,
 *      any 8-character piece);
 *   4. (2026-10-18, the demo's log now prints the database URL) a URL's
 *      password in the .env is its own row: a log printing the URL gets that
 *      span alone as the `DATABASE_URL.password` symbol, the URL readable;
 *      a log printing the .env's own `DATABASE_URL=` line is a copy of the
 *      file, masked whole; no form of the password reaches the model;
 *   5. a recorded HTTP test fixture (2026-10-18) whose sign-in body holds a
 *      labelled .env's ordinary password: a Read comes back with the
 *      password as its field symbol and the JSON as it is; a diff of it
 *      beside the re-recording's placeholder is masked whole; the same
 *      oracle over the password.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

const KEY = "sk_test_ValueOnlyE2E7Kq2Xr9Lm4Tz8";
const VAULT = "VAULT_NOTE_CANARY_9431_do_not_show";
const LOG = [
  "[2026-10-16 08:00:01] check-payments (cron, DEBUG=1) release 1.8.3",
  `DEBUG: Authorization: Bearer ${KEY}`,
  "[2026-10-16 08:00:02] ok: Stripe balance HTTP 200",
  "[2026-10-16 14:00:01] check-payments (cron, DEBUG=1) release 1.8.3",
  `DEBUG: Authorization: Bearer ${KEY}`,
  "[2026-10-16 19:42:10] deploy: release 1.9.0",
  "payments: warning: STRIPE_KEY is empty",
  "[2026-10-16 20:00:02] FAILED: Stripe balance HTTP 401",
  "",
].join("\n");
const ONE_SYMBOL = /^\$MDU:nomodel_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\](?:\n\n\[mandu:secret\] [^\n]*)*$/;

/** The forms of the key this test looks for, independent of the arbiter's. */
function keyForms(v: string): string[] {
  const out = [v, Buffer.from(v).toString("hex"), [...v].reverse().join(""),
    v.replace(/[a-z]/gi, (c) => { const b = c <= "Z" ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b); })];
  for (let pad = 0; pad < 3; pad++) {
    const b64 = Buffer.from("x".repeat(pad) + v).toString("base64").replace(/=+$/, "");
    out.push(b64.slice(pad === 0 ? 0 : pad + 1, b64.length - 1));
  }
  for (let i = 0; i + 8 <= v.length; i++) out.push(v.slice(i, i + 8));
  return out;
}

function req(name: string, input: Record<string, unknown>, content: string, id: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "payments broke last night; here is yesterday's log" },
      { role: "assistant", content: [{ type: "tool_use", id, name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  };
}
const forwarded = (r: MessagesRequest): string => ((r.messages[2]!.content as Array<{ content: string }>)[0]!.content);

test("secrets: an old log holding a registered key reaches the model with the key as its symbol when the call read no secret; every other case is masked whole", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-value-only-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws");
  mkdirSync(join(ws, "shop-app", "logs"), { recursive: true });
  mkdirSync(join(ws, "vault"), { recursive: true });
  const env = join(ws, "shop-app", ".env");
  writeFileSync(env, `STRIPE_SECRET_KEY=${KEY}\nPORT=4242\n`);
  const vault = join(ws, "vault", "notes.txt");
  writeFileSync(vault, `${VAULT}\n`);
  const log = join(ws, "shop-app", "logs", "payments-2026-10-16.log"); // unlabelled
  writeFileSync(log, LOG);

  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", bindings: ["api.stripe.com"] }, { path: vault, level: "no-model", readers: [{ app: "mytool", prints: "nothing" }] }] } as never,
  });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const realHuman = new ArbiterClient(human); await realHuman.connect();
  const real: RealArbiterClient = new ArbiterClient(sock); await real.connect();
  const claude = new ArbiterClientAdapter(real, realHuman);
  const session = "s-value-only";
  const sent: string[] = [];
  let roots = 0;
  const shellFor = async (command: string, child: string, callId: string): Promise<void> => {
    const root = `sh-${++roots}`;
    await claude.recordCallCommand!({ callId, command, sessionKey: session });
    await guard.recordExecRoot({ procKey: root, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true });
    await guard.processLineage({ childKey: child, parentKey: root, session });
  };
  const through = async (r: MessagesRequest): Promise<string> => {
    const out = await rewriteRequest(r, { arbiter: claude, sessionKey: session });
    sent.push(JSON.stringify(out.request));
    return forwarded(out.request);
  };
  try {
    const reg = await guard.registerSecret({ path: env, home, sessionKey: session });
    const field = /STRIPE_SECRET_KEY='?(\$MDU:nomodel_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\](?:\.[A-Za-z0-9_.]+)?)/.exec(reg.twin ?? "")?.[1];
    assert.ok(field, `the .env has a field symbol in its twin: ${reg.twin} (${reg.reason})`);
    await guard.registerSecret({ path: vault, home, sessionKey: session });

    // ── 1. the release: a clean cat, and a Read
    const cat = "cat shop-app/logs/payments-2026-10-16.log";
    await shellFor(cat, "cat-1", "tu_cat");
    const got = await through(req("Bash", { command: cat }, LOG, "tu_cat"));
    assert.equal(got, LOG.split(KEY).join(field), `the log, the key as the .env's field symbol: ${got}`);
    const rendered = LOG.split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");
    const read = await through(req("Read", { file_path: log }, rendered, "tu_read"));
    assert.equal(read, rendered.split(KEY).join(field), `the Read, the same: ${read}`);

    // ── 2. fail closed: masked whole
    const whole: Array<[string, string, string, string]> = [
      ["base64 copy", "tu_b64", cat, `${LOG}token-b64: ${Buffer.from(KEY).toString("base64")}\n`],
      ["base64 wrapped at 20 columns", "tu_b64w", cat, `${LOG}${Buffer.from(`ab${KEY}`).toString("base64").match(/.{1,20}/g)!.join("\n")}\n`],
      ["hex wrapped at 30 columns", "tu_hexw", cat, `${LOG}${Buffer.from(KEY).toString("hex").match(/.{1,30}/g)!.join("\n")}\n`],
      // `od -c` of the key (looking for a stray CR): a form this test's own
      // oracle below does not know, so it is checked here by the mask itself
      ["od -c of the key", "tu_odc", cat, `${LOG}${(KEY.match(/.{1,16}/g) ?? []).map((l, i) => `${(i * 16).toString(8).padStart(7, "0")} ${[...l].map((ch) => `   ${ch}`).join("")}`).join("\n")}\n`],
      ["a 12-character prefix", "tu_prefix", cat, `${LOG}rotated from ${KEY.slice(0, 12)}…\n`],
      ["a $MDU token", "tu_mdu", cat, `${LOG}see $MDU:nomodel_Read[abcd]\n`],
    ];
    for (const [name, id, command, output] of whole) {
      await shellFor(command, `cat-${id}`, id);
      const t = await through(req("Bash", { command }, output, id));
      assert.match(t, ONE_SYMBOL, `${name}: masked whole: ${t}`);
      assert.ok(!t.includes("ok: Stripe balance"), `${name}: no byte of the log`);
    }
    // a call whose tree read a labelled file raw
    const tainted = `mytool vault/notes.txt; ${cat}`;
    await shellFor(tainted, "mytool-1", "tu_taint");
    const open = await guard.decideSecretOpen({ path: vault, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "mytool-1", session, ask: "known" });
    assert.equal(open.verdict, "raw", `the tool reads the vault raw: ${open.reason}`);
    const t = await through(req("Bash", { command: tainted }, `${VAULT}\n${LOG}`, "tu_taint"));
    assert.match(t, ONE_SYMBOL, `a tainted call is masked whole: ${t}`);
    assert.ok(!t.includes(VAULT) && !t.includes("ok: Stripe balance"), t);
    // a cat of the .env itself (path-derived)
    await shellFor("cat shop-app/.env", "cat-env", "tu_env");
    const e = await through(req("Bash", { command: "cat shop-app/.env" }, `STRIPE_SECRET_KEY=${KEY}\nPORT=4242\n`, "tu_env"));
    assert.match(e, ONE_SYMBOL, `the .env itself is masked whole: ${e}`);

    // ── 3. THE ORACLE
    const forms = keyForms(KEY);
    for (const s of sent) {
      for (const f of forms) assert.ok(!s.includes(f), `CONFIDENTIALITY VIOLATION: a form of the key reached the model: ${f}`);
      assert.ok(!s.includes(VAULT), "the vault note never reaches the model");
    }
  } finally {
    for (const c of [guard, realHuman, real as ArbiterClient]) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// demo-api-401-debug's log since 2026-10-18: the debug lines print the
// settings, the key redacted by name, but the database URL with its
// password, which no pattern tool finds. The .env's URL password is its own
// registered row (`DATABASE_URL.password`, the URL around it readable), so
// the release swaps that one span and leaves the URL, host and all.
const DB_PASSWORD = "Copper-Kettle-4471-Brook";
const DB_URL = `postgres://shop:${DB_PASSWORD}@db.shop-app.test:5432/shop`;
const SETTINGS_LOG = [
  "[2026-10-16 08:00:01] check-payments (cron, DEBUG=1) release 1.8.3",
  `DEBUG: settings: STRIPE_SECRET_KEY: [redacted], DATABASE_URL: ${DB_URL}, PORT: 4242`,
  "DEBUG: Authorization: Bearer [redacted, 33 characters]",
  "[2026-10-16 08:00:02] ok: Stripe balance HTTP 200",
  "[2026-10-16 20:00:01] check-payments (cron, DEBUG=1) release 1.9.0",
  `DEBUG: settings: STRIPE_SECRET_KEY: [redacted], DATABASE_URL: ${DB_URL}, PORT: 4242`,
  "DEBUG: Authorization: Bearer [empty]",
  "[2026-10-16 20:00:02] FAILED: Stripe balance HTTP 401",
  "",
].join("\n");

test("secrets: an old log printing the .env's database URL reaches the model with the URL's password as its own field symbol, the URL readable", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-value-only-url-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws");
  mkdirSync(join(ws, "shop-app", "logs"), { recursive: true });
  const env = join(ws, "shop-app", ".env");
  writeFileSync(env, `STRIPE_SECRET_KEY=${KEY}\nDATABASE_URL=${DB_URL}\nPORT=4242\n`);
  writeFileSync(join(ws, "shop-app", "logs", "payments-2026-10-16.log"), SETTINGS_LOG); // unlabelled
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", bindings: ["api.stripe.com"] }] } as never,
  });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const realHuman = new ArbiterClient(human); await realHuman.connect();
  const real: RealArbiterClient = new ArbiterClient(sock); await real.connect();
  const claude = new ArbiterClientAdapter(real, realHuman);
  const session = "s-value-only-url";
  const sent: string[] = [];
  try {
    const reg = await guard.registerSecret({ path: env, home, sessionKey: session });
    const field = /DATABASE_URL='?postgres:\/\/shop:(\$MDU:nomodel_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\][A-Za-z0-9_.]*)@/.exec(reg.twin ?? "")?.[1];
    assert.ok(field, `the .env's twin has the URL's password as a field symbol: ${reg.twin} (${reg.reason})`);
    const cat = "cat shop-app/logs/payments-2026-10-16.log";
    await claude.recordCallCommand!({ callId: "tu_cat", command: cat, sessionKey: session });
    await guard.recordExecRoot({ procKey: "sh-1", ancestors: ["agent-0"], argv: ["/bin/bash", "-c", cat], session, callRoot: true });
    await guard.processLineage({ childKey: "cat-1", parentKey: "sh-1", session });
    const out = await rewriteRequest(req("Bash", { command: cat }, SETTINGS_LOG, "tu_cat"), { arbiter: claude, sessionKey: session });
    sent.push(JSON.stringify(out.request));
    const got = forwarded(out.request);
    assert.equal(got, SETTINGS_LOG.split(DB_PASSWORD).join(field), `the log, the password as the .env's field symbol: ${got}`);
    assert.ok(got.includes("@db.shop-app.test:5432/shop"), "the URL around it stays readable");
    // fail closed: a log that prints the .env's own line (`DATABASE_URL=…`)
    // holds a line of the registered file, a copy of it: masked whole (A4)
    const copy = SETTINGS_LOG.replace(`DATABASE_URL: ${DB_URL},`, `DATABASE_URL=${DB_URL}`);
    await claude.recordCallCommand!({ callId: "tu_copy", command: cat, sessionKey: session });
    await guard.recordExecRoot({ procKey: "sh-2", ancestors: ["agent-0"], argv: ["/bin/bash", "-c", cat], session, callRoot: true });
    await guard.processLineage({ childKey: "cat-2", parentKey: "sh-2", session });
    const whole = await rewriteRequest(req("Bash", { command: cat }, copy, "tu_copy"), { arbiter: claude, sessionKey: session });
    sent.push(JSON.stringify(whole.request));
    assert.match(forwarded(whole.request), ONE_SYMBOL, "the .env's line verbatim: masked whole");
    // THE ORACLE: no form of the password reached the model
    for (const s of sent) for (const f of keyForms(DB_PASSWORD)) assert.ok(!s.includes(f), `CONFIDENTIALITY VIOLATION: a form of the password reached the model: ${f}`);
  } finally {
    for (const c of [guard, realHuman, real as ArbiterClient]) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// A recorded HTTP test fixture (2026-10-18, demo-refund-fixture's shape): a
// nock-style recording made before anyone filtered it, whose sign-in call's
// JSON body holds the sandbox password of a labelled .env. The password is an
// ordinary one (a `!`, hyphens, digits), the user name a plain word the twin
// leaves raw. A Read of the recording reaches the model with the password as
// the .env field's own symbol, the rest of the JSON as it is; the
// re-recording's copy, which holds that placeholder, beside the old one (a
// diff of the two) is masked whole (A3: `$MDU` text in the result).
const PASSWORD = "Wren!Basalt-7720-Ferry";
const RECORDING = `${JSON.stringify([
  { scope: "https://sandbox.payments.test:443", method: "POST", path: "/v1/sessions", body: { username: "ci-refunds", password: PASSWORD }, status: 200, response: { session: "sess_sbx_1" } },
  { scope: "https://sandbox.payments.test:443", method: "POST", path: "/v1/refunds", body: { charge: "ch_1", amount: 1250 }, status: 200, response: { id: "re_1", status: "succeeded" } },
], null, 2)}\n`;

test("secrets: a recorded test fixture holding a registered password in a JSON body reaches the model with the password as its symbol; beside a placeholder it is masked whole", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-value-only-rec-"));
  const home = join(tmp, "home");
  const svc = join(home, "ws", "refunds");
  mkdirSync(join(svc, "test", "fixtures"), { recursive: true });
  const env = join(svc, ".env");
  writeFileSync(env, `PAYMENTS_USER=ci-refunds\nPAYMENTS_PASSWORD=${PASSWORD}\n`);
  const rec = join(svc, "test", "fixtures", "refund.json"); // unlabelled
  writeFileSync(rec, RECORDING);

  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", bindings: ["sandbox.payments.test"] }] } as never,
  });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const realHuman = new ArbiterClient(human); await realHuman.connect();
  const real: RealArbiterClient = new ArbiterClient(sock); await real.connect();
  const claude = new ArbiterClientAdapter(real, realHuman);
  const session = "s-value-only-rec";
  const sent: string[] = [];
  const through = async (r: MessagesRequest): Promise<string> => {
    const out = await rewriteRequest(r, { arbiter: claude, sessionKey: session });
    sent.push(JSON.stringify(out.request));
    return forwarded(out.request);
  };
  try {
    const reg = await guard.registerSecret({ path: env, home, sessionKey: session });
    const field = /PAYMENTS_PASSWORD='?(\$MDU:nomodel_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\](?:\.[A-Za-z0-9_.]+)?)/.exec(reg.twin ?? "")?.[1];
    assert.ok(field, `the .env has a field symbol in its twin: ${reg.twin} (${reg.reason})`);
    assert.match(reg.twin ?? "", /^PAYMENTS_USER=ci-refunds$/m, "the plain user name stays raw in the twin");

    // the Read of the recording: the password as its field symbol, the rest as it is
    const rendered = RECORDING.split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");
    const read = await through(req("Read", { file_path: rec }, rendered, "tu_rec"));
    assert.equal(read, rendered.split(PASSWORD).join(field), `the recording, the password as the .env's field symbol: ${read}`);
    assert.match(read, /"username": "ci-refunds"/);

    // the new recording beside the old one (a diff): `$MDU` text in the result, masked whole
    const diff = `-      "password": "${PASSWORD}"\n+      "password": "${field}"\n`;
    const d = await through(req("Read", { file_path: join(svc, "refund.diff") }, diff, "tu_diff"));
    assert.match(d, ONE_SYMBOL, `the diff is masked whole: ${d}`);

    // THE ORACLE: no form of the password reached the model
    for (const s of sent) for (const f of keyForms(PASSWORD)) assert.ok(!s.includes(f), `CONFIDENTIALITY VIOLATION: a form of the password reached the model: ${f}`);
  } finally {
    for (const c of [guard, realHuman, real as ArbiterClient]) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
