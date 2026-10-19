/**
 * goose-login.test — a Goose login saved by `goose configure` under
 * `mandu goose` (supported-agents.md §5.6.1): the REAL goose binary, the
 * REAL launcher (`main()`), the real arbiter and anthropic-proxy, and a
 * scripted upstream that records the `x-api-key` header of every request.
 * A made-up key, never a real one. No guard here (MANDU_NO_KERNEL=1, the
 * twin bind where the host has one); the guarded half is
 * test/kernel/goose-keyring.test.ts. Self-SKIPs without a goose binary.
 *
 *   secrets.yaml  Goose's own key file (GOOSE_DISABLE_KEYRING), in the
 *                 posture a launch keeps when it cannot bind the key to the
 *                 provider's host (here: MANDU_AUTH_SUBSTITUTION=0; the
 *                 default twin is goose-auth-substitution.test.ts): the key
 *                 is a catalog secret (`secrets.yaml`), so a plain twin put
 *                 `$MDU:…ANTHROPIC_API_KEY` where the key was and Goose sent
 *                 THAT as its key (every turn a 401). This posture
 *                 registers the file but leaves it readable to Goose:
 *                 the upstream gets the key, and (SECURITY) a shell `cat` of
 *                 the file, by name or by a glob, reaches the model with the
 *                 key masked: no request body carries it;
 *   no login      GOOSE_DISABLE_KEYRING, no file, no variable: the launch
 *                 prints the one "no Goose login found" line naming
 *                 ANTHROPIC_API_KEY and `GOOSE_DISABLE_KEYRING=1 goose
 *                 configure`, and nothing reaches the upstream;
 *   doctor        `mandu doctor`'s keyring question against a private
 *                 session bus with the Secret Service mock: it finds Goose's
 *                 item by SearchItems and never opens a session or reads a
 *                 secret (self-SKIPs without dbus-daemon, dbus-send and
 *                 python3's dbus and gi modules).
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { stateAxes } from "../axes.js";
import { FAKE_KEY, findGoose, gooseHome, gooseSkip, launchGoose, secretServiceSkip, startSecretService, startStand, type Stand } from "../lib/goose-login-stand.js";
import { GOOSE_KEYRING_ATTRS, realGooseKeyringItem } from "../../src/agent-login.js";

stateAxes("secrets"); // the shipped default: the key file is a catalog secret only with confidentiality on

const GOOSE = findGoose();
const SKIP = gooseSkip(GOOSE);

let stand: Stand;
before(async () => { if (!SKIP) stand = await startStand("mdu-goose-login-"); });
after(async () => { await stand?.close(); });

test("secrets.yaml login: Goose sends its real key (never a placeholder), and the file's key never reaches the model through a tool", { skip: SKIP, timeout: 300_000 }, async () => {
  const { home, secrets } = gooseHome(stand, "h-file", `ANTHROPIC_API_KEY: ${FAKE_KEY}\n`);
  // By name; by a glob; and with no word of the path in the command at all
  // (only the registered value can mask that one).
  for (const command of [`cat ${secrets}`, "cat ~/.config/goo?e/secr*.yaml", "for f in ~/.config/*/*; do cat \"$f\"; done"]) {
    stand.seen.length = 0;
    stand.command = command;
    // The agent's-own-key-file posture, which a launch keeps when it cannot
    // bind the key to the provider's host (or is told not to): the default
    // twins the file and puts the key back at the proxy
    // (goose-auth-substitution.test.ts, agent-sign-in.md §3).
    const { code, lines } = await launchGoose(GOOSE!, stand, home, { GOOSE_DISABLE_KEYRING: "1", MANDU_AUTH_SUBSTITUTION: "0" }, { kernel: false });
    assert.equal(code, 0, `goose under Mandu exited 0 (${command}):\n${lines.join("\n")}`);
    assert.ok(stand.seen.length >= 2, `the turns reached the upstream (${stand.seen.length})`);
    for (const q of stand.seen) {
      assert.equal(q.key, FAKE_KEY, `x-api-key is the key from secrets.yaml, not a placeholder (${q.key?.slice(0, 24)}…)`);
      assert.ok(!q.body.includes(FAKE_KEY), `INVARIANT: no model request carries the key (${command})`);
      assert.ok(!q.body.includes("MANDUFAKEgoose"), `INVARIANT: not even a piece of it (${command})`);
    }
    const last = stand.seen.at(-1)!.body;
    assert.match(last, /tool_result/, "the shell's result went back to the model");
    assert.match(last, /\$MDU:/, `the key in it went as a placeholder: ${last.slice(last.indexOf("tool_result"), last.indexOf("tool_result") + 400)}`);
    assert.ok(lines.some((l) => l.includes(secrets) && /agent's own key file/.test(l)), `the launch named the file it left readable:\n${lines.join("\n")}`);
    assert.ok(!lines.some((l) => /no Goose login found/.test(l)), "no login warning: the file is a login");
  }
});

test("no login at all (keyring off, no file, no variable): one plain line names both fixes, and nothing reaches the upstream", { skip: SKIP, timeout: 120_000 }, async () => {
  const { home } = gooseHome(stand, "h-none");
  stand.seen.length = 0;
  stand.command = null;
  const { code, lines } = await launchGoose(GOOSE!, stand, home, { GOOSE_DISABLE_KEYRING: "1" }, { kernel: false });
  assert.notEqual(code, 0, "goose cannot log in");
  const note = lines.filter((l) => /no Goose login found/.test(l));
  assert.equal(note.length, 1, lines.join("\n"));
  assert.match(note[0]!, /ANTHROPIC_API_KEY/);
  assert.match(note[0]!, /GOOSE_DISABLE_KEYRING=1 goose configure/);
  assert.equal(stand.seen.length, 0, "no request reached the upstream");
});

const SS_SKIP = process.platform !== "linux" ? "the Secret Service is Linux's" : (secretServiceSkip() || (spawnSync("dbus-send", ["--help"]).error ? "no dbus-send" : false));

test("doctor's keyring question (realGooseKeyringItem) against a real D-Bus Secret Service: found / none / cannot ask, and it never reads a secret", { skip: SS_SKIP, timeout: 60_000 }, async () => {
  const ss = await startSecretService(FAKE_KEY);
  try {
    const ask = realGooseKeyringItem({ PATH: process.env["PATH"], DBUS_SESSION_BUS_ADDRESS: ss.address });
    assert.equal(ask(GOOSE_KEYRING_ATTRS), true, "Goose's item is there");
    assert.equal(ask({ service: "goose", username: "nobody" }), false, "no such item");
    assert.ok(ss.calls().some((c) => c.startsWith("Service.SearchItems")), ss.calls().join("\n"));
    assert.ok(!ss.calls().some((c) => /GetSecret|Unlock|OpenSession/.test(c)), `EXISTENCE ONLY: ${ss.calls().join(", ")}`);
  } finally {
    await ss.close();
  }
  assert.equal(realGooseKeyringItem({ PATH: process.env["PATH"], DBUS_SESSION_BUS_ADDRESS: "unix:path=/nonexistent/mandu-bus" })(GOOSE_KEYRING_ATTRS), null, "no bus: cannot tell");
  assert.equal(realGooseKeyringItem({ PATH: process.env["PATH"] })(GOOSE_KEYRING_ATTRS), null, "no bus address: not asked");
});
