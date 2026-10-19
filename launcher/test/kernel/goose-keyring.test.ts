/**
 * goose-keyring.test — a Goose login saved by `goose configure` under a
 * GUARDED `mandu goose` (supported-agents.md §5.6.1): the REAL goose, the
 * REAL launcher (`main()`), the REAL mandu-net-guard, the real arbiter and
 * proxy, a scripted upstream that records `x-api-key`. Made-up keys only.
 *
 *   keyring       Goose's key only in the system keyring (no variable, no
 *                 secrets.yaml, the keyring on). The CONTROL runs the same
 *                 goose without Mandu against a private session bus: with
 *                 the Secret Service mock (test/fixtures/secret-service-
 *                 mock.py) it reads the key and sends it, so the mock is a
 *                 working keyring; without python3-dbus a bare listener only
 *                 counts that goose dialed the bus (a connection that
 *                 speaks: the guard's own silent probe of who listens is
 *                 not one). Under the guard, the
 *                 session bus is not on the agent's Unix socket allow-list
 *                 (unix-policy.ts), so Goose never reaches it: the mock
 *                 answers no call (or the listener counts no connection),
 *                 nothing reaches the upstream, and the launch printed the
 *                 one line naming ANTHROPIC_API_KEY and
 *                 `GOOSE_DISABLE_KEYRING=1 goose configure`;
 *   secrets.yaml  the file login with the guard serving opens: the launch
 *                 binds the key to the (loopback) upstream, so Goose's open
 *                 gets the twin and sends the placeholder, and the proxy puts
 *                 the key back in `x-api-key` (agent-sign-in.md §3; the
 *                 unguarded half is test/component/goose-auth-substitution.test.ts):
 *                 the upstream gets the key; a shell read of the file
 *                 reaches the model masked.
 *
 * Self-SKIPs without goose, or where the guard is not built or does not come
 * up live (the reason is printed).
 */
import { test, before, after, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { stateAxes } from "../axes.js";
import {
  FAKE_KEY, findGoose, gooseHome, gooseSkip, launchGoose, runGooseBare, secretServiceSkip, startCountingBus, startSecretService,
  startStand, type Stand,
} from "../lib/goose-login-stand.js";
import { resolveNativeBin } from "../../src/services/native-bins.js";

stateAxes("secrets"); // the shipped default; the Unix socket allow-list is part of the confidentiality axis

const GOOSE = findGoose();
const GUARD = process.platform === "linux" ? resolveNativeBin("mandu-net-guard") : null;
const SKIP = gooseSkip(GOOSE) || (GUARD === null ? "mandu-net-guard is not built (scripts/build-native.sh)" : false);
const MOCK_SKIP = secretServiceSkip();

let stand: Stand;
before(async () => { if (!SKIP) stand = await startStand("mdu-goose-kr-"); });
after(async () => { await stand?.close(); });

/** The guard really came up around the launch (else the test says so and skips). */
function guardLive(t: TestContext, lines: string[]): boolean {
  if (lines.some((l) => /net-guard LIVE/.test(l))) return true;
  t.skip(`the guard did not come up live on this host:\n${lines.filter((l) => /guard|WARNING/.test(l)).join("\n")}`);
  return false;
}

test("keyring-only login, guarded: Goose never reaches the session bus, nothing goes upstream, and the launch names both fixes", { skip: SKIP, timeout: 300_000 }, async (t) => {
  const { home } = gooseHome(stand, "h-keyring");
  stand.command = null;
  const mock = MOCK_SKIP ? null : await startSecretService(FAKE_KEY);
  const counting = mock === null ? await startCountingBus() : null;
  const address = mock?.address ?? counting!.address;
  try {
    // CONTROL: the same goose without Mandu reaches the bus.
    stand.seen.length = 0;
    const bare = await runGooseBare(GOOSE!, stand, home, { DBUS_SESSION_BUS_ADDRESS: address });
    if (mock !== null) {
      assert.equal(bare.code, 0, `goose read its key from the mock keyring (stderr: ${bare.stderr})`);
      assert.ok(mock.calls().some((c) => c.startsWith("Item.GetSecret")), mock.calls().join("\n"));
      assert.ok(stand.seen.length > 0 && stand.seen.every((q) => q.key === FAKE_KEY), "without Mandu the keyring's key went upstream");
    } else {
      assert.ok(counting!.connections() > 0, "without Mandu goose dialed the session bus");
      t.diagnostic(`Secret Service mock skipped: ${MOCK_SKIP}; a counting listener stands in for the bus`);
    }
    const before = mock?.calls().length ?? 0;
    const connectionsBefore = counting?.connections() ?? 0;

    // Under the guard.
    stand.seen.length = 0;
    const { code, lines } = await launchGoose(GOOSE!, stand, home, { DBUS_SESSION_BUS_ADDRESS: address }, { kernel: true, netGuardBin: GUARD! });
    if (!guardLive(t, lines)) return;
    assert.notEqual(code, 0, "goose could not log in");
    const note = lines.filter((l) => /Goose would read its key from the system keyring/.test(l));
    assert.equal(note.length, 1, lines.join("\n"));
    assert.match(note[0]!, /ANTHROPIC_API_KEY/);
    assert.match(note[0]!, /GOOSE_DISABLE_KEYRING=1 goose configure/);
    assert.equal(stand.seen.length, 0, "no request reached the upstream");
    if (mock !== null) assert.deepEqual(mock.calls().slice(before), [], "the Secret Service never heard from goose under the guard");
    else assert.equal(counting!.connections(), connectionsBefore, "the bus never saw goose under the guard");
  } finally {
    await mock?.close();
    await counting?.close();
  }
});

test("secrets.yaml login, guarded: the real key goes upstream, and a shell read of the file reaches the model masked", { skip: SKIP, timeout: 300_000 }, async (t) => {
  const { home, secrets } = gooseHome(stand, "h-file", `ANTHROPIC_API_KEY: ${FAKE_KEY}\n`);
  stand.seen.length = 0;
  stand.command = `cat ${secrets}`;
  const { code, lines } = await launchGoose(GOOSE!, stand, home, { GOOSE_DISABLE_KEYRING: "1" }, { kernel: true, netGuardBin: GUARD! });
  if (!guardLive(t, lines)) return;
  assert.equal(code, 0, lines.join("\n"));
  assert.ok(stand.seen.length >= 2, `the turns reached the upstream (${stand.seen.length})`);
  for (const q of stand.seen) {
    assert.equal(q.key, FAKE_KEY, "x-api-key is the key from secrets.yaml");
    assert.ok(!q.body.includes(FAKE_KEY), "INVARIANT: no model request carries the key");
  }
  assert.match(stand.seen.at(-1)!.body, /\$MDU:/, "the shell's read of the file went to the model as a placeholder");
  assert.ok(!lines.some((l) => /system keyring/.test(l)), "no keyring line: the file is the login");
});
