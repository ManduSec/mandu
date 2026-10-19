/**
 * goose-store-real.test — Goose's own session store under `mandu goose`
 * (supported-agents.md §5.6.2): the REAL goose binary, the REAL launcher
 * (`main()`), the real arbiter and anthropic-proxy, a scripted upstream, a
 * made-up key in Goose's own secrets.yaml (the stand of goose-login.test.ts).
 * No guard here (MANDU_NO_KERNEL=1). Self-SKIPs without a goose binary.
 *
 * `~/.local/share/goose` is in SENSITIVE_PATHS, in the catalog (`no-model`)
 * and in AGENT_STORES (never twinned). The unit and stack tests prove
 * the classification; this one proves the two halves together on the real
 * agent:
 *
 *   own store   a session (no `--no-session`) whose prompt carries a
 *               canary: Goose still writes its session store
 *               (`sessions/sessions.db`, with its `-wal`) and the canary is
 *               in it raw, as Goose wrote it (the wrap neither hid the
 *               directory nor handed Goose a copy);
 *   read back   a later session's `shell` reads that store: the canary does
 *               not reach the model (the result is masked);
 *   CONTROL     the same bytes copied into the project folder and read the
 *               same way DO reach the model (the probe is real: the masking
 *               is the store's place, not a value detector).
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { stateAxes } from "../axes.js";
import { FAKE_KEY, findGoose, gooseHome, gooseSkip, launchGoose, startStand, type Stand } from "../lib/goose-login-stand.js";

stateAxes("secrets"); // the shipped default: the store is a catalog location only with confidentiality on

const GOOSE = findGoose();
const SKIP = gooseSkip(GOOSE);
// Not secret-shaped on purpose: only the store's place can mask it.
const CANARY = "GOOSE-STORE-CANARY-58213";

let stand: Stand;
before(async () => { if (!SKIP) stand = await startStand("mdu-goose-store-"); });
after(async () => { await stand?.close(); });

/** The canary in any of the store's files (the db, its -wal), as written. */
function storeHolds(dir: string, text: string): boolean {
  if (!existsSync(dir)) return false;
  return readdirSync(dir).some((f) => f.startsWith("sessions.db") && readFileSync(join(dir, f)).includes(text));
}

test("Goose writes its own session store under mandu goose, and a later shell read of it reaches the model only masked", { skip: SKIP, timeout: 300_000 }, async () => {
  const { home } = gooseHome(stand, "h-store", `ANTHROPIC_API_KEY: ${FAKE_KEY}\n`);
  const env = { GOOSE_DISABLE_KEYRING: "1" };
  const sessions = join(home, ".local", "share", "goose", "sessions");

  // 1. A kept session: Goose writes its store, raw, under the wrap.
  stand.seen.length = 0;
  stand.command = null;
  const first = await launchGoose(GOOSE!, stand, home, env, { kernel: false, args: ["run", "-t", `remember the note ${CANARY}`] });
  assert.equal(first.code, 0, `goose under Mandu exited 0:\n${first.lines.join("\n")}`);
  assert.ok(stand.seen.length >= 1, "the turn reached the upstream");
  assert.ok(existsSync(join(sessions, "sessions.db")), `Goose wrote its session store (${sessions})`);
  assert.ok(storeHolds(sessions, CANARY), "the store holds the session as Goose wrote it (not a twin, not hidden)");

  // 2. A later session reads the store back through its shell.
  const grep = (path: string): string => `grep -a -h -o 'GOOSE-STORE-CANARY-[0-9]*' ${path} | head -n 1`;
  stand.seen.length = 0;
  stand.command = grep("~/.local/share/goose/sessions/sessions.db*");
  const second = await launchGoose(GOOSE!, stand, home, env, { kernel: false, args: ["run", "--no-session", "-t", "look at the earlier session"] });
  assert.equal(second.code, 0, second.lines.join("\n"));
  const last = stand.seen.at(-1)!.body;
  assert.match(last, /tool_result/, "the shell's result went back to the model");
  for (const q of stand.seen) assert.ok(!q.body.includes(CANARY), "INVARIANT: the store's text reaches the model only masked");
  assert.match(last, /\$MDU:/, "the read went to the model as a placeholder");

  // 3. CONTROL: the same bytes in the project folder go out as they are.
  for (const f of readdirSync(sessions).filter((f) => f.startsWith("sessions.db"))) {
    copyFileSync(join(sessions, f), join(home, "work", f.replace("sessions.db", "notes.db")));
  }
  stand.seen.length = 0;
  stand.command = grep(`${join(home, "work")}/notes.db*`);
  const control = await launchGoose(GOOSE!, stand, home, env, { kernel: false, args: ["run", "--no-session", "-t", "look at the notes"] });
  assert.equal(control.code, 0, control.lines.join("\n"));
  assert.ok(stand.seen.at(-1)!.body.includes(CANARY), "the probe is real: a file no rule knows goes out raw");
});
