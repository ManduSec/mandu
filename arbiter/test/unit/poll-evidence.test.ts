/**
 * poll-evidence — a masked `BashOutput` poll's symbol is a value-backstop
 * fingerprint when the call it continues held a secret (plan 13 D7, plan 10
 * §11.12; 2026-10-09).
 *
 * An exec-output row (Bash, BashOutput, exec_command, …) counts in the value
 * backstop only when its own call's tree held a secret (a precautionary row
 * would match its own text forever). A `BashOutput` poll's own id binds no
 * tree, so before this its masked output never counted: a later result
 * repeating what a secret-reading background task printed (hex of the
 * secret, say, past the file's own fingerprints) was not caught. The model
 * proxy now ties the poll to the call that started the task (`callTaint`
 * with `forPoll`, human plane only), and the row counts by that call's tree.
 * A poll tied to a clean call, an untied poll, and a tie claimed from the
 * data socket add nothing (no over-masking).
 *
 * Confidentiality axis (the value backstop serves the model exit).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const HEX = "746f6b656e3d4241434b47524f554e445f504f4c4c5f43414e415259";
const POLL = (out: string): string => `<status>completed</status>\n\n<exit_code>0</exit_code>\n\n<stdout>\n${out}\n</stdout>`;

test("a BashOutput row counts by the tree of the call its poll was tied to (human plane); untied, tied to a clean call, or tied from the data socket it does not", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-poll-evidence-"));
  const s = new ArbiterServer({ socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false });
  await s.listen();
  const human = new ArbiterClient(join(dir, "human", "h.sock"));
  await human.connect();
  const data = new ArbiterClient(join(dir, "a.sock"));
  await data.connect();
  try {
    // the background call's tree read a secret raw; the clean call's did not
    await human.recordExecRoot({ procKey: "sh-bg", argv: ["/bin/bash", "-c", "mytool ./x.txt | od"], session: "pe" });
    await human.taintProcessSecret({ procKey: "sh-bg", path: join(dir, "x.txt"), level: "no-model", app: "mytool", session: "pe" });
    await human.recordCallRoot({ callId: "toolu_bg", procKey: "sh-bg", session: "pe" });
    await human.recordExecRoot({ procKey: "sh-clean", argv: ["/bin/bash", "-c", "make"], session: "pe" });
    await human.recordCallRoot({ callId: "toolu_clean", procKey: "sh-clean", session: "pe" });
    const hits = async (text: string): Promise<string[]> => (await human.scanSecretValues(text)).hits.map((h) => h.symbol);
    const mint = (callId: string, out: string) => human.symbolize({ tool: "BashOutput", value: POLL(out), origin: undefined, confidentiality: "no-model", sessionKey: "pe", callId, resultHead: "claude-task" });

    // 1. the poll of the reading task, masked; untied: its row is no evidence
    const sym = await mint("toolu_poll", HEX);
    assert.deepEqual(await hits(`later: ${HEX}`), [], "untied: the poll's own id binds no tree");
    // 2. a tie claimed from the data socket is ignored
    await data.callTaint("toolu_bg", { forPoll: "toolu_poll", session: "pe" });
    assert.deepEqual(await hits(`later: ${HEX}`), [], "the data socket cannot tie a poll");
    // 3. the proxy's tie, on the human plane: the row counts by the reading call's tree
    await human.callTaint("toolu_bg", { forPoll: "toolu_poll", session: "pe" });
    assert.deepEqual(await hits(`later: ${HEX}`), [sym], "CONFIDENTIALITY: what the secret-reading task printed is caught in a later result");
    assert.deepEqual(await hits("<status>completed</status>\n<exit_code>0</exit_code>"), [], "the poll's status tags are no fingerprints (its head)");
    // 4. a poll tied to a clean call: no evidence, no over-masking
    const clean = "clean-build-output-0123456789abcdefghij";
    await mint("toolu_poll_clean", clean);
    await human.callTaint("toolu_clean", { forPoll: "toolu_poll_clean", session: "pe" });
    assert.deepEqual(await hits(`again: ${clean}`), [], "utility: a clean task's masked poll does not mask its text later");
  } finally {
    human.close();
    data.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
