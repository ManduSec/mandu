/**
 * subcommand-help.test — every reserved verb answers `--help` / `-h` with its
 * usage (release checklist d8). Pure: no protection axis is involved.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { SUBCOMMAND_USAGE, subcommandUsage, wantsHelp } from "../../src/subcommand-help.js";
import { RESERVED_SUBCOMMANDS, runSubcommand } from "../../src/subcommands.js";
import { Layout } from "../../src/services/layout.js";

test("every reserved verb has a usage block that names it", () => {
  for (const verb of RESERVED_SUBCOMMANDS) {
    const text = subcommandUsage(verb);
    assert.ok(text, `no usage for '${verb}'`);
    assert.match(text!, new RegExp(`^usage: mandu ${verb}\\b`), verb);
  }
  assert.deepEqual(Object.keys(SUBCOMMAND_USAGE).sort(), [...RESERVED_SUBCOMMANDS].sort(), "no usage for a verb that does not exist");
});

test("wantsHelp: --help and -h anywhere before a -- separator", () => {
  assert.equal(wantsHelp(["--help"]), true);
  assert.equal(wantsHelp(["-h"]), true);
  assert.equal(wantsHelp(["--print", "--help"]), true);
  assert.equal(wantsHelp([]), false);
  assert.equal(wantsHelp(["--all"]), false);
  assert.equal(wantsHelp(["--", "-h"]), false, "after -- it is an argument");
  assert.equal(wantsHelp(["~/.pgpass", "--json"]), false);
});

test("an unknown verb has no usage", () => {
  assert.equal(subcommandUsage("launch"), null);
});

test("the dispatcher answers --help / -h for EVERY verb with its usage and exit 0, before the verb runs", async () => {
  // In process, the one branch every `mandu <verb>` goes through (run.ts →
  // runSubcommand). The empty env points nowhere: a verb that ran instead of
  // answering would throw or print something else. The real CLI entry and
  // "touches nothing" are the e2e's (test/component/subcommand-help.test.ts).
  const layout = Layout.detect(new URL("../../src/run.ts", import.meta.url).href, {});
  const write = process.stdout.write.bind(process.stdout);
  for (const verb of RESERVED_SUBCOMMANDS) {
    for (const flag of ["--help", "-h"]) {
      let out = "";
      (process.stdout as { write: unknown }).write = (chunk: string | Uint8Array): boolean => { out += String(chunk); return true; };
      let code: number;
      try {
        code = await runSubcommand(verb, [flag], {}, layout);
      } finally {
        (process.stdout as { write: unknown }).write = write;
      }
      assert.equal(code, 0, `${verb} ${flag}`);
      assert.equal(out, subcommandUsage(verb), `${verb} ${flag}: the usage and nothing else`);
    }
  }
});
