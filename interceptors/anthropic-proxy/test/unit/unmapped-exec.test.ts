/**
 * unmapped-exec (unit) — plan 10 §11.12: which input names a command, how an
 * argv array is joined for the arbiter's signature tokenizer, and the level
 * lattice a taint raises along. The openai-proxy mirror pins the same list.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { COMMAND_LIKE_KEYS, argvCommandText, commandLikeFields, commandLikeText, stricterLevel } from "../../src/unmapped-exec.js";

test("the command-like keys (pinned; the openai-proxy mirror pins the same list)", () => {
  assert.deepEqual([...COMMAND_LIKE_KEYS], ["command", "cmd", "commandline", "command_line", "cmdline", "script", "shell", "bash", "code", "argv"]);
});

test("commandLikeText: a string or an argv array under a command-like key, case-insensitive; else null", () => {
  assert.equal(commandLikeText({ command: "cat .env" }), "cat .env");
  assert.equal(commandLikeText({ Cmd: "ls" }), "ls");
  assert.equal(commandLikeText({ commandLine: "ls -la" }), "ls -la");
  assert.equal(commandLikeText({ code: "print(open('n').read())" }), "print(open('n').read())");
  assert.equal(commandLikeText({ argv: ["bash", "-lc", "cat notes.txt"] }), "bash -lc 'cat notes.txt'");
  assert.equal(commandLikeText({ path: "notes.txt" }), null, "a path is not a command");
  assert.equal(commandLikeText({ command: "   " }), null);
  assert.equal(commandLikeText({ command: [1, 2] }), null);
  assert.equal(commandLikeText({ args: { command: "ls" } }), null, "top level only");
  assert.equal(commandLikeText(null), null);
  assert.equal(commandLikeText(["ls"]), null);
  assert.equal(commandLikeText("ls"), null);
});

test("argvCommandText: quoted so the arbiter's tokenizer splits it back", () => {
  assert.equal(argvCommandText(["sh", "-c", "echo 'hi' && cat x"]), `sh -c 'echo '"'"'hi'"'"' && cat x'`);
  assert.equal(argvCommandText(["ls", "/tmp/a.b"]), "ls /tmp/a.b");
  assert.equal(argvCommandText([]), null);
  assert.equal(argvCommandText(["ls", 3]), null);
});

test("stricterLevel: raise only; absent is public; an unknown level ranks strictest", () => {
  assert.equal(stricterLevel(undefined, "any-model"), "any-model");
  assert.equal(stricterLevel("no-model", "any-model"), "no-model", "a taint never lowers a verdict");
  assert.equal(stricterLevel("any-model", "local-model"), "local-model");
  assert.equal(stricterLevel("public", "no-model"), "no-model");
  assert.equal(stricterLevel("from-the-future", "no-model"), "from-the-future");
  assert.equal(stricterLevel("any-model", "from-the-future"), "from-the-future");
});

test("commandLikeFields: every command-like field in order; flags and empties are not commands; unreadable shapes are kept as such", () => {
  assert.deepEqual(commandLikeFields({ Command: "ls", shell: true, timeout: 5, argv: ["a b", "c"], code: "", script: { src: "x" }, bash: [1], cmd: [] }), [
    { key: "Command", text: "ls", shape: "string" },
    { key: "argv", text: "'a b' c", shape: "argv" },
    { key: "script", text: null, shape: "other" },
    { key: "bash", text: null, shape: "other" },
  ]);
  assert.deepEqual(commandLikeFields(null), []);
  assert.deepEqual(commandLikeFields(["ls"]), []);
});
