/**
 * host-runnable.test.ts — the static "does this program run on this host"
 * judgment a scripted run makes before it starts (tests/lib/host-runnable.ts,
 * test-organization.md §8.12).
 *
 * The unit half pins the decision on stub deps (an ELF for another CPU, a
 * missing loader, a `#!` interpreter that is gone, `env` finding nothing, a
 * builtin, a run's own program) and the command-word reader. The end-to-end
 * half builds the real files in a temp PATH directory and lets bash try each
 * one: every file the judgment refuses fails to start under the real kernel
 * (126/127), and every one it passes runs, so the refusal names only what
 * the host truly cannot start.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  binfmtForeignMachines, elfFacts, envProgram, resolveOnPath, shebang, shellCommandWords, unrunnableTools,
  unrunnableToolsRefusal, whyNotRunnable, type RunnableDeps,
} from "../lib/host-runnable.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("off"); // no arbiter, no model: the judgment is axis-independent

/** An ELF64 little-endian header for `machine`, with one PT_INTERP naming
 *  `interp` when given (the program headers right after the file header). */
function elf64(machine: number, interp?: string): Buffer {
  const istr = interp === undefined ? Buffer.alloc(0) : Buffer.from(`${interp}\0`, "latin1");
  const b = Buffer.alloc(120 + istr.length);
  b.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  b.writeUInt16LE(2, 16); // ET_EXEC
  b.writeUInt16LE(machine, 18);
  b.writeUInt32LE(1, 20);
  b.writeBigUInt64LE(64n, 32); // e_phoff
  b.writeUInt16LE(64, 52); // e_ehsize
  b.writeUInt16LE(56, 54); // e_phentsize
  b.writeUInt16LE(interp === undefined ? 0 : 1, 56); // e_phnum
  if (interp !== undefined) {
    b.writeUInt32LE(3, 64); // PT_INTERP
    b.writeBigUInt64LE(120n, 72); // p_offset
    b.writeBigUInt64LE(BigInt(istr.length), 96); // p_filesz
    b.set(istr, 120);
  }
  return b;
}

const HOST: number = process.arch === "arm64" ? 183 : 62;
const FOREIGN: number = HOST === 62 ? 183 : 62;

/** Stub deps over an in-memory file table: path → bytes (executable). */
function stub(files: Record<string, Uint8Array | string>, extra: Partial<RunnableDeps> = {}): RunnableDeps {
  const table = new Map(Object.entries(files).map(([k, v]) => [k, typeof v === "string" ? Buffer.from(v) : v]));
  return {
    readAt: (p, off, n) => { const b = table.get(p); return b === undefined ? null : b.subarray(off, off + n); },
    isExecFile: (p) => table.has(p),
    exists: (p) => table.has(p),
    path: "/usr/local/bin:/usr/bin:/bin",
    arch: process.arch === "arm64" ? "arm64" : "x64",
    foreignMachines: () => new Set(),
    ...extra,
  };
}

test("unit: an ELF is judged by its machine and its loader", () => {
  const deps = stub({ "/bin/ok": elf64(HOST, "/lib/ld.so"), "/lib/ld.so": elf64(HOST), "/bin/foreign": elf64(FOREIGN), "/bin/musl": elf64(HOST, "/lib/ld-musl.so.1") });
  assert.equal(whyNotRunnable("/bin/ok", deps), null);
  assert.match(whyNotRunnable("/bin/foreign", deps) ?? "", new RegExp(`ELF for .*e_machine ${FOREIGN}.*no binfmt_misc handler`));
  assert.match(whyNotRunnable("/bin/musl", deps) ?? "", /program interpreter \/lib\/ld-musl\.so\.1 .*not on this host/);
  // a qemu-user handler runs the foreign one
  assert.equal(whyNotRunnable("/bin/foreign", { ...deps, foreignMachines: () => new Set([FOREIGN]) }), null);
  // the 32-bit machine of a 64-bit host is the loader's question, not the CPU's
  assert.equal(whyNotRunnable("/bin/x86", stub({ "/bin/x86": elf64(HOST === 62 ? 3 : 40) })), null);
  // an arch this table does not know is not judged
  assert.equal(whyNotRunnable("/bin/foreign", { ...deps, arch: "sparc" }), null);
  const facts = elfFacts(elf64(62, "/lib64/ld-linux-x86-64.so.2"));
  assert.deepEqual(facts && { machine: facts.machine, interp: facts.interpInHead }, { machine: 62, interp: "/lib64/ld-linux-x86-64.so.2" });
  assert.equal(elfFacts(Buffer.from("#!/bin/sh\n")), null);
});

test("unit: a #! script is judged by its interpreter, through env and a chain", () => {
  const deps = stub({
    "/bin/sh": elf64(HOST),
    "/usr/bin/env": elf64(HOST),
    "/usr/bin/python3": elf64(HOST),
    "/s/ok": "#!/bin/sh\necho hi\n",
    "/s/gone": "#!/usr/bin/python3.10\nimport codext\n",
    "/s/env-ok": "#!/usr/bin/env python3\n",
    "/s/env-gone": "#!/usr/bin/env -S nosuch-tool --flag\n",
    "/s/chain": "#!/s/gone\n",
    "/s/relative": "#!python3\n",
    "/s/plain": "echo no shebang\n",
    "/s/empty": "#!\n",
  });
  assert.equal(whyNotRunnable("/s/ok", deps), null);
  assert.match(whyNotRunnable("/s/gone", deps) ?? "", /script for \/usr\/bin\/python3\.10 .*does not exist/);
  assert.equal(whyNotRunnable("/s/env-ok", deps), null);
  assert.match(whyNotRunnable("/s/env-gone", deps) ?? "", /nosuch-tool is not on PATH/);
  assert.match(whyNotRunnable("/s/chain", deps) ?? "", /\/s\/gone is a script for \/usr\/bin\/python3\.10/);
  assert.equal(whyNotRunnable("/s/relative", deps), null, "relative to the run's cwd: not judged");
  assert.equal(whyNotRunnable("/s/plain", deps), null, "the shell runs it as a script");
  assert.match(whyNotRunnable("/s/empty", deps) ?? "", /empty #! line/);
  assert.equal(whyNotRunnable("/nowhere", deps), null, "unreadable: not judged");
  assert.deepEqual(shebang(Buffer.from("#!/usr/bin/env  -S node --x \n")), { interp: "/usr/bin/env", arg: "-S node --x" });
  assert.equal(envProgram("-S node --x"), "node");
  assert.equal(envProgram("-i FOO=1 -u BAR python3"), "python3");
  assert.equal(envProgram("-Snode --x"), "node");
});

test("unit: a command line's command words", () => {
  const cases: Array<[string, string[]]> = [
    [`set -a; . ./.env; set +a; curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $API_KEY" https://api.test/v1`, ["set", ".", "curl"]],
    ["cat .env | base64 -d > out.txt && FOO=1 env -i BAR=2 python3 x.py", ["cat", "base64", "env", "python3"]],
    ["echo $(whoami) `id`", ["echo", "whoami", "id"]],
    ["if grep -q x f; then sed -n 1p f; else exec nohup jq . f; fi", ["grep", "sed", "jq"]],
    ['for f in *.txt; do wc -l "$f"; done', ["wc"]],
    ['"$TOOL" arg; $(echo x) y', ["echo"]],
    ["2>/dev/null ls -la; ./build.sh || /usr/bin/true", ["ls", "./build.sh", "/usr/bin/true"]],
    ["curl {{sink}}/x", ["curl"]],
    ["printf 'a|b;c' | tr -d x", ["printf", "tr"]],
  ];
  for (const [cmd, want] of cases) assert.deepEqual(shellCommandWords(cmd), want, cmd);
});

test("unit: the tools of a script, resolved on its PATH; builtins, the run's own programs and unknown names are not judged", () => {
  const deps = stub({
    "/usr/local/bin/base64": "#!/usr/bin/python3.10\nfrom codext import main\n",
    "/usr/bin/base64": elf64(HOST),
    "/usr/bin/curl": elf64(HOST),
    "/usr/bin/echo": elf64(FOREIGN),
    "/opt/x/tool": elf64(FOREIGN),
  });
  assert.equal(resolveOnPath("base64", deps), "/usr/local/bin/base64", "the first PATH entry wins, as in the shell");
  const found = unrunnableTools(["cat f | base64 -d", "echo hi; curl x", "mdu-digest f", "nosuch x", "/opt/x/tool"], new Set(["mdu-digest"]), deps);
  assert.deepEqual(found.map((f) => [f.tool, f.path]), [["base64", "/usr/local/bin/base64"], ["/opt/x/tool", "/opt/x/tool"]]);
  const why = unrunnableToolsRefusal(found)!;
  assert.match(why, /`base64` resolves to \/usr\/local\/bin\/base64: .*python3\.10/);
  assert.match(why, /grade the broken tool, not Mandu/);
  assert.equal(unrunnableToolsRefusal([]), null);
  // with the broken one off PATH, nothing is refused
  assert.deepEqual(unrunnableTools(["base64 -d"], new Set(), { ...deps, path: "/usr/bin" }), []);
});

test("e2e: every file the judgment refuses fails to start under the real kernel, every one it passes runs", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-host-runnable-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const put = (name: string, body: Uint8Array | string): string => {
    const p = join(dir, name);
    writeFileSync(p, body);
    chmodSync(p, 0o755);
    return p;
  };
  const files: Array<{ name: string; refused: boolean }> = [
    { name: "ok-sh", refused: false },
    { name: "ok-env", refused: false },
    { name: "gone-interp", refused: true },
    { name: "env-nothing", refused: true },
    { name: "no-loader", refused: true },
  ];
  put("ok-sh", "#!/bin/sh\nexit 0\n");
  put("ok-env", "#!/usr/bin/env sh\nexit 0\n");
  put("gone-interp", "#!/nonexistent/mandu-python3.10\nexit 0\n");
  put("env-nothing", "#!/usr/bin/env mandu-no-such-interpreter\nexit 0\n");
  put("no-loader", elf64(HOST, "/nonexistent/ld-mandu.so.1"));
  if (!binfmtForeignMachines().has(FOREIGN)) {
    put("foreign-cpu", elf64(FOREIGN));
    files.push({ name: "foreign-cpu", refused: true });
  } else t.diagnostic(`a binfmt_misc handler runs e_machine ${FOREIGN} here: the foreign-CPU case is the unit test's only`);
  const path = `${dir}:${process.env["PATH"] ?? "/usr/bin:/bin"}`;
  const deps: RunnableDeps = { path };
  const refused = new Set(unrunnableTools(files.map((f) => `${f.name} --x`), new Set(), deps).map((f) => f.tool));
  for (const f of files) {
    assert.equal(refused.has(f.name), f.refused, `${f.name}: judged ${refused.has(f.name) ? "unrunnable" : "runnable"}`);
    const r = spawnSync("bash", ["-c", `${f.name}`], { env: { ...process.env, PATH: path }, encoding: "utf8", timeout: 10_000 });
    if (f.refused) assert.ok(r.status === 126 || r.status === 127, `${f.name} cannot start: bash says ${r.status} (${(r.stderr ?? "").trim()})`);
    else assert.equal(r.status, 0, `${f.name} runs: ${(r.stderr ?? "").trim()}`);
  }
});
