/**
 * reader-launchers — confidentiality plan 13 D8 leftovers (3a) and (3b) of
 * !437 ("printers admit nothing"), the arbiter's half.
 *
 * (3a) A program that runs another program (`env`, `timeout`, `nice`,
 * `stdbuf`, …) is a code-running reader under every name a distribution
 * gives it: Ubuntu 26.04 ships GNU coreutils as `gnuenv`, `gnutimeout`, …
 * beside uutils' `env`; Homebrew's GNU tools are `genv`, `gmake`, `gxargs`;
 * some packages name uutils' programs `uu-env` / `uu_env`. A multi-call
 * binary (`toybox`, uutils' `coreutils`, beside `busybox`) carries `env` and
 * `timeout` under one name, and every file of uutils' multi-call directory
 * is `env` whatever its name. A relay that runs a program from its
 * arguments (`nc -e`, `ncat --sh-exec` / `--lua-exec`, `socat EXEC:`) is one
 * too. Before this change `gnuenv`, `toybox`, `nc` listed as a reader of a
 * secret file were leaf programs the human could approve.
 *
 * (3b) The ssh-agent socket's readers: a printer (or a relay) listed there
 * hands the agent's signing to whatever drives it, so the validator now
 * warns on it as it does for a file; the guard (secret_open.rs) refuses it.
 *
 * Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { decideOpen, entryAdmitsNothing, matchReader, readerRunsCode } from "../../policy/flow-taint.js";
import { policyWarnings, validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SYS = { exeSystem: true, loaderEnv: [] as string[] };
const H = "e".repeat(64);

const LAUNCHERS = [
  "gnuenv", "gnutimeout", "gnunice", "gnustdbuf", "gnunohup", "gnuchroot", "gnusetsid", "gnuxargs", "gnufind",
  "genv", "gtimeout", "gnice", "gstdbuf", "gxargs", "gfind", "gmake", "uu-env", "uu_timeout", "uu-nice", "uu_stdbuf",
  "toybox", "coreutils", "/usr/bin/toybox", "/usr/lib/cargo/bin/coreutils/env", "/usr/lib/cargo/bin/coreutils/wc",
  "nc", "nc.openbsd", "nc.traditional", "ncat", "netcat", "socat",
];

test("NEW (3a): a launcher runs code under a distribution's prefix, in a multi-call binary, and as a relay", () => {
  for (const n of LAUNCHERS) assert.equal(readerRunsCode(n), true, n);
  for (const n of ["psql", "aws", "gh", "git", "ssh", "ssh-add", "curl", "gpg-agent", "gnome-keyring-daemon", "bashful", "g", "gnu", "uu-"]) {
    assert.equal(readerRunsCode(n), false, n);
  }
  // no vetted consumer (the consumer table, §11.3) is a launcher under the new
  // forms; npm and cargo run the package's code (scripts, build.rs) and are on
  // the code-running list since 2026-10-04, as yarn, pnpm and node were
  for (const c of ["psql", "aws", "gh", "docker", "kubectl", "helm", "ssh", "scp", "git", "curl", "twine"]) {
    assert.equal(readerRunsCode(c), false, c);
  }
  for (const c of ["npm", "cargo", "yarn", "pnpm", "node"]) assert.equal(readerRunsCode(c), true, c);
});

test("NEW (3a): such a launcher listed for a file admits nothing, bare or pinned; it gets what a non-reader gets", () => {
  for (const n of ["gnuenv", "gnutimeout", "uu-env", "toybox", "ncat"]) {
    const opener = { exe: `/usr/bin/${n}`, sha256: H, ...SYS };
    assert.equal(entryAdmitsNothing(n), true, n);
    assert.equal(entryAdmitsNothing({ app: n, path: `/usr/bin/${n}`, sha256: H }), true, n);
    assert.equal(matchReader([n], opener), null, n);
    assert.equal(matchReader([{ app: n, path: `/usr/bin/${n}`, sha256: H }], opener), null, n);
    assert.equal(decideOpen("/ws/.env", { readers: [n] }, opener, { ask: "always" }).verdict, "deny", n);
    assert.equal(decideOpen("/ws/.env", { readers: [n], others: "twin" }, opener, { ask: "always" }).verdict, "twin", n);
  }
  // a leaf program beside it still reads raw
  const sshAdd = { exe: "/usr/bin/ssh-add", sha256: H, ...SYS };
  assert.equal(decideOpen("/ws/.env", { readers: ["gnuenv", { app: "ssh-add", path: "/usr/bin/ssh-add", sha256: H }] }, sshAdd).verdict, "raw");
});

test("NEW (3b): policyWarnings names a printer or a launcher on the ssh-agent socket's list as admitting nothing", () => {
  const doc = { version: 1, ssh_agent: { readers: ["ssh-add", "socat", { app: "openssl", from: "git" }, "gnuenv", { app: "ssh", from: "git" }] } };
  assert.deepEqual(validatePolicyDocument(doc), [], "a warning never refuses the start");
  const w = policyWarnings(doc);
  assert.equal(w.length, 3, w.join("\n"));
  assert.match(w[0]!, /^ssh_agent\.readers\[1\]: socat .*admits nothing.*your ssh-agent/);
  assert.match(w[1]!, /^ssh_agent\.readers\[2\]: openssl .*admits nothing/);
  assert.match(w[2]!, /^ssh_agent\.readers\[3\]: gnuenv runs any code it is given/);
  assert.ok(w.every((l) => !/script:/.test(l)), "the socket's readers have no script pin");
});
