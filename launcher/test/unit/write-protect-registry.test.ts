/**
 * write-protect-registry — Mandu's runtime registries on the Linux
 * write-protect list (runtime-instances.md §2, "planted paths"): the same
 * entries the macOS profile denies (runtime-registry.ts), each in the form
 * the guard needs (`name` for `current`, `prefix` for the temp names, `self`
 * for the base), under the launch's base and the account's; a link on the
 * arbiter socket's way protected as itself; a registry that would hold the
 * workspace refused. The kernel half is tests/sandbox/write-protect.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RUNTIME_REGISTRY } from "../../src/runtime-registry.js";
import { applyWriteProtect, arbiterSocketFiles, registryHolding, runtimeRegistryProtect, writeProtectList } from "../../src/write-protect.js";

const NOFS = { exists: () => false, isDir: () => false, read: () => null };

test("every runtime registry entry, in the guard's form, under each base once; the base itself `self`", () => {
  const e = runtimeRegistryProtect(["/run/user/7/mandu", "/run/user/7/mandu/", "/tmp/mandu-7", undefined, "rel", "/"]);
  assert.ok(e.every((x) => x.answer === "deny" && x.label === "Mandu's own files"));
  for (const b of ["/run/user/7/mandu", "/tmp/mandu-7"]) {
    const at = (p: string) => e.find((x) => x.path === p);
    for (const d of [...RUNTIME_REGISTRY.dirs, "human"]) assert.equal(at(`${b}/${d}`)?.form, undefined, `${d}/ and everything below it`);
    for (const n of RUNTIME_REGISTRY.names) assert.equal(at(`${b}/${n}`)?.form, "name", `${n}: the entry itself (current is a link)`);
    for (const p of RUNTIME_REGISTRY.prefixes) assert.equal(at(`${b}/${p}`)?.form, "prefix", `${p}*`);
    assert.equal(at(b)?.form, "self", "the base: not renamed or removed, its scope dirs writable");
  }
  const per = RUNTIME_REGISTRY.dirs.length + 1 + RUNTIME_REGISTRY.names.length + RUNTIME_REGISTRY.prefixes.length + 1;
  assert.equal(e.length, 2 * per, "a repeated base (trailing slash) is one; a relative base or / adds nothing");
});

test("writeProtectList: the registry rides the Linux list as Mandu's own files (policy.yaml cannot drop it); not the macOS one", () => {
  const logs: string[] = [];
  const linux = writeProtectList({ HOME: "/h" }, "/w", NOFS, undefined, { deny: [], ask: [], unprotect: ["/rt/instances", "/rt/current", "/rt/dashboard-1.port"] }, (m) => logs.push(m), [], "linux", undefined, ["/rt"]);
  for (const p of ["/rt/instances", "/rt/current", "/rt/.current.tmp-", "/rt/dashboard-", "/rt/vm-guests", "/rt/human", "/rt"]) {
    assert.ok(linux.some((x) => x.path === p && x.answer === "deny"), p);
  }
  assert.equal(logs.filter((l) => /one of Mandu's own files; it stays protected/.test(l)).length, 3, logs.join("\n"));
  const firstAsk = linux.findIndex((x) => x.answer === "ask");
  assert.ok(linux.findIndex((x) => x.path === "/rt/instances") < firstAsk, "before every `ask` entry (the guard takes the first)");
  const mac = writeProtectList({ HOME: "/h" }, "/w", NOFS, undefined, undefined, () => {}, [], "darwin", undefined, ["/rt"]);
  assert.ok(!mac.some((x) => x.path.startsWith("/rt")), "macOS: the profile's own component denies them");
});

test("a link on the arbiter socket's way is protected as itself (`name`), not as the instance it points at", () => {
  const fsx = {
    real: (p: string) => (p === "/run/user/7/mandu/current/arbiter.sock" ? "/run/user/7/mandu/instances/abc/arbiter.sock" : null),
    isLink: (p: string) => p === "/run/user/7/mandu/current",
  };
  const e = arbiterSocketFiles("/run/user/7/mandu/current/arbiter.sock", fsx);
  assert.equal(e.find((x) => x.path === "/run/user/7/mandu/current")?.form, "name");
  assert.equal(e.find((x) => x.path === "/run/user/7/mandu/current/arbiter.sock")?.form, undefined);
});

test("a registry that holds the workspace or the scope dir refuses the launch; the base itself (`self`) does not", () => {
  const e = runtimeRegistryProtect(["/rt"]);
  assert.deepEqual(registryHolding(e, ["/rt/logs/proj"]), { entry: "/rt/logs", holds: "/rt/logs/proj" });
  assert.deepEqual(registryHolding(e, ["/rt/dashboard-x/ws"]), { entry: "/rt/dashboard-*", holds: "/rt/dashboard-x/ws" });
  assert.equal(registryHolding(e, ["/rt/1700000000-42", "/home/u/proj"]), null, "a scope dir and a workspace elsewhere are fine");
  assert.equal(registryHolding(e, ["/rt"]), null, "the base holds the session's own folder; only renaming it is refused");
});

test("the guard policy file carries each entry's form", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-wp-reg-"));
  try {
    const env: Record<string, string> = {};
    applyWriteProtect(runtimeRegistryProtect(["/rt"]), env, { log: () => {}, scopeRunDir: dir, agentExe: "/bin/true", session: "s" });
    const p = JSON.parse(readFileSync(env["MANDU_NET_GUARD_SECRETS"]!, "utf8")) as { writeProtect: Array<{ path: string; form?: string }> };
    assert.equal(p.writeProtect.find((x) => x.path === "/rt/current")?.form, "name");
    assert.equal(p.writeProtect.find((x) => x.path === "/rt/.current.tmp-")?.form, "prefix");
    assert.equal(p.writeProtect.find((x) => x.path === "/rt")?.form, "self");
    assert.equal(p.writeProtect.find((x) => x.path === "/rt/instances")?.form, undefined);
    assert.equal(env["MANDU_NET_GUARD_PROTECT"], "1");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
