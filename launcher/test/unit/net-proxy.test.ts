/**
 * net-proxy.test — env building + identity-checked start-or-reuse + ephemeral
 * port + MITM CA wait, all with injected ServiceDeps (no real port bound, no
 * real npm spawned). The guard matrix mirrors context-proxy.test.ts.
 */
import { test } from "node:test";
import { Layout } from "../../src/services/layout.js";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeCaBundle, writeUserTrustFiles, startNetProxy, NetProxyConflictError, TRUST_VARS } from "../../src/services/net-proxy.js";
import { waitForFile, type ServiceDeps } from "../../src/services/primitives.js";
import type { LaunchPlan } from "../../src/types.js";
import { sessionLogins } from "../../src/agent-login.js";

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid-9", tenant: "live", arbiterSock: "/run/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/run/sid/events", cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, ...over,
  };
}

/** The launch's HOME for the session's logins (ServiceDeps.home). */
const HOME = "/home/netproxy-test";

function deps(over: Partial<ServiceDeps> = {}): ServiceDeps {
  return {
    home: HOME,
    probePort: async () => false, probeIdentity: async () => null,       // nothing listening → we start it
    waitFor: async () => true,          // port comes up
    waitForFile: async () => true,      // CA cert appears
    startDetachedCmd: () => ({ pid: 4322, stop: () => {} }),
    runOnce: () => ({ status: 0, stdout: "", stderr: "" }),
    ...over,
  };
}

/** A matching identity for the default `plan()` (arbiterSock /run/b.sock) —
 *  what a reusable net-proxy for this launch would publish. */
function matchingIdentity(over: Record<string, unknown> = {}) {
  return { mandu: true, service: "net-proxy", sessionKey: "sid-9", arbiterSock: "/run/b.sock", sessionLogins: sessionLogins(plan(), process.env, HOME), ...over };
}

/** Run `fn` with MANDU_NET_PROXY_PORT set (restored afterwards). */
async function withPortEnv(value: string, fn: () => Promise<void>): Promise<void> {
  const saved = process.env["MANDU_NET_PROXY_PORT"];
  process.env["MANDU_NET_PROXY_PORT"] = value;
  try { await fn(); }
  finally {
    if (saved === undefined) delete process.env["MANDU_NET_PROXY_PORT"];
    else process.env["MANDU_NET_PROXY_PORT"] = saved;
  }
}

// The start-or-reuse / conflict cases below exercise a PINNED port (8790, the
// historical well-known one). Since release checklist a1 the built-in default
// is 0 (kernel-assigned, see the default-port test further down), so they pin
// it explicitly. (node --test runs each file in its own process.)
process.env["MANDU_NET_PROXY_PORT"] = "8790";

test("reuses a listening proxy ONLY when its identity matches (same service/arbiter)", async () => {
  let started = 0;
  const r = await startNetProxy(plan(), Layout.dev("/repo"), "/run/sid",
    deps({
      probePort: async () => true,
      probeIdentity: async () => matchingIdentity(),
      startDetachedCmd: () => { started++; return { pid: 1, stop: () => {} }; },
    }));
  r.stop(); // a reused proxy must never be torn down by us
  assert.equal(started, 0, "no new proxy spawned");
  assert.deepEqual(r.netProxy, { host: "127.0.0.1", port: 8790 });
  assert.equal(r.mitmCaCert, undefined);
});

test("a matching-arbiter proxy with a DIFFERENT sessionKey is still reused (sessionKey not part of the key)", async () => {
  let started = 0;
  await startNetProxy(plan(), Layout.dev("/repo"), "/run/sid",
    deps({
      probePort: async () => true,
      probeIdentity: async () => matchingIdentity({ sessionKey: "some-other-session" }),
      startDetachedCmd: () => { started++; return { pid: 1, stop: () => {} }; },
    }));
  assert.equal(started, 0);
});

test("FAILS CLOSED when the listening net-proxy has a DIFFERENT arbiter socket (wrong egress gate)", async () => {
  let started = 0;
  const err = await startNetProxy(plan(), Layout.dev("/repo"), "/run/sid",
    deps({
      probePort: async () => true,
      probeIdentity: async () => matchingIdentity({ arbiterSock: "/run/OTHER.sock" }),
      startDetachedCmd: () => { started++; return { pid: 1, stop: () => {} }; },
    }),
  ).then(() => null, (e) => e as Error);
  assert.ok(err instanceof NetProxyConflictError, "a wrong-arbiter net-proxy is a conflict");
  assert.equal((err as NetProxyConflictError).failClosedFatal, true, "--best-effort must not override it");
  assert.match(err!.message, /occupied by another Mandu net-proxy.*arbiter=\/run\/OTHER\.sock/i);
  assert.equal(started, 0, "never spawns over an occupied port");
});

test("FAILS CLOSED when the port is held by a foreign (non-Mandu) server", async () => {
  await assert.rejects(
    startNetProxy(plan(), Layout.dev("/repo"), "/run/sid",
      deps({ probePort: async () => true, probeIdentity: async () => ({ mandu: false }) })),
    /occupied by a non-Mandu server/i,
  );
  // …and when nothing answers the identity probe at all (bare TCP listener,
  // or an OLD net-proxy build without the endpoint — never adopt blindly).
  await assert.rejects(
    startNetProxy(plan(), Layout.dev("/repo"), "/run/sid",
      deps({ probePort: async () => true, probeIdentity: async () => null })),
    /no \/_mandu\/identity/i,
  );
});

test("FAILS CLOSED on a same-arbiter CONTEXT proxy squatting the port (service must match)", async () => {
  await assert.rejects(
    startNetProxy(plan(), Layout.dev("/repo"), "/run/sid",
      deps({
        probePort: async () => true,
        probeIdentity: async () => matchingIdentity({ service: "anthropic-proxy", viewMap: [] }),
      })),
    /occupied by another Mandu anthropic-proxy/i,
  );
});

test("starts the proxy with the SESSION_KEY = scopeId and waits for the port", async () => {
  let capturedEnv: Record<string, string | undefined> = {};
  const r = await startNetProxy(plan(), Layout.dev("/repo"), "/run/sid",
    deps({ startDetachedCmd: (_c, _a, { env }) => { capturedEnv = env; return { pid: 7, stop: () => {} }; } }));
  assert.equal(capturedEnv["MANDU_SESSION_KEY"], "sid-9");
  assert.equal(capturedEnv["MANDU_NET_PROXY_PORT"], "8790");
  assert.equal(capturedEnv["MANDU_ARBITER_SOCK"], "/run/b.sock");
  assert.equal(capturedEnv["MANDU_NET_PROXY_MITM"], ""); // off
  assert.equal(capturedEnv["MANDU_PORT_FILE"], undefined, "fixed-port launches get no port file");
  assert.deepEqual(r.netProxy, { host: "127.0.0.1", port: 8790 });
});

test("human plane: the proxy gets the arbiter's human socket (its egress resolve runs there); none reported → explicitly unset, never the data socket", async () => {
  for (const [humanSock, want] of [["/run/mandu/human/i.sock", "/run/mandu/human/i.sock"], [null, undefined]] as const) {
    let capturedEnv: Record<string, string | undefined> = {};
    const prior = process.env["MANDU_ARBITER_HUMAN_SOCK"];
    process.env["MANDU_ARBITER_HUMAN_SOCK"] = "/stale/ambient/human.sock";
    try {
      await startNetProxy(plan({ arbiterHumanSock: humanSock }), Layout.dev("/repo"), "/run/sid",
        deps({ startDetachedCmd: (_c, _a, { env }) => { capturedEnv = env; return { pid: 7, stop: () => {} }; } }));
    } finally {
      if (prior === undefined) delete process.env["MANDU_ARBITER_HUMAN_SOCK"]; else process.env["MANDU_ARBITER_HUMAN_SOCK"] = prior;
    }
    assert.equal(capturedEnv["MANDU_ARBITER_HUMAN_SOCK"], want);
    assert.equal(capturedEnv["MANDU_ARBITER_SOCK"], "/run/b.sock", "the data socket stays the data socket");
  }
});

test("start path re-verifies identity: a CONCURRENT foreign proxy winning the port fails CLOSED", async () => {
  // Race: nothing on the port when we check, so we start; our child dies with
  // EADDRINUSE while a DIFFERENT-arbiter proxy (a concurrent launch) wins the
  // bind. The port is UP but foreign — we must NOT adopt it.
  let probeCount = 0;
  let stopped = 0;
  const err = await startNetProxy(plan(), Layout.dev("/repo"), "/run/sid",
    deps({
      probePort: async () => probeCount++ > 0, // false on the top reuse-check, then up
      probeIdentity: async () => matchingIdentity({ arbiterSock: "/run/OTHER.sock" }),
      waitFor: async (check) => Boolean(await check()), // actually evaluate the predicate
      startDetachedCmd: () => ({ pid: 1, stop: () => { stopped++; } }),
    }),
  ).then(() => null, (e) => e as Error);
  assert.ok(err instanceof NetProxyConflictError, "a wrong-session proxy after start is a conflict");
  assert.equal((err as NetProxyConflictError).failClosedFatal, true);
  assert.match(err!.message, /foreign or wrong-session proxy/i);
  assert.equal(stopped, 1, "our dead child was torn down");
});

test("start path adopts our OWN child when its identity matches", async () => {
  let probeCount = 0;
  const r = await startNetProxy(plan(), Layout.dev("/repo"), "/run/sid",
    deps({
      probePort: async () => probeCount++ > 0, // free at first, up after start
      probeIdentity: async () => matchingIdentity(),
      waitFor: async (check) => Boolean(await check()),
    }));
  assert.deepEqual(r.netProxy, { host: "127.0.0.1", port: 8790 });
});

test("MITM: sets MITM=1, waits for the CA cert, returns its path", async () => {
  const r = await startNetProxy(
    plan({ requested: { netProxy: true, netProxyMitm: true, execWrap: false } }),
    Layout.dev("/repo"), "/run/sid", deps());
  assert.match(r.mitmCaCert!, /mandu-egress-ca\.pem$/);
});

test("throws when the port never comes up (fail-closed; manager handles --best-effort)", async () => {
  await assert.rejects(
    startNetProxy(plan(), Layout.dev("/repo"), "/run/sid", deps({ waitFor: async () => false })),
    /net-proxy/i,
  );
});

test("throws when MITM cert never appears", async () => {
  await assert.rejects(
    startNetProxy(
      plan({ requested: { netProxy: true, netProxyMitm: true, execWrap: false } }),
      Layout.dev("/repo"), "/run/sid", deps({ waitForFile: async () => false })),
    /CA cert/i,
  );
});

// ── ephemeral port (MANDU_NET_PROXY_PORT=0): kernel-assigned, published via
// the port file, adopted by the launcher. The point: no stale daemon (or the
// shared stack's pinned net-proxy) can ever squat this launch's rendezvous, so
// the conflict class above cannot occur.

/** Run `fn` with a REAL tmp scope-run dir (the port-file path must exist). */
async function withRunDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-netproxy-"));
  try { await fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

test("port 0: skips the reuse probe, spawns with port 0 + port file, adopts the bound port", async () => {
  await withPortEnv("0", () => withRunDir(async (dir) => {
    let capturedEnv: Record<string, string | undefined> = {};
    const probed: number[] = [];
    const r = await startNetProxy(plan(), Layout.dev("/repo"), dir,
      deps({
        probePort: async (_h, p) => { probed.push(p); return true; },
        probeIdentity: async () => matchingIdentity(),
        waitForFile: async (p) => existsSync(p),
        waitFor: async (check) => Boolean(await check()),
        startDetachedCmd: (_c, _a, { env }) => {
          capturedEnv = env;
          // The fake proxy publishes its kernel-assigned port, as server-main does.
          writeFileSync(env["MANDU_PORT_FILE"]!, "45679");
          return { pid: 1, stop: () => {} };
        },
      }));
    assert.equal(capturedEnv["MANDU_NET_PROXY_PORT"], "0");
    assert.equal(capturedEnv["MANDU_PORT_FILE"], join(dir, "net-proxy.port"));
    assert.equal(r.netProxy.port, 45679, "the launcher adopted the published port");
    assert.ok(!probed.includes(0), "never probed port 0 (no reuse rendezvous exists)");
  }));
});

test("DEFAULT (env unset, a1): port 0 — the port-file handshake, never the well-known 8790 a resident stack or another user holds", async () => {
  const saved = process.env["MANDU_NET_PROXY_PORT"];
  delete process.env["MANDU_NET_PROXY_PORT"];
  try {
    await withRunDir(async (dir) => {
      let capturedEnv: Record<string, string | undefined> = {};
      const probed: number[] = [];
      const r = await startNetProxy(plan(), Layout.dev("/repo"), dir,
        deps({
          // A foreign proxy answers on EVERY port: the default must never probe
          // (and so never adopt / conflict on) a well-known port.
          probePort: async (_h, p) => { probed.push(p); return true; },
          probeIdentity: async () => matchingIdentity(),
          waitForFile: async (p) => existsSync(p),
          waitFor: async (check) => Boolean(await check()),
          startDetachedCmd: (_c, _a, { env }) => {
            capturedEnv = env;
            writeFileSync(env["MANDU_PORT_FILE"]!, "41234");
            return { pid: 1, stop: () => {} };
          },
        }));
      assert.equal(capturedEnv["MANDU_NET_PROXY_PORT"], "0");
      assert.equal(capturedEnv["MANDU_PORT_FILE"], join(dir, "net-proxy.port"));
      assert.equal(r.netProxy.port, 41234);
      assert.ok(!probed.includes(8790), "the well-known port is never touched by default");
    });
  } finally {
    if (saved === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = saved;
  }
});

test("port 0: no port file within the wait is fail-closed (torn down)", async () => {
  await withPortEnv("0", () => withRunDir(async (dir) => {
    let stopped = 0;
    await assert.rejects(
      startNetProxy(plan(), Layout.dev("/repo"), dir,
        deps({
          waitForFile: async () => false,
          startDetachedCmd: () => ({ pid: 1, stop: () => { stopped++; } }),
        })),
      /net-proxy did not come up.*no port file.*its log: .*net-proxy\.log/i,
    );
    assert.equal(stopped, 1);
  }));
});

test("port 0: a proxy that EXITS before publishing its port ends the wait at once, fail-closed, naming the exit (runtime-instances.md §14.6)", async () => {
  await withPortEnv("0", () => withRunDir(async (dir) => {
    let stopped = 0;
    const t0 = Date.now();
    await assert.rejects(
      startNetProxy(plan(), Layout.dev("/repo"), dir,
        deps({
          waitForFile, // the real one: it honors the handle's exit
          startDetachedCmd: () => ({ pid: 1, stop: () => { stopped++; }, exited: () => ({ code: 2, signal: null }) }),
        })),
      /net-proxy did not come up \(no port file at .*: it exited with code 2 before becoming ready; its log: /,
    );
    assert.ok(Date.now() - t0 < 5000, "did not wait out the deadline");
    assert.equal(stopped, 1);
  }));
});

test("port 0: a garbled port file is fail-closed (never compose HTTP(S)_PROXY from it)", async () => {
  await withPortEnv("0", () => withRunDir(async (dir) => {
    let stopped = 0;
    await assert.rejects(
      startNetProxy(plan(), Layout.dev("/repo"), dir,
        deps({
          waitForFile: async (p) => existsSync(p),
          startDetachedCmd: (_c, _a, { env }) => {
            writeFileSync(env["MANDU_PORT_FILE"]!, "EADDRINUSE oops");
            return { pid: 1, stop: () => { stopped++; } };
          },
        })),
      /unusable port/i,
    );
    assert.equal(stopped, 1);
  }));
});

test("port 0: a STALE port file from a previous run is cleared before the spawn", async () => {
  await withPortEnv("0", () => withRunDir(async (dir) => {
    // A leftover file with a plausible port. If it survived, waitForFile would
    // see it instantly and the launcher would adopt a port nobody owns.
    writeFileSync(join(dir, "net-proxy.port"), "59999");
    await assert.rejects(
      startNetProxy(plan(), Layout.dev("/repo"), dir,
        deps({
          // The fake proxy never writes; a real existence check must time out
          // BECAUSE the stale file was removed.
          waitForFile: async (p) => existsSync(p),
        })),
      /no port file/i,
    );
  }));
});

// ── plan 10 §11.5: TLS inspection follows the confidentiality axis ──────────
test("MITM auto: ON when the confidentiality axis is on (env MITM=1, CA path returned); OFF when the axis is off", async () => {
  const seen: string[] = [];
  const mitmEnv = (over: Partial<LaunchPlan>) => deps({
    startDetachedCmd: (async (...args: unknown[]) => {
      const opts = args.find((a) => a && typeof a === "object" && "env" in (a as object)) as { env?: Record<string, string> } | undefined;
      seen.push(opts?.env?.["MANDU_NET_PROXY_MITM"] ?? "(none)");
      return (deps().startDetachedCmd as (...a: unknown[]) => unknown)(...args) as never;
    }) as never,
  });
  const on = await startNetProxy(
    plan({ requested: { netProxy: true, execWrap: false }, effectiveAxes: { integrity: false, confidentiality: true } }),
    Layout.dev("/repo"), "/run/sid", mitmEnv({}));
  assert.match(on.mitmCaCert!, /mandu-egress-ca\.pem$/, "auto-on: the CA is waited for and returned");
  const off = await startNetProxy(
    plan({ requested: { netProxy: true, execWrap: false }, effectiveAxes: { integrity: true, confidentiality: false } }),
    Layout.dev("/repo"), "/run/sid", mitmEnv({}));
  assert.equal(off.mitmCaCert, undefined, "auto-off with the axis off");
  const optOut = await startNetProxy(
    plan({ requested: { netProxy: true, netProxyMitm: false, execWrap: false }, effectiveAxes: { integrity: false, confidentiality: true } }),
    Layout.dev("/repo"), "/run/sid", mitmEnv({}));
  assert.equal(optOut.mitmCaCert, undefined, "--no-net-proxy-mitm wins over the axis");
});

test("MITM auto degrades with a notice when no CA appears; explicit --net-proxy-mitm still fails closed", async () => {
  const noCa = (over: Partial<LaunchPlan>) => startNetProxy(
    plan({ requested: { netProxy: true, execWrap: false }, effectiveAxes: { integrity: false, confidentiality: true }, ...over }),
    Layout.dev("/repo"), "/run/sid", deps({ waitForFile: async () => false }));
  const r = await noCa({});
  assert.equal(r.mitmCaCert, undefined);
  assert.match(r.mitmDegraded!, /TLS inspection unavailable/);
  await assert.rejects(noCa({ requested: { netProxy: true, netProxyMitm: true, execWrap: false } }), /CA cert never appeared/);
});

test("writeCaBundle: system CAs + the session CA in one file (skips when the host has no known bundle)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-ca-"));
  try {
    const session = join(dir, "mandu-egress-ca.pem");
    writeFileSync(session, "-----BEGIN CERTIFICATE-----\nSESSION\n-----END CERTIFICATE-----\n");
    const out = writeCaBundle(dir, session);
    if (out === undefined) return; // no system bundle on this host: nothing to assert
    const text = readFileSync(out, "utf8");
    assert.ok(text.endsWith("SESSION\n-----END CERTIFICATE-----\n"), "the session CA is appended last");
    assert.ok(text.length > 200, "the system store came first");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});


test("plan 12 F6 writeUserTrustFiles: each CA file the user set is merged with the session CA, once per source; junk is left alone", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-ca-"));
  try {
    const session = join(dir, "mandu-egress-ca.pem");
    writeFileSync(session, "-----BEGIN CERTIFICATE-----\nSESSION\n-----END CERTIFICATE-----\n");
    const corp = join(dir, "corp-root.pem");
    writeFileSync(corp, "-----BEGIN CERTIFICATE-----\nCORP\n-----END CERTIFICATE-----\n\n\n");
    const bundle = join(dir, "corp-bundle.pem");
    writeFileSync(bundle, "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nCORP\n-----END CERTIFICATE-----\n");
    const notPem = join(dir, "notes.txt");
    writeFileSync(notPem, "hello");
    const out = writeUserTrustFiles(dir, session, {
      NODE_EXTRA_CA_CERTS: corp,
      SSL_CERT_FILE: bundle,
      REQUESTS_CA_BUNDLE: bundle,
      GIT_SSL_CAINFO: notPem,
      CURL_CA_BUNDLE: join(dir, "missing.pem"),
      AWS_CA_BUNDLE: "  ",
      HOME: corp, // not a trust variable
    });
    assert.deepEqual(Object.keys(out).sort(), ["NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"]);
    assert.equal(out["SSL_CERT_FILE"], out["REQUESTS_CA_BUNDLE"], "one merged file per source path");
    assert.notEqual(out["NODE_EXTRA_CA_CERTS"], out["SSL_CERT_FILE"]);
    const node = readFileSync(out["NODE_EXTRA_CA_CERTS"]!, "utf8");
    assert.equal(node, "-----BEGIN CERTIFICATE-----\nCORP\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nSESSION\n-----END CERTIFICATE-----\n",
      "the user's CA first, the session CA appended");
    assert.match(readFileSync(out["SSL_CERT_FILE"]!, "utf8"), /PUBLIC[\s\S]*CORP[\s\S]*SESSION/);
    for (const p of Object.values(out)) assert.ok(p.startsWith(dir), "written into the session's CA directory");
    assert.deepEqual(writeUserTrustFiles(dir, join(dir, "no-session.pem"), { NODE_EXTRA_CA_CERTS: corp }), {}, "no session CA: nothing");
    assert.deepEqual(writeUserTrustFiles(dir, session, {}), {});
    assert.ok(TRUST_VARS.includes("CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the session's logins (secret-discovery.md §1.10): handed to the proxy, always set; a proxy started for another agent's launch is never adopted", async () => {
  let captured: Record<string, string | undefined> = {};
  let probes = 0;
  await startNetProxy(plan({ target: "codex", ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "codex" } }), Layout.dev("/repo"), "/run/sid",
    deps({ probePort: async () => probes++ > 0, startDetachedCmd: (_c, _a, { env }) => { captured = env; return { pid: 1, stop: () => {} }; }, probeIdentity: async () => matchingIdentity({ sessionLogins: { home: HOME, target: "codex", ullmBinary: "codex" } }), waitFor: async (check) => Boolean(await check()) }));
  const sent = JSON.parse(captured["MANDU_NET_PROXY_SESSION_LOGINS"] ?? "null") as Record<string, unknown>;
  assert.equal(sent["home"], HOME);
  assert.equal(sent["target"], "codex");
  assert.equal(sent["ullmBinary"], "codex");

  // A pinned port held by a proxy that exempts ANOTHER session's logins (a
  // `mandu codex` one under this `mandu claude`): refused, fail-closed.
  await assert.rejects(
    startNetProxy(plan(), Layout.dev("/repo"), "/run/sid",
      deps({ probePort: async () => true, probeIdentity: async () => matchingIdentity({ sessionLogins: { home: HOME, target: "codex", ullmBinary: "codex" } }) })),
    NetProxyConflictError,
  );
  // One that predates the field (none published): refused too.
  await assert.rejects(
    startNetProxy(plan(), Layout.dev("/repo"), "/run/sid",
      deps({ probePort: async () => true, probeIdentity: async () => matchingIdentity({ sessionLogins: undefined }) })),
    NetProxyConflictError,
  );
});
