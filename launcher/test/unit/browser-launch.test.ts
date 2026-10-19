/**
 * browser-launch — `mandu --browser` (docs/design/agents/devtools-relay.md
 * §6.4): the Chrome found (MANDU_BROWSER_BIN first), its command line (the
 * egress proxy, WebRTC kept to it, the session CA's pin, its own profile, a
 * kernel-assigned debugging port), the profile lock, the port file; the flag
 * and its conflict with --browser-cdp; the manager starting Chrome after the
 * egress proxy and before the relay, the relay put in front of it, both
 * stopped at teardown, a failed start refusing the launch; `startBrowser`
 * against a stand-in spawn.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import {
  BROWSER_BOTH_MESSAGE, browserEgressNote, chromeArgs, chromeCandidates, findChrome, headlessFor,
  parseDevToolsActivePort, profileHolder, spkiPin,
} from "../../src/browser-launch.js";
import { startBrowser } from "../../src/services/browser.js";
import { parse as parseIn } from "../../src/parse.js";
import { startServices } from "../../src/services/manager.js";
import { Layout } from "../../src/services/layout.js";
import type { ServiceDeps } from "../../src/services/primitives.js";
import type { LaunchPlan } from "../../src/types.js";
import { hermetic } from "../lib/test-runtime.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const parse = hermetic(parseIn, 1);

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "shell", argv: ["bash"], scopeId: "sid", tenant: "live", arbiterSock: "/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin", proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: false, bestEffort: false, replyFilter: true, ...over,
  };
}

const deps = {
  writeAgentConfig: () => ({ envVar: "X", path: "/x" }),
  startNetProxy: async () => ({ netProxy: { host: "127.0.0.1", port: 8790 }, stop: () => {} }),
  writeExecShims: () => "/shim",
  writeMcpConfig: () => "/w/.mcp.json",
  startContextProxy: async () => ({ host: "127.0.0.1", port: 8788, stop: () => {} }),
  startFsView: async () => null,
  startUllmForwarder: async () => ({ host: "127.0.0.1", port: 8791, url: "http://127.0.0.1:8791", stop: async () => {} }),
  inheritWorkspaceTrust: () => ({ action: "no-config" as const, file: "/nonexistent/.claude.json" }),
  inheritCodexTrust: () => ({ action: "no-config" as const, file: "/nonexistent/config.toml" }),
};

test("findChrome: MANDU_BROWSER_BIN wins (and must exist); else a name on PATH, then an install path", () => {
  const none = () => null;
  assert.equal(findChrome({ MANDU_BROWSER_BIN: "/x/chrome" }, "linux", none, (p) => p === "/x/chrome"), "/x/chrome");
  assert.equal(findChrome({ MANDU_BROWSER_BIN: "/x/chrome" }, "linux", () => "/usr/bin/chromium", () => false), null, "a named binary that is missing is not replaced");
  assert.equal(findChrome({}, "linux", (n) => (n === "chromium" ? "/usr/bin/chromium" : null), () => false), "/usr/bin/chromium");
  assert.equal(findChrome({}, "linux", (n) => (n === "google-chrome-stable" || n === "chromium" ? `/usr/bin/${n}` : null), () => false), "/usr/bin/google-chrome-stable", "PATH order");
  assert.equal(findChrome({}, "linux", none, (p) => p === "/opt/google/chrome/chrome"), "/opt/google/chrome/chrome");
  assert.equal(findChrome({}, "darwin", none, (p) => p === chromeCandidates("darwin").paths[0]), chromeCandidates("darwin").paths[0]);
  assert.equal(findChrome({}, "linux", none, () => false), null);
});

test("headlessFor: asked for, or Linux with no display; a window elsewhere", () => {
  assert.equal(headlessFor({ MANDU_BROWSER_HEADLESS: "1", DISPLAY: ":0" }, "linux"), true);
  assert.equal(headlessFor({}, "linux"), true);
  assert.equal(headlessFor({ DISPLAY: ":0" }, "linux"), false);
  assert.equal(headlessFor({ WAYLAND_DISPLAY: "wayland-0" }, "linux"), false);
  assert.equal(headlessFor({}, "darwin"), false);
  assert.equal(headlessFor({ MANDU_BROWSER_HEADLESS: "0" }, "linux"), true, "0 is not a request, but Linux with no display is headless anyway");
});

test("chromeArgs: a kernel-assigned debugging port, its own profile, the egress proxy with WebRTC kept to it, the CA's pin", () => {
  const a = chromeArgs({ profile: "/h/.mandu/state/browser", proxy: { host: "127.0.0.1", port: 8790 }, caPin: "PIN=", headless: true });
  assert.ok(a.includes("--remote-debugging-port=0"));
  assert.ok(a.includes("--user-data-dir=/h/.mandu/state/browser"));
  assert.ok(a.includes("--proxy-server=http://127.0.0.1:8790"));
  assert.ok(a.includes("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"));
  assert.ok(a.includes("--ignore-certificate-errors-spki-list=PIN="));
  assert.ok(a.includes("--headless"));
  assert.ok(!a.includes("--no-sandbox"), "the sandbox stays on unless asked");
  assert.ok(!a.some((x) => x.startsWith("--proxy-bypass-list")), "no bypass beyond Chrome's loopback default");
  assert.equal(a.at(-1), "about:blank");
  const bare = chromeArgs({ profile: "/p", headless: false, noSandbox: true });
  assert.ok(!bare.some((x) => x.startsWith("--proxy-server") || x.startsWith("--ignore-certificate") || x === "--headless"));
  assert.ok(bare.includes("--no-sandbox"));
});

test("spkiPin: base64 SHA-256 of the CA's public key, as openssl computes it", { skip: (() => { try { execFileSync("openssl", ["version"]); return false; } catch { return "openssl unavailable"; } })() }, () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-spki-"));
  try {
    const key = join(dir, "ca.key");
    const pem = join(dir, "ca.pem");
    execFileSync("openssl", ["ecparam", "-genkey", "-name", "prime256v1", "-out", key]);
    execFileSync("openssl", ["req", "-x509", "-new", "-key", key, "-subj", "/CN=pin test", "-days", "1", "-out", pem]);
    const text = readFileSync(pem, "utf8");
    const der = new X509Certificate(text).publicKey.export({ type: "spki", format: "der" });
    const viaOpenssl = execFileSync("openssl", ["pkey", "-pubin", "-outform", "der"], { input: execFileSync("openssl", ["x509", "-in", pem, "-pubkey", "-noout"]) });
    assert.equal(spkiPin(text), createHash("sha256").update(viaOpenssl).digest("base64"));
    assert.equal(spkiPin(text), createHash("sha256").update(der).digest("base64"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parseDevToolsActivePort: the first line's port, or null while not written", () => {
  assert.equal(parseDevToolsActivePort("41234\n/devtools/browser/abc\n"), 41234);
  assert.equal(parseDevToolsActivePort(""), null);
  assert.equal(parseDevToolsActivePort("0\n"), null);
  assert.equal(parseDevToolsActivePort("70000\n"), null);
  assert.equal(parseDevToolsActivePort("abc\n"), null);
});

test("profileHolder: a live Chrome of this host holds it; another host's, a gone pid, or no lock hold nothing", () => {
  const alive = (pid: number) => pid === 4242;
  assert.equal(profileHolder("box-4242", "box", alive), 4242);
  assert.equal(profileHolder("box-4243", "box", alive), null);
  assert.equal(profileHolder("other-4242", "box", alive), null);
  assert.equal(profileHolder("my-box-4242", "my-box", alive), 4242, "a host name with dashes");
  assert.equal(profileHolder(null, "box", alive), null);
  assert.equal(profileHolder("garbage", "box", alive), null);
});

test("browserEgressNote: warns with no egress proxy, notes a proxy that reads no HTTPS, silent otherwise", () => {
  assert.match(browserEgressNote(false, false)!, /^WARNING: .*straight to the network/);
  assert.match(browserEgressNote(true, false)!, /destination only/);
  assert.equal(browserEgressNote(true, true), null);
});

test("--browser and MANDU_BROWSER reach the plan; with --browser-cdp too the launch is refused", () => {
  assert.equal(parse(["--browser", "--", "bash"], {}).browser, true);
  assert.equal(parse(["--", "bash"], { MANDU_BROWSER: "1" }).browser, true);
  assert.equal(parse(["--", "bash"], { MANDU_BROWSER: "0" }).browser, undefined);
  assert.equal(parse(["--", "bash"], {}).browser, undefined);
  assert.throws(() => parse(["--browser", "--browser-cdp", "http://127.0.0.1:9222", "--", "bash"], {}), { message: BROWSER_BOTH_MESSAGE });
  assert.throws(() => parse(["--browser", "--", "bash"], { MANDU_BROWSER_CDP: "http://127.0.0.1:9222" }), { message: BROWSER_BOTH_MESSAGE });
});

test("manager: Chrome starts after the egress proxy (it is given it), the relay is put in front of it, both stop at teardown", async () => {
  const order: string[] = [];
  let seenProxy: unknown;
  const stopped: string[] = [];
  const lines: string[] = [];
  const p = plan({ browser: true });
  const h = await startServices(p, Layout.dev("/repo"), "/run/sid", {
    ...deps,
    startNetProxy: async () => { order.push("net-proxy"); return { netProxy: { host: "127.0.0.1", port: 8790 }, stop: () => { stopped.push("net-proxy"); } }; },
    startBrowser: async (pl) => {
      order.push("browser");
      seenProxy = pl.netProxy;
      return { endpoint: "http://127.0.0.1:41999", binary: "/usr/bin/chromium", profile: "/h/.mandu/state/browser", headless: true, note: null, stop: () => { stopped.push("browser"); } };
    },
    startCdpRelay: async (pl) => {
      order.push(`relay→${pl.browserCdp}`);
      return { host: "127.0.0.1", port: 40111, url: "http://127.0.0.1:40111", stop: () => { stopped.push("relay"); } };
    },
  }, (m) => lines.push(m));
  assert.deepEqual(order, ["net-proxy", "browser", "relay→http://127.0.0.1:41999"]);
  assert.deepEqual(seenProxy, { host: "127.0.0.1", port: 8790 });
  assert.equal(p.browserCdp, "http://127.0.0.1:41999");
  assert.deepEqual(p.cdpRelay, { host: "127.0.0.1", port: 40111, url: "http://127.0.0.1:40111" });
  assert.ok(lines.some((l) => l.startsWith("browser LIVE — Chrome (/usr/bin/chromium, headless)") && l.includes("through the egress proxy on 127.0.0.1:8790")), lines.join("\n"));
  await h.stop();
  assert.ok(stopped.includes("browser") && stopped.includes("relay"), stopped.join(","));
});

test("manager: a Chrome that cannot start refuses the launch; --best-effort launches with no browser and no relay", async () => {
  const failing = { ...deps, startBrowser: async () => { throw new Error("mandu: --browser found no Chrome"); }, startCdpRelay: async () => { throw new Error("must not start"); } };
  await assert.rejects(startServices(plan({ browser: true }), Layout.dev("/repo"), "/run/sid", failing, () => {}), /found no Chrome/);
  const p = plan({ browser: true, bestEffort: true });
  const lines: string[] = [];
  await (await startServices(p, Layout.dev("/repo"), "/run/sid", failing, (m) => lines.push(m))).stop();
  assert.equal(p.browserCdp, undefined);
  assert.equal(p.cdpRelay, undefined);
  assert.ok(lines.some((l) => /found no Chrome.*WITHOUT it/.test(l)), lines.join("\n"));
});

test("manager: no --browser, no Chrome", async () => {
  let called = false;
  const p = plan();
  await (await startServices(p, Layout.dev("/repo"), "/run/sid", { ...deps, startBrowser: async () => { called = true; throw new Error("no"); } }, () => {})).stop();
  assert.equal(called, false);
});

// ── startBrowser against a stand-in spawn ─────────────────────────────────

function standIn(profile: string, behaviour: "writes" | "exits") {
  const spawned: { cmd: string; args: string[] }[] = [];
  let stops = 0;
  let exited = false;
  const d = {
    probePort: async () => true,
    probeIdentity: async () => null,
    waitFor: async (check: () => boolean | Promise<boolean>, o: { tries: number; delayMs: number; giveUp?: () => boolean }) => {
      for (let i = 0; i < Math.min(o.tries, 20); i++) {
        if (await check()) return true;
        if (o.giveUp?.()) return false;
        await new Promise((r) => setTimeout(r, 5));
      }
      return false;
    },
    waitForFile: async () => true,
    startDetachedCmd: (cmd: string, args: string[]) => {
      spawned.push({ cmd, args });
      if (behaviour === "writes") writeFileSync(join(profile, "DevToolsActivePort"), "41777\n/devtools/browser/x\n");
      else exited = true;
      return { pid: 1, exited: () => (exited ? { code: 0, signal: null } : null), stop: () => { stops++; }, stopLeader: () => {} };
    },
    runOnce: () => ({ status: 0, stdout: "", stderr: "" }),
  } as unknown as ServiceDeps;
  return { d, spawned, stops: () => stops };
}

test("startBrowser: removes the last run's port file, starts Chrome on the profile with the proxy and pin, reads its port", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-browser-"));
  try {
    const profile = join(dir, "profile");
    mkdirSync(profile, { recursive: true });
    writeFileSync(join(profile, "DevToolsActivePort"), "39999\n/devtools/browser/stale\n");
    const bin = join(dir, "chrome");
    writeFileSync(bin, "");
    const s = standIn(profile, "writes");
    // The stand-in writes the port file at spawn; the stale one was removed first.
    const ca = join(dir, "ca.pem");
    const hasOpenssl = (() => { try { execFileSync("openssl", ["version"]); return true; } catch { return false; } })();
    if (hasOpenssl) {
      execFileSync("openssl", ["ecparam", "-genkey", "-name", "prime256v1", "-out", join(dir, "ca.key")]);
      execFileSync("openssl", ["req", "-x509", "-new", "-key", join(dir, "ca.key"), "-subj", "/CN=t", "-days", "1", "-out", ca]);
    }
    const r = await startBrowser({ netProxy: { host: "127.0.0.1", port: 8790 }, ...(hasOpenssl ? { mitmCaCert: ca } : {}) }, dir, s.d, { env: { MANDU_BROWSER_BIN: bin, PATH: "" }, platform: "linux", profile });
    assert.equal(r.endpoint, "http://127.0.0.1:41777");
    assert.equal(r.headless, true, "no display");
    assert.equal(s.spawned.length, 1);
    assert.equal(s.spawned[0]!.cmd, bin);
    assert.ok(s.spawned[0]!.args.includes(`--user-data-dir=${profile}`));
    assert.ok(s.spawned[0]!.args.includes("--proxy-server=http://127.0.0.1:8790"));
    if (hasOpenssl) {
      assert.ok(s.spawned[0]!.args.includes(`--ignore-certificate-errors-spki-list=${spkiPin(readFileSync(ca, "utf8"))}`));
      assert.equal(r.note, null);
    } else {
      assert.match(r.note!, /destination only/);
    }
    r.stop();
    assert.equal(s.stops(), 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("startBrowser: a profile a live Chrome holds is refused before anything starts; no Chrome found is refused", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-browser-"));
  try {
    const profile = join(dir, "profile");
    mkdirSync(profile, { recursive: true });
    symlinkSync(`${hostname()}-${process.pid}`, join(profile, "SingletonLock"));
    const bin = join(dir, "chrome");
    writeFileSync(bin, "");
    const s = standIn(profile, "writes");
    await assert.rejects(startBrowser({}, dir, s.d, { env: { MANDU_BROWSER_BIN: bin }, platform: "linux", profile }), new RegExp(`in use by Chrome \\(pid ${process.pid}\\)`));
    assert.equal(s.spawned.length, 0);
    await assert.rejects(startBrowser({}, dir, s.d, { env: { MANDU_BROWSER_BIN: join(dir, "missing") }, platform: "linux", profile: join(dir, "p2") }), /found no Chrome/);
    assert.equal(existsSync(join(dir, "p2")), false, "nothing made for a launch that found no Chrome");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("startBrowser: a Chrome that exits without opening its port is refused and stopped; with no egress proxy the launch is warned", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-browser-"));
  try {
    const profile = join(dir, "profile");
    const bin = join(dir, "chrome");
    writeFileSync(bin, "");
    const s = standIn(profile, "exits");
    await assert.rejects(startBrowser({}, dir, s.d, { env: { MANDU_BROWSER_BIN: bin }, platform: "linux", profile }), /did not open its debugging port/);
    assert.equal(s.stops(), 1);
    const ok = standIn(profile, "writes");
    const r = await startBrowser({}, dir, ok.d, { env: { MANDU_BROWSER_BIN: bin, DISPLAY: ":0" }, platform: "linux", profile });
    assert.equal(r.headless, false);
    assert.ok(!ok.spawned[0]!.args.some((a) => a.startsWith("--proxy-server")));
    assert.match(r.note!, /^WARNING: .*straight to the network/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
