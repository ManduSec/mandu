#!/usr/bin/env node
// tour-screenshots — regenerate the first-session tour's dashboard
// screenshots (docs/first-session.md, docs/assets/tour/): Home, the session
// page's top, the turn whose Read was masked only later, and an Approvals
// card. No model call, no API key, nothing of the person's own Mandu.
// docs-lane-exempt: it WRITES the screenshots into docs/assets/tour (its
// default --out) and reads no doc.
//
// What it runs, all in this process or under it, all on loopback:
//   - a real ArbiterServer (the `secrets` axes) and a real DashboardServer over
//     a real ArbiterEventSource, wired as the stack suites wire them, with the
//     symbol DB, the event store, MANDU_HOME and HOME in one temp dir;
//   - the event store seeded with the recorded first-session tour
//     (dashboard/test/fixtures/tour-<id>.ndjson, fake secrets): its times moved
//     so it ended a minute and a half ago, its home folder the temp HOME, its
//     two questions worded as the tour words them, its file named and written
//     as the tour's (RECORDED_RENAMES); and a second Claude Code session,
//     still running, that reads deploy/staging.tfvars after it was marked
//     secret (built here, in the recorded events' shapes);
//   - for the Approvals card, a real pending send: the temp `.env` registered
//     as a secret and the arbiter's egress gate asked about its key at
//     api.stripe.com, which no rule binds it to (as
//     tests/stack/approval-names-secret.test.ts does);
//   - a headless Chromium driven over the DevTools protocol (Node's own
//     WebSocket, no npm dependency): 980 CSS px wide, light theme, signed in
//     with the dashboard's one-time admin link, each picture clipped to its
//     page region.
// Then it stops the browser and the servers and removes the temp dir. The
// clock times on the pictures are the run's own (the tour's moments moved to
// now); everything else is fixed.
//
// The browser: --browser <path>, else $MANDU_TOUR_BROWSER, else $CHROME_PATH,
// else the newest Playwright headless shell or Chromium under
// ~/.cache/ms-playwright, else chrome-headless-shell / chromium /
// google-chrome on PATH. None found: it says SKIP and exits 0. Where the
// kernel refuses Chromium's own sandbox (unprivileged user namespaces off),
// it retries with --no-sandbox: the browser opens only this run's loopback
// dashboard.
//
// The browser plumbing (probeBrowser, startBrowser, Cdp, stopProc) is
// exported for the other tools that drive a dashboard page in a headless
// browser; importing this file runs nothing.
//
// The pictures are written as PNG, reduced to a 256-colour palette when
// ImageMagick (`magick` or `convert`) is on PATH.
//
// Needs arbiter/ and dashboard/ installed (`node scripts/install-deps.mjs
// tests` installs both, and tsx with them).
//
// Usage (from anywhere):
//   node scripts/tour-screenshots.mjs [--browser <path>] [--out <dir>] [--only home,session,masked-later,approval]
//     --out   where to write (default docs/assets/tour; sent.png is not made here)
//     --only  a comma-separated subset of the four pictures
import { spawn, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The width every tour picture has, in CSS px (and device px: scale 1). */
export const WIDTH = 980;
/** The recorded tour session (dashboard/test/fixtures/). */
export const TOUR_SESSION = "1791164083-1418381";
/** The second session: Claude Code started again after the file's label. */
export const STAGING_SESSION = "1791165040-1420117";
/** The home folder the recording was made in. */
export const RECORDED_HOME = "/home/user";
/** The two questions as the tour asks them (the recording asked them shorter). */
export const PROMPTS = [
  ["What is in .env?", "What is in .env? Show me its lines."],
  ["What is in deploy/staging.conf?", "What is in deploy/staging.tfvars? Show me its lines."],
];
/** The tour's step-3 file as the recording has it, and as the tour has it
 *  now (raw NDJSON text, so a quote is `\"`): the recording was made with
 *  `deploy/staging.conf`, a file the default catalog's content tier finds
 *  since 2026-10-19 (secret-discovery.md §2.9), and the tour moved to a
 *  Terraform variables file it does not (tests/stack/first-session-fixture
 *  .test.ts). Applied after PROMPTS. */
export const RECORDED_RENAMES = [
  ["staging.conf", "staging.tfvars"],
  ["host = staging.example.com", 'host = \\"staging.example.com\\"'],
];
/** The fake values of the tour's two secrets: never on a picture. */
export const FAKE_VALUES = ["sk_live_fake_123456", "FAKE-STAGING-TOKEN-0000", "FAKE-STRIPE-KEY-0000"];
export const SHOTS = ["home", "session", "masked-later", "approval"];

// ── pure parts (scripts/test/tour-screenshots.test.mjs) ───────────────────────

/** Version-ish order of `name-1243` style directory names, newest first. */
function newestFirst(names) {
  const num = (s) => Number(/-(\d+)$/.exec(s)?.[1] ?? -1);
  return [...names].sort((a, b) => num(b) - num(a));
}

/**
 * The browser to drive, or null. `io` is injectable for the test:
 * `{ exists(path), list(dir) → names | [] }`.
 */
export function probeBrowser({ flag = null, env = process.env, home = homedir(), io = defaultIo } = {}) {
  for (const p of [flag, env.MANDU_TOUR_BROWSER, env.CHROME_PATH]) {
    if (typeof p === "string" && p !== "") return io.exists(p) ? p : null;
  }
  const cache = env.PLAYWRIGHT_BROWSERS_PATH || join(home, ".cache", "ms-playwright");
  const names = io.list(cache);
  const shells = newestFirst(names.filter((n) => n.startsWith("chromium_headless_shell-")));
  const full = newestFirst(names.filter((n) => /^chromium-\d+$/.test(n)));
  for (const d of shells) {
    for (const sub of ["chrome-headless-shell-linux64", "chrome-linux"]) {
      const p = join(cache, d, sub, sub === "chrome-linux" ? "headless_shell" : "chrome-headless-shell");
      if (io.exists(p)) return p;
    }
  }
  for (const d of full) {
    for (const p of [join(cache, d, "chrome-linux64", "chrome"), join(cache, d, "chrome-linux", "chrome")]) {
      if (io.exists(p)) return p;
    }
  }
  for (const dir of (env.PATH ?? "").split(delimiter).filter(Boolean)) {
    for (const name of ["chrome-headless-shell", "chromium", "chromium-browser", "google-chrome"]) {
      if (io.exists(join(dir, name))) return join(dir, name);
    }
  }
  return null;
}

const defaultIo = {
  exists: (p) => existsSync(p),
  list: (d) => { try { return readdirSync(d); } catch { return []; } },
};

/**
 * The recorded tour's events, ready to seed: moved in time so the last one
 * is at `endMs`, the recorded home folder replaced by `home`, and the
 * questions worded as the tour words them. Lines in, events out.
 */
export function movedTour(lines, { endMs, home }) {
  let text = lines.join("\n");
  text = text.split(`${RECORDED_HOME}/`).join(`${home}/`);
  for (const [from, to] of [...PROMPTS, ...RECORDED_RENAMES]) text = text.split(from).join(to);
  const events = text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const shift = endMs - Date.parse(events[events.length - 1].ts);
  return events.map((e) => ({ ...e, ts: new Date(Date.parse(e.ts) + shift).toISOString() }));
}

const dr = (symbolized, original = null, symbols = []) =>
  ({ symbolized, original, differs: original !== null && original !== symbolized, symbols });

/**
 * The second session: Claude Code started again after `deploy/staging.tfvars`
 * was marked secret, asked the same question, got the file with its token as
 * a placeholder, and is still running. In the shapes the launcher and the
 * anthropic-proxy write (as the recorded tour's own); `launch` and `client`
 * are the recorded session's launch_posture and client_info events, reused.
 */
export function stagingSession({ session = STAGING_SESSION, startMs, home, launch, client }) {
  const out = [];
  let seq = 1;
  const ev = (kind, f = {}) => {
    out.push({
      id: `${session}-${String(seq).padStart(3, "0")}`, sessionId: session, turn: 0, ts: new Date(startMs + seq * 4000).toISOString(), seq,
      callId: null, parentId: null, kind, view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
      input: null, output: null, invariant: { violatedInvariant: false }, tenant: "live", ...f,
    });
    seq++;
  };
  const strip = ({ id: _i, sessionId: _s, ts: _t, seq: _q, ...rest }) => rest;
  if (launch) ev(launch.kind, strip(launch));
  if (client) ev(client.kind, strip(client));
  const file = `${home}/mandu-try/deploy/staging.tfvars`;
  const token = "$MDU:nomodel_Read[3f0b].token";
  const sys = "▸ system\nYou are Claude Code, Anthropic's official CLI for Claude.";
  const user = `▸ user\n${PROMPTS[1][1]}`;
  const read = `Read(${JSON.stringify({ file_path: file })})`;
  const lines = `1\thost = "staging.example.com"\n2\ttoken = "${token}"\n3\t`;
  ev("tllm_call", { turn: 1, input: dr(`${sys}\n\n${user}`), output: dr(`→ ${read}`), model: { id: "claude-opus-5-5" } });
  ev("tool_use", { turn: 1, callId: "toolu_01StagingRead0000000001", input: dr(read) });
  ev("tool_result", {
    turn: 2, callId: "toolu_01StagingRead0000000001",
    output: dr(lines, lines, [{ name: token, tool: "Read", field: "token", origin: file, value: null, confidentiality: "no-model" }]),
    policy: { trust: "TRUSTED", reason: "integrity axis OFF — trust classification disabled; structured read-twin: no secret byte in the rendering (plan 10 §2.4)", confidentiality: "no-model" },
  });
  ev("tllm_call", {
    turn: 2, model: { id: "claude-opus-5-5" },
    input: dr(`${sys}\n\n${user}\n\n▸ tool_result\n${lines}`),
    output: dr(`\`deploy/staging.tfvars\` has two settings:\n\n- **\`host\`**: \`staging.example.com\`\n- **\`token\`**: ${token}. Mandu protects this file, so the token reached me only as a placeholder.`),
  });
  ev("desymbolize", { view: "HumanView", emitter: "reply-filter", input: dr(`token = "${token}"`), output: dr(`token = "${token}"`) });
  return out;
}

/**
 * The screenshot clip for a page region `{ top, bottom }` (document CSS px):
 * the full page width, `pad` above and below (a number, or `{ top, bottom }`),
 * whole pixels, never above 0.
 */
export function clipFor(region, { width = WIDTH, pad = 16 } = {}) {
  if (!region || !(region.bottom > region.top)) throw new Error(`no region to capture: ${JSON.stringify(region)}`);
  const { top = 0, bottom: below = 0 } = typeof pad === "number" ? { top: pad, bottom: pad } : pad;
  const y = Math.max(0, Math.floor(region.top - top));
  const bottom = Math.ceil(region.bottom + below);
  return { x: 0, y, width, height: bottom - y, scale: 1 };
}

/** The fake secret values found in `text` (should be none). */
export function leakedValues(text) {
  return FAKE_VALUES.filter((v) => text.includes(v)).concat(/\$MDU:/.test(text) ? ["$MDU token"] : []);
}

export function parseArgs(argv) {
  const o = { browser: null, out: join(REPO_ROOT, "docs", "assets", "tour"), only: [...SHOTS] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { const v = argv[++i]; if (v === undefined) throw new Error(`${a} needs a value`); return v; };
    if (a === "--browser") o.browser = val();
    else if (a === "--out") o.out = resolve(val());
    else if (a === "--only") {
      o.only = val().split(",").map((s) => s.trim()).filter(Boolean);
      const bad = o.only.filter((s) => !SHOTS.includes(s));
      if (bad.length) throw new Error(`unknown picture(s): ${bad.join(", ")} (known: ${SHOTS.join(", ")})`);
    } else if (a === "-h" || a === "--help") o.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return o;
}

// ── the DevTools protocol, over Node's own WebSocket ─────────────────────────

export class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.next = 1;
    this.pending = new Map();
    ws.addEventListener("message", (m) => {
      const msg = JSON.parse(String(m.data));
      const p = msg.id !== undefined ? this.pending.get(msg.id) : undefined;
      if (!p) return;
      this.pending.delete(msg.id);
      if (msg.error) p.reject(new Error(`${p.method}: ${msg.error.message}`));
      else p.resolve(msg.result);
    });
    ws.addEventListener("close", () => {
      for (const p of this.pending.values()) p.reject(new Error("the browser closed the DevTools connection"));
      this.pending.clear();
    });
  }
  static connect(url) {
    return new Promise((ok, fail) => {
      const ws = new WebSocket(url);
      ws.addEventListener("open", () => ok(new Cdp(ws)), { once: true });
      ws.addEventListener("error", () => fail(new Error(`cannot connect to ${url}`)), { once: true });
    });
  }
  send(method, params = {}, sessionId = undefined) {
    const id = this.next++;
    return new Promise((resolveP, reject) => {
      this.pending.set(id, { resolve: resolveP, reject, method });
      this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  close() { try { this.ws.close(); } catch { /* gone */ } }
}

/** Start the browser; answer `{ proc, wsUrl }`. Retries once with
 *  --no-sandbox when the kernel refuses Chromium's sandbox. The browser
 *  leads a process group of its own (see stopProc). */
export async function startBrowser(path, dataDir, env) {
  const base = [
    "--headless", "--remote-debugging-port=0", `--user-data-dir=${dataDir}`, "--hide-scrollbars",
    "--no-first-run", "--no-default-browser-check", "--disable-gpu", "--disable-extensions",
    "--force-color-profile=srgb", "--lang=en-US", "about:blank",
  ];
  for (const extra of [[], ["--no-sandbox"]]) {
    const proc = spawn(path, [...extra, ...base], { env, stdio: ["ignore", "ignore", "pipe"], detached: true });
    trackGroup(proc);
    let err = "";
    const wsUrl = await new Promise((ok) => {
      const timer = setTimeout(() => ok(null), 20_000);
      proc.stderr.on("data", (d) => {
        err += String(d);
        const m = /DevTools listening on (ws:\/\/\S+)/.exec(err);
        if (m) { clearTimeout(timer); ok(m[1]); }
      });
      proc.on("exit", () => { clearTimeout(timer); ok(null); });
    });
    if (wsUrl) return { proc, wsUrl };
    await stopProc(proc);
    if (extra.length === 0 && /No usable sandbox|setuid sandbox|namespace/i.test(err)) {
      console.error("tour-screenshots: this kernel refuses Chromium's sandbox; retrying with --no-sandbox (it opens only this run's loopback dashboard)");
      continue;
    }
    throw new Error(`the browser did not start: ${err.trim().split("\n").slice(-3).join(" | ")}`);
  }
  throw new Error("the browser did not start");
}

// Chromium's helpers (zygote, renderers, the GPU and network services, the
// crash handler) write into the profile too, and outlive the main process by
// a moment: a profile removed when only the main process has exited fails
// with ENOTEMPTY as a helper writes into it (GitHub CI, 2026-10-22). So
// startBrowser makes the browser the leader of its own process group, and
// stopProc ends the whole group and returns only once none of it is left.
// A group still running when this process exits is killed then.
const liveGroups = new Set();
let exitHooked = false;

function trackGroup(proc) {
  if (proc.pid === undefined) return;
  if (!exitHooked) {
    exitHooked = true;
    process.on("exit", () => {
      for (const pid of liveGroups) { try { process.kill(-pid, "SIGKILL"); } catch { /* gone */ } }
    });
  }
  liveGroups.add(proc.pid);
}

/** Some process of the group `pid` leads is still there. */
export function groupAlive(pid) {
  try { process.kill(-pid, 0); return true; } catch (e) { return e.code === "EPERM"; }
}

/**
 * Stop `proc` and, when it leads a process group (startBrowser's browser),
 * every process of the group: SIGTERM, SIGKILL after `graceMs`, and resolve
 * once the process has exited and none of its group is left (at most
 * `waitMs` more after the SIGKILL). A process that leads no group is
 * stopped alone, as before.
 */
export async function stopProc(proc, { graceMs = 3000, waitMs = 10_000 } = {}) {
  const pid = proc.pid;
  const group = pid !== undefined && liveGroups.has(pid);
  const exited = proc.exitCode !== null || proc.signalCode !== null
    ? Promise.resolve()
    : new Promise((r) => proc.once("exit", () => r()));
  const signal = (sig) => {
    if (group) { try { process.kill(-pid, sig); return; } catch { /* the group is gone */ } }
    try { proc.kill(sig); } catch { /* gone */ }
  };
  const gone = async (ms) => {
    const end = Date.now() + ms;
    let done = false;
    void exited.then(() => { done = true; });
    for (;;) {
      await new Promise((r) => setTimeout(r, 25));
      if (done && !(group && groupAlive(pid))) return true;
      if (Date.now() >= end) return false;
    }
  };
  signal("SIGTERM");
  if (!(await gone(graceMs))) {
    signal("SIGKILL");
    if (!(await gone(waitMs))) {
      throw new Error(`the browser (pid ${pid}) or a process of its group outlived SIGKILL by ${waitMs} ms`);
    }
  }
  if (group) liveGroups.delete(pid);
}

/** Remove a browser's profile (or the directory holding it) once stopProc
 *  has returned: with retries, for a file system that answers ENOTEMPTY or
 *  EBUSY for a moment after the last writer is gone. */
export function removeProfile(dir) {
  rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}

/** One browser tab, signed in to the dashboard at `base`. */
async function openTab(cdp) {
  const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
  const s = (method, params) => cdp.send(method, params, sessionId);
  await s("Page.enable");
  await s("Runtime.enable");
  await s("Emulation.setDeviceMetricsOverride", { width: WIDTH, height: 1200, deviceScaleFactor: 1, mobile: false });
  await s("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }, { name: "prefers-reduced-motion", value: "reduce" }] });
  const evaluate = async (expression) => {
    const r = await s("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
    return r.result.value;
  };
  return {
    s, evaluate,
    async go(url, ready, what) {
      await s("Page.navigate", { url });
      const deadline = Date.now() + 20_000;
      for (;;) {
        let ok = false;
        try { ok = await evaluate(`(() => { try { return document.readyState === "complete" && document.fonts.status === "loaded" && !!(${ready}); } catch { return false; } })()`); } catch { /* navigating */ }
        if (ok) break;
        if (Date.now() > deadline) throw new Error(`${what}: the page never got ready (${ready})`);
        await new Promise((r) => setTimeout(r, 150));
      }
      // Let the last fetches land and the layout settle.
      await new Promise((r) => setTimeout(r, 600));
      await evaluate("new Promise((r) => { scrollTo(0, 0); requestAnimationFrame(() => requestAnimationFrame(() => r(true))); })");
    },
  };
}

// The page regions, measured in the page (document CSS px).
const REGION = {
  home: `(() => {
    const top = document.getElementById("hero").getBoundingClientRect().top;
    const bottom = document.getElementById("home-earlier-block").getBoundingClientRect().bottom;
    return { top: top + scrollY, bottom: bottom + scrollY, text: document.getElementById("page-home").innerText };
  })()`,
  session: `(() => {
    const page = document.getElementById("page-agent");
    const top = page.querySelector(".page-head").getBoundingClientRect().top;
    const step = document.querySelector("#agent-story .turn .step");
    return { top: top + scrollY, bottom: step.getBoundingClientRect().bottom + scrollY, text: page.innerText };
  })()`,
  "masked-later": `(() => {
    const raw = document.querySelector("#agent-story .step.raw");
    const turn = raw.closest(".turn");
    return { top: turn.getBoundingClientRect().top + scrollY, bottom: raw.getBoundingClientRect().bottom + scrollY, text: turn.innerText };
  })()`,
  approval: `(() => {
    const card = document.querySelector("#approvals-waiting .ask");
    const head = document.getElementById("approvals-waiting").previousElementSibling;
    return { top: head.getBoundingClientRect().top + scrollY, bottom: card.getBoundingClientRect().bottom + scrollY, text: card.innerText };
  })()`,
};
// A picture that ends inside a card ends at its row's edge.
const PAD = { home: 16, session: { top: 16, bottom: 0 }, "masked-later": { top: 1, bottom: 0 }, approval: 14 };

async function capture(tab, name, outDir, tmp) {
  const region = await tab.evaluate(REGION[name]);
  const leaks = leakedValues(region.text);
  if (leaks.length) throw new Error(`${name}: the page shows ${leaks.join(", ")}; refusing to save it`);
  const clip = clipFor(region, { pad: PAD[name] });
  const { data } = await tab.s("Page.captureScreenshot", { format: "png", clip, captureBeyondViewport: true, fromSurface: true });
  const raw = join(tmp, `${name}.raw.png`);
  writeFileSync(raw, Buffer.from(data, "base64"));
  const out = join(outDir, `${name}.png`);
  const im = ["magick", "convert"].find((c) => spawnSync(c, ["-version"], { stdio: "ignore" }).status === 0);
  const quantized = join(tmp, `${name}.png`);
  // A copy, not a rename: the temp dir may be on another filesystem.
  const made = im && spawnSync(im, [raw, "+dither", "-colors", "256", `PNG8:${quantized}`], { stdio: "inherit" }).status === 0;
  copyFileSync(made ? quantized : raw, out);
  console.log(`tour-screenshots: wrote ${out} (${clip.width}x${clip.height})`);
}

// ── the run ───────────────────────────────────────────────────────────────────

function tsxApi() {
  for (const pkg of ["tests", "dashboard", "arbiter"]) {
    const p = join(REPO_ROOT, pkg, "node_modules", "tsx", "dist", "esm", "api", "index.mjs");
    if (existsSync(p)) return p;
  }
  return null;
}

async function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`tour-screenshots: ${e.message}`); process.exit(2); }
  if (o.help) {
    console.log("usage: node scripts/tour-screenshots.mjs [--browser <path>] [--out <dir>] [--only home,session,masked-later,approval]");
    return;
  }
  const browser = probeBrowser({ flag: o.browser });
  if (!browser) {
    console.log("tour-screenshots: SKIP: no Chromium found (pass --browser <path> or set MANDU_TOUR_BROWSER; a Playwright headless shell under ~/.cache/ms-playwright is found by itself)");
    return;
  }
  const api = tsxApi();
  const installed = ["arbiter", "dashboard"].every((p) => existsSync(join(REPO_ROOT, p, "node_modules")));
  if (!api || !installed) {
    console.error("tour-screenshots: arbiter/ and dashboard/ need their node_modules: run `node scripts/install-deps.mjs tests` first");
    process.exit(1);
  }

  const tmp = mkdtempSync(join(tmpdir(), "mandu-tour-shots-"));
  const home = join(tmp, "home");
  const project = join(home, "mandu-try");
  mkdirSync(join(project, "deploy"), { recursive: true });
  // Nothing of the person's own Mandu: every path the servers derive from
  // HOME or MANDU_HOME lands here, and no running stack is joined.
  for (const k of Object.keys(process.env)) if (k.startsWith("MANDU_") && k !== "MANDU_TOUR_BROWSER") delete process.env[k];
  process.env.HOME = home;
  process.env.MANDU_HOME = join(tmp, "mandu-home");
  process.env.MANDU_POLICY_FILE = join(tmp, "no-policy.yaml");

  const cleanup = [];
  const stopAll = async () => {
    while (cleanup.length) {
      try { await cleanup.pop()(); } catch (e) { console.error(`tour-screenshots: cleanup: ${e.message}`); }
    }
    removeProfile(tmp);
  };
  const onSignal = () => { void stopAll().finally(() => process.exit(130)); };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  try {
    // The tour's folder, with its two fake secrets.
    const envFile = join(project, ".env");
    writeFileSync(envFile, "STRIPE_KEY='sk_live_fake_123456'\nDEBUG=1\n");
    writeFileSync(join(project, "deploy", "staging.tfvars"), 'host = "staging.example.com"\ntoken = "FAKE-STAGING-TOKEN-0000"\n');

    // The event store: the tour ended 90 s ago; the second session runs.
    const eventDir = join(tmp, "events");
    mkdirSync(eventDir, { recursive: true });
    const now = Date.now();
    const fixture = join(REPO_ROOT, "dashboard", "test", "fixtures", `tour-${TOUR_SESSION}.ndjson`);
    const tour = movedTour(readFileSync(fixture, "utf8").split("\n"), { endMs: now - 90_000, home });
    const staging = stagingSession({
      startMs: now - 70_000, home,
      launch: tour.find((e) => e.kind === "launch_posture"), client: tour.find((e) => e.kind === "client_info"),
    });
    for (const [id, events] of [[TOUR_SESSION, tour], [STAGING_SESSION, staging]]) {
      writeFileSync(join(eventDir, `${id}.ndjson`), events.map((e) => JSON.stringify(e)).join("\n") + "\n");
    }

    const { tsImport } = await import(pathToFileURL(api).href);
    const load = (rel) => tsImport(pathToFileURL(join(REPO_ROOT, rel)).href, import.meta.url);
    const { ArbiterServer } = await load("arbiter/ipc/server.ts");
    const { ArbiterClient } = await load("arbiter/ipc/client.ts");
    const { DashboardServer } = await load("dashboard/src/server.ts");
    const { ArbiterEventSource } = await load("dashboard/src/event-source.ts");

    const socketPath = join(tmp, "arbiter.sock");
    const adminPath = join(tmp, "admin.sock");
    const humanPath = join(tmp, "human", "h.sock");
    const arbiter = new ArbiterServer({
      socketPath, adminSocketPath: adminPath, humanSocketPath: humanPath,
      dbPath: join(tmp, "symbols.sqlite"), eventDir, log: () => {},
      confidentiality: true, integrity: false, // the `secrets` mode, the tour's
    });
    await arbiter.listen();
    cleanup.push(() => arbiter.close());
    const gate = new ArbiterClient(socketPath); await gate.connect();
    cleanup.push(() => gate.close());
    const admin = new ArbiterClient(adminPath); await admin.connect();
    cleanup.push(() => admin.close());
    const dashboard = new DashboardServer({
      source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
      approvalsArbiter: {
        egressApprovals: (status) => admin.egressApprovals(status),
        resolveEgressApproval: (id, approve, scope) => admin.resolveEgressApproval(id, approve, scope),
      },
      fileBrowserHome: home,
      configEnv: { MANDU_HOME: process.env.MANDU_HOME, HOME: home },
      log: () => {},
    });
    const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
    cleanup.push(() => dashboard.close());

    const { proc, wsUrl } = await startBrowser(browser, join(tmp, "browser"), { ...process.env, HOME: home });
    cleanup.push(() => stopProc(proc));
    const cdp = await Cdp.connect(wsUrl);
    cleanup.push(() => cdp.close());
    const tab = await openTab(cdp);
    mkdirSync(o.out, { recursive: true });

    // Signed in, as the tour's reader is (its launch line's link).
    await tab.go(`${base}${dashboard.adminLoginPath()}`, `document.getElementById("hero-headline").textContent !== "Checking…"`, "sign-in");

    // Home first: nothing is waiting yet.
    if (o.only.includes("home")) {
      await tab.go(`${base}/`, `document.querySelectorAll("#home-agents .row.agent").length === 1 && document.querySelectorAll("#home-earlier .row.agent").length === 1 && document.getElementById("hero-headline").textContent !== "Checking…"`, "home");
      await capture(tab, "home", o.out, tmp);
    }
    if (o.only.includes("session") || o.only.includes("masked-later")) {
      await tab.go(`${base}/agents/${TOUR_SESSION}`, `document.querySelectorAll("#agent-story .turn .step").length > 0 && document.querySelector("#agent-secrets .secret-card") && document.querySelector("#agent-story .step.raw")`, "session page");
      if (o.only.includes("session")) await capture(tab, "session", o.out, tmp);
      if (o.only.includes("masked-later")) await capture(tab, "masked-later", o.out, tmp);
    }
    if (o.only.includes("approval")) {
      // A real pending send: the key, registered from the tour's .env, asked
      // at a host no rule binds it to, by the running session.
      const reg = await gate.registerSecret({ path: envFile, sessionKey: STAGING_SESSION });
      const symbol = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
      if (!symbol) throw new Error(`registering ${envFile} gave no STRIPE_KEY symbol`);
      const d = await gate.desymbolizationDecision({ symbol, boundary: "network", destination: "api.stripe.com", sessionKey: STAGING_SESSION, scheme: "https" });
      if (d.allow !== false || !d.approvalId) throw new Error(`the gate did not ask: ${JSON.stringify(d)}`);
      await tab.go(`${base}/approvals`, `document.querySelector('#approvals-waiting .ask[data-id="${d.approvalId}"] button')`, "approvals");
      await capture(tab, "approval", o.out, tmp);
    }
  } finally {
    await stopAll();
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().then(() => process.exit(0), (e) => { console.error(`tour-screenshots: ${e.stack ?? e}`); process.exit(1); });
}
