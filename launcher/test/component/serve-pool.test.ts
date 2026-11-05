/**
 * serve-pool (component) — `mandu serve`'s proxy pool over the REAL service
 * stack: a fake systemd (test/lib/fake-systemd.ts) runs the unit `mandu serve
 * install` rendered (the dashboard as the arbiter's supervisor, MANDU_SERVE=1)
 * on the test's own runtime dir, HOME and Mandu home; never the host's user
 * manager, ~/.mandu or ~/.openclaw (docs/design/agents/openclaw-plugin.md
 * §3.2). Axes: `secrets` (the service's default mode; the pool's sessions are
 * gated attachments whatever the mode).
 *
 * The story:
 *   1. `mandu serve install` starts the service; `mandu serve attach
 *      openclaw` declares `openclaw:main` and waits for the pool's proxy;
 *   2. the service registered the secret file under HOME with no launch ever
 *      run (the count in `status`), then the attachment, then the proxy;
 *   3. the port file is a 0600 file in a 0700 directory, and the proxy on
 *      that port names the session and the service's arbiter; a model call
 *      through it goes to the upstream the unit's environment names
 *      (`MANDU_UPSTREAM`, carried at install; never the supervisor's default
 *      api.anthropic.com), carrying the secret only as its placeholder;
 *   4. the arbiter holds a live attachment: the human plane exposed by it, its
 *      posture record `gated` / `openclaw-plugin`, believed;
 *   5. what a confined launch beside it would print (the human-plane watch)
 *      says a plugin session is running and how to avoid it; `mandu serve
 *      status` lists the attachment with its port, health, registration,
 *      secrets and posture, and the same warning;
 *   6. a killed proxy loses its port file at once and comes back on its port;
 *   7. `detach` ends the attachment (the plane walled again); `attach` again,
 *      then `mandu serve stop` ends it too, the port file and folder gone.
 */
import { test } from "node:test";
import "../lib/private-home.js";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stateAxes } from "../axes.js";
import { sweepRuntimeProcesses } from "../lib/runtime-sweep.js";
import { FakeSystemd } from "../lib/fake-systemd.js";
import { realServeDeps, runServe, SERVE_EXIT, type ServeDeps } from "../../src/serve-command.js";
import { SERVE_UNIT } from "../../src/serve-unit.js";
import { Layout } from "../../src/services/layout.js";
import { anthropicProxyPortFile, attachmentDir, parsePortFile } from "../../src/attachment-contract.js";
import { humanPlaneStatusOf } from "../../src/serve-attachments.js";
import { exposureLostLines, parseHumanPlaneStatus } from "../../src/human-plane-watch.js";
import { ndjsonCall } from "../../src/secret-setup.js";
import { probeIdentity } from "../../src/services/primitives.js";

stateAxes("secrets");

const SESSION = "openclaw:main";

function alive(pid: number): boolean {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    return !/^[ZX]/.test(stat.slice(stat.lastIndexOf(")") + 2));
  } catch {
    return false;
  }
}

async function until(pred: () => boolean | Promise<boolean>, ms = 60_000): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await pred()) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return pred();
}

function dashboardPidsOf(base: string): number[] {
  const dir = join(base, "dashboards");
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((n) => n.endsWith(".json")).flatMap((f) => {
    try { const m = JSON.parse(readFileSync(join(dir, f), "utf8")) as { pid?: unknown }; return typeof m.pid === "number" ? [m.pid] : []; } catch { return []; }
  });
}

test("mandu serve: the pool registers the secrets, the attachment and the proxy of a declared session; status and the watch warn; a killed proxy loses its port file; stop ends it", {
  timeout: 600_000, skip: process.platform !== "linux" ? "Linux only (/proc, systemd)" : false,
}, async () => {
  const tmp = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "mdu-sp-")));
  const base = join(tmp, "mandu");
  const manduHome = join(tmp, "mandu-home");
  const home = join(tmp, "home");
  const xdg = join(tmp, "xdg");
  mkdirSync(xdg, { mode: 0o700 });
  // A secret file a launch would register; no launch ever runs here.
  mkdirSync(join(home, ".aws"), { recursive: true });
  const canary = `MDUSERVE${process.pid}x7q2`;
  writeFileSync(join(home, ".aws", "credentials"), `[default]\naws_access_key_id = AKIA${process.pid}EXAMPLE\naws_secret_access_key = ${canary}abcdefghijklmnopqrstu\n`, { mode: 0o600 });
  // The model upstream the unit names: every request the pool proxy forwards.
  const upstreamHits: Array<{ url: string; body: string }> = [];
  const upstream = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      upstreamHits.push({ url: req.url ?? "", body });
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ id: "msg_1", type: "message", role: "assistant", model: "claude-haiku-4-5", content: [{ type: "text", text: "ok" }], stop_reason: "end_turn", usage: { input_tokens: 1, output_tokens: 1 } }));
    });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  const upstreamUrl = `http://127.0.0.1:${(upstream.address() as { port: number }).port}`;
  const unitPath = join(tmp, "config", "systemd", "user", SERVE_UNIT);
  const saved = { MANDU_HOME: process.env["MANDU_HOME"], MANDU_ARBITER_SOCK: process.env["MANDU_ARBITER_SOCK"] };
  process.env["MANDU_HOME"] = manduHome;
  delete process.env["MANDU_ARBITER_SOCK"];
  const unitLog = join(tmp, "unit.log");
  const fake = new FakeSystemd(unitPath, { HOME: home, XDG_RUNTIME_DIR: xdg, USER: process.env["USER"] ?? "u" }, unitLog);
  const serveEnv = {
    HOME: home, PATH: process.env["PATH"], TMPDIR: tmp,
    XDG_CONFIG_HOME: join(tmp, "config"),
    MANDU_RUNTIME_DIR: base, MANDU_HOME: manduHome,
    DASHBOARD_PORT: "0",
    MANDU_UPSTREAM: upstreamUrl,
  };
  const layout = Layout.detect(new URL("../../src/run.ts", import.meta.url).href, {});
  let out = "";
  let err = "";
  const deps: ServeDeps = {
    ...realServeDeps(layout, serveEnv),
    systemctl: fake.run,
    unitOfPid: (pid) => (fake.inUnit(pid) ? SERVE_UNIT : null),
    otherService: () => null,
    linger: () => true,
    attachWaitMs: 180_000,
    out: (s) => { out += s; },
    err: (s) => { err += s; },
  };
  const serve = async (...args: string[]): Promise<number> => {
    out = ""; err = "";
    return runServe(args, serveEnv, deps);
  };
  const log = (): string => (existsSync(unitLog) ? readFileSync(unitLog, "utf8").slice(-4000) : "");
  const portFile = anthropicProxyPortFile(base, SESSION);
  try {
    // 1. The service, then the declaration; attach waits for the proxy.
    assert.equal(await serve("install"), SERVE_EXIT.ok, `install: ${out}${err}\n${log()}`);
    assert.equal(await serve("attach", "openclaw"), SERVE_EXIT.ok, `attach: ${out}${err}\nunit log:\n${log()}`);
    assert.match(out, /attached openclaw:main \(OpenClaw agent main, port \d+\)/);
    assert.match(out, /a plugin session is running .*lost their guard's attestation/);
    assert.match(out, /serving at http:\/\/127\.0\.0\.1:\d+; next: mandu openclaw install/);

    // 3. The contract: 0600 in 0700; the identity names the session and this arbiter.
    assert.equal(statSync(portFile).mode & 0o777, 0o600);
    assert.equal(statSync(attachmentDir(base, SESSION)).mode & 0o777, 0o700);
    const port = parsePortFile(readFileSync(portFile, "utf8"))!;
    const declared = JSON.parse(readFileSync(join(manduHome, "state", "serve-attachments.json"), "utf8")) as { attachments: Array<{ port: number }> };
    assert.equal(port, declared.attachments[0]!.port, "on its declared port");
    const id = await probeIdentity("127.0.0.1", port);
    assert.equal(id?.service, "anthropic-proxy");
    assert.equal(id?.sessionKey, SESSION);
    assert.equal(id?.arbiterSock, join(base, "current", "arbiter.sock"));

    // The model upstream follows the unit's environment, not the supervisor's default.
    assert.match(readFileSync(unitPath, "utf8"), new RegExp(`^Environment="MANDU_UPSTREAM=${upstreamUrl.replace(/[.]/g, "\\.")}"$`, "m"), "install carried MANDU_UPSTREAM");
    const reply = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-api-key": "sk-ant-test", "x-mandu-session-id": SESSION } }, (r) => {
        let b = "";
        r.setEncoding("utf8");
        r.on("data", (c) => (b += c));
        r.on("end", () => resolve({ status: r.statusCode ?? 0, body: b }));
      });
      req.on("error", reject);
      req.end(JSON.stringify({
        model: "claude-haiku-4-5", max_tokens: 64,
        messages: [
          { role: "user", content: "what is in it?" },
          { role: "assistant", content: [{ type: "tool_use", id: "toolu_1", name: "exec", input: { command: "printenv BLOB" } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_1", content: readFileSync(join(home, ".aws", "credentials"), "utf8") }] },
        ],
      }));
    });
    assert.equal(reply.status, 200, reply.body.slice(0, 400));
    const sent = upstreamHits.filter((h) => h.url.includes("/v1/messages"));
    assert.equal(sent.length, 1, "the pool proxy sent the call to the unit's MANDU_UPSTREAM");
    assert.ok(!sent[0]!.body.includes(canary), "CONFIDENTIALITY VIOLATION: the secret the service registered reached the model");
    assert.match(sent[0]!.body, /\$MDU:nomodel_/, "it reached it as its placeholder");

    // 2. The secrets were registered by the service (the pool's record).
    const rec = JSON.parse(readFileSync(join(attachmentDir(base, SESSION), "pool.json"), "utf8")) as { proxyPid: number; secrets: { registered: number } };
    assert.ok(rec.secrets.registered >= 1, `the service registered the secret file: ${JSON.stringify(rec)}`);

    // 4. The arbiter holds it: exposed by the attachment; its posture record believed.
    const status = parseHumanPlaneStatus(await humanPlaneStatusOf(serveEnv))!;
    assert.equal(status.exposed, true);
    assert.deepEqual(status.launches.map((l) => [l.session, l.attachment, l.posture]), [[SESSION, "openclaw-plugin", "gated"]]);
    const hello = await ndjsonCall<{ humanSock: string }>(join(base, "current", "arbiter.sock"), "hello", {}, 3_000);
    const events = await ndjsonCall<{ events: Array<{ kind: string; emitter?: string; claimed?: boolean; data?: unknown; secrets?: unknown }> }>(hello.humanSock, "events", { sessionId: SESSION, sinceSeq: 0 }, 5_000);
    const posture = events.events.find((e) => e.kind === "launch_posture" && e.emitter === "arbiter");
    assert.ok(posture, `the arbiter recorded the posture: ${JSON.stringify(events.events.map((e) => e.kind))}`);
    assert.match(JSON.stringify(posture), /"posture":"gated".*"gap":"openclaw-plugin"|"gap":"openclaw-plugin".*"posture":"gated"/);
    assert.notEqual(posture!.claimed, true, "believed: registered on the walled human plane");

    // 5. A confined launch's watch line, and status.
    const lost = exposureLostLines(status.launches);
    assert.match(lost[0]!, /this session's file guard is not believed: a plugin session is running/);
    assert.match(lost.at(-1)!, /mandu openclaw gateway.*mandu serve stop/);
    assert.equal(await serve("status"), SERVE_EXIT.ok, `${out}${err}`);
    assert.match(out, new RegExp(`attached: +openclaw:main: proxy on 127\\.0\\.0\\.1:${port}, answering, registered, \\d+ secret files? registered, the OpenClaw config does not route through it yet \\(mandu openclaw install\\), posture gated \\(gap openclaw-plugin\\)`));
    assert.match(out, /posture: +gated, gap openclaw-plugin: The AI sees your secrets masked/);
    assert.match(out, /warning: +a plugin session is running .*lost their guard's attestation/);
    assert.match(out, /warning: +to avoid it: run the Gateway under Mandu instead \(mandu openclaw gateway\)/);
    assert.equal(await serve("status", "--json"), SERVE_EXIT.ok);
    const js = JSON.parse(out) as { attachments: Array<{ session: string; healthy: boolean; registered: boolean; gap: string }> };
    assert.deepEqual(js.attachments.map((a) => [a.session, a.healthy, a.registered, a.gap]), [[SESSION, true, true, "openclaw-plugin"]]);

    // 6. A killed proxy: the port file goes at once, then the proxy is back on its port.
    process.kill(rec.proxyPid, "SIGKILL");
    assert.ok(await until(() => !existsSync(portFile), 5_000), "the port file went with the proxy");
    assert.ok(await until(() => existsSync(portFile), 120_000), `the proxy came back\n${log()}`);
    assert.equal(parsePortFile(readFileSync(portFile, "utf8")), port, "on the same port");
    assert.ok(!alive(rec.proxyPid));

    // 7. detach ends the attachment; attach again; stop ends it too.
    assert.equal(await serve("detach", "openclaw"), 0, err);
    assert.ok(await until(async () => parseHumanPlaneStatus(await humanPlaneStatusOf(serveEnv))?.exposed === false, 30_000), "walled again once detached");
    assert.ok(!existsSync(attachmentDir(base, SESSION)));
    assert.equal(await serve("attach", "openclaw"), SERVE_EXIT.ok, `${out}${err}\n${log()}`);
    assert.equal(await serve("stop"), SERVE_EXIT.ok, err);
    assert.ok(!existsSync(portFile) && !existsSync(attachmentDir(base, SESSION)), "stop removes the port file and its folder");
    assert.match(log(), /attachment openclaw:main: ended/, "the pool ended the attachment while the arbiter still answered");
  } finally {
    upstream.close();
    fake.stopAll();
    for (const pid of dashboardPidsOf(base)) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
    await sweepRuntimeProcesses(base);
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    rmSync(tmp, { recursive: true, force: true });
  }
});
