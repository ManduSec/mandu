/**
 * stripped-placeholder-egress — a script the agent wrote with a secret's
 * placeholder in double quotes is refused with how to quote it, not left to
 * fail with a 401 (confidentiality.md §7, "A placeholder the agent's shell
 * would expand").
 *
 * The exec gate requotes the commands the agent runs (!1361); a script
 * written to a file is no command any gate sees. Run by a shell, its
 * `curl -H "Authorization: Bearer $MDU:nomodel_Read[…].STRIPE_KEY"` sends
 * `Bearer :nomodel_Read[…].STRIPE_KEY`: neither the key nor the placeholder.
 *
 * Real components, `secrets` axes: an ArbiterServer with two `.env` files
 * (no-model and any-model, bound to the API host), their registration as the
 * launcher makes it, real bash and zsh (where installed: zsh reads
 * `$MDU:a…` as a modifier and leaves `nymodel_…`) running the script, the
 * real curl, the real NetProxy over its production adapter in front of a
 * recording forwarder, and the real dashboard.
 *
 *   (a) the request is refused 403 with the explanation the program prints
 *       (`egress:shell-expanded-placeholder`, single quotes), the bound host
 *       receives nothing, and no Approvals row is filed;
 *   (b) the model's note: the refusal folds into the call as
 *       `shell-expanded` (the `refused:` line both model proxies word);
 *   (c) the session page says why in the product's words;
 *   (d) the control: the same script with the placeholder single-quoted
 *       reaches the bound host with the real key.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy, type HttpForwarder } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM, StoryStep } from "../../dashboard/src/view-model/agent-page.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HAS_CURL = spawnSync("curl", ["--version"], { stdio: "ignore" }).status === 0;
const HAS_ZSH = spawnSync("zsh", ["-c", "exit 0"], { stdio: "ignore" }).status === 0;
const SESSION = "s-stripped-placeholder";
const BOUND = "api.stripe.test";

function run(shell: string, script: string, proxyPort: number): Promise<string> {
  const proxy = `http://127.0.0.1:${proxyPort}`;
  const env = { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: tmpdir(), http_proxy: proxy, HTTP_PROXY: proxy, NO_PROXY: "", no_proxy: "" };
  return new Promise((resolve) => execFile(shell, [script], { env, timeout: 20_000 }, (_e, out, err) => resolve(`${out}${err}`)));
}

const words = (parts: { kind: string; text: string }[]) => parts.map((p) => (p.kind === "code" ? `\`${p.text}\`` : p.text)).join("");

test("a script with a double-quoted placeholder gets an explanatory refusal (bash, zsh); the bound host receives nothing; single-quoted it goes", { skip: !HAS_CURL ? "curl is not installed" : false, timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-stripped-ph-"));
  const proj = join(tmp, "proj"); mkdirSync(proj);
  const envNo = join(proj, ".env");
  const envAny = join(proj, "any.env");
  const KEY = "sk_live_stripped_4e1f9a0b7c";
  const TOKEN = "tok_any_stripped_8d2e6c";
  writeFileSync(envNo, `STRIPE_KEY=${KEY}\n`);
  writeFileSync(envAny, `API_TOKEN=${TOKEN}\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    adminPolicyDir: null, packDir: null,
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
    policyDocument: { version: 1, paths: [{ path: envNo, level: "no-model", bindings: [BOUND] }, { path: envAny, level: "any-model", bindings: [BOUND] }] },
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const client = async (path: string): Promise<ArbiterClient> => { const c = new ArbiterClient(path); await c.connect(); clients.push(c); return c; };
  const guard = await client(humanPath);
  const admin = await client(join(tmp, "admin.sock"));

  const reached: Array<{ url: string; auth: string }> = [];
  const forwarder: HttpForwarder = async (req) => {
    const a = req.headers["authorization"];
    reached.push({ url: req.url, auth: Array.isArray(a) ? a.join(",") : a ?? "" });
    return { status: 200, headers: { "content-type": "application/json" }, body: Buffer.from('{"object":"list"}') };
  };
  const net = new NetProxy({
    arbiter: new ArbiterClientAdapter(await client(socketPath) as unknown as RealArbiterClient, await client(humanPath) as never),
    forwarder, log: () => {}, sessionId: SESSION,
    attributeHolders: () => [{ procKey: "curl-1", ancestors: ["bash-1", "agent-0"] }],
  });
  const netPort = await net.listen(0);
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath }), log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;

  try {
    const regNo = await guard.registerSecret({ path: envNo, sessionKey: SESSION });
    const regAny = await guard.registerSecret({ path: envAny, sessionKey: SESSION });
    const P = /STRIPE_KEY='?(\$MDU:[^'\s]+)/.exec(regNo.twin!)![1]!;
    const A = /API_TOKEN='?(\$MDU:[^'\s]+)/.exec(regAny.twin!)![1]!;
    assert.match(P, /^\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY$/);
    assert.match(A, /^\$MDU:anymodel_Read\[[0-9a-f]+\]\.API_TOKEN$/);
    // The call the script runs under (the model proxy's record and the
    // supervisor's tree), so the refusal can reach the model's note.
    await guard.recordCallCommand({ callId: "call_script", command: "bash ./list.sh", sessionKey: SESSION });
    await guard.recordExecRoot({ procKey: "bash-1", ancestors: ["agent-0"], argv: ["/bin/bash", "-c", "bash ./list.sh"], session: SESSION, callRoot: true });
    await guard.recordExecRoot({ procKey: "curl-1", parentKey: "bash-1", argv: ["/usr/bin/curl", `http://${BOUND}/v1/customers`], session: SESSION });

    const script = (name: string, shell: string, header: string): string => {
      const path = join(proj, name);
      writeFileSync(path, `#!/usr/bin/env ${shell}\ncurl -sS -w ' %{http_code}' -H ${header} http://${BOUND}/v1/customers\n`);
      chmodSync(path, 0o755);
      return path;
    };

    // (a) bash: the double-quoted no-model placeholder
    const out = await run("bash", script("list.sh", "bash", `"Authorization: Bearer ${P}"`), netPort);
    assert.match(out, / 403$/, out);
    assert.ok(out.includes(`which is the placeholder ${P} after a shell expanded`), out);
    assert.ok(out.includes(`Put the placeholder in single quotes ('${P}')`), out);
    assert.ok(out.includes("egress:shell-expanded-placeholder"), out);
    assert.equal(reached.length, 0, "the bound host received nothing");
    assert.ok(!out.includes(KEY));
    assert.deepEqual(await admin.egressApprovals("pending"), [], "nothing to approve: no Approvals row");

    // zsh: the any-model placeholder, which zsh empties to `nymodel_…`
    if (HAS_ZSH) {
      const z = await run("zsh", script("list.zsh", "zsh", `"Authorization: Bearer ${A}"`), netPort);
      assert.match(z, / 403$/, z);
      assert.ok(z.includes(`which is the placeholder ${A} after a shell expanded`), z);
      assert.equal(reached.length, 0, "the bound host received nothing");
      assert.ok(!z.includes(TOKEN));
    }

    // (b) the model's note: the call's refusal, by kind
    let refused: unknown;
    for (let i = 0; i < 50 && !refused; i++) {
      refused = (await guard.callTaint("call_script", { command: "bash ./list.sh", session: SESSION })).refusedEgress;
      if (!refused) await new Promise((r) => setTimeout(r, 20));
    }
    assert.deepEqual((refused as Array<{ kind: string }>)[0], { app: "curl", kind: "shell-expanded" });

    // (c) the session page says why
    let step: Extract<StoryStep, { kind: "action" }> | undefined;
    let page: AgentPageVM | undefined;
    for (let i = 0; i < 100 && !step; i++) {
      const r = await fetch(`${base}/api/home/agent?session=${SESSION}`);
      page = (await r.json()) as AgentPageVM;
      step = page.story.flatMap((t) => t.steps).find((s): s is Extract<StoryStep, { kind: "action" }> => s.kind === "action" && s.outcome === "blocked" && s.why !== undefined);
      if (!step) await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(step, `the refused request is a step of the page: ${JSON.stringify(page?.story)}`);
    assert.match(words(step.why!), /^The program's shell had emptied the secret's placeholder \(it was not in single quotes\)/);
    assert.ok(!JSON.stringify(page).includes(KEY), "no value on the product page");

    // (d) the control: single-quoted, the bound host gets the real key
    const ok = await run("bash", script("list-ok.sh", "bash", `'Authorization: Bearer ${P}'`), netPort);
    assert.match(ok, / 200$/, ok);
    assert.equal(reached.length, 1);
    assert.equal(reached[0]!.auth, `Bearer ${KEY}`);
  } finally {
    await dashboard.close();
    await net.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
