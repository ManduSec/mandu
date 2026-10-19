/**
 * live-stack — repo paths + the shared live-eval stack (arbiter daemon + the
 * target's ingress proxy) for the LIVE eval backend.
 *
 * Extracted verbatim from run-live.ts (agent-legibility split, behavior-
 * preserving). The launcher AUTOSTARTS the arbiter + net-proxy, but NOT the
 * model/openai proxy — so we boot the arbiter + the right model proxy ourselves
 * (pointed at the fake/real upstream) and tell the launcher to REUSE them via
 * env (MANDU_ARBITER_SOCK + MANDU_{PROXY,OPENAI_PROXY}_PORT +
 * MANDU_NO_ARBITER_AUTOSTART=1).
 */

import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync } from "node:fs";
import { connect } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { waitForSocket, waitForPort, waitForPortFile, sleep } from "./proc-wait.js";

// ─────────────────────────────────────────────────────────────────────────────
// Repo layout (this file lives at eval/lib/, the repo root is two levels up).
// ─────────────────────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
export const LAUNCHER = join(REPO_ROOT, "launcher", "mandu-run.sh");
const ARBITER_DIR = join(REPO_ROOT, "arbiter");
const ARBITER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");
export const ARBITER_TSX = join(ARBITER_DIR, "node_modules", ".bin", "tsx");
const MODEL_PROXY_DIR = join(REPO_ROOT, "interceptors", "anthropic-proxy");
const MODEL_PROXY_MAIN = join(MODEL_PROXY_DIR, "src", "server-main.ts");
export const MODEL_PROXY_TSX = join(MODEL_PROXY_DIR, "node_modules", ".bin", "tsx");
const OPENAI_PROXY_DIR = join(REPO_ROOT, "interceptors", "openai-proxy");
const OPENAI_PROXY_MAIN = join(OPENAI_PROXY_DIR, "src", "server-main.ts");
export const OPENAI_PROXY_TSX = join(OPENAI_PROXY_DIR, "node_modules", ".bin", "tsx");
export const EGRESS_DIR = join(REPO_ROOT, "interceptors", "net-proxy");

export type Target = "claude" | "codex";
export type LiveMode = "fake" | "real-api";
export type Defense = "full" | "none";

// ─────────────────────────────────────────────────────────────────────────────
// A tiny arbiter IPC helper (NDJSON over the unix socket) — we only need
// `symbolize` to pre-register the untrusted symbol (the fake-mode exfil payload).
// Mirrors the inline node client in launcher/test/net-proxy-live.test.sh.
// ─────────────────────────────────────────────────────────────────────────────

export function arbiterSymbolize(
  socketPath: string,
  value: string,
  origin: string,
  timeoutMs = 5000,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const c = connect(socketPath);
    let buf = "";
    const timer = setTimeout(() => {
      c.destroy();
      reject(new Error("arbiter symbolize timed out"));
    }, timeoutMs);
    c.setEncoding("utf8");
    c.on("connect", () => {
      c.write(JSON.stringify({ id: 1, op: "symbolize", tool: "web_fetch", value, origin }) + "\n");
    });
    c.on("data", (d: string) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      clearTimeout(timer);
      c.end();
      try {
        const resp = JSON.parse(buf.slice(0, nl)) as { ok?: boolean; result?: { symbol?: string }; error?: string };
        if (resp.ok && resp.result?.symbol) return resolve(resp.result.symbol);
        reject(new Error(`symbolize failed: ${resp.error ?? buf}`));
      } catch (err) {
        reject(err as Error);
      }
    });
    c.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// The shared stack: a arbiter daemon + the target's ingress proxy.
// ─────────────────────────────────────────────────────────────────────────────

export interface LiveStack {
  socketPath: string;
  arbiterSock: string;
  proxyHost: string;
  proxyPort: number;
  dispose(): Promise<void>;
}

export interface BootOptions {
  tmp: string;
  target: Target;
  /** The upstream origin the proxy forwards to (the fake in fake mode, the real
   *  endpoint in real-api mode). */
  upstreamOrigin: string;
  /** Fake mode → the proxy must accept the fake's self-signed cert. */
  fakeUpstream: boolean;
}

export async function bootStack(opts: BootOptions): Promise<LiveStack> {
  const { tmp, target, upstreamOrigin } = opts;
  const arbiterSock = join(tmp, "arbiter.sock");
  // A throwaway Mandu home: the arbiter's symbol DB and events live in it.
  const manduHome = join(tmp, "mandu-home");
  mkdirSync(manduHome, { recursive: true });

  const children: ChildProcess[] = [];

  // 1. arbiter daemon (setsid → own process group so we can group-kill the tree).
  const arbiter = spawn(ARBITER_TSX, [ARBITER_MAIN, arbiterSock], {
    // MANDU_RUNTIME_DIR: pinned arbiters register a registry-only instance
    // dir — keep it inside this stack's tmp tree (killAll SIGKILLs the tree,
    // so a real-base registration would linger until the next sweep/reap).
    env: {
      ...process.env, MANDU_ARBITER_SOCK: arbiterSock, MANDU_HOME: manduHome,
      MANDU_RUNTIME_DIR: join(tmp, "mandu-runtime"),
      // The red-team corpus attacks the INTEGRITY axis (the paper's defense):
      // stated, never the built-in default (protection-modes.md §4).
      MANDU_INTEGRITY: "1", MANDU_CONFIDENTIALITY: "0",
    },
    stdio: ["ignore", "ignore", "ignore"],
    detached: true,
  });
  children.push(arbiter);
  if (!(await waitForSocket(arbiterSock))) {
    await killAll(children);
    throw new Error("arbiter daemon failed to start (no socket)");
  }

  // 2. the target's ingress proxy, pointed at the (fake/real) upstream.
  const proxyHost = "127.0.0.1";
  // Port 0 + the port file: the kernel picks, the proxy reports what it bound.
  const proxyPortFile = join(tmp, "proxy.port");
  const proxyTsx = target === "claude" ? MODEL_PROXY_TSX : OPENAI_PROXY_TSX;
  const proxyMain = target === "claude" ? MODEL_PROXY_MAIN : OPENAI_PROXY_MAIN;
  const proxyPortEnv = target === "claude" ? "MANDU_PROXY_PORT" : "MANDU_OPENAI_PROXY_PORT";
  const proxy = spawn(proxyTsx, [proxyMain], {
    env: {
      ...process.env,
      MANDU_ARBITER_SOCK: arbiterSock,
      MANDU_HOME: manduHome,
      MANDU_UPSTREAM: upstreamOrigin,
      [proxyPortEnv]: "0",
      MANDU_PROXY_PORT: "0", // both server-mains read MANDU_PROXY_PORT/OPENAI_…; set the generic one too
      MANDU_PORT_FILE: proxyPortFile,
      // The stock server-main forwards over HTTPS only; in fake mode the upstream
      // is our self-signed HTTPS fake, so the proxy must accept it.
      ...(opts.fakeUpstream ? { NODE_TLS_REJECT_UNAUTHORIZED: "0" } : {}),
    },
    stdio: ["ignore", "ignore", "ignore"],
    detached: true,
  });
  children.push(proxy);
  const proxyPort = await waitForPortFile(proxyPortFile);
  if (proxyPort === null || !(await waitForPort(proxyHost, proxyPort))) {
    await killAll(children);
    throw new Error(`${target} ingress proxy failed to start on ${proxyHost} (port file ${proxyPortFile}: ${proxyPort ?? "never written"})`);
  }

  return {
    socketPath: arbiterSock,
    arbiterSock,
    proxyHost,
    proxyPort,
    dispose: async () => {
      await killAll(children);
    },
  };
}

async function killAll(children: ChildProcess[]): Promise<void> {
  for (const c of children) {
    if (c.pid === undefined) continue;
    try {
      // group-kill (the proxy/arbiter spawn tsx→node trees).
      process.kill(-c.pid, "SIGKILL");
    } catch {
      try {
        c.kill("SIGKILL");
      } catch {
        /* already gone */
      }
    }
  }
  await sleep(100);
}
