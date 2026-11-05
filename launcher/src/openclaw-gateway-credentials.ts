/**
 * openclaw-gateway-credentials — OpenClaw's Gateway token and password under
 * `mandu openclaw`: one stable placeholder in every place an OpenClaw process
 * of a Mandu launch reads them (confidentiality-plan-10 §11.4, "OpenClaw's
 * Gateway credentials: one stable placeholder"; openclaw-plugin.md §9).
 *
 * Mandu-new (no reference origin).
 *
 * WHY. OpenClaw's Gateway and its clients authenticate each other with a
 * shared token (or password): `OPENCLAW_GATEWAY_TOKEN` /
 * `OPENCLAW_GATEWAY_PASSWORD` in the environment, `gateway.auth.token` /
 * `gateway.auth.password` (what the Gateway expects) and
 * `gateway.remote.token` / `gateway.remote.password` (what a client sends)
 * in openclaw.json. The environment mask already replaced the variables with
 * their placeholder (applyEnvSecrets), which is the same in every launch:
 * the arbiter mints an environment secret's symbol once per value, not per
 * session (registry.ts registerEnvSecret, findReusableSymbol with no session
 * key), and keeps it in Mandu's state. But the run config the launcher
 * writes kept the user's literal token. So under `mandu openclaw gateway run`
 * the Gateway expected the real token from its config while a `mandu openclaw
 * agent` client sent the placeholder from its environment (OpenClaw 2026.3.12
 * and 2026.7.1-2 read the variable first): "gateway token mismatch", and the
 * client ran the turn itself. Leaving the variable raw (the first fix,
 * superseded the same week) put the real token in the agent's world.
 *
 * NOW. After the environment mask, the launch registers each literal
 * credential of the run config (the arbiter's environment rule: the
 * variable's name, `*_TOKEN` / `*PASSWORD`, makes it a secret) and writes
 * its placeholder in place. Every OpenClaw process of every Mandu launch on
 * the machine then holds the same placeholder, and the real value is in
 * none of their environments nor configs. The value stays registered: the
 * model proxy masks it wherever it reaches a model, the egress gate holds
 * it. The placeholder is the arbiter's random symbol name: it says nothing
 * about the value.
 *
 * THE COST (accepted, 2026-10-27): a client outside Mandu that sends the
 * real token (a plain `openclaw agent`, a remote app) is refused by a Gateway
 * under Mandu. `mandu openclaw gateway` says so at launch
 * (openclaw-argv.ts openclawGatewayClientNotice).
 *
 * THE COMMAND LINE (pinArgvGatewayCredentials): a `--token` / `--password`
 * (either spelling) would sit in the agent's /proc/<pid>/cmdline; it gets
 * the same placeholder, or the launch is refused.
 *
 * A value given as an environment reference (`${OPENCLAW_GATEWAY_TOKEN}`) or
 * a SecretRef object is left: OpenClaw resolves it from the (masked)
 * environment or its own store. Fail-soft like the environment mask: an
 * arbiter error leaves the file as written and says so.
 */
import { readFileSync, statSync, writeFileSync, renameSync } from "node:fs";

type Json = Record<string, unknown>;

/** The variable each credential kind is registered under (its name is what
 *  makes the arbiter's environment rule call it a secret). */
export const OPENCLAW_GATEWAY_CREDENTIAL_VARS = { token: "OPENCLAW_GATEWAY_TOKEN", password: "OPENCLAW_GATEWAY_PASSWORD" } as const;

/** The config fields that hold a Gateway credential. */
export const OPENCLAW_GATEWAY_CREDENTIAL_FIELDS: ReadonlyArray<{ path: readonly [string, string]; kind: "token" | "password" }> = [
  { path: ["auth", "token"], kind: "token" },
  { path: ["auth", "password"], kind: "password" },
  { path: ["remote", "token"], kind: "token" },
  { path: ["remote", "password"], kind: "password" },
];

function obj(v: unknown): Json | undefined {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Json) : undefined;
}

/** A literal credential (not empty, not a `${VAR}` reference, not already a
 *  Mandu placeholder). */
function literal(v: unknown): v is string {
  return typeof v === "string" && v.trim() !== "" && !/^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(v.trim()) && !v.startsWith("$MDU:");
}

/** The literal Gateway credentials of an OpenClaw config, by field. Pure. */
export function openclawGatewayCredentials(doc: Json): Array<{ field: string; kind: "token" | "password"; value: string }> {
  const gw = obj(doc["gateway"]);
  if (gw === undefined) return [];
  const out: Array<{ field: string; kind: "token" | "password"; value: string }> = [];
  for (const f of OPENCLAW_GATEWAY_CREDENTIAL_FIELDS) {
    const v = obj(gw[f.path[0]])?.[f.path[1]];
    if (literal(v)) out.push({ field: `gateway.${f.path.join(".")}`, kind: f.kind, value: v });
  }
  return out;
}

/** `doc` with each literal Gateway credential replaced by its placeholder
 *  (`placeholders`: value → placeholder), and the fields replaced. A value
 *  with no placeholder is left. Pure: `doc` is not changed. */
export function pinOpenclawGatewayCredentials(doc: Json, placeholders: ReadonlyMap<string, string>): { doc: Json; pinned: string[] } {
  const out = structuredClone(doc);
  const gw = obj(out["gateway"]);
  const pinned: string[] = [];
  if (gw === undefined) return { doc: out, pinned };
  for (const f of OPENCLAW_GATEWAY_CREDENTIAL_FIELDS) {
    const section = obj(gw[f.path[0]]);
    const v = section?.[f.path[1]];
    if (section === undefined || !literal(v)) continue;
    const p = placeholders.get(v);
    if (p === undefined) continue;
    section[f.path[1]] = p;
    pinned.push(`gateway.${f.path.join(".")}`);
  }
  return { doc: out, pinned };
}

/** What registering a credential needs of the arbiter (secret-setup.ts
 *  SecretArbiter's registerEnvSecrets). */
export interface CredentialArbiter {
  registerEnvSecrets?(vars: Array<{ name: string; value: string }>): Promise<{ vars: Array<{ name: string; symbol: string | null; twin?: string; reason: string }> }>;
}

/**
 * Register the run config's literal Gateway credentials and write their
 * placeholders in place (the header). Returns the fields pinned and a status
 * line; never throws.
 */
export async function pinRunConfigGatewayCredentials(
  configPath: string,
  deps: { arbiter: CredentialArbiter; log: (m: string) => void },
): Promise<{ pinned: string[]; status: string }> {
  let doc: Json;
  try {
    doc = JSON.parse(readFileSync(configPath, "utf8")) as Json;
  } catch (e) {
    return { pinned: [], status: `skipped: the run config is not readable JSON (${(e as Error).message})` };
  }
  const creds = openclawGatewayCredentials(doc);
  if (creds.length === 0) return { pinned: [], status: "on: no literal Gateway credential" };
  if (!deps.arbiter.registerEnvSecrets) return { pinned: [], status: "off: arbiter has no registerEnvSecrets op" };
  const values = [...new Map(creds.map((c) => [c.value, c.kind])).entries()];
  let res: Awaited<ReturnType<NonNullable<CredentialArbiter["registerEnvSecrets"]>>>;
  try {
    res = await deps.arbiter.registerEnvSecrets(values.map(([value, kind]) => ({ name: OPENCLAW_GATEWAY_CREDENTIAL_VARS[kind], value })));
  } catch (e) {
    deps.log(`WARNING: mandu: OpenClaw's Gateway credential in its config NOT masked — the arbiter could not register it (${(e as Error).message})`);
    return { pinned: [], status: `error: ${(e as Error).message}` };
  }
  const placeholders = new Map<string, string>();
  res.vars.forEach((v, i) => {
    const value = values[i]?.[0];
    if (value !== undefined && v.symbol !== null && v.twin !== undefined && v.twin !== value) placeholders.set(value, v.twin);
  });
  const { doc: pinnedDoc, pinned } = pinOpenclawGatewayCredentials(doc, placeholders);
  if (pinned.length === 0) return { pinned, status: "on: nothing registered" };
  const mode = statSync(configPath).mode & 0o777;
  const tmp = `${configPath}.mandu-pin`;
  writeFileSync(tmp, JSON.stringify(pinnedDoc, null, 2) + "\n", { mode });
  renameSync(tmp, configPath);
  deps.log(`mandu: OpenClaw's Gateway credential (${pinned.join(", ")}) is its placeholder in the run config, as in the environment: the same in every Mandu launch`);
  return { pinned, status: `on: ${pinned.length} pinned` };
}

/** The flags that carry a Gateway credential on OpenClaw's command line
 *  (`gateway run --token`, `tui --token`, `--password`, …), by kind. */
export const OPENCLAW_GATEWAY_CREDENTIAL_FLAGS: Readonly<Record<string, "token" | "password">> = { "--token": "token", "--password": "password" };

/** A Gateway credential on an OpenClaw command line: where it is, its kind,
 *  its value, and its spelling (`--token <v>` or `--token=<v>`). */
export interface ArgvCredential { index: number; flag: string; kind: "token" | "password"; value: string; form: "split" | "eq" }

/** The literal Gateway credentials of an OpenClaw argv (nothing after a
 *  `--`). Pure. */
export function openclawArgvCredentials(argv: readonly string[]): ArgvCredential[] {
  const out: ArgvCredential[] = [];
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    const eq = a.indexOf("=");
    const flag = eq > 0 ? a.slice(0, eq) : a;
    const kind = OPENCLAW_GATEWAY_CREDENTIAL_FLAGS[flag];
    if (kind === undefined) continue;
    if (eq > 0) {
      const value = a.slice(eq + 1);
      if (literal(value)) out.push({ index: i, flag, kind, value, form: "eq" });
    } else if (i + 1 < argv.length) {
      const value = argv[i + 1]!;
      if (literal(value)) out.push({ index: i + 1, flag, kind, value, form: "split" });
      i++;
    }
  }
  return out;
}

/** `argv` with each credential replaced by its placeholder, in the same
 *  spelling. A value with no placeholder is left. Pure. */
export function pinOpenclawArgvCredentials(argv: readonly string[], placeholders: ReadonlyMap<string, string>): { argv: string[]; pinned: string[] } {
  const out = [...argv];
  const pinned: string[] = [];
  for (const c of openclawArgvCredentials(argv)) {
    const p = placeholders.get(c.value);
    if (p === undefined) continue;
    out[c.index] = c.form === "eq" ? `${c.flag}=${p}` : p;
    pinned.push(c.flag);
  }
  return { argv: out, pinned };
}

/**
 * The launch's OpenClaw argv with its Gateway credentials (`--token`,
 * `--password`, either spelling) replaced by their stable placeholder (the
 * one the environment and the run config carry): on the command line a
 * value sits in /proc/<pid>/cmdline, which the agent's own programs can
 * read. Unlike the config (fail-soft), a value that cannot be registered
 * REFUSES the launch, naming the environment variable and the config key
 * instead. The argv unchanged when it holds no credential.
 */
export async function pinArgvGatewayCredentials(
  argv: readonly string[],
  deps: { arbiter: CredentialArbiter; log: (m: string) => void },
): Promise<string[]> {
  const creds = openclawArgvCredentials(argv);
  if (creds.length === 0) return [...argv];
  const refuse = (why: string): never => {
    throw new Error(
      `mandu: refusing to launch openclaw with its Gateway ${[...new Set(creds.map((c) => c.flag))].join(" and ")} on the command line: ${why}. ` +
      "A value there is readable by the agent's own programs (/proc/<pid>/cmdline). Set OPENCLAW_GATEWAY_TOKEN / OPENCLAW_GATEWAY_PASSWORD " +
      "in the environment or gateway.auth.token / gateway.auth.password in openclaw.json instead: Mandu hands OpenClaw their placeholder.",
    );
  };
  if (!deps.arbiter.registerEnvSecrets) return refuse("the arbiter cannot register it");
  const values = [...new Map(creds.map((c) => [c.value, c.kind])).entries()];
  let res: Awaited<ReturnType<NonNullable<CredentialArbiter["registerEnvSecrets"]>>>;
  try {
    res = await deps.arbiter.registerEnvSecrets(values.map(([value, kind]) => ({ name: OPENCLAW_GATEWAY_CREDENTIAL_VARS[kind], value })));
  } catch (e) {
    return refuse(`the arbiter could not register it (${(e as Error).message})`);
  }
  const placeholders = new Map<string, string>();
  res.vars.forEach((v, i) => {
    const value = values[i]?.[0];
    if (value !== undefined && v.symbol !== null && v.twin !== undefined && v.twin !== value) placeholders.set(value, v.twin);
  });
  const { argv: out, pinned } = pinOpenclawArgvCredentials(argv, placeholders);
  if (pinned.length !== creds.length) return refuse("Mandu could not mint its placeholder");
  deps.log(`mandu: OpenClaw's Gateway ${[...new Set(pinned)].join(" and ")} on the command line is its placeholder, as in the environment and the run config`);
  return out;
}
