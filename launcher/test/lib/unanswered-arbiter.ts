/**
 * A mock arbiter's connection handler for launcher e2e tests that need an
 * arbiter socket but no arbiter behavior: it answers every NDJSON request with
 * a bare failure, `{id, ok: false}`, with no error text.
 *
 * Every launch-time reader in src/ treats that reply exactly as it treats no
 * reply at all: the axes and tenant `hello` read as unknown, the connect
 * allowances as none, the model endpoints as `unavailable`, and the main-model
 * bind as "it did not answer" (an error TEXT would make the bind `refused`,
 * and `unknown op` would make the model reads `unsupported`, so neither is
 * sent). The difference is time: a mock that never answered made each reader
 * wait out its 3 s deadline, about 22 s per launch, which was most of the
 * launcher's e2e time in CI (docs/design/testing/continuous-integration.md §5.1).
 *
 * `onLine`, when given, sees each raw request line (a recording mock).
 * `unavailableReply` is the same answer for one line, for a mock that builds
 * its own connection handler.
 */
import type { Socket } from "node:net";

export function unavailableReply(line: string): string {
  let id: unknown = null;
  try { id = (JSON.parse(line) as { id?: unknown }).id ?? null; } catch { /* not JSON: answered all the same */ }
  return JSON.stringify({ id, ok: false });
}

export function answerUnavailable(onLine?: (line: string) => void): (s: Socket) => void {
  return (s) => {
    let buf = "";
    s.setEncoding("utf8");
    // The launcher's readers destroy their socket as soon as they have a line.
    s.on("error", () => {});
    s.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        onLine?.(line);
        let id: unknown = null;
        try { id = (JSON.parse(line) as { id?: unknown }).id ?? null; } catch { /* not JSON: answered all the same */ }
        if (!s.destroyed) s.write(JSON.stringify({ id, ok: false }) + "\n");
      }
    });
  };
}
