/**
 * human-plane — the integration rigs' one spelling of the arbiter's HUMAN-PLANE
 * socket (docs/design/architecture/arbiter-human-plane.md). Mandu-new test helper, no
 * reference origin.
 *
 * The arbiter serves the ops that return originals (desymbolize, shallow
 * resolve, events, sessions, subscribe, verifyEvents) only on the human socket;
 * the data socket every agent-world process can reach refuses them. A rig that
 * boots an in-process `ArbiterServer` passes `humanSocketPath: humanSockIn(dir)`
 * and reads through a client on that path — exactly what the human-facing
 * consumers (the dashboard, fs-sync, the reply filter, the net-proxy) do in
 * production. The directory is created 0700 by the server (and verified).
 * A rig that joins a RUNNING arbiter (the live suites' shared one) discovers
 * its human socket from `hello` with {@link humanSockOf}.
 */

import { join } from "node:path";

import { ArbiterClient } from "../../arbiter/ipc/client.js";

/** The human-plane socket path inside a rig's temp dir: `<dir>/human/h.sock`. */
export function humanSockIn(dir: string): string {
  return join(dir, "human", "h.sock");
}

/** The human-plane socket of the arbiter answering at `dataSock`, from its
 *  `hello` ($MANDU_ARBITER_HUMAN_SOCK wins when set). Throws when the arbiter
 *  names none — a rig never falls back to the data socket for originals. */
export async function humanSockOf(dataSock: string): Promise<string> {
  const explicit = process.env["MANDU_ARBITER_HUMAN_SOCK"];
  if (explicit) return explicit;
  const probe = new ArbiterClient(dataSock);
  try {
    const named = (await probe.hello()).humanSock;
    if (typeof named !== "string" || named === "") {
      throw new Error(`the arbiter at ${dataSock} names no human-plane socket (an arbiter older than arbiter-human-plane.md?)`);
    }
    return named;
  } finally {
    probe.close();
  }
}
