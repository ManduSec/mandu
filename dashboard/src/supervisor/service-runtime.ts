/**
 * service-runtime — the Supervisor's internal per-service runtime record
 * (moved out of supervisor.ts, agent-legibility split; no logic change): its
 * shape, the fresh "stopped" record the constructor builds per service, and
 * the admin-channel teardown every exit path runs.
 *
 * Mandu-new (NO reference origin). Internal to src/supervisor/ — not part of
 * supervisor.ts's public API.
 */

import { type ChildProcess } from "node:child_process";
import { type Socket } from "node:net";
import { type WriteStream } from "node:fs";

import type { ArbiterIdentity, LogLine, ServiceDefinition, ServiceState } from "./supervisor-defs.js";
import type { SocketOwner } from "./socket-owner.js";

export interface ServiceRuntime {
  def: ServiceDefinition;
  state: ServiceState;
  child: ChildProcess | null;
  pid: number | null;
  since: number | null;
  lastError: string | null;
  /** True between a deliberate stop() request and the child's exit; lets the
   * exit handler distinguish an expected stop from a crash. */
  stopping: boolean;
  /** True when this service was ADOPTED (already running on its endpoint when
   * start() ran) rather than spawned by us. We never reap what we didn't start,
   * so stop()/shutdownAll() leave an adopted instance alone (it has no pid). */
  adopted: boolean;
  ring: LogLine[];
  subscribers: Set<(l: LogLine) => void>;
  /** stdout/stderr line-split carry-over (incomplete trailing fragment). */
  carry: { stdout: string; stderr: string };
  /** hello identity of the listening daemon (arbiter only; null = not fetched
   *  or the daemon predates the hello op). */
  identity: ArbiterIdentity | null;
  /** Socket-owner discovery result for an adopted identity-less daemon (the
   *  /proc-verified listener pid — socket-owner.ts); null until found. Cleared
   *  whenever identity is known, or the service stops/spawns/replaces. */
  owner: SocketOwner | null;
  /** Throttle + reentrancy guard for refreshAdoptedIdentity (epoch ms of the
   *  last attempt; 0 = never tried, so the first status() poll retries at once). */
  identRefreshAt: number;
  identRefreshing: boolean;
  /** Set while we spawn our own arbiter to DISPLACE a foreign one still
   *  answering at `current` (foreignArbiterReason): the pid our readiness probe
   *  must not mistake for our own instance. Null otherwise. */
  displacePid: number | null;
  /** Durable per-module log file stream (best-effort; null when closed/unopened
   *  or if opening failed — the supervisor never breaks on a log-file error). */
  logStream: WriteStream | null;
  /** The last stream's close, after the child exited and the stream was
   *  ended: its queued lines still land in the file until then (the
   *  "full log" waits for them, logFileWritten). Null when none is pending. */
  logClosing: Promise<void> | null;
  /** The parent end of the ADMIN CHANNEL socketpair (ServiceDefinition.
   *  adminChannel): live only while a child WE spawned is running. Adopted
   *  instances have none — nobody but the process that spawned an arbiter can
   *  hold its admin channel, which is the whole point (policy-surface-
   *  redesign.md §2.6). Destroyed + nulled on every exit path. */
  adminSocket: Socket | null;
  /** The port a `port-file` service reported when it became ready (shown as
   *  its endpoint while running); null otherwise. */
  boundPort: number | null;
}

// Augment the runtime record with the optional in-flight start promise. Kept off
// the declared interface above to keep that shape minimal; attached lazily.
export interface ServiceRuntime {
  startPromise?: Promise<void>;
}

/** A fresh record for a service that has never run: stopped, empty ring, no
 *  child, no identity, no admin channel. */
export function createServiceRuntime(def: ServiceDefinition): ServiceRuntime {
  return {
    def,
    state: "stopped",
    child: null,
    pid: null,
    since: null,
    lastError: null,
    stopping: false,
    adopted: false,
    ring: [],
    subscribers: new Set(),
    carry: { stdout: "", stderr: "" },
    identity: null,
    owner: null,
    identRefreshAt: 0,
    identRefreshing: false,
    displacePid: null,
    logStream: null,
    logClosing: null,
    adminSocket: null,
    boundPort: null,
  };
}

/** Tear down a service's admin channel (idempotent). */
export function dropAdminChannel(svc: ServiceRuntime): void {
  if (svc.adminSocket) {
    try { svc.adminSocket.destroy(); } catch { /* already gone */ }
    svc.adminSocket = null;
  }
}
