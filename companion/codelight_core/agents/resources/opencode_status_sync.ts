import type {
  CodelightSnapshot,
  CodelightSnapshotSession,
  CodelightSnapshotSink,
} from "./codelight_hook.ts";

export type OpenCodeStatusClient = {
  readonly session: {
    readonly status: (options?: {
      readonly directory?: string;
    }) => Promise<{
      readonly data?: unknown;
      readonly error?: unknown;
    }>;
  };
};

type ScheduledHeartbeat = {
  cancel(): void;
  unref(): void;
};

export type HeartbeatScheduler = (
  task: () => void,
  intervalMs: number,
) => ScheduledHeartbeat;

export type OpenCodeStatusSyncOptions = {
  readonly heartbeatMs?: number;
  readonly keepaliveMs?: number;
  readonly now?: () => number;
  readonly schedule?: HeartbeatScheduler;
};

const HEARTBEAT_ENV = "CODELIGHT_OPENCODE_HEARTBEAT_MS";
const KEEPALIVE_ENV = "CODELIGHT_OPENCODE_SNAPSHOT_KEEPALIVE_MS";
const DEFAULT_HEARTBEAT_MS = 15_000;
const DEFAULT_KEEPALIVE_MS = 300_000;

type OpenCodeStatusSync = {
  dispose(): void;
  noteEvent(): void;
};

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function defaultHeartbeatScheduler(
  task: () => void,
  intervalMs: number,
): ScheduledHeartbeat {
  const timer = setInterval(task, intervalMs);
  return {
    cancel: () => clearInterval(timer),
    unref: () => {
      if (typeof timer !== "object" || timer === null || !("unref" in timer)) {
        return;
      }
      const unref = timer.unref;
      if (typeof unref === "function") unref.call(timer);
    },
  };
}

function intervalFromEnv(name: string, fallback: number): number {
  const value = Number(process.env[name]);
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

function leaseFree(snapshot: CodelightSnapshot): boolean {
  return snapshot.complete &&
    snapshot.sessions.every(({ state }) => state === "idle");
}

function snapshotKey(snapshot: CodelightSnapshot): string {
  const sessions = [...snapshot.sessions]
    .sort((left, right) => (left.sessionId < right.sessionId ? -1 : 1))
    .map(({ sessionId, state }) => [sessionId, state]);
  return JSON.stringify([snapshot.cwd, snapshot.complete, sessions]);
}

function reportForStatus(
  sessionId: string,
  status: unknown,
): CodelightSnapshotSession | null {
  if (!sessionId || !isRecord(status)) return null;
  const statusType = status["type"];
  if (statusType !== "busy" && statusType !== "retry" && statusType !== "idle") {
    return null;
  }
  return {
    sessionId,
    state: statusType === "idle" ? "idle" : "working",
  };
}

function snapshotForStatus(
  data: unknown,
  cwd: string,
): CodelightSnapshot | null {
  if (!isRecord(data)) return null;
  const sessions: CodelightSnapshotSession[] = [];
  for (const [sessionId, status] of Object.entries(data)) {
    const report = reportForStatus(sessionId, status);
    if (report === null) return null;
    sessions.push(report);
  }
  return {
    agentId: "opencode",
    complete: true,
    sessions,
    eventName: "session.status.snapshot",
    cwd,
  };
}

export function createOpenCodeStatusSync(
  client: OpenCodeStatusClient,
  cwd: string,
  sink: CodelightSnapshotSink,
  options: OpenCodeStatusSyncOptions,
): OpenCodeStatusSync {
  let disposed = false;
  let polling = false;
  let resyncPending = false;
  let revision = 0;
  let attempts = 0;
  let delivered: { readonly key: string; readonly at: number } | null = null;
  const now = options.now ?? (() => performance.now());
  const keepaliveMs = options.keepaliveMs ??
    intervalFromEnv(KEEPALIVE_ENV, DEFAULT_KEEPALIVE_MS);
  // Each delivery starts a Python reporter, so an unchanged snapshot is skipped
  // only when the daemon cannot need it again: it was acknowledged, no provider
  // event has advanced the scope since, and it is complete and all idle. Such
  // snapshots carry no lease; any working or waiting session expires after 45 s
  // and must be refreshed every heartbeat. The keepalive bounds how long an
  // agent-wide taint written by another host can wait for this generation's
  // newer complete snapshot.
  const emit = (snapshot: CodelightSnapshot): void => {
    const key = leaseFree(snapshot) ? snapshotKey(snapshot) : null;
    const emittedAt = now();
    if (
      key !== null && delivered !== null && delivered.key === key &&
      emittedAt - delivered.at < keepaliveMs
    ) {
      return;
    }
    delivered = null;
    attempts += 1;
    const attempt = attempts;
    const emittedRevision = revision;
    try {
      sink(snapshot, (ok) => {
        if (
          ok && key !== null && attempt === attempts &&
          emittedRevision === revision
        ) {
          delivered = { key, at: emittedAt };
        }
      });
    } catch { // no-excuse-ok: catch - monitoring cannot break the host agent.
    }
  };
  const synchronize = async (): Promise<void> => {
    if (disposed) return;
    if (polling) {
      resyncPending = true;
      return;
    }
    polling = true;
    const startingRevision = revision;
    try {
      const response = await client.session.status(
        cwd ? { directory: cwd } : undefined,
      );
      if (disposed || startingRevision !== revision) return;
      const snapshot = response.error === undefined
        ? snapshotForStatus(response.data, cwd)
        : null;
      if (snapshot === null) {
        emit({
          agentId: "opencode",
          complete: false,
          sessions: [],
          eventName: "session.status.snapshot.failed",
          cwd,
        });
        return;
      }
      emit(snapshot);
    } catch {
      if (!disposed && startingRevision === revision) {
        emit({
          agentId: "opencode",
          complete: false,
          sessions: [],
          eventName: "session.status.snapshot.failed",
          cwd,
        });
      }
    } finally {
      polling = false;
      if (!disposed && (resyncPending || startingRevision !== revision)) {
        resyncPending = false;
        void synchronize();
      }
    }
  };
  const heartbeat = (options.schedule ?? defaultHeartbeatScheduler)(
    () => void synchronize(),
    options.heartbeatMs ?? intervalFromEnv(HEARTBEAT_ENV, DEFAULT_HEARTBEAT_MS),
  );
  heartbeat.unref();
  void synchronize();
  return {
    dispose: () => {
      disposed = true;
      heartbeat.cancel();
    },
    noteEvent: () => {
      revision += 1;
      delivered = null;
      if (polling) resyncPending = true;
    },
  };
}
