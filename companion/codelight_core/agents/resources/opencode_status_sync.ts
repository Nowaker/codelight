import type {
  CodelightSnapshot,
  CodelightSnapshotSession,
  CodelightSnapshotSink,
} from "./codelight_hook.ts";

export type OpenCodeStatusClient = {
  readonly session: {
    readonly status: (options?: {
      readonly query?: { readonly directory?: string };
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
  readonly schedule?: HeartbeatScheduler;
};

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
  const emit = (snapshot: CodelightSnapshot): void => {
    try {
      sink(snapshot);
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
        cwd ? { query: { directory: cwd } } : undefined,
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
    options.heartbeatMs ?? 15_000,
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
      if (polling) resyncPending = true;
    },
  };
}
