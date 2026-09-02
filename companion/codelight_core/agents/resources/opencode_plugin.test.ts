import { describe, expect, test } from "bun:test";

import type {
  CodelightReport,
  CodelightSnapshot,
} from "./codelight_hook.ts";
import { createOpenCodePlugin } from "./opencode_plugin.ts";

type ScheduledHeartbeat = {
  cancel(): void;
  unref(): void;
};

type HeartbeatScheduler = (
  task: () => void,
  intervalMs: number,
) => ScheduledHeartbeat;

type StatusResponse = {
  readonly data?: unknown;
  readonly error?: unknown;
};

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
  readonly reject: (reason: Error) => void;
} {
  let resolver: ((value: T) => void) | undefined;
  let rejecter: ((reason: Error) => void) | undefined;
  const promise = new Promise<T>((resolve, reject) => {
    resolver = resolve;
    rejecter = reject;
  });
  return {
    promise,
    resolve: (value) => resolver?.(value),
    reject: (reason) => rejecter?.(reason),
  };
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

function pluginInput(
  status: (
    parameters?: { readonly directory?: string },
  ) => Promise<StatusResponse>,
) {
  return {
    directory: "/workspace",
    client: { session: { status } },
  };
}

function recordingScheduler(): {
  readonly schedule: HeartbeatScheduler;
  readonly tasks: Array<{
    readonly run: () => void;
    cancelled: boolean;
    unrefCalled: boolean;
  }>;
} {
  const tasks: Array<{
    readonly run: () => void;
    cancelled: boolean;
    unrefCalled: boolean;
  }> = [];
  return {
    tasks,
    schedule: (run) => {
      const task = { run, cancelled: false, unrefCalled: false };
      tasks.push(task);
      return {
        cancel: () => {
          task.cancelled = true;
        },
        unref: () => {
          task.unrefCalled = true;
        },
      };
    },
  };
}

function recordingTransport(
  reports: CodelightReport[],
  snapshots: CodelightSnapshot[],
) {
  return {
    event: (report: CodelightReport) => reports.push(report),
    snapshot: (snapshot: CodelightSnapshot) => snapshots.push(snapshot),
  };
}

describe("OpenCode lifecycle resynchronization", () => {
  test("passes the workspace as a v2 status parameter", async () => {
    let parameters: { readonly directory?: string } | undefined;
    const plugin = createOpenCodePlugin(
      [],
      recordingTransport([], []),
      { schedule: recordingScheduler().schedule },
    );

    await plugin(pluginInput(async (value) => {
      parameters = value;
      return { data: {} };
    }));
    await settle();

    expect(parameters).toEqual({ directory: "/workspace" });
  });

  test("reports a complete startup snapshot, including explicit idle", async () => {
    const reports: CodelightReport[] = [];
    const snapshots: CodelightSnapshot[] = [];
    const scheduler = recordingScheduler();
    const plugin = createOpenCodePlugin(
      [],
      recordingTransport(reports, snapshots),
      { heartbeatMs: 15_000, schedule: scheduler.schedule },
    );

    await plugin(pluginInput(async () => ({
      data: {
        "session-busy": { type: "busy" },
        "session-idle": { type: "idle" },
      },
    })));
    await settle();

    expect(reports).toEqual([]);
    expect(snapshots).toEqual([{
      agentId: "opencode",
      complete: true,
      sessions: [
        { sessionId: "session-busy", state: "working" },
        { sessionId: "session-idle", state: "idle" },
      ],
      eventName: "session.status.snapshot",
      cwd: "/workspace",
    }]);
    expect(scheduler.tasks[0]?.unrefCalled).toBe(true);
  });

  test("reports unknown on failed snapshots and retries on heartbeat", async () => {
    const reports: CodelightReport[] = [];
    const snapshots: CodelightSnapshot[] = [];
    const scheduler = recordingScheduler();
    let fail = true;
    const plugin = createOpenCodePlugin(
      [],
      recordingTransport(reports, snapshots),
      { heartbeatMs: 15_000, schedule: scheduler.schedule },
    );

    await plugin(pluginInput(async () => (
      fail ? { error: { message: "offline" } } : { data: {} }
    )));
    await settle();
    expect(snapshots.at(-1)?.complete).toBe(false);

    fail = false;
    scheduler.tasks[0]?.run();
    await settle();
    expect(snapshots.at(-1)).toMatchObject({ complete: true, sessions: [] });
  });

  test("treats array status payloads as incomplete", async () => {
    const snapshots: CodelightSnapshot[] = [];
    const scheduler = recordingScheduler();
    const plugin = createOpenCodePlugin(
      [],
      recordingTransport([], snapshots),
      { heartbeatMs: 15_000, schedule: scheduler.schedule },
    );

    await plugin(pluginInput(async () => ({ data: [] })));
    await settle();

    expect(snapshots).toMatchObject([{ complete: false, sessions: [] }]);
  });

  test("does not overlap queries or apply a snapshot older than an event", async () => {
    const reports: CodelightReport[] = [];
    const snapshots: CodelightSnapshot[] = [];
    const scheduler = recordingScheduler();
    const first = deferred<StatusResponse>();
    let calls = 0;
    const plugin = createOpenCodePlugin(
      [],
      recordingTransport(reports, snapshots),
      { heartbeatMs: 15_000, schedule: scheduler.schedule },
    );
    const hooks = await plugin(pluginInput(() => {
      calls += 1;
      return calls === 1
        ? first.promise
        : Promise.resolve({ data: { newer: { type: "busy" } } });
    }));

    scheduler.tasks[0]?.run();
    expect(calls).toBe(1);
    await hooks.event({
      event: {
        type: "session.status",
        properties: { sessionID: "newer", status: { type: "busy" } },
      },
    });
    first.resolve({ data: {} });
    await settle();

    expect(calls).toBe(2);
    expect(reports.map(({ sessionId, state }) => [sessionId, state])).toEqual([
      ["newer", "working"],
    ]);
    expect(reports[0]?.providerEvidenceComplete).toBe(false);
    expect(snapshots).toEqual([{
      agentId: "opencode",
      complete: true,
      sessions: [{ sessionId: "newer", state: "working" }],
      eventName: "session.status.snapshot",
      cwd: "/workspace",
    }]);
  });

  test("ignores a failed snapshot that predates a newer event", async () => {
    const reports: CodelightReport[] = [];
    const snapshots: CodelightSnapshot[] = [];
    const scheduler = recordingScheduler();
    const first = deferred<StatusResponse>();
    let calls = 0;
    const plugin = createOpenCodePlugin(
      [],
      recordingTransport(reports, snapshots),
      { heartbeatMs: 15_000, schedule: scheduler.schedule },
    );
    const hooks = await plugin(pluginInput(() => {
      calls += 1;
      return calls === 1
        ? first.promise
        : Promise.resolve({ data: { newer: { type: "idle" } } });
    }));

    await hooks.event({
      event: {
        type: "session.status",
        properties: { sessionID: "newer", status: { type: "idle" } },
      },
    });
    first.reject(new TypeError("offline"));
    await settle();

    expect(calls).toBe(2);
    expect(reports.map(({ sessionId, state }) => [sessionId, state])).toEqual([
      ["newer", "idle"],
    ]);
    expect(snapshots).toEqual([{
      agentId: "opencode",
      complete: true,
      sessions: [{ sessionId: "newer", state: "idle" }],
      eventName: "session.status.snapshot",
      cwd: "/workspace",
    }]);
  });

  test("cancels the unreferenced heartbeat when the plugin is disposed", async () => {
    const reports: CodelightReport[] = [];
    const snapshots: CodelightSnapshot[] = [];
    const scheduler = recordingScheduler();
    const plugin = createOpenCodePlugin(
      [],
      recordingTransport(reports, snapshots),
      { heartbeatMs: 15_000, schedule: scheduler.schedule },
    );
    const hooks = await plugin(pluginInput(async () => ({ data: {} })));
    await settle();

    await hooks.dispose?.();

    expect(scheduler.tasks[0]?.unrefCalled).toBe(true);
    expect(scheduler.tasks[0]?.cancelled).toBe(true);
  });
});
