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

function acknowledgingTransport(
  snapshots: CodelightSnapshot[],
  outcome: () => boolean = () => true,
) {
  return {
    event: () => {},
    snapshot: (
      snapshot: CodelightSnapshot,
      onDelivery?: (delivered: boolean) => void,
    ) => {
      snapshots.push(snapshot);
      onDelivery?.(outcome());
    },
  };
}

describe("OpenCode redundant snapshot suppression", () => {
  async function idleTab(
    options: { readonly keepaliveMs?: number; readonly ok?: () => boolean } = {},
  ) {
    const snapshots: CodelightSnapshot[] = [];
    const scheduler = recordingScheduler();
    const clock = { now: 0 };
    let data: unknown = { "session-a": { type: "idle" } };
    const plugin = createOpenCodePlugin(
      [],
      acknowledgingTransport(snapshots, options.ok),
      {
        heartbeatMs: 15_000,
        keepaliveMs: options.keepaliveMs ?? 300_000,
        now: () => clock.now,
        schedule: scheduler.schedule,
      },
    );
    const hooks = await plugin(pluginInput(async () => ({ data })));
    await settle();
    const beat = async (): Promise<void> => {
      clock.now += 15_000;
      scheduler.tasks[0]?.run();
      await settle();
    };
    return {
      snapshots,
      hooks,
      beat,
      clock,
      setData: (value: unknown) => {
        data = value;
      },
    };
  }

  test("skips an acknowledged unchanged idle snapshot until the keepalive", async () => {
    const tab = await idleTab({ keepaliveMs: 60_000 });
    expect(tab.snapshots).toHaveLength(1);

    await tab.beat();
    await tab.beat();
    await tab.beat();
    expect(tab.snapshots).toHaveLength(1);

    await tab.beat();
    expect(tab.snapshots).toHaveLength(2);
    await tab.beat();
    expect(tab.snapshots).toHaveLength(2);
  });

  test("delivers a changed snapshot immediately", async () => {
    const tab = await idleTab();
    tab.setData({
      "session-a": { type: "idle" },
      "session-b": { type: "idle" },
    });
    await tab.beat();

    expect(tab.snapshots.at(-1)?.sessions).toEqual([
      { sessionId: "session-a", state: "idle" },
      { sessionId: "session-b", state: "idle" },
    ]);
    expect(tab.snapshots).toHaveLength(2);
  });

  test("treats session order as irrelevant to equality", async () => {
    const tab = await idleTab();
    tab.setData({
      "session-b": { type: "idle" },
      "session-a": { type: "idle" },
    });
    await tab.beat();
    tab.setData({
      "session-a": { type: "idle" },
      "session-b": { type: "idle" },
    });
    await tab.beat();

    expect(tab.snapshots).toHaveLength(2);
  });

  test("refreshes leased working snapshots on every heartbeat", async () => {
    const tab = await idleTab();
    tab.setData({ "session-a": { type: "busy" } });
    await tab.beat();
    await tab.beat();
    await tab.beat();

    expect(tab.snapshots.map(({ sessions }) => sessions[0]?.state)).toEqual([
      "idle",
      "working",
      "working",
      "working",
    ]);
  });

  test("resends after a working period returns to the same idle set", async () => {
    const tab = await idleTab();
    tab.setData({ "session-a": { type: "busy" } });
    await tab.beat();
    tab.setData({ "session-a": { type: "idle" } });
    await tab.beat();
    await tab.beat();

    expect(tab.snapshots.map(({ sessions }) => sessions[0]?.state)).toEqual([
      "idle",
      "working",
      "idle",
    ]);
  });

  test("resends an unchanged snapshot after a provider event", async () => {
    const tab = await idleTab();
    await tab.hooks.event({
      event: {
        type: "session.status",
        properties: { sessionID: "session-a", status: { type: "idle" } },
      },
    });
    await tab.beat();
    await tab.beat();

    expect(tab.snapshots).toHaveLength(2);
  });

  test("retries every heartbeat while the reporter fails", async () => {
    let ok = false;
    const tab = await idleTab({ ok: () => ok });
    await tab.beat();
    await tab.beat();
    expect(tab.snapshots).toHaveLength(3);

    ok = true;
    await tab.beat();
    await tab.beat();
    expect(tab.snapshots).toHaveLength(4);
  });

  test("delivers failed status queries and the recovery that follows", async () => {
    const tab = await idleTab();
    tab.setData([]);
    await tab.beat();
    await tab.beat();
    tab.setData({ "session-a": { type: "idle" } });
    await tab.beat();
    await tab.beat();

    expect(tab.snapshots.map(({ complete }) => complete)).toEqual([
      true,
      false,
      false,
      true,
    ]);
  });

  test("keeps resending when the transport never acknowledges", async () => {
    const snapshots: CodelightSnapshot[] = [];
    const scheduler = recordingScheduler();
    const plugin = createOpenCodePlugin(
      [],
      recordingTransport([], snapshots),
      { heartbeatMs: 15_000, schedule: scheduler.schedule },
    );
    await plugin(pluginInput(async () => ({ data: {} })));
    await settle();
    scheduler.tasks[0]?.run();
    await settle();

    expect(snapshots).toHaveLength(2);
  });
});

describe("OpenCode status sync intervals", () => {
  test("reads heartbeat and keepalive from the environment", async () => {
    const previous = {
      heartbeat: process.env["CODELIGHT_OPENCODE_HEARTBEAT_MS"],
      keepalive: process.env["CODELIGHT_OPENCODE_SNAPSHOT_KEEPALIVE_MS"],
    };
    process.env["CODELIGHT_OPENCODE_HEARTBEAT_MS"] = "5000";
    process.env["CODELIGHT_OPENCODE_SNAPSHOT_KEEPALIVE_MS"] = "10000";
    try {
      const snapshots: CodelightSnapshot[] = [];
      const intervals: number[] = [];
      const tasks: Array<() => void> = [];
      const clock = { now: 0 };
      const plugin = createOpenCodePlugin(
        [],
        acknowledgingTransport(snapshots),
        {
          now: () => clock.now,
          schedule: (task, intervalMs) => {
            tasks.push(task);
            intervals.push(intervalMs);
            return { cancel: () => {}, unref: () => {} };
          },
        },
      );
      await plugin(pluginInput(async () => ({ data: {} })));
      await settle();
      clock.now = 9_999;
      tasks[0]?.();
      await settle();
      expect(snapshots).toHaveLength(1);
      clock.now = 10_000;
      tasks[0]?.();
      await settle();

      expect(intervals).toEqual([5000]);
      expect(snapshots).toHaveLength(2);
    } finally {
      for (const [name, value] of [
        ["CODELIGHT_OPENCODE_HEARTBEAT_MS", previous.heartbeat],
        ["CODELIGHT_OPENCODE_SNAPSHOT_KEEPALIVE_MS", previous.keepalive],
      ] as const) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });

  test("ignores invalid environment intervals", async () => {
    const previous = process.env["CODELIGHT_OPENCODE_HEARTBEAT_MS"];
    process.env["CODELIGHT_OPENCODE_HEARTBEAT_MS"] = "-1";
    try {
      const intervals: number[] = [];
      const plugin = createOpenCodePlugin(
        [],
        recordingTransport([], []),
        {
          schedule: (_task, intervalMs) => {
            intervals.push(intervalMs);
            return { cancel: () => {}, unref: () => {} };
          },
        },
      );
      await plugin(pluginInput(async () => ({ data: {} })));

      expect(intervals).toEqual([15_000]);
    } finally {
      if (previous === undefined) {
        delete process.env["CODELIGHT_OPENCODE_HEARTBEAT_MS"];
      } else {
        process.env["CODELIGHT_OPENCODE_HEARTBEAT_MS"] = previous;
      }
    }
  });
});
