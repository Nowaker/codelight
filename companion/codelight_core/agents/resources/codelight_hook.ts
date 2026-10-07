import { spawnSync } from "node:child_process";
import { invalidateFailedReport } from "./codelight_failure.ts";

export type CodelightState =
  | "working"
  | "waiting"
  | "idle"
  | "ended"
  | "unknown";

export type CodelightReport = {
  readonly agentId: string;
  readonly sessionId: string;
  readonly state: CodelightState;
  readonly eventName: string;
  readonly cwd: string;
  readonly providerEvidenceComplete?: boolean;
};

export type CodelightSnapshotSession = {
  readonly sessionId: string;
  readonly state: "working" | "waiting" | "idle";
};

export type CodelightSnapshot = {
  readonly agentId: string;
  readonly complete: boolean;
  readonly sessions: readonly CodelightSnapshotSession[];
  readonly eventName: string;
  readonly cwd: string;
};

export type CodelightSink = (report: CodelightReport) => void;
// Reports whether the reporter accepted the snapshot. A sink that never calls
// it leaves delivery unconfirmed, so callers must keep resending.
export type SnapshotDelivery = (delivered: boolean) => void;
export type CodelightSnapshotSink = (
  snapshot: CodelightSnapshot,
  onDelivery?: SnapshotDelivery,
) => void;

export type CodelightTransport = {
  readonly event: CodelightSink;
  readonly snapshot: CodelightSnapshotSink;
};

export type CompletingSink<T> = (
  value: T,
  complete: () => void,
) => void;

export function orderedSink<T = CodelightReport>(
  send: CompletingSink<T>,
): (value: T) => void {
  const queue: T[] = [];
  let active = false;

  const startNext = (): void => {
    if (active) return;
    const value = queue.shift();
    if (value === undefined) return;
    active = true;
    let completed = false;
    const complete = (): void => {
      if (completed) return;
      completed = true;
      active = false;
      startNext();
    };
    try {
      send(value, complete);
    } catch {
      complete();
    }
  };

  return (value) => {
    queue.push(value);
    startNext();
  };
}

type LifecycleMessage =
  | { readonly kind: "event"; readonly value: CodelightReport }
  | {
    readonly kind: "snapshot";
    readonly value: CodelightSnapshot;
    readonly onDelivery: SnapshotDelivery | undefined;
  };

type HookInvocation = {
  readonly agentId: string;
  readonly hook: string;
  readonly input: Readonly<Record<string, unknown>>;
};

function hookInvocation(message: LifecycleMessage): HookInvocation {
  switch (message.kind) {
    case "event":
      return {
        agentId: message.value.agentId,
        hook: message.value.state,
        input: {
          session_id: message.value.sessionId,
          hook_event_name: message.value.eventName,
          cwd: message.value.cwd,
          provider_evidence_complete:
            message.value.providerEvidenceComplete ?? true,
        },
      };
    case "snapshot":
      return {
        agentId: message.value.agentId,
        hook: "snapshot",
        input: {
          hook_event_name: message.value.eventName,
          cwd: message.value.cwd,
          complete: message.value.complete,
          sessions: message.value.sessions.map(({ sessionId, state }) => ({
            session_id: sessionId,
            state,
          })),
        },
      };
  }
}

export function processTransport(
  command: readonly string[],
): CodelightTransport {
  const send = orderedSink<LifecycleMessage>((message, complete) => {
    const executable = command[0];
    const acknowledge = (delivered: boolean): void => {
      if (message.kind === "snapshot") message.onDelivery?.(delivered);
    };
    if (executable === undefined) {
      invalidateFailedReport(message.value.agentId);
      acknowledge(false);
      complete();
      return;
    }
    const invocation = hookInvocation(message);
    // OpenCode explicitly exits after short commands. The identity reader must
    // finish while this host is alive; unref or async disposal cannot fence exit.
    const result = spawnSync(
      executable,
      [
        ...command.slice(1),
        "--agent",
        invocation.agentId,
        "--hook",
        invocation.hook,
      ],
      {
        input: JSON.stringify(invocation.input),
        stdio: ["pipe", "ignore", "ignore"],
        timeout: 2000,
        killSignal: "SIGKILL",
      },
    );
    const delivered = result.error === undefined && result.status === 0 &&
      result.signal === null;
    if (!delivered) invalidateFailedReport(invocation.agentId);
    acknowledge(delivered);
    complete();
  });
  return {
    event: (report) => send({ kind: "event", value: report }),
    snapshot: (snapshot, onDelivery) =>
      send({ kind: "snapshot", value: snapshot, onDelivery }),
  };
}

export function processSink(command: readonly string[]): CodelightSink {
  return processTransport(command).event;
}
