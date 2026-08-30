import type {
  CodelightReport,
  CodelightSink,
  CodelightState,
} from "./codelight_hook.ts";
import { processSink } from "./codelight_hook.ts";

export type OmpEventName =
  | "session_start"
  | "session_shutdown"
  | "before_agent_start"
  | "agent_start"
  | "agent_end"
  | "turn_start"
  | "tool_execution_start"
  | "tool_execution_end"
  | "auto_compaction_start"
  | "auto_compaction_end"
  | "auto_retry_start"
  | "auto_retry_end"
  | "tool_approval_requested"
  | "tool_approval_resolved";

export interface OmpContext {
  readonly cwd: string;
  readonly isIdle: () => boolean;
  readonly setTimeout: (
    callback: () => void,
    ms?: number,
  ) => ReturnType<typeof setTimeout>;
  readonly sessionManager: {
    readonly getSessionId: () => string;
  };
}

export interface OmpExtensionApi {
  readonly on: (
    event: OmpEventName,
    handler: (event: unknown, context: OmpContext) => void,
  ) => void;
}

const IDLE_SETTLE_RETRY_MS = 25;
const IDLE_SETTLE_MAX_ATTEMPTS = 200;

function assertNever(value: never): never {
  throw new TypeError(`Unhandled OMP event: ${String(value)}`);
}

function willContinue(event: unknown): boolean {
  return (
    typeof event === "object" &&
    event !== null &&
    "willContinue" in event &&
    event.willContinue === true
  );
}

export function stateForOmpEvent(
  eventName: OmpEventName,
  event: unknown,
  context: OmpContext,
): CodelightState {
  switch (eventName) {
    case "session_start":
      return "idle";
    case "session_shutdown":
      return "ended";
    case "agent_end":
      if (willContinue(event)) return "working";
      return context.isIdle() ? "idle" : "unknown";
    case "tool_approval_requested":
      return "waiting";
    case "before_agent_start":
    case "agent_start":
    case "turn_start":
    case "tool_execution_start":
    case "tool_execution_end":
    case "auto_compaction_start":
    case "auto_compaction_end":
    case "auto_retry_start":
    case "auto_retry_end":
    case "tool_approval_resolved":
      return "working";
    default:
      return assertNever(eventName);
  }
}

function reportForEvent(
  eventName: OmpEventName,
  event: unknown,
  context: OmpContext,
): CodelightReport {
  return {
    agentId: "omp",
    sessionId: context.sessionManager.getSessionId(),
    state: stateForOmpEvent(eventName, event, context),
    eventName,
    cwd: context.cwd,
  };
}

function sendWithoutInterruptingAgent(
  sink: CodelightSink,
  report: CodelightReport,
): void {
  try {
    sink(report);
  } catch {
    // no-excuse-ok: catch - monitoring cannot break the host agent.
  }
}

export function createOmpExtension(
  command: readonly string[],
  sink: CodelightSink = processSink(command),
): (api: OmpExtensionApi) => void {
  return (api) => {
    let generation = 0;

    const settleWhenIdle = (
      event: unknown,
      context: OmpContext,
      expectedGeneration: number,
      attempt = 0,
    ): void => {
      if (attempt >= IDLE_SETTLE_MAX_ATTEMPTS) return;
      context.setTimeout(() => {
        if (generation !== expectedGeneration) return;
        const report = reportForEvent("agent_end", event, context);
        if (report.state === "idle") {
          sendWithoutInterruptingAgent(sink, report);
          return;
        }
        settleWhenIdle(event, context, expectedGeneration, attempt + 1);
      }, IDLE_SETTLE_RETRY_MS);
    };

    const events = [
      "session_start",
      "session_shutdown",
      "before_agent_start",
      "agent_start",
      "agent_end",
      "turn_start",
      "tool_execution_start",
      "tool_execution_end",
      "auto_compaction_start",
      "auto_compaction_end",
      "auto_retry_start",
      "auto_retry_end",
      "tool_approval_requested",
      "tool_approval_resolved",
    ] as const;

    for (const eventName of events) {
      api.on(eventName, (event, context) => {
        generation += 1;
        const report = reportForEvent(eventName, event, context);
        sendWithoutInterruptingAgent(sink, report);
        if (eventName === "agent_end" && report.state === "unknown") {
          settleWhenIdle(event, context, generation);
        }
      });
    }
  };
}
