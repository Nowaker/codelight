import type { CodelightReport, CodelightTransport } from "./codelight_hook.ts";
import { processTransport } from "./codelight_hook.ts";
import {
  createOpenCodeStatusSync,
  type OpenCodeStatusClient,
  type OpenCodeStatusSyncOptions,
} from "./opencode_status_sync.ts";

type EventEnvelope = {
  readonly event: unknown;
};

type PluginInput = {
  readonly client?: OpenCodeStatusClient;
  readonly directory?: string;
};

type OpenCodePlugin = (input: PluginInput) => Promise<{
  readonly dispose?: () => Promise<void>;
  readonly event: (envelope: EventEnvelope) => Promise<void>;
}>;

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null;
}

function stringField(
  record: Readonly<Record<string, unknown>>,
  key: string,
): string {
  const value = record[key];
  return typeof value === "string" ? value : "";
}

export function reportForOpenCodeEvent(
  event: unknown,
  cwd = "",
): CodelightReport | null {
  if (!isRecord(event)) return null;
  const eventName = stringField(event, "type");
  const properties = event["properties"];
  if (!isRecord(properties)) return null;
  const info = properties["info"];
  const sessionId = stringField(properties, "sessionID") ||
    (isRecord(info) ? stringField(info, "id") : "");
  if (!sessionId) return null;

  switch (eventName) {
    case "session.status": {
      const status = properties["status"];
      if (!isRecord(status)) return null;
      const statusType = stringField(status, "type");
      if (statusType === "busy" || statusType === "retry") {
        return {
          agentId: "opencode",
          sessionId,
          state: "working",
          eventName,
          cwd,
        };
      }
      if (statusType === "idle") {
        return {
          agentId: "opencode",
          sessionId,
          state: "idle",
          eventName,
          cwd,
        };
      }
      return null;
    }
    case "permission.asked":
    case "permission.v2.asked":
    case "question.asked":
    case "question.v2.asked":
      return {
        agentId: "opencode",
        sessionId,
        state: "waiting",
        eventName,
        cwd,
      };
    case "permission.replied":
    case "permission.v2.replied":
    case "question.replied":
    case "question.v2.replied":
    case "question.rejected":
    case "question.v2.rejected":
      return {
        agentId: "opencode",
        sessionId,
        state: "working",
        eventName,
        cwd,
      };
    case "session.deleted":
      return {
        agentId: "opencode",
        sessionId,
        state: "ended",
        eventName,
        cwd,
      };
    default:
      return null;
  }
}

export function createOpenCodePlugin(
  command: readonly string[],
  transport: CodelightTransport = processTransport(command),
  options: OpenCodeStatusSyncOptions = {},
): OpenCodePlugin {
  return async (input) => {
    const cwd = input.directory ?? "";
    const emit = (report: CodelightReport): void => {
      try {
        transport.event(report);
      } catch { // no-excuse-ok: catch - monitoring cannot break the host agent.
      }
    };
    const statusSync = input.client === undefined
      ? undefined
      : createOpenCodeStatusSync(input.client, cwd, transport.snapshot, options);

    return {
      dispose: async () => {
        statusSync?.dispose();
      },
      event: async ({ event }) => {
        const report = reportForOpenCodeEvent(event, cwd);
        if (report === null) return;
        statusSync?.noteEvent();
        emit({ ...report, providerEvidenceComplete: false });
      },
    };
  };
}
