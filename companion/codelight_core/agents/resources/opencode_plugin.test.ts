import { describe, expect, test } from "bun:test";

import { reportForOpenCodeEvent } from "./opencode_plugin.ts";

describe("OpenCode lifecycle mapping", () => {
  test("maps busy and idle session status", () => {
    const busy = reportForOpenCodeEvent({
      type: "session.status",
      properties: { sessionID: "session-1", status: { type: "busy" } },
    });
    const idle = reportForOpenCodeEvent({
      type: "session.status",
      properties: { sessionID: "session-1", status: { type: "idle" } },
    });

    expect(busy?.state).toBe("working");
    expect(idle?.state).toBe("idle");
  });

  test("maps prompts and deletion without inventing a session", () => {
    const waiting = reportForOpenCodeEvent({
      type: "permission.asked",
      properties: { sessionID: "session-1" },
    });
    const ended = reportForOpenCodeEvent({
      type: "session.deleted",
      properties: { info: { id: "session-1" } },
    });

    expect(waiting?.state).toBe("waiting");
    expect(ended?.state).toBe("ended");
    expect(reportForOpenCodeEvent({ type: "session.status", properties: {} })).toBe(
      null,
    );
  });
});
