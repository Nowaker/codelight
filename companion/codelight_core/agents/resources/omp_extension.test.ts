import { describe, expect, test } from "bun:test";

import type { OmpContext } from "./omp_extension.ts";
import { stateForOmpEvent } from "./omp_extension.ts";

function context(idle: boolean): OmpContext {
  return {
    cwd: "/tmp/project",
    isIdle: () => idle,
    setTimeout,
    sessionManager: { getSessionId: () => "session-1" },
  };
}

describe("OMP lifecycle mapping", () => {
  test("marks work, approvals, and shutdown distinctly", () => {
    expect(stateForOmpEvent("turn_start", {}, context(false))).toBe("working");
    expect(stateForOmpEvent("tool_approval_requested", {}, context(false))).toBe(
      "waiting",
    );
    expect(stateForOmpEvent("session_shutdown", {}, context(true))).toBe(
      "ended",
    );
  });

  test("only treats agent end as idle after OMP reports idle", () => {
    expect(stateForOmpEvent("agent_end", {}, context(false))).toBe("unknown");
    expect(stateForOmpEvent("agent_end", {}, context(true))).toBe("idle");
    expect(
      stateForOmpEvent("agent_end", { willContinue: true }, context(true)),
    ).toBe("working");
  });
});
