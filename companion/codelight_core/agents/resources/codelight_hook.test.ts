import { describe, expect, test } from "bun:test";

import {
  type CodelightReport,
  orderedSink,
} from "./codelight_hook.ts";

function report(state: CodelightReport["state"]): CodelightReport {
  return {
    agentId: "opencode",
    sessionId: "session-1",
    state,
    eventName: "session.status",
    cwd: "/workspace",
  };
}

describe("ordered hook sink", () => {
  test("does not start the next report until the previous report completes", () => {
    const started: string[] = [];
    const completions: Array<() => void> = [];
    const sink = orderedSink((item, complete) => {
      started.push(item.state);
      completions.push(complete);
    });

    sink(report("idle"));
    sink(report("working"));

    expect(started).toEqual(["idle"]);
    completions[0]?.();
    expect(started).toEqual(["idle", "working"]);
  });
});
