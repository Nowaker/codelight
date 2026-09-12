import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

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

test("short-lived host waits for its hook before explicit exit", () => {
  const directory = mkdtempSync(join(tmpdir(), "codelight-lifetime-"));
  const receipt = join(directory, "receipt");
  try {
    const host = spawnSync(process.execPath, [
      join(import.meta.dir, "transport_lifetime.fixture.ts"), "host", receipt,
    ], { encoding: "utf8", timeout: 5000 });
    expect(host.status).toBe(0);
    const result: unknown = JSON.parse(host.stdout);
    expect(result).toEqual({ pid: host.pid, delivered: true });
    expect(readFileSync(receipt, "utf8")).toBe(String(host.pid));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
