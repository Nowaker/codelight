import { expect, test } from "bun:test";
import { mkdtempSync, readdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { invalidateFailedReport } from "./codelight_failure.ts";

function withConfigHome(run: (taints: () => string) => void): void {
  const home = mkdtempSync(join(tmpdir(), "codelight-failure-"));
  const previous = process.env["CODELIGHT_CONFIG_HOME"];
  process.env["CODELIGHT_CONFIG_HOME"] = home;
  try {
    run(() => {
      const boots = join(home, "monitor_state", "evidence.sqlite3.boots");
      const boot = readdirSync(boots)[0] ?? "";
      return join(boots, boot, "evidence.sqlite3.taints");
    });
  } finally {
    if (previous === undefined) delete process.env["CODELIGHT_CONFIG_HOME"];
    else process.env["CODELIGHT_CONFIG_HOME"] = previous;
    rmSync(home, { recursive: true, force: true });
  }
}

test("repeated failures share one unordered marker per agent", () => {
  withConfigHome((taints) => {
    for (let index = 0; index < 5; index += 1) invalidateFailedReport("opencode");
    invalidateFailedReport("codex");

    const names = readdirSync(taints()).sort();
    expect(names).toHaveLength(2);
    expect(names.every((name) => name.endsWith("-00000000000000000000-1-transport-failed.taint"))).toBe(true);
    const marker = JSON.parse(readFileSync(join(taints(), names[0] ?? ""), "utf8"));
    expect(marker).toMatchObject({ kind: "agent", order_token: null, authority_rank: 1 });
    expect(marker.operation_id).toMatch(/^transport-failed-[\da-f-]{36}$/);
  });
});

test("a failure after a reader claimed the marker writes a new one", () => {
  withConfigHome((taints) => {
    invalidateFailedReport("opencode");
    const name = readdirSync(taints())[0] ?? "";
    renameSync(join(taints(), name), join(taints(), `claimed-${name}`));

    invalidateFailedReport("opencode");

    expect(readdirSync(taints()).sort()).toEqual([name, `claimed-${name}`]);
  });
});
