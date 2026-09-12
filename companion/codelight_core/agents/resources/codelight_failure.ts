import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  closeSync, fsyncSync, linkSync, mkdirSync, openSync, readFileSync,
  renameSync, unlinkSync, writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

class BootIdentityError extends Error {}

function currentBoot(): string {
  let value: string;
  switch (process.platform) {
    case "linux":
      value = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
      break;
    case "darwin": {
      const result = spawnSync("/usr/sbin/sysctl", ["-n", "kern.bootsessionuuid"], {
        encoding: "utf8", timeout: 2000, killSignal: "SIGKILL",
      });
      if (result.status !== 0) throw new BootIdentityError();
      value = result.stdout.trim();
      break;
    }
    default:
      throw new BootIdentityError();
  }
  if (!/^[\da-f]{8}-(?:[\da-f]{4}-){3}[\da-f]{12}$/i.test(value)) {
    throw new BootIdentityError();
  }
  return value.toLowerCase();
}

function durableFile(path: string, content: string): void {
  const descriptor = openSync(path, "wx", 0o600);
  try {
    writeFileSync(descriptor, content);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

export function invalidateFailedReport(agentId: string): void {
  const boot = currentBoot();
  const configured = process.env["CODELIGHT_CONFIG_HOME"] ?? join(homedir(), ".config", "codelight");
  const home = configured === "~" ? homedir()
    : configured.startsWith("~/") ? join(homedir(), configured.slice(2)) : configured;
  const root = join(home, "monitor_state", "evidence.sqlite3.boots", boot);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const metadata = join(root, "boot-id");
  const temporaryBoot = join(root, `.boot-id-${randomUUID()}`);
  durableFile(temporaryBoot, boot);
  try {
    try {
      linkSync(temporaryBoot, metadata);
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "EEXIST")) throw error;
    }
  } finally {
    unlinkSync(temporaryBoot);
  }
  if (readFileSync(metadata, "utf8") !== boot) throw new BootIdentityError();
  const directory = join(root, "evidence.sqlite3.taints");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const operation = `transport-failed-${randomUUID()}`;
  const prefix = createHash("sha256").update(`agent\0${agentId}`).digest("hex");
  const name = `${prefix}-${"0".repeat(20)}-1-${operation}.taint`;
  const temporary = join(directory, `.${prefix}.${name}.${randomUUID()}.tmp`);
  durableFile(temporary, JSON.stringify({
    kind: "agent", agent_id: agentId, order_token: null,
    authority_rank: 1, operation_id: operation,
  }));
  renameSync(temporary, join(directory, name));
  for (const path of [directory, root]) {
    const descriptor = openSync(path, "r");
    try {
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
  }
}
