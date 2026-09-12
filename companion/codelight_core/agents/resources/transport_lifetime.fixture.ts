import { writeFileSync, existsSync } from "node:fs";
import { processTransport } from "./codelight_hook.ts";

const mode = process.argv[2];
const receipt = process.argv[3];
if (receipt === undefined) throw new Error("missing receipt path");
switch (mode) {
  case "hook":
    writeFileSync(receipt, String(process.ppid));
    break;
  case "host": {
    const transport = processTransport([
      process.execPath, import.meta.path, "hook", receipt,
    ]);
    transport.snapshot({
      agentId: "opencode", complete: true, sessions: [],
      eventName: "session.status.snapshot", cwd: "",
    });
    process.stdout.write(JSON.stringify({ pid: process.pid, delivered: existsSync(receipt) }));
    process.exit(0);
  }
  default:
    throw new Error("unknown fixture mode");
}
