import { spawn } from "node:child_process";

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
};

export type CodelightSink = (report: CodelightReport) => void;

export type CompletingSink = (
  report: CodelightReport,
  complete: () => void,
) => void;

export function orderedSink(send: CompletingSink): CodelightSink {
  const queue: CodelightReport[] = [];
  let active = false;

  const startNext = (): void => {
    if (active) return;
    const report = queue.shift();
    if (report === undefined) return;
    active = true;
    let completed = false;
    const complete = (): void => {
      if (completed) return;
      completed = true;
      active = false;
      startNext();
    };
    try {
      send(report, complete);
    } catch {
      complete();
    }
  };

  return (report) => {
    queue.push(report);
    startNext();
  };
}

export function processSink(command: readonly string[]): CodelightSink {
  return orderedSink((report, complete) => {
    const executable = command[0];
    if (executable === undefined) {
      complete();
      return;
    }
    const child = spawn(
      executable,
      [
        ...command.slice(1),
        "--agent",
        report.agentId,
        "--hook",
        report.state,
      ],
      { stdio: ["pipe", "ignore", "ignore"] },
    );
    let settled = false;
    const finish = (): void => {
      if (settled) return;
      settled = true;
      complete();
    };
    child.once("error", finish);
    child.once("close", finish);
    child.stdin.on("error", () => undefined);
    child.stdin.end(
      JSON.stringify({
        session_id: report.sessionId,
        hook_event_name: report.eventName,
        cwd: report.cwd,
      }),
    );
    child.unref();
  });
}
