// VPN4TV: lines the app adds to the service log on the Logs screen.
//
// The mobile clients write their summary lines ("russia-direct: on …") into
// the core's own log, where support reads them. The daemon has no call for
// that, so the bridge (bridge.ts) appends these lines to the log stream it
// relays to the dashboard: after the log the daemon sends to a new subscriber,
// and live as they come. A start clears the core's log; the line of the next
// start begins a new list here too.

import { EventEmitter } from "node:events";

export interface ServiceLogLine {
  warn: boolean;
  message: string;
}

const MAXIMUM_LINES = 20;
const emitter = new EventEmitter();
let lines: ServiceLogLine[] = [];

/** Add a line; [startsRun]: it is the first line of a new start, the earlier ones are gone with that start's log. */
export function writeServiceLogLine(line: ServiceLogLine, startsRun = false): void {
  if (startsRun) {
    lines = [];
  }
  lines.push(line);
  if (lines.length > MAXIMUM_LINES) {
    lines.shift();
  }
  emitter.emit("line", line);
}

/** The daemon went away: its log, and the lines that went with it, are gone. */
export function clearServiceLogLines(): void {
  lines = [];
}

/** The lines of the current start, oldest first. */
export function serviceLogLines(): readonly ServiceLogLine[] {
  return lines;
}

export function onServiceLogLine(listener: (line: ServiceLogLine) => void): () => void {
  emitter.on("line", listener);
  return () => {
    emitter.off("line", listener);
  };
}
