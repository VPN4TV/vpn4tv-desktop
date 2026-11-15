// VPN4TV: the log of Electron's child processes that went away, which names
// the process a native crash dump came from (see vpn4tv/crashDumps.ts).

import { app } from "electron";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  type ProcessGoneLog,
  PROCESS_CRASH_REASONS,
  appendProcessGone,
  parseProcessGoneLog,
} from "./vpn4tv/crashDumps";

function logPath(): string {
  return join(app.getPath("userData"), "process-gone.json");
}

export function processGoneLog(): ProcessGoneLog {
  let text = "";
  try {
    text = readFileSync(logPath(), "utf-8");
  } catch {}
  return parseProcessGoneLog(text, Date.now());
}

interface GoneDetails {
  reason: string;
  exitCode: number;
  name?: string;
  serviceName?: string;
}

export function recordProcessGone(type: string, details: GoneDetails): void {
  if (details.reason === "clean-exit") {
    return;
  }
  try {
    const name = details.name || details.serviceName;
    const log = appendProcessGone(processGoneLog(), {
      at: Date.now(),
      type,
      reason: details.reason,
      exitCode: details.exitCode,
      ...(name ? { name } : {}),
    });
    writeFileSync(logPath(), JSON.stringify(log));
  } catch {
    // Best effort: a missing record only leaves the dump unnamed.
  }
}

/**
 * Records every child process that goes away; [onCrash] runs for those that
 * crashed, so their dumps need not wait for the next launch.
 */
export function watchProcessGone(onCrash: () => void): void {
  // The log starts with the first launch that has it: dumps written before
  // then cannot be told apart.
  try {
    readFileSync(logPath());
  } catch {
    try {
      writeFileSync(logPath(), JSON.stringify(processGoneLog()));
    } catch {}
  }
  app.on("child-process-gone", (_event, details) => {
    recordProcessGone(details.type, details);
    if (PROCESS_CRASH_REASONS.has(details.reason)) {
      onCrash();
    }
  });
  app.on("render-process-gone", (_event, _contents, details) => {
    recordProcessGone("renderer", details);
    if (PROCESS_CRASH_REASONS.has(details.reason)) {
      onCrash();
    }
  });
}
