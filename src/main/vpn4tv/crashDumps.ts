// VPN4TV: what a native crash dump needs to be read on bell.
//
// Electron's crash reporter writes a minidump for any of its processes: the
// main one, a window's renderer, the GPU process, a utility service. Only the
// app's own label went to bell ("The application process crashed."): the dump
// is binary and the upload is text, so 41 reports from August to November said
// nothing at all (group 57e95163b2). Two additions, kept free of Electron so
// they can be tested:
//  - the "gone" events Electron reports for its child processes, kept in a
//    short log, name the process a dump came from; a dump with no event near it
//    is the main process's own, since nobody is left to report that one;
//  - the dump itself goes in the text upload, gzip-compressed and base64-encoded,
//    when it fits; bell decodes it.

import { gzipSync } from "node:zlib";

export interface ProcessGoneEvent {
  /** Milliseconds since the epoch. */
  at: number;
  /** Electron's process type: "GPU", "Utility", "renderer", … */
  type: string;
  /** Electron's reason: "crashed", "oom", "abnormal-exit", "killed", … */
  reason: string;
  exitCode: number;
  /** A utility process's service name, when Electron gives one. */
  name?: string;
}

export interface ProcessGoneLog {
  /** Since when events are recorded: a dump older than that cannot be told apart. */
  since: number;
  events: ProcessGoneEvent[];
}

/** How far apart a dump's time and its process's "gone" event may be. */
export const PROCESS_GONE_MATCH_MILLISECONDS = 30_000;
/** The log keeps the newest events only. */
export const PROCESS_GONE_LOG_LIMIT = 50;
/** The reasons that leave a dump behind (not a clean exit, not a kill from outside). */
export const PROCESS_CRASH_REASONS: ReadonlySet<string> = new Set([
  "crashed",
  "oom",
  "abnormal-exit",
  "launch-failed",
  "integrity-failure",
]);

export const MINIDUMP_UPLOAD_SUFFIX = ".gz.b64";

export function parseProcessGoneLog(text: string, now: number): ProcessGoneLog {
  try {
    const value = JSON.parse(text) as { since?: unknown; events?: unknown };
    const since = typeof value.since === "number" ? value.since : now;
    const events = Array.isArray(value.events)
      ? value.events.filter(
          (event): event is ProcessGoneEvent =>
            typeof event === "object" &&
            event !== null &&
            typeof (event as ProcessGoneEvent).at === "number" &&
            typeof (event as ProcessGoneEvent).type === "string" &&
            typeof (event as ProcessGoneEvent).reason === "string" &&
            typeof (event as ProcessGoneEvent).exitCode === "number",
        )
      : [];
    return { since, events };
  } catch {
    // No log yet, or a damaged one: events count from now.
    return { since: now, events: [] };
  }
}

export function appendProcessGone(log: ProcessGoneLog, event: ProcessGoneEvent): ProcessGoneLog {
  return { since: log.since, events: [...log.events, event].slice(-PROCESS_GONE_LOG_LIMIT) };
}

/** The event closest in time to a dump written at [dumpAt], if one is near enough. */
export function matchProcessGone(log: ProcessGoneLog, dumpAt: number): ProcessGoneEvent | null {
  let best: ProcessGoneEvent | null = null;
  for (const event of log.events) {
    const distance = Math.abs(event.at - dumpAt);
    if (distance > PROCESS_GONE_MATCH_MILLISECONDS) {
      continue;
    }
    if (best === null) {
      best = event;
      continue;
    }
    // A crash outranks a kill nearby (one process brought down by another's crash).
    const crash = PROCESS_CRASH_REASONS.has(event.reason);
    const bestCrash = PROCESS_CRASH_REASONS.has(best.reason);
    if (crash !== bestCrash ? crash : distance < Math.abs(best.at - dumpAt)) {
      best = event;
    }
  }
  return best;
}

/** Windows crash codes read better as NTSTATUS (0xC0000005 = access violation). */
export function formatExitCode(exitCode: number): string {
  if (exitCode < 0 || exitCode > 0xffff) {
    return `${exitCode} (0x${(exitCode >>> 0).toString(16).toUpperCase().padStart(8, "0")})`;
  }
  return String(exitCode);
}

export interface NativeCrashDescription {
  processType: string;
  exceptionReason: string;
}

export function describeNativeCrash(log: ProcessGoneLog, dumpAt: number): NativeCrashDescription {
  const event = matchProcessGone(log, dumpAt);
  if (event !== null) {
    // Electron names the GPU process "GPU" as well: no "GPU (GPU)".
    const processType = event.name && event.name !== event.type ? `${event.type} (${event.name})` : event.type;
    return {
      processType,
      exceptionReason: `The ${processType} process went away: ${event.reason}, exit code ${formatExitCode(event.exitCode)}.`,
    };
  }
  if (dumpAt < log.since) {
    return {
      processType: "unknown",
      exceptionReason: "A process crashed before this version recorded which one.",
    };
  }
  return {
    processType: "main",
    exceptionReason: "The main process crashed (no child process went away near the time of the dump).",
  };
}

/**
 * The upload section for a dump: gzip, base64 in 76-character lines, under a
 * "===== <name>.gz.b64 =====" header. A dump over [budgetBytes] is not cut (a
 * cut dump cannot be read); the section then only says so.
 */
export function minidumpUploadSection(fileName: string, bytes: Uint8Array, budgetBytes: number): string {
  const packed = gzipSync(bytes, { level: 9 }).toString("base64");
  const lines: string[] = [];
  for (let offset = 0; offset < packed.length; offset += 76) {
    lines.push(packed.slice(offset, offset + 76));
  }
  const section = `===== ${fileName}${MINIDUMP_UPLOAD_SUFFIX} =====\n${lines.join("\n")}`;
  if (Buffer.byteLength(section) <= budgetBytes) {
    return section;
  }
  return (
    `===== ${fileName} =====\n` +
    `not sent: ${bytes.length} bytes, ${packed.length} as gzip base64, over the upload limit`
  );
}
