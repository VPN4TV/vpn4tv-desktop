// VPN4TV: ship crash dumps to the same receiver the Android client uses
// (bell.a4e.ar/crash). Without this a report sits on the user's disk and only
// reaches support if they think to export it themselves — which nobody does.
//
// Best effort throughout: a failed upload is retried on the next launch, and
// nothing here may break startup.

import { app } from "electron";

import { Preference, parseBooleanPreference } from "./database";
import * as reports from "./reports";

const RECEIVER_URL = "https://bell.a4e.ar/crash";
const REQUEST_TIMEOUT_MILLISECONDS = 15_000;
const MAXIMUM_BODY_BYTES = 1_500_000;
/** Older reports are the user's to export; we only chase what is fresh. */
const MAXIMUM_REPORTS_PER_RUN = 5;

const enabledPreference = new Preference<boolean>(
  "vpn4tv-send-crash-reports",
  true,
  parseBooleanPreference,
);

const uploadedPreference = new Preference<string[]>(
  "vpn4tv-uploaded-crash-reports",
  [],
  (value) => {
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
      throw new Error("invalid uploaded crash report list");
    }
    return value as string[];
  },
);

export function crashReportUploadEnabled(): boolean {
  return enabledPreference.get();
}

async function upload(name: string, content: string): Promise<void> {
  const body = content.length > MAXIMUM_BODY_BYTES ? content.slice(0, MAXIMUM_BODY_BYTES) : content;
  const response = await fetch(RECEIVER_URL, {
    method: "POST",
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "X-Kind": "crash",
      "X-VC": __APP_VERSION__,
      "X-Client": `desktop-${process.platform}-${process.arch}`,
      "X-Device": `${process.platform} ${process.getSystemVersion?.() ?? ""}`.slice(0, 120),
      "X-Report": name.slice(0, 120),
    },
    body,
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MILLISECONDS),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
}

/**
 * Upload crash reports we have not sent yet. Runs once per launch, after the
 * daemon connection settles — the daemon owns the core's reports.
 */
export async function uploadPendingCrashReports(): Promise<void> {
  if (!enabledPreference.get()) {
    return;
  }
  let entries: { name: string; crashedAt: number }[];
  try {
    entries = await reports.listCrashReports();
  } catch {
    return;
  }
  const uploaded = new Set(uploadedPreference.get());
  const pending = entries
    .filter((entry) => !uploaded.has(entry.name))
    .sort((left, right) => right.crashedAt - left.crashedAt)
    .slice(0, MAXIMUM_REPORTS_PER_RUN);
  for (const entry of pending) {
    try {
      const files = await reports.readCrashReport(entry.name);
      const content = files
        .filter((file) => !file.isBinary && file.content !== "")
        .map((file) => `===== ${file.name} =====\n${file.content}`)
        .join("\n\n");
      if (content !== "") {
        await upload(entry.name, content);
      }
      uploaded.add(entry.name);
    } catch {
      // Offline or the receiver is down — try again next launch.
    }
  }
  // Keep the list bounded; the names we drop are long gone from disk anyway.
  uploadedPreference.set([...uploaded].slice(-100));
}

export function scheduleCrashReportUpload(): void {
  app.whenReady().then(
    () => {
      setTimeout(() => void uploadPendingCrashReports(), 10_000);
    },
    () => {},
  );
}
