// VPN4TV: the desktop answer to Android's per-app proxy — sing-box matches
// executable names, so the picker offers what is running plus anything the user
// points at on disk.

import { execFile } from "node:child_process";
import { basename } from "node:path";
import { promisify } from "node:util";

import { dialog } from "electron";

const run = promisify(execFile);
const LIST_TIMEOUT_MILLISECONDS = 10_000;

/** Executables we never want in the list: the OS and our own process. */
const IGNORED = new Set([
  "System",
  "System Idle Process",
  "Registry",
  "Memory Compression",
  "svchost.exe",
  "csrss.exe",
  "wininit.exe",
  "services.exe",
  "lsass.exe",
  "smss.exe",
  "dwm.exe",
  "fontdrvhost.exe",
  "sing-box-daemon.exe",
  "sing-box-daemon",
  "VPN4TV.exe",
  "VPN4TV",
]);

function isUserApplication(name: string): boolean {
  if (name === "" || IGNORED.has(name)) {
    return false;
  }
  // macOS/Linux daemons and kernel threads are noise for this list.
  return !name.startsWith("com.apple.") && !name.startsWith("(") && !name.endsWith("d");
}

export async function runningApplications(): Promise<string[]> {
  const names = new Set<string>();
  try {
    if (process.platform === "win32") {
      const { stdout } = await run("tasklist", ["/fo", "csv", "/nh"], {
        timeout: LIST_TIMEOUT_MILLISECONDS,
        maxBuffer: 4 * 1024 * 1024,
        windowsHide: true,
      });
      for (const line of stdout.split(/\r?\n/u)) {
        const match = /^"([^"]+)"/u.exec(line);
        if (match !== null) {
          names.add(match[1]);
        }
      }
    } else {
      const { stdout } = await run("ps", ["-Ao", "comm="], {
        timeout: LIST_TIMEOUT_MILLISECONDS,
        maxBuffer: 4 * 1024 * 1024,
      });
      for (const line of stdout.split("\n")) {
        const path = line.trim();
        if (path !== "") {
          names.add(basename(path));
        }
      }
    }
  } catch {
    return [];
  }
  return [...names]
    .filter(isUserApplication)
    .sort((left, right) => left.localeCompare(right, undefined, { sensitivity: "base" }));
}

/**
 * Ask for an application on disk and return the name sing-box will see. On
 * macOS that is the executable inside the bundle, which is normally the bundle
 * name itself.
 */
export async function pickApplication(): Promise<string | null> {
  const filters =
    process.platform === "win32"
      ? [{ name: "Applications", extensions: ["exe"] }]
      : process.platform === "darwin"
        ? [{ name: "Applications", extensions: ["app"] }]
        : [];
  const result = await dialog.showOpenDialog({
    properties: process.platform === "darwin" ? ["openFile", "openDirectory"] : ["openFile"],
    filters,
  });
  const path = result.filePaths[0];
  if (result.canceled || path === undefined) {
    return null;
  }
  const name = basename(path);
  return name.endsWith(".app") ? name.slice(0, -".app".length) : name;
}
