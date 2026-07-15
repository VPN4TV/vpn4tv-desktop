import { app } from "electron";
import { existsSync, mkdirSync, renameSync } from "node:fs";
import { join } from "node:path";

import { readWindowsInstallationLayout } from "./installationLayout";

export interface ApplicationPaths {
  userData: string;
  daemonData: string;
}

let configuredPaths: ApplicationPaths | null = null;

export function configureApplicationPaths(developmentUserDataPath: string): ApplicationPaths {
  if (configuredPaths !== null) {
    return configuredPaths;
  }
  const defaultUserDataPath = join(app.getPath("appData"), "sing-box");
  const legacyUserDataPath = join(app.getPath("appData"), "sing-box-for-desktop");
  let paths: ApplicationPaths;
  if (developmentUserDataPath !== "") {
    paths = {
      userData: developmentUserDataPath,
      daemonData:
        process.platform === "win32"
          ? "C:\\ProgramData\\sing-box-daemon"
          : "/var/lib/sing-box-daemon",
    };
  } else if (process.platform === "win32" && app.isPackaged) {
    const layout = readWindowsInstallationLayout(defaultUserDataPath);
    paths = {
      userData: layout.applicationDataDirectory,
      daemonData: layout.daemonDataDirectory,
    };
  } else {
    paths = {
      userData: defaultUserDataPath,
      daemonData:
        process.platform === "win32"
          ? "C:\\ProgramData\\sing-box-daemon"
          : "/var/lib/sing-box-daemon",
    };
  }

  if (
    paths.userData === defaultUserDataPath &&
    !existsSync(defaultUserDataPath) &&
    existsSync(legacyUserDataPath)
  ) {
    renameSync(legacyUserDataPath, defaultUserDataPath);
  }

  const sessionDataPath = join(paths.userData, "session");
  const crashDumpsPath = join(paths.userData, "crash_dumps");
  mkdirSync(paths.userData, { recursive: true });
  mkdirSync(sessionDataPath, { recursive: true });
  mkdirSync(crashDumpsPath, { recursive: true });
  app.setPath("userData", paths.userData);
  app.setPath("sessionData", sessionDataPath);
  app.setPath("crashDumps", crashDumpsPath);
  configuredPaths = paths;
  return paths;
}

export function applicationPaths(): ApplicationPaths {
  if (configuredPaths === null) {
    throw new Error("application paths are not configured");
  }
  return configuredPaths;
}
