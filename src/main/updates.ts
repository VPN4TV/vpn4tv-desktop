import { execFile } from "node:child_process";
import { createWriteStream } from "node:fs";
import { mkdir, readdir, rename, rm, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as WebReadableStream } from "node:stream/web";

import { app, autoUpdater, BrowserWindow, ipcMain } from "electron";
import { compare, gt, prerelease, valid } from "semver";

import { InstallUpdateResult } from "../shared/gen/experimental/boxdd/desktop_service_pb";
import { UPDATES_CALL, UPDATES_STATE_CHANGED } from "../shared/ipc";
import type {
  AppUpdateInfo,
  ProfilesResult,
  UpdateInstallResult,
  UpdatesState,
  UpdateTrack,
} from "../shared/ipc";
import { applicationCacheDirectory } from "./appCache";
import { parseBooleanPreference, Preference } from "./database";
import { desktopService } from "./daemon";

// VPN4TV: our own feed. Upstream polled SagerNet's GitHub releases and offered
// their SFW-*.exe as an update to this app — a foreign installer the daemon
// would reject anyway (it demands the same signing certificate).
const APPCAST_URL = "https://bell.a4e.ar/vpn4tv-desktop-appcast.json";
const RELEASES_REQUEST_TIMEOUT_MILLISECONDS = 30_000;
const EXIT_CODE_CANCELLED = 1223;
const EXIT_CODE_LAUNCH_FAILED = 1224;

const WINDOWS_UPDATE_ARCHITECTURES: Partial<Record<NodeJS.Architecture, string[]>> = {
  arm64: ["arm64", "x64", "x86"],
  ia32: ["x86"],
  x64: ["x64"],
};
const updateArchitectureTokens = WINDOWS_UPDATE_ARCHITECTURES[process.arch];
// VPN4TV: macOS too. Electron's autoUpdater (Squirrel.Mac) takes a ZIP of the
// new app only when it is signed by the same Developer ID, swaps the bundle
// when the app quits and starts the new one; the system service is upgraded
// afterwards by the setup screen (version mismatch: Upgrade, administrator
// password), as after a manual DMG install.
const MAC_UPDATE_ARCHITECTURES = new Set<NodeJS.Architecture>(["arm64", "x64"]);
const UPDATES_SUPPORTED =
  (process.platform === "win32" && updateArchitectureTokens !== undefined) ||
  (process.platform === "darwin" && MAC_UPDATE_ARCHITECTURES.has(process.arch));

/**
 * VPN4TV: Squirrel.Mac's JSON feed for this architecture, which our own check
 * reads too: {currentRelease, releases: [{version, updateTo: {version, name,
 * notes, pub_date, url, size, prerelease, releaseUrl}}]}. VPN4TV_UPDATE_FEED
 * points it elsewhere, for the update test.
 */
function macFeedURL(): string {
  return process.env.VPN4TV_UPDATE_FEED || `https://bell.a4e.ar/vpn4tv-macos-${process.arch}-update.json`;
}
const APP_IS_PRERELEASE = prerelease(__APP_VERSION__) !== null;

function parseString(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("invalid string preference");
  }
  return value;
}

function parseUpdateTrack(value: unknown): UpdateTrack {
  if (value !== "stable" && value !== "beta") {
    throw new Error("invalid update track preference");
  }
  return value;
}

const updateTrackPreference = new Preference<UpdateTrack>(
  "update_track",
  APP_IS_PRERELEASE ? "beta" : "stable",
  parseUpdateTrack,
);
const checkUpdateEnabledPreference = new Preference(
  "check_update_enabled",
  false,
  parseBooleanPreference,
);
const updateCheckPromptedPreference = new Preference(
  "update_check_prompted",
  false,
  parseBooleanPreference,
);
const cachedUpdateInfoPreference = new Preference("cached_update_info", "", parseString);
const lastShownUpdateVersionPreference = new Preference(
  "last_shown_update_version",
  "",
  parseString,
);
const stableTrackAvailablePreference = new Preference(
  "stable_track_available",
  false,
  parseBooleanPreference,
);
const githubTokenPreference = new Preference("github_token", "", parseString);

function currentTrack(): UpdateTrack {
  if (!stableTrackAvailablePreference.get()) {
    return "beta";
  }
  return updateTrackPreference.get();
}

const runtime = {
  info: null as AppUpdateInfo | null,
  checking: false,
  downloading: false,
  installing: false,
  downloadProgress: 0,
};

function updatesState(): UpdatesState {
  return {
    supported: UPDATES_SUPPORTED,
    track: currentTrack(),
    stableTrackAvailable: stableTrackAvailablePreference.get(),
    checkUpdateEnabled: checkUpdateEnabledPreference.get(),
    prompted: updateCheckPromptedPreference.get(),
    info: runtime.info,
    checking: runtime.checking,
    downloading: runtime.downloading,
    installing: runtime.installing,
    downloadProgress: runtime.downloadProgress,
  };
}

function broadcastState(): void {
  const state = updatesState();
  for (const window of BrowserWindow.getAllWindows()) {
    if (!window.webContents.isDestroyed()) {
      window.webContents.send(UPDATES_STATE_CHANGED, state);
    }
  }
}

function shouldIncludeVersion(version: string, track: UpdateTrack): boolean {
  const normalizedVersion = valid(version);
  if (normalizedVersion === null) {
    return false;
  }
  return gt(normalizedVersion, __APP_VERSION__) || (track === "stable" && APP_IS_PRERELEASE);
}

function setUpdateInfo(info: AppUpdateInfo | null): void {
  runtime.info = info;
  if (info === null) {
    cachedUpdateInfoPreference.set("");
    lastShownUpdateVersionPreference.set("");
  } else {
    cachedUpdateInfoPreference.set(JSON.stringify(info));
  }
  broadcastState();
}

function parseCachedUpdateInfo(cached: string): AppUpdateInfo | null {
  let value: unknown;
  try {
    value = JSON.parse(cached);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const candidate = value as Record<string, unknown>;
  if (
    typeof candidate.versionName !== "string" ||
    typeof candidate.releaseURL !== "string" ||
    typeof candidate.downloadURL !== "string" ||
    typeof candidate.releaseNotes !== "string" ||
    typeof candidate.isPrerelease !== "boolean" ||
    typeof candidate.fileSize !== "number"
  ) {
    return null;
  }
  return {
    versionName: candidate.versionName,
    releaseURL: candidate.releaseURL,
    downloadURL: candidate.downloadURL,
    releaseNotes: candidate.releaseNotes,
    isPrerelease: candidate.isPrerelease,
    fileSize: candidate.fileSize,
  };
}

function loadCachedUpdate(): boolean {
  const cached = cachedUpdateInfoPreference.get();
  if (cached === "") {
    return false;
  }
  const info = parseCachedUpdateInfo(cached);
  const track = currentTrack();
  if (
    info === null ||
    (track === "stable" && info.isPrerelease) ||
    !shouldIncludeVersion(info.versionName, track)
  ) {
    setUpdateInfo(null);
    return false;
  }
  runtime.info = info;
  return lastShownUpdateVersionPreference.get() !== info.versionName;
}

/** One build of one release, as published in our appcast. */
interface AppcastBuild {
  arch: string;
  url: string;
  size?: number;
}

interface AppcastRelease {
  version: string;
  prerelease?: boolean;
  notes?: string;
  releaseUrl?: string;
  builds: AppcastBuild[];
}

async function fetchFeed(url: string): Promise<unknown> {
  const response = await fetch(url, {
    headers: new Headers({ "User-Agent": `VPN4TV/${__APP_VERSION__}` }),
    signal: AbortSignal.timeout(RELEASES_REQUEST_TIMEOUT_MILLISECONDS),
  });
  if (!response.ok) {
    throw new Error(`fetch releases: HTTP ${response.status}`);
  }
  return response.json();
}

/** The Mac feed's releases in the appcast's shape, with this machine's build. */
async function fetchMacReleases(): Promise<AppcastRelease[]> {
  const feed = (await fetchFeed(macFeedURL())) as { releases?: unknown };
  if (!Array.isArray(feed.releases)) {
    throw new Error("update feed has no releases");
  }
  const releases: AppcastRelease[] = [];
  for (const entry of feed.releases) {
    const updateTo = (entry as { updateTo?: Record<string, unknown> } | null)?.updateTo;
    if (typeof updateTo !== "object" || updateTo === null) {
      continue;
    }
    if (typeof updateTo.version !== "string" || typeof updateTo.url !== "string" || updateTo.url === "") {
      continue;
    }
    releases.push({
      version: updateTo.version,
      prerelease: updateTo.prerelease === true,
      notes: typeof updateTo.notes === "string" ? updateTo.notes : "",
      releaseUrl: typeof updateTo.releaseUrl === "string" ? updateTo.releaseUrl : undefined,
      builds: [{
        arch: process.arch,
        url: updateTo.url,
        size: typeof updateTo.size === "number" ? updateTo.size : undefined,
      }],
    });
  }
  return releases;
}

async function fetchReleases(): Promise<AppcastRelease[]> {
  if (process.platform === "darwin") {
    return fetchMacReleases();
  }
  const feed = (await fetchFeed(APPCAST_URL)) as { releases?: unknown };
  if (!Array.isArray(feed.releases)) {
    throw new Error("update feed has no releases");
  }
  return feed.releases.filter(
    (release): release is AppcastRelease =>
      typeof release === "object" &&
      release !== null &&
      typeof (release as AppcastRelease).version === "string" &&
      Array.isArray((release as AppcastRelease).builds),
  );
}

function findAsset(builds: AppcastBuild[]): AppcastBuild | null {
  if (process.platform === "darwin") {
    return builds.find((build) => build.arch === process.arch && build.url !== "") ?? null;
  }
  if (updateArchitectureTokens === undefined) {
    throw new Error(`unsupported Windows architecture: ${process.arch}`);
  }
  for (const token of updateArchitectureTokens) {
    const match = builds.find(
      (build) => build.arch === token && typeof build.url === "string" && build.url !== "",
    );
    if (match !== undefined) {
      return match;
    }
  }
  return null;
}

async function checkForUpdate(): Promise<AppUpdateInfo | null> {
  if (!UPDATES_SUPPORTED) {
    throw new Error("updates are not supported on this platform");
  }
  if (runtime.checking) {
    throw new Error("update check already in progress");
  }
  runtime.checking = true;
  broadcastState();
  try {
    const track = currentTrack();
    const releases = await fetchReleases();
    if (currentTrack() !== track) {
      return runtime.info;
    }
    let best: AppUpdateInfo | null = null;
    for (const release of releases) {
      const asset = findAsset(release.builds);
      if (asset === null) {
        continue;
      }
      const isPrerelease = release.prerelease === true;
      if (!isPrerelease && !stableTrackAvailablePreference.get()) {
        stableTrackAvailablePreference.set(true);
      }
      if (track === "stable" && isPrerelease) {
        continue;
      }
      const version = release.version.startsWith("v") ? release.version.slice(1) : release.version;
      if (!shouldIncludeVersion(version, track)) {
        continue;
      }
      if (best !== null && compare(version, best.versionName) <= 0) {
        continue;
      }
      best = {
        versionName: version,
        releaseURL: release.releaseUrl ?? APPCAST_URL,
        downloadURL: asset.url,
        releaseNotes: release.notes ?? "",
        isPrerelease,
        fileSize: asset.size ?? 0,
      };
    }
    setUpdateInfo(best);
    return best;
  } finally {
    runtime.checking = false;
    broadcastState();
  }
}

function reportDownloadProgress(progress: number): void {
  if (progress < 1 && progress - runtime.downloadProgress < 0.01) {
    return;
  }
  runtime.downloadProgress = progress;
  broadcastState();
}

async function downloadUpdate(info: AppUpdateInfo): Promise<string> {
  const directory = join(applicationCacheDirectory(), "updates");
  await mkdir(directory, { recursive: true });
  const fileName = basename(new URL(info.downloadURL).pathname);
  if (fileName === "" || fileName === "." || fileName === "..") {
    throw new Error("invalid update download URL");
  }
  const destination = join(directory, fileName);

  const existing = await stat(destination).catch(() => null);
  if (existing !== null && info.fileSize > 0 && existing.size === info.fileSize) {
    reportDownloadProgress(1);
    return destination;
  }

  const staleEntries = await readdir(directory).catch(() => [] as string[]);
  for (const entry of staleEntries) {
    if (entry !== fileName) {
      await rm(join(directory, entry), { recursive: true, force: true }).catch(() => {});
    }
  }
  await rm(destination, { force: true });

  const response = await fetch(info.downloadURL, {
    headers: { "User-Agent": `sing-box/${__APP_VERSION__}` },
  });
  if (!response.ok || response.body === null) {
    throw new Error(`download update: HTTP ${response.status}`);
  }
  const totalBytes = Number(response.headers.get("content-length") ?? "") || info.fileSize;
  const temporary = `${destination}.download`;
  let written = 0;
  await pipeline(
    Readable.fromWeb(response.body as unknown as WebReadableStream),
    async function* (source: AsyncIterable<Buffer>) {
      for await (const chunk of source) {
        written += chunk.length;
        if (totalBytes > 0) {
          reportDownloadProgress(Math.min(written / totalBytes, 1));
        }
        yield chunk;
      }
    },
    createWriteStream(temporary),
  );
  if (info.fileSize > 0 && written !== info.fileSize) {
    await rm(temporary, { force: true });
    throw new Error(`downloaded update is truncated: ${written} of ${info.fileSize} bytes`);
  }
  await rename(temporary, destination);
  reportDownloadProgress(1);
  return destination;
}

function launchUpdateInstallerElevated(installerPath: string): Promise<boolean> {
  const quotedInstallerPath = `'${installerPath.replaceAll("'", "''")}'`;
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "try {",
    `Start-Process -FilePath ${quotedInstallerPath} -ArgumentList '--updated','--force-run' -Verb RunAs`,
    "exit 0",
    "} catch {",
    "if ($_.Exception.InnerException -is [System.ComponentModel.Win32Exception] -and $_.Exception.InnerException.NativeErrorCode -eq 1223) {",
    `exit ${EXIT_CODE_CANCELLED}`,
    "}",
    `exit ${EXIT_CODE_LAUNCH_FAILED}`,
    "}",
  ].join("\n");
  return new Promise((resolve, reject) => {
    execFile(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { windowsHide: true },
      (error) => {
        if (error === null) {
          resolve(true);
          return;
        }
        if (typeof error.code !== "number") {
          reject(error);
          return;
        }
        if (error.code === EXIT_CODE_CANCELLED) {
          resolve(false);
          return;
        }
        reject(new Error(`failed to launch the elevated update installer (${error.code})`));
      },
    );
  });
}

function resetInstallationState(): void {
  runtime.downloading = false;
  runtime.installing = false;
  runtime.downloadProgress = 0;
  broadcastState();
}

function prepareInstallation(): AppUpdateInfo {
  if (!UPDATES_SUPPORTED) {
    throw new Error("updates are not supported on this platform");
  }
  const info = runtime.info;
  if (info === null) {
    throw new Error("no update available");
  }
  if (runtime.downloading || runtime.installing) {
    throw new Error("update installation already in progress");
  }
  runtime.downloading = true;
  runtime.installing = false;
  runtime.downloadProgress = 0;
  broadcastState();
  return info;
}

/**
 * VPN4TV: the Mac path. Squirrel.Mac reads the same feed, downloads the ZIP
 * and checks its signature (only an app signed like this one passes), then
 * quitAndInstall swaps the bundle and starts the new version. It reports no
 * progress: the bar stays indeterminate.
 */
function installMac(): Promise<UpdateInstallResult> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      autoUpdater.removeListener("error", onError);
      autoUpdater.removeListener("update-not-available", onNotAvailable);
      autoUpdater.removeListener("update-downloaded", onDownloaded);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onNotAvailable = () => {
      cleanup();
      reject(new Error("the update feed offers no newer version"));
    };
    const onDownloaded = () => {
      cleanup();
      runtime.downloading = false;
      runtime.installing = true;
      broadcastState();
      resolve("started");
      setImmediate(() => autoUpdater.quitAndInstall());
    };
    autoUpdater.on("error", onError);
    autoUpdater.on("update-not-available", onNotAvailable);
    autoUpdater.on("update-downloaded", onDownloaded);
    if (process.env.VPN4TV_UPDATE_AUTOINSTALL === "1") {
      for (const event of ["checking-for-update", "update-available", "update-not-available", "update-downloaded", "before-quit-for-update"] as const) {
        autoUpdater.on(event as "update-available", () => console.log(`[updates] test: event ${event}`));
      }
      autoUpdater.on("error", (error) => console.log(`[updates] test: event error ${error.message}`));
    }
    try {
      autoUpdater.setFeedURL({ url: macFeedURL(), serverType: "json" });
      autoUpdater.checkForUpdates();
    } catch (error) {
      cleanup();
      reject(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

async function downloadAndInstall(): Promise<UpdateInstallResult> {
  const info = prepareInstallation();
  if (process.platform === "darwin") {
    try {
      return await installMac();
    } catch (error) {
      resetInstallationState();
      throw error;
    }
  }
  try {
    const installerPath = await downloadUpdate(info);
    if (desktopService === null) {
      throw new Error("daemon is not available");
    }
    runtime.downloading = false;
    runtime.installing = true;
    broadcastState();
    const response = await desktopService.installUpdate({ installerPath });
    switch (response.result) {
      case InstallUpdateResult.STARTED:
        app.quit();
        return "started";
      case InstallUpdateResult.SIGNER_MISMATCH:
        resetInstallationState();
        return "signer-mismatch";
      case InstallUpdateResult.NOT_NEWER:
        resetInstallationState();
        return "not-newer";
      default:
        throw new Error("daemon returned an invalid update installation result");
    }
  } catch (error) {
    resetInstallationState();
    throw error;
  }
}

async function installWithElevation(): Promise<boolean> {
  // VPN4TV: Windows only; the Mac path never offers it (no signer bypass).
  if (process.platform !== "win32") {
    throw new Error("installing with elevation is not supported on this platform");
  }
  const info = prepareInstallation();
  try {
    const installerPath = await downloadUpdate(info);
    runtime.downloading = false;
    runtime.installing = true;
    broadcastState();
    const launched = await launchUpdateInstallerElevated(installerPath);
    if (!launched) {
      resetInstallationState();
      return false;
    }
    app.quit();
    return true;
  } catch (error) {
    resetInstallationState();
    throw error;
  }
}

const handlers: Record<string, (...callArguments: never[]) => Promise<unknown>> = {
  async state(): Promise<UpdatesState> {
    return updatesState();
  },

  async check(): Promise<AppUpdateInfo | null> {
    return checkForUpdate();
  },

  async getGitHubToken(): Promise<string> {
    return githubTokenPreference.get();
  },

  async setGitHubToken(value: string): Promise<void> {
    const token = parseString(value).trim();
    githubTokenPreference.set(token === "" ? null : token);
  },

  downloadAndInstall,

  installWithElevation,

  async setTrack(track: UpdateTrack): Promise<void> {
    if (!stableTrackAvailablePreference.get()) {
      throw new Error("track selection is not available");
    }
    const parsed = parseUpdateTrack(track);
    updateTrackPreference.set(parsed);
    if (runtime.info !== null && parsed === "stable" && runtime.info.isPrerelease) {
      setUpdateInfo(null);
    } else {
      broadcastState();
    }
  },

  async setCheckUpdateEnabled(value: boolean): Promise<void> {
    checkUpdateEnabledPreference.set(parseBooleanPreference(value));
    updateCheckPromptedPreference.set(true);
    broadcastState();
  },

  async setPrompted(): Promise<void> {
    updateCheckPromptedPreference.set(true);
    broadcastState();
  },

  async markShown(): Promise<void> {
    if (runtime.info !== null) {
      lastShownUpdateVersionPreference.set(runtime.info.versionName);
    }
  },
};

export function registerUpdates(): void {
  ipcMain.handle(
    UPDATES_CALL,
    async (
      _event,
      method: string,
      ...callArguments: unknown[]
    ): Promise<ProfilesResult> => {
      const handler = handlers[method];
      if (!handler) {
        return { ok: false, error: `unknown updates method: ${method}` };
      }
      try {
        const value = await handler(...(callArguments as never[]));
        return { ok: true, value };
      } catch (error) {
        return {
          ok: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  );
}

export async function runStartupUpdateCheck(present: () => void): Promise<void> {
  if (!UPDATES_SUPPORTED) {
    return;
  }
  // VPN4TV: the update test: check the feed (VPN4TV_UPDATE_FEED) and
  // install whatever it offers, without the settings or a window.
  if (process.env.VPN4TV_UPDATE_AUTOINSTALL === "1") {
    try {
      const offered = await checkForUpdate();
      console.log(`[updates] test: offered ${offered?.versionName ?? "nothing"}`);
      if (offered !== null) {
        console.log(`[updates] test: ${await downloadAndInstall()}`);
      }
    } catch (error) {
      console.error("[updates] test failed:", error);
    }
    return;
  }
  const shouldPresentCached = loadCachedUpdate();
  if (!updateCheckPromptedPreference.get() || !checkUpdateEnabledPreference.get()) {
    return;
  }
  if (shouldPresentCached) {
    present();
  }
  let found: AppUpdateInfo | null;
  try {
    found = await checkForUpdate();
  } catch {
    return;
  }
  if (found !== null && lastShownUpdateVersionPreference.get() !== found.versionName) {
    present();
  }
}
