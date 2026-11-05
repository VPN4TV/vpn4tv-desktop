import { ConnectError } from "@connectrpc/connect";
import { BrowserWindow, app, dialog, ipcMain } from "electron";
import { copyFile, mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";

import { pickApplication, runningApplications } from "./vpn4tv/applications";
import { decodeVpn4tvLink } from "./vpn4tv/parser";
import { applyBridgeAuth } from "./vpn4tv/bridgeAuth";
import {
  type ResolvedHostsStore,
  hasFakeDns,
  injectProbedDns,
  injectResolvedHosts,
  preResolveHosts,
  probeDns,
  serverHosts,
  stripFakeDns,
} from "./vpn4tv/dns";
import { applyIPv6Support } from "./vpn4tv/ipv6";
import { hasDynamicOutlineKeys, resolveDynamicOutlineKeys } from "./vpn4tv/outlineDynamic";
import { usableRuleSets } from "./vpn4tv/russiaDirect";
import { probeDnsRu, probeProxyAlive } from "./vpn4tv/russiaDirectProbe";
import {
  type Prepared,
  type Wanted,
  RussiaDirectRuntime,
  russiaDirectLabel,
  russiaDirectLine,
} from "./vpn4tv/russiaDirectRuntime";
import {
  allThroughVpnEnabled,
  autoConnectEnabled,
  convertSubscription,
  hwid,
  forgetSubscriptionInfo,
  rememberRuDirect,
  rememberSubscriptionInfo,
  ruDirectOff,
  ruVpnExtra,
  subscriptionHeaders,
  subscriptionInfo,
} from "./vpn4tv";
import { ServiceStatus_Type } from "../shared/gen/daemon/started_service_pb";
import { ProfileContent_Type } from "../shared/gen/experimental/boxdd/desktop_service_pb";
import { PROFILES_CALL, PROFILES_CHANGED } from "../shared/ipc";
import type {
  ProfileCreate,
  ProfileMetadata,
  ProfileMetadataPatch,
  ProfileType,
  ProfilesResult,
  ProfilesState,
} from "../shared/ipc";
import { writeApplicationCacheFile } from "./appCache";
import { clearServiceLogLines, writeServiceLogLine } from "./appLog";
import { desktopService, startedService } from "./daemon";
import {
  Preference,
  preferenceSnapshot,
  removePreference,
  setPreference,
  settingsDatabase,
} from "./database";
import { oomStartOptions } from "./settings";
import { applicationService } from "./worker";
import { daemonState } from "./state";

const MINIMUM_UPDATE_INTERVAL_MINUTES = 15;
const DEFAULT_UPDATE_INTERVAL_MINUTES = 60;
const REMOTE_REQUEST_TIMEOUT_MILLISECONDS = 30_000;
const MAXIMUM_REMOTE_PROFILE_BYTES = 16 * 1024 * 1024;
const MAXIMUM_REMOTE_ERROR_BYTES = 64 * 1024;

interface ProfileRow {
  id: string;
  name: string;
  type: string;
  remote_url: string | null;
  auto_update: number;
  auto_update_interval_minutes: number;
  last_updated: number | null;
  item_order: number;
}

function profilesDirectory(): string {
  return join(app.getPath("userData"), "profiles");
}

function contentPath(id: string): string {
  return join(profilesDirectory(), `${id}.json`);
}

async function atomicWriteFile(path: string, content: string): Promise<void> {
  await mkdir(profilesDirectory(), { recursive: true });
  const temporaryPath = `${path}.${crypto.randomUUID()}.tmp`;
  try {
    await writeFile(temporaryPath, content);
    await rename(temporaryPath, path);
  } finally {
    await unlink(temporaryPath).catch(() => {});
  }
}

const profileOperations = new Map<string, Promise<void>>();

function runProfileOperation<Result>(
  id: string,
  operation: () => Promise<Result>,
): Promise<Result> {
  const previous = profileOperations.get(id) ?? Promise.resolve();
  const result = previous.catch(() => {}).then(operation);
  const settled = result.then(
    () => {},
    () => {},
  );
  profileOperations.set(id, settled);
  return result.finally(() => {
    if (profileOperations.get(id) === settled) {
      profileOperations.delete(id);
    }
  });
}

const selectedProfilePreference = new Preference<string | null>(
  "selected_profile_id",
  null,
  (value) => {
    if (typeof value !== "string" || value === "") {
      throw new Error("invalid selected profile preference");
    }
    return value;
  },
);

function profileFromRow(row: ProfileRow): ProfileMetadata {
  const profile: ProfileMetadata = {
    id: row.id,
    name: row.name,
    type: row.type as ProfileType,
    autoUpdate: row.auto_update !== 0,
    autoUpdateIntervalMinutes: row.auto_update_interval_minutes,
  };
  if (row.remote_url !== null) {
    profile.remoteUrl = row.remote_url;
  }
  if (row.last_updated !== null) {
    profile.lastUpdated = row.last_updated;
  }
  return profile;
}

function listProfiles(): ProfileMetadata[] {
  const rows = settingsDatabase()
    .prepare("SELECT * FROM profiles ORDER BY item_order ASC")
    .all() as unknown as ProfileRow[];
  return rows.map(profileFromRow);
}

function selectedProfileId(): string | null {
  return selectedProfilePreference.get();
}

function writeSelectedProfileId(id: string | null): void {
  selectedProfilePreference.set(id);
}

function findProfile(id: string): ProfileMetadata {
  const row = settingsDatabase()
    .prepare("SELECT * FROM profiles WHERE id = ?")
    .get(id) as ProfileRow | undefined;
  if (row === undefined) {
    throw new Error(`profile not found: ${id}`);
  }
  return profileFromRow(row);
}

// Mirrors the Apple client's ProfileManager.uniqueName: appends " (n)" until
// the name is free, so imported or created profiles never collide.
function uniqueName(baseName: string): string {
  const existing = new Set(listProfiles().map((profile) => profile.name));
  if (!existing.has(baseName)) {
    return baseName;
  }
  let counter = 1;
  while (existing.has(`${baseName} (${counter})`)) {
    counter += 1;
  }
  return `${baseName} (${counter})`;
}

const changeListeners: (() => void)[] = [];

export function onProfilesChanged(listener: () => void) {
  changeListeners.push(listener);
}

export function profilesState(): ProfilesState {
  return { selectedId: selectedProfileId(), profiles: listProfiles() };
}

function notifyChanged() {
  for (const window of BrowserWindow.getAllWindows()) {
    if (!window.webContents.isDestroyed()) {
      window.webContents.send(PROFILES_CHANGED);
    }
  }
  for (const listener of changeListeners) {
    listener();
  }
}

async function checkConfig(content: string): Promise<void> {
  await applicationService.checkConfig({ content });
}

function errorMessage(error: unknown): string {
  if (error instanceof ConnectError) {
    return error.rawMessage;
  }
  return error instanceof Error ? error.message : String(error);
}

async function readLimitedResponse(
  response: Response,
  maximumBytes: number,
): Promise<string> {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new Error(`response exceeds ${maximumBytes} bytes`);
  }
  if (response.body === null) {
    return "";
  }
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let totalLength = 0;
  for (;;) {
    const result = await reader.read();
    if (result.done) {
      break;
    }
    totalLength += result.value.byteLength;
    if (totalLength > maximumBytes) {
      await reader.cancel();
      throw new Error(`response exceeds ${maximumBytes} bytes`);
    }
    chunks.push(Buffer.from(result.value));
  }
  return Buffer.concat(chunks, totalLength).toString("utf-8");
}

async function fetchRemoteContent(remoteUrl: string, profileId?: string): Promise<string> {
  return (await fetchRemoteProfile(remoteUrl, profileId)).content;
}

// Mirrors libbox's HTTPClient (experimental/libbox/http.go): SetURL turns
// URL userinfo into a basic Authorization header, and Execute accepts only
// HTTP 200, reporting other statuses as "HTTP <Status>: <body>".
async function fetchRemoteProfile(
  remoteUrl: string,
  profileId?: string,
): Promise<{ content: string; routingChanged: boolean }> {
  const requestUrl = new URL(remoteUrl);
  // VPN4TV: identify the install and the platform — the backend tailors the
  // returned subscription on x-device-os.
  const headers = new Headers(subscriptionHeaders(__APP_VERSION__));
  if (requestUrl.username !== "" || requestUrl.password !== "") {
    const credentials = `${decodeURIComponent(requestUrl.username)}:${decodeURIComponent(requestUrl.password)}`;
    headers.set(
      "Authorization",
      `Basic ${Buffer.from(credentials).toString("base64")}`,
    );
    requestUrl.username = "";
    requestUrl.password = "";
  }
  const response = await fetch(requestUrl, {
    headers,
    signal: AbortSignal.timeout(REMOTE_REQUEST_TIMEOUT_MILLISECONDS),
  });
  if (response.status !== 200) {
    const status =
      response.statusText === ""
        ? String(response.status)
        : `${response.status} ${response.statusText}`;
    let body: string;
    try {
      body = await readLimitedResponse(response, MAXIMUM_REMOTE_ERROR_BYTES);
    } catch (error) {
      throw new Error(
        `HTTP ${status}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    throw new Error(`HTTP ${status}: ${body}`);
  }
  // VPN4TV: subscriptions arrive as proxy URIs / Xray JSON / base64 / vpn://,
  // not as sing-box configs — convert before anything stores or starts them.
  // A response that already is a sing-box config passes through untouched.
  if (profileId !== undefined) {
    rememberSubscriptionInfo(profileId, response.headers);
  }
  const content = convertSubscription(
    await readLimitedResponse(response, MAXIMUM_REMOTE_PROFILE_BYTES),
  );
  // VPN4TV: what our server says about "Russia direct" for this subscription
  // (x-vpn4tv-ru-direct, x-vpn4tv-ru-vpn), from a successful response only.
  const routingChanged = profileId !== undefined && rememberRuDirect(profileId, response.headers);
  return { content, routingChanged };
}

async function insertProfile(
  profile: ProfileMetadata,
  content: string,
): Promise<ProfileMetadata> {
  await atomicWriteFile(contentPath(profile.id), content);
  const store = settingsDatabase();
  store.transaction(() => {
    const nextOrder = (
      store
        .prepare(
          "SELECT COALESCE(MAX(item_order) + 1, 0) AS next_order FROM profiles",
        )
        .get() as {
        next_order: number;
      }
    ).next_order;
    store
      .prepare(
        `INSERT INTO profiles (id, name, type, remote_url, auto_update,
          auto_update_interval_minutes, last_updated, item_order)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        profile.id,
        profile.name,
        profile.type,
        profile.remoteUrl ?? null,
        profile.autoUpdate ? 1 : 0,
        profile.autoUpdateIntervalMinutes,
        profile.lastUpdated ?? null,
        nextOrder,
      );
    writeSelectedProfileId(profile.id);
  })();
  notifyChanged();
  reconfigureAutoUpdate();
  return profile;
}

async function importProfileData(
  fileName: string,
  data: Uint8Array,
): Promise<void> {
  if (fileName.toLowerCase().endsWith(".bpf")) {
    const content = await applicationService.decodeProfile({ data });
    await checkConfig(content.config);
    const remote = content.type === ProfileContent_Type.REMOTE;
    // Shared profile files carry LastUpdated in either seconds or milliseconds.
    let lastUpdated: number | undefined;
    if (remote && content.lastUpdated > 0n) {
      lastUpdated =
        content.lastUpdated > 100_000_000_000n
          ? Number(content.lastUpdated)
          : Number(content.lastUpdated) * 1000;
    }
    await insertProfile(
      {
        id: crypto.randomUUID(),
        name: uniqueName(content.name || basename(fileName, ".bpf")),
        type: remote ? "remote" : "local",
        remoteUrl: remote ? content.remotePath : undefined,
        autoUpdate: remote ? content.autoUpdate : false,
        autoUpdateIntervalMinutes:
          remote && content.autoUpdateInterval > 0
            ? content.autoUpdateInterval
            : DEFAULT_UPDATE_INTERVAL_MINUTES,
        lastUpdated,
      },
      content.config,
    );
    return;
  }
  throw new Error(`unsupported profile file: ${fileName}`);
}

async function encodeProfileData(id: string): Promise<Uint8Array> {
  const profile = findProfile(id);
  const remote = profile.type === "remote";
  const encoded = await applicationService.encodeProfile({
    type: remote ? ProfileContent_Type.REMOTE : ProfileContent_Type.LOCAL,
    name: profile.name,
    config: await readFile(contentPath(id), "utf-8"),
    remotePath: remote ? profile.remoteUrl : undefined,
    autoUpdate: remote ? profile.autoUpdate : false,
    autoUpdateInterval: remote ? profile.autoUpdateIntervalMinutes : 0,
    lastUpdated:
      remote && profile.lastUpdated !== undefined
        ? BigInt(profile.lastUpdated)
        : 0n,
  });
  return encoded.data;
}

// ---- VPN4TV: "Russia direct" around every start (vpn4tv/russiaDirect*.ts) ----

const russiaDirect = new RussiaDirectRuntime({
  store: {
    get: (name) => preferenceSnapshot([name])[name],
    set: (name, value) => setPreference(name, value),
    remove: (name) => removePreference(name),
  },
  appVersion: __APP_VERSION__,
  checkConfig: async (content) => {
    try {
      await checkConfig(content);
    } catch (error) {
      throw new Error(errorMessage(error));
    }
  },
  serviceRunning: () =>
    daemonState.connection.phase === "connected" &&
    daemonState.status === ServiceStatus_Type.STARTED,
  log: (warn, message) => (warn ? console.warn : console.info)(`vpn4tv: ${message}`),
  schedule: (milliseconds, callback) => {
    const timer = setTimeout(callback, milliseconds);
    timer.unref();
    return () => clearTimeout(timer);
  },
});

/** What the user and our server want for [profileId]. */
function russiaDirectWanted(profileId?: string): Wanted {
  let offReason: string | null = null;
  if (allThroughVpnEnabled()) {
    offReason = "user";
  } else if (profileId !== undefined && ruDirectOff(profileId)) {
    offReason = "head";
  }
  return {
    offReason,
    extraExceptions: profileId === undefined ? [] : ruVpnExtra(profileId),
    sets: usableRuleSets(),
  };
}

/**
 * One line for support after every start and reload: whether "Russia direct"
 * is in and why not. Into the Logs screen too (appLog.ts), after the start,
 * since a start clears that log.
 */
function logRussiaDirect(prepared: Prepared): void {
  const line = russiaDirectLine(prepared);
  (prepared.warn ? console.warn : console.info)(`vpn4tv: ${line}`);
  writeServiceLogLine({ warn: prepared.warn, message: line }, true);
}

// Starts and reloads go to the daemon one at a time: the crash guard, the
// retry without the block and the one-time restart below each assume that
// nothing else replaces the config while they run.
let serviceStartChain: Promise<void> = Promise.resolve();

function runServiceStart<Result>(operation: () => Promise<Result>): Promise<Result> {
  const result = serviceStartChain.then(operation);
  serviceStartChain = result.then(
    () => {},
    () => {},
  );
  return result;
}

/** This run of the app has started (or is starting) the service itself. */
let startedThisSession = false;
/**
 * Set by the FakeDNS self-check when the proxy works and the fakeip path does
 * not: the starts of this session go without FakeDNS. A connect clears it, as
 * on Android.
 */
let fakeDnsAutoDisabled = false;

/** The last DoH answers for the server names, between starts and runs. */
const resolvedHostsStore: ResolvedHostsStore = {
  async load() {
    const parsed = JSON.parse(await readFile(join(app.getPath("userData"), "dns_prefetch.json"), "utf-8")) as unknown;
    const answers: Record<string, string[]> = {};
    if (typeof parsed === "object" && parsed !== null) {
      for (const [host, addresses] of Object.entries(parsed)) {
        if (Array.isArray(addresses) && addresses.every((address) => typeof address === "string")) {
          answers[host] = addresses;
        }
      }
    }
    return answers;
  },
  async save(answers) {
    await atomicWriteFile(join(app.getPath("userData"), "dns_prefetch.json"), JSON.stringify(answers));
  },
};
/** A start of ours is talking to the daemon right now. */
let serviceStartRunning = false;

interface StartRequest {
  /** A connect: what the last session learned about "Russia direct" starts over. */
  newSession?: boolean;
  /** Check the final config in the worker first, and do not start if it is refused. */
  checkFirst?: boolean;
}

/** The daemon itself went away during a call, as opposed to refusing it or not being there. */
function daemonDiedDuringCall(error: unknown): boolean {
  const message = errorMessage(error);
  if (/ECONNREFUSED|ENOENT/u.test(message)) {
    return false;
  }
  return /ECONNRESET|EPIPE|premature close|socket hang up|stream (?:was )?(?:closed|destroyed|reset)|GOAWAY/iu.test(
    message,
  );
}

async function startServiceWithContent(content: string, profileId?: string): Promise<void> {
  // Set before anything is awaited: the daemon's first STARTED of this run
  // must already see it (the one-time restart below).
  startedThisSession = true;
  await runServiceStart(() => startServiceNow(content, profileId, {}));
}

/** The start itself; only ever called inside runServiceStart. */
async function startServiceNow(
  content: string,
  profileId: string | undefined,
  request: StartRequest,
): Promise<void> {
  if (desktopService === null) {
    throw new Error("daemon is not available");
  }
  startedThisSession = true;
  serviceStartRunning = true;
  // Whatever runs after this start is this start's config.
  russiaDirect.repairPending = false;
  try {
    // VPN4TV: Outline dynamic keys are meant to be fetched by the client before
    // connecting — the provider rotates servers behind them. The resolved key is
    // written back, so the next start still works when the key host is blocked.
    if (hasDynamicOutlineKeys(content)) {
      const resolved = await resolveDynamicOutlineKeys(content);
      if (resolved !== content) {
        content = resolved;
        if (profileId !== undefined) {
          await atomicWriteFile(contentPath(profileId), resolved).catch(() => {});
        }
      }
    }
    // VPN4TV: pick a resolver that is actually reachable on this network before
    // handing the config over — Russian ISPs kill DoH providers in waves, and the
    // one baked into the profile may be dead. Best effort: the probe never blocks
    // a connect for more than a few seconds and leaves the config alone on failure.
    // A machine with IPv6 switched off cannot take the tunnel's IPv6 address, and
    // the start aborts with "set ipv6 address: Element not found".
    // The config without "Russia direct": what a start that fails with it is
    // retried with, and what 1.0.0-beta.13 ran.
    // VPN4TV: and resolve the servers written by name through the DoH chain,
    // pinning the answers (sing-box has no failover between DNS servers). The
    // probe and the names run side by side, each bounded.
    if (request.newSession === true) {
      fakeDnsAutoDisabled = false;
    }
    const probed = probeDns();
    const pinned = preResolveHosts(serverHosts(content), resolvedHostsStore);
    let transformed = injectResolvedHosts(injectProbedDns(content, await probed), await pinned);
    if (fakeDnsAutoDisabled) {
      transformed = stripFakeDns(transformed);
    }
    // VPN4TV: the bridges' SOCKS5 inbounds want a password (bridgeAuth.ts).
    const base = applyBridgeAuth(applyIPv6Support(transformed));
    if (request.newSession === true) {
      russiaDirect.newSession();
    }
    const wanted = russiaDirectWanted(profileId);
    const prepared = await russiaDirect.prepare(base, wanted);
    if (request.checkFirst === true) {
      await checkConfig(prepared.content);
    }
    const options = await oomStartOptions();
    const daemonWasUp = daemonState.connection.phase === "connected";
    const startedAt = Date.now();
    russiaDirect.armForStart(prepared);
    let ran = prepared;
    try {
      await desktopService.startService({ configContent: prepared.content, options });
    } catch (error) {
      if (daemonWasUp && daemonDiedDuringCall(error)) {
        // The core died taking the config. The system restarts the daemon,
        // and the crash guard leaves the block out of the next start.
        russiaDirect.onDaemonLost();
        throw error;
      }
      // A start that fails with "Russia direct" is retried without it; if that
      // fails too, the block was not the cause and the error is the one the
      // user saw before. Without it means with the torrent rule alone. Not
      // when the user asked to stop in the meantime.
      const fallback = russiaDirect.torrentsOnly(base, "session");
      if (
        prepared.content === base ||
        prepared.content === fallback ||
        daemonState.stopRequestedAt >= startedAt
      ) {
        russiaDirect.onStopped();
        throw error;
      }
      const message = errorMessage(error);
      console.warn(`vpn4tv: start with Russia direct failed, retrying without it: ${message}`);
      try {
        await desktopService.startService({ configContent: fallback, options });
      } catch (retryError) {
        console.error(`vpn4tv: start without Russia direct failed too: ${errorMessage(retryError)}`);
        russiaDirect.onStopped();
        throw retryError;
      }
      russiaDirect.rolledBack(message);
      ran = {
        content: fallback,
        state: `off (session: the start with it failed: ${message})`,
        warn: true,
        guarded: false,
        usesDnsRu: false,
      };
    }
    logRussiaDirect(ran);
    russiaDirect.recordApplied(russiaDirectLabel(wanted.offReason), ran);
    russiaDirect.onRunning(ran);
    if (russiaDirect.claimDnsCheck(ran)) {
      void runDnsRuSelfCheck();
    }
    if (!fakeDnsAutoDisabled && hasFakeDns(ran.content)) {
      void runFakeDnsSelfCheck();
    }
  } finally {
    serviceStartRunning = false;
  }
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/**
 * Russian names resolve at Yandex over TCP 53, outside the tunnel. Where that
 * port is closed (hotels, offices, networks abroad) Russian names would stop
 * resolving. Ask for one through the tunnel after connect; if dns-ru does not
 * answer while the proxy does, our DNS rule resolves through dns-direct for
 * the session, and reload. Only ever falls back, once per session.
 */
async function runDnsRuSelfCheck(): Promise<void> {
  try {
    await sleep(4_000); // let the tunnel and the bridges settle
    const wanted = () =>
      !russiaDirect.dnsRuFallback && daemonState.status === ServiceStatus_Type.STARTED;
    const warn = (message: string) => console.warn(`vpn4tv: ${message}`);
    // A second round a minute later when the first cannot tell: the proxy was
    // not up yet either (slow bridges, a start at boot).
    for (let round = 1; round <= 2; round++) {
      if (!wanted()) {
        return;
      }
      if (await probeDnsRu(3, wanted, warn)) {
        console.info("vpn4tv: dns-ru health check OK");
        return;
      }
      if (!wanted()) {
        return;
      }
      if (await probeProxyAlive(wanted)) {
        break;
      }
      warn(`dns-ru health check: no answer, but the proxy is down too — not blaming dns-ru (round ${round} of 2)`);
      if (round === 2) {
        return;
      }
      await sleep(60_000);
    }
    if (!wanted()) {
      return;
    }
    warn("dns-ru health check FAILED — Russian names resolve through dns-direct this session; reloading");
    writeServiceLogLine({ warn: true, message: "russia-direct: dns-ru does not answer, Russian names resolve through dns-direct this session" });
    russiaDirect.dnsRuFallback = true;
    await reloadSelectedIfRunning();
  } catch (error) {
    console.warn(`vpn4tv: dns-ru health check error: ${errorMessage(error)}`);
  }
}

/**
 * A name through the tunnel the way an application reaches it: the system
 * resolver's query is hijacked by the core and answered from FakeDNS, the
 * connection to the fake address is sniffed and sent through the proxy. Any
 * HTTP answer means the fakeip path works. As Android's
 * probeReachableThroughTunnel.
 */
async function probeThroughTunnel(attempts: number, wanted: () => boolean): Promise<boolean> {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    if (!wanted()) {
      return false;
    }
    try {
      const response = await fetch("https://www.youtube.com/generate_204", {
        redirect: "manual",
        headers: { "User-Agent": "VPN4TV-healthcheck" },
        signal: AbortSignal.timeout(5_000),
      });
      if (response.status >= 200 && response.status < 400) {
        return true;
      }
      console.warn(`vpn4tv: tunnel probe attempt ${attempt}/${attempts}: HTTP ${response.status}`);
    } catch (error) {
      console.warn(`vpn4tv: tunnel probe attempt ${attempt}/${attempts} failed: ${errorMessage(error)}`);
    }
    if (attempt < attempts) {
      await sleep(3_000);
    }
  }
  return false;
}

/**
 * Where the fakeip path is broken on a network, every name an application asks
 * for leads nowhere. Reach a name through the tunnel after connect; if that
 * fails while the proxy answers by address, the rest of the session goes
 * without FakeDNS, and reload. Once per session, as on Android
 * (runFakeDnsHealthCheck).
 */
async function runFakeDnsSelfCheck(): Promise<void> {
  try {
    await sleep(3_000); // let the tunnel and the bridges settle
    const wanted = () => !fakeDnsAutoDisabled && daemonState.status === ServiceStatus_Type.STARTED;
    if (!wanted()) {
      return;
    }
    if (await probeThroughTunnel(3, wanted)) {
      console.info("vpn4tv: FakeDNS health check OK — reachable through tunnel");
      return;
    }
    if (!wanted()) {
      return;
    }
    // The name failed: the fakeip path, or the proxy itself? Only the first is
    // a reason to drop FakeDNS.
    if (!(await probeProxyAlive(wanted))) {
      console.warn("vpn4tv: FakeDNS health check: name unreachable but proxy also down — not attributing to FakeDNS");
      return;
    }
    if (!wanted()) {
      return;
    }
    console.warn("vpn4tv: FakeDNS health check FAILED — proxy alive but fakeip path broken; FakeDNS off this session, reloading");
    writeServiceLogLine({ warn: true, message: "FakeDNS does not work on this network: off until the next connect" });
    fakeDnsAutoDisabled = true;
    await reloadSelectedIfRunning();
  } catch (error) {
    console.warn(`vpn4tv: FakeDNS health check error: ${errorMessage(error)}`);
  }
}

let queuedSettingsReload: Promise<void> | null = null;

/**
 * Reload the running service after a setting the start-time config depends
 * on changed ("Everything through VPN", the dns-ru fallback). A burst of
 * changes merges into one reload: the queued one reads the settings when it
 * runs.
 */
export function reloadSelectedIfRunning(): Promise<void> {
  if (queuedSettingsReload !== null) {
    return queuedSettingsReload;
  }
  const reload = runServiceStart(async () => {
    queuedSettingsReload = null;
    const id = selectedProfileId();
    if (id === null || daemonState.status !== ServiceStatus_Type.STARTED) {
      return;
    }
    await startServiceNow(await readFile(contentPath(id), "utf-8"), id, {});
  });
  queuedSettingsReload = reload;
  return reload;
}

/** A restart of the selected profile that nobody asked for; skipped when the service is not running. */
function restartSelectedInBackground(why: string, request: StartRequest, stillWanted: () => boolean): void {
  void runServiceStart(async () => {
    if (!stillWanted() || daemonState.status !== ServiceStatus_Type.STARTED) {
      return;
    }
    const id = selectedProfileId();
    if (id === null) {
      return;
    }
    console.info(`vpn4tv: ${why}`);
    await startServiceNow(await readFile(contentPath(id), "utf-8"), id, request);
  }).catch((error: unknown) => {
    console.warn(`vpn4tv: ${why} — not done: ${errorMessage(error)}`);
  });
}

let firstStartedSeen = false;

/**
 * The daemon says STARTED. A start of ours handles "Russia direct" itself; a
 * service the daemon brought back on its own (after a crash or a reboot, or
 * running since before this app was started) gets three looks:
 *  - a crash with the block was recorded: restart it, the start leaves the
 *    block out (the daemon brought back the very config that crashed);
 *  - it came back less than 30 s ago with a config that carried the block:
 *    the crash guard covers the rest of those 30 s;
 *  - the first time in this run, when the app did not start the service
 *    itself and does not connect at launch: if the last start applied another
 *    revision of the block or lists (an update), restart it once — the daemon
 *    runs the config of the version before. The final config is checked in
 *    the worker first: a working tunnel is not dropped for a config the core
 *    would refuse.
 */
function onServiceStarted(): void {
  if (russiaDirect.repairPending) {
    restartSelectedInBackground(
      "restarting the service the daemon brought back after a crash with Russia direct",
      { newSession: true },
      () => russiaDirect.repairPending,
    );
    return;
  }
  if (serviceStartRunning) {
    return;
  }
  if (startedService !== null) {
    void startedService
      .getStartedAt({})
      .then((reply) => {
        if (!serviceStartRunning && reply.startedAt > 0n) {
          russiaDirect.onRestored(Date.now() - Number(reply.startedAt));
        }
      })
      .catch(() => {});
  }
  if (firstStartedSeen) {
    return;
  }
  firstStartedSeen = true;
  if (startedThisSession || autoConnectEnabled()) {
    return;
  }
  const id = selectedProfileId();
  if (id === null) {
    return;
  }
  const expected = russiaDirectLabel(russiaDirectWanted(id).offReason);
  if (russiaDirect.appliedLabel() === expected) {
    return;
  }
  restartSelectedInBackground(
    `one-time restart: the service runs a config without the current Russia direct (${russiaDirect.appliedLabel() ?? "none"} → ${expected})`,
    { newSession: true, checkFirst: true },
    () => !startedThisSession,
  );
}

/** Follow the daemon for the crash guard, the restart after a crash and the one-time restart. */
function watchServiceForRussiaDirect(): void {
  let lastStatus = daemonState.status;
  daemonState.on("change", () => {
    const status = daemonState.status;
    const previous = lastStatus;
    if (status === previous) {
      return;
    }
    lastStatus = status;
    if (status === null) {
      if (previous !== null) {
        clearServiceLogLines();
        // The status stream broke while connected: the daemon went down. (Another
        // user taking the service over also clears the status, but changes the
        // connection phase first; that is no crash.)
        if (daemonState.connection.phase === "connected") {
          russiaDirect.onDaemonLost();
        }
      }
      return;
    }
    if (status === ServiceStatus_Type.IDLE || status === ServiceStatus_Type.FATAL) {
      if (previous !== null) {
        russiaDirect.onStopped();
      }
      return;
    }
    if (status === ServiceStatus_Type.STARTED) {
      onServiceStarted();
    }
  });
  daemonState.on("stop-requested", () => russiaDirect.onStopped());
}

async function reloadIfSelectedAndRunning(id: string): Promise<void> {
  if (selectedProfileId() !== id) {
    return;
  }
  if (daemonState.status !== ServiceStatus_Type.STARTED) {
    return;
  }
  await startServiceWithContent(await readFile(contentPath(id), "utf-8"), id);
}

function intervalOrDefault(profile: ProfileMetadata): number {
  if (profile.autoUpdateIntervalMinutes > 0) {
    return Math.max(
      profile.autoUpdateIntervalMinutes,
      MINIMUM_UPDATE_INTERVAL_MINUTES,
    );
  }
  return DEFAULT_UPDATE_INTERVAL_MINUTES;
}

function updateRemoteProfile(id: string): Promise<void> {
  return runProfileOperation(id, async () => {
    const profile = findProfile(id);
    if (profile.type !== "remote" || !profile.remoteUrl) {
      throw new Error("not a remote profile");
    }
    const { content: remoteContent, routingChanged } = await fetchRemoteProfile(
      profile.remoteUrl,
      profile.id,
    );
    await checkConfig(remoteContent);
    try {
      const oldContent = await readFile(contentPath(profile.id), "utf-8");
      if (oldContent !== remoteContent) {
        await atomicWriteFile(contentPath(profile.id), remoteContent);
        await reloadIfSelectedAndRunning(profile.id);
      } else if (routingChanged) {
        // VPN4TV: only what our server says about "Russia direct" changed.
        await reloadIfSelectedAndRunning(profile.id);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
      await atomicWriteFile(contentPath(profile.id), remoteContent);
      await reloadIfSelectedAndRunning(profile.id);
    }
    settingsDatabase()
      .prepare("UPDATE profiles SET last_updated = ? WHERE id = ?")
      .run(Date.now(), profile.id);
    notifyChanged();
  });
}

export async function selectProfile(id: string): Promise<void> {
  findProfile(id);
  if (selectedProfileId() === id) {
    return;
  }
  writeSelectedProfileId(id);
  notifyChanged();
  await reloadIfSelectedAndRunning(id);
}

/**
 * VPN4TV: regenerate every remote profile — used when a setting that the
 * generator depends on (FakeDNS) changes, since the stored config is the
 * generated one. Local profiles keep whatever the user provided.
 */
export async function regenerateRemoteProfiles(): Promise<void> {
  for (const profile of profilesState().profiles) {
    if (profile.type !== "remote" || profile.remoteUrl === undefined) {
      continue;
    }
    try {
      const content = await fetchRemoteContent(profile.remoteUrl, profile.id);
      await atomicWriteFile(contentPath(profile.id), content);
      await reloadIfSelectedAndRunning(profile.id);
    } catch {
      // A refresh failure must not lose the profile the user already has.
    }
  }
}

export async function startSelectedProfile(): Promise<void> {
  // VPN4TV: before anything is awaited — see startServiceWithContent.
  startedThisSession = true;
  const selectedId = selectedProfileId();
  if (selectedId === null) {
    throw new Error("no profile selected");
  }
  const content = await readFile(contentPath(selectedId), "utf-8");
  // A connect: what the last session learned about "Russia direct" starts over.
  await runServiceStart(() => startServiceNow(content, selectedId, { newSession: true }));
}

let updateTimer: NodeJS.Timeout | null = null;

async function runDueProfileUpdates(): Promise<void> {
  const now = Date.now();
  const dueProfiles = listProfiles().filter((profile) => {
    if (profile.type !== "remote" || !profile.autoUpdate) {
      return false;
    }
    const intervalMs = intervalOrDefault(profile) * 60 * 1000;
    return profile.lastUpdated === undefined || profile.lastUpdated <= now - intervalMs;
  });
  await Promise.all(
    dueProfiles.map(async (profile) => {
      try {
        await updateRemoteProfile(profile.id);
      } catch (error) {
        console.error(`update profile ${profile.name}:`, error);
      }
    }),
  );
}

function reconfigureAutoUpdate(): void {
  if (updateTimer !== null) {
    clearTimeout(updateTimer);
    updateTimer = null;
  }
  const enabled = listProfiles().filter(
    (profile) => profile.type === "remote" && profile.autoUpdate,
  );
  if (enabled.length === 0) {
    return;
  }
  const intervalMs = Math.min(...enabled.map(intervalOrDefault)) * 60 * 1000;
  const earliest = Math.max(
    Date.now(),
    Math.min(
      ...enabled.map((profile) => (profile.lastUpdated ?? 0) + intervalMs),
    ),
  );
  updateTimer = setTimeout(() => {
    void runDueProfileUpdates().finally(() => {
      reconfigureAutoUpdate();
    });
  }, earliest - Date.now());
}

const handlers: Record<
  string,
  (...callArguments: never[]) => Promise<unknown>
> = {
  async list(): Promise<ProfilesState> {
    return profilesState();
  },

  // VPN4TV: the per-install id support asks users for.
  async vpn4tvDeviceId(): Promise<string> {
    return hwid();
  },

  // VPN4TV: expiry / traffic captured from the subscription headers.
  async vpn4tvSubscriptionInfo(id: string): Promise<unknown> {
    return subscriptionInfo(id);
  },

  // VPN4TV: what is running right now, so split tunnelling can be set up by
  // ticking applications instead of typing executable names.
  async vpn4tvRunningApplications(): Promise<string[]> {
    return runningApplications();
  },

  // VPN4TV: pick an application that is not running at the moment.
  async vpn4tvPickApplication(): Promise<string | null> {
    return pickApplication();
  },

  // VPN4TV: the manual paste box the mobile clients have. A bare link becomes a
  // remote profile so it keeps updating itself; anything else (proxy URIs,
  // base64, a plain config) is converted once into a local profile.
  async vpn4tvImportManual(name: string, text: string): Promise<string> {
    return importPastedContent(name, text);
  },

  async create(init: ProfileCreate): Promise<ProfileMetadata> {
    const profile: ProfileMetadata = {
      id: crypto.randomUUID(),
      name: uniqueName(init.name),
      type: init.type,
      autoUpdate: init.autoUpdate ?? init.type === "remote",
      autoUpdateIntervalMinutes:
        init.autoUpdateIntervalMinutes ?? DEFAULT_UPDATE_INTERVAL_MINUTES,
    };
    let content: string;
    if (init.type === "remote") {
      if (!init.remoteUrl) {
        throw new Error("missing remote URL");
      }
      profile.remoteUrl = init.remoteUrl;
      content = await fetchRemoteContent(init.remoteUrl, profile.id);
      await checkConfig(content);
      profile.lastUpdated = Date.now();
    } else {
      content = init.content ?? "{}";
      if (init.content !== undefined) {
        await checkConfig(content);
      }
    }
    return await insertProfile(profile, content);
  },

  async updateMetadata(id: string, patch: ProfileMetadataPatch): Promise<void> {
    await runProfileOperation(id, async () => {
      const profile = findProfile(id);
      let remoteContent: string | null = null;
      if (
        patch.remoteUrl !== undefined &&
        profile.type === "remote" &&
        patch.remoteUrl !== profile.remoteUrl
      ) {
        remoteContent = await fetchRemoteContent(patch.remoteUrl, id);
        await checkConfig(remoteContent);
        await atomicWriteFile(contentPath(id), remoteContent);
      }
      const store = settingsDatabase();
      store.transaction(() => {
        if (patch.name !== undefined) {
          store
            .prepare("UPDATE profiles SET name = ? WHERE id = ?")
            .run(patch.name, id);
        }
        if (patch.remoteUrl !== undefined && profile.type === "remote") {
          store
            .prepare(
              "UPDATE profiles SET remote_url = ?, last_updated = ? WHERE id = ?",
            )
            .run(
              patch.remoteUrl,
              remoteContent === null
                ? (profile.lastUpdated ?? null)
                : Date.now(),
              id,
            );
        }
        if (patch.autoUpdate !== undefined) {
          store
            .prepare("UPDATE profiles SET auto_update = ? WHERE id = ?")
            .run(patch.autoUpdate ? 1 : 0, id);
        }
        if (patch.autoUpdateIntervalMinutes !== undefined) {
          store
            .prepare(
              "UPDATE profiles SET auto_update_interval_minutes = ? WHERE id = ?",
            )
            .run(
              Math.max(
                patch.autoUpdateIntervalMinutes,
                MINIMUM_UPDATE_INTERVAL_MINUTES,
              ),
              id,
            );
        }
      })();
      notifyChanged();
      reconfigureAutoUpdate();
      if (remoteContent !== null) {
        await reloadIfSelectedAndRunning(id);
      }
    });
  },

  async remove(id: string): Promise<void> {
    await runProfileOperation(id, async () => {
      findProfile(id);
      const store = settingsDatabase();
      forgetSubscriptionInfo(id);
      store.transaction(() => {
        store.prepare("DELETE FROM profiles WHERE id = ?").run(id);
        if (selectedProfileId() === id) {
          const firstRow = store
            .prepare("SELECT id FROM profiles ORDER BY item_order ASC LIMIT 1")
            .get() as { id: string } | undefined;
          writeSelectedProfileId(firstRow === undefined ? null : firstRow.id);
        }
      })();
      try {
        await unlink(contentPath(id));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          throw error;
        }
      }
      notifyChanged();
      reconfigureAutoUpdate();
    });
  },

  async reorder(ids: string[]): Promise<void> {
    const store = settingsDatabase();
    store.transaction(() => {
      const currentIds = (
        store
          .prepare("SELECT id FROM profiles ORDER BY item_order ASC")
          .all() as { id: string }[]
      ).map((row) => row.id);
      const known = new Set(currentIds);
      const ordered = ids.filter((id) => known.has(id));
      const orderedSet = new Set(ordered);
      ordered.push(...currentIds.filter((id) => !orderedSet.has(id)));
      const updateOrderStatement = store.prepare(
        "UPDATE profiles SET item_order = ? WHERE id = ?",
      );
      for (const [index, id] of ordered.entries()) {
        updateOrderStatement.run(index, id);
      }
    })();
    notifyChanged();
  },

  async select(id: string): Promise<void> {
    await selectProfile(id);
  },

  async readContent(id: string): Promise<string> {
    findProfile(id);
    return await readFile(contentPath(id), "utf-8");
  },

  async writeContent(id: string, content: string): Promise<void> {
    await runProfileOperation(id, async () => {
      findProfile(id);
      await atomicWriteFile(contentPath(id), content);
      notifyChanged();
    });
  },

  async updateRemote(id: string): Promise<void> {
    await updateRemoteProfile(id);
  },

  async startService(): Promise<void> {
    await startSelectedProfile();
  },

  async takeOverService(): Promise<void> {
    if (desktopService === null) {
      throw new Error("daemon is not available");
    }
    await desktopService.takeOverService({});
    daemonState.retryConnection();
  },

  async pickImportFile(): Promise<{
    fileName: string;
    data: Uint8Array;
  } | null> {
    const result = await dialog.showOpenDialog({
      filters: [{ name: "sing-box profile", extensions: ["json", "bpf"] }],
      properties: ["openFile"],
    });
    if (result.canceled || result.filePaths.length === 0) {
      return null;
    }
    const filePath = result.filePaths[0];
    return { fileName: basename(filePath), data: await readFile(filePath) };
  },

  async importData(fileName: string, data: Uint8Array): Promise<void> {
    await importProfileData(fileName, data);
  },

  async decodeData(data: Uint8Array): Promise<{ name: string }> {
    const content = await applicationService.decodeProfile({ data });
    return { name: content.name };
  },

  async exportFile(id: string): Promise<boolean> {
    const profile = findProfile(id);
    const result = await dialog.showSaveDialog({
      defaultPath: `${profile.name}.json`,
      filters: [{ name: "sing-box configuration", extensions: ["json"] }],
    });
    if (result.canceled || !result.filePath) {
      return false;
    }
    await copyFile(contentPath(id), result.filePath);
    return true;
  },

  async exportData(id: string): Promise<boolean> {
    const profile = findProfile(id);
    const result = await dialog.showSaveDialog({
      defaultPath: `${profile.name}.bpf`,
      filters: [{ name: "sing-box profile", extensions: ["bpf"] }],
    });
    if (result.canceled || !result.filePath) {
      return false;
    }
    const data = await encodeProfileData(id);
    const cachePath = await writeApplicationCacheFile("share", ".bpf", data);
    await copyFile(cachePath, result.filePath);
    return true;
  },

  async encodeData(id: string): Promise<Uint8Array> {
    return await encodeProfileData(id);
  },
};

/** VPN4TV: create a profile from outside the IPC layer (Telegram onboarding). */
/**
 * VPN4TV: turn pasted or deep-linked content into a profile. A bare link
 * becomes a remote profile so it keeps updating itself; anything else is
 * converted once into a local one.
 */
export async function importPastedContent(name: string, text: string): Promise<string> {
  // vpn4tv:// wraps whatever the user would otherwise paste — unwrap before
  // deciding whether this is a subscription to keep updating or a one-off.
  const trimmed = (decodeVpn4tvLink(text) ?? text).trim();
  const profile = await createProfile(
    /^https?:\/\/\S+$/iu.test(trimmed)
      ? { name, type: "remote", remoteUrl: trimmed, autoUpdate: true }
      : { name, type: "local", content: convertSubscription(trimmed) },
  );
  return profile.id;
}

export async function createProfile(init: ProfileCreate): Promise<ProfileMetadata> {
  const create = handlers.create as (init: ProfileCreate) => Promise<ProfileMetadata>;
  return await create(init);
}

export function registerProfiles() {
  ipcMain.handle(
    PROFILES_CALL,
    async (
      _event,
      method: string,
      ...callArguments: unknown[]
    ): Promise<ProfilesResult> => {
      const handler = handlers[method];
      if (!handler) {
        return { ok: false, error: `unknown profiles method: ${method}` };
      }
      try {
        const value = await handler(...(callArguments as never[]));
        return { ok: true, value };
      } catch (error) {
        if (error instanceof ConnectError) {
          return { ok: false, error: error.rawMessage };
        }
        return {
          ok: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  );
  reconfigureAutoUpdate();
  watchServiceForRussiaDirect();
}
