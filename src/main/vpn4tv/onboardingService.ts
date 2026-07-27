// VPN4TV: the onboarding session that lives in the main process.
//
// The user opens our Telegram bot (QR or button) and the bot pushes the
// subscription back through a long poll keyed by two ids — a UUID (in the QR /
// deep link) and a 10-digit code the user can type. On success we convert the
// subscription and create the profile, exactly like the mobile clients.

import { BrowserWindow, ipcMain, shell } from "electron";

import { VPN4TV_ONBOARDING_CALL, VPN4TV_ONBOARDING_EVENT } from "../../shared/ipc";
import { createProfile, profilesState } from "../profiles";
import { convertSubscription, identity } from "./index";
import {
  TELEGRAM_PROXY_URL,
  fetchSubscription,
  formatPairingCode,
  newPairingCode,
  pollOnce,
  telegramDeepLink,
  telegramQRLink,
} from "./onboarding";

const POLL_INTERVAL_MILLISECONDS = 5_000;
/** Give up after this long so a forgotten window stops polling our backend. */
const SESSION_TIMEOUT_MILLISECONDS = 15 * 60 * 1000;

export interface OnboardingSession {
  uuid: string;
  code: string;
  codeDisplay: string;
  qrLink: string;
  deepLink: string;
  proxyUrl: string;
}

export type OnboardingEvent =
  | { type: "user"; name: string }
  | { type: "imported"; profileName: string }
  | { type: "error"; message: string }
  | { type: "offline" };

let session: OnboardingSession | null = null;
let cancelled = false;

function broadcast(event: OnboardingEvent): void {
  for (const window of BrowserWindow.getAllWindows()) {
    if (!window.isDestroyed()) {
      window.webContents.send(VPN4TV_ONBOARDING_EVENT, event);
    }
  }
}

function start(version: string): OnboardingSession {
  cancelled = false;
  const created: OnboardingSession = {
    uuid: crypto.randomUUID(),
    code: newPairingCode(),
    codeDisplay: "",
    qrLink: "",
    deepLink: "",
    proxyUrl: TELEGRAM_PROXY_URL,
  };
  created.codeDisplay = formatPairingCode(created.code);
  created.qrLink = telegramQRLink(created.uuid);
  created.deepLink = telegramDeepLink(created.uuid);
  session = created;
  void pollLoop(created, version);
  return created;
}

function cancel(): void {
  cancelled = true;
  session = null;
}

async function pollLoop(active: OnboardingSession, version: string): Promise<void> {
  const deadline = Date.now() + SESSION_TIMEOUT_MILLISECONDS;
  let consecutiveNetworkErrors = 0;

  while (!cancelled && session === active && Date.now() < deadline) {
    // Both keys: whichever the user actually used reaches the same session.
    const outcomes = [await pollKey(active.uuid, version), await pollKey(active.code, version)];
    if (cancelled || session !== active) {
      return;
    }
    if (outcomes.some((outcome) => outcome === "done")) {
      return;
    }
    if (outcomes.every((outcome) => outcome === "networkError")) {
      consecutiveNetworkErrors += 1;
      if (consecutiveNetworkErrors === 3) {
        broadcast({ type: "offline" });
      }
    } else {
      consecutiveNetworkErrors = 0;
    }
    await sleep(POLL_INTERVAL_MILLISECONDS);
  }
}

async function pollKey(key: string, version: string): Promise<"done" | "empty" | "networkError"> {
  const outcome = await pollOnce(key, identity(version));
  if (outcome.kind !== "data") {
    return outcome.kind === "networkError" ? "networkError" : "empty";
  }
  const payload = outcome.payload;
  switch (payload.type) {
    case "user_info": {
      const name = [payload.first_name, payload.last_name]
        .filter((part): part is string => typeof part === "string" && part.length > 0)
        .join(" ");
      if (name.length > 0) {
        broadcast({ type: "user", name });
      }
      return "empty";
    }
    case "vpn_config_processed": {
      const entries = Array.isArray(payload.config)
        ? payload.config.filter((entry): entry is string => typeof entry === "string")
        : [];
      try {
        const profileName = await importConfigs(entries, version);
        broadcast({ type: "imported", profileName });
        session = null;
        return "done";
      } catch (error) {
        broadcast({ type: "error", message: error instanceof Error ? error.message : String(error) });
        return "empty";
      }
    }
    default:
      return "empty";
  }
}

/**
 * The bot sends either subscription URLs or inline configs. A URL becomes a
 * remote profile so it keeps auto-updating; inline configs are converted and
 * stored as a local profile.
 */
async function importConfigs(entries: string[], version: string): Promise<string> {
  if (entries.length === 0) {
    throw new Error("The bot sent an empty configuration.");
  }
  const remoteUrl = entries.find(
    (entry) => entry.startsWith("http://") || entry.startsWith("https://"),
  );
  if (remoteUrl !== undefined) {
    const fetched = await fetchSubscription(remoteUrl, identity(version));
    // Validate before storing so a broken subscription fails here, visibly.
    convertSubscription(fetched.content);
    const name = uniqueName(fetched.title ?? "VPN4TV Premium");
    await createProfile({
      name,
      type: "remote",
      remoteUrl,
      autoUpdate: true,
      autoUpdateIntervalMinutes: Math.max(60, (fetched.updateIntervalHours ?? 1) * 60),
    });
    return name;
  }

  const content = convertSubscription(entries.join("\n"));
  const name = uniqueName("VPN4TV");
  await createProfile({ name, type: "local", content });
  return name;
}

function uniqueName(base: string): string {
  const existing = new Set(profilesState().profiles.map((profile) => profile.name));
  if (!existing.has(base)) {
    return base;
  }
  let index = 2;
  while (existing.has(`${base} (${index})`)) {
    index += 1;
  }
  return `${base} (${index})`;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function registerOnboarding(version: string): void {
  ipcMain.handle(VPN4TV_ONBOARDING_CALL, async (_event, method: string, argument: unknown) => {
    switch (method) {
      case "start":
        return session ?? start(version);
      case "restart":
        cancel();
        return start(version);
      case "cancel":
        cancel();
        return null;
      case "openExternal": {
        if (typeof argument !== "string") {
          throw new Error("invalid link");
        }
        // tg:// and https:// only — never hand an arbitrary scheme to the OS.
        if (!argument.startsWith("tg://") && !argument.startsWith("https://")) {
          throw new Error("unsupported link");
        }
        await shell.openExternal(argument);
        return null;
      }
      default:
        throw new Error(`unknown onboarding method: ${method}`);
    }
  });
}
