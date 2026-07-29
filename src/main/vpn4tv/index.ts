// VPN4TV: the seam between the upstream profile machinery and our converter.
//
// The backend serves subscriptions in whatever shape the user's plan uses —
// proxy URIs, an Xray JSON config, base64, an AmneziaVPN payload — while
// sing-box only accepts its own config. Every remote fetch therefore goes
// through here, exactly like SubscriptionUpdater on Apple and the converter on
// Android.

import { Preference } from "../database";
import { generateConfig, type PerAppProxy } from "./generator";
import {
  deviceHeaders,
  newHwid,
  parseUserInfo,
  type DeviceIdentity,
  type SubscriptionUserInfo,
} from "./onboarding";
import { parseSubscription } from "./parser";

const hwidPreference = new Preference<string>("vpn4tv_hwid", "", (value) =>
  typeof value === "string" ? value : "",
);

/** Stable per-install id, created on first use and kept in the settings database. */
export function hwid(): string {
  const stored = hwidPreference.get();
  if (stored.length > 0) {
    return stored;
  }
  const created = newHwid();
  hwidPreference.set(created);
  return created;
}

export function identity(version: string): DeviceIdentity {
  return { hwid: hwid(), version };
}

/** Headers every subscription request carries (x-device-os drives the backend). */
export function subscriptionHeaders(version: string): Record<string, string> {
  return deviceHeaders(identity(version));
}

export class EmptySubscriptionError extends Error {
  constructor() {
    super("No servers found in the subscription.");
    this.name = "EmptySubscriptionError";
  }
}

/**
 * Convert fetched subscription content into a sing-box profile.
 *
 * A response that already is a sing-box config passes through untouched, so
 * users who paste a plain config keep working. Anything else is parsed and
 * regenerated — including the bridge configs, which travel inside the profile
 * under the private "vpn4tv" key for the core to start.
 */
export function convertSubscription(content: string): string {
  const proxies = parseSubscription(content);
  if (proxies.length === 0) {
    throw new EmptySubscriptionError();
  }
  return generateConfig(proxies, {
    fakeDns: fakeDnsEnabled(),
    lanBypass: lanBypassEnabled(),
    perApp: perAppProxy(),
  });
}

const fakeDnsPreference = new Preference<boolean>(
  "vpn4tv-fake-dns",
  true,
  (value) => value !== false,
);

/** FakeDNS is on unless the user turned it off (it bypasses DNS blocking). */
export function fakeDnsEnabled(): boolean {
  return fakeDnsPreference.get();
}

const lanBypassPreference = new Preference<boolean>(
  "vpn4tv-lan-bypass",
  true,
  (value) => value !== false,
);

/** LAN stays off the tunnel unless the user asks for the opposite. */
export function lanBypassEnabled(): boolean {
  return lanBypassPreference.get();
}

const PER_APP_OFF: PerAppProxy = { mode: "off", apps: [] };

export function parsePerAppProxy(value: unknown): PerAppProxy {
  if (typeof value !== "object" || value === null) {
    throw new Error("invalid per-app proxy preference");
  }
  const candidate = value as Record<string, unknown>;
  const mode = candidate.mode;
  if (mode !== "off" && mode !== "exclude" && mode !== "include") {
    throw new Error("invalid per-app proxy mode");
  }
  const apps = candidate.apps;
  if (!Array.isArray(apps) || apps.some((app) => typeof app !== "string")) {
    throw new Error("invalid per-app proxy application list");
  }
  return { mode, apps: apps as string[] };
}

const perAppPreference = new Preference<PerAppProxy>(
  "vpn4tv-per-app",
  PER_APP_OFF,
  parsePerAppProxy,
);

/** Split tunnelling by executable name (the desktop answer to per-app proxy). */
export function perAppProxy(): PerAppProxy {
  return perAppPreference.get();
}

// ---- per-profile subscription metadata (expiry / traffic) ----


function userInfoPreference(profileId: string): Preference<string> {
  return new Preference<string>(`vpn4tv_userinfo_${profileId}`, "", (value) =>
    typeof value === "string" ? value : "",
  );
}

/** Remember what the subscription headers said, so the home screen can show it. */
export function rememberSubscriptionInfo(profileId: string, headers: Headers): void {
  const info = parseUserInfo(headers.get("subscription-userinfo"));
  if (info === undefined) {
    return;
  }
  userInfoPreference(profileId).set(JSON.stringify(info));
}

export function subscriptionInfo(profileId: string): SubscriptionUserInfo | null {
  const stored = userInfoPreference(profileId).get();
  if (stored.length === 0) {
    return null;
  }
  try {
    return JSON.parse(stored) as SubscriptionUserInfo;
  } catch {
    return null;
  }
}

export function forgetSubscriptionInfo(profileId: string): void {
  userInfoPreference(profileId).set(null);
}
