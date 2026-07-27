// VPN4TV: the seam between the upstream profile machinery and our converter.
//
// The backend serves subscriptions in whatever shape the user's plan uses —
// proxy URIs, an Xray JSON config, base64, an AmneziaVPN payload — while
// sing-box only accepts its own config. Every remote fetch therefore goes
// through here, exactly like SubscriptionUpdater on Apple and the converter on
// Android.

import { Preference } from "../database";
import { generateConfig } from "./generator";
import { deviceHeaders, newHwid, type DeviceIdentity } from "./onboarding";
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
  return generateConfig(proxies);
}
