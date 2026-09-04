// VPN4TV: onboarding + subscription plumbing for the desktop client — a port of
// the Android AddProfileScreen flow and the Swift VPN4TVOnboardingViewModel.
//
// The user opens the Telegram bot (QR on screen, or the button) and the backend
// pushes the subscription back to us over a long poll keyed by two ids: a UUID
// (encoded in the QR / deep link) and a 10-digit code the user can type.
//
// Node makes two things much easier than on Apple: arbitrary request headers and
// the SNI pin used when DNS for our host is blocked (tls.connect servername).

import { randomUUID, randomInt } from "node:crypto";
import { connect as tlsConnect } from "node:tls";

export const TELEGRAM_BOT = "VPN4TV_Bot";
export const POLL_ENDPOINT = "https://api.vpn4tv.com/poll";
/** MTProto proxy for users whose Telegram cannot connect at all. */
export const TELEGRAM_PROXY_URL =
  "tg://proxy?server=77.68.23.139&port=443&secret=eeda00e3c1b13bc091d0dde284f09a1dd27275747562652e7275";

/** Our infrastructure anchor: bell's static IP, TLS pinned to its hostname. */
const INFRA_ANCHOR = { ip: "152.53.207.6", sni: "bell.a4e.ar" };
const INFRA_HOSTS = new Set(["api.vpn4tv.com", "bell.a4e.ar"]);

export interface DeviceIdentity {
  hwid: string;
  version: string;
}

/** Headers every subscription/poll request carries (x-device-os drives the backend). */
export function deviceHeaders(identity: DeviceIdentity): Record<string, string> {
  return {
    "x-hwid": identity.hwid,
    "x-device-os": "desktop",
    "x-ver-os": identity.version,
    // The app version in its own header: the backend decides what it may serve
    // from it (naive needs a client that sets route.default_domain_resolver,
    // xhttp one that passes the transport's extra through), and x-ver-os means
    // the OS version on Android, so it cannot carry both.
    "x-app-ver": identity.version,
    "User-Agent": `VPN4TV-Desktop/${identity.version}`,
  };
}

/** Stable per-install id: a UUID without hyphens, exactly like the mobile apps. */
export function newHwid(): string {
  return randomUUID().replace(/-/g, "");
}

/** 10-digit code the user can read out to the bot. */
export function newPairingCode(): string {
  let code = "";
  for (let index = 0; index < 10; index += 1) {
    code += String(randomInt(0, 10));
  }
  return code;
}

/** "D DDD DDD DDD" grouping for display. */
export function formatPairingCode(code: string): string {
  if (code.length !== 10) {
    return code;
  }
  return `${code[0]} ${code.slice(1, 4)} ${code.slice(4, 7)} ${code.slice(7)}`;
}

/** https link for the QR (a phone camera opens the bot through t.me). */
export function telegramQRLink(uuid: string): string {
  return `https://telegram.me/${TELEGRAM_BOT}?start=${uuid}`;
}

/** tg:// deep link for the on-device button — opens the app, not a browser. */
export function telegramDeepLink(uuid: string): string {
  return `tg://resolve?domain=${TELEGRAM_BOT}&start=${uuid}`;
}

export type PollOutcome =
  | { kind: "data"; payload: Record<string, unknown> }
  | { kind: "empty" }
  | { kind: "networkError" };

/** api.vpn4tv.com → bell.a4e.ar mirror (bell proxies the same paths). */
export function mirrorUrl(url: string): string {
  return url.replace("//api.vpn4tv.com/", "//bell.a4e.ar/");
}

/**
 * GET with the same resilience as the mobile clients: a normal request first,
 * then — for our own hosts — the infra anchor (connect to bell's IP with the TLS
 * server name pinned to its hostname), which survives DNS blocking.
 */
export async function resilientGet(
  url: string,
  headers: Record<string, string>,
  timeoutMs = 30_000,
): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { headers, signal: controller.signal });
      if (response.status >= 200 && response.status < 500) {
        return await response.text();
      }
    } finally {
      clearTimeout(timer);
    }
  } catch {
    // fall through to the anchor
  }

  let host: string;
  try {
    host = new URL(url).host;
  } catch {
    return null;
  }
  if (!INFRA_HOSTS.has(host)) {
    return null;
  }
  try {
    return await anchoredGet(mirrorUrl(url), headers, timeoutMs);
  } catch {
    return null;
  }
}

/** HTTPS/1.1 GET to a pinned IP with an explicit TLS server name. */
function anchoredGet(url: string, headers: Record<string, string>, timeoutMs: number): Promise<string> {
  const parsed = new URL(url);
  const path = `${parsed.pathname}${parsed.search}`;
  return new Promise((resolve, reject) => {
    const socket = tlsConnect(
      { host: INFRA_ANCHOR.ip, port: 443, servername: INFRA_ANCHOR.sni, timeout: timeoutMs },
      () => {
        const lines = [
          `GET ${path.length > 0 ? path : "/"} HTTP/1.1`,
          `Host: ${INFRA_ANCHOR.sni}`,
          "Connection: close",
          ...Object.entries(headers)
            .filter(([key]) => key.toLowerCase() !== "host")
            .map(([key, value]) => `${key}: ${value}`),
          "",
          "",
        ];
        socket.write(lines.join("\r\n"));
      },
    );
    const chunks: Buffer[] = [];
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("error", reject);
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("infra anchor timeout"));
    });
    socket.on("close", () => {
      const raw = Buffer.concat(chunks);
      const separator = raw.indexOf("\r\n\r\n");
      resolve(separator < 0 ? raw.toString("utf8") : raw.subarray(separator + 4).toString("utf8"));
    });
  });
}

/** One poll for a single key (uuid or the typed code). */
export async function pollOnce(
  key: string,
  identity: DeviceIdentity,
  timeoutMs = 30_000,
): Promise<PollOutcome> {
  const body = await resilientGet(
    `${POLL_ENDPOINT}?uuid=${encodeURIComponent(key)}`,
    deviceHeaders(identity),
    timeoutMs,
  );
  if (body === null) {
    return { kind: "networkError" };
  }
  let payload: unknown;
  try {
    payload = JSON.parse(body);
  } catch {
    return { kind: "empty" };
  }
  if (typeof payload !== "object" || payload === null) {
    return { kind: "empty" };
  }
  const record = payload as Record<string, unknown>;
  if (record.type === "timeout") {
    return { kind: "empty" };
  }
  return { kind: "data", payload: record };
}

export interface SubscriptionFetch {
  content: string;
  title?: string;
  updateIntervalHours?: number;
  userInfo?: SubscriptionUserInfo;
}

export interface SubscriptionUserInfo {
  upload?: number;
  download?: number;
  total?: number;
  expireEpochSec?: number;
}

/**
 * Fetch a subscription and the metadata headers the backend sets
 * (subscription-userinfo / profile-title / profile-update-interval).
 */
export async function fetchSubscription(
  url: string,
  identity: DeviceIdentity,
  timeoutMs = 30_000,
): Promise<SubscriptionFetch> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { headers: deviceHeaders(identity), signal: controller.signal });
    return {
      content: await response.text(),
      title: decodeProfileTitle(response.headers.get("profile-title")),
      updateIntervalHours: parseOptionalInt(response.headers.get("profile-update-interval")),
      userInfo: parseUserInfo(response.headers.get("subscription-userinfo")),
    };
  } catch (error) {
    // DNS/TLS blocked → anchor, at the cost of the metadata headers.
    const body = await resilientGet(url, deviceHeaders(identity), timeoutMs);
    if (body === null) {
      throw error;
    }
    return { content: body };
  } finally {
    clearTimeout(timer);
  }
}

/** "upload=N; download=N; total=N; expire=epoch" → fields. */
export function parseUserInfo(raw: string | null | undefined): SubscriptionUserInfo | undefined {
  const trimmed = raw?.trim();
  if (!trimmed) {
    return undefined;
  }
  const values: Record<string, number> = {};
  for (const part of trimmed.split(";")) {
    const equals = part.indexOf("=");
    if (equals <= 0) {
      continue;
    }
    const key = part.slice(0, equals).trim().toLowerCase();
    const value = Number.parseInt(part.slice(equals + 1).trim(), 10);
    if (Number.isFinite(value)) {
      values[key] = value;
    }
  }
  if (Object.keys(values).length === 0) {
    return undefined;
  }
  return {
    upload: values.upload,
    download: values.download,
    total: values.total,
    expireEpochSec: values.expire,
  };
}

/** profile-title: plain UTF-8 or "base64:<base64>". */
export function decodeProfileTitle(raw: string | null | undefined): string | undefined {
  const trimmed = raw?.trim();
  if (!trimmed) {
    return undefined;
  }
  if (!trimmed.toLowerCase().startsWith("base64:")) {
    return trimmed;
  }
  const decoded = Buffer.from(trimmed.slice("base64:".length).trim(), "base64").toString("utf8").trim();
  return decoded.length > 0 ? decoded : undefined;
}

function parseOptionalInt(raw: string | null | undefined): number | undefined {
  if (!raw) {
    return undefined;
  }
  const value = Number.parseInt(raw, 10);
  return Number.isFinite(value) ? value : undefined;
}

export function isExpired(info: SubscriptionUserInfo | undefined): boolean {
  if (!info?.expireEpochSec || info.expireEpochSec <= 0) {
    return false;
  }
  return info.expireEpochSec * 1000 < Date.now();
}
